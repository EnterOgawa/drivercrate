//------------------------------------------------------------------------------
/**
 * @file dell_catalog_parser.cpp
 * @brief Dell公式catalog parser実装。
 * @version 01.00.00
 * @date 2026/09/02
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます。
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください。
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  共通XML検証へ移行。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note MSXML 6.0の外部entityとDTDを無効化し、Dell公式schemaから必要項目だけを抽出します。実端末のHardware IDは入力にも出力にも含めません。
 */
//------------------------------------------------------------------------------

#include "platform/dell_catalog_parser.h"

#include "platform/com_raii.h"
#include "platform/official_catalog_validation.h"

#include <Windows.h>
#include <msxml6.h>
#include <wrl/client.h>

#include <algorithm>
#include <cwctype>
#include <limits>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t		MAXIMUM_XML_CHARACTERS = 32U * 1024U * 1024U ;					// XML文字数上限。
constexpr std::size_t		MAXIMUM_RELEASES	   = 4096U ;								// 一platformで保持するdriver数上限。
constexpr std::size_t		MAXIMUM_HARDWARE_IDS   = 131072U ;								// 一platformで保持するID数上限。
constexpr std::uint64_t		MAXIMUM_PACKAGE_BYTES  = 4ULL * 1024ULL * 1024ULL * 1024ULL ;	// 4 GiB。
constexpr std::wstring_view DELL_NAMESPACE = L"openmanage/cm/dm" ;							// Dell catalog XML名前空間。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

using Microsoft::WRL::ComPtr ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief HRESULTを共通NativeErrorへ変換する。
 *
 * COM error codeのbit patternを失わずProvider層へ返す。
 *
 * @param[in] value MSXML APIが返したHRESULT。
 * @return HRESULT bit patternを保持したNativeError。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeError( const HRESULT value) noexcept
{
	return static_cast<NativeError>( value) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorを共通NativeErrorへ変換する。
 *
 * parser独自の入力検証失敗を既存error表現へ統一する。
 *
 * @param[in] value Win32 error code。
 * @return HRESULT_FROM_WIN32で変換したNativeError。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD value) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( value)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Dell表示名を完全一致用keyへ正規化する。
 *
 * 大文字小文字と空白差だけを吸収し、部分一致は許可しない。
 *
 * @param[in] value Registryまたはcatalogの表示名。
 * @return 英数字を大文字化し、区切り文字を除いた比較key。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizeName( const std::wstring_view value)
{
	std::wstring normalized ;	// 英数字だけを保持する完全一致key。
	normalized.reserve( value.size()) ;
	// 表示上の区切りだけを除去し、製品名の英数字情報は順序を保って残す。
	for( const wchar_t character : value) {
		// 英数字と判定された文字だけを大文字keyへ含めて表示名を比較する。
		if( std::iswalnum( character) != 0) {
			normalized.push_back( static_cast<wchar_t>( std::towupper( character))) ;
		}
	}

	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief 安全なDell配布相対pathかを検証する。
 *
 * Scheme、query、親directory、backslash、制御文字を拒否する。
 *
 * @param[in] value Catalogが返した相対path。
 * @return URL pathへ安全に連結できる場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafeRelativePath( const std::wstring_view value) noexcept
{
	// 空・過長・絶対path・親directory参照を公式配布相対pathとして受理しない。
	if( value.empty() || value.size() > 1024 || value.front() == L'/' ||
	   value.find( L"..") != std::wstring_view::npos) {
		return false ;
	}

	// Dell CDNで観測されるASCII path文字だけを許可する。
	return std::all_of( value.begin(), value.end(), []( const wchar_t character) {
		return (character >= L'a' && character <= L'z') ||
			   (character >= L'A' && character <= L'Z') ||
			   (character >= L'0' && character <= L'9') || character == L'/' || character == L'-' ||
			   character == L'_' || character == L'.' ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief SHA-256文字列を正規化して検証する。
 *
 * Install時のbinary hash比較へ曖昧な表現を持ち込まない。
 *
 * @param[in] value Catalog内のSHA-256 text。
 * @return 小文字64桁hex。形式不正時は<tt>std::nullopt</tt>。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> normalizeSha256( const std::wstring_view value)
{
	// SHA-256の64桁を満たさない値を公開hashとして受理しない。
	if( value.size() != 64) {
		return std::nullopt ;
	}

	std::wstring normalized ;	// 小文字へ統一したhash。
	normalized.reserve( value.size()) ;
	// ASCII hex以外を拒否して64桁を維持する。
	for( const wchar_t character : value) {
		// hash内のASCII数字は値を変えず保持する。
		if( character >= L'0' && character <= L'9') {
			normalized.push_back( character) ;
		}
		// hash内の小文字十六進英字は正規形として保持する。
		else if( character >= L'a' && character <= L'f') {
			normalized.push_back( character) ;
		}
		// hash内の大文字十六進英字だけを小文字へ揃える。
		else if( character >= L'A' && character <= L'F') {
			normalized.push_back( static_cast<wchar_t>( character - L'A' + L'a')) ;
		} else {
			return std::nullopt ;
		}
	}

	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief 10進文字列を64-bit byte数へ変換する。
 *
 * Overflowを検出し、download上限として信頼できる値だけ返す。
 *
 * @param[in] value Catalogのsize属性。
 * @return 1～4 GiBのbyte数。形式不正または範囲外は<tt>std::nullopt</tt>。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::uint64_t> parseSize( const std::wstring_view value) noexcept
{
	// 空または二十桁を超えるbyte数表記を解析しない。
	if( value.empty() || value.size() > 20) {
		return std::nullopt ;
	}

	std::uint64_t parsed{} ;	// 現在桁まで変換したbyte数。
	// 全桁を検証しながらoverflowなしで10進値へ変換する。
	for( const wchar_t character : value) {
		// byte数にASCII数字以外を許可しない。
		if( character < L'0' || character > L'9') {
			return std::nullopt ;
		}

		const std::uint64_t digit = static_cast<std::uint64_t>( character - L'0') ;	// 現在桁。
		// 桁追加前にuint64の範囲を確認し、容量のoverflowを拒否する。
		if( parsed > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
			return std::nullopt ;
		}

		parsed = parsed * 10 + digit ;
	}

	// ゼロ容量とpackage取得上限超過を候補metadataへ取り込まない。
	if( parsed == 0 || parsed > MAXIMUM_PACKAGE_BYTES) {
		return std::nullopt ;
	}

	return parsed ;
}

//------------------------------------------------------------------------------
/**
 * @brief NodeからXPathに一致するnode群を取得する。
 *
 * XPath BSTRのownershipを保持し、null listを成功扱いしない。
 *
 * @param[in] parent XPathの基点node。
 * @param[in] xpath Namespace prefix dを使うXPath。
 * @param[out] nodes 成功時のnode list。
 * @return MSXMLが返したHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT selectNodes( IXMLDOMNode &parent, const std::wstring_view xpath,
								  ComPtr<IXMLDOMNodeList> &nodes)
{
	nodes.Reset() ;
	UniqueBstr	  query( xpath) ;										// selectNodes呼出し中だけ所有するXPath。
	const HRESULT result = parent.selectNodes( query.get(), &nodes) ;	// Node取得結果。
	return SUCCEEDED( result) && nodes == nullptr ? E_UNEXPECTED : result ;
}

//------------------------------------------------------------------------------
/**
 * @brief NodeからXPathに一致する単一nodeを取得する。
 *
 * Missing nodeとparser errorを呼出し側が区別できる形で返す。
 *
 * @param[in] parent XPathの基点node。
 * @param[in] xpath Namespace prefix dを使うXPath。
 * @param[out] node 一致時のnode。未収録時はnull。
 * @return MSXMLが返したHRESULT。未収録はS_OK。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT selectSingleNode( IXMLDOMNode &parent, const std::wstring_view xpath,
									   ComPtr<IXMLDOMNode> &node)
{
	node.Reset() ;
	UniqueBstr query( xpath) ;	// selectSingleNode呼出し中だけ所有するXPath。
	return parent.selectSingleNode( query.get(), &node) ;
}

//------------------------------------------------------------------------------
/**
 * @brief XML nodeのtextを取得する。
 *
 * BSTRをstd::wstringへ複製し、embedded nullを拒否する。
 *
 * @param[in] node Text取得対象node。
 * @param[out] text 成功時のUTF-16 text。
 * @return MSXMLが返したHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT readText( IXMLDOMNode &node, std::wstring &text)
{
	text.clear() ;
	UniqueBstr	  value ;									// MSXML getterが割り当てるtext BSTR。
	const HRESULT result = node.get_text( value.put()) ;	// Text取得結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	// XML textが未設定の場合は空の出力を保ち、無効BSTRを参照しない。
	if( value.get() == nullptr) {
		return S_OK ;
	}

	const UINT length = SysStringLen( value.get()) ;	// BSTRのUTF-16文字数。
	text.assign( value.get(), length) ;
	return text.find( L'\0') == std::wstring::npos ? S_OK : E_INVALIDARG ;
}

//------------------------------------------------------------------------------
/**
 * @brief XPathに一致する単一nodeのtextを取得する。
 *
 * Node検索とBSTR変換を一つの検証単位として扱う。
 *
 * @param[in] parent XPathの基点node。
 * @param[in] xpath Text取得対象XPath。
 * @param[out] text 成功時のtext。未収録時は空。
 * @return MSXMLが返したHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT selectText( IXMLDOMNode &parent, const std::wstring_view xpath,
								 std::wstring &text)
{
	text.clear() ;
	ComPtr<IXMLDOMNode> node ;												// XPathに一致した非null node。
	const HRESULT		result = selectSingleNode( parent, xpath, node) ;	// 検索結果。
	// XPath照会失敗と対象node不在では本文読込みへ進まない。
	if( FAILED( result) || node == nullptr) {
		return result ;
	}

	return readText( *node.Get(), text) ;
}

//------------------------------------------------------------------------------
/**
 * @brief XML nodeの指定属性を取得する。
 *
 * NamedNodeMapを介し、属性nodeのtextを安全に複製する。
 *
 * @param[in] node 属性取得対象node。
 * @param[in] name Namespaceなし属性名。
 * @param[out] value 成功時の属性text。未収録時は空。
 * @return MSXMLが返したHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT readAttribute( IXMLDOMNode &node, const std::wstring_view name,
									std::wstring &value)
{
	value.clear() ;
	ComPtr<IXMLDOMNamedNodeMap> attributes ;									// Nodeが所有する属性collection。
	HRESULT						result = node.get_attributes( &attributes) ;	// Collection取得結果。
	// 属性map照会の失敗を保持し、属性なしの場合は空のまま返す。
	if( FAILED( result) || attributes == nullptr) {
		return FAILED( result) ? result : S_OK ;
	}

	UniqueBstr			attributeName( name) ;	// getNamedItem呼出し中だけ所有する属性名。
	ComPtr<IXMLDOMNode> attribute ;				// 一致した属性node。
	result = attributes->getNamedItem( attributeName.get(), &attribute) ;
	// 指定属性の照会失敗または不在では属性値を参照しない。
	if( FAILED( result) || attribute == nullptr) {
		return result ;
	}

	return readText( *attribute.Get(), value) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Node listの要素数を取得する。
 *
 * COMのsigned件数をloopへ渡す前に非負値へ制限する。
 *
 * @param[in] nodes 件数取得対象node list。
 * @param[out] count 成功時の0以上の件数。
 * @return 成功時はS_OK、不正な負数またはMSXML失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT nodeCount( IXMLDOMNodeList &nodes, long &count) noexcept
{
	count				 = 0 ;
	const HRESULT result = nodes.get_length( &count) ;	// MSXML collection件数取得結果。
	return SUCCEEDED( result) && count < 0 ? E_UNEXPECTED : result ;
}

//------------------------------------------------------------------------------
/**
 * @brief Model node群に端末product名が完全一致するか判定する。
 *
 * Catalog displayを部分一致せず比較し、別Dell modelを拒否する。
 *
 * @param[in] parent SupportedSystemsを含む基点node。
 * @param[in] xpath Model node群へのXPath。
 * @param[in] modelKey 正規化済み端末product名。
 * @param[out] matched 完全一致した場合true。
 * @return 成功時はS_OK、MSXML失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT containsModel( IXMLDOMNode &parent, const std::wstring_view xpath,
									const std::wstring_view modelKey, bool &matched)
{
	matched = false ;
	ComPtr<IXMLDOMNodeList> models ;										// SupportedSystems配下のModel node群。
	HRESULT					result = selectNodes( parent, xpath, models) ;	// Node群取得結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	long count{} ;	// Model node件数。
	result = nodeCount( *models.Get(), count) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	// 各Modelの英語Displayを端末product名と完全一致させる。
	for( long index = 0; index < count; ++index) {
		ComPtr<IXMLDOMNode> model ;	// 現在検査中のModel node。
		result = models->get_item( index, &model) ;
		// 列挙中model nodeの取得失敗または欠落を部分一致で隠さない。
		if( FAILED( result) || model == nullptr) {
			return FAILED( result) ? result : E_UNEXPECTED ;
		}

		std::wstring display ;	// Modelの英語表示名。
		result = selectText( *model.Get(), L"d:Display[@lang='en']", display) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( FAILED( result)) {
			return result ;
		}

		// 空でないmodel表示名が正規化後に完全一致した場合だけ適合とする。
		if( !display.empty() && normalizeName( display) == modelKey) {
			matched = true ;
			return S_OK ;
		}
	}

	return S_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief SoftwareComponentが対象Windows世代のx64版を含むか判定する。
 *
 * Windows 10と11が同じmajorVersion 10でもDisplayとosCodeで区別し、x86 packageを候補化しない。
 *
 * @param[in] component Dell SoftwareComponent node。
 * @param[in] windows11 trueならWindows 11、falseならWindows 10。
 * @param[out] supported 対象世代のx64 entryがある場合true。
 * @return 成功時はS_OK、MSXML失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT supportsWindows( IXMLDOMNode &component, const bool windows11, bool &supported)
{
	supported = false ;
	ComPtr<IXMLDOMNodeList> systems ;	// Componentが宣言するOS entry群。
	HRESULT result = selectNodes( component, L"d:SupportedOperatingSystems/d:OperatingSystem",
								 systems) ;	// OS node取得結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	long count{} ;	// OS entry件数。
	result = nodeCount( *systems.Get(), count) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	// x64 entryの表示名またはDell osCodeが対象Windows世代を示すか検査する。
	for( long index = 0; index < count; ++index) {
		ComPtr<IXMLDOMNode> system ;	// 現在検査中のOperatingSystem node。
		result = systems->get_item( index, &system) ;
		// 列挙中OS nodeを取得できなければOS対応判定を成功としない。
		if( FAILED( result) || system == nullptr) {
			return FAILED( result) ? result : E_UNEXPECTED ;
		}

		std::wstring architecture ;	// Catalogが宣言するx64/x86値。
		std::wstring osCode ;		// Dell固有OS code。
		std::wstring display ;		// 人間向けOS表示名。
		result = readAttribute( *system.Get(), L"osArch", architecture) ;
		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( result)) {
			result = readAttribute( *system.Get(), L"osCode", osCode) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( result)) {
			result = selectText( *system.Get(), L"d:Display[@lang='en']", display) ;
		}

		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( FAILED( result)) {
			return result ;
		}

		const std::wstring architectureKey = normalizeName( architecture) ;		// Arch比較key。
		const std::wstring osKey		   = normalizeName( osCode + display) ;	// OS世代比較key。
		// Windows世代を曖昧なmajorVersionだけで判定しない。
		const bool		   generationMatches =
			windows11 ? osKey.find( L"WINDOWS11") != std::wstring::npos || osKey.starts_with( L"W11")
							  : osKey.find( L"WINDOWS10") != std::wstring::npos || osKey.starts_with( L"W10") ;
		// x64と対象Windows世代が同時に一致したOS欄だけを対応ありとする。
		if( architectureKey == L"X64" && generationMatches) {
			supported = true ;
			return S_OK ;
		}
	}

	return S_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief PCIInfo nodeからWindows compatible IDを構成する。
 *
 * PCI VEN/DEVと任意SUBSYSをWindows compatible IDへ変換する。
 *
 * @param[in] pci Dell catalogのPCIInfo node。
 * @param[in,out] ids 重複排除しながら追加するcatalog由来ID集合。
 * @return 成功時はS_OK、属性不正またはMSXML失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT appendPciIds( IXMLDOMNode &pci, std::unordered_set<std::wstring> &ids)
{
	std::wstring vendor ;												// PCI vendorID属性。
	std::wstring device ;												// PCI deviceID属性。
	std::wstring subVendor ;											// PCI subVendorID属性。
	std::wstring subDevice ;											// PCI subDeviceID属性。
	HRESULT		 result = readAttribute( pci, L"vendorID", vendor) ;	// 最初の属性取得結果。
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = readAttribute( pci, L"deviceID", device) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = readAttribute( pci, L"subVendorID", subVendor) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = readAttribute( pci, L"subDeviceID", subDevice) ;
	}

	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	// PCI識別fieldが四桁のASCII十六進表記か確認する、captureを持たない関数。
	const auto validHex4 = []( const std::wstring_view value) {
		return value.size() == 4 &&
			   std::all_of( value.begin(), value.end(), []( const wchar_t character) {
				   return (character >= L'0' && character <= L'9') ||
						  (character >= L'a' && character <= L'f') ||
						  (character >= L'A' && character <= L'F') ;
			   }) ;
	} ;
	// catalogのPCI値と任意subsystem値が四桁十六進で揃わない場合は拒否する。
	if( !validHex4( vendor) || !validHex4( device) ||
	   ((!subVendor.empty() || !subDevice.empty()) &&
		(!validHex4( subVendor) || !validHex4( subDevice)))) {
		return E_INVALIDARG ;
	}

	std::transform( vendor.begin(), vendor.end(), vendor.begin(), ::towupper) ;
	std::transform( device.begin(), device.end(), device.begin(), ::towupper) ;
	std::transform( subVendor.begin(), subVendor.end(), subVendor.begin(), ::towupper) ;
	std::transform( subDevice.begin(), subDevice.end(), subDevice.begin(), ::towupper) ;
	const std::wstring base = L"PCI\\VEN_" + vendor + L"&DEV_" + device ;	// Bus固有base ID。
	ids.insert( base) ;
	// catalogにsubsystemが明示されている場合にだけ詳細な照合IDを追加する。
	if( !subVendor.empty()) {
		ids.insert( base + L"&SUBSYS_" + subDevice + subVendor) ;
	}

	return S_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief PnPInfo nodeからUSB/HDAUDIO compatible IDを構成する。
 *
 * Bus種別をcatalogが持たないため、bus prefixを含む二種類をlocal完全一致照合だけへ渡す。
 *
 * @param[in] pnp Dell catalogのPnPInfo node。
 * @param[in,out] ids 重複排除しながら追加するcatalog由来ID集合。
 * @return 成功時はS_OK、要素不正またはMSXML失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT appendPnpIds( IXMLDOMNode &pnp, std::unordered_set<std::wstring> &ids)
{
	std::wstring vendor ;											// PNPID要素の4桁vendor ID。
	std::wstring product ;											// PnPProductID要素の4桁product ID。
	HRESULT		 result = selectText( pnp, L"d:PNPID", vendor) ;	// Vendor取得結果。
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = selectText( pnp, L"d:PnPProductID", product) ;
	}

	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	// Subsystem識別fieldにも同じ四桁十六進条件を適用する、captureを持たない関数。
	const auto validHex4 = []( const std::wstring_view value) {
		return value.size() == 4 &&
			   std::all_of( value.begin(), value.end(), []( const wchar_t character) {
				   return (character >= L'0' && character <= L'9') ||
						  (character >= L'a' && character <= L'f') ||
						  (character >= L'A' && character <= L'F') ;
			   }) ;
	} ;
	// catalogのvendorとproductが四桁十六進でない場合はPnP照合IDを作らない。
	if( !validHex4( vendor) || !validHex4( product)) {
		return E_INVALIDARG ;
	}

	std::transform( vendor.begin(), vendor.end(), vendor.begin(), ::towupper) ;
	std::transform( product.begin(), product.end(), product.begin(), ::towupper) ;
	ids.insert( L"USB\\VID_" + vendor + L"&PID_" + product) ;
	ids.insert( L"HDAUDIO\\FUNC_01&VEN_" + vendor + L"&DEV_" + product) ;
	return S_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief Componentのcatalog Hardware ID群を取得する。
 *
 * 実端末IDを参照せず、公式catalog側の照合候補だけを構成する。
 *
 * @param[in] component Dell SoftwareComponent node。
 * @param[out] ids SupportedDevicesとSupportedDCHDevices由来ID群。
 * @return 成功時はS_OK、schema不正または上限超過時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT readHardwareIds( IXMLDOMNode &component, std::vector<std::wstring> &ids)
{
	ids.clear() ;
	std::unordered_set<std::wstring> unique ;	// 一component内のID重複排除集合。
	ComPtr<IXMLDOMNodeList>			 pciNodes ;	// 通常/DCH両schemaのPCIInfo node群。
	HRESULT							 result = selectNodes( component,
														  L"d:SupportedDevices/d:Device/d:PCIInfo | "
														  L"d:SupportedDCHDevices/d:Device/d:PCIInfo",
														  pciNodes) ;	// PCI node取得結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	long pciCount{} ;	// PCIInfo node件数。
	result = nodeCount( *pciNodes.Get(), pciCount) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	// 全PCIInfoをWindows compatible IDへ変換する。
	for( long index = 0; index < pciCount; ++index) {
		ComPtr<IXMLDOMNode> pci ;	// 現在変換中のPCIInfo node。
		result = pciNodes->get_item( index, &pci) ;
		// PCI node取得の失敗と欠落を不完全な照合ID集合として返さない。
		if( FAILED( result) || pci == nullptr) {
			return FAILED( result) ? result : E_UNEXPECTED ;
		}

		result = appendPciIds( *pci.Get(), unique) ;
		// PCI情報の変換失敗またはID件数上限超過では収集を中断する。
		if( FAILED( result) || unique.size() > MAXIMUM_HARDWARE_IDS) {
			return FAILED( result) ? result : HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}
	}

	ComPtr<IXMLDOMNodeList> pnpNodes ;	// 通常/DCH両schemaのPnPInfo node群。
	result = selectNodes( component,
						 L"d:SupportedDevices/d:Device/d:PnPInfo | "
						 L"d:SupportedDCHDevices/d:Device/d:PnPInfo",
						 pnpNodes) ;	// PnP node取得結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	long pnpCount{} ;	// PnPInfo node件数。
	result = nodeCount( *pnpNodes.Get(), pnpCount) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	// 全PnPInfoをbus prefix付きのlocal照合候補へ変換する。
	for( long index = 0; index < pnpCount; ++index) {
		ComPtr<IXMLDOMNode> pnp ;	// 現在変換中のPnPInfo node。
		result = pnpNodes->get_item( index, &pnp) ;
		// PnP node取得の失敗と欠落を不完全な照合ID集合として返さない。
		if( FAILED( result) || pnp == nullptr) {
			return FAILED( result) ? result : E_UNEXPECTED ;
		}

		result = appendPnpIds( *pnp.Get(), unique) ;
		// PnP情報の変換失敗またはID件数上限超過では収集を中断する。
		if( FAILED( result) || unique.size() > MAXIMUM_HARDWARE_IDS) {
			return FAILED( result) ? result : HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}
	}

	ids.assign( unique.begin(), unique.end()) ;
	return S_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief Dell release IDを検証する。
 *
 * Opaque identityと一時file名へ使う値を安全な文字へ限定する。
 *
 * @param[in] value SoftwareComponent releaseID属性。
 * @return 1～32桁のASCII英数字だけならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isReleaseId( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= 32 &&
		   std::all_of( value.begin(), value.end(), []( const wchar_t character) {
			   return (character >= L'a' && character <= L'z') ||
					  (character >= L'A' && character <= L'Z') ||
					  (character >= L'0' && character <= L'9') ;
		   }) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/dell_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError parseDellCatalogIndex( const std::wstring_view		xmlUtf16,
								  const std::wstring_view		systemModel,
								  DellPlatformCatalogReference &reference)
{
	const std::wstring modelKey = normalizeName( systemModel) ;	// 完全一致比較用端末model。
	// 空のmodel比較keyでplatform catalogを選ばない。
	if( modelKey.empty()) {
		return nativeError( E_INVALIDARG) ;
	}

	ComPtr<IXMLDOMDocument2> document ;				// Security設定済みDell index DOM。
	const std::wstring		 selectionNamespaces =	// Dell XPath用の固定namespace宣言。
		L"xmlns:d='" + std::wstring( DELL_NAMESPACE) + L"'" ;
	const NativeError documentError =	// 共通security envelope適用済みDOM生成結果。
		loadOfficialXmlDocument( xmlUtf16,
								{.maximumCharacters	  = MAXIMUM_XML_CHARACTERS,
								 .selectionNamespaces = selectionNamespaces},
								document) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( documentError != 0) {
		return documentError ;
	}

	ComPtr<IXMLDOMNodeList> manifests ;	// Index内のplatform別GroupManifest群。
	HRESULT result = selectNodes( *document.Get(), L"/d:ManifestIndex/d:GroupManifest",
								 manifests) ;	// Manifest取得結果。
	// XML照会の失敗原因を共通診断へ保持し、index解析を中断する。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	long count{} ;	// GroupManifest件数。
	result = nodeCount( *manifests.Get(), count) ;
	// manifest一覧の取得失敗を保持し、部分indexを返さない。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	std::optional<DellPlatformCatalogReference> found ;	// 一意に一致した検証済み参照。
	// 全platformのModel Displayを調べ、端末名と完全一致する参照だけを読む。
	for( long index = 0; index < count; ++index) {
		ComPtr<IXMLDOMNode> manifest ;	// 現在検査中のGroupManifest node。
		result = manifests->get_item( index, &manifest) ;
		// manifest nodeの取得失敗と予期しない欠落を診断付きで返す。
		if( FAILED( result) || manifest == nullptr) {
			return nativeError( FAILED( result) ? result : E_UNEXPECTED) ;
		}

		bool matched{} ;	// このGroupManifestが端末modelを含む場合true。
		result = containsModel( *manifest.Get(), L"d:SupportedSystems/d:Brand/d:Model", modelKey,
							   matched) ;
		// model照合中の失敗を不一致へ置き換えず返す。
		if( FAILED( result)) {
			return nativeError( result) ;
		}

		// 指定modelが対応しないmanifestからcatalogを取得しない。
		if( !matched) {
			continue ;
		}

		ComPtr<IXMLDOMNode> information ;	// CAB path/hashを持つManifestInformation node。
		result = selectSingleNode( *manifest.Get(), L"d:ManifestInformation", information) ;
		// 一致manifestの必須情報nodeがなければcatalog参照を構築しない。
		if( FAILED( result) || information == nullptr) {
			return nativeError( FAILED( result) ? result : E_INVALIDARG) ;
		}

		std::wstring path ;		// Platform CAB相対path。
		std::wstring sizeText ;	// Platform CAB byte数文字列。
		std::wstring hashText ;	// Platform CAB SHA-256文字列。
		result = readAttribute( *information.Get(), L"path", path) ;
		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( result)) {
			result = readAttribute( *information.Get(), L"size", sizeText) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( result)) {
			result = selectText( *information.Get(), L"d:Cryptography/d:Hash[@algorithm='SHA256']",
								hashText) ;
		}

		// catalog参照fieldの読込み失敗を同じ診断値で返す。
		if( FAILED( result)) {
			return nativeError( result) ;
		}

		const std::optional<std::uint64_t> size = parseSize( sizeText) ;		// 検証済みCAB byte数。
		const std::optional<std::wstring>  hash = normalizeSha256( hashText) ;	// 検証済みhash。
		// 安全な相対path・有限容量・公開hashが揃わないcatalog参照を拒否する。
		if( !isSafeRelativePath( path) || !size.has_value() || !hash.has_value()) {
			return nativeError( E_INVALIDARG) ;
		}

		DellPlatformCatalogReference candidate ;	// 今回一致した完全なCAB参照。
		candidate.model	 = std::wstring( systemModel) ;
		candidate.path	 = std::move( path) ;
		candidate.sha256 = hash.value() ;
		candidate.size	 = size.value() ;
		// 同じmodelが異なるCABへ曖昧に対応するindexは選ばない。
		if( found.has_value() &&
		   (found->path != candidate.path || found->sha256 != candidate.sha256 ||
			found->size != candidate.size)) {

			return nativeError( E_INVALIDARG) ;
		}

		found = std::move( candidate) ;
	}

	// 一致catalogがない場合は取得先を推測せず未発見の診断を返す。
	if( !found.has_value()) {
		return nativeErrorFromWin32( ERROR_NOT_FOUND) ;
	}

	reference = std::move( found.value()) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/dell_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError parseDellPlatformCatalog( const std::wstring_view xmlUtf16,
									 const std::wstring_view systemModel, const bool windows11,
									 std::vector<DellDriverRelease> &releases)
{
	releases.clear() ;
	const std::wstring modelKey = normalizeName( systemModel) ;	// 完全一致比較用端末model。
	// 空のmodel比較keyでdriver releaseを選ばない。
	if( modelKey.empty()) {
		return nativeError( E_INVALIDARG) ;
	}

	ComPtr<IXMLDOMDocument2> document ;				// Security設定済みplatform catalog DOM。
	const std::wstring		 selectionNamespaces =	// Dell XPath用の固定namespace宣言。
		L"xmlns:d='" + std::wstring( DELL_NAMESPACE) + L"'" ;
	const NativeError documentError =	// 共通security envelope適用済みDOM生成結果。
		loadOfficialXmlDocument( xmlUtf16,
								{.maximumCharacters	  = MAXIMUM_XML_CHARACTERS,
								 .selectionNamespaces = selectionNamespaces},
								document) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( documentError != 0) {
		return documentError ;
	}

	ComPtr<IXMLDOMNodeList> components ;	// ComponentType DRVRのSoftwareComponent群。
	HRESULT					result = selectNodes( *document.Get(),
												 L"/d:Manifest/d:SoftwareComponent[d:ComponentType/@value='DRVR']",
												 components) ;	// Driver component取得結果。
	// platform XMLの照会失敗を保持し、release解析を中断する。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	long count{} ;	// Driver component件数。
	result = nodeCount( *components.Get(), count) ;
	// component一覧の取得失敗を保持し、部分releaseを返さない。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	std::unordered_set<std::wstring> releaseKeys ;			// Release IDとpathの重複排除集合。
	std::size_t						 hardwareIdTotal{} ;	// Platform全体で保持するID数。
	// 全driver componentをmodel、OS、architecture、metadataの順に検証する。
	for( long index = 0; index < count; ++index) {
		ComPtr<IXMLDOMNode> component ;	// 現在検査中のSoftwareComponent node。
		result = components->get_item( index, &component) ;
		// component nodeの取得失敗と予期しない欠落を診断付きで返す。
		if( FAILED( result) || component == nullptr) {
			return nativeError( FAILED( result) ? result : E_UNEXPECTED) ;
		}

		bool modelSupported{} ;	// Componentが端末modelを明示する場合true。
		result = containsModel( *component.Get(), L"d:SupportedSystems/d:Brand/d:Model", modelKey,
							   modelSupported) ;
		// componentのmodel照合失敗を対象外と誤認せず返す。
		if( FAILED( result)) {
			return nativeError( result) ;
		}

		// 対象modelを含まないcomponentをdriver候補にしない。
		if( !modelSupported) {
			continue ;
		}

		bool osSupported{} ;	// Componentが対象Windows世代x64を含む場合true。
		result = supportsWindows( *component.Get(), windows11, osSupported) ;
		// OS照合中の処理失敗を対象外と誤認せず返す。
		if( FAILED( result)) {
			return nativeError( result) ;
		}

		// 対象Windows x64を含まないcomponentをdriver候補にしない。
		if( !osSupported) {
			continue ;
		}

		DellDriverRelease release ;		// 全required metadata検証後に出力へ移すrelease。
		std::wstring	  sizeText ;	// Package size属性文字列。
		std::wstring	  hashText ;	// Package SHA-256文字列。
		std::wstring	  criticality ;	// Dell criticality value。
		result = readAttribute( *component.Get(), L"releaseID", release.releaseId) ;
		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( result)) {
			result = readAttribute( *component.Get(), L"vendorVersion", release.version) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( result)) {
			result = readAttribute( *component.Get(), L"dellVersion", release.dellVersion) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( result)) {
			result = readAttribute( *component.Get(), L"releaseDate", release.releaseDate) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( result)) {
			result = readAttribute( *component.Get(), L"path", release.path) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( result)) {
			result = readAttribute( *component.Get(), L"size", sizeText) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( result)) {
			result = selectText( *component.Get(), L"d:Name/d:Display[@lang='en']", release.title) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( result)) {
			result = selectText( *component.Get(), L"d:Cryptography/d:Hash[@algorithm='SHA256']",
								hashText) ;
		}

		// 必須fieldの取得成功後にだけ任意の重要度nodeを調べる。
		if( SUCCEEDED( result)) {
			ComPtr<IXMLDOMNode> criticalityNode ;	// Optional Criticality node。
			result = selectSingleNode( *component.Get(), L"d:Criticality", criticalityNode) ;
			// 照会が成功し重要度nodeが存在する場合にだけその属性を読む。
			if( SUCCEEDED( result) && criticalityNode != nullptr) {
				result = readAttribute( *criticalityNode.Get(), L"value", criticality) ;
			}
		}

		// release fieldの取得失敗を同じ診断値で返す。
		if( FAILED( result)) {
			return nativeError( result) ;
		}

		const std::optional<std::uint64_t> size = parseSize( sizeText) ;		// 検証済みEXE byte数。
		const std::optional<std::wstring>  hash = normalizeSha256( hashText) ;	// 検証済みhash。
		// release ID・表示値・配布path・容量・hashの境界が不正なら拒否する。
		if( !isReleaseId( release.releaseId) || release.title.empty() || release.title.size() > 512 ||
		   release.version.empty() || release.version.size() > 128 ||
		   !isSafeRelativePath( release.path) || !size.has_value() || !hash.has_value()) {
			return nativeError( E_INVALIDARG) ;
		}

		release.size		= size.value() ;
		release.sha256		= hash.value() ;
		release.recommended = criticality == L"1" || criticality == L"2" ;
		result				= readHardwareIds( *component.Get(), release.hardwareIds) ;
		// catalog側IDの収集に失敗したreleaseを部分的に候補へ追加しない。
		if( FAILED( result)) {
			return nativeError( result) ;
		}

		// Hardware IDを持たないpackageは製品名推測でdeviceへ割り当てない。
		if( release.hardwareIds.empty()) {

			continue ;
		}

		// 全releaseを通じた照合ID件数の加算前に上限超過を検証する。
		if( hardwareIdTotal > MAXIMUM_HARDWARE_IDS - release.hardwareIds.size()) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		hardwareIdTotal += release.hardwareIds.size() ;
		const std::wstring releaseKey =	// 同一payloadを一度だけ候補化するkey。
			release.releaseId + L"\n" + release.path ;
		// 同じrelease keyは重複追加せず既存の一件を保持する。
		if( !releaseKeys.insert( releaseKey).second) {
			continue ;
		}

		// release件数が固定上限へ達した後は追加せず容量超過を返す。
		if( releases.size() >= MAXIMUM_RELEASES) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		releases.push_back( std::move( release)) ;
	}

	return 0 ;
}

} // namespace drivercrate
