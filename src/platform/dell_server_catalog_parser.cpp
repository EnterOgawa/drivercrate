//------------------------------------------------------------------------------
/**
 * @file dell_server_catalog_parser.cpp
 * @brief Dell PowerEdge Enterprise catalog parser実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note MSXML 6.0のDTDと外部参照を無効にし、PowerEdge model、Windows Server build、x64、driver種別、PCI IDを全て満たす個別DUP
 *       だけを返します。
 */
//------------------------------------------------------------------------------

#include "platform/dell_server_catalog_parser.h"

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
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t	MAXIMUM_XML_CHARACTERS = 32U * 1024U * 1024U ;					// XML文字数上限。
constexpr std::size_t	MAXIMUM_COMPONENTS	   = 8192U ;								// Catalog component件数上限。
constexpr std::size_t	MAXIMUM_RELEASES	   = 4096U ;								// 一scanで保持するdriver数上限。
constexpr std::size_t	MAXIMUM_HARDWARE_IDS   = 131072U ;								// Catalog由来PCI ID総数上限。
constexpr std::uint64_t MAXIMUM_PACKAGE_BYTES  = 4ULL * 1024ULL * 1024ULL * 1024ULL ;	// 4 GiB。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

using Microsoft::WRL::ComPtr ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief HRESULTをNativeErrorへ変換する。
 *
 * COM診断値を失わずProvider層へ返す。
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
 * @brief Win32 errorをNativeErrorへ変換する。
 *
 * Schemaと上限の拒否理由を共通error表現へ統一する。
 *
 * @param[in] value Parser検証に対応するWin32 error code。
 * @return HRESULT_FROM_WIN32で変換したNativeError。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD value) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( value)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示名を完全一致用keyへ正規化する。
 *
 * Brand＋Modelとsystem product名の部分一致を許可しない。
 *
 * @param[in] value SMBIOSまたはcatalogの表示名。
 * @return 英数字を大文字化し、表示区切りだけを除いたkey。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizeName( const std::wstring_view value)
{
	std::wstring normalized ;	// 英数字だけを順序通り保持する比較key。
	normalized.reserve( value.size()) ;
	// 表示上の空白とpunctuationだけを除き、文字順を維持する。
	for( const wchar_t character : value) {
		// 英数字と判定された文字だけを大文字keyへ含めてmodel名を比較する。
		if( std::iswalnum( character) != 0) {
			normalized.push_back( static_cast<wchar_t>( std::towupper( character))) ;
		}
	}

	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief NodeからXPathに一致するnode群を取得する。
 *
 * Null listを成功として扱わず、BSTR ownershipを局所化する。
 *
 * @param[in] parent XPath基点node。
 * @param[in] xpath Enterprise catalog用XPath。
 * @param[out] nodes 成功時のnode list。
 * @return MSXMLが返したHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT selectNodes( IXMLDOMNode &parent, const std::wstring_view xpath,
								  ComPtr<IXMLDOMNodeList> &nodes)
{
	nodes.Reset() ;
	UniqueBstr	  query( xpath) ;										// SelectNodes呼出し中だけ所有するXPath。
	const HRESULT result = parent.selectNodes( query.get(), &nodes) ;	// Node取得結果。
	return SUCCEEDED( result) && nodes == nullptr ? E_UNEXPECTED : result ;
}

//------------------------------------------------------------------------------
/**
 * @brief NodeからXPathに一致する単一nodeを取得する。
 *
 * Missing nodeとCOM失敗を呼出し側で区別できる形にする。
 *
 * @param[in] parent XPath基点node。
 * @param[in] xpath 取得対象XPath。
 * @param[out] node 一致時のnode。未収録時はnull。
 * @return MSXMLが返したHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT selectSingleNode( IXMLDOMNode &parent, const std::wstring_view xpath,
									   ComPtr<IXMLDOMNode> &node)
{
	node.Reset() ;
	UniqueBstr query( xpath) ;	// SelectSingleNode呼出し中だけ所有するXPath。
	return parent.selectSingleNode( query.get(), &node) ;
}

//------------------------------------------------------------------------------
/**
 * @brief XML nodeのtextを取得する。
 *
 * Embedded nullを拒否し、BSTRを所有文字列へ複製する。
 *
 * @param[in] node Text取得対象node。
 * @param[out] text 成功時のUTF-16 text。
 * @return MSXMLが返したHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT readText( IXMLDOMNode &node, std::wstring &text)
{
	text.clear() ;
	UniqueBstr	  value ;									// MSXMLが割り当てるtext BSTR。
	const HRESULT result = node.get_text( value.put()) ;	// Text取得結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	// 未設定のXML textは空のまま返し、無効BSTRを参照しない。
	if( value.get() == nullptr) {
		return S_OK ;
	}

	const UINT length = SysStringLen( value.get()) ;	// 終端nullを除くBSTR文字数。
	text.assign( value.get(), length) ;
	return text.find( L'\0') == std::wstring::npos ? S_OK : E_INVALIDARG ;
}

//------------------------------------------------------------------------------
/**
 * @brief XPathに一致する単一nodeのtextを取得する。
 *
 * Node検索とtext変換を同じ境界で処理する。
 *
 * @param[in] parent XPath基点node。
 * @param[in] xpath Text取得対象XPath。
 * @param[out] text 成功時のtext。未収録時は空。
 * @return MSXMLが返したHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT selectText( IXMLDOMNode &parent, const std::wstring_view xpath,
								 std::wstring &text)
{
	text.clear() ;
	ComPtr<IXMLDOMNode> node ;												// XPathに一致した非所有DOM node。
	const HRESULT		result = selectSingleNode( parent, xpath, node) ;	// Node検索結果。
	return FAILED( result) || node == nullptr ? result : readText( *node.Get(), text) ;
}

//------------------------------------------------------------------------------
/**
 * @brief XML nodeの属性値を取得する。
 *
 * Optional属性の欠落を空値として返し、embedded nullを拒否する。
 *
 * @param[in] node 属性を持つDOM node。
 * @param[in] name 取得する属性名。
 * @param[out] value 成功時の属性値。未収録時は空。
 * @return MSXMLが返したHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT readAttribute( IXMLDOMNode &node, const std::wstring_view name,
									std::wstring &value)
{
	value.clear() ;
	ComPtr<IXMLDOMNamedNodeMap> attributes ;									// Nodeが所有する属性map。
	HRESULT						result = node.get_attributes( &attributes) ;	// 属性map取得結果。
	// 属性照会の失敗を保持し、属性map不在では空のまま返す。
	if( FAILED( result) || attributes == nullptr) {
		return FAILED( result) ? result : S_OK ;
	}

	UniqueBstr			attributeName( name) ;	// getNamedItem呼出し中だけ所有する属性名。
	ComPtr<IXMLDOMNode> attribute ;				// 一致した属性node。
	result = attributes->getNamedItem( attributeName.get(), &attribute) ;
	return FAILED( result) || attribute == nullptr ? result : readText( *attribute.Get(), value) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Node list件数を安全なlong値で取得する。
 *
 * 負数件数をloop上限として使用しない。
 *
 * @param[in] nodes 件数取得対象list。
 * @param[out] count 成功時の0以上の件数。
 * @return 成功時はS_OK、負数またはMSXML失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT nodeCount( IXMLDOMNodeList &nodes, long &count)
{
	count				 = 0 ;
	const HRESULT result = nodes.get_length( &count) ;	// List長取得結果。
	return SUCCEEDED( result) && count < 0 ? E_UNEXPECTED : result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 10進文字列を32-bit Windows buildへ変換する。
 *
 * Overflowと空文字を拒否してbuild完全一致に使用する。
 *
 * @param[in] value Catalogの10進属性値。
 * @return 変換成功時の32-bit値。形式不正時は<tt>std::nullopt</tt>。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::uint32_t> parseU32( const std::wstring_view value) noexcept
{
	// 空または十桁を超えるWindows build表記を解析しない。
	if( value.empty() || value.size() > 10) {
		return std::nullopt ;
	}

	std::uint32_t parsed{} ;	// 現在桁まで変換した値。
	// 全桁を10進値へ変換し、各桁でoverflowを検出する。
	for( const wchar_t character : value) {
		// Windows buildにASCII数字以外を許可しない。
		if( character < L'0' || character > L'9') {
			return std::nullopt ;
		}

		const std::uint32_t digit = static_cast<std::uint32_t>( character - L'0') ;	// 現在桁。
		// buildの桁追加でuint32範囲を超える前に拒否する。
		if( parsed > (std::numeric_limits<std::uint32_t>::max() - digit) / 10U) {
			return std::nullopt ;
		}

		parsed = parsed * 10U + digit ;
	}

	return parsed ;
}

//------------------------------------------------------------------------------
/**
 * @brief 10進文字列をDUP byte数へ変換する。
 *
 * Download上限へ使用できるexact sizeだけを返す。
 *
 * @param[in] value SoftwareComponent size属性。
 * @return 1～4 GiBのbyte数。形式不正時は<tt>std::nullopt</tt>。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::uint64_t> parseSize( const std::wstring_view value) noexcept
{
	// 空または二十桁を超えるDUP容量表記を解析しない。
	if( value.empty() || value.size() > 20) {
		return std::nullopt ;
	}

	std::uint64_t parsed{} ;	// 現在桁まで変換したDUP byte数。
	// 全桁を10進値へ変換し、各桁でoverflowを検出する。
	for( const wchar_t character : value) {
		// DUP容量にASCII数字以外を許可しない。
		if( character < L'0' || character > L'9') {
			return std::nullopt ;
		}

		const std::uint64_t digit = static_cast<std::uint64_t>( character - L'0') ;	// 現在桁。
		// 容量の桁追加でuint64範囲を超える前に拒否する。
		if( parsed > (std::numeric_limits<std::uint64_t>::max() - digit) / 10ULL) {
			return std::nullopt ;
		}

		parsed = parsed * 10ULL + digit ;
	}

	return parsed > 0 && parsed <= MAXIMUM_PACKAGE_BYTES ? std::optional<std::uint64_t>( parsed)
														 : std::nullopt ;
}

//------------------------------------------------------------------------------
/**
 * @brief SHA-256文字列を小文字64桁hexへ正規化する。
 *
 * Install時のexact hash照合へ曖昧な文字表現を持ち込まない。
 *
 * @param[in] value Catalogのhash属性。
 * @return 小文字64桁hex。形式不正時は<tt>std::nullopt</tt>。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> normalizeSha256( const std::wstring_view value)
{
	// 公開SHA-256の64桁を満たさない値を受理しない。
	if( value.size() != 64) {
		return std::nullopt ;
	}

	std::wstring normalized ;	// 小文字へ統一したSHA-256。
	normalized.reserve( value.size()) ;
	// 64文字すべてをASCII hexとして検証する。
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
 * @brief Dell CDN用の安全な相対EXE pathか検証する。
 *
 * Scheme、query、親directory、backslash、制御文字を拒否する。
 *
 * @param[in] value Catalogが返したDUP相対path。
 * @return 安全なASCII相対pathかつ「.EXE」終端なら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafeExePath( const std::wstring_view value) noexcept
{
	// 空・過長・絶対path・親directory参照をDUP相対pathとして受理しない。
	if( value.empty() || value.size() > 1024 || value.front() == L'/' ||
	   value.find( L"..") != std::wstring_view::npos || value.size() < 4) {
		return false ;
	}

	const bool safeCharacters =
		std::all_of( value.begin(), value.end(), []( const wchar_t character) {
			return (character >= L'a' && character <= L'z') ||
				   (character >= L'A' && character <= L'Z') ||
				   (character >= L'0' && character <= L'9') || character == L'/' ||
				   character == L'-' || character == L'_' || character == L'.' ;
		}) ; // Dell CDNで観測するASCII path文字だけならtrue。
	const std::wstring extension = normalizeName( value.substr( value.size() - 4)) ;	// 拡張子key。
	return safeCharacters && extension == L"EXE" ;
}

//------------------------------------------------------------------------------
/**
 * @brief Dell release IDを安全な英数字へ限定する。
 *
 * Opaque identityとpackage identityへ外部区切り文字を入れない。
 *
 * @param[in] value SoftwareComponent releaseID属性。
 * @return 1～32桁ASCII英数字だけなら`true`。
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

//------------------------------------------------------------------------------
/**
 * @brief Driver componentが対象PowerEdge modelを含むか判定する。
 *
 * `PowerEdge` BrandとModelを結合し、別modelの部分一致を拒否する。
 *
 * @param[in] component Dell SoftwareComponent node。
 * @param[in] modelKey 正規化済みSMBIOS system product名。
 * @param[out] supported Brand＋Modelが完全一致した場合true。
 * @return 成功時はS_OK、MSXML失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT supportsModel( IXMLDOMNode &component, const std::wstring_view modelKey,
									bool &supported)
{
	supported = false ;
	ComPtr<IXMLDOMNodeList> brands ;												// SupportedSystems配下のBrand node群。
	HRESULT result = selectNodes( component, L"SupportedSystems/Brand", brands) ;	// 取得結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	long brandCount{} ;	// Brand node件数。
	result = nodeCount( *brands.Get(), brandCount) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	// 各Brand内のModel表示をsystem product名へ完全一致させる。
	for( long brandIndex = 0; brandIndex < brandCount; ++brandIndex) {
		ComPtr<IXMLDOMNode> brand ;	// 現在検査中のBrand node。
		result = brands->get_item( brandIndex, &brand) ;
		// brand nodeの取得失敗または欠落でmodel照合を成功としない。
		if( FAILED( result) || brand == nullptr) {
			return FAILED( result) ? result : E_UNEXPECTED ;
		}

		std::wstring brandName ;	// English Brand表示名。
		result = selectText( *brand.Get(), L"Display[@lang='en']", brandName) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( FAILED( result)) {
			return result ;
		}

		// PowerEdge以外のbrandからServer候補を取得しない。
		if( normalizeName( brandName) != L"POWEREDGE") {
			continue ;
		}

		ComPtr<IXMLDOMNodeList> models ;	// 現在Brand配下のModel node群。
		result = selectNodes( *brand.Get(), L"Model", models) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( FAILED( result)) {
			return result ;
		}

		long modelCount{} ;	// 現在BrandのModel件数。
		result = nodeCount( *models.Get(), modelCount) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( FAILED( result)) {
			return result ;
		}

		// Brand＋Modelを構成し、SMBIOS値へ完全一致させる。
		for( long modelIndex = 0; modelIndex < modelCount; ++modelIndex) {
			ComPtr<IXMLDOMNode> model ;	// 現在検査中のModel node。
			result = models->get_item( modelIndex, &model) ;
			// model nodeの取得失敗または欠落を対象外と混同しない。
			if( FAILED( result) || model == nullptr) {
				return FAILED( result) ? result : E_UNEXPECTED ;
			}

			std::wstring modelName ;	// English Model表示名。
			result = selectText( *model.Get(), L"Display[@lang='en']", modelName) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( FAILED( result)) {
				return result ;
			}

			// brandとmodelを連結した非空表示名が完全一致した場合だけ対応とする。
			if( !modelName.empty() && normalizeName( brandName + L" " + modelName) == modelKey) {
				supported = true ;
				return S_OK ;
			}
		}
	}

	return S_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief Driver componentが対象Windows Server buildを含むか判定する。
 *
 * Azure Stack HCIやWin64汎用entryをServer候補へ推測しない。
 *
 * @param[in] component Dell SoftwareComponent node。
 * @param[in] windowsBuild 実OSのCurrentBuildNumber。
 * @param[out] supported Microsoft Server x64 build一致時true。
 * @return 成功時はS_OK、MSXML失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT supportsServerBuild( IXMLDOMNode &component, const std::uint32_t windowsBuild,
										  bool &supported)
{
	supported = false ;
	ComPtr<IXMLDOMNodeList> systems ;	// Componentが宣言するOperatingSystem群。
	HRESULT result = selectNodes( component, L"SupportedOperatingSystems/OperatingSystem",
								 systems) ;	// OS node取得結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	long count{} ;	// OperatingSystem node件数。
	result = nodeCount( *systems.Get(), count) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	// 全OS entryをvendor、architecture、Server表示、buildで完全一致させる。
	for( long index = 0; index < count; ++index) {
		ComPtr<IXMLDOMNode> system ;	// 現在検査中のOperatingSystem node。
		result = systems->get_item( index, &system) ;
		// OS nodeの取得失敗または欠落でOS対応を成功としない。
		if( FAILED( result) || system == nullptr) {
			return FAILED( result) ? result : E_UNEXPECTED ;
		}

		std::wstring vendor ;		// osVendor属性。
		std::wstring architecture ;	// osArch属性。
		std::wstring buildText ;	// buildNumber属性。
		std::wstring osCode ;		// Dell OS code属性。
		std::wstring display ;		// English OS表示名。
		result = readAttribute( *system.Get(), L"osVendor", vendor) ;
		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( result)) {
			result = readAttribute( *system.Get(), L"osArch", architecture) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( result)) {
			result = readAttribute( *system.Get(), L"buildNumber", buildText) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( result)) {
			result = readAttribute( *system.Get(), L"osCode", osCode) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( result)) {
			result = selectText( *system.Get(), L"Display[@lang='en']", display) ;
		}

		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( FAILED( result)) {
			return result ;
		}

		const std::optional<std::uint32_t> build = parseU32( buildText) ;	// Catalog build値。
		const std::wstring osKey = normalizeName( osCode + display) ;		// Server用途確認key。
		// Microsoft・x64・Server・build・OS codeの全条件を満たす欄だけを採用する。
		if( normalizeName( vendor) == L"MICROSOFT" && normalizeName( architecture) == L"X64" &&
		   build.has_value() && build.value() == windowsBuild &&
		   osKey.find( L"WINDOWSSERVER") != std::wstring::npos &&
		   normalizeName( osCode).starts_with( L"W")) {
			supported = true ;
			return S_OK ;
		}
	}

	return S_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief PCIInfo node群をWindows compatible IDへ変換する。
 *
 * Catalog側IDだけを構成し、local Hardware IDを受け取らない。
 *
 * @param[in] component 対象PowerEdge／OSへ適合したcomponent。
 * @param[out] ids 成功時の重複排除済みPCI compatible ID群。
 * @return 成功時はS_OK、属性不正または上限超過時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT readPciIds( IXMLDOMNode &component, std::vector<std::wstring> &ids)
{
	ids.clear() ;
	ComPtr<IXMLDOMNodeList> nodes ;	// SupportedDevices配下のPCIInfo node群。
	// PCIInfo node集合の取得から各対応deviceの検証へ引き継ぐHRESULT。
	HRESULT result = selectNodes( component, L"SupportedDevices/Device/PCIInfo", nodes) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	long count{} ;	// PCIInfo node件数。
	result = nodeCount( *nodes.Get(), count) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	std::unordered_set<std::wstring> unique ;	// 一component内のID重複排除集合。
	const auto						 validHex4 = []( const std::wstring_view value) {
		  return value.size() == 4 &&
				 std::all_of( value.begin(), value.end(), []( const wchar_t character) {
					 return (character >= L'0' && character <= L'9') ||
							(character >= L'a' && character <= L'f') ||
							(character >= L'A' && character <= L'F') ;
				 }) ;
	} ; // PCI属性が4桁ASCII hexかを判定する局所関数。
	// 全PCIInfoをbase IDとSUBSYS付きIDへ変換する。
	for( long index = 0; index < count; ++index) {
		ComPtr<IXMLDOMNode> pci ;	// 現在変換中のPCIInfo node。
		result = nodes->get_item( index, &pci) ;
		// PCI nodeの取得失敗または欠落を部分ID集合として返さない。
		if( FAILED( result) || pci == nullptr) {
			return FAILED( result) ? result : E_UNEXPECTED ;
		}

		std::wstring vendor ;		// vendorID属性。
		std::wstring device ;		// deviceID属性。
		std::wstring subVendor ;	// subVendorID属性。
		std::wstring subDevice ;	// subDeviceID属性。
		result = readAttribute( *pci.Get(), L"vendorID", vendor) ;
		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( result)) {
			result = readAttribute( *pci.Get(), L"deviceID", device) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( result)) {
			result = readAttribute( *pci.Get(), L"subVendorID", subVendor) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( result)) {
			result = readAttribute( *pci.Get(), L"subDeviceID", subDevice) ;
		}

		// catalogのPCI・subsystem値を四桁十六進として読めない場合は拒否する。
		if( FAILED( result) || !validHex4( vendor) || !validHex4( device) || !validHex4( subVendor) ||
		   !validHex4( subDevice)) {
			return FAILED( result) ? result : E_INVALIDARG ;
		}

		std::transform( vendor.begin(), vendor.end(), vendor.begin(), ::towupper) ;
		std::transform( device.begin(), device.end(), device.begin(), ::towupper) ;
		std::transform( subVendor.begin(), subVendor.end(), subVendor.begin(), ::towupper) ;
		std::transform( subDevice.begin(), subDevice.end(), subDevice.begin(), ::towupper) ;
		// 未指定を表すゼロvendor・deviceはPnP照合IDへ変換しない。
		if( vendor == L"0000" || device == L"0000") {
			continue ;
		}

		const std::wstring base = L"PCI\\VEN_" + vendor + L"&DEV_" + device ;	// Bus ID。
		unique.insert( base) ;
		// subsystemの両値が明示された場合にだけ詳細照合IDを追加する。
		if( subVendor != L"0000" && subDevice != L"0000") {
			unique.insert( base + L"&SUBSYS_" + subDevice + subVendor) ;
		}

		// catalog側照合IDの件数が固定上限を超えた場合は収集を中断する。
		if( unique.size() > MAXIMUM_HARDWARE_IDS) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}
	}

	ids.assign( unique.begin(), unique.end()) ;
	return S_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief Relevant driver componentの必須metadataを読み取る。
 *
 * Individual LW64 EXE、SHA-256、size、PCI IDだけを受理する。
 *
 * @param[in] component Model／OS一致済みDriver component。
 * @param[out] release 成功時の検証済みDUP metadata。
 * @return 全必須値が正しい場合はS_OK、それ以外はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT readRelease( IXMLDOMNode &component, DellServerDriverRelease &release)
{
	release = {} ;
	std::wstring packageType ;		// SoftwareComponent packageType属性。
	std::wstring hashAlgorithm ;	// Hash algorithm属性。
	std::wstring sizeText ;			// 10進DUP byte数属性。
	std::wstring rebootText ;		// Reboot required属性。
	std::wstring criticality ;		// Criticality value属性。
	// Release IDの読取りからrecord全体の検証へ引き継ぐHRESULT。
	HRESULT		 result = readAttribute( component, L"releaseID", release.releaseId) ;
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = readAttribute( component, L"vendorVersion", release.version) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = readAttribute( component, L"dellVersion", release.dellVersion) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = readAttribute( component, L"releaseDate", release.releaseDate) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = readAttribute( component, L"packageType", packageType) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = readAttribute( component, L"path", release.path) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = readAttribute( component, L"hash", release.sha256) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = readAttribute( component, L"hashAlgorithm", hashAlgorithm) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = readAttribute( component, L"size", sizeText) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = readAttribute( component, L"rebootRequired", rebootText) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = selectText( component, L"Name/Display[@lang='en']", release.title) ;
	}

	ComPtr<IXMLDOMNode> criticalityNode ;	// Criticality属性の取得元node。
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = selectSingleNode( component, L"Criticality", criticalityNode) ;
	}

	// 照会成功かつ重要度nodeがある場合にだけ任意属性を読む。
	if( SUCCEEDED( result) && criticalityNode != nullptr) {
		result = readAttribute( *criticalityNode.Get(), L"value", criticality) ;
	}

	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	const std::optional<std::wstring> normalizedHash =
		// Exact SHA-256検証結果。
		normalizeSha256( release.sha256) ;
	const std::optional<std::uint64_t> parsedSize = parseSize( sizeText) ;			// Exact size検証結果。
	const std::wstring				   rebootKey  = normalizeName( rebootText) ;	// Boolean比較key。
	// DUPの必須metadata・LW64形式・SHA-256・容量・再起動・重要度を全て検証する。
	if( !isReleaseId( release.releaseId) || release.title.empty() || release.title.size() > 512 ||
	   release.version.empty() || release.version.size() > 128 || release.dellVersion.empty() ||
	   release.dellVersion.size() > 128 || release.releaseDate.empty() ||
	   release.releaseDate.size() > 64 || normalizeName( packageType) != L"LW64" ||
	   normalizeName( hashAlgorithm) != L"SHA256" || !normalizedHash.has_value() ||
	   !parsedSize.has_value() || !isSafeExePath( release.path) ||
	   (rebootKey != L"TRUE" && rebootKey != L"FALSE") ||
	   (criticality != L"1" && criticality != L"2" && criticality != L"3")) {
		return E_INVALIDARG ;
	}

	result = readPciIds( component, release.hardwareIds) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( FAILED( result)) {
		return result ;
	}

	release.sha256		   = normalizedHash.value() ;
	release.size		   = parsedSize.value() ;
	release.recommended	   = criticality == L"1" || criticality == L"2" ;
	release.rebootRequired = rebootKey == L"TRUE" ;
	return S_OK ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/dell_server_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError parseDellServerCatalog( const std::wstring_view				 xmlUtf16,
								   const std::wstring_view				 systemModel,
								   const std::uint32_t					 windowsBuild,
								   std::vector<DellServerDriverRelease> &releases)
{
	releases.clear() ;
	const std::wstring modelKey = normalizeName( systemModel) ;	// Model完全一致用key。
	// model比較keyまたは実Windows buildが未確定ならcatalogを解析しない。
	if( modelKey.empty() || windowsBuild == 0) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	ComPtr<IXMLDOMDocument2> document ;	// Security設定済みEnterprise catalog DOM。
	const NativeError		 documentError = loadOfficialXmlDocument(
		   xmlUtf16, {.maximumCharacters = MAXIMUM_XML_CHARACTERS}, document) ;	// DOM生成結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( documentError != 0) {
		return documentError ;
	}

	ComPtr<IXMLDOMNode> root ;	// `/Manifest`と完全一致するdocument root。
	// Manifest rootの取得からcatalog全体の検証へ引き継ぐHRESULT。
	HRESULT				result = selectSingleNode( *document.Get(), L"/Manifest", root) ;
	// catalog rootを取得できないXMLを受理しない。
	if( FAILED( result) || root == nullptr) {
		return nativeError( FAILED( result) ? result : E_INVALIDARG) ;
	}

	std::wstring baseLocation ;	// Catalogが宣言するpayload origin host。
	result = readAttribute( *root.Get(), L"baseLocation", baseLocation) ;
	// 基点配布hostがDell公式の固定値と一致しなければ参照を使用しない。
	if( FAILED( result) || normalizeName( baseLocation) != L"DOWNLOADSDELLCOM") {
		return nativeError( FAILED( result) ? result : E_INVALIDARG) ;
	}

	ComPtr<IXMLDOMNodeList> components ;	// Root直下のSoftwareComponent群。
	result = selectNodes( *root.Get(), L"SoftwareComponent", components) ;
	// component照会の失敗原因を共通診断値で返す。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	long componentCount{} ;	// Catalog内SoftwareComponent件数。
	result = nodeCount( *components.Get(), componentCount) ;
	// component件数の照会失敗、負値、上限超過を列挙前に拒否する。
	if( FAILED( result) || componentCount < 0 ||
	   static_cast<std::size_t>( componentCount) > MAXIMUM_COMPONENTS) {
		return nativeError( FAILED( result) ? result : HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW)) ;
	}

	std::vector<DellServerDriverRelease> parsed ;				// 全検証成功まで公開しないrelease群。
	std::size_t							 totalHardwareIds{} ;	// Catalog全候補のPCI ID件数。
	// 全componentを種別で分類し、対象model／OSに関係するdriverだけを厳密に読む。
	for( long index = 0; index < componentCount; ++index) {
		ComPtr<IXMLDOMNode> component ;	// 現在検査中のSoftwareComponent node。
		result = components->get_item( index, &component) ;
		// component nodeの取得失敗と欠落を診断付きで返す。
		if( FAILED( result) || component == nullptr) {
			return nativeError( FAILED( result) ? result : E_UNEXPECTED) ;
		}

		ComPtr<IXMLDOMNode> typeNode ;	// ComponentType node。
		result = selectSingleNode( *component.Get(), L"ComponentType", typeNode) ;
		// component種別nodeが欠落した情報をdriverと推測しない。
		if( FAILED( result) || typeNode == nullptr) {
			return nativeError( FAILED( result) ? result : E_INVALIDARG) ;
		}

		std::wstring componentType ;	// Dell component type code。
		result = readAttribute( *typeNode.Get(), L"value", componentType) ;
		// component種別の読込み失敗を同じ診断値で返す。
		if( FAILED( result)) {
			return nativeError( result) ;
		}

		// DRVR以外のcomponentをdriver更新候補に含めない。
		if( normalizeName( componentType) != L"DRVR") {
			continue ;
		}

		bool modelSupported{} ;	// Brand＋Modelが端末へ完全一致した場合true。
		result = supportsModel( *component.Get(), modelKey, modelSupported) ;
		// PowerEdge model照合の処理失敗を単なる対象外へ変えない。
		if( FAILED( result)) {
			return nativeError( result) ;
		}

		// 対象PowerEdge modelを含まないcomponentを除外する。
		if( !modelSupported) {
			continue ;
		}

		bool osSupported{} ;	// Microsoft Server x64 buildが完全一致した場合true。
		result = supportsServerBuild( *component.Get(), windowsBuild, osSupported) ;
		// Server OS照合の処理失敗を単なる対象外へ変えない。
		if( FAILED( result)) {
			return nativeError( result) ;
		}

		// 実行中Server buildに対応しないcomponentを除外する。
		if( !osSupported) {
			continue ;
		}

		DellServerDriverRelease release ;	// 今回検証する個別driver DUP metadata。
		result = readRelease( *component.Get(), release) ;
		// 対象releaseの必須metadata読込みに失敗した場合は部分結果を返さない。
		if( FAILED( result)) {
			return nativeError( result) ;
		}

		// PCI IDがないdriverは名称からdeviceを推測せず候補化しない。
		if( release.hardwareIds.empty()) {
			continue ;
		}

		// release件数と全照合ID件数の上限を追加前に検証する。
		if( parsed.size() >= MAXIMUM_RELEASES ||
		   release.hardwareIds.size() > MAXIMUM_HARDWARE_IDS - totalHardwareIds) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		totalHardwareIds += release.hardwareIds.size() ;
		parsed.push_back( std::move( release)) ;
	}

	releases = std::move( parsed) ;
	return 0 ;
}

} // namespace drivercrate
