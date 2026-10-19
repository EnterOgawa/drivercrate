//------------------------------------------------------------------------------
/**
 * @file hp_catalog_parser.cpp
 * @brief HP公式reference catalog parser実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式取得元policy registryへ統合。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note MSXML 6.0のDTDと外部参照を無効化し、HP公式referenceのうちdriver候補とfile検証に必要な値だけを抽出します。任意commandは読み取りません。
 */
//------------------------------------------------------------------------------

#include "platform/hp_catalog_parser.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/com_raii.h"
#include "platform/official_catalog_validation.h"
#include "platform/official_http_client.h"

#include <Windows.h>
#include <msxml6.h>
#include <wrl/client.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cwctype>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t	MAXIMUM_XML_CHARACTERS = 16U * 1024U * 1024U ;	// XML文字数上限。
constexpr std::size_t	MAXIMUM_PLATFORMS	   = 32768U ;				// Platform node数上限。
constexpr std::size_t	MAXIMUM_SOLUTIONS	   = 16384U ;				// SoftPaq数上限。
constexpr std::size_t	MAXIMUM_DEVICES		   = 65536U ;				// Device対応数上限。
constexpr std::size_t	MAXIMUM_HARDWARE_IDS   = 4096U ;				// 一SoftPaqのHardware ID数上限。
constexpr std::uint64_t MAXIMUM_PAYLOAD_BYTES =
	4ULL * 1024ULL * 1024ULL * 1024ULL ;	// 一payloadの4 GiB上限。
constexpr std::wstring_view PAYLOAD_PREFIX =
	L"https://ftp.hp.com/pub/softpaq/" ;	// 許可payload path prefix。

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
 * @brief Win32 errorを共通NativeErrorへ変換する。
 *
 * Schema検証失敗をProvider共通表現へ揃える。
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
 * @brief XPathに一致する単一nodeを取得する。
 *
 * 必須fieldの欠落を成功扱いにしない。
 *
 * @param[in] parent XPathの基点node。
 * @param[in] xpath 固定schema XPath。
 * @param[out] node 成功時の単一node。
 * @return Node取得時S_OK、未取得時E_FAIL、API失敗時HRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT selectSingleNode( IXMLDOMNode &parent, const std::wstring_view xpath,
									   ComPtr<IXMLDOMNode> &node)
{
	node.Reset() ;
	UniqueBstr	  query( xpath) ;											// selectSingleNode呼出し中だけ所有するXPath。
	const HRESULT result = parent.selectSingleNode( query.get(), &node) ;	// Node取得結果。
	return SUCCEEDED( result) && node == nullptr ? E_FAIL : result ;
}

//------------------------------------------------------------------------------
/**
 * @brief XPathに一致するnode群を取得する。
 *
 * 件数上限を呼出し側が検証できるlistだけを返す。
 *
 * @param[in] parent XPathの基点node。
 * @param[in] xpath 固定schema XPath。
 * @param[out] nodes 成功時のnode list。
 * @return List取得時S_OK、null listはE_FAIL、API失敗時HRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT selectNodes( IXMLDOMNode &parent, const std::wstring_view xpath,
								  ComPtr<IXMLDOMNodeList> &nodes)
{
	nodes.Reset() ;
	UniqueBstr	  query( xpath) ;										// selectNodes呼出し中だけ所有するXPath。
	const HRESULT result = parent.selectNodes( query.get(), &nodes) ;	// List取得結果。
	return SUCCEEDED( result) && nodes == nullptr ? E_FAIL : result ;
}

//------------------------------------------------------------------------------
/**
 * @brief Node本文を上限付きで取得する。
 *
 * 埋込みnullと制御文字を拒否し、表示値の上限を強制する。
 *
 * @param[in] node 本文を取得するXML node。
 * @param[in] maximumCharacters 許容文字数上限。
 * @param[out] text 成功時のASCII空白除去済み本文。
 * @return 有効な非空本文は0、不正値はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readNodeText( IXMLDOMNode &node, const std::size_t maximumCharacters,
									   std::wstring &text)
{
	text.clear() ;
	BSTR		  raw{} ;							// SysFreeStringで解放するnode本文。
	const HRESULT result = node.get_text( &raw) ;	// Text取得結果。
	// 本文取得失敗や欠落時は返却BSTRを解放し、成功値のまま返さない。
	if( FAILED( result) || raw == nullptr) {
		SysFreeString( raw) ;
		return nativeError( FAILED( result) ? result : E_FAIL) ;
	}

	std::wstring value( raw, SysStringLen( raw)) ;	// BSTR lifetimeから独立した本文。
	SysFreeString( raw) ;
	// 先頭のASCII空白を除いた開始位置。元入力のiteratorを同期処理中だけ使用する。
	const auto first = std::find_if_not( value.begin(), value.end(), []( const wchar_t character) {
		return character == L' ' || character == L'\t' ;
	}) ;
	// 末尾のASCII空白を除いた終端位置。元入力のiteratorを同期処理中だけ使用する。
	const auto last = std::find_if_not( value.rbegin(), value.rend(), []( const wchar_t character) {
						  return character == L' ' || character == L'\t' ;
					  }).base() ;
	// 前後の空白を除いて本文が残らないnodeを拒否する。
	if( first >= last) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	value = std::wstring( first, last) ;
	// 上限超過や制御文字を含むnode本文をmetadataとして採用しない。
	if( value.size() > maximumCharacters ||
	   std::any_of( value.begin(), value.end(),
				   []( const wchar_t character) { return character < L' ' ; })) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	text = std::move( value) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 必須XPath nodeの本文を取得する。
 *
 * 必須fieldのselectと本文検証を同じ順序で実行する。
 *
 * @param[in] parent XPathの基点node。
 * @param[in] xpath 必須fieldの固定XPath。
 * @param[in] maximumCharacters 本文文字数上限。
 * @param[out] text 成功時の本文。
 * @return Nodeと本文が有効なら0、それ以外はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRequiredText( IXMLDOMNode &parent, const std::wstring_view xpath,
										   const std::size_t maximumCharacters, std::wstring &text)
{
	ComPtr<IXMLDOMNode> node ;												// XPathへ一致した必須node。
	const HRESULT		result = selectSingleNode( parent, xpath, node) ;	// Node取得結果。
	return FAILED( result) ? nativeError( result)
						  : readNodeText( *node.Get(), maximumCharacters, text) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Nodeの必須attributeを取得する。
 *
 * 暗黙の既定値を許可せずdeviceとSoftPaqの対応を固定する。
 *
 * @param[in] node Attributeを持つXML node。
 * @param[in] name 必須attribute名。
 * @param[in] maximumCharacters 値の文字数上限。
 * @param[out] value 成功時の文字列値。
 * @return 非空attribute取得時は0、それ以外はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRequiredAttribute( IXMLDOMNode &node, const std::wstring_view name,
												const std::size_t maximumCharacters,
												std::wstring	 &value)
{
	ComPtr<IXMLDOMNamedNodeMap> attributes ;									// Nodeのattribute map。
	HRESULT						result = node.get_attributes( &attributes) ;	// Map取得結果。
	// attribute集合を取得できなければ必須属性の解析を中止する。
	if( FAILED( result) || attributes == nullptr) {
		return nativeError( FAILED( result) ? result : E_FAIL) ;
	}

	UniqueBstr			attributeName( name) ;	// getNamedItem呼出し中だけ所有する名前。
	ComPtr<IXMLDOMNode> attribute ;				// 必須attribute node。
	result = attributes->getNamedItem( attributeName.get(), &attribute) ;
	// 指定attributeの取得失敗と欠落を必須metadataの失敗として扱う。
	if( FAILED( result) || attribute == nullptr) {
		return nativeError( FAILED( result) ? result : E_FAIL) ;
	}

	return readNodeText( *attribute.Get(), maximumCharacters, value) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 10進文字列を有限な64-bit値へ変換する。
 *
 * Overflow、符号、0をcatalog metadataへ入れない。
 *
 * @param[in] value ASCII 10進文字列。
 * @param[in] maximum 許可する最大値。
 * @return 1以上maximum以下なら変換値、それ以外はnullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::uint64_t> parseUnsigned( const std::wstring_view value,
														 const std::uint64_t	 maximum) noexcept
{
	// 空、桁数超過、無効な上限を数値変換前に拒否する。
	if( value.empty() || value.size() > 20 || maximum == 0) {
		return std::nullopt ;
	}

	std::uint64_t parsed{} ;	// 現在桁までの変換値。
	// 上限内の10進文字列を先頭から一桁ずつ検証して蓄積する。
	for( const wchar_t character : value) {
		// 10進数字以外を数値へ暗黙変換しない。
		if( character < L'0' || character > L'9') {
			return std::nullopt ;
		}

		const std::uint64_t digit = static_cast<std::uint64_t>( character - L'0') ;	// 現在桁。
		// 桁の乗算と加算前に上限超過を検出する。
		if( parsed > (maximum - std::min( maximum, digit)) / 10) {
			return std::nullopt ;
		}

		parsed = parsed * 10 + digit ;
		// 加算後も要求上限を超えないことを確認する。
		if( parsed > maximum) {
			return std::nullopt ;
		}
	}

	return parsed == 0 ? std::nullopt : std::optional<std::uint64_t>( parsed) ;
}

//------------------------------------------------------------------------------
/**
 * @brief HP Platform IDを大文字4桁hexへ正規化する。
 *
 * File名構築へ任意文字を入れず、HPの固定ID形式だけを許可する。
 *
 * @param[in] value LocalまたはcatalogのPlatform ID。
 * @return 4桁大文字hex、形式不正時はnullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> normalizeSystemId( const std::wstring_view value)
{
	// HP Platform IDの固定4桁形式に合わない値を拒否する。
	if( value.size() != 4) {
		return std::nullopt ;
	}

	std::wstring normalized ;	// 大文字ASCII hexへ変換するID。
	normalized.reserve( value.size()) ;
	// 4桁を検証しながら照合用の大文字hex表現へ揃える。
	for( const wchar_t character : value) {
		// hexの数字部分はそのまま照合keyへ保持する。
		if( character >= L'0' && character <= L'9') {
			normalized.push_back( character) ;
		}
		// 小文字hexを照合用の大文字へ揃える。
		else if( character >= L'a' && character <= L'f') {
			normalized.push_back( static_cast<wchar_t>( character - L'a' + L'A')) ;
		}
		// 既に大文字のhexは変換せず保持する。
		else if( character >= L'A' && character <= L'F') {
			normalized.push_back( character) ;
		} else {
			return std::nullopt ;
		}
	}

	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief File名用release IDを小文字ASCIIへ正規化する。
 *
 * Path separatorやdotをreference URLへ混入させない。
 *
 * @param[in] value Platform listのOSReleaseIdFilename。
 * @return 1～16文字の小文字英数字、形式不正時はnullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> normalizeReleaseId( const std::wstring_view value)
{
	// 空または長すぎるrelease IDをfile名へ使用しない。
	if( value.empty() || value.size() > 16) {
		return std::nullopt ;
	}

	std::wstring normalized ;	// URL構築用の小文字英数字。
	normalized.reserve( value.size()) ;
	// release IDの各文字をASCII英数字に制限して小文字へ揃える。
	for( const wchar_t character : value) {
		// release IDの数字を変更せず保持する。
		if( character >= L'0' && character <= L'9') {
			normalized.push_back( character) ;
		}
		// 小文字英字は正規形として保持する。
		else if( character >= L'a' && character <= L'z') {
			normalized.push_back( character) ;
		}
		// 大文字英字をfile名用の小文字へ揃える。
		else if( character >= L'A' && character <= L'Z') {
			normalized.push_back( static_cast<wchar_t>( character - L'A' + L'a')) ;
		} else {
			return std::nullopt ;
		}
	}

	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief SHA-256文字列を小文字ASCIIへ正規化する。
 *
 * Unicode類似文字とhash長の推測補完を拒否する。
 *
 * @param[in] value ReferenceのSHA-256文字列。
 * @return 64桁小文字hex、形式不正時はnullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> normalizeSha256( const std::wstring_view value)
{
	// SHA-256の固定64桁に合わない値を拒否する。
	if( value.size() != 64) {
		return std::nullopt ;
	}

	std::wstring normalized ;	// 小文字ASCIIへ変換するhash。
	normalized.reserve( value.size()) ;
	// SHA-256の全桁をhexとして検証し小文字へ揃える。
	for( const wchar_t character : value) {
		// 数字と小文字hexは正規形として保持する。
		if( (character >= L'0' && character <= L'9') || (character >= L'a' && character <= L'f')) {
			normalized.push_back( character) ;
		}
		// 大文字hexだけを小文字へ変換する。
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
 * @brief Catalog側Hardware IDを完全一致用ASCIIへ正規化する。
 *
 * Wildcardと非ASCIIを推測照合せず、local matcher専用にする。
 *
 * @param[in] value HP referenceのDeviceId。
 * @return 大文字化した完全ID、unsupported表現時はnullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> normalizeHardwareId( const std::wstring_view value)
{
	// 長さや区切りが不正、またはwildcardを含むcatalog側IDを拒否する。
	if( value.size() < 3 || value.size() > 512 || value.find( L'\\') == std::wstring_view::npos ||
	   value.find( L'*') != std::wstring_view::npos || value.find( L'?') != std::wstring_view::npos) {
		return std::nullopt ;
	}

	std::wstring normalized ;	// ASCII大文字へ変換するHardware ID。
	normalized.reserve( value.size()) ;
	// catalog側Hardware IDを印字可能ASCIIへ制限して照合用に正規化する。
	for( const wchar_t character : value) {
		// 制御文字と非ASCII文字をHardware ID照合keyへ含めない。
		if( character < L' ' || character > L'~') {
			return std::nullopt ;
		}

		normalized.push_back( character >= L'a' && character <= L'z'
								 ? static_cast<wchar_t>( character - L'a' + L'A')
								 : character) ;
	}

	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief SoftPaq IDがopaque identityへ安全に使用できるか判定する。
 *
 * URLやpathとして解釈される文字をpackage identityへ入れない。
 *
 * @param[in] value ReferenceのSoftPaq ID。
 * @return `sp`と1～10桁の10進数字だけならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafeSoftpaqId( const std::wstring_view value) noexcept
{
	return value.size() >= 3 && value.size() <= 12 && value[0] == L's' && value[1] == L'p' &&
		   std::all_of( value.begin() + 2, value.end(), []( const wchar_t character) {
			   return character >= L'0' && character <= L'9' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Driver categoryかを判定する。
 *
 * BIOS、firmware、softwareを名称推測でdriverへ含めない。
 *
 * @param[in] value HP referenceのCategory。
 * @return 対象PC device向け`Driver`分類の場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isDriverCategory( const std::wstring_view value) noexcept
{
	constexpr std::wstring_view PREFIX = L"Driver - " ;	// HPのdriver分類prefix。
	constexpr std::array		EXCLUDED{L"Driver - Dock", L"Driver - Printer",
									 L"Driver - Scanner"} ;	// 別Providerへ分離する分類。
	// 明示されたdriver分類または許可prefixに合致するcategoryかを示す。
	const bool					driver = value == L"Driver" ||
						(value.size() > PREFIX.size() && value.substr( 0, PREFIX.size()) == PREFIX) ;
	return driver && std::find( EXCLUDED.begin(), EXCLUDED.end(), value) == EXCLUDED.end() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 説明文がfirmware同梱を明記しているか判定する。
 *
 * Driver分類でもfirmwareを同梱するSoftPaqを初期版から除外する。
 *
 * @param[in] value HP referenceのDescription。
 * @return 大文字小文字を除いて`FIRMWARE`を含む場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool containsFirmware( const std::wstring_view value) noexcept
{
	constexpr std::wstring_view TARGET = L"FIRMWARE" ;	// 除外判断するASCII語。
	std::wstring				normalized ;			// 大文字化したDescription。
	normalized.reserve( value.size()) ;
	// 説明文を大文字へ揃えてfirmware表記の大小文字差を除く。
	for( const wchar_t character : value) {
		normalized.push_back( static_cast<wchar_t>( std::towupper( character))) ;
	}

	return normalized.find( TARGET) != std::wstring::npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief Version表示値が有限な安全文字列か判定する。
 *
 * Versionをpathへ使用せず、比較不能表記はbrowse-onlyにできる。
 *
 * @param[in] value HP referenceのVersion。
 * @return 1～128文字の許可ASCIIだけならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafeVersion( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= 128 &&
		   std::all_of( value.begin(), value.end(), []( const wchar_t character) {
			   return (character >= L'a' && character <= L'z') ||
					  (character >= L'A' && character <= L'Z') ||
					  (character >= L'0' && character <= L'9') || character == L'.' ||
					  character == L'-' || character == L'_' || character == L' ' ||
					  character == L'(' || character == L')' || character == L'+' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief YYYY-MM-DD形式の日付を検証する。
 *
 * 表示日付を推測変換せず、無効月日を拒否する。
 *
 * @param[in] value ReferenceのDateReleased。
 * @return Calendar上有効な固定形式日付ならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidReleaseDate( const std::wstring_view value) noexcept
{
	// 日付の固定長と区切り位置が違う値を拒否する。
	if( value.size() != 10 || value[4] != L'-' || value[7] != L'-') {
		return false ;
	}

	constexpr std::array<std::size_t, 8> INDEXES{0, 1, 2, 3, 5, 6, 8, 9} ;	// 数字位置。
	// 年月日の各数値位置だけを検証する。
	for( const std::size_t index : INDEXES) {
		// 年月日に数字以外を含む日付を拒否する。
		if( value[index] < L'0' || value[index] > L'9') {
			return false ;
		}
	}

	SYSTEMTIME time{} ;	// SystemTimeToFileTimeでcalendar検証する日付。
	time.wYear	= static_cast<WORD>( (value[0] - L'0') * 1000 + (value[1] - L'0') * 100 +
									(value[2] - L'0') * 10 + (value[3] - L'0')) ;
	time.wMonth = static_cast<WORD>( (value[5] - L'0') * 10 + (value[6] - L'0')) ;
	time.wDay	= static_cast<WORD>( (value[8] - L'0') * 10 + (value[9] - L'0')) ;
	FILETIME converted{} ;	// Calendar検証用の未使用変換結果。
	return SystemTimeToFileTime( &time, &converted) != FALSE ;
}

//------------------------------------------------------------------------------
/**
 * @brief HP payload URLを固定originとSoftPaq名へ制限する。
 *
 * HPのlegacy scheme省略表記だけをHTTPSへ固定変換する。
 *
 * @param[in] value ReferenceのUrl。
 * @param[in] softpaqId 検証済みSoftPaq ID。
 * @return 許可されたHTTPS URL、形式不正時はnullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> normalizePayloadUrl( const std::wstring_view value,
															  const std::wstring_view softpaqId)
{
	constexpr std::wstring_view LEGACY_PREFIX = L"ftp.hp.com/pub/softpaq/" ;	// HP schema表記。
	std::wstring				url ;											// HTTPSへ正規化するpayload URL。
	// 既知のschemeなし公式prefixだけにHTTPS schemeを補う。
	if( value.size() > LEGACY_PREFIX.size() &&
	   value.substr( 0, LEGACY_PREFIX.size()) == LEGACY_PREFIX) {
		url = L"https://" + std::wstring( value) ;
	} else {
		url = std::wstring( value) ;
	}

	const std::span<const std::wstring_view> hosts =
		// 公式host群。
		officialSourceHosts( HP_PROVIDER_ID, OFFICIAL_PAYLOAD_RESOURCE_ID) ;
	const std::wstring expectedName = L"/" + std::wstring( softpaqId) + L".exe" ;	// 末尾名。
	// 公式origin、SoftPaq名、path形式を限定し、迂回表現を含むURLを拒否する。
	if( validateOfficialHttpsUrl( url, hosts) != 0 || url.size() <= PAYLOAD_PREFIX.size() ||
	   url.substr( 0, PAYLOAD_PREFIX.size()) != PAYLOAD_PREFIX || url.size() < expectedName.size() ||
	   url.substr( url.size() - expectedName.size()) != expectedName ||
	   url.find( L"..") != std::wstring::npos || url.find( L'\\') != std::wstring::npos ||
	   url.find( L'?') != std::wstring::npos || url.find( L'#') != std::wstring::npos) {
		return std::nullopt ;
	}

	return url ;
}

//------------------------------------------------------------------------------
/**
 * @brief Node listの有限な件数を取得する。
 *
 * 外部metadataで無制限loopを開始しない。
 *
 * @param[in] nodes 件数を取得するMSXML list。
 * @param[in] maximum 許可するnode数上限。
 * @param[out] length 成功時の0以上の件数。
 * @return 上限内なら0、APIまたは上限違反時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readListLength( IXMLDOMNodeList &nodes, const std::size_t maximum,
										 long &length)
{
	length				 = 0 ;
	const HRESULT result = nodes.get_length( &length) ;	// MSXML list件数取得結果。
	// node件数の取得失敗、負数、上限超過を列挙前に拒否する。
	if( FAILED( result) || length < 0 || static_cast<std::size_t>( length) > maximum) {
		return nativeError( FAILED( result) ? result : HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
	}

	return 0 ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/hp_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError parseHpPlatformCatalog( const std::wstring_view xmlUtf16,
								   const std::wstring_view systemId, const std::uint32_t osBuild,
								   HpPlatformReference &reference)
{
	reference									 = {} ;
	const std::optional<std::wstring> expectedId = normalizeSystemId( systemId) ;	// 期待ID。
	// 正規化可能なplatform IDと有効なOS buildがなければ照合しない。
	if( !expectedId.has_value() || osBuild == 0) {
		return nativeError( E_INVALIDARG) ;
	}

	ComPtr<IXMLDOMDocument2> document ;	// Security設定済みHP platform DOM。
	// XML documentの有限読込みからcatalog検証へ引き継ぐ診断値。
	NativeError				 error =
		loadOfficialXmlDocument( xmlUtf16, {.maximumCharacters = MAXIMUM_XML_CHARACTERS}, document) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	ComPtr<IXMLDOMNode> root ;													// `/ImagePal` root node。
	HRESULT result = selectSingleNode( *document.Get(), L"/ImagePal", root) ;	// Root取得結果。
	// XML rootの取得失敗を保持してplatform検索を中止する。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	ComPtr<IXMLDOMNodeList> platforms ;	// Platform entry群。
	result = selectNodes( *root.Get(), L"Platform", platforms) ;
	// platform集合の取得失敗時は候補なしとして処理しない。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	long platformCount{} ;	// 検証済みPlatform node数。
	error = readListLength( *platforms.Get(), MAXIMUM_PLATFORMS, platformCount) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	bool found{} ;	// 端末ID、x64、buildへ一致するentryを取得済みならtrue。
	// 全Platformを有限回だけ走査し、要求IDに一致するOS entryだけを解析する。
	for( long platformIndex = 0; platformIndex < platformCount; ++platformIndex) {
		ComPtr<IXMLDOMNode> platform ;	// 現在解析するPlatform node。
		result = platforms->get_item( platformIndex, &platform) ;
		// platform nodeの取得失敗や欠落をcatalog失敗として返す。
		if( FAILED( result) || platform == nullptr) {
			return nativeError( FAILED( result) ? result : E_FAIL) ;
		}

		std::wstring catalogId ;	// Platform entryのSystemID。
		error = readRequiredText( *platform.Get(), L"SystemID", 4, catalogId) ;
		const std::optional<std::wstring> normalizedId =
			// 検証済みentry ID。
			error == 0 ? normalizeSystemId( catalogId) : std::nullopt ;
		// platform IDが取得不能または不正ならreferenceを採用しない。
		if( error != 0 || !normalizedId.has_value()) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// 端末のplatform IDと異なる項目は対象外とする。
		if( normalizedId.value() != expectedId.value()) {
			continue ;
		}

		ComPtr<IXMLDOMNodeList> operatingSystems ;	// Platformに対応するOS entry群。
		result = selectNodes( *platform.Get(), L"OS", operatingSystems) ;
		// 対応OS集合を取得できなければplatform照合を中止する。
		if( FAILED( result)) {
			return nativeError( result) ;
		}

		long osCount{} ;	// 検証済みOS node数。
		error = readListLength( *operatingSystems.Get(), 256, osCount) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		// 同じPlatform IDの全OSからx64かつbuild完全一致entryを探す。
		for( long osIndex = 0; osIndex < osCount; ++osIndex) {
			ComPtr<IXMLDOMNode> operatingSystem ;	// 現在解析するOS node。
			result = operatingSystems->get_item( osIndex, &operatingSystem) ;
			// OS nodeの取得失敗や欠落を黙って読み飛ばさない。
			if( FAILED( result) || operatingSystem == nullptr) {
				return nativeError( FAILED( result) ? result : E_FAIL) ;
			}

			std::wstring architecture ;	// Platform listのarchitecture値。
			std::wstring buildText ;	// Platform listの10進build値。
			error = readRequiredText( *operatingSystem.Get(), L"OSArchitecture", 8, architecture) ;
			// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
			if( error == 0) {
				error = readRequiredText( *operatingSystem.Get(), L"OSBuildId", 10, buildText) ;
			}

			const std::optional<std::uint64_t> parsedBuild =
				error == 0 ? parseUnsigned( buildText, std::numeric_limits<std::uint32_t>::max())
						   : std::nullopt ;	// 検証済みbuild値。
			// OS buildの取得または数値化に失敗したreferenceを拒否する。
			if( error != 0 || !parsedBuild.has_value()) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// x64と端末buildに一致しないOS項目を除外する。
			if( architecture != L"64" || parsedBuild.value() != osBuild) {
				continue ;
			}

			HpPlatformReference parsed ;	// 現在entryから構築するreference。
			parsed.systemId = expectedId.value() ;
			parsed.osBuild	= osBuild ;
			error = readRequiredText( *operatingSystem.Get(), L"OSVersion", 8, parsed.osVersion) ;
			std::wstring releaseText ;	// URL file名に使う未正規化release ID。
			// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
			if( error == 0) {
				error = readRequiredText( *operatingSystem.Get(), L"OSReleaseIdFilename", 16,
										 releaseText) ;
			}

			const std::optional<std::wstring> release =
				// 正規化ID。
				error == 0 ? normalizeReleaseId( releaseText) : std::nullopt ;
			// release IDと対応OS版の形式が整合しないreferenceを拒否する。
			if( error != 0 || !release.has_value() ||
			   (parsed.osVersion != L"10.0" && parsed.osVersion != L"11.0")) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			parsed.releaseId = release.value() ;
			// 同じ検索条件に異なるreferenceが一致した場合は曖昧性を拒否する。
			if( found &&
			   (reference.systemId != parsed.systemId || reference.osVersion != parsed.osVersion ||
				reference.releaseId != parsed.releaseId || reference.osBuild != parsed.osBuild)) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			reference = std::move( parsed) ;
			found	  = true ;
		}
	}

	return found ? 0 : nativeErrorFromWin32( ERROR_NOT_FOUND) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/hp_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError parseHpReferenceCatalog( const std::wstring_view		  xmlUtf16,
									const HpPlatformReference	 &reference,
									std::vector<HpDriverRelease> &releases)
{
	releases.clear() ;
	const std::optional<std::wstring> expectedId = normalizeSystemId( reference.systemId) ;	// ID。
	const std::optional<std::wstring> expectedRelease =
		// Release ID。
		normalizeReleaseId( reference.releaseId) ;
	// referenceのplatform、release、build、OS版をpayload解析前に検証する。
	if( !expectedId.has_value() || !expectedRelease.has_value() || reference.osBuild == 0 ||
	   (reference.osVersion != L"10.0" && reference.osVersion != L"11.0")) {
		return nativeError( E_INVALIDARG) ;
	}

	ComPtr<IXMLDOMDocument2> document ;	// Security設定済みHP reference DOM。
	// XML documentの有限読込みからpackage metadata検証へ引き継ぐ診断値。
	NativeError				 error =
		loadOfficialXmlDocument( xmlUtf16, {.maximumCharacters = MAXIMUM_XML_CHARACTERS}, document) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	ComPtr<IXMLDOMNode> root ;													// `/ImagePal` root node。
	HRESULT result = selectSingleNode( *document.Get(), L"/ImagePal", root) ;	// Root取得結果。
	// reference XMLのroot取得失敗時はdriver変換へ進めない。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	std::wstring hpReference ;	// HP公式reference識別値。
	error = readRequiredText( *root.Get(), L"HPReference", 8, hpReference) ;
	ComPtr<IXMLDOMNode> system ;	// ReferenceのSystemInfo/System node。
	// 先行metadataが正常な場合だけSystem nodeを取得する。
	if( error == 0) {
		result = selectSingleNode( *root.Get(), L"SystemInfo/System", system) ;
		error  = FAILED( result) ? nativeError( result) : 0 ;
	}

	std::wstring catalogId ;	// Reference内SystemID。
	std::wstring architecture ;	// Reference内OSArchitecture。
	std::wstring buildText ;	// Reference内OSBuildNumber。
	std::wstring displayValue ;	// Reference内DisplayVersion。
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = readRequiredText( *system.Get(), L"SystemID", 4, catalogId) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = readRequiredText( *system.Get(), L"OSArchitecture", 16, architecture) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = readRequiredText( *system.Get(), L"OSBuildNumber", 10, buildText) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = readRequiredText( *system.Get(), L"DisplayVersion", 16, displayValue) ;
	}

	const std::optional<std::wstring> parsedId =
		// Reference ID。
		error == 0 ? normalizeSystemId( catalogId) : std::nullopt ;
	const std::optional<std::wstring> parsedRelease =
		// Reference release。
		error == 0 ? normalizeReleaseId( displayValue) : std::nullopt ;
	const std::optional<std::uint64_t> parsedBuild =
		error == 0 ? parseUnsigned( buildText, std::numeric_limits<std::uint32_t>::max())
				   : std::nullopt ;	// Reference build。
	// referenceの由来、platform、release、build、x64が期待値へ一致することを確認する。
	if( error != 0 || hpReference != L"Yes" || !parsedId.has_value() || !parsedRelease.has_value() ||
	   !parsedBuild.has_value() || parsedId.value() != expectedId.value() ||
	   parsedRelease.value() != expectedRelease.value() ||
	   parsedBuild.value() != reference.osBuild || architecture != L"64-bit") {
		return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	ComPtr<IXMLDOMNodeList> solutions ;	// Root直下の全SoftPaq metadata群。
	result = selectNodes( *root.Get(), L"Solutions/UpdateInfo", solutions) ;
	// solution集合を取得できなければdriver候補を作らない。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	long solutionCount{} ;	// 検証済みSoftPaq node数。
	error = readListLength( *solutions.Get(), MAXIMUM_SOLUTIONS, solutionCount) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	std::unordered_set<std::wstring>			  knownIds ;		// 全分類の一意なSoftPaq ID集合。
	std::unordered_map<std::wstring, std::size_t> driverIndexes ;	// Driver IDと出力index。
	knownIds.reserve( static_cast<std::size_t>( solutionCount)) ;
	driverIndexes.reserve( static_cast<std::size_t>( solutionCount)) ;
	releases.reserve( static_cast<std::size_t>( solutionCount)) ;
	// Root solutionを一度だけ解析し、driver分類だけをpayload metadataへ変換する。
	for( long solutionIndex = 0; solutionIndex < solutionCount; ++solutionIndex) {
		ComPtr<IXMLDOMNode> solution ;	// 現在解析するSoftPaq node。
		result = solutions->get_item( solutionIndex, &solution) ;
		// solution nodeの取得失敗や欠落をcatalog失敗として返す。
		if( FAILED( result) || solution == nullptr) {
			return nativeError( FAILED( result) ? result : E_FAIL) ;
		}

		std::wstring id ;		// SoftPaq ID。
		std::wstring category ;	// SoftPaq分類。
		error = readRequiredText( *solution.Get(), L"Id", 12, id) ;
		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = readRequiredText( *solution.Get(), L"Category", 128, category) ;
		}

		// SoftPaq IDの不正や重複を拒否し、別packageを同一視しない。
		if( error != 0 || !isSafeSoftpaqId( id) || !knownIds.insert( id).second) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// driver以外のcategoryを導入候補から除外する。
		if( !isDriverCategory( category)) {
			continue ;
		}

		std::wstring description ;	// Firmware同梱を除外する署名済み説明文。
		error = readRequiredText( *solution.Get(), L"Description", 4096, description) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		// firmware同梱を明記したsolutionをdriver候補へ戻さない。
		if( containsFirmware( description)) {
			continue ;
		}

		HpDriverRelease release ;	// 検証後に出力へ追加するdriver metadata。
		release.softpaqId = id ;
		release.category  = category ;
		std::wstring releaseType ;	// Critical／Recommended／Routine分類。
		std::wstring urlText ;		// Scheme省略を許すHP schema URL。
		std::wstring hashText ;		// 未正規化SHA-256。
		std::wstring sizeText ;		// 10進payload byte数。
		error = readRequiredText( *solution.Get(), L"Name", 512, release.title) ;
		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = readRequiredText( *solution.Get(), L"Version", 128, release.version) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = readRequiredText( *solution.Get(), L"Vendor", 256, release.vendor) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = readRequiredText( *solution.Get(), L"ReleaseType", 32, releaseType) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = readRequiredText( *solution.Get(), L"Url", 2048, urlText) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = readRequiredText( *solution.Get(), L"SHA256", 64, hashText) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = readRequiredText( *solution.Get(), L"Size", 20, sizeText) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = readRequiredText( *solution.Get(), L"DateReleased", 10, release.releaseDate) ;
		}

		const std::optional<std::wstring> url =
			// HTTPS payload URL。
			error == 0 ? normalizePayloadUrl( urlText, id) : std::nullopt ;
		const std::optional<std::wstring> hash =
			// 小文字hash。
			error == 0 ? normalizeSha256( hashText) : std::nullopt ;
		const std::optional<std::uint64_t> size =
			// Size。
			error == 0 ? parseUnsigned( sizeText, MAXIMUM_PAYLOAD_BYTES) : std::nullopt ;
		const bool knownReleaseType = releaseType == L"Critical" || releaseType == L"Recommended" ||
									  // 初期版が解釈するHP release type。
									  releaseType == L"Routine" ;
		// 版、公式URL、hash、size、release種別、日付が揃わないpayloadを拒否する。
		if( error != 0 || !isSafeVersion( release.version) || !url.has_value() || !hash.has_value() ||
		   !size.has_value() || !knownReleaseType || !isValidReleaseDate( release.releaseDate)) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		release.installerUrl = url.value() ;
		release.sha256		 = hash.value() ;
		release.size		 = size.value() ;
		release.recommended	 = releaseType == L"Critical" || releaseType == L"Recommended" ;
		driverIndexes.emplace( release.softpaqId, releases.size()) ;
		releases.push_back( std::move( release)) ;
	}

	ComPtr<IXMLDOMNodeList> devices ;	// Catalog側DeviceIdとSoftPaq参照群。
	result = selectNodes( *root.Get(), L"Devices/Device", devices) ;
	// device対応集合の取得失敗を候補なしと区別する。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	long deviceCount{} ;	// 検証済みDevice node数。
	error = readListLength( *devices.Get(), MAXIMUM_DEVICES, deviceCount) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	// DeviceIdとnested IdRefだけを読み、端末側IDをcatalog parserへ渡さない。
	for( long deviceIndex = 0; deviceIndex < deviceCount; ++deviceIndex) {
		ComPtr<IXMLDOMNode> device ;	// 現在解析するDevice node。
		result = devices->get_item( deviceIndex, &device) ;
		// device nodeを取得できなければ対応関係を推測しない。
		if( FAILED( result) || device == nullptr) {
			return nativeError( FAILED( result) ? result : E_FAIL) ;
		}

		std::wstring deviceId ;	// Catalogが宣言するHardware ID相当のDeviceId。
		error = readRequiredText( *device.Get(), L"DeviceId", 512, deviceId) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		const std::optional<std::wstring> hardwareId =
			// Local完全一致用ID。
			normalizeHardwareId( deviceId) ;
		ComPtr<IXMLDOMNodeList> references ;	// Deviceに対応するSoftPaq参照群。
		result = selectNodes( *device.Get(), L"Solutions/UpdateInfo", references) ;
		// deviceのsolution参照集合を取得できなければ解析を中止する。
		if( FAILED( result)) {
			return nativeError( result) ;
		}

		long referenceCount{} ;	// DeviceのSoftPaq参照数。
		error = readListLength( *references.Get(), 1024, referenceCount) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		// 全IdRefがroot solutionを参照することを確認し、driverだけへDeviceIdを付加する。
		for( long referenceIndex = 0; referenceIndex < referenceCount; ++referenceIndex) {
			ComPtr<IXMLDOMNode> solutionReference ;	// 現在解析するIdRef node。
			result = references->get_item( referenceIndex, &solutionReference) ;
			// solution参照nodeの欠落または取得失敗を拒否する。
			if( FAILED( result) || solutionReference == nullptr) {
				return nativeError( FAILED( result) ? result : E_FAIL) ;
			}

			std::wstring idReference ;	// Root SoftPaqを参照するID。
			error = readRequiredAttribute( *solutionReference.Get(), L"IdRef", 12, idReference) ;
			// 不正または未定義のSoftPaq参照をdeviceへ結び付けない。
			if( error != 0 || !isSafeSoftpaqId( idReference) || !knownIds.contains( idReference)) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			const auto driver = driverIndexes.find( idReference) ;	// Driver出力index検索結果。
			// 採用済みdriverと有効なcatalog側IDが揃った場合だけ対応を追加する。
			if( driver != driverIndexes.end() && hardwareId.has_value()) {
				std::vector<std::wstring> &ids = releases[driver->second].hardwareIds ;	// ID群。
				// 一driverに保持するHardware ID数の上限を守る。
				if( ids.size() >= MAXIMUM_HARDWARE_IDS) {
					return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
				}

				ids.push_back( hardwareId.value()) ;
			}
		}
	}

	// IDを重複排除し、local適用性を持たないSoftPaqを候補集合から除外する。
	for( HpDriverRelease &release : releases) {
		std::sort( release.hardwareIds.begin(), release.hardwareIds.end()) ;
		release.hardwareIds.erase(
			std::unique( release.hardwareIds.begin(), release.hardwareIds.end()),
			release.hardwareIds.end()) ;
	}

	std::erase_if( releases,
				  []( const HpDriverRelease &release) { return release.hardwareIds.empty() ; }) ;
	return 0 ;
}

} // namespace drivercrate
