//------------------------------------------------------------------------------
/**
 * @file lenovo_catalog_parser.cpp
 * @brief Lenovo公式catalog parser実装。
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
 * @note MSXML 6.0のDTDと外部参照を無効化し、Lenovo公式schemaのうちdriver候補とfile検証に必要な値だけを抽出します。任意commandは読み取りません。
 */
//------------------------------------------------------------------------------

#include "platform/lenovo_catalog_parser.h"

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

constexpr std::size_t	MAXIMUM_XML_CHARACTERS	   = 4U * 1024U * 1024U ;	// XML文字数上限。
constexpr std::size_t	MAXIMUM_CATALOG_REFERENCES = 4096U ;				// Model別参照数上限。
constexpr std::size_t	MAXIMUM_HARDWARE_IDS	   = 512U ;					// 一packageのID数上限。
constexpr std::uint64_t MAXIMUM_PACKAGE_BYTES =
	4ULL * 1024ULL * 1024ULL * 1024ULL ;	// 一payloadの4 GiB上限。
constexpr std::wstring_view DESCRIPTOR_PREFIX =
	L"https://download.lenovo.com/pccbbs/" ;	// 許可descriptor path prefix。

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
 * Schemaと数値検証の失敗をProvider共通表現へ揃える。
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
 * @brief NodeからXPathに一致する単一nodeを取得する。
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
 * @brief NodeからXPathに一致するnode群を取得する。
 *
 * 件数上限を呼出し側が確認できるlistだけを返す。
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
 * @brief Node本文を長さと制御文字検証付きで取得する。
 *
 * 埋込みnullと制御文字を拒否し、表示値の上限を強制する。
 *
 * @param[in] node 本文を取得するXML node。
 * @param[in] maximumCharacters 許容する文字数上限。
 * @param[out] text 成功時の前後ASCII空白除去済み本文。
 * @return 有効な非空本文は0、不正値はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readNodeText( IXMLDOMNode &node, const std::size_t maximumCharacters,
									   std::wstring &text)
{
	text.clear() ;
	BSTR		  raw{} ;							// SysFreeStringで解放するnode本文。
	const HRESULT result = node.get_text( &raw) ;	// Text取得結果。
	// 本文取得失敗や欠落時はBSTRを解放し、成功値のまま返さない。
	if( FAILED( result) || raw == nullptr) {
		SysFreeString( raw) ;
		return nativeError( FAILED( result) ? result : E_FAIL) ;
	}

	std::wstring value( raw, SysStringLen( raw)) ;	// BSTR lifetimeから独立した本文。
	SysFreeString( raw) ;
	// 先頭のASCII空白を除いた入力開始位置。元入力を同期探索中だけ借用する。
	const auto first = std::find_if_not( value.begin(), value.end(), []( const wchar_t character) {
		return character == L' ' || character == L'\t' ;
	}) ;
	// 末尾のASCII空白を除いた入力終端位置。元入力を同期探索中だけ借用する。
	const auto last = std::find_if_not( value.rbegin(), value.rend(), []( const wchar_t character) {
						  return character == L' ' || character == L'\t' ;
					  }).base() ;
	// 前後空白を除いて本文が残らないnodeを拒否する。
	if( first >= last) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	value = std::wstring( first, last) ;
	// 上限超過や制御文字を含む本文をmetadataにしない。
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
 * @brief Nodeの必須attributeを文字列として取得する。
 *
 * 型変換や暗黙の既定値を許可せずschemaを固定する。
 *
 * @param[in] node Attributeを持つXML node。
 * @param[in] name 必須attribute名。
 * @param[in] maximumCharacters 値の文字数上限。
 * @param[out] value 成功時の文字列値。
 * @return 非空BSTR attribute取得時は0、それ以外はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRequiredAttribute( IXMLDOMNode &node, const std::wstring_view name,
												const std::size_t maximumCharacters,
												std::wstring	 &value)
{
	value.clear() ;
	ComPtr<IXMLDOMNamedNodeMap> attributes ;									// Nodeが所有するattribute map。
	HRESULT						result = node.get_attributes( &attributes) ;	// Map取得結果。
	// 必須attribute集合を取得できなければ解析を中止する。
	if( FAILED( result) || attributes == nullptr) {
		return nativeError( FAILED( result) ? result : E_FAIL) ;
	}

	UniqueBstr			attributeName( name) ;	// getNamedItem呼出し中だけ所有する名前。
	ComPtr<IXMLDOMNode> attribute ;				// 必須attribute node。
	result = attributes->getNamedItem( attributeName.get(), &attribute) ;
	// 必須attributeの取得失敗と欠落をエラーとして返す。
	if( FAILED( result) || attribute == nullptr) {
		return nativeError( FAILED( result) ? result : E_FAIL) ;
	}

	return readNodeText( *attribute.Get(), maximumCharacters, value) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Nodeの任意attributeを取得する。
 *
 * `hide`の旧schema省略だけを明示的に扱えるようにする。
 *
 * @param[in] node Attributeを持つXML node。
 * @param[in] name 任意attribute名。
 * @param[in] maximumCharacters 値の文字数上限。
 * @param[out] value 存在時の文字列値、未存在時nullopt。
 * @return 有効または未存在なら0、不正値はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readOptionalAttribute( IXMLDOMNode &node, const std::wstring_view name,
												const std::size_t			 maximumCharacters,
												std::optional<std::wstring> &value)
{
	value.reset() ;
	ComPtr<IXMLDOMNamedNodeMap> attributes ;									// Nodeが所有するattribute map。
	HRESULT						result = node.get_attributes( &attributes) ;	// Map取得結果。
	// 任意attributeでも集合取得の失敗を欠落扱いにしない。
	if( FAILED( result) || attributes == nullptr) {
		return nativeError( FAILED( result) ? result : E_FAIL) ;
	}

	UniqueBstr			attributeName( name) ;	// getNamedItem呼出し中だけ所有する名前。
	ComPtr<IXMLDOMNode> attribute ;				// 存在する場合のattribute node。
	result = attributes->getNamedItem( attributeName.get(), &attribute) ;
	// 任意attributeの取得API失敗を診断値付きで返す。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	// 任意attributeの欠落は取得失敗と区別して許容する。
	if( attribute == nullptr) {
		return 0 ;
	}

	std::wstring	  text ;	// 検証済みattribute本文。
	// Attribute本文の上限付き読取り結果。後続の文字列検証前に確認する。
	const NativeError error = readNodeText( *attribute.Get(), maximumCharacters, text) ;
	// 取得と本文検証が成功した場合だけ任意値を公開する。
	if( error == 0) {
		value = std::move( text) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 10進文字列を有限な64-bit値へ変換する。
 *
 * Overflowと符号、空値、0を候補metadataへ入れない。
 *
 * @param[in] value ASCII 10進文字列。
 * @param[in] maximum 許可する最大値。
 * @return 1以上maximum以下なら変換値、それ以外はnullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::uint64_t> parseUnsigned( const std::wstring_view value,
														 const std::uint64_t	 maximum) noexcept
{
	// 空、桁数超過、無効上限を数値変換前に拒否する。
	if( value.empty() || value.size() > 20 || maximum == 0) {
		return std::nullopt ;
	}

	std::uint64_t parsed{} ;	// 現在桁までの変換値。
	// 上限内の10進文字列を先頭から一桁ずつ検証して蓄積する。
	for( const wchar_t character : value) {
		// 10進数字以外を数値として受理しない。
		if( character < L'0' || character > L'9') {
			return std::nullopt ;
		}

		const std::uint64_t digit = static_cast<std::uint64_t>( character - L'0') ;	// 現在桁。
		// 次桁の乗算と加算前に上限超過を検出する。
		if( parsed > (maximum - std::min( maximum, digit)) / 10) {
			return std::nullopt ;
		}

		parsed = parsed * 10 + digit ;
		// 加算後も要求上限に収まることを確認する。
		if( parsed > maximum) {
			return std::nullopt ;
		}
	}

	return parsed == 0 ? std::nullopt : std::optional<std::uint64_t>( parsed) ;
}

//------------------------------------------------------------------------------
/**
 * @brief SHA-256文字列を小文字ASCIIへ正規化する。
 *
 * Unicode類似文字とhash長の推測補完を拒否する。
 *
 * @param[in] value Catalogまたはdescriptorのhash文字列。
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
	// SHA-256の全桁を検証して小文字hexへ揃える。
	for( const wchar_t character : value) {
		// 数字と小文字hexを正規形として保持する。
		if( (character >= L'0' && character <= L'9') || (character >= L'a' && character <= L'f')) {
			normalized.push_back( character) ;
		}
		// 大文字hexだけを小文字へ揃える。
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
 * @brief Lenovo descriptor URLを固定originとpathへ制限する。
 *
 * Host allowlistに加えpccbbs配下と拡張子を固定する。
 *
 * @param[in] url Model catalogが提示した絶対URL。
 * @return 許可origin配下のqueryなしXML URLならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAllowedDescriptorUrl( const std::wstring_view url) noexcept
{
	const std::span<const std::wstring_view> hosts =
		officialSourceHosts( LENOVO_PROVIDER_ID,
							OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ;	// Descriptor公式host群。
	// descriptor URLを公式originと既知pathへ制限し、迂回表現を拒否する。
	if( validateOfficialHttpsUrl( url, hosts) != 0 || url.size() <= DESCRIPTOR_PREFIX.size() ||
	   url.substr( 0, DESCRIPTOR_PREFIX.size()) != DESCRIPTOR_PREFIX ||
	   url.find( L'?') != std::wstring_view::npos || url.find( L'#') != std::wstring_view::npos ||
	   url.find( L'\\') != std::wstring_view::npos || url.find( L"..") != std::wstring_view::npos ||
	   url.size() > 2048) {
		return false ;
	}

	constexpr std::wstring_view EXTENSION = L".xml" ;	// 必須descriptor拡張子。
	return url.size() > EXTENSION.size() && _wcsnicmp( url.data() + url.size() - EXTENSION.size(),
													  EXTENSION.data(), EXTENSION.size()) == 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Package IDがopaque identityの構成要素として安全か判定する。
 *
 * URLやlocal pathとして解釈できる文字を許可しない。
 *
 * @param[in] value DescriptorのPackage id。
 * @return 1～64文字のASCII英数字と「._-」だけならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafePackageId( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= 64 &&
		   std::all_of( value.begin(), value.end(), []( const wchar_t character) {
			   return (character >= L'a' && character <= L'z') ||
					  (character >= L'A' && character <= L'Z') ||
					  (character >= L'0' && character <= L'9') || character == L'.' ||
					  character == L'_' || character == L'-' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Installer basenameが安全なEXE名か判定する。
 *
 * Separator、query、親directory、別拡張子を拒否する。
 *
 * @param[in] value DescriptorのInstaller/File/Name。
 * @return 平坦なASCII 「.exe」 basenameならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafeInstallerName( const std::wstring_view value) noexcept
{
	// 長さ不正や親directory表現を含むinstaller名を拒否する。
	if( value.size() < 5 || value.size() > 255 || value.find( L"..") != std::wstring_view::npos) {
		return false ;
	}

	constexpr std::wstring_view EXTENSION = L".exe" ;	// 許可実行file拡張子。
	// EXE拡張子以外をこのinstaller経路で扱わない。
	if( _wcsnicmp( value.data() + value.size() - EXTENSION.size(), EXTENSION.data(),
				 EXTENSION.size()) != 0) {
		return false ;
	}

	return std::all_of( value.begin(), value.end(), []( const wchar_t character) {
		return (character >= L'a' && character <= L'z') ||
			   (character >= L'A' && character <= L'Z') ||
			   (character >= L'0' && character <= L'9') || character == L'.' || character == L'_' ||
			   character == L'-' ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief YYYY-MM-DD形式の日付を検証する。
 *
 * 表示日付を推測変換せず、無効月日を拒否する。
 *
 * @param[in] value DescriptorのReleaseDate。
 * @return Calendar上有効な固定形式日付ならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidReleaseDate( const std::wstring_view value) noexcept
{
	// 日付の固定長と区切り位置が不正な値を拒否する。
	if( value.size() != 10 || value[4] != L'-' || value[7] != L'-') {
		return false ;
	}

	// 年月日の数値位置だけを検証する。
	for( const std::size_t index : {0U, 1U, 2U, 3U, 5U, 6U, 8U, 9U}) {
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
 * @brief Lenovo SigningTimeをFILETIME整数へ変換する。
 *
 * 署名で保護されたUTC時刻としてcertificate chainへ渡す。
 *
 * @param[in] value `YYYY/MM/DD HH:MM:SS`形式の署名時刻。
 * @return 1601年起点100ns単位値、形式またはcalendar不正時nullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::uint64_t> parseSigningTime( const std::wstring_view value) noexcept
{
	// 署名時刻の固定長と日付・時刻の区切り位置を検証する。
	if( value.size() != 19 || value[4] != L'/' || value[7] != L'/' || value[10] != L' ' ||
	   value[13] != L':' || value[16] != L':') {
		return std::nullopt ;
	}

	// 固定timestamp内で十進数字を要求する文字位置の集合。
	constexpr std::array<std::size_t, 14> DIGIT_INDEXES{0, 1,  2,  3,  5,  6,  8,
														9, 11, 12, 14, 15, 17, 18} ;
	// 署名時刻の数値位置だけを検証する。
	for( const std::size_t index : DIGIT_INDEXES) {
		// 署名時刻に数字以外を含む値を拒否する。
		if( value[index] < L'0' || value[index] > L'9') {
			return std::nullopt ;
		}
	}

	SYSTEMTIME time{} ;	// SystemTimeToFileTimeへ渡すUTC署名時刻。
	time.wYear	 = static_cast<WORD>( (value[0] - L'0') * 1000 + (value[1] - L'0') * 100 +
									 (value[2] - L'0') * 10 + (value[3] - L'0')) ;
	time.wMonth	 = static_cast<WORD>( (value[5] - L'0') * 10 + (value[6] - L'0')) ;
	time.wDay	 = static_cast<WORD>( (value[8] - L'0') * 10 + (value[9] - L'0')) ;
	time.wHour	 = static_cast<WORD>( (value[11] - L'0') * 10 + (value[12] - L'0')) ;
	time.wMinute = static_cast<WORD>( (value[14] - L'0') * 10 + (value[15] - L'0')) ;
	time.wSecond = static_cast<WORD>( (value[17] - L'0') * 10 + (value[18] - L'0')) ;
	FILETIME converted{} ;	// Windows epoch表現へ変換した署名時刻。
	// WindowsがFILETIMEへ変換できない日時を採用しない。
	if( SystemTimeToFileTime( &time, &converted) == FALSE) {
		return std::nullopt ;
	}

	ULARGE_INTEGER ticks{} ;	// FILETIME High/Lowを結合した100ns単位値。
	ticks.LowPart  = converted.dwLowDateTime ;
	ticks.HighPart = converted.dwHighDateTime ;
	return ticks.QuadPart == 0 ? std::nullopt : std::optional<std::uint64_t>( ticks.QuadPart) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Catalog側Hardware IDを完全一致用ASCIIへ正規化する。
 *
 * Wildcardと非ASCIIを推測照合せず、local matcher専用にする。
 *
 * @param[in] value Descriptor由来のPnP Hardware ID。
 * @return 大文字化した完全ID、unsupported表現時はnullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> normalizeHardwareId( const std::wstring_view value)
{
	// 長さ、区切り、wildcardの有無を検証し、完全一致できるcatalog側IDだけを扱う。
	if( value.size() < 3 || value.size() > 512 || value.find( L'\\') == std::wstring_view::npos ||
	   value.find( L'*') != std::wstring_view::npos || value.find( L'?') != std::wstring_view::npos) {
		return std::nullopt ;
	}

	std::wstring normalized ;	// ASCII大文字へ変換するHardware ID。
	normalized.reserve( value.size()) ;
	// catalog側IDの各文字を検証して照合用の大文字へ揃える。
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

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/lenovo_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError parseLenovoModelCatalog( const std::wstring_view				 xmlUtf16,
									std::vector<LenovoCatalogReference> &references)
{
	references.clear() ;
	ComPtr<IXMLDOMDocument2> document ;	// Security設定済みLenovo catalog DOM。
	const OfficialXmlPolicy	 policy{.maximumCharacters	 = MAXIMUM_XML_CHARACTERS,
									.selectionNamespaces = {}} ;				// 共通XML policy。
	NativeError error = loadOfficialXmlDocument( xmlUtf16, policy, document) ;	// Parse結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	ComPtr<IXMLDOMNode> root ;													// `/packages` root node。
	HRESULT result = selectSingleNode( *document.Get(), L"/packages", root) ;	// Root取得結果。
	// catalog nodeの取得失敗を候補なしとして処理しない。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	std::wstring countText ;	// Catalogが宣言するpackage件数文字列。
	error = readRequiredAttribute( *root.Get(), L"count", 10, countText) ;
	const std::optional<std::uint64_t> declaredCount =	// 上限確認済み宣言件数。
		error == 0 ? parseUnsigned( countText, MAXIMUM_CATALOG_REFERENCES) : std::nullopt ;
	// 宣言件数を取得または数値化できないcatalogを拒否する。
	if( error != 0 || !declaredCount.has_value()) {
		return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	ComPtr<IXMLDOMNodeList> packages ;	// Catalog内package node群。
	result = selectNodes( *root.Get(), L"package", packages) ;
	// package集合の取得失敗は元の診断値で返す。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	long packageCount{} ;	// MSXMLが返すsigned package件数。
	result = packages->get_length( &packageCount) ;
	// 実node件数とcatalog宣言件数が一致することを確認する。
	if( FAILED( result) || packageCount < 0 ||
	   static_cast<std::uint64_t>( packageCount) != declaredCount.value()) {
		return nativeError( FAILED( result) ? result : E_FAIL) ;
	}

	std::unordered_map<std::wstring, std::size_t> byUrl ;	// URL別重複矛盾検出索引。
	references.reserve( static_cast<std::size_t>( packageCount)) ;
	// 検証済み件数のpackage参照を順に解析し、途中失敗時は全体を拒否する。
	for( long index = 0; index < packageCount; ++index) {
		ComPtr<IXMLDOMNode> package ;	// 現在解析するpackage参照node。
		result = packages->get_item( index, &package) ;
		// 参照nodeを取得できなければ途中までの出力を破棄する。
		if( FAILED( result) || package == nullptr) {
			references.clear() ;
			return nativeError( FAILED( result) ? result : E_FAIL) ;
		}

		LenovoCatalogReference reference ;	// 検証後に出力へ追加する参照。
		error = readRequiredText( *package.Get(), L"location", 2048, reference.descriptorUrl) ;
		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = readRequiredText( *package.Get(), L"category", 256, reference.category) ;
		}

		ComPtr<IXMLDOMNode> checksum ;	// Hash type attributeを持つchecksum node。
		// 先行metadataが正常な場合だけchecksum nodeを取得する。
		if( error == 0) {
			result = selectSingleNode( *package.Get(), L"checksum", checksum) ;
			// checksum取得失敗を後段のhash検証へ引き継ぐ。
			if( FAILED( result)) {
				error = nativeError( result) ;
			}
		}

		std::wstring hashType ;	// 必須`sha256` type文字列。
		std::wstring hashText ;	// Descriptor SHA-256原文。
		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = readRequiredAttribute( *checksum.Get(), L"type", 16, hashType) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = readNodeText( *checksum.Get(), 64, hashText) ;
		}

		const std::optional<std::wstring> hash =	// 小文字へ正規化したdescriptor hash。
			error == 0 ? normalizeSha256( hashText) : std::nullopt ;
		// SHA-256と許可descriptor URLを検証できなければ全参照を破棄する。
		if( error != 0 || _wcsicmp( hashType.c_str(), L"sha256") != 0 || !hash.has_value() ||
		   !isAllowedDescriptorUrl( reference.descriptorUrl)) {
			references.clear() ;
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		reference.sha256	= hash.value() ;
		const auto existing = byUrl.find( reference.descriptorUrl) ;	// 同一URLの既存参照。
		// 同じdescriptor URLが再出現した場合は既存metadataとの整合性を確認する。
		if( existing != byUrl.end()) {
			const LenovoCatalogReference &prior = references[existing->second] ;	// 既存metadata。
			// 同じ取得先のhashやcategoryが矛盾するcatalogを拒否する。
			if( prior.sha256 != reference.sha256 || prior.category != reference.category) {
				references.clear() ;
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			continue ;
		}

		byUrl.emplace( reference.descriptorUrl, references.size()) ;
		references.push_back( std::move( reference)) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/lenovo_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError parseLenovoPackageDescriptor( const std::wstring_view			 xmlUtf16,
										 const std::wstring_view			 descriptorUrl,
										 std::optional<LenovoDriverRelease> &release)
{
	release.reset() ;
	// 許可外descriptor URLをpackage解析の基準にしない。
	if( !isAllowedDescriptorUrl( descriptorUrl)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	ComPtr<IXMLDOMDocument2> document ;	// Security設定済みpackage descriptor DOM。
	const OfficialXmlPolicy	 policy{.maximumCharacters	 = MAXIMUM_XML_CHARACTERS,
									.selectionNamespaces = {}} ;				// 共通XML policy。
	NativeError error = loadOfficialXmlDocument( xmlUtf16, policy, document) ;	// Parse結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	ComPtr<IXMLDOMNode> root ;													// `/Package` root node。
	HRESULT result = selectSingleNode( *document.Get(), L"/Package", root) ;	// Root取得結果。
	// descriptor nodeの取得失敗を保持して解析を中止する。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	ComPtr<IXMLDOMNode> packageType ;	// PackageTypeとtype attribute。
	result = selectSingleNode( *root.Get(), L"PackageType", packageType) ;
	// package種別nodeを取得できなければ種別を推測しない。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	std::wstring packageTypeText ;	// Lenovo package type番号。
	error = readRequiredAttribute( *packageType.Get(), L"type", 2, packageTypeText) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	// 定義外のpackage種別をdriverとして解釈しない。
	if( packageTypeText != L"0" && packageTypeText != L"1" && packageTypeText != L"2" &&
	   packageTypeText != L"3" && packageTypeText != L"4") {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// 既知種別でもdriver以外のpackageは候補化しない。
	if( packageTypeText != L"2") {
		return 0 ;
	}

	std::optional<std::wstring> hide ;	// 任意hide attribute。
	error = readOptionalAttribute( *root.Get(), L"hide", 8, hide) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	// 非表示指定されたpackageを独自判断で候補へ戻さない。
	if( hide.has_value() && _wcsicmp( hide->c_str(), L"True") == 0) {
		return 0 ;
	}

	// 非表示属性が既知の真偽表現でない場合は拒否する。
	if( hide.has_value() && _wcsicmp( hide->c_str(), L"False") != 0) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	LenovoDriverRelease parsed ;	// 全field検証後に出力へ移すrelease。
	error = readRequiredAttribute( *root.Get(), L"id", 64, parsed.packageId) ;
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = readRequiredAttribute( *root.Get(), L"version", 128, parsed.version) ;
	}

	// package IDの取得失敗や安全な識別形式への不一致を拒否する。
	if( error != 0 || !isSafePackageId( parsed.packageId)) {
		return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	result = selectSingleNode( *root.Get(), L"Title/Desc[@id='EN']", packageType) ;
	// 優先titleを取得できない場合は既存の先頭説明欄を確認する。
	if( FAILED( result)) {
		result = selectSingleNode( *root.Get(), L"Title/Desc[1]", packageType) ;
	}

	// 代替説明欄も取得できなければtitleを推測しない。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	error = readNodeText( *packageType.Get(), 512, parsed.title) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	ComPtr<IXMLDOMNode> severity ;	// Severity type attribute node。
	result = selectSingleNode( *root.Get(), L"Severity", severity) ;
	// 重要度nodeを取得できなければmetadata解析を中止する。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	std::wstring severityType ;	// Critical/Recommended/Optional番号。
	error = readRequiredAttribute( *severity.Get(), L"type", 2, severityType) ;
	// 定義外または取得不能の重要度を採用しない。
	if( error != 0 || (severityType != L"1" && severityType != L"2" && severityType != L"3")) {
		return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	parsed.recommended = severityType == L"1" || severityType == L"2" ;

	ComPtr<IXMLDOMNode> reboot ;	// Reboot type attribute node。
	result = selectSingleNode( *root.Get(), L"Reboot", reboot) ;
	// 再起動種別nodeを取得できなければ結果を推測しない。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	std::wstring rebootType ;	// Lenovo reboot種別番号。
	error = readRequiredAttribute( *reboot.Get(), L"type", 2, rebootType) ;
	// 再起動種別を既知の値に制限する。
	if( error != 0 || (rebootType != L"0" && rebootType != L"1" && rebootType != L"3" &&
					  rebootType != L"4" && rebootType != L"5")) {
		return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	parsed.rebootMayBeRequired = rebootType != L"0" ;

	error = readRequiredText( *root.Get(), L"ReleaseDate", 10, parsed.releaseDate) ;
	std::wstring signingTime ;	// XML署名certificate検証へ渡すSigningTime原文。
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = readRequiredText( *root.Get(), L"SigningTime", 19, signingTime) ;
	}

	const std::optional<std::uint64_t> signingFiletime =	// Windows epoch署名時刻。
		error == 0 ? parseSigningTime( signingTime) : std::nullopt ;
	// 公開日付と署名時刻が検証できないpackageを拒否する。
	if( error != 0 || !isValidReleaseDate( parsed.releaseDate) || !signingFiletime.has_value()) {
		return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	parsed.signingFiletime = signingFiletime.value() ;

	ComPtr<IXMLDOMNodeList> installerFiles ;	// Installer配下のFile node群。
	result = selectNodes( *root.Get(), L"Files/Installer/File", installerFiles) ;
	// installer集合を取得できなければpayloadを選択しない。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	long installerCount{} ;	// Descriptorが宣言するinstaller file数。
	result = installerFiles->get_length( &installerCount) ;
	// installerが一つに確定しないdescriptorを拒否する。
	if( FAILED( result) || installerCount != 1) {
		return nativeError( FAILED( result) ? result : E_FAIL) ;
	}

	ComPtr<IXMLDOMNode> installer ;	// 単一installer file node。
	result = installerFiles->get_item( 0, &installer) ;
	// 唯一のinstaller nodeが欠落または取得失敗なら拒否する。
	if( FAILED( result) || installer == nullptr) {
		return nativeError( FAILED( result) ? result : E_FAIL) ;
	}

	std::wstring installerName ;	// URL構築へ使う安全なEXE basename。
	std::wstring installerHash ;	// Installer SHA-256原文。
	std::wstring installerSize ;	// Installer byte数原文。
	error = readRequiredText( *installer.Get(), L"Name", 255, installerName) ;
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = readRequiredText( *installer.Get(), L"CRC", 64, installerHash) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = readRequiredText( *installer.Get(), L"Size", 20, installerSize) ;
	}

	const std::optional<std::wstring> normalizedHash =	// 小文字installer SHA-256。
		error == 0 ? normalizeSha256( installerHash) : std::nullopt ;
	const std::optional<std::uint64_t> parsedSize =	// 上限確認済みinstaller byte数。
		error == 0 ? parseUnsigned( installerSize, MAXIMUM_PACKAGE_BYTES) : std::nullopt ;
	// installer名、期待hash、期待sizeが整合しなければ取得先を作らない。
	if( error != 0 || !isSafeInstallerName( installerName) || !normalizedHash.has_value() ||
	   !parsedSize.has_value()) {
		return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const std::size_t separator = descriptorUrl.find_last_of( L'/') ;	// Descriptor directory境界。
	// descriptorのdirectory境界がなければpayload URLを解決しない。
	if( separator == std::wstring_view::npos) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	parsed.installerUrl = std::wstring( descriptorUrl.substr( 0, separator + 1)) + installerName ;
	const std::span<const std::wstring_view> hosts =
		officialSourceHosts( LENOVO_PROVIDER_ID,
							OFFICIAL_PAYLOAD_RESOURCE_ID) ;	// Payload公式host群。
	// 組み立てたpayload URLにも共通HTTPS host検証を適用する。
	if( validateOfficialHttpsUrl( parsed.installerUrl, hosts) != 0) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	parsed.sha256 = normalizedHash.value() ;
	parsed.size	  = parsedSize.value() ;

	ComPtr<IXMLDOMNodeList> hardwareNodes ;	// Driver適用性に使えるHardware ID node群。
	result = selectNodes(
		*root.Get(),
		L"DetectInstall/_Driver/HardwareID | DetectVersion/_PnPID | Dependencies//_PnPID",
		hardwareNodes) ;
	// Hardware ID集合を取得できなければdevice対応を推測しない。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	long hardwareCount{} ;	// Descriptor内Hardware ID node数。
	result = hardwareNodes->get_length( &hardwareCount) ;
	// Hardware ID件数の取得失敗、負数、上限超過を拒否する。
	if( FAILED( result) || hardwareCount < 0 ||
	   hardwareCount > static_cast<long>( MAXIMUM_HARDWARE_IDS * 4U)) {
		return nativeError( FAILED( result) ? result : E_FAIL) ;
	}

	std::unordered_set<std::wstring> uniqueIds ;	// 大文字化後のID重複排除集合。
	// 有限個のcatalog側Hardware IDを検証し、重複なく保持する。
	for( long index = 0; index < hardwareCount; ++index) {
		ComPtr<IXMLDOMNode> hardwareNode ;	// 現在解析するHardware ID node。
		result = hardwareNodes->get_item( index, &hardwareNode) ;
		// Hardware ID nodeの取得失敗や欠落を黙って読み飛ばさない。
		if( FAILED( result) || hardwareNode == nullptr) {
			return nativeError( FAILED( result) ? result : E_FAIL) ;
		}

		std::wstring hardwareText ;	// Descriptor由来Hardware ID原文。
		error = readNodeText( *hardwareNode.Get(), 512, hardwareText) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		const std::optional<std::wstring> hardwareId =	// 完全一致可能な正規化ID。
			normalizeHardwareId( hardwareText) ;
		// 完全一致用に正規化できないIDをdevice照合の根拠にしない。
		if( !hardwareId.has_value()) {
			continue ;
		}

		// 未登録のHardware IDだけをpackageの対応集合へ追加する。
		if( uniqueIds.insert( hardwareId.value()).second) {
			parsed.hardwareIds.push_back( hardwareId.value()) ;
			// 重複除去後のHardware ID保持件数にも上限を適用する。
			if( parsed.hardwareIds.size() > MAXIMUM_HARDWARE_IDS) {
				return nativeErrorFromWin32( ERROR_TOO_MANY_NAMES) ;
			}
		}
	}

	release = std::move( parsed) ;
	return 0 ;
}

} // namespace drivercrate
