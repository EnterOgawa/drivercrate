//------------------------------------------------------------------------------
/**
 * @file nvidia_winof2_catalog_parser.cpp
 * @brief NVIDIA Networking WinOF-2公式metadata parser実装。
 * @version 01.00.01
 * @date 2026/09/06
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  List解析失敗時の部分出力を破棄。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  WinRT Collectionsの直接includeを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note Windows.Data.Jsonを使用し、固定POST応答をscriptとして実行せず解析します。欠落、重複、別host、別architecture、複数payloadを推測で補完
 *       しません。
 */
//------------------------------------------------------------------------------

#include "platform/nvidia_winof2_catalog_parser.h"

#include "platform/official_http_client.h"

#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cwctype>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

/**
 * @brief 所有権付きJSON array。
 */
using JsonArray = winrt::Windows::Data::Json::JsonArray ;
/**
 * @brief 所有権付きJSON object。
 */
using JsonObject = winrt::Windows::Data::Json::JsonObject ;
/**
 * @brief 所有権付き任意JSON value。
 */
using JsonValue = winrt::Windows::Data::Json::IJsonValue ;
/**
 * @brief JSON型区分。
 */
using JsonValueType = winrt::Windows::Data::Json::JsonValueType ;

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t		MAXIMUM_LANDING_CHARACTERS = 512U * 1024U ;	// 公式page文字数上限。
constexpr std::size_t		MAXIMUM_JSON_CHARACTERS	   = 256U * 1024U ;	// 各POST応答文字数上限。
constexpr std::size_t		MAXIMUM_LIST_VALUES		   = 64U ;			// 一応答の選択肢数上限。
constexpr std::size_t		MAXIMUM_VALUE_CHARACTERS   = 256U ;			// 一metadata値の文字数上限。
// WinOF系列の公式landingで要求する製品見出し。
constexpr std::wstring_view LANDING_TITLE = L"<h1>WinOF-2 / WinOF Drivers</h1>" ;
// WinOFとWinOF-2の対象adapter世代を区別する公式pageの固定説明。
constexpr std::wstring_view LANDING_FAMILY =
	L"For <b>ConnectX-4 and onwards adapter cards</b> drivers download <b>WinOF-2.</b>" ;
// 公式landingから委譲されたことを確認する固定downloader URL。
constexpr std::wstring_view DOWNLOADER_URL =
	L"https://downloaders.azurewebsites.net/downloaders/winof2_downloader/downloader4.html" ;
// WinOF payloadとして許可する公式配布pathの起点。
constexpr std::wstring_view PAYLOAD_PREFIX = L"https://www.mellanox.com/downloads/WinOF/" ;
// WinOF-2の適用条件を照合する公式文書pathの起点。
constexpr std::wstring_view DOCUMENTATION_PREFIX =
	L"https://networking-docs.nvidia.com/winof2driverum/" ;
// WinOF payload取得時のURL検証に渡す許可host集合。
constexpr std::array PAYLOAD_HOSTS{std::wstring_view( L"www.mellanox.com")} ;
// 適用条件の文書URL検証に渡す許可host集合。
constexpr std::array DOCUMENTATION_HOSTS{std::wstring_view( L"networking-docs.nvidia.com")} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 欠落と重複を同じschema拒否として扱う。
 *
 * @param[in] text 有限長の検索対象。
 * @param[in] marker 一度だけ存在すべき固定文字列。
 * @return Markerが一度だけ存在する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool	 markerIsUnique( const std::wstring_view text,
									const std::wstring_view marker) noexcept
{
	const std::size_t position = text.find( marker) ;	// 最初のmarker位置。
	return !marker.empty() && position != std::wstring_view::npos &&
		   text.find( marker, position + marker.size()) == std::wstring_view::npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief UI、URLまたはformへ渡す前の共通文字列境界。
 *
 * @param[in] value JSONから得た表示値。
 * @param[in] maximumCharacters 許可する文字数上限。
 * @return 非空、上限内、制御文字なしの場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafeValue( const std::wstring_view value,
							   const std::size_t	   maximumCharacters) noexcept
{
	return !value.empty() && value.size() <= maximumCharacters &&
		   std::ranges::none_of( value, []( const wchar_t character) {
			   return character < 0x20 || character == 0x7f ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Archive注釈、path、suffixをcurrent版として受理しない。
 *
 * @param[in] value Download Centerのpackage版。
 * @return 三つの有限ASCII数値componentならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isPackageVersion( const std::wstring_view value) noexcept
{
	// 空または上限外の版を拒否する。
	if( value.empty() || value.size() > 32U) {
		return false ;
	}

	std::size_t componentCount{1U} ;	// 現在までに開始した数値component数。
	std::size_t digitCount{} ;			// 現在componentのASCII数字数。
	// 全文字を有限回確認し、三つの数値component以外を拒否する。
	for( const wchar_t character : value) {
		// 版要素の数字を数えて過大な数値表現を検出する。
		if( character >= L'0' && character <= L'9') {
			// 過大な数値componentを拒否する。
			if( ++digitCount > 5U) {
				return false ;
			}

			continue ;
		}

		// 空component、dot以外または四つ目を拒否する。
		if( character != L'.' || digitCount == 0U || componentCount >= 3U) {
			return false ;
		}

		++componentCount ;
		digitCount = 0U ;
	}

	return componentCount == 3U && digitCount != 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief PHPが一件をstring、複数件をarrayで返す差だけを吸収する。
 *
 * @param[in] root StringまたはarrayのJSON root。
 * @param[out] values 成功時の重複しない所有値。
 * @return 型、件数、値が有限schemaを満たす場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool collectStringValues( const JsonValue &root, std::vector<std::wstring> &values)
{
	values.clear() ;
	// 一件応答のstringを検証後に一要素の集合へ揃える。
	if( root.ValueType() == JsonValueType::String) {
		const std::wstring value( root.GetString()) ;	// 一件応答の所有値。
		// 空または過大な一件応答を拒否する。
		if( !isSafeValue( value, MAXIMUM_VALUE_CHARACTERS)) {
			return false ;
		}

		values.push_back( value) ;
		return true ;
	}

	// Stringとarray以外のrootを拒否する。
	if( root.ValueType() != JsonValueType::Array) {
		return false ;
	}

	const JsonArray array = root.GetArray() ;	// 複数選択肢の所有array。
	// 空または過大な選択肢一覧を拒否する。
	if( array.Size() == 0U || array.Size() > MAXIMUM_LIST_VALUES) {
		return false ;
	}

	values.reserve( array.Size()) ;
	// 配列順を保持し、型違いまたは重複があれば全体を拒否する。
	for( const JsonValue &item : array) {
		// 複数件応答にstring以外の要素を許容しない。
		if( item.ValueType() != JsonValueType::String) {
			return false ;
		}

		const std::wstring value( item.GetString()) ;	// 現在の選択肢所有値。
		// 空、上限外または重複値を拒否する。
		if( !isSafeValue( value, MAXIMUM_VALUE_CHARACTERS) ||
		   std::find( values.begin(), values.end(), value) != values.end()) {
			return false ;
		}

		values.push_back( value) ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 欠落、null、数値等を暗黙に文字列へ変換しない。
 *
 * @param[in] object 読取り対象JSON object。
 * @param[in] name 必須property名。
 * @param[in] maximumCharacters 値の文字数上限。
 * @param[out] value 成功時の所有文字列。
 * @return 必須propertyが有限なstringの場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readObjectString( const JsonObject &object, const std::wstring_view name,
									const std::size_t maximumCharacters, std::wstring &value)
{
	value.clear() ;
	const winrt::hstring key( name) ;	// Windows JSON APIへ渡すproperty名。
	// 必須string以外を拒否する。
	if( !object.HasKey( key) || object.GetNamedValue( key).ValueType() != JsonValueType::String) {
		return false ;
	}

	value = object.GetNamedString( key) ;
	return isSafeValue( value, maximumCharacters) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 丸め値をbyte数またはdownload上限へ変換しない。
 *
 * @param[in] value Download Centerの概算size。
 * @return 正のASCII数値とMB単位だけの場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isDisplaySize( const std::wstring_view value) noexcept
{
	// 単位欠落または上限外を拒否する。
	if( value.size() < 4U || value.size() > 32U || !value.ends_with( L" MB")) {
		return false ;
	}

	const std::wstring_view number = value.substr( 0U, value.size() - 3U) ;	// MB前の数値部。
	bool					foundDigit{} ;									// 一桁以上のASCII数字を確認した場合true。
	bool					foundDot{} ;									// 小数点を既に確認した場合true。
	// 数値部を有限回確認し、一つの内部dot以外を拒否する。
	for( std::size_t index = 0U; index < number.size(); ++index) {
		const wchar_t character = number[index] ;	// 現在確認する数値部の一文字。
		// 概算sizeに数値部分が存在することを記録する。
		if( character >= L'0' && character <= L'9') {
			foundDigit = true ;
			continue ;
		}

		// 空小数、複数dotまたは数値外文字を拒否する。
		if( character != L'.' || foundDot || index == 0U || index + 1U == number.size()) {
			return false ;
		}

		foundDot = true ;
	}

	return foundDigit && number.find_first_not_of( L"0.") != std::wstring_view::npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief Hash自体を完全性保証とせず、同一metadataのpackage identityへ使用する。
 *
 * @param[in,out] value Download Centerが提示したSHA-256。
 * @return 64桁hexを小文字へ正規化できた場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool normalizeSha256( std::wstring &value) noexcept
{
	// SHA-256の固定64桁に合わない値を拒否する。
	if( value.size() != 64U) {
		return false ;
	}

	// 全桁を有限回確認し、大文字hexだけを小文字へ正規化する。
	for( wchar_t &character : value) {
		const bool digit = character >= L'0' && character <= L'9' ;	// ASCII数字の場合true。
		const bool lower = character >= L'a' && character <= L'f' ;	// 小文字hexの場合true。
		const bool upper = character >= L'A' && character <= L'F' ;	// 大文字hexの場合true。
		// hex以外の文字をpackage identityのhashに使用しない。
		if( !digit && !lower && !upper) {
			return false ;
		}

		// 大文字hexだけを小文字の正規形へ揃える。
		if( upper) {
			character = static_cast<wchar_t>( std::towlower( character)) ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 任意URLからfile名を抽出せず、検証済み版から期待値だけを作る。
 *
 * @param[in] version 検証済みcurrent package版。
 * @return Download Centerが使用する固定x64 EXE名。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring makeExpectedFileName( const std::wstring_view version)
{
	std::wstring encoded( version) ;	// File名用にdotをunderscoreへ変換する版。
	std::ranges::replace( encoded, L'.', L'_') ;
	return L"MLNX_WinOF2-" + encoded + L"_All_x64.exe" ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_winof2_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseNvidiaWinof2LandingPage( const std::wstring_view html) noexcept
{
	return !html.empty() && html.size() <= MAXIMUM_LANDING_CHARACTERS &&
		   html.find( L'\0') == std::wstring_view::npos && markerIsUnique( html, LANDING_TITLE) &&
		   markerIsUnique( html, LANDING_FAMILY) && markerIsUnique( html, DOWNLOADER_URL) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_winof2_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseNvidiaWinof2Versions( const std::wstring_view json, std::wstring &version)
{
	version.clear() ;
	// 空または上限外JSONをparserへ渡さない。
	if( json.empty() || json.size() > MAXIMUM_JSON_CHARACTERS) {
		return false ;
	}

	try {
		const JsonObject root = JsonObject::Parse( winrt::hstring( json)) ;	// Version応答root。
		std::wstring	 latest ;											// `latest`が明示するcurrent版。
		// 必須版または一覧欠落を拒否する。
		if( !readObjectString( root, L"latest", 32U, latest) || !isPackageVersion( latest) ||
		   !root.HasKey( L"versions") || !root.HasKey( L"ga")) {
			return false ;
		}

		std::vector<std::wstring> versions ;	// Archiveを含む公開版一覧。
		std::vector<std::wstring> current ;		// Download Centerのcurrent一覧。
		// Latestが両一覧で一意でない応答を拒否する。
		if( !collectStringValues( root.GetNamedValue( L"versions"), versions) ||
		   !collectStringValues( root.GetNamedValue( L"ga"), current) ||
		   std::count( versions.begin(), versions.end(), latest) != 1 ||
		   std::count( current.begin(), current.end(), latest) != 1) {
			return false ;
		}

		version = std::move( latest) ;
		return true ;
	} catch( ...) {
		version.clear() ;
		// JSON型、構文または割当て失敗をmetadata拒否へ変換する。
		return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_winof2_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseNvidiaWinof2StringList( const std::wstring_view json, std::vector<std::wstring> &values)
{
	values.clear() ;
	// 空または上限外JSONを拒否する。
	if( json.empty() || json.size() > MAXIMUM_JSON_CHARACTERS) {
		return false ;
	}

	try {
		const JsonValue root =
			// 任意root値。
			winrt::Windows::Data::Json::JsonValue::Parse( winrt::hstring( json)) ;
		// list変換失敗時は有効だった先行要素も公開しない。
		if( !collectStringValues( root, values)) {
			values.clear() ;
			// 途中まで有効なlistを失敗結果として公開しない。
			return false ;
		}

		return true ;
	} catch( ...) {
		values.clear() ;
		// JSON型、構文または割当て失敗をmetadata拒否へ変換する。
		return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_winof2_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool selectNvidiaWinof2Os( const bool windowsServer, const std::uint32_t windowsBuild,
						  NvidiaWinof2OsSelection &selection)
{
	selection = {} ;
	// Serverはclientと分離した明示build対応表で照合する。
	if( windowsServer) {
		// Server buildをcatalogに対応する既知のOS選択へ変換する。
		switch( windowsBuild) {
			// Server 2016 の既知 build は固定 Server 配布の共通選択へ進む。
			case 14'393U:
			// Server 2019 の既知 build は固定 Server 配布の共通選択へ進む。
			case 17'763U:
			// Server 2022 の既知 build は固定 Server 配布の共通選択へ進む。
			case 20'348U:
			// Server 2025 を含む明示済み Server build だけに共通配布を対応付ける。
			case 26'100U:
				selection.distribution = L"Windows Server" ;
				selection.osLabel	   = L"2016 / 2019 / 2022 / 2025" ;
				return true ;
			// 未知の Server build に類似世代の配布を割り当てない。
			default:
				// 未提示Server buildへ類似版を割り当てない。
				return false ;
		}
	}

	// 確認済みWindows 10 buildだけを対応するcatalog選択へ結び付ける。
	if( windowsBuild == 19'044U) {
		selection.distribution = L"Windows Client 10" ;
		selection.osLabel	   = L"21H2" ;
		return true ;
	}

	// 確認済みWindows 11 build群だけをcatalog選択へ結び付ける。
	if( windowsBuild == 22'631U || windowsBuild == 26'100U || windowsBuild == 26'200U) {
		selection.distribution = L"Windows Client 11" ;
		selection.osLabel	   = L"23H2 / 24H2 / 25H2" ;
		return true ;
	}

	// Current版が明示しないclient buildを対象外にする。
	return false ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_winof2_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseNvidiaWinof2DownloadInfo( const std::wstring_view json,
								   const std::wstring_view expectedVersion,
								   NvidiaWinof2Release	  &release)
{
	release = {} ;
	// 不正JSONまたは未検証版を拒否する。
	if( json.empty() || json.size() > MAXIMUM_JSON_CHARACTERS ||
	   !isPackageVersion( expectedVersion)) {
		return false ;
	}

	try {
		const JsonObject root = JsonObject::Parse( winrt::hstring( json)) ;	// Download情報root。
		// 必須array欠落または型違いを拒否する。
		if( !root.HasKey( L"files") || !root.HasKey( L"docs") ||
		   root.GetNamedValue( L"files").ValueType() != JsonValueType::Array ||
		   root.GetNamedValue( L"docs").ValueType() != JsonValueType::Array) {
			return false ;
		}

		const JsonArray files = root.GetNamedArray( L"files") ;	// Payload record群。
		const JsonArray docs  = root.GetNamedArray( L"docs") ;	// Documentation record群。
		// 複数payloadまたは二文書以外を拒否する。
		if( files.Size() != 1U || docs.Size() != 2U ||
		   files.GetAt( 0U).ValueType() != JsonValueType::Object) {
			return false ;
		}

		const JsonObject	file = files.GetAt( 0U).GetObject() ;	// 唯一のWinOF Driver record。
		NvidiaWinof2Release parsed ;								// 全条件成立時だけ公開する一時結果。
		std::wstring		description ;							// Driver分類の完全一致値。
		std::wstring		md5 ;									// 空であることを確認する補助hash欄。
		// 必須payload metadata欠落または不整合を拒否する。
		if( !readObjectString( file, L"file", 128U, parsed.fileName) ||
		   !readObjectString( file, L"desc", 64U, description) || description != L"WinOF Driver" ||
		   !readObjectString( file, L"size", 32U, parsed.displaySize) ||
		   !isDisplaySize( parsed.displaySize) ||
		   !readObjectString( file, L"sha", 64U, parsed.sha256) || !normalizeSha256( parsed.sha256) ||
		   !readObjectString( file, L"url", MAXIMUM_VALUE_CHARACTERS, parsed.downloadUrl)) {
			return false ;
		}

		// 任意MD5欄がある場合は型を検証し、非空hashへの依存を拒否する。
		if( file.HasKey( L"md5sum")) {
			const JsonValue md5Value = file.GetNamedValue( L"md5sum") ;	// 任意MD5欄のJSON値。
			// MD5欄の型変更を拒否する。
			if( md5Value.ValueType() != JsonValueType::String) {
				return false ;
			}

			md5 = md5Value.GetString() ;
			// SHA-256以外のhash依存を追加しない。
			if( !md5.empty()) {
				return false ;
			}
		}

		parsed.packageVersion			= expectedVersion ;
		const std::wstring expectedFile =	// 検証済み版に対応する唯一のx64 file名。
			makeExpectedFileName( expectedVersion) ;
		// 別版、別architecture、別pathまたは別hostを拒否する。
		if( parsed.fileName != expectedFile ||
		   parsed.downloadUrl != std::wstring( PAYLOAD_PREFIX) + expectedFile ||
		   validateOfficialHttpsUrl( parsed.downloadUrl, PAYLOAD_HOSTS) != 0) {
			return false ;
		}

		// 対象release版数へ固定した公式文書directoryの期待URL。
		const std::wstring expectedDocs =
			std::wstring( DOCUMENTATION_PREFIX) + std::wstring( expectedVersion) + L"/" ;
		// 二つの文書recordを順不同で確認し、同じ版の固定URL以外を拒否する。
		for( const JsonValue &item : docs) {
			// 付随文書の項目がobjectでなければschema不正として拒否する。
			if( item.ValueType() != JsonValueType::Object) {
				return false ;
			}

			const JsonObject document = item.GetObject() ;	// 現在確認する文書record。
			std::wstring	 descriptionValue ;				// Release NotesまたはUser Manualの分類。
			std::wstring	 url ;							// 同じ版に限定するNVIDIA文書URL。
			// 文書metadataまたは公式host不整合を拒否する。
			if( !readObjectString( document, L"desc", 64U, descriptionValue) ||
			   !readObjectString( document, L"url", MAXIMUM_VALUE_CHARACTERS, url) ||
			   validateOfficialHttpsUrl( url, DOCUMENTATION_HOSTS) != 0) {
				return false ;
			}

			// 期待URLとlabelが一致する未登録のrelease notesだけを保持する。
			if( descriptionValue == L"Release Notes" && url == expectedDocs + L"release-notes" &&
			   parsed.releaseNotesUrl.empty()) {
				parsed.releaseNotesUrl = std::move( url) ;
			}
			// 期待URLとlabelが一致する未登録のuser manualだけを保持する。
			else if( descriptionValue == L"User Manual" && url == expectedDocs + L"user-manual" &&
					parsed.userManualUrl.empty()) {
				parsed.userManualUrl = std::move( url) ;
			} else {
				// 未知、重複または別版文書を拒否する。
				return false ;
			}
		}

		// 二つの必須文書が揃わない応答を拒否する。
		if( parsed.releaseNotesUrl.empty() || parsed.userManualUrl.empty()) {
			return false ;
		}

		release = std::move( parsed) ;
		return true ;
	} catch( ...) {
		release = {} ;
		// JSON型、構文または割当て失敗をmetadata拒否へ変換する。
		return false ;
	}
}

} // namespace drivercrate
