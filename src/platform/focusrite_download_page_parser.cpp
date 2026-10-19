//------------------------------------------------------------------------------
/**
 * @file focusrite_download_page_parser.cpp
 * @brief Focusrite製品別Windows driver page parser実装。
 * @version 01.00.00
 * @date 2026/09/07
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 固定製品pageを実行せず、現行Windows driver欄の公開属性だけを解析します。EXEの取得、実行、展開、署名検証、PnP適用性判定またはEULA同意は行いません。
 */
//------------------------------------------------------------------------------

#include "platform/focusrite_download_page_parser.h"

#include "platform/official_http_client.h"

#include <array>
#include <cstddef>
#include <new>
#include <string>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t MAXIMUM_HTML_CHARACTERS		   = 1024U * 1024U ;	// HTML文字数上限。
constexpr std::size_t MAXIMUM_WINDOWS_BLOCK_CHARACTERS = 128U * 1024U ;		// Windows欄文字数上限。
constexpr std::size_t MAXIMUM_VALUE_CHARACTERS		   = 4096U ;			// 一つの抽出値の文字数上限。
constexpr std::wstring_view CANONICAL_MARKER =
	L"<link rel=\"canonical\" href=\"https://downloads.focusrite.com/focusrite/"
	L"scarlett-2nd-gen/scarlett-2i2-2nd-gen\" />" ;	// 固定製品pageのcanonical marker。
constexpr std::wstring_view TITLE_MARKER =
	L"<title>Scarlett 2i2 2nd Gen | Focusrite Downloads</title>" ;				// 固定製品title。
constexpr std::wstring_view WINDOWS_BLOCK_MARKER = L"<div class=\"windows\">" ;	// OS欄開始。
constexpr std::wstring_view MAC_BLOCK_MARKER	 = L"<div class=\"mac\">" ;		// 次のOS欄開始。
constexpr std::wstring_view NAME_PREFIX			 = L"Focusrite Driver " ;		// 現行driver名称prefix。
constexpr std::wstring_view NAME_SUFFIX			 = L" - Windows" ;				// 現行driver名称suffix。
constexpr std::wstring_view WINDOWS_DESCRIPTION	 = L"Windows 10 + 11" ;			// 対象OS表示。
// Focusrite公式Windows driver配布先に限定するURL prefix。
constexpr std::wstring_view DOWNLOAD_PREFIX =
	L"https://fael-downloads-prod.focusrite.com/customer/prod/downloads/focusritedriver_" ;
constexpr std::wstring_view FILE_PREFIX = L"focusritedriver_" ;	// EXE basename prefix。
constexpr std::wstring_view FILE_SUFFIX = L".exe" ;				// EXE basename suffix。
constexpr std::wstring_view FILE_TYPE_MARKER =
	L"<span class=\"file-type\">.exe</span>" ;	// 製品pageのfile type表示。
constexpr std::array DOWNLOAD_HOSTS{			// 公式payload host。
									std::wstring_view( L"fael-downloads-prod.focusrite.com")} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 欠落と重複を同じmetadata拒否へ変換し、最初の一致を推測採用しない。
 *
 * @param[in] text 検索対象の有限文字列。
 * @param[in] marker 一意性を確認する空でない文字列。
 * @return markerが一度だけ現れる場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool	 appearsOnce( const std::wstring_view text,
								 const std::wstring_view marker) noexcept
{
	// 空markerの一致を要素の存在確認に使わない。
	if( marker.empty()) {
		return false ;
	}

	const std::size_t position = text.find( marker) ;	// 最初の完全一致位置。
	return position != std::wstring_view::npos &&
		   text.find( marker, position + marker.size()) == std::wstring_view::npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief 要素間の改行とindentだけを許容し、内部空白や文字参照は変更しない。
 *
 * @param[in] value HTML要素内から切り出した非所有文字列。
 * @return 前後のASCII空白だけを除いた入力範囲内のview。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring_view trimAsciiSpace( std::wstring_view value) noexcept
{
	constexpr std::wstring_view SPACES = L" \t\r\n" ;						// HTML indentとして許可する空白。
	const std::size_t			first  = value.find_first_not_of( SPACES) ;	// 最初の非空白位置。
	// 空白だけの要素は空値として扱う。
	if( first == std::wstring_view::npos) {
		return {} ;
	}

	const std::size_t last = value.find_last_not_of( SPACES) ;	// 最後の非空白位置。
	return value.substr( first, last - first + 1U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief HTMLを実行せず、曖昧な複数要素または空要素をfail-closedで拒否する。
 *
 * @param[in] scope 一つのWindows欄に限定した有限文字列。
 * @param[in] opening 値の直前にある一意な開始marker。
 * @param[in] closing 値の直後にある終了marker。
 * @param[out] value 成功時のtrim済み文字列。失敗時は空。
 * @return 開始markerが一意で、直後の終了markerまでの値が上限内の場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readUniqueElementText( const std::wstring_view scope,
										 const std::wstring_view opening,
										 const std::wstring_view closing, std::wstring &value)
{
	value.clear() ;
	// 開始要素が一意でない場合や終了markerがない指定を拒否する。
	if( !appearsOnce( scope, opening) || closing.empty()) {
		return false ;
	}

	const std::size_t openingPosition = scope.find( opening) ;				// 一意な開始marker位置。
	const std::size_t valueBegin	  = openingPosition + opening.size() ;	// 値の開始位置。
	const std::size_t valueEnd		  = scope.find( closing, valueBegin) ;	// 対応する終了位置。
	// 閉じ要素が欠けたHTML断片を採用しない。
	if( valueEnd == std::wstring_view::npos) {
		return false ;
	}

	const std::wstring_view trimmed =
		// 非所有抽出値。
		trimAsciiSpace( scope.substr( valueBegin, valueEnd - valueBegin)) ;
	// 空または上限超過の要素値をmetadataとして保持しない。
	if( trimmed.empty() || trimmed.size() > MAXIMUM_VALUE_CHARACTERS) {
		return false ;
	}

	value.assign( trimmed) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 版と概算sizeの形式確認だけに使用し、大小比較または適用性判定は行わない。
 *
 * @param[in] value 検証するASCII数値列。
 * @param[in] separator 数値component間の区切り文字。
 * @param[in] requiredSeparators 必須区切り数。
 * @param[in] maximumDigits 一componentの最大桁数。
 * @return 全componentが1桁以上で区切り数と上限が一致する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isDecimalComponents( const std::wstring_view value, const wchar_t separator,
									   const std::size_t requiredSeparators,
									   const std::size_t maximumDigits) noexcept
{
	// 空の数値表現や桁数上限のない指定を拒否する。
	if( value.empty() || maximumDigits == 0U) {
		return false ;
	}

	std::size_t separators{} ;		// 完全に確認した区切り数。
	std::size_t componentDigits{} ;	// 現在componentのASCII数字数。
	// 全文字を有限回で確認し、符号、空白またはUnicode数字を受理しない。
	for( const wchar_t character : value) {
		// 数字は現在の構成要素の桁として数える。
		if( character >= L'0' && character <= L'9') {
			++componentDigits ;
			// 一要素の許可桁数を超える数値表現を拒否する。
			if( componentDigits > maximumDigits) {
				return false ;
			}

			continue ;
		}

		// 想定外の区切りや空要素を含む数値表現を拒否する。
		if( character != separator || componentDigits == 0U) {
			return false ;
		}

		++separators ;
		componentDigits = 0U ;
	}

	return componentDigits != 0U && separators == requiredSeparators ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示形式だけを確認し、正確なbyte数または取得上限へ変換しない。
 *
 * @param[in] value 製品pageから抽出した概算size。
 * @return 1～4桁と小数2桁の`MB`表示ならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isDisplaySize( const std::wstring_view value) noexcept
{
	constexpr std::wstring_view SUFFIX = L" MB" ;	// 製品pageの単位suffix。
	// 単位suffixと数値部分を備えない概算sizeを採用しない。
	if( !value.ends_with( SUFFIX) || value.size() <= SUFFIX.size()) {
		return false ;
	}

	const std::wstring_view number =
		// ASCII小数部分。
		value.substr( 0U, value.size() - SUFFIX.size()) ;
	const std::size_t decimal = number.find( L'.') ;	// 整数部と小数部の境界。
	return decimal != std::wstring_view::npos &&
		   number.find( L'.', decimal + 1U) == std::wstring_view::npos && decimal >= 1U &&
		   decimal <= 4U && number.size() - decimal - 1U == 2U &&
		   isDecimalComponents( number, L'.', 1U, 4U) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/focusrite_download_page_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseFocusriteScarlett2i2SecondGenPage( const std::wstring_view		   html,
											FocusriteDownloadPageMetadata &metadata)
{
	metadata = {} ;
	// HTMLの長さと製品識別markerを確認し、別ページや曖昧な応答を拒否する。
	if( html.empty() || html.size() > MAXIMUM_HTML_CHARACTERS ||
	   html.find( L'\0') != std::wstring_view::npos || !appearsOnce( html, CANONICAL_MARKER) ||
	   !appearsOnce( html, TITLE_MARKER) || !appearsOnce( html, NAME_PREFIX)) {
		return false ;
	}

	try {
		const std::size_t namePosition = html.find( NAME_PREFIX) ;					// 現行driver名称の開始位置。
		const std::size_t versionBegin = namePosition + NAME_PREFIX.size() ;		// 配布版開始位置。
		const std::size_t versionEnd   = html.find( NAME_SUFFIX, versionBegin) ;	// 配布版終了位置。
		// 版の範囲を特定できない場合や空の版は採用しない。
		if( versionEnd == std::wstring_view::npos || versionEnd == versionBegin) {
			return false ;
		}

		const std::wstring_view version =
			// 名称内の配布版。
			html.substr( versionBegin, versionEnd - versionBegin) ;
		// 許可した長さと数値構成に合わない版表示を拒否する。
		if( version.size() > 24U || !isDecimalComponents( version, L'.', 2U, 4U)) {
			return false ;
		}

		const std::size_t blockBegin =
			// 対象Windows欄の開始位置。
			html.rfind( WINDOWS_BLOCK_MARKER, namePosition) ;
		const std::size_t blockEnd = html.find( MAC_BLOCK_MARKER, versionEnd) ;	// 次のOS欄位置。
		// Windows欄の境界と長さが整合しなければ対象欄を推測しない。
		if( blockBegin == std::wstring_view::npos || blockEnd == std::wstring_view::npos ||
		   blockEnd <= blockBegin || blockEnd - blockBegin > MAXIMUM_WINDOWS_BLOCK_CHARACTERS) {
			return false ;
		}

		const std::wstring_view block =
			// 現行Windows欄だけのview。
			html.substr( blockBegin, blockEnd - blockBegin) ;
		// Windows欄内の製品名、説明、file種別が一意に確認できる場合だけ解析する。
		if( !appearsOnce( block, NAME_PREFIX) || !appearsOnce( block, WINDOWS_DESCRIPTION) ||
		   !appearsOnce( block, FILE_TYPE_MARKER)) {
			return false ;
		}

		FocusriteDownloadPageMetadata parsed ;	// 全条件成立時だけ出力へ移す結果。
		// 公式HTTPS URLと表示sizeを検証し、queryやfragment付きの取得先を拒否する。
		if( !readUniqueElementText( block, L"href=\"", L"\"", parsed.downloadUrl) ||
		   !readUniqueElementText( block, L"<span class=\"file-size\">", L"</span>",
								  parsed.displaySize) ||
		   !parsed.downloadUrl.starts_with( DOWNLOAD_PREFIX) ||
		   parsed.downloadUrl.find( L'?') != std::wstring::npos ||
		   parsed.downloadUrl.find( L'#') != std::wstring::npos ||
		   validateOfficialHttpsUrl( parsed.downloadUrl, DOWNLOAD_HOSTS) != 0 ||
		   !isDisplaySize( parsed.displaySize)) {
			return false ;
		}

		const std::size_t fileSeparator =
			// Basenameの開始境界。
			parsed.downloadUrl.find_last_of( L'/') ;
		// URL末尾から空でないfile名を取得できなければ拒否する。
		if( fileSeparator == std::wstring_view::npos ||
		   fileSeparator + 1U >= parsed.downloadUrl.size()) {
			return false ;
		}

		parsed.fileName.assign( parsed.downloadUrl.substr( fileSeparator + 1U)) ;
		// 期待する製品prefixとfile suffixに合わないpayload名を採用しない。
		if( !parsed.fileName.starts_with( FILE_PREFIX) || !parsed.fileName.ends_with( FILE_SUFFIX) ||
		   parsed.fileName.size() <= FILE_PREFIX.size() + FILE_SUFFIX.size()) {
			return false ;
		}

		const std::wstring_view identity =
			std::wstring_view( parsed.fileName)
				.substr( FILE_PREFIX.size(), parsed.fileName.size() - FILE_PREFIX.size() -
												// 版とbuild。
												FILE_SUFFIX.size()) ;
		const std::size_t buildSeparator = identity.find( L'_') ;	// 版とpayload buildの境界。
		// file名の版とbuildを表示版へ照合し、曖昧な識別表現を拒否する。
		if( buildSeparator == std::wstring_view::npos ||
		   identity.find( L'_', buildSeparator + 1U) != std::wstring_view::npos ||
		   identity.substr( 0U, buildSeparator) != version ||
		   !isDecimalComponents( identity.substr( buildSeparator + 1U), L'.', 0U, 6U)) {
			return false ;
		}

		parsed.version.assign( version) ;
		metadata = std::move( parsed) ;
		return true ;
	} catch( const std::bad_alloc &) {
		metadata = {} ;
		return false ;
	}
}

} // namespace drivercrate
