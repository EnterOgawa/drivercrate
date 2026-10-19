//------------------------------------------------------------------------------
/**
 * @file ricoh_universal_print_page_parser.cpp
 * @brief Ricoh Universal Print公式download page parser実装。
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
 * @note 固定Ricoh pageを実行せず解析し、六つのx64 OS欄の一致を要求します。欠落、重複、別host、別製品またはOS別package分岐を推測で補完せず拒否します。
 */
//------------------------------------------------------------------------------

#include "platform/ricoh_universal_print_page_parser.h"

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

constexpr std::size_t		MAXIMUM_HTML_CHARACTERS	   = 2U * 1024U * 1024U ;	// HTML文字数上限。
constexpr std::size_t		MAXIMUM_URL_CHARACTERS	   = 4096U ;				// Download URL文字数上限。
constexpr std::size_t		MAXIMUM_VERSION_CHARACTERS = 31U ;					// 配布版文字数上限。
constexpr std::size_t		MAXIMUM_SIZE_CHARACTERS	   = 31U ;					// 概算size文字数上限。
constexpr std::wstring_view PAGE_TITLE =
	L"<h1 class=\"hd01\">Universal Print Driver</h1>" ;	// 対象pageの固定見出し。
constexpr std::wstring_view SECTION_MARKER =
	L"<div class=\"accordion_sct accordionSingleLinkSub\">" ;	// OS欄の開始marker。
constexpr std::wstring_view DRIVER_TITLE =
	L"<strong>PCL6 Driver for Universal Print</strong>" ;					// V4等と区別する対象行。
constexpr std::wstring_view ROW_MARKER = L"<div class=\"dl_list_box\">" ;	// Driver行の開始。
constexpr std::wstring_view DOWNLOAD_PREFIX =
	L"https://support.ricoh.com/bb/pub_e/dr_ut_e/" ;	// 公式driver配布pathの固定prefix。
constexpr std::array OPERATING_SYSTEMS{
	std::wstring_view( L"Microsoft Windows 11 (64-bit)"),
	std::wstring_view( L"Microsoft Windows 10 (64-bit)"),
	std::wstring_view( L"Microsoft Windows Server 2025 (64-bit)"),
	std::wstring_view( L"Microsoft Windows Server 2022 (64-bit)"),
	std::wstring_view( L"Microsoft Windows Server 2019 (64-bit)"),
	// 必須の対象OS欄。
	std::wstring_view( L"Microsoft Windows Server 2016 (64-bit)")} ;
constexpr std::array DOWNLOAD_HOSTS{	// Download URLで許可する完全一致host。
									std::wstring_view( L"support.ricoh.com")} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 欠落と重複を同じmetadata拒否として扱う。
 *
 * @param[in] text 有限長の検索対象。
 * @param[in] marker 一度だけ存在すべき固定文字列。
 * @param[out] position 成功時の開始位置。
 * @return Markerが一度だけ存在する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool	 findUniqueMarker( const std::wstring_view text, const std::wstring_view marker,
									  std::size_t &position) noexcept
{
	position = text.find( marker) ;
	return !marker.empty() && position != std::wstring_view::npos &&
		   text.find( marker, position + marker.size()) == std::wstring_view::npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief 値の内部表現を変更せず、構文上許容する外側空白だけを除去する。
 *
 * @param[in] value HTML内の一つのtext値。
 * @return 前後のASCII空白を除いた非所有view。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring_view trimAsciiSpace( std::wstring_view value) noexcept
{
	// Text nodeの前方にあるASCII空白だけを読み飛ばす。
	while( !value.empty() && (value.front() == L' ' || value.front() == L'\t' ||
							 value.front() == L'\r' || value.front() == L'\n')) {
		value.remove_prefix( 1U) ;
	}

	// Text nodeの後方にあるASCII空白だけを読み飛ばす。
	while( !value.empty() && (value.back() == L' ' || value.back() == L'\t' ||
							 value.back() == L'\r' || value.back() == L'\n')) {
		value.remove_suffix( 1U) ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief DOMやscriptを実行せず、現在schemaの単一text nodeだけを読み取る。
 *
 * @param[in] text 一つのdriver行。
 * @param[in] prefix 値の直前にある一意なmarker。
 * @param[in] suffix 値の終端marker。
 * @param[in] maximum 空白除去後に許可する最大文字数。
 * @param[out] value 成功時の所有値。失敗時は空。
 * @return 一意で有限な値を取得できた場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readUniqueValue( const std::wstring_view text, const std::wstring_view prefix,
								   const std::wstring_view suffix, const std::size_t maximum,
								   std::wstring &value)
{
	value.clear() ;
	std::size_t prefixPosition{} ;	// 一意な値開始markerの位置。
	// 開始 marker が一意に見つからなければ値を抽出しない。
	if( !findUniqueMarker( text, prefix, prefixPosition)) {
		return false ;
	}

	const std::size_t valueBegin = prefixPosition + prefix.size() ;	// 空白除去前の値開始位置。
	const std::size_t valueEnd	 = text.find( suffix, valueBegin) ;	// 値の終端marker位置。
	// 終端 marker が未指定または未検出の場合は値を受理しない。
	if( suffix.empty() || valueEnd == std::wstring_view::npos) {
		return false ;
	}

	const std::wstring_view parsed =
		// 検証対象値。
		trimAsciiSpace( text.substr( valueBegin, valueEnd - valueBegin)) ;
	// 空または上限を超える抽出値は表示 metadata として使わない。
	if( parsed.empty() || parsed.size() > maximum) {
		return false ;
	}

	value.assign( parsed) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 任意path、空component、suffixまたは過大な数値表現を受理しない。
 *
 * @param[in] version 公式pageが明示した版。
 * @return 2～6個の1～5桁ASCII数値componentならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isDottedVersion( const std::wstring_view version) noexcept
{
	// 空または表記上限を超える version を拒否する。
	if( version.empty() || version.size() > MAXIMUM_VERSION_CHARACTERS) {
		return false ;
	}

	std::size_t separators{} ;	// 完全に検証したcomponent間のdot数。
	std::size_t digits{} ;		// 現在componentのASCII数字数。
	// 全文字を有限回で確認し、数字とdot以外を拒否する。
	for( const wchar_t character : version) {
		// Version 成分の数字を数え、単一成分の桁数を検証する。
		if( character >= L'0' && character <= L'9') {
			++digits ;
			// 五桁を超える version 成分を拒否する。
			if( digits > 5U) {
				return false ;
			}
		}
		// 非空の成分の後の dot だけを区切りとして受理する。
		else if( character == L'.' && digits != 0U) {
			++separators ;
			digits = 0U ;
		} else {
			return false ;
		}
	}

	return digits != 0U && separators >= 1U && separators <= 5U ;
}

//------------------------------------------------------------------------------
/**
 * @brief Calendarの完全検証ではなく、固定page schemaからの誤抽出を防止する。
 *
 * @param[in] value MM/DD/YYYY形式で表示された公開日。
 * @return 区切り、数字、月日範囲および4桁年が成立する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isReleaseDate( const std::wstring_view value) noexcept
{
	// 固定の日付桁数と slash 位置が異なる表示を拒否する。
	if( value.size() != 10U || value[2U] != L'/' || value[5U] != L'/') {
		return false ;
	}

	constexpr std::array<std::size_t, 8> DIGIT_POSITIONS{0U, 1U, 3U, 4U,
														 6U, 7U, 8U, 9U} ;	// Slash以外の位置。
	// 全数字位置を確認し、locale依存の変換を使用しない。
	for( const std::size_t position : DIGIT_POSITIONS) {
		// 日付の数値位置に十進数字以外がある場合は拒否する。
		if( value[position] < L'0' || value[position] > L'9') {
			return false ;
		}
	}

	const unsigned int month =
		// 月。
		static_cast<unsigned int>( (value[0U] - L'0') * 10 + (value[1U] - L'0')) ;
	const unsigned int day =
		// 日。
		static_cast<unsigned int>( (value[3U] - L'0') * 10 + (value[4U] - L'0')) ;
	const unsigned int year =
		static_cast<unsigned int>( (value[6U] - L'0') * 1000 + (value[7U] - L'0') * 100 +
								  (value[8U] - L'0') * 10 + (value[9U] - L'0')) ;	// 西暦年。
	return month >= 1U && month <= 12U && day >= 1U && day <= 31U && year >= 2000U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 概算表示をbyte上限や完全性検証へ使用できる数値には変換しない。
 *
 * @param[in] value Comma区切りを許すKB単位の概算size。
 * @return 正のASCII数字と正規の3桁comma区切りに` KB`が続く場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isDisplaySize( const std::wstring_view value) noexcept
{
	constexpr std::wstring_view SUFFIX = L" KB" ;	// 公式pageのsize単位。
	// Size 表記の単位 suffix、数値の存在、全長上限を確認する。
	if( !value.ends_with( SUFFIX) || value.size() <= SUFFIX.size() ||
	   value.size() > MAXIMUM_SIZE_CHARACTERS) {
		return false ;
	}

	const std::wstring_view digits =
		// 単位を除く数値表示。
		value.substr( 0U, value.size() - SUFFIX.size()) ;
	const std::size_t firstComma = digits.find( L',') ;	// 最初の3桁区切り位置。
	// Comma がない size 表記は一続きの十進数字として検証する。
	if( firstComma == std::wstring_view::npos) {
		// Commaなしの全桁がASCII数字であることを確認する。
		for( const wchar_t character : digits) {
			// Comma なしの size 数値に十進数字以外を許可しない。
			if( character < L'0' || character > L'9') {
				return false ;
			}
		}

		return digits.front() != L'0' ;
	}

	// Comma 表記の先頭 group が一桁から三桁の範囲外なら拒否する。
	if( firstComma == 0U || firstComma > 3U) {
		return false ;
	}

	// 最初のgroupがASCII数字だけであることを確認する。
	for( std::size_t index = 0U; index < firstComma; ++index) {
		const wchar_t character = digits[index] ;	// 現在検証するsize文字。
		// Size の先頭 group も十進数字だけで構成されることを確認する。
		if( character < L'0' || character > L'9') {
			return false ;
		}
	}

	std::size_t groupDigits{} ;	// Comma以降で現在groupにある数字数。
	// 最初のcommaより後は必ず3桁groupが続くことを確認する。
	for( std::size_t index = firstComma + 1U; index < digits.size(); ++index) {
		const wchar_t character = digits[index] ;	// 現在検証するsize文字。
		// Comma に到達したら直前 group の三桁を確認し、次の group へ進む。
		if( character == L',') {
			// 二つ目以降の group が三桁でなければ size 表記を拒否する。
			if( groupDigits != 3U) {
				return false ;
			}

			groupDigits = 0U ;
			continue ;
		}

		// Group 内の非数字と三桁を超える追加数字を拒否する。
		if( character < L'0' || character > L'9' || groupDigits >= 3U) {
			return false ;
		}

		++groupDigits ;
	}

	return digits.front() != L'0' && groupDigits == 3U ;
}

//------------------------------------------------------------------------------
/**
 * @brief Path separator、escape、Unicode類似文字または別file形式を拒否する。
 *
 * @param[in] value URL末尾から得たbasename。
 * @return 1～128文字の安全なASCII名で「.exe」終端ならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafeExecutableName( const std::wstring_view value) noexcept
{
	// 空・長さ超過・実行 file 拡張子以外の配布名を拒否する。
	if( value.empty() || value.size() > 128U || !value.ends_with( L".exe")) {
		return false ;
	}

	// Basename全体を有限回で検査し、明示したASCII文字だけを許可する。
	for( const wchar_t character : value) {
		const bool alphaNumeric = (character >= L'0' && character <= L'9') ||
								  (character >= L'A' && character <= L'Z') ||
								  (character >= L'a' && character <= L'z') ;	// File名の英数字。
		// 配布 file 名に許可しない文字を含む場合は受理しない。
		if( !alphaNumeric && character != L'-' && character != L'_' && character != L'.') {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公開URLを表示情報として解析し、payload取得許可は発行しない。
 *
 * @param[in] row 従来型PCL6の一つのdriver行。
 * @param[out] url 成功時の公式HTTPS URL。
 * @param[out] fileName 成功時の安全なEXE basename。
 * @return 一つだけのhrefが固定Ricoh配布pathを示す場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readDownloadUrl( const std::wstring_view row, std::wstring &url,
								   std::wstring &fileName)
{
	url.clear() ;
	fileName.clear() ;
	constexpr std::wstring_view HREF = L"href=\"" ;	// URL値の開始marker。
	std::size_t					hrefPosition{} ;	// 一意なhrefの開始位置。
	// 配布 row の link marker が一意でなければ URL を選ばない。
	if( !findUniqueMarker( row, HREF, hrefPosition)) {
		return false ;
	}

	const std::size_t urlBegin = hrefPosition + HREF.size() ;	// URL値の開始位置。
	const std::size_t urlEnd   = row.find( L'\"', urlBegin) ;	// URL値の終了位置。
	// URL 属性の終端欠落と長さ上限超過を拒否する。
	if( urlEnd == std::wstring_view::npos || urlEnd - urlBegin > MAXIMUM_URL_CHARACTERS) {
		return false ;
	}

	const std::wstring_view parsedUrl = row.substr( urlBegin, urlEnd - urlBegin) ;	// URL値。
	// 固定配布 prefix、query・fragment 禁止、公式 HTTPS の条件を全て確認する。
	if( !parsedUrl.starts_with( DOWNLOAD_PREFIX) || parsedUrl.find( L'?') != std::wstring_view::npos ||
	   parsedUrl.find( L'#') != std::wstring_view::npos ||
	   validateOfficialHttpsUrl( parsedUrl, DOWNLOAD_HOSTS) != 0) {
		return false ;
	}

	const std::size_t separator = parsedUrl.find_last_of( L'/') ;	// Basename直前のpath区切り。
	// URL 末尾に file 名を抽出できる要素がない場合は拒否する。
	if( separator == std::wstring_view::npos || separator + 1U >= parsedUrl.size()) {
		return false ;
	}

	const std::wstring_view parsedName = parsedUrl.substr( separator + 1U) ;	// EXE basename。
	// 抽出した配布名が安全な実行 file 名でなければ拒否する。
	if( !isSafeExecutableName( parsedName)) {
		return false ;
	}

	url.assign( parsedUrl) ;
	fileName.assign( parsedName) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 別OS欄、V4、PostScriptおよびutility行へ探索範囲を広げない。
 *
 * @param[in] html 検証中の固定Ricoh page。
 * @param[in] operatingSystem 一度だけ存在すべき対象x64 OS見出し。
 * @param[out] metadata 成功時の当該OS欄の所有metadata。
 * @return 対象OS欄に一つの従来型PCL6行があり全明示値が有効ならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool parseOperatingSystemSection( const std::wstring_view			html,
											   const std::wstring_view			operatingSystem,
											   RicohUniversalPrintPageMetadata &metadata)
{
	metadata = {} ;
	std::size_t operatingSystemPosition{} ;	// 一意なOS見出しの位置。
	// 対象 OS marker が一意に特定できなければ別 OS 欄を探索しない。
	if( !findUniqueMarker( html, operatingSystem, operatingSystemPosition)) {
		return false ;
	}

	const std::size_t sectionBegin =
		// 対象OS欄の開始位置。
		html.rfind( SECTION_MARKER, operatingSystemPosition) ;
	// 対象 OS を囲む section の開始がない page を拒否する。
	if( sectionBegin == std::wstring_view::npos) {
		return false ;
	}

	const std::size_t nextSection =
		// 次のOS欄位置。
		html.find( SECTION_MARKER, sectionBegin + SECTION_MARKER.size()) ;
	const std::size_t sectionEnd =
		// 対象欄終端。
		nextSection == std::wstring_view::npos ? html.size() : nextSection ;
	// 対象 OS marker が section 境界外にある場合は拒否する。
	if( operatingSystemPosition >= sectionEnd) {
		return false ;
	}

	const std::wstring_view section =
		// 対象OS欄だけのview。
		html.substr( sectionBegin, sectionEnd - sectionBegin) ;
	std::size_t titlePosition{} ;	// 対象PCL6行の一意なtitle位置。
	// 対象 section 内で driver title が一意に見つからなければ拒否する。
	if( !findUniqueMarker( section, DRIVER_TITLE, titlePosition)) {
		return false ;
	}

	const std::size_t rowBegin = section.rfind( ROW_MARKER, titlePosition) ;	// 対象行の開始位置。
	// 対象 driver の row 境界が確定できなければ metadata を抽出しない。
	if( rowBegin == std::wstring_view::npos) {
		return false ;
	}

	const std::size_t nextRow =
		// 次のdriver行位置。
		section.find( ROW_MARKER, rowBegin + ROW_MARKER.size()) ;
	const std::size_t rowEnd =
		// 対象行終端。
		nextRow == std::wstring_view::npos ? section.size() : nextRow ;
	const std::wstring_view row =
		// 対象PCL6行だけのview。
		section.substr( rowBegin, rowEnd - rowBegin) ;
	RicohUniversalPrintPageMetadata parsed ;	// 全検証後だけ公開する一時結果。
	// URL、版、日付、概算 size の必須値と形式が全て揃う row だけを受理する。
	if( !readDownloadUrl( row, parsed.downloadUrl, parsed.fileName) ||
	   !readUniqueValue( row, L"Ver.", L"</span>", MAXIMUM_VERSION_CHARACTERS, parsed.version) ||
	   !isDottedVersion( parsed.version) ||
	   !readUniqueValue( row, L"Released Date:", L"<", 10U, parsed.releaseDate) ||
	   !isReleaseDate( parsed.releaseDate) ||
	   !readUniqueValue( row, L"(File Size :", L")", MAXIMUM_SIZE_CHARACTERS, parsed.displaySize) ||
	   !isDisplaySize( parsed.displaySize)) {
		return false ;
	}

	metadata = std::move( parsed) ;
	return true ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/ricoh_universal_print_page_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseRicohUniversalPrintPage( const std::wstring_view		   html,
								  RicohUniversalPrintPageMetadata &metadata)
{
	metadata = {} ;
	std::size_t pageTitlePosition{} ;	// 一意な対象page見出しの位置。
	// 空・長さ超過・埋込み NUL・固定 title の不一致がある page を拒否する。
	if( html.empty() || html.size() > MAXIMUM_HTML_CHARACTERS ||
	   html.find( L'\0') != std::wstring_view::npos ||
	   !findUniqueMarker( html, PAGE_TITLE, pageTitlePosition)) {
		return false ;
	}

	try {
		RicohUniversalPrintPageMetadata common ;		// 最初のOS欄から得る比較基準。
		bool							first = true ;	// trueの場合は比較基準が未設定。
		// 六つの対象x64 OS欄を全て解析し、同じ配布情報であることを確認する。
		for( const std::wstring_view operatingSystem : OPERATING_SYSTEMS) {
			RicohUniversalPrintPageMetadata current ;	// 現在OS欄の検証済みmetadata。
			// 各対象 OS section を解析できなければ共通配布情報を作らない。
			if( !parseOperatingSystemSection( html, operatingSystem, current)) {
				return false ;
			}

			// 最初の OS section の結果を他 section との一致比較の基準にする。
			if( first) {
				common = std::move( current) ;
				first  = false ;
			}
			// OS別package分岐を一つのreleaseとして扱わない。
			else if( current != common) {
				return false ;
			}
		}

		metadata = std::move( common) ;
		return true ;
	} catch( const std::bad_alloc &) {
		metadata = {} ;
		return false ;
	}
}

} // namespace drivercrate
