//------------------------------------------------------------------------------
/**
 * @file wacom_driver_page_parser.cpp
 * @brief Wacom Windows driver公式page parser実装。
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
 * @note 固定Wacom pageを実行せず、既知templateを除いた一意なWindows配布欄を解析します。統合EXE、EULA、Privacy Notice、Retail／OEM適用性
 *       は後段未接続として閉じます。
 */
//------------------------------------------------------------------------------

#include "platform/wacom_driver_page_parser.h"

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

constexpr std::size_t		MAXIMUM_HTML_CHARACTERS		 = 2U * 1024U * 1024U ;	// HTML文字数上限。
constexpr std::size_t		MAXIMUM_ANCHOR_CHARACTERS	 = 8U * 1024U ;			// 対象a tag文字数上限。
constexpr std::size_t		MAXIMUM_ATTRIBUTE_CHARACTERS = 4096U ;				// 一属性値の文字数上限。
constexpr std::size_t		MAXIMUM_WINDOWS_MARKERS		 = 64U ;				// Windows欄とtemplateの走査上限。
constexpr std::wstring_view WINDOWS_MARKER = L"data-driver-os=\"windows\"" ;	// 対象OS属性。
constexpr std::wstring_view LATEST_TEMPLATE =
	L"{{WindowsLatestDownloadLink}}" ;									// 製品検索templateの未展開値。
constexpr std::wstring_view HISTORY_TEMPLATE = L"{{DownloadLink}}" ;	// 旧版templateの未展開値。
constexpr std::wstring_view WINDOWS_DESCRIPTION =
	L"Windows 10 &amp; 11 (x64) &amp; Windows 11 (ARM64)" ;	// 現行のx64併記境界。
constexpr std::wstring_view DOWNLOAD_PREFIX =
	L"https://cdn.wacom.com/u/productsupport/drivers/win/professional/" ;	// 固定配布path。
constexpr std::wstring_view FILE_PREFIX = L"WacomTablet_" ;					// Windows統合EXEの固定prefix。
constexpr std::wstring_view FILE_SUFFIX = L".exe" ;							// Windows統合EXEの固定suffix。
constexpr std::array		DOWNLOAD_HOSTS{									// Payload URLとして認識する公式host。
									   std::wstring_view( L"cdn.wacom.com")} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief HTMLを実行せず、属性重複、欠落、過大値をmetadata拒否へ変換する。
 *
 * @param[in] tag 一つの開始tagだけを含む有限文字列。
 * @param[in] name 読み取るASCII属性名。
 * @param[out] value 成功時の属性値。失敗時は空。
 * @return 二重引用符で囲まれた属性が一度だけ存在する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readUniqueAttribute( const std::wstring_view tag, const std::wstring_view name,
									   std::wstring &value)
{
	value.clear() ;
	// 空の属性名で HTML 値を探索しない。
	if( name.empty()) {
		return false ;
	}

	std::wstring marker( name) ;	// 属性名と値境界を完全一致で検索する所有marker。
	marker.append( L"=\"") ;
	std::size_t searchPosition{} ;	// 次に同名markerを検索する開始位置。
	std::size_t matches{} ;			// 属性境界が成立したmarker数。
	// Tag全体を有限回で走査し、別属性名のsuffix一致を対象にしない。
	while( searchPosition < tag.size()) {
		const std::size_t position = tag.find( marker, searchPosition) ;	// 現在のmarker位置。
		// 属性 marker がこれ以上見つからなければ探索を終了する。
		if( position == std::wstring_view::npos) {
			break ;
		}

		searchPosition = position + marker.size() ;
		const bool attributeBoundary =
			position != 0U && (tag[position - 1U] == L' ' || tag[position - 1U] == L'\t' ||
							   // 属性名直前の空白境界。
							   tag[position - 1U] == L'\r' || tag[position - 1U] == L'\n') ;
		// 別属性名の部分一致は目的の属性として数えない。
		if( !attributeBoundary) {
			continue ;
		}

		++matches ;
		// 目的の属性が重複した場合は値を消して曖昧な入力を拒否する。
		if( matches != 1U) {
			value.clear() ;
			return false ;
		}

		const std::size_t valueBegin = position + marker.size() ;		// 属性値の開始位置。
		const std::size_t valueEnd	 = tag.find( L'\"', valueBegin) ;	// 属性値の終了位置。
		// 属性値の終端欠落、空値、長さ超過を拒否して出力を破棄する。
		if( valueEnd == std::wstring_view::npos || valueBegin == valueEnd ||
		   valueEnd - valueBegin > MAXIMUM_ATTRIBUTE_CHARACTERS) {
			value.clear() ;
			return false ;
		}

		value.assign( tag.substr( valueBegin, valueEnd - valueBegin)) ;
	}

	return matches == 1U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 日付と時刻の有限範囲確認にだけ使用し、版比較には使用しない。
 *
 * @param[in] text 1～4桁のASCII数字。
 * @param[out] value 成功時の数値。失敗時は0。
 * @return 全文字をoverflowなく10進数へ変換できた場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readAsciiNumber( const std::wstring_view text, unsigned int &value) noexcept
{
	value = 0U ;
	// 空または四桁を超える日付・時刻の数値部分を拒否する。
	if( text.empty() || text.size() > 4U) {
		return false ;
	}

	// 全桁を有限回で確認し、Unicode数字や符号を受理しない。
	for( const wchar_t character : text) {
		// 数値に十進数字以外があれば部分値を消去して拒否する。
		if( character < L'0' || character > L'9') {
			value = 0U ;
			return false ;
		}

		value = value * 10U + static_cast<unsigned int>( character - L'0') ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief `major.minor.patch-build`以外の文字列から版を推測しない。
 *
 * @param[in] version Pageとfile名から得た配布版。
 * @return 三つの数値componentと一つのbuild番号で構成される場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isWacomVersion( const std::wstring_view version) noexcept
{
	// 空または固定表記の上限を超える version を拒否する。
	if( version.empty() || version.size() > 24U) {
		return false ;
	}

	std::size_t dotCount{} ;		// 完全に確認したdot区切り数。
	std::size_t hyphenCount{} ;		// 完全に確認したhyphen区切り数。
	std::size_t componentDigits{} ;	// 現在componentのASCII数字数。
	// 全文字を有限回で確認し、数値componentと既定の区切り以外を拒否する。
	for( const wchar_t character : version) {
		// 数字は現在 version 成分の桁数として数える。
		if( character >= L'0' && character <= L'9') {
			++componentDigits ;
			// 四桁を超える version 成分を拒否する。
			if( componentDigits > 4U) {
				return false ;
			}

			continue ;
		}

		// 空成分と dot・hyphen 以外の区切りを拒否する。
		if( componentDigits == 0U || (character != L'.' && character != L'-')) {
			return false ;
		}

		// Dot 区切りでは build 部分に入っていないことを確認する。
		if( character == L'.') {
			// Build の hyphen 後に dot が現れる version 表記を拒否する。
			if( hyphenCount != 0U) {
				return false ;
			}

			++dotCount ;
		} else {
			++hyphenCount ;
		}

		componentDigits = 0U ;
	}

	return componentDigits != 0U && dotCount == 2U && hyphenCount == 1U ;
}

//------------------------------------------------------------------------------
/**
 * @brief Locale変換を行わず、公式pageの明示値だけを表示用に切り出す。
 *
 * @param[in] value Page属性のM/D/YYYY h:mm:ss AM／PM値。
 * @param[out] date 成功時のM/D/YYYY部分。失敗時は空。
 * @return 日付と12時間制時刻の構造と範囲が有効な場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool parseReleaseDate( const std::wstring_view value, std::wstring &date)
{
	date.clear() ;
	const std::size_t dateEnd = value.find( L' ') ;	// 日付と時刻の区切り位置。
	// 日付と時刻の区切り欠落または空日付を拒否する。
	if( dateEnd == std::wstring_view::npos || dateEnd == 0U) {
		return false ;
	}

	const std::wstring_view datePart   = value.substr( 0U, dateEnd) ;		// M/D/YYYY部分。
	const std::wstring_view timePart   = value.substr( dateEnd + 1U) ;		// h:mm:ss AM／PM部分。
	const std::size_t		firstSlash = datePart.find( L'/') ;				// Monthとdayの区切り。
	const std::size_t secondSlash = datePart.find( L'/', firstSlash + 1U) ;	// Dayとyearの区切り。
	const std::size_t firstColon  = timePart.find( L':') ;					// Hourとminuteの区切り。
	const std::size_t secondColon =
		// Minuteとsecondの区切り。
		timePart.find( L':', firstColon + 1U) ;
	// 日付・時刻の区切り数と必要な末尾領域を確認する。
	if( firstSlash == std::wstring_view::npos || secondSlash == std::wstring_view::npos ||
	   datePart.find( L'/', secondSlash + 1U) != std::wstring_view::npos ||
	   firstColon == std::wstring_view::npos || secondColon == std::wstring_view::npos ||
	   timePart.size() < secondColon + 6U) {
		return false ;
	}

	const std::size_t meridiemSpace = timePart.size() - 3U ;	// AM／PM直前の空白位置。
	// 秒の後に固定の空白と AM／PM 表記がない日時を拒否する。
	if( meridiemSpace <= secondColon || timePart[meridiemSpace] != L' ' ||
	   (timePart.substr( meridiemSpace + 1U) != L"AM" &&
		timePart.substr( meridiemSpace + 1U) != L"PM")) {
		return false ;
	}

	unsigned int month{} ;	// 1～12の月。
	unsigned int day{} ;	// 1～31の日。
	unsigned int year{} ;	// 4桁の西暦年。
	unsigned int hour{} ;	// 1～12の時。
	unsigned int minute{} ;	// 0～59の分。
	unsigned int second{} ;	// 0～59の秒。
	// 年月日・時分秒が十進数として読め、個々の許可範囲に収まることを確認する。
	if( !readAsciiNumber( datePart.substr( 0U, firstSlash), month) ||
	   !readAsciiNumber( datePart.substr( firstSlash + 1U, secondSlash - firstSlash - 1U), day) ||
	   !readAsciiNumber( datePart.substr( secondSlash + 1U), year) ||
	   !readAsciiNumber( timePart.substr( 0U, firstColon), hour) ||
	   !readAsciiNumber( timePart.substr( firstColon + 1U, secondColon - firstColon - 1U), minute) ||
	   !readAsciiNumber( timePart.substr( secondColon + 1U, meridiemSpace - secondColon - 1U),
						second) ||
	   month < 1U || month > 12U || day < 1U || day > 31U || year < 2020U || hour < 1U ||
	   hour > 12U || minute > 59U || second > 59U) {
		return false ;
	}

	date.assign( datePart) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 概算値を正確なbyte数へ換算せず、markupや単位変更を拒否する。
 *
 * @param[in] value Page属性の概算size。
 * @return 1～4桁の正数と` MB`だけで構成される場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isDisplaySize( const std::wstring_view value) noexcept
{
	constexpr std::wstring_view SUFFIX = L" MB" ;	// 現行pageが用いる概算size単位。
	// 概算 size の単位、数値の存在、表示長上限を確認する。
	if( !value.ends_with( SUFFIX) || value.size() <= SUFFIX.size() || value.size() > 8U) {
		return false ;
	}

	const std::wstring_view digits =
		// MB単位のASCII数字部分。
		value.substr( 0U, value.size() - SUFFIX.size()) ;
	unsigned int megabytes{} ;	// 1～9999の概算MB値。
	return readAsciiNumber( digits, megabytes) && megabytes != 0U ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/wacom_driver_page_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseWacomWindowsDriverPage( const std::wstring_view html, WacomDriverPageMetadata &metadata)
{
	metadata = {} ;
	// 空・長さ上限超過・埋込み NUL のある page を解析しない。
	if( html.empty() || html.size() > MAXIMUM_HTML_CHARACTERS ||
	   html.find( L'\0') != std::wstring_view::npos) {
		return false ;
	}

	try {
		std::size_t				searchPosition{} ;	// 次のWindows markerを検索する開始位置。
		std::size_t				markerCount{} ;		// 有限走査したWindows marker数。
		std::size_t				concreteCount{} ;	// 具体的な公式CDN配布欄の数。
		WacomDriverPageMetadata accepted ;			// 一意性確定後に公開する具体的metadata。
		// Windows欄と既知templateを走査し、具体的な現行配布欄を一件だけ選別する。
		while( searchPosition < html.size()) {
			const std::size_t marker = html.find( WINDOWS_MARKER, searchPosition) ;	// OS属性位置。
			// Windows 用 marker を全て処理したら page 探索を終了する。
			if( marker == std::wstring_view::npos) {
				break ;
			}

			searchPosition = marker + WINDOWS_MARKER.size() ;
			++markerCount ;
			// Windows marker 数が固定上限を超える page を拒否する。
			if( markerCount > MAXIMUM_WINDOWS_MARKERS) {
				return false ;
			}

			const std::size_t tagBegin = html.rfind( L"<a ", marker) ;	// 対象a tagの開始位置。
			const std::size_t tagEnd   = html.find( L'>', marker) ;		// 対象a tagの終了位置。
			// Anchor の境界欠落、逆転、長さ超過を拒否する。
			if( tagBegin == std::wstring_view::npos || tagEnd == std::wstring_view::npos ||
			   tagEnd <= tagBegin || tagEnd - tagBegin > MAXIMUM_ANCHOR_CHARACTERS) {
				return false ;
			}

			const std::wstring_view tag =
				// 一つのdownload開始tag。
				html.substr( tagBegin, tagEnd - tagBegin + 1U) ;
			std::wstring operatingSystem ;	// 重複を拒否する対象OS属性値。
			// OS 属性が一意の Windows 指定でない anchor を拒否する。
			if( !readUniqueAttribute( tag, L"data-driver-os", operatingSystem) ||
			   operatingSystem != L"windows") {
				return false ;
			}

			std::wstring downloadUrl ;	// 具体URLまたは既知template値。
			// 通常の配布 URL 属性がない場合は既知の製品検索 template だけを確認する。
			if( !readUniqueAttribute( tag, L"data-download-link", downloadUrl)) {
				std::wstring latestTemplate ;	// 大文字属性名を使う製品検索template値。
				// 大文字属性の値が固定 template と一致しなければ別形式として拒否する。
				if( !readUniqueAttribute( tag, L"data-Download-link", latestTemplate) ||
				   latestTemplate != LATEST_TEMPLATE) {
					return false ;
				}

				continue ;
			}

			// 既知の履歴 template は具体的な現行配布リンクとして数えない。
			if( downloadUrl == HISTORY_TEMPLATE) {
				continue ;
			}

			++concreteCount ;
			// 具体的な配布先が複数ある場合は一つを推測して選ばない。
			if( concreteCount != 1U) {
				return false ;
			}

			WacomDriverPageMetadata parsed ;			// 全条件成立時だけacceptedへ移す結果。
			std::wstring			title ;				// OSと版を含むtitle属性。
			std::wstring			versionLabel ;		// `Driver `を含む版属性。
			std::wstring			description ;		// 対象OSとarchitecture属性。
			std::wstring			releaseDateValue ;	// 時刻を含む公開日属性。
			parsed.downloadUrl = std::move( downloadUrl) ;
			// 必須属性、OS 説明、size、日付、固定配布 URL と HTTPS policy を全て照合する。
			if( !readUniqueAttribute( tag, L"data-title", title) ||
			   !readUniqueAttribute( tag, L"data-version", versionLabel) ||
			   !readUniqueAttribute( tag, L"data-description", description) ||
			   !readUniqueAttribute( tag, L"data-size", parsed.displaySize) ||
			   !readUniqueAttribute( tag, L"data-release-date", releaseDateValue) ||
			   description != WINDOWS_DESCRIPTION || !isDisplaySize( parsed.displaySize) ||
			   !parseReleaseDate( releaseDateValue, parsed.releaseDate) ||
			   !parsed.downloadUrl.starts_with( DOWNLOAD_PREFIX) ||
			   parsed.downloadUrl.find( L'?') != std::wstring::npos ||
			   parsed.downloadUrl.find( L'#') != std::wstring::npos ||
			   validateOfficialHttpsUrl( parsed.downloadUrl, DOWNLOAD_HOSTS) != 0) {
				return false ;
			}

			const std::size_t fileSeparator =
				// Basename境界。
				parsed.downloadUrl.find_last_of( L'/') ;
			// URL 末尾に file 名がなければ配布情報を受理しない。
			if( fileSeparator == std::wstring::npos ||
			   fileSeparator + 1U >= parsed.downloadUrl.size()) {
				return false ;
			}

			parsed.fileName.assign( parsed.downloadUrl.substr( fileSeparator + 1U)) ;
			// 固定 file prefix・suffix と非空の version 部分を持つ名前だけを受理する。
			if( !parsed.fileName.starts_with( FILE_PREFIX) ||
			   !parsed.fileName.ends_with( FILE_SUFFIX) ||
			   parsed.fileName.size() <= FILE_PREFIX.size() + FILE_SUFFIX.size()) {
				return false ;
			}

			parsed.version.assign( parsed.fileName.substr(
				FILE_PREFIX.size(),
				parsed.fileName.size() - FILE_PREFIX.size() - FILE_SUFFIX.size())) ;
			const std::wstring expectedVersion =
				L"Driver " + parsed.version ;	// Page版属性の期待値。
			const std::wstring expectedTitle =
				expectedVersion + L" " + std::wstring( WINDOWS_DESCRIPTION) ;	// Title期待値。
			// File 名の版と表示版・title の明示値が一致することを必須とする。
			if( !isWacomVersion( parsed.version) || versionLabel != expectedVersion ||
			   title != expectedTitle) {
				return false ;
			}

			accepted = std::move( parsed) ;
		}

		// Windows marker が存在し、具体的な配布先が一件だけの page を受理する。
		if( markerCount == 0U || concreteCount != 1U) {
			return false ;
		}

		metadata = std::move( accepted) ;
		return true ;
	} catch( const std::bad_alloc &) {
		metadata = {} ;
		return false ;
	}
}

} // namespace drivercrate
