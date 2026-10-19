//------------------------------------------------------------------------------
/**
 * @file intel_wireless_page_parser.cpp
 * @brief Intel Wireless公式download page parser実装。
 * @version 01.01.00
 * @date 2026/09/03
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/23  非表示領域と可視ampersandを分離し拒否段階を公開。
 * </pre>
 *
 * @note 汎用HTML scrapingを行わず、Intel Wireless固定pageの必須表示と公式URLを一意に検証します。HTMLを実行せず、PnP IDをnetworkへ送信しませ
 *       ん。
 */
//------------------------------------------------------------------------------

#include "platform/intel_wireless_page_parser.h"

#include "platform/official_http_client.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t		MAXIMUM_HTML_CHARACTERS = 2U * 1024U * 1024U ;			// HTML文字数上限。
constexpr std::size_t		MAXIMUM_TAG_CHARACTERS	= 4096U ;						// 一HTML tagの文字数上限。
constexpr std::size_t		MAXIMUM_AVAILABLE_SECTION_CHARACTERS = 64U * 1024U ;	// 対象section上限。
constexpr std::size_t		MAXIMUM_URL_CHARACTERS			= 4096U ;				// Download URL文字数上限。
constexpr std::size_t		MAXIMUM_DISPLAY_SIZE_CHARACTERS = 32U ;					// 表示size文字数上限。

constexpr std::wstring_view AVAILABLE_DOWNLOADS	 = L"Available Downloads" ;			// 対象section開始。
constexpr std::wstring_view DETAILED_DESCRIPTION = L"Detailed Description" ;		// 対象section終了。
constexpr std::wstring_view FILE_PREFIX			 = L"WiFi-" ;						// Driver-only ZIP basename prefix。
constexpr std::wstring_view FILE_SUFFIX			 = L"-Driver64-Win10-Win11.zip" ;	// x64 ZIP suffix。
constexpr std::wstring_view EULA_NOTICE =
	L"Intel requires an accepted license agreement" ;	// 明示同意を要求する表示。
constexpr std::array DOWNLOAD_HOSTS{					// Payloadを許可する公式host。
									std::wstring_view( L"downloadmirror.intel.com")} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief HTML text用空白か判定する。
 *
 * Localeに依存せず、Intel pageで用いる空白だけを正規化する。
 *
 * @param[in] character 判定するUTF-16 code unit。
 * @return ASCII空白またはnon-breaking spaceの場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool	 isHtmlSpace( const wchar_t character) noexcept
{
	return character == L' ' || character == L'\t' || character == L'\r' || character == L'\n' ||
		   character == static_cast<wchar_t>( 0x00a0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Visible textへ単一空白を追加する。
 *
 * Tag境界や連続空白で単語を連結せず、重複空白を増やさない。
 *
 * @param[in,out] text HTML tagを除去中のvisible text。
 */
//------------------------------------------------------------------------------
void appendHtmlSpace( std::wstring &text)
{
	// 表示textの先頭や連続する余分な空白を増やさない。
	if( !text.empty() && text.back() != L' ') {
		text.push_back( L' ') ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief HTMLから有限なvisible textを構築する。
 *
 * DOMやscriptを実行せず、必須ASCII labelの検証だけに使う。
 *
 * @param[in] html 実行せず解析するHTML全体。
 * @return Tagとentityを空白化したtext。不正境界時は`std::nullopt`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> normalizeHtmlText( const std::wstring_view html)
{
	// 空、過大、埋込NUL付きのHTMLをtext変換前に拒否する。
	if( html.empty() || html.size() > MAXIMUM_HTML_CHARACTERS ||
	   html.find( L'\0') != std::wstring_view::npos) {
		return std::nullopt ;
	}

	std::wstring text ;	// Tagを除去し空白を正規化する出力。
	try {
		text.reserve( html.size()) ;
		std::wstring lower( html) ;	// 非表示領域の境界検出だけに使うASCII小文字。
		std::ranges::transform( lower, lower.begin(), []( const wchar_t ch) {
			return ch >= L'A' && ch <= L'Z' ? static_cast<wchar_t>( ch + L'a' - L'A') : ch ;
		}) ;
		// 全入力を一度だけ走査し、tagとentityをvisible labelから分離する。
		for( std::size_t index = 0; index < html.size();) {
			const wchar_t character = html[index] ;	// 現在処理するcode unit。
			// Comment内の疑似tagやentityを可視metadataとして解析しない。
			if( lower.compare( index, 4U, L"<!--") == 0) {
				const auto end = lower.find( L"-->", index + 4U) ;	// Comment終端。
				// 未閉鎖commentは部分本文として扱わない。
				if( end == lower.npos) {
					return std::nullopt ;
				}

				index = end + 3U ;
				appendHtmlSpace( text) ;
				continue ;
			}

			// tag範囲を文字列から除き、表示textの区切りへ変換する。
			if( character == L'<') {
				const std::size_t end = html.find( L'>', index + 1U) ;	// Tag終端位置。
				// 閉じないtagや上限超過のtagを拒否する。
				if( end == std::wstring_view::npos || end - index > MAXIMUM_TAG_CHARACTERS) {
					return std::nullopt ;
				}

				bool hidden{} ;	// 非表示領域を飛ばした場合だけtrue。
				// 実行しないraw text領域は全文を省き、後続の可視欄を維持する。
				for( const std::wstring_view name : {L"script", L"style", L"textarea"}) {
					const std::size_t boundary = index + 1U + name.size() ;	// Tag名直後。
					// Prefix類似名を非表示tagと誤認しない。
					if( lower.compare( index + 1U, name.size(), name) != 0 || boundary > end ||
					   (boundary != end && !isHtmlSpace( lower[boundary]))) {
						continue ;
					}

					const std::wstring closing = L"</" + std::wstring( name) + L">" ;	// 対応終端。
					const auto close = lower.find( closing, end + 1U) ;					// 最初の正しいraw終端。
					// 未閉鎖領域を可視textへ戻さない。
					if( close == lower.npos) {
						return std::nullopt ;
					}

					index  = close + closing.size() ;
					hidden = true ;
					break ;
				}

				appendHtmlSpace( text) ;
				// 非表示領域を飛ばしていない通常tagだけを次の文字へ進める。
				if( !hidden) {
					index = end + 1U ;
				}

				continue ;
			}

			// entityの範囲を確認して表示textの区切りとして扱う。
			if( character == L'&') {
				const wchar_t next =
					index + 1U < html.size() ? html[index + 1U] : L' ' ;	// Entity開始判定。
				// 可視の「A & B」はentityではない。文字参照らしい不正入力は従来どおり拒否する。
				if( !((next >= L'a' && next <= L'z') || (next >= L'A' && next <= L'Z') ||
					 next == L'#')) {
					text.push_back( L'&') ;
					++index ;
					continue ;
				}

				const std::size_t end = html.find( L';', index + 1U) ;	// Entity終端位置。
				// 未終端または過大なentity表現を拒否する。
				if( end == std::wstring_view::npos || end - index > 16U) {
					return std::nullopt ;
				}

				appendHtmlSpace( text) ;
				index = end + 1U ;
				continue ;
			}

			// HTML空白を表示用の単一空白へ揃える。
			if( isHtmlSpace( character)) {
				appendHtmlSpace( text) ;
			} else {
				text.push_back( character) ;
			}

			++index ;
		}
	} catch( const std::bad_alloc &) {
		return std::nullopt ;
	}

	// 表示textの末尾に不要な区切り空白を残さない。
	if( !text.empty() && text.back() == L' ') {
		text.pop_back() ;
	}

	return text.empty() ? std::nullopt : std::optional<std::wstring>( std::move( text)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Markerが一度だけ現れる位置を取得する。
 *
 * 欠落と重複を同じmetadata拒否として扱う。
 *
 * @param[in] text 検索対象text。
 * @param[in] marker 空でない固定marker。
 * @param[out] position 成功時のmarker開始位置。
 * @return Markerが一度だけ存在する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool findUniqueMarker( const std::wstring_view text, const std::wstring_view marker,
									std::size_t &position) noexcept
{
	position = text.find( marker) ;
	return !marker.empty() && position != std::wstring_view::npos &&
		   text.find( marker, position + marker.size()) == std::wstring_view::npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief Intel package version形式を検証する。
 *
 * File名から任意path文字や曖昧なversionを受理しない。
 *
 * @param[in] version ZIP basenameから取得したversion。
 * @return 2～4個の1～3桁ASCII数値componentなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isIntelVersion( const std::wstring_view version) noexcept
{
	// 空または長すぎるpackage版を拒否する。
	if( version.empty() || version.size() > 15U) {
		return false ;
	}

	std::size_t components{} ;	// 完全に検証した数値component数。
	std::size_t digits{} ;		// 現在component内のASCII数字数。
	// 全code unitを走査し、数字と区切り以外を拒否する。
	for( const wchar_t character : version) {
		// 版の数字を要素ごとに数えて桁数を検証する。
		if( character >= L'0' && character <= L'9') {
			++digits ;
			// 一要素が3桁を超える版を拒否する。
			if( digits > 3U) {
				return false ;
			}

			continue ;
		}

		// dot以外の区切りと空の版要素を拒否する。
		if( character != L'.' || digits == 0U) {
			return false ;
		}

		++components ;
		digits = 0U ;
	}

	return digits != 0U && components + 1U >= 2U && components + 1U <= 4U ;
}

//------------------------------------------------------------------------------
/**
 * @brief Driver-only ZIP basenameからversionを取得する。
 *
 * Win10／Win11 x64 driver-only ZIP以外を探索対象にしない。
 *
 * @param[in] fileName URL末尾のbasename。
 * @param[out] version 成功時のpackage version。
 * @return 固定prefix／suffixとversion形式が有効なら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool parseIntelFileName( const std::wstring_view fileName, std::wstring &version)
{
	version.clear() ;
	// driver-only ZIPの命名系列に合わないfile名を拒否する。
	if( !fileName.starts_with( FILE_PREFIX) || !fileName.ends_with( FILE_SUFFIX) ||
	   fileName.size() <= FILE_PREFIX.size() + FILE_SUFFIX.size()) {
		return false ;
	}

	// 固定prefixとsuffixの間に明示されたpackage版数。File名全体の借用部分。
	const std::wstring_view parsed = fileName.substr(
		FILE_PREFIX.size(), fileName.size() - FILE_PREFIX.size() - FILE_SUFFIX.size()) ;
	// file名内の版が許可形式に合わなければ候補化しない。
	if( !isIntelVersion( parsed)) {
		return false ;
	}

	version.assign( parsed) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief HTML anchorから一意のIntel ZIP URLを取得する。
 *
 * Query、fragment、別host、複数候補を推測せず拒否する。
 *
 * @param[in] html Intel pageのraw HTML。
 * @param[out] url 成功時の公式HTTPS payload URL。
 * @param[out] fileName 成功時のdriver-only ZIP basename。
 * @param[out] version 成功時のpackage version。
 * @return 条件を満たすanchorが一件だけなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readDownloadUrl( const std::wstring_view html, std::wstring &url,
								   std::wstring &fileName, std::wstring &version)
{
	url.clear() ;
	fileName.clear() ;
	version.clear() ;
	constexpr std::wstring_view HREF = L"href=\"" ;	// 許可するanchor attribute開始。
	std::size_t					searchPosition{} ;	// 次のhrefを検索する位置。
	std::size_t					matches{} ;			// 条件に一致したdownload anchor数。
	// 全hrefを有限入力内で調べ、driver-only basenameを持つものだけを評価する。
	while( searchPosition < html.size()) {
		const std::size_t href = html.find( HREF, searchPosition) ;	// Href開始位置。
		// 後続のhrefがなければリンク探索を終了する。
		if( href == std::wstring_view::npos) {
			break ;
		}

		const std::size_t valueBegin = href + HREF.size() ;				// URL開始位置。
		const std::size_t valueEnd	 = html.find( L'\"', valueBegin) ;	// URL終了位置。
		// URL属性の未終端や長さ超過を拒否する。
		if( valueEnd == std::wstring_view::npos || valueEnd - valueBegin > MAXIMUM_URL_CHARACTERS) {
			return false ;
		}

		const std::wstring_view candidateUrl =
			// 現在anchorのURL。
			html.substr( valueBegin, valueEnd - valueBegin) ;
		searchPosition = valueEnd + 1U ;
		// queryやfragment付きリンクをpayload候補から除外する。
		if( candidateUrl.find( L'?') != std::wstring_view::npos ||
		   candidateUrl.find( L'#') != std::wstring_view::npos) {
			continue ;
		}

		const std::size_t separator = candidateUrl.find_last_of( L'/') ;	// Basename開始境界。
		// 空でないfile名を末尾から得られないリンクを除外する。
		if( separator == std::wstring_view::npos || separator + 1U >= candidateUrl.size()) {
			continue ;
		}

		const std::wstring_view candidateFile = candidateUrl.substr( separator + 1U) ;	// Basename。
		std::wstring			candidateVersion ;										// Basenameから検証したversion。
		// 対象ZIP名として解析できないリンクを除外する。
		if( !parseIntelFileName( candidateFile, candidateVersion)) {
			continue ;
		}

		// 対象名でも許可HTTPS host以外のURLは拒否する。
		if( validateOfficialHttpsUrl( candidateUrl, DOWNLOAD_HOSTS) != 0) {
			return false ;
		}

		++matches ;
		// 対象リンクが複数ある場合は一つを推測採用しない。
		if( matches != 1U) {
			return false ;
		}

		url.assign( candidateUrl) ;
		fileName.assign( candidateFile) ;
		version = std::move( candidateVersion) ;
	}

	return matches == 1U ;
}

//------------------------------------------------------------------------------
/**
 * @brief Label直後の単一tokenを取得する。
 *
 * 欠落、重複、上限超過をmetadata拒否として扱う。
 *
 * @param[in] section Available Downloadsのvisible text。
 * @param[in] label 一意であるべき固定label。
 * @param[in] maximum Token文字数上限。
 * @param[out] token 成功時の空白までの値。
 * @return Labelと有限な非空tokenが一度だけ存在する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readUniqueToken( const std::wstring_view section, const std::wstring_view label,
								   const std::size_t maximum, std::wstring &token)
{
	token.clear() ;
	std::size_t labelPosition{} ;	// 一意なlabelの開始位置。
	// labelが一意でなければ直後の値を採用しない。
	if( !findUniqueMarker( section, label, labelPosition)) {
		return false ;
	}

	std::size_t valueBegin = labelPosition + label.size() ;	// 空白除去前の値開始位置。
	// labelと値の間の空白だけを範囲内で読み飛ばす。
	while( valueBegin < section.size() && section[valueBegin] == L' ') {
		++valueBegin ;
	}

	const std::size_t valueEnd = section.find( L' ', valueBegin) ;	// Token終了位置。
	// 次のfield開始位置またはsection末尾を使う、現在値の終端。
	const std::size_t end = valueEnd == std::wstring_view::npos ? section.size() : valueEnd ;
	// 空または上限超過のtokenをmetadataとして採用しない。
	if( valueBegin >= end || end - valueBegin > maximum) {
		return false ;
	}

	token.assign( section.substr( valueBegin, end - valueBegin)) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示sizeをSHA-256 label手前から取得する。
 *
 * 概算sizeは表示だけに保持し、download完全性には使用しない。
 *
 * @param[in] section Available Downloadsのvisible text。
 * @param[out] displaySize 成功時の概算size文字列。
 * @return SizeとSHA256 labelが一意で順序と文字種が有効なら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readDisplaySize( const std::wstring_view section, std::wstring &displaySize)
{
	displaySize.clear() ;
	std::size_t sizePosition{} ;	// 一意なSize label位置。
	std::size_t hashPosition{} ;	// 一意なSHA256 label位置。
	// sizeとhashのlabelが一意に得られなければ値の境界を推測しない。
	if( !findUniqueMarker( section, L"Size:", sizePosition) ||
	   !findUniqueMarker( section, L"SHA256:", hashPosition)) {
		return false ;
	}

	std::size_t begin = sizePosition + 5U ;	// Size label直後の位置。
	// size表示の先頭空白だけを除く。
	while( begin < section.size() && section[begin] == L' ') {
		++begin ;
	}

	std::size_t end = hashPosition ;	// SHA256 label直前の位置。
	// size表示の末尾空白だけを範囲を越えず除く。
	while( end > begin && section[end - 1U] == L' ') {
		--end ;
	}

	// 空または過大なsize表示を拒否する。
	if( begin >= end || end - begin > MAXIMUM_DISPLAY_SIZE_CHARACTERS) {
		return false ;
	}

	const std::wstring_view value = section.substr( begin, end - begin) ;	// Size表示値。
	// size表示に数値、空白、既知単位以外の文字を許容しない。
	if( !std::ranges::all_of( value, []( const wchar_t character) {
		   return (character >= L'0' && character <= L'9') || character == L'.' ||
				  character == L' ' || character == L'M' || character == L'G' || character == L'B' ;
	   })) {
		return false ;
	}

	displaySize.assign( value) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief SHA-256表示値を検証する。
 *
 * Unicode類似文字、短縮hash、区切り文字を受理しない。
 *
 * @param[in] value Pageから取得したhash token。
 * @return 64桁uppercase ASCII hexだけなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isUpperSha256( const std::wstring_view value) noexcept
{
	return value.size() == 64U && std::ranges::all_of( value, []( const wchar_t character) {
			   return (character >= L'0' && character <= L'9') ||
					  (character >= L'A' && character <= L'F') ;
		   }) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/intel_wireless_page_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseIntelWirelessDownloadPage( const std::wstring_view	   html,
									IntelWirelessPageMetadata &metadata,
									std::uint32_t			  *failureStage)
{
	const auto reject = [failureStage]( const std::uint32_t stage) {
		// 任意診断callerにだけ内容非保持の失敗段階を返す。
		if( failureStage != nullptr) {
			*failureStage = stage ;
		}

		return false ;
	} ; // 呼出し中だけ有効な診断先。
	// 成功時または未失敗の段階を0で初期化する。
	if( failureStage != nullptr) {
		*failureStage = 0U ;
	}

	metadata									 = {} ;
	const std::optional<std::wstring> normalized = normalizeHtmlText( html) ;	// Visible text。
	// HTMLを有限な表示textへ変換できない場合は解析を中止する。
	if( !normalized.has_value()) {
		return reject( 1U) ;
	}

	std::size_t availablePosition{} ;	// Available Downloads開始位置。
	std::size_t detailsPosition{} ;		// Detailed Description開始位置。
	// download欄と説明欄の見出しが一意に得られることを要求する。
	if( !findUniqueMarker( normalized.value(), AVAILABLE_DOWNLOADS, availablePosition) ||
	   !findUniqueMarker( normalized.value(), DETAILED_DESCRIPTION, detailsPosition)) {
		return reject( 2U) ;
	}

	// Available Downloads見出しの直後から配布情報を探索する開始境界。
	const std::size_t sectionBegin = availablePosition + AVAILABLE_DOWNLOADS.size() ;
	// download欄の順序や長さが不正なページを拒否する。
	if( sectionBegin >= detailsPosition ||
	   detailsPosition - sectionBegin > MAXIMUM_AVAILABLE_SECTION_CHARACTERS) {
		return reject( 3U) ;
	}

	const std::wstring_view section( normalized->data() + sectionBegin,
									detailsPosition - sectionBegin) ;	// Download表示範囲。
	try {
		IntelWirelessPageMetadata parsed ;	// 全検証成功時だけ公開する一時metadata。
		// 一意な取得先のfile名が表示欄にも存在することを確認する。
		if( !readDownloadUrl( html, parsed.downloadUrl, parsed.fileName, parsed.version) ||
		   section.find( parsed.fileName) == std::wstring_view::npos) {
			return reject( 4U) ;
		}

		const std::wstring intro = L"drivers-only distribution packages for Wi-Fi version " +
								   parsed.version ;	// Version整合用公式紹介文。
		std::size_t introPosition{} ;				// 一意な紹介文の開始位置。
		// 説明、driver-only、Windows x64、EULA案内の対応を確認する。
		if( !findUniqueMarker( normalized.value(), intro, introPosition) ||
		   normalized->find( L"Drivers only:") == std::wstring::npos ||
		   section.find( L"Windows 11") == std::wstring_view::npos ||
		   section.find( L"Windows 10") == std::wstring_view::npos ||
		   section.find( L"64-bit") == std::wstring_view::npos ||
		   !findUniqueMarker( normalized.value(), EULA_NOTICE, introPosition)) {
			return reject( 5U) ;
		}

		// 表示sizeとSHA-256を検証できなければ候補情報を返さない。
		if( !readDisplaySize( section, parsed.displaySize) ||
		   !readUniqueToken( section, L"SHA256:", 64U, parsed.sha256) ||
		   !isUpperSha256( parsed.sha256)) {
			return reject( 6U) ;
		}

		parsed.requiresEula = true ;
		metadata			= std::move( parsed) ;
		return true ;
	} catch( const std::bad_alloc &) {
		metadata = {} ;
		return reject( 7U) ;
	}
}

} // namespace drivercrate
