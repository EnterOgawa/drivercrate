//------------------------------------------------------------------------------
/**
 * @file intel_ethernet_server_page_parser.cpp
 * @brief Intel Ethernet Server／Windows 11公式download page parser実装。
 * @version 01.04.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  単一配布と許諾snapshotの結合を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Windows 11 record専用profileを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  現行pageのplain text配布版表記を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/28  配布・許諾へ元controlを伝播しOOMを保持。
 * Ver.01.04.00 Shunji Ogawa  2026/10/26  SHA-512単独と両hash掲載の有限検証を追加。
 * </pre>
 *
 * @note 固定Intel download pageを実行せず解析します。ServerとClientのprofileを混同せず、
 *       欠落、重複、別OS、別host、別形式を推測で補完しません。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#include "platform/intel_ethernet_server_page_parser.h"

#include "platform/intel_download_license_parser.h"
#include "platform/official_http_client.h"

#include <algorithm>
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

constexpr std::size_t		MAXIMUM_HTML_CHARACTERS = 2U * 1024U * 1024U ;	// HTML文字数上限。
constexpr std::size_t		MAXIMUM_URL_CHARACTERS	= 4096U ;				// Download URL文字数上限。
constexpr std::size_t		MAXIMUM_DISPLAY_SIZE_CHARACTERS = 32U ;			// 概算size文字数上限。
constexpr std::wstring_view FILE_PREFIX = L"Wired_driver_" ;				// 対象ZIP名の固定prefix。
constexpr std::wstring_view FILE_SUFFIX = L"_x64.zip" ;						// Windows x64 ZIPの固定suffix。
constexpr std::wstring_view EULA_NOTICE =
	L"Intel requires an accepted license agreement" ;	// 取得前同意を要求する表示。
constexpr std::array DOWNLOAD_HOSTS{					// Payload URLとして認識する公式host。
									std::wstring_view( L"downloadmirror.intel.com")} ;

/**
 * @brief Intel Ethernet download pageの固定profile条件です。
 */
struct IntelEthernetPageProfile {
	/// 一意な配布record名を識別するtitle marker。
	std::wstring_view productTitle ;
	/// Available Downloads欄で要求する対象OS marker。
	std::wstring_view operatingSystem ;
	/// 対象製品一覧で要求するprofile固有marker。不要なprofileでは空です。
	std::wstring_view requiredProduct ;
} ;

constexpr IntelEthernetPageProfile SERVER2025_PROFILE{
	.productTitle	 = L"Intel\x00ae Network Adapter Driver for Windows Server 2025",
	.operatingSystem = L"Windows Server 2025 family"} ;	// 既存Server 2025専用条件。
constexpr IntelEthernetPageProfile WINDOWS11_PROFILE{
	.productTitle	 = L"Intel\x00ae Network Adapter Driver for Microsoft Windows 11",
	.operatingSystem = L"Windows 11 Family",
	.requiredProduct = L"Intel\x00ae Ethernet Network Adapter E610-XT2"} ;	// Record 727998条件。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 欠落と重複を区別せずmetadata拒否にする。
 *
 * @param[in] text 有限長の検索対象。
 * @param[in] marker 一度だけ存在すべき固定文字列。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] position 成功時の開始位置。
 * @return Markerが一度だけ存在する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool findUniqueMarker( CollectorParserContext *control, const std::wstring_view text,
									const std::wstring_view marker, std::size_t &position)
{
	collectorParserCheckpoint( control) ;
	position = collectorParserFind( control, text, marker) ;
	return !marker.empty() && position != std::wstring_view::npos &&
		   collectorParserFind( control, text, marker, position + marker.size()) ==
			   std::wstring_view::npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief 任意path文字、空component、過大な数値表現を受理しない。
 *
 * @param[in] version ZIP basenameから得た配布版。
 * @return 2～4個の1～3桁ASCII数値componentならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isIntelVersion( const std::wstring_view version) noexcept
{
	// 空または長すぎる版をpayload名へ使用しない。
	if( version.empty() || version.size() > 15U) {
		return false ;
	}

	std::size_t components{} ;	// 完全に検証した区切り前component数。
	std::size_t digits{} ;		// 現在componentのASCII数字数。
	// 全文字を有限回で確認し、数字とdot以外を拒否する。
	for( const wchar_t character : version) {
		// 数字を現在の版要素へ数え、許可桁数を検証する。
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
 * @brief Complete Pack、EXE、x86、別命名系列を表示対象へ混入させない。
 *
 * @param[in] fileName URL末尾のbasename。
 * @param[out] version 成功時の明示配布版。
 * @return Windows Server向けx64 ZIP名と版形式が有効ならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool parseFileName( const std::wstring_view fileName, std::wstring &version)
{
	version.clear() ;
	// 対象系列のx64 ZIP命名に合わないfileを候補にしない。
	if( !fileName.starts_with( FILE_PREFIX) || !fileName.ends_with( FILE_SUFFIX) ||
	   fileName.size() <= FILE_PREFIX.size() + FILE_SUFFIX.size()) {
		return false ;
	}

	// Prefixとsuffixを除いた版文字列。元のfileNameと同じ有効期間だけ参照する。
	const std::wstring_view parsed = fileName.substr(
		FILE_PREFIX.size(), fileName.size() - FILE_PREFIX.size() - FILE_SUFFIX.size()) ;
	// file名から取り出した版が許可形式でなければ拒否する。
	if( !isIntelVersion( parsed)) {
		return false ;
	}

	version.assign( parsed) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief hrefとdata-hrefの共通末尾を読み、query、fragment、別host、複数候補を拒否する。
 *
 * @param[in] html 固定Intel pageのraw HTML。
 * @param[out] url 成功時の公式HTTPS URL。
 * @param[out] fileName 成功時の対象ZIP basename。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] version 成功時の明示配布版。
 * @return 条件を満たすURLが一件だけならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readDownloadUrl( CollectorParserContext *control, const std::wstring_view html,
								   std::wstring &url, std::wstring &fileName, std::wstring &version)
{
	collectorParserCheckpoint( control) ;
	url.clear() ;
	fileName.clear() ;
	version.clear() ;
	constexpr std::wstring_view HREF = L"href=\"" ;	// href／data-hrefの値開始marker。
	std::size_t					searchPosition{} ;	// 次のattributeを検索する位置。
	std::size_t					matches{} ;			// 対象ZIP URLの一致数。
	// 全href文字列を走査し、許可命名のZIPだけを評価する。
	while( searchPosition < html.size()) {
		collectorParserStep( control) ;
		const std::size_t href =
			// Attribute開始位置。
			collectorParserFind( control, html, HREF, searchPosition) ;
		// 後続のhrefがなければ有限探索を終了する。
		if( href == std::wstring_view::npos) {
			break ;
		}

		const std::size_t valueBegin = href + HREF.size() ;	// URL開始位置。
		const std::size_t valueEnd =
			// URL終了位置。
			collectorParserFind( control, html, L'\"', valueBegin) ;
		// URL属性の未終端または長さ超過を拒否する。
		if( valueEnd == std::wstring_view::npos || valueEnd - valueBegin > MAXIMUM_URL_CHARACTERS) {
			return false ;
		}

		const std::wstring_view candidateUrl =
			// 現在確認するURL。
			html.substr( valueBegin, valueEnd - valueBegin) ;
		searchPosition = valueEnd + 1U ;
		// queryやfragment付きURLをpayload候補から除外する。
		if( collectorParserFind( control, candidateUrl, L'?') != std::wstring_view::npos ||
		   collectorParserFind( control, candidateUrl, L'#') != std::wstring_view::npos) {
			continue ;
		}

		const std::size_t separator =
			// Basename境界。
			collectorParserFindSet( control, candidateUrl, L"/", false, true) ;
		// 空でない末尾file名を得られないURLを除外する。
		if( separator == std::wstring_view::npos || separator + 1U >= candidateUrl.size()) {
			continue ;
		}

		const std::wstring_view candidateFile = candidateUrl.substr( separator + 1U) ;	// Basename。
		std::wstring			candidateVersion ;										// 現在URLのbasenameから検証した配布版。
		// 対象ZIP名として解析できないリンクを除外する。
		if( !parseFileName( candidateFile, candidateVersion)) {
			continue ;
		}

		// 対象名でも許可HTTPS hostでなければ取得先として認めない。
		if( validateOfficialHttpsUrl( candidateUrl, DOWNLOAD_HOSTS) != 0) {
			return false ;
		}

		++matches ;
		// 複数の対象リンクがある場合は取得先を推測しない。
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
 * @brief HTMLを実行せず、現在pageの単一text nodeだけを読み取る。
 *
 * @param[in] html 固定公式pageのraw HTML。
 * @param[in] label 一度だけ存在すべきASCII label。
 * @param[in] maximum 受理する値の最大文字数。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] value 成功時のtrim済みvisible値。
 * @return Label直後から次のtagまでに有限な値が一件ある場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readTextValue( CollectorParserContext *control, const std::wstring_view html,
								 const std::wstring_view label, const std::size_t maximum,
								 std::wstring &value)
{
	collectorParserCheckpoint( control) ;
	value.clear() ;
	std::size_t position{} ;	// 一意なlabelの開始位置。
	// labelが一意でない場合は表示値を採用しない。
	if( !findUniqueMarker( control, html, label, position)) {
		return false ;
	}

	std::size_t begin = position + label.size() ;	// 空白除去前の値開始位置。
	// 値の先頭にあるASCII空白文字だけを有限なHTML範囲内で読み飛ばす。
	while( begin < html.size() && (html[begin] == L' ' || html[begin] == L'\t' ||
								  html[begin] == L'\r' || html[begin] == L'\n')) {
		collectorParserStep( control) ;
		++begin ;
	}

	std::size_t end = collectorParserFind( control, html, L'<', begin) ;	// 現在text nodeの終了位置。
	// text nodeの終端がない断片を採用しない。
	if( end == std::wstring_view::npos) {
		return false ;
	}

	// Text node末尾にあるASCII空白文字だけを逆方向へ読み飛ばす。
	while( end > begin && (html[end - 1U] == L' ' || html[end - 1U] == L'\t' ||
						  html[end - 1U] == L'\r' || html[end - 1U] == L'\n')) {
		collectorParserStep( control) ;
		--end ;
	}

	// 空または上限超過の表示値を拒否する。
	if( begin >= end || end - begin > maximum) {
		return false ;
	}

	value.assign( html.substr( begin, end - begin)) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示値をbyte数へ推測変換せず、明らかなmarkup混入だけを拒否する。
 *
 * @param[in] value 公式pageの概算size表示。
 * @return 数値、dot、空白、MB／GBを構成する有限値ならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isDisplaySize( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= MAXIMUM_DISPLAY_SIZE_CHARACTERS &&
		   std::ranges::all_of( value, []( const wchar_t character) {
			   return (character >= L'0' && character <= L'9') || character == L'.' ||
					  character == L' ' || character == L'M' || character == L'G' ||
					  character == L'B' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 短縮hash、区切り、Unicode類似文字を受理しない。
 *
 * @param[in] value 公式pageのhash表示。
 * @return 64桁のuppercase ASCII hexならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isUpperSha256( const std::wstring_view value) noexcept
{
	return value.size() == 64U && std::ranges::all_of( value, []( const wchar_t character) {
			   return (character >= L'0' && character <= L'9') ||
					  (character >= L'A' && character <= L'F') ;
		   }) ;
}

/**
 * @brief SHA-512の公表値を大小文字のASCII hexだけに限定します。
 * @param[in] value 同じ配布pageのhash表示。
 * @return 省略や切詰めのない128桁ASCII hexならtrue。
 */
[[nodiscard]] bool isSha512( const std::wstring_view value) noexcept
{
	return value.size() == 128U && std::ranges::all_of( value, []( const wchar_t character) {
			   return (character >= L'0' && character <= L'9') ||
					  (character >= L'A' && character <= L'F') ||
					  (character >= L'a' && character <= L'f') ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Button labelの二重出現を説明欄の版一致として代用しません。
 *
 * @param[in] html 同一配布page。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] fileName URLから検証したZIP名。
 * @return 一意な説明欄のdriver package名と完全一致する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool descriptionMatchesFile( CollectorParserContext *control,
										  const std::wstring_view html,
										  const std::wstring_view fileName)
{
	collectorParserCheckpoint( control) ;
	constexpr std::wstring_view LABEL = L"Driver Package:" ;	// 公式説明欄のlabel。
	std::size_t					position{} ;					// 一意な説明labelの位置。
	// 説明欄の版labelを一意に特定できなければ版一致とみなさない。
	if( !findUniqueMarker( control, html, LABEL, position)) {
		return false ;
	}

	std::wstring_view remainder = html.substr( position + LABEL.size()) ;	// 後続のtextとtag。
	// Strong label内の末尾空白、またはplain label後の空白だけを読み飛ばす。
	while( !remainder.empty() &&
		  (remainder.front() == L' ' || remainder.front() == L'\t' || remainder.front() == L'\r' ||
		   remainder.front() == L'\n' || remainder.front() == L'\u00a0' ||
		   remainder.starts_with( L"&nbsp;"))) {
		collectorParserStep( control) ;
		remainder.remove_prefix( remainder.starts_with( L"&nbsp;") ? 6U : 1U) ;
	}

	// Strong要素でlabelだけを囲む従来構造では、その終端だけを読み飛ばす。
	if( remainder.starts_with( L"</strong>")) {
		remainder.remove_prefix( 9U) ;
	}
	// Plain text以外の未確認tagがlabelと配布版の間にある場合は拒否する。
	else if( !remainder.empty() && remainder.front() == L'<') {
		return false ;
	}

	// 従来strong構造と現行plain構造に共通するASCII／NBSP空白だけを読み飛ばす。
	while( !remainder.empty() &&
		  (remainder.front() == L' ' || remainder.front() == L'\t' || remainder.front() == L'\r' ||
		   remainder.front() == L'\n' || remainder.front() == L'\u00a0' ||
		   remainder.starts_with( L"&nbsp;"))) {
		collectorParserStep( control) ;
		remainder.remove_prefix( remainder.starts_with( L"&nbsp;") ? 6U : 1U) ;
	}

	// label後に配布版textが残らなければ版を取得できたとみなさない。
	if( remainder.empty()) {
		return false ;
	}

	const std::size_t end =
		// 次のtagまでが一つの明示file名。
		collectorParserFind( control, remainder, L'<') ;
	// 説明欄の版textが未終端または過大なら拒否する。
	if( end == remainder.npos || end > 256U) {
		return false ;
	}

	remainder = remainder.substr( 0U, end) ;
	const std::size_t last =
		// 末尾空白境界。
		collectorParserFindSet( control, remainder, L" \t\r\n\u00a0", true, true) ;
	return last != remainder.npos && remainder.substr( 0U, last + 1U) == fileName ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのIntel Ethernet profileだけを静的pageから解析します。
 * @param[in] html 固定公式rootから得た有限HTML。
 * @param[in] profile 呼出し側が固定した製品、OS、対象製品marker。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] metadata 成功時の型付きmetadata。失敗時は初期値。
 * @return Profileと配布行、hash、EULAが整合する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool parseIntelEthernetDownloadPage( CollectorParserContext			*control,
												  const std::wstring_view			 html,
												  const IntelEthernetPageProfile	&profile,
												  IntelEthernetDownloadPageMetadata &metadata)
{
	collectorParserCheckpoint( control) ;
	metadata = {} ;
	// 製品、OS、EULA案内、必要欄を含む上限内のページだけを解析する。
	// 元本文の明示上限超過を配布欠測と分離します。
	if( html.size() > MAXIMUM_HTML_CHARACTERS) {
		collectorParserLimit( control) ;
	}

	// 同じ本文に公式profileの必須表示があることを確認します。
	if( html.empty() || html.size() > MAXIMUM_HTML_CHARACTERS ||
	   collectorParserFind( control, html, L'\0') != std::wstring_view::npos ||
	   collectorParserFind( control, html, profile.productTitle) == std::wstring_view::npos ||
	   collectorParserFind( control, html, profile.operatingSystem) == std::wstring_view::npos ||
	   (!profile.requiredProduct.empty() &&
		collectorParserFind( control, html, profile.requiredProduct) == std::wstring_view::npos) ||
	   collectorParserFind( control, html, EULA_NOTICE) == std::wstring_view::npos ||
	   collectorParserFind( control, html, L"Available Downloads") == std::wstring_view::npos ||
	   collectorParserFind( control, html, L"Detailed Description") == std::wstring_view::npos) {
		return false ;
	}

	try {
		IntelEthernetServerPageMetadata parsed ;	// 全条件成立時だけ公開する一時結果。
		// 一意な取得先とdriver package表記がなければ候補を返さない。
		if( !readDownloadUrl( control, html, parsed.downloadUrl, parsed.fileName, parsed.version) ||
		   collectorParserFind( control, html, L"Driver Package:") == std::wstring_view::npos) {
			return false ;
		}

		std::wstring displaySize ;	// Size labelから得た概算表示。
		std::wstring sha256 ;		// SHA256 labelから得た公開hash。
		std::wstring sha512 ;		// SHA512 labelから得た別算法の公開hash。
		const bool	 hasSha256 =
			// 旧形式の掲載有無。
			collectorParserFind( control, html, L"SHA256:") != html.npos ;
		const bool hasSha512 =
			// 新形式の掲載有無。
			collectorParserFind( control, html, L"SHA512:") != html.npos ;
		// 少なくとも一方を要求し、掲載された両hashの重複・不正を他方で救済しません。
		if( !readTextValue( control, html, L"Size:", MAXIMUM_DISPLAY_SIZE_CHARACTERS, displaySize) ||
		   !isDisplaySize( displaySize) || (!hasSha256 && !hasSha512) ||
		   (hasSha256 &&
			(!readTextValue( control, html, L"SHA256:", 64U, sha256) || !isUpperSha256( sha256))) ||
		   (hasSha512 &&
			(!readTextValue( control, html, L"SHA512:", 128U, sha512) || !isSha512( sha512)))) {
			return false ;
		}

		// URLとbutton labelが同じでも説明欄が別版ならmetadataを拒否する。
		if( !descriptionMatchesFile( control, html, parsed.fileName)) {
			return false ;
		}

		parsed.displaySize	= std::move( displaySize) ;
		parsed.sha256		= std::move( sha256) ;
		parsed.sha512		= std::move( sha512) ;
		parsed.requiresEula = true ;
		// 許諾欄のない旧表示形式は保持するが、存在する不正欄を本文なしへ戻さない。
		if( collectorParserFind( control, html, L"content-raw") != html.npos &&
		   !(control != nullptr
				 ? parseIntelDownloadLicenseForCollector(
					   html, parsed.downloadUrl, parsed.eulaRevision, parsed.eulaText, *control)
				 : parseIntelDownloadLicense( html, parsed.downloadUrl, parsed.eulaRevision,
											 parsed.eulaText))) {
			return false ;
		}

		metadata = std::move( parsed) ;
		return true ;
	} catch( const std::bad_alloc &) {
		// 新経路ではOOMを配布非採用にしません。
		if( control != nullptr) {
			throw ;
		}

		metadata = {} ;
		return false ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/intel_ethernet_server_page_parser.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
bool parseIntelEthernetServerDownloadPage( const std::wstring_view		   html,
										  IntelEthernetServerPageMetadata &metadata)
{
	return parseIntelEthernetDownloadPage( nullptr, html, SERVER2025_PROFILE, metadata) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/intel_ethernet_server_page_parser.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
bool parseIntelEthernetWindows11DownloadPage( const std::wstring_view			html,
											 IntelEthernetDownloadPageMetadata &metadata)
{
	return parseIntelEthernetDownloadPage( nullptr, html, WINDOWS11_PROFILE, metadata) ;
}

/** @see intel_ethernet_server_page_parser.h */
bool parseIntelEthernetWindows11DownloadPageForCollector(
	std::wstring_view html, IntelEthernetDownloadPageMetadata &metadata,
	CollectorParserContext &context)
{
	return parseIntelEthernetDownloadPage( &context, html, WINDOWS11_PROFILE, metadata) ;
}

} // namespace drivercrate
