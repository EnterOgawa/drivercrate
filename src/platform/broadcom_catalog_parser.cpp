//------------------------------------------------------------------------------
/**
 * @file broadcom_catalog_parser.cpp
 * @brief Broadcom公開製品JSONとEULA metadataの解析。
 * @version 01.00.01
 * @date 2026/09/05
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Broadcomの選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  新規作成。
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
 * @note 固定公式JSONから配布情報と非実行の同意本文を結合し、取得・導入は行いません。
 */
//------------------------------------------------------------------------------

#include "platform/broadcom_catalog_parser.h"
#include "core/official_preparation.h"
#include <cstdint>

// 既存VAIO等と同じWindows SDKのSAL差だけを隔離する。
#pragma warning( push)
#pragma warning( disable : 28252 28253 6101)
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#pragma warning( pop)

#include <algorithm>
#include <cstddef>
#include <exception>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {
//------------------------------------------------------------------------------
// 内部型・定数定義。
//------------------------------------------------------------------------------

/**
 * @brief 所有権付きWinRT JSON object。
 */
using JsonObject									   = winrt::Windows::Data::Json::JsonObject ;
constexpr std::size_t		MAXIMUM_CATALOG_CHARACTERS = 2U * 1024U * 1024U ;	// 製品JSON文字数上限。
constexpr std::size_t		MAXIMUM_DOCUMENT_CHARACTERS = 256U * 1024U ;		// EULA JSON文字数上限。
constexpr std::wstring_view DOCUMENT_API_PREFIX =
	L"https://docs.broadcom.com/api/document/download/Windows_Drivers-" ;	// 固定document起点。
constexpr std::wstring_view DOCUMENT_PAGE_PREFIX =
	L"https://docs.broadcom.com/docs/Windows_Drivers-" ;	// Record URLの正確な許可prefix。
// ZIP形状の確認用prefix。Networkの取得権限は別の公式source policyへ委譲する。
constexpr std::wstring_view PAYLOAD_PREFIX =
	L"https://docs.broadcom.com/docs-and-downloads/ethernet-network-adapters/NXE/BRCM_" ;

//------------------------------------------------------------------------------
/**
 * @brief 配布版の四つの数値要素を検査する。INF版や適用性の判定には使用しない。
 *
 * @param[in] value 検査する有限文字列。
 * @return 定義した検査に適合する場合true。不一致はfalse。
 */
//------------------------------------------------------------------------------
bool numericVersion( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= 35U && value.front() != L'.' && value.back() != L'.' &&
		   value.find( L"..") == value.npos && std::count( value.begin(), value.end(), L'.') == 3 &&
		   std::all_of( value.begin(), value.end(), []( const wchar_t character) {
			   return (character >= L'0' && character <= L'9') || character == L'.' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公開recordの結合に使う64文字以内のASCII識別子を検査する。
 *
 * @param[in] value 検査する有限文字列。
 * @return 定義した検査に適合する場合true。不一致はfalse。
 */
//------------------------------------------------------------------------------
bool recordIdentity( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= 64U &&
		   std::all_of( value.begin(), value.end(), []( const wchar_t character) {
			   return (character >= L'a' && character <= L'z') ||
					  (character >= L'A' && character <= L'Z') ||
					  (character >= L'0' && character <= L'9') || character == L'_' ||
					  character == L'-' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定製品の唯一の現行Windows driver recordを解析する。部分出力は呼出し側が失敗時に破棄する。
 *
 * @param[in] root 同一呼出しで所有する製品JSON object。
 * @param[out] release 製品record。出力時の部分値は呼出し側が失敗時に破棄する。
 * @return 定義した検査に適合する場合true。不一致はfalse。
 */
//------------------------------------------------------------------------------
bool parseCatalogObject( const JsonObject &root, std::optional<BroadcomDriverRelease> &release)
{
	// Page Not Foundや別製品を固定製品の取得成功と扱わない。
	if( root.GetNamedString( L"url") != BROADCOM_PRODUCT_PATH ||
	   root.GetNamedString( L"content_type") != L"emulex" ||
	   root.GetNamedString( L"asset_type") != L"Product" ||
	   root.GetNamedString( L"template") != L"ProductDetail" ||
	   root.GetNamedString( L"locale") != L"en-us") {
		return false ;
	}

	const auto tabs = root.GetNamedArray( L"product_tabs") ;	// 固定製品のtab群。
	// 通常構造を超えるtab数を無制限に走査しない。
	if( tabs.Size() == 0U || tabs.Size() > 16U) {
		return false ;
	}

	bool foundDownloads{} ;	// 二つ目のDownloads tabは曖昧として拒否する。
	// 最大16個のtabから唯一のDownloads sectionを検証する。
	for( const auto &tabValue : tabs) {
		const auto tab	  = tabValue.GetObject() ;				// 現在検査するtab。
		const auto title  = tab.GetNamedString( L"title") ;		// 公開表示名。
		const auto format = tab.GetNamedString( L"template") ;	// Section分類。
		// OverviewやDocumentationからdriverを選ばない。
		if( title != L"Downloads" && format != L"Downloads") {
			continue ;
		}

		// Section名と分類の矛盾や重複を拒否する。
		if( foundDownloads || title != L"Downloads" || format != L"Downloads") {
			return false ;
		}

		foundDownloads		 = true ;
		const auto documents = tab.GetNamedArray( L"documents") ;	// 当該製品の配布record。
		// 総record数は固定上限までとする。
		if( documents.Size() > 512U) {
			return false ;
		}

		// 配布分類を先に確認し、Windows driverの現行recordだけを選ぶ。
		for( const auto &documentValue : documents) {
			const auto document = documentValue.GetObject() ;	// 現在の公開配布record。
			// Niccli、firmware、他OSのtitleは対象外とする。
			if( document.GetNamedString( L"title") != BROADCOM_WINDOWS_DRIVER_TITLE) {
				continue ;
			}

			const auto status  = document.GetNamedString( L"doc_status") ;		// Current／Archive分類。
			const auto archive = document.GetNamedString( L"archive_asset") ;	// Archive補助flag。
			// 旧版は履歴導入の監査がないため今回返さない。
			if( status == L"Archive" && archive == L"Yes") {
				continue ;
			}

			// 不明な公開状態と複数現行recordを拒否する。
			if( release.has_value() || status != L"Current" || archive != L"No") {
				return false ;
			}

			const auto		   os = document.GetNamedArray( L"os") ;	// Catalogに掲載されたOS分類。
			// 配布表示版。Windows driver版ではない。
			const std::wstring version{
				std::wstring_view( document.GetNamedString( L"asset_version"))} ;
			// Document情報との結合専用識別子。
			const std::wstring id{std::wstring_view( document.GetNamedString( L"content_id"))} ;
			// 検証済み数値版から期待する公式document URL。
			const std::wstring page = std::wstring( DOCUMENT_PAGE_PREFIX) + version ;
			// 未許可の分類、認証、期限、URL／版不一致は取得要求に使わない。
			if( !numericVersion( version) || !recordIdentity( id) || os.Size() != 1U ||
			   os.GetStringAt( 0U) != L"Windows" ||
			   document.GetNamedString( L"content_type") != L"document" ||
			   document.GetNamedString( L"doc_type") != L"Drivers" ||
			   document.GetNamedString( L"type") != L"zip" ||
			   document.GetNamedString( L"extension") != L"zip" ||
			   document.GetNamedString( L"secured") != L"no" ||
			   document.GetNamedString( L"entitled") != L"no" ||
			   document.GetNamedString( L"locale") != L"en-us" ||
			   document.GetNamedString( L"data-type") != L"regular" ||
			   document.GetNamedBoolean( L"data-expired") ||
			   document.GetNamedString( L"document_title") != BROADCOM_WINDOWS_DRIVER_TITLE ||
			   document.GetNamedString( L"url") != page ||
			   document.GetNamedString( L"data-url") != page ||
			   document.GetNamedString( L"publication_number") != L"Windows_Drivers-" + version) {
				return false ;
			}

			release = BroadcomDriverRelease{.contentId	  = id,
											.assetVersion = version,
											.documentApiUrl =
												std::wstring( DOCUMENT_API_PREFIX) + version} ;
		}
	}

	return foundDownloads ;
}

//------------------------------------------------------------------------------
/**
 * @brief 有限で空白だけではない本文の存在を検査する。HTML表示や同意処理は行わない。
 *
 * @param[in] value 検査する有限文字列。
 * @return 定義した検査に適合する場合true。不一致はfalse。
 */
//------------------------------------------------------------------------------
bool validLicenseText( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= 128U * 1024U && value.find( L'\0') == value.npos &&
		   value.find_first_not_of( L" \t\r\n") != value.npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示tagだけを改行へ変換する。属性・URL・scriptを実行せず、未知の構造は拒否する。
 *
 * @param[in] html 公開licenseの一本文field。最大65,536 UTF-16単位。
 * @param[out] text 成功時の非実行plain text。失敗時は空。
 * @return 省略せずに表示用本文へ変換できた場合true。
 */
//------------------------------------------------------------------------------
bool broadcomLicensePlainText( const std::wstring_view html, std::wstring &text)
{
	text.clear() ;
	// 欠落や上限外の本文を完全な同意対象としない。
	if( html.size() > MAXIMUM_PREPARATION_EULA_CHARACTERS || !validLicenseText( html)) {
		return false ;
	}

	std::wstring result ;	// 成功するまで出力しない本文。入力上限と同じ上限を守る。
	// 入力を前方へ消費し、tagや文字参照の途中で切詰めない。
	for( std::size_t offset = 0U; offset < html.size();) {
		// tag開始を検出した場合は引用属性を考慮して完全なtagを検証する。
		if( html[offset] == L'<') {
			std::size_t end = offset + 1U ;	// 属性中の引用符を考慮するtag終端探索位置。
			wchar_t		quote{} ;			// 0は属性引用符の外側。HTMLを実行するための状態ではない。
			// Tagは512単位以内で走査し、引用符内の大なり記号を終端と誤認しない。
			for( ; end < html.size() && end - offset <= 512U; ++end) {
				const wchar_t character = html[end] ;	// 走査中のtag文字。
				// 属性引用符の内側では大なり記号をtag終端として扱わない。
				if( quote != 0) {
					// 開始時と同じ引用符でだけ属性の引用状態を終了する。
					if( character == quote) {
						quote = 0 ;
					}
				}
				// 属性の開始引用符を保持し、異なる引用符で誤終了しないようにする。
				else if( character == L'"' || character == L'\'') {
					quote = character ;
				}
				// 引用属性の外にある大なり記号でtag走査を終了する。
				else if( character == L'>') {
					break ;
				}
			}

			// 終端欠落や異常に長いtagを本文として隠さない。
			if( end >= html.size() || end - offset > 512U) {
				return false ;
			}

			std::wstring_view tag = html.substr( offset + 1U, end - offset - 1U) ;	// 非所有tag。
			// 閉じtagの先頭slashを分離し、同じ許可名で種別を検証する。
			if( tag.starts_with( L"/")) {
				tag.remove_prefix( 1U) ;
			}

			const auto nameEnd = tag.find_first_of( L" /\t\r\n") ;		// 属性に入る前のtag名末尾。
			const std::wstring_view name = tag.substr( 0U, nameEnd) ;	// 公式本文の表示tagだけを扱う。
			// Script、埋込み物、未知の表示を省略して同意を得ない。
			if( name != L"div" && name != L"p" && name != L"strong" && name != L"b" &&
			   name != L"em" && name != L"i" && name != L"br") {
				return false ;
			}

			// 段落・区画・改行tagでは本文の境界を改行として残す。
			if( name == L"div" || name == L"p" || name == L"br") {
				// 段落境界を文字の連結で失わない。
				result += L"\r\n" ;
			}

			offset = end + 1U ;
		}
		// アンパサンドに続く有限な文字参照を検証して表示文字へ復号する。
		else if( html[offset] == L'&') {
			const std::size_t end = html.find( L';', offset + 1U) ;	// 文字参照の終端候補。
			// 有限長の文字参照を形成しないアンパサンドは通常文字として保持する。
			if( end == html.npos || end - offset > 12U) {
				// 通常文字としてのampersandはそのまま残す。
				result += html[offset++] ;
				continue ;
			}

			// 表示文字へ復号する非所有の文字参照。本文から削除しない。
			const std::wstring_view entity = html.substr( offset + 1U, end - offset - 1U) ;
			// 一文字参照をUnicode scalar valueへ復号し、NUL・surrogateは受理しない。
			std::uint32_t			code{} ;
			// 既知のamp参照を本文のアンパサンドへ復号する。
			if( entity == L"amp") {
				code = L'&' ;
			}
			// 既知のlt参照はmarkupではなく表示文字へ復号する。
			else if( entity == L"lt") {
				code = L'<' ;
			}
			// 既知のgt参照はmarkupではなく表示文字へ復号する。
			else if( entity == L"gt") {
				code = L'>' ;
			}
			// 既知のquot参照を本文の二重引用符へ復号する。
			else if( entity == L"quot") {
				code = L'"' ;
			}
			// 既知の単一引用符参照を同じ表示文字へ復号する。
			else if( entity == L"apos" || entity == L"#39") {
				code = L'\'' ;
			}
			// 既知のnbsp参照を非改行空白として保持する。
			else if( entity == L"nbsp") {
				code = 0xA0U ;
			}
			// 数値参照の明示記号がある場合にだけ十進・十六進のscalarを読む。
			else if( entity.starts_with( L"#")) {
				// trueは16進文字参照、falseは10進文字参照。
				const bool hex = entity.size() > 1U && (entity[1] == L'x' || entity[1] == L'X') ;
				const std::uint32_t base  = hex ? 16U : 10U ;	// 公開文字参照の基数。
				const std::size_t	first = hex ? 2U : 1U ;		// 数値開始位置。
				// 数値部分が空の文字参照を受理しない。
				if( first == entity.size()) {
					return false ;
				}

				// 文字参照は最大12単位であり、加算前の比較でUnicode上限を守る。
				for( std::size_t index = first; index < entity.size(); ++index) {
					const wchar_t		character = entity[index] ;	// 復号中の数値桁。
					const std::uint32_t digit =
						character >= L'0' && character <= L'9'
							? static_cast<std::uint32_t>( character - L'0')
						: character >= L'a' && character <= L'f'
							? static_cast<std::uint32_t>( character - L'a' + 10)
						: character >= L'A' && character <= L'F'
							? static_cast<std::uint32_t>( character - L'A' + 10)
							: base ;	// 基数と同じ値は不正桁のsentinel。
					// 基数外の桁とUnicode上限を超える演算を復号前に拒否する。
					if( digit >= base || code > (0x10FFFFU - digit) / base) {
						return false ;
					}

					code = code * base + digit ;
				}
			} else {
				return false ;
			} // 不明な文字参照を捨てたり推測したりしない。

			// NULと単独surrogateを表示本文へ取り込まない。
			if( code == 0U || (code >= 0xD800U && code <= 0xDFFFU)) {
				return false ;
			}

			// BMP外の有効scalarだけをUTF-16 surrogate pairへ変換する。
			if( code > 0xFFFFU) {
				code -= 0x10000U ;
				result += static_cast<wchar_t>( 0xD800U + (code >> 10U)) ;
				result += static_cast<wchar_t>( 0xDC00U + (code & 0x3FFU)) ;
			} else {
				result += static_cast<wchar_t>( code) ;
			}

			offset = end + 1U ;
		} else {
			result += html[offset++] ;
		}

		// 復号後のEULA文字数が上限を超えた場合は切り詰めず拒否する。
		if( result.size() > MAXIMUM_PREPARATION_EULA_CHARACTERS) {
			return false ;
		}
	}

	// 最終本文が同意表示の共通要件を満たさなければ返さない。
	if( !validPreparationEulaText( result)) {
		return false ;
	}

	text = std::move( result) ;
	return true ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseBroadcomCatalog( const std::wstring_view				json,
						  std::optional<BroadcomDriverRelease> &release)
{
	release.reset() ;
	// 応答上限とNULを構文解析前に確認する。
	if( json.empty() || json.size() > MAXIMUM_CATALOG_CHARACTERS || json.find( L'\0') != json.npos) {
		return false ;
	}

	try {
		JsonObject							 root ;		// この呼出しで所有するJSON root。
		std::optional<BroadcomDriverRelease> parsed ;	// 全体検証後にだけ公開する一時結果。
		// JSONの構文と固定catalog schemaのどちらかが不正なら結果を返さない。
		if( !JsonObject::TryParse( winrt::hstring( json), root) || !parseCatalogObject( root, parsed)) {
			return false ;
		}

		release = std::move( parsed) ;
		return true ;
	} catch( const winrt::hresult_error &) {
		// 欠落や型不正をmetadata拒否として呼出し側へ伝える。
		return false ;
	} catch( const std::exception &) {
		// 文字列等の例外から不完全なrecordを公開しない。
		return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool validateBroadcomDocument( const std::wstring_view json, const BroadcomDriverRelease &release)
{
	// 未検証の入力recordや応答上限を越える本文を拒否する。
	if( json.empty() || json.size() > MAXIMUM_DOCUMENT_CHARACTERS || json.find( L'\0') != json.npos ||
	   !numericVersion( release.assetVersion) || !recordIdentity( release.contentId) ||
	   release.documentApiUrl != std::wstring( DOCUMENT_API_PREFIX) + release.assetVersion) {
		return false ;
	}

	try {
		JsonObject root ;	// この呼出しの範囲だけで所有するdocument情報。
		// HTTP成功でも別documentや未知同意方式を採用しない。
		if( !JsonObject::TryParse( winrt::hstring( json), root) ||
		   root.GetNamedString( L"status_code") != L"200" ||
		   root.GetNamedString( L"content_type") != L"document" ||
		   root.GetNamedString( L"content_id") != release.contentId ||
		   root.GetNamedString( L"doc_type") != L"Downloads" ||
		   root.GetNamedString( L"contenttype") != L"Downloads" ||
		   root.GetNamedString( L"document_type") != L"eula" ||
		   root.GetNamedString( L"document_title") != BROADCOM_WINDOWS_DRIVER_TITLE ||
		   root.GetNamedString( L"locale") != L"en-us" ||
		   root.GetNamedString( L"publication_number") !=
			   L"Windows_Drivers-" + release.assetVersion ||
		   root.GetNamedString( L"eula_type") != L"Shareable License") {
			return false ;
		}

		const auto license = root.GetNamedObject( L"shareable_license") ;	// 公開用license情報。
		// EULA本文が欠けた情報から取得可能とは判断しない。
		if( license.GetNamedString( L"content_type") != L"general_page" ||
		   license.GetNamedString( L"locale") != L"en-us" ||
		   !validLicenseText( license.GetNamedString( L"body_text")) ||
		   !validLicenseText( license.GetNamedString( L"body_bottom_text"))) {
			return false ;
		}

		// NULを含む値も長さを保持し、C文字列への短縮で末尾検証を通過させない。
		const std::wstring payload{std::wstring_view( root.GetNamedString( L"url"))} ;
		// Product recordと同じ版のarchive名。
		const std::wstring suffix = L"/Windows_Drivers-" + release.assetVersion + L".zip" ;
		// 別origin、directory、拡張子、query、fragmentは許可しない。
		if( !payload.starts_with( PAYLOAD_PREFIX) || !payload.ends_with( suffix) ||
		   payload.size() <= PAYLOAD_PREFIX.size() + suffix.size()) {
			return false ;
		}

		// Directory部分も4個の数値要素に限定し、任意pathを受け入れない。
		const std::wstring_view bundleVersion = std::wstring_view( payload).substr(
			PAYLOAD_PREFIX.size(), payload.size() - PAYLOAD_PREFIX.size() - suffix.size()) ;
		return numericVersion( bundleVersion) ;
	} catch( const winrt::hresult_error &) {
		// 型変更と欠落をmetadata拒否として返す。
		return false ;
	} catch( const std::exception &) {
		// 部分的に検証した文書を成功にしない。
		return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseBroadcomPreparedRelease( const std::wstring_view	   json,
								  const BroadcomDriverRelease &release,
								  OfficialReleaseRecord		  &record)
{
	record = {} ;
	// 製品recordとdocumentの結合を検証できなければ準備対象を構築しない。
	if( !validateBroadcomDocument( json, release)) {
		return false ;
	}

	try {
		const JsonObject root = JsonObject::Parse( winrt::hstring( json)) ;	// 検証済みdocument。
		const JsonObject license =
			// 同一documentの本文。
			root.GetNamedObject( L"shareable_license") ;
		// 同意本文の照合に用いる公開license record識別子。
		const std::wstring licenseId{std::wstring_view( license.GetNamedString( L"content_id"))} ;
		// 公開license識別子をopaque表示へ使用する。公表改訂番号だとは推測しない。
		if( !recordIdentity( licenseId)) {
			return false ;
		}

		std::wstring notice ;		// 配布元が提示する冒頭本文。
		std::wstring conditions ;	// 配布元が提示する後半本文。
		// 一方を省略して全文確認済みにしない。
		if( !broadcomLicensePlainText( license.GetNamedString( L"body_text"), notice) ||
		   !broadcomLicensePlainText( license.GetNamedString( L"body_bottom_text"), conditions) ||
		   notice.size() + 2U + conditions.size() > MAXIMUM_PREPARATION_EULA_CHARACTERS) {
			return false ;
		}

		OfficialReleaseRecord parsed ;	// 全fieldを結合してから公開する配布情報。
		parsed.family		  = OfficialReleaseFamily::BROADCOM_NET_XTREME_E ;
		parsed.fileName		  = L"Windows_Drivers-" + release.assetVersion + L".zip" ;
		parsed.packageVersion = release.assetVersion ;
		parsed.downloadUrl	  = std::wstring_view( root.GetNamedString( L"url")) ;
		parsed.license		  = OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD ;
		parsed.eulaRevision	  = L"broadcom-license:" + licenseId ;
		parsed.parserRevision = 1U ;
		parsed.eulaText		  = notice + L"\r\n" + conditions ;
		record				  = std::move( parsed) ;
		return true ;
	} catch( const std::exception &) {
		// JSON型変更・割当て失敗で部分recordを公開しない。
		return false ;
	} catch( const winrt::hresult_error &) {
		// WinRTの型・field欠落を本文なしの成功へ変換しない。
		return false ;
	}
}

} // namespace drivercrate
