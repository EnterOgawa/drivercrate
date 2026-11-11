//------------------------------------------------------------------------------
/**
 * @file wch_catalog_parser.cpp
 * @brief WCH公式serial配布metadata検証実装。
 * @version 01.00.02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公開JSONの限定解析を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * Ver.01.00.02 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 *
 * @note ADR 0094の取得先だけを許可し、関連fileや外部共有URLを採用しない。
 */
//------------------------------------------------------------------------------

#include "platform/wch_catalog_parser.h"
#include "platform/official_release_metadata.h"

// 既存VAIO／CP210xと同じSDK内のSAL差だけを隔離し、applicationの警告は維持する。
#pragma warning( push)
#pragma warning( disable : 28252 28253 6101)
#include <winrt/Windows.Data.Json.h>
#include <winrt/base.h>
#pragma warning( pop)

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {
constexpr std::size_t MAXIMUM_TEXT = 2U * 1024U * 1024U ;	// 各metadataのUTF-16文字数上限。

//------------------------------------------------------------------------------
/**
 * @brief Scriptを実行せず、行頭の審査済み設定形式だけを読む。コメント行を設定と見なさず、未知形式は再審査を要求する。
 *
 * @param[in] html 長さ検証済みの固定公式landing本文。
 * @return 許可API設定が一つでapp scriptが参照される場合true。
 */
//------------------------------------------------------------------------------
bool				  validLanding( const std::wstring_view html) noexcept
{
	constexpr std::wstring_view KEY =
		L"window._CONFIG['domianURL']" ;	// 公式pageにある綴りを変更せず照合する。
	constexpr std::wstring_view ASSIGNMENT =
		L"window._CONFIG['domianURL'] = 'https://api1.wch.cn'" ;	// 許可した公開APIの設定。
	// Challengeや別siteのHTMLを公式SPAの起点にしない。
	if( html.find( L"src=\"/js/app.js\"") == html.npos ||
	   html.find( L"<div id=\"app\"") == html.npos) {
		return false ;
	}

	unsigned	matches{} ;	// 有効な設定行数。複数は曖昧として拒否する。
	std::size_t offset{} ;	// 次の行の先頭。必ず一行分以上進める。
	// 有限な本文を行単位で調べ、コメント内の代替API設定を採用しない。
	while( offset < html.size()) {
		const std::size_t		end	 = html.find( L'\n', offset) ;	// 現在行の終端。
		const std::wstring_view line = html.substr(
			offset, end == html.npos ? html.size() - offset : end - offset) ;	// 非所有の一行。
		const std::size_t		first = line.find_first_not_of( L" \t\r") ;		// Indentを除く位置。
		const std::wstring_view trimmed =
			// 行頭設定。
			first == line.npos ? std::wstring_view{} : line.substr( first) ;
		// 行頭が対象設定 key の場合だけ審査済み assignment 形式を検証する。
		if( trimmed.starts_with( KEY)) {
			// 別origin、曖昧な再代入、未審査形式を拒否する。
			if( ++matches != 1U || !trimmed.starts_with( ASSIGNMENT)) {
				return false ;
			}

			std::wstring_view suffix	= trimmed.substr( ASSIGNMENT.size()) ;		// 設定後の文字列。
			const std::size_t remaining = suffix.find_first_not_of( L" \t\r;") ;	// 終端除外位置。
			suffix = remaining == suffix.npos ? std::wstring_view{} : suffix.substr( remaining) ;
			// 連結や次の式を設定値へ解釈しない。
			if( !suffix.empty() && !suffix.starts_with( L"//")) {
				return false ;
			}
		}

		// 最終行の検証を終えたら改行探索を終了する。
		if( end == html.npos) {
			break ;
		}

		offset = end + 1U ;
	}

	return matches == 1U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 型崩れだけを拒否し、現在driverとの比較には使用しない。
 *
 * @param[in] version JSON上の配布表示版。
 * @return 23文字以内の2～4個の数値要素ならtrue。
 */
//------------------------------------------------------------------------------
bool validDisplayVersion( const std::wstring_view version) noexcept
{
	return !version.empty() && version.size() <= 23U && version.front() != L'.' &&
		   version.back() != L'.' && version.find( L"..") == version.npos &&
		   std::count( version.begin(), version.end(), L'.') >= 1 &&
		   std::count( version.begin(), version.end(), L'.') <= 3 &&
		   std::all_of( version.begin(), version.end(), []( const wchar_t character) {
			   return (character >= L'0' && character <= L'9') || character == L'.' ;
		   }) ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 公式landingとJSONを検証して一つの主recordのZIP URLを得る。任意URLや関連配布物ではなく検証済み整数IDだけを使用する。Windows JSONの型／構文例
 *        外はmetadata拒否に変換する。
 * @param[in] kind 検索対象に固定する配布種別。未知enumは拒否する。 審査済み配布種別。
 * @param[in] html 対応する公式landingのUTF-16本文。2 Mi文字以内。 公式landing本文。
 * @param[in] json 固定lookupで得たUTF-16 JSON。2 Mi文字以内。 公式lookup本文。
 * @param[out] url 成功時のworker内URL。拒否時は空。 成功時だけの取得URL。
 * @return Schema、公開状態、family、ID範囲が有効な場合true。 主recordの全条件が有効な場合true。拒否時は出力を空にする。
 * @note 通信と署名検証は行わない。JSON表示版をINF版や適用性へ流用しない。
 */
//------------------------------------------------------------------------------
bool parseWchOfficialZipUrl( const WchOfficialPackageKind kind, const std::wstring_view html,
							const std::wstring_view json, std::wstring &url)
{
	url.clear() ;
	OfficialReleaseRecord record ;	// 旧URL契約も詳細parserの同じ検証結果を使用する。
	// 部分結果のURLを旧呼出し側へ公開しない。
	if( !parseWchOfficialRelease( kind, html, json, record)) {
		return false ;
	}

	url = std::move( record.downloadUrl) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief WCHの主recordを検証して明示配布版と公開整数IDを保持する。
 * @param[in] kind 固定した審査済み配布系列。
 * @param[in] html 上限付き公式landing本文。
 * @param[in] json 上限付き公式lookup本文。
 * @param[out] record 成功時のworker専用record。拒否時は初期値。
 * @return 既存公開ZIPの全検証条件が成立した場合true。
 * @note 版をINF版として扱わず、未知の日付、容量、hash、許諾を補完しない。
 */
//------------------------------------------------------------------------------
bool parseWchOfficialRelease( const WchOfficialPackageKind kind, const std::wstring_view html,
							 const std::wstring_view json, OfficialReleaseRecord &record)
{
	record = {} ;
	// 未知種別と無制限／曖昧な本文をparserへ渡さない。
	if( (kind != WchOfficialPackageKind::CH341 && kind != WchOfficialPackageKind::CH343) ||
	   html.empty() || json.empty() || html.size() > MAXIMUM_TEXT || json.size() > MAXIMUM_TEXT ||
	   html.find( L'\0') != html.npos || json.find( L'\0') != json.npos || !validLanding( html)) {
		return false ;
	}

	try {
		const auto root = winrt::Windows::Data::Json::JsonObject::Parse(
			// 長さ検証済みのlookup応答。
			winrt::hstring( json)) ;
		// HTTP 200でもAPIが失敗した応答を受理しない。
		if( root.GetNamedNumber( L"code") != 0.0) {
			return false ;
		}

		const auto item = root.GetNamedObject( L"data") ;	// 関連file配列ではなく主record。
		const std::wstring_view name = kind == WchOfficialPackageKind::CH341
										   ? L"CH341SER.ZIP"
										   : L"CH343SER.ZIP" ;	// 対象file名。
		const double id = item.GetNamedNumber( L"id") ;			// 範囲と整数性を検査する公開file ID。
		// 別family、認証、代替URL、不正IDは取得しない。
		if( std::wstring_view( item.GetNamedString( L"name")) != name ||
		   item.GetNamedNumber( L"categoryId") != 67.0 || item.GetNamedString( L"auth") != L"0" ||
		   item.GetNamedValue( L"redirect").ValueType() !=
			   winrt::Windows::Data::Json::JsonValueType::Null ||
		   item.GetNamedValue( L"fullUrl").ValueType() !=
			   winrt::Windows::Data::Json::JsonValueType::Null ||
		   !item.GetNamedString( L"githubDownloadUrl").empty() ||
		   !validDisplayVersion( item.GetNamedString( L"version")) || !std::isfinite( id) ||
		   id < 1.0 || id > 2147483647.0 || std::floor( id) != id) {
			return false ;
		}

		OfficialReleaseRecord parsed ;	// 公開条件を満たした主recordだけを返す。
		parsed.family	  = kind == WchOfficialPackageKind::CH341 ? OfficialReleaseFamily::WCH_CH341
																  : OfficialReleaseFamily::WCH_CH343 ;
		parsed.fileName	  = name ;
		parsed.releaseKey = std::to_wstring( static_cast<std::uint32_t>( id)) ;
		parsed.packageVersion = item.GetNamedString( L"version") ;
		parsed.downloadUrl	  = L"https://file.wch.cn/download/file?id=" + parsed.releaseKey ;
		parsed.parserRevision = 1U ;
		record				  = std::move( parsed) ;
		return true ;
	} catch( const winrt::hresult_error &) {
		// 欠損、型違い、構文不正を呼出し側のMetadataRejectedへ渡す。
		return false ;
	} catch( const std::exception &) {
		// Allocation失敗でも不完全な取得先を公開しない。
		return false ;
	}
}
} // namespace drivercrate
