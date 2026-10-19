//------------------------------------------------------------------------------
/**
 * @file silicon_labs_catalog_parser.cpp
 * @brief CP210x公式配布metadataの検証実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  公式JSONからCP210x配布を限定。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * </pre>
 *
 * @note 公式pathを完全一致で拘束し、未知schemaと曖昧な配布行を拒否する。JSON表示版やmetadata更新時刻をdriverの版／日付へ転用しない。
 */
//------------------------------------------------------------------------------

#include "platform/silicon_labs_catalog_parser.h"
#include "platform/official_release_metadata.h"

// 既存VAIO parserと同じSDK内のSAL差だけを隔離し、applicationの警告は維持する。
#pragma warning( push)
#pragma warning( disable : 28252 28253 6101)
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#pragma warning( pop)

#include <cstddef>
#include <exception>
#include <string>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {
constexpr std::size_t		MAXIMUM_TEXT = 2U * 1024U * 1024U ;	// 各metadata本文のUTF-16上限。
constexpr std::wstring_view ARCHIVE_PATH =
	L"/documents/public/software/CP210x_Universal_Windows_Driver.zip" ;	// 公開ZIP限定path。

//------------------------------------------------------------------------------
/**
 * @brief 表示metadataの型崩れだけを拒否し、適用性や新旧を判定しない。
 *
 * @param[in] value 公式JSONの表示版。
 * @return 2～4個の16bit数値要素ならtrue。
 */
//------------------------------------------------------------------------------
bool validDisplayVersion( const std::wstring_view value) noexcept
{
	// 無版や過大な文字列を配布metadataと扱わない。
	if( value.empty() || value.size() > 23U) {
		return false ;
	}

	unsigned parts{} ;	// 完了した数値要素数。
	unsigned digits{} ;	// 現在要素の桁数。
	unsigned number{} ;	// 現在要素の16bit数値。
	// 終端もseparatorとして処理し、空要素と数値overflowを拒否する。
	for( std::size_t index = 0; index <= value.size(); ++index) {
		const wchar_t character = index == value.size() ? L'.' : value[index] ;	// 検査文字。
		// Dot で version 成分を区切り、次成分の桁数と数値を初期化する。
		if( character == L'.') {
			// 空成分と四成分を超える version 表記を拒否する。
			if( digits == 0U || ++parts > 4U) {
				return false ;
			}

			digits = 0U ;
			number = 0U ;
		} else {
			// Version 成分の非数字と五桁超過を拒否する。
			if( character < L'0' || character > L'9' || ++digits > 5U) {
				return false ;
			}

			number = number * 10U + static_cast<unsigned>( character - L'0') ;
			// Version 成分が 16-bit の範囲を超える場合は拒否する。
			if( number > 65535U) {
				return false ;
			}
		}
	}

	return parts >= 2U ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/silicon_labs_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseSiliconLabsOfficialZipUrl( const std::wstring_view html, const std::wstring_view json,
									std::wstring &url)
{
	url.clear() ;
	OfficialReleaseRecord record ;	// 詳細parserと旧URL契約で検証を共用する一時結果。
	// 旧呼出し側にも全く同じ拒否条件を適用する。
	if( !parseSiliconLabsOfficialRelease( html, json, record)) {
		return false ;
	}

	url = std::move( record.downloadUrl) ;
	return true ;
}

/** @see src/platform/silicon_labs_catalog_parser.h 宣言側の契約を正本とする。 */
bool parseSiliconLabsOfficialRelease( const std::wstring_view html, const std::wstring_view json,
									 OfficialReleaseRecord &record)
{
	record = {} ;
	// 上限外本文と中途終端をJSON parserへ渡さない。
	if( html.empty() || json.empty() || html.size() > MAXIMUM_TEXT || json.size() > MAXIMUM_TEXT ||
	   html.find( L'\0') != html.npos || json.find( L'\0') != json.npos) {
		return false ;
	}

	constexpr std::wstring_view MARKER =
		L"data-resource=\"softwaredocumentlist\"" ;	// 公式download一覧の区画識別子。
	const std::size_t marker = html.find( MARKER) ;	// 対象区画の属性位置。
	// 欠落と複数区画を任意選択しない。
	if( marker == html.npos || html.find( MARKER, marker + MARKER.size()) != html.npos) {
		return false ;
	}

	const std::size_t start = html.rfind( L"<div ", marker) ;	// 属性が所属する開始tag。
	const std::size_t end	= html.find( L'>', marker) ;		// 同じ開始tagの終端。
	// 対象 HTML 属性の境界欠落、長さ超過、別 tag への跨りを拒否する。
	if( start == html.npos || end == html.npos || end - start > 4096U ||
	   html.find( L'>', start) != end) {
		return false ;
	}

	const std::wstring_view tag = html.substr( start, end - start) ;	// 別区画を含まない属性列。
	// 別製品のdownload一覧をCP210x検索の根拠にしない。
	if( tag.find( L"data-contenttypes=\"content-type:software\"") == tag.npos ||
	   tag.find( L"data-softwaretag=\"silicon-labs-software:drivers/vcp-drivers\"") == tag.npos) {
		return false ;
	}

	try {
		const auto root = winrt::Windows::Data::Json::JsonObject::Parse(
			// 長さ検査済みの公式一覧root。
			winrt::hstring( json)) ;
		const auto items = root.GetNamedArray( L"content-type:software") ;	// 型検証済み配布行群。
		// 過大な配布集合を走査しない。
		if( items.Size() == 0U || items.Size() > 128U) {
			return false ;
		}

		unsigned			  matches{} ;	// 対象名に完全一致した行数。複数は全体拒否。
		OfficialReleaseRecord parsed ;		// 検証完了まで外部へ公開しない配布情報。
		// 有限な配布一覧からUniversal Windows版だけを一意に選ぶ。
		for( const auto &value : items) {
			const auto item = value.GetObject() ;	// 一つの型検証済み配布record。
			// macOS、legacy Windows、Linux等は取得しない。
			if( item.GetNamedString( L"name") != L"CP210x Universal Windows Driver") {
				continue ;
			}

			// 配布項目の一意性と固定 archive・形式・言語・version の条件を確認する。
			if( ++matches != 1U ||
			   std::wstring_view( item.GetNamedString( L"externalPath")) != ARCHIVE_PATH ||
			   item.GetNamedString( L"contentTypeTagId") != L"content-type:software" ||
			   item.GetNamedString( L"format") != L"application/zip" ||
			   item.GetNamedString( L"sourceType") != L"DAM" ||
			   item.GetNamedString( L"language") != L"en" ||
			   !validDisplayVersion( item.GetNamedString( L"version"))) {
				return false ;
			}

			const auto software = item.GetNamedArray( L"softwareTypeTagId") ;	// 配布種別tag集合。
			// Software 分類が単一の VCP driver でない配布を拒否する。
			if( software.Size() != 1U ||
			   software.GetAt( 0U).GetString() != L"silicon-labs-software:drivers/vcp-drivers") {
				return false ;
			}

			parsed.packageVersion = item.GetNamedString( L"version") ;
		}

		// 対象配布項目がちょうど一件でなければ URL を確定しない。
		if( matches != 1U) {
			return false ;
		}

		parsed.family		  = OfficialReleaseFamily::SILICON_LABS_CP210X ;
		parsed.fileName		  = L"CP210x_Universal_Windows_Driver.zip" ;
		parsed.downloadUrl	  = L"https://www.silabs.com" + std::wstring( ARCHIVE_PATH) ;
		parsed.parserRevision = 1U ;
		record				  = std::move( parsed) ;
		return true ;
	} catch( const winrt::hresult_error &) {
		// 型違い、欠損、JSON構文不正をmetadata拒否として呼出し側へ返す。
		return false ;
	} catch( const std::exception &) {
		// Allocation失敗でも不完全なURLを公開しない。
		return false ;
	}
}
} // namespace drivercrate
