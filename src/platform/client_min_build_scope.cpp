//------------------------------------------------------------------------------
/**
 * @file client_min_build_scope.cpp
 * @brief client最低buildの原条件と同Catalog owner欄を厳密照合します
 * @version 01.10.01
 * @date 2026/11/18
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/18  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/19  同認証recordとfullhostの非権限照合を端末境界へ接続
 * Ver.01.01.01 Shunji Ogawa  2026/11/19  使用するWinRT Collectionsの直接定義を含める
 * Ver.01.02.00 Shunji Ogawa  2026/11/19  固定baseと条件内GUIDを原詳細URLへ厳密に結合
 * Ver.01.03.00 Shunji Ogawa  2026/11/19  一般Client24H2の26100を期待scope別に結合
 * Ver.01.04.00 Shunji Ogawa  2026/11/20  Catalogの同URL判定と追加欄の最低build条件を接続
 * Ver.01.05.00 Shunji Ogawa  2026/11/20  可視製品欄とArchitectureの全体比較を共有
 * Ver.01.06.00 Shunji Ogawa  2026/11/20  同じリリースのClient S表記の併記に対応
 * Ver.01.07.00 Shunji Ogawa  2026/11/20  検索行の同版順序と明細の製品比較を共通化
 * Ver.01.08.00 Shunji Ogawa  2026/11/22  元証拠に結合した公式Models専用行の最低buildを読取
 * Ver.01.09.00 Shunji Ogawa  2026/11/22  公式Models専用行の取得と検査を同ホストに結合
 * Ver.01.10.00 Shunji Ogawa  2026/11/23  WiX配布のWindowsクライアント条件を同一端末へ照合
 * Ver.01.10.01 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * </pre>
 * @note 同MTAの原JSONは変更せず、比較用の所有textだけを作ります。通信/host APIを呼びません
 * @see docs/adr/0511-client-minimum-build-index-scope.md
 */
//------------------------------------------------------------------------------
#include "platform/client_min_build_scope.h"
#include "platform/server_index_scope.h"
#include "platform/signed_index_acquisition_descriptor_internal.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <optional>
#include <iterator>
#include <utility>
#include "platform/signed_index_json_internal.h"
#include "platform/signed_index_records.h"
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <winrt/Windows.Foundation.Collections.h>

#if defined( GetObject)
#pragma push_macro( "GetObject")
#undef GetObject
#define DRIVERCRATE_CLIENT_MIN_BUILD_RESTORE_GETOBJECT
#endif

namespace drivercrate {
namespace {
using Object					  = winrt::Windows::Data::Json::JsonObject ;	// 同MTAで同期借用します
using Array						  = winrt::Windows::Data::Json::JsonArray ;		// 元順を保持します
using Value						  = winrt::Windows::Data::Json::JsonValue ;		// 独立値の生成だけです
constexpr std::string_view PREFIX = "DriverCrate:client-min-build=" ;			// 新wireの正確な接頭辞です
constexpr std::string_view CATALOG_BASE =
	"https://www.catalog.update.microsoft.com/ScopedViewInline.aspx" ;	// 旧codecでも受理できる固定PAGEです
constexpr std::string_view UPDATE_ID_SUFFIX =
	";catalog-update-id=" ;									// 同LOCAL description内の正確な区切りです
constexpr std::string_view UPDATE_QUERY = "?updateid=" ;	// 実URLだけに復元する固定queryです

//------------------------------------------------------------------------------
/**
 * @brief Catalog update GUIDを正規小文字8-4-4-4-12だけへ限定します
 * @param[in] value 同期借用する元ASCII literalです
 * @return 正確な長さ/区切り/小文字十六進だけtrueです。実在性は原metadata照合へ残します
 * @note 割当て/JSON/WinRTや通信は行いません
 */
//------------------------------------------------------------------------------
bool					   canonicalCatalogUpdateId( const std::string_view value) noexcept
{
	// 不完全/余分なqueryをGUIDへ切り詰めません
	if( value.size() != 36U) {
		return false ;
	}

	// 全36byteの区切り位置と小文字十六進を厳密に確認します
	for( std::size_t index = 0U; index < value.size(); ++index) {
		const auto c = value[index] ;	// 元literalの一byteです
		const bool separator =
			// GUID固定位置です
			index == 8U || index == 13U || index == 18U || index == 23U ;
		// 表記差/別文字を正規化で救済しません
		if( separator ? c != '-' : !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
			return false ;
		}
	}

	return true ;
}
//------------------------------------------------------------------------------
/**
 * @brief reserved記述をcase/外側空白によるlegacy回避から分離します
 * @param[in] text 元条件descriptionの借用です
 * @return 正確又は不正なreserved familyの記述ならtrueです
 * @note ASCII familyだけを比較し、割当て/JSON/WinRTを呼びません
 */
//------------------------------------------------------------------------------
bool reserved( const std::string_view text) noexcept
{
	const auto first = text.find_first_not_of( " \t\r\n") ;				// 不正な外側空白も検出します
	constexpr std::string_view family{"drivercrate:client-min-build"} ;	// reserved family全体です
	// 必要な接頭辞長がないtextは新scopeの記述ではありません
	if( first == text.npos || text.size() - first < family.size()) {
		return false ;
	}

	// 元byteのASCII caseだけを逐次比較し、比較copyの割当てを行いません
	for( std::size_t index = 0U; index < family.size(); ++index) {
		const auto c = text[first + index] ;	// 元descriptionの一byteです
		// 別familyを部分一致でreservedへ変えません
		if( (c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c) != family[index]) {
			return false ;
		}
	}

	return true ;
}
//------------------------------------------------------------------------------
/**
 * @brief 新条件の元根拠を既HTTPS規則と正規SHAへ限定します
 * @param[in] url 原support URLです
 * @param[in] hash 原raw SHA256です
 * @return 両根拠が構造上成立した場合trueです。本文真偽はproducerの別検査です
 * @throws std::bad_alloc URL検査に必要な所有textの割当て失敗です
 */
//------------------------------------------------------------------------------
bool evidence( const std::string &url, const std::string &hash)
{
	try {
		signed_index_acquisition::requireUrl( url, true) ;
		return hash.size() == 64U && std::ranges::all_of( hash, []( char c) {
				   return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ;
			   }) ;
	} catch( const signed_index_json::Failure<IndexRecordsStatus> &) {
		return false ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief protocolの成立条件を失敗closedにします
 * @param[in] valid 必須条件の成立です
 * @throws winrt::hresult_error 不正/未対応又は混在です
 */
//------------------------------------------------------------------------------
void need( bool valid)
{
	// 未確認をdefault scopeへ補完しません
	if( !valid) {
		throw winrt::hresult_error( E_INVALIDARG) ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief owner欄の比較文字列だけでHTML空白参照をbounded復号します
 * @param[in] text 原fieldの所有copyです
 * @return ASCII空白/caseを正規化した比較値。不明entityは残して不一致へ送ります
 * @throws std::bad_alloc 比較値の割当て失敗です
 * @throws std::regex_error 固定比較式の処理失敗です
 */
//------------------------------------------------------------------------------
std::wstring comparison( std::wstring text)
{
	const std::wregex entities{L"&(?:amp|nbsp|#0*(?:9|10|12|13|32|160)|#x0*(?:9|a|c|d|20|a0));",
							   std::regex::icase} ;	// 比較に必要な有限entity集合です
	std::wstring	  decoded ;						// 元文字列の一回走査でだけ復号し、二重encodeを再解釈しません
	std::size_t		  from{} ;						// 原textの未消費位置です
	// 原text上のmatchだけを読み、復号したampから新しい参照を作りません
	for( auto at = std::wsregex_iterator{text.begin(), text.end(), entities};
		at != std::wsregex_iterator{}; ++at) {
		const auto position = static_cast<std::size_t>( at->position()) ;	// 原field内の位置です
		decoded.append( text, from, position - from) ;
		decoded.push_back(
			at->str().size() == 5U && (at->str()[1] == L'a' || at->str()[1] == L'A') ? L'&' : L' ') ;
		from = position + static_cast<std::size_t>( at->length()) ;
	}

	decoded.append( text, from, text.size() - from) ;
	std::wstring out ;			// fieldの比較専用でrawへ戻しません
	bool		 space = true ;	// 先頭/連続空白を一つへまとめます
	// 全fieldを元順に読み、可視文字だけを比較値へ保持します
	for( const auto c : decoded) {
		// ASCII/明示NBSP以外を新scopeの区切りとして推測しません
		if( c == L' ' || c == L'\t' || c == L'\r' || c == L'\n' || c == L'\f' || c == 0xa0) {
			// 連続する表示空白を一つにします
			if( !space) {
				out.push_back( L' ') ;
			}

			space = true ;
		} else {
			out.push_back( static_cast<wchar_t>( c >= L'A' && c <= L'Z' ? c - L'A' + L'a' : c)) ;
			space = false ;
		}
	}

	// 終端空白を製品名の一部へしません
	if( !out.empty() && out.back() == L' ') {
		out.pop_back() ;
	}

	return out ;
}
//------------------------------------------------------------------------------
/**
 * @brief 可視製品欄の表示空白を比較用に揃える
 * @param[in] products 同じ明細にある製品欄の原文
 * @return 製品名と区切りのコンマを保持した比較用文字列
 * @throws std::bad_alloc 比較文字列を確保できない場合
 * @throws std::regex_error 区切りの比較式を処理できない場合
 */
//------------------------------------------------------------------------------
std::wstring catalogProductComparison( std::wstring_view products)
{
	return std::regex_replace( comparison( std::wstring{products}), std::wregex( L" *[,] *"), L", ") ;
}
} // namespace
//------------------------------------------------------------------------------
/**
 * @brief 固定詳細baseとqueryだけから正規GUIDを借用します
 * @param[in] url 呼出し中だけ有効な原実URLです
 * @return 正規GUIDの借用又は空です。host・path・queryの代替表記を拒否します
 * @note 割当てと通信を行いません。返却viewは元URLと同じ寿命です
 */
//------------------------------------------------------------------------------
std::optional<std::string_view> catalogUpdateIdFromDetailsUrl( const std::string_view url) noexcept
{
	// 他の公式endpointや余分なqueryを同詳細へ扱いません
	if( !url.starts_with( CATALOG_BASE) ||
	   !url.substr( CATALOG_BASE.size()).starts_with( UPDATE_QUERY)) {
		return std::nullopt ;
	}

	const auto id = url.substr( CATALOG_BASE.size() + UPDATE_QUERY.size()) ;	// 固定prefix以降全体です
	return canonicalCatalogUpdateId( id) ? std::optional<std::string_view>{id} : std::nullopt ;
}

//------------------------------------------------------------------------------
/**
 * @brief 採用された一般Clientの最低base buildを閉集合で判定します
 * @param[in] minimumBuild 正規数値として読んだ元floorです
 * @return 24H2の26100又は既25H2の26200だけtrueです
 * @note 割当て/JSON/WinRT/host APIを呼ばず、適用性や権限を発行しません
 */
//------------------------------------------------------------------------------
bool isSupportedClientMinimumBuild( const std::uint32_t minimumBuild) noexcept
{
	return minimumBuild == 26100U || minimumBuild == 26200U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原recordの最低build条件を非実行で分類します
 * @param[in] record 借用する同MTAの原JSONです。変更しません
 * @return markerなしNONE、正規単一条件VALID、不正INVALID、別canonical floorはUNSUPPORTEDです
 * @throws std::bad_alloc 有限textの割当て失敗です
 * @note 完全codec/host検査を代替せず、reserved不正をNONEへ戻しません
 */
//------------------------------------------------------------------------------
ClientMinBuildScope readClientMinimumBuildScope( const Object &record)
{
	ClientMinBuildScope result ;	// 不在と成功を区別します
	try {
		// 旧v1等のdescriptor不在を新scopeへ推測しません
		if( !record.HasKey( L"acquisitionDescriptor") ||
		   record.GetNamedValue( L"acquisitionDescriptor").ValueType() !=
			   winrt::Windows::Data::Json::JsonValueType::Object) {
			return result ;
		}

		const auto descriptor = record.GetNamedObject( L"acquisitionDescriptor") ;	// 同原recordです
		// 条件のない旧descriptorは新scopeへ推測しません
		if( !descriptor.HasKey( L"prerequisites")) {
			return result ;
		}

		const auto prerequisites = descriptor.GetNamedObject( L"prerequisites") ;	// 元順の条件です
		const auto items		 = prerequisites.GetNamedArray( L"items") ;			// 上限を先に照合します
		unsigned   found{} ;														// 二個以上を一つへ丸めません
		bool	   otherLocal{} ;													// 新scopeに未知LOCALを混ぜません
		bool	   invalidCondition{} ;												// reserved以外の元条件も同codecの型/根拠を維持します
		// 最大16の元条件を全件読み、kind変更による回避も検出します
		for( const auto &raw : items) {
			const auto item = raw.GetObject() ;	// この一条件だけです
			const auto description =
				// raw textです
				winrt::to_string( item.GetNamedString( L"description")) ;
			const auto kind = item.GetNamedString( L"kind") ;	// defaultへ補完しません
			const auto url =
				// 条件ごとの原URLです
				winrt::to_string( item.GetNamedString( L"evidenceUrl")) ;
			const auto hash =
				// 条件ごとの原SHAです
				winrt::to_string( item.GetNamedString( L"evidenceSha256")) ;
			invalidCondition =
				invalidCondition || item.Size() != 4U ||
				(kind != L"LOCAL_CHECK" && kind != L"USER_CONFIRMATION" &&
				 kind != L"INSEPARABLE_FIRMWARE") ||
				description.empty() || description.size() > 512U ||
				!std::ranges::all_of( description,
									 []( unsigned char c) { return c >= 32U && c != 127U ; }) ||
				!evidence( url, hash) ;
			// reserved以外のLOCALは新scope成立後に拒否します
			if( !reserved( description)) {
				otherLocal = otherLocal || kind == L"LOCAL_CHECK" ;
				continue ;
			}

			result.state = ClientMinBuildState::INVALID ;
			// 型/重複/外側表記の不正をlegacyへ戻しません
			if( ++found != 1U || kind != L"LOCAL_CHECK" || !description.starts_with( PREFIX)) {
				return result ;
			}

			const auto declaration = std::string_view{description}.substr(
				// floorと同update GUIDの全体です
				PREFIX.size()) ;
			const auto separator = declaration.find( UPDATE_ID_SUFFIX) ;	// 採用した唯一の区切りです
			// 未公開の数値単独形やGUID欠落を正規scopeへ戻しません
			if( separator == declaration.npos ||
			   !canonicalCatalogUpdateId( declaration.substr( separator + UPDATE_ID_SUFFIX.size())) ||
			   url != CATALOG_BASE) {
				return result ;
			}

			const auto value = declaration.substr( 0U, separator) ;	// 数値字句だけです
			// 符号/先頭0/非数値/overflowを未採用の正常値へ分類しません
			if( value.empty() || value.front() == '0' || value.size() > 10U ||
			   !std::ranges::all_of( value, []( char c) { return c >= '0' && c <= '9' ; })) {
				return result ;
			}

			std::uint64_t number{} ;	// uint32境界までを正確に保持します
			// 完全数値を一回だけ解析します
			for( const auto c : value) {
				number = number * 10U + static_cast<unsigned>( c - '0') ;
			}

			// 過大な数値を切り詰めません
			if( number > std::numeric_limits<std::uint32_t>::max()) {
				return result ;
			}

			result.minimumBuild	   = static_cast<std::uint32_t>( number) ;
			result.catalogUpdateId = declaration.substr( separator + UPDATE_ID_SUFFIX.size()) ;
			result.evidenceUrl	   = url ;
			result.evidenceSha256  = hash ;
		}

		// 真の旧recordのkey/byteには新fieldを加えません
		if( found == 0U) {
			return result ;
		}

		// 既codecと同じKNOWN/上限、同client用途と同INF根拠を要求します
		if( items.Size() > 16U || invalidCondition || otherLocal || prerequisites.Size() != 3U ||
		   prerequisites.GetNamedString( L"state") != L"KNOWN" ||
		   !prerequisites.GetNamedString( L"reason").empty() ||
		   descriptor.GetNamedString( L"state") != L"KNOWN" ||
		   !descriptor.GetNamedString( L"reason").empty() ||
		   !evidence( result.evidenceUrl, result.evidenceSha256)) {
			return result ;
		}

		// 正規client/X64/標準INFだけで、Serverやinstallerへ条件を貸しません
		for( const auto &[name, expected] :
			std::array<std::pair<std::wstring_view, std::wstring_view>, 4>{
				{{L"targetOs", L"WINDOWS_11"},
				 {L"architecture", L"X64"},
				 {L"acquisition", L"STANDARD_INF_ARCHIVE"},
				 {L"driverKind", L"NORMAL_DRIVER"}}}) {
			const auto value = record.GetNamedObject( name) ;	// 同原fieldだけです
			// 同一client用途の明示成立がないfieldをscopeの成功へ補完しません
			if( value.GetNamedString( L"state") != L"KNOWN" ||
			   !value.GetNamedString( L"reason").empty() ||
			   value.GetNamedString( L"value") != expected) {
				return result ;
			}
		}

		const auto identity =
			// supportとは別の原INF根拠です
			record.GetNamedObject( L"publishedIdentityEvidence") ;
		// supportの根拠を元INFの欠落や不正の救済へ使いません
		if( identity.GetNamedString( L"state") != L"PUBLISHED" ||
		   identity.GetNamedString( L"kind") != L"INF" ||
		   !identity.GetNamedString( L"reason").empty() ||
		   !evidence( winrt::to_string( identity.GetNamedString( L"evidenceUrl")),
					 winrt::to_string( identity.GetNamedString( L"evidenceSha256")))) {
			return result ;
		}

		result.state = isSupportedClientMinimumBuild( result.minimumBuild)
						   ? ClientMinBuildState::VALID
						   : ClientMinBuildState::UNSUPPORTED ;
		return result ;
	} catch( const winrt::hresult_error &) {
		result.state = ClientMinBuildState::INVALID ;
		return result ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 同認証recordの原byteで既共通条件parserを再利用します
 * @param[in] record 同receiptのcodecが原byte/typed値を結合した不変recordです
 * @return markerなしNONE、正規VALID、不正/未対応は別stateです。原byte不足はINVALIDです
 * @pre 同所有/原hash/期限は呼出側が先に確認します。reserved recordは同workerのMTAで読みます
 * @note 例外/割当て失敗はINVALIDへ閉じ、元rawもtyped値も変更しません
 */
//------------------------------------------------------------------------------
ClientMinBuildScope readClientMinimumBuildScope( const IndexDistributionRecord &record) noexcept
{
	ClientMinBuildScope result ;	// 原marker不在だけがNONEです
	try {
		// 旧v1等を新scopeへ補完せず、原条件のない記録をそのまま区別します
		if( !record.acquisitionDescriptor) {
			return result ;
		}

		// 旧NONE/ServerはJSON再解析や新host条件を追加しません
		if( !hasClientMinimumBuildMarker( record)) {
			return result ;
		}

		result.state = ClientMinBuildState::INVALID ;
		// 同codec原byteを欠落/別版から作らず、全申告値も同client用途へ限定します
		if( (record.recordSchemaVersion != 2U &&
			(record.recordSchemaVersion != 3U || !record.catalogHardwareScope) &&
			(record.recordSchemaVersion != 6U || !record.scopedModelsEvidence)) ||
		   record.originalBytes.empty() || record.originalBytes.size() > INDEX_RECORD_MAX_BYTES ||
		   record.targetOs.value != IndexTargetOs::WINDOWS_11 ||
		   record.architecture.value != IndexArchitecture::X64 ||
		   record.driverKind.value != IndexDriverKind::NORMAL_DRIVER ||
		   record.acquisition.value != IndexAcquisitionKind::STANDARD_INF_ARCHIVE) {
			return result ;
		}

		result =
			readClientMinimumBuildScope( Object::Parse( winrt::to_hstring( record.originalBytes))) ;
		// typed側にあったreserved条件が原byteにない矛盾をlegacyへ戻しません
		if( result.state == ClientMinBuildState::NONE) {
			result.state = ClientMinBuildState::INVALID ;
		}

		return result ;
	} catch( const winrt::hresult_error &) {
		result.state = ClientMinBuildState::INVALID ;
		return result ;
	} catch( const std::bad_alloc &) {
		result.state = ClientMinBuildState::INVALID ;
		return result ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief typed条件のreserved family存在を非割当てで確認します
 * @param[in] record 同所有認証receiptの不変recordです。同期借用だけです
 * @return 正規又は不正なreserved記述があればtrueです。成立判定ではありません
 * @note JSON/WinRT/割当てを行わず、後続解析失敗でも元条件の存在を保持します
 */
//------------------------------------------------------------------------------
bool hasClientMinimumBuildMarker( const IndexDistributionRecord &record) noexcept
{
	return record.acquisitionDescriptor &&
		   std::ranges::any_of( record.acquisitionDescriptor->prerequisites.items,
							   []( const auto &condition) {
								   return reserved( condition.description) ;
							   }) ; // 同原typed条件の同期借用だけです
}
//------------------------------------------------------------------------------
/**
 * @brief 元OS条件付きの標準INFで同host再観測を必須にします
 * @param[in] record 同所有認証receiptの不変recordです。同期借用だけです
 * @return Server、reserved client条件、公式Models専用行又はWiX配布行の標準INFならtrueです
 * @pre 元所有/原byte/期限/取得可否の純粋検証を呼出側で先に行います
 * @note 不正clientは先行検証で拒否し、後続解析失敗でも旧NONEへfallbackしません
 */
//------------------------------------------------------------------------------
bool requiresBoundIndexHost( const IndexDistributionRecord &record) noexcept
{
	return record.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE &&
		   (record.recordSchemaVersion == 6U || record.wixContentEvidence ||
			record.targetOs.value == IndexTargetOs::WINDOWS_SERVER ||
			hasClientMinimumBuildMarker( record)) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 正規client最低buildを同scanの原fullhostへ照合します
 * @param[in] scope 元recordのVALID scopeです。不正値を成功へ補完しません
 * @param[in] observed 同scan所有の原観測です。APIを呼びません
 * @return 元API不明UNKNOWN、既知未対応UNSUPPORTED、別product/低build INCOMPATIBLE又は未検査取得ALLOWです
 * @note 原domain/bitsを保持し、実suite非0を等値拒否せず導入適用性へも変換しません
 */
//------------------------------------------------------------------------------
IndexHostGateResult matchClientMinimumBuildHost(
	const ClientMinBuildScope &scope, const WindowsHostPlatformObservation &observed) noexcept
{
	auto result = classifyIndexHost( observed) ;	// 既fullhostの成功/失敗と原codeを保持します
	// 未観測や既知未対応のhostをrecordで成功へ補完しません
	if( result.state != IndexHostGateState::ALLOW_UNVERIFIED) {
		return result ;
	}

	// 未採用floorや不正scopeを他recordから救済しません
	if( scope.state != ClientMinBuildState::VALID ||
	   !isSupportedClientMinimumBuild( scope.minimumBuild) ||
	   !canonicalCatalogUpdateId( scope.catalogUpdateId) || scope.evidenceUrl != CATALOG_BASE) {
		result.state = IndexHostGateState::UNKNOWN ;
		result.error = E_NOTIMPL ;
		return result ;
	}

	// Win11 clientの下限だけを照合し、producer suite0を実host条件へ加えません
	if( observed.value->productType != 1U || observed.value->buildNumber < scope.minimumBuild) {
		result.state = IndexHostGateState::INCOMPATIBLE ;
		result.error = E_ACCESSDENIED ;
	}

	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief 署名索引のWiX配布条件を同じ端末で観測したWindowsの種類とアーキテクチャへ照合します
 * @param[in] record 元OSとアーキテクチャを保持する認証済みレコードです
 * @param[in] observed 同スキャンで取得した端末の観測です
 * @return 未観測、未対応、不一致又は対象条件の一致を表す判定です
 * @note 対象条件の一致だけを返します。追加のシステムAPIを呼ばず、端末の観測と原エラーを保持します
 */
//------------------------------------------------------------------------------
IndexHostGateResult matchWixIndexHost( const IndexDistributionRecord		   &record,
									  const WindowsHostPlatformObservation &observed) noexcept
{
	auto result = classifyIndexHost( observed) ;	// 必須項目とWindows x64の確認結果です
	// 端末観測の不足や既知の対象外は共通判定を保持します
	if( result.state != IndexHostGateState::ALLOW_UNVERIFIED) {
		return result ;
	}

	// 私有WiX配布の確認済み対象条件がなければ一致と扱いません
	if( !record.wixContentEvidence || !record.targetOs.value || !record.architecture.value) {
		result.state = IndexHostGateState::UNKNOWN ;
		result.error = E_NOTIMPL ;
		return result ;
	}

	const auto &host   = *observed.value ;	// 共通判定で取得を確認した原観測です
	const auto	target = host.buildNumber < 22000U
							 ? IndexTargetOs::WINDOWS_10
							 : IndexTargetOs::WINDOWS_11 ;	// クライアントの製品世代です
	// 同じ製品世代のWindowsクライアントx64に限って元Hardware IDの照合へ進めます
	if( host.productType != 1U || record.targetOs.value != target ||
	   record.architecture.value != IndexArchitecture::X64) {
		result.state = IndexHostGateState::INCOMPATIBLE ;
		result.error = E_ACCESSDENIED ;
	}

	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief 固定baseと正規GUIDから同詳細の実URLを一意復元します
 * @param[in] scope 元共通parserの非権限scopeです。同期借用します
 * @return VALID26100/26200かつ正規GUIDだけ実URL、それ以外は空です
 * @throws std::bad_alloc 有限URLの割当てに失敗しました
 * @note 原本文の取得や真偽確認を行わず、wireの固定baseを変更しません
 */
//------------------------------------------------------------------------------
std::string clientMinimumBuildDetailsUrl( const ClientMinBuildScope &scope)
{
	// 未採用floor/不正GUIDからendpointを作りません
	if( scope.state != ClientMinBuildState::VALID ||
	   !isSupportedClientMinimumBuild( scope.minimumBuild) || scope.evidenceUrl != CATALOG_BASE ||
	   !canonicalCatalogUpdateId( scope.catalogUpdateId)) {
		return {} ;
	}

	return std::string{CATALOG_BASE} + std::string{UPDATE_QUERY} + scope.catalogUpdateId ;
}
//------------------------------------------------------------------------------
/**
 * @brief 全同client templateを単独Catalog Win11 scopeへ結びます
 * @param[in] target 元discovery定義です。変更しません
 * @param[in] templates 全同target原recordです。変更しません
 * @return 全て旧scopeならNONE、全Win11が同じ採用floorならVALIDです
 * @throws winrt::hresult_error 不正/混在/初期未対応の生成入口です
 * @throws std::bad_alloc 有限textの割当て失敗です
 */
//------------------------------------------------------------------------------
ClientMinBuildScope declaredClientMinimumBuildScope( const Object &target, const Array &templates)
{
	ClientMinBuildScope result ;	// 他scopeから成功を借りません
	bool				none{} ;	// 同Win11の旧条件です
	bool				otherOs{} ;	// 新scopeで初期未対応の別OS templateです
	// 全retainedを読み、先頭だけでscopeを確定しません
	for( const auto &raw : templates) {
		const auto record = raw.GetObject() ;						// 同原参照です
		const auto scope  = readClientMinimumBuildScope( record) ;	// 不正は明示拒否します
		otherOs =
			otherOs || record.GetNamedObject( L"targetOs").GetNamedString( L"value") != L"WINDOWS_11" ;
		need( scope.state == ClientMinBuildState::NONE || scope.state == ClientMinBuildState::VALID) ;
		// 同Win11 targetのNONE/VALIDだけを混在検査します
		if( record.GetNamedObject( L"targetOs").GetNamedString( L"value") == L"WINDOWS_11") {
			none = none || scope.state == ClientMinBuildState::NONE ;
			// 同targetに正規条件がある事実だけを保持し、NONEとの混在は後で拒否します
			if( scope.state == ClientMinBuildState::VALID) {
				need( result.state == ClientMinBuildState::NONE ||
					 result.minimumBuild == scope.minimumBuild) ;
				result = scope ;
			}
		}
	}

	// 真の旧定義には新制約を追加しません
	if( result.state == ClientMinBuildState::NONE) {
		return result ;
	}

	const auto discovery = target.GetNamedObject( L"discovery") ;	// 初期対応入口だけです
	const auto os		 = discovery.GetNamedArray( L"targetOs") ;	// 混在OSへの投影は未対応です
	need( !none && !otherOs && os.Size() == 1U && os.GetAt( 0U).GetString() == L"WINDOWS_11" &&
		 discovery.GetNamedString( L"kind") == L"CATALOG_SEARCH_V1") ;
	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief 一つの可視製品欄を明示Client最低buildの許容表記に照合します
 * @param[in] products 同じ更新行又は明細から抽出した可視製品欄です
 * @param[in] minimumBuild 期待する正規floorです。別releaseを救済しません
 * @return 通常Clientの二表記があり、残りが同版Client Sだけの場合trueです
 * @throws std::bad_alloc 比較値の割当て失敗です
 * @throws std::regex_error 固定比較式の処理失敗です
 * @note 検索行では確認順の判定だけに使います。Architectureは原明細の別欄です
 */
//------------------------------------------------------------------------------
bool clientMinimumBuildProductsMatch( std::wstring_view products, const std::uint32_t minimumBuild)
{
	// 許可された最小ビルドだけを公式製品欄と照合します
	if( !isSupportedClientMinimumBuild( minimumBuild)) {
		return false ;
	}

	// 最小ビルドに対応するWindowsのリリース名
	const auto		  release = minimumBuild == 26100U ? L"24h2" : L"25h2" ;
	// リリース名を最低条件として表す製品欄の共通部分
	const auto		  suffix = std::wstring{L", version "} + release + L" and later, " ;
	// 通常のWindows 11 Clientを対象にした製品名の接頭部
	const auto		  client = L"windows 11 client" + suffix ;
	// Windows 11 Client Sを対象にした製品名の接頭部
	const auto		  clientS = L"windows 11 client s" + suffix ;
	// 掲載を許可するエディションと配布用途の組み合わせ
	const std::array  labels{client + L"servicing drivers", client + L"upgrade & servicing drivers",
							 clientS + L"servicing drivers",
							 clientS + L"upgrade & servicing drivers"} ;
	// 表記差を整えた公式の全製品欄
	const auto		  actual = catalogProductComparison( products) ;
	// 一つの製品表記を消費するたびに短くなる借用範囲
	std::wstring_view remaining{actual} ;
	// 製品表記が重複していないかを許容値の添字で記録します
	std::array<bool, labels.size()> seen{} ;
	// 製品表記同士の区切り。単独の製品名に含まれるコンマとは照合順で区別します
	constexpr std::wstring_view		delimiter = L", " ;
	// 製品名に含まれるコンマを保ち、完全な既知の表記を一件ずつ照合する
	while( !remaining.empty()) {
		// 入力の先頭と製品単位で一致する許容値
		const auto label = std::ranges::find_if( labels, [&]( const std::wstring &value) {
			return remaining == value || (remaining.starts_with( value) &&
										  remaining.substr( value.size()).starts_with( delimiter)) ;
		}) ;
		// 未許可の製品が一つでも混じる一覧は対象に加えません
		if( label == labels.end()) {
			return false ;
		}

		// 重複記録で参照する許容値の添字
		const auto index = static_cast<std::size_t>( label - labels.begin()) ;
		// 同じ製品表記の重複を完全な対象一覧として受理しません
		if( seen[index]) {
			return false ;
		}

		seen[index] = true ;
		remaining.remove_prefix( label->size()) ;
		// 許可された製品名の末尾まで消費した時点で終了します
		if( remaining.empty()) {
			break ;
		}

		remaining.remove_prefix( delimiter.size()) ;
		// 区切りの後に別の製品表記がない入力を拒否します
		if( remaining.empty()) {
			return false ;
		}
	}

	return seen[0] && seen[1] ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同じ明細から抽出したArchitectureと製品欄の両方を確認します
 * @param[in] products 厳密walkerで確認した明細本文の製品欄です
 * @param[in] architecture 同じ更新の明細のArchitecture欄です
 * @param[in] minimumBuild 期待する正規Client最低buildです
 * @return 単独AMD64と正規のClient製品表記が両方成立した場合trueです
 * @throws std::bad_alloc 比較値の割当てに失敗しました
 * @throws std::regex_error 固定比較式の処理に失敗しました
 */
//------------------------------------------------------------------------------
bool clientMinimumBuildFieldsMatch( std::wstring_view products, std::wstring_view architecture,
								   const std::uint32_t minimumBuild)
{
	return comparison( std::wstring{architecture}) == L"amd64" &&
		   clientMinimumBuildProductsMatch( products, minimumBuild) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 可視製品欄の全体と単独AMD64を同じ明細の許容値へ照合する
 * @param[in] products 既存パーサーが取り出した可視製品欄の原文です
 * @param[in] architecture 同じ明細の可視Architecture欄の原文です
 * @param[in] acceptedProducts 表示空白とASCII小文字で正規化済みの製品欄の許容値です
 * @return 単独AMD64と欄全体の一つの許容値が成立する場合だけtrueです
 * @throws std::bad_alloc 比較文字列を確保できません
 * @throws std::regex_error 固定比較式を処理できません
 * @note 製品名内のコンマを保持し、原欄の本文・順序・観測時刻を変更しません
 */
//------------------------------------------------------------------------------
bool catalogDetailProductFieldsMatch( std::wstring_view products, std::wstring_view architecture,
									 std::initializer_list<std::wstring_view> acceptedProducts)
{
	// 公式欄がx64単独の配布を示す場合だけ製品条件を検査します
	if( comparison( std::wstring{architecture}) != L"amd64") {
		return false ;
	}

	// 公式製品欄を比較用に正規化した文字列
	const auto actual = catalogProductComparison( products) ;
	return std::ranges::find( acceptedProducts, actual) != acceptedProducts.end() ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同原条件の順序と非LOCAL根拠を保持してsupportだけを更新します
 * @param[in] original 不変の原templateです
 * @param[in] evidenceUrl 同native確認済みのGUID query付き実details URLです
 * @param[in] evidenceSha256 同runの原body SHA256です
 * @return 固定base/条件内GUIDの正規一LOCALと元非LOCALを保持する独立JSONです
 * @throws winrt::hresult_error 原scope/新根拠/上限が不正です
 * @throws std::bad_alloc 独立値の割当て失敗です
 */
//------------------------------------------------------------------------------
Object makeClientMinimumBuildPrerequisites( const Object &original, std::wstring_view evidenceUrl,
										   std::wstring_view evidenceSha256)
{
	const auto actualUrl = winrt::to_string( evidenceUrl) ;				// 同nativeの原URLだけです
	const auto id		 = catalogUpdateIdFromDetailsUrl( actualUrl) ;	// 元URLに結合した正規GUIDです
	const auto scope	 = readClientMinimumBuildScope( original) ;		// 宣言floorを別候補から借りません
	need( scope.state == ClientMinBuildState::VALID && id.has_value() &&
		 evidence( std::string{CATALOG_BASE}, winrt::to_string( evidenceSha256))) ;
	auto result = Object::Parse( original.GetNamedObject( L"acquisitionDescriptor")
									.GetNamedObject( L"prerequisites")
									.Stringify()) ;	// 原参照へ戻るaliasを作りません
	// 元順の一LOCALだけを同support原byteへ更新します
	for( const auto &raw : result.GetNamedArray( L"items")) {
		auto condition = raw.GetObject() ;	// 同独立JSONの一条件です
		// 元非LOCALの順序/全field/根拠は一切更新しません
		if( condition.GetNamedString( L"kind") == L"LOCAL_CHECK") {
			condition.Insert( L"description",
							 Value::CreateStringValue( winrt::to_hstring(
								 std::string{PREFIX} + std::to_string( scope.minimumBuild) +
								 std::string{UPDATE_ID_SUFFIX} + std::string{*id}))) ;
			condition.Insert( L"evidenceUrl",
							 Value::CreateStringValue( winrt::to_hstring( CATALOG_BASE))) ;
			condition.Insert( L"evidenceSha256", Value::CreateStringValue( evidenceSha256)) ;
		}
	}

	return result ;
}
} // namespace drivercrate

#if defined( DRIVERCRATE_CLIENT_MIN_BUILD_RESTORE_GETOBJECT)
#pragma pop_macro( "GetObject")
#undef DRIVERCRATE_CLIENT_MIN_BUILD_RESTORE_GETOBJECT
#endif
