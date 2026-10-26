//------------------------------------------------------------------------------
/**
 * @file collector_distribution_candidate.cpp
 * @brief 私有全INF観測を既存v2値と原分母sidecarへ投影します。
 * @version 01.01.02
 * @date 2026/10/24
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/23  全Models/観測OS・原期限・共有descriptorを投影。
 * Ver.01.01.00 Shunji Ogawa  2026/10/24  現行nested member identityと原record完全tupleへ整合。
 * Ver.01.01.01 Shunji Ogawa  2026/10/24  発行fresh24hと新規8日recordの原期限を分離。
 * Ver.01.01.02 Shunji Ogawa  2026/10/25  各実手動確認と同run内容/PAGEの原期限minを保持。
 * </pre>
 * @note 同じnative所有観測だけを読み、JSON結果の成功値を入力にしません。
 * @see docs/adr/0396-collector-distribution-pipeline-connection.md
 */
//------------------------------------------------------------------------------
#include "platform/collector_distribution_candidate.h"
#include "platform/common_driver_package.h"
#include "platform/official_file_verifier.h"
#include "platform/signed_index_json_internal.h"
#include "platform/signed_index_records.h"
#include <algorithm>
#include <cstdio>
#include <new>
#include <map>
#include <span>
#include <tuple>
#include <utility>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#include <Windows.h>

namespace drivercrate {
namespace {
using Object	= winrt::Windows::Data::Json::JsonObject ;		// 保存用DOMだけです。
using Array		= winrt::Windows::Data::Json::JsonArray ;		// 元順を保持する集合です。
using Value		= winrt::Windows::Data::Json::JsonValue ;		// 権限を持たない保存値です。
using ValueType = winrt::Windows::Data::Json::JsonValueType ;	// 原nullを保持します。

/** @brief 固定fieldへ元文字列を保存します。
 * @param[in,out] object 保存用objectです。
 * @param[in] field 固定field名です。
 * @param[in] text 原公開文字列です。
 */
void put( Object &object, const wchar_t *field, const std::wstring_view text)
{
	object.Insert( field, Value::CreateStringValue( text)) ;
}

/** @brief 小さい実数値だけをJSON整数へ保存します。
 * @param[in,out] object 保存用objectです。
 * @param[in] field 固定fieldです。
 * @param[in] value 有限の診断/件数です。
 */
void number( Object &object, const wchar_t *field, const std::int64_t value)
{
	object.Insert( field, Value::CreateNumberValue( static_cast<double>( value))) ;
}

/** @brief 原byteを同CNGで完全hash化します。
 * @param[in] bytes 最大16MiBの生成済みbyteです。
 * @return 正規化しない小文字64桁の実hashです。
 */
std::wstring hash( const std::string_view bytes)
{
	std::wstring output ;	// 共通APIが所有して返すdigestです。
	const auto	 error =
		// 候補16MiB枠は外側で維持します。
		computeDriverContainerSha256( bytes, output) ;
	// Hash不明のまま決定的identityを合成しません。
	if( error != 0) {
		throw winrt::hresult_error( error) ;
	}

	return output ;
}

/** @brief UTC秒を補正せず既存wire形式へ表します。
 * @param[in] value 元観測のUTC秒です。
 * @return 固定20byteのUTC文字列です。
 */
std::wstring utc( const std::chrono::sys_seconds value)
{
	const auto day = std::chrono::floor<std::chrono::days>( value) ;	// 元暦日です。
	const std::chrono::year_month_day date{day} ;						// 閏日を保持します。
	const std::chrono::hh_mm_ss		  time{value - day} ;				// 元時分秒です。
	char							  buffer[32]{} ;					// UTC固定形式だけに使う有限bufferです。
	const auto						  count = std::snprintf(
		   buffer, sizeof( buffer), "%04d-%02u-%02uT%02lld:%02lld:%02lldZ",
		   static_cast<int>( date.year()), static_cast<unsigned>( date.month()),
		   static_cast<unsigned>( date.day()), static_cast<long long>( time.hours().count()),
		   static_cast<long long>( time.minutes().count()),
		   // 値を丸めません。
		   static_cast<long long>( time.seconds().count())) ;
	// 範囲外の元時刻を途中形式で保存しません。
	if( count != 20) {
		throw winrt::hresult_error( E_INVALIDARG) ;
	}

	return winrt::to_hstring( std::string_view{buffer, 20U}).c_str() ;
}

/** @brief 既存v2のKNOWN文字列を作ります。
 * @param[in] text 元公開値です。
 * @return 既知の値だけを持つ申告です。
 */
Object known( const std::wstring_view text)
{
	Object value ;	// 既存3fieldだけです。
	put( value, L"state", L"KNOWN") ;
	put( value, L"value", text) ;
	put( value, L"reason", L"") ;
	return value ;
}

/** @brief 公開hashと計算hashの根拠を独立して保存します。
 * @param[in] digest 対象byteのhashです。未公開時だけ空です。
 * @param[in] url そのhashの元根拠URLです。
 * @param[in] evidence 根拠原byteのhashです。
 * @return 既知根拠または理由付きUNKNOWNです。
 */
Object hashEvidence( const std::wstring_view digest, const std::wstring_view url,
					const std::wstring_view evidence)
{
	Object value ;	// 計算値を公表値へ複写しません。
	put( value, L"state", digest.empty() ? L"UNKNOWN" : L"KNOWN") ;
	put( value, L"sha256", digest) ;
	put( value, L"evidenceUrl", digest.empty() ? L"" : url) ;
	put( value, L"evidenceSha256", digest.empty() ? L"" : evidence) ;
	put( value, L"reason", digest.empty() ? L"PUBLISHED_HASH_UNAVAILABLE" : L"") ;
	return value ;
}

/** @brief 元節の全公開IDを切捨てず保存します。
 * @param[in] model 同じINFから読み取った元節です。
 * @return 種別付きの原全集合です。
 */
Array pnpIds( const OfficialInfPublishedModelSection &model)
{
	Array ids ;	// 表現限界を判定する前も全原IDをsidecarへ保持します。
	// 種別ごとに元順の全IDを保持します。
	for( const bool compatible : {false, true}) {
		const auto &values = compatible ? model.compatibleIds : model.hardwareIds ;	// 同じ元節です。
		// 重複除去や上限切捨てによって成功へ変換しません。
		for( const auto &id : values) {
			Object item ;	// 一つの原IDです。
			put( item, L"kind", compatible ? L"COMPATIBLE" : L"HARDWARE") ;
			put( item, L"value", id) ;
			ids.Append( item) ;
		}
	}

	return ids ;
}

/** @brief INFの全元metadataをsidecarへ保存します。
 * @param[in] inf 同通常検査の個別結果です。
 * @return Provider/CATと全Modelsを含む未署名値です。
 */
Object infSidecar( const CollectorRegistryInfObservation &inf)
{
	Object value ;	// 原検査の全metadataを保持します。
	put( value, L"infIdentity", inf.infIdentity) ;
	put( value, L"nestedArchiveIdentity", inf.nestedArchiveIdentity) ;
	put( value, L"infSha256", inf.identity.infSha256) ;
	put( value, L"classGuid", inf.identity.classGuid) ;
	put( value, L"className", inf.className) ;
	put( value, L"driverVersion", inf.driverVersion) ;
	put( value, L"driverDate", inf.driverDate) ;
	put( value, L"provider", inf.provider) ;
	put( value, L"catalogIdentity", inf.catalogIdentity) ;
	put( value, L"verifiedPublisher", inf.verifiedPublisher) ;
	number( value, L"contentState", inf.contentState) ;
	number( value, L"contentError", inf.contentError) ;
	number( value, L"identityError", inf.identityError) ;
	Array models ;	// 元全節を保持します。
	// 観測した全節を元順どおり保存し、失敗分母を除去しません。
	for( const auto &model : inf.identity.models) {
		Object row ;	// 元一節です。
		put( row, L"modelSection", model.modelSection) ;
		row.Insert( L"pnpIds", pnpIds( model)) ;
		models.Append( row) ;
	}

	value.Insert( L"models", models) ;
	return value ;
}

/** @brief 原INF日付を同じ暦日のISO表現へ移します。
 * @param[in] date 元MM/DD/YYYYです。
 * @return 実在日だけのISO表現です。未知は空です。
 */
std::wstring isoInfDate( const std::wstring_view date)
{
	// 別形式を推測して公開日を合成しません。
	if( date.size() != 10U || date[2] != L'/' || date[5] != L'/') {
		return {} ;
	}

	const std::wstring iso = std::wstring{date.substr( 6U)} + L"-" +
							 std::wstring{date.substr( 0U, 2U)} + L"-" +
							 std::wstring{date.substr( 3U, 2U)} ;	// 暦日を変更しない表記変換です。
	static_cast<void>( signed_index_json::utc( winrt::to_string( iso) + "T00:00:00Z", E_INVALIDARG)) ;
	return iso ;
}

/** @brief 同packageの全INFが共有する取得descriptorを作ります。
 * @param[in] job 厳密検証済みの原jobです。
 * @param[in] page 同実PAGE観測です。
 * @param[in] publisher 同packageの検証済み署名者です。
 * @param[in] checkedAt 元内容検査UTCです。
 * @param[in] expiry 元根拠期限の最小値です。
 * @return INF selectorを含まない既存取得descriptorです。
 */
Object descriptor( const Object &job, const CollectorInspectionPageObservation &page,
				  const std::wstring_view publisher, const std::chrono::sys_seconds checkedAt,
				  const std::chrono::sys_seconds expiry)
{
	const auto		   source = job.GetNamedObject( L"source") ;	// 原exact経路です。
	const std::wstring payload{										// 期限付きqueryは元jobが拒否済みです。
							   source.GetNamedString( L"payloadUrl")} ;
	const std::wstring root{source.GetNamedString( L"rootUrl")} ;			// 元公式pageです。
	const bool		   zip = job.GetNamedString( L"container") == L"ZIP" ;	// 元明示形式です。
	Object			   value ;												// 既存13fieldだけを使います。
	put( value, L"schema", L"driver-index-acquisition-v1") ;
	put( value, L"state", L"KNOWN") ;
	put( value, L"reason", L"") ;
	put( value, L"payloadUrl", payload) ;
	put( value, L"fileName", std::wstring_view{payload}.substr( payload.find_last_of( L'/') + 1U)) ;
	put( value, L"format", zip ? L"ZIP" : L"CABINET") ;
	put( value, L"expectedContentType",
		zip ? L"application/zip" : L"application/vnd.ms-cab-compressed") ;
	value.Insert( L"maximumBytes", job.Lookup( L"maximumBytes")) ;
	Object hop ;	// URLだけで共有を認定せず同検証導線を保持します。
	put( hop, L"url", payload) ;
	put( hop, L"kind",
		source.GetNamedString( L"rootHost") == source.GetNamedString( L"payloadHost")
			? L"OFFICIAL_PAYLOAD_LINK"
			: L"OFFICIAL_CDN_LINK") ;
	put( hop, L"evidenceUrl", root) ;
	put( hop, L"evidenceSha256", page.bodySha256) ;
	Array route ;	// 同exact payloadへの一hopです。
	route.Append( hop) ;
	value.Insert( L"route", route) ;
	Object terms ;	// 原独立確認が揃ったjobだけが呼び出します。
	put( terms, L"state", L"CONFIRMED_NO_CONSENT") ;
	put( terms, L"reason", L"") ;
	put( terms, L"evidenceUrl", root) ;
	put( terms, L"evidenceSha256", page.bodySha256) ;
	put( terms, L"revisionKind", L"NONE") ;
	put( terms, L"revision", L"") ;
	terms.Insert( L"textDocument", Value::CreateNullValue()) ;
	value.Insert( L"terms", terms) ;
	Object prerequisites ;	// 元確認の明示空集合です。
	put( prerequisites, L"state", L"KNOWN") ;
	put( prerequisites, L"reason", L"") ;
	prerequisites.Insert( L"items", Array{}) ;
	value.Insert( L"prerequisites", prerequisites) ;
	value.Insert( L"publisher", known( publisher)) ;
	Object attestation ;	// 元確認時刻をbuild時刻へ置換しません。
	put( attestation, L"kind", L"COLLECTOR_VERIFIED_OFFICIAL_ROUTE") ;
	number( attestation, L"policyRevision", 1U) ;
	put( attestation, L"checkedAtUtc", utc( checkedAt)) ;
	put( attestation, L"validUntilUtc", utc( expiry)) ;
	put( attestation, L"authorityMethod", L"OFFICIAL_SITE_CONTROL_AND_LINK") ;
	put( attestation, L"authorityEvidenceUrl", root) ;
	put( attestation, L"authorityEvidenceSha256", page.bodySha256) ;
	value.Insert( L"attestation", attestation) ;
	return value ;
}
} // namespace

/** @see collector_distribution_candidate.h */
std::string_view CollectorDistributionCandidate::json() const noexcept
{
	return bytes_ ;
}
/** @see collector_distribution_candidate.h */
std::size_t CollectorDistributionCandidate::recordCount() const noexcept
{
	return records_ ;
}

/** @see collector_distribution_candidate.h */
NativeError makeCollectorDistributionRecords(
	const CollectorRegistryVerifiedObservation &observation, const std::chrono::sys_seconds nowUtc,
	CollectorDistributionCandidate &candidate) noexcept
{
	candidate = {} ;
	try {
		const auto job =
			// 元入力だけの参照解析です。
			Object::Parse( winrt::to_hstring( observation.jobBytes_)) ;
		const auto original =
			// 過去研究観測をそのままsidecarに残します。
			job.GetNamedObject( L"record") ;
		const auto route = job.GetNamedObject( L"source") ;	// 検証済み実行条件です。
		const auto declared =
			// 公式申告OSの原集合です。
			original.GetNamedArray( L"operatingSystems") ;
		const auto &page	= observation.page_ ;		// 同HTTPのfresh観測です。
		const auto	checked = observation.checkedAt_ ;	// 同INF検査の元時刻です。
		auto		expiry	= std::min(
			checked + INDEX_ACQUISITION_MAX_VALIDITY,
			page.observedAtUtc + INDEX_ACQUISITION_MAX_VALIDITY) ;	// 同run実内容/PAGEの元期限です。
		const auto review =
			// 原HTTP時刻と区別した四つの実手動確認です。
			job.GetNamedObject( L"review") ;
		// 各scopeの原時刻を独立に制約へ加え、日次再取得で手動確認を延長しません。
		for( const auto scope : {L"official", L"preDownload", L"terms", L"prerequisites"}) {
			const auto reviewed =
				review.GetNamedObject( scope)
					.GetNamedObject( L"evidence")
					.GetNamedString( L"checkedAt") ;	// 当該scopeだけの実確認時刻です。
			const auto reviewedAt =
				signed_index_json::utc( winrt::to_string( reviewed).substr( 0U, 19U) + "Z",
									   E_INVALIDARG) ;	// 元小数秒を延長しない秒切下げです。
			expiry = std::min( expiry, reviewedAt + INDEX_ACQUISITION_MAX_VALIDITY) ;
		}

		const std::wstring family	   = observation.windowsServer_ ? L"WINDOWS_SERVER_X64"
										 : observation.windowsBuild_ >= 22000U ? L"WINDOWS_11_X64"
										 : observation.windowsBuild_ >= 10240U
											 ? L"WINDOWS_10_X64"
											 : L"UNKNOWN" ;	// 現実観測だけのfamilyです。
		const std::wstring projectedOs = family == L"WINDOWS_SERVER_X64" ? L"WINDOWS_SERVER"
										 : family == L"WINDOWS_11_X64"
											 ? L"WINDOWS_11"
											 : L"WINDOWS_10" ;	// 宣言との共通部分でだけ使います。
		const std::wstring sourceId =
			hash( winrt::to_string( job.GetNamedString( L"sourceId")) + "\n" +
				 winrt::to_string(
					 // 同sourceの複数pageを一意に表します。
					 route.GetNamedString( L"rootUrl"))) ;
		Object source ;	// 全参照はsidecarの原sourceへ結合します。
		put( source, L"sourceId", sourceId) ;
		put( source, L"officialOrigin",
			L"https://" + std::wstring{route.GetNamedString( L"rootHost")} + L"/") ;
		source.Insert( L"distributionPage", route.Lookup( L"rootUrl")) ;
		Object official ;	// 独立公式主体確認と同PAGE hashに結合します。
		put( official, L"state", L"PUBLISHED") ;
		put( official, L"kind", L"OFFICIAL_PAGE") ;
		official.Insert( L"evidenceUrl", route.Lookup( L"rootUrl")) ;
		put( official, L"evidenceSha256", page.bodySha256) ;
		put( official, L"reason", L"") ;
		source.Insert( L"officialEvidence", official) ;
		Object output ;	// 候補は未署名であり取得/導入能力を持ちません。
		put( output, L"schema", L"dc-collector-distribution-candidate-v1") ;
		put( output, L"producerVersion", L"collector-distribution-v1") ;
		put( output, L"jobSha256", observation.jobSha256_) ;
		output.Insert( L"job", job) ;
		put( output, L"modelsScope", L"CURRENT_WINDOWS_X64_SELECTION_ONLY") ;
		put( output, L"observedOsFamily", family) ;
		number( output, L"inspectionWindowsBuild", observation.windowsBuild_) ;
		output.Insert( L"inspectionWindowsServer",
					  Value::CreateBooleanValue( observation.windowsServer_)) ;
		number( output, L"inspectionWindowsProductSku", observation.windowsProductSku_) ;
		put( output, L"checkedAtUtc", utc( checked)) ;
		put( output, L"validUntilUtc", utc( expiry)) ;
		put( output, L"pageObservedAtUtc", utc( page.observedAtUtc)) ;
		put( output, L"pageSha256", page.bodySha256) ;
		number( output, L"jobError", observation.jobError_) ;
		Array		 records ;				// 全投影可能recordだけです。空は索引成功ではありません。
		Array		 outcomes ;				// 失敗/未観測/表現限界を含む全分母です。
		Array		 infs ;					// 全原ID・provider・CAT・署名者を保持します。
		std::wstring commonPublisher ;		// 同packageで一意な実署名者だけをdescriptorへ使用します。
		bool		 publisherAmbiguous{} ;	// 複数署名者を一署名者へ推測しません。
		std::map<std::tuple<std::wstring, std::wstring, std::wstring, std::wstring>, std::size_t>
			modelIdentities ;	// 同nested/INF member/原hash/節の一意性です。
		// 全成功INFを先に確認し、同package descriptorとv2 identityの表現を固定します。
		for( const auto &inf : observation.infs_) {
			// 個別拒否は全原分母へ残し、署名者の補完には使いません。
			if( inf.contentError != 0 || inf.identityError != 0 || inf.verifiedPublisher.empty()) {
				continue ;
			}

			// 初回の同検証署名者を比較基準へ固定します。
			if( commonPublisher.empty()) {
				commonPublisher = inf.verifiedPublisher ;
			}

			publisherAmbiguous = publisherAmbiguous || commonPublisher != inf.verifiedPublisher ;
			// 元全節のhash/名前を数え、重複を一つのINF selectorへ丸めません。
			for( const auto &model : inf.identity.models) {
				++modelIdentities[{inf.nestedArchiveIdentity, inf.infIdentity,
								   inf.identity.infSha256, model.modelSection}] ;
			}
		}

		// 全INFを順に扱い、job全体拒否後の先行成功も理由付きで破棄します。
		for( const auto &inf : observation.infs_) {
			infs.Append( infSidecar( inf)) ;
			const bool accepted = inf.contentState == static_cast<std::uint32_t>(
														  CommonInfInspectionState::VERIFIED) &&
								  inf.contentError == 0 && inf.identityError == 0 &&
								  !inf.identity.models.empty() ;	// 同検査の型付き状態です。
			// 公開identity不足の行を分母から消しません。
			if( !accepted) {
				Object outcome ;	// 元個別拒否です。
				put( outcome, L"infIdentity", inf.infIdentity) ;
				put( outcome, L"nestedArchiveIdentity", inf.nestedArchiveIdentity) ;
				put( outcome, L"modelSection", L"") ;
				put( outcome, L"targetOs", L"") ;
				put( outcome, L"reason",
					observation.jobError_ != 0 ? L"DISCARDED_JOB_FAILURE"
											   : L"INF_REJECTED_OR_UNKNOWN") ;
				outcomes.Append( outcome) ;
				continue ;
			}

			// 元Models節を全て評価し、一節でもIDを分割・切捨てしません。
			for( const auto &model : inf.identity.models) {
				// 申告された他OSも未観測として元分母へ保持します。
				for( const auto &os : declared) {
					Object outcome ;	// 元一INF/節/OSです。
					put( outcome, L"infIdentity", inf.infIdentity) ;
					put( outcome, L"nestedArchiveIdentity", inf.nestedArchiveIdentity) ;
					put( outcome, L"modelSection", model.modelSection) ;
					outcome.Insert( L"targetOs", os) ;
					std::wstring reason ;	// 成功空理由または固定の保留理由です。
					// 全体拒否を個別の先行合格で回避しません。
					if( observation.jobError_ != 0) {
						reason = L"DISCARDED_JOB_FAILURE" ;
					}
					// 他familyを現在のModels選択から実証したことにしません。
					else if( std::wstring_view{os.GetString()} != family) {
						reason = L"MODELS_OS_UNOBSERVED" ;
					}
					// 元独立根拠/取得/期限が欠ける場合は取得KNOWNを発行しません。
					else if( !observation.routeVerified_ || page.httpStatus != 200U ||
							page.bodySha256.empty() || page.observedAtUtc > checked ||
							checked > nowUtc ||
							nowUtc >= page.observedAtUtc + std::chrono::hours{24} ||
							nowUtc >= expiry) {
						reason = L"EVIDENCE_EXPIRED_OR_UNCONFIRMED" ;
					}
					// 同じmember/原hash/節の重複やID全集合を別payloadへ変形しません。
					else if( publisherAmbiguous ||
							modelIdentities[{inf.nestedArchiveIdentity, inf.infIdentity,
											 inf.identity.infSha256, model.modelSection}] != 1U ||
							model.hardwareIds.size() + model.compatibleIds.size() >
								INDEX_RECORD_PNP_MAX_COUNT ||
							model.hardwareIds.empty() && model.compatibleIds.empty()) {
						reason = L"V2_REPRESENTATION_LIMIT" ;
					} else {
						Object record ;	// 既存v2の15fieldだけです。
						put( record, L"schema", L"driver-index-record-v2") ;
						put( record, L"sourceId", sourceId) ;
						Object identityKey ;	// 表示名や実行世代をidentityへ混入させません。
						identityKey.Insert( L"source", job.Lookup( L"sourceId")) ;
						identityKey.Insert( L"record", job.Lookup( L"recordId")) ;
						put( identityKey, L"archiveSha256", observation.archiveSha256_) ;
						number( identityKey, L"archiveBytes",
							   static_cast<std::int64_t>( observation.archiveBytes_)) ;
						put( identityKey, L"nestedArchiveIdentity", inf.nestedArchiveIdentity) ;
						put( identityKey, L"infIdentity", inf.infIdentity) ;
						put( identityKey, L"infSha256", inf.identity.infSha256) ;
						put( identityKey, L"modelSection", model.modelSection) ;
						put( identityKey, L"osFamily", family) ;
						put( record, L"recordId", hash( winrt::to_string( identityKey.Stringify()))) ;
						record.Insert( L"product", original.Lookup( L"title")) ;
						record.Insert( L"targetOs", known( projectedOs)) ;
						record.Insert( L"architecture", known( L"X64")) ;
						record.Insert( L"driverKind", known( L"NORMAL_DRIVER")) ;
						record.Insert( L"version", known( inf.driverVersion)) ;
						record.Insert( L"publishedDate", known( isoInfDate( inf.driverDate))) ;
						record.Insert( L"acquisition", known( L"STANDARD_INF_ARCHIVE")) ;
						Object	   package ;	// 公開値と実計算値の根拠を独立して保持します。
						const auto published =
							// 原nullを保持します。
							original.GetNamedValue( L"publishedSha256") ;
						package.Insert( L"publishedHash",
									   hashEvidence( published.ValueType() == ValueType::Null
														? std::wstring_view{}
														: std::wstring_view{published.GetString()},
													route.GetNamedString( L"rootUrl"),
													page.bodySha256)) ;
						package.Insert( L"calculatedHash",
									   hashEvidence( observation.archiveSha256_,
													route.GetNamedString( L"payloadUrl"),
													observation.archiveSha256_)) ;
						Object size ;	// 実byte長だけです。
						put( size, L"state", L"KNOWN") ;
						number( size, L"valueBytes",
							   static_cast<std::int64_t>( observation.archiveBytes_)) ;
						put( size, L"reason", L"") ;
						package.Insert( L"size", size) ;
						record.Insert( L"packageEvidence", package) ;
						record.Insert( L"lastSuccessfulObservationUtc",
									  known( utc( page.observedAtUtc))) ;
						put( record, L"inspectionStage", L"CONTENT_INSPECTED") ;
						Object identity ;	// INF/Modelsは取得descriptorへ混入させません。
						put( identity, L"state", L"PUBLISHED") ;
						put( identity, L"kind", L"INF") ;
						identity.Insert( L"pnpIds", pnpIds( model)) ;
						put( identity, L"classGuid", inf.identity.classGuid) ;
						std::wstring infName = inf.infIdentity ;	// 投影時だけslash表記へ移します。
						std::ranges::replace( infName, L'\\', L'/') ;
						put( identity, L"infIdentity", infName) ;
						std::wstring nestedName =
							inf.nestedArchiveIdentity ;	// 同原memberのwire区切りだけです。
						std::ranges::replace( nestedName, L'\\', L'/') ;
						put( identity, L"nestedArchiveIdentity", nestedName) ;
						put( identity, L"modelSection", model.modelSection) ;
						identity.Insert( L"evidenceUrl", route.Lookup( L"payloadUrl")) ;
						put( identity, L"evidenceSha256", inf.identity.infSha256) ;
						put( identity, L"reason", L"") ;
						record.Insert( L"publishedIdentityEvidence", identity) ;
						record.Insert( L"acquisitionDescriptor",
									  descriptor( job, page, commonPublisher, checked, expiry)) ;
						const auto bytes =
							// Base64前の実record byte数です。
							winrt::to_string( record.Stringify()) ;
						// 64KiB上限を越えた原行は全IDをsidecarへ残して保留します。
						if( bytes.size() > INDEX_RECORD_MAX_BYTES) {
							reason = L"V2_REPRESENTATION_LIMIT" ;
						} else {
							records.Append( record) ;
							outcome.Insert( L"recordId", record.Lookup( L"recordId")) ;
						}
					}

					put( outcome, L"reason", reason.empty() ? L"PROJECTED" : reason) ;
					outcomes.Append( outcome) ;
				}
			}
		}

		Array sources ;	// 参照recordがあるsourceだけを収録します。
		// 全拒否はsourceだけの成功空索引に変換しません。
		if( records.Size() != 0U) {
			sources.Append( source) ;
		}

		output.Insert( L"sources", sources) ;
		output.Insert( L"records", records) ;
		output.Insert( L"infs", infs) ;
		output.Insert( L"outcomes", outcomes) ;
		const auto bytes = winrt::to_string( output.Stringify()) ;	// 全原集合を含む候補byteです。
		// 全原集合が保存枠に入らなければ切捨てず明示API失敗とします。
		if( bytes.size() > 16U * 1024U * 1024U) {
			return HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE) ;
		}

		candidate.bytes_   = bytes ;
		candidate.records_ = records.Size() ;
		return 0 ;
	} catch( const signed_index_json::Failure<NativeError> &failure) {
		return failure.status ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( const winrt::hresult_error &failure) {
		return failure.code().value ;
	} catch( ...) {
		return E_UNEXPECTED ;
	}
}
} // namespace drivercrate
