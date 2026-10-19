//------------------------------------------------------------------------------
/**
 * @file asus_network_record_adapter.cpp
 * @brief ASUS公式ネットワーク配布のrecord変換と固定起点取得を実装します。
 * @version 01.08.00
 * @date 2026/09/20
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/20  ASUSネットワーク配布のAI取得接続を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/20  製品固定なしcatalog queryと取得予算を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/20  取得前目的照合用の公式driver分類をrecordへ保持。
 * Ver.01.03.00 Shunji Ogawa  2026/09/24  公開model明示と現PC識別の公式page入口を分離。
 * Ver.01.04.00 Shunji Ogawa  2026/09/24  公開modelを旧用途hintと分けたquery v2を解析。
 * Ver.01.05.00 Shunji Ogawa  2026/09/28  収集専用候補と共通配布field組立てを追加。
 * Ver.01.06.00 Shunji Ogawa  2026/09/28  収集候補と解析済み公開modelの再照合を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/09/28  同一controlの対象／候補照合と型付き終了を追加。
 * Ver.01.08.00 Shunji Ogawa  2026/09/28  公開modelと公式比較keyを同一正規化で照合。
 * </pre>
 *
 * @note 呼出しthreadで同期実行します。取得用recordは適用性または導入許可ではありません。
 * @see docs/adr/0179-asus-network-ai-acquisition.md
 */
//------------------------------------------------------------------------------

#include "platform/asus_network_record_adapter.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include <Windows.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <string>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {
constexpr std::uint64_t MAXIMUM_BYTES = 128ULL * 1024ULL * 1024ULL ;	// 一ZIPの受信上限。
/**
 * @brief 既知scopeと公式分類・公開titleの対応を確認します。
 * @param[in] entry 公式parserが返した一配布。
 * @param[in] target 明示評価scope。
 * @return 対象ブランド・分類が明示されている場合true。
 */
[[nodiscard]] bool matches( const AsusDriverPageEntry &entry, const AsusNetworkRecordTarget target)
{
	// Scopeごとに公開driver分類を分け、他社・firmware・utilityへ広げない。
	switch( target) {
		// LANのMarvell driver行だけを評価する。
		case AsusNetworkRecordTarget::MARVELL_LAN:
			return entry.category == L"LAN" && entry.title.starts_with( L"Marvell LAN Driver ") ;
		// WirelessのQCA／Qualcomm driver行だけを評価する。
		case AsusNetworkRecordTarget::QUALCOMM_WIFI:
			return entry.category == L"Wireless" &&
				   (entry.title.starts_with( L"QCA WiFi Driver ") ||
					entry.title.starts_with( L"Qualcomm WiFi Driver ")) ;
		// 製品名を固定せず、公式driver分類と後続AI選択で対象を絞る。
		case AsusNetworkRecordTarget::CATALOG:
			return isAsusDriverCatalogCategory( entry.category) ;
	}

	return false ;
}
/**
 * @brief Scope、分類、取得予算の組合せを通信前に検証します。
 * @param[in] target 検査するenum。
 * @param[in] category 汎用scopeで要求するdriver分類。
 * @param[in] maximumBytes 明示した取得予算。
 * @return 定義済みの組合せの場合true。
 */
[[nodiscard]] bool knownTarget( const AsusNetworkRecordTarget target,
							   const std::wstring_view		 category,
							   const std::uint64_t			 maximumBytes) noexcept
{
	// 汎用分類だけは拡張された明示取得予算を認める。
	if( target == AsusNetworkRecordTarget::CATALOG) {
		return isAsusDriverCatalogCategory( category) &&
			   (maximumBytes == MAXIMUM_BYTES || maximumBytes == 4U * MAXIMUM_BYTES) ;
	}

	return category.empty() && maximumBytes == MAXIMUM_BYTES &&
		   (target == AsusNetworkRecordTarget::MARVELL_LAN ||
			target == AsusNetworkRecordTarget::QUALCOMM_WIFI) ;
}
/**
 * @brief 通常recordと収集候補に同じ公式配布fieldを組み立てます。
 * @tparam Record 通常または収集専用のworker内record型。
 * @param[in] entry URLと公開hashを確認済みのASUS行。
 * @param[in] request 同じ公式pageのmodel・OS要求。
 * @param[in] target parser IDとrouteを決める既知scope。
 * @param[in] evidenceId 同じ応答内で一意な1起点ID。
 * @param[in] resolvedUtcSeconds 同じ本文を検証した後の解決時刻。
 * @param[out] record 起点証拠以外の全配布fieldを所有します。
 * @note 本関数は公式URL・取得証拠・source policyを証明しません。
 */
template <class Record>
void fillAsusRecordFields( const AsusDriverPageEntry &entry, const AsusSupportPageRequest &request,
						  const AsusNetworkRecordTarget target, const std::uint64_t evidenceId,
						  const std::uint64_t resolvedUtcSeconds, Record &record)
{
	record.recordEvidenceId = evidenceId ;
	record.parserId			= target == AsusNetworkRecordTarget::CATALOG ? L"asus-catalog-record-v1"
																		 : L"asus-network-record-v1" ;
	record.parserRevision	= 1U ;
	record.recordRoute	  = target == AsusNetworkRecordTarget::CATALOG ? L"asus-support-catalog-zip"
																	   : L"asus-support-network-zip" ;
	record.recordKey	  = request.model + L"|" + entry.opaqueId ;
	record.productFamily  = entry.title ;
	record.driverCategory = entry.category ;
	record.operatingSystem	  = request.osName ;
	record.packageVersion	  = entry.version ;
	record.publishedDate	  = entry.releaseDate ;
	record.terms			  = OfficialDistributionTerms::CONFIRMED_NO_CONSENT ;
	record.resolvedUtcSeconds = resolvedUtcSeconds ;
	OfficialDistributionPayloadRecord payload ;	// 元のASUS配布行に一対一のZIP。
	payload.resourceId		= OFFICIAL_PAYLOAD_RESOURCE_ID ;
	payload.kind			= OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE ;
	payload.fileDisplayName = entry.downloadUrl.substr( entry.downloadUrl.find_last_of( L'/') + 1U) ;
	payload.publishedSha256 = entry.sha256 ;
	payload.expectedContentType = L"application/zip" ;
	payload.maximumBytes		= entry.maximumDownloadBytes ;
	payload.targetUrl			= SecretOfficialUrl{std::wstring( entry.downloadUrl)} ;
	record.payloads.push_back( std::move( payload)) ;
}
/**
 * @brief ASCII公開表示名の文字集合と容量を検証します。
 * @param[in] value メーカーまたは製品の表示名。
 * @param[in] maximum 許可byte数。
 * @return URL、path、ID区切り、制御文字を含まない場合true。
 */
[[nodiscard]] bool validPublicHint( const std::string_view value, const std::size_t maximum)
{
	return !value.empty() && value.size() <= maximum && value.front() != ' ' &&
		   value.back() != ' ' &&
		   std::ranges::all_of( value,
							   []( const char ch) {
								   return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
										  (ch >= '0' && ch <= '9') ||
										  std::string_view( " -().,+").find( ch) !=
											  std::string_view::npos ;
							   }) &&
		   value.find( "www.") == std::string_view::npos ;
}
} // namespace

/** @see asus_network_record_adapter.h */
std::optional<AsusDriverCatalogQuery> parseAsusDriverCatalogQuery( const std::string_view bytes)
{
	// 過大入力を行走査する前に拒否する。
	if( bytes.empty() || bytes.size() > 512U) {
		return std::nullopt ;
	}

	const bool extended = bytes.starts_with( "DCASUSQUERY2\n") ;	// v2だけ公開modelを指定する。
	std::array<std::string_view, 7U> fields{} ;						// 最大7行を借用するview。
	std::size_t						 cursor{} ;						// 次の行の開始位置。
	// 選んだ版の全行にLF終端を要求し、余剰行を認めない。
	for( std::size_t index = 0U; index < (extended ? 7U : 5U); ++index) {
		const auto end = bytes.find( '\n', cursor) ;	// 次の行境界。
		// 切断fileから条件を補わない。
		if( end == std::string_view::npos) {
			return std::nullopt ;
		}

		fields[index] = bytes.substr( cursor, end - cursor) ;
		cursor		  = end + 1U ;
	}

	// 条件は正規形だけを受け入れ、URLやIDをqueryへ持ち込ませない。
	if( cursor != bytes.size() || fields[0] != (extended ? "DCASUSQUERY2" : "DCASUSQUERY1") ||
	   !validPublicHint( fields[1], 32U) || !validPublicHint( fields[2], 64U) ||
	   !validPublicHint( fields[3], 128U) || (fields[4] != "128" && fields[4] != "512")) {
		return std::nullopt ;
	}

	AsusDriverCatalogQuery query ;	// 検証済み公開条件の所有値。
	query.category.assign( fields[1].begin(), fields[1].end()) ;
	// Firmwareやutilityをdriver分類へ読み替えない。
	if( !isAsusDriverCatalogCategory( query.category)) {
		return std::nullopt ;
	}

	query.manufacturer = fields[2] ;
	query.product	   = fields[3] ;
	query.maximumBytes = fields[4] == "128" ? MAXIMUM_BYTES : 4U * MAXIMUM_BYTES ;
	// v2の機種はdriver用途hintとは独立にcanonical公式pageへ変換する。
	if( extended) {
		AsusSupportPageRequest request ;	// 公開modelとOSの検証結果。
		// ASCII外・不正model・未知OSを受理せず旧v1へfallbackしない。
		if( !makeAsusPublicModelSupportPageRequest( std::wstring( fields[5].begin(), fields[5].end()),
												  std::wstring( fields[6].begin(), fields[6].end()),
												  request)) {
			return std::nullopt ;
		}

		query.publicPage = std::move( request) ;
	}

	return query ;
}

/** @see asus_network_record_adapter.h */
bool adaptAsusNetworkDistributionRecords(
	const std::span<const AsusDriverPageEntry> entries, const AsusSupportPageRequest &request,
	const AsusNetworkRecordTarget target, const OfficialSourceEvidence &rootEvidence,
	const std::uint64_t resolvedUtcSeconds, std::vector<OfficialDistributionRecord> &records,
	const std::wstring_view category, const std::uint64_t maximumBytes, std::size_t *overBudget)
{
	records.clear() ;
	// 再利用された観測へ前回の件数を残さない。
	if( overBudget != nullptr) {
		*overBudget = 0U ;
	}

	// 別Provider・cache・過大入力をASUS公式recordへ昇格させない。
	if( !knownTarget( target, category, maximumBytes) || entries.empty() || entries.size() > 512U ||
	   rootEvidence.providerId != ASUS_PROVIDER_ID ||
	   rootEvidence.policyId != ASUS_OFFICIAL_SOURCE_POLICY_ID ||
	   rootEvidence.resourceId != OFFICIAL_PRIMARY_METADATA_RESOURCE_ID ||
	   rootEvidence.acquisition != MeasurementAcquisition::NETWORK_BODY ||
	   rootEvidence.cachePermitted || !rootEvidence.bodyAcquiredUtcSeconds ||
	   resolvedUtcSeconds < *rootEvidence.bodyAcquiredUtcSeconds) {
		return false ;
	}

	AsusSupportPageRequest canonical ;		// 同じ公開modelだけから再構成する正規起点。
	bool				   applicable{} ;	// 純粋な要求構築の成立結果。
	// OS名を既知x64契約へ限定し、任意URLをcallerから受け入れない。
	if( (request.osName != L"Windows 11 64-bit" && request.osName != L"Windows 10 64-bit") ||
	   !makeAsusSupportPageRequest( L"ASUSTeK COMPUTER INC.", request.model, L"", L"",
								   request.osName == L"Windows 11 64-bit" ? 22000U : 19045U, false,
								   canonical, applicable) ||
	   !applicable || canonical.model != request.model || canonical.osName != request.osName ||
	   canonical.pageUrl != request.pageUrl) {
		return false ;
	}

	std::vector<OfficialDistributionRecord> pending ;	// 全検証成功まで公開しない集合。
	// 元page順を保持し、対象scopeの小容量ZIPを一配布一recordへ変換する。
	for( const auto &entry : entries) {
		// 別scopeと今回の小容量評価外を候補なしとして分ける。
		if( !matches( entry, target) ||
		   (target == AsusNetworkRecordTarget::CATALOG && entry.category != category)) {
			continue ;
		}

		// 正常metadataでも今回の明示取得予算を超える配布は取得しない。
		if( entry.maximumDownloadBytes > maximumBytes) {
			// 観測callerだけへ容量による除外を区別して返す。
			if( overBudget != nullptr) {
				++*overBudget ;
			}

			continue ;
		}

		// 既存parser境界を再確認し、URLからhash・版を推測しない。
		if( !entry.downloadUrl.starts_with( L"https://dlcdnets.asus.com/pub/ASUS/") ||
		   entry.downloadUrl.find_first_of( L"?#\\") != std::wstring::npos ||
		   entry.maximumDownloadBytes == 0U || entry.opaqueId.empty() ||
		   entry.sha256.size() != 64U || !std::ranges::all_of( entry.sha256, []( wchar_t ch) {
			   return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f') ;
		   })) {
			return false ;
		}

		// CAB等は今回のZIP持出し契約へ読み替えない。
		if( !entry.downloadUrl.ends_with( L".zip")) {
			continue ;
		}

		// 上限超過や重複を黙って切り捨てず全体拒否する。
		if( pending.size() >= 16U || std::ranges::any_of( pending, [&]( const auto &prior) {
			   return prior.recordKey == request.model + L"|" + entry.opaqueId ||
					  prior.payloads.front().targetUrl.view() == entry.downloadUrl ;
		   })) {
			return false ;
		}

		OfficialDistributionRecord record ;	// 一つの公式行とscopeを保持するrecord。
		record.rootEvidence = rootEvidence ;
		fillAsusRecordFields( entry, request, target, pending.size() + 1U, resolvedUtcSeconds,
							 record) ;
		OfficialDistributionRecordEvidence evidence ;	// 共通検証の非機密結果。
		// 構造・root・文字列契約を一件でも満たさなければ部分集合を返さない。
		if( validateOfficialDistributionRecord( record, evidence) != 0) {
			return false ;
		}

		pending.push_back( std::move( record)) ;
	}

	// 配布なしを正常取得可能と誤表示しない。
	if( pending.empty()) {
		return false ;
	}

	records = std::move( pending) ;
	return true ;
}

/**
 * @brief 旧入口と制御付き入口の共通coreです。
 * @param[in,out] control 新経路の制御。旧入口だけnull。
 * @param[in] page 同一本文のpage。
 * @param[in] request 同じ公式要求。
 * @param[in] resolvedUtcSeconds 本文時刻。
 * @param[out] candidates 全成立後だけ公開する値。
 * @return 集合契約が成立すればtrue。
 */
static bool adaptAsusCollectorNetworkRecordCandidatesCore(
	CollectorParserContext *control, const AsusCollectorPageResult &page,
	const AsusSupportPageRequest &request, const std::uint64_t resolvedUtcSeconds,
	std::vector<OfficialCollectorRecordCandidate> &candidates)
{
	collectorParserCheckpoint( control) ;
	candidates.clear() ;
	// Parserの部分結果でも対象model・OSが揃った有効行だけを候補化する。
	// 明示されたrecord上限だけを独立に判定します。
	if( page.entries.size() > 16U) {
		collectorParserLimit( control) ;
	}

	// 有効な同一製品の採用済み行だけを候補化します。
	if( !page.structurallyValid || !page.targetModelMatches ||
	   (page.sliceStatus != AsusCollectorSliceStatus::ACCEPTED &&
		page.sliceStatus != AsusCollectorSliceStatus::PARTIAL_REJECTED) ||
	   page.category != L"LAN" || page.osName != request.osName || page.productId.empty() ||
	   page.entries.empty() || page.entries.size() > 16U || resolvedUtcSeconds == 0U) {
		return false ;
	}

	AsusSupportPageRequest canonical ;	// 公開modelとOSから再構築した公式page要求。
	// 任意URLや異なるmodelを既知ASUS公式起点へ変換しない。
	if( !makeAsusPublicModelSupportPageRequest( request.model, request.osName, canonical) ||
	   canonical.model != request.model ||
	   page.modelComparisonKey != asusCollectorModelComparisonKey( request.model) ||
	   canonical.osName != request.osName || canonical.pageUrl != request.pageUrl) {
		return false ;
	}

	std::vector<OfficialCollectorRecordCandidate> pending ;	// 全行確認まで非公開の候補集合。
	// Parserの元順序を維持し、URLと公開hashをworker内で再確認する。
	for( const auto &entry : page.entries) {
		collectorParserCheckpoint( control) ;
		// 別分類・未検査URL・不正hash・過大sizeは候補にしない。
		if( entry.category != L"LAN" ||
		   !entry.downloadUrl.starts_with( L"https://dlcdnets.asus.com/pub/ASUS/") ||
		   entry.downloadUrl.find_first_of( L"?#\\") != std::wstring::npos ||
		   !entry.downloadUrl.ends_with( L".zip") || entry.maximumDownloadBytes == 0U ||
		   entry.maximumDownloadBytes > MAXIMUM_BYTES || entry.opaqueId.empty() ||
		   entry.sha256.size() != 64U || !std::ranges::all_of( entry.sha256, []( const wchar_t ch) {
			   return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f') ;
		   })) {
			return false ;
		}

		// Keyと完全URLを一意に保ち、途中の部分集合を返さない。
		if( std::ranges::any_of( pending, [&]( const auto &prior) {
			   collectorParserStep( control) ;
			   return prior.recordKey == request.model + L"|" + entry.opaqueId ||
					  prior.payloads.front().targetUrl.view() == entry.downloadUrl ;
		   })) {
			return false ;
		}

		OfficialCollectorRecordCandidate candidate ;	// 通常evidenceを含まない一時候補。
		fillAsusRecordFields( entry, request, AsusNetworkRecordTarget::CATALOG, pending.size() + 1U,
							 resolvedUtcSeconds, candidate) ;
		pending.push_back( std::move( candidate)) ;
		collectorParserCheckpoint( control) ;
	}

	candidates = std::move( pending) ;
	return true ;
}

/** @see asus_network_record_adapter.h */
NativeError resolveAsusNetworkDistributionRecords(
	const ScanSessionId session, const AsusNetworkRecordTarget target, OfficialHttpClient &client,
	std::vector<OfficialDistributionRecord> &records, AsusNetworkRecordObservation &observation,
	const std::wstring_view category, const std::uint64_t maximumBytes,
	const AsusSupportPageRequest *publicRequest)
{
	records.clear() ;
	observation = {} ;
	// 任意cacheや未定義scopeをnetwork開始前に拒否する。
	if( session == 0U || !knownTarget( target, category, maximumBytes) || client.usesCatalogCache()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	AsusSupportPageRequest request ;		// Serialを含めない現在端末の公式起点。
	bool				   applicable{} ;	// 対応ASUS clientの場合だけtrue。
	NativeError			   error{} ;		// 明示modelまたは現PC識別の先行結果。
	// 明示modelではregistryを読まず、URLも組み込み規則で再構築する。
	if( publicRequest != nullptr) {
		applicable = makeAsusPublicModelSupportPageRequest( publicRequest->model,
														   publicRequest->osName, request) &&
					 request.pageUrl == publicRequest->pageUrl ;
		error = applicable ? 0 : static_cast<NativeError>( E_INVALIDARG) ;
	} else {
		error = readLocalAsusSupportPageRequest( request, applicable) ;
	}

	observation.stage = 1U ;
	// 非ASUSや識別失敗時に架空modelへfallbackしない。
	if( error != 0 || !applicable) {
		return error != 0 ? error
						  : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
	}

	error			  = client.beginSourceSession( session, ASUS_PROVIDER_ID) ;
	observation.stage = 2U ;
	// 根拠session初期化失敗時は取得しない。
	if( error != 0) {
		return error ;
	}

	std::wstring html ;	// Session内だけに保持する公式応答。
	error = client.getUtf8TextForSource( request.pageUrl, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
										8ULL * 1024ULL * 1024ULL, html) ;
	observation.stage = 3U ;
	// HTTP失敗をparserの候補なしへ縮退しない。
	if( error != 0) {
		return error ;
	}

	std::vector<AsusDriverPageEntry> entries ;		// 同じmodel・OSの検証済み配布行。
	const auto evidence = client.sourceEvidence() ;	// 今回のcacheなし応答取得根拠。
	observation.stage	= 4U ;
	// Schema・model・OSの不一致や複数応答の混合を拒否する。
	if( !parseAsusDriverPageHtml(
		   html, request.model, request.osName, entries,
		   target == AsusNetworkRecordTarget::CATALOG
			   ? category
			   : (target == AsusNetworkRecordTarget::MARVELL_LAN ? L"LAN" : L"Wireless"),
		   target == AsusNetworkRecordTarget::CATALOG ? &observation.catalog : nullptr) ||
	   evidence.size() != 1U || evidence.front().scanSessionId != session) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
	}

	observation.entries = entries.size() ;
	observation.stage	= 5U ;
	const auto now		= std::chrono::duration_cast<std::chrono::seconds>(
						  std::chrono::system_clock::now().time_since_epoch())
						 .count() ;	// UTC固定時刻。
	// 時刻と共通record検証が揃う場合だけ秘密URLを後続へ渡す。
	if( now <= 0 || !adaptAsusNetworkDistributionRecords(
					   entries, request, target, evidence.front(), static_cast<std::uint64_t>( now),
					   records, category, maximumBytes, &observation.overBudget)) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
	}

	observation.records = records.size() ;
	observation.stage	= 6U ;
	return 0 ;
}

/** @see asus_network_record_adapter.h */
NativeError resolveAsusNetworkDistributionRecordsForPublicModel(
	const ScanSessionId session, const AsusNetworkRecordTarget target, OfficialHttpClient &client,
	const std::wstring_view publicModel, const std::wstring_view osName,
	std::vector<OfficialDistributionRecord> &records, AsusNetworkRecordObservation &observation,
	const std::wstring_view category, const std::uint64_t maximumBytes)
{
	AsusSupportPageRequest request ;	// URLではなく公開modelから作る正規化済み要求。
	// 明示値が無効な場合はclientを呼ぶ前に拒否する。
	if( !makeAsusPublicModelSupportPageRequest( publicModel, osName, request)) {
		records.clear() ;
		observation = {} ;
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	return resolveAsusNetworkDistributionRecords( session, target, client, records, observation,
												 category, maximumBytes, &request) ;
}

/** @see asus_network_record_adapter.h */
bool adaptAsusCollectorNetworkRecordCandidates(
	const AsusCollectorPageResult &page, const AsusSupportPageRequest &request,
	std::uint64_t resolvedUtcSeconds, std::vector<OfficialCollectorRecordCandidate> &candidates)
{
	return adaptAsusCollectorNetworkRecordCandidatesCore( nullptr, page, request, resolvedUtcSeconds,
														 candidates) ;
}

/** @see asus_network_record_adapter.h */
CollectorParserResult adaptAsusCollectorNetworkRecordCandidatesControlled(
	const AsusCollectorPageResult &page, const AsusSupportPageRequest &request,
	std::uint64_t resolvedUtcSeconds, OfficialCollectorHttpControl &control,
	std::vector<OfficialCollectorRecordCandidate> &candidates)
{
	candidates.clear() ;
	std::vector<OfficialCollectorRecordCandidate> parsed ;	// 途中結果の持出しを防ぐ所有値。
	const auto									  outcome = runCollectorParser(
		   control,
		   [&]( CollectorParserContext &context) {
			   return adaptAsusCollectorNetworkRecordCandidatesCore( &context, page, request,
																									resolvedUtcSeconds, parsed) ;
		   },
		   CollectorIoStage::PROJECT) ;	// 元GETの制御で射影段階を確認します。
	// 終端確認後だけ一括移動します。
	if( outcome.status == CollectorParserStatus::COMPLETED) {
		candidates = std::move( parsed) ;
	}

	return outcome ;
}
} // namespace drivercrate
