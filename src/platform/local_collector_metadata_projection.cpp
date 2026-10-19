//------------------------------------------------------------------------------
/**
 * @file local_collector_metadata_projection.cpp
 * @brief 制御付き公式本文をURL検証後に秘密値なしの全対象射影へ変換します。
 * @version 01.05.01
 * @date 2026/09/28
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  二sourceのURL・通常指紋・全対象edgeを接続。
 * Ver.01.01.00 Shunji Ogawa  2026/09/28  Edgeの元本文・scope契約と公式欠測を保持。
 * Ver.01.02.00 Shunji Ogawa  2026/09/28  二sourceの固定数値診断を公開draftへ保持。
 * Ver.01.03.00 Shunji Ogawa  2026/09/29  Adapter・record・targetとCNGの失敗境界を接続。
 * Ver.01.04.00 Shunji Ogawa  2026/09/29  指紋関係・ordinal解決を本番共通の非所有helperへ抽出。
 * Ver.01.05.00 Shunji Ogawa  2026/09/29  汎用件数guardをworker公開直前へ接続。
 * Ver.01.05.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 通信、取得、controlのfinish、親の受入・保存を行いません。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#include "platform/local_collector_metadata_projection.h"

#include "core/official_source_policy.h"
#include "platform/asus_collector_target_assessment.h"
#include "platform/asus_network_record_adapter.h"
#include "platform/intel_ethernet_windows11_record_adapter.h"

#include <algorithm>
#include <limits>
#include <span>
#include <utility>

namespace drivercrate {
namespace {

/** @brief 数値通知の前後で同じ元期限を検査します。
 * @param[in] diagnostics 秘密値を受け取らない診断依存。
 * @param[in] jobIndex 元job index。
 * @param[in] point 有限の診断位置。
 * @param[in] ordinal 元候補または対象の位置。
 * @param[in,out] control 元GETのPROJECT制御。
 */
void projectionCheckpoint( const CollectorProjectionDiagnostics &diagnostics,
						  const std::size_t jobIndex, const CollectorProjectionPoint point,
						  const std::size_t ordinal, CollectorParserContext &control)
{
	control.checkpoint() ;
	// 未指定時は元checkpointだけで通常の解析を続行します。
	if( diagnostics.checkpoint) {
		diagnostics.checkpoint( jobIndex, point, ordinal) ;
		control.checkpoint() ;
	}
}

/**
 * @brief 公開projectionの同一性をfingerprint以外の全fieldでも確認します。
 * @param[in] a 先行recordの公開射影。同期中だけ借用する。
 * @param[in] b 後続recordの公開射影。同期中だけ借用する。
 * @return Fingerprint以外の全公開fieldとpayload順序が一致する場合true。差がある場合false。
 */
[[nodiscard]] bool samePublicRecord( const OfficialCollectorRecordProjection &a,
									const OfficialCollectorRecordProjection &b)
{
	// 同一fingerprintでも異なる公開fieldを一件へ畳まない。
	if( a.parserId != b.parserId || a.parserRevision != b.parserRevision ||
	   a.recordRoute != b.recordRoute || a.recordKey != b.recordKey ||
	   a.productFamily != b.productFamily || a.driverCategory != b.driverCategory ||
	   a.operatingSystem != b.operatingSystem || a.architecture != b.architecture ||
	   a.packageVersion != b.packageVersion || a.publishedDate != b.publishedDate ||
	   a.terms != b.terms || a.eulaRevision != b.eulaRevision || a.dependencies != b.dependencies ||
	   a.payloads.size() != b.payloads.size()) {
		return false ;
	}

	// 各payloadの公開fieldと元順序を比較します。
	for( std::size_t index = 0U; index < a.payloads.size(); ++index) {
		const auto &left  = a.payloads[index] ;	// 先行recordの同ordinal。
		const auto &right = b.payloads[index] ;	// 新候補の同ordinal。
		// Hash・容量・形式等を一つでも変えた同指紋は衝突として拒否します。
		if( left.resourceId != right.resourceId || left.payloadOrdinal != right.payloadOrdinal ||
		   left.kind != right.kind || left.fileDisplayName != right.fileDisplayName ||
		   left.publishedSizeBytes != right.publishedSizeBytes ||
		   left.publishedSha256 != right.publishedSha256 ||
		   left.publishedSha512 != right.publishedSha512 || left.publisher != right.publisher ||
		   left.expectedContentType != right.expectedContentType) {
			return false ;
		}
	}

	return true ;
}

/**
 * @brief metadata専用にauthority以降の曖昧なURL表記を拒否します。
 * @param[in] url 検査対象URLの元表記。同期中だけ借用し、外部送信しない。
 * @param[in,out] control 同じGETの有限parser制御。走査量と期限を更新・確認する。
 * @return Path、文字、segmentの全表記条件を満たす場合true。不正表記はfalse。
 */
[[nodiscard]] bool safeCollectorUrlShape( const std::wstring_view url,
										 CollectorParserContext &control)
{
	const auto pathStart = url.find( L'/', std::wstring_view( L"https://").size()) ;	// Authority終端。
	// Pathのない配布URLを受理しません。
	if( pathStart == url.npos || pathStart + 1U >= url.size()) {
		return false ;
	}

	// URL全体でquery・fragment・backslash・percentを拒否し、UTF-16も確認します。
	for( std::size_t index = 0U; index < url.size(); ++index) {
		control.step() ;
		const wchar_t ch = url[index] ;	// 現在のUTF-16 code unit。
		// 曖昧なdecodeと制御文字は同じmetadata経路で許さない。
		if( ch <= L' ' || (ch >= L'\x7f' && ch <= L'\x9f') || ch == L'?' || ch == L'#' ||
		   ch == L'\\' || ch == L'%') {
			return false ;
		}

		// UTF-16 surrogateは正しい上位・下位の対だけ受理します。
		if( ch >= 0xD800 && ch <= 0xDBFF) {
			// 上位surrogateに対応する下位が直後に存在しなければ拒否します。
			if( index + 1U >= url.size() || url[index + 1U] < 0xDC00 || url[index + 1U] > 0xDFFF) {
				return false ;
			}

			++index ;
		} else {
			// 単独の下位surrogateも不正です。
			if( ch >= 0xDC00 && ch <= 0xDFFF) {
				return false ;
			}
		}
	}

	const auto path = url.substr( pathStart) ;	// Authorityの後の元表記。
	// 先頭一つを除く空segmentやdot segmentを拒否します。
	if( path.find( L"//") != path.npos || path.back() == L'/') {
		return false ;
	}

	std::size_t start = 1U ;	// 最初のslash直後から検査します。
	// 全segmentを元の表記のまま検査し、decodeや正規化はしません。
	while( start < path.size()) {
		control.step() ;
		const auto end = path.find( L'/', start) ;	// 現segmentの終端。
		const auto segment =
			// 元表記の要素。
			path.substr( start, end == path.npos ? path.npos : end - start) ;
		// 相対pathへの変換余地を残しません。
		if( segment.empty() || segment == L"." || segment == L"..") {
			return false ;
		}

		// 最終segmentまで検査したら終了します。
		if( end == path.npos) {
			break ;
		}

		start = end + 1U ;
	}

	return true ;
}

/**
 * @brief 元候補をpayload用途の組み込みhostとsourceの公開行へ再結合します。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] candidate 元pageから得た配布候補。同期中だけ借用する。
 * @param[in] payload 同じ候補の元payload条件とURL。
 * @param[in] asusEntry ASUSでは同じpageの非null行。Intelではnull。同期中だけ借用する。
 * @param[in,out] control 同じGETの有限parser制御。
 * @return 組み込みpayload用途、公式URL表記、元行の全結合条件を満たす場合true。違反時はfalse。
 */
[[nodiscard]] bool validateCollectorPayload( const CollectorProjectedJobInput		&job,
											const OfficialCollectorRecordCandidate	&candidate,
											const OfficialDistributionPayloadRecord &payload,
											const AsusDriverPageEntry				*asusEntry,
											CollectorParserContext					&control)
{
	const auto *policy = officialSourcePolicyForProvider( job.providerId) ;	// 組み込みsource。
	const auto *resource =
		policy == nullptr
			? nullptr
			: findOfficialSourceResource( *policy, payload.resourceId) ;	// payload用途。
	const auto url = payload.targetUrl.view() ;								// worker内限定の秘密URL借用。
	// Landing hostや保存文字列をpayload許可へ流用しません。
	if( policy == nullptr || policy->id != job.policyId || resource == nullptr ||
	   resource->kind != OfficialSourceResourceKind::PAYLOAD ||
	   validateOfficialHttpsUrl( url, resource->allowedHosts) != 0 ||
	   !safeCollectorUrlShape( url, control)) {
		return false ;
	}

	const auto slash = url.find_last_of( L'/') ;	// 公開basenameの境界。
	// 表示basenameはURLの元表記と完全一致させます。
	if( slash == url.npos || payload.fileDisplayName != url.substr( slash + 1U) ||
	   payload.payloadOrdinal != 0U ||
	   payload.kind != OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE) {
		return false ;
	}

	// 初期ASUS LANだけを元page entryの全重要fieldへ結合します。
	if( job.source.sourceId == L"ASUS_CATALOG") {
		return asusEntry != nullptr && url.starts_with( L"https://dlcdnets.asus.com/pub/ASUS/") &&
			   url.ends_with( L".zip") && url == asusEntry->downloadUrl &&
			   payload.publishedSha256 == asusEntry->sha256 &&
			   payload.maximumBytes == asusEntry->maximumDownloadBytes &&
			   candidate.recordKey == job.publicLocator + L"|" + asusEntry->opaqueId &&
			   candidate.driverCategory == asusEntry->category &&
			   candidate.productFamily == asusEntry->title &&
			   candidate.operatingSystem == job.slices.front().operatingSystem ;
	}

	// Intelはhero／descriptionを同本文で照合した候補の元file名を厳密に維持します。
	if( job.source.sourceId == L"INTEL_ETHERNET_WINDOWS11") {
		return asusEntry == nullptr && url.starts_with( L"https://downloadmirror.intel.com/") &&
			   payload.fileDisplayName ==
				   L"Wired_driver_" + candidate.packageVersion + L"_x64.zip" &&
			   candidate.driverCategory.empty() && candidate.recordEvidenceId == 1U ;
	}

	return false ;
}

/**
 * @brief URL検証済み候補だけを通常canonicalと同じrecord射影へ渡します。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] candidate 一payloadの元候補。同期中だけ借用する。
 * @param[in] asusEntry ASUSの元行。Intelではnull。同期中だけ借用する。
 * @param[in] validatedUtcSeconds 元page検証完了のUnix epoch秒。
 * @param[in,out] control 同じGETのPROJECT制御。Hash等の原障害はこの制御へ伝える。
 * @param[in,out] draft 検査済み公開recordの追加先。例外時は途中状態を保持する。
 * @param[in,out] ordinalToRecord 元候補ordinalからdraft record位置への対応表。
 * @param[in] diagnostics 数値診断だけを受ける同期callback群。
 * @param[in] recordOrdinal 元候補列の0始まり位置。
 * @return 検査済みrecordを追加または同値の既存recordへ結べた場合true。構造拒否・衝突時はfalse。
 */
[[nodiscard]] bool appendCollectorRecord(
	const CollectorProjectedJobInput &job, const OfficialCollectorRecordCandidate &candidate,
	const AsusDriverPageEntry *asusEntry, const std::uint64_t validatedUtcSeconds,
	CollectorParserContext &control, CollectorMetadataProjectionDraft &draft,
	std::vector<std::size_t> &ordinalToRecord, const CollectorProjectionDiagnostics &diagnostics,
	const std::size_t recordOrdinal)
{
	control.checkpoint() ;
	// 現二sourceはいずれも一ZIPだけを一recordに持ちます。
	if( candidate.payloads.size() != 1U ||
	   !validateCollectorPayload( job, candidate, candidate.payloads.front(), asusEntry, control)) {
		return false ;
	}

	OfficialCollectorHashProbe probe ;	// 元CNG失敗値だけを受ける同期依存。
	// 成功digestや候補を外へ渡さず、呼出位置だけを対応させます。
	if( diagnostics.beforeRecordHash) {
		probe = [&] { return diagnostics.beforeRecordHash( job.jobIndex, recordOrdinal) ; } ;
	}

	OfficialCollectorRecordProjection projected ;	// URL非保持の通常canonical結果。
	const NativeError				  error = projectOfficialCollectorRecordWithHashProbe(
		candidate, job.policyId, job.source.resourceId, validatedUtcSeconds, projected,
		probe) ;	// 共通検証結果。
	// 共通field拒否とCNG／OOM失敗を区別し、別canonicalへ再試行しません。
	if( error == static_cast<NativeError>( E_INVALIDARG)) {
		return false ;
	}

	// 共通hash等の実障害は構造拒否ではなく元HRESULTの失敗です。
	if( error != 0) {
		control.failed( CollectorIoErrorDomain::HRESULT_ERROR, static_cast<std::uint32_t>( error)) ;
	}

	// 同指紋は同じ公開record／sliceの場合だけ折り畳みます。
	for( std::size_t index = 0U; index < draft.records.size(); ++index) {
		control.step() ;
		const auto &prior	 = draft.records[index] ;	// 既にURL検証済みの公開record。
		const auto	relation = collector_projection_detail::compareRecords(
			 prior.value, prior.sliceKey, projected, job.slices.front().key) ;	// 実CNG後だけの関係。
		// 指紋が異なれば元ordinalを別recordへ対応させます。
		if( relation == collector_projection_detail::RecordRelation::DISTINCT) {
			continue ;
		}

		// 指紋衝突で公開値が異なる場合は一recordへ畳みません。
		if( relation == collector_projection_detail::RecordRelation::CONFLICT) {
			return false ;
		}

		ordinalToRecord.push_back( index) ;
		return true ;
	}

	CollectorProjectedRecord record ;	// 一候補を所有する新公開record。
	record.value	= std::move( projected) ;
	record.sliceKey = job.slices.front().key ;
	// Source規則と共通hostの検査を終えたpayloadだけ観測をtrueにします。
	for( const auto &payload : record.value.payloads) {
		control.step() ;
		record.payloads.push_back( {payload, true}) ;
	}

	ordinalToRecord.push_back( draft.records.size()) ;
	draft.records.push_back( std::move( record)) ;
	control.checkpoint() ;
	return true ;
}

/**
 * @brief 候補ordinalを検証済みfingerprintへ変換し一edgeへ加えます。
 * @param[in] ordinal 元候補列の0始まり位置。
 * @param[in] ordinalToRecord 検査済みrecordへの対応表。同期中だけ借用する。
 * @param[in] records 対応先の検査済みrecord集合。同期中だけ借用する。
 * @param[in,out] edge 対応するfingerprintの追加先。拒否前に追加した値は保持する。
 * @return 有効な対応先を確認してedgeへ結べた場合true。対応先不正時はfalse。
 */
[[nodiscard]] bool appendEdgeFingerprint( const std::uint32_t			 ordinal,
										 const std::vector<std::size_t> &ordinalToRecord,
										 const std::vector<CollectorProjectedRecord> &records,
										 CollectorProjectedEdge						 &edge)
{
	// 欠測・範囲外参照を成功edgeに変換しません。
	const auto recordIndex = collector_projection_detail::resolveOrdinal(
		ordinal, ordinalToRecord, records.size()) ;	// 範囲外はnull。
	// 不正な元ordinalから仮のrecord参照を発行しません。
	if( !recordIndex) {
		return false ;
	}

	const auto fingerprint = records[*recordIndex].value.stableFingerprint ;	// 検証済み参照。
	// 同じ指紋の複数ordinalでもedge側は一参照だけ保持します。
	if( std::ranges::none_of( edge.recordFingerprints,
							[&]( const auto &prior) { return prior.bytes == fingerprint.bytes ; })) {
		edge.recordFingerprints.push_back( fingerprint) ;
	}

	return true ;
}

/**
 * @brief ASUSの同一store候補と全公開対象を元順序で射影します。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] html 同一GETからdecodeした有限HTML。同期中だけ借用する。
 * @param[in] validatedUtcSeconds 元本文検証完了のUnix epoch秒。
 * @param[in,out] httpControl 同じGETのHTTP観測とPROJECT制御。
 * @param[in,out] control 元予算と期限を継承するparser制御。
 * @param[in,out] draft 公開recordと元順の対象edgeの追加先。拒否時は途中状態を保持する。
 * @param[in] diagnostics 数値だけを扱う同期診断callback群。
 * @return 元本文を解析して許可された公開scopeへ射影できた場合true。構造・対応不成立時はfalse。
 */
[[nodiscard]] bool projectAsus( const CollectorProjectedJobInput &job, const std::wstring_view html,
							   const std::uint64_t					 validatedUtcSeconds,
							   OfficialCollectorHttpControl			&httpControl,
							   CollectorParserContext				&control,
							   CollectorMetadataProjectionDraft		&draft,
							   const CollectorProjectionDiagnostics &diagnostics)
{
	AsusSupportPageRequest request ;	// 元公開modelから再構築する固定公式page。
	// 元公開modelと明示OSから同じ固定公式pageを再構築します。
	if( !makeAsusPublicModelSupportPageRequest( job.publicLocator, job.slices.front().operatingSystem,
											  request)) {
		return false ;
	}

	AsusCollectorPageResult page ;	// 同一Nuxt storeの所有結果。
	auto					parsed = parseAsusCollectorDriverPageHtmlControlled(
		   html, request.model, request.osName, job.slices.front().category,
		   128ULL * 1024ULL * 1024ULL, httpControl, page) ;	// 型付きparser終了。
	// 下位parserの停止・上限・障害を候補なしへ変換しません。
	if( parsed.status != CollectorParserStatus::COMPLETED) {
		throw CollectorParserFailure{parsed} ;
	}

	// 全体schema拒否からHELDを作りません。
	if( page.sliceStatus == AsusCollectorSliceStatus::SCHEMA_REJECTED) {
		return false ;
	}

	// 明示record上限だけは構造拒否と独立に分類します。
	if( page.sliceStatus == AsusCollectorSliceStatus::RECORD_LIMIT) {
		collectorParserLimit( &control) ;
	}

	draft.sourceStatus = static_cast<std::uint32_t>( page.sliceStatus) ;
	draft.sourceSeen   = static_cast<std::uint32_t>( page.seen) ;
	draft.complete	   = page.sliceStatus == AsusCollectorSliceStatus::ACCEPTED ;
	// 部分拒否の理由内訳を本文や行そのものなしで所有します。
	for( std::size_t index = 0U; index < draft.sourceReasonCounts.size(); ++index) {
		control.step() ;
		draft.sourceReasonCounts[index] = static_cast<std::uint32_t>( page.reasonCounts[index]) ;
	}

	std::vector<OfficialCollectorRecordCandidate> candidates ;	// worker内限定の秘密URL集合。
	// 採用行があるときだけ候補化し、正当な空pageは全対象照合へ進めます。
	if( page.sliceStatus == AsusCollectorSliceStatus::ACCEPTED ||
	   page.sliceStatus == AsusCollectorSliceStatus::PARTIAL_REJECTED) {
		parsed = adaptAsusCollectorNetworkRecordCandidatesControlled(
			page, request, validatedUtcSeconds, httpControl, candidates) ;
		// 下位adapterの失敗を空候補に読み替えません。
		if( parsed.status != CollectorParserStatus::COMPLETED) {
			throw CollectorParserFailure{parsed} ;
		}
	}

	projectionCheckpoint( diagnostics, job.jobIndex, CollectorProjectionPoint::ADAPTER_COMPLETE, 0U,
						 control) ;
	std::vector<AsusCollectorTargetQuery> queries ;	// 元対象全件の借用query。
	queries.reserve( job.targets.size()) ;
	// 候補の重複排除より先に元の全対象を作ります。
	for( const auto &scope : job.targets) {
		control.checkpoint() ;
		queries.push_back( {scope.target.id, scope.target.maker, scope.target.model,
						   scope.target.kind, scope.target.purpose, scope.operatingSystem,
						   scope.architecture, scope.chip}) ;
	}

	std::vector<AsusCollectorTargetAssessment> assessed ;	// Dedup前のordinal照合結果。
	parsed =
		inspectAsusCollectorTargetsControlled( page, candidates, queries, httpControl, assessed) ;
	// 元ordinalを持つ全対象の照合失敗を伝播します。
	if( parsed.status != CollectorParserStatus::COMPLETED) {
		throw CollectorParserFailure{parsed} ;
	}

	// 親へ欠けた対象行を成功として渡しません。
	if( assessed.size() != job.targets.size()) {
		return false ;
	}

	std::vector<std::size_t> ordinalToRecord ;	// 元entry順からdedup後recordへの対応。
	ordinalToRecord.reserve( candidates.size()) ;
	// 元entryのordinalを指紋へ置換する前に各URLを再検証します。
	for( std::size_t index = 0U; index < candidates.size(); ++index) {
		projectionCheckpoint( diagnostics, job.jobIndex, CollectorProjectionPoint::RECORD, index,
							 control) ;
		// 元entryへの一対一帰属かURL再検査が崩れたら全体拒否します。
		if( index >= page.entries.size() || candidates[index].recordEvidenceId != index + 1U ||
		   !appendCollectorRecord( job, candidates[index], &page.entries[index], validatedUtcSeconds,
								  control, draft, ordinalToRecord, diagnostics, index)) {
			return false ;
		}
	}

	// 全対象・一sliceを元順序で残し、候補なしもUNKNOWN／理由を保持します。
	for( std::size_t index = 0U; index < assessed.size(); ++index) {
		projectionCheckpoint( diagnostics, job.jobIndex, CollectorProjectionPoint::TARGET, index,
							 control) ;
		const auto &source = assessed[index] ;	// 元targetと同じ位置のsource判定。
		// 並べ替えで別製品の結果を流用しません。
		if( source.targetKey != job.targets[index].target.id) {
			return false ;
		}

		CollectorProjectedEdge edge ;	// 元一対象と一sliceの所有行。
		edge.target			= job.targets[index] ;
		edge.sliceKey		= job.slices.front().key ;
		edge.bodySha256		= draft.bodySha256 ;
		edge.recordParser	= job.recordParser ;
		edge.identityParser = job.identityParser ;
		edge.matchingRule	= job.matchingRule ;
		edge.state			= source.state == AsusCollectorTargetState::MATCH
								  ? CollectorProjectedTargetState::MATCH
							  : source.state == AsusCollectorTargetState::NO_MATCH
								  ? CollectorProjectedTargetState::NO_MATCH
								  : CollectorProjectedTargetState::UNKNOWN ;
		edge.reasonCode		= static_cast<std::uint32_t>( source.reason) ;
		// 公式identityの欠測を公開query名で埋めません。
		if( !source.productId.empty()) {
			edge.sourceProductId = source.productId ;
		}

		// 元page表示名がある場合だけ所有します。
		if( !source.displayModel.empty()) {
			edge.sourceDisplayName = source.displayModel ;
		}

		// 元page比較名がある場合だけ所有します。
		if( !source.comparisonModel.empty()) {
			edge.sourceComparisonName = source.comparisonModel ;
		}

		// NO_MATCH／UNKNOWNでも本文に帰属する検証済み参照は残します。
		for( const auto ordinal : source.candidateOrdinals) {
			control.step() ;
			// 存在しないordinalを無視せず全体失敗へ伝えます。
			if( !appendEdgeFingerprint( ordinal, ordinalToRecord, draft.records, edge)) {
				return false ;
			}
		}

		draft.edges.push_back( std::move( edge)) ;
	}

	return true ;
}

/**
 * @brief Intelの一候補を全対象へ共有して元順序のedgeへ射影します。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] html 同一GETからdecodeした有限HTML。同期中だけ借用する。
 * @param[in] validatedUtcSeconds 元本文検証完了のUnix epoch秒。
 * @param[in,out] httpControl 同じGETのHTTP観測とPROJECT制御。
 * @param[in,out] control 元予算と期限を継承するparser制御。
 * @param[in,out] draft 公開recordと元順の対象edgeの追加先。拒否時は途中状態を保持する。
 * @param[in] diagnostics 数値だけを扱う同期診断callback群。
 * @return 元本文を解析して許可された公開scopeへ射影できた場合true。構造・対応不成立時はfalse。
 */
[[nodiscard]] bool projectIntel( const CollectorProjectedJobInput &job, const std::wstring_view html,
								const std::uint64_t					  validatedUtcSeconds,
								OfficialCollectorHttpControl		 &httpControl,
								CollectorParserContext				 &control,
								CollectorMetadataProjectionDraft	 &draft,
								const CollectorProjectionDiagnostics &diagnostics)
{
	std::vector<IntelCollectorTargetQuery> queries ;	// 同一GETの全公開対象。
	queries.reserve( job.targets.size()) ;
	// 公開targetを一件も省かず同じ本文のidentity照合へ渡します。
	for( const auto &scope : job.targets) {
		control.checkpoint() ;
		queries.push_back( {scope.target.id, scope.target.maker, scope.target.model,
						   scope.target.kind, scope.target.purpose, scope.operatingSystem,
						   scope.architecture, scope.chip}) ;
	}

	IntelCollectorMetadataAssessment assessed ;	// 配布と一覧を同一HTMLで照合した案。
	const auto						 parsed = inspectIntelCollectorMetadataPageControlled(
		  html, queries, validatedUtcSeconds, httpControl, assessed) ;	// 型付き終了。
	// 下位の停止・OOM・上限を保持します。
	if( parsed.status != CollectorParserStatus::COMPLETED) {
		throw CollectorParserFailure{parsed} ;
	}

	// 全体の構造拒否・上限だけを候補欠測と分けます。
	if( assessed.identity.status == IntelCollectorIdentityStatus::SCHEMA_REJECTED) {
		return false ;
	}

	// 明示上限は一覧欠測と区別します。
	if( assessed.identity.status == IntelCollectorIdentityStatus::LIMIT_EXCEEDED) {
		collectorParserLimit( &control) ;
	}

	// 26対象の部分結果を成功へしません。
	if( assessed.targets.size() != job.targets.size()) {
		return false ;
	}

	projectionCheckpoint( diagnostics, job.jobIndex, CollectorProjectionPoint::ADAPTER_COMPLETE, 0U,
						 control) ;
	draft.sourceStatus	   = static_cast<std::uint32_t>( assessed.identity.status) ;
	draft.sourceSeen	   = static_cast<std::uint32_t>( assessed.identity.seen) ;
	draft.sourceDuplicates = static_cast<std::uint32_t>( assessed.identity.duplicates) ;
	draft.sourceRejected   = static_cast<std::uint32_t>( assessed.identity.rejected) ;
	draft.sourceCollisions = static_cast<std::uint32_t>( assessed.identity.collisions) ;
	draft.complete		   = assessed.releaseParsed &&
					 assessed.identity.status == IntelCollectorIdentityStatus::ACCEPTED ;
	std::vector<std::size_t> ordinalToRecord ;	// 共有ordinal 0のrecord参照。
	// Hero・一覧が成立した場合だけ同一本文の候補を検証します。
	if( assessed.candidate) {
		projectionCheckpoint( diagnostics, job.jobIndex, CollectorProjectionPoint::RECORD, 0U,
							 control) ;
		// Heroに帰属したURLだけを検査・射影します。
		if( !appendCollectorRecord( job, *assessed.candidate, nullptr, validatedUtcSeconds, control,
								  draft, ordinalToRecord, diagnostics, 0U)) {
			return false ;
		}
	}

	// Intel一recordのordinal 0を全対象で共有し、対象数に応じてrecordを増やしません。
	for( std::size_t index = 0U; index < assessed.targets.size(); ++index) {
		projectionCheckpoint( diagnostics, job.jobIndex, CollectorProjectionPoint::TARGET, index,
							 control) ;
		const auto &source = assessed.targets[index] ;	// 元公開targetの同位置判定。
		// 別製品へのedge付替えを拒否します。
		if( source.targetKey != job.targets[index].target.id) {
			return false ;
		}

		CollectorProjectedEdge edge ;	// 共有recordへの一対象参照。
		edge.target			= job.targets[index] ;
		edge.sliceKey		= job.slices.front().key ;
		edge.bodySha256		= draft.bodySha256 ;
		edge.recordParser	= job.recordParser ;
		edge.identityParser = job.identityParser ;
		edge.matchingRule	= job.matchingRule ;
		edge.state			= source.state == IntelCollectorTargetState::MATCH
								  ? CollectorProjectedTargetState::MATCH
							  : source.state == IntelCollectorTargetState::NO_MATCH
								  ? CollectorProjectedTargetState::NO_MATCH
								  : CollectorProjectedTargetState::UNKNOWN ;
		edge.reasonCode		= static_cast<std::uint32_t>( source.reason) ;
		// 公式一覧の欠測SKUを元query名から合成しません。
		if( !source.sku.empty()) {
			edge.sourceProductId = source.sku ;
		}

		// 公式表示名が実際にある場合だけ所有します。
		if( !source.displayName.empty()) {
			edge.sourceDisplayName = source.displayName ;
		}

		// 公式比較名が実際にある場合だけ所有します。
		if( !source.comparisonName.empty()) {
			edge.sourceComparisonName = source.comparisonName ;
		}

		// 欠測と範囲外ordinalを区別します。
		if( source.candidateOrdinal &&
		   !appendEdgeFingerprint( *source.candidateOrdinal, ordinalToRecord, draft.records, edge)) {
			return false ;
		}

		draft.edges.push_back( std::move( edge)) ;
	}

	return true ;
}

} // namespace

/** @see local_collector_metadata_projection.h */
collector_projection_detail::RecordRelation collector_projection_detail::compareRecords(
	const OfficialCollectorRecordProjection &prior, const std::wstring_view priorSlice,
	const OfficialCollectorRecordProjection &incoming,
	const std::wstring_view					 incomingSlice) noexcept
{
	// 指紋の異なるrecordを公開fieldだけで折り畳みません。
	if( prior.stableFingerprint.bytes != incoming.stableFingerprint.bytes) {
		return RecordRelation::DISTINCT ;
	}

	// 同じ指紋だけを根拠に別公開値・別sliceを採用しません。
	return priorSlice == incomingSlice && samePublicRecord( prior, incoming)
			   ? RecordRelation::EQUIVALENT
			   : RecordRelation::CONFLICT ;
}

/** @see local_collector_metadata_projection.h */
std::optional<std::size_t> collector_projection_detail::resolveOrdinal(
	const std::uint32_t ordinal, const std::span<const std::size_t> ordinalToRecord,
	const std::size_t recordCount) noexcept
{
	// Ordinalと折畳み後indexの双方を検査し、先頭recordへ補完しません。
	if( ordinal >= ordinalToRecord.size() || ordinalToRecord[ordinal] >= recordCount) {
		return std::nullopt ;
	}

	return ordinalToRecord[ordinal] ;
}

/** @see local_collector_metadata_projection.h */
bool collector_projection_detail::withinCountLimits( const std::size_t records,
													const std::size_t payloads,
													const std::size_t slices,
													const std::size_t edges,
													const std::size_t references) noexcept
{
	return records <= 16U && payloads <= 32U && slices <= 16U && edges <= 3'000U &&
		   references <= 16U ;
}

/** @see local_collector_metadata_projection.h */
collector_projection_detail::CountResult collector_projection_detail::checkCounts(
	const std::span<const CollectorProjectedRecord>		records,
	const std::span<const CollectorProjectedSliceScope> slices,
	const std::span<const CollectorProjectedEdge>		edges) noexcept
{
	// 配列長を先に拒否し、過大入力を全走査してから切り捨てません。
	if( !withinCountLimits( records.size(), 0U, slices.size(), edges.size(), 0U)) {
		return CountResult::LIMIT_EXCEEDED ;
	}

	std::size_t totalPayloads{} ;	// 上限32から差し引いて加算overflowを避ける。
	// 本番workerと将来のv4 readerが実配列だけから合計を導く。
	for( const auto &record : records) {
		// 公開payloadと検証観測payloadの異なる件数を上限失敗へ隠しません。
		if( record.value.payloads.size() != record.payloads.size()) {
			return CountResult::INVALID_SHAPE ;
		}

		// 上限を超える足し算を実行せず、途中までの集合を成功扱いしません。
		if( record.value.payloads.size() > 32U - totalPayloads) {
			return CountResult::LIMIT_EXCEEDED ;
		}

		totalPayloads += record.value.payloads.size() ;
	}

	// 一edgeの参照件数は総edge件数と独立に有限化する。
	for( const auto &edge : edges) {
		// 参照配列を切り詰めて成功edgeへしません。
		if( !withinCountLimits( records.size(), totalPayloads, slices.size(), edges.size(),
							  edge.recordFingerprints.size())) {
			return CountResult::LIMIT_EXCEEDED ;
		}
	}

	return CountResult::WITHIN_LIMIT ;
}

/** @see local_collector_metadata_projection.h */
CollectorParserResult projectCollectorMetadataBody(
	CollectorMetadataBody body, const CollectorPreparedProjectedCampaign &campaign,
	const std::size_t jobIndex, CollectorMetadataProjectionDraft &projection) noexcept
{
	return projectCollectorMetadataBodyWithDiagnostics( std::move( body), campaign, jobIndex,
													   projection, {}) ;
}

/** @see local_collector_metadata_projection.h */
CollectorParserResult projectCollectorMetadataBodyWithDiagnostics(
	CollectorMetadataBody body, const CollectorPreparedProjectedCampaign &campaign,
	const std::size_t jobIndex, CollectorMetadataProjectionDraft &projection,
	const CollectorProjectionDiagnostics &diagnostics) noexcept
{
	projection = {} ;
	std::shared_ptr<CollectorHttpControl> ownedControl ;	// 元GETと同じ所有制御。
	// 本文の一回消費と元prepared jobの再結合を必須にします。
	if( !body.consumeForProjection( campaign, jobIndex, ownedControl)) {
		return {CollectorParserStatus::REJECTED,
				{CollectorIoErrorDomain::PARSER, 1U, CollectorIoStage::PROJECT}} ;
	}

	const auto *prepared = campaign.job( jobIndex) ;	// 元canonicalから再構築したjob。
	// 消費後のjobは同じcampaignからだけ借用します。
	if( prepared == nullptr || ownedControl == nullptr) {
		return {CollectorParserStatus::REJECTED,
				{CollectorIoErrorDomain::PARSER, 1U, CollectorIoStage::PROJECT}} ;
	}

	const auto result = runCollectorParser(
		*ownedControl,
		[&]( CollectorParserContext &control) {
			const auto &job = prepared->value() ;
			// 初期profileの一slice／有限全targetと検証時刻だけを受理します。
			if( job.slices.size() != 1U || job.targets.empty() || job.targets.size() > 300U ||
			   body.validatedUtcMillis() / 1'000U == 0U || body.scopeSha256() != job.scopeSha256 ||
			   body.policyId() != job.policyId) {
				return false ;
			}

			CollectorMetadataProjectionDraft draft ;
			draft.bodySha256		 = body.bodySha256() ;
			draft.sourceId			 = job.source.sourceId ;
			draft.providerId		 = job.providerId ;
			draft.policyId			 = job.policyId ;
			draft.resourceId		 = job.source.resourceId ;
			draft.scopeSha256		 = job.scopeSha256 ;
			draft.cacheBinding		 = job.cacheBinding ;
			draft.validatedUtcMillis = body.validatedUtcMillis() ;
			draft.slices			 = job.slices ;
			const auto seconds		 = body.validatedUtcMillis() / 1'000U ;
			bool	   accepted{} ;
			// Source labelをpolicy IDへcastせず、準備済み二sourceだけを分岐します。
			if( job.source.sourceId == L"ASUS_CATALOG") {
				accepted = projectAsus( job, body.text(), seconds, *ownedControl, control, draft,
									   diagnostics) ;
			}

			// 固定Intel公開pageだけを別のsourceとして扱います。
			if( job.source.sourceId == L"INTEL_ETHERNET_WINDOWS11") {
				accepted = projectIntel( job, body.text(), seconds, *ownedControl, control, draft,
										diagnostics) ;
			}

			// 不成立や途中停止時は公開resultへ部分配列を移しません。
			if( !accepted || draft.edges.size() != job.targets.size()) {
				return false ;
			}

			const auto countResult = collector_projection_detail::checkCounts(
				draft.records, draft.slices, draft.edges) ;	// 公開直前の実配列。
			// 明示上限は不正構造や正当な候補なしと別の分類を保持します。
			if( countResult == collector_projection_detail::CountResult::LIMIT_EXCEEDED) {
				collectorParserLimit( &control) ;
			}

			// 二つのpayload配列の長さが異なる場合は成功draftを公開しません。
			if( countResult == collector_projection_detail::CountResult::INVALID_SHAPE) {
				return false ;
			}

			const bool anyMatch = std::ranges::any_of( draft.edges, []( const auto &edge) {
				return edge.state == CollectorProjectedTargetState::MATCH ;
			}) ;
			draft.status		= anyMatch && !draft.records.empty()
									  ? CollectorProjectionDraftStatus::FETCHED
									  : CollectorProjectionDraftStatus::HELD ;
			control.checkpoint() ;
			projection = std::move( draft) ;
			return true ;
		},
		CollectorIoStage::PROJECT) ;
	// 停止や第一失敗が最終checkpointで先着したら成功配列を全破棄します。
	if( result.status != CollectorParserStatus::COMPLETED) {
		projection = {} ;
	}

	return result ;
}

} // namespace drivercrate
