//------------------------------------------------------------------------------
/**
 * @file scan_measurement.cpp
 * @brief 同一scanの段階別device集合と計測確定度の純粋集計。
 * @version 01.02.01
 * @date 2026/09/10
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  集合の包含関係と候補監査に基づく計測を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  公式HTTP取得根拠の要約と検証を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  公開snapshotのoperation・件数検証を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  有界列挙の終端・一回probe分類を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  全代表行の観測結合を計測母数と同期。
 * Ver.01.01.01 Shunji Ogawa  2026/09/15  自動探索capabilityを既知bitとして受理。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.02.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 入力へのviewは呼出し内だけで借用します。Network、OS API、導入処理を呼びません。
 * @see docs/adr/0139-local-scan-measurement-contract.md
 */
//------------------------------------------------------------------------------

#include "core/scan_measurement.h"

#include "core/candidate_audit.h"
#include "core/candidate_selection.h"
#include "core/local_coverage.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {

/**
 * @brief 観測集合に含まれるdevice識別子の非所有viewを重複排除する。参照元は集合の利用中保持する。
 */
using DeviceSet					  = std::set<std::wstring_view> ;
constexpr std::size_t STAGE_COUNT = 5 ;	// T、Q、R、A、Iの順を固定した内部配列長。
constexpr std::size_t ELIGIBLE	  = 0 ;	// 探索対象集合の配列位置。
constexpr std::size_t QUERY		  = 1 ;	// 個別検索完了集合の配列位置。
constexpr std::size_t INFORMATION = 2 ;	// 情報到達集合の配列位置。
constexpr std::size_t APPLICABLE  = 3 ;	// 適用可能通常更新集合の配列位置。
constexpr std::size_t READY		  = 4 ;	// READY通常更新集合の配列位置。

/** @brief 一Provider分の借用集合と集計途中の状態である。 */
struct ProviderState {
	/// 呼出し中に有効なregistry要素への非所有参照。
	const ProviderDescriptor				  *descriptor{} ;
	/// 固定済み設定で有効な場合だけtrue。
	bool									   enabled{} ;
	/// 管理serviceまたは公式networkだけがtrue。
	bool									   network{} ;
	/// Windows管理serviceの場合だけtrue。
	bool									   managed{} ;
	/// UIへは渡さない段階別opaque集合。
	std::array<DeviceSet, STAGE_COUNT>		   sets ;
	/// 各集合の観測確定度。
	std::array<MeasurementExtent, STAGE_COUNT> extents{} ;
	/// Identityを持たない確定途中の集計。
	ProviderMeasurement						   output ;
	/// 非現在版の未照合候補行数。
	std::uint64_t							   unmatched{} ;
	/// 識別済みrecordの明示結合先。完全申告の最終照合に使う。
	DeviceSet								   recordDevices ;
} ;

/**
 * @brief 定義外の確定度を集合処理へ入れない。
 * @param[in] extent 検査する値。
 * @return 既知の確定度の場合はtrue。
 */
bool knownExtent( const MeasurementExtent extent) noexcept
{
	return extent == MeasurementExtent::NOT_MEASURED || extent == MeasurementExtent::EXACT ||
		   extent == MeasurementExtent::LOWER_BOUND || extent == MeasurementExtent::UNAVAILABLE ;
}

/**
 * @brief 件数を持つ確定度か判定する。
 * @param[in] extent 既知の確定度。
 * @return 確認済み集合を数えられる場合はtrue。
 */
bool hasCount( const MeasurementExtent extent) noexcept
{
	return extent == MeasurementExtent::EXACT || extent == MeasurementExtent::LOWER_BOUND ;
}

/**
 * @brief 計測値の数値有無を確定度に対応付ける。
 * @param[in] count 確認済み集合の大きさ。
 * @param[in] extent 既知の確定度。
 * @return 値を持てない確定度ではnulloptを保持する件数。
 */
CountMeasurement makeCount( const std::uint64_t count, const MeasurementExtent extent)
{
	return {hasCount( extent) ? std::optional<std::uint64_t>{count} : std::nullopt, extent} ;
}

/**
 * @brief 根拠集合が母数内で一意か検査して借用集合へ変換する。
 * @param[in] source Workerの段階別観測値。
 * @param[in] devices 今回のlocal現在版の母数。
 * @param[out] destination 成功時の集合。失敗時は呼出し側が作業結果全体を破棄する。
 * @return 確定度、上限、identityが整合する場合はtrue。
 */
bool loadSet( const MeasurementDeviceSet &source, const DeviceSet &devices, DeviceSet &destination)
{
	// 未計測・不明の値に隠れた集合や過大な入力を受理しない。
	if( !knownExtent( source.extent) || source.identities.size() > MEASUREMENT_DEVICE_LIMIT ||
	   (!hasCount( source.extent) && !source.identities.empty())) {
		return false ;
	}

	// 現在版の一意identityだけを取り込み、重複申告を集計で隠さない。
	for( const std::wstring &identity : source.identities) {
		// 母数にないdeviceを外部metadataから増やさない。
		if( !devices.contains( identity) || !destination.insert( identity).second) {
			return false ;
		}
	}

	return true ;
}

/**
 * @brief 肯定的な候補根拠を確定集合と照合し、未計測なら下限として保持する。
 * @param[in,out] state 当該Providerの集計状態。
 * @param[in] stage 更新する段階の内部配列位置。
 * @param[in] identity 既にDへ照合したopaque device ID。
 * @return 確定済み集合と矛盾しない場合はtrue。
 */
bool addFact( ProviderState &state, const std::size_t stage, const std::wstring_view identity)
{
	// 完全な対象／到達集合から漏れた候補を暗黙に補完しない。
	if( stage <= INFORMATION && state.extents[stage] == MeasurementExtent::EXACT &&
	   !state.sets[stage].contains( identity)) {
		return false ;
	}

	state.sets[stage].insert( identity) ;
	// 新しい肯定的証拠があっても未観測範囲を否定できないため下限に限定する。
	if( !hasCount( state.extents[stage])) {
		state.extents[stage] = MeasurementExtent::LOWER_BOUND ;
	}

	return true ;
}

/**
 * @brief 集合包含を確認する。
 * @param[in] superset 許可する母集合。
 * @param[in] subset その範囲内でなければならない集合。
 * @return 全要素が母集合内ならtrue。
 */
bool includes( const DeviceSet &superset, const DeviceSet &subset)
{
	return std::includes( superset.begin(), superset.end(), subset.begin(), subset.end()) ;
}

/**
 * @brief 公開可能な一resourceの実取得経路と固定IDを検証する。
 * @param[in] resource Provider根拠へ含まれる取得要約。
 * @param[in] descriptor 対応する組み込みProvider定義。
 * @return 固定policy、resource、時刻、cache経路が整合する場合はtrue。
 */
bool validResource( const MeasurementResource &resource,
				   const ProviderDescriptor	 &descriptor) noexcept
{
	// Branchとparserは未接続を許すが、値がある場合は有限かつ有効な値だけを受理する。
	if( resource.branchId.size() > 128U ||
	   (resource.parserRevision.has_value() && resource.parserRevision.value() == 0U)) {
		return false ;
	}

	const OfficialSourcePolicy *const policy =
		// Provider registryが固定した取得元policy。
		findOfficialSourcePolicy( resource.policyId) ;
	// 表示文字列やresource名から別Providerのpolicyを推測しない。
	if( policy == nullptr || policy->providerId != descriptor.id ||
	   descriptor.officialSourcePolicyId != resource.policyId ||
	   findOfficialSourceResource( *policy, resource.resourceId) == nullptr) {
		return false ;
	}

	const bool orderedTimes = !resource.bodyAcquiredUtcSeconds ||
							  !resource.originValidatedUtcSeconds ||
							  resource.bodyAcquiredUtcSeconds.value() <=
								  // 両時刻がある場合の時間順序。
								  resource.originValidatedUtcSeconds.value() ;
	// 一resourceの値へ複数resource集計用のMIXEDや非HTTP区分を混入させない。
	switch( resource.acquisition) {
		// 未接続resourceは時刻とcache方針を持たない場合だけ受理する。
		case MeasurementAcquisition::UNKNOWN:
			return !resource.bodyAcquiredUtcSeconds && !resource.originValidatedUtcSeconds &&
				   !resource.cachePermitted ;

		// Network本文は両時刻、正しい順序、cache方針の記録を必須にする。
		case MeasurementAcquisition::NETWORK_BODY:
			return resource.bodyAcquiredUtcSeconds.has_value() &&
				   resource.originValidatedUtcSeconds.has_value() && orderedTimes &&
				   resource.cachePermitted.has_value() ;

		// Fresh cacheは本文取得時刻を持たず、保存済みorigin時刻と許可方針を必須にする。
		case MeasurementAcquisition::FRESH_CACHE:
			return !resource.bodyAcquiredUtcSeconds &&
				   resource.originValidatedUtcSeconds.has_value() &&
				   resource.cachePermitted == true ;

		// 304再検証cacheも本文取得時刻を捏造せず、再検証時刻と許可方針を必須にする。
		case MeasurementAcquisition::REVALIDATED_CACHE:
			return !resource.bodyAcquiredUtcSeconds &&
				   resource.originValidatedUtcSeconds.has_value() &&
				   resource.cachePermitted == true ;

		// 複数resource用の混在区分を一resourceへ使用しない。
		case MeasurementAcquisition::MIXED:
			return false ;

		// 公式HTTP非該当区分を公式resourceへ使用しない。
		case MeasurementAcquisition::NOT_APPLICABLE:
			return false ;
	}

	return false ;
}

/**
 * @brief 内部配列の段階順を公開値型へ対応付ける。
 * @param[in] values T、Q、R、A、I順の件数。
 * @return 同じ件数を意味のあるfieldへ移した所有値。
 */
StageDeviceCounts stageCounts( const std::array<CountMeasurement, STAGE_COUNT> &values)
{
	return {values[ELIGIBLE], values[QUERY], values[INFORMATION], values[APPLICABLE],
			values[READY]} ;
}

/**
 * @brief 有効Providerの集合を信頼境界・表示groupで絞って重複排除する。
 * @param[in] states Registry順の計測状態。
 * @param[in] filter 集計対象のlocal node集合。
 * @param[in] boundary 0は全network、1は管理service、2は公式network。
 * @param[in] inventoryComplete 全体列挙と詳細処理が完了している場合だけtrue。
 * @return 各段階の和集合。必要な計測の欠損や未照合を下限として保持する。
 */
StageDeviceCounts unionCounts( const std::vector<ProviderState> &states, const DeviceSet &filter,
							  const unsigned int boundary, const bool inventoryComplete)
{
	std::array<CountMeasurement, STAGE_COUNT> values ;	// 公開順に確定する段階別件数。
	// 五段階を独立に確定し、個別query不明を他段階へ一律に波及させない。
	for( std::size_t stage = 0; stage < STAGE_COUNT; ++stage) {
		DeviceSet combined ;						// この段階・表示範囲の和集合。
		bool	  any		  = false ;				// 有効な計測が一つ以上ある場合true。空の確定集合も含む。
		bool	  exact		  = inventoryComplete ;	// 全計測が当該段階で確定した場合だけ維持する。
		bool	  unavailable = false ;				// 有効値がない場合の計測不能を残す。
		// Registry件数で有限な各Providerから同じ段階だけを取り込む。
		for( const ProviderState &state : states) {
			// 無効・非network・別境界を検索済み集合として加算しない。
			if( !state.enabled || !state.network || (boundary == 1 && !state.managed) ||
			   (boundary == 2 && state.managed)) {
				continue ;
			}

			any			= any || hasCount( state.extents[stage]) ;
			exact		= exact && state.extents[stage] == MeasurementExtent::EXACT ;
			unavailable = unavailable || state.extents[stage] == MeasurementExtent::UNAVAILABLE ;
			// 未照合候補の割当先は推測せず、到達以降の完全性だけを保守的に下げる。
			if( stage >= INFORMATION && state.unmatched != 0) {
				exact = false ;
			}

			// 小さい表示母数を走査し、全groupに対して全Provider集合を再列挙しない。
			for( const std::wstring_view identity : filter) {
				// 当該段階に実際の証拠があるnodeだけをこのgroupへ含める。
				if( state.sets[stage].contains( identity)) {
					combined.insert( identity) ;
				}
			}
		}

		const MeasurementExtent extent =
			any ? (exact ? MeasurementExtent::EXACT : MeasurementExtent::LOWER_BOUND)
				: (unavailable
					   ? MeasurementExtent::UNAVAILABLE
					   : MeasurementExtent::NOT_MEASURED) ;	// 空集合と未計測を区別する確定度。
		values[stage] = makeCount( static_cast<std::uint64_t>( combined.size()), extent) ;
	}

	return stageCounts( values) ;
}

/**
 * @brief 同じ母数に対する全network・管理・公式の三内訳を集約する。
 * @param[in] states 有効状態と段階別集合。
 * @param[in] devices 対象表示範囲の母数。
 * @param[in] complete OS inventory完了の根拠。
 * @return Provider別件数を足さず集合で計算した三内訳。
 */
NetworkCoverageMeasurement networkCounts( const std::vector<ProviderState> &states,
										 const DeviceSet &devices, const bool complete)
{
	return {unionCounts( states, devices, 0, complete), unionCounts( states, devices, 1, complete),
			unionCounts( states, devices, 2, complete)} ;
}

/**
 * @brief Provider根拠を同一sessionと母数へ拘束して読み込む。
 * @param[in] evidence 一Providerのworker限定観測。
 * @param[in] devices Local現在版の母数。
 * @param[in,out] state 対応する有効network Providerの作業領域。
 * @return 集合・scope・outcome・recordが整合する場合はtrue。
 */
bool loadEvidence( const ProviderMeasurementEvidence &evidence, const DeviceSet &devices,
				  ProviderState &state)
{
	const bool knownScope = evidence.scope == MeasurementScope::LEGACY_UNKNOWN ||
							evidence.scope == MeasurementScope::DEVICE_QUERY ||
							// 個別証拠の範囲が定義済みか。
							evidence.scope == MeasurementScope::SYSTEM_QUERY ;
	const bool knownOutcome = evidence.queryOutcome == OutcomeCode::NOT_STARTED ||
							  evidence.queryOutcome == OutcomeCode::IN_PROGRESS ||
							  evidence.queryOutcome == OutcomeCode::SUCCESS ||
							  evidence.queryOutcome == OutcomeCode::SUCCEEDED_WITH_ERRORS ||
							  evidence.queryOutcome == OutcomeCode::FAILURE ||
							  // Query結果の既知値判定。
							  evidence.queryOutcome == OutcomeCode::ABORTED ;
	// 定義外・非network・無効の根拠やWUA成功の個別配賦を拒否する。
	if( !state.network || !state.enabled || !knownScope || !knownOutcome ||
	   !knownExtent( evidence.applicabilityExtent) || !knownExtent( evidence.readinessExtent) ||
	   !knownExtent( evidence.recordExtent) ||
	   evidence.resources.size() > MEASUREMENT_RESOURCE_LIMIT ||
	   (state.managed && !evidence.resources.empty()) ||
	   (evidence.scope == MeasurementScope::SYSTEM_QUERY && !state.managed) ||
	   (evidence.scope != MeasurementScope::DEVICE_QUERY &&
		evidence.queryCompleted.extent != MeasurementExtent::NOT_MEASURED) ||
	   !loadSet( evidence.eligible, devices, state.sets[ELIGIBLE]) ||
	   !loadSet( evidence.queryCompleted, devices, state.sets[QUERY]) ||
	   !loadSet( evidence.information, devices, state.sets[INFORMATION]) ||
	   !includes( state.sets[ELIGIBLE], state.sets[QUERY]) ||
	   !includes( state.sets[ELIGIBLE], state.sets[INFORMATION])) {
		return false ;
	}

	// WUA以外の取得要約をregistryの公式policyへ一件ずつ拘束する。
	for( const MeasurementResource &resource : evidence.resources) {
		// 不正な一件を除外して部分公開せず、Provider根拠全体を拒否する。
		if( !validResource( resource, *state.descriptor)) {
			return false ;
		}
	}

	state.output.scope	   = evidence.scope ;
	state.output.resources = evidence.resources ;
	state.extents		   = {evidence.eligible.extent, evidence.queryCompleted.extent,
							  evidence.information.extent, evidence.applicabilityExtent,
							  evidence.readinessExtent} ;
	// System queryの探索範囲をDへ固定し、任意部分集合をsystem全体と呼ばせない。
	if( evidence.scope == MeasurementScope::SYSTEM_QUERY && state.sets[ELIGIBLE] != devices) {
		return false ;
	}

	const bool noTargets = evidence.eligible.extent == MeasurementExtent::EXACT &&
						   state.sets[ELIGIBLE].empty() ;	// 対象0を個別に確定できた場合。
	// 対象なし以外の部分成功・中断は、情報以降の確定値を下限へ抑える。
	if( !noTargets && evidence.queryOutcome != OutcomeCode::SUCCESS) {
		// 対象判定そのものは保持し、query以降だけを段階別に制限する。
		for( std::size_t stage = QUERY; stage < STAGE_COUNT; ++stage) {
			// 未計測を0へ変えず、既にある確定集合だけを下限にする。
			if( state.extents[stage] == MeasurementExtent::EXACT) {
				state.extents[stage] = MeasurementExtent::LOWER_BOUND ;
			}
		}
	}

	// Recordの識別根拠がない状態で内容だけを計数することを禁止する。
	if( evidence.records.size() > MEASUREMENT_CANDIDATE_LIMIT ||
	   (!hasCount( evidence.recordExtent) && !evidence.records.empty())) {
		return false ;
	}

	DeviceSet	  recordIds ;				// Provider・session内の一意record ID集合。
	DeviceSet	  recordDevices ;			// 全recordから明示的に結合できたnodeの和集合。
	std::size_t	  bindings		   = 0 ;	// Recordとdeviceの結合総数。既存候補上限で制限する。
	std::uint64_t unmatchedRecords = 0 ;	// どのD内nodeにも結合しないrecord数。
	// 有限recordを一件ずつ検査し、同一releaseの複数device行をrecord重複にしない。
	for( const MeasurementRecordEvidence &record : evidence.records) {
		// 加算前の残容量でoverflowと過大な結合数を拒否する。
		if( record.identity.empty() || !recordIds.insert( record.identity).second ||
		   record.deviceIdentities.size() > MEASUREMENT_CANDIDATE_LIMIT - bindings) {
			return false ;
		}

		bindings += record.deviceIdentities.size() ;
		DeviceSet bound ;	// 一record内での重複device申告を検出する集合。
		// Recordの結合先は検証済み情報到達集合の範囲へ限定する。
		for( const std::wstring &identity : record.deviceIdentities) {
			// Record本文やtitleから新しい到達先を補完しない。
			if( !state.sets[INFORMATION].contains( identity) || !bound.insert( identity).second) {
				return false ;
			}

			recordDevices.insert( identity) ;
		}

		unmatchedRecords += static_cast<std::uint64_t>( bound.empty()) ;
	}

	// Record列挙を完全と申告する場合は、全情報到達に識別済みrecordを要求する。
	if( evidence.recordExtent == MeasurementExtent::EXACT &&
	   recordDevices != state.sets[INFORMATION]) {
		return false ;
	}

	const MeasurementExtent recordExtent =
		!noTargets && evidence.queryOutcome != OutcomeCode::SUCCESS &&
				evidence.recordExtent == MeasurementExtent::EXACT
			? MeasurementExtent::LOWER_BOUND
			: evidence.recordExtent ;	// 部分queryのrecord列挙を全体確定へ昇格させない。
	state.output.informationRecordCount =
		makeCount( static_cast<std::uint64_t>( recordIds.size()), recordExtent) ;
	state.output.unmatchedInformationRecordCount = makeCount( unmatchedRecords, recordExtent) ;
	state.recordDevices							 = std::move( recordDevices) ;
	return true ;
}

/**
 * @brief 公開段階別件数の値、上限、包含関係を検証する。
 * @param[in] counts T、Q、R、A、Iの公開件数。
 * @param[in] maximumDeviceCount 同じscanまたはgroupのlocal device母数。
 * @return 全件数が有効で、Q/R/A/Iの包含上限を満たす場合はtrue。
 */
bool validPublishedStageCounts( const StageDeviceCounts &counts,
							   const std::uint64_t		maximumDeviceCount) noexcept
{
	const std::array<const CountMeasurement *, STAGE_COUNT> values{
		&counts.eligibleDeviceCount, &counts.queryCompletedDeviceCount,
		&counts.informationDeviceCount, &counts.applicableUpdateDeviceCount,
		&counts.installReadyUpdateDeviceCount} ;	// 公開順の全段階。
	// Optionalと確定度を検証し、値がある段階はlocal母数を超えさせない。
	for( const CountMeasurement *const value : values) {
		// 不正値または母数超過をUIへ公開しない。
		if( value == nullptr || !isCountMeasurementValid( *value) ||
		   (value->value.has_value() && value->value.value() > maximumDeviceCount)) {
			return false ;
		}
	}

	const auto within = []( const CountMeasurement &subset,
						   const CountMeasurement &superset) noexcept {
		// どちらかが未計測なら数値包含を捏造せず、検証対象外とする。
		if( !subset.value.has_value() || !superset.value.has_value()) {
			return true ;
		}

		return subset.value.value() <= superset.value.value() ;
	} ; // 実際に値がある段階間だけを比較する包含検査。
	return within( counts.queryCompletedDeviceCount, counts.eligibleDeviceCount) &&
		   within( counts.informationDeviceCount, counts.eligibleDeviceCount) &&
		   within( counts.applicableUpdateDeviceCount, counts.informationDeviceCount) &&
		   within( counts.installReadyUpdateDeviceCount, counts.applicableUpdateDeviceCount) ;
}

/**
 * @brief 三つのnetwork境界にある全段階件数を検証する。
 * @param[in] measurement 全network、managed、officialの公開件数。
 * @param[in] maximumDeviceCount 同じ表示母数のdevice数。
 * @return 各境界の件数が有効な場合はtrue。
 */
bool validPublishedNetworkCounts( const NetworkCoverageMeasurement &measurement,
								 const std::uint64_t			   maximumDeviceCount) noexcept
{
	return validPublishedStageCounts( measurement.combined, maximumDeviceCount) &&
		   validPublishedStageCounts( measurement.managed, maximumDeviceCount) &&
		   validPublishedStageCounts( measurement.official, maximumDeviceCount) ;
}

/**
 * @brief 公開理由集計のenum、単位、重複を検証する。
 * @param[in] reasons 一Providerまたはinventoryの有限な理由集合。
 * @return 定義済みの理由・単位の組が一意な場合はtrue。
 */
bool validPublishedReasons( const std::span<const MeasurementReasonCount> reasons)
{
	// Enumの直積以上を保持させず、無制限な診断履歴を拒否する。
	if( reasons.size() > 80U) {
		return false ;
	}

	std::set<std::pair<MeasurementReason, MeasurementUnit>> keys ;	// 理由と単位の一意key。
	// 全entryを固定enumへ拘束し、同じkeyの重複を合算して隠さない。
	for( const MeasurementReasonCount &reason : reasons) {
		// 定義外enumまたは重複keyを公開値として受理しない。
		if( reason.reason < MeasurementReason::DISABLED ||
		   reason.reason > MeasurementReason::INCOMPLETE || reason.unit < MeasurementUnit::DEVICE ||
		   reason.unit > MeasurementUnit::REQUEST ||
		   !keys.emplace( reason.reason, reason.unit).second) {
			return false ;
		}
	}

	return true ;
}

/**
 * @brief Provider別のidentityを含まない公開計測をregistry定義へ照合する。
 * @param[in] measurement Provider別の公開件数と取得根拠。
 * @param[in] descriptor 同じstable IDのscan時registry定義。
 * @param[in] maximumDeviceCount Scanのlocal device母数。
 * @return 全fieldが公開契約を満たす場合はtrue。
 */
bool validPublishedProviderMeasurement( const ProviderMeasurement &measurement,
									   const ProviderDescriptor	 &descriptor,
									   const std::uint64_t		  maximumDeviceCount)
{
	const bool knownScope = measurement.scope == MeasurementScope::LEGACY_UNKNOWN ||
							measurement.scope == MeasurementScope::DEVICE_QUERY ||
							// 定義済みscope。
							measurement.scope == MeasurementScope::SYSTEM_QUERY ;
	// Scope、件数、固定理由および有限resource集合をまとめて検証する。
	if( !knownScope || !validPublishedStageCounts( measurement.devices, maximumDeviceCount) ||
	   !isCountMeasurementValid( measurement.unmatchedCandidateCount) ||
	   !isCountMeasurementValid( measurement.informationRecordCount) ||
	   !isCountMeasurementValid( measurement.unmatchedInformationRecordCount) ||
	   measurement.resources.size() > MEASUREMENT_RESOURCE_LIMIT ||
	   !validPublishedReasons( measurement.reasons)) {
		return false ;
	}

	// 未照合recordは識別済みrecord総数を超えない。
	if( measurement.unmatchedInformationRecordCount.value.has_value() &&
	   measurement.informationRecordCount.value.has_value() &&
	   measurement.unmatchedInformationRecordCount.value.value() >
		   measurement.informationRecordCount.value.value()) {
		return false ;
	}

	// 全取得要約を同じProviderの固定policyへ拘束する。
	for( const MeasurementResource &resource : measurement.resources) {
		// 不正な取得経路を一件だけ除外して残りを公開しない。
		if( !validResource( resource, descriptor)) {
			return false ;
		}
	}

	return true ;
}

/**
 * @brief 表現済み母数と属性欠損を現在版から確定し、OS列挙根拠との矛盾を検査する。
 * @param[in] candidates 全候補の借用集合。
 * @param[in] devices 一意な現在版の母数。
 * @param[in,out] inventory 列挙地点の値を保持しつつ表示母数を確定する出力。
 * @return 件数・列挙完了・未収録数に矛盾がなければtrue。
 */
bool completeInventory( const std::span<const UpdateCandidate> candidates, const DeviceSet &devices,
					   DeviceInventoryMeasurement &inventory)
{
	// 理由の全組合せ以上を蓄積させず、event履歴の無制限な複製を防ぐ。
	if( inventory.reasons.size() > 80) {
		return false ;
	}

	std::set<std::pair<MeasurementReason, MeasurementUnit>> reasonKeys ;	// 理由と単位の一意キー。
	// 固定enumの理由だけを元の診断値と独立に保持する。
	for( const MeasurementReasonCount &reason : inventory.reasons) {
		// 定義外enumや重複理由を正常な計測値として公開しない。
		if( reason.reason < MeasurementReason::DISABLED ||
		   reason.reason > MeasurementReason::INCOMPLETE || reason.unit < MeasurementUnit::DEVICE ||
		   reason.unit > MeasurementUnit::REQUEST ||
		   !reasonKeys.emplace( reason.reason, reason.unit).second) {
			return false ;
		}
	}

	const std::array counts{inventory.enumeratedDeviceCount,
							inventory.representedDeviceCount,
							inventory.unrepresentedDeviceCount,
							inventory.missingManufacturerCount,
							inventory.missingClassCount,
							inventory.missingCurrentVersionCount} ;	// 入力された全件数。
	// 値なしと0の矛盾を検出し、旧スカラーから暗黙に補完しない。
	for( const CountMeasurement &count : counts) {
		// 未知enumや不正なoptionalの組を公開しない。
		if( !isCountMeasurementValid( count)) {
			return false ;
		}
	}

	// 現在版から確定できる表現数、製造元欠損、class欠損、現在版欠損。
	std::array<std::uint64_t, 4> actual{static_cast<std::uint64_t>( devices.size()), 0, 0, 0} ;
	// 属性ごとの欠損は同一nodeでも独立に数え、合計をdevice数にしない。
	for( const UpdateCandidate &candidate : candidates) {
		// 現在版以外のmetadata欠損はinventory属性の欠損ではない。
		if( candidate.current) {
			actual[1] += static_cast<std::uint64_t>( candidate.manufacturer.empty()) ;
			actual[2] += static_cast<std::uint64_t>( candidate.driverClass.empty()) ;
			actual[3] += static_cast<std::uint64_t>( candidate.version.empty()) ;
		}
	}

	const std::array supplied{inventory.representedDeviceCount, inventory.missingManufacturerCount,
							  inventory.missingClassCount,
							  inventory.missingCurrentVersionCount} ;	// 既存観測との照合対象。
	// 表示行から確定できる四値に既存申告があれば、違う値を上書きで隠さない。
	for( std::size_t index = 0; index < actual.size(); ++index) {
		// 正確な値または下限を超える矛盾した申告を拒否する。
		if( supplied[index].value.has_value() &&
		   (supplied[index].value.value() > actual[index] ||
			(supplied[index].extent == MeasurementExtent::EXACT &&
			 supplied[index].value.value() != actual[index]))) {
			return false ;
		}
	}

	const CountMeasurement &enumerated = inventory.enumeratedDeviceCount ;	// OS観測数の正本。
	const CountMeasurement &unrepresented =
		inventory.unrepresentedDeviceCount ;	// 同一列挙の未収録数。
	// 全詳細処理完了の申告には、確定した列挙数と未収録0を必須にする。
	if( inventory.detailedEnumerationComplete &&
	   (enumerated.extent != MeasurementExtent::EXACT || enumerated.value != actual[0] ||
		unrepresented.extent != MeasurementExtent::EXACT || unrepresented.value != 0)) {
		return false ;
	}

	// 観測nodeが表示母数より少ない計測を受理しない。
	if( enumerated.value.has_value() && enumerated.value.value() < actual[0]) {
		return false ;
	}

	// 未収録差は同じ確定度の列挙根拠からだけ提示できる。
	if( unrepresented.value.has_value() &&
	   (!enumerated.value.has_value() || unrepresented.extent != enumerated.extent ||
		unrepresented.value.value() != enumerated.value.value() - actual[0])) {
		return false ;
	}

	inventory.representedDeviceCount	 = makeCount( actual[0], MeasurementExtent::EXACT) ;
	inventory.missingManufacturerCount	 = makeCount( actual[1], MeasurementExtent::EXACT) ;
	inventory.missingClassCount			 = makeCount( actual[2], MeasurementExtent::EXACT) ;
	inventory.missingCurrentVersionCount = makeCount( actual[3], MeasurementExtent::EXACT) ;
	return true ;
}

} // namespace

/** @see src/core/scan_measurement.h 宣言側の契約を正本とする。 */
bool isCountMeasurementValid( const CountMeasurement &measurement) noexcept
{
	return knownExtent( measurement.extent) &&
		   measurement.value.has_value() == hasCount( measurement.extent) ;
}

/** @see src/core/scan_measurement.h 宣言側の契約を正本とする。 */
std::optional<BoundedEnumerationMeasurement> classifyBoundedEnumeration(
	const std::uint64_t retainedItemCount, const std::uint64_t itemLimit,
	const BoundedEnumerationStop stop, const BoundedEnumerationProbe probe,
	const NativeError error) noexcept
{
	const bool knownStop = stop == BoundedEnumerationStop::NORMAL_END ||
						   stop == BoundedEnumerationStop::LIMIT ||
						   // 定義済みの本体停止理由。
						   stop == BoundedEnumerationStop::API_FAILURE ;
	const bool knownProbe = probe == BoundedEnumerationProbe::NOT_RUN ||
							probe == BoundedEnumerationProbe::NORMAL_END ||
							probe == BoundedEnumerationProbe::ELEMENT_FOUND ||
							// 定義済みのprobe結果。
							probe == BoundedEnumerationProbe::API_FAILURE ;
	// 上限、enum、保持数またはerror有無が矛盾する入力から観測数を作らない。
	if( itemLimit == 0U || retainedItemCount > itemLimit || !knownStop || !knownProbe ||
	   ((stop == BoundedEnumerationStop::API_FAILURE ||
		 probe == BoundedEnumerationProbe::API_FAILURE) != (error != 0))) {
		return std::nullopt ;
	}

	// 上限前の停止では追加probeを許さず、本体の正常終端と失敗だけを区別する。
	if( stop != BoundedEnumerationStop::LIMIT) {
		// 上限へ到達していない列挙で追加probeを申告する矛盾を拒否する。
		if( probe != BoundedEnumerationProbe::NOT_RUN) {
			return std::nullopt ;
		}

		return BoundedEnumerationMeasurement{
			.observedItemCount	 = {retainedItemCount, stop == BoundedEnumerationStop::NORMAL_END
														   ? MeasurementExtent::EXACT
														   : MeasurementExtent::LOWER_BOUND},
			.enumerationComplete = stop == BoundedEnumerationStop::NORMAL_END,
			.limitExceeded		 = false,
			.error				 = error} ;
	}

	// 上限停止は保持数が上限と一致し、次の一件を一度確認した結果を必須にする。
	if( retainedItemCount != itemLimit || probe == BoundedEnumerationProbe::NOT_RUN) {
		return std::nullopt ;
	}

	// 次のindexが正常終端なら、上限ちょうどの件数を確定できる。
	if( probe == BoundedEnumerationProbe::NORMAL_END) {
		return BoundedEnumerationMeasurement{
			.observedItemCount	 = {retainedItemCount, MeasurementExtent::EXACT},
			.enumerationComplete = true,
			.limitExceeded		 = false,
			.error				 = 0} ;
	}

	// 保持しない追加要素を確認した場合は一件だけを観測下限へ加える。
	if( probe == BoundedEnumerationProbe::ELEMENT_FOUND) {
		// 追加確認した一件を加算できない値から不正な下限を生成しない。
		if( retainedItemCount == std::numeric_limits<std::uint64_t>::max()) {
			return std::nullopt ;
		}

		return BoundedEnumerationMeasurement{
			.observedItemCount	 = {retainedItemCount + 1U, MeasurementExtent::LOWER_BOUND},
			.enumerationComplete = false,
			.limitExceeded		 = true,
			.error				 = 0} ;
	}

	// Probe失敗は保持済み件数だけを下限とし、上限超過を推測しない。
	return BoundedEnumerationMeasurement{
		.observedItemCount	 = {retainedItemCount, MeasurementExtent::LOWER_BOUND},
		.enumerationComplete = false,
		.limitExceeded		 = false,
		.error				 = error} ;
}

/** @see src/core/scan_measurement.h 宣言側の契約を正本とする。 */
bool summarizeOfficialSourceEvidence( const std::span<const OfficialSourceEvidence> evidence,
									 std::vector<MeasurementResource> &resources) noexcept
{
	resources.clear() ;
	// 上限超過を一部要約へ切り詰めず、取得ledger全体を拒否する。
	if( evidence.size() > MEASUREMENT_RESOURCE_LIMIT) {
		return false ;
	}

	try {
		resources.reserve( evidence.size()) ;
		std::wstring_view providerId ;					// 先頭entryで固定するProvider ID。
		ScanSessionId	  session{} ;					// 先頭entryで固定するscan session。
		std::uint64_t	  expectedAcquisitionId{1U} ;	// Ledgerへ期待する連続取得番号。
		// 成功取得ledgerを順序どおり検証し、固定IDと実取得経路だけをcopyする。
		for( const OfficialSourceEvidence &item : evidence) {
			// 未登録、別session、別Provider、欠番を一部だけ正常な根拠として残さない。
			if( !isValidOfficialSourceEvidence( item) ||
			   (!providerId.empty() && item.providerId != providerId) ||
			   (session != 0U && item.scanSessionId != session) ||
			   item.acquisitionId != expectedAcquisitionId) {
				resources.clear() ;
				return false ;
			}

			providerId = item.providerId ;
			session	   = item.scanSessionId ;
			MeasurementResource resource{
				.policyId				   = item.policyId,
				.resourceId				   = item.resourceId,
				.bodyAcquiredUtcSeconds	   = item.bodyAcquiredUtcSeconds,
				.originValidatedUtcSeconds = item.originValidatedUtcSeconds,
				.cachePermitted			   = item.acquisition == MeasurementAcquisition::UNKNOWN
												 ? std::optional<bool>{}
												 : std::optional<bool>{item.cachePermitted},
				.acquisition = item.acquisition} ;	// URLとorigin indexを含めない公開可能要約。
			resources.push_back( std::move( resource)) ;
			++expectedAcquisitionId ;
		}
	} catch( ...) {
		// Allocation失敗時に部分的な取得経路を公開しない。
		resources.clear() ;
		return false ;
	}

	return true ;
}

/** @see src/core/scan_measurement.h 宣言側の契約を正本とする。 */
bool isPublishedScanMeasurementValid( const OperationId operationId,
									 const ScanResult &result) noexcept
{
	// 不正な観測や詳細を正常な母数に含めない。
	if( !isCandidateDetailsSetValid( result.candidates, result.scanSessionId)) {
		return false ;
	}

	// Optional未接続の旧結果は、0件の新計測へ読み替えずそのまま受理する。
	if( !result.measurement.has_value()) {
		return true ;
	}

	try {
		const ScanMeasurement &measurement = result.measurement.value() ;	// 検証する所有snapshot。
		const ScanMeasurementContext &context	  = measurement.context ;	// Operationとscan条件。
		const bool					  knownOsKind = context.osKind == MeasurementOsKind::UNKNOWN ||
								 context.osKind == MeasurementOsKind::CLIENT ||
								 // 定義済みOS区分。
								 context.osKind == MeasurementOsKind::SERVER ;
		// Worker公開時にはoperation、session、version、architecture、時刻順を確定させる。
		if( operationId == 0U || context.contractRevision != 1U ||
		   context.purpose != result.purpose ||
		   (context.purpose != ScanPurpose::STANDARD &&
			context.purpose != ScanPurpose::METADATA_ONLY) ||
		   context.operationId != operationId || context.scanSessionId == 0U ||
		   context.scanSessionId != result.scanSessionId || !context.x64 || !knownOsKind ||
		   context.applicationVersion.empty() || context.applicationVersion.size() > 64U ||
		   (context.osBuild.has_value() && context.osBuild.value() == 0U) ||
		   (context.startedUtcSeconds.has_value() && context.completedUtcSeconds.has_value() &&
			context.startedUtcSeconds.value() > context.completedUtcSeconds.value())) {
			return false ;
		}

		DeviceSet	  devices ;					// 現在版行から再構築するD。
		std::uint64_t missingManufacturer{} ;	// D内の製造元表示欠損数。
		std::uint64_t missingClass{} ;			// D内のclass表示欠損数。
		std::uint64_t missingVersion{} ;		// D内の現在版欠損数。
		std::uint64_t nonCurrentCandidates{} ;	// 未照合上限に使う全非現在版行数。
		// 公開候補からDと欠損数を再構築し、同一deviceの現在版重複を拒否する。
		for( const UpdateCandidate &candidate : result.candidates) {
			// 非現在版はDを増やさず、未照合候補行の上限だけへ数える。
			if( !candidate.current) {
				++nonCurrentCandidates ;
				continue ;
			}

			// 空または重複deviceを正規のlocal母数として受理しない。
			if( candidate.deviceIdentity.empty() ||
			   !devices.insert( candidate.deviceIdentity).second ||
			   devices.size() > MEASUREMENT_DEVICE_LIMIT) {
				return false ;
			}

			missingManufacturer += static_cast<std::uint64_t>( candidate.manufacturer.empty()) ;
			missingClass += static_cast<std::uint64_t>( candidate.driverClass.empty()) ;
			missingVersion += static_cast<std::uint64_t>( candidate.version.empty()) ;
		}

		const auto deviceCount = static_cast<std::uint64_t>( devices.size()) ;	// Dの確定件数。
		const DeviceInventoryMeasurement &inventory = measurement.inventory ;	// 列挙地点の公開根拠。
		const std::array				  inventoryCounts{
			 inventory.enumeratedDeviceCount,
			 inventory.representedDeviceCount,
			 inventory.unrepresentedDeviceCount,
			 inventory.missingManufacturerCount,
			 inventory.missingClassCount,
			 inventory.missingCurrentVersionCount} ;	// 検証対象の全inventory件数。
		// 全inventory件数のoptionalと確定度を先に検証する。
		for( const CountMeasurement &count : inventoryCounts) {
			// 一項目でも不正ならinventory全体を公開しない。
			if( !isCountMeasurementValid( count)) {
				return false ;
			}
		}

		// 表示候補から確定できるDと属性欠損は常にEXACTで一致させる。
		if( inventory.representedDeviceCount.extent != MeasurementExtent::EXACT ||
		   inventory.representedDeviceCount.value != deviceCount ||
		   inventory.missingManufacturerCount.extent != MeasurementExtent::EXACT ||
		   inventory.missingManufacturerCount.value != missingManufacturer ||
		   inventory.missingClassCount.extent != MeasurementExtent::EXACT ||
		   inventory.missingClassCount.value != missingClass ||
		   inventory.missingCurrentVersionCount.extent != MeasurementExtent::EXACT ||
		   inventory.missingCurrentVersionCount.value != missingVersion ||
		   !validPublishedReasons( inventory.reasons)) {
			return false ;
		}

		// OS観測数がある場合は一覧表現数以上でなければならない。
		if( inventory.enumeratedDeviceCount.value.has_value() &&
		   inventory.enumeratedDeviceCount.value.value() < deviceCount) {
			return false ;
		}

		// 同一列挙から確定した未収録数はOS観測数とDの差に一致させる。
		if( inventory.unrepresentedDeviceCount.value.has_value() &&
		   (!inventory.enumeratedDeviceCount.value.has_value() ||
			inventory.unrepresentedDeviceCount.extent != inventory.enumeratedDeviceCount.extent ||
			inventory.unrepresentedDeviceCount.value.value() !=
				inventory.enumeratedDeviceCount.value.value() - deviceCount)) {
			return false ;
		}

		// 詳細完了時はDとOS観測が一致し、未収録0であることを再確認する。
		if( inventory.detailedEnumerationComplete &&
		   (inventory.enumeratedDeviceCount.extent != MeasurementExtent::EXACT ||
			inventory.enumeratedDeviceCount.value != deviceCount ||
			inventory.unrepresentedDeviceCount.extent != MeasurementExtent::EXACT ||
			inventory.unrepresentedDeviceCount.value != 0U)) {
			return false ;
		}

		// 全体network件数と未照合行数をD・候補行の上限へ拘束する。
		if( !validPublishedNetworkCounts( measurement.network, deviceCount) ||
		   !isCountMeasurementValid( measurement.unmatchedCandidateCount) ||
		   (measurement.unmatchedCandidateCount.value.has_value() &&
			measurement.unmatchedCandidateCount.value.value() > nonCurrentCandidates)) {
			return false ;
		}

		std::map<std::wstring_view, const ProviderScanReport *> reports ;	// Stable ID別report索引。
		// 全reportを一意なregistry IDへ拘束し、段階別provider計測も同時に検証する。
		for( const ProviderScanReport &report : result.providerReports) {
			const bool knownState =
				report.state >= ProviderScanState::DISABLED &&
				report.state <= ProviderScanState::CONTENT_REJECTED ;	// 定義済みstate。
			const bool knownOutcome = report.outcome >= OutcomeCode::NOT_STARTED &&
									  report.outcome <= OutcomeCode::ABORTED ;	// 定義済みoutcome。
			// Measurement付きsnapshotは全registry reportへ新指標を一対一で持たせる。
			if( report.descriptor.id.empty() || !knownState || !knownOutcome ||
			   !report.coverage.measurement.has_value() ||
			   !reports.emplace( report.descriptor.id, &report).second ||
			   !validPublishedProviderMeasurement( report.coverage.measurement.value(),
												  report.descriptor, deviceCount)) {
				return false ;
			}
		}

		std::set<std::wstring_view> enabledProviders ;	// Context内の重複しない有効ID集合。
		// Scan開始時の有効集合をreportへ照合し、未知・重複IDを拒否する。
		for( const std::wstring &providerId : context.enabledProviderIds) {
			const auto report = reports.find( providerId) ;	// 同じstable IDのreport。
			// 無効reportまたは未知IDを実行済みProviderとして記録しない。
			if( report == reports.end() || report->second->state == ProviderScanState::DISABLED ||
			   !enabledProviders.insert( providerId).second) {
				return false ;
			}
		}

		// Contextから漏れた有効reportを後のUI設定で補完しない。
		for( const auto &[providerId, report] : reports) {
			const bool enabled = report->state != ProviderScanState::DISABLED ;	// Scan時の実行状態。
			// Reportとcontextの有効／無効が一致しないsnapshotを拒否する。
			if( enabled != enabledProviders.contains( providerId)) {
				return false ;
			}
		}

		std::set<std::pair<std::wstring_view, std::wstring_view>> coverageKeys ;	// Group重複検査。
		std::uint64_t groupedDevices{} ;											// 全manufacturer／class groupのD件数合計。
		// Local coverageはDを一度ずつpartitionし、全groupに段階別snapshotを持たせる。
		for( const LocalCoverageEntry &entry : result.localCoverage) {
			const auto key = std::pair<std::wstring_view, std::wstring_view>{
				entry.manufacturer, entry.driverClass} ;	// 現在表示groupの一意key。
			// Group重複、件数overflowまたは段階別計測欠落を受理しない。
			if( !coverageKeys.insert( key).second ||
			   entry.deviceCount > std::numeric_limits<std::uint64_t>::max() - groupedDevices ||
			   !entry.measurement.has_value() ||
			   !validPublishedNetworkCounts( entry.measurement.value(), entry.deviceCount)) {
				return false ;
			}

			groupedDevices += entry.deviceCount ;
		}

		// 表示group制限を適用する前の全groupがDを過不足なく表す必要がある。
		if( groupedDevices != deviceCount) {
			return false ;
		}
	} catch( ...) {
		// 検証用索引のallocation失敗時は計測だけを無効として扱う。
		return false ;
	}

	return true ;
}

/** @see src/core/scan_measurement.h 宣言側の契約を正本とする。 */
std::optional<ScanMeasurementAggregation> aggregateScanMeasurement(
	const ScanMeasurementContext &context, const std::span<const UpdateCandidate> candidates,
	const std::span<const ProviderDescriptor>		   providers,
	const DeviceInventoryMeasurement				  &inventory,
	const std::span<const ProviderMeasurementEvidence> evidence,
	const std::span<const std::wstring>				   routableCandidateIds)
{
	// 非対応契約、別architecture、過大な集合を割当て前に拒否する。
	if( context.contractRevision != 1 || context.scanSessionId == 0 || !context.x64 ||
	   !isCandidateDetailsSetValid( candidates, context.scanSessionId) ||
	   (context.purpose != ScanPurpose::STANDARD &&
		context.purpose != ScanPurpose::METADATA_ONLY) ||
	   (context.osKind != MeasurementOsKind::UNKNOWN &&
		context.osKind != MeasurementOsKind::CLIENT &&
		context.osKind != MeasurementOsKind::SERVER) ||
	   candidates.size() > MEASUREMENT_CANDIDATE_LIMIT || providers.empty() ||
	   providers.size() > MEASUREMENT_CANDIDATE_LIMIT || evidence.size() > providers.size() ||
	   context.enabledProviderIds.size() > providers.size() ||
	   routableCandidateIds.size() > candidates.size()) {
		return std::nullopt ;
	}

	std::map<std::wstring_view, std::size_t> providerIndexes ;	// 既存registryへの一意索引。
	std::vector<ProviderState>				 states ;			// Registry順の有限な作業領域。
	// 全Providerの信頼境界を一意にし、別の取得元一覧をハードコードしない。
	for( const ProviderDescriptor &provider : providers) {
		const auto sourceMask = provider.capabilities & 0x4F0U ;	// 収集者確認を含む五つの独立境界。
		// 未知bitや複数の信頼境界、重複IDを計測の別枠として受理しない。
		if( provider.id.empty() || (provider.capabilities & ~0x7FFU) != 0 ||
		   (provider.capabilities & capabilityMask( ProviderCapability::SCAN)) == 0 ||
		   std::popcount( sourceMask) != 1 ||
		   !providerIndexes.emplace( provider.id, states.size()).second) {
			return std::nullopt ;
		}

		ProviderState state ;	// このregistry要素の初期状態。新指標は全て未計測。
		state.descriptor = &provider ;
		state.managed	 = (sourceMask & capabilityMask( ProviderCapability::MANAGED_SERVICE)) != 0 ;
		state.network	 = state.managed ||
						(sourceMask & capabilityMask( ProviderCapability::OFFICIAL_NETWORK)) != 0 ;
		states.push_back( std::move( state)) ;
	}

	// Scan開始時に固定した集合だけを有効化し、現在のUI設定を再解釈しない。
	for( const std::wstring &id : context.enabledProviderIds) {
		const auto found = providerIndexes.find( id) ;	// 解決済みIDのregistry位置。
		// 未知IDや重複指定から架空の検索成功を作らない。
		if( found == providerIndexes.end() || states[found->second].enabled) {
			return std::nullopt ;
		}

		states[found->second].enabled = true ;
	}

	// 既定選択を宣言したsnapshotではregistry既定値との食い違いも拒否する。
	for( const ProviderState &state : states) {
		// 明示設定を既定設定と偽って記録しない。
		if( context.usedDefaultProviders && state.enabled != state.descriptor->enabledByDefault) {
			return std::nullopt ;
		}
	}

	DeviceSet devices ;	// 検証済みlocal現在版だけから作るD。
	std::map<std::wstring_view, const UpdateCandidate *>
		candidateIds ;	// 候補契約とrouting照合用索引。
	// 表示候補のidentityと監査を既存validatorへ照合してから母数を作る。
	for( const UpdateCandidate &candidate : candidates) {
		const auto provider = providerIndexes.find( candidate.providerId) ;	// 発行元registry位置。
		// 契約違反を未照合扱いで隠さず、同一candidateの重複も拒否する。
		if( candidate.identity.empty() || candidate.deviceIdentity.empty() ||
		   (context.purpose == ScanPurpose::STANDARD && candidate.packageIdentity.empty()) ||
		   (context.purpose == ScanPurpose::METADATA_ONLY &&
			(!candidate.packageIdentity.empty() || candidate.installable || candidate.recommended ||
			 candidate.action != DriverAction::NONE)) ||
		   provider == providerIndexes.end() ||
		   !candidateIds.emplace( candidate.identity, &candidate).second) {
			return std::nullopt ;
		}

		const ProviderState &state = states[provider->second] ;	// 発行元の設定と検証境界。
		// 必須inventory以外の無効Provider候補や監査・選択根拠の矛盾を拒否する。
		if( (!candidate.current && !state.enabled) ||
		   !isCandidateAuditValid( candidate, *state.descriptor) ||
		   !isCandidateDefaultPreferenceValid( candidate, *state.descriptor)) {
			return std::nullopt ;
		}

		// 現在版はlocal列挙一node一行だけを母数にする。
		if( candidate.current && (!devices.insert( candidate.deviceIdentity).second ||
								 devices.size() > MEASUREMENT_DEVICE_LIMIT)) {
			return std::nullopt ;
		}
	}

	DeviceSet routes ;	// 既存install routingの借用候補ID。
	// Routingは既存候補に限定し、計測側で導入対象を新規生成しない。
	for( const std::wstring &id : routableCandidateIds) {
		const auto found = candidateIds.find( id) ;	// Routing対象の正規候補。
		// 不明・重複・表示専用のroutingは導入可能数へ昇格できない。
		if( found == candidateIds.end() || !found->second->installable ||
		   !routes.insert( id).second) {
			return std::nullopt ;
		}

		const ProviderState &state =
			states[providerIndexes.at( found->second->providerId)] ;	// Routing所有元。
		// Install capabilityのない経路をREADYと数えない。
		if( !state.enabled ||
		   (state.descriptor->capabilities & capabilityMask( ProviderCapability::INSTALL)) == 0) {
			return std::nullopt ;
		}
	}

	DeviceSet evidenceProviders ;	// 同一Providerの二重根拠発行を拒否する集合。
	// Worker根拠を同じsessionの登録Providerへ一対一で対応付ける。
	for( const ProviderMeasurementEvidence &item : evidence) {
		// 専用検索で適用性・導入準備の測定を申告する混入を拒否する。
		if( context.purpose == ScanPurpose::METADATA_ONLY &&
		   (item.applicabilityExtent != MeasurementExtent::NOT_MEASURED ||
			item.readinessExtent != MeasurementExtent::NOT_MEASURED)) {
			return std::nullopt ;
		}

		const auto found = providerIndexes.find( item.providerId) ;	// 根拠発行元のregistry位置。
		// 古いsession、未知Provider、重複発行または内部集合の矛盾を公開しない。
		if( item.scanSessionId != context.scanSessionId || found == providerIndexes.end() ||
		   !evidenceProviders.insert( item.providerId).second ||
		   !loadEvidence( item, devices, states[found->second])) {
			return std::nullopt ;
		}
	}

	// 有効な候補からだけ肯定的到達・適用性・READYの集合を導く。
	for( const UpdateCandidate &candidate : candidates) {
		ProviderState &state =
			states[providerIndexes.at( candidate.providerId)] ;	// 候補発行元の集計。
		// 現在版、local履歴、利用者指定fileをnetwork到達へ含めない。
		if( candidate.current || !state.network) {
			continue ;
		}

		// 正規でも結合できない候補は別の行数とし、割当deviceを推測しない。
		if( !devices.contains( candidate.deviceIdentity)) {
			++state.unmatched ;
			continue ;
		}

		// Origin未確認や拒否済みの表示行を具体的な公式情報到達へ含めない。
		if( !state.managed && candidate.audit.sourceOrigin != CandidateAuditGateState::PASSED) {
			continue ;
		}

		const bool audited =
			state.managed ||
			(candidate.audit.inspectionDownload == CandidateAuditGateState::PASSED &&
			 candidate.audit.contentIntegrity == CandidateAuditGateState::PASSED &&
			 candidate.audit.systemApplicability ==
				 CandidateAuditGateState::PASSED) ;	// 既存gateの確定根拠。
		// 公式pageの由来だけでは具体的recordのschema検証を証明できない。
		if( !audited && !state.sets[INFORMATION].contains( candidate.deviceIdentity)) {
			continue ;
		}

		// 正規候補のlocal結合と探索条件は肯定的証拠になるが、確定集合とは矛盾できない。
		if( !addFact( state, ELIGIBLE, candidate.deviceIdentity) ||
		   !addFact( state, INFORMATION, candidate.deviceIdentity)) {
			return std::nullopt ;
		}

		// 適用性未確認のmetadataは、操作分類にかかわらず全件監査済みと数えない。
		if( !audited &&
		   (candidate.audit.systemApplicability == CandidateAuditGateState::PENDING ||
			candidate.audit.systemApplicability == CandidateAuditGateState::PROVIDER_VALIDATED)) {
			// 肯定的な到達は維持し、未監査範囲が残る更新・READYの確定度だけを下げる。
			for( const std::size_t stage : {APPLICABLE, READY}) {
				// 未計測は未計測のままにし、完了を誤申告した場合だけ下限へ抑える。
				if( state.extents[stage] == MeasurementExtent::EXACT) {
					state.extents[stage] = MeasurementExtent::LOWER_BOUND ;
				}
			}
		}

		// 同版・旧版・表示専用情報は通常更新集合へ含めない。
		if( candidate.action != DriverAction::UPDATE || !audited) {
			continue ;
		}

		static_cast<void>( addFact( state, APPLICABLE, candidate.deviceIdentity)) ;
		// READYと既存routingの両方がある候補だけを準備完了更新へ含める。
		if( candidate.installable &&
		   candidate.audit.installReadiness == CandidateInstallReadiness::READY &&
		   routes.contains( candidate.identity)) {
			static_cast<void>( addFact( state, READY, candidate.deviceIdentity)) ;
		}
	}

	ScanMeasurementAggregation result ;	// 検証後だけ呼出し元へ移動する所有値。
	result.snapshot.context	  = context ;
	result.snapshot.inventory = inventory ;
	// 列挙根拠と表示母数が食い違う測定値を一部だけ公開しない。
	if( !completeInventory( candidates, devices, result.snapshot.inventory)) {
		return std::nullopt ;
	}

	std::uint64_t unmatched		 = 0 ;		// 全networkの未照合行数。候補上限以下である。
	bool		  networkEnabled = false ;	// 全無効と確定0を区別する。
	// Provider別集合の最終包含関係を確認してから公開件数へ変換する。
	for( ProviderState &state : states) {
		// 完全なrecord識別の申告と後から得た候補到達が矛盾する場合は未計測へ隠さず拒否する。
		if( state.output.informationRecordCount.extent == MeasurementExtent::EXACT &&
		   state.recordDevices != state.sets[INFORMATION]) {
			return std::nullopt ;
		}

		// QはRの上位集合とは限らないが、両方ともTの範囲内でなければならない。
		if( !includes( devices, state.sets[ELIGIBLE]) ||
		   !includes( state.sets[ELIGIBLE], state.sets[QUERY]) ||
		   !includes( state.sets[ELIGIBLE], state.sets[INFORMATION]) ||
		   !includes( state.sets[INFORMATION], state.sets[APPLICABLE]) ||
		   !includes( state.sets[APPLICABLE], state.sets[READY])) {
			return std::nullopt ;
		}

		std::array<CountMeasurement, STAGE_COUNT> counts ;	// Provider別の段階順集計。
		// 各段階の確定度を独立に保持する。
		for( std::size_t stage = 0; stage < STAGE_COUNT; ++stage) {
			MeasurementExtent extent = state.extents[stage] ;	// 公開時点の保守的な確定度。
			// 不完全inventoryや未照合を全件確認済みとして表示しない。
			if( extent == MeasurementExtent::EXACT &&
			   (!inventory.detailedEnumerationComplete ||
				(stage >= INFORMATION && state.unmatched != 0))) {
				extent = MeasurementExtent::LOWER_BOUND ;
			}

			counts[stage] = makeCount( static_cast<std::uint64_t>( state.sets[stage].size()), extent) ;
		}

		state.output.devices = stageCounts( counts) ;
		// 無効・非networkを実行済み0と表示せず、network未照合だけを集約する。
		if( state.enabled && state.network) {
			state.output.unmatchedCandidateCount =
				makeCount( state.unmatched, MeasurementExtent::EXACT) ;
			unmatched += state.unmatched ;
			networkEnabled = true ;
		}

		result.providers.push_back( {state.descriptor->id, state.output}) ;
	}

	result.snapshot.unmatchedCandidateCount = makeCount(
		unmatched, networkEnabled ? MeasurementExtent::EXACT : MeasurementExtent::NOT_MEASURED) ;
	result.snapshot.network = networkCounts( states, devices, inventory.detailedEnumerationComplete) ;
	auto coverage =
		// 既存の表示groupと従来の候補到達数。
		aggregateLocalCoverage( candidates, providers) ;
	// 既存group集計が拒否する入力から新しい表示母数を作り直さない。
	if( !coverage.has_value()) {
		return std::nullopt ;
	}

	// 全group分の現在版を一巡で分類し、group数と全候補数の積になる再走査を避ける。
	std::map<std::pair<std::wstring_view, std::wstring_view>, DeviceSet> groupDevices ;
	// 現在版のmanufacturer／classだけをgroupの正本にし、空属性も残す。
	for( const UpdateCandidate &candidate : candidates) {
		// 履歴やnetwork候補の表示値で現在nodeのgroupを変更しない。
		if( candidate.current) {
			groupDevices[{candidate.manufacturer, candidate.driverClass}].insert(
				candidate.deviceIdentity) ;
		}
	}

	// 全groupの数値を先に確定し、UIの表示件数制限やfilterに影響されないようにする。
	for( LocalCoverageEntry &entry : coverage.value()) {
		const DeviceSet &group =
			// 同じ表示母数。
			groupDevices.at( {entry.manufacturer, entry.driverClass}) ;
		entry.measurement = networkCounts( states, group, inventory.detailedEnumerationComplete) ;
	}

	result.localCoverage = std::move( coverage.value()) ;
	return result ;
}

} // namespace drivercrate
