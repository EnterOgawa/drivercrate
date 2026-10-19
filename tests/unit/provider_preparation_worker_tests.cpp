//------------------------------------------------------------------------------
/**
 * @file provider_preparation_worker_tests.cpp
 * @brief 取得準備workerの内部試験。
 * @version 01.02.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  計測有無による副作用回数の不変性を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Scan計測のWorker公開境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX候補発行と指定導入の共通接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Install確認契約を明示。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  候補発行状態と件数fixtureを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  一系列のWorker・Controller結合試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の表示境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  EULA本文と取得再確認の境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得計画とworker実行を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  通常scanの操作結合と協調取消しを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/16  通常索引refreshと非通信worker/UI境界を接続。
 * </pre>
 *
 * @note COM workerを使用しますが、通信・実driver導入・実復元ポイントは使用しません。
 */
//------------------------------------------------------------------------------

#include "provider_preparation_worker_tests.h"
#include "core/candidate_audit.h"
#include "core/official_preparation_audit.h"
#include "core/operation_controller.h"
#include "core/protected_install.h"
#include "core/provider_registry.h"
#include "core/restore_point_service.h"
#include "core/scan_measurement.h"
#include "platform/provider_worker.h"
#include "platform/provider_worker_index_internal.h"
#include "platform/windows_product_type.h"
#include "test_framework.h"
#include <stdexcept>

#include <Windows.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <iostream>
#include <memory>
#include <optional>
#include <semaphore>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {
/** @brief UI役とworkerの間で共有する合成状態。 */
struct FakePreparationState {
	/// Fake scanの開始回数。
	std::atomic_uint32_t		scanCalls{} ;
	/// Fake取得の開始回数。
	std::atomic_uint32_t		acquireCalls{} ;
	/// Fake導入の呼出回数。実installは行わない。
	std::atomic_uint32_t		installCalls{} ;
	/// Fake復旧処理の呼出回数。実APIは呼ばない。
	std::atomic_uint32_t		restoreCalls{} ;
	/// 保持情報失効の要求回数。
	std::atomic_uint32_t		invalidations{} ;
	/// trueなら合成監査表示と対応する検索候補を返す。
	std::atomic_bool			emitAudit{} ;
	/// trueなら表示集約の例外を合成する。
	std::atomic_bool			throwAudit{} ;
	/// 本試験内のfake復旧処理だけを成功させる。
	std::atomic_bool			allowFakeRestore{} ;
	/// trueならfake導入境界から例外を返す。
	std::atomic_bool			throwInstall{} ;
	/// trueなら同じ結合fixtureをASIX取得元で実行する。
	std::atomic_bool			asixPipeline{} ;
	/// trueなら一系列の全段階を成功候補として合成する。
	std::atomic_bool			emitPipeline{} ;
	/// Fake導入中に同じscan保持物が残っていた場合true。
	std::atomic_bool			retainedAtInstall{} ;
	/// 次のscan一回だけを試験信号まで待機させる。
	std::atomic_bool			holdScan{} ;
	/// 次の取得一回だけを取消しまたは試験信号まで待機させる。
	std::atomic_bool			holdAcquire{} ;
	/// Fake取得が協調取消しを観測した場合true。
	std::atomic_bool			cancellationSeen{} ;
	/// Fake通常scanが自分の操作に結合した取消しを観測した場合true。
	std::atomic_bool			scanCancellationSeen{} ;
	/// 対象1が誤って取得された場合true。
	std::atomic_bool			acquiredUnselected{} ;
	/// trueならworkerが拒否すべき計画を返す。
	std::atomic_bool			invalidPlan{} ;
	/// trueなら空の正常scan計測snapshotを返す。
	std::atomic_bool			emitMeasurement{} ;
	/// trueなら別operationの計測を合成する。
	std::atomic_bool			invalidMeasurement{} ;
	/// 待機scanの開始通知。
	std::counting_semaphore<32> scanEntered{0} ;
	/// 待機scanを解放する試験信号。
	std::counting_semaphore<32> scanRelease{0} ;
	/// 待機取得の開始通知。
	std::counting_semaphore<32> acquireEntered{0} ;
	/// 待機取得を解放する試験信号。
	std::counting_semaphore<32> acquireRelease{0} ;
} ;

/** @brief 復元APIを初期化せず、呼出し順序を記録するfake。 */
class FakePreparationRestoreService final : public IRestorePointService {
public:
	/**
	 * @brief Fixture状態を共有する。
	 * Windows復元APIを初期化せず、試験状態だけを保持する。
	 * @param[in] state 誤呼出しを記録する共有状態。 Fixtureの共有状態。
	 */
	explicit FakePreparationRestoreService( std::shared_ptr<FakePreparationState> state) ;
	/**
	 * @brief 実復元ポイントを作らず呼出回数を記録する。
	 * 実復元APIを呼ばず、許可したfixtureだけで保護後のworker順序を検証する。
	 * @param[in] description 使用しない復旧説明。 使用しない合成説明。
	 * @return Fixture指定時は合成成功、それ以外は既定の未成功結果。 指定時だけ合成成功と番号77。それ以外は既定の未成功結果。
	 */
	RestorePointOperationResult begin( std::wstring_view description) noexcept override ;
	/**
	 * @brief 実APIを呼ばず誤呼出しを記録する。
	 * 実APIを呼ばず、fake復旧処理の終了回数を記録する。
	 * @param[in] sequenceNumber 使用しない合成番号。 使用しない合成復元番号。
	 * @return Fixture指定時は合成成功、それ以外は既定の未成功結果。 指定時だけ合成成功と番号77。それ以外は既定の未成功結果。
	 */
	RestorePointOperationResult complete( std::int64_t sequenceNumber) noexcept override ;

private:
	/// 試験側へ誤呼出しを返す共有状態。
	std::shared_ptr<FakePreparationState> state_ ;
} ;

/** @brief 実systemを使わず取得準備と一系列の導入結果を合成するProvider。 */
class FakePreparationProvider final : public IUpdateProvider {
public:
	/**
	 * @brief 合成状態の所有権を共有する。
	 * 実ProviderやHTTPを生成せず、試験状態だけを共有する。
	 * @param[in] state 試験中に有効な共有状態。 Fixtureが所有する合成状態。
	 */
	explicit FakePreparationProvider( std::shared_ptr<FakePreparationState> state) ;
	/**
	 * @brief 有界な偽scan結果を返す。
	 * 待機は一回かつ最大3秒に限定する。一系列試験でも実deviceは列挙しない。
	 * @param[in] session workerが発行した検索ID。 workerの検索ID。
	 * @param[in] options 使用しない合成検索設定。 未使用の設定。
	 * @param[in] progress 使用しない通知先。 未使用の通知先。
	 * @return 通常は実deviceを含まない結果。一系列試験時は非機密の架空候補を含む。 通常は空、一系列試験では架空の表示専用候補を持つ成功結果。
	 */
	ScanResult scan( ScanSessionId session, const ScanOptions &options,
					const ProviderProgressCallback &progress) override ;
	/**
	 * @brief Workerが所有する通常scan取消しを有限待機中に観測する。
	 * @param[in] session Workerが発行した検索session ID。
	 * @param[in] options 実networkを含まない合成検索設定。
	 * @param[in] cancellation 同じoperationの非blocking取消し照会。
	 * @param[in] progress 使用しない合成通知先。
	 * @return 取消し時はABORTED、それ以外は通常の合成scan結果。
	 */
	ScanResult scanWithCancellation( ScanSessionId session, const ScanOptions &options,
									const ProviderScanCancellation &cancellation,
									const ProviderProgressCallback &progress) override ;
	/**
	 * @brief 保持sessionの有限な架空対象を計画へ返す。
	 * 実metadataやURLを使わず、workerでの照合だけを確認する。
	 * @param[in] session 計画を要求する検索ID。
	 * @param[in] planId workerが発行した計画ID。 workerが発行する計画ID。
	 * @return 一系列試験は一対象、既存試験は三対象の計画。旧sessionはnullopt。
	 */
	std::optional<OfficialPreparationPlan> preparationPlan( ScanSessionId session,
														   std::uint64_t planId) override ;
	/**
	 * @brief 転送せず取得済み、または協調取消しを返す。
	 * 実fileを取得せず、有限待機中も取消しを観測する。
	 * @param[in] task 選択されたtask。 workerがclaimした対象。
	 * @param[in] cancellation workerの取消し照会。 協調取消し照会。
	 * @return 合成した取得結果。 合成した取得成功または取消し。
	 */
	OfficialPreparationTransferResult	   acquireForInspection(
			 const OfficialPreparationTask &task, const PreparationCancellation &cancellation) override ;
	/**
	 * @brief 実監査を行わず、非機密reportまたは集約例外を合成する。
	 * 実監査を行わず、worker通知と表示集約失敗の扱いを確認する。
	 * @param[in] result 同一workerの合成取得結果。 Fake取得の確定結果。
	 * @return 合成対象の表示report。通常試験では空。 合成監査report。例外指定時は合成例外。
	 */
	std::vector<OfficialPreparationAuditReport> preparationAuditReports(
		const OfficialPreparationOperationResult &result) override ;
	/**
	 * @brief workerの失効順序を数え、実driverの状態は変更しない。
	 */
	void		  invalidatePreparation() noexcept override ;
	/**
	 * @brief 実installを行わず呼出回数だけを記録する。
	 * 実installを行わず、呼出し時に保持物が生存しているか記録する。
	 * @param[in] session 保持している検索IDとの照合値。 Fakeが保持している検索sessionとの照合値。
	 * @param[in] identities 未使用の選択一覧。 実driverでない合成選択。一系列試験ではIDを照合する。
	 * @param[in] parent 未使用の親Window値。 使用しない親Window値。
	 * @param[in] progress 未使用の通知先。 使用しない通知先。
	 * @return 通常は未開始結果。一系列試験時は全選択候補の合成成功結果。 通常は未実行結果。一系列試験時は入力順の合成成功結果。指定時は合成例外。
	 */
	InstallResult install( ScanSessionId session, std::span<const std::wstring> identities,
						  std::uintptr_t parent, const ProviderProgressCallback &progress) override ;

private:
	/// UI役と共有する試験状態。
	std::shared_ptr<FakePreparationState> state_ ;
	/// worker thread内だけで使用する保持session。
	ScanSessionId						  session_{} ;
} ;

/** @brief 有限待機と終了時解放を保証するworker試験fixture。 */
class WorkerFixture final {
public:
	/**
	 * @brief Fake Providerだけのworkerを生成する。
	 * Windowを生成せず、event queueから結果を回収する。
	 */
	WorkerFixture() ;
	/**
	 * @brief 失敗時の早期returnでもfake待機を解放し、workerを残さない。
	 */
	~WorkerFixture() ;
	/**
	 * @brief 指定eventを最大3秒待つ。未消費eventは次の要求へ保持する。
	 * 異なるeventを捨てず、後続の検証へ保持する。
	 * @param[in] kind 必要なeventの種類。 待つevent種類。
	 * @param[in] operation 必要な操作ID。 待つ操作ID。
	 * @return 該当eventまたはtimeoutのnullopt。 該当eventまたは3秒経過後のnullopt。
	 */
	std::optional<WorkerEvent>			  waitEvent( WorkerEventKind kind, OperationId operation) ;
	/// 試験とworkerの共有状態。
	std::shared_ptr<FakePreparationState> state ;
	/// Fixtureが所有して必ず停止するworker。
	std::unique_ptr<ProviderWorker>		  worker ;

private:
	/// 取り出したが未消費の有界event。
	std::vector<WorkerEvent> pending_ ;
} ;

//------------------------------------------------------------------------------
/**
 * @see tests/unit/provider_preparation_worker_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
FakePreparationProvider::FakePreparationProvider( std::shared_ptr<FakePreparationState> state)
{
	state_ = std::move( state) ;
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/provider_preparation_worker_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult FakePreparationProvider::scan( const ScanSessionId session, const ScanOptions &options,
										 const ProviderProgressCallback &progress)
{
	static_cast<void>( options) ;
	static_cast<void>( progress) ;
	++state_->scanCalls ;
	// 指定された一回のscanだけを有限時間保留し、競合操作を試験できる状態を作る。
	if( state_->holdScan.exchange( false)) {
		state_->scanEntered.release() ;
		static_cast<void>( state_->scanRelease.try_acquire_for( std::chrono::seconds( 3))) ;
	}

	session_ = session ;
	ScanResult result{.succeeded	 = true,
					  .scanSessionId = session,
					  .outcome		 = OutcomeCode::SUCCESS,
					  .state = ProviderScanState::NO_CANDIDATES} ;	// 実deviceを使わない合成結果。
	// 一系列の取得後監査を試験する場合は対応する架空の表示行を用意する。
	if( state_->emitPipeline) {
		UpdateCandidate row ;	// 一系列の取得後監査を反映する架空の表示専用行。
		row.identity	   = L"row:target:0" ;
		row.deviceIdentity = L"device:0" ;
		row.providerId =
			(state_->asixPipeline ? ASIX_AX88179A_PROVIDER_ID : BROADCOM_NET_XTREME_PROVIDER_ID) ;
		row.title =
			state_->asixPipeline ? L"Fictional ASIX discovery" : L"Fictional Broadcom discovery" ;
		row.manufacturer = state_->asixPipeline ? L"ASIX" : L"Broadcom" ;
		row.model =
			state_->asixPipeline ? L"Fictional AX88179A Adapter" : L"Fictional NetXtreme-E Adapter" ;
		row.driverClass	   = L"Net" ;
		row.sourceName	   = state_->asixPipeline ? L"ASIX AX88179A" : L"Broadcom NetXtreme-E" ;
		row.sourceLocation = L"Official vendor website" ;
		row.discoveryBasis = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
		row.audit		   = makeOfficialDiscoveryCandidateAudit() ;
		result.candidates.push_back( std::move( row)) ;
		result.state = ProviderScanState::CANDIDATES_AVAILABLE ;
	}
	// 監査表示を試験する場合は三対象に対応する表示専用行を用意する。
	else if( state_->emitAudit) {
		// 合成計画の三対象と同じID対応を持つ、表示専用候補を用意する。
		for( std::uint32_t index = 0U; index < 3U; ++index) {
			UpdateCandidate row ;	// 監査反映先となる架空の表示行。
			row.identity	   = L"row:target:" + std::to_wstring( index) ;
			row.deviceIdentity = L"device:" + std::to_wstring( index) ;
			row.providerId	   = PROLIFIC_OFFICIAL_PROVIDER_ID ;
			row.discoveryBasis = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
			row.audit		   = makeOfficialDiscoveryCandidateAudit() ;
			result.candidates.push_back( std::move( row)) ;
		}

		result.state = ProviderScanState::CANDIDATES_AVAILABLE ;
	}

	// Worker公開境界の拘束を試験する場合だけ、実deviceを含まない空計測を付加する。
	if( state_->emitMeasurement) {
		ScanMeasurement measurement ;	// Workerがoperationとapplication版を設定する合成snapshot。
		measurement.context.operationId =
			state_->invalidMeasurement ? 99U : 0U ;	// 不正fixtureは別operationを固定する。
		measurement.context.scanSessionId = session ;
		const CountMeasurement exactZero{
			0U, MeasurementExtent::EXACT} ;	// 空の現在版集合と整合する確定0件。
		measurement.inventory.enumeratedDeviceCount		  = exactZero ;
		measurement.inventory.representedDeviceCount	  = exactZero ;
		measurement.inventory.unrepresentedDeviceCount	  = exactZero ;
		measurement.inventory.missingManufacturerCount	  = exactZero ;
		measurement.inventory.missingClassCount			  = exactZero ;
		measurement.inventory.missingCurrentVersionCount  = exactZero ;
		measurement.inventory.detailedEnumerationComplete = true ;
		result.measurement								  = std::move( measurement) ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/provider_preparation_worker_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult FakePreparationProvider::scanWithCancellation(
	const ScanSessionId session, const ScanOptions &options,
	const ProviderScanCancellation &cancellation, const ProviderProgressCallback &progress)
{
	// Queue内で取り消されたscanはProvider処理を開始しない。
	if( cancellation && cancellation()) {
		++state_->scanCalls ;
		state_->scanCancellationSeen = true ;
		return {.scanSessionId = session,
				.outcome	   = OutcomeCode::ABORTED,
				.state		   = ProviderScanState::FAILURE,
				.error		   = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))} ;
	}

	// 指定された一回のscanだけを最大3秒待機し、途中取消しを観測する。
	if( state_->holdScan.exchange( false)) {
		state_->scanEntered.release() ;
		// 10 ms単位で同じ操作の信号と試験解放を最大300回確認する。
		for( std::uint32_t attempt = 0U; attempt < 300U; ++attempt) {
			// 取消し成立後は正常scan結果や準備計画を作らない。
			if( cancellation && cancellation()) {
				++state_->scanCalls ;
				state_->scanCancellationSeen = true ;
				return {.scanSessionId = session,
						.outcome	   = OutcomeCode::ABORTED,
						.state		   = ProviderScanState::FAILURE,
						.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))} ;
			}

			// 試験側が明示解放した場合だけ通常scanへ進む。
			if( state_->scanRelease.try_acquire_for( std::chrono::milliseconds( 10))) {
				break ;
			}
		}
	}

	return scan( session, options, progress) ;
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/provider_preparation_worker_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::optional<OfficialPreparationPlan> FakePreparationProvider::preparationPlan(
	const ScanSessionId session, const std::uint64_t planId)
{
	// 未発行または古いsessionには準備計画を返さない。
	if( session == 0U || session != session_) {
		return std::nullopt ;
	}

	// workerへ返す非機密の合成取得計画。
	OfficialPreparationPlan plan{session, planId, DEFAULT_OFFICIAL_PREPARATION_LIMITS, {}} ;
	const std::uint32_t		targetCount =
		state_->emitPipeline ? 1U : 3U ;	// 一系列試験または既存部分取得試験の対象数。
	const std::wstring_view providerId =
		state_->emitPipeline
			? (state_->asixPipeline ? ASIX_AX88179A_PROVIDER_ID : BROADCOM_NET_XTREME_PROVIDER_ID)
			: PROLIFIC_OFFICIAL_PROVIDER_ID ;	// 対象に固定する登録済みProvider。
	// 一系列では一配布物、既存試験では中央を未選択にできる三配布物を作る。
	for( std::uint32_t index = 0U; index < targetCount; ++index) {
		OfficialPreparationTarget target ;	// 合成した一配布物。
		target.identity		   = L"target:" + std::to_wstring( index) ;
		target.providerId	   = providerId ;
		target.resourceId	   = L"payload" ;
		target.releaseIdentity = L"release:" + std::to_wstring( index) ;
		target.parserRevision  = 1U ;
		target.maximumBytes	   = 100U ;
		target.deviceCount	   = 1U ;
		target.terms		   = OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
		plan.targets.push_back( std::move( target)) ;
	}

	// 計画IDの不一致を注入してworker側の結果検証を確認する。
	if( state_->invalidPlan) {
		// workerが発行した値と一致しないProvider結果を合成する。
		++plan.planId ;
	}

	return plan ;
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/provider_preparation_worker_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialPreparationTransferResult FakePreparationProvider::acquireForInspection(
	const OfficialPreparationTask &task, const PreparationCancellation &cancellation)
{
	++state_->acquireCalls ;
	// 未選択対象への取得呼出しがあれば観測flagへ記録する。
	if( task.target.identity == L"target:1") {
		state_->acquiredUnselected = true ;
	}

	// 指定された一回の取得だけを有限時間保留し、待機中の取消しを検証する。
	if( state_->holdAcquire.exchange( false)) {
		state_->acquireEntered.release() ;
		// 最大約3秒だけ待機し、signal通知がなくても協調取消しを繰り返し確認する。
		for( std::uint32_t attempt = 0U; attempt < 300U; ++attempt) {
			// 待機中に取消しを観測したら取得成功に進まず取消し結果を返す。
			if( cancellation && cancellation()) {
				state_->cancellationSeen = true ;
				return {OfficialPreparationItemState::CANCELLED,
						static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)), 0U} ;
			}

			// 試験側から再開通知を受けた場合は待機loopを抜ける。
			if( state_->acquireRelease.try_acquire_for( std::chrono::milliseconds( 10))) {
				break ;
			}
		}
	}

	return {OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0, 20U} ;
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/provider_preparation_worker_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void FakePreparationProvider::invalidatePreparation() noexcept
{
	++state_->invalidations ;
	session_ = 0U ;
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/provider_preparation_worker_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult FakePreparationProvider::install( const ScanSessionId				   session,
											   const std::span<const std::wstring> identities,
											   const std::uintptr_t				   parent,
											   const ProviderProgressCallback	  &progress)
{
	static_cast<void>( parent) ;
	static_cast<void>( progress) ;
	++state_->installCalls ;
	state_->retainedAtInstall = session != 0U && session == session_ ;
	// 実installは一切行わない。
	if( state_->throwInstall) {
		throw std::runtime_error( "fictional install failure") ;
	}

	// 一系列試験では同じsessionの公開済み一候補だけを模擬成功へ変換する。
	if( state_->emitPipeline) {
		InstallResult result ;	// WorkerのOS別保護結果が後から付加されるProvider成功結果。
		// 同じscanで発行した一候補だけを合成成功へ変換する入力照合値。
		const bool	  valid = session != 0U && session == session_ && identities.size() == 1U &&
						   identities.front() == L"prepared:target:0" ;
		result.succeeded	   = valid ;
		result.downloadOutcome = valid ? OutcomeCode::SUCCESS : OutcomeCode::FAILURE ;
		result.installOutcome  = valid ? OutcomeCode::SUCCESS : OutcomeCode::FAILURE ;
		result.downloadError   = valid ? 0 : static_cast<NativeError>( E_INVALIDARG) ;
		result.installError	   = valid ? 0 : static_cast<NativeError>( E_INVALIDARG) ;
		// 選択identityを欠落させず、成功と拒否のどちらもControllerが照合できる形で返す。
		for( const std::wstring &identity : identities) {
			result.updates.push_back(
				{.identity		  = identity,
				 .downloadOutcome = valid ? OutcomeCode::SUCCESS : OutcomeCode::FAILURE,
				 .downloadError	  = result.downloadError,
				 .installOutcome  = valid ? OutcomeCode::SUCCESS : OutcomeCode::FAILURE,
				 .installError	  = result.installError,
				 .rebootRequired  = valid}) ;
		}

		result.rebootRequired = valid ;
		return result ;
	}

	return {} ;
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/provider_preparation_worker_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
WorkerFixture::WorkerFixture()
{
	state  = std::make_shared<FakePreparationState>() ;
	worker = std::make_unique<ProviderWorker>(
		nullptr, WM_APP + 41U,
		[shared = state]() { return std::make_unique<FakePreparationProvider>( shared) ; },
		[shared = state]() { return std::make_unique<FakePreparationRestoreService>( shared) ; }) ;
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/provider_preparation_worker_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
WorkerFixture::~WorkerFixture()
{
	state->scanRelease.release() ;
	state->acquireRelease.release() ;
	worker->stop() ;
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/provider_preparation_worker_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::optional<WorkerEvent> WorkerFixture::waitEvent( const WorkerEventKind kind,
													const OperationId	  operation)
{
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds( 3) ;	// 待機期限。
	// 期限内だけqueueを回収し、busy spinを避けるため試験threadを短時間yieldする。
	while( std::chrono::steady_clock::now() < deadline) {
		auto arrived = worker->takeEvents() ;	// workerから所有権を移す有限event。
		// 到着したeventを保持し、先の操作の結果も確認できるようにする。
		for( WorkerEvent &event : arrived) {
			pending_.push_back( std::move( event)) ;
		}

		const auto found = std::find_if(
			pending_.begin(), pending_.end(), [kind, operation]( const WorkerEvent &event) {
				return event.kind == kind && event.operationId == operation ;
			}) ; // 今回要求するeventだけの位置。
		// 目的のeventが保留中にあれば所有値を取り出し、他のeventは残す。
		if( found != pending_.end()) {
			WorkerEvent result = std::move( *found) ;	// 呼出し側へ渡す所有値。
			pending_.erase( found) ;
			return result ;
		}

		std::this_thread::sleep_for( std::chrono::milliseconds( 1)) ;
	}

	return std::nullopt ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示した全対象のsnapshotを返し、暗黙の同意を使わない。
 *
 * @param[in] plan workerがeventへ添付した固定計画。
 * @param[in] operation 新しい操作ID。
 * @return 中央対象を未選択とした合成判断。
 */
//------------------------------------------------------------------------------
OfficialPreparationApproval workerApproval( const OfficialPreparationPlan &plan,
										   const OperationId			  operation)
{
	OfficialPreparationApproval approval{
		operation, plan.scanSessionId, plan.planId, plan.limits, {}} ;	// 合成判断。
	// 全対象の可否を記録し、未選択行も省略しない。
	for( const OfficialPreparationTarget &target : plan.targets) {
		approval.decisions.push_back( {target, target.identity != L"target:1", false, false}) ;
	}

	return approval ;
}

//------------------------------------------------------------------------------
/**
 * @brief 検索eventの計画とprepareの部分取得をworker境界で確認する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testWorkerPlanAndPreparation( TestContext &context)
{
	WorkerFixture fixture ;	// Fakeだけを生成するworker。
	DRIVERCRATE_EXPECT( context, !fixture.worker->requestScan( 0U)) ;
	DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( 1U)) ;
	const auto scanned = fixture.waitEvent( WorkerEventKind::SCAN_COMPLETED, 1U) ;	// 検索結果。
	DRIVERCRATE_EXPECT( context, scanned && scanned->preparationPlan) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( !scanned || !scanned->preparationPlan) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, scanned->preparationError == 0) ;
	const auto approval = workerApproval( *scanned->preparationPlan, 2U) ;	// 表示済み計画の判断。
	DRIVERCRATE_EXPECT( context, fixture.worker->requestPreparation( approval)) ;
	// 要求した取得操作の完了event。Timeoutの場合はnullopt。
	const auto completed = fixture.waitEvent( WorkerEventKind::PREPARATION_COMPLETED, 2U) ;
	DRIVERCRATE_EXPECT( context, completed.has_value()) ;
	DRIVERCRATE_EXPECT( context, fixture.state->acquireCalls == 2U) ;
	DRIVERCRATE_EXPECT( context, !fixture.state->acquiredUnselected) ;
	DRIVERCRATE_EXPECT( context, fixture.state->installCalls == 0U) ;
	DRIVERCRATE_EXPECT( context, fixture.state->restoreCalls == 0U) ;
	// 完了eventを取得できた場合にだけ承認結果と三対象の結果を参照する。
	if( completed) {
		DRIVERCRATE_EXPECT( context, completed->preparationResult.approvalError ==
										OfficialPreparationError::NONE) ;
		DRIVERCRATE_EXPECT( context, completed->preparationResult.items.size() == 3U) ;
	}

	DRIVERCRATE_EXPECT( context, !fixture.worker->requestPreparation( approval)) ;
	DRIVERCRATE_EXPECT( context, !fixture.worker->requestPreparationCancel( 2U)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 新scan・導入保護拒否のどちらでも旧取得計画を失効させる。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testWorkerStaleAndInstallInvalidation( TestContext &context)
{
	// 実installを呼ばない無効modeと、新scanによる失効を独立に検証する。
	for( const bool installRequest : {false, true}) {
		WorkerFixture fixture ;	// 今回の失効経路を分離するworker。
		DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( 1U)) ;
		const auto scanned = fixture.waitEvent( WorkerEventKind::SCAN_COMPLETED, 1U) ;	// 旧計画。
		DRIVERCRATE_EXPECT( context, scanned && scanned->preparationPlan) ;
		// scan結果と準備計画が揃わなければ旧計画失効のscenarioを続けない。
		if( !scanned || !scanned->preparationPlan) {
			continue ;
		}

		// 導入による失効scenarioでは不正保護modeの架空要求を送り、実導入は行わない。
		if( installRequest) {
			const std::vector<std::wstring> identities{L"synthetic-target"} ;	// 実driverでないID。
			DRIVERCRATE_EXPECT( context, fixture.worker->requestInstall(
											2U, scanned->scanResult.scanSessionId, identities,
											nullptr, static_cast<InstallProtectionMode>( 255))) ;
			DRIVERCRATE_EXPECT(
				context, fixture.waitEvent( WorkerEventKind::INSTALL_COMPLETED, 2U).has_value()) ;
		} else {
			DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( 2U)) ;
			DRIVERCRATE_EXPECT( context,
							   fixture.waitEvent( WorkerEventKind::SCAN_COMPLETED, 2U).has_value()) ;
		}

		DRIVERCRATE_EXPECT( context, fixture.worker->requestPreparation(
										workerApproval( *scanned->preparationPlan, 3U))) ;
		// 要求した取得操作の完了event。Timeoutの場合はnullopt。
		const auto completed = fixture.waitEvent( WorkerEventKind::PREPARATION_COMPLETED, 3U) ;
		DRIVERCRATE_EXPECT( context, completed.has_value()) ;
		// 完了eventがある場合にだけ旧計画の承認拒否を確認する。
		if( completed) {
			DRIVERCRATE_EXPECT( context, completed->preparationResult.approvalError !=
											OfficialPreparationError::NONE) ;
		}

		DRIVERCRATE_EXPECT( context, fixture.state->invalidations >= 2U) ;
		DRIVERCRATE_EXPECT( context, fixture.state->acquireCalls == 0U) ;
		DRIVERCRATE_EXPECT( context, fixture.state->installCalls == 0U) ;
		DRIVERCRATE_EXPECT( context, fixture.state->restoreCalls == 0U) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 実行中の取得だけへ協調取消しを伝え、stopも完了を待つ。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testWorkerActiveCancellationAndStop( TestContext &context)
{
	// 明示取消しとworker終了の二つの経路を検証する。
	for( const bool stopping : {false, true}) {
		WorkerFixture fixture ;	// 取消しを待つfake worker。
		fixture.state->holdAcquire = true ;
		DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( 1U)) ;
		const auto scanned = fixture.waitEvent( WorkerEventKind::SCAN_COMPLETED, 1U) ;	// 承認元計画。
		DRIVERCRATE_EXPECT( context, scanned && scanned->preparationPlan) ;
		// 準備計画を取得できなければ取消しと停止のscenarioを始めない。
		if( !scanned || !scanned->preparationPlan) {
			continue ;
		}

		DRIVERCRATE_EXPECT( context, fixture.worker->requestPreparation(
										workerApproval( *scanned->preparationPlan, 2U))) ;
		DRIVERCRATE_EXPECT( context,
						   fixture.state->acquireEntered.try_acquire_for( std::chrono::seconds( 3))) ;
		DRIVERCRATE_EXPECT( context, !fixture.worker->requestPreparationCancel( 99U)) ;
		// 停止scenarioでは協調取消しに続くworker終了待ちを検証する。
		if( stopping) {
			fixture.worker->stop() ;
		} else {
			DRIVERCRATE_EXPECT( context, fixture.worker->requestPreparationCancel( 2U)) ;
		}

		// 要求した取得操作の完了event。Timeoutの場合はnullopt。
		const auto completed = fixture.waitEvent( WorkerEventKind::PREPARATION_COMPLETED, 2U) ;
		DRIVERCRATE_EXPECT( context, completed.has_value()) ;
		DRIVERCRATE_EXPECT( context, fixture.state->cancellationSeen) ;
		DRIVERCRATE_EXPECT( context, fixture.state->acquireCalls == 1U) ;
		DRIVERCRATE_EXPECT( context, fixture.state->installCalls == 0U) ;
		DRIVERCRATE_EXPECT( context, fixture.state->restoreCalls == 0U) ;
		// 停止済みworkerが新たなscanを受理しないことを確認する。
		if( stopping) {
			DRIVERCRATE_EXPECT( context, !fixture.worker->requestScan( 3U)) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 通常scan承認を操作IDへ結合し、active／queued／stop取消しを分離する。
 * @param[in,out] context Assertion結果の集計先。
 */
//------------------------------------------------------------------------------
void testWorkerScanCancellationAndApprovalBinding( TestContext &context)
{
	{
		WorkerFixture fixture ;	// 承認内のID改ざんをqueue前に拒否するfake worker。
		ScanOptions	  options ;	// 自動探索Provider一件だけの合成条件。
		options.useDefaultProviders = false ;
		options.enabledProviderIds.emplace_back( INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID) ;
		OfficialDiscoveryScanApproval approval ;	// 固定予算の一scan承認。
		approval.operationId			  = 2U ;
		options.officialDiscoveryApproval = approval ;
		DRIVERCRATE_EXPECT( context, !fixture.worker->requestScan( 1U, options)) ;
		options.officialDiscoveryApproval->operationId = 1U ;
		DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( 1U, options)) ;
		DRIVERCRATE_EXPECT( context,
						   fixture.waitEvent( WorkerEventKind::SCAN_COMPLETED, 1U).has_value()) ;
		DRIVERCRATE_EXPECT( context, !fixture.worker->requestScanCancel( 1U)) ;
	}

	// 明示取消しとworker停止の両方が実行中scanのみに届くことを確認する。
	for( const bool stopping : {false, true}) {
		WorkerFixture fixture ;	// 実行中取消しの独立状態。
		fixture.state->holdScan = true ;
		DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( 1U)) ;
		DRIVERCRATE_EXPECT( context,
						   fixture.state->scanEntered.try_acquire_for( std::chrono::seconds( 3))) ;
		DRIVERCRATE_EXPECT( context, !fixture.worker->requestScanCancel( 99U)) ;
		// 停止と明示取消しを同じfake受理境界へ別々に通す。
		if( stopping) {
			fixture.worker->stop() ;
		} else {
			DRIVERCRATE_EXPECT( context, fixture.worker->requestScanCancel( 1U)) ;
		}

		const auto completed =
			// 取消し終端結果。
			fixture.waitEvent( WorkerEventKind::SCAN_COMPLETED, 1U) ;
		DRIVERCRATE_EXPECT( context,
						   completed && completed->scanResult.outcome == OutcomeCode::ABORTED) ;
		DRIVERCRATE_EXPECT( context, fixture.state->scanCancellationSeen) ;
		DRIVERCRATE_EXPECT( context, fixture.state->scanCalls == 1U) ;
		DRIVERCRATE_EXPECT( context, !fixture.worker->requestScanCancel( 1U)) ;
	}

	{
		WorkerFixture fixture ;	// 未開始queueの信号が別scanへ漏れないことを確認する状態。
		fixture.state->holdScan = true ;
		DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( 1U)) ;
		DRIVERCRATE_EXPECT( context,
						   fixture.state->scanEntered.try_acquire_for( std::chrono::seconds( 3))) ;
		DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( 2U)) ;
		DRIVERCRATE_EXPECT( context, fixture.worker->requestScanCancel( 2U)) ;
		fixture.state->scanRelease.release() ;
		DRIVERCRATE_EXPECT( context,
						   fixture.waitEvent( WorkerEventKind::SCAN_COMPLETED, 1U).has_value()) ;
		const auto cancelled =
			// Queue内で取り消された結果。
			fixture.waitEvent( WorkerEventKind::SCAN_COMPLETED, 2U) ;
		DRIVERCRATE_EXPECT( context,
						   cancelled && cancelled->scanResult.outcome == OutcomeCode::ABORTED) ;
		DRIVERCRATE_EXPECT( context, fixture.state->scanCancellationSeen) ;
		DRIVERCRATE_EXPECT( context, fixture.state->scanCalls == 2U) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 未開始queueとpacketを有限にし、queued取消しを次の操作へ漏らさない。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testWorkerQueueBoundsAndQueuedCancel( TestContext &context)
{
	WorkerFixture fixture ;	// 最初のscanでqueue受付を固定するworker。
	fixture.state->holdScan = true ;
	DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( 1U)) ;
	DRIVERCRATE_EXPECT( context,
					   fixture.state->scanEntered.try_acquire_for( std::chrono::seconds( 3))) ;
	OfficialPreparationPlan plan{
		1U, 1U, DEFAULT_OFFICIAL_PREPARATION_LIMITS, {}} ;	// 合成承認の元値。
	// まだ待機中のfake scanが返す三対象と同一のsnapshotを合成する。
	for( std::uint32_t index = 0U; index < 3U; ++index) {
		OfficialPreparationTarget target ;	// Queue取消しを確認する合成対象。
		target.identity		   = L"target:" + std::to_wstring( index) ;
		target.providerId	   = PROLIFIC_OFFICIAL_PROVIDER_ID ;
		target.resourceId	   = L"payload" ;
		target.releaseIdentity = L"release:" + std::to_wstring( index) ;
		target.parserRevision  = 1U ;
		target.maximumBytes	   = 100U ;
		target.deviceCount	   = 1U ;
		target.terms		   = OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
		plan.targets.push_back( std::move( target)) ;
	}

	auto approval  = workerApproval( plan, 2U) ;	// Fake検索後の計画へ完全一致する合成判断。
	auto oversized = approval ;						// コピー前のpacket上限検証用。
	oversized.decisions.resize( 257U) ;
	DRIVERCRATE_EXPECT( context, !fixture.worker->requestPreparation( oversized)) ;
	oversized = approval ;
	oversized.decisions[0].target.identity.assign( 129U, L'x') ;
	DRIVERCRATE_EXPECT( context, !fixture.worker->requestPreparation( oversized)) ;
	oversized = approval ;
	oversized.decisions[0].target.eulaText.assign( MAXIMUM_PREPARATION_EULA_CHARACTERS + 1U, L'A') ;
	DRIVERCRATE_EXPECT( context, !fixture.worker->requestPreparation( oversized)) ;
	oversized = approval ;
	oversized.decisions.resize( 5U, approval.decisions[0]) ;
	// 個別上限内でも、五対象の本文がpacket全体の保持上限を超えればcopy前に拒否する。
	for( OfficialPreparationDecision &decision : oversized.decisions) {
		decision.target.eulaText.assign( MAXIMUM_PREPARATION_EULA_CHARACTERS, L'A') ;
	}

	DRIVERCRATE_EXPECT( context, !fixture.worker->requestPreparation( oversized)) ;
	DRIVERCRATE_EXPECT( context, fixture.worker->requestPreparation( approval)) ;
	DRIVERCRATE_EXPECT( context, fixture.worker->requestPreparationCancel( 2U)) ;
	DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( 3U)) ;
	DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( 4U)) ;
	DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( 5U)) ;
	DRIVERCRATE_EXPECT( context, !fixture.worker->requestScan( 6U)) ;
	fixture.state->scanRelease.release() ;
	DRIVERCRATE_EXPECT( context,
					   fixture.waitEvent( WorkerEventKind::PREPARATION_COMPLETED, 2U).has_value()) ;
	const auto laterScan = fixture.waitEvent( WorkerEventKind::SCAN_COMPLETED, 5U) ;	// 後続の新計画。
	DRIVERCRATE_EXPECT( context, laterScan && laterScan->preparationPlan) ;
	DRIVERCRATE_EXPECT( context, fixture.state->acquireCalls == 0U) ;
	DRIVERCRATE_EXPECT( context, fixture.state->scanCalls == 4U) ;
	DRIVERCRATE_EXPECT( context, !fixture.worker->requestPreparationCancel( 2U)) ;
	// 後続scanの計画がある場合にだけ以前の取消しが漏れないことを検証する。
	if( laterScan && laterScan->preparationPlan) {
		DRIVERCRATE_EXPECT( context, fixture.worker->requestPreparation(
										workerApproval( *laterScan->preparationPlan, 6U))) ;
		DRIVERCRATE_EXPECT(
			context, fixture.waitEvent( WorkerEventKind::PREPARATION_COMPLETED, 6U).has_value()) ;
		DRIVERCRATE_EXPECT( context, fixture.state->acquireCalls == 2U) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 不正な計画を拒否し、driver scan自体の成功結果は保持する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testWorkerInvalidPlanIsSeparate( TestContext &context)
{
	auto defaults = std::make_shared<FakePreparationState>() ;	// 既定APIの副作用検出用状態。
	FakePreparationProvider provider( defaults) ;				// 通信しないProviderを直接構成する。
	DRIVERCRATE_EXPECT( context, !provider.IUpdateProvider::preparationPlan( 1U, 1U)) ;
	// 未対応の基底APIが返す拒否結果。
	const auto unsupported = provider.IUpdateProvider::acquireForInspection( {}, {}) ;
	// 未対応APIは計画や取得成功を暗黙追加しない。
	DRIVERCRATE_EXPECT( context, unsupported.state == OfficialPreparationItemState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, unsupported.error == static_cast<NativeError>( E_NOTIMPL)) ;
	DRIVERCRATE_EXPECT( context, defaults->acquireCalls == 0U) ;

	WorkerFixture fixture ;	// 間違った計画IDを返すfake。
	fixture.state->invalidPlan = true ;
	DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( 1U)) ;
	const auto scanned = fixture.waitEvent( WorkerEventKind::SCAN_COMPLETED, 1U) ;	// 分離結果。
	DRIVERCRATE_EXPECT( context, scanned.has_value()) ;
	// scan eventがある場合にだけscan成功と準備計画拒否の分離を確認する。
	if( scanned) {
		DRIVERCRATE_EXPECT( context, scanned->scanResult.succeeded) ;
		DRIVERCRATE_EXPECT( context, !scanned->preparationPlan) ;
		DRIVERCRATE_EXPECT( context, scanned->preparationError != 0) ;
	}

	DRIVERCRATE_EXPECT( context, fixture.state->acquireCalls == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Workerが正常計測へoperationと実版を拘束し、別operationの計測だけを破棄する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testWorkerMeasurementPublicationBoundary( TestContext &context)
{
	{
		WorkerFixture		  fixture ;				// 計測未接続時の副作用回数を固定する基準fake。
		constexpr OperationId operationId = 16U ;	// 基準scanへ割り当てる合成operation ID。
		DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( operationId)) ;
		const auto scanned = fixture.waitEvent( WorkerEventKind::SCAN_COMPLETED,
											   operationId) ;	// 計測なしで完了した基準event。
		DRIVERCRATE_EXPECT( context, scanned.has_value() && !scanned->scanResult.measurement) ;
		DRIVERCRATE_EXPECT( context, fixture.state->scanCalls == 1U) ;
		DRIVERCRATE_EXPECT( context, fixture.state->acquireCalls == 0U) ;
		DRIVERCRATE_EXPECT( context, fixture.state->installCalls == 0U) ;
		DRIVERCRATE_EXPECT( context, fixture.state->restoreCalls == 0U) ;
	}

	// 正常snapshotと別operationの不正snapshotを独立workerで比較する。
	for( const bool invalid : {false, true}) {
		WorkerFixture fixture ;	// 通信・実device列挙を行わない計測fake。
		fixture.state->emitMeasurement	  = true ;
		fixture.state->invalidMeasurement = invalid ;
		constexpr OperationId operationId = 17U ;	// Workerが公開snapshotへ拘束する合成ID。
		DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( operationId)) ;
		const auto scanned = fixture.waitEvent( WorkerEventKind::SCAN_COMPLETED,
											   operationId) ;	// Worker境界通過後の所有結果。
		DRIVERCRATE_EXPECT( context, scanned.has_value()) ;
		// Event欠落時はoptionalを参照せず、次のscenarioへ進む。
		if( !scanned) {
			continue ;
		}

		DRIVERCRATE_EXPECT( context, scanned->scanResult.succeeded) ;
		DRIVERCRATE_EXPECT( context, scanned->scanResult.measurement.has_value() == !invalid) ;
		DRIVERCRATE_EXPECT( context, fixture.state->scanCalls == 1U) ;
		DRIVERCRATE_EXPECT( context, fixture.state->acquireCalls == 0U) ;
		DRIVERCRATE_EXPECT( context, fixture.state->installCalls == 0U) ;
		DRIVERCRATE_EXPECT( context, fixture.state->restoreCalls == 0U) ;
		// 正常計測だけは一致するoperation、session、application版を確認する。
		if( scanned->scanResult.measurement) {
			const ScanMeasurementContext &measurementContext =
				scanned->scanResult.measurement->context ;	// 公開後の不変条件。
			DRIVERCRATE_EXPECT( context, measurementContext.operationId == operationId) ;
			DRIVERCRATE_EXPECT( context, measurementContext.scanSessionId ==
											scanned->scanResult.scanSessionId) ;
			DRIVERCRATE_EXPECT( context, measurementContext.applicationVersion == L"0.1.0") ;
			DRIVERCRATE_EXPECT( context,
							   isPublishedScanMeasurementValid( operationId, scanned->scanResult)) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/provider_preparation_worker_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
FakePreparationRestoreService::FakePreparationRestoreService(
	std::shared_ptr<FakePreparationState> state)
{
	state_ = std::move( state) ;
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/provider_preparation_worker_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
RestorePointOperationResult FakePreparationRestoreService::begin(
	const std::wstring_view description) noexcept
{
	static_cast<void>( description) ;
	++state_->restoreCalls ;
	return state_->allowFakeRestore ? RestorePointOperationResult{OutcomeCode::SUCCESS, 0, 77}
									: RestorePointOperationResult{} ;
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/provider_preparation_worker_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
RestorePointOperationResult FakePreparationRestoreService::complete(
	const std::int64_t sequenceNumber) noexcept
{
	static_cast<void>( sequenceNumber) ;
	++state_->restoreCalls ;
	return state_->allowFakeRestore ? RestorePointOperationResult{OutcomeCode::SUCCESS, 0, 77}
									: RestorePointOperationResult{} ;
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/provider_preparation_worker_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------

std::vector<OfficialPreparationAuditReport> FakePreparationProvider::preparationAuditReports(
	const OfficialPreparationOperationResult &result)
{
	// 監査集約の例外を注入し、転送成功の結果が保持されることを確認する。
	if( state_->throwAudit) {
		throw std::runtime_error( "fictional audit report failure") ;
	}

	std::vector<OfficialPreparationAuditReport> reports ;	// 取得した架空対象だけの表示。
	// 監査を発行しないfixtureでは空reportを返す。
	if( !state_->emitAudit) {
		return reports ;
	}

	// 取得成功対象だけに非機密の合成reportを付加する。
	for( const OfficialPreparationItem &item : result.items) {
		// 取得済みでない対象へ架空の監査reportを発行しない。
		if( item.result.state != OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION) {
			continue ;
		}

		OfficialPreparationAuditReport report ;	// 取得済み対象へ対応する架空監査表示。
		report.targetIdentity = item.identity ;
		report.providerId	  = state_->emitPipeline
									? (state_->asixPipeline ? ASIX_AX88179A_PROVIDER_ID
															: BROADCOM_NET_XTREME_PROVIDER_ID)
									: PROLIFIC_OFFICIAL_PROVIDER_ID ;
		OfficialPreparationCandidateAudit row ;	// 同じfake scanに提示した表示専用行。
		row.identity				 = L"row:" + item.identity ;
		row.audit					 = makeOfficialDiscoveryCandidateAudit() ;
		row.audit.inspectionDownload = CandidateAuditGateState::PASSED ;
		// 一系列試験では表示行の合格監査と別identityの導入候補を合成する。
		if( state_->emitPipeline) {
			// 一系列試験では内容・PnP監査済みの表示行と別の選択可能候補を発行する。
			report.content				  = CandidateAuditGateState::PASSED ;
			report.applicability		  = CandidateAuditGateState::PASSED ;
			report.infCount				  = 1U ;
			report.acceptedInfCount		  = 1U ;
			report.examinedPairCount	  = 1U ;
			report.applicablePairCount	  = 1U ;
			row.audit.contentIntegrity	  = CandidateAuditGateState::PASSED ;
			row.audit.systemApplicability = CandidateAuditGateState::PASSED ;
			report.publication.state =
				OfficialPreparationCandidatePublicationState::CANDIDATES_PUBLISHED ;
			report.publication.examinedPairCount = 1U ;
			report.publication.publishedCount	 = 1U ;
			report.candidatePublicationAttempted = true ;
			UpdateCandidate candidate ;	// 実fileやPnP IDを含まない全監査合格の架空候補。
			candidate.identity		  = L"prepared:target:0" ;
			candidate.deviceIdentity  = L"device:0" ;
			candidate.providerId	  = (state_->asixPipeline ? ASIX_AX88179A_PROVIDER_ID
															  : BROADCOM_NET_XTREME_PROVIDER_ID) ;
			candidate.packageIdentity = L"package:target:0" ;
			candidate.title			  = state_->asixPipeline ? L"Fictional ASIX audited driver"
															 : L"Fictional Broadcom audited driver" ;
			candidate.manufacturer	  = state_->asixPipeline ? L"ASIX" : L"Broadcom" ;
			candidate.model			  = state_->asixPipeline ? L"Fictional AX88179A Adapter"
															 : L"Fictional NetXtreme-E Adapter" ;
			candidate.driverClass	  = L"Net" ;
			candidate.provider		  = state_->asixPipeline ? L"ASIX" : L"Broadcom" ;
			candidate.version		  = L"2.0.0.0" ;
			candidate.driverDate	  = L"2026/09/06" ;
			candidate.sourceName =
				state_->asixPipeline ? L"ASIX AX88179A" : L"Broadcom NetXtreme-E" ;
			candidate.sourceLocation   = L"Official vendor package; locally audited" ;
			candidate.action		   = DriverAction::UPDATE ;
			candidate.discoveryBasis   = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
			candidate.audit			   = makeOfficialReadyCandidateAudit() ;
			candidate.installable	   = true ;
			candidate.eulaAccepted	   = true ;
			candidate.allContentCached = true ;
			report.publishedCandidates.push_back( std::move( candidate)) ;
		}

		report.candidates.push_back( std::move( row)) ;
		reports.push_back( std::move( report)) ;
	}

	return reports ;
}

//------------------------------------------------------------------------------
/**
 * @brief 監査DTOの通知と集約例外を分け、転送成功は失敗へ書き換えない。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------

void testWorkerAuditNotification( TestContext &context)
{
	// 正常集約と例外を別workerで検証し、共有状態を持ち越さない。
	for( const bool throwReport : {false, true}) {
		WorkerFixture fixture ;	// 実通信・実監査を行わないworker。
		fixture.state->emitAudit  = true ;
		fixture.state->throwAudit = throwReport ;
		DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( 1U)) ;
		const auto scanned = fixture.waitEvent( WorkerEventKind::SCAN_COMPLETED, 1U) ;	// 合成候補。
		DRIVERCRATE_EXPECT( context, scanned && scanned->preparationPlan) ;
		// 計画を取得できなければ監査DTOの通知試験を進めない。
		if( !scanned || !scanned->preparationPlan) {
			continue ;
		}

		const auto approval = workerApproval( *scanned->preparationPlan, 2U) ;	// 明示的な二対象取得。
		DRIVERCRATE_EXPECT( context, fixture.worker->requestPreparation( approval)) ;
		const auto completed =
			// 取得通知。
			fixture.waitEvent( WorkerEventKind::PREPARATION_COMPLETED, 2U) ;
		DRIVERCRATE_EXPECT( context, completed.has_value()) ;
		// 完了eventがない場合は結果DTOを参照しない。
		if( !completed) {
			continue ;
		}

		const auto &result = completed->preparationResult ;	// 非機密結果の非所有参照。
		DRIVERCRATE_EXPECT( context, result.items.size() == 3U) ;
		DRIVERCRATE_EXPECT( context, result.controlError ==
										(throwReport ? static_cast<NativeError>( E_UNEXPECTED) : 0)) ;
		DRIVERCRATE_EXPECT( context, result.auditReports.size() == (throwReport ? 0U : 2U)) ;
		DRIVERCRATE_EXPECT( context, validatePreparationAuditReports(
										result, approval, scanned->scanResult.candidates)) ;
		DRIVERCRATE_EXPECT( context, fixture.state->acquireCalls == 2U) ;
		DRIVERCRATE_EXPECT( context, fixture.state->installCalls == 0U) ;
		DRIVERCRATE_EXPECT( context, fixture.state->restoreCalls == 0U) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Fake導入の呼出し中は同じsessionを保持し、戻り・例外後は取得承認を失効させる。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------

void testWorkerPreparedLifetimeDuringInstall( TestContext &context)
{
	// 正常returnとProvider例外を分ける。OS変更処理は全てfakeへ注入する。
	for( const bool throwInstall : {false, true}) {
		WorkerFixture fixture ;	// Fake Providerとfake復旧serviceだけを所有するworker。
		fixture.state->allowFakeRestore = true ;
		fixture.state->throwInstall		= throwInstall ;
		DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( 1U)) ;
		const auto scanned =
			// 合成保持状態。
			fixture.waitEvent( WorkerEventKind::SCAN_COMPLETED, 1U) ;
		DRIVERCRATE_EXPECT( context, scanned && scanned->preparationPlan) ;
		// 計画を取得できなければ導入中のsession保持試験を進めない。
		if( !scanned || !scanned->preparationPlan) {
			continue ;
		}

		const std::vector<std::wstring> identities{
			L"fictional-selection"} ;	// 実driverでない選択ID。
		const InstallProtectionMode mode =
			isWindowsServer()
				? InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT
				: InstallProtectionMode::WINDOWS_RESTORE_POINT ;	// OS種別の読取だけを実施する。
		DRIVERCRATE_EXPECT( context,
						   fixture.worker->requestInstall( 2U, scanned->scanResult.scanSessionId,
														  identities, nullptr, mode)) ;
		const auto installed =
			// Fake結果。
			fixture.waitEvent( WorkerEventKind::INSTALL_COMPLETED, 2U) ;
		DRIVERCRATE_EXPECT( context, installed.has_value()) ;
		DRIVERCRATE_EXPECT( context, fixture.state->installCalls == 1U) ;
		DRIVERCRATE_EXPECT( context, fixture.state->retainedAtInstall) ;
		DRIVERCRATE_EXPECT( context, fixture.state->invalidations >= 2U) ;
		DRIVERCRATE_EXPECT( context, fixture.worker->requestPreparation(
										workerApproval( *scanned->preparationPlan, 3U))) ;
		const auto stale =
			// 旧承認要求。
			fixture.waitEvent( WorkerEventKind::PREPARATION_COMPLETED, 3U) ;
		DRIVERCRATE_EXPECT( context, stale && stale->preparationResult.approvalError !=
												 OfficialPreparationError::NONE) ;
		DRIVERCRATE_EXPECT( context, fixture.state->acquireCalls == 0U) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ監査済み候補契約を一系列のWorker eventとしてControllerへ渡し、検索から導入結果と旧session拒否までを確認する。実systemは変更しない。
 *
 * @param[in,out] context Assertionの集計先。
 * @param[in] asix trueならASIX、falseならBroadcom取得元の結合を確認する。
 */
//------------------------------------------------------------------------------
void testWorkerControllerPreparedPipeline( TestContext &context, const bool asix)
{
	WorkerFixture fixture ;	// 実通信・実監査・実導入を行わない一系列worker。
	fixture.state->asixPipeline		= asix ;
	fixture.state->emitAudit		= true ;
	fixture.state->emitPipeline		= true ;
	fixture.state->allowFakeRestore = true ;
	OperationController controller ;					// Worker eventを受けるUI状態機械。
	const BeginResult	scan = controller.beginScan() ;	// 最初の検索operation。
	DRIVERCRATE_EXPECT( context, scan.accepted) ;
	DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( scan.operationId)) ;
	const auto scanned =
		// 検索event。
		fixture.waitEvent( WorkerEventKind::SCAN_COMPLETED, scan.operationId) ;
	DRIVERCRATE_EXPECT( context, scanned && scanned->preparationPlan) ;
	// 不完全なeventから非所有planを参照しない。
	if( !scanned || !scanned->preparationPlan) {
		return ;
	}

	const ScanSessionId originalSession =
		scanned->scanResult.scanSessionId ;	// 導入後に拒否する旧scan session。
	DRIVERCRATE_EXPECT( context, controller.completeScan( scan.operationId, scanned->scanResult)) ;
	DRIVERCRATE_EXPECT( context,
					   controller.setPreparationPlan( scan.operationId, *scanned->preparationPlan)) ;

	OfficialPreparationApproval approval =
		// Controller採番前の全対象判断。
		workerApproval( *scanned->preparationPlan, 0U) ;
	const BeginResult preparation = controller.beginPreparation( approval) ;	// 取得開始結果。
	DRIVERCRATE_EXPECT( context, preparation.accepted) ;
	DRIVERCRATE_EXPECT( context, approval.operationId == preparation.operationId) ;
	DRIVERCRATE_EXPECT( context, fixture.worker->requestPreparation( approval)) ;
	const auto prepared = fixture.waitEvent( WorkerEventKind::PREPARATION_COMPLETED,
											preparation.operationId) ;	// 取得・監査event。
	DRIVERCRATE_EXPECT( context, prepared.has_value()) ;
	// 候補発行が不完全な場合は選択へ進めない。
	if( !prepared || prepared->preparationResult.auditReports.size() != 1U ||
	   prepared->preparationResult.auditReports.front().publishedCandidates.size() != 1U) {
		return ;
	}

	const std::wstring identity = prepared->preparationResult.auditReports.front()
									  .publishedCandidates.front()
									  .identity ;	// Controllerへ発行するopaque候補ID。
	DRIVERCRATE_EXPECT( context, controller.completePreparation( prepared->preparationResult,
															   scanned->scanResult.candidates)) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::SCAN_READY) ;
	const std::array<std::wstring, 1> selection{identity} ;	// 利用者の一device一候補選択。
	const InstallProtectionMode		  mode =
		  isWindowsServer()
				  ? InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT
				  : InstallProtectionMode::WINDOWS_RESTORE_POINT ;	// 実OSと一致するfake保護経路。
	const BeginResult denied =
		controller.beginInstall( originalSession, selection, InstallConfirmation::NOT_CONFIRMED,
								mode) ;	// 最終dialogの取消し。
	DRIVERCRATE_EXPECT( context, !denied.accepted) ;
	DRIVERCRATE_EXPECT( context, fixture.state->installCalls == 0U) ;
	const BeginResult install =
		controller.beginInstall( originalSession, selection, InstallConfirmation::CONFIRMED,
								mode) ;	// 明示導入開始結果。
	DRIVERCRATE_EXPECT( context, install.accepted) ;
	DRIVERCRATE_EXPECT( context, fixture.worker->requestInstall( install.operationId, originalSession,
															   selection, nullptr, mode)) ;
	const auto installed =
		// 導入event。
		fixture.waitEvent( WorkerEventKind::INSTALL_COMPLETED, install.operationId) ;
	DRIVERCRATE_EXPECT( context, installed.has_value()) ;
	// 欠落結果を成功としてControllerへ渡さない。
	if( !installed) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, installed->installResult.succeeded) ;
	DRIVERCRATE_EXPECT( context, installed->installResult.updates.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, installed->installResult.rebootRequired) ;
	DRIVERCRATE_EXPECT( context,
					   controller.completeInstall( install.operationId, installed->installResult)) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::COMPLETED) ;
	DRIVERCRATE_EXPECT( context, controller.scanSessionId() == 0U) ;
	DRIVERCRATE_EXPECT( context, fixture.state->installCalls == 1U) ;
	DRIVERCRATE_EXPECT( context, fixture.state->retainedAtInstall) ;
	DRIVERCRATE_EXPECT( context, !fixture.worker->requestPreparation( approval)) ;

	DRIVERCRATE_EXPECT( context, fixture.state->scanCalls == 1U) ;
	DRIVERCRATE_EXPECT( context, fixture.state->invalidations >= 2U) ;
	const BeginResult nextScan = controller.beginScan() ;	// 旧session拒否用の次検索。
	DRIVERCRATE_EXPECT( context, nextScan.accepted) ;
	DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( nextScan.operationId)) ;
	const auto rescanned =
		// 新検索event。
		fixture.waitEvent( WorkerEventKind::SCAN_COMPLETED, nextScan.operationId) ;
	DRIVERCRATE_EXPECT( context, rescanned.has_value()) ;
	// 新scan欠落時に古いsessionとの比較を続けない。
	if( !rescanned) {
		return ;
	}

	DRIVERCRATE_EXPECT( context,
					   controller.completeScan( nextScan.operationId, rescanned->scanResult)) ;
	const BeginResult stale =
		controller.beginInstall( originalSession, selection, InstallConfirmation::CONFIRMED,
								mode) ;	// 旧一覧からの再導入要求。
	DRIVERCRATE_EXPECT( context, !stale.accepted) ;
	DRIVERCRATE_EXPECT( context, stale.error == BeginError::STALE_SCAN_SESSION) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASIXの合成選択に対する復元開始失敗、正常終了、導入例外時の終了通知を検証する。
 *
 * @param[in,out] context Assertion結果の集計先。
 */
//------------------------------------------------------------------------------
void testAsixClientRestoreBoundary( TestContext &context)
{
	// 復元APIは呼ばず、保護層の開始・導入・終了順だけを三つの独立状態で確認する。
	for( int scenario = 0; scenario < 3; ++scenario)	// 0は正常、1は開始拒否、2は導入例外。
	{
		auto state				= std::make_shared<FakePreparationState>() ;	// 一回分のfake状態。
		state->asixPipeline		= true ;
		state->emitPipeline		= true ;
		state->allowFakeRestore = scenario != 1 ;
		state->throwInstall		= scenario == 2 ;
		FakePreparationProvider		   provider( state) ;								// 実ドライバーを変更しないProvider。
		FakePreparationRestoreService  restore( state) ;								// 実復元ポイントを作らないservice。
		const ProviderProgressCallback progress = []( const ProviderProgress &) {} ;	// 待機なし通知。
		const ScanResult scanned = provider.scan( 101U, {}, progress) ;					// 同一scanを保持する。
		DRIVERCRATE_EXPECT( context, scanned.succeeded) ;
		const std::array<std::wstring, 1> identities{L"prepared:target:0"} ;	// 合成明示選択。
		// Fake復元ポイントとProviderで検証するASIX選択導入の結果。
		const InstallResult result = installWithRestorePoint( provider, restore, 101U, identities,
															 0U, progress, L"Fictional ASIX test") ;
		DRIVERCRATE_EXPECT( context, result.succeeded == (scenario == 0)) ;
		DRIVERCRATE_EXPECT( context, state->installCalls == (scenario == 1 ? 0U : 1U)) ;
		DRIVERCRATE_EXPECT( context, state->restoreCalls == (scenario == 1 ? 1U : 2U)) ;
		DRIVERCRATE_EXPECT( context,
						   result.protectionMode == InstallProtectionMode::WINDOWS_RESTORE_POINT) ;
		// 導入例外scenarioでは例外が共通診断値へ変換されることを確認する。
		if( scenario == 2) {
			DRIVERCRATE_EXPECT( context,
							   result.installError == static_cast<NativeError>( E_UNEXPECTED)) ;
		}
	}
}

/** @brief 空のload結果だけを使うworker refresh接続の非通信Providerです。 */
class RefreshProbeProvider final : public IUpdateProvider, public IIndexScanInventory {
public:
	/** @brief 既存非通信scanの状態だけを共有します。
	 * @param[in] state 同workerを停止するまで所有するfake状態です。
	 */
	explicit RefreshProbeProvider( std::shared_ptr<FakePreparationState> state)
		: inner_( std::move( state))
	{
	}
	/** @brief 既存fakeだけへ通常scanを委譲します。
	 * @param[in] session 元worker sessionです。
	 * @param[in] options 元の有限Provider選択です。
	 * @param[in] progress 元同期通知です。
	 * @return 実inventoryを含まない元scanです。
	 */
	ScanResult scan( ScanSessionId session, const ScanOptions &options,
					const ProviderProgressCallback &progress) override
	{
		return inner_.scan( session, options, progress) ;
	}
	/** @brief 導入を実行せず元fake結果だけを返します。
	 * @param[in] session 元fake sessionです。
	 * @param[in] ids 元fake対象です。
	 * @param[in] parent 未使用の親window値です。
	 * @param[in] progress 元fake通知です。
	 * @return 元fake結果です。実APIを呼びません。
	 */
	InstallResult install( ScanSessionId session, std::span<const std::wstring> ids,
						  std::uintptr_t parent, const ProviderProgressCallback &progress) override
	{
		return inner_.install( session, ids, parent, progress) ;
	}
	/** @brief 空store負例の後段でresolverを捏造しません。
	 * @param[in] operation 未使用の元operationです。
	 * @param[out] context 空へ初期化します。
	 * @param[out] present 空へ初期化します。
	 * @return 常にnullptrです。空storeでは到達しません。
	 */
	std::unique_ptr<IndexPublicIdResolver> indexScanInventory(
		OperationId operation, IndexLookupContext &context,
		std::vector<std::wstring> &present) override
	{
		static_cast<void>( operation) ;
		context = {} ;
		present.clear() ;
		return nullptr ;
	}

private:
	/// 通信・在庫・導入を使わない元fakeの所有です。
	FakePreparationProvider inner_ ;
} ;

/** @brief 固定W01–W07を実worker queueの元終端で照合します。
 * @param[in,out] context 旧assertionを保持する集計先です。
 */
void testWorkerRefreshConnection( TestContext &context)
{
	// 七条件は分母から除外せず一workerずつ停止してから次へ進みます。
	for( unsigned mode = 0U; mode < 7U; ++mode) {
		const auto	  before = context.failureCount() ;	// この固定条件の開始失敗数です。
		WorkerFixture fixture ;							// 早期returnでもstopする所有者です。
		fixture.worker->stop() ;
		unsigned			 refreshes{} ;	// Worker terminal後だけ観測する呼出し数です。
		unsigned			 loads{} ;		// Worker terminal後だけ観測するlocal read数です。
		bool				 currentUtc{} ;	// Refresh後の現在UTCをloadへ渡した事実です。
		std::chrono::seconds elapsed{} ;	// 実待機のない90秒refresh時計です。
		provider_worker_index_detail::Services services{
			.load =
				[&]( auto now) {
					++loads ;
					currentUtc = now == std::optional{std::chrono::sys_seconds{elapsed}} ;
					return IndexStoreResult{.status = IndexStoreStatus::EMPTY_STORE} ;
				},
			.utc	   = [&]() { return std::optional{std::chrono::sys_seconds{elapsed}} ; },
			.monotonic = [&]() { return std::chrono::steady_clock::time_point{elapsed} ; },
			.refresh =
				[&]( const ProviderScanCancellation &) {
					++refreshes ;
					elapsed += std::chrono::seconds{90} ;
					IndexRefreshSummary result{
						.status = IndexRefreshStatus::REFRESHED} ;	// Fake境界だけの観測です。
					// 暗号拒否をlocal cacheの再読取りへ流しません。
					if( mode == 2U) {
						result.status = IndexRefreshStatus::MANIFEST_REJECTED ;
						result.error  = static_cast<NativeError>( E_ACCESSDENIED) ;
					}

					// 明示cacheでも元HTTP失敗を保持します。
					if( mode == 3U) {
						result.status				  = IndexRefreshStatus::AUTHENTICATED_CACHE ;
						result.error				  = static_cast<NativeError>( E_FAIL) ;
						result.httpError			  = static_cast<NativeError>( E_FAIL) ;
						result.usedAuthenticatedCache = true ;
					}

					// 同workerからの取消しもmutex外で有限に受理しcommit事実を残します。
					if( mode == 4U) {
						result.store.commit = IndexStoreCommitDisposition::COMMITTED ;
						static_cast<void>( fixture.worker->requestScanCancel( 1U)) ;
					}

					return result ;
				}} ;
		// 欠損fixtureは製品loadやrefreshへ補完しません。
		if( mode == 5U) {
			services.load = {} ;
		}

		fixture.worker = provider_worker_index_detail::Access::create(
			[state = fixture.state]() { return std::make_unique<RefreshProbeProvider>( state) ; },
			[state = fixture.state]() {
				return std::make_unique<FakePreparationRestoreService>( state) ;
			},
			std::move( services)) ;
		ScanOptions options{
			.useDefaultProviders = false,
			.enabledProviderIds	 = {std::wstring{
				 mode == 1U ? DRIVER_STORE_PROVIDER_ID
							: SIGNED_INDEX_PROVIDER_ID}}} ;	// 無効caseも正規registry集合です。
		DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( 1U, options)) ;
		auto terminal = fixture.waitEvent( WorkerEventKind::SCAN_COMPLETED, 1U) ;	// 実queue終端です。
		DRIVERCRATE_EXPECT( context, terminal.has_value()) ;
		// 未到達を後段成功として数えません。
		if( terminal) {
			DRIVERCRATE_EXPECT( context, refreshes == (mode == 1U || mode == 5U ? 0U : 1U)) ;
			DRIVERCRATE_EXPECT(
				context, loads == (mode == 1U || mode == 2U || mode == 4U || mode == 5U ? 0U : 1U)) ;
			DRIVERCRATE_EXPECT( context, loads == 0U || currentUtc) ;
			DRIVERCRATE_EXPECT( context, terminal->indexSummary.status ==
											(mode == 1U	  ? IndexScanStatus::NOT_RUN
											 : mode == 2U ? IndexScanStatus::LOAD_REJECTED
											 : mode == 4U ? IndexScanStatus::CANCELLED
											 : mode == 5U ? IndexScanStatus::INTERNAL_FAILURE
														  : IndexScanStatus::EMPTY_STORE)) ;
			// 部分失敗でも独立したProvider成功と元refresh errorを同時に保持します。
			if( mode == 2U || mode == 3U) {
				DRIVERCRATE_EXPECT( context, terminal->scanResult.succeeded &&
												terminal->indexSummary.refresh &&
												terminal->indexSummary.refresh->error != 0) ;
			}

			// 取消しでcommit済みの事実自体を消しません。
			if( mode == 4U) {
				DRIVERCRATE_EXPECT( context, terminal->indexSummary.refresh &&
												terminal->indexSummary.refresh->store.commit ==
													IndexStoreCommitDisposition::COMMITTED) ;
			}

			// 二回目は旧sessionを再利用せず一回だけrefreshします。
			if( mode == 6U) {
				const auto firstSession = terminal->scanResult.scanSessionId ;	// 旧確定sessionです。
				DRIVERCRATE_EXPECT( context, fixture.worker->requestScan( 2U, options)) ;
				terminal = fixture.waitEvent( WorkerEventKind::SCAN_COMPLETED, 2U) ;
				DRIVERCRATE_EXPECT( context,
								   terminal && terminal->scanResult.scanSessionId != firstSession &&
									   refreshes == 2U && loads == 2U) ;
			}
		}

		fixture.worker->stop() ;
		std::cout << "P5 worker W0" << mode + 1U << " reached=" << terminal.has_value()
				  << " refreshes=" << refreshes << " loads=" << loads
				  << " failures=" << context.failureCount() - before << '\n' ;
	}
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/provider_preparation_worker_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runProviderPreparationWorkerTests( TestContext &context)
{
	testWorkerRefreshConnection( context) ;
	testWorkerPlanAndPreparation( context) ;
	testWorkerStaleAndInstallInvalidation( context) ;
	testWorkerActiveCancellationAndStop( context) ;
	testWorkerScanCancellationAndApprovalBinding( context) ;
	testWorkerQueueBoundsAndQueuedCancel( context) ;
	testWorkerInvalidPlanIsSeparate( context) ;
	testWorkerMeasurementPublicationBoundary( context) ;
	testWorkerAuditNotification( context) ;
	testWorkerPreparedLifetimeDuringInstall( context) ;
	testWorkerControllerPreparedPipeline( context, false) ;
	testWorkerControllerPreparedPipeline( context, true) ;
	testAsixClientRestoreBoundary( context) ;
}

} // namespace drivercrate::test
