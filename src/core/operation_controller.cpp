//------------------------------------------------------------------------------
/**
 * @file operation_controller.cpp
 * @brief 操作状態管理実装。
 * @version 01.05.01
 * @date 2026/09/01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  候補検証loopの目的を明示。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Install最終確認の明示拒否を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  取得後候補の導入許可を原子的に反映。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  監査合格候補の導入許可を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の表示境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得確認と独立した操作状態を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  関数comment形式統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  復元ポイント状態追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  反復進捗通知受理追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Server用install保護mode追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Scan計測snapshotのoperation照合を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  観測結合と初回actionの導入権限を検証。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  通常scanの協調取消し遷移を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.04.00 Shunji Ogawa  2026/11/10  対象限定の完了更新と未処理所有・本体再検証を接続。
 * Ver.01.05.00 Shunji Ogawa  2026/11/10  最新実確認の選択表示と日内復元保護の実在再利用を接続。
 * Ver.01.05.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 *
 * @note Operationの状態遷移と候補identityのfail-closed検証を実装します。
 */
//------------------------------------------------------------------------------

#include "core/protected_install.h"
#include "core/operation_controller.h"
#include "core/update_provider.h"
#include "core/candidate_audit.h"
#include "core/metadata_search.h"
#include "core/provider_registry.h"
#include "core/official_preparation_audit.h"
#include "core/scan_measurement.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 成功として受理できる Provider outcome かを判定する。
 *
 * @param[in] outcome 判定対象の結果分類。
 * @return 成功または警告付き成功の場合は `true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSuccessOutcome( const OutcomeCode outcome) noexcept
{
	return outcome == OutcomeCode::SUCCESS || outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未選択取得、重複、非終端結果を拒否する。制御系異常の結果欠落は成功表示しない。
 *
 * @param[in] result 取得操作の完了内容。
 * @param[in] approval 開始時に固定した承認snapshot。
 * @return 全対象の終端状態が承認と整合する場合true。
 */
//------------------------------------------------------------------------------
bool validPreparationResult( const OfficialPreparationOperationResult &result,
							const OfficialPreparationApproval		 &approval)
{
	// 未定義の制御状態を正当な完了と扱わない。
	if( result.controlError > 0 || result.approvalError < OfficialPreparationError::NONE ||
	   result.approvalError > OfficialPreparationError::BUDGET_EXCEEDED) {
		return false ;
	}

	// 承認拒否後の取得結果を拒否する。
	if( result.approvalError != OfficialPreparationError::NONE) {
		return result.items.empty() ;
	}

	// 操作エラーを表示し、取得成功を表示しない。
	if( result.controlError < 0 && result.items.empty()) {
		return true ;
	}

	// 部分失敗でも全対象の結果が必要である。
	if( result.items.size() != approval.decisions.size()) {
		return false ;
	}

	std::unordered_set<std::wstring> seen ;	// 重複した完了通知を拒否する対象集合。
	// 承認の順序に依存せず、一対象一結果と未選択対象の未取得を検証する。
	for( const OfficialPreparationItem &item : result.items) {
		const auto decision = std::find_if(	// 対応する開始時の対象snapshot。
			approval.decisions.begin(), approval.decisions.end(),
			[&]( const OfficialPreparationDecision &entry) {
				return entry.target.identity == item.identity ;
			}) ;
		// 承認にない対象や重複通知を拒否し、取得結果を選択対象へ一対一で対応させる。
		if( decision == approval.decisions.end() || !seen.insert( item.identity).second) {
			return false ;
		}

		// 未選択対象には未実行の結果だけを許可し、暗黙の取得を正常扱いにしない。
		if( !decision->acquire) {
			// 未選択対象の取得を成功として表示しない。
			if( item.result.state != OfficialPreparationItemState::NOT_SELECTED ||
			   item.result.error != 0 || item.result.byteCount != 0) {
				return false ;
			}

			continue ;
		}

		// 取得成功の通知には実byte数とerrorの整合を要求し、状態名だけでは信用しない。
		if( item.result.state == OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION) {
			// 成功errorと承認済み上限に矛盾する取得通知を拒否する。
			if( item.result.error != 0 || item.result.byteCount == 0 ||
			   item.result.byteCount > decision->target.maximumBytes) {
				return false ;
			}
		}
		// LOCAL成功は新しい明示承認taskの実claim照合票だけを受理します。
		else if( item.result.state == OfficialPreparationItemState::LOCAL_INSPECTION_COMPLETED) {
			const OfficialPreparationTask task{
				approval.operationId, approval.scanSessionId, approval.planId, decision->target,
				decision->restrictedNetworkApproved} ;	// 元承認全文です。
			// flagだけや取得byte再発行を拒否します。
			if( item.result.error != 0U || item.result.byteCount != 0U ||
			   !item.result.localInspection || !item.result.localInspection->matches( task)) {
				return false ;
			}
		}
		// 未完了、定義外、エラーなし失敗、失敗時の成功byteを拒否する。
		else if( item.result.state < OfficialPreparationItemState::AWAITING_NETWORK_CONSENT ||
				item.result.state > OfficialPreparationItemState::FAILURE ||
				item.result.error >= 0 || item.result.byteCount != 0) {
			return false ;
		}
	}

	return true ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 新しい scan operation を開始する。
 * @return 受付時は新しい operation ID、拒否時は理由を含む結果。
 */
//------------------------------------------------------------------------------
BeginResult OperationController::beginScan()
{
	// 停止開始後に Provider へ新しい command が到達しないよう拒否する。
	if( state_ == ApplicationState::STOPPING) {
		return {.error = BeginError::STOPPING} ;
	}

	// 同時 operation による WUA collection の競合を防ぐ。
	if( state_ == ApplicationState::SCANNING || state_ == ApplicationState::CANCELLING_SCAN ||
	   state_ == ApplicationState::CREATING_RESTORE_POINT ||
	   state_ == ApplicationState::PREPARING ||
	   state_ == ApplicationState::CANCELLING_PREPARATION ||
	   state_ == ApplicationState::CANCELLING_METADATA_SEARCH ||
	   state_ == ApplicationState::DOWNLOADING || state_ == ApplicationState::INSTALLING) {
		return {.error = BeginError::BUSY} ;
	}

	OperationId operationId{} ;	// 今回のscanへ割り当てる0以外のoperation ID。
	// operation IDの上限に達したら再利用せず、新しい検索の開始を拒否する。
	if( !allocateOperationId( operationId)) {
		return {.error = BeginError::ID_EXHAUSTED} ;
	}

	static_cast<void>( preparationSession_.invalidate()) ;
	preparationPlan_.reset() ;
	originalPreparationPlan_.reset() ;
	scanReferenceScopes_.clear() ;
	retainedReferenceIdentities_.clear() ;
	candidateIdentities_.clear() ;
	candidateDevices_.clear() ;
	activeInstallIdentities_.clear() ;
	scanSessionId_ = 0 ;
	scanMeasurement_.reset() ;
	scanPurpose_ = ScanPurpose::STANDARD ;
	metadataSearchRequest_.reset() ;
	metadataSearchSummary_.reset() ;
	activeOperationId_ = operationId ;
	state_			   = ApplicationState::SCANNING ;
	return {.accepted = true, .operationId = operationId} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ通常scanだけを協調取消し結果待ちへ移す。
 * @param[in] operationId Workerへ取消しを要求した操作ID。
 * @return 現在の通常scanへ適用した場合true。
 */
//------------------------------------------------------------------------------
bool OperationController::markScanCancelling( const OperationId operationId) noexcept
{
	// 情報検索、古い操作、開始前または終端済みscanを通常scan取消しへ読み替えない。
	if( scanPurpose_ != ScanPurpose::STANDARD || operationId != activeOperationId_ ||
	   state_ != ApplicationState::SCANNING) {
		return false ;
	}

	state_ = ApplicationState::CANCELLING_SCAN ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider から返された scan 完了を現在の operation へ反映する。Provider から返された scan 完了を現在の operationへ反映する。 注記
 *        : 遅延した古い resultは状態を変更せず拒否する。現在 operation の不正な成功結果は`FAILURE` として適用する。
 * @param[in] operationId 完了対象の operation ID。
 * @param[in] result Provider が返した scan 結果。
 * @return 現在の operation に適用した場合は `true`。
 * @note 遅延した古い result は状態を変更せず拒否する。現在 operation の不正な成功結果は`FAILURE` として適用する。
 */
//------------------------------------------------------------------------------
bool OperationController::completeScan( const OperationId operationId, const ScanResult &result)
{
	// 遅延した result が新しい画面状態を上書きしないよう、state と ID の両方を照合する。
	const bool cancelling = state_ == ApplicationState::CANCELLING_SCAN ;	// 利用者取消し待ち状態。
	// 実行中または取消し待ちの同じ通常scanだけを終端させる。
	if( (state_ != ApplicationState::SCANNING && !cancelling) || operationId != activeOperationId_ ||
	   scanPurpose_ != ScanPurpose::STANDARD) {
		return false ;
	}

	candidateIdentities_.clear() ;
	candidateDevices_.clear() ;
	scanSessionId_ = 0 ;
	// 取消し待ちはABORTEDの非成功結果だけを正常な取消し終端として受理する。
	if( cancelling) {
		state_ = !result.succeeded && result.purpose == ScanPurpose::STANDARD &&
						 result.outcome == OutcomeCode::ABORTED && !result.metadataSearch
					 ? ApplicationState::IDLE
					 : ApplicationState::FAILURE ;
		return true ;
	}

	// 検索失敗は候補なしの正常終了と区別し、導入待ち状態へ進めない。
	if( !result.succeeded || result.purpose != ScanPurpose::STANDARD || result.metadataSearch) {
		state_ = ApplicationState::FAILURE ;
		return true ;
	}

	// 0 session または矛盾した outcome を成功候補として UI へ公開しない。
	if( result.scanSessionId == 0 || !isSuccessOutcome( result.outcome) ||
	   !isCandidateDetailsSetValid( result.candidates, result.scanSessionId)) {
		state_ = ApplicationState::FAILURE ;
		return true ;
	}

	// 全表示候補の identity を検証し、実行可能な候補だけを install 許可集合へ加える。
	std::unordered_set<std::wstring> displayedIdentities ;	// 重複を含まない全表示identity。
	displayedIdentities.reserve( result.candidates.size()) ;
	// 全表示候補を一度ずつ検証し、重複のない導入可能identityとdevice対応だけを保持する。
	for( const UpdateCandidate &candidate : result.candidates) {
		// 候補IDやdevice対応が曖昧なら許可集合を破棄し、一部候補だけの導入を許可しない。
		if( candidate.identity.empty() || candidate.deviceIdentity.empty() ||
		   !displayedIdentities.insert( candidate.identity).second) {
			candidateIdentities_.clear() ;
			candidateDevices_.clear() ;
			state_ = ApplicationState::FAILURE ;
			return true ;
		}

		// Providerが導入可能とした候補だけを、後の選択照合に使う許可集合へ登録する。
		if( candidate.installable) {
			candidateIdentities_.insert( candidate.identity) ;
			candidateDevices_.emplace( candidate.identity, candidate.deviceIdentity) ;
		}
	}

	scanSessionId_ = result.scanSessionId ;
	// 計測の矛盾は正常候補の権限へ波及させず、計測snapshotだけを公開対象から外す。
	if( isPublishedScanMeasurementValid( operationId, result)) {
		scanMeasurement_ = result.measurement ;
	} else {
		scanMeasurement_.reset() ;
	}

	scanReferenceScopes_.clear() ;
	retainedReferenceIdentities_.clear() ;
	originalPreparationPlan_.reset() ;
	// 元scan参照は実行permitと分離してscopeだけを凍結します。
	for( const auto &candidate : result.candidates) {
		// 現在行/取得対象のないmetadataを後から権限へ使いません。
		if( !candidate.current && !candidate.preparationTargetIdentity.empty()) {
			scanReferenceScopes_.emplace(
				candidate.identity,
				std::pair{candidate.deviceIdentity, candidate.preparationTargetIdentity}) ;
		}
	}

	state_ = ApplicationState::SCAN_READY ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在の scan 候補から install operation を開始する。
 * @param[in] scanSessionId 選択元として UI が保持する scan session ID。
 * @param[in] identities 利用者が選択した opaque update identity 群。 利用者が選択した opaque update identity群。
 * @param[in] confirmation 表示中の選択集合に対する今回限りの最終確認状態。 選択集合への今回限りの最終確認状態。
 * @param[in] protectionMode OSと利用者確認に対応するinstall保護方針。 OS別のinstall保護方針。
 * @return 受付時は新しい operation ID、拒否時は理由を含む結果。
 */
//------------------------------------------------------------------------------
BeginResult OperationController::beginInstall( const ScanSessionId				  scanSessionId,
											  const std::span<const std::wstring> identities,
											  const InstallConfirmation			  confirmation,
											  const InstallProtectionMode		  protectionMode)
{
	// 停止開始後に選択内容を Provider へ渡さない。
	if( state_ == ApplicationState::STOPPING) {
		return {.error = BeginError::STOPPING} ;
	}

	// 検索・取得・保護・導入の実行中は、別の導入operationを重ねて開始しない。
	if( state_ == ApplicationState::SCANNING || state_ == ApplicationState::CANCELLING_SCAN ||
	   state_ == ApplicationState::CREATING_RESTORE_POINT ||
	   state_ == ApplicationState::PREPARING ||
	   state_ == ApplicationState::CANCELLING_PREPARATION ||
	   state_ == ApplicationState::CANCELLING_METADATA_SEARCH ||
	   state_ == ApplicationState::DOWNLOADING || state_ == ApplicationState::INSTALLING) {
		return {.error = BeginError::BUSY} ;
	}

	// 有効な検索完了状態がない場合は、保持された表示行だけで導入を開始させない。
	if( state_ != ApplicationState::SCAN_READY || scanSessionId_ == 0 ||
	   scanPurpose_ != ScanPurpose::STANDARD) {
		return {.error = BeginError::NO_SCAN_RESULT} ;
	}

	// 明示確認以外の値ではoperationを発行せず、取消しや不正値を同意と解釈しない。
	if( confirmation != InstallConfirmation::CONFIRMED) {
		// 取消しや定義外値からoperation IDを発行し、workerへ到達させない。
		return {.error = BeginError::CONFIRMATION_REQUIRED} ;
	}

	// UI の古い一覧から現在の Provider session を操作できないよう拒否する。
	if( scanSessionId != scanSessionId_) {
		return {.error = BeginError::STALE_SCAN_SESSION} ;
	}

	// 対象を一件も選んでいない要求では、保護処理やProviderを開始しない。
	if( identities.empty()) {
		return {.error = BeginError::EMPTY_SELECTION} ;
	}

	// 定義外の保護modeを拒否し、復元ポイントやServer確認の境界を迂回させない。
	if( protectionMode != InstallProtectionMode::WINDOWS_RESTORE_POINT &&
	   protectionMode != InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT) {
		// 定義外の値で復元ポイント契約を迂回できないよう、operation開始前に拒否する。
		return {.error = BeginError::INVALID_PROTECTION_MODE} ;
	}

	std::unordered_set<std::wstring> selectedIdentities ;	// 重複検証済みの選択identity集合。
	selectedIdentities.reserve( identities.size()) ;
	std::unordered_set<std::wstring> selectedDevices ;	// 一device一候補を検証するdevice集合。
	selectedDevices.reserve( identities.size()) ;

	// 各 identity が現在の scan で提示済みか、一度だけ選択されたかを検証する。
	for( const std::wstring &identity : identities) {
		// 同じ候補を重複指定した要求を拒否し、二重導入をProviderへ渡さない。
		if( !selectedIdentities.insert( identity).second) {
			return {.error = BeginError::DUPLICATE_IDENTITY} ;
		}

		// 今回の検索で導入を許可していない候補IDは、表示名などから補完しない。
		if( !candidateIdentities_.contains( identity)) {
			return {.error = BeginError::UNKNOWN_IDENTITY} ;
		}

		// Identityに対応するdeviceの検索結果。
		const auto device = candidateDevices_.find( identity) ;
		// device対応を解決できない候補は、一device一候補の検証に通さない。
		if( device == candidateDevices_.end()) {
			return {.error = BeginError::UNKNOWN_IDENTITY} ;
		}

		// 一つのdeviceへ複数版を導入する要求を拒否し、暗黙の実行順で解決しない。
		if( !selectedDevices.insert( device->second).second) {
			// 一 device へ複数版を連続導入する曖昧な command を Provider へ渡さない。
			return {.error = BeginError::DUPLICATE_DEVICE_SELECTION} ;
		}
	}

	OperationId operationId{} ;	// 今回のinstallへ割り当てる0以外のoperation ID。
	// operation IDを一意に発行できない場合は、保護処理や導入を開始しない。
	if( !allocateOperationId( operationId)) {
		return {.error = BeginError::ID_EXHAUSTED} ;
	}

	static_cast<void>( preparationSession_.invalidate()) ;
	preparationPlan_.reset() ;
	activeOperationId_			 = operationId ;
	activeInstallIdentities_	 = std::move( selectedIdentities) ;
	activeInstallProtectionMode_ = protectionMode ;
	state_						 = ApplicationState::CREATING_RESTORE_POINT ;
	return {.accepted = true, .operationId = operationId} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 復元ポイント開始後に現在のoperationをdownload段階へ進める。
 * @param[in] operationId 対象operation ID。
 * @return 現在の復元ポイント作成operationに適用した場合は`true`。
 */
//------------------------------------------------------------------------------
bool OperationController::markDownloading( const OperationId operationId)
{
	// 復元ポイント作成以外の段階や古いoperationからdownloadへ遷移させない。
	if( (state_ != ApplicationState::CREATING_RESTORE_POINT &&
		state_ != ApplicationState::DOWNLOADING) ||
	   operationId != activeOperationId_) {
		return false ;
	}

	state_ = ApplicationState::DOWNLOADING ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 復元ポイント開始またはdownload完了後にinstall段階へ進める。
 * @param[in] operationId 対象 operation ID。
 * @return 現在の保護付きoperationに適用した場合は`true`。
 */
//------------------------------------------------------------------------------
bool OperationController::markInstalling( const OperationId operationId)
{
	// Local候補はdownloadを省略できるため、復元ポイント作成直後からの遷移も許可する。
	if( (state_ != ApplicationState::CREATING_RESTORE_POINT &&
		state_ != ApplicationState::DOWNLOADING && state_ != ApplicationState::INSTALLING) ||
	   operationId != activeOperationId_) {
		return false ;
	}

	state_ = ApplicationState::INSTALLING ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief install operation の最終結果を状態へ反映する。install operation の最終結果を状態へ反映する。 注記:成功結果は開始時 selection と
 *        identityが完全一致する場合だけ受理する。
 * @param[in] operationId 対象 operation ID。
 * @param[in] result workerが返した復元ポイントとupdateごとの最終結果。
 * @param[in] retention 当該操作の実ownerが保持する元subsetです。空では従来の全失効です。
 * @return 現在の operation に適用した場合は `true`。
 * @note 成功結果は開始時 selection と identity が完全一致する場合だけ受理する。
 */
//------------------------------------------------------------------------------
bool OperationController::completeInstall( const OperationId					   operationId,
										  const InstallResult				  &result,
										  const InstallRetentionSummary *const retention)
{
	// 復元ポイントまたはdownload段階でfail-closedに終了できるため各実行stateから受け付ける。
	if( (state_ != ApplicationState::CREATING_RESTORE_POINT &&
		state_ != ApplicationState::DOWNLOADING && state_ != ApplicationState::INSTALLING) ||
	   operationId != activeOperationId_) {
		return false ;
	}

	// trueの場合は個別resultが開始時selectionと一致している。
	bool validResult = result.updates.size() == activeInstallIdentities_.size() ;
	std::unordered_set<std::wstring> resultIdentities ;	// 重複検証済みのresult identity集合。
	resultIdentities.reserve( result.updates.size()) ;

	// Provider の success 表示を、開始時 selection と完全一致する個別結果で裏付ける。
	for( const UpdateExecutionResult &update : result.updates) {
		// 未選択IDや重複を含む導入結果は無効とし、正常な全件結果として反映しない。
		if( update.identity.empty() || !resultIdentities.insert( update.identity).second ||
		   !activeInstallIdentities_.contains( update.identity)) {
			validResult = false ;
		}

		// 個別の取得または導入失敗を含む結果を、全体成功のflagで覆い隠さない。
		if( result.succeeded &&
		   (!isSuccessOutcome( update.downloadOutcome) ||
			(update.installerHandoff
				 ? update.installOutcome != OutcomeCode::NOT_STARTED || update.installError != 0 ||
					   !isSuccessOutcome( update.handoffOutcome) || update.handoffError != 0 ||
					   !update.installerExitCode
				 : !isSuccessOutcome( update.installOutcome)))) {
			validResult = false ;
		}

		// 標準INF結果へinstallerの成功・終了codeを混入させません。
		if( !update.installerHandoff && (update.handoffOutcome != OutcomeCode::NOT_STARTED ||
										update.handoffError != 0 || update.installerExitCode)) {
			validResult = false ;
		}
	}

	// 開始時の保護方針と結果が一致し、方針ごとの復元ポイント契約を満たす必要がある。
	const bool protectionModeMatches = result.protectionMode == activeInstallProtectionMode_ ;
	const bool restorePointResultValid =
		// 作成と実在再利用を分岐検証します。
		isRestorePointProtectionValid( result) ;

	// 保護modeや復元ポイント、取得・導入結果に矛盾する全体成功を拒否する。
	if( result.succeeded &&
	   (!protectionModeMatches || !restorePointResultValid ||
		!isSuccessOutcome( result.downloadOutcome) || !isSuccessOutcome( result.installOutcome))) {
		validResult = false ;
	}

	// Provider成功とidentity契約の両方を満たす最終成功判定。
	const bool succeeded  = result.succeeded && validResult ;
	lastInstallSucceeded_ = succeeded ;
	bool retained		  = validResult && retention && retention->operationId == operationId &&
					retention->scanSessionId == scanSessionId_ && scanSessionId_ != 0U &&
					retention->candidates.size() <= candidateIdentities_.size() &&
					retention->references.size() <= scanReferenceScopes_.size() &&
					(retention->references.empty() || retention->preparationPlan.has_value()) &&
					(retention->providerEntered || !result.succeeded) ;	// 元所有の証明だけです。
	std::unordered_set<std::wstring> remaining ;						// 全件検証後だけ置換する元subsetです。
	std::unordered_map<std::wstring, std::wstring> remainingDevices ;	// 元対応を変更しません。
	std::unordered_set<std::wstring> selectedDevices ;					// 他候補経由の同device再実行も拒否します。
	// 元開始selectionだけから消費対象を求めます。
	for( const auto &identity : activeInstallIdentities_) {
		selectedDevices.insert( candidateDevices_.at( identity)) ;
	}

	// Providerが返した全残存候補を元許可と一対一照合します。
	if( retained) {
		// 元集合の各要素を同じscopeへ一度ずつ照合します。
		for( const auto &candidate : retention->candidates) {
			const auto original = candidateDevices_.find( candidate.identity) ;	// 元発行だけです。
			// 新candidate/deviceや重複、消費deviceを継続へ追加しません。
			if( !candidateIdentities_.contains( candidate.identity) ||
			   original == candidateDevices_.end() ||
			   original->second != candidate.deviceIdentity ||
			   !remaining.insert( candidate.identity).second ||
			   (retention->providerEntered && selectedDevices.contains( candidate.deviceIdentity))) {
				retained = false ;
				break ;
			}

			remainingDevices.emplace( candidate.identity, candidate.deviceIdentity) ;
		}
	}

	std::unordered_set<std::wstring> references ;	// 原参照subsetだけです。
	// 新しい参照や消費deviceを残planへ追加しません。
	if( retained) {
		// 元集合の各要素を同じscopeへ一度ずつ照合します。
		for( const auto &reference : retention->references) {
			const auto origin = scanReferenceScopes_.find( reference.identity) ;	// 元scanの結合です。
			// 元scopeの一対一subsetだけを許します。
			if( origin == scanReferenceScopes_.end() ||
			   origin->second.first != reference.deviceIdentity ||
			   !references.insert( reference.identity).second ||
			   (retention->providerEntered && selectedDevices.contains( reference.deviceIdentity))) {
				retained = false ;
				break ;
			}
		}
	}

	retainedReferenceIdentities_.clear() ;
	// 残参照は全件検証後だけ公開します。
	if( retained) {
		retainedReferenceIdentities_.swap( references) ;
	}

	// 継続を証明できない場合も原導入結果を失敗へ改作しません。
	if( retained) {
		candidateIdentities_.swap( remaining) ;
		candidateDevices_.swap( remainingDevices) ;
	} else {
		candidateIdentities_.clear() ;
		candidateDevices_.clear() ;
	}

	activeInstallIdentities_.clear() ;
	activeInstallProtectionMode_ = InstallProtectionMode::WINDOWS_RESTORE_POINT ;
	// 未失効の元scanだけを次の明示操作へ保持します。
	if( !retained) {
		scanSessionId_ = 0 ;
	}

	state_ = retained ? ApplicationState::SCAN_READY
					  : (succeeded ? ApplicationState::COMPLETED : ApplicationState::FAILURE) ;
	// 原plan/予算/scope検証に失敗した参照だけを保留し、原導入結果は保ちます。
	if( retained && retention->preparationPlan &&
	   !setRemainingPreparationPlan( operationId, scanSessionId_, *retention->preparationPlan)) {
		retainedReferenceIdentities_.clear() ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原参照の残存scopeだけを照合します。
 * @param[in] identity 元発行の参照です。
 * @return 未処理planへ結合している場合trueです。
 */
//------------------------------------------------------------------------------
bool OperationController::isPreparationReferenceAllowed( const std::wstring_view identity) const
{
	return state_ == ApplicationState::SCAN_READY && scanSessionId_ != 0U && preparationPlan_ &&
		   retainedReferenceIdentities_.contains( std::wstring{identity}) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 当該終端に限り新IDの残planを原subsetへ照合します。
 * @param[in] operationId 受理した直前Install操作です。
 * @param[in] session 未失効の元scanです。
 * @param[in] plan 原metadata/予算のsubsetです。
 * @return 一回の全検証と初期化が成立した場合trueです。
 */
//------------------------------------------------------------------------------
bool OperationController::setRemainingPreparationPlan( const OperationId				 operationId,
													  const ScanSessionId			 session,
													  const OfficialPreparationPlan &plan)
{
	// 既setPreparationPlanを緩めず直前の受理終端だけへ限定します。
	if( state_ != ApplicationState::SCAN_READY || operationId != activeOperationId_ ||
	   session == 0U || session != scanSessionId_ || plan.scanSessionId != session ||
	   preparationPlan_ || !originalPreparationPlan_ ||
	   plan.planId <= originalPreparationPlan_->planId ||
	   plan.limits != originalPreparationPlan_->limits || plan.targets.empty() ||
	   plan.targets.size() > originalPreparationPlan_->targets.size()) {
		return false ;
	}

	std::unordered_set<std::wstring> targets ;	// 一対象一回です。
	// 全原tupleと未処理device数を照合してから初期化します。
	for( const auto &target : plan.targets) {
		const auto original =
			std::ranges::find( originalPreparationPlan_->targets, target.identity,
							  &OfficialPreparationTarget::identity) ;	// 元申告です。
		// 別条件や重複を新planへ混ぜません。
		if( original == originalPreparationPlan_->targets.end() || *original != target ||
		   !targets.insert( target.identity).second) {
			return false ;
		}

		std::unordered_set<std::wstring> devices ;	// 元参照からのscopeです。
		// 元集合の各要素を同じscopeへ一度ずつ照合します。
		for( const auto &identity : retainedReferenceIdentities_) {
			const auto &scope = scanReferenceScopes_.at( identity) ;	// 原mapの検証済みkeyです。
			// 他targetをこの対象の件数へ足しません。
			if( scope.second == target.identity) {
				devices.insert( scope.first) ;
			}
		}

		// 消費したcohortを件数縮小や推測で補完しません。
		if( devices.size() != target.deviceCount) {
			return false ;
		}
	}

	// 同scan予算と累積予約、新plan IDを既sessionで再検証します。
	if( preparationSession_.initialize( plan) != OfficialPreparationError::NONE) {
		return false ;
	}

	preparationPlan_ = plan ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 最後に受理したInstall結果の成功を次操作stateと分けます。
 * @return 原結果の全検証に成功した場合trueです。
 */
//------------------------------------------------------------------------------
bool OperationController::lastInstallSucceeded() const noexcept
{
	return lastInstallSucceeded_ ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同scanで未消費の導入可能候補だけを照合します。
 * @param[in] identity 元candidate identityです。
 * @return 残存集合へ結合している場合trueです。
 */
//------------------------------------------------------------------------------
bool OperationController::isInstallCandidateAllowed( const std::wstring_view identity) const
{
	return state_ == ApplicationState::SCAN_READY && scanSessionId_ != 0U &&
		   candidateIdentities_.contains( std::wstring{identity}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 成功した検索に付随する取得計画を固定する。同じ検索への計画差替えを許可せず、既存承認coreで形式と予算を検証する。
 * @param[in] operationId 計画を受け取ったscan操作ID。 計画を受領した検索操作ID。
 * @param[in] plan workerが検証した有限計画。 workerが発行した計画。
 * @return 現在のscanへ初めて有効計画を保持した場合true。 有効計画を現在の検索へ固定した場合true。
 */
//------------------------------------------------------------------------------
bool OperationController::setPreparationPlan( const OperationId				operationId,
											 const OfficialPreparationPlan &plan)
{
	// 古い結果や二度目の計画公開を拒否する。
	if( scanPurpose_ != ScanPurpose::STANDARD || state_ != ApplicationState::SCAN_READY ||
	   operationId != activeOperationId_ || plan.scanSessionId != scanSessionId_ ||
	   preparationPlan_) {
		return false ;
	}

	// 予算とsnapshotの検証を通らない取得計画は、UIの承認対象として登録しない。
	if( preparationSession_.initialize( plan) != OfficialPreparationError::NONE) {
		return false ;
	}

	originalPreparationPlan_ = plan ;
	preparationPlan_		 = plan ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未使用の取得計画をUI確認用に参照する。状態変更をまたいで返却pointerを保存しない。
 * @return 計画なしはnullptr。次の状態変更まで有効な非所有pointer。 未使用計画、またはnullptr。所有権はcontrollerが保持する。
 */
//------------------------------------------------------------------------------
const OfficialPreparationPlan *OperationController::preparationPlan() const noexcept
{
	return scanPurpose_ == ScanPurpose::STANDARD && state_ == ApplicationState::SCAN_READY &&
				   preparationPlan_
			   ? &*preparationPlan_
			   : nullptr ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全対象の判断を照合して取得操作を開始する。取得選択はinstall選択から独立させ、workerとは別にsnapshotを照合する。
 * @param[in,out] approval 操作IDが0の承認。受理時だけ新操作IDを反映する。 全対象判断。操作IDは0を要求し、受理時に採番する。
 * @return 開始結果。不正承認ではworkerへ送信しない。 受理した操作ID、または拒否理由。
 */
//------------------------------------------------------------------------------
BeginResult OperationController::beginPreparation( OfficialPreparationApproval &approval)
{
	// 終了処理に入った後は、新しい検査用取得operationを受理しない。
	if( state_ == ApplicationState::STOPPING) {
		return {.error = BeginError::STOPPING} ;
	}

	// 他のoperationが終了するまで検査用取得を開始せず、処理対象の排他を保つ。
	if( state_ == ApplicationState::SCANNING || state_ == ApplicationState::CANCELLING_SCAN ||
	   state_ == ApplicationState::PREPARING ||
	   state_ == ApplicationState::CANCELLING_PREPARATION ||
	   state_ == ApplicationState::CANCELLING_METADATA_SEARCH ||
	   state_ == ApplicationState::CREATING_RESTORE_POINT ||
	   state_ == ApplicationState::DOWNLOADING || state_ == ApplicationState::INSTALLING) {
		return {.error = BeginError::BUSY} ;
	}

	// 現在の検索結果と取得計画がそろわない状態では、過去の同意を利用できない。
	if( scanPurpose_ != ScanPurpose::STANDARD || state_ != ApplicationState::SCAN_READY ||
	   !preparationPlan_) {
		return {.error = BeginError::NO_SCAN_RESULT} ;
	}

	// 異なる検索sessionへの承認を拒否し、古い候補snapshotで取得を始めない。
	if( approval.scanSessionId != scanSessionId_) {
		return {.error = BeginError::STALE_SCAN_SESSION} ;
	}

	// 過去の承認を再送させない。
	if( approval.operationId != 0) {
		return {.error = BeginError::INVALID_PREPARATION} ;
	}

	// 全拒否でworkerを起動しない。
	if( std::none_of( approval.decisions.begin(), approval.decisions.end(),
					[]( const OfficialPreparationDecision &entry) { return entry.acquire ; })) {
		return {.error = BeginError::EMPTY_SELECTION} ;
	}

	OfficialPreparationApproval pending = approval ;	// 失敗時に呼出元を変更しない検証用copy。
	// 一意のoperation IDが発行できなければ、検査用取得の承認を開始済みにしない。
	if( !allocateOperationId( pending.operationId)) {
		return {.error = BeginError::ID_EXHAUSTED} ;
	}

	// 承認coreが対象や同意の矛盾を検出した場合は、workerへ取得要求を渡さない。
	if( preparationSession_.approve( pending) != OfficialPreparationError::NONE) {
		return {.error = BeginError::INVALID_PREPARATION} ;
	}

	activeOperationId_	 = pending.operationId ;
	approval.operationId = pending.operationId ;
	activePreparation_	 = std::move( pending) ;
	state_				 = ApplicationState::PREPARING ;
	return {.accepted = true, .operationId = activeOperationId_} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 取得取消し要求後の待機状態へ移行する。workerの確定結果まで排他を維持する。
 * @param[in] operationId 取消し対象の取得操作ID。 取消し要求を送信した取得操作ID。
 * @return 現在の取得操作を取消し待ちへ変更した場合true。 現在の取得を取消し待ちへ変更した場合true。
 */
//------------------------------------------------------------------------------
bool OperationController::markPreparationCancelling( const OperationId operationId) noexcept
{
	// 現在実行中の検査用取得だけを取消し対象とし、古い操作IDを適用しない。
	if( state_ != ApplicationState::PREPARING || operationId != activeOperationId_) {
		return false ;
	}

	state_ = ApplicationState::CANCELLING_PREPARATION ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 取得完了を検証し、導入状態を変更せず元の一覧へ戻す。監査reportを全件照合し、全監査合格として発行された候補だけを現在scanの導入許可集合へ追加する。
 * @param[in] result operation／scan／planと対象別の確定結果。 同じoperation／scan／planの取得完了と監査report。
 * @param[in] candidates 表示済み候補。監査reportがある場合は必須。変更しない。 同じscanの表示候補。監査reportがある場合は必須。
 * @param[in] remainingPlan 当該承認の未選択原subsetです。新ID/原scope/予算を全検証します。
 * @return 現在操作の結果を処理した場合true。不正内容はFailedとして適用する。 現在操作ならtrue。不正内容はFailedへ遷移し、旧操作はfalse。
 */
//------------------------------------------------------------------------------
bool OperationController::completePreparation( const OfficialPreparationOperationResult &result,
											  const std::span<const UpdateCandidate>	candidates,
											  const OfficialPreparationPlan *remainingPlan)
{
	// 遅延した別操作／計画の結果を適用しない。
	if( (state_ != ApplicationState::PREPARING &&
		state_ != ApplicationState::CANCELLING_PREPARATION) ||
	   result.operationId != activeOperationId_ ||
	   result.scanSessionId != activePreparation_.scanSessionId ||
	   result.planId != activePreparation_.planId) {
		return false ;
	}

	const bool wasCancelled =
		// 元取消し意図です。
		state_ == ApplicationState::CANCELLING_PREPARATION ;
	bool valid = validPreparationResult( result, activePreparation_) &&
				 // 全件検証。
				 validatePreparationAuditReports( result, activePreparation_, candidates) ;
	// 全体の監査通知が妥当な場合だけ複製へ候補を追加し、検証途中の状態を公開しない。
	if( valid && !wasCancelled) {
		auto nextCandidateIdentities = candidateIdentities_ ;	// 成功時だけ反映する候補ID集合。
		auto nextCandidateDevices	 = candidateDevices_ ;		// 成功時だけ反映するdevice対応。
		// 監査合格として発行された候補だけを、導入許可集合の複製へ追加する。
		for( const OfficialPreparationAuditReport &report : result.auditReports) {
			// Report内の全候補を一件ずつ複製へ追加し、既存IDとの衝突を検出する。
			for( const UpdateCandidate &candidate : report.publishedCandidates) {
				// 発行候補のIDまたはdevice対応が重複したら追加を中断し、部分反映を防ぐ。
				if( !nextCandidateIdentities.insert( candidate.identity).second ||
				   !nextCandidateDevices.emplace( candidate.identity, candidate.deviceIdentity)
						.second) {
					valid = false ;
					break ;
				}
			}

			// 一部だけ許可せず、下の失敗経路で現在session全体を失効する。
			if( !valid) {
				break ;
			}
		}

		// 発行候補の全件検証が終わってから、導入許可集合とdevice対応を同時に置き換える。
		if( valid) {
			// 全件成功後に反映。
			candidateIdentities_ = std::move( nextCandidateIdentities) ;
			candidateDevices_	 = std::move( nextCandidateDevices) ;
		}
	}

	std::unordered_set<std::wstring> unselectedReferences ;	// 当該承認の元未処理subsetです。
	// 新しい任意targetや取得済みtargetを残planへ接続しません。
	if( valid && remainingPlan) {
		// 元集合の各要素を同じscopeへ一度ずつ照合します。
		for( const auto &target : remainingPlan->targets) {
			const auto decision =
				std::ranges::find( activePreparation_.decisions, target,
								  &OfficialPreparationDecision::target) ;	// 元全tupleです。
			// 選択済み/不明targetがあれば残plan全体を拒否します。
			if( decision == activePreparation_.decisions.end() || decision->acquire) {
				unselectedReferences.clear() ;
				remainingPlan = nullptr ;
				break ;
			}

			// 元集合の各要素を同じscopeへ一度ずつ照合します。
			for( const auto &entry : scanReferenceScopes_) {
				// 元対象のscopeを満たした場合だけ次の処理へ進みます。
				if( entry.second.second == target.identity) {
					unselectedReferences.insert( entry.first) ;
				}
			}
		}
	}

	preparationSession_.cancel() ;
	static_cast<void>( preparationSession_.invalidate()) ;
	preparationPlan_.reset() ;
	activePreparation_ = {} ;
	// 監査結果の不整合を検出したら検索sessionを失効させ、残存候補を再利用させない。
	if( !valid) {
		candidateIdentities_.clear() ;
		candidateDevices_.clear() ;
		scanSessionId_ = 0 ;
	}

	state_ = valid ? ApplicationState::SCAN_READY : ApplicationState::FAILURE ;
	retainedReferenceIdentities_.swap( unselectedReferences) ;
	// 既二重setPlan guardを緩めず、受理した同operationの原subsetだけを初期化します。
	if( valid && remainingPlan &&
	   !setRemainingPreparationPlan( result.operationId, scanSessionId_, *remainingPlan)) {
		retainedReferenceIdentities_.clear() ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 新しい operation を拒否する停止状態へ移行する。
 */
//------------------------------------------------------------------------------
void OperationController::stop() noexcept
{
	state_ = ApplicationState::STOPPING ;
	preparationSession_.cancel() ;
	static_cast<void>( preparationSession_.invalidate()) ;
	preparationPlan_.reset() ;
	originalPreparationPlan_.reset() ;
	scanReferenceScopes_.clear() ;
	retainedReferenceIdentities_.clear() ;
	activePreparation_ = {} ;
	candidateIdentities_.clear() ;
	candidateDevices_.clear() ;
	activeInstallIdentities_.clear() ;
	scanSessionId_ = 0 ;
	scanMeasurement_.reset() ;
	metadataSearchRequest_.reset() ;
	metadataSearchSummary_.reset() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在の application state を返す。
 * @return 現在 state。
 */
//------------------------------------------------------------------------------
ApplicationState OperationController::state() const noexcept
{
	return state_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在有効な scan session ID を返す。
 * @return scan result がない場合は 0。
 */
//------------------------------------------------------------------------------
ScanSessionId OperationController::scanSessionId() const noexcept
{
	return scanSessionId_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 最後に受理したscan完了時点の段階別計測を参照する。
 * @return 有効な公開計測への非所有pointer。未接続・不正・新scan中はnullptr。
 * @note 準備操作で再計数せず、install後は選択作用subsetの履歴と未処理scanを保持する。
 */
//------------------------------------------------------------------------------
const ScanMeasurement *OperationController::scanMeasurement() const noexcept
{
	return scanMeasurement_ ? &*scanMeasurement_ : nullptr ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在実行中または最後に完了した operation ID を返す。
 * @return operation 未開始の場合は 0。
 */
//------------------------------------------------------------------------------
OperationId OperationController::activeOperationId() const noexcept
{
	return activeOperationId_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 0 と重複しない次の operation ID を割り当てる。
 * @param[out] operationId 割り当てた ID。
 * @return ID を割り当てられた場合は `true`。
 */
//------------------------------------------------------------------------------
bool OperationController::allocateOperationId( OperationId &operationId) noexcept
{
	// wrap した ID を再利用すると遅延 result と区別できないため、上限到達後は停止する。
	if( nextOperationId_ == 0 || nextOperationId_ == std::numeric_limits<OperationId>::max()) {
		return false ;
	}

	operationId = nextOperationId_ ;
	++nextOperationId_ ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 新しい表示専用検索を受理し、旧候補・取得計画・同意を失効する。
 * @param[in] request 今回だけの明示集合と通信判断。
 * @return 開始した操作IDまたは拒否理由。拒否時は旧状態を変更しない。
 */
//------------------------------------------------------------------------------
BeginResult OperationController::beginMetadataSearch( const MetadataSearchRequest &request)
{
	// 不正な設定では旧表示や権限を破壊せず、検索自体を受理しない。
	if( !validateMetadataSearchRequest( request, builtInProviderDescriptors())) {
		return {.error = BeginError::INVALID_METADATA_SEARCH} ;
	}

	auto	   pending = request ;		// 確保失敗は状態遷移前に呼出元へ伝える。
	const auto begin   = beginScan() ;	// 共通の排他・採番・旧権限失効。
	// 受理済み操作にだけ今回の非導入権限と要求copyを固定する。
	if( begin.accepted) {
		scanPurpose_		   = ScanPurpose::METADATA_ONLY ;
		metadataSearchRequest_ = std::move( pending) ;
	}

	return begin ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ情報検索だけを取消し結果待ちへ移す。
 * @param[in] operationId Workerへ取消しを要求した操作ID。
 * @return 現在の情報検索へ適用した場合true。
 */
//------------------------------------------------------------------------------
bool OperationController::markMetadataSearchCancelling( const OperationId operationId) noexcept
{
	// 通常scanや古い操作を情報検索の取消しへ読み替えない。
	if( scanPurpose_ != ScanPurpose::METADATA_ONLY || operationId != activeOperationId_ ||
	   state_ != ApplicationState::SCANNING) {
		return false ;
	}

	state_ = ApplicationState::CANCELLING_METADATA_SEARCH ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 情報検索の全snapshotを検証し、導入権限なしの終端へ移す。
 * @param[in] operationId 完了対象の操作ID。
 * @param[in] result Workerから受け取った情報検索結果。
 * @return 現在操作を処理した場合true。不正結果はFAILUREとしsummaryを保持しない。
 */
//------------------------------------------------------------------------------
bool OperationController::completeMetadataSearch( const OperationId operationId,
												 const ScanResult &result)
{
	// 取消し結果待ちも排他を維持する。同じ用途・操作だけを終端させる。
	if( scanPurpose_ != ScanPurpose::METADATA_ONLY || operationId != activeOperationId_ ||
	   (state_ != ApplicationState::SCANNING &&
		state_ != ApplicationState::CANCELLING_METADATA_SEARCH)) {
		return false ;
	}

	state_		   = ApplicationState::FAILURE ;
	scanSessionId_ = 0U ;
	metadataSearchSummary_.reset() ;
	scanMeasurement_.reset() ;
	// 不正な部分結果を保持せず、取得・導入sessionはどの終端でも発行しない。
	if( !metadataSearchRequest_ ||
	   !isMetadataSearchResultValid( operationId, *metadataSearchRequest_, result)) {
		return true ;
	}

	metadataSearchSummary_ = result.metadataSearch ;
	scanMeasurement_	   = result.measurement ;
	state_				   = result.outcome == OutcomeCode::FAILURE ? ApplicationState::FAILURE
																	: ApplicationState::COMPLETED ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在または最後の検索の権限種別を返す。
 * @return 結果行のフラグと独立した用途。
 * @return 現在保持するscan用途です。
 */
//------------------------------------------------------------------------------
ScanPurpose OperationController::scanPurpose() const noexcept
{
	return scanPurpose_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 検証済みの情報検索終端を参照する。
 * @return 次の状態変更まで借用できる値。未保持はnullptr。
 * @return 保持済みsummaryがあればその借用pointer、未設定ならnullです。次の状態更新またはcontroller破棄より前にだけ使用します。
 */
//------------------------------------------------------------------------------
const MetadataSearchSummary *OperationController::metadataSearchSummary() const noexcept
{
	return metadataSearchSummary_ ? &*metadataSearchSummary_ : nullptr ;
}

} // namespace drivercrate
