//------------------------------------------------------------------------------
/**
 * @file official_preparation_operation.cpp
 * @brief 承認済み取得の直列実行
 * @version 01.00.03
 * @date 2026/09/06
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得計画とworker実行を追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.00.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.00.03 Shunji Ogawa  2026/11/12  外側tupleの取得予約と開始拒否の原理由を接続
 * </pre>
 *
 * @note 未選択対象を呼ばず、取消しとCallback例外を対象結果へ反映します
 */
//------------------------------------------------------------------------------

#include "core/official_preparation_operation.h"
#include "core/provider_registry.h"
#include <algorithm>
#include <utility>

#include <bit>
#include <cstdint>
#include <optional>

namespace drivercrate {
namespace {
constexpr NativeError INVALID_ARGUMENT =
	std::bit_cast<NativeError>( std::uint32_t{0x80070057U}) ;	// E_INVALIDARGのbit表現
constexpr NativeError UNEXPECTED =
	std::bit_cast<NativeError>( std::uint32_t{0x8000FFFFU}) ;	// Callback例外等のE_UNEXPECTED
constexpr NativeError CANCELLED =
	std::bit_cast<NativeError>( std::uint32_t{0x800704C7U}) ;	// ERROR_CANCELLEDのHRESULT

//------------------------------------------------------------------------------
/**
 * @brief 不明な取消し状態では次の取得を開始しない
 *
 * @param[in] callback 任意の協調取消し照会。空なら取消し信号なし
 * @param[in,out] error 照会例外を記録する制御error
 * @return 取消しまたは照会不能ならtrue
 */
//------------------------------------------------------------------------------
bool cancellationRequested( const PreparationCancellation &callback, NativeError &error) noexcept
{
	try {
		return callback && callback() ;
	} catch( ...) {
		// 例外を無言で破棄せず、操作結果へ診断値を保持する
		error = UNEXPECTED ;
		return true ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 通知の例外をworker外へ漏らさず、後続取得を止める理由として返す
 *
 * @param[in] callback 承認前に検査済みの通知先
 * @param[in] session 確定件数を読む取得状態
 * @param[in,out] error 通知不能時の制御error
 * @return 通知成功時true
 */
//------------------------------------------------------------------------------
bool notifyProgress( const PreparationProgressCallback &callback,
					const OfficialPreparationSession &session, NativeError &error) noexcept
{
	try {
		callback( session.progress()) ;
		return true ;
	} catch( ...) {
		error = UNEXPECTED ;
		return false ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 固定計画と承認を照合し、選択対象だけの取得を直列実行する。選択分だけを一度ずつ取得し、取得後の監査・導入は行わない
 * @param[in,out] session workerが固定計画と予約予算を所有する管理object。 固定計画とscan予約予算を保持する状態
 * @param[in] approval 利用者が明示した全対象の可否。 全対象の明示判断
 * @param[in] acquire 取得境界。空の場合は承認前に拒否する。 worker内の取得境界
 * @param[in] cancellation 取消し照会。空は外部取消し信号なし。 空または協調取消し照会
 * @param[in] progress 確定件数の通知先。空の場合は承認前に拒否する
 * @return 承認の拒否理由または対象別の取得結果。監査表示はProviderが別途付加する。導入しない。 承認拒否または対象別確定結果
 * @note 同一worker threadで呼ぶ。Callbackの例外は制御／対象別errorへ変換する
 */
//------------------------------------------------------------------------------
OfficialPreparationOperationResult executeOfficialPreparation(
	OfficialPreparationSession &session, const OfficialPreparationApproval &approval,
	const PreparationAcquireFunction &acquire, const PreparationCancellation &cancellation,
	const PreparationProgressCallback &progress)
{
	OfficialPreparationOperationResult result{.operationId	 = approval.operationId,
											  .scanSessionId = approval.scanSessionId,
											  .planId = approval.planId} ;	// UIへ返す非機密の結果
	// 取得または進捗の呼出し境界が欠ける場合は、承認や予算を消費する前に拒否する
	if( !acquire || !progress) {
		result.approvalError = OfficialPreparationError::INVALID_APPROVAL ;
		result.controlError	 = INVALID_ARGUMENT ;
		// 不完全な処理境界では承認も予約も消費しない
		return result ;
	}

	result.approvalError = session.approve( approval) ;
	// 古い承認や差替えで取得境界を呼ばない
	if( result.approvalError != OfficialPreparationError::NONE) {
		return result ;
	}

	// 転送中の照会例外も取得関数へ漏らさず、取消しとして伝える
	const PreparationCancellation safeCancellation = [&cancellation, &result]() {
		return cancellationRequested( cancellation, result.controlError) ;
	} ;
	// 取消しまたは進捗通知の制御異常を検出したら、以降の新規取得を止める
	if( safeCancellation() || !notifyProgress( progress, session, result.controlError)) {
		session.cancel() ;
	}

	try {
		// 固定計画の最大256対象を、一度ずつ計画順に消費する
		while( session.state() == OfficialPreparationState::PREPARING) {
			// 取消し後に新しい対象をclaimせず、未開始の承認対象を取消しへ確定する
			if( safeCancellation()) {
				session.cancel() ;
				// 取消し時には未開始の対象をclaimしない
				break ;
			}

			const auto task = session.claimNext() ;	// 今回だけ取得を許可する所有token
			// 継続中の計画から次の対象を取得できない矛盾は、制御失敗として残りを取消す
			if( !task) {
				result.controlError = UNEXPECTED ;
				session.cancel() ;
				break ;
			}

			OfficialPreparationTransferResult transfer{OfficialPreparationItemState::FAILURE,
													   UNEXPECTED, 0U} ;	// 例外時の既定結果
			try {
				// claim後に取消しが届いた場合も取得境界を呼ばず、その対象の取消し結果を作る
				if( safeCancellation()) {
					transfer = {OfficialPreparationItemState::CANCELLED, CANCELLED, 0U} ;
				} else {
					transfer = acquire( *task, safeCancellation) ;
				}
			} catch( ...) {
				transfer = {OfficialPreparationItemState::FAILURE, UNEXPECTED, 0U} ;
			}

			// Providerの矛盾した結果を成功へ補正せず、現在対象を拒否して残りの取得を止める
			if( !session.complete( *task, transfer)) {
				// 不正なProvider結果を成功へ補正せず、現在taskの拒否として確定する
				result.controlError = UNEXPECTED ;
				static_cast<void>( session.complete(
					*task, {OfficialPreparationItemState::REJECTED, UNEXPECTED, 0U})) ;
				session.cancel() ;
			}

			// 取消しや通知系の異常が発生したら、後続対象の取得へ進まない
			if( transfer.state == OfficialPreparationItemState::CANCELLED ||
			   result.controlError != 0 || safeCancellation() ||
			   !notifyProgress( progress, session, result.controlError)) {
				// 制御系異常では以降の取得を開始しない
				session.cancel() ;
			}
		}

		static_cast<void>( notifyProgress( progress, session, result.controlError)) ;
		result.items.assign( session.items().begin(), session.items().end()) ;
	} catch( ...) {
		// 結果copy等のallocation例外でも、残りの承認を後続操作へ流用しない
		session.cancel() ;
		result.controlError = UNEXPECTED ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同scanの取得前参照を含め、明示選択できる元候補だけを判定します
 * @param[in] candidate 表示中の元候補です
 * @param[in] plan 未使用の同scan計画です。計画なしはnullptrです
 * @param[in] scanSessionId 現在の元scanです
 * @return 元のinstallable候補または同scan/target/既知条件へ結合した参照ならtrueです
 * @note 取得前参照を実導入可能へ変更しません。I/O/通信を行いません
 */
//------------------------------------------------------------------------------
bool isInstallPreparationCandidateSelectable( const UpdateCandidate		   &candidate,
											 const OfficialPreparationPlan *plan,
											 const ScanSessionId			scanSessionId) noexcept
{
	// 現在行や同deviceへ結合できない行を選択意図へ読み替えません
	if( candidate.current || candidate.identity.empty() || candidate.deviceIdentity.empty()) {
		return false ;
	}

	// 既存Providerの実導入可能候補は従来どおり明示選択できます
	if( candidate.installable) {
		return true ;
	}

	return plan && plan->scanSessionId == scanSessionId &&
		   candidate.providerId == SIGNED_INDEX_PROVIDER_ID &&
		   candidate.discoveryBasis ==
			   CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION &&
		   !candidate.preparationTargetIdentity.empty() &&
		   std::ranges::any_of( plan->targets, [&]( const auto &target) {
			   return target.identity == candidate.preparationTargetIdentity &&
					  target.providerId == candidate.providerId &&
					  (target.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED ||
					   target.terms == OfficialPreparationTerms::CONFIRMED_NO_CONSENT) ;
		   }) ;
}
//------------------------------------------------------------------------------
/**
 * @brief UIと同じ元選択から、同意flagなしの完全な取得承認snapshotを作ります
 * @param[in] plan 未使用の同scan計画です。計画なしはnullptrです
 * @param[in] scanSessionId 現在の元scanです
 * @param[in] candidates 元表示候補の借用集合です
 * @param[in] indexes 当該表示へ明示checkした有限位置です
 * @return 元全target/未選択判断を含む未承認snapshot。不正/未知条件はnulloptです
 * @note 通信/同意発行を行いません。所有copyの確保例外は呼出元へ返します
 */
//------------------------------------------------------------------------------
std::optional<OfficialPreparationApproval> makeInstallPreparationApproval(
	const OfficialPreparationPlan *plan, const ScanSessionId scanSessionId,
	const std::span<const UpdateCandidate> candidates, const std::span<const std::size_t> indexes)
{
	// 使用済み計画や元scanがない場合に表示文字列から新しい取得を組み立てません
	if( !plan || plan->scanSessionId != scanSessionId || indexes.empty()) {
		return std::nullopt ;
	}

	OfficialPreparationApproval approval ;	// 元選択集合を取得前のworker照合へ渡します
	approval.scanSessionId = plan->scanSessionId ;
	approval.planId		   = plan->planId ;
	approval.limits		   = plan->limits ;
	// 元check集合をopaque identityで固定し、未選択deviceや候補を追加しません
	for( const auto index : indexes) {
		// 古いindexや選択不能行から取得targetを生成しません
		if( index >= candidates.size() ||
		   !isInstallPreparationCandidateSelectable( candidates[index], plan, scanSessionId)) {
			return std::nullopt ;
		}

		approval.installIntentIdentities.push_back( candidates[index].identity) ;
	}

	// 全計画の未選択判断も維持し、選んだ配布物だけへ取得を許可します
	for( const auto &target : plan->targets) {
		OfficialPreparationDecision decision{.target = target} ;	// 未選択を既定にします
		decision.acquire = std::ranges::any_of( indexes, [&]( const auto index) {
			return !candidates[index].installable &&
				   candidates[index].preparationTargetIdentity == target.identity ;
		}) ;
		approval.decisions.push_back( std::move( decision)) ;
	}

	// 選択した全配布物の条件と共有tokenを案内前にも検証します
	for( const auto &decision : approval.decisions) {
		// 未選択対象の利用条件を今回の同意対象へ含めません
		if( !decision.acquire) {
			continue ;
		}

		const auto &target = decision.target ;	// 取得選択した元の全文snapshotです
		// 未取得本文・未知条件・不明な出典を包括同意で補完しません
		if( (target.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED &&
			(!validPreparationEulaText( target.eulaText) || target.eulaRevision.empty() ||
			 target.eulaSourceSubject.empty())) ||
		   (target.terms != OfficialPreparationTerms::ACCEPTANCE_REQUIRED &&
			target.terms != OfficialPreparationTerms::CONFIRMED_NO_CONSENT)) {
			return std::nullopt ;
		}

		// 同一tokenの全選択対象で規約が完全一致しなければ案内全体を拒否します
		if( target.sharedEulaToken != 0U &&
		   std::ranges::any_of( approval.decisions, [&]( const auto &other) {
			   return other.acquire && other.target.sharedEulaToken == target.sharedEulaToken &&
					  (other.target.providerId != target.providerId ||
					   other.target.eulaSourceSubject != target.eulaSourceSubject ||
					   other.target.eulaRevision != target.eulaRevision ||
					   other.target.eulaText != target.eulaText) ;
		   })) {
			return std::nullopt ;
		}
	}

	return approval ;
}
} // namespace drivercrate
