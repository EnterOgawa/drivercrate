//------------------------------------------------------------------------------
/**
 * @file official_preparation_operation.cpp
 * @brief 承認済み取得の直列実行。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得計画とworker実行を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 未選択対象を呼ばず、取消しとCallback例外を対象結果へ反映します。
 */
//------------------------------------------------------------------------------

#include "core/official_preparation_operation.h"

#include <bit>
#include <cstdint>
#include <optional>

namespace drivercrate {
namespace {
constexpr NativeError INVALID_ARGUMENT =
	std::bit_cast<NativeError>( std::uint32_t{0x80070057U}) ;	// E_INVALIDARGのbit表現。
constexpr NativeError UNEXPECTED =
	std::bit_cast<NativeError>( std::uint32_t{0x8000FFFFU}) ;	// Callback例外等のE_UNEXPECTED。
constexpr NativeError CANCELLED =
	std::bit_cast<NativeError>( std::uint32_t{0x800704C7U}) ;	// ERROR_CANCELLEDのHRESULT。

//------------------------------------------------------------------------------
/**
 * @brief 不明な取消し状態では次の取得を開始しない。
 *
 * @param[in] callback 任意の協調取消し照会。空なら取消し信号なし。
 * @param[in,out] error 照会例外を記録する制御error。
 * @return 取消しまたは照会不能ならtrue。
 */
//------------------------------------------------------------------------------
bool cancellationRequested( const PreparationCancellation &callback, NativeError &error) noexcept
{
	try {
		return callback && callback() ;
	} catch( ...) {
		// 例外を無言で破棄せず、操作結果へ診断値を保持する。
		error = UNEXPECTED ;
		return true ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 通知の例外をworker外へ漏らさず、後続取得を止める理由として返す。
 *
 * @param[in] callback 承認前に検査済みの通知先。
 * @param[in] session 確定件数を読む取得状態。
 * @param[in,out] error 通知不能時の制御error。
 * @return 通知成功時true。
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
 * @see src/core/official_preparation_operation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialPreparationOperationResult executeOfficialPreparation(
	OfficialPreparationSession &session, const OfficialPreparationApproval &approval,
	const PreparationAcquireFunction &acquire, const PreparationCancellation &cancellation,
	const PreparationProgressCallback &progress)
{
	OfficialPreparationOperationResult result{.operationId	 = approval.operationId,
											  .scanSessionId = approval.scanSessionId,
											  .planId = approval.planId} ;	// UIへ返す非機密の結果。
	// 取得または進捗の呼出し境界が欠ける場合は、承認や予算を消費する前に拒否する。
	if( !acquire || !progress) {
		result.approvalError = OfficialPreparationError::INVALID_APPROVAL ;
		result.controlError	 = INVALID_ARGUMENT ;
		// 不完全な処理境界では承認も予約も消費しない。
		return result ;
	}

	result.approvalError = session.approve( approval) ;
	// 古い承認や差替えで取得境界を呼ばない。
	if( result.approvalError != OfficialPreparationError::NONE) {
		return result ;
	}

	// 転送中の照会例外も取得関数へ漏らさず、取消しとして伝える。
	const PreparationCancellation safeCancellation = [&cancellation, &result]() {
		return cancellationRequested( cancellation, result.controlError) ;
	} ;
	// 取消しまたは進捗通知の制御異常を検出したら、以降の新規取得を止める。
	if( safeCancellation() || !notifyProgress( progress, session, result.controlError)) {
		session.cancel() ;
	}

	try {
		// 固定計画の最大256対象を、一度ずつ計画順に消費する。
		while( session.state() == OfficialPreparationState::PREPARING) {
			// 取消し後に新しい対象をclaimせず、未開始の承認対象を取消しへ確定する。
			if( safeCancellation()) {
				session.cancel() ;
				// 取消し時には未開始の対象をclaimしない。
				break ;
			}

			const auto task = session.claimNext() ;	// 今回だけ取得を許可する所有token。
			// 継続中の計画から次の対象を取得できない矛盾は、制御失敗として残りを取消す。
			if( !task) {
				result.controlError = UNEXPECTED ;
				session.cancel() ;
				break ;
			}

			OfficialPreparationTransferResult transfer{OfficialPreparationItemState::FAILURE,
													   UNEXPECTED, 0U} ;	// 例外時の既定結果。
			try {
				// claim後に取消しが届いた場合も取得境界を呼ばず、その対象の取消し結果を作る。
				if( safeCancellation()) {
					transfer = {OfficialPreparationItemState::CANCELLED, CANCELLED, 0U} ;
				} else {
					transfer = acquire( *task, safeCancellation) ;
				}
			} catch( ...) {
				transfer = {OfficialPreparationItemState::FAILURE, UNEXPECTED, 0U} ;
			}

			// Providerの矛盾した結果を成功へ補正せず、現在対象を拒否して残りの取得を止める。
			if( !session.complete( *task, transfer)) {
				// 不正なProvider結果を成功へ補正せず、現在taskの拒否として確定する。
				result.controlError = UNEXPECTED ;
				static_cast<void>( session.complete(
					*task, {OfficialPreparationItemState::REJECTED, UNEXPECTED, 0U})) ;
				session.cancel() ;
			}

			// 取消しや通知系の異常が発生したら、後続対象の取得へ進まない。
			if( transfer.state == OfficialPreparationItemState::CANCELLED ||
			   result.controlError != 0 || safeCancellation() ||
			   !notifyProgress( progress, session, result.controlError)) {
				// 制御系異常では以降の取得を開始しない。
				session.cancel() ;
			}
		}

		static_cast<void>( notifyProgress( progress, session, result.controlError)) ;
		result.items.assign( session.items().begin(), session.items().end()) ;
	} catch( ...) {
		// 結果copy等のallocation例外でも、残りの承認を後続操作へ流用しない。
		session.cancel() ;
		result.controlError = UNEXPECTED ;
	}

	return result ;
}

} // namespace drivercrate
