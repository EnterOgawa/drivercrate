//------------------------------------------------------------------------------
/**
 * @file official_preparation_operation.h
 * @brief 承認済み検査用取得の実行契約。
 * @version 01.00.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の表示境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  EULA本文内の非実行URLと取得入力を区別。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得計画とworker実行を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note Callbackはworker内だけで使用し、取得結果を導入許可へ変換しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_preparation.h"
#include "core/official_preparation_audit.h"

#include <functional>
#include <vector>

namespace drivercrate {
// 未接続の経路を有効化しない予約上限。Provider固有の取得・監査上限も別途守る。
inline constexpr OfficialPreparationLimits DEFAULT_OFFICIAL_PREPARATION_LIMITS{
	128ULL * 1024ULL * 1024ULL, 256ULL * 1024ULL * 1024ULL, 512ULL * 1024ULL * 1024ULL, 2U, 4U} ;

/**
 * @brief 転送処理へ渡す協調取消し照会。同期呼出し中だけ有効な非所有参照として渡す。
 */
using PreparationCancellation = std::function<bool()> ;
/**
 * @brief 確定した選択対象の件数を通知する。転送byteや時間による推定率ではない。
 */
using PreparationProgressCallback = std::function<void( const OfficialPreparationProgress &)> ;
/**
 * @brief Worker内の取得境界。Payload URLは渡さず、EULA内のURLは実行しない文字列に限る。
 */
using PreparationAcquireFunction = std::function<OfficialPreparationTransferResult(
	const OfficialPreparationTask &, const PreparationCancellation &)> ;

/** @brief 取得準備操作の結果。全体のinstall成功flagを持たない。 */
struct OfficialPreparationOperationResult {
	/// 対応する承認操作ID。
	OperationId									operationId{} ;
	/// 承認対象の検索session。
	ScanSessionId								scanSessionId{} ;
	/// 承認した計画のID。
	std::uint64_t								planId{} ;
	/// 承認の拒否理由。
	OfficialPreparationError					approvalError{OfficialPreparationError::NO_PLAN} ;
	/// Callback例外等の制御系異常。対象別転送errorとは別。
	NativeError									controlError{} ;
	/// 承認受理時だけ返す対象別の確定結果。
	std::vector<OfficialPreparationItem>		items ;
	/// 取得後の独立した監査表示結果。
	std::vector<OfficialPreparationAuditReport> auditReports ;
} ;

/**
 * @brief 固定計画と承認を照合し、選択対象だけの取得を直列実行する。
 * 選択分だけを一度ずつ取得し、取得後の監査・導入は行わない。
 * @param[in,out] session workerが固定計画と予約予算を所有する管理object。 固定計画とscan予約予算を保持する状態。
 * @param[in] approval 利用者が明示した全対象の可否。 全対象の明示判断。
 * @param[in] acquire 取得境界。空の場合は承認前に拒否する。 worker内の取得境界。
 * @param[in] cancellation 取消し照会。空は外部取消し信号なし。 空または協調取消し照会。
 * @param[in] progress 確定件数の通知先。空の場合は承認前に拒否する。
 * @return 承認の拒否理由または対象別の取得結果。監査表示はProviderが別途付加する。導入しない。 承認拒否または対象別確定結果。
 * @note 同一worker threadで呼ぶ。Callbackの例外は制御／対象別errorへ変換する。
 */
[[nodiscard]] OfficialPreparationOperationResult executeOfficialPreparation(
	OfficialPreparationSession &session, const OfficialPreparationApproval &approval,
	const PreparationAcquireFunction &acquire, const PreparationCancellation &cancellation,
	const PreparationProgressCallback &progress) ;
} // namespace drivercrate
