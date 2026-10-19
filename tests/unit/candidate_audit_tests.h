//------------------------------------------------------------------------------
/**
 * @file candidate_audit_tests.h
 * @brief Driver候補監査状態単体試験定義。
 * @version 01.00.00
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Networkまたは実driverを使用せず、候補監査状態のfail-closed条件を検証します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "test_framework.h"

namespace drivercrate::test {

/**
 * @brief Driver候補監査状態の単体試験群を実行する。
 * Driver候補監査状態の全単体試験を順番に実行する。
 * @param[in,out] context Assertion件数と失敗内容の記録先。
 */
void runCandidateAuditTests( TestContext &context) ;

} // namespace drivercrate::test
