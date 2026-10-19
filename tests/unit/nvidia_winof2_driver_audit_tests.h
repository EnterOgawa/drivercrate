//------------------------------------------------------------------------------
/**
 * @file nvidia_winof2_driver_audit_tests.h
 * @brief WinOF-2内容・PnP監査と候補発行単体試験定義。
 * @version 01.00.00
 * @date 2026/09/07
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 架空閉包と差替え監査を使い、実driver、network、installへ依存せずWinOF-2のfail-closed境界を検証します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief WinOF-2の内容・PnP／rank監査と候補発行の正常系・拒否系を検証する。
 * 正常候補、内容、PnP、rank、identity、class拒否を順に試す。
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
void runNvidiaWinof2DriverAuditTests( TestContext &context) ;

} // namespace drivercrate::test
