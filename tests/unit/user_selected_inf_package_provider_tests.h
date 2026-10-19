//------------------------------------------------------------------------------
/**
 * @file user_selected_inf_package_provider_tests.h
 * @brief 利用者選択INF Provider単体試験定義。
 * @version 01.00.00
 * @date 2026/09/03
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 実driverを導入せず、検証済みINF由来classの候補化境界を確認します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief 利用者選択INF Providerのclass照合とfail-closed policyを検証する。
 * 利用者選択INF Provider単体試験を実行する。
 * 汎用PnP ID入力、class照合、policy矛盾を順番に検証する。
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
void runUserSelectedInfPackageProviderTests( TestContext &context) ;

} // namespace drivercrate::test
