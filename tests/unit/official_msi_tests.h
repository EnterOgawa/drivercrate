//------------------------------------------------------------------------------
/**
 * @file official_msi_tests.h
 * @brief 公式MSI stream選択取得単体試験定義。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Read-only MSI stream試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Windows Installer database APIで架空MSIを生成し、install sequenceを実行せずstream選択とfail-closed境界を検証します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief 公式MSI streamのread-only取得と拒否境界を検証する。
 * 正常取得と全fail-closed MSI fixtureを順に実行する。
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
void runOfficialMsiTests( TestContext &context) ;

} // namespace drivercrate::test
