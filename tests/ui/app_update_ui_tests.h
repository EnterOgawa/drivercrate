//------------------------------------------------------------------------------
/**
 * @file app_update_ui_tests.h
 * @brief App更新の通常MainWindow回帰を宣言します。
 * @version 01.00.01
 * @date 2026/11/11
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/11  App専用の通知付き更新を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 * @note private desktopの非通信fixtureだけで実行します。
 * @see docs/adr/0481-app-inno-setup-and-update-checks.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "test_framework.h"
namespace drivercrate::test {
//------------------------------------------------------------------------------
/**
 * @brief 通知/driver busy/modal/取消し/引継ぎ失敗/closeを確認します。
 * @param[in,out] context 固定期待の集計先です。
 */
//------------------------------------------------------------------------------
void runAppUpdateUiTests( TestContext &context) ;
}
