//------------------------------------------------------------------------------
/**
 * @file protected_install_tests.h
 * @brief 復元ポイント保護付きinstall単体試験定義。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note fakeサービスにより実端末を変更せず保護付きinstall境界を検証します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief 復元ポイント保護付きinstall処理の単体試験を実行する。
 * fakeだけを使用して正常、開始失敗、終了失敗、例外経路を検証する。
 * @param[in,out] context assertion集計先。
 */
void runProtectedInstallTests( TestContext &context) ;

} // namespace drivercrate::test
