//------------------------------------------------------------------------------
/**
 * @file wch_serial_package_tests.h
 * @brief WCH CH340／CH341利用者指定ZIP検証単体試験定義。
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
 * @note Networkや実driverを使用せず、WCH固定USB IDと入力拒否境界を検証します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief WCH CH341SER packageのPnP ID照合と入力拒否境界を検証する。
 * WCH CH341SER packageの全単体試験を実行する。
 * 固定PnP IDの正常・拒否境界とfail-closed入力を検証する。
 * @param[in,out] context Assertion結果の集計先。 Assertion集計先。
 */
void runWchSerialPackageTests( TestContext &context) ;

} // namespace drivercrate::test
