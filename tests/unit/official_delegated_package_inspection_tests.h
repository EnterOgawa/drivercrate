//------------------------------------------------------------------------------
/**
 * @file official_delegated_package_inspection_tests.h
 * @brief Record限定取得と共通package検査の接続単体試験を定義します。
 * @version 01.00.00
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  取得・内容検査・表示専用評価の接続fixtureを追加。
 * </pre>
 *
 * @note 実network、実driver、実installを使用せず、架空recordと存在しない入力pathだけを使用します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief Record限定取得から表示専用評価までの正常・拒否・後始末fixtureを実行します。
 * @param[in,out] context Assertion集計先です。
 */
void runOfficialDelegatedPackageInspectionTests( TestContext &context) ;

} // namespace drivercrate::test
