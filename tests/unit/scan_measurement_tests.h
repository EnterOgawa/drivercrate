//------------------------------------------------------------------------------
/**
 * @file scan_measurement_tests.h
 * @brief 段階別計測の非通信単体試験契約。
 * @version 01.00.00
 * @date 2026/09/10
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  件数・和集合・不正入力の最小fixtureを追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 架空identityだけを使用し、実API、network、導入、復元ポイントを呼びません。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief 段階別計測の確定度と拒否条件を検証する。
 * @param[in,out] context Assertionと失敗件数の集計先。
 */
void runScanMeasurementTests( TestContext &context) ;

} // namespace drivercrate::test
