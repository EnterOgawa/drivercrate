//------------------------------------------------------------------------------
/**
 * @file scan_measurement_diagnostics_tests.h
 * @brief 固定条件scan profileと非機密ASCII reportの単体試験契約。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  固定profileと出力拒否境界の試験を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 合成snapshotとfake streamだけを使用し、network、device、cache、導入APIを呼びません。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief 固定profile、四確定度、非機密化、容量およびI/O失敗を検証する。
 * @param[in,out] context Assertion集計先。
 */
void runScanMeasurementDiagnosticsTests( TestContext &context) ;

} // namespace drivercrate::test
