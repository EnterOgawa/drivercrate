//------------------------------------------------------------------------------
/**
 * @file maintenance_embedded_file_table_tests.h
 * @brief 保守専用PE内表の架空回帰入口。
 * @version 01.00.00
 * @date 2026/10/05
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/05  架空PE内表の回帰を追加。
 * </pre>
 *
 * @note 架空byteを使用し、実署名・実機・networkへ依存しません。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief 架空表の正例と破損・未対応・曖昧の拒否を検証する。
 * @param[in,out] context 呼出し側が所有するassertion集計。
 */
void runMaintenanceEmbeddedFileTableTests( TestContext &context) ;

} // namespace drivercrate::test
