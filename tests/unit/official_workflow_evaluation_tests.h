//------------------------------------------------------------------------------
/**
 * @file official_workflow_evaluation_tests.h
 * @brief 公式探索の固定集合評価試験
 * @version 01.00.02
 * @date 2026/09/15
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.00.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * </pre>
 *
 * @note 架空の固定集合を扱う試験専用実装。実機対応率を計測・公開せず、OSへ作用しない
 * @see docs/adr/0150-device-observation-and-candidate-assessment-contract.md
 */
//------------------------------------------------------------------------------

#pragma once
#include "test_framework.h"

namespace drivercrate::test {
//------------------------------------------------------------------------------
/**
 * @brief 固定集合と未測定を分離した評価契約のfixtureを実行する
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void runOfficialWorkflowEvaluationTests( TestContext &context) ;
} // namespace drivercrate::test
