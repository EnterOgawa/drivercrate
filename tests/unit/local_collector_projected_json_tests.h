//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_json_tests.h
 * @brief 新収集JSONの有限byte・世代別判定の試験入口です。
 * @version 01.00.00
 * @date 2026/09/29
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  有限字句・envelope・版別表の非通信試験を追加。
 * </pre>
 *
 * @note 通信・保存・worker成功の注入を行いません。
 */
//------------------------------------------------------------------------------
#pragma once
#include "test_framework.h"
namespace drivercrate::test {
/** @brief 有限byteと世代別形状だけを独立検査します。
 * @param[in,out] context Assertion集計。
 */
void runCollectorProjectedJsonTests( TestContext &context) ;
}
