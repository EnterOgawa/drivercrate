//------------------------------------------------------------------------------
/**
 * @file intel_collector_identity_parser_tests.h
 * @brief Intel公式製品identityの有限合成試験宣言。
 * @version 01.00.00
 * @date 2026/09/28
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  有限Intel製品identity解析を追加。
 * </pre>
 *
 * @note 通信・record生成・出典証明・driver適用性判定は行いません。
 * @see docs/adr/0221-collector-official-product-identity.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "test_framework.h"

namespace drivercrate::test {

/**
 * @brief 架空HTMLだけで有限Intelidentity解析を検証します。
 * @param[in,out] context Assertion集計先。
 */
void runIntelCollectorIdentityParserTests( TestContext &context) ;

} // namespace drivercrate::test
