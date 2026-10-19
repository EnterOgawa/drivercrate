//------------------------------------------------------------------------------
/**
 * @file official_record_payload_routing_tests.h
 * @brief 公式record payload三方式のrouting単体試験を定義します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  三方式・fallback禁止・秘密非出力fixtureを追加。
 * </pre>
 *
 * @note 実network、実driver、実install、installer起動を行わず、架空recordだけを使用します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief Record payloadの分類、表示評価、拒否と秘密非出力fixtureを実行します。
 * @param[in,out] context Assertion集計先です。
 */
void runOfficialRecordPayloadRoutingTests( TestContext &context) ;

} // namespace drivercrate::test
