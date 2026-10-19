//------------------------------------------------------------------------------
/**
 * @file official_discovery_tests.h
 * @brief 公式自動探索Core境界の単体試験宣言。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  自動探索Core境界試験を追加。
 * </pre>
 *
 * @note 実network、実PnP、payload取得、driver導入を行わない決定的fixtureだけを宣言します。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief 公式自動探索のrequest、device、route、summary拒否境界を検証する。
 * @param[in,out] context Assertionの集計先。
 */
void runOfficialDiscoveryTests( TestContext &context) ;

} // namespace drivercrate::test
