//------------------------------------------------------------------------------
/**
 * @file official_discovery_provider_adapter_tests.h
 * @brief 組み込み公式自動探索registration接続試験を宣言する。
 * @version 01.01.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  固定root registration接続試験を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  部分失敗・重複・privacy試験を追加。
 * </pre>
 *
 * @note 実network、payload取得、driverまたはinstaller実行を行わない合成fixtureだけを使用する。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief Intel matcher、固定root接続、部分失敗、重複、privacy境界を検証する。
 * @param[in,out] context Assertion集計先。
 */
void runOfficialDiscoveryProviderAdapterTests( TestContext &context) ;

} // namespace drivercrate::test
