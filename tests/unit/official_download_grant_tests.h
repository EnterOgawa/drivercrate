//------------------------------------------------------------------------------
/**
 * @file official_download_grant_tests.h
 * @brief 公式配布record、download grant、root resolution単体試験を定義します。
 * @version 01.02.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Record／grant／root routing fixtureを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Hop期限と一回非cache再解決fixtureを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  静的HTML／JSON record helper fixtureを追加。
 * </pre>
 *
 * @note 実network、実driver、実installを使用せず、全URLと配布情報は架空値に限定します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief Record、grant、固定root、静的HTML／JSONと秘密非出力の全fixtureを実行します。
 * @param[in,out] context Assertion集計先。
 */
void runOfficialDownloadGrantTests( TestContext &context) ;

} // namespace drivercrate::test
