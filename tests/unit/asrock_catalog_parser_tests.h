//------------------------------------------------------------------------------
/**
 * @file asrock_catalog_parser_tests.h
 * @brief ASRock公式Web parser単体試験定義。
 * @version 01.00.00
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 実device情報とnetworkを使用せず、架空ASRock page fixtureを検証します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief ASRock公式Web parserと表示専用Provider拒否経路を実行する。
 * ASRock公式Web parserの全単体試験を実行する。
 * 一覧抽出、device関連付け、拒否、install拒否を検証する。
 * @param[in,out] context Assertion集計先。
 */
void runAsrockCatalogParserTests( TestContext &context) ;

} // namespace drivercrate::test
