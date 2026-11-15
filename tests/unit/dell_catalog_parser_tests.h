//------------------------------------------------------------------------------
/**
 * @file dell_catalog_parser_tests.h
 * @brief Dell公式catalog parser単体試験定義
 * @version 01.00.02
 * @date 2026/09/02
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.00.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * </pre>
 *
 * @note Dell index/platform XMLの適用性とfail-closed境界をnetworkなしで検証します。試験dataは架空modelと架空Hardware IDだけを使用
 *       します
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

//------------------------------------------------------------------------------
/**
 * @brief Dell catalog parserの正常系とsecurity境界を検証する。COM MTAを初期化し、networkなしのDell parser試験群を実行する
 * @param[in,out] context assertion集計先
 */
//------------------------------------------------------------------------------
void runDellCatalogParserTests( TestContext &context) ;

} // namespace drivercrate::test
