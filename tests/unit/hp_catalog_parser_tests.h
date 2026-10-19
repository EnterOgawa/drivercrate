//------------------------------------------------------------------------------
/**
 * @file hp_catalog_parser_tests.h
 * @brief HP公式catalog parser単体試験定義。
 * @version 01.00.00
 * @date 2026/09/02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 架空のHP platform listとreferenceを用いるoffline testを定義します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief HP catalog parserの正常系とsecurity拒否系を実行する。
 * HP catalog parserの正常系とsecurity境界を検証する。
 * COM MTAを初期化し、networkなしのHP parser試験を実行する。
 * @param[in,out] context assertion件数と失敗内容の集計先。 Assertion集計先。
 */
void runHpCatalogParserTests( TestContext &context) ;

} // namespace drivercrate::test
