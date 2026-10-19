//------------------------------------------------------------------------------
/**
 * @file asix_catalog_parser_tests.h
 * @brief ASIX AX88179A公式検索単体試験定義。
 * @version 01.00.00
 * @date 2026/09/06
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Terms解析と取得前record結合試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Networkと実deviceを使用せず、製品・Terms parser、OS選択、表示専用scanを検証します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "test_framework.h"

namespace drivercrate::test {

/**
 * @brief ASIX製品・Terms parser、OS別record、表示専用Provider helperの試験を実行する。
 * 製品・Terms parser、OS別record、local probeと拒否経路を登録する。
 * @param[in,out] context Assertionの集計先。
 */
void runAsixCatalogParserTests( TestContext &context) ;

} // namespace drivercrate::test
