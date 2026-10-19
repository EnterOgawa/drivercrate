//------------------------------------------------------------------------------
/**
 * @file intel_download_only_page_tests.h
 * @brief Intel非実行取得parser試験の宣言です。
 * @version 01.00.00
 * @date 2026/09/23
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/23  試験entryを追加。
 * </pre>
 */
//------------------------------------------------------------------------------

#pragma once
namespace drivercrate::test {
class TestContext ;
/**
 * @brief Intel EXE共通parserと拒否境界を通信なしで検証します。
 * @param[in,out] context assertion集計先。
 */
void runIntelDownloadOnlyPageTests( TestContext &context) ;
} // namespace drivercrate::test
