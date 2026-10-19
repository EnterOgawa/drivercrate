//------------------------------------------------------------------------------
/**
 * @file metadata_search_runner_tests.h
 * @brief 専用情報検索実行の非通信試験宣言。
 * @version 01.00.00
 * @date 2026/09/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  非取得専用実行の決定的試験を追加。
 * </pre>
 *
 * @note OS列挙とnetworkをfakeに置換し、実payloadと実導入を呼ばない。
 */
//------------------------------------------------------------------------------

#pragma once
namespace drivercrate::test {
class TestContext ;
/**
 * @brief Registry、部分結果、非取得、権限と専用metadata helperを検証する。
 * @param[in,out] context Assertionの集計先。
 */
void runMetadataSearchRunnerTests( TestContext &context) ;
} // namespace drivercrate::test
