//------------------------------------------------------------------------------
/**
 * @file metadata_search_tests.h
 * @brief 情報検索専用契約の決定的試験宣言。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  Metadata専用検索の契約を追加。
 * </pre>
 *
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {
class TestContext ;

/**
 * @brief 専用要求と表示専用境界を非通信fixtureで検証する。
 * @param[in,out] context Assertionを記録する集計先。
 */
void runMetadataSearchTests( TestContext &context) ;

} // namespace drivercrate::test
