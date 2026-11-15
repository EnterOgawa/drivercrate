//------------------------------------------------------------------------------
/**
 * @file metadata_search_http_tests.h
 * @brief 共通HTTPの非通信backendによる情報検索境界試験
 * @version 01.00.02
 * @date 2026/09/12
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.00.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * </pre>
 *
 * @note 全I/Oをfixtureへ置換し、実通信・既存cache変更を行わない
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#pragma once
namespace drivercrate::test {
class TestContext ;
//------------------------------------------------------------------------------
/**
 * @brief 共通HTTPのmetadata専用境界を非通信fakeで検証する
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void runMetadataSearchHttpTests( TestContext &context) ;
}
