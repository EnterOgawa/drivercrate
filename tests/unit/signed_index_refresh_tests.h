//------------------------------------------------------------------------------
/**
 * @file signed_index_refresh_tests.h
 * @brief 固定署名索引refreshの完全fake回帰入口です。
 * @version 01.00.00
 * @date 2026/10/16
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/16  固定18caseと事前variantの非通信入口を追加。
 * </pre>
 */
//------------------------------------------------------------------------------
#pragma once
namespace drivercrate::test {
class TestContext ;
/** @brief 完全fake HTTP/clock/storeとRAM暗号で固定全caseを実行します。
 * @param[in,out] context 呼出し側が所有するassertion/failure集計先です。
 * @note 製品store、永続鍵、通信、実機、導入を呼びません。
 */
void runSignedIndexRefreshTests( TestContext &context) ;
}
