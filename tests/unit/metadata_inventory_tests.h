//------------------------------------------------------------------------------
/**
 * @file metadata_inventory_tests.h
 * @brief 現在属性列挙の上限・欠損・停止境界の決定的試験。
 * @version 01.03.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  SetupAPIの非実機列挙fixtureを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/11  秘密属性resolverと保存snapshotの内部試験を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/11  通常workerの同scan署名索引読取り境界を接続。
 * Ver.01.03.00 Shunji Ogawa  2026/10/14  Native部分positiveから同署名取得準備の正負を追加。
 * </pre>
 *
 * @note 現在属性の五APIを全てfakeへ置換し、実device列挙と導入を行わない。
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#pragma once
#include "platform/signed_index_store.h"
#include <chrono>
#include <memory>
namespace drivercrate::test {
class TestContext ;
/** @brief 実通常ScanCommandへ隔離保存storeと完全fake inventoryを結びます。
 * @param[in,out] context 共通assertion集計先。
 * @param[in] store 実署名・commit済みの隔離store。製品rootではありません。
 * @param[in] nowUtc Fixtureの信頼UTC。
 * @param[in] expectedRecords 保存storeの元record件数。
 */
void runWorkerSignedIndexScanTests( TestContext &context, std::shared_ptr<SignedIndexStore> store,
								   std::chrono::sys_seconds nowUtc, std::size_t expectedRecords) ;
/**
 * @brief 現在属性列挙の有限境界と停止を実機非依存で検証する。
 * @param[in,out] context Assertion集計先。
 */
void runMetadataInventoryTests( TestContext &context) ;
/** @brief 全fake現在属性scanの秘密stateを真の保存snapshotへ結びます。
 * @param[in,out] context 共通assertion集計先。
 * @param[in] snapshot 実commit／reload済みconst原snapshot。
 * @param[in] nowUtc Fixtureの信頼UTC。
 * @note 実inventory・履歴・network・導入を行いません。
 */
void runDriverStoreIndexResolverTests( TestContext									   &context,
									  std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot,
									  std::chrono::sys_seconds							nowUtc) ;
/** @brief Native証拠付き部分positiveだけを同v2取得準備へ接続します。
 * @param[in,out] context 共通assertion集計先です。
 * @param[in] snapshot 真署名・隔離保存された同意不要v2 fixtureです。
 * @param[in] nowUtc 同snapshotの信頼UTCです。
 * @note HTTP、実端末、実取得・導入、製品storeや署名秘密鍵を使用しません。
 */
void runNativePartialIndexPreparationTests(
	TestContext &context, std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot,
	std::chrono::sys_seconds nowUtc) ;
}
