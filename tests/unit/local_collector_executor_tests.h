//------------------------------------------------------------------------------
/**
 * @file local_collector_executor_tests.h
 * @brief v3観測保存と有限監督の非通信試験を定義します。
 * @version 01.01.00
 * @date 2026/09/27
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/27  応答v3・所有worker回収を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/27  保存中取消し・監督診断の受入を追加。
 * </pre>
 *
 * @note 開発用の有限収集に限定し、製品の取得・導入を許可しません。
 * @see docs/adr/0218-collector-controlled-http-lifetime.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "test_framework.h"
#include "platform/local_collector_recovery.h"
#include <filesystem>
#include <functional>
namespace drivercrate::test {
/** @brief v3の保存・改変拒否・旧version非変更を検査します。
 * @param[in,out] context Assertion集計。
 * @param[in] rootFactory 自作GUIDの一時保護rootを返す同期関数。
 * @param[in] inputFactory 架空の独立group入力を返す同期関数。
 */
void runCollectorV3RecoveryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorRecoveryInput( std::size_t)> &inputFactory) ;
/** @brief 四枠の終了・保存・停止・起動失敗を検査します。
 * @param[in,out] context Assertion集計。
 * @param[in] rootFactory 自作GUIDの一時保護rootを返す同期関数。
 * @param[in] inputFactory 架空の独立group入力を返す同期関数。
 */
void runCollectorExecutorTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorRecoveryInput( std::size_t)> &inputFactory) ;
/** @brief 保存中の取消し伝播・資源診断と横断した受入を検査します。
 * @param[in,out] context 同じ監督threadのAssertion集計。
 * @param[in] rootFactory 自作GUIDの一時保護rootを返す同期関数。
 * @param[in] inputFactory 架空の独立group入力を返す同期関数。
 */
void runCollectorExecutorAcceptanceTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorRecoveryInput( std::size_t)> &inputFactory) ;
} // namespace drivercrate::test
