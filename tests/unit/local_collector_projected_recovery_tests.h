//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_recovery_tests.h
 * @brief input-v3登録と旧世代回収の非通信試験を宣言します。
 * @version 01.00.00
 * @date 2026/09/28
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  新世代登録と旧回収の非通信fixtureを追加。
 * </pre>
 *
 * @note 自作fixture rootだけを使用し、通信・実driver処理を行いません。
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/local_collector_projected_input.h"
#include "test_framework.h"
#include <filesystem>
#include <functional>
namespace drivercrate::test {
/** @brief 新codec・移行・再起動・旧予約拒否を実保護storeで検査します。
 * @param[in,out] context Assertion集計。
 * @param[in] rootFactory 自作GUID rootの同期生成関数。
 * @param[in] inputFactory 公開製品値だけを持つ非通信定義。
 */
void runCollectorProjectedRecoveryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &inputFactory) ;
} // namespace drivercrate::test
