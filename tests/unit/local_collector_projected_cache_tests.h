//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_cache_tests.h
 * @brief CACHEの非保存更新と履歴保持を検証します。
 * @version 01.00.00
 * @date 2026/09/29
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  有限CACHE更新と旧中断互換のfixtureを追加。
 * </pre>
 *
 * @note 通信・実成功CACHE保存・条件付き送信は行いません。
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/local_collector_projected_cache.h"
#include "test_framework.h"
namespace drivercrate::test {
/** @brief 初回CACHEの全field・元hash故障・旧中断形を検査します。
 * @param[in,out] context Assertion集計。
 * @param[in] job 元scope。
 * @param[in] bytes 独立応答codecを通る元byte。
 */
void runCollectorCacheChecks( TestContext &context, const CollectorProjectedJobInput &job,
							 const CollectorProjectedResponseBytes &bytes) ;
/** @brief 前日成功から減少・部分・失敗・完全成功への更新を検査します。
 * @param[in,out] context Assertion集計。
 * @param[in] prior 前日参照fixture。登録済み証明ではありません。
 * @param[in] job 今回scope。
 * @param[in] bytes 減少最終化後の今回byte。
 */
void runCollectorCacheTransitionChecks( TestContext							   &context,
									   const CollectorProjectedHistoryEvidence &prior,
									   const CollectorProjectedJobInput		   &job,
									   const CollectorProjectedResponseBytes   &bytes) ;
} // namespace drivercrate::test
