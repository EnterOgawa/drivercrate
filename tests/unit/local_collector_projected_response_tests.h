//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_response_tests.h
 * @brief 同一GETの応答v4を非通信で検証します。
 * @version 01.01.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  元観測・hash・有限縮退のfixtureを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/29  元成功参照・減少・改変fixture入口を追加。
 * </pre>
 *
 * @note 親の予約受入・永続保存・通信は実行しません。
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/local_collector_projected_response.h"
#include "test_framework.h"
#include <map>
namespace drivercrate::test {
/** @brief 全join後の実worker観測を応答codecへ渡します。
 * @param[in,out] context Assertion集計。
 * @param[in] job 元prepared job。
 * @param[in] worker 偽HTTP本文を処理した実worker結果。
 */
void runCollectorProjectedResponseChecks( TestContext						  &context,
										 const CollectorProjectedJobInput	  &job,
										 const CollectorProjectedWorkerResult &worker) ;
/** @brief 実workerから合成した前日参照を元byteで検証します。
 * @param[in,out] context 試験集計。
 * @param[in] definition 元scopeの公開定義。
 * @param[in] prepared 今回の不変入力。
 * @param[in] workers 件数・元失敗別の全join後観測。100以上はIntel、それ以外はASUSです。
 * @note 前日の取得や登録済み成功CACHEを実測したものではありません。
 */
void runCollectorProjectedHistoryChecks(
	TestContext &context, const CollectorProjectedCampaignDefinition &definition,
	const std::shared_ptr<const CollectorPreparedProjectedCampaign> &prepared,
	const std::map<unsigned, CollectorProjectedWorkerResult>		&workers) ;
}
