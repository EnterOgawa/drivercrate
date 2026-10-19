//------------------------------------------------------------------------------
/**
 * @file local_collector_metadata_codec_tests.h
 * @brief 実worker結果からmetadata codecを非通信検証します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  全field往復と改変拒否を追加。
 * </pre>
 *
 * @note Workerへの成功DTO注入、通信、永続受入を行いません。
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/local_collector_metadata_codec.h"
#include "test_framework.h"
namespace drivercrate::test {
/** @brief 全join後の正常結果を有限codecへ渡して改変拒否を検証します。
 * @param[in,out] context Assertion集計。
 * @param[in] job 元prepared job。
 * @param[in] worker 偽HTTPを解析した実worker結果。
 */
void runCollectorMetadataCodecChecks( TestContext &context, const CollectorProjectedJobInput &job,
									 const CollectorProjectedWorkerResult &worker) ;
}
