//------------------------------------------------------------------------------
/**
 * @file provider_preparation_worker_tests.h
 * @brief 取得準備workerの内部試験宣言。
 * @version 01.00.00
 * @date 2026/09/06
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  一系列のWorker・Controller結合試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得計画とworker実行を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Fake Providerだけを使い、実driverと復元ポイントは変更しません。
 */
//------------------------------------------------------------------------------

#pragma once
namespace drivercrate::test {
class TestContext ;
/**
 * @brief 取得計画、queue、取消し、停止、一系列のWorker・Controller結合試験を実行する。
 * 有限待機のfakeだけでworkerの取得準備境界を確認する。
 * @param[in,out] context Assertionの集計先。
 */
void runProviderPreparationWorkerTests( TestContext &context) ;
} // namespace drivercrate::test
