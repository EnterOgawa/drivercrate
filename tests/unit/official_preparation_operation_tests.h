//------------------------------------------------------------------------------
/**
 * @file official_preparation_operation_tests.h
 * @brief 承認済み取得実行の内部試験宣言。
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
 * @note 実通信せず、fake取得結果だけで状態遷移と呼出回数を確認します。
 */
//------------------------------------------------------------------------------

#pragma once
namespace drivercrate::test {
class TestContext ;
/**
 * @brief 取得executorの選択・取消し・例外試験を実行する。
 * 合成対象だけの取得executor試験を実行する。
 * @param[in,out] context Assertionの集計先。
 */
void runOfficialPreparationOperationTests( TestContext &context) ;
} // namespace drivercrate::test
