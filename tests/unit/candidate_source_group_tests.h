//------------------------------------------------------------------------------
/**
 * @file candidate_source_group_tests.h
 * @brief 同一版取得元候補group単体試験定義。
 * @version 01.00.00
 * @date 2026/09/02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  候補別既定選択根拠試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Networkと端末情報を使用せず、同一版取得元group規則を試験します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief 同一版group、既定取得元、曖昧候補、入力拒否条件を検証する。
 * 同一版取得元候補groupの全単体試験を実行する。
 * Group、既定取得元、非group条件、入力拒否を順に検証する。
 * @param[in,out] context assertion集計先。
 */
void runCandidateSourceGroupTests( TestContext &context) ;

} // namespace drivercrate::test
