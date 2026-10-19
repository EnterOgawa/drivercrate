//------------------------------------------------------------------------------
/**
 * @file official_acquisition_tests.h
 * @brief 公式file検査用取得境界単体試験定義。
 * @version 01.01.00
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/10/06  独立取得証拠試験の入口を追加。
 * </pre>
 *
 * @note Networkへ接続せず、検査用取得の予算、取消し、根拠、hashを検証します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief 公式file検査用取得境界の正常系とfail-closed条件を検証する。
 * 公式file検査用取得境界の全単体試験を実行する。
 * 初期化、取得、根拠、network、取消し、予算試験を順に行う。
 * @param[in,out] context Assertion集計先。
 */
void runOfficialAcquisitionTests( TestContext &context) ;

/**
 * @brief 非通信の架空取得から封印証拠の所有権・拒否・失効を検証する。
 * @param[in,out] context 独立processのassertion集計先。
 * @note 通常unitの件数を変更せず、専用targetからだけ呼ぶ。
 */
void runOfficialAcquiredFileEvidenceTests( TestContext &context) ;

} // namespace drivercrate::test
