//------------------------------------------------------------------------------
/**
 * @file live_search_diagnostics_tests.h
 * @brief Live検索ASCII診断の単体試験契約。
 * @version 01.00.00
 * @date 2026/09/08
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 通信せず数値表示と出力先の故障境界を検証します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief Live検索のASCII診断とstream失敗時の結果を検証する。
 * Live検索の診断出力試験をまとめて実行する。
 * 固定record、locale独立性、故障sinkを非通信で検証する。
 * @param[in,out] context assertion集計先。 Assertion集計先。
 */
void runLiveSearchDiagnosticsTests( TestContext &context) ;

} // namespace drivercrate::test
