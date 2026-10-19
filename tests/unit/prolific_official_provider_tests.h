//------------------------------------------------------------------------------
/**
 * @file prolific_official_provider_tests.h
 * @brief 公式serialの探索・新版受入境界試験。
 * @version 01.00.00
 * @date 2026/09/05
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 公式配布行、今回の取得同意、新版family受入の境界を試験します。実通信、実driver導入、実復元ポイントを使用しません。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {
class TestContext ;
/**
 * @brief 公式serial取得と新版受入の内部試験を実行する。
 * 公式serial経路と新版受入の内部試験を実行する。
 * Network、実driver導入、実復元ポイントに依存しない。
 * @param[in,out] context Assertion集計先。
 */
void runProlificOfficialProviderTests( TestContext &context) ;
} // namespace drivercrate::test
