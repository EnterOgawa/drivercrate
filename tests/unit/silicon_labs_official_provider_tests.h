//------------------------------------------------------------------------------
/**
 * @file silicon_labs_official_provider_tests.h
 * @brief CP210x公式検索と共通serial境界の試験契約。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  CP210x公式検索の拒否境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Network、実file、実deviceの変更に依存しない内部試験。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {
class TestContext ;
/**
 * @brief CP210x公式metadata、同意、family限定監査を通信なしで検証する。
 * Parser、同意、family監査をnetworkと実導入なしで実行する。
 * @param[in,out] context Assertion結果の集計先。 全試験のassertion集計先。
 */
void runSiliconLabsOfficialProviderTests( TestContext &context) ;
} // namespace drivercrate::test
