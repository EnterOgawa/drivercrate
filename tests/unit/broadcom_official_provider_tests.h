//------------------------------------------------------------------------------
/**
 * @file broadcom_official_provider_tests.h
 * @brief Broadcom配布情報の内部試験宣言。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  導入直前再検証と部分失敗試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  監査合格候補の生成試験を追加。
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
 * @note Network、実driver導入、実EULA同意を行わない。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {
class TestContext ;

/**
 * @brief Broadcom公開metadata・監査合格候補・導入再検証・拒否動作を試験する。
 * 合成metadata・取得対象化・導入再検証・部分失敗を確認する。実配布物、実PnP監査、実driver導入は行わない。
 * @param[in,out] context Assertion集計先。 回帰試験のassertion集計先。
 */
void runBroadcomOfficialProviderTests( TestContext &context) ;

} // namespace drivercrate::test
