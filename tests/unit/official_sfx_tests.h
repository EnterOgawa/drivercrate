//------------------------------------------------------------------------------
/**
 * @file official_sfx_tests.h
 * @brief 公式自己解凍形式の静的識別単体試験定義。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  PE末尾7z識別の拒否試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Certificate直前padding試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 架空の小さいPE／7z byte列を使用し、必要最小限のzero alignmentを含む静的構造試験を定義します。実EXE、network、driver導入へ依存しません。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief PE末尾7z形式、Certificate直前padding、fail-closed境界を検証する。
 * 正常構造と全fail-closed fixtureを順に実行する。
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
void runOfficialSfxTests( TestContext &context) ;

} // namespace drivercrate::test
