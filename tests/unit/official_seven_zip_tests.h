//------------------------------------------------------------------------------
/**
 * @file official_seven_zip_tests.h
 * @brief 公式7z有限展開単体試験定義。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  有限decoderの拒否試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Workspace展開試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Solid選択展開量の判定試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 合成7z byte列だけを使用し、networkやdriver導入に依存しないmetadata、memory展開、solid要求量、保護workspace選択展開の試験を定義します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief 公式7zの有限列挙、solid要求量、memory／workspace展開を検証する。
 * 正常memory展開と全fail-closed fixtureを順に実行する。
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
void runOfficialSevenZipTests( TestContext &context) ;

} // namespace drivercrate::test
