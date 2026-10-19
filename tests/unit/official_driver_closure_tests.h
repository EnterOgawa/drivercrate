//------------------------------------------------------------------------------
/**
 * @file official_driver_closure_tests.h
 * @brief 公式driver package監査単体試験定義。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX内容・適用性・report fixture追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernet適用性・report fixture追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernet監査拒否fixture追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 架空ZIPとINFで固定profile、mixed archive、禁止参照および一段nested抽出をnetworkとdriver installに依存せず検証します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief 公式driver package監査、選択的閉包抽出の安全性と有限上限を検証する。
 * Intel／ASIX固定profile、PnP／report、Mixed archive分離、禁止参照、directiveおよび一段nested ZIPを順に検証する。
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
void runOfficialDriverClosureTests( TestContext &context) ;

} // namespace drivercrate::test
