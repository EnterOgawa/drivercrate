//------------------------------------------------------------------------------
/**
 * @file official_driver_closure_tests.h
 * @brief 公式driver package監査単体試験定義
 * @version 01.02.00
 * @date 2026/09/04
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX内容・適用性・report fixture追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernet適用性・report fixture追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernet監査拒否fixture追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.00.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.01.00 Shunji Ogawa  2026/11/18  限定registry-onlyの実reader/閉包と導入拒否を有限回帰
 * Ver.01.02.00 Shunji Ogawa  2026/11/19  収集元の登録とPE exportの限定回帰を公開
 * </pre>
 *
 * @note 架空ZIPとINFで固定profile、mixed archive、禁止参照および一段nested抽出をnetworkとdriver installに依存せず検証します
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

//------------------------------------------------------------------------------
/**
 * @brief 公式driver package監査、選択的閉包抽出の安全性と有限上限を検証する。Intel／ASIX固定profile、PnP／report、Mixed archive分離、禁止
 *        参照、directiveおよび一段nested ZIPを順に検証する
 * @param[in,out] context Assertion件数と失敗内容の集計先
 */
//------------------------------------------------------------------------------
void runOfficialDriverClosureTests( TestContext &context) ;

//------------------------------------------------------------------------------
/**
 * @brief 限定registry-onlyの実閉包と拒否だけを通常unit selectorへ返します
 * @param[in,out] context 元C/D期待と到達phaseを保持する集計先です
 * @note 全旧suiteを呼ばず、実driver/HTTP/registry書込を行いません
 */
//------------------------------------------------------------------------------
void runRequiredRegistrySystemContentTests( TestContext &context) ;

//------------------------------------------------------------------------------
/**
 * @brief デバイス別の収集登録、原CAT、非実行DLLの正常・拒否境界を確認します
 * @param[in,out] context 全条件の到達phaseと拒否理由を集計します
 */
//------------------------------------------------------------------------------
void runCollectorPropertyPageTests( TestContext &context) ;

} // namespace drivercrate::test
