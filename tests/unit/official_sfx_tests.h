//------------------------------------------------------------------------------
/**
 * @file official_sfx_tests.h
 * @brief 公式自己解凍形式の静的識別単体試験定義
 * @version 01.00.04
 * @date 2026/09/06
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  PE末尾7z識別の拒否試験を追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Certificate直前padding試験を追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.00.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.00.03 Shunji Ogawa  2026/11/23  WiX v3の試験契約を追記
 * Ver.01.00.04 Shunji Ogawa  2026/11/23  WiX v3マニフェストの内容選択試験を追記
 * </pre>
 *
 * @note 架空のPEを使い、7zとWiX v3の元範囲と整列を非実行で試験する
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

//------------------------------------------------------------------------------
/**
 * @brief PE末尾7zとWiX v3の境界、元マニフェストの内容選択、破損時の拒否を検証する
 * @param[in,out] context Assertion件数と失敗内容の集計先
 */
//------------------------------------------------------------------------------
void runOfficialSfxTests( TestContext &context) ;

} // namespace drivercrate::test
