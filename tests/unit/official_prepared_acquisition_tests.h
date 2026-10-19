//------------------------------------------------------------------------------
/**
 * @file official_prepared_acquisition_tests.h
 * @brief 配布物再確認付き取得の内部試験宣言。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  ASIX取得identity契約の試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  再確認と取得境界の試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 合成配布情報と取得callbackだけを使用し、実networkやdriver導入を行いません。
 */
//------------------------------------------------------------------------------

#pragma once
#include "test_framework.h"
namespace drivercrate::test {
/**
 * @brief 配布物identity・本文識別子・再確認・取消しの内部試験を実行する。
 * 合成metadataとcallbackだけで再確認、本文結合、取消し、部分失敗を試験する。
 * @param[in,out] context Assertionの集計先。 試験結果の集計先。
 */
void runOfficialPreparedAcquisitionTests( TestContext &context) ;
} // namespace drivercrate::test
