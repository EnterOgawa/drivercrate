//------------------------------------------------------------------------------
/**
 * @file official_preparation_tests.h
 * @brief 取得対象別承認の内部試験宣言。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  配布物単位の取得承認を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 合成計画だけを使う試験を登録し、外部通信と実導入は行いません。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {
class TestContext ;

/**
 * @brief 配布物単位の承認・有限予算・取消しの内部試験を実行する。
 * 合成計画の試験だけを実行し、実取得と実導入を行わない。
 * @param[in,out] context Assertionの集計先。
 */
void runOfficialPreparationTests( TestContext &context) ;
} // namespace drivercrate::test
