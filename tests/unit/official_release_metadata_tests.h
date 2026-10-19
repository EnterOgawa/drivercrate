//------------------------------------------------------------------------------
/**
 * @file official_release_metadata_tests.h
 * @brief 共通配布情報と検索境界の内部試験宣言。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  共通配布情報と検索接続を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 通信と実driver導入を行わない試験だけを登録します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {
class TestContext ;

/**
 * @brief 共通配布情報、local probe、表示専用検索の拒否境界を確認する。
 * 実network・復元・導入を使わない共通metadata試験を登録する。
 * @param[in,out] context Assertionの集計先。
 */
void runOfficialReleaseMetadataTests( TestContext &context) ;
} // namespace drivercrate::test
