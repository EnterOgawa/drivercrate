//------------------------------------------------------------------------------
/**
 * @file prepared_audit_display_tests.h
 * @brief 取得後監査表示の内部試験契約。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  監査合格候補の発行試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の表示境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 非機密の監査表示と全監査合格候補の発行境界を合成値で確認します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {
class TestContext ;
/**
 * @brief 合成監査と候補だけで表示・発行境界を検証する。
 * 表示変換、候補発行、境界拒否、Controller選択を合成値だけで確認する。
 * @param[in,out] context Assertionの集計先。
 */
void runPreparedAuditDisplayTests( TestContext &context) ;
} // namespace drivercrate::test
