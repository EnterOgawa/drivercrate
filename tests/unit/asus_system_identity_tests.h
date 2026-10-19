//------------------------------------------------------------------------------
/**
 * @file asus_system_identity_tests.h
 * @brief ASUS local system識別単体試験定義。
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
 * @note 架空SMBIOS表示値だけでASUS判定、model選択、URL encodeを検証します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief ASUS local system識別の単体試験を実行する。
 * ASUS local system識別単体試験を実行する。
 * System、baseboard、対象外、拒否経路を順番に検証する。
 * @param[in,out] context assertion件数と失敗内容の集計先。 Assertion集計先。
 */
void runAsusSystemIdentityTests( TestContext &context) ;

} // namespace drivercrate::test
