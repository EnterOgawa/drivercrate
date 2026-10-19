//------------------------------------------------------------------------------
/**
 * @file openpgp_signature_verifier_tests.h
 * @brief OpenPGP detached signature単体試験定義。
 * @version 01.00.00
 * @date 2026/09/02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 架空RSA鍵のfixtureで正常署名、改ざん、未知鍵、未対応digestを検証します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief OpenPGP verifierの正常系とfail-closed境界を検証する。
 * OpenPGP verifierの全単体試験を実行する。
 * 正常署名、改ざん、未知鍵、未対応algorithm試験を実行する。
 * @param[in,out] context Assertion件数と失敗内容の集計先。 Assertion集計先。
 */
void runOpenpgpSignatureVerifierTests( TestContext &context) ;

} // namespace drivercrate::test
