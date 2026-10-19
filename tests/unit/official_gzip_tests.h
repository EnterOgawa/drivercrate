//------------------------------------------------------------------------------
/**
 * @file official_gzip_tests.h
 * @brief 公式GZip展開単体試験定義。
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
 * @note GZip正常展開、CRC、ISIZE、展開上限、単一member境界をnetworkなしで検証します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief 公式GZip展開の正常系とfail-closed境界を検証する。
 * 公式GZip展開の全単体試験を実行する。
 * 正常展開、integrity、上限、単一member試験を順に実行する。
 * @param[in,out] context Assertion件数と失敗内容の集計先。 Assertion集計先。
 */
void runOfficialGzipTests( TestContext &context) ;

} // namespace drivercrate::test
