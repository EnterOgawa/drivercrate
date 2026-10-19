//------------------------------------------------------------------------------
/**
 * @file official_zip_tests.h
 * @brief 公式ZIP package安全展開単体試験定義。
 * @version 01.00.00
 * @date 2026/09/03
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 架空ZIP fixtureでpath、展開量、CRC、保護workspace境界を検証します。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief 公式ZIPの安全な事前検証と展開境界を検証する。
 * 公式ZIP安全展開の全単体試験を実行する。
 * 正常階層、危険path、有限上限、CRC改ざん試験を順に実行する。
 * @param[in,out] context Assertion件数と失敗内容の集計先。 Assertion集計先。
 */
void runOfficialZipTests( TestContext &context) ;

} // namespace drivercrate::test
