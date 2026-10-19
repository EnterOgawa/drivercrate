//------------------------------------------------------------------------------
/**
 * @file nvidia_winof2_driver_package_tests.h
 * @brief NVIDIA WinOF-2 MSI driver閉包単体試験定義。
 * @version 01.00.00
 * @date 2026/09/07
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  MSI／CAB閉包fixtureを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 架空MSIとCABだけでFile mapping、選択閉包、mixed file除外、拒否境界を検証します。Network、実driver、installには依存しません。
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief WinOF-2 MSIからdriver閉包を分離する正常系と拒否境界を検証する。
 * 正常閉包、未知INF、identity、mapping拒否を順に実行する。
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
void runNvidiaWinof2DriverPackageTests( TestContext &context) ;

} // namespace drivercrate::test
