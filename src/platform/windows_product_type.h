//------------------------------------------------------------------------------
/**
 * @file windows_product_type.h
 * @brief Windows client／server種別判定定義。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  実OS build番号取得を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Product SKU取得を追加。
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
 * @note 実行中WindowsのServer種別、major build、product SKUを判定します。判定不能値で対象外OS向け処理や前回観測の再利用を許可しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include <cstdint>

namespace drivercrate {

/**
 * @brief 実行中OSがWindows Server productかを判定する。
 * Version Helperのproduct type判定を使用する。Serverと確認できない結果では復元ポイントなしinstallを許可しない。
 * @return Windows Serverの場合は`true`。Clientまたは判定不能の場合は`false`。 Windows Serverの場合は`true`。その他は`false`。
 * @note Server専用の復元ポイントなしinstallを許可するworker境界でも再確認する。
 */
[[nodiscard]] bool			isWindowsServer() noexcept ;

/**
 * @brief 実行中Windowsのmajor build番号を取得する。
 * Processに既に存在するntdllのRtlGetVersionを使用し、固定OS向け公式配布を別世代へ表示しないために使用する。
 * @return 取得できたbuild番号。判定不能、0、32bit超過の場合は0。 実行中Windowsのmajor build番号。判定不能時は0。
 * @note Manifestによるversion仮想化を避けるためworker内のOS境界判定に使用する。
 */
[[nodiscard]] std::uint32_t currentWindowsBuildNumber() noexcept ;

/**
 * @brief 実行中Windowsのproduct SKUを取得する。
 * Windows 10以降の10.0 versionを指定して実product SKUを取得し、edition変更時に前回release観測を失効可能にする。
 * @return GetProductInfoが返したPRODUCT_*値。取得不能または未定義時は0。 GetProductInfoが返すPRODUCT_*値。取得不能時は0。
 * @note 端末内OS fingerprintへedition差を反映するためだけに使用する。
 */
[[nodiscard]] std::uint32_t currentWindowsProductSku() noexcept ;

} // namespace drivercrate
