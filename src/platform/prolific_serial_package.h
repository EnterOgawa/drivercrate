//------------------------------------------------------------------------------
/**
 * @file prolific_serial_package.h
 * @brief Prolific serial署名済みINF ZIP検証定義。
 * @version 01.00.01
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
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 利用者がProlific公式pageから取得したDCHU INF ZIPを対象に、Ports class、Provider、標準VID、署名、CAT memberを端末内で検証します
 *       。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/user_selected_inf_package.h"

#include <span>
#include <string_view>

namespace drivercrate {

/**
 * @brief Prolific固有APIが使用する共通検証結果。
 */
using ProlificSerialPackageContents = UserSelectedInfPackageContents ;

/**
 * @brief 利用者選択Prolific DCHU ZIPを保護領域へ複製して検証する。
 * 利用者選択Prolific DCHU ZIPを検証する。
 * 入手元を推測せず、一段nested ZIPを含む内容だけを検証する。
 * @param[in] selectedPath 利用者が一件だけ選択したlocal ZIP path。 利用者選択ZIP path。
 * @param[in] scanSessionId 呼出し側が割り当てた0ではないscan session ID。
 * @param[in,out] workspace 未初期化の保護workspace。検証fileを単独所有する。 複製と展開fileの保護領域。
 * @param[out] contents 成功時のarchive hash、entry、検証済みINF。失敗時は完了段階だけを保持する。 全検証成功時のProlific package情報。
 * @return 全検証成功時は0、入力、ZIP、INF、CATまたは署名違反時はHRESULT。 共通検証とProlific固有検証の成功時は0。
 * @note 公式外側ZIPに含まれるWindows 10用と11用の一段nested ZIPも検証する。
 */
[[nodiscard]] NativeError inspectProlificSerialPackageFile( std::wstring_view		  selectedPath,
														   ScanSessionId			  scanSessionId,
														   OfficialDownloadWorkspace &workspace,
														   ProlificSerialPackageContents &contents) ;

/**
 * @brief Prolific INFをinstall直前に再検証する。
 * Scan時と同じProlific policyでSetupAPI呼出し前に再検証する。
 * @param[in] workspace Scan時の複製ZIPと展開fileを所有する保護workspace。 Scan時の保護領域。
 * @param[in] entries Scan時に確定した全ZIP entry。 Scan時の全展開file。
 * @param[in] expected Scan時に検証したINF metadata。 Scan時のINF metadata。
 * @return 構造、Prolific family、署名、CAT member、全metadataが一致する場合は0。 全metadata、family、CAT member、署名の一致時は0
 *         。
 */
[[nodiscard]] NativeError reverifyProlificSerialInfPackage(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	const OfficialInfPackage &expected) ;

/**
 * @brief INF内のPnP IDが公式pageで明示されたProlific標準USB IDか判定する。
 * PnP IDがProlific公式pageの標準VIDとPIDか判定する。
 * PIDの部分一致を許さず、revisionまたはinterface suffixだけ許可する。
 * @param[in] hardwareId 署名済みINFから取得したPnP Hardware ID。 署名済みINFから得たPnP ID。
 * @return 許可された`VID_067B`とPIDに完全一致する場合は`true`。 `VID_067B`、許可PID、許可形式に完全一致時は`true`。
 */
[[nodiscard]] bool isProlificSerialCandidateHardwareId( std::wstring_view hardwareId) noexcept ;

} // namespace drivercrate
