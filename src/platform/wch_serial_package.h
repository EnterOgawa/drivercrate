//------------------------------------------------------------------------------
/**
 * @file wch_serial_package.h
 * @brief WCH USB serial署名済みINF ZIP検証定義。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  CH342／CH343系package検証追加。
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
 * @note 利用者選択WCH公式ZIPの現行Windows directoryだけを安全に選択し、CH340／CH341およびCH342／CH343系Ports INF、全参照file、固定
 *       archive、署名を製品family別の変更不可policyで検証します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/user_selected_inf_package.h"

#include <span>
#include <string_view>

namespace drivercrate {

class OfficialDownloadWorkspace ;

/**
 * @brief WCH固有APIが使用する共通利用者選択INF ZIP検証結果。
 */
using WchSerialPackageContents = UserSelectedInfPackageContents ;

/**
 * @brief 利用者選択WCH CH341SER ZIPを保護領域へ複製して検証する。
 * 利用者選択WCH CH341SER ZIPを検証する。
 * ZIP全体を検査し、現行subtreeだけを展開して署名検証する。
 * @param[in] selectedPath 利用者が公式siteから取得して選択した一つのZIP path。 利用者選択ZIP path。
 * @param[in] scanSessionId 0ではないscan session ID。
 * @param[in,out] workspace 未初期化の保護workspace。選択fileだけを単独所有する。 複製と選択fileの保護領域。
 * @param[out] contents 成功時のarchive identity、選択entry、検証済みINF。 全検証成功時のWCH package情報。
 * @return 全検証成功時は0、入力、ZIP、INF、CATまたは署名違反時はHRESULT。 共通検証とWCH固有検証の成功時は0。
 * @note 入手元を証明せず、固定`CH341SER\\WIN 1X` directory以外を展開しない。
 */
[[nodiscard]] NativeError inspectWchSerialPackageFile( std::wstring_view			 selectedPath,
													  ScanSessionId				 scanSessionId,
													  OfficialDownloadWorkspace &workspace,
													  WchSerialPackageContents	&contents) ;

/**
 * @brief WCH INFをinstall直前に再検証する。
 * Scan時と同じWCH policyでSetupAPI呼出し前に再検証する。
 * @param[in] workspace Scan時の選択fileを所有する保護workspace。 Scan時の保護領域。
 * @param[in] entries Scan時に確定した選択ZIP entry群。 Scan時に選択した展開file群。
 * @param[in] expected Scan時に候補へ対応付けたINF metadata。 Scan時のINF metadata。
 * @return 構造、WCH family、署名、CAT member、全metadataが一致する場合は0。 全metadata、family、CAT member、署名の一致時は0。
 */
[[nodiscard]] NativeError reverifyWchSerialInfPackage( const OfficialDownloadWorkspace  &workspace,
													  std::span<const OfficialZipEntry> entries,
													  const OfficialInfPackage		   &expected) ;

/**
 * @brief INF内のPnP IDがWCH公式CH341SER packageの固定USB IDか判定する。
 * PnP IDがWCH CH341SER固定USB IDか判定する。
 * PrefixやPIDの部分一致を許さず、custom VID／PIDを除外する。
 * @param[in] hardwareId 署名済みINFから取得したPnP ID。 署名済みINFから得たPnP ID。
 * @return 固定VID／PIDまたは公式INFの固定revision IDと完全一致する場合は`true`。 固定allowlistへ完全一致する場合は`true`。
 */
[[nodiscard]] bool		  isWchSerialCandidateHardwareId( std::wstring_view hardwareId) noexcept ;

/**
 * @brief 利用者選択WCH CH343SER ZIPを保護領域へ複製して検証する。
 * 利用者選択WCH CH343SER 2.2 ZIPを検証する。
 * ZIP全体を検査し、固定現行subtreeだけを展開・検証する。
 * @param[in] selectedPath 利用者が公式siteから取得して選択した一つのZIP path。 利用者選択ZIP path。
 * @param[in] scanSessionId 0ではないscan session ID。
 * @param[in,out] workspace 未初期化の保護workspace。選択fileだけを単独所有する。 複製と選択fileの保護領域。
 * @param[out] contents 成功時のarchive identity、選択entry、検証済みINF。 全検証成功時のWCH package情報。
 * @return 全検証成功時は0、入力、ZIP、INF、CATまたは署名違反時はHRESULT。 固定archiveとWCH固有検証の成功時は0。
 * @note 入手元を証明せず、固定`CH343SER\\Driver\\WIN 1X`以外を展開しない。
 */
[[nodiscard]] NativeError inspectWchMultiSerialPackageFile( std::wstring_view		  selectedPath,
														   ScanSessionId			  scanSessionId,
														   OfficialDownloadWorkspace &workspace,
														   WchSerialPackageContents	 &contents) ;

/**
 * @brief WCH CH342／CH343系INFをinstall直前に再検証する。
 * Scan時と同じCH343SER 2.2 policyでSetupAPI前に再検証する。
 * @param[in] workspace Scan時の選択fileを所有する保護workspace。 Scan時の保護領域。
 * @param[in] entries Scan時に確定した選択ZIP entry群。 Scan時に選択した展開file群。
 * @param[in] expected Scan時に候補へ対応付けたINF metadata。 Scan時のINF metadata。
 * @return 固定archive、全file hash、構造、WCH family、署名が一致する場合は0。 固定archive、全file hash、metadata、署名一致時は0。
 */
[[nodiscard]] NativeError reverifyWchMultiSerialInfPackage(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	const OfficialInfPackage &expected) ;

/**
 * @brief INF内のPnP IDがWCH公式CH343SER 2.2の固定USB IDか判定する。
 * PnP IDがWCH CH343SER 2.2の固定USB IDか判定する。
 * Interfaceとrevisionを含むIDを短縮せず、custom IDを除外する。
 * @param[in] hardwareId 署名済みINFから取得したPnP ID。 署名済みINFから得たPnP ID。
 * @return 固定VID／PID／interface／revision IDと完全一致する場合は`true`。 固定allowlistへ完全一致する場合は`true`。
 */
[[nodiscard]] bool isWchMultiSerialCandidateHardwareId( std::wstring_view hardwareId) noexcept ;

} // namespace drivercrate
