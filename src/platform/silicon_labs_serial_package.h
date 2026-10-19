//------------------------------------------------------------------------------
/**
 * @file silicon_labs_serial_package.h
 * @brief Silicon Labs CP210x署名済みINF ZIP検証定義。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  公式serial取得と新版受入境界を更新。
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
 * @note 利用者がSilicon Labs公式pageから取得したCP210x ZIPを対象に、Windows x64用INF、CAT、SYSだけを選択し、端末内で検証します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/user_selected_inf_package.h"

#include <span>
#include <string_view>

namespace drivercrate {

/**
 * @brief Silicon Labs固有APIが使用する共通検証結果。
 */
using SiliconLabsSerialPackageContents = UserSelectedInfPackageContents ;

/**
 * @brief 構造検証済みINFが審査済みCP210x familyの新版受入条件を満たすか判定する。
 * CP210x familyの受入境界を公開する。
 * 内部testとpackage検証で同じ受入条件を使用する。
 * @param[in] package 構造検証済みINF metadata。署名検証は呼出し側が別途行う。
 * @return 有効なDriverVer、固定file構造、標準ID完全集合が成立する場合はtrue。 固定構造と有効なDriverVerが成立する場合はtrue。
 * @note 本判定だけで署名、入手元、現在deviceへの適用性を保証しない。
 */
[[nodiscard]] bool		  isSiliconLabsSerialPackageFamily( const OfficialInfPackage &package) ;

/**
 * @brief 利用者選択Silicon Labs CP210x ZIPを保護領域へ複製して検証する。
 * 利用者選択Silicon Labs CP210x ZIPを検証する。
 * 設定scriptと別architecture SYSを展開または実行しない。
 * @param[in] selectedPath 利用者が一件だけ選択したlocal ZIP path。 利用者選択ZIP path。
 * @param[in] scanSessionId 呼出し側が割り当てた0ではないscan session ID。
 * @param[in,out] workspace 未初期化の保護workspace。検証fileを単独所有する。 複製と選択展開fileの保護領域。
 * @param[out] contents 成功時のarchive hash、entry、検証済みINF。 全検証成功時のCP210x package情報。
 * @return 全検証成功時は0、入力、ZIP、INF、CATまたは署名違反時はHRESULT。 共通検証とCP210x固有検証の成功時は0。
 * @note 設定scriptと別architecture binaryは検査だけ行い、fileとして展開しない。
 */
[[nodiscard]] NativeError inspectSiliconLabsSerialPackageFile(
	std::wstring_view selectedPath, ScanSessionId scanSessionId,
	OfficialDownloadWorkspace &workspace, SiliconLabsSerialPackageContents &contents) ;

/**
 * @brief Silicon Labs CP210x INFをinstall直前に再検証する。
 * 保護領域の差替えをSetupAPI呼出し前にfail-closedで拒否する。
 * @param[in] workspace Scan時の複製ZIPと選択展開fileを所有する保護workspace。 Scan時の複製と選択展開file。
 * @param[in] entries Scan時に確定したINF、CAT、x64 SYS entry。 Scan時に確定した全3 file entry。
 * @param[in] expected Scan時に検証したINF metadata。
 * @return 構造、CP210x family、署名、CAT member、全metadataが一致する場合は0。 全file hash、INF、CAT member、metadata一致時は
 *         0。
 */
[[nodiscard]] NativeError reverifySiliconLabsSerialInfPackage(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	const OfficialInfPackage &expected) ;

/**
 * @brief INF内のPnP IDがCP210x 11.5.0の標準USB IDか判定する。
 * Custom VID／PID、revision追加、interface省略を拒否する。
 * @param[in] hardwareId 署名済みINFから取得したPnP Hardware ID。 署名済みINFから得たPnP ID。
 * @return 許可された`VID_10C4`、PID、interfaceへ完全一致する場合は`true`。 固定14 IDの一つへASCII case非依存で完全一致時は`true`。
 */
[[nodiscard]] bool isSiliconLabsSerialCandidateHardwareId( std::wstring_view hardwareId) noexcept ;

} // namespace drivercrate
