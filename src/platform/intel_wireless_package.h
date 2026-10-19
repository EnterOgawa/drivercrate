//------------------------------------------------------------------------------
/**
 * @file intel_wireless_package.h
 * @brief Intel Wireless署名済みINF ZIP検証定義。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  共通利用者選択ZIP検証へ接続。
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
 * @note 利用者がIntelの利用許諾へ同意して取得したdriver-only ZIPを保護領域へ複製し、全INF、CAT、参照fileをsystem変更なしで検証します。選択元pathと
 *       PnP IDはUI、networkまたは永続logへ渡しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/user_selected_inf_package.h"

#include <span>
#include <string>
#include <string_view>

namespace drivercrate {

/**
 * @brief Intel公開APIが使用する共通検証結果。
 */
using IntelWirelessPackageContents = UserSelectedInfPackageContents ;

/**
 * @brief 利用者選択Intel Wireless ZIPを保護領域へ複製して全driverを検証する。
 * 利用者選択Intel Wireless ZIPを検証する。
 * 選択元の由来を公式とは断定せず、Intel Provider、Windows driver署名、CAT member、x64 Net classを実内容で検証する。
 * @param[in] selectedPath File dialogで利用者が一件だけ選択したlocal ZIP path。 利用者が選択したlocal ZIP path。
 * @param[in] scanSessionId 呼出し側が割り当てた0ではないscan session ID。
 * @param[in,out] workspace 未初期化の保護workspace。成功・失敗を問わずfileを所有する。 複製と展開fileを所有する保護領域。
 * @param[out] contents 成功時のarchive hash、entryおよび検証済みINF。失敗時は空にする。 成功時の検証済みpackage情報。
 * @return 全検証成功時は0、入力file、ZIP、INF、CATまたは署名違反時はHRESULT。 全ZIP、INF、CAT、参照file検証成功時は0。
 * @note 本関数はdownload、EULA同意、driver installを行わない。選択元fileは共有なしで開く。
 */
[[nodiscard]] NativeError inspectIntelWirelessPackageFile( std::wstring_view			 selectedPath,
														  ScanSessionId				 scanSessionId,
														  OfficialDownloadWorkspace &workspace,
														  IntelWirelessPackageContents &contents) ;

/**
 * @brief 一つのIntel Wireless INFをinstall直前に再検証する。
 * 再検証結果をscan時の完全なsnapshotへ比較し、差替えられたpackageをSetupAPIへ渡さない。
 * @param[in] workspace Scan時の複製ZIPと展開fileを所有する保護workspace。 Scan時の展開fileを所有する保護領域。
 * @param[in] entries Scan時に確定した全ZIP entry。
 * @param[in] expected Scan時に検証してcandidateへ対応付けたINF metadata。 Scan時に検証したINF metadata。
 * @return 構造、署名、CAT member、全metadataがScan時と一致する場合は0。 構造、署名、CAT member、metadataが全て一致する場合は0。
 * @note File変更、欠落、別INFへの差替えを検出した場合は導入前に拒否する。
 */
[[nodiscard]] NativeError reverifyIntelWirelessInfPackage(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	const OfficialInfPackage &expected) ;

} // namespace drivercrate
