//------------------------------------------------------------------------------
/**
 * @file generic_inf_package.h
 * @brief 汎用署名済みINF ZIP検証定義。
 * @version 01.01.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  SYS不要Printer INF対応追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  PrinterとPrintQueueの照合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  WIA user-mode Image INF対応追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Nested archive拒否を厳格化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Peripheral firmware拒否を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Virtual audio PnP ID拒否を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Virtual capture PnP ID拒否を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Mobile／virtual payload拒否を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Software device全class拒否を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  共通個別INF検査のlocal入力adapterを追加。
 * Ver.01.01.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 利用者が選択した取得元未証明のdriver-only ZIPを、非boot-criticalなsetup class、WHCP署名、CAT member、PnP ID完全一致へ限定し
 *       ます。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/user_selected_inf_package.h"

#include <span>
#include <string_view>

namespace drivercrate {

class OfficialDownloadWorkspace ;

/**
 * @brief 汎用Providerが使用する共通検証結果。
 */
using GenericInfPackageContents = UserSelectedInfPackageContents ;

/**
 * @brief 構造検証済みINFが汎用Providerのdriver-only条件を満たすか判定する。
 * 汎用INF packageのdriver-only条件を確認する。
 * ADR 0076／0077に従い、SYS不要条件をPrinterとDLL型Imageへ限定し、ADR 0078～0083の複合payload、software device、firmwareを拒
 * 否する。
 * @param[in] package Class、version、PnP ID、参照fileを検証済みのINF。 構造検証済みのINF metadata。
 * @return Printer、DLL型Image、またはSYSを持つ許可packageの場合は`true`。 Container／virtual image／firmware参照がなく、
 *         Printer、DLL型Image、またはSYSを持つ場合は`true`。
 * @note PrinterはWindows inbox print stackを利用する正規packageに限りSYSなしを許可する。
 * @note ImageはCAT保護されたvendor DLLを参照するWIA packageだけを許可する。
 * @note 内側container、virtual image、firmwareを参照する複合packageは拒否する。
 * @note 全許可classのsoftware enumeratorは別capabilityがないため拒否する。
 */
[[nodiscard]] bool		  isGenericInfPackageSupported( const OfficialInfPackage &package) ;

/**
 * @brief 汎用INFのsetup classと現在device classの対応を判定する。
 * 汎用INFと現在deviceのsetup classを照合する。
 * Windowsのprinter driver INFとPnP inventoryのclass差だけを一方向に許可する。PnP IDの完全一致は別途必須とする。
 * @param[in] infClass 検証済みINFのsetup class。
 * @param[in] deviceClass 現在deviceのsetup class。
 * @return 完全一致または`Printer`から`PrintQueue`への対応なら`true`。 完全一致またはPrinterからPrintQueueへの対応なら`true`。
 */
[[nodiscard]] bool		  isGenericInfDeviceClassMatch( std::wstring_view infClass,
													   std::wstring_view deviceClass) noexcept ;

/**
 * @brief 利用者指定の汎用driver-only ZIPを保護領域で検証する。
 * 利用者指定の汎用driver-only ZIPを検証する。
 * 入手元や最新版を推測せず、ADR 0075／0078／0079／0082／0083の汎用境界を共通検証器へ委譲し、複合payloadを全entryから拒否する。
 * @param[in] selectedPath 利用者が一件だけ選択したlocal ZIP path。 利用者が選択したlocal ZIP path。
 * @param[in] scanSessionId 呼出し側が割り当てた0ではないscan session ID。
 * @param[in,out] workspace 複製と展開fileを単独所有する保護領域。 複製と展開fileを所有する保護領域。
 * @param[out] contents 成功時の全検証済みINF群。失敗時は完了段階だけを保持する。
 * @return 全検証成功時は0、構造、class、署名、CAT member違反時はHRESULT。 全検証成功時は0、最初の構造・署名違反はHRESULT。
 * @note Packageの入手元、最新版、OEM推奨を証明せず、network通信も行わない。
 * @note INFからの参照有無を問わず、内側container、virtual image、firmwareを拒否する。
 */
[[nodiscard]] NativeError inspectGenericInfPackageFile( std::wstring_view		  selectedPath,
													   ScanSessionId			  scanSessionId,
													   OfficialDownloadWorkspace &workspace,
													   GenericInfPackageContents &contents) ;

/**
 * @brief 汎用INFをinstall直前にscan時の内容へ再照合する。
 * 汎用INFをinstall直前に再検証する。
 * 管理者権限を持つ競合processによるscan後差替えと、内側container／virtual image／firmwareを含むscan entryをinstall前に拒否する。
 * @param[in] workspace Scan時の複製ZIPと展開fileを所有する保護領域。 Scan時の展開fileを所有する保護領域。
 * @param[in] entries Scan時にsizeとSHA-256を確定した全通常file。 Scan時にhashを確定した全通常file。
 * @param[in] expected Candidateへ対応付けたscan時のINF metadata。 Scan時の検証済みINF metadata。
 * @return 全file、metadata、CAT member、署名が一致する場合は0。 Scan時の全fileとINF metadataが再成立する場合は0。
 * @note Scan時entryに内側container、virtual image、firmwareがある場合はfail-closedで拒否する。
 */
[[nodiscard]] NativeError reverifyGenericInfPackage( const OfficialDownloadWorkspace	 &workspace,
													std::span<const OfficialZipEntry> entries,
													const OfficialInfPackage		 &expected) ;

/**
 * @brief 汎用package検証済みPnP IDをlocal matcherへ渡せるか判定する。
 * 汎用packageのPnP IDをlocal matcherへ渡せるか判定する。
 * Vendor prefixを推測せず、後段で現在deviceへ完全一致させる。
 * @param[in] hardwareId CATで保護されたINFから取得したPnP ID。 CATで保護されたINF由来PnP ID。
 * @return 空でないIDの場合は`true`。 空でない場合は`true`。
 * @note IDはworker内の完全一致だけに使用し、UI、log、networkへ渡さない。
 */
[[nodiscard]] bool		  isGenericInfCandidateHardwareId( std::wstring_view hardwareId) noexcept ;

/**
 * @brief 明示local ZIP／CABを共通個別INF検査へ渡す。
 * @param[in] selectedPath 利用者が選択した一file。
 * @param[in] scanSessionId 0ではないscan session。
 * @param[in,out] workspace Copyを所有する未初期化の保護領域。
 * @param[out] contents 個別成功と拒否を所有する共通結果。全体失敗では空。
 * @return 全体検査完了時0、取込み・上限・全体検査失敗時はHRESULT。
 * @note 公式由来の証明、実行、導入許可は発行しない。
 */
[[nodiscard]] NativeError inspectCommonLocalInfPackageFile(
	std::wstring_view selectedPath, ScanSessionId scanSessionId,
	OfficialDownloadWorkspace &workspace, UserSelectedInfPackageContents &contents) ;

} // namespace drivercrate
