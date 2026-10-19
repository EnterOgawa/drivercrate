//------------------------------------------------------------------------------
/**
 * @file provider_registry.h
 * @brief 組み込みProvider registry定義。
 * @version 01.02.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel Ethernet ID責務を更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Install注意種別の参照契約を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Focusrite表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Wacom Windows表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Ricoh PCL6表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  NVIDIA WinOF-2表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  ASIX AX88179A表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Intel Ethernet Server検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  共通配布情報とIntel公式検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  NetXtreme-E表示専用検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公式2経路とfamily別予算を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  CP210x公式取得とserial共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  公式serial取得と新版受入境界を更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Coverage整合性検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Lenovo公式PC Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  HP公式PC Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  VAIO公式PC Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Dell PowerEdge Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  利用者選択INF ZIP Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  WCH CH342／CH343系Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Prolific serial区分C Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  WCH serial区分C Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Silicon Labs区分C Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  汎用署名済みINF Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式取得元policy ID追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  監査拒否状態の保持追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  AMD表示専用Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Provider scan結果整合性検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASUS段階Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASRock表示専用Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Intel Ethernet Windows 11検索IDを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  署名索引の共通取得境界と既存経路の区別を追加。
 * </pre>
 *
 * @note 組み込み取得元のstable ID、表示名、capability、既定状態を一元管理します。Driver metadataや端末識別情報は保持しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <optional>
#include <span>
#include <string_view>

namespace drivercrate {

//------------------------------------------------------------------------------
// Provider ID定義。
//------------------------------------------------------------------------------

inline constexpr std::wstring_view WINDOWS_UPDATE_PROVIDER_ID = L"windows-update" ;
// 認証索引の全メーカーに共通な検査用取得ledgerのstable ID。
inline constexpr std::wstring_view SIGNED_INDEX_PROVIDER_ID = L"signed-index-acquisition" ;
// 端末内のDriver Store列挙・指定版導入を識別するstable ID。
inline constexpr std::wstring_view DRIVER_STORE_PROVIDER_ID = L"driver-store" ;
// NVIDIA公式GPU候補のscan／install routingに使用するstable ID。
inline constexpr std::wstring_view NVIDIA_PROVIDER_ID = L"nvidia-official" ;
// Dell client向け公式catalog Providerのstable ID。
inline constexpr std::wstring_view DELL_PROVIDER_ID = L"dell-official" ;
// Dell PowerEdge向け公式catalog Providerをclient系列と区別するstable ID。
inline constexpr std::wstring_view DELL_POWER_EDGE_PROVIDER_ID = L"dell-poweredge-official" ;
// Lenovo公式catalog Providerの設定・routingに使用するstable ID。
inline constexpr std::wstring_view LENOVO_PROVIDER_ID = L"lenovo-official" ;
// HP公式catalog Providerの設定・routingに使用するstable ID。
inline constexpr std::wstring_view HP_PROVIDER_ID = L"hp-official" ;
// VAIO公式catalog Providerの設定・routingに使用するstable ID。
inline constexpr std::wstring_view VAIO_PROVIDER_ID = L"vaio-official" ;
// 利用者指定Intel無線packageの静的検証経路を識別するstable ID。
inline constexpr std::wstring_view INTEL_WIRELESS_PACKAGE_PROVIDER_ID = L"intel-wireless-package" ;
// 利用者指定Prolific serial packageの検証経路を識別するstable ID。
inline constexpr std::wstring_view PROLIFIC_SERIAL_PACKAGE_PROVIDER_ID = L"prolific-serial-package" ;
inline constexpr std::wstring_view PROLIFIC_OFFICIAL_PROVIDER_ID =
	L"prolific-official" ;	// 明示同意により公式DCHU ZIPを取得するProvider。
inline constexpr std::wstring_view SILICON_LABS_OFFICIAL_PROVIDER_ID =
	L"silicon-labs-official" ;	// 明示同意により公式CP210x ZIPを取得するProvider。
inline constexpr std::wstring_view WCH_OFFICIAL_PROVIDER_ID =
	L"wch-official" ;	// 明示同意により公式CH341SER ZIPを取得するProvider。
inline constexpr std::wstring_view WCH_MULTI_OFFICIAL_PROVIDER_ID =
	L"wch-multi-official" ;	// 明示同意により公式CH343SER ZIPを取得するProvider。
inline constexpr std::wstring_view BROADCOM_NET_XTREME_PROVIDER_ID =
	L"broadcom-netxtreme-e" ;	// NetXtreme-Eの公式配布情報だけを検索するProvider。
inline constexpr std::wstring_view INTEL_WIFI_OFFICIAL_PROVIDER_ID =
	L"intel-wifi-official" ;	// Intel Wi-Fiの公式配布情報だけを検索するProvider。
inline constexpr std::wstring_view INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID =
	L"intel-ethernet-server-2025-official" ;	// Server 2025向けIntel Ethernet公式Provider。
inline constexpr std::wstring_view INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID =
	L"intel-ethernet-windows11-official" ;	// Windows 11向けIntel Ethernet表示検索Provider。
inline constexpr std::wstring_view ASIX_AX88179A_PROVIDER_ID =
	L"asix-ax88179a-official" ;	// Windows client x64向けASIX表示検索Provider。
inline constexpr std::wstring_view RICOH_UNIVERSAL_PRINT_PROVIDER_ID =
	L"ricoh-universal-print-official" ;	// Windows x64向けRicoh PCL6表示検索Provider。
inline constexpr std::wstring_view WACOM_WINDOWS_PROVIDER_ID =
	L"wacom-windows-official" ;	// Windows x64対応Wacom統合driver表示検索Provider。
inline constexpr std::wstring_view FOCUSRITE_SCARLETT2I2_PROVIDER_ID =
	L"focusrite-scarlett-2i2-official" ;	// Scarlett 2i2 2nd Gen表示検索Provider。
inline constexpr std::wstring_view NVIDIA_WINOF2_PROVIDER_ID =
	L"nvidia-winof2-official" ;	// NVIDIA Networking WinOF-2表示検索Provider。
// 利用者指定Silicon Labs serial packageの検証経路を識別するstable ID。
inline constexpr std::wstring_view SILICON_LABS_SERIAL_PACKAGE_PROVIDER_ID =
	L"silicon-labs-serial-package" ;
// 利用者指定WCH CH341 packageの検証経路を識別するstable ID。
inline constexpr std::wstring_view WCH_SERIAL_PACKAGE_PROVIDER_ID = L"wch-serial-package" ;
// 利用者指定WCH multi-serial packageの検証経路を識別するstable ID。
inline constexpr std::wstring_view WCH_MULTI_SERIAL_PACKAGE_PROVIDER_ID =
	L"wch-multi-serial-package" ;
// 利用者指定の署名付き汎用INF package検証経路を識別するstable ID。
inline constexpr std::wstring_view GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID =
	L"generic-signed-inf-package" ;
inline constexpr std::wstring_view AMD_PROVIDER_ID = L"amd-official" ;	// AMD表示専用Provider ID。
inline constexpr std::wstring_view ASUS_PROVIDER_ID =
	L"asus-official" ;	// ASUS公式support page Provider ID。
inline constexpr std::wstring_view ASROCK_PROVIDER_ID =
	L"asrock-official" ;	// ASRock公式最新driver一覧Provider ID。

/**
 * @brief 単一registryから通常scanへ接続済みのSCAN能力viewを登録順で返す。
 * @return Process lifetime中有効なSCAN群。取得専用entryは含めません。
 */
[[nodiscard]] std::span<const ProviderDescriptor> builtInProviderDescriptors() noexcept ;

/** @brief 通常scanと取得専用を含む単一canonical registry全体からIDを解決します。
 * @param[in] providerId 完全一致のstable ID。
 * @return 整合したregistryの一意なentry。不明または不整合はnullptr。
 */
[[nodiscard]] const ProviderDescriptor			 *findProviderDescriptor(
			  std::wstring_view providerId) noexcept ;

/** @brief 同じregistry正本から共通索引の取得専用entryだけを返します。
 * @return 全registry整合時だけ不変entryのprocess lifetime参照。不整合時nullptr。
 * @note 通常scan／metadata検索の実接続済みviewへ追加せず、取得能力は封印grantで別検証します。
 */
[[nodiscard]] const ProviderDescriptor		  *signedIndexAcquisitionProviderDescriptor() noexcept ;

/**
 * @brief Stable Provider IDに対応するinstall注意種別を取得する。
 * Stable Provider IDからinstall注意種別を取得する。
 * 未知IDまたは不正registryをNoneへ縮退せず、呼出側がinstallをfail-closedで中止できる値を返す。
 * @param[in] providerId 完全一致で検索する組み込みProvider ID。
 * @return Registryが整合しIDが一意な場合は注意種別、それ以外は値なし。 Registryが整合しIDが一意なら注意種別、それ以外は値なし。
 * @note 値なしを`InstallNoticeKind::None`へ読み替えず、installをfail-closedで中止する。
 */
[[nodiscard]] std::optional<InstallNoticeKind> providerInstallNotice(
	std::wstring_view providerId) noexcept ;

/**
 * @brief Scan設定が既知Provider IDだけを重複なく指定しているか検証する。
 * Scan設定のProvider ID集合を検証する。
 * 未知または重複ID、入力fileとの矛盾、公式origin policyの不整合をProvider呼出し前に拒否する。
 * @param[in] options UIまたは呼出し側が指定したscan設定。
 * @return 既定設定または検証済み明示設定の場合は`true`。 既定設定または既知IDだけの明示設定なら`true`。
 */
[[nodiscard]] bool				validateScanOptions( const ScanOptions &options) noexcept ;

/**
 * @brief 指定Providerを今回のscanで有効にするか判定する。
 * Providerのscan有効状態を解決する。
 * 未知IDを推測せず、registryのstable IDだけを比較する。
 * @param[in] options 検証対象のscan設定。 Scan設定。
 * @param[in] descriptor 判定する登録済みProvider。
 * @return 既定値または明示選択で有効な場合は`true`。 既定値または明示選択で有効なら`true`。
 * @note 未検証設定でも未知IDを有効と判断しない。
 */
[[nodiscard]] bool				isProviderEnabled( const ScanOptions		   &options,
												  const ProviderDescriptor &descriptor) noexcept ;

/**
 * @brief UserSelectedFile Providerへ明示された一つのlocal file pathを取得する。
 * UserSelectedFile Providerのlocal file pathを取得する。
 * Pathを複製せずworker commandの有効期間だけ参照し、不正設定を推測で補完しない。
 * @param[in] options 検証済みの明示scan設定。
 * @param[in] providerId UserSelectedFile capability付きの既知Provider ID。 UserSelectedFile capability付き
 *                   Provider。
 * @return 一意な入力path。未指定、重複、不正Providerの場合は空view。 一意な入力path。設定不正または未指定の場合は空view。
 */
[[nodiscard]] std::wstring_view userSelectedFileForProvider( const ScanOptions &options,
															std::wstring_view  providerId) noexcept ;

/**
 * @brief 現在版を除く一つのProviderの表示候補件数を数える。
 * 現在版を除くProviderの表示候補件数を数える。
 * Local inventoryの現在版をupdate候補件数へ含めない。
 * @param[in] result 単一Providerのscan結果。
 * @return 更新、再導入、旧版候補の合計件数。
 */
[[nodiscard]] std::uint64_t		countDisplayCandidates( const ScanResult &result) noexcept ;

/**
 * @brief 単一Providerのscan結果をUI用到達状態へ正規化する。
 * 単一Provider結果をUI用scan状態へ正規化する。
 * Providerが明示した対象外と監査段階別の拒否を維持する。
 * @param[in] result 単一Providerのscan結果。
 * @param[in] enabled scan条件で有効だった場合は`true`。 Scan条件で有効だった場合true。
 * @return 無効、対象外、候補有無、失敗または監査段階別拒否の分類。 無効、対象外、候補なし、候補あり、失敗、拒否の分類。
 */
[[nodiscard]] ProviderScanState resolveProviderScanState( const ScanResult &result,
														 bool			   enabled) noexcept ;

/**
 * @brief Providerの成功flag、outcome、到達状態が矛盾しないか確認する。
 * Providerのscan結果field間の整合性を検証する。
 * 成功flag、outcome、到達状態を独立に信用せず、相互に矛盾する結果をaggregateへ渡さない。
 * @param[in] result 単一Providerが返したscan結果。
 * @param[in] enabled scan条件で有効だった場合は`true`。 Scan条件で有効だった場合は`true`。
 * @return 無効Providerまたは整合する実行結果の場合は`true`。
 */
[[nodiscard]] bool isProviderScanResultConsistent( const ScanResult &result, bool enabled) noexcept ;

/**
 * @brief Provider coverageの件数関係が矛盾していないか確認する。
 * Provider coverageの件数関係を検証する。
 * Providerまたはaggregateの計数誤りをUIへ渡す前に検出する。
 * @param[in] coverage 端末内で集計した対象／判定device数。
 * @return 判定数が対象数以下の場合は`true`。
 */
[[nodiscard]] bool isValidProviderCoverage( const ProviderCoverage &coverage) noexcept ;

/**
 * @brief ProviderCapabilityをmaskへ変換する。
 * @param[in] capability 変換対象の単一capability。
 * @return capabilityを表すbit mask。
 */
[[nodiscard]] constexpr ProviderCapabilityMask capabilityMask(
	const ProviderCapability capability) noexcept
{
	return static_cast<ProviderCapabilityMask>( capability) ;
}

} // namespace drivercrate
