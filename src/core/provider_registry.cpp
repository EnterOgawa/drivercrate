//------------------------------------------------------------------------------
/**
 * @file provider_registry.cpp
 * @brief 組み込みProvider registry実装。
 * @version 01.06.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX候補発行と指定導入の共通接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  ASIXの検査用Download能力を登録。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel Ethernet導入能力を公開。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel Server向けinstall注意種別を登録。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernetの取得前提確認と選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Focusrite表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Wacom Windows表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Ricoh PCL6表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  NVIDIA Displayを表示専用へ訂正。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  NVIDIA WinOF-2表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  ASIX AX88179A表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Intel Ethernet Server検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Broadcomの導入能力を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Broadcomの選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  共通配布情報とIntel公式検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  NetXtreme-E表示専用検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公式2経路とfamily別予算を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  CP210x公式取得とserial共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  公式serial取得と新版受入境界を更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  既定取得元優先段階追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Coverage整合性検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Lenovo公式PC Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  HP公式PC Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  VAIO公式PC Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Dell PowerEdge Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Provider探索経路区分追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  利用者選択INF ZIP Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Prolific serial区分C Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  WCH serial区分C Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  WCH CH342／CH343系Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Silicon Labs区分C Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  汎用署名済みINF Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式取得元policy接続追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  監査拒否状態の保持追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  AMD表示専用Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Scan成功／拒否状態の矛盾拒否追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Provider outcome整合性検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASUS段階Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASUS install capability追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASRock表示専用Provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Intel Ethernet Windows 11検索Providerを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  Intel Windows 11固定root自動探索能力を接続。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  一scan承認と旧個別同意の排他検証を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/15  Payload未許可の正常metadata終端を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/12  署名索引の共通取得境界と既存経路の区別を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * </pre>
 *
 * @note Provider識別子と能力を一元登録し、検査用Download能力をInstall能力と区別します。
 */
//------------------------------------------------------------------------------

#include "core/provider_registry.h"

#include "core/official_source_policy.h"

#include <algorithm>
#include <array>
#include <cstddef>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// Registry定数定義。
//------------------------------------------------------------------------------

constexpr ProviderCapabilityMask SCAN_INSTALL_CAPABILITIES =
	capabilityMask( ProviderCapability::SCAN) | capabilityMask( ProviderCapability::DOWNLOAD) |
	capabilityMask( ProviderCapability::INSTALL) ;

// 組み込みProviderのstable ID・capability・既定値を一箇所で定義する正本。
const std::array<ProviderDescriptor, 31> BUILT_IN_PROVIDERS{
	ProviderDescriptor{.id			 = std::wstring( WINDOWS_UPDATE_PROVIDER_ID),
					   .displayName	 = L"Windows Update / WSUS",
					   .capabilities = SCAN_INSTALL_CAPABILITIES |
									   capabilityMask( ProviderCapability::MANAGED_SERVICE),
					   .selectionTier	 = ProviderSelectionTier::MANAGED_SERVICE,
					   .discoveryBasis	 = CandidateDiscoveryBasis::MANAGED_SERVICE,
					   .enabledByDefault = true},
	ProviderDescriptor{.id			 = std::wstring( DRIVER_STORE_PROVIDER_ID),
					   .displayName	 = L"Windows Driver Store",
					   .capabilities = capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::INSTALL) |
									   capabilityMask( ProviderCapability::HISTORY) |
									   capabilityMask( ProviderCapability::LOCAL_INVENTORY),
					   .selectionTier	 = ProviderSelectionTier::LOCAL_INVENTORY,
					   .discoveryBasis	 = CandidateDiscoveryBasis::LOCAL_INVENTORY,
					   .enabledByDefault = true},
	ProviderDescriptor{.id			 = std::wstring( NVIDIA_PROVIDER_ID),
					   .displayName	 = L"NVIDIA 公式カタログ",
					   .capabilities = capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::HISTORY) |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier	 = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis	 = CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG,
					   .enabledByDefault = true,
					   .officialSourcePolicyId = std::wstring( NVIDIA_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( DELL_PROVIDER_ID),
					   .displayName	 = L"Dell 公式PCカタログ",
					   .capabilities = SCAN_INSTALL_CAPABILITIES |
									   capabilityMask( ProviderCapability::HISTORY) |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier	 = ProviderSelectionTier::OEM_OFFICIAL,
					   .discoveryBasis	 = CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG,
					   .enabledByDefault = true,
					   .officialSourcePolicyId = std::wstring( DELL_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{
		.id			  = std::wstring( DELL_POWER_EDGE_PROVIDER_ID),
		.displayName  = L"Dell PowerEdge 公式Enterpriseカタログ",
		.capabilities = SCAN_INSTALL_CAPABILITIES | capabilityMask( ProviderCapability::HISTORY) |
						capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
		.selectionTier			= ProviderSelectionTier::OEM_OFFICIAL,
		.discoveryBasis			= CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG,
		.enabledByDefault		= true,
		.officialSourcePolicyId = std::wstring( DELL_POWER_EDGE_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( LENOVO_PROVIDER_ID),
					   .displayName	 = L"Lenovo 公式PCカタログ",
					   .capabilities = SCAN_INSTALL_CAPABILITIES |
									   capabilityMask( ProviderCapability::HISTORY) |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier	 = ProviderSelectionTier::OEM_OFFICIAL,
					   .discoveryBasis	 = CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG,
					   .enabledByDefault = true,
					   .officialSourcePolicyId = std::wstring( LENOVO_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( HP_PROVIDER_ID),
					   .displayName	 = L"HP 公式PCカタログ",
					   .capabilities = SCAN_INSTALL_CAPABILITIES |
									   capabilityMask( ProviderCapability::HISTORY) |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier	 = ProviderSelectionTier::OEM_OFFICIAL,
					   .discoveryBasis	 = CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG,
					   .enabledByDefault = true,
					   .officialSourcePolicyId = std::wstring( HP_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( VAIO_PROVIDER_ID),
					   .displayName	 = L"VAIO Global 公式PCカタログ",
					   .capabilities = SCAN_INSTALL_CAPABILITIES |
									   capabilityMask( ProviderCapability::HISTORY) |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier	 = ProviderSelectionTier::OEM_OFFICIAL,
					   .discoveryBasis	 = CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG,
					   .enabledByDefault = true,
					   .officialSourcePolicyId = std::wstring( VAIO_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( INTEL_WIRELESS_PACKAGE_PROVIDER_ID),
					   .displayName	 = L"Intel Wireless ZIP（利用者選択）",
					   .capabilities = capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::INSTALL) |
									   capabilityMask( ProviderCapability::HISTORY) |
									   capabilityMask( ProviderCapability::USER_SELECTED_FILE),
					   .selectionTier	 = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis	 = CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE,
					   .enabledByDefault = false},
	ProviderDescriptor{.id			 = std::wstring( PROLIFIC_SERIAL_PACKAGE_PROVIDER_ID),
					   .displayName	 = L"Prolific Serial ZIP（利用者選択）",
					   .capabilities = capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::INSTALL) |
									   capabilityMask( ProviderCapability::HISTORY) |
									   capabilityMask( ProviderCapability::USER_SELECTED_FILE),
					   .selectionTier	 = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis	 = CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE,
					   .enabledByDefault = false},
	ProviderDescriptor{.id			 = std::wstring( SILICON_LABS_SERIAL_PACKAGE_PROVIDER_ID),
					   .displayName	 = L"Silicon Labs CP210x ZIP（利用者選択）",
					   .capabilities = capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::INSTALL) |
									   capabilityMask( ProviderCapability::HISTORY) |
									   capabilityMask( ProviderCapability::USER_SELECTED_FILE),
					   .selectionTier	 = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis	 = CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE,
					   .enabledByDefault = false},
	ProviderDescriptor{.id			 = std::wstring( WCH_SERIAL_PACKAGE_PROVIDER_ID),
					   .displayName	 = L"WCH CH340/CH341 ZIP（利用者選択）",
					   .capabilities = capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::INSTALL) |
									   capabilityMask( ProviderCapability::HISTORY) |
									   capabilityMask( ProviderCapability::USER_SELECTED_FILE),
					   .selectionTier	 = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis	 = CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE,
					   .enabledByDefault = false},
	ProviderDescriptor{.id			 = std::wstring( WCH_MULTI_SERIAL_PACKAGE_PROVIDER_ID),
					   .displayName	 = L"WCH CH342/CH343系 ZIP（利用者選択）",
					   .capabilities = capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::INSTALL) |
									   capabilityMask( ProviderCapability::HISTORY) |
									   capabilityMask( ProviderCapability::USER_SELECTED_FILE),
					   .selectionTier	 = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis	 = CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE,
					   .enabledByDefault = false},
	ProviderDescriptor{.id			 = std::wstring( GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID),
					   .displayName	 = L"署名済みINF ZIP（利用者選択・取得元未証明）",
					   .capabilities = capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::INSTALL) |
									   capabilityMask( ProviderCapability::HISTORY) |
									   capabilityMask( ProviderCapability::USER_SELECTED_FILE),
					   .selectionTier	 = ProviderSelectionTier::USER_PROVIDED,
					   .discoveryBasis	 = CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE,
					   .enabledByDefault = false},
	ProviderDescriptor{.id			 = std::wstring( AMD_PROVIDER_ID),
					   .displayName	 = L"AMD 公式support page（表示専用）",
					   .capabilities = capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier		   = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis		   = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
					   .enabledByDefault	   = true,
					   .officialSourcePolicyId = std::wstring( AMD_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( ASUS_PROVIDER_ID),
					   .displayName	 = L"ASUS 公式support page",
					   .capabilities = capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::DOWNLOAD) |
									   capabilityMask( ProviderCapability::INSTALL) |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier		   = ProviderSelectionTier::OEM_OFFICIAL,
					   .discoveryBasis		   = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
					   .enabledByDefault	   = false,
					   .officialSourcePolicyId = std::wstring( ASUS_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( ASROCK_PROVIDER_ID),
					   .displayName	 = L"ASRock 公式最新driver一覧（表示専用）",
					   .capabilities = capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier		   = ProviderSelectionTier::OEM_OFFICIAL,
					   .discoveryBasis		   = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
					   .enabledByDefault	   = false,
					   .officialSourcePolicyId = std::wstring( ASROCK_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( PROLIFIC_OFFICIAL_PROVIDER_ID),
					   .displayName	 = L"Prolific 公式DCHU INF ZIP（検索時に検査用取得を確認）",
					   .capabilities = capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) |
									   capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::DOWNLOAD) |
									   capabilityMask( ProviderCapability::INSTALL) |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier		   = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis		   = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
					   .enabledByDefault	   = false,
					   .officialSourcePolicyId = std::wstring( PROLIFIC_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( SILICON_LABS_OFFICIAL_PROVIDER_ID),
					   .displayName	 = L"Silicon Labs 公式CP210x ZIP（検索時に検査用取得を確認）",
					   .capabilities = capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) |
									   SCAN_INSTALL_CAPABILITIES |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier	 = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis	 = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
					   .enabledByDefault = false,
					   .officialSourcePolicyId =
						   std::wstring( SILICON_LABS_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( WCH_OFFICIAL_PROVIDER_ID),
					   .displayName	 = L"WCH 公式CH340／CH341 ZIP（検索時に検査用取得を確認）",
					   .capabilities = capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) |
									   SCAN_INSTALL_CAPABILITIES |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier		   = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis		   = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
					   .enabledByDefault	   = false,
					   .officialSourcePolicyId = std::wstring( WCH_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( WCH_MULTI_OFFICIAL_PROVIDER_ID),
					   .displayName	 = L"WCH 公式CH342／CH343系 ZIP（検索時に検査用取得を確認）",
					   .capabilities = capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) |
									   SCAN_INSTALL_CAPABILITIES |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier		   = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis		   = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
					   .enabledByDefault	   = false,
					   .officialSourcePolicyId = std::wstring( WCH_MULTI_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( BROADCOM_NET_XTREME_PROVIDER_ID),
					   .displayName	 = L"Broadcom NetXtreme-E",
					   .capabilities = capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::DOWNLOAD) |
									   capabilityMask( ProviderCapability::INSTALL) |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier		   = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis		   = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
					   .enabledByDefault	   = false,
					   .officialSourcePolicyId = std::wstring( BROADCOM_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( INTEL_WIFI_OFFICIAL_PROVIDER_ID),
					   .displayName	 = L"Intel Wi-Fi",
					   .capabilities = capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) |
									   capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier	 = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis	 = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
					   .enabledByDefault = false,
					   .officialSourcePolicyId =
						   std::wstring( INTEL_WIFI_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID),
					   .displayName	 = L"Intel Ethernet（Windows Server 2025）",
					   .capabilities = capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) |
									   capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::DOWNLOAD) |
									   capabilityMask( ProviderCapability::INSTALL) |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier	 = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis	 = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
					   .installNotice	 = InstallNoticeKind::INTEL_ETHERNET_SERVER,
					   .enabledByDefault = false,
					   .officialSourcePolicyId =
						   std::wstring( INTEL_ETHERNET_SERVER2025_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID),
					   .displayName	 = L"Intel Ethernet（Windows 11・表示専用）",
					   .capabilities = capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) |
									   capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK) |
									   capabilityMask( ProviderCapability::AUTOMATIC_DISCOVERY),
					   .selectionTier	 = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis	 = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
					   .enabledByDefault = false,
					   .officialSourcePolicyId =
						   std::wstring( INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( ASIX_AX88179A_PROVIDER_ID),
					   .displayName	 = L"ASIX AX88179A（Windows x64・監査後の選択導入）",
					   .capabilities = capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::DOWNLOAD) |
									   capabilityMask( ProviderCapability::INSTALL) |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier		   = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis		   = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
					   .installNotice		   = InstallNoticeKind::ASIX_CLIENT_NIC,
					   .enabledByDefault	   = false,
					   .officialSourcePolicyId = std::wstring( ASIX_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( RICOH_UNIVERSAL_PRINT_PROVIDER_ID),
					   .displayName	 = L"Ricoh PCL6 Universal Print（Windows x64・表示専用）",
					   .capabilities = capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) |
									   capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier	 = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis	 = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
					   .enabledByDefault = false,
					   .officialSourcePolicyId =
						   std::wstring( RICOH_UNIVERSAL_PRINT_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( WACOM_WINDOWS_PROVIDER_ID),
					   .displayName	 = L"Wacom Windows Tablet Driver（x64・表示専用）",
					   .capabilities = capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) |
									   capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier	 = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis	 = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
					   .enabledByDefault = false,
					   .officialSourcePolicyId =
						   std::wstring( WACOM_WINDOWS_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( FOCUSRITE_SCARLETT2I2_PROVIDER_ID),
					   .displayName	 = L"Focusrite Scarlett 2i2 2nd Gen（x64・表示専用）",
					   .capabilities = capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) |
									   capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier	 = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis	 = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
					   .enabledByDefault = false,
					   .officialSourcePolicyId =
						   std::wstring( FOCUSRITE_SCARLETT2I2_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( NVIDIA_WINOF2_PROVIDER_ID),
					   .displayName	 = L"NVIDIA Networking WinOF-2（x64・表示専用）",
					   .capabilities = capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
					   .selectionTier	 = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis	 = CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG,
					   .enabledByDefault = false,
					   .officialSourcePolicyId =
						   std::wstring( NVIDIA_WINOF2_OFFICIAL_SOURCE_POLICY_ID)},
	ProviderDescriptor{.id			 = std::wstring( SIGNED_INDEX_PROVIDER_ID),
					   .displayName	 = L"署名索引（収集者確認・端末内検証）",
					   .capabilities = capabilityMask( ProviderCapability::SCAN) |
									   capabilityMask( ProviderCapability::DOWNLOAD) |
									   capabilityMask( ProviderCapability::INSTALL) |
									   capabilityMask( ProviderCapability::SIGNED_INDEX_ACQUISITION),
					   .selectionTier = ProviderSelectionTier::COMPONENT_OFFICIAL,
					   .discoveryBasis =
						   CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION,
					   .enabledByDefault = true}} ;

//------------------------------------------------------------------------------
/**
 * @brief 組み込みProvider定義とinstall注意種別を検証する。
 *
 * 空ID、重複ID、未定義値、Intel以外へのNIC注意文登録を拒否し、不正なregistryから候補確認を継続させない。
 * @return 全定義が一意かつ既知の組合せの場合は`true`。
 */
//------------------------------------------------------------------------------
bool validateBuiltInProviderDescriptors() noexcept
{
	std::size_t intelNoticeCount{} ;	// Intel Ethernet Server注意種別の登録件数。
	bool		acquisitionGroup{} ;	// SCAN群の後に取得専用群が始まった状態。

	// 固定件数のregistryを順番に検証し、IDと注意種別の一意な対応を保証する。
	for( std::size_t index = 0; index < BUILT_IN_PROVIDERS.size(); ++index) {
		const ProviderDescriptor &descriptor = BUILT_IN_PROVIDERS[index] ;	// 現在の登録定義。
		const bool				  hasScan	 =								// 全組み込みProviderに必要なscan capability。
			(descriptor.capabilities & capabilityMask( ProviderCapability::SCAN)) != 0U ;
		// 取得専用群へ移った後にSCAN定義が戻る不連続registryを拒否します。
		if( hasScan && acquisitionGroup) {
			return false ;
		}

		// 非SCAN entryは共通索引の実装済み取得能力だけを持ち、通常scanや導入を宣言しません。
		if( !hasScan) {
			acquisitionGroup = true ;
			// 不接続のscanや導入能力を取得専用entryへ混入させません。
			if( descriptor.id != SIGNED_INDEX_PROVIDER_ID || descriptor.enabledByDefault ||
			   !descriptor.officialSourcePolicyId.empty() ||
			   descriptor.capabilities !=
				   (capabilityMask( ProviderCapability::DOWNLOAD) |
					capabilityMask( ProviderCapability::SIGNED_INDEX_ACQUISITION))) {
				return false ;
			}
		}

		const bool duplicate =	// 現在位置より前に同じstable IDがある場合はtrue。
			std::find_if( BUILT_IN_PROVIDERS.begin(),
						 BUILT_IN_PROVIDERS.begin() + static_cast<std::ptrdiff_t>( index),
						 [&descriptor]( const ProviderDescriptor &registered) {
							 return registered.id == descriptor.id ;
						 }) != BUILT_IN_PROVIDERS.begin() + static_cast<std::ptrdiff_t>( index) ;
		// 表示と検索に必要な定義が欠ける、またはIDが重複するProvider構成を拒否する。
		if( descriptor.id.empty() || descriptor.displayName.empty() ||
		   (!hasScan && descriptor.id != SIGNED_INDEX_PROVIDER_ID) || duplicate ||
		   descriptor.discoveryBasis == CandidateDiscoveryBasis::UNSPECIFIED) {
			return false ;
		}

		// Provider固有の最終注意文を登録元へ照合し、欠落や別Providerへの誤表示を防ぐ。
		switch( descriptor.installNotice) {
			case InstallNoticeKind::NONE:
				// Intel候補から必須のServer NIC注意文が欠落する構成を拒否する。
				if( descriptor.id == INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ||
				   descriptor.id == ASIX_AX88179A_PROVIDER_ID) {
					return false ;
				}

				break ;

			case InstallNoticeKind::INTEL_ETHERNET_SERVER:
				// 別ProviderへIntel固有の運用条件を誤表示しない。
				if( descriptor.id != INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID) {
					return false ;
				}

				++intelNoticeCount ;
				break ;

			case InstallNoticeKind::ASIX_CLIENT_NIC:
				// ASIX以外の取得元へclient NIC条件を付けない。
				if( descriptor.id != ASIX_AX88179A_PROVIDER_ID) {
					return false ;
				}

				break ;

			// 未知の notice を無警告として扱わず Provider 定義を拒否する。
			default:
				// 未定義の注意種別を警告なしとして扱わない。
				return false ;
		}
	}

	return intelNoticeCount == 1U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 移行中のProvider別検査同意が一つ以上指定されているか確認する。
 *
 * @param[in] options 検証するscan設定。
 * @return 四つの旧同意のいずれかがtrueの場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasLegacyInspectionApproval( const ScanOptions &options) noexcept
{
	return options.prolificInspectionApproved || options.siliconLabsInspectionApproved ||
		   options.wchInspectionApproved || options.wchMultiInspectionApproved ;
}

//------------------------------------------------------------------------------
/**
 * @brief 新しい一scan承認の有限値と固定予算を検証する。
 *
 * @param[in] approval UIが表示してworkerへ渡す承認snapshot。
 * @return Operation、enum、全予算が製品固定値と一致する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validateOfficialScanApproval(
	const OfficialDiscoveryScanApproval &approval) noexcept
{
	const OfficialDiscoveryMetadataLimits metadataLimits ;	// 製品固定metadata予算。
	const OfficialDiscoveryPayloadLimits  payloadLimits ;	// 製品固定payload予算。
	const bool							  knownPermission =	// 定義済みの検査許可ならtrue。
		approval.inspectionPermission == OfficialDiscoveryInspectionPermission::METADATA_ONLY ||
		approval.inspectionPermission ==
			OfficialDiscoveryInspectionPermission::ALLOW_VERIFIED_DRIVER_PACKAGE ;
	const bool knownCacheMode =	// 定義済みのcache選択ならtrue。
		approval.cacheMode == OfficialDiscoveryCacheMode::USE_FRESH ||
		approval.cacheMode == OfficialDiscoveryCacheMode::FORCE_REFRESH ;
	return approval.operationId != 0U && knownPermission && knownCacheMode &&
		   approval.metadataLimits == metadataLimits && approval.payloadLimits == payloadLimits ;
}

//------------------------------------------------------------------------------
/**
 * @brief 今回選択したProvider集合に公式network取得元があるか確認する。
 *
 * @param[in] options 既定または明示Provider集合。
 * @return 選択済みProviderにOFFICIAL_NETWORK capabilityが一件以上ある場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasSelectedOfficialNetworkProvider( const ScanOptions &options) noexcept
{
	// Registry正本だけを走査し、未知IDから公式通信権限を推測しない。
	for( const ProviderDescriptor &descriptor : BUILT_IN_PROVIDERS) {
		// 既定値または明示ID完全一致だけで今回の選択状態を確定する。
		const bool selected =
			options.useDefaultProviders
				? descriptor.enabledByDefault
				: std::find( options.enabledProviderIds.begin(), options.enabledProviderIds.end(),
							descriptor.id) != options.enabledProviderIds.end() ;
		// 選択済みの公式network境界を一件確認した時点で目的を満たす。
		if( selected &&
		   (descriptor.capabilities & capabilityMask( ProviderCapability::OFFICIAL_NETWORK)) != 0U) {
			return true ;
		}
	}

	return false ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/core/provider_registry.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::span<const ProviderDescriptor> builtInProviderDescriptors() noexcept
{
	// Registry矛盾時は部分的なProvider一覧を公開しない。
	if( !validateBuiltInProviderDescriptors()) {
		return {} ;
	}

	const auto end = std::find_if(
		BUILT_IN_PROVIDERS.begin(), BUILT_IN_PROVIDERS.end(), []( const ProviderDescriptor &entry) {
			return (entry.capabilities & capabilityMask( ProviderCapability::SCAN)) == 0U ;
		}) ; // 単一正本のSCAN能力群だけの終端。
	return {BUILT_IN_PROVIDERS.data(), static_cast<std::size_t>( end - BUILT_IN_PROVIDERS.begin())} ;
}

/** @see provider_registry.h 宣言側の契約を正本とする。 */
const ProviderDescriptor *findProviderDescriptor( const std::wstring_view providerId) noexcept
{
	// 部分的な登録や不正registryのIDを権限根拠として返しません。
	if( !validateBuiltInProviderDescriptors()) {
		return nullptr ;
	}

	const auto entry = std::find_if( BUILT_IN_PROVIDERS.begin(), BUILT_IN_PROVIDERS.end(),
									[providerId]( const ProviderDescriptor &value) {
										return value.id == providerId ;
									}) ; // Canonical全体の完全一致。
	return entry == BUILT_IN_PROVIDERS.end() ? nullptr : &*entry ;
}

/** @see provider_registry.h 宣言側の契約を正本とする。 */
const ProviderDescriptor *signedIndexAcquisitionProviderDescriptor() noexcept
{
	return findProviderDescriptor( SIGNED_INDEX_PROVIDER_ID) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/provider_registry.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::optional<InstallNoticeKind> providerInstallNotice( const std::wstring_view providerId) noexcept
{
	const auto *descriptor = findProviderDescriptor( providerId) ;	// Canonical全体の一意な登録定義。
	// 未知Providerへ既定の注意文を推測して返さず、照合不能を呼出し元へ示す。
	if( descriptor == nullptr) {
		return std::nullopt ;
	}

	return descriptor->installNotice ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/provider_registry.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool validateScanOptions( const ScanOptions &options) noexcept
{
	// 組み込み定義と通信policyの整合が崩れている場合は、どの検索設定も受理しない。
	if( !validateBuiltInProviderDescriptors() || !validateBuiltInOfficialSourcePolicies()) {
		return false ;
	}

	const bool legacyApproval = hasLegacyInspectionApproval( options) ;	// 移行中の個別同意有無。
	// 新旧同意を同時指定した要求は、広い方へ権限を合成せず全体を拒否する。
	if( options.officialDiscoveryApproval.has_value() && legacyApproval) {
		return false ;
	}

	// 新承認は固定予算を変更できず、公式networkを含む同じProvider集合だけに使用する。
	if( options.officialDiscoveryApproval.has_value() &&
	   (!validateOfficialScanApproval( *options.officialDiscoveryApproval) ||
		!hasSelectedOfficialNetworkProvider( options))) {
		return false ;
	}

	// 既定設定には個別指定や旧個別同意を混在させず、利用者の指定範囲を曖昧にしない。
	if( options.useDefaultProviders) {
		return options.enabledProviderIds.empty() && options.userSelectedFiles.empty() &&
			   !legacyApproval ;
	}

	const bool prolificEnabled =	// 一度限りの検査同意を関連付ける明示Provider選択。
		std::find( options.enabledProviderIds.begin(), options.enabledProviderIds.end(),
				  PROLIFIC_OFFICIAL_PROVIDER_ID) != options.enabledProviderIds.end() ;
	// 旧入力では無同意のpayload取得と、対象のない同意tokenを拒否する。
	if( !options.officialDiscoveryApproval.has_value() &&
	   options.prolificInspectionApproved != prolificEnabled) {
		return false ;
	}

	const bool siliconLabsEnabled =	// CP210x検査同意を対応するProviderだけへ拘束する。
		std::find( options.enabledProviderIds.begin(), options.enabledProviderIds.end(),
				  SILICON_LABS_OFFICIAL_PROVIDER_ID) != options.enabledProviderIds.end() ;
	// 別メーカーの同意や、対象外の同意tokenを受理しない。
	if( !options.officialDiscoveryApproval.has_value() &&
	   options.siliconLabsInspectionApproved != siliconLabsEnabled) {
		return false ;
	}

	const bool wchEnabled =	// CH341SERの取得同意を一つのProviderへ拘束する。
		std::find( options.enabledProviderIds.begin(), options.enabledProviderIds.end(),
				  WCH_OFFICIAL_PROVIDER_ID) != options.enabledProviderIds.end() ;
	const bool wchMultiEnabled =	// CH343SERの取得同意を別に確認する。
		std::find( options.enabledProviderIds.begin(), options.enabledProviderIds.end(),
				  WCH_MULTI_OFFICIAL_PROVIDER_ID) != options.enabledProviderIds.end() ;
	// 同じメーカーでも別familyの同意は流用しない。
	if( !options.officialDiscoveryApproval.has_value() &&
	   (options.wchInspectionApproved != wchEnabled ||
		options.wchMultiInspectionApproved != wchMultiEnabled)) {
		return false ;
	}

	// 有限な組み込みProvider数を線形確認し、検証中のallocation失敗を発生させない。
	for( std::size_t index = 0; index < options.enabledProviderIds.size(); ++index) {
		const std::wstring &id = options.enabledProviderIds[index] ;	// 現在検証するID。
		// 設定IDが組み込み定義に存在するかを示す。ID参照は同期検索中だけ借用する。
		const bool			known = std::any_of(
			 BUILT_IN_PROVIDERS.begin(), BUILT_IN_PROVIDERS.end(), [&id]( const auto &descriptor) {
				 return descriptor.id == id &&
						(descriptor.capabilities & capabilityMask( ProviderCapability::SCAN)) != 0U ;
			 }) ;
		const bool duplicate =
			std::find( options.enabledProviderIds.begin(),
					  options.enabledProviderIds.begin() + static_cast<std::ptrdiff_t>( index),
					  id) != options.enabledProviderIds.begin() +
								 // 先行IDとの重複状態。
								 static_cast<std::ptrdiff_t>( index) ;
		// 未知IDや重複指定のある明示Provider集合を拒否し、要求範囲を勝手に補完しない。
		if( !known || duplicate) {
			return false ;
		}
	}

	// Local pathを受け取れる有効Providerだけに、一件の非空fileを関連付ける。
	for( std::size_t index = 0; index < options.userSelectedFiles.size(); ++index) {
		const UserSelectedProviderFile &input = options.userSelectedFiles[index] ;	// 現在入力。
		// 利用者指定fileのProviderに対応する定義。入力参照は同期検索中だけ借用する。
		const auto						descriptor = std::find_if(
			 BUILT_IN_PROVIDERS.begin(), BUILT_IN_PROVIDERS.end(),
			 [&input]( const ProviderDescriptor &value) { return value.id == input.providerId ; }) ;
		// 既知Providerが利用者指定fileを扱うcapabilityを持つ場合だけtrue。
		const bool inputCapable = descriptor != BUILT_IN_PROVIDERS.end() &&
								  (descriptor->capabilities &
								   capabilityMask( ProviderCapability::USER_SELECTED_FILE)) != 0 ;
		const bool enabled =
			std::find( options.enabledProviderIds.begin(), options.enabledProviderIds.end(),
					  input.providerId) != options.enabledProviderIds.end() ;	// 明示有効状態。
		const bool duplicate =
			std::find_if( options.userSelectedFiles.begin(),
						 options.userSelectedFiles.begin() + static_cast<std::ptrdiff_t>( index),
						 [&input]( const UserSelectedProviderFile &value) {
							 return value.providerId == input.providerId ;
						 }) != options.userSelectedFiles.begin() +
								   // 先行file入力とのProvider重複状態。
								   static_cast<std::ptrdiff_t>( index) ;
		// 無効Providerへのfile指定や空・埋込みNUL・重複入力を拒否し、選択した一件だけを扱う。
		if( !inputCapable || !enabled || input.path.empty() ||
		   input.path.find( L'\0') != std::wstring::npos || duplicate) {
			return false ;
		}
	}

	// UserSelectedFile Providerは入力なしでnetworkやdirectory探索へ縮退させない。
	for( const ProviderDescriptor &descriptor : BUILT_IN_PROVIDERS) {
		// 有効Providerに利用者指定fileが必要かを判定するcapability。
		const bool inputCapable =
			(descriptor.capabilities & capabilityMask( ProviderCapability::USER_SELECTED_FILE)) != 0 ;
		const bool enabled =
			std::find( options.enabledProviderIds.begin(), options.enabledProviderIds.end(),
					  descriptor.id) != options.enabledProviderIds.end() ;	// Provider有効状態。
		const auto inputCount =
			std::count_if( options.userSelectedFiles.begin(), options.userSelectedFiles.end(),
						  [&descriptor]( const UserSelectedProviderFile &input) {
							  return input.providerId == descriptor.id ;
						  }) ; // 関連file件数。
		// file入力型Providerが有効なら一件の入力を必須とし、省略や複数指定を許可しない。
		if( inputCapable && enabled && inputCount != 1) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/provider_registry.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isProviderEnabled( const ScanOptions &options, const ProviderDescriptor &descriptor) noexcept
{
	// 既定設定ではregistryの有効値を正本とし、UI独自のProvider一覧を使わない。
	if( options.useDefaultProviders) {
		return descriptor.enabledByDefault ;
	}

	return std::find( options.enabledProviderIds.begin(), options.enabledProviderIds.end(),
					 descriptor.id) != options.enabledProviderIds.end() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/provider_registry.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring_view userSelectedFileForProvider( const ScanOptions		 &options,
											  const std::wstring_view providerId) noexcept
{
	// 不正な検索設定や空IDからlocal fileを解決せず、無効な選択を返す。
	if( providerId.empty() || !validateScanOptions( options)) {
		return {} ;
	}

	// 指定Providerへ結び付いた単一入力の位置。検索用ID viewは呼出し中だけ有効。
	const auto input =
		std::find_if( options.userSelectedFiles.begin(), options.userSelectedFiles.end(),
					 [providerId]( const UserSelectedProviderFile &value) {
						 return value.providerId == providerId ;
					 }) ;
	return input == options.userSelectedFiles.end() ? std::wstring_view{}
													: std::wstring_view( input->path) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/provider_registry.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::uint64_t countDisplayCandidates( const ScanResult &result) noexcept
{
	return static_cast<std::uint64_t>(
		std::count_if( result.candidates.begin(), result.candidates.end(),
					  []( const UpdateCandidate &candidate) { return !candidate.current ; })) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/provider_registry.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ProviderScanState resolveProviderScanState( const ScanResult &result, const bool enabled) noexcept
{
	// 無効化されたProviderを検索失敗や候補なしとは表示せず、無効の状態を保つ。
	if( !enabled) {
		return ProviderScanState::DISABLED ;
	}

	// 検索に失敗した場合は、正常な候補なしの状態へ補正しない。
	if( !result.succeeded) {
		// 取得元・metadata・本体の拒否理由を保持し、それ以外の失敗は検索失敗へまとめる。
		switch( result.state) {
			// 失敗結果の metadata 拒否は専用分類を保持する共通分岐へ進む。
			case ProviderScanState::METADATA_REJECTED:
			// 失敗結果の取得元拒否は専用分類を保持する共通分岐へ進む。
			case ProviderScanState::SOURCE_REJECTED:
			// 失敗結果の download 失敗は専用分類を保持する共通分岐へ進む。
			case ProviderScanState::DOWNLOAD_FAILED:
			// 内容拒否を含む詳細な失敗分類は元の状態を維持する。
			case ProviderScanState::CONTENT_REJECTED:
				return result.state ;
			// 失敗結果なのに無効状態を示す矛盾は共通失敗へ進む。
			case ProviderScanState::DISABLED:
			// 失敗結果なのに対象外を示す矛盾は共通失敗へ進む。
			case ProviderScanState::NOT_APPLICABLE:
			// 失敗結果なのに候補なしを示す矛盾は共通失敗へ進む。
			case ProviderScanState::NO_CANDIDATES:
			// 失敗結果なのに候補ありを示す矛盾は共通失敗へ進む。
			case ProviderScanState::CANDIDATES_AVAILABLE:
			// Payload未許可を失敗結果と組み合わせた矛盾は共通失敗へ進む。
			case ProviderScanState::PAYLOAD_NOT_APPROVED:
			// 回線未許可も失敗結果と組み合わせた矛盾は共通失敗へ進む。
			case ProviderScanState::NETWORK_NOT_APPROVED:
			// 一般の失敗と矛盾した成功表示を失敗状態へ正規化する。
			case ProviderScanState::FAILURE:
				return ProviderScanState::FAILURE ;
		}

		return ProviderScanState::FAILURE ;
	}

	const std::uint64_t candidateCount = countDisplayCandidates( result) ;	// 非現在版候補数。
	// 成功結果の対象外・候補有無を実件数へ照合し、矛盾した状態を検索失敗へ落とす。
	switch( result.state) {
		// 対象外は候補がゼロの場合だけ維持し、候補を伴う矛盾は失敗にする。
		case ProviderScanState::NOT_APPLICABLE:
			return candidateCount == 0U ? ProviderScanState::NOT_APPLICABLE
										: ProviderScanState::FAILURE ;
		// 候補なしの宣言は実候補数による共通分類へ進む。
		case ProviderScanState::NO_CANDIDATES:
		// 候補あり・なしは実際の候補数に従って正規化する。
		case ProviderScanState::CANDIDATES_AVAILABLE:
			return candidateCount == 0U ? ProviderScanState::NO_CANDIDATES
										: ProviderScanState::CANDIDATES_AVAILABLE ;
		// Payload未許可はmetadata成立と候補0件の場合だけ維持する。
		case ProviderScanState::PAYLOAD_NOT_APPROVED:
			return candidateCount == 0U ? ProviderScanState::PAYLOAD_NOT_APPROVED
										: ProviderScanState::FAILURE ;
		// 回線未許可は候補0件の制御終端として維持する。
		case ProviderScanState::NETWORK_NOT_APPROVED:
			return candidateCount == 0U ? ProviderScanState::NETWORK_NOT_APPROVED
										: ProviderScanState::FAILURE ;
		// 成功結果の無効状態は矛盾として共通失敗へ進む。
		case ProviderScanState::DISABLED:
		// 成功結果の失敗状態は矛盾として共通失敗へ進む。
		case ProviderScanState::FAILURE:
		// 成功結果の metadata 拒否は矛盾として共通失敗へ進む。
		case ProviderScanState::METADATA_REJECTED:
		// 成功結果の取得元拒否は矛盾として共通失敗へ進む。
		case ProviderScanState::SOURCE_REJECTED:
		// 成功結果の download 失敗は矛盾として共通失敗へ進む。
		case ProviderScanState::DOWNLOAD_FAILED:
		// 内容拒否等の成功と矛盾する分類を一般の失敗へ正規化する。
		case ProviderScanState::CONTENT_REJECTED:
			return ProviderScanState::FAILURE ;
	}

	return ProviderScanState::FAILURE ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/provider_registry.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isProviderScanResultConsistent( const ScanResult &result, const bool enabled) noexcept
{
	// 無効なProviderには未実行結果の検証を要求せず、有効Providerの処理と分離する。
	if( !enabled) {
		return true ;
	}

	const bool successOutcome =	// succeeded=trueと対応できるoutcome。
		result.outcome == OutcomeCode::SUCCESS ||
		result.outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS ;
	// 成功flagと終了区分の矛盾、および未開始の完了通知を拒否する。
	if( result.succeeded != successOutcome || result.outcome == OutcomeCode::NOT_STARTED) {
		return false ;
	}

	// 成功を報告したProviderにも候補状態の整合を要求し、矛盾した成功を表示しない。
	if( result.succeeded) {
		return resolveProviderScanState( result, true) != ProviderScanState::FAILURE ;
	}

	// 失敗結果は失敗または中止の終了区分に限定し、部分成功との食い違いを拒否する。
	if( result.outcome != OutcomeCode::FAILURE && result.outcome != OutcomeCode::ABORTED) {
		return false ;
	}

	// 失敗の理由を表す状態だけを受理し、対象外や候補なしを失敗通知へ混ぜない。
	switch( result.state) {
		// 失敗結果の一般失敗は整合する状態として共通受理へ進む。
		case ProviderScanState::FAILURE:
		// 失敗結果の metadata 拒否は整合する状態として共通受理へ進む。
		case ProviderScanState::METADATA_REJECTED:
		// 失敗結果の取得元拒否は整合する状態として共通受理へ進む。
		case ProviderScanState::SOURCE_REJECTED:
		// 失敗結果の download 失敗は整合する状態として共通受理へ進む。
		case ProviderScanState::DOWNLOAD_FAILED:
		// 内容拒否を含む失敗系の状態を失敗結果と整合すると認める。
		case ProviderScanState::CONTENT_REJECTED:
			return true ;
		// 失敗結果の無効状態は矛盾として共通拒否へ進む。
		case ProviderScanState::DISABLED:
		// 失敗結果の対象外状態は矛盾として共通拒否へ進む。
		case ProviderScanState::NOT_APPLICABLE:
		// 失敗結果の候補なし状態は矛盾として共通拒否へ進む。
		case ProviderScanState::NO_CANDIDATES:
		// 候補あり等の成功系状態と失敗結果の組合せを拒否する。
		case ProviderScanState::CANDIDATES_AVAILABLE:
		// Payload未許可は成功終端であり、失敗結果とは両立しない。
		case ProviderScanState::PAYLOAD_NOT_APPROVED:
		// 回線未許可も通信を始めない成功終端であり失敗結果とは両立しない。
		case ProviderScanState::NETWORK_NOT_APPROVED:
			return false ;
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/provider_registry.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isValidProviderCoverage( const ProviderCoverage &coverage) noexcept
{
	return coverage.assessedDeviceCount <= coverage.eligibleDeviceCount ;
}

} // namespace drivercrate
