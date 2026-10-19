//------------------------------------------------------------------------------
/**
 * @file official_source_policy.cpp
 * @brief 公式取得元policy registry実装。
 * @version 01.03.00
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  ASIXのTerms・検査用配布物用途を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernetの取得前提確認と選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Focusrite公式取得元を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Wacom Windows公式取得元を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Ricoh PCL6公式取得元を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  NVIDIA WinOF-2取得元を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  ASIX AX88179A表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Intel Ethernet Server検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Broadcomの選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  共通配布情報とIntel公式検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  NetXtreme-E表示専用検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公式2経路とfamily別予算を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  CP210x公式取得とserial共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  公式serial取得と新版受入境界を更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  取得根拠検証強化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Opaque origin経路検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  AMD公式Web取得元追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASUS公式取得元追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASRock公式取得元追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  ASRock公式landing起点追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  公式resource実取得経路の検証を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Intel Ethernet Windows 11取得元を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/23  Wi-Fi ZIPのrecord限定payload用途を分離して追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/23  製品一覧外の取得専用開発policyを独立検証・解決。
 * </pre>
 *
 * @note 公式Providerの用途別hostとredirect方針を一元管理し、内容・導入監査とは分離します。
 */
//------------------------------------------------------------------------------

#include "core/official_source_policy.h"

#include "core/provider_registry.h"

#include <algorithm>
#include <array>
#include <cstddef>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t	MAXIMUM_POLICY_ID_CHARACTERS = 64U ;	// Stable ID文字数上限。
constexpr std::size_t	MAXIMUM_RESOURCES_PER_POLICY = 16U ;	// 一Providerのresource数上限。
constexpr std::size_t	MAXIMUM_HOSTS_PER_RESOURCE	 = 8U ;		// 一resourceのhost数上限。
constexpr std::uint32_t MAXIMUM_REDIRECTS			 = 5U ;		// Policyで許可できるredirect上限。

constexpr std::array<std::wstring_view, 1> NVIDIA_LANDING_HOSTS{
	L"www.nvidia.com"} ;	// NVIDIA公式landing host。
constexpr std::array<std::wstring_view, 1> NVIDIA_PRIMARY_METADATA_HOSTS{
	L"www.nvidia.com"} ;	// NVIDIA製品lookup host。
constexpr std::array<std::wstring_view, 1> NVIDIA_SECONDARY_METADATA_HOSTS{
	L"gfwsl.geforce.com"} ;	// NVIDIA release metadata host。
constexpr std::array<std::wstring_view, 1> NVIDIA_PAYLOAD_HOSTS{
	L".download.nvidia.com"} ;	// NVIDIA payload domainとsubdomain。

constexpr std::array<std::wstring_view, 1> DELL_HOSTS{
	L"downloads.dell.com"} ;	// Dell catalogとpayloadの公式host。
constexpr std::array<std::wstring_view, 1> LENOVO_HOSTS{
	L"download.lenovo.com"} ;	// Lenovo catalogとpayloadの公式host。
constexpr std::array<std::wstring_view, 1> HP_METADATA_HOSTS{
	L"hpia.hpcloud.hp.com"} ;	// HP Image Assistant metadata host。
constexpr std::array<std::wstring_view, 1> HP_PAYLOAD_HOSTS{
	L"ftp.hp.com"} ;	// HTTPS SoftPaq payload host。
constexpr std::array<std::wstring_view, 1> VAIO_METADATA_HOSTS{
	L"support.vaio.com"} ;	// VAIO modelとupdate metadata host。
constexpr std::array<std::wstring_view, 2> VAIO_PAYLOAD_HOSTS{
	L"dlcdnglobal.support.vaio.com", L"dlcdn2.support.vaio.com"} ;	// VAIO payload host。
constexpr std::array<std::wstring_view, 1> AMD_METADATA_HOSTS{
	L"www.amd.com"} ;	// AMD製品一覧と製品別support pageの公式host。
constexpr std::array<std::wstring_view, 1> AMD_PAYLOAD_HOSTS{
	L"drivers.amd.com"} ;	// 今回は取得しないAMD payload host。
constexpr std::array<std::wstring_view, 1> ASUS_METADATA_HOSTS{
	L"www.asus.com"} ;	// ASUS製品別support pageの公式host。
constexpr std::array<std::wstring_view, 1> ASUS_PAYLOAD_HOSTS{
	L"dlcdnets.asus.com"} ;	// ASUS Global driver archive CDN host。
constexpr std::array<std::wstring_view, 1> ASROCK_METADATA_HOSTS{
	L"www.asrock.com"} ;	// ASRock Latest Drivers Update一覧の公式host。

// NVIDIA Providerの用途別resource policy。
constexpr std::array<OfficialSourceResourcePolicy, 4> NVIDIA_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = NVIDIA_LANDING_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::METADATA,
								 .allowedHosts	   = NVIDIA_PRIMARY_METADATA_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_SECONDARY_METADATA_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::METADATA,
								 .allowedHosts	   = NVIDIA_SECONDARY_METADATA_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::PAYLOAD,
								 .allowedHosts	   = NVIDIA_PAYLOAD_HOSTS,
								 .maximumRedirects = 0}} ;

// Dell PC Providerの用途別resource policy。
constexpr std::array<OfficialSourceResourcePolicy, 3> DELL_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = DELL_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::METADATA,
								 .allowedHosts	   = DELL_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::PAYLOAD,
								 .allowedHosts	   = DELL_HOSTS,
								 .maximumRedirects = 0}} ;

// Dell PowerEdge Providerの用途別resource policy。
constexpr std::array<OfficialSourceResourcePolicy, 4> DELL_POWER_EDGE_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = DELL_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::METADATA,
								 .allowedHosts	   = DELL_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_DETACHED_SIGNATURE_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::DETACHED_SIGNATURE,
								 .allowedHosts	   = DELL_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::PAYLOAD,
								 .allowedHosts	   = DELL_HOSTS,
								 .maximumRedirects = 0}} ;

// Lenovo Providerの用途別resource policy。
constexpr std::array<OfficialSourceResourcePolicy, 3> LENOVO_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = LENOVO_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::METADATA,
								 .allowedHosts	   = LENOVO_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::PAYLOAD,
								 .allowedHosts	   = LENOVO_HOSTS,
								 .maximumRedirects = 0}} ;

// HP Providerの用途別resource policy。
constexpr std::array<OfficialSourceResourcePolicy, 3> HP_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = HP_METADATA_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::METADATA,
								 .allowedHosts	   = HP_METADATA_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::PAYLOAD,
								 .allowedHosts	   = HP_PAYLOAD_HOSTS,
								 .maximumRedirects = 0}} ;

// VAIO Providerの用途別resource policy。
constexpr std::array<OfficialSourceResourcePolicy, 3> VAIO_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = VAIO_METADATA_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::METADATA,
								 .allowedHosts	   = VAIO_METADATA_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::PAYLOAD,
								 .allowedHosts	   = VAIO_PAYLOAD_HOSTS,
								 .maximumRedirects = 0}} ;

// AMD表示専用Providerの用途別resource policy。
constexpr std::array<OfficialSourceResourcePolicy, 4> AMD_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = AMD_METADATA_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::METADATA,
								 .allowedHosts	   = AMD_METADATA_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_SECONDARY_METADATA_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::METADATA,
								 .allowedHosts	   = AMD_METADATA_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::PAYLOAD,
								 .allowedHosts	   = AMD_PAYLOAD_HOSTS,
								 .maximumRedirects = 0}} ;

// ASUS Providerの用途別resource policy。
constexpr std::array<OfficialSourceResourcePolicy, 3> ASUS_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = ASUS_METADATA_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::METADATA,
								 .allowedHosts	   = ASUS_METADATA_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::PAYLOAD,
								 .allowedHosts	   = ASUS_PAYLOAD_HOSTS,
								 .maximumRedirects = 0}} ;

// ASRock表示専用Providerの用途別resource policy。
constexpr std::array<OfficialSourceResourcePolicy, 2> ASROCK_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = ASROCK_METADATA_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::METADATA,
								 .allowedHosts	   = ASROCK_METADATA_HOSTS,
								 .maximumRedirects = 0}} ;

// 公式network Providerと一対一に対応する組み込みpolicy群。
constexpr std::array<std::wstring_view, 1> PROLIFIC_HOSTS{
	L"www.prolific.com.tw"} ;	// 他subdomainと外部mirrorは許可しない。
constexpr std::array<OfficialSourceResourcePolicy, 2> PROLIFIC_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = PROLIFIC_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::PAYLOAD,
								 .allowedHosts	   = PROLIFIC_HOSTS,
								 .maximumRedirects = 0}} ;	// 製品pageとZIPを別用途に拘束する。

constexpr std::array<std::wstring_view, 1> SILICON_LABS_HOSTS{
	L"www.silabs.com"} ;	// Subdomain、login service、外部CDNへ許可を広げない。
constexpr std::array<OfficialSourceResourcePolicy, 3> SILICON_LABS_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = SILICON_LABS_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::METADATA,
								 .allowedHosts	   = SILICON_LABS_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::PAYLOAD,
								 .allowedHosts	   = SILICON_LABS_HOSTS,
								 .maximumRedirects = 0}} ;	// 用途ごとに取得根拠を保持する。

constexpr std::array<std::wstring_view, 1> WCH_LANDING_HOSTS{
	L"www.wch.cn"} ;	// 公式配布pageの完全一致host。
constexpr std::array<std::wstring_view, 1> WCH_METADATA_HOSTS{
	L"api1.wch.cn"} ;	// 公開lookupの完全一致host。
constexpr std::array<std::wstring_view, 1> WCH_PAYLOAD_HOSTS{
	L"file.wch.cn"} ;	// 公式download UIが示すfile hostだけを許可する。
constexpr std::array<OfficialSourceResourcePolicy, 3> WCH_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = WCH_LANDING_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::METADATA,
								 .allowedHosts	   = WCH_METADATA_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id		   = OFFICIAL_PAYLOAD_RESOURCE_ID,
								 .kind		   = OfficialSourceResourceKind::PAYLOAD,
								 .allowedHosts = WCH_PAYLOAD_HOSTS,
								 .maximumRedirects =
									 0}} ;	// 2 familyで同じ用途別host制約を使用する。

constexpr std::array<std::wstring_view, 1> BROADCOM_PRODUCT_HOSTS{
	L"www.broadcom.com"} ;	// 固定公開製品JSONの公式host。
constexpr std::array<std::wstring_view, 1> BROADCOM_DOCUMENT_HOSTS{
	L"docs.broadcom.com"} ;	// 公開EULA metadataと選択取得ZIPの公式host。
// ADR 0102の選択取得だけにpayload用途を追加する。Install許可とは別である。
constexpr std::array<OfficialSourceResourcePolicy, 4> BROADCOM_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = BROADCOM_PRODUCT_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::METADATA,
								 .allowedHosts	   = BROADCOM_PRODUCT_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_SECONDARY_METADATA_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::METADATA,
								 .allowedHosts	   = BROADCOM_DOCUMENT_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::PAYLOAD,
								 .allowedHosts	   = BROADCOM_DOCUMENT_HOSTS,
								 .maximumRedirects = 0}} ;

constexpr std::array<std::wstring_view, 1> INTEL_WIFI_PAGE_HOSTS{
	L"www.intel.com"} ;	// Wi-Fi IT管理者向け公開pageの完全一致host。
// ADR 0197の開発用ZIP取得先。通常Providerの導入能力を変更しない。
constexpr std::array<std::wstring_view, 1> INTEL_WIFI_PAYLOAD_HOSTS{L"downloadmirror.intel.com"} ;
// Landingとmetadataの既存起点を保ち、record限定取得のpayload用途を分離する。
constexpr std::array<OfficialSourceResourcePolicy, 3> INTEL_WIFI_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = INTEL_WIFI_PAGE_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::METADATA,
								 .allowedHosts	   = INTEL_WIFI_PAGE_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::PAYLOAD,
								 .allowedHosts	   = INTEL_WIFI_PAYLOAD_HOSTS,
								 .maximumRedirects = 0}} ;

constexpr std::array<std::wstring_view, 1> INTEL_ETHERNET_SERVER_PAGE_HOSTS{
	L"www.intel.com"} ;	// Server 2025向けEthernet配布pageの完全一致host。
constexpr std::array<std::wstring_view, 1> INTEL_ETHERNET_SERVER_PAYLOAD_HOSTS{
	L"downloadmirror.intel.com"} ;	// 許諾snapshotに結合した配布ZIPの完全一致host。
// Pageとpayloadを分離し、取得前に利用者の同意と同一scanの取得根拠を要求する。
constexpr std::array<OfficialSourceResourcePolicy, 2> INTEL_ETHERNET_SERVER_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = INTEL_ETHERNET_SERVER_PAGE_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::PAYLOAD,
								 .allowedHosts	   = INTEL_ETHERNET_SERVER_PAYLOAD_HOSTS,
								 .maximumRedirects = 0}} ;

// Windows 11 recordも同じIntel公式hostを使用するが、Server系列とは別policyで追跡する。
constexpr std::array<OfficialSourceResourcePolicy, 2> INTEL_ETHERNET_WINDOWS11_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = INTEL_ETHERNET_SERVER_PAGE_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::PAYLOAD,
								 .allowedHosts	   = INTEL_ETHERNET_SERVER_PAYLOAD_HOSTS,
								 .maximumRedirects = 0}} ;

constexpr std::array<std::wstring_view, 1> ASIX_PAGE_HOSTS{
	L"www.asix.com.tw"} ;	// AX88179A製品・Terms・配布endpointの完全一致host。
// ADR 0136の本文同意・取得前提確認を経た選択取得だけへpayload用途を追加する。
constexpr std::array<OfficialSourceResourcePolicy, 3> ASIX_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = ASIX_PAGE_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::METADATA,
								 .allowedHosts	   = ASIX_PAGE_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::PAYLOAD,
								 .allowedHosts	   = ASIX_PAGE_HOSTS,
								 .maximumRedirects = 0}} ;

constexpr std::array<std::wstring_view, 1> RICOH_UNIVERSAL_PRINT_PAGE_HOSTS{
	L"support.ricoh.com"} ;	// Universal Print Driver pageの完全一致host。
// 公開hashと内容監査が未解決のため、payload用途を登録しない。
constexpr std::array<OfficialSourceResourcePolicy, 1> RICOH_UNIVERSAL_PRINT_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = RICOH_UNIVERSAL_PRINT_PAGE_HOSTS,
								 .maximumRedirects = 0}} ;

constexpr std::array<std::wstring_view, 1> WACOM_WINDOWS_PAGE_HOSTS{
	L"www.wacom.com"} ;	// Product Resources pageの完全一致host。
// 統合EXEの内容監査とEULA結合が未解決のため、payload用途を登録しない。
constexpr std::array<OfficialSourceResourcePolicy, 1> WACOM_WINDOWS_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = WACOM_WINDOWS_PAGE_HOSTS,
								 .maximumRedirects = 0}} ;

constexpr std::array<std::wstring_view, 1> FOCUSRITE_SCARLETT2I2_PAGE_HOSTS{
	L"downloads.focusrite.com"} ;	// Scarlett 2i2 2nd Gen pageの完全一致host。
// EXE内容監査とPnP適用性が未解決のため、payload用途を登録しない。
constexpr std::array<OfficialSourceResourcePolicy, 1> FOCUSRITE_SCARLETT2I2_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = FOCUSRITE_SCARLETT2I2_PAGE_HOSTS,
								 .maximumRedirects = 0}} ;

constexpr std::array<std::wstring_view, 1> NVIDIA_WINOF2_LANDING_HOSTS{
	L"network.nvidia.com"} ;	// WinOF-2製品pageの完全一致host。
constexpr std::array<std::wstring_view, 1> NVIDIA_WINOF2_METADATA_HOSTS{
	L"downloaders.azurewebsites.net"} ;	// NVIDIA pageが委譲するDownload Center host。
// 混在EXEの取得・内容監査が未完了のため、payload用途を登録しない。
constexpr std::array<OfficialSourceResourcePolicy, 2> NVIDIA_WINOF2_RESOURCES{
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
								 .allowedHosts	   = NVIDIA_WINOF2_LANDING_HOSTS,
								 .maximumRedirects = 0},
	OfficialSourceResourcePolicy{.id			   = OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
								 .kind			   = OfficialSourceResourceKind::METADATA,
								 .allowedHosts	   = NVIDIA_WINOF2_METADATA_HOSTS,
								 .maximumRedirects = 0}} ;

// 全公式network Providerと一対一に対応するpolicy集合。
// PROLIFICの固定metadata GET起点。Payload URLは登録しない。
constexpr std::array<OfficialMetadataEndpoint, 1> PROLIFIC_METADATA_ENDPOINTS{
	OfficialMetadataEndpoint{OFFICIAL_LANDING_RESOURCE_ID,
							 L"https://www.prolific.com.tw/portfolio-item/pl2303gt/"}} ;

// INTELの固定metadata GET起点。Payload URLは登録しない。
constexpr std::array<OfficialMetadataEndpoint, 1> INTEL_METADATA_ENDPOINTS{OfficialMetadataEndpoint{
	OFFICIAL_LANDING_RESOURCE_ID,
	L"https://www.intel.com/content/www/us/en/download/18231/"
	L"intel-proset-wireless-software-and-wi-fi-drivers-for-it-administrators.html"}} ;

// INTEL_ETHERNET_SERVER2025の固定metadata GET起点。Payload URLは登録しない。
constexpr std::array<OfficialMetadataEndpoint, 1> INTEL_ETHERNET_SERVER2025_METADATA_ENDPOINTS{
	OfficialMetadataEndpoint{OFFICIAL_LANDING_RESOURCE_ID,
							 L"https://www.intel.com/content/www/us/en/download/838943/"
							 L"intel-network-adapter-driver-for-windows-server-2025.html"}} ;

// INTEL_ETHERNET_WINDOWS11の固定metadata GET起点。Payload URLは登録しない。
constexpr std::array<OfficialMetadataEndpoint, 1> INTEL_ETHERNET_WINDOWS11_METADATA_ENDPOINTS{
	OfficialMetadataEndpoint{OFFICIAL_LANDING_RESOURCE_ID,
							 L"https://www.intel.com/content/www/us/en/download/727998/"
							 L"intel-network-adapter-driver-for-microsoft-windows-11.html"}} ;

// RICOH_UNIVERSAL_PCL6の固定metadata GET起点。Payload URLは登録しない。
constexpr std::array<OfficialMetadataEndpoint, 1> RICOH_UNIVERSAL_PCL6_METADATA_ENDPOINTS{
	OfficialMetadataEndpoint{OFFICIAL_LANDING_RESOURCE_ID,
							 L"https://support.ricoh.com/bb/html/dr_ut_e/rc3/model/p_i/p_ies.htm"}} ;

// WACOM_WINDOWS_TABLETの固定metadata GET起点。Payload URLは登録しない。
constexpr std::array<OfficialMetadataEndpoint, 1> WACOM_WINDOWS_TABLET_METADATA_ENDPOINTS{
	OfficialMetadataEndpoint{OFFICIAL_LANDING_RESOURCE_ID,
							 L"https://www.wacom.com/en-us/support/product-support/drivers"}} ;

// FOCUSRITE_SCARLETT2I2の固定metadata GET起点。Payload URLは登録しない。
constexpr std::array<OfficialMetadataEndpoint, 1> FOCUSRITE_SCARLETT2I2_METADATA_ENDPOINTS{
	OfficialMetadataEndpoint{OFFICIAL_LANDING_RESOURCE_ID,
							 L"https://downloads.focusrite.com/focusrite/scarlett-2nd-gen/"
							 L"scarlett-2i2-2nd-gen"}} ;

// SILICON_LABSの固定metadata GET起点。Payload URLは登録しない。
constexpr std::array<OfficialMetadataEndpoint, 2> SILICON_LABS_METADATA_ENDPOINTS{
	OfficialMetadataEndpoint{OFFICIAL_LANDING_RESOURCE_ID,
							 L"https://www.silabs.com/software-and-tools/"
							 L"usb-to-uart-bridge-vcp-drivers?tab=downloads"},
	OfficialMetadataEndpoint{OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
							 L"https://www.silabs.com/sl/search/softwaredocumentsearchquery.json/"
							 L"ct-software/soft-drivers_vcp-drivers.json"}} ;

// WCH_CH341の固定metadata GET起点。Payload URLは登録しない。
constexpr std::array<OfficialMetadataEndpoint, 2> WCH_CH341_METADATA_ENDPOINTS{
	OfficialMetadataEndpoint{OFFICIAL_LANDING_RESOURCE_ID,
							 L"https://www.wch.cn/downloads/CH341SER_ZIP.html"},
	OfficialMetadataEndpoint{OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
							 L"https://api1.wch.cn/api/official/website/common/"
							 L"relationFiles?fileName=CH341SER_ZIP.html"}} ;

// WCH_CH343の固定metadata GET起点。Payload URLは登録しない。
constexpr std::array<OfficialMetadataEndpoint, 2> WCH_CH343_METADATA_ENDPOINTS{
	OfficialMetadataEndpoint{OFFICIAL_LANDING_RESOURCE_ID,
							 L"https://www.wch.cn/downloads/CH343SER_ZIP.html"},
	OfficialMetadataEndpoint{OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
							 L"https://api1.wch.cn/api/official/website/common/"
							 L"relationFiles?fileName=CH343SER_ZIP.html"}} ;

// 組み込み公式Providerの取得元・用途・固定metadata起点の唯一の登録表。
// 開発用sourceは製品一覧・通常scanへ公開しない。製品policyとは別に同じvalidatorを通す。
const std::array<ProviderDescriptor, 1>		  DEVELOPMENT_PROVIDERS{ProviderDescriptor{
		  .id					  = std::wstring( INTEL_DOWNLOAD_DEVELOPMENT_PROVIDER_ID),
		  .displayName			  = L"Intel download-only development",
		  .capabilities			  = capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
		  .enabledByDefault		  = false,
		  .officialSourcePolicyId = std::wstring( INTEL_DOWNLOAD_DEVELOPMENT_POLICY_ID)}} ;
// BluetoothとArcの起点は別resource、payloadは同じ公式配布hostへ限定する。
constexpr std::array<OfficialSourcePolicy, 1> DEVELOPMENT_POLICIES{
	OfficialSourcePolicy{.id		 = INTEL_DOWNLOAD_DEVELOPMENT_POLICY_ID,
						 .providerId = INTEL_DOWNLOAD_DEVELOPMENT_PROVIDER_ID,
						 .resources	 = INTEL_WIFI_RESOURCES}} ;

// 通常製品Providerに一対一で対応する既存policy集合。
constexpr std::array<OfficialSourcePolicy, 22> BUILT_IN_POLICIES{
	OfficialSourcePolicy{.id		 = NVIDIA_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId = NVIDIA_PROVIDER_ID,
						 .resources	 = NVIDIA_RESOURCES},
	OfficialSourcePolicy{.id		 = DELL_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId = DELL_PROVIDER_ID,
						 .resources	 = DELL_RESOURCES},
	OfficialSourcePolicy{.id		 = DELL_POWER_EDGE_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId = DELL_POWER_EDGE_PROVIDER_ID,
						 .resources	 = DELL_POWER_EDGE_RESOURCES},
	OfficialSourcePolicy{.id		 = LENOVO_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId = LENOVO_PROVIDER_ID,
						 .resources	 = LENOVO_RESOURCES},
	OfficialSourcePolicy{.id		 = HP_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId = HP_PROVIDER_ID,
						 .resources	 = HP_RESOURCES},
	OfficialSourcePolicy{.id		 = VAIO_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId = VAIO_PROVIDER_ID,
						 .resources	 = VAIO_RESOURCES},
	OfficialSourcePolicy{.id		 = AMD_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId = AMD_PROVIDER_ID,
						 .resources	 = AMD_RESOURCES},
	OfficialSourcePolicy{.id		 = ASUS_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId = ASUS_PROVIDER_ID,
						 .resources	 = ASUS_RESOURCES},
	OfficialSourcePolicy{.id		 = ASROCK_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId = ASROCK_PROVIDER_ID,
						 .resources	 = ASROCK_RESOURCES},
	OfficialSourcePolicy{.id				= PROLIFIC_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId		= PROLIFIC_OFFICIAL_PROVIDER_ID,
						 .resources			= PROLIFIC_RESOURCES,
						 .metadataEndpoints = PROLIFIC_METADATA_ENDPOINTS},
	OfficialSourcePolicy{.id				= SILICON_LABS_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId		= SILICON_LABS_OFFICIAL_PROVIDER_ID,
						 .resources			= SILICON_LABS_RESOURCES,
						 .metadataEndpoints = SILICON_LABS_METADATA_ENDPOINTS},
	OfficialSourcePolicy{.id				= WCH_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId		= WCH_OFFICIAL_PROVIDER_ID,
						 .resources			= WCH_RESOURCES,
						 .metadataEndpoints = WCH_CH341_METADATA_ENDPOINTS},
	OfficialSourcePolicy{.id				= WCH_MULTI_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId		= WCH_MULTI_OFFICIAL_PROVIDER_ID,
						 .resources			= WCH_RESOURCES,
						 .metadataEndpoints = WCH_CH343_METADATA_ENDPOINTS},
	OfficialSourcePolicy{.id		 = BROADCOM_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId = BROADCOM_NET_XTREME_PROVIDER_ID,
						 .resources	 = BROADCOM_RESOURCES},
	OfficialSourcePolicy{.id				= INTEL_WIFI_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId		= INTEL_WIFI_OFFICIAL_PROVIDER_ID,
						 .resources			= INTEL_WIFI_RESOURCES,
						 .metadataEndpoints = INTEL_METADATA_ENDPOINTS},
	OfficialSourcePolicy{.id				= INTEL_ETHERNET_SERVER2025_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId		= INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID,
						 .resources			= INTEL_ETHERNET_SERVER_RESOURCES,
						 .metadataEndpoints = INTEL_ETHERNET_SERVER2025_METADATA_ENDPOINTS},
	OfficialSourcePolicy{.id				= INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId		= INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID,
						 .resources			= INTEL_ETHERNET_WINDOWS11_RESOURCES,
						 .metadataEndpoints = INTEL_ETHERNET_WINDOWS11_METADATA_ENDPOINTS},
	OfficialSourcePolicy{.id		 = ASIX_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId = ASIX_AX88179A_PROVIDER_ID,
						 .resources	 = ASIX_RESOURCES},
	OfficialSourcePolicy{.id				= RICOH_UNIVERSAL_PRINT_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId		= RICOH_UNIVERSAL_PRINT_PROVIDER_ID,
						 .resources			= RICOH_UNIVERSAL_PRINT_RESOURCES,
						 .metadataEndpoints = RICOH_UNIVERSAL_PCL6_METADATA_ENDPOINTS},
	OfficialSourcePolicy{.id				= WACOM_WINDOWS_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId		= WACOM_WINDOWS_PROVIDER_ID,
						 .resources			= WACOM_WINDOWS_RESOURCES,
						 .metadataEndpoints = WACOM_WINDOWS_TABLET_METADATA_ENDPOINTS},
	OfficialSourcePolicy{.id				= FOCUSRITE_SCARLETT2I2_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId		= FOCUSRITE_SCARLETT2I2_PROVIDER_ID,
						 .resources			= FOCUSRITE_SCARLETT2I2_RESOURCES,
						 .metadataEndpoints = FOCUSRITE_SCARLETT2I2_METADATA_ENDPOINTS},
	OfficialSourcePolicy{.id		 = NVIDIA_WINOF2_OFFICIAL_SOURCE_POLICY_ID,
						 .providerId = NVIDIA_WINOF2_PROVIDER_ID,
						 .resources	 = NVIDIA_WINOF2_RESOURCES}} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Stable IDに使用できるASCII文字列か判定する。
 *
 * 空、長過ぎる値、先頭／末尾hyphen、Unicode類似文字を拒否する。
 *
 * @param[in] value 検証するID。
 * @return 小文字英数字と内部hyphenだけの場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidStableId( const std::wstring_view value) noexcept
{
	// 空ID、過大なID、区切りで始終するIDを拒否し、policy照合の曖昧さを防ぐ。
	if( value.empty() || value.size() > MAXIMUM_POLICY_ID_CHARACTERS || value.front() == L'-' ||
	   value.back() == L'-') {
		return false ;
	}

	// Stable IDを構成する全文字を有限に確認する。
	for( const wchar_t character : value) {
		const bool lowercaseLetter = character >= L'a' && character <= L'z' ;	// ASCII小文字。
		const bool digit		   = character >= L'0' && character <= L'9' ;	// ASCII数字。
		// policy IDを許可した小文字ASCIIへ限定し、別表記への暗黙の正規化を行わない。
		if( !lowercaseLetter && !digit && character != L'-') {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASCII DNS名がhost policyとして有効か判定する。
 *
 * Wildcard、空label、Unicode、label端hyphenを拒否する。
 *
 * @param[in] value 完全一致hostまたは先頭dot付きsuffix。
 * @return ASCII DNS labelとsuffix規則を満たす場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidHostPattern( const std::wstring_view value) noexcept
{
	const bool suffix = !value.empty() && value.front() == L'.' ;		// Subdomain許可policyの場合true。
	const std::wstring_view host = suffix ? value.substr( 1) : value ;	// DNS名本体。
	// 空host、全体長超過、前後の空labelを拒否し、不完全なDNS名を登録しない。
	if( host.empty() || host.size() > 253U || host.front() == L'.' || host.back() == L'.') {
		return false ;
	}

	std::size_t labelLength{} ;	// 現在labelの文字数。
	wchar_t		previous{} ;	// Label末尾hyphenを判定する直前文字。
	// DNS名を先頭から確認し、空labelと不正文字を拒否する。
	for( const wchar_t character : host) {
		// DNS labelの終端で長さと末尾を検証し、次のlabelへ進む前に不正なhostを除く。
		if( character == L'.') {
			// 空label、過長label、末尾hyphenを含むhostをallowlistの根拠へ使わない。
			if( labelLength == 0U || labelLength > 63U || previous == L'-') {
				return false ;
			}

			labelLength = 0U ;
			previous	= character ;
			continue ;
		}

		const bool lowercaseLetter = character >= L'a' && character <= L'z' ;	// ASCII小文字。
		const bool uppercaseLetter = character >= L'A' && character <= L'Z' ;	// ASCII大文字。
		const bool digit		   = character >= L'0' && character <= L'9' ;	// ASCII数字。
		// DNS labelに使わない文字を拒否し、URLやpathをhost名として受理しない。
		if( !lowercaseLetter && !uppercaseLetter && !digit && character != L'-') {
			return false ;
		}

		// hyphenで始まるDNS labelを受理せず、曖昧なhost指定を防ぐ。
		if( labelLength == 0U && character == L'-') {
			return false ;
		}

		++labelLength ;
		previous = character ;
	}

	return labelLength != 0U && labelLength <= 63U && previous != L'-' ;
}

//------------------------------------------------------------------------------
/**
 * @brief Resource用途が定義済みか判定する。
 *
 * 外部値のcast等で生じた定義外用途をfail-closedで拒否する。
 *
 * @param[in] kind 検証するresource用途。
 * @return 定義済み列挙値の場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidResourceKind( const OfficialSourceResourceKind kind) noexcept
{
	// 実装が用途を識別できるresourceだけを許可し、未知用途に通信権限を与えない。
	switch( kind) {
		// Landing page は既知の resource 用途として共通受理へ進む。
		case OfficialSourceResourceKind::LANDING_PAGE:
		// Metadata は既知の resource 用途として共通受理へ進む。
		case OfficialSourceResourceKind::METADATA:
		// Detached signature は既知の resource 用途として共通受理へ進む。
		case OfficialSourceResourceKind::DETACHED_SIGNATURE:
		// Payload を含む定義済み resource 用途を形式上有効と認める。
		case OfficialSourceResourceKind::PAYLOAD:
			return true ;
		// 未知の用途を公式 resource policy へ登録させない。
		default:
			return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Stable resource IDと用途が一致するか判定する。
 *
 * 呼出APIの用途と異なるhost policyへのすり替えを拒否する。
 *
 * @param[in] resource IDと用途を検証するresource policy。
 * @return 組み込みで定義したIDと用途の組合せなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool resourceIdMatchesKind( const OfficialSourceResourcePolicy &resource) noexcept
{
	// 案内pageの固定IDをpayloadやmetadataの取得権限へ流用させない。
	if( resource.id == OFFICIAL_LANDING_RESOURCE_ID) {
		return resource.kind == OfficialSourceResourceKind::LANDING_PAGE ;
	}

	// metadata用の固定IDはmetadata用途に限定し、別用途の制限を迂回させない。
	if( resource.id == OFFICIAL_PRIMARY_METADATA_RESOURCE_ID ||
	   resource.id == OFFICIAL_SECONDARY_METADATA_RESOURCE_ID) {
		return resource.kind == OfficialSourceResourceKind::METADATA ;
	}

	// 分離署名のIDに別種のresourceを結び付けず、署名の取得境界を維持する。
	if( resource.id == OFFICIAL_DETACHED_SIGNATURE_RESOURCE_ID) {
		return resource.kind == OfficialSourceResourceKind::DETACHED_SIGNATURE ;
	}

	// payload用のIDは本体取得のpolicyに限定し、別用途の上限で処理させない。
	if( resource.id == OFFICIAL_PAYLOAD_RESOURCE_ID) {
		return resource.kind == OfficialSourceResourceKind::PAYLOAD ;
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief Resource policy単体の構造を検証する。
 *
 * 重複hostを大小文字を区別せず拒否し、空allowlistを許可しない。
 *
 * @param[in] resource 検証するresource policy。
 * @return ID、用途、host、redirect上限が有効な場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidResourcePolicy( const OfficialSourceResourcePolicy &resource) noexcept
{
	// resourceの用途、host集合、redirect上限が不正なら通信policyを登録しない。
	if( !isValidStableId( resource.id) || !isValidResourceKind( resource.kind) ||
	   !resourceIdMatchesKind( resource) || resource.allowedHosts.empty() ||
	   resource.allowedHosts.size() > MAXIMUM_HOSTS_PER_RESOURCE ||
	   resource.maximumRedirects > MAXIMUM_REDIRECTS) {
		return false ;
	}

	// 全hostを有限に検証し、後続の通信へ不正policyを渡さない。
	for( std::size_t index = 0U; index < resource.allowedHosts.size(); ++index) {
		const std::wstring_view host = resource.allowedHosts[index] ;	// 現在検証するhost。
		// 不正なhost表記をallowlistへ含めず、通信開始前にpolicyを拒否する。
		if( !isValidHostPattern( host)) {
			return false ;
		}

		// 前方entryだけと比較し、大小文字差による重複policyも拒否する。
		for( std::size_t previousIndex = 0U; previousIndex < index; ++previousIndex) {
			const std::wstring_view previousHost =
				resource.allowedHosts[previousIndex] ;	// 先行host entry。
			// ASCIIの大文字小文字だけが異なるhostも重複として拒否し、origin indexを一意に保つ。
			if( host.size() == previousHost.size() &&
			   std::equal( host.begin(), host.end(), previousHost.begin(),
						  []( const wchar_t left, const wchar_t right) {
							  // 比較元host文字をASCII小文字へ正規化する。
							  const wchar_t normalizedLeft = static_cast<wchar_t>(
								  left >= L'A' && left <= L'Z' ? left - L'A' + L'a' : left) ;
							  // 比較先host文字をASCII小文字へ正規化する。
							  const wchar_t normalizedRight = static_cast<wchar_t>(
								  right >= L'A' && right <= L'Z' ? right - L'A' + L'a' : right) ;
							  return normalizedLeft == normalizedRight ;
						  })) {
				return false ;
			}
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Providerが公式network capabilityを持つか判定する。
 *
 * Capability maskの他のbitを変更せず公式network境界だけを見る。
 *
 * @param[in] provider 判定するProvider定義。
 * @return OfficialNetwork bitが設定されている場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isOfficialNetworkProvider( const ProviderDescriptor &provider) noexcept
{
	return (provider.capabilities & capabilityMask( ProviderCapability::OFFICIAL_NETWORK)) != 0U ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/core/official_source_policy.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::span<const OfficialSourcePolicy> builtInOfficialSourcePolicies() noexcept
{
	return BUILT_IN_POLICIES ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_source_policy.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
const OfficialSourcePolicy *findOfficialSourcePolicy( const std::wstring_view policyId) noexcept
{
	// Stable IDが完全一致するpolicyだけを採用する。
	const auto policy = std::find_if(
		BUILT_IN_POLICIES.begin(), BUILT_IN_POLICIES.end(),
		[policyId]( const OfficialSourcePolicy &value) { return value.id == policyId ; }) ;
	// 製品IDと完全一致した場合は既存定義を維持する。
	if( policy != BUILT_IN_POLICIES.end()) {
		return &*policy ;
	}

	// 開発用の一意な固定ID以外へfallbackしない。
	return policyId == INTEL_DOWNLOAD_DEVELOPMENT_POLICY_ID ? &DEVELOPMENT_POLICIES.front()
															: nullptr ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_source_policy.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
const OfficialSourcePolicy *officialSourcePolicyForProvider(
	const std::wstring_view providerId) noexcept
{
	// Provider IDが完全一致するpolicyだけを採用する。
	const auto policy = std::find_if(
		BUILT_IN_POLICIES.begin(), BUILT_IN_POLICIES.end(),
		[providerId]( const OfficialSourcePolicy &value) { return value.providerId == providerId ; }) ;
	// 製品Providerの解決結果を変更しない。
	if( policy != BUILT_IN_POLICIES.end()) {
		return &*policy ;
	}

	// 開発sourceは製品Provider一覧へは登録しない。
	return providerId == INTEL_DOWNLOAD_DEVELOPMENT_PROVIDER_ID ? &DEVELOPMENT_POLICIES.front()
																: nullptr ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_source_policy.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
const OfficialSourceResourcePolicy *findOfficialSourceResource(
	const OfficialSourcePolicy &policy, const std::wstring_view resourceId) noexcept
{
	// Resource IDが完全一致する用途だけを採用する。
	const auto resource = std::find_if(
		policy.resources.begin(), policy.resources.end(),
		[resourceId]( const OfficialSourceResourcePolicy &value) { return value.id == resourceId ; }) ;
	return resource == policy.resources.end() ? nullptr : &*resource ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_source_policy.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring_view officialMetadataEndpoint( const std::wstring_view providerId,
										   const std::wstring_view resourceId) noexcept
{
	const auto *policy = officialSourcePolicyForProvider( providerId) ;	// 正本の有限policy。
	// 未対応policyを別ProviderのURLへ補完しない。
	if( policy == nullptr) {
		return {} ;
	}

	const auto found =
		std::find_if( policy->metadataEndpoints.begin(), policy->metadataEndpoints.end(),
					 [resourceId]( const auto &endpoint) {
						 return endpoint.resourceId == resourceId ;
					 }) ; // 完全一致する用途。
	return found == policy->metadataEndpoints.end() ? std::wstring_view{} : found->url ;
}

/** @see core/official_source_policy.h */
bool validateOfficialSourcePolicies( const std::span<const OfficialSourcePolicy> policies,
									const std::span<const ProviderDescriptor>	providers) noexcept
{
	// Providerより多いpolicyを拒否し、一Provider一policyの前提を維持する。
	if( policies.size() > providers.size()) {
		return false ;
	}

	// 全policyを登録順に検証し、IDとProvider対応の一意性を確認する。
	for( std::size_t policyIndex = 0U; policyIndex < policies.size(); ++policyIndex) {
		const OfficialSourcePolicy &policy = policies[policyIndex] ;	// 現在のpolicy。
		// policyとProviderのID、resource数が不正なら、通信制限の登録を成立させない。
		if( !isValidStableId( policy.id) || !isValidStableId( policy.providerId) ||
		   policy.resources.empty() || policy.resources.size() > MAXIMUM_RESOURCES_PER_POLICY) {
			return false ;
		}

		// Policy IDとProvider IDはそれぞれ一意でなければならない。
		for( std::size_t previousIndex = 0U; previousIndex < policyIndex; ++previousIndex) {
			const OfficialSourcePolicy &previous = policies[previousIndex] ;	// 先行policy。
			// policy IDまたはProvider対応の重複を拒否し、一つの取得要求に複数の制限を与えない。
			if( policy.id == previous.id || policy.providerId == previous.providerId) {
				return false ;
			}
		}

		// Policyが参照するProviderをstable IDで解決する。
		const auto provider = std::find_if(
			providers.begin(), providers.end(),
			[&policy]( const ProviderDescriptor &value) { return value.id == policy.providerId ; }) ;
		// 未登録Providerや公式通信能力のないProviderへ、公式取得policyを結び付けない。
		if( provider == providers.end() || !isOfficialNetworkProvider( *provider) ||
		   provider->officialSourcePolicyId != policy.id) {
			return false ;
		}

		const bool metadataCapable =
			(provider->capabilities & capabilityMask( ProviderCapability::METADATA_ONLY_SCAN)) !=
			0U ;	// 専用能力との両側対応。
		// 専用能力と固定起点の片側だけを登録しない。
		if( metadataCapable != !policy.metadataEndpoints.empty() ||
		   policy.metadataEndpoints.size() > 2U) {
			return false ;
		}

		// 最大二起点を用途と一意性へ照合し、詳細URL検証は共通HTTPで実施する。
		for( std::size_t endpointIndex = 0U; endpointIndex < policy.metadataEndpoints.size();
			++endpointIndex) {
			const auto &endpoint =
				policy.metadataEndpoints[endpointIndex] ;	// 固定resourceとURLの組。
			const auto *resource =
				// 用途の正本。
				findOfficialSourceResource( policy, endpoint.resourceId) ;
			// Payload・空URL・過大URLを情報検索の起点へ使用しない。
			if( resource == nullptr || endpoint.url.empty() || endpoint.url.size() > 8192U ||
			   !endpoint.url.starts_with( L"https://") ||
			   (resource->kind != OfficialSourceResourceKind::LANDING_PAGE &&
				resource->kind != OfficialSourceResourceKind::METADATA)) {
				return false ;
			}

			// 同じ用途へ複数URLを登録して任意の選択余地を作らない。
			for( std::size_t previous = 0U; previous < endpointIndex; ++previous) {
				// 一つの用途に複数起点を持つ曖昧なpolicyを拒否する。
				if( policy.metadataEndpoints[previous].resourceId == endpoint.resourceId) {
					return false ;
				}
			}
		}

		bool hasLanding{} ;			// 一つ以上の公式起点が登録されている場合true。
		bool hasReadableContent{} ;	// Landing、metadataまたはpayloadがある場合true。
		// Policy内の全resourceを検証し、用途とIDの一意性を確認する。
		for( std::size_t resourceIndex = 0U; resourceIndex < policy.resources.size();
			++resourceIndex) {
			const OfficialSourceResourcePolicy &resource =
				policy.resources[resourceIndex] ;	// 現在のresource policy。
			// 一つでもresourceの検証が失敗したpolicyは、部分的に利用可能として登録しない。
			if( !isValidResourcePolicy( resource)) {
				return false ;
			}

			// 同じpolicy内のresource ID重複を拒否する。
			for( std::size_t previousIndex = 0U; previousIndex < resourceIndex; ++previousIndex) {
				// 同じresource IDに複数の制限を設定させず、照合結果を一意にする。
				if( resource.id == policy.resources[previousIndex].id) {
					return false ;
				}
			}

			hasLanding = hasLanding || resource.kind == OfficialSourceResourceKind::LANDING_PAGE ;
			hasReadableContent = hasReadableContent ||
								 resource.kind == OfficialSourceResourceKind::LANDING_PAGE ||
								 resource.kind == OfficialSourceResourceKind::METADATA ||
								 resource.kind == OfficialSourceResourceKind::PAYLOAD ;
		}

		// 公式案内と読取り対象の両方を持たないpolicyを、不完全な取得経路として拒否する。
		if( !hasLanding || !hasReadableContent) {
			return false ;
		}
	}

	// 全公式network Providerが一意なpolicyを持ち、それ以外はpolicy IDを持たないことを確認する。
	for( const ProviderDescriptor &provider : providers) {
		const std::size_t matches = static_cast<std::size_t>( std::count_if(
			policies.begin(), policies.end(), [&provider]( const OfficialSourcePolicy &policy) {
				return policy.providerId == provider.id ;
			})) ; // 対応policy件数。
		// 公式通信を行うProviderには専用policyを必須とし、非network Providerとは別に照合する。
		if( isOfficialNetworkProvider( provider)) {
			// 公式network Providerには一意のpolicyを必須とし、根拠のない通信を許可しない。
			if( matches != 1U || provider.officialSourcePolicyId.empty()) {
				return false ;
			}
		}
		// 非network Providerへ公式通信policyを付加し、権限を拡張する構成を拒否する。
		else if( matches != 0U || !provider.officialSourcePolicyId.empty()) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_source_policy.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool validateBuiltInOfficialSourcePolicies() noexcept
{
	// 両集合の内部整合とidentity衝突を検証してから解決を許可する。
	if( !validateOfficialSourcePolicies( BUILT_IN_POLICIES, builtInProviderDescriptors()) ||
	   !validateOfficialSourcePolicies( DEVELOPMENT_POLICIES, DEVELOPMENT_PROVIDERS)) {
		return false ;
	}

	// 開発IDを製品側へ重複登録し、同じ証拠を二用途へ転用しない。
	for( const auto &policy : BUILT_IN_POLICIES) {
		// PolicyとProviderのいずれかが重なれば全体を拒否する。
		if( policy.id == INTEL_DOWNLOAD_DEVELOPMENT_POLICY_ID ||
		   policy.providerId == INTEL_DOWNLOAD_DEVELOPMENT_PROVIDER_ID) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_source_policy.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::span<const std::wstring_view> officialSourceHosts( const std::wstring_view providerId,
													   const std::wstring_view resourceId) noexcept
{
	// Registry全体がProvider定義と不一致の場合は部分的なhost解決も許可しない。
	if( !validateBuiltInOfficialSourcePolicies()) {
		return {} ;
	}

	const OfficialSourcePolicy *const policy =
		// Providerの組み込みpolicy。
		officialSourcePolicyForProvider( providerId) ;
	// 登録されていないpolicyには空の許可host集合を返し、既定hostへfallbackしない。
	if( policy == nullptr) {
		return {} ;
	}

	const OfficialSourceResourcePolicy *const resource =
		// 用途別resource policy。
		findOfficialSourceResource( *policy, resourceId) ;
	return resource == nullptr ? std::span<const std::wstring_view>{} : resource->allowedHosts ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_source_policy.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isValidOfficialSourceEvidence( const OfficialSourceEvidence &evidence) noexcept
{
	// 不整合registryを根拠として候補を後段へ渡さない。
	if( !validateBuiltInOfficialSourcePolicies()) {
		return false ;
	}

	// 取得操作とscanの対応を特定できない根拠は、公式取得済みとして受理しない。
	if( evidence.scanSessionId == 0U || evidence.acquisitionId == 0U ||
	   evidence.providerId.empty() || evidence.policyId.empty() || evidence.resourceId.empty()) {
		return false ;
	}

	const bool orderedTimes = !evidence.bodyAcquiredUtcSeconds ||
							  !evidence.originValidatedUtcSeconds ||
							  evidence.bodyAcquiredUtcSeconds.value() <=
								  // 両時刻がある場合の時間順序。
								  evidence.originValidatedUtcSeconds.value() ;
	// 一resourceの実取得経路と時刻・cache許可の組合せを曖昧な値として受理しない。
	switch( evidence.acquisition) {
		// 旧adapterの未接続値は時刻を伴わない場合だけ有効な根拠として残す。
		case MeasurementAcquisition::UNKNOWN:
			// 未接続根拠に時刻またはcache方針が混在する矛盾を拒否する。
			if( evidence.bodyAcquiredUtcSeconds || evidence.originValidatedUtcSeconds ||
			   evidence.cachePermitted) {
				return false ;
			}

			break ;

		// Network本文は本文取得とorigin検証の両時刻を要求する。
		case MeasurementAcquisition::NETWORK_BODY:
			// 本文とoriginの両時刻がなく、または順序が逆転したnetwork根拠を拒否する。
			if( !evidence.bodyAcquiredUtcSeconds || !evidence.originValidatedUtcSeconds ||
			   !orderedTimes) {
				return false ;
			}

			break ;

		// Fresh cacheは過去のorigin検証時刻を持つが、今回の本文取得時刻を捏造しない。
		case MeasurementAcquisition::FRESH_CACHE:
			// Cache許可と過去のorigin検証時刻が揃わないfresh cache根拠を拒否する。
			if( evidence.bodyAcquiredUtcSeconds || !evidence.originValidatedUtcSeconds ||
			   !evidence.cachePermitted) {
				return false ;
			}

			break ;

		// 304は今回のorigin再検証時刻を持ち、元本文取得時刻が不明なら空のままにする。
		case MeasurementAcquisition::REVALIDATED_CACHE:
			// Cache許可と今回のorigin再検証時刻が揃わない304根拠を拒否する。
			if( evidence.bodyAcquiredUtcSeconds || !evidence.originValidatedUtcSeconds ||
			   !evidence.cachePermitted) {
				return false ;
			}

			break ;

		// 混在は複数resource集計専用、非該当は公式HTTP取得一件の根拠にしない。
		case MeasurementAcquisition::MIXED:
			return false ;

		// 非HTTP区分を公式source evidence一件の取得根拠として受理しない。
		case MeasurementAcquisition::NOT_APPLICABLE:
			return false ;
	}

	const OfficialSourcePolicy *const policy =
		// Evidenceが指定するpolicy。
		findOfficialSourcePolicy( evidence.policyId) ;
	// 取得根拠を別Providerのpolicyへ付け替える通知を拒否する。
	if( policy == nullptr || policy->providerId != evidence.providerId) {
		return false ;
	}

	const OfficialSourceResourcePolicy *const resource =
		// Evidenceのresource。
		findOfficialSourceResource( *policy, evidence.resourceId) ;
	// resourceとredirect回数、経路の件数が一致しない取得根拠を拒否する。
	if( resource == nullptr || evidence.redirectCount > resource->maximumRedirects ||
	   evidence.originPolicyIndices.empty() ||
	   evidence.originPolicyIndices.size() !=
		   static_cast<std::size_t>( evidence.redirectCount) + 1U) {
		return false ;
	}

	// originIndexはopaque経路内で現在照合する組み込みorigin位置である。
	for( const std::uint32_t originIndex : evidence.originPolicyIndices) {
		// allowlist外を指すorigin indexを拒否し、記録だけで許可hostを拡張させない。
		if( originIndex >= resource->allowedHosts.size()) {
			return false ;
		}
	}

	return true ;
}

} // namespace drivercrate
