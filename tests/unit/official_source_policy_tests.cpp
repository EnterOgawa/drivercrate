//------------------------------------------------------------------------------
/**
 * @file official_source_policy_tests.cpp
 * @brief 公式取得元policy registry単体試験実装。
 * @version 01.01.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  非cache modeでも公式境界を維持する試験。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  ASIXの三用途・単一host・redirect禁止を照合。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernetの取得前提確認と選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Focusrite製品page policy試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Wacom Windows policy試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Ricoh PCL6 policy試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  NVIDIA WinOF-2 policy試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  ASIX AX88179A policy試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Intel Ethernet Server policy試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  共通配布情報とIntel公式検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  NetXtreme-E表示専用検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公式2経路とfamily別予算を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  CP210x公式取得とserial共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  公式serial取得と新版受入境界を更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  HTTP取得根拠session試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Opaque origin経路試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  AMD公式host policy試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASUS公式host policy試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASRock公式host policy試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  ASRock landing起点試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  実HTTP取得経路と時刻の拒否条件を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/15  Windows 11 Ethernet取得元件数を検証。
 * Ver.01.01.00 Shunji Ogawa  2026/10/15  Payload媒体型と単一UTF-8 charsetの正負を追加。
 * </pre>
 *
 * @note 公式originをruntime入力から追加せず、用途別hostとProviderを完全一致で解決する境界をnetworkへ接続せず検証します。
 */
//------------------------------------------------------------------------------

#include "official_source_policy_tests.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/official_http_client.h"
#include "test_framework.h"

#include <algorithm>
#include <array>
#include <span>
#include <string>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
/**
 * @brief 組み込みorigin policyとProvider対応を検証する。
 *
 * 全公式network Providerが一意な組み込みpolicyを持ち、local Providerがpolicyを持たないことを確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testBuiltInPolicies( TestContext &context)
{
	const std::span policies  = builtInOfficialSourcePolicies() ;	// 組み込みorigin policy群。
	const std::span providers = builtInProviderDescriptors() ;		// 組み込みProvider群。
	DRIVERCRATE_EXPECT( context, policies.size() == 22U) ;
	DRIVERCRATE_EXPECT( context, validateBuiltInOfficialSourcePolicies()) ;
	DRIVERCRATE_EXPECT( context, validateOfficialSourcePolicies( policies, providers)) ;

	std::size_t officialProviderCount{} ;	// OfficialNetwork capabilityを持つProvider数。
	// 全Providerのpolicy有無がcapabilityと一致することを確認する。
	for( const ProviderDescriptor &provider : providers) {
		const bool official =
			(provider.capabilities & capabilityMask( ProviderCapability::OFFICIAL_NETWORK)) !=
			0U ;	// 公式network Providerの場合true。
		const OfficialSourcePolicy *const policy =
			// Provider対応policy。
			officialSourcePolicyForProvider( provider.id) ;
		// 公式network Providerだけを数え、対応する取得元policyの登録を要求する。
		if( official) {
			++officialProviderCount ;
			DRIVERCRATE_EXPECT( context, policy != nullptr) ;
			DRIVERCRATE_EXPECT( context, !provider.officialSourcePolicyId.empty()) ;
			DRIVERCRATE_EXPECT( context,
							   policy != nullptr && policy->id == provider.officialSourcePolicyId) ;
		} else {
			DRIVERCRATE_EXPECT( context, policy == nullptr) ;
			DRIVERCRATE_EXPECT( context, provider.officialSourcePolicyId.empty()) ;
		}
	}

	DRIVERCRATE_EXPECT( context, officialProviderCount == policies.size()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 用途別host allowlistの最小境界を検証する。
 *
 * Metadataとpayloadを別resourceとして解決し、未知IDで空にfail-closedすることを確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testResourceHosts( TestContext &context)
{
	const std::span nvidiaLookup = officialSourceHosts(
		NVIDIA_PROVIDER_ID, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ;	// NVIDIA製品lookup host。
	const std::span nvidiaRelease = officialSourceHosts(
		NVIDIA_PROVIDER_ID, OFFICIAL_SECONDARY_METADATA_RESOURCE_ID) ;	// NVIDIA release host。
	const std::span nvidiaPayload = officialSourceHosts(
		NVIDIA_PROVIDER_ID, OFFICIAL_PAYLOAD_RESOURCE_ID) ;	// NVIDIA payload domain。
	DRIVERCRATE_EXPECT( context, nvidiaLookup.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, nvidiaLookup[0] == L"www.nvidia.com") ;
	DRIVERCRATE_EXPECT( context, nvidiaRelease.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, nvidiaRelease[0] == L"gfwsl.geforce.com") ;
	DRIVERCRATE_EXPECT( context, nvidiaPayload.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, nvidiaPayload[0] == L".download.nvidia.com") ;

	const std::span hpMetadata = officialSourceHosts(
		HP_PROVIDER_ID, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ;	// HP metadata host。
	const std::span hpPayload =
		// HP payload host。
		officialSourceHosts( HP_PROVIDER_ID, OFFICIAL_PAYLOAD_RESOURCE_ID) ;
	DRIVERCRATE_EXPECT( context, hpMetadata.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, hpMetadata[0] == L"hpia.hpcloud.hp.com") ;
	DRIVERCRATE_EXPECT( context, hpPayload.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, hpPayload[0] == L"ftp.hp.com") ;

	const std::span vaioPayload = officialSourceHosts(
		VAIO_PROVIDER_ID, OFFICIAL_PAYLOAD_RESOURCE_ID) ;	// VAIO payload host群。
	DRIVERCRATE_EXPECT( context, vaioPayload.size() == 2U) ;
	DRIVERCRATE_EXPECT( context, vaioPayload[0] == L"dlcdnglobal.support.vaio.com") ;
	DRIVERCRATE_EXPECT( context, vaioPayload[1] == L"dlcdn2.support.vaio.com") ;

	const std::span amdPrimary = officialSourceHosts(
		AMD_PROVIDER_ID, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ;	// AMD製品一覧host。
	const std::span amdSecondary = officialSourceHosts(
		AMD_PROVIDER_ID, OFFICIAL_SECONDARY_METADATA_RESOURCE_ID) ;	// AMD製品page host。
	const std::span amdPayload =
		// 未取得payload host。
		officialSourceHosts( AMD_PROVIDER_ID, OFFICIAL_PAYLOAD_RESOURCE_ID) ;
	DRIVERCRATE_EXPECT( context, amdPrimary.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, amdPrimary[0] == L"www.amd.com") ;
	DRIVERCRATE_EXPECT( context, amdSecondary.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, amdSecondary[0] == L"www.amd.com") ;
	DRIVERCRATE_EXPECT( context, amdPayload.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, amdPayload[0] == L"drivers.amd.com") ;

	const std::span asusMetadata = officialSourceHosts(
		ASUS_PROVIDER_ID, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ;	// ASUS製品別page host。
	const std::span asusPayload =
		// ASUS CDN host。
		officialSourceHosts( ASUS_PROVIDER_ID, OFFICIAL_PAYLOAD_RESOURCE_ID) ;
	DRIVERCRATE_EXPECT( context, asusMetadata.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, asusMetadata[0] == L"www.asus.com") ;
	DRIVERCRATE_EXPECT( context, asusPayload.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, asusPayload[0] == L"dlcdnets.asus.com") ;

	const std::span asrockLanding = officialSourceHosts(
		ASROCK_PROVIDER_ID, OFFICIAL_LANDING_RESOURCE_ID) ;	// ASRock公式landing host。
	const std::span asrockMetadata = officialSourceHosts(
		ASROCK_PROVIDER_ID, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ;	// ASRock固定一覧host。
	DRIVERCRATE_EXPECT( context, asrockLanding.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, asrockLanding[0] == L"www.asrock.com") ;
	DRIVERCRATE_EXPECT( context, asrockMetadata.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, asrockMetadata[0] == L"www.asrock.com") ;
	DRIVERCRATE_EXPECT(
		context, officialSourceHosts( ASROCK_PROVIDER_ID, OFFICIAL_PAYLOAD_RESOURCE_ID).empty()) ;

	const std::span intelEthernetLanding =
		officialSourceHosts( INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID,
							OFFICIAL_LANDING_RESOURCE_ID) ;	// Intel Server 2025固定page host。
	DRIVERCRATE_EXPECT( context, intelEthernetLanding.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, intelEthernetLanding[0] == L"www.intel.com") ;
	const std::span intelEthernetPayload =
		officialSourceHosts( INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID,
							OFFICIAL_PAYLOAD_RESOURCE_ID) ;	// 承認対象ZIP host。
	DRIVERCRATE_EXPECT( context, intelEthernetPayload.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( intelEthernetPayload.size() == 1U) {
		DRIVERCRATE_EXPECT( context, intelEthernetPayload[0] == L"downloadmirror.intel.com") ;
	}

	const std::span intelWindows11Landing =
		officialSourceHosts( INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID,
							OFFICIAL_LANDING_RESOURCE_ID) ;	// Intel record 727998固定page host。
	DRIVERCRATE_EXPECT( context, intelWindows11Landing.size() == 1U) ;
	// Hostを取得できた場合だけ完全一致値を確認する。
	if( intelWindows11Landing.size() == 1U) {
		DRIVERCRATE_EXPECT( context, intelWindows11Landing[0] == L"www.intel.com") ;
	}

	const std::span intelWindows11Payload =
		officialSourceHosts( INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID,
							OFFICIAL_PAYLOAD_RESOURCE_ID) ;	// Record限定grantが参照するZIP host。
	DRIVERCRATE_EXPECT( context, intelWindows11Payload.size() == 1U) ;
	// Hostを取得できた場合だけ完全一致値を確認する。
	if( intelWindows11Payload.size() == 1U) {
		DRIVERCRATE_EXPECT( context, intelWindows11Payload[0] == L"downloadmirror.intel.com") ;
	}

	DRIVERCRATE_EXPECT( context,
					   officialMetadataEndpoint( INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID,
												OFFICIAL_LANDING_RESOURCE_ID) ==
						   L"https://www.intel.com/content/www/us/en/download/727998/"
						   L"intel-network-adapter-driver-for-microsoft-windows-11.html") ;

	const OfficialSourcePolicy *const intelPolicy = officialSourcePolicyForProvider(
		INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID) ;	// Payload redirectを許可しないpolicy。
	DRIVERCRATE_EXPECT( context, intelPolicy != nullptr) ;
	// Intelのpolicyが取得できた場合にだけpayload用途の制限を検証する。
	if( intelPolicy != nullptr) {
		const OfficialSourceResourcePolicy *const resource = findOfficialSourceResource(
			*intelPolicy, OFFICIAL_PAYLOAD_RESOURCE_ID) ;	// 固定payload用途。
		DRIVERCRATE_EXPECT( context, resource != nullptr) ;
		// payload resourceが取得できた場合にだけredirect禁止を検証する。
		if( resource != nullptr) {
			DRIVERCRATE_EXPECT( context, resource->maximumRedirects == 0U) ;
		}
	}

	const std::span asixLanding = officialSourceHosts(
		ASIX_AX88179A_PROVIDER_ID, OFFICIAL_LANDING_RESOURCE_ID) ;	// AX88179A固定page host。
	DRIVERCRATE_EXPECT( context, asixLanding.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, asixLanding[0] == L"www.asix.com.tw") ;
	const OfficialSourcePolicy *const asixPolicy =
		// 二pageと選択取得のpolicy。
		officialSourcePolicyForProvider( ASIX_AX88179A_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, asixPolicy != nullptr) ;
	// ASIXのpolicyが取得できた場合にだけ三用途のhost境界を検証する。
	if( asixPolicy != nullptr) {
		DRIVERCRATE_EXPECT( context, asixPolicy->id == L"asix-ax88179a-origin-v2") ;
		DRIVERCRATE_EXPECT( context, asixPolicy->resources.size() == 3U) ;
		// 各用途のhostを完全一致で固定し、redirectを許可していないことを確認する。
		for( const OfficialSourceResourcePolicy &resource : asixPolicy->resources) {
			DRIVERCRATE_EXPECT( context, resource.allowedHosts.size() == 1U) ;
			// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
			if( resource.allowedHosts.size() == 1U) {
				DRIVERCRATE_EXPECT( context, resource.allowedHosts.front() == L"www.asix.com.tw") ;
			}

			DRIVERCRATE_EXPECT( context, resource.maximumRedirects == 0U) ;
		}

		DRIVERCRATE_EXPECT(
			context, findOfficialSourceResource( *asixPolicy,
												OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) != nullptr) ;
		DRIVERCRATE_EXPECT( context, findOfficialSourceResource(
										*asixPolicy, OFFICIAL_PAYLOAD_RESOURCE_ID) != nullptr) ;
	}

	const std::span ricohLanding = officialSourceHosts(
		RICOH_UNIVERSAL_PRINT_PROVIDER_ID, OFFICIAL_LANDING_RESOURCE_ID) ;	// Ricoh固定page host。
	DRIVERCRATE_EXPECT( context, ricohLanding.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, ricohLanding[0] == L"support.ricoh.com") ;
	DRIVERCRATE_EXPECT( context, officialSourceHosts( RICOH_UNIVERSAL_PRINT_PROVIDER_ID,
													OFFICIAL_PAYLOAD_RESOURCE_ID)
									.empty()) ;

	const std::span wacomLanding = officialSourceHosts(
		WACOM_WINDOWS_PROVIDER_ID, OFFICIAL_LANDING_RESOURCE_ID) ;	// Wacom固定page host。
	DRIVERCRATE_EXPECT( context, wacomLanding.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, wacomLanding[0] == L"www.wacom.com") ;
	DRIVERCRATE_EXPECT(
		context,
		officialSourceHosts( WACOM_WINDOWS_PROVIDER_ID, OFFICIAL_PAYLOAD_RESOURCE_ID).empty()) ;

	const std::span focusriteLanding =
		officialSourceHosts( FOCUSRITE_SCARLETT2I2_PROVIDER_ID,
							OFFICIAL_LANDING_RESOURCE_ID) ;	// Focusrite固定製品page host。
	DRIVERCRATE_EXPECT( context, focusriteLanding.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, focusriteLanding[0] == L"downloads.focusrite.com") ;
	DRIVERCRATE_EXPECT( context, officialSourceHosts( FOCUSRITE_SCARLETT2I2_PROVIDER_ID,
													OFFICIAL_PAYLOAD_RESOURCE_ID)
									.empty()) ;

	const std::span nvidiaWinof2Landing = officialSourceHosts(
		NVIDIA_WINOF2_PROVIDER_ID, OFFICIAL_LANDING_RESOURCE_ID) ;	// NVIDIA製品page host。
	const std::span nvidiaWinof2Metadata = officialSourceHosts(
		NVIDIA_WINOF2_PROVIDER_ID, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ;	// 委譲metadata host。
	DRIVERCRATE_EXPECT( context, nvidiaWinof2Landing.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, nvidiaWinof2Landing[0] == L"network.nvidia.com") ;
	DRIVERCRATE_EXPECT( context, nvidiaWinof2Metadata.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, nvidiaWinof2Metadata[0] == L"downloaders.azurewebsites.net") ;
	DRIVERCRATE_EXPECT(
		context,
		officialSourceHosts( NVIDIA_WINOF2_PROVIDER_ID, OFFICIAL_PAYLOAD_RESOURCE_ID).empty()) ;

	DRIVERCRATE_EXPECT(
		context, officialSourceHosts( L"unknown-provider", OFFICIAL_PAYLOAD_RESOURCE_ID).empty()) ;
	DRIVERCRATE_EXPECT( context, officialSourceHosts( DELL_PROVIDER_ID, L"unknown-resource").empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不正なorigin policy構造を拒否することを検証する。
 *
 * Wildcard host、重複resource、redirect過大、capability不一致をnetwork request前に拒否する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testInvalidPolicies( TestContext &context)
{
	constexpr std::array<std::wstring_view, 1> VALID_HOSTS{
		L"downloads.example.test"} ;	// 正常な完全一致host。
	// Landingとpayloadを持つ正常なresource群。
	const std::array<OfficialSourceResourcePolicy, 2> validResources{
		OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
									 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
									 .allowedHosts	   = VALID_HOSTS,
									 .maximumRedirects = 0},
		OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
									 .kind			   = OfficialSourceResourceKind::PAYLOAD,
									 .allowedHosts	   = VALID_HOSTS,
									 .maximumRedirects = 1}} ;
	const std::array validProviders{
		ProviderDescriptor{.id				 = L"test-provider",
						   .displayName		 = L"Test official provider",
						   .capabilities	 = capabilityMask( ProviderCapability::OFFICIAL_NETWORK),
						   .selectionTier	 = ProviderSelectionTier::COMPONENT_OFFICIAL,
						   .discoveryBasis	 = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
						   .enabledByDefault = false,
						   .officialSourcePolicyId = L"test-policy"}} ;	// 対応Provider。
	const std::array validPolicies{
		OfficialSourcePolicy{.id		 = L"test-policy",
							 .providerId = L"test-provider",
							 .resources	 = validResources}} ;	// 正常なpolicy。
	DRIVERCRATE_EXPECT( context, validateOfficialSourcePolicies( validPolicies, validProviders)) ;

	// Landing page自体をmetadataとして読む表示専用Providerの正常なresource群。
	const std::array<OfficialSourceResourcePolicy, 1> landingOnlyResources{
		OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
									 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
									 .allowedHosts	   = VALID_HOSTS,
									 .maximumRedirects = 0}} ;
	const std::array landingOnlyPolicies{
		OfficialSourcePolicy{.id		 = L"test-policy",
							 .providerId = L"test-provider",
							 .resources	 = landingOnlyResources}} ;	// 表示専用の正常policy。
	DRIVERCRATE_EXPECT( context,
					   validateOfficialSourcePolicies( landingOnlyPolicies, validProviders)) ;

	constexpr std::array<std::wstring_view, 1> WILDCARD_HOSTS{
		L"*.example.test"} ;	// Wildcardを含む不正host。
	// 不正なwildcard hostをlandingへ設定したresource群。
	const std::array<OfficialSourceResourcePolicy, 2> wildcardResources{
		OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
									 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
									 .allowedHosts	   = WILDCARD_HOSTS,
									 .maximumRedirects = 0},
		OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
									 .kind			   = OfficialSourceResourceKind::PAYLOAD,
									 .allowedHosts	   = VALID_HOSTS,
									 .maximumRedirects = 0}} ;
	const std::array wildcardPolicies{
		OfficialSourcePolicy{.id		 = L"test-policy",
							 .providerId = L"test-provider",
							 .resources	 = wildcardResources}} ;	// 不正host policy。
	DRIVERCRATE_EXPECT( context, !validateOfficialSourcePolicies( wildcardPolicies, validProviders)) ;

	// 同じstable resource IDを二回使用するresource群。
	const std::array<OfficialSourceResourcePolicy, 2> duplicateResources{
		OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
									 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
									 .allowedHosts	   = VALID_HOSTS,
									 .maximumRedirects = 0},
		OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
									 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
									 .allowedHosts	   = VALID_HOSTS,
									 .maximumRedirects = 0}} ;
	const std::array duplicatePolicies{
		OfficialSourcePolicy{.id		 = L"test-policy",
							 .providerId = L"test-provider",
							 .resources	 = duplicateResources}} ;	// Resource ID重複policy。
	DRIVERCRATE_EXPECT( context, !validateOfficialSourcePolicies( duplicatePolicies, validProviders)) ;

	// Stable resource IDと用途が矛盾するresource群。
	const std::array<OfficialSourceResourcePolicy, 2> mismatchedKindResources{
		OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
									 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
									 .allowedHosts	   = VALID_HOSTS,
									 .maximumRedirects = 0},
		OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
									 .kind			   = OfficialSourceResourceKind::METADATA,
									 .allowedHosts	   = VALID_HOSTS,
									 .maximumRedirects = 0}} ;
	const std::array mismatchedKindPolicies{
		OfficialSourcePolicy{.id		 = L"test-policy",
							 .providerId = L"test-provider",
							 .resources	 = mismatchedKindResources}} ;	// 用途矛盾policy。
	DRIVERCRATE_EXPECT( context,
					   !validateOfficialSourcePolicies( mismatchedKindPolicies, validProviders)) ;

	// Application上限を超えるredirect回数を持つresource群。
	const std::array<OfficialSourceResourcePolicy, 2> excessiveRedirectResources{
		OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
									 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
									 .allowedHosts	   = VALID_HOSTS,
									 .maximumRedirects = 0},
		OfficialSourceResourcePolicy{.id			   = OFFICIAL_PAYLOAD_RESOURCE_ID,
									 .kind			   = OfficialSourceResourceKind::PAYLOAD,
									 .allowedHosts	   = VALID_HOSTS,
									 .maximumRedirects = 6}} ;
	const std::array excessiveRedirectPolicies{
		OfficialSourcePolicy{.id		 = L"test-policy",
							 .providerId = L"test-provider",
							 .resources	 = excessiveRedirectResources}} ;	// 上限超過policy。
	DRIVERCRATE_EXPECT( context,
					   !validateOfficialSourcePolicies( excessiveRedirectPolicies, validProviders)) ;

	// 列挙型の定義外用途を持つresource群。
	const std::array<OfficialSourceResourcePolicy, 2> invalidKindResources{
		OfficialSourceResourcePolicy{.id			   = OFFICIAL_LANDING_RESOURCE_ID,
									 .kind			   = OfficialSourceResourceKind::LANDING_PAGE,
									 .allowedHosts	   = VALID_HOSTS,
									 .maximumRedirects = 0},
		OfficialSourceResourcePolicy{.id		   = OFFICIAL_PAYLOAD_RESOURCE_ID,
									 .kind		   = static_cast<OfficialSourceResourceKind>( 99),
									 .allowedHosts = VALID_HOSTS,
									 .maximumRedirects = 0}} ;
	const std::array invalidKindPolicies{
		OfficialSourcePolicy{.id		 = L"test-policy",
							 .providerId = L"test-provider",
							 .resources	 = invalidKindResources}} ;	// 定義外用途を持つpolicy。
	DRIVERCRATE_EXPECT( context,
					   !validateOfficialSourcePolicies( invalidKindPolicies, validProviders)) ;

	const std::array nonNetworkProviders{
		ProviderDescriptor{.id				 = L"test-provider",
						   .displayName		 = L"Test local provider",
						   .capabilities	 = capabilityMask( ProviderCapability::LOCAL_INVENTORY),
						   .selectionTier	 = ProviderSelectionTier::LOCAL_INVENTORY,
						   .discoveryBasis	 = CandidateDiscoveryBasis::LOCAL_INVENTORY,
						   .enabledByDefault = false,
						   .officialSourcePolicyId = L"test-policy"}} ;	// Capability不一致。
	DRIVERCRATE_EXPECT( context,
					   !validateOfficialSourcePolicies( validPolicies, nonNetworkProviders)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Opaque取得根拠のsessionとpolicy境界を検証する。
 *
 * URLとhostを保持せず、既知IDとredirect上限だけで取得根拠をscan sessionへ拘束する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testSourceEvidence( TestContext &context)
{
	const OfficialSourceEvidence valid{
		.scanSessionId		 = 42,
		.acquisitionId		 = 1,
		.providerId			 = std::wstring( NVIDIA_PROVIDER_ID),
		.policyId			 = std::wstring( NVIDIA_OFFICIAL_SOURCE_POLICY_ID),
		.resourceId			 = std::wstring( OFFICIAL_PRIMARY_METADATA_RESOURCE_ID),
		.redirectCount		 = 0,
		.originPolicyIndices = {0U}} ;	// 登録済みpolicyとresourceに一致する根拠。
	DRIVERCRATE_EXPECT( context, isValidOfficialSourceEvidence( valid)) ;

	OfficialSourceEvidence invalid = valid ;	// 各拒否条件へ変更する取得根拠。
	invalid.scanSessionId		   = 0 ;
	DRIVERCRATE_EXPECT( context, !isValidOfficialSourceEvidence( invalid)) ;
	invalid				  = valid ;
	invalid.acquisitionId = 0 ;
	DRIVERCRATE_EXPECT( context, !isValidOfficialSourceEvidence( invalid)) ;
	invalid			   = valid ;
	invalid.providerId = std::wstring( DELL_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, !isValidOfficialSourceEvidence( invalid)) ;
	invalid			   = valid ;
	invalid.resourceId = L"unknown-resource" ;
	DRIVERCRATE_EXPECT( context, !isValidOfficialSourceEvidence( invalid)) ;
	invalid						= valid ;
	invalid.redirectCount		= 1 ;
	invalid.originPolicyIndices = {0U, 0U} ;
	DRIVERCRATE_EXPECT( context, !isValidOfficialSourceEvidence( invalid)) ;
	invalid = valid ;
	invalid.originPolicyIndices.clear() ;
	DRIVERCRATE_EXPECT( context, !isValidOfficialSourceEvidence( invalid)) ;
	invalid						= valid ;
	invalid.originPolicyIndices = {0U, 0U} ;
	DRIVERCRATE_EXPECT( context, !isValidOfficialSourceEvidence( invalid)) ;
	invalid						= valid ;
	invalid.originPolicyIndices = {1U} ;
	DRIVERCRATE_EXPECT( context, !isValidOfficialSourceEvidence( invalid)) ;

	OfficialSourceEvidence network	  = valid ;	// 今回取得したnetwork本文の実経路。
	network.acquisition				  = MeasurementAcquisition::NETWORK_BODY ;
	network.bodyAcquiredUtcSeconds	  = 100U ;
	network.originValidatedUtcSeconds = 101U ;
	DRIVERCRATE_EXPECT( context, isValidOfficialSourceEvidence( network)) ;
	OfficialSourceEvidence fresh	= valid ;	// 保存時のorigin検証時刻を伴うfresh cache。
	fresh.acquisition				= MeasurementAcquisition::FRESH_CACHE ;
	fresh.originValidatedUtcSeconds = 90U ;
	fresh.cachePermitted			= true ;
	DRIVERCRATE_EXPECT( context, isValidOfficialSourceEvidence( fresh)) ;
	OfficialSourceEvidence revalidated = fresh ;	// 304で今回再検証したcache本文。
	revalidated.acquisition			   = MeasurementAcquisition::REVALIDATED_CACHE ;
	DRIVERCRATE_EXPECT( context, isValidOfficialSourceEvidence( revalidated)) ;
	invalid							  = network ;
	invalid.originValidatedUtcSeconds = 99U ;
	DRIVERCRATE_EXPECT( context, !isValidOfficialSourceEvidence( invalid)) ;
	invalid						   = fresh ;
	invalid.bodyAcquiredUtcSeconds = 80U ;
	DRIVERCRATE_EXPECT( context, !isValidOfficialSourceEvidence( invalid)) ;
	invalid				   = valid ;
	invalid.cachePermitted = true ;
	DRIVERCRATE_EXPECT( context, !isValidOfficialSourceEvidence( invalid)) ;
	invalid				= valid ;
	invalid.acquisition = MeasurementAcquisition::MIXED ;
	DRIVERCRATE_EXPECT( context, !isValidOfficialSourceEvidence( invalid)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief HTTP clientの取得根拠session境界を検証する。
 *
 * 未知Providerとresource用途違反をnetwork request前に拒否し、session失効時にledgerを破棄することを確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testHttpSourceSession( TestContext &context)
{
	OfficialHttpClient client ;	// 取得根拠session境界の検査対象。
	NativeError		   error =
		// 組み込みProvider開始結果。
		client.beginSourceSession( 17U, NVIDIA_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, error == 0) ;
	DRIVERCRATE_EXPECT( context, client.sourceEvidence().empty()) ;
	DRIVERCRATE_EXPECT(
		context, !client.hasSourceEvidence( 17U, NVIDIA_PROVIDER_ID, OFFICIAL_PAYLOAD_RESOURCE_ID)) ;

	std::wstring text{L"unchanged"} ;	// 拒否時に破棄される出力文字列。
	error = client.getUtf8TextForSource( L"https://download.nvidia.com/sample",
										OFFICIAL_PAYLOAD_RESOURCE_ID, 1U, text) ;
	DRIVERCRATE_EXPECT( context, error == static_cast<NativeError>( E_ACCESSDENIED)) ;
	DRIVERCRATE_EXPECT( context, text.empty()) ;
	DRIVERCRATE_EXPECT( context, client.sourceEvidence().empty()) ;

	// 未知Provider開始結果。
	error = client.beginSourceSession( 18U, L"unknown-provider") ;
	DRIVERCRATE_EXPECT( context, error == static_cast<NativeError>( E_ACCESSDENIED)) ;
	DRIVERCRATE_EXPECT( context, client.sourceEvidence().empty()) ;

	// 次session開始結果。
	error = client.beginSourceSession( 19U, VAIO_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, error == 0) ;
	client.invalidateSourceSession() ;
	DRIVERCRATE_EXPECT( context, client.sourceEvidence().empty()) ;
	DRIVERCRATE_EXPECT( context, !client.hasSourceEvidence( 19U, VAIO_PROVIDER_ID,
														  OFFICIAL_PRIMARY_METADATA_RESOURCE_ID)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Cache無効化が公式origin・HTTPS・応答上限を回避しないことを検証する。入力拒否だけを使い、実HTTPとcache I/Oを呼ばない。
 *
 * @param[in,out] context 決定的assertionの集計先。
 */
//------------------------------------------------------------------------------
void testCatalogCacheModes( TestContext &context)
{
	const OfficialHttpClient defaultClient ;	// 既定の通常検索設定を確認するclient。
	DRIVERCRATE_EXPECT( context, defaultClient.usesCatalogCache()) ;
	// 通常検索と非cache検証の両modeで、network前の拒否境界を照合する。
	for( const bool useCache : {true, false})	// 今回確認するcache利用設定。
	{
		OfficialHttpClient client( useCache) ;	// Modeを固定した独立の取得根拠session。
		DRIVERCRATE_EXPECT( context, client.usesCatalogCache() == useCache) ;
		DRIVERCRATE_EXPECT( context, client.beginSourceSession( 1U, NVIDIA_PROVIDER_ID) == 0) ;
		std::wstring output = L"stale" ;	// 拒否時の古い本文混入を検出する出力。
		DRIVERCRATE_EXPECT( context, client.getUtf8TextForSource(
										L"https://example.invalid/catalog",
										OFFICIAL_PRIMARY_METADATA_RESOURCE_ID, 1024U, output) != 0) ;
		DRIVERCRATE_EXPECT( context, output.empty()) ;
		DRIVERCRATE_EXPECT( context, client.getUtf8TextForSource(
										L"http://www.nvidia.com/catalog",
										OFFICIAL_PRIMARY_METADATA_RESOURCE_ID, 1024U, output) != 0) ;
		DRIVERCRATE_EXPECT( context, client.getUtf8TextForSource(
										L"https://www.nvidia.com/catalog",
										OFFICIAL_PRIMARY_METADATA_RESOURCE_ID, 0U, output) != 0) ;
		DRIVERCRATE_EXPECT( context, client.sourceEvidence().empty()) ;
		client.invalidateSourceSession() ;
		DRIVERCRATE_EXPECT( context, client.usesCatalogCache() == useCache) ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_source_policy_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOfficialSourcePolicyTests( TestContext &context)
{
	// 公式ZIPに付く単一UTF-8 charsetを本文非変換で受理し、型・構文の不一致を拒否します。
	DRIVERCRATE_EXPECT( context,
					   matchesOfficialPayloadContentType( L"application/zip", L"application/zip")) ;
	DRIVERCRATE_EXPECT( context, matchesOfficialPayloadContentType( L"application/zip; charset=UTF-8",
																  L"application/zip")) ;
	DRIVERCRATE_EXPECT( context, matchesOfficialPayloadContentType(
									L"application/zip;charset=\"utf-8\"", L"application/zip")) ;
	DRIVERCRATE_EXPECT(
		context, !matchesOfficialPayloadContentType( L"application/octet-stream; charset=utf-8",
													L"application/zip")) ;
	DRIVERCRATE_EXPECT( context, !matchesOfficialPayloadContentType(
									L"application/zipx; charset=utf-8", L"application/zip")) ;
	DRIVERCRATE_EXPECT( context,
					   !matchesOfficialPayloadContentType( L"application/zip;", L"application/zip")) ;
	DRIVERCRATE_EXPECT( context, !matchesOfficialPayloadContentType(
									L"application/zip; boundary=utf-8", L"application/zip")) ;
	DRIVERCRATE_EXPECT( context, !matchesOfficialPayloadContentType(
									L"application/zip; charset=iso-8859-1", L"application/zip")) ;
	DRIVERCRATE_EXPECT( context, !matchesOfficialPayloadContentType(
									L"application/zip; charset=\"utf-8", L"application/zip")) ;
	DRIVERCRATE_EXPECT( context,
					   !matchesOfficialPayloadContentType(
						   L"application/zip; charset=utf-8; charset=utf-8", L"application/zip")) ;
	DRIVERCRATE_EXPECT( context, !matchesOfficialPayloadContentType(
									L"application/zip,application/zip", L"application/zip")) ;
	DRIVERCRATE_EXPECT( context,
					   !matchesOfficialPayloadContentType(
						   L"application/zip; charset=utf-8,application/zip", L"application/zip")) ;
	DRIVERCRATE_EXPECT(
		context, !matchesOfficialPayloadContentType( L"application/zip\r\nX:1", L"application/zip")) ;
	DRIVERCRATE_EXPECT( context, !matchesOfficialPayloadContentType(
									L"application/zip; charset=utf-8\n", L"application/zip")) ;
	DRIVERCRATE_EXPECT( context, !matchesOfficialPayloadContentType( L"application/zip", L"")) ;
	DRIVERCRATE_EXPECT(
		context, !matchesOfficialPayloadContentType( std::wstring( 257U, L'a'), L"application/zip")) ;
	testBuiltInPolicies( context) ;
	testResourceHosts( context) ;
	testInvalidPolicies( context) ;
	testSourceEvidence( context) ;
	testHttpSourceSession( context) ;
	testCatalogCacheModes( context) ;
}

} // namespace drivercrate::test
