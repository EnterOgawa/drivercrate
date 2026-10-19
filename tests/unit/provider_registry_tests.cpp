//------------------------------------------------------------------------------
/**
 * @file provider_registry_tests.cpp
 * @brief Provider registry単体試験実装。
 * @version 01.05.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  ASIXのDownload能力とInstall無効を照合。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Registry検証loopの目的を明示。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel Ethernet導入能力の期待値を更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Install注意種別の登録試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernetの取得前提確認と選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Focusrite表示検索登録試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Wacom Windows登録試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Ricoh PCL6登録試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  NVIDIA表示専用capability試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  NVIDIA WinOF-2登録試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  ASIX AX88179A登録試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Intel Ethernet Server登録試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Broadcom導入capability試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  共通配布情報とIntel公式検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  NetXtreme-E表示専用検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公式2経路とfamily別予算を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  CP210x公式取得とserial共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  公式serial取得と新版受入境界を更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  既定取得元優先段階試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Coverage整合性試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Lenovo Provider登録試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  HP Provider登録試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  VAIO Provider登録試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Dell PowerEdge登録試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Provider探索経路試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  利用者選択file設定試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Prolific区分C登録試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  WCH区分C登録試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  WCH CH342／CH343系登録試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Silicon Labs区分C登録試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASUS routing capability試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  汎用署名済みINF登録試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  監査段階別scan状態試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  AMD表示専用Provider試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Scan成功／拒否矛盾試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Provider outcome矛盾試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASUS段階Provider登録試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASRock表示専用Provider試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * Ver.01.00.02 Shunji Ogawa  2026/09/15  Windows 11 Ethernet検索Providerを検証。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Windows 11固定root自動探索能力を検証。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  一scan承認のscope・予算・新旧排他試験を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  公式探索の通信・payload未承認状態を検証。
 * Ver.01.04.00 Shunji Ogawa  2026/10/12  真署名索引から共通取得・検査と拒否の内部fixtureを追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.05.01 Shunji Ogawa  2026/10/12  通常索引の指定導入を含むINSTALL登録22件を確認。
 * </pre>
 *
 * @note 端末情報やnetworkを使用せずProvider設定のfail-closed条件を試験します。
 */
//------------------------------------------------------------------------------

#include "provider_registry_tests.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "test_framework.h"

#include <algorithm>
#include <unordered_set>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
/**
 * @brief 組み込みProvider定義の一意性と必須capabilityを検証する。
 *
 * Stable ID、表示名、Scan capability、既定有効を確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testDescriptors( TestContext &context)
{
	const std::span descriptors = builtInProviderDescriptors() ;	// Registry試験対象。
	DRIVERCRATE_EXPECT( context, descriptors.size() == 31U) ;
	// 到達可能な実device数とは区別し、導入能力を宣言するstable Provider ID数を集計する。
	const auto installProviderCount =
		std::ranges::count_if( descriptors, []( const ProviderDescriptor &descriptor) {
			return (descriptor.capabilities & capabilityMask( ProviderCapability::INSTALL)) != 0U ;
		}) ;
	DRIVERCRATE_EXPECT( context, installProviderCount == 22) ;
	std::unordered_set<std::wstring> ids ;	// Stable ID重複検出集合。
	// 全組み込みProviderの必須metadata、stable ID一意性、能力、注意種別を確認する。
	for( const ProviderDescriptor &descriptor : descriptors) {
		DRIVERCRATE_EXPECT( context, !descriptor.id.empty()) ;
		DRIVERCRATE_EXPECT( context, !descriptor.displayName.empty()) ;
		DRIVERCRATE_EXPECT( context, ids.insert( descriptor.id).second) ;
		DRIVERCRATE_EXPECT(
			context, (descriptor.capabilities & capabilityMask( ProviderCapability::SCAN)) != 0) ;
		DRIVERCRATE_EXPECT( context,
						   descriptor.discoveryBasis != CandidateDiscoveryBasis::UNSPECIFIED) ;
		const InstallNoticeKind expectedNotice =	// 固定Provider別の最終確認注意種別。
			descriptor.id == INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID
				? InstallNoticeKind::INTEL_ETHERNET_SERVER
				: (descriptor.id == ASIX_AX88179A_PROVIDER_ID ? InstallNoticeKind::ASIX_CLIENT_NIC
															  : InstallNoticeKind::NONE) ;
		DRIVERCRATE_EXPECT( context, descriptor.installNotice == expectedNotice) ;
		const bool defaultDisabled =	// 利用者入力または監査完了待ちで既定無効のProvider。
			descriptor.id == INTEL_WIRELESS_PACKAGE_PROVIDER_ID ||
			descriptor.id == PROLIFIC_SERIAL_PACKAGE_PROVIDER_ID ||
			descriptor.id == SILICON_LABS_SERIAL_PACKAGE_PROVIDER_ID ||
			descriptor.id == WCH_SERIAL_PACKAGE_PROVIDER_ID ||
			descriptor.id == WCH_MULTI_SERIAL_PACKAGE_PROVIDER_ID ||
			descriptor.id == GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID ||
			descriptor.id == ASUS_PROVIDER_ID || descriptor.id == ASROCK_PROVIDER_ID ||
			descriptor.id == PROLIFIC_OFFICIAL_PROVIDER_ID ||
			descriptor.id == SILICON_LABS_OFFICIAL_PROVIDER_ID ||
			descriptor.id == WCH_OFFICIAL_PROVIDER_ID ||
			descriptor.id == WCH_MULTI_OFFICIAL_PROVIDER_ID ||
			descriptor.id == BROADCOM_NET_XTREME_PROVIDER_ID ||
			descriptor.id == INTEL_WIFI_OFFICIAL_PROVIDER_ID ||
			descriptor.id == INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ||
			descriptor.id == INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID ||
			descriptor.id == ASIX_AX88179A_PROVIDER_ID ||
			descriptor.id == RICOH_UNIVERSAL_PRINT_PROVIDER_ID ||
			descriptor.id == WACOM_WINDOWS_PROVIDER_ID ||
			descriptor.id == FOCUSRITE_SCARLETT2I2_PROVIDER_ID ||
			descriptor.id == NVIDIA_WINOF2_PROVIDER_ID ;
		DRIVERCRATE_EXPECT( context, descriptor.enabledByDefault != defaultDisabled) ;
	}

	const auto *indexAcquisition =
		// 同じregistryの用途限定entry。
		signedIndexAcquisitionProviderDescriptor() ;
	DRIVERCRATE_EXPECT(
		context, indexAcquisition != nullptr && indexAcquisition->id == SIGNED_INDEX_PROVIDER_ID &&
					 indexAcquisition->enabledByDefault &&
					 indexAcquisition->officialSourcePolicyId.empty() &&
					 indexAcquisition->capabilities ==
						 (capabilityMask( ProviderCapability::SCAN) |
						  capabilityMask( ProviderCapability::INSTALL) |
						  capabilityMask( ProviderCapability::DOWNLOAD) |
						  capabilityMask( ProviderCapability::SIGNED_INDEX_ACQUISITION))) ;
	DRIVERCRATE_EXPECT( context,
					   findProviderDescriptor( SIGNED_INDEX_PROVIDER_ID) == indexAcquisition &&
						   findProviderDescriptor( L"unknown-index") == nullptr) ;
	ScanOptions acquisitionOnly ;	// 取得専用IDを通常scan能力へ昇格させない確認。
	acquisitionOnly.useDefaultProviders = false ;
	acquisitionOnly.enabledProviderIds.emplace_back( SIGNED_INDEX_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, validateScanOptions( acquisitionOnly)) ;

	DRIVERCRATE_EXPECT( context,
					   descriptors[0].selectionTier == ProviderSelectionTier::MANAGED_SERVICE) ;
	DRIVERCRATE_EXPECT( context,
					   descriptors[1].selectionTier == ProviderSelectionTier::LOCAL_INVENTORY) ;
	const ProviderCapabilityMask nvidiaExpectedCapabilities =	// NVIDIA表示専用の能力集合。
		capabilityMask( ProviderCapability::SCAN) | capabilityMask( ProviderCapability::HISTORY) |
		capabilityMask( ProviderCapability::OFFICIAL_NETWORK) ;
	DRIVERCRATE_EXPECT( context, descriptors[2].id == NVIDIA_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, descriptors[2].capabilities == nvidiaExpectedCapabilities) ;
	const auto broadcom = std::find_if( descriptors.begin(), descriptors.end(),
									   []( const ProviderDescriptor &descriptor) {
										   return descriptor.id == BROADCOM_NET_XTREME_PROVIDER_ID ;
									   }) ; // Broadcomの登録定義。
	DRIVERCRATE_EXPECT( context, broadcom != descriptors.end()) ;
	// Broadcom定義を取得できた場合にだけinstall capabilityを検証する。
	if( broadcom != descriptors.end()) {
		DRIVERCRATE_EXPECT(
			context, (broadcom->capabilities & capabilityMask( ProviderCapability::INSTALL)) != 0U) ;
	}

	const auto intelEthernet = std::find_if(
		descriptors.begin(), descriptors.end(), []( const ProviderDescriptor &descriptor) {
			return descriptor.id == INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ;
		}) ; // Server検索定義。
	DRIVERCRATE_EXPECT( context, intelEthernet != descriptors.end()) ;
	// Intel Ethernet定義を取得できた場合にだけ既定状態と取得元境界を検証する。
	if( intelEthernet != descriptors.end()) {
		DRIVERCRATE_EXPECT( context, !intelEthernet->enabledByDefault) ;
		DRIVERCRATE_EXPECT( context, intelEthernet->capabilities ==
										(capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) |
										 capabilityMask( ProviderCapability::SCAN) |
										 capabilityMask( ProviderCapability::DOWNLOAD) |
										 capabilityMask( ProviderCapability::INSTALL) |
										 capabilityMask( ProviderCapability::OFFICIAL_NETWORK))) ;
		DRIVERCRATE_EXPECT( context, intelEthernet->discoveryBasis ==
										CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE) ;
		DRIVERCRATE_EXPECT( context, intelEthernet->installNotice ==
										InstallNoticeKind::INTEL_ETHERNET_SERVER) ;
		DRIVERCRATE_EXPECT( context, (intelEthernet->capabilities &
									 capabilityMask( ProviderCapability::INSTALL)) != 0U) ;
	}

	const auto intelWindows11 = std::find_if(
		descriptors.begin(), descriptors.end(), []( const ProviderDescriptor &descriptor) {
			return descriptor.id == INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID ;
		}) ; // Windows 11表示検索定義。
	DRIVERCRATE_EXPECT( context, intelWindows11 != descriptors.end()) ;
	// 登録を取得できた場合だけ既定OFFと固定root探索能力を確認する。
	if( intelWindows11 != descriptors.end()) {
		DRIVERCRATE_EXPECT( context, !intelWindows11->enabledByDefault) ;
		DRIVERCRATE_EXPECT( context, intelWindows11->capabilities ==
										(capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) |
										 capabilityMask( ProviderCapability::SCAN) |
										 capabilityMask( ProviderCapability::OFFICIAL_NETWORK) |
										 capabilityMask( ProviderCapability::AUTOMATIC_DISCOVERY))) ;
		DRIVERCRATE_EXPECT( context, intelWindows11->discoveryBasis ==
										CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE) ;
		DRIVERCRATE_EXPECT( context, intelWindows11->officialSourcePolicyId ==
										INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID) ;
		DRIVERCRATE_EXPECT( context, (intelWindows11->capabilities &
									 capabilityMask( ProviderCapability::DOWNLOAD)) == 0U) ;
		DRIVERCRATE_EXPECT( context, (intelWindows11->capabilities &
									 capabilityMask( ProviderCapability::INSTALL)) == 0U) ;
	}

	const auto intelNotice =	// Stable IDから取得したIntel Server固有注意種別。
		providerInstallNotice( INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, intelNotice.has_value()) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( intelNotice.has_value()) {
		DRIVERCRATE_EXPECT( context, *intelNotice == InstallNoticeKind::INTEL_ETHERNET_SERVER) ;
	}

	DRIVERCRATE_EXPECT( context, !providerInstallNotice( L"unknown-provider").has_value()) ;
	const auto asix = std::find_if( descriptors.begin(), descriptors.end(),
								   []( const ProviderDescriptor &descriptor) {
									   return descriptor.id == ASIX_AX88179A_PROVIDER_ID ;
								   }) ; // ASIX検索定義。
	DRIVERCRATE_EXPECT( context, asix != descriptors.end()) ;
	// ASIX定義を取得できた場合にだけ専用注意区分とcapabilityを検証する。
	if( asix != descriptors.end()) {
		DRIVERCRATE_EXPECT( context, !asix->enabledByDefault) ;
		DRIVERCRATE_EXPECT( context, providerInstallNotice( ASIX_AX88179A_PROVIDER_ID) ==
										InstallNoticeKind::ASIX_CLIENT_NIC) ;
		DRIVERCRATE_EXPECT( context, asix->capabilities ==
										(capabilityMask( ProviderCapability::SCAN) |
										 capabilityMask( ProviderCapability::DOWNLOAD) |
										 capabilityMask( ProviderCapability::INSTALL) |
										 capabilityMask( ProviderCapability::OFFICIAL_NETWORK))) ;
		DRIVERCRATE_EXPECT( context,
						   asix->discoveryBasis == CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE) ;
	}

	const auto ricoh = std::find_if( descriptors.begin(), descriptors.end(),
									[]( const ProviderDescriptor &descriptor) {
										return descriptor.id == RICOH_UNIVERSAL_PRINT_PROVIDER_ID ;
									}) ; // Ricoh検索定義。
	DRIVERCRATE_EXPECT( context, ricoh != descriptors.end()) ;
	// Ricoh定義を取得できた場合にだけ表示専用の取得元境界を検証する。
	if( ricoh != descriptors.end()) {
		DRIVERCRATE_EXPECT( context, !ricoh->enabledByDefault) ;
		DRIVERCRATE_EXPECT( context, ricoh->capabilities ==
										(capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) |
										 capabilityMask( ProviderCapability::SCAN) |
										 capabilityMask( ProviderCapability::OFFICIAL_NETWORK))) ;
		DRIVERCRATE_EXPECT( context,
						   ricoh->discoveryBasis == CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE) ;
		DRIVERCRATE_EXPECT( context, ricoh->officialSourcePolicyId ==
										RICOH_UNIVERSAL_PRINT_OFFICIAL_SOURCE_POLICY_ID) ;
	}

	const auto wacom = std::find_if( descriptors.begin(), descriptors.end(),
									[]( const ProviderDescriptor &descriptor) {
										return descriptor.id == WACOM_WINDOWS_PROVIDER_ID ;
									}) ; // Wacom検索定義。
	DRIVERCRATE_EXPECT( context, wacom != descriptors.end()) ;
	// Wacom定義を取得できた場合にだけ表示専用の取得元境界を検証する。
	if( wacom != descriptors.end()) {
		DRIVERCRATE_EXPECT( context, !wacom->enabledByDefault) ;
		DRIVERCRATE_EXPECT( context, wacom->capabilities ==
										(capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) |
										 capabilityMask( ProviderCapability::SCAN) |
										 capabilityMask( ProviderCapability::OFFICIAL_NETWORK))) ;
		DRIVERCRATE_EXPECT( context,
						   wacom->discoveryBasis == CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE) ;
		DRIVERCRATE_EXPECT( context, wacom->officialSourcePolicyId ==
										WACOM_WINDOWS_OFFICIAL_SOURCE_POLICY_ID) ;
	}

	const auto focusrite = std::find_if(
		descriptors.begin(), descriptors.end(), []( const ProviderDescriptor &descriptor) {
			return descriptor.id == FOCUSRITE_SCARLETT2I2_PROVIDER_ID ;
		}) ; // Focusrite検索定義。
	DRIVERCRATE_EXPECT( context, focusrite != descriptors.end()) ;
	// Focusrite定義を取得できた場合にだけ表示専用の取得元境界を検証する。
	if( focusrite != descriptors.end()) {
		DRIVERCRATE_EXPECT( context, !focusrite->enabledByDefault) ;
		DRIVERCRATE_EXPECT( context, focusrite->capabilities ==
										(capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) |
										 capabilityMask( ProviderCapability::SCAN) |
										 capabilityMask( ProviderCapability::OFFICIAL_NETWORK))) ;
		DRIVERCRATE_EXPECT( context,
						   focusrite->discoveryBasis == CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE) ;
		DRIVERCRATE_EXPECT( context, focusrite->officialSourcePolicyId ==
										FOCUSRITE_SCARLETT2I2_OFFICIAL_SOURCE_POLICY_ID) ;
		DRIVERCRATE_EXPECT( context, (focusrite->capabilities &
									 capabilityMask( ProviderCapability::DOWNLOAD)) == 0U) ;
		DRIVERCRATE_EXPECT(
			context, (focusrite->capabilities & capabilityMask( ProviderCapability::INSTALL)) == 0U) ;
	}

	const auto nvidiaWinof2 = std::find_if( descriptors.begin(), descriptors.end(),
										   []( const ProviderDescriptor &descriptor) {
											   return descriptor.id == NVIDIA_WINOF2_PROVIDER_ID ;
										   }) ; // WinOF-2検索定義。
	DRIVERCRATE_EXPECT( context, nvidiaWinof2 != descriptors.end()) ;
	// NVIDIA WinOF-2定義を取得できた場合にだけ構造化catalog境界を検証する。
	if( nvidiaWinof2 != descriptors.end()) {
		DRIVERCRATE_EXPECT( context, !nvidiaWinof2->enabledByDefault) ;
		DRIVERCRATE_EXPECT( context, nvidiaWinof2->capabilities ==
										(capabilityMask( ProviderCapability::SCAN) |
										 capabilityMask( ProviderCapability::OFFICIAL_NETWORK))) ;
		DRIVERCRATE_EXPECT( context, nvidiaWinof2->discoveryBasis ==
										CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG) ;
		DRIVERCRATE_EXPECT( context, nvidiaWinof2->officialSourcePolicyId ==
										NVIDIA_WINOF2_OFFICIAL_SOURCE_POLICY_ID) ;
	}

	DRIVERCRATE_EXPECT( context,
					   descriptors[2].selectionTier == ProviderSelectionTier::COMPONENT_OFFICIAL) ;
	DRIVERCRATE_EXPECT( context,
					   descriptors[3].selectionTier == ProviderSelectionTier::OEM_OFFICIAL) ;
	DRIVERCRATE_EXPECT( context,
					   descriptors[4].selectionTier == ProviderSelectionTier::OEM_OFFICIAL) ;
	DRIVERCRATE_EXPECT( context,
					   descriptors[5].selectionTier == ProviderSelectionTier::OEM_OFFICIAL) ;
	DRIVERCRATE_EXPECT( context,
					   descriptors[6].selectionTier == ProviderSelectionTier::OEM_OFFICIAL) ;
	DRIVERCRATE_EXPECT( context,
					   descriptors[7].selectionTier == ProviderSelectionTier::OEM_OFFICIAL) ;
	DRIVERCRATE_EXPECT( context,
					   descriptors[8].selectionTier == ProviderSelectionTier::COMPONENT_OFFICIAL) ;
	DRIVERCRATE_EXPECT( context,
					   descriptors[9].selectionTier == ProviderSelectionTier::COMPONENT_OFFICIAL) ;
	DRIVERCRATE_EXPECT( context,
					   descriptors[10].selectionTier == ProviderSelectionTier::COMPONENT_OFFICIAL) ;
	DRIVERCRATE_EXPECT( context,
					   descriptors[11].selectionTier == ProviderSelectionTier::COMPONENT_OFFICIAL) ;
	DRIVERCRATE_EXPECT( context,
					   descriptors[12].selectionTier == ProviderSelectionTier::COMPONENT_OFFICIAL) ;
	DRIVERCRATE_EXPECT( context,
					   descriptors[13].selectionTier == ProviderSelectionTier::USER_PROVIDED) ;
	DRIVERCRATE_EXPECT( context,
					   descriptors[14].selectionTier == ProviderSelectionTier::COMPONENT_OFFICIAL) ;
	DRIVERCRATE_EXPECT( context,
					   descriptors[15].selectionTier == ProviderSelectionTier::OEM_OFFICIAL) ;
	DRIVERCRATE_EXPECT( context,
					   descriptors[16].selectionTier == ProviderSelectionTier::OEM_OFFICIAL) ;
	DRIVERCRATE_EXPECT( context,
					   descriptors[0].discoveryBasis == CandidateDiscoveryBasis::MANAGED_SERVICE) ;
	DRIVERCRATE_EXPECT( context,
					   descriptors[1].discoveryBasis == CandidateDiscoveryBasis::LOCAL_INVENTORY) ;
	// 構造化公式catalogとして登録する既存6 Providerの探索根拠を確認する。
	for( std::size_t index = 2; index < 8; ++index) {
		DRIVERCRATE_EXPECT( context, descriptors[index].discoveryBasis ==
										CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG) ;
	}

	DRIVERCRATE_EXPECT( context, descriptors[8].discoveryBasis ==
									CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE) ;
	DRIVERCRATE_EXPECT( context, (descriptors[8].capabilities &
								 capabilityMask( ProviderCapability::USER_SELECTED_FILE)) != 0) ;
	DRIVERCRATE_EXPECT( context, descriptors[9].discoveryBasis ==
									CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE) ;
	DRIVERCRATE_EXPECT( context, (descriptors[9].capabilities &
								 capabilityMask( ProviderCapability::USER_SELECTED_FILE)) != 0) ;
	DRIVERCRATE_EXPECT( context, descriptors[10].discoveryBasis ==
									CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE) ;
	DRIVERCRATE_EXPECT( context, (descriptors[10].capabilities &
								 capabilityMask( ProviderCapability::USER_SELECTED_FILE)) != 0) ;
	DRIVERCRATE_EXPECT( context, descriptors[11].discoveryBasis ==
									CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE) ;
	DRIVERCRATE_EXPECT( context, (descriptors[11].capabilities &
								 capabilityMask( ProviderCapability::USER_SELECTED_FILE)) != 0) ;
	DRIVERCRATE_EXPECT( context, descriptors[12].discoveryBasis ==
									CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE) ;
	DRIVERCRATE_EXPECT( context, (descriptors[12].capabilities &
								 capabilityMask( ProviderCapability::USER_SELECTED_FILE)) != 0) ;
	DRIVERCRATE_EXPECT( context, descriptors[13].discoveryBasis ==
									CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE) ;
	DRIVERCRATE_EXPECT( context, (descriptors[13].capabilities &
								 capabilityMask( ProviderCapability::USER_SELECTED_FILE)) != 0) ;
	DRIVERCRATE_EXPECT( context, descriptors[14].id == AMD_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, descriptors[14].discoveryBasis ==
									CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE) ;
	DRIVERCRATE_EXPECT( context, (descriptors[14].capabilities &
								 capabilityMask( ProviderCapability::OFFICIAL_NETWORK)) != 0) ;
	DRIVERCRATE_EXPECT( context, (descriptors[14].capabilities &
								 capabilityMask( ProviderCapability::DOWNLOAD)) == 0) ;
	DRIVERCRATE_EXPECT(
		context, (descriptors[14].capabilities & capabilityMask( ProviderCapability::INSTALL)) == 0) ;
	DRIVERCRATE_EXPECT( context, descriptors[15].id == ASUS_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, descriptors[15].discoveryBasis ==
									CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE) ;
	DRIVERCRATE_EXPECT( context, (descriptors[15].capabilities &
								 capabilityMask( ProviderCapability::OFFICIAL_NETWORK)) != 0) ;
	DRIVERCRATE_EXPECT( context, (descriptors[15].capabilities &
								 capabilityMask( ProviderCapability::DOWNLOAD)) != 0) ;
	DRIVERCRATE_EXPECT(
		context, (descriptors[15].capabilities & capabilityMask( ProviderCapability::INSTALL)) != 0) ;
	DRIVERCRATE_EXPECT( context, !descriptors[15].enabledByDefault) ;
	DRIVERCRATE_EXPECT( context, descriptors[16].id == ASROCK_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, descriptors[16].discoveryBasis ==
									CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE) ;
	DRIVERCRATE_EXPECT( context, (descriptors[16].capabilities &
								 capabilityMask( ProviderCapability::OFFICIAL_NETWORK)) != 0) ;
	DRIVERCRATE_EXPECT( context, (descriptors[16].capabilities &
								 capabilityMask( ProviderCapability::DOWNLOAD)) == 0) ;
	DRIVERCRATE_EXPECT(
		context, (descriptors[16].capabilities & capabilityMask( ProviderCapability::INSTALL)) == 0) ;
	DRIVERCRATE_EXPECT( context, !descriptors[16].enabledByDefault) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既定設定と明示的なProvider選択を検証する。
 *
 * 全無効を含む明示設定と既定設定を別の状態として確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testSelection( TestContext &context)
{
	const std::span	  descriptors = builtInProviderDescriptors() ;	// 判定対象Provider群。
	const ScanOptions defaults{} ;									// Registry既定設定。
	DRIVERCRATE_EXPECT( context, validateScanOptions( defaults)) ;
	// 既定設定が全Registry entryのenabled_by_defaultと一致することを確認する。
	for( const ProviderDescriptor &descriptor : descriptors) {
		DRIVERCRATE_EXPECT( context,
						   isProviderEnabled( defaults, descriptor) == descriptor.enabledByDefault) ;
	}

	const ScanOptions none{.useDefaultProviders = false} ;	// 利用者が全て無効にした設定。
	DRIVERCRATE_EXPECT( context, validateScanOptions( none)) ;
	// 明示的な全無効設定が全Providerの実行を拒否することを確認する。
	for( const ProviderDescriptor &descriptor : descriptors) {
		DRIVERCRATE_EXPECT( context, !isProviderEnabled( none, descriptor)) ;
	}

	// WUAとNVIDIAだけを明示的に有効化するscan設定fixture。
	const ScanOptions selected{.useDefaultProviders = false,
							   .enabledProviderIds	= {std::wstring( WINDOWS_UPDATE_PROVIDER_ID),
													   std::wstring( NVIDIA_PROVIDER_ID)}} ;
	DRIVERCRATE_EXPECT( context, validateScanOptions( selected)) ;
	DRIVERCRATE_EXPECT( context, isProviderEnabled( selected, descriptors[0])) ;
	DRIVERCRATE_EXPECT( context, !isProviderEnabled( selected, descriptors[1])) ;
	DRIVERCRATE_EXPECT( context, isProviderEnabled( selected, descriptors[2])) ;
	DRIVERCRATE_EXPECT( context, !isProviderEnabled( selected, descriptors[3])) ;
	DRIVERCRATE_EXPECT( context, !isProviderEnabled( selected, descriptors[4])) ;
	DRIVERCRATE_EXPECT( context, !isProviderEnabled( selected, descriptors[5])) ;
	DRIVERCRATE_EXPECT( context, !isProviderEnabled( selected, descriptors[6])) ;
	DRIVERCRATE_EXPECT( context, !isProviderEnabled( selected, descriptors[7])) ;
	DRIVERCRATE_EXPECT( context, !isProviderEnabled( selected, descriptors[8])) ;
	DRIVERCRATE_EXPECT( context, !isProviderEnabled( selected, descriptors[9])) ;
	DRIVERCRATE_EXPECT( context, !isProviderEnabled( selected, descriptors[10])) ;
	DRIVERCRATE_EXPECT( context, !isProviderEnabled( selected, descriptors[11])) ;
	DRIVERCRATE_EXPECT( context, !isProviderEnabled( selected, descriptors[12])) ;
	DRIVERCRATE_EXPECT( context, !isProviderEnabled( selected, descriptors[13])) ;
	DRIVERCRATE_EXPECT( context, !isProviderEnabled( selected, descriptors[14])) ;
	DRIVERCRATE_EXPECT( context, !isProviderEnabled( selected, descriptors[15])) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 新しい一scan承認を公式Provider集合と固定予算へ厳格に結合することを検証する。
 *
 * 旧Provider別同意との同時指定、対象外scope、operation欠損、予算改変を拒否する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testOfficialDiscoveryApproval( TestContext &context)
{
	// Windows 11 Intel Ethernetだけへ結合する固定予算の基準承認。
	ScanOptions options{
		.useDefaultProviders = false,
		.enabledProviderIds	 = {std::wstring( INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID)}} ;
	options.officialDiscoveryApproval = OfficialDiscoveryScanApproval{
		.operationId			   = 17U,
		.inspectionPermission	   = OfficialDiscoveryInspectionPermission::METADATA_ONLY,
		.restrictedNetworkApproved = false,
		.cacheMode				   = OfficialDiscoveryCacheMode::USE_FRESH} ;
	DRIVERCRATE_EXPECT( context, validateScanOptions( options)) ;

	options.prolificInspectionApproved = true ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( options)) ;
	options.prolificInspectionApproved			   = false ;
	options.officialDiscoveryApproval->operationId = 0U ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( options)) ;
	options.officialDiscoveryApproval->operationId = 17U ;
	options.officialDiscoveryApproval->inspectionPermission =
		static_cast<OfficialDiscoveryInspectionPermission>( 99) ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( options)) ;
	options.officialDiscoveryApproval->inspectionPermission =
		OfficialDiscoveryInspectionPermission::METADATA_ONLY ;
	options.officialDiscoveryApproval->cacheMode = static_cast<OfficialDiscoveryCacheMode>( 99) ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( options)) ;
	options.officialDiscoveryApproval->cacheMode = OfficialDiscoveryCacheMode::USE_FRESH ;
	options.officialDiscoveryApproval->metadataLimits.sessionBytes++ ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( options)) ;
	options.officialDiscoveryApproval->metadataLimits = {} ;
	options.officialDiscoveryApproval->payloadLimits.maximumSessionFiles++ ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( options)) ;
	options.officialDiscoveryApproval->payloadLimits = {} ;
	options.enabledProviderIds						 = {std::wstring( DRIVER_STORE_PROVIDER_ID)} ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( options)) ;

	ScanOptions defaults ;	// 移行中も既定Provider集合を明示承認へ結合できる。
	defaults.officialDiscoveryApproval = OfficialDiscoveryScanApproval{.operationId = 18U} ;
	DRIVERCRATE_EXPECT( context, validateScanOptions( defaults)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 利用者選択fileとProviderの一対一対応を検証する。
 *
 * File入力可能Providerだけが、有効時に一つのpathを受け取るfail-closed設定を確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testUserSelectedFiles( TestContext &context)
{
	const ScanOptions valid{
		.useDefaultProviders = false,
		.enabledProviderIds	 = {std::wstring( DRIVER_STORE_PROVIDER_ID),
								std::wstring( INTEL_WIRELESS_PACKAGE_PROVIDER_ID)},
		.userSelectedFiles	 = {{.providerId = std::wstring( INTEL_WIRELESS_PACKAGE_PROVIDER_ID),
								 .path		 = L"C:\\Fictional\\wireless.zip"}}} ;	// 正常な一件入力。
	DRIVERCRATE_EXPECT( context, validateScanOptions( valid)) ;
	DRIVERCRATE_EXPECT( context,
					   userSelectedFileForProvider( valid, INTEL_WIRELESS_PACKAGE_PROVIDER_ID) ==
						   L"C:\\Fictional\\wireless.zip") ;
	DRIVERCRATE_EXPECT( context,
					   userSelectedFileForProvider( valid, DRIVER_STORE_PROVIDER_ID).empty()) ;

	const ScanOptions sixFiles{
		.useDefaultProviders = false,
		.enabledProviderIds	 = {std::wstring( INTEL_WIRELESS_PACKAGE_PROVIDER_ID),
								std::wstring( PROLIFIC_SERIAL_PACKAGE_PROVIDER_ID),
								std::wstring( SILICON_LABS_SERIAL_PACKAGE_PROVIDER_ID),
								std::wstring( WCH_SERIAL_PACKAGE_PROVIDER_ID),
								std::wstring( WCH_MULTI_SERIAL_PACKAGE_PROVIDER_ID),
								std::wstring( GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID)},
		.userSelectedFiles	 = {
			  {.providerId = std::wstring( INTEL_WIRELESS_PACKAGE_PROVIDER_ID),
			   .path	   = L"C:\\Fictional\\wireless.zip"},
			  {.providerId = std::wstring( PROLIFIC_SERIAL_PACKAGE_PROVIDER_ID),
			   .path	   = L"C:\\Fictional\\serial.zip"},
			  {.providerId = std::wstring( SILICON_LABS_SERIAL_PACKAGE_PROVIDER_ID),
			   .path	   = L"C:\\Fictional\\cp210x.zip"},
			  {.providerId = std::wstring( WCH_SERIAL_PACKAGE_PROVIDER_ID),
			   .path	   = L"C:\\Fictional\\wch341.zip"},
			  {.providerId = std::wstring( WCH_MULTI_SERIAL_PACKAGE_PROVIDER_ID),
			   .path	   = L"C:\\Fictional\\wch343.zip"},
			  {.providerId = std::wstring( GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID),
			   .path	   = L"C:\\Fictional\\generic-driver.zip"}}} ;	// 区分C Provider別入力。
	DRIVERCRATE_EXPECT( context, validateScanOptions( sixFiles)) ;
	DRIVERCRATE_EXPECT( context,
					   userSelectedFileForProvider( sixFiles, PROLIFIC_SERIAL_PACKAGE_PROVIDER_ID) ==
						   L"C:\\Fictional\\serial.zip") ;
	DRIVERCRATE_EXPECT(
		context, userSelectedFileForProvider( sixFiles, SILICON_LABS_SERIAL_PACKAGE_PROVIDER_ID) ==
					 L"C:\\Fictional\\cp210x.zip") ;
	DRIVERCRATE_EXPECT( context,
					   userSelectedFileForProvider( sixFiles, WCH_SERIAL_PACKAGE_PROVIDER_ID) ==
						   L"C:\\Fictional\\wch341.zip") ;
	DRIVERCRATE_EXPECT(
		context, userSelectedFileForProvider( sixFiles, WCH_MULTI_SERIAL_PACKAGE_PROVIDER_ID) ==
					 L"C:\\Fictional\\wch343.zip") ;
	DRIVERCRATE_EXPECT(
		context, userSelectedFileForProvider( sixFiles, GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID) ==
					 L"C:\\Fictional\\generic-driver.zip") ;

	const ScanOptions missingFile{
		.useDefaultProviders = false,
		.enabledProviderIds	 = {std::wstring( INTEL_WIRELESS_PACKAGE_PROVIDER_ID)}} ;	// 入力欠落。
	DRIVERCRATE_EXPECT( context, !validateScanOptions( missingFile)) ;

	const ScanOptions disabledFile{
		.useDefaultProviders = false,
		.enabledProviderIds	 = {std::wstring( DRIVER_STORE_PROVIDER_ID)},
		.userSelectedFiles	 = {{.providerId = std::wstring( INTEL_WIRELESS_PACKAGE_PROVIDER_ID),
								 .path = L"C:\\Fictional\\wireless.zip"}}} ;	// 無効Provider入力。
	DRIVERCRATE_EXPECT( context, !validateScanOptions( disabledFile)) ;

	const ScanOptions wrongCapability{
		.useDefaultProviders = false,
		.enabledProviderIds	 = {std::wstring( DRIVER_STORE_PROVIDER_ID)},
		.userSelectedFiles	 = {{.providerId = std::wstring( DRIVER_STORE_PROVIDER_ID),
								 .path = L"C:\\Fictional\\wireless.zip"}}} ;	// 非対応Provider入力。
	DRIVERCRATE_EXPECT( context, !validateScanOptions( wrongCapability)) ;

	const ScanOptions duplicateFiles{
		.useDefaultProviders = false,
		.enabledProviderIds	 = {std::wstring( INTEL_WIRELESS_PACKAGE_PROVIDER_ID)},
		.userSelectedFiles	 = {
			  {.providerId = std::wstring( INTEL_WIRELESS_PACKAGE_PROVIDER_ID),
			   .path	   = L"C:\\Fictional\\wireless-a.zip"},
			  {.providerId = std::wstring( INTEL_WIRELESS_PACKAGE_PROVIDER_ID),
			   .path	   = L"C:\\Fictional\\wireless-b.zip"}}} ;	// 同一Providerへの重複入力。
	DRIVERCRATE_EXPECT( context, !validateScanOptions( duplicateFiles)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未知ID、重複ID、矛盾する既定設定を拒否することを検証する。
 *
 * UI迂回時も未知Providerへ通信またはroutingしない条件を確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testInvalidSelection( TestContext &context)
{
	// 未知のstable IDを指定したscan設定の拒否用入力。
	const ScanOptions unknown{.useDefaultProviders = false,
							  .enabledProviderIds  = {L"unknown-provider"}} ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( unknown)) ;

	// 同じProviderを重複指定したscan設定の拒否用入力。
	const ScanOptions duplicate{
		.useDefaultProviders = false,
		.enabledProviderIds	 = {std::wstring( DELL_PROVIDER_ID), std::wstring( DELL_PROVIDER_ID)}} ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( duplicate)) ;

	// 既定設定と明示集合を併記した矛盾設定の拒否用入力。
	const ScanOptions contradictory{
		.useDefaultProviders = true,
		.enabledProviderIds	 = {std::wstring( WINDOWS_UPDATE_PROVIDER_ID)}} ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( contradictory)) ;

	const ScanOptions contradictoryFile{
		.userSelectedFiles = {{.providerId = std::wstring( INTEL_WIRELESS_PACKAGE_PROVIDER_ID),
							   .path = L"C:\\Fictional\\wireless.zip"}}} ;	// 既定設定との矛盾。
	DRIVERCRATE_EXPECT( context, !validateScanOptions( contradictoryFile)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider結果を取得元別scan状態へ正規化することを検証する。
 *
 * 無効、対象外、候補有無、失敗、監査段階別拒否を確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testScanStates( TestContext &context)
{
	ScanResult result{.succeeded = true, .outcome = OutcomeCode::SUCCESS} ;	// 基本成功結果。
	DRIVERCRATE_EXPECT( context,
					   resolveProviderScanState( result, false) == ProviderScanState::DISABLED) ;
	DRIVERCRATE_EXPECT( context,
					   resolveProviderScanState( result, true) == ProviderScanState::NO_CANDIDATES) ;

	result.state = ProviderScanState::NOT_APPLICABLE ;
	DRIVERCRATE_EXPECT( context,
					   resolveProviderScanState( result, true) == ProviderScanState::NOT_APPLICABLE) ;
	result.state = ProviderScanState::PAYLOAD_NOT_APPROVED ;
	DRIVERCRATE_EXPECT( context, resolveProviderScanState( result, true) ==
									ProviderScanState::PAYLOAD_NOT_APPROVED) ;
	DRIVERCRATE_EXPECT( context, isProviderScanResultConsistent( result, true)) ;
	result.state = ProviderScanState::NETWORK_NOT_APPROVED ;
	DRIVERCRATE_EXPECT( context, resolveProviderScanState( result, true) ==
									ProviderScanState::NETWORK_NOT_APPROVED) ;
	DRIVERCRATE_EXPECT( context, isProviderScanResultConsistent( result, true)) ;

	result.state = ProviderScanState::NO_CANDIDATES ;
	result.candidates.push_back( {.identity = L"current", .current = true}) ;
	result.candidates.push_back( {.identity = L"candidate"}) ;
	DRIVERCRATE_EXPECT( context, countDisplayCandidates( result) == 1) ;
	DRIVERCRATE_EXPECT( context, resolveProviderScanState( result, true) ==
									ProviderScanState::CANDIDATES_AVAILABLE) ;
	result.state = ProviderScanState::PAYLOAD_NOT_APPROVED ;
	DRIVERCRATE_EXPECT( context,
					   resolveProviderScanState( result, true) == ProviderScanState::FAILURE) ;
	result.state = ProviderScanState::NETWORK_NOT_APPROVED ;
	DRIVERCRATE_EXPECT( context,
					   resolveProviderScanState( result, true) == ProviderScanState::FAILURE) ;

	result.succeeded = false ;
	result.state	 = ProviderScanState::FAILURE ;
	DRIVERCRATE_EXPECT( context,
					   resolveProviderScanState( result, true) == ProviderScanState::FAILURE) ;
	result.state = ProviderScanState::METADATA_REJECTED ;
	DRIVERCRATE_EXPECT( context, resolveProviderScanState( result, true) ==
									ProviderScanState::METADATA_REJECTED) ;
	result.state = ProviderScanState::SOURCE_REJECTED ;
	DRIVERCRATE_EXPECT( context, resolveProviderScanState( result, true) ==
									ProviderScanState::SOURCE_REJECTED) ;
	result.state = ProviderScanState::DOWNLOAD_FAILED ;
	DRIVERCRATE_EXPECT( context, resolveProviderScanState( result, true) ==
									ProviderScanState::DOWNLOAD_FAILED) ;
	result.state = ProviderScanState::CONTENT_REJECTED ;
	DRIVERCRATE_EXPECT( context, resolveProviderScanState( result, true) ==
									ProviderScanState::CONTENT_REJECTED) ;

	result.succeeded = true ;
	result.state	 = ProviderScanState::SOURCE_REJECTED ;
	DRIVERCRATE_EXPECT( context,
					   resolveProviderScanState( result, true) == ProviderScanState::FAILURE) ;
	result.state = ProviderScanState::NOT_APPLICABLE ;
	DRIVERCRATE_EXPECT( context,
					   resolveProviderScanState( result, true) == ProviderScanState::FAILURE) ;
	result.candidates.clear() ;
	result.state = ProviderScanState::DISABLED ;
	DRIVERCRATE_EXPECT( context,
					   resolveProviderScanState( result, true) == ProviderScanState::FAILURE) ;
	result.state = static_cast<ProviderScanState>( 999) ;
	DRIVERCRATE_EXPECT( context,
					   resolveProviderScanState( result, true) == ProviderScanState::FAILURE) ;

	result = {.succeeded = true,
			  .outcome	 = OutcomeCode::SUCCESS,
			  .state	 = ProviderScanState::NO_CANDIDATES} ;
	DRIVERCRATE_EXPECT( context, isProviderScanResultConsistent( result, true)) ;
	result.outcome = OutcomeCode::FAILURE ;
	DRIVERCRATE_EXPECT( context, !isProviderScanResultConsistent( result, true)) ;

	result.succeeded = false ;
	result.state	 = ProviderScanState::SOURCE_REJECTED ;
	DRIVERCRATE_EXPECT( context, isProviderScanResultConsistent( result, true)) ;
	result.outcome = OutcomeCode::SUCCEEDED_WITH_ERRORS ;
	DRIVERCRATE_EXPECT( context, !isProviderScanResultConsistent( result, true)) ;

	result.outcome = OutcomeCode::FAILURE ;
	result.state   = ProviderScanState::NO_CANDIDATES ;
	DRIVERCRATE_EXPECT( context, !isProviderScanResultConsistent( result, true)) ;
	result.state = ProviderScanState::PAYLOAD_NOT_APPROVED ;
	DRIVERCRATE_EXPECT( context, !isProviderScanResultConsistent( result, true)) ;
	result.state = ProviderScanState::NETWORK_NOT_APPROVED ;
	DRIVERCRATE_EXPECT( context, !isProviderScanResultConsistent( result, true)) ;
	DRIVERCRATE_EXPECT( context, isProviderScanResultConsistent( result, false)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider coverageの対象／判定件数関係を検証する。
 *
 * 判定済みdevice数が対象device数を超える矛盾を拒否する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testCoverage( TestContext &context)
{
	constexpr ProviderCoverage VALID{.eligibleDeviceCount = 4,
									 .assessedDeviceCount = 3} ;	// 正常coverage。
	constexpr ProviderCoverage EMPTY{} ;							// 対象外coverage。
	constexpr ProviderCoverage INVALID{.eligibleDeviceCount = 3,
									   .assessedDeviceCount = 4} ;	// 矛盾coverage。
	DRIVERCRATE_EXPECT( context, isValidProviderCoverage( VALID)) ;
	DRIVERCRATE_EXPECT( context, isValidProviderCoverage( EMPTY)) ;
	DRIVERCRATE_EXPECT( context, !isValidProviderCoverage( INVALID)) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/provider_registry_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runProviderRegistryTests( TestContext &context)
{
	testDescriptors( context) ;
	testSelection( context) ;
	testOfficialDiscoveryApproval( context) ;
	testUserSelectedFiles( context) ;
	testInvalidSelection( context) ;
	testScanStates( context) ;
	testCoverage( context) ;
}

} // namespace drivercrate::test
