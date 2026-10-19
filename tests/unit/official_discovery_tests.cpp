//------------------------------------------------------------------------------
/**
 * @file official_discovery_tests.cpp
 * @brief 公式自動探索Core境界の決定的単体試験。
 * @version 01.07.00
 * @date 2026/09/15
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  自動探索Core境界試験を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Bus分類とinventory hint変換試験を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  Registrationとroute planner試験を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  Purpose共通実行と汎用継続試験を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/15  自動探索negative fixture集合を追加。
 * Ver.01.04.01 Shunji Ogawa  2026/09/15  合成registryの探索Providerを一件へ固定。
 * Ver.01.05.00 Shunji Ogawa  2026/09/15  一scan承認の要求変換と予算改変拒否を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/09/15  事前停止summaryとProvider状態変換を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/09/15  Parser identityとfresh cache優先実行試験を追加。
 * </pre>
 *
 * @note 架空device identityだけを使用し、実端末の識別情報を保持しません。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#include "official_discovery_tests.h"

#include "core/official_discovery.h"
#include "core/official_discovery_execution.h"
#include "core/official_discovery_planner.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/official_discovery_inventory.h"
#include "test_framework.h"

#include <algorithm>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {

/**
 * @brief 既存公式Providerの合成copyへ自動探索capabilityを付与する。
 * @return Prolific公式Providerだけを明示選択できる合成registry。
 */
[[nodiscard]] std::vector<ProviderDescriptor> makeDiscoveryProviders()
{
	const auto builtIn = builtInProviderDescriptors() ;								// 製品registryの検証済み正本。
	std::vector<ProviderDescriptor> providers( builtIn.begin(), builtIn.end()) ;	// 合成copy。
	// 製品で有効になった自動探索能力を除き、本fixtureの対象Provider一件だけを後で選ぶ。
	for( ProviderDescriptor &descriptor : providers) {
		descriptor.capabilities &= ~capabilityMask( ProviderCapability::AUTOMATIC_DISCOVERY) ;
	}

	const auto provider =
		std::find_if( providers.begin(), providers.end(), []( const ProviderDescriptor &descriptor) {
			return descriptor.id == PROLIFIC_OFFICIAL_PROVIDER_ID ;
		}) ; // 固定landing resourceを持つ既存公式Provider。
	// Registry前提が成立したfixtureだけに自動探索能力を追加する。
	if( provider != providers.end()) {
		provider->capabilities |= capabilityMask( ProviderCapability::AUTOMATIC_DISCOVERY) ;
	}

	return providers ;
}

/**
 * @brief 明示Provider一件のmetadata限定自動探索要求を作る。
 * @return 固定policyとProlific Providerへ結合した要求。
 */
[[nodiscard]] OfficialDiscoveryRequest makeRequest()
{
	OfficialDiscoveryRequest request ;	// 権限を持ち越さない一回の要求。
	request.useDefaultProviders = false ;
	request.enabledProviderIds.emplace_back( PROLIFIC_OFFICIAL_PROVIDER_ID) ;
	return request ;
}

/**
 * @brief 名前と現在版が欠損しても保持できる架空device hintを作る。
 * @param[in] scanSessionId 観測を結合するscan session ID。
 * @return UNKNOWN busと有効なclass GUIDを持つ非機密fixture。
 */
[[nodiscard]] OfficialDiscoveryDeviceHint makeDevice( const ScanSessionId scanSessionId)
{
	OfficialDiscoveryDeviceHint device ;	// 実PnP IDを持たない架空device。
	device.deviceIdentity			  = L"fixture-node" ;
	device.bus						  = OfficialDiscoveryDeviceBus::UNKNOWN ;
	device.setupClassGuid			  = L"{4d36e978-e325-11ce-bfc1-08002be10318}" ;
	device.observation.scanSessionId  = scanSessionId ;
	device.observation.deviceIdentity = device.deviceIdentity ;
	return device ;
}

/**
 * @brief 固定landing resourceへ結合した専用routeを作る。
 * @return 一deviceだけを参照する架空route。
 */
[[nodiscard]] OfficialDiscoveryRoute makeRoute()
{
	OfficialDiscoveryRoute route ;	// URLを含まない固定root route。
	route.routeId			= 1U ;
	route.providerId		= PROLIFIC_OFFICIAL_PROVIDER_ID ;
	route.rootResourceId	= OFFICIAL_LANDING_RESOURCE_ID ;
	route.kind				= OfficialDiscoveryRouteKind::DEDICATED ;
	route.hintGroupIdentity = L"fixture-hint-group" ;
	route.deviceIdentities.emplace_back( L"fixture-node") ;
	return route ;
}

/**
 * @brief USB busの架空hintだけをroute対象にする。
 * @param[in] device Raw ID非保持の検証済みhint。
 * @return USB分類の場合true。
 */
[[nodiscard]] bool matchesUsbDevice( const OfficialDiscoveryDeviceHint &device) noexcept
{
	return device.bus == OfficialDiscoveryDeviceBus::USB ;
}

/**
 * @brief PCI busの架空hintだけをroute対象にする。
 * @param[in] device Raw ID非保持の検証済みhint。
 * @return PCI分類の場合true。
 */
[[nodiscard]] bool matchesPciDevice( const OfficialDiscoveryDeviceHint &device) noexcept
{
	return device.bus == OfficialDiscoveryDeviceBus::PCI ;
}

/**
 * @brief 有効な架空hintを表示属性の有無にかかわらずroute対象にする。
 * @param[in] device Raw ID非保持の検証済みhint。
 * @return 常にtrue。
 */
[[nodiscard]] bool matchesAnyDevice( const OfficialDiscoveryDeviceHint &device) noexcept
{
	(void)device ;
	return true ;
}

/**
 * @brief Prolific固定landingへ結合した合成registrationを作る。
 * @param[in] kind 専用または汎用固定rootの種別。
 * @param[in] matcher 端末内の非送信hint matcher。
 * @return Network hintなしで非空resolverを持つregistration。
 */
[[nodiscard]] OfficialDiscoveryRegistration makeRegistration(
	const OfficialDiscoveryRouteKind kind, const OfficialDiscoveryHintMatcher matcher)
{
	OfficialDiscoveryRegistration registration ;	// 組み込み公式rootへ結合するfixture。
	registration.providerId		= PROLIFIC_OFFICIAL_PROVIDER_ID ;
	registration.sourcePolicyId = PROLIFIC_OFFICIAL_SOURCE_POLICY_ID ;
	registration.rootResourceId = OFFICIAL_LANDING_RESOURCE_ID ;
	registration.parserId		= L"fixture-official-discovery-parser" ;
	registration.parserRevision = 1U ;
	registration.kind			= kind ;
	registration.matcher		= matcher ;
	registration.resolver		= []( const OfficialDiscoveryRequest &,
								 const OfficialDiscoveryRoute &route,
								 std::span<const OfficialDiscoveryDeviceHint>) {
		  return OfficialDiscoveryRouteSummary{
				  .routeId = route.routeId, .providerId = route.providerId, .kind = route.kind} ;
	} ; // Plannerから呼ばれない固定root resolver fixture。
	return registration ;
}

/**
 * @brief 元routeへ完全一致する合成resolver summaryを作る。
 * @param[in] route 実行対象の固定root route。
 * @param[in] state 保持する有限な終了状態。
 * @param[in] recordCount 解決済みmetadata record件数。
 * @param[in] packageCount Driver packageと分類した件数。
 * @param[in] error 失敗状態だけに設定するnative診断値。
 * @return Route identityと全device件数へ結合したsummary。
 */
[[nodiscard]] OfficialDiscoveryRouteSummary makeRouteResult( const OfficialDiscoveryRoute	 &route,
															const OfficialDiscoveryRouteState state,
															const std::uint32_t recordCount	 = 0U,
															const std::uint32_t packageCount = 0U,
															const NativeError	error		 = 0)
{
	return OfficialDiscoveryRouteSummary{
		.routeId	  = route.routeId,
		.providerId	  = route.providerId,
		.kind		  = route.kind,
		.state		  = state,
		.error		  = error,
		.deviceCount  = static_cast<std::uint32_t>( route.deviceIdentities.size()),
		.recordCount  = recordCount,
		.packageCount = packageCount} ;
}

/**
 * @brief 解決済みroute一件を持つ公開summaryを作る。
 * @param[in] binding 開始時に固定した三つのID。
 * @param[in] request 開始時に固定した要求。
 * @return 一record、一driver packageを示す合成summary。
 */
[[nodiscard]] OfficialDiscoverySummary makeSummary( const OfficialDiscoveryBinding &binding,
												   const OfficialDiscoveryRequest &request)
{
	OfficialDiscoverySummary summary ;	// 非機密な公開結果fixture。
	summary.binding			  = binding ;
	summary.request			  = request ;
	summary.inventoryComplete = true ;
	summary.deviceCount		  = 1U ;
	summary.routes.push_back(
		OfficialDiscoveryRouteSummary{.routeId	  = 1U,
									  .providerId = std::wstring( PROLIFIC_OFFICIAL_PROVIDER_ID),
									  .kind		  = OfficialDiscoveryRouteKind::DEDICATED,
									  .state	  = OfficialDiscoveryRouteState::DEDICATED_RESOLVED,
									  .error	  = 0,
									  .deviceCount	= 1U,
									  .recordCount	= 1U,
									  .packageCount = 1U}) ;
	return summary ;
}

/**
 * @brief Provider capabilityと一scan requestのfail-closed条件を検証する。
 * @param[in,out] context Assertionの集計先。
 */
void testRequestValidation( TestContext &context)
{
	std::vector<ProviderDescriptor> providers = makeDiscoveryProviders() ;	// 合成registry。
	const auto						provider =
		std::find_if( providers.begin(), providers.end(), []( const ProviderDescriptor &descriptor) {
			return descriptor.id == PROLIFIC_OFFICIAL_PROVIDER_ID ;
		}) ; // 自動探索対象。
	DRIVERCRATE_EXPECT( context, provider != providers.end()) ;
	// 前提登録が欠ける場合はdereferenceせず、失敗assertionを保持する。
	if( provider == providers.end()) {
		return ;
	}

	OfficialDiscoveryRequest request = makeRequest() ;	// 基準となる有効要求。
	DRIVERCRATE_EXPECT( context, isOfficialDiscoveryProvider( *provider)) ;
	DRIVERCRATE_EXPECT( context, validateOfficialDiscoveryRequest( request, providers)) ;

	request.purpose = ScanPurpose::METADATA_ONLY ;
	DRIVERCRATE_EXPECT( context, validateOfficialDiscoveryRequest( request, providers)) ;
	request.inspectionPermission =
		OfficialDiscoveryInspectionPermission::ALLOW_VERIFIED_DRIVER_PACKAGE ;
	DRIVERCRATE_EXPECT( context, !validateOfficialDiscoveryRequest( request, providers)) ;
	request.purpose = ScanPurpose::STANDARD ;
	DRIVERCRATE_EXPECT( context, validateOfficialDiscoveryRequest( request, providers)) ;
	request.inspectionPermission = static_cast<OfficialDiscoveryInspectionPermission>( 99) ;
	DRIVERCRATE_EXPECT( context, !validateOfficialDiscoveryRequest( request, providers)) ;
	request.inspectionPermission = OfficialDiscoveryInspectionPermission::METADATA_ONLY ;
	request.cacheMode			 = static_cast<OfficialDiscoveryCacheMode>( 99) ;
	DRIVERCRATE_EXPECT( context, !validateOfficialDiscoveryRequest( request, providers)) ;
	request.cacheMode = OfficialDiscoveryCacheMode::FORCE_REFRESH ;
	DRIVERCRATE_EXPECT( context, validateOfficialDiscoveryRequest( request, providers)) ;
	request.metadataLimits.sessionAttempts++ ;
	DRIVERCRATE_EXPECT( context, !validateOfficialDiscoveryRequest( request, providers)) ;
	request.metadataLimits = {} ;
	request.payloadLimits.maximumSessionFiles++ ;
	DRIVERCRATE_EXPECT( context, !validateOfficialDiscoveryRequest( request, providers)) ;
	request.payloadLimits = {} ;
	request.policyRevision++ ;
	DRIVERCRATE_EXPECT( context, !validateOfficialDiscoveryRequest( request, providers)) ;
	request.policyRevision = OFFICIAL_DISCOVERY_POLICY_REVISION ;
	request.enabledProviderIds.emplace_back( PROLIFIC_OFFICIAL_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, !validateOfficialDiscoveryRequest( request, providers)) ;
	request.enabledProviderIds.pop_back() ;
	request.enabledProviderIds.front() = L"unknown-provider" ;
	DRIVERCRATE_EXPECT( context, !validateOfficialDiscoveryRequest( request, providers)) ;
	request.enabledProviderIds.front() = PROLIFIC_OFFICIAL_PROVIDER_ID ;
	request.useDefaultProviders		   = true ;
	DRIVERCRATE_EXPECT( context, !validateOfficialDiscoveryRequest( request, providers)) ;
	request.enabledProviderIds.clear() ;
	provider->enabledByDefault = true ;
	DRIVERCRATE_EXPECT( context, validateOfficialDiscoveryRequest( request, providers)) ;
	provider->capabilities &= ~capabilityMask( ProviderCapability::AUTOMATIC_DISCOVERY) ;
	DRIVERCRATE_EXPECT( context, !validateOfficialDiscoveryRequest( request, providers)) ;
	provider->capabilities |= capabilityMask( ProviderCapability::AUTOMATIC_DISCOVERY) ;
	provider->capabilities |= 0x80000000U ;
	DRIVERCRATE_EXPECT( context, !validateOfficialDiscoveryRequest( request, providers)) ;
	provider->capabilities &= ~0x80000000U ;
	providers.push_back( *provider) ;
	DRIVERCRATE_EXPECT( context, !validateOfficialDiscoveryRequest( request, providers)) ;
}

/**
 * @brief UIの一scan承認を固定scopeの通常自動探索requestへ変換する境界を検証する。
 * @param[in,out] context Assertionの集計先。
 */
void testStandardApprovalMapping( TestContext &context)
{
	const std::span descriptors = builtInProviderDescriptors() ;	// 製品registryの正本。
	ScanOptions		options{.useDefaultProviders = false,
							.enabledProviderIds	 = {std::wstring(
							 INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID)}} ;	// 自動探索一件。
	options.officialDiscoveryApproval = OfficialDiscoveryScanApproval{
		.operationId = 41U,
		.inspectionPermission =
			OfficialDiscoveryInspectionPermission::ALLOW_VERIFIED_DRIVER_PACKAGE,
		.restrictedNetworkApproved = true,
		.cacheMode				   = OfficialDiscoveryCacheMode::FORCE_REFRESH} ;
	DRIVERCRATE_EXPECT( context, validateScanOptions( options)) ;
	const auto request =
		// 権限を補完しない変換結果。
		makeStandardOfficialDiscoveryRequest( options, descriptors) ;
	DRIVERCRATE_EXPECT( context, request.has_value()) ;
	// 変換が成立した場合だけ全承認fieldとProvider scopeの完全一致を確認する。
	if( request.has_value()) {
		DRIVERCRATE_EXPECT( context, request->purpose == ScanPurpose::STANDARD) ;
		DRIVERCRATE_EXPECT( context, !request->useDefaultProviders) ;
		DRIVERCRATE_EXPECT( context, request->enabledProviderIds == options.enabledProviderIds) ;
		DRIVERCRATE_EXPECT(
			context, request->inspectionPermission ==
						 OfficialDiscoveryInspectionPermission::ALLOW_VERIFIED_DRIVER_PACKAGE) ;
		DRIVERCRATE_EXPECT( context, request->restrictedNetworkApproved) ;
		DRIVERCRATE_EXPECT( context,
						   request->cacheMode == OfficialDiscoveryCacheMode::FORCE_REFRESH) ;
		DRIVERCRATE_EXPECT( context, request->metadataLimits ==
										options.officialDiscoveryApproval->metadataLimits) ;
		DRIVERCRATE_EXPECT( context, request->payloadLimits ==
										options.officialDiscoveryApproval->payloadLimits) ;
	}

	options.prolificInspectionApproved = true ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( options)) ;
	DRIVERCRATE_EXPECT( context,
					   !makeStandardOfficialDiscoveryRequest( options, descriptors).has_value()) ;
	options.prolificInspectionApproved = false ;
	options.officialDiscoveryApproval->payloadLimits.maximumSessionBytes-- ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( options)) ;
	options.officialDiscoveryApproval->payloadLimits = {} ;
	options.officialDiscoveryApproval->operationId	 = 0U ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( options)) ;
	options.officialDiscoveryApproval->operationId = 41U ;
	options.enabledProviderIds					   = {std::wstring( DRIVER_STORE_PROVIDER_ID)} ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( options)) ;
	options.officialDiscoveryApproval.reset() ;
	DRIVERCRATE_EXPECT( context, validateScanOptions( options)) ;
	DRIVERCRATE_EXPECT( context,
					   !makeStandardOfficialDiscoveryRequest( options, descriptors).has_value()) ;
}

/**
 * @brief Binding、有限bus、raw識別情報拒否を検証する。
 * @param[in,out] context Assertionの集計先。
 */
void testDeviceValidation( TestContext &context)
{
	OfficialDiscoveryBinding binding{
		.operationId = 3U, .scanSessionId = 7U, .inventoryGeneration = 11U} ;	// 有効binding。
	DRIVERCRATE_EXPECT( context, isOfficialDiscoveryBindingValid( binding)) ;
	binding.inventoryGeneration = 0U ;
	DRIVERCRATE_EXPECT( context, !isOfficialDiscoveryBindingValid( binding)) ;
	binding.inventoryGeneration = 11U ;

	OfficialDiscoveryDeviceHint device = makeDevice( binding.scanSessionId) ;	// OF01 fixture。
	DRIVERCRATE_EXPECT( context, validateOfficialDiscoveryDeviceHint( device, binding.scanSessionId)) ;
	device.bus = OfficialDiscoveryDeviceBus::PCI ;
	DRIVERCRATE_EXPECT( context, validateOfficialDiscoveryDeviceHint( device, binding.scanSessionId)) ;
	device.bus = static_cast<OfficialDiscoveryDeviceBus>( 99) ;
	DRIVERCRATE_EXPECT( context,
					   !validateOfficialDiscoveryDeviceHint( device, binding.scanSessionId)) ;
	device.bus						  = OfficialDiscoveryDeviceBus::UNKNOWN ;
	device.deviceIdentity			  = L"PCI\\VEN_1234&DEV_5678" ;
	device.observation.deviceIdentity = device.deviceIdentity ;
	DRIVERCRATE_EXPECT( context,
					   !validateOfficialDiscoveryDeviceHint( device, binding.scanSessionId)) ;
	device.deviceIdentity			  = L"fixture-node" ;
	device.observation.deviceIdentity = device.deviceIdentity ;
	device.model					  = L"USB\\VID_1234&PID_5678" ;
	DRIVERCRATE_EXPECT( context,
					   !validateOfficialDiscoveryDeviceHint( device, binding.scanSessionId)) ;
	device.model		  = L"" ;
	device.setupClassGuid = L"not-a-guid" ;
	DRIVERCRATE_EXPECT( context,
					   !validateOfficialDiscoveryDeviceHint( device, binding.scanSessionId)) ;
	device.setupClassGuid = L"{4d36e978-e325-11ce-bfc1-08002be10318}" ;
	DRIVERCRATE_EXPECT( context,
					   !validateOfficialDiscoveryDeviceHint( device, binding.scanSessionId + 1U)) ;
}

/**
 * @brief Worker内bus分類と完全inventoryからのraw ID非保持変換を検証する。
 * @param[in,out] context Assertionの集計先。
 */
void testInventoryHintProjection( TestContext &context)
{
	DRIVERCRATE_EXPECT( context, classifyOfficialDiscoveryDeviceBus( L"PCI\\fixture") ==
									OfficialDiscoveryDeviceBus::PCI) ;
	DRIVERCRATE_EXPECT( context, classifyOfficialDiscoveryDeviceBus( L"usb\\fixture") ==
									OfficialDiscoveryDeviceBus::USB) ;
	DRIVERCRATE_EXPECT( context, classifyOfficialDiscoveryDeviceBus( L"ACPI\\fixture") ==
									OfficialDiscoveryDeviceBus::ACPI) ;
	DRIVERCRATE_EXPECT( context, classifyOfficialDiscoveryDeviceBus( L"HID\\fixture") ==
									OfficialDiscoveryDeviceBus::HID) ;
	DRIVERCRATE_EXPECT( context, classifyOfficialDiscoveryDeviceBus( L"BTHENUM\\fixture") ==
									OfficialDiscoveryDeviceBus::BLUETOOTH) ;
	DRIVERCRATE_EXPECT( context, classifyOfficialDiscoveryDeviceBus( L"SWD\\fixture") ==
									OfficialDiscoveryDeviceBus::SOFTWARE) ;
	DRIVERCRATE_EXPECT( context, classifyOfficialDiscoveryDeviceBus( L"ROOT\\fixture") ==
									OfficialDiscoveryDeviceBus::ROOT) ;
	DRIVERCRATE_EXPECT( context, classifyOfficialDiscoveryDeviceBus( L"STORAGE\\fixture") ==
									OfficialDiscoveryDeviceBus::OTHER) ;
	DRIVERCRATE_EXPECT( context, classifyOfficialDiscoveryDeviceBus( L"") ==
									OfficialDiscoveryDeviceBus::UNKNOWN) ;
	DRIVERCRATE_EXPECT( context, classifyOfficialDiscoveryDeviceBus( L"\\fixture") ==
									OfficialDiscoveryDeviceBus::UNKNOWN) ;
	std::wstring controlIdentity = L"PCI\\fixture" ;	// 制御文字拒否用の架空native identity。
	controlIdentity.push_back( L'\n') ;
	DRIVERCRATE_EXPECT( context, classifyOfficialDiscoveryDeviceBus( controlIdentity) ==
									OfficialDiscoveryDeviceBus::UNKNOWN) ;

	constexpr ScanSessionId session = 7U ;	// Inventoryと観測を結合する架空session。
	OfficialCatalogDevice	device ;		// Raw IDを含まない有効なcatalog snapshot。
	device.deviceIdentity	 = L"fixture-node" ;
	device.model			 = L"Fixture Serial Adapter" ;
	device.manufacturer		 = L"Fixture Devices" ;
	device.driverClass		 = L"Ports" ;
	device.deviceClassGuid	 = L"{4d36e978-e325-11ce-bfc1-08002be10318}" ;
	device.currentProvider	 = L"Fixture Publisher" ;
	device.deviceObservation = makeDevice( session).observation ;
	device.discoveryBus		 = OfficialDiscoveryDeviceBus::USB ;
	std::vector<OfficialCatalogDevice> devices{device} ;							// 完全inventory fixture。
	const auto hints = makeOfficialDiscoveryDeviceHints( session, true, devices) ;	// 変換結果。
	DRIVERCRATE_EXPECT( context, hints.has_value()) ;
	// 有効変換が得られた場合だけ内容を参照する。
	if( hints) {
		DRIVERCRATE_EXPECT( context, hints->size() == 1U) ;
		DRIVERCRATE_EXPECT( context, hints->front().deviceIdentity == device.deviceIdentity) ;
		DRIVERCRATE_EXPECT( context, hints->front().bus == OfficialDiscoveryDeviceBus::USB) ;
		DRIVERCRATE_EXPECT( context, hints->front().model == device.model) ;
		DRIVERCRATE_EXPECT( context,
						   hints->front().observation.deviceIdentity == device.deviceIdentity) ;
	}

	DRIVERCRATE_EXPECT( context,
					   !makeOfficialDiscoveryDeviceHints( session, false, devices).has_value()) ;
	devices.push_back( device) ;
	DRIVERCRATE_EXPECT( context,
					   !makeOfficialDiscoveryDeviceHints( session, true, devices).has_value()) ;
	devices.pop_back() ;
	devices.front().deviceObservation->scanSessionId = session + 1U ;
	DRIVERCRATE_EXPECT( context,
					   !makeOfficialDiscoveryDeviceHints( session, true, devices).has_value()) ;
	devices.front()		  = device ;
	devices.front().model = L"USB\\VID_fixture" ;
	DRIVERCRATE_EXPECT( context,
					   !makeOfficialDiscoveryDeviceHints( session, true, devices).has_value()) ;
	devices.front()				 = device ;
	devices.front().discoveryBus = static_cast<OfficialDiscoveryDeviceBus>( 99) ;
	DRIVERCRATE_EXPECT( context,
					   !makeOfficialDiscoveryDeviceHints( session, true, devices).has_value()) ;
}

/**
 * @brief Registrationの固定root結合と専用優先route planを検証する。
 * @param[in,out] context Assertionの集計先。
 */
void testRoutePlanner( TestContext &context)
{
	std::vector<ProviderDescriptor> providers = makeDiscoveryProviders() ;	// 合成registry。
	OfficialDiscoveryRequest		request	  = makeRequest() ;				// Prolificだけのscope。
	const OfficialDiscoveryBinding	binding{
		 .operationId = 5U, .scanSessionId = 7U, .inventoryGeneration = 13U} ;	// Plan binding。
	OfficialDiscoveryDeviceHint first  = makeDevice( binding.scanSessionId) ;	// 最初のUSB device。
	first.bus						   = OfficialDiscoveryDeviceBus::USB ;
	first.manufacturer				   = L"Fixture   Devices" ;
	first.model						   = L"Serial Adapter" ;
	OfficialDiscoveryDeviceHint second = first ;	// 同じ正規化hintを持つ別device。
	second.deviceIdentity			   = L"fixture-node-2" ;
	second.observation.deviceIdentity  = second.deviceIdentity ;
	second.manufacturer				   = L"fixture\u00A0devices" ;
	OfficialDiscoveryDeviceHint third  = first ;	// 固定rootへ対応しないPCI device。
	third.deviceIdentity			   = L"fixture-node-3" ;
	third.observation.deviceIdentity   = third.deviceIdentity ;
	third.bus						   = OfficialDiscoveryDeviceBus::PCI ;
	std::vector<OfficialDiscoveryDeviceHint>   devices{first, second, third} ;	// 完全inventory。
	std::vector<OfficialDiscoveryRegistration> registrations{
		makeRegistration( OfficialDiscoveryRouteKind::DEDICATED, matchesUsbDevice),
		makeRegistration( OfficialDiscoveryRouteKind::GENERIC_OFFICIAL_ROOT,
						 matchesUsbDevice)} ;	// 専用と汎用の同一固定root。
	DRIVERCRATE_EXPECT( context, validateOfficialDiscoveryRegistrations( registrations, providers)) ;

	std::uint32_t resolverCalls{} ;	// Plannerが実行callbackを呼ばないことの観測値。
	registrations.front().resolver =
		[&resolverCalls]( const OfficialDiscoveryRequest &, const OfficialDiscoveryRoute &route,
						 std::span<const OfficialDiscoveryDeviceHint>) {
			++resolverCalls ;
			return OfficialDiscoveryRouteSummary{
				.routeId = route.routeId, .providerId = route.providerId, .kind = route.kind} ;
		} ;
	const auto plan = makeOfficialDiscoveryRoutePlan( binding, request, true, devices, registrations,
													 providers) ;	// 決定的plan。
	DRIVERCRATE_EXPECT( context, plan.has_value()) ;
	DRIVERCRATE_EXPECT( context, resolverCalls == 0U) ;
	// 有効planが得られた場合だけroute順序とgroup内容を確認する。
	if( plan) {
		DRIVERCRATE_EXPECT( context, plan->routes.size() == 2U) ;
		DRIVERCRATE_EXPECT( context,
						   plan->routes.front().kind == OfficialDiscoveryRouteKind::DEDICATED) ;
		DRIVERCRATE_EXPECT( context, plan->routes.back().kind ==
										OfficialDiscoveryRouteKind::GENERIC_OFFICIAL_ROOT) ;
		DRIVERCRATE_EXPECT( context, plan->routes.front().deviceIdentities.size() == 2U) ;
		DRIVERCRATE_EXPECT( context, plan->routes.front().hintGroupIdentity == L"hint-group:1") ;
		DRIVERCRATE_EXPECT( context, plan->routes.back().hintGroupIdentity == L"hint-group:2") ;
		DRIVERCRATE_EXPECT( context, plan->noTrustedRootDeviceIdentities.size() == 1U) ;
		DRIVERCRATE_EXPECT( context,
						   plan->noTrustedRootDeviceIdentities.front() == third.deviceIdentity) ;
		DRIVERCRATE_EXPECT( context,
						   isOfficialDiscoveryRoutePlanValid( binding, request, devices,
															 registrations, providers, *plan)) ;

		OfficialDiscoveryRoutePlan invalidPlan = *plan ;	// Route順序改変の拒否用copy。
		invalidPlan.routes.front().kind		   = OfficialDiscoveryRouteKind::GENERIC_OFFICIAL_ROOT ;
		DRIVERCRATE_EXPECT( context, !isOfficialDiscoveryRoutePlanValid( binding, request, devices,
																	   registrations, providers,
																	   invalidPlan)) ;
		invalidPlan = *plan ;
		invalidPlan.noTrustedRootDeviceIdentities.emplace_back( first.deviceIdentity) ;
		DRIVERCRATE_EXPECT( context, !isOfficialDiscoveryRoutePlanValid( binding, request, devices,
																	   registrations, providers,
																	   invalidPlan)) ;
	}

	std::vector<OfficialDiscoveryRegistration> genericOnly{
		makeRegistration( OfficialDiscoveryRouteKind::GENERIC_OFFICIAL_ROOT,
						 matchesUsbDevice)} ;	// 専用adapter欠損時の汎用route。
	const auto genericPlan = makeOfficialDiscoveryRoutePlan(
		binding, request, true, devices, genericOnly, providers) ;	// 汎用だけのplan。
	DRIVERCRATE_EXPECT( context, genericPlan.has_value()) ;
	// 汎用planが得られた場合だけ最初のroute種別を参照する。
	if( genericPlan) {
		DRIVERCRATE_EXPECT( context, genericPlan->routes.size() == 1U) ;
		DRIVERCRATE_EXPECT( context, genericPlan->routes.front().kind ==
										OfficialDiscoveryRouteKind::GENERIC_OFFICIAL_ROOT) ;
	}

	std::vector<OfficialDiscoveryRegistration> noMatch{
		makeRegistration( OfficialDiscoveryRouteKind::DEDICATED,
						 matchesPciDevice)} ;					// PCIだけに対応するregistration。
	std::vector<OfficialDiscoveryDeviceHint> usbOnly{first} ;	// 固定rootに対応しない一device。
	const auto noRootPlan = makeOfficialDiscoveryRoutePlan( binding, request, true, usbOnly, noMatch,
														   providers) ;	// NO_TRUSTED_ROOT用plan。
	DRIVERCRATE_EXPECT( context, noRootPlan.has_value()) ;
	// Routeなしplanが得られた場合だけ未対応identityを確認する。
	if( noRootPlan) {
		DRIVERCRATE_EXPECT( context, noRootPlan->routes.empty()) ;
		DRIVERCRATE_EXPECT( context, noRootPlan->noTrustedRootDeviceIdentities.size() == 1U) ;
	}

	OfficialDiscoveryRegistration invalidRegistration = registrations.front() ;	// 拒否用copy。
	invalidRegistration.resolver					  = {} ;
	DRIVERCRATE_EXPECT(
		context,
		!validateOfficialDiscoveryRegistrations(
			std::span<const OfficialDiscoveryRegistration>( &invalidRegistration, 1U), providers)) ;
	invalidRegistration				   = registrations.front() ;
	invalidRegistration.rootResourceId = OFFICIAL_PAYLOAD_RESOURCE_ID ;
	DRIVERCRATE_EXPECT(
		context,
		!validateOfficialDiscoveryRegistrations(
			std::span<const OfficialDiscoveryRegistration>( &invalidRegistration, 1U), providers)) ;
	invalidRegistration					  = registrations.front() ;
	invalidRegistration.networkHintFields = 1U ;
	DRIVERCRATE_EXPECT(
		context,
		!validateOfficialDiscoveryRegistrations(
			std::span<const OfficialDiscoveryRegistration>( &invalidRegistration, 1U), providers)) ;
	invalidRegistration			 = registrations.front() ;
	invalidRegistration.parserId = L"Parser With Spaces" ;
	DRIVERCRATE_EXPECT(
		context,
		!validateOfficialDiscoveryRegistrations(
			std::span<const OfficialDiscoveryRegistration>( &invalidRegistration, 1U), providers)) ;
	invalidRegistration				   = registrations.front() ;
	invalidRegistration.parserRevision = 0U ;
	DRIVERCRATE_EXPECT(
		context,
		!validateOfficialDiscoveryRegistrations(
			std::span<const OfficialDiscoveryRegistration>( &invalidRegistration, 1U), providers)) ;
	registrations.push_back( registrations.front()) ;
	DRIVERCRATE_EXPECT( context, !validateOfficialDiscoveryRegistrations( registrations, providers)) ;
}

/**
 * @brief 通常／metadata共通planと専用0件後の汎用継続状態を検証する。
 * @param[in,out] context Assertionの集計先。
 */
void testRoutePlanExecution( TestContext &context)
{
	std::vector<ProviderDescriptor> providers = makeDiscoveryProviders() ;	// 合成registry。
	OfficialDiscoveryRequest standardRequest  = makeRequest() ;				// Metadata限定権限の通常scan要求。
	const OfficialDiscoveryBinding binding{
		.operationId = 17U, .scanSessionId = 19U, .inventoryGeneration = 23U} ;	// 共通binding。
	OfficialDiscoveryDeviceHint device = makeDevice( binding.scanSessionId) ;	// USB fixture。
	device.bus						   = OfficialDiscoveryDeviceBus::USB ;
	std::vector<OfficialDiscoveryDeviceHint> devices{device} ;	// 一deviceの完全inventory。
	std::vector<ScanPurpose>				 observedPurposes ;	// Resolverへ渡されたpurposeの順序。
	std::vector<OfficialDiscoveryRegistration> registrations{
		makeRegistration( OfficialDiscoveryRouteKind::DEDICATED, matchesUsbDevice),
		makeRegistration( OfficialDiscoveryRouteKind::GENERIC_OFFICIAL_ROOT,
						 matchesUsbDevice)} ;	// 専用0件から汎用成功へ進むfixture。
	registrations.front().resolver =
		[&observedPurposes]( const OfficialDiscoveryRequest &request,
							const OfficialDiscoveryRoute   &route,
							std::span<const OfficialDiscoveryDeviceHint>) {
			observedPurposes.push_back( request.purpose) ;
			return makeRouteResult( route, OfficialDiscoveryRouteState::NO_RECORD) ;
		} ;
	registrations.back().resolver =
		[&observedPurposes]( const OfficialDiscoveryRequest &request,
							const OfficialDiscoveryRoute   &route,
							std::span<const OfficialDiscoveryDeviceHint>) {
			observedPurposes.push_back( request.purpose) ;
			return makeRouteResult( route, OfficialDiscoveryRouteState::GENERIC_RESOLVED, 1U, 1U) ;
		} ;

	const auto standardPlan = makeOfficialDiscoveryRoutePlan(
		binding, standardRequest, true, devices, registrations, providers) ;	// 通常目的plan。
	DRIVERCRATE_EXPECT( context, standardPlan.has_value()) ;
	std::optional<OfficialDiscoverySummary> standardSummary ;	// 通常目的の実行結果。
	// Planが成立した場合だけresolverへ渡す。
	if( standardPlan) {
		standardSummary = runOfficialDiscoveryRoutePlan( binding, standardRequest, *standardPlan,
														devices, registrations, providers) ;
	}

	DRIVERCRATE_EXPECT( context, standardSummary.has_value()) ;
	// 通常結果が成立した場合だけ専用0件と汎用成功を別行で確認する。
	if( standardSummary) {
		DRIVERCRATE_EXPECT( context, standardSummary->routes.size() == 2U) ;
		DRIVERCRATE_EXPECT( context, standardSummary->routes.front().state ==
										OfficialDiscoveryRouteState::NO_RECORD) ;
		DRIVERCRATE_EXPECT( context, standardSummary->routes.back().state ==
										OfficialDiscoveryRouteState::GENERIC_RESOLVED) ;
	}

	OfficialDiscoveryRequest metadataRequest = standardRequest ;	// 同じProvider範囲の情報検索目的。
	metadataRequest.purpose					 = ScanPurpose::METADATA_ONLY ;
	const auto metadataPlan					 = makeOfficialDiscoveryRoutePlan(
		 binding, metadataRequest, true, devices, registrations, providers) ;	// Metadata目的plan。
	DRIVERCRATE_EXPECT( context, metadataPlan.has_value()) ;
	std::optional<OfficialDiscoverySummary> metadataSummary ;	// Metadata目的の実行結果。
	// Planが成立した場合だけ同じexecutorへ渡す。
	if( metadataPlan) {
		metadataSummary = runOfficialDiscoveryRoutePlan( binding, metadataRequest, *metadataPlan,
														devices, registrations, providers) ;
	}

	DRIVERCRATE_EXPECT( context, metadataSummary.has_value()) ;
	DRIVERCRATE_EXPECT( context, observedPurposes.size() == 4U) ;
	// 四回のresolver実行が得られた場合だけpurpose順を参照する。
	if( observedPurposes.size() == 4U) {
		DRIVERCRATE_EXPECT( context, observedPurposes[0] == ScanPurpose::STANDARD) ;
		DRIVERCRATE_EXPECT( context, observedPurposes[1] == ScanPurpose::STANDARD) ;
		DRIVERCRATE_EXPECT( context, observedPurposes[2] == ScanPurpose::METADATA_ONLY) ;
		DRIVERCRATE_EXPECT( context, observedPurposes[3] == ScanPurpose::METADATA_ONLY) ;
	}

	// 両planが成立した場合だけroute shapeがpurposeと独立していることを確認する。
	if( standardPlan && metadataPlan) {
		DRIVERCRATE_EXPECT( context, standardPlan->routes.size() == metadataPlan->routes.size()) ;
		DRIVERCRATE_EXPECT( context, standardPlan->routes.front().routeId ==
										metadataPlan->routes.front().routeId) ;
	}

	std::uint32_t genericCalls{} ;	// 専用成功後の汎用resolver呼出し回数。
	registrations.front().resolver = []( const OfficialDiscoveryRequest &,
										const OfficialDiscoveryRoute &route,
										std::span<const OfficialDiscoveryDeviceHint>) {
		return makeRouteResult( route, OfficialDiscoveryRouteState::DEDICATED_RESOLVED, 1U, 1U) ;
	} ;
	registrations.back().resolver = [&genericCalls]( const OfficialDiscoveryRequest &,
													const OfficialDiscoveryRoute &route,
													std::span<const OfficialDiscoveryDeviceHint>) {
		++genericCalls ;
		return makeRouteResult( route, OfficialDiscoveryRouteState::GENERIC_RESOLVED, 1U, 1U) ;
	} ;
	const auto resolvedPlan = makeOfficialDiscoveryRoutePlan(
		binding, standardRequest, true, devices, registrations, providers) ;	// 専用成功plan。
	std::optional<OfficialDiscoverySummary> resolvedSummary ;					// 重複抑止後の結果。
	// Planが成立した場合だけ専用成功resolverを実行する。
	if( resolvedPlan) {
		resolvedSummary = runOfficialDiscoveryRoutePlan( binding, standardRequest, *resolvedPlan,
														devices, registrations, providers) ;
	}

	DRIVERCRATE_EXPECT( context, resolvedSummary.has_value()) ;
	DRIVERCRATE_EXPECT( context, genericCalls == 0U) ;
	// 結果が成立した場合だけ汎用routeのskip状態を確認する。
	if( resolvedSummary) {
		DRIVERCRATE_EXPECT( context, resolvedSummary->routes.back().state ==
										OfficialDiscoveryRouteState::SKIPPED_AFTER_DEDICATED) ;
	}

	std::vector<OfficialDiscoveryRegistration> genericOnly{
		makeRegistration( OfficialDiscoveryRouteKind::GENERIC_OFFICIAL_ROOT,
						 matchesUsbDevice)} ;	// 専用adapter欠損fixture。
	genericOnly.front().resolver = []( const OfficialDiscoveryRequest &,
									  const OfficialDiscoveryRoute &route,
									  std::span<const OfficialDiscoveryDeviceHint>) {
		return makeRouteResult( route, OfficialDiscoveryRouteState::GENERIC_RESOLVED, 1U, 1U) ;
	} ;
	const auto genericOnlyPlan = makeOfficialDiscoveryRoutePlan(
		binding, standardRequest, true, devices, genericOnly, providers) ;	// 汎用だけのplan。
	DRIVERCRATE_EXPECT( context, genericOnlyPlan.has_value()) ;
	std::optional<OfficialDiscoverySummary> genericOnlySummary ;	// 専用欠損を保持する結果。
	// Planが成立した場合だけ汎用resolverへ渡す。
	if( genericOnlyPlan) {
		genericOnlySummary = runOfficialDiscoveryRoutePlan(
			binding, standardRequest, *genericOnlyPlan, devices, genericOnly, providers) ;
	}

	DRIVERCRATE_EXPECT( context, genericOnlySummary.has_value()) ;
	// 汎用結果が成立した場合だけ専用欠損集合を確認する。
	if( genericOnlySummary) {
		DRIVERCRATE_EXPECT( context,
						   genericOnlySummary->dedicatedUnavailableDeviceIdentities.size() == 1U) ;
		DRIVERCRATE_EXPECT( context, genericOnlySummary->noTrustedRootDeviceIdentities.empty()) ;
	}

	std::vector<OfficialDiscoveryRegistration> noMatch{makeRegistration(
		OfficialDiscoveryRouteKind::DEDICATED, matchesPciDevice)} ;	// 固定rootに一致しないfixture。
	const auto noRootPlan = makeOfficialDiscoveryRoutePlan( binding, standardRequest, true, devices,
														   noMatch, providers) ;	// Routeなしplan。
	DRIVERCRATE_EXPECT( context, noRootPlan.has_value()) ;
	std::optional<OfficialDiscoverySummary> noRootSummary ;	// NO_TRUSTED_ROOTだけの結果。
	// Planが成立した場合だけrouteなしexecutorへ渡す。
	if( noRootPlan) {
		noRootSummary = runOfficialDiscoveryRoutePlan( binding, standardRequest, *noRootPlan,
													  devices, noMatch, providers) ;
	}

	DRIVERCRATE_EXPECT( context, noRootSummary.has_value()) ;
	// Routeなし結果が成立した場合だけ明示分類を確認する。
	if( noRootSummary) {
		DRIVERCRATE_EXPECT( context, noRootSummary->routes.empty()) ;
		DRIVERCRATE_EXPECT( context, noRootSummary->noTrustedRootDeviceIdentities.size() == 1U) ;
	}
}

/**
 * @brief HTTP前の制御終端とProvider別scan状態への変換を検証する。
 * @param[in,out] context Assertionの集計先。
 */
void testProviderScanResultProjection( TestContext &context)
{
	std::vector<ProviderDescriptor> providers = makeDiscoveryProviders() ;	// 合成registry。
	OfficialDiscoveryRequest		request	  = makeRequest() ;				// 通常scan要求。
	const OfficialDiscoveryBinding	binding{
		 .operationId = 41U, .scanSessionId = 43U, .inventoryGeneration = 47U} ;	// 開始binding。
	OfficialDiscoveryDeviceHint device = makeDevice( binding.scanSessionId) ;		// USB device。
	device.bus						   = OfficialDiscoveryDeviceBus::USB ;
	std::vector<OfficialDiscoveryDeviceHint>   devices{device} ;	// 一件の完全inventory。
	std::vector<OfficialDiscoveryRegistration> registrations{makeRegistration(
		OfficialDiscoveryRouteKind::DEDICATED, matchesUsbDevice)} ;	// 一route fixture。
	const auto plan = makeOfficialDiscoveryRoutePlan( binding, request, true, devices, registrations,
													 providers) ;	// 検証済みplan。
	DRIVERCRATE_EXPECT( context, plan.has_value()) ;
	// Planが成立しない場合は後続参照を避けて失敗assertionだけを残す。
	if( !plan) {
		return ;
	}

	const auto networkSummary = makeOfficialDiscoveryControlSummary(
		binding, request, *plan, devices, registrations, providers,
		OfficialDiscoveryRouteState::NETWORK_NOT_APPROVED) ;	// HTTP未実行結果。
	DRIVERCRATE_EXPECT( context, networkSummary.has_value()) ;
	std::optional<ScanResult> networkResult ;	// Provider状態への変換結果。
	// Summaryが有効な場合だけProvider変換を実行する。
	if( networkSummary) {
		networkResult = makeOfficialDiscoveryProviderScanResult(
			binding.scanSessionId, PROLIFIC_OFFICIAL_PROVIDER_ID, devices, *plan, *networkSummary,
			providers) ;
	}

	DRIVERCRATE_EXPECT( context, networkResult.has_value()) ;
	// 変換結果がある場合だけ回線未許可と未判定coverageを確認する。
	if( networkResult) {
		DRIVERCRATE_EXPECT(
			context, networkResult->succeeded && networkResult->outcome == OutcomeCode::SUCCESS &&
						 networkResult->state == ProviderScanState::NETWORK_NOT_APPROVED) ;
		DRIVERCRATE_EXPECT( context, networkResult->coverage.eligibleDeviceCount == 1U &&
										networkResult->coverage.assessedDeviceCount == 0U) ;
	}

	DRIVERCRATE_EXPECT( context, !makeOfficialDiscoveryControlSummary(
									 binding, request, *plan, devices, registrations, providers,
									 OfficialDiscoveryRouteState::NO_RECORD)
									 .has_value()) ;
	registrations.front().resolver = []( const OfficialDiscoveryRequest &,
										const OfficialDiscoveryRoute &route,
										std::span<const OfficialDiscoveryDeviceHint>) {
		return makeRouteResult( route, OfficialDiscoveryRouteState::DEDICATED_RESOLVED, 1U, 1U) ;
	} ; // Payload metadataを一件解決するresolver。
	const auto resolvedSummary = runOfficialDiscoveryRoutePlan(
		binding, request, *plan, devices, registrations, providers) ;	// 解決結果。
	DRIVERCRATE_EXPECT( context, resolvedSummary.has_value()) ;
	std::optional<ScanResult> resolvedResult ;	// 未取得状態への変換結果。
	// Summaryが成立した場合だけ同じplanへ再結合する。
	if( resolvedSummary) {
		resolvedResult = makeOfficialDiscoveryProviderScanResult(
			binding.scanSessionId, PROLIFIC_OFFICIAL_PROVIDER_ID, devices, *plan, *resolvedSummary,
			providers) ;
	}

	DRIVERCRATE_EXPECT( context, resolvedResult.has_value()) ;
	// Metadata解決だけを候補または取得成功へ昇格させない。
	if( resolvedResult) {
		DRIVERCRATE_EXPECT( context,
						   resolvedResult->succeeded &&
							   resolvedResult->state == ProviderScanState::PAYLOAD_NOT_APPROVED &&
							   resolvedResult->candidates.empty()) ;
		DRIVERCRATE_EXPECT( context, resolvedResult->coverage.eligibleDeviceCount == 1U &&
										resolvedResult->coverage.assessedDeviceCount == 1U) ;
	}

	DRIVERCRATE_EXPECT( context, resolvedSummary && !makeOfficialDiscoveryProviderScanResult(
														binding.scanSessionId, L"unknown-provider",
														devices, *plan, *resolvedSummary, providers)
														.has_value()) ;

	std::vector<OfficialDiscoveryRegistration> noMatch{makeRegistration(
		OfficialDiscoveryRouteKind::DEDICATED, matchesPciDevice)} ;	// 対象routeなしfixture。
	const auto								   noMatchPlan =
		makeOfficialDiscoveryRoutePlan( binding, request, true, devices, noMatch,
									   providers) ;	// Routeなしplan。
	DRIVERCRATE_EXPECT( context, noMatchPlan.has_value()) ;
	std::optional<OfficialDiscoverySummary> noMatchSummary ;	// Routeなし公開summary。
	std::optional<ScanResult>				noMatchResult ;		// 対象外Provider結果。
	// Planが成立した場合だけnetworkを呼ばないexecutorと変換を確認する。
	if( noMatchPlan) {
		noMatchSummary = runOfficialDiscoveryRoutePlan( binding, request, *noMatchPlan, devices,
													   noMatch, providers) ;
		// Summaryが成立した場合だけProvider結果へ変換する。
		if( noMatchSummary) {
			noMatchResult = makeOfficialDiscoveryProviderScanResult(
				binding.scanSessionId, PROLIFIC_OFFICIAL_PROVIDER_ID, devices, *noMatchPlan,
				*noMatchSummary, providers) ;
		}
	}

	DRIVERCRATE_EXPECT( context, noMatchSummary.has_value() && noMatchResult.has_value()) ;
	DRIVERCRATE_EXPECT( context, noMatchResult && noMatchResult->succeeded &&
									noMatchResult->state == ProviderScanState::NOT_APPLICABLE &&
									noMatchResult->coverage.eligibleDeviceCount == 0U) ;
}

/**
 * @brief Fresh cache、cache miss、通信未許可と明示refreshの実行順を検証します。
 * @param[in,out] context Assertionの集計先です。
 */
void testRouteCachePriority( TestContext &context)
{
	std::vector<ProviderDescriptor> providers = makeDiscoveryProviders() ;	// 合成registry。
	OfficialDiscoveryRequest		request	  = makeRequest() ;				// Fresh cacheを許可する通常要求。
	const OfficialDiscoveryBinding	binding{
		 .operationId = 41U, .scanSessionId = 43U, .inventoryGeneration = 47U} ;	// 開始時binding。
	const std::vector devices{makeDevice( binding.scanSessionId)} ;					// 一件の完全inventory。
	std::uint32_t	  resolverCalls{} ;												// Cache miss時だけ増えるresolver回数。
	std::vector<OfficialDiscoveryRegistration> registrations{makeRegistration(
		OfficialDiscoveryRouteKind::DEDICATED, matchesAnyDevice)} ;	// 固定root一件。
	registrations.front().resolver =
		[&resolverCalls]( const OfficialDiscoveryRequest &, const OfficialDiscoveryRoute &route,
						 std::span<const OfficialDiscoveryDeviceHint>) {
			++resolverCalls ;
			return makeRouteResult( route, OfficialDiscoveryRouteState::NO_RECORD) ;
		} ; // Network resolverの呼出し回数を観測するfixture。
	const auto plan = makeOfficialDiscoveryRoutePlan( binding, request, true, devices, registrations,
													 providers) ;	// Fresh cache要求の一route plan。
	DRIVERCRATE_EXPECT( context, plan.has_value() && plan->routes.size() == 1U) ;
	// Planが成立しない場合はroute参照を避け、以降の検証を打ち切ります。
	if( !plan || plan->routes.size() != 1U) {
		return ;
	}

	std::uint32_t							cacheCalls{} ;	// Fresh要求でだけ増えるcache照会回数。
	const OfficialDiscoveryRouteCacheLookup positiveCache =
		[&cacheCalls]( const OfficialDiscoveryRequest &, const OfficialDiscoveryRoute &route) {
			++cacheCalls ;
			return std::optional{
				makeRouteResult( route, OfficialDiscoveryRouteState::CACHE_POSITIVE, 1U, 1U)} ;
		} ; // URLやgrantを返さないpositive cache fixture。
	const auto cached =
		runOfficialDiscoveryRoutePlan( binding, request, *plan, devices, registrations, providers,
									  positiveCache, false) ;	// 通信未許可でもcacheを優先。
	DRIVERCRATE_EXPECT( context,
					   cached.has_value() && cached->routes.front().state ==
												 OfficialDiscoveryRouteState::CACHE_POSITIVE) ;
	DRIVERCRATE_EXPECT( context, cacheCalls == 1U && resolverCalls == 0U) ;

	const OfficialDiscoveryRouteCacheLookup invalidCache = []( const OfficialDiscoveryRequest &,
															  const OfficialDiscoveryRoute &route) {
		return std::optional{
			makeRouteResult( route, OfficialDiscoveryRouteState::DEDICATED_RESOLVED, 1U, 1U)} ;
	} ; // Cache callbackが返せないnetwork解決状態です。
	const auto rejectedCache = runOfficialDiscoveryRoutePlan(
		binding, request, *plan, devices, registrations, providers, invalidCache,
		false) ;	// 不正cacheを採用せず通信未許可へ閉じる結果。
	DRIVERCRATE_EXPECT( context, rejectedCache.has_value() &&
									rejectedCache->routes.front().state ==
										OfficialDiscoveryRouteState::NETWORK_NOT_APPROVED) ;
	DRIVERCRATE_EXPECT( context, resolverCalls == 0U) ;

	OfficialDiscoveryRequest refreshRequest = request ;	// Cache照会を禁止する明示refresh要求。
	refreshRequest.cacheMode				= OfficialDiscoveryCacheMode::FORCE_REFRESH ;
	const auto refreshPlan					= makeOfficialDiscoveryRoutePlan(
		 binding, refreshRequest, true, devices, registrations, providers) ;	// Refresh専用plan。
	DRIVERCRATE_EXPECT( context, refreshPlan.has_value()) ;
	// Refresh planが成立した場合だけ同じcache callbackを渡して非呼出しを確認します。
	if( refreshPlan) {
		const auto refreshed = runOfficialDiscoveryRoutePlan(
			binding, refreshRequest, *refreshPlan, devices, registrations, providers, positiveCache,
			false) ;	// 通信未許可によりresolverも開始しない結果。
		DRIVERCRATE_EXPECT( context, refreshed.has_value() &&
										refreshed->routes.front().state ==
											OfficialDiscoveryRouteState::NETWORK_NOT_APPROVED) ;
	}

	DRIVERCRATE_EXPECT( context, cacheCalls == 1U && resolverCalls == 0U) ;
	const auto cacheMiss =
		runOfficialDiscoveryRoutePlan( binding, request, *plan, devices, registrations, providers,
									  {}, true) ;	// 許可済みresolver結果。
	DRIVERCRATE_EXPECT( context,
					   cacheMiss.has_value() && cacheMiss->routes.front().state ==
													OfficialDiscoveryRouteState::NO_RECORD) ;
	DRIVERCRATE_EXPECT( context, resolverCalls == 1U) ;
}

/**
 * @brief 上限、stale、raw ID、重複、callback失敗のnegative fixtureを検証する。
 * @param[in,out] context Assertionの集計先。
 */
void testDiscoveryNegativeFixtures( TestContext &context)
{
	std::vector<ProviderDescriptor> providers = makeDiscoveryProviders() ;	// 合成registry。
	OfficialDiscoveryRequest		request	  = makeRequest() ;				// Prolific一件の通常要求。
	const OfficialDiscoveryBinding	binding{
		 .operationId = 29U, .scanSessionId = 31U, .inventoryGeneration = 37U} ;	// 基準binding。
	OfficialDiscoveryDeviceHint device =
		// 表示欠損・未知bus正例。
		makeDevice( binding.scanSessionId) ;
	std::vector<OfficialDiscoveryDeviceHint>   devices{device} ;	// 一件の完全inventory。
	std::vector<OfficialDiscoveryRegistration> registrations{makeRegistration(
		OfficialDiscoveryRouteKind::DEDICATED, matchesAnyDevice)} ;	// 全表示欠損を保持する固定root。
	const auto								   missingDisplayPlan = makeOfficialDiscoveryRoutePlan(
		binding, request, true, devices, registrations, providers) ;	// UNKNOWN bus／空表示のplan。
	DRIVERCRATE_EXPECT( context, missingDisplayPlan.has_value()) ;
	// Planが成立した場合だけrouteが表示値を含まないことを確認する。
	if( missingDisplayPlan) {
		DRIVERCRATE_EXPECT( context, missingDisplayPlan->routes.size() == 1U) ;
		DRIVERCRATE_EXPECT( context,
						   missingDisplayPlan->routes.front().hintGroupIdentity == L"hint-group:1") ;
		DRIVERCRATE_EXPECT( context, missingDisplayPlan->routes.front().deviceIdentities.front() ==
										device.deviceIdentity) ;
	}

	OfficialDiscoveryDeviceHint staleDevice = device ;	// 古いsession観測の拒否用copy。
	staleDevice.observation.scanSessionId	= binding.scanSessionId + 1U ;
	std::vector<OfficialDiscoveryDeviceHint> staleDevices{staleDevice} ;	// Stale inventory。
	DRIVERCRATE_EXPECT( context, !makeOfficialDiscoveryRoutePlan(
									 binding, request, true, staleDevices, registrations, providers)
									 .has_value()) ;
	DRIVERCRATE_EXPECT( context, !makeOfficialDiscoveryRoutePlan( binding, request, false, devices,
																registrations, providers)
									 .has_value()) ;

	OfficialDiscoveryDeviceHint rawDisplayDevice = device ;	// Raw ID形式の表示値拒否用copy。
	rawDisplayDevice.model						 = L"USB\\VID_fixture" ;
	std::vector<OfficialDiscoveryDeviceHint> rawDisplayDevices{rawDisplayDevice} ;	// 不正hint集合。
	DRIVERCRATE_EXPECT( context,
					   !makeOfficialDiscoveryRoutePlan( binding, request, true, rawDisplayDevices,
													   registrations, providers)
							.has_value()) ;

	OfficialDiscoveryRegistration invalidRegistration =
		// Policy不一致用copy。
		registrations.front() ;
	invalidRegistration.sourcePolicyId = SILICON_LABS_OFFICIAL_SOURCE_POLICY_ID ;
	DRIVERCRATE_EXPECT(
		context,
		!validateOfficialDiscoveryRegistrations(
			std::span<const OfficialDiscoveryRegistration>( &invalidRegistration, 1U), providers)) ;
	invalidRegistration			   = registrations.front() ;
	invalidRegistration.providerId = L"unknown-provider" ;
	DRIVERCRATE_EXPECT(
		context,
		!validateOfficialDiscoveryRegistrations(
			std::span<const OfficialDiscoveryRegistration>( &invalidRegistration, 1U), providers)) ;
	invalidRegistration			= registrations.front() ;
	invalidRegistration.matcher = nullptr ;
	DRIVERCRATE_EXPECT(
		context,
		!validateOfficialDiscoveryRegistrations(
			std::span<const OfficialDiscoveryRegistration>( &invalidRegistration, 1U), providers)) ;
	invalidRegistration		 = registrations.front() ;
	invalidRegistration.kind = static_cast<OfficialDiscoveryRouteKind>( 99) ;
	DRIVERCRATE_EXPECT(
		context,
		!validateOfficialDiscoveryRegistrations(
			std::span<const OfficialDiscoveryRegistration>( &invalidRegistration, 1U), providers)) ;

	std::vector<OfficialDiscoveryDeviceHint> overRouteDevices ;	// 64 route上限超過fixture。
	overRouteDevices.reserve( OFFICIAL_DISCOVERY_ROUTE_LIMIT + 1U) ;
	// 異なるmodelの65 deviceを一registrationへ渡し、group単位の上限拒否を発生させる。
	for( std::size_t index = 0U; index <= OFFICIAL_DISCOVERY_ROUTE_LIMIT; ++index) {
		OfficialDiscoveryDeviceHint item = makeDevice( binding.scanSessionId) ;	// 一意な架空device。
		item.deviceIdentity				 = L"fixture-node:" + std::to_wstring( index + 1U) ;
		item.observation.deviceIdentity	 = item.deviceIdentity ;
		item.model						 = L"Fixture Model " + std::to_wstring( index + 1U) ;
		overRouteDevices.push_back( std::move( item)) ;
	}

	DRIVERCRATE_EXPECT( context,
					   !makeOfficialDiscoveryRoutePlan( binding, request, true, overRouteDevices,
													   registrations, providers)
							.has_value()) ;

	OfficialDiscoveryDeviceHint second = device ;	// 同じ正規化hintの別device。
	second.deviceIdentity			   = L"fixture-node-2" ;
	second.observation.deviceIdentity  = second.deviceIdentity ;
	std::vector<OfficialDiscoveryDeviceHint> groupedDevices{device, second} ;	// 重複排除正例。
	const auto								 groupedPlan =
		makeOfficialDiscoveryRoutePlan( binding, request, true, groupedDevices, registrations,
									   providers) ;	// 一route二deviceのplan。
	DRIVERCRATE_EXPECT( context, groupedPlan.has_value()) ;
	// Planが成立した場合だけ重複実行keyの改変を検証する。
	if( groupedPlan) {
		DRIVERCRATE_EXPECT( context, groupedPlan->routes.size() == 1U) ;
		DRIVERCRATE_EXPECT( context, groupedPlan->routes.front().deviceIdentities.size() == 2U) ;
		OfficialDiscoveryRoutePlan duplicateRoutePlan = *groupedPlan ;				// 同じ実行keyの不正copy。
		OfficialDiscoveryRoute duplicateRoute = duplicateRoutePlan.routes.front() ;	// 重複route。
		duplicateRoute.routeId				  = 2U ;
		duplicateRoute.hintGroupIdentity	  = L"hint-group:2" ;
		duplicateRoutePlan.routes.push_back( duplicateRoute) ;
		DRIVERCRATE_EXPECT( context, !isOfficialDiscoveryRoutePlanValid(
										binding, request, groupedDevices, registrations, providers,
										duplicateRoutePlan)) ;
	}

	registrations.front().resolver = []( const OfficialDiscoveryRequest &,
										const OfficialDiscoveryRoute &,
										std::span<const OfficialDiscoveryDeviceHint>) {
		return OfficialDiscoveryRouteSummary{} ;
	} ; // Identityと件数を欠く不正resolver。
	const auto invalidResolverPlan = makeOfficialDiscoveryRoutePlan(
		binding, request, true, devices, registrations, providers) ;	// 不正結果用plan。
	std::optional<OfficialDiscoverySummary> rejectedSummary ;			// Metadata拒否への変換結果。
	// Planが成立した場合だけ不正resolverを呼び出す。
	if( invalidResolverPlan) {
		rejectedSummary = runOfficialDiscoveryRoutePlan( binding, request, *invalidResolverPlan,
														devices, registrations, providers) ;
	}

	DRIVERCRATE_EXPECT( context, rejectedSummary.has_value()) ;
	// 結果が成立した場合だけ不正summaryの有限拒否状態を確認する。
	if( rejectedSummary) {
		DRIVERCRATE_EXPECT( context, rejectedSummary->routes.front().state ==
										OfficialDiscoveryRouteState::METADATA_REJECTED) ;
		DRIVERCRATE_EXPECT( context, rejectedSummary->routes.front().error != 0) ;
	}

	registrations.front().resolver =
		[]( const OfficialDiscoveryRequest &, const OfficialDiscoveryRoute &,
		   std::span<const OfficialDiscoveryDeviceHint>) -> OfficialDiscoveryRouteSummary {
		throw std::runtime_error( "fixture resolver failure") ;
	} ; // Callback例外を有限失敗へ変換するfixture。
	const auto exceptionPlan = makeOfficialDiscoveryRoutePlan(
		binding, request, true, devices, registrations, providers) ;	// 例外結果用plan。
	std::optional<OfficialDiscoverySummary> failedSummary ;				// 例外の有限変換結果。
	// Planが成立した場合だけ例外resolverを呼び出す。
	if( exceptionPlan) {
		failedSummary = runOfficialDiscoveryRoutePlan( binding, request, *exceptionPlan, devices,
													  registrations, providers) ;
	}

	DRIVERCRATE_EXPECT( context, failedSummary.has_value()) ;
	// 結果が成立した場合だけ例外診断を確認する。
	if( failedSummary) {
		DRIVERCRATE_EXPECT( context, failedSummary->routes.front().state ==
										OfficialDiscoveryRouteState::FAILED) ;
		DRIVERCRATE_EXPECT( context, failedSummary->routes.front().error != 0) ;
	}

	// Planのbinding改変をresolver呼出し前に拒否する。
	if( exceptionPlan) {
		OfficialDiscoveryRoutePlan stalePlan = *exceptionPlan ;	// 遅延結果を模した改変copy。
		stalePlan.binding.inventoryGeneration++ ;
		DRIVERCRATE_EXPECT( context,
						   !runOfficialDiscoveryRoutePlan( binding, request, stalePlan, devices,
														  registrations, providers)
								.has_value()) ;
	}
}

/**
 * @brief 固定root routeと公開summaryの一対一bindingを検証する。
 * @param[in,out] context Assertionの集計先。
 */
void testRouteAndSummaryValidation( TestContext &context)
{
	std::vector<ProviderDescriptor> providers = makeDiscoveryProviders() ;	// 合成registry。
	OfficialDiscoveryBinding		binding{
			   .operationId = 3U, .scanSessionId = 7U, .inventoryGeneration = 11U} ;	// 開始時binding。
	OfficialDiscoveryRequest				 request = makeRequest() ;					// 開始時request。
	// 同じsessionへ結合した一deviceの有限hint集合。
	std::vector<OfficialDiscoveryDeviceHint> devices{makeDevice( binding.scanSessionId)} ;
	std::vector<OfficialDiscoveryRoute>		 routes{makeRoute()} ;	// 一つの固定root route。
	DRIVERCRATE_EXPECT( context, validateOfficialDiscoveryRoute( routes.front(), devices, providers)) ;

	OfficialDiscoveryRoute invalidRoute = routes.front() ;	// 個別route拒否用copy。
	invalidRoute.rootResourceId			= OFFICIAL_PAYLOAD_RESOURCE_ID ;
	DRIVERCRATE_EXPECT( context, !validateOfficialDiscoveryRoute( invalidRoute, devices, providers)) ;
	invalidRoute = routes.front() ;
	invalidRoute.deviceIdentities.emplace_back( L"fixture-node") ;
	DRIVERCRATE_EXPECT( context, !validateOfficialDiscoveryRoute( invalidRoute, devices, providers)) ;
	invalidRoute	  = routes.front() ;
	invalidRoute.kind = static_cast<OfficialDiscoveryRouteKind>( 99) ;
	DRIVERCRATE_EXPECT( context, !validateOfficialDiscoveryRoute( invalidRoute, devices, providers)) ;

	OfficialDiscoverySummary summary = makeSummary( binding, request) ;	// 基準となる有効summary。
	DRIVERCRATE_EXPECT( context, isOfficialDiscoverySummaryValid( binding, request, devices, routes,
																summary, providers)) ;
	summary.binding.scanSessionId++ ;
	DRIVERCRATE_EXPECT( context, !isOfficialDiscoverySummaryValid( binding, request, devices, routes,
																 summary, providers)) ;
	summary					  = makeSummary( binding, request) ;
	summary.inventoryComplete = false ;
	DRIVERCRATE_EXPECT( context, !isOfficialDiscoverySummaryValid( binding, request, devices, routes,
																 summary, providers)) ;
	summary						 = makeSummary( binding, request) ;
	summary.routes.front().state = OfficialDiscoveryRouteState::NO_RECORD ;
	DRIVERCRATE_EXPECT( context, !isOfficialDiscoverySummaryValid( binding, request, devices, routes,
																 summary, providers)) ;
	summary.routes.front().recordCount	= 0U ;
	summary.routes.front().packageCount = 0U ;
	DRIVERCRATE_EXPECT( context, isOfficialDiscoverySummaryValid( binding, request, devices, routes,
																summary, providers)) ;
	summary.routes.front().state = OfficialDiscoveryRouteState::FAILED ;
	DRIVERCRATE_EXPECT( context, !isOfficialDiscoverySummaryValid( binding, request, devices, routes,
																 summary, providers)) ;
	summary.routes.front().error = -1 ;
	DRIVERCRATE_EXPECT( context, isOfficialDiscoverySummaryValid( binding, request, devices, routes,
																summary, providers)) ;
	summary.routes.front().state = static_cast<OfficialDiscoveryRouteState>( 99) ;
	DRIVERCRATE_EXPECT( context, !isOfficialDiscoverySummaryValid( binding, request, devices, routes,
																 summary, providers)) ;

	summary							 = makeSummary( binding, request) ;
	OfficialDiscoveryRoute duplicate = routes.front() ;	// 同じ実行keyの重複route。
	duplicate.routeId				 = 2U ;
	routes.push_back( duplicate) ;
	summary.routes.push_back( summary.routes.front()) ;
	summary.routes.back().routeId = 2U ;
	DRIVERCRATE_EXPECT( context, !isOfficialDiscoverySummaryValid( binding, request, devices, routes,
																 summary, providers)) ;
}

} // namespace

/** @see official_discovery_tests.h */
void runOfficialDiscoveryTests( TestContext &context)
{
	testRequestValidation( context) ;
	testStandardApprovalMapping( context) ;
	testDeviceValidation( context) ;
	testInventoryHintProjection( context) ;
	testRoutePlanner( context) ;
	testRoutePlanExecution( context) ;
	testProviderScanResultProjection( context) ;
	testRouteCachePriority( context) ;
	testDiscoveryNegativeFixtures( context) ;
	testRouteAndSummaryValidation( context) ;
}

} // namespace drivercrate::test
