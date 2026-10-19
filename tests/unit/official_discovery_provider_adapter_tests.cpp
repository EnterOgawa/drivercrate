//------------------------------------------------------------------------------
/**
 * @file official_discovery_provider_adapter_tests.cpp
 * @brief 組み込み公式自動探索registration接続試験を実装する。
 * @version 01.01.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  固定root registration接続試験を実装。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  部分失敗・重複・privacy試験を実装。
 * Ver.01.01.01 Shunji Ogawa  2026/09/15  Cache parser identityの固定登録を検証。
 * </pre>
 *
 * @note Resolverは有限な合成結果だけを返し、URL、Hardware ID、instance ID、serialを扱わない。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#include "official_discovery_provider_adapter_tests.h"

#include "core/official_discovery_execution.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/official_discovery_provider_adapter.h"
#include "platform/intel_ethernet_windows11_record_adapter.h"
#include "platform/official_release_metadata.h"
#include "test_framework.h"

#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {

// Registration接続試験のoperation ID。
constexpr OperationId					  OPERATION_ID = 6'101U ;
// Registration接続試験のscan session ID。
constexpr ScanSessionId					  SESSION_ID = 6'201U ;
// Registration接続試験のinventory generation。
constexpr std::uint64_t					  INVENTORY_GENERATION = 6'301U ;

/**
 * @brief Intel E610表示を持つraw ID非保持device hintを作る。
 * @param[in] sessionId 観測元scan session ID。
 * @param[in] identity UI行へ結合する架空opaque identity。
 * @return PCI Net classへ固定した有効hint。
 */
[[nodiscard]] OfficialDiscoveryDeviceHint makeIntelEthernetDevice( const ScanSessionId sessionId,
																  std::wstring		  identity)
{
	OfficialDiscoveryDeviceHint device ;	// 実PnP IDを含まない合成device。
	device.deviceIdentity			  = std::move( identity) ;
	device.bus						  = OfficialDiscoveryDeviceBus::PCI ;
	device.setupClassGuid			  = L"{4d36e972-e325-11ce-bfc1-08002be10318}" ;
	device.deviceClass				  = L"Net" ;
	device.manufacturer				  = L"Intel Corporation" ;
	device.model					  = L"Intel(R) Ethernet Network Adapter E610-XT2" ;
	device.observation.scanSessionId  = sessionId ;
	device.observation.deviceIdentity = device.deviceIdentity ;
	return device ;
}

/**
 * @brief Intel Windows 11 Provider一件だけを明示するmetadata専用要求を作る。
 * @return Payload取得許可を持たない有効request。
 */
[[nodiscard]] OfficialDiscoveryRequest makeRequest()
{
	OfficialDiscoveryRequest request ;	// 固定root metadataだけを許可する開始要求。
	request.purpose				= ScanPurpose::METADATA_ONLY ;
	request.useDefaultProviders = false ;
	request.enabledProviderIds	= {std::wstring{INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID}} ;
	return request ;
}

/**
 * @brief E610 matcherがbus、class、manufacturer、系列表示をfail-closedで判定することを確認する。
 * @param[in,out] context Assertion集計先。
 */
void testIntelMatcher( TestContext &context)
{
	const OfficialDiscoveryDeviceHint baseline =
		// 合格基準。
		makeIntelEthernetDevice( SESSION_ID, L"fixture-device:intel-e610") ;
	DRIVERCRATE_EXPECT( context, matchesIntelEthernetWindows11OfficialDiscoveryHint( baseline)) ;
	OfficialDiscoveryDeviceHint otherListedSeries = baseline ;	// 固定page末尾の掲載系列。
	otherListedSeries.model						  = L"Intel(R) Ethernet Network Adapter E835" ;
	DRIVERCRATE_EXPECT( context,
					   matchesIntelEthernetWindows11OfficialDiscoveryHint( otherListedSeries)) ;

	OfficialDiscoveryDeviceHint wrongBus = baseline ;	// USBへ差し替えた同名device。
	wrongBus.bus						 = OfficialDiscoveryDeviceBus::USB ;
	DRIVERCRATE_EXPECT( context, !matchesIntelEthernetWindows11OfficialDiscoveryHint( wrongBus)) ;
	OfficialDiscoveryDeviceHint wrongClass = baseline ;	// Display classへ差し替えたdevice。
	wrongClass.setupClassGuid			   = L"{4d36e968-e325-11ce-bfc1-08002be10318}" ;
	wrongClass.deviceClass				   = L"Display" ;
	DRIVERCRATE_EXPECT( context, !matchesIntelEthernetWindows11OfficialDiscoveryHint( wrongClass)) ;
	OfficialDiscoveryDeviceHint wrongVendor = baseline ;	// 別メーカー表示へ差し替えたdevice。
	wrongVendor.manufacturer				= L"Fictional Vendor" ;
	DRIVERCRATE_EXPECT( context, !matchesIntelEthernetWindows11OfficialDiscoveryHint( wrongVendor)) ;
	OfficialDiscoveryDeviceHint wrongSeries = baseline ;	// Ethernet掲載系列を持たないIntel device。
	wrongSeries.model						= L"Intel(R) Wi-Fi 7 Adapter" ;
	DRIVERCRATE_EXPECT( context, !matchesIntelEthernetWindows11OfficialDiscoveryHint( wrongSeries)) ;
}

/**
 * @brief Provider正本から作ったregistrationを共通planner／executorへ接続する。
 * @param[in,out] context Assertion集計先。
 */
void testRegistrationConnection( TestContext &context)
{
	OfficialDiscoveryRecordAdapterSession recordSession ;		// 秘密recordを保持するworker相当session。
	std::uint32_t						  callCount{} ;			// 固定resolverの実行回数。
	bool								  fixedRootObserved{} ;	// 固定root引数の一致状態。
	const OfficialDiscoveryFixedRootResolver resolver =
		[&callCount, &fixedRootObserved](
			const ScanSessionId scanSessionId, const std::uint64_t recordEvidenceId,
			const std::wstring_view providerId, const std::wstring_view rootResourceId,
			const std::wstring_view builtInRootUrl, const std::uint64_t maximumRecordBytes,
			const OfficialRecordFetchMode fetchMode, OfficialDistributionRecord &) {
			++callCount ;
			const OfficialSourceDefinition *const definition = officialSourceDefinition(
				OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11) ;	// 固定定義の正本。
			fixedRootObserved = definition != nullptr && scanSessionId == SESSION_ID &&
								recordEvidenceId == 1U &&
								providerId == INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID &&
								rootResourceId == OFFICIAL_LANDING_RESOURCE_ID &&
								builtInRootUrl == definition->landingUrl &&
								maximumRecordBytes == definition->maximumMetadataBytes &&
								fetchMode == OfficialRecordFetchMode::BYPASS_CACHE ;
			return OfficialDiscoveryFixedRootResult{
				.state = OfficialDiscoveryFixedRootState::NO_RECORD, .error = 0} ;
		} ; // Networkを使わず固定引数だけを観測するresolver。
	const auto descriptors	 = builtInProviderDescriptors() ;	// Capabilityを含むProvider正本。
	const auto registrations = makeBuiltInOfficialDiscoveryRegistrations(
		recordSession, resolver, []() noexcept { return false ; }, descriptors) ;	// 接続結果。
	DRIVERCRATE_EXPECT( context, registrations.has_value() && registrations->size() == 1U) ;
	DRIVERCRATE_EXPECT( context,
					   callCount == 0U && recordSession.activeBinding().scanSessionId == 0U) ;
	// Factoryが成功した場合だけ同じ集合を共通planへ渡す。
	if( !registrations) {
		return ;
	}

	DRIVERCRATE_EXPECT( context,
					   validateOfficialDiscoveryRegistrations( *registrations, descriptors)) ;
	DRIVERCRATE_EXPECT( context, registrations->front().parserId ==
										INTEL_ETHERNET_WINDOWS11_RECORD_PARSER_ID &&
									registrations->front().parserRevision ==
										INTEL_ETHERNET_WINDOWS11_RECORD_PARSER_REVISION) ;
	const OfficialDiscoveryRequest request = makeRequest() ;	// 一Provider限定のmetadata要求。
	const OfficialDiscoveryBinding binding{
		OPERATION_ID, SESSION_ID, INVENTORY_GENERATION} ;	// Planとrecord sessionの開始binding。
	const std::vector devices{
		makeIntelEthernetDevice( SESSION_ID, L"fixture-device:intel-e610-port-1"),
		makeIntelEthernetDevice( SESSION_ID,
								L"fixture-device:intel-e610-port-2")} ;	// 同一groupの二port。
	const auto plan = makeOfficialDiscoveryRoutePlan(
		binding, request, true, devices, *registrations, descriptors) ;	// 共通route plan。
	DRIVERCRATE_EXPECT( context, plan.has_value() && plan->routes.size() == 1U &&
									plan->routes.front().deviceIdentities.size() == 2U) ;
	DRIVERCRATE_EXPECT( context, recordSession.beginSession( binding, request, descriptors) == 0) ;
	std::optional<OfficialDiscoverySummary> summary ;	// 共通executorの公開結果。
	// 有効planだけを実行して固定resolverの有限結果を集約する。
	if( plan) {
		summary = runOfficialDiscoveryRoutePlan( binding, request, *plan, devices, *registrations,
												descriptors) ;
	}

	DRIVERCRATE_EXPECT( context, summary.has_value() && summary->routes.size() == 1U) ;
	// 集約結果が存在する場合だけ候補なしのtyped状態を確認する。
	if( summary) {
		DRIVERCRATE_EXPECT( context, summary->routes.front().state ==
											OfficialDiscoveryRouteState::NO_RECORD &&
										summary->routes.front().deviceCount == 2U &&
										summary->routes.front().recordCount == 0U &&
										summary->routes.front().packageCount == 0U) ;
	}

	DRIVERCRATE_EXPECT( context, callCount == 1U && fixedRootObserved) ;
	DRIVERCRATE_EXPECT( context, recordSession.retainedRecordCount() == 0U &&
									recordSession.resolvedPackages().empty()) ;
}

/**
 * @brief 空callbackとCapability不一致をregistration構築前に拒否する。
 * @param[in,out] context Assertion集計先。
 */
void testRegistrationRejections( TestContext &context)
{
	OfficialDiscoveryRecordAdapterSession	 session ;	// 各拒否で未開始を維持するsession。
	const OfficialDiscoveryFixedRootResolver resolver =
		[]( ScanSessionId, std::uint64_t, std::wstring_view, std::wstring_view, std::wstring_view,
		   std::uint64_t, OfficialRecordFetchMode, OfficialDistributionRecord &) {
			return OfficialDiscoveryFixedRootResult{
				.state = OfficialDiscoveryFixedRootState::NO_RECORD, .error = 0} ;
		} ; // Networkを使用しない有効callback。
	const auto descriptors = builtInProviderDescriptors() ;	// 正常なProvider正本。
	DRIVERCRATE_EXPECT( context, !makeBuiltInOfficialDiscoveryRegistrations(
									 session, {}, []() noexcept { return false ; }, descriptors)
									 .has_value()) ;
	DRIVERCRATE_EXPECT(
		context,
		!makeBuiltInOfficialDiscoveryRegistrations( session, resolver, {}, descriptors).has_value()) ;

	std::vector<ProviderDescriptor> missingCapability( descriptors.begin(),
													  // Capabilityを除く合成copy。
													  descriptors.end()) ;
	const auto						intel =
		std::find_if( missingCapability.begin(), missingCapability.end(),
					 []( const ProviderDescriptor &descriptor) {
						 return descriptor.id == INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID ;
					 }) ; // 自動探索Provider定義。
	// 対象Providerが存在する場合だけ自動探索能力を除去する。
	if( intel != missingCapability.end()) {
		intel->capabilities &= ~capabilityMask( ProviderCapability::AUTOMATIC_DISCOVERY) ;
	}

	DRIVERCRATE_EXPECT( context,
					   !makeBuiltInOfficialDiscoveryRegistrations(
							session, resolver, []() noexcept { return false ; }, missingCapability)
							.has_value()) ;
	DRIVERCRATE_EXPECT( context, session.activeBinding().scanSessionId == 0U) ;
}

/**
 * @brief Production resolverが任意rootとcache有効clientを通信前に拒否することを確認する。
 * @param[in,out] context Assertion集計先。
 */
void testProductionResolverPreflight( TestContext &context)
{
	const OfficialSourceDefinition *const definition = officialSourceDefinition(
		OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11) ;	// 固定引数を得る組み込み定義。
	DRIVERCRATE_EXPECT( context, definition != nullptr) ;
	// 組み込み定義を取得できた場合だけ通信前拒否の引数を構築する。
	if( definition == nullptr) {
		return ;
	}

	OfficialHttpClient		   noCacheClient( false) ;	// Network到達前に拒否されるcache無効client。
	OfficialDistributionRecord record ;					// 失敗時に空を維持する秘密record出力。
	const OfficialDiscoveryFixedRootResult arbitraryRoot =
		resolveIntelEthernetWindows11OfficialDiscoveryRecord(
			SESSION_ID, 1U, definition->providerId, OFFICIAL_LANDING_RESOURCE_ID,
			L"https://fixture.invalid/not-the-built-in-root", definition->maximumMetadataBytes,
			OfficialRecordFetchMode::BYPASS_CACHE, noCacheClient, record) ;	// 任意root入力。
	DRIVERCRATE_EXPECT( context,
					   arbitraryRoot.state == OfficialDiscoveryFixedRootState::METADATA_REJECTED &&
						   arbitraryRoot.error != 0 && record.recordEvidenceId == 0U &&
						   noCacheClient.sourceEvidence().empty()) ;

	OfficialHttpClient cachedClient( true) ;	// 自動探索recordでは許可しないcache有効client。
	const OfficialDiscoveryFixedRootResult cached =
		resolveIntelEthernetWindows11OfficialDiscoveryRecord(
			SESSION_ID, 1U, definition->providerId, OFFICIAL_LANDING_RESOURCE_ID,
			definition->landingUrl, definition->maximumMetadataBytes,
			OfficialRecordFetchMode::BYPASS_CACHE, cachedClient, record) ;	// Cache有効入力。
	DRIVERCRATE_EXPECT( context,
					   cached.state == OfficialDiscoveryFixedRootState::METADATA_REJECTED &&
						   cached.error != 0 && record.recordEvidenceId == 0U &&
						   cachedClient.sourceEvidence().empty()) ;
}

/**
 * @brief 公開文字列がURLまたはPnP raw IDに見える禁止tokenを含むか確認する。
 * @param[in] value Planまたはsummaryから得た公開文字列。
 * @return 禁止tokenを一つ以上含む場合true。
 */
[[nodiscard]] bool containsPrivateDiscoveryText( const std::wstring_view value) noexcept
{
	return value.find( L"https://") != std::wstring_view::npos ||
		   value.find( L"PCI\\") != std::wstring_view::npos ||
		   value.find( L"VEN_") != std::wstring_view::npos ||
		   value.find( L"token=") != std::wstring_view::npos ;
}

/**
 * @brief 複数routeの部分失敗保持、重複registration拒否、公開文字列のprivacyを検証する。
 * @param[in,out] context Assertion集計先。
 */
void testPartialFailureDuplicateAndPrivacy( TestContext &context)
{
	OfficialDiscoveryRecordAdapterSession	 recordSession ;	// 二routeを同じscanへ保持するsession。
	std::uint32_t							 resolverCalls{} ;	// Routeごとの固定resolver呼出し回数。
	const OfficialDiscoveryFixedRootResolver resolver =
		[&resolverCalls]( ScanSessionId, std::uint64_t, std::wstring_view, std::wstring_view,
						 std::wstring_view, std::uint64_t, OfficialRecordFetchMode,
						 OfficialDistributionRecord &) {
			++resolverCalls ;
			// 最初のrouteは正常なrecordなし、二件目は通常失敗として別状態を返す。
			if( resolverCalls == 1U) {
				return OfficialDiscoveryFixedRootResult{
					.state = OfficialDiscoveryFixedRootState::NO_RECORD, .error = 0} ;
			}

			return OfficialDiscoveryFixedRootResult{.state =
														OfficialDiscoveryFixedRootState::FAILED,
													.error = static_cast<NativeError>( E_FAIL)} ;
		} ; // Network、URL、device hintを受け取らない部分失敗fixture。
	const auto descriptors	 = builtInProviderDescriptors() ;	// Provider能力の正本。
	const auto registrations = makeBuiltInOfficialDiscoveryRegistrations(
		recordSession, resolver, []() noexcept { return false ; }, descriptors) ;	// 正常registry。
	DRIVERCRATE_EXPECT( context, registrations.has_value()) ;
	// Factoryが成功した場合だけ部分失敗と重複の入力を構築する。
	if( !registrations) {
		return ;
	}

	const OfficialDiscoveryRequest request = makeRequest() ;	// Metadataだけを許可する要求。
	const OfficialDiscoveryBinding binding{OPERATION_ID + 1U, SESSION_ID + 1U,
										   INVENTORY_GENERATION + 1U} ;	// 別試験のbinding。
	OfficialDiscoveryDeviceHint	   e610 = makeIntelEthernetDevice(
		   binding.scanSessionId, L"fixture-device:privacy-e610") ;	// 一つ目のroute group。
	OfficialDiscoveryDeviceHint e835 = makeIntelEthernetDevice(
		binding.scanSessionId, L"fixture-device:privacy-e835") ;	// 二つ目のroute group。
	e835.model = L"Intel(R) Ethernet Network Adapter E835" ;
	const std::vector devices{std::move( e610), std::move( e835)} ;	// 表示modelが異なる二group。
	const auto		  plan = makeOfficialDiscoveryRoutePlan(
		   binding, request, true, devices, *registrations, descriptors) ;	// 二routeの所有plan。
	DRIVERCRATE_EXPECT( context, plan.has_value() && plan->routes.size() == 2U) ;
	DRIVERCRATE_EXPECT( context, recordSession.beginSession( binding, request, descriptors) == 0) ;
	std::optional<OfficialDiscoverySummary> summary ;	// 部分失敗を保持する公開集計。
	// 有効planだけを実行し、一方の失敗後も残りrouteを保持する。
	if( plan) {
		summary = runOfficialDiscoveryRoutePlan( binding, request, *plan, devices, *registrations,
												descriptors) ;
	}

	DRIVERCRATE_EXPECT( context,
					   summary.has_value() && summary->routes.size() == 2U && resolverCalls == 2U) ;
	// 集約結果が存在する場合だけ二状態と全公開文字列を確認する。
	if( summary && plan) {
		const std::size_t noRecordCount = static_cast<std::size_t>( std::count_if(
			summary->routes.begin(), summary->routes.end(),
			[]( const OfficialDiscoveryRouteSummary &route) {
				return route.state == OfficialDiscoveryRouteState::NO_RECORD && route.error == 0 ;
			})) ; // 正常な候補なしroute数。
		const std::size_t failedCount	= static_cast<std::size_t>( std::count_if(
			  summary->routes.begin(), summary->routes.end(),
			  []( const OfficialDiscoveryRouteSummary &route) {
				  return route.state == OfficialDiscoveryRouteState::FAILED && route.error != 0 ;
			  })) ; // 診断付き失敗route数。
		DRIVERCRATE_EXPECT( context, noRecordCount == 1U && failedCount == 1U) ;
		// PlanのProvider、root、group、opaque identityに秘密URLやraw IDを許可しない。
		for( const OfficialDiscoveryRoute &route : plan->routes) {
			DRIVERCRATE_EXPECT( context, !containsPrivateDiscoveryText( route.providerId) &&
											!containsPrivateDiscoveryText( route.rootResourceId) &&
											!containsPrivateDiscoveryText( route.hintGroupIdentity)) ;
			// Route内の全opaque identityを同じprivacy規則へ照合する。
			for( const std::wstring &identity : route.deviceIdentities) {
				DRIVERCRATE_EXPECT( context, !containsPrivateDiscoveryText( identity)) ;
			}
		}

		// SummaryはProvider ID以外のroot、URL、device表示値を持たないことを確認する。
		for( const OfficialDiscoveryRouteSummary &route : summary->routes) {
			DRIVERCRATE_EXPECT( context, !containsPrivateDiscoveryText( route.providerId)) ;
		}
	}

	std::vector<OfficialDiscoveryRegistration> duplicated = *registrations ;	// 正常registryのcopy。
	duplicated.push_back( duplicated.front()) ;
	DRIVERCRATE_EXPECT( context, !validateOfficialDiscoveryRegistrations( duplicated, descriptors)) ;
	DRIVERCRATE_EXPECT( context, !makeOfficialDiscoveryRoutePlan( binding, request, true, devices,
																duplicated, descriptors)
									 .has_value()) ;
	DRIVERCRATE_EXPECT( context, recordSession.retainedRecordCount() == 0U &&
									recordSession.resolvedPackages().empty()) ;
}

} // namespace

/** @see official_discovery_provider_adapter_tests.h */
void runOfficialDiscoveryProviderAdapterTests( TestContext &context)
{
	testIntelMatcher( context) ;
	testRegistrationConnection( context) ;
	testRegistrationRejections( context) ;
	testProductionResolverPreflight( context) ;
	testPartialFailureDuplicateAndPrivacy( context) ;
}

} // namespace drivercrate::test
