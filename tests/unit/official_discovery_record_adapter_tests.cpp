//------------------------------------------------------------------------------
/**
 * @file official_discovery_record_adapter_tests.cpp
 * @brief 公式自動探索固定root adapterの決定的単体試験を実装する。
 * @version 01.01.02
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  固定root、失敗理由、秘密record保持試験を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/09/15  合成registryの探索Providerを一件へ固定。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  取得準備対象とEULA snapshot試験を追加。
 * Ver.01.01.01 Shunji Ogawa  2026/09/15  Registrationへcache parser identityを追加。
 * Ver.01.01.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 全resolverはmemory内だけで動作し、実URLへ通信しない。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#include "official_discovery_record_adapter_tests.h"

#include "core/official_discovery_execution.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/official_discovery_record_adapter.h"
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

// 最初の合成operation ID。
constexpr OperationId		FIRST_OPERATION_ID = 2'001U ;
// 最初の合成scan session ID。
constexpr ScanSessionId		FIRST_SESSION_ID = 3'001U ;
// 合成inventory generation。
constexpr std::uint64_t		INVENTORY_GENERATION = 4'001U ;
// Adapterへ許可する固定root本文上限。
constexpr std::uint64_t		RECORD_BYTES = 512ULL * 1'024ULL ;
// Record内だけで所有する合成payload URL。
constexpr std::wstring_view PRIVATE_PAYLOAD_URL =
	L"https://temporary.fixture.invalid/driver.zip?token=private-adapter-token" ;
// 公開metadataとして扱う合成SHA-256。
constexpr std::wstring_view PUBLISHED_SHA256 =
	L"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ;

/**
 * @brief Intel Server descriptorの合成copyへ自動探索能力だけを追加する。
 * @return 他fieldを組み込み正本と一致させたProvider集合。
 */
[[nodiscard]] std::vector<ProviderDescriptor> makeProviders()
{
	const auto builtIn = builtInProviderDescriptors() ;								// 製品registryの検証済み正本。
	std::vector<ProviderDescriptor> providers( builtIn.begin(), builtIn.end()) ;	// 合成copy。
	// 製品で有効になった自動探索能力を除き、本fixtureの対象Provider一件だけを後で選ぶ。
	for( ProviderDescriptor &descriptor : providers) {
		descriptor.capabilities &= ~capabilityMask( ProviderCapability::AUTOMATIC_DISCOVERY) ;
	}

	const auto provider =
		std::find_if( providers.begin(), providers.end(), []( const ProviderDescriptor &descriptor) {
			return descriptor.id == INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ;
		}) ; // 固定landingを持つ試験対象Provider。
	// 組み込み正本に対象が存在する場合だけtest copyへ能力を追加する。
	if( provider != providers.end()) {
		provider->capabilities |= capabilityMask( ProviderCapability::AUTOMATIC_DISCOVERY) ;
	}

	return providers ;
}

/**
 * @brief 一つのProviderだけを明示するmetadata専用要求を作る。
 * @return 自動探索policyへ結合した合成request。
 */
[[nodiscard]] OfficialDiscoveryRequest makeRequest()
{
	OfficialDiscoveryRequest request ;	// Payload権限を持たない開始要求。
	request.purpose				= ScanPurpose::METADATA_ONLY ;
	request.useDefaultProviders = false ;
	request.enabledProviderIds	= {std::wstring{INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID}} ;
	return request ;
}

/**
 * @brief 同じProviderへ検査用payload取得まで許可する通常scan要求を作る。
 * @return 固定payload予算と一Providerへ結合した合成request。
 */
[[nodiscard]] OfficialDiscoveryRequest makePayloadRequest()
{
	OfficialDiscoveryRequest request = makeRequest() ;	// Metadata要求からProvider範囲を継承する。
	request.purpose					 = ScanPurpose::STANDARD ;
	request.inspectionPermission =
		OfficialDiscoveryInspectionPermission::ALLOW_VERIFIED_DRIVER_PACKAGE ;
	return request ;
}

/**
 * @brief 指定IDへ結合したraw ID非保持device hintを作る。
 * @param[in] sessionId 観測元scan session ID。
 * @param[in] identity UI行と結合するopaque identity。
 * @return Net classの合成PCI device hint。
 */
[[nodiscard]] OfficialDiscoveryDeviceHint makeDevice( const ScanSessionId sessionId,
													 std::wstring		 identity)
{
	OfficialDiscoveryDeviceHint device ;	// 実PnP IDを含まない合成device。
	device.deviceIdentity			  = std::move( identity) ;
	device.bus						  = OfficialDiscoveryDeviceBus::PCI ;
	device.setupClassGuid			  = L"{4d36e972-e325-11ce-bfc1-08002be10318}" ;
	device.deviceClass				  = L"Net" ;
	device.manufacturer				  = L"Fictional Vendor" ;
	device.observation.scanSessionId  = sessionId ;
	device.observation.deviceIdentity = device.deviceIdentity ;
	return device ;
}

/**
 * @brief 指定deviceを参照する専用固定root routeを作る。
 * @param[in] routeId Session内の一意なroute ID。
 * @param[in] deviceIdentity 参照するopaque device identity。
 * @return Intel Server固定landingへ結合したroute。
 */
[[nodiscard]] OfficialDiscoveryRoute makeRoute( const std::uint64_t routeId,
											   std::wstring		   deviceIdentity)
{
	OfficialDiscoveryRoute route ;	// URLと表示hintを持たない実行route。
	route.routeId			= routeId ;
	route.providerId		= INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ;
	route.rootResourceId	= OFFICIAL_LANDING_RESOURCE_ID ;
	route.kind				= OfficialDiscoveryRouteKind::DEDICATED ;
	route.hintGroupIdentity = L"fixture-adapter-group:" + std::to_wstring( routeId) ;
	route.deviceIdentities.push_back( std::move( deviceIdentity)) ;
	return route ;
}

/**
 * @brief PCI busの合成deviceだけを専用route対象にする。
 * @param[in] device Plannerが借用するraw ID非保持hint。
 * @return PCIの場合true。
 */
[[nodiscard]] bool matchesPciDevice( const OfficialDiscoveryDeviceHint &device) noexcept
{
	return device.bus == OfficialDiscoveryDeviceBus::PCI ;
}

/**
 * @brief Resolverへ渡されたidentityで一つの有効な秘密recordを作る。
 * @param[in] scanSessionId 現在のscan session ID。
 * @param[in] recordEvidenceId Sessionが割り当てたrecord証拠ID。
 * @return Intel Server固定landingへ結合した一payload record。
 */
[[nodiscard]] OfficialDistributionRecord makeRecord( const ScanSessionId scanSessionId,
													const std::uint64_t recordEvidenceId)
{
	OfficialDistributionRecord record ;	// 秘密payload URLを所有する合成record。
	record.rootEvidence = OfficialSourceEvidence{
		.scanSessionId			= scanSessionId,
		.acquisitionId			= recordEvidenceId + 10U,
		.providerId				= std::wstring{INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID},
		.policyId				= std::wstring{INTEL_ETHERNET_SERVER2025_OFFICIAL_SOURCE_POLICY_ID},
		.resourceId				= std::wstring{OFFICIAL_LANDING_RESOURCE_ID},
		.redirectCount			= 0U,
		.originPolicyIndices	= {0U},
		.acquisition			= MeasurementAcquisition::NETWORK_BODY,
		.bodyAcquiredUtcSeconds = 50'000U,
		.originValidatedUtcSeconds = 50'001U,
		.cachePermitted			   = false} ;
	record.recordEvidenceId = recordEvidenceId ;
	record.parserId			= L"automatic-record-adapter-fixture-v1" ;
	record.parserRevision	= 1U ;
	record.recordRoute		= L"fixed-root-record" ;
	record.recordKey		= L"fixture-record-1" ;
	record.productFamily	= L"Fictional Ethernet Family" ;
	record.operatingSystem	= L"Windows x64" ;
	record.architecture		= OfficialDistributionArchitecture::WINDOWS_X64 ;
	record.packageVersion	= L"1.2.3" ;
	record.publishedDate	= L"2026-09-15" ;
	record.terms			= OfficialDistributionTerms::CONFIRMED_NO_CONSENT ;
	record.payloads.push_back( OfficialDistributionPayloadRecord{
		.resourceId				  = std::wstring{OFFICIAL_PAYLOAD_RESOURCE_ID},
		.payloadOrdinal			  = 0U,
		.kind					  = OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE,
		.fileDisplayName		  = L"fictional-driver.zip",
		.publishedSizeBytes		  = 4'096U,
		.publishedSha256		  = std::wstring{PUBLISHED_SHA256},
		.publisher				  = L"Fictional Device Vendor",
		.expectedContentType	  = L"application/zip",
		.maximumBytes			  = 8'192U,
		.externalExpiryUtcSeconds = std::nullopt,
		.targetUrl				  = SecretOfficialUrl{std::wstring{PRIVATE_PAYLOAD_URL}}}) ;
	record.resolvedUtcSeconds = 50'002U ;
	return record ;
}

/**
 * @brief 指定終端状態を返す固定root adapterを作る。
 * @param[in] state Resolverが返す有限状態。
 * @param[in] error 失敗状態で返す診断値。
 * @param[in,out] callCount Resolver呼出し回数の観測先。
 * @param[in,out] fixedRootObserved 固定rootと引数bindingが成立した観測先。
 * @param[in] acceptanceRequired 合成recordのEULA同意を必須とする場合true。同意不要を表す場合false。
 * @return Intel Server専用route用の非通信adapter。
 * @note 返すadapterがcaptureするcallCountとfixedRootObservedは、adapterの呼出し完了まで呼出し側が保持する。
 */
[[nodiscard]] OfficialDiscoveryFixedRootAdapter makeAdapter(
	const OfficialDiscoveryFixedRootState state, const NativeError error, std::uint32_t &callCount,
	bool &fixedRootObserved, const bool acceptanceRequired = false)
{
	OfficialDiscoveryFixedRootAdapter adapter ;	// 固定rootへだけ到達する合成adapter。
	adapter.providerId		   = INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ;
	adapter.rootResourceId	   = OFFICIAL_LANDING_RESOURCE_ID ;
	adapter.kind			   = OfficialDiscoveryRouteKind::DEDICATED ;
	adapter.maximumRecordBytes = RECORD_BYTES ;
	adapter.resolver =
		[&callCount, &fixedRootObserved, state, acceptanceRequired,
		 error]( const ScanSessionId scanSessionId, const std::uint64_t recordEvidenceId,
				const std::wstring_view providerId, const std::wstring_view rootResourceId,
				const std::wstring_view builtInRootUrl, const std::uint64_t maximumRecordBytes,
				const OfficialRecordFetchMode fetchMode, OfficialDistributionRecord &record) {
			++callCount ;
			fixedRootObserved = scanSessionId != 0U && recordEvidenceId != 0U &&
								providerId == INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID &&
								rootResourceId == OFFICIAL_LANDING_RESOURCE_ID &&
								!builtInRootUrl.empty() && maximumRecordBytes == RECORD_BYTES &&
								fetchMode == OfficialRecordFetchMode::BYPASS_CACHE ;
			// 解決済み状態だけが秘密recordを返す。
			if( state == OfficialDiscoveryFixedRootState::RESOLVED) {
				record = makeRecord( scanSessionId, recordEvidenceId) ;
				// EULA fixtureではrevisionと全文を同じrecordへ固定する。
				if( acceptanceRequired) {
					record.terms		= OfficialDistributionTerms::ACCEPTANCE_REQUIRED ;
					record.eulaRevision = L"fixture-license-v1" ;
					record.eulaText		= L"Fictional driver package license text." ;
				}
			}

			return OfficialDiscoveryFixedRootResult{state, error} ;
		} ;
	return adapter ;
}

/**
 * @brief Payload許可、group再照合、EULA snapshot、非claim性を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testPreparationTargetDescription( TestContext &context)
{
	const std::vector<ProviderDescriptor> providers = makeProviders() ;			// 合成Provider snapshot。
	const OfficialDiscoveryRequest		  request	= makePayloadRequest() ;	// Payload許可要求。
	const OfficialDiscoveryBinding binding{FIRST_OPERATION_ID + 500U, FIRST_SESSION_ID + 500U,
										   INVENTORY_GENERATION + 500U} ;	// 今回binding。
	// 一payloadへ結合する合成device集合。
	const std::vector devices{makeDevice( binding.scanSessionId, L"fixture-device:preparation")} ;
	const OfficialDiscoveryRoute route =
		// 一回だけ解決する固定root route。
		makeRoute( 1U, devices.front().deviceIdentity) ;
	std::uint32_t							callCount{} ;			// Resolver呼出し回数。
	bool									fixedRootObserved{} ;	// 固定root引数の観測結果。
	const OfficialDiscoveryFixedRootAdapter adapter =
		makeAdapter( OfficialDiscoveryFixedRootState::RESOLVED, 0, callCount, fixedRootObserved,
					true) ;							// EULA同意必須recordを返すadapter。
	OfficialDiscoveryRecordAdapterSession session ;	// 秘密recordと対象snapshotの所有者。
	DRIVERCRATE_EXPECT( context, session.beginSession( binding, request, providers) == 0) ;
	const OfficialDiscoveryRouteSummary summary = session.resolveRoute(
		request, route, devices, adapter, []() { return false ; }) ;	// 非取消しrecord解決。
	const auto groups =
		// 一payloadの実行group。
		groupOfficialDiscoveryPackages( session.resolvedPackages()) ;
	DRIVERCRATE_EXPECT( context, summary.state == OfficialDiscoveryRouteState::DEDICATED_RESOLVED &&
									groups.has_value() && groups->size() == 1U) ;

	std::vector<OfficialPreparationTarget>	  targets ;			// URL非保持の準備対象出力。
	std::vector<OfficialDiscoveryEulaPackage> eulaPackages ;	// EULA group化前snapshot出力。
	std::vector<OfficialRecordPayloadDescriptor>
				payloadDescriptors ;											// 準備対象と同順のURL非保持表示descriptor出力。
	NativeError descriptionError = static_cast<NativeError>( E_UNEXPECTED) ;	// 対象変換結果。
	// Groupが成立した場合だけ権限を増やさない表示descriptorを先に生成する。
	if( groups) {
		descriptionError = session.describeDisplayPayloads( binding, *groups, payloadDescriptors) ;
	}

	DRIVERCRATE_EXPECT( context, descriptionError == 0 && payloadDescriptors.size() == 1U &&
									session.retainedRecordCount() == 1U) ;
	// 表示descriptor生成が成立した場合も秘密recordをclaimしないことを確認する。
	if( payloadDescriptors.size() == 1U) {
		DRIVERCRATE_EXPECT( context, payloadDescriptors.front().providerId ==
											INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID &&
										payloadDescriptors.front().payloadResourceId ==
											OFFICIAL_PAYLOAD_RESOURCE_ID &&
										payloadDescriptors.front().downloadGrantSupported) ;
	}

	// Groupが成立した場合だけ取得準備対象変換を実行する。
	if( groups) {
		descriptionError = session.describePreparationTargets( binding, *groups, targets,
															  eulaPackages, payloadDescriptors) ;
	}

	DRIVERCRATE_EXPECT( context, descriptionError == 0 && targets.size() == 1U &&
									eulaPackages.size() == 1U && payloadDescriptors.size() == 1U &&
									session.retainedRecordCount() == 1U) ;
	// 対象を公開できた場合はgroup、payload、EULA、予算がrecordへ一致することを確認する。
	if( targets.size() == 1U && eulaPackages.size() == 1U && payloadDescriptors.size() == 1U &&
	   groups) {
		const OfficialPreparationTarget		  &target = targets.front() ;		// 公開した一対象。
		const OfficialDiscoveryEulaPackage	  &eula	  = eulaPackages.front() ;	// 同じ対象のEULA。
		const OfficialRecordPayloadDescriptor &descriptor =
			// 同じ対象の表示用descriptor。
			payloadDescriptors.front() ;
		DRIVERCRATE_EXPECT(
			context,
			target.identity == groups->front().packageIdentity &&
				target.releaseIdentity == groups->front().packageIdentity &&
				target.providerId == INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID &&
				target.resourceId == OFFICIAL_PAYLOAD_RESOURCE_ID && target.parserRevision == 1U &&
				target.maximumBytes == 8'192U && target.deviceCount == 1U &&
				target.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED &&
				target.eulaRevision == L"fixture-license-v1" &&
				target.eulaText == L"Fictional driver package license text." &&
				target.sharedEulaToken == 0U && eula.packageIdentity == target.identity &&
				eula.providerId == target.providerId && eula.eulaRevision == target.eulaRevision &&
				eula.eulaText == target.eulaText && eula.maximumBytes == target.maximumBytes &&
				descriptor.scanSessionId == binding.scanSessionId &&
				descriptor.providerId == target.providerId &&
				descriptor.payloadResourceId == target.resourceId &&
				descriptor.payloadKind == OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE &&
				descriptor.downloadGrantSupported) ;
	}

	// Stale bindingは先行成功の出力を空に戻し、秘密recordを保持したまま拒否する。
	if( groups) {
		OfficialDiscoveryBinding staleBinding =
			binding ;	// Scan sessionだけを差し替える不正binding。
		++staleBinding.scanSessionId ;
		DRIVERCRATE_EXPECT(
			context, session.describePreparationTargets( staleBinding, *groups, targets,
														eulaPackages, payloadDescriptors) != 0 &&
						 targets.empty() && eulaPackages.empty() && payloadDescriptors.empty() &&
						 session.retainedRecordCount() == 1U) ;
	}

	// Metadataだけのrequestでは同じ有効recordでもpayload準備対象を発行しない。
	OfficialDiscoveryRecordAdapterSession metadataSession ;	// 権限分離を確認する別session。
	const OfficialDiscoveryBinding		  metadataBinding{
		   binding.operationId + 1U, binding.scanSessionId + 1U,
		   binding.inventoryGeneration + 1U} ;							// Metadata専用binding。
	const OfficialDiscoveryRequest metadataRequest = makeRequest() ;	// Payload権限なし要求。
	const std::vector			   metadataDevices{
		 makeDevice( metadataBinding.scanSessionId,
								L"fixture-device:metadata-only")} ;	// Metadataだけで解決するdevice集合。
	const OfficialDiscoveryRoute metadataRoute =
		// Metadataだけで解決するroute。
		makeRoute( 1U, metadataDevices.front().deviceIdentity) ;
	std::uint32_t metadataCalls{} ;			// Metadata resolver呼出し回数。
	bool		  metadataRootObserved{} ;	// Metadata固定root引数の観測結果。
	const OfficialDiscoveryFixedRootAdapter metadataAdapter =
		makeAdapter( OfficialDiscoveryFixedRootState::RESOLVED, 0, metadataCalls,
					metadataRootObserved) ;	// 同じrecordを返すがpayload権限は持たないadapter。
	DRIVERCRATE_EXPECT(
		context, metadataSession.beginSession( metadataBinding, metadataRequest, providers) == 0) ;
	static_cast<void>( metadataSession.resolveRoute(
		metadataRequest, metadataRoute, metadataDevices, metadataAdapter,
		[]() { return false ; })) ;	// Metadata解決自体は許可する。
	const auto metadataGroups =
		// 同じpackage group。
		groupOfficialDiscoveryPackages( metadataSession.resolvedPackages()) ;
	// Metadata-onlyでもURL非保持の配布表示descriptorまでは生成できる。
	if( metadataGroups) {
		DRIVERCRATE_EXPECT( context,
						   metadataSession.describeDisplayPayloads( metadataBinding, *metadataGroups,
																   payloadDescriptors) == 0 &&
							   payloadDescriptors.size() == 1U &&
							   metadataSession.retainedRecordCount() == 1U) ;
	}

	// Groupが存在しても開始時permissionがmetadata-onlyなら取得準備対象生成を拒否する。
	if( metadataGroups) {
		DRIVERCRATE_EXPECT(
			context,
			metadataSession.describePreparationTargets( metadataBinding, *metadataGroups, targets,
													   eulaPackages, payloadDescriptors) != 0 &&
				targets.empty() && eulaPackages.empty() && payloadDescriptors.empty() &&
				metadataSession.retainedRecordCount() == 1U) ;
	}
}

/**
 * @brief 固定root成功時のpackage参照と秘密record claimを検証する。
 * @param[in,out] context Assertion集計先。
 */
void testResolvedRecordAndClaim( TestContext &context)
{
	const std::vector<ProviderDescriptor> providers = makeProviders() ;	// 合成Provider snapshot。
	const OfficialDiscoveryRequest		  request	= makeRequest() ;	// Metadata専用要求。
	const OfficialDiscoveryBinding		  binding{FIRST_OPERATION_ID, FIRST_SESSION_ID,
											  INVENTORY_GENERATION} ;	// 開始時binding。
	// 一つのrouteへ結合する合成device集合。
	const std::vector devices{makeDevice( binding.scanSessionId, L"fixture-device:adapter-1")} ;
	// 合成deviceを参照する専用route。
	const OfficialDiscoveryRoute			route = makeRoute( 1U, devices.front().deviceIdentity) ;
	std::uint32_t							callCount{} ;			// Resolver呼出し回数。
	bool									fixedRootObserved{} ;	// 固定root binding観測結果。
	// 成功recordを返す固定root adapter。
	const OfficialDiscoveryFixedRootAdapter adapter =
		makeAdapter( OfficialDiscoveryFixedRootState::RESOLVED, 0, callCount, fixedRootObserved) ;
	OfficialDiscoveryRecordAdapterSession session ;	// Worker内record所有者。
	DRIVERCRATE_EXPECT( context, session.beginSession( binding, request, providers) == 0) ;
	DRIVERCRATE_EXPECT(
		context, validateOfficialDiscoveryFixedRootAdapter( adapter, route, devices, providers)) ;
	const OfficialDiscoveryRouteSummary summary = session.resolveRoute(
		request, route, devices, adapter, []() { return false ; }) ;	// 非取消し実行。
	DRIVERCRATE_EXPECT( context, summary.state == OfficialDiscoveryRouteState::DEDICATED_RESOLVED &&
									summary.error == 0 && summary.recordCount == 1U &&
									summary.packageCount == 1U) ;
	DRIVERCRATE_EXPECT( context, callCount == 1U && fixedRootObserved) ;
	DRIVERCRATE_EXPECT(
		context, session.retainedRecordCount() == 1U && session.resolvedPackages().size() == 1U &&
					 session.resolvedPackages().front().routeId == route.routeId &&
					 session.resolvedPackages().front().deviceIdentities == route.deviceIdentities) ;

	ResolvedOfficialDistributionRecord claimed ;	// Claim成功時の秘密record所有先。
	const std::uint64_t				   evidenceId =
		// 公開package参照のopaque証拠ID。
		session.resolvedPackages().front().recordEvidenceId ;
	DRIVERCRATE_EXPECT(
		context, session.claimResolvedRecord( binding.scanSessionId + 1U, evidenceId, claimed) != 0) ;
	DRIVERCRATE_EXPECT(
		context, session.claimResolvedRecord( binding.scanSessionId, evidenceId, claimed) == 0) ;
	DRIVERCRATE_EXPECT( context, claimed.evidence.recordEvidenceId == evidenceId &&
									claimed.record.payloads.front().targetUrl.view() ==
										PRIVATE_PAYLOAD_URL &&
									session.retainedRecordCount() == 0U) ;
	DRIVERCRATE_EXPECT(
		context, session.claimResolvedRecord( binding.scanSessionId, evidenceId, claimed) != 0) ;
	session.invalidate() ;
	DRIVERCRATE_EXPECT( context, session.activeBinding().scanSessionId == 0U &&
									session.resolvedPackages().empty()) ;
}

/**
 * @brief 固定root adapterを共通planner／executorのresolverへ接続する。
 * @param[in,out] context Assertion集計先。
 */
void testCoreExecutorConnection( TestContext &context)
{
	const std::vector<ProviderDescriptor> providers = makeProviders() ;	// 合成Provider snapshot。
	const OfficialDiscoveryRequest		  request	= makeRequest() ;	// Metadata専用要求。
	const OfficialDiscoveryBinding		  binding{FIRST_OPERATION_ID + 1U, FIRST_SESSION_ID + 1U,
											  INVENTORY_GENERATION + 1U} ;	// 共通planのbinding。
	// Plannerが一routeへまとめる二つの同種device。
	const std::vector devices{makeDevice( binding.scanSessionId, L"fixture-device:core-1"),
							  makeDevice( binding.scanSessionId, L"fixture-device:core-2")} ;
	std::uint32_t	  callCount{} ;			// Resolver呼出し回数。
	bool			  fixedRootObserved{} ;	// 固定root引数の観測結果。
	// 共通executorへ差し込む成功adapter。
	const OfficialDiscoveryFixedRootAdapter adapter =
		makeAdapter( OfficialDiscoveryFixedRootState::RESOLVED, 0, callCount, fixedRootObserved) ;
	OfficialDiscoveryRecordAdapterSession session ;	// Executor callbackが使うworker session。
	DRIVERCRATE_EXPECT( context, session.beginSession( binding, request, providers) == 0) ;
	OfficialDiscoveryRegistration registration ;	// Plannerとexecutorが共有する一registration。
	registration.providerId		= INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ;
	registration.sourcePolicyId = INTEL_ETHERNET_SERVER2025_OFFICIAL_SOURCE_POLICY_ID ;
	registration.rootResourceId = OFFICIAL_LANDING_RESOURCE_ID ;
	registration.parserId		= L"fixture-record-adapter-parser" ;
	registration.parserRevision = 1U ;
	registration.kind			= OfficialDiscoveryRouteKind::DEDICATED ;
	registration.matcher		= matchesPciDevice ;
	registration.resolver =
		[&session, &adapter]( const OfficialDiscoveryRequest					   &resolverRequest,
							 const OfficialDiscoveryRoute					   &resolverRoute,
							 const std::span<const OfficialDiscoveryDeviceHint> resolverDevices) {
			return session.resolveRoute( resolverRequest, resolverRoute, resolverDevices, adapter,
										[]() { return false ; }) ;
		} ;
	// 一件の専用registrationから作る所有plan。
	const auto plan = makeOfficialDiscoveryRoutePlan( binding, request, true, devices,
													 std::span{&registration, 1U}, providers) ;
	DRIVERCRATE_EXPECT( context, plan.has_value() && plan->routes.size() == 1U) ;
	std::optional<OfficialDiscoverySummary> summary ;	// 共通executorの公開結果。
	// Plan生成に成功した場合だけresolver接続を実行する。
	if( plan) {
		summary = runOfficialDiscoveryRoutePlan( binding, request, *plan, devices,
												std::span{&registration, 1U}, providers) ;
	}

	DRIVERCRATE_EXPECT( context, summary.has_value() && summary->routes.size() == 1U) ;
	// 公開summaryが存在する場合だけroute状態を確認する。
	if( summary) {
		DRIVERCRATE_EXPECT( context, summary->routes.front().state ==
											OfficialDiscoveryRouteState::DEDICATED_RESOLVED &&
										summary->routes.front().recordCount == 1U &&
										summary->routes.front().packageCount == 1U) ;
	}

	DRIVERCRATE_EXPECT( context, callCount == 1U && fixedRootObserved) ;
	DRIVERCRATE_EXPECT(
		context, session.retainedRecordCount() == 1U && session.resolvedPackages().size() == 1U &&
					 session.resolvedPackages().front().deviceIdentities.size() == 2U) ;
}

/**
 * @brief Resolverの五つの非成功理由を変更せずroute summaryへ保持する。
 * @param[in,out] context Assertion集計先。
 */
void testFailureStateMapping( TestContext &context)
{
	const std::vector<ProviderDescriptor> providers =
		// 各session共通の合成registry。
		makeProviders() ;
	const OfficialDiscoveryRequest request = makeRequest() ;	// 各session共通の要求。
	struct StateCase {
		/// Adapterが返す有限状態。
		OfficialDiscoveryFixedRootState adapterState{} ;
		/// 公開summaryで期待する状態。
		OfficialDiscoveryRouteState		expectedState{} ;
		/// 失敗状態だけに設定する診断値。
		NativeError						error{} ;
	} ;
	// 非成功理由と公開状態の一対一対応集合。
	const std::vector<StateCase> cases{
		{OfficialDiscoveryFixedRootState::NO_RECORD, OfficialDiscoveryRouteState::NO_RECORD, 0},
		{OfficialDiscoveryFixedRootState::CANCELLED, OfficialDiscoveryRouteState::CANCELLED, 0},
		{OfficialDiscoveryFixedRootState::FAILED, OfficialDiscoveryRouteState::FAILED,
		 static_cast<NativeError>( E_FAIL)},
		{OfficialDiscoveryFixedRootState::SOURCE_REJECTED,
		 OfficialDiscoveryRouteState::SOURCE_REJECTED, static_cast<NativeError>( E_ACCESSDENIED)},
		{OfficialDiscoveryFixedRootState::METADATA_REJECTED,
		 OfficialDiscoveryRouteState::METADATA_REJECTED, static_cast<NativeError>( E_INVALIDARG)}} ;
	OfficialDiscoveryRecordAdapterSession session ;	// Session間の単調性も確認する所有者。
	// 全非成功状態を別sessionで実行し、recordやpackageを残さないことを確認する。
	for( std::size_t index = 0U; index < cases.size(); ++index) {
		const OfficialDiscoveryBinding binding{
			FIRST_OPERATION_ID + index + 10U, FIRST_SESSION_ID + index + 10U,
			INVENTORY_GENERATION + index + 10U} ;	// 今回の単調binding。
		// 今回のsessionだけへ結合する一device集合。
		const std::vector devices{
			makeDevice( binding.scanSessionId, L"fixture-device:failure-" + std::to_wstring( index))} ;
		// 同じdeviceを一度だけ参照するroute。
		const OfficialDiscoveryRoute route = makeRoute( 1U, devices.front().deviceIdentity) ;
		std::uint32_t				 callCount{} ;			// 今回のcallback回数。
		bool						 fixedRootObserved{} ;	// 今回の固定root観測。
		// 今回注入する非成功状態のadapter。
		const OfficialDiscoveryFixedRootAdapter adapter = makeAdapter(
			cases[index].adapterState, cases[index].error, callCount, fixedRootObserved) ;
		DRIVERCRATE_EXPECT( context, session.beginSession( binding, request, providers) == 0) ;
		const OfficialDiscoveryRouteSummary summary = session.resolveRoute(
			request, route, devices, adapter, []() { return false ; }) ;	// 状態注入実行。
		DRIVERCRATE_EXPECT( context, summary.state == cases[index].expectedState &&
										summary.error == cases[index].error &&
										summary.recordCount == 0U && summary.packageCount == 0U) ;
		DRIVERCRATE_EXPECT( context, callCount == 1U && fixedRootObserved) ;
		DRIVERCRATE_EXPECT( context, session.retainedRecordCount() == 0U &&
										session.resolvedPackages().empty()) ;
	}
}

/**
 * @brief 取消し、二重route、stale request、adapter不整合をresolver前に拒否する。
 * @param[in,out] context Assertion集計先。
 */
void testPreResolutionRejections( TestContext &context)
{
	const std::vector<ProviderDescriptor> providers = makeProviders() ;	// 合成Provider snapshot。
	const OfficialDiscoveryRequest		  request	= makeRequest() ;	// 開始時request。
	const OfficialDiscoveryBinding binding{FIRST_OPERATION_ID + 100U, FIRST_SESSION_ID + 100U,
										   INVENTORY_GENERATION + 100U} ;	// 開始時binding。
	// 取消しと二重実行へ使う一device集合。
	const std::vector devices{makeDevice( binding.scanSessionId, L"fixture-device:rejection")} ;
	// 最初のsessionで一度だけclaimするroute。
	const OfficialDiscoveryRoute	  route = makeRoute( 1U, devices.front().deviceIdentity) ;
	std::uint32_t					  callCount{} ;			// Resolverが呼ばれない境界の観測値。
	bool							  fixedRootObserved{} ;	// Resolverが呼ばれない境界の観測値。
	// Resolver前拒否を観測する正常adapter。
	OfficialDiscoveryFixedRootAdapter adapter =
		makeAdapter( OfficialDiscoveryFixedRootState::NO_RECORD, 0, callCount, fixedRootObserved) ;
	OfficialDiscoveryRecordAdapterSession session ;	// Worker相当の一session。
	DRIVERCRATE_EXPECT( context, session.beginSession( binding, request, providers) == 0) ;
	const OfficialDiscoveryRouteSummary cancelled = session.resolveRoute(
		request, route, devices, adapter, []() { return true ; }) ;	// 開始前取消し。
	DRIVERCRATE_EXPECT( context, cancelled.state == OfficialDiscoveryRouteState::CANCELLED &&
									callCount == 0U) ;
	const OfficialDiscoveryRouteSummary duplicate = session.resolveRoute(
		request, route, devices, adapter, []() { return false ; }) ;	// 同じrouteの再使用。
	DRIVERCRATE_EXPECT( context, duplicate.state == OfficialDiscoveryRouteState::METADATA_REJECTED &&
									duplicate.error != 0 && callCount == 0U) ;

	const OfficialDiscoveryBinding nextBinding{binding.operationId + 1U, binding.scanSessionId + 1U,
											   binding.inventoryGeneration +
												   1U} ;	// 次の有効session。
	// 次sessionのstale requestと過大adapterへ使うdevice集合。
	const std::vector			   nextDevices{
		 makeDevice( nextBinding.scanSessionId, L"fixture-device:rejection-next")} ;
	// 次sessionでまだclaimしていないroute。
	const OfficialDiscoveryRoute nextRoute = makeRoute( 1U, nextDevices.front().deviceIdentity) ;
	DRIVERCRATE_EXPECT( context, session.beginSession( nextBinding, request, providers) == 0) ;
	OfficialDiscoveryRequest staleRequest = request ;	// 開始時から改変する要求。
	staleRequest.cacheMode				  = OfficialDiscoveryCacheMode::FORCE_REFRESH ;
	// 開始時requestと一致しない実行結果。
	const OfficialDiscoveryRouteSummary stale =
		session.resolveRoute( staleRequest, nextRoute, nextDevices, adapter, []() { return false ; }) ;
	DRIVERCRATE_EXPECT( context, stale.state == OfficialDiscoveryRouteState::METADATA_REJECTED &&
									stale.error != 0 && callCount == 0U) ;
	adapter.maximumRecordBytes = OFFICIAL_DISCOVERY_RECORD_BYTES_LIMIT + 1U ;
	DRIVERCRATE_EXPECT( context, !validateOfficialDiscoveryFixedRootAdapter( adapter, nextRoute,
																		   nextDevices, providers)) ;
	// 2 MiB上限超過adapterを渡した実行結果。
	const OfficialDiscoveryRouteSummary excessive =
		session.resolveRoute( request, nextRoute, nextDevices, adapter, []() { return false ; }) ;
	DRIVERCRATE_EXPECT( context, excessive.state == OfficialDiscoveryRouteState::METADATA_REJECTED &&
									excessive.error != 0 && callCount == 0U) ;
}

/**
 * @brief Resolverの不正結果、source差替え、metadata不正を理由別に拒否する。
 * @param[in,out] context Assertion集計先。
 */
void testPostResolutionRejections( TestContext &context)
{
	const std::vector<ProviderDescriptor> providers = makeProviders() ;	// 合成Provider snapshot。
	const OfficialDiscoveryRequest		  request	= makeRequest() ;	// 各session共通の要求。
	OfficialDiscoveryRecordAdapterSession session ;						// 単調な三sessionを管理する所有者。
	// CallbackのRESOLVEDと非0診断の矛盾をmetadata拒否へ固定する。
	{
		const OfficialDiscoveryBinding binding{FIRST_OPERATION_ID + 200U, FIRST_SESSION_ID + 200U,
											   INVENTORY_GENERATION + 200U} ;	// 一つ目のbinding。
		// 不正結果のresolverへ渡すdevice集合。
		const std::vector devices{makeDevice( binding.scanSessionId, L"fixture-device:bad-state")} ;
		// 一つ目のsessionへ結合するroute。
		const OfficialDiscoveryRoute route = makeRoute( 1U, devices.front().deviceIdentity) ;
		std::uint32_t				 callCount{} ;			// Callback回数。
		bool						 fixedRootObserved{} ;	// 固定root観測。
		// 成功状態と失敗診断を同時に返す不正adapter。
		const OfficialDiscoveryFixedRootAdapter adapter =
			makeAdapter( OfficialDiscoveryFixedRootState::RESOLVED, static_cast<NativeError>( E_FAIL),
						callCount, fixedRootObserved) ;
		DRIVERCRATE_EXPECT( context, session.beginSession( binding, request, providers) == 0) ;
		// Callback結果矛盾を拒否したsummary。
		const OfficialDiscoveryRouteSummary summary =
			session.resolveRoute( request, route, devices, adapter, []() { return false ; }) ;
		DRIVERCRATE_EXPECT( context,
						   summary.state == OfficialDiscoveryRouteState::METADATA_REJECTED &&
							   summary.error != 0 && session.retainedRecordCount() == 0U) ;
	}

	// 正常recordのProvider証拠差替えをsource拒否へ固定する。
	{
		const OfficialDiscoveryBinding binding{FIRST_OPERATION_ID + 201U, FIRST_SESSION_ID + 201U,
											   INVENTORY_GENERATION + 201U} ;	// 二つ目のbinding。
		// Source evidence差替えへ使うdevice集合。
		const std::vector devices{makeDevice( binding.scanSessionId, L"fixture-device:bad-source")} ;
		// 二つ目のsessionへ結合するroute。
		const OfficialDiscoveryRoute	  route = makeRoute( 1U, devices.front().deviceIdentity) ;
		OfficialDiscoveryFixedRootAdapter adapter ;	// Source差替えcallbackを持つadapter。
		adapter.providerId		   = INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ;
		adapter.rootResourceId	   = OFFICIAL_LANDING_RESOURCE_ID ;
		adapter.kind			   = OfficialDiscoveryRouteKind::DEDICATED ;
		adapter.maximumRecordBytes = RECORD_BYTES ;
		adapter.resolver		   = []( const ScanSessionId scanSessionId,
								const std::uint64_t recordEvidenceId, std::wstring_view,
								std::wstring_view, std::wstring_view, std::uint64_t,
								OfficialRecordFetchMode, OfficialDistributionRecord &record) {
			  record						 = makeRecord( scanSessionId, recordEvidenceId) ;
			  record.rootEvidence.providerId = INTEL_WIFI_OFFICIAL_PROVIDER_ID ;
			  return OfficialDiscoveryFixedRootResult{OfficialDiscoveryFixedRootState::RESOLVED, 0} ;
		} ;
		DRIVERCRATE_EXPECT( context, session.beginSession( binding, request, providers) == 0) ;
		// Provider ID差替えをsource拒否したsummary。
		const OfficialDiscoveryRouteSummary summary =
			session.resolveRoute( request, route, devices, adapter, []() { return false ; }) ;
		DRIVERCRATE_EXPECT( context, summary.state == OfficialDiscoveryRouteState::SOURCE_REJECTED &&
										summary.error != 0 && session.retainedRecordCount() == 0U) ;
	}

	// Rootは正しいがpayload順序が不正なrecordをmetadata拒否へ固定する。
	{
		const OfficialDiscoveryBinding binding{FIRST_OPERATION_ID + 202U, FIRST_SESSION_ID + 202U,
											   INVENTORY_GENERATION + 202U} ;	// 三つ目のbinding。
		// Metadata破損へ使うdevice集合。
		const std::vector			   devices{
			 makeDevice( binding.scanSessionId, L"fixture-device:bad-metadata")} ;
		// 三つ目のsessionへ結合するroute。
		const OfficialDiscoveryRoute	  route = makeRoute( 1U, devices.front().deviceIdentity) ;
		OfficialDiscoveryFixedRootAdapter adapter ;	// Metadata破損callbackを持つadapter。
		adapter.providerId		   = INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ;
		adapter.rootResourceId	   = OFFICIAL_LANDING_RESOURCE_ID ;
		adapter.kind			   = OfficialDiscoveryRouteKind::DEDICATED ;
		adapter.maximumRecordBytes = RECORD_BYTES ;
		adapter.resolver		   = []( const ScanSessionId scanSessionId,
								const std::uint64_t recordEvidenceId, std::wstring_view,
								std::wstring_view, std::wstring_view, std::uint64_t,
								OfficialRecordFetchMode, OfficialDistributionRecord &record) {
			  record								 = makeRecord( scanSessionId, recordEvidenceId) ;
			  record.payloads.front().payloadOrdinal = 1U ;
			  return OfficialDiscoveryFixedRootResult{OfficialDiscoveryFixedRootState::RESOLVED, 0} ;
		} ;
		DRIVERCRATE_EXPECT( context, session.beginSession( binding, request, providers) == 0) ;
		// Payload ordinal破損をmetadata拒否したsummary。
		const OfficialDiscoveryRouteSummary summary =
			session.resolveRoute( request, route, devices, adapter, []() { return false ; }) ;
		DRIVERCRATE_EXPECT( context,
						   summary.state == OfficialDiscoveryRouteState::METADATA_REJECTED &&
							   summary.error != 0 && session.retainedRecordCount() == 0U &&
							   session.resolvedPackages().empty()) ;
	}
}

} // namespace

/** @see official_discovery_record_adapter_tests.h */
void runOfficialDiscoveryRecordAdapterTests( TestContext &context)
{
	testResolvedRecordAndClaim( context) ;
	testPreparationTargetDescription( context) ;
	testCoreExecutorConnection( context) ;
	testFailureStateMapping( context) ;
	testPreResolutionRejections( context) ;
	testPostResolutionRejections( context) ;
}

} // namespace drivercrate::test
