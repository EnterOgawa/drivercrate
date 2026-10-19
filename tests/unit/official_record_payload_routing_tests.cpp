//------------------------------------------------------------------------------
/**
 * @file official_record_payload_routing_tests.cpp
 * @brief 公式record payload三方式のrouting単体試験を実装します。
 * @version 01.04.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  三方式・fallback禁止・秘密非出力fixtureを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  自動探索package重複排除fixtureを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  自動探索のdevice別表示専用候補fixtureを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  URL非保持cache schemaと失効fixtureを追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/15  OF17の全binding失効と対象外negativeを追加。
 * </pre>
 *
 * @note 架空の秘密URLとEULA本文はrecord内だけに置き、通信、file取得またはprocess生成を行いません。
 */
//------------------------------------------------------------------------------

#include "official_record_payload_routing_tests.h"

#include "core/candidate_assessment.h"
#include "core/candidate_audit.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/official_discovery_cache.h"
#include "platform/official_discovery_package.h"
#include "platform/official_record_payload_routing.h"
#include "platform/secret_official_url.h"
#include "test_framework.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr ScanSessionId		SESSION_ID		   = 1'601U ;	// 架空scan session IDです。
constexpr std::uint64_t		RECORD_EVIDENCE_ID = 701U ;		// 架空record証拠IDです。
// Record内だけで所有しdescriptorへ複製しない架空完全URLです。
constexpr std::wstring_view PRIVATE_URL =
	L"https://temporary.fixture.invalid/payload.bin?token=record-private-fixture" ;
constexpr std::wstring_view PRIVATE_TOKEN =
	L"record-private-fixture" ;	// 秘密query識別用文字列です。
// Record内の有無だけをdescriptorへ渡す架空公開SHA-256です。
constexpr std::wstring_view PUBLISHED_SHA256 =
	L"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ;
// Record内だけで所有しdescriptorへ複製しない架空EULA本文です。
constexpr std::wstring_view PRIVATE_EULA_TEXT =
	L"Fictional EULA body private to the record worker." ;
// 現在OSを表す架空の64桁lowercase SHA-256です。
constexpr std::wstring_view OPERATING_SYSTEM_FINGERPRINT =
	L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ;
// 現在device集合を表す端末固有HMAC由来の架空fingerprintです。
constexpr std::wstring_view DEVICE_CONFIGURATION_FINGERPRINT =
	L"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" ;

//------------------------------------------------------------------------------
// Fixture生成関数定義。
//------------------------------------------------------------------------------

/**
 * @brief 指定方式と公開basenameを持つ有効な架空recordを作ります。
 * @param[in] kind Parserが明示するpayload方式です。
 * @param[in] fileDisplayName 公式recordが表示するbasenameです。
 * @return Intel組み込みrootへ結合できる一payload recordです。
 */
[[nodiscard]] OfficialDistributionRecord makeRecord( const OfficialDistributionPayloadKind kind,
													std::wstring fileDisplayName)
{
	OfficialDistributionRecord record ;	// URL、EULA本文と全stable fieldを所有する結果です。
	record.rootEvidence = OfficialSourceEvidence{
		.scanSessionId			= SESSION_ID,
		.acquisitionId			= 601U,
		.providerId				= std::wstring{INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID},
		.policyId				= std::wstring{INTEL_ETHERNET_SERVER2025_OFFICIAL_SOURCE_POLICY_ID},
		.resourceId				= std::wstring{OFFICIAL_LANDING_RESOURCE_ID},
		.redirectCount			= 0U,
		.originPolicyIndices	= {0U},
		.acquisition			= MeasurementAcquisition::NETWORK_BODY,
		.bodyAcquiredUtcSeconds = 29'000U,
		.originValidatedUtcSeconds = 29'001U,
		.cachePermitted			   = false} ;
	record.recordEvidenceId = RECORD_EVIDENCE_ID ;
	record.parserId			= L"payload-routing-fixture-parser-v1" ;
	record.parserRevision	= 1U ;
	record.recordRoute		= L"payload-routing-fixture-route" ;
	record.recordKey		= L"payload-routing-fixture-record" ;
	record.productFamily	= L"Fictional Ethernet Family" ;
	record.operatingSystem	= L"Windows 11 x64" ;
	record.architecture		= OfficialDistributionArchitecture::WINDOWS_X64 ;
	record.packageVersion	= L"3.0.0" ;
	record.publishedDate	= L"2026-09-15" ;
	record.terms			= OfficialDistributionTerms::ACCEPTANCE_REQUIRED ;
	record.eulaRevision		= L"fixture-eula-v1" ;
	record.eulaText			= std::wstring{PRIVATE_EULA_TEXT} ;
	record.payloads.push_back( OfficialDistributionPayloadRecord{
		.resourceId				  = std::wstring{OFFICIAL_PAYLOAD_RESOURCE_ID},
		.payloadOrdinal			  = 0U,
		.kind					  = kind,
		.fileDisplayName		  = std::move( fileDisplayName),
		.publishedSizeBytes		  = 4'096U,
		.publishedSha256		  = std::wstring{PUBLISHED_SHA256},
		.publisher				  = L"Fictional Device Vendor",
		.expectedContentType	  = L"application/octet-stream",
		.maximumBytes			  = 8'192U,
		.externalExpiryUtcSeconds = std::nullopt,
		.targetUrl				  = SecretOfficialUrl{std::wstring{PRIVATE_URL}}}) ;
	record.resolvedUtcSeconds = 29'002U ;
	return record ;
}

/**
 * @brief 一payload recordを検証してURL非保持descriptor一件へ変換します。
 * @param[in] record 変換中に変更しない架空recordです。
 * @param[out] descriptor 成功時の唯一のdescriptorです。
 * @return Record検証と一件変換に成功すれば0です。
 */
[[nodiscard]] NativeError describeSinglePayload( const OfficialDistributionRecord &record,
												OfficialRecordPayloadDescriptor	 &descriptor)
{
	descriptor = {} ;
	OfficialDistributionRecordEvidence evidence ;	// Recordから得るURL非保持証拠です。
	NativeError						   error =
		// Record検証結果です。
		validateOfficialDistributionRecord( record, evidence) ;
	// 無効recordをdescriptor変換へ渡さない。
	if( error != 0) {
		return error ;
	}

	std::vector<OfficialRecordPayloadDescriptor> descriptors ;	// 一件を要求する変換結果です。
	error = describeOfficialDistributionRecordPayloads( record, evidence, descriptors) ;
	// 変換失敗または一件でない結果を部分成功にしない。
	if( error != 0 || descriptors.size() != 1U) {
		return error != 0 ? error : static_cast<NativeError>( E_FAIL) ;
	}

	descriptor = std::move( descriptors.front()) ;
	return 0 ;
}

/**
 * @brief Record由来だけを示す表示専用候補を作ります。
 * @return 公式Web探索とblocked監査を持つopaque候補です。
 */
[[nodiscard]] UpdateCandidate makeCandidate()
{
	UpdateCandidate candidate ;	// Descriptorと結合する表示専用候補です。
	candidate.identity		  = L"candidate:routing:1" ;
	candidate.deviceIdentity  = L"device:routing:1" ;
	candidate.providerId	  = INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ;
	candidate.packageIdentity = L"package:routing:1" ;
	candidate.discoveryBasis  = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
	candidate.action		  = DriverAction::INITIAL_INSTALL ;
	candidate.audit			  = makeOfficialDiscoveryCandidateAudit() ;
	return candidate ;
}

/**
 * @brief Intel Server Providerへ自動探索能力を付けた合成registryを作ります。
 * @return 製品正本のcopyへ試験能力だけを追加したProvider集合です。
 */
[[nodiscard]] std::vector<ProviderDescriptor> makeDiscoveryProviders()
{
	const auto builtIn = builtInProviderDescriptors() ;								// 製品registryの検証済み正本です。
	std::vector<ProviderDescriptor> providers( builtIn.begin(), builtIn.end()) ;	// 合成copyです。
	const auto						provider =
		std::find_if( providers.begin(), providers.end(), []( const ProviderDescriptor &descriptor) {
			return descriptor.id == INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ;
		}) ; // 固定landingを持つ試験対象Providerです。
	// 正本Providerが存在する場合だけ合成copyへ自動探索能力を追加します。
	if( provider != providers.end()) {
		provider->capabilities |= capabilityMask( ProviderCapability::AUTOMATIC_DISCOVERY) ;
	}

	return providers ;
}

/**
 * @brief Package routeへ結合する架空device hintを作ります。
 * @param[in] identity Scan session内のopaque device identityです。
 * @return Net classへ結合したraw ID非保持hintです。
 */
[[nodiscard]] OfficialDiscoveryDeviceHint makeDiscoveryDevice( std::wstring identity)
{
	OfficialDiscoveryDeviceHint device ;	// 実PnP IDを持たない架空deviceです。
	device.deviceIdentity			  = std::move( identity) ;
	device.bus						  = OfficialDiscoveryDeviceBus::PCI ;
	device.setupClassGuid			  = L"{4d36e972-e325-11ce-bfc1-08002be10318}" ;
	device.observation.scanSessionId  = SESSION_ID ;
	device.observation.deviceIdentity = device.deviceIdentity ;
	return device ;
}

/**
 * @brief 指定device集合を参照する架空の専用固定root routeを作ります。
 * @param[in] routeId Scan session内で一意なroute IDです。
 * @param[in] deviceIdentities Routeへ結合するopaque device identity集合です。
 * @return Intel Server固定landingへ結合したrouteです。
 */
[[nodiscard]] OfficialDiscoveryRoute makeDiscoveryRoute( const std::uint64_t		  routeId,
														std::vector<std::wstring> deviceIdentities)
{
	OfficialDiscoveryRoute route ;	// 表示値とURLを含まない固定root routeです。
	route.routeId			= routeId ;
	route.providerId		= INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ;
	route.rootResourceId	= OFFICIAL_LANDING_RESOURCE_ID ;
	route.kind				= OfficialDiscoveryRouteKind::DEDICATED ;
	route.hintGroupIdentity = L"fixture-package-group:" + std::to_wstring( routeId) ;
	route.deviceIdentities	= std::move( deviceIdentities) ;
	return route ;
}

/**
 * @brief Descriptorの全表示文字列に秘密URL要素またはhash値がないか確認します。
 * @param[in] descriptor 検証するURL非保持descriptorです。
 * @return 秘密token、完全URL、hash値、EULA本文のいずれも含まない場合trueです。
 */
[[nodiscard]] bool excludesPrivateText( const OfficialRecordPayloadDescriptor &descriptor) noexcept
{
	return descriptor.providerId.find( PRIVATE_TOKEN) == std::wstring::npos &&
		   descriptor.policyId.find( PRIVATE_TOKEN) == std::wstring::npos &&
		   descriptor.rootResourceId.find( PRIVATE_TOKEN) == std::wstring::npos &&
		   descriptor.payloadResourceId.find( PRIVATE_TOKEN) == std::wstring::npos &&
		   descriptor.fileDisplayName.find( PRIVATE_TOKEN) == std::wstring::npos &&
		   descriptor.productFamily.find( PRIVATE_TOKEN) == std::wstring::npos &&
		   descriptor.operatingSystem.find( PRIVATE_TOKEN) == std::wstring::npos &&
		   descriptor.packageVersion.find( PRIVATE_URL) == std::wstring::npos &&
		   descriptor.publishedDate.find( PUBLISHED_SHA256) == std::wstring::npos &&
		   descriptor.declaredPublisher.find( PRIVATE_EULA_TEXT) == std::wstring::npos &&
		   descriptor.eulaRevision.find( PRIVATE_EULA_TEXT) == std::wstring::npos ;
}

//------------------------------------------------------------------------------
// 三方式分類試験。
//------------------------------------------------------------------------------

/**
 * @brief INF、installer、unsupportedをrecord型だけで固定routeへ分類します。
 * @param[in,out] context Assertion集計先です。
 */
void testTypedRoutesAndPrivacy( TestContext &context)
{
	OfficialDistributionRecord infRecord =	// 共通INF検査へ進む架空ZIP recordです。
		makeRecord( OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE, L"driver-package.ZIP") ;
	OfficialRecordPayloadDescriptor inf ;	// INF recordのURL非保持descriptorです。
	DRIVERCRATE_EXPECT( context, describeSinglePayload( infRecord, inf) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   inf.payloadKind == OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE &&
						   inf.route == OfficialRecordPayloadRoute::COMMON_INF_INSPECTION &&
						   inf.downloadGrantSupported && inf.contentInspectorAvailable &&
						   !inf.executorAvailable) ;
	DRIVERCRATE_EXPECT( context, inf.publishedSizeBytes == 4'096U && inf.publishedSha256Available &&
									inf.eulaRevision == L"fixture-eula-v1") ;
	DRIVERCRATE_EXPECT( context, excludesPrivateText( inf)) ;
	DRIVERCRATE_EXPECT( context, infRecord.payloads[0].targetUrl.view() == PRIVATE_URL) ;

	OfficialDistributionRecord installerRecord =	// 専用監査待ちの架空EXE recordです。
		makeRecord( OfficialDistributionPayloadKind::OFFICIAL_INSTALLER, L"driver-installer.exe") ;
	OfficialRecordPayloadDescriptor installer ;	// InstallerのURL非保持descriptorです。
	DRIVERCRATE_EXPECT( context, describeSinglePayload( installerRecord, installer) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   installer.route == OfficialRecordPayloadRoute::DEDICATED_INSTALLER_AUDIT &&
						   installer.downloadGrantSupported &&
						   !installer.contentInspectorAvailable && !installer.executorAvailable) ;
	DRIVERCRATE_EXPECT( context, excludesPrivateText( installer)) ;

	OfficialDistributionRecord unsupportedRecord =	// 取得しない未対応方式recordです。
		makeRecord( OfficialDistributionPayloadKind::UNSUPPORTED, L"driver-payload.bin") ;
	OfficialRecordPayloadDescriptor unsupported ;	// 表示専用descriptorです。
	DRIVERCRATE_EXPECT( context, describeSinglePayload( unsupportedRecord, unsupported) == 0) ;
	DRIVERCRATE_EXPECT(
		context, unsupported.route == OfficialRecordPayloadRoute::DISPLAY_ONLY_UNSUPPORTED &&
					 !unsupported.downloadGrantSupported &&
					 !unsupported.contentInspectorAvailable && !unsupported.executorAvailable) ;
	DRIVERCRATE_EXPECT( context, excludesPrivateText( unsupported)) ;

	OfficialDistributionRecordEvidence unsupportedEvidence ;	// Grant拒否前の有効record証拠です。
	DRIVERCRATE_EXPECT(
		context, validateOfficialDistributionRecord( unsupportedRecord, unsupportedEvidence) == 0) ;
	RecordScopedDownloadGrant grant ;	// 未対応方式から発行できないgrantです。
	DRIVERCRATE_EXPECT(
		context, grant.issue( unsupportedRecord, unsupportedEvidence, 0U, 801U, 30'000U, 0U) != 0) ;
	DRIVERCRATE_EXPECT( context,
					   grant.metadata().state == OfficialDownloadGrantState::NOT_REQUESTED &&
						   !unsupportedRecord.payloads[0].targetUrl.empty()) ;
}

/**
 * @brief 偽拡張子でrecord方式を別routeへfallbackしないことを検証します。
 * @param[in,out] context Assertion集計先です。
 */
void testNoExtensionFallback( TestContext &context)
{
	OfficialDistributionRecord fakeInf =	// EXE名でもINF kindを変更しないrecordです。
		makeRecord( OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE, L"not-an-inf.exe") ;
	OfficialRecordPayloadDescriptor inf ;	// 共通routeだが検査能力なしのdescriptorです。
	DRIVERCRATE_EXPECT( context, describeSinglePayload( fakeInf, inf) == 0) ;
	DRIVERCRATE_EXPECT( context, inf.route == OfficialRecordPayloadRoute::COMMON_INF_INSPECTION &&
									!inf.contentInspectorAvailable) ;

	UpdateCandidate		candidate = makeCandidate() ;	// 表示専用評価の結合先です。
	CandidateAssessment assessment ;					// 方式を保持する八軸結果です。
	DRIVERCRATE_EXPECT( context,
					   makeOfficialRecordPayloadDisplayAssessment( inf, candidate, assessment)) ;
	DRIVERCRATE_EXPECT(
		context, assessment.installMethod == CandidateInstallMethod::STANDARD_INF &&
					 assessment.acquisition.state == CandidateAssessmentState::UNSUPPORTED &&
					 !assessment.executorAvailable && !isCandidateAssessmentReady( assessment)) ;
	candidate.assessment = assessment ;
	DRIVERCRATE_EXPECT( context, isCandidateDetailsValid( candidate, SESSION_ID)) ;

	OfficialDistributionRecord zippedInstaller =	// ZIP名でもinstaller routeを維持するrecordです。
		makeRecord( OfficialDistributionPayloadKind::OFFICIAL_INSTALLER, L"installer-container.zip") ;
	OfficialRecordPayloadDescriptor installer ;	// INF検査へfallbackしないdescriptorです。
	DRIVERCRATE_EXPECT( context, describeSinglePayload( zippedInstaller, installer) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   installer.route == OfficialRecordPayloadRoute::DEDICATED_INSTALLER_AUDIT &&
						   !installer.contentInspectorAvailable) ;
	candidate = makeCandidate() ;
	DRIVERCRATE_EXPECT(
		context, makeOfficialRecordPayloadDisplayAssessment( installer, candidate, assessment)) ;
	DRIVERCRATE_EXPECT(
		context, assessment.installMethod == CandidateInstallMethod::OFFICIAL_INSTALLER &&
					 assessment.acquisition.reason == CandidateAssessmentReason::NOT_ACQUIRED &&
					 !assessment.executorAvailable) ;

	OfficialDistributionRecord zippedUnsupported =	// ZIP名でも取得しない未対応recordです。
		makeRecord( OfficialDistributionPayloadKind::UNSUPPORTED, L"unknown-driver.zip") ;
	OfficialRecordPayloadDescriptor unsupported ;	// 表示だけを許可するdescriptorです。
	DRIVERCRATE_EXPECT( context, describeSinglePayload( zippedUnsupported, unsupported) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   unsupported.route == OfficialRecordPayloadRoute::DISPLAY_ONLY_UNSUPPORTED &&
						   !unsupported.downloadGrantSupported) ;
	candidate = makeCandidate() ;
	DRIVERCRATE_EXPECT(
		context, makeOfficialRecordPayloadDisplayAssessment( unsupported, candidate, assessment)) ;
	DRIVERCRATE_EXPECT( context, assessment.installMethod == CandidateInstallMethod::UNDETERMINED &&
									assessment.acquisition.reason ==
										CandidateAssessmentReason::FORMAT_UNSUPPORTED &&
									!assessment.executorAvailable) ;
}

/**
 * @brief Stale証拠、route改変、未知同意区分と候補能力の不一致を拒否します。
 * @param[in,out] context Assertion集計先です。
 */
void testStaleAndCapabilityRejections( TestContext &context)
{
	OfficialDistributionRecord record =	// Stale故障注入元の正常recordです。
		makeRecord( OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE, L"driver.zip") ;
	OfficialDistributionRecordEvidence evidence ;	// 正常record証拠です。
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( record, evidence) == 0) ;
	++evidence.recordEvidenceId ;
	std::vector<OfficialRecordPayloadDescriptor> descriptors( 1U) ;	// 失敗時に消去する旧出力です。
	descriptors[0].providerId = L"must-be-cleared" ;
	DRIVERCRATE_EXPECT(
		context, describeOfficialDistributionRecordPayloads( record, evidence, descriptors) != 0) ;
	DRIVERCRATE_EXPECT( context, descriptors.empty()) ;

	OfficialRecordPayloadDescriptor descriptor ;	// 改変検証に使う正常descriptorです。
	DRIVERCRATE_EXPECT( context, describeSinglePayload( record, descriptor) == 0) ;
	descriptor.route = OfficialRecordPayloadRoute::DEDICATED_INSTALLER_AUDIT ;
	DRIVERCRATE_EXPECT( context, !isOfficialRecordPayloadDescriptorValid( descriptor)) ;
	DRIVERCRATE_EXPECT( context, describeSinglePayload( record, descriptor) == 0) ;
	descriptor.terms = static_cast<OfficialDistributionTerms>( 99U) ;
	DRIVERCRATE_EXPECT( context, !isOfficialRecordPayloadDescriptorValid( descriptor)) ;

	DRIVERCRATE_EXPECT( context, describeSinglePayload( record, descriptor) == 0) ;
	UpdateCandidate candidate = makeCandidate() ;	// Provider故障注入対象の表示候補です。
	candidate.providerId	  = L"wrong-provider" ;
	CandidateAssessment assessment ;	// 失敗時に空へ戻る評価出力です。
	DRIVERCRATE_EXPECT(
		context, !makeOfficialRecordPayloadDisplayAssessment( descriptor, candidate, assessment)) ;
	DRIVERCRATE_EXPECT( context, assessment.scanSessionId == 0U) ;

	candidate			  = makeCandidate() ;
	candidate.installable = true ;
	DRIVERCRATE_EXPECT(
		context, !makeOfficialRecordPayloadDisplayAssessment( descriptor, candidate, assessment)) ;
	candidate				 = makeCandidate() ;
	candidate.discoveryBasis = CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE ;
	DRIVERCRATE_EXPECT(
		context, !makeOfficialRecordPayloadDisplayAssessment( descriptor, candidate, assessment)) ;
}

/**
 * @brief Record fingerprintとpayload ordinalだけで複数portの実行単位をまとめます。
 * @param[in,out] context Assertion集計先です。
 */
void testAutomaticDiscoveryPackageGrouping( TestContext &context)
{
	OfficialDistributionRecord record =
		// 一つの検証済みpayloadを表す架空recordです。
		makeRecord( OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE, L"driver-package.zip") ;
	OfficialRecordPayloadDescriptor payload ;	// URL非保持のpayload descriptorです。
	DRIVERCRATE_EXPECT( context, describeSinglePayload( record, payload) == 0) ;
	std::vector<ProviderDescriptor> providers = makeDiscoveryProviders() ;	// 合成registryです。
	std::vector<OfficialDiscoveryDeviceHint> devices{makeDiscoveryDevice( L"fixture-port:1"),
													 makeDiscoveryDevice( L"fixture-port:2"),
													 // 同じpackageへ対応する三portです。
													 makeDiscoveryDevice( L"fixture-port:3")} ;
	OfficialDiscoveryRoute					 firstRoute =
		// 二port routeです。
		makeDiscoveryRoute( 1U, {L"fixture-port:1", L"fixture-port:2"}) ;
	OfficialDiscoveryRoute secondRoute =
		// 同じrecordへ到達する別hint routeです。
		makeDiscoveryRoute( 2U, {L"fixture-port:3"}) ;
	const auto first = makeOfficialDiscoveryResolvedPackage( firstRoute, payload, devices,
															providers) ;	// 初出package参照です。
	OfficialRecordPayloadDescriptor secondPayload = payload ;				// 別解決を表す同じstable recordです。
	secondPayload.recordEvidenceId++ ;
	const auto second = makeOfficialDiscoveryResolvedPackage( secondRoute, secondPayload, devices,
															 providers) ;	// 二つ目のroute参照です。
	DRIVERCRATE_EXPECT( context, first.has_value() && second.has_value()) ;

	std::optional<std::vector<OfficialDiscoveryPackageGroup>> groups ;	// 重複排除結果です。
	// 両参照が成立した場合だけ一groupへまとめます。
	if( first && second) {
		const std::array packages{*first, *second} ;	// Route初出順の二参照です。
		groups = groupOfficialDiscoveryPackages( packages) ;
	}

	DRIVERCRATE_EXPECT( context, groups.has_value()) ;
	// Groupが成立した場合だけpackage、record、route、device件数を確認します。
	if( groups) {
		DRIVERCRATE_EXPECT( context, groups->size() == 1U) ;
		DRIVERCRATE_EXPECT( context, groups->front().recordEvidenceIds.size() == 2U) ;
		DRIVERCRATE_EXPECT( context, groups->front().routeIds.size() == 2U) ;
		DRIVERCRATE_EXPECT( context, groups->front().deviceIdentities.size() == 3U) ;
		DRIVERCRATE_EXPECT( context, isOfficialDiscoveryPackageGroupValid( groups->front())) ;
		const auto provider = std::find_if(
			providers.begin(), providers.end(), []( const ProviderDescriptor &descriptor) {
				return descriptor.id == INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ;
			}) ; // 自動探索候補へ結合するregistry定義です。
		// Registry定義が存在する場合だけ三deviceの非選択表示行を生成します。
		if( provider != providers.end()) {
			const auto candidates = makeOfficialRecordPayloadDisplayCandidates(
				// Record由来のdevice別表示行です。
				groups->front(), payload, devices, *provider) ;
			DRIVERCRATE_EXPECT( context, candidates.has_value() && candidates->size() == 3U) ;
			// 全行が同じpayloadを共有し、別device identityと非導入状態を持つことを確認します。
			if( candidates && candidates->size() == 3U) {
				// 生成順に全deviceの表示専用状態と初期評価を検証します。
				for( std::size_t index{}; index < candidates->size(); ++index) {
					const UpdateCandidate &candidate =
						(*candidates)[index] ;	// 今回検証する表示行です。
					DRIVERCRATE_EXPECT(
						context, candidate.deviceIdentity == devices[index].deviceIdentity &&
									 candidate.packageIdentity == groups->front().packageIdentity &&
									 candidate.action == DriverAction::NONE &&
									 !candidate.installable && !candidate.recommended &&
									 candidate.assessment.has_value() &&
									 candidate.assessment->acquisition.reason ==
										 CandidateAssessmentReason::NOT_ACQUIRED &&
									 isCandidateAuditValid( candidate, *provider) &&
									 isCandidateDetailsValid( candidate, SESSION_ID)) ;
				}
			}

			std::vector<OfficialDiscoveryDeviceHint> missingDevice =
				devices ;	// 欠落拒否用copyです。
			missingDevice.pop_back() ;
			DRIVERCRATE_EXPECT( context, !makeOfficialRecordPayloadDisplayCandidates(
											 groups->front(), payload, missingDevice, *provider)
											 .has_value()) ;
		}
	}

	// Package identityが表示名、版、URL、EULA本文から作られていないことを確認します。
	if( first) {
		DRIVERCRATE_EXPECT( context, first->packageIdentity.find( payload.fileDisplayName) ==
										std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, first->packageIdentity.find( payload.packageVersion) ==
										std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context,
						   first->packageIdentity.find( PRIVATE_TOKEN) == std::wstring::npos) ;
	}

	// 同じrecordの別payload ordinalは同一packageへまとめません。
	OfficialRecordPayloadDescriptor nextOrdinal = payload ;	// 二payload record相当の別ordinalです。
	nextOrdinal.payloadCount					= 2U ;
	nextOrdinal.payloadOrdinal					= 1U ;
	const auto distinct = makeOfficialDiscoveryResolvedPackage( firstRoute, nextOrdinal, devices,
															   providers) ;	// 別package参照です。
	DRIVERCRATE_EXPECT( context, distinct.has_value()) ;
	// 初出参照と別ordinalが成立した場合だけ二groupへ分かれることを確認します。
	if( first && distinct) {
		const std::array packages{*first, *distinct} ;	// 同じrouteの異なるpayloadです。
		const auto		 distinctGroups =
			// Payload ordinal別のgroup結果です。
			groupOfficialDiscoveryPackages( packages) ;
		DRIVERCRATE_EXPECT( context, distinctGroups.has_value() && distinctGroups->size() == 2U) ;
	}

	OfficialRecordPayloadDescriptor wrongPolicy = payload ;	// Policy差替え拒否用copyです。
	wrongPolicy.policyId						= INTEL_WIFI_OFFICIAL_SOURCE_POLICY_ID ;
	DRIVERCRATE_EXPECT(
		context, !makeOfficialDiscoveryResolvedPackage( firstRoute, wrongPolicy, devices, providers)
					  .has_value()) ;
	// 同じrouteから同じpayloadを二重報告した入力を全体拒否します。
	if( first) {
		const std::array duplicateRoutePackages{*first, *first} ;	// 不正な二重報告です。
		DRIVERCRATE_EXPECT( context,
						   !groupOfficialDiscoveryPackages( duplicateRoutePackages).has_value()) ;
		OfficialDiscoveryResolvedPackage zeroFingerprint = *first ;	// 未設定record拒否用copyです。
		zeroFingerprint.recordFingerprint				 = {} ;
		DRIVERCRATE_EXPECT( context, !isOfficialDiscoveryResolvedPackageValid( zeroFingerprint)) ;
	}
}

/**
 * @brief Positive／negative cacheのURL非保持schema、期限と全失効条件を検証します。
 * @param[in,out] context Assertion集計先です。
 */
void testOfficialDiscoveryCacheContract( TestContext &context)
{
	OfficialDistributionRecord record =
		// EULA本文と秘密URLをcacheへ渡さない一payload recordです。
		makeRecord( OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE, L"driver-package.zip") ;
	OfficialRecordPayloadDescriptor descriptor ;	// Positive entryへ縮退する公開descriptorです。
	DRIVERCRATE_EXPECT( context, describeSinglePayload( record, descriptor) == 0) ;
	const std::array descriptors{descriptor} ;	// 一recordのordinal完全集合です。
	const auto		 positive = makeOfficialDiscoveryPositiveCacheEntry(
		  descriptors, OFFICIAL_DISCOVERY_POLICY_REVISION, record.parserId, record.parserRevision,
		  30'000U, std::wstring{OPERATING_SYSTEM_FINGERPRINT},
		  std::wstring{DEVICE_CONFIGURATION_FINGERPRINT}) ;	// 24時間のURL非保持entryです。
	DRIVERCRATE_EXPECT( context, positive.has_value()) ;
	// 生成できた場合だけ保存field、秘密非出力とfreshnessを検証します。
	if( positive) {
		DRIVERCRATE_EXPECT( context, isOfficialDiscoveryCacheEntryValid( *positive)) ;
		DRIVERCRATE_EXPECT( context, positive->expiresUtcSeconds - positive->observedUtcSeconds ==
										OFFICIAL_DISCOVERY_POSITIVE_FRESH_SECONDS) ;
		const OfficialDiscoveryCachedPayload &payload =
			// 公開保存値です。
			positive->payloads.front() ;
		const std::wstring publicText =
			positive->providerId + positive->policyId + positive->rootResourceId +
			positive->parserId + positive->operatingSystemFingerprint +
			positive->deviceConfigurationFingerprint + payload.payloadResourceId +
			payload.fileDisplayName + payload.productFamily + payload.operatingSystem +
			payload.packageVersion + payload.publishedDate + payload.declaredPublisher +
			payload.eulaRevision ;	// Entryが外部化できる全文字列fieldです。
		DRIVERCRATE_EXPECT( context, publicText.find( PRIVATE_URL) == std::wstring::npos &&
										publicText.find( PRIVATE_TOKEN) == std::wstring::npos &&
										publicText.find( PRIVATE_EULA_TEXT) == std::wstring::npos &&
										publicText.find( PUBLISHED_SHA256) == std::wstring::npos) ;

		OfficialDiscoveryCacheQuery query{
			.cacheMode					= OfficialDiscoveryCacheMode::USE_FRESH,
			.providerId					= positive->providerId,
			.policyId					= positive->policyId,
			.rootResourceId				= positive->rootResourceId,
			.policyRevision				= positive->policyRevision,
			.parserId					= positive->parserId,
			.parserRevision				= positive->parserRevision,
			.nowUtcSeconds				= positive->observedUtcSeconds + 1U,
			.operatingSystemFingerprint = positive->operatingSystemFingerprint,
			.deviceConfigurationFingerprint =
				positive->deviceConfigurationFingerprint} ;	// 現在条件。
		DRIVERCRATE_EXPECT( context, evaluateOfficialDiscoveryCacheEntry( *positive, query) ==
										OfficialDiscoveryCacheDisposition::FRESH_POSITIVE) ;
		std::vector<ProviderDescriptor> providers =
			// Cache行のregistry正本。
			makeDiscoveryProviders() ;
		const auto provider =
			std::find_if( providers.begin(), providers.end(), []( const ProviderDescriptor &value) {
				return value.id == INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ;
			}) ;								 // Cache entryを所有するProvider。
		const std::vector			 devices{	// 現在device hint。
									 makeDiscoveryDevice( L"fixture-cache-device:1")} ;
		const OfficialDiscoveryRoute route =
			// 現在planの固定root route。
			makeDiscoveryRoute( 31U, {devices.front().deviceIdentity}) ;
		// Registry正本が存在する場合だけfresh cacheの表示専用復元を確認します。
		if( provider != providers.end()) {
			const auto candidates = makeOfficialDiscoveryCachedDisplayCandidates(
				*positive, query, SESSION_ID, route, devices, *provider) ;	// URL非保持の一表示行。
			DRIVERCRATE_EXPECT( context, candidates.has_value() && candidates->size() == 1U) ;
			// 一行が成立した場合だけ導入不可、非選択とcache由来表示を確認します。
			if( candidates && candidates->size() == 1U) {
				const UpdateCandidate &candidate = candidates->front() ;	// 復元したcache表示行。
				DRIVERCRATE_EXPECT(
					context, !candidate.installable && candidate.action == DriverAction::NONE &&
								 candidate.sourceLocation.find( L"cache") != std::wstring::npos) ;
			}
		}

		query.cacheMode = OfficialDiscoveryCacheMode::FORCE_REFRESH ;
		DRIVERCRATE_EXPECT( context, evaluateOfficialDiscoveryCacheEntry( *positive, query) ==
										OfficialDiscoveryCacheDisposition::STALE) ;
		// 明示refreshでは同じentryから表示行も復元しません。
		if( provider != providers.end()) {
			DRIVERCRATE_EXPECT(
				context, !makeOfficialDiscoveryCachedDisplayCandidates( *positive, query, SESSION_ID,
																	   route, devices, *provider)
							  .has_value()) ;
		}

		query.cacheMode							 = OfficialDiscoveryCacheMode::USE_FRESH ;
		query.operatingSystemFingerprint.front() = L'c' ;
		DRIVERCRATE_EXPECT( context, evaluateOfficialDiscoveryCacheEntry( *positive, query) ==
										OfficialDiscoveryCacheDisposition::STALE) ;
		query.operatingSystemFingerprint			 = positive->operatingSystemFingerprint ;
		query.deviceConfigurationFingerprint.front() = L'd' ;
		DRIVERCRATE_EXPECT( context, evaluateOfficialDiscoveryCacheEntry( *positive, query) ==
										OfficialDiscoveryCacheDisposition::STALE) ;
		query.deviceConfigurationFingerprint = positive->deviceConfigurationFingerprint ;
		++query.policyRevision ;
		DRIVERCRATE_EXPECT( context, evaluateOfficialDiscoveryCacheEntry( *positive, query) ==
										OfficialDiscoveryCacheDisposition::STALE) ;
		query.policyRevision = positive->policyRevision ;
		query.parserId += L".changed" ;
		DRIVERCRATE_EXPECT( context, evaluateOfficialDiscoveryCacheEntry( *positive, query) ==
										OfficialDiscoveryCacheDisposition::STALE) ;
		query.parserId = positive->parserId ;
		++query.parserRevision ;
		DRIVERCRATE_EXPECT( context, evaluateOfficialDiscoveryCacheEntry( *positive, query) ==
										OfficialDiscoveryCacheDisposition::STALE) ;
		query.parserRevision = positive->parserRevision ;
		query.providerId += L".changed" ;
		DRIVERCRATE_EXPECT( context, evaluateOfficialDiscoveryCacheEntry( *positive, query) ==
										OfficialDiscoveryCacheDisposition::INVALID) ;
		query.providerId = positive->providerId ;
		query.policyId += L".changed" ;
		DRIVERCRATE_EXPECT( context, evaluateOfficialDiscoveryCacheEntry( *positive, query) ==
										OfficialDiscoveryCacheDisposition::INVALID) ;
		query.policyId = positive->policyId ;
		query.rootResourceId += L".changed" ;
		DRIVERCRATE_EXPECT( context, evaluateOfficialDiscoveryCacheEntry( *positive, query) ==
										OfficialDiscoveryCacheDisposition::INVALID) ;
		query.rootResourceId = positive->rootResourceId ;
		query.nowUtcSeconds	 = positive->expiresUtcSeconds ;
		DRIVERCRATE_EXPECT( context, evaluateOfficialDiscoveryCacheEntry( *positive, query) ==
										OfficialDiscoveryCacheDisposition::STALE) ;
		query.nowUtcSeconds = positive->observedUtcSeconds - 1U ;
		DRIVERCRATE_EXPECT( context, evaluateOfficialDiscoveryCacheEntry( *positive, query) ==
										OfficialDiscoveryCacheDisposition::INVALID) ;

		OfficialDiscoveryCacheEntry corrupted = *positive ;	// 期限改変を表す保存値copyです。
		corrupted.expiresUtcSeconds++ ;
		DRIVERCRATE_EXPECT( context, !isOfficialDiscoveryCacheEntryValid( corrupted)) ;
		corrupted = *positive ;
		corrupted.payloads.push_back( corrupted.payloads.front()) ;
		DRIVERCRATE_EXPECT( context, !isOfficialDiscoveryCacheEntryValid( corrupted)) ;
		corrupted = *positive ;
		++corrupted.schemaRevision ;
		DRIVERCRATE_EXPECT( context, !isOfficialDiscoveryCacheEntryValid( corrupted)) ;
	}

	const auto negative = makeOfficialDiscoveryNegativeCacheEntry(
		OfficialDiscoveryCacheEntryKind::NO_RECORD, descriptor.providerId, descriptor.policyId,
		descriptor.rootResourceId, OFFICIAL_DISCOVERY_POLICY_REVISION, record.parserId,
		record.parserRevision, 40'000U, std::wstring{OPERATING_SYSTEM_FINGERPRINT},
		std::wstring{DEVICE_CONFIGURATION_FINGERPRINT}) ;	// 6時間の正常なrecordなしentryです。
	DRIVERCRATE_EXPECT( context, negative.has_value()) ;
	// Negativeが生成できた場合だけ、空record状態とfreshnessを確認します。
	if( negative) {
		OfficialDiscoveryCacheQuery query{
			.cacheMode					= OfficialDiscoveryCacheMode::USE_FRESH,
			.providerId					= negative->providerId,
			.policyId					= negative->policyId,
			.rootResourceId				= negative->rootResourceId,
			.policyRevision				= negative->policyRevision,
			.parserId					= negative->parserId,
			.parserRevision				= negative->parserRevision,
			.nowUtcSeconds				= negative->observedUtcSeconds + 1U,
			.operatingSystemFingerprint = negative->operatingSystemFingerprint,
			.deviceConfigurationFingerprint =
				negative->deviceConfigurationFingerprint} ;	// 現在条件。
		DRIVERCRATE_EXPECT( context, negative->payloads.empty() &&
										evaluateOfficialDiscoveryCacheEntry( *negative, query) ==
											OfficialDiscoveryCacheDisposition::FRESH_NEGATIVE) ;
		query.nowUtcSeconds = negative->expiresUtcSeconds ;
		DRIVERCRATE_EXPECT( context, evaluateOfficialDiscoveryCacheEntry( *negative, query) ==
										OfficialDiscoveryCacheDisposition::STALE) ;
	}

	const auto notApplicable = makeOfficialDiscoveryNegativeCacheEntry(
		OfficialDiscoveryCacheEntryKind::NOT_APPLICABLE, descriptor.providerId, descriptor.policyId,
		descriptor.rootResourceId, OFFICIAL_DISCOVERY_POLICY_REVISION, record.parserId,
		record.parserRevision, 45'000U, std::wstring{OPERATING_SYSTEM_FINGERPRINT},
		std::wstring{DEVICE_CONFIGURATION_FINGERPRINT}) ;	// 対象外を候補なしと区別するentryです。
	DRIVERCRATE_EXPECT( context, notApplicable.has_value()) ;
	// 対象外entryが成立した場合だけ6時間のnegative期限と空payloadを確認します。
	if( notApplicable) {
		DRIVERCRATE_EXPECT( context, notApplicable->payloads.empty() &&
										notApplicable->expiresUtcSeconds -
												notApplicable->observedUtcSeconds ==
											OFFICIAL_DISCOVERY_NEGATIVE_FRESH_SECONDS) ;
	}

	DRIVERCRATE_EXPECT( context, !makeOfficialDiscoveryNegativeCacheEntry(
									 OfficialDiscoveryCacheEntryKind::POSITIVE_RECORD,
									 descriptor.providerId, descriptor.policyId,
									 descriptor.rootResourceId, OFFICIAL_DISCOVERY_POLICY_REVISION,
									 record.parserId, record.parserRevision, 50'000U,
									 std::wstring{OPERATING_SYSTEM_FINGERPRINT},
									 std::wstring{DEVICE_CONFIGURATION_FINGERPRINT})
									 .has_value()) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_record_payload_routing_tests.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
void runOfficialRecordPayloadRoutingTests( TestContext &context)
{
	testTypedRoutesAndPrivacy( context) ;
	testNoExtensionFallback( context) ;
	testStaleAndCapabilityRejections( context) ;
	testAutomaticDiscoveryPackageGrouping( context) ;
	testOfficialDiscoveryCacheContract( context) ;
}

} // namespace drivercrate::test
