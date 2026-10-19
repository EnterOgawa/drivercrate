//------------------------------------------------------------------------------
/**
 * @file official_delegated_package_inspection_tests.cpp
 * @brief Record限定取得と共通package検査の接続単体試験を実装します。
 * @version 01.03.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  取得・内容検査・表示専用評価の接続fixtureを追加。
 * Ver.01.00.01 Shunji Ogawa  2026/09/15  公開hashと実取得hashの不一致拒否を検証。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  OF05／09／13の秘密非出力fixtureを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  PnP観測と取得後監査reportのfixtureを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  OF02／03のpackage側ID限定照合と二device結果を明示。
 * Ver.01.03.01 Shunji Ogawa  2026/10/15  全体INF件数と照合開始前のpair上限を検証。
 * </pre>
 *
 * @note 架空URLはgrantだけが所有し、通信、driver取得、導入またはinstaller実行を行いません。
 */
//------------------------------------------------------------------------------

#include "official_delegated_package_inspection_tests.h"

#include "core/candidate_assessment.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/official_delegated_package_inspection.h"
#include "platform/official_discovery_package.h"
#include "platform/official_download_workspace.h"
#include "platform/secret_official_url.h"
#include "test_framework.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr ScanSessionId		SESSION_ID			= 1'501U ;	// 架空scan session IDです。
constexpr std::uint64_t		RECORD_EVIDENCE_ID	= 301U ;	// 架空record証拠IDです。
constexpr std::uint64_t		GRANT_ID			= 401U ;	// 架空download grant IDです。
constexpr std::uint64_t		PACKAGE_EVIDENCE_ID = 501U ;	// 架空内容検査証拠IDです。
// 架空payload `abc`と結合する実取得SHA-256です。
constexpr std::wstring_view ACTUAL_SHA256 =
	L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ;
// 実fileを作らず内容拒否に使うworker内pathです。
constexpr std::wstring_view PRIVATE_PATH =
	L"C:\\develop\\DriverCrate\\work\\tmp\\never-created-secret-package.zip" ;
// 秘密URLが表示評価へ混入しないことを確認する文字列です。
constexpr std::wstring_view				 PRIVATE_URL_TOKEN = L"token=private-fixture" ;

//------------------------------------------------------------------------------
// Fixture生成関数定義。
//------------------------------------------------------------------------------

/**
 * @brief Record限定取得adapterへ渡す有効な架空recordを作ります。
 * @param[in] fileDisplayName 公式recordが表示するpayload basenameです。
 * @param[in] kind Recordが明示するpayload方式です。
 * @return Intel組み込みrootへ結合できる一payload recordです。
 */
[[nodiscard]] OfficialDistributionRecord makeRecord(
	std::wstring fileDisplayName, const OfficialDistributionPayloadKind kind =
									  OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE)
{
	OfficialDistributionRecord record ;	// 全stable fieldと秘密URLを所有する結果です。
	record.rootEvidence = OfficialSourceEvidence{
		.scanSessionId			= SESSION_ID,
		.acquisitionId			= 201U,
		.providerId				= std::wstring{INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID},
		.policyId				= std::wstring{INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID},
		.resourceId				= std::wstring{OFFICIAL_LANDING_RESOURCE_ID},
		.redirectCount			= 0U,
		.originPolicyIndices	= {0U},
		.acquisition			= MeasurementAcquisition::NETWORK_BODY,
		.bodyAcquiredUtcSeconds = 19'000U,
		.originValidatedUtcSeconds = 19'001U,
		.cachePermitted			   = false} ;
	record.recordEvidenceId = RECORD_EVIDENCE_ID ;
	record.parserId			= L"delegated-package-fixture-parser-v1" ;
	record.parserRevision	= 1U ;
	record.recordRoute		= L"delegated-package-fixture-route" ;
	record.recordKey		= L"delegated-package-fixture-record" ;
	record.productFamily	= L"Fictional Ethernet Family" ;
	record.operatingSystem	= L"Windows 11 x64" ;
	record.architecture		= OfficialDistributionArchitecture::WINDOWS_X64 ;
	record.packageVersion	= L"2.0.0.0" ;
	record.publishedDate	= L"2026-09-15" ;
	record.terms			= OfficialDistributionTerms::CONFIRMED_NO_CONSENT ;
	record.payloads.push_back( OfficialDistributionPayloadRecord{
		.resourceId				  = std::wstring{OFFICIAL_PAYLOAD_RESOURCE_ID},
		.payloadOrdinal			  = 0U,
		.kind					  = kind,
		.fileDisplayName		  = std::move( fileDisplayName),
		.publishedSizeBytes		  = 3U,
		.publishedSha256		  = std::wstring{ACTUAL_SHA256},
		.publisher				  = L"Fictional Device Vendor",
		.expectedContentType	  = L"application/zip",
		.maximumBytes			  = 64U,
		.externalExpiryUtcSeconds = std::nullopt,
		.targetUrl				  = SecretOfficialUrl{
			   L"https://temporary.fixture.invalid/driver.zip?token=private-fixture"}}) ;
	record.resolvedUtcSeconds = 19'002U ;
	return record ;
}

/**
 * @brief 架空recordからgrantを発行し、必要なら取得成功として一回消費します。
 * @param[out] grant 成功時に発行済みまたは消費済みgrantを所有します。
 * @param[in] consumeSuccess 取得成功の終端まで進める場合trueです。
 * @param[in] fileDisplayName Recordが明示するpayload basenameです。
 * @param[in] kind Recordが明示するpayload方式です。
 * @return Record検証、発行と指定した状態遷移が成功すれば0です。
 */
[[nodiscard]] NativeError makeGrant( RecordScopedDownloadGrant &grant, const bool consumeSuccess,
									std::wstring fileDisplayName = L"fictional-driver.zip",
									const OfficialDistributionPayloadKind kind =
										OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE)
{
	OfficialDistributionRecord record =
		// 秘密record。
		makeRecord( std::move( fileDisplayName), kind) ;
	OfficialDistributionRecordEvidence evidence ;	// URLを含まないrecord検証結果です。
	NativeError						   error =
		// Record検証結果です。
		validateOfficialDistributionRecord( record, evidence) ;
	// 無効recordからgrantを発行しない。
	if( error != 0) {
		return error ;
	}

	error = grant.issue( record, evidence, 0U, GRANT_ID, 20'000U, 0U) ;
	// 発行失敗時は未発行grantをそのまま返す。
	if( error != 0 || !consumeSuccess) {
		return error ;
	}

	error = grant.claim( SESSION_ID, GRANT_ID, 20'010U) ;
	// Claim失敗時は取得成功へ進めない。
	if( error != 0) {
		return error ;
	}

	SecretOfficialUrl requestUrl =
		// 一回の架空HTTP request所有URLです。
		grant.takeTargetUrlForHttp() ;
	// URL移送失敗を取得成功として終端しない。
	if( requestUrl.empty()) {
		return static_cast<NativeError>( E_FAIL) ;
	}

	return grant.finishAcquisition( OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION, 0) ;
}

/**
 * @brief 消費済みgrantへ一致する架空成功取得ledger結果を作ります。
 * @return 実pathとhashをworker内だけに持つ取得結果です。
 */
[[nodiscard]] OfficialAcquisitionResult makeAcquisition()
{
	return OfficialAcquisitionResult{
		.state					 = OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
		.error					 = 0,
		.networkCostError		 = 0,
		.networkCost			 = OfficialNetworkCostKind::UNRESTRICTED,
		.scanSessionId			 = SESSION_ID,
		.acquisitionId			 = 601U,
		.providerId				 = std::wstring{INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID},
		.resourceId				 = std::wstring{OFFICIAL_PAYLOAD_RESOURCE_ID},
		.inspectionPath			 = std::wstring{PRIVATE_PATH},
		.byteCount				 = 3U,
		.sha256					 = std::wstring{ACTUAL_SHA256},
		.publishedSizeVerified	 = true,
		.publishedSha256Verified = true,
		.delegatedRecord		 = true,
		.recordEvidenceId		 = RECORD_EVIDENCE_ID,
		.downloadGrantId		 = GRANT_ID,
		.grantReresolutionCount	 = 0U,
		.validatedDestinationAddressCount = 1U,
		.destinationLocallyResolved		  = true} ;
}

/**
 * @brief 表示専用評価へ結合する架空候補を作ります。
 * @return Providerと内容metadataへ一致するopaque identity付き候補です。
 */
[[nodiscard]] UpdateCandidate makeCandidate()
{
	UpdateCandidate candidate ;	// 秘密値を含まない表示候補です。
	candidate.identity				 = L"candidate:delegated:1" ;
	candidate.deviceIdentity		 = L"device:delegated:1" ;
	candidate.providerId			 = INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID ;
	candidate.packageIdentity		 = L"package:delegated:1" ;
	candidate.provider				 = L"Fictional Device Vendor" ;
	candidate.version				 = L"2.0.0.0" ;
	candidate.audit.installReadiness = CandidateInstallReadiness::DISPLAY_ONLY ;
	return candidate ;
}

/**
 * @brief 指定IDへ結合したraw ID非保持の架空device hintを作ります。
 * @param[in] identity UI行と結合するopaque identityです。
 * @return Intel公式固定rootへroute可能なNet classのPCI deviceです。
 */
[[nodiscard]] OfficialDiscoveryDeviceHint makeDevice( std::wstring identity)
{
	OfficialDiscoveryDeviceHint device ;	// 実PnP IDを含まない合成deviceです。
	device.deviceIdentity			  = std::move( identity) ;
	device.bus						  = OfficialDiscoveryDeviceBus::PCI ;
	device.setupClassGuid			  = L"{4d36e972-e325-11ce-bfc1-08002be10318}" ;
	device.deviceClass				  = L"Net" ;
	device.manufacturer				  = L"Fictional Device Vendor" ;
	device.model					  = L"Fictional Ethernet Adapter" ;
	device.observation.scanSessionId  = SESSION_ID ;
	device.observation.deviceIdentity = device.deviceIdentity ;
	return device ;
}

/**
 * @brief 架空recordとdevice集合からdescriptorと実行groupを生成します。
 * @param[in] devices Groupへ結合する検証済みdevice hint集合です。
 * @param[in] kind Recordが明示するpayload方式です。
 * @param[out] descriptor 成功時のURL非保持payload descriptorです。
 * @param[out] group 成功時のrecord／route／device結合groupです。
 * @return 全record、routeとgroup検証が成功すればtrueです。
 */
[[nodiscard]] bool makePayloadBinding( const std::span<const OfficialDiscoveryDeviceHint> devices,
									  const OfficialDistributionPayloadKind				 kind,
									  OfficialRecordPayloadDescriptor					&descriptor,
									  OfficialDiscoveryPackageGroup						&group)
{
	descriptor = {} ;
	group	   = {} ;
	OfficialDistributionRecord record =
		// 秘密URLを関数内だけに保持する架空公式recordです。
		makeRecord( kind == OfficialDistributionPayloadKind::OFFICIAL_INSTALLER
					   ? L"fictional-installer.exe"
					   : L"fictional-driver.zip",
				   kind) ;
	OfficialDistributionRecordEvidence evidence ;	// URL非保持の検証済みrecord証拠です。
	// Record検証失敗時は部分descriptorを公開しない。
	if( validateOfficialDistributionRecord( record, evidence) != 0) {
		return false ;
	}

	std::vector<OfficialRecordPayloadDescriptor> descriptors ;	// 一payloadの表示descriptor集合です。
	// Descriptor変換の件数が一件でなければrouteへ進めない。
	if( describeOfficialDistributionRecordPayloads( record, evidence, descriptors) != 0 ||
	   descriptors.size() != 1U) {
		return false ;
	}

	OfficialDiscoveryRoute route ;	// 固定Intel landingと全deviceを結合する架空routeです。
	route.routeId			= 1U ;
	route.providerId		= INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID ;
	route.rootResourceId	= OFFICIAL_LANDING_RESOURCE_ID ;
	route.kind				= OfficialDiscoveryRouteKind::DEDICATED ;
	route.hintGroupIdentity = L"delegated-package-fixture-group" ;
	// 入力順をgroupとreportのdevice対応順として保持する。
	for( const OfficialDiscoveryDeviceHint &device : devices) {
		route.deviceIdentities.push_back( device.deviceIdentity) ;
	}

	const auto package =
		makeOfficialDiscoveryResolvedPackage( route, descriptors.front(), devices,
											 // Registryと公式policyへ拘束したpackage参照です。
											 builtInProviderDescriptors()) ;
	// RouteまたはProvider不整合を合成groupで補完しない。
	if( !package) {
		return false ;
	}

	const std::array<OfficialDiscoveryResolvedPackage, 1U> packages{*package} ;	// 一件集約入力。
	const auto groups = groupOfficialDiscoveryPackages( packages) ;				// 実装と同じgroup化結果です。
	// 一件以外の集約結果を任意選択しない。
	if( !groups || groups->size() != 1U) {
		return false ;
	}

	descriptor = std::move( descriptors.front()) ;
	group	   = std::move( groups->front()) ;
	return true ;
}

/**
 * @brief Descriptorとgroupへ一致する取得承認targetを作ります。
 * @param[in] descriptor Payload resourceと利用条件の正本です。
 * @param[in] group Opaque package identityとdevice件数の正本です。
 * @return 64 byte上限の架空準備対象です。
 */
[[nodiscard]] OfficialPreparationTarget makeTarget(
	const OfficialRecordPayloadDescriptor &descriptor, const OfficialDiscoveryPackageGroup &group)
{
	OfficialPreparationTarget target ;	// URLと端末識別子を含まない承認snapshotです。
	target.identity		   = group.packageIdentity ;
	target.providerId	   = descriptor.providerId ;
	target.resourceId	   = descriptor.payloadResourceId ;
	target.releaseIdentity = L"delegated-package-fixture-release" ;
	target.parserRevision  = 1U ;
	target.maximumBytes	   = 64U ;
	target.deviceCount	   = static_cast<std::uint32_t>( group.deviceIdentities.size()) ;
	target.terms		   = OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
	return target ;
}

//------------------------------------------------------------------------------
// 接続・拒否試験。
//------------------------------------------------------------------------------

/**
 * @brief 正常変換とstale、取消し、例外、内容拒否時の全体結果消去を検証します。
 * @param[in,out] context Assertion集計先です。
 */
void testConversionAndInspectionFailures( TestContext &context)
{
	RecordScopedDownloadGrant grant ;	// 成功終端させる架空grantです。
	DRIVERCRATE_EXPECT( context, makeGrant( grant, true) == 0) ;
	const OfficialAcquisitionResult acquisition = makeAcquisition() ;	// 対応する取得ledger結果です。
	DelegatedOfficialPackageInput	input ;								// Adapter出力です。
	DRIVERCRATE_EXPECT( context, makeDelegatedOfficialPackageInput( acquisition, grant, input) == 0) ;
	DRIVERCRATE_EXPECT( context, input.archive.inspectionPath == PRIVATE_PATH) ;
	DRIVERCRATE_EXPECT( context, input.archive.sha256 == ACTUAL_SHA256) ;
	DRIVERCRATE_EXPECT( context, input.provenance.acquisitionId == 601U) ;
	DRIVERCRATE_EXPECT( context, input.provenance.recordEvidenceId == RECORD_EVIDENCE_ID) ;
	DRIVERCRATE_EXPECT( context, input.provenance.downloadGrantId == GRANT_ID) ;
	DRIVERCRATE_EXPECT( context, grant.payloadView().targetUrl.empty()) ;

	CommonDriverPackageInspection inspection ;	// 各失敗で部分結果を残さない出力です。
	DRIVERCRATE_EXPECT(
		context, inspectDelegatedOfficialDriverPackage( SESSION_ID + 1U, input, inspection) != 0) ;
	DRIVERCRATE_EXPECT( context, inspection.scanSessionId == 0U && inspection.infs.empty()) ;

	const std::function<bool()> cancellation = []() noexcept {
		return true ;
	} ; // 即時取消しfixture。
	DRIVERCRATE_EXPECT( context, inspectDelegatedOfficialDriverPackage( SESSION_ID, input, inspection,
																	  cancellation) != 0) ;
	DRIVERCRATE_EXPECT( context, inspection.scanSessionId == 0U && inspection.infs.empty()) ;

	const std::function<bool()> throwingCancellation =
		[]() -> bool {	// 例外を返す外部callbackです。
		throw std::runtime_error( "fixture cancellation failure") ;
	} ;
	DRIVERCRATE_EXPECT( context, inspectDelegatedOfficialDriverPackage( SESSION_ID, input, inspection,
																	  throwingCancellation) != 0) ;
	DRIVERCRATE_EXPECT( context, inspection.scanSessionId == 0U && inspection.infs.empty()) ;

	DRIVERCRATE_EXPECT( context,
					   inspectDelegatedOfficialDriverPackage( SESSION_ID, input, inspection) != 0) ;
	DRIVERCRATE_EXPECT( context, inspection.scanSessionId == 0U &&
									inspection.archiveSha256.empty() && inspection.infs.empty()) ;
}

/**
 * @brief Grant未消費、Provider不一致、公開metadata矛盾と未対応形式を拒否することを検証します。
 * @param[in,out] context Assertion集計先です。
 */
void testConversionRejections( TestContext &context)
{
	RecordScopedDownloadGrant consumed ;	// 正常消費済みgrantです。
	DRIVERCRATE_EXPECT( context, makeGrant( consumed, true) == 0) ;
	OfficialAcquisitionResult	  acquisition = makeAcquisition() ;	// 故障注入対象の取得結果です。
	DelegatedOfficialPackageInput output ;							// 失敗時に消去される出力です。

	acquisition.providerId		  = L"wrong-provider" ;
	output.archive.inspectionPath = L"must-be-cleared" ;
	DRIVERCRATE_EXPECT( context,
					   makeDelegatedOfficialPackageInput( acquisition, consumed, output) != 0) ;
	DRIVERCRATE_EXPECT( context, output.archive.inspectionPath.empty() &&
									output.provenance.providerId.empty()) ;

	acquisition							= makeAcquisition() ;
	acquisition.publishedSha256Verified = false ;
	DRIVERCRATE_EXPECT( context,
					   makeDelegatedOfficialPackageInput( acquisition, consumed, output) != 0) ;

	acquisition		   = makeAcquisition() ;
	acquisition.sha256 = L"aa7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ;
	DRIVERCRATE_EXPECT( context,
					   makeDelegatedOfficialPackageInput( acquisition, consumed, output) != 0) ;

	RecordScopedDownloadGrant issued ;	// 未消費状態を維持するgrantです。
	DRIVERCRATE_EXPECT( context, makeGrant( issued, false) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   makeDelegatedOfficialPackageInput( makeAcquisition(), issued, output) != 0) ;

	RecordScopedDownloadGrant unsupportedExtension ;	// 内容から補完しない拡張子fixtureです。
	DRIVERCRATE_EXPECT( context,
					   makeGrant( unsupportedExtension, true, L"fictional-driver.exe") == 0) ;
	DRIVERCRATE_EXPECT( context, makeDelegatedOfficialPackageInput(
									makeAcquisition(), unsupportedExtension, output) != 0) ;

	RecordScopedDownloadGrant installer ;	// INF共通検査へ渡さないinstaller方式fixtureです。
	DRIVERCRATE_EXPECT( context,
					   makeGrant( installer, true, L"fictional-installer.zip",
								 OfficialDistributionPayloadKind::OFFICIAL_INSTALLER) == 0) ;
	DRIVERCRATE_EXPECT(
		context, makeDelegatedOfficialPackageInput( makeAcquisition(), installer, output) != 0) ;
}

/**
 * @brief 個別拒否を保持しつつ合格INFだけを公式由来の表示専用評価へ結合します。
 * @param[in,out] context Assertion集計先です。
 */
void testPartialAssessmentAndPrivacy( TestContext &context)
{
	RecordScopedDownloadGrant grant ;	// 成功終端させる架空grantです。
	DRIVERCRATE_EXPECT( context, makeGrant( grant, true) == 0) ;
	DelegatedOfficialPackageInput input ;	// 共通検査との結合入力です。
	DRIVERCRATE_EXPECT( context,
					   makeDelegatedOfficialPackageInput( makeAcquisition(), grant, input) == 0) ;

	CommonDriverPackageInspection packageInspection ;	// 一件拒否、一件合格の部分結果です。
	packageInspection.scanSessionId = SESSION_ID ;
	packageInspection.archiveSha256 = std::wstring{ACTUAL_SHA256} ;
	packageInspection.archiveBytes	= 3U ;
	CommonInfInspection rejected ;	// 静的閉包を作れなかった個別結果です。
	rejected.scanSessionId = SESSION_ID ;
	rejected.state		   = CommonInfInspectionState::CLOSURE_REJECTED ;
	rejected.error		   = static_cast<NativeError>( E_INVALIDARG) ;
	packageInspection.infs.push_back( std::move( rejected)) ;

	CommonInfInspection verified ;	// 内容と署名を検証済みとする架空個別結果です。
	verified.scanSessionId			  = SESSION_ID ;
	verified.state					  = CommonInfInspectionState::VERIFIED ;
	verified.workspace				  = std::make_unique<OfficialDownloadWorkspace>() ;
	const NativeError initializeError =	// 後始末を観測する保護workspace作成結果です。
		verified.workspace->initialize( L"delegated-fixture", SESSION_ID) ;
	DRIVERCRATE_EXPECT( context, initializeError == 0) ;
	HANDLE		 marker = INVALID_HANDLE_VALUE ;					// Workspace destructorが削除する空file handleです。
	NativeError	 markerError = static_cast<NativeError>( E_FAIL) ;	// Marker作成結果です。
	std::wstring markerPath ;										// Destructor後の削除確認にだけ使うtest内pathです。
	// 初期化済みworkspaceだけへ後始末確認用fileを作る。
	if( initializeError == 0) {
		markerError = verified.workspace->createFile( L"cleanup-marker.bin", marker) ;
		markerPath	= verified.workspace->path( L"cleanup-marker.bin") ;
	}

	DRIVERCRATE_EXPECT( context, markerError == 0 && marker != INVALID_HANDLE_VALUE) ;
	// 作成成功handleを閉じ、destructorによるfile削除を妨げない。
	if( marker != INVALID_HANDLE_VALUE) {
		CloseHandle( marker) ;
	}

	verified.closure.packages.push_back(
		{.providerName = L"Fictional Device Vendor", .driverVersion = L"2.0.0.0"}) ;
	packageInspection.infs.push_back( std::move( verified)) ;

	UpdateCandidate		candidate = makeCandidate() ;	// 公式Providerの表示専用候補です。
	CandidateAssessment assessment ;					// 結合成功時だけ設定する八軸評価です。
	DRIVERCRATE_EXPECT( context, !makeDelegatedOfficialInfCandidateAssessment(
									SESSION_ID, input, candidate, packageInspection, 0U,
									PACKAGE_EVIDENCE_ID, 0, 0x1000U, assessment)) ;
	DRIVERCRATE_EXPECT( context, assessment.scanSessionId == 0U) ;
	DRIVERCRATE_EXPECT( context, makeDelegatedOfficialInfCandidateAssessment(
									SESSION_ID, input, candidate, packageInspection, 1U,
									PACKAGE_EVIDENCE_ID, 0, 0x1000U, assessment)) ;
	DRIVERCRATE_EXPECT( context, assessment.origin.state == CandidateAssessmentState::PASSED &&
									assessment.origin.evidenceKind ==
										CandidateEvidenceKind::OFFICIAL_RECORD &&
									assessment.origin.evidenceId == RECORD_EVIDENCE_ID) ;
	DRIVERCRATE_EXPECT(
		context, assessment.acquisition.evidenceId == PACKAGE_EVIDENCE_ID &&
					 assessment.method.state == CandidateAssessmentState::UNSUPPORTED &&
					 !assessment.executorAvailable && !isCandidateAssessmentReady( assessment)) ;
	DRIVERCRATE_EXPECT( context,
					   !candidate.installable && candidate.audit.installReadiness ==
													 CandidateInstallReadiness::DISPLAY_ONLY) ;

	DRIVERCRATE_EXPECT(
		context, assessment.candidateIdentity.find( PRIVATE_PATH) == std::wstring::npos &&
					 assessment.packageIdentity.find( ACTUAL_SHA256) == std::wstring::npos &&
					 input.provenance.providerId.find( PRIVATE_URL_TOKEN) == std::wstring::npos &&
					 input.provenance.payloadResourceId.find( PRIVATE_PATH) == std::wstring::npos) ;
	const std::wstring publicText =
		input.provenance.providerId + input.provenance.policyId + input.provenance.rootResourceId +
		input.provenance.payloadResourceId + assessment.candidateIdentity +
		assessment.deviceIdentity +
		assessment.packageIdentity ;	// UI・reportへ渡せる文字列fieldの直列化。
	constexpr std::array<std::wstring_view, 5U> PRIVATE_TOKENS{
		L"temporary.fixture.invalid", L"/driver.zip", PRIVATE_URL_TOKEN, PRIVATE_PATH,
		ACTUAL_SHA256} ;	// 公開fieldへ現れてはならないURL、query、path、hash片。
	// 全秘密片がURL非保持provenanceと表示評価へ混入しないことを個別に検証する。
	for( const std::wstring_view token : PRIVATE_TOKENS) {
		DRIVERCRATE_EXPECT( context, publicText.find( token) == std::wstring::npos) ;
	}

	candidate.providerId = L"wrong-provider" ;
	DRIVERCRATE_EXPECT( context, !makeDelegatedOfficialInfCandidateAssessment(
									SESSION_ID, input, candidate, packageInspection, 1U,
									PACKAGE_EVIDENCE_ID, 0, 0x1000U, assessment)) ;
	DRIVERCRATE_EXPECT( context, assessment.scanSessionId == 0U) ;

	candidate				= makeCandidate() ;
	packageInspection.error = static_cast<NativeError>( E_FAIL) ;
	DRIVERCRATE_EXPECT( context, !makeDelegatedOfficialInfCandidateAssessment(
									SESSION_ID, input, candidate, packageInspection, 1U,
									PACKAGE_EVIDENCE_ID, 0, 0x1000U, assessment)) ;
	packageInspection.error = 0 ;

	packageInspection.infs[1].workspace.reset() ;
	DRIVERCRATE_EXPECT( context, !markerPath.empty() && GetFileAttributesW( markerPath.c_str()) ==
														   INVALID_FILE_ATTRIBUTES) ;
}

/**
 * @brief 内容合格後のread-only PnP観測と既存表示行reportを検証します。
 * @param[in,out] context Assertion集計先です。
 */
void testApplicabilityAndPreparationReport( TestContext &context)
{
	RecordScopedDownloadGrant grant ;	// 共通内容検査入力へ結合する消費済みgrantです。
	DRIVERCRATE_EXPECT( context, makeGrant( grant, true) == 0) ;
	const OfficialAcquisitionResult acquisition =
		// URL非保持の成功取得結果です。
		makeAcquisition() ;
	DelegatedOfficialPackageInput input ;	// PnP観測まで保持する由来結合入力です。
	DRIVERCRATE_EXPECT( context, makeDelegatedOfficialPackageInput( acquisition, grant, input) == 0) ;

	std::vector<OfficialDiscoveryDeviceHint> devices ;	// Group順の二device fixtureです。
	devices.push_back( makeDevice( L"device:delegated:1")) ;
	devices.push_back( makeDevice( L"device:delegated:2")) ;
	OfficialRecordPayloadDescriptor descriptor ;	// Recordから生成するURL非保持descriptorです。
	OfficialDiscoveryPackageGroup	group ;			// Record、routeとdeviceの結合groupです。
	DRIVERCRATE_EXPECT(
		context, makePayloadBinding( devices, OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE,
									descriptor, group)) ;

	CommonDriverPackageInspection packageInspection ;	// 一件拒否、一件合格の内容結果です。
	packageInspection.scanSessionId = SESSION_ID ;
	packageInspection.archiveSha256 = std::wstring{ACTUAL_SHA256} ;
	packageInspection.archiveBytes	= 3U ;
	CommonInfInspection rejected ;	// 個別拒否を全体失敗と区別するINFです。
	rejected.scanSessionId = SESSION_ID ;
	rejected.state		   = CommonInfInspectionState::SIGNATURE_REJECTED ;
	rejected.error		   = static_cast<NativeError>( E_ACCESSDENIED) ;
	packageInspection.infs.push_back( std::move( rejected)) ;
	CommonInfInspection verified ;	// PnP observerへ渡る一つの合格INFです。
	verified.scanSessionId = SESSION_ID ;
	verified.state		   = CommonInfInspectionState::VERIFIED ;
	verified.workspace	   = std::make_unique<OfficialDownloadWorkspace>() ;
	DRIVERCRATE_EXPECT( context, verified.workspace->initialize( L"delegated-pnp", SESSION_ID) == 0) ;
	OfficialInfPackage package ;	// 実fileを参照しない合成済みINF構造です。
	package.infRelativePath = L"driver\\fixture.inf" ;
	package.className		= L"Net" ;
	package.providerName	= L"Fictional Device Vendor" ;
	package.driverVersion	= L"2.0.0.0" ;
	package.hardwareIds.push_back( L"PCI\\VEN_FAKE&DEV_0001") ;
	verified.closure.packages.push_back( std::move( package)) ;
	packageInspection.infs.push_back( std::move( verified)) ;

	std::vector<std::wstring> observedDevices ;	// Observer呼出し順を確認するopaque ID集合です。
	bool packageIdentifierObserved{} ;			// Package側IDだけがlocal matcherへ到達した場合trueです。
	const DelegatedOfficialInfRankObserver observer =
		[&observedDevices, &packageIdentifierObserved](
			const ScanSessionId session, const std::wstring_view		 deviceIdentity,
			const OfficialDownloadWorkspace &, const OfficialInfPackage &observedPackage,
			std::optional<std::uint32_t> &candidateRank) {
			observedDevices.emplace_back( deviceIdentity) ;
			packageIdentifierObserved =
				packageIdentifierObserved ||
				(observedPackage.hardwareIds.size() == 1U &&
				 observedPackage.hardwareIds.front() == L"PCI\\VEN_FAKE&DEV_0001") ;
			// 最初のdeviceだけへWindows一致rankを返し、二件目は正常な非適用とする。
			if( session == SESSION_ID && deviceIdentity == L"device:delegated:1" &&
			   observedPackage.className == L"Net") {
				candidateRank = 0x1000U ;
			} else {
				candidateRank.reset() ;
			}

			return static_cast<NativeError>( 0) ;
		} ; // Test内だけでWindows rank観測を決定的に置換するcallbackです。
	std::vector<DelegatedOfficialDeviceApplicability> applicability ;	// Device別観測出力です。
	DRIVERCRATE_EXPECT(
		context, inspectDelegatedOfficialDriverApplicability(
					 SESSION_ID, input, packageInspection, devices, observer, applicability) == 0) ;
	DRIVERCRATE_EXPECT( context, observedDevices.size() == 2U && applicability.size() == 2U) ;
	DRIVERCRATE_EXPECT( context, packageIdentifierObserved) ;
	DRIVERCRATE_EXPECT( context, applicability[0].examinedPairCount == 1U &&
									applicability[0].applicablePairCount == 1U &&
									applicability[0].failedPairCount == 0U) ;
	DRIVERCRATE_EXPECT( context, applicability[1].examinedPairCount == 1U &&
									applicability[1].applicablePairCount == 0U &&
									applicability[1].failedPairCount == 0U) ;

	const std::array<std::wstring, 2U> candidateIdentities{
		L"candidate:delegated:1", L"candidate:delegated:2"} ;	// Group順の既存表示行IDです。
	const OfficialPreparationTarget target =
		// 取得承認snapshotです。
		makeTarget( descriptor, group) ;
	const auto report = makeDelegatedOfficialPreparationAuditReport(
		target, group, descriptor, candidateIdentities, acquisition, 0, packageInspection, 0,
		applicability) ;	// 取得・内容・PnPの非機密集計です。
	DRIVERCRATE_EXPECT( context, report.has_value()) ;
	// Reportが生成できた場合だけfieldを参照し、失敗時のtest process例外を避ける。
	if( report) {
		DRIVERCRATE_EXPECT( context, report->candidates.size() == 2U) ;
		// 想定件数を満たさない失敗結果から候補fieldを参照しません。
		if( report->candidates.size() != 2U) {
			return ;
		}

		const std::wstring publicText =
			report->targetIdentity + report->providerId + report->candidates[0].identity +
			report->candidates[1].identity ;	// UIへ渡せる文字列fieldです。
		DRIVERCRATE_EXPECT( context,
						   publicText.find( L"PCI\\VEN_FAKE&DEV_0001") == std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, report->content == CandidateAuditGateState::PASSED &&
										report->applicability == CandidateAuditGateState::PASSED) ;
		DRIVERCRATE_EXPECT( context, report->infCount == 2U && report->acceptedInfCount == 1U &&
										report->examinedPairCount == 2U &&
										report->applicablePairCount == 1U) ;
		DRIVERCRATE_EXPECT( context, report->candidates.size() == 2U &&
										report->candidates[0].audit.systemApplicability ==
											CandidateAuditGateState::PASSED &&
										report->candidates[1].audit.systemApplicability ==
											CandidateAuditGateState::REJECTED) ;
		DRIVERCRATE_EXPECT(
			context,
			report->publication.state ==
					OfficialPreparationCandidatePublicationState::NOT_STARTED &&
				!report->candidatePublicationAttempted && report->publishedCandidates.empty() &&
				report->candidates[0].audit.installReadiness == CandidateInstallReadiness::BLOCKED) ;
	}

	std::reverse( applicability.begin(), applicability.end()) ;
	DRIVERCRATE_EXPECT( context, !makeDelegatedOfficialPreparationAuditReport(
									 target, group, descriptor, candidateIdentities, acquisition, 0,
									 packageInspection, 0, applicability)
									 .has_value()) ;

	const NativeError pnpFailure = static_cast<NativeError>( E_FAIL) ;	// PnP全体失敗fixtureです。
	const auto		  failedPnpReport = makeDelegatedOfficialPreparationAuditReport(
		   target, group, descriptor, candidateIdentities, acquisition, 0, packageInspection,
		   pnpFailure, {}) ;	// 個別結果を持たない全体失敗reportです。
	DRIVERCRATE_EXPECT( context,
					   failedPnpReport.has_value() &&
						   failedPnpReport->content == CandidateAuditGateState::PASSED &&
						   failedPnpReport->applicability == CandidateAuditGateState::FAILURE &&
						   failedPnpReport->candidates[0].audit.systemApplicability ==
							   CandidateAuditGateState::FAILURE) ;

	const NativeError conversionFailure = static_cast<NativeError>( E_INVALIDARG) ;	// 変換失敗です。
	const CommonDriverPackageInspection emptyInspection ;							// 入力変換前なので未開始の内容結果です。
	const auto failedContentReport = makeDelegatedOfficialPreparationAuditReport(
		target, group, descriptor, candidateIdentities, acquisition, conversionFailure,
		emptyInspection, 0, {}) ;	// 取得成功と内容処理失敗を分離するreportです。
	DRIVERCRATE_EXPECT( context,
					   failedContentReport.has_value() &&
						   failedContentReport->content == CandidateAuditGateState::FAILURE &&
						   failedContentReport->applicability == CandidateAuditGateState::PENDING) ;

	OfficialRecordPayloadDescriptor installerDescriptor ;	// 公式installer表示descriptorです。
	OfficialDiscoveryPackageGroup	installerGroup ;		// 同じdevice群のinstaller実行groupです。
	DRIVERCRATE_EXPECT(
		context, makePayloadBinding( devices, OfficialDistributionPayloadKind::OFFICIAL_INSTALLER,
									installerDescriptor, installerGroup)) ;
	const OfficialPreparationTarget installerTarget =
		// Installer取得承認snapshotです。
		makeTarget( installerDescriptor, installerGroup) ;
	const NativeError unsupportedAudit = static_cast<NativeError>(
		// 専用監査未接続の明示診断です。
		HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
	const auto installerReport = makeDelegatedOfficialPreparationAuditReport(
		installerTarget, installerGroup, installerDescriptor, candidateIdentities, acquisition,
		unsupportedAudit, emptyInspection, 0, {}) ;	// 取得済み・監査待ちのinstaller reportです。
	DRIVERCRATE_EXPECT( context,
					   installerReport.has_value() &&
						   installerReport->content == CandidateAuditGateState::PENDING &&
						   installerReport->applicability == CandidateAuditGateState::PENDING &&
						   installerReport->candidates[0].audit.inspectionDownload ==
							   CandidateAuditGateState::PASSED &&
						   installerReport->candidates[0].audit.installReadiness ==
							   CandidateInstallReadiness::BLOCKED) ;

	applicability.push_back( {.deviceIdentity = L"must-be-cleared"}) ;
	const std::function<bool()> cancellation = []() noexcept {
		return true ;
	} ; // 即時取消しで部分PnP結果を破棄するfixtureです。
	DRIVERCRATE_EXPECT( context, inspectDelegatedOfficialDriverApplicability(
									SESSION_ID, input, packageInspection, devices, observer,
									applicability, cancellation) != 0) ;
	DRIVERCRATE_EXPECT( context, applicability.empty()) ;

	const DelegatedOfficialInfRankObserver throwingObserver =
		[]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
		   const OfficialInfPackage &, std::optional<std::uint32_t> &) -> NativeError {
		throw std::runtime_error( "fixture rank observer failure") ;
	} ; // 外部callback例外をworker境界で封じるfixtureです。
	DRIVERCRATE_EXPECT( context, inspectDelegatedOfficialDriverApplicability(
									SESSION_ID, input, packageInspection, devices, throwingObserver,
									applicability) != 0) ;
	DRIVERCRATE_EXPECT( context, applicability.empty()) ;
}

/**
 * @brief 一般reportの全体INF件数と全照合開始前の有限予算を検証します。
 * @param[in,out] context Assertion集計先です。
 */
void testWholePayloadCountAndPairBudget( TestContext &context)
{
	RecordScopedDownloadGrant grant ;	// 通信しない架空の消費済みgrantです。
	DRIVERCRATE_EXPECT( context, makeGrant( grant, true) == 0) ;
	const auto					  acquisition = makeAcquisition() ;	// 三byteの合成取得結果です。
	DelegatedOfficialPackageInput input ;							// 実fileを持たないPnP境界入力です。
	DRIVERCRATE_EXPECT( context, makeDelegatedOfficialPackageInput( acquisition, grant, input) == 0) ;
	std::vector<OfficialDiscoveryDeviceHint> devices{makeDevice( L"device:delegated:1"),
													 // 架空の二deviceを固定します。
													 makeDevice( L"device:delegated:2")} ;
	OfficialRecordPayloadDescriptor			 descriptor ;	// 同じ取得元を指す表示descriptorです。
	OfficialDiscoveryPackageGroup			 group ;		// 取得とdeviceを結ぶ固定groupです。
	DRIVERCRATE_EXPECT(
		context, makePayloadBinding( devices, OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE,
									descriptor, group)) ;
	const auto target = makeTarget( descriptor, group) ;	// 取得承認のsnapshotです。
	const std::array<std::wstring, 2> identities{L"candidate:count:1",
												 L"candidate:count:2"} ;	// 表示行です。
	CommonDriverPackageInspection	  inspection ;							// 内容検査を実行した証拠にはしない合成構造です。
	inspection.scanSessionId = SESSION_ID ;
	inspection.archiveSha256 = std::wstring{ACTUAL_SHA256} ;
	inspection.archiveBytes	 = 3U ;
	std::uint32_t						   calls{} ;	// 非導入observerの呼出回数です。
	const DelegatedOfficialInfRankObserver observer =
		[&calls]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
				 const OfficialInfPackage &, std::optional<std::uint32_t> &rank) {
			++calls ;
			rank.reset() ;
			return NativeError{} ;
		} ; // 全pairを正常な非適用とし、内容合格を適合へ変えません。
	std::vector<DelegatedOfficialDeviceApplicability> applicability ;	// 完了時だけ受け取る集計です。
	// 33件・実測相当57件・4096件の全内容を省略せず集計します。
	for( const std::uint32_t count : {33U, 57U, 4096U}) {
		// 次の有限件数まで架空の所有workspaceを追加し、実fileを生成しません。
		while( inspection.infs.size() < count) {
			CommonInfInspection inf ;	// CAT等の実検査結果として報告しないfixtureです。
			inf.scanSessionId = SESSION_ID ;
			inf.state		  = CommonInfInspectionState::VERIFIED ;
			inf.workspace	  = std::make_unique<OfficialDownloadWorkspace>() ;
			inf.closure.packages.emplace_back() ;
			inspection.infs.push_back( std::move( inf)) ;
		}

		calls = 0U ;
		DRIVERCRATE_EXPECT(
			context, inspectDelegatedOfficialDriverApplicability(
						 SESSION_ID, input, inspection, devices, observer, applicability) == 0) ;
		DRIVERCRATE_EXPECT( context, calls == count * 2U) ;
		const auto report = makeDelegatedOfficialPreparationAuditReport(
			target, group, descriptor, identities, acquisition, 0, inspection, 0,
			applicability) ;	// 一般producerを直接検証します。
		DRIVERCRATE_EXPECT(
			context, report && report->acceptedInfCount == count && report->infCount == count &&
						 report->examinedPairCount == count * 2U &&
						 report->applicablePairCount == 0U && report->publishedCandidates.empty()) ;
	}

	// 全体4096 INFと32deviceで旧最大仕事量131072組の境界を確認します。
	while( devices.size() < 32U) {
		devices.push_back( makeDevice( L"device:count:" + std::to_wstring( devices.size()))) ;
	}

	calls = 0U ;
	DRIVERCRATE_EXPECT(
		context, inspectDelegatedOfficialDriverApplicability( SESSION_ID, input, inspection, devices,
															 observer, applicability) == 0) ;
	DRIVERCRATE_EXPECT( context, calls == 131072U) ;
	devices.push_back( makeDevice( L"device:count:overflow")) ;
	calls = 0U ;
	DRIVERCRATE_EXPECT(
		context, inspectDelegatedOfficialDriverApplicability( SESSION_ID, input, inspection, devices,
															 observer, applicability) != 0) ;
	DRIVERCRATE_EXPECT( context, calls == 0U && applicability.empty()) ;
	devices.resize( 2U) ;
	inspection.infs.emplace_back() ;
	DRIVERCRATE_EXPECT(
		context, inspectDelegatedOfficialDriverApplicability( SESSION_ID, input, inspection, devices,
															 observer, applicability) != 0) ;
	DRIVERCRATE_EXPECT( context, calls == 0U && applicability.empty()) ;
	DRIVERCRATE_EXPECT(
		context, !makeDelegatedOfficialPreparationAuditReport( target, group, descriptor, identities,
															  acquisition, 0, inspection, 0, {})
					  .has_value()) ;
	inspection.infs.pop_back() ;
	inspection.infs.front().error = static_cast<NativeError>( E_ACCESSDENIED) ;
	DRIVERCRATE_EXPECT(
		context, inspectDelegatedOfficialDriverApplicability( SESSION_ID, input, inspection, devices,
															 observer, applicability) != 0) ;
	DRIVERCRATE_EXPECT( context, calls == 0U && applicability.empty()) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_delegated_package_inspection_tests.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
void runOfficialDelegatedPackageInspectionTests( TestContext &context)
{
	testWholePayloadCountAndPairBudget( context) ;
	testConversionAndInspectionFailures( context) ;
	testConversionRejections( context) ;
	testPartialAssessmentAndPrivacy( context) ;
	testApplicabilityAndPreparationReport( context) ;
}

} // namespace drivercrate::test
