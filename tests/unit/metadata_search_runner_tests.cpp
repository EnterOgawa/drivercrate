//------------------------------------------------------------------------------
/**
 * @file metadata_search_runner_tests.cpp
 * @brief 専用Registry実行と表示専用終端の決定的試験。
 * @version 01.02.01
 * @date 2026/09/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  非取得専用実行の決定的試験を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Local観測snapshotの引継ぎと不正結合拒否を検証。
 * Ver.01.01.01 Shunji Ogawa  2026/09/15  組み込みProvider件数を更新。
 * Ver.01.01.02 Shunji Ogawa  2026/10/12  不成立結果のoptionalを参照しないfixtureへ補正。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.02.01 Shunji Ogawa  2026/10/12  索引専用callback空と選択拒否・不成立fixtureの参照安全を確認。
 * </pre>
 *
 * @note OS列挙とnetworkをfakeに置換し、実payloadと実導入を呼ばない。
 */
//------------------------------------------------------------------------------

#include "metadata_search_runner_tests.h"
#include "core/candidate_audit.h"
#include "core/metadata_search.h"
#include "core/metadata_search_report.h"
#include "core/provider_registry.h"
#include "core/operation_controller.h"
#include "platform/composite_update_provider.h"
#include "platform/metadata_search_runner.h"
#include "platform/official_release_discovery_provider.h"
#include "platform/provider_worker.h"
#include "test_framework.h"
#include "support/scan_measurement_diagnostics.h"

#include <Windows.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <stdexcept>
#include <memory>
#include <optional>
#include <semaphore>
#include <thread>
#include <string>
#include <vector>

namespace drivercrate::test {
namespace {
constexpr ScanSessionId SESSION = 42U ;	// Fakeごとの一意な検索session。

/** @brief 現在属性・Provider終端・取消しを独立に切り替える内部fake。 */
struct MetadataFixture {
	/// 現在行として発行する合成node数。
	std::size_t				  nodeCount{2U} ;
	/// Inventory開始の失敗を注入する。
	bool					  inventoryFailure{} ;
	/// 現在属性の部分列挙を注入する。
	bool					  inventoryPartial{} ;
	/// 全公式callbackを失敗させる。
	bool					  providerFailure{} ;
	/// Callbackから例外を発生させる。
	bool					  providerException{} ;
	/// 非導入契約違反を注入する。
	bool					  malicious{} ;
	/// このoperationだけに所属する取消し要求。
	bool					  cancelled{} ;
	/// 一Providerの確定後に全体を中止する。
	bool					  cancelAfterProvider{} ;
	/// Inventory境界の呼出し回数。
	std::size_t				  inventoryCalls{} ;
	/// 実行したProviderのID。未選択callbackの非実行を確認する。
	std::vector<std::wstring> providerCalls ;
	/// 観測を持つlocal代表を生成する場合true。
	bool					  withObservations{} ;
	/// 旧sessionの観測を注入する場合true。
	bool					  staleObservation{} ;
	/// 非通信callbackで受け取った有効な観測数。
	std::size_t				  observedDevices{} ;

	/**
     * @brief 現在属性だけの合成行を返す。
     * @param[in] session 要求したsession。
     * @param[in,out] execution Fakeの取消しを観測するcontext。
     * @param[in] progress 確定進捗の通知先。
     * @param[out] measurement 同じ列挙の件数根拠。
     * @return 現在行または開始失敗。履歴と導入対象を持たない。
     */
	ScanResult inventory( const ScanSessionId session, MetadataSearchExecutionContext &execution,
						 const ProviderProgressCallback &progress,
						 DeviceInventoryMeasurement		&measurement)
	{
		++inventoryCalls ;
		ScanResult result ;	// 一回の所有結果。
		result.scanSessionId = session ;
		result.purpose		 = ScanPurpose::METADATA_ONLY ;
		result.state		 = ProviderScanState::FAILURE ;
		result.outcome		 = OutcomeCode::FAILURE ;
		// 開始失敗と取消しで現在nodeを捏造しない。
		if( inventoryFailure || execution.checkpoint() != 0) {
			result.error = static_cast<NativeError>( E_FAIL) ;
			return result ;
		}

		// 有限な合成nodeだけを現在属性行へ変換する。
		for( std::size_t index = 0U; index < nodeCount; ++index) {
			UpdateCandidate row ;	// 実IDを含まない現在行。
			row.identity		= L"current-" + std::to_wstring( index) ;
			row.deviceIdentity	= L"device-" + std::to_wstring( index) ;
			row.providerId		= DRIVER_STORE_PROVIDER_ID ;
			row.model			= L"PL2303 Fixture" ;
			row.manufacturer	= L"Fixture" ;
			row.driverClass		= L"Ports" ;
			row.deviceClassGuid = L"{4d36e978-e325-11ce-bfc1-08002be10318}" ;
			row.current			= true ;
			row.version			= L"1.0" ;
			row.discoveryBasis	= CandidateDiscoveryBasis::LOCAL_INVENTORY ;
			row.audit			= makeWindowsManagedCandidateAudit( true) ;
			// 通常fixtureとの互換性を維持し、専用試行だけで観測を付ける。
			if( withObservations) {
				row.deviceObservation					= DeviceObservation{} ;
				row.deviceObservation->scanSessionId	= session + (staleObservation ? 1U : 0U) ;
				row.deviceObservation->deviceIdentity	= row.deviceIdentity ;
				row.deviceObservation->node.read.state	= DevicePropertyReadState::VALUE ;
				row.deviceObservation->node.statusFlags = 0x400U ;
				row.deviceObservation->node.problemCode = 28U ;
				row.deviceObservation->driverPresence	= DeviceDriverPresence::NOT_INSTALLED ;
			}

			result.candidates.push_back( std::move( row)) ;
		}

		measurement.enumeratedDeviceCount		= {nodeCount, inventoryPartial
																  ? MeasurementExtent::LOWER_BOUND
																  : MeasurementExtent::EXACT} ;
		measurement.unrepresentedDeviceCount	= {0U, measurement.enumeratedDeviceCount.extent} ;
		measurement.detailedEnumerationComplete = !inventoryPartial ;
		result.succeeded						= true ;
		result.outcome =
			inventoryPartial ? OutcomeCode::SUCCEEDED_WITH_ERRORS : OutcomeCode::SUCCESS ;
		result.state = nodeCount == 0U ? ProviderScanState::NO_CANDIDATES
									   : ProviderScanState::CANDIDATES_AVAILABLE ;
		progress( {.stage		   = ProviderStage::SCANNING_DEVICES,
				  .percentComplete = 100U,
				  .completedItems  = nodeCount,
				  .totalItems	   = nodeCount}) ;
		return result ;
	}

	/**
     * @brief 既存正本registryへfake専用callbackだけを接続する。
     * @return 正本と同一descriptor集合。通常scanや取得serviceを含めない。
     */
	std::vector<MetadataSearchRegistration> registrations()
	{
		std::vector<MetadataSearchRegistration> entries ;	// 全正本登録の一回限りのcopy。
		// 一つの正本を使い、選択集合を別の固定Provider一覧から生成しない。
		for( const auto &descriptor : builtInProviderDescriptors()) {
			MetadataSearchRegistration entry{descriptor, {}} ;	// 非対応は空callbackを維持する。
			// 専用能力だけをfakeで接続する。
			if( isMetadataSearchProvider( descriptor)) {
				entry.scan = [this, id = descriptor.id](
								 const ScanSessionId						  session,
								 const std::span<const OfficialCatalogDevice> devices, bool,
								 std::uint32_t, MetadataSearchExecutionContext &,
								 const ProviderProgressCallback &progress,
								 ProviderMeasurementEvidence	&evidence) {
					providerCalls.push_back( id) ;
					// 例外の後に別の通常scanへfallbackしないことを検証する。
					if( providerException) {
						throw std::runtime_error( "metadata fixture") ;
					}

					ScanResult result ;	// 同sessionの表示専用子結果。
					result.scanSessionId = session ;
					result.purpose		 = ScanPurpose::METADATA_ONLY ;
					result.outcome = providerFailure ? OutcomeCode::FAILURE : OutcomeCode::SUCCESS ;
					result.state =
						providerFailure
							? ProviderScanState::FAILURE
							: (devices.empty() ? ProviderScanState::NOT_APPLICABLE
											   : ProviderScanState::CANDIDATES_AVAILABLE) ;
					result.error		   = providerFailure ? static_cast<NativeError>( E_FAIL) : 0 ;
					result.succeeded	   = !providerFailure ;
					evidence.providerId	   = id ;
					evidence.scanSessionId = session ;
					evidence.scope		   = MeasurementScope::DEVICE_QUERY ;
					evidence.queryOutcome  = result.outcome ;
					evidence.eligible.extent = MeasurementExtent::EXACT ;
					evidence.queryCompleted.extent =
						providerFailure ? MeasurementExtent::LOWER_BOUND : MeasurementExtent::EXACT ;
					evidence.information.extent = evidence.queryCompleted.extent ;
					evidence.recordExtent		= evidence.queryCompleted.extent ;
					// 同型二台も別deviceとしてTへ結合する。
					for( const auto &device : devices) {
						// Provider内部のlocal snapshotだけを数え、requestやreportへ観測を出さない。
						if( device.deviceObservation &&
						   isDeviceObservationBound( *device.deviceObservation, session,
													device.deviceIdentity) &&
						   device.deviceObservation->driverPresence ==
							   DeviceDriverPresence::NOT_INSTALLED) {
							++observedDevices ;
						}

						evidence.eligible.identities.push_back( device.deviceIdentity) ;
						// 失敗したqueryから情報行とRを生成しない。
						if( providerFailure) {
							continue ;
						}

						evidence.queryCompleted.identities.push_back( device.deviceIdentity) ;
						evidence.information.identities.push_back( device.deviceIdentity) ;
						UpdateCandidate row ;	// 適用性とpackage identityを持たない表示行。
						row.identity	   = id + L":info:" + device.deviceIdentity ;
						row.providerId	   = id ;
						row.deviceIdentity = device.deviceIdentity ;
						row.model		   = device.model ;
						row.manufacturer   = device.manufacturer ;
						row.driverClass	   = device.driverClass ;
						row.discoveryBasis = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
						row.audit		   = makeOfficialDiscoveryCandidateAudit() ;
						row.installable	   = malicious ;
						result.candidates.push_back( std::move( row)) ;
					}

					// 一recordが二deviceへ結合してもrecord数は一件とする。
					if( !providerFailure && !devices.empty()) {
						evidence.records.push_back(
							{id + L":record", evidence.information.identities}) ;
					}

					progress( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
							  .percentComplete = 100U,
							  .completedItems  = devices.size(),
							  .totalItems	   = devices.size()}) ;
					// 呼出し終端で取消しを注入し、後続callbackが呼ばれないことを確かめる。
					if( cancelAfterProvider) {
						cancelled = true ;
					}

					return result ;
				} ;
			}

			entries.push_back( std::move( entry)) ;
		}

		return entries ;
	}

	/**
     * @brief 一つの専用sessionを非通信fakeで完結させる。
     * @param[in] request 今回だけの専用集合。
     * @return Runnerの所有結果。Operation bindingだけを公開時と同じように追加する。
     */
	ScanResult run( const MetadataSearchRequest &request)
	{
		MetadataSearchExecutionContext execution( SESSION, request,
												 [this] { return cancelled ; }) ;	// Fake token。
		auto entries = registrations() ;											// Contextと同じrun内で生存するcallback集合。
		ScanMeasurementContext conditions ;											// Public検証もできる非機密な固定条件。
		conditions.applicationVersion = L"fixture" ;
		conditions.osKind			  = MeasurementOsKind::CLIENT ;
		conditions.osBuild			  = 26100U ;
		ScanResult result			  = runMetadataSearch(
			SESSION, request, execution, entries,
			[this]( auto session, auto &budget, const auto &progress, auto &measurement) {
				return inventory( session, budget, progress, measurement) ;
			},
			conditions, []( const ProviderProgress &) {}) ;	// 外部UIを呼ばない通知先。
		// Worker公開時と同じ非ゼロoperationを付与する。
		if( result.metadataSearch) {
			result.metadataSearch->operationId = 7U ;
		}

		// 計測は同じoperationへ拘束する。
		if( result.measurement) {
			result.measurement->context.operationId = 7U ;
		}

		return result ;
	}
} ;

/**
 * @brief 専用registry、全終端、和集合、非導入のfake実行を検証する。
 * @param[in,out] context Assertionの集計先。
 */
void testRunner( TestContext &context)
{
	MetadataSearchRequest request ;	// 通常設定や同意を含まない今回の明示集合。
	request.enabledProviderIds.emplace_back( PROLIFIC_OFFICIAL_PROVIDER_ID) ;
	MetadataFixture fixture ;							// 初期状態は合成二台・一record。
	auto			entries = fixture.registrations() ;	// 正本31登録の非通信callback。
	DRIVERCRATE_EXPECT( context, entries.size() == 31U) ;
	DRIVERCRATE_EXPECT( context, validateMetadataSearchRegistrations( entries)) ;
	const auto index = std::find_if( entries.begin(), entries.end(), []( const auto &entry) {
		return entry.descriptor.id == SIGNED_INDEX_PROVIDER_ID ;
	}) ; // 通常SCAN／INSTALLだけを持つ索引登録の位置。
	DRIVERCRATE_EXPECT( context, index != entries.end()) ;
	// 索引登録が欠けた失敗を保持し、欠損iteratorを参照しない。
	if( index == entries.end()) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, !index->scan && !isMetadataSearchProvider( index->descriptor) &&
									index->descriptor.enabledByDefault) ;
	MetadataSearchRequest indexOnly ;	// STANDARD既定状態を情報検索許可へ読み替えない要求。
	indexOnly.enabledProviderIds.emplace_back( SIGNED_INDEX_PROVIDER_ID) ;
	MetadataFixture refusedFixture ;								// 情報検索拒否時に一callbackも実行しない依存。
	const auto		refusedIndex = refusedFixture.run( indexOnly) ;	// 能力非対応IDの明示拒否結果。
	DRIVERCRATE_EXPECT( context, !refusedIndex.succeeded && refusedFixture.inventoryCalls == 0U &&
									refusedFixture.providerCalls.empty()) ;
	index->scan = []( auto, auto, auto, auto, auto &, const auto &, auto &) {
		return ScanResult{} ;
	} ; // 非対応のcallback注入を完全一致validatorで拒否する人工改ざん。
	DRIVERCRATE_EXPECT( context, !validateMetadataSearchRegistrations( entries)) ;
	entries = fixture.registrations() ;
	DRIVERCRATE_EXPECT( context,
					   std::count_if( entries.begin(), entries.end(), []( const auto &entry) {
						   return static_cast<bool>( entry.scan) ;
					   }) == 10) ;
	DRIVERCRATE_EXPECT( context,
					   std::count_if( entries.begin(), entries.end(), []( const auto &entry) {
						   return entry.descriptor.enabledByDefault ;
					   }) == 10) ;
	std::reverse( entries.begin(), entries.end()) ;
	DRIVERCRATE_EXPECT( context, validateMetadataSearchRegistrations( entries)) ;
	auto supported = std::find_if( entries.begin(), entries.end(), []( const auto &entry) {
		return static_cast<bool>( entry.scan) ;
	}) ; // 欠落させる一登録。
	DRIVERCRATE_EXPECT( context, supported != entries.end() && !entries.empty()) ;
	// 前提不成立の失敗を保持し、end iteratorまたは空集合を変更しない。
	if( supported == entries.end() || entries.empty()) {
		return ;
	}

	supported->scan = {} ;
	DRIVERCRATE_EXPECT( context, !validateMetadataSearchRegistrations( entries)) ;
	entries				 = fixture.registrations() ;
	entries.front().scan = []( auto, auto, auto, auto, auto &, const auto &, auto &) {
		return ScanResult{} ;
	} ;
	DRIVERCRATE_EXPECT( context, !validateMetadataSearchRegistrations( entries)) ;
	entries = fixture.registrations() ;
	entries.front().descriptor.capabilities |= 0x80000000U ;
	DRIVERCRATE_EXPECT( context, !validateMetadataSearchRegistrations( entries)) ;

	auto result = fixture.run( request) ;	// 一Providerの正常情報到達。
	{
		auto invalidEntries = fixture.registrations() ;	// 件数不一致で明示的に拒否する元登録。
		invalidEntries.pop_back() ;
		MetadataSearchExecutionContext execution{SESSION,
												 request} ;	// Payload許可を持たない実context。
		const auto					   rejected = runMetadataSearch(
			SESSION, request, execution, invalidEntries,
			[&fixture]( auto id, auto &budget, const auto &notify, auto &measurement) {
				return fixture.inventory( id, budget, notify, measurement) ;
			},
			{}, []( const ProviderProgress &) {}) ;	// 不正集合を通常scanへfallbackしません。
		DRIVERCRATE_EXPECT( context, !rejected.succeeded && !rejected.metadataSearch &&
										!rejected.measurement) ;
	}
	DRIVERCRATE_EXPECT( context, result.metadataSearch && result.measurement && result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.outcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context,
					   result.candidates.size() == 4U && fixture.providerCalls.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, hasOnlyMetadataDisplayCandidates( result)) ;
	DRIVERCRATE_EXPECT( context, isPublishedScanMeasurementValid( 7U, result)) ;
	// 集計未生成時のdereferenceを避け、元のassertion失敗を保つ。
	if( result.measurement) {
		DRIVERCRATE_EXPECT( context,
						   result.measurement->network.official.informationDeviceCount.value == 2U) ;
		DRIVERCRATE_EXPECT(
			context, result.measurement->network.official.applicableUpdateDeviceCount.extent ==
						 MeasurementExtent::NOT_MEASURED) ;
		DRIVERCRATE_EXPECT(
			context, !result.measurement->network.official.installReadyUpdateDeviceCount.value) ;
	}

	request.enabledProviderIds.emplace_back( SILICON_LABS_OFFICIAL_PROVIDER_ID) ;
	fixture = {} ;
	result	= fixture.run( request) ;
	DRIVERCRATE_EXPECT( context, result.succeeded && fixture.providerCalls.size() == 2U &&
									result.candidates.size() == 6U) ;
	// 二Providerが同じdeviceへ情報を返してもRは和集合二台のままとする。
	if( result.measurement) {
		DRIVERCRATE_EXPECT( context,
						   result.measurement->network.combined.informationDeviceCount.value == 2U) ;
	}

	fixture			  = {} ;
	fixture.nodeCount = 0U ;
	result			  = fixture.run( request) ;
	DRIVERCRATE_EXPECT( context, result.succeeded && result.outcome == OutcomeCode::SUCCESS &&
									result.candidates.empty()) ;
	fixture					 = {} ;
	fixture.inventoryFailure = true ;
	result					 = fixture.run( request) ;
	DRIVERCRATE_EXPECT( context, result.metadataSearch && result.outcome == OutcomeCode::FAILURE &&
									fixture.providerCalls.empty()) ;
	fixture					 = {} ;
	fixture.inventoryPartial = true ;
	result					 = fixture.run( request) ;
	DRIVERCRATE_EXPECT( context, result.metadataSearch &&
									result.outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
	fixture					= {} ;
	fixture.providerFailure = true ;
	result					= fixture.run( request) ;
	DRIVERCRATE_EXPECT( context, result.metadataSearch && result.outcome == OutcomeCode::FAILURE &&
									result.candidates.size() == 2U) ;
	fixture					  = {} ;
	fixture.providerException = true ;
	result					  = fixture.run( request) ;
	DRIVERCRATE_EXPECT( context, result.metadataSearch && result.outcome == OutcomeCode::FAILURE &&
									result.candidates.size() == 2U) ;
	fixture			  = {} ;
	fixture.cancelled = true ;
	result			  = fixture.run( request) ;
	DRIVERCRATE_EXPECT( context, result.metadataSearch && result.outcome == OutcomeCode::ABORTED &&
									fixture.providerCalls.empty()) ;
	fixture						= {} ;
	fixture.cancelAfterProvider = true ;
	result						= fixture.run( request) ;
	DRIVERCRATE_EXPECT( context, result.metadataSearch && result.outcome == OutcomeCode::ABORTED &&
									fixture.providerCalls.size() == 1U) ;
	DRIVERCRATE_EXPECT( context,
					   result.candidates.size() == 4U && hasOnlyMetadataDisplayCandidates( result)) ;
	fixture			  = {} ;
	fixture.malicious = true ;
	result			  = fixture.run( request) ;
	DRIVERCRATE_EXPECT( context, !result.metadataSearch && result.outcome == OutcomeCode::FAILURE &&
									result.candidates.empty()) ;

	CompositeUpdateProvider		   composite ;	// Constructorと既取消し専用scanだけで実APIを避ける。
	MetadataSearchExecutionContext cancelled( SESSION, request,
											 [] { return true ; }) ;	// 最初から取消し。
	result =
		composite.scanMetadataOnly( SESSION, request, cancelled, []( const ProviderProgress &) {}) ;
	DRIVERCRATE_EXPECT( context, result.metadataSearch && result.outcome == OutcomeCode::ABORTED) ;
	DRIVERCRATE_EXPECT( context, !composite.preparationPlan( SESSION, 1U)) ;
	const std::array<std::wstring, 1> forged{L"forged"} ;	// 未発行の導入要求。
	DRIVERCRATE_EXPECT( context, composite.install( SESSION, forged, 0U, {}).installOutcome ==
									OutcomeCode::FAILURE) ;
}

/**
 * @brief 実際の共用metadata helperが停止後commitとpackage権限を作らないことを検証する。
 * @param[in,out] context Assertionの集計先。
 */
void testDedicatedHelper( TestContext &context)
{
	MetadataSearchRequest request ;	// 審査済み一系列だけの明示集合。
	request.enabledProviderIds.emplace_back( PROLIFIC_OFFICIAL_PROVIDER_ID) ;
	bool								 cancel{} ;	// Readerや進捗から切り替えるoperation token。
	std::size_t							 reads{} ;	// HTTPを呼ばないfake reader回数。
	std::array<OfficialCatalogDevice, 2> devices ;	// 同じ型番で異なるopaque device。
	// 合成表示属性だけを固定する。
	for( std::size_t index = 0U; index < devices.size(); ++index) {
		devices[index].deviceIdentity = L"helper-" + std::to_wstring( index) ;
		devices[index].model		  = L"PL2303 Fixture" ;
		devices[index].driverClass	  = L"Ports" ;
	}

	const OfficialReleaseMetadataReader reader = [&reads]( auto family, auto, auto &record, auto &) {
		++reads ;
		record.family		  = family ;
		record.fileName		  = L"fixture.zip" ;
		record.downloadUrl	  = L"https://example.invalid/fixture.zip" ;
		record.parserRevision = 1U ;
		return NativeError{} ;
	} ; // URLはfake内部専用で、実HTTP・表示・logへ送らない。
	// 同じcallback期間だけ借用する、行commit途中の取消し状態。
	MetadataSearchExecutionContext execution( SESSION, request, [&cancel] { return cancel ; }) ;
	DRIVERCRATE_EXPECT( context, execution.beginProvider( PROLIFIC_OFFICIAL_PROVIDER_ID) == 0) ;
	ProviderMeasurementEvidence evidence ;	// 適用性を含めない同session根拠。
	auto						result = scanOfficialReleaseMetadata(
		   OfficialReleaseFamily::PROLIFIC_DCHU, SESSION, devices, false, reader,
		   [&cancel]( const ProviderProgress &progress) {
			   // 一行commit済みの地点で取消しを要求する。
			   if( progress.completedItems == 1U) {
				   cancel = true ;
			   }
		   },
		   26100U, {}, &evidence, &execution) ;	// 通常Provider.scanは呼ばない。
	DRIVERCRATE_EXPECT( context, result.outcome == OutcomeCode::ABORTED && reads == 1U &&
									result.candidates.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, hasOnlyMetadataDisplayCandidates( result) &&
									result.candidates.front().version.empty()) ;
	DRIVERCRATE_EXPECT( context, evidence.applicabilityExtent == MeasurementExtent::NOT_MEASURED &&
									evidence.readinessExtent == MeasurementExtent::NOT_MEASURED) ;
	MetadataSearchExecutionContext serverExecution( SESSION + 1U, request) ;	// 非対象OSの別run。
	DRIVERCRATE_EXPECT( context, serverExecution.beginProvider( PROLIFIC_OFFICIAL_PROVIDER_ID) == 0) ;
	result = scanOfficialReleaseMetadata(
		OfficialReleaseFamily::PROLIFIC_DCHU, SESSION + 1U, devices, true, reader,
		[]( const ProviderProgress &) {}, 26100U, {}, &evidence, &serverExecution) ;
	DRIVERCRATE_EXPECT( context, result.succeeded &&
									result.state == ProviderScanState::NOT_APPLICABLE &&
									reads == 1U) ;
}

/**
 * @brief 正規の全終端、改ざん、状態遷移と旧権限の失効を検証する。
 * @param[in,out] context Assertionの集計先。
 */
void testPublicationAndController( TestContext &context)
{
	MetadataSearchRequest request ;	// 正本から全専用能力を明示するfixture。
	// Registryの順序を固定一覧へ複製せず、能力を持つ専用十件だけを選ぶ。
	for( const auto &descriptor : builtInProviderDescriptors()) {
		// 未対応能力を通常scanで補完しない。
		if( isMetadataSearchProvider( descriptor)) {
			request.enabledProviderIds.push_back( descriptor.id) ;
		}
	}

	MetadataFixture fixture ;						// 全十経路に同じ二台を結合する。
	const auto		all = fixture.run( request) ;	// 架空全十経路の正規公開結果。
	DRIVERCRATE_EXPECT( context,
					   fixture.providerCalls.size() == 10U && all.candidates.size() == 22U) ;
	DRIVERCRATE_EXPECT( context, isMetadataSearchResultValid( 7U, request, all)) ;
	DRIVERCRATE_EXPECT( context, !all.candidates.empty()) ;
	// 不正公開結果から前後行を借用せず、元の期待失敗を保持する。
	if( all.candidates.empty()) {
		return ;
	}

	std::vector<ScanResult> terminals{all} ;	// 正常・0件・部分・失敗・取消しの全終端。
	fixture			  = {} ;
	fixture.nodeCount = 0U ;
	terminals.push_back( fixture.run( request)) ;
	fixture					 = {} ;
	fixture.inventoryPartial = true ;
	terminals.push_back( fixture.run( request)) ;
	fixture					 = {} ;
	fixture.inventoryFailure = true ;
	terminals.push_back( fixture.run( request)) ;
	fixture					= {} ;
	fixture.providerFailure = true ;
	terminals.push_back( fixture.run( request)) ;
	fixture					  = {} ;
	fixture.providerException = true ;
	terminals.push_back( fixture.run( request)) ;
	fixture			  = {} ;
	fixture.cancelled = true ;
	terminals.push_back( fixture.run( request)) ;
	fixture						= {} ;
	fixture.cancelAfterProvider = true ;
	terminals.push_back( fixture.run( request)) ;
	// 元の成功flagにかかわらず整合した表示専用終端だけを受理する。
	for( auto result : terminals) {
		DRIVERCRATE_EXPECT( context, isMetadataSearchResultValid( 7U, request, result)) ;
		OperationController controller ;								// 一runごとに状態を独立させる。
		const auto begin = controller.beginMetadataSearch( request) ;	// IDは1から発行される。
		DRIVERCRATE_EXPECT( context, begin.accepted &&
										controller.scanPurpose() == ScanPurpose::METADATA_ONLY) ;
		DRIVERCRATE_EXPECT( context, !controller.beginScan().accepted) ;
		DRIVERCRATE_EXPECT( context, !controller.completeScan( begin.operationId, result)) ;
		DRIVERCRATE_EXPECT( context,
						   !controller.completeMetadataSearch( begin.operationId + 1U, result)) ;
		DRIVERCRATE_EXPECT( context, controller.markMetadataSearchCancelling( begin.operationId)) ;
		DRIVERCRATE_EXPECT( context, !controller.beginMetadataSearch( request).accepted) ;
		DRIVERCRATE_EXPECT( context, result.metadataSearch && result.measurement) ;
		// 期待assertionが失敗しても不成立optionalへ進まず、拒否結果を安全に保持します。
		if( !result.metadataSearch || !result.measurement) {
			continue ;
		}

		result.metadataSearch->operationId		= begin.operationId ;
		result.measurement->context.operationId = begin.operationId ;
		DRIVERCRATE_EXPECT( context, controller.completeMetadataSearch( begin.operationId, result)) ;
		DRIVERCRATE_EXPECT( context,
						   controller.metadataSearchSummary() && controller.scanMeasurement()) ;
		DRIVERCRATE_EXPECT( context, controller.state() == (result.outcome == OutcomeCode::FAILURE
															   ? ApplicationState::FAILURE
															   : ApplicationState::COMPLETED)) ;
		DRIVERCRATE_EXPECT( context,
						   controller.scanSessionId() == 0U && !controller.preparationPlan()) ;
		const std::array<std::wstring, 1> forged{L"current-0"} ;	// 表示行に対する不正導入要求。
		DRIVERCRATE_EXPECT(
			context,
			!controller.beginInstall( SESSION, forged, InstallConfirmation::CONFIRMED).accepted) ;
		OfficialPreparationApproval approval ;	// 別用途の古い取得承認。
		approval.scanSessionId = SESSION ;
		DRIVERCRATE_EXPECT( context, !controller.beginPreparation( approval).accepted) ;
		const auto normal = controller.beginScan() ;	// 後続の明示通常scanは新sessionから始まる。
		DRIVERCRATE_EXPECT( context, normal.accepted && normal.operationId > begin.operationId &&
										controller.scanPurpose() == ScanPurpose::STANDARD &&
										!controller.metadataSearchSummary()) ;
		DRIVERCRATE_EXPECT( context, !controller.completeMetadataSearch( begin.operationId, result)) ;
		DRIVERCRATE_EXPECT( context, controller.completeScan( normal.operationId, result) &&
										controller.state() == ApplicationState::FAILURE &&
										controller.scanSessionId() == 0U) ;
	}

	auto changed								   = all ;	// 不正packetを一項目ずつ注入するcopy。
	changed.candidates.back().metadataDistribution = MetadataDistributionDetails{
		.version = L"7.6.5", .license = MetadataLicenseStatus::ACCEPTANCE_BEFORE_DOWNLOAD} ;
	DRIVERCRATE_EXPECT( context, isMetadataSearchResultValid( 7U, request, changed)) ;
	DRIVERCRATE_EXPECT( context, changed.candidates.back().version.empty() &&
									!changed.candidates.back().eulaAccepted &&
									!changed.candidates.back().installable) ;
	changed.candidates.back().metadataDistribution->license =
		static_cast<MetadataLicenseStatus>( 99) ;
	DRIVERCRATE_EXPECT( context, !isMetadataSearchResultValid( 7U, request, changed)) ;
	changed							  = all ;
	changed.candidates.back().version = L"not-an-inf-version" ;
	DRIVERCRATE_EXPECT( context, !isMetadataSearchResultValid( 7U, request, changed)) ;
	changed = all ;
	changed.candidates.front().metadataDistribution =
		MetadataDistributionDetails{.version = L"7.6.5"} ;
	DRIVERCRATE_EXPECT( context, !isMetadataSearchResultValid( 7U, request, changed)) ;
	changed								   = all ;
	changed.candidates.front().installable = true ;
	DRIVERCRATE_EXPECT( context, !isMetadataSearchResultValid( 7U, request, changed)) ;
	changed			= all ;
	changed.purpose = ScanPurpose::STANDARD ;
	DRIVERCRATE_EXPECT( context, !isMetadataSearchResultValid( 7U, request, changed)) ;
	changed													  = all ;
	changed.metadataSearch->request.restrictedNetworkApproved = true ;
	DRIVERCRATE_EXPECT( context, !isMetadataSearchResultValid( 7U, request, changed)) ;
	changed								= all ;
	changed.metadataSearch->operationId = 8U ;
	DRIVERCRATE_EXPECT( context, !isMetadataSearchResultValid( 7U, request, changed)) ;
	changed									= all ;
	changed.metadataSearch->usage.bodyBytes = 1U ;
	DRIVERCRATE_EXPECT( context, !isMetadataSearchResultValid( 7U, request, changed)) ;
	changed = all ;
	changed.providerReports.front().descriptor.capabilities |= 0x80000000U ;
	DRIVERCRATE_EXPECT( context, !isMetadataSearchResultValid( 7U, request, changed)) ;
	changed												  = all ;
	changed.providerReports.back().descriptor.displayName = L"forged" ;
	DRIVERCRATE_EXPECT( context, !isMetadataSearchResultValid( 7U, request, changed)) ;
	changed = all ;
	changed.metadataSearch->providers.pop_back() ;
	DRIVERCRATE_EXPECT( context, !isMetadataSearchResultValid( 7U, request, changed)) ;
	changed															  = all ;
	changed.measurement->network.official.applicableUpdateDeviceCount = {0U,
																		 MeasurementExtent::EXACT} ;
	DRIVERCRATE_EXPECT( context, !isMetadataSearchResultValid( 7U, request, changed)) ;
	changed									  = all ;
	changed.candidates.back().packageIdentity = L"forged" ;
	DRIVERCRATE_EXPECT( context, !isMetadataSearchResultValid( 7U, request, changed)) ;
	changed = all ;
	std::reverse( changed.providerReports.begin(), changed.providerReports.end()) ;
	std::reverse( changed.metadataSearch->providers.begin(),
				 changed.metadataSearch->providers.end()) ;
	std::reverse( changed.measurement->context.enabledProviderIds.begin(),
				 changed.measurement->context.enabledProviderIds.end()) ;
	DRIVERCRATE_EXPECT( context, isMetadataSearchResultValid( 7U, request, changed)) ;
	OperationController stopped ;										// Window close後の遅延結果を破棄する状態機械。
	const auto			begin = stopped.beginMetadataSearch( request) ;	// 停止前の操作。
	stopped.stop() ;
	DRIVERCRATE_EXPECT( context, !stopped.completeMetadataSearch( begin.operationId, all)) ;
	DRIVERCRATE_EXPECT( context, !stopped.beginMetadataSearch( request).accepted) ;
}

/** @brief Workerと試験threadで共有する、実APIを持たない有限fixture状態。 */
struct MetadataWorkerState {
	/// 通常scanの誤呼出しを検出する。
	std::atomic_uint32_t		normalCalls{} ;
	/// 専用callbackの呼出し数。
	std::atomic_uint32_t		metadataCalls{} ;
	/// 準備計画の要求回数。情報検索では増えてはならない。
	std::atomic_uint32_t		planCalls{} ;
	/// 検査用取得の誤呼出し数。
	std::atomic_uint32_t		acquireCalls{} ;
	/// 導入APIの誤呼出し数。
	std::atomic_uint32_t		installCalls{} ;
	/// 復元APIの誤呼出し数。
	std::atomic_uint32_t		restoreCalls{} ;
	/// 一回の通常scanを試験信号まで待機させる。
	std::atomic_bool			holdNormal{} ;
	/// 一回の情報検索を試験信号まで待機させる。
	std::atomic_bool			holdMetadata{} ;
	/// 不正な用途を通常callbackから返す。
	std::atomic_bool			forgedNormal{} ;
	/// 不正な導入可能行を専用callbackから返す。
	std::atomic_bool			forgedMetadata{} ;
	/// 待機地点への到達通知。
	std::counting_semaphore<16> entered{0} ;
	/// 待機を解除するfixture信号。
	std::counting_semaphore<16> released{0} ;
} ;

/** @brief 復旧APIを初期化せず誤呼出しだけを記録する。 */
class MetadataWorkerRestore final : public IRestorePointService {
public:
	/** @brief Counterを共有する。@param[in] state 両threadで所有するfixture。 */
	explicit MetadataWorkerRestore( std::shared_ptr<MetadataWorkerState> state)
		: state_( std::move( state))
	{
	}
	/** @brief 実APIを呼ばず失敗する。@param[in] description 未使用の説明。@return 合成失敗。 */
	RestorePointOperationResult begin( std::wstring_view description) noexcept override
	{
		static_cast<void>( description) ;
		++state_->restoreCalls ;
		return {.outcome = OutcomeCode::FAILURE, .error = static_cast<NativeError>( E_FAIL)} ;
	}
	/** @brief 実APIを呼ばず失敗する。@param[in] sequenceNumber 未使用の番号。@return 合成失敗。 */
	RestorePointOperationResult complete( std::int64_t sequenceNumber) noexcept override
	{
		static_cast<void>( sequenceNumber) ;
		++state_->restoreCalls ;
		return {.outcome = OutcomeCode::FAILURE, .error = static_cast<NativeError>( E_FAIL)} ;
	}

private:
	/// Worker lifetimeを包含するcounter所有権。
	std::shared_ptr<MetadataWorkerState> state_ ;
} ;

/** @brief 専用runner以外をcounterに置き換えるworker用fake。 */
class MetadataWorkerProvider final : public IUpdateProvider {
public:
	/** @brief Fixtureを共有する。@param[in] state 誤呼出しと待機の所有状態。 */
	explicit MetadataWorkerProvider( std::shared_ptr<MetadataWorkerState> state)
		: state_( std::move( state))
	{
	}
	/**
     * @brief 空の通常scan、または用途違反を合成する。
     * @param[in] session Workerの一意ID。
     * @param[in] options 使用しない通常条件。
     * @param[in] progress 使用しない通知先。
     * @return 外部APIを含まない所有結果。
     */
	ScanResult scan( ScanSessionId session, const ScanOptions &options,
					const ProviderProgressCallback &progress) override
	{
		static_cast<void>( options) ;
		static_cast<void>( progress) ;
		++state_->normalCalls ;
		// Queue内取消しを決定的に再現するため一回だけ最大3秒待つ。
		if( state_->holdNormal.exchange( false)) {
			state_->entered.release() ;
			static_cast<void>( state_->released.try_acquire_for( std::chrono::seconds( 3))) ;
		}

		// 実deviceを列挙しない通常scanの空結果。
		ScanResult result{
			.succeeded = true, .scanSessionId = session, .outcome = OutcomeCode::SUCCESS} ;
		// Workerの用途検証を試すため不正な専用用途だけを注入する。
		if( state_->forgedNormal) {
			result.purpose = ScanPurpose::METADATA_ONLY ;
		}

		return result ;
	}
	/**
     * @brief Worker自身のcontextを使い、実列挙と通信なしで専用runnerを実行する。
     * @param[in] session Workerの一意ID。
     * @param[in] request 今回だけの明示集合。
     * @param[in,out] execution Workerが所有する取消しと予算。
     * @param[in] progress Workerの結果通知先。
     * @return 操作IDをまだ持たない正規の情報検索結果。
     */
	ScanResult scanMetadataOnly( ScanSessionId session, const MetadataSearchRequest &request,
								MetadataSearchExecutionContext &execution,
								const ProviderProgressCallback &progress) override
	{
		++state_->metadataCalls ;
		// 実行中取消しを安全地点直前で注入し、最大3秒で必ずfixtureを解放する。
		if( state_->holdMetadata.exchange( false)) {
			state_->entered.release() ;
			static_cast<void>( state_->released.try_acquire_for( std::chrono::seconds( 3))) ;
		}

		MetadataFixture		   fixture ;									// このcallback内だけで生存する非通信Provider状態。
		auto				   registrations = fixture.registrations() ;	// 全登録の正本copy。
		ScanMeasurementContext conditions ;									// Workerが版と操作を後で拘束する計測。
		conditions.osKind  = MeasurementOsKind::CLIENT ;
		conditions.osBuild = 26100U ;
		auto result		   = runMetadataSearch(
			   session, request, execution, registrations,
			   [&fixture]( auto id, auto &budget, const auto &notify, auto &measurement) {
				   return fixture.inventory( id, budget, notify, measurement) ;
			   },
			   conditions, progress) ;	// 取得serviceを含まないrunner。
		// 正規runnerの後で候補を改ざんし、Workerの独立検証を試す。
		if( state_->forgedMetadata && !result.candidates.empty()) {
			result.candidates.front().installable = true ;
		}

		return result ;
	}
	/**
     * @brief 準備計画の誤呼出しを記録する。
     * @param[in] session 未使用の検索ID。
     * @param[in] planId 未使用の計画ID。
     * @return 常に計画なし。
     */
	std::optional<OfficialPreparationPlan> preparationPlan( ScanSessionId session,
														   std::uint64_t planId) override
	{
		static_cast<void>( session) ;
		static_cast<void>( planId) ;
		++state_->planCalls ;
		return std::nullopt ;
	}
	/**
     * @brief 取得の誤呼出しを記録し、fileを生成しない。
     * @param[in] task 未使用の対象。
     * @param[in] cancellation 未使用の信号。
     * @return 合成した未取得失敗。
     */
	OfficialPreparationTransferResult acquireForInspection(
		const OfficialPreparationTask &task, const PreparationCancellation &cancellation) override
	{
		static_cast<void>( task) ;
		static_cast<void>( cancellation) ;
		++state_->acquireCalls ;
		return {OfficialPreparationItemState::FAILURE, static_cast<NativeError>( E_FAIL), 0U} ;
	}
	/**
     * @brief 導入の誤呼出しを記録し、OSを変更しない。
     * @param[in] session 未使用の検索ID。
     * @param[in] identities 未使用の選択集合。
     * @param[in] parentWindow 未使用の親Window。
     * @param[in] progress 未使用の通知先。
     * @return 合成した未導入結果。
     */
	InstallResult install( ScanSessionId session, std::span<const std::wstring> identities,
						  std::uintptr_t				  parentWindow,
						  const ProviderProgressCallback &progress) override
	{
		static_cast<void>( session) ;
		static_cast<void>( identities) ;
		static_cast<void>( parentWindow) ;
		static_cast<void>( progress) ;
		++state_->installCalls ;
		return {} ;
	}

private:
	/// Workerと主threadの間で共有するfixture所有権。
	std::shared_ptr<MetadataWorkerState> state_ ;
} ;

/**
 * @brief 同じ操作の終端を最大3秒の有限pollで取り出す。
 * @param[in,out] worker 停止まで所有するfake worker。
 * @param[in] operationId 対象の操作ID。
 * @param[in] kind 対象の専用event種別。
 * @return 一致した所有event。未着は値なし。
 */
std::optional<WorkerEvent> waitMetadataWorker( ProviderWorker &worker, OperationId operationId,
											  WorkerEventKind kind)
{
	// Fakeは外部APIを待たず、300回でtimeoutを確定する。
	for( std::size_t attempt = 0U; attempt < 300U; ++attempt) {
		// 到着済みの有限queueから対象操作だけを探す。
		for( auto &event : worker.takeEvents()) {
			// 進捗または別operationを完了として扱わない。
			if( event.operationId == operationId && event.kind == kind) {
				return std::move( event) ;
			}
		}

		std::this_thread::sleep_for( std::chrono::milliseconds( 10)) ;
	}

	return std::nullopt ;
}

/**
 * @brief Workerの用途照合、取消し寿命、旧承認拒否と副作用0回を検証する。
 * @param[in,out] context Assertionの集計先。
 */
void testMetadataWorker( TestContext &context)
{
	const auto	   state = std::make_shared<MetadataWorkerState>() ;	// Fake factoryだけへ共有する。
	ProviderWorker worker(
		nullptr, WM_APP + 41U, [state] { return std::make_unique<MetadataWorkerProvider>( state) ; },
		[state] {
			return std::make_unique<MetadataWorkerRestore>( state) ;
		}) ;						   // 実復元APIも生成しない。
	MetadataSearchRequest request ;	// 初期選択を明示した一系列。
	request.enabledProviderIds.emplace_back( PROLIFIC_OFFICIAL_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, !worker.requestMetadataSearch( 0U, request)) ;
	DRIVERCRATE_EXPECT( context, !worker.requestMetadataSearch( 1U, {})) ;
	DRIVERCRATE_EXPECT( context, worker.requestMetadataSearch( 1U, request)) ;
	auto event =
		// 正常終端。
		waitMetadataWorker( worker, 1U, WorkerEventKind::METADATA_SEARCH_COMPLETED) ;
	DRIVERCRATE_EXPECT( context,
					   event && isMetadataSearchResultValid( 1U, request, event->scanResult)) ;
	DRIVERCRATE_EXPECT( context, state->metadataCalls == 1U && state->normalCalls == 0U &&
									state->planCalls == 0U) ;
	DRIVERCRATE_EXPECT( context, !worker.requestMetadataSearchCancel( 1U) &&
									!worker.requestPreparationCancel( 1U)) ;
	const std::array<std::wstring, 1> forged{L"current-0"} ;	// 改ざんした表示行への導入要求。
	DRIVERCRATE_EXPECT(
		context, worker.requestInstall( 2U, event ? event->scanResult.scanSessionId : 1U, forged,
									   nullptr, InstallProtectionMode::WINDOWS_RESTORE_POINT)) ;
	event = waitMetadataWorker( worker, 2U, WorkerEventKind::INSTALL_COMPLETED) ;
	DRIVERCRATE_EXPECT( context, event && state->installCalls == 0U && state->restoreCalls == 0U) ;
	OfficialPreparationApproval approval ;	// 旧計画を装った有限のpacket。
	approval.operationId   = 3U ;
	approval.scanSessionId = 1U ;
	approval.planId		   = 1U ;
	approval.decisions.emplace_back() ;
	DRIVERCRATE_EXPECT( context, worker.requestPreparation( approval)) ;
	event = waitMetadataWorker( worker, 3U, WorkerEventKind::PREPARATION_COMPLETED) ;
	DRIVERCRATE_EXPECT( context, event && event->preparationResult.controlError != 0 &&
									state->acquireCalls == 0U) ;
	state->holdMetadata = true ;
	DRIVERCRATE_EXPECT( context, worker.requestMetadataSearch( 4U, request)) ;
	DRIVERCRATE_EXPECT( context, state->entered.try_acquire_for( std::chrono::seconds( 3))) ;
	DRIVERCRATE_EXPECT( context, !worker.requestMetadataSearchCancel( 3U) &&
									!worker.requestPreparationCancel( 4U)) ;
	DRIVERCRATE_EXPECT( context, worker.requestMetadataSearchCancel( 4U)) ;
	state->released.release() ;
	event = waitMetadataWorker( worker, 4U, WorkerEventKind::METADATA_SEARCH_COMPLETED) ;
	DRIVERCRATE_EXPECT( context, event && event->scanResult.outcome == OutcomeCode::ABORTED &&
									isMetadataSearchResultValid( 4U, request, event->scanResult)) ;
	state->holdNormal = true ;
	DRIVERCRATE_EXPECT( context, worker.requestScan( 5U)) ;
	DRIVERCRATE_EXPECT( context, state->entered.try_acquire_for( std::chrono::seconds( 3))) ;
	DRIVERCRATE_EXPECT( context, worker.requestMetadataSearch( 6U, request)) ;
	DRIVERCRATE_EXPECT( context, !worker.requestMetadataSearchCancel( 5U) &&
									worker.requestMetadataSearchCancel( 6U)) ;
	state->released.release() ;
	event = waitMetadataWorker( worker, 6U, WorkerEventKind::METADATA_SEARCH_COMPLETED) ;
	DRIVERCRATE_EXPECT( context, event && event->scanResult.outcome == OutcomeCode::ABORTED &&
									event->scanResult.candidates.empty() &&
									isMetadataSearchResultValid( 6U, request, event->scanResult)) ;
	DRIVERCRATE_EXPECT( context, state->normalCalls == 1U && state->planCalls == 1U) ;
	state->forgedMetadata = true ;
	DRIVERCRATE_EXPECT( context, worker.requestMetadataSearch( 7U, request)) ;
	event = waitMetadataWorker( worker, 7U, WorkerEventKind::METADATA_SEARCH_COMPLETED) ;
	DRIVERCRATE_EXPECT( context, event && event->scanResult.outcome == OutcomeCode::FAILURE &&
									!event->scanResult.metadataSearch &&
									event->scanResult.candidates.empty()) ;
	state->forgedNormal = true ;
	DRIVERCRATE_EXPECT( context, worker.requestScan( 8U)) ;
	event = waitMetadataWorker( worker, 8U, WorkerEventKind::SCAN_COMPLETED) ;
	DRIVERCRATE_EXPECT( context, event && !event->scanResult.succeeded && !event->preparationPlan &&
									state->planCalls == 1U) ;
	worker.stop() ;
	DRIVERCRATE_EXPECT( context, !worker.requestMetadataSearch( 9U, request)) ;
	DRIVERCRATE_EXPECT( context, state->acquireCalls == 0U && state->installCalls == 0U &&
									state->restoreCalls == 0U) ;
}

/**
 * @brief 明示引数、新schema、旧baseline拒否と禁止field非出力を検証する。
 * @param[in,out] context Assertionの集計先。
 */
void testMetadataReport( TestContext &context)
{
	const std::vector<std::vector<std::wstring_view>> rejected{
		{L"--run-metadata"},
		{L"--provider", PROLIFIC_OFFICIAL_PROVIDER_ID},
		{L"--run-metadata", L"--provider"},
		{L"--run-metadata", L"--provider", L"unknown"},
		{L"--run-metadata", L"--provider", WINDOWS_UPDATE_PROVIDER_ID},
		{L"--run-metadata", L"--provider", PROLIFIC_OFFICIAL_PROVIDER_ID, L"--provider",
		 PROLIFIC_OFFICIAL_PROVIDER_ID},
		{L"--run-metadata", L"--provider", PROLIFIC_OFFICIAL_PROVIDER_ID,
		 L"--allow-restricted-network", L"--allow-restricted-network"},
		{L"--describe-metadata", L"--provider", PROLIFIC_OFFICIAL_PROVIDER_ID},
		{L"--run-metadata", L"--provider", PROLIFIC_OFFICIAL_PROVIDER_ID, L"--url",
		 L"https://example.invalid"},
		{L"--run-metadata", L"--provider", PROLIFIC_OFFICIAL_PROVIDER_ID, L"--run-baseline"},
	} ; // 絶対にWorkerを生成してはならない引数列。
	// 全拒否入力で部分的な要求が外へ残らないことを確認する。
	for( const auto &arguments : rejected) {
		const auto command = parseMetadataSearchArguments( arguments) ;	// 純粋な入力分類。
		DRIVERCRATE_EXPECT( context, command.kind == MetadataSearchCommandKind::REJECTED &&
										command.request.enabledProviderIds.empty() &&
										!command.request.restrictedNetworkApproved) ;
	}

	DRIVERCRATE_EXPECT( context, parseMetadataSearchArguments( {}).kind ==
									MetadataSearchCommandKind::DESCRIBE) ;
	const std::array describe{std::wstring_view( L"--describe-metadata")} ;	// 条件だけの単一flag。
	DRIVERCRATE_EXPECT( context, parseMetadataSearchArguments( describe).kind ==
									MetadataSearchCommandKind::DESCRIBE) ;
	const std::array<std::wstring_view, 4> approved{
		L"--run-metadata", L"--provider", PROLIFIC_OFFICIAL_PROVIDER_ID,
		L"--allow-restricted-network"} ;							// 今回限りの明示許可。
	const auto command = parseMetadataSearchArguments( approved) ;	// 一つの有効要求。
	DRIVERCRATE_EXPECT( context, command.kind == MetadataSearchCommandKind::RUN &&
									command.request.restrictedNetworkApproved) ;
	// 新しいrunで前回の回線同意を継承してはならない通常の明示入力。
	const std::array<std::wstring_view, 3> ordinary{L"--run-metadata", L"--provider",
													PROLIFIC_OFFICIAL_PROVIDER_ID} ;
	DRIVERCRATE_EXPECT( context,
					   !parseMetadataSearchArguments( ordinary).request.restrictedNetworkApproved) ;
	std::string description ;	// I/Oを使わない条件出力。
	DRIVERCRATE_EXPECT(
		context, buildMetadataSearchDescription( description) &&
					 description.starts_with( "record=metadata_search_conditions\n") &&
					 description.find( "initial_selection=empty\n") != std::string::npos &&
					 description.find( "limit.session_body_bytes=33554432\n") != std::string::npos) ;
	MetadataFixture fixture ;									// 非通信の正常二台。
	auto			result = fixture.run( command.request) ;	// Worker公開済みと同じ結合。
	std::string		report ;									// 完全構築した非機密本文。
	DRIVERCRATE_EXPECT( context,
					   buildMetadataSearchReport( 7U, L"fixture", command.request, result, report)) ;
	DRIVERCRATE_EXPECT(
		context, report.starts_with(
					 "record=metadata_search_report\nschema_revision=1\npurpose=metadata_only\n")) ;
	DRIVERCRATE_EXPECT( context,
					   report.find( "official.A.extent=not_measured\n") != std::string::npos &&
						   report.find( "official.I.value=unknown\n") != std::string::npos &&
						   report.find( "inventory.D.value=2\n") != std::string::npos &&
						   report.find( "official.R.value=2\n") != std::string::npos) ;
	DRIVERCRATE_EXPECT( context, report.find( "current-0") == std::string::npos &&
									report.find( "device-0") == std::string::npos &&
									report.find( "PL2303 Fixture") == std::string::npos &&
									report.find( "https:") == std::string::npos &&
									report.find( "Fixture") == std::string::npos) ;
	const std::string expected = report ;	// 入力順と端末表示値の変更で出力が変わらない基準。
	// 端末表示値を変更しても非機密reportへ転記されないことを確認する。
	for( auto &candidate : result.candidates) {
		candidate.title			 = L"FORBIDDEN_FIXTURE_ONLY" ;
		candidate.model			 = L"FORBIDDEN_FIXTURE_ONLY" ;
		candidate.sourceLocation = L"FORBIDDEN_FIXTURE_ONLY" ;
	}

	std::reverse( result.providerReports.begin(), result.providerReports.end()) ;
	std::reverse( result.metadataSearch->providers.begin(), result.metadataSearch->providers.end()) ;
	DRIVERCRATE_EXPECT( context,
					   buildMetadataSearchReport( 7U, L"fixture", command.request, result, report) &&
						   report == expected &&
						   report.find( "FORBIDDEN_FIXTURE_ONLY") == std::string::npos) ;
	result.metadataSearch->usage.bodyBytes = 1U ;
	report								   = "unchanged" ;
	DRIVERCRATE_EXPECT(
		context, !buildMetadataSearchReport( 7U, L"fixture", command.request, result, report) &&
					 report == "unchanged") ;
	result = fixture.run( command.request) ;
	DRIVERCRATE_EXPECT(
		context, !buildMetadataSearchReport( 7U, L"different", command.request, result, report)) ;
	ScanOptions baseline ;	// STANDARD専用の旧固定profile。
	DRIVERCRATE_EXPECT( context, resolveBaselineScanOptions( baseline)) ;
	DRIVERCRATE_EXPECT( context,
					   !buildScanMeasurementReport( 7U, L"fixture", baseline, result, report)) ;
	fixture.cancelled = true ;
	result			  = fixture.run( command.request) ;
	DRIVERCRATE_EXPECT(
		context, buildMetadataSearchReport( 7U, L"fixture", command.request, result, report) &&
					 report.find( "outcome=aborted\nreason=cancelled\n") != std::string::npos &&
					 report.find( "provider.reason=not_run_after_stop\n") != std::string::npos) ;
}
/**
 * @brief 観測の非通信引継ぎ、分母保持とstale結果のnetwork前拒否を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testObservationSnapshot( TestContext &context)
{
	MetadataSearchRequest request ;	// 選択した一つのfakeのみを呼ぶ。
	request.enabledProviderIds.emplace_back( PROLIFIC_OFFICIAL_PROVIDER_ID) ;
	MetadataFixture fixture ;	// 未導入の二代表を保持する。
	fixture.withObservations = true ;
	auto result				 = fixture.run( request) ;	// 実networkを使用しない終端結果。
	DRIVERCRATE_EXPECT( context, result.succeeded && hasOnlyMetadataDisplayCandidates( result)) ;
	DRIVERCRATE_EXPECT( context, fixture.observedDevices == 2U && result.candidates.size() == 4U) ;
	DRIVERCRATE_EXPECT( context,
					   result.measurement &&
						   result.measurement->inventory.representedDeviceCount.value == 2U) ;
	DRIVERCRATE_EXPECT( context, result.candidates[0].deviceObservation.has_value()) ;
	result.candidates[0].deviceObservation->scanSessionId = SESSION + 1U ;
	DRIVERCRATE_EXPECT( context, !hasOnlyMetadataDisplayCandidates( result)) ;
	DRIVERCRATE_EXPECT( context, !isPublishedScanMeasurementValid( 7U, result)) ;
	fixture					 = {} ;
	fixture.withObservations = true ;
	fixture.staleObservation = true ;
	result					 = fixture.run( request) ;
	DRIVERCRATE_EXPECT( context, !result.succeeded && fixture.providerCalls.empty()) ;
}

} // namespace

/** @see metadata_search_runner_tests.h */
void runMetadataSearchRunnerTests( TestContext &context)
{
	testRunner( context) ;
	testDedicatedHelper( context) ;
	testPublicationAndController( context) ;
	testMetadataWorker( context) ;
	testMetadataReport( context) ;
	testObservationSnapshot( context) ;
}
} // namespace drivercrate::test
