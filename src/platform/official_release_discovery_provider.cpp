//------------------------------------------------------------------------------
/**
 * @file official_release_discovery_provider.cpp
 * @brief 共通配布情報の検索・取得・監査・指定導入処理。
 * @version 01.00.01
 * @date 2026/09/05
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  Read-only live検索の非cache構築を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX候補発行と指定導入の共通接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  Binding導入adapterを共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  File責務を指定INF導入まで更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel指定導入のOS・session拘束を明示。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel指定導入adapterの試験境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel Ethernet指定導入境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernet binding callbackを接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernetの選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernet検索行の監査対応を保持。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  公表概算sizeを候補表示へ接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Client系列のOS build契約を明確化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  取得元表示と公開日を定義駆動へ変更。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  前回release差分接続を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Intel Ethernet Server検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得計画とworker実行を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  共通配布情報と検索接続を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  共通metadata計測根拠を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  実HTTP取得経路の計測要約を接続。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * </pre>
 *
 * @note 同型deviceを個別に扱い、取得承認・内容／PnP監査が済むまで導入候補にしません。発行済み候補だけを保持bindingで指定deviceへ導入し、全終端でscanを失効させます。
 */
//------------------------------------------------------------------------------

#include "platform/official_release_discovery_provider.h"
#include "core/metadata_search_budget.h"

#include "core/candidate_audit.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "platform/windows_product_type.h"

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {
constexpr std::size_t MAXIMUM_DEVICES = 4096U ;	// 検索対象snapshotと表示行の上限。

//------------------------------------------------------------------------------
/**
 * @brief 配布版をtitle、明示公開日を日付欄へ示し、INF版や更新必要性を補完しない。Package IDは当該metadataの参照であり導入許可ではない。
 *
 * @param[in] session 当該検索のsession。
 * @param[in] ordinal 0から始まる表示行連番。
 * @param[in] device Local probeで系列が一致したsnapshot。
 * @param[in] definition 固定取得元定義。
 * @param[in] release 同sessionの公式取得・解析が成功した配布情報。
 * @param[in] metadataOnly trueは取得用package identityも生成しない専用mode。
 * @return 所有値の表示DTO。取得URLと許諾本文は含めない。
 */
//------------------------------------------------------------------------------
UpdateCandidate		  makeDiscoveryCandidate( const ScanSessionId session, const std::size_t ordinal,
											 const OfficialCatalogDevice	&device,
											 const OfficialSourceDefinition &definition,
											 const OfficialReleaseRecord	&release,
											 const bool						 metadataOnly = false)
{
	UpdateCandidate	   candidate ;							// 未監査の配布情報を表示する所有DTO。
	const std::wstring sourceId( definition.providerId) ;	// Registryと一致する取得元ID。
	candidate.identity =
		sourceId + L":info:" + std::to_wstring( session) + L":" + std::to_wstring( ordinal) ;
	// 専用情報検索では取得用identityを生成しない。
	if( !metadataOnly) {
		candidate.packageIdentity = sourceId + L":release:" + std::to_wstring( session) + L":0" ;
	}

	candidate.providerId	  = sourceId ;
	candidate.deviceIdentity  = device.deviceIdentity ;
	candidate.manufacturer	  = device.manufacturer ;
	candidate.model			  = device.model ;
	candidate.driverClass	  = device.driverClass ;
	candidate.deviceClassGuid = device.deviceClassGuid ;
	// 既存registryだけを取得元表示名の正本にする。
	for( const ProviderDescriptor &descriptor : builtInProviderDescriptors()) {
		// Registry の Provider ID に一致した表示名を取得元と title に使用する。
		if( descriptor.id == definition.providerId) {
			candidate.sourceName = descriptor.displayName ;
			candidate.title		 = descriptor.displayName ;
			break ;
		}
	}

	// INFのProviderと署名publisherは未監査なので、提供元欄を表示名から補完しない。
	if( !release.packageVersion.empty()) {
		// INF版欄にはコピーしない。
		candidate.title += L" " + release.packageVersion ;
	}

	candidate.driverDate = release.publishedDate ;
	// 明示配布版だけを独立欄へ渡し、INF版欄と取得許可は空のまま維持する。
	if( metadataOnly) {
		MetadataDistributionDetails details ;	// URL・許諾本文・hashを含まない表示snapshot。
		details.version = release.packageVersion ;
		// 異なる契約のenumを数値castせず、確認済みの意味だけを変換する。
		switch( release.license) {
			// 今回は同意せず、別操作で必要な許諾確認だけを表示する。
			case OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD:
				details.license = MetadataLicenseStatus::ACCEPTANCE_BEFORE_DOWNLOAD ;
				break ;

			// 取得前同意不要のmetadataを取得許可として扱わない。
			case OfficialReleaseLicense::CONFIRMED_NO_CONSENT:
				details.license = MetadataLicenseStatus::CONFIRMED_NO_CONSENT ;
				break ;

			// 未知・未解決値は未確認のままにする。
			default:
				details.license = MetadataLicenseStatus::UNRESOLVED ;
				break ;
		}

		candidate.metadataDistribution = std::move( details) ;
		candidate.maximumDownloadBytes = release.publishedSizeBytes.value_or( 0U) ;
	}

	candidate.sourceLocation	  = definition.displayOrigin ;
	candidate.displayDownloadSize = release.displaySize ;
	candidate.discoveryBasis	  = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
	candidate.audit				  = makeOfficialDiscoveryCandidateAudit() ;
	candidate.action			  = DriverAction::NONE ;
	candidate.defaultPreference	  = CandidateDefaultPreference::NONE ;
	candidate.installable		  = false ;
	candidate.recommended		  = false ;
	candidate.current			  = false ;
	candidate.eulaAccepted		  = false ;
	candidate.allContentCached	  = false ;
	return candidate ;
}

//------------------------------------------------------------------------------
/**
 * @brief Candidate IDを表示名から再生成せず、scan結果のopaque値をそのまま保持する。不一致時は出力を変更しない。
 *
 * @param[in] session 候補とdeviceを生成した0ではないscan session。
 * @param[in] devices 検索へ渡した全deviceの非機密snapshot。
 * @param[in] result Intel Ethernetの成功した表示候補群。
 * @param[out] retainedDevices 成功時に候補順で更新する対象device群。
 * @param[out] retainedCandidateIdentities 成功時に同順で更新する表示候補ID群。
 * @return 全候補が一意なIntel Ethernet deviceへ対応する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool makeIntelEthernetScanBindings(
	const ScanSessionId session, const std::span<const OfficialCatalogDevice> devices,
	const ScanResult &result, std::vector<OfficialCatalogDevice> &retainedDevices,
	std::vector<std::wstring> &retainedCandidateIdentities)
{
	// 失敗・空・旧sessionの結果を取得後監査へ保持しない。
	if( session == 0U || !result.succeeded || result.scanSessionId != session ||
	   result.candidates.empty() || result.candidates.size() > MAXIMUM_DEVICES) {
		return false ;
	}

	std::vector<OfficialCatalogDevice> matchedDevices ;				// 候補順へ揃えた一時device群。
	std::vector<std::wstring>		   candidateIdentities ;		// 同じindexの一時候補ID群。
	std::unordered_set<std::wstring>   uniqueCandidateIdentities ;	// 候補ID重複の検証集合。
	matchedDevices.reserve( result.candidates.size()) ;
	candidateIdentities.reserve( result.candidates.size()) ;
	uniqueCandidateIdentities.reserve( result.candidates.size()) ;
	std::size_t candidateIndex{} ;	// 現在対応付けるresult.candidatesのindex。
	// 検索と同じ入力順・系列条件で対象を辿り、生成済み候補との完全対応を確認する。
	for( const OfficialCatalogDevice &device : devices)	// 現在確認する非機密snapshot。
	{
		// Intel Ethernet の local 対象条件に一致しない device は対応表へ加えない。
		if( !officialReleaseDeviceMatches( OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025,
										 device)) {
			continue ;
		}

		// 表示されていないdeviceを保持対象へ追加しない。
		if( candidateIndex >= result.candidates.size()) {
			return false ;
		}

		const UpdateCandidate &candidate =
			result.candidates[candidateIndex] ;	// 同じ検索順で生成された表示行。
		// 別Provider、別device、重複候補を曖昧な対応へ変換しない。
		if( candidate.identity.empty() ||
		   candidate.providerId != INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ||
		   candidate.deviceIdentity != device.deviceIdentity ||
		   !uniqueCandidateIdentities.insert( candidate.identity).second) {
			return false ;
		}

		matchedDevices.push_back( device) ;
		candidateIdentities.push_back( candidate.identity) ;
		++candidateIndex ;
	}

	// 対応deviceのない余剰候補を保持しない。
	if( candidateIndex != result.candidates.size()) {
		return false ;
	}

	retainedDevices				= std::move( matchedDevices) ;
	retainedCandidateIdentities = std::move( candidateIdentities) ;
	return true ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult scanOfficialReleaseMetadata(
	const OfficialReleaseFamily family, const ScanSessionId session,
	const std::span<const OfficialCatalogDevice> devices, const bool windowsServer,
	const OfficialReleaseMetadataReader &reader, const ProviderProgressCallback &progress,
	const std::uint32_t						   windowsBuild,
	const OfficialReleaseObservationEvaluator &observationEvaluator,
	ProviderMeasurementEvidence *const		   measurementEvidence,
	MetadataSearchExecutionContext *const	   execution)
{
	// 呼出し側が保持する前回根拠を、新しい検索の部分結果と混在させない。
	if( measurementEvidence != nullptr) {
		*measurementEvidence = {} ;
	}

	ScanResult result{.scanSessionId = session,
					  .outcome		 = OutcomeCode::FAILURE,
					  .state		 = ProviderScanState::FAILURE} ;	// 成功条件が揃うまでは失敗。
	result.purpose = execution != nullptr ? ScanPurpose::METADATA_ONLY : ScanPurpose::STANDARD ;
	const OfficialSourceDefinition *const definition =
		// 組み込みの非所有定義。
		officialSourceDefinition( family) ;
	// 定義・session・件数・callback が不正な scan は取得境界を呼ばない。
	if( definition == nullptr || session == 0U || devices.size() > MAXIMUM_DEVICES || !reader ||
	   !progress ||
	   (execution != nullptr &&
		(execution->scanSessionId() != session ||
		 execution->activeProviderId() != definition->providerId || observationEvaluator))) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		// 不正sessionや上限超過では取得境界を呼ばない。
		return result ;
	}

	// Providerとsessionを固定し、端末identityはworker内の集合だけへ保持する。
	if( measurementEvidence != nullptr) {
		measurementEvidence->providerId	   = definition->providerId ;
		measurementEvidence->scanSessionId = session ;
		measurementEvidence->scope		   = MeasurementScope::DEVICE_QUERY ;
	}

	// 専用contextの停止だけを確認し、通常scanの実行順序を変えない。
	const auto stopped = [&result, execution, measurementEvidence]() {
		// 通常経路は従来の同期処理をそのまま継続する。
		if( execution == nullptr) {
			return false ;
		}

		const NativeError error = execution->checkpoint() ;	// 最初に観測された停止の診断。
		// 継続許可された区間だけが新しい照合・commitへ進む。
		if( error == 0) {
			return false ;
		}

		result.error	 = error ;
		result.succeeded = false ;
		result.outcome	 = execution->sessionStopReason() == MetadataSearchReason::CANCELLED
							   ? OutcomeCode::ABORTED
							   : OutcomeCode::FAILURE ;
		result.state	 = ProviderScanState::FAILURE ;
		// 未完了集合を確定0へ昇格させず、既に結合したrecordだけを保持する。
		if( measurementEvidence != nullptr) {
			measurementEvidence->queryOutcome		   = result.outcome ;
			measurementEvidence->eligible.extent	   = MeasurementExtent::LOWER_BOUND ;
			measurementEvidence->queryCompleted.extent = MeasurementExtent::LOWER_BOUND ;
			measurementEvidence->information.extent	   = MeasurementExtent::LOWER_BOUND ;
			measurementEvidence->recordExtent		   = MeasurementExtent::LOWER_BOUND ;
		}

		return true ;
	} ;
	// Queue直後の取消しでもinventory属性を解析し始めない。
	if( stopped()) {
		return result ;
	}

	std::vector<const OfficialCatalogDevice *> matched ;	// 呼出し中だけ有効な参照対象。
	std::unordered_set<std::wstring>		   identities ;	// 端末identityの重複を通信前に拒否する。
	// 全snapshotを有限回で確認し、検索対象だけを記憶する。
	for( const OfficialCatalogDevice &device : devices) {
		// 有限loop内でも個別deadlineと取消しを観測する。
		if( stopped()) {
			return result ;
		}

		// 空・長さ超過・重複 identity を含む inventory から候補を作らない。
		if( device.deviceIdentity.empty() || device.deviceIdentity.size() > 256U ||
		   !identities.insert( device.deviceIdentity).second) {
			result.error = static_cast<NativeError>( E_INVALIDARG) ;
			// 曖昧なinventoryから同じdeviceの候補を二重生成しない。
			return result ;
		}

		// 系列の OS 条件と local device 条件が両方成立する対象だけを保持する。
		if( officialReleaseOperatingSystemMatches( family, windowsServer, windowsBuild) &&
		   officialReleaseDeviceMatches( family, device)) {
			matched.push_back( &device) ;
			// Probe済みTを保持し、途中停止では下限として公開できるようにする。
			if( execution != nullptr && measurementEvidence != nullptr) {
				measurementEvidence->eligible.identities.push_back( device.deviceIdentity) ;
			}
		}
	}

	result.coverage.eligibleDeviceCount = matched.size() ;
	// Local probeが明示的に一致させたnodeだけを探索対象として確定する。
	if( measurementEvidence != nullptr) {
		measurementEvidence->eligible.extent = MeasurementExtent::EXACT ;
		measurementEvidence->eligible.identities.clear() ;
		measurementEvidence->eligible.identities.reserve( matched.size()) ;
		// 同型nodeをまとめず、一つのopaque identityを一件として保持する。
		for( const OfficialCatalogDevice *const device : matched) {
			measurementEvidence->eligible.identities.push_back( device->deviceIdentity) ;
		}
	}

	// 対象 device がない場合は通信せず対象外として scan を完了する。
	if( matched.empty()) {
		// 対象0は未検索と区別できる確定0として全段階へ保持する。
		if( measurementEvidence != nullptr) {
			measurementEvidence->queryOutcome		   = OutcomeCode::SUCCESS ;
			measurementEvidence->queryCompleted.extent = MeasurementExtent::EXACT ;
			measurementEvidence->information.extent	   = MeasurementExtent::EXACT ;
			measurementEvidence->applicabilityExtent =
				execution != nullptr ? MeasurementExtent::NOT_MEASURED : MeasurementExtent::EXACT ;
			measurementEvidence->readinessExtent =
				execution != nullptr ? MeasurementExtent::NOT_MEASURED : MeasurementExtent::EXACT ;
			measurementEvidence->recordExtent = MeasurementExtent::EXACT ;
		}

		result.succeeded = true ;
		result.outcome	 = OutcomeCode::SUCCESS ;
		result.state	 = ProviderScanState::NOT_APPLICABLE ;
		progress( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
				  .percentComplete = 100U,
				  .completedItems  = 0U,
				  .totalItems	   = 0U}) ;
		return result ;
	}

	progress( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
			  .percentComplete = 0U,
			  .completedItems  = 0U,
			  .totalItems	   = matched.size()}) ;
	OfficialReleaseRecord release ;				// Worker内だけで保持し、UIへ直接送らない取得情報。
	bool				  metadataRejected{} ;	// Readerが解析・取得根拠拒否を返した場合true。
	// 計測接続時だけ、実際のreader呼出し開始をquery状態へ反映する。
	if( measurementEvidence != nullptr) {
		measurementEvidence->queryOutcome = OutcomeCode::IN_PROGRESS ;
	}

	// Progress callbackによる取消し後も新しいreader呼出しを開始しない。
	if( stopped()) {
		return result ;
	}

	result.error = reader( family, session, release, metadataRejected) ;
	// Reader終端で取消し・期限が成立した場合はcommitしない。
	if( stopped()) {
		return result ;
	}

	// 通信失敗や不完全 metadata を候補なしの成功として扱わない。
	if( result.error != 0 || metadataRejected || release.family != family ||
	   release.parserRevision == 0U || release.fileName.empty() || release.downloadUrl.empty()) {
		// 取得 error がない形式不正または明示的な拒否を metadata 拒否に分類する。
		if( result.error == 0 || metadataRejected) {
			result.state = ProviderScanState::METADATA_REJECTED ;
		}

		// 形式不正に診断値が付いていない場合も成功にせず不正 data とする。
		if( result.error == 0) {
			result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
		}

		// 途中失敗時は確認済み0件を下限として保持し、情報なしへ昇格させない。
		if( measurementEvidence != nullptr) {
			measurementEvidence->queryOutcome		   = OutcomeCode::FAILURE ;
			measurementEvidence->queryCompleted.extent = MeasurementExtent::LOWER_BOUND ;
			measurementEvidence->information.extent	   = MeasurementExtent::LOWER_BOUND ;
			measurementEvidence->applicabilityExtent   = execution != nullptr
															 ? MeasurementExtent::NOT_MEASURED
															 : MeasurementExtent::LOWER_BOUND ;
			measurementEvidence->readinessExtent	   = execution != nullptr
															 ? MeasurementExtent::NOT_MEASURED
															 : MeasurementExtent::LOWER_BOUND ;
			measurementEvidence->recordExtent		   = MeasurementExtent::LOWER_BOUND ;
		}

		// 通信失敗や未解析の情報を候補なしとして成功にしない。
		return result ;
	}

	// 一つの検証済みrecordが全一致nodeへ到達した事実をpayload取得と独立して保持する。
	if( measurementEvidence != nullptr) {
		measurementEvidence->queryOutcome	= OutcomeCode::SUCCESS ;
		measurementEvidence->queryCompleted = measurementEvidence->eligible ;
		measurementEvidence->information	= measurementEvidence->eligible ;
		measurementEvidence->applicabilityExtent =
			execution != nullptr ? MeasurementExtent::NOT_MEASURED : MeasurementExtent::LOWER_BOUND ;
		measurementEvidence->readinessExtent =
			execution != nullptr ? MeasurementExtent::NOT_MEASURED : MeasurementExtent::LOWER_BOUND ;
		measurementEvidence->recordExtent = MeasurementExtent::EXACT ;
		measurementEvidence->records.push_back(
			{std::wstring( definition->providerId) + L":record:" + std::to_wstring( session) + L":0",
			 measurementEvidence->information.identities}) ;
	}

	progress( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
			  .percentComplete = 70U,
			  .completedItems  = 0U,
			  .totalItems	   = matched.size()}) ;
	// 一回の配布情報を同型deviceごとに参照し、別identityの行を維持する。
	for( std::size_t index = 0U; index < matched.size(); ++index) {
		// 個別表示行の生成前に停止を観測し、後続行のcommitを抑止する。
		if( stopped()) {
			return result ;
		}

		UpdateCandidate candidate =
			makeDiscoveryCandidate( session, index, *matched[index], *definition, release,
								   execution != nullptr) ;	// 現在deviceの表示行。
		// 観測差分の評価が提供された場合だけ非機密の差分を候補へ反映する。
		if( observationEvaluator) {
			candidate.releaseObservationDifference =
				// 非機密な前回差分だけを反映。
				observationEvaluator( *matched[index], release) ;
		}

		// 一行の生成中に期限が到達した場合も、未commit行を保持結果へ混ぜない。
		if( stopped()) {
			return result ;
		}

		result.candidates.push_back( std::move( candidate)) ;
		progress( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
				  .percentComplete =
					  static_cast<std::uint32_t>( 70U + (index + 1U) * 30U / matched.size()),
				  .completedItems = index + 1U,
				  .totalItems	  = matched.size()}) ;
	}

	// ここでのassessedは系列配布情報の参照完了であり、PnP適用性の完了ではない。
	result.coverage.assessedDeviceCount = matched.size() ;
	result.succeeded					= true ;
	result.outcome						= OutcomeCode::SUCCESS ;
	result.state						= ProviderScanState::CANDIDATES_AVAILABLE ;
	return result ;
}

/** @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。 */
ScanResult scanOfficialMetadataOnly( const OfficialReleaseFamily family, const ScanSessionId session,
									const std::span<const OfficialCatalogDevice> devices,
									const bool windowsServer, const std::uint32_t windowsBuild,
									MetadataSearchExecutionContext &execution,
									const ProviderProgressCallback &progress,
									ProviderMeasurementEvidence	   &evidence)
{
	OfficialHttpClient http( execution) ;	// 専用用途と借用contextを呼出し内だけ所有する。
	// 読取結果は純粋表示helperへ渡し、Providerの準備状態へ保存しない。
	const OfficialReleaseMetadataReader reader =
		[&http, &execution]( const auto selectedFamily, const auto selectedSession,
							OfficialReleaseRecord &record, bool &rejected) {
			return readOfficialReleaseMetadata( selectedFamily, selectedSession, http, record,
											   rejected, &execution) ;
		} ;
	ScanResult result = scanOfficialReleaseMetadata( family, session, devices, windowsServer, reader,
													progress, windowsBuild, {}, &evidence,
													&execution) ;	// 表示行と計測だけの所有結果。
	// Source ledgerのURLを公開せず、固定resourceとcache使用根拠だけを残す。
	if( !summarizeOfficialSourceEvidence( http.sourceEvidence(), evidence.resources)) {
		// 由来の根拠が矛盾する行を未知のcache状態だけに落として公開しない。
		evidence = {} ;
		result.candidates.clear() ;
		result.succeeded = false ;
		result.outcome	 = OutcomeCode::FAILURE ;
		result.state	 = ProviderScanState::METADATA_REJECTED ;
		result.error	 = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialReleaseDiscoveryProvider::OfficialReleaseDiscoveryProvider(
	const OfficialReleaseFamily family) noexcept
	: OfficialReleaseDiscoveryProvider( family, {})
{
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialReleaseDiscoveryProvider::OfficialReleaseDiscoveryProvider(
	const OfficialReleaseFamily family, OfficialInfRankAuditor rankAuditor) noexcept
	: OfficialReleaseDiscoveryProvider( family, std::move( rankAuditor), {}, {}, {})
{
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialReleaseDiscoveryProvider::OfficialReleaseDiscoveryProvider(
	const OfficialReleaseFamily family, OfficialInfRankAuditor rankAuditor,
	OfficialInfInstallBinder bindingCreator, OfficialInfInstallBindingReleaser bindingReleaser,
	OfficialBoundInfInstaller boundInstaller, const bool useCatalogCache) noexcept
	: family_( family), rankAuditor_( std::move( rankAuditor)),
	  bindingCreator_( std::move( bindingCreator)), bindingReleaser_( std::move( bindingReleaser)),
	  boundInstaller_( std::move( boundInstaller)), http_( useCatalogCache)
{
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void OfficialReleaseDiscoveryProvider::configureReleaseObservationContext(
	const std::span<const LocalOfficialReleaseObservation> previous,
	const OfficialReleaseEnvironmentFingerprints		  &environment)
{
	previousReleaseObservations_.assign( previous.begin(), previous.end()) ;
	observationEnvironment_ = environment ;
	currentReleaseObservations_.clear() ;
}

//------------------------------------------------------------------------------
/**
	 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
	 */
//------------------------------------------------------------------------------
std::span<const LocalOfficialReleaseObservation> OfficialReleaseDiscoveryProvider::
	releaseObservations() const noexcept
{
	return currentReleaseObservations_ ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult OfficialReleaseDiscoveryProvider::scan(
	const ScanSessionId scanSessionId, const std::span<const OfficialCatalogDevice> devices,
	const LocalHardwareIdMatcher   &hardwareIdMatcher,
	const ProviderProgressCallback &progressCallback)
{
	static_cast<void>( hardwareIdMatcher) ;
	// 設定済みの前回観測を維持し、前回scanの配布情報と今回観測だけを失効させる。
	resetPreparedDownload() ;
	retainedRelease_ = {} ;
	currentReleaseObservations_.clear() ;
	retainedSessionId_	 = 0U ;
	retainedDeviceCount_ = 0U ;
	http_.invalidateSourceSession() ;
	OfficialReleaseRecord				observed ;	// Scan全体が成功するまで公開しない一時metadata。
	const OfficialReleaseMetadataReader reader =
		[this, &observed]( const OfficialReleaseFamily family, const ScanSessionId session,
						  OfficialReleaseRecord &release, bool &rejected) {
			// 元のHTTP／解析失敗を失わず、一時保持の可否だけを判断する。
			const NativeError error =
				readOfficialReleaseMetadata( family, session, http_, release, rejected) ;
			// 取得・解析成功だけを一時保持し、失敗後の古い情報を残さない。
			if( error == 0 && !rejected) {
				observed = release ;
			}

			return error ;
		} ; // 任意URLを受け取らない固定公式metadata取得境界。
	FILETIME observedTime{} ;	// Live metadata確認へ使用する現在UTC FILETIME。
	GetSystemTimeAsFileTime( &observedTime) ;
	ULARGE_INTEGER observedTimeValue{} ;	// 二つのDWORDを永続形式の64-bit値へ変換する共用体。
	observedTimeValue.LowPart  = observedTime.dwLowDateTime ;
	observedTimeValue.HighPart = observedTime.dwHighDateTime ;
	bool observationFailed{} ;	// 一件でも観測生成に失敗した場合に全今回観測を破棄する。
	const OfficialReleaseObservationEvaluator observationEvaluator =
		[this, &observationFailed, observedFileTime = observedTimeValue.QuadPart](
			const OfficialCatalogDevice &device,
			const OfficialReleaseRecord &release) -> std::optional<ReleaseObservationDifference> {
		// Local stateが利用不能ならlive検索だけを継続する。
		if( observationFailed || observationEnvironment_.operatingSystem.empty() ||
		   observationEnvironment_.deviceConfiguration.empty()) {
			return std::nullopt ;
		}

		OfficialReleaseObservationEvaluation evaluation ;	// 今回観測と非機密差分。
		// 観測評価の失敗時は部分観測を破棄し、候補生成とは分離する。
		if( !evaluateOfficialReleaseObservation(
			   family_, release, device, observationEnvironment_.operatingSystem,
			   observationEnvironment_.deviceConfiguration, observedFileTime,
			   previousReleaseObservations_, evaluation)) {
			observationFailed = true ;
			currentReleaseObservations_.clear() ;
			// 部分観測を保存せず、候補生成自体は継続する。
			return std::nullopt ;
		}

		currentReleaseObservations_.push_back( std::move( evaluation.observation)) ;
		return evaluation.difference ;
	} ; // HMACとhash自体を候補へ渡さず、差分enumだけを返すcallback。
	// 全ての表示行生成が成功した場合だけmetadataを継続保持する。
	ScanResult result = scanOfficialReleaseMetadata(
		family_, scanSessionId, devices, isWindowsServer(), reader, progressCallback,
		currentWindowsBuildNumber(), observationEvaluator, &measurementEvidence_) ;
	// 同じ取得ledgerを追加通信せず公開可能な固定source要約へ変換する。
	static_cast<void>(
		summarizeOfficialSourceEvidence( http_.sourceEvidence(), measurementEvidence_.resources)) ;
	// 一部でも観測に失敗した場合は候補全体の差分表示を取り消す。
	if( observationFailed) {
		// 途中まで付いた差分も一括破棄し、曖昧な一部観測をUIへ表示しない。
		for( UpdateCandidate &candidate : result.candidates) {
			candidate.releaseObservationDifference.reset() ;
		}
	}

	// 生成された行数はhelperで4096以下へ制限され、別deviceでも配布物の保持は一件だけ。
	if( result.succeeded && !result.candidates.empty() &&
	   result.candidates.size() <= MAXIMUM_DEVICES) {
		// Intel Ethernet の内部対応を確定できなければ候補と取得 session を失効させる。
		if( family_ == OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025 &&
		   !makeIntelEthernetScanBindings( scanSessionId, devices, result, retainedDevices_,
										  retainedCandidateIdentities_)) {
			currentReleaseObservations_.clear() ;
			result.candidates.clear() ;
			result.succeeded = false ;
			result.outcome	 = OutcomeCode::FAILURE ;
			result.state	 = ProviderScanState::FAILURE ;
			result.error	 = static_cast<NativeError>( E_UNEXPECTED) ;
			http_.invalidateSourceSession() ;
			// 内部対応が曖昧な候補をUIまたは取得計画へ渡さない。
			return result ;
		}

		retainedRelease_	 = std::move( observed) ;
		retainedSessionId_	 = scanSessionId ;
		retainedDeviceCount_ = static_cast<std::uint32_t>( result.candidates.size()) ;
		ownerThreadId_		 = GetCurrentThreadId() ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult executeIntelEthernetPreparedInstall(
	const IntelEthernetPreparedInstallContext &context,
	const std::span<const std::wstring> identities, const PreparedInfReverifier &reverifier,
	const OfficialInfRankAuditor &rankAuditor, const OfficialBoundInfInstaller &boundInstaller,
	const std::uintptr_t parentWindowNative, const ProviderProgressCallback &progressCallback)
{
	return executeBoundPreparedInstall( OfficialDriverAuditProfile::INTEL_ETHERNET_SERVER2025,
									   context, identities, reverifier, rankAuditor, boundInstaller,
									   parentWindowNative, progressCallback) ;
}
//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult OfficialReleaseDiscoveryProvider::install(
	const ScanSessionId scanSessionId, const std::span<const std::wstring> identities,
	const std::uintptr_t parentWindowNative, const ProviderProgressCallback &progressCallback)
{
	// Intel Ethernet 以外の系列へ専用導入能力を流用する要求を拒否する。
	if( family_ != OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025) {
		invalidatePreparation() ;
		InstallResult rejected ;	// Install能力を持たない別familyの固定拒否結果。
		rejected.downloadOutcome = OutcomeCode::FAILURE ;
		rejected.downloadError	 = static_cast<NativeError>( E_NOTIMPL) ;
		rejected.installOutcome	 = OutcomeCode::FAILURE ;
		rejected.installError	 = static_cast<NativeError>( E_NOTIMPL) ;
		// Intel Wi-Fi等へEthernet専用の導入能力を波及させない。
		return rejected ;
	}

	const bool			windowsServer = isWindowsServer() ;	// Intel導入可否に使う実OS種別。
	const std::uint32_t windowsBuild =
		// Intel導入可否に使う実OS build番号。
		currentWindowsBuildNumber() ;
	const bool providerContextConfirmed =	// 導入可能な固定系列と同意済み保持状態の確認結果。
		scanSessionId != 0U && scanSessionId == retainedSessionId_ &&
		GetCurrentThreadId() == ownerThreadId_ && candidatesPublished_ && publicationResolved_ &&
		preparedTarget_.has_value() && acquisitionAttempted_ &&
		acquisition_.publishedSha256Verified && !retainedRelease_.publishedSha256.empty() &&
		retainedRelease_.publishedSha256 == acquisition_.sha256 &&
		preparedTarget_->providerId == INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID &&
		preparedTarget_->resourceId == OFFICIAL_PAYLOAD_RESOURCE_ID &&
		preparedTarget_->parserRevision == retainedRelease_.parserRevision &&
		preparedTarget_->terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED &&
		preparedTarget_->eulaRevision == retainedRelease_.eulaRevision &&
		preparedTarget_->eulaText == retainedRelease_.eulaText &&
		preparedTarget_->requiresPrerequisiteConfirmation && rankAuditor_ && boundInstaller_ &&
		http_.hasSourceEvidence( scanSessionId, INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID,
								OFFICIAL_LANDING_RESOURCE_ID) &&
		http_.hasSourceEvidence( scanSessionId, INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID,
								OFFICIAL_PAYLOAD_RESOURCE_ID) ;

	try {
		const IntelEthernetPreparedInstallContext context{
			.scanSessionId = scanSessionId,
			.acquisition   = &acquisition_,
			.targets	   = &installTargets_,
			.auditedPackages =
				std::span<const OfficialAuditedInfPackage>( preparedAudit_.auditedPackages),
			.windowsServer			 = windowsServer,
			.windowsBuild			 = windowsBuild,
			.sourceEvidenceConfirmed = providerContextConfirmed,
		} ; // Provider外へ保存しないIntel固有の非所有fixture境界。
		const PreparedInfReverifier reverifier = []( const OfficialAuditedInfPackage &package) {
			return reverifyOfficialAuditedInfPackage( package) ;
		} ; // 本番閉包再検証。
		InstallResult result = executeIntelEthernetPreparedInstall(
			context, identities, reverifier, rankAuditor_, boundInstaller_, parentWindowNative,
			progressCallback) ;	// 保持物の有効期間内だけ実行する。
		invalidatePreparation() ;
		return result ;
	} catch( ...) {
		// Callbackまたは一時copyの例外でもbindingと取得物を解放してからworker境界へ返す。
		invalidatePreparation() ;
		throw ;
	}
}
//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::vector<OfficialPreparationTarget> makeReleasePreparationTargets(
	const OfficialReleaseRecord &release, const ScanSessionId scanSessionId,
	const std::uint64_t planId, const std::uint32_t deviceCount)
{
	// 未解析・対象外・識別不能な情報から計画を生成しない。
	if( (release.family != OfficialReleaseFamily::INTEL_WIFI &&
		release.family != OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025) ||
	   scanSessionId == 0U || planId == 0U || deviceCount == 0U || deviceCount > MAXIMUM_DEVICES ||
	   release.parserRevision == 0U || release.fileName.empty() || release.downloadUrl.empty()) {
		return {} ;
	}

	const OfficialSourceDefinition *const definition =
		// Registryを参照する組み込み定義。
		officialSourceDefinition( release.family) ;
	// 系列の定義がない場合は取得準備対象を発行しない。
	if( definition == nullptr) {
		return {} ;
	}

	OfficialPreparationTarget target ;	// URLを含まない対象snapshot。
	target.providerId = definition->providerId ;
	target.identity	  = target.providerId + L":prepare:" + std::to_wstring( planId) ;
	target.releaseIdentity =
		target.providerId + L":release:" + std::to_wstring( scanSessionId) + L":0" ;
	target.resourceId	  = OFFICIAL_PAYLOAD_RESOURCE_ID ;
	target.parserRevision = release.parserRevision ;
	target.maximumBytes	  = DEFAULT_OFFICIAL_PREPARATION_LIMITS.maximumFileBytes ;
	target.deviceCount	  = deviceCount ;
	// 本文の提示・revision固定・payload policy接続前に同意可能としない。
	target.terms = OfficialPreparationTerms::UNRESOLVED ;
	// Intel Ethernet の取得準備だけに、専用の EULA と公表 hash 条件を適用する。
	if( release.family == OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025) {
		// Parser由来の本文・版・公開hashがない配布情報を取得承認へ昇格しない。
		if( release.parserRevision < 2U ||
		   release.license != OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD ||
		   release.eulaRevision.empty() || !validPreparationEulaText( release.eulaText) ||
		   release.publishedSha256.size() != 64U ||
		   release.publishedSha256.find_first_not_of( L"0123456789ABCDEF") != std::wstring::npos) {
			return {} ;
		}

		target.maximumBytes						= 128ULL * 1024ULL * 1024ULL ;
		target.terms							= OfficialPreparationTerms::ACCEPTANCE_REQUIRED ;
		target.eulaRevision						= release.eulaRevision ;
		target.eulaText							= release.eulaText ;
		target.requiresPrerequisiteConfirmation = true ;
	}

	OfficialPreparationSession validation ;	// 共通のID・本文・件数上限を再利用する。
	// UIへ渡してから不正が判明する計画を生成しない。
	if( validation.initialize(
		   {scanSessionId, planId, DEFAULT_OFFICIAL_PREPARATION_LIMITS, {target}}) !=
	   OfficialPreparationError::NONE) {
		return {} ;
	}

	return {std::move( target)} ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::vector<OfficialPreparationTarget> OfficialReleaseDiscoveryProvider::preparationTargets(
	const ScanSessionId scanSessionId, const std::uint64_t planId)
{
	// Intel監査用の検索行対応が欠けた取得計画もfail-closedで拒否する。
	if( scanSessionId == 0U || scanSessionId != retainedSessionId_ ||
	   GetCurrentThreadId() != ownerThreadId_ || acquisitionAttempted_ || planId == 0U ||
	   planId <= preparedPlanId_ ||
	   (family_ == OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025 &&
		(retainedDeviceCount_ == 0U || retainedDevices_.size() != retainedDeviceCount_ ||
		 retainedCandidateIdentities_.size() != retainedDevices_.size()))) {
		return {} ;
	}

	auto targets = makeReleasePreparationTargets( retainedRelease_, scanSessionId, planId,
												 retainedDeviceCount_) ;	// 一配布物の対象。
	// 発行できた取得対象がある場合だけ現在 plan に結び付けて保持する。
	if( !targets.empty()) {
		preparedTarget_ = targets.front() ;
		preparedPlanId_ = planId ;
	}

	return targets ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
const ProviderMeasurementEvidence &OfficialReleaseDiscoveryProvider::measurementEvidence()
	const noexcept
{
	return measurementEvidence_ ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void OfficialReleaseDiscoveryProvider::invalidatePreparation() noexcept
{
	resetPreparedDownload() ;
	retainedRelease_ = {} ;
	previousReleaseObservations_.clear() ;
	observationEnvironment_ = {} ;
	currentReleaseObservations_.clear() ;
	measurementEvidence_ = {} ;
	retainedSessionId_	 = 0U ;
	retainedDeviceCount_ = 0U ;
	http_.invalidateSourceSession() ;
}

} // namespace drivercrate
