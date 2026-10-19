//------------------------------------------------------------------------------
/**
 * @file metadata_search_runner.cpp
 * @brief 現在属性と専用metadata callbackの有界な直列実行。
 * @version 01.01.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  非取得専用のRegistry実行境界を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  端末内の観測snapshotと候補詳細を結合。
 * </pre>
 *
 * @note 許可の入力は専用callbackだけであり、通常scanや導入へのfallbackを持たない。
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#include "platform/metadata_search_runner.h"

#include "core/candidate_audit.h"
#include "core/candidate_selection.h"
#include "core/metadata_search.h"
#include "core/provider_registry.h"

#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {
constexpr NativeError INVALID_ARGUMENT = static_cast<NativeError>( E_INVALIDARG) ;	// 契約拒否。
constexpr NativeError INTERNAL_ERROR   = static_cast<NativeError>( E_UNEXPECTED) ;	// 例外と内部矛盾。

/**
 * @brief 表示名とpolicyを含む全descriptor fieldを正本へ照合する。
 * @param[in] left 一回の実行snapshot。
 * @param[in] right Registry正本。
 * @return 全登録fieldが完全一致した場合true。
 */
bool sameDescriptor( const ProviderDescriptor &left, const ProviderDescriptor &right) noexcept
{
	return left.id == right.id && left.displayName == right.displayName &&
		   left.capabilities == right.capabilities && left.selectionTier == right.selectionTier &&
		   left.discoveryBasis == right.discoveryBasis &&
		   left.installNotice == right.installNotice &&
		   left.enabledByDefault == right.enabledByDefault &&
		   left.officialSourcePolicyId == right.officialSourcePolicyId ;
}

/**
 * @brief 一Providerが返した行の由来と非導入契約を確認する。
 * @param[in] result 検査する結果。
 * @param[in] descriptor 固定した発行元。
 * @param[in] session 現在のsession。
 * @param[in] inventory trueは全行が現在属性である必要がある。
 * @param[in] devices 現在属性から得たD。Inventory検証時は使用しない。
 * @return 行が一意で発行元・用途・device結合・監査が整合する場合true。
 */
bool validRows( const ScanResult &result, const ProviderDescriptor &descriptor,
			   const ScanSessionId session, const bool inventory,
			   const std::set<std::wstring> &devices)
{
	// 子結果から別sessionの計画・aggregate reportを注入させない。
	if( result.scanSessionId != session || !hasOnlyMetadataDisplayCandidates( result) ||
	   result.candidates.size() > MEASUREMENT_DEVICE_LIMIT || !result.providerReports.empty() ||
	   result.metadataSearch || result.measurement || !isValidProviderCoverage( result.coverage) ||
	   result.succeeded != (result.outcome == OutcomeCode::SUCCESS ||
							result.outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS) ||
	   (result.outcome != OutcomeCode::SUCCESS &&
		result.outcome != OutcomeCode::SUCCEEDED_WITH_ERRORS &&
		result.outcome != OutcomeCode::FAILURE && result.outcome != OutcomeCode::ABORTED)) {
		return false ;
	}

	std::set<std::wstring> identities ;	// 当該Providerの一意な候補ID。
	std::set<std::wstring> bound ;		// 初期readerは一device一情報行に限定する。
	// 上限付き全行を検証し、部分的に異常行だけを捨てて成功へ変換しない。
	for( const UpdateCandidate &candidate : result.candidates) {
		// 現在行の偽装、別Provider、端末外の結合、選択権限を全て拒否する。
		if( candidate.identity.empty() || candidate.identity.size() > 256U ||
		   candidate.providerId != descriptor.id || candidate.deviceIdentity.empty() ||
		   candidate.deviceIdentity.size() > 256U || candidate.current != inventory ||
		   (!inventory && !devices.contains( candidate.deviceIdentity)) ||
		   !identities.insert( candidate.identity).second ||
		   !bound.insert( candidate.deviceIdentity).second ||
		   !isCandidateAuditValid( candidate, descriptor) ||
		   !isCandidateDetailsValid( candidate, session) ||
		   !isCandidateDefaultPreferenceValid( candidate, descriptor)) {
			return false ;
		}
	}

	return true ;
}

/**
 * @brief 子結果の非機密なProvider終端を作成する。
 * @param[in] descriptor Registry正本。
 * @param[in] result 検証済みの子結果。
 * @return 発行元、状態、診断、件数と元outcomeの所有report。
 */
ProviderScanReport providerReport( const ProviderDescriptor &descriptor, const ScanResult &result)
{
	return {.descriptor		= descriptor,
			.state			= resolveProviderScanState( result, true),
			.error			= result.error,
			.candidateCount = result.candidates.size(),
			.coverage		= result.coverage,
			.outcome		= result.outcome} ;
}
} // namespace

/** @see src/platform/metadata_search_runner.h 宣言側の契約を正本とする。 */
bool validateMetadataSearchRegistrations(
	const std::span<const MetadataSearchRegistration> registrations) noexcept
{
	const auto descriptors = builtInProviderDescriptors() ;	// 正本の非所有view。
	// 一部登録を落として専用能力の欠落を隠すことを禁止する。
	if( registrations.size() != descriptors.size()) {
		return false ;
	}

	// 全登録をID集合として照合し、表示・実行順が違っても同じ契約を要求する。
	for( const MetadataSearchRegistration &registration : registrations) {
		// Callbackの発行元を同じIDの正本descriptorへ対応付ける。
		const auto expected = std::find_if( descriptors.begin(), descriptors.end(),
										   [&registration]( const auto &descriptor) {
											   return descriptor.id == registration.descriptor.id ;
										   }) ;
		// 正本不一致、片側能力、重複、専用source不整合を実行前に拒否する。
		if( expected == descriptors.end() || !sameDescriptor( registration.descriptor, *expected) ||
		   static_cast<bool>( registration.scan) != isMetadataSearchProvider( *expected) ||
		   std::count_if( registrations.begin(), registrations.end(),
						 [&registration]( const auto &entry) {
							 return entry.descriptor.id == registration.descriptor.id ;
						 }) != 1) {
			return false ;
		}
	}

	return true ;
}

/** @see src/platform/metadata_search_runner.h 宣言側の契約を正本とする。 */
ScanResult runMetadataSearch( const ScanSessionId session, const MetadataSearchRequest &request,
							 MetadataSearchExecutionContext					  &execution,
							 const std::span<const MetadataSearchRegistration> registrations,
							 const MetadataInventoryScan					  &inventory,
							 ScanMeasurementContext							   measurementContext,
							 const ProviderProgressCallback					  &progress)
{
	ScanResult result ;	// 公開権限を持たない一回の所有結果。
	result.scanSessionId = session ;
	result.purpose		 = ScanPurpose::METADATA_ONLY ;
	result.outcome		 = OutcomeCode::FAILURE ;
	result.state		 = ProviderScanState::FAILURE ;
	// 入力矛盾でinventoryやネットワークを呼ばず、旧権限の復活も行わない。
	if( session == 0U || execution.scanSessionId() != session || execution.request() != request ||
	   !validateMetadataSearchRequest( request, builtInProviderDescriptors()) ||
	   !validateMetadataSearchRegistrations( registrations) || !inventory || !progress) {
		result.error = INVALID_ARGUMENT ;
		return result ;
	}

	const auto inventoryRegistration =
		std::find_if( registrations.begin(), registrations.end(), []( const auto &entry) {
			return entry.descriptor.id == DRIVER_STORE_PROVIDER_ID ;
		}) ; // 必須依存。
	// Registryにない別inventoryを暗黙に代用しない。
	if( inventoryRegistration == registrations.end()) {
		result.error = INTERNAL_ERROR ;
		return result ;
	}

	MetadataSearchSummary summary ;	// 全登録の終了理由を後で一度だけ公開する。
	summary.scanSessionId = session ;
	summary.request		  = request ;
	std::uint32_t lastPercent{} ;	// 確定段階だけから更新し、時間では増加させない。
	const auto	  notify = [&progress, &lastPercent]( ProviderProgress update) {
		   update.percentComplete = std::max( lastPercent, std::min( update.percentComplete, 100U)) ;
		   lastPercent			  = update.percentComplete ;
		   progress( update) ;
	} ; // Borrowした通知先はrun中だけ生存する。
	DeviceInventoryMeasurement inventoryMeasurement ;	// 同一現在属性列挙地点の根拠。
	ScanResult				   local ;					// 列挙が返した現在行だけを所有する。
	try {
		local = inventory(
			session, execution,
			[&notify]( ProviderProgress update) {
				update.percentComplete = std::min( update.percentComplete, 100U) * 20U / 100U ;
				notify( update) ;
			},
			inventoryMeasurement) ;
	} catch( ...) {
		// 例外時には公式Providerを開始せず、既知の消費と失敗を残す。
		local.scanSessionId = session ;
		local.purpose		= ScanPurpose::METADATA_ONLY ;
		local.outcome		= OutcomeCode::FAILURE ;
		local.state			= ProviderScanState::FAILURE ;
		local.error			= INTERNAL_ERROR ;
	}

	std::set<std::wstring> deviceIds ;	// 現在行だけを母数にする一意集合。
	// Inventory契約違反のデータから公式queryを作らない。
	if( !validRows( local, inventoryRegistration->descriptor, session, true, deviceIds)) {
		result.error = INTERNAL_ERROR ;
		return result ;
	}

	std::vector<OfficialCatalogDevice> devices ;	// Native IDと履歴を含まない現在snapshot。
	devices.reserve( local.candidates.size()) ;
	// Local現在行の表示属性だけを公式probe用に所有copyする。
	for( const UpdateCandidate &candidate : local.candidates) {
		deviceIds.insert( candidate.deviceIdentity) ;
		devices.push_back( {.deviceIdentity	  = candidate.deviceIdentity,
						   .model			  = candidate.model,
						   .manufacturer	  = candidate.manufacturer,
						   .driverClass		  = candidate.driverClass,
						   .deviceClassGuid	  = candidate.deviceClassGuid,
						   .currentProvider	  = candidate.provider,
						   .currentVersion	  = candidate.version,
						   .currentDate		  = candidate.driverDate,
						   .deviceObservation = candidate.deviceObservation}) ;
	}

	// 必須inventoryの元終端を、公式Provider成功数とは独立に保持する。
	const ProviderScanReport localReport = providerReport( inventoryRegistration->descriptor, local) ;
	result.candidates					 = std::move( local.candidates) ;
	summary.inventoryComplete			 = inventoryMeasurement.detailedEnumerationComplete ;
	std::vector<ProviderMeasurementEvidence> allEvidence ;	// T/Q/Rの一回限りの内部集合。
	std::size_t completedProviders{} ;						// 正常終端と個別失敗の処理済み数。
	std::size_t successfulProviders{} ;						// Local成功を含まない、正常な公式検索終端数。
	std::optional<MetadataSearchReason>
				firstFailure ;				// 全体停止がなければ最初の個別失敗を表示する。
	NativeError firstError = local.error ;	// 未完了の元診断を成功値で上書きしない。
	// 正常または部分の列挙が終端した段階だけを20%完了とする。
	if( local.succeeded && !execution.sessionStopped()) {
		notify( {.stage			 = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
				.percentComplete = 20U,
				.completedItems	 = 0U,
				.totalItems		 = request.enabledProviderIds.size()}) ;
	}

	// 正本registry順で全状態を作る。未選択はcallbackを呼ばず明示的に区別する。
	for( const MetadataSearchRegistration &registration : registrations) {
		const auto &descriptor = registration.descriptor ;	// 呼出し中だけ借用する固定登録。
		// Driver Storeは明示Provider集合と別の必須依存として一回だけ報告する。
		if( descriptor.id == DRIVER_STORE_PROVIDER_ID) {
			result.providerReports.push_back( localReport) ;
			summary.providers.push_back( {.providerId = descriptor.id,
										 .reason = local.succeeded ? MetadataSearchReason::COMPLETED
																   : MetadataSearchReason::FAILED,
										 .error	 = local.error}) ;
			continue ;
		}

		const bool selected =
			std::find( request.enabledProviderIds.begin(), request.enabledProviderIds.end(),
					  descriptor.id) != request.enabledProviderIds.end() ;	// 開始時に固定した選択。
		// 通常既定有効でも今回選択されていないProviderを実行しない。
		if( !selected) {
			result.providerReports.push_back( {.descriptor = descriptor}) ;
			summary.providers.push_back(
				{.providerId = descriptor.id, .reason = MetadataSearchReason::NOT_SELECTED}) ;
			continue ;
		}

		const NativeError stopError = execution.checkpoint() ;	// 各Provider開始前の全体停止確認。
		// Inventory開始失敗、取消し、全体予算停止では後続Providerへ進まない。
		if( !local.succeeded || stopError != 0) {
			result.providerReports.push_back( {.descriptor = descriptor,
											  .state	  = ProviderScanState::FAILURE,
											  .error   = stopError != 0 ? stopError : local.error,
											  .outcome = OutcomeCode::NOT_STARTED}) ;
			summary.providers.push_back( {.providerId = descriptor.id,
										 .reason	 = MetadataSearchReason::NOT_RUN_AFTER_STOP,
										 .error		 = stopError != 0 ? stopError : local.error}) ;
			continue ;
		}

		const NativeError beginError =
			// 個別予算と時刻を固定する。
			execution.beginProvider( descriptor.id) ;
		// 開始直前にも取消しを観測し、未開始を成功として数えない。
		if( beginError != 0) {
			result.providerReports.push_back( {.descriptor = descriptor,
											  .state	  = ProviderScanState::FAILURE,
											  .error	  = beginError,
											  .outcome	  = OutcomeCode::NOT_STARTED}) ;
			summary.providers.push_back( {.providerId = descriptor.id,
										 .reason	 = MetadataSearchReason::NOT_RUN_AFTER_STOP,
										 .error		 = beginError}) ;
			continue ;
		}

		ProviderMeasurementEvidence evidence ;	// Provider内の確定済みqueryとrecord根拠。
		ScanResult					child ;		// 異常時も前Providerの表示行を変更しない一時結果。
		try {
			child = registration.scan(
				session, devices, measurementContext.osKind == MeasurementOsKind::SERVER,
				measurementContext.osBuild.value_or( 0U), execution,
				[&notify, &completedProviders, &request]( ProviderProgress update) {
					update.percentComplete =
						20U +
						static_cast<std::uint32_t>(
							(completedProviders * 100U + std::min( update.percentComplete, 100U)) *
							70U / (request.enabledProviderIds.size() * 100U)) ;
					notify( update) ;
				},
				evidence) ;
		} catch( ...) {
			// 例外で未返却の途中行は公開せず、既存の総消費と前Provider行を保持する。
			child.scanSessionId = session ;
			child.purpose		= ScanPurpose::METADATA_ONLY ;
			child.outcome		= OutcomeCode::FAILURE ;
			child.state			= ProviderScanState::FAILURE ;
			child.error			= INTERNAL_ERROR ;
			evidence			= {} ;
		}

		// 取得・導入権限や発行元の混入は全体の結果契約違反として拒否する。
		if( !validRows( child, descriptor, session, false, deviceIds) ||
		   child.candidates.size() > MEASUREMENT_CANDIDATE_LIMIT - result.candidates.size()) {
			execution.finishProvider( MetadataSearchReason::FAILED, INTERNAL_ERROR) ;
			result.candidates.clear() ;
			result.providerReports.clear() ;
			result.error = INTERNAL_ERROR ;
			return result ;
		}

		const NativeError afterError = execution.checkpoint() ;	// Callback終端の停止を固定する。
		// 遅い同期callの成功を期限・取消し後の正常終端に変換しない。
		if( afterError != 0) {
			child.succeeded = false ;
			child.error		= afterError ;
			child.outcome	= execution.sessionStopReason() == MetadataSearchReason::CANCELLED
								  ? OutcomeCode::ABORTED
								  : OutcomeCode::FAILURE ;
		}

		const MetadataSearchReason reason =
			child.succeeded
				? (child.state == ProviderScanState::NOT_APPLICABLE
					   ? MetadataSearchReason::NOT_APPLICABLE
					   : MetadataSearchReason::COMPLETED)
				: MetadataSearchReason::FAILED ;	// 個別停止があればcontext側の主因を優先する。
		execution.finishProvider( reason, child.error) ;
		const MetadataProviderSummary providerSummary =
			// 確定済み消費と主因。
			execution.providers().back() ;
		summary.providers.push_back( providerSummary) ;
		result.providerReports.push_back( providerReport( descriptor, child)) ;
		// 正常終端数へlocal inventoryや未着手を含めない。
		if( child.succeeded) {
			++successfulProviders ;
		}
		// 前に観測した個別停止理由を後続失敗で上書きしない。
		else if( !firstFailure) {
			firstFailure = providerSummary.reason ;
			firstError	 = providerSummary.error ;
		}

		// 空の未接続計測を0件として補完せず、存在する同session根拠だけを集約する。
		if( !evidence.providerId.empty()) {
			allEvidence.push_back( std::move( evidence)) ;
		}

		// 個々の専用callbackが停止前にcommitした所有行だけを保持する。
		for( UpdateCandidate &candidate : child.candidates) {
			result.candidates.push_back( std::move( candidate)) ;
		}

		// 全体取消しでは未処理の残りを完了扱いにして進捗を増やさない。
		if( !execution.sessionStopped()) {
			++completedProviders ;
			notify( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
					.percentComplete =
						20U + static_cast<std::uint32_t>( completedProviders * 70U /
														 request.enabledProviderIds.size()),
					.completedItems = completedProviders,
					.totalItems		= request.enabledProviderIds.size()}) ;
		}
	}

	summary.reason = execution.sessionStopReason().value_or(
		!local.succeeded ? MetadataSearchReason::FAILED
						 : firstFailure.value_or( MetadataSearchReason::COMPLETED)) ;
	// 取消しは成功flagと別の正規終端として部分情報を保持する。
	if( summary.reason == MetadataSearchReason::CANCELLED) {
		result.outcome = OutcomeCode::ABORTED ;
	}
	// Local inventoryだけの成功を公式検索成功と表示しない。
	else if( successfulProviders == 0U) {
		result.outcome = OutcomeCode::FAILURE ;
	}
	// 全選択検索とinventoryが正常に完了した場合だけ全体成功にする。
	else if( successfulProviders == request.enabledProviderIds.size() && summary.inventoryComplete &&
			summary.reason == MetadataSearchReason::COMPLETED) {
		result.outcome = OutcomeCode::SUCCESS ;
	} else {
		result.outcome = OutcomeCode::SUCCEEDED_WITH_ERRORS ;
	}

	result.succeeded = result.outcome == OutcomeCode::SUCCESS ||
					   result.outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS ;
	result.state = result.succeeded
					   ? (result.candidates.empty() ? ProviderScanState::NO_CANDIDATES
													: ProviderScanState::CANDIDATES_AVAILABLE)
					   : ProviderScanState::FAILURE ;
	result.error = execution.sessionStopped() ? execution.checkpoint() : firstError ;
	measurementContext.scanSessionId		= session ;
	measurementContext.purpose				= ScanPurpose::METADATA_ONLY ;
	measurementContext.usedDefaultProviders = false ;
	measurementContext.enabledProviderIds	= request.enabledProviderIds ;
	measurementContext.enabledProviderIds.emplace_back( DRIVER_STORE_PROVIDER_ID) ;
	const auto unixSeconds = std::chrono::duration_cast<std::chrono::seconds>(
								 std::chrono::system_clock::now().time_since_epoch())
								 .count() ;	// 公開準備時の実UTC。
	// Epochより前の時刻を巨大な符号なし時刻へ変換しない。
	if( unixSeconds >= 0) {
		measurementContext.completedUtcSeconds = static_cast<std::uint64_t>( unixSeconds) ;
	}

	auto measured = aggregateScanMeasurement( measurementContext, result.candidates,
											 builtInProviderDescriptors(), inventoryMeasurement,
											 allEvidence, {}) ;	// 取得routingは常に空。
	// 部分的な集計不整合を有効reportへ混ぜない。表示自体の扱いはWorkerが拒否する。
	if( !measured) {
		result.candidates.clear() ;
		result.providerReports.clear() ;
		result.succeeded = false ;
		result.outcome	 = OutcomeCode::FAILURE ;
		result.error	 = INTERNAL_ERROR ;
		return result ;
	}

	result.measurement	 = std::move( measured->snapshot) ;
	result.localCoverage = std::move( measured->localCoverage) ;
	// 順序を仮定せず各Providerへ同じIDの集計を戻す。
	for( ProviderScanReport &report : result.providerReports) {
		const auto entry = std::find_if( measured->providers.begin(), measured->providers.end(),
										[&report]( const auto &value) {
											return value.providerId == report.descriptor.id ;
										}) ; // 一意な集計。
		// 集計対象の欠落は空計測として隠さず全体契約を拒否する。
		if( entry == measured->providers.end()) {
			result.candidates.clear() ;
			result.providerReports.clear() ;
			result.measurement.reset() ;
			result.succeeded = false ;
			result.outcome	 = OutcomeCode::FAILURE ;
			result.error	 = INTERNAL_ERROR ;
			return result ;
		}

		report.coverage.measurement = entry->measurement ;
	}

	summary.usage				= execution.usage() ;
	summary.elapsedMilliseconds = execution.elapsedMilliseconds() ;
	result.metadataSearch		= std::move( summary) ;
	// 実際に終えた結果検証の10%だけを足し、未実施Provider分は補完しない。
	notify( {.stage			 = ProviderStage::MERGING_CANDIDATES,
			.percentComplete = std::min( 100U, lastPercent + 10U),
			.completedItems	 = completedProviders,
			.totalItems		 = request.enabledProviderIds.size()}) ;
	return result ;
}

} // namespace drivercrate
