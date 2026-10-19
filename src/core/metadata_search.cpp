//------------------------------------------------------------------------------
/**
 * @file metadata_search.cpp
 * @brief 情報検索の許可集合と表示専用性の検証実装。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  Metadata専用検索の契約を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  観測と候補詳細の非取得用途・session結合を検証。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  十Provider用の結果予算を検証。
 * Ver.01.02.01 Shunji Ogawa  2026/09/15  自動探索capabilityを既知bitとして受理。
 * </pre>
 *
 * @see docs/adr/0153-intel-ethernet-windows11-provider-integration.md
 */
//------------------------------------------------------------------------------

#include "core/metadata_search.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "core/candidate_audit.h"
#include "core/candidate_selection.h"
#include "core/scan_measurement.h"

#include <algorithm>
#include <cstddef>
#include <set>

namespace drivercrate {

/** @see metadata_search.h */
bool isMetadataSearchProvider( const ProviderDescriptor &descriptor) noexcept
{
	// 未知bitや混合trust boundaryを専用検索能力として受理しない。
	const auto required = capabilityMask( ProviderCapability::SCAN) |
						  capabilityMask( ProviderCapability::OFFICIAL_NETWORK) |
						  capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) ;
	// 単一の公式境界と専用能力がそろわない登録は検索入口にしない。
	if( (descriptor.capabilities & ~0x3FFU) != 0U ||
	   (descriptor.capabilities & required) != required ||
	   (descriptor.capabilities & 0xF0U) != capabilityMask( ProviderCapability::OFFICIAL_NETWORK)) {
		return false ;
	}

	const auto *policy = officialSourcePolicyForProvider( descriptor.id) ;	// 固定公式起点の正本。
	return policy != nullptr && descriptor.officialSourcePolicyId == policy->id ;
}

/** @see metadata_search.h */
bool validateMetadataSearchRequest( const MetadataSearchRequest				&request,
								   const std::span<const ProviderDescriptor> descriptors) noexcept
{
	// 任意policyや空集合、過大な入力は列挙・通信より前に拒否する。
	if( request.policyId != METADATA_SEARCH_POLICY_ID ||
	   request.policyRevision != METADATA_SEARCH_POLICY_REVISION ||
	   request.enabledProviderIds.empty() ||
	   request.enabledProviderIds.size() > METADATA_SEARCH_PROVIDER_LIMIT || descriptors.empty() ||
	   descriptors.size() > METADATA_SEARCH_PROVIDER_LIMIT) {
		return false ;
	}

	// Registryの重複を検索順依存の権限判定へ変えない。
	for( std::size_t index = 0; index < descriptors.size(); ++index) {
		const auto &descriptor = descriptors[index] ;	// 現在検証する登録定義。
		// 空IDや重複IDを走査順だけで一つへ解決しない。
		if( descriptor.id.empty() ||
		   std::count_if( descriptors.begin(), descriptors.end(), [&descriptor]( const auto &item) {
			   return item.id == descriptor.id ;
		   }) != 1) {
			return false ;
		}
	}

	// 明示IDごとに一意な専用callback能力を要求する。
	for( const auto &id : request.enabledProviderIds) {
		const auto found =
			std::find_if( descriptors.begin(), descriptors.end(), [&id]( const auto &item) {
				return item.id == id ;
			}) ; // ID完全一致の登録位置。
		// 未登録・未対応・重複選択では通常scanへ代替しない。
		if( found == descriptors.end() || !isMetadataSearchProvider( *found) ||
		   std::count( request.enabledProviderIds.begin(), request.enabledProviderIds.end(), id) !=
			   1) {
			return false ;
		}
	}

	return true ;
}

/** @see metadata_search.h */
bool hasOnlyMetadataDisplayCandidates( const ScanResult &result) noexcept
{
	// Purposeを既定値から推測せず専用結果だけを受理する。
	if( result.purpose != ScanPurpose::METADATA_ONLY || result.scanSessionId == 0U ||
	   !isCandidateDetailsSetValid( result.candidates, result.scanSessionId)) {
		return false ;
	}

	// UIの一括選択でも権限が復活しない候補だけを受理する。
	for( const auto &candidate : result.candidates) {
		// 行に混入した取得・導入・既定選択の権限を一つでも拒否する。
		if( candidate.installable || candidate.recommended ||
		   candidate.action != DriverAction::NONE || !candidate.packageIdentity.empty() ||
		   candidate.defaultPreference != CandidateDefaultPreference::NONE ||
		   candidate.eulaAccepted || candidate.allContentCached ||
		   candidate.releaseObservationDifference) {
			return false ;
		}

		// 配布版を現在INF版へ混入せず、未知の許諾enumを同意不要として表示しない。
		if( (!candidate.current && !candidate.version.empty()) ||
		   (candidate.metadataDistribution &&
			(candidate.current || candidate.metadataDistribution->version.size() > 256U ||
			 (candidate.metadataDistribution->license != MetadataLicenseStatus::UNRESOLVED &&
			  candidate.metadataDistribution->license !=
				  MetadataLicenseStatus::ACCEPTANCE_BEFORE_DOWNLOAD &&
			  candidate.metadataDistribution->license !=
				  MetadataLicenseStatus::CONFIRMED_NO_CONSENT)))) {
			return false ;
		}
	}

	return true ;
}

/** @see metadata_search.h */
bool isMetadataSearchResultValid( const OperationId			  operationId,
								 const MetadataSearchRequest &request,
								 const ScanResult			 &result) noexcept
{
	try {
		const auto descriptors = builtInProviderDescriptors() ;	// 公開時点の登録正本。
		// 欠けたsummaryや通常結果を部分的な情報検索成功として公開しない。
		if( operationId == 0U || !validateMetadataSearchRequest( request, descriptors) ||
		   !hasOnlyMetadataDisplayCandidates( result) || !result.metadataSearch ||
		   !result.measurement || result.providerReports.size() != descriptors.size() ||
		   result.candidates.size() > MEASUREMENT_CANDIDATE_LIMIT ||
		   !isPublishedScanMeasurementValid( operationId, result)) {
			return false ;
		}

		const auto &summary	 = *result.metadataSearch ;	// Workerへ渡した条件と照合する所有値。
		const auto &measured = *result.measurement ;	// 同一snapshotの段階別計測。
		// 通常既定集合や別操作の同意を今回のrequestへ読み替えない。
		if( summary.operationId != operationId || summary.scanSessionId != result.scanSessionId ||
		   summary.request != request || summary.providers.size() != descriptors.size() ||
		   summary.inventoryComplete != measured.inventory.detailedEnumerationComplete ||
		   measured.context.usedDefaultProviders ||
		   measured.context.enabledProviderIds.size() != request.enabledProviderIds.size() + 1U ||
		   summary.reason < MetadataSearchReason::COMPLETED ||
		   summary.reason > MetadataSearchReason::NETWORK_NOT_APPROVED ||
		   summary.reason == MetadataSearchReason::NOT_SELECTED ||
		   summary.reason == MetadataSearchReason::NOT_APPLICABLE ||
		   result.succeeded != (result.outcome == OutcomeCode::SUCCESS ||
								result.outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS) ||
		   (result.outcome != OutcomeCode::SUCCESS &&
			result.outcome != OutcomeCode::SUCCEEDED_WITH_ERRORS &&
			result.outcome != OutcomeCode::FAILURE && result.outcome != OutcomeCode::ABORTED) ||
		   (summary.reason == MetadataSearchReason::CANCELLED) !=
			   (result.outcome == OutcomeCode::ABORTED)) {
			return false ;
		}

		// A/Iは0件ではなく未測定であることを検査する。
		const auto unmeasured = []( const StageDeviceCounts &counts) {
			return counts.applicableUpdateDeviceCount.extent == MeasurementExtent::NOT_MEASURED &&
				   !counts.applicableUpdateDeviceCount.value &&
				   counts.installReadyUpdateDeviceCount.extent == MeasurementExtent::NOT_MEASURED &&
				   !counts.installReadyUpdateDeviceCount.value ;
		} ; // 所有状態を捕捉しない純粋検査。
		// 情報検索で適用性または導入準備の実績を生成させない。
		if( !unmeasured( measured.network.combined) || !unmeasured( measured.network.official)) {
			return false ;
		}

		MetadataSearchUsage			total ;					// 有界な個別消費だけを合計する。
		std::size_t					successfulProviders{} ;	// Inventoryを含まない正常な公式終端数。
		std::set<std::wstring_view> identities ;			// 全Provider間でも候補IDを一意にする。
		std::set<std::wstring_view> devices ;				// Current行から再構築する結合先。
		// 現在行のProvider偽装と重複を拒否する。
		for( const auto &candidate : result.candidates) {
			// Display identityの欠落・過大入力から参照先を推測しない。
			if( candidate.identity.empty() || candidate.identity.size() > 256U ||
			   candidate.deviceIdentity.empty() || candidate.deviceIdentity.size() > 256U ||
			   !identities.insert( candidate.identity).second ||
			   (candidate.current && (candidate.providerId != DRIVER_STORE_PROVIDER_ID ||
									  !devices.insert( candidate.deviceIdentity).second))) {
				return false ;
			}
		}

		// Registry順にIDで索引し、結果順の違いを許しつつ欠落・重複を拒否する。
		for( const auto &descriptor : descriptors) {
			// 正本IDへ対応するProvider元結果の借用索引。
			const auto report = std::find_if(
				result.providerReports.begin(), result.providerReports.end(),
				[&descriptor]( const auto &value) { return value.descriptor.id == descriptor.id ; }) ;
			// 同じ発行元の消費・停止理由だけを照合する借用索引。
			const auto detail = std::find_if(
				summary.providers.begin(), summary.providers.end(),
				[&descriptor]( const auto &value) { return value.providerId == descriptor.id ; }) ;
			// 全29登録に一対一で拘束されたsnapshotだけを公開する。
			if( report == result.providerReports.end() || detail == summary.providers.end() ||
			   std::count_if( summary.providers.begin(), summary.providers.end(),
							 [&descriptor]( const auto &value) {
								 return value.providerId == descriptor.id ;
							 }) != 1) {
				return false ;
			}

			const auto &actual	  = report->descriptor ;						// 固定policyを含む元の発行元。
			const bool	inventory = descriptor.id == DRIVER_STORE_PROVIDER_ID ;	// 必須依存。
			// 開始時の明示集合に所属する登録だけが公式callbackを実行できる。
			const bool	selected =
				std::find( request.enabledProviderIds.begin(), request.enabledProviderIds.end(),
						  descriptor.id) != request.enabledProviderIds.end() ;
			// 表示名・能力・tier・policyも正本と一致させ、未知bitを許さない。
			if( actual.id != descriptor.id || actual.displayName != descriptor.displayName ||
			   actual.capabilities != descriptor.capabilities ||
			   actual.selectionTier != descriptor.selectionTier ||
			   actual.discoveryBasis != descriptor.discoveryBasis ||
			   actual.installNotice != descriptor.installNotice ||
			   actual.enabledByDefault != descriptor.enabledByDefault ||
			   actual.officialSourcePolicyId != descriptor.officialSourcePolicyId ||
			   detail->reason < MetadataSearchReason::COMPLETED ||
			   detail->reason > MetadataSearchReason::NOT_RUN_AFTER_STOP ||
			   detail->error != report->error || !isValidProviderCoverage( report->coverage) ||
			   (report->state != ProviderScanState::DISABLED) != (selected || inventory)) {
				return false ;
			}

			const auto &usage = detail->usage ;	// 個別固定上限以下の実消費。
			// Probeは本文と別に数え、開始resource数より多くできない。
			if( usage.bodyBytes > 4ULL * 1024ULL * 1024ULL || usage.logicalResources > 2U ||
			   usage.httpAttempts > 12U || usage.probeBytes > usage.logicalResources ||
			   (usage.logicalResources == 0U &&
				(usage.bodyBytes != 0U || usage.httpAttempts != 0U)) ||
			   ((!selected || detail->reason == MetadataSearchReason::NOT_RUN_AFTER_STOP) &&
				usage != MetadataSearchUsage{}) ||
			   report->coverage.measurement->resources.size() > usage.logicalResources ||
			   (selected && !unmeasured( report->coverage.measurement->devices))) {
				return false ;
			}

			total.bodyBytes += usage.bodyBytes ;
			total.probeBytes += usage.probeBytes ;
			total.logicalResources += usage.logicalResources ;
			total.httpAttempts += usage.httpAttempts ;
			const bool normal = detail->reason == MetadataSearchReason::COMPLETED ||
								// 正常な検索終端。
								detail->reason == MetadataSearchReason::NOT_APPLICABLE ;
			const bool successful = report->outcome == OutcomeCode::SUCCESS ||
									// Provider元の終端。
									report->outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS ;
			// 未選択、未実施、失敗を候補0の正常終了へ変換しない。
			if( (!selected && !inventory &&
				(detail->reason != MetadataSearchReason::NOT_SELECTED ||
				 report->outcome != OutcomeCode::NOT_STARTED || report->error != 0)) ||
			   ((selected || inventory) && detail->reason == MetadataSearchReason::NOT_SELECTED) ||
			   (normal &&
				(!successful || (report->error != 0 && report->outcome == OutcomeCode::SUCCESS))) ||
			   (selected && normal && !unmeasured( report->coverage.measurement->devices)) ||
			   (selected && !normal && successful) ||
			   (detail->reason == MetadataSearchReason::NOT_RUN_AFTER_STOP &&
				report->outcome != OutcomeCode::NOT_STARTED)) {
				return false ;
			}

			successfulProviders += static_cast<std::size_t>( selected && normal) ;
			std::set<std::wstring_view> bound ;				// 同一Providerの一device一情報行。
			std::size_t					candidateCount{} ;	// 申告件数を全行から再検証する。
			// 当該Providerの行だけを監査・結合先へ照合する。
			for( const auto &candidate : result.candidates) {
				// 他Providerの行はその登録を処理するときに検証する。
				if( candidate.providerId != descriptor.id) {
					continue ;
				}

				++candidateCount ;
				// 未選択source、現在行偽装、未結合node、監査矛盾を公開しない。
				if( (!selected && !inventory) || candidate.current != inventory ||
				   !devices.contains( candidate.deviceIdentity) ||
				   !bound.insert( candidate.deviceIdentity).second ||
				   !isCandidateAuditValid( candidate, descriptor) ||
				   !isCandidateDefaultPreferenceValid( candidate, descriptor)) {
					return false ;
				}
			}

			// Report件数を非機密な実行件数の正本として偽装させない。
			if( candidateCount != report->candidateCount) {
				return false ;
			}
		}

		// 未登録発行元の行を全report走査の外へ残さない。
		if( std::any_of( result.candidates.begin(), result.candidates.end(),
					   [&descriptors]( const auto &candidate) {
						   return std::none_of( descriptors.begin(), descriptors.end(),
											   [&candidate]( const auto &descriptor) {
												   return candidate.providerId == descriptor.id ;
											   }) ;
					   }) ||
		   total != summary.usage || total.bodyBytes > 32ULL * 1024ULL * 1024ULL ||
		   total.logicalResources > 20U || total.httpAttempts > 120U ||
		   (result.outcome == OutcomeCode::SUCCESS &&
			(!summary.inventoryComplete || summary.reason != MetadataSearchReason::COMPLETED ||
			 successfulProviders != request.enabledProviderIds.size())) ||
		   (result.outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS && successfulProviders == 0U)) {
			return false ;
		}

		return true ;
	} catch( ...) {
		// 一時索引の確保失敗でも部分的な権限・reportを公開しない。
		return false ;
	}
}

} // namespace drivercrate
