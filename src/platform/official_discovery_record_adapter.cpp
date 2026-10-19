//------------------------------------------------------------------------------
/**
 * @file official_discovery_record_adapter.cpp
 * @brief 公式自動探索の固定root解決、失敗保持、秘密record sessionを実装する。
 * @version 01.02.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  固定root adapterと秘密record sessionを実装。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  検査用取得対象とEULA snapshot生成を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  通常scanの表示専用payload descriptor生成を追加。
 * </pre>
 *
 * @note 固定endpointは組み込みsource policyから実行直前に取得し、route、UI、log、cacheへ複製しない。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#include "platform/official_discovery_record_adapter.h"

#include "core/official_source_policy.h"

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

// 一scanで保持する秘密recordの固定上限。
constexpr std::size_t	  MAXIMUM_RETAINED_RECORDS = OFFICIAL_DISCOVERY_ROUTE_LIMIT ;
// 既存取得準備契約が許可するopaque identityの最大文字数。
constexpr std::size_t	  MAXIMUM_PREPARATION_ID_CHARACTERS = 128U ;
// 入力契約またはcallback結果の不整合を表す診断値。
constexpr NativeError	  INVALID_ARGUMENT = static_cast<NativeError>( E_INVALIDARG) ;
// Allocation失敗を表す診断値。
constexpr NativeError	  OUT_OF_MEMORY = static_cast<NativeError>( E_OUTOFMEMORY) ;
// 型不明例外を情報漏洩なしで表す診断値。
constexpr NativeError	  UNEXPECTED_FAILURE = static_cast<NativeError>( E_FAIL) ;

/**
 * @brief Win32 errorをHRESULT bit patternへ変換する。
 * @param[in] error 変換するWin32 error code。
 * @return NativeErrorで保持するHRESULT bit pattern。
 */
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

/**
 * @brief 固定root resolver結果の状態と診断値が矛盾しないか確認する。
 * @param[in] result Provider adapterが返した有限結果。
 * @return 解決・空・取消しは診断0、三失敗は非0の場合true。
 */
[[nodiscard]] bool isFixedRootResultValid( const OfficialDiscoveryFixedRootResult &result) noexcept
{
	// 診断を要求する三つの失敗状態ならtrue。
	const bool diagnosticState = result.state == OfficialDiscoveryFixedRootState::FAILED ||
								 result.state == OfficialDiscoveryFixedRootState::SOURCE_REJECTED ||
								 result.state == OfficialDiscoveryFixedRootState::METADATA_REJECTED ;
	// 未開始や未知enumを正常終了へ補完せず拒否する。
	if( result.state < OfficialDiscoveryFixedRootState::RESOLVED ||
	   result.state > OfficialDiscoveryFixedRootState::METADATA_REJECTED) {
		return false ;
	}

	return diagnosticState == (result.error != 0) ;
}

/**
 * @brief Adapterの固定Provider、policy、root、endpointを検証する。
 * @param[in] adapter 検証する一adapter。
 * @param[in] route 同じ実行単位のroute。
 * @return 組み込みsource policyと完全一致する場合true。
 */
[[nodiscard]] bool hasBoundFixedRoot( const OfficialDiscoveryFixedRootAdapter &adapter,
									 const OfficialDiscoveryRoute			 &route) noexcept
{
	// Routeとは異なるProvider、root、種別をadapterから補完しない。
	if( adapter.providerId != route.providerId || adapter.rootResourceId != route.rootResourceId ||
	   adapter.kind != route.kind || adapter.maximumRecordBytes == 0U ||
	   adapter.maximumRecordBytes > OFFICIAL_DISCOVERY_RECORD_BYTES_LIMIT || !adapter.resolver) {
		return false ;
	}

	const OfficialSourcePolicy *const policy =
		// Providerへ結合した組み込みsource policy。
		officialSourcePolicyForProvider( adapter.providerId) ;
	const OfficialSourceResourcePolicy *const resource =
		policy == nullptr
			? nullptr
			: findOfficialSourceResource( *policy, adapter.rootResourceId) ;	// 固定root用途。
	// Landing／metadata用途と固定endpointを持たないadapterを実行しない。
	return policy != nullptr && resource != nullptr &&
		   (resource->kind == OfficialSourceResourceKind::LANDING_PAGE ||
			resource->kind == OfficialSourceResourceKind::METADATA) &&
		   !officialMetadataEndpoint( adapter.providerId, adapter.rootResourceId).empty() ;
}

/**
 * @brief Resolverが返したroot evidenceをrouteと今回の証拠IDへ完全一致させる。
 * @param[in] record 秘密URLを所有するresolver結果。
 * @param[in] route 実行した固定root route。
 * @param[in] scanSessionId 現在のscan session ID。
 * @param[in] recordEvidenceId 今回割り当てた証拠ID。
 * @return 組み込みsource evidenceと全identityが一致する場合true。
 */
[[nodiscard]] bool hasBoundSourceEvidence( const OfficialDistributionRecord &record,
										  const OfficialDiscoveryRoute	   &route,
										  const ScanSessionId				scanSessionId,
										  const std::uint64_t recordEvidenceId) noexcept
{
	const OfficialSourcePolicy *const policy =
		// Route Providerの組み込みpolicy。
		officialSourcePolicyForProvider( route.providerId) ;
	// Source evidence自体とrouteへの全結合が成立する場合だけ後続metadata検証へ進める。
	return policy != nullptr && isValidOfficialSourceEvidence( record.rootEvidence) &&
		   record.recordEvidenceId == recordEvidenceId &&
		   record.rootEvidence.scanSessionId == scanSessionId &&
		   record.rootEvidence.providerId == route.providerId &&
		   record.rootEvidence.policyId == policy->id &&
		   record.rootEvidence.resourceId == route.rootResourceId ;
}

/**
 * @brief Callbackの有限状態を公開route状態へ一対一で変換する。
 * @param[in] state 検証済みの固定root状態。
 * @return 同じ理由を保持する公開route状態。
 */
[[nodiscard]] OfficialDiscoveryRouteState routeStateFromFixedRoot(
	const OfficialDiscoveryFixedRootState state) noexcept
{
	// Resolverが明示した非成功理由を縮退させず変換する。
	switch( state) {
		// 正常なrecordなしを保持する。
		case OfficialDiscoveryFixedRootState::NO_RECORD:
			return OfficialDiscoveryRouteState::NO_RECORD ;
		// 協調取消しを保持する。
		case OfficialDiscoveryFixedRootState::CANCELLED:
			return OfficialDiscoveryRouteState::CANCELLED ;
		// 通常失敗を保持する。
		case OfficialDiscoveryFixedRootState::FAILED:
			return OfficialDiscoveryRouteState::FAILED ;
		// Source拒否を保持する。
		case OfficialDiscoveryFixedRootState::SOURCE_REJECTED:
			return OfficialDiscoveryRouteState::SOURCE_REJECTED ;
		// Metadata拒否を保持する。
		case OfficialDiscoveryFixedRootState::METADATA_REJECTED:
			return OfficialDiscoveryRouteState::METADATA_REJECTED ;
		// 解決済み状態はroute種別を必要とするため呼出側で処理する。
		case OfficialDiscoveryFixedRootState::RESOLVED:
			return OfficialDiscoveryRouteState::METADATA_REJECTED ;
		// 未開始状態はresolverの終端結果として許可しない。
		case OfficialDiscoveryFixedRootState::NOT_STARTED:
			return OfficialDiscoveryRouteState::METADATA_REJECTED ;
		// 定義外enumもmetadata拒否へ閉じる。
		default:
			return OfficialDiscoveryRouteState::METADATA_REJECTED ;
	}
}

/**
 * @brief Route identityを保持した初期summaryを作る。
 * @param[in] route 元route。
 * @return Device件数を安全に保持した未開始summary。
 */
[[nodiscard]] OfficialDiscoveryRouteSummary makeInitialSummary(
	const OfficialDiscoveryRoute &route) noexcept
{
	OfficialDiscoveryRouteSummary summary ;	// 全終端状態で共通のroute identity。
	summary.routeId	   = route.routeId ;
	summary.providerId = route.providerId ;
	summary.kind	   = route.kind ;
	// Core上限内のrouteだけが呼ばれるが、変換前にも型上限を守る。
	if( route.deviceIdentities.size() <= std::numeric_limits<std::uint32_t>::max()) {
		summary.deviceCount = static_cast<std::uint32_t>( route.deviceIdentities.size()) ;
	}

	return summary ;
}

/**
 * @brief 一payload descriptorがpackage groupの不変fieldへ完全一致するか確認する。
 * @param[in] descriptor 保持recordから再生成したURL非保持payload descriptor。
 * @param[in] group 既存の重複排除済みpackage group。
 * @return Session、Provider、policy、root、fingerprint、payload順が一致する場合true。
 */
[[nodiscard]] bool isDescriptorBoundToGroup( const OfficialRecordPayloadDescriptor &descriptor,
											const OfficialDiscoveryPackageGroup	  &group) noexcept
{
	return descriptor.providerId == group.providerId && descriptor.policyId == group.policyId &&
		   descriptor.rootResourceId == group.rootResourceId &&
		   descriptor.recordFingerprint.bytes == group.recordFingerprint.bytes &&
		   descriptor.payloadCount == group.payloadCount &&
		   descriptor.payloadOrdinal == group.payloadOrdinal ;
}

/**
 * @brief Recordの利用条件を既存取得準備の有限区分へ変換する。
 * @param[in] terms 検証済み公式recordの利用条件。
 * @param[out] result 対応する既存取得準備の利用条件。
 * @return 既知の二分類を変換できた場合true。
 */
[[nodiscard]] bool convertPreparationTerms( const OfficialDistributionTerms terms,
										   OfficialPreparationTerms		  &result) noexcept
{
	// Download前同意不要は同じ意味の準備区分へ変換する。
	if( terms == OfficialDistributionTerms::CONFIRMED_NO_CONSENT) {
		result = OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
		return true ;
	}

	// 固定revisionと全文への同意必須は同じ意味の準備区分へ変換する。
	if( terms == OfficialDistributionTerms::ACCEPTANCE_REQUIRED) {
		result = OfficialPreparationTerms::ACCEPTANCE_REQUIRED ;
		return true ;
	}

	return false ;
}

} // namespace

/** @see official_discovery_record_adapter.h */
bool validateOfficialDiscoveryFixedRootAdapter(
	const OfficialDiscoveryFixedRootAdapter &adapter, const OfficialDiscoveryRoute &route,
	const std::span<const OfficialDiscoveryDeviceHint> devices,
	const std::span<const ProviderDescriptor>		   descriptors) noexcept
{
	return validateOfficialDiscoveryRoute( route, devices, descriptors) &&
		   hasBoundFixedRoot( adapter, route) ;
}

/** @see official_discovery_record_adapter.h */
NativeError OfficialDiscoveryRecordAdapterSession::beginSession(
	const OfficialDiscoveryBinding &binding, const OfficialDiscoveryRequest &request,
	const std::span<const ProviderDescriptor> descriptors) noexcept
{
	// 不正要求、0、再使用、逆行IDで現在sessionを置き換えない。
	if( !isOfficialDiscoveryBindingValid( binding) ||
	   !validateOfficialDiscoveryRequest( request, descriptors) ||
	   binding.operationId <= latestOperationId_ || binding.scanSessionId <= latestSessionId_) {
		return nativeErrorFromWin32( ERROR_REVISION_MISMATCH) ;
	}

	try {
		std::vector<ProviderDescriptor> providerDescriptors(
			// 開始時registryの所有copy。
			descriptors.begin(), descriptors.end()) ;
		providerDescriptors_ = std::move( providerDescriptors) ;
		request_			 = request ;
		packages_.clear() ;
		packages_.reserve( OFFICIAL_DISCOVERY_PACKAGE_REFERENCE_LIMIT) ;
		records_.clear() ;
		records_.reserve( MAXIMUM_RETAINED_RECORDS) ;
		resolvedRouteIds_.clear() ;
		resolvedRouteIds_.reserve( OFFICIAL_DISCOVERY_ROUTE_LIMIT) ;
		binding_			  = binding ;
		latestOperationId_	  = binding.operationId ;
		latestSessionId_	  = binding.scanSessionId ;
		nextRecordEvidenceId_ = 1U ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		// 新sessionの領域不足時は旧秘密recordも公開せず全体を失効させる。
		invalidate() ;
		return OUT_OF_MEMORY ;
	} catch( ...) {
		// Registry copyの未知例外をworker thread外へ漏らさない。
		invalidate() ;
		return UNEXPECTED_FAILURE ;
	}
}

/** @see official_discovery_record_adapter.h */
OfficialDiscoveryRouteSummary OfficialDiscoveryRecordAdapterSession::resolveRoute(
	const OfficialDiscoveryRequest &request, const OfficialDiscoveryRoute &route,
	const std::span<const OfficialDiscoveryDeviceHint> devices,
	const OfficialDiscoveryFixedRootAdapter			  &adapter,
	const OfficialRecordResolutionCancellation		  &cancellation) noexcept
{
	OfficialDiscoveryRouteSummary summary = makeInitialSummary( route) ;	// URL非保持の終端結果。
	// Session、request、route、adapter、取消し境界をresolver呼出し前に全て照合する。
	if( !isOfficialDiscoveryBindingValid( binding_) || request != request_ ||
	   !validateOfficialDiscoveryFixedRootAdapter( adapter, route, devices, providerDescriptors_) ||
	   !cancellation || records_.size() >= MAXIMUM_RETAINED_RECORDS ||
	   nextRecordEvidenceId_ == std::numeric_limits<std::uint64_t>::max()) {
		summary.state = OfficialDiscoveryRouteState::METADATA_REJECTED ;
		summary.error = INVALID_ARGUMENT ;
		return summary ;
	}

	try {
		// 同じroute IDは成功・空・失敗を問わず一sessionで一度だけ実行する。
		if( !resolvedRouteIds_.insert( route.routeId).second) {
			summary.state = OfficialDiscoveryRouteState::METADATA_REJECTED ;
			summary.error = nativeErrorFromWin32( ERROR_ALREADY_EXISTS) ;
			return summary ;
		}

		// Resolver開始前の取消しでは固定rootを一度も渡さない。
		if( cancellation()) {
			summary.state = OfficialDiscoveryRouteState::CANCELLED ;
			return summary ;
		}

		const std::uint64_t		recordEvidenceId = nextRecordEvidenceId_++ ;	// 今回だけの証拠ID。
		const std::wstring_view builtInRootUrl =
			// 組み込み正本から実行時に借用する固定endpoint。
			officialMetadataEndpoint( adapter.providerId, adapter.rootResourceId) ;
		OfficialDistributionRecord			   record ;	// Resolverが設定する秘密URL所有record。
		// 固定rootだけをProvider固有parserへ渡した終端結果。
		const OfficialDiscoveryFixedRootResult result =
			adapter.resolver( binding_.scanSessionId, recordEvidenceId, adapter.providerId,
							 adapter.rootResourceId, builtInRootUrl, adapter.maximumRecordBytes,
							 OfficialRecordFetchMode::BYPASS_CACHE, record) ;
		// 未知状態または診断値の矛盾をProvider成功として扱わない。
		if( !isFixedRootResultValid( result)) {
			summary.state = OfficialDiscoveryRouteState::METADATA_REJECTED ;
			summary.error = INVALID_ARGUMENT ;
			return summary ;
		}

		// Resolver後の取消しでは受け取った秘密recordを保持しない。
		if( cancellation()) {
			summary.state = OfficialDiscoveryRouteState::CANCELLED ;
			return summary ;
		}

		// 空または失敗結果は理由と診断だけを保持し、record本文を公開しない。
		if( result.state != OfficialDiscoveryFixedRootState::RESOLVED) {
			summary.state = routeStateFromFixedRoot( result.state) ;
			summary.error = result.error ;
			return summary ;
		}

		// Root取得証拠の差替えはmetadata拒否と混ぜずsource拒否にする。
		if( !hasBoundSourceEvidence( record, route, binding_.scanSessionId, recordEvidenceId)) {
			summary.state = OfficialDiscoveryRouteState::SOURCE_REJECTED ;
			summary.error = nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
			return summary ;
		}

		OfficialDistributionRecordEvidence evidence ;	// URL非保持の共通record証拠。
		const NativeError				   validationError =
			// Stable fingerprintを含むrecord全体検証。
			validateOfficialDistributionRecord( record, evidence) ;
		// Schema、payload、EULA等の不正recordをsessionへ保持しない。
		if( validationError != 0 || evidence.recordEvidenceId != recordEvidenceId ||
		   evidence.rootEvidence.providerId != route.providerId ||
		   evidence.rootEvidence.resourceId != route.rootResourceId) {
			summary.state = OfficialDiscoveryRouteState::METADATA_REJECTED ;
			summary.error = validationError != 0 ? validationError : INVALID_ARGUMENT ;
			return summary ;
		}

		std::vector<OfficialRecordPayloadDescriptor> payloads ;	// URL非保持の全payload説明。
		const NativeError							 descriptionError =
			// Record順序を維持する方式分類結果。
			describeOfficialDistributionRecordPayloads( record, evidence, payloads) ;
		// Descriptor変換失敗または空結果を解決済みとして保持しない。
		if( descriptionError != 0 || payloads.empty()) {
			summary.state = OfficialDiscoveryRouteState::METADATA_REJECTED ;
			summary.error = descriptionError != 0 ? descriptionError : INVALID_ARGUMENT ;
			return summary ;
		}

		std::vector<OfficialDiscoveryResolvedPackage>
			resolvedPackages ;	// 今回route分のcommit前参照。
		resolvedPackages.reserve( payloads.size()) ;
		// 全payloadを同じrouteとinventoryへ結合し、一件でも不正なら全体を拒否する。
		for( const OfficialRecordPayloadDescriptor &payload : payloads) {
			const auto resolved = makeOfficialDiscoveryResolvedPackage(
				route, payload, devices, providerDescriptors_) ;	// 一payloadの安全な参照。
			// Package identityを作れないrecordを部分成功として保持しない。
			if( !resolved) {
				summary.state = OfficialDiscoveryRouteState::METADATA_REJECTED ;
				summary.error = INVALID_ARGUMENT ;
				return summary ;
			}

			resolvedPackages.push_back( *resolved) ;
		}

		const std::size_t packageStart = packages_.size() ;	// Rollback用の開始位置。
		// 証拠IDへ秘密recordの所有権を移す一意な挿入結果。
		const auto		  inserted = records_.emplace(
			   recordEvidenceId,
			   ResolvedOfficialDistributionRecord{std::move( evidence), std::move( record)}) ;
		// 単調ID衝突を成功として公開しない。
		if( !inserted.second) {
			summary.state = OfficialDiscoveryRouteState::METADATA_REJECTED ;
			summary.error = nativeErrorFromWin32( ERROR_ALREADY_EXISTS) ;
			return summary ;
		}

		try {
			packages_.insert( packages_.end(), resolvedPackages.begin(), resolvedPackages.end()) ;
		} catch( ...) {
			// Package commit失敗時は同じ証拠IDの秘密recordと部分参照を同時に戻す。
			packages_.resize( packageStart) ;
			records_.erase( recordEvidenceId) ;
			throw ;
		}

		summary.state		 = route.kind == OfficialDiscoveryRouteKind::DEDICATED
								   ? OfficialDiscoveryRouteState::DEDICATED_RESOLVED
								   : OfficialDiscoveryRouteState::GENERIC_RESOLVED ;
		summary.recordCount	 = 1U ;
		summary.packageCount = static_cast<std::uint32_t>( resolvedPackages.size()) ;
		// 公開summaryの件数・route結合を内部生成後も再検証する。
		if( !isOfficialDiscoveryRouteSummaryValid( route, summary)) {
			packages_.resize( packageStart) ;
			records_.erase( recordEvidenceId) ;
			summary.recordCount	 = 0U ;
			summary.packageCount = 0U ;
			summary.state		 = OfficialDiscoveryRouteState::METADATA_REJECTED ;
			summary.error		 = INVALID_ARGUMENT ;
		}

		return summary ;
	} catch( const std::bad_alloc &) {
		summary.recordCount	 = 0U ;
		summary.packageCount = 0U ;
		summary.state		 = OfficialDiscoveryRouteState::FAILED ;
		summary.error		 = OUT_OF_MEMORY ;
		return summary ;
	} catch( ...) {
		// Provider callbackやcontainerの未知例外をworker thread外へ漏らさない。
		summary.recordCount	 = 0U ;
		summary.packageCount = 0U ;
		summary.state		 = OfficialDiscoveryRouteState::FAILED ;
		summary.error		 = UNEXPECTED_FAILURE ;
		return summary ;
	}
}

/** @see official_discovery_record_adapter.h */
std::span<const OfficialDiscoveryResolvedPackage> OfficialDiscoveryRecordAdapterSession::
	resolvedPackages() const noexcept
{
	return packages_ ;
}

/** @see official_discovery_record_adapter.h */
NativeError OfficialDiscoveryRecordAdapterSession::describeDisplayPayloads(
	const OfficialDiscoveryBinding						&binding,
	const std::span<const OfficialDiscoveryPackageGroup> groups,
	std::vector<OfficialRecordPayloadDescriptor>		&payloadDescriptors) const noexcept
{
	payloadDescriptors.clear() ;
	// Stale、空、過大groupまたは無効sessionから表示metadataを公開しない。
	if( !isOfficialDiscoveryBindingValid( binding_) || binding != binding_ || groups.empty() ||
	   groups.size() > OFFICIAL_DISCOVERY_PACKAGE_REFERENCE_LIMIT) {
		return INVALID_ARGUMENT ;
	}

	try {
		std::vector<OfficialRecordPayloadDescriptor>
			pending ;	// 全record証拠を再照合した後だけ公開するdescriptor集合。
		pending.reserve( groups.size()) ;
		// 各groupの全record証拠を同じpayloadへ戻し、初出descriptorだけを表示用に保持する。
		for( const OfficialDiscoveryPackageGroup &group : groups) {
			// 不正groupを部分表示へ縮退させない。
			if( !isOfficialDiscoveryPackageGroupValid( group)) {
				return INVALID_ARGUMENT ;
			}

			OfficialRecordPayloadDescriptor canonical ;		// 初出証拠から再生成する表示descriptor。
			bool							initialized{} ;	// 一件以上の証拠を再照合した場合true。
			// 同じstable recordへ到達した全証拠IDを確認し、差替えやclaim済みを拒否する。
			for( const std::uint64_t evidenceId : group.recordEvidenceIds) {
				const auto found = records_.find( evidenceId) ;	// 秘密recordの証拠ID完全一致位置。
				// 未知または既にclaimしたrecordを別証拠から補完しない。
				if( found == records_.end()) {
					return nativeErrorFromWin32( ERROR_NOT_FOUND) ;
				}

				const ResolvedOfficialDistributionRecord &resolved =
					found->second ;	// 保持record借用。
				// Groupのstable fingerprintと件数を保存済み証拠へ再結合する。
				if( resolved.evidence.recordEvidenceId != evidenceId ||
				   resolved.evidence.stableFingerprint.bytes != group.recordFingerprint.bytes ||
				   resolved.evidence.payloadCount != group.payloadCount) {
					return nativeErrorFromWin32( ERROR_REVISION_MISMATCH) ;
				}

				std::vector<OfficialRecordPayloadDescriptor>
								  descriptors ;	// Recordから再生成するURL非保持payload一覧。
				const NativeError descriptionError = describeOfficialDistributionRecordPayloads(
					resolved.record, resolved.evidence, descriptors) ;	// 表示直前の再検証境界。
				// Payload順やdescriptor生成失敗を別payloadへのfallbackにしない。
				if( descriptionError != 0 || group.payloadOrdinal >= descriptors.size()) {
					return descriptionError != 0 ? descriptionError : INVALID_ARGUMENT ;
				}

				const OfficialRecordPayloadDescriptor &descriptor =
					descriptors[group.payloadOrdinal] ;	// Groupが指定したexact payload行。
				// Recordから再生成した全不変fieldをgroupへ戻せない場合は拒否する。
				if( descriptor.recordEvidenceId != evidenceId ||
				   !isDescriptorBoundToGroup( descriptor, group)) {
					return nativeErrorFromWin32( ERROR_REVISION_MISMATCH) ;
				}

				// Stable fingerprintが一致する同一payloadでは初出の公開metadataだけを保持する。
				if( !initialized) {
					canonical	= descriptor ;
					initialized = true ;
				}
			}

			// Group validatorが保証する証拠集合を一件も再生成できない場合は拒否する。
			if( !initialized) {
				return static_cast<NativeError>( E_UNEXPECTED) ;
			}

			pending.push_back( std::move( canonical)) ;
		}

		payloadDescriptors = std::move( pending) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		// 途中生成値を公開せず、呼出側が領域不足を区別できる診断を返す。
		payloadDescriptors.clear() ;
		return OUT_OF_MEMORY ;
	} catch( ...) {
		// 文字列・vectorの未知例外をworker thread外へ漏らさない。
		payloadDescriptors.clear() ;
		return UNEXPECTED_FAILURE ;
	}
}

/** @see official_discovery_record_adapter.h */
NativeError OfficialDiscoveryRecordAdapterSession::describePreparationTargets(
	const OfficialDiscoveryBinding						&binding,
	const std::span<const OfficialDiscoveryPackageGroup> groups,
	std::vector<OfficialPreparationTarget>				&targets,
	std::vector<OfficialDiscoveryEulaPackage>			&eulaPackages,
	std::vector<OfficialRecordPayloadDescriptor>		&payloadDescriptors) const noexcept
{
	targets.clear() ;
	eulaPackages.clear() ;
	payloadDescriptors.clear() ;
	// Stale、空、過大groupまたは無効sessionから取得対象を公開しない。
	if( !isOfficialDiscoveryBindingValid( binding_) || binding != binding_ ||
	   request_.inspectionPermission !=
		   OfficialDiscoveryInspectionPermission::ALLOW_VERIFIED_DRIVER_PACKAGE ||
	   groups.empty() || groups.size() > OFFICIAL_DISCOVERY_EULA_PACKAGE_LIMIT) {
		return INVALID_ARGUMENT ;
	}

	try {
		std::vector<OfficialPreparationTarget> pendingTargets ;	// 全照合後だけ公開する対象集合。
		std::vector<OfficialDiscoveryEulaPackage>
			pendingEulaPackages ;	// 全照合後だけEULA sessionへ渡すsnapshot集合。
		std::vector<OfficialRecordPayloadDescriptor>
			pendingPayloadDescriptors ;	// 各対象と同順で公開するURL非保持descriptor集合。
		pendingTargets.reserve( groups.size()) ;
		pendingEulaPackages.reserve( groups.size()) ;
		pendingPayloadDescriptors.reserve( groups.size()) ;
		// 各groupの全record証拠を再生成descriptorへ照合し、一payloadを一対象へ変換する。
		for( const OfficialDiscoveryPackageGroup &group : groups) {
			// 不正groupまたは既存準備契約のID上限超過を部分対象へ縮退させない。
			if( !isOfficialDiscoveryPackageGroupValid( group) ||
			   group.packageIdentity.size() > MAXIMUM_PREPARATION_ID_CHARACTERS) {
				return INVALID_ARGUMENT ;
			}

			OfficialPreparationTarget canonicalTarget ;	// 最初の証拠から作るgroup共通対象。
			OfficialRecordPayloadDescriptor
				 canonicalDescriptor ;	// 最初の証拠から作るURL非保持表示descriptor。
			bool targetInitialized{} ;	// 一件以上の取得可能descriptorを照合した場合true。
			// 同じstable recordへ到達した全証拠IDを確認し、差替えやclaim済みを拒否する。
			for( const std::uint64_t evidenceId : group.recordEvidenceIds) {
				const auto found = records_.find( evidenceId) ;	// 秘密recordの証拠ID完全一致位置。
				// 未知または既にclaimしたrecordを別証拠から補完しない。
				if( found == records_.end()) {
					return nativeErrorFromWin32( ERROR_NOT_FOUND) ;
				}

				const ResolvedOfficialDistributionRecord &resolved =
					found->second ;	// 保持record借用。
				// Groupのstable fingerprintと件数を保存済み証拠へ再結合する。
				if( resolved.evidence.recordEvidenceId != evidenceId ||
				   resolved.evidence.stableFingerprint.bytes != group.recordFingerprint.bytes ||
				   resolved.evidence.payloadCount != group.payloadCount) {
					return nativeErrorFromWin32( ERROR_REVISION_MISMATCH) ;
				}

				std::vector<OfficialRecordPayloadDescriptor>
								  descriptors ;	// Recordから再生成するURL非保持payload一覧。
				const NativeError descriptionError = describeOfficialDistributionRecordPayloads(
					resolved.record, resolved.evidence, descriptors) ;	// 取得直前と同じ再検証境界。
				// Payload順やdescriptor生成失敗を別payloadへのfallbackにしない。
				if( descriptionError != 0 || group.payloadOrdinal >= descriptors.size()) {
					return descriptionError != 0 ? descriptionError : INVALID_ARGUMENT ;
				}

				const OfficialRecordPayloadDescriptor &descriptor =
					descriptors[group.payloadOrdinal] ;	// Groupが指定したexact payload行。
				// Recordから再生成した全不変fieldをgroupへ戻せない場合は拒否する。
				if( descriptor.recordEvidenceId != evidenceId ||
				   !isDescriptorBoundToGroup( descriptor, group)) {
					return nativeErrorFromWin32( ERROR_REVISION_MISMATCH) ;
				}

				// Unsupported payloadは取得権限を持たない表示専用なので準備対象へ含めない。
				if( !descriptor.downloadGrantSupported) {
					continue ;
				}

				OfficialPreparationTerms preparationTerms ;	// 既存準備契約へ渡す有限条件。
				// 未知の利用条件を同意不要へ変換しない。
				if( !convertPreparationTerms( descriptor.terms, preparationTerms)) {
					return INVALID_ARGUMENT ;
				}

				OfficialPreparationTarget currentTarget ;	// 今回証拠から再構築する非機密対象。
				currentTarget.identity		  = group.packageIdentity ;
				currentTarget.providerId	  = group.providerId ;
				currentTarget.resourceId	  = descriptor.payloadResourceId ;
				currentTarget.releaseIdentity = group.packageIdentity ;
				currentTarget.parserRevision  = resolved.evidence.parserRevision ;
				currentTarget.maximumBytes =
					resolved.record.payloads[group.payloadOrdinal].maximumBytes ;
				currentTarget.deviceCount =
					static_cast<std::uint32_t>( group.deviceIdentities.size()) ;
				currentTarget.terms = preparationTerms ;
				// 同意必須の場合だけrevisionと全文を既存UI snapshotへ複製する。
				if( preparationTerms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED) {
					currentTarget.eulaRevision = resolved.record.eulaRevision ;
					currentTarget.eulaText	   = resolved.record.eulaText ;
				}

				// 同じgroupの別証拠は全対象fieldまで完全一致する場合だけ受理する。
				if( targetInitialized && currentTarget != canonicalTarget) {
					return nativeErrorFromWin32( ERROR_REVISION_MISMATCH) ;
				}

				// 初出の取得可能証拠をgroup共通対象として固定する。
				if( !targetInitialized) {
					canonicalTarget		= std::move( currentTarget) ;
					canonicalDescriptor = descriptor ;
					targetInitialized	= true ;
				}
			}

			// Unsupportedだけのgroupは表示専用のまま取得計画へ公開しない。
			if( !targetInitialized) {
				continue ;
			}

			// EULA同意必須対象は完全一致group化用snapshotも同時に作る。
			if( canonicalTarget.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED) {
				pendingEulaPackages.push_back( {.packageIdentity = canonicalTarget.identity,
											   .providerId		= canonicalTarget.providerId,
											   .eulaRevision	= canonicalTarget.eulaRevision,
											   .eulaText		= canonicalTarget.eulaText,
											   .maximumBytes	= canonicalTarget.maximumBytes}) ;
			}

			pendingTargets.push_back( std::move( canonicalTarget)) ;
			pendingPayloadDescriptors.push_back( std::move( canonicalDescriptor)) ;
		}

		targets			   = std::move( pendingTargets) ;
		eulaPackages	   = std::move( pendingEulaPackages) ;
		payloadDescriptors = std::move( pendingPayloadDescriptors) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		// 途中生成値を公開せず、呼出側が領域不足を区別できる診断を返す。
		targets.clear() ;
		eulaPackages.clear() ;
		payloadDescriptors.clear() ;
		return OUT_OF_MEMORY ;
	} catch( ...) {
		// 文字列・vectorの未知例外をworker thread外へ漏らさない。
		targets.clear() ;
		eulaPackages.clear() ;
		payloadDescriptors.clear() ;
		return UNEXPECTED_FAILURE ;
	}
}

/** @see official_discovery_record_adapter.h */
NativeError OfficialDiscoveryRecordAdapterSession::claimResolvedRecord(
	const ScanSessionId scanSessionId, const std::uint64_t recordEvidenceId,
	ResolvedOfficialDistributionRecord &record) noexcept
{
	record = {} ;
	// Stale sessionまたは0 IDから現在recordを検索しない。
	if( binding_.scanSessionId == 0U || scanSessionId != binding_.scanSessionId ||
	   recordEvidenceId == 0U) {
		return nativeErrorFromWin32( ERROR_REVISION_MISMATCH) ;
	}

	const auto found = records_.find( recordEvidenceId) ;	// Opaque証拠IDの完全一致位置。
	// 未知またはclaim済みIDを別recordへfallbackしない。
	if( found == records_.end()) {
		return nativeErrorFromWin32( ERROR_NOT_FOUND) ;
	}

	record = std::move( found->second) ;
	records_.erase( found) ;
	return 0 ;
}

/** @see official_discovery_record_adapter.h */
void OfficialDiscoveryRecordAdapterSession::invalidate() noexcept
{
	binding_ = {} ;
	request_ = {} ;
	providerDescriptors_.clear() ;
	records_.clear() ;
	packages_.clear() ;
	resolvedRouteIds_.clear() ;
	nextRecordEvidenceId_ = 1U ;
}

/** @see official_discovery_record_adapter.h */
std::size_t OfficialDiscoveryRecordAdapterSession::retainedRecordCount() const noexcept
{
	return records_.size() ;
}

/** @see official_discovery_record_adapter.h */
OfficialDiscoveryBinding OfficialDiscoveryRecordAdapterSession::activeBinding() const noexcept
{
	return binding_ ;
}

} // namespace drivercrate
