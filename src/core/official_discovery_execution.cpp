//------------------------------------------------------------------------------
/**
 * @file official_discovery_execution.cpp
 * @brief 共通route planのpurpose伝達と専用／汎用実行状態集約。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Purpose伝達と専用／汎用継続を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/09/15  開始時bindingとrequestの再照合を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  通信未許可summaryとProvider結果変換を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  Fresh cache優先とroute別通信許可を追加。
 * </pre>
 *
 * @note Resolver例外と不正summaryは有限な失敗状態へ変換し、汎用routeの成功で削除しません。
 * Hardware ID、instance ID、URL、pathは入力型にも出力型にも含めません。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#include "core/official_discovery_execution.h"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace drivercrate {
namespace {

// Resolverが契約外summaryを返した場合のE_INVALIDARG相当診断値。
constexpr NativeError INVALID_RESOLVER_RESULT_ERROR = -2147024809 ;
// ResolverがC++例外を送出した場合のE_UNEXPECTED相当診断値。
constexpr NativeError RESOLVER_EXCEPTION_ERROR = -2147418113 ;
// 制御終端に固有診断がない内部失敗を表すE_FAILのbit pattern。
constexpr NativeError CONTROL_FAILURE_ERROR = -2147467259 ;
// 通常scan取消しを表すHRESULT_FROM_WIN32(ERROR_CANCELLED)のbit pattern。
constexpr NativeError CANCELLED_ERROR = std::bit_cast<NativeError>( std::uint32_t{0x800704C7U}) ;

/**
 * @brief Routeへ一致する唯一のregistrationを検索する。
 * @param[in] route Plan内の検証済み想定route。
 * @param[in] registrations Plan生成時と同じregistration集合。
 * @return 一件だけ一致する場合の借用pointer。それ以外はnullptr。
 */
[[nodiscard]] const OfficialDiscoveryRegistration *findExecutionRegistration(
	const OfficialDiscoveryRoute						&route,
	const std::span<const OfficialDiscoveryRegistration> registrations) noexcept
{
	const auto found = std::find_if(
		registrations.begin(), registrations.end(), [&route]( const auto &registration) {
			return registration.providerId == route.providerId &&
				   registration.rootResourceId == route.rootResourceId &&
				   registration.kind == route.kind ;
		}) ; // Provider、root、種別が完全一致する実行registration。
	// 欠損または重複callbackを一意として返さない。
	if( found == registrations.end() ||
	   std::count_if( registrations.begin(), registrations.end(),
					 [&route]( const auto &registration) {
						 return registration.providerId == route.providerId &&
								registration.rootResourceId == route.rootResourceId &&
								registration.kind == route.kind ;
					 }) != 1) {
		return nullptr ;
	}

	return &*found ;
}

/**
 * @brief 同じProvider、root、deviceの専用解決状態を表す端末内keyを作る。
 * @param[in] providerId Provider stable ID。
 * @param[in] rootResourceId 固定root resource ID。
 * @param[in] deviceIdentity Scan内のopaque device identity。
 * @return 表示値やURLを含まない重複抑止key。
 */
[[nodiscard]] std::wstring makeDedicatedResolutionKey( const std::wstring_view providerId,
													  const std::wstring_view rootResourceId,
													  const std::wstring_view deviceIdentity)
{
	std::wstring key( providerId) ;	// Provider stable IDから始める端末内key。
	key.push_back( L'\x1F') ;
	key.append( rootResourceId) ;
	key.push_back( L'\x1F') ;
	key.append( deviceIdentity) ;
	return key ;
}

/**
 * @brief Routeと状態へ結合した件数0の内部summaryを作る。
 * @param[in] route 元planのroute。
 * @param[in] state 保持する未実行または失敗状態。
 * @param[in] error 状態に対応する0またはnative診断値。
 * @return Route identityと全device件数を保持するsummary。
 */
[[nodiscard]] OfficialDiscoveryRouteSummary makeInternalRouteSummary(
	const OfficialDiscoveryRoute &route, const OfficialDiscoveryRouteState state,
	const NativeError error)
{
	return OfficialDiscoveryRouteSummary{
		.routeId	  = route.routeId,
		.providerId	  = route.providerId,
		.kind		  = route.kind,
		.state		  = state,
		.error		  = error,
		.deviceCount  = static_cast<std::uint32_t>( route.deviceIdentities.size()),
		.recordCount  = 0U,
		.packageCount = 0U} ;
}

/**
 * @brief Providerが開始時requestで選択されているか確認する。
 * @param[in] request 検証済みの既定または明示scope。
 * @param[in] descriptor Registry正本の自動探索Provider。
 * @return Registry既定または明示IDにより選択されている場合true。
 */
[[nodiscard]] bool isSelectedDiscoveryProvider( const OfficialDiscoveryRequest &request,
											   const ProviderDescriptor		  &descriptor) noexcept
{
	// 既定設定ではdescriptorの正本値だけを使用する。
	if( request.useDefaultProviders) {
		return descriptor.enabledByDefault ;
	}

	return std::find( request.enabledProviderIds.begin(), request.enabledProviderIds.end(),
					 descriptor.id) != request.enabledProviderIds.end() ;
}

/**
 * @brief Provider結果へ候補なしで保持できる成功route状態か確認する。
 * @param[in] state 一routeの検証済み状態。
 * @return Recordなしまたは専用成功後の重複抑止ならtrue。
 */
[[nodiscard]] bool isSuccessfulEmptyState( const OfficialDiscoveryRouteState state) noexcept
{
	return state == OfficialDiscoveryRouteState::CACHE_NEGATIVE ||
		   state == OfficialDiscoveryRouteState::SKIPPED_AFTER_DEDICATED ||
		   state == OfficialDiscoveryRouteState::NO_RECORD ;
}

/**
 * @brief Provider結果へmetadata解決済みとして保持できるroute状態か確認する。
 * @param[in] state 一routeの検証済み状態。
 * @return Cache、専用、汎用またはEULA待ちでrecordがある場合true。
 */
[[nodiscard]] bool isResolvedState( const OfficialDiscoveryRouteState state) noexcept
{
	return state == OfficialDiscoveryRouteState::CACHE_POSITIVE ||
		   state == OfficialDiscoveryRouteState::DEDICATED_RESOLVED ||
		   state == OfficialDiscoveryRouteState::GENERIC_RESOLVED ||
		   state == OfficialDiscoveryRouteState::AWAITING_EULA ;
}

/**
 * @brief Cache callbackだけが返せる二つの正常状態か確認します。
 * @param[in] state 検証するroute状態です。
 * @return Fresh positiveまたはfresh negativeの場合trueです。
 */
[[nodiscard]] bool isCacheState( const OfficialDiscoveryRouteState state) noexcept
{
	return state == OfficialDiscoveryRouteState::CACHE_POSITIVE ||
		   state == OfficialDiscoveryRouteState::CACHE_NEGATIVE ;
}

} // namespace

/** @see official_discovery_execution.h */
std::optional<OfficialDiscoverySummary> runOfficialDiscoveryRoutePlan(
	const OfficialDiscoveryBinding &binding, const OfficialDiscoveryRequest &request,
	const OfficialDiscoveryRoutePlan					&plan,
	const std::span<const OfficialDiscoveryDeviceHint>	 devices,
	const std::span<const OfficialDiscoveryRegistration> registrations,
	const std::span<const ProviderDescriptor>			 descriptors,
	OfficialDiscoveryRouteCacheLookup cacheLookup, const bool resolverApproved)
{
	// Planと全開始snapshotをresolver呼出し前に再結合する。
	if( !isOfficialDiscoveryRoutePlanValid( binding, request, devices, registrations, descriptors,
										  plan)) {
		return std::nullopt ;
	}

	OfficialDiscoverySummary summary ;	// 全routeを保持する非機密な所有結果。
	summary.binding								 = plan.binding ;
	summary.request								 = plan.request ;
	summary.inventoryComplete					 = plan.inventoryComplete ;
	summary.deviceCount							 = plan.deviceCount ;
	summary.dedicatedUnavailableDeviceIdentities = plan.dedicatedUnavailableDeviceIdentities ;
	summary.noTrustedRootDeviceIdentities		 = plan.noTrustedRootDeviceIdentities ;
	summary.routes.reserve( plan.routes.size()) ;
	std::unordered_set<std::wstring> dedicatedResolved ;	// 専用成功済みProvider／root／device集合。
	// 専用を先、汎用を後に並べたplan順を維持してresolverを同期実行する。
	for( const OfficialDiscoveryRoute &route : plan.routes) {
		const OfficialDiscoveryRegistration *registration =
			// 固定root resolver。
			findExecutionRegistration( route, registrations) ;
		// Plan validator後にregistrationを失った内部不整合では実行を開始しない。
		if( registration == nullptr) {
			return std::nullopt ;
		}

		bool skipGeneric =
			// 暫定判定。
			route.kind == OfficialDiscoveryRouteKind::GENERIC_OFFICIAL_ROOT ;
		// 汎用routeの全deviceが同じProvider／rootの専用routeで解決済みか確認する。
		for( const std::wstring &deviceIdentity : route.deviceIdentities) {
			// 一件でも専用未解決なら汎用fallbackを実行する。
			if( !dedicatedResolved.contains( makeDedicatedResolutionKey(
				   route.providerId, route.rootResourceId, deviceIdentity))) {
				skipGeneric = false ;
				break ;
			}
		}

		// 専用成功後もroute結果を一対一に残し、resolverだけを重複実行しない。
		if( skipGeneric) {
			summary.routes.push_back( makeInternalRouteSummary(
				route, OfficialDiscoveryRouteState::SKIPPED_AFTER_DEDICATED, 0)) ;
			continue ;
		}

		OfficialDiscoveryRouteSummary routeSummary ;	// Cache、resolverまたは有限制御の一route結果。
		bool						  cacheUsed{} ;		// Fresh cache summaryを採用した場合trueです。
		// 明示refresh以外ではURL非保持cacheをnetworkより先に照会します。
		if( plan.request.cacheMode == OfficialDiscoveryCacheMode::USE_FRESH && cacheLookup) {
			try {
				const auto cached = cacheLookup( plan.request, route) ;	// 現在rootの任意fresh結果。
				// Cache専用状態と元routeへの完全結合が成立した結果だけを採用します。
				if( cached && isCacheState( cached->state) &&
				   isOfficialDiscoveryRouteSummaryValid( route, *cached)) {
					routeSummary = *cached ;
					cacheUsed	 = true ;
				}
			} catch( ...) {
				// Cache読取り例外をnetwork失敗へ変換せず、許可済みresolverへ進みます。
			}
		}

		// Cache miss時に回線が許可されないrouteはresolverを呼ばず明示状態へ確定します。
		if( !cacheUsed && !resolverApproved) {
			routeSummary = makeInternalRouteSummary(
				route, OfficialDiscoveryRouteState::NETWORK_NOT_APPROVED, 0) ;
		}

		// Cache missかつ通信許可済みの場合だけ現在routeのresolver入力を構築します。
		if( !cacheUsed && resolverApproved) {
			std::vector<OfficialDiscoveryDeviceHint> routeDevices ;	// Route参照だけのresolver入力。
			routeDevices.reserve( route.deviceIdentities.size()) ;
			// Opaque identityを開始時hintへ完全一致で解決します。
			for( const std::wstring &deviceIdentity : route.deviceIdentities) {
				const auto device = std::find_if(
					devices.begin(), devices.end(), [&deviceIdentity]( const auto &candidate) {
						return candidate.deviceIdentity == deviceIdentity ;
					}) ; // Routeが参照する一意なhint。
				// Plan再検証後の欠損は内部不整合として全体を拒否します。
				if( device == devices.end()) {
					return std::nullopt ;
				}

				routeDevices.push_back( *device) ;
			}

			try {
				routeSummary = registration->resolver( plan.request, route, routeDevices) ;
				// SKIPPED状態はexecutorだけが専用成功根拠から生成できます。
				if( routeSummary.state == OfficialDiscoveryRouteState::SKIPPED_AFTER_DEDICATED ||
				   !isOfficialDiscoveryRouteSummaryValid( route, routeSummary)) {
					routeSummary = makeInternalRouteSummary(
						route, OfficialDiscoveryRouteState::METADATA_REJECTED,
						INVALID_RESOLVER_RESULT_ERROR) ;
				}
			} catch( ...) {
				// Resolver境界から例外を漏らさず、元routeへ有限な失敗診断を結合します。
				routeSummary = makeInternalRouteSummary( route, OfficialDiscoveryRouteState::FAILED,
														RESOLVER_EXCEPTION_ERROR) ;
			}
		}

		summary.routes.push_back( routeSummary) ;
		// 専用routeがrecordを解決した場合だけ同じrootの汎用重複実行を抑止する。
		if( route.kind == OfficialDiscoveryRouteKind::DEDICATED &&
		   (routeSummary.state == OfficialDiscoveryRouteState::DEDICATED_RESOLVED ||
			routeSummary.state == OfficialDiscoveryRouteState::CACHE_POSITIVE)) {
			// 専用成功をroute内の各opaque deviceへ結合する。
			for( const std::wstring &deviceIdentity : route.deviceIdentities) {
				dedicatedResolved.insert( makeDedicatedResolutionKey(
					route.providerId, route.rootResourceId, deviceIdentity)) ;
			}
		}
	}

	// 全結果を開始時planへ一括で戻し、部分的な不正summaryを公開しない。
	if( !isOfficialDiscoverySummaryValid( plan.binding, plan.request, devices, plan.routes, summary,
										descriptors)) {
		return std::nullopt ;
	}

	return summary ;
}

/** @see official_discovery_execution.h */
std::optional<OfficialDiscoverySummary> makeOfficialDiscoveryControlSummary(
	const OfficialDiscoveryBinding &binding, const OfficialDiscoveryRequest &request,
	const OfficialDiscoveryRoutePlan					&plan,
	const std::span<const OfficialDiscoveryDeviceHint>	 devices,
	const std::span<const OfficialDiscoveryRegistration> registrations,
	const std::span<const ProviderDescriptor> descriptors, const OfficialDiscoveryRouteState state)
{
	// HTTP開始前に確定できる三状態以外をresolver結果として合成しない。
	if( state != OfficialDiscoveryRouteState::NETWORK_NOT_APPROVED &&
	   state != OfficialDiscoveryRouteState::BUDGET_EXCEEDED &&
	   state != OfficialDiscoveryRouteState::CANCELLED) {
		return std::nullopt ;
	}

	// Planと全開始snapshotをsummary生成前に再結合する。
	if( !isOfficialDiscoveryRoutePlanValid( binding, request, devices, registrations, descriptors,
										  plan)) {
		return std::nullopt ;
	}

	OfficialDiscoverySummary summary ;	// Resolverを実行しない全routeの非機密結果。
	summary.binding								 = plan.binding ;
	summary.request								 = plan.request ;
	summary.inventoryComplete					 = plan.inventoryComplete ;
	summary.deviceCount							 = plan.deviceCount ;
	summary.dedicatedUnavailableDeviceIdentities = plan.dedicatedUnavailableDeviceIdentities ;
	summary.noTrustedRootDeviceIdentities		 = plan.noTrustedRootDeviceIdentities ;
	summary.routes.reserve( plan.routes.size()) ;
	// 全routeを同じ事前停止理由へ一対一で確定する。
	for( const OfficialDiscoveryRoute &route : plan.routes) {
		summary.routes.push_back( makeInternalRouteSummary( route, state, 0)) ;
	}

	// 合成結果も通常executorと同じ公開validatorへ通す。
	if( !isOfficialDiscoverySummaryValid( binding, request, devices, plan.routes, summary,
										descriptors)) {
		return std::nullopt ;
	}

	return summary ;
}

/** @see official_discovery_execution.h */
std::optional<ScanResult> makeOfficialDiscoveryProviderScanResult(
	const ScanSessionId scanSessionId, const std::wstring_view providerId,
	const std::span<const OfficialDiscoveryDeviceHint> devices,
	const OfficialDiscoveryRoutePlan &plan, const OfficialDiscoverySummary &summary,
	const std::span<const ProviderDescriptor> descriptors)
{
	// Summary全体とscan sessionを開始時snapshotへ戻せない入力を拒否する。
	if( scanSessionId == 0U || providerId.empty() || plan.binding.scanSessionId != scanSessionId ||
	   !isOfficialDiscoverySummaryValid( plan.binding, plan.request, devices, plan.routes, summary,
										descriptors)) {
		return std::nullopt ;
	}

	const auto descriptor = std::find_if( descriptors.begin(), descriptors.end(),
										 [providerId]( const ProviderDescriptor &candidate) {
											 return candidate.id == providerId ;
										 }) ; // 変換対象のregistry正本。
	// 未登録、重複、未選択または自動探索能力のないProviderへ結果を作らない。
	if( descriptor == descriptors.end() ||
	   std::count_if( descriptors.begin(), descriptors.end(),
					 [providerId]( const ProviderDescriptor &candidate) {
						 return candidate.id == providerId ;
					 }) != 1 ||
	   !isOfficialDiscoveryProvider( *descriptor) ||
	   !isSelectedDiscoveryProvider( plan.request, *descriptor)) {
		return std::nullopt ;
	}

	std::unordered_set<std::wstring> eligibleDevices ;			// 当該Providerへrouteされたdevice集合。
	std::unordered_set<std::wstring> assessedDevices ;			// 正常終端まで判定したdevice集合。
	bool							 hasRoutes{} ;				// 当該Providerのrouteがある場合true。
	bool							 hasSuccessfulResult{} ;	// 一route以上が正常終端ならtrue。
	bool							 hasPackage{} ;				// 一件以上のpayload metadataがある場合true。
	bool							 networkNotApproved{} ;		// 全正常結果が回線待ちの場合true候補。
	bool							 cancelled{} ;				// 一route以上が取消しの場合true。
	bool							 budgetExceeded{} ;			// 一route以上が予算到達の場合true。
	bool							 sourceRejected{} ;			// 一route以上がsource拒否の場合true。
	bool							 metadataRejected{} ;		// 一route以上がmetadata拒否の場合true。
	bool							 failed{} ;					// 一route以上が一般失敗の場合true。
	NativeError						 firstError{} ;				// Route順で最初の非zero診断値。
	// Planとsummaryの同じ位置を走査し、Provider別状態と有限coverageを集約する。
	for( std::size_t index = 0U; index < plan.routes.size(); ++index) {
		const OfficialDiscoveryRoute &route = plan.routes[index] ;	// 元planの一route。
		// 別Providerのrouteは当該Provider結果へ混在させない。
		if( route.providerId != providerId) {
			continue ;
		}

		hasRoutes = true ;
		// 同じProvider内のroute重複をcoverageで二重計上しない。
		for( const std::wstring &deviceIdentity : route.deviceIdentities) {
			eligibleDevices.insert( deviceIdentity) ;
		}

		const OfficialDiscoveryRouteSummary &routeSummary = summary.routes[index] ;	// 対応結果。
		const bool resolved		= isResolvedState( routeSummary.state) ;			// Metadata解決済み状態。
		const bool emptySuccess = isSuccessfulEmptyState( routeSummary.state) ;		// 正常な空結果。
		// 正常にmetadata有無を判定したrouteだけを判定済みcoverageへ加える。
		if( resolved || emptySuccess) {
			hasSuccessfulResult = true ;
			// 同じProviderの正常routeに属するdeviceを一度ずつ判定済みにする。
			for( const std::wstring &deviceIdentity : route.deviceIdentities) {
				assessedDevices.insert( deviceIdentity) ;
			}
		}

		hasPackage = hasPackage || (resolved && routeSummary.packageCount != 0U) ;
		networkNotApproved =
			networkNotApproved ||
			routeSummary.state == OfficialDiscoveryRouteState::NETWORK_NOT_APPROVED ;
		cancelled = cancelled || routeSummary.state == OfficialDiscoveryRouteState::CANCELLED ;
		budgetExceeded =
			budgetExceeded || routeSummary.state == OfficialDiscoveryRouteState::BUDGET_EXCEEDED ;
		sourceRejected =
			sourceRejected || routeSummary.state == OfficialDiscoveryRouteState::SOURCE_REJECTED ;
		metadataRejected = metadataRejected ||
						   routeSummary.state == OfficialDiscoveryRouteState::METADATA_REJECTED ;
		failed = failed || routeSummary.state == OfficialDiscoveryRouteState::FAILED ;
		// 最初のProvider診断だけを表示用結果へ保持する。
		if( firstError == 0 && routeSummary.error != 0) {
			firstError = routeSummary.error ;
		}
	}

	ScanResult result ;	// 候補を含めない自動探索Providerの有限結果。
	result.scanSessionId				= scanSessionId ;
	result.purpose						= ScanPurpose::STANDARD ;
	result.coverage.eligibleDeviceCount = eligibleDevices.size() ;
	result.coverage.assessedDeviceCount = assessedDevices.size() ;
	// 対応routeがないProviderは通信失敗や候補なしへ変換しない。
	if( !hasRoutes) {
		result.succeeded = true ;
		result.outcome	 = OutcomeCode::SUCCESS ;
		result.state	 = ProviderScanState::NOT_APPLICABLE ;
		return result ;
	}

	// 部分成功または全失敗の判定に使用する一件以上の異常終端状態。
	const bool hasFailure =
		cancelled || budgetExceeded || sourceRejected || metadataRejected || failed ;
	// 一件以上の正常metadata結果があれば失敗routeを部分成功として保持する。
	if( hasSuccessfulResult) {
		result.succeeded = true ;
		result.outcome	 = hasFailure ? OutcomeCode::SUCCEEDED_WITH_ERRORS : OutcomeCode::SUCCESS ;
		result.state =
			hasPackage ? ProviderScanState::PAYLOAD_NOT_APPROVED : ProviderScanState::NO_CANDIDATES ;
		result.error = firstError ;
		return result ;
	}

	// 全routeが回線未許可なら正常な未実行状態として保持する。
	if( networkNotApproved && !hasFailure) {
		result.succeeded = true ;
		result.outcome	 = OutcomeCode::SUCCESS ;
		result.state	 = ProviderScanState::NETWORK_NOT_APPROVED ;
		return result ;
	}

	result.succeeded = false ;
	result.outcome	 = cancelled ? OutcomeCode::ABORTED : OutcomeCode::FAILURE ;
	result.state	 = sourceRejected	  ? ProviderScanState::SOURCE_REJECTED
					   : metadataRejected ? ProviderScanState::METADATA_REJECTED
										  : ProviderScanState::FAILURE ;
	result.error =
		firstError != 0 ? firstError : (cancelled ? CANCELLED_ERROR : CONTROL_FAILURE_ERROR) ;
	return result ;
}

} // namespace drivercrate
