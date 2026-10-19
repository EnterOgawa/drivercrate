//------------------------------------------------------------------------------
/**
 * @file official_discovery_planner.cpp
 * @brief 公式自動探索registration検証と決定的route plan生成実装。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Registration検証と決定的route plannerを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Purpose伝達と専用adapter欠損集合を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  Cache失効用parser identityの検証を追加。
 * </pre>
 *
 * @note 表示値は端末内のgroup key作成中だけ正規化し、routeへ複製しません。
 * Resolver callbackは検証対象にするだけで、本実装から呼び出しません。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#include "core/official_discovery_planner.h"

#include "core/official_source_policy.h"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <map>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace drivercrate {
namespace {

/**
 * @brief Route種別が定義済みか確認する。
 * @param[in] kind 検証するroute種別。
 * @return 専用または汎用固定rootの場合true。
 */
[[nodiscard]] bool isKnownRegistrationKind( const OfficialDiscoveryRouteKind kind) noexcept
{
	return kind == OfficialDiscoveryRouteKind::DEDICATED ||
		   kind == OfficialDiscoveryRouteKind::GENERIC_OFFICIAL_ROOT ;
}

/**
 * @brief Parser stable IDが有限ASCII識別子か確認します。
 * @param[in] value 検証するregistrationのparser IDです。
 * @return 1～128文字のlowercase英数、dot、underscoreまたはhyphenだけならtrueです。
 */
[[nodiscard]] bool isParserStableId( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= OFFICIAL_DISCOVERY_STABLE_ID_LIMIT &&
		   std::all_of( value.begin(), value.end(), []( const wchar_t character) noexcept {
			   return (character >= L'a' && character <= L'z') ||
					  (character >= L'0' && character <= L'9') || character == L'.' ||
					  character == L'_' || character == L'-' ;
		   }) ;
}

/**
 * @brief 固定集合に含めるUnicode空白か確認する。
 * @param[in] character 検証するUTF-16 code unit。
 * @return ASCII空白またはUnicode White_Spaceの固定値の場合true。
 */
[[nodiscard]] bool isRoutingWhitespace( const wchar_t character) noexcept
{
	return character == L' ' || character == L'\u0085' || character == L'\u00A0' ||
		   character == L'\u1680' || (character >= L'\u2000' && character <= L'\u200A') ||
		   character == L'\u2028' || character == L'\u2029' || character == L'\u202F' ||
		   character == L'\u205F' || character == L'\u3000' ;
}

/**
 * @brief 表示値のASCII大小文字と連続Unicode空白だけを比較用に正規化する。
 * @param[in] value Raw ID形式を含まない検証済み表示値。
 * @return 前後空白を除去し、内部空白を一つへまとめた端末内比較値。
 */
[[nodiscard]] std::wstring normalizeRoutingDisplay( const std::wstring_view value)
{
	std::wstring normalized ;	// Routeへ公開しない比較専用文字列。
	normalized.reserve( value.size()) ;
	bool pendingSpace{} ;	// 非空文字間に一つのASCII空白を挿入する場合true。
	// 元tokenを除去せず、ASCII caseと固定Unicode空白だけを順に変換する。
	for( const wchar_t character : value) {
		// 前後と連続空白を一つのpending状態へまとめる。
		if( isRoutingWhitespace( character)) {
			pendingSpace = !normalized.empty() ;
			continue ;
		}

		// 直前に内部空白があった場合だけ一文字を追加する。
		if( pendingSpace) {
			normalized.push_back( L' ') ;
			pendingSpace = false ;
		}

		// ASCII大文字だけを小文字へ変え、Unicode文字やmodel tokenを推測変換しない。
		const wchar_t normalizedCharacter =
			character >= L'A' && character <= L'Z' ? character - L'A' + L'a' : character ;
		normalized.push_back( normalizedCharacter) ;
	}

	return normalized ;
}

/**
 * @brief 一deviceの表示hintを境界付きの端末内group keyへ変換する。
 * @param[in] device Core検証済みのraw ID非保持hint。
 * @return Bus、class、manufacturer、model、現在Providerを分離した比較key。
 */
[[nodiscard]] std::wstring makeRoutingGroupKey( const OfficialDiscoveryDeviceHint &device)
{
	std::wstring key = std::to_wstring( static_cast<std::uint32_t>( device.bus)) ;	// 有限bus。
	// 表示値内に許可しない制御区切りを使い、field境界の連結曖昧性を防ぐ。
	key.push_back( L'\x1F') ;
	key.append( normalizeRoutingDisplay( device.setupClassGuid)) ;
	key.push_back( L'\x1F') ;
	key.append( normalizeRoutingDisplay( device.deviceClass)) ;
	key.push_back( L'\x1F') ;
	key.append( normalizeRoutingDisplay( device.manufacturer)) ;
	key.push_back( L'\x1F') ;
	key.append( normalizeRoutingDisplay( device.model)) ;
	key.push_back( L'\x1F') ;
	key.append( normalizeRoutingDisplay( device.currentProvider)) ;
	return key ;
}

/**
 * @brief Requestで一つのProviderが選択されているか判定する。
 * @param[in] request 検証済みの既定または明示scope。
 * @param[in] descriptor Registry正本の一Provider。
 * @return 既定状態または明示IDにより今回選択されている場合true。
 */
[[nodiscard]] bool isDiscoveryProviderSelected( const OfficialDiscoveryRequest &request,
											   const ProviderDescriptor		  &descriptor) noexcept
{
	// 既定集合はregistryの値だけを正本にする。
	if( request.useDefaultProviders) {
		return descriptor.enabledByDefault ;
	}

	return std::find( request.enabledProviderIds.begin(), request.enabledProviderIds.end(),
					 descriptor.id) != request.enabledProviderIds.end() ;
}

/**
 * @brief Provider IDとroute種別に一致するregistrationを数える。
 * @param[in] registrations 検証対象集合。
 * @param[in] providerId 完全一致させるProvider ID。
 * @param[in] rootResourceId 完全一致させる固定root ID。
 * @param[in] kind 完全一致させるroute種別。
 * @return 一致件数。
 */
[[nodiscard]] std::size_t countMatchingRegistrations(
	const std::span<const OfficialDiscoveryRegistration> registrations,
	const std::wstring_view providerId, const std::wstring_view rootResourceId,
	const OfficialDiscoveryRouteKind kind) noexcept
{
	return static_cast<std::size_t>( std::count_if(
		registrations.begin(), registrations.end(),
		[providerId, rootResourceId, kind]( const OfficialDiscoveryRegistration &registration) {
			return registration.providerId == providerId &&
				   registration.rootResourceId == rootResourceId && registration.kind == kind ;
		})) ;
}

/**
 * @brief Routeが参照する唯一のregistrationを取得する。
 * @param[in] route 検証するroute。
 * @param[in] registrations 検証済み想定のregistration集合。
 * @return 一件だけ一致する場合の借用pointer。それ以外はnullptr。
 */
[[nodiscard]] const OfficialDiscoveryRegistration *findRouteRegistration(
	const OfficialDiscoveryRoute						&route,
	const std::span<const OfficialDiscoveryRegistration> registrations) noexcept
{
	const auto found = std::find_if(
		registrations.begin(), registrations.end(), [&route]( const auto &registration) {
			return registration.providerId == route.providerId &&
				   registration.rootResourceId == route.rootResourceId &&
				   registration.kind == route.kind ;
		}) ; // Provider、root、種別が完全一致するregistration。
	// 欠損または重複した実行adapterを一意として返さない。
	if( found == registrations.end() ||
	   countMatchingRegistrations( registrations, route.providerId, route.rootResourceId,
								  route.kind) != 1U) {
		return nullptr ;
	}

	return &*found ;
}

/**
 * @brief Route IDから外部情報を含まないhint group identityを作る。
 * @param[in] routeId Plan内で1から単調増加するroute ID。
 * @return Core opaque identity規則に収まる固定prefixと10進ID。
 */
[[nodiscard]] std::wstring makeHintGroupIdentity( const std::uint64_t routeId)
{
	return L"hint-group:" + std::to_wstring( routeId) ;
}

} // namespace

/** @see official_discovery_planner.h */
bool validateOfficialDiscoveryRegistrations(
	const std::span<const OfficialDiscoveryRegistration> registrations,
	const std::span<const ProviderDescriptor>			 descriptors) noexcept
{
	// 空、過大または不正Provider registryを部分的な自動探索一覧へ変換しない。
	if( registrations.empty() || registrations.size() > OFFICIAL_DISCOVERY_ROUTE_LIMIT ||
	   descriptors.empty() || descriptors.size() > OFFICIAL_DISCOVERY_PROVIDER_LIMIT) {
		return false ;
	}

	// 全registrationを一意な自動探索Providerと固定公式rootへ結合する。
	for( std::size_t index = 0U; index < registrations.size(); ++index) {
		const OfficialDiscoveryRegistration &registration = registrations[index] ;	// 現在定義。
		const auto descriptor = std::find_if( descriptors.begin(), descriptors.end(),
											 [&registration]( const auto &candidate) {
												 return candidate.id == registration.providerId ;
											 }) ; // Stable IDへ一致するProvider正本。
		// 未知・重複Providerまたは自動探索能力のない定義を拒否する。
		if( descriptor == descriptors.end() ||
		   std::count_if( descriptors.begin(), descriptors.end(),
						 [&registration]( const auto &candidate) {
							 return candidate.id == registration.providerId ;
						 }) != 1 ||
		   !isOfficialDiscoveryProvider( *descriptor) ||
		   descriptor->officialSourcePolicyId != registration.sourcePolicyId ||
		   !isParserStableId( registration.parserId) || registration.parserRevision == 0U ||
		   !isKnownRegistrationKind( registration.kind) || registration.matcher == nullptr ||
		   !registration.resolver ||
		   registration.networkHintFields != OFFICIAL_DISCOVERY_NETWORK_HINT_NONE) {
			return false ;
		}

		const OfficialSourcePolicy *policy =
			// 組み込み公式policy。
			officialSourcePolicyForProvider( registration.providerId) ;
		const OfficialSourceResourcePolicy *resource =
			policy == nullptr
				? nullptr
				: findOfficialSourceResource( *policy, registration.rootResourceId) ;	// 固定root。
		// Policy IDとlanding／metadata用途が完全一致しないrootを実行対象にしない。
		if( policy == nullptr || policy->id != registration.sourcePolicyId || resource == nullptr ||
		   (resource->kind != OfficialSourceResourceKind::LANDING_PAGE &&
			resource->kind != OfficialSourceResourceKind::METADATA)) {
			return false ;
		}

		// 同じProvider、root、route種別を入力順で上書きしない。
		for( std::size_t previousIndex = 0U; previousIndex < index; ++previousIndex) {
			const OfficialDiscoveryRegistration &previous =
				registrations[previousIndex] ;	// 先行registration。
			// 実行keyが同じ場合はcallback差を根拠に複数回実行しない。
			if( previous.providerId == registration.providerId &&
			   previous.rootResourceId == registration.rootResourceId &&
			   previous.kind == registration.kind) {
				return false ;
			}
		}
	}

	// 自動探索能力を宣言した全Providerが少なくとも一つのregistrationを持つことを確認する。
	for( const ProviderDescriptor &descriptor : descriptors) {
		// 自動探索Provider以外を別一覧へ登録することは要求しない。
		if( !isOfficialDiscoveryProvider( descriptor)) {
			continue ;
		}

		// Capabilityだけを宣言した実行不能Providerをregistryへ残さない。
		if( std::none_of( registrations.begin(), registrations.end(),
						[&descriptor]( const auto &registration) {
							return registration.providerId == descriptor.id ;
						})) {
			return false ;
		}
	}

	return true ;
}

/** @see official_discovery_planner.h */
std::optional<OfficialDiscoveryRoutePlan> makeOfficialDiscoveryRoutePlan(
	const OfficialDiscoveryBinding &binding, const OfficialDiscoveryRequest &request,
	const bool inventoryComplete, const std::span<const OfficialDiscoveryDeviceHint> devices,
	const std::span<const OfficialDiscoveryRegistration> registrations,
	const std::span<const ProviderDescriptor>			 descriptors)
{
	// 不完全・空・過大snapshotまたは不正な開始契約から部分planを作らない。
	if( !isOfficialDiscoveryBindingValid( binding) || !inventoryComplete || devices.empty() ||
	   devices.size() > OFFICIAL_DISCOVERY_DEVICE_LIMIT ||
	   devices.size() > std::numeric_limits<std::uint32_t>::max() ||
	   !validateOfficialDiscoveryRequest( request, descriptors) ||
	   !validateOfficialDiscoveryRegistrations( registrations, descriptors)) {
		return std::nullopt ;
	}

	std::unordered_set<std::wstring> deviceIdentities ;	// 入力deviceの一意性検証集合。
	deviceIdentities.reserve( devices.size()) ;
	// 全hintを同じsessionへ結合し、重複identityを計画前に拒否する。
	for( const OfficialDiscoveryDeviceHint &device : devices) {
		// 一件でも不正または重複ならmatcherを呼び出さない。
		if( !validateOfficialDiscoveryDeviceHint( device, binding.scanSessionId) ||
		   !deviceIdentities.insert( device.deviceIdentity).second) {
			return std::nullopt ;
		}
	}

	OfficialDiscoveryRoutePlan plan ;	// 全route検証後だけ返す所有plan。
	plan.binding		   = binding ;
	plan.request		   = request ;
	plan.inventoryComplete = true ;
	plan.deviceCount	   = static_cast<std::uint32_t>( devices.size()) ;
	std::unordered_set<std::wstring> routedDevices ;	// 一件以上の固定rootへ対応したdevice集合。
	routedDevices.reserve( devices.size()) ;
	std::unordered_set<std::wstring> dedicatedDevices ;	// 専用routeへ対応したdevice集合。
	dedicatedDevices.reserve( devices.size()) ;
	std::uint64_t nextRouteId = 1U ;	// 専用から汎用へ単調増加するroute ID。
	// Route種別の固定順で計画し、registrationの入力順へ意味を持たせない。
	for( const OfficialDiscoveryRouteKind kind :
		{OfficialDiscoveryRouteKind::DEDICATED,
		 OfficialDiscoveryRouteKind::GENERIC_OFFICIAL_ROOT}) {
		// Provider registryの正本順でselected Providerだけを計画する。
		for( const ProviderDescriptor &descriptor : descriptors) {
			// 今回未選択または自動探索能力のないProviderはrouteを作らない。
			if( !isDiscoveryProviderSelected( request, descriptor) ||
			   !isOfficialDiscoveryProvider( descriptor)) {
				continue ;
			}

			// 同じProviderと種別に属する固定root registrationを全て確認する。
			for( const OfficialDiscoveryRegistration &registration : registrations) {
				// 別Providerまたは別route種別を現在の段階へ混在させない。
				if( registration.providerId != descriptor.id || registration.kind != kind) {
					continue ;
				}

				std::map<std::wstring, std::vector<std::wstring>>
					groups ;	// 正規化hint別device集合。
				// Matcherに合うdeviceを表示値非公開の比較keyへまとめる。
				for( const OfficialDiscoveryDeviceHint &device : devices) {
					// 対象外deviceは別registrationの判定へ残す。
					if( !registration.matcher( device)) {
						continue ;
					}

					groups[makeRoutingGroupKey( device)].push_back( device.deviceIdentity) ;
					routedDevices.insert( device.deviceIdentity) ;
					// 専用adapterへの対応を汎用だけのdeviceと区別する。
					if( registration.kind == OfficialDiscoveryRouteKind::DEDICATED) {
						dedicatedDevices.insert( device.deviceIdentity) ;
					}
				}

				// Key順で同じ正規化hintを一routeへまとめ、出力へ表示値を残さない。
				for( auto &[groupKey, identities] : groups) {
					(void)groupKey ;	// Map順序だけに使いrouteへ複製しない端末内key。
					// 固定上限を超える場合は一部routeを返さずplan全体を拒否する。
					if( plan.routes.size() >= OFFICIAL_DISCOVERY_ROUTE_LIMIT ||
					   nextRouteId == std::numeric_limits<std::uint64_t>::max()) {
						return std::nullopt ;
					}

					OfficialDiscoveryRoute route ;	// 表示値とURLを含まない一実行route。
					route.routeId			= nextRouteId++ ;
					route.providerId		= registration.providerId ;
					route.rootResourceId	= registration.rootResourceId ;
					route.kind				= registration.kind ;
					route.hintGroupIdentity = makeHintGroupIdentity( route.routeId) ;
					route.deviceIdentities	= std::move( identities) ;
					plan.routes.push_back( std::move( route)) ;
				}
			}
		}
	}

	// 専用欠損と固定rootなしを入力順の別集合へ分類する。
	for( const OfficialDiscoveryDeviceHint &device : devices) {
		// どの固定rootにも対応しないdeviceだけをno trusted rootへ置く。
		if( !routedDevices.contains( device.deviceIdentity)) {
			plan.noTrustedRootDeviceIdentities.push_back( device.deviceIdentity) ;
			continue ;
		}

		// 汎用routeだけに対応するdeviceは専用adapter欠損として別に保持する。
		if( !dedicatedDevices.contains( device.deviceIdentity)) {
			plan.dedicatedUnavailableDeviceIdentities.push_back( device.deviceIdentity) ;
		}
	}

	// 自身で生成したplanも公開前validatorへ通し、内部不整合を値なしにする。
	if( !isOfficialDiscoveryRoutePlanValid( binding, request, devices, registrations, descriptors,
										  plan)) {
		return std::nullopt ;
	}

	return plan ;
}

/** @see official_discovery_planner.h */
bool isOfficialDiscoveryRoutePlanValid(
	const OfficialDiscoveryBinding &binding, const OfficialDiscoveryRequest &request,
	const std::span<const OfficialDiscoveryDeviceHint>	 devices,
	const std::span<const OfficialDiscoveryRegistration> registrations,
	const std::span<const ProviderDescriptor> descriptors, const OfficialDiscoveryRoutePlan &plan)
{
	// Binding、request、完全inventory、有限件数、registryを一括で再検証する。
	if( !isOfficialDiscoveryBindingValid( binding) || plan.binding != binding ||
	   plan.request != request || !plan.inventoryComplete || devices.empty() ||
	   devices.size() > OFFICIAL_DISCOVERY_DEVICE_LIMIT ||
	   devices.size() > std::numeric_limits<std::uint32_t>::max() ||
	   plan.deviceCount != static_cast<std::uint32_t>( devices.size()) ||
	   plan.routes.size() > OFFICIAL_DISCOVERY_ROUTE_LIMIT ||
	   !validateOfficialDiscoveryRequest( request, descriptors) ||
	   !validateOfficialDiscoveryRegistrations( registrations, descriptors)) {
		return false ;
	}

	std::unordered_set<std::wstring> inputDevices ;	// 入力hintの一意なopaque identity集合。
	inputDevices.reserve( devices.size()) ;
	// 全入力hintを同じsessionへ再結合する。
	for( const OfficialDiscoveryDeviceHint &device : devices) {
		// 不正または重複deviceをroute参照の正本にしない。
		if( !validateOfficialDiscoveryDeviceHint( device, binding.scanSessionId) ||
		   !inputDevices.insert( device.deviceIdentity).second) {
			return false ;
		}
	}

	std::unordered_set<std::wstring> routedDevices ;	// 有効routeが参照したdevice集合。
	routedDevices.reserve( devices.size()) ;
	std::unordered_set<std::wstring> dedicatedDevices ;	// 専用routeが参照したdevice集合。
	dedicatedDevices.reserve( devices.size()) ;
	std::vector<std::wstring> executionKeys ;	// 正規化hintを含む重複実行検査key。
	executionKeys.reserve( plan.routes.size()) ;
	OfficialDiscoveryRouteKind previousKind = OfficialDiscoveryRouteKind::DEDICATED ;	// 順序検証値。
	// 全routeを1始まりID、専用優先、固定registrationへ再結合する。
	for( std::size_t routeIndex = 0U; routeIndex < plan.routes.size(); ++routeIndex) {
		const OfficialDiscoveryRoute		&route = plan.routes[routeIndex] ;	// 現在の出力route。
		const OfficialDiscoveryRegistration *registration =
			// 対応する唯一の実行adapter。
			findRouteRegistration( route, registrations) ;
		// Route自身、ID、group identity、selected Provider、registrationを確認する。
		if( route.routeId != routeIndex + 1U ||
		   route.hintGroupIdentity != makeHintGroupIdentity( route.routeId) ||
		   !validateOfficialDiscoveryRoute( route, devices, descriptors) ||
		   registration == nullptr) {
			return false ;
		}

		const auto descriptor =
			std::find_if( descriptors.begin(), descriptors.end(), [&route]( const auto &candidate) {
				return candidate.id == route.providerId ;
			}) ; // Routeが参照するProvider正本。
		// 未選択Providerをplanへ追加しない。
		if( descriptor == descriptors.end() || !isDiscoveryProviderSelected( request, *descriptor)) {
			return false ;
		}

		// 汎用route開始後に専用routeへ戻るplanを許可しない。
		if( previousKind == OfficialDiscoveryRouteKind::GENERIC_OFFICIAL_ROOT &&
		   route.kind == OfficialDiscoveryRouteKind::DEDICATED) {
			return false ;
		}

		previousKind = route.kind ;

		std::optional<std::wstring> groupKey ;	// Route内全deviceで一致させる正規化hint。
		// 全device参照がmatcher対象で同じgroup keyを持つか確認する。
		for( const std::wstring &deviceIdentity : route.deviceIdentities) {
			const auto device = std::find_if( devices.begin(), devices.end(),
											 [&deviceIdentity]( const auto &candidate) {
												 return candidate.deviceIdentity == deviceIdentity ;
											 }) ; // Opaque identityへ一致する入力hint。
			// 欠損参照やmatcher不一致を計画済みrouteとして受理しない。
			if( device == devices.end() || !registration->matcher( *device)) {
				return false ;
			}

			const std::wstring currentGroupKey =
				// 現在hintの比較key。
				makeRoutingGroupKey( *device) ;
			// 最初のdeviceと異なる正規化hintを同じrouteへ混在させない。
			if( groupKey && *groupKey != currentGroupKey) {
				return false ;
			}

			groupKey = currentGroupKey ;
			routedDevices.insert( deviceIdentity) ;
			// 専用adapterへ対応するdeviceを汎用だけの集合から除外する。
			if( route.kind == OfficialDiscoveryRouteKind::DEDICATED) {
				dedicatedDevices.insert( deviceIdentity) ;
			}
		}

		// 空routeは前段validatorが拒否するため、比較key欠損も内部矛盾として拒否する。
		if( !groupKey) {
			return false ;
		}

		std::wstring executionKey = route.providerId ;	// Providerから始める端末内重複検査key。
		executionKey.push_back( L'\x1F') ;
		executionKey.append( route.rootResourceId) ;
		executionKey.push_back( L'\x1F') ;
		executionKey.append( std::to_wstring( static_cast<std::uint32_t>( route.kind))) ;
		executionKey.push_back( L'\x1F') ;
		executionKey.append( *groupKey) ;
		// 同じProvider、root、種別、正規化hintを一sessionで複数回計画しない。
		if( std::find( executionKeys.begin(), executionKeys.end(), executionKey) !=
		   executionKeys.end()) {
			return false ;
		}

		executionKeys.push_back( std::move( executionKey)) ;
	}

	std::unordered_set<std::wstring> dedicatedUnavailableDevices ;	// 専用欠損出力の重複検査集合。
	dedicatedUnavailableDevices.reserve( plan.dedicatedUnavailableDeviceIdentities.size()) ;
	// 専用adapter欠損deviceを汎用routeへ対応した入力だけに限定する。
	for( const std::wstring &deviceIdentity : plan.dedicatedUnavailableDeviceIdentities) {
		// 未知、重複、未routeまたは専用route済みdeviceを欠損集合へ入れない。
		if( !inputDevices.contains( deviceIdentity) || !routedDevices.contains( deviceIdentity) ||
		   dedicatedDevices.contains( deviceIdentity) ||
		   !dedicatedUnavailableDevices.insert( deviceIdentity).second) {
			return false ;
		}
	}

	std::unordered_set<std::wstring> noTrustedRootDevices ;	// 未route出力の重複検査集合。
	noTrustedRootDevices.reserve( plan.noTrustedRootDeviceIdentities.size()) ;
	// 未route deviceを入力集合へ完全一致させる。
	for( const std::wstring &deviceIdentity : plan.noTrustedRootDeviceIdentities) {
		// 未知、重複またはroute済みdeviceをNO_TRUSTED_ROOTへ重ねない。
		if( !inputDevices.contains( deviceIdentity) || routedDevices.contains( deviceIdentity) ||
		   !noTrustedRootDevices.insert( deviceIdentity).second) {
			return false ;
		}
	}

	// 全input deviceがroute済みまたはno trusted rootのどちらか一方に存在することを確認する。
	for( const OfficialDiscoveryDeviceHint &device : devices) {
		const bool routed = routedDevices.contains( device.deviceIdentity) ;	// Route参照の有無。
		const bool noRoot =
			// 未route記録の有無。
			noTrustedRootDevices.contains( device.deviceIdentity) ;
		const bool dedicated =
			// 専用routeの有無。
			dedicatedDevices.contains( device.deviceIdentity) ;
		const bool dedicatedUnavailable =
			// 専用欠損記録の有無。
			dedicatedUnavailableDevices.contains( device.deviceIdentity) ;
		// 欠落、重複または専用有無と欠損集合の矛盾を拒否する。
		if( routed == noRoot || dedicatedUnavailable != (routed && !dedicated)) {
			return false ;
		}
	}

	return true ;
}

} // namespace drivercrate
