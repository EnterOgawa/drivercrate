//------------------------------------------------------------------------------
/**
 * @file official_discovery.cpp
 * @brief 公式自動探索のrequest、device、route、summary検証実装。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  自動探索の値型と厳格validatorを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Planner実行状態と未route device検証を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  一scan承認の固定要求変換と予算検証を追加。
 * </pre>
 *
 * @note 検証はI/Oを行わず、入力に含まれないURL、端末識別子、Providerを推測しません。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#include "core/official_discovery.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <string_view>

namespace drivercrate {
namespace {

// 全Provider capabilityの既知bit集合。
constexpr ProviderCapabilityMask KNOWN_PROVIDER_CAPABILITIES = 0x3FFU ;
// 相互排他的な四つのProvider trust boundary bit集合。
constexpr ProviderCapabilityMask PROVIDER_TRUST_BOUNDARIES = 0xF0U ;

/**
 * @brief Provider、resource、opaque identityに使用する有限ASCII表記を検証する。
 * @param[in] value 検証する文字列。
 * @param[in] maximumCharacters 許可する最大文字数。
 * @return 非空かつ許可文字だけで上限内の場合true。
 */
[[nodiscard]] bool				 isBoundedIdentifier( const std::wstring_view value,
													 const std::size_t		 maximumCharacters) noexcept
{
	// 空値、過大値、埋込みNULを識別子として後続処理へ渡さない。
	if( value.empty() || value.size() > maximumCharacters ||
	   value.find( L'\0') != std::wstring_view::npos) {
		return false ;
	}

	// URL、path、生PnP IDを表現できない限定ASCII集合だけを許可する。
	for( const wchar_t character : value) {
		// ASCII英数字ならtrue。
		const bool alphaNumeric = (character >= L'a' && character <= L'z') ||
								  (character >= L'A' && character <= L'Z') ||
								  (character >= L'0' && character <= L'9') ;
		// 区切り用途以外の文字があればopaque値として受理しない。
		if( !alphaNumeric && character != L'-' && character != L'_' && character != L'.' &&
		   character != L':') {
			return false ;
		}
	}

	return true ;
}

/**
 * @brief Local表示hintに制御文字、生PnP ID形式、過大値がないか検証する。
 * @param[in] value 検証する空を許す表示値。
 * @return 空または上限内の非機密表示値の場合true。
 */
[[nodiscard]] bool isBoundedDisplayHint( const std::wstring_view value) noexcept
{
	// 上限超過とWindows識別子の区切りをroute DTOへ複製させない。
	if( value.size() > OFFICIAL_DISCOVERY_DISPLAY_VALUE_LIMIT ||
	   value.find( L'\\') != std::wstring_view::npos) {
		return false ;
	}

	// 改行、埋込みNUL、その他の制御文字をnetwork hintやUIへ渡さない。
	for( const wchar_t character : value) {
		// 表示値にはASCII controlを許可しない。
		if( character < L' ') {
			return false ;
		}
	}

	return true ;
}

/**
 * @brief Setup class GUIDのcanonical波括弧表記を検証する。
 * @param[in] value 検証するGUID文字列。
 * @return 8-4-4-4-12桁の16進表記の場合true。
 */
[[nodiscard]] bool isCanonicalGuid( const std::wstring_view value) noexcept
{
	// 固定長と波括弧を満たさない値をclass識別子として扱わない。
	if( value.size() != 38U || value.front() != L'{' || value.back() != L'}') {
		return false ;
	}

	// 区切り位置以外を16進文字に限定し、別形式を推測で正規化しない。
	for( std::size_t index = 1U; index + 1U < value.size(); ++index) {
		const wchar_t character = value[index] ;	// 現在検証するGUID文字。
		// Canonical GUIDでハイフンを置く固定位置ならtrue。
		const bool	  separator = index == 9U || index == 14U || index == 19U || index == 24U ;
		// 固定位置のハイフン以外は16進一文字を必須にする。
		if( separator) {
			// 区切り位置へ別文字があるGUIDを拒否する。
			if( character != L'-') {
				return false ;
			}
		} else {
			// GUIDで許可するASCII 16進文字ならtrue。
			const bool hexadecimal = (character >= L'0' && character <= L'9') ||
									 (character >= L'a' && character <= L'f') ||
									 (character >= L'A' && character <= L'F') ;
			// 16進以外の文字を含むGUIDを拒否する。
			if( !hexadecimal) {
				return false ;
			}
		}
	}

	return true ;
}

/**
 * @brief 有限bus enumが定義済みか検証する。
 * @param[in] bus 検証するbus値。
 * @return UNKNOWNを含む定義済み値の場合true。
 */
[[nodiscard]] bool isKnownBus( const OfficialDiscoveryDeviceBus bus) noexcept
{
	return bus >= OfficialDiscoveryDeviceBus::PCI && bus <= OfficialDiscoveryDeviceBus::UNKNOWN ;
}

/**
 * @brief Inspection permissionが定義済みか検証する。
 * @param[in] permission 検証する権限値。
 * @return 二つの定義済み値のいずれかの場合true。
 */
[[nodiscard]] bool isKnownInspectionPermission(
	const OfficialDiscoveryInspectionPermission permission) noexcept
{
	return permission == OfficialDiscoveryInspectionPermission::METADATA_ONLY ||
		   permission == OfficialDiscoveryInspectionPermission::ALLOW_VERIFIED_DRIVER_PACKAGE ;
}

/**
 * @brief Cache modeが定義済みか検証する。
 * @param[in] mode 検証するcache mode。
 * @return 二つの定義済み値のいずれかの場合true。
 */
[[nodiscard]] bool isKnownCacheMode( const OfficialDiscoveryCacheMode mode) noexcept
{
	return mode == OfficialDiscoveryCacheMode::USE_FRESH ||
		   mode == OfficialDiscoveryCacheMode::FORCE_REFRESH ;
}

/**
 * @brief Route種別が定義済みか検証する。
 * @param[in] kind 検証するroute種別。
 * @return 専用または汎用固定rootの場合true。
 */
[[nodiscard]] bool isKnownRouteKind( const OfficialDiscoveryRouteKind kind) noexcept
{
	return kind == OfficialDiscoveryRouteKind::DEDICATED ||
		   kind == OfficialDiscoveryRouteKind::GENERIC_OFFICIAL_ROOT ;
}

/**
 * @brief Route状態が定義済みか検証する。
 * @param[in] state 検証するroute状態。
 * @return ADR 0157で定めた有限状態の場合true。
 */
[[nodiscard]] bool isKnownRouteState( const OfficialDiscoveryRouteState state) noexcept
{
	return state >= OfficialDiscoveryRouteState::NOT_STARTED &&
		   state <= OfficialDiscoveryRouteState::METADATA_REJECTED ;
}

/**
 * @brief Provider IDを重複のないregistry定義へ解決する。
 * @param[in] providerId 完全一致で検索するstable ID。
 * @param[in] descriptors 検索するProvider定義集合。
 * @return 一意な一致があればその要素、なければnullptr。
 */
[[nodiscard]] const ProviderDescriptor *findUniqueProvider(
	const std::wstring_view					  providerId,
	const std::span<const ProviderDescriptor> descriptors) noexcept
{
	const ProviderDescriptor *found{} ;	// 一件目の完全一致だけを借用する。
	// Registry全体を走査し、同じIDが二件あれば曖昧な権限解決を拒否する。
	for( const ProviderDescriptor &descriptor : descriptors) {
		// IDが一致しない登録は検索対象として読み飛ばす。
		if( descriptor.id != providerId) {
			continue ;
		}

		// 二件目の一致を検出した場合は一意な結果を返さない。
		if( found != nullptr) {
			return nullptr ;
		}

		found = &descriptor ;
	}

	return found ;
}

/**
 * @brief Route summaryの状態、診断、有限件数の整合性を検証する。
 * @param[in] route 開始時に検証した元route。
 * @param[in] summary Workerが返した一routeの集計。
 * @return 元routeとの結合と状態別件数が矛盾しない場合true。
 */
[[nodiscard]] bool isRouteSummaryValidInternal(
	const OfficialDiscoveryRoute &route, const OfficialDiscoveryRouteSummary &summary) noexcept
{
	// Identity、Provider、種別、device件数を元routeから推測せず完全一致させる。
	if( summary.routeId != route.routeId || summary.providerId != route.providerId ||
	   summary.kind != route.kind || !isKnownRouteState( summary.state) ||
	   route.deviceIdentities.size() > std::numeric_limits<std::uint32_t>::max() ||
	   summary.deviceCount != static_cast<std::uint32_t>( route.deviceIdentities.size()) ||
	   summary.recordCount > OFFICIAL_DISCOVERY_DEVICE_LIMIT ||
	   summary.packageCount > OFFICIAL_DISCOVERY_DEVICE_LIMIT) {
		return false ;
	}

	// Native errorを必須にする三つの失敗状態ならtrue。
	const bool diagnosticState = summary.state == OfficialDiscoveryRouteState::FAILED ||
								 summary.state == OfficialDiscoveryRouteState::SOURCE_REJECTED ||
								 summary.state == OfficialDiscoveryRouteState::METADATA_REJECTED ;
	// 診断状態だけに非ゼロerrorを要求し、成功や未実行へ失敗値を混入させない。
	if( diagnosticState != (summary.error != 0)) {
		return false ;
	}

	// 一件以上のrecordを必要とする解決済み状態ならtrue。
	const bool resolved = summary.state == OfficialDiscoveryRouteState::CACHE_POSITIVE ||
						  summary.state == OfficialDiscoveryRouteState::DEDICATED_RESOLVED ||
						  summary.state == OfficialDiscoveryRouteState::GENERIC_RESOLVED ;
	// 解決状態には一件以上のrecordを要求し、候補0件表示と区別する。
	if( resolved && summary.recordCount == 0U) {
		return false ;
	}

	// 専用または汎用の成功状態を異なるroute種別へ付け替えない。
	if( (summary.state == OfficialDiscoveryRouteState::DEDICATED_RESOLVED &&
		summary.kind != OfficialDiscoveryRouteKind::DEDICATED) ||
	   (summary.state == OfficialDiscoveryRouteState::GENERIC_RESOLVED &&
		summary.kind != OfficialDiscoveryRouteKind::GENERIC_OFFICIAL_ROOT) ||
	   (summary.state == OfficialDiscoveryRouteState::SKIPPED_AFTER_DEDICATED &&
		summary.kind != OfficialDiscoveryRouteKind::GENERIC_OFFICIAL_ROOT)) {
		return false ;
	}

	// Recordとpackageの両件数を0に限定する正常な空結果ならtrue。
	const bool emptyResult = summary.state == OfficialDiscoveryRouteState::CACHE_NEGATIVE ||
							 summary.state == OfficialDiscoveryRouteState::NO_RECORD ;
	// 否定cacheまたは正常なrecordなしへrecord／packageを残さない。
	if( emptyResult && (summary.recordCount != 0U || summary.packageCount != 0U)) {
		return false ;
	}

	// Recordとpackageがあるまま個別EULAを待つ状態ならtrue。
	const bool waitingForEula = summary.state == OfficialDiscoveryRouteState::AWAITING_EULA ;
	// EULA待ちは対象となるrecordとdriver packageが両方存在する場合だけ許可する。
	if( waitingForEula && (summary.recordCount == 0U || summary.packageCount == 0U)) {
		return false ;
	}

	// 解決済み件数を保持できない未実行または失敗状態ならtrue。
	const bool noPayloadResult =
		summary.state == OfficialDiscoveryRouteState::NOT_STARTED ||
		summary.state == OfficialDiscoveryRouteState::DISABLED ||
		summary.state == OfficialDiscoveryRouteState::NOT_ROUTABLE ||
		summary.state == OfficialDiscoveryRouteState::SKIPPED_AFTER_DEDICATED ||
		summary.state == OfficialDiscoveryRouteState::NO_TRUSTED_ROOT ||
		summary.state == OfficialDiscoveryRouteState::NETWORK_NOT_APPROVED ||
		summary.state == OfficialDiscoveryRouteState::BUDGET_EXCEEDED ||
		summary.state == OfficialDiscoveryRouteState::CANCELLED || diagnosticState ;
	// 未実行または失敗状態に解決済み件数を残して部分成功へ見せない。
	if( noPayloadResult && (summary.recordCount != 0U || summary.packageCount != 0U)) {
		return false ;
	}

	// Package数がある結果には必ず対応するmetadata recordを要求する。
	return summary.packageCount == 0U || summary.recordCount != 0U ;
}

} // namespace

/** @see official_discovery.h */
bool isOfficialDiscoveryRouteSummaryValid( const OfficialDiscoveryRoute		  &route,
										  const OfficialDiscoveryRouteSummary &summary) noexcept
{
	return isRouteSummaryValidInternal( route, summary) ;
}

/** @see official_discovery.h */
bool isOfficialDiscoveryProvider( const ProviderDescriptor &descriptor) noexcept
{
	// 自動探索Providerに必須のoperationとtrust boundary bit。
	const auto required = capabilityMask( ProviderCapability::SCAN) |
						  capabilityMask( ProviderCapability::OFFICIAL_NETWORK) |
						  capabilityMask( ProviderCapability::AUTOMATIC_DISCOVERY) ;
	// 未知bit、複数trust boundary、必須能力欠落を自動探索入口として受理しない。
	if( descriptor.id.empty() || descriptor.capabilities == 0U ||
	   (descriptor.capabilities & ~KNOWN_PROVIDER_CAPABILITIES) != 0U ||
	   (descriptor.capabilities & required) != required ||
	   (descriptor.capabilities & PROVIDER_TRUST_BOUNDARIES) !=
		   capabilityMask( ProviderCapability::OFFICIAL_NETWORK)) {
		return false ;
	}

	const auto *policy = officialSourcePolicyForProvider( descriptor.id) ;	// 固定公式policy。
	return policy != nullptr && descriptor.officialSourcePolicyId == policy->id ;
}

/** @see official_discovery.h */
bool validateOfficialDiscoveryRequest(
	const OfficialDiscoveryRequest			 &request,
	const std::span<const ProviderDescriptor> descriptors) noexcept
{
	// 未知policy、purpose、権限、cache mode、過大registryを通信前に拒否する。
	const OfficialDiscoveryMetadataLimits metadataLimits ;	// 製品固定metadata予算。
	const OfficialDiscoveryPayloadLimits  payloadLimits ;	// 製品固定payload予算。
	// 固定契約から外れるfieldを一件でも含む要求はProvider選択へ進めない。
	if( request.policyId != OFFICIAL_DISCOVERY_POLICY_ID ||
	   request.policyRevision != OFFICIAL_DISCOVERY_POLICY_REVISION ||
	   (request.purpose != ScanPurpose::STANDARD &&
		request.purpose != ScanPurpose::METADATA_ONLY) ||
	   !isKnownInspectionPermission( request.inspectionPermission) ||
	   !isKnownCacheMode( request.cacheMode) || request.metadataLimits != metadataLimits ||
	   request.payloadLimits != payloadLimits || descriptors.empty() ||
	   descriptors.size() > OFFICIAL_DISCOVERY_PROVIDER_LIMIT ||
	   request.enabledProviderIds.size() > OFFICIAL_DISCOVERY_PROVIDER_LIMIT) {
		return false ;
	}

	// Metadata専用purposeからpayload取得権限へ拡張する要求を拒否する。
	if( request.purpose == ScanPurpose::METADATA_ONLY &&
	   request.inspectionPermission != OfficialDiscoveryInspectionPermission::METADATA_ONLY) {
		return false ;
	}

	// Registry IDを一意な有限ASCII値へ限定し、検索順で権限を解決しない。
	for( std::size_t index = 0U; index < descriptors.size(); ++index) {
		const ProviderDescriptor &descriptor = descriptors[index] ;	// 現在の登録定義。
		// 不正または重複IDが一件でもあればregistry全体を拒否する。
		if( !isBoundedIdentifier( descriptor.id, OFFICIAL_DISCOVERY_STABLE_ID_LIMIT) ||
		   std::count_if( descriptors.begin(), descriptors.end(), [&descriptor]( const auto &item) {
			   return item.id == descriptor.id ;
		   }) != 1) {
			return false ;
		}
	}

	// 既定集合と明示集合を混在させず、空の明示集合も全Providerへ読み替えない。
	if( request.useDefaultProviders != request.enabledProviderIds.empty()) {
		return false ;
	}

	std::size_t selectedCount{} ;	// 自動探索能力を持つ有効Provider数。
	// Registry正本から今回の対象集合を解決する。
	for( const ProviderDescriptor &descriptor : descriptors) {
		// 明示集合にIDが完全一致する場合だけtrue。
		const bool explicitlySelected =
			std::find( request.enabledProviderIds.begin(), request.enabledProviderIds.end(),
					  descriptor.id) != request.enabledProviderIds.end() ;
		// 既定または明示のどちらか一方の規則で今回有効ならtrue。
		const bool selected =
			request.useDefaultProviders ? descriptor.enabledByDefault : explicitlySelected ;
		// 今回の対象でないProviderは能力検証の対象から除外する。
		if( !selected) {
			continue ;
		}

		// WUA等の同一scan対象は維持し、自動探索能力を持つ公式Providerだけを計数する。
		if( isOfficialDiscoveryProvider( descriptor)) {
			++selectedCount ;
		}
	}

	// 明示IDが全て一意でregistryに存在するかを個別に確認する。
	for( const std::wstring &providerId : request.enabledProviderIds) {
		// 重複または未登録IDを既定集合で補完しない。
		if( std::count( request.enabledProviderIds.begin(), request.enabledProviderIds.end(),
					  providerId) != 1 ||
		   findUniqueProvider( providerId, descriptors) == nullptr) {
			return false ;
		}
	}

	return selectedCount != 0U ;
}

/** @see official_discovery.h */
std::optional<OfficialDiscoveryRequest> makeStandardOfficialDiscoveryRequest(
	const ScanOptions &options, const std::span<const ProviderDescriptor> descriptors) noexcept
{
	// 構造不正、旧個別同意、または新しい一scan承認のない入力を自動探索へ変換しない。
	if( !validateScanOptions( options) || !options.officialDiscoveryApproval.has_value()) {
		return std::nullopt ;
	}

	const OfficialDiscoveryScanApproval &approval =
		*options.officialDiscoveryApproval ;	// UIが表示した変更不可の承認snapshot。
	OfficialDiscoveryRequest request ;			// Core executorへ渡す権限縮小なしの所有値。
	request.purpose					  = ScanPurpose::STANDARD ;
	request.useDefaultProviders		  = options.useDefaultProviders ;
	request.enabledProviderIds		  = options.enabledProviderIds ;
	request.inspectionPermission	  = approval.inspectionPermission ;
	request.restrictedNetworkApproved = approval.restrictedNetworkApproved ;
	request.cacheMode				  = approval.cacheMode ;
	request.metadataLimits			  = approval.metadataLimits ;
	request.payloadLimits			  = approval.payloadLimits ;
	// Provider scopeと自動探索能力まで整合する場合だけrequestを公開する。
	if( !validateOfficialDiscoveryRequest( request, descriptors)) {
		return std::nullopt ;
	}

	return request ;
}

/** @see official_discovery.h */
bool isOfficialDiscoveryBindingValid( const OfficialDiscoveryBinding &binding) noexcept
{
	return binding.operationId != 0U && binding.scanSessionId != 0U &&
		   binding.inventoryGeneration != 0U ;
}

/** @see official_discovery.h */
bool validateOfficialDiscoveryDeviceHint( const OfficialDiscoveryDeviceHint &hint,
										 const ScanSessionId				scanSessionId) noexcept
{
	// Opaque identity、有限bus、canonical class、表示値を一括で検証する。
	if( scanSessionId == 0U ||
	   !isBoundedIdentifier( hint.deviceIdentity, OFFICIAL_DISCOVERY_OPAQUE_ID_LIMIT) ||
	   !isKnownBus( hint.bus) || !isCanonicalGuid( hint.setupClassGuid) ||
	   !isBoundedDisplayHint( hint.deviceClass) || !isBoundedDisplayHint( hint.manufacturer) ||
	   !isBoundedDisplayHint( hint.model) || !isBoundedDisplayHint( hint.currentProvider)) {
		return false ;
	}

	return isDeviceObservationBound( hint.observation, scanSessionId, hint.deviceIdentity) ;
}

/** @see official_discovery.h */
bool validateOfficialDiscoveryRoute( const OfficialDiscoveryRoute					  &route,
									const std::span<const OfficialDiscoveryDeviceHint> devices,
									const std::span<const ProviderDescriptor> descriptors) noexcept
{
	// 空・過大・未知routeをregistryやinventoryから推測して補完しない。
	if( route.routeId == 0U ||
	   !isBoundedIdentifier( route.providerId, OFFICIAL_DISCOVERY_STABLE_ID_LIMIT) ||
	   !isBoundedIdentifier( route.rootResourceId, OFFICIAL_DISCOVERY_STABLE_ID_LIMIT) ||
	   !isBoundedIdentifier( route.hintGroupIdentity, OFFICIAL_DISCOVERY_OPAQUE_ID_LIMIT) ||
	   !isKnownRouteKind( route.kind) || route.deviceIdentities.empty() ||
	   route.deviceIdentities.size() > OFFICIAL_DISCOVERY_DEVICE_LIMIT || devices.empty() ||
	   devices.size() > OFFICIAL_DISCOVERY_DEVICE_LIMIT || descriptors.empty() ||
	   descriptors.size() > OFFICIAL_DISCOVERY_PROVIDER_LIMIT) {
		return false ;
	}

	const ProviderDescriptor *descriptor =
		// Routeの登録正本。
		findUniqueProvider( route.providerId, descriptors) ;
	// 未登録または自動探索未対応Providerへrouteを接続しない。
	if( descriptor == nullptr || !isOfficialDiscoveryProvider( *descriptor)) {
		return false ;
	}

	const auto *policy = officialSourcePolicyForProvider( descriptor->id) ;	// 固定公式policy。
	const auto *resource =
		policy == nullptr ? nullptr
						  : findOfficialSourceResource( *policy, route.rootResourceId) ;	// 固定root。
	// Landingまたはmetadata用途の登録済みresourceだけを探索起点として許可する。
	if( resource == nullptr || (resource->kind != OfficialSourceResourceKind::LANDING_PAGE &&
							   resource->kind != OfficialSourceResourceKind::METADATA)) {
		return false ;
	}

	// Route内deviceを一意なinventory要素へ完全一致で解決する。
	for( const std::wstring &deviceIdentity : route.deviceIdentities) {
		// 生ID形式や重複したopaque identityをrouteへ残さない。
		if( !isBoundedIdentifier( deviceIdentity, OFFICIAL_DISCOVERY_OPAQUE_ID_LIMIT) ||
		   std::count( route.deviceIdentities.begin(), route.deviceIdentities.end(),
					  deviceIdentity) != 1 ||
		   std::count_if( devices.begin(), devices.end(), [&deviceIdentity]( const auto &device) {
			   return device.deviceIdentity == deviceIdentity ;
		   }) != 1) {
			return false ;
		}
	}

	return true ;
}

/** @see official_discovery.h */
bool isOfficialDiscoverySummaryValid( const OfficialDiscoveryBinding					   &binding,
									 const OfficialDiscoveryRequest					   &request,
									 const std::span<const OfficialDiscoveryDeviceHint> devices,
									 const std::span<const OfficialDiscoveryRoute>		routes,
									 const OfficialDiscoverySummary					   &summary,
									 const std::span<const ProviderDescriptor> descriptors) noexcept
{
	// 開始時snapshot、完全inventory、有限件数、一対一route数を公開境界で照合する。
	if( !isOfficialDiscoveryBindingValid( binding) || summary.binding != binding ||
	   summary.request != request || !summary.inventoryComplete || devices.empty() ||
	   devices.size() > OFFICIAL_DISCOVERY_DEVICE_LIMIT ||
	   devices.size() > std::numeric_limits<std::uint32_t>::max() ||
	   summary.deviceCount != static_cast<std::uint32_t>( devices.size()) ||
	   routes.size() > OFFICIAL_DISCOVERY_ROUTE_LIMIT || summary.routes.size() != routes.size() ||
	   summary.dedicatedUnavailableDeviceIdentities.size() > devices.size() ||
	   summary.noTrustedRootDeviceIdentities.size() > devices.size() ||
	   !validateOfficialDiscoveryRequest( request, descriptors)) {
		return false ;
	}

	// 全device hintを同じscan sessionへ結合し、重複identityを拒否する。
	for( const OfficialDiscoveryDeviceHint &device : devices) {
		// 一件でも不正または重複ならsummary全体を公開しない。
		if( !validateOfficialDiscoveryDeviceHint( device, binding.scanSessionId) ||
		   std::count_if( devices.begin(), devices.end(), [&device]( const auto &item) {
			   return item.deviceIdentity == device.deviceIdentity ;
		   }) != 1) {
			return false ;
		}
	}

	std::size_t expectedDedicatedUnavailable{} ;	// 汎用だけに含まれるdevice件数。
	std::size_t expectedNoTrustedRoot{} ;			// どのrouteにも含まれないdevice件数。
	// Plan上の専用・汎用有無から二つの非実行分類を再構築する。
	for( const OfficialDiscoveryDeviceHint &device : devices) {
		const bool dedicated = std::any_of(
			routes.begin(), routes.end(), [&device]( const OfficialDiscoveryRoute &route) {
				return route.kind == OfficialDiscoveryRouteKind::DEDICATED &&
					   std::find( route.deviceIdentities.begin(), route.deviceIdentities.end(),
								 device.deviceIdentity) != route.deviceIdentities.end() ;
			}) ; // 専用route参照の有無。
		const bool generic = std::any_of(
			routes.begin(), routes.end(), [&device]( const OfficialDiscoveryRoute &route) {
				return route.kind == OfficialDiscoveryRouteKind::GENERIC_OFFICIAL_ROOT &&
					   std::find( route.deviceIdentities.begin(), route.deviceIdentities.end(),
								 device.deviceIdentity) != route.deviceIdentities.end() ;
			}) ;													  // 汎用route参照の有無。
		const bool dedicatedUnavailable = !dedicated && generic ;	// 専用だけが欠損した分類。
		const bool noTrustedRoot		= !dedicated && !generic ;	// 固定rootがない分類。
		const auto dedicatedUnavailableCount =
			std::count( summary.dedicatedUnavailableDeviceIdentities.begin(),
					   summary.dedicatedUnavailableDeviceIdentities.end(),
					   device.deviceIdentity) ;	// 公開summary内の出現数。
		const auto noTrustedRootCount =
			std::count( summary.noTrustedRootDeviceIdentities.begin(),
					   summary.noTrustedRootDeviceIdentities.end(),
					   device.deviceIdentity) ;	// 公開summary内の出現数。
		// Deviceごとの期待分類と欠損／重複なしの出現数を一致させる。
		if( dedicatedUnavailableCount != (dedicatedUnavailable ? 1 : 0) ||
		   noTrustedRootCount != (noTrustedRoot ? 1 : 0)) {
			return false ;
		}

		expectedDedicatedUnavailable += dedicatedUnavailable ? 1U : 0U ;
		expectedNoTrustedRoot += noTrustedRoot ? 1U : 0U ;
	}

	// 未知identityを件数だけで分類済みdeviceへ混入させない。
	if( summary.dedicatedUnavailableDeviceIdentities.size() != expectedDedicatedUnavailable ||
	   summary.noTrustedRootDeviceIdentities.size() != expectedNoTrustedRoot) {
		return false ;
	}

	// 計画routeの重複、参照、registry bindingを全て検証する。
	for( std::size_t routeIndex = 0U; routeIndex < routes.size(); ++routeIndex) {
		const OfficialDiscoveryRoute &route = routes[routeIndex] ;	// 現在の元route。
		// Route IDとprovider/root/kind/hint groupが重なるplanを全体拒否する。
		for( std::size_t previousIndex = 0U; previousIndex < routeIndex; ++previousIndex) {
			const OfficialDiscoveryRoute &previous = routes[previousIndex] ;	// 先行route。
			// 同じProvider、root、種別、正規化hint groupなら重複実行keyである。
			const bool					  duplicateKey = previous.providerId == route.providerId &&
									  previous.rootResourceId == route.rootResourceId &&
									  previous.kind == route.kind &&
									  previous.hintGroupIdentity == route.hintGroupIdentity ;
			// IDまたは実行keyの重複を順序で解決しない。
			if( previous.routeId == route.routeId || duplicateKey) {
				return false ;
			}
		}

		// 一routeの不正参照を他routeの成功で隠さない。
		if( !validateOfficialDiscoveryRoute( route, devices, descriptors)) {
			return false ;
		}

		const auto detail = std::find_if( summary.routes.begin(), summary.routes.end(),
										 [&route]( const auto &candidate) {
											 return candidate.routeId == route.routeId ;
										 }) ; // 元route IDへ完全一致する公開集計。
		// Summaryの欠落、重複、状態矛盾を一件でも許可しない。
		if( detail == summary.routes.end() ||
		   std::count_if( summary.routes.begin(), summary.routes.end(),
						 [&route]( const auto &item) { return item.routeId == route.routeId ; }) !=
			   1 ||
		   !isOfficialDiscoveryRouteSummaryValid( route, *detail)) {
			return false ;
		}
	}

	return true ;
}

} // namespace drivercrate
