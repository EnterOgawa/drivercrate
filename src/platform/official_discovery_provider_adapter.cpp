//------------------------------------------------------------------------------
/**
 * @file official_discovery_provider_adapter.cpp
 * @brief 審査済みProviderの端末内matcherと固定root registrationを実装する。
 * @version 01.01.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Intel Windows 11固定root registrationを実装。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Cache失効用parser identityをregistrationへ結合。
 * </pre>
 *
 * @note Matcherは表示hintをnetworkへ渡さず、registration callbackも組み込み固定root以外のURLを
 *       入力できません。通常scanからの実行許可は別工程です。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#include "platform/official_discovery_provider_adapter.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/intel_ethernet_windows11_record_adapter.h"
#include "platform/official_release_metadata.h"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {

// Windows Net setup classのcanonical GUID。
constexpr std::wstring_view NET_SETUP_CLASS_GUID = L"{4d36e972-e325-11ce-bfc1-08002be10318}" ;
// 固定Intel pageが掲載するEthernet controller系列の表示token。
constexpr std::array		INTEL_ETHERNET_SERIES{
	   std::wstring_view( L"I210"), std::wstring_view( L"I219"),	std::wstring_view( L"I225"),
	   std::wstring_view( L"I226"), std::wstring_view( L"I350"),	std::wstring_view( L"X550"),
	   std::wstring_view( L"X710"), std::wstring_view( L"XL710"), std::wstring_view( L"XXV710"),
	   std::wstring_view( L"E610"), std::wstring_view( L"E810"),	std::wstring_view( L"E830"),
	   std::wstring_view( L"E835"), std::wstring_view( L"V710")} ;

/**
 * @brief 二つの有限文字列をWindows ordinal規則で大文字小文字を無視して比較する。
 * @param[in] left 左辺文字列。
 * @param[in] right 右辺文字列。
 * @return 同じ文字列の場合true。
 */
[[nodiscard]] bool sameText( const std::wstring_view left, const std::wstring_view right) noexcept
{
	// Win32のsigned長へ安全に変換できない入力を一致させない。
	if( left.size() > static_cast<std::size_t>( std::numeric_limits<int>::max()) ||
	   right.size() > static_cast<std::size_t>( std::numeric_limits<int>::max())) {
		return false ;
	}

	return CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

/**
 * @brief 有限文字列が指定prefixから始まるか大文字小文字を無視して確認する。
 * @param[in] value 検証する表示文字列。
 * @param[in] prefix 先頭に要求する文字列。
 * @return Prefixが完全一致する場合true。
 */
[[nodiscard]] bool startsWithText( const std::wstring_view value,
								  const std::wstring_view prefix) noexcept
{
	return value.size() >= prefix.size() && sameText( value.substr( 0U, prefix.size()), prefix) ;
}

/**
 * @brief 有限文字列が指定tokenを含むか大文字小文字を無視して確認する。
 * @param[in] value 検証する表示文字列。
 * @param[in] token 含有を要求する非空文字列。
 * @return 一箇所以上で完全一致する場合true。
 */
[[nodiscard]] bool containsText( const std::wstring_view value,
								const std::wstring_view token) noexcept
{
	// 空tokenまたは短い入力を含有成立へ変換しない。
	if( token.empty() || value.size() < token.size()) {
		return false ;
	}

	// Tokenを収められる各位置だけを走査し、最初の一致で終了する。
	for( std::size_t offset = 0U; offset <= value.size() - token.size(); ++offset) {
		// 現在位置が同じordinal文字列なら対象系列として返す。
		if( sameText( value.substr( offset, token.size()), token)) {
			return true ;
		}
	}

	return false ;
}

} // namespace

/** @see official_discovery_provider_adapter.h */
bool matchesIntelEthernetWindows11OfficialDiscoveryHint(
	const OfficialDiscoveryDeviceHint &hint) noexcept
{
	// E610を含む固定PCI Ethernet pageへUSB、仮想、未知busをrouteしない。
	if( hint.bus != OfficialDiscoveryDeviceBus::PCI ||
	   !sameText( hint.setupClassGuid, NET_SETUP_CLASS_GUID) ||
	   (!hint.deviceClass.empty() && !sameText( hint.deviceClass, L"Net"))) {
		return false ;
	}

	const bool intelModel = startsWithText( hint.model, L"Intel(R) ") ||
							startsWithText( hint.model, L"Intel® ") ||
							// Intel表示名の境界。
							startsWithText( hint.model, L"Intel ") ;
	// 空の製造元表示はmodel境界へ委ね、明示された別メーカーだけを拒否する。
	const bool intelManufacturer =
		hint.manufacturer.empty() || startsWithText( hint.manufacturer, L"Intel") ;
	// 別メーカー表示またはIntel Ethernet以外のmodelを固定pageへまとめない。
	if( !intelModel || !intelManufacturer) {
		return false ;
	}

	// 固定pageに掲載される系列tokenのいずれかだけを端末内route対象にする。
	for( const std::wstring_view series : INTEL_ETHERNET_SERIES) {
		// 一系列でも含む場合は探索先だけを確定し、適用性判定は後段へ残す。
		if( containsText( hint.model, series)) {
			return true ;
		}
	}

	return false ;
}

/** @see official_discovery_provider_adapter.h */
std::optional<std::vector<OfficialDiscoveryRegistration>> makeBuiltInOfficialDiscoveryRegistrations(
	OfficialDiscoveryRecordAdapterSession	 &recordSession,
	OfficialDiscoveryFixedRootResolver		  intelEthernetWindows11Resolver,
	OfficialRecordResolutionCancellation	  cancellation,
	const std::span<const ProviderDescriptor> descriptors)
{
	const OfficialSourceDefinition *const definition = officialSourceDefinition(
		OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11) ;	// 審査済み固定root定義。
	// 空callbackまたは組み込み定義の不整合を部分registryへ変換しない。
	if( !intelEthernetWindows11Resolver || !cancellation || definition == nullptr ||
	   definition->providerId != INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID ||
	   definition->sourceId != INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID ||
	   definition->landingUrl.empty() || definition->maximumMetadataBytes == 0U ||
	   definition->maximumMetadataBytes > OFFICIAL_DISCOVERY_RECORD_BYTES_LIMIT) {
		return std::nullopt ;
	}

	OfficialDiscoveryFixedRootAdapter fixedAdapter{
		.providerId			= INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID,
		.rootResourceId		= OFFICIAL_LANDING_RESOURCE_ID,
		.kind				= OfficialDiscoveryRouteKind::DEDICATED,
		.maximumRecordBytes = definition->maximumMetadataBytes,
		.resolver			= std::move( intelEthernetWindows11Resolver)} ;	// 固定root adapter。
	OfficialDiscoveryRegistration registration{
		.providerId		= std::wstring{definition->providerId},
		.sourcePolicyId = std::wstring{definition->sourceId},
		.rootResourceId = std::wstring{OFFICIAL_LANDING_RESOURCE_ID},
		.parserId		= std::wstring{INTEL_ETHERNET_WINDOWS11_RECORD_PARSER_ID},
		.parserRevision = INTEL_ETHERNET_WINDOWS11_RECORD_PARSER_REVISION,
		.kind			= OfficialDiscoveryRouteKind::DEDICATED,
		.matcher		= matchesIntelEthernetWindows11OfficialDiscoveryHint,
		.resolver =
			[&recordSession, fixedAdapter = std::move( fixedAdapter),
			 cancellation = std::move( cancellation)](
				const OfficialDiscoveryRequest &request, const OfficialDiscoveryRoute &route,
				const std::span<const OfficialDiscoveryDeviceHint> devices) {
				return recordSession.resolveRoute( request, route, devices, fixedAdapter,
												  cancellation) ;
			},
		.networkHintFields = OFFICIAL_DISCOVERY_NETWORK_HINT_NONE} ;	// Session借用callback。
	std::vector<OfficialDiscoveryRegistration> registrations ;			// 全件検証前の所有registry。
	registrations.push_back( std::move( registration)) ;
	// Capabilityを宣言した全Providerと固定sourceを一括検証し、不完全registryを返さない。
	if( !validateOfficialDiscoveryRegistrations( registrations, descriptors)) {
		return std::nullopt ;
	}

	return registrations ;
}

} // namespace drivercrate
