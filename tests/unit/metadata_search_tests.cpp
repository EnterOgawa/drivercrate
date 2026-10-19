//------------------------------------------------------------------------------
/**
 * @file metadata_search_tests.cpp
 * @brief 情報検索requestの拒否と非導入候補の決定的試験。
 * @version 01.00.00
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
 * </pre>
 *
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#include "metadata_search_tests.h"

#include "core/metadata_search.h"
#include "core/provider_registry.h"
#include "platform/official_release_metadata.h"
#include "test_framework.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace drivercrate::test {
namespace {
/**
 * @brief 初期Serial表示probeのtoken境界と欠損情報を決定的に検証する。
 * @param[in,out] context Assertionの集計先。
 */
void testSerialProbes( TestContext &context)
{
	OfficialCatalogDevice device ;	// 実IDを持たない合成inventory。
	device.deviceIdentity  = L"fixture-node" ;
	device.driverClass	   = L"Ports" ;
	device.deviceClassGuid = L"{4d36e978-e325-11ce-bfc1-08002be10318}" ;
	const std::array families{OfficialReleaseFamily::SILICON_LABS_CP210X,
							  OfficialReleaseFamily::WCH_CH341,
							  OfficialReleaseFamily::WCH_CH343} ;	// 初期三系列。
	const std::array tokens{L"CP210x", L"CH341", L"CH343"} ;		// 代表となる完全token。
	// 各系列を同じ欠損・矛盾fixtureで検証し、別系列への通信対象化を拒否する。
	for( std::size_t index = 0U; index < families.size(); ++index) {
		device.model = L"USB (" + std::wstring( tokens[index]) + L") Port" ;
		DRIVERCRATE_EXPECT( context, officialReleaseDeviceMatches( families[index], device)) ;
		device.model = tokens[index] ;
		DRIVERCRATE_EXPECT( context, officialReleaseDeviceMatches( families[index], device)) ;
		device.model += L"0" ;
		DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches( families[index], device)) ;
		device.model = L"X" + std::wstring( tokens[index]) ;
		DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches( families[index], device)) ;
		device.model = tokens[index] ;
		device.deviceClassGuid.clear() ;
		DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches( families[index], device)) ;
		device.deviceClassGuid = L"{4d36e972-e325-11ce-bfc1-08002be10318}" ;
		DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches( families[index], device)) ;
		device.deviceClassGuid = L"{4d36e978-e325-11ce-bfc1-08002be10318}" ;
		device.driverClass	   = L"Net" ;
		DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches( families[index], device)) ;
		device.driverClass.clear() ;
		DRIVERCRATE_EXPECT( context, officialReleaseDeviceMatches( families[index], device)) ;
		device.driverClass = L"Ports" ;
		device.model	   = L"CP210x CH341 CH343" ;
		DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches( families[index], device)) ;
		device.model = std::wstring( 513U, L' ') + tokens[index] ;
		DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches( families[index], device)) ;
		DRIVERCRATE_EXPECT( context,
						   officialReleaseOperatingSystemMatches( families[index], false, 26100U)) ;
		DRIVERCRATE_EXPECT( context,
						   !officialReleaseOperatingSystemMatches( families[index], true, 26100U)) ;
	}

	device.model = L"cp210X" ;
	DRIVERCRATE_EXPECT( context, officialReleaseDeviceMatches( families[0], device)) ;
	device.model = L"CP2102" ;
	DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches( families[0], device)) ;
	device.model = L"USB ch340 (Port)" ;
	DRIVERCRATE_EXPECT( context, officialReleaseDeviceMatches( families[1], device)) ;
	device.model = L"CH342" ;
	DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches( families[2], device)) ;
	device.model = L"USB ch343 (Port)" ;
	DRIVERCRATE_EXPECT( context, officialReleaseDeviceMatches( families[2], device)) ;
	// CH340も同じ完全token条件で、別型番や同じ名の部分文字列を対象にしない。
	for( const auto model :
		{L"CH340", L"(ch340)", L"USB [CH340]", L"CH340X", L"XCH340", L"CH3410"}) {
		device.model		= model ;
		const bool expected = device.model == L"CH340" || device.model == L"(ch340)" ||
							  // 括弧を含む完全tokenだけを許す。
							  device.model == L"USB [CH340]" ;
		DRIVERCRATE_EXPECT( context, officialReleaseDeviceMatches( families[1], device) == expected) ;
	}

	device.model = L"CH340 CH341" ;
	DRIVERCRATE_EXPECT( context, officialReleaseDeviceMatches( families[1], device)) ;
	device.model = L"CH340 CP210x" ;
	DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches( families[1], device)) ;
}
} // namespace

/** @see metadata_search_tests.h */
void runMetadataSearchTests( TestContext &context)
{
	testSerialProbes( context) ;
	const auto						builtIn = builtInProviderDescriptors() ;	// 製品と同じ正本。
	std::vector<ProviderDescriptor> descriptors( builtIn.begin(),
												// 能力接続前のfixture。
												builtIn.end()) ;
	auto found = std::find_if( descriptors.begin(), descriptors.end(), []( const auto &descriptor) {
		return descriptor.id == PROLIFIC_OFFICIAL_PROVIDER_ID ;
	}) ; // 既存公式policyを持つ一登録。
	DRIVERCRATE_EXPECT( context, found != descriptors.end()) ;
	// 前提登録がなければdereferenceせず、そのassertion失敗を保持する。
	if( found == descriptors.end()) {
		return ;
	}

	found->capabilities |= capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) ;
	MetadataSearchRequest request ;	// 明示許可とpolicy拒否を検証する要求。
	DRIVERCRATE_EXPECT( context, !validateMetadataSearchRequest( request, descriptors)) ;
	request.enabledProviderIds.emplace_back( PROLIFIC_OFFICIAL_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, validateMetadataSearchRequest( request, descriptors)) ;
	request.restrictedNetworkApproved = true ;
	DRIVERCRATE_EXPECT( context, validateMetadataSearchRequest( request, descriptors)) ;
	request.enabledProviderIds.emplace_back( PROLIFIC_OFFICIAL_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, !validateMetadataSearchRequest( request, descriptors)) ;
	request.enabledProviderIds.pop_back() ;
	request.policyRevision++ ;
	DRIVERCRATE_EXPECT( context, !validateMetadataSearchRequest( request, descriptors)) ;
	request.policyRevision = METADATA_SEARCH_POLICY_REVISION ;
	request.policyId	   = L"unknown" ;
	DRIVERCRATE_EXPECT( context, !validateMetadataSearchRequest( request, descriptors)) ;
	request.policyId				   = METADATA_SEARCH_POLICY_ID ;
	request.enabledProviderIds.front() = L"unknown" ;
	DRIVERCRATE_EXPECT( context, !validateMetadataSearchRequest( request, descriptors)) ;
	request.enabledProviderIds.front() = WINDOWS_UPDATE_PROVIDER_ID ;
	DRIVERCRATE_EXPECT( context, !validateMetadataSearchRequest( request, descriptors)) ;
	request.enabledProviderIds.front() = PROLIFIC_OFFICIAL_PROVIDER_ID ;
	found->capabilities |= 0x80000000U ;
	DRIVERCRATE_EXPECT( context, !validateMetadataSearchRequest( request, descriptors)) ;
	found->capabilities &= ~0x80000000U ;
	found->officialSourcePolicyId = L"unknown" ;
	DRIVERCRATE_EXPECT( context, !validateMetadataSearchRequest( request, descriptors)) ;

	ScanResult result ;	// 行flagの改ざんでも権限を受理しない結果。
	result.scanSessionId = 7U ;
	DRIVERCRATE_EXPECT( context, !hasOnlyMetadataDisplayCandidates( result)) ;
	result.purpose = ScanPurpose::METADATA_ONLY ;
	result.candidates.emplace_back() ;
	DRIVERCRATE_EXPECT( context, hasOnlyMetadataDisplayCandidates( result)) ;
	result.candidates.front().installable = true ;
	DRIVERCRATE_EXPECT( context, !hasOnlyMetadataDisplayCandidates( result)) ;
	result.candidates.front().installable = false ;
	result.candidates.front().recommended = true ;
	DRIVERCRATE_EXPECT( context, !hasOnlyMetadataDisplayCandidates( result)) ;
	result.candidates.front().recommended = false ;
	result.candidates.front().action	  = DriverAction::UPDATE ;
	DRIVERCRATE_EXPECT( context, !hasOnlyMetadataDisplayCandidates( result)) ;
	result.candidates.clear() ;
	result.purpose = static_cast<ScanPurpose>( 99) ;
	DRIVERCRATE_EXPECT( context, !hasOnlyMetadataDisplayCandidates( result)) ;
}

} // namespace drivercrate::test
