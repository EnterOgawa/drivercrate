//------------------------------------------------------------------------------
/**
 * @file scan_measurement_tests.cpp
 * @brief 段階別和集合と計測契約の決定的単体試験。
 * @version 01.00.00
 * @date 2026/09/10
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  非通信の計測値・集合・監査境界試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  公式HTTP取得経路の要約試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  UI公開snapshotの再検証試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  列挙・候補上限と段階分類の境界試験を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 実machine inventoryを使わず、Providerの取得や導入を実行しません。
 */
//------------------------------------------------------------------------------

#include "scan_measurement_tests.h"

#include "core/candidate_audit.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "core/scan_measurement.h"
#include "test_framework.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {

/** @brief 架空の三node・四Providerをまとめた可変fixtureである。 */
struct MeasurementFixture {
	/// 明示Provider集合と固定session。
	ScanMeasurementContext					 condition ;
	/// Local、managed、公式P、公式Qの順の定義。
	std::vector<ProviderDescriptor>			 providers ;
	/// 現在版、表示用metadata、WUA更新、local旧版。
	std::vector<UpdateCandidate>			 candidates ;
	/// 確定した三nodeの詳細列挙。
	DeviceInventoryMeasurement				 inventory ;
	/// Managed、P、Qの実観測を模した根拠。
	std::vector<ProviderMeasurementEvidence> evidence ;
	/// WUA更新一件だけの既存導入routing。
	std::vector<std::wstring>				 routes ;
} ;

/**
 * @brief 正規の監査経路を持つ架空Providerを作る。
 * @param[in] id Fixture内で一意な固定ID。
 * @param[in] source 一つだけ指定するtrust boundary。
 * @return Scan能力と経路を整合させた定義。
 */
ProviderDescriptor makeMeasurementProvider( const std::wstring_view	id,
										   const ProviderCapability source)
{
	ProviderDescriptor provider ;	// 実network先を持たない架空registry要素。
	provider.id			  = id ;
	provider.displayName  = id ;
	provider.capabilities = capabilityMask( ProviderCapability::SCAN) | capabilityMask( source) ;
	// Local fixtureは現在版と旧版のWindows管理経路を持つ。
	if( source == ProviderCapability::LOCAL_INVENTORY) {
		provider.selectionTier	= ProviderSelectionTier::LOCAL_INVENTORY ;
		provider.discoveryBasis = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
		provider.capabilities |= capabilityMask( ProviderCapability::INSTALL) ;
	}
	// Managed fixtureはWUAの監査委譲と導入routingを持つ。
	else if( source == ProviderCapability::MANAGED_SERVICE) {
		provider.selectionTier	= ProviderSelectionTier::MANAGED_SERVICE ;
		provider.discoveryBasis = CandidateDiscoveryBasis::MANAGED_SERVICE ;
		provider.capabilities |= capabilityMask( ProviderCapability::INSTALL) ;
	} else {
		provider.selectionTier			= ProviderSelectionTier::COMPONENT_OFFICIAL ;
		provider.discoveryBasis			= CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG ;
		provider.officialSourcePolicyId = L"fixture-policy" ;
	}

	return provider ;
}

/**
 * @brief 指定経路と矛盾しない架空candidateを作る。
 * @param[in] id 一意な候補ID。
 * @param[in] device Opaque local結合先。
 * @param[in] provider Fixtureの発行元定義。
 * @param[in] current 現在版行の場合true。
 * @return 内容監査・install可否を経路へ対応させた候補。
 */
UpdateCandidate makeMeasurementCandidate( const std::wstring_view id, const std::wstring_view device,
										 const ProviderDescriptor &provider, const bool current)
{
	UpdateCandidate candidate ;	// 本試験だけで使う所有値の候補。
	candidate.identity		  = id ;
	candidate.deviceIdentity  = device ;
	candidate.providerId	  = provider.id ;
	candidate.packageIdentity = L"fixture-package" ;
	candidate.manufacturer	  = L"Fixture maker" ;
	candidate.driverClass	  = L"Fixture class" ;
	candidate.version		  = L"1.0" ;
	candidate.discoveryBasis  = provider.discoveryBasis ;
	candidate.current		  = current ;
	// 公式fixtureは具体的metadataまでの表示専用候補であり、監査合格を主張しない。
	if( provider.discoveryBasis == CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG) {
		candidate.audit = makeOfficialMetadataCandidateAudit() ;
	} else {
		candidate.audit		  = makeWindowsManagedCandidateAudit( current) ;
		candidate.installable = !current ;
		candidate.action	  = current ? DriverAction::NONE : DriverAction::UPDATE ;
	}

	return candidate ;
}

/**
 * @brief 有限なopaque集合を完全計測として作る。
 * @param[in] identities 架空deviceの一意な一覧。
 * @return EXACTと指定identityを持つworker根拠。
 */
MeasurementDeviceSet exactSet( const std::initializer_list<std::wstring> identities)
{
	return {MeasurementExtent::EXACT, identities} ;
}

/**
 * @brief ADR 0139の三node・重複情報到達の基準fixtureを作る。
 * @return D=3、公式到達2、managed到達1、通常更新1の測定入力。
 */
MeasurementFixture makeMeasurementFixture()
{
	MeasurementFixture fixture ;	// 取得関数やnative APIを持たない測定一式。
	fixture.providers = {
		makeMeasurementProvider( L"local", ProviderCapability::LOCAL_INVENTORY),
		makeMeasurementProvider( L"managed", ProviderCapability::MANAGED_SERVICE),
		makeMeasurementProvider( L"official-p", ProviderCapability::OFFICIAL_NETWORK),
		makeMeasurementProvider( L"official-q", ProviderCapability::OFFICIAL_NETWORK)} ;
	fixture.condition.scanSessionId			= 1 ;
	fixture.condition.operationId			= 2 ;
	fixture.condition.usedDefaultProviders	= false ;
	fixture.condition.enabledProviderIds	= {L"local", L"managed", L"official-p", L"official-q"} ;
	fixture.inventory.enumeratedDeviceCount = {3, MeasurementExtent::EXACT} ;
	fixture.inventory.unrepresentedDeviceCount	  = {0, MeasurementExtent::EXACT} ;
	fixture.inventory.detailedEnumerationComplete = true ;
	fixture.candidates							  = {
		   makeMeasurementCandidate( L"current-1", L"d1", fixture.providers[0], true),
		   makeMeasurementCandidate( L"current-2", L"d2", fixture.providers[0], true),
		   makeMeasurementCandidate( L"current-3", L"d3", fixture.providers[0], true),
		   makeMeasurementCandidate( L"managed-1", L"d1", fixture.providers[1], false),
		   makeMeasurementCandidate( L"p-1", L"d1", fixture.providers[2], false),
		   makeMeasurementCandidate( L"p-2", L"d2", fixture.providers[2], false),
		   makeMeasurementCandidate( L"q-1", L"d2", fixture.providers[3], false),
		   makeMeasurementCandidate( L"older-3", L"d3", fixture.providers[0], false)} ;
	fixture.candidates.back().action = DriverAction::DOWNGRADE ;
	ProviderMeasurementEvidence managed ;	// System query成功でもQは未計測のまま。
	managed.providerId			= L"managed" ;
	managed.scanSessionId		= 1 ;
	managed.scope				= MeasurementScope::SYSTEM_QUERY ;
	managed.queryOutcome		= OutcomeCode::SUCCESS ;
	managed.eligible			= exactSet( {L"d1", L"d2", L"d3"}) ;
	managed.information			= exactSet( {L"d1"}) ;
	managed.applicabilityExtent = MeasurementExtent::EXACT ;
	managed.readinessExtent		= MeasurementExtent::EXACT ;
	ProviderMeasurementEvidence official ;	// 同一recordが二nodeへ情報到達する根拠。
	official.providerId			 = L"official-p" ;
	official.scanSessionId		 = 1 ;
	official.scope				 = MeasurementScope::DEVICE_QUERY ;
	official.queryOutcome		 = OutcomeCode::SUCCESS ;
	official.eligible			 = exactSet( {L"d1", L"d2"}) ;
	official.queryCompleted		 = exactSet( {L"d1", L"d2"}) ;
	official.information		 = exactSet( {L"d1", L"d2"}) ;
	official.applicabilityExtent = MeasurementExtent::LOWER_BOUND ;
	official.readinessExtent	 = MeasurementExtent::LOWER_BOUND ;
	official.recordExtent		 = MeasurementExtent::EXACT ;
	official.records			 = {{L"record-1", {L"d1", L"d2"}}} ;
	fixture.evidence			 = {managed, official} ;
	official.providerId			 = L"official-q" ;
	official.eligible			 = exactSet( {L"d2"}) ;
	official.queryCompleted		 = exactSet( {L"d2"}) ;
	official.information		 = exactSet( {L"d2"}) ;
	official.records			 = {{L"record-1", {L"d2"}}} ;
	fixture.evidence.push_back( official) ;
	fixture.routes = {L"managed-1"} ;
	return fixture ;
}

/**
 * @brief Device数と全候補行数だけを可変にしたlocal-only fixtureを作る。
 * @param[in] deviceCount 重複しない現在版行の数。
 * @param[in] candidateCount 現在版を含む全候補行数。deviceCount以上でなければならない。
 * @return 実PnP列挙を行わない、指定行数の所有fixture。
 */
MeasurementFixture makeLimitFixture( const std::size_t deviceCount, const std::size_t candidateCount)
{
	MeasurementFixture fixture ;	// 上限検証に必要なlocal Providerだけを持つ入力。
	fixture.providers = {makeMeasurementProvider( L"local", ProviderCapability::LOCAL_INVENTORY)} ;
	fixture.condition.scanSessionId				  = 1U ;
	fixture.condition.operationId				  = 2U ;
	fixture.condition.usedDefaultProviders		  = false ;
	fixture.condition.enabledProviderIds		  = {L"local"} ;
	fixture.inventory.enumeratedDeviceCount		  = {static_cast<std::uint64_t>( deviceCount),
													 MeasurementExtent::EXACT} ;
	fixture.inventory.unrepresentedDeviceCount	  = {0U, MeasurementExtent::EXACT} ;
	fixture.inventory.detailedEnumerationComplete = true ;
	fixture.candidates.reserve( candidateCount) ;
	// 各deviceへ一行ずつ現在版を発行し、Dの保持上限を直接検証できる母数を作る。
	for( std::size_t deviceIndex = 0U; deviceIndex < deviceCount; ++deviceIndex) {
		const std::wstring device = L"limit-device-" +
									// このfixture内だけで一意なopaque device ID。
									std::to_wstring( deviceIndex) ;
		const std::wstring identity =
			L"limit-current-" + std::to_wstring( deviceIndex) ;	// 現在版行の一意なcandidate ID。
		fixture.candidates.push_back(
			makeMeasurementCandidate( identity, device, fixture.providers.front(), true)) ;
	}

	// 残りは先頭deviceの非現在版とし、補完現在行を含む候補総数の上限を検証する。
	for( std::size_t candidateIndex = deviceCount; candidateIndex < candidateCount;
		++candidateIndex) {
		const std::wstring identity =
			L"limit-candidate-" + std::to_wstring( candidateIndex) ;	// 全行で重複しないcandidate ID。
		fixture.candidates.push_back( makeMeasurementCandidate( identity, L"limit-device-0",
															  fixture.providers.front(), false)) ;
	}

	return fixture ;
}

/**
 * @brief Fixtureを純粋集計へ渡す。
 * @param[in] fixture 検証対象の所有値。
 * @return 集計契約が成立した場合だけ結果を返す。
 */
std::optional<ScanMeasurementAggregation> measure( const MeasurementFixture &fixture)
{
	return aggregateScanMeasurement( fixture.condition, fixture.candidates, fixture.providers,
									fixture.inventory, fixture.evidence, fixture.routes) ;
}

/**
 * @brief 基準fixtureの純粋集計をUI公開用ScanResultへ変換する。
 * @param[in] fixture 集計済み入力とregistry定義。
 * @return 全公開fieldを接続した結果。集計拒否時は値なし。
 */
std::optional<ScanResult> makePublishedMeasurementResult( const MeasurementFixture &fixture)
{
	const auto aggregation = measure( fixture) ;	// Identity集合を公開件数へ変換した基準結果。
	// 基準fixture自体が不正なら部分的な公開結果を作らない。
	if( !aggregation.has_value()) {
		return std::nullopt ;
	}

	ScanResult result ;	// WorkerがUIへ渡す形の所有結果。
	result.succeeded							   = true ;
	result.scanSessionId						   = fixture.condition.scanSessionId ;
	result.outcome								   = OutcomeCode::SUCCESS ;
	result.state								   = ProviderScanState::CANDIDATES_AVAILABLE ;
	result.candidates							   = fixture.candidates ;
	result.localCoverage						   = aggregation->localCoverage ;
	result.measurement							   = aggregation->snapshot ;
	result.measurement->context.applicationVersion = L"0.1.0" ;
	result.providerReports.reserve( fixture.providers.size()) ;
	// Registry順の全Providerへ純粋集計が返した公開measurementを一対一で接続する。
	for( std::size_t index = 0; index < fixture.providers.size(); ++index) {
		result.providerReports.push_back(
			{.descriptor = fixture.providers[index],
			 .state		 = ProviderScanState::CANDIDATES_AVAILABLE,
			 .coverage	 = {.measurement = aggregation->providers[index].measurement},
			 .outcome	 = OutcomeCode::SUCCESS}) ;
	}

	return result ;
}

/**
 * @brief 未計測、確定0、下限0、値不明と不正な組を区別する。
 * @param[in,out] context Assertion集計先。
 */
void testCountExtents( TestContext &context)
{
	DRIVERCRATE_EXPECT( context, isCountMeasurementValid( {})) ;
	DRIVERCRATE_EXPECT( context, isCountMeasurementValid( {0, MeasurementExtent::EXACT})) ;
	DRIVERCRATE_EXPECT( context, isCountMeasurementValid( {0, MeasurementExtent::LOWER_BOUND})) ;
	DRIVERCRATE_EXPECT( context,
					   isCountMeasurementValid( {std::nullopt, MeasurementExtent::UNAVAILABLE})) ;
	DRIVERCRATE_EXPECT( context, !isCountMeasurementValid( {0, MeasurementExtent::NOT_MEASURED})) ;
	DRIVERCRATE_EXPECT( context, !isCountMeasurementValid( {0, MeasurementExtent::UNAVAILABLE})) ;
	DRIVERCRATE_EXPECT( context, !isCountMeasurementValid( {std::nullopt, MeasurementExtent::EXACT})) ;
	DRIVERCRATE_EXPECT( context,
					   !isCountMeasurementValid( {std::nullopt, MeasurementExtent::LOWER_BOUND})) ;
	DRIVERCRATE_EXPECT( context, !isCountMeasurementValid( {0, static_cast<MeasurementExtent>( 99)})) ;
	DRIVERCRATE_EXPECT( context, !ProviderCoverage{}.measurement.has_value()) ;
	DRIVERCRATE_EXPECT( context, !ScanResult{}.measurement.has_value()) ;
}

/**
 * @brief Deviceとcompatible driverの上限直前・一致・超過を同じ純粋分類で検証する。
 * @param[in,out] context Assertion集計先。
 */
void testBoundedEnumerationClassification( TestContext &context)
{
	const auto deviceBelow = classifyBoundedEnumeration(
		4095U, 4096U, BoundedEnumerationStop::NORMAL_END, BoundedEnumerationProbe::NOT_RUN,
		0U) ;	// Device上限直前の正常終端。
	DRIVERCRATE_EXPECT( context,
					   deviceBelow.has_value() && deviceBelow->observedItemCount.value == 4095U &&
						   deviceBelow->observedItemCount.extent == MeasurementExtent::EXACT &&
						   deviceBelow->enumerationComplete && !deviceBelow->limitExceeded &&
						   deviceBelow->error == 0U) ;
	const auto deviceAt = classifyBoundedEnumeration( 4096U, 4096U, BoundedEnumerationStop::LIMIT,
													 BoundedEnumerationProbe::NORMAL_END,
													 0U) ;	// 一回probeで終端を確認した上限ちょうど。
	DRIVERCRATE_EXPECT( context,
					   deviceAt.has_value() && deviceAt->observedItemCount.value == 4096U &&
						   deviceAt->observedItemCount.extent == MeasurementExtent::EXACT &&
						   deviceAt->enumerationComplete && !deviceAt->limitExceeded) ;
	const auto deviceAbove = classifyBoundedEnumeration( 4096U, 4096U, BoundedEnumerationStop::LIMIT,
														BoundedEnumerationProbe::ELEMENT_FOUND,
														0U) ;	// 保持しない4097件目の存在確認。
	DRIVERCRATE_EXPECT(
		context, deviceAbove.has_value() && deviceAbove->observedItemCount.value == 4097U &&
					 deviceAbove->observedItemCount.extent == MeasurementExtent::LOWER_BOUND &&
					 !deviceAbove->enumerationComplete && deviceAbove->limitExceeded) ;
	const auto deviceProbeFailure = classifyBoundedEnumeration(
		4096U, 4096U, BoundedEnumerationStop::LIMIT, BoundedEnumerationProbe::API_FAILURE,
		5U) ;	// 追加probe自体の合成失敗。
	DRIVERCRATE_EXPECT(
		context,
		deviceProbeFailure.has_value() && deviceProbeFailure->observedItemCount.value == 4096U &&
			deviceProbeFailure->observedItemCount.extent == MeasurementExtent::LOWER_BOUND &&
			!deviceProbeFailure->enumerationComplete && !deviceProbeFailure->limitExceeded &&
			deviceProbeFailure->error == 5U) ;

	const auto driverBelow = classifyBoundedEnumeration(
		511U, 512U, BoundedEnumerationStop::NORMAL_END, BoundedEnumerationProbe::NOT_RUN,
		0U) ;	// Driver上限直前の正常終端。
	DRIVERCRATE_EXPECT( context,
					   driverBelow.has_value() && driverBelow->observedItemCount.value == 511U &&
						   driverBelow->observedItemCount.extent == MeasurementExtent::EXACT) ;
	const auto driverAt = classifyBoundedEnumeration( 512U, 512U, BoundedEnumerationStop::LIMIT,
													 BoundedEnumerationProbe::NORMAL_END,
													 0U) ;	// 一回probeで確認した512件ちょうど。
	DRIVERCRATE_EXPECT( context, driverAt.has_value() && driverAt->observedItemCount.value == 512U &&
									driverAt->enumerationComplete && !driverAt->limitExceeded) ;
	const auto driverAbove = classifyBoundedEnumeration( 512U, 512U, BoundedEnumerationStop::LIMIT,
														BoundedEnumerationProbe::ELEMENT_FOUND,
														0U) ;	// 保持しない513件目の存在確認。
	DRIVERCRATE_EXPECT(
		context, driverAbove.has_value() && driverAbove->observedItemCount.value == 513U &&
					 driverAbove->observedItemCount.extent == MeasurementExtent::LOWER_BOUND &&
					 driverAbove->limitExceeded) ;
	const auto earlyFailure = classifyBoundedEnumeration(
		511U, 512U, BoundedEnumerationStop::API_FAILURE, BoundedEnumerationProbe::NOT_RUN,
		6U) ;	// 上限前の列挙失敗による確認済み下限。
	DRIVERCRATE_EXPECT(
		context, earlyFailure.has_value() && earlyFailure->observedItemCount.value == 511U &&
					 earlyFailure->observedItemCount.extent == MeasurementExtent::LOWER_BOUND &&
					 earlyFailure->error == 6U) ;

	DRIVERCRATE_EXPECT( context,
					   !classifyBoundedEnumeration( 0U, 0U, BoundedEnumerationStop::NORMAL_END,
												   BoundedEnumerationProbe::NOT_RUN, 0U)) ;
	DRIVERCRATE_EXPECT( context,
					   !classifyBoundedEnumeration( 4097U, 4096U, BoundedEnumerationStop::NORMAL_END,
												   BoundedEnumerationProbe::NOT_RUN, 0U)) ;
	DRIVERCRATE_EXPECT( context,
					   !classifyBoundedEnumeration( 4095U, 4096U, BoundedEnumerationStop::LIMIT,
												   BoundedEnumerationProbe::NORMAL_END, 0U)) ;
	DRIVERCRATE_EXPECT( context,
					   !classifyBoundedEnumeration( 4096U, 4096U, BoundedEnumerationStop::LIMIT,
												   BoundedEnumerationProbe::NOT_RUN, 0U)) ;
	DRIVERCRATE_EXPECT( context,
					   !classifyBoundedEnumeration( 12U, 4096U, BoundedEnumerationStop::NORMAL_END,
												   BoundedEnumerationProbe::ELEMENT_FOUND, 0U)) ;
	DRIVERCRATE_EXPECT( context,
					   !classifyBoundedEnumeration( 12U, 4096U, BoundedEnumerationStop::API_FAILURE,
												   BoundedEnumerationProbe::NOT_RUN, 0U)) ;
	DRIVERCRATE_EXPECT( context,
					   !classifyBoundedEnumeration( 12U, 4096U, BoundedEnumerationStop::NORMAL_END,
												   BoundedEnumerationProbe::NOT_RUN, 5U)) ;
	DRIVERCRATE_EXPECT( context,
					   !classifyBoundedEnumeration( 1U, 1U, static_cast<BoundedEnumerationStop>( 99),
												   BoundedEnumerationProbe::NOT_RUN, 0U)) ;
	DRIVERCRATE_EXPECT( context,
					   !classifyBoundedEnumeration( 1U, 1U, BoundedEnumerationStop::LIMIT,
												   static_cast<BoundedEnumerationProbe>( 99), 0U)) ;
	constexpr std::uint64_t maximum =
		std::numeric_limits<std::uint64_t>::max() ;	// 追加一件を表現できない整数上限。
	DRIVERCRATE_EXPECT( context,
					   !classifyBoundedEnumeration( maximum, maximum, BoundedEnumerationStop::LIMIT,
												   BoundedEnumerationProbe::ELEMENT_FOUND, 0U)) ;
}

/**
 * @brief Device母数と補完現在行を含む候補総数の保持上限を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testCandidateAndDeviceLimits( TestContext &context)
{
	MeasurementFixture fixture = makeLimitFixture( 4095U, 4095U) ;	// Device上限直前。
	DRIVERCRATE_EXPECT( context, measure( fixture).has_value()) ;
	// Device保持上限ちょうど。
	fixture = makeLimitFixture( 4096U, 4096U) ;
	DRIVERCRATE_EXPECT( context, measure( fixture).has_value()) ;
	// 候補上限内だがDevice上限を一件超える入力。
	fixture = makeLimitFixture( 4097U, 4097U) ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;

	// 現在版一行を含む候補上限直前。
	fixture = makeLimitFixture( 1U, 32767U) ;
	DRIVERCRATE_EXPECT( context, measure( fixture).has_value()) ;
	// 現在版一行を含む候補保持上限ちょうど。
	fixture = makeLimitFixture( 1U, 32768U) ;
	DRIVERCRATE_EXPECT( context, measure( fixture).has_value()) ;
	// 現在版補完後に候補保持上限を一件超える入力。
	fixture = makeLimitFixture( 1U, 32769U) ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;
}

/**
 * @brief Network、fresh cache、304の取得ledgerを固定ID要約へ変換する。
 * @param[in,out] context Assertion集計先。
 */
void testOfficialSourceSummary( TestContext &context)
{
	OfficialSourceEvidence network{.scanSessionId = 7U,
								   .acquisitionId = 1U,
								   .providerId	  = std::wstring( NVIDIA_PROVIDER_ID),
								   .policyId	  = std::wstring( NVIDIA_OFFICIAL_SOURCE_POLICY_ID),
								   .resourceId	  = std::wstring( OFFICIAL_LANDING_RESOURCE_ID),
								   .originPolicyIndices	   = {0U},
								   .acquisition			   = MeasurementAcquisition::NETWORK_BODY,
								   .bodyAcquiredUtcSeconds = 100U,
								   .originValidatedUtcSeconds = 101U,
								   .cachePermitted = false} ;	// Cache無効のnetwork本文取得根拠。
	OfficialSourceEvidence fresh = network ;					// 同一sessionで続くfresh cache根拠。
	fresh.acquisitionId			 = 2U ;
	fresh.resourceId			 = std::wstring( OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ;
	fresh.acquisition			 = MeasurementAcquisition::FRESH_CACHE ;
	fresh.bodyAcquiredUtcSeconds.reset() ;
	fresh.originValidatedUtcSeconds		  = 90U ;
	fresh.cachePermitted				  = true ;
	OfficialSourceEvidence revalidated	  = fresh ;	// 304でoriginを再検証した第三resource。
	revalidated.acquisitionId			  = 3U ;
	revalidated.resourceId				  = std::wstring( OFFICIAL_SECONDARY_METADATA_RESOURCE_ID) ;
	revalidated.acquisition				  = MeasurementAcquisition::REVALIDATED_CACHE ;
	revalidated.originValidatedUtcSeconds = 102U ;
	const std::array evidence{network, fresh, revalidated} ;				// 連続する一Provider ledger。
	std::vector<MeasurementResource> resources{{.policyId = L"stale"}} ;	// 成功時に置換する出力。
	DRIVERCRATE_EXPECT( context, summarizeOfficialSourceEvidence( evidence, resources)) ;
	DRIVERCRATE_EXPECT( context, resources.size() == evidence.size()) ;
	DRIVERCRATE_EXPECT( context, resources[0].acquisition == MeasurementAcquisition::NETWORK_BODY &&
									resources[0].bodyAcquiredUtcSeconds == 100U &&
									resources[0].cachePermitted == false) ;
	DRIVERCRATE_EXPECT( context, resources[1].acquisition == MeasurementAcquisition::FRESH_CACHE &&
									!resources[1].bodyAcquiredUtcSeconds &&
									resources[1].originValidatedUtcSeconds == 90U &&
									resources[1].cachePermitted == true) ;
	DRIVERCRATE_EXPECT( context,
					   resources[2].acquisition == MeasurementAcquisition::REVALIDATED_CACHE &&
						   resources[2].originValidatedUtcSeconds == 102U) ;
	DRIVERCRATE_EXPECT( context,
					   resources[0].branchId.empty() && !resources[0].parserRevision.has_value()) ;

	std::array invalid		 = evidence ;	// 欠番を含むledger。
	invalid[1].acquisitionId = 3U ;
	DRIVERCRATE_EXPECT( context, !summarizeOfficialSourceEvidence( invalid, resources)) ;
	DRIVERCRATE_EXPECT( context, resources.empty()) ;
	invalid					 = evidence ;
	invalid[1].scanSessionId = 8U ;
	DRIVERCRATE_EXPECT( context, !summarizeOfficialSourceEvidence( invalid, resources)) ;
	DRIVERCRATE_EXPECT( context, resources.empty()) ;
	DRIVERCRATE_EXPECT( context, summarizeOfficialSourceEvidence(
									std::span<const OfficialSourceEvidence>{}, resources) &&
									resources.empty()) ;
}

/**
 * @brief 取得要約を組み込みProviderへ拘束し、Provider集計へ所有値で反映する。
 * @param[in,out] context Assertion集計先。
 */
void testOfficialSourceAggregation( TestContext &context)
{
	MeasurementFixture fixture =
		// 公式Pだけを実registry定義へ置換する入力。
		makeMeasurementFixture() ;
	const auto descriptors = builtInProviderDescriptors() ;	// Process寿命中有効な組み込みregistry。
	const auto found	   = std::find_if( descriptors.begin(), descriptors.end(),
										  []( const ProviderDescriptor &descriptor) {
										  return descriptor.id == NVIDIA_PROVIDER_ID ;
									  }) ; // 固定IDに一致する実Provider定義。
	DRIVERCRATE_EXPECT( context, found != descriptors.end()) ;
	// 実registryに対象Providerがなければ不正iteratorを参照せず試験を終了する。
	if( found == descriptors.end()) {
		return ;
	}

	fixture.providers[2]					= *found ;
	fixture.condition.enabledProviderIds[2] = std::wstring( NVIDIA_PROVIDER_ID) ;
	fixture.candidates[4] = makeMeasurementCandidate( L"p-1", L"d1", fixture.providers[2], false) ;
	fixture.candidates[5] = makeMeasurementCandidate( L"p-2", L"d2", fixture.providers[2], false) ;
	fixture.evidence[1].providerId = std::wstring( NVIDIA_PROVIDER_ID) ;
	fixture.evidence[1].resources  = {
		 {.policyId					 = std::wstring( NVIDIA_OFFICIAL_SOURCE_POLICY_ID),
		  .resourceId				 = std::wstring( OFFICIAL_PRIMARY_METADATA_RESOURCE_ID),
		  .bodyAcquiredUtcSeconds	 = 100U,
		  .originValidatedUtcSeconds = 101U,
		  .cachePermitted			 = false,
		  .acquisition				 = MeasurementAcquisition::NETWORK_BODY}} ;
	const auto result = measure( fixture) ;	// Registryへ拘束した取得要約の集計結果。
	DRIVERCRATE_EXPECT( context, result.has_value() &&
									result->providers[2].measurement.resources.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, result.has_value() &&
									result->providers[2].measurement.resources[0].resourceId ==
										OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ;
	fixture.evidence[1].resources[0].resourceId = L"unknown-resource" ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;
	fixture.evidence[1].resources.clear() ;
	fixture.evidence[0].resources = {{.policyId	  = std::wstring( NVIDIA_OFFICIAL_SOURCE_POLICY_ID),
									  .resourceId = std::wstring( OFFICIAL_LANDING_RESOURCE_ID)}} ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;
}

/**
 * @brief 同型node、同一record、複数取得元、旧版の単位を混同しない。
 * @param[in,out] context Assertion集計先。
 */
void testMeasurementUnions( TestContext &context)
{
	MeasurementFixture fixture = makeMeasurementFixture() ;	// 三nodeの基準入力。
	const auto		   result  = measure( fixture) ;		// 通信を行わず得る決定的な集計。
	DRIVERCRATE_EXPECT( context, result.has_value()) ;
	// 前提を欠く場合は結果を参照せず、一次失敗だけを残す。
	if( !result.has_value()) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, result->snapshot.inventory.representedDeviceCount.value == 3) ;
	DRIVERCRATE_EXPECT( context,
					   result->snapshot.network.combined.informationDeviceCount.value == 2) ;
	DRIVERCRATE_EXPECT( context,
					   result->snapshot.network.official.informationDeviceCount.value == 2) ;
	DRIVERCRATE_EXPECT( context, result->snapshot.network.managed.informationDeviceCount.value == 1) ;
	DRIVERCRATE_EXPECT( context,
					   result->snapshot.network.combined.applicableUpdateDeviceCount.value == 1) ;
	DRIVERCRATE_EXPECT( context,
					   result->snapshot.network.combined.installReadyUpdateDeviceCount.value == 1) ;
	DRIVERCRATE_EXPECT( context, result->providers[2].measurement.informationRecordCount.value == 1) ;
	DRIVERCRATE_EXPECT( context, result->providers[3].measurement.informationRecordCount.value == 1) ;
	DRIVERCRATE_EXPECT( context, result->snapshot.network.combined.informationDeviceCount.extent ==
									MeasurementExtent::EXACT) ;
	DRIVERCRATE_EXPECT( context, result->snapshot.network.managed.queryCompletedDeviceCount.extent ==
									MeasurementExtent::NOT_MEASURED) ;
	DRIVERCRATE_EXPECT( context,
					   result->snapshot.network.combined.queryCompletedDeviceCount.value == 2) ;
	DRIVERCRATE_EXPECT( context,
					   result->snapshot.network.combined.queryCompletedDeviceCount.extent ==
						   MeasurementExtent::LOWER_BOUND) ;
	DRIVERCRATE_EXPECT( context, result->localCoverage.size() == 1 &&
									result->localCoverage[0].deviceCount == 3) ;
	DRIVERCRATE_EXPECT( context, result->localCoverage[0].candidateDeviceCount == 3) ;
	DRIVERCRATE_EXPECT(
		context, result->localCoverage[0].measurement->combined.informationDeviceCount.value == 2) ;
	DRIVERCRATE_EXPECT( context, fixture.candidates.size() == 8 && fixture.routes.size() == 1) ;
	fixture.evidence[1].records.push_back(
		{L"record-unmatched", {}}) ;					// Deviceへ結合しない二件目の識別済みrecord。
	const auto unmatchedRecord = measure( fixture) ;	// Record数と到達device数を別単位で集計する。
	DRIVERCRATE_EXPECT(
		context, unmatchedRecord.has_value() &&
					 unmatchedRecord->providers[2].measurement.informationRecordCount.value == 2U) ;
	DRIVERCRATE_EXPECT(
		context,
		unmatchedRecord.has_value() &&
			unmatchedRecord->providers[2].measurement.unmatchedInformationRecordCount.value == 1U) ;
	DRIVERCRATE_EXPECT(
		context, unmatchedRecord.has_value() &&
					 unmatchedRecord->snapshot.network.official.informationDeviceCount.value == 2U) ;
	fixture.candidates.push_back(
		makeMeasurementCandidate( L"unmatched-1", L"unbound", fixture.providers[1], false)) ;
	const auto unmatched = measure( fixture) ;	// 正規の未照合候補は行数だけを増やす。
	DRIVERCRATE_EXPECT( context, unmatched.has_value() &&
									unmatched->snapshot.unmatchedCandidateCount.value == 1) ;
	DRIVERCRATE_EXPECT( context,
					   unmatched.has_value() &&
						   unmatched->snapshot.network.combined.informationDeviceCount.value == 2) ;
	DRIVERCRATE_EXPECT( context,
					   unmatched.has_value() &&
						   unmatched->snapshot.network.combined.informationDeviceCount.extent ==
							   MeasurementExtent::LOWER_BOUND) ;
	fixture.candidates.push_back(
		makeMeasurementCandidate( L"ambiguous-1", L"ambiguous", fixture.providers[2], false)) ;
	const auto ambiguous =
		// Local matcherが一意に解決できない別候補も未照合行として残す。
		measure( fixture) ;
	DRIVERCRATE_EXPECT( context, ambiguous.has_value() &&
									ambiguous->snapshot.unmatchedCandidateCount.value == 2U) ;
	DRIVERCRATE_EXPECT( context,
					   ambiguous.has_value() &&
						   ambiguous->snapshot.network.combined.informationDeviceCount.value == 2U) ;
	fixture.routes.clear() ;
	const auto noRouting = measure( fixture) ;	// 有効候補でも導入routingなしではIへ加算しない。
	DRIVERCRATE_EXPECT(
		context, noRouting.has_value() &&
					 noRouting->snapshot.network.combined.applicableUpdateDeviceCount.value == 1) ;
	DRIVERCRATE_EXPECT(
		context, noRouting.has_value() &&
					 noRouting->snapshot.network.combined.installReadyUpdateDeviceCount.value == 0) ;
}

/**
 * @brief 現在版・同版・旧版・表示用新版を通常更新とREADYへ誤加算しない。
 * @param[in,out] context Assertion集計先。
 */
void testCandidateStageClassifications( TestContext &context)
{
	MeasurementFixture fixture = makeMeasurementFixture() ;	// A=I=1の基準入力。
	fixture.providers[2].capabilities |= capabilityMask( ProviderCapability::INSTALL) ;
	// READYでも通常更新ではない同版候補。
	UpdateCandidate same = makeMeasurementCandidate( L"p-same", L"d1", fixture.providers[2], false) ;
	same.version		 = L"1.0" ;
	same.action			 = DriverAction::REINSTALL ;
	same.audit			 = makeOfficialReadyCandidateAudit() ;
	same.installable	 = true ;
	// READYでも通常更新ではない旧版候補。
	UpdateCandidate older =
		makeMeasurementCandidate( L"p-older", L"d2", fixture.providers[2], false) ;
	older.version	  = L"0.5" ;
	older.action	  = DriverAction::DOWNGRADE ;
	older.audit		  = makeOfficialReadyCandidateAudit() ;
	older.installable = true ;
	// 表示版だけが大きくても内容適用性を確認していない公式metadata候補。
	UpdateCandidate packageOnly =
		makeMeasurementCandidate( L"q-package-new", L"d2", fixture.providers[3], false) ;
	// Package表示版だけが現在INF版より大きく見えるfixture。
	packageOnly.version = L"99.0" ;
	packageOnly.action	= DriverAction::UPDATE ;
	fixture.candidates.push_back( std::move( same)) ;
	fixture.candidates.push_back( std::move( older)) ;
	fixture.candidates.push_back( std::move( packageOnly)) ;
	fixture.routes.push_back( L"p-same") ;
	fixture.routes.push_back( L"p-older") ;
	const auto result = measure( fixture) ;	// Actionと監査段階を適用した和集合。
	DRIVERCRATE_EXPECT( context, result.has_value()) ;
	DRIVERCRATE_EXPECT( context, result.has_value() && fixture.candidates.size() == 11U) ;
	DRIVERCRATE_EXPECT( context,
					   result.has_value() &&
						   result->snapshot.network.combined.informationDeviceCount.value == 2U) ;
	DRIVERCRATE_EXPECT(
		context, result.has_value() &&
					 result->snapshot.network.combined.applicableUpdateDeviceCount.value == 1U) ;
	DRIVERCRATE_EXPECT(
		context, result.has_value() &&
					 result->snapshot.network.combined.installReadyUpdateDeviceCount.value == 1U) ;
	DRIVERCRATE_EXPECT(
		context,
		result.has_value() &&
			result->providers[3].measurement.devices.applicableUpdateDeviceCount.value == 0U) ;
}

/**
 * @brief 部分結果、旧計測、payload失敗後のmetadata到達を維持する。
 * @param[in,out] context Assertion集計先。
 */
void testMeasurementPartialResults( TestContext &context)
{
	MeasurementFixture fixture = makeMeasurementFixture() ;	// 失敗条件を一つずつ加える基準入力。
	fixture.evidence[0].queryOutcome = OutcomeCode::SUCCEEDED_WITH_ERRORS ;
	const auto partial				 = measure( fixture) ;	// WUA部分成功を全件確認済みとしない。
	DRIVERCRATE_EXPECT( context,
					   partial.has_value() &&
						   partial->snapshot.network.managed.informationDeviceCount.value == 1) ;
	DRIVERCRATE_EXPECT( context,
					   partial.has_value() &&
						   partial->snapshot.network.combined.informationDeviceCount.extent ==
							   MeasurementExtent::LOWER_BOUND) ;
	constexpr std::array managedOutcomes{OutcomeCode::SUCCESS, OutcomeCode::SUCCEEDED_WITH_ERRORS,
										 OutcomeCode::FAILURE,
										 OutcomeCode::ABORTED} ;	// WUA全体queryの四つの終端分類。
	// 同じ肯定的候補を維持し、全体成功以外では未確認範囲を下限として公開する。
	for( const OutcomeCode outcome : managedOutcomes) {
		fixture							 = makeMeasurementFixture() ;
		fixture.evidence[0].queryOutcome = outcome ;
		const auto				measured = measure( fixture) ;	// 一つのWUA終端状態を持つ集計結果。
		const MeasurementExtent expectedExtent =
			outcome == OutcomeCode::SUCCESS
				? MeasurementExtent::EXACT
				: MeasurementExtent::LOWER_BOUND ;	// 情報段階の期待確定度。
		DRIVERCRATE_EXPECT(
			context, measured.has_value() &&
						 measured->snapshot.network.managed.informationDeviceCount.value == 1U) ;
		DRIVERCRATE_EXPECT( context,
						   measured.has_value() &&
							   measured->snapshot.network.managed.informationDeviceCount.extent ==
								   expectedExtent) ;
		DRIVERCRATE_EXPECT(
			context, measured.has_value() &&
						 measured->snapshot.network.managed.queryCompletedDeviceCount.extent ==
							 MeasurementExtent::NOT_MEASURED) ;
	}

	fixture = makeMeasurementFixture() ;
	fixture.evidence.clear() ;
	const auto legacy = measure( fixture) ;	// 集合なしでも有効WUA候補の肯定的到達だけは残せる。
	DRIVERCRATE_EXPECT( context,
					   legacy.has_value() &&
						   legacy->snapshot.network.combined.informationDeviceCount.value == 1) ;
	DRIVERCRATE_EXPECT( context,
					   legacy.has_value() &&
						   legacy->snapshot.network.combined.informationDeviceCount.extent ==
							   MeasurementExtent::LOWER_BOUND) ;
	DRIVERCRATE_EXPECT( context,
					   legacy.has_value() &&
						   legacy->snapshot.network.official.informationDeviceCount.extent ==
							   MeasurementExtent::NOT_MEASURED) ;
	fixture										  = makeMeasurementFixture() ;
	fixture.inventory.detailedEnumerationComplete = false ;
	fixture.inventory.enumeratedDeviceCount		  = {4, MeasurementExtent::LOWER_BOUND} ;
	fixture.inventory.unrepresentedDeviceCount	  = {1, MeasurementExtent::LOWER_BOUND} ;
	fixture.inventory.reasons = {{MeasurementReason::INCOMPLETE, MeasurementUnit::DEVICE, 1U}} ;
	fixture.inventory.error	  = 5U ;
	fixture.candidates[0].manufacturer.clear() ;
	fixture.candidates[0].version.clear() ;
	const auto inventory = measure( fixture) ;	// 未収録nodeとD内属性欠損を区別する。
	DRIVERCRATE_EXPECT( context,
					   inventory.has_value() &&
						   inventory->snapshot.inventory.unrepresentedDeviceCount.value == 1) ;
	DRIVERCRATE_EXPECT( context,
					   inventory.has_value() &&
						   inventory->snapshot.inventory.missingManufacturerCount.value == 1) ;
	DRIVERCRATE_EXPECT( context,
					   inventory.has_value() &&
						   inventory->snapshot.inventory.missingCurrentVersionCount.value == 1) ;
	DRIVERCRATE_EXPECT( context, inventory.has_value() &&
									inventory->snapshot.inventory.reasons.size() == 1U &&
									inventory->snapshot.inventory.error == 5U) ;
	DRIVERCRATE_EXPECT( context,
					   inventory.has_value() &&
						   inventory->snapshot.network.combined.informationDeviceCount.extent ==
							   MeasurementExtent::LOWER_BOUND) ;
	fixture = makeMeasurementFixture() ;
	fixture.candidates.erase( fixture.candidates.begin() + 4, fixture.candidates.begin() + 6) ;
	const auto payloadFailure =
		// 後段失敗でP候補がなくても検証済みmetadata根拠を保持する。
		measure( fixture) ;
	DRIVERCRATE_EXPECT(
		context,
		payloadFailure.has_value() &&
			payloadFailure->providers[2].measurement.devices.informationDeviceCount.value == 2) ;
	DRIVERCRATE_EXPECT(
		context,
		payloadFailure.has_value() &&
			payloadFailure->providers[2].measurement.devices.installReadyUpdateDeviceCount.value ==
				0) ;
}

/**
 * @brief 全無効と確定した対象0・検索情報0を分離する。
 * @param[in,out] context Assertion集計先。
 */
void testMeasurementEmptyScopes( TestContext &context)
{
	MeasurementFixture fixture = makeMeasurementFixture() ;	// 現在版三行だけを残す入力。
	fixture.candidates.resize( 3) ;
	fixture.evidence.clear() ;
	fixture.routes.clear() ;
	fixture.condition.enabledProviderIds = {L"local"} ;
	const auto disabled					 = measure( fixture) ;	// 無効は検索済み0ではない。
	DRIVERCRATE_EXPECT( context,
					   disabled.has_value() &&
						   disabled->snapshot.network.combined.informationDeviceCount.extent ==
							   MeasurementExtent::NOT_MEASURED) ;
	fixture.condition.enabledProviderIds.push_back( L"official-p") ;
	ProviderMeasurementEvidence empty ;	// 対象外を明示的に確認したProvider根拠。
	empty.providerId		  = L"official-p" ;
	empty.scanSessionId		  = 1 ;
	empty.scope				  = MeasurementScope::DEVICE_QUERY ;
	empty.eligible			  = exactSet( {}) ;
	empty.queryCompleted	  = exactSet( {}) ;
	empty.information		  = exactSet( {}) ;
	empty.applicabilityExtent = MeasurementExtent::EXACT ;
	empty.readinessExtent	  = MeasurementExtent::EXACT ;
	fixture.evidence		  = {empty} ;
	const auto notApplicable  = measure( fixture) ;	// 対象0を確定できた範囲でだけEXACT 0を使う。
	DRIVERCRATE_EXPECT(
		context, notApplicable.has_value() &&
					 notApplicable->snapshot.network.combined.informationDeviceCount.value == 0) ;
	DRIVERCRATE_EXPECT( context,
					   notApplicable.has_value() &&
						   notApplicable->snapshot.network.combined.informationDeviceCount.extent ==
							   MeasurementExtent::EXACT) ;
	fixture.evidence[0].eligible	   = exactSet( {L"d1"}) ;
	fixture.evidence[0].queryCompleted = exactSet( {L"d1"}) ;
	fixture.evidence[0].queryOutcome   = OutcomeCode::SUCCESS ;
	const auto noInformation = measure( fixture) ;	// 対象があっても正常query範囲で情報0を区別する。
	DRIVERCRATE_EXPECT( context,
					   noInformation.has_value() &&
						   noInformation->snapshot.network.combined.eligibleDeviceCount.value == 1) ;
	DRIVERCRATE_EXPECT(
		context, noInformation.has_value() &&
					 noInformation->snapshot.network.combined.informationDeviceCount.value == 0) ;
	fixture.evidence[0].queryCompleted = {MeasurementExtent::LOWER_BOUND, {}} ;
	fixture.evidence[0].queryOutcome   = OutcomeCode::FAILURE ;
	const auto failed = measure( fixture) ;	// 検索失敗の0を確定した情報なしにしない。
	DRIVERCRATE_EXPECT( context,
					   failed.has_value() &&
						   failed->snapshot.network.combined.informationDeviceCount.value == 0) ;
	DRIVERCRATE_EXPECT( context,
					   failed.has_value() &&
						   failed->snapshot.network.combined.informationDeviceCount.extent ==
							   MeasurementExtent::LOWER_BOUND) ;
}

/**
 * @brief 契約違反を未照合や0へ縮退させない。
 * @param[in,out] context Assertion集計先。
 */
void testMeasurementRejections( TestContext &context)
{
	MeasurementFixture fixture = makeMeasurementFixture() ;	// 一度に一つの拒否条件を加える入力。
	fixture.candidates.push_back( fixture.candidates.front()) ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;
	fixture							 = makeMeasurementFixture() ;
	fixture.candidates[3].providerId = L"unknown" ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;
	fixture							  = makeMeasurementFixture() ;
	fixture.evidence[0].scanSessionId = 2 ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;
	fixture						 = makeMeasurementFixture() ;
	fixture.evidence[1].eligible = exactSet( {L"d1"}) ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;
	fixture							   = makeMeasurementFixture() ;
	fixture.evidence[0].queryCompleted = exactSet( {L"d1", L"d2", L"d3"}) ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;
	fixture							 = makeMeasurementFixture() ;
	fixture.evidence[0].queryOutcome = static_cast<OutcomeCode>( 99) ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;
	fixture = makeMeasurementFixture() ;
	fixture.evidence[1].information.identities.push_back( L"d1") ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;
	fixture = makeMeasurementFixture() ;
	fixture.evidence[1].records.push_back( fixture.evidence[1].records.front()) ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;
	fixture = makeMeasurementFixture() ;
	fixture.condition.enabledProviderIds.push_back( L"managed") ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;
	fixture									= makeMeasurementFixture() ;
	fixture.inventory.enumeratedDeviceCount = {2, MeasurementExtent::EXACT} ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;
	fixture									   = makeMeasurementFixture() ;
	fixture.inventory.unrepresentedDeviceCount = {1, MeasurementExtent::EXACT} ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;
	fixture									 = makeMeasurementFixture() ;
	fixture.inventory.representedDeviceCount = {std::numeric_limits<std::uint64_t>::max(),
												MeasurementExtent::EXACT} ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;
	fixture = makeMeasurementFixture() ;
	fixture.routes.push_back( L"p-1") ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;
	fixture							   = makeMeasurementFixture() ;
	fixture.condition.contractRevision = 2 ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;
	fixture								   = makeMeasurementFixture() ;
	fixture.condition.usedDefaultProviders = true ;
	DRIVERCRATE_EXPECT( context, !measure( fixture).has_value()) ;
}

/**
 * @brief Worker公開時のoperation、session、nested measurementを一括で再検証する。
 * @param[in,out] context Assertion集計先。
 */
void testPublishedMeasurementValidation( TestContext &context)
{
	MeasurementFixture fixture = makeMeasurementFixture() ;				// 正常公開結果を作る基準入力。
	const auto published = makePublishedMeasurementResult( fixture) ;	// 全nested値を持つ公開DTO。
	DRIVERCRATE_EXPECT( context, published.has_value()) ;
	// 基準結果を作れなければ後続の変更試験で不正参照しない。
	if( !published.has_value()) {
		return ;
	}

	DRIVERCRATE_EXPECT( context,
					   isPublishedScanMeasurementValid( fixture.condition.operationId, *published)) ;
	DRIVERCRATE_EXPECT(
		context, !isPublishedScanMeasurementValid( fixture.condition.operationId + 1U, *published)) ;
	ScanResult invalid = *published ;	// 一条件ずつ壊す公開結果のcopy。
	invalid.measurement->context.applicationVersion.clear() ;
	DRIVERCRATE_EXPECT( context,
					   !isPublishedScanMeasurementValid( fixture.condition.operationId, invalid)) ;
	invalid = *published ;
	invalid.providerReports[0].coverage.measurement.reset() ;
	DRIVERCRATE_EXPECT( context,
					   !isPublishedScanMeasurementValid( fixture.condition.operationId, invalid)) ;
	invalid																  = *published ;
	invalid.localCoverage[0].measurement->combined.informationDeviceCount = {
		4U, MeasurementExtent::EXACT} ;
	DRIVERCRATE_EXPECT( context,
					   !isPublishedScanMeasurementValid( fixture.condition.operationId, invalid)) ;
	invalid							 = *published ;
	invalid.providerReports[0].state = ProviderScanState::DISABLED ;
	DRIVERCRATE_EXPECT( context,
					   !isPublishedScanMeasurementValid( fixture.condition.operationId, invalid)) ;
	invalid.measurement.reset() ;
	DRIVERCRATE_EXPECT( context,
					   isPublishedScanMeasurementValid( fixture.condition.operationId, invalid)) ;
}

} // namespace

/** @see tests/unit/scan_measurement_tests.h 宣言側の契約を正本とする。 */
void runScanMeasurementTests( TestContext &context)
{
	testCountExtents( context) ;
	testBoundedEnumerationClassification( context) ;
	testCandidateAndDeviceLimits( context) ;
	testOfficialSourceSummary( context) ;
	testOfficialSourceAggregation( context) ;
	testMeasurementUnions( context) ;
	testCandidateStageClassifications( context) ;
	testMeasurementPartialResults( context) ;
	testMeasurementEmptyScopes( context) ;
	testMeasurementRejections( context) ;
	testPublishedMeasurementValidation( context) ;
}

} // namespace drivercrate::test
