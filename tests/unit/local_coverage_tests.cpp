//------------------------------------------------------------------------------
/**
 * @file local_coverage_tests.cpp
 * @brief Local候補到達集計単体試験実装。
 * @version 01.00.00
 * @date 2026/09/02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Provider探索経路追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  利用者選択package集計追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Manufacturer intake分類試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  準備後のscan計測保持試験を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 架空のmanufacturer、class、opaque IDで取得元別の重複排除と拒否条件を検証します。
 */
//------------------------------------------------------------------------------

#include "local_coverage_tests.h"

#include "core/local_coverage.h"
#include "core/provider_registry.h"
#include "test_framework.h"

#include <array>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Test用Provider定義を作成する。
 *
 * 集計に関係しない表示名と選択tierは固定値を使用する。
 *
 * @param[in] id Test内で一意なstable Provider ID。
 * @param[in] source 集計対象のtrust boundary capability。
 * @return Scanと指定取得元capabilityを持つProvider定義。
 */
//------------------------------------------------------------------------------
[[nodiscard]] ProviderDescriptor makeProvider( const std::wstring_view  id,
											  const ProviderCapability source)
{
	CandidateDiscoveryBasis discoveryBasis =	// 集計元capabilityに対応する探索経路。
		CandidateDiscoveryBasis::LOCAL_INVENTORY ;
	// 管理service capabilityにWindows委譲の検出根拠を対応付ける。
	if( source == ProviderCapability::MANAGED_SERVICE) {
		discoveryBasis = CandidateDiscoveryBasis::MANAGED_SERVICE ;
	}
	// 公式network capabilityに構造化catalogの検出根拠を対応付ける。
	else if( source == ProviderCapability::OFFICIAL_NETWORK) {
		discoveryBasis = CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG ;
	}
	// 明示file選択capabilityに手動取込の検出根拠を対応付ける。
	else if( source == ProviderCapability::USER_SELECTED_FILE) {
		discoveryBasis = CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE ;
	}

	return {.id				  = std::wstring( id),
			.displayName	  = std::wstring( id),
			.capabilities	  = capabilityMask( ProviderCapability::SCAN) | capabilityMask( source),
			.selectionTier	  = ProviderSelectionTier::LOCAL_INVENTORY,
			.discoveryBasis	  = discoveryBasis,
			.enabledByDefault = true} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Test用candidateを作成する。
 *
 * Hardware IDや実machine inventoryをtest dataへ含めない。
 *
 * @param[in] identity Scan session内で一意な架空candidate ID。
 * @param[in] device Candidateを束ねる架空opaque device ID。
 * @param[in] provider Registryへ照合するProvider ID。
 * @param[in] current trueの場合はpresent deviceの現在版行。
 * @param[in] manufacturer 現在deviceの架空製造元表示名。
 * @param[in] driverClass 現在deviceの架空setup class表示名。
 * @return Local coverage試験に必要なfieldを持つcandidate。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UpdateCandidate makeCandidate( const std::wstring_view identity,
											const std::wstring_view device,
											const std::wstring_view provider, const bool current,
											const std::wstring_view manufacturer,
											const std::wstring_view driverClass)
{
	return {.identity		 = std::wstring( identity),
			.deviceIdentity	 = std::wstring( device),
			.providerId		 = std::wstring( provider),
			.packageIdentity = L"package-" + std::wstring( identity),
			.manufacturer	 = std::wstring( manufacturer),
			.driverClass	 = std::wstring( driverClass),
			.discoveryBasis	 = CandidateDiscoveryBasis::LOCAL_INVENTORY,
			.current		 = current} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Manufacturer／class別に候補到達deviceを一度だけ数える。
 *
 * 同一deviceの複数候補を重複計数せず、取得元別件数と全取得元のunionを別々に確定する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testSourceCounts( TestContext &context)
{
	const std::array providers{
		makeProvider( L"local", ProviderCapability::LOCAL_INVENTORY),
		makeProvider( L"managed", ProviderCapability::MANAGED_SERVICE),
		makeProvider( L"official", ProviderCapability::OFFICIAL_NETWORK),
		// 架空registry。
		makeProvider( L"user-selected", ProviderCapability::USER_SELECTED_FILE)} ;
	std::vector<UpdateCandidate> candidates ;	// 二group、三deviceの架空candidate集合。
	candidates.push_back(
		makeCandidate( L"current-a", L"device-a", L"local", true, L"Vendor A", L"Display")) ;
	candidates.push_back(
		makeCandidate( L"current-b", L"device-b", L"local", true, L"Vendor B", L"Net")) ;
	candidates.push_back(
		makeCandidate( L"current-c", L"device-c", L"local", true, L"Vendor A", L"Display")) ;
	candidates.push_back( makeCandidate( L"local-a-1", L"device-a", L"local", false, L"", L"")) ;
	candidates.push_back( makeCandidate( L"local-a-2", L"device-a", L"local", false, L"", L"")) ;
	candidates.push_back( makeCandidate( L"managed-a", L"device-a", L"managed", false, L"", L"")) ;
	candidates.push_back( makeCandidate( L"managed-b", L"device-b", L"managed", false, L"", L"")) ;
	candidates.push_back( makeCandidate( L"official-a", L"device-a", L"official", false, L"", L"")) ;
	candidates.push_back( makeCandidate( L"official-c", L"device-c", L"official", false, L"", L"")) ;
	candidates.push_back(
		makeCandidate( L"selected-c", L"device-c", L"user-selected", false, L"", L"")) ;
	candidates.push_back( makeCandidate( L"unmatched", L"synthetic-device", L"managed", false,
									   L"Vendor X", L"Unknown")) ;

	const auto coverage = aggregateLocalCoverage( candidates, providers) ;	// 集計結果。
	DRIVERCRATE_EXPECT( context, coverage.has_value()) ;
	DRIVERCRATE_EXPECT( context, coverage.has_value() && coverage->size() == 2) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( !coverage.has_value() || coverage->size() != 2) {
		return ;
	}

	const LocalCoverageEntry &display = coverage->front() ;	// Vendor A／Display集計。
	DRIVERCRATE_EXPECT( context, display.manufacturer == L"Vendor A") ;
	DRIVERCRATE_EXPECT( context, display.driverClass == L"Display") ;
	DRIVERCRATE_EXPECT( context, display.deviceCount == 2) ;
	DRIVERCRATE_EXPECT( context, display.candidateDeviceCount == 2) ;
	DRIVERCRATE_EXPECT( context, display.managedCandidateDeviceCount == 1) ;
	DRIVERCRATE_EXPECT( context, display.officialCandidateDeviceCount == 2) ;
	DRIVERCRATE_EXPECT( context, display.userSelectedCandidateDeviceCount == 1) ;
	DRIVERCRATE_EXPECT( context, display.localCandidateDeviceCount == 1) ;
	DRIVERCRATE_EXPECT( context, display.reviewState == ManufacturerReviewState::PENDING_INTAKE) ;

	const LocalCoverageEntry &network = coverage->back() ;	// Vendor B／Net集計。
	DRIVERCRATE_EXPECT( context, network.manufacturer == L"Vendor B") ;
	DRIVERCRATE_EXPECT( context, network.driverClass == L"Net") ;
	DRIVERCRATE_EXPECT( context, network.deviceCount == 1) ;
	DRIVERCRATE_EXPECT( context, network.candidateDeviceCount == 1) ;
	DRIVERCRATE_EXPECT( context, network.managedCandidateDeviceCount == 1) ;
	DRIVERCRATE_EXPECT( context, network.officialCandidateDeviceCount == 0) ;
	DRIVERCRATE_EXPECT( context, network.userSelectedCandidateDeviceCount == 0) ;
	DRIVERCRATE_EXPECT( context, network.localCandidateDeviceCount == 0) ;
	DRIVERCRATE_EXPECT( context, network.reviewState == ManufacturerReviewState::PENDING_INTAKE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Manufacturer表示名をS63+ intake状態へ分類する。
 *
 * 審査済みalias、Windows標準、未列挙、識別不能を表示名だけで分類し、表記揺れ以外を推測しないことを確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testManufacturerReviewClassification( TestContext &context)
{
	DRIVERCRATE_EXPECT( context, classifyManufacturerReviewState( L"Intel(R) Corporation") ==
									ManufacturerReviewState::REVIEWED) ;
	DRIVERCRATE_EXPECT( context, classifyManufacturerReviewState( L"Dell Inc.") ==
									ManufacturerReviewState::REVIEWED) ;
	DRIVERCRATE_EXPECT( context, classifyManufacturerReviewState( L"Microsoft Corporation") ==
									ManufacturerReviewState::PLATFORM) ;
	DRIVERCRATE_EXPECT( context, classifyManufacturerReviewState( L"(標準システム デバイス)") ==
									ManufacturerReviewState::PLATFORM) ;
	DRIVERCRATE_EXPECT( context, classifyManufacturerReviewState( L"Fictional Device Company") ==
									ManufacturerReviewState::PENDING_INTAKE) ;
	DRIVERCRATE_EXPECT( context, classifyManufacturerReviewState( L" - . ") ==
									ManufacturerReviewState::UNIDENTIFIED) ;
	DRIVERCRATE_EXPECT( context, classifyManufacturerReviewState( L"") ==
									ManufacturerReviewState::UNIDENTIFIED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief InventoryとProviderの矛盾を拒否する。
 *
 * 重複current device、未知Provider、曖昧なtrust boundaryをfail-closedで拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testInvalidContracts( TestContext &context)
{
	const std::array	  providers{makeProvider( L"local", ProviderCapability::LOCAL_INVENTORY),
								// 正常registry。
								makeProvider( L"managed", ProviderCapability::MANAGED_SERVICE)} ;
	const UpdateCandidate current =
		// 正常現在版。
		makeCandidate( L"current", L"device", L"local", true, L"Vendor", L"System") ;

	const std::array duplicateCurrent{current, current} ;	// 同じopaque deviceを持つ重複現在版。
	DRIVERCRATE_EXPECT( context, !aggregateLocalCoverage( duplicateCurrent, providers).has_value()) ;

	// 未知Providerの候補を含むcoverage集約の拒否用入力。
	const std::array unknownProvider{
		current, makeCandidate( L"candidate", L"device", L"unknown", false, L"", L"")} ;
	DRIVERCRATE_EXPECT( context, !aggregateLocalCoverage( unknownProvider, providers).has_value()) ;

	ProviderDescriptor ambiguous = makeProvider(
		L"ambiguous", ProviderCapability::MANAGED_SERVICE) ;	// 複数trust boundaryのProvider。
	ambiguous.capabilities |= capabilityMask( ProviderCapability::OFFICIAL_NETWORK) ;
	// 同じ対象へ曖昧なProvider定義を与えるcoverage検証用入力。
	const std::array ambiguousProviders{providers[0], ambiguous} ;
	DRIVERCRATE_EXPECT(
		context, !aggregateLocalCoverage( std::array{current}, ambiguousProviders).has_value()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 空inventoryを空集計として返す。
 *
 * Present deviceが0件の正常scanを集計失敗と誤認しない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testEmptyInventory( TestContext &context)
{
	const std::array				   providers{	// 最小registry。
								 makeProvider( L"local", ProviderCapability::LOCAL_INVENTORY)} ;
	const std::vector<UpdateCandidate> candidates ;							// Present deviceがない空inventory。
	const auto coverage = aggregateLocalCoverage( candidates, providers) ;	// 空集計結果。
	DRIVERCRATE_EXPECT( context, coverage.has_value()) ;
	DRIVERCRATE_EXPECT( context, coverage.has_value() && coverage->empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 準備後の候補到達再集計でscan時点の段階別measurementだけを保持する。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testMeasurementPreservation( TestContext &context)
{
	const std::array providers{makeProvider( L"local", ProviderCapability::LOCAL_INVENTORY),
							   // 最小registry。
							   makeProvider( L"official", ProviderCapability::OFFICIAL_NETWORK)} ;
	std::vector<UpdateCandidate> scanCandidates{
		// Scan時のD。
		makeCandidate( L"current", L"device", L"local", true, L"Vendor", L"Net")} ;
	auto scanCoverage = aggregateLocalCoverage( scanCandidates, providers) ;	// 候補準備前のgroup。
	DRIVERCRATE_EXPECT( context, scanCoverage.has_value() && scanCoverage->size() == 1U) ;
	// 基準groupが得られない場合は後続の要素参照を行わない。
	if( !scanCoverage.has_value() || scanCoverage->size() != 1U) {
		return ;
	}

	NetworkCoverageMeasurement snapshot ;	// Scan完了時点に固定する段階別件数。
	snapshot.combined.eligibleDeviceCount	 = {1U, MeasurementExtent::EXACT} ;
	snapshot.combined.informationDeviceCount = {0U, MeasurementExtent::EXACT} ;
	(*scanCoverage)[0].measurement			 = snapshot ;
	scanCandidates.push_back( makeCandidate( L"prepared", L"device", L"official", false, L"", L"")) ;
	auto refreshed =
		// 準備候補追加後の従来集計。
		aggregateLocalCoverage( scanCandidates, providers) ;
	DRIVERCRATE_EXPECT( context, refreshed.has_value() && refreshed->size() == 1U) ;
	// 再集計が成立した場合だけsnapshot保持と新しい候補到達値を検証する。
	if( refreshed.has_value() && refreshed->size() == 1U) {
		DRIVERCRATE_EXPECT( context, preserveLocalCoverageMeasurements( *scanCoverage, *refreshed)) ;
		DRIVERCRATE_EXPECT( context, (*refreshed)[0].candidateDeviceCount == 1U) ;
		DRIVERCRATE_EXPECT(
			context, (*refreshed)[0].measurement->combined.informationDeviceCount.value == 0U) ;
		(*refreshed)[0].deviceCount = 2U ;
		DRIVERCRATE_EXPECT( context, !preserveLocalCoverageMeasurements( *scanCoverage, *refreshed)) ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/local_coverage_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runLocalCoverageTests( TestContext &context)
{
	testSourceCounts( context) ;
	testManufacturerReviewClassification( context) ;
	testInvalidContracts( context) ;
	testEmptyInventory( context) ;
	testMeasurementPreservation( context) ;
}

} // namespace drivercrate::test
