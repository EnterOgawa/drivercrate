//------------------------------------------------------------------------------
/**
 * @file candidate_source_group_tests.cpp
 * @brief 同一版取得元候補group単体試験実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  候補別既定選択根拠試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  探索経路境界試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Candidate行とroutingを削除せず、明示版完全一致の関連付けを試験します。
 */
//------------------------------------------------------------------------------

#include "candidate_source_group_tests.h"

#include "core/candidate_source_group.h"
#include "test_framework.h"

#include <array>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
/**
 * @brief Test用Provider descriptorを作成する。
 *
 * Tierに対応する信頼境界capabilityを設定して根拠を検証する。
 *
 * @param[in] id Test内だけで使用するstable ID。
 * @param[in] tier 候補根拠へ対応する取得元区分。
 * @return Group試験に必要なfieldを持つProvider descriptor。
 */
//------------------------------------------------------------------------------
[[nodiscard]] ProviderDescriptor makeProvider( const std::wstring_view	  id,
											  const ProviderSelectionTier tier)
{
	ProviderCapability boundary = ProviderCapability::LOCAL_INVENTORY ;	// 取得元境界bit。
	// 管理service tierに整合する信頼境界でProvider fixtureを構築する。
	if( tier == ProviderSelectionTier::MANAGED_SERVICE) {
		boundary = ProviderCapability::MANAGED_SERVICE ;
	}
	// 公式vendor tierに整合するnetwork信頼境界でProvider fixtureを構築する。
	else if( tier == ProviderSelectionTier::OEM_OFFICIAL ||
			tier == ProviderSelectionTier::COMPONENT_OFFICIAL) {
		boundary = ProviderCapability::OFFICIAL_NETWORK ;
	}

	CandidateDiscoveryBasis discoveryBasis =	// Tierに対応する正常な探索経路。
		CandidateDiscoveryBasis::LOCAL_INVENTORY ;
	// 管理serviceの取得元にはWindows委譲の検出根拠を設定する。
	if( tier == ProviderSelectionTier::MANAGED_SERVICE) {
		discoveryBasis = CandidateDiscoveryBasis::MANAGED_SERVICE ;
	}
	// 公式vendorの取得元には構造化catalogの検出根拠を設定する。
	else if( tier == ProviderSelectionTier::OEM_OFFICIAL ||
			tier == ProviderSelectionTier::COMPONENT_OFFICIAL) {
		discoveryBasis = CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG ;
	}

	return {.id			  = std::wstring( id),
			.displayName  = std::wstring( id),
			.capabilities = static_cast<ProviderCapabilityMask>( ProviderCapability::SCAN) |
							static_cast<ProviderCapabilityMask>( boundary),
			.selectionTier	  = tier,
			.discoveryBasis	  = discoveryBasis,
			.enabledByDefault = true} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Test用install可能candidateを作成する。
 *
 * 各試験は必要な差分fieldだけを呼出し後に変更する。
 *
 * @param[in] identity Test候補の一意ID。
 * @param[in] providerId Registryへ照合するProvider ID。
 * @param[in] preference Providerが提示する既定選択根拠。
 * @return Deviceと版を固定した通常更新candidate。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UpdateCandidate makeCandidate( const std::wstring_view			 identity,
											const std::wstring_view			 providerId,
											const CandidateDefaultPreference preference)
{
	CandidateDiscoveryBasis discoveryBasis =	// Candidate根拠に対応する正常な探索経路。
		CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG ;
	// 管理service推奨の候補fixtureはWindows委譲の検出根拠で構築する。
	if( preference == CandidateDefaultPreference::MANAGED_APPLICABLE) {
		discoveryBasis = CandidateDiscoveryBasis::MANAGED_SERVICE ;
	}
	// local候補fixtureはlocal列挙の検出根拠で構築する。
	else if( providerId == L"local") {
		discoveryBasis = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
	}

	return {.identity		   = std::wstring( identity),
			.deviceIdentity	   = L"device-a",
			.providerId		   = std::wstring( providerId),
			.packageIdentity   = L"package-" + std::wstring( identity),
			.version		   = L"10.20.30.40",
			.action			   = DriverAction::UPDATE,
			.defaultPreference = preference,
			.discoveryBasis	   = discoveryBasis,
			.recommended	   = preference != CandidateDefaultPreference::NONE &&
						   preference != CandidateDefaultPreference::COMPONENT_GENERIC,
			.installable = true} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 異なる取得元の完全一致版を一groupへまとめることを検証する。
 *
 * Candidate順と無関係にOEM検証済み候補を既定取得元にする。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testGroupAndPreference( TestContext &context)
{
	// 各取得元区分を一つずつ持つProvider定義群。
	const std::array providers{
		makeProvider( L"component", ProviderSelectionTier::COMPONENT_OFFICIAL),
		makeProvider( L"local", ProviderSelectionTier::LOCAL_INVENTORY),
		makeProvider( L"oem", ProviderSelectionTier::OEM_OFFICIAL),
		makeProvider( L"managed", ProviderSelectionTier::MANAGED_SERVICE)} ;
	const std::array candidates{
		// 同一device／版／actionを持つ取得元別候補群。
		makeCandidate( L"component-candidate", L"component",
					  CandidateDefaultPreference::COMPONENT_REFERENCE),
		makeCandidate( L"local-candidate", L"local", CandidateDefaultPreference::NONE),
		makeCandidate( L"oem-candidate", L"oem", CandidateDefaultPreference::OEM_VALIDATED),
		makeCandidate( L"managed-candidate", L"managed",
					  CandidateDefaultPreference::MANAGED_APPLICABLE)} ;

	const auto groups = groupEquivalentCandidateSources( candidates, providers) ;	// 統合結果。
	DRIVERCRATE_EXPECT( context, groups.has_value()) ;
	DRIVERCRATE_EXPECT( context, groups->size() == 1) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( !groups.has_value() || groups->size() != 1) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, groups->front().candidateIndexes.size() == candidates.size()) ;
	DRIVERCRATE_EXPECT( context, groups->front().candidateIndexes.front() == 0) ;
	DRIVERCRATE_EXPECT( context, groups->front().candidateIndexes.back() == 3) ;
	DRIVERCRATE_EXPECT( context, groups->front().preferredCandidateIndex == 2) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同一根拠ではscan結果順を使用することを検証する。
 *
 * Registry順でなくcandidate初出順をtie breakに使用する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testCandidateOrderTie( TestContext &context)
{
	// Registry順とcandidate順が逆になる同じOEM区分のProvider定義群。
	const std::array providers{makeProvider( L"oem-a", ProviderSelectionTier::OEM_OFFICIAL),
							   makeProvider( L"oem-b", ProviderSelectionTier::OEM_OFFICIAL)} ;
	const std::array candidates{
		// Provider bを先にした同根拠の候補群。
		makeCandidate( L"from-b", L"oem-b", CandidateDefaultPreference::OEM_VALIDATED),
		makeCandidate( L"from-a", L"oem-a", CandidateDefaultPreference::OEM_VALIDATED)} ;
	const auto groups = groupEquivalentCandidateSources( candidates, providers) ;	// 統合結果。
	DRIVERCRATE_EXPECT( context, groups.has_value()) ;
	DRIVERCRATE_EXPECT( context, groups->size() == 1) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( groups.has_value() && groups->size() == 1) {
		DRIVERCRATE_EXPECT( context, groups->front().preferredCandidateIndex == 0) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 推測または曖昧な候補をgroup化しないことを検証する。
 *
 * 版欠損、操作なし、操作差、選択不能、重複をまとめない。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testNonEquivalentCandidates( TestContext &context)
{
	// OEMとcomponentの二つの取得元境界を持つProvider定義群。
	const std::array providers{
		makeProvider( L"source-a", ProviderSelectionTier::OEM_OFFICIAL),
		makeProvider( L"source-b", ProviderSelectionTier::COMPONENT_OFFICIAL)} ;

	std::array missingVersion{
		// 一方の明示versionを欠損させる候補群。
		makeCandidate( L"missing-a", L"source-a", CandidateDefaultPreference::OEM_VALIDATED),
		makeCandidate( L"missing-b", L"source-b", CandidateDefaultPreference::COMPONENT_REFERENCE)} ;
	missingVersion[0].version.clear() ;
	const auto missingGroups =
		// 版欠損結果。
		groupEquivalentCandidateSources( missingVersion, providers) ;
	DRIVERCRATE_EXPECT( context, missingGroups.has_value() && missingGroups->empty()) ;

	std::array noAction{
		// 両方のactionをNoneへ変更する候補群。
		makeCandidate( L"none-a", L"source-a", CandidateDefaultPreference::OEM_VALIDATED),
		makeCandidate( L"none-b", L"source-b", CandidateDefaultPreference::COMPONENT_REFERENCE)} ;
	noAction[0].action			  = DriverAction::NONE ;
	noAction[1].action			  = DriverAction::NONE ;
	noAction[0].recommended		  = false ;
	noAction[1].recommended		  = false ;
	noAction[0].defaultPreference = CandidateDefaultPreference::NONE ;
	noAction[1].defaultPreference = CandidateDefaultPreference::NONE ;
	const auto noActionGroups =
		// 操作なし結果。
		groupEquivalentCandidateSources( noAction, providers) ;
	DRIVERCRATE_EXPECT( context, noActionGroups.has_value() && noActionGroups->empty()) ;

	std::array differentAction{
		// 一方をReinstallへ変更する候補群。
		makeCandidate( L"action-a", L"source-a", CandidateDefaultPreference::OEM_VALIDATED),
		makeCandidate( L"action-b", L"source-b", CandidateDefaultPreference::COMPONENT_REFERENCE)} ;
	differentAction[1].action			 = DriverAction::REINSTALL ;
	differentAction[1].recommended		 = false ;
	differentAction[1].defaultPreference = CandidateDefaultPreference::NONE ;
	const auto actionGroups =
		// 操作不一致結果。
		groupEquivalentCandidateSources( differentAction, providers) ;
	DRIVERCRATE_EXPECT( context, actionGroups.has_value() && actionGroups->empty()) ;

	std::array displayOnly{
		// 一方を表示専用へ変更する候補群。
		makeCandidate( L"display-a", L"source-a", CandidateDefaultPreference::OEM_VALIDATED),
		makeCandidate( L"display-b", L"source-b", CandidateDefaultPreference::COMPONENT_REFERENCE)} ;
	displayOnly[1].installable		 = false ;
	displayOnly[1].recommended		 = false ;
	displayOnly[1].defaultPreference = CandidateDefaultPreference::NONE ;
	const auto displayGroups =
		// 選択不能結果。
		groupEquivalentCandidateSources( displayOnly, providers) ;
	DRIVERCRATE_EXPECT( context, displayGroups.has_value() && displayGroups->empty()) ;

	const std::array duplicateSource{
		// 同一Providerが同じgroup keyを重複提示する候補群。
		makeCandidate( L"duplicate-a", L"source-a", CandidateDefaultPreference::OEM_VALIDATED),
		makeCandidate( L"duplicate-b", L"source-a", CandidateDefaultPreference::OEM_VALIDATED),
		makeCandidate( L"duplicate-c", L"source-b",
					  CandidateDefaultPreference::COMPONENT_REFERENCE)} ;
	const auto duplicateGroups =
		// 同一Provider重複結果。
		groupEquivalentCandidateSources( duplicateSource, providers) ;
	DRIVERCRATE_EXPECT( context, duplicateGroups.has_value() && duplicateGroups->empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不正registryまたはcandidate identityを拒否する。
 *
 * 空、重複、未知IDを既定取得元の推測へ使用しない。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testInvalidInput( TestContext &context)
{
	// 正常入力の基準にする二つのProvider定義。
	const std::array validProviders{
		makeProvider( L"source-a", ProviderSelectionTier::OEM_OFFICIAL),
		makeProvider( L"source-b", ProviderSelectionTier::COMPONENT_OFFICIAL)} ;
	const std::array validCandidates{
		// 正常入力の基準にする同一版候補群。
		makeCandidate( L"candidate-a", L"source-a", CandidateDefaultPreference::OEM_VALIDATED),
		makeCandidate( L"candidate-b", L"source-b",
					  CandidateDefaultPreference::COMPONENT_REFERENCE)} ;
	const std::vector<ProviderDescriptor> emptyProviders ;	// Provider未登録の異常入力。
	DRIVERCRATE_EXPECT(
		context, !groupEquivalentCandidateSources( validCandidates, emptyProviders).has_value()) ;

	const std::array duplicateProviders{
		// Stable IDが重複するProvider定義群。
		makeProvider( L"source-a", ProviderSelectionTier::OEM_OFFICIAL),
		makeProvider( L"source-a", ProviderSelectionTier::COMPONENT_OFFICIAL)} ;
	DRIVERCRATE_EXPECT(
		context, !groupEquivalentCandidateSources( validCandidates, duplicateProviders).has_value()) ;

	std::array unknownProvider	  = validCandidates ;	// 未知Provider IDへ変更する候補群。
	unknownProvider[1].providerId = L"unknown" ;
	DRIVERCRATE_EXPECT(
		context, !groupEquivalentCandidateSources( unknownProvider, validProviders).has_value()) ;

	std::array duplicateIdentity  = validCandidates ;	// Identityを重複させる候補群。
	duplicateIdentity[1].identity = duplicateIdentity[0].identity ;
	DRIVERCRATE_EXPECT(
		context, !groupEquivalentCandidateSources( duplicateIdentity, validProviders).has_value()) ;

	std::array contradictoryPreference = validCandidates ;	// 根拠とtierを矛盾させる候補群。
	contradictoryPreference[0].defaultPreference = CandidateDefaultPreference::MANAGED_APPLICABLE ;
	DRIVERCRATE_EXPECT(
		context,
		!groupEquivalentCandidateSources( contradictoryPreference, validProviders).has_value()) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/candidate_source_group_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runCandidateSourceGroupTests( TestContext &context)
{
	testGroupAndPreference( context) ;
	testCandidateOrderTie( context) ;
	testNonEquivalentCandidates( context) ;
	testInvalidInput( context) ;
}

} // namespace drivercrate::test
