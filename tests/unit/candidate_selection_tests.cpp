//------------------------------------------------------------------------------
/**
 * @file candidate_selection_tests.cpp
 * @brief Driver候補の既定選択単体試験実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  探索経路選択境界試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  取得元未証明package境界試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 取得元間でversionや日付を比較せず、Providerが明示した根拠だけを初期選択へ使用することを検証します。
 */
//------------------------------------------------------------------------------

#include "candidate_selection_tests.h"

#include "core/candidate_selection.h"
#include "test_framework.h"

#include <array>
#include <string>
#include <string_view>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 内部試験関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Test用Provider定義を作成する。
 *
 * Tierに対応するManagedService、OfficialNetwork、LocalInventoryを一つだけ設定する。
 *
 * @param[in] id Test内だけで使用するstable ID。
 * @param[in] tier 候補根拠へ対応する取得元tier。
 * @return Scan、install、および信頼境界capabilityを持つ定義。
 */
//------------------------------------------------------------------------------
[[nodiscard]] ProviderDescriptor makeProvider( const std::wstring_view	  id,
											  const ProviderSelectionTier tier)
{
	ProviderCapability boundary = ProviderCapability::LOCAL_INVENTORY ;	// 取得元境界bit。
	// 管理service tierのfixtureは同じ信頼境界capabilityで構築する。
	if( tier == ProviderSelectionTier::MANAGED_SERVICE) {
		boundary = ProviderCapability::MANAGED_SERVICE ;
	}
	// 利用者取込tierのfixtureはfile明示選択の信頼境界で構築する。
	else if( tier == ProviderSelectionTier::USER_PROVIDED) {
		boundary = ProviderCapability::USER_SELECTED_FILE ;
	}
	// 公式vendor tierのfixtureは公式networkの信頼境界で構築する。
	else if( tier == ProviderSelectionTier::OEM_OFFICIAL ||
			tier == ProviderSelectionTier::COMPONENT_OFFICIAL) {
		boundary = ProviderCapability::OFFICIAL_NETWORK ;
	}

	CandidateDiscoveryBasis discoveryBasis =	// Tierに対応する正常な探索経路。
		CandidateDiscoveryBasis::LOCAL_INVENTORY ;
	// 管理serviceのfixtureにはWindows委譲の検出根拠を対応付ける。
	if( tier == ProviderSelectionTier::MANAGED_SERVICE) {
		discoveryBasis = CandidateDiscoveryBasis::MANAGED_SERVICE ;
	}
	// 利用者取込のfixtureには手動package取込の検出根拠を対応付ける。
	else if( tier == ProviderSelectionTier::USER_PROVIDED) {
		discoveryBasis = CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE ;
	}
	// 公式vendorのfixtureには公式構造化catalogの検出根拠を対応付ける。
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
 * @brief Test用通常更新候補を作成する。
 *
 * Versionと日付は選択へ影響しない固定値にする。
 *
 * @param[in] identity Test候補の一意ID。
 * @param[in] device Candidateを束ねるopaque device ID。
 * @param[in] providerId Registryへ照合するProvider ID。
 * @param[in] preference Providerが提示する既定選択根拠。
 * @param[in] recommended Providerが推奨通常更新とした場合true。
 * @return 指定値を持つinstall可能な通常更新候補。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UpdateCandidate makeCandidate( const std::wstring_view			 identity,
											const std::wstring_view			 device,
											const std::wstring_view			 providerId,
											const CandidateDefaultPreference preference,
											const bool						 recommended)
{
	CandidateDiscoveryBasis discoveryBasis =	// Candidate根拠に対応する正常な探索経路。
		CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG ;
	// Windows適用性に従うfixtureでは管理serviceの検出根拠を使用する。
	if( preference == CandidateDefaultPreference::MANAGED_APPLICABLE) {
		discoveryBasis = CandidateDiscoveryBasis::MANAGED_SERVICE ;
	}
	// local Providerのfixtureではlocal列挙の検出根拠を使用する。
	else if( providerId == L"local") {
		discoveryBasis = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
	}

	return {.identity		   = std::wstring( identity),
			.deviceIdentity	   = std::wstring( device),
			.providerId		   = std::wstring( providerId),
			.packageIdentity   = L"package-" + std::wstring( identity),
			.version		   = L"1.0.0",
			.driverDate		   = L"2026/09/02",
			.action			   = DriverAction::UPDATE,
			.defaultPreference = preference,
			.discoveryBasis	   = discoveryBasis,
			.recommended	   = recommended,
			.installable	   = true} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 候補別既定選択根拠の固定順位を検証する。
 *
 * ADR 0038の順序と同順位を優先しない条件を検証する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testPreferenceOrder( TestContext &context)
{
	DRIVERCRATE_EXPECT( context, candidateDefaultPreferencePrecedes(
									CandidateDefaultPreference::OEM_VALIDATED,
									CandidateDefaultPreference::COMPONENT_REFERENCE)) ;
	DRIVERCRATE_EXPECT( context, candidateDefaultPreferencePrecedes(
									CandidateDefaultPreference::COMPONENT_REFERENCE,
									CandidateDefaultPreference::MANAGED_APPLICABLE)) ;
	DRIVERCRATE_EXPECT(
		context, candidateDefaultPreferencePrecedes( CandidateDefaultPreference::MANAGED_APPLICABLE,
													CandidateDefaultPreference::COMPONENT_GENERIC)) ;
	DRIVERCRATE_EXPECT(
		context, candidateDefaultPreferencePrecedes( CandidateDefaultPreference::COMPONENT_GENERIC,
													CandidateDefaultPreference::NONE)) ;
	DRIVERCRATE_EXPECT(
		context, !candidateDefaultPreferencePrecedes( CandidateDefaultPreference::OEM_VALIDATED,
													 CandidateDefaultPreference::OEM_VALIDATED)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一device一候補を検証根拠だけで初期選択することを検証する。
 *
 * OEMを優先し、同根拠では候補初出順を維持する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testDefaultSelection( TestContext &context)
{
	// Managed、component、OEMの候補根拠を検証できるProvider定義。
	const std::array providers{
		makeProvider( L"managed", ProviderSelectionTier::MANAGED_SERVICE),
		makeProvider( L"component", ProviderSelectionTier::COMPONENT_OFFICIAL),
		makeProvider( L"oem", ProviderSelectionTier::OEM_OFFICIAL)} ;
	// 同一deviceの異種根拠と、別deviceの同順位を含む候補群。
	const std::array candidates{makeCandidate( L"managed-a", L"device-a", L"managed",
											  CandidateDefaultPreference::MANAGED_APPLICABLE, true),
								makeCandidate( L"component-a", L"device-a", L"component",
											  CandidateDefaultPreference::COMPONENT_REFERENCE,
											  true),
								makeCandidate( L"oem-a", L"device-a", L"oem",
											  CandidateDefaultPreference::OEM_VALIDATED, true),
								makeCandidate( L"oem-b-first", L"device-b", L"oem",
											  CandidateDefaultPreference::OEM_VALIDATED, true),
								makeCandidate( L"oem-b-second", L"device-b", L"oem",
											  CandidateDefaultPreference::OEM_VALIDATED, true)} ;

	const auto		 selection =	// 一device一候補へ正規化した初期選択状態。
		buildDefaultCandidateSelection( candidates, providers) ;
	DRIVERCRATE_EXPECT( context, selection.has_value()) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( !selection.has_value()) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, selection->size() == candidates.size()) ;
	DRIVERCRATE_EXPECT( context, !selection->at( 0)) ;
	DRIVERCRATE_EXPECT( context, !selection->at( 1)) ;
	DRIVERCRATE_EXPECT( context, selection->at( 2)) ;
	DRIVERCRATE_EXPECT( context, selection->at( 3)) ;
	DRIVERCRATE_EXPECT( context, !selection->at( 4)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Generic候補と通常更新以外を初期選択しないことを検証する。
 *
 * OEM未検証、旧版、および表示専用候補を明示選択だけにする。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testSelectionExclusions( TestContext &context)
{
	// Generic componentとlocal表示候補を検証するProvider定義。
	const std::array providers{
		makeProvider( L"component", ProviderSelectionTier::COMPONENT_OFFICIAL),
		makeProvider( L"local", ProviderSelectionTier::LOCAL_INVENTORY)} ;
	std::array candidates{
		// Generic、downgrade、現在版の除外対象候補群。
		makeCandidate( L"generic", L"device-a", L"component",
					  CandidateDefaultPreference::COMPONENT_GENERIC, false),
		makeCandidate( L"downgrade", L"device-b", L"local", CandidateDefaultPreference::NONE, false),
		makeCandidate( L"current", L"device-c", L"local", CandidateDefaultPreference::NONE, true)} ;
	candidates[1].action	  = DriverAction::DOWNGRADE ;
	candidates[2].action	  = DriverAction::NONE ;
	candidates[2].current	  = true ;
	candidates[2].installable = false ;

	const auto selection =	// 除外候補だけから作る初期選択状態。
		buildDefaultCandidateSelection( candidates, providers) ;
	DRIVERCRATE_EXPECT( context, selection.has_value()) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( selection.has_value()) {
		DRIVERCRATE_EXPECT( context, selection->size() == candidates.size()) ;
		DRIVERCRATE_EXPECT( context, !selection->at( 0)) ;
		DRIVERCRATE_EXPECT( context, !selection->at( 1)) ;
		DRIVERCRATE_EXPECT( context, !selection->at( 2)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 探索経路区分と初期選択境界を検証する。
 *
 * 区分B／Cを明示選択専用とし、Providerとの不一致を拒否する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testDiscoveryBasisBoundaries( TestContext &context)
{
	ProviderDescriptor pageProvider =	// 公式Web pageを探索する架空OEM Provider。
		makeProvider( L"official-page", ProviderSelectionTier::OEM_OFFICIAL) ;
	pageProvider.discoveryBasis	  = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
	UpdateCandidate pageCandidate =	// 自動選択根拠を持たない区分B候補。
		makeCandidate( L"page", L"device-page", L"official-page", CandidateDefaultPreference::NONE,
					  false) ;
	pageCandidate.discoveryBasis = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
	DRIVERCRATE_EXPECT( context, isCandidateDiscoveryBasisValid( pageCandidate, pageProvider)) ;
	DRIVERCRATE_EXPECT( context, isCandidateDefaultPreferenceValid( pageCandidate, pageProvider)) ;

	const std::array pageProviders{pageProvider} ;		// 初期選択試験用Provider集合。
	const std::array pageCandidates{pageCandidate} ;	// 初期選択試験用候補集合。
	const auto		 pageSelection =					// 区分Bを含む一device分の初期選択結果。
		buildDefaultCandidateSelection( pageCandidates, pageProviders) ;
	DRIVERCRATE_EXPECT( context, pageSelection.has_value()) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( pageSelection.has_value()) {
		DRIVERCRATE_EXPECT( context, !pageSelection->at( 0)) ;
	}

	UpdateCandidate recommendedPage	  = pageCandidate ;	// 誤って自動選択を要求する区分B候補。
	recommendedPage.defaultPreference = CandidateDefaultPreference::OEM_VALIDATED ;
	recommendedPage.recommended		  = true ;
	DRIVERCRATE_EXPECT( context, !isCandidateDefaultPreferenceValid( recommendedPage, pageProvider)) ;

	UpdateCandidate mismatchedPage = pageCandidate ;	// Registryより探索経路を昇格した候補。
	mismatchedPage.discoveryBasis  = CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG ;
	DRIVERCRATE_EXPECT( context, !isCandidateDiscoveryBasisValid( mismatchedPage, pageProvider)) ;

	ProviderDescriptor importedProvider =	// 利用者指定fileだけを扱う架空Provider。
		makeProvider( L"imported", ProviderSelectionTier::COMPONENT_OFFICIAL) ;
	importedProvider.capabilities =
		static_cast<ProviderCapabilityMask>( ProviderCapability::SCAN) |
		static_cast<ProviderCapabilityMask>( ProviderCapability::INSTALL) |
		static_cast<ProviderCapabilityMask>( ProviderCapability::USER_SELECTED_FILE) ;
	importedProvider.discoveryBasis	  = CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE ;
	UpdateCandidate importedCandidate =	// 自動選択根拠を持たない区分C候補。
		makeCandidate( L"imported", L"device-imported", L"imported",
					  CandidateDefaultPreference::NONE, false) ;
	importedCandidate.discoveryBasis = CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE ;
	DRIVERCRATE_EXPECT( context,
					   isCandidateDiscoveryBasisValid( importedCandidate, importedProvider)) ;
	DRIVERCRATE_EXPECT( context,
					   isCandidateDefaultPreferenceValid( importedCandidate, importedProvider)) ;

	ProviderDescriptor unverifiedProvider =	// 取得元を証明しない汎用file Provider。
		makeProvider( L"user-provided", ProviderSelectionTier::USER_PROVIDED) ;
	UpdateCandidate unverifiedCandidate =	// 初期選択しない取得元未証明候補。
		makeCandidate( L"user-provided", L"device-user-provided", L"user-provided",
					  CandidateDefaultPreference::NONE, false) ;
	unverifiedCandidate.discoveryBasis = CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE ;
	DRIVERCRATE_EXPECT( context,
					   isCandidateDiscoveryBasisValid( unverifiedCandidate, unverifiedProvider)) ;
	DRIVERCRATE_EXPECT( context,
					   isCandidateDefaultPreferenceValid( unverifiedCandidate, unverifiedProvider)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 矛盾した候補根拠とidentityをfail-closedで拒否する。
 *
 * 未知Provider、重複ID、根拠欠損、境界不一致を拒否する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testInvalidSelectionInput( TestContext &context)
{
	// ManagedとOEMの信頼境界を持つ正常なProvider定義。
	const std::array providers{makeProvider( L"managed", ProviderSelectionTier::MANAGED_SERVICE),
							   makeProvider( L"oem", ProviderSelectionTier::OEM_OFFICIAL)} ;
	// 各不正条件の基点とする一件の正常候補。
	const std::array validCandidate{makeCandidate(
		L"valid", L"device-a", L"managed", CandidateDefaultPreference::MANAGED_APPLICABLE, true)} ;

	std::array		 unknownProvider = validCandidate ;	// 未知Provider IDへ変更する候補群。
	unknownProvider[0].providerId	 = L"unknown" ;
	DRIVERCRATE_EXPECT( context,
					   !buildDefaultCandidateSelection( unknownProvider, providers).has_value()) ;

	std::array missingPreference		   = validCandidate ;	// 推奨更新の根拠を欠損させる候補群。
	missingPreference[0].defaultPreference = CandidateDefaultPreference::NONE ;
	DRIVERCRATE_EXPECT( context,
					   !buildDefaultCandidateSelection( missingPreference, providers).has_value()) ;

	std::array mismatchedPreference = validCandidate ;	// Provider境界と根拠を矛盾させる候補群。
	mismatchedPreference[0].defaultPreference = CandidateDefaultPreference::OEM_VALIDATED ;
	DRIVERCRATE_EXPECT(
		context, !buildDefaultCandidateSelection( mismatchedPreference, providers).has_value()) ;

	const std::array duplicateCandidates{validCandidate[0],
										 validCandidate[0]} ;	// Identity重複候補群。
	DRIVERCRATE_EXPECT( context,
					   !buildDefaultCandidateSelection( duplicateCandidates, providers).has_value()) ;

	const std::array duplicateProviders{
		// Stable IDが重複するProvider定義群。
		makeProvider( L"managed", ProviderSelectionTier::MANAGED_SERVICE),
		makeProvider( L"managed", ProviderSelectionTier::MANAGED_SERVICE)} ;
	DRIVERCRATE_EXPECT(
		context, !buildDefaultCandidateSelection( validCandidate, duplicateProviders).has_value()) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/candidate_selection_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runCandidateSelectionTests( TestContext &context)
{
	testPreferenceOrder( context) ;
	testDefaultSelection( context) ;
	testSelectionExclusions( context) ;
	testDiscoveryBasisBoundaries( context) ;
	testInvalidSelectionInput( context) ;
}

} // namespace drivercrate::test
