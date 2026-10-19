//------------------------------------------------------------------------------
/**
 * @file candidate_audit_tests.cpp
 * @brief Driver候補監査状態単体試験実装。
 * @version 01.02.00
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  表示専用公式探索状態追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  拒否状態の順序矛盾試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Candidate操作矛盾試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式全監査合格状態試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Release観測差分拒否試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  詳細assessmentと観測結合のfixtureを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  公式installer実行範囲未確認の保留試験を追加。
 * </pre>
 *
 * @note 取得経路別の監査状態とinstall準備状態の矛盾を決定的に検証します。
 */
//------------------------------------------------------------------------------

#include "candidate_audit_tests.h"

#include "core/candidate_audit.h"
#include "core/candidate_assessment.h"
#include "core/candidate_selection.h"

#include <array>
#include <utility>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
/**
 * @brief 表示名やURLを使わず、registryが提供する値に相当する定義を組み立てる。
 *
 * @param[in] basis Candidateの探索経路。
 * @param[in] capability 経路に必要な単一capability。
 * @param[in] official 公式origin policyを持たせる場合は`true`。
 * @return 監査整合性試験用の最小Provider定義。
 */
//------------------------------------------------------------------------------
ProviderDescriptor makeDescriptor( const CandidateDiscoveryBasis basis,
								  const ProviderCapability capability, const bool official)
{
	ProviderDescriptor descriptor ;	// 監査整合性試験へ渡すProvider定義。
	descriptor.id					  = L"test-provider" ;
	descriptor.capabilities			  = static_cast<ProviderCapabilityMask>( capability) ;
	descriptor.discoveryBasis		  = basis ;
	descriptor.officialSourcePolicyId = official ? L"test-policy" : L"" ;
	return descriptor ;
}

//------------------------------------------------------------------------------
/**
 * @brief Identity等の別契約を試験対象にせず、監査状態に必要なfieldだけを設定する。
 *
 * @param[in] basis Candidateの探索経路。
 * @param[in] audit 検証対象の監査状態。
 * @param[in] installable Install workflowを許可する場合は`true`。
 * @return 通常更新を表す最小候補。
 */
//------------------------------------------------------------------------------
UpdateCandidate makeCandidate( const CandidateDiscoveryBasis basis,
							  const CandidateAuditStatus &audit, const bool installable)
{
	UpdateCandidate candidate ;	// 監査整合性判定へ渡す候補。
	candidate.discoveryBasis = basis ;
	candidate.audit			 = audit ;
	candidate.action		 = DriverAction::UPDATE ;
	candidate.installable	 = installable ;
	return candidate ;
}

//------------------------------------------------------------------------------
/**
 * @brief WUA候補とDriver Store現在版／別版の委譲状態を検証する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testWindowsManagedStates( TestContext &context)
{
	const ProviderDescriptor   managed = makeDescriptor( CandidateDiscoveryBasis::MANAGED_SERVICE,
														ProviderCapability::MANAGED_SERVICE,
														false) ;	// WUA定義。
	const CandidateAuditStatus managedAudit =
		// Install可能なWindows管理状態。
		makeWindowsManagedCandidateAudit( false) ;
	// Windows管理経路へ監査を委譲する正常候補fixture。
	const UpdateCandidate managedCandidate =
		makeCandidate( CandidateDiscoveryBasis::MANAGED_SERVICE, managedAudit, true) ;
	DRIVERCRATE_EXPECT( context, isCandidateAuditValid( managedCandidate, managed)) ;

	UpdateCandidate missingAction = managedCandidate ;	// Install可能だが操作なしの候補。
	missingAction.action		  = DriverAction::NONE ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( missingAction, managed)) ;

	UpdateCandidate unknownAction = managedCandidate ;	// 定義外操作を持つ候補。
	unknownAction.action		  = static_cast<DriverAction>( 999) ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( unknownAction, managed)) ;

	const ProviderDescriptor local	= makeDescriptor( CandidateDiscoveryBasis::LOCAL_INVENTORY,
													 ProviderCapability::LOCAL_INVENTORY,
													 false) ;	// Driver Store定義。
	const UpdateCandidate	 stored = makeCandidate( CandidateDiscoveryBasis::LOCAL_INVENTORY,
													// 別版Driver Store候補。
													makeWindowsManagedCandidateAudit( false), true) ;
	DRIVERCRATE_EXPECT( context, isCandidateAuditValid( stored, local)) ;

	UpdateCandidate current = makeCandidate( CandidateDiscoveryBasis::LOCAL_INVENTORY,
											// 現在版表示候補。
											makeWindowsManagedCandidateAudit( true), false) ;
	current.current			= true ;
	current.action			= DriverAction::NONE ;
	DRIVERCRATE_EXPECT( context, isCandidateAuditValid( current, local)) ;

	current.recommended = true ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( current, local)) ;
	current.recommended = false ;

	UpdateCandidate currentFromWua = current ;	// 不正なWUA現在版表示候補。
	currentFromWua.discoveryBasis  = CandidateDiscoveryBasis::MANAGED_SERVICE ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( currentFromWua, managed)) ;

	current.audit.contentIntegrity = CandidateAuditGateState::REJECTED ;
	current.audit.installReadiness = CandidateInstallReadiness::BLOCKED ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( current, local)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式metadata確認と全監査完了を区別し、過大なReadyを拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testOfficialStateTransitions( TestContext &context)
{
	const ProviderDescriptor official =
		makeDescriptor( CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG,
					   ProviderCapability::OFFICIAL_NETWORK, true) ;	// 公式Provider定義。
	CandidateAuditStatus audit =
		// Payload監査前の公式候補状態。
		makeOfficialMetadataCandidateAudit() ;
	// 公式構造化catalog由来の表示専用候補。監査状態を段階ごとに差し替える。
	UpdateCandidate candidate =
		makeCandidate( CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG, audit, false) ;
	DRIVERCRATE_EXPECT( context, isCandidateAuditValid( candidate, official)) ;

	candidate.recommended = true ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( candidate, official)) ;
	candidate.recommended = false ;

	candidate.installable				= true ;
	candidate.audit.installReadiness	= CandidateInstallReadiness::READY ;
	candidate.audit.inspectionDownload	= CandidateAuditGateState::PASSED ;
	candidate.audit.contentIntegrity	= CandidateAuditGateState::PASSED ;
	candidate.audit.systemApplicability = CandidateAuditGateState::PASSED ;
	candidate.recommended				= true ;
	candidate.action					= DriverAction::REINSTALL ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( candidate, official)) ;
	candidate.action = DriverAction::UPDATE ;
	DRIVERCRATE_EXPECT( context, isCandidateAuditValid( candidate, official)) ;
	candidate.recommended = false ;

	const CandidateAuditStatus ready =
		// G11-B～Dを全て通過した公式候補状態。
		makeOfficialReadyCandidateAudit() ;
	DRIVERCRATE_EXPECT( context, ready.sourceOrigin == CandidateAuditGateState::PASSED) ;
	DRIVERCRATE_EXPECT( context, ready.inspectionDownload == CandidateAuditGateState::PASSED) ;
	DRIVERCRATE_EXPECT( context, ready.contentIntegrity == CandidateAuditGateState::PASSED) ;
	DRIVERCRATE_EXPECT( context, ready.systemApplicability == CandidateAuditGateState::PASSED) ;
	DRIVERCRATE_EXPECT( context, ready.installReadiness == CandidateInstallReadiness::READY) ;
	// 必要な監査を完了したinstall可能候補の正常fixture。
	const UpdateCandidate readyCandidate =
		makeCandidate( CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG, ready, true) ;
	DRIVERCRATE_EXPECT( context, isCandidateAuditValid( readyCandidate, official)) ;

	candidate.audit.inspectionDownload = CandidateAuditGateState::PENDING ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( candidate, official)) ;

	candidate.audit.sourceOrigin = CandidateAuditGateState::PENDING ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( candidate, official)) ;

	CandidateAuditStatus sourceRejected =
		// 公式起点を拒否した初段状態。
		makeOfficialDiscoveryCandidateAudit() ;
	sourceRejected.sourceOrigin		= CandidateAuditGateState::REJECTED ;
	sourceRejected.installReadiness = CandidateInstallReadiness::BLOCKED ;
	// 取得元で拒否された候補を成功へ昇格させないためのfixture。
	UpdateCandidate rejectedCandidate =
		makeCandidate( CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG, sourceRejected, false) ;
	DRIVERCRATE_EXPECT( context, isCandidateAuditValid( rejectedCandidate, official)) ;

	rejectedCandidate.audit.inspectionDownload = CandidateAuditGateState::MANAGED_BY_WINDOWS ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( rejectedCandidate, official)) ;

	CandidateAuditStatus contentRejected =
		// Download後に内容を拒否した状態。
		makeOfficialMetadataCandidateAudit() ;
	contentRejected.inspectionDownload = CandidateAuditGateState::PASSED ;
	contentRejected.contentIntegrity   = CandidateAuditGateState::REJECTED ;
	rejectedCandidate.audit			   = contentRejected ;
	DRIVERCRATE_EXPECT( context, isCandidateAuditValid( rejectedCandidate, official)) ;

	rejectedCandidate.audit.systemApplicability = CandidateAuditGateState::PASSED ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( rejectedCandidate, official)) ;

	const ProviderDescriptor webPage =
		makeDescriptor( CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
					   ProviderCapability::OFFICIAL_NETWORK, true) ;	// 区分B Provider定義。
	UpdateCandidate displayCandidate = makeCandidate( CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
													 makeOfficialDiscoveryCandidateAudit(),
													 false) ;	// System監査前の表示候補。
	displayCandidate.action			 = DriverAction::NONE ;
	DRIVERCRATE_EXPECT( context, displayCandidate.audit.systemApplicability ==
									CandidateAuditGateState::PENDING) ;
	DRIVERCRATE_EXPECT( context, isCandidateAuditValid( displayCandidate, webPage)) ;

	const UpdateCandidate readyPageCandidate =
		makeCandidate( CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE, makeOfficialReadyCandidateAudit(),
					  true) ;	// 全監査合格の区分B候補。
	DRIVERCRATE_EXPECT( context, isCandidateAuditValid( readyPageCandidate, webPage)) ;

	displayCandidate.audit.installReadiness = CandidateInstallReadiness::READY ;
	displayCandidate.installable			= true ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( displayCandidate, webPage)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 利用者指定fileを公式由来へ昇格せず、拒否候補のinstallをfail-closedで禁止する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testUserSelectedAndRejectedStates( TestContext &context)
{
	const ProviderDescriptor selected =
		makeDescriptor( CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE,
					   ProviderCapability::USER_SELECTED_FILE, false) ;	// 区分C Provider定義。
	UpdateCandidate candidate = makeCandidate( CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE,
											  makeUserSelectedCandidateAudit(),
											  true) ;	// 取得元未証明の検証済みpackage。
	DRIVERCRATE_EXPECT( context, isCandidateAuditValid( candidate, selected)) ;

	candidate.audit.sourceOrigin = CandidateAuditGateState::PASSED ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( candidate, selected)) ;

	candidate.audit					 = makeUserSelectedCandidateAudit() ;
	candidate.audit.contentIntegrity = CandidateAuditGateState::REJECTED ;
	candidate.audit.installReadiness = CandidateInstallReadiness::BLOCKED ;
	candidate.installable			 = false ;
	DRIVERCRATE_EXPECT( context, isCandidateAuditValid( candidate, selected)) ;

	candidate.audit.inspectionDownload = CandidateAuditGateState::MANAGED_BY_WINDOWS ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( candidate, selected)) ;
	candidate.audit.inspectionDownload = CandidateAuditGateState::NOT_APPLICABLE ;

	candidate.audit.systemApplicability = CandidateAuditGateState::PASSED ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( candidate, selected)) ;
	candidate.audit.systemApplicability = CandidateAuditGateState::PROVIDER_VALIDATED ;

	candidate.installable = true ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( candidate, selected)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Castで混入した定義外enumをfail-closedで拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testUnknownStates( TestContext &context)
{
	const ProviderDescriptor managed   = makeDescriptor( CandidateDiscoveryBasis::MANAGED_SERVICE,
														ProviderCapability::MANAGED_SERVICE,
														false) ;	// WUA定義。
	UpdateCandidate			 candidate = makeCandidate( CandidateDiscoveryBasis::MANAGED_SERVICE,
													   // 基本候補。
													   makeWindowsManagedCandidateAudit( false), true) ;
	candidate.audit.sourceOrigin	   = static_cast<CandidateAuditGateState>( 999) ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( candidate, managed)) ;

	candidate.audit					 = makeWindowsManagedCandidateAudit( false) ;
	candidate.audit.installReadiness = static_cast<CandidateInstallReadiness>( 999) ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( candidate, managed)) ;

	candidate.audit						   = makeWindowsManagedCandidateAudit( false) ;
	candidate.releaseObservationDifference = ReleaseObservationDifference::FIRST_OBSERVATION ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( candidate, managed)) ;

	const ProviderDescriptor official =
		makeDescriptor( CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
					   ProviderCapability::OFFICIAL_NETWORK, true) ;	// 公式Web Provider定義。
	candidate		 = makeCandidate( CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE,
									 makeOfficialDiscoveryCandidateAudit(), false) ;
	candidate.action = DriverAction::NONE ;
	candidate.releaseObservationDifference = ReleaseObservationDifference::FIRST_OBSERVATION ;
	DRIVERCRATE_EXPECT( context, isCandidateAuditValid( candidate, official)) ;

	candidate.releaseObservationDifference = ReleaseObservationDifference::INVALID ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( candidate, official)) ;

	candidate.releaseObservationDifference =
		// 定義外の観測差分。
		static_cast<ReleaseObservationDifference>( 999) ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( candidate, official)) ;
}

/**
 * @brief 実packageの合格ではない詳細契約用の架空snapshotを作る。
 * @return 全八軸の意味整合性だけを満たすfixture。
 */
CandidateAssessment makeDetailedAssessment()
{
	CandidateAssessment result ;	// 実APIや署名証拠を持たない固定値。
	result.scanSessionId	 = 83U ;
	result.candidateIdentity = L"candidate:83:1" ;
	result.deviceIdentity	 = L"device:83:0" ;
	result.packageIdentity	 = L"package:83:1" ;
	result.origin			 = {CandidateAssessmentState::PASSED,
								CandidateAssessmentReason::VALIDATED,
								CandidateEvidenceKind::OFFICIAL_RECORD,
								1U,
								{}} ;
	result.acquisition		 = {CandidateAssessmentState::PASSED,
								CandidateAssessmentReason::VALIDATED,
								CandidateEvidenceKind::PACKAGE_INSPECTION,
								2U,
								{}} ;
	result.signature		 = {CandidateAssessmentState::PASSED,
								CandidateAssessmentReason::VALIDATED,
								CandidateEvidenceKind::WINDOWS_API,
								3U,
								{}} ;
	result.applicability	 = result.signature ;
	result.windowsSelection	 = result.signature ;
	result.driverOnly		 = result.acquisition ;
	result.requirements		 = {CandidateAssessmentState::NOT_APPLICABLE,
								CandidateAssessmentReason::NO_EXPLICIT_REQUIREMENT,
								CandidateEvidenceKind::OFFICIAL_RECORD,
								4U,
								{}} ;
	result.method			 = {CandidateAssessmentState::PASSED,
								CandidateAssessmentReason::VALIDATED,
								CandidateEvidenceKind::IMPLEMENTATION_POLICY,
								5U,
								{}} ;
	result.installMethod	 = CandidateInstallMethod::STANDARD_INF ;
	result.executorAvailable = true ;
	return result ;
}

/**
 * @brief 詳細の未知値・結合・明示条件と未実装方式の拒否を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testDetailedAssessments( TestContext &context)
{
	auto value = makeDetailedAssessment() ;	// 通信しない全軸fixture。
	DRIVERCRATE_EXPECT( context, isCandidateAssessmentReady( value)) ;
	DRIVERCRATE_EXPECT( context,
					   isCandidateAssessmentBound( value, 83U, value.candidateIdentity,
												  value.deviceIdentity, value.packageIdentity)) ;
	DRIVERCRATE_EXPECT( context,
					   !isCandidateAssessmentBound( value, 84U, value.candidateIdentity,
												   value.deviceIdentity, value.packageIdentity)) ;
	DRIVERCRATE_EXPECT( context,
					   !isCandidateAssessmentBound( value, 83U, L"different", value.deviceIdentity,
												   value.packageIdentity)) ;
	DRIVERCRATE_EXPECT( context, !isCandidateAssessmentBound( value, 83U, value.candidateIdentity,
															L"different", value.packageIdentity)) ;
	DRIVERCRATE_EXPECT( context, !isCandidateAssessmentBound( value, 83U, value.candidateIdentity,
															value.deviceIdentity, L"different")) ;
	value.signature.evidenceKind = CandidateEvidenceKind::USER_INPUT ;
	DRIVERCRATE_EXPECT( context, !isCandidateAssessmentValid( value)) ;
	value			= makeDetailedAssessment() ;
	value.signature = {CandidateAssessmentState::REJECTED,
					   CandidateAssessmentReason::SIGNATURE_INVALID,
					   CandidateEvidenceKind::WINDOWS_API,
					   3U,
					   {}} ;
	DRIVERCRATE_EXPECT( context,
					   isCandidateAssessmentValid( value) && !isCandidateAssessmentReady( value)) ;
	value.signature.reason = CandidateAssessmentReason::API_FAILURE ;
	DRIVERCRATE_EXPECT( context, !isCandidateAssessmentValid( value)) ;
	value.signature.state = CandidateAssessmentState::FAILED ;
	value.signature.diagnostic =
		DeviceDiagnostic{DeviceDiagnosticDomain::HRESULT_VALUE, 0x80004005U} ;
	DRIVERCRATE_EXPECT( context,
					   isCandidateAssessmentValid( value) && !isCandidateAssessmentReady( value)) ;
	value.signature.diagnostic->code = 0U ;
	DRIVERCRATE_EXPECT( context, !isCandidateAssessmentValid( value)) ;
	value				   = makeDetailedAssessment() ;
	value.windowsSelection = {CandidateAssessmentState::NOT_CHECKED,
							  CandidateAssessmentReason::LEGACY_POLICY_HOLD,
							  CandidateEvidenceKind::IMPLEMENTATION_POLICY,
							  8U,
							  {}} ;
	DRIVERCRATE_EXPECT( context,
					   isCandidateAssessmentValid( value) && !isCandidateAssessmentReady( value)) ;
	DRIVERCRATE_EXPECT( context, value.applicability.state == CandidateAssessmentState::PASSED) ;
	value = makeDetailedAssessment() ;
	value.explicitRequirements.push_back( {1U, CandidateComponentRole::FIRMWARE_STATE, false,
										  CandidateRequirementState::UNVERIFIED,
										  CandidateEvidenceKind::OFFICIAL_RECORD, 4U}) ;
	DRIVERCRATE_EXPECT( context, isCandidateAssessmentReady( value)) ;
	value.explicitRequirements.front().required = true ;
	DRIVERCRATE_EXPECT( context, !isCandidateAssessmentValid( value)) ;
	value.requirements = {CandidateAssessmentState::NOT_CHECKED,
						  CandidateAssessmentReason::REQUIREMENT_UNVERIFIED,
						  CandidateEvidenceKind::OFFICIAL_RECORD,
						  4U,
						  {}} ;
	DRIVERCRATE_EXPECT( context,
					   isCandidateAssessmentValid( value) && !isCandidateAssessmentReady( value)) ;
	value.explicitRequirements.front().state = CandidateRequirementState::UNSATISFIED ;
	value.requirements.state				 = CandidateAssessmentState::REJECTED ;
	value.requirements.reason				 = CandidateAssessmentReason::REQUIREMENT_UNSATISFIED ;
	DRIVERCRATE_EXPECT( context,
					   isCandidateAssessmentValid( value) && !isCandidateAssessmentReady( value)) ;
	value.explicitRequirements.front().state = CandidateRequirementState::SATISFIED ;
	value.requirements.state				 = CandidateAssessmentState::PASSED ;
	value.requirements.reason				 = CandidateAssessmentReason::VALIDATED ;
	DRIVERCRATE_EXPECT( context, isCandidateAssessmentReady( value)) ;
	value.explicitRequirements.push_back( value.explicitRequirements.front()) ;
	DRIVERCRATE_EXPECT( context, !isCandidateAssessmentValid( value)) ;
	value.explicitRequirements.pop_back() ;
	// 明示条件の有限上限ちょうどまでは異なる条件を保持する。
	for( std::uint64_t index = 2U; index <= 16U; ++index) {
		auto requirement		  = value.explicitRequirements.front() ;	// 同じ検査範囲の架空条件。
		requirement.requirementId = index ;
		value.explicitRequirements.push_back( requirement) ;
	}

	DRIVERCRATE_EXPECT( context, isCandidateAssessmentReady( value)) ;
	value.explicitRequirements.push_back( {17U, CandidateComponentRole::COMPONENT, true,
										  CandidateRequirementState::SATISFIED,
										  CandidateEvidenceKind::OFFICIAL_RECORD, 4U}) ;
	DRIVERCRATE_EXPECT( context, !isCandidateAssessmentValid( value)) ;
	value				= makeDetailedAssessment() ;
	value.installMethod = CandidateInstallMethod::OFFICIAL_INSTALLER ;
	DRIVERCRATE_EXPECT( context, !isCandidateAssessmentValid( value)) ;
	value.executorAvailable = false ;
	value.method			= {CandidateAssessmentState::UNSUPPORTED,
							   CandidateAssessmentReason::EXECUTOR_UNAVAILABLE,
							   CandidateEvidenceKind::IMPLEMENTATION_POLICY,
							   5U,
							   {}} ;
	DRIVERCRATE_EXPECT( context,
					   isCandidateAssessmentValid( value) && !isCandidateAssessmentReady( value)) ;
	value					= makeDetailedAssessment() ;
	value.installMethod		= CandidateInstallMethod::OFFICIAL_INSTALLER ;
	value.executorAvailable = false ;
	value.method			= {CandidateAssessmentState::NOT_CHECKED,
							   CandidateAssessmentReason::EXECUTION_SCOPE_UNVERIFIED,
							   CandidateEvidenceKind::IMPLEMENTATION_POLICY,
							   5U,
							   {}} ;
	DRIVERCRATE_EXPECT( context,
					   isCandidateAssessmentValid( value) && !isCandidateAssessmentReady( value)) ;
	value.installMethod = static_cast<CandidateInstallMethod>( 999U) ;
	DRIVERCRATE_EXPECT( context, !isCandidateAssessmentValid( value)) ;
	value				= makeDetailedAssessment() ;
	value.origin.reason = static_cast<CandidateAssessmentReason>( 999U) ;
	DRIVERCRATE_EXPECT( context, !isCandidateAssessmentValid( value)) ;
	value			   = makeDetailedAssessment() ;
	value.origin.state = static_cast<CandidateAssessmentState>( 999U) ;
	DRIVERCRATE_EXPECT( context, !isCandidateAssessmentValid( value)) ;
	value					  = makeDetailedAssessment() ;
	value.origin.evidenceKind = static_cast<CandidateEvidenceKind>( 999U) ;
	DRIVERCRATE_EXPECT( context, !isCandidateAssessmentValid( value)) ;
	value					= makeDetailedAssessment() ;
	value.origin.evidenceId = 0U ;
	DRIVERCRATE_EXPECT( context, !isCandidateAssessmentValid( value)) ;
	value = makeDetailedAssessment() ;
	value.candidateIdentity.assign( 257U, L'x') ;
	DRIVERCRATE_EXPECT( context, !isCandidateAssessmentValid( value)) ;
	value		 = makeDetailedAssessment() ;
	value.origin = {} ;
	DRIVERCRATE_EXPECT( context,
					   isCandidateAssessmentValid( value) && !isCandidateAssessmentReady( value)) ;
}

/**
 * @brief 詳細付き初回候補と観測の結合拒否を、旧候補の互換性と分離して検証する。
 * @param[in,out] context Assertion集計先。
 */
void testDetailsPublication( TestContext &context)
{
	UpdateCandidate candidate ;	// 未実装executorを持つ架空公式初回候補。
	candidate.assessment					= makeDetailedAssessment() ;
	candidate.identity						= candidate.assessment->candidateIdentity ;
	candidate.deviceIdentity				= candidate.assessment->deviceIdentity ;
	candidate.packageIdentity				= candidate.assessment->packageIdentity ;
	candidate.discoveryBasis				= CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
	candidate.audit							= makeOfficialDiscoveryCandidateAudit() ;
	candidate.audit.installReadiness		= CandidateInstallReadiness::BLOCKED ;
	candidate.action						= DriverAction::INITIAL_INSTALL ;
	candidate.assessment->executorAvailable = false ;
	candidate.assessment->method			= {CandidateAssessmentState::UNSUPPORTED,
											   CandidateAssessmentReason::EXECUTOR_UNAVAILABLE,
											   CandidateEvidenceKind::IMPLEMENTATION_POLICY,
											   5U,
											   {}} ;
	auto descriptor = makeDescriptor( candidate.discoveryBasis, ProviderCapability::OFFICIAL_NETWORK,
									 true) ;	// 旧監査との整合対象。
	descriptor.selectionTier = ProviderSelectionTier::COMPONENT_OFFICIAL ;
	candidate.providerId	 = descriptor.id ;
	DRIVERCRATE_EXPECT( context, isCandidateAuditValid( candidate, descriptor)) ;
	DRIVERCRATE_EXPECT( context, isCandidateDetailsValid( candidate, 83U)) ;
	DRIVERCRATE_EXPECT( context, isCandidateDefaultPreferenceValid( candidate, descriptor)) ;
	const auto initial	  = candidate ;	// 各拒否条件の起点。
	candidate.installable = true ;
	DRIVERCRATE_EXPECT( context, !isCandidateDetailsValid( candidate)) ;
	candidate			  = initial ;
	candidate.recommended = true ;
	DRIVERCRATE_EXPECT( context, !isCandidateDetailsValid( candidate)) ;
	candidate = initial ;
	candidate.assessment.reset() ;
	DRIVERCRATE_EXPECT( context, !isCandidateDetailsValid( candidate)) ;
	candidate								= initial ;
	candidate.assessment->executorAvailable = true ;
	DRIVERCRATE_EXPECT( context, !isCandidateDetailsValid( candidate)) ;
	candidate						 = initial ;
	candidate.audit.installReadiness = CandidateInstallReadiness::READY ;
	DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( candidate, descriptor)) ;
	candidate							= initial ;
	candidate.assessment->scanSessionId = 84U ;
	DRIVERCRATE_EXPECT( context, !isCandidateDetailsValid( candidate, 83U)) ;
	candidate							 = initial ;
	candidate.assessment->deviceIdentity = L"other-device" ;
	DRIVERCRATE_EXPECT( context, !isCandidateDetailsValid( candidate)) ;
	candidate								= initial ;
	candidate.assessment->candidateIdentity = L"other-candidate" ;
	DRIVERCRATE_EXPECT( context, !isCandidateDetailsValid( candidate)) ;
	candidate							  = initial ;
	candidate.assessment->packageIdentity = L"other-package" ;
	DRIVERCRATE_EXPECT( context, !isCandidateDetailsValid( candidate)) ;
	candidate							= initial ;
	candidate.assessment->origin.reason = CandidateAssessmentReason::ORIGIN_REJECTED ;
	candidate.assessment->origin.state	= CandidateAssessmentState::REJECTED ;
	DRIVERCRATE_EXPECT( context, !isCandidateDetailsValid( candidate)) ;
	candidate						 = initial ;
	candidate.assessment->signature	 = {CandidateAssessmentState::REJECTED,
										CandidateAssessmentReason::SIGNATURE_INVALID,
										CandidateEvidenceKind::WINDOWS_API,
										3U,
										{}} ;
	candidate.audit.contentIntegrity = CandidateAuditGateState::PASSED ;
	DRIVERCRATE_EXPECT( context, !isCandidateDetailsValid( candidate)) ;
	UpdateCandidate current ;	// 表示名・現在版がなくても残すlocal代表。
	current.identity							= L"current:83:0" ;
	current.deviceIdentity						= initial.deviceIdentity ;
	current.current								= true ;
	current.discoveryBasis						= CandidateDiscoveryBasis::LOCAL_INVENTORY ;
	current.deviceObservation					= DeviceObservation{} ;
	current.deviceObservation->scanSessionId	= 83U ;
	current.deviceObservation->deviceIdentity	= current.deviceIdentity ;
	current.deviceObservation->node.read.state	= DevicePropertyReadState::VALUE ;
	current.deviceObservation->node.statusFlags = 0x400U ;
	current.deviceObservation->node.problemCode = 28U ;
	current.deviceObservation->driverPresence	= DeviceDriverPresence::NOT_INSTALLED ;
	DRIVERCRATE_EXPECT( context, isCandidateDetailsValid( current, 83U)) ;
	DRIVERCRATE_EXPECT( context, !isCandidateDetailsValid( current, 84U)) ;
	std::array<UpdateCandidate, 2> rows{current, initial} ;	// 同じdeviceの代表と初回候補。
	DRIVERCRATE_EXPECT( context, isCandidateDetailsSetValid( rows, 83U)) ;
	rows[1]			 = current ;
	rows[1].identity = L"duplicate-representative" ;
	DRIVERCRATE_EXPECT( context, !isCandidateDetailsSetValid( rows, 83U)) ;
	current.current = false ;
	DRIVERCRATE_EXPECT( context, !isCandidateDetailsValid( current)) ;
	current.current		   = true ;
	current.discoveryBasis = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
	DRIVERCRATE_EXPECT( context, !isCandidateDetailsValid( current)) ;
	current.discoveryBasis = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
	current.assessment	   = initial.assessment ;
	DRIVERCRATE_EXPECT( context, !isCandidateDetailsValid( current)) ;
	current.assessment.reset() ;
	current.deviceObservation.reset() ;
	DRIVERCRATE_EXPECT( context, isCandidateDetailsValid( current)) ;
	DRIVERCRATE_EXPECT( context, !isCandidateDetailsSetValid( {}, 0U)) ;
}

/**
 * @brief 全有限理由の正例と異なる成否への改変を決定的に照合する。
 * @param[in,out] context Assertion集計先。
 */
void testAllAssessmentReasons( TestContext &context)
{
	const std::array<std::pair<CandidateAssessmentAxis, CandidateAssessmentFinding>, 28> fixtures{
		{{CandidateAssessmentAxis::ORIGIN,
		  {CandidateAssessmentState::NOT_CHECKED,
		   CandidateAssessmentReason::NOT_EXAMINED,
		   CandidateEvidenceKind::NONE,
		   0U,
		   {}}},
		 {CandidateAssessmentAxis::ORIGIN,
		  {CandidateAssessmentState::PASSED,
		   CandidateAssessmentReason::VALIDATED,
		   CandidateEvidenceKind::OFFICIAL_RECORD,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::SIGNATURE,
		  {CandidateAssessmentState::MANAGED_BY_WINDOWS,
		   CandidateAssessmentReason::WINDOWS_MANAGED,
		   CandidateEvidenceKind::WINDOWS_API,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::SIGNATURE,
		  {CandidateAssessmentState::FAILED, CandidateAssessmentReason::API_FAILURE,
		   CandidateEvidenceKind::WINDOWS_API, 1U,
		   DeviceDiagnostic{DeviceDiagnosticDomain::HRESULT_VALUE, 0x80004005U}}},
		 {CandidateAssessmentAxis::ACQUISITION,
		  {CandidateAssessmentState::UNSUPPORTED,
		   CandidateAssessmentReason::FORMAT_UNSUPPORTED,
		   CandidateEvidenceKind::PACKAGE_INSPECTION,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::ORIGIN,
		  {CandidateAssessmentState::NOT_CHECKED,
		   CandidateAssessmentReason::ORIGIN_UNVERIFIED,
		   CandidateEvidenceKind::NONE,
		   0U,
		   {}}},
		 {CandidateAssessmentAxis::ORIGIN,
		  {CandidateAssessmentState::NOT_APPLICABLE,
		   CandidateAssessmentReason::USER_PROVIDED,
		   CandidateEvidenceKind::USER_INPUT,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::ORIGIN,
		  {CandidateAssessmentState::REJECTED,
		   CandidateAssessmentReason::ORIGIN_REJECTED,
		   CandidateEvidenceKind::OFFICIAL_RECORD,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::ORIGIN,
		  {CandidateAssessmentState::NOT_CHECKED,
		   CandidateAssessmentReason::DELEGATION_UNVERIFIED,
		   CandidateEvidenceKind::OFFICIAL_RECORD,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::ACQUISITION,
		  {CandidateAssessmentState::NOT_CHECKED,
		   CandidateAssessmentReason::NOT_ACQUIRED,
		   CandidateEvidenceKind::NONE,
		   0U,
		   {}}},
		 {CandidateAssessmentAxis::ACQUISITION,
		  {CandidateAssessmentState::REJECTED,
		   CandidateAssessmentReason::REFERENCED_FILE_MISSING,
		   CandidateEvidenceKind::PACKAGE_INSPECTION,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::ACQUISITION,
		  {CandidateAssessmentState::REJECTED,
		   CandidateAssessmentReason::HASH_MISMATCH,
		   CandidateEvidenceKind::PACKAGE_INSPECTION,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::SIGNATURE,
		  {CandidateAssessmentState::REJECTED,
		   CandidateAssessmentReason::SIGNATURE_INVALID,
		   CandidateEvidenceKind::WINDOWS_API,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::SIGNATURE,
		  {CandidateAssessmentState::NOT_CHECKED,
		   CandidateAssessmentReason::PUBLISHER_UNVERIFIED,
		   CandidateEvidenceKind::WINDOWS_API,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::APPLICABILITY,
		  {CandidateAssessmentState::REJECTED,
		   CandidateAssessmentReason::PNP_MISMATCH,
		   CandidateEvidenceKind::WINDOWS_API,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::APPLICABILITY,
		  {CandidateAssessmentState::REJECTED,
		   CandidateAssessmentReason::OS_MISMATCH,
		   CandidateEvidenceKind::WINDOWS_API,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::APPLICABILITY,
		  {CandidateAssessmentState::REJECTED,
		   CandidateAssessmentReason::ARCHITECTURE_MISMATCH,
		   CandidateEvidenceKind::WINDOWS_API,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::WINDOWS_SELECTION,
		  {CandidateAssessmentState::NOT_CHECKED,
		   CandidateAssessmentReason::RANK_UNVERIFIED,
		   CandidateEvidenceKind::NONE,
		   0U,
		   {}}},
		 {CandidateAssessmentAxis::WINDOWS_SELECTION,
		  {CandidateAssessmentState::NOT_CHECKED,
		   CandidateAssessmentReason::LEGACY_POLICY_HOLD,
		   CandidateEvidenceKind::IMPLEMENTATION_POLICY,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::WINDOWS_SELECTION,
		  {CandidateAssessmentState::PASSED,
		   CandidateAssessmentReason::NO_CHANGE,
		   CandidateEvidenceKind::WINDOWS_API,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::WINDOWS_SELECTION,
		  {CandidateAssessmentState::PASSED,
		   CandidateAssessmentReason::NOT_RECOMMENDED,
		   CandidateEvidenceKind::WINDOWS_API,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::DRIVER_ONLY,
		  {CandidateAssessmentState::REJECTED,
		   CandidateAssessmentReason::FIRMWARE_PAYLOAD,
		   CandidateEvidenceKind::PACKAGE_INSPECTION,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::DRIVER_ONLY,
		  {CandidateAssessmentState::REJECTED,
		   CandidateAssessmentReason::INSEPARABLE_FIRMWARE_UPDATE,
		   CandidateEvidenceKind::PACKAGE_INSPECTION,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::REQUIREMENTS,
		  {CandidateAssessmentState::NOT_APPLICABLE,
		   CandidateAssessmentReason::NO_EXPLICIT_REQUIREMENT,
		   CandidateEvidenceKind::OFFICIAL_RECORD,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::REQUIREMENTS,
		  {CandidateAssessmentState::REJECTED,
		   CandidateAssessmentReason::REQUIREMENT_UNSATISFIED,
		   CandidateEvidenceKind::OFFICIAL_RECORD,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::REQUIREMENTS,
		  {CandidateAssessmentState::NOT_CHECKED,
		   CandidateAssessmentReason::REQUIREMENT_UNVERIFIED,
		   CandidateEvidenceKind::OFFICIAL_RECORD,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::METHOD,
		  {CandidateAssessmentState::UNSUPPORTED,
		   CandidateAssessmentReason::EXECUTOR_UNAVAILABLE,
		   CandidateEvidenceKind::IMPLEMENTATION_POLICY,
		   1U,
		   {}}},
		 {CandidateAssessmentAxis::METHOD,
		  {CandidateAssessmentState::NOT_CHECKED,
		   CandidateAssessmentReason::EXECUTION_SCOPE_UNVERIFIED,
		   CandidateEvidenceKind::IMPLEMENTATION_POLICY,
		   1U,
		   {}}}}} ;	// 実内容の証明ではなく、理由と状態・証拠種類の契約集合。
	static_assert( fixtures.size() ==
				  static_cast<std::size_t>( CandidateAssessmentReason::EXECUTION_SCOPE_UNVERIFIED) +
					  1U) ;
	// 各理由の正常状態を確認し、定義した他の六状態では同じ理由を拒否する。
	for( const auto &[axis, finding] : fixtures) {
		DRIVERCRATE_EXPECT( context, isCandidateAssessmentFindingValid( axis, finding)) ;
		// 状態のすり替えを全有限値で確認し、理由だけを合格へ再利用しない。
		for( unsigned state = 0U; state < 7U; ++state) {
			auto mutated  = finding ;	// 一軸の状態だけを変更する。
			mutated.state = static_cast<CandidateAssessmentState>( state) ;
			DRIVERCRATE_EXPECT( context, isCandidateAssessmentFindingValid( axis, mutated) ==
											(mutated.state == finding.state)) ;
		}
	}

	// 任意のutility・extension・NVM条件の未充足だけでは通常driverを保留しない。
	for( const auto role :
		{CandidateComponentRole::EXTENSION_INF, CandidateComponentRole::COMPONENT,
		 CandidateComponentRole::UTILITY, CandidateComponentRole::FIRMWARE_STATE}) {
		auto detail = makeDetailedAssessment() ;	// 基本driverの全条件を満たす架空値。
		detail.explicitRequirements.push_back( {1U, role, false,
											   CandidateRequirementState::UNSATISFIED,
											   CandidateEvidenceKind::OFFICIAL_RECORD, 4U}) ;
		DRIVERCRATE_EXPECT( context, isCandidateAssessmentReady( detail)) ;
		detail.explicitRequirements.front().required = true ;
		detail.requirements.state					 = CandidateAssessmentState::REJECTED ;
		detail.requirements.reason = CandidateAssessmentReason::REQUIREMENT_UNSATISFIED ;
		DRIVERCRATE_EXPECT( context, isCandidateAssessmentValid( detail) &&
										!isCandidateAssessmentReady( detail)) ;
		detail.explicitRequirements.front().role = static_cast<CandidateComponentRole>( 99U) ;
		DRIVERCRATE_EXPECT( context, !isCandidateAssessmentValid( detail)) ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/candidate_audit_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runCandidateAuditTests( TestContext &context)
{
	testWindowsManagedStates( context) ;
	testOfficialStateTransitions( context) ;
	testUserSelectedAndRejectedStates( context) ;
	testUnknownStates( context) ;
	testDetailedAssessments( context) ;
	testDetailsPublication( context) ;
	testAllAssessmentReasons( context) ;
}

} // namespace drivercrate::test
