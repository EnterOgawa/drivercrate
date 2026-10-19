//------------------------------------------------------------------------------
/**
 * @file prepared_audit_display_tests.cpp
 * @brief 取得後監査表示と候補発行境界の内部試験。
 * @version 01.01.01
 * @date 2026/09/06
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  共通report契約へ監査profileとrankを整合。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Install確認契約を明示。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  候補発行状態と件数fixtureを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  監査合格候補の発行境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の表示境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  準備後の詳細sessionと初回導入拒否を検証。
 * Ver.01.01.01 Shunji Ogawa  2026/10/15  全体INF件数と有限pair境界の回帰を追加。
 * </pre>
 *
 * @note 非機密の監査表示と全監査合格候補の発行境界を合成値で確認します。
 */
//------------------------------------------------------------------------------

#include "prepared_audit_display_tests.h"
#include "core/candidate_audit.h"
#include "core/official_preparation_audit.h"
#include "core/official_preparation_operation.h"
#include "core/operation_controller.h"
#include "core/provider_registry.h"
#include "platform/broadcom_update_provider.h"
#include "platform/official_catalog_provider.h"
#include "platform/official_driver_package_audit.h"
#include "test_framework.h"

#include <array>
#include <bit>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {
constexpr NativeError AUDIT_FAILURE = std::bit_cast<NativeError>( 0x80004005U) ;	// 合成E_FAIL。

/** @brief 実device・実fileを含めず、表示更新の照合を行う合成fixture。 */
struct AuditDisplayFixture {
	/// 架空の同系列device二件。
	std::vector<OfficialCatalogDevice> devices ;
	/// 内容合格・適用性部分失敗の合成集計。
	OfficialDriverPackageAudit		   audit ;
	/// 同意を検証する一対象の合成計画。
	OfficialPreparationPlan			   plan ;
	/// 合成取得の明示判断。
	OfficialPreparationApproval		   approval ;
	/// 取得成功と独立した監査report。
	OfficialPreparationOperationResult result ;
	/// 同じscanの表示専用行二件。
	std::vector<UpdateCandidate>	   candidates ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 実fileの内容合格とは扱わず、共通reportに必要な閉包profileとrank集計を整合させ、表示DTOと状態遷移だけを試験する。
 * @return 架空の二deviceと一配布物の所有fixture。
 */
//------------------------------------------------------------------------------

AuditDisplayFixture auditDisplayFixture()
{
	AuditDisplayFixture fixture ;	// 各試験が変更できる独立snapshot。
	// 異なるopaque IDで、同系列でも適用性の異なる二deviceを合成する。
	for( std::uint32_t index = 0U; index < 2U; ++index) {
		OfficialCatalogDevice device ;	// 本試験だけの非機密device。
		device.deviceIdentity = L"fictional-device:" + std::to_wstring( index) ;
		device.model		  = L"Broadcom NetXtreme-E Fictional Adapter" ;
		device.manufacturer	  = L"Broadcom" ;
		device.driverClass	  = L"Net" ;
		fixture.devices.push_back( device) ;
		fixture.candidates.push_back( makeBroadcomDiscoveryCandidate( 12U, index, device, {})) ;
	}

	fixture.audit.scanSessionId			  = 12U ;
	fixture.audit.summary.state			  = OfficialDriverPackageAuditState::AUDITED ;
	fixture.audit.summary.infCount		  = 2U ;
	fixture.audit.summary.auditedInfCount = 2U ;
	fixture.audit.auditedPackages.push_back(
		{.profile =
			 OfficialDriverAuditProfile::BROADCOM_NET_XTREME_E}) ;	// 一つ目の合成閉包profile。
	fixture.audit.auditedPackages.push_back(
		{.profile =
			 OfficialDriverAuditProfile::BROADCOM_NET_XTREME_E}) ;	// 二つ目の合成閉包profile。
	fixture.audit.applicability.state = OfficialDriverApplicabilityState::APPLICABLE_TARGETS ;
	fixture.audit.applicability.examinedPairCount	= 4U ;
	fixture.audit.applicability.applicablePairCount = 1U ;
	fixture.audit.applicability.failedPairCount		= 1U ;
	fixture.audit.applicability.rejectedPairCount	= 2U ;
	fixture.audit.applicability.firstPairError		= AUDIT_FAILURE ;
	OfficialDriverRankAudit rankAudit ;	// PnP文字列を含まない合成Applicable結果。
	rankAudit.decision = OfficialDriverRankDecision::APPLICABLE ;
	fixture.audit.rankApprovedTargets.push_back(
		{fixture.devices.front().deviceIdentity, 0U, rankAudit}) ;
	OfficialPreparationTarget target ;	// 実metadataからではない試験用計画対象。
	target.identity			   = L"fictional-target" ;
	target.providerId		   = BROADCOM_NET_XTREME_PROVIDER_ID ;
	target.resourceId		   = L"payload" ;
	target.releaseIdentity	   = L"fictional-release" ;
	target.parserRevision	   = 1U ;
	target.maximumBytes		   = 100U ;
	target.deviceCount		   = 2U ;
	target.terms			   = OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
	fixture.plan			   = {12U, 1U, DEFAULT_OFFICIAL_PREPARATION_LIMITS, {target}} ;
	fixture.approval		   = {2U, 12U, 1U, fixture.plan.limits, {{target, true, false, false}}} ;
	fixture.result.operationId = 2U ;
	fixture.result.scanSessionId = 12U ;
	fixture.result.planId		 = 1U ;
	fixture.result.approvalError = OfficialPreparationError::NONE ;
	fixture.result.items.push_back(
		{target.identity, {OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0, 80U}}) ;
	fixture.result.auditReports.push_back(
		makeBroadcomPreparationAuditReport( 12U, target.identity, fixture.devices, fixture.audit)) ;
	return fixture ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実fileを合格扱いにせず、DTO、Controller、routing前検証だけに使用する。
 *
 * @param[in] fixture 同じscanの表示候補とdeviceを持つfixture。
 * @param[in] deviceIndex 発行対象deviceのfixture内index。
 * @param[in] identity 既存行と重複しない候補ID。
 * @param[in] version INFから取得した空でない明示version。
 * @return 全監査合格・未選択の合成Broadcom候補。
 */
//------------------------------------------------------------------------------
UpdateCandidate publishedCandidate( const AuditDisplayFixture &fixture,
								   const std::size_t deviceIndex, std::wstring identity,
								   std::wstring version)
{
	UpdateCandidate candidate	= fixture.candidates.at( deviceIndex) ;	// 同じdeviceの表示値。
	candidate.identity			= std::move( identity) ;
	candidate.packageIdentity	= L"fictional-broadcom-package" ;
	candidate.title				= L"Fictional audited Broadcom driver" ;
	candidate.provider			= L"Broadcom" ;
	candidate.version			= std::move( version) ;
	candidate.action			= DriverAction::UPDATE ;
	candidate.defaultPreference = CandidateDefaultPreference::NONE ;
	candidate.audit				= makeOfficialReadyCandidateAudit() ;
	candidate.current			= false ;
	candidate.recommended		= false ;
	candidate.installable		= true ;
	candidate.eulaAccepted		= true ;
	candidate.allContentCached	= true ;
	candidate.browseOnly		= false ;
	return candidate ;
}

//------------------------------------------------------------------------------
/**
 * @brief 合格deviceと判定不能deviceを分け、元候補の選択権限を変更しない。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testPreparedAuditPartialDisplay( TestContext &context)
{

	const auto	fixture = auditDisplayFixture() ;				// 部分失敗を含む合成取得。
	const auto &report	= fixture.result.auditReports.front() ;	// 変換済みの非機密集計。
	DRIVERCRATE_EXPECT( context, report.acceptedInfCount == 2U) ;
	DRIVERCRATE_EXPECT( context, report.applicablePairCount == 1U) ;
	DRIVERCRATE_EXPECT( context, report.firstPairError == AUDIT_FAILURE) ;
	DRIVERCRATE_EXPECT( context, report.candidates[0].audit.systemApplicability ==
									CandidateAuditGateState::PASSED) ;
	DRIVERCRATE_EXPECT( context, report.candidates[1].audit.systemApplicability ==
									CandidateAuditGateState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, validatePreparationAuditReports( fixture.result, fixture.approval,
																fixture.candidates)) ;
	// 元候補は内容未監査のまま。変換関数が選択や導入状態を変更しないことを確認する。
	for( const UpdateCandidate &candidate : fixture.candidates) {
		DRIVERCRATE_EXPECT( context, !candidate.installable && !candidate.recommended) ;
		DRIVERCRATE_EXPECT( context,
						   candidate.audit.contentIntegrity == CandidateAuditGateState::PENDING) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 非適用完了と取消しによる全体失敗を区別して表示する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testPreparedAuditNoMatchAndCancel( TestContext &context)
{

	auto fixture = auditDisplayFixture() ;	// 独立した合成監査。
	fixture.audit.rankApprovedTargets.clear() ;
	fixture.audit.applicability		  = {} ;
	fixture.audit.applicability.state = OfficialDriverApplicabilityState::NO_APPLICABLE_TARGETS ;
	fixture.audit.applicability.examinedPairCount = 4U ;
	fixture.audit.applicability.rejectedPairCount = 4U ;
	fixture.result.auditReports					  = {makeBroadcomPreparationAuditReport(
		  12U, L"fictional-target", fixture.devices, fixture.audit)} ;
	DRIVERCRATE_EXPECT( context,
					   fixture.result.auditReports[0].candidates[0].audit.systemApplicability ==
						   CandidateAuditGateState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, validatePreparationAuditReports( fixture.result, fixture.approval,
																fixture.candidates)) ;
	// 取消し時は共通監査が部分合格を破棄する。
	fixture.audit					  = {} ;
	fixture.audit.summary.state		  = OfficialDriverPackageAuditState::FAILURE ;
	fixture.audit.summary.error		  = AUDIT_FAILURE ;
	fixture.audit.applicability.state = OfficialDriverApplicabilityState::FAILURE ;
	fixture.audit.applicability.error = AUDIT_FAILURE ;
	fixture.result.auditReports		  = {makeBroadcomPreparationAuditReport(
		  12U, L"fictional-target", fixture.devices, fixture.audit)} ;
	DRIVERCRATE_EXPECT( context, validatePreparationAuditReports( fixture.result, fixture.approval,
																fixture.candidates)) ;
	DRIVERCRATE_EXPECT( context,
					   fixture.result.auditReports[0].candidates[0].audit.systemApplicability ==
						   CandidateAuditGateState::PENDING) ;
	DRIVERCRATE_EXPECT( context, fixture.result.items[0].result.byteCount == 80U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 旧操作、未選択、別Provider、重複対象・未知行を全件拒否する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testPreparedAuditBindingRejection( TestContext &context)
{

	// 独立した各mutationが、それぞれの照合拒否を通ることを確認する。
	for( std::uint32_t mutation = 0U; mutation < 9U; ++mutation) {
		auto fixture = auditDisplayFixture() ;	// 一項目だけを変更する独立fixture。
		// operation・選択・Provider・identityの不整合を個別に注入して表示反映の拒否を検証する。
		switch( mutation) {
			// 別operationから届いた監査結果を拒否する。
			case 0U:
				++fixture.result.operationId ;
				break ;

			// 別scan sessionの監査結果を拒否する。
			case 1U:
				++fixture.result.scanSessionId ;
				break ;

			// 別計画の監査結果を拒否する。
			case 2U:
				++fixture.result.planId ;
				break ;

			// 取得を選択していない対象への監査表示を拒否する。
			case 3U:
				fixture.approval.decisions[0].acquire = false ;
				break ;

			// 監査reportのProvider差替えを検出する。
			case 4U:
				fixture.result.auditReports[0].providerId = WINDOWS_UPDATE_PROVIDER_ID ;
				break ;

			// 同じ対象の監査reportが重複した通知を検証する。
			case 5U:
				fixture.result.auditReports.push_back( fixture.result.auditReports[0]) ;
				break ;

			// 未知の候補identityを持つ監査行の拒否を検証する。
			case 6U:
				fixture.result.auditReports[0].candidates[0].identity = L"unknown" ;
				break ;

			// 異なる監査行に同じ候補identityを付けた場合を検証する。
			case 7U:
				fixture.result.auditReports[0].candidates[1].identity =
					fixture.result.auditReports[0].candidates[0].identity ;
				break ;

			// 取得中止の項目に監査済み表示を付与しないことを検証する。
			case 8U:
				fixture.result.items[0].result.state = OfficialPreparationItemState::CANCELLED ;
				break ;

			// 定義した通知改変以外ではfixtureを変更しない。
			default:
				break ;
		}

		DRIVERCRATE_EXPECT( context, !validatePreparationAuditReports(
										fixture.result, fixture.approval, fixture.candidates)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 件数矛盾、未定義状態、現在版・選択候補の上書きと導入権限の付加を拒否する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testPreparedAuditGateRejection( TestContext &context)
{

	// 件数と状態の境界を一つずつ破り、他条件の不正に依存しない拒否を確認する。
	for( std::uint32_t mutation = 0U; mutation < 9U; ++mutation) {
		auto  fixture = auditDisplayFixture() ;				// 正常な表示reportから開始する。
		auto &report  = fixture.result.auditReports[0] ;	// 今回だけ変更するreport。
		// 監査件数と状態の矛盾、既存行の上書きを個別に注入する。
		switch( mutation) {
			// 許容上限を超える受理INF件数を検証する。
			case 0U:
				report.acceptedInfCount = 33U ;
				break ;

			// 許容上限を超える評価pair件数を検証する。
			case 1U:
				report.examinedPairCount = 131073U ;
				break ;

			// 未定義の内容gate状態を合格として表示しないことを検証する。
			case 2U:
				report.content = static_cast<CandidateAuditGateState>( 255) ;
				break ;

			// 表示専用監査からinstall可能状態への不正な昇格を検証する。
			case 3U:
				report.candidates[0].audit.installReadiness = CandidateInstallReadiness::READY ;
				break ;

			// 現在使用中の候補を監査結果で上書きしないことを検証する。
			case 4U:
				fixture.candidates[0].current = true ;
				break ;

			// 既にinstall可能な候補を監査表示で上書きしないことを検証する。
			case 5U:
				fixture.candidates[0].installable = true ;
				break ;

			// 適用性拒否を含む候補を合格reportへ混在させた場合を検証する。
			case 6U:
				report.candidates[1].audit.systemApplicability = CandidateAuditGateState::REJECTED ;
				break ;

			// 内容合格と診断値が矛盾するreportを検証する。
			case 7U:
				report.contentError = 1 ;
				break ;

			// 評価済み件数と整合しない適用pair件数を検証する。
			case 8U:
				report.applicablePairCount = 5U ;
				break ;

			// 定義したreport改変以外ではfixtureを変更しない。
			default:
				break ;
		}

		DRIVERCRATE_EXPECT( context, !validatePreparationAuditReports(
										fixture.result, fixture.approval, fixture.candidates)) ;
	}

	auto fixture = auditDisplayFixture() ;	// 未接続Providerの空reportも正当な結果である。
	fixture.result.auditReports.clear() ;
	DRIVERCRATE_EXPECT( context,
					   validatePreparationAuditReports( fixture.result, fixture.approval, {})) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全監査合格候補だけが既存scanへ追加でき、Controllerの明示選択対象になる。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testPreparedCandidatePublication( TestContext &context)
{
	auto  fixture			 = auditDisplayFixture() ;			// 合格組合せを一件持つ取得結果。
	auto &report			 = fixture.result.auditReports[0] ;	// 今回候補を発行する監査report。
	report.publication.state = OfficialPreparationCandidatePublicationState::CANDIDATES_PUBLISHED ;
	report.publication.examinedPairCount = 1U ;
	report.publication.publishedCount	 = 1U ;
	report.candidatePublicationAttempted = true ;
	report.publishedCandidates.push_back(
		publishedCandidate( fixture, 0U, L"published-candidate", L"2.0.0.0")) ;
	DRIVERCRATE_EXPECT( context,
					   validatePreparationCandidatePublication( report, fixture.candidates)) ;
	DRIVERCRATE_EXPECT( context, validatePreparationAuditReports( fixture.result, fixture.approval,
																fixture.candidates)) ;

	auto &candidate = report.publishedCandidates.front() ;	// 詳細付きの公開境界だけを追加確認する。
	candidate.assessment	 = CandidateAssessment{} ;
	auto &detail			 = *candidate.assessment ;	// 寿命は以下のresetまで。
	detail.scanSessionId	 = 12U ;
	detail.candidateIdentity = candidate.identity ;
	detail.deviceIdentity	 = candidate.deviceIdentity ;
	detail.packageIdentity	 = candidate.packageIdentity ;
	detail.origin			 = {CandidateAssessmentState::PASSED,
								CandidateAssessmentReason::VALIDATED,
								CandidateEvidenceKind::OFFICIAL_RECORD,
								1U,
								{}} ;
	detail.acquisition		 = {CandidateAssessmentState::MANAGED_BY_WINDOWS,
								CandidateAssessmentReason::WINDOWS_MANAGED,
								CandidateEvidenceKind::WINDOWS_API,
								2U,
								{}} ;
	detail.signature		 = detail.acquisition ;
	detail.applicability	 = detail.acquisition ;
	detail.windowsSelection	 = detail.acquisition ;
	detail.driverOnly		 = detail.acquisition ;
	detail.requirements		 = detail.acquisition ;
	detail.method			 = {CandidateAssessmentState::PASSED,
								CandidateAssessmentReason::VALIDATED,
								CandidateEvidenceKind::IMPLEMENTATION_POLICY,
								3U,
								{}} ;
	detail.installMethod	 = CandidateInstallMethod::STANDARD_INF ;
	detail.executorAvailable = true ;
	DRIVERCRATE_EXPECT( context, validatePreparationAuditReports( fixture.result, fixture.approval,
																fixture.candidates)) ;
	detail.scanSessionId = 13U ;
	DRIVERCRATE_EXPECT( context, !validatePreparationAuditReports( fixture.result, fixture.approval,
																 fixture.candidates)) ;
	detail.scanSessionId = 12U ;
	candidate.action	 = DriverAction::INITIAL_INSTALL ;
	DRIVERCRATE_EXPECT( context, !validatePreparationAuditReports( fixture.result, fixture.approval,
																 fixture.candidates)) ;
	candidate.action = DriverAction::UPDATE ;
	candidate.assessment.reset() ;
	OperationController controller ;					// 実Providerから分離した状態管理。
	const BeginResult	scan = controller.beginScan() ;	// 新しい合成scan操作。
	ScanResult			scanned ;						// 取得前の表示専用候補二件。
	scanned.scanSessionId = 12U ;
	scanned.succeeded	  = true ;
	scanned.outcome		  = OutcomeCode::SUCCESS ;
	scanned.candidates	  = fixture.candidates ;
	DRIVERCRATE_EXPECT( context, controller.completeScan( scan.operationId, scanned)) ;
	DRIVERCRATE_EXPECT( context, controller.setPreparationPlan( scan.operationId, fixture.plan)) ;
	fixture.approval.operationId  = 0U ;
	const BeginResult preparation = controller.beginPreparation( fixture.approval) ;	// 明示取得。
	DRIVERCRATE_EXPECT( context, preparation.accepted) ;
	fixture.result.operationId = preparation.operationId ;
	DRIVERCRATE_EXPECT( context, controller.completePreparation( fixture.result, fixture.candidates)) ;
	const std::array<std::wstring, 1> selection{L"published-candidate"} ;	// 新規候補の選択。
	DRIVERCRATE_EXPECT(
		context, controller.beginInstall( 12U, selection, InstallConfirmation::CONFIRMED).accepted) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ID上書き、別device、非合格device、未監査、推奨化、同版重複を全件拒否する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testPreparedCandidatePublicationRejection( TestContext &context)
{
	// 正常な一候補から一条件だけを変更し、発行境界の各拒否理由を確認する。
	for( std::uint32_t mutation = 0U; mutation < 9U; ++mutation) {
		auto  fixture = auditDisplayFixture() ;				// 各mutation専用の独立fixture。
		auto &report  = fixture.result.auditReports[0] ;	// 候補発行元report。
		report.publication.state =
			OfficialPreparationCandidatePublicationState::CANDIDATES_PUBLISHED ;
		report.publication.examinedPairCount = 1U ;
		report.publication.publishedCount	 = 1U ;
		report.candidatePublicationAttempted = true ;
		report.publishedCandidates.push_back(
			publishedCandidate( fixture, 0U, L"published-candidate", L"2.0.0.0")) ;
		UpdateCandidate &candidate = report.publishedCandidates[0] ;	// 今回変更する候補。
		// 候補のidentity・device・監査・推奨状態を個別に不正化して全件拒否を検証する。
		switch( mutation) {
			// 新規発行候補による既存候補identityの上書きを検証する。
			case 0U:
				candidate.identity = fixture.candidates[0].identity ;
				break ;

			// 現在のdevice集合にない対象への候補発行を検証する。
			case 1U:
				candidate.deviceIdentity = L"unknown-device" ;
				break ;

			// 監査から発行した候補を自動推奨へ昇格させないことを検証する。
			case 2U:
				candidate.recommended = true ;
				break ;

			// 発行候補に必要なinstall capabilityがない場合を検証する。
			case 3U:
				candidate.installable = false ;
				break ;

			// 内容監査が未完了の候補を発行しないことを検証する。
			case 4U:
				candidate.audit.contentIntegrity = CandidateAuditGateState::PENDING ;
				break ;

			// 導入actionが定まらない候補の発行を検証する。
			case 5U:
				candidate.action = DriverAction::NONE ;
				break ;

			// 公式監査候補をWUA由来と偽装した入力を検証する。
			case 6U:
				candidate.providerId = WINDOWS_UPDATE_PROVIDER_ID ;
				break ;

			// 候補発行を試行していないreportに候補を混在させた場合を検証する。
			case 7U:
				report.candidatePublicationAttempted = false ;
				break ;

			// 監査に合格していない別deviceへの候補付替えを検証する。
			case 8U:
				candidate.deviceIdentity = fixture.devices[1].deviceIdentity ;
				break ;

			// 定義した候補改変以外ではfixtureを変更しない。
			default:
				break ;
		}

		DRIVERCRATE_EXPECT( context,
						   !validatePreparationCandidatePublication( report, fixture.candidates)) ;
	}

	auto  fixture			 = auditDisplayFixture() ;			// 同device／同版を二重発行するfixture。
	auto &report			 = fixture.result.auditReports[0] ;	// 二件の新規候補を持つreport。
	report.publication.state = OfficialPreparationCandidatePublicationState::CANDIDATES_PUBLISHED ;
	report.publication.examinedPairCount = 2U ;
	report.publication.publishedCount	 = 2U ;
	report.candidatePublicationAttempted = true ;
	report.applicablePairCount			 = 2U ;
	report.publishedCandidates.push_back(
		publishedCandidate( fixture, 0U, L"published-candidate-a", L"2.0.0.0")) ;
	report.publishedCandidates.push_back(
		publishedCandidate( fixture, 0U, L"published-candidate-b", L"2.0.0.0")) ;
	DRIVERCRATE_EXPECT( context,
					   !validatePreparationCandidatePublication( report, fixture.candidates)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 監査表示後も導入許可を増やさず、既存候補と現在版を保持する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testPreparedAuditControllerNonpromotion( TestContext &context)
{

	auto				fixture = auditDisplayFixture() ;	// 同じscanの取得承認と監査結果。
	OperationController controller ;						// 実Providerを呼ばないUI状態管理。
	const auto			scan = controller.beginScan() ;		// 新しいscan操作のID。
	ScanResult			scanned ;							// 表示専用候補二件の正常検索結果。
	scanned.scanSessionId = 12U ;
	scanned.succeeded	  = true ;
	scanned.outcome		  = OutcomeCode::SUCCESS ;
	scanned.candidates	  = fixture.candidates ;
	DRIVERCRATE_EXPECT( context, controller.completeScan( scan.operationId, scanned)) ;
	DRIVERCRATE_EXPECT( context, controller.setPreparationPlan( scan.operationId, fixture.plan)) ;
	fixture.approval.operationId = 0U ;
	DRIVERCRATE_EXPECT( context, controller.beginPreparation( fixture.approval).accepted) ;
	fixture.result.operationId = fixture.approval.operationId ;
	auto stale				   = fixture.result ;	// 別sessionから遅延した結果。
	++stale.scanSessionId ;
	DRIVERCRATE_EXPECT( context, !controller.completePreparation( stale, fixture.candidates)) ;
	DRIVERCRATE_EXPECT( context, controller.completePreparation( fixture.result, fixture.candidates)) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::SCAN_READY) ;
	const std::array<std::wstring, 1> selection{
		fixture.candidates[0].identity} ;	// 表示専用行の選択要求。
	DRIVERCRATE_EXPECT(
		context, !controller.beginInstall( 12U, selection, InstallConfirmation::CONFIRMED).accepted) ;
	DRIVERCRATE_EXPECT( context,
					   !controller.completePreparation( fixture.result, fixture.candidates)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在操作でも未知の監査行を含む結果はFailedとして一覧を失効させる。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testPreparedAuditControllerInvalidResult( TestContext &context)
{

	auto				fixture = auditDisplayFixture() ;	// 改変前は正常な合成report。
	OperationController controller ;						// 実APIから分離した状態管理。
	const auto			scan = controller.beginScan() ;		// 新しいscan操作。
	ScanResult			scanned ;							// 同じsessionの表示専用候補。
	scanned.scanSessionId = 12U ;
	scanned.succeeded	  = true ;
	scanned.outcome		  = OutcomeCode::SUCCESS ;
	scanned.candidates	  = fixture.candidates ;
	DRIVERCRATE_EXPECT( context, controller.completeScan( scan.operationId, scanned)) ;
	DRIVERCRATE_EXPECT( context, controller.setPreparationPlan( scan.operationId, fixture.plan)) ;
	fixture.approval.operationId = 0U ;
	DRIVERCRATE_EXPECT( context, controller.beginPreparation( fixture.approval).accepted) ;
	fixture.result.operationId							  = fixture.approval.operationId ;
	fixture.result.auditReports[0].candidates[0].identity = L"not-displayed" ;
	DRIVERCRATE_EXPECT( context, controller.completePreparation( fixture.result, fixture.candidates)) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, controller.scanSessionId() == 0U) ;
}

/**
 * @brief 全体内容件数と実device照合数を分け、過大・逆転・overflowを拒否します。
 * @param[in,out] context Assertion集計先です。
 */
void testPreparedAuditPayloadCounts( TestContext &context)
{
	// 旧32件超の拒否を33件・実測相当57件・既存総INF上限で再現します。
	for( const std::uint32_t count : {33U, 57U, 4096U}) {
		auto  fixture	= auditDisplayFixture() ;				// 実内容・実適用性を主張しない独立DTOです。
		auto &report	= fixture.result.auditReports.front() ;	// 同じ承認の架空監査です。
		report.infCount = count == 57U ? 72U : count ;
		report.acceptedInfCount = count ;
		DRIVERCRATE_EXPECT( context, validatePreparationAuditReports(
										fixture.result, fixture.approval, fixture.candidates)) ;
	}

	auto  fixture = auditDisplayFixture() ;					// 同じ固定承認を各負例へ再使用します。
	auto &report  = fixture.result.auditReports.front() ;	// 発行候補なしの内容合格表示です。
	// 総数超過・合格数逆転・uint32最大をそれぞれ独立に拒否します。
	for( const auto counts : {std::pair{4097U, 57U}, std::pair{4097U, 4097U}, std::pair{56U, 57U},
							 std::pair{4096U, 0xffff'ffffU}}) {
		report.infCount			= counts.first ;
		report.acceptedInfCount = counts.second ;
		DRIVERCRATE_EXPECT( context, !validatePreparationAuditReports(
										fixture.result, fixture.approval, fixture.candidates)) ;
	}

	report.infCount										  = 4096U ;
	report.acceptedInfCount								  = 4096U ;
	fixture.approval.decisions.front().target.deviceCount = 32U ;
	report.examinedPairCount							  = 131072U ;
	DRIVERCRATE_EXPECT( context, validatePreparationAuditReports( fixture.result, fixture.approval,
																fixture.candidates)) ;
	report.examinedPairCount = 131073U ;
	DRIVERCRATE_EXPECT( context, !validatePreparationAuditReports( fixture.result, fixture.approval,
																 fixture.candidates)) ;
	report.examinedPairCount = 0xffff'ffffU ;
	DRIVERCRATE_EXPECT( context, !validatePreparationAuditReports( fixture.result, fixture.approval,
																 fixture.candidates)) ;
	fixture.approval.decisions.front().target.deviceCount = 33U ;
	report.examinedPairCount							  = 4U ;
	DRIVERCRATE_EXPECT( context, !validatePreparationAuditReports( fixture.result, fixture.approval,
																 fixture.candidates)) ;
	report.applicability	   = CandidateAuditGateState::FAILURE ;
	report.applicabilityError  = AUDIT_FAILURE ;
	report.examinedPairCount   = 0U ;
	report.applicablePairCount = 0U ;
	report.failedPairCount	   = 0U ;
	// 予算による全体拒否は、部分成功ではなく理由付きの失敗として表示できます。
	for( auto &row : report.candidates) {
		row.audit.systemApplicability = CandidateAuditGateState::FAILURE ;
	}

	DRIVERCRATE_EXPECT( context, validatePreparationAuditReports( fixture.result, fixture.approval,
																fixture.candidates)) ;
	report.examinedPairCount = 1U ;
	DRIVERCRATE_EXPECT( context, !validatePreparationAuditReports( fixture.result, fixture.approval,
																 fixture.candidates)) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/prepared_audit_display_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------

void runPreparedAuditDisplayTests( TestContext &context)
{
	testPreparedAuditPayloadCounts( context) ;
	testPreparedAuditPartialDisplay( context) ;
	testPreparedAuditNoMatchAndCancel( context) ;
	testPreparedAuditBindingRejection( context) ;
	testPreparedAuditGateRejection( context) ;
	testPreparedCandidatePublication( context) ;
	testPreparedCandidatePublicationRejection( context) ;
	testPreparedAuditControllerNonpromotion( context) ;
	testPreparedAuditControllerInvalidResult( context) ;
}
} // namespace drivercrate::test
