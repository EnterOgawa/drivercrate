//------------------------------------------------------------------------------
/**
 * @file official_preparation_audit.cpp
 * @brief 取得後監査と表示候補の照合。
 * @version 01.04.00
 * @date 2026/10/24
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  候補発行状態と有限件数の検証を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  監査合格候補の検証境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の表示境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  準備後の候補詳細を承認sessionへ再結合。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  同版INF代替を独立Windows tokenへ限定して区別。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.03.01 Shunji Ogawa  2026/10/15  全体INF件数と元承認deviceの有限pair数を照合。
 * Ver.01.04.00 Shunji Ogawa  2026/10/24  同device複数原参照をunique作用device数と分けて検証。
 * </pre>
 *
 * @note 取得成功と独立した監査結果を扱い、全監査合格時だけ新規候補を検証します。
 */
//------------------------------------------------------------------------------

#include "core/official_preparation_audit.h"
#include "core/candidate_audit.h"
#include "core/candidate_selection.h"
#include "core/candidate_source_group.h"
#include "core/official_preparation_operation.h"
#include "core/provider_registry.h"
#include <tuple>

#include <algorithm>
#include <cstddef>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace drivercrate {
namespace {
//------------------------------------------------------------------------------
/**
 * @brief Windows委譲やProvider推測を取得後監査の合格へ混入させない。
 *
 * @param[in] state 表示へ受け入れる段階状態。
 * @return 表示用四状態のいずれかならtrue。
 */
//------------------------------------------------------------------------------

bool displayGate( const CandidateAuditGateState state) noexcept
{
	return state == CandidateAuditGateState::PENDING || state == CandidateAuditGateState::PASSED ||
		   state == CandidateAuditGateState::REJECTED || state == CandidateAuditGateState::FAILURE ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/core/official_preparation_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool validatePreparationCandidatePublication( const OfficialPreparationAuditReport  &report,
											 const std::span<const UpdateCandidate> candidates)
{
	const OfficialPreparationCandidatePublication &publication =
		report.publication ;	// URLやPnP IDを含まないProvider発行集計。
	// 監査合格数を超える集計、過大入力、HRESULTでない正値を拒否する。
	if( publication.examinedPairCount > report.applicablePairCount ||
	   publication.publishedCount > publication.examinedPairCount ||
	   publication.excludedPairCount > publication.examinedPairCount ||
	   publication.firstError > 0 || report.candidates.size() > 4096U ||
	   candidates.size() > 65536U) {
		return false ;
	}

	// 候補発行の終端状態と件数を照合し、未実施や失敗を発行成功として表示しない。
	switch( publication.state) {
		// 公開未開始では候補・件数・error が未処理状態と整合することを要求する。
		case OfficialPreparationCandidatePublicationState::NOT_STARTED:
			return !report.candidatePublicationAttempted && report.publishedCandidates.empty() &&
				   publication.examinedPairCount == 0U && publication.publishedCount == 0U &&
				   publication.excludedPairCount == 0U && publication.firstError == 0 ;
		// 対象なしでは監査合格後の全組合せが除外され、候補を公開していないことを確認する。
		case OfficialPreparationCandidatePublicationState::NO_ELIGIBLE_CANDIDATES:
			return report.content == CandidateAuditGateState::PASSED &&
				   report.applicability == CandidateAuditGateState::PASSED &&
				   !report.candidatePublicationAttempted && report.publishedCandidates.empty() &&
				   publication.examinedPairCount != 0U &&
				   publication.examinedPairCount == report.applicablePairCount &&
				   publication.publishedCount == 0U &&
				   publication.excludedPairCount == publication.examinedPairCount &&
				   publication.firstError != 0 ;
		// 公開失敗では合格監査と無候補・除外件数・失敗 code の整合を確認する。
		case OfficialPreparationCandidatePublicationState::FAILURE:
			return report.content == CandidateAuditGateState::PASSED &&
				   report.applicability == CandidateAuditGateState::PASSED &&
				   !report.candidatePublicationAttempted && report.publishedCandidates.empty() &&
				   publication.publishedCount == 0U &&
				   publication.excludedPairCount == publication.examinedPairCount &&
				   publication.firstError != 0 ;
		// 公開済み候補は後続で候補内容と Provider・routing の契約まで検証する。
		case OfficialPreparationCandidatePublicationState::CANDIDATES_PUBLISHED:
			// 以下で候補内容、Provider能力およびrouting前提まで検証する。
			break ;

		// 未知の公開状態を正常 report として受理しない。
		default:
			return false ;
	}

	// 全監査合格以外から選択可能候補を発行しない。
	if( report.content != CandidateAuditGateState::PASSED ||
	   report.applicability != CandidateAuditGateState::PASSED ||
	   !report.candidatePublicationAttempted || report.publishedCandidates.empty() ||
	   report.publishedCandidates.size() > 4096U ||
	   report.publishedCandidates.size() > 65536U - candidates.size() ||
	   report.publishedCandidates.size() > report.applicablePairCount ||
	   publication.examinedPairCount != report.applicablePairCount ||
	   static_cast<std::size_t>( publication.publishedCount) != report.publishedCandidates.size() ||
	   publication.publishedCount !=
		   publication.examinedPairCount - publication.excludedPairCount ||
	   (publication.excludedPairCount == 0U && publication.firstError != 0) ||
	   (publication.excludedPairCount != 0U && publication.firstError == 0)) {
		return false ;
	}

	const auto descriptors = builtInProviderDescriptors() ;	// Process内の不変registry。
	const auto descriptor =
		std::find_if( descriptors.begin(), descriptors.end(), [&]( const ProviderDescriptor &value) {
			return value.id == report.providerId ;
		}) ; // 発行元の能力定義。
	// 未登録または導入能力のないProviderから、導入可能候補を発行させない。
	if( descriptor == descriptors.end() ||
	   (descriptor->capabilities & capabilityMask( ProviderCapability::INSTALL)) == 0U) {
		return false ;
	}

	std::unordered_map<std::wstring_view, const UpdateCandidate *> known ;	// 既存ID索引。
	std::unordered_set<std::wstring_view> passedReportDevices ;				// 適用性合格行のdevice集合。
	// 既存候補を一意に索引化し、監査reportが明示した行からdevice集合を固定する。
	for( const UpdateCandidate &candidate : candidates) {
		// 既存候補の空IDと重複を拒否し、新規候補との対応を一意に保つ。
		if( candidate.identity.empty() || !known.emplace( candidate.identity, &candidate).second) {
			return false ;
		}
	}

	// 既存表示行だけをdevice対応の根拠にし、Providerが新しいdevice IDを作ることを拒否する。
	for( const OfficialPreparationCandidateAudit &row : report.candidates) {
		const auto found = known.find( row.identity) ;	// 対応する既存候補。
		// 監査対象を同じProviderの表示済みdeviceへ結び付けられなければ候補を発行しない。
		if( found == known.end() || found->second->providerId != report.providerId ||
		   found->second->deviceIdentity.empty()) {
			return false ;
		}

		// 適用性が実際に合格したdeviceだけを、新規候補の発行先として許可する。
		if( row.audit.systemApplicability == CandidateAuditGateState::PASSED) {
			passedReportDevices.insert( found->second->deviceIdentity) ;
		}
	}

	std::unordered_set<std::wstring_view> identities ;	// 新規候補内のID重複検出集合。
	std::set<std::tuple<std::wstring_view, std::wstring_view, std::uint64_t>>
								 versions ;	// 同版代替は独立native tokenまで区別します。
	std::vector<UpdateCandidate> merged( candidates.begin(),
										// Group検証用snapshot。
										candidates.end()) ;
	merged.reserve( candidates.size() + report.publishedCandidates.size()) ;
	// 全発行候補を一件ずつ検証し、最後に同一版取得元group全体の整合も確認する。
	for( const UpdateCandidate &candidate : report.publishedCandidates) {
		const auto bindingToken =
			candidate.providerId == SIGNED_INDEX_PROVIDER_ID &&
					candidate.discoveryBasis ==
						CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION &&
					candidate.assessment && isCandidateAssessmentReady( *candidate.assessment) &&
					candidate.assessment->windowsSelection.evidenceKind ==
						CandidateEvidenceKind::WINDOWS_API &&
					candidate.assessment->method.evidenceKind ==
						CandidateEvidenceKind::IMPLEMENTATION_POLICY &&
					candidate.assessment->method.evidenceId ==
						candidate.assessment->windowsSelection.evidenceId
				? candidate.assessment->windowsSelection.evidenceId
				: 0U ;	// Private routeで実権限を別照合します。
		// 全監査と同意、device対応、候補の一意性がそろわない発行結果をまとめて拒否する。
		if( candidate.identity.empty() || known.contains( candidate.identity) ||
		   !identities.insert( candidate.identity).second ||
		   candidate.providerId != report.providerId ||
		   !passedReportDevices.contains( candidate.deviceIdentity) ||
		   candidate.packageIdentity.empty() || candidate.version.empty() || candidate.current ||
		   candidate.recommended || !candidate.installable ||
		   candidate.defaultPreference != CandidateDefaultPreference::NONE ||
		   candidate.action == DriverAction::NONE || !candidate.eulaAccepted ||
		   !candidate.allContentCached ||
		   candidate.audit.sourceOrigin != CandidateAuditGateState::PASSED ||
		   candidate.audit.inspectionDownload != CandidateAuditGateState::PASSED ||
		   candidate.audit.contentIntegrity != CandidateAuditGateState::PASSED ||
		   candidate.audit.systemApplicability != CandidateAuditGateState::PASSED ||
		   candidate.audit.installReadiness != CandidateInstallReadiness::READY ||
		   !versions.emplace( candidate.deviceIdentity, candidate.version, bindingToken).second ||
		   !isCandidateDefaultPreferenceValid( candidate, *descriptor) ||
		   !isCandidateAuditValid( candidate, *descriptor)) {
			return false ;
		}

		merged.push_back( candidate) ;
	}

	return groupEquivalentCandidateSources( merged, descriptors).has_value() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_preparation_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------

bool validatePreparationAuditReports( const OfficialPreparationOperationResult &result,
									 const OfficialPreparationApproval		  &approval,
									 const std::span<const UpdateCandidate>	   candidates)
{
	// 未接続Providerの監査を成功・失敗のどちらにも補完しない。
	if( result.auditReports.empty()) {
		return true ;
	}

	// 旧承認・制御異常・無制限の通知へ監査表示を付加させない。
	if( result.operationId == 0U || result.operationId != approval.operationId ||
	   result.scanSessionId == 0U || result.scanSessionId != approval.scanSessionId ||
	   result.planId == 0U || result.planId != approval.planId ||
	   result.approvalError != OfficialPreparationError::NONE || result.controlError != 0 ||
	   result.auditReports.size() > 256U || approval.decisions.size() > 256U ||
	   result.items.size() > 256U || candidates.size() > 65536U) {
		return false ;
	}

	std::unordered_map<std::wstring_view, const UpdateCandidate *> known ;	// 非所有の既存行索引。
	// 一覧全体の候補IDが一意であることを確認し、reportとの照合を線形探索にしない。
	for( const UpdateCandidate &candidate : candidates) {
		// 表示済み候補との照合先が空または重複なら、監査通知を適用しない。
		if( candidate.identity.empty() ||
		   !isCandidateDetailsValid( candidate, result.scanSessionId) ||
		   !known.emplace( candidate.identity, &candidate).second) {
			return false ;
		}
	}

	std::unordered_set<std::wstring_view> targets ;			// 一対象一reportの照合集合。
	std::unordered_set<std::wstring_view> updated ;			// 複数report間でも一行一更新に限る。
	const auto descriptors = builtInProviderDescriptors() ;	// Process内の不変registry。
	// 最大256対象、全report合計4096行に限定して全体を検証する。
	for( const OfficialPreparationAuditReport &report : result.auditReports) {
		const auto decision =
			std::find_if( approval.decisions.begin(), approval.decisions.end(),
						 [&]( const OfficialPreparationDecision &value) {
							 return value.target.identity == report.targetIdentity ;
						 }) ; // 固定承認の対象。
		const auto item		  = std::find_if( result.items.begin(), result.items.end(),
											 [&]( const OfficialPreparationItem &value) {
											 return value.identity == report.targetIdentity ;
										 }) ; // 対象の転送結果。
		const auto descriptor = std::find_if( descriptors.begin(), descriptors.end(),
											 [&]( const ProviderDescriptor &value) {
												 return value.id == report.providerId ;
											 }) ; // 当該取得元の能力定義。
		// 未選択・未取得・別Provider・重複・過大な結果を拒否する。
		if( report.targetIdentity.empty() || !targets.insert( report.targetIdentity).second ||
		   decision == approval.decisions.end() || !decision->acquire ||
		   decision->target.deviceCount == 0U || decision->target.deviceCount > 4096U ||
		   report.providerId != decision->target.providerId || item == result.items.end() ||
		   item->result.state != OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION ||
		   item->result.error != 0 || item->result.byteCount == 0U ||
		   item->result.byteCount > decision->target.maximumBytes ||
		   descriptor == descriptors.end() || report.candidates.empty() ||
		   report.candidates.size() > 4096U - updated.size()) {
			return false ;
		}

		// 件数の逆転や監査未合格からの適用性昇格を拒否する。
		if( !displayGate( report.content) || !displayGate( report.applicability) ||
		   report.contentError > 0 || report.firstContentRejection > 0 ||
		   report.applicabilityError > 0 || report.firstPairError > 0 ||
		   report.infCount > OFFICIAL_PREPARATION_MAXIMUM_INF_COUNT ||
		   report.acceptedInfCount > report.infCount ||
		   (report.applicabilityError == 0 &&
			(report.acceptedInfCount + (report.installerHandoff ? 1U : 0U)) >
				OFFICIAL_PREPARATION_MAXIMUM_PAIR_COUNT / decision->target.deviceCount) ||
		   (report.applicabilityError != 0 && report.examinedPairCount != 0U) ||
		   report.examinedPairCount > OFFICIAL_PREPARATION_MAXIMUM_PAIR_COUNT ||
		   report.examinedPairCount >
			   static_cast<std::uint64_t>( report.acceptedInfCount +
										  (report.installerHandoff ? 1U : 0U)) *
				   decision->target.deviceCount ||
		   report.applicablePairCount > report.examinedPairCount ||
		   report.failedPairCount > report.examinedPairCount - report.applicablePairCount ||
		   (report.content == CandidateAuditGateState::PASSED &&
			((report.acceptedInfCount == 0U && !report.installerHandoff) ||
			 report.contentError != 0)) ||
		   (report.content != CandidateAuditGateState::PASSED &&
			(report.acceptedInfCount != 0U || report.examinedPairCount != 0U ||
			 (report.applicability != CandidateAuditGateState::PENDING &&
			  report.applicability != CandidateAuditGateState::FAILURE))) ||
		   (report.applicability == CandidateAuditGateState::PASSED &&
			(report.applicablePairCount == 0U || report.applicabilityError != 0)) ||
		   (report.applicability != CandidateAuditGateState::PASSED &&
			report.applicablePairCount != 0U)) {
			return false ;
		}

		// Installer専用監査をINF件数へ加算せず、他Providerや混在形式を受理しません。
		if( report.installerHandoff &&
		   (report.providerId != SIGNED_INDEX_PROVIDER_ID || report.infCount != 0U ||
			report.acceptedInfCount != 0U ||
			std::ranges::any_of( report.publishedCandidates, []( const auto &candidate) {
				return !candidate.assessment || candidate.assessment->installMethod !=
													CandidateInstallMethod::OFFICIAL_INSTALLER ;
			}))) {
			return false ;
		}

		std::unordered_set<std::wstring> reportDevices ;	// 元参照行数と作用device数を分離します。
		// 各行は既存の表示専用候補に限り、監査以外のfieldを更新対象にしない。
		for( const OfficialPreparationCandidateAudit &row : report.candidates) {
			const auto found = known.find( row.identity) ;	// 表示済みの候補を指す非所有参照。
			// 未表示IDや重複した監査行を拒否し、一候補へ複数の更新通知を適用しない。
			if( found == known.end() || !updated.insert( row.identity).second) {
				return false ;
			}

			UpdateCandidate candidate = *found->second ;	// 共通監査検証用の一時snapshot。
			// 現在版・選択候補の変更と、部分失敗からの非適用断定を禁止する。
			if( candidate.providerId != report.providerId || candidate.deviceIdentity.empty() ||
			   candidate.current || candidate.installable || candidate.recommended ||
			   candidate.action != DriverAction::NONE ||
			   candidate.defaultPreference != CandidateDefaultPreference::NONE ||
			   candidate.audit.sourceOrigin != CandidateAuditGateState::PASSED ||
			   row.audit.sourceOrigin != CandidateAuditGateState::PASSED ||
			   row.audit.inspectionDownload != CandidateAuditGateState::PASSED ||
			   row.audit.contentIntegrity != report.content ||
			   !displayGate( row.audit.systemApplicability) ||
			   row.audit.installReadiness != CandidateInstallReadiness::BLOCKED ||
			   (row.audit.systemApplicability == CandidateAuditGateState::PASSED &&
				report.applicability != CandidateAuditGateState::PASSED) ||
			   (row.audit.systemApplicability == CandidateAuditGateState::REJECTED &&
				(report.applicability == CandidateAuditGateState::PENDING ||
				 report.applicabilityError != 0 || report.failedPairCount != 0U))) {
				return false ;
			}

			reportDevices.insert( candidate.deviceIdentity) ;
			candidate.audit = row.audit ;
			// 既存の公式候補監査契約もそのまま適用する。
			if( !isCandidateAuditValid( candidate, *descriptor)) {
				return false ;
			}
		}

		// 同deviceの複数原recordは保持し、新しい作用deviceの追加は承認件数で拒否します。
		if( reportDevices.size() > decision->target.deviceCount) {
			return false ;
		}

		// 候補発行の全体が整合しない場合は監査表示も適用しない。
		if( !validatePreparationCandidatePublication( report, candidates)) {
			return false ;
		}

		// 発行済みの有限集合を、自己申告sessionでなく当該承認のsessionへ再照合する。
		for( const auto &candidate : report.publishedCandidates) {
			// 旧scanから流用した詳細を新規install authorityへ登録しない。
			if( !isCandidateDetailsValid( candidate, result.scanSessionId)) {
				return false ;
			}
		}
	}

	return true ;
}
} // namespace drivercrate
