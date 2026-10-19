//------------------------------------------------------------------------------
/**
 * @file official_prepared_audit_report.cpp
 * @brief 公式取得後監査の非機密report共通生成処理。
 * @version 01.00.00
 * @date 2026/09/08
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 監査状態と既存候補IDだけを表示用へ変換し、機密値と導入routingを出力しません。入力構造の矛盾は例外で全体拒否し、部分的なreportを返しません。
 */
//------------------------------------------------------------------------------

#include "platform/official_prepared_audit_report.h"

#include "core/candidate_audit.h"

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t MAXIMUM_TARGET_IDENTITY_CHARACTERS = 128U ;	// 取得承認対象IDの文字数上限。
constexpr std::size_t MAXIMUM_IDENTITY_CHARACTERS		 = 256U ;	// Device／候補IDの文字数上限。
constexpr std::size_t MAXIMUM_DEVICES					 = 4'096U ;	// 一reportのdevice行数上限。
constexpr std::size_t MAXIMUM_INF_COUNT					 = 32U ;	// 一配布物の監査INF数上限。
constexpr std::size_t MAXIMUM_PAIRS =
	MAXIMUM_INF_COUNT * MAXIMUM_DEVICES ;	// INFとdeviceの監査組合せ上限。

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_prepared_audit_report.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialPreparationAuditReport makeOfficialPreparedAuditReport(
	const OfficialDriverAuditProfile profile, const ScanSessionId session,
	const std::wstring_view targetIdentity, const std::span<const OfficialCatalogDevice> devices,
	const std::span<const std::wstring> candidateIdentities,
	const OfficialDriverPackageAudit   &audit)
{
	const std::wstring_view providerId =
		// 共通監査policyに固定されたProvider。
		officialDriverAuditProviderId( profile) ;
	// Session、identity、件数と監査結果の対応が不正なら report 全体を拒否する。
	if( providerId.empty() || session == 0U || targetIdentity.empty() ||
	   targetIdentity.size() > MAXIMUM_TARGET_IDENTITY_CHARACTERS || devices.empty() ||
	   devices.size() > MAXIMUM_DEVICES || candidateIdentities.size() != devices.size() ||
	   (audit.scanSessionId != 0U && audit.scanSessionId != session) ||
	   audit.summary.infCount > MAXIMUM_INF_COUNT ||
	   audit.summary.auditedInfCount > audit.summary.infCount ||
	   audit.summary.rejectedInfCount > audit.summary.infCount - audit.summary.auditedInfCount ||
	   audit.auditedPackages.size() != audit.summary.auditedInfCount ||
	   audit.applicability.examinedPairCount > MAXIMUM_PAIRS ||
	   audit.applicability.applicablePairCount > audit.applicability.examinedPairCount ||
	   audit.applicability.failedPairCount >
		   audit.applicability.examinedPairCount - audit.applicability.applicablePairCount ||
	   audit.applicability.rejectedPairCount > audit.applicability.examinedPairCount -
												   audit.applicability.applicablePairCount -
												   audit.applicability.failedPairCount ||
	   audit.rankApprovedTargets.size() != audit.applicability.applicablePairCount) {
		throw std::logic_error( "invalid official prepared audit report") ;
	}

	// 保持閉包を固定profileへ拘束し、別Providerの監査結果を表示へ転用しない。
	for( const OfficialAuditedInfPackage &package :
		audit.auditedPackages)	// 現在profileを照合する監査済み閉包。
	{
		// 監査 package の profile が要求と異なる結果を混在させない。
		if( package.profile != profile) {
			throw std::logic_error( "official prepared audit profile mismatch") ;
		}
	}

	std::unordered_set<std::wstring_view> knownDevices ;	// 一意な検索device ID集合。
	std::unordered_set<std::wstring_view> knownCandidates ;	// 一意な既存候補ID集合。
	knownDevices.reserve( devices.size()) ;
	knownCandidates.reserve( candidateIdentities.size()) ;
	// Report行と合格組合せを同じ検索snapshotへ拘束するため、全対応を先に検証する。
	for( std::size_t index = 0U; index < devices.size(); ++index)	// 現在の対応行index。
	{
		const OfficialCatalogDevice &device = devices[index] ;	// 現在の候補対応device。
		const std::wstring			&candidateIdentity =
			candidateIdentities[index] ;	// 同じindexの表示済みopaque候補ID。
		// 空・長すぎる identity と device・候補の重複を表示用対応表へ受理しない。
		if( device.deviceIdentity.empty() ||
		   device.deviceIdentity.size() > MAXIMUM_IDENTITY_CHARACTERS ||
		   candidateIdentity.empty() || candidateIdentity.size() > MAXIMUM_IDENTITY_CHARACTERS ||
		   !knownDevices.insert( device.deviceIdentity).second ||
		   !knownCandidates.insert( candidateIdentity).second) {
			throw std::logic_error( "invalid official prepared audit binding") ;
		}
	}

	OfficialPreparationAuditReport report ;	// 機密値と導入routingを持たない表示用所有値。
	report.targetIdentity		 = targetIdentity ;
	report.providerId			 = providerId ;
	report.contentError			 = audit.summary.error ;
	report.firstContentRejection = audit.summary.firstRejectionError ;
	report.applicabilityError	 = audit.applicability.error ;
	report.firstPairError		 = audit.applicability.firstPairError ;
	report.infCount				 = static_cast<std::uint32_t>( audit.summary.infCount) ;
	report.acceptedInfCount		 = static_cast<std::uint32_t>( audit.summary.auditedInfCount) ;
	report.examinedPairCount = static_cast<std::uint32_t>( audit.applicability.examinedPairCount) ;
	report.applicablePairCount =
		static_cast<std::uint32_t>( audit.applicability.applicablePairCount) ;
	report.failedPairCount = static_cast<std::uint32_t>( audit.applicability.failedPairCount) ;
	// 内容監査の状態を UI の gate 状態へ変換し、拒否と失敗を区別する。
	switch( audit.summary.state) {
		// 未実施の内容監査は、reportの未評価状態を維持する。
		case OfficialDriverPackageAuditState::NOT_STARTED:
			break ;

		// 内容監査を通過した事実だけを、内容gateの合格へ反映する。
		case OfficialDriverPackageAuditState::AUDITED:
			report.content = CandidateAuditGateState::PASSED ;
			break ;

		// 対応するINFがないpackageは、内容gateの拒否へ合流する。
		case OfficialDriverPackageAuditState::NO_SUPPORTED_INF:
		// 内容境界での不適合は、処理失敗と区別して拒否へ反映する。
		case OfficialDriverPackageAuditState::REJECTED:
			report.content = CandidateAuditGateState::REJECTED ;
			break ;

		// 内容監査の実行失敗は、拒否ではなく失敗として残す。
		case OfficialDriverPackageAuditState::FAILURE:
			report.content = CandidateAuditGateState::FAILURE ;
			break ;

		// 定義外の内容状態を含むreportは、全体を拒否する。
		default:
			throw std::logic_error( "unknown official content audit state") ;
	}

	// 適用性監査の状態を gate 状態へ変換し、未判定と非適用を区別する。
	switch( audit.applicability.state) {
		// 未実施の適用性評価から、合否を推測しない。
		case OfficialDriverApplicabilityState::NOT_STARTED:
			break ;

		// 適用対象が確認できた事実を、適用性gateの合格へ反映する。
		case OfficialDriverApplicabilityState::APPLICABLE_TARGETS:
			report.applicability = CandidateAuditGateState::PASSED ;
			break ;

		// 適用対象なしは、評価失敗の有無で拒否と失敗を区別する。
		case OfficialDriverApplicabilityState::NO_APPLICABLE_TARGETS:
			report.applicability = report.failedPairCount == 0U ? CandidateAuditGateState::REJECTED
																: CandidateAuditGateState::FAILURE ;
			break ;

		// 適用性の不適合を、内容gateと独立した拒否として記録する。
		case OfficialDriverApplicabilityState::REJECTED:
			report.applicability = CandidateAuditGateState::REJECTED ;
			break ;

		// 適用性評価の実行失敗を、候補なしへ読み替えない。
		case OfficialDriverApplicabilityState::FAILURE:
			report.applicability = CandidateAuditGateState::FAILURE ;
			break ;

		// 定義外の適用性状態を含むreportは、全体を拒否する。
		default:
			throw std::logic_error( "unknown official applicability audit state") ;
	}

	std::unordered_set<std::wstring_view> approvedDevices ;	// 合格組合せがある既知device ID集合。
	approvedDevices.reserve( audit.rankApprovedTargets.size()) ;
	// 合格組合せを保持INFと今回のdevice集合へ拘束し、別scanや不合格rankを拒否する。
	for( const OfficialRankApprovedInfTarget &target :
		audit.rankApprovedTargets)	// 現在検証する監査合格組合せ。
	{
		// 未知 package、rank 不合格、未知 device の承認結果は report へ渡さない。
		if( target.auditedPackageIndex >= audit.auditedPackages.size() ||
		   target.rankAudit.decision != OfficialDriverRankDecision::APPLICABLE ||
		   !knownDevices.contains( target.deviceIdentity)) {
			throw std::logic_error( "invalid official approved audit target") ;
		}

		approvedDevices.insert( target.deviceIdentity) ;
	}

	report.candidates.reserve( devices.size()) ;
	// 検索時のIDを変更せず、既存候補行の監査fieldだけを入力順に生成する。
	for( std::size_t index = 0U; index < devices.size(); ++index)	// 現在の表示行index。
	{
		const OfficialCatalogDevice		 &device = devices[index] ;	// 現在reportへ反映するdevice。
		OfficialPreparationCandidateAudit row ;						// 導入不可を維持する一つの監査表示行。
		row.identity				 = candidateIdentities[index] ;
		row.audit					 = makeOfficialDiscoveryCandidateAudit() ;
		row.audit.inspectionDownload = CandidateAuditGateState::PASSED ;
		row.audit.contentIntegrity	 = report.content ;
		// 内容監査を通過した場合だけ device ごとの適用性 gate を反映する。
		if( report.content == CandidateAuditGateState::PASSED) {
			// 承認済み集合に存在する device だけを適用性合格とする。
			if( approvedDevices.erase( device.deviceIdentity) != 0U) {
				row.audit.systemApplicability = CandidateAuditGateState::PASSED ;
			}
			// 適用性の監査が未完了なら個別行も未判定のまま保持する。
			else if( report.applicability == CandidateAuditGateState::PENDING) {
				row.audit.systemApplicability = CandidateAuditGateState::PENDING ;
			} else {
				// 個別失敗を特定できない場合は非適用と断定せず、判定不能を表示する。
				row.audit.systemApplicability =
					report.failedPairCount != 0U || report.applicabilityError != 0 ||
							report.applicability == CandidateAuditGateState::FAILURE
						? CandidateAuditGateState::FAILURE
						: CandidateAuditGateState::REJECTED ;
			}
		}

		report.candidates.push_back( std::move( row)) ;
	}

	// 表示対象へ対応しない承認済み device が残る矛盾は拒否する。
	if( !approvedDevices.empty()) {
		throw std::logic_error( "unmapped official approved audit target") ;
	}

	return report ;
}

} // namespace drivercrate
