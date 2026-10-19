//------------------------------------------------------------------------------
/**
 * @file candidate_assessment.cpp
 * @brief 候補の詳細検証状態と証拠結合の純粋validator。
 * @version 01.03.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  候補の有限な詳細検証契約を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  検査で判明した構成役割と未収集を分離。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * </pre>
 *
 * @note 値は同じscanの証拠に結合し、未確認を合格へ補完しない。OS・networkへ作用しない。
 * @see docs/adr/0150-device-observation-and-candidate-assessment-contract.md
 */
//------------------------------------------------------------------------------

#include "core/candidate_assessment.h"

#include <array>
#include <utility>

namespace drivercrate {
namespace {

/**
 * @brief 連続した有限enumの定義範囲を確認する。
 * @tparam Enum 0から始まる契約enum。
 * @param[in] value 検証する値。
 * @param[in] last 最後の定義値。
 * @return 未知値や負値でなければtrue。
 */
template <typename Enum> bool isKnown( const Enum value, const Enum last) noexcept
{
	return static_cast<unsigned>( value) <= static_cast<unsigned>( last) ;
}

/**
 * @brief 条件の出典に使える実検査の種類を確認する。
 * @param[in] kind 証拠種別。
 * @return 公式recordまたはpackage検査の場合true。
 */
bool isRequirementEvidence( const CandidateEvidenceKind kind) noexcept
{
	return kind == CandidateEvidenceKind::OFFICIAL_RECORD ||
		   kind == CandidateEvidenceKind::PACKAGE_INSPECTION ;
}

/**
 * @brief 当該軸の合格根拠に適切な種類だけを認める。
 * @param[in] axis 検証した軸。
 * @param[in] kind 証拠種別。
 * @return 利用者入力や別の検査を合格根拠へ転用していなければtrue。
 */
bool isValidationEvidence( const CandidateAssessmentAxis axis,
						  const CandidateEvidenceKind	kind) noexcept
{
	// 固定の八軸と必要な検証主体を対応させる。
	switch( axis) {
		// 公式由来は検証した公式recordを正本とする。
		case CandidateAssessmentAxis::ORIGIN:
			return kind == CandidateEvidenceKind::OFFICIAL_RECORD ||
				   kind == CandidateEvidenceKind::COLLECTOR_ATTESTATION ;
		// 取得物の実検査で参照閉包を確認する。
		case CandidateAssessmentAxis::ACQUISITION:
		// Driver-onlyも実際に扱う内容を確認する。
		case CandidateAssessmentAxis::DRIVER_ONLY:
			return kind == CandidateEvidenceKind::PACKAGE_INSPECTION ;
		// 署名合格はWindows policyの結果を必要とする。
		case CandidateAssessmentAxis::SIGNATURE:
		// 基礎適合を表示名から推測しない。
		case CandidateAssessmentAxis::APPLICABILITY:
		// 順位はWindowsの結果を別軸として扱う。
		case CandidateAssessmentAxis::WINDOWS_SELECTION:
			return kind == CandidateEvidenceKind::WINDOWS_API ;
		// 明示条件の出典はrecordまたは検査した内容に限る。
		case CandidateAssessmentAxis::REQUIREMENTS:
			return isRequirementEvidence( kind) ;
		// Executor実装の事実を明示する。
		case CandidateAssessmentAxis::METHOD:
			return kind == CandidateEvidenceKind::IMPLEMENTATION_POLICY ;
	}

	return false ;
}

/**
 * @brief 固定八軸を所有snapshotから借用する。
 * @param[in] assessment 本関数と利用側の走査中に生存するsnapshot。
 * @return 軸とそのfindingの固定長対応。
 */
auto findings( const CandidateAssessment &assessment) noexcept
{
	return std::array<std::pair<CandidateAssessmentAxis, const CandidateAssessmentFinding *>, 8>{{
		{CandidateAssessmentAxis::ORIGIN, &assessment.origin},
		{CandidateAssessmentAxis::ACQUISITION, &assessment.acquisition},
		{CandidateAssessmentAxis::SIGNATURE, &assessment.signature},
		{CandidateAssessmentAxis::APPLICABILITY, &assessment.applicability},
		{CandidateAssessmentAxis::WINDOWS_SELECTION, &assessment.windowsSelection},
		{CandidateAssessmentAxis::DRIVER_ONLY, &assessment.driverOnly},
		{CandidateAssessmentAxis::REQUIREMENTS, &assessment.requirements},
		{CandidateAssessmentAxis::METHOD, &assessment.method},
	}} ;
}

/**
 * @brief 既存候補と同じ有限identity条件を確認する。
 * @param[in] value 本呼出し中だけ借用するidentity。
 * @param[in] allowEmpty Package未取得の場合だけ空を許す。
 * @return 上限内でNULを含まず空の許可と矛盾しなければtrue。
 */
bool isIdentity( const std::wstring_view value, const bool allowEmpty = false) noexcept
{
	return (allowEmpty || !value.empty()) && value.size() <= 256U &&
		   value.find( L'\0') == std::wstring_view::npos ;
}

/**
 * @brief 全明示条件と主理由を照合する。
 * @param[in] assessment 最大16条件のsnapshot。
 * @return 重複・未知値・必須条件不足の隠蔽がなければtrue。
 */
bool areRequirementsValid( const CandidateAssessment &assessment) noexcept
{
	// 過大な条件集合は候補登録前に拒否する。
	if( assessment.explicitRequirements.size() > 16U) {
		return false ;
	}

	bool hasRequired{} ;	// 任意条件を必須条件の分母へ加算しない。
	bool hasUnsatisfied{} ;	// 確認済みの不足を不明より優先する。
	bool hasUnverified{} ;	// 必要値の欠損は不足と区別する。
	// 最大16件だけを検証し、同じ条件を重複計上しない。
	for( std::size_t index = 0U; index < assessment.explicitRequirements.size(); ++index) {
		const auto &requirement = assessment.explicitRequirements[index] ;	// 当該scopeだけの借用。
		// 個別条件に条件なしや未確認出典を設定させない。
		if( requirement.requirementId == 0U || requirement.evidenceId == 0U ||
		   !isRequirementEvidence( requirement.evidenceKind) ||
		   !isKnown( requirement.role, CandidateComponentRole::FIRMWARE_STATE) ||
		   !isKnown( requirement.state, CandidateRequirementState::UNVERIFIED) ||
		   requirement.state == CandidateRequirementState::NO_EXPLICIT_REQUIREMENT) {
			return false ;
		}

		// 先行する最大15件との重複だけを確認する。
		for( std::size_t previous = 0U; previous < index; ++previous) {
			// 同じ条件の矛盾する二重記録を拒否する。
			if( assessment.explicitRequirements[previous].requirementId ==
			   requirement.requirementId) {
				return false ;
			}
		}

		hasRequired = hasRequired || requirement.required ;
		hasUnsatisfied =
			hasUnsatisfied ||
			(requirement.required && requirement.state == CandidateRequirementState::UNSATISFIED) ;
		hasUnverified =
			hasUnverified ||
			(requirement.required && requirement.state == CandidateRequirementState::UNVERIFIED) ;
	}

	const auto reason = assessment.requirements.reason ;	// 固定一件の要約理由。
	// 実際の不足条件がある場合は合格や未確認へ丸めない。
	if( hasUnsatisfied) {
		return reason == CandidateAssessmentReason::REQUIREMENT_UNSATISFIED ;
	}

	// 不足の確証はなく必要値が未知の場合、その候補だけを未確認へ残す。
	if( hasUnverified) {
		return reason == CandidateAssessmentReason::REQUIREMENT_UNVERIFIED ;
	}

	// 実際の全必須条件を確認した場合だけ充足の合格とする。
	if( hasRequired) {
		return reason == CandidateAssessmentReason::VALIDATED ;
	}

	// 任意条件だけで保留を作らず、条件なしは検査範囲を持つ主理由で明示する。
	if( !assessment.explicitRequirements.empty()) {
		return reason == CandidateAssessmentReason::NO_EXPLICIT_REQUIREMENT ;
	}

	return reason != CandidateAssessmentReason::VALIDATED &&
		   reason != CandidateAssessmentReason::REQUIREMENT_UNSATISFIED &&
		   reason != CandidateAssessmentReason::REQUIREMENT_UNVERIFIED ;
}
} // namespace

/** @see src/core/candidate_assessment.h */
bool isCandidateAssessmentFindingValid( const CandidateAssessmentAxis	 axis,
									   const CandidateAssessmentFinding &finding) noexcept
{
	// 未知enumと証拠連番の矛盾を、表示や導入判定へ渡さない。
	if( !isKnown( axis, CandidateAssessmentAxis::METHOD) ||
	   !isKnown( finding.state, CandidateAssessmentState::MANAGED_BY_WINDOWS) ||
	   !isKnown( finding.reason, CandidateAssessmentReason::INSTALLER_SCOPE_ATTESTED) ||
	   !isKnown( finding.evidenceKind, CandidateEvidenceKind::COLLECTOR_ATTESTATION) ||
	   ((finding.evidenceKind == CandidateEvidenceKind::NONE) != (finding.evidenceId == 0U))) {
		return false ;
	}

	// 元診断は実失敗または拒否だけに結合し、成功のstale errorを認めない。
	if( finding.diagnostic &&
	   ((finding.state != CandidateAssessmentState::FAILED &&
		 finding.state != CandidateAssessmentState::REJECTED) ||
		!isDevicePropertyReadStatusValid( {DevicePropertyReadState::FAILED, *finding.diagnostic}))) {
		return false ;
	}

	const auto state = finding.state ;			// 分岐中に変更しない検証状態。
	const auto kind	 = finding.evidenceKind ;	// worker内の証拠種類。
	// 有限な理由ごとに軸・成否・検査主体を固定する。
	switch( finding.reason) {
		// Binary挙動の実証ではない収集者申告を専用理由へ分離します。
		case CandidateAssessmentReason::INSTALLER_SCOPE_ATTESTED:
			return axis == CandidateAssessmentAxis::DRIVER_ONLY &&
				   state == CandidateAssessmentState::PASSED &&
				   kind == CandidateEvidenceKind::COLLECTOR_ATTESTATION && finding.evidenceId != 0U ;
		// 公式installer固有の非該当を標準INFの順位合格へ変更しません。
		case CandidateAssessmentReason::INSTALLER_HANDOFF_SELECTION:
			return axis == CandidateAssessmentAxis::WINDOWS_SELECTION &&
				   state == CandidateAssessmentState::NOT_APPLICABLE &&
				   kind == CandidateEvidenceKind::IMPLEMENTATION_POLICY && finding.evidenceId != 0U ;
		// 未実施では証拠や診断を捏造しない。
		case CandidateAssessmentReason::NOT_EXAMINED:
			return state == CandidateAssessmentState::NOT_CHECKED &&
				   kind == CandidateEvidenceKind::NONE ;
		// 軸に対応する実検査だけを合格とする。
		case CandidateAssessmentReason::VALIDATED:
			return state == CandidateAssessmentState::PASSED && isValidationEvidence( axis, kind) ;
		// Windows管理を独自合格へ読み替えない。
		case CandidateAssessmentReason::WINDOWS_MANAGED:
			return state == CandidateAssessmentState::MANAGED_BY_WINDOWS &&
				   kind == CandidateEvidenceKind::WINDOWS_API ;
		// API失敗は元codeを必須にし、不適合と区別する。
		case CandidateAssessmentReason::API_FAILURE:
			return state == CandidateAssessmentState::FAILED && finding.diagnostic &&
				   (kind == CandidateEvidenceKind::WINDOWS_API || isRequirementEvidence( kind)) ;
		// Parserや方式の未対応は不適合の証明ではない。
		case CandidateAssessmentReason::FORMAT_UNSUPPORTED:
			return state == CandidateAssessmentState::UNSUPPORTED &&
				   (kind == CandidateEvidenceKind::PACKAGE_INSPECTION ||
					kind == CandidateEvidenceKind::IMPLEMENTATION_POLICY) ;
		// 公式性が未確認の場合は起点軸の未確認とする。
		case CandidateAssessmentReason::ORIGIN_UNVERIFIED:
		// 委譲未確認も取得済みや公式合格へ昇格しない。
		case CandidateAssessmentReason::DELEGATION_UNVERIFIED:
			return axis == CandidateAssessmentAxis::ORIGIN &&
				   state == CandidateAssessmentState::NOT_CHECKED &&
				   (kind == CandidateEvidenceKind::NONE ||
					kind == CandidateEvidenceKind::OFFICIAL_RECORD) ;
		// 持込みfileは内容合格でも公式由来の証明にはならない。
		case CandidateAssessmentReason::USER_PROVIDED:
			return axis == CandidateAssessmentAxis::ORIGIN &&
				   state == CandidateAssessmentState::NOT_APPLICABLE &&
				   kind == CandidateEvidenceKind::USER_INPUT ;
		// 起点の具体的な拒否を別軸へ流用しない。
		case CandidateAssessmentReason::ORIGIN_REJECTED:
			return axis == CandidateAssessmentAxis::ORIGIN &&
				   state == CandidateAssessmentState::REJECTED &&
				   kind == CandidateEvidenceKind::OFFICIAL_RECORD ;
		// 未取得は内容の不適合ではない。
		case CandidateAssessmentReason::NOT_ACQUIRED:
			return axis == CandidateAssessmentAxis::ACQUISITION &&
				   state == CandidateAssessmentState::NOT_CHECKED &&
				   (kind == CandidateEvidenceKind::NONE ||
					kind == CandidateEvidenceKind::OFFICIAL_RECORD) ;
		// 実際の参照欠落を取得閉包の拒否として示す。
		case CandidateAssessmentReason::REFERENCED_FILE_MISSING:
		// Hashの不一致を形式未対応へ落として回避させない。
		case CandidateAssessmentReason::HASH_MISMATCH:
			return axis == CandidateAssessmentAxis::ACQUISITION &&
				   state == CandidateAssessmentState::REJECTED &&
				   kind == CandidateEvidenceKind::PACKAGE_INSPECTION ;
		// 無効署名はWindows policyの実判定を必要とする。
		case CandidateAssessmentReason::SIGNATURE_INVALID:
			return axis == CandidateAssessmentAxis::SIGNATURE &&
				   state == CandidateAssessmentState::REJECTED &&
				   kind == CandidateEvidenceKind::WINDOWS_API ;
		// 必要publisherの未確認は無効署名とは異なる。
		case CandidateAssessmentReason::PUBLISHER_UNVERIFIED:
			return axis == CandidateAssessmentAxis::SIGNATURE &&
				   state == CandidateAssessmentState::NOT_CHECKED &&
				   (kind == CandidateEvidenceKind::WINDOWS_API ||
					kind == CandidateEvidenceKind::PACKAGE_INSPECTION) ;
		// 実PnP照合で確認した不一致を保持する。
		case CandidateAssessmentReason::PNP_MISMATCH:
		// OSの不一致は名前や現在版欠損と区別する。
		case CandidateAssessmentReason::OS_MISMATCH:
		// x64照合の不一致だけを当該理由で拒否する。
		case CandidateAssessmentReason::ARCHITECTURE_MISMATCH:
			return axis == CandidateAssessmentAxis::APPLICABILITY &&
				   state == CandidateAssessmentState::REJECTED &&
				   kind == CandidateEvidenceKind::WINDOWS_API ;
		// 現在順位未確認は基礎適合の不一致ではない。
		case CandidateAssessmentReason::RANK_UNVERIFIED:
			return axis == CandidateAssessmentAxis::WINDOWS_SELECTION &&
				   state == CandidateAssessmentState::NOT_CHECKED &&
				   (kind == CandidateEvidenceKind::NONE ||
					kind == CandidateEvidenceKind::WINDOWS_API) ;
		// 旧policyでの保留をWindowsの不適合と表示しない。
		case CandidateAssessmentReason::LEGACY_POLICY_HOLD:
			return axis == CandidateAssessmentAxis::WINDOWS_SELECTION &&
				   state == CandidateAssessmentState::NOT_CHECKED &&
				   kind == CandidateEvidenceKind::IMPLEMENTATION_POLICY ;
		// 変更なしを独自の新しい通常更新へ変換しない。
		case CandidateAssessmentReason::NO_CHANGE:
		// 非推奨でも適合済み候補の明示選択とは分離する。
		case CandidateAssessmentReason::NOT_RECOMMENDED:
			return axis == CandidateAssessmentAxis::WINDOWS_SELECTION &&
				   state == CandidateAssessmentState::PASSED &&
				   kind == CandidateEvidenceKind::WINDOWS_API ;
		// Firmwareそのものはdriver導入対象ではない。
		case CandidateAssessmentReason::FIRMWARE_PAYLOAD:
		// 選択部分と分離不能な更新だけを混在として拒否する。
		case CandidateAssessmentReason::INSEPARABLE_FIRMWARE_UPDATE:
			return axis == CandidateAssessmentAxis::DRIVER_ONLY &&
				   state == CandidateAssessmentState::REJECTED &&
				   kind == CandidateEvidenceKind::PACKAGE_INSPECTION ;
		// 調べていない状態を条件なしへ補完しない。
		case CandidateAssessmentReason::NO_EXPLICIT_REQUIREMENT:
			return axis == CandidateAssessmentAxis::REQUIREMENTS &&
				   state == CandidateAssessmentState::NOT_APPLICABLE && isRequirementEvidence( kind) ;
		// 実際の明示必須条件不足だけを拒否理由にする。
		case CandidateAssessmentReason::REQUIREMENT_UNSATISFIED:
			return axis == CandidateAssessmentAxis::REQUIREMENTS &&
				   state == CandidateAssessmentState::REJECTED && isRequirementEvidence( kind) ;
		// 必要値未知を不足と断定しない。
		case CandidateAssessmentReason::REQUIREMENT_UNVERIFIED:
			return axis == CandidateAssessmentAxis::REQUIREMENTS &&
				   state == CandidateAssessmentState::NOT_CHECKED && isRequirementEvidence( kind) ;
		// 方式の未実装は基礎適合の不一致ではない。
		case CandidateAssessmentReason::EXECUTOR_UNAVAILABLE:
			return axis == CandidateAssessmentAxis::METHOD &&
				   state == CandidateAssessmentState::UNSUPPORTED &&
				   kind == CandidateEvidenceKind::IMPLEMENTATION_POLICY ;
		// 実行範囲の未確認は自動起動を許可しない。
		case CandidateAssessmentReason::EXECUTION_SCOPE_UNVERIFIED:
			return axis == CandidateAssessmentAxis::METHOD &&
				   state == CandidateAssessmentState::NOT_CHECKED &&
				   (kind == CandidateEvidenceKind::IMPLEMENTATION_POLICY ||
					kind == CandidateEvidenceKind::OFFICIAL_RECORD) ;
	}

	return false ;
}

/** @see src/core/candidate_assessment.h */
bool isCandidateAssessmentValid( const CandidateAssessment &assessment) noexcept
{
	// 結合不能なsnapshotと未知方式を拒否する。
	if( assessment.scanSessionId == 0U || !isIdentity( assessment.candidateIdentity) ||
	   !isIdentity( assessment.deviceIdentity) || !isIdentity( assessment.packageIdentity, true) ||
	   !isKnown( assessment.installMethod, CandidateInstallMethod::MANUAL) ||
	   (assessment.componentRole &&
		!isKnown( *assessment.componentRole, CandidateComponentRole::FIRMWARE_STATE))) {
		return false ;
	}

	// 八つの固定軸を一度ずつ確認する。
	for( const auto &[axis, finding] : findings( assessment)) {
		// 一軸でも理由や証拠が矛盾していればsnapshotを登録しない。
		if( !isCandidateAssessmentFindingValid( axis, *finding)) {
			return false ;
		}
	}

	// Executorの存在を主理由と一致させ、新方式の実装を先取りしない。
	if( assessment.executorAvailable) {
		// 03で実行可能なのは既存のWindows管理または標準INFの経路だけである。
		if( (assessment.installMethod != CandidateInstallMethod::WINDOWS_MANAGED &&
			assessment.installMethod != CandidateInstallMethod::STANDARD_INF &&
			assessment.installMethod != CandidateInstallMethod::OFFICIAL_INSTALLER) ||
		   (assessment.method.state != CandidateAssessmentState::PASSED &&
			assessment.method.state != CandidateAssessmentState::MANAGED_BY_WINDOWS)) {
			return false ;
		}
	} else {
		// 実行経路がない方式で方式の合格を表示しない。
		if( assessment.method.state == CandidateAssessmentState::PASSED ||
		   assessment.method.state == CandidateAssessmentState::MANAGED_BY_WINDOWS ||
		   assessment.method.state == CandidateAssessmentState::NOT_APPLICABLE) {
			return false ;
		}
	}

	// Installer固有の非該当を他方式のrank検査の省略へ流用しません。
	if( (assessment.windowsSelection.reason ==
		CandidateAssessmentReason::INSTALLER_HANDOFF_SELECTION) !=
	   (assessment.installMethod == CandidateInstallMethod::OFFICIAL_INSTALLER &&
		assessment.executorAvailable)) {
		return false ;
	}

	// Installer専用の作用範囲申告を標準INFの実内容検査へ転用しません。
	if( (assessment.driverOnly.reason == CandidateAssessmentReason::INSTALLER_SCOPE_ATTESTED) !=
	   (assessment.installMethod == CandidateInstallMethod::OFFICIAL_INSTALLER &&
		assessment.executorAvailable)) {
		return false ;
	}

	return areRequirementsValid( assessment) ;
}

/** @see src/core/candidate_assessment.h */
bool isCandidateAssessmentBound( const CandidateAssessment &assessment,
								const std::uint64_t		   scanSessionId,
								const std::wstring_view	   candidateIdentity,
								const std::wstring_view	   deviceIdentity,
								const std::wstring_view	   packageIdentity) noexcept
{
	return isCandidateAssessmentValid( assessment) && assessment.scanSessionId == scanSessionId &&
		   assessment.candidateIdentity == candidateIdentity &&
		   assessment.deviceIdentity == deviceIdentity &&
		   assessment.packageIdentity == packageIdentity ;
}

/** @see src/core/candidate_assessment.h */
bool isCandidateAssessmentReady( const CandidateAssessment &assessment) noexcept
{
	// 全内部条件と既存executorの存在を確認する。
	if( !isCandidateAssessmentValid( assessment) || !assessment.executorAvailable) {
		return false ;
	}

	// 一つの未確認・拒否・失敗・未対応も必要条件の合格へ補完しない。
	for( const auto &[axis, finding] : findings( assessment)) {
		// 各軸は合格、OS管理、検証済みの非該当だけを許す。
		if( finding->state != CandidateAssessmentState::PASSED &&
		   finding->state != CandidateAssessmentState::MANAGED_BY_WINDOWS &&
		   finding->state != CandidateAssessmentState::NOT_APPLICABLE) {
			return false ;
		}

		// 持込み由来の非該当と条件なし以外は導入準備の非該当としない。
		if( finding->state == CandidateAssessmentState::NOT_APPLICABLE &&
		   axis != CandidateAssessmentAxis::ORIGIN &&
		   axis != CandidateAssessmentAxis::REQUIREMENTS &&
		   !(axis == CandidateAssessmentAxis::WINDOWS_SELECTION &&
			 assessment.installMethod == CandidateInstallMethod::OFFICIAL_INSTALLER &&
			 finding->reason == CandidateAssessmentReason::INSTALLER_HANDOFF_SELECTION)) {
			return false ;
		}
	}

	return true ;
}

} // namespace drivercrate
