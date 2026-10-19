//------------------------------------------------------------------------------
/**
 * @file candidate_audit.cpp
 * @brief Driver候補監査状態の生成と整合性検証。
 * @version 01.05.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  拒否状態の経路別順序検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  操作分類と選択可否の矛盾拒否追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式全監査合格状態追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Release観測差分の定義外値拒否追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  詳細assessmentと代表行の整合性検証を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  共通local内容・適合合格と未接続方式の分離を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.04.00 Shunji Ogawa  2026/10/12  私有native bindingの署名索引初回だけREADYへ受理。
 * Ver.01.05.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * </pre>
 *
 * @note 監査状態からURL、端末識別子、local pathを推測せず、Providerが明示した取得経路とinstall可否の関係だけを決定的に検証します。
 */
//------------------------------------------------------------------------------

#include "core/candidate_audit.h"
#include "core/provider_registry.h"

#include <optional>
#include <unordered_set>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
/**
 * @brief Cast等で混入した定義外値をscan session登録前に拒否する。
 *
 * @param[in] state Providerが設定した監査gate状態。
 * @return 定義済みenum値の場合は`true`。
 */
//------------------------------------------------------------------------------
bool isKnownGateState( const CandidateAuditGateState state) noexcept
{
	// 定義済みの監査状態だけを列挙し、未知の値を正規状態として扱わない。
	switch( state) {
		// 対象外 gate は定義済み状態として共通受理へ進む。
		case CandidateAuditGateState::NOT_APPLICABLE:
		// 未判定 gate は定義済み状態として共通受理へ進む。
		case CandidateAuditGateState::PENDING:
		// 合格 gate は定義済み状態として共通受理へ進む。
		case CandidateAuditGateState::PASSED:
		// Windows 管理 gate は定義済み状態として共通受理へ進む。
		case CandidateAuditGateState::MANAGED_BY_WINDOWS:
		// Provider 検証 gate は定義済み状態として共通受理へ進む。
		case CandidateAuditGateState::PROVIDER_VALIDATED:
		// 利用者提供の未検証 gate は定義済み状態として共通受理へ進む。
		case CandidateAuditGateState::USER_PROVIDED_UNVERIFIED:
		// 拒否 gate は定義済み状態として共通受理へ進む。
		case CandidateAuditGateState::REJECTED:
		// 実行失敗を含む既知 gate の値を形式上有効と認める。
		case CandidateAuditGateState::FAILURE:
			return true ;
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 定義外状態を選択可能候補へ昇格させずfail-closedで扱う。
 *
 * @param[in] readiness Providerが設定したinstall準備状態。
 * @return 定義済みenum値の場合は`true`。
 */
//------------------------------------------------------------------------------
bool isKnownInstallReadiness( const CandidateInstallReadiness readiness) noexcept
{
	// 表示専用から導入可能までの既知状態だけを受理し、暗黙の昇格を防ぐ。
	switch( readiness) {
		// 表示専用は既知の準備状態として共通受理へ進む。
		case CandidateInstallReadiness::DISPLAY_ONLY:
		// 監査待ちは既知の準備状態として共通受理へ進む。
		case CandidateInstallReadiness::AUDIT_PENDING:
		// 準備完了は既知の準備状態として共通受理へ進む。
		case CandidateInstallReadiness::READY:
		// 導入不可を含む既知の準備状態を形式上有効と認める。
		case CandidateInstallReadiness::BLOCKED:
			return true ;
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief Driver操作分類が定義済みか確認する。
 *
 * Cast等で混入した未知操作をinstall routingへ渡さない。
 *
 * @param[in] action Candidateが提示した操作分類。
 * @return 定義済みの操作分類の場合は`true`。
 */
//------------------------------------------------------------------------------
bool isKnownDriverAction( const DriverAction action) noexcept
{
	// 操作の意味が確定する列挙値だけを受理し、未知操作を導入へ渡さない。
	switch( action) {
		// 操作なしは既知の分類として共通受理へ進む。
		case DriverAction::NONE:
		// 通常更新は既知の分類として共通受理へ進む。
		case DriverAction::UPDATE:
		// 再導入は既知の分類として共通受理へ進む。
		case DriverAction::REINSTALL:
		// 旧版への切替を含む既知の操作分類を形式上有効と認める。
		case DriverAction::DOWNGRADE:
		// 初回導入は既知の表示分類であり、実行許可は別検証する。
		case DriverAction::INITIAL_INSTALL:
			return true ;
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 比較失敗を示すInvalidと未知enumをUI表示前に拒否する。
 *
 * @param[in] difference Candidateが持つ任意の前回観測差分。
 * @return 値なし、または有効な差分enum値の場合true。
 */
//------------------------------------------------------------------------------
bool isKnownReleaseObservationDifference(
	const std::optional<ReleaseObservationDifference> &difference) noexcept
{
	// 比較を実施していない候補には、比較結果の妥当性検査を要求しない。
	if( !difference.has_value()) {
		return true ;
	}

	// 比較不能の値と未知の値を除外し、説明可能な観測差分だけを公開する。
	switch( *difference) {
		// 比較失敗を表す無効値は UI の観測差分として受理しない。
		case ReleaseObservationDifference::INVALID:
			return false ;
		// 初回観測は既知の差分として共通受理へ進む。
		case ReleaseObservationDifference::FIRST_OBSERVATION:
		// 取得元変更は既知の差分として共通受理へ進む。
		case ReleaseObservationDifference::SOURCE_BINDING_CHANGED:
		// Device binding 変更は既知の差分として共通受理へ進む。
		case ReleaseObservationDifference::DEVICE_BINDING_CHANGED:
		// OS 変更は既知の差分として共通受理へ進む。
		case ReleaseObservationDifference::OPERATING_SYSTEM_CHANGED:
		// Device 構成変更は既知の差分として共通受理へ進む。
		case ReleaseObservationDifference::DEVICE_CONFIGURATION_CHANGED:
		// Policy 変更は既知の差分として共通受理へ進む。
		case ReleaseObservationDifference::POLICY_CHANGED:
		// Parser 変更は既知の差分として共通受理へ進む。
		case ReleaseObservationDifference::PARSER_CHANGED:
		// 配布変更は既知の差分として共通受理へ進む。
		case ReleaseObservationDifference::RELEASE_CHANGED:
		// 内容識別値変更は既知の差分として共通受理へ進む。
		case ReleaseObservationDifference::CONTENT_IDENTITY_CHANGED:
		// 保留理由変更は既知の差分として共通受理へ進む。
		case ReleaseObservationDifference::PENDING_REASON_CHANGED:
		// Metadata 同一は既知の比較結果として共通受理へ進む。
		case ReleaseObservationDifference::METADATA_UNCHANGED:
		// 内容識別値同一を含む既知の比較結果を表示可能と認める。
		case ReleaseObservationDifference::STRONG_IDENTITY_UNCHANGED:
			return true ;
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief Installを許可できない監査結果を共通判定する。
 *
 * @param[in] state 拒否または失敗か確認する監査gate状態。
 * @return `REJECTED`または`FAILURE`の場合は`true`。
 */
//------------------------------------------------------------------------------
bool isRejectedOrFailed( const CandidateAuditGateState state) noexcept
{
	return state == CandidateAuditGateState::REJECTED || state == CandidateAuditGateState::FAILURE ;
}

//------------------------------------------------------------------------------
/**
 * @brief Providerの自己申告ではなくregistryのbit集合を確認する。
 *
 * @param[in] descriptor 組み込みProvider定義。
 * @param[in] capability 確認する単一capability。
 * @return 指定capabilityが登録されている場合は`true`。
 */
//------------------------------------------------------------------------------
bool hasProviderCapability( const ProviderDescriptor &descriptor,
						   const ProviderCapability	 capability) noexcept
{
	const ProviderCapabilityMask mask =
		// 確認対象bit。
		static_cast<ProviderCapabilityMask>( capability) ;
	return (descriptor.capabilities & mask) != 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 拒否済み表示候補もregistryとの経路不一致を許容しない。
 *
 * @param[in] basis Candidateが明示した探索経路。
 * @param[in] descriptor 組み込みProvider定義。
 * @return 探索経路に必要なcapabilityをProviderが持つ場合は`true`。
 */
//------------------------------------------------------------------------------
bool isDiscoverySupported( const CandidateDiscoveryBasis basis,
						  const ProviderDescriptor	   &descriptor) noexcept
{
	// 候補が主張する探索経路を、その経路を実行できるProvider能力へ照合する。
	switch( basis) {
		// Windows 管理の探索根拠には対応する管理 service 能力を要求する。
		case CandidateDiscoveryBasis::MANAGED_SERVICE:
			return hasProviderCapability( descriptor, ProviderCapability::MANAGED_SERVICE) ;
		// Local 探索根拠には inventory 能力を要求する。
		case CandidateDiscoveryBasis::LOCAL_INVENTORY:
			return hasProviderCapability( descriptor, ProviderCapability::LOCAL_INVENTORY) ;
		// 構造化公式 catalog は公式 network の共通検証へ進む。
		case CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG:
		// 公式 Web 探索には network 能力と明示的な取得元 policy を要求する。
		case CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE:
			return hasProviderCapability( descriptor, ProviderCapability::OFFICIAL_NETWORK) &&
				   !descriptor.officialSourcePolicyId.empty() ;
		// 利用者指定 package の探索根拠には file 指定能力を要求する。
		case CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE:
			return hasProviderCapability( descriptor, ProviderCapability::USER_SELECTED_FILE) ;
		// 収集者確認は公式live探索と異なる索引専用能力へ結合します。
		case CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION:
			return hasProviderCapability( descriptor,
										 ProviderCapability::SIGNED_INDEX_ACQUISITION) &&
				   !hasProviderCapability( descriptor, ProviderCapability::OFFICIAL_NETWORK) ;
		// 未指定の探索根拠は registry 整合性を成立させない。
		case CandidateDiscoveryBasis::UNSPECIFIED:
			return false ;
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 前段失敗後に後段成功を設定する矛盾を拒否する。Metadataだけの確認を監査合格へ昇格せず、`READY`は全gateが`PASSED`の場合だけ許可する。
 *
 * @param[in] audit 公式network候補の監査状態。
 * @return 公式取得経路で許可された監査遷移なら`true`。
 */
//------------------------------------------------------------------------------
bool isOfficialCandidateAuditValid( const CandidateAuditStatus &audit) noexcept
{
	// 取得元で拒否された候補は後続監査を未実施に保ち、導入不可の場合だけ保持する。
	if( audit.sourceOrigin != CandidateAuditGateState::PASSED) {
		return isRejectedOrFailed( audit.sourceOrigin) &&
			   audit.inspectionDownload == CandidateAuditGateState::PENDING &&
			   audit.contentIntegrity == CandidateAuditGateState::PENDING &&
			   audit.systemApplicability == CandidateAuditGateState::PENDING &&
			   audit.installReadiness == CandidateInstallReadiness::BLOCKED ;
	}

	const bool systemPrevalidated =
		audit.systemApplicability == CandidateAuditGateState::PENDING ||
		audit.systemApplicability ==
			CandidateAuditGateState::PROVIDER_VALIDATED ;	// 後段監査前に許可する状態。
	// 取得が未完了または拒否済みなら、内容未検査と導入不可の状態を保つ場合だけ受理する。
	if( audit.inspectionDownload == CandidateAuditGateState::PENDING ||
	   isRejectedOrFailed( audit.inspectionDownload)) {
		return audit.contentIntegrity == CandidateAuditGateState::PENDING && systemPrevalidated &&
			   audit.installReadiness == CandidateInstallReadiness::BLOCKED ;
	}

	// 検査用取得の成功が確定していない状態から内容監査の合格を主張させない。
	if( audit.inspectionDownload != CandidateAuditGateState::PASSED) {
		return false ;
	}

	// 内容が未確認または拒否済みの候補は、導入不可の事前照合状態に限定する。
	if( audit.contentIntegrity == CandidateAuditGateState::PENDING ||
	   isRejectedOrFailed( audit.contentIntegrity)) {
		return systemPrevalidated && audit.installReadiness == CandidateInstallReadiness::BLOCKED ;
	}

	// 内容監査に使えない状態を合格と解釈せず、矛盾した監査列を拒否する。
	if( audit.contentIntegrity != CandidateAuditGateState::PASSED) {
		return false ;
	}

	// 実機適用性が未確定または拒否済みなら、内容合格だけで導入可能にしない。
	if( audit.systemApplicability == CandidateAuditGateState::PENDING ||
	   audit.systemApplicability == CandidateAuditGateState::PROVIDER_VALIDATED ||
	   isRejectedOrFailed( audit.systemApplicability)) {
		return audit.installReadiness == CandidateInstallReadiness::BLOCKED ;
	}

	// 実機適用性の合格が確定した候補だけを、最終的な導入可否の判定へ進める。
	if( audit.systemApplicability != CandidateAuditGateState::PASSED) {
		return false ;
	}

	return audit.installReadiness == CandidateInstallReadiness::READY ||
		   audit.installReadiness == CandidateInstallReadiness::BLOCKED ;
}

//------------------------------------------------------------------------------
/**
 * @brief 取得元未証明とdownload非該当を固定し、内容またはsystem拒否後のinstall開始を許可しない。
 *
 * @param[in] audit 利用者指定package候補の監査状態。
 * @return 利用者指定経路で許可された監査遷移なら`true`。
 */
//------------------------------------------------------------------------------
bool isUserSelectedCandidateAuditValid( const CandidateAuditStatus &audit) noexcept
{
	// 利用者指定fileの取得元を公式取得やネットワーク取得済みとして扱わせない。
	if( audit.sourceOrigin != CandidateAuditGateState::USER_PROVIDED_UNVERIFIED ||
	   audit.inspectionDownload != CandidateAuditGateState::NOT_APPLICABLE) {
		return false ;
	}

	// 内容で拒否されたfileは適用性を昇格させず、導入不可の結果だけを残す。
	if( isRejectedOrFailed( audit.contentIntegrity)) {
		// 内容拒否後にsystem適用性を合格へ昇格させていないことを示す。
		const bool systemNotPromoted =
			audit.systemApplicability == CandidateAuditGateState::PENDING ||
			audit.systemApplicability == CandidateAuditGateState::PROVIDER_VALIDATED ;
		return systemNotPromoted && audit.installReadiness == CandidateInstallReadiness::BLOCKED ;
	}

	// 内容を確認できていない利用者指定fileを、後続の導入判定へ通さない。
	if( audit.contentIntegrity != CandidateAuditGateState::PASSED) {
		return false ;
	}

	// 適用性で拒否されたfileは、内容が合格でも導入不可の結果に限定する。
	if( isRejectedOrFailed( audit.systemApplicability)) {
		return audit.installReadiness == CandidateInstallReadiness::BLOCKED ;
	}

	// 共通経路の基礎適合合格は、方式未接続の表示専用状態として保持する。
	if( audit.systemApplicability == CandidateAuditGateState::PASSED) {
		return audit.installReadiness == CandidateInstallReadiness::BLOCKED ;
	}

	return audit.systemApplicability == CandidateAuditGateState::PROVIDER_VALIDATED &&
		   audit.installReadiness == CandidateInstallReadiness::AUDIT_PENDING ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/core/candidate_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
CandidateAuditStatus makeWindowsManagedCandidateAudit( const bool displayOnly) noexcept
{
	CandidateAuditStatus audit ;	// Windows管理経路として返す監査状態。
	audit.sourceOrigin		  = CandidateAuditGateState::MANAGED_BY_WINDOWS ;
	audit.inspectionDownload  = CandidateAuditGateState::MANAGED_BY_WINDOWS ;
	audit.contentIntegrity	  = CandidateAuditGateState::MANAGED_BY_WINDOWS ;
	audit.systemApplicability = CandidateAuditGateState::MANAGED_BY_WINDOWS ;
	audit.installReadiness =
		displayOnly ? CandidateInstallReadiness::DISPLAY_ONLY : CandidateInstallReadiness::READY ;
	return audit ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/candidate_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
CandidateAuditStatus makeOfficialMetadataCandidateAudit() noexcept
{
	CandidateAuditStatus audit ;	// 公式metadata確認後の候補監査状態。
	audit.sourceOrigin		  = CandidateAuditGateState::PASSED ;
	audit.inspectionDownload  = CandidateAuditGateState::PENDING ;
	audit.contentIntegrity	  = CandidateAuditGateState::PENDING ;
	audit.systemApplicability = CandidateAuditGateState::PROVIDER_VALIDATED ;
	audit.installReadiness	  = CandidateInstallReadiness::BLOCKED ;
	return audit ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/candidate_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
CandidateAuditStatus makeOfficialReadyCandidateAudit() noexcept
{
	CandidateAuditStatus audit ;	// 全公式監査を完了した候補状態。
	audit.sourceOrigin		  = CandidateAuditGateState::PASSED ;
	audit.inspectionDownload  = CandidateAuditGateState::PASSED ;
	audit.contentIntegrity	  = CandidateAuditGateState::PASSED ;
	audit.systemApplicability = CandidateAuditGateState::PASSED ;
	audit.installReadiness	  = CandidateInstallReadiness::READY ;
	return audit ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/candidate_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
CandidateAuditStatus makeOfficialDiscoveryCandidateAudit() noexcept
{
	CandidateAuditStatus audit ;	// 公式page由来だけを確認した候補監査状態。
	audit.sourceOrigin		  = CandidateAuditGateState::PASSED ;
	audit.inspectionDownload  = CandidateAuditGateState::PENDING ;
	audit.contentIntegrity	  = CandidateAuditGateState::PENDING ;
	audit.systemApplicability = CandidateAuditGateState::PENDING ;
	audit.installReadiness	  = CandidateInstallReadiness::BLOCKED ;
	return audit ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/candidate_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
CandidateAuditStatus makeUserSelectedCandidateAudit() noexcept
{
	CandidateAuditStatus audit ;	// 利用者指定packageの候補監査状態。
	audit.sourceOrigin		  = CandidateAuditGateState::USER_PROVIDED_UNVERIFIED ;
	audit.inspectionDownload  = CandidateAuditGateState::NOT_APPLICABLE ;
	audit.contentIntegrity	  = CandidateAuditGateState::PASSED ;
	audit.systemApplicability = CandidateAuditGateState::PROVIDER_VALIDATED ;
	audit.installReadiness	  = CandidateInstallReadiness::AUDIT_PENDING ;
	return audit ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/candidate_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isCandidateAuditValid( const UpdateCandidate	&candidate,
						   const ProviderDescriptor &descriptor) noexcept
{
	const CandidateAuditStatus &audit = candidate.audit ;	// 検証対象の監査状態。
	// 新しい詳細の矛盾を既存の集約監査で隠さない。
	if( !isCandidateDetailsValid( candidate)) {
		return false ;
	}

	// 未知の監査値や探索経路との矛盾を拒否し、表示する保証の範囲を登録定義へ固定する。
	if( !isKnownGateState( audit.sourceOrigin) || !isKnownGateState( audit.inspectionDownload) ||
	   !isKnownGateState( audit.contentIntegrity) || !isKnownGateState( audit.systemApplicability) ||
	   !isKnownInstallReadiness( audit.installReadiness) || !isKnownDriverAction( candidate.action) ||
	   !isKnownReleaseObservationDifference( candidate.releaseObservationDifference) ||
	   (candidate.releaseObservationDifference.has_value() &&
		candidate.discoveryBasis != CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG &&
		candidate.discoveryBasis != CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE) ||
	   candidate.discoveryBasis != descriptor.discoveryBasis ||
	   !isDiscoverySupported( candidate.discoveryBasis, descriptor)) {
		return false ;
	}

	// 現在構成の代表行はdriver存在を保証せず、操作候補とは別の表示制約を確認する。
	if( candidate.current) {
		// 現在構成行を更新推奨や再導入可能とする矛盾、および非localの探索根拠を拒否する。
		if( candidate.installable || candidate.recommended ||
		   candidate.action != DriverAction::NONE ||
		   audit.installReadiness != CandidateInstallReadiness::DISPLAY_ONLY ||
		   candidate.discoveryBasis != CandidateDiscoveryBasis::LOCAL_INVENTORY) {
			return false ;
		}
	}

	// 推奨表示を導入可能な通常更新に限定し、旧版や表示専用候補の暗黙選択を防ぐ。
	if( !candidate.current && candidate.recommended &&
	   (!candidate.installable || candidate.action != DriverAction::UPDATE)) {
		return false ;
	}

	// 実行内容を持たない候補を導入可能として登録しない。
	if( !candidate.current && candidate.installable && candidate.action == DriverAction::NONE) {
		return false ;
	}

	// 導入可否flagと監査段階を一致させ、表示と実行許可が食い違う候補を拒否する。
	if( candidate.installable !=
	   (audit.installReadiness == CandidateInstallReadiness::AUDIT_PENDING ||
		audit.installReadiness == CandidateInstallReadiness::READY)) {
		return false ;
	}

	// 探索経路ごとの信頼境界へ監査結果を照合し、異なるProviderの保証を混在させない。
	switch( candidate.discoveryBasis) {
		// Windows 管理候補は全監査 gate の委譲状態と導入準備状態を照合する。
		case CandidateDiscoveryBasis::MANAGED_SERVICE:
			return hasProviderCapability( descriptor, ProviderCapability::MANAGED_SERVICE) &&
				   audit.sourceOrigin == CandidateAuditGateState::MANAGED_BY_WINDOWS &&
				   audit.inspectionDownload == CandidateAuditGateState::MANAGED_BY_WINDOWS &&
				   audit.contentIntegrity == CandidateAuditGateState::MANAGED_BY_WINDOWS &&
				   audit.systemApplicability == CandidateAuditGateState::MANAGED_BY_WINDOWS &&
				   audit.installReadiness == CandidateInstallReadiness::READY ;
		// Local 候補は Windows 管理 gate と現在版に応じた準備状態を照合する。
		case CandidateDiscoveryBasis::LOCAL_INVENTORY:
			return hasProviderCapability( descriptor, ProviderCapability::LOCAL_INVENTORY) &&
				   audit.sourceOrigin == CandidateAuditGateState::MANAGED_BY_WINDOWS &&
				   audit.inspectionDownload == CandidateAuditGateState::MANAGED_BY_WINDOWS &&
				   audit.contentIntegrity == CandidateAuditGateState::MANAGED_BY_WINDOWS &&
				   audit.systemApplicability == CandidateAuditGateState::MANAGED_BY_WINDOWS &&
				   audit.installReadiness == (candidate.current
												  ? CandidateInstallReadiness::DISPLAY_ONLY
												  : CandidateInstallReadiness::READY) ;
		// 構造化 catalog 候補は公式 network の共通監査へ進む。
		case CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG:
		// 公式 Web 候補は登録能力・取得元 policy・監査組合せの成立を要求する。
		case CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE:
			return hasProviderCapability( descriptor, ProviderCapability::OFFICIAL_NETWORK) &&
				   !descriptor.officialSourcePolicyId.empty() &&
				   isOfficialCandidateAuditValid( audit) ;
		// 利用者指定候補は file 指定能力と専用の監査組合せを照合する。
		case CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE:
			return hasProviderCapability( descriptor, ProviderCapability::USER_SELECTED_FILE) &&
				   (audit.systemApplicability != CandidateAuditGateState::PASSED ||
					(candidate.assessment && candidate.assessment->applicability.state ==
												 CandidateAssessmentState::PASSED)) &&
				   isUserSelectedCandidateAuditValid( audit) ;
		// 収集者確認は独立境界です。内容・Windows適合と本体routeが別途必要です。
		case CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION:
			return hasProviderCapability( descriptor,
										 ProviderCapability::SIGNED_INDEX_ACQUISITION) &&
				   !hasProviderCapability( descriptor, ProviderCapability::OFFICIAL_NETWORK) &&
				   !candidate.recommended &&
				   candidate.defaultPreference == CandidateDefaultPreference::NONE &&
				   audit.sourceOrigin == CandidateAuditGateState::PASSED &&
				   (!candidate.installable ||
					(candidate.assessment &&
					 candidate.assessment->origin.evidenceKind ==
						 CandidateEvidenceKind::COLLECTOR_ATTESTATION &&
					 audit.inspectionDownload == CandidateAuditGateState::PASSED &&
					 audit.contentIntegrity == CandidateAuditGateState::PASSED &&
					 audit.systemApplicability == CandidateAuditGateState::PASSED &&
					 audit.installReadiness == CandidateInstallReadiness::READY)) ;
		// 探索根拠が未指定の候補を監査済みとして受理しない。
		case CandidateDiscoveryBasis::UNSPECIFIED:
			return false ;
	}

	return false ;
}

/** @see src/core/candidate_audit.h */
bool isCandidateDetailsValid( const UpdateCandidate &candidate,
							 const ScanSessionId	scanSessionId) noexcept
{
	// 観測はlocal代表行だけに所有させ、他候補・他sessionからの複製を拒否する。
	if( candidate.deviceObservation &&
	   (!candidate.current ||
		candidate.discoveryBasis != CandidateDiscoveryBasis::LOCAL_INVENTORY ||
		!isDeviceObservationBound( *candidate.deviceObservation,
								  scanSessionId == 0U ? candidate.deviceObservation->scanSessionId
													  : scanSessionId,
								  candidate.deviceIdentity))) {
		return false ;
	}

	const bool boundInitial =
		candidate.action == DriverAction::INITIAL_INSTALL &&
		candidate.providerId == SIGNED_INDEX_PROVIDER_ID &&
		candidate.discoveryBasis == CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION &&
		!candidate.current && candidate.installable && !candidate.recommended &&
		candidate.defaultPreference == CandidateDefaultPreference::NONE &&
		candidate.allContentCached &&
		candidate.audit.installReadiness == CandidateInstallReadiness::READY &&
		candidate.assessment && isCandidateAssessmentReady( *candidate.assessment) &&
		(candidate.assessment->windowsSelection.evidenceKind ==
			 CandidateEvidenceKind::WINDOWS_API ||
		 (candidate.assessment->installMethod == CandidateInstallMethod::OFFICIAL_INSTALLER &&
		  candidate.assessment->windowsSelection.reason ==
			  CandidateAssessmentReason::INSTALLER_HANDOFF_SELECTION)) &&
		candidate.assessment->windowsSelection.evidenceId !=
			0U ;	// 実行権限は別途私有tokenで検証します。
	// 未対応Providerの初回は表示に限定し、READY表示だけで旧routingへ渡しません。
	if( candidate.action == DriverAction::INITIAL_INSTALL && !boundInitial &&
	   (candidate.current || candidate.installable || candidate.recommended ||
		candidate.defaultPreference != CandidateDefaultPreference::NONE ||
		candidate.audit.installReadiness != CandidateInstallReadiness::BLOCKED ||
		!candidate.assessment || candidate.assessment->executorAvailable ||
		candidate.assessment->method.reason != CandidateAssessmentReason::EXECUTOR_UNAVAILABLE)) {
		return false ;
	}

	// 旧Providerは詳細未収集として扱い、既存auditの保証を変更しない。
	if( !candidate.assessment) {
		return true ;
	}

	const auto &detail = *candidate.assessment ;	// 当該候補だけの検査snapshot。
	// 現在構成を候補検査と混同せず、全identityと選択可能性を再確認する。
	if( candidate.current ||
	   !isCandidateAssessmentBound(
		   detail, scanSessionId == 0U ? detail.scanSessionId : scanSessionId, candidate.identity,
		   candidate.deviceIdentity, candidate.packageIdentity) ||
	   (candidate.installable && !isCandidateAssessmentReady( detail))) {
		return false ;
	}

	// 由来確認は集約監査と同じ事実を指すため、保証をすり替えさせない。
	if( (detail.origin.state == CandidateAssessmentState::PASSED &&
		candidate.audit.sourceOrigin != CandidateAuditGateState::PASSED) ||
	   (detail.origin.reason == CandidateAssessmentReason::USER_PROVIDED &&
		candidate.audit.sourceOrigin != CandidateAuditGateState::USER_PROVIDED_UNVERIFIED) ||
	   (detail.origin.state == CandidateAssessmentState::MANAGED_BY_WINDOWS &&
		candidate.audit.sourceOrigin != CandidateAuditGateState::MANAGED_BY_WINDOWS)) {
		return false ;
	}

	// 同版・非推奨の実選択結果を推奨通常更新へ読み替えない。
	if( candidate.recommended &&
	   (detail.windowsSelection.reason == CandidateAssessmentReason::NO_CHANGE ||
		detail.windowsSelection.reason == CandidateAssessmentReason::NOT_RECOMMENDED)) {
		return false ;
	}

	// 詳細の拒否・失敗を同じ集約の合格で覆い隠さない。
	const auto conflicts = []( const CandidateAssessmentFinding &finding,
							  const CandidateAuditGateState		gate) {
		return (finding.state == CandidateAssessmentState::REJECTED ||
				finding.state == CandidateAssessmentState::FAILED) &&
			   (gate == CandidateAuditGateState::PASSED ||
				gate == CandidateAuditGateState::PROVIDER_VALIDATED ||
				gate == CandidateAuditGateState::MANAGED_BY_WINDOWS) ;
	} ; // Captureなし。合格を捏造する組だけを検出する。
	return !conflicts( detail.origin, candidate.audit.sourceOrigin) &&
		   !conflicts( detail.signature, candidate.audit.contentIntegrity) &&
		   !conflicts( detail.driverOnly, candidate.audit.contentIntegrity) &&
		   !conflicts( detail.applicability, candidate.audit.systemApplicability) &&
		   !conflicts( detail.acquisition,
					  detail.acquisition.reason ==
								  CandidateAssessmentReason::REFERENCED_FILE_MISSING ||
							  detail.acquisition.reason == CandidateAssessmentReason::HASH_MISMATCH
						  ? candidate.audit.contentIntegrity
						  : candidate.audit.inspectionDownload) ;
}

/** @see src/core/candidate_audit.h */
bool isCandidateDetailsSetValid( const std::span<const UpdateCandidate> candidates,
								const ScanSessionId					   scanSessionId) noexcept
{
	// Sessionのないsnapshotや既存上限を超える結果を照合しない。
	if( scanSessionId == 0U || candidates.size() > 32768U) {
		return false ;
	}

	try {
		std::unordered_set<std::wstring_view>
			representatives ;	// 候補が生存する間だけ借用する代表ID。
		// 全候補を一回走査し、deviceの代表行重複を拒否する。
		for( const auto &candidate : candidates) {
			// 詳細不整合や重複を一部成功として残さない。
			if( !isCandidateDetailsValid( candidate, scanSessionId) ||
			   (candidate.current && !representatives.insert( candidate.deviceIdentity).second)) {
				return false ;
			}
		}

		return true ;
	} catch( ...) {
		// 索引の確保失敗は登録拒否として呼出し元へ返す。
		return false ;
	}
}

} // namespace drivercrate
