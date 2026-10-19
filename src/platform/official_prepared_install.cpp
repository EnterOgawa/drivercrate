//------------------------------------------------------------------------------
/**
 * @file official_prepared_install.cpp
 * @brief 監査済み公式INFの共通導入処理。
 * @version 01.00.00
 * @date 2026/09/07
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  候補別callback例外を個別結果化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Provider workerが所有する取得物と監査済み閉包を再検証し、個別結果を保持します。本処理は保持物の解放、再取得または自動retryを行いません。
 */
//------------------------------------------------------------------------------

#include "platform/official_prepared_install.h"

#include "core/update_types.h"
#include "platform/official_file_verifier.h"

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Scan中のrank状態変化を検出し、不一致時の導入を拒否する。
 *
 * @param[in] left 取得後監査時に固定したPnP／rank結果。
 * @param[in] right Install直前に再取得したPnP／rank結果。
 * @return 判断、位置、rank、識別子scoreが完全一致する場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool rankAuditsEqual( const OfficialDriverRankAudit &left,
								   const OfficialDriverRankAudit &right) noexcept
{
	return left.decision == right.decision &&
		   left.currentPosition.kind == right.currentPosition.kind &&
		   left.currentPosition.index == right.currentPosition.index &&
		   left.candidatePosition.kind == right.candidatePosition.kind &&
		   left.candidatePosition.index == right.candidatePosition.index &&
		   left.currentRank == right.currentRank && left.candidateRank == right.candidateRank &&
		   left.currentIdentifierScore == right.currentIdentifierScore &&
		   left.candidateIdentifierScore == right.candidateIdentifierScore ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_prepared_install.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult executePreparedInfInstall(
	const PreparedInfInstallPolicy &policy, const PreparedInfInstallContext &context,
	const std::span<const std::wstring> identities, const PreparedInfReverifier &reverifier,
	const OfficialInfRankAuditor &rankAuditor, const PreparedVerifiedInfInstaller &installer,
	const std::uintptr_t parentWindowNative, const ProviderProgressCallback &progressCallback)
{
	InstallResult result ;	// 選択順で返す候補別の個別結果。
	result.updates.reserve( identities.size()) ;
	// 入力順とidentityを保持し、部分失敗でも全候補の結果を返す。
	for( const std::wstring &identity : identities) {
		result.updates.push_back( {.identity = identity}) ;
	}

	std::unordered_set<std::wstring> uniqueIdentities ;	// Candidate IDの重複検出集合。
	std::unordered_set<std::wstring> uniqueDevices ;	// 一device一候補の検証集合。
	bool valid = !policy.providerId.empty() && policy.providerId.size() <= 256U &&
				 !policy.resourceId.empty() && policy.resourceId.size() <= 256U &&
				 context.scanSessionId != 0U && context.acquisition != nullptr &&
				 !context.packageIdentity.empty() && context.packageIdentity.size() <= 256U &&
				 context.targets != nullptr && !context.targets->empty() &&
				 context.targets->size() <= 4096U && !context.auditedPackages.empty() &&
				 context.auditedPackages.size() <= 32U && context.sourceEvidenceConfirmed &&
				 !identities.empty() && identities.size() <= 4096U && reverifier && rankAuditor &&
				 installer && progressCallback ;	// 全体入力の事前検証結果。
	// 共通前提が成立した場合だけ、全選択 identity の個別対応を照合する。
	if( valid) {
		// 全ID、device、packageおよびINF indexをsystem変更前に検証する。
		for( const std::wstring &identity : identities) {
			const auto target = context.targets->find( identity) ;	// 発行済みrouting。
			// 重複・未知 ID と device・package・監査済み INF の不整合を一件でも認めない。
			if( identity.empty() || identity.size() > 256U ||
			   !uniqueIdentities.insert( identity).second || target == context.targets->end() ||
			   target->second.deviceIdentity.empty() ||
			   target->second.deviceIdentity.size() > 256U ||
			   !uniqueDevices.insert( target->second.deviceIdentity).second ||
			   target->second.packageIdentity != context.packageIdentity ||
			   target->second.auditedPackageIndex >= context.auditedPackages.size() ||
			   context.auditedPackages[target->second.auditedPackageIndex].workspace == nullptr ||
			   context.auditedPackages[target->second.auditedPackageIndex]
					   .closure.packages.size() != 1U ||
			   context.auditedPackages[target->second.auditedPackageIndex]
				   .closure.packages.front()
				   .infRelativePath.empty() ||
			   context.auditedPackages[target->second.auditedPackageIndex]
				   .closure.packages.front()
				   .providerName.empty() ||
			   context.auditedPackages[target->second.auditedPackageIndex]
				   .closure.packages.front()
				   .driverVersion.empty()) {
				valid = false ;
				break ;
			}
		}
	}

	// 事前照合に失敗した要求は system を変更せず全選択候補を拒否する。
	if( !valid) {
		result.downloadOutcome = OutcomeCode::FAILURE ;
		result.downloadError   = static_cast<NativeError>( E_INVALIDARG) ;
		result.installOutcome  = OutcomeCode::FAILURE ;
		result.installError	   = static_cast<NativeError>( E_INVALIDARG) ;
		// System変更前の拒否を全選択候補へ明示する。
		for( UpdateExecutionResult &update : result.updates) {
			update.downloadOutcome = OutcomeCode::FAILURE ;
			update.downloadError   = static_cast<NativeError>( E_INVALIDARG) ;
			update.installOutcome  = OutcomeCode::FAILURE ;
			update.installError	   = static_cast<NativeError>( E_INVALIDARG) ;
		}

		return result ;
	}

	progressCallback( {.stage		   = ProviderStage::DOWNLOADING,
					  .percentComplete = 0,
					  .completedItems  = 0,
					  .totalItems	   = 1}) ;
	NativeError archiveError{} ;	// 外側fileの取得identity・size・hash再検証結果。
	const OfficialAcquisitionResult &acquisition =
		*context.acquisition ;	// 入力検証後だけ参照する外側file snapshot。
	// 取得状態と session・取得元・保持物の根拠が不正なら archive を拒否する。
	if( acquisition.state != OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ||
	   acquisition.scanSessionId != context.scanSessionId || acquisition.acquisitionId == 0U ||
	   acquisition.providerId != policy.providerId || acquisition.resourceId != policy.resourceId ||
	   acquisition.inspectionPath.empty() || acquisition.byteCount == 0U ||
	   acquisition.sha256.empty()) {
		archiveError = static_cast<NativeError>( E_ACCESSDENIED) ;
	} else {
		const OfficialFileMetadataPolicy metadata{
			.expectedSize	= acquisition.byteCount,
			.expectedSha256 = acquisition.sha256} ;	// G11-Bが固定した外側file snapshot。
		archiveError = verifyOfficialFileMetadata( acquisition.inspectionPath, metadata) ;
	}

	std::size_t downloaded{} ;	// 外側file再検証に成功した候補数。
	// 同じ外側fileの結果を全候補へ反映し、downloadとinstallを別状態で保持する。
	for( UpdateExecutionResult &update : result.updates) {
		// Archive の検証成功だけを取得成功として数え、導入結果とは分離する。
		if( archiveError == 0) {
			update.downloadOutcome = OutcomeCode::SUCCESS ;
			++downloaded ;
		} else {
			update.downloadOutcome = OutcomeCode::FAILURE ;
			update.downloadError   = archiveError ;
			update.installOutcome  = OutcomeCode::FAILURE ;
			update.installError	   = archiveError ;
		}
	}

	result.downloadError = archiveError ;
	// Archive を受理できない場合は導入を止める理由を全体結果へ保持する。
	if( archiveError != 0) {
		result.installError = archiveError ;
	}

	progressCallback( {.stage		   = ProviderStage::DOWNLOADING,
					  .percentComplete = 20,
					  .completedItems  = 1,
					  .totalItems	   = 1}) ;

	std::unordered_map<std::size_t, NativeError>
				infVerifications ;	// 監査済みINF index別の一回だけ行う閉包再検証結果。
	std::size_t installed{} ;		// Windows標準導入に成功した候補数。
	// 選択順にINF閉包、PnP／rankを再監査し、個別失敗後も残りの結果を確定する。
	for( std::size_t index = 0U; index < identities.size(); ++index) {
		UpdateExecutionResult		   &update = result.updates[index] ;	// 現在候補の個別結果。
		const PreparedInfInstallTarget &target =
			// 保持routing。
			context.targets->at( identities[index]) ;
		NativeError installError = archiveError ;	// 現在候補の再監査または導入結果。
		bool		rebootRequired{} ;				// 現在INFの再起動要求。
		try {
			// 取得物の検証が成立した場合だけ対象 INF 閉包の再検証へ進む。
			if( installError == 0) {
				const OfficialAuditedInfPackage &audited =
					context.auditedPackages[target.auditedPackageIndex] ;	// 保持INF閉包。
				const auto [verification, inserted] =
					// 再検証cache。
					infVerifications.try_emplace( target.auditedPackageIndex, 0) ;
				// 同じ監査 package の再検証は一度だけ実施し、その結果を共有する。
				if( inserted) {
					try {
						verification->second = reverifier( audited) ;
					} catch( ...) {
						// 同じ閉包を使う後続候補も未検証として通さず、共通失敗を再利用する。
						verification->second = static_cast<NativeError>( E_UNEXPECTED) ;
					}
				}

				installError = verification->second ;
				// INF の再検証に成功した場合だけ現在の PnP 適用性と rank を確認する。
				if( installError == 0) {
					const OfficialInfPackage &package =
						// 再検証済みINF metadata。
						audited.closure.packages.front() ;
					OfficialDriverRankAudit currentRank ;	// Install直前のPnP／rank結果。
					try {
						installError = rankAuditor( context.scanSessionId, target.deviceIdentity,
												   *audited.workspace, package, currentRank) ;
					} catch( ...) {
						installError = static_cast<NativeError>( E_UNEXPECTED) ;
					}

					// 現在の rank が非適用または保持した監査結果と異なれば再 scan を要求する。
					if( installError == 0 &&
					   (currentRank.decision != OfficialDriverRankDecision::APPLICABLE ||
						!rankAuditsEqual( target.rankAudit, currentRank))) {
						installError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY)) ;
					}

					// 取得物・INF・現在 rank の全検証を通過した候補だけを installer へ渡す。
					if( installError == 0) {
						const std::wstring infPath =
							// 保持INFの絶対path。
							audited.workspace->path( package.infRelativePath) ;
						try {
							installError =
								installer( context.scanSessionId, target.deviceIdentity, infPath,
										  package.providerName, package.driverVersion,
										  parentWindowNative, rebootRequired) ;
						} catch( ...) {
							installError = static_cast<NativeError>( E_UNEXPECTED) ;
						}
					}
				}
			}
		} catch( ...) {
			// 候補固有の一時処理失敗を全体例外へせず、後続候補と確定済み結果を維持する。
			installError   = static_cast<NativeError>( E_UNEXPECTED) ;
			rebootRequired = false ;
		}

		update.rebootRequired = rebootRequired ;
		result.rebootRequired = result.rebootRequired || rebootRequired ;
		// Installer の正常終了だけを導入成功件数へ加える。
		if( installError == 0) {
			update.installOutcome = OutcomeCode::SUCCESS ;
			++installed ;
		}
		// 導入前に失敗した未開始候補にも失敗状態と診断値を明示する。
		else if( update.installOutcome == OutcomeCode::NOT_STARTED) {
			update.installOutcome = OutcomeCode::FAILURE ;
			update.installError	  = installError ;
			// 全体結果に診断値がない場合だけ今回の導入失敗を保持する。
			if( result.installError == 0) {
				result.installError = installError ;
			}
		}

		const std::uint64_t completed = index + 1U ;	// 再監査と導入を完了した候補数。
		progressCallback( {.stage = ProviderStage::INSTALLING,
						  .percentComplete =
							  static_cast<std::uint32_t>( 20U + completed * 80U / identities.size()),
						  .completedItems = completed,
						  .totalItems	  = identities.size()}) ;
	}

	result.succeeded = installed == identities.size() ;
	result.downloadOutcome =
		downloaded == identities.size()
			? OutcomeCode::SUCCESS
			: (downloaded == 0U ? OutcomeCode::FAILURE : OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
	result.installOutcome =
		installed == identities.size()
			? OutcomeCode::SUCCESS
			: (installed == 0U ? OutcomeCode::FAILURE : OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
	return result ;
}

} // namespace drivercrate
