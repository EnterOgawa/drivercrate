//------------------------------------------------------------------------------
/**
 * @file asix_preparation.cpp
 * @brief ASIX取得済みdriver packageの内容・適用性監査処理。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX候補発行と指定導入の共通接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX対象検証付き共通report wrapperを追加。
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
 * @note ASIX取得結果を固定Net profileへ接続し、内容合格後だけ端末内PnP／rankを監査します。Provider workerで処理し、導入は復旧保護後の固定binding再
 *       検証境界へ渡します。
 */
//------------------------------------------------------------------------------

#include "platform/asix_preparation.h"

#include "platform/asix_update_provider.h"
#include "platform/official_prepared_audit_report.h"

#include <Windows.h>

#include <stdexcept>
namespace drivercrate {

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_preparation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError auditAsixAx88179aPreparedPackage( const ScanSessionId			  scanSessionId,
											 const OfficialAcquisitionResult &acquisition,
											 const std::wstring_view		  expectedSha256,
											 const std::span<const OfficialCatalogDevice> devices,
											 const OfficialInfRankAuditor  &rankAuditor,
											 const PreparationCancellation &cancellation,
											 OfficialDriverPackageAudit	   &audit)
{
	audit = {} ;
	// session・対象件数・端末内監査callbackを確定できない要求では取得fileを開かない。
	if( scanSessionId == 0U || acquisition.scanSessionId != scanSessionId || devices.empty() ||
	   devices.size() > 4096U || !rankAuditor) {
		audit.summary.state = OfficialDriverPackageAuditState::REJECTED ;
		audit.summary.error = static_cast<NativeError>( E_INVALIDARG) ;
		// 対象または端末内監査境界が不明なまま取得fileを開かない。
		return audit.summary.error ;
	}

	// 全deviceを有限照合し、別系列の表示候補をASIXの監査対象へ混入させない。
	for( const OfficialCatalogDevice &device : devices)	// 現在確認する非機密device snapshot。
	{
		// 対象外deviceが混在するASIX監査要求を全体拒否する。
		if( !isAsixAx88179aDevice( device)) {
			audit.summary.state = OfficialDriverPackageAuditState::REJECTED ;
			audit.summary.error = static_cast<NativeError>( E_INVALIDARG) ;
			return audit.summary.error ;
		}
	}

	const OfficialDriverPackageAuditRequest request{
		.acquisition	= &acquisition,
		.expectedSha256 = expectedSha256,
		.archiveFormat	= OfficialDriverArchiveFormat::ZIP,
		.profile = OfficialDriverAuditProfile::ASIX_AX88179A} ;	// 公開hash任意の固定Net profile。
	const NativeError contentError = auditOfficialDriverPackage(
		request, audit, cancellation) ;	// 閉包、CAT、全参照fileの内容監査結果。
	// 内容拒否をPnP適用性の合格へ変換しない。
	if( contentError != 0 || audit.summary.state != OfficialDriverPackageAuditState::AUDITED) {
		return contentError ;
	}

	return auditOfficialDriverApplicability( scanSessionId, devices, rankAuditor, audit,
											cancellation) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_preparation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialPreparationAuditReport makeAsixPreparationAuditReport(
	const ScanSessionId session, const std::wstring_view targetIdentity,
	const std::span<const OfficialCatalogDevice> devices,
	const std::span<const std::wstring>			 candidateIdentities,
	const OfficialDriverPackageAudit			&audit)
{
	// 共通helperへ渡す前に、全deviceがASIX固定製品の検索条件と一致することを確認する。
	for( const OfficialCatalogDevice &device : devices)	// 現在検証する候補対応device。
	{
		// 対象外deviceをASIX固定profileの監査表示へ結び付けない。
		if( !isAsixAx88179aDevice( device)) {
			throw std::logic_error( "invalid ASIX prepared audit binding") ;
		}
	}

	return makeOfficialPreparedAuditReport( OfficialDriverAuditProfile::ASIX_AX88179A, session,
										   targetIdentity, devices, candidateIdentities, audit) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_preparation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void publishAsixPreparedCandidates(
	const ScanSessionId session, const std::uint64_t acquisitionId, const std::uint64_t byteCount,
	const std::span<const OfficialCatalogDevice> devices, const OfficialDriverPackageAudit &audit,
	const OfficialInfInstallBinder &binder, const OfficialInfInstallBindingReleaser &releaser,
	OfficialPreparationAuditReport &report, BoundPreparedInstallTargets &targets) noexcept
{
	publishBoundPreparedCandidates( OfficialDriverAuditProfile::ASIX_AX88179A, session,
								   acquisitionId, byteCount, devices, audit, binder, releaser,
								   report, targets) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_preparation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult executeAsixPreparedInstall( const BoundPreparedInstallContext	&context,
										 const std::span<const std::wstring> identities,
										 const PreparedInfReverifier		&reverifier,
										 const OfficialInfRankAuditor		&rankAuditor,
										 const OfficialBoundInfInstaller	&installer,
										 const std::uintptr_t				 parentWindowNative,
										 const ProviderProgressCallback		&progressCallback)
{
	return executeBoundPreparedInstall( OfficialDriverAuditProfile::ASIX_AX88179A, context,
									   identities, reverifier, rankAuditor, installer,
									   parentWindowNative, progressCallback) ;
}

} // namespace drivercrate
