//------------------------------------------------------------------------------
/**
 * @file official_release_preparation.cpp
 * @brief Intel Ethernetの承認済み取得・監査・候補発行adapter。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX候補発行と指定導入の共通接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  候補発行を共通binding処理へ委譲。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel監査report集約を共通helperへ移行。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  非対応OEMの明示除外到達条件を修正。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  File責務を候補発行まで更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Binding失効loopの目的を明示。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel指定導入後の保持物契約を反映。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel候補routingとbinding失効を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  同意済み一配布物の取得を共通基盤へ接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  固定Net profileの取得後監査wrapperを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  検索行対応snapshotの失効処理を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  取得成功と監査結果の独立保持を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  既存候補用の非機密監査reportを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Worker内で固定対象を再確認し、同一scanで一回だけ取得・監査します。許諾と利用前提の明示確認は呼出し元の承認sessionが検証し、tokenをclaimします。監査結果は取
 *       得結果と分離し、監査合格候補と保持routingを同時に発行します。発行候補の指定導入は保持routingとbindingを再検証する別実装へ委譲します。
 */
//------------------------------------------------------------------------------

#include "platform/official_release_discovery_provider.h"

#include "core/candidate_audit.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/official_acquisition.h"
#include "platform/official_download_workspace.h"
#include "platform/official_prepared_acquisition.h"
#include "platform/official_prepared_audit_report.h"
#include "platform/windows_product_type.h"

#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace drivercrate {

OfficialReleaseDiscoveryProvider::~OfficialReleaseDiscoveryProvider() = default ;

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError auditIntelEthernetPreparedPackage( const ScanSessionId			   scanSessionId,
											  const OfficialAcquisitionResult &acquisition,
											  const std::wstring_view		   expectedSha256,
											  const std::span<const OfficialCatalogDevice> devices,
											  const OfficialInfRankAuditor	&rankAuditor,
											  const PreparationCancellation &cancellation,
											  OfficialDriverPackageAudit	&audit)
{
	audit = {} ;
	// 取得元と scan session の不一致、空または上限超過の対象集合を監査前に拒否する。
	if( scanSessionId == 0U || acquisition.scanSessionId != scanSessionId || devices.empty() ||
	   devices.size() > 4096U) {
		audit.summary.state = OfficialDriverPackageAuditState::REJECTED ;
		audit.summary.error = static_cast<NativeError>( E_INVALIDARG) ;
		// 取得元sessionと対象deviceが不明なまま監査しない。
		return audit.summary.error ;
	}

	// 全deviceを有限照合し、別系列の表示候補をIntel Ethernetの対象へ混入させない。
	for( const OfficialCatalogDevice &device : devices)	// 現在確認する非機密device snapshot。
	{
		// Intel Ethernet の local 対象条件に一致しない device を監査集合へ許可しない。
		if( !officialReleaseDeviceMatches( OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025,
										 device)) {
			audit.summary.state = OfficialDriverPackageAuditState::REJECTED ;
			audit.summary.error = static_cast<NativeError>( E_INVALIDARG) ;
			return audit.summary.error ;
		}
	}

	const OfficialDriverPackageAuditRequest request{
		.acquisition	= &acquisition,
		.expectedSha256 = expectedSha256,
		.archiveFormat	= OfficialDriverArchiveFormat::ZIP,
		.profile =
			OfficialDriverAuditProfile::INTEL_ETHERNET_SERVER2025} ;	// 公開hash必須Net profile。
	const NativeError error = auditOfficialDriverPackage(
		request, audit, cancellation) ;	// 閉包・CAT・全参照fileの内容監査結果。
	// 内容拒否をPnP適用性の合格へ変換しない。
	if( error != 0 || audit.summary.state != OfficialDriverPackageAuditState::AUDITED) {
		return error ;
	}

	return auditOfficialDriverApplicability( scanSessionId, devices, rankAuditor, audit,
											cancellation) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialPreparationAuditReport makeIntelEthernetPreparationAuditReport(
	const ScanSessionId session, const std::wstring_view targetIdentity,
	const std::span<const OfficialCatalogDevice> devices,
	const std::span<const std::wstring>			 candidateIdentities,
	const OfficialDriverPackageAudit			&audit)
{
	// 共通helperへ渡す前に、Intel固有の対象系列または明示除外対象であることを全件確認する。
	for( const OfficialCatalogDevice &device : devices)	// 現在検証する候補対応device。
	{
		const bool reportableDevice =
			officialReleaseDeviceMatches( OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025,
										 device) ||
			isKnownUnsupportedIntelEthernetModel(
				device.model) ;	// 明示拒否結果だけを作る既知非対応OEMも許可する。
		// 対象系列の表示境界を満たさない device の監査 report を拒否する。
		if( !reportableDevice) {
			throw std::logic_error( "invalid Intel Ethernet prepared audit binding") ;
		}
	}

	return makeOfficialPreparedAuditReport( OfficialDriverAuditProfile::INTEL_ETHERNET_SERVER2025,
										   session, targetIdentity, devices, candidateIdentities,
										   audit) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void publishIntelEthernetPreparedCandidates(
	const ScanSessionId session, const std::uint64_t acquisitionId,
	const std::uint64_t maximumDownloadBytes, const std::span<const OfficialCatalogDevice> devices,
	const OfficialDriverPackageAudit &audit, const OfficialInfInstallBinder &bindingCreator,
	const OfficialInfInstallBindingReleaser &bindingReleaser,
	OfficialPreparationAuditReport			&report,
	IntelEthernetPreparedInstallTargets		&installTargets) noexcept
{
	publishBoundPreparedCandidates( OfficialDriverAuditProfile::INTEL_ETHERNET_SERVER2025, session,
								   acquisitionId, maximumDownloadBytes, devices, audit,
								   bindingCreator, bindingReleaser, report, installTargets) ;
}
//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void OfficialReleaseDiscoveryProvider::resetPreparedDownload() noexcept
{
	// Providerが発行したtokenだけを破棄し、同じscanにある他Providerのbindingを維持する。
	if( bindingReleaser_) {
		// 現在保持する全候補routingを巡回し、Providerが発行したtokenだけを個別破棄する。
		for( const auto &route : installTargets_) {
			static_cast<void>( bindingReleaser_( retainedSessionId_, route.second.binding.token)) ;
		}
	}

	installTargets_.clear() ;
	candidatesPublished_ = false ;
	publicationResolved_ = false ;
	preparedTarget_.reset() ;
	preparedPlanId_		  = 0U ;
	acquisitionAttempted_ = false ;
	// INF閉包を外側取得fileとworkspaceより先に解放する。
	preparedAudit_ = {} ;
	acquisition_   = {} ;
	acquisitionSession_.reset() ;
	// 専用RAIIが自身の既知fileだけを破棄する。
	workspace_.reset() ;
	retainedDevices_.clear() ;
	retainedCandidateIdentities_.clear() ;
	ownerThreadId_ = 0U ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialPreparationTransferResult OfficialReleaseDiscoveryProvider::acquireForInspection(
	const OfficialPreparationTask &task, const PreparationCancellation &cancellation)
{
	// 系列・thread・session・plan・同意条件・取得根拠を照合し、不正な取得を拒否する。
	if( family_ != OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025 || !preparedTarget_ ||
	   acquisitionAttempted_ || task.operationId == 0U ||
	   task.scanSessionId != retainedSessionId_ || task.planId != preparedPlanId_ ||
	   task.target != *preparedTarget_ || GetCurrentThreadId() != ownerThreadId_ ||
	   !preparedTarget_->requiresPrerequisiteConfirmation ||
	   preparedTarget_->terms != OfficialPreparationTerms::ACCEPTANCE_REQUIRED ||
	   !http_.hasSourceEvidence( retainedSessionId_, INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID,
								OFFICIAL_LANDING_RESOURCE_ID)) {
		return {OfficialPreparationItemState::REJECTED, static_cast<NativeError>( E_INVALIDARG), 0} ;
	}

	// 以降の取消し・失敗でも同じ計画を再実行しない。
	acquisitionAttempted_ = true ;
	// 実 OS が系列の対応範囲外なら保持済み計画があっても取得しない。
	if( !officialReleaseOperatingSystemMatches( family_, isWindowsServer(),
											  currentWindowsBuildNumber())) {
		return {OfficialPreparationItemState::REJECTED, static_cast<NativeError>( E_NOTIMPL), 0} ;
	}

	try {
		// 取得開始前に取消し要求を確認し、不要な通信を避ける。
		if( cancellation && cancellation()) {
			return {OfficialPreparationItemState::CANCELLED,
					static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)), 0} ;
		}

		workspace_			= std::make_unique<OfficialDownloadWorkspace>() ;
		acquisitionSession_ = std::make_unique<OfficialAcquisitionSession>() ;
		const OfficialAcquisitionLimits limits{preparedTarget_->maximumBytes,
											   preparedTarget_->maximumBytes,
											   preparedTarget_->maximumBytes,
											   256ULL * 1024ULL * 1024ULL,
											   1U,
											   1U} ;	// 一file限定予算。
		NativeError error = workspace_->initialize( INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID,
												   retainedSessionId_) ;	// 元の初期化診断値。
		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = acquisitionSession_->initialize( retainedSessionId_, limits) ;
		}

		// 未初期化なら通信しない。
		if( error != 0) {
			return {OfficialPreparationItemState::FAILURE, error, 0} ;
		}

		OfficialHttpAcquisitionTransport transport( http_) ;	// 同じ公式取得根拠の非所有adapter。
		WindowsOfficialNetworkCostReader costReader ;			// Windows標準の課金状態照会。
		const PreparedReleaseRefresh	 refresh = [this]( OfficialReleaseRecord &current,
													  bool					&rejected) {
			return readOfficialReleaseMetadata( family_, retainedSessionId_, http_, current,
												   rejected) ;
		} ; // 起点は組込み固定page。再確認した本文・版・URL・hashの全一致を共通層が要求する。
		const OfficialPreparationTransferResult transfer = acquirePreparedRelease(
			task, *preparedTarget_, retainedRelease_, refresh, *acquisitionSession_, *workspace_,
			transport, costReader, cancellation, acquisition_) ;	// 先に確定する取得結果。
		// 取得成功した保持物だけを内容監査へ渡し、取得状態と監査結果を分離する。
		if( transfer.state == OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION &&
		   transfer.error == 0) {
			try {
				static_cast<void>( auditIntelEthernetPreparedPackage(
					retainedSessionId_, acquisition_, retainedRelease_.publishedSha256,
					retainedDevices_, rankAuditor_, cancellation, preparedAudit_)) ;
			} catch( ...) {
				// 監査境界外の例外では部分合格を破棄し、確定済みの取得成功は維持する。
				preparedAudit_					   = {} ;
				preparedAudit_.scanSessionId	   = retainedSessionId_ ;
				preparedAudit_.summary.state	   = OfficialDriverPackageAuditState::FAILURE ;
				preparedAudit_.summary.error	   = static_cast<NativeError>( E_UNEXPECTED) ;
				preparedAudit_.applicability.state = OfficialDriverApplicabilityState::FAILURE ;
				preparedAudit_.applicability.error = preparedAudit_.summary.error ;
			}
		}

		// 内容拒否・非適用でもdownloadの終端状態とbyte数を変更しない。
		return transfer ;
	} catch( ...) {
		// 未完了の保持物だけを解放し、一回限りの実行済み状態は維持する。
		acquisition_ = {} ;
		acquisitionSession_.reset() ;
		workspace_.reset() ;
		return {OfficialPreparationItemState::FAILURE, static_cast<NativeError>( E_FAIL), 0} ;
	}
}

//------------------------------------------------------------------------------
/**
	 * @see src/platform/official_release_discovery_provider.h 宣言側の契約を正本とする。
	 */
//------------------------------------------------------------------------------
std::optional<OfficialPreparationAuditReport> OfficialReleaseDiscoveryProvider::
	preparationAuditReport( const ScanSessionId	   scanSessionId,
						   const std::wstring_view targetIdentity)
{
	// 未取得・旧session・別対象・未監査・再発行へreportを補完しない。
	if( family_ != OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025 || scanSessionId == 0U ||
	   scanSessionId != retainedSessionId_ || !preparedTarget_ ||
	   preparedTarget_->identity != targetIdentity || !acquisitionAttempted_ ||
	   acquisition_.state != OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ||
	   acquisition_.error != 0 || acquisition_.scanSessionId != scanSessionId ||
	   acquisition_.providerId != INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ||
	   acquisition_.resourceId != OFFICIAL_PAYLOAD_RESOURCE_ID || acquisition_.byteCount == 0U ||
	   acquisition_.acquisitionId == 0U || !acquisition_.publishedSha256Verified ||
	   preparedAudit_.summary.state == OfficialDriverPackageAuditState::NOT_STARTED ||
	   retainedDevices_.empty() || retainedDevices_.size() != retainedCandidateIdentities_.size() ||
	   GetCurrentThreadId() != ownerThreadId_ || publicationResolved_) {
		return std::nullopt ;
	}

	OfficialPreparationAuditReport report = makeIntelEthernetPreparationAuditReport(
		scanSessionId, targetIdentity, retainedDevices_, retainedCandidateIdentities_,
		preparedAudit_) ;	// URL、path、生PnP IDを含まない既存行snapshot。
	// 内容と適用性の両 gate を通過していない report から候補を公開しない。
	if( report.content != CandidateAuditGateState::PASSED ||
	   report.applicability != CandidateAuditGateState::PASSED) {
		publicationResolved_ = true ;
		// 監査拒否または失敗を候補発行へ昇格しない。
		return report ;
	}

	const auto descriptors = builtInProviderDescriptors() ;	// Process内の固定Provider registry。
	const auto descriptor  = std::ranges::find_if( descriptors, []( const ProviderDescriptor &value) {
		 return value.id == INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ;
	 }) ; // Intelの能力定義。
	// Registry の導入能力と binding 境界が揃わなければ候補公開を拒否する。
	if( descriptor == descriptors.end() ||
	   (descriptor->capabilities & capabilityMask( ProviderCapability::INSTALL)) == 0U ||
	   !bindingCreator_ || !bindingReleaser_) {
		report.publication.state	  = OfficialPreparationCandidatePublicationState::FAILURE ;
		report.publication.firstError = static_cast<NativeError>( E_NOTIMPL) ;
		publicationResolved_		  = true ;
		// RegistryとDriver Store境界が揃う前に選択候補を公開しない。
		return report ;
	}

	IntelEthernetPreparedInstallTargets installTargets ;	// 成功時だけ保持する新routing。
	publishIntelEthernetPreparedCandidates(
		scanSessionId, acquisition_.acquisitionId, acquisition_.byteCount, retainedDevices_,
		preparedAudit_, bindingCreator_, bindingReleaser_, report,
		installTargets) ;	// 固定fixtureとProviderが共有する候補公開境界。
	// 候補公開が確定した場合だけ内部 install routing を同時に保持する。
	if( report.publication.state ==
	   OfficialPreparationCandidatePublicationState::CANDIDATES_PUBLISHED) {
		// 全候補検証後だけProviderへcommitする。
		installTargets_		 = std::move( installTargets) ;
		candidatesPublished_ = true ;
	}

	publicationResolved_ = true ;
	return report ;
}
} // namespace drivercrate
