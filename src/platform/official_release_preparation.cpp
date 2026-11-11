//------------------------------------------------------------------------------
/**
 * @file official_release_preparation.cpp
 * @brief Intel Ethernetの承認済み取得・監査・候補発行adapter。
 * @version 01.00.01
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
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
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

//------------------------------------------------------------------------------
/**
 * @brief Workerが所有する取得fileと公式HTTP根拠を解放する。
 */
//------------------------------------------------------------------------------
OfficialReleaseDiscoveryProvider::~OfficialReleaseDiscoveryProvider() = default ;

//------------------------------------------------------------------------------
/**
 * @brief Intel Ethernetの同一scan取得物を内容監査と端末内PnP監査へ接続する。Server 2025向け固定Net profileで全INFを監査し、署名合格INFだけを
 *        端末内で照合する。製品名一致だけでは適用や導入を許可しない。
 * @param[in] scanSessionId 保持deviceと取得結果に共通の検索session。
 * @param[in] acquisition 公式由来と公開hashを確認し、workerが所有する取得結果。 同じworkerが所有する公開hash確認済み取得結果。
 * @param[in] expectedSha256 公式metadataの公開SHA-256。空または実測値の代用を拒否する。 公式metadataに掲載された公開SHA-256。
 * @param[in] devices 同じscanでIntel Ethernet系列へ照合したdevice群。 同一scanで系列照合済みのdevice群。
 * @param[in] rankAuditor 同じworkerのDriver Store照合callback。 Windows標準PnP／rank監査。
 * @param[in] cancellation 空または協調取消し照会。
 * @param[out] audit 内容と適用性の独立した結果。導入候補は作らない。 内容・適用性の結果と単独所有閉包。
 * @return 全体処理成功時0。入力・内容・全体処理失敗時はHRESULT。 全体処理成功時0、拒否・失敗時はHRESULT。
 * @note 製品名は対象範囲の事前確認に限り、適用性はPnP／rank監査を正本とする。
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
 * @brief Intel Ethernet監査を検索時の既存候補行へ反映する非機密reportを作る。Intel対象系列と既知非対応OEMだけを確認してから、固定profileの共通helper
 *        へ集約を委譲する。候補発行とinstall準備状態の昇格は行わない。
 * @param[in] session 保持している0ではない検索session。 監査対象を取得した検索session。
 * @param[in] targetIdentity 利用者が取得を承認したopaque対象ID。
 * @param[in] devices 検索候補順に保持した非機密device snapshot。 検索候補順の非機密device snapshot。
 * @param[in] candidateIdentities devicesと同じ順序の既存opaque候補ID。 devicesと同じ順序の既存候補ID。
 * @param[in] audit 同じ取得物の内容・PnP／rank監査結果。 同一取得物の内容・PnP／rank監査結果。
 * @return 既存候補の監査fieldを持つ、候補発行前の非機密report。 既存行の監査fieldだけを更新する非機密report。
 * @throws std::logic_error session、件数、identityまたは監査保持構造が矛盾する場合。
 * @note Intel対象確認後に共通集約へ委譲する。候補追加はProvider methodが別に実行する。
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
 * @brief Intel Ethernet監査合格組合せから候補と導入routingを同時に構成する。個別の版不明、既知非対応、重複、binding失敗は除外する。構造矛盾では今回発行した全
 *        tokenと候補を破棄し、例外をworker境界へ漏らさない。
 * @param[in] session 候補を発行する0ではない検索session。 候補を発行する検索session。
 * @param[in] acquisitionId 同じ取得成功物の0ではないopaque ID。 検証済み外側取得物のopaque ID。
 * @param[in] maximumDownloadBytes 検証済み外側取得物のbyte数。1以上。
 * @param[in] devices 同じscanで保持する一意な非機密device snapshot。 同じscanで保持する非機密device snapshot。
 * @param[in] audit 内容とPnP／rank監査に合格した保持構造。
 * @param[in] bindingCreator 一意なWindows nodeのbindingを発行するcallback。 Windows nodeのbinding発行callback。
 * @param[in] bindingReleaser 未commit tokenを個別破棄するcallback。 未commit tokenの破棄callback。
 * @param[in,out] report 候補発行前の合格report。発行結果と候補を反映する。 合格reportへ発行集計と候補を反映する。
 * @param[out] installTargets 全件成功時だけ候補ID別routingを返す。失敗時は空。 成功時だけ返す候補ID別routing。
 * @note 個別の版不明、既知非対応、重複、binding失敗は除外し、構造矛盾では全件破棄する。
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
 * @brief 次scanやinstall開始時に監査閉包、取得物、検索行対応の順で解放する。前回release観測の設定は維持する。
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
 * @brief 承認済みIntel Ethernet ZIPを一回だけ検査用に取得する。同一thread・scan・plan・対象と実OSを確認し、一配布物を有限量だけ取得する。取得成功時だけ監査
 *        し、その拒否・取消し・例外で取得結果を書き換えない。自動retryせず、次scanまで取得結果と監査結果をworker内で別々に所有する。
 * @param[in] task Workerがclaimした固定対象。任意URLや未承認tokenを受け付けない。 Workerが承認sessionでclaimした今回の固定対象。
 * @param[in] cancellation 空または協調取消し照会。導入処理は呼ばない。
 * @return 再確認と共通取得の終端状態。内容監査・適用性・導入結果を含めない。 取得終端状態、診断値、byte数。監査合格・導入許可は含めない。
 * @note 同一worker／scan限定。呼出し元が前提確認と許諾同意を検証してからclaimする。
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
 * @brief 保持監査を同じ取得対象と既存候補行の非機密表示へ変換する。全監査合格組合せを現在deviceとWindows nodeへ再拘束し、未選択候補とworker内routingを同時に一
 *        度だけcommitする。個別binding失敗は当該組合せだけを除外し、構造矛盾では全新規候補を破棄する。
 * @param[in] scanSessionId 現在保持している検索session。
 * @param[in] targetIdentity 承認済み取得計画内のopaque対象ID。
 * @return 同じ取得成功対象の監査report。未取得・旧session・別対象はnullopt。 既存監査行、候補発行状態および発行候補。不一致はnullopt。
 * @note 全監査合格時だけ候補とroutingを一括発行し、同じ対象への再発行を拒否する。
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
