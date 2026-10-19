//------------------------------------------------------------------------------
/**
 * @file broadcom_preparation.cpp
 * @brief Broadcom公式配布物の承認対象化と選択取得。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Broadcom監査report集約を共通helperへ移行。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  候補発行の非機密集計を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Release観測context失効を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  監査合格候補と導入routingを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の表示境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Broadcomの取得後監査を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 取得と導入を分離し、成功ZIPをworkerの保護workspaceで所有します。
 */
//------------------------------------------------------------------------------

#include "core/candidate_audit.h"
#include "core/official_preparation_operation.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/broadcom_update_provider.h"
#include "platform/official_acquisition.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_package_audit.h"
#include "platform/official_prepared_acquisition.h"
#include "platform/official_prepared_audit_report.h"
#include "platform/official_release_metadata.h"
#include <Windows.h>
#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {
// 一配布物の取得上限。共通計画の一file上限128 MiBを超えない。
constexpr std::uint64_t						ARCHIVE_BYTES = 128ULL * 1024ULL * 1024ULL ;

//------------------------------------------------------------------------------
/**
 * @brief 数値を補完・正規化せず、比較不能な版は明示再導入へ残す。
 *
 * @param[in] version INFまたは現在driverのversion文字列。
 * @return 4要素を厳密に解析できた場合は数値配列、それ以外は空。
 */
//------------------------------------------------------------------------------
std::optional<std::array<std::uint32_t, 4>> parseBroadcomDriverVersion(
	const std::wstring_view version) noexcept
{
	std::array<std::uint32_t, 4> parts{} ;		// 解析済みの四要素。
	std::size_t					 partIndex{} ;	// 現在確定する要素index。
	std::uint64_t				 value{} ;		// 32-bit超過を検出する現在値。
	bool						 hasDigit{} ;	// 現在要素へ数字を一つ以上読んだ場合true。
	// 全文字を一度走査し、四要素以外、空要素、ASCII数字以外、overflowを拒否する。
	for( const wchar_t character : version) {
		// ASCII数字を現在のversion componentへ取り込み、有限整数として比較する。
		if( character >= L'0' && character <= L'9') {
			const std::uint32_t digit =
				// 現在の十進一桁。
				static_cast<std::uint32_t>( character - L'0') ;
			// version componentの桁追加でuint32上限を超える前に拒否する。
			if( value > (std::numeric_limits<std::uint32_t>::max() - digit) / 10U) {
				return std::nullopt ;
			}

			value	 = value * 10U + digit ;
			hasDigit = true ;
			continue ;
		}

		// 不正区切り・空component・過剰componentをversionとして受理しない。
		if( character != L'.' || !hasDigit || partIndex >= parts.size() - 1U) {
			return std::nullopt ;
		}

		parts[partIndex] = static_cast<std::uint32_t>( value) ;
		++partIndex ;
		value	 = 0U ;
		hasDigit = false ;
	}

	// 四要素と末尾の数字が揃わないversionは比較不能とする。
	if( !hasDigit || partIndex != parts.size() - 1U) {
		return std::nullopt ;
	}

	parts[partIndex] = static_cast<std::uint32_t>( value) ;
	return parts ;
}

//------------------------------------------------------------------------------
/**
 * @brief 比較不能時は最新版と推測せず、利用者が明示確認する再導入へ分類する。
 *
 * @param[in] candidateVersion INFが明示した候補version。
 * @param[in] currentVersion 同じdeviceの現在driver version。
 * @return 数値比較に対応する更新、再導入または旧版への切替。
 */
//------------------------------------------------------------------------------
DriverAction classifyBroadcomAction( const std::wstring_view candidateVersion,
									const std::wstring_view currentVersion) noexcept
{
	const auto candidate = parseBroadcomDriverVersion( candidateVersion) ;	// INF版。
	const auto current	 = parseBroadcomDriverVersion( currentVersion) ;	// 現在版。
	// 比較不能な版を最新と断定せず、明示確認が必要な再導入へ分類する。
	if( !candidate || !current) {
		return DriverAction::REINSTALL ;
	}

	// 比較可能な候補版が現在版より大きい場合だけ更新に分類する。
	if( *candidate > *current) {
		return DriverAction::UPDATE ;
	}

	// 比較可能な候補版が現在版より小さい場合だけ旧版に分類する。
	if( *candidate < *current) {
		return DriverAction::DOWNGRADE ;
	}

	return DriverAction::REINSTALL ;
}

//------------------------------------------------------------------------------
/**
 * @brief 日付は表示専用とし、適用性や版の新旧判定には使用しない。
 *
 * @param[in] value INF DriverVerのMM/DD/YYYY日付。
 * @return YYYY/MM/DD形式。形式不正時は空文字列。
 */
//------------------------------------------------------------------------------
std::wstring formatBroadcomDriverDate( const std::wstring_view value)
{
	// INF日付の固定書式が一致しなければ表示用に並べ替えない。
	if( value.size() != 10U || value[2U] != L'/' || value[5U] != L'/') {
		return {} ;
	}

	// 区切り以外の全位置をASCII数字に限定する。
	for( std::size_t index = 0U; index < value.size(); ++index) {
		// 日付の数字位置に非数字がある場合は空表示を返す。
		if( index != 2U && index != 5U && (value[index] < L'0' || value[index] > L'9')) {
			return {} ;
		}
	}

	return std::wstring( value.substr( 6U, 4U)) + L"/" + std::wstring( value.substr( 0U, 2U)) + L"/" +
		   std::wstring( value.substr( 3U, 2U)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider内の監査順序だけから同じsessionで一意な候補IDを発行する。
 *
 * @param[in] session 候補が属する検索session。
 * @param[in] rankTargetIndex 監査合格組合せの保持index。
 * @return 表示値から復元しないopaque候補ID。
 */
//------------------------------------------------------------------------------
std::wstring broadcomCandidateIdentity( const ScanSessionId session,
									   const std::size_t   rankTargetIndex)
{
	return L"broadcom-driver:" + std::to_wstring( session) + L":" + std::to_wstring( rankTargetIndex) ;
}

//------------------------------------------------------------------------------
/**
 * @brief URL、title、versionを識別子へ使用せず、検証済み取得identityだけを使用する。
 *
 * @param[in] session 候補が属する検索session。
 * @param[in] acquisitionId 共通取得層が発行した取得連番。
 * @return 同じ外側ZIPを束ねるopaque package ID。
 */
//------------------------------------------------------------------------------
std::wstring broadcomPackageIdentity( const ScanSessionId session, const std::uint64_t acquisitionId)
{
	return L"broadcom-package:" + std::to_wstring( session) + L":" + std::to_wstring( acquisitionId) ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
BroadcomUpdateProvider::BroadcomUpdateProvider( OfficialInfRankAuditor rankAuditor)
	: rankAuditor_( std::move( rankAuditor))
{
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
BroadcomUpdateProvider::BroadcomUpdateProvider( OfficialInfRankAuditor		rankAuditor,
											   BroadcomVerifiedInfInstaller installer)
	: rankAuditor_( std::move( rankAuditor)), installer_( std::move( installer))
{
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError auditBroadcomPreparedPackage( const ScanSessionId			  scanSessionId,
										 const OfficialAcquisitionResult &acquisition,
										 const std::wstring_view		  expectedSha256,
										 const std::span<const OfficialCatalogDevice> devices,
										 const OfficialInfRankAuditor				 &rankAuditor,
										 const PreparationCancellation				 &cancellation,
										 OfficialDriverPackageAudit					 &audit)
{
	audit = {} ;
	// session不一致と空・過大な対象集合を監査開始前に拒否する。
	if( scanSessionId == 0U || acquisition.scanSessionId != scanSessionId || devices.empty() ||
	   devices.size() > 4096U) {
		audit.summary.state = OfficialDriverPackageAuditState::REJECTED ;
		audit.summary.error = static_cast<NativeError>( E_INVALIDARG) ;
		// 取得元sessionと対象deviceが不明なまま監査しない。
		return audit.summary.error ;
	}

	// 全deviceを有限照合し、別系列の表示候補をBroadcomの対象へ混入させない。
	for( const OfficialCatalogDevice &device : devices) {
		// Broadcom対象系列以外のdeviceを固定Net profileで監査しない。
		if( !broadcomNetxtremeEDevice( device)) {
			audit.summary.state = OfficialDriverPackageAuditState::REJECTED ;
			audit.summary.error = static_cast<NativeError>( E_INVALIDARG) ;
			return audit.summary.error ;
		}
	}

	const OfficialDriverPackageAuditRequest request{
		.acquisition	= &acquisition,
		.expectedSha256 = expectedSha256,
		.archiveFormat	= OfficialDriverArchiveFormat::ZIP,
		.profile = OfficialDriverAuditProfile::BROADCOM_NET_XTREME_E} ;	// 登録済みのNet限定profile。
	const NativeError error =
		// 閉包・CAT・全参照fileの結果。
		auditOfficialDriverPackage( request, audit, cancellation) ;
	// 内容拒否をPnP適用性の合格へ変換しない。
	if( error != 0 || audit.summary.state != OfficialDriverPackageAuditState::AUDITED) {
		return error ;
	}

	return auditOfficialDriverApplicability( scanSessionId, devices, rankAuditor, audit,
											cancellation) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::vector<UpdateCandidate> makeBroadcomPreparedCandidates(
	const ScanSessionId session, const OfficialAcquisitionResult &acquisition,
	const std::span<const OfficialCatalogDevice> devices, const OfficialDriverPackageAudit &audit)
{
	// 取得identityと全監査結果・対象件数が整合しなければ導入候補を発行しない。
	if( session == 0U || acquisition.state != OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ||
	   acquisition.scanSessionId != session || acquisition.acquisitionId == 0U ||
	   acquisition.providerId != BROADCOM_NET_XTREME_PROVIDER_ID ||
	   acquisition.resourceId != OFFICIAL_PAYLOAD_RESOURCE_ID ||
	   acquisition.inspectionPath.empty() || acquisition.byteCount == 0U ||
	   acquisition.sha256.empty() || acquisition.error != 0 || audit.scanSessionId != session ||
	   audit.summary.state != OfficialDriverPackageAuditState::AUDITED ||
	   audit.summary.error != 0 || audit.summary.auditedInfCount == 0U ||
	   audit.summary.auditedInfCount != audit.auditedPackages.size() ||
	   audit.applicability.state != OfficialDriverApplicabilityState::APPLICABLE_TARGETS ||
	   audit.applicability.error != 0 ||
	   audit.applicability.applicablePairCount != audit.rankApprovedTargets.size() ||
	   audit.auditedPackages.empty() || audit.rankApprovedTargets.empty() || devices.empty() ||
	   devices.size() > 4096U || audit.rankApprovedTargets.size() > 4096U) {
		throw std::logic_error( "invalid Broadcom candidate publication") ;
	}

	std::unordered_map<std::wstring_view, const OfficialCatalogDevice *>
		deviceIndex ;	// Device索引。
	deviceIndex.reserve( devices.size()) ;
	// 検索時の系列snapshotを一意に索引化し、監査外のdeviceを候補へ混ぜない。
	for( const OfficialCatalogDevice &device : devices) {
		// 対象外deviceと重複identityを候補発行用索引へ取り込まない。
		if( !broadcomNetxtremeEDevice( device) ||
		   !deviceIndex.emplace( device.deviceIdentity, &device).second) {
			throw std::logic_error( "invalid Broadcom candidate device") ;
		}
	}

	std::set<std::pair<std::wstring, std::wstring>> publishedVersions ;	// Device／版の重複集合。
	std::vector<UpdateCandidate>					candidates ;		// UIへ渡す非機密の全監査合格候補。
	candidates.reserve( audit.rankApprovedTargets.size()) ;
	// G11-Dに合格した保持順で候補を生成し、同じdevice／versionの複数INFは一件へまとめる。
	for( std::size_t index = 0U; index < audit.rankApprovedTargets.size(); ++index) {
		const OfficialRankApprovedInfTarget &approved =
			audit.rankApprovedTargets[index] ;								// 現在の合格組合せ。
		const auto device = deviceIndex.find( approved.deviceIdentity) ;	// 同じscanのdevice。
		// 適用性未合格、未知device、範囲外package参照を候補へ変換しない。
		if( approved.rankAudit.decision != OfficialDriverRankDecision::APPLICABLE ||
		   device == deviceIndex.end() ||
		   approved.auditedPackageIndex >= audit.auditedPackages.size()) {
			throw std::logic_error( "invalid Broadcom rank target") ;
		}

		const OfficialAuditedInfPackage &audited =
			audit.auditedPackages[approved.auditedPackageIndex] ;	// 対応する保持閉包。
		// 保護領域・固定profile・一INF閉包が揃わないpackageを候補へ変換しない。
		if( !audited.workspace ||
		   audited.profile != OfficialDriverAuditProfile::BROADCOM_NET_XTREME_E ||
		   audited.closure.packages.size() != 1U) {
			throw std::logic_error( "invalid Broadcom audited package") ;
		}

		const OfficialInfPackage &package = audited.closure.packages.front() ;	// INF明示metadata。
		// INFの明示版・publisher・Net classが揃わないpackageを公開しない。
		if( package.driverVersion.empty() || package.providerName.empty() ||
		   package.className != L"Net") {
			throw std::logic_error( "invalid Broadcom INF metadata") ;
		}

		// 同じdevice／同版は一候補とし、一device一候補選択を明瞭に保つ。
		if( !publishedVersions.emplace( approved.deviceIdentity, package.driverVersion).second) {
			continue ;
		}

		UpdateCandidate candidate ;	// 保持pathやPnP IDを含まない選択候補。
		candidate.identity		  = broadcomCandidateIdentity( session, index) ;
		candidate.deviceIdentity  = approved.deviceIdentity ;
		candidate.providerId	  = std::wstring( BROADCOM_NET_XTREME_PROVIDER_ID) ;
		candidate.packageIdentity = broadcomPackageIdentity( session, acquisition.acquisitionId) ;
		candidate.title			  = L"Broadcom NetXtreme-E Driver " + package.driverVersion ;
		candidate.manufacturer	  = device->second->manufacturer ;
		candidate.model			  = device->second->model ;
		candidate.driverClass	  = device->second->driverClass ;
		candidate.deviceClassGuid = device->second->deviceClassGuid ;
		candidate.provider		  = package.providerName ;
		candidate.version		  = package.driverVersion ;
		candidate.driverDate	  = formatBroadcomDriverDate( package.driverDate) ;
		candidate.sourceName	  = L"Broadcom NetXtreme-E official driver package" ;
		candidate.sourceLocation  = L"www.broadcom.com / docs.broadcom.com" ;
		candidate.maximumDownloadBytes = acquisition.byteCount ;
		candidate.action =
			classifyBroadcomAction( package.driverVersion, device->second->currentVersion) ;
		candidate.defaultPreference	  = CandidateDefaultPreference::NONE ;
		candidate.discoveryBasis	  = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
		candidate.audit				  = makeOfficialReadyCandidateAudit() ;
		candidate.current			  = false ;
		candidate.recommended		  = false ;
		candidate.installable		  = true ;
		candidate.eulaAccepted		  = true ;
		candidate.allContentCached	  = true ;
		candidate.rebootMayBeRequired = true ;
		// WUA optional候補ではなく、明示選択は探索区分で制御する。
		candidate.browseOnly = false ;
		candidates.push_back( std::move( candidate)) ;
	}

	// 監査合格対象があるのに公開候補が空となる不整合を成功扱いにしない。
	if( candidates.empty()) {
		throw std::logic_error( "empty Broadcom candidate publication") ;
	}

	return candidates ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::optional<BroadcomPreparedAuditSummary> BroadcomUpdateProvider::preparationAuditSummary(
	const ScanSessionId scanSessionId) const
{
	// 旧監査や未実行を合格集計として返さない。
	if( scanSessionId == 0U || scanSessionId != retainedSessionId_ ||
	   acquisition_.state != OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ||
	   preparedAudit_.summary.state == OfficialDriverPackageAuditState::NOT_STARTED) {
		return std::nullopt ;
	}

	return BroadcomPreparedAuditSummary{preparedAudit_.summary, preparedAudit_.applicability} ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::vector<OfficialPreparationTarget> makeBroadcomPreparationTargets(
	const OfficialReleaseRecord &release, const ScanSessionId scanSessionId,
	const std::uint64_t planId, const std::uint32_t deviceCount)
{
	// 専用parserを通った本文付き配布物だけを計画へ渡す。
	if( release.family != OfficialReleaseFamily::BROADCOM_NET_XTREME_E ||
	   release.license != OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD ||
	   release.parserRevision != 1U || release.downloadUrl.empty() || release.fileName.empty() ||
	   !validPreparationEulaText( release.eulaText)) {
		return {} ;
	}

	OfficialPreparationTarget  target{L"broadcom-target:" + std::to_wstring( scanSessionId) + L":" +
										  std::to_wstring( planId),
									  std::wstring( BROADCOM_NET_XTREME_PROVIDER_ID),
									  std::wstring( OFFICIAL_PAYLOAD_RESOURCE_ID),
									  L"broadcom-release:" + std::to_wstring( scanSessionId),
									  release.parserRevision,
									  ARCHIVE_BYTES,
									  deviceCount,
									  OfficialPreparationTerms::ACCEPTANCE_REQUIRED,
									  release.eulaRevision,
									  release.eulaText} ;	// 表示・同意・実行の全field照合対象。
	OfficialPreparationSession validation ;					// ID・件数・本文の共通契約を再利用する。
	// 共通の計画validatorが拒否する準備対象を公開しない。
	if( validation.initialize(
		   {scanSessionId, planId, DEFAULT_OFFICIAL_PREPARATION_LIMITS, {target}}) !=
	   OfficialPreparationError::NONE) {
		return {} ;
	}

	return {std::move( target)} ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::vector<OfficialPreparationTarget> BroadcomUpdateProvider::preparationTargets(
	const ScanSessionId scanSessionId, const std::uint64_t planId)
{
	// 古い計画や一度消費した配布物へ承認を再利用しない。
	if( scanSessionId == 0U || scanSessionId != retainedSessionId_ ||
	   GetCurrentThreadId() != ownerThreadId_ || acquisitionAttempted_ || planId == 0U ||
	   planId <= preparedPlanId_) {
		return {} ;
	}

	auto targets = makeBroadcomPreparationTargets( retainedRelease_, scanSessionId, planId,
												  retainedDeviceCount_) ;	// 有限な一対象。
	// 有効な準備対象がある場合にだけ次工程照合用の対象とplan IDを保持する。
	if( !targets.empty()) {
		preparedTarget_ = targets.front() ;
		preparedPlanId_ = planId ;
	}

	return targets ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError BroadcomUpdateProvider::refreshPreparedRelease( OfficialReleaseRecord &current,
														   bool					 &rejected)
{
	current	 = {} ;
	rejected = false ;
	std::wstring catalog ;	// 固定公式起点からの現行配布一覧。
	NativeError	 error = httpClient_.getUtf8TextForSource(
		 BROADCOM_CATALOG_URL, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID, 2ULL * 1024ULL * 1024ULL,
		 catalog) ;	// HTTP失敗を保持する診断値。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	std::optional<BroadcomDriverRelease> release ;	// 再確認した製品record。
	// 現在catalogのdocument identityが保持値から変わっていれば承認を転用しない。
	if( !parseBroadcomCatalog( catalog, release) || !release ||
	   release->contentId != retainedDocument_.contentId ||
	   release->assetVersion != retainedDocument_.assetVersion ||
	   release->documentApiUrl != retainedDocument_.documentApiUrl) {
		rejected = true ;
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH)) ;
	}

	std::wstring document ;	// 同じ配布物の公開document／license情報。
	error = httpClient_.getUtf8TextForSource( release->documentApiUrl,
											 OFFICIAL_SECONDARY_METADATA_RESOURCE_ID,
											 256ULL * 1024ULL, document) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	// 結合recordと一次・二次取得根拠を検証できなければ現在metadataを破棄する。
	if( !parseBroadcomPreparedRelease( document, *release, current) ||
	   !httpClient_.hasSourceEvidence( retainedSessionId_, BROADCOM_NET_XTREME_PROVIDER_ID,
									  OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ||
	   !httpClient_.hasSourceEvidence( retainedSessionId_, BROADCOM_NET_XTREME_PROVIDER_ID,
									  OFFICIAL_SECONDARY_METADATA_RESOURCE_ID)) {
		current	 = {} ;
		rejected = true ;
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialPreparationTransferResult BroadcomUpdateProvider::acquireForInspection(
	const OfficialPreparationTask &task, const PreparationCancellation &cancellation)
{
	// 対象再取得、古いsession・plan、承認snapshot差替え、別threadの要求を拒否する。
	if( !preparedTarget_ || acquisitionAttempted_ || task.operationId == 0U ||
	   task.scanSessionId != retainedSessionId_ || task.planId != preparedPlanId_ ||
	   task.target != *preparedTarget_ || GetCurrentThreadId() != ownerThreadId_) {
		return {OfficialPreparationItemState::REJECTED, static_cast<NativeError>( E_INVALIDARG), 0} ;
	}

	// 失敗・取消しでも次scanまで自動retryしない。
	acquisitionAttempted_ = true ;
	workspace_			  = std::make_unique<OfficialDownloadWorkspace>() ;
	acquisitionSession_	  = std::make_unique<OfficialAcquisitionSession>() ;
	const OfficialAcquisitionLimits limits{ARCHIVE_BYTES,
										   ARCHIVE_BYTES,
										   ARCHIVE_BYTES,
										   256ULL * 1024ULL * 1024ULL,
										   1U,
										   1U} ;	// 共通計画より広げない一配布物の取得ledger。
	// 保護領域と取得ledgerの初期化に失敗した元の診断値を保持する。
	NativeError error = workspace_->initialize( BROADCOM_NET_XTREME_PROVIDER_ID, retainedSessionId_) ;
	// 初期化失敗時はnetworkを呼ばず、元の診断値で終端にする。
	if( error == 0) {
		error = acquisitionSession_->initialize( retainedSessionId_, limits) ;
	}

	// 取得準備の失敗を未取得の結果として返し、payload取得へ進まない。
	if( error != 0) {
		return {OfficialPreparationItemState::FAILURE, error, 0} ;
	}

	OfficialHttpAcquisitionTransport transport( httpClient_) ;	// 共通取得層への非所有adapter。
	WindowsOfficialNetworkCostReader costReader ;				// Windowsの課金状態だけを照会する。
	const PreparedReleaseRefresh refresh = [this]( OfficialReleaseRecord &record, bool &rejected) {
		return refreshPreparedRelease( record, rejected) ;
	} ; // 起点を固定した再確認処理。
	const OfficialPreparationTransferResult transfer = acquirePreparedRelease(
		task, *preparedTarget_, retainedRelease_, refresh, *acquisitionSession_, *workspace_,
		transport, costReader, cancellation, acquisition_) ;	// Downloadと監査は別結果で保持する。
	// 検査用取得が成功したpayloadだけを固定profileの監査へ渡す。
	if( transfer.state == OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION) {
		static_cast<void>( auditBroadcomPreparedPackage(
			retainedSessionId_, acquisition_, retainedRelease_.publishedSha256, retainedDevices_,
			rankAuditor_, cancellation, preparedAudit_)) ;
	}

	// 内容拒否・非適用でも、完了したdownloadを失敗へ書き換えない。
	return transfer ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void BroadcomUpdateProvider::invalidatePreparation() noexcept
{
	installTargets_.clear() ;
	candidatesPublished_ = false ;
	preparedTarget_.reset() ;
	preparedPlanId_		  = 0U ;
	acquisitionAttempted_ = false ;
	// 閉包を元ZIPより先に解放する。
	preparedAudit_ = {} ;
	retainedDevices_.clear() ;
	acquisition_ = {} ;
	acquisitionSession_.reset() ;
	// 所有する既知の一時fileだけを既存RAIIで破棄する。
	workspace_.reset() ;
	retainedRelease_ = {} ;
	previousReleaseObservations_.clear() ;
	observationEnvironment_ = {} ;
	currentReleaseObservations_.clear() ;
	retainedDocument_	 = {} ;
	retainedSessionId_	 = 0U ;
	retainedDeviceCount_ = 0U ;
	ownerThreadId_		 = 0U ;
	httpClient_.invalidateSourceSession() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------

OfficialPreparationAuditReport makeBroadcomPreparationAuditReport(
	const ScanSessionId session, const std::wstring_view targetIdentity,
	const std::span<const OfficialCatalogDevice> devices, const OfficialDriverPackageAudit &audit)
{
	// 過大入力からID群を作らない。
	if( devices.empty() || devices.size() > 4096U) {
		throw std::logic_error( "invalid prepared audit display") ;
	}

	std::vector<std::wstring> candidateIdentities ;	// 検索時と同じ規則で作る既存候補ID群。
	candidateIdentities.reserve( devices.size()) ;
	// Broadcom対象系列だけに、既存表示行と一致する有限連番IDを生成する。
	for( std::size_t index = 0U; index < devices.size(); ++index) {
		const OfficialCatalogDevice &device = devices[index] ;	// 対応する既存の非機密device。
		// Broadcom対象外のdeviceを監査表示へ関連付けない。
		if( !broadcomNetxtremeEDevice( device)) {
			throw std::logic_error( "invalid prepared display device") ;
		}

		candidateIdentities.push_back( L"broadcom-info:" + std::to_wstring( session) + L":" +
									  // 表示済みopaque候補ID。
									  std::to_wstring( index)) ;
	}

	return makeOfficialPreparedAuditReport( OfficialDriverAuditProfile::BROADCOM_NET_XTREME_E,
										   session, targetIdentity, devices, candidateIdentities,
										   audit) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::optional<OfficialPreparationAuditReport> BroadcomUpdateProvider::preparationAuditReport(
	const ScanSessionId scanSessionId, const std::wstring_view targetIdentity)
{
	// 未取得・旧session・別thread・再発行の要求に導入候補を返さない。
	if( scanSessionId == 0U || scanSessionId != retainedSessionId_ || !preparedTarget_ ||
	   preparedTarget_->identity != targetIdentity ||
	   acquisition_.state != OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ||
	   GetCurrentThreadId() != ownerThreadId_ || candidatesPublished_) {
		return std::nullopt ;
	}

	OfficialPreparationAuditReport report = makeBroadcomPreparationAuditReport(
		scanSessionId, targetIdentity, retainedDevices_, preparedAudit_) ;	// 既存行の監査結果。
	// 拒否・失敗を選択可能候補へ読み替えない。
	if( report.content != CandidateAuditGateState::PASSED ||
	   report.applicability != CandidateAuditGateState::PASSED) {
		return report ;
	}

	std::vector<UpdateCandidate> candidates = makeBroadcomPreparedCandidates(
		scanSessionId, acquisition_, retainedDevices_, preparedAudit_) ;	// 全監査合格候補。
	std::unordered_map<std::wstring, BroadcomPreparedInstallTarget>
		installTargets ;	// 候補と保持物の新routing。
	installTargets.reserve( candidates.size()) ;
	std::set<std::pair<std::wstring, std::wstring>> routedVersions ;	// Device／版の重複集合。
	// 候補生成と同じ保持順・重複規則で、opaque IDを監査済みINFへ結び付ける。
	for( std::size_t index = 0U; index < preparedAudit_.rankApprovedTargets.size(); ++index) {
		const OfficialRankApprovedInfTarget &approved =
			preparedAudit_.rankApprovedTargets[index] ;	// 現在の監査合格組合せ。
		// 監査済みpackage範囲外の参照から導入routingを作らない。
		if( approved.auditedPackageIndex >= preparedAudit_.auditedPackages.size()) {
			throw std::logic_error( "invalid Broadcom route package") ;
		}

		const OfficialAuditedInfPackage &audited =
			preparedAudit_.auditedPackages[approved.auditedPackageIndex] ;	// 保持INF閉包。
		// 一INFに固定されていない閉包から導入routingを作らない。
		if( audited.closure.packages.size() != 1U) {
			throw std::logic_error( "invalid Broadcom route closure") ;
		}

		const OfficialInfPackage &package = audited.closure.packages.front() ;	// INF明示metadata。
		// 公開候補と同じdevice／version重複排除を適用する。
		if( !routedVersions.emplace( approved.deviceIdentity, package.driverVersion).second) {
			continue ;
		}

		const std::wstring identity =
			// 公開候補との完全一致ID。
			broadcomCandidateIdentity( scanSessionId, index) ;
		// 同じcandidate identityの導入routingが重複する場合は公開を中止する。
		if( !installTargets
				.emplace( identity,
						 BroadcomPreparedInstallTarget{
							 .packageIdentity =
								 broadcomPackageIdentity( scanSessionId, acquisition_.acquisitionId),
							 .deviceIdentity	  = approved.deviceIdentity,
							 .auditedPackageIndex = approved.auditedPackageIndex,
							 .rankAudit			  = approved.rankAudit})
				.second) {
			throw std::logic_error( "duplicate Broadcom install route") ;
		}
	}

	// 公開候補と導入routingの件数が一致しなければ状態を確定しない。
	if( installTargets.size() != candidates.size()) {
		throw std::logic_error( "Broadcom publication route mismatch") ;
	}

	report.publication.state = OfficialPreparationCandidatePublicationState::CANDIDATES_PUBLISHED ;
	report.publication.examinedPairCount = report.applicablePairCount ;
	report.publication.publishedCount	 = static_cast<std::uint32_t>( candidates.size()) ;
	report.publication.excludedPairCount =
		report.publication.examinedPairCount - report.publication.publishedCount ;
	// 重複除外された組合せがある場合は発行reportへ診断を残す。
	if( report.publication.excludedPairCount != 0U) {
		report.publication.firstError =
			static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_ALREADY_EXISTS)) ;
	}

	report.candidatePublicationAttempted = true ;
	report.publishedCandidates			 = std::move( candidates) ;
	// 全検証成功後だけProvider状態へ反映する。
	installTargets_		 = std::move( installTargets) ;
	candidatesPublished_ = true ;
	return report ;
}

} // namespace drivercrate
