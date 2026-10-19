//------------------------------------------------------------------------------
/**
 * @file official_bound_preparation.cpp
 * @brief 公式INFのbinding付き候補発行と導入。
 * @version 01.00.00
 * @date 2026/09/09
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  Intel実装を固定二profileへ共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 候補とroutingを同時に発行し、導入直前に保持fileとbindingを再確認します。
 */
//------------------------------------------------------------------------------

#include "platform/official_bound_preparation.h"
#include "core/candidate_audit.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/asix_update_provider.h"
#include "platform/official_download_workspace.h"
#include "platform/official_release_local_probe.h"
#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>
#include <optional>
#include <set>
#include <stdexcept>
#include <utility>
#include <vector>
namespace drivercrate {
namespace {
//------------------------------------------------------------------------------
/**
 * @brief 欠損版をReinstallへ補完せず、候補発行前の操作分類にだけ使う。
 *
 * @param[in] version INFまたは現在Windows nodeの原文version。
 * @return 4要素が0～65534で全要素0でない場合のpacked値。それ以外は空。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::uint64_t> parseBoundDriverVersion(
	const std::wstring_view version) noexcept
{
	std::array<std::uint16_t, 4> parts{} ;		// 確定した4要素の16-bit値。
	std::size_t					 partIndex{} ;	// 現在読み取る要素index。
	std::uint32_t				 value{} ;		// 上限判定前の現在要素値。
	bool						 hasDigit{} ;	// 現在要素へ一桁以上読んだ場合true。
	// 入力全体を一度だけ走査し、ASCII数字と三つの区切り以外を拒否する。
	for( const wchar_t character : version) {
		// 候補分類に使う版の数字を上限付き要素へ取り込む。
		if( character >= L'0' && character <= L'9') {
			const std::uint32_t digit =
				// 現在の十進一桁。
				static_cast<std::uint32_t>( character - L'0') ;
			// Windows版要素として許可した上限を超えさせない。
			if( value > (65534U - digit) / 10U) {
				return std::nullopt ;
			}

			value	 = value * 10U + digit ;
			hasDigit = true ;
			continue ;
		}

		// 不正区切り、空要素、過剰要素を含む版を拒否する。
		if( character != L'.' || !hasDigit || partIndex >= parts.size() - 1U) {
			return std::nullopt ;
		}

		parts[partIndex] = static_cast<std::uint16_t>( value) ;
		++partIndex ;
		value	 = 0U ;
		hasDigit = false ;
	}

	// 必要要素数の不足や末尾空要素を補完せず拒否する。
	if( !hasDigit || partIndex != parts.size() - 1U) {
		return std::nullopt ;
	}

	parts[partIndex] = static_cast<std::uint16_t>( value) ;
	// 全要素0は有効な選択版として発行しない。
	if( std::ranges::all_of( parts, []( const std::uint16_t part) { return part == 0U ; })) {
		return std::nullopt ;
	}

	std::uint64_t packed{} ;	// 左から16-bitずつ連結する比較用値。
	// 4要素を上位から連結し、通常の整数比較を版の辞書順比較と一致させる。
	for( const std::uint16_t part : parts) {
		packed = (packed << 16U) | part ;
	}

	return packed ;
}

//------------------------------------------------------------------------------
/**
 * @brief 両版が厳密解析済みの場合だけ操作を分類し、日付は使わない。
 *
 * @param[in] candidate 検証済み候補版のpacked値。
 * @param[in] current 同じdeviceの現在版packed値。
 * @return 数値比較に対応する更新、再導入または旧版への切替。
 */
//------------------------------------------------------------------------------
[[nodiscard]] DriverAction classifyBoundDriverAction( const std::uint64_t candidate,
													 const std::uint64_t current) noexcept
{
	// 厳密解析した候補版が現在版を上回る場合だけ通常更新にする。
	if( candidate > current) {
		return DriverAction::UPDATE ;
	}

	// 厳密解析した候補版が現在版を下回る場合は旧版への切替にする。
	if( candidate < current) {
		return DriverAction::DOWNGRADE ;
	}

	return DriverAction::REINSTALL ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_bound_preparation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isKnownUnsupportedIntelEthernetModel( const std::wstring_view model) noexcept
{
	constexpr std::array<std::wstring_view, 2> UNSUPPORTED_MODELS{
		L"HPE Synergy 4610C 10/25Gb Ethernet Adapter",
		L"HPE 10/25Gb Ethernet Adapter"} ;	// Intelの公式READMEが明示した非対応表示。
	// 二つの固定表示だけをWindowsのordinal case-insensitive比較で確認する。
	for( const std::wstring_view unsupported : UNSUPPORTED_MODELS) {
		// 既知の非対応model名と完全一致する場合だけ除外判定を返す。
		if( model.size() <= static_cast<std::size_t>( std::numeric_limits<int>::max()) &&
		   CompareStringOrdinal( model.data(), static_cast<int>( model.size()), unsupported.data(),
								static_cast<int>( unsupported.size()), TRUE) == CSTR_EQUAL) {
			return true ;
		}
	}

	return false ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 同じdecisionだけで一致とせず、PnP位置、score、full rankを全て比較する。
 *
 * @param[in] left 取得後監査で固定したrank結果。
 * @param[in] right Binding発行時に再取得したrank結果。
 * @return 全ての非機密rank fieldが一致する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool boundRankAuditsEqual( const OfficialDriverRankAudit &left,
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
 * @see src/platform/official_bound_preparation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------

void publishBoundPreparedCandidates( const OfficialDriverAuditProfile profile,
									const ScanSessionId session, const std::uint64_t acquisitionId,
									const std::uint64_t maximumDownloadBytes,
									const std::span<const OfficialCatalogDevice> devices,
									const OfficialDriverPackageAudit			&audit,
									const OfficialInfInstallBinder				&bindingCreator,
									const OfficialInfInstallBindingReleaser		&bindingReleaser,
									OfficialPreparationAuditReport				&report,
									BoundPreparedInstallTargets &installTargets) noexcept
{
	const bool asix = profile == OfficialDriverAuditProfile::ASIX_AX88179A ;	// ASIX固定分岐。
	// 共通化しても審査済み二profile以外へ能力を波及させない。
	const bool supported = asix || profile == OfficialDriverAuditProfile::INTEL_ETHERNET_SERVER2025 ;
	// 固定profileからだけProviderを解決し、未知profileは候補公開前に拒否する。
	const std::wstring_view provider =
		asix ? ASIX_AX88179A_PROVIDER_ID : INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ;
	// profile、予算、session、監査、未公開状態の前提を確認し既存routingへ混在させない。
	if( !supported || (asix && maximumDownloadBytes > 8ULL * 1024ULL * 1024ULL) || session == 0U ||
	   acquisitionId == 0U || maximumDownloadBytes == 0U || devices.empty() ||
	   devices.size() > 4096U || audit.scanSessionId != session ||
	   audit.rankApprovedTargets.empty() || audit.rankApprovedTargets.size() > 4096U ||
	   report.targetIdentity.empty() || report.providerId != provider ||
	   report.content != CandidateAuditGateState::PASSED ||
	   report.applicability != CandidateAuditGateState::PASSED ||
	   report.applicablePairCount != audit.rankApprovedTargets.size() ||
	   report.publication.state != OfficialPreparationCandidatePublicationState::NOT_STARTED ||
	   report.publication.examinedPairCount != 0U || report.publication.publishedCount != 0U ||
	   report.publication.excludedPairCount != 0U || report.publication.firstError != 0 ||
	   report.candidatePublicationAttempted || !report.publishedCandidates.empty() ||
	   !installTargets.empty()) {
		report.publication.state	  = OfficialPreparationCandidatePublicationState::FAILURE ;
		report.publication.firstError = static_cast<NativeError>( E_INVALIDARG) ;
		// 既存routingまたは監査不一致へ新しい候補を混在させない。
		return ;
	}

	// binding発行と失敗時解放の両callbackが揃うまで公開しない。
	if( !bindingCreator || !bindingReleaser) {
		report.publication.state	  = OfficialPreparationCandidatePublicationState::FAILURE ;
		report.publication.firstError = static_cast<NativeError>( E_NOTIMPL) ;
		// Bindingの発行とrollbackが対で揃うまで候補を公開しない。
		return ;
	}

	std::unordered_map<std::wstring_view, const OfficialCatalogDevice *>
								 deviceIndex ;							// 保持snapshotだけを参照するdevice索引。
	std::vector<UpdateCandidate> candidates ;							// UIへ追加する非機密の未選択候補群。
	BoundPreparedInstallTargets	 pendingTargets ;						// 全件成功後だけ返す新routing。
	std::set<std::pair<std::wstring, std::wstring>> publishedVersions ;	// Device／原文版集合。
	std::vector<std::uint64_t> issuedTokens ;							// 途中失敗時に破棄するDriver Store token群。
	report.publication.examinedPairCount = report.applicablePairCount ;

	try {
		deviceIndex.reserve( devices.size()) ;
		// 監査対象deviceを一意に索引化し、別sessionのidentity混入を先に拒否する。
		for( const OfficialCatalogDevice &device : devices) {
			const bool publishableOrExplicitlyRejected =
				(asix ? isAsixAx88179aDevice( device)
					  : (officialReleaseDeviceMatches(
							 OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025,
							 device) ||
						 isKnownUnsupportedIntelEthernetModel(
							 device.model))) ;	// 既知非対応OEMはbinding前の明示除外分岐へだけ渡す。
			// 公開可能でも明示除外でもないdeviceやidentity重複を拒否する。
			if( !publishableOrExplicitlyRejected ||
			   !deviceIndex.emplace( device.deviceIdentity, &device).second) {
				throw std::logic_error( "invalid bound prepared publication device") ;
			}
		}

		candidates.reserve( audit.rankApprovedTargets.size()) ;
		pendingTargets.reserve( audit.rankApprovedTargets.size()) ;
		issuedTokens.reserve( audit.rankApprovedTargets.size()) ;
		const std::wstring packageIdentity =
			std::wstring( asix ? L"asix-package:" : L"intel-ethernet-package:") +
			std::to_wstring( session) + L":" +
			// 同じ検証済み外側ZIPのopaque ID。
			std::to_wstring( acquisitionId) ;
		// G11-D合格順を有限連番の正本とし、候補とroutingを同じloopで生成する。
		for( std::size_t index = 0U; index < audit.rankApprovedTargets.size(); ++index) {
			const OfficialRankApprovedInfTarget &approved =
				audit.rankApprovedTargets[index] ;								// 現在の監査合格組合せ。
			const auto device = deviceIndex.find( approved.deviceIdentity) ;	// 保持deviceの索引結果。
			// rank未承認、未知device、範囲外package indexを公開要求へ含めない。
			if( approved.rankAudit.decision != OfficialDriverRankDecision::APPLICABLE ||
			   device == deviceIndex.end() ||
			   approved.auditedPackageIndex >= audit.auditedPackages.size()) {
				throw std::logic_error( "invalid bound prepared approved target") ;
			}

			const OfficialAuditedInfPackage &audited =
				audit.auditedPackages[approved.auditedPackageIndex] ;	// 保持INF閉包。
			// 監査済みworkspace、profile、単一packageの対応を確認する。
			if( !audited.workspace || audited.profile != profile ||
			   audited.closure.packages.size() != 1U) {
				throw std::logic_error( "invalid bound prepared audited package") ;
			}

			const OfficialInfPackage &package =
				// 明示INF metadata。
				audited.closure.packages.front() ;
			// Provider、明示版、Net classを備えないINFから候補を作らない。
			if( package.providerName.empty() || package.driverVersion.empty() ||
			   package.className != L"Net") {
				throw std::logic_error( "invalid bound prepared INF metadata") ;
			}

			// Intelの既知非対応modelは監査済みでも候補から除外する。
			if( !asix && isKnownUnsupportedIntelEthernetModel( device->second->model)) {
				++report.publication.excludedPairCount ;
				// 先行診断がない場合だけ非対応modelの診断を記録する。
				if( report.publication.firstError == 0) {
					report.publication.firstError =
						static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
				}

				// 既知の二製品は利用者同意でも候補へ戻さない。
				continue ;
			}

			const std::optional<std::uint64_t> candidateVersion =
				// INFの比較可能版。
				parseBoundDriverVersion( package.driverVersion) ;
			const std::optional<std::uint64_t> currentVersion = parseBoundDriverVersion(
				device->second->currentVersion) ;	// Scan時現在版の比較可能値。
			// 候補版または現在版が不明なら警告なしの再導入へ補完せず除外する。
			if( !candidateVersion || !currentVersion) {
				++report.publication.excludedPairCount ;
				// 先行診断がない場合だけ版metadata不正を記録する。
				if( report.publication.firstError == 0) {
					report.publication.firstError =
						static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
				}

				// 不明版を旧版警告なしのReinstallへ変換しない。
				continue ;
			}

			const std::pair<std::wstring, std::wstring> versionKey{
				approved.deviceIdentity, package.driverVersion} ;	// 発行済みdevice／原文版。
			// 同device・同一明示版を重ねて公開しない。
			if( publishedVersions.contains( versionKey)) {
				++report.publication.excludedPairCount ;
				// 先行診断がない場合だけ版重複の除外理由を記録する。
				if( report.publication.firstError == 0) {
					report.publication.firstError =
						static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_ALREADY_EXISTS)) ;
				}

				// 同device／完全一致版の複数INFを一候補へまとめる。
				continue ;
			}

			OfficialInfInstallBinding binding ;	// Driver Storeが再固定する非機密binding。
			const NativeError		  bindingError = bindingCreator(
				session, approved.deviceIdentity, *audited.workspace, package,
				device->second->currentProvider, device->second->currentVersion,
				device->second->currentDate, approved.rankAudit, binding) ;	// 個別発行結果。
			// 一deviceのbinding失敗を除外結果へ残し、他deviceの処理は続ける。
			if( bindingError != 0) {
				++report.publication.excludedPairCount ;
				// 最初のbinding失敗を保持し、不正な成功側診断値も失敗へ補正する。
				if( report.publication.firstError == 0) {
					report.publication.firstError =
						bindingError < 0 ? bindingError : static_cast<NativeError>( E_UNEXPECTED) ;
				}

				// 一deviceの状態変更で別deviceの合格候補を破棄しない。
				continue ;
			}

			// 一tokenを二候補へ使わない。
			if( std::ranges::find( issuedTokens, binding.token) != issuedTokens.end()) {
				throw std::logic_error( "duplicate bound token") ;
			}

			try {
				// Commit前のrollback対象へ登録する。
				issuedTokens.push_back( binding.token) ;
			} catch( ...) {
				// Token記録用memory確保に失敗しても、直前に発行した秘密記録を取り残さない。
				static_cast<void>( bindingReleaser( session, binding.token)) ;
				throw ;
			}

			// 発行bindingを現在版、候補版、日付、rank証拠へ再照合する。
			if( binding.token == 0U || binding.currentProvider != device->second->currentProvider ||
			   binding.currentVersion != device->second->currentVersion ||
			   binding.currentDate != device->second->currentDate ||
			   binding.candidateProvider != package.providerName ||
			   binding.candidateVersion != package.driverVersion || binding.candidateDate.empty() ||
			   !boundRankAuditsEqual( binding.rankAudit, approved.rankAudit)) {
				throw std::logic_error( "invalid bound prepared install binding") ;
			}

			// 公開版keyの重複挿入という内部不整合を拒否する。
			if( !publishedVersions.emplace( versionKey).second) {
				throw std::logic_error( "duplicate bound prepared published version") ;
			}

			const std::wstring candidateIdentity =
				std::wstring( asix ? L"asix-driver:" : L"intel-ethernet-driver:") +
				// Opaque候補ID。
				std::to_wstring( session) + L":" + std::to_wstring( index) ;
			UpdateCandidate candidate ;	// 秘密pathやPnP IDを含まない未選択候補。
			candidate.identity		  = candidateIdentity ;
			candidate.deviceIdentity  = approved.deviceIdentity ;
			candidate.providerId	  = std::wstring( provider) ;
			candidate.packageIdentity = packageIdentity ;
			candidate.title =
				std::wstring( asix ? L"ASIX AX88179A Driver " : L"Intel Ethernet Driver ") +
				binding.candidateVersion ;
			candidate.manufacturer	  = device->second->manufacturer ;
			candidate.model			  = device->second->model ;
			candidate.driverClass	  = device->second->driverClass ;
			candidate.deviceClassGuid = device->second->deviceClassGuid ;
			candidate.provider		  = binding.candidateProvider ;
			candidate.version		  = binding.candidateVersion ;
			candidate.driverDate	  = binding.candidateDate ;
			candidate.sourceName	  = asix ? L"ASIX AX88179A official driver package"
											 : L"Intel Ethernet official driver package" ;
			candidate.sourceLocation =
				asix ? L"www.asix.com.tw" : L"www.intel.com / downloadmirror.intel.com" ;
			candidate.maximumDownloadBytes = maximumDownloadBytes ;
			candidate.action = classifyBoundDriverAction( *candidateVersion, *currentVersion) ;
			candidate.defaultPreference	  = CandidateDefaultPreference::NONE ;
			candidate.discoveryBasis	  = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
			candidate.audit				  = makeOfficialReadyCandidateAudit() ;
			candidate.current			  = false ;
			candidate.recommended		  = false ;
			candidate.installable		  = true ;
			candidate.eulaAccepted		  = true ;
			candidate.allContentCached	  = true ;
			candidate.rebootMayBeRequired = true ;
			candidate.browseOnly		  = false ;

			BoundPreparedInstallTarget route ;	// 候補と保持物の一対一routing。
			route.prepared.packageIdentity	   = packageIdentity ;
			route.prepared.deviceIdentity	   = approved.deviceIdentity ;
			route.prepared.auditedPackageIndex = approved.auditedPackageIndex ;
			route.prepared.rankAudit		   = approved.rankAudit ;
			route.binding					   = std::move( binding) ;
			// 同じ候補identityへのrouting重複をcommit前に拒否する。
			if( !pendingTargets.emplace( candidateIdentity, std::move( route)).second) {
				throw std::logic_error( "duplicate bound prepared install route") ;
			}

			candidates.push_back( std::move( candidate)) ;
		}

		// 候補と導入routingの件数が一致しなければ公開しない。
		if( pendingTargets.size() != candidates.size()) {
			throw std::logic_error( "bound prepared publication route mismatch") ;
		}
	} catch( ...) {
		// 外部bindingを全て戻してから部分候補を破棄し、元の監査reportは残す。
		for( const std::uint64_t token : issuedTokens)	// 今回発行に成功した一つのtoken。
		{
			static_cast<void>( bindingReleaser( session, token)) ;
		}

		report.publication.state		  = OfficialPreparationCandidatePublicationState::FAILURE ;
		report.publication.publishedCount = 0U ;
		report.publication.excludedPairCount = report.publication.examinedPairCount ;
		report.publication.firstError		 = static_cast<NativeError>( E_UNEXPECTED) ;
		report.candidatePublicationAttempted = false ;
		report.publishedCandidates.clear() ;
		installTargets.clear() ;
		// 全件commitできない状態を部分成功として返さない。
		return ;
	}

	report.publication.publishedCount = static_cast<std::uint32_t>( candidates.size()) ;
	// 監査合格でも発行対象0件を独立した結果として返す。
	if( candidates.empty()) {
		report.publication.state =
			OfficialPreparationCandidatePublicationState::NO_ELIGIBLE_CANDIDATES ;
		// 先行の除外理由がない場合だけ対象なしの診断を付ける。
		if( report.publication.firstError == 0) {
			report.publication.firstError =
				static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_FOUND)) ;
		}

		// 監査合格と発行0件を別状態のまま返す。
		return ;
	}

	report.publication.state = OfficialPreparationCandidatePublicationState::CANDIDATES_PUBLISHED ;
	report.candidatePublicationAttempted = true ;
	report.publishedCandidates			 = std::move( candidates) ;
	// 全候補検証後だけrouting ownershipを返す。
	installTargets = std::move( pendingTargets) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_bound_preparation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------

InstallResult executeBoundPreparedInstall(
	const OfficialDriverAuditProfile profile, const BoundPreparedInstallContext &context,
	const std::span<const std::wstring> identities, const PreparedInfReverifier &reverifier,
	const OfficialInfRankAuditor &rankAuditor, const OfficialBoundInfInstaller &boundInstaller,
	const std::uintptr_t parentWindowNative, const ProviderProgressCallback &progressCallback)
{
	const bool asix = profile == OfficialDriverAuditProfile::ASIX_AX88179A ;	// ASIXのclient境界。
	// 導入契約と試験を持つ固定二profileだけを受理する。
	const bool supported = asix || profile == OfficialDriverAuditProfile::INTEL_ETHERNET_SERVER2025 ;
	// OS条件は固定profile別に照合し、未知profileをIntelへ読み替えない。
	const bool osMatches = asix ? (!context.windowsServer && context.windowsBuild >= 10240U)
								: officialReleaseOperatingSystemMatches(
									  OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025,
									  context.windowsServer, context.windowsBuild) ;
	std::unordered_map<std::wstring, PreparedInfInstallTarget>
				 preparedTargets ;	// 共通executorへ渡す候補ID別の非機密routing copy。
	std::wstring packageIdentity ;	// 全発行候補が共有する取得identity由来のopaque package ID。
	bool		 routesValid =
		supported && osMatches && context.scanSessionId != 0U && context.acquisition != nullptr &&
		context.acquisition->scanSessionId == context.scanSessionId && context.targets != nullptr &&
		!context.targets->empty() && context.targets->size() <= 4096U &&
		!context.auditedPackages.empty() && context.auditedPackages.size() <= 32U &&
		(asix || context.acquisition->publishedSha256Verified) &&
		(!asix || context.acquisition->byteCount <= 8ULL * 1024ULL * 1024ULL) &&
		context.sourceEvidenceConfirmed &&
		// 全routingの初期検証結果。
		static_cast<bool>( boundInstaller) ;
	// 基本routing条件が成立した場合だけ保持対象を共通executor向けに検証する。
	if( routesValid) {
		preparedTargets.reserve( context.targets->size()) ;
		// Provider保持routingを一件ずつ検証し、共通executor用の一時copyへ集約する。
		// `entry`は現在検証中の候補IDと固定profileのroutingである。
		for( const auto &entry : *context.targets) {
			const BoundPreparedInstallTarget &route = entry.second ;	// 現在の保持routing。
			// identity、profile、package、binding、一意性の不整合を検出して全routingを拒否する。
			if( entry.first.empty() || route.prepared.packageIdentity.empty() ||
			   route.prepared.auditedPackageIndex >= context.auditedPackages.size() ||
			   context.auditedPackages[route.prepared.auditedPackageIndex].profile != profile ||
			   route.prepared.deviceIdentity.empty() || route.binding.token == 0U ||
			   (!packageIdentity.empty() && packageIdentity != route.prepared.packageIdentity) ||
			   !preparedTargets.emplace( entry.first, route.prepared).second) {
				routesValid = false ;
				break ;
			}

			// 最初のroutingから全対象が共有すべきpackage identityを確定する。
			if( packageIdentity.empty()) {
				packageIdentity = route.prepared.packageIdentity ;
			}
		}
	}

	const PreparedInfInstallContext preparedContext{
		.scanSessionId			 = context.scanSessionId,
		.acquisition			 = context.acquisition,
		.packageIdentity		 = packageIdentity,
		.targets				 = &preparedTargets,
		.auditedPackages		 = context.auditedPackages,
		.sourceEvidenceConfirmed = routesValid,
	} ; // Provider外へ保存しない非所有executor入力。
	const PreparedVerifiedInfInstaller installer = [&context, &boundInstaller](
													   const ScanSessionId	   session,
													   const std::wstring_view deviceIdentity,
													   const std::wstring_view infPath,
													   const std::wstring_view expectedProvider,
													   const std::wstring_view expectedVersion,
													   const std::uintptr_t	   parentWindow,
													   bool					  &rebootRequired) {
		const BoundPreparedInstallTarget
			*selectedRoute{} ;	// Callback入力と一意に一致する保持bindingの非所有参照。
		// 保持routing集合がなければ導入先を解決しない。
		if( context.targets == nullptr) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		// 最大4096件の保持routingからdevice、INF path、Provider、版が一致する一件を探す。
		// `entry`は現在照合中の候補IDと固定profileのroutingである。
		for( const auto &entry : *context.targets) {
			const BoundPreparedInstallTarget &route = entry.second ;	// 照合中routing。
			// 要求deviceと異なるroutingや範囲外packageを照合対象から除外する。
			if( route.prepared.deviceIdentity != deviceIdentity ||
			   route.prepared.auditedPackageIndex >= context.auditedPackages.size()) {
				continue ;
			}

			const OfficialAuditedInfPackage &audited =
				context
					.auditedPackages[route.prepared.auditedPackageIndex] ;	// 候補に固定したINF閉包。
			// 所有workspaceと単一INFの前提が失われた監査対象を拒否する。
			if( !audited.workspace || audited.closure.packages.size() != 1U) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			const OfficialInfPackage &package =
				// 一意な監査済みINF metadata。
				audited.closure.packages.front() ;
			// INF path、Provider、版が要求と異なるroutingを採用しない。
			if( audited.workspace->path( package.infRelativePath) != infPath ||
			   package.providerName != expectedProvider ||
			   package.driverVersion != expectedVersion) {
				continue ;
			}

			// 複数routingが同じ導入要求へ一致する曖昧性を拒否する。
			if( selectedRoute != nullptr) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			selectedRoute = &route ;
		}

		// 一意なroutingとbound installerが揃わなければ導入しない。
		if( selectedRoute == nullptr || !boundInstaller) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		const OfficialAuditedInfPackage &audited =
			context.auditedPackages[selectedRoute->prepared
										.auditedPackageIndex] ;	// 選択候補の保持閉包。
		const OfficialInfPackage &package =
			// 専用導入境界へ渡す監査済みINF。
			audited.closure.packages.front() ;
		return boundInstaller( session, deviceIdentity, *audited.workspace, package,
							  selectedRoute->binding, parentWindow, rebootRequired) ;
	} ; // UI入力からbindingを作らず、Provider保持routingだけから解決するadapter。

	const PreparedInfInstallPolicy policy{
		.providerId =
			asix ? ASIX_AX88179A_PROVIDER_ID : INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID,
		.resourceId = OFFICIAL_PAYLOAD_RESOURCE_ID} ;	// 固定profileの許可組合せ。
	return executePreparedInfInstall( policy, preparedContext, identities, reverifier, rankAuditor,
									 installer, parentWindowNative, progressCallback) ;
}

} // namespace drivercrate
