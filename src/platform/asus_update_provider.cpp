//------------------------------------------------------------------------------
/**
 * @file asus_update_provider.cpp
 * @brief ASUS公式support page Provider実装。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Package内容監査接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Local PnP／Rank監査接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  候補化とinstall routing接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  Rank位置の明示比較へ修正。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note ASUS端末でだけ公式pageとpayloadを取得し、全INFの選択閉包、CAT、publisher、local PnP／Rankを検証し、全gate合格候補だけを再検証して
 *       Driver Store導入境界へroutingします。
 */
//------------------------------------------------------------------------------

#include "platform/asus_update_provider.h"

#include "core/candidate_audit.h"
#include "core/official_source_policy.h"
#include "core/package_selection.h"
#include "core/provider_registry.h"
#include "platform/asus_catalog_parser.h"
#include "platform/asus_system_identity.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::uint64_t MAXIMUM_PAGE_BYTES = 8ULL * 1024ULL * 1024ULL ;	// HTML応答上限。
// 単一payload取得を制限するbyte上限。
constexpr std::uint64_t MAXIMUM_PAYLOAD_BYTES = 4ULL * 1024ULL * 1024ULL * 1024ULL ;
// 一scan sessionでASUS Providerに割り当てる総取得byte上限。
constexpr std::uint64_t MAXIMUM_PROVIDER_BYTES = 16ULL * 1024ULL * 1024ULL * 1024ULL ;
// 取得開始時に保護workspace側へ残す空き容量の最低byte数。
constexpr std::uint64_t MINIMUM_FREE_BYTES		= 1ULL * 1024ULL * 1024ULL * 1024ULL ;
constexpr std::uint32_t MAXIMUM_PROVIDER_FILES	= 64U ;		// 一scanで取得できるarchive数上限。
constexpr std::size_t	MAXIMUM_CANDIDATE_COUNT = 4'096U ;	// 一scanで公開するASUS候補数上限。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief ASUS用の有限取得予算を生成する。
 *
 * 公開sizeが丸め値のためfile上限を予約値に使い、無制限取得を許可しない。
 * @return 一file、Provider、session、disk reserveの固定上限。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialAcquisitionLimits asusAcquisitionLimits() noexcept
{
	return OfficialAcquisitionLimits{.maximumFileBytes	   = MAXIMUM_PAYLOAD_BYTES,
									 .maximumProviderBytes = MAXIMUM_PROVIDER_BYTES,
									 .maximumSessionBytes  = MAXIMUM_PROVIDER_BYTES,
									 .minimumFreeBytes	   = MINIMUM_FREE_BYTES,
									 .maximumProviderFiles = MAXIMUM_PROVIDER_FILES,
									 .maximumSessionFiles  = MAXIMUM_PROVIDER_FILES} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 取得計画のarchive形式を固定する。
 *
 * 外部titleや取得pathではなく、G11-B計画時に生成した「.zip」／「.cab」だけから内容監査方式を決定する。
 *
 * @param[in] workspaceFileName Providerが固定した内部file名。
 * @param[out] format 成功時のZIPまたはCAB parser種別。
 * @return 固定拡張子を認識できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool acquisitionArchiveFormat( const std::wstring_view		 workspaceFileName,
											OfficialDriverArchiveFormat &format) noexcept
{
	// 計画上のZIP file名だけをZIP decoderへ対応付ける。
	if( workspaceFileName.ends_with( L".zip")) {
		format = OfficialDriverArchiveFormat::ZIP ;
		return true ;
	}

	// 計画上のCAB file名だけをCAB decoderへ対応付ける。
	if( workspaceFileName.ends_with( L".cab")) {
		format = OfficialDriverArchiveFormat::CABINET ;
		return true ;
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief Driver versionを4要素の数値へ変換する。
 *
 * Version文字列を正規化または補完せず、比較不能を維持する。
 *
 * @param[in] version INFまたは現在driverのversion文字列。
 * @return 4要素を厳密に解析できた場合は数値配列、それ以外は空。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::array<std::uint32_t, 4>> parseVersion(
	const std::wstring_view version) noexcept
{
	std::array<std::uint32_t, 4> parts{} ;		// 解析済みversion要素。
	std::size_t					 partIndex{} ;	// 現在確定する要素index。
	std::uint64_t				 value{} ;		// 現在要素のoverflow検査用値。
	bool						 hasDigit{} ;	// 現在要素に数字が一つ以上ある場合true。
	// 全文字を一度だけ読み、4要素以外と32-bit超過を拒否する。
	for( const wchar_t character : version) {
		// ASCII数字を現在のversion componentへ取り込み、有限整数として保持する。
		if( character >= L'0' && character <= L'9') {
			const std::uint32_t digit =
				// 現在の10進一桁。
				static_cast<std::uint32_t>( character - L'0') ;
			// version componentの桁追加でuint32上限を超える前に拒否する。
			if( value > (std::numeric_limits<std::uint32_t>::max() - digit) / 10U) {
				return std::nullopt ;
			}

			value	 = value * 10U + digit ;
			hasDigit = true ;
			continue ;
		}

		// 不正区切り・空component・過剰componentを四要素版として受理しない。
		if( character != L'.' || !hasDigit || partIndex >= parts.size() - 1U) {
			return std::nullopt ;
		}

		parts[partIndex] = static_cast<std::uint32_t>( value) ;
		++partIndex ;
		value	 = 0U ;
		hasDigit = false ;
	}

	// 末尾componentを含めて四要素が揃わない版を数値比較しない。
	if( !hasDigit || partIndex != parts.size() - 1U) {
		return std::nullopt ;
	}

	parts[partIndex] = static_cast<std::uint32_t>( value) ;
	return parts ;
}

//------------------------------------------------------------------------------
/**
 * @brief 検証済みdriver versionを現在版に対するactionへ分類する。
 *
 * 比較不能時は新しい版と推測せず明示再導入へ分類する。
 *
 * @param[in] candidateVersion INFが宣言した4要素version。
 * @param[in] currentVersion SetupAPIが返した現在driver version。
 * @return 数値比較結果に対応するUpdate、ReinstallまたはDowngrade。
 */
//------------------------------------------------------------------------------
[[nodiscard]] DriverAction classifyAction( const std::wstring_view candidateVersion,
										  const std::wstring_view currentVersion) noexcept
{
	const auto candidate = parseVersion( candidateVersion) ;	// INF version解析結果。
	const auto current	 = parseVersion( currentVersion) ;		// 現在version解析結果。
	// 数値比較できない版の組合せを更新または旧版と断定せず再導入区分にする。
	if( !candidate.has_value() || !current.has_value()) {
		return DriverAction::REINSTALL ;
	}

	// 比較可能な候補版が現在版より大きい場合だけ更新区分にする。
	if( candidate.value() > current.value()) {
		return DriverAction::UPDATE ;
	}

	// 比較可能な候補版が現在版より小さい場合だけ旧版区分にする。
	if( candidate.value() < current.value()) {
		return DriverAction::DOWNGRADE ;
	}

	return DriverAction::REINSTALL ;
}

//------------------------------------------------------------------------------
/**
 * @brief INF日付をUIの年月日順へ変換する。
 *
 * 日付は表示専用とし、適用性または新旧判定に使用しない。
 *
 * @param[in] value INF DriverVerの`MM/DD/YYYY`日付。
 * @return `YYYY/MM/DD`形式。形式不正時は空文字列。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring formatDriverDate( const std::wstring_view value)
{
	// INF日付の固定書式が一致しなければ表示用日付へ変換しない。
	if( value.size() != 10U || value[2U] != L'/' || value[5U] != L'/') {
		return {} ;
	}

	// Separator以外をASCII数字へ限定する。
	for( std::size_t index = 0U; index < value.size(); ++index) {
		// 日付の固定slash位置は数字検証から除く。
		if( index == 2U || index == 5U) {
			continue ;
		}

		// 日付fieldに数字以外が含まれる場合は空表示として返す。
		if( value[index] < L'0' || value[index] > L'9') {
			return {} ;
		}
	}

	return std::wstring( value.substr( 6U, 4U)) + L"/" + std::wstring( value.substr( 0U, 2U)) + L"/" +
		   std::wstring( value.substr( 3U, 2U)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つのG11-D監査結果が完全一致するか確認する。
 *
 * Session中にdevice状態が変化した場合はinstallを拒否する。
 *
 * @param[in] left Scan時のrank監査結果。
 * @param[in] right Install直前のrank監査結果。
 * @return 全判断根拠が完全一致する場合は`true`。
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
 * @see src/platform/asus_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
AsusUpdateProvider::AsusUpdateProvider( AsusOfficialInfRankAuditor rankAuditor,
									   AsusVerifiedInfInstaller	  installer)
	: rankAuditor_( std::move( rankAuditor)), installer_( std::move( installer))
{
}

AsusUpdateProvider::~AsusUpdateProvider() = default ;

//------------------------------------------------------------------------------
/**
 * @see src/platform/asus_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult AsusUpdateProvider::scan( const ScanSessionId							 scanSessionId,
									const std::span<const OfficialCatalogDevice> devices,
									const LocalHardwareIdMatcher				&hardwareIdMatcher,
									const ProviderProgressCallback				&progressCallback)
{
	static_cast<void>( hardwareIdMatcher) ;
	invalidateScanSession() ;
	ScanResult result ;	// ASUS Provider単独のscan結果。
	result.scanSessionId = scanSessionId ;
	result.outcome		 = OutcomeCode::FAILURE ;
	result.state		 = ProviderScanState::FAILURE ;
	// 未発行sessionと必須callback欠落をscan開始前に拒否する。
	if( scanSessionId == 0U || !progressCallback || !rankAuditor_ || !installer_) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
					  .percentComplete = 0,
					  .completedItems  = 0,
					  .totalItems	   = 1}) ;

	AsusSupportPageRequest request ;											// Local SMBIOSとWindows世代から固定するpage要求。
	bool				   applicable{} ;										// ASUS clientとして安全に識別できた場合true。
	NativeError error = readLocalAsusSupportPageRequest( request, applicable) ;	// 判定結果。
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	// ASUS対象systemでない場合は通信せず対象外を返す。
	if( !applicable) {
		result.succeeded = true ;
		result.outcome	 = OutcomeCode::SUCCESS ;
		result.state	 = ProviderScanState::NOT_APPLICABLE ;
		progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
						  .percentComplete = 100,
						  .completedItems  = 1,
						  .totalItems	   = 1}) ;
		return result ;
	}

	error = httpClient_.beginSourceSession( scanSessionId, ASUS_PROVIDER_ID) ;
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	std::wstring pageHtml ;	// UTF-16へ変換済みのASUS製品別support page HTML。
	error = httpClient_.getUtf8TextForSource( request.pageUrl, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
											 MAXIMUM_PAGE_BYTES, pageHtml) ;
	// page取得失敗時はsource sessionを失効させて診断を返す。
	if( error != 0) {
		invalidateScanSession() ;
		result.error = error ;
		return result ;
	}

	std::vector<AsusDriverPageEntry> entries ;	// Model／OS／schema検証済みの検査前metadata。
	// page schemaの不整合はmetadata拒否としてsessionを失効させる。
	if( !parseAsusDriverPageHtml( pageHtml, request.model, request.osName, entries)) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		invalidateScanSession() ;
		return result ;
	}

	// 検証済みpageに対象がない場合は候補なしを返し、保持sessionを終了する。
	if( entries.empty()) {
		result.succeeded = true ;
		result.outcome	 = OutcomeCode::SUCCESS ;
		result.state	 = ProviderScanState::NO_CANDIDATES ;
		progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
						  .percentComplete = 100,
						  .completedItems  = 1,
						  .totalItems	   = 1}) ;
		invalidateScanSession() ;
		return result ;
	}

	error = makeAsusPackageAcquisitionPlan( entries, acquisitionPlan_) ;
	// 取得計画を検証できない場合はmetadata拒否としてsessionを終了する。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		invalidateScanSession() ;
		return result ;
	}

	try {
		workspace_			= std::make_unique<OfficialDownloadWorkspace>() ;
		acquisitionSession_ = std::make_unique<OfficialAcquisitionSession>() ;
		localDevices_.assign( devices.begin(), devices.end()) ;
	} catch( const std::bad_alloc &) {
		invalidateScanSession() ;
		result.error = static_cast<NativeError>( E_OUTOFMEMORY) ;
		return result ;
	}

	error = workspace_->initialize( L"asus-official", scanSessionId) ;
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = acquisitionSession_->initialize( scanSessionId, asusAcquisitionLimits()) ;
	}

	// 取得準備に失敗した場合はsessionを失効させて後続取得を行わない。
	if( error != 0) {
		invalidateScanSession() ;
		result.error = error ;
		return result ;
	}

	scanSessionId_						= scanSessionId ;
	ownerThreadId_						= GetCurrentThreadId() ;
	result.coverage.eligibleDeviceCount = devices.size() ;
	const std::size_t totalArchives = acquisitionPlan_.size() ;	// Scan開始時に固定した総archive数。

	try {
		WindowsOfficialNetworkCostReader costReader ;						// Machine-wide network cost取得境界。
		NativeError						 firstError{} ;						// 最初の個別archive失敗診断値。
		ProviderScanState firstFailureState{ProviderScanState::FAILURE} ;	// 最初に失敗した監査段階。
		bool			  allArchivesAssessed{true} ;						// 全公開archiveをG11-Dまで確認できた場合true。
		std::size_t		  candidateOrdinal{} ;								// Opaque candidate identity用session内連番。
		std::size_t		  processedArchives{} ;								// 成否を確定したarchive試行数。
		result.candidates.reserve( std::min<std::size_t>( devices.size(), MAXIMUM_PROVIDER_FILES)) ;

		// 公式pageの全archiveを一度ずつ取得し、内容とlocal PnPを監査する。
		for( std::size_t planIndex = 0U; planIndex < totalArchives; ++planIndex) {
			const AsusPackageAcquisitionPlanEntry &plan =
				acquisitionPlan_[planIndex] ;							// 現在取得する公開archive計画。
			const AsusDriverPageEntry &metadata = entries[planIndex] ;	// 対応する表示metadata。
			const std::uint64_t		   completedBefore = planIndex ;	// 現在archive前の完了件数。
			const HttpDownloadProgressCallback downloadProgress =
				[&progressCallback, completedBefore, totalArchives]( const std::uint64_t received,
																	const std::uint64_t expected) {
					// 現在fileの受信済み割合。期待長が不明な間は0に固定する。
					const std::uint64_t filePercent =
						expected == 0U ? 0U
									   : std::min<std::uint64_t>( 100U, received * 100U / expected) ;
					// 完了archive件数と現在fileの受信率を、取得段階の70%幅へ換算した値。
					const std::uint64_t scaled =
						(completedBefore * 70U + filePercent * 70U / 100U) / totalArchives ;
					progressCallback( {.stage		   = ProviderStage::DOWNLOADING,
									  .percentComplete = static_cast<std::uint32_t>( 10U + scaled),
									  .completedItems  = completedBefore,
									  .totalItems	   = totalArchives}) ;
				} ; // 一archiveの受信量をscan全体10～80%へ変換する関数。

			OfficialAcquisitionResult acquisition ;	// G11-Bが固定する外側archive取得結果。
			error = acquireForInspection( scanSessionId, plan.opaqueId, false, costReader,
										 downloadProgress, {}, acquisition) ;
			processedArchives = planIndex + 1U ;
			// archive取得失敗を記録し、同意待ちによる中断と他archiveへの継続を分ける。
			if( error != 0) {
				allArchivesAssessed = false ;
				// 後続archiveの失敗で上書きしないよう最初の取得失敗を保持する。
				if( firstError == 0) {
					firstError		  = error ;
					firstFailureState = ProviderScanState::DOWNLOAD_FAILED ;
				}

				// Cost同意待ちは残りも同じnetwork条件になるため追加通信を開始しない。
				if( acquisition.state == OfficialAcquisitionState::AWAITING_NETWORK_CONSENT) {
					break ;
				}

				continue ;
			}

			AsusDriverPackageAuditSummary contentSummary ;	// G11-C／署名監査の件数結果。
			error = auditAcquiredPackage( scanSessionId, plan.opaqueId, acquisition, contentSummary) ;
			// 内容監査に失敗したarchiveは候補化せず、部分失敗として後続を確認する。
			if( error != 0) {
				allArchivesAssessed = false ;
				// 最初の内容監査失敗を処理障害または内容拒否の区分付きで保持する。
				if( firstError == 0) {
					firstError		  = error ;
					firstFailureState = contentSummary.state == AsusDriverPackageAuditState::FAILURE
											? ProviderScanState::FAILURE
											: ProviderScanState::CONTENT_REJECTED ;
				}

				continue ;
			}

			// 内容監査済みでないarchiveを適用性照合へ渡さない。
			if( contentSummary.state != AsusDriverPackageAuditState::AUDITED) {
				continue ;
			}

			AsusDriverApplicabilitySummary applicability ;	// G11-Dの組合せ監査結果。
			error = auditRetainedPackageApplicability( scanSessionId, plan.opaqueId, rankAuditor_,
													  applicability) ;
			// 適用性監査処理の失敗を記録して当該archiveを除外する。
			if( error != 0) {
				allArchivesAssessed = false ;
				// 適用性監査の最初の失敗原因を後続の結果で上書きしない。
				if( firstError == 0) {
					firstError		  = error ;
					firstFailureState = ProviderScanState::FAILURE ;
				}

				continue ;
			}

			// 一組でも監査errorがあれば全archive正常評価済みとはしない。
			if( applicability.firstPairError != 0) {
				allArchivesAssessed = false ;
				// 個別組合せの最初のerrorをProvider全体の診断へ引き継ぐ。
				if( firstError == 0) {
					firstError		  = applicability.firstPairError ;
					firstFailureState = ProviderScanState::FAILURE ;
				}
			}

			const std::size_t  archiveIndex = auditedArchives_.size() - 1U ;	// 保持archive index。
			AuditedArchive	  &archive		= auditedArchives_[archiveIndex] ;	// 監査済みarchive。
			const std::wstring packageIdentity = L"asus-package:" + std::to_wstring( scanSessionId) +
												 L":" +
												 // URLを含まない同一payload ID。
												 std::to_wstring( planIndex) ;
			// G11-DでApplicableとなった組合せだけを候補とinstall routingへ登録する。
			for( const AsusRankApprovedInfTarget &approved : archive.package.rankApprovedTargets) {
				// 公開候補数が上限へ達した場合は無制限に候補を追加しない。
				if( candidateOrdinal >= MAXIMUM_CANDIDATE_COUNT) {
					throw std::length_error( "ASUS candidate limit exceeded") ;
				}

				// 監査済みpackage範囲外の参照を候補routingへ登録しない。
				if( approved.auditedPackageIndex >= archive.package.auditedPackages.size()) {
					throw std::logic_error( "invalid ASUS audited package index") ;
				}

				const auto device =
					std::find_if( localDevices_.begin(), localDevices_.end(),
								 [&approved]( const OfficialCatalogDevice &value) {
									 return value.deviceIdentity == approved.deviceIdentity ;
								 }) ; // 表示device。
				// 保持device集合にないidentityを導入候補へ結び付けない。
				if( device == localDevices_.end()) {
					throw std::logic_error( "invalid ASUS device identity") ;
				}

				const OfficialInfPackage &package =
					archive.package.auditedPackages[approved.auditedPackageIndex]
						.closure.packages.front() ;	// 全監査を通過したINF metadata。
				const std::wstring identity = L"asus-candidate:" + std::to_wstring( scanSessionId) +
											  L":" +
											  // Session内だけで有効な候補ID。
											  std::to_wstring( candidateOrdinal) ;
				const DriverAction action =
					// 新旧分類。
					classifyAction( package.driverVersion, device->currentVersion) ;

				UpdateCandidate candidate ;	// PnP IDとpathを含まないASUS公式候補。
				candidate.identity			   = identity ;
				candidate.deviceIdentity	   = device->deviceIdentity ;
				candidate.providerId		   = std::wstring( ASUS_PROVIDER_ID) ;
				candidate.packageIdentity	   = packageIdentity ;
				candidate.title				   = metadata.title + L" " + package.driverVersion ;
				candidate.manufacturer		   = device->manufacturer ;
				candidate.model				   = device->model ;
				candidate.driverClass		   = device->driverClass ;
				candidate.deviceClassGuid	   = device->deviceClassGuid ;
				candidate.provider			   = package.providerName ;
				candidate.version			   = package.driverVersion ;
				candidate.driverDate		   = formatDriverDate( package.driverDate) ;
				candidate.sourceName		   = L"ASUS 公式support page" ;
				candidate.sourceLocation	   = L"ASUS公式 HTTPS（G11全監査済み）" ;
				candidate.maximumDownloadBytes = archive.acquisition.byteCount ;
				candidate.action			   = action ;
				candidate.defaultPreference	   = CandidateDefaultPreference::NONE ;
				candidate.discoveryBasis	   = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
				candidate.audit				   = makeOfficialReadyCandidateAudit() ;
				candidate.current			   = false ;
				candidate.recommended		   = false ;
				candidate.installable		   = true ;
				candidate.eulaAccepted		   = false ;
				candidate.allContentCached	   = true ;
				candidate.rebootMayBeRequired  = true ;
				candidate.browseOnly		   = true ;

				installTargets_.emplace(
					identity, InstallTarget{.packageIdentity	 = packageIdentity,
											.deviceIdentity		 = approved.deviceIdentity,
											.archiveIndex		 = archiveIndex,
											.auditedPackageIndex = approved.auditedPackageIndex,
											.rankAudit			 = approved.rankAudit}) ;
				result.candidates.push_back( std::move( candidate)) ;
				++candidateOrdinal ;
			}

			progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
							  .percentComplete = static_cast<std::uint32_t>(
								  80U + processedArchives * 20U / totalArchives),
							  .completedItems = processedArchives,
							  .totalItems	  = totalArchives}) ;
		}

		result.coverage.assessedDeviceCount =
			allArchivesAssessed ? result.coverage.eligibleDeviceCount : 0U ;
		// 候補があっても先行errorがあれば警告付き成功として診断を残す。
		if( !result.candidates.empty()) {
			result.succeeded = true ;
			result.outcome =
				firstError == 0 ? OutcomeCode::SUCCESS : OutcomeCode::SUCCEEDED_WITH_ERRORS ;
			result.state = ProviderScanState::CANDIDATES_AVAILABLE ;
			result.error = firstError ;
		}
		// 候補がなくerrorがある場合は候補なし成功にせずsessionを失効させる。
		else if( firstError != 0) {
			result.succeeded = false ;
			result.outcome	 = OutcomeCode::FAILURE ;
			result.state	 = firstFailureState ;
			result.error	 = firstError ;
			invalidateScanSession() ;
		} else {
			result.succeeded = true ;
			result.outcome	 = OutcomeCode::SUCCESS ;
			result.state	 = ProviderScanState::NO_CANDIDATES ;
			// Install対象がないscanでは大容量archiveと取得根拠を保持しない。
			invalidateScanSession() ;
		}

		progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
						  .percentComplete = 100,
						  .completedItems  = processedArchives,
						  .totalItems	   = totalArchives}) ;
		return result ;
	} catch( const std::bad_alloc &) {
		invalidateScanSession() ;
		result.candidates.clear() ;
		result.error = static_cast<NativeError>( E_OUTOFMEMORY) ;
		return result ;
	} catch( const std::length_error &) {
		invalidateScanSession() ;
		result.candidates.clear() ;
		result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TOO_MANY_NAMES)) ;
		return result ;
	} catch( ...) {
		// 内部routing不整合を候補として公開せず、保持中の取得物とsessionを破棄する。
		invalidateScanSession() ;
		result.candidates.clear() ;
		result.error = static_cast<NativeError>( E_UNEXPECTED) ;
		return result ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asus_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult AsusUpdateProvider::install( const ScanSessionId				  scanSessionId,
										  const std::span<const std::wstring> identities,
										  const std::uintptr_t				  parentWindowNative,
										  const ProviderProgressCallback	 &progressCallback)
{
	InstallResult result ;	// 選択順で返すASUS候補の実行結果。
	result.updates.reserve( identities.size()) ;
	std::unordered_map<std::wstring, std::size_t> updateIndices ;	// Candidate別結果index。
	updateIndices.reserve( identities.size()) ;
	// 入力順を保持し、後続package groupから個別結果へ戻せる索引を構築する。
	for( std::size_t index = 0U; index < identities.size(); ++index) {
		result.updates.push_back( {.identity = identities[index]}) ;
		updateIndices.emplace( identities[index], index) ;
	}

	std::unordered_set<std::wstring>   uniqueIdentities ;	// Candidate重複検出集合。
	std::unordered_set<std::wstring>   uniqueDevices ;		// 一device一候補検証集合。
	std::vector<PackageSelectionEntry> packageEntries ;		// Candidateと外側archiveの対応群。
	packageEntries.reserve( identities.size()) ;
	// Session・owner thread・選択・導入境界・取得根拠を全て満たすかの検証結果。
	bool valid = scanSessionId != 0U && scanSessionId == scanSessionId_ &&
				 GetCurrentThreadId() == ownerThreadId_ && !identities.empty() && rankAuditor_ &&
				 installer_ && progressCallback &&
				 httpClient_.hasSourceEvidence( scanSessionId, ASUS_PROVIDER_ID,
											   OFFICIAL_PAYLOAD_RESOURCE_ID) ;
	// 全identity、device、archiveおよびINF indexをsystem変更前に検証する。
	for( const std::wstring &identity : identities) {
		const auto target = installTargets_.find( identity) ;	// Scan時target検索結果。
		// 重複identity・同device二選択・未知対象・範囲外archiveを導入前に拒否する。
		if( !valid || !uniqueIdentities.insert( identity).second || target == installTargets_.end() ||
		   !uniqueDevices.insert( target->second.deviceIdentity).second ||
		   target->second.archiveIndex >= auditedArchives_.size()) {
			valid = false ;
			break ;
		}

		const AuditedArchive &archive =
			auditedArchives_[target->second.archiveIndex] ;	// Targetの外側archive。
		// 保持package参照が範囲外または一INF閉包でない選択を拒否する。
		if( target->second.auditedPackageIndex >= archive.package.auditedPackages.size() ||
		   archive.package.auditedPackages[target->second.auditedPackageIndex]
				   .closure.packages.size() != 1U) {
			valid = false ;
			break ;
		}

		packageEntries.push_back(
			{.candidateIdentity = identity, .packageIdentity = target->second.packageIdentity}) ;
	}

	std::optional<std::vector<PackageSelectionGroup>> packageGroups ;	// 一回検証単位。
	// 全選択の照合が成立した場合にだけpackage単位へ集約する。
	if( valid) {
		packageGroups = groupPackageSelection( packageEntries) ;
	}

	// package集約を確定できない要求は全対象の取得・導入を失敗として返す。
	if( !packageGroups.has_value()) {
		result.downloadOutcome = OutcomeCode::FAILURE ;
		result.downloadError   = static_cast<NativeError>( E_INVALIDARG) ;
		result.installOutcome  = OutcomeCode::FAILURE ;
		result.installError	   = static_cast<NativeError>( E_INVALIDARG) ;
		// 拒否した選択に属する全候補へ同じ入力不正の未実行結果を付ける。
		for( UpdateExecutionResult &update : result.updates) {
			update.downloadOutcome = OutcomeCode::FAILURE ;
			update.downloadError   = static_cast<NativeError>( E_INVALIDARG) ;
			update.installOutcome  = OutcomeCode::FAILURE ;
			update.installError	   = static_cast<NativeError>( E_INVALIDARG) ;
		}

		invalidateScanSession() ;
		return result ;
	}

	std::unordered_map<std::size_t, NativeError>
		archiveErrors ;	// Archive index別の一回だけ実施した再検証結果。
	archiveErrors.reserve( packageGroups->size()) ;
	std::size_t downloaded{} ;	// 外側archive再検証まで成功した候補数。
	progressCallback( {.stage		   = ProviderStage::DOWNLOADING,
					  .percentComplete = 0,
					  .completedItems  = 0,
					  .totalItems	   = packageGroups->size()}) ;
	// 同じ外側archiveを一度だけsize／hashへ再照合し、全group候補へ結果を反映する。
	for( std::size_t groupIndex = 0U; groupIndex < packageGroups->size(); ++groupIndex) {
		const PackageSelectionGroup &group = (*packageGroups)[groupIndex] ;	// 現在archive群。
		const InstallTarget			&representative =
			// Archive索引の代表target。
			installTargets_.at( group.candidateIdentities.front()) ;
		const AuditedArchive &archive =
			auditedArchives_[representative.archiveIndex] ;	// Scan時固定archive。
		NativeError archiveError{} ;						// 外側file再検証結果。
		// 取得状態・session・Provider・用途・path・公開hashの根拠を再検証する。
		if( archive.acquisition.state != OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ||
		   archive.acquisition.acquisitionId == 0U ||
		   archive.acquisition.scanSessionId != scanSessionId ||
		   archive.acquisition.providerId != ASUS_PROVIDER_ID ||
		   archive.acquisition.resourceId != OFFICIAL_PAYLOAD_RESOURCE_ID ||
		   archive.acquisition.inspectionPath.empty() ||
		   !archive.acquisition.publishedSha256Verified) {
			archiveError = static_cast<NativeError>( E_ACCESSDENIED) ;
		} else {
			const OfficialFileMetadataPolicy metadata{
				.expectedSize	= archive.acquisition.byteCount,
				.expectedSha256 = archive.acquisition.sha256,
			} ; // G11-Bが固定した外側archive snapshot。
			archiveError = verifyOfficialFileMetadata( archive.acquisition.inspectionPath, metadata) ;
		}

		archiveErrors.emplace( representative.archiveIndex, archiveError) ;
		// 同一archiveを選んだ全候補へcache検証結果を複製する。
		for( const std::wstring &identity : group.candidateIdentities) {
			UpdateExecutionResult &update = result.updates[updateIndices.at( identity)] ;	// 結果。
			// archiveの再検証が成功した候補だけを取得成功に数える。
			if( archiveError == 0) {
				update.downloadOutcome = OutcomeCode::SUCCESS ;
				++downloaded ;
			} else {
				update.downloadOutcome = OutcomeCode::FAILURE ;
				update.downloadError   = archiveError ;
				update.installOutcome  = OutcomeCode::FAILURE ;
				update.installError	   = archiveError ;
				// 後続archiveの失敗で最初のdownload診断を上書きしない。
				if( result.downloadError == 0) {
					result.downloadError = archiveError ;
				}

				// 後続archiveの失敗で最初のinstall診断を上書きしない。
				if( result.installError == 0) {
					result.installError = archiveError ;
				}
			}
		}

		const std::uint64_t completed = groupIndex + 1U ;	// 再検証済みarchive数。
		progressCallback(
			{.stage			  = ProviderStage::DOWNLOADING,
			 .percentComplete = static_cast<std::uint32_t>( completed * 20U / packageGroups->size()),
			 .completedItems  = completed,
			 .totalItems	  = packageGroups->size()}) ;
	}

	std::map<std::pair<std::size_t, std::size_t>, NativeError>
				infVerifications ;	// 同じINF閉包を一度だけ再検証した結果。
	std::size_t installed{} ;		// SetupAPI導入に成功した候補数。
	// 選択順にPnP／Rankを再監査し、個別失敗後も残りの結果を確定する。
	for( std::size_t index = 0U; index < identities.size(); ++index) {
		UpdateExecutionResult &update		= result.updates[index] ;					// 現在候補の個別結果。
		const InstallTarget	  &target		= installTargets_.at( identities[index]) ;	// 現在target。
		const NativeError	   archiveError = archiveErrors.at( target.archiveIndex) ;	// 外側結果。
		NativeError			   installError = archiveError ;							// 現在候補の再検証または導入結果。
		bool				   rebootRequired{} ;										// 現在INFが要求した再起動flag。
		// 取得再検証が成功した候補だけをINFとrankの導入直前確認へ進める。
		if( installError == 0) {
			AuditedArchive		  &archive = auditedArchives_[target.archiveIndex] ;	// 保持archive。
			AsusAuditedInfPackage &auditedPackage =
				archive.package.auditedPackages[target.auditedPackageIndex] ;	// 対象INF閉包。
			const std::pair<std::size_t, std::size_t> verificationKey{
				target.archiveIndex, target.auditedPackageIndex} ;	// 一回検証key。
			const auto [verification, inserted] =
				// 再検証cache entry。
				infVerifications.try_emplace( verificationKey, 0) ;
			// 同じarchive内の同じINF閉包は初回だけ再検証し、結果を共有する。
			if( inserted) {
				verification->second = reverifyAsusAuditedInfPackage( auditedPackage) ;
			}

			installError = verification->second ;
			// INF再検証が成功した場合にだけ現在の適用性とrankを照会する。
			if( installError == 0) {
				const OfficialInfPackage &package =
					// 再検証済みINF metadata。
					auditedPackage.closure.packages.front() ;
				OfficialDriverRankAudit currentRank ;	// Install直前のG11-D結果。
				installError = rankAuditor_( scanSessionId, target.deviceIdentity,
											*auditedPackage.workspace, package, currentRank) ;
				// 適用性が失われた場合と以前のrank監査から変化した場合は再scanを要求する。
				if( installError == 0 &&
				   (currentRank.decision != OfficialDriverRankDecision::APPLICABLE ||
					!rankAuditsEqual( target.rankAudit, currentRank))) {
					installError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY)) ;
				}

				// 内容と最新rankの再検証を通過した場合にだけ指定INFの導入を呼び出す。
				if( installError == 0) {
					const std::wstring infPath =
						// INF絶対path。
						auditedPackage.workspace->path( package.infRelativePath) ;
					installError = installer_( scanSessionId, target.deviceIdentity, infPath,
											  package.providerName, package.driverVersion,
											  parentWindowNative, rebootRequired) ;
				}
			}
		}

		update.rebootRequired = rebootRequired ;
		result.rebootRequired = result.rebootRequired || rebootRequired ;
		// 指定導入が成功した候補だけをinstall成功件数へ加える。
		if( installError == 0) {
			update.installOutcome = OutcomeCode::SUCCESS ;
			++installed ;
		}
		// 未確定の候補結果には取得・再検証・導入で検出した失敗を反映する。
		else if( update.installOutcome == OutcomeCode::NOT_STARTED) {
			update.installOutcome = OutcomeCode::FAILURE ;
			update.installError	  = installError ;
			// 候補ごとの後続失敗で最初のinstall診断を上書きしない。
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
	invalidateScanSession() ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asus_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError AsusUpdateProvider::acquireForInspection(
	const ScanSessionId scanSessionId, const std::wstring_view opaqueId,
	const bool restrictedNetworkApproved, IOfficialNetworkCostReader &costReader,
	const HttpDownloadProgressCallback &progressCallback,
	const HttpCancellationCallback &cancellationCallback, OfficialAcquisitionResult &result)
{
	result = {} ;
	// 古いsession、別thread、未準備の取得領域、通知先欠落を取得前に拒否する。
	if( scanSessionId == 0U || scanSessionId != scanSessionId_ || opaqueId.empty() ||
	   GetCurrentThreadId() != ownerThreadId_ || acquisitionSession_ == nullptr ||
	   workspace_ == nullptr || !progressCallback) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result.error ;
	}

	const auto entry = std::find_if( acquisitionPlan_.begin(), acquisitionPlan_.end(),
									[opaqueId]( const AsusPackageAcquisitionPlanEntry &value) {
										return value.opaqueId == opaqueId ;
									}) ; // Session内で完全一致した取得計画entry。
	// 現在の取得計画にないopaque IDからpayloadを取得しない。
	if( entry == acquisitionPlan_.end()) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result.error ;
	}

	OfficialHttpAcquisitionTransport transport( httpClient_) ;	// ASUS source根拠を照合するadapter。
	return acquireAsusPackageForInspection( *entry, restrictedNetworkApproved, *acquisitionSession_,
										   *workspace_, transport, costReader, progressCallback,
										   cancellationCallback, result) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asus_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError AsusUpdateProvider::auditAcquiredPackage( const ScanSessionId			  scanSessionId,
													 const std::wstring_view		  opaqueId,
													 const OfficialAcquisitionResult &acquisition,
													 AsusDriverPackageAuditSummary	 &summary)
{
	summary = {} ;
	// 現在のsessionと所有threadに結び付かない内容監査要求を拒否する。
	if( scanSessionId == 0U || scanSessionId != scanSessionId_ || opaqueId.empty() ||
	   GetCurrentThreadId() != ownerThreadId_ || acquisitionSession_ == nullptr ||
	   workspace_ == nullptr) {
		summary.state = AsusDriverPackageAuditState::REJECTED ;
		summary.error = static_cast<NativeError>( E_INVALIDARG) ;
		return summary.error ;
	}

	const auto planEntry = std::find_if( acquisitionPlan_.begin(), acquisitionPlan_.end(),
										[opaqueId]( const AsusPackageAcquisitionPlanEntry &value) {
											return value.opaqueId == opaqueId ;
										}) ; // 公開hashを所有するscan時計画entry。
	const bool alreadyAudited =
		std::ranges::any_of( auditedArchives_, [opaqueId]( const AuditedArchive &value) {
			return value.opaqueId == opaqueId ;
		}) ;										 // 同一recordの監査済み状態。
	OfficialDriverArchiveFormat archiveFormat{} ;	// 計画file名から固定するparser種別。
	// 未知計画・監査の二重実行・未対応archive形式を内容監査へ渡さない。
	if( planEntry == acquisitionPlan_.end() || alreadyAudited ||
	   !acquisitionArchiveFormat( planEntry->workspaceFileName, archiveFormat)) {
		summary.state = AsusDriverPackageAuditState::REJECTED ;
		summary.error = static_cast<NativeError>( E_INVALIDARG) ;
		return summary.error ;
	}

	AsusDriverPackageAudit				package ;	// 成功時にProviderが所有する内容監査結果。
	const AsusDriverPackageAuditRequest request{
		.acquisition	= &acquisition,
		.expectedSha256 = planEntry->publishedSha256,
		.archiveFormat	= archiveFormat} ;									// Scan時公開hashへ拘束した監査要求。
	const NativeError error = auditAsusDriverPackage( request, package) ;	// 全INF監査結果。
	summary					= package.summary ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	try {
		auditedArchives_.push_back( {.opaqueId	 = std::wstring( opaqueId),
									.acquisition = acquisition,
									.package	 = std::move( package)}) ;
	} catch( const std::bad_alloc &) {
		summary		  = {} ;
		summary.state = AsusDriverPackageAuditState::FAILURE ;
		summary.error = static_cast<NativeError>( E_OUTOFMEMORY) ;
		return summary.error ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asus_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError AsusUpdateProvider::auditRetainedPackageApplicability(
	const ScanSessionId scanSessionId, const std::wstring_view opaqueId,
	const AsusOfficialInfRankAuditor &rankAuditor, AsusDriverApplicabilitySummary &summary)
{
	summary = {} ;
	// session・thread・rank callbackを照合できない適用性監査を拒否する。
	if( scanSessionId == 0U || scanSessionId != scanSessionId_ || opaqueId.empty() ||
	   GetCurrentThreadId() != ownerThreadId_ || !rankAuditor) {
		summary.state = AsusDriverApplicabilityState::REJECTED ;
		summary.error = static_cast<NativeError>( E_INVALIDARG) ;
		return summary.error ;
	}

	const auto archive = std::find_if( auditedArchives_.begin(), auditedArchives_.end(),
									  [opaqueId]( const AuditedArchive &value) {
										  return value.opaqueId == opaqueId ;
									  }) ; // 内容監査済みrecord検索結果。
	// 未保持archiveと適用性監査済みarchiveの再要求を拒否する。
	if( archive == auditedArchives_.end() ||
	   archive->package.applicability.state != AsusDriverApplicabilityState::NOT_STARTED) {
		summary.state = AsusDriverApplicabilityState::REJECTED ;
		summary.error = static_cast<NativeError>( E_INVALIDARG) ;
		return summary.error ;
	}

	const NativeError error = auditAsusDriverApplicability(
		scanSessionId, localDevices_, rankAuditor, archive->package) ;	// G11-D接続結果。
	summary = archive->package.applicability ;
	return error ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asus_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void AsusUpdateProvider::invalidateScanSession() noexcept
{
	installTargets_.clear() ;
	auditedArchives_.clear() ;
	localDevices_.clear() ;
	workspace_.reset() ;
	acquisitionSession_.reset() ;
	acquisitionPlan_.clear() ;
	scanSessionId_ = 0U ;
	ownerThreadId_ = 0U ;
	httpClient_.invalidateSourceSession() ;
}

} // namespace drivercrate
