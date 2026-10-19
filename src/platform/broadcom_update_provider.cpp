//------------------------------------------------------------------------------
/**
 * @file broadcom_update_provider.cpp
 * @brief Broadcom NetXtreme-E公式配布情報の検索。
 * @version 01.00.00
 * @date 2026/09/05
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Broadcom固定policy wrapperへ移行。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  前回release差分接続を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  導入再検証を共通executorへ分離。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  監査済みINFの導入境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Broadcomの取得後監査を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Workerで公式検索情報を保持し、明示承認後に取得・監査したINFだけを導入候補へ昇格します。
 */
//------------------------------------------------------------------------------

#include "platform/broadcom_update_provider.h"

#include "core/candidate_audit.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "core/update_types.h"

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {
constexpr std::size_t	MAXIMUM_DEVICES		   = 4096U ;				// 一回に扱う非機密snapshot数上限。
constexpr std::uint64_t MAXIMUM_CATALOG_BYTES  = 2U * 1024U * 1024U ;	// 製品JSON応答byte上限。
constexpr std::uint64_t MAXIMUM_DOCUMENT_BYTES = 256U * 1024U ;			// Document JSON応答byte上限。

//------------------------------------------------------------------------------
/**
 * @brief 有限長の表示値を大文字小文字を除いて比較する。外部へ端末情報を送信しない。
 *
 * @param[in] left 比較元の表示値。
 * @param[in] right 比較先の表示値。
 * @return 定義した検査に適合する場合true。不一致はfalse。
 */
//------------------------------------------------------------------------------
bool sameText( const std::wstring_view left, const std::wstring_view right) noexcept
{
	return !left.empty() && left.size() <= 512U && left.size() == right.size() &&
		   CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示名の系列prefixと語境界を確認する。製品型番や適用性を推測しない。
 *
 * @param[in] text 系列を調べる表示名。
 * @param[in] prefix 期待する系列prefix。
 * @return 定義した検査に適合する場合true。不一致はfalse。
 */
//------------------------------------------------------------------------------
bool familyPrefix( const std::wstring_view text, const std::wstring_view prefix) noexcept
{
	return text.size() <= 512U && text.size() >= prefix.size() &&
		   sameText( text.substr( 0U, prefix.size()), prefix) &&
		   (text.size() == prefix.size() || text[prefix.size()] == L' ') ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool broadcomNetxtremeEDevice( const OfficialCatalogDevice &device) noexcept
{
	return !device.deviceIdentity.empty() && device.deviceIdentity.size() <= 256U &&
		   sameText( device.driverClass, L"Net") &&
		   (device.deviceClassGuid.empty() ||
			sameText( device.deviceClassGuid, L"{4d36e972-e325-11ce-bfc1-08002be10318}")) &&
		   familyPrefix( device.model, L"Broadcom NetXtreme-E") &&
		   (familyPrefix( device.manufacturer, L"Broadcom") ||
			familyPrefix( device.currentProvider, L"Broadcom")) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
UpdateCandidate makeBroadcomDiscoveryCandidate( const ScanSessionId			session,
											   const std::size_t			ordinal,
											   const OfficialCatalogDevice &device,
											   const BroadcomDriverRelease &release)
{
	UpdateCandidate candidate ;	// 監査未完了の表示専用行。
	candidate.identity =
		L"broadcom-info:" + std::to_wstring( session) + L":" + std::to_wstring( ordinal) ;
	candidate.deviceIdentity  = device.deviceIdentity ;
	candidate.providerId	  = std::wstring( BROADCOM_NET_XTREME_PROVIDER_ID) ;
	candidate.packageIdentity = L"broadcom-document:" + std::to_wstring( session) ;
	candidate.title = std::wstring( BROADCOM_WINDOWS_DRIVER_TITLE) + L" " + release.assetVersion ;
	candidate.manufacturer	  = device.manufacturer ;
	candidate.model			  = device.model ;
	candidate.driverClass	  = device.driverClass ;
	candidate.deviceClassGuid = device.deviceClassGuid ;
	candidate.provider		  = L"Broadcom" ;
	candidate.sourceName	  = L"Broadcom NetXtreme-E / N210TP" ;
	candidate.sourceLocation  = L"www.broadcom.com / docs.broadcom.com" ;
	candidate.discoveryBasis  = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
	candidate.audit			  = makeOfficialDiscoveryCandidateAudit() ;
	// 既定のNone／falseを明記し、将来の初期値変更でも表示情報を導入候補にしない。
	candidate.action			= DriverAction::NONE ;
	candidate.defaultPreference = CandidateDefaultPreference::NONE ;
	candidate.installable		= false ;
	candidate.recommended		= false ;
	candidate.current			= false ;
	candidate.eulaAccepted		= false ;
	candidate.allContentCached	= false ;
	return candidate ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void BroadcomUpdateProvider::configureReleaseObservationContext(
	const std::span<const LocalOfficialReleaseObservation> previous,
	const OfficialReleaseEnvironmentFingerprints		  &environment)
{
	previousReleaseObservations_.assign( previous.begin(), previous.end()) ;
	observationEnvironment_ = environment ;
	currentReleaseObservations_.clear() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::span<const LocalOfficialReleaseObservation> BroadcomUpdateProvider::releaseObservations()
	const noexcept
{
	return currentReleaseObservations_ ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult BroadcomUpdateProvider::scan( const ScanSessionId							 scanSessionId,
										const std::span<const OfficialCatalogDevice> devices,
										const LocalHardwareIdMatcher   &hardwareIdMatcher,
										const ProviderProgressCallback &progressCallback)
{
	static_cast<void>( hardwareIdMatcher) ;
	// Public失効は観測contextも消去するため、Compositeが今回設定した値だけを退避する。
	std::vector<LocalOfficialReleaseObservation> previousObservations =
		// 今回scan用の前回観測。
		std::move( previousReleaseObservations_) ;
	OfficialReleaseEnvironmentFingerprints observationEnvironment =
		// 今回scan用の現在環境。
		std::move( observationEnvironment_) ;
	invalidatePreparation() ;
	previousReleaseObservations_ = std::move( previousObservations) ;
	observationEnvironment_		 = std::move( observationEnvironment) ;
	ScanResult result ;	// 単一Providerの検索結果。
	result.scanSessionId = scanSessionId ;
	result.outcome		 = OutcomeCode::FAILURE ;
	result.state		 = ProviderScanState::FAILURE ;
	// 未発行session、通知先欠落、device数上限超過を通信前に拒否する。
	if( scanSessionId == 0U || !progressCallback || devices.size() > MAXIMUM_DEVICES) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		// 不正session、上限超過、通知先欠落では通信しない。
		return result ;
	}

	std::vector<const OfficialCatalogDevice *> matched ;	// 呼出し中だけ有効な対象snapshot view。
	std::unordered_set<std::wstring>		   identities ;	// 同じopaque deviceの重複を検出する。
	// 最大4096件を端末内で照合し、対象がない場合はnetworkへ進まない。
	for( const auto &device : devices) {
		// Broadcom NetXtreme-Eに該当するlocal deviceだけを検索対象へ含める。
		if( broadcomNetxtremeEDevice( device)) {
			// 同じdevice identityから重複した表示候補を作らない。
			if( !identities.insert( device.deviceIdentity).second) {
				result.error = static_cast<NativeError>( E_INVALIDARG) ;
				// 同じdeviceへ重複した表示候補を作らない。
				return result ;
			}

			matched.push_back( &device) ;
		}
	}

	result.coverage.eligibleDeviceCount = matched.size() ;
	// 対応deviceがない場合は通信せず対象外を返す。
	if( matched.empty()) {
		result.succeeded = true ;
		result.outcome	 = OutcomeCode::SUCCESS ;
		result.state	 = ProviderScanState::NOT_APPLICABLE ;
		progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
						  .percentComplete = 100,
						  .completedItems  = 0,
						  .totalItems	   = 0}) ;
		return result ;
	}

	progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
					  .percentComplete = 0,
					  .completedItems  = 0,
					  .totalItems	   = matched.size()}) ;
	result.error = httpClient_.beginSourceSession( scanSessionId, BROADCOM_NET_XTREME_PROVIDER_ID) ;
	// 初期段階の失敗がある場合は保持した診断を返し、取得を続けない。
	if( result.error != 0) {
		return result ;
	}

	std::wstring catalog ;	// 上限付きで取得する固定製品JSON。
	result.error = httpClient_.getUtf8TextForSource( BROADCOM_CATALOG_URL,
													OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
													MAXIMUM_CATALOG_BYTES, catalog) ;
	// 通信失敗を候補なし／最新へ変換しない。
	if( result.error != 0) {
		return result ;
	}

	std::optional<BroadcomDriverRelease> release ;	// 現行配布record。存在しない場合は空。
	// catalog schemaの検証失敗を候補なし成功として扱わない。
	if( !parseBroadcomCatalog( catalog, release)) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
		return result ;
	}

	progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
					  .percentComplete = 40,
					  .completedItems  = 0,
					  .totalItems	   = matched.size()}) ;
	// 現行配布recordがある場合にだけ同じdocumentのEULA情報を取得する。
	if( release.has_value()) {
		std::wstring document ;	// 公開EULA情報。取得対象化用に解析するが、scanでは同意しない。
		result.error = httpClient_.getUtf8TextForSource( release->documentApiUrl,
														OFFICIAL_SECONDARY_METADATA_RESOURCE_ID,
														MAXIMUM_DOCUMENT_BYTES, document) ;
		// 同意情報の取得失敗を無視して公開行を返さない。
		if( result.error != 0) {
			return result ;
		}

		// documentと配布recordの結合が不正ならmetadata拒否を返す。
		if( !validateBroadcomDocument( document, *release)) {
			result.state = ProviderScanState::METADATA_REJECTED ;
			result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
			return result ;
		}

		// 本文表示未対応でも既存の表示専用検索を失敗へ降格しない。取得対象は空になる。
		static_cast<void>( parseBroadcomPreparedRelease( document, *release, retainedRelease_)) ;
	}

	// 現在sessionの公式取得根拠が揃わない情報を公式候補として表示しない。
	if( !httpClient_.hasSourceEvidence( scanSessionId, BROADCOM_NET_XTREME_PROVIDER_ID,
									  OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ||
	   (release.has_value() &&
		!httpClient_.hasSourceEvidence( scanSessionId, BROADCOM_NET_XTREME_PROVIDER_ID,
									   OFFICIAL_SECONDARY_METADATA_RESOURCE_ID))) {
		result.state = ProviderScanState::SOURCE_REJECTED ;
		result.error = static_cast<NativeError>( E_UNEXPECTED) ;
		// 現在sessionの取得元根拠がない情報を公式と表示しない。
		return result ;
	}

	progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
					  .percentComplete = 80,
					  .completedItems  = 0,
					  .totalItems	   = matched.size()}) ;
	// 現行配布recordを確認できた場合にだけ表示行と観測差分を生成する。
	if( release.has_value()) {
		FILETIME observedTime{} ;	// Live metadata確認へ使用する現在UTC FILETIME。
		GetSystemTimeAsFileTime( &observedTime) ;
		ULARGE_INTEGER observedTimeValue{} ;	// FILETIMEを永続64-bit値へ変換する共用体。
		observedTimeValue.LowPart  = observedTime.dwLowDateTime ;
		observedTimeValue.HighPart = observedTime.dwHighDateTime ;
		bool observationFailed{} ;	// 一件でも失敗した場合に今回観測全体を破棄する。
		// 取得元とdocument結合を確認した後だけ、系列参照用の非選択行を作る。
		for( std::size_t index = 0U; index < matched.size(); ++index) {
			UpdateCandidate candidate = makeBroadcomDiscoveryCandidate(
				scanSessionId, index, *matched[index], *release) ;	// 現在deviceの表示行。
			// familyと観測環境が揃い、先行失敗もない場合にだけ差分を評価する。
			if( !observationFailed &&
			   retainedRelease_.family == OfficialReleaseFamily::BROADCOM_NET_XTREME_E &&
			   !observationEnvironment_.operatingSystem.empty() &&
			   !observationEnvironment_.deviceConfiguration.empty()) {
				OfficialReleaseObservationEvaluation evaluation ;	// 今回観測と非機密差分。
				// 評価成功した観測だけを保存候補へ含め、差分を表示行に付ける。
				if( evaluateOfficialReleaseObservation(
					   OfficialReleaseFamily::BROADCOM_NET_XTREME_E, retainedRelease_,
					   *matched[index], observationEnvironment_.operatingSystem,
					   observationEnvironment_.deviceConfiguration, observedTimeValue.QuadPart,
					   previousReleaseObservations_, evaluation)) {
					currentReleaseObservations_.push_back( std::move( evaluation.observation)) ;
					candidate.releaseObservationDifference = evaluation.difference ;
				} else {
					observationFailed = true ;
					currentReleaseObservations_.clear() ;
				}
			}

			result.candidates.push_back( std::move( candidate)) ;
			progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
							  .percentComplete = static_cast<std::uint32_t>(
								  80U + (index + 1U) * 20U / matched.size()),
							  .completedItems = index + 1U,
							  .totalItems	  = matched.size()}) ;
		}

		// 観測に一件でも失敗した場合は部分的な差分表示を全候補から除く。
		if( observationFailed) {
			// 部分観測を表示または保存せず、通常のlive検索結果だけを維持する。
			for( UpdateCandidate &candidate : result.candidates) {
				candidate.releaseObservationDifference.reset() ;
			}
		}
	}

	// 有効な配布recordがある場合にだけ同じdevice集合と所有threadを準備用に保持する。
	if( release.has_value()) {
		retainedDevices_.reserve( matched.size()) ;
		// 取得後も同じ非機密device集合だけを監査し、再列挙による対象差替えを防ぐ。
		for( const OfficialCatalogDevice *const device : matched) {
			retainedDevices_.push_back( *device) ;
		}

		retainedDocument_	 = *release ;
		retainedSessionId_	 = scanSessionId ;
		retainedDeviceCount_ = static_cast<std::uint32_t>( matched.size()) ;
		// 保持物を作成したworker threadを固定する。
		ownerThreadId_ = GetCurrentThreadId() ;
	}

	result.coverage.assessedDeviceCount = matched.size() ;
	result.succeeded					= true ;
	result.outcome						= OutcomeCode::SUCCESS ;
	result.state = release.has_value() ? ProviderScanState::CANDIDATES_AVAILABLE
									   : ProviderScanState::NO_CANDIDATES ;
	progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
					  .percentComplete = 100,
					  .completedItems  = matched.size(),
					  .totalItems	   = matched.size()}) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult executeBroadcomPreparedInstall( const BroadcomPreparedInstallContext &context,
											 const std::span<const std::wstring>   identities,
											 const BroadcomInfReverifier		  &reverifier,
											 const OfficialInfRankAuditor		  &rankAuditor,
											 const BroadcomVerifiedInfInstaller	  &installer,
											 const std::uintptr_t			 parentWindowNative,
											 const ProviderProgressCallback &progressCallback)
{
	const PreparedInfInstallPolicy policy{
		.providerId = BROADCOM_NET_XTREME_PROVIDER_ID,
		.resourceId = OFFICIAL_PAYLOAD_RESOURCE_ID} ;	// Broadcom wrapperだけが固定する許可組合せ。
	return executePreparedInfInstall( policy, context, identities, reverifier, rankAuditor,
									 installer, parentWindowNative, progressCallback) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/broadcom_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult BroadcomUpdateProvider::install( const ScanSessionId				  scanSessionId,
											  const std::span<const std::wstring> identities,
											  const std::uintptr_t			  parentWindowNative,
											  const ProviderProgressCallback &progressCallback)
{
	const bool providerContextConfirmed =
		scanSessionId != 0U && scanSessionId == retainedSessionId_ &&
		GetCurrentThreadId() == ownerThreadId_ && candidatesPublished_ &&
		httpClient_.hasSourceEvidence( scanSessionId, BROADCOM_NET_XTREME_PROVIDER_ID,
									  OFFICIAL_PAYLOAD_RESOURCE_ID) ;	// Worker所有状態と公式根拠。
	const std::wstring packageIdentity = L"broadcom-package:" + std::to_wstring( scanSessionId) +
										 L":" +
										 // 取得identity由来のopaque package ID。
										 std::to_wstring( acquisition_.acquisitionId) ;
	const BroadcomPreparedInstallContext context{
		.scanSessionId	 = scanSessionId,
		.acquisition	 = &acquisition_,
		.packageIdentity = packageIdentity,
		.targets		 = &installTargets_,
		.auditedPackages =
			std::span<const OfficialAuditedInfPackage>( preparedAudit_.auditedPackages),
		.sourceEvidenceConfirmed = providerContextConfirmed,
	} ; // Provider外へ保存しない非所有executor入力。
	const BroadcomInfReverifier reverifier = []( const OfficialAuditedInfPackage &package) {
		return reverifyOfficialAuditedInfPackage( package) ;
	} ; // 共通の本番閉包再検証。
	try {
		InstallResult result = executeBroadcomPreparedInstall(
			context, identities, reverifier, rankAuditor_, installer_, parentWindowNative,
			progressCallback) ;	// 保持物が有効な間だけ実行する個別結果。
		invalidatePreparation() ;
		return result ;
	} catch( ...) {
		// Callback例外時も保持fileとroutingを解放し、workerの共通例外処理へ診断を委ねる。
		invalidatePreparation() ;
		throw ;
	}
}

} // namespace drivercrate
