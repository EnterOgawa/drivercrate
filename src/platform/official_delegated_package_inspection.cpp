//------------------------------------------------------------------------------
/**
 * @file official_delegated_package_inspection.cpp
 * @brief Record限定取得結果と共通driver package検査の接続実装。
 * @version 01.02.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Record限定取得と共通内容検査のadapterを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  公式由来を表示専用候補評価へ再結合。
 * Ver.01.01.01 Shunji Ogawa  2026/09/15  公開SHA-256と実取得hashを再照合。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  Device別PnP観測と取得後表示reportを追加。
 * Ver.01.02.01 Shunji Ogawa  2026/10/15  全体INF件数と照合開始前のpair予算を共通化。
 * </pre>
 *
 * @note Adapterはworker内の取得証拠と内容入力を分離し、秘密URL、実pathまたはhashをUIへ渡しません。
 * @see docs/adr/0151-common-package-content-and-origin-separation.md
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#include "platform/official_delegated_package_inspection.h"

#include "core/candidate_audit.h"
#include "core/official_preparation_audit.h"

#include "platform/official_discovery_package.h"

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <limits>
#include <new>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t	  MAXIMUM_INTERNAL_PATH_CHARACTERS = 32'767U ;	// Windows内部path上限。
constexpr std::size_t	  SHA256_CHARACTERS				   = 64U ;		// 固定済みSHA-256の文字数。
constexpr std::size_t	  MAXIMUM_DEVICE_COUNT			   = 4'096U ;	// 一packageのdevice数上限。
constexpr std::size_t	  MAXIMUM_IDENTITY_CHARACTERS	   = 256U ;		// Opaque IDの文字数上限。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

/**
 * @brief Win32 errorをHRESULT bit patternへ変換します。
 * @param[in] error Win32 error codeです。
 * @return 対応するHRESULT bit patternです。
 */
[[nodiscard]] NativeError fromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

/**
 * @brief 固定済み実file hashが64桁のlowercase ASCII SHA-256か確認します。
 * @param[in] value 検証するhashです。
 * @return 形式を満たす場合trueです。
 */
[[nodiscard]] bool isLowerSha256( const std::wstring_view value) noexcept
{
	return value.size() == SHA256_CHARACTERS &&
		   std::ranges::all_of( value, []( const wchar_t character) noexcept {
			   return (character >= L'0' && character <= L'9') ||
					  (character >= L'a' && character <= L'f') ;
		   }) ;
}

/**
 * @brief 公開SHA-256とlowercase実取得SHA-256がASCII caseを除き一致するか確認します。
 * @param[in] published 公式recordが保持する64桁hex hashです。
 * @param[in] actual 取得層が実fileから算出したlowercase hashです。
 * @return 両hashが同じ値の場合trueです。
 */
[[nodiscard]] bool sameSha256( const std::wstring_view published,
							  const std::wstring_view actual) noexcept
{
	// 長さと実取得hash形式が不正なら比較を成立させない。
	if( published.size() != SHA256_CHARACTERS || !isLowerSha256( actual)) {
		return false ;
	}

	return std::ranges::equal( published, actual, []( wchar_t left, const wchar_t right) noexcept {
		// 公開値だけASCII uppercaseをlowercaseへ正規化し、localeへ依存しない。
		if( left >= L'A' && left <= L'F') {
			left = static_cast<wchar_t>( left - L'A' + L'a') ;
		}

		return left == right ;
	}) ;
}

/**
 * @brief Stable record fingerprintが未設定の全zeroでないか確認します。
 * @param[in] fingerprint 検証するURL非保持fingerprintです。
 * @return 1 byte以上が0以外ならtrueです。
 */
[[nodiscard]] bool hasRecordFingerprint( const OfficialStableRecordFingerprint &fingerprint) noexcept
{
	return std::ranges::any_of( fingerprint.bytes,
							   []( const std::byte value) noexcept { return value != std::byte{} ; }) ;
}

/**
 * @brief 公開basenameの最終拡張子から共通検査形式を決めます。
 * @param[in] fileDisplayName Grantが保持する公開basenameです。
 * @return ZIP／CABの場合は形式、それ以外は空です。
 */
[[nodiscard]] std::optional<OfficialDriverArchiveFormat> archiveFormat(
	const std::wstring_view fileDisplayName)
{
	// Directory成分や空basenameを形式判定へ使用しない。
	if( fileDisplayName.empty() || fileDisplayName.size() > MAX_PATH ||
	   fileDisplayName.find_first_of( L"/\\") != std::wstring_view::npos) {
		return std::nullopt ;
	}

	const std::size_t dot = fileDisplayName.find_last_of( L'.') ;	// 最終拡張子の開始位置。
	// 拡張子を持たないbasenameを実file内容から補完しない。
	if( dot == std::wstring_view::npos) {
		return std::nullopt ;
	}

	std::wstring extension( fileDisplayName.substr( dot)) ;	// ASCII小文字化する拡張子。
	std::ranges::transform( extension, extension.begin(), []( const wchar_t character) noexcept {
		return character >= L'A' && character <= L'Z'
				   ? static_cast<wchar_t>( character - L'A' + L'a')
				   : character ;
	}) ;
	// 共通検査が静的に扱うZIPだけを選択する。
	if( extension == L".zip") {
		return OfficialDriverArchiveFormat::ZIP ;
	}

	// 共通検査が静的に扱う単一CABだけを選択する。
	if( extension == L".cab") {
		return OfficialDriverArchiveFormat::CABINET ;
	}

	return std::nullopt ;
}

/**
 * @brief 変換後のworker内入力が改変されていない有限値か確認します。
 * @param[in] input 検証する変換済み入力です。
 * @return 共通検査へ渡せる構造ならtrueです。
 */
[[nodiscard]] bool isValidInput( const DelegatedOfficialPackageInput &input) noexcept
{
	const DelegatedOfficialPackageProvenance &provenance = input.provenance ;	// URL非保持証拠。
	return input.archive.scanSessionId != 0U &&
		   input.archive.scanSessionId == provenance.scanSessionId &&
		   !input.archive.inspectionPath.empty() &&
		   input.archive.inspectionPath.size() <= MAXIMUM_INTERNAL_PATH_CHARACTERS &&
		   input.archive.byteCount != 0U && isLowerSha256( input.archive.sha256) &&
		   provenance.acquisitionId != 0U && !provenance.providerId.empty() &&
		   !provenance.policyId.empty() && !provenance.rootResourceId.empty() &&
		   !provenance.payloadResourceId.empty() && provenance.recordEvidenceId != 0U &&
		   provenance.downloadGrantId != 0U && hasRecordFingerprint( provenance.recordFingerprint) &&
		   provenance.grantReresolutionCount <= 1U &&
		   provenance.validatedDestinationAddressCount != 0U &&
		   provenance.destinationLocallyResolved &&
		   (input.format == OfficialDriverArchiveFormat::ZIP ||
			input.format == OfficialDriverArchiveFormat::CABINET) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_package_inspection.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError makeDelegatedOfficialPackageInput( const OfficialAcquisitionResult &acquisition,
											  const RecordScopedDownloadGrant &grant,
											  DelegatedOfficialPackageInput	  &input) noexcept
{
	input												= {} ;
	const RecordScopedDownloadGrantMetadata	  &metadata = grant.metadata() ;	// URL非保持grant状態。
	const RecordScopedDownloadGrantPayloadView payload =
		// 公開payload metadata。
		grant.payloadView() ;
	// 成功終端した一回使用grant以外を内容検査へ接続しない。
	if( metadata.state != OfficialDownloadGrantState::CONSUMED ||
	   metadata.outcome != OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION ||
	   metadata.error != 0 || metadata.method != OfficialDownloadGrantMethod::GET) {
		return fromWin32( ERROR_INVALID_STATE) ;
	}

	// 取得成功以外、固定URL経路または秘密URLが残る不整合を拒否する。
	if( acquisition.state != OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ||
	   acquisition.error != 0 || !acquisition.delegatedRecord || !payload.targetUrl.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 取得ledgerとgrantのsession、Provider、payload、record、grantと再解決回数を再結合する。
	if( acquisition.scanSessionId == 0U || acquisition.acquisitionId == 0U ||
	   acquisition.scanSessionId != metadata.scanSessionId ||
	   acquisition.providerId != metadata.providerId ||
	   acquisition.resourceId != payload.resourceId ||
	   acquisition.recordEvidenceId != metadata.recordEvidenceId ||
	   acquisition.downloadGrantId != metadata.grantId ||
	   acquisition.grantReresolutionCount != metadata.reresolutionCount) {
		return fromWin32( ERROR_REVISION_MISMATCH) ;
	}

	// URL非保持record identityと公式取得先検証が欠落した成功結果を受理しない。
	if( metadata.providerId.empty() || metadata.policyId.empty() ||
	   metadata.rootResourceId.empty() || payload.resourceId.empty() ||
	   metadata.recordEvidenceId == 0U || metadata.grantId == 0U ||
	   !hasRecordFingerprint( metadata.recordFingerprint) || metadata.reresolutionCount > 1U ||
	   acquisition.validatedDestinationAddressCount == 0U ||
	   !acquisition.destinationLocallyResolved) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 実取得file identityとgrantの有限受信上限を共通検査前に固定する。
	if( acquisition.inspectionPath.empty() ||
	   acquisition.inspectionPath.size() > MAXIMUM_INTERNAL_PATH_CHARACTERS ||
	   acquisition.byteCount == 0U || metadata.maximumBytes == 0U ||
	   acquisition.byteCount > metadata.maximumBytes ||
	   payload.maximumBytes != metadata.maximumBytes || !isLowerSha256( acquisition.sha256)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 公開exact sizeの有無と取得層の一致確認結果が矛盾する場合は拒否する。
	if( acquisition.publishedSizeVerified != payload.publishedSizeBytes.has_value() ||
	   (payload.publishedSizeBytes && acquisition.byteCount != *payload.publishedSizeBytes)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 一致済みflagだけを信用せず、公開hashと実取得hashをこの接続境界でも再照合する。
	if( acquisition.publishedSha256Verified != !payload.publishedSha256.empty() ||
	   (!payload.publishedSha256.empty() &&
		!sameSha256( payload.publishedSha256, acquisition.sha256))) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// INF package以外を拡張子だけで共通driver packageへ読み替えない。
	if( payload.kind != OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE) {
		return fromWin32( ERROR_NOT_SUPPORTED) ;
	}

	try {
		const std::optional<OfficialDriverArchiveFormat> format =
			// 公開basenameだけに基づく検査形式。
			archiveFormat( payload.fileDisplayName) ;
		// 未対応、欠落またはdirectory付きbasenameを実pathから補完しない。
		if( !format) {
			return fromWin32( ERROR_NOT_SUPPORTED) ;
		}

		DelegatedOfficialPackageInput pending ;	// 全copy成功後だけ公開する変換結果。
		pending.archive	   = {.scanSessionId  = acquisition.scanSessionId,
							  .inspectionPath = acquisition.inspectionPath,
							  .byteCount	  = acquisition.byteCount,
							  .sha256		  = acquisition.sha256} ;
		pending.format	   = *format ;
		pending.provenance = {.scanSessionId		  = acquisition.scanSessionId,
							  .acquisitionId		  = acquisition.acquisitionId,
							  .providerId			  = acquisition.providerId,
							  .policyId				  = metadata.policyId,
							  .rootResourceId		  = metadata.rootResourceId,
							  .payloadResourceId	  = acquisition.resourceId,
							  .recordEvidenceId		  = acquisition.recordEvidenceId,
							  .downloadGrantId		  = acquisition.downloadGrantId,
							  .payloadOrdinal		  = metadata.payloadOrdinal,
							  .recordFingerprint	  = metadata.recordFingerprint,
							  .grantReresolutionCount = acquisition.grantReresolutionCount,
							  .validatedDestinationAddressCount =
								  acquisition.validatedDestinationAddressCount,
							  .destinationLocallyResolved = acquisition.destinationLocallyResolved,
							  .publishedSizeVerified	  = acquisition.publishedSizeVerified,
							  .publishedSha256Verified	  = acquisition.publishedSha256Verified} ;
		// 内部copyで失われたfieldや不正既定値を公開前に拒否する。
		if( !isValidInput( pending)) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		input = std::move( pending) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		// 文字列copy等の例外をworker境界から外へ漏らさない。
		return static_cast<NativeError>( E_FAIL) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_package_inspection.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError inspectDelegatedOfficialDriverPackage( const ScanSessionId activeScanSessionId,
												  const DelegatedOfficialPackageInput &input,
												  CommonDriverPackageInspection		  &inspection,
												  const std::function<bool()>		  &cancellation)
{
	inspection = {} ;
	// 旧scanの取得fileまたは改変された変換入力を共通検査へ渡さない。
	if( activeScanSessionId == 0U || input.provenance.scanSessionId != activeScanSessionId) {
		inspection.error = fromWin32( ERROR_REVISION_MISMATCH) ;
		return inspection.error ;
	}

	// URL非保持証拠とarchive identityの構造不整合を内容parserへ渡さない。
	if( !isValidInput( input)) {
		inspection.error = static_cast<NativeError>( E_INVALIDARG) ;
		return inspection.error ;
	}

	return inspectCommonDriverPackage( input.archive, input.format, inspection, cancellation) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_package_inspection.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError inspectDelegatedOfficialDriverApplicability(
	const ScanSessionId activeScanSessionId, const DelegatedOfficialPackageInput &input,
	const CommonDriverPackageInspection				  &packageInspection,
	const std::span<const OfficialDiscoveryDeviceHint> devices,
	const DelegatedOfficialInfRankObserver			  &rankObserver,
	std::vector<DelegatedOfficialDeviceApplicability> &results,
	const std::function<bool()>						  &cancellation)
{
	results.clear() ;
	// Stale session、改変された取得入力または全体失敗した内容検査をPnPへ渡さない。
	if( activeScanSessionId == 0U || input.provenance.scanSessionId != activeScanSessionId ||
	   !isValidInput( input) || packageInspection.error != 0 ||
	   packageInspection.scanSessionId != activeScanSessionId ||
	   packageInspection.archiveSha256 != input.archive.sha256 ||
	   packageInspection.archiveBytes != input.archive.byteCount) {
		return fromWin32( ERROR_REVISION_MISMATCH) ;
	}

	// 空、過大またはcallbackなしの要求から適用性を補完しない。
	if( devices.empty() || devices.size() > MAXIMUM_DEVICE_COUNT || !rankObserver ||
	   packageInspection.infs.size() > OFFICIAL_PREPARATION_MAXIMUM_INF_COUNT) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const auto acceptedInfCount =
		static_cast<std::size_t>( std::ranges::count_if( packageInspection.infs, []( const auto &inf) {
			return inf.state == CommonInfInspectionState::VERIFIED ;
		})) ; // 内容合格数だけで全deviceの仕事量を乗算前に検査します。
	// 旧最大仕事量を超える照合は開始せず、途中の未判定を正常結果へ変えません。
	if( acceptedInfCount > OFFICIAL_PREPARATION_MAXIMUM_PAIR_COUNT / devices.size()) {
		return fromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// 成功状態と所有閉包の矛盾を全て事前拒否し、部分observerを実行しません。
	for( const auto &inf : packageInspection.infs) {
		// 内容拒否INFは照合しませんが、合格状態には完全な所有閉包を要求します。
		if( inf.state == CommonInfInspectionState::VERIFIED &&
		   (inf.error != 0U || !inf.workspace || inf.closure.packages.size() != 1U)) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}
	}

	try {
		std::unordered_set<std::wstring_view> deviceIdentities ;	// 入力内のopaque device一意性集合。
		deviceIdentities.reserve( devices.size()) ;
		// 全deviceを現在sessionへ拘束し、一部だけ観測する状態を作らない。
		for( const OfficialDiscoveryDeviceHint &device : devices) {
			// Raw識別子を含まない有効hintだけをWindows観測へ渡す。
			if( !validateOfficialDiscoveryDeviceHint( device, activeScanSessionId) ||
			   !deviceIdentities.insert( device.deviceIdentity).second) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}
		}

		std::vector<DelegatedOfficialDeviceApplicability>
			pending ;	// 全組合せ完了後だけ公開する結果。
		pending.reserve( devices.size()) ;
		// Device順を保持し、候補IDとのindex対応を固定する。
		for( const OfficialDiscoveryDeviceHint &device : devices) {
			DelegatedOfficialDeviceApplicability result ;	// 現在deviceの有限PnP観測集計。
			result.deviceIdentity = device.deviceIdentity ;
			// 取消し時は未完了の部分結果を表示へ渡さない。
			if( cancellation && cancellation()) {
				results.clear() ;
				return fromWin32( ERROR_CANCELLED) ;
			}

			// 内容合格した各INFだけを同じdeviceのWindows候補nodeへ照合する。
			for( const CommonInfInspection &inf : packageInspection.infs) {
				// 個別内容拒否はPnPへ渡さず、他の合格INFを継続する。
				if( inf.state != CommonInfInspectionState::VERIFIED) {
					continue ;
				}

				// 合格INFは一つの所有workspaceと一つの解析済みpackageを必須とする。
				if( !inf.workspace || inf.closure.packages.size() != 1U ||
				   result.examinedPairCount == std::numeric_limits<std::uint32_t>::max()) {
					results.clear() ;
					return static_cast<NativeError>( E_INVALIDARG) ;
				}

				// BlockingするWindows列挙の各組合せ間で利用者の取消しを反映する。
				if( cancellation && cancellation()) {
					results.clear() ;
					return fromWin32( ERROR_CANCELLED) ;
				}

				std::optional<std::uint32_t> candidateRank ;	// Windowsが返す一致nodeの最小rank。
				// Observerが返した現在組合せの完了診断値です。
				const NativeError			 error =
					rankObserver( activeScanSessionId, device.deviceIdentity, *inf.workspace,
								 inf.closure.packages.front(), candidateRank) ;
				++result.examinedPairCount ;
				// API失敗を非適用へ読み替えず、最初の診断値と件数を保持する。
				if( error != 0) {
					++result.failedPairCount ;
					// 最初の個別失敗だけを非機密reportへ残す。
					if( result.firstPairError == 0) {
						result.firstPairError = error ;
					}
				}
				// Windowsが一致nodeを返した組合せだけを適用可能として数える。
				else if( candidateRank.has_value()) {
					++result.applicablePairCount ;
				}
			}

			pending.push_back( std::move( result)) ;
		}

		// 全組合せ後の取消しも部分成功を公開せず確定取消しにする。
		if( cancellation && cancellation()) {
			return fromWin32( ERROR_CANCELLED) ;
		}

		results = std::move( pending) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		results.clear() ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		// 外部callbackを含む例外をworker境界から漏らさず、部分結果を破棄する。
		results.clear() ;
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_package_inspection.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
std::optional<OfficialPreparationAuditReport> makeDelegatedOfficialPreparationAuditReport(
	const OfficialPreparationTarget &target, const OfficialDiscoveryPackageGroup &group,
	const OfficialRecordPayloadDescriptor &descriptor,
	const std::span<const std::wstring>	   candidateIdentities,
	const OfficialAcquisitionResult &acquisition, const NativeError inspectionError,
	const CommonDriverPackageInspection &packageInspection, const NativeError applicabilityError,
	const std::span<const DelegatedOfficialDeviceApplicability> applicability)
{
	// 承認target、scan descriptorと成功取得ledgerをURL非保持identityで再結合する。
	if( target.identity.empty() || target.identity.size() > MAXIMUM_IDENTITY_CHARACTERS ||
	   !isOfficialDiscoveryPackageGroupValid( group) || target.identity != group.packageIdentity ||
	   target.providerId != descriptor.providerId || descriptor.providerId != group.providerId ||
	   descriptor.policyId != group.policyId || descriptor.rootResourceId != group.rootResourceId ||
	   descriptor.recordFingerprint.bytes != group.recordFingerprint.bytes ||
	   descriptor.payloadCount != group.payloadCount ||
	   descriptor.payloadOrdinal != group.payloadOrdinal || group.recordEvidenceIds.empty() ||
	   descriptor.recordEvidenceId != group.recordEvidenceIds.front() ||
	   target.resourceId != descriptor.payloadResourceId || target.maximumBytes == 0U ||
	   target.deviceCount == 0U || target.deviceCount > MAXIMUM_DEVICE_COUNT ||
	   candidateIdentities.size() != target.deviceCount || candidateIdentities.empty() ||
	   group.deviceIdentities.size() != target.deviceCount ||
	   !isOfficialRecordPayloadDescriptorValid( descriptor) || !descriptor.downloadGrantSupported ||
	   acquisition.state != OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ||
	   acquisition.error != 0 || !acquisition.delegatedRecord ||
	   acquisition.scanSessionId != descriptor.scanSessionId ||
	   acquisition.providerId != descriptor.providerId ||
	   acquisition.resourceId != descriptor.payloadResourceId ||
	   acquisition.recordEvidenceId != descriptor.recordEvidenceId ||
	   acquisition.acquisitionId == 0U || acquisition.downloadGrantId == 0U ||
	   acquisition.byteCount == 0U || acquisition.byteCount > target.maximumBytes ||
	   acquisition.publishedSizeVerified != descriptor.publishedSizeBytes.has_value() ||
	   (descriptor.publishedSizeBytes && acquisition.byteCount != *descriptor.publishedSizeBytes) ||
	   acquisition.publishedSha256Verified != descriptor.publishedSha256Available) {
		return std::nullopt ;
	}

	try {
		std::unordered_set<std::wstring_view> knownCandidates ;	// 既存候補IDの一意性集合。
		knownCandidates.reserve( candidateIdentities.size()) ;
		// 空、過大または重複した表示行へ監査結果を結合しない。
		for( const std::wstring &identity : candidateIdentities) {
			// 一意な有限opaque IDだけを既存表示行との対応へ使用する。
			if( identity.empty() || identity.size() > MAXIMUM_IDENTITY_CHARACTERS ||
			   !knownCandidates.insert( identity).second) {
				return std::nullopt ;
			}
		}

		OfficialPreparationAuditReport report ;	// URL、path、hashとPnP IDを含まない表示結果。
		report.targetIdentity = target.identity ;
		report.providerId	  = target.providerId ;
		// Payload方式に応じ、実装済み内容監査だけを合否へ変換する。
		switch( descriptor.route) {
			// 標準INF packageだけを共通内容・PnP監査の集計へ進める。
			case OfficialRecordPayloadRoute::COMMON_INF_INSPECTION: {
				// 全体内容検査失敗時は部分結果や適用性を表示へ混在させない。
				if( inspectionError != 0) {
					// 失敗時の空出力契約または未実施PnP状態が崩れていればreportを拒否する。
					if( (packageInspection.error != 0 &&
						packageInspection.error != inspectionError) ||
					   packageInspection.scanSessionId != 0U ||
					   !packageInspection.archiveSha256.empty() ||
					   packageInspection.archiveBytes != 0U || !packageInspection.infs.empty() ||
					   applicabilityError != 0 || !applicability.empty()) {
						return std::nullopt ;
					}

					report.content		= CandidateAuditGateState::FAILURE ;
					report.contentError = inspectionError ;
					break ;
				}

				// 成功した共通検査は同じ取得file identityと有限INF集合を必須とする。
				if( packageInspection.error != 0 ||
				   packageInspection.scanSessionId != descriptor.scanSessionId ||
				   packageInspection.archiveSha256 != acquisition.sha256 ||
				   packageInspection.archiveBytes != acquisition.byteCount ||
				   packageInspection.infs.size() > OFFICIAL_PREPARATION_MAXIMUM_INF_COUNT) {
					return std::nullopt ;
				}

				report.infCount = static_cast<std::uint32_t>( packageInspection.infs.size()) ;
				// 個別拒否を保持しながら、合格したINF数だけを内容gateへ集計する。
				for( const CommonInfInspection &inf : packageInspection.infs) {
					// 合格行は後続PnP観測が利用できる所有閉包を必須とする。
					if( inf.state == CommonInfInspectionState::VERIFIED) {
						// 成功状態、所有物と有限件数の矛盾を監査合格へ含めない。
						if( inf.error != 0 || !inf.workspace || inf.closure.packages.size() != 1U ||
						   report.acceptedInfCount >= OFFICIAL_PREPARATION_MAXIMUM_INF_COUNT) {
							return std::nullopt ;
						}

						++report.acceptedInfCount ;
					}
					// 拒否行は最初の診断値を残し、合格行の監査を妨げない。
					else {
						// 理由のない拒否状態を表示用拒否へ補完しない。
						if( inf.error == 0) {
							return std::nullopt ;
						}

						// 最初の内容拒否だけを利用者向け集計へ保持する。
						if( report.firstContentRejection == 0) {
							report.firstContentRejection = inf.error ;
						}
					}
				}

				// 一件以上の完全閉包だけを内容合格とし、INFなし・全拒否を区別する。
				report.content = report.acceptedInfCount != 0U ? CandidateAuditGateState::PASSED
															   : CandidateAuditGateState::REJECTED ;
				// 内容合格前はPnP結果を受理せず、未実施状態を維持する。
				if( report.content != CandidateAuditGateState::PASSED) {
					// 内容不合格後に作られたPnP状態をreportへ混在させない。
					if( applicabilityError != 0 || !applicability.empty()) {
						return std::nullopt ;
					}

					break ;
				}

				// PnP全体失敗時は個別部分結果を表示へ流用しない。
				if( applicabilityError != 0) {
					// 全体失敗時の部分的なdevice結果を適用性表示へ使わない。
					if( !applicability.empty()) {
						return std::nullopt ;
					}

					report.applicability	  = CandidateAuditGateState::FAILURE ;
					report.applicabilityError = applicabilityError ;
					break ;
				}

				// 正常完了したPnP結果は全candidateと同順・同数であることを要求する。
				if( applicability.size() != candidateIdentities.size()) {
					return std::nullopt ;
				}

				std::unordered_set<std::wstring_view> knownDevices ;	// PnP結果内のdevice一意性集合。
				knownDevices.reserve( applicability.size()) ;
				// Device別件数とHRESULTを検証して有限な全体集計を作る。
				for( std::size_t index = 0U; index < applicability.size(); ++index) {
					const DelegatedOfficialDeviceApplicability &device =
						applicability[index] ;	// Groupと同じindexのPnP観測結果。
					// Device順、一意性、INF組合せ件数と失敗診断の矛盾を拒否する。
					if( device.deviceIdentity.empty() ||
					   device.deviceIdentity.size() > MAXIMUM_IDENTITY_CHARACTERS ||
					   device.deviceIdentity != group.deviceIdentities[index] ||
					   !knownDevices.insert( device.deviceIdentity).second ||
					   device.examinedPairCount != report.acceptedInfCount ||
					   device.applicablePairCount > device.examinedPairCount ||
					   device.failedPairCount >
						   device.examinedPairCount - device.applicablePairCount ||
					   (device.failedPairCount == 0U) != (device.firstPairError == 0)) {
						return std::nullopt ;
					}

					// 先行deviceの集計で総予算を消費済みなら後続結果を受理しません。
					if( device.examinedPairCount >
					   OFFICIAL_PREPARATION_MAXIMUM_PAIR_COUNT - report.examinedPairCount) {
						return std::nullopt ;
					}

					report.examinedPairCount += device.examinedPairCount ;
					report.applicablePairCount += device.applicablePairCount ;
					report.failedPairCount += device.failedPairCount ;
					// 最初の個別API失敗だけを全体reportへ保持する。
					if( report.firstPairError == 0 && device.firstPairError != 0) {
						report.firstPairError = device.firstPairError ;
					}
				}

				// 一件でもWindows一致があれば合格、なければ失敗有無で拒否と判定不能を分ける。
				report.applicability =
					report.applicablePairCount != 0U
						? CandidateAuditGateState::PASSED
						: (report.failedPairCount != 0U ? CandidateAuditGateState::FAILURE
														: CandidateAuditGateState::REJECTED) ;
				break ;
			}

			case OfficialRecordPayloadRoute::DEDICATED_INSTALLER_AUDIT:
				// Installerは取得済みでも専用内容監査未接続のため、合否を補完しない。
				if( inspectionError == 0 || packageInspection.scanSessionId != 0U ||
				   !packageInspection.infs.empty() || applicabilityError != 0 ||
				   !applicability.empty()) {
					return std::nullopt ;
				}

				report.contentError = inspectionError ;
				break ;

			case OfficialRecordPayloadRoute::DISPLAY_ONLY_UNSUPPORTED:
			// 未対応方式は取得対象ではなく、本reportへ昇格させない。
			default:
				return std::nullopt ;
		}

		report.candidates.reserve( candidateIdentities.size()) ;
		// Scanで発行済みの各表示行へ同じ取得・内容集計とdevice別PnP結果を結合する。
		for( std::size_t index = 0U; index < candidateIdentities.size(); ++index) {
			OfficialPreparationCandidateAudit row ;	// Install禁止を維持する一表示行の監査状態。
			row.identity				 = candidateIdentities[index] ;
			row.audit					 = makeOfficialDiscoveryCandidateAudit() ;
			row.audit.inspectionDownload = CandidateAuditGateState::PASSED ;
			row.audit.contentIntegrity	 = report.content ;
			// 内容合格後だけdevice別Windows観測を行状態へ反映する。
			if( report.content == CandidateAuditGateState::PASSED) {
				// PnP全体失敗では全行を判定不能として表示する。
				if( report.applicabilityError != 0) {
					row.audit.systemApplicability = CandidateAuditGateState::FAILURE ;
				}
				// 一件以上の一致nodeを持つdeviceだけを適用性合格とする。
				else if( applicability[index].applicablePairCount != 0U) {
					row.audit.systemApplicability = CandidateAuditGateState::PASSED ;
				}
				// 個別API失敗を非適用へ読み替えない。
				else if( applicability[index].failedPairCount != 0U ||
						report.failedPairCount != 0U) {
					row.audit.systemApplicability = CandidateAuditGateState::FAILURE ;
				} else {
					// 全組合せを正常確認して一致がないdeviceだけを非適用とする。
					row.audit.systemApplicability = CandidateAuditGateState::REJECTED ;
				}
			}

			report.candidates.push_back( std::move( row)) ;
		}

		return report ;
	} catch( const std::bad_alloc &) {
		return std::nullopt ;
	} catch( ...) {
		// 文字列・集合構築の例外から部分reportを公開しない。
		return std::nullopt ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_package_inspection.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
bool makeDelegatedOfficialInfCandidateAssessment(
	const ScanSessionId activeScanSessionId, const DelegatedOfficialPackageInput &input,
	const UpdateCandidate &candidate, const CommonDriverPackageInspection &packageInspection,
	const std::size_t infOrdinal, const std::uint64_t packageEvidenceId,
	const NativeError applicabilityError, const std::optional<std::uint32_t> candidateRank,
	CandidateAssessment &assessment)
{
	assessment = {} ;
	// Stale session、改変された入力または別Provider候補へ公式由来を再利用しない。
	if( activeScanSessionId == 0U || input.provenance.scanSessionId != activeScanSessionId ||
	   !isValidInput( input) || candidate.providerId != input.provenance.providerId) {
		return false ;
	}

	// 全体失敗、別archiveまたは範囲外INFの部分結果を表示候補へ結合しない。
	if( packageInspection.error != 0 || packageInspection.scanSessionId != activeScanSessionId ||
	   packageInspection.archiveSha256 != input.archive.sha256 ||
	   packageInspection.archiveBytes != input.archive.byteCount ||
	   infOrdinal >= packageInspection.infs.size()) {
		return false ;
	}

	const CandidateAssessmentFinding origin{
		CandidateAssessmentState::PASSED, CandidateAssessmentReason::VALIDATED,
		CandidateEvidenceKind::OFFICIAL_RECORD,
		input.provenance.recordEvidenceId} ;	// 取得物内容とは独立した公式record由来証拠。
	CandidateAssessment pending ;				// 全八軸の能力制約を再確認後だけ公開する結果。
	// 共通builderに実内容、Windows適合と由来を渡し、identity不整合を拒否する。
	if( !makeCommonInfCandidateAssessment( activeScanSessionId, candidate,
										 packageInspection.infs[infOrdinal], packageEvidenceId,
										 origin, applicabilityError, candidateRank, pending)) {
		return false ;
	}

	// 内容・由来・適合が合格しても未接続executorを導入可能へ昇格させない。
	if( pending.origin.evidenceId != input.provenance.recordEvidenceId ||
	   pending.method.state != CandidateAssessmentState::UNSUPPORTED ||
	   pending.method.reason != CandidateAssessmentReason::EXECUTOR_UNAVAILABLE ||
	   pending.executorAvailable || isCandidateAssessmentReady( pending)) {
		return false ;
	}

	assessment = std::move( pending) ;
	return true ;
}

} // namespace drivercrate
