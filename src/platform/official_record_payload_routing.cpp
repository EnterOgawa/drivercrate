//------------------------------------------------------------------------------
/**
 * @file official_record_payload_routing.cpp
 * @brief 検証済み公式record payloadのURL非保持方式分類実装。
 * @version 01.03.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  三方式のURL非保持payload descriptorを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  方式別の表示専用候補評価を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  自動探索のdevice別表示専用候補生成を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/23  取得専用型を内容検査・導入routingから拒否。
 * </pre>
 *
 * @note 方式分類はrecord parserの型付き値を正本とし、拡張子やcontent typeによるfallbackを行いません。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#include "platform/official_record_payload_routing.h"

#include "core/candidate_audit.h"
#include "core/candidate_selection.h"
#include "platform/official_discovery_package.h"

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <new>
#include <ranges>
#include <span>
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

constexpr std::size_t MAXIMUM_ID_CHARACTERS = 256U ;				// Stable IDとroute fieldの文字数上限です。
constexpr std::size_t MAXIMUM_FILE_NAME_CHARACTERS = 260U ;			// 公開basenameの文字数上限です。
constexpr std::size_t MAXIMUM_PRODUCT_CHARACTERS   = 512U ;			// 公開製品系列の文字数上限です。
constexpr std::size_t MAXIMUM_OS_CHARACTERS		   = 256U ;			// 対象OS表示の文字数上限です。
constexpr std::size_t MAXIMUM_VERSION_CHARACTERS   = 128U ;			// Package版表示の文字数上限です。
constexpr std::size_t MAXIMUM_DATE_CHARACTERS	   = 128U ;			// 公開日表示の文字数上限です。
constexpr std::size_t MAXIMUM_PUBLISHER_CHARACTERS = 512U ;			// 自己申告publisherの文字数上限です。
constexpr std::size_t MAXIMUM_EULA_REVISION_CHARACTERS = 4'096U ;	// EULA改訂識別子上限です。

// 自動探索の非選択行を他の候補namespaceと衝突させない固定prefixです。
constexpr std::wstring_view AUTOMATIC_CANDIDATE_PREFIX = L"official-candidate:" ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

/**
 * @brief Plain textが有限で制御文字を含まないか確認します。
 * @param[in] value 検証する文字列です。
 * @param[in] maximumCharacters 許可するUTF-16 code unit上限です。
 * @param[in] allowEmpty 空文字列を許可する場合trueです。
 * @return 指定した有限plain text条件を満たす場合trueです。
 */
[[nodiscard]] bool isFiniteText( const std::wstring_view value, const std::size_t maximumCharacters,
								const bool allowEmpty) noexcept
{
	// 空値の可否と文字数上限を走査前に確定する。
	if( (!allowEmpty && value.empty()) || value.size() > maximumCharacters) {
		return false ;
	}

	// 全code unitを確認し、制御文字を表示descriptorへ複製しない。
	for( const wchar_t character : value) {
		// NUL、C0、DELを公開metadataへ残さない。
		if( character < L' ' || character == L'\x7f') {
			return false ;
		}
	}

	return true ;
}

/**
 * @brief Scan内のrecord証拠とpayload順だけから有限の表示行identityを作ります。
 * @param[in] descriptor 検証済みpayload descriptorです。
 * @param[in] deviceOrdinal Group内の0起点device順です。
 * @return URL、表示名、PnP IDを含まない256文字以下のopaque identityです。
 * @throws std::bad_alloc 文字列領域を確保できない場合です。
 */
[[nodiscard]] std::wstring makeAutomaticCandidateIdentity(
	const OfficialRecordPayloadDescriptor &descriptor, const std::size_t deviceOrdinal)
{
	std::wstring identity{AUTOMATIC_CANDIDATE_PREFIX} ;	// 固定namespaceを持つ生成値です。
	identity.append( std::to_wstring( descriptor.scanSessionId)) ;
	identity.push_back( L':') ;
	identity.append( std::to_wstring( descriptor.recordEvidenceId)) ;
	identity.push_back( L':') ;
	identity.append( std::to_wstring( descriptor.payloadOrdinal)) ;
	identity.push_back( L':') ;
	identity.append( std::to_wstring( deviceOrdinal)) ;
	return identity ;
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
 * @brief 二つの公式root取得証拠が全fieldで一致するか確認します。
 * @param[in] left 比較元です。
 * @param[in] right 比較先です。
 * @return URL非保持の全取得fieldが一致する場合trueです。
 */
[[nodiscard]] bool sameSourceEvidence( const OfficialSourceEvidence &left,
									  const OfficialSourceEvidence &right) noexcept
{
	return left.scanSessionId == right.scanSessionId && left.acquisitionId == right.acquisitionId &&
		   left.providerId == right.providerId && left.policyId == right.policyId &&
		   left.resourceId == right.resourceId && left.redirectCount == right.redirectCount &&
		   left.originPolicyIndices == right.originPolicyIndices &&
		   left.acquisition == right.acquisition &&
		   left.bodyAcquiredUtcSeconds == right.bodyAcquiredUtcSeconds &&
		   left.originValidatedUtcSeconds == right.originValidatedUtcSeconds &&
		   left.cachePermitted == right.cachePermitted ;
}

/**
 * @brief 二つのrecord evidenceが同じ検証snapshotか確認します。
 * @param[in] left 比較元です。
 * @param[in] right 比較先です。
 * @return Root、record ID、parser、fingerprint、件数と時刻が一致する場合trueです。
 */
[[nodiscard]] bool sameRecordEvidence( const OfficialDistributionRecordEvidence &left,
									  const OfficialDistributionRecordEvidence &right) noexcept
{
	return sameSourceEvidence( left.rootEvidence, right.rootEvidence) &&
		   left.recordEvidenceId == right.recordEvidenceId &&
		   left.parserRevision == right.parserRevision &&
		   left.stableFingerprint.bytes == right.stableFingerprint.bytes &&
		   left.payloadCount == right.payloadCount &&
		   left.resolvedUtcSeconds == right.resolvedUtcSeconds ;
}

/**
 * @brief Payload kindを拡張子に依存しない次段routeへ写像します。
 * @param[in] kind Parserが明示したpayload kindです。
 * @return 三方式に対応する固定routeです。
 */
[[nodiscard]] OfficialRecordPayloadRoute routeForKind(
	const OfficialDistributionPayloadKind kind) noexcept
{
	// Parserが明示した方式だけで次の検査境界を決める。
	switch( kind) {
		// 標準INF packageは共通内容検査だけへ渡す。
		case OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE:
			return OfficialRecordPayloadRoute::COMMON_INF_INSPECTION ;
		// InstallerはINF parserへ渡さず専用監査待ちにする。
		case OfficialDistributionPayloadKind::OFFICIAL_INSTALLER:
			return OfficialRecordPayloadRoute::DEDICATED_INSTALLER_AUDIT ;
		// 未対応方式は取得せず表示だけを許可する。
		case OfficialDistributionPayloadKind::UNSUPPORTED:
			return OfficialRecordPayloadRoute::DISPLAY_ONLY_UNSUPPORTED ;
		// 開発用取得専用には製品の検査・導入routeを割り当てない。
		case OfficialDistributionPayloadKind::DOWNLOAD_ONLY_FILE:
			return OfficialRecordPayloadRoute::DISPLAY_ONLY_UNSUPPORTED ;
	}

	return OfficialRecordPayloadRoute::DISPLAY_ONLY_UNSUPPORTED ;
}

/**
 * @brief 公開basenameが共通INF検査で扱うZIP／CABか確認します。
 * @param[in] fileDisplayName Recordが明示したdirectoryなしbasenameです。
 * @return 最終拡張子がcase-insensitiveな`.zip`または`.cab`の場合trueです。
 */
[[nodiscard]] bool isCommonInfArchiveName( const std::wstring_view fileDisplayName)
{
	const std::size_t dot = fileDisplayName.find_last_of( L'.') ;	// 最終拡張子の開始位置です。
	// 拡張子がなければ内容からINF archiveと推測しない。
	if( dot == std::wstring_view::npos) {
		return false ;
	}

	std::wstring extension( fileDisplayName.substr( dot)) ;	// ASCII小文字化する拡張子です。
	std::ranges::transform( extension, extension.begin(), []( const wchar_t character) noexcept {
		return character >= L'A' && character <= L'Z'
				   ? static_cast<wchar_t>( character - L'A' + L'a')
				   : character ;
	}) ;
	return extension == L".zip" || extension == L".cab" ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_record_payload_routing.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
bool isOfficialRecordPayloadDescriptorValid(
	const OfficialRecordPayloadDescriptor &descriptor) noexcept
{
	// URL非保持identityと公開表示metadataを有限値に限定する。
	if( descriptor.scanSessionId == 0U || descriptor.recordEvidenceId == 0U ||
	   !isFiniteText( descriptor.providerId, MAXIMUM_ID_CHARACTERS, false) ||
	   !isFiniteText( descriptor.policyId, MAXIMUM_ID_CHARACTERS, false) ||
	   !isFiniteText( descriptor.rootResourceId, MAXIMUM_ID_CHARACTERS, false) ||
	   !hasRecordFingerprint( descriptor.recordFingerprint) || descriptor.payloadCount == 0U ||
	   descriptor.payloadCount > 32U || descriptor.payloadOrdinal >= descriptor.payloadCount ||
	   !isFiniteText( descriptor.payloadResourceId, MAXIMUM_ID_CHARACTERS, false) ||
	   !isFiniteText( descriptor.fileDisplayName, MAXIMUM_FILE_NAME_CHARACTERS, false) ||
	   descriptor.fileDisplayName.find_first_of( L"/\\") != std::wstring::npos ||
	   !isFiniteText( descriptor.productFamily, MAXIMUM_PRODUCT_CHARACTERS, false) ||
	   !isFiniteText( descriptor.operatingSystem, MAXIMUM_OS_CHARACTERS, false) ||
	   !isFiniteText( descriptor.packageVersion, MAXIMUM_VERSION_CHARACTERS, true) ||
	   !isFiniteText( descriptor.publishedDate, MAXIMUM_DATE_CHARACTERS, true) ||
	   !isFiniteText( descriptor.declaredPublisher, MAXIMUM_PUBLISHER_CHARACTERS, true) ||
	   !isFiniteText( descriptor.eulaRevision, MAXIMUM_EULA_REVISION_CHARACTERS, true) ||
	   descriptor.executorAvailable) {
		return false ;
	}

	// 未知のDownload前同意区分を表示または取得判断へ使用しない。
	if( descriptor.terms != OfficialDistributionTerms::CONFIRMED_NO_CONSENT &&
	   descriptor.terms != OfficialDistributionTerms::ACCEPTANCE_REQUIRED) {
		return false ;
	}

	// Download前同意区分とEULA revisionの有無を一致させる。
	if( (descriptor.terms == OfficialDistributionTerms::CONFIRMED_NO_CONSENT &&
		descriptor.eulaRevision.size() != 0U) ||
	   (descriptor.terms == OfficialDistributionTerms::ACCEPTANCE_REQUIRED &&
		descriptor.eulaRevision.empty())) {
		return false ;
	}

	// 三つのpayload kindとroute、現在実装済み能力を固定対応にする。
	switch( descriptor.payloadKind) {
		// INFはgrantと共通静的検査を持つがexecutorはまだ接続しない。
		case OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE:
			return descriptor.route == OfficialRecordPayloadRoute::COMMON_INF_INSPECTION &&
				   descriptor.downloadGrantSupported &&
				   descriptor.contentInspectorAvailable ==
					   isCommonInfArchiveName( descriptor.fileDisplayName) ;
		// Installerはgrantを持つが専用監査とexecutorを未接続のまま示す。
		case OfficialDistributionPayloadKind::OFFICIAL_INSTALLER:
			return descriptor.route == OfficialRecordPayloadRoute::DEDICATED_INSTALLER_AUDIT &&
				   descriptor.downloadGrantSupported && !descriptor.contentInspectorAvailable ;
		// 未対応方式はrecord表示以外の能力を持たない。
		case OfficialDistributionPayloadKind::UNSUPPORTED:
			return descriptor.route == OfficialRecordPayloadRoute::DISPLAY_ONLY_UNSUPPORTED &&
				   !descriptor.downloadGrantSupported && !descriptor.contentInspectorAvailable ;
		// 未検査取得を製品の表示・検査descriptorへ昇格しない。
		case OfficialDistributionPayloadKind::DOWNLOAD_ONLY_FILE:
			return false ;
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_record_payload_routing.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError describeOfficialDistributionRecordPayloads(
	const OfficialDistributionRecord &record, const OfficialDistributionRecordEvidence &evidence,
	std::vector<OfficialRecordPayloadDescriptor> &descriptors) noexcept
{
	descriptors.clear() ;
	OfficialDistributionRecordEvidence current ;	// 現在recordから再計算する証拠です。
	const NativeError				   validationError =
		// Record全体の再検証結果です。
		validateOfficialDistributionRecord( record, current) ;
	// 無効recordまたは別snapshotの証拠から表示descriptorを作らない。
	if( validationError != 0) {
		return validationError ;
	}

	// URL差替えを除く全証拠fieldが呼出し元snapshotと一致しない場合は拒否する。
	if( !sameRecordEvidence( current, evidence)) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH)) ;
	}

	try {
		std::vector<OfficialRecordPayloadDescriptor> pending ;	// 全件成功後だけ公開する結果です。
		pending.reserve( record.payloads.size()) ;
		// Record順の全payloadを一回ずつ分類し、unsupportedも欠落させない。
		for( const OfficialDistributionPayloadRecord &payload : record.payloads) {
			const OfficialRecordPayloadRoute route =
				// 型だけの固定route。
				routeForKind( payload.kind) ;
			// 秘密値を除外してrecordとpayloadの表示・能力だけを保持する一行です。
			OfficialRecordPayloadDescriptor descriptor{
				.scanSessionId			  = record.rootEvidence.scanSessionId,
				.recordEvidenceId		  = record.recordEvidenceId,
				.providerId				  = record.rootEvidence.providerId,
				.policyId				  = record.rootEvidence.policyId,
				.rootResourceId			  = record.rootEvidence.resourceId,
				.recordFingerprint		  = current.stableFingerprint,
				.payloadCount			  = current.payloadCount,
				.payloadOrdinal			  = payload.payloadOrdinal,
				.payloadResourceId		  = payload.resourceId,
				.payloadKind			  = payload.kind,
				.route					  = route,
				.fileDisplayName		  = payload.fileDisplayName,
				.productFamily			  = record.productFamily,
				.operatingSystem		  = record.operatingSystem,
				.packageVersion			  = record.packageVersion,
				.publishedDate			  = record.publishedDate,
				.publishedSizeBytes		  = payload.publishedSizeBytes,
				.publishedSha256Available = !payload.publishedSha256.empty(),
				.declaredPublisher		  = payload.publisher,
				.terms					  = record.terms,
				.eulaRevision			  = record.eulaRevision,
				.downloadGrantSupported =
					payload.kind != OfficialDistributionPayloadKind::UNSUPPORTED,
				.contentInspectorAvailable =
					payload.kind == OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE &&
					isCommonInfArchiveName( payload.fileDisplayName),
				.executorAvailable = false} ;
			// 不正な一行を部分表示せずrecord全体を拒否する。
			if( !isOfficialRecordPayloadDescriptorValid( descriptor)) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			pending.push_back( std::move( descriptor)) ;
		}

		descriptors = std::move( pending) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		// 文字列とvector copyの例外をworker境界から漏らさない。
		return static_cast<NativeError>( E_FAIL) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_record_payload_routing.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
bool makeOfficialRecordPayloadDisplayAssessment( const OfficialRecordPayloadDescriptor &descriptor,
												const UpdateCandidate				  &candidate,
												CandidateAssessment					  &assessment)
{
	assessment = {} ;
	// 公式探索の非現在・非選択候補と同じProviderだけへrecord由来を結合する。
	if( !isOfficialRecordPayloadDescriptorValid( descriptor) || candidate.current ||
	   candidate.installable || candidate.recommended ||
	   candidate.providerId != descriptor.providerId ||
	   (candidate.discoveryBasis != CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG &&
		candidate.discoveryBasis != CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE) ||
	   candidate.audit.sourceOrigin != CandidateAuditGateState::PASSED ||
	   candidate.audit.installReadiness != CandidateInstallReadiness::BLOCKED) {
		return false ;
	}

	CandidateAssessment pending ;	// 全方式の能力制約を検証後だけ公開する八軸評価です。
	pending.scanSessionId	  = descriptor.scanSessionId ;
	pending.candidateIdentity = candidate.identity ;
	pending.deviceIdentity	  = candidate.deviceIdentity ;
	pending.packageIdentity	  = candidate.packageIdentity ;
	pending.origin		  = {CandidateAssessmentState::PASSED, CandidateAssessmentReason::VALIDATED,
							 CandidateEvidenceKind::OFFICIAL_RECORD, descriptor.recordEvidenceId} ;
	pending.signature	  = {CandidateAssessmentState::NOT_CHECKED,
							 CandidateAssessmentReason::NOT_EXAMINED, CandidateEvidenceKind::NONE, 0U} ;
	pending.applicability = pending.signature ;
	pending.windowsSelection  = pending.signature ;
	pending.driverOnly		  = pending.signature ;
	pending.requirements	  = pending.signature ;
	pending.method			  = {CandidateAssessmentState::UNSUPPORTED,
								 CandidateAssessmentReason::EXECUTOR_UNAVAILABLE,
								 CandidateEvidenceKind::IMPLEMENTATION_POLICY, descriptor.recordEvidenceId} ;
	pending.executorAvailable = false ;

	// Payload方式ごとに未取得・未対応と導入方式を固定し、拡張子から別routeへ切り替えない。
	switch( descriptor.payloadKind) {
		// 検査可能なINF archiveは内容未取得として示す。
		case OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE:
			pending.installMethod = CandidateInstallMethod::STANDARD_INF ;
			pending.acquisition =
				descriptor.contentInspectorAvailable
					? CandidateAssessmentFinding{CandidateAssessmentState::NOT_CHECKED,
												 CandidateAssessmentReason::NOT_ACQUIRED,
												 CandidateEvidenceKind::OFFICIAL_RECORD,
												 descriptor.recordEvidenceId}
					: CandidateAssessmentFinding{CandidateAssessmentState::UNSUPPORTED,
												 CandidateAssessmentReason::FORMAT_UNSUPPORTED,
												 CandidateEvidenceKind::IMPLEMENTATION_POLICY,
												 descriptor.recordEvidenceId} ;
			break ;

		// InstallerはINF検査へ渡さず、専用監査未接続の未取得状態を示す。
		case OfficialDistributionPayloadKind::OFFICIAL_INSTALLER:
			pending.installMethod = CandidateInstallMethod::OFFICIAL_INSTALLER ;
			pending.acquisition	  = {
				  CandidateAssessmentState::NOT_CHECKED, CandidateAssessmentReason::NOT_ACQUIRED,
				  CandidateEvidenceKind::OFFICIAL_RECORD, descriptor.recordEvidenceId} ;
			break ;

		// 未対応方式は取得せず、内容方式も未対応として表示する。
		case OfficialDistributionPayloadKind::UNSUPPORTED:
			pending.installMethod = CandidateInstallMethod::UNDETERMINED ;
			pending.acquisition	  = {CandidateAssessmentState::UNSUPPORTED,
									 CandidateAssessmentReason::FORMAT_UNSUPPORTED,
									 CandidateEvidenceKind::IMPLEMENTATION_POLICY,
									 descriptor.recordEvidenceId} ;
			pending.driverOnly	  = pending.acquisition ;
			break ;

		// 開発用取得専用を標準導入やinstaller方式へ変換しない。
		case OfficialDistributionPayloadKind::DOWNLOAD_ONLY_FILE:
			return false ;
	}

	// 全八軸とopaque identityが結合できず、またはexecutorが現れた結果を公開しない。
	if( !isCandidateAssessmentBound( pending, descriptor.scanSessionId, candidate.identity,
								   candidate.deviceIdentity, candidate.packageIdentity) ||
	   pending.executorAvailable || isCandidateAssessmentReady( pending)) {
		return false ;
	}

	assessment = std::move( pending) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_record_payload_routing.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
std::optional<std::vector<UpdateCandidate>> makeOfficialRecordPayloadDisplayCandidates(
	const OfficialDiscoveryPackageGroup &group, const OfficialRecordPayloadDescriptor &descriptor,
	const std::span<const OfficialDiscoveryDeviceHint> devices, const ProviderDescriptor &provider)
{
	// Group、descriptor、registryの不変fieldを照合してからdevice表示値を参照する。
	if( !isOfficialDiscoveryPackageGroupValid( group) ||
	   !isOfficialRecordPayloadDescriptorValid( descriptor) ||
	   descriptor.providerId != group.providerId || descriptor.policyId != group.policyId ||
	   descriptor.rootResourceId != group.rootResourceId ||
	   descriptor.recordFingerprint.bytes != group.recordFingerprint.bytes ||
	   descriptor.payloadCount != group.payloadCount ||
	   descriptor.payloadOrdinal != group.payloadOrdinal || provider.id != group.providerId ||
	   provider.discoveryBasis == CandidateDiscoveryBasis::UNSPECIFIED ||
	   std::find( group.recordEvidenceIds.begin(), group.recordEvidenceIds.end(),
				 descriptor.recordEvidenceId) == group.recordEvidenceIds.end()) {
		return std::nullopt ;
	}

	try {
		std::vector<UpdateCandidate> candidates ;				// 全device照合後だけ返す非選択表示行集合。
		std::unordered_set<std::wstring_view> knownDevices ;	// 入力hintの一意性検証集合。
		knownDevices.reserve( devices.size()) ;
		// 同じscan以外のhintと重複identityをgroup検索へ使わない。
		for( const OfficialDiscoveryDeviceHint &device : devices) {
			// 一件でも不正または重複なら部分候補を返さない。
			if( !validateOfficialDiscoveryDeviceHint( device, descriptor.scanSessionId) ||
			   !knownDevices.insert( device.deviceIdentity).second) {
				return std::nullopt ;
			}
		}

		candidates.reserve( group.deviceIdentities.size()) ;
		// Group順の全deviceを同じpayload metadataと一意な表示行へ結合する。
		for( std::size_t deviceOrdinal{}; deviceOrdinal < group.deviceIdentities.size();
			++deviceOrdinal) {
			const std::wstring &deviceIdentity =
				group.deviceIdentities[deviceOrdinal] ;	// 今回候補へ結合するopaque device ID。
			const auto hint =
				std::find_if( devices.begin(), devices.end(), [&deviceIdentity]( const auto &value) {
					return value.deviceIdentity == deviceIdentity ;
				}) ; // 同じscanの表示値だけを持つdevice hint。
			// Groupが参照するdeviceを別表示名や架空nodeへfallbackしない。
			if( hint == devices.end()) {
				return std::nullopt ;
			}

			UpdateCandidate candidate ;	// 取得前の非選択・導入不可行。
			candidate.identity		  = makeAutomaticCandidateIdentity( descriptor, deviceOrdinal) ;
			candidate.deviceIdentity  = deviceIdentity ;
			candidate.providerId	  = descriptor.providerId ;
			candidate.packageIdentity = group.packageIdentity ;
			candidate.title		   = descriptor.productFamily + L" / " + descriptor.fileDisplayName ;
			candidate.manufacturer = hint->manufacturer ;
			candidate.model		   = hint->model ;
			candidate.driverClass  = hint->deviceClass ;
			candidate.deviceClassGuid = hint->setupClassGuid ;
			candidate.provider		  = descriptor.declaredPublisher ;
			candidate.version		  = descriptor.packageVersion ;
			candidate.driverDate	  = descriptor.publishedDate ;
			candidate.sourceName	  = provider.displayName ;
			candidate.sourceLocation  = L"検証済み公式配布record（payload未取得）" ;
			// 公開exact sizeだけを表示し、未知sizeを0 byteと表示しない。
			if( descriptor.publishedSizeBytes) {
				candidate.maximumDownloadBytes = *descriptor.publishedSizeBytes ;
				candidate.displayDownloadSize =
					std::to_wstring( *descriptor.publishedSizeBytes) + L" byte" ;
			}

			candidate.action			= DriverAction::NONE ;
			candidate.defaultPreference = CandidateDefaultPreference::NONE ;
			candidate.discoveryBasis	= provider.discoveryBasis ;
			candidate.audit				= makeOfficialDiscoveryCandidateAudit() ;
			candidate.discoveryBus		= hint->bus ;
			CandidateAssessment assessment ;	// 方式と未取得理由を結合する詳細snapshot。
			// Descriptor能力と候補監査が一致しない一行を部分的に公開しない。
			if( candidate.identity.size() > OFFICIAL_DISCOVERY_OPAQUE_ID_LIMIT ||
			   !makeOfficialRecordPayloadDisplayAssessment( descriptor, candidate, assessment)) {
				return std::nullopt ;
			}

			candidate.assessment = std::move( assessment) ;
			// Registry能力、監査、詳細bindingを公開直前に再検証する。
			if( !isCandidateDefaultPreferenceValid( candidate, provider) ||
			   !isCandidateAuditValid( candidate, provider) ||
			   !isCandidateDetailsValid( candidate, descriptor.scanSessionId)) {
				return std::nullopt ;
			}

			candidates.push_back( std::move( candidate)) ;
		}

		return candidates ;
	} catch( const std::bad_alloc &) {
		return std::nullopt ;
	} catch( ...) {
		// 表示metadataのcopy失敗を一部候補へ縮退させない。
		return std::nullopt ;
	}
}

} // namespace drivercrate
