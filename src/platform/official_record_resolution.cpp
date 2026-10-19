//------------------------------------------------------------------------------
/**
 * @file official_record_resolution.cpp
 * @brief 未信頼URL入力を組み込み公式rootへ限定して解決するworker境界を実装します。
 * @version 01.01.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  固定root routingと有限session registryを実装。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  非cacheの一回grant再解決を実装。
 * </pre>
 *
 * @note Submitted URLをresolverへ渡さず、Provider registryとsource policyの固定endpointだけを
 *       network起点にします。全recordと秘密URLはworker内session失効時に破棄します。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#include "platform/official_record_resolution.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"

#include <Windows.h>
#include <winhttp.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <span>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t	MAXIMUM_RESOLVER_REGISTRATIONS	 = 64U ;	// Resolver登録上限。
constexpr std::size_t	MAXIMUM_RETAINED_RECORDS		 = 64U ;	// 一scanのrecord上限。
constexpr std::size_t	MAXIMUM_SUBMITTED_URL_CHARACTERS = 8'192U ;	// 未信頼URL上限。
																   // 一root応答の絶対上限。
constexpr std::uint64_t MAXIMUM_RECORD_BYTES = 4ULL * 1'024ULL * 1'024ULL ;

constexpr NativeError	INVALID_ARGUMENT = static_cast<NativeError>( E_INVALIDARG) ;	// 入力違反。
constexpr NativeError	UNEXPECTED		 = static_cast<NativeError>( E_UNEXPECTED) ;	// ID枯渇等。
constexpr NativeError	OUT_OF_MEMORY = static_cast<NativeError>( E_OUTOFMEMORY) ;		// Allocation失敗。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをHRESULT bit patternへ変換します。
 * @param[in] error 変換するWin32 error code。
 * @return NativeErrorで保持するHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 消費済みgrantがADR 0152の一回再解決条件を満たすか確認します。
 * @param[in] metadata URLを含まない元grant metadata。
 * @return 認識済み外部expiry、初回、期限結果と許可診断が揃う場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isReresolutionEligible(
	const RecordScopedDownloadGrantMetadata &metadata) noexcept
{
	const NativeError timeout	   = nativeErrorFromWin32( ERROR_TIMEOUT) ;	// Hop前期限切れ診断。
	const NativeError unauthorized = static_cast<NativeError>(
		// 最初の401。
		MAKE_HRESULT( SEVERITY_ERROR, FACILITY_HTTP, HTTP_STATUS_DENIED)) ;
	const NativeError forbidden = static_cast<NativeError>(
		// 最初の403。
		MAKE_HRESULT( SEVERITY_ERROR, FACILITY_HTTP, HTTP_STATUS_FORBIDDEN)) ;
	return metadata.state == OfficialDownloadGrantState::CONSUMED &&
		   metadata.outcome == OfficialDownloadGrantState::GRANT_EXPIRED &&
		   metadata.externalExpiryPresent && metadata.reresolutionCount == 0U &&
		   (metadata.error == timeout || metadata.error == unauthorized ||
			metadata.error == forbidden) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Stable Provider IDに対応する組み込みdescriptorを検索します。
 * @param[in] providerId 完全一致で検索するID。
 * @return Process lifetime中有効なdescriptor。未登録時はnullptrです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] const ProviderDescriptor *findProviderDescriptor(
	const std::wstring_view providerId) noexcept
{
	const std::span<const ProviderDescriptor> descriptors =
		// 組み込みProvider正本。
		builtInProviderDescriptors() ;
	// Stable IDが完全一致する組み込みProvider位置。
	const auto found = std::find_if(
		descriptors.begin(), descriptors.end(),
		[providerId]( const ProviderDescriptor &descriptor) { return descriptor.id == providerId ; }) ;
	return found == descriptors.end() ? nullptr : std::addressof( *found) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Descriptorが公式network capabilityを明示するか確認します。
 * @param[in] descriptor 組み込みProvider descriptor。
 * @return `OFFICIAL_NETWORK` bitが設定されている場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasOfficialNetworkCapability( const ProviderDescriptor &descriptor) noexcept
{
	return (descriptor.capabilities & capabilityMask( ProviderCapability::OFFICIAL_NETWORK)) != 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのresolver登録が組み込みregistryと固定endpointへ一致するか確認します。
 * @param[in] registration 検証するresolver登録。
 * @return Provider、policy、resource、endpoint、callbackが全て有効な場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidRegistration(
	const OfficialRecordResolverRegistration &registration) noexcept
{
	// 空IDまたは空callbackをProvider登録として扱わない。
	if( registration.providerId.empty() || registration.rootResourceId.empty() ||
	   !registration.resolver) {
		return false ;
	}

	const ProviderDescriptor *const descriptor =
		// Provider正本。
		findProviderDescriptor( registration.providerId) ;
	const OfficialSourcePolicy *const policy =
		// Providerのsource policy。
		officialSourcePolicyForProvider( registration.providerId) ;
	// 公式network capabilityと一対一policyを持たないProviderをresolverへ登録しない。
	if( descriptor == nullptr || policy == nullptr || !hasOfficialNetworkCapability( *descriptor) ||
	   descriptor->officialSourcePolicyId != policy->id) {
		return false ;
	}

	const OfficialSourceResourcePolicy *const resource =
		// Root用途policy。
		findOfficialSourceResource( *policy, registration.rootResourceId) ;
	// Landingまたはmetadata用途以外をrecord rootとして登録しない。
	if( resource == nullptr || (resource->kind != OfficialSourceResourceKind::LANDING_PAGE &&
							   resource->kind != OfficialSourceResourceKind::METADATA)) {
		return false ;
	}

	// 固定metadata endpointを持たないresourceへ未信頼URLからfallbackしない。
	return !officialMetadataEndpoint( registration.providerId, registration.rootResourceId).empty() ;
}

//------------------------------------------------------------------------------
/**
 * @brief CommandのProvider・resourceに完全一致するresolver登録を検索します。
 * @param[in] registrations 検証済みの有限registry。
 * @param[in] providerId 明示された組み込みProvider ID。
 * @param[in] rootResourceId 明示された固定root resource ID。
 * @return Registry要素への非所有pointer。未登録時はnullptrです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] const OfficialRecordResolverRegistration *findRegistration(
	const std::span<const OfficialRecordResolverRegistration> registrations,
	const std::wstring_view providerId, const std::wstring_view rootResourceId) noexcept
{
	// Provider・root resource pairが完全一致する登録位置。
	const auto found = std::find_if(
		registrations.begin(), registrations.end(),
		[providerId, rootResourceId]( const OfficialRecordResolverRegistration &registration) {
			return registration.providerId == providerId &&
				   registration.rootResourceId == rootResourceId ;
		}) ;
	return found == registrations.end() ? nullptr : std::addressof( *found) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未信頼URL入力が秘密所有領域へ保持できる有限文字列か確認します。
 * @param[in] value 直接通信には使用しない提出URL。
 * @return 非空、上限内、NUL・制御文字なしの場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidSubmittedUrl( const std::wstring_view value) noexcept
{
	// 空またはURL長上限を超える入力をroute選択材料として受理しない。
	if( value.empty() || value.size() > MAXIMUM_SUBMITTED_URL_CHARACTERS) {
		return false ;
	}

	// 全UTF-16 code unitを確認し、NULとASCII制御文字を拒否する。
	for( const wchar_t character : value) {
		// Controlを含む入力を表示やnetwork境界へ渡さない。
		if( character < L' ') {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Resolverが返したrecordを選択済みProvider・root・IDへ再結合します。
 * @param[in] record Resolverが構築した型付きrecord。
 * @param[in] evidence 共通検証で作成したURL非保持証拠。
 * @param[in] scanSessionId 現在のsession ID。
 * @param[in] recordEvidenceId 今回割り当てたrecord証拠ID。
 * @param[in] registration 選択した組み込みresolver登録。
 * @return 全bindingが一致する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isBoundResolvedRecord(
	const OfficialDistributionRecord &record, const OfficialDistributionRecordEvidence &evidence,
	const ScanSessionId scanSessionId, const std::uint64_t recordEvidenceId,
	const OfficialRecordResolverRegistration &registration) noexcept
{
	const OfficialSourcePolicy *const policy =
		// 正本policy。
		officialSourcePolicyForProvider( registration.providerId) ;
	// Registry検証後にpolicyが失われた矛盾を受理しない。
	if( policy == nullptr) {
		return false ;
	}

	return record.recordEvidenceId == recordEvidenceId &&
		   evidence.recordEvidenceId == recordEvidenceId &&
		   record.rootEvidence.scanSessionId == scanSessionId &&
		   evidence.rootEvidence.scanSessionId == scanSessionId &&
		   record.rootEvidence.providerId == registration.providerId &&
		   evidence.rootEvidence.providerId == registration.providerId &&
		   record.rootEvidence.policyId == policy->id &&
		   evidence.rootEvidence.policyId == policy->id &&
		   record.rootEvidence.resourceId == registration.rootResourceId &&
		   evidence.rootEvidence.resourceId == registration.rootResourceId ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_record_resolution.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
bool validateOfficialRecordResolverRegistrations(
	const std::span<const OfficialRecordResolverRegistration> registrations) noexcept
{
	// 空registryまたは有限上限を超えるregistryを実行しない。
	if( registrations.empty() || registrations.size() > MAXIMUM_RESOLVER_REGISTRATIONS ||
	   !validateBuiltInOfficialSourcePolicies()) {
		return false ;
	}

	// 全登録を組み込み正本へ照合し、Provider・resource pairの重複も検査する。
	for( std::size_t index = 0U; index < registrations.size(); ++index) {
		const OfficialRecordResolverRegistration &registration =
			registrations[index] ;	// 今回の登録。
		// 一登録でも不正ならregistry全体を使用しない。
		if( !isValidRegistration( registration)) {
			return false ;
		}

		// 前方に同じProvider・resource pairがあればdispatchを曖昧にするため拒否する。
		for( std::size_t previous = 0U; previous < index; ++previous) {
			const OfficialRecordResolverRegistration &earlier =
				registrations[previous] ;	// 比較する先行登録。
			// Exact pairの二重登録を拒否する。
			if( earlier.providerId == registration.providerId &&
			   earlier.rootResourceId == registration.rootResourceId) {
				return false ;
			}
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_record_resolution.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError OfficialRecordResolutionSession::beginSession(
	const ScanSessionId scanSessionId) noexcept
{
	// 0、同じIDの再使用または過去IDへの逆行で既存sessionを置き換えない。
	if( scanSessionId == 0U || scanSessionId <= latestSessionId_) {
		return nativeErrorFromWin32( ERROR_REVISION_MISMATCH) ;
	}

	records_.clear() ;
	activeSessionId_	  = scanSessionId ;
	latestSessionId_	  = scanSessionId ;
	nextRecordEvidenceId_ = 1U ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_record_resolution.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
OfficialRecordResolutionResult OfficialRecordResolutionSession::resolve(
	OfficialRecordResolutionCommand							&&command,
	const std::span<const OfficialRecordResolverRegistration> registrations,
	const OfficialRecordResolutionCancellation				 &cancellation) noexcept
{
	OfficialRecordResolutionResult result{
		.operationId   = command.operationId,
		.scanSessionId = command.scanSessionId} ;	// 秘密値を含まない終端result。
	const bool submittedUrlValid =
		// 消去前に確認する有限入力状態。
		isValidSubmittedUrl( command.submittedUrl.view()) ;
	command.submittedUrl.clear() ;
	// Registry、session、operation順序、上限、取消しcallback、提出URLを全て先に検証する。
	if( !validateOfficialRecordResolverRegistrations( registrations) || activeSessionId_ == 0U ||
	   command.scanSessionId != activeSessionId_ || command.operationId == 0U ||
	   command.operationId <= latestOperationId_ || command.maximumRecordBytes == 0U ||
	   command.maximumRecordBytes > MAXIMUM_RECORD_BYTES || !cancellation || !submittedUrlValid) {
		result.state = OfficialRecordResolutionState::REJECTED ;
		result.error = INVALID_ARGUMENT ;
		return result ;
	}

	const OfficialRecordResolverRegistration *const registration =
		findRegistration( registrations, command.providerId,
						 command.rootResourceId) ;	// Explicit pairだけを検索する。
	// 未知Provider／resourceをhostや表示名から推測せず拒否する。
	if( registration == nullptr) {
		result.state = OfficialRecordResolutionState::REJECTED ;
		result.error = nativeErrorFromWin32( ERROR_NOT_FOUND) ;
		return result ;
	}

	try {
		result.providerId	  = std::wstring( registration->providerId) ;
		result.rootResourceId = std::wstring( registration->rootResourceId) ;
	} catch( const std::bad_alloc &) {
		result.state = OfficialRecordResolutionState::FAILED ;
		result.error = OUT_OF_MEMORY ;
		return result ;
	} catch( ...) {
		// 非機密IDのcopy例外もworker thread外へ漏らさない。
		result.state = OfficialRecordResolutionState::FAILED ;
		result.error = static_cast<NativeError>( E_FAIL) ;
		return result ;
	}

	// Record上限またはID空間の終端に達したsessionで追加resolverを呼ばない。
	if( records_.size() >= MAXIMUM_RETAINED_RECORDS ||
	   nextRecordEvidenceId_ == std::numeric_limits<std::uint64_t>::max()) {
		result.state = OfficialRecordResolutionState::REJECTED ;
		result.error = UNEXPECTED ;
		return result ;
	}

	latestOperationId_						 = command.operationId ;
	const std::uint64_t		recordEvidenceId = nextRecordEvidenceId_++ ;	// 今回だけ使用するID。
	const std::wstring_view rootUrl =
		officialMetadataEndpoint( registration->providerId,
								 registration->rootResourceId) ;	// 組み込み固定endpoint。

	try {
		// Resolver開始前の取消しを確認し、公式rootへ一requestも送らない。
		if( cancellation()) {
			result.state = OfficialRecordResolutionState::CANCELLED ;
			result.error = nativeErrorFromWin32( ERROR_CANCELLED) ;
			return result ;
		}

		OfficialDistributionRecord resolved ;	// Resolverが構築するworker内秘密record。
		const NativeError		   resolveError = registration->resolver(
			 activeSessionId_, recordEvidenceId, registration->providerId,
			 registration->rootResourceId, rootUrl, command.maximumRecordBytes,
			 OfficialRecordFetchMode::BYPASS_CACHE,
			 resolved) ;	// 固定rootだけを渡すProvider固有処理。
		// Root取得またはparserの診断をrecord拒否へ書き換えず保持する。
		if( resolveError != 0) {
			result.state = OfficialRecordResolutionState::FAILED ;
			result.error = resolveError ;
			return result ;
		}

		// Resolver完了後の取消しでは、受け取った秘密recordを保持せず破棄する。
		if( cancellation()) {
			result.state = OfficialRecordResolutionState::CANCELLED ;
			result.error = nativeErrorFromWin32( ERROR_CANCELLED) ;
			return result ;
		}

		OfficialDistributionRecordEvidence evidence ;	// 共通検証が作るURL非保持証拠。
		const NativeError				   validationError =
			// Record構造・fingerprint結果。
			validateOfficialDistributionRecord( resolved, evidence) ;
		// 構造不正または選択Provider／rootと結合しないrecordをsessionへ保存しない。
		if( validationError != 0 || !isBoundResolvedRecord( resolved, evidence, activeSessionId_,
														  recordEvidenceId, *registration)) {
			result.state = OfficialRecordResolutionState::REJECTED ;
			result.error = validationError != 0 ? validationError : INVALID_ARGUMENT ;
			return result ;
		}

		// 一意IDで秘密recordをsession索引へ挿入した結果。
		const auto inserted = records_.emplace(
			recordEvidenceId,
			ResolvedOfficialDistributionRecord{std::move( evidence), std::move( resolved)}) ;
		// 発行済みIDとの内部衝突を成功として公開しない。
		if( !inserted.second) {
			result.state = OfficialRecordResolutionState::REJECTED ;
			result.error = nativeErrorFromWin32( ERROR_ALREADY_EXISTS) ;
			return result ;
		}

		result.state			   = OfficialRecordResolutionState::RESOLVED ;
		result.error			   = 0 ;
		result.recordEvidenceId	   = recordEvidenceId ;
		result.retainedRecordCount = static_cast<std::uint32_t>( records_.size()) ;
		return result ;
	} catch( const std::bad_alloc &) {
		result.state = OfficialRecordResolutionState::FAILED ;
		result.error = OUT_OF_MEMORY ;
		return result ;
	} catch( ...) {
		// Callback例外をworker thread外へ漏らさず、URLや本文を診断へ含めない。
		result.state = OfficialRecordResolutionState::FAILED ;
		result.error = static_cast<NativeError>( E_FAIL) ;
		return result ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_record_resolution.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
OfficialGrantReresolutionResult OfficialRecordResolutionSession::reresolveGrant(
	const OfficialGrantReresolutionCommand &command, const RecordScopedDownloadGrant &consumedGrant,
	const std::span<const OfficialRecordResolverRegistration> registrations,
	const OfficialRecordResolutionCancellation				 &cancellation,
	RecordScopedDownloadGrant								 &replacementGrant) noexcept
{
	const RecordScopedDownloadGrantMetadata &previous =
		// URL非保持の元grant binding。
		consumedGrant.metadata() ;
	OfficialGrantReresolutionResult result{.operationId	  = command.operationId,
										   .scanSessionId = command.scanSessionId,
										   .previousGrantId =
											   previous.grantId} ;	// 秘密値を含まない終端result。
	// Session、operation、上限、出力状態、取消しと期限理由を全てresolver前に検証する。
	if( !validateOfficialRecordResolverRegistrations( registrations) || activeSessionId_ == 0U ||
	   command.scanSessionId != activeSessionId_ || command.operationId == 0U ||
	   command.operationId <= latestOperationId_ || command.maximumRecordBytes == 0U ||
	   command.maximumRecordBytes > MAXIMUM_RECORD_BYTES || command.replacementGrantId == 0U ||
	   command.replacementGrantId == previous.grantId || command.issuedUtcSeconds == 0U ||
	   !cancellation ||
	   replacementGrant.metadata().state != OfficialDownloadGrantState::NOT_REQUESTED ||
	   !isReresolutionEligible( previous) || previous.scanSessionId != activeSessionId_) {
		result.state = OfficialGrantReresolutionState::NOT_ELIGIBLE ;
		result.error = INVALID_ARGUMENT ;
		return result ;
	}

	const OfficialRecordResolverRegistration *const registration =
		findRegistration( registrations, previous.providerId,
						 previous.rootResourceId) ;	// 元grantが結合した固定rootだけを検索する。
	const OfficialSourcePolicy *const policy =
		// 元Providerの組み込み正本。
		officialSourcePolicyForProvider( previous.providerId) ;
	// 元grantのProvider、policy、rootが現在の組み込みregistryへ一致しなければ再解決しない。
	if( registration == nullptr || policy == nullptr || previous.policyId != policy->id) {
		result.state = OfficialGrantReresolutionState::REJECTED ;
		result.error = nativeErrorFromWin32( ERROR_NOT_FOUND) ;
		return result ;
	}

	try {
		result.providerId	  = previous.providerId ;
		result.rootResourceId = previous.rootResourceId ;
	} catch( const std::bad_alloc &) {
		result.state = OfficialGrantReresolutionState::FAILED ;
		result.error = OUT_OF_MEMORY ;
		return result ;
	} catch( ...) {
		// 非機密IDのcopy例外をworker thread外へ漏らさない。
		result.state = OfficialGrantReresolutionState::FAILED ;
		result.error = static_cast<NativeError>( E_FAIL) ;
		return result ;
	}

	// Session内record IDが枯渇した場合はcallbackや新grantを作らない。
	if( nextRecordEvidenceId_ == std::numeric_limits<std::uint64_t>::max()) {
		result.state = OfficialGrantReresolutionState::REJECTED ;
		result.error = UNEXPECTED ;
		return result ;
	}

	latestOperationId_						 = command.operationId ;
	const std::uint64_t		recordEvidenceId = nextRecordEvidenceId_++ ;	// 今回だけ使用する証拠ID。
	const std::wstring_view rootUrl =
		officialMetadataEndpoint( registration->providerId,
								 registration->rootResourceId) ;	// URL入力から作らない固定endpoint。

	try {
		// 再解決開始前の取消しを確認し、公式rootへ一requestも送らない。
		if( cancellation()) {
			result.state = OfficialGrantReresolutionState::CANCELLED ;
			result.error = nativeErrorFromWin32( ERROR_CANCELLED) ;
			return result ;
		}

		OfficialDistributionRecord refreshed ;	// Cacheを使わず取得する新しい秘密record。
		const NativeError		   resolveError = registration->resolver(
			 activeSessionId_, recordEvidenceId, registration->providerId,
			 registration->rootResourceId, rootUrl, command.maximumRecordBytes,
			 OfficialRecordFetchMode::BYPASS_CACHE, refreshed) ;	// 非cache固定root取得結果。
		// Root取得またはparser失敗時は古いURLを再使用しない。
		if( resolveError != 0) {
			result.state = OfficialGrantReresolutionState::FAILED ;
			result.error = resolveError ;
			return result ;
		}

		// Resolver完了後の取消しでは新recordと秘密URLを保持しない。
		if( cancellation()) {
			result.state = OfficialGrantReresolutionState::CANCELLED ;
			result.error = nativeErrorFromWin32( ERROR_CANCELLED) ;
			return result ;
		}

		OfficialDistributionRecordEvidence evidence ;	// 再計算するURL非保持証拠。
		const NativeError				   validationError =
			// Record構造・fingerprint。
			validateOfficialDistributionRecord( refreshed, evidence) ;
		// 非cache根拠を含むProvider／root binding不成立なら新grantを発行しない。
		if( validationError != 0 || !isBoundResolvedRecord( refreshed, evidence, activeSessionId_,
														  recordEvidenceId, *registration)) {
			result.state = OfficialGrantReresolutionState::REJECTED ;
			result.error = validationError != 0 ? validationError : INVALID_ARGUMENT ;
			return result ;
		}

		// EULAを含む全stable fieldが変わった場合は利用者確認なしのURL更新を拒否する。
		if( evidence.stableFingerprint.bytes != previous.recordFingerprint.bytes) {
			result.state = OfficialGrantReresolutionState::RECORD_CHANGED ;
			result.error = nativeErrorFromWin32( ERROR_REVISION_MISMATCH) ;
			return result ;
		}

		// 同じpayload ordinal、上限、認識済みexpiring方式が維持されないrecordを拒否する。
		if( previous.payloadOrdinal >= refreshed.payloads.size() ||
		   refreshed.payloads[previous.payloadOrdinal].maximumBytes != previous.maximumBytes ||
		   !refreshed.payloads[previous.payloadOrdinal].externalExpiryUtcSeconds) {
			result.state = OfficialGrantReresolutionState::RECORD_CHANGED ;
			result.error = nativeErrorFromWin32( ERROR_REVISION_MISMATCH) ;
			return result ;
		}

		bool			  sameTarget{} ;	// 秘密URL値を公開せず比較した結果。
		// 再解決URLを元grantの秘密fingerprintへ照合した診断。
		const NativeError targetError = consumedGrant.compareConsumedTarget(
			refreshed.payloads[previous.payloadOrdinal].targetUrl.view(), sameTarget) ;
		// Target hashを比較できない場合は新しいURLと推測しない。
		if( targetError != 0) {
			result.state = OfficialGrantReresolutionState::FAILED ;
			result.error = targetError ;
			return result ;
		}

		// 同じ期限切れまたは拒否URLを無条件retryするgrantは発行しない。
		if( sameTarget) {
			result.state = OfficialGrantReresolutionState::REJECTED ;
			result.error = nativeErrorFromWin32( ERROR_RETRY) ;
			return result ;
		}

		const NativeError issueError = replacementGrant.issue(
			refreshed, evidence, previous.payloadOrdinal, command.replacementGrantId,
			command.issuedUtcSeconds, 1U) ;	// URLだけが変わった二つ目の一回使用grant。
		// 新しいexpiryの安全余裕を含むgrant発行失敗を成功へ補完しない。
		if( issueError != 0) {
			result.state = OfficialGrantReresolutionState::FAILED ;
			result.error = issueError ;
			return result ;
		}

		result.state			  = OfficialGrantReresolutionState::REFRESHED ;
		result.error			  = 0 ;
		result.replacementGrantId = command.replacementGrantId ;
		return result ;
	} catch( const std::bad_alloc &) {
		result.state = OfficialGrantReresolutionState::FAILED ;
		result.error = OUT_OF_MEMORY ;
		return result ;
	} catch( ...) {
		// Callbackや内部境界の未知例外をworker thread外へ漏らさない。
		result.state = OfficialGrantReresolutionState::FAILED ;
		result.error = static_cast<NativeError>( E_FAIL) ;
		return result ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_record_resolution.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError OfficialRecordResolutionSession::claimResolvedRecord(
	const ScanSessionId scanSessionId, const std::uint64_t recordEvidenceId,
	ResolvedOfficialDistributionRecord &record) noexcept
{
	record = {} ;
	// Stale session、0 IDまたは失効済みsessionから秘密recordを取り出さない。
	if( activeSessionId_ == 0U || scanSessionId != activeSessionId_ || recordEvidenceId == 0U) {
		return nativeErrorFromWin32( ERROR_REVISION_MISMATCH) ;
	}

	auto node = records_.extract( recordEvidenceId) ;	// 成功時だけ所有権を外へ移すnode。
	// 未知または一度claim済みのIDを再使用しない。
	if( node.empty()) {
		return nativeErrorFromWin32( ERROR_NOT_FOUND) ;
	}

	record = std::move( node.mapped()) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_record_resolution.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
void OfficialRecordResolutionSession::invalidate() noexcept
{
	records_.clear() ;
	activeSessionId_	  = 0U ;
	nextRecordEvidenceId_ = 1U ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_record_resolution.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
ScanSessionId OfficialRecordResolutionSession::activeSessionId() const noexcept
{
	return activeSessionId_ ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_record_resolution.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
std::size_t OfficialRecordResolutionSession::retainedRecordCount() const noexcept
{
	return records_.size() ;
}

} // namespace drivercrate
