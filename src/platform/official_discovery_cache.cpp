//------------------------------------------------------------------------------
/**
 * @file official_discovery_cache.cpp
 * @brief URL非保持の公式自動探索cache schemaとfreshness判定実装。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Cache schema、生成と失効判定を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Fresh positiveの表示専用候補復元を追加。
 * </pre>
 *
 * @note URL、host、path、query、token、EULA本文、grant、PnP ID、rankまたはinstall tokenを
 *       受け取るfieldを持たず、不正entryをfreshへ縮退させません。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#include "platform/official_discovery_cache.h"

#include "core/candidate_audit.h"
#include "core/candidate_selection.h"
#include "core/official_source_policy.h"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <new>
#include <ranges>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t SHA256_CHARACTERS				  = 64U ;		// 環境fingerprintの固定文字数。
constexpr std::size_t MAXIMUM_ID_CHARACTERS			  = 128U ;		// Stable IDとparser IDの保持上限。
constexpr std::size_t MAXIMUM_PAYLOAD_COUNT			  = 32U ;		// 一recordのpayload上限。
constexpr std::size_t MAXIMUM_DISPLAY_CANDIDATE_COUNT = 32'768U ;	// 一scanの表示行上限。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

/**
 * @brief 文字列が有限で非制御の識別子か確認します。
 * @param[in] value 検証するstable IDです。
 * @return 1～128文字で制御文字と埋込NULを含まない場合trueです。
 */
[[nodiscard]] bool	  isFiniteIdentifier( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= MAXIMUM_ID_CHARACTERS && value.front() != L' ' &&
		   value.back() != L' ' &&
		   std::ranges::none_of( value, []( const wchar_t character) noexcept {
			   return character == L'\0' || character == L'\r' || character == L'\n' ||
					  character == L'\t' || (character >= 0x202A && character <= 0x202E) ||
					  (character >= 0x2066 && character <= 0x2069) ;
		   }) ;
}

/**
 * @brief 値が64桁lowercase ASCII SHA-256か確認します。
 * @param[in] value 検証する環境fingerprintです。
 * @return 固定形式を満たす場合trueです。
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
 * @brief Stable record fingerprintが全zeroでないか確認します。
 * @param[in] fingerprint 検証するURL非保持fingerprintです。
 * @return 一byte以上が0以外ならtrueです。
 */
[[nodiscard]] bool hasRecordFingerprint( const OfficialStableRecordFingerprint &fingerprint) noexcept
{
	return std::ranges::any_of( fingerprint.bytes,
							   []( const std::byte value) noexcept { return value != std::byte{} ; }) ;
}

/**
 * @brief Provider、policyとrootが組み込みsource policyへ完全一致するか確認します。
 * @param[in] providerId Provider registryのstable IDです。
 * @param[in] policyId 組み込みsource policy IDです。
 * @param[in] rootResourceId Landingまたはmetadata resource IDです。
 * @return 自動探索の固定rootとして利用できる関係ならtrueです。
 */
[[nodiscard]] bool isFixedRootBinding( const std::wstring_view providerId,
									  const std::wstring_view policyId,
									  const std::wstring_view rootResourceId) noexcept
{
	const OfficialSourcePolicy *const policy =
		// Providerへ一意に結合した組み込みpolicyです。
		officialSourcePolicyForProvider( providerId) ;
	const OfficialSourceResourcePolicy *const resource =
		policy == nullptr
			? nullptr
			: findOfficialSourceResource( *policy, rootResourceId) ;	// 固定root resourceです。
	return policy != nullptr && policy->id == policyId && resource != nullptr &&
		   (resource->kind == OfficialSourceResourceKind::LANDING_PAGE ||
			resource->kind == OfficialSourceResourceKind::METADATA) ;
}

/**
 * @brief Payload方式からrecord時点の表示・検査能力を再構築します。
 * @param[in] entry Cacheの共通record由来です。
 * @param[in] payload 検証する一payload公開metadataです。
 * @param[in] payloadCount 同じrecordのpayload総数です。
 * @return 既存record descriptor validatorに合格する場合trueです。
 */
[[nodiscard]] bool isCachedPayloadValid( const OfficialDiscoveryCacheEntry	 &entry,
										const OfficialDiscoveryCachedPayload &payload,
										const std::uint32_t					  payloadCount) noexcept
{
	try {
		OfficialRecordPayloadRoute route =
			OfficialRecordPayloadRoute::DISPLAY_ONLY_UNSUPPORTED ;	// 未対応方式の既定表示route。
		bool downloadGrantSupported{} ;								// 元record解決時にgrantを発行できた方式ならtrueです。
		bool contentInspectorAvailable{} ;							// 元record解決時に静的内容検査を選べた場合trueです。
		// Payload kindだけから元record descriptorと同じ能力を復元する。
		switch( payload.payloadKind) {
			// 標準INFは元record時点でgrantを持ち、ZIP／CABなら共通検査を持つ。
			case OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE: {
				route				   = OfficialRecordPayloadRoute::COMMON_INF_INSPECTION ;
				downloadGrantSupported = true ;
				const std::size_t dot =
					// 公開basenameの最終拡張子位置。
					payload.fileDisplayName.find_last_of( L'.') ;
				std::wstring extension =
					dot == std::wstring::npos
						? std::wstring{}
						: payload.fileDisplayName.substr( dot) ;	// ASCII比較用拡張子。
				std::ranges::transform( extension, extension.begin(), []( const wchar_t character) {
					return character >= L'A' && character <= L'Z'
							   ? static_cast<wchar_t>( character - L'A' + L'a')
							   : character ;
				}) ;
				contentInspectorAvailable = extension == L".zip" || extension == L".cab" ;
				break ;
			}

			// 公式installerは元record時点でgrantを持つが専用内容監査を持たない。
			case OfficialDistributionPayloadKind::OFFICIAL_INSTALLER:
				route				   = OfficialRecordPayloadRoute::DEDICATED_INSTALLER_AUDIT ;
				downloadGrantSupported = true ;
				break ;

			// 未対応方式はrecord表示だけへ限定する。
			case OfficialDistributionPayloadKind::UNSUPPORTED:
				break ;

			// 定義外方式を未対応表示へ縮退させない。
			default:
				return false ;
		}

		OfficialRecordPayloadDescriptor descriptor{
			.scanSessionId			   = 1U,
			.recordEvidenceId		   = 1U,
			.providerId				   = entry.providerId,
			.policyId				   = entry.policyId,
			.rootResourceId			   = entry.rootResourceId,
			.recordFingerprint		   = entry.recordFingerprint,
			.payloadCount			   = payloadCount,
			.payloadOrdinal			   = payload.payloadOrdinal,
			.payloadResourceId		   = payload.payloadResourceId,
			.payloadKind			   = payload.payloadKind,
			.route					   = route,
			.fileDisplayName		   = payload.fileDisplayName,
			.productFamily			   = payload.productFamily,
			.operatingSystem		   = payload.operatingSystem,
			.packageVersion			   = payload.packageVersion,
			.publishedDate			   = payload.publishedDate,
			.publishedSizeBytes		   = payload.publishedSizeBytes,
			.publishedSha256Available  = payload.publishedSha256Available,
			.declaredPublisher		   = payload.declaredPublisher,
			.terms					   = payload.terms,
			.eulaRevision			   = payload.eulaRevision,
			.downloadGrantSupported	   = downloadGrantSupported,
			.contentInspectorAvailable = contentInspectorAvailable,
			.executorAvailable		   = false} ;	// Cache自体へ実行権限を付けない検証用descriptor。
		return isOfficialRecordPayloadDescriptorValid( descriptor) ;
	} catch( ...) {
		// noexcept validatorでは文字列copy等の例外を不正entryとして拒否します。
		return false ;
	}
}

/**
 * @brief Entry種別の最大fresh秒数を返します。
 * @param[in] kind Positiveまたはnegative entry種別です。
 * @return 定義済み種別の最大秒数、未知値は0です。
 */
[[nodiscard]] std::uint64_t maximumFreshSeconds( const OfficialDiscoveryCacheEntryKind kind) noexcept
{
	// Positiveと二つのnegativeだけを固定期限へ対応させる。
	switch( kind) {
		// Positive recordは最大24時間です。
		case OfficialDiscoveryCacheEntryKind::POSITIVE_RECORD:
			return OFFICIAL_DISCOVERY_POSITIVE_FRESH_SECONDS ;
		// 対象外とrecordなしは最大6時間です。
		case OfficialDiscoveryCacheEntryKind::NOT_APPLICABLE:
		// Recordなしも同じnegative期限です。
		case OfficialDiscoveryCacheEntryKind::NO_RECORD:
			return OFFICIAL_DISCOVERY_NEGATIVE_FRESH_SECONDS ;
		// 未知値へ既定期限を与えない。
		default:
			return 0U ;
	}
}

/**
 * @brief 現在queryの構造が有限か確認します。
 * @param[in] query 一scanのcache照会条件です。
 * @return 全fieldが現在条件として有効ならtrueです。
 */
[[nodiscard]] bool isCacheQueryValid( const OfficialDiscoveryCacheQuery &query) noexcept
{
	return (query.cacheMode == OfficialDiscoveryCacheMode::USE_FRESH ||
			query.cacheMode == OfficialDiscoveryCacheMode::FORCE_REFRESH) &&
		   isFiniteIdentifier( query.providerId) && isFiniteIdentifier( query.policyId) &&
		   isFiniteIdentifier( query.rootResourceId) && query.policyRevision != 0U &&
		   isFiniteIdentifier( query.parserId) && query.parserRevision != 0U &&
		   query.nowUtcSeconds != 0U && isLowerSha256( query.operatingSystemFingerprint) &&
		   isLowerSha256( query.deviceConfigurationFingerprint) &&
		   isFixedRootBinding( query.providerId, query.policyId, query.rootResourceId) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_discovery_cache.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
bool isOfficialDiscoveryCacheEntryValid( const OfficialDiscoveryCacheEntry &entry) noexcept
{
	try {
		const std::uint64_t maximumAge =
			// 種別ごとの最大fresh秒数。
			maximumFreshSeconds( entry.kind) ;
		// Schema、固定root、revision、環境、時刻と有限期限を一括で検証する。
		if( entry.schemaRevision != OFFICIAL_DISCOVERY_CACHE_SCHEMA_REVISION || maximumAge == 0U ||
		   !isFiniteIdentifier( entry.providerId) || !isFiniteIdentifier( entry.policyId) ||
		   !isFiniteIdentifier( entry.rootResourceId) || entry.policyRevision == 0U ||
		   !isFiniteIdentifier( entry.parserId) || entry.parserRevision == 0U ||
		   entry.observedUtcSeconds == 0U || entry.expiresUtcSeconds <= entry.observedUtcSeconds ||
		   entry.expiresUtcSeconds - entry.observedUtcSeconds > maximumAge ||
		   !isLowerSha256( entry.operatingSystemFingerprint) ||
		   !isLowerSha256( entry.deviceConfigurationFingerprint) ||
		   !isFixedRootBinding( entry.providerId, entry.policyId, entry.rootResourceId)) {
			return false ;
		}

		// Positiveだけがrecord fingerprintと1～32件のpayloadを保持する。
		if( entry.kind == OfficialDiscoveryCacheEntryKind::POSITIVE_RECORD) {
			// Fingerprintまたは有限payload集合を欠くpositiveを利用しない。
			if( !hasRecordFingerprint( entry.recordFingerprint) || entry.payloads.empty() ||
			   entry.payloads.size() > MAXIMUM_PAYLOAD_COUNT) {
				return false ;
			}

			std::unordered_set<std::wstring_view> resources ;	// Payload resource IDの一意性集合。
			resources.reserve( entry.payloads.size()) ;
			// 全ordinalを欠落なしの入力順で検証し、公開metadataの重複を拒否する。
			for( std::size_t index = 0U; index < entry.payloads.size(); ++index) {
				const OfficialDiscoveryCachedPayload &payload =
					entry.payloads[index] ;	// 現在payload。
				// Ordinal、既存descriptor契約とresource一意性がそろう場合だけ保存可能とする。
				if( payload.payloadOrdinal != index ||
				   !isCachedPayloadValid( entry, payload,
										 static_cast<std::uint32_t>( entry.payloads.size())) ||
				   !resources.insert( payload.payloadResourceId).second) {
					return false ;
				}
			}

			return true ;
		}

		// Negativeはrecordやpayload metadataを保持してはならない。
		return !hasRecordFingerprint( entry.recordFingerprint) && entry.payloads.empty() ;
	} catch( ...) {
		// noexcept永続境界では一意性集合等の例外を不正entryとして拒否します。
		return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_discovery_cache.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
OfficialDiscoveryCacheDisposition evaluateOfficialDiscoveryCacheEntry(
	const OfficialDiscoveryCacheEntry &entry, const OfficialDiscoveryCacheQuery &query) noexcept
{
	// 構造不正をstaleへ落として過去表示に再利用しない。
	if( !isOfficialDiscoveryCacheEntryValid( entry) || !isCacheQueryValid( query) ||
	   query.nowUtcSeconds < entry.observedUtcSeconds) {
		return OfficialDiscoveryCacheDisposition::INVALID ;
	}

	// 明示refresh、固定root、revision、環境または期限の変化で必ずnetwork再確認を要求する。
	if( query.cacheMode == OfficialDiscoveryCacheMode::FORCE_REFRESH ||
	   query.providerId != entry.providerId || query.policyId != entry.policyId ||
	   query.rootResourceId != entry.rootResourceId ||
	   query.policyRevision != entry.policyRevision || query.parserId != entry.parserId ||
	   query.parserRevision != entry.parserRevision ||
	   query.operatingSystemFingerprint != entry.operatingSystemFingerprint ||
	   query.deviceConfigurationFingerprint != entry.deviceConfigurationFingerprint ||
	   query.nowUtcSeconds >= entry.expiresUtcSeconds) {
		return OfficialDiscoveryCacheDisposition::STALE ;
	}

	return entry.kind == OfficialDiscoveryCacheEntryKind::POSITIVE_RECORD
			   ? OfficialDiscoveryCacheDisposition::FRESH_POSITIVE
			   : OfficialDiscoveryCacheDisposition::FRESH_NEGATIVE ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_discovery_cache.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
std::optional<OfficialDiscoveryCacheEntry> makeOfficialDiscoveryPositiveCacheEntry(
	const std::span<const OfficialRecordPayloadDescriptor> descriptors,
	const std::uint32_t policyRevision, std::wstring parserId, const std::uint32_t parserRevision,
	const std::uint64_t observedUtcSeconds, std::wstring operatingSystemFingerprint,
	std::wstring deviceConfigurationFingerprint)
{
	// 空、過大、無効revisionまたは期限加算overflowからentryを作らない。
	if( descriptors.empty() || descriptors.size() > MAXIMUM_PAYLOAD_COUNT || policyRevision == 0U ||
	   parserRevision == 0U || observedUtcSeconds == 0U ||
	   observedUtcSeconds >
		   std::numeric_limits<std::uint64_t>::max() - OFFICIAL_DISCOVERY_POSITIVE_FRESH_SECONDS) {
		return std::nullopt ;
	}

	try {
		const OfficialRecordPayloadDescriptor &first =
			// 共通record由来の正本。
			descriptors.front() ;
		OfficialDiscoveryCacheEntry entry ;	// 全payload検証後だけ返すURL非保持entry。
		entry.kind				 = OfficialDiscoveryCacheEntryKind::POSITIVE_RECORD ;
		entry.providerId		 = first.providerId ;
		entry.policyId			 = first.policyId ;
		entry.rootResourceId	 = first.rootResourceId ;
		entry.policyRevision	 = policyRevision ;
		entry.parserId			 = std::move( parserId) ;
		entry.parserRevision	 = parserRevision ;
		entry.recordFingerprint	 = first.recordFingerprint ;
		entry.observedUtcSeconds = observedUtcSeconds ;
		entry.expiresUtcSeconds	 = observedUtcSeconds + OFFICIAL_DISCOVERY_POSITIVE_FRESH_SECONDS ;
		entry.operatingSystemFingerprint	 = std::move( operatingSystemFingerprint) ;
		entry.deviceConfigurationFingerprint = std::move( deviceConfigurationFingerprint) ;
		entry.payloads.reserve( descriptors.size()) ;
		// Descriptor順と共通record fieldを維持して秘密を持たない公開metadataだけをcopyする。
		for( std::size_t index = 0U; index < descriptors.size(); ++index) {
			const OfficialRecordPayloadDescriptor &descriptor = descriptors[index] ;	// 現在payload。
			// 異なるrecord、欠落ordinalまたは不正descriptorを一entryへ混在させない。
			if( !isOfficialRecordPayloadDescriptorValid( descriptor) ||
			   descriptor.providerId != first.providerId || descriptor.policyId != first.policyId ||
			   descriptor.rootResourceId != first.rootResourceId ||
			   descriptor.recordFingerprint.bytes != first.recordFingerprint.bytes ||
			   descriptor.recordEvidenceId != first.recordEvidenceId ||
			   descriptor.payloadCount != descriptors.size() ||
			   descriptor.payloadOrdinal != index) {
				return std::nullopt ;
			}

			entry.payloads.push_back( OfficialDiscoveryCachedPayload{
				.payloadOrdinal			  = descriptor.payloadOrdinal,
				.payloadResourceId		  = descriptor.payloadResourceId,
				.payloadKind			  = descriptor.payloadKind,
				.fileDisplayName		  = descriptor.fileDisplayName,
				.productFamily			  = descriptor.productFamily,
				.operatingSystem		  = descriptor.operatingSystem,
				.packageVersion			  = descriptor.packageVersion,
				.publishedDate			  = descriptor.publishedDate,
				.publishedSizeBytes		  = descriptor.publishedSizeBytes,
				.publishedSha256Available = descriptor.publishedSha256Available,
				.declaredPublisher		  = descriptor.declaredPublisher,
				.terms					  = descriptor.terms,
				.eulaRevision			  = descriptor.eulaRevision}) ;
		}

		// 生成結果も読取り時と同じ公開validatorへ通す。
		if( !isOfficialDiscoveryCacheEntryValid( entry)) {
			return std::nullopt ;
		}

		return entry ;
	} catch( const std::bad_alloc &) {
		return std::nullopt ;
	} catch( ...) {
		// 文字列copy等の例外から部分entryを返さない。
		return std::nullopt ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_discovery_cache.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
std::optional<OfficialDiscoveryCacheEntry> makeOfficialDiscoveryNegativeCacheEntry(
	const OfficialDiscoveryCacheEntryKind kind, std::wstring providerId, std::wstring policyId,
	std::wstring rootResourceId, const std::uint32_t policyRevision, std::wstring parserId,
	const std::uint32_t parserRevision, const std::uint64_t observedUtcSeconds,
	std::wstring operatingSystemFingerprint, std::wstring deviceConfigurationFingerprint)
{
	// Positive、未知状態、無効revisionまたは期限加算overflowをnegativeへ保存しない。
	if( (kind != OfficialDiscoveryCacheEntryKind::NOT_APPLICABLE &&
		kind != OfficialDiscoveryCacheEntryKind::NO_RECORD) ||
	   policyRevision == 0U || parserRevision == 0U || observedUtcSeconds == 0U ||
	   observedUtcSeconds >
		   std::numeric_limits<std::uint64_t>::max() - OFFICIAL_DISCOVERY_NEGATIVE_FRESH_SECONDS) {
		return std::nullopt ;
	}

	try {
		OfficialDiscoveryCacheEntry entry ;	// Validator合格後だけ返すnegative entry。
		entry.kind				 = kind ;
		entry.providerId		 = std::move( providerId) ;
		entry.policyId			 = std::move( policyId) ;
		entry.rootResourceId	 = std::move( rootResourceId) ;
		entry.policyRevision	 = policyRevision ;
		entry.parserId			 = std::move( parserId) ;
		entry.parserRevision	 = parserRevision ;
		entry.observedUtcSeconds = observedUtcSeconds ;
		entry.expiresUtcSeconds	 = observedUtcSeconds + OFFICIAL_DISCOVERY_NEGATIVE_FRESH_SECONDS ;
		entry.operatingSystemFingerprint	 = std::move( operatingSystemFingerprint) ;
		entry.deviceConfigurationFingerprint = std::move( deviceConfigurationFingerprint) ;
		// Fixed root、環境、期限と空record状態を同じ公開validatorへ通す。
		if( !isOfficialDiscoveryCacheEntryValid( entry)) {
			return std::nullopt ;
		}

		return entry ;
	} catch( const std::bad_alloc &) {
		return std::nullopt ;
	} catch( ...) {
		// 文字列copy等の例外から部分entryを返さない。
		return std::nullopt ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_discovery_cache.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
std::optional<std::vector<UpdateCandidate>> makeOfficialDiscoveryCachedDisplayCandidates(
	const OfficialDiscoveryCacheEntry &entry, const OfficialDiscoveryCacheQuery &query,
	const ScanSessionId scanSessionId, const OfficialDiscoveryRoute &route,
	const std::span<const OfficialDiscoveryDeviceHint> devices, const ProviderDescriptor &provider)
{
	// Fresh positive、現在session、固定rootとProvider正本が完全一致する場合だけ復元します。
	if( evaluateOfficialDiscoveryCacheEntry( entry, query) !=
		   OfficialDiscoveryCacheDisposition::FRESH_POSITIVE ||
	   scanSessionId == 0U || route.routeId == 0U || route.providerId != entry.providerId ||
	   route.rootResourceId != entry.rootResourceId || provider.id != entry.providerId ||
	   provider.discoveryBasis == CandidateDiscoveryBasis::UNSPECIFIED ||
	   (route.kind != OfficialDiscoveryRouteKind::DEDICATED &&
		route.kind != OfficialDiscoveryRouteKind::GENERIC_OFFICIAL_ROOT) ||
	   route.deviceIdentities.empty() || devices.empty() ||
	   route.deviceIdentities.size() > MAXIMUM_DISPLAY_CANDIDATE_COUNT ||
	   entry.payloads.size() > MAXIMUM_DISPLAY_CANDIDATE_COUNT / route.deviceIdentities.size()) {
		return std::nullopt ;
	}

	try {
		std::vector<UpdateCandidate> candidates ;	// 全行検証後だけ返す非選択cache表示集合。
		candidates.reserve( entry.payloads.size() * route.deviceIdentities.size()) ;
		std::unordered_set<std::wstring_view> routeDevices ;	// Route内のopaque device一意性集合。
		routeDevices.reserve( route.deviceIdentities.size()) ;
		// Current routeが参照する全deviceを同じsessionのhintへ一意に戻します。
		for( const std::wstring &deviceIdentity : route.deviceIdentities) {
			const auto hint =
				std::find_if( devices.begin(), devices.end(), [&deviceIdentity]( const auto &value) {
					return value.deviceIdentity == deviceIdentity ;
				}) ; // 現在routeが参照するhint。
			// 重複、欠落または別sessionのdeviceへcache metadataを結合しません。
			if( !routeDevices.insert( deviceIdentity).second || hint == devices.end() ||
			   std::count_if( devices.begin(), devices.end(),
							 [&deviceIdentity]( const auto &value) {
								 return value.deviceIdentity == deviceIdentity ;
							 }) != 1 ||
			   !validateOfficialDiscoveryDeviceHint( *hint, scanSessionId)) {
				return std::nullopt ;
			}
		}

		// Cacheの全payloadを現在routeの全deviceへ表示専用で展開します。
		for( const OfficialDiscoveryCachedPayload &payload : entry.payloads) {
			OfficialRecordPayloadRoute payloadRoute =
				OfficialRecordPayloadRoute::DISPLAY_ONLY_UNSUPPORTED ;	// 方式別表示境界。
			bool downloadGrantSupported{} ;								// 元record再解決時だけgrant可能な方式ならtrueです。
			bool contentInspectorAvailable{} ;							// 現在実装が静的内容検査を持つ方式ならtrueです。
			// Payload kindから表示assessment用descriptor能力だけを再構築します。
			switch( payload.payloadKind) {
				// 標準INF packageは元record再解決後に共通検査へ進める方式です。
				case OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE: {
					payloadRoute		   = OfficialRecordPayloadRoute::COMMON_INF_INSPECTION ;
					downloadGrantSupported = true ;
					const std::size_t dot =
						// 公開basenameの最終拡張子位置。
						payload.fileDisplayName.find_last_of( L'.') ;
					std::wstring extension =
						dot == std::wstring::npos
							? std::wstring{}
							: payload.fileDisplayName.substr( dot) ;	// ASCII比較用拡張子。
					std::ranges::transform(
						extension, extension.begin(), []( const wchar_t character) {
							return character >= L'A' && character <= L'Z'
									   ? static_cast<wchar_t>( character - L'A' + L'a')
									   : character ;
						}) ;
					contentInspectorAvailable = extension == L".zip" || extension == L".cab" ;
					break ;
				}

				// 公式installerは専用監査未完了としてだけ表示します。
				case OfficialDistributionPayloadKind::OFFICIAL_INSTALLER:
					payloadRoute		   = OfficialRecordPayloadRoute::DEDICATED_INSTALLER_AUDIT ;
					downloadGrantSupported = true ;
					break ;

				// 未対応方式は取得または検査能力なしで表示します。
				case OfficialDistributionPayloadKind::UNSUPPORTED:
					break ;

				// 定義外方式を未対応表示へ縮退させません。
				default:
					return std::nullopt ;
			}

			const OfficialRecordPayloadDescriptor descriptor{
				.scanSessionId			   = scanSessionId,
				.recordEvidenceId		   = route.routeId,
				.providerId				   = entry.providerId,
				.policyId				   = entry.policyId,
				.rootResourceId			   = entry.rootResourceId,
				.recordFingerprint		   = entry.recordFingerprint,
				.payloadCount			   = static_cast<std::uint32_t>( entry.payloads.size()),
				.payloadOrdinal			   = payload.payloadOrdinal,
				.payloadResourceId		   = payload.payloadResourceId,
				.payloadKind			   = payload.payloadKind,
				.route					   = payloadRoute,
				.fileDisplayName		   = payload.fileDisplayName,
				.productFamily			   = payload.productFamily,
				.operatingSystem		   = payload.operatingSystem,
				.packageVersion			   = payload.packageVersion,
				.publishedDate			   = payload.publishedDate,
				.publishedSizeBytes		   = payload.publishedSizeBytes,
				.publishedSha256Available  = payload.publishedSha256Available,
				.declaredPublisher		   = payload.declaredPublisher,
				.terms					   = payload.terms,
				.eulaRevision			   = payload.eulaRevision,
				.downloadGrantSupported	   = downloadGrantSupported,
				.contentInspectorAvailable = contentInspectorAvailable,
				.executorAvailable		   = false} ;	// Cache自体へ権限を追加しない表示descriptor。
			// Cache validatorと同じdescriptor契約が成立しないpayloadを表示しません。
			if( !isOfficialRecordPayloadDescriptorValid( descriptor)) {
				return std::nullopt ;
			}

			// 一payloadを現在routeの全deviceへ非選択行として展開します。
			for( std::size_t deviceOrdinal{}; deviceOrdinal < route.deviceIdentities.size();
				++deviceOrdinal) {
				const std::wstring &deviceIdentity =
					route.deviceIdentities[deviceOrdinal] ;	// 現在行のopaque device identity。
				const auto		hint = std::find_if( devices.begin(), devices.end(),
													[&deviceIdentity]( const auto &value) {
													return value.deviceIdentity == deviceIdentity ;
												}) ; // 事前検証済みの現在hint。
				UpdateCandidate candidate ;	// Cache由来の非選択・導入不可表示行。
				candidate.identity = L"official-cache-candidate:" + std::to_wstring( route.routeId) +
									 L":" + std::to_wstring( payload.payloadOrdinal) + L":" +
									 std::to_wstring( deviceOrdinal) ;
				candidate.deviceIdentity  = deviceIdentity ;
				candidate.providerId	  = entry.providerId ;
				candidate.packageIdentity = L"official-cache-package:" +
											std::to_wstring( route.routeId) + L":" +
											std::to_wstring( payload.payloadOrdinal) ;
				candidate.title		   = payload.productFamily + L" / " + payload.fileDisplayName ;
				candidate.manufacturer = hint->manufacturer ;
				candidate.model		   = hint->model ;
				candidate.driverClass  = hint->deviceClass ;
				candidate.deviceClassGuid = hint->setupClassGuid ;
				candidate.provider		  = payload.declaredPublisher ;
				candidate.version		  = payload.packageVersion ;
				candidate.driverDate	  = payload.publishedDate ;
				candidate.sourceName	  = provider.displayName ;
				candidate.sourceLocation  = L"公式配布record cache（再取得前・導入不可）" ;
				// 公開exact sizeがある場合だけ表示と上限値へ反映します。
				if( payload.publishedSizeBytes) {
					candidate.maximumDownloadBytes = *payload.publishedSizeBytes ;
					candidate.displayDownloadSize =
						std::to_wstring( *payload.publishedSizeBytes) + L" byte" ;
				}

				candidate.action			= DriverAction::NONE ;
				candidate.defaultPreference = CandidateDefaultPreference::NONE ;
				candidate.discoveryBasis	= provider.discoveryBasis ;
				candidate.audit				= makeOfficialDiscoveryCandidateAudit() ;
				candidate.discoveryBus		= hint->bus ;
				CandidateAssessment assessment ;	// Cache由来と未取得理由を結合する詳細snapshot。
				// 表示assessment、opaque ID長、監査と詳細bindingが全て成立する行だけを追加します。
				if( candidate.identity.size() > OFFICIAL_DISCOVERY_OPAQUE_ID_LIMIT ||
				   candidate.packageIdentity.size() > OFFICIAL_DISCOVERY_OPAQUE_ID_LIMIT ||
				   !makeOfficialRecordPayloadDisplayAssessment( descriptor, candidate, assessment)) {
					return std::nullopt ;
				}

				candidate.assessment = std::move( assessment) ;
				// Cache表示も通常record表示と同じ候補validatorへ通します。
				if( !isCandidateDefaultPreferenceValid( candidate, provider) ||
				   !isCandidateAuditValid( candidate, provider) ||
				   !isCandidateDetailsValid( candidate, scanSessionId)) {
					return std::nullopt ;
				}

				candidates.push_back( std::move( candidate)) ;
			}
		}

		return candidates ;
	} catch( const std::bad_alloc &) {
		return std::nullopt ;
	} catch( ...) {
		// 表示metadataのcopy失敗を部分候補へ縮退させません。
		return std::nullopt ;
	}
}

} // namespace drivercrate
