//------------------------------------------------------------------------------
/**
 * @file official_discovery_cache.h
 * @brief URL非保持の公式自動探索cache schemaとfreshness判定。
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
 * @note 本型はProvider worker内だけで使用します。URL、host、path、query、token、EULA本文、grant、
 *       local path、PnP ID、serial、rankまたはinstall tokenを保持しません。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_discovery.h"
#include "platform/official_record_payload_routing.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::uint32_t OFFICIAL_DISCOVERY_CACHE_SCHEMA_REVISION  = 1U ;		// 永続schema revision。
constexpr std::uint64_t OFFICIAL_DISCOVERY_POSITIVE_FRESH_SECONDS = 86'400U ;	// 24時間。
constexpr std::uint64_t OFFICIAL_DISCOVERY_NEGATIVE_FRESH_SECONDS = 21'600U ;	// 6時間。

/**
 * @brief 一つの公式rootについて保存できる有限結果を表します。
 */
enum class OfficialDiscoveryCacheEntryKind {
	/// 一件以上の検証済みURL非保持record metadataです。
	POSITIVE_RECORD,
	/// 同じ環境ではProvider対象外と正常判定した結果です。
	NOT_APPLICABLE,
	/// 固定rootを正常に確認したがrecordがなかった結果です。
	NO_RECORD,
} ;

/**
 * @brief Freshness照合後にcacheを利用できる範囲を表します。
 */
enum class OfficialDiscoveryCacheDisposition {
	/// Entryまたは照会条件が構造的に不正です。
	INVALID,
	/// Entryは正常ですが期限または環境条件が変化しています。
	STALE,
	/// 現在条件で表示metadataだけを復元できるpositive entryです。
	FRESH_POSITIVE,
	/// 現在条件で当該rootの送信だけを省略できるnegative entryです。
	FRESH_NEGATIVE,
} ;

/**
 * @brief Positive entryへ保存する一payloadの公開metadataです。
 */
struct OfficialDiscoveryCachedPayload {
	/// Record内の0起点payload順序です。
	std::uint32_t					payloadOrdinal{} ;
	/// Payload用途のstable resource IDです。
	std::wstring					payloadResourceId ;
	/// Parserが明示したpayload方式です。
	OfficialDistributionPayloadKind payloadKind{OfficialDistributionPayloadKind::UNSUPPORTED} ;
	/// 公式recordが表示するbasenameです。
	std::wstring					fileDisplayName ;
	/// Recordが明示した公開製品系列です。
	std::wstring					productFamily ;
	/// Recordが明示した対象Windows releaseまたはbranchです。
	std::wstring					operatingSystem ;
	/// Recordが明示したpackage版です。欠落時は空です。
	std::wstring					packageVersion ;
	/// Recordが明示した公開日です。欠落時は空です。
	std::wstring					publishedDate ;
	/// Recordが明示したexact byte数です。欠落時は未指定です。
	std::optional<std::uint64_t>	publishedSizeBytes ;
	/// RecordがSHA-256を明示した場合trueです。Hash値自体は保存しません。
	bool							publishedSha256Available{} ;
	/// Recordが自己申告するpublisherです。署名検証済みを意味しません。
	std::wstring					declaredPublisher ;
	/// Download前利用条件の区分です。今回の同意を意味しません。
	OfficialDistributionTerms		terms{OfficialDistributionTerms::ACCEPTANCE_REQUIRED} ;
	/// 同意対象の改訂識別子です。同意不要の場合は空です。
	std::wstring					eulaRevision ;

	/**
	 * @brief 保存可能な公開metadataを完全一致で比較します。
	 * @param[in] other 比較対象のpayloadです。
	 * @return 全field一致時trueです。
	 */
	bool operator==( const OfficialDiscoveryCachedPayload &other) const = default ;
} ;

/**
 * @brief 一つのProvider固定rootへ結合するURL非保持cache entryです。
 */
struct OfficialDiscoveryCacheEntry {
	/// 永続形式のrevisionです。
	std::uint32_t					schemaRevision{OFFICIAL_DISCOVERY_CACHE_SCHEMA_REVISION} ;
	/// Positiveまたは保存可能な二つのnegative状態です。
	OfficialDiscoveryCacheEntryKind kind{OfficialDiscoveryCacheEntryKind::NO_RECORD} ;
	/// Provider registryのstable IDです。
	std::wstring					providerId ;
	/// 組み込み公式取得元policyのstable IDです。
	std::wstring					policyId ;
	/// Landingまたはmetadata固定rootのresource IDです。
	std::wstring					rootResourceId ;
	/// 自動探索policyのrevisionです。
	std::uint32_t					policyRevision{} ;
	/// Record parserのstable IDです。
	std::wstring					parserId ;
	/// Record parserの単調revisionです。
	std::uint32_t					parserRevision{} ;
	/// Positive recordのURL非保持stable fingerprintです。Negativeでは全zeroです。
	OfficialStableRecordFingerprint recordFingerprint ;
	/// Positive recordの全payload公開metadataです。Negativeでは空です。
	std::vector<OfficialDiscoveryCachedPayload> payloads ;
	/// 検証済み結果を観測したUTC秒です。
	std::uint64_t								observedUtcSeconds{} ;
	/// Freshとして利用できない最初のUTC秒です。
	std::uint64_t								expiresUtcSeconds{} ;
	/// OS種別、build、x64を表す64桁lowercase SHA-256です。
	std::wstring								operatingSystemFingerprint ;
	/// 端末固有HMAC binding集合を表す64桁lowercase SHA-256です。
	std::wstring								deviceConfigurationFingerprint ;
} ;

/**
 * @brief 一回のscanがcache entryへ要求する現在条件です。
 */
struct OfficialDiscoveryCacheQuery {
	/// `USE_FRESH`または利用者の明示再確認です。
	OfficialDiscoveryCacheMode cacheMode{OfficialDiscoveryCacheMode::USE_FRESH} ;
	/// 現在選択中のProvider stable IDです。
	std::wstring			   providerId ;
	/// 現在の組み込みsource policy IDです。
	std::wstring			   policyId ;
	/// 現在routeの固定root resource IDです。
	std::wstring			   rootResourceId ;
	/// 現在の自動探索policy revisionです。
	std::uint32_t			   policyRevision{} ;
	/// 現在のrecord parser IDです。
	std::wstring			   parserId ;
	/// 現在のrecord parser revisionです。
	std::uint32_t			   parserRevision{} ;
	/// 期限と時計逆行を判断する現在UTC秒です。
	std::uint64_t			   nowUtcSeconds{} ;
	/// 現在OSの64桁fingerprintです。
	std::wstring			   operatingSystemFingerprint ;
	/// 現在device集合の64桁fingerprintです。
	std::wstring			   deviceConfigurationFingerprint ;
} ;

/**
 * @brief Cache entryの有限値、Provider固定root、期限とpayload集合を検証します。
 * @param[in] entry 検証するURL非保持entryです。
 * @return 永続化可能な完全entryの場合trueです。
 */
[[nodiscard]] bool isOfficialDiscoveryCacheEntryValid(
	const OfficialDiscoveryCacheEntry &entry) noexcept ;

/**
 * @brief Entryを現在scanの環境・revision・時刻へ照合します。
 * @param[in] entry 構造検証も行う保存済みentryです。
 * @param[in] query 現在の固定root、環境、revisionとcache modeです。
 * @return 不正、stale、fresh positiveまたはfresh negativeです。
 * @note `FORCE_REFRESH`は正常entryもstaleにし、network失敗時のfallbackを許可しません。
 */
[[nodiscard]] OfficialDiscoveryCacheDisposition evaluateOfficialDiscoveryCacheEntry(
	const OfficialDiscoveryCacheEntry &entry, const OfficialDiscoveryCacheQuery &query) noexcept ;

/**
 * @brief 検証済みrecord descriptor集合から24時間のpositive entryを作ります。
 * @param[in] descriptors 同じrecordから生成したordinal完全集合です。
 * @param[in] policyRevision 現在の自動探索policy revisionです。
 * @param[in] parserId Recordを生成したparser stable IDです。
 * @param[in] parserRevision Recordを生成したparser revisionです。
 * @param[in] observedUtcSeconds Network検証が完了したUTC秒です。
 * @param[in] operatingSystemFingerprint 現在OSの64桁fingerprintです。
 * @param[in] deviceConfigurationFingerprint 現在device集合の64桁fingerprintです。
 * @return 全fieldを保存境界へ縮退できる場合のentry、それ以外は値なしです。
 */
[[nodiscard]] std::optional<OfficialDiscoveryCacheEntry> makeOfficialDiscoveryPositiveCacheEntry(
	std::span<const OfficialRecordPayloadDescriptor> descriptors, std::uint32_t policyRevision,
	std::wstring parserId, std::uint32_t parserRevision, std::uint64_t observedUtcSeconds,
	std::wstring operatingSystemFingerprint, std::wstring deviceConfigurationFingerprint) ;

/**
 * @brief 正常な対象外またはrecordなしから6時間のnegative entryを作ります。
 * @param[in] kind `NOT_APPLICABLE`または`NO_RECORD`です。
 * @param[in] providerId Provider registryのstable IDです。
 * @param[in] policyId 組み込みsource policy IDです。
 * @param[in] rootResourceId Landingまたはmetadata固定root resource IDです。
 * @param[in] policyRevision 現在の自動探索policy revisionです。
 * @param[in] parserId Record parserのstable IDです。
 * @param[in] parserRevision Record parserの単調revisionです。
 * @param[in] observedUtcSeconds 正常な否定結果を確定したUTC秒です。
 * @param[in] operatingSystemFingerprint 現在OSの64桁fingerprintです。
 * @param[in] deviceConfigurationFingerprint 現在device集合の64桁fingerprintです。
 * @return 保存可能なnegative entry、それ以外は値なしです。
 */
[[nodiscard]] std::optional<OfficialDiscoveryCacheEntry> makeOfficialDiscoveryNegativeCacheEntry(
	OfficialDiscoveryCacheEntryKind kind, std::wstring providerId, std::wstring policyId,
	std::wstring rootResourceId, std::uint32_t policyRevision, std::wstring parserId,
	std::uint32_t parserRevision, std::uint64_t observedUtcSeconds,
	std::wstring operatingSystemFingerprint, std::wstring deviceConfigurationFingerprint) ;

/**
 * @brief Fresh positive entryを現在routeの非選択・導入不可表示行へ復元します。
 * @param[in] entry URL非保持のpositive cache entryです。
 * @param[in] query 現在環境、parser、時刻とcache modeです。
 * @param[in] scanSessionId 現在の0ではないscan session IDです。
 * @param[in] route 現在planが検証した固定root routeです。
 * @param[in] devices 現在inventoryのraw ID非保持device hint集合です。
 * @param[in] provider Routeを所有するProvider registry正本です。
 * @return 全bindingとcandidate詳細が有効な場合の表示行集合、それ以外は値なしです。
 * @note Cacheからdownload grant、EULA同意、現在PnP適合、rankまたはinstall routingを復元しません。
 */
[[nodiscard]] std::optional<std::vector<UpdateCandidate>>
makeOfficialDiscoveryCachedDisplayCandidates( const OfficialDiscoveryCacheEntry &entry,
											 const OfficialDiscoveryCacheQuery &query,
											 ScanSessionId						scanSessionId,
											 const OfficialDiscoveryRoute	   &route,
											 std::span<const OfficialDiscoveryDeviceHint> devices,
											 const ProviderDescriptor					 &provider) ;

} // namespace drivercrate
