//------------------------------------------------------------------------------
/**
 * @file intel_ethernet_windows11_record_adapter.h
 * @brief Intel Ethernet Windows 11 releaseから型付きdistribution recordへの変換定義。
 * @version 01.06.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Intel record 727998用adapterを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  固定root typed resolverを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  Cache失効用parser identityを公開。
 * Ver.01.03.00 Shunji Ogawa  2026/09/23  Intel ZIP系列の共通record変換を公開。
 * Ver.01.04.00 Shunji Ogawa  2026/09/28  727998の収集候補と製品別三状態照合を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/09/28  三状態の優先順位と製品fieldの保持条件を明記。
 * Ver.01.06.00 Shunji Ogawa  2026/09/28  型付き制御入口を追加。
 * Ver.01.06.01 Shunji Ogawa  2026/10/26  SHA-512解釈のparser revisionへ更新。
 * </pre>
 *
 * @note URLは成功時に秘密所有型へ移し、UI、log、cacheへ渡しません。本変換だけではroot証拠、
 *       内容、PnP適用性、推奨または導入可能性の合格を意味しません。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/official_discovery_record_adapter.h"
#include "platform/official_download_grant.h"
#include "platform/official_http_client.h"
#include "platform/official_release_metadata.h"
#include "platform/intel_collector_identity_parser.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

// 自動探索cacheを現在parser実装へ結合するstable ID。
inline constexpr std::wstring_view INTEL_ETHERNET_WINDOWS11_RECORD_PARSER_ID =
	L"intel-ethernet-windows11-page" ;
// Parserのschemaまたは解釈変更時に更新する単調revision。
inline constexpr std::uint32_t INTEL_ETHERNET_WINDOWS11_RECORD_PARSER_REVISION = 4U ;

/** @brief 727998本文と照合する公開targetの借用入力です。 */
struct IntelCollectorTargetQuery {
	/// 評価集合の公開key。空または重複は入力全体を拒否します。
	std::wstring_view targetKey ;
	/// 公開メーカー表示名。
	std::wstring_view maker ;
	/// 公開製品名。大小文字・世代・®を保持して完全一致させます。
	std::wstring_view model ;
	/// NETWORK_ADAPTER等の公開製品種別。
	std::wstring_view kind ;
	/// Ethernet等の明示したdriver目的。
	std::wstring_view purpose ;
	/// Windows 11等の明示OS。Planにない場合はsource scopeからcallerが渡します。
	std::wstring_view operatingSystem ;
	/// x64等の明示architecture。
	std::wstring_view architecture ;
	/// 明示chip条件。空ならchip照合は要求しません。
	std::wstring_view chip ;
} ;

/** @brief Sourceの同一本文に依存する一時照合状態です。取得許可ではありません。 */
enum class IntelCollectorTargetState {
	/// 公開製品・目的・OS・architectureが揃った一時一致。
	MATCH,
	/// 検証済み公開fieldに明示矛盾がある。
	NO_MATCH,
	/// Source不成立・欠測・未掲載・未知条件を含む。
	UNKNOWN
} ;

/** @brief 明示矛盾を未知より優先し、同状態内は製品、目的、OS、architecture、chipの順です。 */
enum class IntelCollectorTargetReason {
	/// 全軸が一致した。
	MATCHED,
	/// 配布recordの解析またはfield検証に失敗した。
	RELEASE_UNKNOWN,
	/// 一覧または配布hero所属の構造を確認できなかった。
	IDENTITY_UNKNOWN,
	/// Targetの公開fieldが有限契約を満たさない。
	INVALID_QUERY,
	/// Makerまたは製品種別が公式scopeと矛盾する。
	PRODUCT_CONFLICT,
	/// 公開名は一覧に見つからず、不適合は確定しない。
	PRODUCT_UNLISTED,
	/// 部分一覧に衝突があり、欠測の製品は判定できない。
	PRODUCT_AMBIGUOUS,
	/// 明示された別の既知driver目的。
	PURPOSE_CONFLICT,
	/// 目的の意味を公式profileと比較できない。
	PURPOSE_UNKNOWN,
	/// 明示された別の既知OS。
	OS_CONFLICT,
	/// OSの意味を公式profileと比較できない。
	OS_UNKNOWN,
	/// 明示された別の既知architecture。
	ARCHITECTURE_CONFLICT,
	/// Architectureの意味を公式profileと比較できない。
	ARCHITECTURE_UNKNOWN,
	/// Chipの構造化根拠がこのpageにない。
	CHIP_UNKNOWN
} ;

/** @brief URL・本文hash・fingerprintを含まないworker内の一時target照合案です。 */
struct IntelCollectorTargetAssessment {
	/// 元の公開target key。
	std::wstring				 targetKey ;
	/// 三状態。MATCHもGET出典・取得許可ではありません。
	IntelCollectorTargetState	 state{IntelCollectorTargetState::UNKNOWN} ;
	/// 第一理由。
	IntelCollectorTargetReason	 reason{IntelCollectorTargetReason::RELEASE_UNKNOWN} ;
	/// 同じ本文で製品名が一致したSKU。目的等が非一致でも保持し、未掲載時は空。
	std::wstring				 sku ;
	/// 整形済みの公開製品名。
	std::wstring				 displayName ;
	/// NFC後の完全一致比較名。
	std::wstring				 comparisonName ;
	/// Worker内の候補ordinal。Record未成立時はnull。最終record参照ではありません。
	std::optional<std::uint32_t> candidateOrdinal ;
} ;

/** @brief 一本文から得た一時候補と対象別照合です。すべてworker内に限定します。 */
struct IntelCollectorMetadataAssessment {
	/// Release parserと配布heroが成立した場合だけtrue。
	bool											releaseParsed{} ;
	/// 同一本文内の専用一覧結果。GET出典は含みません。
	IntelCollectorIdentityResult					identity ;
	/// Release成立時だけ存在する証拠未発行の一時record候補。
	std::optional<OfficialCollectorRecordCandidate> candidate ;
	/// 入力target順の三状態照合案。
	std::vector<IntelCollectorTargetAssessment>		targets ;
} ;

/**
 * @brief 一つの727998本文から配布候補と製品別照合案を組み立てます。
 * @param[in] html 既存release parserと専用一覧parserへ同時に渡す借用本文。
 * @param[in] targets 最大300件の公開targetと明示OS／architecture。
 * @param[in] resolvedUtcSeconds 呼出元が別途確認した本文時刻以降の非zero UTC秒。
 * @param[out] assessment 成功時のworker内一時値。入力拒否時は初期値。
 * @return 入力集合と処理上限が有効ならtrue。配布・一覧の不成立はtrueの結果内で区別します。
 * @note 本関数はGETや公式出典を検証しません。候補はgrantに変換できず、最終edgeの
 *       fingerprint／本文hash／policy証明は後続のGET所有wrapperで設定します。
 */
[[nodiscard]] bool inspectIntelCollectorMetadataPage(
	std::wstring_view html, std::span<const IntelCollectorTargetQuery> targets,
	std::uint64_t resolvedUtcSeconds, IntelCollectorMetadataAssessment &assessment) ;

/**
 * @brief 既存Intel ZIP parserの結果をfamily別根拠と同意に結合して共通recordへ変換します。
 * @param[in,out] release Wi-Fi、Windows 11またはServer 2025 Ethernetの解析結果。
 * @param[in] rootEvidence 同じfamilyの公式root本文取得証拠。
 * @param[in] recordEvidenceId Session内の非zero証拠ID。
 * @param[in] resolvedUtcSeconds Record確定時刻。
 * @param[out] record 成功時だけ公開する秘密URL所有record。失敗時は初期値。
 * @return 既知parser、family、file、hash、同意本文、rootが一致する場合true。
 * @note 端末適合・内容検査・導入許可は発行しません。EXEは対象外です。
 */
[[nodiscard]] bool adaptIntelZipDistributionRecord( OfficialReleaseRecord	   &&release,
												   const OfficialSourceEvidence &rootEvidence,
												   std::uint64_t				 recordEvidenceId,
												   std::uint64_t				 resolvedUtcSeconds,
												   OfficialDistributionRecord	&record) ;

/**
 * @brief Intel record 727998のrelease metadataをURL秘密所有のdistribution recordへ変換します。
 * @param[in,out] release Windows 11専用parserの結果。成功時は文字列の所有権を結果へ移します。
 * @param[in] rootEvidence 固定Intel root本文のURL非保持取得証拠。
 * @param[in] recordEvidenceId 同じscan session内で割り当てた0ではないrecord証拠ID。
 * @param[in] resolvedUtcSeconds Root検証後にrecordを固定したUTC秒。
 * @param[out] record 成功時の一payload record。失敗時は初期値です。
 * @return Family、版、file、hash、EULA、root時刻が有限かつ整合する場合は`true`。
 * @post 成功時は`release.downloadUrl`を含む文字列を結果へ移動します。
 * @note 概算表示をexact byte数へ変換せず、`publishedSizeBytes`の欠落を維持します。
 */
[[nodiscard]] bool adaptIntelEthernetWindows11DistributionRecord(
	OfficialReleaseRecord &&release, const OfficialSourceEvidence &rootEvidence,
	std::uint64_t recordEvidenceId, std::uint64_t resolvedUtcSeconds,
	OfficialDistributionRecord &record) ;

/**
 * @brief 組み込みIntel record 727998固定rootを取得して型付きdistribution recordへ解決する。
 * @param[in] scanSessionId 現在のworker scan session ID。
 * @param[in] recordEvidenceId Sessionが今回だけ割り当てた0ではないrecord証拠ID。
 * @param[in] providerId Registryで検証済みのIntel Windows 11 Provider ID。
 * @param[in] rootResourceId Source policyの固定landing resource ID。
 * @param[in] builtInRootUrl 組み込みsource policyから得た固定landing URL。
 * @param[in] maximumRecordBytes 固定定義と一致する2 MiB以下の本文上限。
 * @param[in] fetchMode 秘密URLをcacheへ保存しない固定mode。
 * @param[in,out] client Composite workerが所有するcache無効の公式HTTP client。
 * @param[out] record 解決成功時だけ設定する秘密URL所有record。
 * @return 解決、通常失敗、source拒否、metadata拒否を区別するURL非保持結果。
 * @note 同期network処理を含むためUI threadから呼びません。Device hintまたは端末IDを受け取りません。
 */
[[nodiscard]] OfficialDiscoveryFixedRootResult resolveIntelEthernetWindows11OfficialDiscoveryRecord(
	ScanSessionId scanSessionId, std::uint64_t recordEvidenceId, std::wstring_view providerId,
	std::wstring_view rootResourceId, std::wstring_view builtInRootUrl,
	std::uint64_t maximumRecordBytes, OfficialRecordFetchMode fetchMode, OfficialHttpClient &client,
	OfficialDistributionRecord &record) ;

/**
 * @brief 同一本文の配布・一覧・全対象を停止理由を保って解析します。
 * @param[in] html 同一GET本文。
 * @param[in] targets 最大300件の公開対象。
 * @param[in] resolvedUtcSeconds 本文時刻。
 * @param[in,out] control 元GETの必須制御。
 * @param[out] assessment 完了後だけ公開する所有結果。
 * @return 解析手順の型付き終了。
 */
[[nodiscard]] CollectorParserResult inspectIntelCollectorMetadataPageControlled(
	std::wstring_view html, std::span<const IntelCollectorTargetQuery> targets,
	std::uint64_t resolvedUtcSeconds, OfficialCollectorHttpControl &control,
	IntelCollectorMetadataAssessment &assessment) ;
} // namespace drivercrate
