//------------------------------------------------------------------------------
/**
 * @file asus_network_record_adapter.h
 * @brief ASUS公式ネットワーク配布を共通recordへ接続します。
 * @version 01.06.00
 * @date 2026/09/20
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/20  ASUSネットワーク配布のAI取得接続を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/20  製品固定なしcatalog queryと取得予算を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/20  取得前目的照合用の公式driver分類をrecordへ保持。
 * Ver.01.03.00 Shunji Ogawa  2026/09/24  公開model明示の公式page解決入口を分離。
 * Ver.01.04.00 Shunji Ogawa  2026/09/24  旧用途hintと別の公開model付きquery v2を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/09/28  収集専用候補と共通配布field組立てを追加。
 * Ver.01.06.00 Shunji Ogawa  2026/09/28  必須制御付き候補／対象照合入口を追加。
 * </pre>
 *
 * @note 呼出しthreadで同期実行します。取得用recordは適用性または導入許可ではありません。
 * @see docs/adr/0179-asus-network-ai-acquisition.md
 */
//------------------------------------------------------------------------------

#pragma once
#include "platform/asus_catalog_parser.h"
#include "platform/asus_system_identity.h"
#include "platform/official_download_grant.h"
#include "platform/official_http_client.h"
#include <cstdint>
#include <cstddef>
#include <span>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
/** @brief URLや端末情報を含めない公式record解決の段階観測です。 */
struct AsusNetworkRecordObservation {
	/// 引数0、local識別1、session2、HTTP3、parser4、adapter5、完了6です。
	std::uint32_t				 stage{} ;
	/// 既存parserが正常に返したmetadata件数。未解析は0です。
	std::size_t					 entries{} ;
	/// 共通recordへ変換できた件数。失敗時は0です。
	std::size_t					 records{} ;
	/// 対象category内の解析結果。従来scopeでは未使用です。
	AsusDriverCatalogObservation catalog{} ;
	/// 有効metadataのうち明示容量予算を超えた件数です。
	std::size_t					 overBudget{} ;
} ;
/** @brief 開発用の公開配布確認scopeです。実機適合を表しません。 */
enum class AsusNetworkRecordTarget {
	/// Marvell LANの公開ZIPを対象にします。
	MARVELL_LAN,
	/// QCA／Qualcomm Wi-Fiの公開ZIPを対象にします。
	QUALCOMM_WIFI,
	/// 製品名の事前登録を要求しない明示driver categoryです。
	CATALOG
} ;
/** @brief 端末IDやURLを含めない開発用の公開探索条件です。 */
struct AsusDriverCatalogQuery {
	/// 公式分類のうちdriverとして許可済みのcategoryです。
	std::wstring						  category ;
	/// AIへ渡す公開メーカー名。ASCII 1～64 byteです。
	std::string							  manufacturer ;
	/// AIへ渡す公開製品名。ASCII 1～128 byteです。
	std::string							  product ;
	/// 一取得の上限。128 MiBまたは512 MiBです。
	std::uint64_t						  maximumBytes{} ;
	/// v2だけの明示ASUS公開modelとOS。旧queryでは空で現PC識別を維持します。
	std::optional<AsusSupportPageRequest> publicPage ;
} ;
/**
 * @brief 有限のcanonical query fileを通信なしで検証します。
 * @param[in] bytes DCASUSQUERY1の5行、または公開model／OSを追加したDCASUSQUERY2の7行。
 * @return 正常時の公開条件。不正文字、未知分類、過大予算では空。
 * @note URL、path、制御文字、ID形式を公開hintとして受け入れません。
 */
[[nodiscard]] std::optional<AsusDriverCatalogQuery> parseAsusDriverCatalogQuery(
	std::string_view bytes) ;
/**
 * @brief 検証済みASUS解析結果を同一rootの有限record集合へ変換します。
 * @param[in] entries 既存parserが同じ応答から返した配布metadata。
 * @param[in] request 同じ応答で照合したmodel・OS・固定公式起点。
 * @param[in] target 明示されたネットワーク配布scope。
 * @param[in] rootEvidence Cacheなし本文取得のASUS公式根拠。
 * @param[in] resolvedUtcSeconds 本文解析後のUTC秒。
 * @param[out] records 成功時の1～16 record。失敗時は空。
 * @param[in] category CATALOGでだけ指定する公式分類。
 * @param[in] maximumBytes 128 MiB、CATALOGでは512 MiBも指定可能。
 * @param[out] overBudget 非null時に予算超過の件数を返します。
 * @return 公式根拠、公開hash、ZIP、有限集合を検証できた場合true。
 * @note URLをログやAIへ渡しません。端末の生ID照合は行いません。
 */
[[nodiscard]] bool adaptAsusNetworkDistributionRecords(
	std::span<const AsusDriverPageEntry> entries, const AsusSupportPageRequest &request,
	AsusNetworkRecordTarget target, const OfficialSourceEvidence &rootEvidence,
	std::uint64_t resolvedUtcSeconds, std::vector<OfficialDistributionRecord> &records,
	std::wstring_view category = {}, std::uint64_t maximumBytes = 128ULL * 1024ULL * 1024ULL,
	std::size_t *overBudget = nullptr) ;

/**
 * @brief 収集専用の同一store解析結果から、証拠未発行の一時record候補を作ります。
 * @param[in] page 同じ本文・同じrequestで解析したASUS公開identityと採用行。
 * @param[in] request 解析時に使用した公式model・OSのcanonical要求。
 * @param[in] resolvedUtcSeconds 同一本文の検証時刻以降のUTC秒。
 * @param[out] candidates 成功時だけ秘密URLを含むworker内候補を返します。
 * @return 同一scope、公式URL、公開hash、一意性と16件上限を満たした場合true。
 * @note 呼出元はpageとrequestの同一本文結合を保証します。取得証拠・grantは発行しません。
 */
[[nodiscard]] bool adaptAsusCollectorNetworkRecordCandidates(
	const AsusCollectorPageResult &page, const AsusSupportPageRequest &request,
	std::uint64_t resolvedUtcSeconds, std::vector<OfficialCollectorRecordCandidate> &candidates) ;
/**
 * @brief 現在のASUS公開model起点を一回取得し、既存parserからrecordを作ります。
 * @param[in] session 現在操作の0でないsession。
 * @param[in] target 明示されたscope。
 * @param[in,out] client Cache無効の公式HTTP owner。
 * @param[out] records 成功時の同一応答record集合。失敗時は空。
 * @param[out] observation 最後に開始した段階と非機密件数。
 * @param[in] category CATALOGでだけ指定する公式分類。
 * @param[in] maximumBytes 128 MiB、CATALOGでは512 MiBも指定可能。
 * @param[in] publicRequest 非null時だけ公開model明示要求。必ずcanonicalに再構築して検証します。
 * @return 成功0、対象外・通信・schema拒否はHRESULT。
 * @note COM apartment内で同期実行します。Payload取得や実行は行いません。
 */
[[nodiscard]] NativeError resolveAsusNetworkDistributionRecords(
	ScanSessionId session, AsusNetworkRecordTarget target, OfficialHttpClient &client,
	std::vector<OfficialDistributionRecord> &records, AsusNetworkRecordObservation &observation,
	std::wstring_view category = {}, std::uint64_t maximumBytes = 128ULL * 1024ULL * 1024ULL,
	const AsusSupportPageRequest *publicRequest = nullptr) ;

/**
 * @brief 明示した公開ASUS modelの公式pageを一回取得し型付きrecordを作ります。
 * @param[in] session 現在操作の0でないsession。
 * @param[in] target 明示されたscope。
 * @param[in,out] client Cache無効の公式HTTP owner。
 * @param[in] publicModel 公式pageへ使う公開製品model。端末から列挙したIDではありません。
 * @param[in] osName 明示したWindows 10／11 64-bit表記。
 * @param[out] records 成功時の同一応答record集合。
 * @param[out] observation 段階と件数。失敗時の原因区別に使用します。
 * @param[in] category CATALOGの公式driver分類。
 * @param[in] maximumBytes 一件の有限取得上限。
 * @return 成功0、model／OS・通信・schema拒否はHRESULT。
 * @note 現PCのregistryは読まず、成功だけで端末PnP適合としません。
 */
[[nodiscard]] NativeError resolveAsusNetworkDistributionRecordsForPublicModel(
	ScanSessionId session, AsusNetworkRecordTarget target, OfficialHttpClient &client,
	std::wstring_view publicModel, std::wstring_view osName,
	std::vector<OfficialDistributionRecord> &records, AsusNetworkRecordObservation &observation,
	std::wstring_view category = {}, std::uint64_t maximumBytes = 128ULL * 1024ULL * 1024ULL) ;
/**
 * @brief 同じcoreで停止・失敗と候補／対象の照合結果を分けます。
 * @param[in] page 同じ本文のpage。
 * @param[in] request 同じ公式要求。
 * @param[in] resolvedUtcSeconds 本文時刻。
 * @param[in,out] control 元GETの必須制御。
 * @param[out] candidates 完了時のみ公開する所有値。
 * @return 解析／照合の型付き終了。
 */
[[nodiscard]] CollectorParserResult adaptAsusCollectorNetworkRecordCandidatesControlled(
	const AsusCollectorPageResult &page, const AsusSupportPageRequest &request,
	std::uint64_t resolvedUtcSeconds, OfficialCollectorHttpControl &control,
	std::vector<OfficialCollectorRecordCandidate> &candidates) ;
} // namespace drivercrate
