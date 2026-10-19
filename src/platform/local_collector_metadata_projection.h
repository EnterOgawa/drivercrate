//------------------------------------------------------------------------------
/**
 * @file local_collector_metadata_projection.h
 * @brief 同じ公式200本文から秘密を除いた収集用recordと全対象edgeを作ります。
 * @version 01.05.00
 * @date 2026/09/28
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  URL再検証と秘密値なし全対象射影を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/28  Edgeの本文・parser結合と欠測公式値を明示。
 * Ver.01.02.00 Shunji Ogawa  2026/09/28  部分拒否・一覧重複の固定数値診断を保持。
 * Ver.01.03.00 Shunji Ogawa  2026/09/29  秘密値・成功DTOを渡さない境界診断を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/29  指紋関係とordinal解決の非所有判定を公開。
 * Ver.01.05.00 Shunji Ogawa  2026/09/29  実配列の有限件数と構造不一致の共通判定を追加。
 * </pre>
 *
 * @note HTTP終端・取得・保存を行わず、開発用worker内でのみ使用します。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/collector_parser_control.h"
#include "platform/local_collector_http_client.h"
#include "platform/official_download_grant.h"

#include <cstdint>
#include <cstddef>
#include <functional>
#include <array>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {

/** @brief 元parserの結果を変更できない固定診断位置です。 */
enum class CollectorProjectionPoint {
	/// Sourceの候補化が完了した直後です。
	ADAPTER_COMPLETE,
	/// 元ordinalのrecordを検証・射影する直前です。
	RECORD,
	/// 元順序の対象edgeを組み立てる直前です。
	TARGET
} ;

/** @brief 開発用workerだけで借用する失敗専用依存です。通常は全て空です。 */
struct CollectorProjectionDiagnostics {
	/// Job index・固定位置・元ordinalだけの通知。成功値やcontrolを返せません。
	std::function<void( std::size_t, CollectorProjectionPoint, std::size_t)> checkpoint ;
	/// Job index・record ordinalに対するCNG直前の元NTSTATUS。成功なら実hashします。
	std::function<std::int32_t( std::size_t, std::size_t)>					beforeRecordHash ;
} ;

/** @brief 全条件が成立したか、本文から確定できないかを区別します。 */
enum class CollectorProjectedTargetState {
	/// 全条件が同一本文の証拠と一致しました。
	MATCH,
	/// 検証済み公開fieldに明示矛盾があります。
	NO_MATCH,
	/// 必要な公開根拠が欠けており不適合と断定できません。
	UNKNOWN
} ;

/** @brief 一payloadの構文検査観測と公開metadataです。 */
struct CollectorProjectedPayload {
	/// URLを含まない通常の公開field。
	OfficialCollectorPayloadProjection value ;
	/// 同一本文・組み込みpolicy・source固有規則を検査した観測です。到達確認ではありません。
	bool							   payloadLinkValidated{} ;
} ;

/** @brief 同一本文の公開record一件です。 */
struct CollectorProjectedRecord {
	/// 元の通常canonical指紋と公開field。
	OfficialCollectorRecordProjection	   value ;
	/// この本文で要求した有限slice key。
	std::wstring						   sliceKey ;
	/// URLを除いた各payloadの検査観測。
	std::vector<CollectorProjectedPayload> payloads ;
} ;

/** @brief 元公開対象を減らさない一対象・一sliceの所有edgeです。 */
struct CollectorProjectedEdge {
	/// 元manifest内のindexと公開field。端末PnP IDではありません。
	CollectorProjectedTargetScope				 target ;
	/// 元要求sliceのkey。
	std::wstring								 sliceKey ;
	/// 同じ200本文のraw byte hash。
	std::wstring								 bodySha256 ;
	/// 元scopeに固定したrecord parser。
	std::wstring								 recordParser ;
	/// 元scopeに固定した製品一覧parser。
	std::wstring								 identityParser ;
	/// 元scopeに固定した三状態照合規則。
	std::wstring								 matchingRule ;
	/// 対象照合の三状態。
	CollectorProjectedTargetState				 state{CollectorProjectedTargetState::UNKNOWN} ;
	/// Source別enumの元数値。source IDと併せて解釈します。
	std::uint32_t								 reasonCode{} ;
	/// 公式側が示した製品識別子。未掲載ならnullです。
	std::optional<std::wstring>					 sourceProductId ;
	/// 公式側の表示名。未掲載ならnullです。
	std::optional<std::wstring>					 sourceDisplayName ;
	/// 公式側の比較名。未掲載ならnullです。
	std::optional<std::wstring>					 sourceComparisonName ;
	/// 検証済みrecordへの重複なし参照。取得許可ではありません。
	std::vector<OfficialStableRecordFingerprint> recordFingerprints ;
} ;

/** @brief Wrapperの正常・保留・最小失敗を区別します。 */
enum class CollectorProjectionDraftStatus {
	/// 有効recordと一件以上のMATCHを保持します。親の最終成功ではありません。
	FETCHED,
	/// 全対象を保持したまま取得対象を確定できません。
	HELD,
	/// 構造・停止・障害時に成功配列を保持しません。
	MINIMAL_FAILURE
} ;

/** @brief Workerが親へmoveできる秘密値なしの未確定射影です。 */
struct CollectorMetadataProjectionDraft {
	/// HTTPのfinish・親の減少判定より前の暫定分類。
	CollectorProjectionDraftStatus status{CollectorProjectionDraftStatus::MINIMAL_FAILURE} ;
	/// 元200 raw byteのhash。
	std::wstring				   bodySha256 ;
	/// 元GETの公開source／policy／resource。
	std::wstring				   sourceId ;
	/// 元組み込みprovider。
	std::wstring				   providerId ;
	/// 元組み込みpolicy。
	std::wstring				   policyId ;
	/// 元landing／metadata resource。
	std::wstring				   resourceId ;
	/// 全公開対象とsliceの結合。
	std::wstring				   scopeSha256 ;
	/// 元jobの専用cache binding。
	std::wstring				   cacheBinding ;
	/// 元本文の検証時刻。処理完了時刻へ延長しません。
	std::uint64_t				   validatedUtcMillis{} ;
	/// 部分拒否を含まない場合だけtrue。親のCACHE許可ではありません。
	bool						   complete{} ;
	/// Source parserの固定状態値と診断数。本文・URLを含みません。
	std::uint32_t				   sourceStatus{} ;
	/// Source parserが確認した行数。上限拒否時の全件数ではありません。
	std::uint32_t				   sourceSeen{} ;
	/// ASUS行の固定理由順の件数。Intelでは全zeroです。
	std::array<std::uint32_t, 6U>  sourceReasonCounts{} ;
	/// Intel一覧の同key・同名の重複数。ASUSでは0です。
	std::uint32_t				   sourceDuplicates{} ;
	/// Intel一覧の不正行数。ASUSではreasonCountsへ記録します。
	std::uint32_t				   sourceRejected{} ;
	/// Intel一覧の衝突行数。ASUSでは0です。
	std::uint32_t				   sourceCollisions{} ;
	/// 要求順の全sliceと公開record／全target edge。
	std::vector<CollectorProjectedSliceScope> slices ;
	/// 同指紋・同内容を折り畳んだ公開record。
	std::vector<CollectorProjectedRecord>	  records ;
	/// 元対象順に保持する全edge。
	std::vector<CollectorProjectedEdge>		  edges ;
} ;

/** @brief Worker内部の公開record関係とordinalを、所有値の変更なしで判定します。 */
namespace collector_projection_detail {

/** @brief 既存一recordと新候補の指紋・公開field関係です。 */
enum class RecordRelation {
	/// 指紋が異なる独立recordです。
	DISTINCT,
	/// 指紋・公開field・sliceが同じであり折畳み可能です。
	EQUIVALENT,
	/// 指紋だけが同じで公開fieldまたはsliceが異なります。
	CONFLICT
} ;

/** @brief 件数上限と構造不一致を混ぜない非保存判定です。 */
enum class CountResult {
	/// 汎用件数上限内で、二つのpayload配列の長さが一致します。
	WITHIN_LIMIT,
	/// Record／payload／slice／edge／一edge参照のいずれかが上限超過です。
	LIMIT_EXCEEDED,
	/// 同じrecord内の公開payloadと検証観測payloadの件数が異なります。
	INVALID_SHAPE
} ;

/** @brief 五つの汎用件数だけをoverflowなしで比較します。
 * @param[in] records 一jobのrecord件数。
 * @param[in] payloads 一jobのpayload合計件数。
 * @param[in] slices 一jobのslice件数。
 * @param[in] edges 一jobのedge件数。
 * @param[in] references 一edge内のrecord参照件数。
 * @return 全て第5節の上限内ならtrue。初期profileの適合・保存許可は含みません。
 */
[[nodiscard]] bool withinCountLimits( std::size_t records, std::size_t payloads, std::size_t slices,
									 std::size_t edges, std::size_t references) noexcept ;

/** @brief 実配列だけから件数を測り、上限と配列長の矛盾を分類します。
 * @param[in] records URL非保持の公開record配列。
 * @param[in] slices 元scope順のslice配列。
 * @param[in] edges 全対象のedge配列。
 * @return 件数上限内／上限超過／payload配列長不一致。
 * @note 結果は取得・保存許可ではなく、field同値・scope・byte数は別途検査します。
 */
[[nodiscard]] CountResult	 checkCounts( std::span<const CollectorProjectedRecord>	   records,
										 std::span<const CollectorProjectedSliceScope> slices,
										 std::span<const CollectorProjectedEdge>	   edges) noexcept ;

/** @brief 実CNG後の二recordだけを比較する本番と共通の非所有判定です。
 * @param[in] prior 先にURLと通常recordを検証した公開値。
 * @param[in] priorSlice 先行recordの元slice key。
 * @param[in] incoming 新候補の通常record公開値。
 * @param[in] incomingSlice 新候補の元slice key。
 * @return 指紋と全公開field・sliceの関係。取得・保存許可は発行しません。
 */
[[nodiscard]] RecordRelation compareRecords( const OfficialCollectorRecordProjection &prior,
											std::wstring_view						 priorSlice,
											const OfficialCollectorRecordProjection &incoming,
											std::wstring_view incomingSlice) noexcept ;

/** @brief 元candidate ordinalが検証済みrecordを指す場合だけindexを返します。
 * @param[in] ordinal 元候補配列内の位置。
 * @param[in] ordinalToRecord 元順序から折畳み後record indexへの対応。
 * @param[in] recordCount 実際に検証・保持したrecord件数。
 * @return 範囲内index。欠損・範囲外ならnullで、0へ補完しません。
 */
[[nodiscard]] std::optional<std::size_t> resolveOrdinal(
	std::uint32_t ordinal, std::span<const std::size_t> ordinalToRecord,
	std::size_t recordCount) noexcept ;

} // namespace collector_projection_detail

/** @brief 一回GET本文を消費し、二つの固定公式sourceだけを射影します。
 * @param[in] body 同じworkerからmoveされた未消費の正常200本文。
 * @param[in] campaign 保存canonicalから再構築した変更不能全job。
 * @param[in] jobIndex 元予約jobのindex。
 * @param[out] projection 完了時だけ所有する公開値。失敗時は最小失敗の空配列です。
 * @return 解析・URL・共通record・全edgeの型付き結果。
 * @note 成功でも取得権限、HTTP終端、CACHE許可を発行しません。元制御は本文内からのみ取得します。
 */
[[nodiscard]] CollectorParserResult projectCollectorMetadataBody(
	CollectorMetadataBody body, const CollectorPreparedProjectedCampaign &campaign,
	std::size_t jobIndex, CollectorMetadataProjectionDraft &projection) noexcept ;

/** @brief 元本文と同じ本番coreへ数値だけの診断依存を接続します。
 * @param[in] body 同じGETの未消費本文。
 * @param[in] campaign 元の変更不能全job。
 * @param[in] jobIndex 元予約のjob index。
 * @param[out] projection 成功時だけ公開値。失敗時は空配列。
 * @param[in] diagnostics 同期呼出し中だけ借用する依存。停止は元controlへ伝えます。
 * @return 通常入口と同じ型付き終了値。
 * @note 診断callbackへ秘密値を渡さず、取得許可や成功DTOの注入を認めません。
 */
[[nodiscard]] CollectorParserResult projectCollectorMetadataBodyWithDiagnostics(
	CollectorMetadataBody body, const CollectorPreparedProjectedCampaign &campaign,
	std::size_t jobIndex, CollectorMetadataProjectionDraft &projection,
	const CollectorProjectionDiagnostics &diagnostics) noexcept ;

} // namespace drivercrate
