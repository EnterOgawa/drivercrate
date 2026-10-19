//------------------------------------------------------------------------------
/**
 * @file local_collector_metadata_codec.h
 * @brief 収集metadataの固定所有型と非保存codecを定義します。
 * @version 01.00.00
 * @date 2026/09/29
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  有限metadata往復とscope関係検査を追加。
 * </pre>
 *
 * @note 純粋な値の検査です。予約受入、cache決定、永続保存を行いません。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/local_collector_projected_executor.h"
#include "platform/local_collector_projected_json.h"

namespace drivercrate {

/** @brief Metadataの有限理由です。元sourceの理由とは独立です。 */
enum class CollectorMetadataReason {
	/// 全採用です。
	NONE,
	/// 元sourceの部分性を保持します。
	SOURCE_INCOMPLETE,
	/// 有効recordがありません。
	NO_ELIGIBLE_RECORD,
	/// 一致対象がありません。
	NO_MATCHING_TARGET,
	/// 親が以前の成功から減少を確認しました。
	DECREASED,
	/// 明示上限です。OOMではありません。
	PROJECTION_LIMIT,
	/// 元workerの失敗です。
	WORKER_FAILURE,
	/// 親が元200根拠を拒否しました。
	CACHE_BASIS_INVALID,
	/// Metadata hashの元HRESULT失敗です。
	METADATA_HASH
} ;
/** @brief Metadataの固定形です。 */
enum class CollectorMetadataForm {
	/// 正常、保留、上限または304です。
	FULL,
	/// 配列を持たない失敗です。
	MINIMAL_FAILURE
} ;
/** @brief 旧OBSERVEDと独立したmetadata分類です。 */
enum class CollectorMetadataOutcome {
	/// 一件以上のrecordとMATCHを保持します。
	FETCHED,
	/// 非採用です。
	HELD,
	/// 元失敗または親失敗です。
	FAILED,
	/// 元200の再検証候補です。単独では許可されません。
	REVALIDATED
} ;
/** @brief Slice単位の採否です。 */
enum class CollectorMetadataDisposition {
	/// 今回のsliceを採用します。
	ACCEPTED,
	/// 今回のsliceを採用しません。
	HELD
} ;
/** @brief 明示上限の発生位置です。 */
enum class CollectorMetadataLimitStage {
	/// 上限なしです。
	NONE,
	/// Worker内の上限です。
	WORKER,
	/// 親の件数検査です。
	COUNTS,
	/// Metadata実byteです。
	METADATA_BYTES,
	/// 応答実byteです。
	RESPONSE_BYTES,
	/// 外側実byteです。
	ENVELOPE_BYTES
} ;
/** @brief 最小失敗の発生位置です。 */
enum class CollectorMetadataErrorPhase {
	/// 元workerです。
	WORKER,
	/// 元200検査です。
	CACHE_BASIS,
	/// Metadata hash APIです。
	METADATA_HASH
} ;
/** @brief 元予約と本文に対応する公開bindingです。 */
struct CollectorMetadataBinding {
	/// Source識別子。
	std::wstring				 source ;
	/// Provider識別子。
	std::wstring				 provider ;
	/// Policy識別子。
	std::wstring				 policy ;
	/// 取得元resource識別子。
	std::wstring				 resource ;
	/// 全対象scope hash。
	std::wstring				 scope ;
	/// Cache binding hash。
	std::wstring				 cache ;
	/// 元本文hash。未取得では空です。
	std::wstring				 body ;
	/// 元検証時刻。欠測を0で補いません。
	std::optional<std::uint64_t> validatedUtc ;
} ;
/** @brief 元sliceと最終採否を分離して所有します。 */
struct CollectorMetadataSlice {
	/// 元要求の全field。
	CollectorProjectedSliceScope scope ;
	/// 採用または保留。
	CollectorMetadataDisposition disposition{CollectorMetadataDisposition::HELD} ;
	/// 固定理由。
	CollectorMetadataReason		 reason{CollectorMetadataReason::NONE} ;
	/// 部分性と採否を含む最終完全性。
	bool						 complete{} ;
} ;
/** @brief Source parserの数値だけの実観測です。 */
struct CollectorMetadataSource {
	/// Source別の既知状態値。
	std::uint32_t				  status{} ;
	/// 実走査数。
	std::uint32_t				  seen{} ;
	/// ASUS六分類の順序固定件数。
	std::array<std::uint32_t, 6U> reasonCounts{} ;
	/// Intel重複数。
	std::uint32_t				  duplicates{} ;
	/// Intel拒否数。
	std::uint32_t				  rejected{} ;
	/// Intel衝突数。
	std::uint32_t				  collisions{} ;
} ;
/** @brief 実配列から測った有限件数です。 */
struct CollectorMetadataCounts {
	/// Record総数。
	std::uint32_t records{} ;
	/// Payload総数。
	std::uint32_t payloads{} ;
	/// Slice総数。
	std::uint32_t slices{} ;
	/// Edge総数。
	std::uint32_t edges{} ;
	/// 一edge内の最大参照数。
	std::uint32_t maximumReferences{} ;
} ;
/** @brief 消去された診断をoptionalで区別します。 */
struct CollectorMetadataDiagnostics {
	/// 元worker分類。
	CollectorProjectedWorkerReason		   workerReason{CollectorProjectedWorkerReason::NONE} ;
	/// 元parser終了。未開始ではnullです。
	std::optional<CollectorParserResult>   parser ;
	/// 元source観測。消去済みではnullです。
	std::optional<CollectorMetadataSource> source ;
	/// 実件数。消去済みではnullです。
	std::optional<CollectorMetadataCounts> counts ;
	/// 明示上限位置。
	CollectorMetadataLimitStage			   limitStage{CollectorMetadataLimitStage::NONE} ;
} ;
/** @brief 本文や自由文を含まない失敗観測です。 */
struct CollectorMetadataError {
	/// 元失敗位置。
	CollectorMetadataErrorPhase phase{CollectorMetadataErrorPhase::WORKER} ;
	/// 元数値domain。
	CollectorIoErrorDomain		domain{CollectorIoErrorDomain::NONE} ;
	/// 元32 bit code。
	std::uint32_t				code{} ;
} ;
/** @brief 固定schemaの全metadata fieldを所有します。権限型ではありません。 */
struct CollectorMetadataDocument {
	/// 全体形。
	CollectorMetadataForm				  form{CollectorMetadataForm::FULL} ;
	/// 親最終化前にも使う分類。
	CollectorMetadataOutcome			  outcome{CollectorMetadataOutcome::HELD} ;
	/// 固定理由。
	CollectorMetadataReason				  reason{CollectorMetadataReason::NONE} ;
	/// 最終完全性。
	bool								  complete{} ;
	/// 常にtrueです。
	bool								  researchOnly{true} ;
	/// 常にfalseです。
	bool								  publishable{} ;
	/// 常にfalseです。
	bool								  downloadEligible{} ;
	/// 公開sourceと本文への結合。
	CollectorMetadataBinding			  binding ;
	/// 元順序のrecord。
	std::vector<CollectorProjectedRecord> records ;
	/// 元順序のsliceと最終採否。
	std::vector<CollectorMetadataSlice>	  slices ;
	/// 元順序の全対象edge。
	std::vector<CollectorProjectedEdge>	  edges ;
	/// 元数値診断。
	CollectorMetadataDiagnostics		  diagnostics ;
	/// 最小失敗以外ではnullです。
	std::optional<CollectorMetadataError> error ;
} ;

/** @brief 正常draftを全scope照合後に非保存metadataへ変換します。
 * @param[in] job 元prepared jobの公開値。
 * @param[in] draft 正常parserが作った未確定値。
 * @param[in] parser 元COMPLETED観測。
 * @param[out] document 成功時だけ所有値。失敗時は空の初期型。
 * @return 有限検査結果。I/O、予約、減少、cache採否は後続の親入口で必ず検査します。
 */
[[nodiscard]] collector_projected_json::Result makeCollectorMetadataDocument(
	const CollectorProjectedJobInput &job, const CollectorMetadataProjectionDraft &draft,
	const CollectorParserResult &parser, CollectorMetadataDocument &document) noexcept ;

/** @brief 全field・公開値・元scopeの関係を検査して有限符号化します。
 * @param[in] job 元入力の公開scope。HTTP観測の代用にはしません。
 * @param[in] document 型付き全field。
 * @param[out] bytes Canonical UTF-8。失敗時は空。入力とのaliasは禁止です。
 * @return 結果。Hash、保存、予約受入は行いません。
 */
[[nodiscard]] collector_projected_json::Result encodeCollectorMetadata(
	const CollectorProjectedJobInput &job, const CollectorMetadataDocument &document,
	std::string &bytes) noexcept ;

/** @brief 有限事前走査・型検査・全関係検査・再符号化完全一致を行います。
 * @param[in] job 元入力の公開scope。
 * @param[in] bytes 最大512 KiBの元UTF-8。
 * @param[out] document 成功時だけ所有値。失敗時は空の初期型。
 * @return 結果。Worker成功、通常record evidence、取得権限を発行しません。
 */
[[nodiscard]] collector_projected_json::Result decodeCollectorMetadata(
	const CollectorProjectedJobInput &job, std::string_view bytes,
	CollectorMetadataDocument &document) noexcept ;

} // namespace drivercrate
