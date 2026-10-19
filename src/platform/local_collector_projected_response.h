//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_response.h
 * @brief 収集応答v4の非保存所有型と元I/O再結合codecです。
 * @version 01.01.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  応答v4全field・元I/O・実byte hashを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/29  成功参照と減少の非保存最終化を追加。
 * </pre>
 *
 * @note Codec成功は予約受入や保存許可ではありません。履歴contextは親入口で必須です。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/local_collector_metadata_codec.h"
#include "platform/local_collector_projected_input.h"

namespace drivercrate {
/** @brief 固定cache操作名です。実際の更新を実行しません。 */
enum class CollectorProjectedCacheAction {
	/// 今回200を新成功候補にします。
	REPLACE,
	/// 元200を304で再検証する候補です。
	REVALIDATE,
	/// 条件付き再利用を無効にする候補です。
	INVALIDATE
} ;
/** @brief 固定cache理由です。自由文を保存しません。 */
enum class CollectorProjectedCacheReason {
	/// 全採用とvalidatorあり。
	ACCEPTED,
	/// 全採用ですがvalidatorなし。
	NO_VALIDATOR,
	/// 元200の再検証。
	REVALIDATED,
	/// 部分結果。
	PARTIAL,
	/// 今回の採用なし。
	NO_CURRENT_MATCH,
	/// 元成功から減少。
	DECREASED,
	/// 明示上限。
	PROJECTION_LIMIT,
	/// 元worker失敗。
	WORKER_FAILURE,
	/// 元200根拠拒否。
	CACHE_BASIS_INVALID,
	/// Metadata hash故障。
	METADATA_HASH
} ;
/** @brief 更新予定の固定値です。保存や履歴の真正性は保証しません。 */
struct CollectorProjectedCacheDecision {
	/// 元metadataから導く操作。
	CollectorProjectedCacheAction action{CollectorProjectedCacheAction::INVALIDATE} ;
	/// 同じ導出で決める理由。
	CollectorProjectedCacheReason reason{CollectorProjectedCacheReason::WORKER_FAILURE} ;
} ;
/** @brief 元200へ直接結合する六fieldです。単独では検証済みpinではありません。 */
struct CollectorProjectedOriginal200 {
	/// 元generation。
	std::wstring  generation ;
	/// 元操作hash。
	std::wstring  operation ;
	/// 元応答実byte hash。
	std::wstring  response ;
	/// 元metadata hash。
	std::wstring  projection ;
	/// 元200 raw hash。
	std::wstring  body ;
	/// 元header時刻。今回時刻へ延長しません。
	std::uint64_t headerUtc{} ;
} ;
/** @brief 元観測とmetadataを保持するv4の公開値です。権限型ではありません。 */
struct CollectorProjectedResponse {
	/// 元generation。
	std::wstring								 generation ;
	/// 元job。
	std::wstring								 job ;
	/// 元source。
	std::wstring								 source ;
	/// 元request。
	std::wstring								 request ;
	/// 元cache binding。
	std::wstring								 cache ;
	/// 元予約のJST日。
	std::wstring								 day ;
	/// 元本文上限。
	std::uint64_t								 maximum{} ;
	/// 元予約開始UTC。
	std::uint64_t								 started{} ;
	/// 元worker終了UTC。
	std::uint64_t								 finished{} ;
	/// 親の受領UTC。現在時計との照合は親が実施します。
	std::uint64_t								 accepted{} ;
	/// 最終metadataと同じ状態。
	CollectorMetadataOutcome					 state{CollectorMetadataOutcome::FAILED} ;
	/// 実本文量。未知はnullです。
	std::optional<std::uint64_t>				 bytes ;
	/// 明示送信0／1。
	std::uint32_t								 sends{} ;
	/// 元HTTP status。未受信0。
	std::uint32_t								 status{} ;
	/// 元I/O error code。親hash障害で上書きしません。
	std::uint32_t								 error{} ;
	/// 元I/O error domain。
	CollectorIoErrorDomain						 errorDomain{CollectorIoErrorDomain::NONE} ;
	/// 同じGETの待機期限。欠測の外側表現は0です。
	std::uint64_t								 retryAfter{} ;
	/// 同じGETの要確認。
	bool										 review{} ;
	/// 現profileはfalseです。
	bool										 challenge{} ;
	/// 元raw hash。
	std::wstring								 body ;
	/// 成功codec時に計算済みのmetadata hash。特殊hash故障時のみ空です。
	std::wstring								 projection ;
	/// 元I/O全観測。旧v1 objectを内包します。
	CollectorIoSnapshot							 io ;
	/// 全fieldのmetadata。
	CollectorMetadataDocument					 metadata ;
	/// 送信validator。現在workerはnull固定です。
	std::optional<std::wstring>					 requestValidator ;
	/// 元応答validator。未観測ではnullです。
	std::optional<std::wstring>					 responseValidator ;
	/// 304時だけ元200参照。
	std::optional<CollectorProjectedOriginal200> original200 ;
	/// Metadataから独立再導出する更新候補。
	CollectorProjectedCacheDecision				 cacheDecision ;
} ;
/** @brief 非保存符号化物です。親受入済み・保存済みと呼びません。 */
struct CollectorProjectedResponseBytes {
	/// 元byteに対応する所有値。
	CollectorProjectedResponse value ;
	/// Metadataの元canonical byte。
	std::string				   metadata ;
	/// 応答全体の元canonical byte。
	std::string				   response ;
	/// 旧schema名を持つ有限外側byte。
	std::string				   envelope ;
	/// 応答実byte hash。
	std::wstring			   responseSha256 ;
} ;
/** @brief 成功値を差し込めないhash段階です。 */
enum class CollectorProjectedHashStage {
	/// Metadata符号化後。
	METADATA,
	/// 応答符号化後。
	RESPONSE,
	/// 読み戻し時のmetadata独立検証。
	READ_METADATA,
	/// 読み戻し時の応答独立検証。
	READ_RESPONSE
} ;
/** @brief 負のHRESULTだけを注入可能な診断です。0では必ず実CNGを使います。 */
using CollectorProjectedHashProbe = std::function<NativeError( CollectorProjectedHashStage)> ;
/** @brief 失敗段階を上限とhashの型と併せて返します。 */
struct CollectorProjectedResponseResult {
	/// 字句・関係・OOM・hash・上限の結果。
	collector_projected_json::Result result ;
	/// 上限／hashが生じた層。成功・関係違反はNONEです。
	CollectorMetadataLimitStage		 stage{CollectorMetadataLimitStage::NONE} ;
} ;

/** @brief 元成功sliceの参照と実byteです。登録済み権限型ではありません。 */
struct CollectorProjectedHistoryEvidence {
	/// 元canonicalを組み込み契約と照合済みの所有入力。
	std::shared_ptr<const CollectorPreparedProjectedCampaign> campaign ;
	/// 元入力内のjob位置。
	std::size_t												  jobIndex{} ;
	/// 元G。
	std::wstring											  generation ;
	/// 元Gとjobから作られたO。
	std::wstring											  operation ;
	/// 元応答実byteのhash。
	std::wstring											  response ;
	/// 元metadata実byteのhash。
	std::wstring											  projection ;
	/// 以前ACCEPTEDだったslice key。
	std::wstring											  slice ;
	/// 元canonical input。最大768 KiB。
	std::string												  input ;
	/// 元v3 intent。最大4 KiB。
	std::string												  startIntent ;
	/// 元v4 envelope。最大2 MiB。
	std::string												  envelope ;
} ;

/** @brief hash生成前の今回候補と過去参照です。保存・送信許可ではありません。 */
struct CollectorProjectedHistoryFinalization {
	/// 元I/Oを保持した今回200または失敗候補。
	CollectorProjectedResponse					 response ;
	/// 同bindingの成功参照を比較した件数。
	std::uint32_t								 comparedSlices{} ;
	/// 減少したslice数。
	std::uint32_t								 decreasedSlices{} ;
	/// 同bindingの完全成功200候補。304 pinではありません。
	std::optional<CollectorProjectedOriginal200> previousFull200 ;
	/// 元200で観測したvalidator。欠測を生成しません。
	std::optional<std::wstring>					 previousValidator ;
} ;

/** @brief 元input・intent・応答byteと成功sliceを照合して減少を判定します。
 * @param[in] job 今回の変更不能なprepared job。
 * @param[in] worker 全join後の元結果。ここでは所有監督を証明しません。
 * @param[in] acceptedUtc 今回の親受領UTC。
 * @param[in] history 最大16件の元参照。重複slice・壊れた別bindingも拒否します。
 * @param[out] output 成功時だけ最終候補。失敗時は空。入力とのaliasは禁止です。
 * @param[in] probe 元応答を読む際のhash故障専用診断。
 * @return 元codecのhash失敗または関係違反。縮退や再試行はしません。
 * @note Root登録・直近成功・保存完了を証明しません。現200のoriginal200はnullのままです。
 */
[[nodiscard]] collector_projected_json::Result finalizeCollectorProjectedHistory(
	const CollectorPreparedProjectedJob &job, const CollectorProjectedWorkerResult &worker,
	std::uint64_t acceptedUtc, std::span<const CollectorProjectedHistoryEvidence> history,
	CollectorProjectedHistoryFinalization &output,
	const CollectorProjectedHashProbe	  &probe = {}) noexcept ;

/** @brief 現metadataだけからcache更新候補を再導出します。
 * @param[in] response 検査対象の値。減少・元200真正性は別途親contextが検査します。
 * @return 固定操作と理由。保存や再送許可ではありません。
 */
[[nodiscard]] CollectorProjectedCacheDecision collectorProjectedCacheDecision(
	const CollectorProjectedResponse &response) noexcept ;

/** @brief 同一GETの所有観測を履歴判定前の応答候補へ変換します。
 * @param[in] job 元prepared jobの公開値。
 * @param[in] worker 全join後に読み取った元結果。ここではjoin自体を証明しません。
 * @param[in] acceptedUtc 親が観測した受領UTC。
 * @param[out] response 成功時だけ非保存候補。失敗時は空。
 * @return 型・元I/O・draft結合の検査結果。履歴なしとは判定しません。
 * @note 通常200／元失敗だけです。304成功を生成しません。最終親入口は別工程です。
 */
[[nodiscard]] collector_projected_json::Result makeCollectorProjectedResponseCandidate(
	const CollectorProjectedJobInput &job, const CollectorProjectedWorkerResult &worker,
	std::uint64_t acceptedUtc, CollectorProjectedResponse &response) noexcept ;

/** @brief 全field・元I/Oを検査し、metadata／応答の実hashと外側を生成します。
 * @param[in] job 元固定scope。
 * @param[in] response 履歴判定を終えた値。値型だけでは親受入済みではありません。
 * @param[out] encoded 成功時だけ実byte。失敗時は空。入力responseとのaliasは禁止です。
 * @param[in] probe 数値だけの任意診断。
 * @return 元hash errorと失敗層。入力projectionが非空なら実計算値との一致も必須です。
 */
[[nodiscard]] CollectorProjectedResponseResult encodeCollectorProjectedResponse(
	const CollectorProjectedJobInput &job, const CollectorProjectedResponse &response,
	CollectorProjectedResponseBytes	  &encoded,
	const CollectorProjectedHashProbe &probe = {}) noexcept ;

/** @brief 保存byteを独立CNGと全field関係へ照合します。縮退・修復しません。
 * @param[in] job 元固定scope。
 * @param[in] envelope 最大2 MiBの保存byte。
 * @param[out] decoded 成功時だけ元byteと所有値。入力envelopeとのaliasは禁止です。
 * @param[in] probe 読込み時のhash失敗専用診断。
 * @return 結果。元世代・intent・登録／履歴への再結合は保存監督の責任です。
 */
[[nodiscard]] CollectorProjectedResponseResult decodeCollectorProjectedResponse(
	const CollectorProjectedJobInput &job, std::string_view envelope,
	CollectorProjectedResponseBytes	  &decoded,
	const CollectorProjectedHashProbe &probe = {}) noexcept ;

/** @brief Live候補だけの一回有限縮退とhash故障分類を行います。
 * @param[in] job 元scope。
 * @param[in] response 親が最終化する候補。元I/Oは変更しません。
 * @param[out] encoded 成功時だけ保存前byte。入力responseとのaliasは禁止です。親の予約受入を実行しません。
 * @param[in] probe 元段階の負HRESULTのみ。
 * @return 失敗時は出力空。第一worker error／OOM／応答hash故障を置換しません。
 */
[[nodiscard]] CollectorProjectedResponseResult encodeCollectorProjectedResponseWithFallback(
	const CollectorProjectedJobInput &job, const CollectorProjectedResponse &response,
	CollectorProjectedResponseBytes	  &encoded,
	const CollectorProjectedHashProbe &probe = {}) noexcept ;
} // namespace drivercrate
