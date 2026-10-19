//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_cache.h
 * @brief 成功履歴と最新試行を分ける有限CACHE値を定義します。
 * @version 01.02.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  CACHE値と非保存更新を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/29  親の非保存応答・CACHE結合結果を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/30  登録履歴の変更不能な読取りcontextを追加。
 * </pre>
 *
 * @note CACHE値単独は登録・参照先実在を証明しません。専用contextも送信許可ではありません。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/local_collector_projected_response.h"
#include <utility>

namespace drivercrate {
/** @brief 同じ親照合で作る応答とCACHE候補です。保存・登録済み証明ではありません。 */
struct CollectorProjectedPreparedUpdate {
	/// 元v4と独立読戻し後の値。
	CollectorProjectedResponseBytes response ;
	/// 同じ応答から導出した最大24 KiBのCACHE本文。
	std::string						cache ;
	/// CACHE本文の実SHA-256。送信許可ではありません。
	std::wstring					cacheSha256 ;
} ;
/** @brief 再利用の可否と区別する固定更新理由です。 */
enum class CollectorCacheReason {
	/// 完全200と観測済みtag。
	ACCEPTED,
	/// 完全200ですがtagは未観測。
	NO_VALIDATOR,
	/// 採用可能な部分結果だけ更新。
	PARTIAL,
	/// 今回一致なし。
	NO_CURRENT_MATCH,
	/// 元成功から減少。
	DECREASED,
	/// 射影上限で停止。
	PROJECTION_LIMIT,
	/// Worker失敗。
	WORKER_FAILURE,
	/// 元200根拠不成立。
	CACHE_BASIS_INVALID,
	/// Metadata hash失敗。
	METADATA_HASH,
	/// 元応答が中断。
	INTERRUPTED
} ;
/** @brief 最新試行の直接参照です。 */
struct CollectorCacheAttempt {
	/// 元generation。
	std::wstring generation ;
	/// 元操作hash。
	std::wstring operation ;
	/// 元応答本文hash。
	std::wstring response ;
} ;
/** @brief Sliceごとの最後の成功参照です。 */
struct CollectorCacheSlice {
	/// 元generation。
	std::wstring generation ;
	/// 元操作hash。
	std::wstring operation ;
	/// 元応答hash。
	std::wstring response ;
	/// 元metadata hash。
	std::wstring projection ;
	/// 重複を許さないslice key。
	std::wstring slice ;
} ;
/** @brief 実header時刻を持つ検証参照です。 */
struct CollectorCacheValidation {
	/// 元generation。
	std::wstring  generation ;
	/// 元操作hash。
	std::wstring  operation ;
	/// 元応答hash。
	std::wstring  response ;
	/// 元metadata hash。
	std::wstring  projection ;
	/// 元header UTC。現在時刻へ延長しません。
	std::uint64_t headerUtc{} ;
} ;
/** @brief 最大16成功sliceの所有値です。旧binding参照も履歴として保持します。 */
struct CollectorProjectedCache {
	/// 元要求key。
	std::wstring								 request ;
	/// 最新試行のbinding。過去参照のbindingを意味しません。
	std::wstring								 binding ;
	/// 成否にかかわらず最新試行。
	CollectorCacheAttempt						 attempt ;
	/// 最後の完全成功200。
	std::optional<CollectorProjectedOriginal200> original200 ;
	/// 順序を維持する最後の成功群。
	std::vector<CollectorCacheSlice>			 slices ;
	/// 最後の完全成功の検証参照。
	std::optional<CollectorCacheValidation>		 validated ;
	/// 構造上の再利用候補。送信許可ではありません。
	bool										 reusable{} ;
	/// 最新試行から決める理由。
	CollectorCacheReason						 reason{CollectorCacheReason::INTERRUPTED} ;
	/// 観測済みtag。非再利用形ではnull。
	std::optional<std::wstring>					 etag ;
} ;

class LocalCollectorRecovery ;
/** @brief 保護storeの登録と更新履歴を検査して所有する開発用contextです。送信許可ではありません。 */
class CollectorRegisteredProjectedHistory final {
public:
	/** @brief 保存監督だけが作れる構築keyです。 */
	class ConstructionKey {
		friend class LocalCollectorRecovery ;
		/** @brief 任意callerによる履歴context生成を禁止します。 */
		ConstructionKey() = default ;
	} ;
	/** @brief 全保存根拠の検査後だけ値を所有します。
	 * @param[in] key 保存監督だけが作る構築key。
	 * @param[in] cache 検証した最新CACHE。
	 * @param[in] slices 全保存根拠と結合した成功slice。
	 * @param[in] rootHash 元root本文のSHA-256。
	 * @param[in] cacheHash 登録済みCACHE本文のSHA-256。
	 * @param[in] operations 再計算した操作数。最大300。
	 */
	CollectorRegisteredProjectedHistory( ConstructionKey key, CollectorProjectedCache cache,
										std::vector<CollectorProjectedHistoryEvidence> slices,
										std::wstring rootHash, std::wstring cacheHash,
										std::size_t operations)
		: cache_( std::move( cache)), slices_( std::move( slices)), rootHash_( std::move( rootHash)),
		  cacheHash_( std::move( cacheHash)), operations_( operations)
	{
		(void)key ;
	}
	/** @brief 登録と更新後像を照合した最新値を借用します。
	 * @return Contextと同じ寿命のconst参照。
	 */
	[[nodiscard]] const CollectorProjectedCache &cache() const noexcept
	{
		return cache_ ;
	}
	/** @brief 全参照検証済みの成功sliceを借用します。
	 * @return 最大16件、contextと同じ寿命のconst参照。
	 */
	[[nodiscard]] const std::vector<CollectorProjectedHistoryEvidence> &slices() const noexcept
	{
		return slices_ ;
	}
	/** @brief 検査したroot本文hashを返します。
	 * @return Contextと同じ寿命のconst参照。
	 */
	[[nodiscard]] const std::wstring &rootHash() const noexcept
	{
		return rootHash_ ;
	}
	/** @brief 最新CACHEの登録hashを返します。
	 * @return Contextと同じ寿命のconst参照。
	 */
	[[nodiscard]] const std::wstring &cacheHash() const noexcept
	{
		return cacheHash_ ;
	}
	/** @brief 更新前後を再計算した操作数を返します。
	 * @return 1～300。
	 */
	[[nodiscard]] std::size_t operations() const noexcept
	{
		return operations_ ;
	}

private:
	/// 登録済み最新値。公開の再利用flagは送信許可ではありません。
	CollectorProjectedCache						   cache_ ;
	/// 元入力・開始intent・元応答を所有する成功slice集合。
	std::vector<CollectorProjectedHistoryEvidence> slices_ ;
	/// 読取り時のroot本文hash。
	std::wstring								   rootHash_ ;
	/// Root登録と一致したCACHE本文hash。
	std::wstring								   cacheHash_ ;
	/// 有限な検証閉包の操作数。
	std::size_t									   operations_{} ;
} ;

/** @brief 固定順・最大24 KiBのCACHE本文を作ります。保存はしません。
 * @param[in] cache 構造と相互参照を検査する公開値。
 * @param[out] body 成功時の本文、失敗時は空。
 * @return 固定分類と元OOM数値。
 */
[[nodiscard]] collector_projected_json::Result encodeCollectorProjectedCache(
	const CollectorProjectedCache &cache, std::string &body) noexcept ;
/** @brief 有限canonical本文を読み、全fieldと参照関係を検査します。
 * @param[in] body 元CACHE本文。外側envelope hashは保存層の責任です。
 * @param[out] cache 成功時の値、失敗時は空。
 * @return 固定分類。登録・元応答の実在は証明しません。
 */
[[nodiscard]] collector_projected_json::Result decodeCollectorProjectedCache(
	std::string_view body, CollectorProjectedCache &cache) noexcept ;
/** @brief 元v4を独立検証し、成功参照を保持した次CACHE値を導出します。
 * @param[in] job 今回の元scope。
 * @param[in] envelope 今回の元応答。減少は親で最終化済みであること。
 * @param[in] before 過去値またはnull。登録と全履歴の再検証は親が行います。
 * @param[out] after 成功時の値、失敗時は空。全入力とのaliasは禁止です。
 * @param[in] probe 下位hashの失敗専用診断。
 * @return 原hash HRESULT／OOMを保持する結果。REVALIDATEDは拒否します。
 */
[[nodiscard]] collector_projected_json::Result deriveCollectorProjectedCache(
	const CollectorProjectedJobInput &job, std::string_view envelope,
	const CollectorProjectedCache *before, CollectorProjectedCache &after,
	const CollectorProjectedHashProbe &probe = {}) noexcept ;
/** @brief 中断時に過去成功を保持し、validatorだけを解除します。
 * @param[in] request 同じrequest key。
 * @param[in] binding 今回binding。
 * @param[in] attempt 保存監督が元中断応答から導いた直接参照。
 * @param[in] before 過去値または初回のnull。
 * @param[out] after 成功時の値、失敗時は空。全入力とのaliasは禁止です。
 * @return 構造検査結果。元応答や登録の証明は監督の責任です。
 */
[[nodiscard]] collector_projected_json::Result makeInterruptedCollectorCache(
	std::wstring_view request, std::wstring_view binding, const CollectorCacheAttempt &attempt,
	const CollectorProjectedCache *before, CollectorProjectedCache &after) noexcept ;
} // namespace drivercrate
