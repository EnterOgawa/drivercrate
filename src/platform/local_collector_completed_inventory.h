//------------------------------------------------------------------------------
/**
 * @file local_collector_completed_inventory.h
 * @brief 全完了v3 rootの保護raw由来の読取り封印contextを定義します。
 * @version 01.01.00
 * @date 2026/10/02
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  全履歴／全raw再照合後だけ発行するcontextを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/02  同じraw由来の共有値と検証済みCACHE参照を保持。
 * </pre>
 *
 * @note 新区間seal、switch保存、取得、導入の許可ではありません。
 */
//------------------------------------------------------------------------------
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace drivercrate {
/** @brief Semantic検査済みの一つの保護raw identityです。 */
struct CollectorCompletedInventoryFile {
	/// current／runsの固定相対名。caller入力pathではありません。
	std::wstring  name ;
	/// 外側envelopeを含む元rawのSHA-256。
	std::wstring  sha256 ;
	/// 元保護handleから読み取ったbyte数。
	std::uint64_t bytes{} ;
} ;
/** @brief 最大512行を元順序で結合する一shardです。 */
struct CollectorCompletedInventoryShard {
	/// 有限canonical inventory本文。
	std::string	 body ;
	/// 本文の完全SHA-256。
	std::wstring sha256 ;
} ;
/** @brief 登録本文と元200閉包の両方を検査した現区間CACHE参照です。 */
struct CollectorCompletedCacheReference {
	/// ROOT登録の完全request hash。
	std::wstring request ;
	/// 登録と一致した最新CACHE本文のSHA-256。raw hashではありません。
	std::wstring cacheSha256 ;
	/// 元200／操作閉包から検査した最新binding。
	std::wstring binding ;
} ;
/** @brief 全検査から導出する値です。単体DTOは保存権限／検査証明ではありません。 */
struct CollectorCompletedRootEvidence {
	/// 元ROOT本文のSHA-256。
	std::wstring								  rootSha256 ;
	/// 元ROOTの保存identity。
	std::wstring								  rootKey ;
	/// 検査した元ROOT最高UTC。検査時計とは別です。
	std::uint64_t								  rootUtcMillis{} ;
	/// 同じ検査で使用した元予算canonical本文。
	std::string									  budgetBody ;
	/// 同じ検査で使用した元control canonical本文。
	std::string									  controlBody ;
	/// ROOT登録順の元CACHE由来。単体DTOは成功証明ではありません。
	std::vector<CollectorCompletedCacheReference> caches ;
	/// 検査UTC。元履歴の時計／期限を変更しません。
	std::uint64_t								  inspectedUtcMillis{} ;
	/// 重複しない全保存rawの合計。再読取り課金とは別です。
	std::uint64_t								  fileBytes{} ;
	/// 元登録の全完了世代数。
	std::size_t									  generations{} ;
	/// 閉包再検査済み操作数。
	std::size_t									  operations{} ;
	/// current、runsの順で固定した全存在file。
	std::vector<CollectorCompletedInventoryFile>  files ;
	/// 最大16個のordinal順shard。
	std::vector<CollectorCompletedInventoryShard> shards ;
	/// 全shard／ROOT／source／共有予算／controlの封印本文。
	std::string									  seal ;
	/// 封印本文のSHA-256。
	std::wstring								  sealSha256 ;
} ;
class LocalCollectorRecovery ;
/** @brief 完了根拠を全raw再照合後に所有するimmutable contextです。live leaseではありません。 */
class CollectorCompletedRootInventory final {
public:
	/** @brief 保存監督だけが生成できる構築keyです。 */
	class ConstructionKey {
		friend class LocalCollectorRecovery ;
		/** @brief Caller hash／JSONによる偽造を禁止します。 */
		ConstructionKey() = default ;
	} ;
	/** @brief 全検査後だけ元根拠を所有します。
	 * @param[in] key 保存監督だけのkey。
	 * @param[in] evidence 同じ呼出しで全raw再照合済みの所有値。
	 */
	CollectorCompletedRootInventory( ConstructionKey key, CollectorCompletedRootEvidence evidence)
		: evidence_( std::move( evidence))
	{
		(void)key ;
	}
	/** @brief 検査時点のimmutable根拠を借用します。
	 * @return Contextと同じ寿命のconst参照。後続保存時のfresh検査を代行しません。
	 */
	[[nodiscard]] const CollectorCompletedRootEvidence &evidence() const noexcept
	{
		return evidence_ ;
	}

private:
	/// Contextの所有値。公開getterから変更できません。
	CollectorCompletedRootEvidence evidence_ ;
} ;
}
