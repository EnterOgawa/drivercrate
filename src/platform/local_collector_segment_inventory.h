//------------------------------------------------------------------------------
/**
 * @file local_collector_segment_inventory.h
 * @brief 同親の現区間共有値と完了履歴を結合した読取り根拠を定義します。
 * @version 01.01.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  同時借用の一致検査後だけ区間根拠を発行。
 * Ver.01.01.00 Shunji Ogawa  2026/10/03  保護実handleの初回切替回復と検査を追加。
 * Ver.01.01.01 Shunji Ogawa  2026/10/03  ROOT未保存の連続準備prefix回復と検査を追加。
 * </pre>
 *
 * @note 読取り時点の整合性記録です。保存・切替・通信・導入許可ではありません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "local_collector_campaign.h"
#include "local_collector_collection_store.h"
#include "local_collector_completed_inventory.h"
#include "local_collector_shared_inventory.h"
#include <functional>
#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace drivercrate {
struct CollectorSegmentRecoveryState ;
/** @brief 両readerが検査した一rawのscope付きidentityです。 */
struct CollectorSegmentInventoryFile {
	/// parent／segment／historyだけの導出済みscope。
	std::wstring  scope ;
	/// 元readerの固定current／runs相対名。
	std::wstring  name ;
	/// 元envelopeを含むraw SHA-256。
	std::wstring  sha256 ;
	/// 元handleで確認したraw byte数。
	std::uint64_t bytes{} ;
} ;
/** @brief 同じ呼出しの全再検査に結合する値です。単体DTOは証明ではありません。 */
struct CollectorSegmentRootEvidence {
	/// 同じhistory leaseの全完了根拠。各raw名のscopeはhistoryです。
	std::shared_ptr<const CollectorCompletedRootInventory> history ;
	/// 同じ親／子の共有根拠。各rawは元parent／segment scopeを保持します。
	std::shared_ptr<const CollectorSharedRootInventory>	   shared ;
	/// 親／子共有、historyの元順序で結合した8192行以内の全raw集合。
	std::vector<CollectorSegmentInventoryFile>			   files ;
	/// scope別に同名を保持した全raw byte数。
	std::uint64_t										   fileBytes{} ;
	/// 最大512行ずつ16個以内のordinal順区間inventory本文とhash。
	std::vector<CollectorCompletedInventoryShard>		   shards ;
	/// 両根拠の完全hashと一致検査を閉じる16 KiB以内の本文。
	std::string											   seal ;
	/// seal本文のSHA-256。配布署名ではありません。
	std::wstring										   sealSha256 ;
} ;
class LocalCollectorSegmentInventory ;
/** @brief 同じ保護leaseの一致と最終再照合後だけ作るimmutable根拠です。 */
class CollectorSegmentRootInventory final {
public:
	/** @brief 結合監督だけが持つ非公開構築能力です。 */
	class ConstructionKey {
		friend class LocalCollectorSegmentInventory ;
		/** @brief CallerのDTO／hashからの発行を禁止します。 */
		ConstructionKey() = default ;
	} ;
	/** @brief 結合検査後の二根拠とsealを所有します。
	 * @param[in] key 結合監督だけの構築能力。
	 * @param[in] evidence 全raw再照合済みの同一呼出しの値。
	 */
	CollectorSegmentRootInventory( ConstructionKey key, CollectorSegmentRootEvidence evidence)
		: evidence_( std::move( evidence))
	{
		(void)key ;
	}
	/** @brief 検査時点の所有値を借用します。
	 * @return Contextと同寿命のconst参照。後続保存のfresh検査ではありません。
	 */
	[[nodiscard]] const CollectorSegmentRootEvidence &evidence() const noexcept
	{
		return evidence_ ;
	}

private:
	/// 変更能力やlive leaseを持たない所有根拠です。
	CollectorSegmentRootEvidence evidence_ ;
} ;
/** @brief 現区間の実保護readerだけを結合する非通信監督です。 */
class LocalCollectorSegmentInventory final {
public:
	/** @brief 同親履歴の共有全値／CACHE由来と全rawを非変更で検査します。
	 * @param[in,out] collection 単一thread限定の親writer。
	 * @param[in,out] segment 同じ親の唯一history付きlease。呼出し中は破棄しません。
	 * @param[in] sources 元履歴のsource契約。1～20件です。
	 * @param[in] utcMillis 元最高UTC以上の検査時計。保存時計は変更しません。
	 * @param[out] inventory 全検査後だけの所有根拠。失敗時は空です。
	 * @param[in] beforeFinalRecheck 両借用中の数値停止／fixture改変診断。通常は空です。
	 * @return 成功0、内容13、容量68、能力87、再入170、各readerの元I/O／CNG／確保error。
	 * @note 旧区間CACHE参照を拒否します。実worker join／switch／CLIへは未接続です。
	 */
	[[nodiscard]] static DWORD inspect(
		LocalCollectorCollectionStore &collection, LocalCollectorSegmentLease &segment,
		std::span<const CollectorCampaignSource> sources, std::uint64_t utcMillis,
		std::shared_ptr<const CollectorSegmentRootInventory> &inventory,
		const std::function<DWORD()>						 &beforeFinalRecheck = {}) noexcept ;

private:
	friend class LocalCollectorSegmentStorage ;
	/** @brief 保護回復holdの実旧履歴と元head投影を同時検査します。
	 * @param[in] stores 私有holdの親／旧子／旧historyです。
	 * @param[in] state 実intent／headまたは同handle由来の内部codec候補です。単体は能力ではありません。
	 * @param[in] sources 元履歴のsource契約です。
	 * @param[out] inventory 全再照合と元seal一致後だけの根拠です。
	 * @param[in] beforeFinalRecheck 両借用中だけの非通信診断です。
	 * @return 第一数値結果です。
	 */
	[[nodiscard]] static DWORD inspectRecovery(
		const std::array<LocalCollectorStateStore *, 3U>	 &stores,
		const CollectorSegmentRecoveryState					 &state,
		std::span<const CollectorCampaignSource>			  sources,
		std::shared_ptr<const CollectorSegmentRootInventory> &inventory,
		const std::function<DWORD()>						 &beforeFinalRecheck) noexcept ;
} ;
} // namespace drivercrate
