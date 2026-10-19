//------------------------------------------------------------------------------
/**
 * @file local_collector_shared_store.h
 * @brief 親headに結合した初回66本文の実保存と読戻しを定義します。
 * @version 01.06.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  初回共有保存・固定prefix回復を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/02  元予約精算の区間commitと読戻しを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/02  予約・日次・CACHE参照の共通commitを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/02  同親leaseの読取り共有根拠入口を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/02  history付き専用leaseの共有marker照合に対応。
 * Ver.01.05.00 Shunji Ogawa  2026/10/02  同親履歴との私有結合再検査を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/03  保護実handleの初回切替回復と検査を追加。
 * </pre>
 *
 * @note 開発用の四型保存と共有根拠です。区間switch・ROOT／CACHE内容・通信は未接続です。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "local_collector_collection_store.h"
#include "local_collector_shared_ledger.h"
#include "local_collector_shared_update.h"
#include "local_collector_shared_operation.h"
#include "local_collector_shared_inventory.h"
#include <cstddef>
#include <functional>

namespace drivercrate {
struct CollectorSegmentSwitchDraft ;
/** @brief 実atomic置換の直後だけ数値停止を返す非通信診断です。
 * @note 引数は呼出し入口の元保存ordinalです。成功状態・本文・hashを注入しません。
 */
using CollectorSharedCheckpoint = std::function<DWORD( std::size_t)> ;

/** @brief 同じ親／子能力で初回と四型の元操作の保存・再検査を行います。 */
class LocalCollectorSharedStore final {
public:
	/** @brief 同親のready head／全像／閉鎖操作と全rawを読み取り専用に検査します。
	 * @param[in,out] collection 親writer。単一threadで使用します。
	 * @param[in,out] segment 同じ親の唯一子lease。呼出し中は破棄しません。
	 * @param[in] utcMillis 元最高UTC以上の検査時計。保存時計を更新しません。
	 * @param[out] inventory 最終再照合後だけの根拠。失敗時は空です。
	 * @param[in] beforeFinalRecheck 数値停止だけの任意非通信診断。
	 * @return 成功0、拒否13、容量68、別能力87、再入170、確保8、第一I/O／CNG code。
	 * @note CACHE内容／ROOT／実worker join／switch許可を発行せず、保存もしません。
	 */
	[[nodiscard]] static DWORD inspectSharedRootInventory(
		LocalCollectorCollectionStore &collection, LocalCollectorSegmentLease &segment,
		std::uint64_t utcMillis, std::shared_ptr<const CollectorSharedRootInventory> &inventory,
		const std::function<DWORD()> &beforeFinalRecheck = {}) noexcept ;
	/** @brief 元snapshotから初回保存または同じintentの不足suffixを反映します。
	 * @param[in,out] collection 親writer。呼出し中は変更・破棄しないでください。
	 * @param[in,out] segment 同じ親の唯一の子lease。呼出し中は解放しないでください。
	 * @param[in] snapshot 元初回値。再開では全値が完全一致する必要があります。
	 * @param[in] checkpoint 各実保存直後の任意停止診断。0なら継続します。
	 * @return 成功0、拒否13、能力不一致87、再入170、容量68、確保失敗8、第一I/O／CNG code。
	 * @note 単一thread限定。成功でもseal由来・予約・取得許可を発行しません。
	 */
	[[nodiscard]] static DWORD bootstrap( LocalCollectorCollectionStore		 &collection,
										 LocalCollectorSegmentLease			 &segment,
										 const CollectorSharedLedgerSnapshot &snapshot,
										 const CollectorSharedCheckpoint &checkpoint = {}) noexcept ;

	/** @brief Ready headと全原像／区間操作／現在値を再検査して値を読み戻します。
	 * @param[in,out] collection 親writer。更新・通信は行いません。
	 * @param[in,out] segment 同じ親の唯一の子lease。
	 * @param[out] snapshot 全検査後だけの元値。失敗時は空です。入力とのaliasは禁止です。
	 * @return 成功0、未完了／改変13、能力不一致87、再入170、容量68、確保失敗8、第一I/O／CNG code。
	 * @note 更新headでは元操作を全再導出します。保存・時刻補完・未登録prefixの自律回復は行いません。
	 */
	[[nodiscard]] static DWORD load( LocalCollectorCollectionStore &collection,
									LocalCollectorSegmentLease	  &segment,
									CollectorSharedLedgerSnapshot &snapshot) noexcept ;
	/** @brief 元予約精算を区間へ先行保存し一つの親commitで現在値へ反映します。
	 * @param[in,out] collection 親writer。呼出し中は変更・破棄しないでください。
	 * @param[in,out] segment 同じ親の唯一子lease。呼出し中は解放しないでください。
	 * @param[in] operation 元受領／明示中断。再開では全値を変更しません。
	 * @param[in] checkpoint 実保存直後の任意停止診断。元ordinalは1～変更role数＋3です。
	 * @return 成功0、拒否13、能力不一致87、再入170、容量68、確保失敗8、第一I/O／CNG code。
	 * @note 元snapshotは保存履歴から再導出します。公式応答・新規予約・HTTP・CACHE更新ではありません。
	 */
	[[nodiscard]] static DWORD settle( LocalCollectorCollectionStore	  &collection,
									  LocalCollectorSegmentLease	  &segment,
									  const CollectorSharedSettlement &operation,
									  const CollectorSharedCheckpoint &checkpoint = {}) noexcept ;
	/** @brief 四型の元操作を同じ区間commitで保存・再導出します。
	 * @param[in,out] collection 親writer。呼出し中は変更・破棄しません。
	 * @param[in,out] segment 同じ親の唯一子lease。
	 * @param[in] operation 元予約・日次・未検証参照または精算。
	 * @param[in] checkpoint 実保存直後の元ordinal診断。
	 * @return 成功0、拒否13、待機1237、容量68、能力87、再入170、確保8、第一I/O／CNG code。
	 * @note 保存成功は実dispatch許可・CACHE本文検査済み証明ではありません。
	 */
	[[nodiscard]] static DWORD commit( LocalCollectorCollectionStore	  &collection,
									  LocalCollectorSegmentLease	  &segment,
									  const CollectorSharedOperation  &operation,
									  const CollectorSharedCheckpoint &checkpoint = {}) noexcept ;

private:
	friend class LocalCollectorSegmentInventory ;
	/** @brief 保護二子回復監督だけへ元head投影と共有全操作再導出を提供します。
	 * @param[in,out] parent 私有同親handleです。
	 * @param[in,out] child 同じholdの旧子です。
	 * @param[in] draft 実回復byteから検査した元intentです。
	 * @param[in] oldHeadRaw 実親または同intent記録から得た元headです。
	 * @param[out] inventory 全実rawと物理headの最終照合後だけの根拠です。
	 * @param[in] beforeFinalRecheck 同時履歴の照合と非通信診断です。
	 * @param[in] afterFinalRecheck 両借用中の履歴最終再検査です。
	 * @return 第一I/O／CNG／容量／内容結果です。
	 * @note 元headを書き戻しません。追加role本文は発行前に別途完全照合が必要です。
	 */
	[[nodiscard]] static DWORD inspectRecoveryRootInventoryBound(
		LocalCollectorStateStore &parent, LocalCollectorStateStore &child,
		const CollectorSegmentSwitchDraft &draft, std::string_view oldHeadRaw,
		std::shared_ptr<const CollectorSharedRootInventory>				&inventory,
		const std::function<DWORD( const CollectorSharedRootEvidence &)> &beforeFinalRecheck,
		const std::function<DWORD()> &afterFinalRecheck) noexcept ;

	/** @brief 同親結合監督だけが借用中に相手readerを最終再検査します。
	 * @param[in,out] collection 元親writer。
	 * @param[in,out] segment 同じ親の唯一子lease。
	 * @param[in] utcMillis 検査UTC。
	 * @param[out] inventory 全検査後だけの所有根拠。失敗時は空。
	 * @param[in] beforeFinalRecheck 未公開実根拠の照合と数値診断。寿命はこの呼出しだけです。
	 * @param[in] afterFinalRecheck 共有検査後、両借用中の履歴再検査。成功値を注入しません。
	 * @return 元共有readerと相手再検査の第一error。
	 */
	[[nodiscard]] static DWORD inspectSharedRootInventoryBound(
		LocalCollectorCollectionStore &collection, LocalCollectorSegmentLease &segment,
		std::uint64_t utcMillis, std::shared_ptr<const CollectorSharedRootInventory> &inventory,
		const std::function<DWORD( const CollectorSharedRootEvidence &)> &beforeFinalRecheck,
		const std::function<DWORD()> &afterFinalRecheck) noexcept ;
} ;
} // namespace drivercrate
