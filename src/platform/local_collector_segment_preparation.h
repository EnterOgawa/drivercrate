//------------------------------------------------------------------------------
/**
 * @file local_collector_segment_preparation.h
 * @brief 実同親根拠から非保存の切替draftを導出します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  実根拠由来の非保存準備を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/02  実HTTP所有閉鎖を保持する非保存入口を追加。
 * </pre>
 *
 * @note 旧入口の停止boolはcaller観測です。新入口は実HTTP所有閉鎖を保持しますが保存許可ではありません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "local_collector_http_activity.h"
#include "local_collector_segment_inventory.h"
#include "local_collector_segment_switch.h"
#include <Windows.h>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string_view>
#include <utility>

namespace drivercrate {
class LocalCollectorSegmentPreparation ;
/** @brief 実HTTP再発行停止と同じ呼出しの非保存draftを所有します。 */
class CollectorSegmentQuiescentSwitch final {
public:
	/** @brief Fresh閉鎖入口だけが使う非公開構築keyです。 */
	class ConstructionKey {
		friend class LocalCollectorSegmentPreparation ;
		/** @brief Caller観測や古い根拠からの構築を禁止します。 */
		ConstructionKey() = default ;
	} ;
	/** @brief 同じ呼出しの実所有閉鎖とdraftを保持します。
	 * @param[in] key 私有構築key。
	 * @param[in] freeze 元history writerの実所有0から取得した閉鎖。
	 * @param[in] prepared 同じ閉鎖中にfresh検査した根拠とdraft。
	 */
	CollectorSegmentQuiescentSwitch(
		ConstructionKey key, std::shared_ptr<const CollectorStoreHttpFreeze> freeze,
		std::shared_ptr<const class CollectorSegmentPreparedSwitch> prepared)
		: freeze_( std::move( freeze)), prepared_( std::move( prepared))
	{
		(void)key ;
	}
	/** @brief この閉鎖中にfresh取得した非保存draftを借用します。
	 * @return Contextと同じ寿命のconst参照。保存許可ではありません。
	 */
	[[nodiscard]] const CollectorSegmentSwitchDraft	  &draft() const noexcept ;
	/** @brief この閉鎖中の実同親根拠を借用します。
	 * @return Contextと同じ寿命のconst参照。Windows handle leaseではありません。
	 */
	[[nodiscard]] const CollectorSegmentRootInventory &root() const noexcept ;

private:
	/// 最後の参照まで新しいHTTP監督／permitの発行を拒否します。
	std::shared_ptr<const CollectorStoreHttpFreeze>				freeze_ ;
	/// 閉鎖保持中に最終全raw再照合した非保存値。
	std::shared_ptr<const class CollectorSegmentPreparedSwitch> prepared_ ;
} ;
/** @brief 同じ呼出しの実根拠と非保存draftだけを所有します。live leaseではありません。 */
class CollectorSegmentPreparedSwitch final {
public:
	/** @brief 準備入口だけが持つ非公開構築keyです。 */
	class ConstructionKey {
		friend class LocalCollectorSegmentPreparation ;
		/** @brief Caller hashや古い根拠からの発行を禁止します。 */
		ConstructionKey() = default ;
	} ;
	/** @brief 新しく検査した根拠とその全draftを所有します。
	 * @param[in] key 私有構築key。
	 * @param[in] root 同じ呼出しの実同親根拠。
	 * @param[in] draft 根拠へ全hashを結合した非保存値。
	 */
	CollectorSegmentPreparedSwitch( ConstructionKey										key,
								   std::shared_ptr<const CollectorSegmentRootInventory> root,
								   CollectorSegmentSwitchDraft							draft)
		: root_( std::move( root)), draft_( std::move( draft))
	{
		(void)key ;
	}
	/** @brief 準備時点の実同親根拠を借用します。
	 * @return Contextと同じ寿命のconst参照。後続のfresh検査ではありません。
	 */
	[[nodiscard]] const CollectorSegmentRootInventory &root() const noexcept
	{
		return *root_ ;
	}
	/** @brief 非保存draftの所有値を借用します。
	 * @return Contextと同じ寿命のconst参照。保存許可ではありません。
	 */
	[[nodiscard]] const CollectorSegmentSwitchDraft &draft() const noexcept
	{
		return draft_ ;
	}

private:
	/// 新しい呼出しで検査した元所有根拠です。
	std::shared_ptr<const CollectorSegmentRootInventory> root_ ;
	/// 元根拠の全hashを保持する非保存出力です。
	CollectorSegmentSwitchDraft							 draft_ ;
} ;
/** @brief 初回一区間の実readerと非保存draft coreを結合します。 */
class LocalCollectorSegmentPreparation final {
public:
	/** @brief Callerの停止boolを使わず実所有閉鎖中にfresh準備します。
	 * @param[in,out] collection 単一threadの実親writer。
	 * @param[in,out] segment 同親history lease。Contextを使用する間は解放しません。
	 * @param[in] sources 元履歴のsource契約。
	 * @param[in] newSegment 新しい完全小文字hash。診断前に複製します。
	 * @param[in] acceptedUtcMillis 元accepted UTC。元台帳は変更しません。
	 * @param[out] prepared 実HTTP再発行停止とfresh値の所有。失敗時は空です。
	 * @param[in] beforeFinalRecheck 全借用と閉鎖保持中の数値診断。
	 * @return 成功0、history能力87、所有／借用／旧freeze170、内容13、元error。
	 * @note 非保存です。旧出力内keyのaliasを保持し、旧閉鎖生存中の置換は170で拒否します。
	 */
	[[nodiscard]] static DWORD prepareQuiescent(
		LocalCollectorCollectionStore &collection, LocalCollectorSegmentLease &segment,
		std::span<const CollectorCampaignSource> sources, std::wstring_view newSegment,
		std::uint64_t											acceptedUtcMillis,
		std::shared_ptr<const CollectorSegmentQuiescentSwitch> &prepared,
		const std::function<DWORD()>						   &beforeFinalRecheck = {}) noexcept ;
	/** @brief Caller hashを受け取らず、fresh根拠から全切替draftを作ります。
	 * @param[in,out] collection 単一thread限定の実親writer。
	 * @param[in,out] segment 同親の唯一history付きlease。呼出し中は解放しません。
	 * @param[in] sources 元履歴のsource契約。1～20件です。
	 * @param[in] newSegment 新しい完全小文字hash。呼出し開始時に複製します。
	 * @param[in] acceptedUtcMillis 元accepted UTC。元台帳や待機の時刻を変更しません。
	 * @param[in] workersJoinedObservation Callerの停止観測。falseは13、trueもjoin証明ではありません。
	 * @param[out] prepared 全成立後だけのimmutable準備。失敗時は空です。旧所有値は同期呼出し中だけ保持します。
	 * @param[in] beforeFinalRecheck 元readerの数値診断。全借用中だけ実行します。
	 * @return 成功0、拒否13、容量68、能力87、再入170、元I/O／CNG／確保error。
	 * @note 初回区間限定です。実保存はfresh検査と実worker所有停止の別入口を必要とします。
	 */
	[[nodiscard]] static DWORD prepare(
		LocalCollectorCollectionStore &collection, LocalCollectorSegmentLease &segment,
		std::span<const CollectorCampaignSource> sources, std::wstring_view newSegment,
		std::uint64_t acceptedUtcMillis, bool workersJoinedObservation,
		std::shared_ptr<const CollectorSegmentPreparedSwitch> &prepared,
		const std::function<DWORD()>						  &beforeFinalRecheck = {}) noexcept ;
} ;
} // namespace drivercrate
