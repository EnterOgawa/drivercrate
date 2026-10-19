//------------------------------------------------------------------------------
/**
 * @file local_collector_segment_storage.h
 * @brief 同親handle保持・保存先払いと切替準備の実保存を定義します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  同親保持と固定保存roleの容量先払いを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/02  同一holdの切替準備実保存と不足分再開を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/02  私有新子と元66像／base／bootstrap保存を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/02  保存済み全像のcarryと専用初期ROOT保存を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/02  元head保持記録と親head実保存を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/03  保護実handleの初回切替回復と検査を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/03  ROOT未保存の連続準備prefix回復と検査を追加。
 * </pre>
 *
 * @note 初回ROOT保存済み切替の回復は親head保存だけへ接続します。通常収集は未接続です。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "local_collector_collection_store.h"
#include "local_collector_campaign.h"
#include "local_collector_segment_preparation.h"
#include "local_collector_http_activity.h"
#include <Windows.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
namespace drivercrate {
/** @brief 保存roleの固定三scopeです。任意path指定ではありません。 */
enum class CollectorSegmentStorageScope {
	/// 恒久collection親です。
	PARENT,
	/// 完了済み旧子です。history本文は変更しません。
	OLD_SEGMENT,
	/// 未作成新子です。history初期ROOTは別工程です。
	NEW_SEGMENT
} ;
/** @brief 元切替identityから導出する一保存予定です。DTO単体は保存許可ではありません。 */
struct CollectorSegmentStorageRole {
	/// 同じ親に限定する固定scopeです。
	CollectorSegmentStorageScope scope{} ;
	/// 固定roleと元hashから導出するcurrent／runs相対名です。
	std::wstring				 name ;
	/// 既存shared envelopeです。markerだけは元canonical byteです。
	std::string					 raw ;
} ;
/** @brief 一storeに独立適用する保守的な追加容量です。 */
struct CollectorSegmentStorageCost {
	/// 置換旧byteを引かない全保存byteです。
	std::uint64_t bytes{} ;
	/// 最大一保存のstaging実byteです。
	std::uint64_t stagingBytes{} ;
	/// currentの重複なし予定名数です。既存名も減算しません。
	std::size_t	  currentNames{} ;
	/// runsの重複なし予定名数です。
	std::size_t	  runNames{} ;
} ;
/** @brief 全保存byteと一stagingを三storeへ独立先払いします。
 * @param[in] usage 親／旧子／新子のusage。DTO単体は実handle根拠ではありません。
 * @param[in] roles 最大90予定。headの二回保存はbyteだけ重複計数します。
 * @param[out] cost 成功時だけの三scope容量。失敗時は空です。aliasは禁止です。
 * @return 成功0、形式13、容量68、確保8。
 * @note 一storeの5 GiB／directoryの4096entry／一rawの2 MiBを拡張しません。
 */
[[nodiscard]] DWORD checkCollectorSegmentStorageCapacity(
	const std::array<CollectorStoreUsage, 3U>	&usage,
	std::span<const CollectorSegmentStorageRole> roles,
	std::array<CollectorSegmentStorageCost, 3U> &cost) noexcept ;
class LocalCollectorSegmentStorage ;
/** @brief 同親handle・HTTP閉鎖と実freshまたは回復検査の固定roleを所有する非保存予約です。
 * @note 最後の参照解放も元監督threadで行ってください。mutable storeは公開しません。
 */
class CollectorSegmentStorageReservation final {
public:
	/** @brief 実fresh／回復入口だけに構築を限定する私有keyです。 */
	class ConstructionKey {
		friend class LocalCollectorSegmentStorage ;
		/** @brief Caller DTOや古い準備値からの発行を禁止します。 */
		ConstructionKey() = default ;
	} ;
	/** @brief 同じ呼出しの保持・fresh準備と固定roleを所有します。
	 * @param[in] key 私有構築key。
	 * @param[in] hold 元親／旧子／historyの強所有です。
	 * @param[in] prepared 同じHTTP閉鎖中のfresh根拠です。
	 * @param[in] roles 先払い済み固定保存roleです。
	 * @param[in] cost 同じroleの三scope容量です。
	 */
	CollectorSegmentStorageReservation(
		ConstructionKey key, std::shared_ptr<const CollectorCollectionSwitchHold> hold,
		std::shared_ptr<const CollectorSegmentQuiescentSwitch> prepared,
		std::vector<CollectorSegmentStorageRole>			   roles,
		std::array<CollectorSegmentStorageCost, 3U>			   cost)
		: hold_( std::move( hold)), prepared_( std::move( prepared)), roles_( std::move( roles)),
		  cost_( cost)
	{
		(void)key ;
	}
	/** @brief 実回復readerと全role照合だけから回復予約を所有します。
	 * @param[in] key 私有回復発行keyです。
	 * @param[in] hold 非作成で開いた実旧子、存在する新子と親の強所有です。
	 * @param[in] freeze 実旧historyのHTTP所有0からの閉鎖です。
	 * @param[in] root 旧head投影と全履歴から再導出した元根拠です。
	 * @param[in] draft 同じ根拠と全66像から再導出した元draftです。
	 * @param[in] roles 全実byteと一致した固定予定です。
	 * @param[in] preparation ROOT未保存の全prefix再検査からだけ発行する場合trueです。
	 */
	CollectorSegmentStorageReservation( ConstructionKey										key,
									   std::shared_ptr<const CollectorCollectionSwitchHold> hold,
									   std::shared_ptr<const CollectorStoreHttpFreeze>		freeze,
									   std::shared_ptr<const CollectorSegmentRootInventory> root,
									   CollectorSegmentSwitchDraft							draft,
									   std::vector<CollectorSegmentStorageRole>				roles,
									   bool preparation = false)
		: hold_( std::move( hold)), recoveredRoot_( std::move( root)),
		  recoveredDraft_( std::move( draft)), recoveryFreeze_( std::move( freeze)),
		  recoveryPreparation_( preparation), roles_( std::move( roles))
	{
		(void)key ;
	}
	/** @brief 非保存固定roleを寿命限定で借用します。
	 * @return この予約と同じ寿命のconst span。mutable storeは渡しません。
	 */
	[[nodiscard]] std::span<const CollectorSegmentStorageRole> roles() const noexcept
	{
		return roles_ ;
	}
	/** @brief 独立先払いした三scope容量を借用します。
	 * @return Fresh予約の全予定容量です。回復予約は空値で、保存直前に不足suffixを再先払いします。
	 */
	[[nodiscard]] const std::array<CollectorSegmentStorageCost, 3U> &cost() const noexcept
	{
		return cost_ ;
	}
	/** @brief 同じ実freshまたは回復検査の非保存draftを借用します。
	 * @return この予約と同じ寿命のconst参照。保存許可ではありません。
	 */
	[[nodiscard]] const CollectorSegmentSwitchDraft &draft() const noexcept
	{
		return recoveredRoot_ ? recoveredDraft_ : prepared_->draft() ;
	}

private:
	friend class LocalCollectorSegmentStorage ;
	/// HTTP閉鎖を返すより後に元history／旧子／親handleを解放します。
	std::shared_ptr<const CollectorCollectionSwitchHold>   hold_ ;
	/// 同じfresh検査の閉鎖です。回復予約では空で、単独の旧contextを受け取りません。
	std::shared_ptr<const CollectorSegmentQuiescentSwitch> prepared_ ;
	/** @brief 元freshまたは実回復検査の根拠を借用します。
	 * @return 予約と同寿命の元全raw根拠です。
	 */
	[[nodiscard]] const CollectorSegmentRootEvidence	  &evidence() const noexcept
	{
		return recoveredRoot_ ? recoveredRoot_->evidence() : prepared_->root().evidence() ;
	}
	/// 実回復readerの全旧raw根拠です。Fresh予約では空です。
	std::shared_ptr<const CollectorSegmentRootInventory> recoveredRoot_ ;
	/// 実回復根拠から再導出したdraftです。Fresh prepared値を偽造しません。
	CollectorSegmentSwitchDraft							 recoveredDraft_ ;
	/// 二子handleより先に返す実旧historyの閉鎖です。
	std::shared_ptr<const CollectorStoreHttpFreeze>		 recoveryFreeze_ ;
	/// ROOT未保存の再導出・全prefix検査から発行した準備保存能力だけがtrueです。
	const bool											 recoveryPreparation_{} ;
	/// 先払い済みの固定順保存予定です。
	std::vector<CollectorSegmentStorageRole>			 roles_ ;
	/// 親／旧子／未作成新子の独立容量です。
	std::array<CollectorSegmentStorageCost, 3U>			 cost_ ;
} ;
/** @brief 元親と旧子の実検査・保持・先払いと固定不足保存を結合します。 */
class LocalCollectorSegmentStorage final {
public:
	/** @brief 実保存済み初期ROOTから旧全履歴を再検査して回復予約を発行します。
	 * @param[in,out] collection 再初期化した同collectionの単一writerです。
	 * @param[in] intentKey 親固定intent名を選ぶ完全hashです。実本文hashを再検査します。
	 * @param[in] sources 元履歴のsource契約です。
	 * @param[out] reservation 実二子／HTTP閉鎖と全再照合後だけの所有です。失敗は空です。
	 * @param[in] beforeFinalRecheck 両意味readerの借用中だけの非通信診断です。
	 * @return 成功0、能力87、再入170、内容13、後続ordinal50、元容量／I/O／CNG／確保code。
	 * @note 親head保存専用です。旧準備／新子／ROOTの保存と通常収集は許可しません。
	 */
	[[nodiscard]] static DWORD recover(
		LocalCollectorCollectionStore &collection, std::wstring_view intentKey,
		std::span<const CollectorCampaignSource>				   sources,
		std::shared_ptr<const CollectorSegmentStorageReservation> &reservation,
		const std::function<DWORD()> &beforeFinalRecheck = {}) noexcept ;
	/** @brief ROOT未保存の実intentと旧全履歴から連続準備prefixの回復予約を発行します。
	 * @param[in,out] collection 再初期化した同collectionの単一writerです。
	 * @param[in] intentKey 固定intentを選ぶ完全hashです。実本文と全再導出を要求します。
	 * @param[in] sources 元履歴のsource契約です。
	 * @param[out] reservation 全元rawと存在する準備prefixを再検査した所有です。失敗は空です。
	 * @param[in] beforeFinalRecheck 両意味readerの借用中だけの非通信診断です。
	 * @return 成功0、能力87、再入170、内容13、後続ordinal50、第一容量／I/O／CNG／確保code。
	 * @note 初回だけです。物理headは元head、activationとROOTは未保存でなければ拒否します。
	 * directory／lockの作成穴を補完せず、通常収集・HTTP再開を許可しません。
	 */
	[[nodiscard]] static DWORD recoverPreparation(
		LocalCollectorCollectionStore &collection, std::wstring_view intentKey,
		std::span<const CollectorCampaignSource>				   sources,
		std::shared_ptr<const CollectorSegmentStorageReservation> &reservation,
		const std::function<DWORD()> &beforeFinalRecheck = {}) noexcept ;

	/** @brief 実保存ROOTから元head保持記録と親登録／最終headを保存します。
	 * @param[in] reservation 同親handle・HTTP閉鎖と元全raw根拠を持つ生存予約です。
	 * @param[out] saved 最後に全検査した記録／二headの0～3件です。事前拒否時は0です。
	 * @param[in] afterSave 各実保存・全再照合後だけ呼ぶ数値診断です。
	 * @return 成功0、能力87、再入170、内容13、容量68、確保8、第一I/O／CNG code。
	 * @note 単一監督thread限定です。保存済み元head記録を保持し、再起動回復・HTTP許可は発行しません。
	 */
	[[nodiscard]] static DWORD saveParentHeads(
		std::shared_ptr<const CollectorSegmentStorageReservation> reservation, std::size_t &saved,
		const std::function<DWORD( std::size_t)> &afterSave = {}) noexcept ;
	/** @brief 保存済み新子69準備から専用初期ROOTを保存します。
	 * @param[in] reservation 元全raw・同親handle・HTTP閉鎖を所有する生存予約です。
	 * @param[out] saved 最後に検査した専用ROOTの0／1件です。事前拒否時は0です。
	 * @param[in] afterSave 一ROOTの実保存・全再検査後だけ呼ぶ数値診断です。
	 * @return 成功0、能力87、再入170、内容13、容量68、確保8、第一I/O／CNG code。
	 * @note 単一監督thread限定です。親head／旧台帳・ROOTを変更せず、再起動回復・通信許可は発行しません。
	 */
	[[nodiscard]] static DWORD saveInitialHistoryRoot(
		std::shared_ptr<const CollectorSegmentStorageReservation> reservation, std::size_t &saved,
		const std::function<DWORD( std::size_t)> &afterSave = {}) noexcept ;
	/** @brief 旧準備が完了した元予約から新子69roleの不足分だけを保存します。
	 * @param[in] reservation 元freshまたは準備回復検査と同親handle／HTTP閉鎖を所有する予約です。
	 * @param[out] saved 最後に全検査した新子側prefix件数です。事前拒否時は0です。
	 * @param[in] afterSave 新子marker／各保存後の全検査後だけ呼ぶ数値診断です。
	 * @return 成功0、能力87、再入170、内容13、容量68、確保8、第一I/O／CNG code。
	 * @note 同一監督thread／生存予約限定です。空historyだけを作り、ROOT／head・通信は発行しません。
	 */
	[[nodiscard]] static DWORD saveNewSegmentPreparation(
		std::shared_ptr<const CollectorSegmentStorageReservation> reservation, std::size_t &saved,
		const std::function<DWORD( std::size_t)> &afterSave = {}) noexcept ;
	/** @brief 同じ生存中の予約から固定準備prefixの不足分だけを保存します。
	 * @param[in] reservation Freshまたは準備回復検査と実handle／HTTP閉鎖を所有する元予約です。
	 * @param[out] saved 最後に全検査した物理prefix件数。事前拒否時は0です。
	 * @param[in] afterSave 各保存後の全検査後だけ呼ぶ数値診断。通常は空です。
	 * @return 成功0、能力87、再入170、内容13、容量68、確保8、第一I/O／CNG code。
	 * @note 単一監督thread限定です。新子／headを保存せず、ROOT保存済み回復予約は拒否します。
	 */
	[[nodiscard]] static DWORD savePreparation(
		std::shared_ptr<const CollectorSegmentStorageReservation> reservation, std::size_t &saved,
		const std::function<DWORD( std::size_t)> &afterSave = {}) noexcept ;
	/** @brief Caller成功hashなしで実同親保持と固定roleを作ります。
	 * @param[in,out] collection 実親writer。単一threadで呼び出します。
	 * @param[in,out] segment 同じ親の唯一history lease。呼出し中は解放しません。
	 * @param[in] sources 元source契約。fresh readerで検査します。
	 * @param[in] newSegment 未存在の完全小文字新区間keyです。
	 * @param[in] acceptedUtcMillis 元accepted UTCです。元台帳の時計を変更しません。
	 * @param[out] reservation 同親handleと実HTTP閉鎖の所有。全失敗は空です。
	 * @return 成功0、能力87、形式13、容量68、再入170、確保8、第一I/O／CNG code。
	 * @note Alias旧出力は同期呼出し中保持します。新子・intent・headは保存しません。
	 */
	[[nodiscard]] static DWORD prepare(
		LocalCollectorCollectionStore &collection, LocalCollectorSegmentLease &segment,
		std::span<const CollectorCampaignSource> sources, std::wstring_view newSegment,
		std::uint64_t											   acceptedUtcMillis,
		std::shared_ptr<const CollectorSegmentStorageReservation> &reservation) noexcept ;

private:
	/** @brief 二回復入口の実所有・旧意味reader・全raw再導出を共通化します。
	 * @param[in,out] collection 同collectionの未借用実writerです。
	 * @param[in] intentKey 実固定intentの完全hashです。
	 * @param[in] sources 元履歴のsource契約です。
	 * @param[out] reservation 最終非保存検査後だけの回復能力です。失敗は空です。
	 * @param[in] beforeFinalRecheck 実意味reader内だけの診断です。
	 * @param[in] preparation ROOT未保存の連続準備prefix回復だけがtrueです。
	 * @return 第一数値結果です。
	 */
	[[nodiscard]] static DWORD recoverInternal(
		LocalCollectorCollectionStore &collection, std::wstring_view intentKey,
		std::span<const CollectorCampaignSource>				   sources,
		std::shared_ptr<const CollectorSegmentStorageReservation> &reservation,
		const std::function<DWORD()> &beforeFinalRecheck, bool preparation) noexcept ;
	/** @brief 実所有する元全rawと旧／新準備prefix・全名・不足容量を非保存検査します。
	 * @param[in] reservation 準備回復の未公開候補です。
	 * @return 成功0、能力87、第一容量／I/O／CNG codeです。
	 * @throws DWORD 第一数値code。呼出し元の回復入口で保持します。
	 */
	[[nodiscard]] static DWORD verifyPreparationRecovery(
		const std::shared_ptr<const CollectorSegmentStorageReservation> &reservation) ;
	/** @brief 両予約経路の親head検査と不足suffix保存を共通化します。
	 * @param[in] reservation 同親の実検査済み所有です。
	 * @param[out] saved 最後に再照合した四状態の0～3です。
	 * @param[in] afterSave 実保存後だけの非通信診断です。
	 * @param[in] validateOnly 回復発行前の非保存再検査だけならtrueです。
	 * @return 第一数値結果です。
	 */
	[[nodiscard]] static DWORD parentHeads(
		std::shared_ptr<const CollectorSegmentStorageReservation> reservation, std::size_t &saved,
		const std::function<DWORD( std::size_t)> &afterSave, bool validateOnly) noexcept ;
} ;
} // namespace drivercrate
