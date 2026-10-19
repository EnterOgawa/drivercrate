//------------------------------------------------------------------------------
/**
 * @file local_collector_collection_store.h
 * @brief 有限collectionの親writerと親所有segment leaseを定義します。
 * @version 01.08.01
 * @date 2026/10/01
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/01  私有親writer・強所有子leaseを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/02  初回共有保存の同親lease借用を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/02  明示history付き区間leaseと固定履歴を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/02  非保存切替holdへ同親handleを強所有。
 * Ver.01.04.00 Shunji Ogawa  2026/10/02  保持能力だけの切替準備保存借用を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/02  元intentに結合した私有新子writerを追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/03  保護実handleの初回切替回復と検査を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/10/03  ROOT未保存の連続準備prefix回復と検査を追加。
 * Ver.01.08.00 Shunji Ogawa  2026/10/03  初回reader専用の同親四handle所有を追加。
 * Ver.01.08.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note 単一threadで使用します。共有台帳commit・seal・通信は行いません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "local_collector_state_store.h"
#include <Windows.h>
#include <array>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

namespace drivercrate {
struct CollectorCollectionSession ;
struct CollectorCollectionSwitchHold ;
struct CollectorCollectionReadHold ;
class LocalCollectorCollectionStore ;
class LocalCollectorSharedStore ;

/** @brief 子writerの寿命中、親writerを強所有する単一leaseです。 */
class LocalCollectorSegmentLease final {
public:
	/** @brief 子handleを閉じてから親借用を解除します。fileは削除しません。 */
	~LocalCollectorSegmentLease() ;
	/**
	 * @brief 子writerと親sessionの寿命管理の二重管理を防ぐため、コピー構築を禁止する。
	 */
	LocalCollectorSegmentLease( const LocalCollectorSegmentLease &) = delete ;
	/**
	 * @brief 子writerと親sessionの寿命管理を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	LocalCollectorSegmentLease			   &operator=( const LocalCollectorSegmentLease &) = delete ;
	/** @brief 寿命限定の子storeを借り受けます。
	 * @return Leaseまたは取得済み同親切替holdの存続中だけ有効なreference。再初期化を拒否します。
	 * @note 通常はleaseより先に借用を終え、切替holdで延長した場合も最後のholdより先に終えてください。
	 */
	[[nodiscard]] LocalCollectorStateStore &store() noexcept ;
	/** @brief 明示history付きleaseの固定履歴storeを借用します。
	 * @return 専用leaseなら非null、旧leaseならnull。取得済み同親切替hold生存中だけ元寿命を延長できます。
	 * @note 通常はleaseより先に借用を終え、延長時も最後のholdより先に終えてください。v3完了証明ではありません。
	 */
	[[nodiscard]] LocalCollectorStateStore *history() noexcept ;

private:
	friend class LocalCollectorCollectionStore ;
	/** @brief 親所有と初期化済み子を引き取ります。
	 * @param[in] session 単一親writerの強所有。
	 * @param[in] child 初期化済み子writerの強所有。
	 * @param[in] history 明示専用子だけの固定履歴。旧子は空です。
	 */
	LocalCollectorSegmentLease( std::shared_ptr<CollectorCollectionSession> session,
							   std::shared_ptr<LocalCollectorStateStore>   child,
							   std::unique_ptr<LocalCollectorStateStore>   history) ;
	/// 子handleより後に解放する親session。
	std::shared_ptr<CollectorCollectionSession> session_ ;
	/// 親から取得した補助子writer。
	std::shared_ptr<LocalCollectorStateStore>	child_ ;
	/// 子を強所有する固定履歴。取得済み切替holdも共有できます。旧leaseでは空です。
	std::shared_ptr<LocalCollectorStateStore>	history_ ;
} ;

/** @brief Collection全体の単一writerと有限子containerを所有します。 */
class LocalCollectorCollectionStore final {
public:
	/** @brief 未初期化wrapperを作ります。 */
	LocalCollectorCollectionStore() ;
	/** @brief Wrapper参照を解放します。残るleaseは親lockを保持します。 */
	~LocalCollectorCollectionStore() ;
	/**
	 * @brief 親writerと子containerの管理状態の二重管理を防ぐため、コピー構築を禁止する。
	 */
	LocalCollectorCollectionStore( const LocalCollectorCollectionStore &) = delete ;
	/**
	 * @brief 親writerと子containerの管理状態を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	LocalCollectorCollectionStore &operator=( const LocalCollectorCollectionStore &) = delete ;
	/** @brief 私有親layoutとcanonical markerを検査・初回登録します。
	 * @param[in] root Callerがworkspace内に限定した絶対path。末尾はkeyと同じです。
	 * @param[in] key 恒久collectionの完全小文字hash。
	 * @return 成功0、借用中170、拒否・I/Oは元Win32 code、確保失敗8。
	 * @note 既存rootの非空marker欠損や別modeを修復しません。
	 */
	[[nodiscard]] DWORD			   initialize( const std::filesystem::path &root,
											  std::wstring_view			   key) noexcept ;
	/** @brief 子借用がない場合だけ親writerを解放します。
	 * @return 未借用0、借用中170。失敗時は同じ親を保持します。
	 */
	[[nodiscard]] DWORD			   close() noexcept ;
	/** @brief 親能力に結合した最大一子を開きます。
	 * @param[in] key 完全小文字segment hash。seal由来は後続coreが検証します。
	 * @param[in] create 欠損子の保護作成を許す場合true。
	 * @param[out] lease 成功時だけのowner。入力の非空を170で拒否し、そのownerは保持します。
	 * @return 成功0、未初期化87、二重借用170、容量68、拒否・I/Oは元Win32 code。
	 * @note 0でも共有HEAD・seal・取得許可は発行しません。
	 */
	[[nodiscard]] DWORD			   borrowSegment( std::wstring_view key, bool create,
												 std::unique_ptr<LocalCollectorSegmentLease> &lease) noexcept ;
	/** @brief 専用markerの同親区間と固定historyだけを明示借用します。
	 * @param[in] key 完全小文字segment hash。任意history pathは受理しません。
	 * @param[in] create 欠損子／historyの保護作成を許す場合true。
	 * @param[out] lease 成功時だけの所有者。非空入力は170で拒否し保持します。
	 * @return 成功0、未初期化87、二重170、容量68、別mode13、元I/O／確保8。
	 * @note 旧modeへのfallback・移行・seal・通信は行いません。
	 */
	[[nodiscard]] DWORD			   borrowHistorySegment(
				   std::wstring_view key, bool create,
				   std::unique_ptr<LocalCollectorSegmentLease> &lease) noexcept ;

private:
	friend class LocalCollectorSharedStore ;
	friend class LocalCollectorSegmentStorage ;
	friend class LocalCollectorSegmentReader ;
	/** @brief 実intentの固定二子と新historyを非作成で強所有します。
	 * @param[in] oldKey 同じ実intentで検査した旧区間keyです。
	 * @param[in] newKey 同じ実intentで検査した新区間keyです。
	 * @param[out] hold 全保護handle成功時だけの所有です。失敗時は空です。
	 * @param[out] stores 親／旧子／新子／新historyです。同期readerだけへ私有借用します。
	 * @param[out] markers 同じ既存schemaから生成した親／旧子／新子のcanonical markerです。
	 * @return 成功0、能力87、再入170、二子集合13、第一I/O／確保8です。
	 * @note marker本文と現在集合を読まず、readerが予算付きで全検査します。旧historyを開きません。
	 */
	[[nodiscard]] DWORD		   openSegmentRead( std::wstring_view oldKey, std::wstring_view newKey,
											   std::shared_ptr<const CollectorCollectionReadHold> &hold,
											   std::array<LocalCollectorStateStore *, 4U>		  &stores,
											   std::array<std::string, 3U> &markers) noexcept ;
	/** @brief 生存中の同じreader所有と固定二子集合だけを再検査します。
	 * @param[in] hold 全成功後の私有同親所有です。
	 * @return 成功0、能力87、集合13、第一保護I/Oです。
	 * @note 本文read・保存・HTTPを行いません。
	 */
	[[nodiscard]] static DWORD verifySegmentRead(
		const std::shared_ptr<const CollectorCollectionReadHold> &hold) ;
	/** @brief 未借用の実親だけを回復開始時に私有参照します。
	 * @param[out] parent 同期回復入口だけの親。失敗時はnullです。
	 * @return 成功0、未初期化87、他借用中170です。
	 */
	[[nodiscard]] DWORD recoveryParent( LocalCollectorStateStore *&parent) noexcept ;
	/** @brief 指定intent由来の旧子と存在する固定新子を非作成で強所有します。
	 * @param[in] oldKey 実intentで検査した旧区間keyです。
	 * @param[in] newKey 同じintentの新区間keyです。
	 * @param[out] hold 全handleとmarker検査後だけの所有です。失敗は空です。
	 * @param[in] preparation ROOT未保存の準備回復だけで新子未作成を許す場合trueです。
	 * @return 成功0、能力87、再入170、内容13、第一I/O／確保8です。
	 * @note 私有能力取得だけです。旧台帳／履歴の検査とHTTP閉鎖を別途要求します。
	 */
	[[nodiscard]] DWORD openRecoverySwitch(
		std::wstring_view oldKey, std::wstring_view newKey,
		std::shared_ptr<const CollectorCollectionSwitchHold> &hold,
		bool												  preparation = false) noexcept ;

	/** @brief 同じholdの保存入口だけへ固定三handleを借用します。
	 * @param[in] hold Freshまたは実回復予約が強所有する私有能力です。
	 * @param[in] acquire 最初の取得だけtrue、保持中の再検査はfalseです。
	 * @param[out] stores 親／旧子／historyの順です。失敗時は空です。
	 * @param[out] next 指定時だけ新子／新historyを返します。未作成は空です。
	 * @return 成功0、能力87、再入170、集合拒否13、元I/O code。
	 * @note 元markerと旧子／開始済み元新子だけを再照合します。公開store借用ではありません。
	 */
	[[nodiscard]] static DWORD borrowSwitchStorage(
		const std::shared_ptr<const CollectorCollectionSwitchHold> &hold, bool acquire,
		std::array<LocalCollectorStateStore *, 3U> &stores,
		std::array<LocalCollectorStateStore *, 2U> *next = nullptr) ;
	/** @brief 保存済み元intentへ結合した新子／空historyだけを私有作成します。
	 * @param[in] hold 保存借用中の同親能力です。
	 * @param[in] intentName 元予約の固定親intent名です。
	 * @param[in] intentRaw 元予約の完全一致本文です。
	 * @param[out] next 全成功時だけの新子／空historyです。公開しません。
	 * @return 成功0、能力87、内容13、元I/O code。
	 * @note 呼出し前に元全raw・旧準備prefixと全保存容量を検査してください。ROOTは作りません。
	 */
	[[nodiscard]] static DWORD createSwitchStorage(
		const std::shared_ptr<const CollectorCollectionSwitchHold> &hold,
		std::wstring_view intentName, std::string_view intentRaw,
		std::array<LocalCollectorStateStore *, 2U> &next) ;
	/** @brief 元保存借用だけを返します。親lockとHTTP閉鎖は保持します。
	 * @param[in] hold 取得済みの元私有能力です。
	 */
	static void releaseSwitchStorage(
		const std::shared_ptr<const CollectorCollectionSwitchHold> &hold) noexcept ;
	/** @brief Fresh切替準備だけへ同親handleと単一writerを強所有させます。
	 * @param[in,out] lease この親だけのhistory付き旧子。
	 * @param[in] nextKey 未作成の完全新区間key。元keyと区別します。
	 * @param[out] hold 全成功時だけの私有保持。失敗時は空です。
	 * @param[out] usage 親／旧子の同handle実usage。失敗時は空です。
	 * @return 成功0、能力87、再入170、形式13、容量68、元I/O／確保8。
	 * @note 新子を作成せず、旧lease解放後も最後のholdまでhandleを保持します。
	 */
	[[nodiscard]] DWORD reserveSwitch( LocalCollectorSegmentLease &lease, std::wstring_view nextKey,
									  std::shared_ptr<const CollectorCollectionSwitchHold> &hold,
									  std::array<CollectorStoreUsage, 2U> &usage) noexcept ;
	/** @brief 明示した一modeだけで同親子leaseを作ります。
	 * @param[in] key 完全segment hash。
	 * @param[in] create 欠損専用領域の作成許可。
	 * @param[in] withHistory 新子と固定履歴を持つ場合true。旧子はfalseです。
	 * @param[out] lease 全成功時だけの所有者。非空入力は保持します。
	 * @return 成功0、拒否・I/Oの元code。
	 */
	[[nodiscard]] DWORD borrowSegmentImpl(
		std::wstring_view key, bool create, bool withHistory,
		std::unique_ptr<LocalCollectorSegmentLease> &lease) noexcept ;
	/** @brief 同じ親の唯一の子能力を共有保存へ私有借用します。
	 * @param[in,out] lease この親sessionが強所有されている子lease。
	 * @param[out] parent 成功時だけの親store。lease／wrapperより先に借用を終えてください。
	 * @param[in,out] remaining 親／子markerの実sizeを先払いするraw残予算。
	 * @return 成功0、能力不一致87、再入170、marker／集合拒否13、元I/O error。
	 * @note 親／子markerと唯一のcontainerを再照合します。通信能力ではありません。
	 */
	[[nodiscard]] DWORD							sharedParent( LocalCollectorSegmentLease &lease,
															 LocalCollectorStateStore *&parent, std::uint64_t &remaining) ;
	/** @brief 同じ呼出しの共有保存借用だけを解除します。親writerは保持します。 */
	void										releaseSharedParent() noexcept ;
	/// Wrapperと子leaseが共同所有する親session。親自身は子を所有しません。
	std::shared_ptr<CollectorCollectionSession> session_ ;
} ;
} // namespace drivercrate
