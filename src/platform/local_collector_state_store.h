//------------------------------------------------------------------------------
/**
 * @file local_collector_state_store.h
 * @brief 収集台帳の作成時ACLと検証済みhandleによる永続化を定義します。
 * @version 01.13.01
 * @date 2026/09/25
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/25  作成時ACLと既存状態の拒否境界を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/25  完全SHA名の保護run列挙契約を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/27  単一campaign借用とwriter状態の照会を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/27  共通予算の借用・current列挙とmode拒否を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/27  v2単一借用とstaging込み容量観測を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/01  私有collection階層と親所有の子storeを追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/02  同handle実sizeのraw先払い読取りを追加。
 * Ver.01.07.00 Shunji Ogawa  2026/10/02  共有読取り根拠へ監督借用を限定公開。
 * Ver.01.08.00 Shunji Ogawa  2026/10/02  明示history付き子と親所有履歴の保護配置を追加。
 * Ver.01.09.00 Shunji Ogawa  2026/10/02  HTTP実所有ticketと排他的freezeを追加。
 * Ver.01.10.00 Shunji Ogawa  2026/10/03  保護実handleの初回切替回復と検査を追加。
 * Ver.01.11.00 Shunji Ogawa  2026/10/03  ROOT未保存の連続準備prefix回復と検査を追加。
 * Ver.01.12.00 Shunji Ogawa  2026/10/03  非作成readerの私有handleと有限名監査を追加。
 * Ver.01.12.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * Ver.01.13.00  Shunji Ogawa  2026/10/17  欠損を作成しない既存writer取得を追加。
 * Ver.01.13.01  Shunji Ogawa  2026/10/17  作成と非作成writerの祖先事前検査を共通化。
 * </pre>
 *
 * @note 実行user、SYSTEM、Administratorsを信頼し、既存ACLを変更しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "local_collector_http_activity.h"

#include <Windows.h>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

class LocalCollectorCampaign ;
class LocalCollectorWaitLedger ;
class LocalCollectorBudgetLedger ;
class LocalCollectorCollectionStore ;

/** @brief 保護handleで数えたstaging込みの保存容量です。 */
struct CollectorStoreUsage {
	/// current直下の全entry数。
	std::size_t	  currentEntries{} ;
	/// runs直下の全entry数。
	std::size_t	  runEntries{} ;
	/// 二directoryの全通常fileのbyte合計。
	std::uint64_t bytes{} ;
} ;

/**
 * @brief 台帳のownerと保護DACLが固定した三principalだけを許可するか確認します。
 * @param[in] descriptor 有効なsecurity descriptor。所有権は移しません。
 * @param[in] userSid collectorのprocess user SID。所有権は移しません。
 * @param[in] directory trueなら子に継承するOICIを要求します。
 * @return 明示したowner、ACE、mask、flagだけの場合true。
 */
[[nodiscard]] bool isLocalCollectorDescriptorAllowed( PSECURITY_DESCRIPTOR descriptor, PSID userSid,
													 bool directory) noexcept ;

/** @brief 単一writerの台帳を保護された専用rootに保持します。 */
class LocalCollectorStateStore final {
public:
	/** @brief 空のstoreを作成します。 */
	LocalCollectorStateStore() ;
	/** @brief 保持したlockとdirectory handleを解放します。fileは削除しません。 */
	~LocalCollectorStateStore() ;
	/**
	 * @brief writer lockとdirectory HANDLEの解放責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	LocalCollectorStateStore( const LocalCollectorStateStore &) = delete ;
	/**
	 * @brief writer lockとdirectory HANDLEの解放責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	LocalCollectorStateStore &operator=( const LocalCollectorStateStore &) = delete ;

	/**
     * @brief 新規rootを保護して作成するか、既存root全体を変更せず検査します。
     * @param[in] root callerがworkspace内へ限定した絶対path。
     * @param[in] writable trueでは欠損directoryとlockを作成し、writer lockを保持します。
     * @return 成功0、拒否・API失敗は元のWin32 error。
     * @note falseでは書込み・新規作成をせず、未存在rootも入力検証成功とします。
     */
	[[nodiscard]] DWORD		  initialize( const std::filesystem::path &root, bool writable) ;

	/** @brief 既存rootとlockだけを完全検査してwriterを保持します。
	 * @param[in] root 既に存在する専用絶対path。
	 * @return 成功0、欠損・保護・競合は元Win32 error。
	 * @note directory、lock、modeを作成・修復せず、成功時の所有期間はstoreの寿命です。
	 *       通常writerと同じ親所有・予約segment／historyの直開き防御を適用します。
	 */
	[[nodiscard]] DWORD		  initializeExistingWriter( const std::filesystem::path &root) ;

	/**
     * @brief 通常fileを同じ検証済みhandleから最大2 MiB読みます。
     * @param[in] relative runsまたはcurrent直下のJSON名。
     * @param[out] bytes 成功時の本文。欠損・失敗時は空です。
     * @param[out] found fileが存在して読み取れた場合true。
     * @return 成功または欠損0、拒否・API失敗はWin32 error。
     */
	[[nodiscard]] DWORD		  read( const std::filesystem::path &relative, std::string &bytes,
								   bool &found) ;

	/** @brief 同じ実handleのbyte長を先払いして有限rawを読みます。
	 * @param[in] relative runsまたはcurrent直下のJSON名。
	 * @param[out] bytes 全成功時だけの本文。欠損／失敗時は空です。
	 * @param[out] found 全成功の存在時だけtrue。
	 * @param[in,out] remaining 実sizeを確保・ReadFile前に差し引く残予算。I/O失敗でも返金しません。
	 * @return 成功または欠損0、予算不足68、元Win32 error。
	 * @note 一fileの既存2 MiBと同handle検査を維持します。
	 */
	[[nodiscard]] DWORD read( const std::filesystem::path &relative, std::string &bytes, bool &found,
							 std::uint64_t &remaining) ;

	/**
     * @brief 検証済みの保護一時fileをflushしてJSONを置換します。
     * @param[in] relative runsまたはcurrent直下のJSON名。
     * @param[in] bytes 最大2 MiBの本文。
     * @return 成功0、拒否・API失敗はWin32 error。既存ACLを修復しません。
     */
	[[nodiscard]] DWORD write( const std::filesystem::path &relative, std::string_view bytes) ;

	/** @brief 検証済みruns直下のJSON名だけを有限列挙します。
     * @param[out] names 成功時だけ最大4096件のfile名。pathは含めません。
     * @return 成功0、拒否・API失敗は元のWin32 error。
     */
	[[nodiscard]] DWORD listRunNames( std::vector<std::wstring> &names) ;

	/** @brief 検証済みcurrent直下のJSON名だけを有限列挙します。
	 * @param[out] names 成功時の最大4096件のfile名。固定順に返します。
	 * @return 成功0、拒否・API失敗は元のWin32 error。
	 * @note runsと同じhandle・owner・ACL検査を各entryへ適用します。
	 */
	[[nodiscard]] DWORD listCurrentNames( std::vector<std::wstring> &names) ;

	/** @brief 全確定fileと残留stagingを同じ保護handleから集計します。
	 * @param[out] usage 成功時だけの有限集計。失敗時は空です。
	 * @return 成功0、容量68または元I/O code。
	 */
	[[nodiscard]] DWORD inspectUsage( CollectorStoreUsage &usage) ;

	/** @brief 最後のI/OのWin32 errorを返します。
     * @return 成功0、それ以外は元の数値error。
     */
	[[nodiscard]] DWORD lastError() const noexcept ;

	/** @brief 単一writer lockを保持した書込み可能なstoreか確認します。
     * @return writer初期化が成功している場合true。read-only検証はfalseです。
     */
	[[nodiscard]] bool	isWritable() const noexcept ;

	/** @brief 初期化時に検証した専用rootを読みます。
     * @return Store存続中の参照。借用期間中の再初期化は拒否します。
     */
	[[nodiscard]] const std::filesystem::path &root() const noexcept ;

private:
	friend class LocalCollectorCampaign ;
	friend class LocalCollectorWaitLedger ;
	friend class LocalCollectorBudgetLedger ;
	friend class LocalCollectorRecovery ;
	friend class LocalCollectorCollectionStore ;
	friend class LocalCollectorSharedStore ;
	friend class LocalCollectorSegmentPreparation ;
	friend class LocalCollectorSegmentStorage ;
	friend class LocalCollectorSegmentReader ;
	/** @brief 読取り証明だけへ非作成の同親専用子handleを発行します。
	 * @param[in] parent 初期化済み同親writerです。子が寿命を延長します。
	 * @param[in] key 完全小文字segment hashです。
	 * @return 成功0、能力87、第一保護／sharing errorです。
	 * @note metadata内の全監査は行いません。readerが必要集合とmarkerを別途検査します。
	 */
	[[nodiscard]] DWORD initializeReadSegment(
		const std::shared_ptr<LocalCollectorStateStore> &parent, std::wstring_view key) ;
	/** @brief 読取り証明だけへ固定新historyを非作成で開きます。
	 * @param[in] segment 同親の専用新子writerです。履歴が寿命を延長します。
	 * @return 成功0、能力87、第一保護／sharing errorです。
	 * @note mode／ROOTを作成・読取りしません。固定集合と本文はreaderが検査します。
	 */
	[[nodiscard]] DWORD initializeReadHistory(
		const std::shared_ptr<LocalCollectorStateStore> &segment) ;
	/** @brief 同じ監督だけにHTTP実所有登録を発行します。
	 * @param[in] borrower このwriterを借用した元Recovery state。
	 * @param[out] lease 全成立後だけの実所有登録。失敗時は空です。
	 * @return 成功0、能力87、freeze170、上限68、確保8。
	 */
	[[nodiscard]] DWORD acquireHttpActivity(
		const void *borrower, std::shared_ptr<const CollectorStoreHttpLease> &lease) noexcept ;
	/** @brief 監督借用とHTTP実所有が0の場合だけ再発行を止めます。
	 * @param[out] freeze 全成立後だけの閉鎖所有。失敗時は空です。
	 * @return 成功0、能力87、既存借用／所有170、確保8。
	 */
	[[nodiscard]] DWORD freezeHttpActivity(
		std::shared_ptr<const CollectorStoreHttpFreeze> &freeze) noexcept ;
	/** @brief HTTP監督初期化の前に排他的freezeを確認します。
	 * @return 閉鎖中170、それ以外0。Storeを変更しません。
	 */
	[[nodiscard]] DWORD checkHttpSupervisor() const noexcept ;

	/** @brief 親sessionだけが呼べるcollection初期化です。
	 * @param[in] root 完全collection keyを末尾に持つ専用絶対path。
	 * @param[in] expected 作成前に完全一致を要求する親marker。
	 * @return 成功0、拒否または元Win32 error。
	 */
	[[nodiscard]] DWORD initializeCollection( const std::filesystem::path &root,
											 std::string_view			  expected) ;

	/** @brief 取得済み親を強所有して子writerを開きます。
	 * @param[in] parent Writerを保持するcollection store。子より長く保持します。
	 * @param[in] key 完全小文字segment hash。
	 * @param[in] create 欠損子の保護作成を許す場合true。
	 * @param[in] expected 作成前に完全一致を要求する子marker。
	 * @param[in] withHistory 固定historyを許す専用子の場合true。旧子はfalseです。
	 * @return 成功0、拒否または元Win32 error。
	 */
	[[nodiscard]] DWORD initializeOwnedSegment(
		const std::shared_ptr<LocalCollectorStateStore> &parent, std::wstring_view key, bool create,
		std::string_view expected, bool withHistory = false) ;

	/** @brief 明示history付き子を強所有して固定履歴writerを開きます。
	 * @param[in] segment Writerを持つ専用子。履歴より長く保持します。
	 * @param[in] create 欠損固定historyだけの保護作成を許す場合true。
	 * @return 成功0、別能力87、拒否または元Win32 error。
	 * @note v3 ROOTの登録・回復・完了検証は行いません。
	 */
	[[nodiscard]] DWORD initializeOwnedHistory(
		const std::shared_ptr<LocalCollectorStateStore> &segment, bool create) ;

	/** @brief 私有回復だけで専用初期ROOTまたは許された空historyを非作成で開きます。
	 * @param[in] segment 同親holdが強所有する専用新区間writerです。
	 * @param[in] allowEmpty ROOT未保存の準備回復だけで全実数0を許す場合trueです。
	 * @return 保護・排他と一ROOTまたは許された空配置の実usage成立0、別能力87、内容13、元I/O code。
	 * @note 通常mode欠損境界は変更しません。ROOT本文と全像／intentの検査を別途必須にします。
	 */
	[[nodiscard]] DWORD initializeRecoveryHistory(
		const std::shared_ptr<LocalCollectorStateStore> &segment, bool allowEmpty = false) ;

	/** @brief 親直下の保護segment container名だけを検査します。
	 * @param[out] names 成功時の最大1024完全hash名。失敗時は空です。
	 * @return 成功0、容量68または元Win32 error。
	 */
	[[nodiscard]] DWORD listSegments( std::vector<std::wstring> &names) ;

	/** @brief 通常storeの作成／非作成で同じ祖先能力の事前検査を適用します。
	 * @param[in] root 専用絶対path。
	 * @param[in] writable Writer lockを保持する場合true。
	 * @param[in] create 欠損directory／lockの作成を許す場合true。
	 * @return 成功0、能力違反または元Win32 error。
	 * @note 私有の親所有子・historyはこの通常入口へ接続しません。
	 */
	[[nodiscard]] DWORD initializeLegacy( const std::filesystem::path &root, bool writable,
										 bool create) ;

	/** @brief 通常／私有親／親所有子の共通保護初期化です。
	 * @param[in] root 専用絶対path。
	 * @param[in] writable Writer lockを保持する場合true。
	 * @param[in] collection 親だけでsegments階層を許す場合true。
	 * @param[in] parent 子が寿命を延長する親。通常と親自身は空です。
	 * @param[in] create 欠損directory／lockを作る場合true。
	 * @param[in] expected 新親／子の作成前marker。通常storeは空です。
	 * @param[in] withHistory 専用子直下だけに固定historyを許す場合true。
	 * @param[in] recoveryHistory 私有回復の一ROOTまたは許された空配置を後段検査する場合trueです。
	 * @param[in] checkpointOnly 私有readerだけでmetadata内全監査を後段の固定集合へ委譲する場合trueです。
	 * @return 成功0、拒否または元Win32 error。
	 */
	[[nodiscard]] DWORD initializeImpl( const std::filesystem::path &root, bool writable,
									   bool										 collection,
									   std::shared_ptr<LocalCollectorStateStore> parent,
									   bool create, std::string_view expected = {},
									   bool withHistory = false, bool recoveryHistory = false,
									   bool checkpointOnly = false) ;

	/** @brief 既知の二directoryのentryを同じ保護境界で列挙します。
	 * @param[in] directory runsまたはcurrentの固定名。
	 * @param[out] names 成功時の固定順JSON名。拒否時は空です。
	 * @param[out] entries 指定時はstaging込みentry数。未指定ならnullです。
	 * @param[out] bytes 指定時は同じhandleからの全byte数。未指定ならnullです。
	 * @param[in] maximumEntries 全entryの上限です。既定4096、私有readerは固定集合へ縮小します。
	 * @return 成功0、拒否・API失敗は元Win32 code。
	 */
	[[nodiscard]] DWORD listNames( std::wstring_view directory, std::vector<std::wstring> &names,
								  std::size_t *entries = nullptr, std::uint64_t *bytes = nullptr,
								  std::size_t maximumEntries = 4096U) ;

	/** @brief 監督core一つだけへwriterを借用します。
     * @param[in] borrower 存続中のcore state。nullを拒否します。
     * @return 成功0、未初期化87、二重借用170。
     */
	[[nodiscard]] DWORD borrowCampaign( const void *borrower) noexcept ;

	/** @brief 取得した借用だけを解除し、writerを保持します。
     * @param[in] borrower 借用時と同じcore state。
     */
	void				releaseCampaign( const void *borrower) noexcept ;

	/** @brief 一つの監督待機台帳へstoreを借用します。
     * @param[in] borrower 存続中の待機台帳。nullを拒否します。
     * @return 成功0、未初期化87、二重借用170。
     */
	[[nodiscard]] DWORD borrowWaitLedger( const void *borrower) noexcept ;

	/** @brief 取得した待機台帳の借用だけを解除します。
     * @param[in] borrower 借用時と同じstate。
     */
	void				releaseWaitLedger( const void *borrower) noexcept ;

	/** @brief Windows handleとsecurity descriptorの単独所有状態です。 */
	struct State ;
	/// 初期化から終了まで所有するWindows資源。
	std::unique_ptr<State> state_ ;
} ;

/**
 * @brief v2登録済みrootへ旧CLI・v1 coreの更新を混用させません。
 * @param[in,out] store Writer初期化済みの保護store。
 * @return mode欠損0、mode存在13、読取り拒否・破損は元Win32 code。
 * @note markerが不正でも更新を許可せず、fileを変更しません。
 */
[[nodiscard]] DWORD rejectLocalCollectorCampaignMode( LocalCollectorStateStore &store) ;

} // namespace drivercrate
