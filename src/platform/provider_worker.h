//------------------------------------------------------------------------------
/**
 * @file provider_worker.h
 * @brief Provider worker定義。
 * @version 01.03.02
 * @date 2026/09/01
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得計画とworker実行を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  件数付き進捗event追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  公式vendor Provider統合。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Provider選択条件転送追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Server用install保護mode転送追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  操作限定の通常scan取消し信号を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/11  通常workerの同scan署名索引読取り境界を接続。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  同scan索引の取得計画と非機密内容結果を追加。
 * Ver.01.03.01 Shunji Ogawa  2026/10/12  default/delete宣言の所有権と非実行契約を補足。
 * Ver.01.03.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note Blocking provider operationをCOM MTA worker threadへ隔離します。UI通知は有限result queueとPostMessageを使用し
 *       ます。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/restore_point_service.h"
#include "core/update_provider.h"
#include "platform/signed_index_scan.h"

#include <Windows.h>

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <variant>
#include <vector>

namespace drivercrate {
namespace provider_worker_index_detail {
struct Services ;
struct Access ;
}

//------------------------------------------------------------------------------
// Worker event型定義。
//------------------------------------------------------------------------------

/**
 * @brief worker から UI へ渡す event の種類を表す。
 */
enum class WorkerEventKind {
	/// Provider operationの段階、件数、および完了率通知。
	PROGRESS,
	/// ScanResultを伴うscan完了通知。
	SCAN_COMPLETED,
	/// 通常scanと混同しない、表示専用情報検索の終端通知。
	METADATA_SEARCH_COMPLETED,
	/// InstallResultを伴うinstall完了通知。
	INSTALL_COMPLETED,
	/// 選択済み取得対象の確定件数。既存導入進捗とは別。
	PREPARATION_PROGRESS,
	/// 検査用取得の対象別結果。導入結果ではない。
	PREPARATION_COMPLETED,
} ;

/**
 * @brief 一つの Provider operation に対応する worker event を表す。
 */
struct WorkerEvent {
	/// 通常scanの索引専用非機密件数。候補・導入権限ではありません。
	IndexScanSummary					   indexSummary ;
	/// 索引の取得・内容の個別確定結果。候補／導入能力ではありません。
	IndexPreparationSummary				   indexPreparation ;
	/// Event payloadの種類。
	WorkerEventKind						   kind{WorkerEventKind::SCAN_COMPLETED} ;
	/// UI state machineが割り当てたoperation ID。
	OperationId							   operationId{} ;
	/// Progress時だけ参照する確定済み進捗値。
	ProviderProgress					   progress ;
	/// ScanCompleted時だけ参照するscan結果。
	ScanResult							   scanResult ;
	/// InstallCompleted時だけ参照するinstall結果。
	InstallResult						   installResult ;
	/// Scan成功時の任意の取得計画。
	std::optional<OfficialPreparationPlan> preparationPlan ;
	/// 計画だけの失敗。driver scan結果とは独立。
	NativeError							   preparationError{} ;
	/// 取得専用の確定件数。
	OfficialPreparationProgress			   preparationProgress ;
	/// 取得専用の完了結果。
	OfficialPreparationOperationResult	   preparationResult ;
} ;

/**
 * @brief Worker内でProviderを生成し、単独所有権をworkerへ返すfactory。
 */
using ProviderFactory = std::function<std::unique_ptr<IUpdateProvider>()> ;
/**
 * @brief Worker内で生成する復旧保護service。Unit testではWindows APIを呼ばないfakeを指定する。
 */
using RestorePointFactory = std::function<std::unique_ptr<IRestorePointService>()> ;

/**
 * @brief Provider command を直列実行し、結果を UI message で通知する。
 */
class ProviderWorker final {
public:
	/**
	 * @brief 全組み込みProviderを統合するProvider workerを開始する。
	 * @param[in] notificationWindow result 通知を受ける top-level Window。
	 * @param[in] notificationMessage result queue 到着時に送る WM_APP 範囲の message ID。 result queue 到着時に送る
	 *                   WM_APP範囲の message ID。
	 */
	ProviderWorker( HWND notificationWindow, UINT notificationMessage) ;

	/**
	 * @brief test 用 Provider factory を使用する worker を開始する。
	 * 全組み込みProviderを統合するProvider workerを開始する。
	 * @param[in] notificationWindow result 通知を受ける top-level Window。
	 * @param[in] notificationMessage result queue 到着時に送る WM_APP 範囲の message ID。 result queue 到着時に送る
	 *                   WM_APP範囲の message ID。
	 * @param[in] providerFactory worker thread 内で Provider を生成する factory。 worker thread内でProviderを生
	 *                   成するfactory。test以外では既定aggregateを使用する。
	 */
	ProviderWorker( HWND notificationWindow, UINT notificationMessage,
				   ProviderFactory providerFactory) ;

	/**
	 * @brief Providerと復旧保護の双方を差し替えた内部試験用workerを開始する。
	 * 両factoryを保持してからthreadを開始し、内部試験で実復元APIの初期化も避けられる。
	 * @param[in] notificationWindow 結果通知先の非所有Window。
	 * @param[in] notificationMessage 通知message ID。
	 * @param[in] providerFactory worker内のProvider生成関数。
	 * @param[in] restorePointFactory worker内の復旧保護service生成関数。
	 * @note 既定constructorは従来のWindows復旧保護serviceを使用する。
	 */
	ProviderWorker( HWND notificationWindow, UINT notificationMessage,
				   ProviderFactory providerFactory, RestorePointFactory restorePointFactory) ;

	/**
	 * @brief 未開始 command を破棄し、実行中 operation の完了後に worker を停止する。
	 * 未開始 command を破棄し、実行中 operation の完了後に workerを停止する。
	 */
	~ProviderWorker() ;

	// Threadと同期objectを単独所有するためcopy/moveを禁止する。
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	ProviderWorker( const ProviderWorker &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	ProviderWorker &operator=( const ProviderWorker &) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	ProviderWorker( ProviderWorker &&) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	ProviderWorker	  &operator=( ProviderWorker &&) = delete ;

	/**
	 * @brief driver update scan を有限 command queue へ登録する。
	 * Provider選択条件を保持したdriver update scanを有限command queueへ登録する。
	 * @param[in] operationId UI state machine が割り当てた operation ID。
	 * @param[in] options 今回有効にする組み込みProvider設定。 scanで使用するProvider選択条件。
	 * @return 登録できた場合は `true`。
	 */
	[[nodiscard]] bool requestScan( OperationId operationId, ScanOptions options = {}) ;

	/**
	 * @brief 同じqueued／active通常scanにだけ協調取消しを要求する。
	 * @param[in] operationId 取り消す通常scanの操作ID。
	 * @return 同じ未完了scanの信号を設定した場合true。
	 * @note 情報検索、取得準備、導入の信号には作用しません。
	 */
	[[nodiscard]] bool requestScanCancel( OperationId operationId) ;

	/**
	 * @brief 明示集合と操作専用取消し信号を情報検索commandとして所有する。
	 * @param[in] operationId 単調増加する非ゼロ操作ID。
	 * @param[in] request 固定policyと専用Providerだけの明示要求。
	 * @return 不正要求、古いID、停止、queue上限はfalse。通常scanへ代替しない。
	 */
	[[nodiscard]] bool requestMetadataSearch( OperationId		   operationId,
											 MetadataSearchRequest request) ;

	/**
	 * @brief 同じqueued／active情報検索へだけ協調取消しを要求する。
	 * @param[in] operationId 取消す情報検索の操作ID。通常scan等には作用しない。
	 * @return 同じ未完了操作の信号を設定した場合true。
	 */
	[[nodiscard]] bool requestMetadataSearchCancel( OperationId operationId) ;

	/**
	 * @brief 選択 update の download/install を command queue へ登録する。
	 * 選択 update の download/install を command queueへ登録する。
	 * @param[in] operationId UI state machine が割り当てた operation ID。
	 * @param[in] scanSessionId 選択元 scan session ID。
	 * @param[in] identities UI に提示済みの opaque identity 群。
	 * @param[in] parentWindow WUA dialog の親 Window。
	 * @param[in] protectionMode OSと利用者確認に対応するinstall保護方針。 OS別のinstall保護方針。
	 * @return 登録できた場合は `true`。
	 */
	[[nodiscard]] bool requestInstall( OperationId operationId, ScanSessionId scanSessionId,
									  std::span<const std::wstring> identities, HWND parentWindow,
									  InstallProtectionMode protectionMode) ;

	/**
	 * @brief 現在蓄積された event を ownership ごと UI thread へ移す。
	 * @return 到着順の event 群。
	 */
	[[nodiscard]] std::vector<WorkerEvent> takeEvents() ;

	/**
	 * @brief 表示した全対象の取得可否を有限queueへコピーする。
	 * UIの判断を取得許可として信用せず、workerで固定計画へ再照合する。
	 * @param[in] approval 利用者の判断。承認自体はworker内で再照合する。 全対象のsnapshotと取得判断。
	 * @return 有界な新操作を登録した場合true。0／古い操作IDと停止中は拒否する。 有界な新操作をqueueへコピーした場合true。
	 */
	[[nodiscard]] bool requestPreparation( const OfficialPreparationApproval &approval) ;

	/**
	 * @brief 同じ操作IDのqueued／active取得に協調取消しを要求する。
	 * 他のprepare、scan、installを取消さず、workerの状態objectへ直接触れない。
	 * @param[in] operationId 取消すprepare操作。scan／installには作用しない。 取消すprepareのID。0は無効。
	 * @return 対象操作の信号を設定した場合true。 queuedまたはactiveの同じ取得へ信号を設定した場合true。
	 */
	[[nodiscard]] bool requestPreparationCancel( OperationId operationId) ;

	/**
	 * @brief 新規 command を拒否し、実行中 operation の安全な完了後に worker を停止する。
	 * 新規 command を拒否し、実行中 operation の安全な完了後にworker を停止する。
	 * 新規 command を拒否し、実行中 operation の安全な完了後にworker を停止する。 注記: WUA operationを強制終了しないため、この呼出しは実行中
	 * operationの完了まで待つ。
	 * @note WUA operation を強制終了しないため、この呼出しは実行中 operation の完了まで待つ。
	 */
	void			   stop() noexcept ;

private:
	/** @brief 製品固定serviceまたは内部fixtureをthread開始前に所有します。
	 * @param[in] notificationWindow 非所有通知Window。
	 * @param[in] notificationMessage 通知message。
	 * @param[in] providerFactory 同worker Provider生成関数。
	 * @param[in] restorePointFactory 同worker復旧service生成関数。
	 * @param[in] indexServices 内部固定索引能力。通常入口は任意設定を受理しません。
	 */
	ProviderWorker( HWND notificationWindow, UINT notificationMessage,
				   ProviderFactory providerFactory, RestorePointFactory restorePointFactory,
				   std::unique_ptr<provider_worker_index_detail::Services> indexServices) ;
	friend struct provider_worker_index_detail::Access ;
	/**
     * @brief queue に保持する一回の scan 要求である。
     */
	struct ScanCommand {
		/// UI state machineが割り当てたscan operation ID。
		OperationId						  operationId{} ;
		/// Scan sessionへ固定するProvider選択。
		ScanOptions						  options ;
		/// Queued／activeで同じoperationだけが共有する取消し信号。
		std::shared_ptr<std::atomic_bool> cancellation ;
	} ;

	/**
     * @brief queue に ownership ごと保持する一回の install 要求である。
     */
	struct InstallCommand {
		/// UI state machineが割り当てたinstall operation ID。
		OperationId				  operationId{} ;
		/// 候補を取得したscan session ID。
		ScanSessionId			  scanSessionId{} ;
		/// 利用者が選択したopaque identity群。
		std::vector<std::wstring> identities ;
		/// Installer UIが参照する非所有parent Window handle。
		HWND					  parentWindow{} ;
		/// UI確認時に固定し、workerが実OSと再照合するinstall保護方針。
		InstallProtectionMode	  protectionMode{InstallProtectionMode::WINDOWS_RESTORE_POINT} ;
	} ;

	/** @brief 対象別承認と一操作限定の取消し信号を所有する要求。 */
	struct PreparationCommand {
		/// UIから受け取る有界な判断snapshot。
		OfficialPreparationApproval		  approval ;
		/// queued／activeで同じ信号を共有する。
		std::shared_ptr<std::atomic_bool> cancellation ;
	} ;

	/** @brief 非導入検索の入力とqueued／active共通の取消し信号を所有する。 */
	struct MetadataSearchCommand {
		/// Worker終端まで同じ用途へ拘束する操作ID。
		OperationId						  operationId{} ;
		/// 通常scanのpayload同意を含まない今回の要求。
		MetadataSearchRequest			  request ;
		/// 同一操作だけが共有する非blocking取消し状態。
		std::shared_ptr<std::atomic_bool> cancellation ;
	} ;

	/**
	 * @brief Workerの有限queueが所有する要求値。種別ごとのsessionと取消し状態を保持する。
	 */
	using Command =
		std::variant<ScanCommand, InstallCommand, PreparationCommand, MetadataSearchCommand> ;

	/**
	 * @brief COM MTA を初期化して command を直列処理する thread entry である。
	 * COM MTA を初期化して command を直列処理する thread entryである。
	 */
	void						 run() noexcept ;

	/**
	 * @brief result queue へ event を追加して UI へ通知する。
	 * @param[in] event 追加する event。
	 */
	void						 publishEvent( WorkerEvent event) noexcept ;

	/**
	 * @brief 0 と重複しない scan session ID を割り当てる。
	 * @param[out] scanSessionId 割り当てた ID。
	 * @return 割り当てられた場合は `true`。
	 */
	[[nodiscard]] bool			 allocateScanSessionId( ScanSessionId &scanSessionId) noexcept ;

	/// 未処理command数の上限。
	static constexpr std::size_t MAXIMUM_QUEUED_COMMANDS = 4 ;
	/// 未取得event数の上限。
	static constexpr std::size_t MAXIMUM_QUEUED_EVENTS = 32 ;

	/// Result到着通知先の非所有Window handle。
	HWND						 notificationWindow_{} ;
	/// UIへ送るWM_APP範囲のmessage ID。
	UINT						 notificationMessage_{} ;
	/// Worker thread内でproviderを生成する関数。
	ProviderFactory				 providerFactory_ ;
	/// Worker thread内の復旧保護service生成関数。
	RestorePointFactory			 restorePointFactory_ ;
	/// Thread開始前に固定するworker専用索引service。
	std::unique_ptr<provider_worker_index_detail::Services> indexServices_ ;

	/// Command queueとstopping_を保護するmutex。
	std::mutex												commandMutex_ ;
	/// Command追加または停止要求を通知する条件変数。
	std::condition_variable									commandReady_ ;
	/// UIから受理した有限FIFO command queue。
	std::deque<Command>										commands_ ;
	/// trueの場合は新規commandを拒否しworkerを停止する。
	bool													stopping_{} ;
	/// Command受付全体の単調ID高水位。
	OperationId												latestRequestedOperationId_{} ;
	/// commandMutex_で保護する実行中の通常scan ID。
	OperationId												activeScanId_{} ;
	/// 通常scan実行中だけ保持する操作限定信号。
	std::shared_ptr<std::atomic_bool>						activeScanCancellation_ ;
	/// commandMutex_で保護する実行中prepare ID。
	OperationId												activePreparationId_{} ;
	/// 実行中だけ保持する信号。
	std::shared_ptr<std::atomic_bool>						activePreparationCancellation_ ;
	/// commandMutex_で保護する実行中情報検索ID。完了公開前に0へ戻す。
	OperationId												activeMetadataSearchId_{} ;
	/// 情報検索専用の共有信号。通常scan、取得、導入へ転用しない。
	std::shared_ptr<std::atomic_bool>						activeMetadataSearchCancellation_ ;

	/// Result event queueを保護するmutex。
	std::mutex												eventMutex_ ;
	/// UIがownershipを取得する有限FIFO event queue。
	std::deque<WorkerEvent>									events_ ;

	/// 次回割り当てる0以外のscan session ID。
	ScanSessionId											nextScanSessionId_{1} ;
	/// Worker内だけで発行する計画ID。
	std::uint64_t											nextPreparationPlanId_{1U} ;
	/// ProviderとCOM apartmentを所有するworker thread。
	std::jthread											thread_ ;
} ;

} // namespace drivercrate
