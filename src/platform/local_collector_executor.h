//------------------------------------------------------------------------------
/**
 * @file local_collector_executor.h
 * @brief 四slotのworker所有権・結果保存・全回収を定義します。
 * @version 01.01.01
 * @date 2026/09/27
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/27  応答v3・所有worker回収を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/27  保存中取消しと全体診断の契約を補足。
 * Ver.01.01.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note 開発用の有限収集に限定し、製品の取得・導入を許可しません。
 * @see docs/adr/0218-collector-controlled-http-lifetime.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "local_collector_http_control.h"
#include "official_http_client.h"
#include "local_driver_collector.h"
#include <atomic>
#include <functional>
#include <memory>
#include <thread>
#include <vector>

namespace drivercrate {
/** @brief Worker内だけで一回GETを行う明示依存です。Store／WinRT objectを共有しません。 */
using CollectorExecutorGet =
	std::function<NativeError( std::size_t, const CollectorRecoveryDispatch &, CollectorHttpPermit &,
							  CollectorControlledHttpObservation &)> ;
/** @brief 予約後の一件thread作成。例外は送信0のSETUPとして回収します。 */
using CollectorExecutorStart = std::function<std::thread( std::function<void()>)> ;
/** @brief 全依存を明示する開発用監督条件です。 */
struct CollectorExecutorDependencies {
	/// 全workerと監督が使うthread-safeな元clock。
	CollectorHttpClock	   clock ;
	/// Worker内の一回GET。空をnativeへ補完しません。
	CollectorExecutorGet   get ;
	/// Join可能threadを返す明示開始。空をnativeへ補完しません。
	CollectorExecutorStart start ;
} ;
/** @brief 当runの有限停止分類です。Generation summaryではありません。 */
enum class CollectorExecutorOutcome {
	/// 全jobが非再送状態です。Summaryは後続です。
	TERMINAL,
	/// 長期待機／予算で未予約が残ります。
	DEFERRED,
	/// 利用者取消しを受理して全workerを回収しました。
	CANCELLED,
	/// 最初の失敗を保持し、全workerを回収しました。
	FAILED
} ;
/** @brief Driver本体／製品適合を数えない監督結果です。 */
struct CollectorExecutorReport {
	/// 有限停止分類。
	CollectorExecutorOutcome outcome{CollectorExecutorOutcome::FAILED} ;
	/// 最初の監督／保存error。解放未確認は観測CLEANUP原値または5023です。
	DWORD					 error{} ;
	/// 永続予約したworker slot数。
	std::size_t				 reserved{} ;
	/// Join可能なthreadを開始した数。
	std::size_t				 started{} ;
	/// 終了通知後にjoinした数。
	std::size_t				 joined{} ;
	/// v3保存・精算が完了した数。
	std::size_t				 saved{} ;
	/// 実行＋通知待ち＋join／保存中の最大数。
	std::size_t				 peakSlots{} ;
	/// 個別GET等が失敗したjob数。製品対応率ではありません。
	std::size_t				 failedJobs{} ;
} ;
/** @brief 通信権限を加えず、明示した通常thread開始を返します。
 * @return 一件のjoin可能threadを作る関数。
 */
[[nodiscard]] CollectorExecutorStart collectorNativeThreadStarter() ;
/** @brief 所有するjob順の公開条件からworker専用clientを作ります。
 * @param[in] targets 検証済みmanifestの共有jobと同順序の所有条件。
 * @return 一回GET依存。構築だけでは通信しません。
 * @note Parser／cache未接続なので取得成功は監督側でHELDです。
 */
[[nodiscard]] CollectorExecutorGet	 makeNativeCollectorExecutorGet(
	  std::vector<LocalCollectorTarget> targets) ;
/** @brief 一つのwriter監督で四枠を保存・joinまで占有します。 */
class LocalCollectorExecutor final {
public:
	/** @brief 通知・四結果領域・permit poolを予約前に確保します。
     * @param[in] dependencies 全関数が必要な明示依存。
     * @throws std::invalid_argument 依存欠損の場合。
     * @throws std::bad_alloc 予約前の確保に失敗した場合。
     */
	explicit LocalCollectorExecutor( CollectorExecutorDependencies dependencies) ;
	/** @brief 所有workerを停止・joinし、未保存予約を勝手に削除しません。 */
	~LocalCollectorExecutor() ;
	/**
	 * @brief workerの停止・joinと四枠の管理責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	LocalCollectorExecutor( const LocalCollectorExecutor &) = delete ;
	/**
	 * @brief workerの停止・joinと四枠の管理責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	LocalCollectorExecutor				 &operator=( const LocalCollectorExecutor &) = delete ;
	/** @brief 初期化済み復旧監督を同じwriter threadで一回実行します。
     * @param[in,out] recovery Executorより長く存続する単一writer監督。
     * @return 予約・回収・保存件数と第一error。Summaryや製品成功ではありません。
     * @pre 初期化で旧予約回収を完了しており、他のexecutor／permit poolを同じ監督へ混在させません。
     * @note 保護store操作はこの呼出しthreadだけです。COM MTA内で使用します。
     */
	[[nodiscard]] CollectorExecutorReport run( LocalCollectorRecovery &recovery) ;
	/** @brief Run共通signalを公開し、workerが次checkpointで取消しを観測します。
	 * @note 保存やnative APIを待たず通知します。COMPLETE確定後の結果は変更しません。
	 */
	void								  requestStop() noexcept ;

private:
	/** @brief 固定slot・通知・第一errorの所有状態です。 */
	struct State ;
	/// 全workerより長く存続する唯一の状態。
	std::unique_ptr<State> state_ ;
} ;
} // namespace drivercrate
