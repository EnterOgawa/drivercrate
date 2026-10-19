//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_executor.h
 * @brief 新GET・解析・秘密資源回収から親への所有結果移譲を定義します。
 * @version 01.02.02
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  四slotの専用worker終端を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/29  射影の失敗専用診断依存を所有。
 * Ver.01.02.00 Shunji Ogawa  2026/09/29  同一監督identity・一回親prepareの非公開結合を追加。
 * Ver.01.02.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * Ver.01.02.02   Shunji Ogawa  2026/10/16 native client factoryの戻り値と所有・実行境界を明記。
 * </pre>
 *
 * @note 開発用の保存前接続です。v4保存・精算・slot再利用は未接続です。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/local_collector_executor.h"
#include "platform/local_collector_metadata_projection.h"

#include <functional>
#include <memory>
#include <cstddef>
#include <optional>

namespace drivercrate {
/** @brief WorkerのMTA内で一回clientだけを生成します。結果DTOの注入はできません。 */
using CollectorProjectedClientFactory = std::function<std::unique_ptr<LocalCollectorHttpClient>()> ;
/** @brief 構築前に全て明示する所有依存です。空依存のnative補完はありません。 */
struct CollectorProjectedExecutorDependencies {
	/// 全対象を元canonicalから再構築した不変campaign。
	std::shared_ptr<const CollectorPreparedProjectedCampaign> campaign ;
	/// 全worker・親が共有する非blocking・thread-safe時計。
	CollectorHttpClock										  clock ;
	/// Worker内で生成・破棄するclient。複数threadから呼ばれます。
	CollectorProjectedClientFactory							  createClient ;
	/// 一件のjoin可能threadを開始します。開始後に例外を投げてはなりません。
	CollectorExecutorStart									  start ;
	/// 各workerから数値だけを通知する任意依存。借用先は全joinまで存続します。
	CollectorProjectionDiagnostics							  diagnostics ;
} ;
/**
 * @brief 明示native clientだけを生成する依存を返します。構築では通信しません。
 * @return 呼出しごとにnative clientを単独所有するfactory。clientの生成は呼出しworkerのMTAで行います。
 */
[[nodiscard]] CollectorProjectedClientFactory collectorNativeProjectedClientFactory() ;
/** @brief 正常解析・明示上限・原失敗を区別する固定理由です。 */
enum class CollectorProjectedWorkerReason {
	/// 正常なFETCHEDまたはHELD。親受入・保存は未完了です。
	NONE,
	/// 明示された射影上限。OOMとは異なります。
	PROJECTION_LIMIT,
	/// 元HTTP・解析・停止・setupの失敗です。
	IO_FAILURE
} ;
/** @brief Join後の親だけが読める、秘密本文やcontrolを持たない所有結果です。 */
struct CollectorProjectedWorkerResult {
	/// 永続予約の全field。文字列は予約前に確保します。
	CollectorRecoveryDispatch			 binding ;
	/// 同じGETの元status・hash・validator・待機観測。
	CollectorControlledHttpObservation	 http ;
	/// 秘密資源・COM回収後に一回sealedした元I/O。
	CollectorIoSnapshot					 io ;
	/// 型付きparser終了。解析未開始ならnullです。
	std::optional<CollectorParserResult> parser ;
	/// 最終worker分類。親のCACHE判定ではありません。
	CollectorProjectedWorkerReason		 reason{CollectorProjectedWorkerReason::IO_FAILURE} ;
	/// 成功候補または明示的な空失敗。本文・URL・COMを含みません。
	CollectorMetadataProjectionDraft	 projection ;
} ;
/** @brief 保存済みと誤解しない四slotの回収報告です。 */
struct CollectorProjectedExecutorReport {
	/// 最初の監督・SETUP・clock・未回収native error。個別parser拒否は含めません。
	DWORD		error{} ;
	/// 永続予約して未精算のまま保持するslot数。
	std::size_t reserved{} ;
	/// 実thread開始数。
	std::size_t started{} ;
	/// 実threadをjoinした数。起動失敗の枠は含めません。
	std::size_t joined{} ;
	/// 起動失敗を含む通知受領数。
	std::size_t notified{} ;
	/// 全join時点の利用者取消しsignal。
	bool		cancellationRequested{} ;
} ;
/** @brief 同一process内の専用四slotを予約から全joinまで所有します。保存は行いません。 */
class LocalCollectorProjectedExecutor final {
public:
	/** @brief 全slot・元controlを最初の予約より前に確保します。
	 * @param[in] dependencies 空を許さない明示依存。Captured借用先は全joinまで必要です。
	 * @throws std::invalid_argument 依存またはprepared入力が欠ける場合。
	 * @throws std::bad_alloc 予約前の確保が失敗した場合。
	 */
	explicit LocalCollectorProjectedExecutor( CollectorProjectedExecutorDependencies dependencies) ;
	/** @brief 全workerを停止・joinします。未精算予約・保存物は削除しません。 */
	~LocalCollectorProjectedExecutor() ;
	/**
	 * @brief 専用四slotと全workerのjoin責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	LocalCollectorProjectedExecutor( const LocalCollectorProjectedExecutor &) = delete ;
	/**
	 * @brief 専用四slotと全workerのjoin責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	LocalCollectorProjectedExecutor &operator=( const LocalCollectorProjectedExecutor &) = delete ;
	/** @brief 同じ親writerで次の一件を予約し専用workerへ渡します。
	 * @param[in,out] recovery 同じprepared世代の監督。他poolとの混在は禁止です。
	 * @return 成功0、未準備／四枠使用済み1237、取消し995、または原error。
	 * @note 待機・保存・slot再利用はしません。失敗した起動もjoinで回収してください。
	 */
	[[nodiscard]] DWORD				 startNext( LocalCollectorRecovery &recovery) ;
	/** @brief 追加受付を閉じ、全通知を待ってjoinします。同じwriterから使用します。
	 * @return 未精算予約数・実join数・第一error。二度目は同じ結果を返します。
	 * @note 待機は500msごとに取消し／全体失敗を観測します。強制thread終了は行いません。
	 */
	[[nodiscard]] CollectorProjectedExecutorReport		join() ;
	/** @brief 他threadから取消しsignalだけを公開します。確定済み結果は変更しません。 */
	void												requestStop() noexcept ;
	/** @brief 全join後だけ元slotの不変結果を参照します。
	 * @param[in] slot 予約した順の0～3。
	 * @return 全join後の予約済みslotのみ非null。寿命はexecutorと同じです。
	 */
	[[nodiscard]] const CollectorProjectedWorkerResult *result( std::size_t slot) const noexcept ;

private:
	friend class LocalCollectorRecovery ;
	/** @brief 同じ監督へ全join済みの一結果を一度だけ渡します。
	 * @param[in] owner 予約元監督の非再利用token。
	 * @param[in] slot 元予約slot。
	 * @param[out] campaign 成功時だけ元prepared入力の借用。失敗時null。
	 * @param[out] worker 成功時だけ元const結果の借用。失敗時null。
	 * @return 元の全体error、関係拒否13、または成功0。両借用はexecutorまで存続します。
	 */
	[[nodiscard]] DWORD takeInitialPreparation( const std::shared_ptr<const std::byte>	 &owner,
											   std::size_t								  slot,
											   const CollectorPreparedProjectedCampaign *&campaign,
											   const CollectorProjectedWorkerResult		*&worker) ;
	/** @brief 親の第一準備失敗を全体停止へ伝播します。
	 * @param[in] error 非zeroの元数値。既存の第一errorは置換しません。
	 */
	void				failPreparation( DWORD error) ;
	/** @brief Workerより長く存続する所有状態です。 */
	struct State ;
	/// 四slotと全依存の唯一の所有者。
	std::unique_ptr<State> state_ ;
} ;
} // namespace drivercrate
