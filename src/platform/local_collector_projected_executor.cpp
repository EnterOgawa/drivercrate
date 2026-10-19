//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_executor.cpp
 * @brief 専用workerの同一GET解析・一回終端・全joinを実装します。
 * @version 01.02.00
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
 * Ver.01.01.00 Shunji Ogawa  2026/09/29  元本文と失敗専用診断を同じworkerへ結合。
 * Ver.01.02.00 Shunji Ogawa  2026/09/29  別監督・未join・二重prepareの非公開gateを追加。
 * </pre>
 *
 * @note 新応答を旧v3保存へ渡さず、全予約を未精算のまま保持します。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#include "platform/local_collector_projected_executor.h"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <new>
#include <stdexcept>
#include <system_error>
#include <type_traits>
#include <utility>
#include <winrt/base.h>

namespace drivercrate {

static_assert( std::is_nothrow_move_assignable_v<CollectorProjectedWorkerResult>) ;
static_assert( std::is_nothrow_move_constructible_v<CollectorProjectedWorkerResult>) ;

/** @brief 固定四slotとready bitを所有する専用状態です。 */
struct LocalCollectorProjectedExecutor::State {
	/** @brief 通知前はworker、全join後は親だけが結果へアクセスします。 */
	struct Slot {
		/// 保存後に発行される元許可。再利用しません。
		CollectorHttpPermit			   permit ;
		/// Joinする一つのthread。
		std::thread					   worker ;
		/// 予約前に領域を確保する公開結果。
		CollectorProjectedWorkerResult value ;
		/// 予約後の数値操作だけで有効化します。
		bool						   occupied{} ;
		/// 親prepareを試みたslot。失敗時も再利用しません。
		bool						   preparationTaken{} ;
	} ;
	/// 準備済み入力・clock・client生成・開始callbackの所有値。
	CollectorProjectedExecutorDependencies dependencies ;
	/// 全controlが共有する非blocking取消しsignal。
	std::shared_ptr<std::atomic_bool>	   cancelled ;
	/// 予約前に四controlを確保する元発行元。
	CollectorHttpPermitPool				   pool ;
	/// 実行／通知／join後も未精算のまま保持する四枠。
	std::array<Slot, 4U>				   slots ;
	/// 通知bitの変更だけを保護します。
	std::mutex							   mutex ;
	/// Worker完了と外部取消しの通知。
	std::condition_variable				   changed ;
	/// 追加allocationなしの固定通知領域。
	std::array<bool, 4U>				   ready{} ;
	/// Workerが先に発見した全体停止error。原値を先着保持します。
	std::atomic<DWORD>					   fatal{} ;
	/// 同じ親writerが更新する数値報告。
	CollectorProjectedExecutorReport	   report ;
	/// Join開始・全体停止後は新しい予約をしません。
	bool								   closed{} ;
	/// 全threadをjoinした後だけ親へ結果を公開します。
	bool								   joined{} ;
	/// 最初の予約前に固定する監督の所有identity。address再利用を防ぎます。
	std::shared_ptr<const std::byte>	   recoveryOwner ;

	/** @brief 全依存を保存前に検査します。
	 * @param[in] value 所有して渡す明示依存。
	 */
	explicit State( CollectorProjectedExecutorDependencies value)
		: dependencies( std::move( value)), cancelled( std::make_shared<std::atomic_bool>( false)),
		  pool( dependencies.clock, cancelled)
	{
		// 不完全な依存を通常HTTPや可変入力へ補完しません。
		if( !dependencies.campaign || !dependencies.campaign->jobCount() ||
		   !dependencies.createClient || !dependencies.start) {
			throw std::invalid_argument( "projected collector dependencies") ;
		}
	}
	/** @brief 第一の全体errorを保持し、未終端だけを停止します。
	 * @param[in] error 原監督error。利用者取消しは0です。
	 */
	void stop( DWORD error)
	{
		// 後発障害で最初の数値を置き換えません。
		if( report.error == 0U) {
			report.error = error ;
		}

		closed = true ;
		pool.requestStop( cancelled->load( std::memory_order_acquire)
							 ? CollectorIoCause::CANCELLED
							 : CollectorIoCause::SHARED_STOP) ;
	}
	/** @brief 同一slotの原失敗を追加allocationなしで保持します。
	 * @param[in] index 対象slot。
	 * @param[in] domain 原codeのdomain。
	 * @param[in] code 32bitの原値。
	 */
	void failSetup( std::size_t index, CollectorIoErrorDomain domain, std::uint32_t code)
	{
		pool.controls_[index]->fail( CollectorIoCause::SETUP,
									{domain, code, CollectorIoStage::SETUP}, false) ;
	}
	/** @brief 元先着causeを維持して射影を確定し、一度だけ通知します。
	 * @param[in] index 秘密資源とCOMを回収済みのslot。
	 */
	void finish( std::size_t index) noexcept
	{
		auto &value = slots[index].value ;	// 通知前の唯一writerです。
		(void)pool.controls_[index]->finish() ;
		value.io = pool.controls_[index]->snapshot() ;
		// 全解析完了を先着原因と別に確認します。
		const bool parsed =
			value.parser && value.parser->status == CollectorParserStatus::COMPLETED ;
		const bool limited = value.parser &&
							 value.parser->status == CollectorParserStatus::LIMIT_EXCEEDED &&
							 value.io.cause == CollectorIoCause::PARSER &&
							 value.io.error.domain == value.parser->error.domain &&
							 value.io.error.code == value.parser->error.code &&
							 // 先行停止を上限に変換しません。
							 value.io.error.stage == value.parser->error.stage ;
		// 元COMPLETEだけが暫定の正常配列を親へ渡せます。
		if( value.io.cause == CollectorIoCause::COMPLETE && parsed) {
			value.reason = CollectorProjectedWorkerReason::NONE ;
		} else {
			value.projection = {} ;
			// 明示LIMITと元PARSERが一致する場合だけHELDです。OOMは失敗のままです。
			if( limited) {
				value.projection.status = CollectorProjectionDraftStatus::HELD ;
				value.reason			= CollectorProjectedWorkerReason::PROJECTION_LIMIT ;
			} else {
				value.reason = CollectorProjectedWorkerReason::IO_FAILURE ;
			}
		}

		DWORD error{} ;	// 親の保存を許さない全体障害だけを公開します。
		// Clock異常では終了時刻を推測しません。
		if( !value.io.finishedUtcMillis || value.io.cause == CollectorIoCause::CLOCK) {
			error = ERROR_INVALID_DATA ;
		}

		// 未回収nativeは元副診断を優先します。
		if( error == 0U && !value.io.nativeReleased) {
			error = value.io.native && value.io.native->stage == CollectorIoStage::CLEANUP
						? value.io.native->code
						: ERROR_INVALID_STATE ;
		}

		// 起動障害では次予約を止めます。
		if( error == 0U && value.io.cause == CollectorIoCause::SETUP) {
			error = value.io.error.code ;
		}

		// 別workerの第一障害を後発で置き換えません。
		if( error != 0U) {
			DWORD expected{} ;	// 先着errorのみを格納します。
			(void)fatal.compare_exchange_strong( expected, error, std::memory_order_release) ;
		}

		{
			const std::lock_guard lock( mutex) ;	// 完了済み値をready bitと共に公開します。
			ready[index] = true ;
		}
		changed.notify_all() ;
	}
	/** @brief 元prepared入力と同じGETだけを解析する専用callbackです。
	 * @param[in] index Workerが所有するslot。
	 */
	void getAndProject( std::size_t index)
	{
		auto &slot	 = slots[index] ;					// Workerの同期scopeだけで借用します。
		auto  client = dependencies.createClient() ;	// COM初期化後だけ構築します。
		// 欠けたclientをnativeへ補完しません。
		if( !client) {
			failSetup( index, CollectorIoErrorDomain::HRESULT_ERROR,
					  static_cast<std::uint32_t>( E_POINTER)) ;
			return ;
		}

		std::optional<CollectorMetadataBody>  body ;	// 秘密本文はこのscope内で全破棄します。
		std::shared_ptr<CollectorHttpControl> control ;	// 同じGETの元control。
		const auto							  error = client->getMetadataBody(
			   *dependencies.campaign, slot.value.binding.jobIndex, slot.value.binding, slot.permit,
			   L"", body, slot.value.http, control) ;	// Validator pin前は無条件一回だけです。
		// HTTP自身のtyped failureはそのまま維持します。
		if( error != 0) {
			// Preflightなどで原controlへ未反映の場合だけSETUPで止めます。
			if( pool.controls_[index]->snapshot().cause == CollectorIoCause::NONE) {
				failSetup( index, CollectorIoErrorDomain::HRESULT_ERROR,
						  static_cast<std::uint32_t>( error)) ;
			}

			return ;
		}

		// 正常200本文と元controlが揃わない場合に成功を合成しません。
		if( !body || control != pool.controls_[index]) {
			failSetup( index, CollectorIoErrorDomain::WIN32_ERROR, ERROR_INVALID_STATE) ;
			return ;
		}

		slot.value.parser = projectCollectorMetadataBodyWithDiagnostics(
			std::move( *body), *dependencies.campaign, slot.value.binding.jobIndex,
			slot.value.projection, dependencies.diagnostics) ;
		// 消費拒否などwrapperが未記録の失敗もPROJECTの原型を保ちます。
		if( slot.value.parser->status != CollectorParserStatus::COMPLETED &&
		   pool.controls_[index]->snapshot().cause == CollectorIoCause::NONE) {
			control->fail( CollectorIoCause::PARSER, slot.value.parser->error, false) ;
		}
	}
	/** @brief COM・秘密値のscopeを閉じてから一回finishします。
	 * @param[in] index 一回起動したslot。
	 */
	void worker( std::size_t index) noexcept
	{
		bool apartment{} ;	// Init成功した場合だけuninitします。
		try {
			winrt::init_apartment( winrt::apartment_type::multi_threaded) ;
			apartment = true ;
			// 起動と競合した取消しではclientを作りません。
			if( cancelled->load( std::memory_order_acquire)) {
				pool.controls_[index]->requestStop() ;
			} else {
				getAndProject( index) ;
			}
		} catch( const winrt::hresult_error &error) {
			failSetup( index, CollectorIoErrorDomain::HRESULT_ERROR,
					  static_cast<std::uint32_t>( error.code().value)) ;
		} catch( const std::bad_alloc &) {
			failSetup( index, CollectorIoErrorDomain::HRESULT_ERROR,
					  static_cast<std::uint32_t>( E_OUTOFMEMORY)) ;
		} catch( ...) {
			failSetup( index, CollectorIoErrorDomain::HRESULT_ERROR,
					  static_cast<std::uint32_t>( E_FAIL)) ;
		}

		// Client・本文・候補は既にscopeを抜けています。
		if( apartment) {
			winrt::uninit_apartment() ;
		}

		finish( index) ;
	}
	/** @brief Prepared jobの文字列だけを予約前に所有します。
	 * @param[in] index 次に使うslot。
	 * @param[in] jobIndex Readinessが示した共有job。
	 * @return 元prepared jobが存在する場合true。
	 */
	bool prepareBinding( std::size_t index, std::size_t jobIndex)
	{
		const auto *prepared =
			// 不変の元jobだけを使用します。
			dependencies.campaign->job( jobIndex) ;
		// 別inputのjobを予約しません。
		if( !prepared) {
			return false ;
		}

		const auto &job = prepared->value() ;	// 全文字列のcopyは永続予約の前です。
		// 親が予約前に所有する結合。
		auto	   &binding	  = slots[index].value.binding ;
		binding.mode		  = CollectorRecoveryDispatch::Mode::PROJECTED ;
		binding.jobIndex	  = job.jobIndex ;
		binding.generationKey = dependencies.campaign->generationKey() ;
		binding.jobKey		  = job.jobKey ;
		binding.requestKey	  = job.requestKey ;
		binding.cacheBinding  = job.cacheBinding ;
		binding.scopeSha256	  = job.scopeSha256 ;
		binding.source		  = job.source ;
		return true ;
	}
} ;

/** @see local_collector_projected_executor.h */
CollectorProjectedClientFactory collectorNativeProjectedClientFactory()
{
	// Clientの生成先は呼出しworkerのMTAだけです。
	return [] { return std::make_unique<LocalCollectorHttpClient>() ; } ;
}

/** @see local_collector_projected_executor.h */
LocalCollectorProjectedExecutor::LocalCollectorProjectedExecutor(
	CollectorProjectedExecutorDependencies dependencies)
	: state_( std::make_unique<State>( std::move( dependencies)))
{
}

/** @see local_collector_projected_executor.h */
LocalCollectorProjectedExecutor::~LocalCollectorProjectedExecutor()
{
	// 通常の明示join後は確定観測と取消し報告を変更しません。
	if( !state_->joined) {
		state_->stop( 0U) ;
		(void)join() ;
	}
}

/** @see local_collector_projected_executor.h */
DWORD LocalCollectorProjectedExecutor::startNext( LocalCollectorRecovery &recovery)
{
	auto &state = *state_ ;	// Parent writerだけが予約・報告を変更します。
	// 未回収の起動障害を次予約で追い越しません。
	if( state.fatal.load( std::memory_order_acquire) != 0U) {
		state.stop( state.fatal.load( std::memory_order_acquire)) ;
	}

	// 取消しを新しい予約前に反映します。
	if( state.cancelled->load( std::memory_order_acquire)) {
		state.stop( 0U) ;
		return ERROR_OPERATION_ABORTED ;
	}

	// Join開始済みは新規起動しません。
	if( state.closed) {
		return state.report.error != 0U ? state.report.error : ERROR_INVALID_STATE ;
	}

	// 同じGを別workspaceで作った場合も予約元を混在させません。
	if( state.recoveryOwner && state.recoveryOwner != recovery.projectedOwnerToken()) {
		state.stop( ERROR_INVALID_DATA) ;
		return state.report.error ;
	}

	state.recoveryOwner = recovery.projectedOwnerToken() ;
	// 別世代でprepared入力を流用しません。
	if( recovery.generationKey() != state.dependencies.campaign->generationKey()) {
		state.stop( ERROR_INVALID_DATA) ;
		return state.report.error ;
	}

	// 未精算slotは使い回しません。
	if( state.report.reserved == state.slots.size()) {
		return ERROR_RETRY ;
	}

	const auto index = state.report.reserved ;	// 次の空slot。Poolの元順序と一致します。
	auto	  &slot	 = state.slots[index] ;		// 次に予約する固定slot。
	try {
		const auto sample = state.dependencies.clock() ;	// Readinessは予約ではありません。
		CollectorRecoveryReadiness readiness ;				// 元監督による非変更照会。
		// 元readinessの原error。
		const auto				   readError =
			recovery.readinessProjected( sample.utcMillis, sample.steadyMillis, readiness) ;
		// 壊れた時計や状態を待機へ変換しません。
		if( readError != 0U) {
			state.stop( readError) ;
			return readError ;
		}

		// 同group・間隔・終端をこの接続器が迂回しません。
		if( readiness.kind != CollectorRecoveryReadinessKind::READY || !readiness.jobIndex) {
			return ERROR_RETRY ;
		}

		// 所有文字列の確保は全て予約前です。
		if( !state.prepareBinding( index, *readiness.jobIndex)) {
			state.stop( ERROR_INVALID_DATA) ;
			return state.report.error ;
		}

		const auto error = state.pool.reserveProjected( recovery, slot.permit) ;	// 元永続予約。
		// 保存失敗ではworkerを起動しません。
		if( error != 0U) {
			// 正当な枠待ち以外は原errorで全体停止します。
			if( error != ERROR_RETRY) {
				state.stop( error) ;
			}

			return error ;
		}

		slot.occupied = true ;
		++state.report.reserved ;
		const auto &original		 = *slot.permit.binding() ;	// 予約後は数値だけを代入します。
		auto	   &binding			 = slot.value.binding ;		// 元時刻を結合する所有値。
		binding.startedUtcMillis	 = original.startedUtcMillis ;
		binding.anchorUtcMillis		 = original.anchorUtcMillis ;
		binding.anchorSteadyMillis	 = original.anchorSteadyMillis ;
		binding.deadlineUtcMillis	 = original.deadlineUtcMillis ;
		binding.deadlineSteadyMillis = original.deadlineSteadyMillis ;
		// 元scope・jobが変わった場合は一回もGETせず失敗を確定します。
		if( !sameCollectorRecoveryDispatch( binding, original)) {
			state.failSetup( index, CollectorIoErrorDomain::WIN32_ERROR, ERROR_INVALID_DATA) ;
			state.finish( index) ;
			state.stop( ERROR_INVALID_DATA) ;
			return state.report.error ;
		}

		// Stateは全joinまで存続し、slotは再使用されません。
		slot.worker = state.dependencies.start( [&state, index] { state.worker( index) ; }) ;
		// Detached／空threadを成功起動へ数えません。
		if( !slot.worker.joinable()) {
			throw std::system_error( static_cast<int>( ERROR_INVALID_STATE), std::system_category()) ;
		}

		++state.report.started ;
		return ERROR_SUCCESS ;
	} catch( const std::system_error &error) {
		const auto code = static_cast<DWORD>( error.code().value()) ;	// 起動APIの元数値。
		// 永続予約済みだけを送信0の固定結果へ確定します。
		if( slot.occupied) {
			state.failSetup( index, CollectorIoErrorDomain::WIN32_ERROR, code) ;
		}

		state.stop( code) ;
	} catch( const std::bad_alloc &) {
		// 予約後OOMでもbindingは既に所有しており追加文字列を作りません。
		if( slot.occupied) {
			state.failSetup( index, CollectorIoErrorDomain::HRESULT_ERROR,
							static_cast<DWORD>( E_OUTOFMEMORY)) ;
		}

		state.stop( static_cast<DWORD>( E_OUTOFMEMORY)) ;
	} catch( ...) {
		// 未分類の依存失敗を成功へ丸めません。
		if( slot.occupied) {
			state.failSetup( index, CollectorIoErrorDomain::HRESULT_ERROR,
							static_cast<DWORD>( E_FAIL)) ;
		}

		state.stop( static_cast<DWORD>( E_FAIL)) ;
	}

	// 起動していない予約済みslotにも通知を一度発行します。
	if( slot.occupied) {
		state.finish( index) ;
	}

	return state.report.error ;
}

/** @see local_collector_projected_executor.h */
CollectorProjectedExecutorReport LocalCollectorProjectedExecutor::join()
{
	auto &state = *state_ ;	// 親writerだけがjoinと報告を更新します。
	// 二重joinは新たなfinishや通知を発生させません。
	if( state.joined) {
		return state.report ;
	}

	state.closed = true ;
	// 全予約の通知を受理するまで有限間隔で停止・第一errorを確認します。
	while( state.report.notified < state.report.reserved) {
		const auto fatal = state.fatal.load( std::memory_order_acquire) ;	// Workerの第一全体障害。
		// 取消し・clock・setupは全未終端workerへ反映します。
		if( fatal != 0U || state.cancelled->load( std::memory_order_acquire)) {
			state.stop( fatal) ;
		}

		// Ready bitを消費し、mutexを解放してからjoinします。
		for( std::size_t index = 0U; index < state.report.reserved; ++index) {
			bool ready{} ;	// 一回通知の所有権を親へ移します。
			{
				// 通知bitの読取りと一回消費だけを保護。
				const std::lock_guard lock( state.mutex) ;
				ready = std::exchange( state.ready[index], false) ;
			}
			// 未通知slotの結果へはアクセスしません。
			if( !ready) {
				continue ;
			}

			auto &slot = state.slots[index] ;	// 通知後もjoin完了まで所有を保持します。
			// 起動失敗の空threadはjoin件数へ含めません。
			if( slot.worker.joinable()) {
				slot.worker.join() ;
				++state.report.joined ;
			}

			++state.report.notified ;
		}

		// 全通知の後に不要な待機をしません。
		if( state.report.notified < state.report.reserved) {
			std::unique_lock lock( state.mutex) ;	// 待機中はlockを解放します。
			state.changed.wait_for( lock, std::chrono::milliseconds( 500), [&state] {
				// 通知bitだけを検査し、結果を先読みしません。
				for( const auto ready : state.ready) {
					// 一つでも完了したら親へ戻します。
					if( ready) {
						return true ;
					}
				}

				return false ;
			}) ;
		}
	}

	// 最後のworkerが通知直前に発見した障害も報告します。
	if( state.fatal.load( std::memory_order_acquire) != 0U) {
		state.stop( state.fatal.load( std::memory_order_acquire)) ;
	}

	state.report.cancellationRequested = state.cancelled->load( std::memory_order_acquire) ;
	state.joined					   = true ;
	return state.report ;
}

/** @see local_collector_projected_executor.h */
void LocalCollectorProjectedExecutor::requestStop() noexcept
{
	state_->cancelled->store( true, std::memory_order_release) ;
	state_->changed.notify_all() ;
}

/** @see local_collector_projected_executor.h */
const CollectorProjectedWorkerResult *LocalCollectorProjectedExecutor::result(
	std::size_t slot) const noexcept
{
	// 全join前・未予約slotは親から結果を読めません。
	if( !state_->joined || slot >= state_->report.reserved) {
		return nullptr ;
	}

	return &state_->slots[slot].value ;
}

/** @see local_collector_projected_executor.h */
DWORD LocalCollectorProjectedExecutor::takeInitialPreparation(
	const std::shared_ptr<const std::byte> &owner, std::size_t slot,
	const CollectorPreparedProjectedCampaign *&campaign,
	const CollectorProjectedWorkerResult	 *&worker)
{
	campaign	= nullptr ;
	worker		= nullptr ;
	auto &state = *state_ ;	// 親writerだけが使用する非公開入口。
	// 元のSETUP／CLOCK等を関係errorで上書きしません。
	if( state.report.error != 0U) {
		return state.report.error ;
	}

	// 一回性・全回収・元所有者を全て満たした結果だけを取り出します。
	if( !owner || owner != state.recoveryOwner || !state.joined ||
	   state.report.joined != state.report.started ||
	   state.report.notified != state.report.reserved || slot >= state.report.reserved ||
	   !state.slots[slot].occupied || state.slots[slot].preparationTaken) {
		return ERROR_INVALID_DATA ;
	}

	state.slots[slot].preparationTaken = true ;
	campaign						   = state.dependencies.campaign.get() ;
	worker							   = &state.slots[slot].value ;
	return ERROR_SUCCESS ;
}
/** @see local_collector_projected_executor.h */
void LocalCollectorProjectedExecutor::failPreparation( DWORD error)
{
	state_->stop( error) ;
}
} // namespace drivercrate
