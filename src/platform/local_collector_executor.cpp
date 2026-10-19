//------------------------------------------------------------------------------
/**
 * @file local_collector_executor.cpp
 * @brief WorkerのCOM・client寿命とv3保存後のslot解放を実装します。
 * @version 01.01.00
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
 * Ver.01.01.00 Shunji Ogawa  2026/09/27  取消し伝播・全体診断を補修。
 * </pre>
 *
 * @note 開発用の有限収集に限定し、製品の取得・導入を許可しません。
 * @see docs/adr/0218-collector-controlled-http-lifetime.md
 */
//------------------------------------------------------------------------------
#include "local_collector_executor.h"
#include "local_collector_http_client.h"
#include <winrt/base.h>
#include <algorithm>
#include <array>
#include <condition_variable>
#include <chrono>
#include <mutex>
#include <new>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace drivercrate {
namespace {
/** @brief 元分類を有限な保存名へ変換します。
 * @param[in] domain 元観測のdomain。
 * @return 固定名。未知値は保存前検査で拒否する表現です。
 */
std::wstring_view domainName( CollectorIoErrorDomain domain)
{
	// 原値の意味を保存名へ保つ。
	switch( domain) {
		// 成功。
		case CollectorIoErrorDomain::NONE:
			return L"NONE" ;
		// Win32原値。
		case CollectorIoErrorDomain::WIN32_ERROR:
			return L"WIN32" ;
		// Winsock原値。
		case CollectorIoErrorDomain::WINSOCK_ERROR:
			return L"WINSOCK" ;
		// HRESULT原bit pattern。
		case CollectorIoErrorDomain::HRESULT_ERROR:
			return L"HRESULT" ;
		// HTTP status。
		case CollectorIoErrorDomain::HTTP:
			return L"HTTP" ;
		// 固定parser拒否。
		case CollectorIoErrorDomain::PARSER:
			return L"PARSER" ;
	}

	return L"INVALID" ;
}
} // namespace
/** @see local_collector_executor.h */
CollectorExecutorStart collectorNativeThreadStarter()
{
	return []( std::function<void()> entry) { return std::thread( std::move( entry)) ; } ;
}
/** @see local_collector_executor.h */
CollectorExecutorGet makeNativeCollectorExecutorGet( std::vector<LocalCollectorTarget> targets)
{
	return [targets = std::move( targets)](
			   std::size_t index, const CollectorRecoveryDispatch &binding,
			   CollectorHttpPermit				  &permit,
			   CollectorControlledHttpObservation &observation) -> NativeError {
		// 不正job indexで別製品を代用しない。
		if( index >= targets.size()) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		LocalCollectorHttpClient			  client ;	// 当workerのCOM scopeより短い専用client。
		std::wstring						  text ;	// Parser未接続の一時本文。
		std::shared_ptr<CollectorHttpControl> control ;	// Scope中だけの同じ制御。
		return client.get( targets[index], binding, permit, L"", text, observation, control) ;
	} ;
}
/** @brief Slotと結果を予約前に所有し、単一writerが後処理します。 */
struct LocalCollectorExecutor::State {
	/** @brief 実行から保存まで占有する一枠です。 */
	struct Slot {
		/// 監督が所有しworkerが一度claimする許可。
		CollectorHttpPermit				   permit ;
		/// Native APIを所有するthread。監督がjoinします。
		std::thread						   worker ;
		/// COM利用後に返る所有HTTP結果。
		CollectorControlledHttpObservation http ;
		/// Workerが資源解放後に確定した固定観測。
		CollectorIoSnapshot				   io ;
		/// 通知前にthread作成が失敗した場合もtrueです。
		bool							   occupied{} ;
	} ;
	/// 予約前に固定する時計・GET・開始依存。
	CollectorExecutorDependencies	  dependencies ;
	/// 予約前に確保し全controlが共有するrun取消しsignal。
	std::shared_ptr<std::atomic_bool> cancelled ;
	/// 四controlを予約前に確保する発行元。
	CollectorHttpPermitPool			  pool ;
	/// 四件より増えない結果領域。
	std::array<Slot, 4>				  slots ;
	/// Ready bitだけを保護し、I/O・join・保存中は保持しません。
	std::mutex						  mutex ;
	/// Ready bitと受付停止の通知。
	std::condition_variable			  changed ;
	/// Queueに追加allocationしない固定結果通知。
	std::array<bool, 4>				  ready{} ;
	/// 同じexecutorを別runへ再使用しません。
	bool							  used{} ;
	/// 新規dispatch停止後だけtrueです。
	bool							  stopping{} ;
	/// 保存失敗後の追加store更新を禁止します。
	bool							  writesStopped{} ;
	/// 当runの固定数値集計。
	CollectorExecutorReport			  report ;

	/** @brief 四枠と全依存を予約前に検査します。
     * @param[in] value 明示依存。
     */
	explicit State( CollectorExecutorDependencies value)
		: dependencies( std::move( value)), cancelled( std::make_shared<std::atomic_bool>( false)),
		  pool( dependencies.clock, cancelled)
	{
		// 不完全なfixtureをnative処理へ補完しない。
		if( !dependencies.get || !dependencies.start) {
			throw std::invalid_argument( "collector executor dependencies") ;
		}
	}
	/** @brief 第一errorを保存し、全未終端controlへ停止を通知します。
     * @param[in] error 元監督error。正常停止は0です。
     * @param[in] cause CANCELLEDまたはSHARED_STOP。
     */
	void stop( DWORD error, CollectorIoCause cause = CollectorIoCause::SHARED_STOP)
	{
		// 後続errorで第一の保存／起動失敗を上書きしない。
		if( report.error == 0U) {
			report.error = error ;
		}

		stopping = true ;
		pool.requestStop( cause) ;
		changed.notify_all() ;
	}
	/** @brief 保存後・予約前後にrun取消しを観測します。
	 * @return 取消しが公開されている場合trueです。
	 */
	bool observeCancellation()
	{
		const bool requested = cancelled->load( std::memory_order_acquire) ;	// 共有signalだけを読む。
		// 第一errorと未終端slotだけに停止を反映する。
		if( requested && !stopping) {
			stop( 0U, CollectorIoCause::CANCELLED) ;
		}

		return requested ;
	}
	/** @brief Slotの確定結果を通知し、queue容量待ちを行いません。
     * @param[in] index 所有slot。
     */
	void notify( std::size_t index) noexcept
	{
		{
			const std::lock_guard lock( mutex) ;	// Bitの公開だけを保護する。
			ready[index] = true ;
		}
		changed.notify_all() ;
	}
	/** @brief Worker例外を追加allocationなしの固定結果へ変換します。
     * @param[in] index 元slot。
     * @param[in] domain 元数値のdomain。
     * @param[in] code 原32 bit。
     */
	void fail( std::size_t index, CollectorIoErrorDomain domain, std::uint32_t code)
	{
		pool.controls_[index]->fail( CollectorIoCause::SETUP,
									{domain, code, CollectorIoStage::SETUP}, false) ;
	}
	/** @brief Worker内のCOMとclientを解放してから観測を確定します。
     * @param[in] index 元slot。
     */
	void worker( std::size_t index) noexcept
	{
		auto &slot = slots[index] ;	// 当threadだけが通知前の結果を書きます。
		bool  apartment{} ;			// Init成功時だけuninitする。
		try {
			winrt::init_apartment( winrt::apartment_type::multi_threaded) ;
			apartment = true ;
			// 起動と競合した取消しでもGET依存へ進まず元予約を回収する。
			if( cancelled->load( std::memory_order_acquire)) {
				pool.controls_[index]->requestStop() ;
			} else {
				const auto error =
					dependencies.get( slot.permit.binding()->jobIndex, *slot.permit.binding(),
									 slot.permit, slot.http) ;	// 一回だけGET。
				// GET依存が原失敗をまだ反映していない場合も成功にしない。
				if( error != 0 &&
				   pool.controls_[index]->snapshot().cause == CollectorIoCause::NONE) {
					fail( index, CollectorIoErrorDomain::HRESULT_ERROR,
						 static_cast<std::uint32_t>( error)) ;
				}
			}
		} catch( const winrt::hresult_error &error) {
			fail( index, CollectorIoErrorDomain::HRESULT_ERROR,
				 static_cast<std::uint32_t>( error.code().value)) ;
		} catch( const std::bad_alloc &) {
			fail( index, CollectorIoErrorDomain::HRESULT_ERROR,
				 static_cast<std::uint32_t>( E_OUTOFMEMORY)) ;
		} catch( ...) {
			fail( index, CollectorIoErrorDomain::HRESULT_ERROR, static_cast<std::uint32_t>( E_FAIL)) ;
		}

		// Client scopeが終わりCOM利用を終了してから結果を公開する。
		if( apartment) {
			winrt::uninit_apartment() ;
		}

		(void)pool.controls_[index]->finish() ;
		slot.io = pool.controls_[index]->snapshot() ;
		notify( index) ;
	}
	/** @brief Join後だけ元観測を基本応答へ結合します。
     * @param[in] slot 終了済み所有結果。
     * @param[in] accepted 元監督受領UTC。
     * @return Parser未接続のHELDまたは型付き失敗。
     */
	CollectorRecoveryResponse response( const Slot &slot, std::uint64_t accepted)
	{
		CollectorRecoveryResponse result ;	// JSONやWinRT objectをworkerから受け取らない。
		result.state			   = slot.io.cause == CollectorIoCause::COMPLETE
										 ? CollectorCampaignJobState::HELD
										 : CollectorCampaignJobState::FAILED ;
		result.finishedUtcMillis   = slot.io.finishedUtcMillis.value() ;
		result.acceptedUtcMillis   = accepted ;
		result.bytesKnown		   = slot.io.bytesKnown ;
		result.receivedBytes	   = slot.io.bytesKnown ? slot.io.lowerBytes : 0U ;
		result.sentRequests		   = slot.io.sends ;
		result.status			   = slot.http.status ;
		result.error			   = slot.io.error.code ;
		result.errorDomain		   = domainName( slot.io.error.domain) ;
		result.retryAfterUtcMillis = slot.http.retryAfterUtcMillis.value_or( 0U) ;
		result.needsReview		   = slot.http.retryAfterNeedsReview ;
		result.bodySha256		   = slot.http.bodySha256 ;
		return result ;
	}
	/** @brief Ready一件を取り出し、join・保存後だけslotを解放します。
     * @param[in,out] recovery 同じwriterの復旧監督。
     * @return 一件処理した場合true。
     */
	bool consume( LocalCollectorRecovery &recovery)
	{
		std::size_t index = slots.size() ;	// 欠測sentinel。
		{
			const std::lock_guard lock( mutex) ;	// Bitだけを取り出す。
			// 固定四枠から一件だけを選ぶ。通知順の時刻を捏造しない。
			for( std::size_t candidate = 0U; candidate < ready.size(); ++candidate) {
				// Ready以外のworkerをjoin待ちしない。
				if( ready[candidate]) {
					ready[candidate] = false ;
					index			 = candidate ;
					break ;
				}
			}
		}
		// 通知がなければ有限waitへ戻る。
		if( index == slots.size()) {
			return false ;
		}

		auto &slot = slots[index] ;	// Join後だけ結果を読む。
		// 作成失敗slotにはjoin可能threadがない。
		if( slot.worker.joinable()) {
			slot.worker.join() ;
			++report.joined ;
		}

		// 個別HTTP拒否は他sourceを止めず件数へ記録する。
		if( slot.io.cause != CollectorIoCause::COMPLETE) {
			++report.failedJobs ;
		}

		// 時計欠測を架空finishedへ補完しない。
		if( !slot.io.finishedUtcMillis || !slot.io.elapsedMillis ||
		   slot.io.cause == CollectorIoCause::CLOCK) {
			writesStopped = true ;
			stop( ERROR_INVALID_DATA) ;
		}

		// 第一保存失敗後は回収だけ行う。
		if( !writesStopped) {
			try {
				const auto sample = dependencies.clock() ;	// 元終了後の監督受領時刻。
				const auto result =
					// 文字列確保は監督でのみ行う。
					response( slot, sample.utcMillis) ;
				const auto error = recovery.acceptControlled(
					*slot.permit.binding(), result, slot.io, sample.utcMillis,
					sample.steadyMillis) ;	// 元観測を省略しない。
				// 保存・精算の第一errorを保持して以降のstore更新を止める。
				if( error != 0U) {
					writesStopped = true ;
					stop( error) ;
				} else {
					++report.saved ;
				}
			} catch( ...) {
				writesStopped = true ;
				stop( ERROR_INVALID_DATA) ;
			}
		}

		// 個別HTTP原因を全体の資源解放errorへ取り違えない。
		if( !slot.io.nativeReleased) {
			const auto cleanupError =
				slot.io.native && slot.io.native->domain == CollectorIoErrorDomain::WIN32_ERROR &&
						slot.io.native->stage == CollectorIoStage::CLEANUP
					? slot.io.native->code
					: ERROR_INVALID_STATE ;	// 原値欠測は固定の解放未確認。
			stop( cleanupError) ;
		}
		// 解放済みの準備失敗は元errorを保持して新規受付を止める。
		else if( slot.io.cause == CollectorIoCause::SETUP) {
			stop( slot.io.error.code != 0U ? slot.io.error.code : ERROR_INVALID_STATE) ;
		}

		// 保存失敗slotは再利用せず、未精算予約を次回回収へ残す。
		if( !writesStopped) {
			slot.permit			  = CollectorHttpPermit{} ;
			slot.http			  = {} ;
			slot.io				  = {} ;
			slot.occupied		  = false ;
			pool.occupied_[index] = false ;
		} else {
			slot.occupied = false ;
		}

		return true ;
	}
	/** @brief 状態破棄前に全threadを所有者監督が回収します。 */
	void joinAll() noexcept
	{
		pool.requestStop( CollectorIoCause::SHARED_STOP) ;
		// Detachも強制終了も使わず、全所有threadを回収する。
		for( auto &slot : slots) {
			// 終了通知未読でも破棄前にjoinする。
			if( slot.worker.joinable()) {
				slot.worker.join() ;
			}
		}
	}
} ;
/** @see local_collector_executor.h */
LocalCollectorExecutor::LocalCollectorExecutor( CollectorExecutorDependencies dependencies)
	: state_( std::make_unique<State>( std::move( dependencies)))
{
}
/** @see local_collector_executor.h */
LocalCollectorExecutor::~LocalCollectorExecutor()
{
	state_->joinAll() ;
}
/** @see local_collector_executor.h */
void LocalCollectorExecutor::requestStop() noexcept
{
	state_->cancelled->store( true, std::memory_order_release) ;
	state_->changed.notify_all() ;
}
/** @see local_collector_executor.h */
CollectorExecutorReport LocalCollectorExecutor::run( LocalCollectorRecovery &recovery)
{
	auto &state = *state_ ;	// 監督threadだけが固定集計を更新する。
	// 同じrunや所有threadを再使用しない。
	if( std::exchange( state.used, true)) {
		auto refused	= state.report ;	// 元runの数値を保持した拒否結果。
		refused.error	= ERROR_INVALID_STATE ;
		refused.outcome = CollectorExecutorOutcome::FAILED ;
		return refused ;
	}

	try {
		// 未予約が長期延期または全job終端となるまで通知・共通選択を使う。
		for( ;;) {
			// 別threadの取消しを監督から全controlへ通知する。
			(void)state.observeCancellation() ;

			// 通知済み結果を四件まで回収してから新予約へ進む。
			while( state.consume( recovery)) {
			}

			// 結果保存中に公開された取消しを次予約より前に観測する。
			(void)state.observeCancellation() ;

			const auto active =
				std::count_if( state.slots.begin(), state.slots.end(),
							  []( const auto &slot) { return slot.occupied ; }) ;	// 結果待ちも含む。
			// 停止後も全通知・joinが終わるまでは帰らない。
			if( state.stopping && active == 0) {
				break ;
			}

			std::uint64_t waitMillis = 500U ;	// 取消しと結果通知で早期復帰する有限wait。
			bool		  dispatched{} ;		// 予約成功時だけ次の候補へ進む。
			// Pool上限は通知・join・保存後まで占有する。
			if( !state.stopping && state.pool.occupied() < 4U) {
				const auto sample = state.dependencies.clock() ;	// 候補照会と同じ二clock。
				CollectorRecoveryReadiness readiness ;				// 非変更照会。
				// 同じ監督の共通選択結果と原error。
				const auto				   error =
					recovery.readiness( sample.utcMillis, sample.steadyMillis, readiness) ;
				// 状態異常後に予約を追加しない。
				if( error != 0U) {
					state.stop( error) ;
				}
				// 共通判定が開始可能な一件だけを永続予約する。
				else if( readiness.kind == CollectorRecoveryReadinessKind::READY) {
					// 照会と予約の間に届いた取消しでは予約を増やさない。
					if( state.observeCancellation()) {
						continue ;
					}

					const auto vacant =
						std::find_if( state.slots.begin(), state.slots.end(), []( const auto &slot) {
							return !slot.occupied ;
						}) ; // 四枠の空き。
					const auto index = static_cast<std::size_t>(
						// 保存まで同じslot。
						std::distance( state.slots.begin(), vacant)) ;
					const auto reserved =
						// 永続保存後だけ開始する。
						state.pool.reserve( recovery, vacant->permit) ;
					// 保存失敗ではworkerを作らない。
					if( reserved != 0U) {
						state.stop( reserved) ;
					} else {
						vacant->occupied = true ;
						++state.report.reserved ;
						state.report.peakSlots =
							std::max( state.report.peakSlots, state.pool.occupied()) ;
						// 永続予約中の取消しは未送信のv3として回収し、workerを作らない。
						if( state.observeCancellation()) {
							(void)state.pool.controls_[index]->finish() ;
							vacant->io = state.pool.controls_[index]->snapshot() ;
							state.notify( index) ;
						} else {
							// 取消し未観測の元予約だけを所有threadへ渡す。
							try {
								vacant->worker = state.dependencies.start(
									[&state, index] { state.worker( index) ; }) ;
								// 終了責任のないthreadを所有workerとしない。
								if( !vacant->worker.joinable()) {
									throw std::system_error( ERROR_INVALID_HANDLE,
															std::system_category()) ;
								}

								++state.report.started ;
							} catch( const std::system_error &error) {
								const auto code = static_cast<std::uint32_t>(
									// 元開始失敗の原値。
									error.code().value()) ;
								state.fail( index, CollectorIoErrorDomain::WIN32_ERROR, code) ;
								(void)state.pool.controls_[index]->finish() ;
								vacant->io = state.pool.controls_[index]->snapshot() ;
								state.notify( index) ;
								state.stop( code) ;
							} catch( const std::bad_alloc &) {
								state.fail( index, CollectorIoErrorDomain::HRESULT_ERROR,
										   static_cast<std::uint32_t>( E_OUTOFMEMORY)) ;
								(void)state.pool.controls_[index]->finish() ;
								vacant->io = state.pool.controls_[index]->snapshot() ;
								state.notify( index) ;
								state.stop( static_cast<DWORD>( E_OUTOFMEMORY)) ;
							} catch( ...) {
								state.fail( index, CollectorIoErrorDomain::HRESULT_ERROR,
										   static_cast<std::uint32_t>( E_FAIL)) ;
								(void)state.pool.controls_[index]->finish() ;
								vacant->io = state.pool.controls_[index]->snapshot() ;
								state.notify( index) ;
								state.stop( static_cast<DWORD>( E_FAIL)) ;
							}
						}

						dispatched = true ;
					}
				}
				// 全所有workerの回収後だけ長期延期または終端を返す。
				else if( active == 0 &&
						(readiness.kind == CollectorRecoveryReadinessKind::DEFERRED ||
						 readiness.kind == CollectorRecoveryReadinessKind::TERMINAL)) {
					state.report.outcome =
						readiness.kind == CollectorRecoveryReadinessKind::TERMINAL
							? CollectorExecutorOutcome::TERMINAL
							: CollectorExecutorOutcome::DEFERRED ;
					break ;
				}
				// 外部予約を所有threadなしで待機し続けない。
				else if( active == 0 &&
						readiness.kind == CollectorRecoveryReadinessKind::ACTIVE_WAIT) {
					// 他の未回収予約を所有workerなしで待ち続けない。
					state.stop( ERROR_INVALID_STATE) ;
				}
				// 共通間隔の最短wakeだけ有限waitへ結合する。
				else if( readiness.kind == CollectorRecoveryReadinessKind::INTERVAL_WAIT) {
					waitMillis = std::min( waitMillis, readiness.waitMillis) ;
				}
			}

			// 新規dispatch成功時だけ有限四枠の次候補を直ちに調べる。
			if( dispatched) {
				continue ;
			}

			std::unique_lock lock( state.mutex) ;	// 条件待機中はreleaseされ、I/Oや保存を行わない。
			state.changed.wait_for(
				lock, std::chrono::milliseconds( std::max<std::uint64_t>( 1U, waitMillis)), [&state] {
					return (!state.stopping && state.cancelled->load( std::memory_order_acquire)) ||
						   std::any_of( state.ready.begin(), state.ready.end(),
									   []( bool value) { return value ; }) ;
				}) ;
		}
	} catch( ...) {
		state.stop( ERROR_INVALID_DATA) ;
		state.writesStopped = true ;
		// Entry外の例外でも全slotを回収し、未保存を成功へしない。
		for( ;;) {
			// 最後の終了通知まで有限waitで回収する。
			while( state.consume( recovery)) {
			}

			// 全占有slotの通知を回収したら終了する。
			if( std::none_of( state.slots.begin(), state.slots.end(),
							[]( const auto &slot) { return slot.occupied ; })) {
				break ;
			}

			std::unique_lock lock( state.mutex) ;	// Notifyだけを待つ。
			state.changed.wait_for( lock, std::chrono::milliseconds( 500), [&state] {
				return std::any_of( state.ready.begin(), state.ready.end(),
								   []( bool value) { return value ; }) ;
			}) ;
		}
	}

	// 第一errorを取消し表示で隠さない。
	if( state.report.error != 0U) {
		state.report.outcome = CollectorExecutorOutcome::FAILED ;
	}
	// Errorなしの取消しだけを正常な回収済み取消しとして返す。
	else if( state.cancelled->load( std::memory_order_acquire)) {
		state.report.outcome = CollectorExecutorOutcome::CANCELLED ;
	}

	return state.report ;
}
} // namespace drivercrate
