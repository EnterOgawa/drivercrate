//------------------------------------------------------------------------------
/**
 * @file local_collector_http_control.cpp
 * @brief 永続予約permitと二clock期限・原値観測を実装します。
 * @version 01.05.00
 * @date 2026/09/28
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/27  一回許可・有限clock・失敗時観測を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/27  制御予約へ接続し元結合判定を共用。
 * Ver.01.02.00 Shunji Ogawa  2026/09/27  保存中もrun取消しを観測。
 * Ver.01.03.00 Shunji Ogawa  2026/09/28  PARSE直前の実時計値を借用可能にする。
 * Ver.01.04.00 Shunji Ogawa  2026/09/28  新世代の永続射影予約へ許可発行を接続。
 * Ver.01.05.00 Shunji Ogawa  2026/10/02  予約前の実所有登録と全controlの強所有を追加。
 * </pre>
 *
 * @note 通信・thread起動・応答保存は行いません。解放は後続executorがjoin・保存後に担当します。
 * @see docs/adr/0218-collector-controlled-http-lifetime.md
 */
//------------------------------------------------------------------------------
#include "local_collector_http_control.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace drivercrate {
namespace {
// 既存監督と同じ通常時計の上端。
constexpr std::uint64_t LAST_UTC = 4102444799999ULL ;

} // namespace

/** @see local_collector_http_control.h */
CollectorHttpControl::CollectorHttpControl( CollectorHttpClock					   clock,
										   std::shared_ptr<const std::atomic_bool> cancellation)
	: clock_( std::move( clock)), cancellation_( std::move( cancellation))
{
	// 無制御のnative既定へfallbackしない。
	if( !clock_) {
		throw std::invalid_argument( "collector clock required") ;
	}
}

/** @see local_collector_http_control.h */
void CollectorHttpControl::arm( CollectorRecoveryDispatch &&dispatch) noexcept
{
	binding_					   = std::move( dispatch) ;
	previous_					   = {binding_.anchorUtcMillis, binding_.anchorSteadyMillis} ;
	observation_				   = {} ;
	observation_.deadlineUtcMillis = binding_.deadlineUtcMillis ;
	observation_.elapsedMillis	   = 0U ;
	armed_						   = true ;
	claimed_					   = false ;
	sendCommitted_				   = false ;
	clockValid_					   = true ;
}

/** @see local_collector_http_control.h */
void CollectorHttpControl::stopLocked( const CollectorIoCause cause,
									  const CollectorIoError error) noexcept
{
	// 観測先着の原因を後続errorで変更しない。
	if( observation_.cause == CollectorIoCause::NONE) {
		observation_.cause = cause ;
		observation_.stage = error.stage ;
		observation_.error = error ;
	}
}

/** @see local_collector_http_control.h */
bool CollectorHttpControl::sampleLocked( const bool checkDeadline)
{
	CollectorHttpClockSample current ;	// Callbackから得た観測だけを使う。
	try {
		current = clock_() ;
	} catch( ...) {
		clockValid_ = false ;
	}

	// 欠測・後退・範囲外を現在値へ丸めず永続的に停止する。
	if( !clockValid_ || current.utcMillis < previous_.utcMillis || current.utcMillis > LAST_UTC ||
	   current.steadyMillis < previous_.steadyMillis ||
	   current.steadyMillis - binding_.anchorSteadyMillis >= 9007199254740992ULL) {
		clockValid_ = false ;
		observation_.elapsedMillis.reset() ;
		stopLocked( CollectorIoCause::CLOCK,
				   {CollectorIoErrorDomain::WIN32_ERROR, ERROR_INVALID_DATA, observation_.stage}) ;
		return false ;
	}

	previous_				   = current ;
	observation_.elapsedMillis = current.steadyMillis - binding_.anchorSteadyMillis ;
	// 保存中も次checkpointで取消しを受理し、通知threadの時刻を後付けしない。
	if( cancellation_ && cancellation_->load( std::memory_order_acquire)) {
		// 外部停止の初回観測だけを保持する。
		if( !observation_.stopElapsedMillis) {
			observation_.stopElapsedMillis = observation_.elapsedMillis ;
		}

		stopLocked( CollectorIoCause::CANCELLED, {CollectorIoErrorDomain::WIN32_ERROR,
												 ERROR_OPERATION_ABORTED, observation_.stage}) ;
		return false ;
	}

	// 二clockの片方だけでも期限到達なら次APIを開始しない。
	if( checkDeadline && (current.utcMillis >= binding_.deadlineUtcMillis ||
						 current.steadyMillis >= binding_.deadlineSteadyMillis)) {
		stopLocked( CollectorIoCause::DEADLINE,
				   {CollectorIoErrorDomain::WIN32_ERROR, ERROR_TIMEOUT, observation_.stage}) ;
		return false ;
	}

	return true ;
}

/** @see local_collector_http_control.h */
bool CollectorHttpControl::claim( const void *client, const CollectorRecoveryDispatch &binding)
{
	const std::lock_guard lock( mutex_) ;	// 同じslotを二clientへ発行しない。
	// 空・二重・別結合を送信可能にしない。
	if( !armed_ || claimed_ || client == nullptr ||
	   !sameCollectorRecoveryDispatch( binding_, binding)) {
		stopLocked( CollectorIoCause::SETUP, {CollectorIoErrorDomain::WIN32_ERROR,
											 ERROR_INVALID_PARAMETER, CollectorIoStage::SETUP}) ;
		return false ;
	}

	claimed_ = true ;
	return sampleLocked() && observation_.cause == CollectorIoCause::NONE ;
}

/** @see local_collector_http_control.h */
std::uint32_t CollectorHttpControl::begin( const CollectorIoStage stage,
										  const std::uint32_t	 phaseLimitMillis)
{
	const std::lock_guard lock( mutex_) ;	// 開始確定だけを短いlock内で行う。
	// 未発行・未claim・終端済みのI/Oを許可しない。
	if( !armed_ || !claimed_ || observation_.sealed ||
	   observation_.cause != CollectorIoCause::NONE) {
		return 0U ;
	}

	observation_.stage = stage ;
	// 不定timeout・未知stage・二重SENDは固定拒否する。
	if( phaseLimitMillis == 0U || stage < CollectorIoStage::SETUP ||
	   stage >= CollectorIoStage::COMPLETE || (stage == CollectorIoStage::SEND && sendCommitted_) ||
	   (stage >= CollectorIoStage::RECEIVE && stage <= CollectorIoStage::PROJECT &&
		observation_.sends != 1U)) {
		stopLocked( CollectorIoCause::SETUP,
				   {CollectorIoErrorDomain::WIN32_ERROR, ERROR_INVALID_PARAMETER, stage}) ;
		return 0U ;
	}

	// 開始を確定する直前に時計を採取する。
	if( !sampleLocked()) {
		return 0U ;
	}

	// 実API回数とは別に一度のSEND開始を確定する。
	if( stage == CollectorIoStage::SEND) {
		sendCommitted_ = true ;
	}

	return static_cast<std::uint32_t>(
		std::min( {static_cast<std::uint64_t>( phaseLimitMillis),
				  binding_.deadlineUtcMillis - previous_.utcMillis,
				  binding_.deadlineSteadyMillis - previous_.steadyMillis})) ;
}

/** @see local_collector_http_control.h */
bool CollectorHttpControl::noteSendCall()
{
	const std::lock_guard lock( mutex_) ;	// 明示的な一APIだけを計数する。
	// 開始未確定や二回目を追加送信へ変換しない。
	if( !armed_ || !claimed_ || observation_.sealed ||
	   observation_.cause != CollectorIoCause::NONE) {
		return false ;
	}

	// API呼出し前の論理矛盾は送信0または既観測1を保持する。
	if( !sendCommitted_ || observation_.sends != 0U) {
		stopLocked( CollectorIoCause::SETUP, {CollectorIoErrorDomain::WIN32_ERROR,
											 ERROR_INVALID_STATE, CollectorIoStage::SEND}) ;
		return false ;
	}

	// 取消し・期限がこの検査の後なら当API一回をin-flightとして扱う。
	if( !sampleLocked()) {
		return false ;
	}

	observation_.sends = 1U ;
	return true ;
}

/** @see local_collector_http_control.h */
bool CollectorHttpControl::noteRead( const std::uint32_t requested, const std::uint32_t received)
{
	const std::lock_guard lock( mutex_) ;	// 成功read量は取消しより先に保持する。
	// 確定済み結果は拒否時にも変更しない。
	if( observation_.sealed) {
		return false ;
	}

	// 結果確定後の変更と未送信の架空計数を拒否する。
	if( !armed_ || !claimed_ || observation_.sends != 1U || requested == 0U || requested > 65536U ||
	   received > requested ||
	   requested > binding_.source.maximumResponseBytes - observation_.lowerBytes) {
		observation_.bytesKnown = false ;
		stopLocked( CollectorIoCause::SETUP, {CollectorIoErrorDomain::WIN32_ERROR,
											 ERROR_INVALID_DATA, CollectorIoStage::READ}) ;
		return false ;
	}

	observation_.lowerBytes += received ;
	return true ;
}

/** @see local_collector_http_control.h */
bool CollectorHttpControl::noteHeaders()
{
	const std::lock_guard lock( mutex_) ;	// Retry-After秒を後で結合し直さない。
	// Header時刻は一度だけ実送信後に観測する。
	if( !claimed_ || observation_.sealed || observation_.sends != 1U ||
	   observation_.headerUtcMillis || observation_.cause != CollectorIoCause::NONE ||
	   !sampleLocked()) {
		return false ;
	}

	observation_.headerUtcMillis = previous_.utcMillis ;
	return true ;
}

/** @see local_collector_http_control.h */
void CollectorHttpControl::fail( const CollectorIoCause cause, const CollectorIoError error,
								const bool bytesUnknown)
{
	const std::lock_guard lock( mutex_) ;	// 原値と先着原因を別々に保持する。
	// 確定済み結果は後続の失敗通知で再採点しない。
	if( observation_.sealed) {
		return ;
	}

	// 失敗により欠測した全受信量を0へ補わない。
	if( bytesUnknown) {
		observation_.bytesKnown = false ;
	}

	// 一つ目のnative失敗だけを副診断にも残す。
	if( !observation_.native && error.code != 0U && error.stage >= CollectorIoStage::RESERVATION &&
	   error.stage <= CollectorIoStage::COMPLETE &&
	   (error.domain == CollectorIoErrorDomain::WIN32_ERROR ||
		error.domain == CollectorIoErrorDomain::WINSOCK_ERROR ||
		error.domain == CollectorIoErrorDomain::HRESULT_ERROR)) {
		observation_.native = error ;
	}

	// 呼出し側の不正な終端値を成功へ解釈しない。
	if( cause <= CollectorIoCause::COMPLETE || cause > CollectorIoCause::CLOCK || error.code == 0U ||
	   error.domain <= CollectorIoErrorDomain::NONE ||
	   error.domain > CollectorIoErrorDomain::PARSER ||
	   error.stage < CollectorIoStage::RESERVATION || error.stage > CollectorIoStage::COMPLETE) {
		stopLocked( CollectorIoCause::SETUP, {CollectorIoErrorDomain::WIN32_ERROR,
											 ERROR_INVALID_PARAMETER, observation_.stage}) ;
	} else {
		stopLocked( cause, error) ;
	}

	// 原errorの確定後にだけclockを検査し、API先着を保持する。
	(void)sampleLocked() ;
}

/** @see local_collector_http_control.h */
void CollectorHttpControl::requestStop( const CollectorIoCause cause)
{
	const std::lock_guard lock( mutex_) ;	// API待機を保持しない先着確定lock。
	// COMPLETEや確定済み結果を取消しへ変えない。
	if( observation_.sealed || observation_.cause == CollectorIoCause::COMPLETE || !armed_) {
		return ;
	}

	const bool sampled = sampleLocked( false) ;	// 同時発見はCLOCK→取消し→期限。
	// 初回停止の実経過だけを記録する。
	if( sampled && !observation_.stopElapsedMillis) {
		observation_.stopElapsedMillis = observation_.elapsedMillis ;
	}

	// 呼出し側が原因を自作してCOMPLETE等にしない。
	if( cause != CollectorIoCause::CANCELLED && cause != CollectorIoCause::SHARED_STOP) {
		stopLocked( CollectorIoCause::SETUP, {CollectorIoErrorDomain::WIN32_ERROR,
											 ERROR_INVALID_PARAMETER, observation_.stage}) ;
	} else {
		stopLocked( cause, {CollectorIoErrorDomain::WIN32_ERROR, ERROR_OPERATION_ABORTED,
						   observation_.stage}) ;
	}
}

/** @see local_collector_http_control.h */
void CollectorHttpControl::setNativeReleased( const bool released)
{
	const std::lock_guard lock( mutex_) ;	// 所有workerの解放結果だけを反映する。
	// 結果確定後は資源診断も変更しない。
	if( !observation_.sealed) {
		observation_.nativeReleased = released ;
	}
}

/** @see local_collector_http_control.h */
bool CollectorHttpControl::finish()
{
	const std::lock_guard lock( mutex_) ;	// Cleanup後にだけ最終結果を確定する。
	// 未予約・未claimでもSETUPや取消しの結果は回収できる。
	if( !armed_ || observation_.sealed) {
		return false ;
	}

	(void)sampleLocked() ;
	// Native解放と実送信がないものを正常完了にしない。
	if( !observation_.nativeReleased || !claimed_ || observation_.sends != 1U) {
		stopLocked( CollectorIoCause::SETUP, {CollectorIoErrorDomain::WIN32_ERROR,
											 ERROR_INVALID_STATE, CollectorIoStage::CLEANUP}) ;
	}

	// 時計が壊れた場合は架空の終了UTCを保存しない。
	if( clockValid_) {
		observation_.finishedUtcMillis = previous_.utcMillis ;
	}

	stopLocked( CollectorIoCause::COMPLETE,
			   {CollectorIoErrorDomain::NONE, 0U, CollectorIoStage::COMPLETE}) ;
	observation_.sealed = true ;
	return true ;
}

/** @see local_collector_http_control.h */
CollectorIoSnapshot CollectorHttpControl::snapshot() const
{
	const std::lock_guard lock( mutex_) ;	// 整合する一観測を返す。
	return observation_ ;
}

/** @see local_collector_http_control.h */
std::optional<CollectorHttpClockSample> CollectorHttpControl::lastClockSample() const
{
	const std::lock_guard lock( mutex_) ;	// beginの実採取値と状態を一緒に読む。
	return clockValid_ && armed_ ? std::optional<CollectorHttpClockSample>{previous_}
								 : std::nullopt ;
}

/** @see local_collector_http_control.h */
const CollectorRecoveryDispatch &CollectorHttpControl::binding() const noexcept
{
	return binding_ ;
}

/** @see local_collector_http_control.h */
std::shared_ptr<CollectorHttpControl> CollectorHttpPermit::claim(
	const void *client, const CollectorRecoveryDispatch &binding)
{
	// Poolが永続予約したもの以外にcontrolを返さない。
	if( !control_ || !control_->claim( client, binding)) {
		return {} ;
	}

	return control_ ;
}

/** @see local_collector_http_control.h */
bool CollectorHttpPermit::present() const noexcept
{
	return control_ != nullptr ;
}

/** @see local_collector_http_control.h */
const CollectorRecoveryDispatch *CollectorHttpPermit::binding() const noexcept
{
	return control_ ? &control_->binding() : nullptr ;
}

/** @see local_collector_http_control.h */
CollectorHttpPermitPool::CollectorHttpPermitPool(
	const CollectorHttpClock &clock, std::shared_ptr<const std::atomic_bool> cancellation)
	: clock_( clock)
{
	// 空依存を実clockへ補完しない。
	if( !clock_) {
		throw std::invalid_argument( "collector clock required") ;
	}

	// 全四slotを台帳予約より前に確保する。
	for( auto &control : controls_) {
		control = std::make_shared<CollectorHttpControl>( clock_, cancellation) ;
	}
}

/** @see local_collector_http_control.h */
DWORD CollectorHttpPermitPool::reserve( LocalCollectorRecovery &recovery,
									   CollectorHttpPermit	  &permit)
{
	return reserveForMode( recovery, permit, false) ;
}

/** @see local_collector_http_control.h */
DWORD CollectorHttpPermitPool::reserveProjected( LocalCollectorRecovery &recovery,
												CollectorHttpPermit	   &permit)
{
	return reserveForMode( recovery, permit, true) ;
}

/** @see local_collector_http_control.h */
DWORD CollectorHttpPermitPool::reserveForMode( LocalCollectorRecovery &recovery,
											  CollectorHttpPermit &permit, const bool projected)
{
	// 別writerの予約を同じslot集合へ混在させない。
	if( recoveryOwner_ && recoveryOwner_ != recovery.projectedOwnerToken()) {
		return ERROR_INVALID_PARAMETER ;
	}

	// 既存許可を上書きして未回収slotを失わない。
	if( permit.present() || stopped_) {
		return stopped_ ? ERROR_OPERATION_ABORTED : ERROR_INVALID_PARAMETER ;
	}

	// 最初の予約より前に実所有を登録し、閉鎖中はclock／storeを触りません。
	if( !httpActivity_) {
		const auto code = recovery.acquireHttpActivity( httpActivity_) ;	// 第一登録結果です。
		// 私有所有不成立では永続予約や許可発行へ進みません。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		recoveryOwner_ = recovery.projectedOwnerToken() ;
		// 空slotも元登録へ結合し、持ち出したcontrolが残る間は閉鎖しません。
		for( auto &control : controls_) {
			control->httpActivity_ = httpActivity_ ;
		}
	}

	// 実行・結果待ち・保存中・join待ちを合計四件へ制限する。
	for( std::size_t index = 0U; index < controls_.size(); ++index) {
		// 回収・保存前のslotは使い回さない。
		if( occupied_[index]) {
			continue ;
		}

		// 旧clientがcontrolを保持したまま新jobへarmして停止先を混同しない。
		if( controls_[index].use_count() != 1) {
			stopped_ = true ;
			return ERROR_INVALID_STATE ;
		}

		CollectorHttpClockSample sample ;	// 保存直前の共通clock対。
		try {
			sample = clock_() ;
		} catch( ...) {
			stopped_ = true ;
			return ERROR_INVALID_DATA ;
		}

		CollectorRecoveryDispatch dispatch ;	// 文字列確保はrecoveryの保存前に完了する。
		const auto				  error =
			// 一回の永続予約。
			projected ? recovery.reserveProjected( sample.utcMillis, sample.steadyMillis, dispatch)
					  : recovery.reserveControlled( sample.utcMillis, sample.steadyMillis, dispatch) ;
		// 保存失敗では許可を発行しない。元errorをそのまま返す。
		if( error != 0U) {
			return error ;
		}

		occupied_[index] = true ;
		controls_[index]->arm( std::move( dispatch)) ;
		permit.control_ = controls_[index] ;
		return ERROR_SUCCESS ;
	}

	return ERROR_RETRY ;
}

/** @see local_collector_http_control.h */
void CollectorHttpPermitPool::requestStop( const CollectorIoCause cause)
{
	stopped_ = true ;
	// 発行済みの固定四slotへ通知する。別threadからnative handleを閉じない。
	for( std::size_t index = 0U; index < controls_.size(); ++index) {
		// 未予約slotへ取消し結果を作らない。
		if( occupied_[index]) {
			controls_[index]->requestStop( cause) ;
		}
	}
}

/** @see local_collector_http_control.h */
std::size_t CollectorHttpPermitPool::occupied() const noexcept
{
	return static_cast<std::size_t>( std::count( occupied_.begin(), occupied_.end(), true)) ;
}
} // namespace drivercrate
