//------------------------------------------------------------------------------
/**
 * @file local_collector_shared_update.cpp
 * @brief 元予約と二制御行を固定観測から非通信で精算します。
 * @version 01.00.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  固定操作codecと元課金／待機の再導出を追加。
 * </pre>
 *
 * @note 保存・新予約・日次切替・CACHE・公式応答検査を実行しません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#include "local_collector_shared_update.h"
#include "local_collector_projected_json.h"
#include <algorithm>
#include <cstddef>
#include <new>
#include <utility>

namespace drivercrate {
namespace {
using collector_projected_json::Reader ;
using collector_projected_json::Writer ;
using collector_projected_json::Failure ;
using collector_projected_json::Status ;
/** @brief 元形式拒否を数値で伝播します。
 * @param[in] valid 必須条件。
 * @param[in] code 元拒否code。
 * @throws DWORD 条件不成立時。
 */
void require( const bool valid, const DWORD code = ERROR_INVALID_DATA)
{
	// 容量と関係不成立を区別します。
	if( !valid) {
		throw code ;
	}
}
/** @brief 他codecの第一codeをそのまま保持します。
 * @param[in] code 元codec結果。
 * @throws DWORD 不成立の元数値。
 */
void io( const DWORD code)
{
	require( code == 0U, code) ;
}
/** @brief 有限ASCIIの元identityを復号します。
 * @param[in,out] r 固定順reader。
 * @param[in] limit 解除後の最大byte。
 * @return 正規化しない元identity。
 */
std::wstring text( Reader &r, const std::size_t limit)
{
	const auto raw = r.text( limit) ;	// ASCII以外をsource keyへ正規化しません。
	require( std::all_of( raw.begin(), raw.end(), []( const unsigned char c) { return c < 128U ; })) ;
	return {raw.begin(), raw.end()} ;
}
/** @brief bool以外を数値や文字列から補完しません。
 * @param[in,out] r 固定順reader。
 * @return 元bool。
 */
bool boolean( Reader &r)
{
	const auto raw = r.value() ;	// 固定二値だけを認めます。
	require( raw == "true" || raw == "false") ;
	return raw == "true" ;
}
/** @brief 有限identity・時計・未観測量の表現を検査します。
 * @param[in] op 元操作。
 * @throws DWORD 不正操作。
 */
void valid( const CollectorSharedSettlement &op)
{
	const auto &q = op.request ;		// 元予約identityです。
	const auto &o = op.observation ;	// 元待機観測です。
	require( !q.group.empty() && q.group.size() <= 96U &&
			std::all_of( q.group.begin(), q.group.end(),
						[]( const wchar_t c) {
							return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
								   (c >= L'0' && c <= L'9') || c == L'-' || c == L'_' || c == L'.' ;
						}) &&
			collector_projected_json::isHash( q.requestKey) &&
			collector_projected_json::isHash( q.generationKey) &&
			collector_projected_json::isHash( q.jobKey)) ;
	require( op.started >= 1000U && op.started % 1000U == 0U && op.started <= op.finished &&
			op.finished <= op.accepted && op.accepted <= 4102444799999ULL &&
			op.receivedBytes <= 8U * 1024U * 1024U && (op.bytesKnown || op.receivedBytes == 0U) &&
			o.status <= 599U && (o.status == 0U || o.status >= 100U) &&
			o.retryAfterUtcMillis <= 253402300799999ULL &&
			(!o.successful ||
			 ((o.status == 200U || o.status == 304U) && !o.needsReview && !o.challenge))) ;
	require( !op.interrupted || (!op.bytesKnown && !o.successful && o.status == 0U &&
								o.retryAfterUtcMillis == 0U && !o.needsReview && !o.challenge)) ;
}
/** @brief 全fieldを固定順の有限本文へ出力します。
 * @param[in] op 形式検査済み操作。
 * @return Canonical元操作。
 */
std::string encode( const CollectorSharedSettlement &op)
{
	valid( op) ;
	Writer w( 4096U) ;	// 元操作だけの独立byte上限です。
	w.append( "{\"schema\":\"collector-shared-settlement-v1\",\"group\":") ;
	w.wideText( op.request.group) ;
	w.append( ",\"request\":") ;
	w.wideText( op.request.requestKey) ;
	w.append( ",\"generation\":") ;
	w.wideText( op.request.generationKey) ;
	w.append( ",\"job\":") ;
	w.wideText( op.request.jobKey) ;
	w.append( ",\"started\":") ;
	w.number( op.started) ;
	w.append( ",\"finished\":") ;
	w.number( op.finished) ;
	w.append( ",\"accepted\":") ;
	w.number( op.accepted) ;
	w.append( ",\"successful\":") ;
	w.append( op.observation.successful ? "true" : "false") ;
	w.append( ",\"status\":") ;
	w.number( op.observation.status) ;
	w.append( ",\"retryAfter\":") ;
	w.number( op.observation.retryAfterUtcMillis) ;
	w.append( ",\"needsReview\":") ;
	w.append( op.observation.needsReview ? "true" : "false") ;
	w.append( ",\"challenge\":") ;
	w.append( op.observation.challenge ? "true" : "false") ;
	w.append( ",\"bytesKnown\":") ;
	w.append( op.bytesKnown ? "true" : "false") ;
	w.append( ",\"receivedBytes\":") ;
	w.number( op.receivedBytes) ;
	w.append( ",\"interrupted\":") ;
	w.append( op.interrupted ? "true" : "false") ;
	w.append( "}") ;
	return w.take() ;
}
} // namespace
/** @see local_collector_shared_update.h */
DWORD encodeCollectorSharedSettlement( const CollectorSharedSettlement &operation,
									  std::string					  &bytes) noexcept
{
	bytes.clear() ;
	try {
		bytes = encode( operation) ;
		return 0U ;
	} catch( const DWORD code) {
		return code ;
	} catch( const Failure f) {
		return f.status == Status::SIZE_LIMIT ? 68U : 13U ;
	} catch( const std::bad_alloc &) {
		return 8U ;
	} catch( ...) {
		return 13U ;
	}
}
/** @see local_collector_shared_update.h */
DWORD decodeCollectorSharedSettlement( const std::string_view	 bytes,
									  CollectorSharedSettlement &operation) noexcept
{
	operation = {} ;
	try {
		Reader					  r( bytes, 4096U) ;	// 全fieldと元byteを完全消費します。
		CollectorSharedSettlement op ;					// 最後まで公開しない元操作です。
		r.literal( "{\"schema\":\"collector-shared-settlement-v1\",\"group\":") ;
		op.request.group = text( r, 96U) ;
		r.literal( ",\"request\":") ;
		op.request.requestKey = text( r, 64U) ;
		r.literal( ",\"generation\":") ;
		op.request.generationKey = text( r, 64U) ;
		r.literal( ",\"job\":") ;
		op.request.jobKey = text( r, 64U) ;
		r.literal( ",\"started\":") ;
		op.started = r.number() ;
		r.literal( ",\"finished\":") ;
		op.finished = r.number() ;
		r.literal( ",\"accepted\":") ;
		op.accepted = r.number() ;
		r.literal( ",\"successful\":") ;
		op.observation.successful = boolean( r) ;
		r.literal( ",\"status\":") ;
		const auto status = r.number() ;	// DWORDへ縮小する前に有限範囲を検査します。
		require( status <= 599U) ;
		op.observation.status = static_cast<std::uint32_t>( status) ;
		r.literal( ",\"retryAfter\":") ;
		op.observation.retryAfterUtcMillis = r.number() ;
		r.literal( ",\"needsReview\":") ;
		op.observation.needsReview = boolean( r) ;
		r.literal( ",\"challenge\":") ;
		op.observation.challenge = boolean( r) ;
		r.literal( ",\"bytesKnown\":") ;
		op.bytesKnown = boolean( r) ;
		r.literal( ",\"receivedBytes\":") ;
		op.receivedBytes = r.number() ;
		r.literal( ",\"interrupted\":") ;
		op.interrupted = boolean( r) ;
		r.literal( "}") ;
		r.finish() ;
		require( encode( op) == bytes) ;
		operation = std::move( op) ;
		return 0U ;
	} catch( const DWORD code) {
		return code ;
	} catch( const Failure f) {
		return f.status == Status::SIZE_LIMIT ? 68U : 13U ;
	} catch( const std::bad_alloc &) {
		return 8U ;
	} catch( ...) {
		return 13U ;
	}
}
/** @see local_collector_shared_update.h */
DWORD deriveCollectorSharedSettlement( const CollectorSharedLedgerSnapshot &before,
									  const CollectorSharedSettlement	  &operation,
									  CollectorSharedLedgerSnapshot		  &after,
									  CollectorSharedSettlementDelta	  &delta) noexcept
{
	after = {} ;
	delta = {} ;
	try {
		CollectorSharedLedgerBytes verified ;	// 他行も含む元台帳全体の関係を検査します。
		io( encodeCollectorSharedLedger( before, verified)) ;
		valid( operation) ;
		require( operation.accepted >= before.lastUtcMillis) ;
		const auto &q		= operation.request ;					// 元予約identityです。
		const auto	request = before.requests.find( q.requestKey) ;	// 元開始intentを選びます。
		require( request != before.requests.end() && request->second.control.group == q.group &&
				request->second.control.generation == q.generationKey &&
				request->second.control.job == q.jobKey &&
				request->second.control.started == operation.started) ;
		const auto row = std::find_if( before.budget.reservations.begin(),
									  before.budget.reservations.end(), [&]( const auto &r) {
										  return r.campaign == q.generationKey && r.job == q.jobKey ;
									  }) ; // 一予約です。
		require( row != before.budget.reservations.end() && row->phase == 0U &&
				row->group == q.group && row->started * 1000U == operation.started &&
				operation.receivedBytes <= row->maximum) ;
		CollectorWaitSnapshot waitBefore{
			before.lastUtcMillis,
			{{L"g-" + q.group, before.groups.at( q.group)},
			 {L"r-" + q.requestKey, request->second.control}}} ;	// 二行だけです。
		CollectorWaitSnapshot waitAfter ;							// 既存24時間待機・reviewを同じ関数で再導出します。
		require( prepareCollectorWaitSettlement(
			waitBefore, q, operation.observation, operation.started, operation.finished,
			operation.accepted, operation.accepted, false, waitAfter)) ;
		auto	   pending = before ;	// 他行・CACHE・元日を変更しない複製です。
		const auto index =
			// 元一予約ordinal。
			static_cast<std::size_t>( row - before.budget.reservations.begin()) ;
		auto &settled		   = pending.budget.reservations[index] ;	// 元phase0だけを閉じます。
		settled.phase		   = operation.interrupted ? 2U : 1U ;
		settled.charged		   = operation.bytesKnown ? operation.receivedBytes : settled.maximum ;
		pending.budget.lastUtc = std::max( pending.budget.lastUtc, operation.accepted / 1000U) ;
		pending.lastUtcMillis  = operation.accepted ;
		pending.groups.at( q.group)				  = waitAfter.controls.at( L"g-" + q.group) ;
		pending.requests.at( q.requestKey).control = waitAfter.controls.at( L"r-" + q.requestKey) ;
		io( encodeCollectorSharedLedger( pending, verified)) ;
		CollectorSharedSettlementDelta change ;	// 全前後状態ではなく元一予約／二行だけです。
		change.operation = encode( operation) ;
		require( encodeCollectorBudgetSnapshot( {before.budget.day, before.budget.lastUtc, {*row}},
											  change.budgetBefore) &&
				encodeCollectorBudgetSnapshot(
					{pending.budget.day, pending.budget.lastUtc, {settled}}, change.budgetAfter) &&
				encodeCollectorWaitSnapshot( waitBefore, change.waitBefore) &&
				encodeCollectorWaitSnapshot( waitAfter, change.waitAfter)) ;
		after = std::move( pending) ;
		delta = std::move( change) ;
		return 0U ;
	} catch( const DWORD code) {
		return code ;
	} catch( const Failure f) {
		return f.status == Status::SIZE_LIMIT ? 68U : 13U ;
	} catch( const std::bad_alloc &) {
		return 8U ;
	} catch( ...) {
		return 13U ;
	}
}
} // namespace drivercrate
