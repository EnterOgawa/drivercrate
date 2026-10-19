//------------------------------------------------------------------------------
/**
 * @file local_collector_shared_operation.cpp
 * @brief 予約・日次・CACHE参照の固定操作を非通信で再導出します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  有限codec・予算待機と元参照比較を追加。
 * </pre>
 *
 * @note 純coreです。実HTTP・CACHE本文・seal・実時計を検証済みとしません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#include "local_collector_shared_operation.h"
#include "local_collector_projected_json.h"
#include <algorithm>
#include <cstddef>
#include <iomanip>
#include <new>
#include <sstream>
#include <utility>

namespace drivercrate {
namespace {
using collector_projected_json::Reader ;
using collector_projected_json::Writer ;
using collector_projected_json::Failure ;
using collector_projected_json::Status ;
/** @brief 元数値拒否を伝播します。
 * @param[in] ok 必須条件。
 * @param[in] code 元数値code。
 * @throws DWORD 条件不成立時。
 */
void require( const bool ok, const DWORD code = 13U)
{
	// 容量・待機と不正関係を区別します。
	if( !ok) {
		throw code ;
	}
}
/** @brief 元codec結果を変更しません。
 * @param[in] code 元codec code。
 */
void io( const DWORD code)
{
	require( code == 0U, code) ;
}
/** @brief 有限ASCII tokenを正規化せず検査します。
 * @param[in] value 元group。
 * @return 元規約に一致する場合true。
 */
bool token( const std::wstring_view value)
{
	return !value.empty() && value.size() <= 96U &&
		   std::all_of( value.begin(), value.end(), []( const wchar_t c) {
			   return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
					  (c >= L'0' && c <= L'9') || c == L'-' || c == L'_' || c == L'.' ;
		   }) ;
}
/** @brief 元identityを検査します。
 * @param[in] q 元要求tuple。
 */
void identity( const CollectorWaitRequest &q)
{
	require( token( q.group) && collector_projected_json::isHash( q.requestKey) &&
			collector_projected_json::isHash( q.generationKey) &&
			collector_projected_json::isHash( q.jobKey)) ;
}
/** @brief UTCの有限範囲を検査します。
 * @param[in] utc UTC millisecond。
 */
void clock( const std::uint64_t utc)
{
	require( utc >= 1000U && utc <= 4102444799999ULL) ;
}
/** @brief UTCからOSの有限暦変換でJST日を得ます。
 * @param[in] utc UTC millisecond。
 * @return YYYYMMDD。元時計は変更しません。
 */
std::wstring day( const std::uint64_t utc)
{
	clock( utc) ;
	ULARGE_INTEGER ticks{} ;	// 有限UTCへJST九時間を加えたFILETIMEです。
	ticks.QuadPart = (utc / 1000U + 32400U + 11644473600ULL) * 10000000ULL ;
	const FILETIME file{ticks.LowPart, ticks.HighPart} ;	// 同じ暦変換入力です。
	SYSTEMTIME	   time{} ;									// UTC APIへJST offset済み値を渡します。
	require( FileTimeToSystemTime( &file, &time) != FALSE) ;
	std::wostringstream s ;	// 固定八桁の有限日付です。
	s << std::setfill( L'0') << std::setw( 4) << time.wYear << std::setw( 2) << time.wMonth
	  << std::setw( 2) << time.wDay ;
	return s.str() ;
}
/** @brief 三hash参照だけをcanonicalで表現します。
 * @param[in] ref 元未検証参照。nulloptも保存意味を持ちます。
 * @return 固定参照本文。
 */
std::string reference( const std::optional<CollectorSharedCacheReference> &ref)
{
	// 根拠なしを空hashへ補完しません。
	if( !ref) {
		return "null" ;
	}

	require( collector_projected_json::isHash( ref->segment) &&
			collector_projected_json::isHash( ref->cacheSha256) &&
			collector_projected_json::isHash( ref->binding)) ;
	Writer w( 1024U) ;	// 任意pathを受け取らない三hashです。
	w.append( "{\"segment\":") ;
	w.wideText( ref->segment) ;
	w.append( ",\"cacheSha256\":") ;
	w.wideText( ref->cacheSha256) ;
	w.append( ",\"binding\":") ;
	w.wideText( ref->binding) ;
	w.append( "}") ;
	return w.take() ;
}
/** @brief 固定ASCII本文をUnicodeへ補完せず読みます。
 * @param[in,out] r 元reader。
 * @param[in] limit 最大byte。
 * @return 元ASCII文字列。
 */
std::wstring text( Reader &r, const std::size_t limit)
{
	const auto s = r.text( limit) ;	// 元ASCIIのbyte範囲を固定します。
	require( std::all_of( s.begin(), s.end(), []( const unsigned char c) { return c < 128U ; })) ;
	return {s.begin(), s.end()} ;
}
/** @brief 三hashの固定fieldを完全消費します。
 * @param[in] bytes 元参照本文。
 * @return 元参照またはnullopt。
 */
std::optional<CollectorSharedCacheReference> readReference( const std::string_view bytes)
{
	// 根拠なしを元成功へ読み替えません。
	if( bytes == "null") {
		return std::nullopt ;
	}

	Reader						  r( bytes, 1024U) ;	// 元三field以外を認めません。
	CollectorSharedCacheReference value ;				// 全fieldを読んでから返します。
	r.literal( "{\"segment\":") ;
	value.segment = text( r, 64U) ;
	r.literal( ",\"cacheSha256\":") ;
	value.cacheSha256 = text( r, 64U) ;
	r.literal( ",\"binding\":") ;
	value.binding = text( r, 64U) ;
	r.literal( "}") ;
	r.finish() ;
	require( reference( value) == bytes) ;
	return value ;
}
/** @brief Tupleを固定順へ出力します。
 * @param[in,out] w 有限writer。
 * @param[in] q 元tuple。
 */
void writeIdentity( Writer &w, const CollectorWaitRequest &q)
{
	identity( q) ;
	w.append( ",\"group\":") ;
	w.wideText( q.group) ;
	w.append( ",\"request\":") ;
	w.wideText( q.requestKey) ;
	w.append( ",\"generation\":") ;
	w.wideText( q.generationKey) ;
	w.append( ",\"job\":") ;
	w.wideText( q.jobKey) ;
}
/** @brief Tupleを固定順で復号します。
 * @param[in,out] r 有限reader。
 * @return 全identityを形式検査したtuple。
 */
CollectorWaitRequest readIdentity( Reader &r)
{
	CollectorWaitRequest q ;	// 元tupleを正規化しません。
	r.literal( ",\"group\":") ;
	q.group = text( r, 96U) ;
	r.literal( ",\"request\":") ;
	q.requestKey = text( r, 64U) ;
	r.literal( ",\"generation\":") ;
	q.generationKey = text( r, 64U) ;
	r.literal( ",\"job\":") ;
	q.jobKey = text( r, 64U) ;
	identity( q) ;
	return q ;
}
/** @brief 操作を型別の有限canonicalへ符号化します。
 * @param[in] op 元variant。
 * @return 元型の本文。
 */
std::string encode( const CollectorSharedOperation &op)
{
	// 元精算schema・byteを変更しません。
	if( const auto *s = std::get_if<CollectorSharedSettlement>( &op)) {
		std::string bytes ;	// 既存codecの元表現です。
		io( encodeCollectorSharedSettlement( *s, bytes)) ;
		return bytes ;
	}

	Writer w( 4096U) ;	// 追加操作の独立有限枠です。
	w.append( "{\"schema\":\"collector-shared-operation-v1\",\"kind\":") ;
	// 予約は秒境界と最大量を型検査します。
	if( const auto *r = std::get_if<CollectorSharedReservation>( &op)) {
		clock( r->started) ;
		require( r->started % 1000U == 0U && r->maximum > 0U && r->maximum <= 8U * 1024U * 1024U &&
				r->steadyElapsedMillis <= 4102444799999ULL) ;
		w.text( "RESERVE") ;
		writeIdentity( w, r->request) ;
		w.append( ",\"started\":") ;
		w.number( r->started) ;
		w.append( ",\"maximum\":") ;
		w.number( r->maximum) ;
		w.append( ",\"steadyElapsedMillis\":") ;
		w.number( r->steadyElapsedMillis) ;
	}
	// 元acceptedだけからJST日を導出します。
	else if( const auto *d = std::get_if<CollectorSharedDayRoll>( &op)) {
		clock( d->accepted) ;
		w.text( "DAY_ROLL") ;
		w.append( ",\"accepted\":") ;
		w.number( d->accepted) ;
	} else {
		const auto &c = std::get<CollectorSharedCacheUpdate>( op) ;	// 未知kindを生成しません。
		clock( c.accepted) ;
		require( token( c.group) && collector_projected_json::isHash( c.requestKey)) ;
		w.text( "CACHE_REFERENCE") ;
		w.append( ",\"group\":") ;
		w.wideText( c.group) ;
		w.append( ",\"request\":") ;
		w.wideText( c.requestKey) ;
		w.append( ",\"accepted\":") ;
		w.number( c.accepted) ;
		w.append( ",\"expected\":") ;
		w.append( reference( c.expected)) ;
		w.append( ",\"next\":") ;
		w.append( reference( c.next)) ;
	}

	w.append( "}") ;
	return w.take() ;
}
/** @brief 有限日次headerと対象一予約だけを差分へ保存します。
 * @param[in] b 元または新budget。
 * @param[in] row 対象一予約。対象なしはnullです。
 * @return 全予約を重複しないcanonical差分。
 */
std::string budgetHeader( const CollectorBudgetSnapshot &b, const CollectorBudgetReservation *row)
{
	std::uint64_t charged{} ;	// 検査済み1 GiB内の総課金です。
	// 日次の全予約を読んで総量だけを保持します。
	for( const auto &entry : b.reservations) {
		charged += entry.charged ;
	}

	Writer w( 4096U) ;	// 一行と有限headerだけです。
	w.append( "{\"day\":") ;
	w.wideText( b.day) ;
	w.append( ",\"lastUtc\":") ;
	w.number( b.lastUtc) ;
	w.append( ",\"count\":") ;
	w.number( b.reservations.size()) ;
	w.append( ",\"charged\":") ;
	w.number( charged) ;
	w.append( ",\"row\":") ;
	// 対象予約がない日次変更では全1200行を複製しません。
	if( !row) {
		w.append( "null") ;
	} else {
		std::string one ;	// 同じ旧budget codecで対象一行を再検査します。
		require( encodeCollectorBudgetSnapshot( {b.day, b.lastUtc, {*row}}, one)) ;
		w.append( one) ;
	}

	w.append( "}") ;
	return w.take() ;
}
/** @brief 既存二行だけの待機本文を符号化します。
 * @param[in] s 元または新台帳。
 * @param[in] q 対象tuple。
 * @return 元最大二行のcanonical本文。
 */
std::string waitRows( const CollectorSharedLedgerSnapshot &s, const CollectorWaitRequest &q)
{
	CollectorWaitSnapshot wait{s.lastUtcMillis, {}} ;	// 未登録行をbeforeへ生成しません。
	// 既存groupだけを疎な前像へ保持します。
	if( s.groups.contains( q.group)) {
		wait.controls.emplace( L"g-" + q.group, s.groups.at( q.group)) ;
	}

	// 既存requestだけを疎な前像へ保持します。
	if( s.requests.contains( q.requestKey)) {
		wait.controls.emplace( L"r-" + q.requestKey, s.requests.at( q.requestKey).control) ;
	}

	std::string bytes ;	// 全4096行ではなく最大二行です。
	require( encodeCollectorWaitSnapshot( wait, bytes)) ;
	return bytes ;
}
/** @brief 元日・日次容量・待機・slotを検査し開始を一回登録します。
 * @param[in,out] s 元値を複製した未公開台帳。
 * @param[in] op 元予約。
 */
void reserve( CollectorSharedLedgerSnapshot &s, const CollectorSharedReservation &op)
{
	const auto &q = op.request ;	// 元identityを変更しません。
	require( op.started >= s.lastUtcMillis && day( op.started) == s.budget.day) ;
	require( s.budget.reservations.size() < 1200U, 68U) ;
	require( s.budget.reservations.empty() ||
				op.started / 1000U - s.budget.reservations.front().started < 14400U,
			68U) ;
	std::uint64_t charged{} ;	// 日次元課金を返金せず集計します。
	std::size_t	  active{} ;	// 同時四slotを上限とします。
	// 全予約の重複・元課金・同group占有を検査します。
	for( const auto &row : s.budget.reservations) {
		require( row.campaign != q.generationKey || row.job != q.jobKey) ;
		charged += row.charged ;
		// 未精算groupには次予約を登録しません。
		if( row.phase == 0U) {
			++active ;
			require( row.group != q.group, ERROR_RETRY) ;
		}
	}

	require( active < 4U, ERROR_RETRY) ;
	require( op.maximum <= 1024U * 1024U * 1024U - charged, 68U) ;
	// 新groupは最大20の有限集合に限ります。
	if( !s.groups.contains( q.group)) {
		require( s.groups.size() < 20U, 68U) ;
		CollectorWaitControl g ;	// 初回groupは元時刻だけを持ちます。
		g.group	   = q.group ;
		g.observed = op.started ;
		s.groups.emplace( q.group, g) ;
	}

	auto &group = s.groups.at( q.group) ;	// 旧期限・reviewを引き継ぎます。
	require( !group.review && op.started >= group.notBefore &&
				(group.completed == 0U ||
				 (op.started >= group.completed && op.started - group.completed >= 2000U)) &&
				op.steadyElapsedMillis >= 2000U,
			ERROR_RETRY) ;
	// 新requestだけを恒久集合へ追加します。
	if( !s.requests.contains( q.requestKey)) {
		require( s.requests.size() < 4096U, 68U) ;
		CollectorSharedRequestState r ;	// 新行に架空CACHEを作りません。
		r.control.group	   = q.group ;
		r.control.request  = q.requestKey ;
		r.control.observed = op.started ;
		s.requests.emplace( q.requestKey, r) ;
	}

	auto &request = s.requests.at( q.requestKey).control ;	// 旧CACHE・期限を変更しません。
	require( request.group == q.group && request.started == 0U) ;
	require( !request.review && op.started >= request.notBefore, ERROR_RETRY) ;
	request.generation = q.generationKey ;
	request.job		   = q.jobKey ;
	request.started	   = op.started ;
	request.observed   = op.started ;
	group.observed	   = op.started ;
	s.budget.reservations.push_back(
		{q.generationKey, q.jobKey, q.group, op.started / 1000U, op.maximum, op.maximum, 0U}) ;
	s.budget.lastUtc = op.started / 1000U ;
	s.lastUtcMillis	 = op.started ;
}
} // namespace
/** @see local_collector_shared_operation.h */
DWORD encodeCollectorSharedOperation( const CollectorSharedOperation &operation,
									 std::string					&bytes) noexcept
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
/** @see local_collector_shared_operation.h */
DWORD decodeCollectorSharedOperation( const std::string_view	   bytes,
									 CollectorSharedOperation &operation) noexcept
{
	operation = CollectorSharedSettlement{} ;
	try {
		// 元精算だけは既存codecへ委譲します。
		if( bytes.starts_with( "{\"schema\":\"collector-shared-settlement-v1\"")) {
			CollectorSharedSettlement s ;	// 原schemaを維持します。
			io( decodeCollectorSharedSettlement( bytes, s)) ;
			operation = std::move( s) ;
			return 0U ;
		}

		Reader r( bytes, 4096U) ;	// 未知schema・kind・追加fieldを拒否します。
		r.literal( "{\"schema\":\"collector-shared-operation-v1\",\"kind\":") ;
		const auto				 kind = r.text( 32U) ;	// 固定三kindだけです。
		CollectorSharedOperation pending ;				// 全消費前には公開しません。
		// 新規予約の元tupleを完全に読みます。
		if( kind == "RESERVE") {
			CollectorSharedReservation q ;	// 未登録予約を復号します。
			q.request = readIdentity( r) ;
			r.literal( ",\"started\":") ;
			q.started = r.number() ;
			r.literal( ",\"maximum\":") ;
			q.maximum = r.number() ;
			r.literal( ",\"steadyElapsedMillis\":") ;
			q.steadyElapsedMillis = r.number() ;
			pending				  = std::move( q) ;
		}
		// 日次は任意の自己申告日付を読みません。
		else if( kind == "DAY_ROLL") {
			r.literal( ",\"accepted\":") ;
			pending = CollectorSharedDayRoll{r.number()} ;
		} else {
			require( kind == "CACHE_REFERENCE") ;
			CollectorSharedCacheUpdate c ;	// 元期待値と同現区間参照です。
			r.literal( ",\"group\":") ;
			c.group = text( r, 96U) ;
			r.literal( ",\"request\":") ;
			c.requestKey = text( r, 64U) ;
			r.literal( ",\"accepted\":") ;
			c.accepted = r.number() ;
			r.literal( ",\"expected\":") ;
			c.expected = readReference( r.value()) ;
			r.literal( ",\"next\":") ;
			const auto next = readReference( r.value()) ;	// 次参照はnull不可です。
			require( next.has_value()) ;
			c.next	= *next ;
			pending = std::move( c) ;
		}

		r.literal( "}") ;
		r.finish() ;
		require( encode( pending) == bytes) ;
		operation = std::move( pending) ;
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
/** @see local_collector_shared_operation.h */
DWORD deriveCollectorSharedOperation( const CollectorSharedLedgerSnapshot &before,
									 const CollectorSharedOperation		 &operation,
									 CollectorSharedLedgerSnapshot		 &after,
									 CollectorSharedOperationDelta		 &delta) noexcept
{
	after = {} ;
	delta = {} ;
	try {
		CollectorSharedOperationDelta change ;	// 全検査まで公開しない疎な差分です。
		change.operation = encode( operation) ;
		// 精算は既存の意味・疎なv1本文を維持します。
		if( const auto *s = std::get_if<CollectorSharedSettlement>( &operation)) {
			CollectorSharedSettlementDelta old ;	// 元精算の全差分です。
			io( deriveCollectorSharedSettlement( before, *s, after, old)) ;
			change.budgetBefore = std::move( old.budgetBefore) ;
			change.budgetAfter	= std::move( old.budgetAfter) ;
			change.waitBefore	= std::move( old.waitBefore) ;
			change.waitAfter	= std::move( old.waitAfter) ;
			delta				= std::move( change) ;
			return 0U ;
		}

		CollectorSharedLedgerBytes verified ;	// 元全行・予約関係を検査します。
		io( encodeCollectorSharedLedger( before, verified)) ;
		auto pending = before ;	// 他行・元観測・CACHEを保持した複製です。
		// 予約の一行と最大二制御行だけを履歴へ保持します。
		if( const auto *r = std::get_if<CollectorSharedReservation>( &operation)) {
			reserve( pending, *r) ;
			change.budgetBefore = budgetHeader( before.budget, nullptr) ;
			change.budgetAfter	= budgetHeader( pending.budget, &pending.budget.reservations.back()) ;
			change.waitBefore	= waitRows( before, r->request) ;
			change.waitAfter	= waitRows( pending, r->request) ;
		}
		// 日次変更は全未精算閉鎖後だけ認めます。
		else if( const auto *d = std::get_if<CollectorSharedDayRoll>( &operation)) {
			require( d->accepted >= before.lastUtcMillis && day( d->accepted) > before.budget.day) ;
			require( std::none_of( before.budget.reservations.begin(),
								 before.budget.reservations.end(),
								 []( const auto &row) { return row.phase == 0U ; })) ;
			change.budgetBefore	  = budgetHeader( before.budget, nullptr) ;
			pending.budget		  = {day( d->accepted), d->accepted / 1000U, {}} ;
			pending.lastUtcMillis = d->accepted ;
			change.budgetAfter	  = budgetHeader( pending.budget, nullptr) ;
		} else {
			const auto &c =
				std::get<CollectorSharedCacheUpdate>( operation) ;	// 未検証参照だけの置換です。
			require( c.accepted >= before.lastUtcMillis && before.requests.contains( c.requestKey)) ;
			auto &row = pending.requests.at( c.requestKey) ;	// 元制御時刻を進めません。
			require( row.control.group == c.group && row.control.started == 0U) ;
			change.cacheBefore = reference( row.cache) ;
			change.cacheAfter  = reference( c.next) ;
			require( change.cacheBefore == reference( c.expected) &&
					change.cacheBefore != change.cacheAfter) ;
			row.cache			  = c.next ;
			pending.lastUtcMillis = c.accepted ;
		}

		io( encodeCollectorSharedLedger( pending, verified)) ;
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
