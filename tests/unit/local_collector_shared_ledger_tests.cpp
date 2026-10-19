//------------------------------------------------------------------------------
/**
 * @file local_collector_shared_ledger_tests.cpp
 * @brief 共有台帳の全shardと元予算・非変更carryを非通信で検査します。
 * @version 01.00.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/01  4096境界・元制御／予算保持・改変拒否を追加。
 * </pre>
 *
 * @note 架空hashと固定時計だけを使い、File I/O・HTTP・GPU・導入は行いません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#include "platform/local_collector_shared_ledger.h"
#include "test_framework.h"
#include <winrt/base.h>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>

namespace drivercrate::test {
namespace {
// 実機時計や実deviceとは独立したUTC秒。
constexpr std::uint64_t UTC = 1790456400ULL ;
// 共通shard上限を試す全4096行。
constexpr std::size_t	REQUESTS = 4096U ;

/** @brief 同じ長いprefixを持つ架空の完全hex keyを作ります。
 * @param[in] value 架空keyの末尾整数。
 * @return 64桁の小文字hex。
 */
std::wstring			key( const std::size_t value)
{
	std::wostringstream stream ;	// URLや端末情報を含まない固定hex。
	stream << std::hex << std::setfill( L'0') << std::setw( 64) << value ;
	return stream.str() ;
}

/** @brief 固定時計と要確認待機を持つ閉鎖台帳を作ります。
 * @param[in] count Request数。各keyは同prefixです。
 * @return 型付きの架空台帳。
 */
CollectorSharedLedgerSnapshot fixture( const std::size_t count = 2U)
{
	CollectorSharedLedgerSnapshot s ;	// 初期に一groupと元日課金を保持します。
	s.collection	 = key( 99999U) ;
	s.lastUtcMillis	 = UTC * 1000U ;
	s.budget.day	 = L"20260927" ;
	s.budget.lastUtc = UTC ;
	s.budget.reservations.push_back( {key( 9000U), key( 9001U), L"fixture-group", UTC,
									 8U * 1024U * 1024U, 8U * 1024U * 1024U, 2U}) ;
	CollectorWaitControl group ;	// 要確認を日付や区間で自動解除しません。
	group.group		= L"fixture-group" ;
	group.observed	= UTC * 1000U ;
	group.completed = UTC * 1000U ;
	group.notBefore = (UTC + 300U) * 1000U ;
	group.review	= true ;
	s.groups.emplace( group.group, group) ;
	// 全requestへ元待機と元CACHE参照を与えます。
	for( std::size_t i = 0U; i < count; ++i) {
		CollectorSharedRequestState row ;	// 引継ぎ対象の各元値。
		row.control.group	  = group.group ;
		row.control.request	  = key( i + 1U) ;
		row.control.observed  = UTC * 1000U ;
		row.control.notBefore = (UTC + 86400U) * 1000U ;
		row.cache			  = CollectorSharedCacheReference{key( 7U), key( 8U), key( 9U)} ;
		s.requests.emplace( row.control.request, row) ;
	}

	return s ;
}

/** @brief Encode拒否時に部分本文が公開されないことを検査します。
 * @param[in,out] c Assertion集計。
 * @param[in] s 拒否対象の架空状態。
 * @param[in] code 固定した元拒否code。
 */
void rejected( TestContext &c, const CollectorSharedLedgerSnapshot &s, const DWORD code)
{
	CollectorSharedLedgerBytes bytes ;	// 失敗時の出力クリアも検査します。
	bytes.budget = "old" ;
	bytes.groups = "old" ;
	bytes.requests.fill( "old") ;
	DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( s, bytes) == code) ;
	DRIVERCRATE_EXPECT( c, bytes.budget.empty() && bytes.groups.empty()) ;
	DRIVERCRATE_EXPECT( c, std::all_of( bytes.requests.begin(), bytes.requests.end(),
									  []( const auto &value) { return value.empty() ; })) ;
}

/** @brief Decode拒否時に部分状態が公開されないことを検査します。
 * @param[in,out] c Assertion集計。
 * @param[in] bytes 改変した元本文。
 * @param[in] code 期待拒否code。
 */
void refusedBytes( TestContext &c, const CollectorSharedLedgerBytes &bytes, const DWORD code)
{
	auto state = fixture() ;	// 失敗時の旧出力残留も拒否します。
	DRIVERCRATE_EXPECT( c, decodeCollectorSharedLedger( bytes, state) == code) ;
	DRIVERCRATE_EXPECT( c, state.collection.empty() && state.groups.empty() &&
							  state.requests.empty() && state.budget.reservations.empty() &&
							  state.lastUtcMillis == 0U) ;
}

/** @brief 正常・容量・全shard再結合を検査します。
 * @param[in,out] c Assertion集計。
 */
void roundTrips( TestContext &c)
{
	// 空から4096まで、各shard境界を一つずつ試します。
	for( const std::size_t count : {0U, 1U, 63U, 64U, 65U, 127U, 128U, 129U, 300U, 301U, 4096U}) {
		const auto s = fixture( count) ;	// 同prefixでも昇順連続割当で全shardへ分散します。
		CollectorSharedLedgerBytes bytes ;	// 全66本文の独立出力。
		DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( s, bytes) == 0U) ;
		CollectorSharedLedgerSnapshot copy ;	// 旧予算codecへ全requestを渡しません。
		DRIVERCRATE_EXPECT( c, decodeCollectorSharedLedger( bytes, copy) == 0U) ;
		DRIVERCRATE_EXPECT( c, copy.requests.size() == count && copy.collection == s.collection) ;
		DRIVERCRATE_EXPECT( c, copy.groups.at( L"fixture-group").review &&
								  copy.groups.at( L"fixture-group").completed == UTC * 1000U) ;
		DRIVERCRATE_EXPECT( c, copy.budget.reservations.front().charged == 8U * 1024U * 1024U &&
								  copy.budget.reservations.front().phase == 2U) ;
		DRIVERCRATE_EXPECT( c, checkCollectorSharedLedgerCarry( s, copy, UTC * 1000U) == 0U) ;
		DRIVERCRATE_EXPECT( c,
						   checkCollectorSharedLedgerCarry( s, copy, (UTC + 86400U) * 1000U) == 0U) ;
		// 全元要求の期限と旧bindingは切替検査で更新されません。
		for( const auto &[id, row] : copy.requests) {
			DRIVERCRATE_EXPECT( c, row.control.notBefore == s.requests.at( id).control.notBefore &&
									  row.cache && row.cache->binding == key( 9U)) ;
		}
	}

	rejected( c, fixture( REQUESTS + 1U), ERROR_TOO_MANY_NAMES) ;
	auto s = fixture() ;	// Budget予約数は旧意味の1200を維持します。
	s.budget.reservations.clear() ;
	// 同じ元日に最大1200個の閉鎖予約を作ります。
	for( std::size_t i = 0U; i < 1200U; ++i) {
		s.budget.reservations.push_back(
			{key( i + 20000U), key( i + 30000U), L"fixture-group", UTC, 1024U, 1024U, 2U}) ;
	}

	CollectorSharedLedgerBytes bytes ;	// 閉鎖予約を落とさずencodeします。
	DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( s, bytes) == 0U) ;
	CollectorSharedLedgerSnapshot copy ;	// 保存順と全予約を再結合します。
	DRIVERCRATE_EXPECT( c, decodeCollectorSharedLedger( bytes, copy) == 0U &&
							  copy.budget.reservations.size() == 1200U) ;
	s.budget.reservations.push_back( s.budget.reservations.front()) ;
	rejected( c, s, ERROR_TOO_MANY_NAMES) ;
}

/** @brief 制御・予約対応と非変更carryの改変拒否を検査します。
 * @param[in,out] c Assertion集計。
 */
void relations( TestContext &c)
{
	const auto original				= fixture() ;	// 保持すべき元待機・元日課金。
	auto	   s					= original ;	// 各拒否は元状態から独立して改変します。
	s.groups.begin()->second.review = false ;
	DRIVERCRATE_EXPECT( c, checkCollectorSharedLedgerCarry( original, s, UTC * 1000U) == 13U) ;
	s											 = original ;
	s.requests.begin()->second.control.notBefore = 0U ;
	DRIVERCRATE_EXPECT( c, checkCollectorSharedLedgerCarry( original, s, UTC * 1000U) == 13U) ;
	s									  = original ;
	s.budget.reservations.front().phase	  = 1U ;
	s.budget.reservations.front().charged = 0U ;
	DRIVERCRATE_EXPECT( c, checkCollectorSharedLedgerCarry( original, s, UTC * 1000U) == 13U) ;
	s			 = original ;
	s.collection = key( 22U) ;
	DRIVERCRATE_EXPECT( c, checkCollectorSharedLedgerCarry( original, s, UTC * 1000U) == 13U) ;
	s										  = original ;
	s.requests.begin()->second.cache->binding = key( 12U) ;
	DRIVERCRATE_EXPECT( c, checkCollectorSharedLedgerCarry( original, s, UTC * 1000U) == 13U) ;
	DRIVERCRATE_EXPECT( c, checkCollectorSharedLedgerCarry( original, original, UTC * 1000U - 1U) ==
							  13U) ;
	s = original ;
	s.groups.clear() ;
	rejected( c, s, 13U) ;
	s										 = original ;
	s.requests.begin()->second.control.group = L"missing" ;
	rejected( c, s, 13U) ;
	s										   = original ;
	s.requests.begin()->second.control.request = key( 999U) ;
	rejected( c, s, 13U) ;
	s								  = original ;
	s.groups.begin()->second.observed = s.lastUtcMillis + 1U ;
	rejected( c, s, 13U) ;
	s										  = original ;
	s.requests.begin()->second.cache->segment = L"../outside" ;
	rejected( c, s, 13U) ;
	s = original ;
	s.budget.reservations.push_back( s.budget.reservations.front()) ;
	rejected( c, s, 13U) ;
	s									  = original ;
	s.budget.reservations.front().charged = 0U ;
	rejected( c, s, 13U) ;
	s			 = original ;
	s.budget.day = L"20260928" ;
	rejected( c, s, 13U) ;
	s									= original ;
	s.budget.reservations.front().group = L"missing" ;
	rejected( c, s, 13U) ;
	s											 = original ;
	s.requests.begin()->second.control.notBefore = 253402300799999ULL ;
	rejected( c, s, 13U) ;
	s.requests.begin()->second.control.review = true ;
	CollectorSharedLedgerBytes bytes ;	// 要確認の長い元期限は短縮しません。
	DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( s, bytes) == 0U) ;
	s									= original ;
	s.budget.reservations.front().phase = 0U ;
	auto &row	   = s.requests.begin()->second.control ;	// 元予約へ完全に結合した開始intent。
	row.started	   = UTC * 1000U ;
	row.generation = key( 9000U) ;
	row.job		   = key( 9001U) ;
	DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( s, bytes) == 0U) ;
	CollectorSharedLedgerSnapshot running ;	// Codecは未精算を保持できますがcarryは拒否します。
	DRIVERCRATE_EXPECT( c, decodeCollectorSharedLedger( bytes, running) == 0U) ;
	DRIVERCRATE_EXPECT( c, checkCollectorSharedLedgerCarry( s, running, UTC * 1000U) == 13U) ;
	s.budget.reservations.clear() ;
	rejected( c, s, 13U) ;
	s											  = original ;
	s.requests.begin()->second.control.generation = key( 123U) ;
	rejected( c, s, 13U) ;
	s = original ;
	// 日次1 GiB境界まで元maximum課金を保持します。
	s.budget.reservations.clear() ;
	// 元maximumを持つ128閉鎖予約で1 GiBちょうどを作ります。
	for( std::size_t i = 0U; i < 128U; ++i) {
		s.budget.reservations.push_back( {key( 40000U + i), key( 50000U + i), L"fixture-group", UTC,
										 8U * 1024U * 1024U, 8U * 1024U * 1024U, 2U}) ;
	}

	DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( s, bytes) == 0U) ;
	s.budget.reservations.push_back( {key( 5555U), key( 5556U), L"fixture-group", UTC, 1U, 1U, 2U}) ;
	rejected( c, s, 13U) ;
}

/** @brief Group個数と実開始四slotの固定境界を検査します。
 * @param[in,out] c Assertion集計。
 */
void groupAndSlotBoundaries( TestContext &c)
{
	auto	   s		 = fixture() ;					// Request未変更のまま最大20groupへ増やします。
	const auto prototype = s.groups.begin()->second ;	// 元制御の有限fixture値。
	// 既存一groupへ19の架空groupを加えます。
	for( std::size_t i = 1U; i < 20U; ++i) {
		auto group	= prototype ;	// 全行とも元最高UTCを保持します。
		group.group = L"group-" + std::to_wstring( i) ;
		s.groups.emplace( group.group, group) ;
	}

	CollectorSharedLedgerBytes bytes ;	// 上限ちょうどは保存形式にできます。
	DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( s, bytes) == 0U) ;
	CollectorSharedLedgerSnapshot decoded ;	// Group省略や重複がない全再結合。
	DRIVERCRATE_EXPECT( c, decodeCollectorSharedLedger( bytes, decoded) == 0U &&
							  decoded.groups.size() == 20U) ;
	auto extra	= prototype ;	// 容量超過fixtureをsource許可へ使いません。
	extra.group = L"group-20" ;
	s.groups.emplace( extra.group, extra) ;
	rejected( c, s, ERROR_TOO_MANY_NAMES) ;
	s = fixture( 0U) ;
	s.budget.reservations.clear() ;
	s.groups.clear() ;
	// 四つの独立groupで各一つの未精算を元予約へ対応させます。
	for( std::size_t i = 0U; i < 4U; ++i) {
		auto group	= prototype ;	// Group行自体には開始intentを付けません。
		group.group = L"slot-" + std::to_wstring( i) ;
		s.groups.emplace( group.group, group) ;
		CollectorSharedRequestState row ;	// 元予約へ一対一に結合した開始状態。
		row.control.group	   = group.group ;
		row.control.request	   = key( 100U + i) ;
		row.control.observed   = UTC * 1000U ;
		row.control.started	   = UTC * 1000U ;
		row.control.generation = key( 1000U + i) ;
		row.control.job		   = key( 2000U + i) ;
		s.requests.emplace( row.control.request, row) ;
		s.budget.reservations.push_back(
			{row.control.generation, row.control.job, row.control.group, UTC, 1U, 1U, 0U}) ;
	}

	DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( s, bytes) == 0U) ;
	DRIVERCRATE_EXPECT( c, decodeCollectorSharedLedger( bytes, decoded) == 0U) ;
	DRIVERCRATE_EXPECT( c, checkCollectorSharedLedgerCarry( s, decoded, UTC * 1000U) == 13U) ;
	auto wrong								   = s ;	// 同groupへの二未精算は型付きでも拒否します。
	wrong.requests.at( key( 101U)).control.group = L"slot-0" ;
	wrong.budget.reservations[1].group		   = L"slot-0" ;
	rejected( c, wrong, 13U) ;
	auto group	= prototype ;	// 五つ目の独立groupでも四slot制約を維持します。
	group.group = L"slot-4" ;
	s.groups.emplace( group.group, group) ;
	CollectorSharedRequestState fifth = s.requests.begin()->second ;	// 元開始値を保持します。
	fifth.control.group				  = group.group ;
	fifth.control.request			  = key( 104U) ;
	fifth.control.generation		  = key( 1004U) ;
	fifth.control.job				  = key( 2004U) ;
	s.requests.emplace( fifth.control.request, fifth) ;
	s.budget.reservations.push_back(
		{fifth.control.generation, fifth.control.job, group.group, UTC, 1U, 1U, 0U}) ;
	rejected( c, s, 13U) ;
	s = fixture() ;
	// Nullは参照未保持です。
	s.requests.begin()->second.cache.reset() ;
	DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( s, bytes) == 0U) ;
	DRIVERCRATE_EXPECT( c, decodeCollectorSharedLedger( bytes, decoded) == 0U &&
							  !decoded.requests.begin()->second.cache) ;
}

/** @brief 保存byteの全ordinal・field・容量の拒否を検査します。
 * @param[in,out] c Assertion集計。
 */
void byteRejections( TestContext &c)
{
	CollectorSharedLedgerBytes original ;	// 65要求で二shardに実行を分けます。
	DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( fixture( 65U), original) == 0U) ;
	// 空shardも削除・取り違えを許しません。
	for( std::size_t i = 0U; i < original.requests.size(); ++i) {
		auto bytes = original ;	// それぞれ独立した改変です。
		bytes.requests[i].clear() ;
		refusedBytes( c, bytes, 13U) ;
		bytes = original ;
		bytes.requests[i].insert( bytes.requests[i].size() - 1U, ",\"unknown\":0") ;
		refusedBytes( c, bytes, 13U) ;
	}

	auto bytes = original ;	// Ordinalと集合の結合を検査します。
	std::swap( bytes.requests[0], bytes.requests[1]) ;
	refusedBytes( c, bytes, 13U) ;
	bytes			  = original ;
	bytes.requests[1] = bytes.requests[0] ;
	refusedBytes( c, bytes, 13U) ;
	bytes = original ;
	bytes.groups.push_back( ' ') ;
	refusedBytes( c, bytes, 13U) ;
	bytes = original ;
	bytes.budget.clear() ;
	refusedBytes( c, bytes, 13U) ;
	bytes = original ;
	bytes.requests[0].assign( 768U * 1024U + 1U, 'x') ;
	refusedBytes( c, bytes, ERROR_TOO_MANY_NAMES) ;
	bytes = original ;
	bytes.requests.fill( std::string( 768U * 1024U, 'x')) ;
	refusedBytes( c, bytes, ERROR_TOO_MANY_NAMES) ;
	bytes		   = original ;
	const auto pos = bytes.requests[1].find( "\"totalRequests\":65") ;	// 全件数の一field。
	DRIVERCRATE_EXPECT( c, pos != std::string::npos) ;
	// 既存fieldだけを変えた同形byteでも集合全体で拒否します。
	if( pos != std::string::npos) {
		bytes.requests[1].replace( pos, std::string( "\"totalRequests\":65").size(),
								  "\"totalRequests\":64") ;
		refusedBytes( c, bytes, 13U) ;
	}

	// 前へkeyを追加すると後続行がshardを移りますが、元制御値は保持します。
	auto						s	 = fixture( 64U) ;				// 元第一shardの最終行。
	const auto					last = s.requests.rbegin()->first ;	// 次shardへ移る恒久key。
	CollectorSharedRequestState row	 = s.requests.begin()->second ;	// 新規の架空公開要求。
	row.control.request				 = key( 0U) ;
	s.requests.emplace( row.control.request, row) ;
	DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( s, bytes) == 0U) ;
	CollectorSharedLedgerSnapshot copy ;	// 再結合後も恒久keyと元期限は同じです。
	DRIVERCRATE_EXPECT( c, decodeCollectorSharedLedger( bytes, copy) == 0U &&
							  copy.requests.at( last).control.notBefore == (UTC + 86400U) * 1000U) ;
}
} // namespace
} // namespace drivercrate::test

/** @brief 非通信の共有台帳試験を独立して実行します。
 * @return 全期待成立0、fixture例外2、期待不成立1。
 */
int main()
{
	drivercrate::test::TestContext context ;	// 他のCTest分母と合算しません。
	try {
		winrt::init_apartment( winrt::apartment_type::multi_threaded) ;
		drivercrate::test::roundTrips( context) ;
		drivercrate::test::relations( context) ;
		drivercrate::test::groupAndSlotBoundaries( context) ;
		drivercrate::test::byteRejections( context) ;
		winrt::uninit_apartment() ;
	} catch( ...) {
		std::cerr << "Shared ledger fixture exception\n" ;
		return 2 ;
	}

	std::cout << "Shared ledger assertions: " << context.assertionCount()
			  << ", failures: " << context.failureCount() << '\n' ;
	return context.failureCount() == 0 ? 0 : 1 ;
}
