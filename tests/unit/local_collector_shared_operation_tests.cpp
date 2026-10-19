//------------------------------------------------------------------------------
/**
 * @file local_collector_shared_operation_tests.cpp
 * @brief 追加三操作の実保存・意味・停止回復と混在鎖を検査します。
 * @version 01.01.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  三操作保存窓と64操作境界fixtureを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/02  独立した混在鎖の総合受入fixtureを追加。
 * </pre>
 *
 * @note 自身の架空fixtureだけです。公式HTTP・driver・OS設定を変更しません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#include "platform/local_collector_shared_store.h"
#include "platform/local_collector_projected_json.h"
#include "platform/official_file_verifier.h"
#include "test_framework.h"
#include <Windows.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {
// 自身の架空元日20260927だけのUTC秒です。
constexpr std::uint64_t UTC = 1790456400ULL ;
/** @brief 固定した架空完全hashを作ります。
 * @param[in] value 架空identity整数。
 * @return 小文字64桁hash。
 */
std::wstring			key( const std::size_t value)
{
	std::wostringstream s ;	// 同じ元入力を保持します。
	s << std::hex << std::setw( 64) << std::setfill( L'0') << value ;
	return s.str() ;
}
/** @brief Setup失敗をassertion分母と区別します。
 * @param[in] ok 必須setup。
 */
void require( const bool ok)
{
	// 不成立setupから試験を継続しません。
	if( !ok) {
		throw std::runtime_error( "Shared operation fixture setup failed") ;
	}
}
/** @brief 未精算なしと旧review／CACHEを持つ元台帳です。
 * @return 自身の有限snapshot。
 */
CollectorSharedLedgerSnapshot fixture()
{
	CollectorSharedLedgerSnapshot s ;	// 旧課金を予約・参照更新で消しません。
	s.collection	= key( 1U) ;
	s.lastUtcMillis = UTC * 1000U ;
	s.budget = {L"20260927", UTC, {{key( 9000U), key( 9001U), L"fixture-a", UTC - 20U, 32U, 7U, 1U}}} ;
	// 二groupを固定し旧期限／reviewの保持を検査します。
	for( std::size_t i = 0U; i < 2U; ++i) {
		CollectorWaitControl g ;	// 第一groupだけは要確認で停止しています。
		g.group		= i == 0U ? L"fixture-a" : L"fixture-b" ;
		g.observed	= UTC * 1000U ;
		g.completed = (UTC - 10U) * 1000U ;
		g.review	= i == 0U ;
		g.notBefore = i == 0U ? (UTC + 900U) * 1000U : 0U ;
		s.groups.emplace( g.group, g) ;
		CollectorSharedRequestState r ;	// 制御とCACHEの元観測を保持します。
		r.control			= g ;
		r.control.request	= key( 20U + i) ;
		r.control.completed = 0U ;
		r.cache				= CollectorSharedCacheReference{key( 8U), key( 9U), key( 10U)} ;
		s.requests.emplace( r.control.request, r) ;
	}

	return s ;
}
/** @brief 秒境界の固定予約です。
 * @return 二つ目の元requestへの予約。
 */
CollectorSharedReservation reservation()
{
	return {{L"fixture-b", key( 21U), key( 1000U), key( 100U)}, (UTC + 100U) * 1000U, 4096U, 2000U} ;
}
/** @brief 追加操作四条件を固定します。
 * @param[in] kind 0予約、1日次、2同UTC参照、3UTC前進参照。
 * @return 元固定operation。
 */
CollectorSharedOperation operation( const std::size_t kind)
{
	// 登録済みrequestへの予約です。
	if( kind == 0U) {
		return reservation() ;
	}

	// 元日を明示的に進めます。
	if( kind == 1U) {
		return CollectorSharedDayRoll{(UTC + 86400U) * 1000U} ;
	}

	return CollectorSharedCacheUpdate{L"fixture-b",
									  key( 21U),
									  (UTC + (kind == 3U ? 1U : 0U)) * 1000U,
									  CollectorSharedCacheReference{key( 8U), key( 9U), key( 10U)},
									  {key( 2U), key( 99U), key( 11U)}} ;
}
/** @brief 自身の保護parentと唯一子leaseです。 */
struct Session {
	/// 元collection writer。
	LocalCollectorCollectionStore				parent ;
	/// Parentより先に解放する唯一子lease。
	std::unique_ptr<LocalCollectorSegmentLease> child ;
	/** @brief 自身の領域を開き元初回だけを登録します。
	 * @param[in] root 自身の絶対fixture領域。
	 * @param[in] initial 初回snapshotを登録する場合true。
	 */
	Session( const std::filesystem::path &root, const bool initial)
	{
		require( parent.initialize( root, key( 1U)) == 0U) ;
		require( parent.borrowSegment( key( 2U), true, child) == 0U) ;
		// 元初回以外では保存を作り直しません。
		if( initial) {
			require( LocalCollectorSharedStore::bootstrap( parent, *child, fixture()) == 0U) ;
		}
	}
} ;
/** @brief 内部backslash絶対pathで自身の領域だけを扱います。
 * @param[in] path 自身の元絶対path。
 * @return 内部extended path。
 */
std::filesystem::path extended( const std::filesystem::path &path)
{
	return L"\\\\?\\" + std::filesystem::path( path).make_preferred().native() ;
}
/** @brief Lock以外の全保存byteを保持します。
 * @param[in] root 自身のfixture。
 * @return 相対名と原byte。
 */
std::map<std::wstring, std::string> image( const std::filesystem::path &root)
{
	std::map<std::wstring, std::string> result ;	// 拒否／再起動後の非変更像です。
	// 自身の階層を全名・原byteで確認します。
	for( const auto &entry : std::filesystem::recursive_directory_iterator( extended( root))) {
		// 排他lockだけは共有read不可なので対象外です。
		if( entry.is_regular_file() && entry.path().filename() != L"collector.lock") {
			std::ifstream f( entry.path(), std::ios::binary) ;	// 自身の保護fixtureだけです。
			require( f.good()) ;
			result.emplace( entry.path().lexically_relative( extended( root)).native(),
						   std::string( std::istreambuf_iterator<char>( f), {})) ;
		}
	}

	return result ;
}
/** @brief 全canonical66本文を比較します。
 * @param[in] a 元値。
 * @param[in] b 比較値。
 * @return 保存意味が完全一致する場合true。
 */
bool equal( const CollectorSharedLedgerSnapshot &a, const CollectorSharedLedgerSnapshot &b)
{
	CollectorSharedLedgerBytes aa ;	// 元全本文です。
	CollectorSharedLedgerBytes bb ;	// 比較全本文です。
	return encodeCollectorSharedLedger( a, aa) == 0U && encodeCollectorSharedLedger( b, bb) == 0U &&
		   aa.budget == bb.budget && aa.groups == bb.groups && aa.requests == bb.requests ;
}
/** @brief 元全像と明示した停止ordinalから固定suffixを回復します。
 * @param[in,out] c Native集計。
 * @param[in] root 自身の独立fixture。
 * @param[in] kind 固定追加operation。
 * @param[in] stop 実保存直後の元ordinal。
 * @param[in] saves 元保存総数。
 */
void window( TestContext &c, const std::filesystem::path &root, const std::size_t kind,
			const std::size_t stop, const std::size_t saves)
{
	const auto					  op = operation( kind) ;	// 回復時も同じ元操作です。
	CollectorSharedLedgerSnapshot expected ;				// 元純coreから固定した保存像です。
	CollectorSharedOperationDelta delta ;					// 保存関係を別に検査します。
	require( deriveCollectorSharedOperation( fixture(), op, expected, delta) == 0U) ;
	std::map<std::wstring, std::string> originals ;	// 初回履歴は全byte保持します。
	{
		Session s( root, true) ;	// 自身の初回保存です。
		originals = image( root) ;
		DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::commit(
								  s.parent, *s.child, op, [&]( const std::size_t ordinal) {
									  return ordinal == stop ? 995U : 0U ;
								  }) == 995U) ;
	}
	{
		Session		s( root, false) ;	// 別ownerで回復中にも停止します。
		std::size_t count{} ;			// 初回からの元ordinalだけを数えます。
		DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::commit( s.parent, *s.child, op,
																[&]( const std::size_t ordinal) {
																	++count ;
																	require( ordinal == stop + 1U) ;
																	return 995U ;
																}) == (stop == saves ? 0U : 995U)) ;
		DRIVERCRATE_EXPECT( c, count == (stop == saves ? 0U : 1U)) ;
	}
	{
		Session		s( root, false) ;	// 第三ownerで残りだけを反映します。
		std::size_t count{} ;			// 元suffixだけの保存数です。
		DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::commit(
								  s.parent, *s.child, op, [&]( const std::size_t ordinal) {
									  ++count ;
									  require( ordinal == stop + 1U + count) ;
									  return 0U ;
								  }) == 0U) ;
		DRIVERCRATE_EXPECT( c, count == (stop == saves ? 0U : saves - stop - 1U)) ;
	}
	// 完了後さらに二回の新ownerで保存0と全byte非変更を測ります。
	for( std::size_t restart = 0U; restart < 2U; ++restart) {
		Session	   s( root, false) ;		// 旧時計を補完しない独立再起動です。
		const auto before = image( root) ;	// 元確定保存像です。
		DRIVERCRATE_EXPECT(
			c, LocalCollectorSharedStore::commit( s.parent, *s.child, op,
												 []( const std::size_t) { return 995U ; }) == 0U) ;
		CollectorSharedLedgerSnapshot loaded ;	// 完全検査後だけ公開されます。
		DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::load( s.parent, *s.child, loaded) == 0U &&
								  equal( expected, loaded)) ;
		DRIVERCRATE_EXPECT( c, image( root) == before) ;
		// 初回元履歴の全byteが変更されていないことを照合します。
		for( const auto &[name, raw] : originals) {
			// 親current以外の元準備像・base・intent・markerだけは不変です。
			if( !name.starts_with( L"current\\") ||
			   name == L"current\\collector-campaign-mode-v1.json") {
				require( before.at( name) == raw) ;
			}
		}
	}
}
/** @brief 純coreの拒否・境界と独立期待値を検査します。
 * @param[in,out] c Native集計。
 */
void core( TestContext &c)
{
	const auto					  before = fixture() ;	// 元閉鎖済み予算です。
	CollectorSharedLedgerSnapshot after ;				// 拒否では空です。
	CollectorSharedOperationDelta delta ;				// 拒否では空です。
	// 全追加型のcanonical roundtripと余分なbyte拒否を測ります。
	for( std::size_t kind = 0U; kind < 4U; ++kind) {
		std::string				 bytes ;	// 元固定操作です。
		CollectorSharedOperation decoded ;	// 全消費後だけ設定します。
		DRIVERCRATE_EXPECT( c, encodeCollectorSharedOperation( operation( kind), bytes) == 0U &&
								  decodeCollectorSharedOperation( bytes, decoded) == 0U) ;
		std::string again ;	// 元schemaと値の完全一致です。
		DRIVERCRATE_EXPECT( c,
						   encodeCollectorSharedOperation( decoded, again) == 0U && bytes == again) ;
		DRIVERCRATE_EXPECT( c, decodeCollectorSharedOperation( bytes + " ", decoded) == 13U) ;
	}

	DRIVERCRATE_EXPECT( c,
					   deriveCollectorSharedOperation( before, reservation(), after, delta) == 0U &&
						   after.budget.reservations.size() == 2U &&
						   after.budget.reservations.back().phase == 0U &&
						   after.budget.reservations.back().charged == 4096U &&
						   after.requests.at( key( 21U)).control.started == (UTC + 100U) * 1000U &&
						   after.requests.at( key( 20U)).control.review &&
						   after.requests.at( key( 21U)).cache->cacheSha256 == key( 9U)) ;
	const auto running = after ;	// 元日次切替を未精算中は拒否します。
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedOperation( running, operation( 1U), after, delta) ==
								  13U &&
							  after.collection.empty() && delta.operation.empty()) ;
	DRIVERCRATE_EXPECT( c,
					   deriveCollectorSharedOperation( before, operation( 1U), after, delta) == 0U &&
						   after.budget.day == L"20260928" && after.budget.reservations.empty() &&
						   after.requests.at( key( 20U)).control.notBefore ==
							   before.requests.at( key( 20U)).control.notBefore &&
						   after.requests.at( key( 20U)).control.review &&
						   after.requests.at( key( 21U)).cache->segment == key( 8U)) ;
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedOperation(
							  before, CollectorSharedDayRoll{UTC * 1000U}, after, delta) == 13U) ;
	DRIVERCRATE_EXPECT( c,
					   deriveCollectorSharedOperation( before, operation( 2U), after, delta) == 0U &&
						   after.requests.at( key( 21U)).cache->cacheSha256 == key( 99U) &&
						   after.requests.at( key( 21U)).control.observed == UTC * 1000U &&
						   after.budget.reservations[0].charged == 7U) ;
	// 予約の不正・待機条件を元一fieldずつ変えて切り分けます。
	for( std::size_t kind = 0U; kind < 8U; ++kind) {
		auto  op	   = reservation() ;	// 元入力のコピーだけを故意に変更します。
		DWORD expected = 13U ;				// 条件別の元拒否codeです。
		// 八つの独立拒否を固定します。
		switch( kind) {
			case 0U:	// 元時計を戻しません。
				op.started = (UTC - 1U) * 1000U ;
				break ;

			case 1U:	// 暗黙に日次切替をしません。
				op.started += 86400000U ;
				break ;

			case 2U:	// 最大量0は予算予約ではありません。
				op.maximum = 0U ;
				break ;

			case 3U:	// 最大8 MiBを超えません。
				op.maximum = 8U * 1024U * 1024U + 1U ;
				break ;

			case 4U:	// 新baselineの二秒経過を満たします。
				op.steadyElapsedMillis = 1999U ;
				expected			   = 1237U ;
				break ;

			case 5U:	// ReviewとnotBeforeを予約で解除しません。
				op.request.group	  = L"fixture-a" ;
				op.request.requestKey = key( 20U) ;
				expected			  = 1237U ;
				break ;

			case 6U:	// 既存requestのgroupを変えません。
				op.request.group = L"new-group" ;
				break ;

			default:	// 同日同generation／jobを再計上しません。
				op.request.generationKey = key( 9000U) ;
				op.request.jobKey		 = key( 9001U) ;
				break ;
		}

		DRIVERCRATE_EXPECT( c,
						   deriveCollectorSharedOperation( before, op, after, delta) == expected &&
							   after.collection.empty() && delta.operation.empty()) ;
	}

	auto expiry	   = reservation() ;	// 元初回から四時間の境界です。
	expiry.started = (UTC - 20U + 14400U) * 1000U ;
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedOperation( before, expiry, after, delta) == 68U) ;
	auto stale = std::get<CollectorSharedCacheUpdate>( operation( 2U)) ;	// 期待旧参照の差替えです。
	stale.expected->cacheSha256 = key( 999U) ;
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedOperation( before, stale, after, delta) == 13U) ;
	stale = std::get<CollectorSharedCacheUpdate>( operation( 2U)) ;
	stale.accepted -= 1U ;
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedOperation( before, stale, after, delta) == 13U) ;
	stale	   = std::get<CollectorSharedCacheUpdate>( operation( 2U)) ;
	stale.next = *stale.expected ;
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedOperation( before, stale, after, delta) == 13U) ;
	DRIVERCRATE_EXPECT( c,
					   deriveCollectorSharedOperation( running, operation( 2U), after, delta) == 13U) ;
}
/** @brief 日次・恒久集合・slotと元CACHEの独立境界を検査します。
 * @param[in,out] c Native集計。
 */
void boundaries( TestContext &c)
{
	CollectorSharedLedgerSnapshot after ;				// 失敗時は空です。
	CollectorSharedOperationDelta delta ;				// 失敗時は空です。
	auto						  state = fixture() ;	// 形式正常な日次1200行を作ります。
	state.budget.reservations.clear() ;
	// 全closed行の開始順・同日・一意identityを保ちます。
	for( std::size_t i = 0U; i < 1200U; ++i) {
		state.budget.reservations.push_back(
			{key( 10000U + i), key( 20000U + i), L"fixture-b", UTC - 20U, 1U, 1U, 1U}) ;
	}

	CollectorSharedLedgerBytes valid ;	// 反証入力自体の成立を独立に確認します。
	DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( state, valid) == 0U) ;
	DRIVERCRATE_EXPECT( c,
					   deriveCollectorSharedOperation( state, reservation(), after, delta) == 68U &&
						   after.collection.empty()) ;
	state.budget.reservations.resize( 1199U) ;
	DRIVERCRATE_EXPECT( c,
					   deriveCollectorSharedOperation( state, reservation(), after, delta) == 0U &&
						   after.budget.reservations.size() == 1200U) ;
	state = fixture() ;
	state.budget.reservations.clear() ;
	// 実byte取得ではない型付き日次1 GiB課金です。
	for( std::size_t i = 0U; i < 128U; ++i) {
		state.budget.reservations.push_back( {key( 10000U + i), key( 20000U + i), L"fixture-b",
											 UTC - 20U, 8U * 1024U * 1024U, 8U * 1024U * 1024U,
											 1U}) ;
	}

	DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( state, valid) == 0U &&
							  deriveCollectorSharedOperation( state, reservation(), after, delta) ==
								  68U) ;
	state.budget.reservations.back().charged -= 4096U ;
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedOperation( state, reservation(), after, delta) == 0U) ;
	state = fixture() ;
	// 四groupを同時一slotずつ保持する形式正常の反証入力です。
	for( std::size_t i = 0U; i < 4U; ++i) {
		const auto			 group = L"active-" + std::to_wstring( i) ;	// 有限な独立groupです。
		CollectorWaitControl g ;										// 元group完了はありません。
		g.group	   = group ;
		g.observed = UTC * 1000U ;
		state.groups.emplace( group, g) ;
		CollectorSharedRequestState r ;	// 元予算に結合する開始intentです。
		r.control			 = g ;
		r.control.request	 = key( 1000U + i) ;
		r.control.started	 = UTC * 1000U ;
		r.control.generation = key( 3000U + i) ;
		r.control.job		 = key( 4000U + i) ;
		state.requests.emplace( r.control.request, r) ;
		state.budget.reservations.push_back(
			{r.control.generation, r.control.job, group, UTC, 1U, 1U, 0U}) ;
	}

	DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( state, valid) == 0U &&
							  deriveCollectorSharedOperation( state, reservation(), after, delta) ==
								  1237U) ;
	state = fixture() ;
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedOperation( state, reservation(), after, delta) == 0U) ;
	// 元pendingを同group次予約へ流用しません。
	state	= after ;
	auto op = reservation() ;	// 時計・identityは正しく進めます。
	op.started += 2000U ;
	op.request.requestKey	 = key( 200U) ;
	op.request.generationKey = key( 2000U) ;
	op.request.jobKey		 = key( 201U) ;
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedOperation( state, op, after, delta) == 1237U) ;
	auto cache = std::get<CollectorSharedCacheUpdate>(
		// 時刻拒否と開始intent拒否を切り分けます。
		operation( 2U)) ;
	cache.accepted = state.lastUtcMillis ;
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedOperation( state, cache, after, delta) == 13U) ;
	state									= fixture() ;
	state.groups.at( L"fixture-b").completed = (UTC + 99U) * 1000U ;
	state.groups.at( L"fixture-b").observed	= (UTC + 99U) * 1000U ;
	state.lastUtcMillis						= (UTC + 99U) * 1000U ;
	DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( state, valid) == 0U &&
							  deriveCollectorSharedOperation( state, reservation(), after, delta) ==
								  1237U) ;
	state										  = fixture() ;
	state.requests.at( key( 21U)).control.notBefore = (UTC + 101U) * 1000U ;
	DRIVERCRATE_EXPECT( c,
					   deriveCollectorSharedOperation( state, reservation(), after, delta) == 1237U) ;
	state.requests.at( key( 21U)).control.notBefore = 0U ;
	state.requests.at( key( 21U)).control.review	  = true ;
	DRIVERCRATE_EXPECT( c,
					   deriveCollectorSharedOperation( state, reservation(), after, delta) == 1237U) ;
	state				  = fixture() ;
	op					  = reservation() ;
	op.request.group	  = L"new-group" ;
	op.request.requestKey = key( 6000U) ;
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedOperation( state, op, after, delta) == 0U &&
							  after.groups.size() == 3U && after.requests.size() == 3U &&
							  !after.requests.at( key( 6000U)).cache) ;
	// Group上限20の反証入力を元待機のまま作ります。
	for( std::size_t i = 0U; i < 18U; ++i) {
		CollectorWaitControl g ;	// 空groupでも元観測を保持します。
		g.group	   = L"extra-" + std::to_wstring( i) ;
		g.observed = UTC * 1000U ;
		state.groups.emplace( g.group, g) ;
	}

	DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( state, valid) == 0U &&
							  deriveCollectorSharedOperation( state, op, after, delta) == 68U) ;
	state = fixture() ;
	// 同prefix4096行は実製品対応数ではありません。
	for( std::size_t i = 2U; i < 4096U; ++i) {
		auto r			  = state.requests.at( key( 21U)) ;	// CACHE付き元閉鎖行を保持します。
		r.control.request = key( 20U + i) ;
		state.requests.emplace( r.control.request, r) ;
	}

	DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( state, valid) == 0U &&
							  deriveCollectorSharedOperation( state, op, after, delta) == 68U) ;
	op = reservation() ;
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedOperation( state, op, after, delta) == 0U &&
							  after.requests.size() == 4096U) ;
	cache = std::get<CollectorSharedCacheUpdate>( operation( 2U)) ;
	cache.expected.reset() ;
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedOperation( fixture(), cache, after, delta) == 13U) ;
	cache			 = std::get<CollectorSharedCacheUpdate>( operation( 2U)) ;
	cache.requestKey = key( 9999U) ;
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedOperation( fixture(), cache, after, delta) == 13U) ;
	cache		= std::get<CollectorSharedCacheUpdate>( operation( 2U)) ;
	cache.group = L"fixture-a" ;
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedOperation( fixture(), cache, after, delta) == 13U) ;
}
/** @brief 追加型・元精算v1・日次の混在鎖と改変拒否を検査します。
 * @param[in,out] c Native集計。
 * @param[in] root 自身の領域。
 */
void mixed( TestContext &c, const std::filesystem::path &root)
{
	Session	   s( root, true) ;				// 新v2予約から旧v1精算へ接続します。
	const auto reserve = reservation() ;	// 同じ元開始です。
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::commit( s.parent, *s.child, reserve) == 0U) ;
	CollectorSharedSettlement settle ;	// 旧schemaの元成功200です。
	settle.request				  = reserve.request ;
	settle.started				  = reserve.started ;
	settle.finished				  = reserve.started + 1000U ;
	settle.accepted				  = reserve.started + 2000U ;
	settle.bytesKnown			  = true ;
	settle.receivedBytes		  = 7U ;
	settle.observation.successful = true ;
	settle.observation.status	  = 200U ;
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::settle( s.parent, *s.child, settle) == 0U) ;
	auto cache = std::get<CollectorSharedCacheUpdate>( operation( 2U)) ;	// 元制御時刻を変えません。
	cache.accepted = settle.accepted ;
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::commit( s.parent, *s.child, cache) == 0U) ;
	DRIVERCRATE_EXPECT( c,
					   LocalCollectorSharedStore::commit( s.parent, *s.child, operation( 1U)) == 0U) ;
	CollectorSharedLedgerSnapshot loaded ;	// 四操作の混在再導出です。
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::load( s.parent, *s.child, loaded) == 0U &&
							  loaded.budget.day == L"20260928" &&
							  loaded.requests.at( key( 21U)).control.notBefore ==
								  settle.finished + 86400000U) ;
	const auto before = image( root) ;	// 古い操作を再適用して巻き戻しません。
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::commit( s.parent, *s.child, cache) == 13U &&
							  image( root) == before) ;
	cache.accepted	   = (UTC + 86400U) * 1000U ;
	cache.expected	   = cache.next ;
	cache.next.segment = key( 999U) ;
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::commit( s.parent, *s.child, cache) == 13U &&
							  image( root) == before) ;
}
/** @brief 同一区間64操作と65番目の非変更容量拒否を測ります。
 * @param[in,out] c Native集計。
 * @param[in] root 自身の領域。
 */
void capacity( TestContext &c, const std::filesystem::path &root)
{
	Session s( root, true) ;												// 参照操作だけの有限64履歴です。
	auto	op = std::get<CollectorSharedCacheUpdate>( operation( 2U)) ;	// 同UTCで元時計は不変です。
	// 固定64回だけ実保存し、次参照を前の完全期待値へ結合します。
	for( std::size_t i = 0U; i < 64U; ++i) {
		op.next.cacheSha256 = key( 99U + i) ;
		DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::commit( s.parent, *s.child, op) == 0U) ;
		op.expected = op.next ;
	}

	CollectorSharedLedgerSnapshot loaded ;	// 全64recordを実再導出します。
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::load( s.parent, *s.child, loaded) == 0U &&
							  loaded.requests.at( key( 21U)).cache->cacheSha256 == key( 162U)) ;
	const auto before	= image( root) ;	// 65操作目を保存しません。
	op.next.cacheSha256 = key( 999U) ;
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::commit( s.parent, *s.child, op) == 68U &&
							  image( root) == before) ;
}
/** @brief 二日・成功と中断を含む固定七操作を作ります。
 * @return 回復中も変更しない元操作列。
 */
std::vector<CollectorSharedOperation> combinedOperations()
{
	const auto				  first = reservation() ;	// 元日の最初の新規予約です。
	CollectorSharedSettlement success ;					// 元成功200だけの観測です。
	success.request				   = first.request ;
	success.started				   = first.started ;
	success.finished			   = first.started + 1000U ;
	success.accepted			   = first.started + 2000U ;
	success.bytesKnown			   = true ;
	success.receivedBytes		   = 7U ;
	success.observation.successful = true ;
	success.observation.status	   = 200U ;
	auto cache	   = std::get<CollectorSharedCacheUpdate>( operation( 2U)) ;	// 元成功後の参照です。
	cache.accepted = success.accepted ;
	auto second	   = first ;	// 翌日の旧24時間期限より後にだけ予約します。
	second.request.generationKey = key( 1001U) ;
	second.request.jobKey		 = key( 101U) ;
	second.started				 = (UTC + 86510U) * 1000U ;
	CollectorSharedSettlement abandoned ;	// 成功やbyte既知を捏造しない明示中断です。
	abandoned.request	  = second.request ;
	abandoned.started	  = second.started ;
	abandoned.finished	  = second.started + 1000U ;
	abandoned.accepted	  = second.started + 2000U ;
	abandoned.interrupted = true ;
	auto nextCache		  = cache ;	// 中断は旧成功参照を消さず、別の明示参照だけを保存します。
	nextCache.accepted	  = abandoned.accepted ;
	nextCache.expected	  = cache.next ;
	nextCache.next		  = {key( 2U), key( 199U), key( 12U)} ;
	return {first, success, cache, operation( 1U), second, abandoned, nextCache} ;
}
/** @brief 同じ元prefixだけを実保存します。
 * @param[in,out] s 自身の所有session。
 * @param[in] count 先行する元操作数。最大七です。
 */
void combinedPrefix( Session &s, const std::size_t count)
{
	const auto ops = combinedOperations() ;	// 原条件を再起動時に変更しません。
	require( count <= ops.size()) ;
	// 対象操作の前までを実保存し、後の操作は先取りしません。
	for( std::size_t i = 0U; i < count; ++i) {
		require( LocalCollectorSharedStore::commit( s.parent, *s.child, ops[i]) == 0U) ;
	}
}
/** @brief 全66本文の比較とは独立した元課金・中断・旧値を検査します。
 * @param[in,out] c 独立native分母。
 * @param[in] s 七操作完了後の実読戻し値。
 */
void combinedMeaning( TestContext &c, const CollectorSharedLedgerSnapshot &s)
{
	const auto &request = s.requests.at( key( 21U)) ;	// 翌日中断した対象行です。
	DRIVERCRATE_EXPECT( c, s.budget.day == L"20260928" && s.budget.reservations.size() == 1U &&
							  s.budget.reservations[0].started == UTC + 86510U &&
							  s.budget.reservations[0].phase == 2U &&
							  s.budget.reservations[0].charged == 4096U) ;
	DRIVERCRATE_EXPECT( c, request.control.started == 0U) ;
	DRIVERCRATE_EXPECT( c, request.control.completed == 0U) ;
	DRIVERCRATE_EXPECT( c, s.groups.at( L"fixture-b").completed == (UTC + 86511U) * 1000U) ;
	DRIVERCRATE_EXPECT( c, request.control.notBefore == (UTC + 172911U) * 1000U) ;
	DRIVERCRATE_EXPECT( c, request.cache->cacheSha256 == key( 199U)) ;
	DRIVERCRATE_EXPECT( c, s.groups.at( L"fixture-a").review &&
							  s.requests.at( key( 20U)).control.notBefore == (UTC + 900U) * 1000U &&
							  s.requests.at( key( 20U)).cache->cacheSha256 == key( 9U) &&
							  s.lastUtcMillis == (UTC + 86512U) * 1000U) ;
}
/** @brief 先行操作を保持した停止・再停止・二回再起動を測ります。
 * @param[in,out] c 独立native分母。
 * @param[in] root 自身の独立fixture。
 * @param[in] stage 元七操作の対象ordinal。
 * @param[in] stop 対象操作内の元保存ordinal。
 * @param[in] saves 対象の元保存総数。
 */
void combinedWindow( TestContext &c, const std::filesystem::path &root, const std::size_t stage,
					const std::size_t stop, const std::size_t saves)
{
	const auto ops		= combinedOperations() ;	// 最新操作だけを再開します。
	auto	   expected = fixture() ;				// 同じ元prefixから全値を再導出します。
	// 純coreと実保存を別に通し、対象操作の後の値を固定します。
	for( std::size_t i = 0U; i <= stage; ++i) {
		CollectorSharedLedgerSnapshot after ;	// 未検査値を公開しません。
		CollectorSharedOperationDelta delta ;	// 意味の疎な前後値です。
		require( deriveCollectorSharedOperation( expected, ops[i], after, delta) == 0U) ;
		expected = after ;
	}

	std::map<std::wstring, std::string> originals ;	// 過去の履歴は全byte保持します。
	{
		Session s( root, true) ;	// 自身の初回と元prefixだけを保存します。
		combinedPrefix( s, stage) ;
		originals = image( root) ;
		DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::commit( s.parent, *s.child, ops[stage],
																[stop]( const std::size_t n) {
																	return n == stop ? 995U : 0U ;
																}) == 995U) ;
	}
	{
		Session		s( root, false) ;	// 別ownerで最初の不足保存にも停止します。
		std::size_t observed{} ;		// 元ordinalだけを観測します。
		const auto	code = LocalCollectorSharedStore::commit( s.parent, *s.child, ops[stage],
															 [&]( const std::size_t n) {
																 observed = n ;
																 return 995U ;
															 }) ; // 元値は不変です。
		DRIVERCRATE_EXPECT( c, code == (stop == saves ? 0U : 995U) &&
								  observed == (stop == saves ? 0U : stop + 1U)) ;
	}
	{
		Session		s( root, false) ;	// 第三ownerで不足suffixだけを完了します。
		std::size_t observed{} ;		// 完了までの最後の元ordinalです。
		DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::commit( s.parent, *s.child, ops[stage],
																[&]( const std::size_t n) {
																	observed = n ;
																	return 0U ;
																}) == 0U &&
								  observed == (stop >= saves - 1U ? 0U : saves)) ;
	}
	const auto all = image( root) ;	// 回復後の全確定byteです。
	// さらに二回の新ownerで元操作反復0と全再導出・非変更を確認します。
	for( std::size_t restart = 0U; restart < 2U; ++restart) {
		Session s( root, false) ;	// 前ownerのhandleを再利用しません。
		DRIVERCRATE_EXPECT(
			c, LocalCollectorSharedStore::commit( s.parent, *s.child, ops[stage],
												 []( const std::size_t) { return 995U ; }) == 0U) ;
		CollectorSharedLedgerSnapshot loaded ;	// 完全検査済み値だけです。
		DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::load( s.parent, *s.child, loaded) == 0U &&
								  equal( expected, loaded)) ;
		DRIVERCRATE_EXPECT( c, all == image( root)) ;
		// 七操作が完了した窓だけで独立した課金・旧値も検査します。
		if( stage == 6U) {
			combinedMeaning( c, loaded) ;
		}
	}

	// 対象操作の前からある区間履歴・元準備像・markerは全て維持します。
	for( const auto &[name, raw] : originals) {
		// 親current以外と恒久mode markerだけは不変です。
		if( !name.starts_with( L"current\\") || name == L"current\\collector-campaign-mode-v1.json") {
			DRIVERCRATE_EXPECT( c, all.at( name) == raw) ;
		}
	}
}
/** @brief 混在64操作と65拒否・二回再起動を検査します。
 * @param[in,out] c 独立native分母。
 * @param[in] root 自身のfixture。
 */
void combinedCapacity( TestContext &c, const std::filesystem::path &root)
{
	auto op =
		std::get<CollectorSharedCacheUpdate>( combinedOperations().back()) ;	// 既存参照から続けます。
	op.expected = op.next ;
	{
		Session s( root, true) ;	// 元七操作の履歴と旧reviewを維持します。
		combinedPrefix( s, 7U) ;
		CollectorSharedLedgerSnapshot loaded ;	// 日次と中断の独立期待値です。
		DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::load( s.parent, *s.child, loaded) == 0U) ;
		combinedMeaning( c, loaded) ;
		// 元七操作に57参照だけを追加し、一区間64の固定境界へ達します。
		for( std::size_t i = 0U; i < 57U; ++i) {
			op.next.cacheSha256 = key( 3000U + i) ;
			DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::commit( s.parent, *s.child, op) == 0U) ;
			// 最新元操作は期待旧値を変更する前の値として保持します。
			if( i != 56U) {
				op.expected = op.next ;
			}
		}
	}
	const auto all = image( root) ;	// 確定64操作の全byteです。
	// 二回の別ownerでも全64操作を再導出し、最新反復は新課金／保存を出しません。
	for( std::size_t restart = 0U; restart < 2U; ++restart) {
		Session s( root, false) ;	// 次区間は作りません。
		DRIVERCRATE_EXPECT(
			c, LocalCollectorSharedStore::commit( s.parent, *s.child, op,
												 []( const std::size_t) { return 995U ; }) == 0U) ;
		CollectorSharedLedgerSnapshot loaded ;	// 元64操作からの完全値です。
		DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::load( s.parent, *s.child, loaded) == 0U &&
								  loaded.requests.at( key( 21U)).cache->cacheSha256 == key( 3056U) &&
								  loaded.budget.reservations[0].charged == 4096U) ;
		auto overflow			  = op ;	// 65個目は保存前に68で停止します。
		overflow.expected		  = op.next ;
		overflow.next.cacheSha256 = key( 9999U) ;
		DRIVERCRATE_EXPECT( c,
						   LocalCollectorSharedStore::commit( s.parent, *s.child, overflow) == 68U &&
							   all == image( root)) ;
	}
}
/** @brief 自身の既存fileの原byteを読みます。
 * @param[in] path 自身のfixture。
 * @return 原byte。
 */
std::string combinedContents( const std::filesystem::path &path)
{
	std::ifstream stream( extended( path), std::ios::binary) ;	// 正規化しません。
	require( stream.good()) ;
	return {std::istreambuf_iterator<char>( stream), {}} ;
}
/** @brief 自身の反証fixtureだけを改変します。
 * @param[in] path 自身の既存file。
 * @param[in] bytes 故意の不成立byte。
 */
void combinedAlter( const std::filesystem::path &path, const std::string_view bytes)
{
	std::ofstream stream( extended( path),
						 std::ios::binary | std::ios::trunc) ;	// 自身のACLは非変更です。
	require( stream.good()) ;
	stream.write( bytes.data(), static_cast<std::streamsize>( bytes.size())) ;
	require( stream.good()) ;
}
/** @brief 自己CNG一致の反証envelopeを作ります。
 * @param[in] body 自身の有限body。
 * @return 正しい自己hashだけを持つenvelope。
 */
std::string combinedEnvelope( const std::string_view body)
{
	std::wstring hash ;	// 元鎖への結合とは別です。
	require( computeCollectorMetadataSha256( body, hash) == 0) ;
	collector_projected_json::Writer w( 2U * 1024U * 1024U) ;	// 元上限を維持します。
	w.append( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
	w.text( body) ;
	w.append( ",\"sha256\":") ;
	w.wideText( hash) ;
	w.append( "}") ;
	return w.take() ;
}
/** @brief 追加v2の三型・schema・別候補・非prefixを拒否します。
 * @param[in,out] c 独立native分母。
 * @param[in] root 自身のfixture。
 * @param[in] kind 固定六反証。
 */
void combinedRejected( TestContext &c, const std::filesystem::path &root, const std::size_t kind)
{
	Session			  s( root, true) ;									// 実dataを変更しません。
	const auto		  ops	 = combinedOperations() ;					// 登録前後の同じ元操作です。
	const std::size_t target = kind == 1U ? 3U : kind == 2U ? 2U : 0U ;	// 追加三型を別に検査します。
	combinedPrefix( s, target) ;
	const auto stop = kind == 4U ? 1U : kind == 5U ? 3U : target == 2U ? 4U : 69U ;	// 元保存窓です。
	require( LocalCollectorSharedStore::commit(
				s.parent, *s.child, ops[target],
				[stop]( const std::size_t n) { return n == stop ? 995U : 0U ; }) == 995U) ;
	// 自己hashを再計算した追加recordでも元鎖とschemaを照合します。
	if( kind < 4U) {
		const auto record = root / L"segments" / key( 2U) / L"runs" /
							(target == 3U	? L"shared-update-03.json"
							 : target == 2U ? L"shared-update-02.json"
											: L"shared-update-00.json") ;	// 自身の固定名です。
		const auto raw = combinedContents( record) ;						// Readerより長く元byteを所有します。
		collector_projected_json::Reader reader( raw,
												2U * 1024U * 1024U) ;	// 反証bodyだけを読みます。
		reader.literal( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
		auto body = reader.text( 768U * 1024U) ;	// 原schemaのcanonical bodyです。
		// CACHE三hash参照を完全形式の別hashへ置換します。
		if( kind == 2U) {
			const auto field = body.find( "\"cacheAfter\":") ;	// 元recordの直接参照だけです。
			const auto at =
				// 元segment三hashの先頭です。
				body.find( std::string( 63U, '0') + "2", field) ;
			require( field != std::string::npos && at != std::string::npos) ;
			body.replace( at, 64U, std::string( 64U, 'f')) ;
		}
		// 余分なv2 fieldを持つ旧v1への差替えを互換としません。
		else if( kind == 3U) {
			const auto at = body.find( "collector-shared-update-v2") ;	// 原schemaは必須です。
			require( at != std::string::npos) ;
			body.replace( at, std::string_view( "collector-shared-update-v2").size(),
						 "collector-shared-update-v1") ;
		} else {
			const auto at = body.find( "\"previousHead\":\"") ;	// 予約／日次の元親head参照です。
			require( at != std::string::npos) ;
			body.replace( at + std::string_view( "\"previousHead\":\"").size(), 64U,
						 std::string( 64U, 'f')) ;
		}

		combinedAlter( record, combinedEnvelope( body)) ;
	}
	// 未登録の第二候補を無視して元一件だけ回復しません。
	else if( kind == 4U) {
		require( s.child->store().write( L"runs/shared-update-01.json", "{}") == 0U) ;
	} else {
		CollectorSharedLedgerSnapshot after ;	// 正しい元afterでも非prefixは拒否します。
		CollectorSharedOperationDelta delta ;	// 対象予約だけの元意味です。
		require( deriveCollectorSharedOperation( fixture(), ops[0], after, delta) == 0U) ;
		CollectorSharedLedgerBytes bytes ;	// 末尾現在像を先取りする反証です。
		require( encodeCollectorSharedLedger( after, bytes) == 0U) ;
		combinedAlter( root / L"current/shared-requests-3f.json",
					  combinedEnvelope( bytes.requests[63U])) ;
	}

	const auto all = image( root) ;	// 故意の不成立も自動修復しません。
	DRIVERCRATE_EXPECT( c,
					   LocalCollectorSharedStore::commit( s.parent, *s.child, ops[target]) == 13U &&
						   all == image( root)) ;
	CollectorSharedLedgerSnapshot loaded = fixture() ;	// 失敗時は部分値も旧値も公開しません。
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::load( s.parent, *s.child, loaded) == 13U &&
							  loaded.collection.empty() && all == image( root)) ;
}
/** @brief 追加三型の実rename第一5と残留stageを検査します。
 * @param[in,out] c 独立native分母。
 * @param[in] root 自身のfixture。
 * @param[in] kind 元予約・日次・参照。
 */
void combinedBlocked( TestContext &c, const std::filesystem::path &root, const std::size_t kind)
{
	Session	   s( root, true) ;			// 登録headからの不足保存を実行します。
	const auto op = operation( kind) ;	// 型別の元操作だけです。
	require( LocalCollectorSharedStore::commit( s.parent, *s.child, op, []( const std::size_t n) {
				return n == 2U ? 995U : 0U ;
			}) == 995U) ;
	const auto	 path = root / L"current/collection-head-v1.json" ;	// 自身の登録headを保持します。
	const auto	 original = combinedContents( path) ;				// 失敗後もこのbyteが必要です。
	const HANDLE handle	  = CreateFileW( extended( path).c_str(), GENERIC_READ,
										FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
										FILE_ATTRIBUTE_NORMAL, nullptr) ;	// DELETE共有だけを止めます。
	require( handle != INVALID_HANDLE_VALUE) ;
	const auto closer = []( void *value) { CloseHandle( value) ; } ;		// 自身のhandleだけを解放します。
	const std::unique_ptr<void, decltype( closer)> guard( handle, closer) ;	// 例外時も閉じます。
	const auto									  code =
		// 第一数値を保持します。
		LocalCollectorSharedStore::commit( s.parent, *s.child, op) ;
	std::cout << "Combined blocked-replace " << kind << " Win32 code: " << code << '\n' ;
	DRIVERCRATE_EXPECT(
		c, code == 5U && original == combinedContents( path) &&
			   std::filesystem::exists( extended( root / L"current/collection-head-v1.json.tmp"))) ;
	const auto all = image( root) ;	// 残留stageも自動変更しません。
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::commit( s.parent, *s.child, op) == 13U &&
							  all == image( root)) ;
}
/** @brief 固定33代表窓・混在容量・六反証・三実I/Oを実行します。
 * @param[in,out] c 独立native分母。
 * @param[in] base 自身の未存在fixture親領域。
 */
void combined( TestContext &c, const std::filesystem::path &base)
{
	const std::vector<std::size_t> totals{69U, 69U, 4U, 69U, 69U, 69U, 4U} ;	// 元保存予測です。
	// 七操作それぞれの登録・prefix・確定の代表窓だけを測ります。
	for( std::size_t stage = 0U; stage < totals.size(); ++stage) {
		const auto				 total = totals[stage] ;	// 対象一操作の元保存数です。
		std::vector<std::size_t> stops{1U, 2U, (total + 1U) / 2U, total - 1U,
									   total} ;	// 最大五点です。
		std::sort( stops.begin(), stops.end()) ;
		stops.erase( std::unique( stops.begin(), stops.end()), stops.end()) ;
		// 同UTC四保存の重複だけを除き、元ordinalを変えません。
		for( const auto stop : stops) {
			combinedWindow(
				c,
				base / (L"combined-" + std::to_wstring( stage) + L"-" + std::to_wstring( stop)) /
					key( 1U),
				stage, stop, total) ;
		}
	}

	combinedCapacity( c, base / L"combined-capacity" / key( 1U)) ;
	// 六つの改変条件は独立した自身のfixtureだけに作ります。
	for( std::size_t kind = 0U; kind < 6U; ++kind) {
		combinedRejected( c, base / (L"combined-reject-" + std::to_wstring( kind)) / key( 1U), kind) ;
	}

	// 元追加三型それぞれで最終headの実rename拒否を確認します。
	for( std::size_t kind = 0U; kind < 3U; ++kind) {
		combinedBlocked( c, base / (L"combined-blocked-" + std::to_wstring( kind)) / key( 1U), kind) ;
	}
}
} // namespace
} // namespace drivercrate::test
/** @brief 追加操作の独立native runnerです。
 * @param[in] argc 無引数または固定検証mode一件だけです。
 * @param[in] argv 固定mode名。未知引数はfixture作成前に拒否します。
 * @return 成功0、assertion不成立1、setup例外2。
 * @retval 87 未知／余分な引数。
 */
int main( const int argc, char *argv[])
{
	const bool combined =
		// 明示検証専用です。
		argc == 2 && std::string_view( argv[1]) == "--combined-recovery" ;
	// 未知modeや余分な引数を旧試験の成功へ読み替えません。
	if( argc != 1 && !combined) {
		return 87 ;
	}

	try {
		drivercrate::test::TestContext c ;	// 構成別の独立分母です。
		const auto base = std::filesystem::absolute( std::filesystem::path( L"work/tmp") /
													(L"shared-operation-" +
													 std::to_wstring( GetCurrentProcessId()) + L"-" +
													 // 自身の未存在領域です。
													 std::to_wstring( GetTickCount64()))) ;
		drivercrate::test::require( std::filesystem::create_directories( base)) ;
		// 明示した追加検証だけを独立分母で実行します。
		if( combined) {
			drivercrate::test::combined( c, base) ;
			std::cout << "Shared combined assertions: " << c.assertionCount()
					  << ", failures: " << c.failureCount() << '\n' ;
			return c.failureCount() == 0U ? 0 : 1 ;
		}

		drivercrate::test::core( c) ;
		drivercrate::test::boundaries( c) ;
		const std::vector<std::size_t> saves{69U, 69U, 4U,
											 68U} ;	// 元三型・二UTC条件の全保存窓です。
		// 計210独立fixtureの実保存直後にだけ停止します。
		for( std::size_t kind = 0U; kind < saves.size(); ++kind) {
			// 各operationの元保存ordinalを全て測ります。
			for( std::size_t stop = 1U; stop <= saves[kind]; ++stop) {
				drivercrate::test::window(
					c,
					base / (L"case-" + std::to_wstring( kind) + L"-" + std::to_wstring( stop)) /
						drivercrate::test::key( 1U),
					kind, stop, saves[kind]) ;
			}
		}

		drivercrate::test::mixed( c, base / L"mixed" / drivercrate::test::key( 1U)) ;
		drivercrate::test::capacity( c, base / L"capacity" / drivercrate::test::key( 1U)) ;
		std::cout << "Shared operation assertions: " << c.assertionCount()
				  << ", failures: " << c.failureCount() << '\n' ;
		return c.failureCount() == 0U ? 0 : 1 ;
	} catch( const std::exception &error) {
		std::cerr << error.what() << '\n' ;
		return 2 ;
	}
}
