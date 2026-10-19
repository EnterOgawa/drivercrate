//------------------------------------------------------------------------------
/**
 * @file local_collector_shared_update_tests.cpp
 * @brief 元予約精算の再導出・実commit・停止回復と改変拒否を検査します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  固定精算・69保存後停止・原像保持のnativeを追加。
 * </pre>
 *
 * @note 自身の架空fixtureだけを使います。実HTTP・driver・OS設定を変更しません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#include "platform/local_collector_shared_store.h"
#include "platform/local_collector_projected_json.h"
#include "platform/official_file_verifier.h"
#include "test_framework.h"
#include <winrt/base.h>
#include <Windows.h>
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
// 実時計・実機とは無関係の元予約UTC秒です。
constexpr std::uint64_t UTC = 1790456400ULL ;
/** @brief 架空完全hashを固定桁で作ります。
 * @param[in] number 架空identity整数。
 * @return 小文字64桁hex。
 */
std::wstring			key( const std::size_t number)
{
	std::wostringstream s ;	// 同じ元入力を保持します。
	s << std::hex << std::setfill( L'0') << std::setw( 64) << number ;
	return s.str() ;
}
/** @brief Setup不成立をassertion結果と区別します。
 * @param[in] ok 必須setup条件。
 * @throws std::runtime_error Setup失敗。
 */
void require( const bool ok)
{
	// 不成立のsetupを測定成功へ含めません。
	if( !ok) {
		throw std::runtime_error( "Shared update fixture setup failed") ;
	}
}
/** @brief 二つの元未精算と任意の非稼働行を持つ閉鎖fixtureです。
 * @param[in] count 元request総数。二以上です。
 * @return 元予約と開始intentが完全一致する台帳。
 */
CollectorSharedLedgerSnapshot fixture( const std::size_t count = 2U)
{
	CollectorSharedLedgerSnapshot s ;	// 元CACHEとreviewを精算で消しません。
	s.collection	 = key( 1U) ;
	s.lastUtcMillis	 = UTC * 1000U ;
	s.budget.day	 = L"20260927" ;
	s.budget.lastUtc = UTC ;
	// 二groupを同時一slotずつ保持します。
	for( std::size_t i = 0U; i < 2U; ++i) {
		const auto			 name = i == 0U ? L"fixture-a" : L"fixture-b" ;	// 元の恒久group。
		CollectorWaitControl group ;										// Groupの元期限とreviewです。
		group.group		= name ;
		group.observed	= UTC * 1000U ;
		group.completed = (UTC - 10U) * 1000U ;
		group.notBefore = (UTC + 900U) * 1000U ;
		group.review	= i == 0U ;
		s.groups.emplace( name, group) ;
		s.budget.reservations.push_back(
			{key( 1000U + i), key( 100U + i), name, UTC, 4U * 1024U * 1024U, 4U * 1024U * 1024U, 0U}) ;
	}

	// 同prefixのrequestを固定昇順で保持します。
	for( std::size_t i = 0U; i < count; ++i) {
		CollectorSharedRequestState row ;	// 先頭二件だけが元未精算です。
		row.control.group	  = i == 1U ? L"fixture-b" : L"fixture-a" ;
		row.control.request	  = key( 20U + i) ;
		row.control.observed  = UTC * 1000U ;
		row.control.notBefore = (UTC + 900U) * 1000U ;
		row.control.review	  = i == 0U ;
		// 元未精算を予算と一対一に結合します。
		if( i < 2U) {
			row.control.generation = key( 1000U + i) ;
			row.control.job		   = key( 100U + i) ;
			row.control.started	   = UTC * 1000U ;
		}

		row.cache = CollectorSharedCacheReference{key( 8U), key( 9U), key( 10U)} ;
		s.requests.emplace( row.control.request, row) ;
	}

	return s ;
}
/** @brief 元予約と同じidentityの受領／中断です。
 * @param[in] index 二つの元予約のordinal。
 * @param[in] interrupted trueは応答なしの明示中断。
 * @return 固定した元時刻と観測。
 */
CollectorSharedSettlement operation( const std::size_t index = 0U, const bool interrupted = false)
{
	CollectorSharedSettlement op ;	// 回復時にもこの値を変更しません。
	op.request	= {index == 0U ? L"fixture-a" : L"fixture-b", key( 20U + index), key( 1000U + index),
				  key( 100U + index)} ;
	op.started	= UTC * 1000U ;
	op.finished = (UTC + 10U + index * 2U) * 1000U ;
	op.accepted = op.finished + 1000U ;
	op.interrupted			  = interrupted ;
	op.bytesKnown			  = !interrupted ;
	op.receivedBytes		  = interrupted ? 0U : 7U ;
	op.observation.successful = !interrupted ;
	op.observation.status	  = interrupted ? 0U : 200U ;
	return op ;
}
/** @brief 親writerと唯一子leaseを保持する実fixtureです。 */
struct Session {
	/// 元collection単一writer。
	LocalCollectorCollectionStore				parent ;
	/// Parentより先に解放する唯一子。
	std::unique_ptr<LocalCollectorSegmentLease> child ;
	/** @brief 自身の領域を開き、初回時だけ元台帳を保存します。
	 * @param[in] root 自身の絶対fixture領域。
	 * @param[in] initial trueは初回保存、falseは元中断／確定領域の再起動。
	 * @param[in] count 初回の元request数。
	 */
	Session( const std::filesystem::path &root, const bool initial, const std::size_t count = 2U)
	{
		require( parent.initialize( root, key( 1U)) == 0U) ;
		require( parent.borrowSegment( key( 2U), true, child) == 0U) ;
		// 元初回だけを同じ保護storeへ接続します。
		if( initial) {
			require( LocalCollectorSharedStore::bootstrap( parent, *child, fixture( count)) == 0U) ;
		}
	}
} ;
/** @brief 自身の絶対pathだけを内部extended表現で扱います。
 * @param[in] path 自身のfixture path。
 * @return Backslashを揃えた内部path。
 */
std::filesystem::path extended( const std::filesystem::path &path)
{
	return L"\\\\?\\" + std::filesystem::path( path).make_preferred().native() ;
}
/** @brief 自身のfile原byteを正規化せず読取ります。
 * @param[in] path 自身の既存file。
 * @return 原byte。
 */
std::string contents( const std::filesystem::path &path)
{
	std::ifstream stream( extended( path), std::ios::binary) ;	// 自身のfixtureだけです。
	require( stream.good()) ;
	return {std::istreambuf_iterator<char>( stream), {}} ;
}
/** @brief 自身の既存fileへ故意の不成立を作ります。
 * @param[in] path 自身のfile。
 * @param[in] bytes 改変する元byte。
 */
void alter( const std::filesystem::path &path, const std::string_view bytes)
{
	std::ofstream stream( extended( path),
						 std::ios::binary | std::ios::trunc) ;	// 自身のACLは保持します。
	require( stream.good()) ;
	stream.write( bytes.data(), static_cast<std::streamsize>( bytes.size())) ;
	require( stream.good()) ;
}
/** @brief 自身のlock以外の全原byteを保持します。
 * @param[in] root Fixtureだけの領域。
 * @return 相対名と原byte。未知file／stagingも含みます。
 */
std::map<std::wstring, std::string> image( const std::filesystem::path &root)
{
	std::map<std::wstring, std::string> result ;	// 拒否・再起動の非変更像です。
	// 自身の階層を一回走査します。
	for( const auto &entry : std::filesystem::recursive_directory_iterator( extended( root))) {
		// 排他lockは本文を持たずread共有を許可しません。
		if( entry.is_regular_file() && entry.path().filename() != L"collector.lock") {
			std::ifstream stream( entry.path(), std::ios::binary) ;	// Extendedのまま開きます。
			require( stream.good()) ;
			result.emplace( entry.path().lexically_relative( extended( root)).native(),
						   std::string( std::istreambuf_iterator<char>( stream), {})) ;
		}
	}

	return result ;
}
/** @brief 全66 canonical本文を比較します。
 * @param[in] a 元値。
 * @param[in] b 読戻し値。
 * @return 全保存意味が一致すればtrue。
 */
bool equal( const CollectorSharedLedgerSnapshot &a, const CollectorSharedLedgerSnapshot &b)
{
	CollectorSharedLedgerBytes aa ;	// 元本文です。
	CollectorSharedLedgerBytes bb ;	// 読戻し本文です。
	return encodeCollectorSharedLedger( a, aa) == 0U && encodeCollectorSharedLedger( b, bb) == 0U &&
		   aa.budget == bb.budget && aa.groups == bb.groups && aa.requests == bb.requests ;
}
/** @brief 自己hashが正しくても意味不成立の反証像を作ります。
 * @param[in] body 自身の架空canonical body。
 * @return 実CNGで再計算した専用envelope。
 */
std::string envelope( const std::string_view body)
{
	std::wstring hash ;	// 自己整合だけでは正しい元操作の証明にしません。
	require( computeCollectorMetadataSha256( body, hash) == 0) ;
	collector_projected_json::Writer w( 2U * 1024U * 1024U) ;	// 元上限を維持します。
	w.append( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
	w.text( body) ;
	w.append( ",\"sha256\":") ;
	w.wideText( hash) ;
	w.append( "}") ;
	return w.take() ;
}
/** @brief 自身のrecordの参照hashを自己整合させて改変します。
 * @param[in] raw 自身の保存envelope。
 * @param[in] field 故意に差し替える固定field名。
 * @return 本文CNG hashは一致するが元鎖と不一致のbyte。
 */
std::string forged( const std::string_view raw, const std::string &field)
{
	collector_projected_json::Reader r( raw,
									   2U * 1024U * 1024U) ;	// 反証fixture自身の固定envelopeです。
	r.literal( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
	auto	   body = r.text( 768U * 1024U) ;				// 自身の原本文を改変します。
	const auto at	= body.find( "\"" + field + "\":\"") ;	// 元の固定hash fieldだけです。
	require( at != std::string::npos) ;
	const auto hash = key( 9999U) ;	// 別の完全hashでも元鎖へ結合しません。
	body.replace( at + field.size() + 4U, 64U, winrt::to_string( winrt::hstring( hash))) ;
	return envelope( body) ;
}
/** @brief 元待機・課金と他行保持、疎な前後像を独立の期待値で検査します。
 * @param[in,out] c Native集計。
 */
void semantic( TestContext &c)
{
	const auto before = fixture( 4096U) ;				// 旧controlへ全4096行を渡さない入力です。
	CollectorSharedLedgerSnapshot  after ;				// 成功時だけ公開します。
	CollectorSharedSettlementDelta delta ;				// 一予約／二制御行だけの前後像です。
	const auto					   op = operation() ;	// 既知7 byteの受領です。
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedSettlement( before, op, after, delta) == 0U) ;
	DRIVERCRATE_EXPECT(
		c, after.requests.size() == 4096U && after.budget.reservations[0].phase == 1U &&
			   after.budget.reservations[0].charged == 7U && after.budget.day == before.budget.day) ;
	DRIVERCRATE_EXPECT(
		c, after.requests.at( key( 20U)).control.notBefore == op.finished + 86400000U &&
			   after.requests.at( key( 20U)).control.started == 0U &&
			   after.requests.at( key( 20U)).control.review && after.groups.at( L"fixture-a").review &&
			   after.groups.at( L"fixture-a").completed == op.finished) ;
	DRIVERCRATE_EXPECT( c, after.requests.at( key( 20U)).cache->cacheSha256 == key( 9U) &&
							  after.requests.at( key( 21U)).control.started == UTC * 1000U &&
							  after.requests.at( key( 4095U + 20U)).control.observed == UTC * 1000U) ;
	CollectorBudgetSnapshot budget ;	// 疎な一予約を既存codecで独立検査します。
	CollectorWaitSnapshot	wait ;		// 全4096行ではなく二行だけです。
	DRIVERCRATE_EXPECT( c, parseCollectorBudgetSnapshot( delta.budgetAfter, budget) &&
							  budget.reservations.size() == 1U) ;
	DRIVERCRATE_EXPECT( c, parseCollectorWaitSnapshot( delta.waitAfter, wait) &&
							  wait.controls.size() == 2U) ;
	std::string				  encoded ;	// 全byte roundtripを照合します。
	CollectorSharedSettlement decoded ;	// 拒否後の出力も検査します。
	DRIVERCRATE_EXPECT( c, encodeCollectorSharedSettlement( op, encoded) == 0U &&
							  decodeCollectorSharedSettlement( encoded, decoded) == 0U) ;
	std::string again ;	// Decoderが元値を変えていないことを確認します。
	DRIVERCRATE_EXPECT( c,
					   encodeCollectorSharedSettlement( decoded, again) == 0U && again == encoded) ;
	DRIVERCRATE_EXPECT( c, decodeCollectorSharedSettlement( encoded + " ", decoded) == 13U &&
							  decoded.accepted == 0U) ;
	// 元開始と観測の矛盾を全て非通信で拒否します。
	for( std::size_t kind = 0U; kind < 12U; ++kind) {
		auto invalid = op ;	// 元入力を条件ごとに独立改変します。
		// 一つだけを改変して拒否原因を固定します。
		switch( kind) {
			case 0U:	// 元requestを差し替えません。
				invalid.request.requestKey = key( 999U) ;
				break ;

			case 1U:	// 元groupを変更しません。
				invalid.request.group = L"fixture-b" ;
				break ;

			case 2U:	// 元generationを差し替えません。
				invalid.request.generationKey = key( 999U) ;
				break ;

			case 3U:	// 元jobを差し替えません。
				invalid.request.jobKey = key( 999U) ;
				break ;

			case 4U:	// 開始を元予約から変更しません。
				invalid.started += 1000U ;
				break ;

			case 5U:	// 最大枠を超えて精算しません。
				invalid.receivedBytes = 4U * 1024U * 1024U + 1U ;
				break ;

			case 6U:	// 未知量を既知7 byteへ偽装しません。
				invalid.bytesKnown = false ;
				break ;

			case 7U:	// 中断へ実HTTP観測を混ぜません。
				invalid.interrupted = true ;
				break ;

			case 8U:	// 受領時計を元最高値より戻しません。
				invalid.finished = UTC * 1000U - 1U ;
				break ;

			case 9U:	// 成功へ403を混ぜません。
				invalid.observation.status = 403U ;
				break ;

			case 10U:	// 開始を元秒へ完全結合します。
				invalid.started += 1U ;
				break ;

			default:	// 成功へchallengeを混ぜません。
				invalid.observation.challenge = true ;
				break ;
		}

		DRIVERCRATE_EXPECT( c,
						   deriveCollectorSharedSettlement( before, invalid, after, delta) == 13U &&
							   after.collection.empty() && delta.operation.empty()) ;
	}

	const auto stopped = operation( 0U, true) ;	// 未知byte課金の明示中断です。
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedSettlement( before, stopped, after, delta) == 0U &&
							  after.budget.reservations[0].phase == 2U &&
							  after.budget.reservations[0].charged == 4U * 1024U * 1024U) ;
	const auto closed = after ;	// 入出力を分けて同じ予約の再精算を拒否します。
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedSettlement( closed, stopped, after, delta) == 13U &&
							  after.collection.empty() && delta.operation.empty()) ;
	auto retry							  = operation( 1U) ;	// 503と未観測byteの元group期限です。
	retry.observation.successful		  = false ;
	retry.observation.status			  = 503U ;
	retry.observation.retryAfterUtcMillis = (UTC + 2U * 86400U) * 1000U ;
	retry.observation.needsReview		  = true ;
	retry.bytesKnown					  = false ;
	retry.receivedBytes					  = 0U ;
	DRIVERCRATE_EXPECT(
		c, deriveCollectorSharedSettlement( before, retry, after, delta) == 0U &&
			   after.groups.at( L"fixture-b").notBefore == retry.observation.retryAfterUtcMillis &&
			   after.groups.at( L"fixture-b").review && after.requests.at( key( 21U)).control.review &&
			   after.budget.reservations[1].phase == 1U &&
			   after.budget.reservations[1].charged == 4U * 1024U * 1024U) ;
	// 同じ元rate-limitのもう一つのstatusです。
	retry.observation.status = 429U ;
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedSettlement( before, retry, after, delta) == 0U &&
							  after.groups.at( L"fixture-b").notBefore ==
								  retry.observation.retryAfterUtcMillis) ;
	auto forbidden					 = operation( 1U) ;	// 403はgroupのreviewを解除しません。
	forbidden.observation.successful = false ;
	forbidden.observation.status	 = 403U ;
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedSettlement( before, forbidden, after, delta) == 0U &&
							  after.groups.at( L"fixture-b").review) ;
	auto nextDay = op ;	// 日跨ぎの受領も元日の予約へ精算します。
	nextDay.finished += 86400000U ;
	nextDay.accepted += 86400000U ;
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedSettlement( before, nextDay, after, delta) == 0U &&
							  after.budget.day == before.budget.day &&
							  after.budget.reservations[0].started == UTC &&
							  after.budget.reservations[0].charged == 7U) ;
	auto advanced		   = before ;	// 形式正常の元最高時計より受領を戻せません。
	advanced.lastUtcMillis = op.accepted + 1U ;
	DRIVERCRATE_EXPECT( c, deriveCollectorSharedSettlement( advanced, op, after, delta) == 13U &&
							  after.collection.empty() && delta.operation.empty()) ;
	DRIVERCRATE_EXPECT( c,
					   deriveCollectorSharedSettlement( fixture( 4097U), op, after, delta) == 68U &&
						   after.collection.empty() && delta.operation.empty()) ;
}
/** @brief 二更新・元履歴保持・reentrancy・別親能力を検査します。
 * @param[in,out] c Native集計。
 * @param[in] root 自身の領域。
 */
void normal( TestContext &c, const std::filesystem::path &root)
{
	Session	   s( root, true) ;										// 初回未精算二枠だけを保存します。
	const auto original = image( root / L"segments" / key( 2U)) ;	// 元準備像とbaseを保持します。
	DWORD	   nested{} ;											// 実保存中の再入結果です。
	DRIVERCRATE_EXPECT(
		c, LocalCollectorSharedStore::settle( s.parent, *s.child, operation(),
											 [&]( const std::size_t n) {
												 // 元操作保存の直後だけ再入を検査します。
												 if( n == 1U) {
													 nested = LocalCollectorSharedStore::settle(
														 s.parent, *s.child, operation()) ;
												 }

												 return 0U ;
											 }) == 0U &&
			   nested == 170U) ;
	DRIVERCRATE_EXPECT(
		c, LocalCollectorSharedStore::settle( s.parent, *s.child, operation( 1U, true)) == 0U) ;
	CollectorSharedLedgerSnapshot saved ;	// 最新値を元操作から全再生します。
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::load( s.parent, *s.child, saved) == 0U &&
							  saved.budget.reservations[0].charged == 7U &&
							  saved.budget.reservations[1].phase == 2U &&
							  saved.budget.reservations[1].charged == 4U * 1024U * 1024U) ;
	const auto current = image( root / L"segments" / key( 2U)) ;	// 元fileの全byteを比較します。
	// 更新を元bootstrap像へ上書きしていないことを検査します。
	for( const auto &[name, raw] : original) {
		DRIVERCRATE_EXPECT( c, current.at( name) == raw) ;
	}

	const auto all = image( root) ;	// 最新再精算を新しい課金にしません。
	DRIVERCRATE_EXPECT(
		c, LocalCollectorSharedStore::settle( s.parent, *s.child, operation( 1U, true)) == 0U &&
			   all == image( root)) ;
	DRIVERCRATE_EXPECT( c,
					   LocalCollectorSharedStore::settle( s.parent, *s.child, operation()) == 13U &&
						   all == image( root)) ;
	Session other( root.parent_path().parent_path() / L"other" / key( 1U), true) ;	// 別の親能力です。
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::settle( other.parent, *s.child, operation()) ==
								  87U &&
							  all == image( root)) ;
}
/** @brief 全保存後停止・回復中再停止・二回別owner再起動を検査します。
 * @param[in,out] c Native集計。
 * @param[in] root 自身の独立領域。
 * @param[in] stop 元1～全保存数のordinal。
 * @param[in] sparse trueは同UTCの三role／六保存、falseは66role／69保存です。
 */
void window( TestContext &c, const std::filesystem::path &root, const std::size_t stop,
			const bool sparse = false)
{
	auto op = operation() ;	// 全再起動で同じ元操作を使用します。
	// 同UTCではheaderを変えず、実変更roleだけを保存します。
	if( sparse) {
		op.finished = op.started ;
		op.accepted = op.started ;
	}

	const std::size_t total = sparse ? 6U : 69U ;	// 元変更role数と確定保存数です。
	{
		Session s( root, true) ;	// 元初回値を独立保存します。
		DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::settle( s.parent, *s.child, op,
																[stop]( const std::size_t n) {
																	return n == stop ? 995U : 0U ;
																}) == 995U) ;
	}
	{
		Session		recovering( root, false) ;	// 回復中も最初の不足保存の直後で停止します。
		std::size_t observed{} ;				// 元suffix ordinalだけを観測します。
		const auto	code = LocalCollectorSharedStore::settle( recovering.parent, *recovering.child,
															 op, [&]( const std::size_t n) {
																 observed = n ;
																 return 995U ;
															 }) ; // 元操作は変更しません。
		DRIVERCRATE_EXPECT( c, code == (stop == total ? 0U : 995U) &&
								  observed == (stop == total ? 0U : stop + 1U)) ;
	}
	{
		Session recovered( root, false) ;	// 再停止後の同じ不足suffixだけを保存します。
		DRIVERCRATE_EXPECT(
			c, LocalCollectorSharedStore::settle( recovered.parent, *recovered.child, op) == 0U) ;
	}
	const auto all = image( root) ;	// 回復後の全原byteです。
	// 別ownerによる二回再起動でも新操作を作りません。
	for( std::size_t repeat = 0U; repeat < 2U; ++repeat) {
		Session						  loaded( root, false) ;	// 前回のhandleを再利用しません。
		CollectorSharedLedgerSnapshot copy ;					// 全再導出後だけ公開します。
		DRIVERCRATE_EXPECT(
			c, LocalCollectorSharedStore::settle( loaded.parent, *loaded.child, op,
												 []( const std::size_t) { return 995U ; }) == 0U) ;
		DRIVERCRATE_EXPECT(
			c, LocalCollectorSharedStore::load( loaded.parent, *loaded.child, copy) == 0U &&
				   copy.budget.reservations[0].charged == 7U &&
				   copy.requests.at( key( 20U)).control.notBefore == op.finished + 86400000U) ;
		DRIVERCRATE_EXPECT( c, all == image( root)) ;
	}
}
/** @brief 自己hash一致の偽像を含む改変／非prefix／別候補を拒否します。
 * @param[in,out] c Native集計。
 * @param[in] root 自身の領域。
 * @param[in] kind 八つの独立拒否条件。
 */
void rejected( TestContext &c, const std::filesystem::path &root, const std::size_t kind)
{
	Session	   s( root, true) ;	// 拒否条件を別々に保存します。
	const auto stop = kind == 1U				 ? 3U
					  : kind == 4U || kind == 7U ? 1U
												 : 69U ;	// 非prefix／未登録と確定を区別します。
	require( LocalCollectorSharedStore::settle(
				s.parent, *s.child, operation(),
				[stop]( const std::size_t n) { return n == stop ? 995U : 0U ; }) == 995U) ;
	const auto child = root / L"segments" / key( 2U) ;	// 自身の固定元区間です。
	// 自己整合hashでも元headとの結合が不成立なら拒否します。
	if( kind == 0U) {
		alter( child / L"runs/shared-update-00.json",
			  forged( contents( child / L"runs/shared-update-00.json"), "previousHead")) ;
	}
	// 元afterの正しいbyteでも連続prefix以外は拒否します。
	else if( kind == 1U) {
		CollectorSharedLedgerSnapshot  after ;	// 正しい元afterの末尾像だけです。
		CollectorSharedSettlementDelta delta ;	// 全roleを変更したことを別に導出します。
		require( deriveCollectorSharedSettlement( fixture(), operation(), after, delta) == 0U) ;
		CollectorSharedLedgerBytes bytes ;	// 元codecの正しい末尾bodyです。
		require( encodeCollectorSharedLedger( after, bytes) == 0U) ;
		alter( root / L"current/shared-requests-3f.json", envelope( bytes.requests[63U])) ;
	}
	// 確定後欠損を不足suffixとして再作成しません。
	else if( kind == 2U) {
		require( std::filesystem::remove( extended( root / L"current/shared-requests-3f.json"))) ;
	}
	// 元操作がなくてもheadだけで精算済みにしません。
	else if( kind == 3U) {
		require( std::filesystem::remove( extended( child / L"runs/shared-update-00.json"))) ;
	}
	// 未登録の別操作候補を無視しません。
	else if( kind == 4U) {
		require( s.child->store().write( L"runs/shared-update-01.json", "{}") == 0U) ;
	}
	// 元baseを最新台帳から補完しません。
	else if( kind == 5U) {
		alter( child / L"current/segment-shared-base-v1.json", "{}") ;
	}
	// 自己整合headでも別tipは全鎖へ一致しません。
	else if( kind == 6U) {
		alter( root / L"current/collection-head-v1.json",
			  forged( contents( root / L"current/collection-head-v1.json"), "tip")) ;
	}

	const auto all = image( root) ;	// 改変後の元状態を自動修復しません。
	auto	   op  = operation() ;	// 別時刻候補も保存前に拒否します。
	// 元record保存後のaccepted変更を許しません。
	if( kind == 7U) {
		++op.accepted ;
	}

	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::settle( s.parent, *s.child, op) == 13U &&
							  all == image( root)) ;
	CollectorSharedLedgerSnapshot copy = fixture() ;	// 失敗後に旧値も部分値も公開しません。
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::load( s.parent, *s.child, copy) == 13U &&
							  copy.collection.empty() && all == image( root)) ;
}
/** @brief 実rename第一5とstaging残留の非変更停止を検査します。
 * @param[in,out] c Native集計。
 * @param[in] root 自身の領域。
 */
void blocked( TestContext &c, const std::filesystem::path &root)
{
	Session s( root, true) ;	// 親commit登録後で止めます。
	require(
		LocalCollectorSharedStore::settle( s.parent, *s.child, operation(), []( const std::size_t n) {
			return n == 2U ? 995U : 0U ;
		}) == 995U) ;
	const auto	 path	= root / L"current/collection-head-v1.json" ;	// 自身の登録headだけです。
	const auto	 old	= contents( path) ;								// 失敗後も元headを保持します。
	const HANDLE handle = CreateFileW( extended( path).c_str(), GENERIC_READ,
									  FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
									  FILE_ATTRIBUTE_NORMAL, nullptr) ;	// DELETE共有を与えません。
	require( handle != INVALID_HANDLE_VALUE) ;
	const auto closer = []( void *value) { CloseHandle( value) ; } ;		// 自身のhandleだけを解放します。
	const std::unique_ptr<void, decltype( closer)> guard( handle, closer) ;	// 実rename拒否のRAIIです。
	const auto code = LocalCollectorSharedStore::settle( s.parent, *s.child,
														// 第一数値を観測します。
														operation()) ;
	std::cout << "Shared update blocked-replace Win32 code: " << code << '\n' ;
	DRIVERCRATE_EXPECT(
		c, code == 5U && contents( path) == old &&
			   std::filesystem::exists( extended( root / L"current/collection-head-v1.json.tmp"))) ;
	const auto failed = image( root) ;	// 残留stageも自動変更しません。
	DRIVERCRATE_EXPECT( c,
					   LocalCollectorSharedStore::settle( s.parent, *s.child, operation()) == 13U &&
						   failed == image( root)) ;
}
} // namespace
} // namespace drivercrate::test
/** @brief 自身の固定native fixtureを非通信で実行します。
 * @return 合格0、assertion失敗1、setup不成立2。
 */
int wmain()
{
	try {
		winrt::init_apartment( winrt::apartment_type::multi_threaded) ;
		drivercrate::test::TestContext c ;	// 架空nativeの独立分母です。
		const auto base = std::filesystem::absolute( std::filesystem::path( L"work/tmp") /
													(L"shared-update-" +
													 std::to_wstring( GetCurrentProcessId()) + L"-" +
													 // 自身の未存在領域。
													 std::to_wstring( GetTickCount64()))) ;
		drivercrate::test::require( std::filesystem::create_directories( base)) ;
		drivercrate::test::semantic( c) ;
		drivercrate::test::normal( c, base / L"normal" / drivercrate::test::key( 1U)) ;
		// 69個の独立領域で全実atomic保存後の停止を測ります。
		for( std::size_t stop = 1U; stop <= 69U; ++stop) {
			drivercrate::test::window(
				c, base / (L"stop-" + std::to_wstring( stop)) / drivercrate::test::key( 1U), stop) ;
		}

		// 同UTCの三roleだけの六保存でも不足ordinalを正しく回復します。
		for( std::size_t stop = 1U; stop <= 6U; ++stop) {
			drivercrate::test::window(
				c, base / (L"sparse-" + std::to_wstring( stop)) / drivercrate::test::key( 1U), stop,
				true) ;
		}

		// 八拒否条件を独立させて原改変を保持します。
		for( std::size_t kind = 0U; kind < 8U; ++kind) {
			drivercrate::test::rejected(
				c, base / (L"rejected-" + std::to_wstring( kind)) / drivercrate::test::key( 1U),
				kind) ;
		}

		drivercrate::test::blocked( c, base / L"blocked" / drivercrate::test::key( 1U)) ;
		std::cout << "Shared update assertions: " << c.assertionCount()
				  << ", failures: " << c.failureCount() << '\n' ;
		return c.failureCount() == 0U ? 0 : 1 ;
	} catch( const std::exception &error) {
		std::cerr << error.what() << '\n' ;
		return 2 ;
	}
}
