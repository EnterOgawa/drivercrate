//------------------------------------------------------------------------------
/**
 * @file local_collector_segment_switch_tests.cpp
 * @brief 元値非変更・切替前条件・全draft結合と有限codecを検査します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  切替draftの非循環結合と有限契約を追加。
 * </pre>
 *
 * @note 架空hashの非保存fixtureです。実seal・復旧・HTTP・導入を測りません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#include "platform/local_collector_segment_switch.h"
#include "platform/official_file_verifier.h"
#include "test_framework.h"
#include <winrt/base.h>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <utility>

namespace drivercrate::test {
namespace {
// 旧fixtureと同じ元UTC秒を保持し実機時計を使いません。
constexpr std::uint64_t UTC = 1790456400ULL ;

/** @brief 有限の架空完全keyを作ります。
 * @param[in] value 末尾の架空整数。
 * @return 64桁の小文字hex。
 */
std::wstring			key( const std::size_t value)
{
	std::wostringstream stream ;	// 実deviceやURLを含みません。
	stream << std::hex << std::setfill( L'0') << std::setw( 64) << value ;
	return stream.str() ;
}
/** @brief Fixtureの検査済みASCII hashを明示的にbyteへ変換します。
 * @param[in] value keyまたは成功CNGが返した完全ASCII hash。
 * @return 一文字一byteの元順序。
 */
std::string asciiHash( const std::wstring_view value)
{
	std::string bytes ;	// 暗黙のUnicode縮小を使いません。
	// FixtureとCNGの既知ASCII範囲だけを明示変換します。
	for( const wchar_t letter : value) {
		bytes.push_back( static_cast<char>( letter)) ;
	}

	return bytes ;
}
/** @brief 旧待機・review・未知課金を保持する元閉鎖台帳です。
 * @param[in] count 架空request数。
 * @return 実公式根拠を主張しない型付きfixture。
 */
CollectorSharedLedgerSnapshot snapshot( const std::size_t count = 2U)
{
	CollectorSharedLedgerSnapshot s ;	// 次区間作成で自動初期化しない元値です。
	s.collection	 = key( 99999U) ;
	s.lastUtcMillis	 = UTC * 1000U ;
	s.budget.day	 = L"20260927" ;
	s.budget.lastUtc = UTC ;
	s.budget.reservations.push_back( {key( 9000U), key( 9001U), L"fixture-group", UTC,
									 8U * 1024U * 1024U, 8U * 1024U * 1024U, 2U}) ;
	CollectorWaitControl group ;	// 元二秒間隔と長い待機を持ちます。
	group.group		= L"fixture-group" ;
	group.observed	= UTC * 1000U ;
	group.completed = UTC * 1000U ;
	group.notBefore = (UTC + 300U) * 1000U ;
	group.review	= true ;
	s.groups.emplace( group.group, group) ;
	// 境界数でも元期限・旧CACHE参照を保持します。
	for( std::size_t n = 0U; n < count; ++n) {
		CollectorSharedRequestState row ;	// 全66本文一致の比較対象です。
		row.control.group	  = group.group ;
		row.control.request	  = key( n + 1U) ;
		row.control.observed  = UTC * 1000U ;
		row.control.notBefore = (UTC + 86400U) * 1000U ;
		row.cache			  = CollectorSharedCacheReference{key( 7U), key( 8U), key( 9U)} ;
		s.requests.emplace( row.control.request, row) ;
	}

	return s ;
}
/** @brief 偽のseal参照と閉鎖観測で非保存requestを作ります。
 * @return 実seal／worker停止の証明ではない元入力。
 */
CollectorSegmentSwitchRequest request()
{
	CollectorSegmentSwitchRequest r ;	// 初回区間からのdraftだけです。
	r.oldSegment  = key( 50000U) ;
	r.newSegment  = key( 50001U) ;
	r.oldHead	  = key( 50002U) ;
	r.oldRoot	  = key( 50003U) ;
	r.seal		  = key( 50004U) ;
	r.inventory	  = {key( 50005U)} ;
	r.accepted	  = UTC * 1000U ;
	r.observation = {true, true, true, 0U, 0U, false} ;
	return r ;
}
/** @brief 独立したCNG呼出しで元body hashを取得します。
 * @param[in,out] c Assertion集計。
 * @param[in] body 非空のfixture本文。
 * @return 実CNGの元本文hash。
 */
std::wstring hash( TestContext &c, const std::string_view body)
{
	std::wstring value ;	// Draftの出力hashを使いません。
	DRIVERCRATE_EXPECT( c, computeCollectorMetadataSha256( body, value) == 0) ;
	return value ;
}
/** @brief 失敗時の全draft出力クリアを検査します。
 * @param[in,out] c Assertion集計。
 * @param[in] before 元台帳。
 * @param[in] after 改変または元carry。
 * @param[in] r 改変または元request。
 * @param[in] code 元拒否code。
 */
void rejected( TestContext &c, const CollectorSharedLedgerSnapshot &before,
			  const CollectorSharedLedgerSnapshot &after, const CollectorSegmentSwitchRequest &r,
			  const DWORD code = ERROR_INVALID_DATA)
{
	CollectorSegmentSwitchDraft d ;	// 部分値が残る失敗も検出します。
	d.base				= "old" ;
	d.intent.collection = key( 1U) ;
	d.images.fill( key( 2U)) ;
	DRIVERCRATE_EXPECT( c, prepareCollectorSegmentSwitchDraft( before, after, r, d) == code) ;
	DRIVERCRATE_EXPECT( c, d.base.empty() && d.bootstrap.empty() && d.nextHead.empty() &&
							  d.intentBytes.empty() && d.intentHash.empty() &&
							  d.intent.collection.empty()) ;
	DRIVERCRATE_EXPECT(
		c, std::all_of( d.images.begin(), d.images.end(), []( const auto &v) { return v.empty() ; })) ;
}
/** @brief Decode失敗の出力クリアも検査します。
 * @param[in,out] c Assertion集計。
 * @param[in] bytes 改変した有限本文。
 * @param[in] code 元拒否code。
 */
void refusedBytes( TestContext &c, const std::string_view bytes,
				  const DWORD code = ERROR_INVALID_DATA)
{
	CollectorSegmentSwitchIntent i ;	// 古い値を失敗後に残しません。
	i.collection = key( 1U) ;
	i.inventory	 = {key( 2U)} ;
	DRIVERCRATE_EXPECT( c, decodeCollectorSegmentSwitchIntent( bytes, i) == code) ;
	DRIVERCRATE_EXPECT( c, i == CollectorSegmentSwitchIntent{}) ;
}
/** @brief 固定元入力・全本文指紋と非変更carryを検査します。
 * @param[in,out] c Assertion集計。
 */
void roundTrips( TestContext &c)
{
	// 空・shard境界・4096最大件数の型付き条件を独立に確認します。
	for( const std::size_t count : {0U, 1U, 64U, 65U, 4096U}) {
		const auto s = snapshot( count) ;	// 実保存raw枠の達成値ではありません。
		auto	   r = request() ;			// 翌日acceptedでも元日の課金をリセットしません。
		r.accepted += 86400000U ;
		CollectorSharedLedgerBytes original ;	// 呼出し前の66元本文です。
		DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( s, original) == 0U) ;
		CollectorSegmentSwitchDraft d ;	// 非保存出力です。
		DRIVERCRATE_EXPECT( c, prepareCollectorSegmentSwitchDraft( s, s, r, d) == 0U) ;
		DRIVERCRATE_EXPECT( c, checkCollectorSegmentSwitchDraft( s, s, r, d) == 0U) ;
		DRIVERCRATE_EXPECT( c, d.intent.ordinal == 1U && d.intent.accepted == r.accepted) ;
		DRIVERCRATE_EXPECT( c, hash( c, d.base) == d.intent.base &&
								  hash( c, d.bootstrap) == d.intent.bootstrap &&
								  hash( c, d.nextHead) == d.intent.nextHead &&
								  hash( c, d.intentBytes) == d.intentHash) ;
		DRIVERCRATE_EXPECT( c, hash( c, original.budget) == d.images[0] &&
								  hash( c, original.groups) == d.images[1]) ;
		std::string ledger = "{\"schema\":\"collector-shared-digest-v1\",\"collection\":\"" +
							 asciiHash( s.collection) +
							 "\",\"hashes\":[" ;	// Writerを使わない独立byte組立てです。
		// 既存store契約の66 hashを独立に元本文から再計算します。
		for( std::size_t n = 0U; n < 66U; ++n) {
			const auto &body  = n == 0U	  ? original.budget
								: n == 1U ? original.groups
										  : original.requests[n - 2U] ;	// 元固定roleの本文です。
			const auto	value = hash( c, body) ;						// 不信任draft.imagesを借用しません。
			// 先頭以外に既存domainのcommaだけを付けます。
			if( n != 0U) {
				ledger += "," ;
			}

			ledger += "\"" + asciiHash( value) + "\"" ;
		}

		ledger += "]}" ;
		DRIVERCRATE_EXPECT( c, hash( c, ledger) == d.intent.ledger) ;
		// 全shardの元最高時刻とCACHE bindingを同じ本文hashへ保持します。
		for( std::size_t n = 0U; n < original.requests.size(); ++n) {
			DRIVERCRATE_EXPECT( c, hash( c, original.requests[n]) == d.images[n + 2U]) ;
		}

		CollectorSegmentSwitchIntent copy ;	// 全field順の独立decodeです。
		DRIVERCRATE_EXPECT( c, decodeCollectorSegmentSwitchIntent( d.intentBytes, copy) == 0U &&
								  copy == d.intent) ;
		std::string bytes ;	// 再encodeの完全一致を測ります。
		DRIVERCRATE_EXPECT( c, encodeCollectorSegmentSwitchIntent( copy, bytes) == 0U &&
								  bytes == d.intentBytes) ;
		CollectorSharedLedgerBytes after ;	// Callerの原値も変えていません。
		DRIVERCRATE_EXPECT(
			c, encodeCollectorSharedLedger( s, after) == 0U && original.budget == after.budget &&
				   original.groups == after.groups && original.requests == after.requests) ;
		DRIVERCRATE_EXPECT( c, s.budget.day == L"20260927" && s.lastUtcMillis == UTC * 1000U &&
								  s.budget.reservations.front().charged == 8U * 1024U * 1024U &&
								  s.groups.begin()->second.review &&
								  s.groups.begin()->second.completed == UTC * 1000U) ;
		DRIVERCRATE_EXPECT( c, d.base.find( "bootstrap") == std::string::npos &&
								  d.base.find( "nextHead") == std::string::npos &&
								  d.bootstrap.find( "intent") == std::string::npos &&
								  d.nextHead.find( "intent") == std::string::npos) ;
	}
}
/** @brief 全切替前条件と開始・未精算／carry改変を拒否します。
 * @param[in,out] c Assertion集計。
 */
void readiness( TestContext &c)
{
	const auto s = snapshot() ;	// 反証毎に同じ元状態から作ります。
	// 六つのcaller観測を一つずつ未成立へ変えます。
	for( unsigned kind = 0U; kind < 6U; ++kind) {
		auto r = request() ;	// 他条件は全て固定した正常値です。
		// Worker停止観測を欠かした条件です。
		if( kind == 0U) {
			r.observation.workersJoined = false ;
		}
		// 最後の世代完了を欠かした条件です。
		else if( kind == 1U) {
			r.observation.lastGenerationComplete = false ;
		}
		// Summary／pointerの整合を欠かした条件です。
		else if( kind == 2U) {
			r.observation.summaryPointerConsistent = false ;
		}
		// 一つの未受領を残した条件です。
		else if( kind == 3U) {
			r.observation.unreceived = 1U ;
		}
		// 一つの未精算を残した条件です。
		else if( kind == 4U) {
			r.observation.unsettled = 1U ;
		} else {
			// 既存commitを活動中とした条件です。
			r.observation.activeCommit = true ;
		}

		rejected( c, s, s, r) ;
	}

	auto pending = s ;	// 台帳側の開始／予約はcallerの0観測とは別に検査します。
	pending.budget.reservations.front().phase = 0U ;
	auto &row	   = pending.requests.begin()->second.control ;	// 予約と一対一の開始を作ります。
	row.generation = key( 9000U) ;
	row.job		   = key( 9001U) ;
	row.started	   = UTC * 1000U ;
	CollectorSharedLedgerBytes valid ;	// 関係正常な未精算でもcarryを拒否します。
	DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( pending, valid) == 0U) ;
	rejected( c, pending, pending, request()) ;
	auto after							= s ;	// 元reviewの自動解除を許しません。
	after.groups.begin()->second.review = false ;
	rejected( c, s, after, request()) ;
	after = s ;
	after.requests.begin()->second.control.notBefore += 1U ;
	rejected( c, s, after, request()) ;
	after = s ;
	after.groups.begin()->second.completed -= 1U ;
	rejected( c, s, after, request()) ;
	after									  = s ;
	after.budget.reservations.front().phase	  = 1U ;
	after.budget.reservations.front().charged = 1U ;
	rejected( c, s, after, request()) ;
	after										  = s ;
	after.requests.begin()->second.cache->binding = key( 20U) ;
	rejected( c, s, after, request()) ;
	after			 = s ;
	after.collection = key( 20U) ;
	rejected( c, s, after, request()) ;
	auto r = request() ;	// 回復時の時計で元acceptedを後退させません。
	r.accepted -= 1U ;
	rejected( c, s, s, r) ;
	r.accepted = 4102444800000ULL ;
	rejected( c, s, s, r) ;
}
/** @brief Ordinalと集合件数・元順序を検査します。
 * @param[in,out] c Assertion集計。
 */
void boundaries( TestContext &c)
{
	const auto s = snapshot() ;	// 件数試験以外の状態は固定です。
	auto	   r = request() ;	// 最大16inventoryを一件ずつ確認します。
	// 件数1～16を保持しcanonical decodeでも順序が変わらないことを測ります。
	for( std::size_t n = 1U; n <= 16U; ++n) {
		r.inventory.clear() ;
		// 新しい元順序のn件を用意します。
		for( std::size_t k = 0U; k < n; ++k) {
			r.inventory.push_back( key( 60000U + k)) ;
		}

		CollectorSegmentSwitchDraft d ;	// 物理inventoryの達成試験ではありません。
		DRIVERCRATE_EXPECT( c, prepareCollectorSegmentSwitchDraft( s, s, r, d) == 0U) ;
		CollectorSegmentSwitchIntent copy ;	// 全項目を元順序で読み戻します。
		DRIVERCRATE_EXPECT( c, decodeCollectorSegmentSwitchIntent( d.intentBytes, copy) == 0U &&
								  copy.inventory == r.inventory) ;
		// 二件以上では元ordinalの逆転を同一draftとして受理しません。
		if( n > 1U) {
			auto reversed = r ;	// 照合元だけを反転して差分を測ります。
			std::reverse( reversed.inventory.begin(), reversed.inventory.end()) ;
			DRIVERCRATE_EXPECT( c, checkCollectorSegmentSwitchDraft( s, s, reversed, d) == 13U) ;
		}
	}

	r.inventory.push_back( key( 70000U)) ;
	rejected( c, s, s, r, ERROR_TOO_MANY_NAMES) ;
	r = request() ;
	r.inventory.clear() ;
	rejected( c, s, s, r) ;
	r			 = request() ;
	r.oldOrdinal = 1022U ;
	// 旧区間1022までの架空seal参照を元履歴順に用意します。
	for( std::size_t n = 0U; n < 1022U; ++n) {
		r.sealed.push_back( {key( 100000U + n), key( 200000U + n)}) ;
	}

	CollectorSegmentSwitchDraft d ;	// 最終許可ordinalの型付きdraftです。
	DRIVERCRATE_EXPECT( c, prepareCollectorSegmentSwitchDraft( s, s, r, d) == 0U) ;
	DRIVERCRATE_EXPECT( c, d.intent.ordinal == 1023U && d.nextHead.size() < 256U * 1024U) ;
	DRIVERCRATE_EXPECT( c, checkCollectorSegmentSwitchDraft( s, s, r, d) == 0U) ;
	auto reversed = r ;	// 元履歴順をsortして同一扱いしません。
	std::reverse( reversed.sealed.begin(), reversed.sealed.end()) ;
	DRIVERCRATE_EXPECT( c, checkCollectorSegmentSwitchDraft( s, s, reversed, d) == 13U) ;
	r.oldOrdinal = 1023U ;
	r.sealed.push_back( {key( 300000U), key( 300001U)}) ;
	rejected( c, s, s, r, ERROR_TOO_MANY_NAMES) ;
	r			 = request() ;
	r.oldOrdinal = 1U ;
	rejected( c, s, s, r) ;
	r.sealed = {{key( 100U), key( 101U)}} ;
	DRIVERCRATE_EXPECT( c, prepareCollectorSegmentSwitchDraft( s, s, r, d) == 0U) ;
	r.sealed.front().segment = r.newSegment ;
	rejected( c, s, s, r) ;
	r.sealed.front().segment = r.oldSegment ;
	rejected( c, s, s, r) ;
	r.oldOrdinal = 2U ;
	r.sealed	 = {{key( 100U), key( 101U)}, {key( 100U), key( 102U)}} ;
	rejected( c, s, s, r) ;
	r			 = request() ;
	r.newSegment = r.oldSegment ;
	rejected( c, s, s, r) ;
	r		  = request() ;
	r.oldHead = L"../outside" ;
	rejected( c, s, s, r) ;
	rejected( c, snapshot( 4097U), snapshot( 4097U), request(), ERROR_TOO_MANY_NAMES) ;
}
/** @brief 全draft role・hashと自己hash再計算の改変を拒否します。
 * @param[in,out] c Assertion集計。
 */
void bindings( TestContext &c)
{
	const auto					s = snapshot() ;	// 原観測と原台帳を照合側だけが保持します。
	const auto					r = request() ;		// 不信任draftの値から再導出しません。
	CollectorSegmentSwitchDraft original ;			// 正常参照出力です。
	DRIVERCRATE_EXPECT( c, prepareCollectorSegmentSwitchDraft( s, s, r, original) == 0U) ;
	// 全66本文hashの一件ずつ差替えを別反証で測ります。
	for( std::size_t n = 0U; n < original.images.size(); ++n) {
		auto d		= original ;	// 他値を一切変えない独立改変です。
		d.images[n] = key( 400000U + n) ;
		DRIVERCRATE_EXPECT( c, checkCollectorSegmentSwitchDraft( s, s, r, d) == 13U) ;
	}

	// 四つの元bodyを一件ずつ変え、外側hashの更新でも拒否することを測ります。
	for( unsigned role = 0U; role < 4U; ++role) {
		auto d = original ;	// 自己CNG再計算を正当な元値へ昇格しません。
		// 新baseの自己hashだけを再計算します。
		if( role == 0U) {
			d.base += " " ;
			d.intent.base = hash( c, d.base) ;
		}
		// Bootstrapの自己hashだけを再計算します。
		else if( role == 1U) {
			d.bootstrap += " " ;
			d.intent.bootstrap = hash( c, d.bootstrap) ;
		}
		// Next headの自己hashだけを再計算します。
		else if( role == 2U) {
			d.nextHead += " " ;
			d.intent.nextHead = hash( c, d.nextHead) ;
		} else {
			// Intentの全fieldを自己整合する別元acceptedへ変えます。
			d.intent.accepted += 1U ;
		}

		DRIVERCRATE_EXPECT( c, encodeCollectorSegmentSwitchIntent( d.intent, d.intentBytes) == 0U) ;
		d.intentHash = hash( c, d.intentBytes) ;
		DRIVERCRATE_EXPECT( c, checkCollectorSegmentSwitchDraft( s, s, r, d) == 13U) ;
	}

	auto d		 = original ;	// Intent hashだけの改変です。
	d.intentHash = key( 5U) ;
	DRIVERCRATE_EXPECT( c, checkCollectorSegmentSwitchDraft( s, s, r, d) == 13U) ;
	d = original ;
	d.intentBytes += " " ;
	DRIVERCRATE_EXPECT( c, checkCollectorSegmentSwitchDraft( s, s, r, d) == 13U) ;
	auto changed	= r ;	// 元oldHeadの差替えも全結合へ反映しなければ拒否します。
	changed.oldHead = key( 123U) ;
	DRIVERCRATE_EXPECT( c, checkCollectorSegmentSwitchDraft( s, s, changed, original) == 13U) ;
	changed		 = r ;
	changed.seal = key( 123U) ;
	DRIVERCRATE_EXPECT( c, checkCollectorSegmentSwitchDraft( s, s, changed, original) == 13U) ;
	changed			= r ;
	changed.oldRoot = key( 123U) ;
	DRIVERCRATE_EXPECT( c, checkCollectorSegmentSwitchDraft( s, s, changed, original) == 13U) ;
	changed					  = r ;
	changed.inventory.front() = key( 123U) ;
	DRIVERCRATE_EXPECT( c, checkCollectorSegmentSwitchDraft( s, s, changed, original) == 13U) ;
}
/** @brief 非canonical・未知field・全切断位置と型境界を検査します。
 * @param[in,out] c Assertion集計。
 */
void codecRejections( TestContext &c)
{
	const auto					s = snapshot() ;	// 固定原本文から各改変を作ります。
	CollectorSegmentSwitchDraft d ;					// 原intent本文です。
	DRIVERCRATE_EXPECT( c, prepareCollectorSegmentSwitchDraft( s, s, request(), d) == 0U) ;
	// 全有限切断位置を元prefixのまま拒否します。
	for( std::size_t n = 0U; n < d.intentBytes.size(); ++n) {
		refusedBytes( c, std::string_view( d.intentBytes).substr( 0U, n)) ;
	}

	refusedBytes( c, d.intentBytes + " ") ;
	refusedBytes( c, d.intentBytes + std::string( 1U, '\0')) ;
	refusedBytes( c, std::string( 16U * 1024U + 1U, 'x'), ERROR_TOO_MANY_NAMES) ;
	auto bytes = d.intentBytes ;	// 未知fieldの部分受理を拒否します。
	bytes.insert( bytes.size() - 1U, ",\"extra\":true") ;
	refusedBytes( c, bytes) ;
	bytes = d.intentBytes ;
	bytes.insert( bytes.find( "\"ordinal\":1") + 10U, "0") ;
	refusedBytes( c, bytes) ;
	bytes		   = d.intentBytes ;
	const auto pos = bytes.find( "\"oldHead\":") ;	// 重複fieldの挿入位置です。
	bytes.insert( pos, "\"oldHead\":\"bad\",") ;
	refusedBytes( c, bytes) ;
	bytes = d.intentBytes ;
	bytes.replace( bytes.find( "\"inventory\":["), std::string( "\"inventory\":[").size(),
				  "\"inventory\":{") ;
	refusedBytes( c, bytes) ;
	auto i			   = d.intent ;	// Typed encodeも全hashを検査します。
	i.collection	   = std::wstring( 64U, L'A') ;
	std::string output = "old" ;	// 拒否時に旧出力を残しません。
	DRIVERCRATE_EXPECT( c, encodeCollectorSegmentSwitchIntent( i, output) == 13U && output.empty()) ;
	i		  = d.intent ;
	i.ordinal = 0U ;
	DRIVERCRATE_EXPECT( c, encodeCollectorSegmentSwitchIntent( i, output) == 13U && output.empty()) ;
	i.ordinal = 1024U ;
	DRIVERCRATE_EXPECT( c, encodeCollectorSegmentSwitchIntent( i, output) == 68U && output.empty()) ;
	i = d.intent ;
	i.inventory.assign( 17U, key( 1U)) ;
	DRIVERCRATE_EXPECT( c, encodeCollectorSegmentSwitchIntent( i, output) == 68U && output.empty()) ;
	// Decode側の17件境界もtyped encodeを通さず作ります。
	bytes = d.intentBytes ;
	std::string array ;	// 同じ原hashの17個を有限JSONで持ちます。
	// 余分な17個目をhash検査前に容量拒否させます。
	for( std::size_t n = 0U; n < 17U; ++n) {
		// 配列区切りだけを元順序に追加します。
		if( n != 0U) {
			array += "," ;
		}

		array += "\"0000000000000000000000000000000000000000000000000000000000000001\"" ;
	}

	const auto begin =
		// 元開始です。
		bytes.find( "\"inventory\":[") + std::string( "\"inventory\":[").size() ;
	const auto end = bytes.find( "]", begin) ;	// 元一hash配列の末尾です。
	bytes.replace( begin, end - begin, array) ;
	refusedBytes( c, bytes, ERROR_TOO_MANY_NAMES) ;
}
} // namespace
} // namespace drivercrate::test

/** @brief 非保存切替draftを独立nativeで検査します。
 * @return 合格0、期待不成立1、fixture例外2。
 */
int main()
{
	drivercrate::test::TestContext context ;	// 実保存試験とは別分母です。
	try {
		winrt::init_apartment( winrt::apartment_type::multi_threaded) ;
		drivercrate::test::roundTrips( context) ;
		drivercrate::test::readiness( context) ;
		drivercrate::test::boundaries( context) ;
		drivercrate::test::bindings( context) ;
		drivercrate::test::codecRejections( context) ;
		winrt::uninit_apartment() ;
	} catch( ...) {
		std::cerr << "Segment switch draft fixture exception\n" ;
		return 2 ;
	}

	std::cout << "Segment switch draft assertions: " << context.assertionCount()
			  << ", failures: " << context.failureCount() << '\n' ;
	return context.failureCount() == 0 ? 0 : 1 ;
}
