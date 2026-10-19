//------------------------------------------------------------------------------
/**
 * @file local_collector_shared_ledger.cpp
 * @brief 共有台帳を有限canonical本文へ再結合し非変更carryを判定します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/01  固定64 shardと旧予算意味を保持するcodecを追加。
 * </pre>
 *
 * @note 任意callerの値の整合だけを検査します。File I/O・hash grantは発行しません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#include "local_collector_shared_ledger.h"
#include "local_collector_projected_json.h"
#include <algorithm>
#include <iterator>
#include <new>
#include <set>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {
// 既存のcanonical字句と追記前byte上限を使います。
using collector_projected_json::Reader ;
using collector_projected_json::Writer ;
using collector_projected_json::Failure ;
using collector_projected_json::Status ;
// 新modeの一行・本文・全本文の独立上限。
constexpr std::size_t	ROW_LIMIT = 1024U ;
// 一本文のcanonical byte上限です。
constexpr std::size_t	BODY_LIMIT = 768U * 1024U ;
// 固定66本文を同時に保持する合計byte上限です。
constexpr std::size_t	TOTAL_LIMIT = 8U * 1024U * 1024U ;
// 既存監督UTCと要確認期限の上限を維持します。
constexpr std::uint64_t LAST_UTC = 4102444799999ULL ;
// 要確認状態でだけ保持できる元絶対期限です。
constexpr std::uint64_t LAST_REVIEW = 253402300799999ULL ;

/** @brief 固定関係の不成立をbyte上限と区別して拒否します。
 * @param[in] condition 成立が必須の関係。
 * @throws Failure 関係が不成立の場合。
 */
void					require( const bool condition)
{
	// Schemaや結合の不成立を容量拒否へ変えません。
	if( !condition) {
		throw Failure{Status::INVALID} ;
	}
}

/** @brief 固定件数を確保・符号化より前に検査します。
 * @param[in] condition 容量内の場合true。
 * @throws Failure 容量超過の場合。
 */
void capacity( const bool condition)
{
	// 過大集合をJSONへ変換する前に止めます。
	if( !condition) {
		throw Failure{Status::SIZE_LIMIT} ;
	}
}

/** @brief 元groupの96文字ASCII token契約を維持します。
 * @param[in] value 元group ID。
 * @return 許可tokenの場合true。
 */
bool token( const std::wstring_view value)
{
	return !value.empty() && value.size() <= 96U &&
		   std::all_of( value.begin(), value.end(), []( const wchar_t ch) {
			   return (ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z') ||
					  (ch >= L'0' && ch <= L'9') || ch == L'-' || ch == L'_' || ch == L'.' ;
		   }) ;
}

/** @brief Unicodeをsource IDへ勝手に正規化せず有限ASCIIだけを読みます。
 * @param[in,out] reader 寿命中有効なcanonical reader。
 * @param[in] limit ASCII文字列のbyte上限。
 * @return 元ASCIIのUTF-16値。
 * @throws Failure 字句・文字範囲が不成立の場合。
 */
std::wstring ascii( Reader &reader, const std::size_t limit)
{
	const auto value = reader.text( limit) ;	// 解除後も有限の元byte。
	require(
		std::all_of( value.begin(), value.end(), []( const unsigned char ch) { return ch <= 127U ; })) ;
	return std::wstring( value.begin(), value.end()) ;
}

/** @brief 旧制御の時刻・開始intentを同じ意味で検査します。
 * @param[in] row 検査対象の制御値。
 * @param[in] request trueはrequest行、falseはgroup行。
 * @param[in] utc 保存最高millisecond。
 * @throws Failure 型や時計・identityが不成立の場合。
 */
void controlValid( const CollectorWaitControl &row, const bool request, const std::uint64_t utc)
{
	require( token( row.group) && row.observed != 0U && row.observed <= utc &&
			row.completed <= row.observed && row.notBefore <= LAST_REVIEW &&
			(row.notBefore <= LAST_UTC || row.review) &&
			(request ? collector_projected_json::isHash( row.request) : row.request.empty())) ;
	// 開始なしのhash残留やgroupへの開始intentを受理しません。
	if( row.started == 0U) {
		require( row.generation.empty() && row.job.empty()) ;
	} else {
		require( request && row.started <= row.observed &&
				collector_projected_json::isHash( row.generation) &&
				collector_projected_json::isHash( row.job)) ;
	}
}

/** @brief 一行を固定field順で符号化します。
 * @param[in] row 元制御と任意CACHE参照。
 * @param[in] request trueの場合だけcache fieldを持ちます。
 * @return 1024 byte以下のcanonical行。
 * @throws Failure 不正参照・byte容量超過の場合。
 */
std::string rowBytes( const CollectorSharedRequestState &row, const bool request)
{
	Writer		writer( ROW_LIMIT) ;	// 追加前に一行のbyteを制限します。
	const auto &c = row.control ;		// Callerの元値を借用します。
	writer.append( "{\"group\":") ;
	writer.wideText( c.group) ;
	writer.append( ",\"request\":") ;
	writer.wideText( c.request) ;
	writer.append( ",\"observed\":") ;
	writer.number( c.observed) ;
	writer.append( ",\"notBefore\":") ;
	writer.number( c.notBefore) ;
	writer.append( ",\"completed\":") ;
	writer.number( c.completed) ;
	writer.append( ",\"needsReview\":") ;
	writer.append( c.review ? "true" : "false") ;
	writer.append( ",\"generation\":") ;
	writer.wideText( c.generation) ;
	writer.append( ",\"job\":") ;
	writer.wideText( c.job) ;
	writer.append( ",\"started\":") ;
	writer.number( c.started) ;
	// Group行に任意CACHE参照を付けません。
	if( request) {
		writer.append( ",\"cache\":") ;
		// 根拠未保持を空hash参照へ補完しません。
		if( row.cache) {
			require( collector_projected_json::isHash( row.cache->segment) &&
					collector_projected_json::isHash( row.cache->cacheSha256) &&
					collector_projected_json::isHash( row.cache->binding)) ;
			writer.append( "{\"segment\":") ;
			writer.wideText( row.cache->segment) ;
			writer.append( ",\"cacheSha256\":") ;
			writer.wideText( row.cache->cacheSha256) ;
			writer.append( ",\"binding\":") ;
			writer.wideText( row.cache->binding) ;
			writer.append( "}") ;
		} else {
			writer.append( "null") ;
		}
	}

	writer.append( "}") ;
	return writer.take() ;
}

/** @brief 一行の全fieldを順に読み、unknown fieldを残しません。
 * @param[in] bytes 借用する最大1024 byteの元行。
 * @param[in] request trueはCACHE field付きのrequest行。
 * @return 元値。台帳間関係は全再結合後に検査します。
 * @throws Failure 固定byte・型・fieldが不成立の場合。
 */
CollectorSharedRequestState readRow( const std::string_view bytes, const bool request)
{
	Reader						r( bytes, ROW_LIMIT) ;	// 深さ・字句・実byteの事前検査。
	CollectorSharedRequestState row ;					// 完全に読むまで外へ公開しません。
	auto					   &c = row.control ;		// 元制御の全fieldを保持します。
	r.literal( "{\"group\":") ;
	c.group = ascii( r, 96U) ;
	r.literal( ",\"request\":") ;
	c.request = ascii( r, 64U) ;
	r.literal( ",\"observed\":") ;
	c.observed = r.number() ;
	r.literal( ",\"notBefore\":") ;
	c.notBefore = r.number() ;
	r.literal( ",\"completed\":") ;
	c.completed = r.number() ;
	r.literal( ",\"needsReview\":") ;
	const auto flag = r.value() ;	// bool以外を数値やstringから推測しません。
	require( flag == "true" || flag == "false") ;
	c.review = flag == "true" ;
	r.literal( ",\"generation\":") ;
	c.generation = ascii( r, 64U) ;
	r.literal( ",\"job\":") ;
	c.job = ascii( r, 64U) ;
	r.literal( ",\"started\":") ;
	c.started = r.number() ;
	// Groupにはcache fieldを認めず、requestには省略を認めません。
	if( request) {
		r.literal( ",\"cache\":") ;
		const auto cacheBytes = r.value() ;	// Nullまたは三hash参照だけです。
		// Nullを実在するCACHEの検証成功へ読み替えません。
		if( cacheBytes != "null") {
			Reader cache( cacheBytes, ROW_LIMIT) ;	// 任意pathを許さない固定三field。
			CollectorSharedCacheReference ref ;		// 全hashを読んでから設定します。
			cache.literal( "{\"segment\":") ;
			ref.segment = ascii( cache, 64U) ;
			cache.literal( ",\"cacheSha256\":") ;
			ref.cacheSha256 = ascii( cache, 64U) ;
			cache.literal( ",\"binding\":") ;
			ref.binding = ascii( cache, 64U) ;
			cache.literal( "}") ;
			cache.finish() ;
			row.cache = std::move( ref) ;
		}
	}

	r.literal( "}") ;
	r.finish() ;
	require( rowBytes( row, request) == bytes) ;
	return row ;
}

/** @brief 型の全関係と元予算を検査します。
 * @param[in] s Callerの元台帳。
 * @return 既存codecで再検査したcanonical予算本文。
 * @throws Failure 容量・時刻・予約対応が不成立の場合。
 */
std::string validate( const CollectorSharedLedgerSnapshot &s)
{
	capacity( s.groups.size() <= 20U && s.requests.size() <= 4096U &&
			 s.budget.reservations.size() <= 1200U) ;
	require( collector_projected_json::isHash( s.collection) && s.lastUtcMillis >= 1000U &&
			s.lastUtcMillis <= LAST_UTC && s.budget.lastUtc <= s.lastUtcMillis / 1000U) ;
	std::string budget ;	// 既存予約phase・元日・未知課金を再検査します。
	require( encodeCollectorBudgetSnapshot( s.budget, budget)) ;
	// Group行を先に検査してrequestの所属集合を固定します。
	for( const auto &[key, row] : s.groups) {
		require( key == row.group) ;
		controlValid( row, false, s.lastUtcMillis) ;
	}

	// 元campaign／jobへ一意に結合する借用開始intentです。
	std::map<std::pair<std::wstring, std::wstring>, const CollectorWaitControl *> active ;
	// Requestの開始intentを元予約のidentityへ一対一に結合します。
	for( const auto &[key, row] : s.requests) {
		require( key == row.control.request && s.groups.contains( row.control.group)) ;
		controlValid( row.control, true, s.lastUtcMillis) ;
		(void)rowBytes( row, true) ;
		// 閉鎖済みrequestは未精算集合へ加えません。
		if( row.control.started != 0U) {
			require(
				active
					.emplace( std::make_pair( row.control.generation, row.control.job), &row.control)
					.second) ;
		}
	}

	std::size_t			   pending{} ;		// 未精算予約数。最大四slot。
	std::set<std::wstring> activeGroups ;	// 同group二予約を拒否します。
	// 全元予約の所属groupと未精算開始を確認します。
	for( const auto &row : s.budget.reservations) {
		require( s.groups.contains( row.group)) ;
		// 閉鎖済み予約に開始intentが残っていても受理しません。
		if( row.phase != 0U) {
			require( !active.contains( {row.campaign, row.job})) ;
			continue ;
		}

		const auto found = active.find( {row.campaign, row.job}) ;	// 元予約の一intent。
		require( found != active.end() && found->second->group == row.group &&
				found->second->started == row.started * 1000U &&
				activeGroups.insert( row.group).second) ;
		++pending ;
	}

	require( pending == active.size() && pending <= 4U) ;
	return budget ;
}

/** @brief 元collection・UTCを固定headerへ出力します。
 * @param[in,out] w 追記前予算を持つwriter。
 * @param[in] s 元台帳。
 * @param[in] schema 固定組み込みschema。
 */
void header( Writer &w, const CollectorSharedLedgerSnapshot &s, const std::string_view schema)
{
	w.append( "{\"schema\":") ;
	w.text( schema) ;
	w.append( ",\"collection\":") ;
	w.wideText( s.collection) ;
	w.append( ",\"lastUtcMillis\":") ;
	w.number( s.lastUtcMillis) ;
}

/** @brief 全本文のbyteを加算前に制限します。
 * @param[in] bytes 固定66本文。
 * @throws Failure 個別または全本文容量を超える場合。
 */
void bundleCapacity( const CollectorSharedLedgerBytes &bytes)
{
	std::size_t total{} ;	// Overflowする前に有限差分で計算します。
	// 空を欠損として後続schema検査へ渡し、byte容量と区別します。
	for( const auto *body : {&bytes.budget, &bytes.groups}) {
		capacity( body->size() <= BODY_LIMIT && body->size() <= TOTAL_LIMIT - total) ;
		total += body->size() ;
	}

	// 全64 shardも同じ累積本文枠へ含めます。
	for( const auto &body : bytes.requests) {
		capacity( body.size() <= BODY_LIMIT && body.size() <= TOTAL_LIMIT - total) ;
		total += body.size() ;
	}
}

/** @brief 完全検査後だけ固定66本文を作ります。
 * @param[in] s 元台帳。
 * @return 固定順の所有本文。
 * @throws Failure 容量・関係・字句が不成立の場合。
 */
CollectorSharedLedgerBytes encode( const CollectorSharedLedgerSnapshot &s)
{
	const auto				   budget = validate( s) ;	// 旧予算を独自に丸めません。
	CollectorSharedLedgerBytes bytes ;					// 全成立後だけcallerへ移します。
	Writer					   b( BODY_LIMIT) ;			// 新予算schemaと元objectの結合。
	b.append( "{\"schema\":\"collector-shared-budget-v1\",\"collection\":") ;
	b.wideText( s.collection) ;
	b.append( ",\"budget\":") ;
	b.append( budget) ;
	b.append( "}") ;
	bytes.budget = b.take() ;
	Writer g( BODY_LIMIT) ;	// Group昇順の現在値。
	header( g, s, "collector-shared-groups-v1") ;
	g.append( ",\"count\":") ;
	g.number( s.groups.size()) ;
	g.append( ",\"rows\":[") ;
	std::size_t ordinal{} ;	// Groupのdelimiterを固定します。
	// Group行を省略せず固定map順で保存します。
	for( const auto &[key, row] : s.groups) {
		(void)key ;
		// 二行目以降だけdelimiterを出力します。
		if( ordinal++ != 0U) {
			g.append( ",") ;
		}

		g.append( rowBytes( {row, std::nullopt}, false)) ;
	}

	g.append( "]}") ;
	bytes.groups = g.take() ;
	auto it		 = s.requests.begin() ;	// 全keyを連続64行ずつ割り当てます。
	// 空shardも同じcollectionとUTCへ拘束します。
	for( std::size_t index = 0U; index < bytes.requests.size(); ++index) {
		Writer w( BODY_LIMIT) ;	// 一shardの独立本文予算。
		header( w, s, "collector-shared-requests-v1") ;
		w.append( ",\"ordinal\":") ;
		w.number( index) ;
		w.append( ",\"totalRequests\":") ;
		w.number( s.requests.size()) ;
		const auto count = std::min<std::size_t>(
			64U, s.requests.size() -
					 // 残行数。
					 static_cast<std::size_t>( std::distance( s.requests.begin(), it))) ;
		w.append( ",\"count\":") ;
		w.number( count) ;
		w.append( ",\"rows\":[") ;
		// このshardの最大64行だけを一度ずつ出力します。
		for( std::size_t row = 0U; row < count; ++row, ++it) {
			// 行区切りだけを固定構文として出力します。
			if( row != 0U) {
				w.append( ",") ;
			}

			w.append( rowBytes( it->second, true)) ;
		}

		w.append( "]}") ;
		bytes.requests[index] = w.take() ;
	}

	bundleCapacity( bytes) ;
	return bytes ;
}

/** @brief 固定headerと集合間collection・UTCを照合します。
 * @param[in,out] r 有限reader。
 * @param[in] s 予算とgroupから得た固定値。
 * @param[in] schema 組み込みschema。
 * @param[in] groups trueでは最高UTCを初めて設定します。
 * @return Headerの元最高UTC。
 * @throws Failure 異なるcollection・UTCやschemaの場合。
 */
std::uint64_t readHeader( Reader &r, const CollectorSharedLedgerSnapshot &s,
						 const std::string_view schema, const bool groups)
{
	r.literal( "{\"schema\":") ;
	require( r.text( 96U) == schema) ;
	r.literal( ",\"collection\":") ;
	require( ascii( r, 64U) == s.collection) ;
	r.literal( ",\"lastUtcMillis\":") ;
	const auto utc = r.number() ;	// Group以外は同じ最高値を要求します。
	require( groups || utc == s.lastUtcMillis) ;
	return utc ;
}

/** @brief 全66本文を検査して初めてtyped値を返します。
 * @param[in] bytes 変更しない元本文。
 * @return 全再結合済み値。
 * @throws Failure 不正・過大本文の場合。
 */
CollectorSharedLedgerSnapshot decode( const CollectorSharedLedgerBytes &bytes)
{
	bundleCapacity( bytes) ;
	CollectorSharedLedgerSnapshot s ;		// 途中成功を公開しません。
	Reader b( bytes.budget, BODY_LIMIT) ;	// 外側予算schemaだけを新形式として読みます。
	b.literal( "{\"schema\":\"collector-shared-budget-v1\",\"collection\":") ;
	s.collection = ascii( b, 64U) ;
	b.literal( ",\"budget\":") ;
	require( parseCollectorBudgetSnapshot( b.value(), s.budget)) ;
	b.literal( "}") ;
	b.finish() ;
	Reader g( bytes.groups, BODY_LIMIT) ;	// 全groupを先に固定します。
	s.lastUtcMillis = readHeader( g, s, "collector-shared-groups-v1", true) ;
	g.literal( ",\"count\":") ;
	const auto groups = g.number() ;	// 確保前の最大20行。
	capacity( groups <= 20U) ;
	g.literal( ",\"rows\":[") ;
	std::wstring previous ;	// 昇順をdecode時にも要求します。
	// 宣言された有限group数だけを読みます。
	for( std::size_t i = 0U; i < groups; ++i) {
		// delimiter欠損や余分な行を受理しません。
		if( i != 0U) {
			g.literal( ",") ;
		}

		auto row = readRow( g.value(), false) ;	// 元値を保持した一行。
		require( previous.empty() || previous < row.control.group) ;
		previous = row.control.group ;
		require( s.groups.emplace( row.control.group, row.control).second) ;
	}

	g.literal( "]}") ;
	g.finish() ;
	previous.clear() ;
	std::uint64_t total{} ;	// Shard間で一致が必須の全要求数。
	// ordinal順の64 fileを省略せず再結合します。
	for( std::size_t index = 0U; index < bytes.requests.size(); ++index) {
		Reader r( bytes.requests[index], BODY_LIMIT) ;	// このshardの独立検査。
		(void)readHeader( r, s, "collector-shared-requests-v1", false) ;
		r.literal( ",\"ordinal\":") ;
		require( r.number() == index) ;
		r.literal( ",\"totalRequests\":") ;
		const auto declared = r.number() ;	// 4096以内に限定してから行数計算します。
		capacity( declared <= 4096U) ;
		// 最初のshardだけが全件数を設定します。
		if( index == 0U) {
			total = declared ;
		}

		require( declared == total) ;
		r.literal( ",\"count\":") ;
		const auto count	= r.number() ;	// 昇順連続64行の固定割当。
		const auto expected = total > index * 64U ? std::min<std::uint64_t>( 64U,
																			total - index * 64U)
												  : 0U ;	// 空shardにも同じ契約を適用します。
		require( count == expected) ;
		r.literal( ",\"rows\":[") ;
		// 全requestのkey順と一意性をshard境界でも検査します。
		for( std::size_t i = 0U; i < count; ++i) {
			// 先頭以外のdelimiterを完全一致で読みます。
			if( i != 0U) {
				r.literal( ",") ;
			}

			auto row = readRow( r.value(), true) ;	// 追加前の有限一行。
			require( previous.empty() || previous < row.control.request) ;
			previous = row.control.request ;
			require( s.requests.emplace( previous, std::move( row)).second) ;
		}

		r.literal( "]}") ;
		r.finish() ;
	}

	const auto checked = encode( s) ;	// 関係検査とcanonical再encodeを共通化します。
	require( checked.budget == bytes.budget && checked.groups == bytes.groups &&
			checked.requests == bytes.requests) ;
	return s ;
}

/** @brief 例外を数値だけの公開結果へ変換します。
 * @tparam Fn 借用lambdaの型。
 * @param[in] action 同期中だけ呼び出す操作。capture所有者は存続しています。
 * @return 成功0、不正13、容量68、確保失敗8。
 */
template <class Fn> DWORD boundary( const Fn &action) noexcept
{
	try {
		action() ;
		return ERROR_SUCCESS ;
	} catch( const Failure &failure) {
		return failure.status == Status::SIZE_LIMIT		 ? ERROR_TOO_MANY_NAMES
			   : failure.status == Status::OUT_OF_MEMORY ? ERROR_NOT_ENOUGH_MEMORY
														 : ERROR_INVALID_DATA ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}
} // namespace

/** @see local_collector_shared_ledger.h */
DWORD encodeCollectorSharedLedger( const CollectorSharedLedgerSnapshot &snapshot,
								  CollectorSharedLedgerBytes		  &bytes) noexcept
{
	bytes = {} ;
	// 入力を借用し、全検査後だけ出力へ移譲します。
	return boundary( [&] { bytes = encode( snapshot) ; }) ;
}

/** @see local_collector_shared_ledger.h */
DWORD decodeCollectorSharedLedger( const CollectorSharedLedgerBytes &bytes,
								  CollectorSharedLedgerSnapshot	   &snapshot) noexcept
{
	snapshot = {} ;
	// 失敗時に部分groupや部分requestを公開しません。
	return boundary( [&] { snapshot = decode( bytes) ; }) ;
}

/** @see local_collector_shared_ledger.h */
DWORD checkCollectorSharedLedgerCarry( const CollectorSharedLedgerSnapshot &before,
									  const CollectorSharedLedgerSnapshot &after,
									  const std::uint64_t				   utcMillis) noexcept
{
	// 全本文の完全一致だけを判定し、保存や時計更新はしません。
	return boundary( [&] {
		require( utcMillis >= before.lastUtcMillis && utcMillis <= LAST_UTC) ;
		const auto first  = encode( before) ;	// 元台帳の関係を先に検査します。
		const auto second = encode( after) ;	// 型付きcallerの変更も完全検査します。
		require( first.budget == second.budget && first.groups == second.groups &&
				first.requests == second.requests) ;
		// 全予約が閉鎖される前に区間を切り替えません。
		for( const auto &row : before.budget.reservations) {
			require( row.phase != 0U) ;
		}

		// 予算対応済みでも未精算intentを非変更carryの許可へ読み替えません。
		for( const auto &[key, row] : before.requests) {
			(void)key ;
			require( row.control.started == 0U) ;
		}
	}) ;
}
} // namespace drivercrate
