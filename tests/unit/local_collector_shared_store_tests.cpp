//------------------------------------------------------------------------------
/**
 * @file local_collector_shared_store_tests.cpp
 * @brief 初回共有台帳の136保存後停止・実回復・非変更拒否を検査します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  初回136窓・原像保持・物理I/O拒否を追加。
 * </pre>
 *
 * @note 自身の架空fixtureだけを使用します。HTTP・driver・OS設定を変更しません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#include "platform/local_collector_shared_store.h"
#include "test_framework.h"
#include <winrt/base.h>
#include <algorithm>
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
// 実時計や機器とは無関係の元UTC秒です。
constexpr std::uint64_t UTC = 1790456400ULL ;
/** @brief 架空完全hashを固定桁で作ります。
 * @param[in] number 架空identity整数。
 * @return 小文字64桁hex。
 */
std::wstring			key( const std::size_t number)
{
	std::wostringstream s ;	// 元入力を固定桁で表現します。
	s << std::hex << std::setfill( L'0') << std::setw( 64) << number ;
	return s.str() ;
}
/** @brief Test setup不成立をassertion結果と区別します。
 * @param[in] ok 必須setup条件。
 * @throws std::runtime_error Setup失敗。
 */
void require( const bool ok)
{
	// 原setup失敗を測定成功へ合算しません。
	if( !ok) {
		throw std::runtime_error( "Shared store fixture setup failed") ;
	}
}
/** @brief 元待機・review・課金を保持する閉鎖snapshotです。
 * @param[in] count 架空request数。
 * @return 恒久collection key 1の元値。
 */
CollectorSharedLedgerSnapshot fixture( const std::size_t count = 2U)
{
	CollectorSharedLedgerSnapshot s ;	// 保存後に現在時計で作り直しません。
	s.collection	 = key( 1U) ;
	s.lastUtcMillis	 = UTC * 1000U ;
	s.budget.day	 = L"20260927" ;
	s.budget.lastUtc = UTC ;
	s.budget.reservations.push_back( {key( 1000U), key( 1001U), L"fixture-group", UTC,
									 8U * 1024U * 1024U, 8U * 1024U * 1024U, 2U}) ;
	CollectorWaitControl group ;	// Reviewと元group完了時刻をそのまま保持します。
	group.group		= L"fixture-group" ;
	group.observed	= UTC * 1000U ;
	group.completed = UTC * 1000U ;
	group.notBefore = (UTC + 300U) * 1000U ;
	group.review	= true ;
	s.groups.emplace( group.group, group) ;
	// 同prefixの全requestへ元期限を登録します。
	for( std::size_t i = 0U; i < count; ++i) {
		CollectorSharedRequestState row ;	// 型付きの元要求です。
		row.control.group	  = group.group ;
		row.control.request	  = key( i + 20U) ;
		row.control.observed  = UTC * 1000U ;
		row.control.notBefore = (UTC + 86400U) * 1000U ;
		s.requests.emplace( row.control.request, row) ;
	}

	return s ;
}
/** @brief 借用writerを子leaseより後に解放するfixtureです。 */
struct Session {
	/// Collection全体のwriter。
	LocalCollectorCollectionStore				parent ;
	/// Parentより先に解放する一子owner。
	std::unique_ptr<LocalCollectorSegmentLease> child ;
	/** @brief 自身のrootと唯一子を開きます。
	 * @param[in] root Fixture専用collection領域。
	 */
	explicit Session( const std::filesystem::path &root)
	{
		require( parent.initialize( root, key( 1U)) == 0U) ;
		require( parent.borrowSegment( key( 2U), true, child) == 0U) ;
	}
} ;
/** @brief 自身のfixtureに限り内部extended表現でfileを開きます。
 * @param[in] path 検査済み自身の絶対fixture path。
 * @return Backslashを揃えた内部path。
 */
std::filesystem::path extended( const std::filesystem::path &path)
{
	return L"\\\\?\\" + std::filesystem::path( path).make_preferred().native() ;
}
/** @brief 自身のfixture byteを正規化せず読みます。
 * @param[in] path Fixture専用file。
 * @return 元binary byte。
 */
std::string contents( const std::filesystem::path &path)
{
	std::ifstream stream( extended( path), std::ios::binary) ;	// 自身の閉鎖fileだけです。
	require( stream.good()) ;
	return std::string( std::istreambuf_iterator<char>( stream), {}) ;
}
/** @brief 自身の既存fixtureへ不正byteを作ります。
 * @param[in] path 存在するfixture専用file。
 * @param[in] bytes 故意の不正本文。
 */
void alter( const std::filesystem::path &path, const std::string_view bytes)
{
	std::ofstream stream( extended( path), std::ios::binary | std::ios::trunc) ;	// ACLは変更しません。
	require( stream.good()) ;
	stream.write( bytes.data(), static_cast<std::streamsize>( bytes.size())) ;
	require( stream.good()) ;
}
/** @brief Lock以外の自身の全file原byteを比較用に保持します。
 * @param[in] root 架空fixtureだけの専用root。
 * @return 相対名と原byte。未知file／stagingも含みます。
 */
std::map<std::wstring, std::string> image( const std::filesystem::path &root)
{
	std::map<std::wstring, std::string> result ;	// 自身のfixtureの非公開比較像です。
	// 自身の通常階層だけを一度ずつ走査します。
	for( const auto &entry : std::filesystem::recursive_directory_iterator( extended( root))) {
		// 排他lockは本文を持たず共有readを許可しません。
		if( entry.is_regular_file() && entry.path().filename() != L"collector.lock") {
			std::ifstream stream( entry.path(), std::ios::binary) ;	// Extended pathのまま開きます。
			require( stream.good()) ;
			result.emplace( entry.path().lexically_relative( extended( root)).native(),
						   std::string( std::istreambuf_iterator<char>( stream), {})) ;
		}
	}

	return result ;
}
/** @brief 型付き値の全66本文を比較します。
 * @param[in] a 元状態。
 * @param[in] b 読戻し状態。
 * @return 全意味と保存表現が一致すればtrue。
 */
bool equal( const CollectorSharedLedgerSnapshot &a, const CollectorSharedLedgerSnapshot &b)
{
	CollectorSharedLedgerBytes aa ;	// 元66本文です。
	CollectorSharedLedgerBytes bb ;	// 読戻し66本文です。
	return encodeCollectorSharedLedger( a, aa) == 0U && encodeCollectorSharedLedger( b, bb) == 0U &&
		   aa.budget == bb.budget && aa.groups == bb.groups && aa.requests == bb.requests ;
}
/** @brief 元136手順の一atomic保存直後で停止させます。
 * @param[in,out] session 自身の借用session。
 * @param[in] stop 元手順の1～136 ordinal。
 * @return 元995。Setup不成立は例外です。
 */
DWORD stopped( Session &session, const std::size_t stop)
{
	return LocalCollectorSharedStore::bootstrap(
		session.parent, *session.child, fixture(), [stop]( const std::size_t ordinal) {
			return ordinal == stop ? ERROR_OPERATION_ABORTED : 0U ;
		}) ;
}
/** @brief 閉鎖値・最大request・再入／別能力拒否を検査します。
 * @param[in,out] c Native集計。
 * @param[in] base 自身の未存在fixture親。
 */
void normal( TestContext &c, const std::filesystem::path &base)
{
	Session						  s( base / L"normal" / key( 1U)) ;	// 初回専用の実writerです。
	CollectorSharedLedgerSnapshot copy = fixture() ;				// 失敗出力のクリアも検査します。
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::load( s.parent, *s.child, copy) == 13U) ;
	DRIVERCRATE_EXPECT( c, copy.collection.empty()) ;
	std::vector<std::size_t> observed ;	// 実136保存の順序です。
	DWORD					 nested{} ;	// Callback再入の元codeです。
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::bootstrap(
							  s.parent, *s.child, fixture(), [&]( const std::size_t ordinal) {
								  observed.push_back( ordinal) ;
								  // 初回保存中の再入は別保存を開始させません。
								  if( ordinal == 1U) {
									  nested = LocalCollectorSharedStore::bootstrap(
										  s.parent, *s.child, fixture()) ;
								  }

								  return 0U ;
							  }) == 0U) ;
	DRIVERCRATE_EXPECT( c, nested == 170U && observed.size() == 136U) ;
	// すべての元ordinalが一度ずつ増加したことを検査します。
	for( std::size_t i = 0U; i < observed.size(); ++i) {
		DRIVERCRATE_EXPECT( c, observed[i] == i + 1U) ;
	}

	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::load( s.parent, *s.child, copy) == 0U) ;
	DRIVERCRATE_EXPECT( c, equal( fixture(), copy)) ;
	Session	   other( base / L"other" / key( 1U)) ;	// 同じhashでも別writer能力です。
	const auto before =
		// 元全file像です。
		image( s.child->store().root().parent_path().parent_path()) ;
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::bootstrap( other.parent, *s.child, fixture()) ==
							  87U) ;
	DRIVERCRATE_EXPECT( c, before == image( s.child->store().root().parent_path().parent_path())) ;
	Session large( base / L"large" / key( 1U)) ;	// 同prefix4096要求の実保存です。
	DRIVERCRATE_EXPECT(
		c, LocalCollectorSharedStore::bootstrap( large.parent, *large.child, fixture( 4096U)) == 0U) ;
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::load( large.parent, *large.child, copy) == 0U) ;
	DRIVERCRATE_EXPECT( c, equal( fixture( 4096U), copy)) ;
	const auto full =
		// 容量拒否前の元byteです。
		image( large.child->store().root().parent_path().parent_path()) ;
	DRIVERCRATE_EXPECT(
		c, LocalCollectorSharedStore::bootstrap( large.parent, *large.child, fixture( 4097U)) == 68U) ;
	DRIVERCRATE_EXPECT( c, full == image( large.child->store().root().parent_path().parent_path())) ;
	auto dense	  = fixture( 4096U) ;				// 形式上限内でも回復rawが不足する元入力です。
	auto control  = dense.groups.begin()->second ;	// Groupの最大長を元関係へ反映します。
	control.group = std::wstring( 96U, L'g') ;
	dense.groups.clear() ;
	dense.groups.emplace( control.group, control) ;
	dense.budget.reservations.front().group = control.group ;
	// CACHE参照を含む全行でも型付き形式自体は正常です。
	for( auto &[request, row] : dense.requests) {
		static_cast<void>( request) ;
		row.control.group = control.group ;
		row.cache		  = CollectorSharedCacheReference{key( 7U), key( 8U), key( 9U)} ;
	}

	CollectorSharedLedgerBytes encoded ;	// Raw保存前にcodec成立を別々に確認します。
	DRIVERCRATE_EXPECT( c, encodeCollectorSharedLedger( dense, encoded) == 0U) ;
	Session		bounded( base / L"dense" / key( 1U)) ;			// 自身の未保存領域です。
	const auto	empty = image( base / L"dense" / key( 1U)) ;	// Marker以外の追加も拒否します。
	std::size_t writes{} ;										// 保存後callbackが一度も呼ばれないことを観測します。
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::bootstrap( bounded.parent, *bounded.child,
															   dense, [&]( const std::size_t) {
																   ++writes ;
																   return 0U ;
															   }) == 68U) ;
	DRIVERCRATE_EXPECT( c, writes == 0U) ;
	DRIVERCRATE_EXPECT( c, empty == image( base / L"dense" / key( 1U))) ;
}
/** @brief 全atomic保存後の停止と別ownerによる不足回復を検査します。
 * @param[in,out] c Native集計。
 * @param[in] root 独立した未存在collection root。
 * @param[in] stop 元保存ordinal。
 */
void window( TestContext &c, const std::filesystem::path &root, const std::size_t stop)
{
	{
		Session s( root) ;	// 元呼出しを実保護storeへ接続します。
		DRIVERCRATE_EXPECT( c, stopped( s, stop) == 995U) ;
	}
	Session		recovered( root) ;	// 元時刻を変更せず別ownerで再初期化します。
	std::size_t written{} ;			// 不足suffixだけの実保存回数です。
	DRIVERCRATE_EXPECT(
		c, LocalCollectorSharedStore::bootstrap(
			   recovered.parent, *recovered.child, fixture(), [&]( const std::size_t ordinal) {
				   ++written ;
				   DRIVERCRATE_EXPECT( c, ordinal == stop + written) ;
				   return 0U ;
			   }) == 0U) ;
	DRIVERCRATE_EXPECT( c, written == 136U - stop) ;
	CollectorSharedLedgerSnapshot copy ;	// Readyだけを公開します。
	DRIVERCRATE_EXPECT(
		c, LocalCollectorSharedStore::load( recovered.parent, *recovered.child, copy) == 0U) ;
	DRIVERCRATE_EXPECT( c, equal( fixture(), copy)) ;
	const auto saved = image( root) ;	// 確定後の全byteを保持します。
	recovered.child.reset() ;
	DRIVERCRATE_EXPECT( c, recovered.parent.close() == 0U) ;
	// 別ownerの二回再起動・同じ入口と読戻しを非変更で確認します。
	for( std::size_t repeat = 0U; repeat < 2U; ++repeat) {
		Session reloaded( root) ;	// 前のownerのhandle／観測を再利用しません。
		DRIVERCRATE_EXPECT(
			c, LocalCollectorSharedStore::bootstrap( reloaded.parent, *reloaded.child, fixture(),
													[]( const std::size_t) { return 995U ; }) == 0U) ;
		DRIVERCRATE_EXPECT(
			c, LocalCollectorSharedStore::load( reloaded.parent, *reloaded.child, copy) == 0U) ;
		DRIVERCRATE_EXPECT( c, equal( fixture(), copy) && saved == image( root)) ;
	}
}
/** @brief 改変・欠損・二候補・非prefixを保存前に拒否します。
 * @param[in,out] c Native集計。
 * @param[in] root 自身の未存在fixture領域。
 * @param[in] kind 九つの独立拒否条件。
 */
void rejected( TestContext &c, const std::filesystem::path &root, const std::size_t kind)
{
	Session s( root) ;	// 条件ごとに独立した保護領域です。
	require( stopped( s, kind == 0U ? 2U : kind == 3U ? 70U : 136U) == 995U) ;
	const auto child = s.child->store().root() ;	// 自身の改変対象です。
	// 固定条件にだけ故障を作り、期待値を緩和しません。
	if( kind == 0U) {
		auto changed = fixture() ;	// 未完了intentに別時刻を与えます。
		++changed.lastUtcMillis ;
		const auto original = image( root) ;	// 別候補拒否の非変更像です。
		DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::bootstrap( s.parent, *s.child, changed) ==
								  13U) ;
		DRIVERCRATE_EXPECT( c, original == image( root)) ;
		return ;
	}
	// 現在値の改変を自動修復しないことを検査します。
	else if( kind == 1U) {
		alter( root / L"current/shared-requests-00.json", "{}") ;
	}
	// 確定済みの欠損を不足prefixへ戻しません。
	else if( kind == 2U) {
		require( std::filesystem::remove( extended( root / L"current/shared-requests-3f.json"))) ;
	}
	// 正しい元byteでも順序の異なる反映を拒否します。
	else if( kind == 3U) {
		std::vector<std::wstring> names ;	// 保護準備像から正しい末尾byteだけを借ります。
		require( s.child->store().listRunNames( names) == 0U) ;
		const auto last = std::find_if( names.begin(), names.end(), []( const auto &name) {
			return name.ends_with( L"-41.json") ;
		}) ; // 固定66番目の像です。
		require( last != names.end()) ;
		alter( root / L"current/shared-groups-v1.json",
			  // 元末尾の正しいbyteです。
			  contents( child / L"runs" / *last)) ;
		require( MoveFileExW( extended( root / L"current/shared-groups-v1.json").c_str(),
							extended( root / L"current/shared-requests-3f.json").c_str(),
							0U) != FALSE) ;	// 自身の保護ACLを保って非prefixを作ります。
	}
	// 未登録の別候補を無視して保存させません。
	else if( kind == 4U) {
		require( s.child->store().write( L"runs/unknown.json", "{}") == 0U) ;
	}
	// 現在値が正しくても元baseの改変を拒否します。
	else if( kind == 5U) {
		alter( child / L"current/segment-shared-base-v1.json", "{}") ;
	}
	// 元準備像も確定headへ結合して再検査します。
	else if( kind == 6U || kind == 8U) {
		std::vector<std::wstring> names ;	// 自身の保存元を保護列挙します。
		require( s.child->store().listRunNames( names) == 0U) ;
		const auto selected = std::find_if( names.begin(), names.end(), [kind]( const auto &name) {
			return kind == 6U ? name.ends_with( L"-00.json")
							  : name.starts_with( L"shared-bootstrap-intent-") ;
		}) ; // 元予算準備像またはintentだけを選びます。
		require( selected != names.end()) ;
		// 元予算のhashも現在値だけで代用しません。
		if( kind == 6U) {
			alter( child / L"runs" / *selected, "{}") ;
		} else {
			require( std::filesystem::remove( extended( child / L"runs" / *selected))) ;
		}
	} else {
		alter( root / L"current/collection-head-v1.json", "{}") ;
	}

	const auto original = image( root) ;	// 拒否後の全byteを比較します。
	DRIVERCRATE_EXPECT( c,
					   LocalCollectorSharedStore::bootstrap( s.parent, *s.child, fixture()) == 13U) ;
	DRIVERCRATE_EXPECT( c, original == image( root)) ;
	CollectorSharedLedgerSnapshot copy = fixture() ;	// 失敗時は部分値も旧値も公開しません。
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::load( s.parent, *s.child, copy) == 13U) ;
	DRIVERCRATE_EXPECT( c, copy.collection.empty() && original == image( root)) ;
}
/** @brief Win32の実rename失敗と残留stagingの非変更拒否を検査します。
 * @param[in,out] c Native集計。
 * @param[in] root 自身の独立領域。
 */
void blocked( TestContext &c, const std::filesystem::path &root)
{
	Session s( root) ;	// 親commit登録の直後で止めます。
	require( stopped( s, 68U) == 995U) ;
	const auto	 path	= root / L"current/collection-head-v1.json" ;	// 既存登録headです。
	const auto	 old	= contents( path) ;								// エラー後も登録像を保持します。
	const HANDLE handle = CreateFileW(
		extended( path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) ;	// 自身のheadのDELETE共有を与えません。
	require( handle != INVALID_HANDLE_VALUE) ;
	const auto closer = []( void *value) {
		CloseHandle( value) ;
	} ; // 全終了で自身のhandleだけを解放します。
	const std::unique_ptr<void, decltype( closer)> guard( handle, closer) ;	// 実rename拒否の所有です。
	DRIVERCRATE_EXPECT( c,
					   LocalCollectorSharedStore::bootstrap( s.parent, *s.child, fixture()) == 5U) ;
	DRIVERCRATE_EXPECT( c, contents( path) == old) ;
	DRIVERCRATE_EXPECT(
		c, std::filesystem::exists( extended( root / L"current/collection-head-v1.json.tmp"))) ;
	const auto failed = image( root) ;	// 残留stagingも保持します。
	DRIVERCRATE_EXPECT( c,
					   LocalCollectorSharedStore::bootstrap( s.parent, *s.child, fixture()) == 13U) ;
	DRIVERCRATE_EXPECT( c, failed == image( root)) ;
}
/** @brief 同handle実sizeの先払い・失敗出力を検査します。
 * @param[in,out] c Native集計。
 * @param[in] root 自身の専用領域。
 */
void rawBudget( TestContext &c, const std::filesystem::path &root)
{
	Session s( root) ;	// 共有bootstrapと分けたraw試験です。
	require( s.child->store().write( L"runs/raw-proof.json", "abc") == 0U) ;
	std::uint64_t remaining = 2U ;		// 実3 byteに不足する元予算です。
	std::string	  raw		= "old" ;	// 失敗時の出力を残しません。
	bool		  found		= true ;	// 欠損／容量拒否はfalseです。
	DRIVERCRATE_EXPECT( c,
					   s.child->store().read( L"runs/raw-proof.json", raw, found, remaining) == 68U) ;
	DRIVERCRATE_EXPECT( c, remaining == 2U && raw.empty() && !found) ;
	remaining = 3U ;
	DRIVERCRATE_EXPECT( c,
					   s.child->store().read( L"runs/raw-proof.json", raw, found, remaining) == 0U) ;
	DRIVERCRATE_EXPECT( c, remaining == 0U && raw == "abc" && found) ;
	DRIVERCRATE_EXPECT( c, s.child->store().read( L"runs/missing.json", raw, found, remaining) == 0U) ;
	DRIVERCRATE_EXPECT( c, remaining == 0U && raw.empty() && !found) ;
}
} // namespace
} // namespace drivercrate::test

/** @brief 架空の独立実filesystem fixtureを非通信で実行します。
 * @return 全合格0、assertion失敗1、setup失敗2。
 */
int wmain()
{
	try {
		winrt::init_apartment( winrt::apartment_type::multi_threaded) ;
		drivercrate::test::TestContext c ;	// 実filesystemの観測だけを集計します。
		const auto base = std::filesystem::absolute( std::filesystem::path( L"work/tmp") /
													(L"shared-store-" +
													 std::to_wstring( GetCurrentProcessId()) + L"-" +
													 // 自身の未存在領域です。
													 std::to_wstring( GetTickCount64()))) ;
		drivercrate::test::require( std::filesystem::create_directories( base)) ;
		drivercrate::test::normal( c, base) ;
		// 136個の独立領域で各atomic保存後の元停止を測ります。
		for( std::size_t stop = 1U; stop <= 136U; ++stop) {
			drivercrate::test::window(
				c, base / (L"stop-" + std::to_wstring( stop)) / drivercrate::test::key( 1U), stop) ;
		}

		// 九種類の改変を独立して保存前拒否します。
		for( std::size_t kind = 0U; kind < 9U; ++kind) {
			drivercrate::test::rejected(
				c, base / (L"rejected-" + std::to_wstring( kind)) / drivercrate::test::key( 1U),
				kind) ;
		}

		drivercrate::test::blocked( c, base / L"blocked" / drivercrate::test::key( 1U)) ;
		drivercrate::test::rawBudget( c, base / L"raw" / drivercrate::test::key( 1U)) ;
		std::cout << "Shared store assertions: " << c.assertionCount()
				  << ", failures: " << c.failureCount() << '\n' ;
		return c.failureCount() == 0U ? 0 : 1 ;
	} catch( const std::exception &error) {
		std::cerr << error.what() << '\n' ;
		return 2 ;
	}
}
