//------------------------------------------------------------------------------
/**
 * @file local_collector_shared_inventory_tests.cpp
 * @brief 同親共有根拠の非変更・全raw結合・最終再照合を検査します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  共有inventory実byteと閉鎖根拠fixtureを追加。
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
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <type_traits>
#include <set>
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
#include <source_location>
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
 * @param[in] location Setup元source位置。製品診断へ渡しません。
 */
void require( const bool ok, const std::source_location location = std::source_location::current())
{
	// 不成立setupから試験を継続しません。
	if( !ok) {
		throw std::runtime_error( "Shared inventory fixture setup failed at line " +
								 std::to_string( location.line())) ;
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

/** @brief 自身の閉鎖fixtureだけを改変します。
 * @param[in] path 存在する自身のfile。
 * @param[in] bytes 故意の不正rawまたは元raw。
 */
void alter( const std::filesystem::path &path, const std::string_view bytes)
{
	std::ofstream stream( extended( path), std::ios::binary | std::ios::trunc) ;	// ACLは変更しません。
	require( stream.good()) ;
	stream.write( bytes.data(), static_cast<std::streamsize>( bytes.size())) ;
	require( stream.good()) ;
}
/** @brief 実raw／本文の指紋を独立計算します。
 * @param[in] bytes Fixtureが保持する元byte。
 * @return CNGで計算した完全hash。
 */
std::wstring hash( const std::string_view bytes)
{
	std::wstring result ;	// 本番context内の指紋を期待値へ流用しません。
	require( computeCollectorMetadataSha256( bytes, result) == 0) ;
	return result ;
}
/** @brief 自己hashが正しい不正schemaのenvelopeです。
 * @return 本文が空objectである共有envelope。
 */
std::string invalidEnvelope()
{
	collector_projected_json::Writer w( 4096U) ;	// 固定file schemaを別に保ちます。
	w.append( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
	w.text( "{}") ;
	w.append( ",\"sha256\":") ;
	w.wideText( hash( "{}")) ;
	w.append( "}") ;
	return w.take() ;
}
/** @brief 二日・成功・中断・参照を含む元七操作です。
 * @return 本番storeへ渡す元列。
 */
std::vector<CollectorSharedOperation> operations()
{
	const auto				  first = reservation() ;	// 元日の予約正本です。
	CollectorSharedSettlement success ;					// 元成功の型付き観測です。
	success.request				   = first.request ;
	success.started				   = first.started ;
	success.finished			   = first.started + 1000U ;
	success.accepted			   = first.started + 2000U ;
	success.bytesKnown			   = true ;
	success.receivedBytes		   = 7U ;
	success.observation.successful = true ;
	success.observation.status	   = 200U ;
	auto cache	   = std::get<CollectorSharedCacheUpdate>( operation( 2U)) ;	// 最初の元参照更新です。
	cache.accepted = success.accepted ;
	auto second	   = first ;	// 期限後だけ翌日再予約します。
	second.request.generationKey = key( 1001U) ;
	second.request.jobKey		 = key( 101U) ;
	second.started				 = (UTC + 86510U) * 1000U ;
	CollectorSharedSettlement abandoned ;	// 未知byteのmaximum精算です。
	abandoned.request	  = second.request ;
	abandoned.started	  = second.started ;
	abandoned.finished	  = second.started + 1000U ;
	abandoned.accepted	  = second.started + 2000U ;
	abandoned.interrupted = true ;
	auto next			  = cache ;	// 明示参照だけを変更し失敗を成功にしません。
	next.accepted		  = abandoned.accepted ;
	next.expected		  = cache.next ;
	next.next			  = {key( 2U), key( 199U), key( 12U)} ;
	return {first, success, cache, operation( 1U), second, abandoned, next} ;
}
/** @brief 元proofの全fieldを独立rawとJSONへ突合します。
 * @param[in,out] c Native集計。
 * @param[in] proof 全検査後のimmutable根拠。
 * @param[in] root 自身の親root。
 * @param[in] expected 事前に固定した元状態。
 * @param[in] count 元完了操作数。
 * @param[in] inspected 事前に固定した検査UTC。
 */
void inspect( TestContext &c, const CollectorSharedRootInventory &proof,
			 const std::filesystem::path &root, const CollectorSharedLedgerSnapshot &expected,
			 const std::size_t count, const std::uint64_t inspected)
{
	const auto &e	= proof.evidence() ;	// Context内のimmutable所有値です。
	const auto	all = image( root) ;		// Scopeを含む実rawを独立に読みます。
	DRIVERCRATE_EXPECT( c, equal( e.snapshot, expected)) ;
	DRIVERCRATE_EXPECT( c, e.segment == key( 2U) && e.operations == count &&
							  e.inspectedUtcMillis == inspected && e.files.size() == 137U + count) ;
	DRIVERCRATE_EXPECT( c, all.size() == e.files.size()) ;
	std::set<std::wstring> seen ;		// 全fileの一回登録を独立に確認します。
	std::uint64_t		   bytes{} ;	// 重複しない実file byteを集計します。
	// 別JSON実装でinventoryの全fieldを調べます。
	const auto inv = winrt::Windows::Data::Json::JsonObject::Parse( winrt::to_hstring( e.inventory)) ;
	// 原本文の全fieldを別JSON実装で調べます。
	DRIVERCRATE_EXPECT( c,
					   inv.Size() == 6U &&
						   inv.GetNamedString( L"schema") == L"collector-shared-root-inventory-v1" &&
						   inv.GetNamedString( L"collection") == key( 1U) &&
						   inv.GetNamedString( L"segment") == key( 2U) &&
						   inv.GetNamedString( L"head") == e.headSha256 &&
						   inv.GetNamedNumber( L"fileCount") == static_cast<double>( e.files.size())) ;
	const auto rows = inv.GetNamedArray( L"files") ;	// 全行の元ordinalを保持します。
	DRIVERCRATE_EXPECT( c, rows.Size() == e.files.size()) ;
	// 全行のscope・元raw hash・sizeを自己申告JSON以外へ突合します。
	for( std::size_t i = 0U; i < e.files.size(); ++i) {
		const auto &file = e.files[i] ;	// Inventory元ordinalです。
		// Fixtureのnative名と保護相対名を比較します。
		auto		relative = std::filesystem::path( file.name).make_preferred().native() ;
		// Fixtureのnative名と保護相対名を比較します。
		// 子は同じ検査済みsegment keyからだけ構成します。
		if( !file.parent) {
			relative = L"segments\\" + key( 2U) + L"\\" + relative ;
		}

		const auto found = all.find( relative) ;	// 実保存名の完全一致です。
		DRIVERCRATE_EXPECT( c, found != all.end() && seen.insert( relative).second) ;
		require( found != all.end()) ;
		DRIVERCRATE_EXPECT( c, file.bytes == found->second.size() &&
								  file.sha256 == hash( found->second)) ;
		bytes += found->second.size() ;
		const auto row =
			// JSON ordinalの独立比較です。
			rows.GetObjectAt( static_cast<std::uint32_t>( i)) ;
		DRIVERCRATE_EXPECT( c, row.Size() == 4U &&
								  row.GetNamedString( L"scope") ==
									  (file.parent ? L"parent" : L"segment") &&
								  row.GetNamedString( L"name") == file.name &&
								  row.GetNamedNumber( L"bytes") == static_cast<double>( file.bytes) &&
								  row.GetNamedString( L"sha256") == file.sha256) ;
	}

	DRIVERCRATE_EXPECT( c, bytes == e.fileBytes && hash( e.inventory) == e.inventorySha256 &&
							  hash( e.seal) == e.sealSha256) ;
	const auto head = winrt::Windows::Data::Json::JsonObject::Parse(
		// 外側と内側を分けます。
		winrt::to_hstring( all.at( L"current\\collection-head-v1.json"))) ;
	DRIVERCRATE_EXPECT( c, hash( winrt::to_string( head.GetNamedString( L"body"))) == e.headSha256) ;
	// 実ready headの元台帳結合を別に検査します。
	const auto body = winrt::Windows::Data::Json::JsonObject::Parse( head.GetNamedString( L"body")) ;
	// 元ready headの台帳結合です。
	DRIVERCRATE_EXPECT( c, body.GetNamedString( L"ledger") == e.ledger) ;
	// 共有sealの固定全fieldを独立に照合します。
	const auto seal = winrt::Windows::Data::Json::JsonObject::Parse( winrt::to_hstring( e.seal)) ;
	// 共有sealはROOT完了を表すfieldを持ちません。
	DRIVERCRATE_EXPECT(
		c, seal.Size() == 11U &&
			   seal.GetNamedString( L"schema") == L"collector-shared-root-seal-v1" &&
			   seal.GetNamedString( L"collection") == key( 1U) &&
			   seal.GetNamedString( L"segment") == key( 2U) &&
			   seal.GetNamedString( L"head") == e.headSha256 &&
			   seal.GetNamedString( L"ledger") == e.ledger &&
			   seal.GetNamedNumber( L"rootUtc") == static_cast<double>( expected.lastUtcMillis) &&
			   seal.GetNamedNumber( L"inspectedUtc") == static_cast<double>( inspected) &&
			   seal.GetNamedNumber( L"operations") == static_cast<double>( count) &&
			   seal.GetNamedNumber( L"fileCount") == static_cast<double>( e.files.size()) &&
			   seal.GetNamedNumber( L"fileBytes") == static_cast<double>( bytes) &&
			   seal.GetNamedString( L"inventory") == e.inventorySha256) ;
}
/** @brief 七操作の各閉鎖点と再起動を非変更で測ります。
 * @param[in,out] c Native集計。
 * @param[in] root 自身のfixture。
 */
void normal( TestContext &c, const std::filesystem::path &root)
{
	std::string					  originalSeal ;			// 元閉鎖点の反復identityです。
	std::string					  originalInventory ;		// 元名／byteの比較像です。
	CollectorSharedLedgerSnapshot expected = fixture() ;	// 純coreと実保存の二正本を比較します。
	std::shared_ptr<const CollectorSharedRootInventory>
			   retained ;						// 後続保存から独立した古いsnapshotです。
	const auto now = (UTC + 86512U) * 1000U ;	// 全七操作後も時計後退しない固定検査時計です。
	{
		Session	   s( root, true) ;			// 元初回だけを作ります。
		const auto before = image( root) ;	// 原byte非変更の独立像です。
		require( LocalCollectorSharedStore::inspectSharedRootInventory( s.parent, *s.child, now,
																	  retained) == 0U) ;
		inspect( c, *retained, root, expected, 0U, now) ;
		DRIVERCRATE_EXPECT( c, image( root) == before) ;
		const auto ops = operations() ;	// 全四型を含む固定列です。
		// 未精算中の二点は読取り拒否し閉鎖点だけを根拠へ昇格します。
		for( std::size_t i = 0U; i < ops.size(); ++i) {
			CollectorSharedLedgerSnapshot after ;	// 純coreの再導出結果です。
			CollectorSharedOperationDelta delta ;	// 元操作関係を先に検査します。
			require( deriveCollectorSharedOperation( expected, ops[i], after, delta) == 0U) ;
			require( LocalCollectorSharedStore::commit( s.parent, *s.child, ops[i]) == 0U) ;
			expected	   = std::move( after) ;
			const auto raw = image( root) ;	// 読取りは待機／課金を変更しません。
			std::shared_ptr<const CollectorSharedRootInventory> proof =
				retained ;	// 拒否時のクリアを測ります。
			// 未精算を自動中断しない実結果を保持します。
			const auto code = LocalCollectorSharedStore::inspectSharedRootInventory(
				s.parent, *s.child, now, proof) ;
			// 未精算を自動中断しない実結果です。
			DRIVERCRATE_EXPECT( c, code == (i == 0U || i == 4U ? 13U : 0U)) ;
			DRIVERCRATE_EXPECT( c, image( root) == raw) ;
			// 二つの元予約点は閉鎖根拠を持てません。
			if( i == 0U || i == 4U) {
				DRIVERCRATE_EXPECT( c, !proof) ;
			} else {
				require( static_cast<bool>( proof)) ;
				inspect( c, *proof, root, expected, i + 1U, now) ;
				originalSeal	  = proof->evidence().seal ;
				originalInventory = proof->evidence().inventory ;
			}
		}

		DRIVERCRATE_EXPECT( c, equal( retained->evidence().snapshot, fixture()) &&
								  retained->evidence().operations == 0U) ;
	}
	Session	   reopened( root, false) ;							// 別ownerで原履歴を再検査します。
	const auto before = image( root) ;							// 元七操作の保存byteです。
	std::shared_ptr<const CollectorSharedRootInventory> proof ;	// 新ownerのfresh根拠です。
	require( LocalCollectorSharedStore::inspectSharedRootInventory( reopened.parent, *reopened.child,
																  now, proof) == 0U) ;
	DRIVERCRATE_EXPECT( c, proof->evidence().seal == originalSeal &&
							  proof->evidence().inventory == originalInventory &&
							  image( root) == before) ;
	require( LocalCollectorSharedStore::inspectSharedRootInventory( reopened.parent, *reopened.child,
																  now + 86400000U, proof) == 0U) ;
	DRIVERCRATE_EXPECT( c, proof->evidence().seal != originalSeal &&
							  proof->evidence().inventory == originalInventory &&
							  equal( proof->evidence().snapshot, expected)) ;
	DRIVERCRATE_EXPECT( c, image( root) == before && expected.budget.reservations.size() == 1U &&
							  expected.budget.reservations.front().phase == 2U &&
							  expected.budget.reservations.front().charged == 4096U &&
							  expected.groups.at( L"fixture-a").review) ;
}
/** @brief 全rawの改変と自己hashが正しい不正本文を拒否します。
 * @param[in,out] c Native集計。
 * @param[in] root 自身の閉鎖fixture。
 */
void changed( TestContext &c, const std::filesystem::path &root)
{
	Session s( root, true) ;	// 原初回を保存します。
	// 全型を実保存した最新の閉鎖鎖を作ります。
	for( const auto &op : operations()) {
		require( LocalCollectorSharedStore::commit( s.parent, *s.child, op) == 0U) ;
	}

	const auto originals = image( root) ;			// 全144存在fileの元byteです。
	const auto now		 = (UTC + 86512U) * 1000U ;	// 元七操作より後の固定時計です。
	// 各fileを独立に改変し原byteへ戻して次条件と混合しません。
	for( const auto &[name, raw] : originals) {
		// Raw破損と正しい外側hashの不正schemaを別条件で測ります。
		for( const auto &bad : {std::string( "{}"), invalidEnvelope()}) {
			alter( root / name, bad) ;
			const auto before = image( root) ;	// 改変後もreaderは一切保存しません。
			std::shared_ptr<const CollectorSharedRootInventory>
				proof ;	// 不正byteからは発行不可です。
			DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::inspectSharedRootInventory(
									  s.parent, *s.child, now, proof) == 13U &&
									  !proof) ;
			DRIVERCRATE_EXPECT( c, before == image( root)) ;
			alter( root / name, raw) ;
		}
	}

	std::shared_ptr<const CollectorSharedRootInventory> proof ;	// 全原byte復元後のfresh検査です。
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::inspectSharedRootInventory( s.parent, *s.child,
																				now, proof) == 0U &&
							  image( root) == originals) ;
}
/** @brief 停止・再入・別能力と最終raw差替え／追加／I/Oを測ります。
 * @param[in,out] c Native集計。
 * @param[in] base 自身のfixture親。
 */
void finalChecks( TestContext &c, const std::filesystem::path &base)
{
	LocalCollectorCollectionStore missingAncestor ;	// 準備エラーを製品の作成境界と切り分けます。
	// 同じ最初の不足祖先の元Win32 codeを直接観測します。
	const HANDLE missing = CreateFileW( extended( base).c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
									   FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
									   FILE_FLAG_BACKUP_SEMANTICS, nullptr) ;
	const DWORD	 nativeError = GetLastError() ;	// 2／3を推測で取り違えません。
	require( missing == INVALID_HANDLE_VALUE) ;
	// 本番の第一I/O errorを独立oracleと比較します。
	const DWORD storeError = missingAncestor.initialize( base / L"probe" / key( 1U), key( 1U)) ;
	DRIVERCRATE_EXPECT( c, storeError == nativeError && storeError != 0U) ;
	std::cout << "Missing ancestor native error: " << nativeError << '\n' ;
	DRIVERCRATE_EXPECT( c, !std::filesystem::exists( base)) ;
	// Workspace祖先はfixtureが先に用意し、保護storeの作成境界を緩和しません。
	require( std::filesystem::create_directories( base)) ;
	Session	   s( base / L"normal" / key( 1U), true) ;						// 元初回の能力を保持します。
	Session	   other( base / L"other" / key( 1U), true) ;					// 同名でも別親です。
	const auto root = s.child->store().root().parent_path().parent_path() ;	// 自身のcollectionです。
	const auto before = image( root) ;										// 全拒否でraw非変更を要求します。
	std::shared_ptr<const CollectorSharedRootInventory> proof ;				// 失敗は空にします。
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::inspectSharedRootInventory(
							  other.parent, *s.child, UTC * 1000U, proof) == 87U &&
							  !proof) ;
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::inspectSharedRootInventory(
							  s.parent, *s.child, UTC * 1000U - 1U, proof) == 13U &&
							  !proof) ;
	// 数値停止は成功値を注入せず借用を返却します。
	for( const DWORD code : {5U, 1223U, 13U, 8U}) {
		DRIVERCRATE_EXPECT(
			c, LocalCollectorSharedStore::inspectSharedRootInventory(
				   s.parent, *s.child, UTC * 1000U, proof, [code] { return code ; }) == code &&
				   !proof) ;
		CollectorSharedLedgerSnapshot copy ;	// 失敗終端で元借用が返却されたことを測ります。
		DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::load( s.parent, *s.child, copy) == 0U) ;
	}

	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::inspectSharedRootInventory(
							  s.parent, *s.child, UTC * 1000U, proof,
							  []() -> DWORD { throw std::bad_alloc{} ; }) == 8U &&
							  !proof) ;
	DWORD nested{} ;	// 外側検査中の再入は170です。
	DWORD loadCode{} ;	// 通常loadも同じ共有借用を占有できません。
	DRIVERCRATE_EXPECT( c,
					   LocalCollectorSharedStore::inspectSharedRootInventory(
						   s.parent, *s.child, UTC * 1000U, proof,
						   [&] {
							   std::shared_ptr<const CollectorSharedRootInventory>
								   local ;	// 外側outputと別ownerです。
							   nested = LocalCollectorSharedStore::inspectSharedRootInventory(
								   s.parent, *s.child, UTC * 1000U, local) ;
							   CollectorSharedLedgerSnapshot copy ;	// 正常値を再入で得られません。
							   loadCode = LocalCollectorSharedStore::load( s.parent, *s.child, copy) ;
							   return 0U ;
						   }) == 0U &&
						   proof && nested == 170U && loadCode == 170U) ;
	DRIVERCRATE_EXPECT( c, image( root) == before) ;
	// 履歴の最終再readだけを塞ぐ自身の固定fileです。
	const auto target = s.child->store().root() / L"current/segment-shared-base-v1.json" ;
	// 初回read後の実履歴再readだけを塞ぐ自身のfileです。
	HANDLE	   blocker = INVALID_HANDLE_VALUE ;	// 自身の診断handleだけを最後に閉じます。
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::inspectSharedRootInventory(
							  s.parent, *s.child, UTC * 1000U, proof,
							  [&] {
								  blocker = CreateFileW( extended( target).c_str(), GENERIC_READ, 0U,
														nullptr, OPEN_EXISTING, 0U, nullptr) ;
								  require( blocker != INVALID_HANDLE_VALUE) ;
								  return 0U ;
							  }) == 32U &&
							  !proof) ;
	require( CloseHandle( blocker) != FALSE) ;
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::inspectSharedRootInventory(
							  s.parent, *s.child, UTC * 1000U, proof) == 0U &&
							  image( root) == before) ;
	// 最終変更と未知追加をそれぞれ独立した元領域で測ります。
	for( const bool addition : {false, true}) {
		// 最終改変の二条件に独立した元領域を作ります。
		Session	   altered( base / (addition ? L"addition" : L"change") / key( 1U), true) ;
		// 他条件の改変を持ち越しません。
		const auto ownRoot = altered.child->store().root().parent_path().parent_path() ;
		// 自身の元collectionです。
		DRIVERCRATE_EXPECT(
			c, LocalCollectorSharedStore::inspectSharedRootInventory(
				   altered.parent, *altered.child, UTC * 1000U, proof,
				   [&] {
					   // 未知名は元借用storeの保護作成だけで追加します。
					   if( addition) {
						   require( altered.child->store().write( L"runs/unknown.json", "{}") == 0U) ;
					   } else {
						   alter( ownRoot / L"current/collection-head-v1.json", "{}") ;
					   }

					   return 0U ;
				   }) == 13U &&
				   !proof) ;
		const auto invalid = image( ownRoot) ;	// Callbackの変更以外をreaderは保存しません。
		DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::inspectSharedRootInventory(
								  altered.parent, *altered.child, UTC * 1000U, proof) == 13U &&
								  !proof && image( ownRoot) == invalid) ;
	}
}
/** @brief 最大64操作の実存在201fileを検査します。
 * @param[in,out] c Native集計。
 * @param[in] root 自身のfixture。
 */
void maximum( TestContext &c, const std::filesystem::path &root)
{
	Session s( root, true) ;												// 元参照操作だけで閉鎖64回を作ります。
	auto	op = std::get<CollectorSharedCacheUpdate>( operation( 2U)) ;	// 元同UTC・期限を保持します。
	// 旧期待参照を一回ずつ更新します。
	for( std::size_t i = 0U; i < 64U; ++i) {
		op.next.cacheSha256 = key( 99U + i) ;
		require( LocalCollectorSharedStore::commit( s.parent, *s.child, op) == 0U) ;
		op.expected = op.next ;
	}

	CollectorSharedLedgerSnapshot expected ;	// 既存loadと新readerを同じ原像へ照合します。
	require( LocalCollectorSharedStore::load( s.parent, *s.child, expected) == 0U) ;
	std::shared_ptr<const CollectorSharedRootInventory> proof ;	// 新根拠は全64を再導出します。
	require( LocalCollectorSharedStore::inspectSharedRootInventory( s.parent, *s.child, UTC * 1000U,
																  proof) == 0U) ;
	inspect( c, *proof, root, expected, 64U, UTC * 1000U) ;
}
/** @brief 未登録／active commitを回復せず非変更拒否します。
 * @param[in,out] c Native集計。
 * @param[in] base 自身のfixture親。
 */
void pending( TestContext &c, const std::filesystem::path &base)
{
	require( std::filesystem::create_directories( base)) ;
	std::shared_ptr<const CollectorSharedRootInventory> proof ;	// 途中状態からは根拠を発行しません。
	Session empty( base / L"empty" / key( 1U), false) ;			// Marker以外は未登録です。
	// 各拒否前の元rawです。
	auto	before = image( empty.child->store().root().parent_path().parent_path()) ;
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::inspectSharedRootInventory(
							  empty.parent, *empty.child, UTC * 1000U, proof) == 13U &&
							  !proof) ;
	DRIVERCRATE_EXPECT( c, before == image( empty.child->store().root().parent_path().parent_path())) ;
	Session boot( base / L"bootstrap" / key( 1U), false) ;	// 最後のreadyより前で停止します。
	require( LocalCollectorSharedStore::bootstrap(
				boot.parent, *boot.child, fixture(),
				[]( std::size_t ordinal) { return ordinal == 135U ? 995U : 0U ; }) == 995U) ;
	before = image( boot.child->store().root().parent_path().parent_path()) ;
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::inspectSharedRootInventory(
							  boot.parent, *boot.child, UTC * 1000U, proof) == 13U &&
							  !proof) ;
	DRIVERCRATE_EXPECT( c, before == image( boot.child->store().root().parent_path().parent_path())) ;
	Session	   active( base / L"operation" / key( 1U), true) ;	// 新予約の登録head後で止めます。
	const auto op = reservation() ;								// 元予約時計／identityを固定します。
	require( LocalCollectorSharedStore::commit(
				active.parent, *active.child, op,
				[]( std::size_t ordinal) { return ordinal == 2U ? 995U : 0U ; }) == 995U) ;
	before = image( active.child->store().root().parent_path().parent_path()) ;
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::inspectSharedRootInventory(
							  active.parent, *active.child, op.started, proof) == 13U &&
							  !proof) ;
	DRIVERCRATE_EXPECT( c,
					   before == image( active.child->store().root().parent_path().parent_path())) ;
	require( LocalCollectorSharedStore::commit( active.parent, *active.child, op) == 0U) ;
	before = image( active.child->store().root().parent_path().parent_path()) ;
	DRIVERCRATE_EXPECT( c, LocalCollectorSharedStore::inspectSharedRootInventory(
							  active.parent, *active.child, op.started, proof) == 13U &&
							  !proof) ;
	DRIVERCRATE_EXPECT( c,
					   before == image( active.child->store().root().parent_path().parent_path())) ;
}
} // namespace
} // namespace drivercrate::test

/** @brief 独立した同親共有根拠fixtureを非通信で実行します。
 * @return 合格0、assertion失敗1、setup失敗2。
 */
int wmain()
{
	static_assert( !std::is_default_constructible_v<
				  drivercrate::CollectorSharedRootInventory::ConstructionKey>) ;
	static_assert( !std::is_constructible_v<drivercrate::CollectorSharedRootInventory,
										   drivercrate::CollectorSharedRootEvidence>) ;
	try {
		winrt::init_apartment( winrt::apartment_type::multi_threaded) ;
		drivercrate::test::TestContext c ;	// この独立nativeだけの分母です。
		const auto base = std::filesystem::absolute( std::filesystem::path( L"work/tmp") /
													(L"shared-inventory-" +
													 std::to_wstring( GetCurrentProcessId()) + L"-" +
													 // 自身の未存在fixtureだけです。
													 std::to_wstring( GetTickCount64()))) ;
		drivercrate::test::require( std::filesystem::create_directories( base)) ;
		drivercrate::test::normal( c, base / L"normal" / drivercrate::test::key( 1U)) ;
		drivercrate::test::changed( c, base / L"changed" / drivercrate::test::key( 1U)) ;
		drivercrate::test::finalChecks( c, base / L"final") ;
		drivercrate::test::pending( c, base / L"pending") ;
		drivercrate::test::maximum( c, base / L"maximum" / drivercrate::test::key( 1U)) ;
		std::cout << "Shared inventory assertions: " << c.assertionCount()
				  << ", failures: " << c.failureCount() << '\n' ;
		return c.failureCount() == 0U ? 0 : 1 ;
	} catch( const std::exception &error) {
		std::cerr << error.what() << '\n' ;
		return 2 ;
	}
}
