//------------------------------------------------------------------------------
/**
 * @file local_collector_shared_store.cpp
 * @brief 初回共有台帳の全保存像と物理prefixを親headへ結合します。
 * @version 01.06.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  固定136手順・前検査・不足回復を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/02  疎な精算record・更新head・固定回復を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/02  追加三操作v2の共通commit・混在再導出を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/02  同親共有履歴の全raw根拠と最終照合を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/02  同親専用leaseのhistory付きmarkerを明示照合。
 * Ver.01.05.00 Shunji Ogawa  2026/10/02  共有借用中の私有履歴再検査を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/03  保護実handleの初回切替回復と検査を追加。
 * </pre>
 *
 * @note 開発用更新と共有根拠です。区間seal・移行・実dispatch・取得許可・HTTPは未接続です。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#include "local_collector_shared_store.h"
#include "local_collector_segment_switch.h"
#include "local_collector_projected_json.h"
#include "official_file_verifier.h"
#include <variant>
#include <algorithm>
#include <array>
#include <memory>
#include <new>
#include <optional>
#include <set>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {
using collector_projected_json::Reader ;
using collector_projected_json::Writer ;
using collector_projected_json::Failure ;
using collector_projected_json::Status ;
// 最終再読込み込みの共有raw上限。
constexpr std::uint64_t RAW_LIMIT = 16U * 1024U * 1024U ;
// 親／子の固定markerは新能力への入口です。
constexpr auto			MODE = L"current/collector-campaign-mode-v1.json" ;
// 初回専用headの既知相対名です。
constexpr auto			HEAD = L"current/collection-head-v1.json" ;
// 初回baseはROOTやsealを証明しません。
constexpr auto			BASE = L"current/segment-shared-base-v1.json" ;

/** @brief 不成立を元数値で伝播します。
 * @param[in] ok 成立が必須の条件。
 * @param[in] code 不成立の第一数値。
 * @throws DWORD 条件不成立時。
 */
void					require( const bool ok, const DWORD code = ERROR_INVALID_DATA)
{
	// 容量・I/Oを形式拒否へ変えません。
	if( !ok) {
		throw code ;
	}
}
/** @brief APIの第一数値errorを保持します。
 * @param[in] code 元結果。
 * @throws DWORD 失敗code。
 */
void io( const DWORD code)
{
	require( code == ERROR_SUCCESS, code) ;
}
/** @brief 有限原byteの実CNG指紋を作ります。
 * @param[in] value 最大2 MiBの所有byte。
 * @return 元byteの小文字SHA-256。
 * @throws DWORD 元CNG error。
 */
std::wstring digest( const std::string_view value)
{
	std::wstring hash ;	// 元byteの内部指紋です。
	io( static_cast<DWORD>( computeCollectorMetadataSha256( value, hash))) ;
	return hash ;
}
/** @brief 固定schemaの有限本文を専用envelopeに包みます。
 * @param[in] body 字句／意味検査済みのcanonical本文。
 * @return 2 MiB以下の保存byte。
 * @throws Failure 字句・byte上限拒否。
 * @throws DWORD CNG失敗。
 */
std::string pack( const std::string_view body)
{
	Writer w( 2U * 1024U * 1024U) ;	// 外側の独立上限です。
	w.append( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
	w.text( body) ;
	w.append( ",\"sha256\":") ;
	w.wideText( digest( body)) ;
	w.append( "}") ;
	return w.take() ;
}
/** @brief 全field順と元本文hashを検査して原byteを取り出します。
 * @param[in] raw 最大2 MiBの保存envelope。
 * @return 最大768 KiBの元本文。
 * @throws Failure 字句・容量拒否。
 * @throws DWORD Hash／CNG不成立。
 */
std::string unpack( const std::string_view raw)
{
	Reader r( raw, 2U * 1024U * 1024U) ;	// 任意fieldを部分採用しません。
	r.literal( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
	auto body = r.text( 768U * 1024U) ;	// 照合対象の元byteです。
	r.literal( ",\"sha256\":") ;
	const auto hash = r.text( 64U) ;	// CNG値との完全一致対象です。
	r.literal( "}") ;
	r.finish() ;
	require( digest( body) == std::wstring( hash.begin(), hash.end())) ;
	return body ;
}
/** @brief 固定ordinalを二桁hexにします。
 * @param[in] ordinal 固定66 role以内の値。
 * @return 小文字二桁の既知name断片。
 */
std::wstring hexOrdinal( const std::size_t ordinal)
{
	constexpr std::wstring_view digits = L"0123456789abcdef" ;	// 名称の固定ASCIIです。
	return std::wstring{digits[ordinal / 16U], digits[ordinal % 16U]} ;
}
/** @brief 全66 roleの現在名を値からではなくordinalから作ります。
 * @param[in] ordinal 0予算、1group、2～65 request。
 * @return 親current直下の固定相対名。
 */
std::wstring currentName( const std::size_t ordinal)
{
	// 最初の二roleをrequest名と混同しません。
	if( ordinal < 2U) {
		return ordinal == 0U ? L"current/shared-budget-v1.json" : L"current/shared-groups-v1.json" ;
	}

	return L"current/shared-requests-" + hexOrdinal( ordinal - 2U) + L".json" ;
}
/** @brief 初回intent keyと固定ordinalから準備名を導出します。
 * @param[in] key 検査済みintent hash。
 * @param[in] ordinal 0～65の固定順。
 * @return 子runsの既知名。
 */
std::wstring preparedName( const std::wstring_view key, const std::size_t ordinal)
{
	return L"runs/shared-bootstrap-" + std::wstring( key) + L"-" + hexOrdinal( ordinal) + L".json" ;
}
/** @brief 任意pathを使わず初回intentの名を作ります。
 * @param[in] key 検査済みintent hash。
 * @return 子runs直下の固定名。
 */
std::wstring intentName( const std::wstring_view key)
{
	return L"runs/shared-bootstrap-intent-" + std::wstring( key) + L".json" ;
}
/** @brief 保存順とhash循環を固定した初回bundleです。 */
struct Bundle {
	/// 恒久collection key。
	std::wstring				 collection ;
	/// 唯一の初回segment key。
	std::wstring				 segment ;
	/// 現在時刻で更新しない元最高UTC。
	std::uint64_t				 accepted{} ;
	/// 全66本文hashを順序付きで結合したdigest。
	std::wstring				 ledger ;
	/// 固定ordinalの66保存envelope。
	std::array<std::string, 66U> images ;
	/// 子baseの保存envelope。
	std::string					 base ;
	/// Base本文だけの指紋。
	std::wstring				 baseHash ;
	/// 初回intentの保存envelope。
	std::string					 intent ;
	/// Intent本文だけの指紋。
	std::wstring				 intentHash ;
	/// 未反映状態を固定する親登録head。
	std::string					 registered ;
	/// 全値と元intentへ結合する確定head。
	std::string					 ready ;
} ;
/** @brief 固定66本文を同じordinal順で借り受けます。
 * @param[in] bytes 元codecの所有byte。
 * @param[in] ordinal 固定66 role以内。
 * @return Bytes存続中の本文参照。
 */
const std::string &bodyAt( const CollectorSharedLedgerBytes &bytes, const std::size_t ordinal)
{
	// 固定先頭roleを同じ順序へ結合します。
	if( ordinal < 2U) {
		return ordinal == 0U ? bytes.budget : bytes.groups ;
	}

	return bytes.requests[ordinal - 2U] ;
}
/** @brief 登録と確定で異なるfieldだけを固定headへ反映します。
 * @param[in] b Hash循環なしに準備したbundle。
 * @param[in] ready trueは確定、falseはcommit登録。
 * @return 専用envelope付きの固定head。
 */
std::string headBytes( const Bundle &b, const bool ready)
{
	Writer w( 16U * 1024U) ;	// 既知fieldだけの有限headです。
	w.append( "{\"schema\":\"collector-collection-head-v1\",\"collection\":") ;
	w.wideText( b.collection) ;
	w.append( ",\"segment\":") ;
	w.wideText( b.segment) ;
	w.append( ",\"ordinal\":0,\"revision\":1,\"accepted\":") ;
	w.number( b.accepted) ;
	w.append( ",\"ledger\":") ;
	w.wideText( ready ? b.ledger : L"") ;
	w.append( ",\"base\":") ;
	w.wideText( ready ? b.baseHash : L"") ;
	w.append( ",\"bootstrap\":") ;
	w.wideText( b.intentHash) ;
	w.append( ",\"sealed\":[],\"commit\":") ;
	// 未反映headにだけ唯一のintentを登録します。
	if( ready) {
		w.append( "null") ;
	} else {
		w.wideText( b.intentHash) ;
	}

	w.append( "}") ;
	return pack( w.view()) ;
}
/** @brief Snapshotの全意味検査後にhash循環なしで全保存像を作ります。
 * @param[in] s Caller所有の元初回値。
 * @param[in] segment 検査済み唯一の子key。
 * @return 固定66原像・intent・base・二head。
 * @throws DWORD Codec／CNG失敗。
 * @throws Failure 有限JSON上限違反。
 */
Bundle prepare( const CollectorSharedLedgerSnapshot &s, const std::wstring_view segment)
{
	CollectorSharedLedgerBytes bytes ;	// 元codecの完全検査済み出力です。
	io( encodeCollectorSharedLedger( s, bytes)) ;
	Bundle b ;	// 全保存像をwriter更新より先に保持します。
	b.collection = s.collection ;
	b.segment	 = segment ;
	b.accepted	 = s.lastUtcMillis ;
	std::array<std::wstring, 66U> hashes ;				// 各本文へのdomain付き集合指紋です。
	Writer						  set( 16U * 1024U) ;	// 順序を失わないdigest対象です。
	set.append( "{\"schema\":\"collector-shared-digest-v1\",\"collection\":") ;
	set.wideText( b.collection) ;
	set.append( ",\"hashes\":[") ;
	// 予算・group・64 shardを一度ずつ同じ順序に包みます。
	for( std::size_t i = 0U; i < b.images.size(); ++i) {
		hashes[i]	= digest( bodyAt( bytes, i)) ;
		b.images[i] = pack( bodyAt( bytes, i)) ;
		// 先頭だけ配列区切りを省きます。
		if( i != 0U) {
			set.append( ",") ;
		}

		set.wideText( hashes[i]) ;
	}

	set.append( "]}") ;
	b.ledger = digest( set.view()) ;
	Writer base( 16U * 1024U) ;	// 自身やintentのhashを本文へ入れません。
	base.append( "{\"schema\":\"collector-segment-shared-base-v1\",\"collection\":") ;
	base.wideText( b.collection) ;
	base.append( ",\"segment\":") ;
	base.wideText( b.segment) ;
	base.append( ",\"ordinal\":0,\"accepted\":") ;
	base.number( b.accepted) ;
	base.append( ",\"ledger\":") ;
	base.wideText( b.ledger) ;
	base.append( "}") ;
	b.baseHash = digest( base.view()) ;
	b.base	   = pack( base.view()) ;
	Writer intent( 16U * 1024U) ;	// Ready headをhashへ入れない固定intentです。
	intent.append( "{\"schema\":\"collector-shared-bootstrap-v1\",\"collection\":") ;
	intent.wideText( b.collection) ;
	intent.append( ",\"segment\":") ;
	intent.wideText( b.segment) ;
	intent.append( ",\"accepted\":") ;
	intent.number( b.accepted) ;
	intent.append( ",\"ledger\":") ;
	intent.wideText( b.ledger) ;
	intent.append( ",\"hashes\":[") ;
	// 同じ66 hashを変更せずintentへ登録します。
	for( std::size_t i = 0U; i < hashes.size(); ++i) {
		// 固定順の配列をcanonicalに区切ります。
		if( i != 0U) {
			intent.append( ",") ;
		}

		intent.wideText( hashes[i]) ;
	}

	intent.append( "],\"base\":") ;
	intent.wideText( b.baseHash) ;
	intent.append( "}") ;
	b.intentHash = digest( intent.view()) ;
	b.intent	 = pack( intent.view()) ;
	b.registered = headBytes( b, false) ;
	b.ready		 = headBytes( b, true) ;
	return b ;
}
/** @brief 再照合する一fileの最初の存在・byteです。 */
struct Tracked {
	/// 借用中だけ有効な親または子store。
	LocalCollectorStateStore  *store{} ;
	/// Roleから導出した相対名。
	std::wstring			   name ;
	/// 初回観測の原byte。欠損ならnullopt。
	std::optional<std::string> raw ;
} ;
/** @brief 全読取りと最終照合を同じ16 MiB予算へ結合します。 */
struct ReadSet {
	/// 呼出し全体のraw残予算。
	std::uint64_t			  &remaining ;
	/// 最大256個の最初の実file観測。
	std::vector<Tracked>	   files ;
	/** @brief 既知名の原byteを初回だけ読んで保持します。
	 * @param[in,out] store Borrowed保護store。
	 * @param[in] name 固定role名。
	 * @return 存在byteまたは欠損。I/Oは欠損へ格下げしません。
	 */
	std::optional<std::string> get( LocalCollectorStateStore &store, const std::wstring &name)
	{
		// 同じ名の重複readを初回観測へ束ねます。
		for( const auto &file : files) {
			// 存在と不在の両方を同じstoreへ結合します。
			if( file.store == &store && file.name == name) {
				return file.raw ;
			}
		}

		require( files.size() < 256U, ERROR_TOO_MANY_NAMES) ;
		std::string raw ;		// 同handle実sizeを先払いした出力です。
		bool		found{} ;	// 欠損を部分本文にしません。
		io( store.read( name, raw, found, remaining)) ;
		Tracked file{&store, name,
					 found ? std::optional<std::string>( std::move( raw))
						   : std::nullopt} ;	// 初回所有像。
		files.push_back( std::move( file)) ;
		return files.back().raw ;
	}
	/** @brief 全存在／欠損とbyteを同じ予算で再照合します。
	 * @param[in] changedStore 自身が保存した一recordのstore。通常はnullです。
	 * @param[in] changedName 自身が保存した一recordの固定名。別途fresh照合を必須にします。
	 */
	void recheck( const LocalCollectorStateStore *changedStore = nullptr,
				 const std::wstring_view		 changedName  = {})
	{
		// 最大256の元fileだけを再読し、差替えを拒否します。
		for( const auto &file : files) {
			// 変更した一recordはfresh handleで別途完全一致を確認します。
			if( file.store == changedStore && file.name == changedName) {
				continue ;
			}

			std::string raw ;		// 最終照合の独立出力です。
			bool		found{} ;	// 元不在も再照合対象です。
			io( file.store->read( file.name, raw, found, remaining)) ;
			require( found == file.raw.has_value() && (!found || raw == *file.raw)) ;
		}
	}
} ;
/** @brief 元136手順のうち不足している一保存です。 */
struct Step {
	/// 親または子のborrowed writer。
	LocalCollectorStateStore *store{} ;
	/// 固定roleから導出した相対名。
	std::wstring			  name ;
	/// Bundle存続中だけの元保存byte。
	std::string_view		  raw ;
	/// 元初回保存の1～136 ordinal。
	std::size_t				  ordinal{} ;
} ;
/** @brief 確定予定名以外と残留stagingを非変更拒否します。
 * @param[in,out] store 親または子の保護store。
 * @param[in] current 許可するcurrent file名集合。
 * @param[in] runs 許可するruns file名集合。
 */
void names( LocalCollectorStateStore &store, const std::set<std::wstring> &current,
		   const std::set<std::wstring> &runs)
{
	std::vector<std::wstring> cn ;	// 属性・ACL検査済みのcurrent名です。
	std::vector<std::wstring> rn ;	// 属性・ACL検査済みのruns名です。
	io( store.listCurrentNames( cn)) ;
	io( store.listRunNames( rn)) ;
	CollectorStoreUsage usage ;	// Stagingも含む実容量です。
	io( store.inspectUsage( usage)) ;
	require( usage.currentEntries == cn.size() && usage.runEntries == rn.size()) ;
	// JSONから許可名を追加せず固定集合と比較します。
	for( const auto &name : cn) {
		require( current.contains( name)) ;
	}

	// 複数intentと未知履歴を初回として無視しません。
	for( const auto &name : rn) {
		require( runs.contains( name)) ;
	}
}
/** @brief 親／子の全許可名を固定bundleから構成します。
 * @param[in,out] parent 親store。
 * @param[in,out] child 子store。
 * @param[in] b 同じ元初回bundle。
 */
void shape( LocalCollectorStateStore &parent, LocalCollectorStateStore &child, const Bundle &b)
{
	std::set<std::wstring> current{L"collector-campaign-mode-v1.json",
								   L"collection-head-v1.json"} ;	// 親固定集合。
	std::set<std::wstring> runs{
		// 一intentだけです。
		std::filesystem::path( intentName( b.intentHash)).filename().native()} ;
	// 全66 roleを親現在値と子準備像へ一度ずつ登録します。
	for( std::size_t i = 0U; i < b.images.size(); ++i) {
		current.insert( std::filesystem::path( currentName( i)).filename().native()) ;
		runs.insert( std::filesystem::path( preparedName( b.intentHash, i)).filename().native()) ;
	}

	names( parent, current, {}) ;
	names( child, {L"collector-campaign-mode-v1.json", L"segment-shared-base-v1.json"}, runs) ;
}
/** @brief 既存原像を完全照合し連続prefixの不足保存だけを返します。
 * @param[in,out] parent 親writer。
 * @param[in,out] child 子writer。
 * @param[in] b 元入力からの完全bundle。
 * @param[in,out] reads 共通raw先払いと最終照合の所有集合。
 * @return 元順序での不足suffix。Readyなら空です。
 */
std::vector<Step> plan( LocalCollectorStateStore &parent, LocalCollectorStateStore &child,
					   const Bundle &b, ReadSet &reads)
{
	shape( parent, child, b) ;
	require( reads.get( parent, MODE).has_value() && reads.get( child, MODE).has_value()) ;
	const auto intent = reads.get( child, intentName( b.intentHash)) ;	// 元候補の存在です。
	require( !intent || *intent == b.intent) ;
	std::vector<Step> steps ;	// 保存前に全拒否を済ませた計画です。
	// 初回intentだけを不足分として先行登録します。
	if( !intent) {
		steps.push_back( {&child, intentName( b.intentHash), b.intent, 1U}) ;
	}

	std::size_t prepared{} ;	// 準備像の連続prefix数です。
	bool		gap{} ;			// 最初の欠損以降に既存像を認めません。
	// 全66名の存在と原byteを必ず照合します。
	for( std::size_t i = 0U; i < b.images.size(); ++i) {
		const auto raw = reads.get( child, preparedName( b.intentHash, i)) ;	// 元順序の像です。
		// 既存像はintentと連続prefixに必須結合します。
		if( raw) {
			require( intent && !gap && *raw == b.images[i]) ;
			++prepared ;
		} else {
			gap = true ;
			steps.push_back( {&child, preparedName( b.intentHash, i), b.images[i], i + 2U}) ;
		}
	}

	const auto head	 = reads.get( parent, HEAD) ;	// 欠損・登録・確定を三状態で区別します。
	const bool ready = head && *head == b.ready ;	// 自己申告schemaだけでは認めません。
	require( !head || *head == b.registered || ready) ;
	require( !head || (intent && prepared == 66U)) ;
	// 全準備像の後だけ親commitを登録します。
	if( !head) {
		steps.push_back( {&parent, HEAD, b.registered, 68U}) ;
	}

	std::size_t applied{} ;	// 現在値の連続prefix数です。
	gap = false ;
	// 登録headの後にだけ親の全66値を反映します。
	for( std::size_t i = 0U; i < b.images.size(); ++i) {
		const auto raw = reads.get( parent, currentName( i)) ;	// 同じroleの現在値です。
		// 登録なし・非prefix・別本文を保存前に拒否します。
		if( raw) {
			require( head && !gap && *raw == b.images[i]) ;
			++applied ;
		} else {
			gap = true ;
			steps.push_back( {&parent, currentName( i), b.images[i], i + 69U}) ;
		}
	}

	const auto base = reads.get( child, BASE) ;	// 本文全反映の次だけに存在できます。
	require( !base || (head && applied == 66U && *base == b.base)) ;
	require( !ready || (applied == 66U && base)) ;
	// 子baseの不足だけを反映します。
	if( !base) {
		steps.push_back( {&child, BASE, b.base, 135U}) ;
	}

	// 全固定像のあとで確定headを一回置換します。
	if( !ready) {
		steps.push_back( {&parent, HEAD, b.ready, 136U}) ;
	}

	return steps ;
}
/** @brief 固定像の保存量と最大staging余裕を書込み前に先払いします。
 * @param[in,out] parent 親writer。
 * @param[in,out] child 子writer。
 * @param[in] steps 全成立後の不足suffix。
 */
void storageBudget( LocalCollectorStateStore &parent, LocalCollectorStateStore &child,
				   const std::vector<Step> &steps)
{
	// 親／子それぞれに元5 GiBとentry枠を独立適用します。
	for( auto *store : {&parent, &child}) {
		CollectorStoreUsage usage ;	// 同handleの全通常file／staging実量です。
		io( store->inspectUsage( usage)) ;
		std::uint64_t pending{} ;	// 置換旧像も引かない保守的な追加量です。
		std::size_t	  current{} ;	// 全保存と一stagingの余裕を先払いします。
		std::size_t	  runs{} ;		// 保存予定のruns追加枠です。
		std::size_t	  largest{} ;	// 最大一stagingの実byteです。
		// 同じstoreへ書く有限stepだけを積算します。
		for( const auto &step : steps) {
			// 別storeの量を流用しません。
			if( step.store == store) {
				pending += step.raw.size() ;
				largest = std::max( largest, step.raw.size()) ;
				current += step.name.starts_with( L"current/") ? 1U : 0U ;
				runs += step.name.starts_with( L"runs/") ? 1U : 0U ;
			}
		}

		require( usage.bytes + pending + largest <= 5ULL * 1024U * 1024U * 1024U &&
					usage.currentEntries + current + 1U <= 4096U &&
					usage.runEntries + runs + 1U <= 4096U,
				ERROR_TOO_MANY_NAMES) ;
	}
}
/** @brief 確定後の全原像／現在値の二読込み必要量を計算します。
 * @param[in] b 保存する固定bundle。
 * @return Marker余裕込みの保守的な実raw予約量。
 */
std::uint64_t finalReadBudget( const Bundle &b)
{
	std::uint64_t total =
		// 両marker余裕です。
		b.intent.size() + b.base.size() + b.ready.size() + 4096U ;
	// 同じ66像を準備と現在値の二箇所から読む必要量です。
	for( const auto &image : b.images) {
		total += 2U * image.size() ;
	}

	return 2U * total ;
}
/** @brief Ready headから参照してよい固定intent keyだけを読みます。
 * @param[in] raw 専用envelopeの確定head。
 * @param[in] collection 同じ実親key。
 * @param[in] segment 同じ実子key。
 * @return 正規の初回intent hash。本文全結合は後続で再計算します。
 */
std::wstring readyIntent( const std::string_view raw, const std::wstring_view collection,
						 const std::wstring_view segment)
{
	const auto body = unpack( raw) ;	// 固定field順を別に全消費します。
	Reader	   r( body, 16U * 1024U) ;	// 任意headや未知fieldを許しません。
	r.literal( "{\"schema\":\"collector-collection-head-v1\",\"collection\":") ;
	const auto c = r.text( 64U) ;	// 親の元keyと比較します。
	require( std::wstring( c.begin(), c.end()) == collection) ;
	r.literal( ",\"segment\":") ;
	const auto s = r.text( 64U) ;	// 子の元keyと比較します。
	require( std::wstring( s.begin(), s.end()) == segment) ;
	r.literal( ",\"ordinal\":0,\"revision\":1,\"accepted\":") ;
	static_cast<void>( r.number()) ;
	r.literal( ",\"ledger\":") ;
	static_cast<void>( r.text( 64U)) ;
	r.literal( ",\"base\":") ;
	static_cast<void>( r.text( 64U)) ;
	r.literal( ",\"bootstrap\":") ;
	const auto key = r.text( 64U) ;	// Name生成の前に完全hashを検査します。
	r.literal( ",\"sealed\":[],\"commit\":null}") ;
	r.finish() ;
	std::wstring result( key.begin(), key.end()) ;	// 正規化しない元ASCIIです。
	require( collector_projected_json::isHash( result)) ;
	return result ;
}
/** @brief 初回または更新headの固定参照です。 */
struct UpdateHead {
	/// 元bootstrapの完全本文hash。
	std::wstring bootstrap ;
	/// 完了した区間操作数。0～64です。
	std::size_t	 count{} ;
	/// 未反映の唯一操作hash。確定では空です。
	std::wstring commit ;
} ;
/** @brief Hashと固定fieldを検査してheadの有限参照を読取ります。
 * @param[in] raw 元head envelope。
 * @param[in] collection 元親identity。
 * @param[in] segment 元子identity。
 * @return 初回または更新の有限参照。全値は再導出後にbyte照合します。
 */
UpdateHead updateHead( const std::string_view raw, const std::wstring_view collection,
					  const std::wstring_view segment)
{
	const auto body = unpack( raw) ;	// 自己申告hashだけでheadを受理しません。
	Reader	   r( body, 16U * 1024U) ;	// 未知schemaとfieldを完全拒否します。
	r.literal( "{\"schema\":") ;
	const auto schema  = r.text( 64U) ;									// 明示した二schemaだけです。
	const bool updated = schema == "collector-shared-update-head-v1" ;	// 初回schemaを別に保ちます。
	require( updated || schema == "collector-collection-head-v1") ;
	r.literal( ",\"collection\":") ;
	const auto c = r.text( 64U) ;	// 同じ親へ結合します。
	require( std::wstring( c.begin(), c.end()) == collection) ;
	r.literal( ",\"segment\":") ;
	const auto s = r.text( 64U) ;	// 同じ子へ結合します。
	require( std::wstring( s.begin(), s.end()) == segment) ;
	r.literal( ",\"ordinal\":0,\"revision\":") ;
	const auto revision = r.number() ;	// 縮小前に64操作の上限を検査します。
	require( revision >= 1U && revision <= 65U && (updated || revision == 1U)) ;
	r.literal( ",\"accepted\":") ;
	static_cast<void>( r.number()) ;
	r.literal( ",\"ledger\":") ;
	static_cast<void>( r.text( 64U)) ;
	r.literal( ",\"base\":") ;
	static_cast<void>( r.text( 64U)) ;
	r.literal( ",\"bootstrap\":") ;
	const auto key = r.text( 64U) ;	// Name生成前に完全hashを確認します。
	UpdateHead h{std::wstring( key.begin(), key.end()),
				 static_cast<std::size_t>( revision - 1U),
				 {}} ;	// 有限参照。
	require( collector_projected_json::isHash( h.bootstrap)) ;
	// 新headだけに最新の操作tipを必須とします。
	if( updated) {
		r.literal( ",\"tip\":") ;
		const auto tip = r.text( 64U) ;	// 後続の元操作再計算で全byteへ結合します。
		require( (h.count == 0U && tip.empty()) ||
				(h.count != 0U &&
				 collector_projected_json::isHash( std::wstring( tip.begin(), tip.end())))) ;
	}

	r.literal( ",\"sealed\":[],\"commit\":") ;
	const auto commit = r.value() ;	// Nullまたは唯一の完全hashです。
	// 未反映操作をreadyへ読み替えません。
	if( commit != "null") {
		Reader	   value( commit, 128U) ;		// 固定hash文字列だけを読みます。
		const auto hash = value.text( 64U) ;	// 小文字完全hashを検査します。
		value.finish() ;
		h.commit.assign( hash.begin(), hash.end()) ;
		require( updated && collector_projected_json::isHash( h.commit)) ;
	}

	r.literal( "}") ;
	r.finish() ;
	return h ;
}
/** @brief 単一有限区間の更新順から操作名を導出します。
 * @param[in] ordinal 0～63の区間操作index。
 * @return 子runsの固定名。
 */
std::wstring updateName( const std::size_t ordinal)
{
	require( ordinal < 64U, ERROR_TOO_MANY_NAMES) ;
	return L"runs/shared-update-" + hexOrdinal( ordinal) + L".json" ;
}
/** @brief 元bootstrapと再導出した最新状態の有限鎖です。 */
struct UpdateChain {
	/// 元初回像。更新後もbase／bootstrapを変えません。
	Bundle						  initial ;
	/// 操作を順に再導出した最新状態。
	CollectorSharedLedgerSnapshot snapshot ;
	/// 最新66像と台帳digest。ここで導出した初回baseは使いません。
	Bundle						  current ;
	/// 再導出した最新ready headの保存byte。
	std::string					  head ;
	/// 最新record本文hash。初回では空です。
	std::wstring				  tip ;
	/// 全再導出を終えた操作数。
	std::size_t					  count{} ;
} ;
/** @brief 元base／bootstrapを保った更新headを構成します。
 * @param[in] chain 元初回像。
 * @param[in] current 親へ反映する現在像。
 * @param[in] count 完了操作数。
 * @param[in] tip 最新完了操作hash。
 * @param[in] commit 唯一の未反映操作hash。確定では空です。
 * @return 固定新schemaのhead envelope。
 */
std::string updateHeadBytes( const UpdateChain &chain, const Bundle &current,
							const std::size_t count, const std::wstring_view tip,
							const std::wstring_view commit)
{
	Writer w( 16U * 1024U) ;	// 元headと同じ有限field集合です。
	w.append( "{\"schema\":\"collector-shared-update-head-v1\",\"collection\":") ;
	w.wideText( chain.initial.collection) ;
	w.append( ",\"segment\":") ;
	w.wideText( chain.initial.segment) ;
	w.append( ",\"ordinal\":0,\"revision\":") ;
	w.number( count + 1U) ;
	w.append( ",\"accepted\":") ;
	w.number( current.accepted) ;
	w.append( ",\"ledger\":") ;
	w.wideText( current.ledger) ;
	w.append( ",\"base\":") ;
	w.wideText( chain.initial.baseHash) ;
	w.append( ",\"bootstrap\":") ;
	w.wideText( chain.initial.intentHash) ;
	w.append( ",\"tip\":") ;
	w.wideText( tip) ;
	w.append( ",\"sealed\":[],\"commit\":") ;
	// 確定と未反映操作の参照を別状態として保存します。
	if( commit.empty()) {
		w.append( "null") ;
	} else {
		w.wideText( commit) ;
	}

	w.append( "}") ;
	return pack( w.view()) ;
}
/** @brief 一操作の意味再導出と固定保存像です。 */
struct UpdateImages {
	/// 元の四型操作を再導出した後の台帳。
	CollectorSharedLedgerSnapshot after ;
	/// 一操作反映後の66現在像。
	Bundle						  current ;
	/// 元head・操作・疎な前後像を結合する保存record。
	std::string					  record ;
	/// 元record本文hash。
	std::wstring				  key ;
	/// 旧台帳のまま唯一commitを登録したhead。
	std::string					  registered ;
	/// 全現在値の反映後だけ確定するhead。
	std::string					  ready ;
} ;
/** @brief 元操作と前の鎖から更新像を全て再導出します。
 * @param[in] chain 元の検査済み鎖。
 * @param[in] operation 元精算・新規予約・日次切替・未検証CACHE参照。
 * @return 元操作の疎な前後差分と全現在像。
 */
UpdateImages updateImages( const UpdateChain &chain, const CollectorSharedOperation &operation)
{
	require( chain.count < 64U, ERROR_TOO_MANY_NAMES) ;
	UpdateImages				  result ;	// 更新前の値をcallerから注入しません。
	CollectorSharedOperationDelta delta ;	// 元操作から再計算した疎な前後像です。
	// 未検証CACHE参照の置換先は同じ現区間に限ります。
	if( const auto *cache = std::get_if<CollectorSharedCacheUpdate>( &operation)) {
		require( cache->next.segment == chain.initial.segment) ;
	}

	io( deriveCollectorSharedOperation( chain.snapshot, operation, result.after, delta)) ;
	result.current = prepare( result.after, chain.initial.segment) ;
	Writer	   w( 768U * 1024U) ;	// 疎な予算・二制御行・CACHE差分だけを保持します。
	const bool legacy =
		std::holds_alternative<CollectorSharedSettlement>( operation) ;	// 元v1を維持します。
	w.append( legacy ? "{\"schema\":\"collector-shared-update-v1\",\"collection\":"
					: "{\"schema\":\"collector-shared-update-v2\",\"collection\":") ;
	w.wideText( chain.initial.collection) ;
	w.append( ",\"segment\":") ;
	w.wideText( chain.initial.segment) ;
	w.append( ",\"ordinal\":") ;
	w.number( chain.count + 1U) ;
	w.append( ",\"previousHead\":") ;
	w.wideText( digest( unpack( chain.head))) ;
	w.append( ",\"beforeLedger\":") ;
	w.wideText( chain.current.ledger) ;
	w.append( ",\"afterLedger\":") ;
	w.wideText( result.current.ledger) ;
	w.append( ",\"operation\":") ;
	w.append( delta.operation) ;
	w.append( ",\"budgetBefore\":") ;
	w.text( delta.budgetBefore) ;
	w.append( ",\"budgetAfter\":") ;
	w.text( delta.budgetAfter) ;
	w.append( ",\"waitBefore\":") ;
	w.text( delta.waitBefore) ;
	w.append( ",\"waitAfter\":") ;
	w.text( delta.waitAfter) ;
	// 追加三操作だけ新schemaへ疎な参照前後像を保存します。
	if( !legacy) {
		w.append( ",\"cacheBefore\":") ;
		w.text( delta.cacheBefore) ;
		w.append( ",\"cacheAfter\":") ;
		w.text( delta.cacheAfter) ;
	}

	w.append( "}") ;
	result.key		  = digest( w.view()) ;
	result.record	  = pack( w.view()) ;
	result.registered = updateHeadBytes( chain, chain.current, chain.count, chain.tip, result.key) ;
	result.ready	  = updateHeadBytes( chain, result.current, chain.count + 1U, result.key, {}) ;
	return result ;
}
/** @brief 保存recordの全固定fieldを消費して元操作だけを復号します。
 * @param[in] raw 元record envelope。
 * @return 型付き元操作。前後像・identityは再導出したrecordとの全byte照合が必須です。
 */
CollectorSharedOperation recordOperation( const std::string_view raw)
{
	const auto body = unpack( raw) ;	// 保存原byteのCNG hashを先に検査します。
	Reader	   r( body, 768U * 1024U) ;	// 任意fieldを無視して残しません。
	const bool legacy =
		// 原schemaです。
		body.starts_with( "{\"schema\":\"collector-shared-update-v1\"") ;
	r.literal( legacy ? "{\"schema\":\"collector-shared-update-v1\",\"collection\":"
					 : "{\"schema\":\"collector-shared-update-v2\",\"collection\":") ;
	static_cast<void>( r.text( 64U)) ;
	r.literal( ",\"segment\":") ;
	static_cast<void>( r.text( 64U)) ;
	r.literal( ",\"ordinal\":") ;
	static_cast<void>( r.number()) ;
	r.literal( ",\"previousHead\":") ;
	static_cast<void>( r.text( 64U)) ;
	r.literal( ",\"beforeLedger\":") ;
	static_cast<void>( r.text( 64U)) ;
	r.literal( ",\"afterLedger\":") ;
	static_cast<void>( r.text( 64U)) ;
	r.literal( ",\"operation\":") ;
	CollectorSharedOperation operation ;	// 全fieldを読んだ後だけ返します。
	io( decodeCollectorSharedOperation( r.value(), operation)) ;
	require( legacy == std::holds_alternative<CollectorSharedSettlement>( operation)) ;
	r.literal( ",\"budgetBefore\":") ;
	static_cast<void>( r.text( 4096U)) ;
	r.literal( ",\"budgetAfter\":") ;
	static_cast<void>( r.text( 4096U)) ;
	r.literal( ",\"waitBefore\":") ;
	static_cast<void>( r.text( 8192U)) ;
	r.literal( ",\"waitAfter\":") ;
	static_cast<void>( r.text( 8192U)) ;
	// v1へ追加fieldを補完せずv2の全fieldだけ読みます。
	if( !legacy) {
		r.literal( ",\"cacheBefore\":") ;
		static_cast<void>( r.text( 1024U)) ;
		r.literal( ",\"cacheAfter\":") ;
		static_cast<void>( r.text( 1024U)) ;
	}

	r.literal( "}") ;
	r.finish() ;
	return operation ;
}
/** @brief 元bootstrapの全原像から初回鎖を再構成します。
 * @param[in,out] child 同じ親能力の子store。
 * @param[in] key 元bootstrap hash。
 * @param[in] collection 同じ親identity。
 * @param[in,out] history 選択区間の有限原byte読取り。
 * @return 全原像に一致する元初回鎖。
 */
UpdateChain initialChain( LocalCollectorStateStore &child, const std::wstring_view key,
						 const std::wstring_view collection, ReadSet &history)
{
	CollectorSharedLedgerBytes bytes ;	// 全66原像を同じcodecへ渡します。
	// 固定bootstrap準備像を一度ずつ読みます。
	for( std::size_t i = 0U; i < 66U; ++i) {
		const auto raw = history.get( child, preparedName( key, i)) ;	// 元ordinal像です。
		require( raw.has_value()) ;
		const auto body = unpack( *raw) ;	// 元本文hashを検査します。
		// 二先頭roleとrequest shardを混同しません。
		if( i < 2U) {
			(i == 0U ? bytes.budget : bytes.groups) = body ;
		} else {
			bytes.requests[i - 2U] = body ;
		}
	}

	UpdateChain chain ;	// 初回値からだけ後続操作を再生します。
	io( decodeCollectorSharedLedger( bytes, chain.snapshot)) ;
	require( chain.snapshot.collection == collection) ;
	chain.initial = prepare( chain.snapshot, child.root().filename().native()) ;
	require( chain.initial.intentHash == key &&
			history.get( child, intentName( key)) == chain.initial.intent &&
			history.get( child, BASE) == chain.initial.base) ;
	chain.current = chain.initial ;
	chain.head	  = chain.initial.ready ;
	return chain ;
}
/** @brief 全登録操作を順に再導出して固定鎖へ結合します。
 * @param[in,out] child 元区間store。
 * @param[in,out] chain 初回から再生する鎖。
 * @param[in] count 検査する完了操作数。
 * @param[in,out] history 元byteと最終再照合。
 */
void replayUpdates( LocalCollectorStateStore &child, UpdateChain &chain, const std::size_t count,
				   ReadSet &history)
{
	// 最大64操作をordinal順に一回ずつ再導出します。
	for( std::size_t i = 0U; i < count; ++i) {
		const auto raw = history.get( child, updateName( i)) ;	// 欠損履歴は元予約へ戻しません。
		require( raw.has_value()) ;
		auto update =
			// 期待値を保存自己申告から作りません。
			updateImages( chain, recordOperation( *raw)) ;
		require( *raw == update.record) ;
		chain.snapshot = std::move( update.after) ;
		chain.current  = std::move( update.current) ;
		chain.head	   = std::move( update.ready) ;
		chain.tip	   = std::move( update.key) ;
		++chain.count ;
	}
}
/** @brief 初回原像と登録済みの有限操作名だけを許可します。
 * @param[in,out] parent 親store。
 * @param[in,out] child 元区間store。
 * @param[in] b 元初回bundle。
 * @param[in] operations 存在し得る完了／未反映操作数。
 * @param[in] extra 私有回復だけの親runs／子current／子runs追加名です。通常は空です。
 */
void updateShape( LocalCollectorStateStore &parent, LocalCollectorStateStore &child, const Bundle &b,
				 const std::size_t							   operations,
				 const std::array<std::set<std::wstring>, 3U> &extra = {})
{
	std::set<std::wstring> current{L"collector-campaign-mode-v1.json",
								   L"collection-head-v1.json"} ;	// 親固定名。
	std::set<std::wstring> runs{
		// 元一intent。
		std::filesystem::path( intentName( b.intentHash)).filename().native()} ;
	// 初回66像は現在値と元準備で両方保持します。
	for( std::size_t i = 0U; i < 66U; ++i) {
		current.insert( std::filesystem::path( currentName( i)).filename().native()) ;
		runs.insert( std::filesystem::path( preparedName( b.intentHash, i)).filename().native()) ;
	}

	// 登録序数からだけ固定名を導出します。
	for( std::size_t i = 0U; i < operations; ++i) {
		runs.insert( std::filesystem::path( updateName( i)).filename().native()) ;
	}

	runs.insert( extra[2].begin(), extra[2].end()) ;
	std::set<std::wstring> childCurrent{
		L"collector-campaign-mode-v1.json",
		L"segment-shared-base-v1.json"} ;	// 私有回復だけの追加currentを元固定集合へ限定します。
	childCurrent.insert( extra[1].begin(), extra[1].end()) ;
	names( parent, current, extra[0]) ;
	names( child, childCurrent, runs) ;
}
/** @brief 元before／after連続prefixから不足更新だけを計画します。
 * @param[in,out] parent 親writer。
 * @param[in,out] child 元区間writer。
 * @param[in] chain 元before鎖。
 * @param[in] update 元操作から導出した更新像。
 * @param[in,out] current 親currentの16 MiB観測。
 * @param[in,out] history 元区間の64 MiB観測。
 * @return 保存前に完全照合した元ordinalの不足手順。
 */
std::vector<Step> updatePlan( LocalCollectorStateStore &parent, LocalCollectorStateStore &child,
							 const UpdateChain &chain, const UpdateImages &update, ReadSet &current,
							 ReadSet &history)
{
	updateShape( parent, child, chain.initial, chain.count + 1U) ;
	const auto name	  = updateName( chain.count) ;	// 元次ordinalだけを操作候補にします。
	const auto record = history.get( child, name) ;	// 登録前の孤立候補も同じ元操作へ結合します。
	require( !record || *record == update.record) ;
	const auto head = current.get( parent, HEAD) ;	// 元・登録・確定だけを許可します。
	require( head.has_value()) ;
	const bool registered = *head == update.registered ;	// 元ledgerを保つ一intentです。
	const bool ready	  = *head == update.ready ;			// 全反映後だけのheadです。
	require( *head == chain.head || registered || ready) ;
	require( (!registered && !ready) || record.has_value()) ;
	std::vector<Step> steps ;	// 全role検査後だけ書込みます。
	// 元操作を現在値より先に永続化します。
	if( !record) {
		steps.push_back( {&child, name, update.record, 1U}) ;
	}

	// 元headが未登録なら同じ一intentへ固定します。
	if( !registered && !ready) {
		steps.push_back( {&parent, HEAD, update.registered, 2U}) ;
	}

	bool		gap{} ;		// After prefixの後にbefore suffixだけを認めます。
	std::size_t changed{} ;	// 元変更role数にordinalを結合します。
	// 全66現在像を検査し、変更roleだけを元順序に適用します。
	for( std::size_t i = 0U; i < 66U; ++i) {
		const auto raw = current.get( parent, currentName( i)) ;	// 欠損を初回作成へ戻しません。
		require( raw.has_value()) ;
		// 非変更roleも原byte完全一致が必須です。
		if( chain.current.images[i] == update.current.images[i]) {
			require( *raw == chain.current.images[i]) ;
			continue ;
		}

		++changed ;
		// 元afterは登録済みの連続prefixだけに許可します。
		if( *raw == update.current.images[i]) {
			require( (registered || ready) && !gap) ;
		} else {
			require( !ready && *raw == chain.current.images[i]) ;
			gap = true ;
			steps.push_back( {&parent, currentName( i), update.current.images[i], changed + 2U}) ;
		}
	}

	// 全反映後だけ新headを確定します。
	if( !ready) {
		steps.push_back( {&parent, HEAD, update.ready, changed + 3U}) ;
	}

	return steps ;
}
/** @brief 中断後の最大再検査を現在／履歴の別固定枠へ先払いします。
 * @param[in] chain 元before鎖。
 * @param[in] update 変更後像。
 * @param[in] history 原履歴観測。
 * @param[in] child 元区間store。
 */
void updateReadBudget( const UpdateChain &chain, const UpdateImages &update, const ReadSet &history,
					  const LocalCollectorStateStore &child)
{
	std::uint64_t shared =
		std::max( {chain.head.size(), update.registered.size(), update.ready.size()}) +
		4096U ;	// Marker余裕。
	// 元／更新像の大きい方を再開と最終の各二読取りへ含めます。
	for( std::size_t i = 0U; i < 66U; ++i) {
		shared += std::max( chain.current.images[i].size(), update.current.images[i].size()) ;
	}

	require( 4U * shared + 4096U <= RAW_LIMIT, ERROR_TOO_MANY_NAMES) ;
	std::uint64_t total = update.record.size() ;		// 不足recordも保存前に予算へ含めます。
	const auto	  name	= updateName( chain.count) ;	// 候補は一度だけ加算します。
	// 原履歴を最大四読取りとして保守的に確保します。
	for( const auto &file : history.files) {
		// 自身の一候補は先に加算した同じ更新原像だけです。
		if( file.raw && !(file.store == &child && file.name == name)) {
			total += file.raw->size() ;
		}
	}

	require( 4U * total <= 64U * 1024U * 1024U, ERROR_TOO_MANY_NAMES) ;
}
/** @brief 更新経路の両mode原byteを固定schemaへ再照合します。
 * @param[in,out] parent 親store。
 * @param[in,out] child 元区間store。
 * @param[in,out] current 共通16 MiBの原byte観測。
 * @param[in] withHistory 同親leaseの専用history能力が存在する場合true。
 */
void updateMarkers( LocalCollectorStateStore &parent, LocalCollectorStateStore &child,
				   ReadSet &current, const bool withHistory)
{
	Writer p( 4096U) ;	// 私有能力と同じ固定親markerです。
	p.append(
		"{\"schema\":\"collector-collection-store-v1\",\"mode\":\"SEGMENTED_METADATA_V1\",\"collection\":") ;
	p.wideText( parent.root().filename().native()) ;
	p.append( "}") ;
	Writer c( 4096U) ;	// 同じ唯一子の固定markerです。
	c.append( withHistory ? "{\"schema\":\"collector-segment-history-store-v1\",\"collection\":"
						 : "{\"schema\":\"collector-segment-store-v1\",\"collection\":") ;
	c.wideText( parent.root().filename().native()) ;
	c.append( ",\"segment\":") ;
	c.wideText( child.root().filename().native()) ;
	// 能力に結合した固定配置だけを照合し、相手schemaへfallbackしません。
	if( withHistory) {
		c.append( ",\"history\":\"history\"") ;
	}

	c.append( "}") ;
	require( current.get( parent, MODE) == p.view() && current.get( child, MODE) == c.view()) ;
}
/** @brief 更新済みready headから全登録操作と現在値を非変更で再検査します。
 * @param[in,out] parent 親store。
 * @param[in,out] child 元区間store。
 * @param[in] head 元ready head。
 * @param[in,out] current 親現在値の原byte観測。
 * @param[in] withHistory 同親leaseのhistory能力に一致したmarker選択です。
 * @return 全検査後だけの現在台帳。
 */
CollectorSharedLedgerSnapshot loadUpdates( LocalCollectorStateStore &parent,
										  LocalCollectorStateStore &child, const std::string &head,
										  ReadSet &current, const bool withHistory)
{
	const auto h = updateHead( head, parent.root().filename().native(),
							  // 有限参照。
							  child.root().filename().native()) ;
	require( h.commit.empty() && h.count != 0U) ;
	updateMarkers( parent, child, current, withHistory) ;
	std::uint64_t remaining = 64U * 1024U * 1024U ;	// 選択区間だけの元履歴枠です。
	ReadSet		  history{remaining, {}} ;			// 現在16 MiBと混在させません。
	auto		  chain = initialChain( child, h.bootstrap, parent.root().filename().native(),
									   history) ;	// 元初回鎖です。
	replayUpdates( child, chain, h.count, history) ;
	require( head == chain.head) ;
	updateShape( parent, child, chain.initial, chain.count) ;
	// 最新の全66現在像を元操作再導出へ結合します。
	for( std::size_t i = 0U; i < 66U; ++i) {
		require( current.get( parent, currentName( i)) == chain.current.images[i]) ;
	}

	current.recheck() ;
	history.recheck() ;
	updateShape( parent, child, chain.initial, chain.count) ;
	return std::move( chain.snapshot) ;
}
/** @brief 全存在名を意味検査済みの原byteへ結合します。
 * @param[in,out] parent 同親の保護store。
 * @param[in,out] child 選択した子leaseのstore。
 * @param[in] current 親現在像と両markerの読取り集合。
 * @param[in] history 元bootstrap／区間操作の読取り集合。
 * @param[in] chain 全操作から再導出した閉鎖鎖。
 * @param[in] utcMillis 元時計を変更しない検査UTC。
 * @param[in] skipped 私有回復の固定追加roleです。通常は空です。
 * @return 固定inventory／sealを持つ共有側だけの根拠。
 */
CollectorSharedRootEvidence sharedEvidence(
	LocalCollectorStateStore &parent, LocalCollectorStateStore &child, const ReadSet &current,
	const ReadSet &history, const UpdateChain &chain, const std::uint64_t utcMillis,
	const std::array<std::set<std::wstring>, 2U> &skipped = {})
{
	CollectorSharedRootEvidence evidence ;	// 全nameとrawが揃うまで外へ公開しません。
	evidence.snapshot			= chain.snapshot ;
	evidence.segment			= child.root().filename().native() ;
	evidence.headSha256			= digest( unpack( chain.head)) ;
	evidence.ledger				= chain.current.ledger ;
	evidence.inspectedUtcMillis = utcMillis ;
	evidence.operations			= chain.count ;
	// 親current／runs、子current／runsの元列挙順を維持します。
	for( const bool isParent : {true, false}) {
		auto &store = isParent ? parent : child ;	// 同親の二store以外を参照しません。
		std::vector<std::wstring> cn ;				// 保護handleで検査したcurrent名です。
		std::vector<std::wstring> rn ;				// 保護handleで検査したruns名です。
		io( store.listCurrentNames( cn)) ;
		io( store.listRunNames( rn)) ;
		// 既知名のsemantic読取りに存在した全rawだけを登録します。
		for( const bool isCurrent : {true, false}) {
			const auto &names = isCurrent ? cn : rn ;	// 任意JSONの名前は使いません。
			// 各保護列挙順の一名を実検査済みbyteへ結合します。
			for( const auto &name : names) {
				const auto relative =
					(isCurrent ? L"current/" : L"runs/") + name ;	// 固定role相対名。
				// 私有回復の追加roleは後続の完全byte照合へ分離します。
				if( skipped[isParent ? 0U : 1U].contains( relative)) {
					continue ;
				}

				const Tracked *matched{} ;	// 両集合で重複する証拠も拒否します。
				// 意味検査で使った二つの有限集合だけを探索します。
				for( const auto *set : {&current, &history}) {
					// Callerのhashを採用せず読取り集合の原像へ結合します。
					for( const auto &file : set->files) {
						// 同一store／同一固定名を一度だけ採用します。
						if( file.store == &store && file.name == relative) {
							require( !matched && file.raw.has_value()) ;
							matched = &file ;
						}
					}
				}

				require( matched && evidence.files.size() < 256U,
						matched ? ERROR_TOO_MANY_NAMES : ERROR_INVALID_DATA) ;
				const auto size =
					// 実rawの元sizeです。
					static_cast<std::uint64_t>( matched->raw->size()) ;
				evidence.fileBytes += size ;
				evidence.files.push_back( {isParent, relative, digest( *matched->raw), size}) ;
			}
		}
	}

	std::size_t present{} ;	// 列挙で落ちたsemantic参照も成功にしません。
	// 全semantic存在参照が一回だけinventoryへ載ることを確認します。
	for( const auto *set : {&current, &history}) {
		// 不在はinventoryへ含めませんが最終再照合では維持します。
		for( const auto &file : set->files) {
			present += file.raw.has_value() ? 1U : 0U ;
		}
	}

	require( present == evidence.files.size()) ;
	Writer inventory( 256U * 1024U) ;	// 固定256行以内の有限本文です。
	inventory.append( "{\"schema\":\"collector-shared-root-inventory-v1\",\"collection\":") ;
	inventory.wideText( evidence.snapshot.collection) ;
	inventory.append( ",\"segment\":") ;
	inventory.wideText( evidence.segment) ;
	inventory.append( ",\"head\":") ;
	inventory.wideText( evidence.headSha256) ;
	inventory.append( ",\"fileCount\":") ;
	inventory.number( evidence.files.size()) ;
	inventory.append( ",\"files\":[") ;
	// 全存在rawのscopeと固定順を本文へ結合します。
	for( std::size_t i = 0U; i < evidence.files.size(); ++i) {
		const auto &file = evidence.files[i] ;	// 元列挙ordinalの一行です。
		// 先頭以外だけJSON separatorを追加します。
		if( i != 0U) {
			inventory.append( ",") ;
		}

		inventory.append( "{\"scope\":") ;
		inventory.text( file.parent ? "parent" : "segment") ;
		inventory.append( ",\"name\":") ;
		inventory.wideText( file.name) ;
		inventory.append( ",\"bytes\":") ;
		inventory.number( file.bytes) ;
		inventory.append( ",\"sha256\":") ;
		inventory.wideText( file.sha256) ;
		inventory.append( "}") ;
	}

	inventory.append( "]}") ;
	evidence.inventory		 = inventory.take() ;
	evidence.inventorySha256 = digest( evidence.inventory) ;
	Writer seal( 16U * 1024U) ;	// ROOT／CACHE内容を証明しない共有側の固定fieldです。
	seal.append( "{\"schema\":\"collector-shared-root-seal-v1\",\"collection\":") ;
	seal.wideText( evidence.snapshot.collection) ;
	seal.append( ",\"segment\":") ;
	seal.wideText( evidence.segment) ;
	seal.append( ",\"head\":") ;
	seal.wideText( evidence.headSha256) ;
	seal.append( ",\"ledger\":") ;
	seal.wideText( evidence.ledger) ;
	seal.append( ",\"rootUtc\":") ;
	seal.number( evidence.snapshot.lastUtcMillis) ;
	seal.append( ",\"inspectedUtc\":") ;
	seal.number( utcMillis) ;
	seal.append( ",\"operations\":") ;
	seal.number( evidence.operations) ;
	seal.append( ",\"fileCount\":") ;
	seal.number( evidence.files.size()) ;
	seal.append( ",\"fileBytes\":") ;
	seal.number( evidence.fileBytes) ;
	seal.append( ",\"inventory\":") ;
	seal.wideText( evidence.inventorySha256) ;
	seal.append( "}") ;
	evidence.seal		= seal.take() ;
	evidence.sealSha256 = digest( evidence.seal) ;
	return evidence ;
}
} // namespace

/** @see local_collector_shared_store.h */
DWORD LocalCollectorSharedStore::bootstrap( LocalCollectorCollectionStore	   &collection,
										   LocalCollectorSegmentLease		   &segment,
										   const CollectorSharedLedgerSnapshot &snapshot,
										   const CollectorSharedCheckpoint	   &checkpoint) noexcept
{
	try {
		std::uint64_t			  remaining = RAW_LIMIT ;	// 能力照合から最終readまで同じ予算です。
		LocalCollectorStateStore *parent{} ;				// 同じleaseの親だけを借用します。
		io( collection.sharedParent( segment, parent, remaining)) ;
		const auto release = []( LocalCollectorCollectionStore *owner) {
			owner->releaseSharedParent() ;
		} ; // 全終了で再入禁止を解除します。
		const std::unique_ptr<LocalCollectorCollectionStore, decltype( release)> guard(
			&collection, release) ;	// Wrapperを削除しない借用RAIIです。
		require( snapshot.collection == parent->root().filename().native()) ;
		const auto b = prepare(
			snapshot, segment.store().root().filename().native()) ;	// 全像は元値からだけ導出します。
		// 初回も中断後の最大前検査と最終readを同じraw枠内に確保します。
		require( finalReadBudget( b) <= (RAW_LIMIT - 4096U) / 2U, ERROR_TOO_MANY_NAMES) ;
		ReadSet	   reads{remaining, {}} ;	// 書込み前の全名前／byteを保持します。
		const auto steps =
			// 全不成立を保存前に確認します。
			plan( *parent, segment.store(), b, reads) ;
		reads.recheck() ;
		shape( *parent, segment.store(), b) ;
		storageBudget( *parent, segment.store(), steps) ;
		// 成功後の全原像再照合も保存前に有限予約します。
		if( !steps.empty()) {
			require( finalReadBudget( b) <= remaining, ERROR_TOO_MANY_NAMES) ;
		}

		// 固定prefixの不足suffixだけを元ordinalで反映します。
		for( const auto &step : steps) {
			io( step.store->write( step.name, step.raw)) ;
			// 診断停止は実atomic置換後だけに適用します。
			if( checkpoint) {
				io( checkpoint( step.ordinal)) ;
			}
		}

		// 新しい実file観測から確定headと全像を再検査します。
		if( !steps.empty()) {
			ReadSet finalReads{remaining, {}} ;	// 保存前の欠損観測を再利用しません。
			require( plan( *parent, segment.store(), b, finalReads).empty()) ;
			finalReads.recheck() ;
			shape( *parent, segment.store(), b) ;
		}

		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		return code ;
	} catch( const Failure failure) {
		return failure.status == Status::SIZE_LIMIT ? ERROR_TOO_MANY_NAMES : ERROR_INVALID_DATA ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}
/** @see local_collector_shared_store.h */
DWORD LocalCollectorSharedStore::settle( LocalCollectorCollectionStore	&collection,
										LocalCollectorSegmentLease		&segment,
										const CollectorSharedSettlement &operation,
										const CollectorSharedCheckpoint &checkpoint) noexcept
{
	try {
		return commit( collection, segment, CollectorSharedOperation{operation}, checkpoint) ;
	} catch( const std::bad_alloc &) {
		return 8U ;
	} catch( ...) {
		return 13U ;
	}
}
/** @see local_collector_shared_store.h */
DWORD LocalCollectorSharedStore::commit( LocalCollectorCollectionStore	&collection,
										LocalCollectorSegmentLease		&segment,
										const CollectorSharedOperation	&operation,
										const CollectorSharedCheckpoint &checkpoint) noexcept
{
	try {
		std::uint64_t			  remaining = RAW_LIMIT ;	// 能力照合から最終現在像まで同じ枠です。
		LocalCollectorStateStore *parent{} ;				// 同じ親のwriterだけを借用します。
		io( collection.sharedParent( segment, parent, remaining)) ;
		const auto release = []( LocalCollectorCollectionStore *owner) {
			owner->releaseSharedParent() ;
		} ; // 全終了で借用解除。
		const std::unique_ptr<LocalCollectorCollectionStore, decltype( release)> guard(
			&collection, release) ;			// Wrapperは削除しません。
		ReadSet current{remaining, {}} ;	// 親現在値と両markerだけです。
		updateMarkers( *parent, segment.store(), current, segment.history() != nullptr) ;
		const auto head = current.get( *parent, HEAD) ;	// 初回確定なしに通常更新しません。
		require( head.has_value()) ;
		const auto	  h				   = updateHead( *head, parent->root().filename().native(),
													// 有限参照。
													segment.store().root().filename().native()) ;
		std::uint64_t historyRemaining = 64U * 1024U * 1024U ;	// 元区間の履歴専用枠です。
		ReadSet		  history{historyRemaining, {}} ;			// 全登録操作を一度ずつ保持します。
		std::string	  encoded ;									// 元操作との完全一致を再試行でも維持します。
		io( encodeCollectorSharedOperation( operation, encoded)) ;
		std::size_t count = h.count ;	// 既に確定した末尾と同じ操作なら非変更再検査です。
		// 確定済みの同じ末尾操作だけは二重精算せず再照合します。
		if( h.commit.empty() && count != 0U) {
			const auto last =
				// 必須元末尾record。
				history.get( segment.store(), updateName( count - 1U)) ;
			require( last.has_value()) ;
			std::string lastOperation ;	// 正規形式を完全復号してから比較します。
			io( encodeCollectorSharedOperation( recordOperation( *last), lastOperation)) ;
			// 同じ元操作の再開を新しい予約精算へ置換しません。
			if( lastOperation == encoded) {
				--count ;
			}
		}

		auto chain = initialChain( segment.store(), h.bootstrap, parent->root().filename().native(),
								  history) ;	// 元初回値。
		replayUpdates( segment.store(), chain, count, history) ;
		auto	   update = updateImages( chain, operation) ;	// 元予約／待機からだけ導出します。
		const auto steps  = updatePlan( *parent, segment.store(), chain, update, current,
									   history) ;	// 全拒否は保存前です。
		current.recheck() ;
		history.recheck() ;
		updateShape( *parent, segment.store(), chain.initial, chain.count + 1U) ;
		updateReadBudget( chain, update, history, segment.store()) ;
		storageBudget( *parent, segment.store(), steps) ;
		// 元操作と登録headを先行し、不足suffixだけ元ordinalで保存します。
		for( const auto &step : steps) {
			io( step.store->write( step.name, step.raw)) ;
			// 実atomic保存直後の元停止だけを返します。
			if( checkpoint) {
				io( checkpoint( step.ordinal)) ;
			}
		}

		// 追加保存があった場合は新handleの全現在像と元recordを照合します。
		if( !steps.empty()) {
			ReadSet finalCurrent{remaining, {}} ;	// 更新前観測を現在値へ流用しません。
			updateMarkers( *parent, segment.store(), finalCurrent, segment.history() != nullptr) ;
			require( finalCurrent.get( *parent, HEAD) == update.ready) ;
			// 全66現在値が同じ一操作のafterへ一致した後だけ成功します。
			for( std::size_t i = 0U; i < 66U; ++i) {
				require( finalCurrent.get( *parent, currentName( i)) == update.current.images[i]) ;
			}

			ReadSet finalRecord{historyRemaining, {}} ;		// 元一recordを欠損観測から再利用しません。
			const auto name = updateName( chain.count) ;	// 自身が保存した唯一recordです。
			require( finalRecord.get( segment.store(), name) == update.record) ;
			finalCurrent.recheck() ;
			finalRecord.recheck() ;
			history.recheck( &segment.store(), name) ;
			updateShape( *parent, segment.store(), chain.initial, chain.count + 1U) ;
		}

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

/** @see local_collector_shared_store.h */
DWORD LocalCollectorSharedStore::load( LocalCollectorCollectionStore &collection,
									  LocalCollectorSegmentLease	&segment,
									  CollectorSharedLedgerSnapshot &snapshot) noexcept
{
	snapshot = {} ;
	try {
		std::uint64_t			  remaining = RAW_LIMIT ;	// Ready全閉包を再読込みする共通予算です。
		LocalCollectorStateStore *parent{} ;				// 成功した同一能力だけを借用します。
		io( collection.sharedParent( segment, parent, remaining)) ;
		const auto release = []( LocalCollectorCollectionStore *owner) {
			owner->releaseSharedParent() ;
		} ; // 失敗時も借用だけを解除します。
		const std::unique_ptr<LocalCollectorCollectionStore, decltype( release)> guard(
			&collection, release) ;						// Wrapper非所有のRAIIです。
		ReadSet	   reads{remaining, {}} ;				// 欠損・原byte・最終照合を保持します。
		const auto head = reads.get( *parent, HEAD) ;	// 未完了を初回成功へ戻しません。
		require( head.has_value()) ;
		// 明示した新schemaだけを通常精算の再導出readerへ渡します。
		if( unpack( *head).starts_with( "{\"schema\":\"collector-shared-update-head-v1\",")) {
			snapshot =
				loadUpdates( *parent, segment.store(), *head, reads, segment.history() != nullptr) ;
			return 0U ;
		}

		const auto segmentKey = segment.store().root().filename().native() ;	// 実子identityです。
		const auto key		  = readyIntent( *head, parent->root().filename().native(),
											segmentKey) ;	// 固定名の唯一intent。
		CollectorSharedLedgerBytes bytes ;					// 全準備像を意味codecへ戻します。
		// 固定66 fileの欠損・原hashを独立に検査します。
		for( std::size_t i = 0U; i < 66U; ++i) {
			const auto raw = reads.get( segment.store(), preparedName( key, i)) ;	// 元初回像です。
			require( raw.has_value()) ;
			const auto body = unpack( *raw) ;	// Hash確認後も意味codecは省略しません。
			// 元codecの二先頭roleとrequest shardへ再結合します。
			if( i < 2U) {
				(i == 0U ? bytes.budget : bytes.groups) = body ;
			} else {
				bytes.requests[i - 2U] = body ;
			}
		}

		CollectorSharedLedgerSnapshot pending ;	// 全検査後だけ公開する元値です。
		io( decodeCollectorSharedLedger( bytes, pending)) ;
		require( pending.collection == parent->root().filename().native()) ;
		const auto b = prepare( pending, segmentKey) ;	// 保存自己申告からではなく型から再導出します。
		require( b.intentHash == key && *head == b.ready &&
				plan( *parent, segment.store(), b, reads).empty()) ;
		reads.recheck() ;
		shape( *parent, segment.store(), b) ;
		snapshot = std::move( pending) ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		return code ;
	} catch( const Failure failure) {
		return failure.status == Status::SIZE_LIMIT ? ERROR_TOO_MANY_NAMES : ERROR_INVALID_DATA ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}
/** @see local_collector_shared_store.h */
DWORD LocalCollectorSharedStore::inspectSharedRootInventory(
	LocalCollectorCollectionStore &collection, LocalCollectorSegmentLease &segment,
	const std::uint64_t utcMillis, std::shared_ptr<const CollectorSharedRootInventory> &inventory,
	const std::function<DWORD()> &beforeFinalRecheck) noexcept
{
	try {
		// 公開診断は未公開根拠を受け取らず、従来と同じ順序で数値だけを返します。
		const std::function<DWORD( const CollectorSharedRootEvidence &)> before =
			[&beforeFinalRecheck]( const CollectorSharedRootEvidence &) {
				return beforeFinalRecheck ? beforeFinalRecheck() : ERROR_SUCCESS ;
			} ; // 診断参照はこの同期呼出し中だけ有効です。
		return inspectSharedRootInventoryBound( collection, segment, utcMillis, inventory, before,
											   {}) ;
	} catch( const std::bad_alloc &) {
		inventory.reset() ;
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		inventory.reset() ;
		return ERROR_INVALID_DATA ;
	}
}
/** @see local_collector_shared_store.h */
DWORD LocalCollectorSharedStore::inspectSharedRootInventoryBound(
	LocalCollectorCollectionStore &collection, LocalCollectorSegmentLease &segment,
	const std::uint64_t utcMillis, std::shared_ptr<const CollectorSharedRootInventory> &inventory,
	const std::function<DWORD( const CollectorSharedRootEvidence &)> &beforeFinalRecheck,
	const std::function<DWORD()>									&afterFinalRecheck) noexcept
{
	inventory.reset() ;
	try {
		std::uint64_t remaining = RAW_LIMIT ;	// 親能力と最終照合の同じ16 MiB先払い枠です。
		LocalCollectorStateStore *parent{} ;	// Callerの別rootを採用しません。
		io( collection.sharedParent( segment, parent, remaining)) ;
		const auto releaseParent = []( LocalCollectorCollectionStore *owner) {
			owner->releaseSharedParent() ;
		} ; // 全終端で親の共有再入を解除します。
		const std::unique_ptr<LocalCollectorCollectionStore, decltype( releaseParent)> parentGuard(
			&collection, releaseParent) ;	// 親writer自体は破棄しないRAIIです。
		std::byte borrower{} ;				// 同期検査中だけ有効な監督能力です。
		io( segment.store().borrowCampaign( &borrower)) ;
		const auto releaseChild = [&borrower]( LocalCollectorStateStore *owner) {
			owner->releaseCampaign( &borrower) ;
		} ; // 親より先に子の監督借用を返却します。
		const std::unique_ptr<LocalCollectorStateStore, decltype( releaseChild)> childGuard(
			&segment.store(), releaseChild) ;	// Storeの実所有は元leaseに残します。
		ReadSet current{remaining, {}} ;		// 両marker／head／全66現在像です。
		updateMarkers( *parent, segment.store(), current, segment.history() != nullptr) ;
		const auto head = current.get( *parent, HEAD) ;	// 未登録やactive commitを回復しません。
		require( head.has_value()) ;
		const auto h = updateHead( *head, parent->root().filename().native(),
								  // 同親の有限参照です。
								  segment.store().root().filename().native()) ;
		require( h.commit.empty()) ;
		std::uint64_t historyRemaining = 64U * 1024U * 1024U ;	// 子履歴は独立した元64 MiB枠です。
		ReadSet		  history{historyRemaining, {}} ;			// 全bootstrapと最大64操作の原像です。
		auto chain = initialChain( segment.store(), h.bootstrap, parent->root().filename().native(),
								  history) ;	// 型付き元値からだけ再導出します。
		replayUpdates( segment.store(), chain, h.count, history) ;
		require( *head == chain.head) ;
		io( checkCollectorSharedLedgerCarry( chain.snapshot, chain.snapshot, utcMillis)) ;
		updateShape( *parent, segment.store(), chain.initial, chain.count) ;
		// 親の全66像を元操作再導出の結果へ結合します。
		for( std::size_t i = 0U; i < 66U; ++i) {
			require( current.get( *parent, currentName( i)) == chain.current.images[i]) ;
		}

		// 同じ実rawだけから未公開根拠を導出します。
		auto evidence =
			sharedEvidence( *parent, segment.store(), current, history, chain, utcMillis) ;
		// 同じ実rawだけから作る未公開値です。
		// 非通信診断が停止しても証拠値を公開しません。
		if( beforeFinalRecheck) {
			io( beforeFinalRecheck( evidence)) ;
		}

		current.recheck() ;
		history.recheck() ;
		updateShape( *parent, segment.store(), chain.initial, chain.count) ;
		// 最終列挙の全名／順序も元inventoryへ照合します。
		const auto final =
			sharedEvidence( *parent, segment.store(), current, history, chain, utcMillis) ;
		// 最終全列挙も初回の名前／順序と一致させます。
		require( final.inventory == evidence.inventory && final.seal == evidence.seal) ;
		// 私有結合監督だけが双方の借用中に元履歴を最終検査します。
		if( afterFinalRecheck) {
			io( afterFinalRecheck()) ;
		}

		// 私有keyは全再照合後にだけ使用します。
		auto verified = std::make_shared<const CollectorSharedRootInventory>(
			CollectorSharedRootInventory::ConstructionKey{}, std::move( evidence)) ;
		// 私有keyはこの全再照合後にだけ使用します。
		inventory = std::move( verified) ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		return code ;
	} catch( const Failure failure) {
		return failure.status == Status::SIZE_LIMIT		 ? ERROR_TOO_MANY_NAMES
			   : failure.status == Status::OUT_OF_MEMORY ? ERROR_NOT_ENOUGH_MEMORY
														 : ERROR_INVALID_DATA ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}
/** @see local_collector_shared_store.h */
DWORD LocalCollectorSharedStore::inspectRecoveryRootInventoryBound(
	LocalCollectorStateStore &parent, LocalCollectorStateStore &child,
	const CollectorSegmentSwitchDraft &draft, const std::string_view oldHeadRaw,
	std::shared_ptr<const CollectorSharedRootInventory>				&inventory,
	const std::function<DWORD( const CollectorSharedRootEvidence &)> &beforeFinalRecheck,
	const std::function<DWORD()>									&afterFinalRecheck) noexcept
{
	inventory.reset() ;
	try {
		std::uint64_t remaining = RAW_LIMIT ;				// 親能力と最終照合の同じ16 MiB先払い枠です。
		const auto	  utcMillis = draft.intent.accepted ;	// 元acceptedで封印を再導出します。
		const std::array<std::set<std::wstring>, 2U> skipped = [&draft] {
			std::array<std::set<std::wstring>, 2U>
				result ;	// 許可する追加名は元intentからだけ導出します。
			result[0].insert( L"runs/segment-switch-intent-" + draft.intentHash + L".json") ;
			result[0].insert( L"runs/segment-switch-activation-" + draft.intentHash + L".json") ;
			result[1].insert( L"current/segment-seal-v1.json") ;
			// 最大16shardの元ordinalを固定名へ結合します。
			for( std::size_t n = 0U; n < draft.intent.inventory.size(); ++n) {
				constexpr std::wstring_view digits = L"0123456789abcdef" ;	// 元二桁hex名です。
				result[1].insert( L"runs/segment-inventory-" + draft.intentHash + L"-" +
								 std::wstring{digits[n / 16U], digits[n % 16U]} + L".json") ;
			}

			return result ;
		}() ; // Captureは同期検査より長く存続しません。
		std::array<std::set<std::wstring>, 3U> extra ;	// Parent runs、旧current、旧runsです。
		// 導出済み固定名をdirectory別の許可集合に分けます。
		for( std::size_t scope = 0U; scope < skipped.size(); ++scope) {
			// 単なる除外名ではなく、後続で全byteを照合する固定roleです。
			for( const auto &name : skipped[scope]) {
				extra[scope == 0U					  ? 0U
					  : name.starts_with( L"current/") ? 1U
													  : 2U]
					.insert( std::filesystem::path( name).filename().native()) ;
			}
		}

		std::byte borrower{} ;	// 同期検査中だけ有効な監督能力です。
		io( child.borrowCampaign( &borrower)) ;
		const auto releaseChild = [&borrower]( LocalCollectorStateStore *owner) {
			owner->releaseCampaign( &borrower) ;
		} ; // 親より先に子の監督借用を返却します。
		const std::unique_ptr<LocalCollectorStateStore, decltype( releaseChild)> childGuard(
			&child, releaseChild) ;			// Storeの実所有は元leaseに残します。
		ReadSet current{remaining, {}} ;	// 両marker／head／全66現在像です。
		updateMarkers( parent, child, current, true) ;
		ReadSet physical{remaining, {}} ;	// 実現在headを元論理headとは別に最終照合します。
		require( physical.get( parent, HEAD).has_value()) ;
		current.files.push_back( {&parent, HEAD, std::string( oldHeadRaw)}) ;
		const auto head = current.get( parent, HEAD) ;	// 未登録やactive commitを回復しません。
		require( head.has_value()) ;
		const auto h = updateHead( *head, parent.root().filename().native(),
								  // 同親の有限参照です。
								  child.root().filename().native()) ;
		require( h.commit.empty()) ;
		std::uint64_t historyRemaining = 64U * 1024U * 1024U ;	// 子履歴は独立した元64 MiB枠です。
		ReadSet		  history{historyRemaining, {}} ;			// 全bootstrapと最大64操作の原像です。
		auto		  chain = initialChain( child, h.bootstrap, parent.root().filename().native(),
										   history) ;	// 型付き元値からだけ再導出します。
		replayUpdates( child, chain, h.count, history) ;
		require( *head == chain.head) ;
		io( checkCollectorSharedLedgerCarry( chain.snapshot, chain.snapshot, utcMillis)) ;
		updateShape( parent, child, chain.initial, chain.count, extra) ;
		// 親の全66像を元操作再導出の結果へ結合します。
		for( std::size_t i = 0U; i < 66U; ++i) {
			require( current.get( parent, currentName( i)) == chain.current.images[i]) ;
		}

		// 同じ実rawだけから未公開根拠を導出します。
		auto evidence = sharedEvidence( parent, child, current, history, chain, utcMillis, skipped) ;
		// 同じ実rawだけから作る未公開値です。
		// 非通信診断が停止しても証拠値を公開しません。
		if( beforeFinalRecheck) {
			io( beforeFinalRecheck( evidence)) ;
		}

		current.recheck( &parent, HEAD) ;
		physical.recheck() ;
		history.recheck() ;
		updateShape( parent, child, chain.initial, chain.count, extra) ;
		// 最終列挙の全名／順序も元inventoryへ照合します。
		const auto final =
			sharedEvidence( parent, child, current, history, chain, utcMillis, skipped) ;
		// 最終全列挙も初回の名前／順序と一致させます。
		require( final.inventory == evidence.inventory && final.seal == evidence.seal) ;
		// 私有結合監督だけが双方の借用中に元履歴を最終検査します。
		if( afterFinalRecheck) {
			io( afterFinalRecheck()) ;
		}

		// 私有keyは全再照合後にだけ使用します。
		auto verified = std::make_shared<const CollectorSharedRootInventory>(
			CollectorSharedRootInventory::ConstructionKey{}, std::move( evidence)) ;
		// 私有keyはこの全再照合後にだけ使用します。
		inventory = std::move( verified) ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		return code ;
	} catch( const Failure failure) {
		return failure.status == Status::SIZE_LIMIT		 ? ERROR_TOO_MANY_NAMES
			   : failure.status == Status::OUT_OF_MEMORY ? ERROR_NOT_ENOUGH_MEMORY
														 : ERROR_INVALID_DATA ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}
} // namespace drivercrate
