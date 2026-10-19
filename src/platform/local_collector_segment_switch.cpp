//------------------------------------------------------------------------------
/**
 * @file local_collector_segment_switch.cpp
 * @brief 非変更carryと固定切替intent／base／headの結合を検査します。
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
 * @note 実seal由来・保護保存・復旧・HTTPへ接続しないdraft coreです。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#include "local_collector_segment_switch.h"
#include "local_collector_projected_json.h"
#include "official_file_verifier.h"
#include <new>
#include <set>
#include <utility>

namespace drivercrate {
namespace {
using collector_projected_json::Failure ;
using collector_projected_json::Reader ;
using collector_projected_json::Status ;
using collector_projected_json::Writer ;
// Intent・base・bootstrapの独立byte上限です。
constexpr std::size_t	SMALL_LIMIT = 16U * 1024U ;
// 1023個のseal参照を有限headへ保持する独立上限です。
constexpr std::size_t	HEAD_LIMIT = 256U * 1024U ;
// 既存監督と同じUTC millisecondの上限です。
constexpr std::uint64_t LAST_UTC = 4102444799999ULL ;

/** @brief 第一数値errorをそのまま伝播します。
 * @param[in] ok 必須条件。
 * @param[in] code 元失敗code。
 * @throws DWORD 条件不成立時。
 */
void					require( const bool ok, const DWORD code = ERROR_INVALID_DATA)
{
	// 容量・CNG障害を形式不正へ変えません。
	if( !ok) {
		throw code ;
	}
}
/** @brief 元本文だけのCNG指紋を返します。
 * @param[in] bytes 非空の有限canonical本文。
 * @return 元byteの小文字SHA-256。
 * @throws DWORD 第一CNG code。
 */
std::wstring digest( const std::string_view bytes)
{
	std::wstring hash ;																		// 外側や別fieldのhashへ置換しません。
	const auto code = static_cast<DWORD>( computeCollectorMetadataSha256( bytes, hash)) ;	// 元値です。
	require( code == ERROR_SUCCESS, code) ;
	return hash ;
}
/** @brief 完全小文字hashだけを受理します。
 * @param[in] hash 入力の元hash。
 * @throws DWORD 形式拒否13。
 */
void hashValid( const std::wstring_view hash)
{
	require( collector_projected_json::isHash( hash)) ;
}
/** @brief Inventory hashの有限集合を検査します。
 * @param[in] hashes 元ordinal順のhash。
 * @throws DWORD 空集合／不正13、17個目68。
 */
void inventoryValid( const std::vector<std::wstring> &hashes)
{
	require( hashes.size() <= 16U, ERROR_TOO_MANY_NAMES) ;
	require( !hashes.empty()) ;
	// 各shardの元hashを検査し、順序をsortしません。
	for( const auto &hash : hashes) {
		hashValid( hash) ;
	}
}
/** @brief 固定型の関係と有限値を先に検査します。
 * @param[in] intent Caller所有の元intent。
 * @throws DWORD 形式13、容量68。
 */
void intentValid( const CollectorSegmentSwitchIntent &intent)
{
	require( intent.ordinal <= 1023U, ERROR_TOO_MANY_NAMES) ;
	require( intent.ordinal != 0U && intent.accepted <= LAST_UTC) ;
	hashValid( intent.collection) ;
	hashValid( intent.oldSegment) ;
	hashValid( intent.newSegment) ;
	require( intent.oldSegment != intent.newSegment) ;
	hashValid( intent.oldHead) ;
	hashValid( intent.ledger) ;
	hashValid( intent.oldRoot) ;
	hashValid( intent.seal) ;
	inventoryValid( intent.inventory) ;
	hashValid( intent.base) ;
	hashValid( intent.bootstrap) ;
	hashValid( intent.nextHead) ;
}
/** @brief 元順序を失わず有限hash配列を出力します。
 * @tparam Range 元hashを持つ有限range。
 * @param[in,out] writer 既存の有限sink。
 * @param[in] hashes 型側で件数・hashを検査したrange。
 * @throws Failure Byte上限・字句拒否。
 */
template <class Range> void hashArray( Writer &writer, const Range &hashes)
{
	writer.append( "[") ;
	bool first = true ;	// 区切りをfieldの一部として固定します。
	// 既存順序のhashを一度ずつ保持します。
	for( const auto &hash : hashes) {
		// 先頭だけcommaを省きます。
		if( !first) {
			writer.append( ",") ;
		}

		first = false ;
		writer.wideText( hash) ;
	}

	writer.append( "]") ;
}
/** @brief Intentを固定field順へ符号化します。
 * @param[in] intent 元型付きintent。
 * @return 最大16 KiBのcanonical本文。
 * @throws DWORD 関係拒否13、容量68。
 * @throws Failure 字句・byte拒否。
 */
std::string encode( const CollectorSegmentSwitchIntent &intent)
{
	intentValid( intent) ;
	Writer w( SMALL_LIMIT) ;	// 未知fieldを追加しません。
	w.append( "{\"schema\":\"collector-segment-switch-v1\",\"collection\":") ;
	w.wideText( intent.collection) ;
	w.append( ",\"oldSegment\":") ;
	w.wideText( intent.oldSegment) ;
	w.append( ",\"newSegment\":") ;
	w.wideText( intent.newSegment) ;
	w.append( ",\"oldHead\":") ;
	w.wideText( intent.oldHead) ;
	w.append( ",\"ordinal\":") ;
	w.number( intent.ordinal) ;
	w.append( ",\"accepted\":") ;
	w.number( intent.accepted) ;
	w.append( ",\"ledger\":") ;
	w.wideText( intent.ledger) ;
	w.append( ",\"oldRoot\":") ;
	w.wideText( intent.oldRoot) ;
	w.append( ",\"seal\":") ;
	w.wideText( intent.seal) ;
	w.append( ",\"inventory\":") ;
	hashArray( w, intent.inventory) ;
	w.append( ",\"base\":") ;
	w.wideText( intent.base) ;
	w.append( ",\"bootstrap\":") ;
	w.wideText( intent.bootstrap) ;
	w.append( ",\"nextHead\":") ;
	w.wideText( intent.nextHead) ;
	w.append( "}") ;
	return w.take() ;
}
/** @brief Readerの元文字列を完全hashへ変換します。
 * @param[in,out] reader 固定順の有限reader。
 * @return 全byte検査後だけの64文字hash。
 * @throws Failure 字句拒否。
 * @throws DWORD 形式拒否13。
 */
std::wstring readHash( Reader &reader)
{
	const auto		   text = reader.text( 64U) ;			// 非ASCIIや短い値も後で拒否します。
	const std::wstring hash( text.begin(), text.end()) ;	// 検査前の元byteを保持します。
	hashValid( hash) ;
	return hash ;
}
/** @brief 全fieldを読み再encode一致を要求します。
 * @param[in] bytes 元canonical本文。
 * @return 全検査後のintent。
 * @throws Failure 字句／byte上限拒否。
 * @throws DWORD 関係13、容量68。
 */
CollectorSegmentSwitchIntent decode( const std::string_view bytes)
{
	Reader						 r( bytes, SMALL_LIMIT) ;	// 全byte事前検査と余分field拒否を使います。
	CollectorSegmentSwitchIntent intent ;					// 成功前の値を外へ公開しません。
	r.literal( "{\"schema\":\"collector-segment-switch-v1\",\"collection\":") ;
	intent.collection = readHash( r) ;
	r.literal( ",\"oldSegment\":") ;
	intent.oldSegment = readHash( r) ;
	r.literal( ",\"newSegment\":") ;
	intent.newSegment = readHash( r) ;
	r.literal( ",\"oldHead\":") ;
	intent.oldHead = readHash( r) ;
	r.literal( ",\"ordinal\":") ;
	intent.ordinal = r.number() ;
	r.literal( ",\"accepted\":") ;
	intent.accepted = r.number() ;
	r.literal( ",\"ledger\":") ;
	intent.ledger = readHash( r) ;
	r.literal( ",\"oldRoot\":") ;
	intent.oldRoot = readHash( r) ;
	r.literal( ",\"seal\":") ;
	intent.seal = readHash( r) ;
	r.literal( ",\"inventory\":") ;
	const auto array = r.value() ;			// 配列の有限substringだけを借用します。
	Reader	   items( array, SMALL_LIMIT) ;	// 要素を巨大objectの文字列へ変えません。
	items.literal( "[") ;
	// 非空配列は最大16項目を確保前に検査します。
	if( array != "[]") {
		// 区切りの終了まで同じ元順序で読む有限loopです。
		for( ;;) {
			require( intent.inventory.size() < 16U, ERROR_TOO_MANY_NAMES) ;
			intent.inventory.push_back( readHash( items)) ;
			// Readerが現在残り位置を直接公開しないため有限prefixを再構築して比較します。
			Writer prefix( SMALL_LIMIT) ;	// 最大16件の既知hashだけです。
			hashArray( prefix, intent.inventory) ;
			// 完全配列ならここで閉じ、余分要素を受理しません。
			if( prefix.view() == array) {
				break ;
			}

			items.literal( ",") ;
		}
	}

	items.literal( "]") ;
	items.finish() ;
	r.literal( ",\"base\":") ;
	intent.base = readHash( r) ;
	r.literal( ",\"bootstrap\":") ;
	intent.bootstrap = readHash( r) ;
	r.literal( ",\"nextHead\":") ;
	intent.nextHead = readHash( r) ;
	r.literal( "}") ;
	r.finish() ;
	require( encode( intent) == bytes) ;
	return intent ;
}
/** @brief 元66本文を固定ordinalで借用します。
 * @param[in] bytes 関係検査済みの元codec出力。
 * @param[in] ordinal 0～65。
 * @return Bytesの寿命内だけの本文reference。
 */
const std::string &bodyAt( const CollectorSharedLedgerBytes &bytes, const std::size_t ordinal)
{
	// 二先頭roleをrequest shardへ取り違えません。
	if( ordinal < 2U) {
		return ordinal == 0U ? bytes.budget : bytes.groups ;
	}

	return bytes.requests[ordinal - 2U] ;
}
/** @brief Seal集合の件数・重複・新旧key混入を検査します。
 * @param[in] request 元切替identity。
 * @throws DWORD 形式13、容量68。
 */
void requestValid( const CollectorSegmentSwitchRequest &request)
{
	require( request.oldOrdinal < 1023U && request.sealed.size() <= 1022U, ERROR_TOO_MANY_NAMES) ;
	require( request.sealed.size() == request.oldOrdinal) ;
	const auto &o = request.observation ;	// 実検査済み証明ではない元観測です。
	require( o.workersJoined && o.lastGenerationComplete && o.summaryPointerConsistent &&
			o.unreceived == 0U && o.unsettled == 0U && !o.activeCommit) ;
	std::set<std::wstring> keys ;	// 重複だけを検出し元履歴順を変更しません。
	hashValid( request.oldSegment) ;
	hashValid( request.newSegment) ;
	require( request.oldSegment != request.newSegment) ;
	// 過去sealed区間を新activeとして再登録しません。
	for( const auto &ref : request.sealed) {
		hashValid( ref.segment) ;
		hashValid( ref.seal) ;
		require( ref.segment != request.oldSegment && ref.segment != request.newSegment &&
				keys.insert( ref.segment).second) ;
	}
}
/** @brief Base・bootstrapに共通する一方向のidentityを出力します。
 * @param[in,out] w 有限sink。
 * @param[in] i 元intent。未導出hashはこの断片へ入れません。
 */
void identity( Writer &w, const CollectorSegmentSwitchIntent &i)
{
	w.append( ",\"collection\":") ;
	w.wideText( i.collection) ;
	w.append( ",\"segment\":") ;
	w.wideText( i.newSegment) ;
	w.append( ",\"ordinal\":") ;
	w.number( i.ordinal) ;
	w.append( ",\"accepted\":") ;
	w.number( i.accepted) ;
	w.append( ",\"oldRoot\":") ;
	w.wideText( i.oldRoot) ;
	w.append( ",\"ledger\":") ;
	w.wideText( i.ledger) ;
	w.append( ",\"oldSegment\":") ;
	w.wideText( i.oldSegment) ;
	w.append( ",\"seal\":") ;
	w.wideText( i.seal) ;
}
/** @brief 元二snapshotから全非保存draftを導出します。
 * @param[in] before 元台帳。
 * @param[in] carried 全非変更が必須の次台帳。
 * @param[in] request 元identity／切替前観測。
 * @return 全本文・全指紋を持つ非保存draft。
 * @throws DWORD 形式13、容量68、元CNG code。
 * @throws Failure 字句／byte拒否。
 */
CollectorSegmentSwitchDraft prepare( const CollectorSharedLedgerSnapshot &before,
									const CollectorSharedLedgerSnapshot &carried,
									const CollectorSegmentSwitchRequest &request)
{
	requestValid( request) ;
	DWORD code =
		// 非変更検査です。
		checkCollectorSharedLedgerCarry( before, carried, request.accepted) ;
	require( code == ERROR_SUCCESS, code) ;
	CollectorSharedLedgerBytes bytes ;	// 元値を固定66本文で再検査します。
	code = encodeCollectorSharedLedger( before, bytes) ;
	require( code == ERROR_SUCCESS, code) ;
	CollectorSegmentSwitchDraft draft ;				// hashが揃ってから外へ移譲します。
	auto					   &i = draft.intent ;	// 同じbundle内の型付きidentityです。
	i.collection				  = before.collection ;
	i.oldSegment				  = request.oldSegment ;
	i.newSegment				  = request.newSegment ;
	i.oldHead					  = request.oldHead ;
	i.ordinal					  = request.oldOrdinal + 1U ;
	i.accepted					  = request.accepted ;
	i.oldRoot					  = request.oldRoot ;
	i.seal						  = request.seal ;
	i.inventory					  = request.inventory ;
	hashValid( i.oldHead) ;
	hashValid( i.oldRoot) ;
	hashValid( i.seal) ;
	inventoryValid( i.inventory) ;
	// 元予算・group・requestの全本文hashを同じ固定順で保持します。
	for( std::size_t n = 0U; n < draft.images.size(); ++n) {
		draft.images[n] = digest( bodyAt( bytes, n)) ;
	}

	Writer ledger( SMALL_LIMIT) ;	// 既存shared storeと同じdigest domainです。
	ledger.append( "{\"schema\":\"collector-shared-digest-v1\",\"collection\":") ;
	ledger.wideText( i.collection) ;
	ledger.append( ",\"hashes\":") ;
	hashArray( ledger, draft.images) ;
	ledger.append( "}") ;
	i.ledger = digest( ledger.view()) ;
	Writer base( SMALL_LIMIT) ;	// 下流hashや自己hashを含めません。
	base.append( "{\"schema\":\"collector-segment-switch-base-v1\"") ;
	identity( base, i) ;
	base.append( "}") ;
	draft.base = base.take() ;
	i.base	   = digest( draft.base) ;
	Writer bootstrap( SMALL_LIMIT) ;	// intentやnextHeadのhashを含めません。
	bootstrap.append( "{\"schema\":\"collector-segment-switch-bootstrap-v1\"") ;
	identity( bootstrap, i) ;
	bootstrap.append( ",\"oldHead\":") ;
	bootstrap.wideText( i.oldHead) ;
	bootstrap.append( ",\"inventory\":") ;
	hashArray( bootstrap, i.inventory) ;
	bootstrap.append( ",\"base\":") ;
	bootstrap.wideText( i.base) ;
	bootstrap.append( ",\"hashes\":") ;
	hashArray( bootstrap, draft.images) ;
	bootstrap.append( "}") ;
	draft.bootstrap = bootstrap.take() ;
	i.bootstrap		= digest( draft.bootstrap) ;
	Writer head( HEAD_LIMIT) ;	// 最大1023参照を持つ既知schemaです。
	head.append( "{\"schema\":\"collector-segment-switch-head-v1\",\"collection\":") ;
	head.wideText( i.collection) ;
	head.append( ",\"segment\":") ;
	head.wideText( i.newSegment) ;
	head.append( ",\"ordinal\":") ;
	head.number( i.ordinal) ;
	head.append( ",\"revision\":1,\"accepted\":") ;
	head.number( i.accepted) ;
	head.append( ",\"ledger\":") ;
	head.wideText( i.ledger) ;
	head.append( ",\"base\":") ;
	head.wideText( i.base) ;
	head.append( ",\"bootstrap\":") ;
	head.wideText( i.bootstrap) ;
	head.append( ",\"sealed\":[") ;
	// 元参照を同じ履歴順で保持し、最後に今回旧sealだけを追加します。
	for( std::size_t n = 0U; n <= request.sealed.size(); ++n) {
		// 先頭以外へ固定区切りを加えます。
		if( n != 0U) {
			head.append( ",") ;
		}

		const CollectorSegmentSealReference ref =
			n == request.sealed.size() ? CollectorSegmentSealReference{i.oldSegment, i.seal}
									   : request.sealed[n] ;	// 元参照です。
		head.append( "{\"segment\":") ;
		head.wideText( ref.segment) ;
		head.append( ",\"seal\":") ;
		head.wideText( ref.seal) ;
		head.append( "}") ;
	}

	head.append( "],\"commit\":null}") ;
	draft.nextHead	  = head.take() ;
	i.nextHead		  = digest( draft.nextHead) ;
	draft.intentBytes = encode( i) ;
	draft.intentHash  = digest( draft.intentBytes) ;
	return draft ;
}
/** @brief 失敗を公開数値に変換して元CNG errorを保持します。
 * @tparam Fn 同期borrowed操作の型。
 * @param[in] action 出力は全成立後だけへ移譲する処理。
 * @return 成功0、形式13、容量68、確保8、元CNG code。
 */
template <class Fn> DWORD boundary( const Fn &action) noexcept
{
	try {
		action() ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		return code ;
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

/** @see local_collector_segment_switch.h */
DWORD encodeCollectorSegmentSwitchIntent( const CollectorSegmentSwitchIntent &intent,
										 std::string						&bytes) noexcept
{
	bytes = {} ;
	return boundary( [&] { bytes = encode( intent) ; }) ;
}
/** @see local_collector_segment_switch.h */
DWORD decodeCollectorSegmentSwitchIntent( const std::string_view		   bytes,
										 CollectorSegmentSwitchIntent &intent) noexcept
{
	intent = {} ;
	return boundary( [&] { intent = decode( bytes) ; }) ;
}
/** @see local_collector_segment_switch.h */
DWORD prepareCollectorSegmentSwitchDraft( const CollectorSharedLedgerSnapshot &before,
										 const CollectorSharedLedgerSnapshot &carried,
										 const CollectorSegmentSwitchRequest &request,
										 CollectorSegmentSwitchDraft		 &draft) noexcept
{
	draft = {} ;
	return boundary( [&] { draft = prepare( before, carried, request) ; }) ;
}
/** @see local_collector_segment_switch.h */
DWORD checkCollectorSegmentSwitchDraft( const CollectorSharedLedgerSnapshot &before,
									   const CollectorSharedLedgerSnapshot &carried,
									   const CollectorSegmentSwitchRequest &request,
									   const CollectorSegmentSwitchDraft   &draft) noexcept
{
	return boundary( [&] {
		const auto expected =
			// 不信任出力を参照せず再導出します。
			prepare( before, carried, request) ;
		require( expected.intent == draft.intent && expected.images == draft.images &&
				expected.base == draft.base && expected.bootstrap == draft.bootstrap &&
				expected.nextHead == draft.nextHead && expected.intentBytes == draft.intentBytes &&
				expected.intentHash == draft.intentHash) ;
	}) ;
}
} // namespace drivercrate
