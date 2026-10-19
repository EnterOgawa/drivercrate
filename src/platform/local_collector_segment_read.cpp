//------------------------------------------------------------------------------
/**
 * @file local_collector_segment_read.cpp
 * @brief 初回readyの有限byte結合と非作成handleの読取り証明を検査します。
 * @version 01.01.00
 * @date 2026/10/03
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/03  非保存の初回ready／checkpoint検査を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/03  非作成同親handleと最終再照合のcontextを追加。
 * </pre>
 *
 * @note 通常CLIや監督へ接続しません。直接根拠の証明だけで旧payloadを再生しません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#include "local_collector_segment_read.h"
#include "local_collector_projected_json.h"
#include "official_file_verifier.h"
#include <algorithm>
#include <cstddef>
#include <initializer_list>
#include <new>
#include <memory>
#include <string>
#include <vector>
#include <utility>

namespace drivercrate {
namespace {
using collector_projected_json::Reader ;							// 固定field順と有限字句を検査します。
using collector_projected_json::Writer ;							// Canonical envelopeを再導出します。
using collector_projected_json::Failure ;							// 内容と容量の第一分類を保持します。
using collector_projected_json::Status ;							// 内部失敗を公開数値へ変換します。
constexpr std::size_t	RAW_LIMIT		 = 2U * 1024U * 1024U ;		// 一rawの独立上限です。
constexpr std::size_t	SMALL_LIMIT		 = 16U * 1024U ;			// 制御本文の独立上限です。
constexpr std::size_t	INVENTORY_LIMIT	 = 256U * 1024U ;			// 一shard本文の独立上限です。
constexpr std::uint64_t FILE_BYTES_LIMIT = 144U * 1024U * 1024U ;	// 旧二根拠の登録合計上限です。
/** @brief 必須結合の不成立を第一数値で停止します。
 * @param[in] condition 成立が必要な関係です。
 * @param[in] code 内容または容量の拒否結果です。
 * @throws DWORD 条件不成立時の第一数値です。
 */
void					require( const bool condition, const DWORD code = ERROR_INVALID_DATA)
{
	// 部分一致から成功値を補完しません。
	if( !condition) {
		throw code ;
	}
}
/** @brief 下位codecとCNGの第一数値を保持します。
 * @param[in] code 元処理の結果です。
 * @throws DWORD 元失敗数値です。
 */
void io( const DWORD code)
{
	// 内容13への読み替えによる元障害の消失を防ぎます。
	if( code != ERROR_SUCCESS) {
		throw code ;
	}
}
/** @brief 元byteから実CNG SHA-256を求めます。
 * @param[in] body 有限元byteです。
 * @return 小文字64桁の元hashです。
 * @throws DWORD 第一CNG errorです。
 */
std::wstring digest( const std::string_view body)
{
	std::wstring hash ;	// 成功時だけの完全hashです。
	io( static_cast<DWORD>( computeCollectorMetadataSha256( body, hash))) ;
	return hash ;
}
/** @brief 固定shared envelopeと実CNG、外側canonicalを照合します。
 * @param[in] raw 最大2 MiBの元rawです。
 * @param[in] limit 用途別本文上限です。
 * @return 検査した元本文です。
 * @throws Failure 字句・有限枠違反です。
 * @throws DWORD 内容13または第一CNG errorです。
 */
std::string unpack( const std::string_view raw, const std::size_t limit)
{
	Reader reader( raw, RAW_LIMIT) ;	// 確保前に外側を検査します。
	reader.literal( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
	auto body = reader.text( limit) ;	// 本文の用途別上限を維持します。
	reader.literal( ",\"sha256\":") ;
	const auto hash = reader.text( 64U) ;	// 余分なhash byteを許可しません。
	reader.literal( "}") ;
	reader.finish() ;
	const auto actual = digest( body) ;	// 外側hashと本文hashを混同しません。
	require( std::wstring( hash.begin(), hash.end()) == actual) ;
	Writer canonical( RAW_LIMIT) ;	// 元rawのcanonical表現だけを再導出します。
	canonical.append( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
	canonical.text( body) ;
	canonical.append( ",\"sha256\":") ;
	canonical.wideText( actual) ;
	canonical.append( "}") ;
	require( canonical.view() == raw) ;
	return body ;
}
/** @brief 一rawの独立枠と二回分の集合残枠を確保前に先払いします。
 * @param[in] raw 呼出し中に借用する元入力です。
 * @param[in,out] remaining 用途別の二回分のbyte残枠です。
 * @throws DWORD 有限枠68です。
 */
void charge( const std::string_view raw, std::uint64_t &remaining)
{
	require( raw.size() <= RAW_LIMIT && raw.size() <= remaining / 2U, ERROR_TOO_MANY_NAMES) ;
	remaining -= static_cast<std::uint64_t>( raw.size()) * 2U ;
}
/** @brief seal／inventoryの固定hash fieldを読む内部部品です。
 * @param[in,out] reader 同じ本文の消費位置です。
 * @return 文法検査後の完全hashです。
 * @throws Failure 字句・有限枠拒否です。
 * @throws DWORD 内容13です。
 */
std::wstring hashText( Reader &reader)
{
	const auto	 raw = reader.text( 64U) ;			// 固定ASCII hashだけを受理します。
	std::wstring value( raw.begin(), raw.end()) ;	// 文法照合後に公開する値です。
	require( collector_projected_json::isHash( value)) ;
	return value ;
}
/** @brief 元sealの22fieldとintent／時計／全shard参照を結合します。
 * @param[in] raw 旧sealの元envelopeです。
 * @param[in,out] state まだ公開しない候補です。
 * @throws Failure 字句・有限枠拒否です。
 * @throws DWORD 内容13・容量68・第一CNG errorです。
 */
void checkpoint( const std::string_view raw, CollectorSegmentInitialReadState &state)
{
	const auto	body   = unpack( raw, SMALL_LIMIT) ;	// 元sealの独立本文です。
	const auto &intent = state.recovery.draft.intent ;	// 全carryと結合した元intentです。
	require( digest( body) == intent.seal) ;
	Reader reader( body, SMALL_LIMIT) ;	// 追加fieldと並替えを許可しません。
	reader.literal( "{\"schema\":\"collector-segment-root-seal-v1\",\"collection\":") ;
	require( hashText( reader) == intent.collection) ;
	reader.literal( ",\"segment\":") ;
	require( hashText( reader) == intent.oldSegment) ;
	reader.literal( ",\"rootKey\":") ;
	state.checkpoint.rootKey = hashText( reader) ;
	reader.literal( ",\"root\":") ;
	require( hashText( reader) == intent.oldRoot) ;
	reader.literal( ",\"rootUtc\":") ;
	require( reader.number() == state.recovery.carried.lastUtcMillis) ;
	reader.literal( ",\"inspectedUtc\":") ;
	require( reader.number() == intent.accepted) ;
	reader.literal( ",\"head\":") ;
	require( hashText( reader) == intent.oldHead) ;
	reader.literal( ",\"ledger\":") ;
	require( hashText( reader) == intent.ledger) ;
	reader.literal( ",\"historySeal\":") ;
	state.checkpoint.historySeal = hashText( reader) ;
	reader.literal( ",\"sharedSeal\":") ;
	state.checkpoint.sharedSeal = hashText( reader) ;
	reader.literal( ",\"generations\":") ;
	state.checkpoint.generations = reader.number() ;
	reader.literal( ",\"historyOperations\":") ;
	state.checkpoint.historyOperations = reader.number() ;
	reader.literal( ",\"sharedOperations\":") ;
	state.checkpoint.sharedOperations = reader.number() ;
	reader.literal( ",\"cacheCount\":") ;
	state.checkpoint.cacheCount = reader.number() ;
	reader.literal( ",\"historyFiles\":") ;
	state.checkpoint.historyFiles = reader.number() ;
	reader.literal( ",\"sharedFiles\":") ;
	state.checkpoint.sharedFiles = reader.number() ;
	reader.literal( ",\"historyBytes\":") ;
	state.checkpoint.historyBytes = reader.number() ;
	reader.literal( ",\"sharedBytes\":") ;
	state.checkpoint.sharedBytes = reader.number() ;
	reader.literal( ",\"fileCount\":") ;
	const auto files = reader.number() ;	// 行読取り前に全件数を先払いします。
	reader.literal( ",\"fileBytes\":") ;
	const auto	bytes = reader.number() ;	// 登録合計は実read byteではありません。
	const auto &value = state.checkpoint ;	// 元集計を有限値だけに限定します。
	require( value.generations > 0U && files > 0U) ;
	require( value.generations <= 300U && value.historyOperations <= 300U &&
				value.sharedOperations <= 64U && value.cacheCount <= 300U &&
				value.sharedFiles <= 256U && value.historyFiles <= 8192U - value.sharedFiles &&
				value.historyBytes <= FILE_BYTES_LIMIT &&
				value.sharedBytes <= FILE_BYTES_LIMIT - value.historyBytes,
			ERROR_TOO_MANY_NAMES) ;
	require( files == value.historyFiles + value.sharedFiles &&
			bytes == value.historyBytes + value.sharedBytes &&
			intent.inventory.size() == (files + 511U) / 512U) ;
	reader.literal( ",\"inventory\":[") ;
	// 元intentの全shardを同じ順で結合します。
	for( std::size_t n = 0U; n < intent.inventory.size(); ++n) {
		// 先頭以外へ固定separatorを置きます。
		if( n != 0U) {
			reader.literal( ",") ;
		}

		require( hashText( reader) == intent.inventory[n]) ;
	}

	reader.literal( "]}") ;
	reader.finish() ;
}
/** @brief scopeと相対名を既存storeの小文字ASCII文法へ限定します。
 * @param[in] file 一行の元登録です。
 * @return 親current／runs、子current／runs、history current／runsの順序です。
 * @throws DWORD 内容13です。
 */
std::size_t fileOrder( const CollectorSegmentReadFile &file)
{
	require( file.scope == L"parent" || file.scope == L"segment" || file.scope == L"history") ;
	const auto slash = file.name.find( L'/') ;	// 固定一階層だけを検査します。
	require( slash != std::wstring::npos) ;
	const std::wstring_view directory( file.name.data(), slash) ;			// 任意pathへ渡しません。
	const auto name = std::wstring_view( file.name).substr( slash + 1U) ;	// 元filenameです。
	require( (directory == L"current" || directory == L"runs") && !name.empty() &&
			name.front() != L'.' && name.size() <= 160U && name.ends_with( L".json") &&
			std::all_of( name.begin(), name.end(), []( const wchar_t letter) {
				return (letter >= L'a' && letter <= L'z') || (letter >= L'0' && letter <= L'9') ||
					   letter == L'-' || letter == L'.' ;
			})) ; // Lambdaは借用名のASCII字句だけを検査します。
	const auto scope = file.scope == L"parent"	  ? 0U
					   : file.scope == L"segment" ? 2U
												  : 4U ;	// 固定群です。
	return scope + (directory == L"runs" ? 1U : 0U) ;
}
/** @brief 全inventory行の元順・hash・集計と元head rawを結合します。
 * @param[in] bytes 同期借用する元raw集合です。
 * @param[in,out] state 全検査前の候補です。
 * @throws Failure 字句・有限枠拒否です。
 * @throws DWORD 内容13・容量68・第一CNG errorです。
 */
void inventory( const CollectorSegmentInitialReadBytes &bytes,
			   CollectorSegmentInitialReadState		  &state)
{
	const auto &intent = state.recovery.draft.intent ;	// 全shard参照の正本です。
	const auto	count =
		state.checkpoint.historyFiles + state.checkpoint.sharedFiles ;	// 最大8192です。
	require( bytes.oldInventory.size() == intent.inventory.size()) ;
	std::uint64_t historyFiles{} ;	// 行から独立再計数します。
	std::uint64_t sharedFiles{} ;	// 親／子の合計です。
	std::uint64_t historyBytes{} ;	// 登録sizeをoverflow前に加算します。
	std::uint64_t sharedBytes{} ;	// 実I/Oのread量とは別です。
	std::size_t	  headRows{} ;		// 親の元head一行だけが結合対象です。
	std::size_t	  previousOrder{} ;	// 元群順を変更しません。
	state.files.reserve( static_cast<std::size_t>( count)) ;
	// 元512行shardと最後の残行をordinal順に一度ずつ検査します。
	for( std::size_t ordinal = 0U; ordinal < bytes.oldInventory.size(); ++ordinal) {
		const auto body = unpack( bytes.oldInventory[ordinal], INVENTORY_LIMIT) ;	// 一shardだけです。
		require( digest( body) == intent.inventory[ordinal]) ;
		Reader reader( body, INVENTORY_LIMIT) ;	// 固定六fieldと行順を検査します。
		reader.literal( "{\"schema\":\"collector-segment-root-inventory-v1\",\"collection\":") ;
		require( hashText( reader) == intent.collection) ;
		reader.literal( ",\"segment\":") ;
		require( hashText( reader) == intent.oldSegment) ;
		reader.literal( ",\"ordinal\":") ;
		require( reader.number() == ordinal) ;
		reader.literal( ",\"fileCount\":") ;
		require( reader.number() == count) ;
		reader.literal( ",\"files\":[") ;
		const auto rows =
			std::min<std::uint64_t>( 512U, count - state.files.size()) ;	// 空shardはありません。
		// 固定行数を消費し、不足・追加行を拒否します。
		for( std::uint64_t n = 0U; n < rows; ++n) {
			// 行先頭以外へ固定delimiterを置きます。
			if( n != 0U) {
				reader.literal( ",") ;
			}

			CollectorSegmentReadFile file ;	// 全結合前に外へ公開しません。
			reader.literal( "{\"scope\":") ;
			const auto scope = reader.text( 7U) ;	// 最大historyだけを許可します。
			file.scope.assign( scope.begin(), scope.end()) ;
			reader.literal( ",\"name\":") ;
			const auto name = reader.text( 168U) ;	// current/と最大160名だけです。
			file.name.assign( name.begin(), name.end()) ;
			reader.literal( ",\"bytes\":") ;
			file.bytes = reader.number() ;
			reader.literal( ",\"sha256\":") ;
			file.sha256 = hashText( reader) ;
			reader.literal( "}") ;
			require( file.bytes > 0U) ;
			require( file.bytes <= RAW_LIMIT, ERROR_TOO_MANY_NAMES) ;
			const auto order = fileOrder( file) ;	// 名前を開く能力へ変換しません。
			// 群の巻戻しと同scope／directoryの重複・並替えを拒否します。
			if( !state.files.empty()) {
				require( order > previousOrder ||
						(order == previousOrder && state.files.back().name < file.name)) ;
			}

			previousOrder = order ;
			auto &total =
				// 元scopeごとの合計です。
				file.scope == L"history" ? historyBytes : sharedBytes ;
			require( file.bytes <= FILE_BYTES_LIMIT - total, ERROR_TOO_MANY_NAMES) ;
			total += file.bytes ;
			(file.scope == L"history" ? historyFiles : sharedFiles)++ ;
			// 本文hashでなく元head envelopeのraw hash／sizeへ結合します。
			if( file.scope == L"parent" && file.name == L"current/collection-head-v1.json") {
				++headRows ;
				require( file.bytes == state.recovery.oldHeadRaw.size() &&
						file.sha256 == digest( state.recovery.oldHeadRaw)) ;
			}

			state.files.push_back( std::move( file)) ;
		}

		reader.literal( "]}") ;
		reader.finish() ;
	}

	require( headRows == 1U && state.files.size() == count &&
			historyFiles == state.checkpoint.historyFiles &&
			sharedFiles == state.checkpoint.sharedFiles &&
			historyBytes == state.checkpoint.historyBytes &&
			sharedBytes == state.checkpoint.sharedBytes) ;
}
} // namespace
/** @see local_collector_segment_read.h */
DWORD decodeCollectorSegmentInitialRead( const CollectorSegmentInitialReadBytes &bytes,
										CollectorSegmentInitialReadState	   &state) noexcept
{
	state = {} ;
	try {
		require( !bytes.oldInventory.empty()) ;
		require( bytes.oldInventory.size() <= 16U, ERROR_TOO_MANY_NAMES) ;
		std::uint64_t sharedRemaining = 16U * 1024U * 1024U ;	// 二回分の必要入力だけの先払いです。
		std::uint64_t segmentRemaining =
			64U * 1024U * 1024U ;	// 実markerや名数は後続readerで追加します。
		charge( bytes.recovery.head, sharedRemaining) ;
		// 現在親66rawを別の共有枠へ先払いします。
		for( const auto raw : bytes.currentImages) {
			charge( raw, sharedRemaining) ;
		}

		// 固定制御rawを用途別の新区間枠へ先払いします。
		for( const auto raw : {bytes.recovery.intent, bytes.recovery.activation, bytes.recovery.root,
							  bytes.base, bytes.bootstrap, bytes.oldSeal}) {
			charge( raw, segmentRemaining) ;
		}

		// 全carry像を枠の先払い後だけ復号します。
		for( const auto raw : bytes.recovery.images) {
			charge( raw, segmentRemaining) ;
		}

		// 直接inventoryだけを読み、登録された旧payloadへアクセスしません。
		for( const auto raw : bytes.oldInventory) {
			charge( raw, segmentRemaining) ;
		}

		CollectorSegmentInitialReadState next ;	// 全成功前は外へ公開しません。
		io( decodeCollectorSegmentRecovery( bytes.recovery, next.recovery)) ;
		require( next.recovery.saved == 3U &&
				unpack( bytes.base, SMALL_LIMIT) == next.recovery.draft.base &&
				unpack( bytes.bootstrap, SMALL_LIMIT) == next.recovery.draft.bootstrap &&
				bytes.currentImages == bytes.recovery.images) ;
		checkpoint( bytes.oldSeal, next) ;
		inventory( bytes, next) ;
		next.sharedInputBytes  = 16U * 1024U * 1024U - sharedRemaining ;
		next.segmentInputBytes = 64U * 1024U * 1024U - segmentRemaining ;
		state				   = std::move( next) ;
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

/** @see local_collector_segment_read.h */
CollectorSegmentReadContext::CollectorSegmentReadContext(
	ConstructionKey, std::shared_ptr<const CollectorCollectionReadHold> hold,
	CollectorSegmentInitialReadState state)
	: hold_( std::move( hold)), state_( std::move( state))
{
}
/** @see local_collector_segment_read.h */
CollectorSegmentReadContext::~CollectorSegmentReadContext() = default ;
/** @see local_collector_segment_read.h */
const CollectorSegmentInitialReadState &CollectorSegmentReadContext::state() const noexcept
{
	return state_ ;
}

namespace {
/** @brief 同期reader内だけの全直接読取りrawです。外部から再構築できません。 */
struct SegmentReadRaw {
	/// 親0／旧子1／新子2／新history3の私有scopeです。
	std::size_t	 scope{} ;
	/// 親現在値の16 MiB枠だけならtrueです。
	bool		 shared{} ;
	/// 固定schemaから生成したcurrent／runs名です。
	std::wstring name ;
	/// 保護handleから読んだ元rawです。最終再照合まで変更しません。
	std::string	 raw ;
} ;
/** @brief 0～255の固定ordinalを完全小文字二桁へ変換します。
 * @param[in] ordinal 固定66像または最大16shardのordinalです。
 * @return 固定名に使用する二文字です。
 */
std::wstring segmentReadOrdinal( const std::size_t ordinal)
{
	constexpr std::wstring_view HEX = L"0123456789abcdef" ;	// 固定wire表記です。
	std::wstring				result( 2U, L'0') ;			// 二文字以外を生成しません。
	result[0] = HEX[(ordinal >> 4U) & 15U] ;
	result[1] = HEX[ordinal & 15U] ;
	return result ;
}
/** @brief 親66現在値の固定相対名を返します。
 * @param[in] ordinal 予算0／group1／request2～65です。
 * @return 既存保存schemaの完全名です。
 */
std::wstring segmentReadCurrentName( const std::size_t ordinal)
{
	// 固定予算をrequest shardへ読み替えません。
	if( ordinal == 0U) {
		return L"current/shared-budget-v1.json" ;
	}

	// 固定groupを空値で補完しません。
	if( ordinal == 1U) {
		return L"current/shared-groups-v1.json" ;
	}

	return L"current/shared-requests-" + segmentReadOrdinal( ordinal - 2U) + L".json" ;
}
} // namespace

/** @see local_collector_segment_read.h */
DWORD LocalCollectorSegmentReader::inspect(
	LocalCollectorCollectionStore &collection, const std::wstring_view intentKey,
	std::shared_ptr<const CollectorSegmentReadContext> &context,
	CollectorSegmentReadDiagnostics					   &diagnostics,
	const std::function<DWORD()>					   &beforeFinalRecheck) noexcept
{
	diagnostics = {} ;
	// 発行済み能力を暗黙に返したり異なる親へ移したりしません。
	if( context) {
		return ERROR_BUSY ;
	}

	try {
		require( collector_projected_json::isHash( intentKey), ERROR_INVALID_PARAMETER) ;
		const std::wstring key( intentKey) ;	// Callbackによる元借用文字列の変更から分離します。
		LocalCollectorStateStore *parent{} ;	// 未借用の元親だけです。
		io( collection.recoveryParent( parent)) ;
		std::array<LocalCollectorStateStore *, 4U> stores{parent, nullptr, nullptr,
														  nullptr} ;	// 私有handleです。
		std::uint64_t sharedRemaining  = 16U * 1024U * 1024U ;			// Marker／再読取りを含む総残枠です。
		std::uint64_t segmentRemaining = 64U * 1024U * 1024U ;			// 直接根拠だけの総残枠です。
		std::vector<SegmentReadRaw> reads ;								// 最終再検査まで全元rawを保持します。
		reads.reserve( 160U) ;
		const auto readRaw = [&]( const std::size_t scope, const std::wstring &name,
								 const bool shared, const bool final, std::string &raw) {
			bool  found{} ;	// 必須欠損を成功へ補完しません。
			auto &remaining =
				shared ? sharedRemaining : segmentRemaining ;	// scope別の同じ残枠です。
			const auto before = remaining ;						// I/O失敗でも実size先払いを部分診断へ残します。
			auto	  &calls  = shared ? diagnostics.sharedReadCalls
									   : diagnostics.segmentReadCalls ;	// 実試行数です。
			++calls ;
			// 最終再読取りを初回readと別に計数します。
			if( final) {
				++diagnostics.finalReadCalls ;
			}

			const auto code =
				stores[scope]->read( name, raw, found, remaining) ;	// 同handle・先払いreadです。
			auto &charged =
				shared ? diagnostics.sharedBytes : diagnostics.segmentBytes ;	// 実size先払い量です。
			charged += before - remaining ;
			io( code) ;
			require( found, ERROR_FILE_NOT_FOUND) ;
		} ; // 同期入口より長く生存するstoreと残枠だけを参照します。
		const auto add = [&]( const std::size_t scope, std::wstring name, const bool shared) {
			auto &names =
				shared ? diagnostics.sharedNames : diagnostics.segmentNames ;	// 独立参照枠です。
			require( names < (shared ? 256U : 6000U), ERROR_TOO_MANY_NAMES) ;
			// 同じscopeの重複rawを別根拠として登録しません。
			for( const auto &entry : reads) {
				require( entry.scope != scope || entry.name != name) ;
			}

			++names ;
			SegmentReadRaw entry ;	// 元byteの全取得後だけ登録します。
			entry.scope	 = scope ;
			entry.shared = shared ;
			entry.name	 = std::move( name) ;
			readRaw( scope, entry.name, shared, false, entry.raw) ;
			reads.push_back( std::move( entry)) ;
			return reads.size() - 1U ;
		} ; // 検査中の全rawと実診断へ結合します。外へ借用を返しません。

		const auto markerIndex =
			// 親登録です。
			add( 0U, L"current/collector-campaign-mode-v1.json", true) ;
		const auto headIndex =
			// 現物最終headです。
			add( 0U, L"current/collection-head-v1.json", true) ;
		const auto intentIndex =
			// 固定起点です。
			add( 0U, L"runs/segment-switch-intent-" + key + L".json", false) ;
		const auto intentBody =
			// 元実CNGとcanonicalです。
			unpack( reads[intentIndex].raw, SMALL_LIMIT) ;
		require( digest( intentBody) == key) ;
		CollectorSegmentSwitchIntent intent ;	// 実本文からの固定二子です。
		io( decodeCollectorSegmentSwitchIntent( intentBody, intent)) ;
		require( intent.collection == parent->root().filename().native(), ERROR_INVALID_PARAMETER) ;
		// 後続区間を初回readerへfallbackしません。
		if( intent.ordinal != 1U) {
			return ERROR_NOT_SUPPORTED ;
		}

		std::shared_ptr<const CollectorCollectionReadHold>
									hold ;		// 元wrapperより長く同親を所有します。
		std::array<std::string, 3U> markers ;	// 既存登録schemaと同じ生成元です。
		io( collection.openSegmentRead( intent.oldSegment, intent.newSegment, hold, stores, markers)) ;
		++diagnostics.collectionChecks ;
		require( reads[markerIndex].raw == markers[0]) ;
		const auto oldMarkerIndex =
			// 旧専用登録です。
			add( 1U, L"current/collector-campaign-mode-v1.json", false) ;
		const auto newMarkerIndex =
			// 新専用登録です。
			add( 2U, L"current/collector-campaign-mode-v1.json", false) ;
		require( reads[oldMarkerIndex].raw == markers[1] && reads[newMarkerIndex].raw == markers[2]) ;
		const auto activationIndex =
			// 元head保持です。
			add( 0U, L"runs/segment-switch-activation-" + key + L".json", false) ;
		const auto rootIndex =
			// 私有専用ROOTです。
			add( 3U, L"current/segment-history-root-v1.json", false) ;
		const auto baseIndex =
			// 新子固定baseです。
			add( 2U, L"current/segment-shared-base-v1.json", false) ;
		const auto bootstrapIndex =
			// carry結合です。
			add( 2U, L"runs/segment-switch-bootstrap-" + key + L".json", false) ;
		const auto				 sealIndex = add( 1U, L"current/segment-seal-v1.json",
												 false) ;	// 全旧payloadを開かないcheckpointです。
		std::vector<std::size_t> inventoryIndices ;			// 実intent由来の全登録shardです。
		// 最大16の元ordinalだけを固定名から読みます。JSONのfile名を開きません。
		for( std::size_t n = 0U; n < intent.inventory.size(); ++n) {
			inventoryIndices.push_back(
				add( 1U, L"runs/segment-inventory-" + key + L"-" + segmentReadOrdinal( n) + L".json",
					false)) ;
		}

		std::array<std::size_t, 66U> carryIndices ;		// 元固定66carryの参照位置です。
		std::array<std::size_t, 66U> currentIndices ;	// 親現在値の全66参照位置です。
		// 空request shardも補完せず全66像を読みます。
		for( std::size_t n = 0U; n < carryIndices.size(); ++n) {
			carryIndices[n] = add(
				2U, L"runs/segment-switch-image-" + key + L"-" + segmentReadOrdinal( n) + L".json",
				false) ;
			currentIndices[n] = add( 0U, segmentReadCurrentName( n), true) ;
		}

		std::vector<std::string_view> inventories ;	// 全rawが固定された後だけ借用します。
		// 各shardの元ordinalと寿命を維持します。
		for( const auto n : inventoryIndices) {
			inventories.emplace_back( reads[n].raw) ;
		}

		CollectorSegmentInitialReadBytes bytes ;	// すべて実保護handle由来です。
		bytes.recovery.intent	  = reads[intentIndex].raw ;
		bytes.recovery.activation = reads[activationIndex].raw ;
		bytes.recovery.root		  = reads[rootIndex].raw ;
		bytes.recovery.head		  = reads[headIndex].raw ;
		bytes.base				  = reads[baseIndex].raw ;
		bytes.bootstrap			  = reads[bootstrapIndex].raw ;
		bytes.oldSeal			  = reads[sealIndex].raw ;
		bytes.oldInventory		  = inventories ;
		// 元rawの完全一致とcodecへ同じ66順序を渡します。
		for( std::size_t n = 0U; n < carryIndices.size(); ++n) {
			bytes.recovery.images[n] = reads[carryIndices[n]].raw ;
			bytes.currentImages[n]	 = reads[currentIndices[n]].raw ;
		}

		CollectorSegmentInitialReadState decoded ;	// 全codec成功だけでは発行しません。
		io( decodeCollectorSegmentInitialRead( bytes, decoded)) ;
		const auto checkDirectory = [&]( const std::size_t		scope,
										const std::wstring_view directory) {
			std::vector<std::wstring> expected ;		// 読んだ固定集合からだけ導出します。
			std::uint64_t			  expectedBytes{} ;	// 同scope／directoryの全raw合計です。
			// 旧scopeを全列挙せず、現在対象三storeだけを検査します。
			for( const auto &entry : reads) {
				const std::filesystem::path name( entry.name) ;	// reader自身の固定名です。
				// 同じ現在directoryだけの実名とusageを集計します。
				if( entry.scope == scope && name.parent_path().native() == directory) {
					expected.push_back( name.filename().native()) ;
					expectedBytes += entry.raw.size() ;
				}
			}

			std::sort( expected.begin(), expected.end()) ;
			std::vector<std::wstring> names ;			// 現在同handleの全確定名です。
			std::size_t				  entries{} ;		// stagingを含む実entry数です。
			std::uint64_t			  actualBytes{} ;	// 同じ属性handleの合計sizeです。
			++diagnostics.directoryChecks ;
			io( stores[scope]->listNames( directory, names, &entries, &actualBytes,
										expected.size() + 1U)) ;
			require( names == expected && entries == expected.size() &&
					actualBytes == expectedBytes) ;
		} ; // 非通信同期検査だけです。旧payloadの名とusageは検査しません。
		const auto checkNames = [&] {
			// 親／新子／新historyの固定二directoryを一回ずつ検査します。
			for( const auto scope : {0U, 2U, 3U}) {
				checkDirectory( scope, L"current") ;
				checkDirectory( scope, L"runs") ;
			}
		} ; // 同じ固定raw集合と現在storeに限定した再検査です。
		checkNames() ;
		// 診断成功を元file不変の証明へ読み替えず、直後に全再検査します。
		if( beforeFinalRecheck) {
			io( beforeFinalRecheck()) ;
		}

		io( LocalCollectorCollectionStore::verifySegmentRead( hold)) ;
		++diagnostics.collectionChecks ;
		checkNames() ;
		// 全直接rawを同じ残枠で再読取りし、一byte差も能力へ昇格させません。
		for( const auto &entry : reads) {
			std::string actual ;	// 一raw再照合だけの所有です。
			readRaw( entry.scope, entry.name, entry.shared, true, actual) ;
			require( actual == entry.raw) ;
		}

		context = std::make_shared<CollectorSegmentReadContext>(
			CollectorSegmentReadContext::ConstructionKey{}, std::move( hold), std::move( decoded)) ;
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
} // namespace drivercrate
