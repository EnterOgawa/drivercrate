//------------------------------------------------------------------------------
/**
 * @file index_capacity_tests.cpp
 * @brief 原368recordを保持した大規模codec/store/lookupの有限回帰を定義します。
 * @version 01.00.01
 * @date 2026/11/07
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/07  旧byte保持・全ID進行・大規模上限回帰を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 * @note signed_index_manifest_tests.cpp末尾へincludeし既RAM鍵/隔離storeを共有します。
 * 新IDは架空公開IDだけです。本番key、実inventory、HTTP、installedを使用しません。
 * @see docs/adr/0458-bounded-index-capacity-and-owned-state-maps.md
 */
//------------------------------------------------------------------------------
#include "signed_index_manifest_tests.h"
#include "metadata_inventory_tests.h"
#include "platform/signed_index_record_lookup.h"
#include "platform/unsigned_index_candidate.h"
#include "platform/signed_index_codec_internal.h"
#include "platform/unsigned_index_probe_internal.h"
#include "test_framework.h"
#include "core/index_capacity_limits.h"
#include <Windows.h>
#include <psapi.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <stdexcept>
#include <vector>

namespace drivercrate::test {
namespace {
/** @brief fixture生成だけが使用するWinRT objectです。 */
using CapacityObject = winrt::Windows::Data::Json::JsonObject ;
/** @brief fixtureの原順序を維持する配列です。 */
using CapacityArray = winrt::Windows::Data::Json::JsonArray ;
/** @brief fixtureの型付きJSON値です。 */
using CapacityValue = winrt::Windows::Data::Json::JsonValue ;
// 原368を失効前で検査する固定機能時計です。実性能時計とは別です。
const auto CAPACITY_NOW =
	std::chrono::sys_days{std::chrono::year{2026} / 11 / 7} + std::chrono::hours{1} ;

//------------------------------------------------------------------------------
/**
 * @brief 架空公開IDに使う全単射の64bit mixerです。
 * @param[in] value 生成対象の非秘密ordinalです。
 * @return 圧縮比だけで巨大入力を救済しない決定的なbit列です。
 */
//------------------------------------------------------------------------------
std::uint64_t capacityMix( std::uint64_t value)
{
	value += 0x9e3779b97f4a7c15ULL ;
	value = (value ^ (value >> 30U)) * 0xbf58476d1ce4e5b9ULL ;
	value = (value ^ (value >> 27U)) * 0x94d049bb133111ebULL ;
	return value ^ (value >> 31U) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 実端末から独立した一意の架空公開IDを作ります。
 * @param[in] ordinal 新fixtureの0起点位置です。
 * @return 合法ASCIIの合成IDです。実inventory値ではありません。
 */
//------------------------------------------------------------------------------
std::string capacityId( std::uint64_t ordinal)
{
	constexpr std::string_view alphabet =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" ;	// 32文字の固定公開文法です。
	std::string result = "T\\" ;				// 架空bus名です。
	// 二つの独立mixを固定26文字へ展開し、同じindexのIDを再現できます。
	for( const auto value : {capacityMix( ordinal), capacityMix( ordinal ^ 0x4452434150414349ULL)}) {
		// 全64bitを保持し、末尾だけを取り出して衝突させません。
		for( unsigned position = 0U; position < 13U; ++position) {
			result.push_back( alphabet[(value >> (position * 5U)) & 31U]) ;
		}
	}

	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元fixture fileを有限byteで読み、oversize/途中変更を拒否します。
 * @param[in] path 764基準から新規作成した私有index fileです。
 * @return 元UTF-8 byteです。
 */
//------------------------------------------------------------------------------
std::string capacityRead( const std::filesystem::path &path)
{
	const auto count = std::filesystem::file_size( path) ;	// 開く前の有限量です。
	// 過大fixtureで容量拒否の試験前提を偽装しません。
	if( count > index_capacity::EXPANDED_BYTES) {
		throw std::runtime_error( "capacity fixture input too large") ;
	}

	std::ifstream input( path, std::ios::binary) ;					// 明示fixture以外の探索を行いません。
	std::string	  raw( static_cast<std::size_t>( count), '\0') ;	// 同byte数だけ所有します。
	input.read( raw.data(), static_cast<std::streamsize>( raw.size())) ;
	// 部分read/追記を元byteの成功にしません。
	if( !input || input.peek() != std::char_traits<char>::eof()) {
		throw std::runtime_error( "capacity fixture read changed") ;
	}

	return raw ;
}
//------------------------------------------------------------------------------
/**
 * @brief fixture重複寿命と製品scanを分ける補助資源観測です。
 * @param[in] phase 非機密の固定生成段階名です。
 * @note Peakはprocess全体の原OS値であり、resetやscanだけへの置換を行いません。
 */
//------------------------------------------------------------------------------
void capacityPhase( std::string_view phase)
{
	PROCESS_MEMORY_COUNTERS_EX counters{} ;	// OSのcurrent/peakをそのまま観測します。
	counters.cb = sizeof( counters) ;
	// OS計数取得不能をpeak0の性能成功へ変換しません。
	if( !GetProcessMemoryInfo( GetCurrentProcess(),
							 reinterpret_cast<PROCESS_MEMORY_COUNTERS *>( &counters),
							 sizeof( counters))) {
		throw std::runtime_error( "capacity memory observation failed") ;
	}

	std::cout << "CAPACITY_PHASE {\"phase\":\"" << phase
			  << "\",\"currentPrivateBytes\":" << counters.PrivateUsage
			  << ",\"peakPrivateBytes\":" << counters.PeakPagefileUsage
			  << ",\"workingSetBytes\":" << counters.WorkingSetSize << "}\n" ;
}

/** @brief 実RAM署名/保存の大規模fixture所有結果です。 */
struct CapacityFixture {
	/// 同fixture-mainだけを信頼する実隔離storeです。
	std::shared_ptr<SignedIndexStore> store ;
	/// 元record件数です。
	std::size_t						  records{} ;
	/// 実際に生成した全公開ID数です。
	std::size_t						  inputs{} ;
	/// 最後にだけ一致させる合成公開IDです。
	std::string						  tailId ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 原368のencoded byte/期限を保ち合法なcompact IDを末尾へ追加します。
 * @param[in,out] context 共通assertion集計先です。
 * @param[in] key 名前を持たないRAM CNG鍵です。
 * @param[in] baselineIndex 新規私有base368/index.jsonです。元SHAを必須にします。
 * @param[in] totalInputs 原368を含む要求公開ID数です。
 * @param[in] tailUnknown trueだけ末尾へ0-ID UNKNOWN recordを追加します。
 * @return 実codec/署名/保護保存から得た隔離storeと元件数です。
 */
//------------------------------------------------------------------------------
CapacityFixture capacityFixture( TestContext &context, const RamKey &key,
								const std::filesystem::path &baselineIndex, std::size_t totalInputs,
								bool tailUnknown)
{
	const auto baselineRaw = capacityRead( baselineIndex) ;	// 原byte pinからだけfixtureを組みます。
	DRIVERCRATE_EXPECT( context,
					   recordDigest( key, baselineRaw) ==
						   "99388802879d62ca6e391392f668f27bf42df723c3f3e1b6e2b630756bba444b") ;
	auto baseline =
		// 元record entryを再生成しません。
		CapacityObject::Parse( winrt::to_hstring( baselineRaw)) ;
	const auto originalRecords =
		// Base64原byteを保つ元368entryです。
		baseline.GetNamedArray( L"records") ;
	auto sources = baseline.GetNamedArray( L"sources") ;	// 同じ元source集合です。
	DRIVERCRATE_EXPECT( context, originalRecords.Size() == 368U && sources.Size() == 17U &&
									totalInputs > 32711U) ;
	// 重複sourceを件数だけで成功にしません。
	for( const auto &source : sources) {
		DRIVERCRATE_EXPECT( context,
						   source.GetObject().GetNamedString( L"sourceId") != L"fixture-source") ;
	}

	sources.Append( CapacityObject::Parse( winrt::to_hstring( recordSource()))) ;
	auto generated = CapacityObject::Parse( winrt::to_hstring(
		descriptorRecord( descriptorFixture(),
						 // 元架空v2 schemaです。
						 distributionRecord( "capacity-base", true, "CONTENT_INSPECTED")))) ;
	generated.SetNamedValue( L"inspectionStage",
							CapacityValue::CreateStringValue( L"CONTENT_INSPECTED")) ;
	auto attestation = generated.GetNamedObject( L"acquisitionDescriptor")
						   .GetNamedObject( L"attestation") ;	// 新fixtureだけの時刻です。
	attestation.SetNamedValue( L"checkedAtUtc",
							  CapacityValue::CreateStringValue( L"2026-11-07T01:00:00Z")) ;
	attestation.SetNamedValue( L"validUntilUtc",
							  CapacityValue::CreateStringValue( L"2026-11-08T01:00:00Z")) ;
	std::string entries =
		// 原368 entryの原base64を維持します。
		winrt::to_string( originalRecords.Stringify()) ;
	entries.pop_back() ;
	std::string index =
		"{\"schema\":\"driver-index-records-v2\",\"assetGeneration\":7,\"sources\":" +
		// 新しいouterだけです。
		winrt::to_string( sources.Stringify()) + ",\"records\":" + entries ;
	std::size_t inputs = 32711U ;		// 元368の固定された全入力数です。
	std::size_t generatedRecords{} ;	// 末尾へ足した合法record数です。
	std::string tailId ;				// 架空末尾IDだけです。
	// per-record4096を保ったまま要求総入力まで作り、IDを間引きません。
	while( inputs < totalInputs) {
		const auto	  count = std::min( index_capacity::RECORD_IDS,
									   totalInputs - inputs) ;	// 一recordへ入る有限数です。
		CapacityArray ids ;										// 一record分だけDOMを保持します。
		// 同じ公開文法のunique IDを原ordinalから決定的に生成します。
		for( std::size_t offset = 0U; offset < count; ++offset) {
			tailId = capacityId( inputs + offset) ;
			CapacityObject id ;	// 非秘密の公開fixture IDです。
			id.SetNamedValue( L"kind", CapacityValue::CreateStringValue( L"HARDWARE")) ;
			id.SetNamedValue( L"value", CapacityValue::CreateStringValue( winrt::to_hstring( tailId))) ;
			ids.Append( id) ;
		}

		generated.SetNamedValue( L"recordId", CapacityValue::CreateStringValue(
												 L"capacity-" + std::to_wstring( generatedRecords))) ;
		generated.GetNamedObject( L"publishedIdentityEvidence").SetNamedValue( L"pnpIds", ids) ;
		const auto raw = winrt::to_string( generated.Stringify()) ;	// この新recordだけの原byteです。
		DRIVERCRATE_EXPECT( context, raw.size() <= index_capacity::RECORD_BYTES) ;
		index += ',' ;
		index += recordEntry( key, raw) ;
		inputs += count ;
		++generatedRecords ;
	}

	// 全入力枠を使い切った後の証拠不足recordも訪問対象へ残します。
	if( tailUnknown) {
		const auto unknown = CapacityObject::Parse( winrt::to_hstring( distributionRecord(
			"capacity-unknown", false))) ;	// 既schema helperの明示UNKNOWNを使います。
		index += ',' ;
		index += recordEntry( key, winrt::to_string( unknown.Stringify())) ;
	}

	index += "]}" ;
	const auto recordCount =
		368U + generatedRecords + (tailUnknown ? 1U : 0U) ;	// 全原record数です。
	const IndexManifestQuality quality{18U, recordCount, tailUnknown ? 1U : 0U,
									   recordCount - (tailUnknown ? 1U : 0U),
									   0U} ;	// 原段階ごとの正確な分母です。
	auto inputsSigned = makeStoreInputs( key, index, 9U, 7U, CAPACITY_NOW, "2026-11-07T01:00:00Z",
										"2026-11-08T00:00:00Z", (index.size() + 127U) / 128U,
										quality) ;		// RAMだけの実RSA-PSSです。
	const auto indexBytes = index.size() ;				// 解放前の実byte数を保持します。
	const auto indexHash  = recordDigest( key, index) ;	// gzipと独立した生成原byte pinです。
	capacityPhase( "gzip-ready") ;
	std::string{}.swap( index) ;	// gzip/manifestが元byteを所有済みなので巨大な生成bufferを閉じます。
	capacityPhase( "assembled-index-released") ;
	const auto decoded = [&] {
		const auto bytes =
			authenticateIndexAssetBytes( inputsSigned.manifest, inputsSigned.gzip,
										CAPACITY_NOW) ;	// 共通の実gzip/CRC/展開/比率です。
		// fixture生成の失敗を容量拒否の成功へ換算しません。
		if( !bytes.receipt) {
			throw std::runtime_error( "capacity gzip fixture invalid") ;
		}

		return readSignedIndexRecords(
			*bytes.receipt,
			CAPACITY_NOW) ;	// receiptは認証assetを値で所有し、元assetの借用ではありません。
	}() ; // 最初のasset展開byteはrecords receipt成立後に破棄します。
	capacityPhase( "records-owned-first-asset-released") ;
	// 新上限+1は、他のbyte/signature条件成立後の専用拒否だけを合格にします。
	if( totalInputs > index_capacity::WHOLE_PUBLIC_IDS) {
		DRIVERCRATE_EXPECT( context, decoded.status == IndexRecordsStatus::INPUT_COUNT_LIMIT &&
										!decoded.receipt) ;
		return {} ;
	}

	DRIVERCRATE_EXPECT( context,
					   decoded.status == IndexRecordsStatus::SCHEMA_VALIDATED && decoded.receipt) ;
	// 正常fixtureの不成立を後続の未実行で隠しません。
	if( !decoded.receipt) {
		std::cout << "CAPACITY_CODEC_STATUS " << static_cast<unsigned>( decoded.status) << '\n' ;
		throw std::runtime_error( "capacity record fixture invalid") ;
	}

	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{"fixture-main", key.publicBlob}}} ;									// 本番配布keyを含みません。
	auto opened = signed_index_store_detail::Access::createIsolated( trust) ;	// 実DPAPIと閉rootです。
	// 元storeが作れない結果を正常索引へ変換しません。
	if( !opened.store) {
		throw std::runtime_error( "capacity isolated store unavailable") ;
	}

	// 同原byteを実再認証して隔離storeへ保存した結果です。
	const auto committed = opened.store->commit( *decoded.receipt, inputsSigned.envelope,
												inputsSigned.gzip, CAPACITY_NOW) ;
	capacityPhase( "commit-reauthenticated") ;
	DRIVERCRATE_EXPECT( context,
					   committed.snapshot &&
						   committed.snapshot->schemaReceipt().records().size() == recordCount) ;
	// 各元recordのencoded byte/期限を全件比較し、新しいhashだけの主張にしません。
	if( committed.snapshot) {
		const auto records =
			// 元const保存receiptだけです。
			committed.snapshot->schemaReceipt().records() ;
		// 旧368の原base64・SHAを一件ずつ検査します。期限はその原byte内にあります。
		for( std::size_t ordinal = 0U; ordinal < 368U; ++ordinal) {
			const auto expected = originalRecords.GetAt( static_cast<std::uint32_t>( ordinal))
									  .GetObject() ;	// 764基準の原entryです。
			const auto actual = CapacityObject::Parse( winrt::to_hstring( recordEntry(
				key, records[ordinal].originalBytes))) ;	// 保存済みの原byteだけを再符号化します。
			DRIVERCRATE_EXPECT( context, expected.GetNamedString( L"recordBytesBase64") ==
												actual.GetNamedString( L"recordBytesBase64") &&
											expected.GetNamedString( L"recordSha256") ==
												actual.GetNamedString( L"recordSha256")) ;
		}
	}

	std::cout << "CAPACITY_FIXTURE {\"inputs\":" << totalInputs << ",\"records\":" << recordCount
			  << ",\"oldEncodedRecordsExact\":368,\"indexBytes\":" << indexBytes
			  << ",\"indexSha256\":\"" << indexHash
			  << "\",\"gzipBytes\":" << inputsSigned.gzip.size()
			  << ",\"productionSignatures\":0}\n" ;
	return {std::shared_ptr<SignedIndexStore>{std::move( opened.store)}, recordCount, inputs,
			std::move( tailId)} ;
}

/** @brief record境界だけに使う小さい同期resolverです。性能資格には使いません。 */
class CapacityResolver final : public IndexPublicIdResolver {
public:
	/// 実callback件数です。
	mutable std::size_t					  calls{} ;
	/// 0は確定不一致、1は一意positive、2は明示未完了です。
	unsigned							  mode{} ;
	/// 未署名probe fixtureだけが一意positiveにする架空公開IDです。
	std::string							  tailId ;
	/**
	 * @brief 人工modeと呼出回数で索引容量の境界結果を返すfakeです。
	 * @param[in] kind メーカー公表INF側identifierの元役割。native property指定ではありません。
	 * @param[in] publishedId 元公開ASCII ID。端末actual IDではありません。
	 * @param[in] classGuid 元申告ClassGUID。
	 * @param[in] context 現在のworker context。
	 * @param[in] present 現在の有限opaque集合。本呼出し中だけ借用します。
	 * @return 同じcontextを持つ人工結果です。mode2だけ未完了、mode1またはmode3のtailId一致ではpresent先頭一件を返します。
	 * @note kind/classGuidは使用せず、publishedIdはmode3の文字列比較だけに使います。実inventory/ClassGUID適合やrankを検査しません。
	 *       presentはpositive modeで非空である試験前提です。
	 */
	[[nodiscard]] IndexPublicIdResolution resolve(
		IndexPnpIdKind kind, std::string_view publishedId, std::string_view classGuid,
		IndexLookupContext context, std::span<const std::wstring> present) const override
	{
		static_cast<void>( kind) ;
		static_cast<void>( publishedId) ;
		static_cast<void>( classGuid) ;
		++calls ;
		IndexPublicIdResolution result{context, mode != 2U, 0U, {}} ;	// fakeだけの元結果です。
		// 合成positiveは同contextに渡された一opaqueだけです。
		if( mode == 1U || (mode == 3U && publishedId == tailId)) {
			result.devices.push_back( present.front()) ;
		}

		return result ;
	}
} ;

//------------------------------------------------------------------------------
/**
 * @brief 32000+2000の全record prefixと途中取消し/保持不足を独立に確認します。
 * @param[in,out] context 共通集計先です。
 * @param[in] key 同processのRAM鍵です。
 */
//------------------------------------------------------------------------------
void capacityRecordBoundaries( TestContext &context, const RamKey &key)
{
	std::vector<std::string> rows ;			// 異なる原record九件です。
	std::size_t				 ordinal{} ;	// 架空IDを一意にする元位置です。
	// 八件4000IDと一件2000IDを作り、単一record4096を超えません。
	for( unsigned row = 0U; row < 9U; ++row) {
		auto		  record = CapacityObject::Parse( winrt::to_hstring(
			 // v1元schemaです。
			 distributionRecord( "boundary-" + std::to_string( row)))) ;
		CapacityArray ids ;	// 一recordだけの元ID集合です。
		// 全IDを一度ずつ生成します。
		for( unsigned id = 0U; id < (row == 8U ? 2000U : 4000U); ++id) {
			CapacityObject item ;	// 架空公開IDです。
			item.SetNamedValue( L"kind", CapacityValue::CreateStringValue( L"HARDWARE")) ;
			item.SetNamedValue( L"value", CapacityValue::CreateStringValue(
											 winrt::to_hstring( capacityId( ordinal++)))) ;
			ids.Append( item) ;
		}

		record.GetNamedObject( L"publishedIdentityEvidence").SetNamedValue( L"pnpIds", ids) ;
		rows.push_back( winrt::to_string( record.Stringify())) ;
	}

	const auto				 snapshot = lookupSnapshot( key, rows.front(), rows.size(), nullptr, 9U,
													   rows) ;			// 実codec/store/reloadです。
	const IndexLookupContext active{21U, 22U, 23U} ;					// 同期fixtureだけの完全contextです。
	const std::array<std::wstring, 1U> present{L"capacity-opaque"} ;	// 架空opaque一件です。
	CapacityResolver				   resolver ;						// 真NO_RELATIONだけを返します。
	IndexLookupBudget				   budget ;							// default batch枠は32768です。
	budget.compactNoRelations = true ;
	// 完全record prefixだけを保持した先頭batchです。
	const auto first =
		lookupSignedIndexRecords( snapshot, active, active, present, budget, NOW, &resolver) ;
	DRIVERCRATE_EXPECT( context, first.lookup && first.lookup->progress().completedRecords == 8U &&
									first.lookup->progress().processedPublicIds == 32000U &&
									first.lookup->progress().nextRecordOffset == 8U &&
									first.lookup->progress().stopReason ==
										IndexLookupStopReason::CALL_BUDGET &&
									first.lookup->relations().empty() && resolver.calls == 32000U) ;
	budget.recordOffset = 8U ;
	// 元offsetから残recordを処理した次batchです。
	const auto last =
		lookupSignedIndexRecords( snapshot, active, active, present, budget, NOW, &resolver) ;
	DRIVERCRATE_EXPECT( context, last.lookup && last.lookup->progress().completedRecords == 1U &&
									last.lookup->progress().processedPublicIds == 2000U &&
									resolver.calls == 34000U) ;
	// 同じ原prefixを再開し、record途中の停止を次recordへ飛ばしません。
	budget.recordOffset	 = 0U ;
	resolver.calls		 = 0U ;
	budget.stopRequested = [&] { return resolver.calls >= 4007U ; } ;
	// 途中recordをcommitしない取消し結果です。
	const auto cancelled =
		lookupSignedIndexRecords( snapshot, active, active, present, budget, NOW, &resolver) ;
	DRIVERCRATE_EXPECT( context, cancelled.lookup &&
									cancelled.lookup->progress().completedRecords == 1U &&
									cancelled.lookup->progress().processedPublicIds == 4000U &&
									cancelled.lookup->progress().nextRecordOffset == 1U &&
									cancelled.lookup->progress().stopReason ==
										IndexLookupStopReason::STOP_REQUESTED &&
									resolver.calls == 4007U) ;
	budget.stopRequested			= {} ;
	budget.maximumRelations			= 4001U ;
	budget.maximumRelatedIdentities = 4001U ;
	resolver.calls					= 0U ;
	resolver.mode					= 1U ;
	// 保持枠内の完全recordだけを所有する結果です。
	const auto retained =
		lookupSignedIndexRecords( snapshot, active, active, present, budget, NOW, &resolver) ;
	DRIVERCRATE_EXPECT( context, retained.lookup &&
									retained.lookup->progress().completedRecords == 1U &&
									retained.lookup->progress().nextRecordOffset == 1U &&
									retained.lookup->progress().stopReason ==
										IndexLookupStopReason::RETAINED_CAPACITY &&
									retained.lookup->relations().size() == 4000U) ;
	// 途中recordの一部positiveを混入させず、元record0だけを保持します。
	if( retained.lookup) {
		// 保持した全tupleが完全な先頭recordだけに属することを確認します。
		for( const auto &relation : retained.lookup->relations()) {
			DRIVERCRATE_EXPECT( context, relation.recordIndex == 0U) ;
		}
	}
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 独立byte条件を満たす最小UNKNOWN65536/65537 recordを共通値codecで確認します。
 * @param[in,out] context 共通集計先です。
 * @note v1値codecの容量だけです。未署名値から認証receiptや内容成功を発行しません。
 */
//------------------------------------------------------------------------------
void runIndexCapacityRecordCountTests( TestContext &context)
{
	const auto before = context.assertionCount() ;	// 本境界だけの実分母です。
	// 名称のない同processのsoftware RAM鍵です。
	RamKey	   key ;
	// 名称のないsoftware/RAM鍵だけです。
	key.generate( 3072U) ;
	auto record = CapacityObject::Parse( winrt::to_hstring(
		// 最小の未知値を保持します。
		distributionRecord( "r", false, "UNCONFIRMED", "s"))) ;
	record.SetNamedValue( L"product", CapacityValue::CreateStringValue( L"p")) ;
	// 全UNKNOWN fieldの不足理由を保持し、最小byte正例を構成します。
	for( const auto field : {L"targetOs", L"architecture", L"driverKind", L"version",
							L"publishedDate", L"acquisition", L"lastSuccessfulObservationUtc"}) {
		record.GetNamedObject( field).SetNamedValue( L"reason",
												   CapacityValue::CreateStringValue( L"u")) ;
	}

	// 未観測hashとsizeの理由を空へ置き換えず最小表現へ揃えます。
	for( const auto field : {L"publishedHash", L"calculatedHash", L"size"}) {
		record.GetNamedObject( L"packageEvidence")
			.GetNamedObject( field)
			.SetNamedValue( L"reason", CapacityValue::CreateStringValue( L"u")) ;
	}

	record.GetNamedObject( L"publishedIdentityEvidence")
		.SetNamedValue( L"reason", CapacityValue::CreateStringValue( L"u")) ;
	auto templateManifest =
		makeStoreInputs( key,
						distributionIndex( recordSource(), recordEntry( key, distributionRecord())))
			.manifest.data() ;	// 共通manifest値の型と原期限です。
	std::string entries ;		// 全recordの正しい原hashを保持します。
	std::size_t rawBytes{} ;	// byte上限が先に当たらない独立性を確認します。
	// 合法な一意recordを上限ちょうどと一件超過まで原順に作ります。
	for( std::size_t ordinal = 0U; ordinal <= index_capacity::RECORDS; ++ordinal) {
		record.SetNamedValue( L"recordId",
							 CapacityValue::CreateStringValue( L"r" + std::to_wstring( ordinal))) ;
		const auto raw = winrt::to_string( record.Stringify()) ;	// 同schemaの一意recordです。
		rawBytes += raw.size() ;
		// 二件目以降だけcommaを加え、元entryを連結します。
		if( !entries.empty()) {
			entries += ',' ;
		}

		entries += recordEntry( key, raw) ;
		// 境界到達前には巨大codecを反復せず、二つの独立条件だけを検査します。
		if( ordinal + 1U < index_capacity::RECORDS) {
			continue ;
		}

		const auto count = ordinal + 1U ;	// 上限ちょうどと+1の二条件だけです。
		const auto index =
			// 原source参照が全件一致します。
			distributionIndex( recordSource( "s"), entries) ;
		DRIVERCRATE_EXPECT( context, rawBytes <= index_capacity::TOTAL_RECORD_BYTES &&
										index.size() <= index_capacity::EXPANDED_BYTES) ;
		// 値codecの閉品質分母です。
		templateManifest.quality = {1U, count, 0U, 0U, count} ;
		// 原hashと全schema条件を検査した共通codec結果です。
		const auto decoded = signed_index_detail::decodeIndexRecordsData(
			templateManifest, std::as_bytes( std::span{index.data(), index.size()}), NOW) ;
		DRIVERCRATE_EXPECT( context, count == index_capacity::RECORDS
										? decoded.status == IndexRecordsStatus::SCHEMA_VALIDATED &&
											  decoded.data && decoded.data->records.size() == count
										: decoded.status == IndexRecordsStatus::COUNT_LIMIT &&
											  !decoded.data) ;
	}

	std::cout
		<< "CAPACITY_RECORD_COUNT {\"normal\":65536,\"rejected\":65537,\"rawRecordBytesPlusOne\":"
		<< rawBytes
		<< ",\"valueCodecOnly\":true,\"assertions\":" << context.assertionCount() - before << "}\n" ;
}

//------------------------------------------------------------------------------
/**
 * @brief native producer原fileをRAM署名/隔離store/通常scan/planへ接続します。
 * @param[in,out] context 共通集計先です。
 * @param[in] directory 私有native producerの保存先です。
 */
//------------------------------------------------------------------------------
void runIndexCapacityProducedConsumerTests( TestContext				   &context,
										   const std::filesystem::path &directory)
{
	// 名称のない同processのsoftware RAM鍵です。
	RamKey key ;
	// production鍵とは独立した同process RAMだけです。
	key.generate( 3072U) ;
	auto fixture = [&] {
		const auto nativeRaw =
			// native producer原byteです。
			capacityRead( directory / L"manifest.raw.json") ;
		const auto gzipRaw =
			// 元gzipをそのまま使用します。
			capacityRead( directory / L"index.json.gz") ;
		DRIVERCRATE_EXPECT( context, nativeRaw.size() <= INDEX_MANIFEST_MAX_BYTES &&
										gzipRaw.size() > 16U * 1024U * 1024U &&
										gzipRaw.size() <= index_capacity::GZIP_BYTES) ;
		const auto gzip = std::as_bytes(
			std::span{gzipRaw.data(), gzipRaw.size()}) ;	// hash/CRCと展開も同byteです。
		{
			const auto unsignedValue = validateUnsignedIndexCandidate(
				nativeRaw, gzip, CAPACITY_NOW) ;	// 元manifestも本unsigned codecで確認します。
			DRIVERCRATE_EXPECT( context,
							   unsignedValue.receipt &&
								   unsignedValue.receipt->manifest.quality.recordCount == 605U) ;
		}
		// 既beginFixtureはfixture-mainだけを受けます。原gzip/record/hash/期限を保ち、RAM用keyIdだけを分けます。
		const auto fixtureRaw = replaced(
			nativeRaw, "\"keyId\":\"" + std::string{index_distribution_trust::KEY_ID} + "\"",
			"\"keyId\":\"fixture-main\"") ;
		const auto wire =
			// 元本番署名や鍵を利用しません。
			envelope( fixtureRaw, key.sign( fixtureRaw)) ;
		// 本番storeへ配置しないfixtureだけのRAM公開blobです。
		const std::array<signed_index_detail::TrustKey, 1U> trust{
			{{"fixture-main", key.publicBlob}}} ;
		// 同RAM trustが元署名byteを検査した結果です。
		const auto authenticated =
			signed_index_detail::authenticateWithTrustKeys( wire, CAPACITY_NOW, std::nullopt, trust) ;
		DRIVERCRATE_EXPECT( context, authenticated.manifest.has_value()) ;
		// RAM署名不成立を後段storeの空結果で隠しません。
		if( !authenticated.manifest) {
			throw std::runtime_error( "native producer fixture manifest rejected") ;
		}

		const auto decoded = [&] {
			const auto asset = authenticateIndexAssetBytes(
				*authenticated.manifest, gzip, CAPACITY_NOW) ;	// 元hash/サイズ/比率/CRCです。
			// 実gzip検査不成立からrecords receiptを作りません。
			if( !asset.receipt) {
				throw std::runtime_error( "native producer fixture gzip rejected") ;
			}

			return readSignedIndexRecords( *asset.receipt, CAPACITY_NOW) ;
		}() ;
		DRIVERCRATE_EXPECT( context, decoded.receipt.has_value()) ;
		// 原record/hash/期限の拒否をconsumer未実行の成功へ置き換えません。
		if( !decoded.receipt) {
			throw std::runtime_error( "native producer fixture records rejected") ;
		}

		std::size_t inputs{} ;	// 全原IDを数え、生成側の申告だけを分母にしません。
		std::string tailId ;	// 元synthetic recordの最後の照合素材だけです。
		// 全recordの実公開IDを集計し、最後の合成照合素材を選びます。
		for( const auto &record : decoded.receipt->records()) {
			inputs += record.publishedIdentityEvidence.pnpIds.size() ;
			// 架空classとIDを持つ原recordだけをnative低位fixtureへ結びます。
			if( record.publishedIdentityEvidence.classGuid ==
				   "{11111111-2222-3333-4444-555555555555}" &&
			   !record.publishedIdentityEvidence.pnpIds.empty()) {
				tailId = record.publishedIdentityEvidence.pnpIds.back().value ;
			}
		}

		DRIVERCRATE_EXPECT( context, inputs == 1000000U && !tailId.empty()) ;
		const IndexLookupContext probeContext{11U, 12U, 13U} ;			// 架空診断だけのcontextです。
		const std::array<std::wstring, 1U> present{L"probe-opaque"} ;	// 実inventoryではありません。
		CapacityResolver probeResolver ;								// 認証/導入能力を持たない同期診断fakeです。
		probeResolver.mode	 = 3U ;
		probeResolver.tailId = tailId ;
		const auto probe =
			unsigned_index_probe_detail::probe( decoded.receipt->records(), probeContext, present,
											   probeResolver) ;	// CLIと同じ集計です。
		DRIVERCRATE_EXPECT( context, probe.completed && probe.calls == 1000000U &&
										probe.rows.size() == 605U && probe.matchedRecords == 1U &&
										probeResolver.calls == 1000000U) ;
		{
			std::vector<IndexDistributionRecord> tooMany(
				257U) ;	// 原4096IDの反復で次record全体を一件超過させます。
			// 既codec済みの4096個の公開値だけを診断guardへ渡します。新認証receiptは作りません。
			for( const auto &record : decoded.receipt->records()) {
				// 既codec済みの最大4096IDを持つ原recordだけで診断の総枠を構成します。
				if( record.publishedIdentityEvidence.pnpIds.size() == index_capacity::RECORD_IDS) {
					// 全行へ同じ元公開値を複写し、診断callerの次record拒否を確認します。
					for( auto &row : tooMany) {
						row.publishedIdentityEvidence = record.publishedIdentityEvidence ;
					}

					break ;
				}
			}

			probeResolver.mode	= 0U ;
			probeResolver.calls = 0U ;
			const auto rejected = unsigned_index_probe_detail::probe(
				tooMany, probeContext, present, probeResolver) ;	// 全体枠は製品と同じ固定値です。
			DRIVERCRATE_EXPECT( context,
							   !rejected.completed &&
								   rejected.calls == index_capacity::WHOLE_PUBLIC_IDS &&
								   rejected.rows.size() == 256U &&
								   probeResolver.calls == index_capacity::WHOLE_PUBLIC_IDS) ;
		}
		std::cout
			<< "CAPACITY_PROBE {\"inputs\":1000000,\"records\":605,\"positiveRecords\":1,\"nextWholeRecordRejected\":true,\"authenticated\":false,\"realInventory\":false}\n" ;

		auto opened = signed_index_store_detail::Access::createIsolated(
			trust) ;	// 実保護storeは新private rootだけです。
		// 隔離store初期化の失敗を保存成功へ数えません。
		if( !opened.store) {
			throw std::runtime_error( "native producer isolated store unavailable") ;
		}

		// 同原byteを実再認証して隔離storeへ保存した結果です。
		const auto committed = opened.store->commit( *decoded.receipt, wire, gzip, CAPACITY_NOW) ;
		DRIVERCRATE_EXPECT( context, committed.snapshot.has_value()) ;
		std::cout << "CAPACITY_PRODUCED_WIRE {\"nativeManifestSha256\":\""
				  << recordDigest( key, nativeRaw) << "\",\"fixtureManifestSha256\":\""
				  << recordDigest( key, fixtureRaw)
				  << "\",\"fixtureKeyIdOnlyChanged\":true,\"gzipSha256\":\""
				  << recordDigest( key, gzipRaw) << "\",\"productionSignatures\":0}\n" ;
		return CapacityFixture{std::shared_ptr<SignedIndexStore>{std::move( opened.store)},
							   decoded.receipt->records().size(), inputs, std::move( tailId)} ;
	}() ; // codec/commit一時所有を閉じてから本consumerが原storeをreloadします。
	// 本native scanの全record/IDと停止理由の匿名分母です。
	const auto summary =
		runIndexCapacityNativeScan( context, fixture.store, CAPACITY_NOW, fixture.records,
								   fixture.inputs, fixture.tailId, false, false) ;
	DRIVERCRATE_EXPECT( context, summary.status == IndexScanStatus::COMPLETED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 旧368原byteを保持し全ID/record容量とnative matcherを有限確認します。
 * @param[in,out] context 共通assertion集計先です。
 * @param[in] baselineIndex 764基準から作った私有base368/index.jsonです。
 * @param[in] requestedInputs 0は旧上限超/境界matrix、正値はその全公開ID数です。
 * @param[in] large trueは4096nodeの完全低位fakeを使います。
 * @param[in] realClock trueだけ実時間/メモリ性能を受入分母にします。
 * @param[in] tailUnknown trueだけ全入力枠消費後に0-ID UNKNOWNを追加します。
 * @note 実鍵/store/inventory/通信/導入を使用せずRAM署名の隔離storeだけです。
 */
//------------------------------------------------------------------------------
void runIndexCapacityTests( TestContext &context, const std::filesystem::path &baselineIndex,
						   std::size_t requestedInputs, bool large, bool realClock,
						   bool tailUnknown)
{
	RamKey key ;	// 名前を持たない既software fixtureだけです。
	key.generate( 3072U) ;
	const auto requested =
		// 旧32768の直後にpositiveを置きます。
		requestedInputs == 0U ? 32769U : requestedInputs ;
	// 原byteと全IDを保持する私有storeだけの所有結果です。
	auto fixture = capacityFixture( context, key, baselineIndex, requested, tailUnknown) ;
	// 上限+1は署名済みassetのcodec拒否だけを確認し、端末処理へ進めません。
	if( requested > index_capacity::WHOLE_PUBLIC_IDS) {
		return ;
	}

	// 本native scanの全record/IDと停止理由の匿名分母です。
	const auto summary =
		runIndexCapacityNativeScan( context, fixture.store, CAPACITY_NOW, fixture.records,
								   fixture.inputs, fixture.tailId, large, realClock) ;
	DRIVERCRATE_EXPECT( context, summary.status == (tailUnknown ? IndexScanStatus::PARTIAL
															   : IndexScanStatus::COMPLETED)) ;
	// 機能matrixだけが境界と最後のprogress取消しを追加し、実測を反復しません。
	if( requestedInputs == 0U) {
		capacityRecordBoundaries( context, key) ;
		auto loaded = fixture.store->reload( CAPACITY_NOW) ;	// 元storeの実再認証です。
		DRIVERCRATE_EXPECT( context, loaded.snapshot.has_value()) ;
		// empty/unissued前提をcoverage成功へ補完しません。
		if( !loaded.snapshot) {
			throw std::runtime_error( "capacity lease reload unavailable") ;
		}

		runIndexCapacityNativeLeaseChecks(
			context,
			std::make_shared<const AuthenticatedIndexSnapshot>( std::move( *loaded.snapshot)),
			CAPACITY_NOW) ;
		static_cast<void>( runIndexCapacityNativeScan( context, fixture.store, CAPACITY_NOW,
													 fixture.records, fixture.inputs,
													 fixture.tailId, false, false, true)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief positive/UNKNOWN/native projectionの保持32768/32769を確認します。
 * @param[in,out] context 共通集計先です。
 */
//------------------------------------------------------------------------------
void runIndexCapacityRetainedTests( TestContext &context)
{
	// 名称を持たない同processだけのsoftware RAM鍵です。
	RamKey key ;
	// 同processだけのRAM鍵です。
	key.generate( 3072U) ;
	std::vector<std::string> rows ;			// 一record4096以下の正規v1原byteです。
	std::size_t				 ordinal{} ;	// 架空公開IDを一意にする位置です。
	// 八件4096IDと最後の一IDで32768/32769を独立に作ります。
	for( unsigned row = 0U; row < 9U; ++row) {
		auto		  record = CapacityObject::Parse( winrt::to_hstring(
			 // 一意recordです。
			 distributionRecord( "retained-" + std::to_string( row)))) ;
		CapacityArray ids ;	// このrecordだけの公開IDです。
		// IDを間引かず元ordinal順に全件追加します。
		for( unsigned index = 0U; index < (row == 8U ? 1U : 4096U); ++index) {
			CapacityObject id ;	// 架空公開値だけです。
			id.SetNamedValue( L"kind", CapacityValue::CreateStringValue( L"HARDWARE")) ;
			id.SetNamedValue( L"value", CapacityValue::CreateStringValue(
										   winrt::to_hstring( capacityId( ordinal++)))) ;
			ids.Append( id) ;
		}

		record.GetNamedObject( L"publishedIdentityEvidence").SetNamedValue( L"pnpIds", ids) ;
		rows.push_back( winrt::to_string( record.Stringify())) ;
	}

	const IndexLookupContext		   active{11U, 12U, 13U} ;			// fake診断の同contextです。
	const std::array<std::wstring, 1U> present{L"retained-opaque"} ;	// 実端末値を含みません。
	// positiveと未完了を別々に保持し、UNKNOWNを不一致へcompactしません。
	for( const unsigned mode : {1U, 2U}) {
		// positive又はUNKNOWNを返す架空の同期callbackです。
		CapacityResolver resolver ;
		// 同期fakeだけです。
		resolver.mode			 = mode ;
		const auto exactSnapshot = lookupSnapshot( key, rows.front(), 8U, nullptr, 9U,
												  std::span{rows}.first( 8U)) ;	// 正常32768IDです。
		const auto exact = lookupSignedIndexRecords( exactSnapshot, active, active, present, {}, NOW,
													&resolver) ;	// 元全recordが完了します。
		DRIVERCRATE_EXPECT( context, exact.lookup && exact.lookup->relations().size() == 32768U &&
										exact.lookup->progress().processedPublicIds == 32768U &&
										exact.lookup->progress().completedRecords == 8U) ;
		// 正例不成立でprivate凍結の意味を変えません。
		if( !exact.lookup) {
			throw std::runtime_error( "retained exact lookup rejected") ;
		}

		DRIVERCRATE_EXPECT( context, signed_index_acquisition_detail::Access::freezeFixture(
										exactSnapshot, active, std::span{&*exact.lookup, 1U}, NOW)
										.lookup.has_value()) ;
		const auto overflow = lookupSnapshot( key, rows.front(), 9U, nullptr, 9U,
											 rows) ;	// 最後の一IDを落とさない別snapshotです。
		const auto first	= lookupSignedIndexRecords( overflow, active, active, present, {}, NOW,
													   &resolver) ;	// 先頭八recordだけをcommitします。
		DRIVERCRATE_EXPECT( context, first.lookup &&
										first.lookup->progress().nextRecordOffset == 8U &&
										first.lookup->relations().size() == 32768U) ;
		IndexLookupBudget remaining ;	// 元残枠を次batchへ渡します。
		remaining.recordOffset	   = 8U ;
		remaining.maximumRelations = 0U ;
		remaining.maximumRelatedIdentities =
			mode == 1U ? 0U : index_capacity::RETAINED_OPAQUE_IDENTITIES ;
		const auto stopped = lookupSignedIndexRecords( overflow, active, active, present, remaining,
													  NOW, &resolver) ;	// 超過を切り詰めません。
		DRIVERCRATE_EXPECT( context, stopped.lookup && stopped.lookup->relations().empty() &&
										stopped.lookup->progress().completedRecords == 0U &&
										stopped.lookup->progress().nextRecordOffset == 8U &&
										stopped.lookup->progress().stopReason ==
											IndexLookupStopReason::RETAINED_CAPACITY) ;
		std::cout << "CAPACITY_RETAINED {\"mode\":" << mode
				  << ",\"normal\":32768,\"nextId32769Rejected\":true,\"remainingRecords\":1}\n" ;
	}

	// 小さい保持境界の一時byteを次の独立fixtureへ持ち越しません。
	rows.clear() ;
	// 二uniqueと5461cohort recordで、cohort全copyのopaqueが32768に一致します。
	for( std::size_t index = 0U; index < 5464U; ++index) {
		auto raw =
			// 正規v1の一意recordです。
			distributionRecord( "projection-" + std::to_string( index)) ;
		// 中間recordは両nodeのCompatible原集合へ一致し、全二proofを投影します。
		if( index >= 2U && index < 5463U) {
			raw = replaced( std::move( raw), "TESTBUS\\\\SYNTH_0001",
						   "TESTBUS\\\\NATIVE_COMPATIBLE_OTHER") ;
		}

		rows.push_back( std::move( raw)) ;
	}

	// 全prefix正常と、一opaqueだけ超える末尾record停止を分けます。
	for( const bool overflowing : {false, true}) {
		const auto count = overflowing ? 5464U : 5463U ;	// 元record数です。
		const auto snapshot =
			lookupSnapshot( key, rows.front(), count, nullptr, 9U,
						   std::span{rows}.first( count)) ;	// 全hash/codec/storeを通します。
		runIndexCapacityProjectionBoundary( context, snapshot, NOW, overflowing) ;
	}
}
} // namespace drivercrate::test
