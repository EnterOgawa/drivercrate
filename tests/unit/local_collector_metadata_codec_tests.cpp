//------------------------------------------------------------------------------
/**
 * @file local_collector_metadata_codec_tests.cpp
 * @brief 全field往復と元scope関係の改変拒否を検証します。
 * @version 01.00.01
 * @date 2026/09/29
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  実worker結果の往復と関係改変を追加。
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 成功DTOはworkerへ注入しません。改変はcodecの拒否試験専用です。
 */
//------------------------------------------------------------------------------
#include "local_collector_metadata_codec_tests.h"
#include "platform/official_file_verifier.h"
#include <functional>

namespace drivercrate::test {
namespace {
/**
 * @brief 投影JSON codecの成否と元診断を保持する。
 */
using Status = collector_projected_json::Status ;
/**
 * @brief 解析済みmetadataと元観測の値を所有し、codecへ渡す。
 */
using Document = CollectorMetadataDocument ;

/**
 * @brief 改変byteを新hashでも救済せず、型付きreaderが拒否することを確認します。
 * @param[in,out] context 同期試験のassertionと失敗数の集計先。試験中だけ借用する。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] bytes 拒否を期待する改変metadataの借用byte view。
 */
void rejectBytes( TestContext &context, const CollectorProjectedJobInput &job,
				 std::string_view bytes)
{
	std::wstring hash ;	// 改変後に再計算する独立CNG hash。
	DRIVERCRATE_EXPECT( context, computeBytesSha256( bytes, hash) == 0 &&
									collector_projected_json::isHash( hash)) ;
	Document decoded ;	// 失敗時の出力消去を確認する先行値。
	decoded.records.resize( 1U) ;
	DRIVERCRATE_EXPECT( context, decodeCollectorMetadata( job, bytes, decoded).status != Status::OK) ;
	DRIVERCRATE_EXPECT( context, decoded.records.empty() && decoded.slices.empty() &&
									decoded.edges.empty() && !decoded.diagnostics.counts) ;
}
/**
 * @brief 一つの固定文字列を差し替え、変更箇所が実在したことも検査します。
 * @param[in,out] context 同期試験のassertionと失敗数の集計先。試験中だけ借用する。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] bytes 複製して一箇所を改変する元byte。
 * @param[in] from 元byteに必ず存在させる置換前文字列。
 * @param[in] to 拒否を期待する置換後文字列。
 */
void replaceAndReject( TestContext &context, const CollectorProjectedJobInput &job,
					  const std::string &bytes, std::string_view from, std::string_view to)
{
	std::string changed	 = bytes ;					// 成功byteを変更しない複製。
	const auto	position = changed.find( from) ;	// 固定fieldの位置。
	DRIVERCRATE_EXPECT( context, position != std::string::npos) ;
	// 見つからない場合も先行assertionを失敗として保持します。
	if( position == std::string::npos) {
		return ;
	}

	changed.replace( position, from.size(), to) ;
	rejectBytes( context, job, changed) ;
}
/**
 * @brief 一つの所有field改変をwriterが出力前に拒否します。
 * @param[in,out] context 同期試験のassertionと失敗数の集計先。試験中だけ借用する。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] original 複製前の正常metadata値。
 * @param[in] mutate 複製だけを同期中に改変するcallback。借用参照を保持しない。
 */
void rejectDocument( TestContext &context, const CollectorProjectedJobInput &job,
					const Document &original, const std::function<void( Document &)> &mutate)
{
	Document changed = original ;	// 拒否試験だけの複製。
	mutate( changed) ;
	std::string bytes = "stale" ;	// 失敗時消去を確認。
	DRIVERCRATE_EXPECT( context,
					   encodeCollectorMetadata( job, changed, bytes).status == Status::INVALID &&
						   bytes.empty()) ;
}
/**
 * @brief Codecの有限形の往復だけを検査し、親受入へ流用しません。
 * @param[in,out] context 同期試験のassertionと失敗数の集計先。試験中だけ借用する。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] document Encode/decode往復を確認する正常metadata値。
 */
void roundTrip( TestContext &context, const CollectorProjectedJobInput &job,
			   const Document &document)
{
	std::string encoded ;	// Canonical metadata。
	Document	decoded ;	// 型付き復元値。
	std::string repeated ;	// 復元値の独立再符号化。
	DRIVERCRATE_EXPECT( context,
					   encodeCollectorMetadata( job, document, encoded).status == Status::OK) ;
	DRIVERCRATE_EXPECT( context,
					   decodeCollectorMetadata( job, encoded, decoded).status == Status::OK) ;
	DRIVERCRATE_EXPECT( context,
					   encodeCollectorMetadata( job, decoded, repeated).status == Status::OK &&
						   repeated == encoded) ;
}
} // namespace

/** @see local_collector_metadata_codec_tests.h */
void runCollectorMetadataCodecChecks( TestContext &context, const CollectorProjectedJobInput &job,
									 const CollectorProjectedWorkerResult &worker)
{
	DRIVERCRATE_EXPECT( context,
					   worker.reason == CollectorProjectedWorkerReason::NONE && worker.parser) ;
	// 成功観測を作り直してcodecへ渡しません。
	if( worker.reason != CollectorProjectedWorkerReason::NONE || !worker.parser) {
		return ;
	}

	Document   document ;	// 実workerの正常draftからだけ構築。
	const auto made = makeCollectorMetadataDocument( job, worker.projection, *worker.parser,
													document) ;	// 非保存変換。
	context.expect( made.status == Status::OK, "metadata actual worker conversion", __FILE__,
				   __LINE__) ;
	// 後続assertionの連鎖障害を避けても元失敗を保持します。
	if( made.status != Status::OK) {
		return ;
	}

	// 300対象×16参照は件数内でも512 KiBを超えます。親の縮約・保存は後続工程です。
	if( document.edges.size() == 300U && document.records.size() == 16U) {
		std::string oversized = "stale" ;	// 途中byteを公開しない出力。
		DRIVERCRATE_EXPECT( context, encodeCollectorMetadata( job, document, oversized).status ==
											Status::SIZE_LIMIT &&
										oversized.empty()) ;
		DRIVERCRATE_EXPECT( context, worker.projection.edges.size() == 300U &&
										worker.projection.records.size() == 16U) ;
		return ;
	}

	roundTrip( context, job, document) ;
	std::string encoded ;	// 元成功byte。
	DRIVERCRATE_EXPECT( context,
					   encodeCollectorMetadata( job, document, encoded).status == Status::OK) ;
	DRIVERCRATE_EXPECT( context, encoded.size() <= collector_projected_json::METADATA_LIMIT &&
									encoded.find( "https:") == std::string::npos &&
									encoded.find( "file:") == std::string::npos) ;
	DRIVERCRATE_EXPECT( context,
					   document.edges.size() == job.targets.size() && document.diagnostics.counts &&
						   document.diagnostics.counts->edges == job.targets.size() &&
						   document.binding.body == worker.http.bodySha256 &&
						   document.binding.validatedUtc == worker.projection.validatedUtcMillis) ;
	// 全field型・順序・未知field・改変hashの拒否を同じreaderで検査します。
	replaceAndReject( context, job, encoded, "\"researchOnly\":true", "\"researchOnly\":false") ;
	replaceAndReject( context, job, encoded, "\"publishable\":false", "\"publishable\":true") ;
	replaceAndReject( context, job, encoded, "\"downloadEligible\":false",
					 "\"downloadEligible\":true") ;
	replaceAndReject( context, job, encoded, "\"researchOnly\":true", "\"researchOnly\":1") ;
	replaceAndReject( context, job, encoded, "\"researchOnly\":true",
					 "\"researchOnly\":true,\"researchOnly\":true") ;
	replaceAndReject( context, job, encoded, "\"profile\":", "\"unknown\":null,\"profile\":") ;
	replaceAndReject( context, job, encoded, "\"schema\":", "\"schemaMissing\":") ;
	replaceAndReject( context, job, encoded, "\"form\":\"FULL\"", "\"form\":\"FUTURE\"") ;
	replaceAndReject( context, job, encoded, "\"workerReason\":\"NONE\"",
					 "\"workerReason\":\"IO_FAILURE\"") ;
	replaceAndReject( context, job, encoded, "\"limitStage\":\"NONE\"", "\"limitStage\":\"WORKER\"") ;
	replaceAndReject( context, job, encoded, "\"researchOnly\":true,\"publishable\":false",
					 "\"publishable\":false,\"researchOnly\":true") ;
	rejectBytes( context, job, encoded + " ") ;
	replaceAndReject( context, job, encoded,
					 "\"maximumReferences\":" +
						 std::to_string( document.diagnostics.counts->maximumReferences),
					 "\"maximumReferences\":99") ;
	replaceAndReject( context, job, encoded,
					 "\"reasonCode\":" + std::to_string( document.edges.front().reasonCode),
					 "\"reasonCode\":99") ;
	replaceAndReject( context, job, encoded,
					 "\"scope\":\"" + winrt::to_string( document.binding.scope) + "\"",
					 "\"scope\":\"" + std::string( 64U, 'f') + "\"") ;
	rejectDocument( context, job, document,
				   []( Document &value) { value.binding.scope.assign( 64U, L'f') ; }) ;
	rejectDocument( context, job, document,
				   []( Document &value) { value.binding.cache.assign( 64U, L'f') ; }) ;
	rejectDocument( context, job, document,
				   []( Document &value) { value.binding.body.assign( 64U, L'f') ; }) ;
	rejectDocument( context, job, document,
				   []( Document &value) { value.binding.source = L"OTHER" ; }) ;
	rejectDocument( context, job, document,
				   []( Document &value) { value.binding.validatedUtc.reset() ; }) ;
	rejectDocument( context, job, document,
				   []( Document &value) { value.diagnostics.counts.reset() ; }) ;
	rejectDocument( context, job, document,
				   []( Document &value) { value.diagnostics.source.reset() ; }) ;
	rejectDocument( context, job, document,
				   []( Document &value) { value.diagnostics.parser.reset() ; }) ;
	rejectDocument( context, job, document,
				   []( Document &value) { value.diagnostics.source->status = 99U ; }) ;
	rejectDocument( context, job, document,
				   []( Document &value) { value.diagnostics.counts->edges += 1U ; }) ;
	rejectDocument( context, job, document,
				   []( Document &value) { value.slices.front().scope.key = L"changed" ; }) ;
	rejectDocument( context, job, document, []( Document &value) {
		value.slices.front().complete = !value.slices.front().complete ;
	}) ;
	rejectDocument( context, job, document,
				   []( Document &value) { value.edges.front().target.target.model += L" other" ; }) ;
	rejectDocument( context, job, document,
				   []( Document &value) { value.edges.front().target.index += 1U ; }) ;
	rejectDocument( context, job, document,
				   []( Document &value) { value.edges.front().identityParser += L"x" ; }) ;
	rejectDocument( context, job, document,
				   []( Document &value) { value.edges.front().recordParser += L"x" ; }) ;
	rejectDocument( context, job, document,
				   []( Document &value) { value.edges.front().matchingRule += L"x" ; }) ;
	rejectDocument( context, job, document,
				   []( Document &value) { value.edges.front().reasonCode = 99U ; }) ;
	rejectDocument( context, job, document,
				   []( Document &value) { value.edges.front().sourceDisplayName = L"" ; }) ;
	// 存在するidentityでも元sourceの公開ID文法と比較名を検査します。
	if( document.edges.front().sourceProductId) {
		rejectDocument( context, job, document, []( Document &value) {
			value.edges.front().sourceProductId = L"invalid-id" ;
		}) ;
		rejectDocument( context, job, document, []( Document &value) {
			value.edges.front().sourceComparisonName = L"other" ;
		}) ;
	}

	rejectDocument( context, job, document, []( Document &value) {
		value.edges.pop_back() ;
		value.diagnostics.counts->edges -= 1U ;
	}) ;
	// 元二配列の九fieldそれぞれの差を成功byteへ隠しません。
	if( !document.records.empty()) {
		const auto marker = encoded.find( "\"fingerprint\":\"") ;	// 元内部指紋のfield。
		DRIVERCRATE_EXPECT( context, marker != std::string::npos) ;
		// 有効hexと再計算hashだけを残してedge参照との不一致を作ります。
		if( marker != std::string::npos) {
			std::string changed = encoded ;	// Canonical順序を保持する改変。
			const auto	position =
				marker + std::string_view( "\"fingerprint\":\"").size() ;	// 最初のhex位置。
			changed[position] = changed[position] == '0' ? '1' : '0' ;
			rejectBytes( context, job, changed) ;
		}

		const std::vector<std::function<void( OfficialCollectorPayloadProjection &)>> mutations{
			[]( auto &value) { value.resourceId += L"x" ; },
			[]( auto &value) { value.payloadOrdinal += 1U ; },
			[]( auto &value) { value.kind = OfficialDistributionPayloadKind::UNSUPPORTED ; },
			[]( auto &value) { value.fileDisplayName += L"x" ; },
			[]( auto &value) { value.publishedSizeBytes = 999U ; },
			[]( auto &value) { value.publishedSha256 = L"bad" ; },
			[]( auto &value) { value.publishedSha512 = L"bad" ; },
			[]( auto &value) { value.publisher += L"x" ; },
			[]( auto &value) { value.expectedContentType += L"x" ; }} ;	// 一方だけの改変集合。
		// 見かけの長さ一致だけで二配列を受理しません。
		for( const auto &mutation : mutations) {
			rejectDocument( context, job, document, [&]( Document &value) {
				mutation( value.records.front().payloads.front().value) ;
			}) ;
			auto draft = worker.projection ;	// 親変換入口の改変コピー。
			mutation( draft.records.front().payloads.front().value) ;
			Document refused ;	// 成功へ変換されない出力。
			DRIVERCRATE_EXPECT(
				context,
				makeCollectorMetadataDocument( job, draft, *worker.parser, refused).status ==
						Status::INVALID &&
					refused.records.empty()) ;
		}

		rejectDocument( context, job, document, []( Document &value) {
			value.records.front().payloads.front().payloadLinkValidated = false ;
		}) ;
		rejectDocument( context, job, document,
					   []( Document &value) { value.records.front().value.parserRevision += 1U ; }) ;
		rejectDocument( context, job, document,
					   []( Document &value) { value.records.front().value.recordKey = L"wrong" ; }) ;
		rejectDocument( context, job, document, []( Document &value) {
			value.records.front().value.productFamily = L"https://example.invalid/x" ;
		}) ;
		rejectDocument( context, job, document, []( Document &value) {
			value.records.front().value.dependencies.resize( 33U, L"dependency") ;
		}) ;
		rejectDocument( context, job, document,
					   []( Document &value) { value.records.push_back( value.records.front()) ; }) ;
		replaceAndReject( context, job, encoded, "\"payloadOrdinal\":0", "\"payloadOrdinal\":1") ;
		replaceAndReject( context, job, encoded, "\"payloadLinkValidated\":true",
						 "\"payloadLinkValidated\":false") ;
		replaceAndReject( context, job, encoded, "\"architecture\":\"WINDOWS_X64\"",
						 "\"architecture\":\"ARM64\"") ;
		replaceAndReject( context, job, encoded,
						 "\"parserRevision\":", "\"parserRevision\":0,\"ignored\":") ;
	}

	// 空形の各fieldも型付きcodecで往復します。元I/O受入ではありません。
	Document empty = document ;	// 正常値とは別の純粋codec fixture。
	empty.records.clear() ;
	empty.slices.clear() ;
	empty.edges.clear() ;
	empty.binding.body.clear() ;
	empty.binding.validatedUtc.reset() ;
	empty.diagnostics = {} ;
	empty.complete	  = true ;
	empty.outcome	  = CollectorMetadataOutcome::REVALIDATED ;
	empty.reason	  = CollectorMetadataReason::NONE ;
	roundTrip( context, job, empty) ;
	empty.complete = false ;
	empty.form	   = CollectorMetadataForm::MINIMAL_FAILURE ;
	empty.outcome  = CollectorMetadataOutcome::FAILED ;
	empty.reason   = CollectorMetadataReason::CACHE_BASIS_INVALID ;
	empty.error	   = CollectorMetadataError{CollectorMetadataErrorPhase::CACHE_BASIS,
											CollectorIoErrorDomain::PARSER, 1U} ;
	roundTrip( context, job, empty) ;
	empty.reason				   = CollectorMetadataReason::WORKER_FAILURE ;
	empty.error					   = CollectorMetadataError{CollectorMetadataErrorPhase::WORKER,
											CollectorIoErrorDomain::WIN32_ERROR, 5U} ;
	empty.diagnostics.workerReason = CollectorProjectedWorkerReason::IO_FAILURE ;
	roundTrip( context, job, empty) ;
	rejectDocument( context, job, empty,
				   []( Document &value) { value.diagnostics.counts = CollectorMetadataCounts{} ; }) ;
}
} // namespace drivercrate::test
