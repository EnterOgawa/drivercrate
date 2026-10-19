//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_cache_tests.cpp
 * @brief CACHEの拒否・保持・決定的更新を非通信検証します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  有限CACHE更新と旧中断互換のfixtureを追加。
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 通信・実成功CACHE保存・条件付き送信は行いません。
 */
//------------------------------------------------------------------------------
#include "local_collector_projected_cache_tests.h"
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <algorithm>
#include <array>

namespace drivercrate::test {
namespace {
/**
 * @brief 投影JSON codecの成否と元診断を保持する。
 */
using Status = collector_projected_json::Status ;
/**
 * @brief 投影jobへ結合するcache値を所有し、codecの読み書きへ渡す。
 */
using Cache = CollectorProjectedCache ;
/**
 * @brief 投影cacheの受理・拒否理由を保持する。
 */
using Reason = CollectorCacheReason ;
/**
 * @brief Hash処理が到達した段階を保持し、不完全な検証と完了を区別する。
 */
using Stage = CollectorProjectedHashStage ;
/** @brief 全fieldを固定byteで往復検査します。
 * @param[in,out] context Assertion集計。
 * @param[in] value 公開CACHE値。
 * @return 元canonical本文。
 */
std::string roundTrip( TestContext &context, const Cache &value)
{
	std::string body ;	// 元canonical本文。
	DRIVERCRATE_EXPECT( context, encodeCollectorProjectedCache( value, body).status == Status::OK) ;
	Cache decoded ;	// 独立readerの出力。
	DRIVERCRATE_EXPECT( context, decodeCollectorProjectedCache( body, decoded).status == Status::OK) ;
	std::string again ;	// 一字も変わらない再符号化。
	DRIVERCRATE_EXPECT( context,
					   encodeCollectorProjectedCache( decoded, again).status == Status::OK &&
						   body == again && body.size() <= 24U * 1024U) ;
	return body ;
}
/** @brief 固定構造の改変が空出力のまま拒否されることを確認します。
 * @param[in,out] context Assertion集計。
 * @param[in] original 元値。
 * @param[in] mutate 局所コピーだけを改変するcallback。
 * @param[in] expected 期待する固定失敗区分。
 */
void rejectValue( TestContext &context, const Cache &original,
				 const std::function<void( Cache &)> &mutate, Status expected = Status::INVALID)
{
	Cache changed = original ;	// このcaseだけの値。
	mutate( changed) ;
	std::string body = "stale" ;	// 失敗時に旧byteを残させません。
	DRIVERCRATE_EXPECT( context, encodeCollectorProjectedCache( changed, body).status == expected &&
									body.empty()) ;
}
/** @brief 旧WinRT中断生成と新codecが同一byteを返すことを検査します。
 * @param[in,out] context Assertion集計。
 */
void interruptedCompatibility( TestContext &context)
{
	using Object = winrt::Windows::Data::Json::JsonObject ;
	using Value	 = winrt::Windows::Data::Json::JsonValue ;
	const std::wstring			request( 64U, L'a') ;	// 架空の内部key。
	const std::wstring			binding( 64U, L'b') ;	// 架空のbinding。
	// 架空の別中断操作。
	const CollectorCacheAttempt attempt{std::wstring( 64U, L'c'), std::wstring( 64U, L'd'),
										std::wstring( 64U, L'e')} ;
	Object						legacy ;	// 旧実装と同じ挿入順を保持します。
	legacy.Insert( L"schema", Value::CreateStringValue( L"collector-campaign-cache-v1")) ;
	legacy.Insert( L"request", Value::CreateStringValue( request)) ;
	legacy.Insert( L"binding", Value::CreateStringValue( binding)) ;
	Object reference ;	// 元応答を直接指す三値。
	reference.Insert( L"generation", Value::CreateStringValue( attempt.generation)) ;
	reference.Insert( L"operation", Value::CreateStringValue( attempt.operation)) ;
	reference.Insert( L"response", Value::CreateStringValue( attempt.response)) ;
	legacy.Insert( L"attempt", reference) ;
	legacy.Insert( L"original200", Value::CreateNullValue()) ;
	legacy.Insert( L"slices", winrt::Windows::Data::Json::JsonArray()) ;
	legacy.Insert( L"validated", Value::CreateNullValue()) ;
	legacy.Insert( L"reusable", Value::CreateBooleanValue( false)) ;
	legacy.Insert( L"reason", Value::CreateStringValue( L"INTERRUPTED")) ;
	legacy.Insert( L"etag", Value::CreateNullValue()) ;
	Cache value ;	// 新入口の初回形。
	DRIVERCRATE_EXPECT(
		context, makeInterruptedCollectorCache( request, binding, attempt, nullptr, value).status ==
					 Status::OK) ;
	DRIVERCRATE_EXPECT( context, roundTrip( context, value) == winrt::to_string( legacy.Stringify())) ;
}
/** @brief 完全成功fixtureの不整合・有限上限・順序維持を検査します。
 * @param[in,out] context Assertion集計。
 * @param[in] job 元scope。
 * @param[in] bytes 元応答byte。
 * @param[in] cache tag付き全成功値。
 */
void strictChecks( TestContext &context, const CollectorProjectedJobInput &job,
				  const CollectorProjectedResponseBytes &bytes, const Cache &cache)
{
	const std::array<std::function<void( Cache &)>, 25> changes{
		[]( auto &v) { v.request.clear() ; },
		[]( auto &v) { v.binding.assign( 64U, L'G') ; },
		[]( auto &v) { v.attempt.generation.clear() ; },
		[]( auto &v) { v.attempt.operation.assign( 63U, L'a') ; },
		[]( auto &v) { v.attempt.response[0] = L'F' ; },
		[]( auto &v) { v.original200.reset() ; },
		[]( auto &v) { v.validated.reset() ; },
		[]( auto &v) { v.slices.clear() ; },
		[]( auto &v) { v.original200->body.clear() ; },
		[]( auto &v) { v.original200->headerUtc = 999U ; },
		[]( auto &v) { v.original200->headerUtc = 4102444800000ULL ; },
		[]( auto &v) { v.validated->headerUtc++ ; },
		[]( auto &v) { v.validated->projection.assign( 64U, L'f') ; },
		[]( auto &v) { v.validated->operation.assign( 64U, L'f') ; },
		[]( auto &v) { v.original200->generation.assign( 64U, L'f') ; },
		[]( auto &v) { v.attempt.operation.assign( 64U, L'f') ; },
		[]( auto &v) { v.slices[0].projection.clear() ; },
		[]( auto &v) { v.slices[0].slice.clear() ; },
		[]( auto &v) { v.slices[0].response.clear() ; },
		[]( auto &v) { v.slices.push_back( v.slices[0]) ; },
		[]( auto &v) { v.reusable = false ; },
		[]( auto &v) { v.etag.reset() ; },
		[]( auto &v) { v.etag = L"not-quoted" ; },
		[]( auto &v) { v.reason = Reason::INTERRUPTED ; },
		[]( auto &v) {
			v.reason = static_cast<Reason>( 999) ;
		}} ; // 正常全成功tag付きだけに適用する一要因変更。
	// 各一要因変更を独立した出力で試します。
	for( const auto &change : changes) {
		rejectValue( context, cache, change) ;
	}

	const auto original = roundTrip( context, cache) ;	// 改変前の保存候補byte。
	const std::array<std::function<void( std::string &)>, 9> mutations{
		[]( auto &s) { s += ' ' ; },
		[]( auto &s) { s.insert( 1U, "\"extra\":null,") ; },
		[]( auto &s) { s.insert( 1U, "\"schema\":\"collector-campaign-cache-v1\",") ; },
		[]( auto &s) { s.replace( s.find( "\"reusable\":true"), 15U, "\"reusable\":1") ; },
		[]( auto &s) { s.replace( s.find( "\"ACCEPTED\""), 10U, "\"REVALIDATED\"") ; },
		[]( auto &s) { s.insert( s.find( "\"headerUtc\":") + 12U, "-") ; },
		[]( auto &s) { s.insert( s.find( "\"headerUtc\":") + 12U, "0") ; },
		[]( auto &s) { s.insert( 0U, "\xef\xbb\xbf") ; },
		[]( auto &s) { s[s.size() / 2U] = '\0' ; }} ;	// 字句・重複・型・未対応理由・canonicalの改変。
	// Hash envelope外の本文にも厳密な固定形を要求します。
	for( const auto &mutate : mutations) {
		auto changed = original ;	// 旧byteは保持します。
		mutate( changed) ;
		Cache out = cache ;	// 失敗時に空へ戻ることを確認します。
		DRIVERCRATE_EXPECT( context,
						   decodeCollectorProjectedCache( changed, out).status != Status::OK &&
							   out.request.empty() && out.slices.empty() && !out.original200 &&
							   !out.etag) ;
	}

	Cache out ;	// 予算境界と更新拒否の出力。
	DRIVERCRATE_EXPECT(
		context, decodeCollectorProjectedCache( std::string( 24U * 1024U + 1U, ' '), out).status ==
					 Status::SIZE_LIMIT) ;
	auto before		= cache ;	// 過去成功を持つ無効形にして最新operationだけ変えます。
	before.reason	= Reason::INTERRUPTED ;
	before.reusable = false ;
	before.etag.reset() ;
	before.attempt.operation.assign( 64U, L'f') ;
	const auto seed = before.slices[0] ;	// 16参照の有限構造fixture。
	before.slices.clear() ;
	// 全て異なるkeyを作り、新要求keyを含めません。
	for( unsigned index = 0; index < 16U; ++index) {
		auto slice = seed ;	// 参照先実在を主張するfixtureではありません。
		slice.slice.assign( 64U, L"0123456789abcdef"[index]) ;
		before.slices.push_back( std::move( slice)) ;
	}

	roundTrip( context, before) ;
	DRIVERCRATE_EXPECT( context,
					   deriveCollectorProjectedCache( job, bytes.envelope, &before, out).status ==
							   Status::SIZE_LIMIT &&
						   out.request.empty() && out.slices.empty()) ;
	before.slices[7].slice = cache.slices[0].slice ;
	DRIVERCRATE_EXPECT(
		context,
		deriveCollectorProjectedCache( job, bytes.envelope, &before, out).status == Status::OK &&
			out.slices.size() == 16U && out.slices[7].response == cache.attempt.response &&
			out.slices[6].slice == before.slices[6].slice &&
			out.slices[8].slice == before.slices[8].slice) ;
	rejectValue(
		context, before, []( auto &v) { v.slices.push_back( v.slices[0]) ; }, Status::SIZE_LIMIT) ;
	before.request.assign( 64U, L'f') ;
	DRIVERCRATE_EXPECT( context,
					   deriveCollectorProjectedCache( job, bytes.envelope, &before, out).status ==
							   Status::INVALID &&
						   out.request.empty()) ;
	DRIVERCRATE_EXPECT( context,
					   deriveCollectorProjectedCache( job, bytes.envelope, &cache, out).status ==
							   Status::INVALID &&
						   out.request.empty()) ;
	// 同operationの中断再適用も拒否します。
	DRIVERCRATE_EXPECT( context, makeInterruptedCollectorCache( cache.request, cache.binding,
															  cache.attempt, &cache, out)
											.status == Status::INVALID &&
									out.request.empty()) ;
	// 読み込みhash二段の元値を、INVALIDやcache missにしません。
	for( const auto stage : {Stage::READ_RESPONSE, Stage::READ_METADATA}) {
		// OOM例外と元HRESULTを別々に注入します。
		for( unsigned mode = 0; mode < 3U; ++mode) {
			unsigned   calls{} ;	// 同一故障は一度だけ。
			// 更新導出の結果。
			const auto result = deriveCollectorProjectedCache(
				job, bytes.envelope, nullptr, out, [&]( Stage current) -> NativeError {
					// 対象外の段階は実CNGへ進めます。
					if( current != stage) {
						return 0 ;
					}

					++calls ;
					// 実allocation例外も有限境界で捕捉します。
					if( mode == 2U) {
						throw std::bad_alloc{} ;
					}

					return mode == 0U ? E_ACCESSDENIED : E_OUTOFMEMORY ;
				}) ; // 数値だけを返し、成功digestを注入しません。
			DRIVERCRATE_EXPECT(
				context,
				result.status == (mode == 0U ? Status::HASH_FAILURE : Status::OUT_OF_MEMORY) &&
					result.error == (mode == 0U ? E_ACCESSDENIED : E_OUTOFMEMORY) && calls == 1U &&
					out.request.empty()) ;
		}
	}

	DRIVERCRATE_EXPECT(
		context, deriveCollectorProjectedCache( job, bytes.envelope + " ", nullptr, out).status ==
						 Status::INVALID &&
					 out.request.empty()) ;
}
} // namespace

void runCollectorCacheChecks( TestContext &context, const CollectorProjectedJobInput &job,
							 const CollectorProjectedResponseBytes &bytes)
{
	Cache	   cache ;	// 初回の非保存値。
	// 更新導出の結果。
	const auto result = deriveCollectorProjectedCache( job, bytes.envelope, nullptr, cache) ;
	// 未接続の304成功を新200更新へ流用しません。
	if( bytes.value.state == CollectorMetadataOutcome::REVALIDATED) {
		DRIVERCRATE_EXPECT( context, result.status == Status::INVALID && cache.request.empty()) ;
		return ;
	}

	DRIVERCRATE_EXPECT( context, result.status == Status::OK) ;
	// 前提失敗後に空値のfieldを参照しません。
	if( result.status != Status::OK) {
		return ;
	}

	const auto saved = roundTrip( context, cache) ;	// 元値の不変性も最後に確認します。
	// 失敗・減少の理由を別区分へ読み替えないことを確認します。
	for( const auto &[metadataReason, cacheReason] : std::array{
			std::pair{CollectorMetadataReason::DECREASED, Reason::DECREASED},
			std::pair{CollectorMetadataReason::PROJECTION_LIMIT, Reason::PROJECTION_LIMIT},
			std::pair{CollectorMetadataReason::WORKER_FAILURE, Reason::WORKER_FAILURE},
			std::pair{CollectorMetadataReason::CACHE_BASIS_INVALID, Reason::CACHE_BASIS_INVALID},
			std::pair{CollectorMetadataReason::METADATA_HASH, Reason::METADATA_HASH}}) {
		DRIVERCRATE_EXPECT( context, (bytes.value.metadata.reason == metadataReason) ==
										(cache.reason == cacheReason)) ;
	}

	// 不成立304内の参照を新成功へ昇格せず、既存CACHEだけを保持します。
	if( bytes.value.status == 304U && bytes.value.state == CollectorMetadataOutcome::FAILED) {
		Cache prior ;	// 参照実在を主張しない構造fixtureです。
		prior.request = cache.request ;
		prior.binding = cache.binding ;
		prior.attempt = {std::wstring( 64U, L'a'), std::wstring( 64U, L'b'), std::wstring( 64U, L'c')} ;
		prior.original200 = CollectorProjectedOriginal200{
			prior.attempt.generation, prior.attempt.operation, prior.attempt.response,
			std::wstring( 64U, L'e'),  std::wstring( 64U, L'f'), 1000U} ;
		prior.validated =
			CollectorCacheValidation{prior.attempt.generation, prior.attempt.operation,
									 prior.attempt.response, prior.original200->projection, 1000U} ;
		prior.slices.push_back( {prior.attempt.generation, prior.attempt.operation,
								prior.attempt.response, prior.original200->projection,
								job.slices.front().key}) ;
		prior.reason		= Reason::ACCEPTED ;
		prior.reusable		= true ;
		prior.etag			= L"\"previous-tag\"" ;
		const auto oldBytes = roundTrip( context, prior) ;	// 以前の全成功を変更しません。
		Cache	   failed ;									// 失敗でも旧成功を消去しません。
		DRIVERCRATE_EXPECT(
			context, deriveCollectorProjectedCache( job, bytes.envelope, &prior, failed).status ==
						 Status::OK) ;
		auto expected	  = prior ;	// 許可された最新試行と無効化だけ更新します。
		expected.attempt  = cache.attempt ;
		expected.reason	  = cache.reason ;
		expected.reusable = false ;
		expected.etag.reset() ;
		DRIVERCRATE_EXPECT( context, roundTrip( context, failed) == roundTrip( context, expected) &&
										roundTrip( context, prior) == oldBytes) ;
	}

	DRIVERCRATE_EXPECT( context, cache.request == bytes.value.request &&
									cache.binding == bytes.value.cache &&
									cache.attempt.generation == bytes.value.generation &&
									cache.attempt.response == bytes.responseSha256) ;
	const bool full = bytes.value.cacheDecision.action ==
					  CollectorProjectedCacheAction::REPLACE ;	// 応答codecの完全成功区分。
	DRIVERCRATE_EXPECT(
		context,
		cache.original200.has_value() == full && cache.validated.has_value() == full &&
			cache.reusable == (full && bytes.value.responseValidator.has_value()) &&
			cache.etag == (full ? bytes.value.responseValidator : std::optional<std::wstring>{})) ;
	// 完全成功の元header／本文／projectionは改変せず保存候補へ移します。
	if( full) {
		DRIVERCRATE_EXPECT( context,
						   cache.original200->headerUtc == bytes.value.io.headerUtcMillis &&
							   cache.original200->body == bytes.value.body &&
							   cache.original200->projection == bytes.value.projection) ;
	}

	const auto accepted =
		std::count_if( bytes.value.metadata.slices.begin(), bytes.value.metadata.slices.end(),
					  []( const auto &slice) {
						  return slice.disposition == CollectorMetadataDisposition::ACCEPTED ;
					  }) ; // 検査中だけ借用。
	DRIVERCRATE_EXPECT( context, cache.slices.size() ==
									(bytes.value.state == CollectorMetadataOutcome::FETCHED
										 ? static_cast<std::size_t>( accepted)
										 : 0U)) ;
	// 架空の別中断操作。
	CollectorCacheAttempt attempt{std::wstring( 64U, L'a'), std::wstring( 64U, L'b'),
								  std::wstring( 64U, L'c')} ;
	Cache				  interrupted ;	// 別bindingでの次中断も旧成功を保持します。
	DRIVERCRATE_EXPECT( context,
					   makeInterruptedCollectorCache( cache.request, std::wstring( 64U, L'd'),
													 attempt, &cache, interrupted)
							   .status == Status::OK) ;
	auto expected = cache ;	// 中断で変えてよいfieldだけを独立に変更します。
	expected.binding.assign( 64U, L'd') ;
	expected.attempt  = attempt ;
	expected.reason	  = Reason::INTERRUPTED ;
	expected.reusable = false ;
	expected.etag.reset() ;
	DRIVERCRATE_EXPECT( context, roundTrip( context, interrupted) == roundTrip( context, expected) &&
									roundTrip( context, cache) == saved) ;
	// 明示tagありの全成功fixtureでだけ関連field拒否を試します。
	if( cache.reusable) {
		strictChecks( context, job, bytes, cache) ;
	}

	interruptedCompatibility( context) ;
}
void runCollectorCacheTransitionChecks( TestContext							   &context,
									   const CollectorProjectedHistoryEvidence &prior,
									   const CollectorProjectedJobInput		   &job,
									   const CollectorProjectedResponseBytes   &bytes)
{
	Cache before ;	// 元byteから独立導出した前日値。
	DRIVERCRATE_EXPECT( context,
					   deriveCollectorProjectedCache( prior.campaign->job( prior.jobIndex)->value(),
													 prior.envelope, nullptr, before)
							   .status == Status::OK) ;
	const auto original = roundTrip( context, before) ;	// 保存前値を変更しないことを確認します。
	Cache	   after ;									// 今回最終化済みの値だけを適用します。
	// 更新導出の結果。
	const auto result = deriveCollectorProjectedCache( job, bytes.envelope, &before, after) ;
	DRIVERCRATE_EXPECT( context, result.status == Status::OK) ;
	// 空出力をさらに成功として検査しません。
	if( result.status != Status::OK) {
		return ;
	}

	roundTrip( context, after) ;
	auto expected	  = before ;	// 今回の三参照と許可された成功だけ独立に更新します。
	expected.request  = bytes.value.request ;
	expected.binding  = bytes.value.cache ;
	expected.attempt  = after.attempt ;
	expected.reason	  = after.reason ;
	expected.reusable = false ;
	expected.etag.reset() ;
	// Fixtureは同じslice一件で、成功時だけ元slotを置換します。
	if( bytes.value.state == CollectorMetadataOutcome::FETCHED) {
		DRIVERCRATE_EXPECT( context, after.slices.size() == 1U &&
										after.slices[0].response == bytes.responseSha256 &&
										after.slices[0].generation == bytes.value.generation &&
										after.slices[0].projection == bytes.value.projection &&
										after.slices[0].slice == before.slices[0].slice) ;
		expected.slices = after.slices ;
	}

	// 完全成功だけ元200と検証参照・tagの更新を許します。
	if( bytes.value.cacheDecision.action == CollectorProjectedCacheAction::REPLACE) {
		DRIVERCRATE_EXPECT(
			context, after.original200 && after.original200->response == bytes.responseSha256 &&
						 after.original200->headerUtc == bytes.value.io.headerUtcMillis &&
						 after.validated && after.validated->response == bytes.responseSha256) ;
		expected.original200 = after.original200 ;
		expected.validated	 = after.validated ;
		expected.etag		 = bytes.value.responseValidator ;
		expected.reusable	 = expected.etag.has_value() ;
	}

	DRIVERCRATE_EXPECT( context, roundTrip( context, expected) == roundTrip( context, after) &&
									roundTrip( context, before) == original) ;
	// 正当な旧bindingを履歴として保持し、今回成功へ捏造しません。
	before.binding.assign( 64U, L'f') ;
	Cache changed ;	// 同じ旧参照と違うbindingだけの比較。
	DRIVERCRATE_EXPECT(
		context,
		deriveCollectorProjectedCache( job, bytes.envelope, &before, changed).status == Status::OK &&
			roundTrip( context, changed) == roundTrip( context, after)) ;
}
} // namespace drivercrate::test
