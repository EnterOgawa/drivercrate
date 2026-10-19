//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_response_tests.cpp
 * @brief 応答v4の往復・改変・失敗数値の保持を検証します。
 * @version 01.02.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  実workerの正常・失敗結果と有限縮退を検証。
 * Ver.01.01.00 Shunji Ogawa  2026/09/29  前日参照・件数変化・改変と原失敗を検査。
 * Ver.01.02.00 Shunji Ogawa  2026/09/29  CACHE型と28履歴更新のfixtureを接続。
 * Ver.01.02.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 改変値はcodec拒否試験専用です。成功workerや履歴の真正性を作りません。
 */
//------------------------------------------------------------------------------
#include "local_collector_projected_response_tests.h"
#include "local_collector_projected_cache_tests.h"
#include "platform/local_collector_http_observation.h"
#include "platform/local_collector_projected_start.h"
#include "platform/official_file_verifier.h"

namespace drivercrate::test {
namespace {
/**
 * @brief 投影JSON codecの成否と元診断を保持する。
 */
using Status = collector_projected_json::Status ;
/**
 * @brief 一回の投影応答の状態と観測値を所有し、codecへ渡す。
 */
using Response = CollectorProjectedResponse ;
/**
 * @brief 投影応答の符号化byteとhash結果を所有する。
 */
using Bytes = CollectorProjectedResponseBytes ;
/**
 * @brief 収集metadataの不成立理由をschemaの列挙値で保持し、成功結果と区別する。
 */
using Reason = CollectorMetadataReason ;
/**
 * @brief 有限予算の到達段階を保持し、正常完了と区別する。
 */
using Limit = CollectorMetadataLimitStage ;
/**
 * @brief Hash処理が到達した段階を保持し、不完全な検証と完了を区別する。
 */
using Stage = CollectorProjectedHashStage ;

/**
 * @brief I/O codecと外側に分かれた元観測の全保存fieldを比較します。
 * @param[in,out] context 同期試験のassertionと失敗数の集計先。試験中だけ借用する。
 * @param[in] before 往復前の元観測。
 * @param[in] after 往復後に比較する所有観測。
 */
void sameObservation( TestContext &context, const CollectorIoSnapshot &before,
					 const CollectorIoSnapshot &after)
{
	std::string		   first ;				// 既存codecの元byte。
	std::string		   second ;				// 復元した同じcodecのbyte。
	const std::wstring key( 64U, L'a') ;	// 比較だけの同一permit key。
	DRIVERCRATE_EXPECT( context, encodeCollectorHttpObservation( before, key, first) &&
									encodeCollectorHttpObservation( after, key, second) &&
									first == second) ;
	DRIVERCRATE_EXPECT(
		context,
		before.error.domain == after.error.domain && before.error.code == after.error.code &&
			before.error.stage == after.error.stage && before.sends == after.sends &&
			before.bytesKnown == after.bytesKnown &&
			before.finishedUtcMillis == after.finishedUtcMillis && before.sealed == after.sealed) ;
}
/**
 * @brief 下位hash一致だけに依存せず往復と別CNGの値を検査します。
 * @param[in,out] context 同期試験のassertionと失敗数の集計先。試験中だけ借用する。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] encoded 元byteと独立CNGを比較する符号化済み応答。
 */
void roundTrip( TestContext &context, const CollectorProjectedJobInput &job, const Bytes &encoded)
{
	Bytes					   decoded ;	// 独立readerの復元物。
	std::array<std::size_t, 4> calls{} ;	// 段階ごとの実計算前通知回数。
	const auto				   result =
		decodeCollectorProjectedResponse( job, encoded.envelope, decoded, [&]( Stage stage) {
			++calls[static_cast<std::size_t>( stage)] ;
			return NativeError{0} ;
		}) ; // 0は実CNGを省略しません。
	DRIVERCRATE_EXPECT( context, result.result.status == Status::OK) ;
	// 一つの失敗を大量の空値比較へ伝播しません。
	if( result.result.status != Status::OK) {
		return ;
	}

	const bool missingHash =
		// 特殊最小形だけhashなし。
		encoded.value.metadata.reason == Reason::METADATA_HASH ;
	DRIVERCRATE_EXPECT( context,
					   calls == (std::array<std::size_t, 4>{0U, 0U, missingHash ? 0U : 1U, 1U})) ;
	DRIVERCRATE_EXPECT( context, decoded.envelope == encoded.envelope &&
									decoded.response == encoded.response &&
									decoded.metadata == encoded.metadata &&
									decoded.responseSha256 == encoded.responseSha256) ;
	sameObservation( context, encoded.value.io, decoded.value.io) ;
	std::wstring hash ;	// Readerとは別の実CNG。
	DRIVERCRATE_EXPECT( context, computeBytesSha256( encoded.response, hash) == 0 &&
									hash == encoded.responseSha256) ;
	// 親hash故障の最小形だけ再hashを要求しません。
	if( !missingHash) {
		DRIVERCRATE_EXPECT( context, computeBytesSha256( encoded.metadata, hash) == 0 &&
										hash == encoded.value.projection) ;
	}

	Bytes repeated ;	// 型付きreader後の再符号化。
	DRIVERCRATE_EXPECT(
		context, encodeCollectorProjectedResponse( job, decoded.value, repeated).result.status ==
						 Status::OK &&
					 repeated.envelope == encoded.envelope) ;
	runCollectorCacheChecks( context, job, encoded) ;
}
/**
 * @brief 外側hashを再計算しても不整合fieldは受理されないことを検査します。
 * @param[in,out] context 同期試験のassertionと失敗数の集計先。試験中だけ借用する。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] original 改変前の正常な符号化済み応答。
 * @param[in] from 元byteに存在する置換前文字列。
 * @param[in] to 拒否を期待する置換後文字列。
 */
void rejectBytes( TestContext &context, const CollectorProjectedJobInput &job, const Bytes &original,
				 std::string_view from, std::string_view to)
{
	std::string changed	 = original.response ;		// 元成功を保持する局所改変。
	const auto	position = changed.find( from) ;	// 全field固定順の改変位置。
	DRIVERCRATE_EXPECT( context, position != std::string::npos) ;
	// 見つからない場合を改変成功と表示しません。
	if( position == std::string::npos) {
		return ;
	}

	changed.replace( position, from.size(), to) ;
	collector_projected_json::EnvelopeBytes outer ;		// 新hash付き不正応答。
	std::string								envelope ;	// 実CNGを通した外側byte。
	DRIVERCRATE_EXPECT( context,
					   collector_projected_json::encodeEnvelope( changed, envelope, outer).status ==
						   Status::OK) ;
	Bytes decoded ;	// 失敗時の全出力消去。
	decoded.envelope = "stale" ;
	DRIVERCRATE_EXPECT(
		context,
		decodeCollectorProjectedResponse( job, envelope, decoded).result.status == Status::INVALID &&
			decoded.envelope.empty() && decoded.response.empty() && decoded.metadata.empty()) ;
}
/**
 * @brief 任意の型付き不整合を縮退せず拒否します。
 * @param[in,out] context 同期試験のassertionと失敗数の集計先。試験中だけ借用する。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] original 複製前の正常応答。
 * @param[in] mutate 複製した値だけを同期改変するcallback。借用参照を保持しない。
 */
void rejectValue( TestContext &context, const CollectorProjectedJobInput &job,
				 const Response &original, const std::function<void( Response &)> &mutate)
{
	Response changed = original ;	// Codecだけに渡す改変値。
	mutate( changed) ;
	Bytes encoded ;	// 拒否時の出力。
	encoded.envelope = "stale" ;
	DRIVERCRATE_EXPECT(
		context,
		encodeCollectorProjectedResponseWithFallback( job, changed, encoded).result.status ==
				Status::INVALID &&
			encoded.envelope.empty()) ;
}
/**
 * @brief 生きた予約の代用ではなく公開job結合の破損を検査します。
 * @param[in,out] context 同期試験のassertionと失敗数の集計先。試験中だけ借用する。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] worker 元bindingとdraftを持つ架空worker結果。
 */
void bindingChecks( TestContext &context, const CollectorProjectedJobInput &job,
				   const CollectorProjectedWorkerResult &worker)
{
	const std::array<std::function<void( CollectorProjectedWorkerResult &)>, 8> mutations{
		[]( auto &value) { value.binding.jobIndex += 1U ; },
		[]( auto &value) { value.binding.scopeSha256.assign( 64U, L'f') ; },
		[]( auto &value) { value.binding.requestKey.assign( 64U, L'f') ; },
		[]( auto &value) { value.binding.cacheBinding.assign( 64U, L'f') ; },
		[]( auto &value) { value.binding.source.resourceId += L'x' ; },
		[]( auto &value) { value.binding.mode = CollectorRecoveryDispatch::Mode::CONTROLLED ; },
		[]( auto &value) { value.binding.deadlineUtcMillis += 1U ; },
		[]( auto &value) {
			value.io.error.stage = static_cast<CollectorIoStage>( 999U) ;
		}} ; // 元全field照合の独立した改変。
	// 各改変を元所有値から独立に検査します。
	for( const auto &mutate : mutations) {
		auto changed = worker ;	// 成功workerへ戻さない局所複製。
		mutate( changed) ;
		Response rejected ;	// 失敗時に空になる値。
		DRIVERCRATE_EXPECT( context, makeCollectorProjectedResponseCandidate(
										job, changed, *worker.io.finishedUtcMillis + 1U, rejected)
												.status == Status::INVALID &&
										rejected.generation.empty()) ;
	}
}
/**
 * @brief 失敗専用probeでhash故障・OOM・一回縮退を区別します。
 * @param[in,out] context 同期試験のassertionと失敗数の集計先。試験中だけ借用する。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] candidate 故障・終端形ごとに複製する正常応答候補。
 */
void hashChecks( TestContext &context, const CollectorProjectedJobInput &job,
				const Response &candidate)
{
	std::array<std::size_t, 4> calls{} ;	// 故障した段階を再試行しない回数。
	Bytes					   encoded ;	// 検査対象の非保存byte。
	const auto				   failed =
		encodeCollectorProjectedResponseWithFallback( job, candidate, encoded, [&]( Stage stage) {
			++calls[static_cast<std::size_t>( stage)] ;
			return stage == Stage::METADATA ? NativeError{E_ACCESSDENIED} : NativeError{0} ;
		}) ; // 成功値は注入しません。
	// 第一worker errorは後続のhash分類へ置換しません。
	if( candidate.metadata.reason == Reason::WORKER_FAILURE) {
		DRIVERCRATE_EXPECT( context, failed.result.status == Status::HASH_FAILURE &&
										failed.result.error == E_ACCESSDENIED &&
										encoded.envelope.empty() && calls[0] == 1U &&
										calls[1] == 0U) ;
	} else {
		DRIVERCRATE_EXPECT( context,
						   failed.result.status == Status::OK && calls[0] == 1U && calls[1] == 1U &&
							   encoded.value.metadata.reason == Reason::METADATA_HASH &&
							   encoded.value.projection.empty() && encoded.value.metadata.error &&
							   encoded.value.metadata.error->code ==
								   static_cast<std::uint32_t>( E_ACCESSDENIED) &&
							   encoded.value.error == candidate.error &&
							   encoded.value.errorDomain == candidate.errorDomain) ;
		// 正常終了した縮退物だけを読み戻します。
		if( failed.result.status == Status::OK) {
			sameObservation( context, candidate.io, encoded.value.io) ;
			roundTrip( context, job, encoded) ;
		}
	}

	const auto responseFailure =
		encodeCollectorProjectedResponseWithFallback( job, candidate, encoded, []( Stage stage) {
			return stage == Stage::RESPONSE ? NativeError{E_ACCESSDENIED} : NativeError{0} ;
		}) ; // 応答hash故障では保存候補なし。
	DRIVERCRATE_EXPECT( context, responseFailure.result.status == Status::HASH_FAILURE &&
									responseFailure.stage == Limit::RESPONSE_BYTES &&
									responseFailure.result.error == E_ACCESSDENIED &&
									encoded.envelope.empty()) ;
	const auto oom =
		encodeCollectorProjectedResponseWithFallback( job, candidate, encoded, []( Stage stage) {
			return stage == Stage::METADATA ? NativeError{E_OUTOFMEMORY} : NativeError{0} ;
		}) ; // メモリ不足はbyte上限と異なる全体停止。
	DRIVERCRATE_EXPECT( context, oom.result.status == Status::OUT_OF_MEMORY &&
									oom.result.error == E_OUTOFMEMORY && encoded.envelope.empty()) ;
	DRIVERCRATE_EXPECT(
		context, encodeCollectorProjectedResponseWithFallback( job, candidate, encoded, []( Stage) {
					 return NativeError{1} ;
				 }).result.status == Status::INVALID) ;
	DRIVERCRATE_EXPECT( context, encodeCollectorProjectedResponseWithFallback(
									job, candidate, encoded, []( Stage) -> NativeError {
										throw std::bad_alloc{} ;
									}).result.status == Status::OUT_OF_MEMORY) ;
}
/**
 * @brief 304／cache拒否等の値型だけを往復し、live受入に流用しません。
 * @param[in,out] context 同期試験のassertionと失敗数の集計先。試験中だけ借用する。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @param[in] candidate 故障・終端形ごとに複製する正常応答候補。
 */
void shapeChecks( TestContext &context, const CollectorProjectedJobInput &job,
				 const Response &candidate)
{
	Bytes encoded ;	// 値型fixtureの出力。登録済み履歴ではありません。
	// 元失敗で未知byte量と下限量を別に保持します。
	if( candidate.io.cause != CollectorIoCause::COMPLETE) {
		Response unknown = candidate ;	// 元HTTP失敗の型付き複製。
		unknown.bytes.reset() ;
		unknown.io.bytesKnown = false ;
		DRIVERCRATE_EXPECT( context,
						   encodeCollectorProjectedResponse( job, unknown, encoded).result.status ==
							   Status::OK) ;
		roundTrip( context, job, encoded) ;
		DRIVERCRATE_EXPECT( context, encoded.response.find( "\"bytes\":null") != std::string::npos &&
										encoded.value.io.lowerBytes == candidate.io.lowerBytes) ;
		return ;
	}

	Response current = candidate ;	// 有効ETagの有無は正常metadata採用と分離します。
	rejectValue( context, job, candidate, []( auto &value) {
		value.io.elapsedMillis = value.io.deadlineUtcMillis - value.started ;
	}) ;
	rejectValue( context, job, candidate,
				[]( auto &value) { value.metadata.diagnostics.parser.reset() ; }) ;
	current.responseValidator = L"\"fixture-v1\"" ;
	current.cacheDecision	  = collectorProjectedCacheDecision( current) ;
	DRIVERCRATE_EXPECT( context,
					   encodeCollectorProjectedResponse( job, current, encoded).result.status ==
						   Status::OK) ;
	roundTrip( context, job, encoded) ;
	// 全対象一致か否かをcache採用判定とは別に確認します。
	if( current.metadata.complete && std::all_of( current.metadata.edges.begin(),
												current.metadata.edges.end(), []( const auto &edge) {
													return edge.state ==
														   CollectorProjectedTargetState::MATCH ;
												})) {
		DRIVERCRATE_EXPECT(
			context, current.cacheDecision.action == CollectorProjectedCacheAction::REPLACE &&
						 current.cacheDecision.reason == CollectorProjectedCacheReason::ACCEPTED) ;
		current.responseValidator.reset() ;
		current.cacheDecision = collectorProjectedCacheDecision( current) ;
		DRIVERCRATE_EXPECT( context, current.cacheDecision.reason ==
										CollectorProjectedCacheReason::NO_VALIDATOR) ;
		DRIVERCRATE_EXPECT( context,
						   encodeCollectorProjectedResponse( job, current, encoded).result.status ==
							   Status::OK) ;
		roundTrip( context, job, encoded) ;
	}

	// 元200参照の全fieldを持つschemaを検査します。送信前pinや実304観測は生成しません。
	Response cached = candidate ;	// 純粋codecだけの304形。
	cached.body.clear() ;
	cached.projection.clear() ;
	cached.bytes			 = 0U ;
	cached.status			 = 304U ;
	cached.io.lowerBytes	 = 0U ;
	cached.state			 = CollectorMetadataOutcome::REVALIDATED ;
	cached.requestValidator	 = L"\"fixture-v1\"" ;
	cached.responseValidator = cached.requestValidator ;
	cached.original200		 = CollectorProjectedOriginal200{
		  std::wstring( 64U, L'a'), std::wstring( 64U, L'b'), std::wstring( 64U, L'c'),
		  std::wstring( 64U, L'd'), candidate.body,			*candidate.io.headerUtcMillis} ;
	cached.metadata			= {} ;
	cached.metadata.binding = candidate.metadata.binding ;
	cached.metadata.binding.body.clear() ;
	cached.metadata.binding.validatedUtc.reset() ;
	cached.metadata.outcome					 = cached.state ;
	cached.metadata.form					 = CollectorMetadataForm::FULL ;
	cached.metadata.reason					 = Reason::NONE ;
	cached.metadata.complete				 = true ;
	cached.metadata.diagnostics.workerReason = CollectorProjectedWorkerReason::NONE ;
	cached.cacheDecision					 = collectorProjectedCacheDecision( cached) ;
	DRIVERCRATE_EXPECT( context,
					   encodeCollectorProjectedResponse( job, cached, encoded).result.status ==
						   Status::OK) ;
	roundTrip( context, job, encoded) ;
	rejectBytes( context, job, encoded, "\"original200\":{\"generation\":",
				"\"original200\":{\"extra\":false,\"generation\":") ;
	rejectValue( context, job, cached, []( auto &value) { value.original200.reset() ; }) ;
	rejectValue( context, job, cached,
				[]( auto &value) { value.original200->headerUtc = value.finished + 1U ; }) ;
	rejectValue( context, job, cached, []( auto &value) { value.requestValidator.reset() ; }) ;
	rejectValue( context, job, cached,
				[]( auto &value) { value.responseValidator = L"\"changed\"" ; }) ;
	rejectValue( context, job, cached, [&]( auto &value) {
		value.metadata.diagnostics.parser = candidate.metadata.diagnostics.parser ;
	}) ;
	hashChecks( context, job, cached) ;
	cached.responseValidator.reset() ;
	DRIVERCRATE_EXPECT( context,
					   encodeCollectorProjectedResponse( job, cached, encoded).result.status ==
						   Status::OK) ;
	roundTrip( context, job, encoded) ;
	cached.state			 = CollectorMetadataOutcome::FAILED ;
	cached.metadata.outcome	 = cached.state ;
	cached.metadata.complete = false ;
	cached.metadata.form	 = CollectorMetadataForm::MINIMAL_FAILURE ;
	cached.metadata.reason	 = Reason::CACHE_BASIS_INVALID ;
	cached.metadata.error	 = CollectorMetadataError{CollectorMetadataErrorPhase::CACHE_BASIS,
													  CollectorIoErrorDomain::PARSER, 1U} ;
	cached.cacheDecision	 = collectorProjectedCacheDecision( cached) ;
	DRIVERCRATE_EXPECT( context,
					   encodeCollectorProjectedResponse( job, cached, encoded).result.status ==
						   Status::OK) ;
	roundTrip( context, job, encoded) ;
}
} // namespace

/** @see local_collector_projected_response_tests.h */
void runCollectorProjectedResponseChecks( TestContext						  &context,
										 const CollectorProjectedJobInput	  &job,
										 const CollectorProjectedWorkerResult &worker)
{
	Response   candidate ;	// 実worker所有観測だけからの非保存候補。
	const auto made = makeCollectorProjectedResponseCandidate(
		job, worker, *worker.io.finishedUtcMillis + 1U, candidate) ;	// 履歴受入ではない。
	const auto label = "response candidate source=" + winrt::to_string( job.source.sourceId) +
					   " cause=" + std::to_string( static_cast<unsigned>( worker.io.cause)) +
					   " error=" + std::to_string( worker.io.error.code) ;	// 固定公開診断。
	context.expect( made.status == Status::OK, label, __FILE__, __LINE__) ;
	// 失敗原因の最初のassertionを保持して後続参照を止めます。
	if( made.status != Status::OK) {
		return ;
	}

	bindingChecks( context, job, worker) ;
	Bytes	   encoded ;	// 元I/Oとmetadataを持つ応答。
	const bool oversized = worker.projection.edges.size() == 300U &&
						   // 実大集合のbyte超過。
						   worker.projection.records.size() == 16U ;
	const auto direct =
		// 縮退前の正確な結果。
		encodeCollectorProjectedResponse( job, candidate, encoded) ;
	// 元件数内の大集合は初めてbyte上限に到達します。
	if( oversized) {
		DRIVERCRATE_EXPECT( context, direct.result.status == Status::SIZE_LIMIT &&
										direct.stage == Limit::METADATA_BYTES &&
										encoded.envelope.empty()) ;
	} else {
		context.expect( direct.result.status == Status::OK, label + " encode", __FILE__, __LINE__) ;
		// 通常失敗時の連鎖を止めます。
		if( direct.result.status != Status::OK) {
			return ;
		}
	}

	const auto result =
		// 有限一回縮退。
		encodeCollectorProjectedResponseWithFallback( job, candidate, encoded) ;
	context.expect( result.result.status == Status::OK, label + " fallback", __FILE__, __LINE__) ;
	// 成功した所有物だけを復号へ進めます。
	if( result.result.status != Status::OK) {
		return ;
	}

	DRIVERCRATE_EXPECT( context,
					   encoded.metadata.size() <= collector_projected_json::METADATA_LIMIT &&
						   encoded.response.size() <= collector_projected_json::RESPONSE_LIMIT &&
						   encoded.envelope.size() <= collector_projected_json::ENVELOPE_LIMIT &&
						   encoded.response.find( "https:") == std::string::npos) ;
	sameObservation( context, worker.io, encoded.value.io) ;
	roundTrip( context, job, encoded) ;
	// 縮退時の元診断量を実測0や欠測に書き換えません。
	if( oversized) {
		DRIVERCRATE_EXPECT(
			context,
			encoded.value.state == CollectorMetadataOutcome::HELD &&
				encoded.value.metadata.reason == Reason::PROJECTION_LIMIT &&
				encoded.value.metadata.diagnostics.limitStage == Limit::METADATA_BYTES &&
				encoded.value.metadata.records.empty() && encoded.value.metadata.slices.empty() &&
				encoded.value.metadata.edges.empty() && encoded.value.metadata.diagnostics.counts &&
				encoded.value.metadata.diagnostics.counts->records == 16U &&
				encoded.value.metadata.diagnostics.counts->edges == 300U &&
				encoded.value.metadata.binding.validatedUtc ==
					candidate.metadata.binding.validatedUtc &&
				worker.projection.edges.size() == 300U && worker.projection.records.size() == 16U) ;
		return ;
	}

	hashChecks( context, job, candidate) ;
	shapeChecks( context, job, candidate) ;
	rejectBytes( context, job, encoded, "\"challenge\":false", "\"challenge\":true") ;
	rejectBytes( context, job, encoded, "\"sends\":" + std::to_string( candidate.sends),
				"\"sends\":2") ;
	rejectBytes( context, job, encoded, "\"state\":", "\"unknown\":null,\"state\":") ;
	rejectBytes( context, job, encoded, "\"maximum\":" + std::to_string( candidate.maximum),
				"\"maximum\":0") ;
	rejectBytes( context, job, encoded,
				"\"projection\":\"" + winrt::to_string( encoded.value.projection) + "\"",
				"\"projection\":\"" + std::string( 64U, 'f') + "\"") ;
	rejectBytes( context, job, encoded,
				"\"cacheDecision\":{\"action\":", "\"cacheDecision\":{\"extra\":false,\"action\":") ;
	rejectValue( context, job, candidate,
				[]( auto &value) { value.io.finishedUtcMillis = value.finished + 1U ; }) ;
	rejectValue( context, job, candidate, []( auto &value) { value.io.nativeReleased = false ; }) ;
	rejectValue( context, job, candidate, []( auto &value) { value.io.sealed = false ; }) ;
	rejectValue( context, job, candidate, []( auto &value) { value.accepted = value.finished - 1U ; }) ;
	rejectValue( context, job, candidate, []( auto &value) { value.day = L"20000101" ; }) ;
	rejectValue( context, job, candidate, []( auto &value) { value.projection.assign( 64U, L'f') ; }) ;
	rejectValue( context, job, candidate, []( auto &value) {
		value.cacheDecision.action = static_cast<CollectorProjectedCacheAction>( 999U) ;
	}) ;
	rejectValue( context, job, candidate, []( auto &value) { value.requestValidator = L"invalid" ; }) ;
	rejectValue( context, job, candidate, []( auto &value) { value.original200.emplace() ; }) ;
	// Parser未開始・worker失敗の欠測をschemaが埋めていないことを確認します。
	if( worker.reason != CollectorProjectedWorkerReason::NONE) {
		DRIVERCRATE_EXPECT( context, !encoded.value.metadata.diagnostics.source &&
										!encoded.value.metadata.diagnostics.counts &&
										!encoded.value.metadata.binding.validatedUtc &&
										encoded.value.metadata.diagnostics.parser.has_value() ==
											worker.parser.has_value()) ;
	}

	// 独立readerのhash故障も元HRESULTを保持します。
	for( const auto stage : {Stage::READ_METADATA, Stage::READ_RESPONSE}) {
		Bytes	   decoded ;	// 故障時は空。
		const auto failure =
			decodeCollectorProjectedResponse( job, encoded.envelope, decoded, [&]( Stage current) {
				return current == stage ? NativeError{E_ACCESSDENIED} : NativeError{0} ;
			}) ; // 二段を別々に一回だけ停止。
		DRIVERCRATE_EXPECT( context, failure.result.status == Status::HASH_FAILURE &&
										failure.result.error == E_ACCESSDENIED &&
										decoded.envelope.empty()) ;
	}
}
namespace {
/** @brief 前日または当日の参照を合成し、本番codecで有限byteを生成します。
 * @param[in,out] context 試験集計。
 * @param[in] definition 元の公開定義。
 * @param[in] original 本物のworkerが生成したfixture結果。
 * @param[in] previous 前日へ時刻を移す場合true。当日は同一操作拒否試験専用です。
 * @return 登録されていない合成履歴。実取得証跡とはしません。
 */
CollectorProjectedHistoryEvidence historyFixture(
	TestContext &context, const CollectorProjectedCampaignDefinition &definition,
	const CollectorProjectedWorkerResult &original, bool previous = true)
{
	CollectorProjectedHistoryEvidence  entry ;		// 参照だけでなく全元byteを所有します。
	CollectorProjectedCampaignIdentity identity ;	// 元manifestから実Gを計算します。
	DRIVERCRATE_EXPECT( context, makeCollectorProjectedCampaignIdentity(
									definition, previous ? L"20260926" : L"20260927", identity)) ;
	DRIVERCRATE_EXPECT( context,
					   prepareCollectorProjectedCampaign(
						   identity.canonicalInput, identity.inputSha256, identity.generationKey,
						   definition.artifactSha256, definition.sources, entry.campaign)) ;
	// 準備失敗を参照合成の成功へ進めません。
	if( !entry.campaign) {
		return entry ;
	}

	auto				worker = original ;										// 変更するのはこの合成用所有copyだけです。
	const std::uint64_t delta  = previous ? 86400000U : 0U ;					// 前日への固定差分。
	const auto &job = entry.campaign->job( worker.binding.jobIndex)->value() ;	// 前日の同job。
	worker.binding.generationKey = identity.generationKey ;
	worker.binding.jobKey		 = job.jobKey ;
	worker.binding.requestKey	 = job.requestKey ;
	worker.binding.cacheBinding	 = job.cacheBinding ;
	worker.binding.scopeSha256	 = job.scopeSha256 ;
	worker.binding.startedUtcMillis -= delta ;
	worker.binding.anchorUtcMillis -= delta ;
	worker.binding.deadlineUtcMillis -= delta ;
	worker.io.deadlineUtcMillis -= delta ;
	*worker.io.finishedUtcMillis -= delta ;
	// 全正常fixtureはheaderを観測済みです。欠測を新時刻で補完しません。
	if( worker.io.headerUtcMillis) {
		*worker.io.headerUtcMillis -= delta ;
	}

	// 消去済み失敗のdraftへ架空の検証時刻を追加しません。
	if( worker.reason == CollectorProjectedWorkerReason::NONE) {
		worker.projection.validatedUtcMillis -= delta ;
		worker.projection.cacheBinding = job.cacheBinding ;
		worker.projection.scopeSha256  = job.scopeSha256 ;
	}

	Response value ;	// 同じ正常／部分／失敗結果の元byteだけを生成します。
	DRIVERCRATE_EXPECT( context, makeCollectorProjectedResponseCandidate(
									job, worker, *worker.io.finishedUtcMillis + 1U, value)
										.status == Status::OK) ;
	Bytes bytes ;	// Metadataと応答を実CNGで符号化します。
	DRIVERCRATE_EXPECT( context, encodeCollectorProjectedResponse( job, value, bytes).result.status ==
									Status::OK) ;
	entry.jobIndex	 = job.jobIndex ;
	entry.generation = identity.generationKey ;
	entry.input		 = identity.canonicalInput ;
	DRIVERCRATE_EXPECT( context,
					   encodeCollectorProjectedStart( identity, worker.binding, entry.startIntent)) ;
	DRIVERCRATE_EXPECT( context,
					   computeBytesSha256( "response-v2\n" + winrt::to_string( entry.generation) +
											  "\n" + winrt::to_string( job.jobKey) + "\n",
										  entry.operation) == 0) ;
	entry.response	 = bytes.responseSha256 ;
	entry.projection = bytes.value.projection ;
	entry.slice		 = job.slices.front().key ;
	entry.envelope	 = bytes.envelope ;
	return entry ;
}
} // namespace

/** @see local_collector_projected_response_tests.h */
void runCollectorProjectedHistoryChecks(
	TestContext &context, const CollectorProjectedCampaignDefinition &definition,
	const std::shared_ptr<const CollectorPreparedProjectedCampaign> &prepared,
	const std::map<unsigned, CollectorProjectedWorkerResult>		&workers)
{
	using Final	   = CollectorProjectedHistoryFinalization ;
	using Evidence = CollectorProjectedHistoryEvidence ;
	DRIVERCRATE_EXPECT( context, workers.size() == 10U) ;
	// 欠けたworkerをdefault成功値で補完しません。
	if( workers.size() != 10U) {
		return ;
	}

	std::map<unsigned, Evidence> history ;	// 正常・部分・失敗を含む前日参照。
	// 有限十結果だけから新しい実byteを作ります。
	for( const auto &[mode, worker] : workers) {
		history.emplace( mode, historyFixture( context, definition, worker)) ;
	}

	const std::array noMatchHistory{history.at( 100U)} ;	// 200でも対象一致がない前日結果。
	Final			 rejected ;								// 同requestでもACCEPTED履歴にはできません。
	DRIVERCRATE_EXPECT(
		context, finalizeCollectorProjectedHistory( *prepared->job( 0U), workers.at( 114U),
												   *workers.at( 114U).io.finishedUtcMillis + 2U,
												   noMatchHistory, rejected)
							 .status == Status::INVALID &&
					 rejected.response.generation.empty()) ;

	// 以前の正常1／2／16件・部分1件、Intelの一対象MATCHを今回同sourceの全結果へ比較します。
	for( const unsigned prior : {0U, 19U, 20U, 22U, 114U}) {
		const std::array entries{history.at( prior)} ;	// 直近成功の登録を証明するものではありません。
		// 新0件、増加、同数置換、縮小、部分、上限、read／parser失敗を区別します。
		for( const auto &[mode, worker] : workers) {
			// 違うrequestの値を件数比較しません。
			if( (prior >= 100U) != (mode >= 100U)) {
				continue ;
			}

			const auto &job = *prepared->job( worker.binding.jobIndex) ;	// 同scopeの不変job。
			Final		result ;											// 失敗時に古い結果を残さないことも確認します。
			const auto	status =
				finalizeCollectorProjectedHistory( job, worker, *worker.io.finishedUtcMillis + 2U,
												  entries, result) ;	// 先にhashを作らない入口。
			context.expect( status.status == Status::OK,
						   "history " + std::to_string( prior) + " -> " + std::to_string( mode),
						   __FILE__, __LINE__) ;
			// 前提失敗で大量の空出力比較を続けません。
			if( status.status != Status::OK) {
				continue ;
			}

			const bool comparable =
				// 正常200だけ。
				worker.reason == CollectorProjectedWorkerReason::NONE ;
			const bool decreased = comparable && worker.projection.records.size() <
													 // Fixture元件数から独立期待値。
													 workers.at( prior).projection.records.size() ;
			DRIVERCRATE_EXPECT(
				context,
				result.comparedSlices == (comparable ? 1U : 0U) &&
					result.decreasedSlices == (decreased ? 1U : 0U) &&
					result.response.metadata.records.size() == worker.projection.records.size() &&
					result.previousFull200.has_value() == (prior != 22U && prior != 114U) &&
					!result.response.original200 && result.response.projection.empty()) ;
			DRIVERCRATE_EXPECT( context,
							   (result.response.metadata.reason == Reason::DECREASED) == decreased) ;
			// 以前のvalidator／headerを新しい受領時刻へ延長しません。
			if( result.previousFull200) {
				DRIVERCRATE_EXPECT(
					context, result.previousFull200->response == entries[0].response &&
								 result.previousFull200->headerUtc ==
									 *workers.at( prior).io.headerUtcMillis - 86400000U &&
								 result.previousValidator == workers.at( prior).http.entityTag) ;
			}

			sameObservation( context, worker.io, result.response.io) ;
			// 同数置換や減少でも新しい指紋だけを保存候補に残します。
			for( std::size_t i = 0; i < worker.projection.records.size(); ++i) {
				DRIVERCRATE_EXPECT(
					context, result.response.metadata.records[i].value.stableFingerprint.bytes ==
								 worker.projection.records[i].value.stableFingerprint.bytes) ;
			}

			Bytes bytes ;	// 最終化した後にだけhash／外側を生成します。
			DRIVERCRATE_EXPECT( context, encodeCollectorProjectedResponseWithFallback(
											job.value(), result.response, bytes)
												.result.status == Status::OK) ;
			roundTrip( context, job.value(), bytes) ;
			runCollectorCacheTransitionChecks( context, entries[0], job.value(), bytes) ;
			DRIVERCRATE_EXPECT( context, entries[0].envelope == history.at( prior).envelope) ;
		}
	}

	const auto &worker	 = workers.at( 0U) ;					// 今回1件。
	const auto &job		 = *prepared->job( 1U) ;				// 同ASUS scope。
	const auto	accepted = *worker.io.finishedUtcMillis + 2U ;	// 受領順序は固定。
	const auto	run		 = [&]( std::span<const Evidence> entries, Final &output,
						   const CollectorProjectedHashProbe &probe = {}) {
		  return finalizeCollectorProjectedHistory( job, worker, accepted, entries, output, probe) ;
	} ; // 各caseの出力は独立にし、同一失敗のretryを行いません。
	Final empty ;	// 空履歴は登録不在の証明ではありません。
	DRIVERCRATE_EXPECT( context, run( {}, empty).status == Status::OK && empty.comparedSlices == 0U &&
									!empty.previousFull200) ;
	const std::array<std::function<void( Evidence &)>, 15> mutations{
		[]( auto &e) { e.campaign.reset() ; },
		[]( auto &e) { e.jobIndex = 99U ; },
		[]( auto &e) { e.generation.assign( 64U, L'f') ; },
		[]( auto &e) { e.operation.assign( 64U, L'f') ; },
		[]( auto &e) { e.response.assign( 64U, L'f') ; },
		[]( auto &e) { e.projection.assign( 64U, L'f') ; },
		[]( auto &e) { e.slice.assign( 64U, L'f') ; },
		[]( auto &e) { e.input.clear() ; },
		[]( auto &e) { e.startIntent.clear() ; },
		[]( auto &e) { e.envelope.clear() ; },
		[]( auto &e) { e.input += ' ' ; },
		[]( auto &e) { e.startIntent += ' ' ; },
		[]( auto &e) { e.envelope += ' ' ; },
		[]( auto &e) { e.input.resize( 768U * 1024U + 1U, ' ') ; },
		[]( auto &e) { e.startIntent.resize( 4097U, ' ') ; }} ;	// 元参照の一要因変更。
	// 別bindingを含め、全ての破損を出力空のまま拒否します。
	for( const auto &mutate : mutations) {
		std::array entries{history.at( 19U)} ;	// 前日2件の元参照。
		mutate( entries[0]) ;
		Final result = empty ;	// 古い成功値を残させません。
		DRIVERCRATE_EXPECT( context, run( entries, result).status == Status::INVALID &&
										result.response.generation.empty() &&
										result.response.metadata.records.empty() &&
										result.comparedSlices == 0U && !result.previousFull200 &&
										!result.previousValidator) ;
	}

	// 古い失敗／保留・別request・同操作・重複slice・上限を成功履歴にしません。
	for( const std::vector<Evidence> entries :
		{std::vector<Evidence>{history.at( 21U)}, std::vector<Evidence>{history.at( 23U)},
		 std::vector<Evidence>{history.at( 100U)}, std::vector<Evidence>{history.at( 102U)},
		 std::vector<Evidence>{historyFixture( context, definition, worker, false)},
		 std::vector<Evidence>{history.at( 19U), history.at( 19U)},
		 std::vector<Evidence>( 17U, history.at( 19U))}) {
		Final result ;	// 停止時は全出力空。
		DRIVERCRATE_EXPECT( context, run( entries, result).status == Status::INVALID &&
										result.response.generation.empty() &&
										!result.previousFull200) ;
	}

	auto changedDefinition = definition ;	// 元artifactは実行時と異なるが旧世代では正当です。
	changedDefinition.artifactSha256.assign( 64U, L'c') ;
	std::array different{	// 同request別binding。
						 historyFixture( context, changedDefinition, workers.at( 19U))} ;
	Final	   mismatch ;	// 破損と正当な旧bindingを区別します。
	DRIVERCRATE_EXPECT( context, run( different, mismatch).status == Status::OK &&
									mismatch.comparedSlices == 0U && !mismatch.previousFull200 &&
									mismatch.response.metadata.reason == Reason::NONE) ;
	different[0].response.assign( 64U, L'f') ;
	DRIVERCRATE_EXPECT( context, run( different, mismatch).status == Status::INVALID &&
									mismatch.response.generation.empty()) ;

	auto noTag = workers.at( 19U) ;	// 欠測validatorを生成しない合成fixture。
	noTag.http.entityTag.clear() ;
	const std::array withoutValidator{historyFixture( context, definition, noTag)} ;	// 正常全成功。
	Final			 noValidator ;														// 元200は存在するが条件付き送信の権限はありません。
	DRIVERCRATE_EXPECT( context, run( withoutValidator, noValidator).status == Status::OK &&
									noValidator.previousFull200 && !noValidator.previousValidator) ;
	// Codecを通る時刻改変・別intentでも元予約との再結合で停止します。
	for( unsigned mode = 0U; mode < 5U; ++mode) {
		std::array entries{history.at( 19U)} ;	// 独立した前日二件の元byte。
		auto	  &entry = entries[0] ;			// このcaseだけを書き換えます。
		Bytes	   old ;						// 既存応答codec自身では有効な所有値。
		DRIVERCRATE_EXPECT(
			context, decodeCollectorProjectedResponse( entry.campaign->job( entry.jobIndex)->value(),
													  entry.envelope, old)
							 .result.status == Status::OK) ;
		// 親受領の未来化と元開始時刻のずれは応答codecだけでは判定できません。
		if( mode <= 1U) {
			// 過去応答の受領時刻を未来へ延ばす改変を拒否します。
			if( mode == 0U) {
				old.value.accepted = accepted + 1U ;
			} else {
				old.value.started -= 1000U ;
				old.value.io.deadlineUtcMillis -= 1000U ;
			}

			Bytes changed ;	// hashも正しく再計算した改変物。
			DRIVERCRATE_EXPECT( context,
							   encodeCollectorProjectedResponse(
								   entry.campaign->job( entry.jobIndex)->value(), old.value, changed)
									   .result.status == Status::OK) ;
			entry.envelope = changed.envelope ;
			entry.response = changed.responseSha256 ;
		} else {
			CollectorProjectedCampaignDefinition decoded ;	// 同じ元入力。
			CollectorProjectedCampaignIdentity	 identity ;	// 開始intentを正当に符号化する根拠。
			CollectorRecoveryDispatch			 start ;	// 時刻だけを一要因変更します。
			DRIVERCRATE_EXPECT(
				context, parseCollectorProjectedCampaignIdentity( entry.input, decoded, identity) &&
							 parseCollectorProjectedStart( identity, entry.startIntent, start)) ;
			// Deadlineは有効範囲でも元応答と一致しなければ拒否します。
			if( mode == 2U) {
				--start.deadlineUtcMillis ;
				--start.deadlineSteadyMillis ;
			}
			// ミリ秒だけのanchor変更で応答headerより後に予約を置く偽装です。
			else if( mode == 3U) {
				++start.anchorUtcMillis ;
				++start.anchorSteadyMillis ;
			} else {
				// 別jobの実intentを流用する拒否試験です。
				entry.startIntent = history.at( 114U).startIntent ;
			}

			// 別job以外の二つは同じ専用codecで有効な開始byteを作ります。
			if( mode != 4U) {
				DRIVERCRATE_EXPECT(
					context, encodeCollectorProjectedStart( identity, start, entry.startIntent)) ;
			}
		}

		Final result = noValidator ;	// 旧元200候補も拒否時は破棄します。
		DRIVERCRATE_EXPECT( context, run( entries, result).status == Status::INVALID &&
										result.response.generation.empty() &&
										!result.previousFull200) ;
	}

	// 本文改変後に外側hashを再計算しても、元metadata hashが一致しなければ拒否します。
	std::array								forged{history.at( 19U)} ;	// 元参照のコピー。
	collector_projected_json::EnvelopeBytes oldOuter ;					// 元の応答実byte。
	DRIVERCRATE_EXPECT(
		context, collector_projected_json::decodeEnvelope( forged[0].envelope, oldOuter).status ==
					 Status::OK) ;
	const auto position = oldOuter.response.find( "\"projection\":\"") ;	// 固定field位置。
	DRIVERCRATE_EXPECT( context, position != std::string::npos) ;
	// 未検出のまま文字列を範囲外参照しません。
	if( position != std::string::npos) {
		oldOuter.response.replace( position + 14U, 64U, 64U, 'f') ;
		collector_projected_json::EnvelopeBytes outer ;	// 正しく再hashした偽応答。
		DRIVERCRATE_EXPECT( context, collector_projected_json::encodeEnvelope(
										oldOuter.response, forged[0].envelope, outer)
											.status == Status::OK) ;
		forged[0].response = outer.responseSha256 ;
		forged[0].projection.assign( 64U, L'f') ;
		Final result ;	// 二つの参照hashを書き換えても元metadataを再検証します。
		DRIVERCRATE_EXPECT( context, run( forged, result).status == Status::INVALID &&
										result.response.generation.empty()) ;
	}

	// 二段hashの元数値・allocation失敗をcache missやINVALIDへ変換しません。
	for( const auto stage : {Stage::READ_RESPONSE, Stage::READ_METADATA}) {
		// 数値OOMと実例外も分けます。
		for( const unsigned mode : {0U, 1U, 2U}) {
			const std::array entries{history.at( 19U)} ;	// 元byteをそのまま読む。
			Final			 result ;						// 故障後の公開値なし。
			unsigned		 calls{} ;						// 同一hashを再試行しない。
			const auto		 status = run( entries, result, [&]( Stage current) -> NativeError {
				  // 別hash段階は本物のCNGへ進みます。
				  if( current != stage) {
					  return 0 ;
				  }

				  ++calls ;
				  // 例外OOMの捕捉境界を確認します。
				  if( mode == 2U) {
					  throw std::bad_alloc{} ;
				  }

				  return mode == 0U ? E_ACCESSDENIED : E_OUTOFMEMORY ;
			  }) ; // 成功digestを注入するcallbackではありません。
			DRIVERCRATE_EXPECT(
				context,
				status.status == (mode == 0U ? Status::HASH_FAILURE : Status::OUT_OF_MEMORY) &&
					status.error == (mode == 0U ? E_ACCESSDENIED : E_OUTOFMEMORY) && calls == 1U &&
					result.response.generation.empty() && !result.previousFull200) ;
		}
	}
}
} // namespace drivercrate::test
