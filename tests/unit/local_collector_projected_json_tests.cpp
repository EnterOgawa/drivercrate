//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_json_tests.cpp
 * @brief 新形式のbyte境界・改変・原hash・版別排他を非通信で検証します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  有限字句・envelope・版別表の非通信試験を追加。
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 架空byte fixtureは型付きmetadataや成功応答ではありません。実収集数へ加算しません。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#include "local_collector_projected_json_tests.h"
#include "platform/local_collector_projected_json.h"
#include "platform/local_collector_projected_storage_rules.h"
#include "platform/local_collector_http_observation.h"
#include "platform/official_file_verifier.h"
#include <array>
#include <functional>
#include <limits>
#include <new>
#include <string>
#include <vector>
#include <windows.h>

namespace drivercrate::test {
namespace {
namespace json = collector_projected_json ;
/**
 * @brief 保存応答のschema世代を保持し、世代別の読取り規則を選ぶ。
 */
using Version = CollectorStoredResponseVersion ;

/** @brief 型付き例外の分類を数値で観測します。
 * @param[in] action 同期で終わる非保存操作。
 * @return 正常OKまたは元Failureの分類。
 */
json::Status failureOf( const std::function<void()> &action)
{
	try {
		action() ;
		return json::Status::OK ;
	} catch( const json::Failure &failure) {
		return failure.status ;
	}
}

/** @brief 各層のexact／+1と追記前検査を確認します。
 * @param[in,out] context Assertion集計。
 */
void sinkBoundaries( TestContext &context)
{
	// 四層を同じsinkで検査しても、それぞれ独立した上限を渡す。
	for( const auto limit :
		{json::IO_LIMIT, json::METADATA_LIMIT, json::RESPONSE_LIMIT, json::ENVELOPE_LIMIT}) {
		json::Writer	  sink( limit) ;		// 各層の空sink。
		const std::string exact( limit, 'x') ;	// 正確に上限までのraw byte。
		sink.append( exact) ;
		DRIVERCRATE_EXPECT( context, sink.view() == exact) ;
		DRIVERCRATE_EXPECT( context,
						   failureOf( [&] { sink.append( "x") ; }) == json::Status::SIZE_LIMIT) ;
		DRIVERCRATE_EXPECT( context, sink.view() == exact) ;
		DRIVERCRATE_EXPECT( context, sink.take() == exact && sink.view().empty()) ;
		const std::string quoted =
			"\"" + std::string( limit - 2U, 'x') + "\"" ;	// 有効JSONでのexact。
		json::Reader reader( quoted, limit) ;				// 型parse前にbyte数を検査する。
		DRIVERCRATE_EXPECT( context, reader.text( limit - 2U).size() == limit - 2U) ;
		reader.finish() ;
		DRIVERCRATE_EXPECT( context, failureOf( [&] {
										const json::Reader excess( quoted + "x", limit) ;
									}) == json::Status::SIZE_LIMIT) ;
		json::Writer textSink( limit) ;	// Escapeなしの引用符も予算に含む。
		textSink.text( std::string( limit - 2U, 'x')) ;
		DRIVERCRATE_EXPECT( context, textSink.view() == quoted) ;
		json::Writer overflow( limit) ;	// 追加時だけでなく文字列終端でも超過を拒否する。
		DRIVERCRATE_EXPECT( context, failureOf( [&] {
										overflow.text( std::string( limit - 1U, 'x')) ;
									}) == json::Status::SIZE_LIMIT) ;
		DRIVERCRATE_EXPECT( context, overflow.view().size() <= limit) ;
	}

	DRIVERCRATE_EXPECT( context,
					   failureOf( [] { const json::Writer invalid( 0U) ; }) == json::Status::INVALID) ;
	DRIVERCRATE_EXPECT( context, failureOf( [] {
									const json::Writer invalid( json::ENVELOPE_LIMIT + 1U) ;
								}) == json::Status::INVALID) ;
	json::Writer escaping( 6U) ;	// 二文字が各二byteとなり、引用符を含めexact。
	escaping.text( "\"\\") ;
	DRIVERCRATE_EXPECT( context, escaping.view() == "\"\\\"\\\\\"") ;
	json::Writer tooSmall( 5U) ;	// 同じ二文字でも表現後byteで拒否する。
	DRIVERCRATE_EXPECT( context,
					   failureOf( [&] { tooSmall.text( "\"\\") ; }) == json::Status::SIZE_LIMIT) ;
	json::Reader limited( "\"abcd\"", 6U) ;	// 入力予算と解除後予算の独立性。
	DRIVERCRATE_EXPECT( context, failureOf( [&] { static_cast<void>( limited.text( 3U)) ; }) ==
									json::Status::SIZE_LIMIT) ;
}

/** @brief 最短Unicodeと整数表現を確認します。
 * @param[in,out] context Assertion集計。
 */
void scalars( TestContext &context)
{
	const std::wstring text =
		L"日本語/quote\"slash\\\U0001f4e6" ;	// 公開text policyとは独立した字句fixture。
	const std::string expected =
		"\"日本語/quote\\\"slash\\\\\xf0\x9f\x93\xa6\"" ;	// 正規の最短UTF-8。
	json::Writer sink( 1024U) ;							// BOM・改行・正規化を追加しない。
	sink.wideText( text) ;
	DRIVERCRATE_EXPECT( context, sink.view() == expected) ;
	json::Reader reader( sink.view(), 1024U) ;		// 正規形を原Unicodeへ戻す。
	const auto	 decoded = reader.text( 1024U) ;	// UTF-8の解除結果。
	reader.finish() ;
	json::Writer second( 1024U) ;	// 二回目でも元byteを保持する。
	second.text( decoded) ;
	DRIVERCRATE_EXPECT( context, second.view() == expected) ;
	// ASCII外の各長さの端を最短表現で扱う。
	for( const std::wstring &value : {std::wstring( L"\x7f\x80\x7ff\x800\xd7ff\xe000\xffff"),
									 std::wstring( L"\U00010000\U0010ffff")}) {
		json::Writer encoded( 128U) ;	// Scalar境界fixture。
		encoded.wideText( value) ;
		json::Reader scan( encoded.view(), 128U) ;	// 同じ原byteを受理する。
		json::Writer again( 128U) ;					// UTF-8再encodeの一致。
		again.text( scan.text( 128U)) ;
		scan.finish() ;
		DRIVERCRATE_EXPECT( context, encoded.view() == again.view()) ;
	}

	// 制御文字はどの位置でも文字列として出力しない。
	for( unsigned int code = 0U; code < 32U; ++code) {
		json::Writer	  encoded( 128U) ;							// 一件ずつ空sinkへ戻す。
		const std::string value( 1U, static_cast<char>( code)) ;	// Raw C0またはNUL。
		DRIVERCRATE_EXPECT( context,
						   failureOf( [&] { encoded.text( value) ; }) == json::Status::INVALID) ;
		DRIVERCRATE_EXPECT( context, failureOf( [&] {
										const json::Reader invalid( "\"" + value + "\"", 128U) ;
									}) == json::Status::INVALID) ;
		const std::wstring wide( 1U, static_cast<wchar_t>( code)) ;	// UTF-16側も同じ禁止。
		DRIVERCRATE_EXPECT( context,
						   failureOf( [&] { encoded.wideText( wide) ; }) == json::Status::INVALID) ;
	}

	// 孤立・逆順surrogateをsilent replacementへ変換しない。
	for( const std::wstring &value : {std::wstring( 1U, L'\xd800'), std::wstring( 1U, L'\xdc00'),
									 std::wstring( L"\xdc00\xd800"), std::wstring( L"\xd800X")}) {
		json::Writer encoded( 128U) ;	// 不正code unit専用。
		DRIVERCRATE_EXPECT( context,
						   failureOf( [&] { encoded.wideText( value) ; }) == json::Status::INVALID) ;
	}

	// 継続欠損・過長・surrogate・Unicode上限超過のbyte列を全て拒否する。
	for( const std::string &value :
		{std::string( "\x80"), std::string( "\xc0\xaf"), std::string( "\xc2"),
		 std::string( "\xe0\x80\xaf"), std::string( "\xed\xa0\x80"), std::string( "\xf0\x80\x80\xaf"),
		 std::string( "\xf4\x90\x80\x80"), std::string( "\xf5\x80\x80\x80"), std::string( "\xe3\x81"),
		 std::string( "\xe3X\x82")}) {
		json::Writer encoded( 128U) ;	// 不正UTF-8を上位schemaへ渡さない。
		DRIVERCRATE_EXPECT( context,
						   failureOf( [&] { encoded.text( value) ; }) == json::Status::INVALID) ;
		DRIVERCRATE_EXPECT( context, failureOf( [&] {
										const json::Reader invalid( "\"" + value + "\"", 128U) ;
									}) == json::Status::INVALID) ;
	}

	// 0、32bit境界、JSON精度上限を丸めず往復する。
	for( const auto value :
		{0ULL, 1ULL, 9ULL, 10ULL, 4294967295ULL, 4294967296ULL, json::MAX_INTEGER}) {
		json::Writer encoded( 32U) ;	// 十進固定表現。
		encoded.number( value) ;
		DRIVERCRATE_EXPECT( context, encoded.view() == std::to_string( value)) ;
		json::Reader decodedNumber( encoded.view(), 32U) ;	// doubleを経由しない。
		DRIVERCRATE_EXPECT( context, decodedNumber.number() == value) ;
		decodedNumber.finish() ;
	}

	json::Writer number( 32U) ;	// 上限外の拒否。
	DRIVERCRATE_EXPECT( context, failureOf( [&] { number.number( json::MAX_INTEGER + 1U) ; }) ==
									json::Status::INVALID) ;
	DRIVERCRATE_EXPECT( context, failureOf( [&] {
									number.number( std::numeric_limits<std::uint64_t>::max()) ;
								}) == json::Status::INVALID) ;
}

/** @brief 型parseに入る前の全字句・深さ検査と原byte借用を確認します。
 * @param[in,out] context Assertion集計。
 */
void grammar( TestContext &context)
{
	// 別表現、途中終端、複数root、空白、型の崩れを拒否する。
	for( const std::string &value : {"",
									" ",
									"{}\n",
									" {}",
									"{ }",
									"[]true",
									"[1,]",
									"{\"a\":}",
									"{\"a\":0,}",
									"[}",
									"{]",
									"{a:0}",
									"{\"a\"0}",
									"00",
									"01",
									"-0",
									"-1",
									"+1",
									"1.0",
									"1e0",
									"NaN",
									"Infinity",
									"True",
									"NULL",
									"tru",
									"falsee",
									"9007199254740992",
									"18446744073709551615",
									"\"\\/\"",
									"\"\\u0041\"",
									"\"\\u65e5\"",
									"\"\\n\"",
									"\"\\t\"",
									"\"x",
									"\"x\\",
									"\xef\xbb\xbf{}"}) {
		DRIVERCRATE_EXPECT( context, failureOf( [&] { const json::Reader invalid( value, 1024U) ; }) ==
										json::Status::INVALID) ;
	}

	// 深さ16は許可し、17は入力が有限でも拒否する。
	for( std::size_t depth = 1U; depth <= 17U; ++depth) {
		const std::string value =
			// 純array深さ。
			std::string( depth, '[') + "0" + std::string( depth, ']') ;
		const auto result =
			// 事前検査のみ。
			failureOf( [&] { const json::Reader checked( value, 1024U) ; }) ;
		DRIVERCRATE_EXPECT( context,
						   result == (depth <= 16U ? json::Status::OK : json::Status::INVALID)) ;
	}

	const std::string mixed =
		"{\"list\":[true,false,null,\"[[[\\\"}}}\",9007199254740991]}" ;	// 字符中の括弧は深さではない。
	json::Reader reader( mixed, 1024U) ;									// 元byteを部分objectへ分割する。
	reader.literal( "{\"list\":") ;
	const auto raw = reader.value() ;	// 内側arrayのbyteをそのまま借用する。
	DRIVERCRATE_EXPECT( context, raw == std::string_view( mixed).substr( 8U, mixed.size() - 9U)) ;
	reader.literal( "}") ;
	reader.finish() ;
	json::Reader unconsumed( "{}", 16U) ;	// 消費し忘れも成功にしない。
	DRIVERCRATE_EXPECT( context, failureOf( [&] { unconsumed.finish() ; }) == json::Status::INVALID) ;
	DRIVERCRATE_EXPECT( context,
					   failureOf( [&] { unconsumed.literal( "[]") ; }) == json::Status::INVALID) ;
	DRIVERCRATE_EXPECT( context, failureOf( [&] { static_cast<void>( unconsumed.number()) ; }) ==
									json::Status::INVALID) ;
}

/** @brief 実CNGで外側のhash対象・非正規形拒否・失敗分離を確認します。
 * @param[in,out] context Assertion集計。
 */
void envelopes( TestContext &context)
{
	const std::string response =
		"{\"schema\":\"collector-campaign-response-v4\",\"fixture\":\"日本語\\\"\\\\\",\"n\":0}" ;	// 意味検査前のbyte fixture。
	std::string					 encoded ;														// 保存は行わずメモリ内だけで検査する。
	json::EnvelopeBytes			 original ;														// 原byteと実CNG digest。
	std::size_t					 hashCalls{} ;													// 0を返してもCNGが実行される診断。
	const json::HashFailureProbe observe = [&] {
		++hashCalls ;
		return NativeError{0} ;
	} ; // 数値だけのprobe。
	DRIVERCRATE_EXPECT( context, json::encodeEnvelope( response, encoded, original, observe).status ==
									json::Status::OK) ;
	std::wstring expected ;	// 外側ではなく本文だけの独立hash。
	DRIVERCRATE_EXPECT( context, computeBytesSha256( response, expected) == 0) ;
	DRIVERCRATE_EXPECT(
		context, expected == L"219defb3e0805a5012ffaa561c55513c096523f32e51b1f7acebfe0516a53a32") ;
	DRIVERCRATE_EXPECT( context,
					   original.response == response && original.responseSha256 == expected) ;
	json::EnvelopeBytes restored ;	// Readerの独立CNG後だけ公開される値。
	DRIVERCRATE_EXPECT( context,
					   json::decodeEnvelope( encoded, restored, observe).status == json::Status::OK) ;
	DRIVERCRATE_EXPECT( context, hashCalls == 2U && restored.response == response &&
									restored.responseSha256 == expected) ;
	std::string			encodedAgain ;	// Canonical外側も一意なbyteへ戻る。
	json::EnvelopeBytes roundTrip ;		// 別出力を使いaliasを避ける。
	DRIVERCRATE_EXPECT( context,
					   json::encodeEnvelope( restored.response, encodedAgain, roundTrip).status ==
							   json::Status::OK &&
						   encodedAgain == encoded) ;

	std::vector<std::string> mutations ;	// 構文・型・field・hashの改変集合。
	mutations.push_back( encoded + "\n") ;
	mutations.push_back( " " + encoded) ;
	mutations.push_back( encoded.substr( 0U, encoded.size() - 1U) + ",\"extra\":0}") ;
	mutations.push_back( encoded.substr( 0U, encoded.size() - 1U) + ",\"body\":\"duplicate\"}") ;
	mutations.push_back( encoded.substr( 0U, encoded.size() - 1U) + ",\"sha256\":\"duplicate\"}") ;
	mutations.push_back( encoded.substr( 0U, encoded.size() - 1U) + ",\"schema\":\"duplicate\"}") ;
	std::string changed				= encoded ;	// Canonical文字列内の一byte改変。
	changed[changed.find( "日本語")] = 'x' ;
	mutations.push_back( changed) ;
	// 内容は同じでもkeyの別escapeを拒否する。
	changed = encoded ;
	changed.replace( changed.find( "\"body\""), 6U, "\"b\\u006fdy\"") ;
	mutations.push_back( changed) ;
	// 正しいhex桁数でも異なるdigestを拒否する。
	changed						 = encoded ;
	changed[changed.size() - 3U] = changed[changed.size() - 3U] == 'a' ? 'b' : 'a' ;
	mutations.push_back( changed) ;
	// Hashのuppercaseを許容しない。
	changed						 = encoded ;
	changed[changed.size() - 3U] = 'A' ;
	mutations.push_back( changed) ;
	// Bodyの型をstring以外へ変更する。
	changed				 = encoded ;
	const auto bodyStart = changed.find( "\"body\":") + 7U ;	// 固定fieldの値の位置。
	const auto hashStart = changed.find( ",\"sha256\":") ;		// Body fieldの終端。
	changed.replace( bodyStart, hashStart - bodyStart, "{}") ;
	mutations.push_back( changed) ;
	// 未知のouter schemaを拒否する。
	changed = encoded ;
	changed.replace( changed.find( "envelope-v1"), 11U, "envelope-v2") ;
	mutations.push_back( changed) ;
	// 正しいUTF-8とJSONのまま本文を変更しても、元hashは一致しない。
	changed = encoded ;
	changed.replace( changed.find( "fixture"), 7U, "changed") ;
	mutations.push_back( changed) ;
	json::Writer reordered( json::ENVELOPE_LIMIT) ;	// 同じ三fieldでも順序変更を拒否する。
	reordered.append( "{\"schema\":\"collector-campaign-envelope-v1\",\"sha256\":") ;
	reordered.wideText( expected) ;
	reordered.append( ",\"body\":") ;
	reordered.text( response) ;
	reordered.append( "}") ;
	mutations.push_back( reordered.take()) ;
	// 失敗時には以前の結果を返さず全出力を空にする。
	for( const auto &mutation : mutations) {
		restored = original ;
		DRIVERCRATE_EXPECT( context,
						   json::decodeEnvelope( mutation, restored).status != json::Status::OK) ;
		DRIVERCRATE_EXPECT( context, restored.response.empty() && restored.responseSha256.empty()) ;
	}

	// 有限入力の全途中切断が成功へ流れないことを検査する。
	for( std::size_t length = 0U; length < encoded.size(); ++length) {
		DRIVERCRATE_EXPECT(
			context,
			json::decodeEnvelope( std::string_view( encoded).substr( 0U, length), restored).status !=
				json::Status::OK) ;
	}

	hashCalls							= 0U ;
	const json::HashFailureProbe denied = [&] {
		++hashCalls ;
		return NativeError{E_ACCESSDENIED} ;
	} ; // 元HRESULTの失敗だけ。
	std::string failed = "stale" ;	// 失敗時の消去を検査する。
	restored		   = original ;
	const auto encodingFailure =
		// 自動retryなし。
		json::encodeEnvelope( response, failed, restored, denied) ;
	DRIVERCRATE_EXPECT( context, encodingFailure.status == json::Status::HASH_FAILURE &&
									encodingFailure.error == E_ACCESSDENIED) ;
	DRIVERCRATE_EXPECT( context, hashCalls == 1U && failed.empty() && restored.response.empty() &&
									restored.responseSha256.empty()) ;
	const auto decodingFailure =
		// 読取り側もfailureのまま。
		json::decodeEnvelope( encoded, restored, denied) ;
	DRIVERCRATE_EXPECT( context, decodingFailure.status == json::Status::HASH_FAILURE &&
									decodingFailure.error == E_ACCESSDENIED && hashCalls == 2U) ;
	DRIVERCRATE_EXPECT( context,
					   original.response == response && original.responseSha256 == expected) ;
	DRIVERCRATE_EXPECT( context, json::encodeEnvelope( response, failed, restored, [] {
									return NativeError{E_OUTOFMEMORY} ;
								}).status == json::Status::OUT_OF_MEMORY) ;
	DRIVERCRATE_EXPECT( context, json::decodeEnvelope( encoded, restored, []() -> NativeError {
									throw std::bad_alloc{} ;
								}).status == json::Status::OUT_OF_MEMORY) ;
	DRIVERCRATE_EXPECT( context, json::encodeEnvelope( response, failed, restored, [] {
									return NativeError{1} ;
								}).status == json::Status::INVALID) ;
	DRIVERCRATE_EXPECT( context, json::encodeEnvelope(
									"{\"schema\":\"collector-campaign-response-v3\",\"fixture\":0}",
									failed, restored)
										.status == json::Status::INVALID) ;
	// 応答768 KiBを外側でescapeしても応答自身の上限を変えない。
	const std::string prefix =
		"{\"schema\":\"collector-campaign-response-v4\",\"fixture\":\"" ;	// 字句だけの大容量fixture。
	const std::string exact =
		prefix + std::string( json::RESPONSE_LIMIT - prefix.size() - 2U, 'x') + "\"}" ;	// exact。
	DRIVERCRATE_EXPECT( context,
					   json::encodeEnvelope( exact, failed, restored).status == json::Status::OK) ;
	json::EnvelopeBytes large ;	// 非aliasの読取り出力。
	DRIVERCRATE_EXPECT( context, json::decodeEnvelope( failed, large).status == json::Status::OK &&
									large.response == exact) ;
	DRIVERCRATE_EXPECT( context, json::encodeEnvelope( exact + "x", failed, restored).status ==
									json::Status::SIZE_LIMIT) ;
	DRIVERCRATE_EXPECT( context, failed.empty() && restored.response.empty()) ;
	DRIVERCRATE_EXPECT(
		context,
		json::decodeEnvelope( std::string( json::ENVELOPE_LIMIT + 1U, 'x'), restored).status ==
			json::Status::SIZE_LIMIT) ;
	json::Writer escapedBody( json::RESPONSE_LIMIT) ;	// 二重JSON化で増える最大級のescape集合。
	escapedBody.append( "{\"schema\":\"collector-campaign-response-v4\",\"fixture\":") ;
	escapedBody.text( std::string( 380000U, '\\')) ;
	escapedBody.append( "}") ;
	DRIVERCRATE_EXPECT( context,
					   json::encodeEnvelope( escapedBody.view(), encodedAgain, roundTrip).status ==
						   json::Status::OK) ;
	DRIVERCRATE_EXPECT( context, encodedAgain.size() > json::RESPONSE_LIMIT &&
									encodedAgain.size() <= json::ENVELOPE_LIMIT) ;
	DRIVERCRATE_EXPECT( context,
					   json::decodeEnvelope( encodedAgain, restored).status == json::Status::OK &&
						   restored.response == escapedBody.view()) ;
}

/** @brief 元I/O v1のbyteを並べ替えず新字句層へ埋め込めることを検査します。
 * @param[in,out] context Assertion集計。
 */
void ioCompatibility( TestContext &context)
{
	CollectorIoSnapshot io ;	// Codec単体の固定観測。Worker成功を注入する試験ではない。
	io.cause			 = CollectorIoCause::COMPLETE ;
	io.stage			 = CollectorIoStage::COMPLETE ;
	io.deadlineUtcMillis = 2000U ;
	io.elapsedMillis	 = 100U ;
	io.headerUtcMillis	 = 1000U ;
	io.lowerBytes		 = 123U ;
	io.nativeReleased	 = true ;
	io.sealed			 = true ;
	const std::wstring permit( 64U, L'a') ;	// 架空O。
	std::string		   bytes ;				// 既存WinRT codecの原出力。
	DRIVERCRATE_EXPECT( context, encodeCollectorHttpObservation( io, permit, bytes)) ;
	const std::string golden =
		"{\"schema\":\"collector-http-observation-v1\",\"permit\":\"" + std::string( 64U, 'a') +
		// 旧順序の固定golden。
		"\",\"deadline\":2000,\"elapsed\":100,\"headerUtc\":1000,\"cause\":\"COMPLETE\",\"stage\":\"COMPLETE\",\"native\":null,\"lowerBytes\":123,\"stopElapsed\":null,\"nativeReleased\":true}" ;
	DRIVERCRATE_EXPECT( context, bytes == golden) ;
	json::Writer outer( json::RESPONSE_LIMIT) ;	// 新側でもI/O objectの原byteを維持する。
	outer.append( "{\"io\":") ;
	outer.append( bytes) ;
	outer.append( "}") ;
	json::Reader restored( outer.view(), json::RESPONSE_LIMIT) ;	// 型付き上位codecの消費手順。
	restored.literal( "{\"io\":") ;
	const auto raw = restored.value() ;	// Objectを再Stringifyしない。
	restored.literal( "}") ;
	restored.finish() ;
	DRIVERCRATE_EXPECT( context, raw == bytes) ;
	CollectorIoSnapshot decoded ;	// 旧codecでも同じbyteを受理する。
	DRIVERCRATE_EXPECT( context, decodeCollectorHttpObservation( raw, permit, decoded)) ;
	DRIVERCRATE_EXPECT( context,
					   decoded.headerUtcMillis == io.headerUtcMillis && decoded.lowerBytes == 123U) ;
}

/** @brief 全存在組合せ・世代別状態表・固定保存名を検査します。
 * @param[in,out] context Assertion集計。
 */
void storageRules( TestContext &context)
{
	const std::array<Version, 8U> expected{Version::ABSENT,	  Version::V2,		Version::V3,
										   Version::CONFLICT, Version::V4,		Version::CONFLICT,
										   Version::CONFLICT, Version::CONFLICT} ;	// 三bit存在表。
	// 全八通りを固定表と照合し、最新優先による隠蔽を防ぐ。
	for( std::size_t mask = 0U; mask < expected.size(); ++mask) {
		DRIVERCRATE_EXPECT( context,
						   collectorStoredResponseVersion( (mask & 1U) != 0U, (mask & 2U) != 0U,
														  (mask & 4U) != 0U) == expected[mask]) ;
	}

	const std::wstring hash( 64U, L'a') ;	// 架空の元O／応答hash。
	DRIVERCRATE_EXPECT( context, collectorResponseFileName( Version::V2, hash) ==
									L"runs/campaign-response-v2-" + hash + L".json") ;
	DRIVERCRATE_EXPECT( context, collectorResponseFileName( Version::V3, hash) ==
									L"runs/campaign-response-v3-" + hash + L".json") ;
	DRIVERCRATE_EXPECT( context, collectorResponseFileName( Version::V4, hash) ==
									L"runs/campaign-response-v4-" + hash + L".json") ;
	DRIVERCRATE_EXPECT( context, !collectorResponseFileName( Version::ABSENT, hash) &&
									!collectorResponseFileName( Version::CONFLICT, hash)) ;
	// 相対path・大文字・短いhashを保存名の一部へ採用しない。
	for( const std::wstring &bad : {std::wstring{}, std::wstring( 63U, L'a'), std::wstring( 64U, L'A'),
								   std::wstring( 64U, L'g'), std::wstring( L"../response")}) {
		DRIVERCRATE_EXPECT( context, !collectorResponseFileName( Version::V4, bad)) ;
		DRIVERCRATE_EXPECT( context, !collectorProjectedStateShapeAllowed( L"FETCHED", true,
																		 Version::V4, bad, hash)) ;
		DRIVERCRATE_EXPECT( context, !collectorProjectedStateShapeAllowed( L"FETCHED", true,
																		 Version::V4, hash, bad)) ;
	}

	const std::array<std::wstring_view, 10U> states{
		L"PENDING",		L"DEFERRED", L"RUNNING", L"INTERRUPTED", L"OBSERVED", L"FETCHED",
		L"REVALIDATED", L"FAILED",	 L"HELD",	 L"UNKNOWN"} ;	// 旧新と未知の状態集合。
	// 各版の許可pairを固定の正例表と比較する。
	for( std::uint32_t storage = 1U; storage <= 4U; ++storage) {
		// 未知enumも正例表にないものとして拒否する。
		for( const auto version : {Version::ABSENT, Version::V2, Version::V3, Version::V4,
								  Version::CONFLICT, static_cast<Version>( 99)}) {
			// 全状態に対しI/Oの欠測／存在を個別に測る。
			for( const auto state : states) {
				// 二つのbool値を固定順に検査する。
				for( const bool observed : {false, true}) {
					bool			   allowed{} ;	// 下の明示正例集合だけを有効にする。
					const std::wstring key = std::to_wstring( storage) + L":" +
											 std::to_wstring( static_cast<int>( version)) + L":" +
											 std::wstring( state) +
											 (observed ? L":1" : L":0") ;	// 直積の一条件。
					const std::array<std::wstring_view, 12U> positive{
						L"2:1:OBSERVED:0", L"2:1:FAILED:0",
						L"2:1:HELD:0",	   L"2:1:INTERRUPTED:0",
						L"2:2:OBSERVED:1", L"2:2:FAILED:1",
						L"2:2:HELD:1",	   L"3:1:INTERRUPTED:0",
						L"3:3:FETCHED:1",  L"3:3:REVALIDATED:1",
						L"3:3:FAILED:1",   L"3:3:HELD:1"} ;	// 独立した許可一覧。
					// 条件式を複製せず、仕様の正例集合へ完全一致させる。
					for( const auto candidate : positive) {
						allowed = allowed || candidate == key ;
					}

					DRIVERCRATE_EXPECT( context, collectorResponseVersionAllowed(
													storage, version, state, observed) == allowed) ;
				}
			}
		}
	}

	// 新終端はv4・元intent・hash・Oの全てを要求する。
	for( const auto state : {L"FETCHED", L"REVALIDATED", L"FAILED", L"HELD"}) {
		DRIVERCRATE_EXPECT(
			context, collectorProjectedStateShapeAllowed( state, true, Version::V4, hash, hash)) ;
		DRIVERCRATE_EXPECT(
			context, !collectorProjectedStateShapeAllowed( state, false, Version::V4, hash, hash)) ;
		DRIVERCRATE_EXPECT(
			context, !collectorProjectedStateShapeAllowed( state, true, Version::V3, hash, hash)) ;
		DRIVERCRATE_EXPECT(
			context, !collectorProjectedStateShapeAllowed( state, true, Version::V2, hash, hash)) ;
	}

	DRIVERCRATE_EXPECT(
		context, collectorProjectedStateShapeAllowed( L"PENDING", false, Version::ABSENT, L"", L"")) ;
	DRIVERCRATE_EXPECT( context, collectorProjectedStateShapeAllowed( L"DEFERRED", false,
																	Version::ABSENT, L"", L"")) ;
	DRIVERCRATE_EXPECT(
		context, collectorProjectedStateShapeAllowed( L"RUNNING", true, Version::ABSENT, L"", L"")) ;
	DRIVERCRATE_EXPECT(
		context, !collectorProjectedStateShapeAllowed( L"PENDING", true, Version::ABSENT, L"", L"")) ;
	DRIVERCRATE_EXPECT( context, !collectorProjectedStateShapeAllowed( L"RUNNING", false,
																	 Version::ABSENT, L"", L"")) ;
	DRIVERCRATE_EXPECT(
		context, !collectorProjectedStateShapeAllowed( L"RUNNING", true, Version::V4, hash, hash)) ;
	DRIVERCRATE_EXPECT(
		context, !collectorProjectedStateShapeAllowed( L"OBSERVED", true, Version::V4, hash, hash)) ;
	DRIVERCRATE_EXPECT(
		context, !collectorProjectedStateShapeAllowed( L"UNKNOWN", true, Version::V4, hash, hash)) ;
	DRIVERCRATE_EXPECT( context, collectorProjectedStateShapeAllowed( L"INTERRUPTED", false,
																	Version::V2, hash, hash)) ;
	DRIVERCRATE_EXPECT( context, collectorProjectedStateShapeAllowed( L"INTERRUPTED", true,
																	Version::V2, hash, hash)) ;
	DRIVERCRATE_EXPECT( context, !collectorProjectedStateShapeAllowed( L"INTERRUPTED", true,
																	 Version::V4, hash, hash)) ;
}
} // namespace

/** @see local_collector_projected_json_tests.h */
void runCollectorProjectedJsonTests( TestContext &context)
{
	sinkBoundaries( context) ;
	scalars( context) ;
	grammar( context) ;
	envelopes( context) ;
	ioCompatibility( context) ;
	storageRules( context) ;
}
} // namespace drivercrate::test
