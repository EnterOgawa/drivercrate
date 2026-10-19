//------------------------------------------------------------------------------
/**
 * @file local_driver_collector_tests.cpp
 * @brief 非通信の時計・HTTP fixtureで収集run再開を検証します。
 * @version 01.11.03
 * @date 2026/09/27
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/25  日跨ぎ再開とHTTP試験入口を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/25  条件付きHTTPと200・304の永続接続を検証。
 * Ver.01.02.00 Shunji Ogawa  2026/09/25  待機期限・中断回収・破損・保留のfixtureを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/27  mode存在時の旧収集・通信抑止を検証。
 * Ver.01.04.00 Shunji Ogawa  2026/09/27  全旧契約の非変更読込みと未回収拒否を検証。
 * Ver.01.05.00 Shunji Ogawa  2026/09/27  旧複数manifestと403・Retry-Afterの取込み検証。
 * Ver.01.06.00 Shunji Ogawa  2026/09/27  実v4保存物からv2への移行と旧履歴変更を検証。
 * Ver.01.07.00 Shunji Ogawa  2026/09/27  共通request生成と旧canonical keyの一致を検証。
 * Ver.01.08.00 Shunji Ogawa  2026/10/03  非変更待機exportと欠損・競合・未回収拒否を検証。
 * Ver.01.09.00 Shunji Ogawa  2026/10/14  新200原byteと304／失敗の空出力を検証。
 * Ver.01.10.00 Shunji Ogawa  2026/10/15  日次receiptとdue前後・保護本文・世代を検証。
 * Ver.01.11.00 Shunji Ogawa  2026/10/17  原日次予約の非変更照合と拒否分母を追加。
 * Ver.01.11.01 Shunji Ogawa  2026/10/18  日跨ぎfixtureの元戻り値と状態errorを診断表示。
 * Ver.01.11.02 Shunji Ogawa  2026/10/18 一時path診断を除去し元の期待と評価回数を保持。
 * Ver.01.11.03 Shunji Ogawa  2026/10/18 自作fixtureの実I/O表記を揃え長い保存物を検査。
 * </pre>
 *
 * @note fixtureで新規作成した専用root以外を変更せず、実networkを使いません。
 */
//------------------------------------------------------------------------------

#include "platform/local_driver_collector.h"
#include "platform/official_http_transport.h"
#include "platform/official_http_client.h"
#include "platform/official_file_verifier.h"
#include "platform/official_release_metadata.h"
#include "platform/local_collector_state_store.h"
#include "platform/local_collector_legacy.h"
#include "platform/local_collector_recovery.h"
#include "core/provider_registry.h"
#include "core/official_source_policy.h"
#include "test_framework.h"

#include <Windows.h>
#include <objbase.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#include <chrono>
#include <cstring>
#include <algorithm>
#include <map>
#include <filesystem>
#include <fstream>
#include <format>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace drivercrate::test {
namespace {

// fake transportのopen到達回数。実通信なしを間接確認する。
std::uint32_t	 fakeOpenCalls{} ;

/** @brief 実WinHTTPを呼ばず通信失敗を返します。 */
HINTERNET WINAPI failedOpen( LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD)
{
	++fakeOpenCalls ;
	SetLastError( ERROR_GEN_FAILURE) ;
	return nullptr ;
}

/** @brief 実DNSを使わず公開宛先一件を返します。 */
NativeError publicDestination( std::wstring_view,
							  std::vector<OfficialResolvedNetworkAddress> &addresses)
{
	OfficialResolvedNetworkAddress address ;	// 架空の公開IPv4。
	address.family	 = OfficialNetworkAddressFamily::IPV4 ;
	address.bytes[0] = std::byte{8} ;
	address.bytes[1] = std::byte{8} ;
	address.bytes[2] = std::byte{8} ;
	address.bytes[3] = std::byte{8} ;
	addresses		 = {address} ;
	return 0 ;
}

/** @brief 全I/Oを置換した応答と送信観測です。 */
struct CollectorHttpFixture {
	/// 固定HTTP status。
	DWORD									   status{200U} ;
	/// Redirect試験時だけ使う有限status列。
	std::vector<DWORD>						   sequence ;
	/// 同名headerも保持するfixture。
	std::map<DWORD, std::vector<std::wstring>> headers ;
	/// 保存しない架空本文。
	std::string								   body{"<html>fixture</html>"} ;
	/// 今回のGET header観測。
	std::wstring							   sentHeaders ;
	/// 本文位置。
	std::size_t								   offset{} ;
	/// 全送信件数。
	unsigned								   sends{} ;
	/// 本文読取り件数。
	unsigned								   reads{} ;
	/// 固定option観測bit。
	unsigned								   options{} ;
} ;

thread_local CollectorHttpFixture  *activeFixture{} ;	// C関数pointer用のthread内状態。

/** @brief 接続・DNSを含む全低位呼出しをfakeへ固定します。 */
[[nodiscard]] OfficialHttpTransport fixtureTransport( CollectorHttpFixture &fixture)
{
	activeFixture = &fixture ;
	OfficialHttpTransport transport ;	// 実通信を一切持たないI/O表。
	transport.resolveDestination = publicDestination ;
	transport.open				 = []( LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) -> HINTERNET {
		  activeFixture->sentHeaders.clear() ;
		  activeFixture->options = 0U ;
		  return activeFixture ;
	} ;
	transport.connect = []( HINTERNET handle, LPCWSTR, INTERNET_PORT, DWORD) -> HINTERNET {
		return handle ;
	} ;
	transport.openRequest = []( HINTERNET handle, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *,
							   DWORD) -> HINTERNET { return handle ; } ;
	transport.setTimeouts = []( HINTERNET, int, int, int, int) -> BOOL { return TRUE ; } ;
	transport.setOption	  = []( HINTERNET handle, DWORD option, LPVOID value, DWORD bytes) -> BOOL {
		  auto &state = *static_cast<CollectorHttpFixture *>( handle) ;	// Option観測。
		  // 想定外のoptionを暗黙成功させない。
		  if( bytes != sizeof( DWORD)) {
			  return FALSE ;
		  }

		  const auto setting = *static_cast<DWORD *>( value) ;	// API設定値。
		  // Cookie送受信禁止を確認する。
		  if( option == WINHTTP_OPTION_DISABLE_FEATURE && setting == WINHTTP_DISABLE_COOKIES) {
			  state.options |= 1U ;
			  return TRUE ;
		  }

		  // 既定資格情報を使用しない。
		  if( option == WINHTTP_OPTION_AUTOLOGON_POLICY &&
			 setting == WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH) {
			  state.options |= 2U ;
			  return TRUE ;
		  }

		  // 自動redirectは使わない。
		  if( option == WINHTTP_OPTION_REDIRECT_POLICY &&
			 setting == WINHTTP_OPTION_REDIRECT_POLICY_NEVER) {
			  state.options |= 4U ;
			  return TRUE ;
		  }

		  return FALSE ;
	} ;
	transport.addHeaders = []( HINTERNET handle, LPCWSTR headers, DWORD length, DWORD) -> BOOL {
		static_cast<CollectorHttpFixture *>( handle)->sentHeaders.append( headers, length) ;
		return TRUE ;
	} ;
	transport.sendRequest = []( HINTERNET handle, LPCWSTR, DWORD, LPVOID, DWORD, DWORD,
							   DWORD_PTR) -> BOOL {
		auto &state = *static_cast<CollectorHttpFixture *>( handle) ;	// 送信数と本文位置。
		// 指定した系列がある場合だけ次の応答へ進める。
		if( !state.sequence.empty()) {
			state.status =
				state.sequence[std::min<std::size_t>( state.sends, state.sequence.size() - 1U)] ;
		}

		++state.sends ;
		state.offset = 0U ;
		return TRUE ;
	} ;
	transport.receiveResponse = []( HINTERNET, LPVOID) -> BOOL { return TRUE ; } ;
	transport.queryHeaders = []( HINTERNET handle, DWORD info, LPCWSTR, LPVOID output, LPDWORD bytes,
								LPDWORD index) -> BOOL {
		auto &state = *static_cast<CollectorHttpFixture *>( handle) ;	// 現在応答。
		// 数値statusをWinHTTPのsizeで返す。
		if( info == (WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER)) {
			*static_cast<DWORD *>( output) = state.status ;
			*bytes						  = sizeof( DWORD) ;
			return TRUE ;
		}

		const auto found	= state.headers.find( info) ;	// 同名header集合。
		const auto position = index ? *index : 0U ;			// Header列挙位置。
		// 欠損または列挙完了。
		if( found == state.headers.end() || position >= found->second.size()) {
			SetLastError( ERROR_WINHTTP_HEADER_NOT_FOUND) ;
			return FALSE ;
		}

		const auto &value = found->second[position] ;	// 今回のheader値。
		const auto	required =
			// 終端込み長。
			static_cast<DWORD>( (value.size() + 1U) * sizeof( wchar_t)) ;
		// 必要sizeの事前照会。
		if( output == nullptr || *bytes < required) {
			*bytes = required ;
			SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			return FALSE ;
		}

		std::memcpy( output, value.c_str(), required) ;
		*bytes = required - sizeof( wchar_t) ;
		// 本読取り時だけ次のheaderへ進める。
		if( index) {
			++*index ;
		}

		return TRUE ;
	} ;
	transport.queryAvailable = []( HINTERNET handle, LPDWORD available) -> BOOL {
		const auto &state = *static_cast<CollectorHttpFixture *>( handle) ;	// 残本文。
		*available		  = static_cast<DWORD>( state.body.size() - state.offset) ;
		return TRUE ;
	} ;
	transport.readData = []( HINTERNET handle, LPVOID output, DWORD requested,
							LPDWORD received) -> BOOL {
		auto	  &state = *static_cast<CollectorHttpFixture *>( handle) ;	// 現読取り位置。
		const auto count =
			std::min<std::size_t>( requested, state.body.size() - state.offset) ;	// 有限copy長。
		std::memcpy( output, state.body.data() + state.offset, count) ;
		state.offset += count ;
		++state.reads ;
		*received = static_cast<DWORD>( count) ;
		return TRUE ;
	} ;
	transport.closeHandle = []( HINTERNET) -> BOOL { return TRUE ; } ;
	return transport ;
}

/** @brief 収集専用HTTPの再確認と通常取得根拠の分離を検証します。
 * @param[in,out] context 原期待を削除しないassertion集計。
 * @note 全HTTPは有限RAM fixtureであり、実通信・端末照合・取得許可を発行しません。
 */
void conditionalHttp( TestContext &context)
{
	CollectorHttpFixture fixture ;	// 全呼出しで実通信しない。
	fixture.body						= "\n<html>metadata\r\n</html>" ;
	fixture.headers[WINHTTP_QUERY_ETAG] = {L"\"revision1\""} ;
	const auto				 transport	= fixtureTransport( fixture) ;	// Fixtureを借用するtransport。
	OfficialHttpClient		 client( transport) ;						// 通常cacheを使わないsession。
	CollectorHttpObservation observation ;								// 明示HTTP観測。
	std::wstring			 text ;										// 200だけの本文出力。
	std::string				 raw = "previous-sentinel" ;				// 明示出力の原byteと失敗時の失効を測る。
	const auto fetch = [&]( std::wstring_view tag) {					// 同じ公式resourceへsessionを毎回開始する。
		return client.beginSourceSession( 1U, ASUS_PROVIDER_ID) != 0
				   ? static_cast<NativeError>( E_FAIL)
				   : client.getCollectorMetadataForSource(
						 L"https://www.asus.com/supportonly/sample-board/helpdesk_download/",
						 OFFICIAL_PRIMARY_METADATA_RESOURCE_ID, 1024U, tag, text, observation,
						 &raw) ;
	} ;
	DRIVERCRATE_EXPECT( context, fetch( {}) == 0 && observation.status == 200U &&
									observation.entityTag == L"\"revision1\"" && !text.empty()) ;
	DRIVERCRATE_EXPECT( context, client.sourceEvidence().size() == 1U &&
									observation.bodySha256.size() == 64U && fixture.options == 7U) ;
	DRIVERCRATE_EXPECT( context, raw == fixture.body) ;
	fixture.status	 = 304U ;
	const auto reads = fixture.reads ;	// 304前の本文読取り数。
	DRIVERCRATE_EXPECT( context,
					   fetch( L"\"revision1\"") == 0 && text.empty() && observation.status == 304U) ;
	DRIVERCRATE_EXPECT( context, client.sourceEvidence().empty() && observation.bodySha256.empty() &&
									fixture.reads == reads) ;
	DRIVERCRATE_EXPECT( context, raw.empty()) ;
	DRIVERCRATE_EXPECT( context, fixture.sentHeaders.find( L"If-None-Match: \"revision1\"") !=
									std::wstring::npos) ;
	DRIVERCRATE_EXPECT( context, fetch( {}) != 0 && client.sourceEvidence().empty()) ;
	DRIVERCRATE_EXPECT( context, fetch( L"\"revision2\"") != 0 && client.sourceEvidence().empty()) ;
	fixture.headers.erase( WINHTTP_QUERY_ETAG) ;
	DRIVERCRATE_EXPECT( context, fetch( L"\"revision1\"") != 0) ;
	fixture.headers[WINHTTP_QUERY_ETAG] = {L"\"revision1\""} ;
	fixture.headers[WINHTTP_QUERY_VARY] = {L"Cookie"} ;
	DRIVERCRATE_EXPECT( context, fetch( L"\"revision1\"") != 0) ;
	fixture.status = 200U ;
	DRIVERCRATE_EXPECT( context, fetch( {}) == 0 && observation.entityTag.empty()) ;
	fixture.headers[WINHTTP_QUERY_VARY] = {L"Accept-Encoding", L"User-Agent"} ;
	DRIVERCRATE_EXPECT( context, fetch( {}) == 0 && !observation.entityTag.empty()) ;
	fixture.headers[WINHTTP_QUERY_CACHE_CONTROL] = {L"public", L"no-store"} ;
	DRIVERCRATE_EXPECT( context, fetch( {}) == 0 && observation.entityTag.empty()) ;
	fixture.headers.erase( WINHTTP_QUERY_CACHE_CONTROL) ;
	fixture.headers[WINHTTP_QUERY_ETAG] = {L"\"https://not-saved.example/\""} ;
	DRIVERCRATE_EXPECT( context, fetch( {}) == 0 && observation.entityTag.empty()) ;
	fixture.headers[WINHTTP_QUERY_ETAG] = {L"\"a\"", L"\"b\""} ;
	DRIVERCRATE_EXPECT( context, fetch( {}) == 0 && observation.entityTag.empty()) ;
	fixture.status = 429U ;
	DRIVERCRATE_EXPECT( context, fetch( {}) != 0 && observation.status == 429U &&
									client.sourceEvidence().empty()) ;
	fixture.headers[WINHTTP_QUERY_RETRY_AFTER] = {L"172800"} ;
	const auto readsBefore = fixture.reads ;	// 拒否bodyを読まないことを確認する。
	DRIVERCRATE_EXPECT( context, fetch( {}) != 0 && observation.retryAfterDelaySeconds == 172800U &&
									!observation.retryAfterNeedsReview &&
									fixture.reads == readsBefore) ;
	fixture.headers[WINHTTP_QUERY_RETRY_AFTER] = {L"Mon, 28 Sep 2026 00:00:00 GMT"} ;
	fixture.status							   = 503U ;
	DRIVERCRATE_EXPECT( context, fetch( {}) != 0 && observation.retryAfterUtcSeconds == 1790553600U &&
									!observation.retryAfterNeedsReview) ;
	// 未対応・不正待機を即時再送へ変換しない。
	for( const auto value : {L"", L"-1", L"2.5", L"2592001", L"9999999999999999999999", L"tomorrow",
							L"Sun, 28 Sep 2026 00:00:00 GMT", L"Monday, 28-Sep-26 00:00:00 GMT"}) {
		fixture.headers[WINHTTP_QUERY_RETRY_AFTER] = {value} ;
		DRIVERCRATE_EXPECT( context, fetch( {}) != 0 && observation.retryAfterNeedsReview) ;
	}

	fixture.headers[WINHTTP_QUERY_RETRY_AFTER] = {L"120", L"240"} ;
	DRIVERCRATE_EXPECT( context, fetch( {}) != 0 && observation.retryAfterNeedsReview) ;
	fixture.headers[WINHTTP_QUERY_RETRY_AFTER] = {L"", L"120"} ;
	DRIVERCRATE_EXPECT( context, fetch( {}) != 0 && observation.retryAfterNeedsReview) ;
	fixture.headers[WINHTTP_QUERY_RETRY_AFTER] = {L" 0 "} ;
	DRIVERCRATE_EXPECT( context, fetch( {}) != 0 && observation.retryAfterDelaySeconds == 0U &&
									!observation.retryAfterNeedsReview) ;
	fixture.headers.erase( WINHTTP_QUERY_RETRY_AFTER) ;
	fixture.status = 200U ;
	fixture.body   = std::string( 1U, static_cast<char>( 0xff)) ;
	DRIVERCRATE_EXPECT( context, fetch( {}) != 0 && text.empty() && client.sourceEvidence().empty()) ;
	DRIVERCRATE_EXPECT( context, raw.empty()) ;
	fixture.body								  = "fixture" ;
	fixture.headers[WINHTTP_QUERY_CONTENT_LENGTH] = {L"500"} ;
	DRIVERCRATE_EXPECT( context, fetch( {}) != 0 && client.sourceEvidence().empty()) ;
	const auto sends = fixture.sends ;	// 不正validatorは送信前拒否。
	DRIVERCRATE_EXPECT( context, fetch( L"\"a\"\r\nX: injected") != 0 && fixture.sends == sends) ;
	DRIVERCRATE_EXPECT( context, isCollectorEntityTag( L"W/\"a-1_2.3:4\"") &&
									!isCollectorEntityTag( L"\"\"") &&
									!isCollectorEntityTag( std::wstring( 257U, L'a'))) ;
	std::wstring	  hash ;							// 既存hash上限と新専用上限の分離。
	const std::string large( 1024U * 1024U + 1U, 'a') ;	// 既存上限超の有限本文。
	DRIVERCRATE_EXPECT( context, computeBytesSha256( large, hash) != 0 &&
									computeCollectorMetadataSha256( large, hash) == 0 &&
									hash.size() == 64U) ;
	fixture.headers.erase( WINHTTP_QUERY_CONTENT_LENGTH) ;
	fixture.headers[WINHTTP_QUERY_ETAG]		= {L"\"revision1\""} ;
	fixture.headers[WINHTTP_QUERY_LOCATION] = {
		L"https://www.asus.com/supportonly/redirect/helpdesk_download/"} ;
	fixture.sequence = {302U, 200U} ;
	fixture.sends	 = 0U ;
	// ASUSの現policyはredirect上限0。汎用helperの上限を理由に緩和しない。
	DRIVERCRATE_EXPECT( context, fetch( L"\"revision1\"") != 0 && fixture.sends == 1U &&
									observation.entityTag.empty() &&
									client.sourceEvidence().empty()) ;
	fixture.sequence = {302U, 304U} ;
	fixture.sends	 = 0U ;
	DRIVERCRATE_EXPECT( context, fetch( L"\"revision1\"") != 0 && client.sourceEvidence().empty()) ;
	fixture.sequence						= {302U, 200U} ;
	fixture.sends							= 0U ;
	fixture.headers[WINHTTP_QUERY_LOCATION] = {L"https://dlcdnets.asus.com/not-the-same-origin"} ;
	DRIVERCRATE_EXPECT( context, fetch( L"\"revision1\"") != 0 && fixture.sends == 1U &&
									client.sourceEvidence().empty()) ;
}

/** @brief 自作fixtureの実I/Oだけにextended DOS表記を使用します。
 * @param[in] path 自身のGUID領域内で構築した検証済み絶対DOS path。
 * @return backslashを揃えた同じ対象のextended path。
 * @pre 削除の許可範囲と非reparse検査は呼出し元で維持します。
 */
[[nodiscard]] std::filesystem::path fixtureIoPath( const std::filesystem::path &path)
{
	return L"\\\\?\\" + std::filesystem::path( path).make_preferred().native() ;
}

/** @brief 自身で作る専用fixture rootを一つ割り当てます。 */
[[nodiscard]] std::filesystem::path fixtureRoot()
{
	// 同時実行fixtureと衝突しない名前を取得する。
	GUID id{} ;
	// UUID生成失敗を既存rootへの書込みに変換しない。
	if( FAILED( CoCreateGuid( &id))) {
		throw std::runtime_error( "fixture GUID failed") ;
	}

	// Windows GUID表記に必要な固定buffer。
	wchar_t text[40]{} ;
	// 不完全な名前をstate rootにしない。
	if( StringFromGUID2( id, text, 40) == 0) {
		throw std::runtime_error( "fixture name failed") ;
	}

	return std::filesystem::current_path() / L"work" / L"state" /
		   (std::wstring( L"collector-run-fixture-") + text) ;
}

/** @brief 厳密に自作rootと確認した場合だけ終了後に削除します。 */
void cleanupFixture( const std::filesystem::path &root)
{
	// 現workspace直下の唯一許可したfixture親directory。
	const auto base = std::filesystem::current_path() / L"work" / L"state" ;
	// 自作prefix・直下・非reparseを確認してからだけ削除する。
	if( root.is_absolute() && root.parent_path() == base &&
	   root.filename().native().starts_with( L"collector-run-fixture-") &&
	   (GetFileAttributesW( root.c_str()) & FILE_ATTRIBUTE_REPARSE_POINT) == 0U) {
		// cleanup失敗を試験の成功に隠さない。
		std::error_code error ;
		std::filesystem::remove_all( fixtureIoPath( root), error) ;
		// fixture残存時は失敗として報告する。
		if( error) {
			throw std::runtime_error( "fixture cleanup failed") ;
		}
	}
}

/** @brief manifestの公開二targetを読みます。 */
void loadTargets( std::vector<LocalCollectorTarget> &targets, std::wstring &manifest)
{
	// 既存の公開target fixtureを本番manifest parserへ通す。
	if( !loadLocalCollectorManifest(
		   std::filesystem::path( L"tests/fixtures/local_driver_collector_manifest_v1.json"),
		   targets, manifest) ||
	   targets.size() != 2U) {
		throw std::runtime_error( "collector fixture manifest failed") ;
	}
}

/** @brief 途中終了後に元日付と固定母数を維持して再開します。 */
void crossDayResume( TestContext &context, const std::filesystem::path &root,
					const std::vector<LocalCollectorTarget> &targets, const std::wstring &manifest)
{
	// 二番目のtargetだけ時刻不明にして未完了checkpointを残す。
	std::uint32_t			utcCalls{} ;
	// 一時間超過を最初のtargetへだけ再現する。
	std::uint32_t			steadyCalls{} ;
	// 単調時計fixtureの固定原点。
	const auto				zero = std::chrono::steady_clock::time_point{} ;
	// 本番CLIには露出しない試験専用入口。
	LocalCollectorTestHooks hooks ;
	OfficialHttpTransport	noNetwork ;	// 予算fixtureでも実HTTP・DNSを無効にする。
	noNetwork.open				 = failedOpen ;
	noNetwork.resolveDestination = publicDestination ;
	hooks.httpTransport			 = &noNetwork ;
	hooks.jstDay				 = [] { return L"20260925" ; } ;
	hooks.utcSeconds			 = [&utcCalls] { return ++utcCalls == 2U ? 0U : 1790294400U ; } ;
	hooks.steadyNow				 = [&steadyCalls, zero] {
		 return zero + (steadyCalls++ == 0U ? std::chrono::hours( 0) : std::chrono::hours( 2)) ;
	} ;
	// 元日付の途中終了状態を保持する。
	LocalCollectorRun first ;
	DRIVERCRATE_EXPECT( context, runLocalDriverCollectorWithHooks( root, targets, manifest, false,
																 hooks, first) == 2) ;
	DRIVERCRATE_EXPECT( context, first.day == L"20260925" && !first.complete &&
									first.targets.size() == 2U &&
									first.targets[0].state == LocalCollectorTargetState::DEFERRED &&
									first.targets[1].state == LocalCollectorTargetState::PENDING) ;

	hooks.jstDay	 = [] { return L"20260926" ; } ;
	hooks.utcSeconds = [] { return 1790380800U ; } ;
	hooks.steadyNow	 = [zero, count = 0U]() mutable {
		 return zero + (count++ == 0U ? std::chrono::hours( 0) : std::chrono::hours( 2)) ;
	} ;
	// 翌日に同じ元日付と未完了母数で終える。
	LocalCollectorRun resumed ;
	DRIVERCRATE_EXPECT( context, runLocalDriverCollectorWithHooks( root, targets, manifest, false,
																 hooks, resumed) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   resumed.day == L"20260925" && resumed.complete && resumed.reusedCheckpoint &&
						   resumed.resumedEarlierDay &&
						   resumed.targets[0].state == LocalCollectorTargetState::DEFERRED &&
						   resumed.targets[1].state == LocalCollectorTargetState::DEFERRED) ;

	hooks.steadyNow = [zero, count = 0U]() mutable {
		return zero + (count++ == 0U ? std::chrono::hours( 0) : std::chrono::hours( 2)) ;
	} ;
	// 次の起動で初めて新しい日付のrunを作る。
	LocalCollectorRun next ;
	DRIVERCRATE_EXPECT( context, runLocalDriverCollectorWithHooks( root, targets, manifest, false,
																 hooks, next) == 0) ;
	DRIVERCRATE_EXPECT( context, next.day == L"20260926" && next.complete &&
									!next.reusedCheckpoint && !next.resumedEarlierDay) ;
	// 完了済み当日runを再度通信しない。
	LocalCollectorRun repeated ;
	DRIVERCRATE_EXPECT( context, runLocalDriverCollectorWithHooks( root, targets, manifest, false,
																 hooks, repeated) == 0) ;
	DRIVERCRATE_EXPECT( context, repeated.day == L"20260926" && repeated.reusedCheckpoint &&
									repeated.complete) ;
}

/** @brief fake HTTPだけが使われ、通信失敗を成功recordへ変換しません。 */
void injectedHttpFailure( TestContext &context, const std::filesystem::path &root,
						 const std::vector<LocalCollectorTarget> &targets,
						 const std::wstring						 &manifest)
{
	// 公式HTTP clientの低位I/Oのみをfakeへ置換する。
	OfficialHttpTransport transport ;
	transport.open				 = failedOpen ;
	transport.resolveDestination = publicDestination ;
	// 実networkなしの単一target失敗を確定させる。
	LocalCollectorTestHooks hooks ;
	hooks.jstDay		= [] { return L"20260925" ; } ;
	hooks.utcSeconds	= [] { return 1790294400U ; } ;
	hooks.steadyNow		= [] { return std::chrono::steady_clock::time_point{} ; } ;
	hooks.httpTransport = &transport ;
	// 失敗後のrecord非昇格を検査する結果。
	LocalCollectorRun run ;
	fakeOpenCalls = 0U ;
	DRIVERCRATE_EXPECT( context, runLocalDriverCollectorWithHooks( root, {targets[1]}, manifest,
																 false, hooks, run) == 1) ;
	DRIVERCRATE_EXPECT( context, fakeOpenCalls == 1U && run.complete && run.targets.size() == 1U &&
									run.targets[0].state == LocalCollectorTargetState::FAILED &&
									run.targets[0].records.empty() &&
									run.targets[0].lastSuccessfulValidationAt == 0U) ;
}

/** @brief 固定ASUS pageを同じ既存parserへ通します。 */
[[nodiscard]] std::string collectorPage()
{
	return R"(<html><script type="application/json" data-ssr="true" id="__NUXT_DATA__">
[{"model":1,"productId":2,"downloadUrl":3},"SAMPLE-BOARD",123,"",{"Id":5,"Name":6},"52","Windows 11 64-bit",
{"Name":8,"Count":9,"Files":10,"IsDescShow":11},"LAN",1,[12],false,
{"Id":13,"Version":14,"Title":15,"FileSize":16,"ReleaseDate":17,"DownloadUrl":18,"sha256":20},
"1@66@7@8@52@5@DRV_LAN_Fictional_W11_64_V11252750919.zip",
"1125.27.50.919","Fictional ASUS LAN Driver","14.67 MB","2025/12/31",
{"Global":19,"China":3},"/pub/ASUS/mb/04LAN/DRV_LAN_Fictional_W11_64_V11252750919.zip",
"DEF73029462651E78B30791C9E6EDB2E99F86755B2334F942612A50467761CB5"]
</script></html>)" ;
}

/** @brief 外側hashとpointerを整合させたまま保存内容へ故障を注入します。
 * @param[in] root 自作fixture root。
 * @param[in] run 保存直後の元run。
 * @param[in] missingRecords trueならrecords欠損、falseならrequest bindingを変更します。
 * @param[in] retainedMode 1は元本文field欠損、2は本文改変、0は従来の射影故障です。
 * @return 故障fixtureの書込み成功時true。
 */
[[nodiscard]] bool alterSavedProjection( const std::filesystem::path &root,
										const LocalCollectorRun &run, bool missingRecords,
										int retainedMode = 0)
{
	using Object = winrt::Windows::Data::Json::JsonObject ;
	using Value	 = winrt::Windows::Data::Json::JsonValue ;
	LocalCollectorStateStore store ;	// 通常の保護読書き境界を使用する。
	// 専用fixture以外に変更しない。
	if( store.initialize( root, true) != 0U) {
		return false ;
	}

	const auto suffix = run.manifestSha256 + L"-" + run.contractSha256 + L".json" ;		// 契約別file名。
	const auto runPath = std::filesystem::path( L"runs") / (run.day + L"-" + suffix) ;	// 今回のrun。
	const auto pointerPath = std::filesystem::path( L"current") / suffix ;				// 同じ契約pointer。
	std::string bytes ;																	// 保護storeのenvelope。
	bool		found{} ;																// 欠損と読取り成功の区別。
	// 元runを通常の権限検査で読む。
	if( store.read( runPath, bytes, found) != 0U || !found) {
		return false ;
	}

	Object envelope = Object::Parse( winrt::to_hstring( bytes)) ;			// 外側schema。
	Object body		= Object::Parse( envelope.GetNamedString( L"body")) ;	// 内側run。
	Object target	= body.GetNamedArray( L"targets").GetObjectAt( 0U) ;	// 一つのtarget。
	// Record欠損でもETagだけは残す。
	if( retainedMode == 1) {
		target.Remove( L"retainedBodyBytesBase64") ;
	}
	// 有効base64だが元body hashと異なるbyteを保存します。
	else if( retainedMode == 2) {
		target.Insert( L"retainedBodyBytesBase64", Value::CreateStringValue( L"AA==")) ;
	}
	// Record欠損でもvalidatorだけを残します。
	else if( missingRecords) {
		target.Insert( L"records", winrt::Windows::Data::Json::JsonArray{}) ;
	} else {
		target.Insert( L"requestBindingSha256", Value::CreateStringValue( std::wstring( 64U, L'0'))) ;
	}

	const auto writeEnvelope = [&]( const std::filesystem::path &path, Object &wrapper,
								   const Object &inner) {
		std::wstring hash ;	// 変更後の正しい外側hash。
		// 破損envelopeではなく結合失効を試験する。
		if( computeBytesSha256( winrt::to_string( inner.Stringify()), hash) != 0) {
			return false ;
		}

		wrapper.Insert( L"body", Value::CreateStringValue( inner.Stringify())) ;
		wrapper.Insert( L"sha256", Value::CreateStringValue( hash)) ;
		return store.write( path, winrt::to_string( wrapper.Stringify())) == 0U ;
	} ;
	// Runとpointerの両方のhashを整合させる。
	if( !writeEnvelope( runPath, envelope, body) || store.read( pointerPath, bytes, found) != 0U ||
	   !found) {
		return false ;
	}

	Object		 pointerEnvelope = Object::Parse( winrt::to_hstring( bytes)) ;			// Pointerの外側schema。
	Object		 pointer = Object::Parse( pointerEnvelope.GetNamedString( L"body")) ;	// Pointer本文。
	std::wstring hash ;																	// 変更後runへの参照。
	// Hash計算失敗をfixture成功としない。
	if( computeBytesSha256( winrt::to_string( body.Stringify()), hash) != 0) {
		return false ;
	}

	pointer.Insert( L"runSha256", Value::CreateStringValue( hash)) ;
	return writeEnvelope( pointerPath, pointerEnvelope, pointer) ;
}

/** @brief 200解析から日次304、変更200、拒否まで同じ永続入口で確認します。 */
void conditionalRuns( TestContext &context, const std::filesystem::path &root,
					 const std::vector<LocalCollectorTarget> &targets, const std::wstring &manifest)
{
	CollectorHttpFixture fixture ;	// 実通信を行わないASUS応答。
	fixture.body						= collectorPage() ;
	fixture.headers[WINHTTP_QUERY_ETAG] = {L"\"v1\""} ;
	const auto				transport	= fixtureTransport( fixture) ;	// 同期呼出しだけ借用するI/O。
	unsigned				day			= 25U ;							// 各回の日付とUTCを同時に進める。
	LocalCollectorTestHooks hooks ;										// 実時計に依存しないfixture。
	hooks.httpTransport = &transport ;
	hooks.jstDay = [&day] { return day <= 30U ? L"202609" + std::to_wstring( day) : L"20261001" ; } ;
	hooks.utcSeconds = [&day] { return 1790294400ULL + (day - 25U) * 86400ULL ; } ;
	hooks.steadyNow	 = [] { return std::chrono::steady_clock::time_point{} ; } ;
	LocalCollectorRun run ;	// 実装が返すcheckpoint結果。
	const auto		  invoke = [&] {
		   return runLocalDriverCollectorWithHooks( root, {targets[0]}, manifest, false, hooks, run) ;
	} ; // 同一core。
	DRIVERCRATE_EXPECT( context,
					   invoke() == 0 && run.targets[0].state == LocalCollectorTargetState::UPDATED) ;
	// Parser接続に失敗した場合は後続の成功仮定を使わない。
	if( run.targets.size() != 1U || run.targets[0].records.empty()) {
		return ;
	}

	const auto first = run.targets[0] ;	// 元200の成功状態。
	DRIVERCRATE_EXPECT( context, first.entityTag == L"\"v1\"" && first.records.size() == 1U &&
									first.lastHttpStatus == 200U) ;
	DRIVERCRATE_EXPECT( context, first.lastFetchedAt == first.lastSuccessfulValidationAt &&
									first.projectionSha256.size() == 64U) ;
	fixture.status = 304U ;
	++day ;
	DRIVERCRATE_EXPECT( context, invoke() == 0 &&
									run.targets[0].state == LocalCollectorTargetState::UNCHANGED) ;
	DRIVERCRATE_EXPECT( context, run.targets[0].records == first.records &&
									run.targets[0].lastHttpStatus == 304U &&
									run.targets[0].lastFetchedAt == first.lastFetchedAt &&
									run.targets[0].bodySha256 == first.bodySha256 &&
									run.targets[0].lastSuccessfulValidationAt ==
										first.lastSuccessfulValidationAt + 86400U) ;
	DRIVERCRATE_EXPECT( context,
					   fixture.sentHeaders.find( L"If-None-Match: \"v1\"") != std::wstring::npos) ;
	const auto sends = fixture.sends ;	// 同日再起動前の送信数。
	DRIVERCRATE_EXPECT( context, invoke() == 0 && run.reusedCheckpoint && fixture.sends == sends) ;
	DRIVERCRATE_EXPECT( context, alterSavedProjection( root, run, false)) ;
	fixture.status						= 200U ;
	fixture.headers[WINHTTP_QUERY_ETAG] = {L"\"v2\""} ;
	const auto position = fixture.body.find( "1125.27.50.919") ;	// 公開版だけを更新する位置。
	fixture.body.replace( position, std::string( "1125.27.50.919").size(), "1125.28.50.920") ;
	++day ;
	DRIVERCRATE_EXPECT( context,
					   invoke() == 0 && run.targets[0].state == LocalCollectorTargetState::UPDATED) ;
	const auto changed = run.targets[0] ;	// 新200の成功状態。
	DRIVERCRATE_EXPECT( context, fixture.sentHeaders.find( L"If-None-Match") == std::wstring::npos) ;
	DRIVERCRATE_EXPECT( context, changed.records[0].packageVersion == L"1125.28.50.920" &&
									changed.bodySha256 != first.bodySha256 &&
									changed.entityTag == L"\"v2\"") ;
	fixture.status						= 304U ;
	fixture.headers[WINHTTP_QUERY_ETAG] = {L"\"wrong\""} ;
	++day ;
	DRIVERCRATE_EXPECT( context,
					   invoke() == 1 && run.targets[0].state == LocalCollectorTargetState::FAILED) ;
	DRIVERCRATE_EXPECT( context, run.targets[0].records == changed.records &&
									run.targets[0].lastSuccessfulValidationAt ==
										changed.lastSuccessfulValidationAt &&
									run.targets[0].entityTag.empty()) ;
	fixture.status						= 200U ;
	fixture.headers[WINHTTP_QUERY_ETAG] = {L"\"v2\""} ;
	++day ;
	DRIVERCRATE_EXPECT(
		context, invoke() == 0 && run.targets[0].state == LocalCollectorTargetState::UNCHANGED &&
					 fixture.sentHeaders.find( L"If-None-Match") == std::wstring::npos) ;
	fixture.status = 429U ;
	++day ;
	fixture.status = 200U ;
	DRIVERCRATE_EXPECT( context, alterSavedProjection( root, run, true)) ;
	DRIVERCRATE_EXPECT( context,
					   invoke() == 0 && run.targets[0].records == changed.records &&
						   fixture.sentHeaders.find( L"If-None-Match") == std::wstring::npos) ;
	fixture.status = 429U ;
	++day ;
	const auto validated = run.targets[0].lastSuccessfulValidationAt ;	// 失敗前の最新成功時刻。
	DRIVERCRATE_EXPECT( context, invoke() == 1 && run.targets[0].lastHttpStatus == 429U &&
									run.targets[0].lastSuccessfulValidationAt == validated &&
									run.targets[0].records == changed.records &&
									run.targets[0].entityTag.empty()) ;
}

/** @brief 一試験だけの保護root・時計・fake HTTPを所有します。 */
struct CollectorScenario {
	/// Cleanup失敗を報告する借用先。
	TestContext						 &context ;
	/// このfixtureだけで新規作成するroot。
	std::filesystem::path			  root{fixtureRoot()} ;
	/// 実HTTPに接続しない応答。
	CollectorHttpFixture			  http ;
	/// HTTP状態を同期呼出し中だけ借用する表。
	OfficialHttpTransport			  transport{fixtureTransport( http)} ;
	/// 固定manifestの公開targetだけを保持する。
	std::vector<LocalCollectorTarget> targets ;
	/// Manifestのbyte指紋。別manifest試験だけ架空の別指紋へ変更する。
	std::wstring					  manifest ;
	/// 2026-09-25からの経過日数。
	int								  day{} ;
	/// 同じ日に追加するUTC秒。
	std::uint64_t					  offsetSeconds{} ;
	/// 本番CLIへ公開しない差込み。
	LocalCollectorTestHooks			  hooks ;
	/// 直近呼出しの実core結果。
	LocalCollectorRun				  run ;

	/** @brief 公開targetと元manifestを同じ実coreに渡します。
	 * @param[in,out] test assertion集計先。
	 * @param[in] values 固定公開target。
	 * @param[in] hash 元manifest指紋。
	 */
	CollectorScenario( TestContext &test, std::vector<LocalCollectorTarget> values,
					  std::wstring hash)
		: context( test), targets( std::move( values)), manifest( std::move( hash))
	{
		http.body						 = collectorPage() ;
		http.headers[WINHTTP_QUERY_ETAG] = {L"\"v1\""} ;
		hooks.httpTransport				 = &transport ;
		hooks.utcSeconds				 = [this] {
			return 1790294400ULL + static_cast<std::uint64_t>( day) * 86400ULL + offsetSeconds ;
		} ;
		hooks.jstDay = [this] {
			const std::chrono::year_month_day date{
				std::chrono::sys_days{std::chrono::year{2026} / 9 / 25} +
				std::chrono::days{day}} ;	// 日次時計。
			return std::format( L"{:04}{:02}{:02}", static_cast<int>( date.year()),
							   static_cast<unsigned>( date.month()),
							   static_cast<unsigned>( date.day())) ;
		} ;
		hooks.steadyNow = [] { return std::chrono::steady_clock::time_point{} ; } ;
	}

	/** @brief 検査済みの自作rootだけを回収します。 */
	~CollectorScenario()
	{
		try {
			cleanupFixture( root) ;
		} catch( ...) {
			context.expect( false, "scenario cleanup", __FILE__, __LINE__) ;
		}
	}

	/** @brief 同じ収集coreを同期実行します。
	 * @return 本番と同じ終了code。
	 */
	int invoke()
	{
		activeFixture = &http ;
		return runLocalDriverCollectorWithHooks( root, targets, manifest, false, hooks, run) ;
	}

	/** @brief 最新結果のrunまたはpointer名を得ます。
	 * @param[in] pointer trueならcurrent、falseならrun。
	 * @return 保護rootからの相対path。
	 */
	std::filesystem::path path( bool pointer) const
	{
		const auto suffix =
			run.manifestSha256 + L"-" + run.contractSha256 + L".json" ;	// 完全なkey。
		return pointer ? std::filesystem::path( L"current") / suffix
					   : std::filesystem::path( L"runs") / (run.day + L"-" + suffix) ;
	}

	/** @brief 永続化されたbyteを権限確認付きで読みます。
	 * @param[in] file 保護rootからの相対名。
	 * @return 欠損は空、失敗は例外。
	 */
	std::string read( const std::filesystem::path &file) const
	{
		LocalCollectorStateStore store ;	// 完了したcoreと別の読取りhandle。
		std::string				 bytes ;	// 原byte。
		bool					 found{} ;	// 欠損も観測する。
		// API失敗を空として成功にしない。
		if( store.initialize( root, true) != 0U || store.read( file, bytes, found) != 0U) {
			throw std::runtime_error( "scenario read") ;
		}

		return bytes ;
	}

	/** @brief 故障注入を自作rootの保護store内に限定します。
	 * @param[in] file 書込み先の相対名。
	 * @param[in] bytes 故障を含む有限fixture。
	 */
	void write( const std::filesystem::path &file, const std::string &bytes) const
	{
		LocalCollectorStateStore store ;	// 書込み時も通常のACLとlockを確認する。
		// 書込み失敗は後続の故障再現成功としない。
		if( store.initialize( root, true) != 0U || store.write( file, bytes) != 0U) {
			throw std::runtime_error( "scenario write") ;
		}
	}
} ;

/**
 * @brief v2 modeへの旧収集書込みを通信前に拒否します。
 * @param[in,out] context assertion集計。
 * @param[in] targets 公開fixture集合。
 * @param[in] manifest 元manifest指紋。
 */
void campaignModeScenarios( TestContext &context, const std::vector<LocalCollectorTarget> &targets,
						   const std::wstring &manifest)
{
	// 未知本文と破損本文も、旧collectorからのmode解除理由にしない。
	for( const std::string marker : {"{}", "corrupt-mode"}) {
		CollectorScenario scenario( context, {targets[0]}, manifest) ;	// 通信counter付きの自作root。
		scenario.write( L"current/collector-campaign-mode-v1.json", marker) ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 2 &&
										scenario.run.stateError == ERROR_INVALID_DATA &&
										scenario.http.sends == 0U) ;
		DRIVERCRATE_EXPECT( context,
						   scenario.read( L"current/collector-campaign-mode-v1.json") == marker) ;
		DRIVERCRATE_EXPECT( context, scenario.read( scenario.path( true)).empty() &&
										scenario.read( scenario.path( false)).empty()) ;
		LocalCollectorStateStore store ;	// 旧run・予算が新設されていないことを列挙で確認する。
		DRIVERCRATE_EXPECT( context, store.initialize( scenario.root, true) == 0U) ;
		std::vector<std::wstring> names ;	// mode一件以外に確定fileがない。
		DRIVERCRATE_EXPECT(
			context, store.listCurrentNames( names) == 0U &&
						 names == std::vector<std::wstring>( {L"collector-campaign-mode-v1.json"})) ;
		DRIVERCRATE_EXPECT( context, store.listRunNames( names) == 0U && names.empty()) ;
	}
}

/** @brief 一件pageから二件の検証可能な架空pageを作ります。
 * @return 実parserを通すNuxt JSONを持つHTML。
 */
[[nodiscard]] std::string twoRecordPage()
{
	using Object	 = winrt::Windows::Data::Json::JsonObject ;
	using Array		 = winrt::Windows::Data::Json::JsonArray ;
	using Value		 = winrt::Windows::Data::Json::JsonValue ;
	const auto page	 = collectorPage() ;	// 一件の既存fixture。
	const auto start = page.find( '[') ;	// Nuxt JSONの先頭。
	const auto end	 = page.rfind( ']') ;	// Nuxt JSONの終端。
	Array	   root =
		// 有限参照配列。
		Array::Parse( winrt::to_hstring( page.substr( start, end - start + 1U))) ;
	Object record = Object::Parse( root.GetObjectAt( 12U).Stringify()) ;	// 独立した二件目のrecord。
	record.Insert( L"Id", Value::CreateNumberValue( root.Size())) ;
	root.Append( Value::CreateStringValue( L"1@66@7@8@52@5@DRV_LAN_Fictional_Second.zip")) ;
	Object download ;	// 二件目の公開配布URL。
	download.Insert( L"Global", Value::CreateNumberValue( root.Size())) ;
	download.Insert( L"China", Value::CreateNumberValue( 3)) ;
	root.Append( Value::CreateStringValue( L"/pub/ASUS/mb/04LAN/DRV_LAN_Fictional_Second.zip")) ;
	record.Insert( L"DownloadUrl", Value::CreateNumberValue( root.Size())) ;
	root.Append( download) ;
	root.GetArrayAt( 10U).Append( Value::CreateNumberValue( root.Size())) ;
	root.Append( record) ;
	root.SetAt( 9U, Value::CreateNumberValue( 2)) ;
	return page.substr( 0U, start) + winrt::to_string( root.Stringify()) + page.substr( end + 1U) ;
}

/** @brief Commit窓とtarget保存位置の中断を回収します。
 * @param[in,out] context assertion集計。
 * @param[in] targets 公開fixture集合。
 * @param[in] manifest 元manifest指紋。
 */
void recoveryScenarios( TestContext &context, const std::vector<LocalCollectorTarget> &targets,
					   const std::wstring &manifest)
{
	// 初回pointer欠損と前世代pointerありの両方を試す。
	for( bool previous : {false, true}) {
		CollectorScenario scenario( context, {targets[0]}, manifest) ;	// 一試験専用root。
		std::string		  oldPointer ;									// 中断前の確定pointer。
		// 旧pointerを持つ試験だけ先に一日完了させる。
		if( previous) {
			DRIVERCRATE_EXPECT( context, scenario.invoke() == 0) ;
			oldPointer = scenario.read( scenario.path( true)) ;
			++scenario.day ;
		}

		scenario.hooks.stopAfterCheckpoint = []( LocalCollectorCheckpoint point, std::size_t) {
			return point == LocalCollectorCheckpoint::RUN_COMPLETED ;
		} ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 2 && scenario.run.complete &&
										scenario.run.stateError == ERROR_OPERATION_ABORTED) ;
		const auto savedRun = scenario.read( scenario.path( false)) ;	// 完了本文はすでに永続化済み。
		const auto savedDay = scenario.run.day ;						// 元runの日付。
		const auto sends	= scenario.http.sends ;						// 回収時に増えない送信数。
		DRIVERCRATE_EXPECT( context, scenario.read( scenario.path( true)) == oldPointer) ;
		scenario.hooks.stopAfterCheckpoint = {} ;
		++scenario.day ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 0 && scenario.run.recoveredCommit &&
										scenario.run.reusedCheckpoint &&
										scenario.run.day == savedDay &&
										scenario.http.sends == sends) ;
		DRIVERCRATE_EXPECT( context, scenario.read( scenario.path( false)) == savedRun &&
										!scenario.read( scenario.path( true)).empty()) ;
		scenario.http.status = 304U ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 0 && !scenario.run.recoveredCommit &&
										!scenario.run.reusedCheckpoint &&
										scenario.run.day != savedDay &&
										scenario.http.sends == sends + 1U) ;
	}

	// 未開始・HTTP直前・一件保存後の各境界を別rootで試す。
	for( const auto stop :
		{LocalCollectorCheckpoint::RUN_STARTED, LocalCollectorCheckpoint::TARGET_STARTED,
		 LocalCollectorCheckpoint::TARGET_SAVED}) {
		CollectorScenario scenario( context, targets,
								   manifest) ;	// 二target、IntelにはASUS本文を返すためschema拒否。
		scenario.hooks.stopAfterCheckpoint = [stop]( LocalCollectorCheckpoint point,
													std::size_t				 index) {
			return point == stop && (point == LocalCollectorCheckpoint::RUN_STARTED || index == 0U) ;
		} ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 2 && !scenario.run.complete) ;
		const auto before				   = scenario.http.sends ;	// 完了済み一件の送信は重ねない。
		scenario.hooks.stopAfterCheckpoint = {} ;
		++scenario.day ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 1 && scenario.run.complete &&
										scenario.run.resumedEarlierDay &&
										scenario.http.sends == 2U) ;
		DRIVERCRATE_EXPECT(
			context, scenario.run.targets[0].records.size() == 1U &&
						 scenario.run.targets[1].state == LocalCollectorTargetState::FAILED &&
						 before == (stop == LocalCollectorCheckpoint::TARGET_SAVED ? 1U : 0U)) ;
	}
}

/** @brief Source待機を翌日と別manifestへ引き継ぎます。
 * @param[in,out] context assertion集計。
 * @param[in] targets 公開fixture集合。
 * @param[in] manifest 元manifest指紋。
 */
void cooldownScenarios( TestContext &context, const std::vector<LocalCollectorTarget> &targets,
					   const std::wstring &manifest)
{
	{
		CollectorScenario scenario( context, {targets[0]}, manifest) ;	// 秒数指定。
		scenario.http.status							 = 429U ;
		scenario.http.headers[WINHTTP_QUERY_RETRY_AFTER] = {L"172800"} ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 1 &&
										scenario.run.targets[0].nextAttemptAt == 1790467200U &&
										scenario.http.sends == 1U) ;
		++scenario.day ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 0 &&
										scenario.run.targets[0].state ==
											LocalCollectorTargetState::DEFERRED &&
										scenario.http.sends == 1U) ;
		scenario.manifest = std::wstring( 64U, L'b') ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 0 &&
										scenario.run.targets[0].state ==
											LocalCollectorTargetState::DEFERRED &&
										scenario.http.sends == 1U) ;
		++scenario.day ;
		scenario.http.status = 200U ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 0 &&
										scenario.run.targets[0].state ==
											LocalCollectorTargetState::UPDATED &&
										scenario.http.sends == 2U) ;
	}
	{
		CollectorScenario scenario( context, {targets[0]}, manifest) ;	// 日付指定。
		scenario.http.status							 = 503U ;
		scenario.http.headers[WINHTTP_QUERY_RETRY_AFTER] = {L"Mon, 28 Sep 2026 00:00:00 GMT"} ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 1 &&
										scenario.run.targets[0].nextAttemptAt == 1790553600U) ;
		scenario.day = 2 ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 0 && scenario.http.sends == 1U) ;
		scenario.day		 = 3 ;
		scenario.http.status = 200U ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 0 && scenario.http.sends == 2U) ;
	}
	{
		CollectorScenario scenario( context, {targets[0]}, manifest) ;	// 不明待機は自動解除しない。
		scenario.http.status							 = 429U ;
		scenario.http.headers[WINHTTP_QUERY_RETRY_AFTER] = {L"broken"} ;
		DRIVERCRATE_EXPECT( context,
						   scenario.invoke() == 1 &&
							   scenario.run.targets[0].state == LocalCollectorTargetState::HELD &&
							   scenario.run.targets[0].holdReason == L"RETRY_AFTER") ;
		scenario.day = 10 ;
		DRIVERCRATE_EXPECT( context,
						   scenario.invoke() == 1 && scenario.http.sends == 1U &&
							   scenario.run.targets[0].state == LocalCollectorTargetState::HELD) ;
	}
	{
		LocalCollectorTarget extra = targets[0] ;	// 別公開modelだが同じASUS source。
		extra.publicModel		   = L"SAMPLE-SECOND" ;
		extra.keySha256			   = std::wstring( 64U, L'c') ;
		CollectorScenario scenario( context, {targets[0], extra, targets[1]},
								   manifest) ;	// 三target固定。
		scenario.http.sequence							 = {429U, 200U} ;
		scenario.http.headers[WINHTTP_QUERY_RETRY_AFTER] = {L"172800"} ;
		DRIVERCRATE_EXPECT(
			context, scenario.invoke() == 1 && scenario.http.sends == 2U &&
						 scenario.run.targets[1].state == LocalCollectorTargetState::DEFERRED &&
						 scenario.run.targets[2].state == LocalCollectorTargetState::FAILED) ;
	}
}

/** @brief 空・減少・schema失敗が前回成功を消さないことを検証します。
 * @param[in,out] context assertion集計。
 * @param[in] targets 公開fixture集合。
 * @param[in] manifest 元manifest指紋。
 */
void retentionScenarios( TestContext &context, const std::vector<LocalCollectorTarget> &targets,
						const std::wstring &manifest)
{
	CollectorScenario scenario( context, {targets[0]}, manifest) ;	// 二件から減少させる一系列。
	scenario.http.body = twoRecordPage() ;
	DRIVERCRATE_EXPECT( context,
					   scenario.invoke() == 0 && scenario.run.targets[0].records.size() == 2U) ;
	const auto previous = scenario.run.targets[0] ;	// 旧成功の完全保存確認。
	++scenario.day ;
	scenario.http.body = collectorPage() ;
	DRIVERCRATE_EXPECT( context, scenario.invoke() == 1 &&
									scenario.run.targets[0].holdReason == L"RECORD_DECREASE" &&
									scenario.run.targets[0].observedRecordCount == 1U) ;
	DRIVERCRATE_EXPECT( context, scenario.run.targets[0].records == previous.records &&
									scenario.run.targets[0].bodySha256 == previous.bodySha256 &&
									scenario.run.targets[0].lastSuccessfulValidationAt ==
										previous.lastSuccessfulValidationAt &&
									scenario.run.targets[0].entityTag.empty()) ;
	++scenario.day ;
	const auto position =
		// 完全な空categoryを構成する位置。
		scenario.http.body.find( "\"LAN\",1,[12],false") ;
	scenario.http.body.replace( position, std::string( "\"LAN\",1,[12],false").size(),
							   "\"LAN\",0,[],false") ;
	DRIVERCRATE_EXPECT( context, scenario.invoke() == 1 &&
									scenario.run.targets[0].holdReason == L"EMPTY_RESPONSE" &&
									scenario.run.targets[0].records == previous.records &&
									scenario.run.targets[0].observedRecordCount == 0U) ;
	++scenario.day ;
	scenario.http.body =
		"<html>TEST_RAW_DO_NOT_PERSIST https://example.invalid/token FAKE_EULA_BODY</html>" ;
	scenario.http.headers[WINHTTP_QUERY_SET_COOKIE] = {L"TEST_COOKIE_DO_NOT_PERSIST"} ;
	DRIVERCRATE_EXPECT( context,
					   scenario.invoke() == 1 &&
						   scenario.run.targets[0].state == LocalCollectorTargetState::FAILED &&
						   scenario.run.targets[0].records == previous.records &&
						   scenario.run.targets[0].lastSuccessfulValidationAt ==
							   previous.lastSuccessfulValidationAt) ;
	const auto saved = scenario.read( scenario.path( false)) ;	// 永続化された公開field群。
	DRIVERCRATE_EXPECT( context, saved.find( "TEST_RAW") == std::string::npos &&
									saved.find( "TEST_COOKIE") == std::string::npos &&
									saved.find( "FAKE_EULA") == std::string::npos &&
									saved.find( "https:") == std::string::npos &&
									saved.find( "/pub/ASUS/") == std::string::npos) ;
	++scenario.day ;
	scenario.http.body = twoRecordPage() ;
	DRIVERCRATE_EXPECT( context,
					   scenario.invoke() == 0 &&
						   scenario.run.targets[0].state == LocalCollectorTargetState::UNCHANGED &&
						   scenario.run.targets[0].holdReason == L"NONE") ;
}

/** @brief 架空runの本文hashを正しく再構成しschema検証だけを試験します。
 * @param[in] body 非通信fixtureだけの変更済みJSON本文。
 * @return 本文hashが一致するenvelopeのUTF-8。
 * @throws std::runtime_error SHA-256計算に失敗した場合。
 */
[[nodiscard]] std::string fixtureEnvelope( const winrt::Windows::Data::Json::JsonObject &body)
{
	const auto	 bytes = winrt::to_string( body.Stringify()) ;	// 原byteへ一度だけ変換する。
	std::wstring hash ;											// 同じ本文のSHA-256。
	// Hash段階の失敗をschema拒否の試験へ混ぜない。
	if( computeBytesSha256( bytes, hash) != 0) {
		throw std::runtime_error( "fixture envelope hash failed") ;
	}

	winrt::Windows::Data::Json::JsonObject envelope ;	// 本番と同じ三field。
	envelope.Insert( L"schema", winrt::Windows::Data::Json::JsonValue::CreateStringValue(
								   L"dc-collector-envelope-v1")) ;
	envelope.Insert( L"sha256", winrt::Windows::Data::Json::JsonValue::CreateStringValue( hash)) ;
	envelope.Insert( L"body", winrt::Windows::Data::Json::JsonValue::CreateStringValue(
								 winrt::to_hstring( bytes))) ;
	return winrt::to_string( envelope.Stringify()) ;
}

/** @brief 存在する破損台帳を初回欠損として無視させません。
 * @param[in,out] context assertion集計。
 * @param[in] targets 公開fixture集合。
 * @param[in] manifest 元manifest指紋。
 */
void corruptionScenarios( TestContext &context, const std::vector<LocalCollectorTarget> &targets,
						 const std::wstring &manifest)
{
	// Pointerとrunの破損を独立して確認する。
	for( bool pointer : {false, true}) {
		CollectorScenario scenario( context, {targets[0]}, manifest) ;	// 独立root。
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 0) ;
		const auto path = scenario.path( pointer) ;	// 自作fileだけを故障化する。
		scenario.write( path, "{\"schema\":\"corrupt\",\"private\":\"FAKE_TOKEN\"}") ;
		++scenario.day ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 2 &&
										scenario.run.stateError == ERROR_INVALID_DATA &&
										scenario.http.sends == 1U) ;
		DRIVERCRATE_EXPECT( context, scenario.read( path).find( "FAKE_TOKEN") != std::string::npos) ;
	}

	// 正しい本文hashでも未知schema・矛盾した完了状態・曖昧な世代を拒否する。
	for( unsigned mode = 0U; mode < 4U; ++mode) {
		CollectorScenario scenario( context, {targets[0]}, manifest) ;	// Pointer未確定の一世代。
		scenario.hooks.stopAfterCheckpoint = []( LocalCollectorCheckpoint point, std::size_t) {
			return point == LocalCollectorCheckpoint::RUN_COMPLETED ;
		} ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 2 && scenario.run.complete) ;
		const auto original = scenario.path( false) ;	// 自作完了runだけを変更する。
		const auto wrapper	= winrt::Windows::Data::Json::JsonObject::Parse(
			 // 検証済み外側。
			 winrt::to_hstring( scenario.read( original))) ;
		auto body = winrt::Windows::Data::Json::JsonObject::Parse(
			// 検証対象のrun。
			wrapper.GetNamedString( L"body")) ;
		auto destination = original ;	// 二世代試験だけ別日付へ複製する。
		// 旧版・未知版をv4として読ませない。
		if( mode == 0U) {
			body.Insert( L"schema", winrt::Windows::Data::Json::JsonValue::CreateStringValue(
									   L"dc-collector-run-v999")) ;
		}
		// 完了runに未開始targetを混ぜない。
		else if( mode == 1U) {
			body.GetNamedArray( L"targets")
				.GetObjectAt( 0U)
				.Insert( L"state",
						winrt::Windows::Data::Json::JsonValue::CreateStringValue( L"PENDING")) ;
		} else {
			body.Insert( L"day",
						winrt::Windows::Data::Json::JsonValue::CreateStringValue( L"20260926")) ;
			destination = std::filesystem::path( L"runs") /
						  (L"20260926" + original.filename().native().substr( 8U)) ;
			// 完了二世代と完了／未完了混在を別々に拒否する。
			if( mode == 3U) {
				body.Insert( L"complete",
							winrt::Windows::Data::Json::JsonValue::CreateBooleanValue( false)) ;
			}
		}

		scenario.write( destination, fixtureEnvelope( body)) ;
		scenario.day					   = 2 ;
		scenario.hooks.stopAfterCheckpoint = {} ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 2 &&
										scenario.run.stateError == ERROR_INVALID_DATA &&
										scenario.http.sends == 1U) ;
		DRIVERCRATE_EXPECT( context, scenario.read( scenario.path( true)).empty()) ;
	}

	{
		CollectorScenario scenario( context, {targets[0]}, manifest) ;	// 時計後退。
		scenario.day = 1 ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 0) ;
		scenario.day = 0 ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 2 && scenario.http.sends == 1U) ;
	}
	{
		CollectorScenario scenario( context, {targets[0]}, manifest) ;	// Source待機の破損。
		scenario.http.status = 429U ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 1) ;
		std::wstring hash ;	// 固定source別key。
		DRIVERCRATE_EXPECT( context, computeBytesSha256( "ASUS_CATALOG", hash) == 0) ;
		scenario.write( std::filesystem::path( L"current") / (L"cooldown-" + hash + L".json"), "{}") ;
		++scenario.day ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 2 && scenario.http.sends == 1U) ;
	}
}

/** @brief 全旧契約の読込み・公開request共有・欠損拒否を検査します。
 * @param[in,out] context Assertion集計。
 * @param[in] targets 公開入力fixture。
 * @param[in] manifest 元manifest hash。
 */
void legacyInspection( TestContext &context, const std::vector<LocalCollectorTarget> &targets,
					  const std::wstring &manifest)
{
	// 成功、限流、空集合、未完了、pointer未昇格を独立検証する。
	for( unsigned mode = 0U; mode < 8U; ++mode) {
		CollectorScenario scenario( context, {targets[0]}, manifest) ;	// 実HTTPを持たない旧core。
		// 限流応答に対応するsource待機も読ませる。
		if( mode == 1U) {
			scenario.http.status = 429U ;
		}

		// 空の正常応答を永続失敗へ変換しない。
		if( mode == 2U) {
			scenario.http.body = "{\"Status\":\"SUCCESS\",\"Result\":{\"Obj\":[]}}" ;
		}

		// 旧実行中のrunを残して移行拒否を確認する。
		if( mode == 3U) {
			scenario.hooks.stopAfterCheckpoint = []( auto point, auto) {
				return point == LocalCollectorCheckpoint::TARGET_STARTED ;
			} ;
		}

		// 完了runだけでpointer未更新の窓を残す。
		if( mode == 4U) {
			scenario.hooks.stopAfterCheckpoint = []( auto point, auto) {
				return point == LocalCollectorCheckpoint::RUN_COMPLETED ;
			} ;
		}

		// 403は自動解除しないgroup reviewへ引き継ぐ。
		if( mode == 5U) {
			scenario.http.status = 403U ;
		}

		// Retry-Afterの元期限を日数上限で短縮しない。
		if( mode >= 6U) {
			scenario.http.status							 = 429U ;
			scenario.http.headers[WINHTTP_QUERY_RETRY_AFTER] = {
				mode == 6U ? L"172800" : L"Fri, 31 Dec 9999 00:00:00 GMT"} ;
		}

		(void)scenario.invoke() ;
		LocalCollectorStateStore store ;	// 同じ元保存fileを非変更で読む。
		DRIVERCRATE_EXPECT( context, store.initialize( scenario.root, true) == 0U) ;
		// 旧全契約から非変更で得る公開待機。
		CollectorLegacySnapshot snapshot ;
		std::wstring			reason ;	// 元codeと分類。
		// 全旧fileを検査した元error。
		const auto				code = inspectLocalCollectorLegacy(
			 store, scenario.hooks.utcSeconds() * 1000U + 1000U, snapshot, reason) ;
		// 閉鎖済みの三種類だけを引継ぎ可能と判定する。
		if( mode < 3U || mode >= 5U) {
			// 失敗時だけcaseと元codeを表示する。
			if( code != 0U || snapshot.fileCount != (mode == 1U || mode >= 6U ? 3U : 2U)) {
				std::cerr << "legacy mode=" << mode << " code=" << code
						  << " files=" << snapshot.fileCount << "\n" ;
			}

			DRIVERCRATE_EXPECT(
				context, code == 0U && snapshot.fileCount == (mode == 1U || mode >= 6U ? 3U : 2U) &&
							 snapshot.lastUsedDay == L"20260925") ;
			DRIVERCRATE_EXPECT( context, snapshot.digest.size() == 64U && !snapshot.waits.empty()) ;
			// Source待機をrequest待機と別に保持していることを確認する。
			if( mode >= 5U) {
				// 引継ぎ後のgroup待機行。
				const auto groupWait =
					std::find_if( snapshot.waits.begin(), snapshot.waits.end(),
								 []( const auto &wait) { return wait.requestKey.empty() ; }) ;
				DRIVERCRATE_EXPECT( context, groupWait != snapshot.waits.end()) ;
				// 行の存在を確認した上で期限と要確認を照合する。
				if( groupWait != snapshot.waits.end()) {
					DRIVERCRATE_EXPECT(
						context, mode == 6U ? groupWait->notBefore ==
												  (scenario.hooks.utcSeconds() + 172800U) * 1000U
											: groupWait->review) ;
				}
			}
		} else {
			DRIVERCRATE_EXPECT( context,
							   code == ERROR_RETRY && reason == L"LEGACY_RECOVERY_REQUIRED") ;
		}
	}

	{
		// 二つの旧manifestは同じ公開request待機へ統合する。
		CollectorScenario scenario( context, {targets[0]}, manifest) ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 0) ;
		scenario.manifest = std::wstring( 64U, L'b') ;
		++scenario.day ;
		DRIVERCRATE_EXPECT( context, scenario.invoke() == 0 && scenario.http.sends == 2U) ;
		// 現manifestによるfilterなしで全旧契約を読む。
		LocalCollectorStateStore store ;
		DRIVERCRATE_EXPECT( context, store.initialize( scenario.root, true) == 0U) ;
		// 四fileから得る統合待機。
		CollectorLegacySnapshot snapshot ;
		// 未採点の失敗理由を正常結果へ変換しない。
		std::wstring			reason ;
		DRIVERCRATE_EXPECT(
			context, inspectLocalCollectorLegacy( store, scenario.hooks.utcSeconds() * 1000U + 1000U,
												 snapshot, reason) == 0U) ;
		DRIVERCRATE_EXPECT( context, snapshot.fileCount == 4U && snapshot.waits.size() == 1U &&
										snapshot.lastUsedDay == L"20260926" &&
										snapshot.waits[0].notBefore ==
											(scenario.hooks.utcSeconds() + 86400U) * 1000U) ;
	}
	// 公式の公開requestに共通するgroup。
	std::wstring group ;
	std::wstring key ;	// 同じ公開modelのcategory間で共有するkey。
	DRIVERCRATE_EXPECT( context, makeLocalCollectorRequestKey( targets[0], group, key) &&
									group == L"asus" && key.size() == 64U) ;
	LocalCollectorRequest request ;	// 新しい公式requestと旧keyを同じ入力で比較する。
	DRIVERCRATE_EXPECT(
		context,
		makeLocalCollectorRequest( targets[0], request) && request.group == group &&
			request.requestKey == key && request.source == targets[0].source &&
			!request.provider.empty() && !request.resource.empty() &&
			request.url.starts_with( L"https://") &&
			request.accept ==
				L"application/json, application/xml, text/xml, application/octet-stream, */*") ;
	LocalCollectorTarget invalid = targets[0] ;	// 元target keyの偽造を拒否する。
	invalid.publicModel += L"changed" ;
	DRIVERCRATE_EXPECT( context, !makeLocalCollectorRequestKey( invalid, group, key) &&
									group.empty() && key.empty()) ;
	DRIVERCRATE_EXPECT( context, !makeLocalCollectorRequest( invalid, request) &&
									request.url.empty() && request.requestKey.empty() &&
									request.source.empty()) ;
}

/** @brief 実旧targetに結合した非通信v2入力を作ります。
 * @param[in] target 検証済み旧公開target。
 * @return 一つの公開requestを持つ架空manifest。
 */
CollectorRecoveryInput legacyRecoveryInput( const LocalCollectorTarget &target)
{
	// v4 targetから恒久requestを本番関数で再構成する。
	CollectorRecoveryInput input ;
	// 元公式起点のgroupとrequest。
	std::wstring		   group ;
	// Hashは旧bindingとは別の恒久identity。
	std::wstring		   request ;
	// 未対応targetから試験用の許可を作らない。
	if( !makeLocalCollectorRequestKey( target, group, request)) {
		throw std::runtime_error( "legacy request") ;
	}

	input.manifestBytes =
		R"({"schema":"collector-campaign-manifest-v1","campaignId":"migration","planSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","os":"WINDOWS_11_X64","targets":[{"id":"product","maker":"Fixture","model":"Public Model","kind":"MAINBOARD","purpose":"network"}],"jobs":[{"source":"fixture","resource":"metadata","locator":"public-page","locale":"en-US","page":1,"targets":["product"]}]})" ;
	input.sources		 = {{L"fixture", L"metadata", group, L"parser-v1", 8U * 1024U * 1024U}} ;
	input.artifactSha256 = std::wstring( 64U, L'a') ;
	input.requestKeys	 = {request} ;
	input.cacheBindings	 = {std::wstring( 64U, L'b')} ;
	return input ;
}

/** @brief 保護storeの全確定byteを非変更比較用に読みます。
 * @param[in,out] store 自作rootのwriter。
 * @return 相対名と保存byte。
 */
std::map<std::wstring, std::string> legacySavedFiles( LocalCollectorStateStore &store)
{
	// URLや実端末IDを含まない架空保存物だけを比較する。
	std::map<std::wstring, std::string> result ;
	// 保護列挙を両directoryに使う。
	for( const auto directory : {L"current", L"runs"}) {
		// 有限な確定fileの名前だけ。
		std::vector<std::wstring> names ;
		// 全量列挙に失敗した結果で非変更合格にしない。
		if( (std::wstring_view( directory) == L"current" ? store.listCurrentNames( names)
													   : store.listRunNames( names)) != 0U) {
			throw std::runtime_error( "legacy list") ;
		}

		// 元byteの完全一致を確認するため全fileを読む。
		for( const auto &name : names) {
			// 同じ保護handleから読み込む元byte。
			std::string raw ;
			// 欠損を空fileと区別する。
			bool		found{} ;
			// 固定directoryだけを結合する。
			const auto	relative = std::filesystem::path( directory) / name ;
			// 部分比較へ縮退しない。
			if( store.read( relative, raw, found) != 0U || !found) {
				throw std::runtime_error( "legacy read") ;
			}

			result.emplace( relative.generic_wstring(), raw) ;
		}
	}

	return result ;
}

/** @brief 正常形式の別旧契約を保存します。別binaryの実行ではありません。
 * @param[in,out] scenario 空結果で閉鎖済みの自作fixture。
 * @param[in] contract 別の架空artifact契約hash。
 */
void legacyCloneContract( CollectorScenario &scenario, const std::wstring &contract)
{
	// Bindingが空の正常未成功runだけを複製する。
	const auto envelope = winrt::Windows::Data::Json::JsonObject::Parse(
		winrt::to_hstring( scenario.read( scenario.path( false)))) ;
	// 元codecの全fieldとcanonical順序を保持する。
	auto body = winrt::Windows::Data::Json::JsonObject::Parse( envelope.GetNamedString( L"body")) ;
	body.Insert( L"contractSha256",
				winrt::Windows::Data::Json::JsonValue::CreateStringValue( contract)) ;
	// 新pointerは変更後run本文へ結合する。
	std::wstring runHash ;
	// Hash計算失敗を正常fixtureとして扱わない。
	if( computeBytesSha256( winrt::to_string( body.Stringify()), runHash) != 0U) {
		throw std::runtime_error( "legacy clone hash") ;
	}

	// 元pointerのfield順序を保持する。
	const auto pointerEnvelope = winrt::Windows::Data::Json::JsonObject::Parse(
		winrt::to_hstring( scenario.read( scenario.path( true)))) ;
	// 同じ日・manifestの別artifactを登録する。
	auto pointer =
		winrt::Windows::Data::Json::JsonObject::Parse( pointerEnvelope.GetNamedString( L"body")) ;
	pointer.Insert( L"contractSha256",
				   winrt::Windows::Data::Json::JsonValue::CreateStringValue( contract)) ;
	pointer.Insert( L"runSha256", winrt::Windows::Data::Json::JsonValue::CreateStringValue( runHash)) ;
	// Nameと本文の二hashを一致させる。
	const auto suffix = scenario.manifest + L"-" + contract + L".json" ;
	scenario.write( std::filesystem::path( L"runs") / (scenario.run.day + L"-" + suffix),
				   fixtureEnvelope( body)) ;
	scenario.write( std::filesystem::path( L"current") / suffix, fixtureEnvelope( pointer)) ;
}

/** @brief 旧category／別契約のv2取込みと同日未知使用量を確認します。
 * @param[in,out] context Assertion集計。
 * @param[in] targets 元公式target fixture。
 * @param[in] manifest 元manifest hash。
 */
void legacyEnrollment( TestContext &context, const std::vector<LocalCollectorTarget> &targets,
					  const std::wstring &manifest)
{
	// ASUSの別categoryでも同じpage requestを共有する。
	auto wireless	  = targets[0] ;
	wireless.category = L"Wireless" ;
	DRIVERCRATE_EXPECT(
		context, computeBytesSha256(
					 winrt::to_string( wireless.source + L"\n" + wireless.publicModel + L"\n" +
									  wireless.operatingSystem + L"\n" + wireless.category + L"\n"),
					 wireless.keySha256) == 0U) ;
	// Scope外の旧Intelも取り込む。
	CollectorScenario scenario( context, {targets[0], wireless, targets[1]}, manifest) ;
	scenario.http.body = R"({"Status":"SUCCESS","Result":{"Obj":[]}})" ;
	// 元bindingなしの未成功runを実codecで生成する。
	(void)scenario.invoke() ;
	legacyCloneContract( scenario, std::wstring( 64U, L'c')) ;
	// 同日使用量不明を0使用にして新予約しない。
	LocalCollectorStateStore store ;
	DRIVERCRATE_EXPECT( context, store.initialize( scenario.root, true) == 0U) ;
	// ASUS一要求を今回scopeとする。
	const auto input = legacyRecoveryInput( targets[0]) ;
	// 旧全fileの原byteを保持する。
	const auto oldFiles = legacySavedFiles( store) ;
	{
		// 同日初回は登録だけを確定して延期する。
		LocalCollectorRecovery core ;
		DRIVERCRATE_EXPECT( context,
						   core.initialize( store, input, scenario.hooks.utcSeconds() * 1000U, 0U) ==
							   ERROR_RETRY) ;
		DRIVERCRATE_EXPECT( context, core.reason() == L"LEGACY_DAY_USAGE_UNKNOWN" &&
										core.generationKey().empty()) ;
	}
	// 実保存台帳の元envelopeを読む。
	std::string raw ;
	// 登録済みfileの存在確認。
	bool		found{} ;
	DRIVERCRATE_EXPECT( context,
					   store.read( L"current/campaign-controls-v1.json", raw, found) == 0U && found) ;
	// 二category・二契約をASUS一要求へ統合、Intelのscope外待機も保持する。
	CollectorWaitSnapshot controls ;
	DRIVERCRATE_EXPECT(
		context,
		parseCollectorWaitSnapshot(
			winrt::to_string( winrt::Windows::Data::Json::JsonObject::Parse( winrt::to_hstring( raw))
								 .GetNamedString( L"body")),
			controls)) ;
	DRIVERCRATE_EXPECT( context, controls.controls.size() == 4U &&
									controls.controls.contains( L"g-intel") &&
									controls.controls.at( L"r-" + input.requestKeys[0]).notBefore ==
										(scenario.hooks.utcSeconds() + 86400U) * 1000U) ;
	// 旧契約の原byteは一つも書き換えない。
	const auto registered = legacySavedFiles( store) ;
	// 元四file全部を完全一致で照合する。
	for( const auto &[name, bytes] : oldFiles) {
		DRIVERCRATE_EXPECT( context, registered.at( name) == bytes) ;
	}

	{
		// 翌日になっても独立request待機を再確認する。
		LocalCollectorRecovery core ;
		DRIVERCRATE_EXPECT( context, core.initialize( store, input,
													(scenario.hooks.utcSeconds() + 86400U) * 1000U,
													0U) == 0U) ;
		// 待機満了済みの一要求だけを予約する。
		CollectorRecoveryDispatch dispatch ;
		DRIVERCRATE_EXPECT( context, core.reserve( (scenario.hooks.utcSeconds() + 86400U) * 1000U,
												 2000U, dispatch) == 0U) ;
	}
}

/** @brief 登録後の正常形式の改変・追加・削除も非変更拒否します。
 * @param[in,out] context Assertion集計。
 * @param[in] targets 元target fixture。
 * @param[in] manifest 元manifest hash。
 */
void legacyChangedAfterEnrollment( TestContext							  &context,
								  const std::vector<LocalCollectorTarget> &targets,
								  const std::wstring					  &manifest)
{
	// 旧byte集合の三つの変化を別rootで試す。
	for( unsigned fault = 0U; fault < 3U; ++fault) {
		// 結果なしの正常閉鎖runを持つ独立root。
		CollectorScenario scenario( context, {targets[0]}, manifest) ;
		scenario.http.body = R"({"Status":"SUCCESS","Result":{"Obj":[]}})" ;
		(void)scenario.invoke() ;
		// 旧と同じ恒久requestへ結合する。
		const auto input = legacyRecoveryInput( targets[0]) ;
		{
			// 翌日に新modeを登録する。
			LocalCollectorStateStore store ;
			DRIVERCRATE_EXPECT( context, store.initialize( scenario.root, true) == 0U) ;
			// 登録を確定してから故障を注入する。
			LocalCollectorRecovery core ;
			DRIVERCRATE_EXPECT(
				context, core.initialize( store, input,
										 (scenario.hooks.utcSeconds() + 86400U) * 1000U, 0U) == 0U) ;
		}
		// 正常な別契約を追加する。
		if( fault == 0U) {
			legacyCloneContract( scenario, std::wstring( 64U, L'c')) ;
		}

		// 登録済みのrunを改変し、hashとpointerも再結合する。
		if( fault == 1U) {
			// 原runの外側を先に検査する。
			const auto envelope = winrt::Windows::Data::Json::JsonObject::Parse(
				winrt::to_hstring( scenario.read( scenario.path( false)))) ;
			// 正常な過去観測の値だけを変更する。
			auto body =
				winrt::Windows::Data::Json::JsonObject::Parse( envelope.GetNamedString( L"body")) ;
			body.GetNamedArray( L"targets")
				.GetObjectAt( 0U)
				.Insert( L"nextAttemptAt",
						winrt::Windows::Data::Json::JsonValue::CreateNumberValue(
							static_cast<double>( scenario.hooks.utcSeconds() + 86401U))) ;
			// 本文hashの再計算。
			std::wstring runHash ;
			DRIVERCRATE_EXPECT(
				context, computeBytesSha256( winrt::to_string( body.Stringify()), runHash) == 0U) ;
			// Pointerも正常形式を保ち、単なるhash不一致とは区別する。
			const auto pointerEnvelope = winrt::Windows::Data::Json::JsonObject::Parse(
				winrt::to_hstring( scenario.read( scenario.path( true)))) ;
			// 元five-field pointer。
			auto pointer = winrt::Windows::Data::Json::JsonObject::Parse(
				pointerEnvelope.GetNamedString( L"body")) ;
			pointer.Insert( L"runSha256",
						   winrt::Windows::Data::Json::JsonValue::CreateStringValue( runHash)) ;
			scenario.write( scenario.path( false), fixtureEnvelope( body)) ;
			scenario.write( scenario.path( true), fixtureEnvelope( pointer)) ;
		}

		// 削除は今回作ったGUID rootの既知一fileに限定する。
		if( fault == 2U) {
			// 既知相対pathを完全なfixture rootへ解決する。
			const auto file = scenario.root / scenario.path( false) ;
			DRIVERCRATE_EXPECT( context, file.parent_path().parent_path() == scenario.root &&
											scenario.root.filename().wstring().starts_with(
												L"collector-run-fixture-") &&
											DeleteFileW( fixtureIoPath( file).c_str())) ;
		}

		// 故障後の原byte集合を保存する。
		LocalCollectorStateStore store ;
		DRIVERCRATE_EXPECT( context, store.initialize( scenario.root, true) == 0U) ;
		// 拒否前に全byteを取得する。
		const auto			   before = legacySavedFiles( store) ;
		// 元rootを修復して通信許可を戻さない。
		LocalCollectorRecovery core ;
		DRIVERCRATE_EXPECT( context,
						   core.initialize( store, input,
										   (scenario.hooks.utcSeconds() + 86400U) * 1000U + 1000U,
										   0U) == ERROR_INVALID_DATA) ;
		DRIVERCRATE_EXPECT( context, core.reason() == L"LEGACY_STATE_CHANGED" &&
										legacySavedFiles( store) == before) ;
	}
}

/** @brief 正常envelopeを用いて初回待機表の容量を検査します。
 * @param[in,out] context Assertion集計。
 * @param[in] targets 元target fixture。
 * @param[in] manifest 元manifest hash。
 */
void legacyEnrollmentCapacity( TestContext							  &context,
							  const std::vector<LocalCollectorTarget> &targets,
							  const std::wstring					  &manifest)
{
	// 新しい旧request一件の取込みで300を越える場合だけ拒否する。
	for( const bool full : {false, true}) {
		// 実codecの旧空結果を持つroot。
		CollectorScenario scenario( context, {targets[0]}, manifest) ;
		scenario.http.body = R"({"Status":"SUCCESS","Result":{"Obj":[]}})" ;
		(void)scenario.invoke() ;
		// 旧scopeの公開requestを使う入力。
		const auto			  input = legacyRecoveryInput( targets[0]) ;
		// 初回登録時刻へ結合する正常な既存controls。
		CollectorWaitSnapshot table ;
		table.lastUtc = (scenario.hooks.utcSeconds() + 86400U) * 1000U ;
		// 一つの既存groupを含める。
		CollectorWaitControl group ;
		group.group	   = L"asus" ;
		group.observed = table.lastUtc ;
		table.controls.emplace( L"g-asus", group) ;
		// 架空request集合の299／300境界。
		for( unsigned index = 0U; index < (full ? 300U : 299U); ++index) {
			// 既存request一件の正常待機。
			auto row = group ;
			DRIVERCRATE_EXPECT( context, computeBytesSha256( "enrollment-" + std::to_string( index),
														   row.request) == 0U) ;
			table.controls.emplace( L"r-" + row.request, row) ;
		}

		// 本番codecを経由して正規表現を固定する。
		std::string control ;
		DRIVERCRATE_EXPECT( context, encodeCollectorWaitSnapshot( table, control)) ;
		// 同じ保護writerに正常tableを配置する。
		LocalCollectorStateStore store ;
		DRIVERCRATE_EXPECT( context, store.initialize( scenario.root, true) == 0U) ;
		// 外側envelopeだけを両初期保存物へ共用するfixture。
		const auto save = [&]( const std::wstring &name, const std::string &body) {
			// 正常なbody hash。
			std::wstring hash ;
			// 保存準備失敗を受入の数値errorと混同しない。
			if( computeBytesSha256( body, hash) != 0U) {
				throw std::runtime_error( "enrollment envelope hash") ;
			}

			// v2が使用する既存envelope schema。
			winrt::Windows::Data::Json::JsonObject envelope ;
			envelope.Insert( L"schema", winrt::Windows::Data::Json::JsonValue::CreateStringValue(
										   L"collector-campaign-envelope-v1")) ;
			envelope.Insert( L"body", winrt::Windows::Data::Json::JsonValue::CreateStringValue(
										 winrt::to_hstring( body))) ;
			envelope.Insert( L"sha256",
							winrt::Windows::Data::Json::JsonValue::CreateStringValue( hash)) ;
			// 通常の保護保存が失敗した場合は採点を止める。
			if( store.write( name, winrt::to_string( envelope.Stringify())) != 0U) {
				throw std::runtime_error( "enrollment envelope write") ;
			}
		} ;
		save( L"current/campaign-controls-v1.json", control) ;
		save( L"current/campaign-controls-marker-v1.json", "collector-campaign-controls-root-v1") ;
		// 登録前の原byte集合。
		const auto			   before = legacySavedFiles( store) ;
		// 上限判定は新mode保存より先である。
		LocalCollectorRecovery core ;
		DRIVERCRATE_EXPECT( context, core.initialize( store, input, table.lastUtc, 0U) ==
										(full ? ERROR_TOO_MANY_NAMES : 0U)) ;
		// 容量拒否では一つも保存しない。
		if( full) {
			DRIVERCRATE_EXPECT( context, core.reason() == L"STATE_CAPACITY" &&
											legacySavedFiles( store) == before) ;
		}
	}
}

/** @brief 実旧保存byteから待機exportを作り、元fileと期限を保持するか確認します。
 * @param[in,out] context Assertion集計。
 * @param[in] targets 架空の公開製品条件。
 * @param[in] manifest 元manifest指紋。
 */
void legacyExportScenarios( TestContext &context, const std::vector<LocalCollectorTarget> &targets,
						   const std::wstring &manifest)
{
	// 成功・長期待機・二種類の未回収・新modeを独立したrootで検査する。
	for( unsigned mode = 0U; mode < 5U; ++mode) {
		CollectorScenario scenario( context, {targets[0]}, manifest) ;	// 非通信の旧run所有者。
		// 9999年の期限を出力時にも短縮しない。
		if( mode == 1U) {
			scenario.http.status							 = 429U ;
			scenario.http.headers[WINHTTP_QUERY_RETRY_AFTER] = {L"Fri, 31 Dec 9999 00:00:00 GMT"} ;
		}

		// HTTP前の予約またはpointer前の確定窓を残す。
		if( mode == 2U || mode == 3U) {
			scenario.hooks.stopAfterCheckpoint = [mode]( auto point, auto) {
				return point == (mode == 2U ? LocalCollectorCheckpoint::TARGET_STARTED
											: LocalCollectorCheckpoint::RUN_COMPLETED) ;
			} ;
		}

		(void)scenario.invoke() ;
		std::map<std::wstring, std::string> before ;	// 元の全旧fileのbyte集合。
		{
			LocalCollectorStateStore store ;	// 排他所有中のexport拒否も確認する。
			DRIVERCRATE_EXPECT( context, store.initialize( scenario.root, true) == 0U) ;
			// 新modeの存在は部分的な旧exportを拒否する。
			if( mode == 4U) {
				DRIVERCRATE_EXPECT(
					context, store.write( L"current/collector-campaign-mode-v1.json", "{}") == 0U) ;
			}

			before = legacySavedFiles( store) ;
			CollectorLegacySnapshot blocked ;		// 競合時の出力は空のままにする。
			std::string				blockedBytes ;	// APIはlockを奪わずbyteを生成しない。
			DRIVERCRATE_EXPECT( context,
							   prepareLocalCollectorLegacyExport(
								   scenario.root, scenario.hooks.utcSeconds() * 1000U + 1000U,
								   blocked, blockedBytes) != 0U &&
								   blockedBytes.empty()) ;
		}
		CollectorLegacySnapshot snapshot ;	// Lock解放後の完全検証結果。
		std::string				bytes ;		// 秘密を含まない待機JSON。
		const DWORD				code = prepareLocalCollectorLegacyExport(
			scenario.root, scenario.hooks.utcSeconds() * 1000U + 1000U, snapshot,
			bytes) ;	// 実旧decoderを再利用する。
		// 確定済みの旧v4だけが持出し可能である。
		if( mode < 2U) {
			DRIVERCRATE_EXPECT( context, code == 0U && snapshot.fileCount == (mode == 0U ? 2U : 3U)) ;
			const auto document =
				// 元出力。
				winrt::Windows::Data::Json::JsonObject::Parse( winrt::to_hstring( bytes)) ;
			DRIVERCRATE_EXPECT( context,
							   document.Size() == 6U && document.GetNamedString( L"schema") ==
															L"dc-collector-legacy-wait-export-v1") ;
			DRIVERCRATE_EXPECT(
				context, document.GetNamedString( L"legacyDigest") == snapshot.digest &&
							 document.GetNamedArray( L"waits").Size() == snapshot.waits.size()) ;
			// 各期限とreviewを元のtyped結果から変更していないか比較する。
			for( std::size_t index = 0U; index < snapshot.waits.size(); ++index) {
				const auto row = document.GetNamedArray( L"waits").GetObjectAt(
					// 対応行。
					static_cast<std::uint32_t>( index)) ;
				const auto &wait = snapshot.waits[index] ;	// 元待機の借用。
				DRIVERCRATE_EXPECT(
					context,
					row.Size() == 5U && row.GetNamedString( L"group") == wait.group &&
						row.GetNamedString( L"requestKey") == wait.requestKey &&
						row.GetNamedNumber( L"observed") == static_cast<double>( wait.observed) &&
						row.GetNamedNumber( L"notBefore") == static_cast<double>( wait.notBefore) &&
						row.GetNamedBoolean( L"review") == wait.review) ;
			}

			DRIVERCRATE_EXPECT( context, bytes.find( "https:") == std::string::npos &&
											bytes.find( "publicModel") == std::string::npos &&
											bytes.find( "path") == std::string::npos) ;
		} else {
			DRIVERCRATE_EXPECT( context, code != 0U && bytes.empty() && snapshot.fileCount == 0U) ;
		}

		LocalCollectorStateStore store ;	// 出力前後の原byteを比較する。
		DRIVERCRATE_EXPECT( context, store.initialize( scenario.root, true) == 0U &&
										legacySavedFiles( store) == before) ;
	}

	const auto				missing = fixtureRoot() ;	// 作成していない専用root。
	CollectorLegacySnapshot snapshot ;					// 欠損時は空の結果。
	std::string				bytes ;						// 初回履歴なしへ読み替えない。
	DRIVERCRATE_EXPECT( context, prepareLocalCollectorLegacyExport( missing, 1790294400000ULL,
																  snapshot, bytes) != 0U &&
									!std::filesystem::exists( missing) && bytes.empty()) ;
}

/** @brief 実配布物を含めず既存Intel parserの契約を通す架空metadataです。
 * @return 非通信transportだけへ渡すUTF-8 HTML。
 */
[[nodiscard]] std::string dailyIntelPage()
{
	return R"(<html><h1>Intel® Network Adapter Driver for Microsoft Windows 11*</h1>
<p>Intel requires an accepted license agreement in order to download this file.</p>
<textarea id="content-raw" class="license-modal-content_body_license-text-raw" tabindex="0"><html lang="en"><head><title>Intel Fixture License Agreement [v2030.01.02]</title></head><body><p>Artificial fixture terms.</p></body></html></textarea>
<h2>Available Downloads</h2>
<button data-modal-id="1" data-href="https://downloadmirror.intel.com/900011/Wired_driver_31.2.2_x64.zip">Wired_driver_31.2.2_x64.zip</button>
<li>Windows 11 Family*</li><li>Size: 38.6 MB</li>
<li>SHA256: 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF</li>
<h2>Detailed Description</h2><p><strong>Driver Package:</strong> Wired_driver_31.2.2_x64.zip</p>
<h2>This download is valid for the product(s) listed below.</h2>
<a>Intel® Ethernet Network Adapter E610-XT2</a></html>)" ;
}

/** @brief 人工200→304、早着HOLDと同日due後、未通信と単調世代を確認します。
 * @param[in,out] context Assertion集計。
 * @param[in] targets 既存manifest parserが返した公開二対象。
 * @param[in] manifest 元fixture manifestのhash。
 */
void dailyReceiptScenarios( TestContext &context, const std::vector<LocalCollectorTarget> &targets,
						   const std::wstring &manifest)
{
	using Object = winrt::Windows::Data::Json::JsonObject ;
	CollectorScenario scenario( context, {targets[1]}, manifest) ;	// Intel一対象だけの自作root。
	scenario.http.body	   = dailyIntelPage() ;
	scenario.offsetSeconds = 10U ;
	// 同じfixtureだけを同期呼出し中に借用し、実HTTPを一切持ちません。
	const auto invoke = [&scenario] {
		activeFixture = &scenario.http ;
		return runLocalDriverCollectorWithHooks( scenario.root, scenario.targets, scenario.manifest,
												false, scenario.hooks, scenario.run, false, true) ;
	} ;
	const int initialCode = invoke() ;	// 第一失敗の原因を固定数値で観測します。
	std::cout << "DAILY_ARTIFICIAL_INITIAL code=" << initialCode
			  << " state_error=" << scenario.run.stateError
			  << " target_error=" << scenario.run.targets.front().error
			  << " http=" << scenario.run.targets.front().lastHttpStatus
			  << " generation=" << scenario.run.dailyGeneration << " sends=" << scenario.http.sends
			  << '\n' ;
	DRIVERCRATE_EXPECT( context, initialCode == 0 && scenario.run.dailyGeneration == 4U &&
									scenario.http.sends == 1U &&
									scenario.run.targets.front().retainedMetadataBytes ==
										scenario.http.body) ;
	std::string firstReceipt ;	// 元200 receiptの厳密byte。
	DRIVERCRATE_EXPECT( context, makeLocalCollectorDailyReceipt( scenario.run, firstReceipt)) ;
	// 失敗したfixtureから後続成功を推測しません。
	if( firstReceipt.empty() || scenario.run.targets.front().records.empty()) {
		return ;
	}

	const auto first = scenario.run.targets.front() ;	// 元fetch・本文・射影を保持します。
	// この試験内で作った架空metadataだけをproducer境界の再現用原記録へ返します。
	std::cout << "DAILY_ARTIFICIAL_200 " << firstReceipt << '\n' ;
	const auto firstJson = Object::Parse( winrt::to_hstring( firstReceipt)) ;	// 明示200 receipt。
	DRIVERCRATE_EXPECT( context, firstJson.GetNamedString( L"outcome") == L"NEW_200" &&
									firstJson.GetNamedNumber( L"httpStatus") == 200.0) ;
	const auto head = scenario.read( L"current/daily-generation-v1.json") ;	// 予約済み4。
	DRIVERCRATE_EXPECT( context, invoke() == 0 && scenario.http.sends == 1U &&
									scenario.run.reusedCheckpoint &&
									scenario.run.dailyGeneration == 0U) ;
	std::string repeated ;	// 旧HTTP200を今回200と表現しないreceipt。
	DRIVERCRATE_EXPECT( context, makeLocalCollectorDailyReceipt( scenario.run, repeated)) ;
	DRIVERCRATE_EXPECT( context,
					   Object::Parse( winrt::to_hstring( repeated)).GetNamedString( L"outcome") ==
							   L"NO_NETWORK" &&
						   scenario.read( L"current/daily-generation-v1.json") == head) ;
	++scenario.day ;
	scenario.offsetSeconds = 0U ;
	// 別manifestでも恒久request待機を継承します。
	scenario.manifest = std::wstring( 64U, L'b') ;
	DRIVERCRATE_EXPECT( context,
					   invoke() == 3 && scenario.run.dailyHeld && scenario.http.sends == 1U &&
						   scenario.run.dailyNotBefore == first.nextAttemptAt &&
						   !scenario.run.complete && scenario.read( scenario.path( false)).empty()) ;
	std::string held ;	// 当日runを作らない正直な保留。
	DRIVERCRATE_EXPECT(
		context, makeLocalCollectorDailyReceipt( scenario.run, held) &&
					 Object::Parse( winrt::to_hstring( held)).GetNamedString( L"outcome") == L"HOLD") ;
	scenario.manifest	   = manifest ;
	scenario.offsetSeconds = 10U ;
	scenario.http.status   = 304U ;
	DRIVERCRATE_EXPECT(
		context,
		invoke() == 0 && scenario.http.sends == 2U && scenario.run.dailyGeneration == 5U &&
			scenario.run.targets.front().lastHttpStatus == 304U &&
			scenario.run.targets.front().lastFetchedAt == first.lastFetchedAt &&
			scenario.run.targets.front().lastSuccessfulValidationAt ==
				first.lastSuccessfulValidationAt + 86400U &&
			scenario.run.targets.front().bodySha256 == first.bodySha256 &&
			scenario.run.targets.front().retainedMetadataBytes == first.retainedMetadataBytes &&
			scenario.run.targets.front().rawMetadataBytes.empty() &&
			scenario.http.sentHeaders.find( L"If-None-Match: \"v1\"") != std::wstring::npos) ;
	std::string revalidated ;	// 元本文を新200と偽らない304 receipt。
	DRIVERCRATE_EXPECT( context, makeLocalCollectorDailyReceipt( scenario.run, revalidated)) ;
	// 実配布本文を含まない架空304を、別processの投影検証へ渡します。
	std::cout << "DAILY_ARTIFICIAL_304 " << revalidated << '\n' ;
	std::wstring firstHash ;	// 世代headのreceipt hash鎖。
	DRIVERCRATE_EXPECT( context, computeBytesSha256( firstReceipt, firstHash) == 0 &&
									scenario.run.dailyPreviousReceiptSha256 == firstHash) ;
	const auto secondJson =
		// 元fetchと今回validationの別値。
		Object::Parse( winrt::to_hstring( revalidated)) ;
	DRIVERCRATE_EXPECT( context, secondJson.GetNamedString( L"outcome") == L"REVALIDATED_304" &&
									secondJson.GetNamedNumber( L"httpStatus") == 304.0 &&
									secondJson.GetNamedString( L"bodyBytesBase64") ==
										firstJson.GetNamedString( L"bodyBytesBase64")) ;
	// 所有copyへの各故障を個別に試し、元の保護stateは変更しません。
	for( const int mode : {0, 1, 2}) {
		auto damaged = scenario.run ;	// 既存304正常例の所有copy。
		// 本文欠損を旧成功で補完しません。
		if( mode == 0) {
			damaged.targets.front().retainedMetadataBytes.clear() ;
		}
		// 元hashと異なるbyteを公開しません。
		else if( mode == 1) {
			damaged.targets.front().retainedMetadataBytes.push_back( 'x') ;
		} else {
			damaged.targets.front().records.front().packageVersion = L"changed" ;
		}

		std::string rejected ;	// 拒否時に空を維持する出力。
		DRIVERCRATE_EXPECT( context,
						   !makeLocalCollectorDailyReceipt( damaged, rejected) && rejected.empty()) ;
	}

	{
		LocalCollectorStateStore locked ;	// 同一rootの実排他を保持します。
		DRIVERCRATE_EXPECT( context, locked.initialize( scenario.root, true) == 0U) ;
		DRIVERCRATE_EXPECT( context, invoke() == 2 && scenario.http.sends == 2U) ;
	}
	++scenario.day ;
	// 自作fixture rootの特定headだけを除き、世代巻戻りを通信前に拒否させます。
	DRIVERCRATE_EXPECT( context,
					   DeleteFileW( (scenario.root / L"current/daily-generation-v1.json").c_str()) !=
						   FALSE) ;
	DRIVERCRATE_EXPECT( context, invoke() == 2 && scenario.http.sends == 2U) ;
	scenario.write( L"current/daily-generation-v1.json", "{}") ;
	DRIVERCRATE_EXPECT( context, invoke() == 2 && scenario.http.sends == 2U) ;

	// 元本文fieldの欠損と改変を外側hash正常の保護fixtureで別々に検証します。
	for( const int mode : {1, 2}) {
		CollectorScenario broken( context, {targets[1]}, manifest) ;	// 故障ごとの新規fake root。
		broken.http.body = dailyIntelPage() ;
		DRIVERCRATE_EXPECT( context, runLocalDriverCollectorWithHooks( broken.root, broken.targets,
																	 manifest, false, broken.hooks,
																	 broken.run, false, true) == 0) ;
		DRIVERCRATE_EXPECT( context, alterSavedProjection( broken.root, broken.run, false, mode)) ;
		const auto before =
			// 予約headを維持します。
			broken.read( L"current/daily-generation-v1.json") ;
		++broken.day ;
		broken.http.status = 304U ;
		DRIVERCRATE_EXPECT(
			context, runLocalDriverCollectorWithHooks( broken.root, broken.targets, manifest, false,
													  broken.hooks, broken.run, false, true) == 2 &&
						 broken.read( L"current/daily-generation-v1.json") == before) ;
		DRIVERCRATE_EXPECT( context, broken.http.sends == (mode == 1 ? 2U : 1U)) ;
	}

	// HTTP直前と保存後の中断を別の固定分母で回収します。
	for( const auto stop :
		{LocalCollectorCheckpoint::TARGET_STARTED, LocalCollectorCheckpoint::TARGET_SAVED}) {
		CollectorScenario stopped( context, {targets[1]}, manifest) ;	// 一中断境界だけのfake root。
		stopped.http.body				  = dailyIntelPage() ;
		stopped.hooks.stopAfterCheckpoint = [stop]( LocalCollectorCheckpoint point, std::size_t) {
			return point == stop ;
		} ; // 同期callback内で固定境界だけを比較します。
		DRIVERCRATE_EXPECT( context, runLocalDriverCollectorWithHooks(
										stopped.root, stopped.targets, manifest, false,
										stopped.hooks, stopped.run, false, true) == 2 &&
										stopped.run.stateError == ERROR_OPERATION_ABORTED) ;
		stopped.hooks.stopAfterCheckpoint = {} ;
		DRIVERCRATE_EXPECT( context,
						   runLocalDriverCollectorWithHooks( stopped.root, stopped.targets, manifest,
															false, stopped.hooks, stopped.run,
															false, true) == 0 &&
							   stopped.http.sends == 1U &&
							   stopped.run.dailyGeneration ==
								   (stop == LocalCollectorCheckpoint::TARGET_STARTED ? 4U : 0U)) ;
	}
}

/** @brief 自作rootの全名前・directory・file byteを有限に固定します。
 * @param[in] root このsuiteが作成したfixtureだけ。
 * @return Lockを含む全通常fileとdirectoryの完全snapshot。
 */
[[nodiscard]] std::map<std::wstring, std::string> reservationFiles(
	const std::filesystem::path &root)
{
	std::map<std::wstring, std::string> result ;	// 非変更比較用の所有byte。
	// 自作fixtureの最大64項目だけを列挙し、全名前を比較へ残す。
	for( const auto &entry : std::filesystem::recursive_directory_iterator( root)) {
		// 予想外の肥大化を部分snapshotで合格しない。
		if( result.size() >= 64U || entry.is_symlink()) {
			throw std::runtime_error( "reservation snapshot cap") ;
		}

		const auto name = entry.path().lexically_relative( root).generic_wstring() ;	// 相対名。
		// Directoryも名前不変の比較へ含める。
		if( entry.is_directory()) {
			result.emplace( name, "DIRECTORY") ;
		} else {
			// 通常file以外・過大fileを読み込まない。
			if( !entry.is_regular_file() || entry.file_size() > 2U * 1024U * 1024U) {
				throw std::runtime_error( "reservation snapshot file") ;
			}

			std::ifstream input( fixtureIoPath( entry.path()),
								std::ios::binary) ;	// 自作fileだけの原byte。
			std::string	  raw( std::istreambuf_iterator<char>{input},
							  std::istreambuf_iterator<char>{}) ;	// 完全読取。
			// 短い読取を非変更証明にしない。
			if( !input || raw.size() != entry.file_size()) {
				throw std::runtime_error( "reservation snapshot read") ;
			}

			result.emplace( name, std::move( raw)) ;
		}
	}

	return result ;
}

/** @brief 原予約と現在headの一致・全非変更・有限故障を人工rootだけで確認します。
 * @param[in,out] context Assertion集計。
 * @param[in] targets 既存の公開二対象fixture。
 * @param[in] manifest 元manifest hash。
 */
void dailyReservationScenarios( TestContext							   &context,
							   const std::vector<LocalCollectorTarget> &targets,
							   const std::wstring					   &manifest)
{
	using Object = winrt::Windows::Data::Json::JsonObject ;
	using Value	 = winrt::Windows::Data::Json::JsonValue ;
	using Mode	 = LocalCollectorReservationMode ;
	CollectorScenario scenario( context, {targets[1]}, manifest) ;	// 一対象の人工root。
	scenario.http.body = dailyIntelPage() ;
	activeFixture	   = &scenario.http ;
	DRIVERCRATE_EXPECT( context, runLocalDriverCollectorWithHooks( scenario.root, scenario.targets,
																 manifest, false, scenario.hooks,
																 scenario.run, false, true) == 0) ;
	std::string receipt ;	// 原serializerの完全byte。
	DRIVERCRATE_EXPECT( context, makeLocalCollectorDailyReceipt( scenario.run, receipt)) ;
	LocalCollectorReservationFacts facts ;										// 本文を持たない公開結果。
	const auto					   before = reservationFiles( scenario.root) ;	// Lockも含む全byte。
	const auto					   sends  = scenario.http.sends ;				// 偽transportの開始回数。
	// 一つのroot/原receiptを同期借用し、前後の全file不変を各呼出しで検査する。
	const auto					   verify = [&]( const std::string &raw, const Mode mode,
							const std::wstring_view expected) {
		const auto saved = reservationFiles( scenario.root) ;	// 今回呼出しの直前。
		const auto code = verifyLocalCollectorDailyReservation( scenario.root, manifest, raw, mode,
																				   facts, scenario.hooks) ;	// 非変更。
		DRIVERCRATE_EXPECT( context, (code == 0U) == expected.empty() && facts.reason == expected) ;
		DRIVERCRATE_EXPECT( context, reservationFiles( scenario.root) == saved &&
															scenario.http.sends == sends) ;
		// 失敗から部分世代/hashを返さない。
		if( code != 0U) {
			DRIVERCRATE_EXPECT( context, facts.generation == 0U && facts.receiptSha256.empty()) ;
		}
	} ;
	verify( receipt, Mode::FRESH_INPUT, L"") ;
	DRIVERCRATE_EXPECT( context, facts.generation == 4U && facts.receiptSha256.size() == 64U &&
									reservationFiles( scenario.root) == before) ;
	verify( receipt, Mode::LEGACY_FENCE, L"") ;
	verify( receipt + " ", Mode::FRESH_INPUT, L"DAILY_RESERVATION_RECEIPT") ;
	const auto trustedClock = scenario.hooks.utcSeconds ;	// 元の固定時計を保持する。
	// 観測より一秒前へ時計を戻す。
	scenario.hooks.utcSeconds = [] { return 1790294399ULL ; } ;
	verify( receipt, Mode::FRESH_INPUT, L"DAILY_RESERVATION_TIME") ;
	scenario.hooks.utcSeconds = trustedClock ;
	verify( "{\"schema\":\"duplicate\"," + receipt.substr( 1U), Mode::FRESH_INPUT,
		   L"DAILY_RESERVATION_RECEIPT") ;
	verify( receipt, static_cast<Mode>( 17), L"DAILY_RESERVATION_RECEIPT") ;
	// 各fieldを一つずつ変え、元予約を上書きせず厳密拒否する。
	for( const auto field :
		{L"manifestSha256", L"source", L"previousReceiptSha256", L"contractSha256", L"bodySha256",
		 L"projectionSha256", L"requestBindingSha256", L"bodyBytesBase64", L"projectionBytesBase64",
		 L"day"}) {
		auto changed = Object::Parse( winrt::to_hstring( receipt)) ;	// 個別の所有copy。
		changed.Insert( field, Value::CreateStringValue( std::wstring_view( field) == L"day"
														   ? L"99999999"
														   : std::wstring( 64U, L'0'))) ;
		const std::wstring_view name( field) ;	// 期待する最初の拒否境界。
		const auto				expected = name == L"contractSha256"
											   ? L"DAILY_RESERVATION_CONTRACT"
											   : (name == L"manifestSha256" || name == L"source" ||
											  name == L"previousReceiptSha256"
													  ? L"DAILY_RESERVATION_BINDING"
													  : L"DAILY_RESERVATION_HEAD") ;	// 原headを保持する。
		verify( winrt::to_string( changed.Stringify()), Mode::FRESH_INPUT, expected) ;
	}

	// 時刻と成功状態の型・順序を有限variantで検査する。
	for( const auto field :
		{L"generation", L"httpStatus", L"error", L"stateError", L"lastAttemptAt", L"notBefore"}) {
		auto changed = Object::Parse( winrt::to_hstring( receipt)) ;	// boolを数値へ暗黙昇格しない。
		changed.Insert( field, Value::CreateBooleanValue( true)) ;
		const std::wstring_view name( field) ;	// 時刻か成功bindingかを区別する。
		verify( winrt::to_string( changed.Stringify()), Mode::FRESH_INPUT,
			   name == L"lastAttemptAt" || name == L"notBefore" ? L"DAILY_RESERVATION_TIME"
																: L"DAILY_RESERVATION_BINDING") ;
	}

	scenario.offsetSeconds = 86400U ;
	verify( receipt, Mode::FRESH_INPUT, L"DAILY_RESERVATION_TIME") ;
	verify( receipt, Mode::LEGACY_FENCE, L"") ;
	scenario.offsetSeconds = 0U ;
	{
		LocalCollectorStateStore locked ;	// 同じ既存writerとの競合だけを再現する。
		DRIVERCRATE_EXPECT( context, locked.initializeExistingWriter( scenario.root) == 0U) ;
		DRIVERCRATE_EXPECT( context, verifyLocalCollectorDailyReservation(
										scenario.root, manifest, receipt, Mode::FRESH_INPUT, facts,
										scenario.hooks) != 0U &&
										facts.reason == L"DAILY_RESERVATION_STORE") ;
	}
	DRIVERCRATE_EXPECT( context, reservationFiles( scenario.root) == before) ;
	const auto head =
		// 故障後も原byteを保持する。
		scenario.read( L"current/daily-generation-v1.json") ;
	// 外側hashが正しいheadでも別世代・別receiptを受理しない。
	for( const bool changeGeneration : {true, false}) {
		const auto wrapper = Object::Parse( winrt::to_hstring( head)) ;			// 元envelopeの所有参照。
		auto changedHead   = Object::Parse( wrapper.GetNamedString( L"body")) ;	// 一fieldだけ変える。
		// 自己申告の新世代から原予約を発行しない。
		if( changeGeneration) {
			changedHead.Insert( L"generation", Value::CreateNumberValue( 5.0)) ;
		} else {
			changedHead.Insert( L"receiptSha256", Value::CreateStringValue( std::wstring( 64U, L'0'))) ;
		}

		scenario.write( L"current/daily-generation-v1.json", fixtureEnvelope( changedHead)) ;
		verify( receipt, Mode::FRESH_INPUT, L"DAILY_RESERVATION_HEAD") ;
	}

	// 原byteの自己hashとheadだけが一致しても、保存runにない本文を受理しない。
	auto changedReceipt = Object::Parse( winrt::to_hstring( receipt)) ;	// 一field故障の所有copy。
	changedReceipt.Insert( L"bodyBytesBase64", Value::CreateStringValue( L"AA==")) ;
	const auto changedBytes =
		// 原serializerと同形式。
		winrt::to_string( changedReceipt.Stringify()) ;
	std::wstring changedHash ;	// 故障byteの正しい自己hash。
	DRIVERCRATE_EXPECT( context, computeBytesSha256( changedBytes, changedHash) == 0U) ;
	const auto headWrapper = Object::Parse( winrt::to_hstring( head)) ;			// 元世代4のenvelope。
	auto matchingHead = Object::Parse( headWrapper.GetNamedString( L"body")) ;	// 世代は変更しない。
	matchingHead.Insert( L"receiptSha256", Value::CreateStringValue( changedHash)) ;
	scenario.write( L"current/daily-generation-v1.json", fixtureEnvelope( matchingHead)) ;
	verify( changedBytes, Mode::FRESH_INPUT, L"DAILY_RESERVATION_RECEIPT") ;
	scenario.write( L"current/daily-generation-v1.json", "{}") ;
	verify( receipt, Mode::FRESH_INPUT, L"DAILY_RESERVATION_STORE") ;
	scenario.write( L"current/daily-generation-v1.json", head) ;
	scenario.write( L"current/unknown.json", "{}") ;
	verify( receipt, Mode::FRESH_INPUT, L"DAILY_RESERVATION_STORE") ;
	DRIVERCRATE_EXPECT( context,
					   DeleteFileW( (scenario.root / L"current/unknown.json").c_str()) != FALSE) ;
	DRIVERCRATE_EXPECT( context,
					   DeleteFileW( (scenario.root / L"current/daily-generation-v1.json").c_str()) !=
						   FALSE) ;
	verify( receipt, Mode::FRESH_INPUT, L"DAILY_RESERVATION_STORE") ;
	scenario.write( L"current/daily-generation-v1.json", head) ;
	const auto missing = fixtureRoot() ;	// 作成しない別の人工path。
	DRIVERCRATE_EXPECT( context, verifyLocalCollectorDailyReservation( missing, manifest, receipt,
																	 Mode::FRESH_INPUT, facts,
																	 scenario.hooks) != 0U &&
									!std::filesystem::exists( missing)) ;
	// 保護fixture内だけで、別旧契約の正しいrequest/射影/run/pointer/receipt鎖を構成する。
	auto legacyRun			 = scenario.run ;	// 現在契約の原成功から独立した人工過去契約。
	legacyRun.contractSha256 = std::wstring( 64U, L'c') ;
	const auto *definition =
		// 固定公式定義。
		officialSourceDefinition( OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11) ;
	DRIVERCRATE_EXPECT( context, definition != nullptr) ;
	// 定義がなければ安全な旧契約fixtureを生成できない。
	if( definition == nullptr) {
		return ;
	}

	Object identity ;	// 旧validatorと同じ順序の非通信request結合。
	identity.Insert( L"target", Value::CreateStringValue( scenario.targets.front().keySha256)) ;
	identity.Insert( L"contract", Value::CreateStringValue( legacyRun.contractSha256)) ;
	identity.Insert( L"provider", Value::CreateStringValue( definition->providerId)) ;
	identity.Insert( L"resource", Value::CreateStringValue( OFFICIAL_LANDING_RESOURCE_ID)) ;
	identity.Insert( L"url", Value::CreateStringValue( definition->landingUrl)) ;
	DRIVERCRATE_EXPECT( context,
					   computeBytesSha256( winrt::to_string( identity.Stringify()),
										  legacyRun.targets.front().requestBindingSha256) == 0U) ;
	const auto originalJson = Object::Parse( winrt::to_hstring( receipt)) ;	// 原record配列を保持する。
	Object	   projection ;													// 元body/fetchと新旧契約bindingの正しい結合。
	projection.Insert( L"requestBindingSha256",
					  Value::CreateStringValue( legacyRun.targets.front().requestBindingSha256)) ;
	projection.Insert( L"bodySha256",
					  Value::CreateStringValue( legacyRun.targets.front().bodySha256)) ;
	projection.Insert( L"lastFetchedAt", Value::CreateNumberValue( static_cast<double>(
											legacyRun.targets.front().lastFetchedAt))) ;
	projection.Insert( L"records", originalJson.GetNamedArray( L"records")) ;
	DRIVERCRATE_EXPECT( context,
					   computeBytesSha256( winrt::to_string( projection.Stringify()),
										  legacyRun.targets.front().projectionSha256) == 0U) ;
	const auto savedEnvelope =
		// 原保存run。
		Object::Parse( winrt::to_hstring( scenario.read( scenario.path( false)))) ;
	auto savedRun =
		// 変更対象は自作copyだけ。
		Object::Parse( savedEnvelope.GetNamedString( L"body")) ;
	savedRun.Insert( L"contractSha256", Value::CreateStringValue( legacyRun.contractSha256)) ;
	auto savedTarget = savedRun.GetNamedArray( L"targets").GetObjectAt( 0U) ;	// 同じ一対象。
	savedTarget.Insert( L"requestBindingSha256",
					   Value::CreateStringValue( legacyRun.targets.front().requestBindingSha256)) ;
	savedTarget.Insert( L"projectionSha256",
					   Value::CreateStringValue( legacyRun.targets.front().projectionSha256)) ;
	std::wstring savedRunHash ;	// 変更後の正しいrun hash。
	DRIVERCRATE_EXPECT(
		context, computeBytesSha256( winrt::to_string( savedRun.Stringify()), savedRunHash) == 0U) ;
	const auto pointerEnvelope =
		// 原pointer。
		Object::Parse( winrt::to_hstring( scenario.read( scenario.path( true)))) ;
	auto pointer =
		// 新しい旧契約専用pointer。
		Object::Parse( pointerEnvelope.GetNamedString( L"body")) ;
	pointer.Insert( L"contractSha256", Value::CreateStringValue( legacyRun.contractSha256)) ;
	pointer.Insert( L"runSha256", Value::CreateStringValue( savedRunHash)) ;
	const auto suffix = manifest + L"-" + legacyRun.contractSha256 + L".json" ;	// 別契約の固定名。
	scenario.write( std::filesystem::path( L"runs") / (legacyRun.day + L"-" + suffix),
				   fixtureEnvelope( savedRun)) ;
	scenario.write( std::filesystem::path( L"current") / suffix, fixtureEnvelope( pointer)) ;
	std::string legacyReceipt ;	// 旧契約を原serializerで正しく拘束する。
	DRIVERCRATE_EXPECT( context, makeLocalCollectorDailyReceipt( legacyRun, legacyReceipt)) ;
	std::wstring legacyHash ;	// 正しい原receipt全byte hash。
	DRIVERCRATE_EXPECT( context, computeBytesSha256( legacyReceipt, legacyHash) == 0U) ;
	Object legacyHead ;	// 人工旧予約の最大世代だけ。
	legacyHead.Insert( L"schema", Value::CreateStringValue( L"dc-collector-daily-generation-v1")) ;
	legacyHead.Insert( L"generation", Value::CreateNumberValue( 4.0)) ;
	legacyHead.Insert( L"receiptSha256", Value::CreateStringValue( legacyHash)) ;
	scenario.write( L"current/daily-generation-v1.json", fixtureEnvelope( legacyHead)) ;
	verify( legacyReceipt, Mode::FRESH_INPUT, L"DAILY_RESERVATION_CONTRACT") ;
	verify( legacyReceipt, Mode::LEGACY_FENCE, L"") ;
	scenario.offsetSeconds = 86400U ;
	verify( legacyReceipt, Mode::LEGACY_FENCE, L"") ;
	DRIVERCRATE_EXPECT( context, DeleteFileW( (scenario.root / L"collector.lock").c_str()) != FALSE) ;
	verify( legacyReceipt, Mode::LEGACY_FENCE, L"DAILY_RESERVATION_STORE") ;
	DRIVERCRATE_EXPECT( context, !std::filesystem::exists( scenario.root / L"collector.lock")) ;
	CollectorScenario revalidation( context, {targets[1]}, manifest) ;	// 304だけの独立人工root。
	revalidation.http.body = dailyIntelPage() ;
	activeFixture		   = &revalidation.http ;
	DRIVERCRATE_EXPECT( context, runLocalDriverCollectorWithHooks(
									revalidation.root, revalidation.targets, manifest, false,
									revalidation.hooks, revalidation.run, false, true) == 0) ;
	++revalidation.day ;
	revalidation.http.status = 304U ;
	DRIVERCRATE_EXPECT( context, runLocalDriverCollectorWithHooks(
									revalidation.root, revalidation.targets, manifest, false,
									revalidation.hooks, revalidation.run, false, true) == 0) ;
	std::string receipt304 ;	// 元fetchを保持する新validationの原byte。
	DRIVERCRATE_EXPECT( context, makeLocalCollectorDailyReceipt( revalidation.run, receipt304)) ;
	const auto before304 = reservationFiles( revalidation.root) ;	// 新世代5の完全snapshot。
	DRIVERCRATE_EXPECT(
		context,
		verifyLocalCollectorDailyReservation( revalidation.root, manifest, receipt304,
											 Mode::FRESH_INPUT, facts, revalidation.hooks) == 0U &&
			facts.generation == 5U && reservationFiles( revalidation.root) == before304 &&
			revalidation.http.sends == 2U) ;
	std::cout
		<< "DAILY_RESERVATION_FINITE completed=1 root_unchanged=1 network=0 reserve=0 key=0\n" ;
}

} // namespace
} // namespace drivercrate::test

/** @brief 作成・削除範囲を限定した非通信fixtureを起動します。 */
int main()
{
	drivercrate::test::TestContext context ;
	std::filesystem::path		   first ;
	std::filesystem::path		   second ;
	std::filesystem::path		   third ;	// 条件付き取得専用の一時root。
	try {
		// 通常のmanifest parserを通した公開target二件。
		std::vector<drivercrate::LocalCollectorTarget> targets ;
		// manifest実byte SHA-256。
		std::wstring								   manifest ;
		drivercrate::test::loadTargets( targets, manifest) ;
		first  = drivercrate::test::fixtureRoot() ;
		second = drivercrate::test::fixtureRoot() ;
		third  = drivercrate::test::fixtureRoot() ;
		drivercrate::test::conditionalHttp( context) ;
		drivercrate::test::crossDayResume( context, first, targets, manifest) ;
		drivercrate::test::injectedHttpFailure( context, second, targets, manifest) ;
		drivercrate::test::conditionalRuns( context, third, targets, manifest) ;
		drivercrate::test::recoveryScenarios( context, targets, manifest) ;
		drivercrate::test::cooldownScenarios( context, targets, manifest) ;
		drivercrate::test::retentionScenarios( context, targets, manifest) ;
		drivercrate::test::corruptionScenarios( context, targets, manifest) ;
		drivercrate::test::campaignModeScenarios( context, targets, manifest) ;
		drivercrate::test::legacyInspection( context, targets, manifest) ;
		drivercrate::test::legacyEnrollment( context, targets, manifest) ;
		drivercrate::test::legacyChangedAfterEnrollment( context, targets, manifest) ;
		drivercrate::test::legacyEnrollmentCapacity( context, targets, manifest) ;
		drivercrate::test::legacyExportScenarios( context, targets, manifest) ;
		drivercrate::test::dailyReceiptScenarios( context, targets, manifest) ;
		drivercrate::test::dailyReservationScenarios( context, targets, manifest) ;
		drivercrate::test::cleanupFixture( first) ;
		drivercrate::test::cleanupFixture( second) ;
		drivercrate::test::cleanupFixture( third) ;
	} catch( const std::exception &error) {
		std::cerr << "Fixture exception: " << error.what() << '\n' ;
		context.expect( false, "collector run fixture exception", __FILE__, __LINE__) ;
		// 条件付きfixtureの自作rootだけを回収する。
		if( !third.empty()) {
			try {
				drivercrate::test::cleanupFixture( third) ;
			} catch( ...) {
			}
		}

		// 自作rootが確定した場合だけ後始末を試みる。
		if( !first.empty()) {
			try {
				drivercrate::test::cleanupFixture( first) ;
			} catch( ...) {
			}
		}

		// 二番目も自作rootが確定した場合だけ後始末する。
		if( !second.empty()) {
			try {
				drivercrate::test::cleanupFixture( second) ;
			} catch( ...) {
			}
		}
	}

	std::cout << "Collector run tests: " << context.assertionCount() << " assertions, "
			  << context.failureCount() << " failures\n" ;
	return context.failureCount() == 0U ? 0 : 1 ;
}
