//------------------------------------------------------------------------------
/**
 * @file app_update_tests.cpp
 * @brief App更新の版/JSON/worker/完全fake HTTPを確認します。
 * @version 01.00.00
 * @date 2026/11/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/11  App専用の通知付き更新を追加。
 * </pre>
 * @note 実network・署名鍵・driver操作・Setup実行を行いません。
 * @see docs/adr/0481-app-inno-setup-and-update-checks.md
 */
//------------------------------------------------------------------------------
#include "core/app_update.h"
#include "platform/app_update_service_internal.h"
#include "platform/official_file_verifier.h"
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace {
using namespace drivercrate ;
unsigned assertions{} ;	// 固定期待の分母です。
unsigned failures{} ;	// 失敗を後続成功で隠しません。
/** @brief 固定期待を集計します。
 * @param[in] value 期待成立値です。
 */
void	 expect( const bool value)
{
	++assertions ;
	// assertion位置だけを出力します。
	if( !value) {
		++failures ;
		std::printf( "FAIL assertion=%u\n", assertions) ;
	}
}
/** @brief 正常な架空Setup宣言を作ります。
 * @return 非実行payloadのhashを持つ値です。
 */
AppUpdateRelease sample()
{
	const std::string bytes = "synthetic setup bytes" ;	// 署名や実行物ではありません。
	std::wstring	  hash ;							// fixture byteの完全digestです。
	expect( computeBytesSha256( bytes, hash) == 0) ;
	std::string ascii ;	// SHAのASCII hexだけを明示して変換します。
	// 検査済みhexの各文字をnarrowingします。
	for( const wchar_t digit : hash) {
		ascii.push_back( static_cast<char>( digit)) ;
	}

	return {{{1U, 0U, 5U}}, bytes.size(), ascii} ;
}
/** @brief 一assetだけの架空GitHub JSONを作ります。
 * @param[in] release 正常な架空宣言です。
 * @return 固定repo/tag/assetのJSONです。
 */
std::string metadata( const AppUpdateRelease &release)
{
	return "{\"tag_name\":\"v" + formatAppVersion( release.version) +
		   "\",\"draft\":false,\"prerelease\":false,\"assets\":[{\"name\":\"DriverCrateSetup-windows-x64.exe\","
		   "\"state\":\"uploaded\",\"size\":" +
		   std::to_string( release.sizeBytes) + ",\"digest\":\"sha256:" + release.sha256 +
		   "\",\"browser_download_url\":\"https://github.com/EnterOgawa/drivercrate/releases/download/v" +
		   formatAppVersion( release.version) + "/DriverCrateSetup-windows-x64.exe\"}]}" ;
}
/** @brief 一箇所だけの入力破損を作ります。
 * @param[in] text 元の架空JSONです。
 * @param[in] from 置換対象です。
 * @param[in] to 不正な値です。
 * @return 置換後のJSONです。
 */
std::string changed( std::string text, std::string_view from, std::string_view to)
{
	const auto position = text.find( from) ;	// 一意の対象位置です。
	expect( position != std::string::npos) ;
	// 試験の誤りで範囲外を書きません。
	if( position != std::string::npos) {
		text.replace( position, from.size(), to) ;
	}

	return text ;
}
/** @brief 版とJSONの正常/拒否境界を確認します。 */
void policy()
{
	const AppVersion current{{1U, 0U, 4U}} ;	// 架空の元版です。
	expect( parseAppVersion( "1.0.5") == AppVersion{{1U, 0U, 5U}}) ;
	const std::vector<std::string> invalid{
		"",		  "1",		   "1.2",		"1.2.3.0",	  "01.2.3", "1.02.3", "1.2.03",
		"-1.2.3", "1.2.65536", "65536.0.1", "1.2.3-beta", " 1.2.3", "1.2.3 "} ;	// 固定の負例です。
	// 各不足/過大を同じ入口へ通します。
	for( const auto &text : invalid) {
		expect( !parseAppVersion( text)) ;
	}

	expect( *parseAppVersion( "1.10.0") > *parseAppVersion( "1.9.65535")) ;
	const auto						release = sample() ;			// 正常宣言です。
	const auto						raw		= metadata( release) ;	// 元JSONです。
	std::optional<AppUpdateRelease> offered ;						// parserの所有出力です。
	expect( parseAppUpdateReleaseJson( raw, current, offered).kind == AppUpdateFailureKind::NONE &&
		   offered == release) ;
	expect( parseAppUpdateReleaseJson( raw, release.version, offered).kind ==
			   AppUpdateFailureKind::NONE &&
		   !offered) ;
	expect( parseAppUpdateReleaseJson(
			   "{\"tag_name\":\"v1.0.4\",\"draft\":false,\"prerelease\":false}", current, offered)
				   .kind == AppUpdateFailureKind::NONE &&
		   !offered) ;
	const std::vector<std::pair<std::string, std::string>> corrupt{
		{"\"draft\":false", "\"draft\":true"},
		{"\"prerelease\":false", "\"prerelease\":true"},
		{"v1.0.5", "v01.0.5"},
		{"\"assets\":[", "\"assets\":null,\"ignored\":["},
		{"\"size\":" + std::to_string( release.sizeBytes), "\"size\":0"},
		{"\"size\":" + std::to_string( release.sizeBytes), "\"size\":134217729"},
		{"\"size\":" + std::to_string( release.sizeBytes), "\"size\":1.5"},
		{"\"state\":\"uploaded\"", "\"state\":\"new\""},
		{"\"digest\":\"sha256:", "\"digest\":\"sha512:"},
		{"\"name\":\"DriverCrateSetup-windows-x64.exe\"", "\"name\":\"Other.exe\""},
		{"https://github.com/EnterOgawa/drivercrate/releases/",
		 "https://github.com/Other/drivercrate/releases/"}} ;	// 一条件だけを壊す負例です。
	// 各失敗後にも出力が空になることを確認します。
	for( const auto &[from, to] : corrupt) {
		expect( parseAppUpdateReleaseJson( changed( raw, from, to), current, offered).kind ==
				   AppUpdateFailureKind::METADATA &&
			   !offered) ;
	}

	const auto first	 = raw.find( "[") ;	// 元asset配列の先頭です。
	const auto duplicate = raw.substr( 0U, raw.size() - 2U) + "," +
						   raw.substr( first + 1U, raw.size() - first - 3U) +
						   "]}" ;	// 正確assetを二つにします。
	expect( parseAppUpdateReleaseJson( duplicate, current, offered).kind ==
		   AppUpdateFailureKind::METADATA) ;
	expect( parseAppUpdateReleaseJson( std::string( 262145U, ' '), current, offered).kind ==
		   AppUpdateFailureKind::METADATA) ;
	expect( parseAppUpdateReleaseJson( std::string( "\xc0\xaf"), current, offered).kind ==
		   AppUpdateFailureKind::METADATA) ;
	AppUpdateSchedule schedule ;	// fakeの単調時計です。
	expect( schedule.due( 100U)) ;
	schedule.attempted( 100U) ;
	// 逆行は新しい24hへ送ります。
	expect( !schedule.due( 99U)) ;
	expect( !schedule.due( 99U + APP_UPDATE_INTERVAL_MS - 1U)) ;
	expect( schedule.due( 99U + APP_UPDATE_INTERVAL_MS)) ;
	schedule.attempted( 5U * APP_UPDATE_INTERVAL_MS) ;
	expect( !schedule.due( 5U * APP_UPDATE_INTERVAL_MS + 1U)) ;
}
/** @brief workerの明示同意/停止の共有観測です。 */
struct WorkerState {
	/// 実行した確認数です。
	std::atomic_uint checks{} ;
	/// 明示同意後だけ増える取得数です。
	std::atomic_uint downloads{} ;
	/// ready後だけ増える引継ぎ数です。
	std::atomic_uint launches{} ;
	/// 取消しを試す有限待機です。
	std::atomic_bool hold{} ;
} ;
/** @brief workerを完全な非通信I/Oで動かします。 */
class Backend final : public AppUpdateBackend {
public:
	/** @brief 非機密counterだけを共有します。
	 * @param[in] state workerより長生きする状態です。
	 */
	explicit Backend( std::shared_ptr<WorkerState> state) : state_( std::move( state))
	{
	}
	/** @brief 架空の新版を返します。
	 * @param[in] cancel 元の取消しです。
	 * @return 架空の一件です。
	 */
	AppUpdateEvent check( const AppUpdateCancellation &cancel) noexcept override
	{
		++state_->checks ;
		// 取消しが到達するまでだけ有限に待ちます。
		for( unsigned count{}; state_->hold && !cancel() && count < 3000U; ++count) {
			Sleep( 1U) ;
		}

		AppUpdateEvent result ;	// 共有resourceを含みません。
		result.release = AppUpdateRelease{{{1U, 0U, 5U}}, 2U, std::string( 64U, 'a')} ;
		return result ;
	}
	/** @brief 明示取得だけを数えます。
	 * @param[in] release 元の宣言です。
	 * @param[in] cancel 元の取消しです。
	 * @return 固定成功です。
	 */
	AppUpdateFailure download( const AppUpdateRelease	  &release,
							  const AppUpdateCancellation &cancel) noexcept override
	{
		static_cast<void>( release) ;
		static_cast<void>( cancel) ;
		++state_->downloads ;
		return {} ;
	}
	/** @brief 起動失敗を注入し、元App維持を確認します。
	 * @param[in] release 元の宣言です。
	 * @param[in] cancel 元の取消しです。
	 * @return 固定の起動失敗です。
	 */
	AppUpdateFailure launch( const AppUpdateRelease		&release,
							const AppUpdateCancellation &cancel) noexcept override
	{
		static_cast<void>( release) ;
		static_cast<void>( cancel) ;
		++state_->launches ;
		return {AppUpdateFailureKind::LAUNCH, E_ACCESSDENIED, 0U, 0U} ;
	}

private:
	/// 両threadの非機密counterだけです。
	std::shared_ptr<WorkerState> state_ ;
} ;
/** @brief 一結果を有限時間だけ待ちます。
 * @param[in,out] service 試験するworkerです。
 * @return 受信した結果。不達は失敗分類です。
 */
AppUpdateEvent wait( AppUpdateService &service)
{
	// 同期API待機を含まないfixtureを最大3秒で終えます。
	for( unsigned count{}; count < 3000U; ++count) {
		auto event = service.takeEvent() ;	// 所有結果だけを一回取得します。
		// 結果が届いた時点で終了します。
		if( event) {
			return *event ;
		}

		Sleep( 1U) ;
	}

	expect( false) ;
	return {AppUpdateStage::IDLE, {AppUpdateFailureKind::NETWORK, E_FAIL, 0U, 0U}, {}, false} ;
}
/** @brief 二重要求/同意前0/見送り/明示再確認/取消しを確認します。 */
void worker()
{
	auto			 state = std::make_shared<WorkerState>() ;					// thread停止まで共有します。
	AppUpdateService service( nullptr, 0U, std::make_unique<Backend>( state)) ;	// HWNDは使いません。
	expect( !service.requestDownload() && !service.requestLaunch()) ;
	expect( service.requestCheck( false)) ;
	expect( !service.requestCheck( true)) ;
	expect( wait( service).release.has_value() && state->downloads == 0U && state->launches == 0U) ;
	service.dismiss() ;
	expect( service.requestCheck( false)) ;
	expect( !wait( service).release && state->downloads == 0U) ;
	expect( service.requestCheck( true)) ;
	expect( wait( service).release.has_value()) ;
	expect( service.requestDownload()) ;
	expect( wait( service).failure.kind == AppUpdateFailureKind::NONE &&
		   service.stage() == AppUpdateStage::READY) ;
	expect( state->downloads == 1U && state->launches == 0U) ;
	expect( service.requestLaunch()) ;
	expect( wait( service).failure.kind == AppUpdateFailureKind::LAUNCH && state->launches == 1U) ;
	expect( service.stage() == AppUpdateStage::IDLE && !service.requestLaunch()) ;
	state->hold = true ;
	expect( service.requestCheck( true)) ;
	service.cancel() ;
	expect( wait( service).failure.kind == AppUpdateFailureKind::CANCELLED) ;
	service.stop() ;
	expect( !service.requestCheck( true)) ;
}
/** @brief fake HTTPの一応答です。 */
struct Response {
	/// 元statusです。
	DWORD		 status{200U} ;
	/// MIMEです。
	std::wstring mime{L"application/json; charset=utf-8"} ;
	/// 原bodyです。
	std::string	 body ;
	/// 元Locationです。
	std::wstring location ;
	/// 元Retry-Afterです。
	std::wstring retry ;
} ;
/** @brief 全WinHTTPを非通信で置換する所有状態です。 */
struct HttpState {
	/// 順に返す応答です。
	std::vector<Response>	  responses ;
	/// 実送信数です。
	unsigned				  sends{} ;
	/// 現bodyの読取位置です。
	std::size_t				  offset{} ;
	/// 実connect先です。試験中のRAMだけに保持します。
	std::vector<std::wstring> hosts ;
	/// private宛先を返す拒否例です。
	bool					  privateAddress{} ;
} ;
/** @brief 同期fixtureだけに有効な完全I/Oの参照です。 */
thread_local HttpState *active{} ;
/** @brief 非通信のsessionを返します。
 * @param[in] agent 固定識別子です。
 * @param[in] access proxy modeです。
 * @param[in] proxy 未使用です。
 * @param[in] bypass 未使用です。
 * @param[in] flags 未使用です。
 * @return fake handleです。
 */
HINTERNET WINAPI open( LPCWSTR agent, DWORD access, LPCWSTR proxy, LPCWSTR bypass, DWORD flags)
{
	static_cast<void>( agent) ;
	static_cast<void>( access) ;
	static_cast<void>( proxy) ;
	static_cast<void>( bypass) ;
	static_cast<void>( flags) ;
	return active ;
}
/** @brief 実connect先だけを観測します。
 * @param[in] session fake handleです。
 * @param[in] host 検証済みhostです。
 * @param[in] port HTTPS portです。
 * @param[in] reserved 未使用です。
 * @return fake handleです。
 */
HINTERNET WINAPI connect( HINTERNET session, LPCWSTR host, INTERNET_PORT port, DWORD reserved)
{
	static_cast<void>( session) ;
	static_cast<void>( reserved) ;
	expect( port == 443U) ;
	active->hosts.emplace_back( host) ;
	return active ;
}
/** @brief GETだけのfake requestを返します。
 * @param[in] connection fake handleです。
 * @param[in] verb 固定GETです。
 * @param[in] object 固定pathです。
 * @param[in] version 未使用です。
 * @param[in] referer 未使用です。
 * @param[in] accept 未使用です。
 * @param[in] flags HTTPS flagです。
 * @return fake handleです。
 */
HINTERNET WINAPI request( HINTERNET connection, LPCWSTR verb, LPCWSTR object, LPCWSTR version,
						 LPCWSTR referer, LPCWSTR *accept, DWORD flags)
{
	static_cast<void>( connection) ;
	static_cast<void>( object) ;
	static_cast<void>( version) ;
	static_cast<void>( referer) ;
	static_cast<void>( accept) ;
	expect( std::wstring_view( verb) == L"GET" && (flags & WINHTTP_FLAG_SECURE) != 0U) ;
	return active ;
}
/** @brief finite timeoutを受理します。
 * @param[in] handle fake handleです。
 * @param[in] resolve 正のtimeoutです。
 * @param[in] connection 正のtimeoutです。
 * @param[in] send 正のtimeoutです。
 * @param[in] receive 正のtimeoutです。
 * @return TRUEです。
 */
BOOL WINAPI timeouts( HINTERNET handle, int resolve, int connection, int send, int receive)
{
	static_cast<void>( handle) ;
	expect( resolve > 0 && connection > 0 && send > 0 && receive > 0) ;
	return TRUE ;
}
/** @brief option設定を受理します。
 * @param[in] handle fake handleです。
 * @param[in] option 固定optionです。
 * @param[in] value 借用値です。
 * @param[in] size 借用byte数です。
 * @return TRUEです。
 */
BOOL WINAPI option( HINTERNET handle, DWORD option, LPVOID value, DWORD size)
{
	static_cast<void>( handle) ;
	static_cast<void>( option) ;
	static_cast<void>( value) ;
	static_cast<void>( size) ;
	return TRUE ;
}
/** @brief 固定headerを受理します。
 * @param[in] handle fake handleです。
 * @param[in] value 固定headerです。
 * @param[in] size 文字数です。
 * @param[in] flags 固定flagです。
 * @return TRUEです。
 */
BOOL WINAPI headers( HINTERNET handle, LPCWSTR value, DWORD size, DWORD flags)
{
	static_cast<void>( handle) ;
	static_cast<void>( value) ;
	static_cast<void>( size) ;
	static_cast<void>( flags) ;
	return TRUE ;
}
/** @brief 各応答の先頭へ進めます。
 * @param[in] handle fake handleです。
 * @param[in] headers 固定headerです。
 * @param[in] headerSize 文字数です。
 * @param[in] data GETではnullです。
 * @param[in] length GETでは0です。
 * @param[in] total GETでは0です。
 * @param[in] context 未使用です。
 * @return 応答があればTRUEです。
 */
BOOL WINAPI send( HINTERNET handle, LPCWSTR headers, DWORD headerSize, LPVOID data, DWORD length,
				 DWORD total, DWORD_PTR context)
{
	static_cast<void>( handle) ;
	static_cast<void>( headers) ;
	static_cast<void>( headerSize) ;
	static_cast<void>( data) ;
	static_cast<void>( length) ;
	static_cast<void>( total) ;
	static_cast<void>( context) ;
	++active->sends ;
	active->offset = 0U ;
	return active->sends <= active->responses.size() ;
}
/** @brief 応答開始を受理します。
 * @param[in] handle fake handleです。
 * @param[in] reserved 未使用です。
 * @return TRUEです。
 */
BOOL WINAPI receive( HINTERNET handle, LPVOID reserved)
{
	static_cast<void>( handle) ;
	static_cast<void>( reserved) ;
	return TRUE ;
}
/** @brief 同名一件の有限headerを返します。
 * @param[in] handle fake handleです。
 * @param[in] level header selectorです。
 * @param[in] name 未使用です。
 * @param[out] buffer 要求された値です。
 * @param[in,out] size byte容量/実長です。
 * @param[in,out] index 同名headerの位置です。
 * @return 本読取り成功ならTRUEです。
 */
BOOL WINAPI query( HINTERNET handle, DWORD level, LPCWSTR name, LPVOID buffer, LPDWORD size,
				  LPDWORD index)
{
	static_cast<void>( handle) ;
	static_cast<void>( name) ;
	const auto &response = active->responses.at( active->sends - 1U) ;	// 同応答です。
	const DWORD kind	 = level & 0xffffU ;							// 固定selectorです。
	// 数値statusだけをそのまま返します。
	if( kind == WINHTTP_QUERY_STATUS_CODE && (level & WINHTTP_QUERY_FLAG_NUMBER) != 0U) {
		*static_cast<DWORD *>( buffer) = response.status ;
		*size						  = sizeof( DWORD) ;
		return TRUE ;
	}

	std::wstring value ;	// 対象headerだけです。
	// 必要な固定header以外を欠損として返します。
	if( kind == WINHTTP_QUERY_CONTENT_TYPE) {
		value = response.mime ;
	}
	// 厳密なbody実長を宣言します。
	else if( kind == WINHTTP_QUERY_CONTENT_LENGTH) {
		value = std::to_wstring( response.body.size()) ;
	}
	// 有限redirectだけのLocationです。
	else if( kind == WINHTTP_QUERY_LOCATION) {
		value = response.location ;
	}
	// 元の待機headerだけを返します。
	else if( kind == WINHTTP_QUERY_RETRY_AFTER) {
		value = response.retry ;
	}

	// 欠損と同名二件目を明示します。
	if( value.empty() || (index && *index != 0U)) {
		SetLastError( ERROR_WINHTTP_HEADER_NOT_FOUND) ;
		return FALSE ;
	}

	const DWORD needed =
		// 終端込みです。
		static_cast<DWORD>( (value.size() + 1U) * sizeof( wchar_t)) ;
	// 長さprobeではindexを消費しません。
	if( !buffer || *size < needed) {
		*size = needed ;
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	std::memcpy( buffer, value.c_str(), needed) ;
	*size = static_cast<DWORD>( value.size() * sizeof( wchar_t)) ;
	// 本照会成功時だけ次へ進めます。
	if( index) {
		++*index ;
	}

	return TRUE ;
}
/** @brief 残body量だけを返します。
 * @param[in] handle fake handleです。
 * @param[out] count 残byteです。
 * @return TRUEです。
 */
BOOL WINAPI available( HINTERNET handle, LPDWORD count)
{
	static_cast<void>( handle) ;
	*count =
		static_cast<DWORD>( active->responses.at( active->sends - 1U).body.size() - active->offset) ;
	return TRUE ;
}
/** @brief 指定chunkだけを返します。
 * @param[in] handle fake handleです。
 * @param[out] buffer 借用出力です。
 * @param[in] maximum 最大byte数です。
 * @param[out] received 実byte数です。
 * @return TRUEです。
 */
BOOL WINAPI read( HINTERNET handle, LPVOID buffer, DWORD maximum, LPDWORD received)
{
	static_cast<void>( handle) ;
	const auto &body = active->responses.at( active->sends - 1U).body ;	// 現bodyです。
	const auto	count =
		std::min<std::size_t>( maximum, body.size() - active->offset) ;	// 容量内だけです。
	std::memcpy( buffer, body.data() + active->offset, count) ;
	active->offset += count ;
	*received = static_cast<DWORD>( count) ;
	return TRUE ;
}
/** @brief fake handleの解放を受理します。
 * @param[in] handle fake handleです。
 * @return TRUEです。
 */
BOOL WINAPI close( HINTERNET handle)
{
	static_cast<void>( handle) ;
	return TRUE ;
}
/** @brief 全通信をfakeへ置き換えます。
 * @return native DNSを含まない完全I/Oです。
 */
OfficialHttpTransport transport()
{
	OfficialHttpTransport io ;	// 各ABIを完全に置き換えます。
	io.open				  = open ;
	io.connect			  = connect ;
	io.openRequest		  = request ;
	io.setTimeouts		  = timeouts ;
	io.setOption		  = option ;
	io.addHeaders		  = headers ;
	io.sendRequest		  = send ;
	io.receiveResponse	  = receive ;
	io.queryHeaders		  = query ;
	io.queryAvailable	  = available ;
	io.readData			  = read ;
	io.closeHandle		  = close ;
	io.resolveDestination = []( std::wstring_view							host,
							   std::vector<OfficialResolvedNetworkAddress> &addresses) {
		static_cast<void>( host) ;
		OfficialResolvedNetworkAddress address ;	// 固定の公開宛先です。
		address.bytes[0] = active->privateAddress ? std::byte{10} : std::byte{8} ;
		address.bytes[1] = std::byte{8} ;
		address.bytes[2] = std::byte{8} ;
		address.bytes[3] = std::byte{8} ;
		addresses		 = {address} ;
		return static_cast<NativeError>( 0) ;
	} ;
	return io ;
}
/** @brief 一回だけの共通HTTPへfakeを渡します。
 * @param[in,out] state 完全な非通信応答です。
 * @param[out] result 最小結果です。
 * @param[in] cancelled 送信前取消しです。
 * @return 元HTTP結果です。
 */
NativeError get( HttpState &state, app_update_detail::HttpResult &result,
				const bool cancelled = false)
{
	active = &state ;
	OfficialHttpClient	   client( transport()) ;	// cacheは使いません。
	SignedIndexHttpControl control ;				// 他の用途と共有しません。
	control.deadline	 = std::chrono::steady_clock::now() + std::chrono::seconds( 15) ;
	control.monotonicNow = []() {
		return std::chrono::steady_clock::now() ;
	} ; // 完全fixtureも元期限を検証します。
	control.cancellation = [cancelled]() { return cancelled ; } ;
	return app_update_detail::Access::http( client, nullptr, nullptr, control, result) ;
}
/** @brief 固定route/HTTP拒否/取消しとfile保護を確認します。 */
void http()
{
	const auto					  release = sample() ;	// 架空配布物です。
	app_update_detail::HttpResult result ;				// 任意本文を出力しません。
	HttpState					  state ;				// 各例は独立の応答です。
	state.responses = {{200U, L"application/json; charset=utf-8", metadata( release), {}, {}}} ;
	const auto initialCode = get( state, result) ;	// 元のHTTP拒否値を数値で観測します。
	std::printf( "http-initial code=%08x status=%lu sends=%u bytes=%zu\n",
				static_cast<unsigned>( initialCode), result.status, state.sends,
				result.metadata.size()) ;
	expect( initialCode == 0 && result.metadata == metadata( release) && state.sends == 1U) ;
	expect( state.hosts == std::vector<std::wstring>{L"api.github.com"}) ;
	state			= {} ;
	state.responses = {{302U, L"text/html", {}, L"https://github.com/EnterOgawa/drivercrate", {}}} ;
	expect( get( state, result) != 0 && state.sends == 1U) ;
	state			= {} ;
	state.responses = {{429U, L"application/json", {}, {}, L"120"}} ;
	expect( get( state, result) != 0 && result.status == 429U && result.retryAfterSeconds == 120U) ;
	state			= {} ;
	state.responses = {{200U, L"text/html", "<html/>", {}, {}}} ;
	expect( get( state, result) != 0 && result.metadata.empty()) ;
	state			= {} ;
	state.responses = {{200U, L"application/json", std::string( 262145U, ' '), {}, {}}} ;
	expect( get( state, result) != 0 && result.metadata.empty()) ;
	state			= {} ;
	state.responses = {{200U, L"application/json", "{}", {}, {}}} ;
	expect( get( state, result, true) != 0 && state.sends == 0U) ;
	state				 = {} ;
	state.privateAddress = true ;
	state.responses		 = {{200U, L"application/json", "{}", {}, {}}} ;
	expect( get( state, result) != 0 && state.sends == 0U) ;
	std::vector<wchar_t> temporary( 32768U) ;	// Windowsが返すuser tempをheapで所有します。
	const auto			 length =
		// 実長です。
		GetTempPathW( static_cast<DWORD>( temporary.size()), temporary.data()) ;
	expect( length > 0U && length < 32768U) ;
	const auto root = std::filesystem::path( temporary.data()) /
					  (L"DriverCrate-app-update-fixture-" + std::to_wstring( GetCurrentProcessId()) +
					   L"-" + std::to_wstring( GetTickCount64())) ;	// この一回だけの明示scopeです。
	expect( std::filesystem::create_directory( root)) ;
	state			= {} ;
	state.responses = {{200U, L"application/json", metadata( release), {}, {}},
					   {302U,
						L"application/octet-stream",
						{},
						L"https://release-assets.githubusercontent.com/synthetic/setup?test=1",
						{}},
					   {200U, L"application/octet-stream", "synthetic setup bytes", {}, {}}} ;
	active			= &state ;
	unsigned				   verified{} ;	// 完全fake署名境界の回数です。
	unsigned				   launched{} ;	// 実行せず記録します。
	app_update_detail::Fixture fixture ;	// 全I/Oを所有して固定します。
	fixture.appPath	  = root / L"DriverCrate.exe" ;
	fixture.current	  = {{1U, 0U, 4U}} ;
	fixture.transport = transport() ;
	fixture.verify	  = [&]( const std::filesystem::path &path, const AppUpdateRelease &expected) {
		   ++verified ;
		   std::wstring hash ;	// 偽の署名成功でもbyte一致を確認します。
		   expect( computeFileSha256( path.native(), hash) == 0) ;
		   expect( hash == std::wstring( expected.sha256.begin(), expected.sha256.end())) ;
		   return AppUpdateFailure{} ;
	} ;
	fixture.launch = [&]( const std::filesystem::path &path,
						 const std::filesystem::path &directory) {
		++launched ;
		expect( path == root / L".app-update" / L"DriverCrateSetup-windows-x64.exe" &&
			   directory == root) ;
		return AppUpdateFailure{AppUpdateFailureKind::LAUNCH, E_ACCESSDENIED, 0U, 0U} ;
	} ;
	auto backend =
		// nativeへfallbackしません。
		app_update_detail::Access::fixtureBackend( std::move( fixture)) ;
	const auto checked = backend->check( []() { return false ; }) ;	// metadataだけです。
	expect( checked.release == release && state.sends == 1U && verified == 0U) ;
	const auto downloadResult =
		// 元の段階と数値です。
		backend->download( release, []() { return false ; }) ;
	std::printf( "http-download kind=%u code=%08x status=%lu sends=%u\n",
				static_cast<unsigned>( downloadResult.kind),
				static_cast<unsigned>( downloadResult.error), downloadResult.httpStatus,
				state.sends) ;
	expect( downloadResult.kind == AppUpdateFailureKind::NONE) ;
	expect( verified == 1U && launched == 0U && state.sends == 3U) ;
	const auto setup =
		root / L".app-update" / L"DriverCrateSetup-windows-x64.exe" ;	// 保護対象です。
	const HANDLE writer =
		CreateFileW( setup.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
					OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) ;	// 差替えを試します。
	expect( writer == INVALID_HANDLE_VALUE) ;
	// 予想外に開いたhandleも試験自身が閉じます。
	if( writer != INVALID_HANDLE_VALUE) {
		CloseHandle( writer) ;
	}

	expect( backend->launch( release, []() { return false ; }).kind == AppUpdateFailureKind::LAUNCH &&
		   verified == 2U && launched == 1U) ;
	// fixtureのpinを解除してから自己fileだけを消します。
	backend.reset() ;
	const bool owned = root.filename().native().starts_with( L"DriverCrate-app-update-fixture-") &&
					   std::filesystem::equivalent( root.parent_path(),
												   // 同じ解決済みparentを要求します。
												   std::filesystem::path( temporary.data())) ;
	expect( owned) ;
	// 想定外scopeならcleanupも進めません。
	if( !owned) {
		return ;
	}

	expect( std::filesystem::remove( setup)) ;
	expect( std::filesystem::remove( root / L".app-update")) ;
	expect( std::filesystem::remove( root)) ;
	active = nullptr ;
}
}
/** @brief 全て非通信の固定試験だけを実行します。
 * @return 全期待成立時は0です。
 */
int main()
{
	try {
		std::printf( "app-update phase=policy\n") ;
		std::fflush( stdout) ;
		policy() ;
		std::printf( "app-update phase=worker\n") ;
		std::fflush( stdout) ;
		worker() ;
		std::printf( "app-update phase=http\n") ;
		std::fflush( stdout) ;
		http() ;
	} catch( ...) {
		expect( false) ;
	}

	std::printf( "app-update assertions=%u failures=%u\n", assertions, failures) ;
	return failures == 0U ? 0 : 1 ;
}
