//------------------------------------------------------------------------------
/**
 * @file metadata_search_http_tests.cpp
 * @brief 共通HTTPの非通信backendによる情報検索境界試験。
 * @version 01.01.00
 * @date 2026/09/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  固定起点・cache・受信・停止のfake試験を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/09/15  Windows 11 Ethernet固定起点を検証。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  透明な共通User-Agentの完全一致検証を追加。
 * </pre>
 *
 * @note 全I/Oをfixtureへ置換し、実通信・既存cache変更を行わない。
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#include "metadata_search_http_tests.h"

#include "core/metadata_search_budget.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/official_http_client.h"
#include "platform/official_release_metadata.h"
#include "test_framework.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {

/** @brief 一つの同期HTTP要求とcache応答だけを保持する非通信fixture。 */
struct HttpFixture {
	/// Fake応答のstatus。再試行が発生したら送信数で検出する。
	DWORD								  status{200U} ;
	/// Content-Length未指定はchunked相当。実byte長とは独立に指定する。
	std::optional<std::wstring>			  declared ;
	/// 固定応答の本文。実payloadや端末情報を含まない。
	std::string							  body{"metadata"} ;
	/// Fake bodyで次に読み取る位置。
	std::size_t							  offset{} ;
	/// 一度に返すchunkの上限。
	DWORD								  chunk{65536U} ;
	/// Fake session・connection・request生成回数。
	unsigned							  opened{} ;
	/// 同じfake backendで解放したhandle数。
	unsigned							  closed{} ;
	/// SendRequestを実際に呼んだ回数。
	unsigned							  sends{} ;
	/// ReadData呼出し回数。
	unsigned							  reads{} ;
	/// QueryDataAvailable呼出し回数。
	unsigned							  availableCalls{} ;
	/// 四phaseが全て正の有限値ならtrue。
	bool								  finiteTimeouts{true} ;
	/// HTTPS・GET・default proxy等の必須optionに違反がない場合true。
	bool								  safeOptions{true} ;
	/// 自動redirect禁止を確認した場合true。
	bool								  redirectDisabled{} ;
	/// Medium auto logon policyを確認した場合true。
	bool								  mediumLogon{} ;
	/// Requestに付けられたheader。固定fixture情報だけを保持する。
	std::wstring						  headers ;
	/// 注入先から参照する取消し状態。
	bool								  cancelled{} ;
	/// 注入時計のmonotonic millisecond。
	std::uint64_t						  ticks{} ;
	/// 現在の回線が制限なしとして照会される場合true。
	bool								  unrestricted{true} ;
	/// Cost照会回数。cache hitでは0のまま。
	unsigned							  costReads{} ;
	/// Cacheへ返す検証済みentry。
	CatalogCacheEntry					  cache ;
	/// Cache読取りのfake診断。
	NativeError							  cacheError{} ;
	/// Cache読取り回数。
	unsigned							  cacheLoads{} ;
	/// Cache保存回数。
	unsigned							  cacheStores{} ;
	/// Cache破棄回数。
	unsigned							  cacheDiscards{} ;
	/// ReadData失敗を注入する1-based回数。0は失敗なし。
	unsigned							  failReadAt{} ;
	/// ReadDataが0 byteを返す異常を注入する。
	bool								  zeroRead{} ;
	/// 確保容量以上の書込みはせず、返却countだけの不整合を注入する。
	bool								  oversizedReadCount{} ;
	/// Header本文照会の元診断を注入する。
	DWORD								  headerBodyError{} ;
	/// 任意API境界で取消しや期限を変更する同期hook。
	std::function<void( std::string_view)> hook ;
	/// Parser前後のcheckpointを、取得根拠の有無から特定する試験用取消し照会。
	std::function<bool()>				  cancellationProbe ;

	/**
     * @brief 同期fixture内の非所有hookを呼ぶ。
     * @param[in] stage 固定のAPI段階名。
     */
	void								  visit( const std::string_view stage)
	{
		// 明示した故障注入点だけを実行する。
		if( hook) {
			hook( stage) ;
		}
	}
} ;

// WinHttpOpenにはhandle引数がないため、試験threadだけの借用先を使う。
thread_local HttpFixture *activeHttpFixture{} ;

/**
 * @brief 全十二APIを非通信callbackへ置換する。
 * @return 実WinHTTP handleを作らない完全な関数table。
 */
OfficialHttpTransport	  fakeTransport()
{
	OfficialHttpTransport transport ;	// 既定APIを全て以下のfakeで置換する。
	// Openだけは引数にfixture handleがないため、試験threadの借用先を使用する。
	transport.open = []( LPCWSTR userAgent, DWORD access, LPCWSTR proxy, LPCWSTR bypass,
						DWORD flags) -> HINTERNET {
		auto &fixture = *activeHttpFixture ;	// 本試験scopeが所有する状態。
		++fixture.opened ;
		fixture.safeOptions &= userAgent != nullptr &&
							   std::wstring_view( userAgent) ==
								   L"Mozilla/5.0 (compatible; DriverCrate/0.1.0; "
								   L"+https://github.com/EnterOgawa/drivercrate)" &&
							   access == WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY && proxy == nullptr &&
							   bypass == nullptr && flags == 0U ;
		fixture.visit( "open") ;
		return &fixture ;
	} ;
	// 接続handleは同じfixtureを借用し、network接続を生成しない。
	transport.connect = []( HINTERNET session, LPCWSTR, INTERNET_PORT port,
						   DWORD reserved) -> HINTERNET {
		auto &fixture = *static_cast<HttpFixture *>( session) ;	// Fake sessionの借用先。
		++fixture.opened ;
		fixture.safeOptions &= port == INTERNET_DEFAULT_HTTPS_PORT && reserved == 0U ;
		return &fixture ;
	} ;
	// Pathは生の端末情報を含まない固定policyから渡される。記録せず必須optionだけを検査する。
	transport.openRequest = []( HINTERNET connection, LPCWSTR verb, LPCWSTR, LPCWSTR,
							   LPCWSTR referer, LPCWSTR *, DWORD flags) -> HINTERNET {
		auto &fixture = *static_cast<HttpFixture *>( connection) ;	// Fake connectionの借用先。
		++fixture.opened ;
		fixture.safeOptions &=
			std::wstring_view( verb) == L"GET" && referer == nullptr && flags == WINHTTP_FLAG_SECURE ;
		return &fixture ;
	} ;
	// 全phaseが正の有限値で、元の60秒上限を超えないことを記録する。
	transport.setTimeouts = []( HINTERNET handle, int resolve, int connect, int send,
							   int receive) -> BOOL {
		auto &fixture = *static_cast<HttpFixture *>( handle) ;	// 当該timeout設定先。
		fixture.finiteTimeouts &= resolve > 0 && connect > 0 && send > 0 && receive > 0 &&
								  resolve <= 60000 && connect <= 60000 && send <= 60000 &&
								  receive <= 60000 ;
		fixture.visit( "timeouts") ;
		return TRUE ;
	} ;
	// 制限緩和optionが指定された場合はfixture内の検査を失敗させる。
	transport.setOption = []( HINTERNET handle, DWORD option, LPVOID value, DWORD bytes) -> BOOL {
		auto &fixture = *static_cast<HttpFixture *>( handle) ;	// Option対象のfake request。
		fixture.safeOptions &= bytes == sizeof( DWORD) ;
		const auto setting = *static_cast<const DWORD *>( value) ;	// 呼出し側が指定した固定設定。
		// 共通HTTPが明示すべき自動redirect禁止を検査する。
		if( option == WINHTTP_OPTION_REDIRECT_POLICY) {
			fixture.redirectDisabled = setting == WINHTTP_OPTION_REDIRECT_POLICY_NEVER ;
		}
		// 資格情報を無制限送信する設定へ変わっていないことを確認する。
		else if( option == WINHTTP_OPTION_AUTOLOGON_POLICY) {
			fixture.mediumLogon = setting == WINHTTP_AUTOLOGON_SECURITY_LEVEL_MEDIUM ;
		} else {
			fixture.safeOptions = false ;
		}

		return TRUE ;
	} ;
	// Cache ETag以外の個別情報をrequestへ加えていないことを検査できるよう保持する。
	transport.addHeaders = []( HINTERNET handle, LPCWSTR headers, DWORD length, DWORD) -> BOOL {
		auto &fixture = *static_cast<HttpFixture *>( handle) ;	// 固定headerの記録先。
		fixture.headers.append( headers, length) ;
		return TRUE ;
	} ;
	// 実送信回数と、任意bodyを送っていないことを記録する。
	transport.sendRequest = []( HINTERNET handle, LPCWSTR headers, DWORD length, LPVOID optional,
							   DWORD optionalLength, DWORD totalLength, DWORD_PTR context) -> BOOL {
		auto &fixture = *static_cast<HttpFixture *>( handle) ;	// Sendに対応するfixture。
		++fixture.sends ;
		fixture.safeOptions &= headers == nullptr && length == 0U && optional == nullptr &&
							   optionalLength == 0U && totalLength == 0U && context == 0U ;
		fixture.visit( "send") ;
		return TRUE ;
	} ;
	// 同期待機復帰点で取消し・期限を注入する。
	transport.receiveResponse = []( HINTERNET handle, LPVOID) -> BOOL {
		static_cast<HttpFixture *>( handle)->visit( "receive") ;
		return TRUE ;
	} ;
	// Statusと有限文字列headerのWinHTTP二段階照会を再現する。
	transport.queryHeaders = []( HINTERNET handle, DWORD info, LPCWSTR, LPVOID output, LPDWORD bytes,
								LPDWORD) -> BOOL {
		auto &fixture = *static_cast<HttpFixture *>( handle) ;	// 現在responseの所有fixture。
		fixture.visit( "headers") ;
		// Statusは数値照会専用として返す。
		if( info == (WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER)) {
			*static_cast<DWORD *>( output) = fixture.status ;
			*bytes						  = sizeof( DWORD) ;
			return TRUE ;
		}

		const auto value =
			info == WINHTTP_QUERY_CONTENT_LENGTH
				? fixture.declared
				: (info == WINHTTP_QUERY_ETAG
					   ? std::optional<std::wstring>( L"\"fake-etag\"")
					   : std::optional<std::wstring>{}) ;	// 当該headerだけのfixture値。
		// 欠損headerを明示0へ変換しない。
		if( !value) {
			SetLastError( ERROR_WINHTTP_HEADER_NOT_FOUND) ;
			return FALSE ;
		}

		const auto needed =
			// 終端を含む必要量。
			static_cast<DWORD>( (value->size() + 1U) * sizeof( wchar_t)) ;
		// 最初の照会または容量不足では本文をcopyしない。
		if( output == nullptr || *bytes < needed) {
			*bytes = needed ;
			SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			return FALSE ;
		}

		// 第2段階のnative診断を保存できることを検査する。
		if( info == WINHTTP_QUERY_CONTENT_LENGTH && fixture.headerBodyError != 0U) {
			SetLastError( fixture.headerBodyError) ;
			return FALSE ;
		}

		std::memcpy( output, value->c_str(), needed) ;
		*bytes = needed - sizeof( wchar_t) ;
		return TRUE ;
	} ;
	// 残本文を示す。EOF復帰時も協調停止hookを動かす。
	transport.queryAvailable = []( HINTERNET handle, LPDWORD bytes) -> BOOL {
		auto &fixture = *static_cast<HttpFixture *>( handle) ;	// 有限本文の読取り位置。
		++fixture.availableCalls ;
		*bytes = static_cast<DWORD>( fixture.body.size() - fixture.offset) ;
		fixture.visit( *bytes == 0U ? "eof" : "available") ;
		return TRUE ;
	} ;
	// Bufferへは要求量以内しか書かず、異常countとAPI失敗を独立に再現する。
	transport.readData = []( HINTERNET handle, LPVOID buffer, DWORD requested,
							LPDWORD received) -> BOOL {
		auto &fixture = *static_cast<HttpFixture *>( handle) ;	// 同期本文の借用先。
		++fixture.reads ;
		// 部分成功後の失敗を自動retryさせない。
		if( fixture.failReadAt == fixture.reads) {
			SetLastError( ERROR_WINHTTP_CONNECTION_ERROR) ;
			return FALSE ;
		}

		const auto copied = fixture.zeroRead
								? 0U
								: std::min( {requested, fixture.chunk,
											static_cast<DWORD>( fixture.body.size() -
															   fixture.offset)}) ;	// 実copy量。
		std::memcpy( buffer, fixture.body.data() + fixture.offset, copied) ;
		fixture.offset += copied ;
		*received = fixture.oversizedReadCount ? requested + 1U : copied ;
		fixture.visit( "read") ;
		return TRUE ;
	} ;
	// Fake handleをWinHttpCloseHandleへ渡さず、所有権の解放を記録する。
	transport.closeHandle = []( HINTERNET handle) -> BOOL {
		++static_cast<HttpFixture *>( handle)->closed ;
		return TRUE ;
	} ;
	return transport ;
}

/**
 * @brief 一つのHTTP fixtureとcontextとclientを寿命順に所有する。
 * @note Scopeを跨ぐnative handle・cache・network状態は存在しない。
 */
struct HttpCase {
	/// Backend callbackが借用する最長寿命の状態。
	HttpFixture					   fixture ;
	/// Fixtureだけへアクセスするcache callback。
	OfficialHttpCacheAccess		   cacheAccess ;
	/// 累積予算とcost・時計・取消しの実装。
	MetadataSearchExecutionContext execution ;
	/// 全検証はproductionのまま、低位I/Oだけを置換するclient。
	OfficialHttpClient			   client ;

	/**
     * @brief 一providerの独立した情報検索を開始する。
     * @param[in] useCache 非永続cache callbackを有効にする場合true。
     * @param[in] approved 未知・従量回線の今回限りの許可。
     * @param[in] limits 固定上限以下の試験予算。
     */
	explicit HttpCase( const bool useCache = false, const bool approved = false,
					  const MetadataSearchLimits limits = {})
		: cacheAccess{
			  [this]( std::wstring_view, std::uint64_t, std::uint64_t, CatalogCacheEntry &entry) {
				  ++fixture.cacheLoads ;
				  fixture.visit( "cache-load") ;
				  entry = fixture.cache ;
				  return fixture.cacheError ;
			  },
			  [this]( std::wstring_view, std::span<const std::byte>, std::wstring_view) {
				  ++fixture.cacheStores ;
				  fixture.visit( "cache-store") ;
				  return static_cast<NativeError>( 0) ;
			  },
			  [this]( std::wstring_view) { ++fixture.cacheDiscards ; }},
		  execution(
			  79U,
			  MetadataSearchRequest{
				  .enabledProviderIds		 = {std::wstring( PROLIFIC_OFFICIAL_PROVIDER_ID)},
				  .restrictedNetworkApproved = approved},
			  [this] {
				  return fixture.cancelled ||
						 (fixture.cancellationProbe && fixture.cancellationProbe()) ;
			  },
			  [this] { return fixture.ticks ; },
			  [this] {
				  ++fixture.costReads ;
				  fixture.visit( "cost") ;
				  return MetadataNetworkCost{fixture.unrestricted, 0} ;
			  },
			  limits),
		  client( execution, fakeTransport(), useCache ? &cacheAccess : nullptr)
	{
		activeHttpFixture = &fixture ;
		static_cast<void>( execution.beginProvider( PROLIFIC_OFFICIAL_PROVIDER_ID)) ;
		static_cast<void>( client.beginSourceSession( 79U, PROLIFIC_OFFICIAL_PROVIDER_ID)) ;
	}

	/** @brief 全HTTP handleが同期解放された後にthread-local借用先を外す。 */
	~HttpCase()
	{
		activeHttpFixture = nullptr ;
	}

	/**
     * @brief 固定metadata起点だけを共通取得経路へ渡す。
     * @param[out] result 正常UTF-8本文。失敗時は空。
     * @return 本番と同じnative診断。
     */
	NativeError fetch( std::wstring &result)
	{
		return client.getUtf8TextForSource(
			officialMetadataEndpoint( PROLIFIC_OFFICIAL_PROVIDER_ID, OFFICIAL_LANDING_RESOURCE_ID),
			OFFICIAL_LANDING_RESOURCE_ID, 2U * 1024U * 1024U, result) ;
	}
} ;

/**
 * @brief 文字列fixtureを検証済みcache本文相当へcopyする。
 * @param[in] body 非機密の固定test本文。
 * @return 本文と同じbyte列。
 */
std::vector<std::byte> cacheBytes( const std::string_view body)
{
	const auto bytes =
		// 読取り専用の有限byte view。
		std::as_bytes( std::span( body.data(), body.size())) ;
	return {bytes.begin(), bytes.end()} ;
}

/**
 * @brief 固定起点と全I/O遮断、完全な依存注入を確認する。
 * @param[in,out] context Assertion集計先。
 */
void testFixedEndpoints( TestContext &context)
{
	unsigned endpoints{} ;	// 九providerの登録された十二起点を数える。
	// 登録された起点だけが共通lookupとHTTPS policyに一致することを確認する。
	for( const auto &provider : builtInProviderDescriptors()) {
		const auto *policy =
			// 登録された取得元policy。
			officialSourcePolicyForProvider( provider.id) ;
		// Network policyを持たないproviderは起点数へ含めない。
		if( policy == nullptr) {
			continue ;
		}

		// 一provider最大二resourceの固定起点を全件照合する。
		for( const auto &endpoint : policy->metadataEndpoints) {
			++endpoints ;
			DRIVERCRATE_EXPECT( context, officialMetadataEndpoint(
											provider.id, endpoint.resourceId) == endpoint.url) ;
			const auto *resource =
				// 対応用途。
				findOfficialSourceResource( *policy, endpoint.resourceId) ;
			DRIVERCRATE_EXPECT( context, resource != nullptr) ;
			DRIVERCRATE_EXPECT( context,
							   validateOfficialHttpsUrl( endpoint.url, resource->allowedHosts) == 0) ;
		}
	}

	DRIVERCRATE_EXPECT( context, endpoints == 13U) ;
	// 同じhostのpayload path・query追加・fragment・非HTTPS・未知用途を全て通信前に拒否する。
	for( const auto suffix : {L"payload.exe", L"?extra=1", L"#section", L"/", L"\n"}) {
		HttpCase	 run ;				// 不正要求ごとの独立状態。
		std::wstring result = L"old" ;	// 失敗時に既存本文を残さない確認先。
		const auto	 url	= std::wstring( officialMetadataEndpoint( PROLIFIC_OFFICIAL_PROVIDER_ID,
																	OFFICIAL_LANDING_RESOURCE_ID)) +
						 suffix ;	// 固定起点から変更した入力。
		DRIVERCRATE_EXPECT( context, run.client.getUtf8TextForSource(
										url, OFFICIAL_LANDING_RESOURCE_ID, 2097152U, result) != 0) ;
		DRIVERCRATE_EXPECT( context, result.empty()) ;
		DRIVERCRATE_EXPECT( context, run.fixture.opened == 0U && run.fixture.cacheLoads == 0U) ;
		DRIVERCRATE_EXPECT( context, run.execution.usage().logicalResources == 0U) ;
	}

	HttpCase run ;							// 不完全tableを試す独立client。
	auto	 transport = fakeTransport() ;	// 一必須callbackを欠落させる。
	transport.readData = nullptr ;
	OfficialHttpClient invalid( run.execution, transport) ;	// Native fallbackは禁止する。
	DRIVERCRATE_EXPECT( context,
					   invalid.beginSourceSession( 79U, PROLIFIC_OFFICIAL_PROVIDER_ID) != 0) ;
	DRIVERCRATE_EXPECT( context, run.fixture.opened == 0U) ;
}

/**
 * @brief 本文上限、宣言長、chunk異常、UTF-8失敗の消費を確認する。
 * @param[in,out] context Assertion集計先。
 */
void testBodyBoundaries( TestContext &context)
{
	// 実固定2MiBの直前・一致・probe超過を実ReadData境界で検証する。
	for( const auto size : {2097151U, 2097152U, 2097153U}) {
		HttpCase run ;	// 初期budgetを共有しない一resource。
		run.fixture.body.assign( size, 'x') ;
		std::wstring result ;	// 巨大本文も上限以内でだけ取得する。
		DRIVERCRATE_EXPECT( context, (run.fetch( result) == 0) == (size <= 2097152U)) ;
		DRIVERCRATE_EXPECT( context, run.execution.usage().bodyBytes == std::min( size, 2097152U)) ;
		DRIVERCRATE_EXPECT( context,
						   run.execution.usage().probeBytes == (size > 2097152U ? 1U : 0U)) ;
		DRIVERCRATE_EXPECT( context, run.fixture.offset == size) ;
		DRIVERCRATE_EXPECT( context,
						   run.fixture.sends == 1U && run.execution.usage().httpAttempts == 1U) ;
		DRIVERCRATE_EXPECT( context, run.fixture.opened == run.fixture.closed) ;
		DRIVERCRATE_EXPECT( context, run.fixture.finiteTimeouts && run.fixture.safeOptions &&
										run.fixture.redirectDisabled && run.fixture.mediumLogon) ;
		DRIVERCRATE_EXPECT( context, (result.empty()) == (size > 2097152U)) ;
	}

	// 不正または超過宣言長は受信byteを創作せず、body読取り前に拒否する。
	for( const auto length : {L"2097153", L"18446744073709551615", L"18446744073709551616",
							 L"999999999999999999999999999", L"-1", L" 8", L"8x", L""}) {
		HttpCase run ;	// Content-Lengthだけを変えたHTTP 200。
		run.fixture.declared = length ;
		std::wstring result ;	// 拒否時は空。
		DRIVERCRATE_EXPECT( context, run.fetch( result) != 0 && result.empty()) ;
		DRIVERCRATE_EXPECT( context,
						   run.fixture.reads == 0U && run.execution.usage().bodyBytes == 0U) ;
		DRIVERCRATE_EXPECT( context, run.fixture.sends == 1U) ;
	}

	// 明示0・短い宣言・長い宣言と実本文の不一致を受信後に拒否する。
	for( const auto length : {L"0", L"7", L"9"}) {
		HttpCase run ;	// 実本文は8 byte。
		run.fixture.declared = length ;
		std::wstring result ;	// 不一致本文を利用しない。
		DRIVERCRATE_EXPECT( context, run.fetch( result) != 0 && result.empty()) ;
		DRIVERCRATE_EXPECT( context, run.execution.usage().bodyBytes == 8U) ;
	}

	HttpCase exact ;	// 正しい宣言長は従来のmetadata取得を妨げない。
	exact.fixture.declared = L"8" ;
	exact.fixture.chunk	   = 3U ;
	std::wstring result ;	// 成功・失敗ごとに共通関数が初期化する出力。
	DRIVERCRATE_EXPECT( context, exact.fetch( result) == 0 && result == L"metadata") ;
	DRIVERCRATE_EXPECT( context,
					   exact.fixture.reads == 3U && exact.client.sourceEvidence().size() == 1U) ;
	// Zero read・過大返却count・部分受信後失敗をそれぞれ一度だけ処理する。
	for( unsigned mode = 0U; mode < 3U; ++mode) {
		HttpCase run ;	// 故障注入は当該resourceに閉じる。
		run.fixture.chunk			   = 3U ;
		run.fixture.zeroRead		   = mode == 0U ;
		run.fixture.oversizedReadCount = mode == 1U ;
		run.fixture.failReadAt		   = mode == 2U ? 2U : 0U ;
		DRIVERCRATE_EXPECT( context, run.fetch( result) != 0 && result.empty()) ;
		DRIVERCRATE_EXPECT( context, run.fixture.sends == 1U && run.client.sourceEvidence().empty()) ;
		DRIVERCRATE_EXPECT( context, run.execution.usage().bodyBytes == (mode == 2U ? 3U : 0U)) ;
		DRIVERCRATE_EXPECT( context, run.fixture.opened == run.fixture.closed) ;
	}

	// 取得は成功しても不正UTF-8・NUL・空本文ではledgerを発行せず消費は返さない。
	for( const auto &body : {std::string( "\xc0\xaf", 2U), std::string( "a\0b", 3U), std::string{}}) {
		HttpCase run ;	// Encoding検査は本番decode関数を使用する。
		run.fixture.body = body ;
		DRIVERCRATE_EXPECT( context, run.fetch( result) != 0 && result.empty()) ;
		DRIVERCRATE_EXPECT( context, run.execution.usage().bodyBytes == body.size()) ;
		DRIVERCRATE_EXPECT( context, run.client.sourceEvidence().empty()) ;
	}

	HttpCase headerFailure ;	// 第2段階header照会の元診断を確認する。
	headerFailure.fixture.declared		  = L"8" ;
	headerFailure.fixture.headerBodyError = ERROR_WINHTTP_TIMEOUT ;
	DRIVERCRATE_EXPECT( context,
					   headerFailure.fetch( result) ==
						   static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_WINHTTP_TIMEOUT))) ;
}

/**
 * @brief Fresh・304・破損cacheと回線許可の組合せを確認する。
 * @param[in,out] context Assertion集計先。
 */
void testCacheAndStatus( TestContext &context)
{
	// Freshと304は同じ本文を一度だけ消費し、送信数は区別する。
	for( const auto state : {CatalogCacheState::FRESH, CatalogCacheState::STALE}) {
		HttpCase run( true) ;	// 実cacheへアクセスしない。
		run.fixture.cache  = {state, cacheBytes( "cached"), L"\"fixture\"", 1U} ;
		run.fixture.status = 304U ;
		std::wstring result ;	// Network bodyとは異なるcache本文を確認する。
		DRIVERCRATE_EXPECT( context, run.fetch( result) == 0 && result == L"cached") ;
		DRIVERCRATE_EXPECT( context, run.execution.usage().bodyBytes == 6U) ;
		DRIVERCRATE_EXPECT( context, run.execution.usage().logicalResources == 1U) ;
		DRIVERCRATE_EXPECT( context, run.fixture.reads == 0U) ;
		DRIVERCRATE_EXPECT( context,
						   run.fixture.sends == (state == CatalogCacheState::FRESH ? 0U : 1U)) ;
		DRIVERCRATE_EXPECT( context, run.fixture.costReads == run.fixture.sends) ;
		DRIVERCRATE_EXPECT( context, run.fixture.cacheStores == run.fixture.sends) ;
		DRIVERCRATE_EXPECT( context, run.client.sourceEvidence().size() == 1U) ;
		DRIVERCRATE_EXPECT( context, run.client.sourceEvidence().front().acquisition ==
										(state == CatalogCacheState::FRESH
											 ? MeasurementAcquisition::FRESH_CACHE
											 : MeasurementAcquisition::REVALIDATED_CACHE)) ;
		DRIVERCRATE_EXPECT( context, (run.fixture.headers.find( L"If-None-Match: \"fixture\"") !=
									 std::wstring::npos) == (state == CatalogCacheState::STALE)) ;
	}

	// 未知回線でもFresh cacheは使用可能。Missは今回の明示許可だけで送信可能。
	for( const bool approved : {false, true}) {
		// FreshとMissingの双方を、同意と独立に照合する。
		for( const bool fresh : {false, true}) {
			HttpCase run( true, approved) ;	// Cost readerが未知を返す一run。
			run.fixture.unrestricted = false ;
			run.fixture.cache = {fresh ? CatalogCacheState::FRESH : CatalogCacheState::MISSING,
								 fresh ? cacheBytes( "cached") : std::vector<std::byte>{},
								 {},
								 fresh ? std::optional<std::uint64_t>( 1U) : std::nullopt} ;
			std::wstring result ;	// 成功時だけ本文を残す。
			DRIVERCRATE_EXPECT( context, (run.fetch( result) == 0) == (approved || fresh)) ;
			DRIVERCRATE_EXPECT( context, run.fixture.sends == (approved && !fresh ? 1U : 0U)) ;
		}
	}

	// 破損entryとcache I/O errorの自動network fallbackを禁止する。
	for( const bool ioError : {false, true}) {
		HttpCase run( true) ;	// Cacheエラーごとの独立状態。
		run.fixture.cache.state = CatalogCacheState::INVALIDATED ;
		run.fixture.cacheError	= ioError ? static_cast<NativeError>( E_ACCESSDENIED) : 0 ;
		std::wstring result ;	// Cache失敗後も空を保持する。
		DRIVERCRATE_EXPECT( context, run.fetch( result) != 0 && result.empty()) ;
		DRIVERCRATE_EXPECT( context, run.fixture.opened == 0U && run.fixture.sends == 0U) ;
		DRIVERCRATE_EXPECT( context, run.execution.usage().bodyBytes == 0U) ;
	}

	// 全初期metadata起点はredirect禁止。拒否statusや304不整合もretryせず本文を読まない。
	for( const DWORD status : {301U, 302U, 303U, 307U, 308U, 403U, 404U, 429U, 500U, 304U}) {
		HttpCase run( true) ;	// Miss cacheと固定応答だけを使用する。
		run.fixture.status = status ;
		std::wstring result ;	// Status拒否時は本文なし。
		DRIVERCRATE_EXPECT( context, run.fetch( result) != 0 && result.empty()) ;
		DRIVERCRATE_EXPECT( context, run.fixture.sends == 1U && run.fixture.reads == 0U) ;
		DRIVERCRATE_EXPECT( context, run.fixture.cacheStores == 0U &&
										run.fixture.opened == run.fixture.closed) ;
	}

	MetadataSearchLimits limits ;	// Cacheも同じresource予算を使うことを小さな本文で再現する。
	limits.resourceBytes = 4U ;
	HttpCase oversized( true, false, limits) ;	// Freshでも本文予算を免除しない。
	oversized.fixture.cache = {CatalogCacheState::FRESH, cacheBytes( "12345"), {}, 1U} ;
	std::wstring result ;	// 超過cacheは本文を公開しない。
	DRIVERCRATE_EXPECT( context, oversized.fetch( result) != 0 && result.empty()) ;
	DRIVERCRATE_EXPECT( context, oversized.execution.usage().bodyBytes == 4U &&
									oversized.execution.usage().probeBytes == 1U &&
									oversized.fixture.sends == 0U) ;
}

/**
 * @brief API復帰・chunk・cacheの各段階で停止し、後続処理を遮断する。
 * @param[in,out] context Assertion集計先。
 */
void testCancellation( TestContext &context)
{
	// 各同期API中の取消しを、実APIの戻り直後に観測させる。
	for( const std::string_view stage : {"cost", "send", "receive", "headers", "available", "read",
										"eof", "cache-load", "cache-store"}) {
		HttpCase run( true) ;	// Missから一つのfake本文を取得する。
		run.fixture.chunk = 3U ;
		// Fixtureが所有するhookは同じscopeの状態だけを書き換える。
		run.fixture.hook = [&]( const std::string_view visited) {
			// 指定した境界だけで取消しを成立させる。
			if( visited == stage) {
				run.fixture.cancelled = true ;
			}
		} ;
		std::wstring result ;	// 取消し後はdecode済みでも公開しない。
		DRIVERCRATE_EXPECT( context, run.fetch( result) != 0 && result.empty()) ;
		DRIVERCRATE_EXPECT( context,
						   run.execution.sessionStopReason() == MetadataSearchReason::CANCELLED) ;
		DRIVERCRATE_EXPECT( context, run.client.sourceEvidence().empty()) ;
		DRIVERCRATE_EXPECT( context,
						   run.fixture.sends <= 1U && run.fixture.opened == run.fixture.closed) ;
		DRIVERCRATE_EXPECT( context, run.fixture.cacheStores == (stage == "cache-store" ? 1U : 0U)) ;
		// 既読chunkだけを消費し、取消し後に残bodyを読み足さない。
		if( stage == "read") {
			DRIVERCRATE_EXPECT( context,
							   run.fixture.reads == 1U && run.execution.usage().bodyBytes == 3U) ;
		}

		// EOF待機中の取消しでもcacheを書き込まない。
		if( stage == "eof") {
			DRIVERCRATE_EXPECT( context, run.execution.usage().bodyBytes == 8U) ;
		}
	}

	HttpCase expired ;	// 同期受信でprovider期限へ到達するfixture。
	expired.fixture.hook = [&]( const std::string_view stage) {
		// 実時間を待たず、response wait終了時刻だけを動かす。
		if( stage == "receive") {
			expired.fixture.ticks = 90000U ;
		}
	} ;
	std::wstring result ;	// Deadline後の本文なし。
	DRIVERCRATE_EXPECT( context, expired.fetch( result) != 0 && result.empty()) ;
	DRIVERCRATE_EXPECT( context,
					   expired.fixture.reads == 0U && expired.execution.providerStopReason() ==
														  MetadataSearchReason::DEADLINE_EXCEEDED) ;
}

/**
 * @brief Schema拒否時の消費保持とparser前後の協調停止を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testParserBoundaries( TestContext &context)
{
	// 配布file名は合成値。取得先として使用せずmetadata本文にだけ含める。
	constexpr std::string_view PAGE =
		R"(<table><tr><td>Windows DCHU+DFx+Modem Standy Driver INF Setup</td>)"
		R"(<td>Win10 / Win11</td><td><a href="/wp-content/uploads/2026/01/)"
		R"(PL2303G_DCHU_fixture.zip">ZIP</a></td></tr></table>)" ;
	// 正常・schema拒否・parse前取消し・parse後取消しを同じHTTP取得経路で実行する。
	for( unsigned mode = 0U; mode < 4U; ++mode) {
		HttpCase run ;	// 一providerのHTTPと共通release読取りを結合する。
		run.fixture.body = mode == 1U ? "<html>missing metadata</html>" : std::string( PAGE) ;
		unsigned afterEvidence{} ;	// Ledger確定後のparse前・parse後checkpoint順。
		// Ledger確定後にだけ数え、HTTP内部のcheckpoint数の変化へ依存しない。
		run.fixture.cancellationProbe = [&] {
			// HTTP途中は停止せず、共通reader側へ制御が戻るのを待つ。
			if( run.client.sourceEvidence().empty()) {
				return false ;
			}

			++afterEvidence ;
			return (mode == 2U && afterEvidence == 1U) || (mode == 3U && afterEvidence == 2U) ;
		} ;
		OfficialReleaseRecord record ;		// 失敗時はpayload URLや版を保持しない。
		bool				  rejected{} ;	// 通信停止とschema拒否を分ける。
		const auto			  error = readOfficialReleaseMetadata(
			   OfficialReleaseFamily::PROLIFIC_DCHU, 79U, run.client, record, rejected,
			   &run.execution) ;	// ProductionのHTTP＋parser結果。
		DRIVERCRATE_EXPECT( context, (error == 0) == (mode == 0U)) ;
		DRIVERCRATE_EXPECT( context, rejected == (mode == 1U)) ;
		DRIVERCRATE_EXPECT( context, record.downloadUrl.empty() == (mode != 0U)) ;
		DRIVERCRATE_EXPECT( context, record.packageVersion.empty()) ;
		DRIVERCRATE_EXPECT( context, run.fixture.sends == 1U &&
										run.execution.usage().bodyBytes == run.fixture.body.size()) ;
		DRIVERCRATE_EXPECT( context, run.execution.usage().logicalResources == 1U) ;
		// Parser前または後の停止を通常のschema拒否と混同しない。
		if( mode >= 2U) {
			DRIVERCRATE_EXPECT( context, run.execution.sessionStopReason() ==
											MetadataSearchReason::CANCELLED) ;
			DRIVERCRATE_EXPECT( context, afterEvidence == mode - 1U) ;
		}
	}
}

} // namespace

/** @see metadata_search_http_tests.h */
void runMetadataSearchHttpTests( TestContext &context)
{
	testFixedEndpoints( context) ;
	testBodyBoundaries( context) ;
	testCacheAndStatus( context) ;
	testCancellation( context) ;
	testParserBoundaries( context) ;
}

} // namespace drivercrate::test
