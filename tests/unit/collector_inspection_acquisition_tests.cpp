//------------------------------------------------------------------------------
/**
 * @file collector_inspection_acquisition_tests.cpp
 * @brief 外部台帳の一回収集取得scopeを完全非通信で検証する独立試験。
 * @version 01.01.01
 * @date 2026/10/06
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  静的link・実HTTP境界の非通信試験を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/24  必須解析に合わせ試験の所有・型・失敗制御を明示。
 * Ver.01.01.00 Shunji Ogawa  2026/11/04  定義候補の実metadata再確認と単一GUID拘束を追加。
 * Ver.01.01.01 Shunji Ogawa  2026/11/09  timeout/取消code期待のNativeError型だけを明示。
 * </pre>
 *
 * @note 全HTTP／DNSをfixtureへ置換し、実network・導入・Taskを使用しない。
 * @see docs/adr/0280-collector-scoped-inspection-acquisition.md
 */
//------------------------------------------------------------------------------
#include "platform/collector_inspection_acquisition.h"
#include "platform/collector_definition_request.h"
#include "platform/official_download_workspace.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <optional>
#include <objbase.h>
#include <stdexcept>
#include <vector>
#include <utility>

namespace {
/** @brief 一hopの架空応答。 */
struct Response {
	/// HTML起点または検査payloadの本文。
	std::string					body ;
	/// 受信headerのstatus。
	DWORD						status{200U} ;
	/// HTMLのMIMEとUTF-8。
	std::wstring				mime{L"text/html; charset=utf-8"} ;
	/// 同一origin内redirect fixture。
	std::optional<std::wstring> location ;
} ;
/** @brief 同期HTTP表を全部置換する一fixture。 */
struct Fixture {
	/// 送信順の二応答。
	std::vector<Response>	  responses ;
	/// 完了した送信回数。未送信0。
	std::size_t				  sends{} ;
	/// 現本文の読取byte位置。
	std::size_t				  offset{} ;
	/// 作成したfake handle数。
	std::size_t				  opened{} ;
	/// 全fake handleの解放数。
	std::size_t				  closed{} ;
	/// 全resolver呼出し数。
	std::size_t				  dns{} ;
	/// trueなら一宛先をprivateにする。
	bool					  privateAddress{} ;
	/// trueなら二回目以降のpayload DNSだけprivateにする。
	bool					  privatePayload{} ;
	/// trueなら本文途中でReadDataを失敗させる。
	bool					  failRead{} ;
	/// 安全なtimeout・cookie・credential条件が維持された場合true。
	bool					  safe{true} ;
	/// 閉model protocolだけがPOSTを使用します。
	bool					  model{} ;
	/// 同processの偽UTC秒です。
	std::uint64_t			  now{1000U} ;
	/// Payload DNSの待機中に失効させます。
	bool					  expireOnPayloadDns{} ;
	/// POST応答後に時計を後退させます。
	bool					  rollbackAfterPost{} ;
	/// 非秘密のverb列。秘密queryは保持しません。
	std::vector<std::wstring> methods ;
} ;
thread_local Fixture *fixture{} ;	// 同期試験scopeだけの非所有参照。
std::size_t			  checks{} ;	// 独立した有限assertion数。

/** @brief 失敗時は固定診断だけで終了する。
 * @param[in] condition 個別の期待条件。
 */
void				  check( bool condition)
{
	++checks ;
	// 元入力やURLを診断へ含めない。
	if( !condition) {
		throw std::runtime_error( "COLLECTOR_INSPECTION_CHECK") ;
	}
}

/** @brief 全WinHTTP／DNS関数を架空表へ置換する。
 * @return Native呼出しへfallbackしない完全表。
 */
drivercrate::OfficialHttpTransport transport()
{
	drivercrate::OfficialHttpTransport api ;	// 下の全関数で上書きする所有表。
	api.open = []( LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) -> HINTERNET {
		++fixture->opened ;
		return fixture ;
	} ;
	api.connect = []( HINTERNET, LPCWSTR, INTERNET_PORT, DWORD) -> HINTERNET {
		++fixture->opened ;
		return fixture ;
	} ;
	api.openRequest = []( HINTERNET, LPCWSTR verb, LPCWSTR, LPCWSTR, LPCWSTR referer, LPCWSTR *,
						 DWORD) -> HINTERNET {
		fixture->safe &= std::wstring_view( verb) == L"GET" ||
						 (fixture->model && std::wstring_view( verb) == L"POST") ;
		fixture->methods.emplace_back( verb) ;
		// 閉POSTのRefererだけをWinHTTP引数へ渡し、GETへ流用しません。
		fixture->safe &=
			std::wstring_view( verb) == L"POST"
				? (referer != nullptr && std::wstring_view( referer) == L"https://www.asus.com/")
				: referer == WINHTTP_NO_REFERER ;
		++fixture->opened ;
		return fixture ;
	} ;
	api.setTimeouts = []( HINTERNET, int resolve, int connect, int send, int receive) -> BOOL {
		fixture->safe &= resolve > 0 && connect > 0 && send > 0 && receive > 0 ;
		return TRUE ;
	} ;
	api.setOption = []( HINTERNET, DWORD option, LPVOID value, DWORD size) -> BOOL {
		// 誤ったoption bufferは試験失敗として記録し、無効なDWORDを参照しない。
		if( value == nullptr || size != sizeof( DWORD)) {
			fixture->safe = false ;
			SetLastError( ERROR_INVALID_PARAMETER) ;
			return FALSE ;
		}

		const auto setting = *static_cast<DWORD *>( value) ;	// 架空optionの有限DWORD。
		// 既定資格情報を送る設定を試験でも拒否する。
		if( option == WINHTTP_OPTION_AUTOLOGON_POLICY) {
			fixture->safe &= setting == WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH ;
		}

		// Cookieの自動処理を両HTTPで無効化する。
		if( option == WINHTTP_OPTION_DISABLE_FEATURE) {
			fixture->safe &= (setting & WINHTTP_DISABLE_COOKIES) != 0U ;
		}

		return TRUE ;
	} ;
	api.addHeaders = []( HINTERNET, LPCWSTR text, DWORD size, DWORD) -> BOOL {
		const std::wstring_view value( text, size) ;	// 共通HTTPが設定する非秘密headerだけ。
		fixture->safe &=
			value.starts_with( L"Accept: ") || value == L"Cache-Control: no-cache\r\n" ||
			(fixture->model &&
			 value == L"Content-Type: application/json\r\nOrigin: https://www.asus.com\r\n") ;
		return TRUE ;
	} ;
	api.sendRequest = []( HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR) -> BOOL {
		// 用意した二応答を超える再送を拒否する。
		if( fixture->sends >= fixture->responses.size()) {
			SetLastError( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
			return FALSE ;
		}

		++fixture->sends ;
		fixture->offset = 0U ;
		return TRUE ;
	} ;
	api.receiveResponse = []( HINTERNET, LPVOID) -> BOOL {
		// 元発行時刻より前へ戻す故障を同POST応答へ注入します。
		if( fixture->rollbackAfterPost && fixture->sends == 2U) {
			fixture->now = 999U ;
		}

		return TRUE ;
	} ;
	api.queryHeaders = []( HINTERNET, DWORD info, LPCWSTR, LPVOID output, LPDWORD size,
						  LPDWORD) -> BOOL {
		const auto &response = fixture->responses.at( fixture->sends - 1U) ;	// 現hopの不変応答。
		// Statusだけは数値として返す。
		if( info == (WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER)) {
			*static_cast<DWORD *>( output) = response.status ;
			*size						  = sizeof( DWORD) ;
			return TRUE ;
		}

		std::wstring text ;	// 元fixture以外のheaderを合成しない。
		// HTML MIMEの二段照会を再現する。
		if( info == WINHTTP_QUERY_CONTENT_TYPE) {
			text = response.mime ;
		}
		// 同じ本文の完全な実byte数だけを宣言する。
		else if( info == WINHTTP_QUERY_CONTENT_LENGTH) {
			text = std::to_wstring( response.body.size()) ;
		}
		// 明示redirect以外にLocationを付与しない。
		else if( info == WINHTTP_QUERY_LOCATION && response.location) {
			text = *response.location ;
		} else {
			SetLastError( ERROR_WINHTTP_HEADER_NOT_FOUND) ;
			return FALSE ;
		}

		const auto required =
			// 有限header量。
			static_cast<DWORD>( (text.size() + 1U) * sizeof( wchar_t)) ;
		// WinHTTPの第一段または容量不足を同じerrorで再現する。
		if( output == nullptr || *size < required) {
			*size = required ;
			SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			return FALSE ;
		}

		std::memcpy( output, text.c_str(), required) ;
		*size = required - sizeof( wchar_t) ;
		return TRUE ;
	} ;
	api.queryAvailable = []( HINTERNET, LPDWORD size) -> BOOL {
		*size = static_cast<DWORD>( fixture->responses.at( fixture->sends - 1U).body.size() -
								   fixture->offset) ;
		return TRUE ;
	} ;
	api.readData = []( HINTERNET, LPVOID output, DWORD requested, LPDWORD size) -> BOOL {
		// 途中故障を完全取得へ昇格させない。
		if( fixture->failRead) {
			SetLastError( ERROR_WINHTTP_CONNECTION_ERROR) ;
			return FALSE ;
		}

		const auto &body = fixture->responses.at( fixture->sends - 1U).body ;	// 現本文。
		const auto	bytes =
			std::min<std::size_t>( requested, body.size() - fixture->offset) ;	// 上限内copy量。
		std::memcpy( output, body.data() + fixture->offset, bytes) ;
		fixture->offset += bytes ;
		*size = static_cast<DWORD>( bytes) ;
		return TRUE ;
	} ;
	api.closeHandle = []( HINTERNET) -> BOOL {
		++fixture->closed ;
		return TRUE ;
	} ;
	api.resolveDestination =
		[]( std::wstring_view, std::vector<drivercrate::OfficialResolvedNetworkAddress> &addresses) {
			++fixture->dns ;
			// API/POSTの後、GETのDNS待機中に期限が尽きる場合です。
			if( fixture->expireOnPayloadDns && fixture->dns == 3U) {
				fixture->now = 2000U ;
			}

			drivercrate::OfficialResolvedNetworkAddress address ;	// 架空IPv4一件。
			address.bytes[0] =
				(fixture->privateAddress || (fixture->privatePayload && fixture->dns >= 2U))
					? std::byte{10U}
					: std::byte{8U} ;
			address.bytes[1] = std::byte{8U} ;
			address.bytes[2] = std::byte{8U} ;
			address.bytes[3] = std::byte{8U} ;
			addresses		 = {address} ;
			return drivercrate::NativeError{} ;
		} ;
	api.utcNow = []() { return fixture->now ; } ;
	return api ;
}

/** @brief 実回線APIを使用しない試験cost。 */
class Cost final : public drivercrate::IOfficialNetworkCostReader {
public:
	/// 今回のfixture区分。
	drivercrate::OfficialNetworkCostKind value{drivercrate::OfficialNetworkCostKind::UNRESTRICTED} ;
	/** @brief 不変区分を返す。
	 * @param[out] output 試験区分。
	 * @return 成功0。
	 */
	drivercrate::NativeError read( drivercrate::OfficialNetworkCostKind &output) noexcept override
	{
		output = value ;
		return 0 ;
	}
} ;

/** @brief 正例と拒否例を有限に実行する。 */
void run()
{
	{
		Fixture state ;	// Backendの誤buffer拒否だけを独立して観測する。
		fixture		   = &state ;
		const auto api = transport() ;								// 実WinHTTPへ接続しない完全表。
		DWORD value	   = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH ;	// ゼロ長とnullを有効値から分ける。
		check( api.setOption( nullptr, WINHTTP_OPTION_AUTOLOGON_POLICY, nullptr, sizeof( value)) ==
				  FALSE &&
			  GetLastError() == ERROR_INVALID_PARAMETER && !state.safe) ;
		state.safe = true ;
		check( api.setOption( nullptr, WINHTTP_OPTION_AUTOLOGON_POLICY, &value, 0U) == FALSE &&
			  GetLastError() == ERROR_INVALID_PARAMETER && !state.safe) ;
		state.safe = true ;
		check( api.setOption( nullptr, WINHTTP_OPTION_AUTOLOGON_POLICY, &value, sizeof( value)) !=
				  FALSE &&
			  state.safe) ;
		fixture = nullptr ;
	}

	const drivercrate::CollectorInspectionSource source{
		L"https://maker.vendor.test/driver.html", L"maker.vendor.test",
		L"https://cdn.vendor.test/driver.zip", L"cdn.vendor.test",
		L"https://cdn.vendor.test/driver.zip"} ;	// 手動台帳の架空scope。
	check( drivercrate::validateCollectorInspectionSource( source)) ;
	const std::wstring anchor =
		L"<a href=\"" + source.href + L"\">driver</a>" ;	// 唯一の配布anchor。
	check( drivercrate::verifyCollectorInspectionLink( anchor, source)) ;
	// 非表示・非anchor・曖昧・引用符内のlinkは根拠にしない。
	for( const auto &html :
		{L"<!--" + anchor + L"-->", L"<script>" + anchor + L"</script>",
		 L"<style>" + anchor + L"</style>", L"<template>" + anchor + L"</template>",
		 L"<noscript>" + anchor + L"</noscript>", L"<textarea>" + anchor + L"</textarea>",
		 anchor + anchor, L"<div title='" + anchor + L"'>x</div>",
		 L"<a HREF=\"bad\" href=\"" + source.href + L"\">x</a>",
		 L"<script\t>" + anchor + L"</script>", L"<script/>" + anchor + L"</script>",
		 L"<plaintext>" + anchor, L"<a data-x=' href=\"" + source.href + L"\"'>x</a>"}) {
		check( !drivercrate::verifyCollectorInspectionLink( html, source)) ;
	}

	check( drivercrate::verifyCollectorInspectionLink( L"<script>x</script>" + anchor, source)) ;
	// URL、host、解決、同意queryの不正形を非通信で拒否する。
	for( std::size_t index = 0U; index < 5U; ++index) {
		auto invalid = source ;	// 正例から一条件だけ変更する。
		// 個別入力項目の拒否を独立に確認する。
		switch( index) {
			case 0U:	// 異なるhost名を許可しない。
				invalid.payloadHost = L"other.vendor.test" ;
				break ;

			case 1U:	// Queryを導線へ取り込まない。
				invalid.payloadUrl += L"?key=x" ;
				break ;

			case 2U:	// 相対schemeの補完をしない。
				invalid.href = L"//cdn.vendor.test/driver.zip" ;
				break ;

			case 3U:	// Suffix allowlistを許可しない。
				invalid.rootHost = L".vendor.test" ;
				break ;

			default:	// 別payloadへ取得を転用しない。
				invalid.href = L"/other.zip" ;
				break ;
		}

		check( !drivercrate::validateCollectorInspectionSource( invalid)) ;
	}

	// 実ファイルの共通取得・証拠発行をHTTPだけfakeにして確認する。
	for( std::size_t index = 0U; index < 18U; ++index) {
		Fixture state{{Response{"<a href=\"https://cdn.vendor.test/driver.zip\">driver</a>"},
					   Response{"abc"}}} ;	// 二応答。
		fixture = &state ;
		Cost cost ;											// 下記拒否case以外はunrestricted。
		auto scope = source ;								// 各fixtureの定義。成功値・認証は含めない。
		drivercrate::OfficialAcquisitionSession session ;	// 生存issuerの所有。
		drivercrate::OfficialDownloadWorkspace	workspace ;	// 試験fileだけを回収する。
		check( session.initialize( 6410U, {33554432U, 33554432U, 33554432U, 0U, 1U, 1U}) == 0) ;
		check( workspace.initialize( drivercrate::COLLECTOR_INSPECTION_PROVIDER_ID, 6410U) == 0) ;
		// 起点不一致・回線・private・MIME・途中故障を個別に注入する。
		switch( index) {
			case 1U:	// 起点link欠落を本体不適合へ変換しない。
				state.responses[0].body = "<a href=\"other.zip\">other</a>" ;
				break ;

			case 2U:	// 回線同意を合成しない。
				cost.value = drivercrate::OfficialNetworkCostKind::RESTRICTED ;
				break ;

			case 3U:	// HTTP前に全private宛先を拒否する。
				state.privateAddress = true ;
				break ;

			case 4U:	// HTML以外の起点はparserへ渡さない。
				state.responses[0].mime = L"application/octet-stream" ;
				break ;

			case 5U:	// 元HTTP故障を成功へ補完しない。
				state.failRead = true ;
				break ;

			case 6U:	// 304を実本文取得として扱わない。
				state.responses[0].status = 304U ;
				break ;

			case 7U:	// 同一origin redirect後も絶対hrefは有効。
				state.responses.insert(
					state.responses.begin(),
					Response{"", 302U, L"text/html", L"https://maker.vendor.test/renamed.html"}) ;
				break ;

			case 8U:	// Rootの別origin redirectを拒否する。
				state.responses[0].status	= 302U ;
				state.responses[0].location = L"https://foreign.vendor.test/page.html" ;
				break ;

			case 9U:	// 不明回線を自動承認しない。
				cost.value = drivercrate::OfficialNetworkCostKind::UNKNOWN ;
				break ;

			case 10U:	// 別sessionを起点GET前に拒否する。
				break ;

			case 11U:	// 相対hrefをredirect前baseで誤認しない。
				scope.payloadUrl		= L"https://maker.vendor.test/driver.zip" ;
				scope.payloadHost		= scope.rootHost ;
				scope.href				= L"driver.zip" ;
				state.responses[0].body = "<a href=\"driver.zip\">driver</a>" ;
				state.responses.insert(
					state.responses.begin(),
					Response{"", 302U, L"text/html", L"https://maker.vendor.test/new/page.html"}) ;
				break ;

			case 12U:	// Root成功後のprivate payload DNSを拒否する。
				state.privatePayload = true ;
				break ;

			case 13U:	// Payloadの別origin redirectを追跡しない。
				state.responses[1].status	= 302U ;
				state.responses[1].location = L"https://foreign.vendor.test/driver.zip" ;
				break ;

			case 14U:	// 不完全I/O表をnativeで補完しない。
				break ;

			case 15U:	// Charset省略のHTMLも同じ厳密UTF-8復号を通す。
				state.responses[0].mime = L"text/html" ;
				break ;

			case 16U:	// 省略許可を任意MIMEへ広げない。
				state.responses[0].mime = L"text/plain" ;
				break ;

			case 17U:	// Header省略時も非UTF-8 byteを拒否する。
				state.responses[0].mime = L"text/html" ;
				state.responses[0].body = std::string( 1U, static_cast<char>( 0xff)) ;
				break ;

			default:	// 同じ二GET・一scopeの正例。
				break ;
		}

		auto api = transport() ;	// 全fake表。欠損caseだけ一要素を落とす。
		// 欠損constructor表からnativeへfallbackしない。
		if( index == 14U) {
			api.open = nullptr ;
		}

		drivercrate::CollectorInspectionAcquisition adapter( std::move( api)) ;	// 全非通信。
		drivercrate::OfficialAcquisitionResult		result ;					// 成功／拒否を分離する。
		const auto									error =
			// 一回試行。
			adapter.acquire( index == 10U ? 6411U : 6410U, scope, session, workspace, cost, {},
							result) ;
		check( (error == 0) == (index == 0U || index == 7U || index == 15U)) ;
		check( adapter.sourceVerified() == (index == 0U || index == 7U || index == 15U)) ;
		check( state.safe && state.closed == state.opened) ;
		drivercrate::OfficialAcquiredFileEvidence evidence ;	// 公開boolからは作らない。
		check( (session.bindAcquiredFile( workspace, result.acquisitionId, evidence) == 0) ==
			  (index == 0U || index == 7U || index == 15U)) ;
		const auto sends = state.sends ;	// 同adapter再使用後の不変送信数。
		check( adapter.acquire( 6410U, source, session, workspace, cost, {}, result) != 0) ;
		check( state.sends == sends) ;
		check( index != 2U || (sends == 0U && state.dns == 0U)) ;
		check( index != 3U || sends == 0U) ;
	}

	fixture = nullptr ;
}

/** @brief 定義選択を実native I/Oへ再結合し、同processの取得証拠だけを発行します。 */
void runDefinitions()
{
	constexpr std::wstring_view guid =
		L"12345678-1234-1234-1234-123456789abc" ;	// 架空公開GUIDです。
	const std::wstring dialog =
		L"https://www.catalog.update.microsoft.com/DownloadDialog.aspx?updateIDs="
		L"%5B%7B%22size%22%3A0%2C%22languages%22%3A%22%22%2C%22uidInfo%22%3A%22" +
		std::wstring( guid) + L"%22%2C%22updateID%22%3A%22" + std::wstring( guid) +
		L"%22%7D%5D" ;	// 同一GUID一件の独立期待です。
	// 四fixtureはPUBLIC成功/偽anchor拒否/Catalog成功/混合GUID拒否です。
	for( std::size_t index = 0U; index < 5U; ++index) {
		Fixture state ;	// このcaseだけが所有する全fake I/Oです。
		fixture = &state ;
		drivercrate::CollectorDefinitionRequest definition ;	// 未認証選択に成功値はありません。
		definition.maximumBytes = 2ULL * 1024ULL * 1024ULL * 1024ULL ;
		definition.source		= {L"https://maker.vendor.test/drivers", L"maker.vendor.test",
								   L"https://cdn.vendor.test/driver.zip", L"cdn.vendor.test",
								   L"https://cdn.vendor.test/driver.zip"} ;
		state.responses = {Response{"<a href=\"https://cdn.vendor.test/driver.zip\">current</a>"},
						   Response{"abc"}} ;
		// 公開v queryを除去せず原anchorと同じURLへ結びます。
		if( index == 4U) {
			definition.source.href += L"?v=ab12CD" ;
			definition.source.payloadUrl = definition.source.href ;
			state.responses[0].body =
				"<a href=\"https://cdn.vendor.test/driver.zip?v=ab12CD\">current</a>" ;
		}

		// 取得metadataが選択と異なれば、その成功bool等を渡す余地はありません。
		if( index == 1U) {
			state.responses[0].body = "<a href=\"https://cdn.vendor.test/other.zip\">other</a>" ;
		}

		// Catalogは同検索/details/dialogの三原応答をfakeで渡します。
		if( index == 2U || index == 3U) {
			definition.protocol		   = drivercrate::CollectorDefinitionProtocol::CATALOG_SEARCH ;
			definition.source		   = {L"https://www.catalog.update.microsoft.com/",
										  L"www.catalog.update.microsoft.com",
										  L"https://cdn.vendor.test/driver.cab", L"cdn.vendor.test",
										  L"https://cdn.vendor.test/driver.cab"} ;
			definition.catalogUpdateId = guid ;
			definition.catalogSearchUrl =
				L"https://www.catalog.update.microsoft.com/Search.aspx?q=Fixture" ;
			definition.catalogDetailsUrl =
				L"https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=" +
				std::wstring( guid) ;
			definition.catalogDownloadUrl = dialog ;
			definition.publishedSha256 =
				L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ;
			state.responses = {
				Response{"<tr id=\"12345678-1234-1234-1234-123456789abc_R0\">Fixture 2.0.0.0</tr>"},
				Response{"Architecture: AMD64; Windows 10, Vibranium and later"},
				Response{
					"downloadInformation[0].files[0].url = 'https://cdn.vendor.test/driver.cab';\n"
					"downloadInformation[0].files[0].sha256 = 'ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=';"},
				Response{"abc"}} ;
			// 選択GUIDを含むだけの追加queryはmetadata要求前に拒否します。
			if( index == 3U) {
				definition.catalogDownloadUrl += L"&other=00000000-0000-0000-0000-000000000000" ;
			}
		}

		Cost cost ;											// 実cost APIへ接続しないunrestricted fixtureです。
		drivercrate::OfficialAcquisitionSession session ;	// このcaseの生存issuerです。
		drivercrate::OfficialDownloadWorkspace	workspace ;	// 正常fileだけを回収する所有領域です。
		check( session.initialize( 6680U, {definition.maximumBytes, definition.maximumBytes,
										 definition.maximumBytes, 0U, 1U, 1U}) == 0) ;
		check( workspace.initialize( drivercrate::COLLECTOR_INSPECTION_PROVIDER_ID, 6680U) == 0) ;
		drivercrate::CollectorInspectionAcquisition adapter(
			// 全HTTP/DNSをfakeへ固定します。
			transport()) ;
		drivercrate::OfficialAcquisitionResult result ;					// 内容検査成功と混同しない取得結果です。
		drivercrate::CollectorDefinitionMetadataObservation observed ;	// 同I/Oだけの実数です。
		const auto error = adapter.acquireDefinition( 6680U, definition, session, workspace, cost,
													 {}, result, observed) ;	// 一回試行です。
		const bool success =
			// 拒否fixtureはpayload未取得です。
			index == 0U || index == 2U || index == 4U ;
		check( (error == 0) == success) ;
		check( adapter.sourceVerified() == success) ;
		check( state.safe && state.opened == state.closed) ;
		check( state.sends == (index == 0U || index == 4U ? 2U
							  : index == 1U				 ? 1U
							  : index == 2U				 ? 4U
														 : 0U)) ;
		check( observed.requests == (index == 0U || index == 1U || index == 4U ? 1U
									: index == 2U							  ? 3U
																			  : 0U)) ;
		drivercrate::OfficialAcquiredFileEvidence evidence ;	// JSONから構築しません。
		check( (session.bindAcquiredFile( workspace, result.acquisitionId, evidence) == 0) ==
			  success) ;
		const auto sends = state.sends ;	// 再使用後も不変の要求数です。
		check( adapter.acquireDefinition( 6680U, definition, session, workspace, cost, {}, result,
										observed) != 0) ;
		check( state.sends == sends) ;
	}

	fixture = nullptr ;
}

/** @brief Intelの同page解析・両hash算法・候補変更拒否を実保存へ結びます。 */
void runDefinitionIntel()
{
	const std::string prefix =
		"<html><h1>Intel® Network Adapter Driver for Microsoft Windows 11*</h1>"
		"<p>Intel requires an accepted license agreement in order to download this file.</p>"
		"<h2>Available Downloads</h2><button data-href=\"https://downloadmirror.intel.com/900011/"
		"Wired_driver_31.2.2_x64.zip\">Wired_driver_31.2.2_x64.zip</button>"
		"<li>Windows 11 Family*</li><li>Size: 38.6 MB</li><li>" ;	// 原parser fixtureと同じ公開構造です。
	const std::string suffix =
		"</li><h2>Detailed Description</h2><p><strong>Driver Package:</strong> "
		"Wired_driver_31.2.2_x64.zip</p><h2>This download is valid for the product(s) listed below.</h2>"
		"<a>Intel® Ethernet Network Adapter E610-XT2</a></html>" ;	// 別product parserを使用しません。
	// SHA-256/SHA-512の二正例とURL/hash hint変更の二負例です。
	for( std::size_t index = 0U; index < 4U; ++index) {
		Fixture state ;	// 同runの二応答だけです。
		fixture			= &state ;
		state.responses = {
			Response{
				prefix +
				(index == 1U
					 ? "SHA512: ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
					 : "SHA256: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD") +
				suffix},
			Response{"abc"}} ;
		drivercrate::CollectorDefinitionRequest definition ;	// 同じ公開起点/候補以外を持ちません。
		definition.protocol		= drivercrate::CollectorDefinitionProtocol::INTEL_RELEASE ;
		definition.maximumBytes = 2ULL * 1024ULL * 1024ULL * 1024ULL ;
		definition.source		= {
			  L"https://www.intel.com/content/www/us/en/download/727998/intel-network-adapter-driver-for-microsoft-windows-11.html",
			  L"www.intel.com",
			  L"https://downloadmirror.intel.com/900011/Wired_driver_31.2.2_x64.zip",
			  L"downloadmirror.intel.com", L""} ;
		// 別payloadや原本文にない公表hashを実GETで救済しません。
		if( index == 2U) {
			definition.source.payloadUrl = L"https://downloadmirror.intel.com/900011/other.zip" ;
		}

		// Hintがある場合も同pageの原hashへ再結合します。
		if( index == 3U) {
			definition.publishedSha256 = std::wstring( 64U, L'0') ;
		}

		Cost cost ;											// 追加同意を偽造しないunrestricted fixtureです。
		drivercrate::OfficialAcquisitionSession session ;	// このrunの元issuerです。
		drivercrate::OfficialDownloadWorkspace	workspace ;	// 所有する試験fileです。
		check( session.initialize( 6681U, {definition.maximumBytes, definition.maximumBytes,
										 definition.maximumBytes, 0U, 1U, 1U}) == 0) ;
		check( workspace.initialize( drivercrate::COLLECTOR_INSPECTION_PROVIDER_ID, 6681U) == 0) ;
		drivercrate::CollectorInspectionAcquisition adapter(
			// WinHTTP/DNSを完全置換します。
			transport()) ;
		drivercrate::OfficialAcquisitionResult				result ;	// Hash検証後の取得結果です。
		drivercrate::CollectorDefinitionMetadataObservation observed ;	// Metadata I/O実数です。
		drivercrate::CollectorDefinitionPublicMetadata confirmed ;		// 公表値と取得証拠を区別します。
		const auto									   error =
			adapter.acquireDefinition( 6681U, definition, session, workspace, cost, {}, result,
									  observed, &confirmed) ;	// 一回だけです。
		// 失敗診断も本文/URL無しのcase番号と元HRESULTだけを保持します。
		if( (error == 0) != (index < 2U)) {
			std::printf( "Intel definition case %zu error 0x%08lx\n", index,
						static_cast<unsigned long>( error)) ;
		}

		check( (error == 0) == (index < 2U)) ;
		check( state.sends == (index < 2U ? 2U : 1U) && observed.requests == 1U) ;
		check( state.safe && state.opened == state.closed) ;
		drivercrate::OfficialAcquiredFileEvidence evidence ;	// 通常の生存sessionへだけ結びます。
		check( (session.bindAcquiredFile( workspace, result.acquisitionId, evidence) == 0) ==
			  (index < 2U)) ;
		check( index >= 2U || (confirmed.publishedSha256.empty() == (index == 1U) &&
							  confirmed.publishedSha512.empty() == (index == 0U))) ;
	}

	fixture = nullptr ;
}

/** @brief 公開model再照合→秘密POST→exact GETと元期限の拒否を非通信で検証します。 */
void runDefinitionModel()
{
	const std::string path =
		"/pub/ASUS/GamingNB/Image/Software/Firmware/17609/DriverV1.exe" ;	// 架空payloadです。
	const std::string hash =
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ;	// abcのSHA256です。
	// 正例、model/hash/期限/field/DNS中失効/後退/取消しを一条件ずつ変えます。
	for( std::size_t index = 0U; index < 10U; ++index) {
		Fixture state ;	// 全三要求の私有fakeです。
		state.model	   = true ;
		fixture		   = &state ;
		const auto api = "{\"Status\":\"SUCCESS\",\"Result\":{\"Model\":\"" +
						 std::string( index == 1U ? "OTHER" : "G614FR") +
						 "\",\"Obj\":[{\"Files\":[{\"DownloadUrl\":{\"Global\":\"" + path +
						 "\"},\"sha256\":\"" + hash + "\"}]}]}}" ;	// 実API構造だけです。
		const auto token = "{\"status\":200,\"result\":{\"signature\":\"Abc_-~\",\"expires\":\"" +
						   std::string( index == 2U ? "1029" : "1600") +
						   "\",\"keyPairId\":\"K123\"}}" ;	// 秘密値は合成です。
		state.responses			 = {Response{api, 200U, L"application/json; charset=utf-8"},
									Response{index == 3U ? "{\"status\":200,\"result\":{}}" : token, 200U,
											 L"application/json"},
									Response{"abc"}} ;
		state.expireOnPayloadDns = index == 4U ;
		// HTTP失敗の元statusも不適合や未送信へ置換しません。
		if( index == 9U) {
			state.responses[0].status = 503U ;
		}

		state.rollbackAfterPost = index == 5U ;
		drivercrate::CollectorDefinitionRequest definition ;	// 宣言だけに権限はありません。
		definition.protocol		   = drivercrate::CollectorDefinitionProtocol::MODEL_CDN ;
		definition.maximumBytes	   = 1024U ;
		definition.anonymousCdn	   = {L"G614FR", std::wstring( path.begin(), path.end()), L"asus"} ;
		definition.publishedSha256 = std::wstring( hash.begin(), hash.end()) ;
		definition.source		   = {L"https://www.asus.com/supportonly/g614fr/helpdesk_download/",
									  L"www.asus.com",
									  drivercrate::asusAnonymousCdnCanonicalUrl( definition.anonymousCdn),
									  L"dlcdnta.asus.com", L""} ;
		// 元APIの同file hashと違うhintではPOSTへ進みません。
		if( index == 8U) {
			definition.publishedSha256 = std::wstring( 64U, L'0') ;
		}

		// 元canonical queryを変更した場合はmetadata前に拒否します。
		if( index == 7U) {
			definition.source.payloadUrl += L"&extra=1" ;
		}

		Cost									cost ;		// 実回線照会は行いません。
		drivercrate::OfficialAcquisitionSession session ;	// 同一callerの生存issuerです。
		drivercrate::OfficialDownloadWorkspace	workspace ;	// 当該caseの所有fileだけです。
		check( session.initialize( 6682U, {1024U, 1024U, 1024U, 0U, 1U, 1U}) == 0) ;
		check( workspace.initialize( drivercrate::COLLECTOR_INSPECTION_PROVIDER_ID, 6682U) == 0) ;
		drivercrate::CollectorInspectionAcquisition adapter(
			// 実networkへfallbackしません。
			transport()) ;
		drivercrate::OfficialAcquisitionResult				result ;	// 取得と内容を分けた結果です。
		drivercrate::CollectorDefinitionMetadataObservation observed ;	// 秘密URLを含まない実数です。
		drivercrate::CollectorDefinitionPublicMetadata confirmed ;		// 元canonical URLだけを返します。
		const drivercrate::HttpCancellationCallback	   cancellation = [&]() {
			   return index == 6U && state.sends >= 2U ;
		} ; // POST応答中の停止です。
		const auto error =
			adapter.acquireDefinition( 6682U, definition, session, workspace, cost, cancellation,
									  result, observed, &confirmed) ;	// 一回試行です。
		check( (error == 0) == (index == 0U)) ;
		check( state.safe && state.opened == state.closed) ;
		const auto expected = index == 0U									? 3U
							  : (index == 1U || index == 8U || index == 9U) ? 1U
							  : index == 7U									? 0U
											: 2U ;	// 拒否はGET送信前です。
		check( state.sends == expected) ;
		check( observed.requests == (index == 0U ? 2U : expected)) ;
		check( index != 0U || state.methods == std::vector<std::wstring>{L"GET", L"POST", L"GET"}) ;
		check( index != 0U || confirmed.source.payloadUrl == definition.source.payloadUrl) ;
		drivercrate::OfficialAcquiredFileEvidence
			evidence ;	// 通常のissuerへ実fileだけを結合します。
		check( (session.bindAcquiredFile( workspace, result.acquisitionId, evidence) == 0) ==
			  (index == 0U)) ;
		check( index != 4U ||
			  (error == static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT)) &&
			   adapter.payloadTransfer().attemptedRequests() == 0U)) ;
		check( index != 5U || error == E_INVALIDARG) ;
		check( index != 6U ||
			  error == static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))) ;
		check( index != 9U || observed.httpStatus == 503U) ;
	}

	fixture = nullptr ;
}
} // namespace

/** @brief CLIから入力を受けず全非通信試験を行う。
 * @return 全合格0、拒否fixture不一致1。
 */
int main()
{
	const auto initialized =
		// 実collectorと同じCOM-only MTAです。
		CoInitializeEx( nullptr, COINIT_MULTITHREADED) ;
	// WinRTを追加初期化したfixtureだけの成功にしません。
	if( FAILED( initialized)) {
		return 2 ;
	}

	try {
		run() ;
		runDefinitions() ;
		runDefinitionIntel() ;
		runDefinitionModel() ;
		std::printf( "Collector inspection checks: %zu\n", checks) ;
		CoUninitialize() ;
		return 0 ;
	} catch( ...) {
		CoUninitialize() ;
		std::printf( "Collector inspection failed at check: %zu\n", checks) ;
		return 1 ;
	}
}
