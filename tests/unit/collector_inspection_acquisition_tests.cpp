//------------------------------------------------------------------------------
/**
 * @file collector_inspection_acquisition_tests.cpp
 * @brief 外部台帳の一回収集取得scopeを完全非通信で検証する独立試験。
 * @version 01.00.00
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
 * </pre>
 *
 * @note 全HTTP／DNSをfixtureへ置換し、実network・導入・Taskを使用しない。
 * @see docs/adr/0280-collector-scoped-inspection-acquisition.md
 */
//------------------------------------------------------------------------------
#include "platform/collector_inspection_acquisition.h"
#include "platform/official_download_workspace.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <optional>
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
	std::vector<Response> responses ;
	/// 完了した送信回数。未送信0。
	std::size_t			  sends{} ;
	/// 現本文の読取byte位置。
	std::size_t			  offset{} ;
	/// 作成したfake handle数。
	std::size_t			  opened{} ;
	/// 全fake handleの解放数。
	std::size_t			  closed{} ;
	/// 全resolver呼出し数。
	std::size_t			  dns{} ;
	/// trueなら一宛先をprivateにする。
	bool				  privateAddress{} ;
	/// trueなら二回目以降のpayload DNSだけprivateにする。
	bool				  privatePayload{} ;
	/// trueなら本文途中でReadDataを失敗させる。
	bool				  failRead{} ;
	/// 安全なtimeout・cookie・credential条件が維持された場合true。
	bool				  safe{true} ;
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
	api.openRequest = []( HINTERNET, LPCWSTR verb, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *,
						 DWORD) -> HINTERNET {
		fixture->safe &= std::wstring_view( verb) == L"GET" ;
		++fixture->opened ;
		return fixture ;
	} ;
	api.setTimeouts = []( HINTERNET, int resolve, int connect, int send, int receive) -> BOOL {
		fixture->safe &= resolve > 0 && connect > 0 && send > 0 && receive > 0 ;
		return TRUE ;
	} ;
	api.setOption = []( HINTERNET, DWORD option, LPVOID value, DWORD size) -> BOOL {
		fixture->safe &= value != nullptr && size == sizeof( DWORD) ;
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
		fixture->safe &= value.starts_with( L"Accept: ") || value == L"Cache-Control: no-cache\r\n" ;
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
	api.receiveResponse = []( HINTERNET, LPVOID) -> BOOL { return TRUE ; } ;
	api.queryHeaders	= []( HINTERNET, DWORD info, LPCWSTR, LPVOID output, LPDWORD size,
							 LPDWORD) -> BOOL {
		   const auto &response = fixture->responses.at( fixture->sends - 1U) ;	// 現hopの不変応答。
		   // Statusだけは数値として返す。
		   if( info == (WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER)) {
			   *static_cast<DWORD *>( output) = response.status ;
			   *size						 = sizeof( DWORD) ;
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
	api.utcNow = []() { return std::uint64_t{1000U} ; } ;
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
} // namespace

/** @brief CLIから入力を受けず全非通信試験を行う。
 * @return 全合格0、拒否fixture不一致1。
 */
int main()
{
	try {
		run() ;
		std::printf( "Collector inspection checks: %zu\n", checks) ;
		return 0 ;
	} catch( ...) {
		std::printf( "Collector inspection failed at check: %zu\n", checks) ;
		return 1 ;
	}
}
