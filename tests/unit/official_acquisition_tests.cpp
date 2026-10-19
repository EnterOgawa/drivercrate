//------------------------------------------------------------------------------
/**
 * @file official_acquisition_tests.cpp
 * @brief 公式file検査用取得境界単体試験実装。
 * @version 01.13.02
 * @date 2026/09/04
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Workspace DACL継承試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASUS有限取得接続試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Record限定grantの保護取得fixtureを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  Delegated GETの全hop非通信fixtureを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  OF05経路をIntel Windows 11 policyへ結合。
 * Ver.01.04.00 Shunji Ogawa  2026/09/15  OF06のopen redirectと循環拒否fixtureを追加。
 * Ver.01.05.00 Shunji Ogawa  2026/09/15  OF09のsize・hash・HTML本文拒否fixtureを追加。
 * Ver.01.06.00 Shunji Ogawa  2026/09/15  Delegated GETの共通User-Agent完全一致検証を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/09/23  固定／委譲取得のSHA-512一致・不一致・混在・回収を検証。
 * Ver.01.08.00 Shunji Ogawa  2026/09/23  非実行取得profileのfake転送と内容検査拒否を確認。
 * Ver.01.08.01 Shunji Ogawa  2026/10/02  AI依存を撤去し非AI共通処理と試験を維持。
 * Ver.01.09.00 Shunji Ogawa  2026/10/06  封印取得証拠の非通信所有権・改変・失効試験を追加。
 * Ver.01.10.00 Shunji Ogawa  2026/10/12  真署名索引から共通取得・検査と拒否の内部fixtureを追加。
 * Ver.01.11.00 Shunji Ogawa  2026/10/12  実worker commandから非空INF ZIPの内容結果まで確認。
 * Ver.01.12.00 Shunji Ogawa  2026/10/12  Grant後の内部例外失効・結果保持・新scanと停止を検証。
 * Ver.01.13.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.13.01 Shunji Ogawa  2026/10/12  正常候補helperを内部unit構成だけへ限定し独立取得targetを保持。
 * Ver.01.13.02 Shunji Ogawa  2026/10/12  取消しの実到達phaseと有限同期を条件別に検証。
 * </pre>
 *
 * @note Fake transportとcost readerを使用し、実network、実driver、実installへ依存せず検査用取得状態を検証します。
 */
//------------------------------------------------------------------------------

#include "official_acquisition_tests.h"
// 全低位fake依存を持つ通常unitだけが新候補fixtureをリンクする。
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
#include "signed_index_candidate_binding_tests.h"
#endif
#include "platform/official_record_utilities.h"
#include "platform/official_delegated_package_inspection.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/asus_package_acquisition.h"
#include "platform/official_acquisition.h"
#include "platform/official_delegated_package_inspection.h"
#include "platform/official_download_grant.h"
#include "platform/official_download_workspace.h"
#include "platform/secret_official_url.h"
#include "platform/signed_index_acquisition_adapter_internal.h"
#include "platform/provider_worker_index_internal.h"
#include "platform/signed_index_store.h"
#include "core/official_preparation_operation.h"
#include "test_framework.h"

#include <Windows.h>

#include <Aclapi.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <iostream>
#include <type_traits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <atomic>
#include <chrono>
#include <semaphore>
#include <thread>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 試験用境界定義。
//------------------------------------------------------------------------------

/**
 * @brief Delegated GET一hopの架空HTTP応答を表す。
 */
struct DelegatedHttpResponse {
	/// 応答status code。
	DWORD						status{HTTP_STATUS_OK} ;
	/// Redirect応答の絶対Location。最終応答では未指定。
	std::optional<std::wstring> location ;
	/// 最終応答で返す架空本文。
	std::string					body{"abc"} ;
	/// Content-Length文字列。未指定時はchunked相当。
	std::optional<std::wstring> declared{L"3"} ;
	/// 索引経路だけが照合する元最終Content-Type。
	std::optional<std::wstring> contentType{L"application/zip"} ;
} ;

/**
 * @brief 完全fakeの到達phaseを二thread間で有限に保持します。
 * @note 実workerと試験threadが共有所有し、取得authorityや成功結果を発行しません。
 */
struct WorkerAcquisitionPhase {
	/// Workerが指定した低位phaseへ到達したことを一度だけ通知します。
	std::binary_semaphore entered{0} ;
	/// 同operationへの取消し要求後に試験threadが一度だけ解除します。
	std::binary_semaphore released{0} ;
	/// Worker側の五秒待機が終了条件に達した場合trueです。
	std::atomic_bool	  timedOut{} ;

	/**
	 * @brief 現在workerの低位phaseを通知して有限な試験解除を待ちます。
	 * @return 五秒以内に解除された場合trueです。期限超過は観測を失敗へ残します。
	 * @note 同workerだけが一度呼び、lockや取得authorityを保持しません。
	 */
	[[nodiscard]] bool	  hold()
	{
		entered.release() ;
		const bool resumed =
			// 有限解除の実結果です。
			released.try_acquire_for( std::chrono::seconds{5}) ;
		timedOut.store( !resumed) ;
		return resumed ;
	}
} ;

/**
 * @brief Delegated GETの全WinHTTP呼出しを非通信で再現するfixtureである。
 */
struct DelegatedHttpFixture {
	/// 索引の各DNS address拒否試験だけで私設addressを返す指定。
	bool							   privateDns{} ;
	/// Request順に返す有限応答列。
	std::vector<DelegatedHttpResponse> responses{DelegatedHttpResponse{}} ;
	/// 現在responseの0起点index。送信前は最大値。
	std::size_t						   activeResponseIndex{std::numeric_limits<std::size_t>::max()} ;
	/// 現在本文で次に読み取るbyte位置。
	std::size_t						   bodyOffset{} ;
	/// 一回のReadDataで返すbyte上限。
	DWORD							   chunk{64U * 1'024U} ;
	/// Connectへ渡された架空host列。
	std::vector<std::wstring>		   connectedHosts ;
	/// OpenRequestへ渡された架空path／query列。
	std::vector<std::wstring>		   requestedPaths ;
	/// Local resolverへ渡された架空host列。
	std::vector<std::wstring>		   resolvedHosts ;
	/// Hop開始ごとに返す架空UTC秒列。
	std::vector<std::uint64_t> utcSeconds{20'010U, 20'010U, 20'010U, 20'010U, 20'010U, 20'010U} ;
	/// 次に返すUTC秒のindex。
	std::size_t				   utcIndex{} ;
	/// 作成したsession／connection／request handle数。
	std::uint32_t			   opened{} ;
	/// 解放した架空handle数。
	std::uint32_t			   closed{} ;
	/// Bodyなしで実行したGET送信数。
	std::uint32_t			   sends{} ;
	/// ReadData呼出し数。
	std::uint32_t			   reads{} ;
	/// 自動redirect禁止を設定した回数。
	std::uint32_t			   redirectDisabled{} ;
	/// HIGH auto-logon policyを設定した回数。
	std::uint32_t			   highLogon{} ;
	/// System proxy、HTTPS GET、headerなしbodyなしを維持した場合true。
	bool					   safeRequest{true} ;
	/// 1-basedで失敗させるReadData回数。0は失敗なし。
	std::uint32_t			   failReadAt{} ;
	/// 指定ReadData回数の直後に取消しを成立させる。0は取消しなし。
	std::uint32_t			   cancelAfterRead{} ;
	/// 取消しcallbackが返す現在値。
	bool					   cancellationRequested{} ;
	/// 実send開始後の返却前だけを保持する非authority callback。未指定なら保持しません。
	std::function<bool()>	   afterSend ;
} ;

// WinHttpOpenと注入clockから現在fixtureを解決する試験thread限定の借用先。
thread_local DelegatedHttpFixture  *activeDelegatedHttpFixture{} ;

/**
 * @brief Delegated GET専用の完全な非通信I/O表を作る。
 * @return WinHTTP、DNS、UTCの全境界を現在threadのfixtureへ委譲する表。
 * @pre 呼出しthreadのactiveDelegatedHttpFixtureは、そのworker停止まで所有するfixtureを指します。
 * @note Fake handleは同fixtureを借用し、全依存を置換してnative通信へfallbackしません。
 * 指定されたsend保持が五秒で解除されなければERROR_TIMEOUTを保持してFALSEを返します。
 */
[[nodiscard]] OfficialHttpTransport makeDelegatedHttpTransport()
{
	OfficialHttpTransport transport ;	// 全低位I/Oを以下のfakeで置換する結果。
	// System／per-user proxyを選択するsessionだけを架空作成する。
	transport.open = []( LPCWSTR userAgent, const DWORD access, LPCWSTR proxy, LPCWSTR bypass,
						DWORD flags) -> HINTERNET {
		auto &fixture = *activeDelegatedHttpFixture ;	// 試験scopeが所有する現在fixture。
		++fixture.opened ;
		fixture.safeRequest &= userAgent != nullptr &&
							   std::wstring_view( userAgent) ==
								   L"Mozilla/5.0 (compatible; DriverCrate/0.1.0; "
								   L"+https://github.com/EnterOgawa/drivercrate)" &&
							   access == WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY && proxy == nullptr &&
							   bypass == nullptr && flags == 0U ;
		return &fixture ;
	} ;
	// 検証済みhostへのHTTPS既定port接続を記録する。
	transport.connect = []( const HINTERNET session, LPCWSTR serverName, const INTERNET_PORT port,
						   const DWORD reserved) -> HINTERNET {
		auto &fixture = *static_cast<DelegatedHttpFixture *>( session) ;	// Sessionのfixture。
		++fixture.opened ;
		fixture.safeRequest &= port == INTERNET_DEFAULT_HTTPS_PORT && reserved == 0U ;
		fixture.connectedHosts.emplace_back( serverName) ;
		return &fixture ;
	} ;
	// BodyなしHTTPS GETのpathだけを試験内に記録する。
	transport.openRequest = []( const HINTERNET connection, LPCWSTR verb, LPCWSTR objectName,
							   LPCWSTR, LPCWSTR referer, LPCWSTR *,
							   const DWORD flags) -> HINTERNET {
		auto &fixture = *static_cast<DelegatedHttpFixture *>( connection) ;	// Connectionのfixture。
		++fixture.opened ;
		fixture.safeRequest &=
			std::wstring_view( verb) == L"GET" && referer == nullptr && flags == WINHTTP_FLAG_SECURE ;
		fixture.requestedPaths.emplace_back( objectName) ;
		return &fixture ;
	} ;
	// 全phaseが正の有限timeoutなら安全設定を維持する。
	transport.setTimeouts = []( const HINTERNET handle, const int resolve, const int connect,
							   const int send, const int receive) -> BOOL {
		auto &fixture = *static_cast<DelegatedHttpFixture *>( handle) ;	// Timeout対象fixture。
		fixture.safeRequest &= resolve > 0 && connect > 0 && send > 0 && receive > 0 &&
							   resolve <= 60'000 && connect <= 60'000 && send <= 60'000 &&
							   receive <= 60'000 ;
		return TRUE ;
	} ;
	// 自動redirect禁止とcredential非送信のHIGH policyだけを受理する。
	transport.setOption = []( const HINTERNET handle, const DWORD option, const LPVOID value,
							 const DWORD bytes) -> BOOL {
		auto &fixture = *static_cast<DelegatedHttpFixture *>( handle) ;	// Option対象fixture。
		fixture.safeRequest &= value != nullptr && bytes == sizeof( DWORD) ;
		const DWORD setting =
			// 固定option値。
			value == nullptr ? 0U : *static_cast<const DWORD *>( value) ;
		// ApplicationがLocationを検証するための自動redirect禁止を数える。
		if( option == WINHTTP_OPTION_REDIRECT_POLICY) {
			fixture.redirectDisabled += setting == WINHTTP_OPTION_REDIRECT_POLICY_NEVER ? 1U : 0U ;
			fixture.safeRequest &= setting == WINHTTP_OPTION_REDIRECT_POLICY_NEVER ;
		}
		// Dynamic targetへ既定credentialを送らないHIGH policyを数える。
		else if( option == WINHTTP_OPTION_AUTOLOGON_POLICY) {
			fixture.highLogon += setting == WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH ? 1U : 0U ;
			fixture.safeRequest &= setting == WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH ;
		} else {
			fixture.safeRequest = false ;
		}

		return TRUE ;
	} ;
	// 共通Accept以外のcredential、Cookie、Referer相当headerを拒否する。
	transport.addHeaders = []( const HINTERNET handle, LPCWSTR headers, const DWORD length,
							  const DWORD) -> BOOL {
		auto &fixture = *static_cast<DelegatedHttpFixture *>( handle) ;	// Header対象fixture。
		const std::wstring_view value( headers, length) ;				// 今回追加するheader。
		fixture.safeRequest &= value.starts_with( L"Accept: ") &&
							   value.find( L"Authorization:") == std::wstring_view::npos &&
							   value.find( L"Cookie:") == std::wstring_view::npos &&
							   value.find( L"Referer:") == std::wstring_view::npos ;
		return TRUE ;
	} ;
	// 任意bodyまたは個別headerなしの一回GETだけを次の応答へ進める。
	transport.sendRequest = []( const HINTERNET handle, LPCWSTR headers, const DWORD length,
							   LPVOID optional, const DWORD optionalLength, const DWORD totalLength,
							   const DWORD_PTR context) -> BOOL {
		auto &fixture = *static_cast<DelegatedHttpFixture *>( handle) ;	// 送信対象fixture。
		fixture.safeRequest &= headers == nullptr && length == 0U && optional == nullptr &&
							   optionalLength == 0U && totalLength == 0U && context == 0U ;
		// 用意した応答数を超える予期しない送信を失敗させる。
		if( fixture.sends >= fixture.responses.size()) {
			SetLastError( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
			return FALSE ;
		}

		fixture.activeResponseIndex = fixture.sends ;
		fixture.bodyOffset			= 0U ;
		++fixture.sends ;
		// 指定した取消し再現だけで送信開始済みphaseを保持し、期限超過を成功にしません。
		if( fixture.afterSend && !fixture.afterSend()) {
			SetLastError( ERROR_TIMEOUT) ;
			return FALSE ;
		}

		return TRUE ;
	} ;
	// Send成功済み応答だけを受信済みとして返す。
	transport.receiveResponse = []( const HINTERNET handle, LPVOID) -> BOOL {
		const auto &fixture = *static_cast<DelegatedHttpFixture *>( handle) ;	// 応答fixture。
		// 現在応答がなければ受信成功を返さない。
		if( fixture.activeResponseIndex >= fixture.responses.size()) {
			SetLastError( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
			return FALSE ;
		}

		return TRUE ;
	} ;
	// Status、Location、Content-LengthのWinHTTP二段階照会を再現する。
	transport.queryHeaders = []( const HINTERNET handle, const DWORD info, LPCWSTR, LPVOID output,
								LPDWORD bytes, LPDWORD headerIndex) -> BOOL {
		auto &fixture = *static_cast<DelegatedHttpFixture *>( handle) ;	// Header対象fixture。
		// 現在応答がなければheader値を返さない。
		if( fixture.activeResponseIndex >= fixture.responses.size() || bytes == nullptr) {
			SetLastError( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
			return FALSE ;
		}

		const DelegatedHttpResponse &response =
			fixture.responses[fixture.activeResponseIndex] ;	// 現在hopの応答。
		// Status codeは数値照会へ直接返す。
		if( info == (WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER)) {
			*static_cast<DWORD *>( output) = response.status ;
			*bytes						  = sizeof( DWORD) ;
			return TRUE ;
		}

		const std::optional<std::wstring> *value = nullptr ;	// 照会対象の任意header。
		// Redirect Locationを選択する。
		if( info == WINHTTP_QUERY_LOCATION) {
			value = &response.location ;
		}
		// 最終本文のContent-Lengthを選択する。
		else if( info == WINHTTP_QUERY_CONTENT_LENGTH) {
			value = &response.declared ;
		}
		// 索引の共通有限header readerだけへ一つのmedia typeを返す。
		else if( info == WINHTTP_QUERY_CONTENT_TYPE) {
			// 既に一headerを返したreaderへ重複を合成しない。
			if( headerIndex != nullptr && *headerIndex != 0U) {
				SetLastError( ERROR_WINHTTP_HEADER_NOT_FOUND) ;
				return FALSE ;
			}

			value = &response.contentType ;
		}

		// 未指定または対象外headerは欠損として返す。
		if( value == nullptr || !value->has_value()) {
			SetLastError( ERROR_WINHTTP_HEADER_NOT_FOUND) ;
			return FALSE ;
		}

		const DWORD required =	// 終端NULを含むheader byte数。
			static_cast<DWORD>( ((*value)->size() + 1U) * sizeof( wchar_t)) ;
		// 一段目または不足bufferには必要量だけを返す。
		if( output == nullptr || *bytes < required) {
			*bytes = required ;
			SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			return FALSE ;
		}

		std::memcpy( output, (*value)->c_str(), required) ;
		*bytes = required - sizeof( wchar_t) ;
		// 同名header反復readerだけへ前進を通知する。
		if( info == WINHTTP_QUERY_CONTENT_TYPE && headerIndex != nullptr) {
			++*headerIndex ;
		}

		return TRUE ;
	} ;
	// 現在本文の未読byte数を有限DWORDで返す。
	transport.queryAvailable = []( const HINTERNET handle, LPDWORD bytes) -> BOOL {
		auto &fixture = *static_cast<DelegatedHttpFixture *>( handle) ;	// 本文対象fixture。
		// 現在応答と出力先がなければ本文量を返さない。
		if( fixture.activeResponseIndex >= fixture.responses.size() || bytes == nullptr) {
			SetLastError( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
			return FALSE ;
		}

		const auto &body = fixture.responses[fixture.activeResponseIndex].body ;	// 現在の架空本文。
		*bytes			 = static_cast<DWORD>( body.size() - fixture.bodyOffset) ;
		return TRUE ;
	} ;
	// 現在本文をchunk上限までcopyし、部分成功後の故障と取消しを注入する。
	transport.readData = []( const HINTERNET handle, LPVOID buffer, const DWORD requested,
							LPDWORD received) -> BOOL {
		auto &fixture = *static_cast<DelegatedHttpFixture *>( handle) ;	// Read対象fixture。
		++fixture.reads ;
		// 指定回のAPI故障ではbyteを返さない。
		if( fixture.failReadAt == fixture.reads) {
			SetLastError( ERROR_WINHTTP_CONNECTION_ERROR) ;
			return FALSE ;
		}

		const auto &body = fixture.responses[fixture.activeResponseIndex].body ;	// 現在の架空本文。
		const DWORD copied = std::min( {requested, fixture.chunk,
									   // 実copy量。
									   static_cast<DWORD>( body.size() - fixture.bodyOffset)}) ;
		std::memcpy( buffer, body.data() + fixture.bodyOffset, copied) ;
		fixture.bodyOffset += copied ;
		*received = copied ;
		// 指定回の読取り後に次の保存前取消しを成立させる。
		if( fixture.cancelAfterRead == fixture.reads) {
			fixture.cancellationRequested = true ;
		}

		return TRUE ;
	} ;
	// 同じfake backendが作った所有handleの解放数を記録する。
	transport.closeHandle = []( const HINTERNET handle) -> BOOL {
		++static_cast<DelegatedHttpFixture *>( handle)->closed ;
		return TRUE ;
	} ;
	// 架空hostを一件のIPv4へ解決し、private名だけ10/8を返す。
	transport.resolveDestination = []( const std::wstring_view					   host,
									  std::vector<OfficialResolvedNetworkAddress> &addresses) {
		auto &fixture = *activeDelegatedHttpFixture ;	// Resolver対象fixture。
		fixture.resolvedHosts.emplace_back( host) ;
		addresses.clear() ;
		OfficialResolvedNetworkAddress address ;	// 一件だけ返す架空IPv4 address。
		address.family = OfficialNetworkAddressFamily::IPV4 ;
		// Private拒否fixtureのhostだけ10.0.0.1へ解決する。
		if( fixture.privateDns || host.find( L"private") != std::wstring_view::npos) {
			address.bytes[0] = std::byte{10U} ;
			address.bytes[3] = std::byte{1U} ;
		} else {
			address.bytes[0] = std::byte{8U} ;
			address.bytes[1] = std::byte{8U} ;
			address.bytes[2] = std::byte{8U} ;
			address.bytes[3] = std::byte{8U} ;
		}

		addresses.push_back( address) ;
		return static_cast<NativeError>( 0) ;
	} ;
	// 各hop直前にfixtureが用意したUTC秒を一回ずつ返す。
	transport.utcNow = []() {
		auto &fixture = *activeDelegatedHttpFixture ;	// 時計対象fixture。
		// 用意した回数を超えるhopは0時刻でfail-closedにする。
		if( fixture.utcIndex >= fixture.utcSeconds.size()) {
			return std::uint64_t{0U} ;
		}

		return fixture.utcSeconds[fixture.utcIndex++] ;
	} ;
	return transport ;
}

/**
 * @brief Memory上の架空byte列をfileへ保存する取得transportである。
 */
class FakeAcquisitionTransport final : public IOfficialAcquisitionTransport {
public:
	/**
	 * @brief 架空payloadを取得先fileへ保存する。
	 * 実networkを使用せず、partial file、取消し、例外を再現する。
	 * @param[in] url 検証対象の架空公式URL。
	 * @param[in] resourceId 検証対象のpayload resource ID。
	 * @param[in] maximumBytes 書込みを許可する上限byte数。
	 * @param[in] outputFile 呼出し側が所有する書込み先handle。
	 * @param[in] progressCallback 書込み後の確定進捗通知先。
	 * @param[in] cancellationCallback 書込み後の取消し確認先。
	 * @return 保存成功時は0、上限、書込み、取消し失敗時はHRESULT。
	 * @see drivercrate::IOfficialAcquisitionTransport::download
	 */
	[[nodiscard]] NativeError download(
		std::wstring_view url, std::wstring_view resourceId, std::uint64_t maximumBytes,
		HANDLE outputFile, const HttpDownloadProgressCallback &progressCallback,
		const HttpCancellationCallback &cancellationCallback) override ;

	/**
	 * @brief Claim済み架空grantから一回のGETを再現する。
	 * 秘密URLを保存せず、固定取得と同じbyte書込み・取消し・例外注入を使用する。
	 * @param[in,out] request Claim済みgrantを所有する一回request。
	 * @param[in] outputFile 呼出し側が所有する書込み先handle。
	 * @param[in] progressCallback 書込み後の確定進捗通知先。
	 * @param[in] cancellationCallback 書込み後の取消し確認先。
	 * @param[out] destinationEvidence 成功時に設定する架空public宛先根拠。
	 * @return 保存とgrant終端成功時は0、拒否、取消しまたは失敗時はHRESULT。
	 * @see drivercrate::IOfficialAcquisitionTransport::downloadDelegated
	 */
	[[nodiscard]] NativeError downloadDelegated(
		OfficialDelegatedGetRequest &request, HANDLE outputFile,
		const HttpDownloadProgressCallback &progressCallback,
		const HttpCancellationCallback	   &cancellationCallback,
		OfficialPublicDestinationEvidence  &destinationEvidence) override ;

	/**
	 * @brief 架空の公式取得根拠を照合する。
	 * 引数はsession側の伝達確認に使用し、実ledgerは参照しない。
	 * @param[in] scanSessionId 呼出し側が照合するsession ID。
	 * @param[in] providerId 呼出し側が照合するProvider ID。
	 * @param[in] resourceId 呼出し側が照合するresource ID。
	 * @return 設定上、取得根拠がある場合は`true`。
	 * @see drivercrate::IOfficialAcquisitionTransport::hasSourceEvidence
	 */
	[[nodiscard]] bool hasSourceEvidence( ScanSessionId scanSessionId, std::wstring_view providerId,
										 std::wstring_view resourceId) const noexcept override ;

	/// Fileへ保存する架空payload byte列。
	std::string		   bytes{"abc"} ;
	/// trueの場合だけ公式取得根拠を返す。
	bool			   evidence{true} ;
	/// trueの場合は書込み後に取消しを確認する。
	bool			   cancelAfterWrite{} ;
	/// trueの場合は書込み後に架空例外を送出する。
	bool			   throwAfterWrite{} ;
	/// 実際に開始したdownload呼出し数。
	std::uint32_t	   downloadCalls{} ;
	/// Record限定downloadを開始した回数。
	std::uint32_t	   delegatedDownloadCalls{} ;
	/// 直近downloadへ渡された有限受信上限byte数。
	std::uint64_t	   lastMaximumBytes{} ;
} ;

/**
 * @brief 設定済みnetwork costとerrorを返す差替え境界である。
 */
class FakeNetworkCostReader final : public IOfficialNetworkCostReader {
public:
	/**
	 * @brief 設定済みnetwork costを返す。
	 * OS設定へ依存せずcost成功、不明、失敗経路を再現する。
	 * @param[out] cost 設定済みcost分類。
	 * @return 設定済みの成功値またはHRESULT。
	 * @see drivercrate::IOfficialNetworkCostReader::read
	 */
	[[nodiscard]] NativeError read( OfficialNetworkCostKind &cost) noexcept override ;

	/// 呼出し時に返すcost分類。
	OfficialNetworkCostKind	  configuredCost{OfficialNetworkCostKind::UNRESTRICTED} ;
	/// 呼出し時に返す診断値。
	NativeError				  configuredError{} ;
	/// 実行されたcost照会回数。
	std::uint32_t			  readCalls{} ;
} ;

//------------------------------------------------------------------------------
// 試験用境界実装。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_acquisition_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError FakeAcquisitionTransport::download( const std::wstring_view			   url,
											   const std::wstring_view			   resourceId,
											   const std::uint64_t				   maximumBytes,
											   const HANDLE						   outputFile,
											   const HttpDownloadProgressCallback &progressCallback,
											   const HttpCancellationCallback &cancellationCallback)
{
	static_cast<void>( url) ;
	static_cast<void>( resourceId) ;
	++downloadCalls ;
	lastMaximumBytes = maximumBytes ;
	// 架空payloadも取得上限とWin32書込み長の双方を超えないよう制限する。
	if( bytes.size() > maximumBytes || bytes.size() > std::numeric_limits<DWORD>::max()) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
	}

	DWORD written{} ;	// WriteFileが保存した架空payload byte数。
	// 架空payloadの保存失敗を実際のWin32診断値で返す。
	if( WriteFile( outputFile, bytes.data(), static_cast<DWORD>( bytes.size()), &written, nullptr) ==
	   FALSE) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
	}

	// APIが成功しても全byteを書き込めなければ短い書込みとして拒否する。
	if( written != static_cast<DWORD>( bytes.size())) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_WRITE_FAULT)) ;
	}

	progressCallback( bytes.size(), bytes.size()) ;
	// 書込み後の転送例外を注入して部分fileのcleanupを検証する。
	if( throwAfterWrite) {
		throw std::runtime_error( "fictional transport failure") ;
	}

	// 書込み後の取消要求を注入し、取得成功へ進まない経路を検証する。
	if( cancelAfterWrite && cancellationCallback && cancellationCallback()) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_acquisition_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError FakeAcquisitionTransport::downloadDelegated(
	OfficialDelegatedGetRequest &request, const HANDLE outputFile,
	const HttpDownloadProgressCallback &progressCallback,
	const HttpCancellationCallback	   &cancellationCallback,
	OfficialPublicDestinationEvidence  &destinationEvidence)
{
	destinationEvidence = {} ;
	++delegatedDownloadCalls ;
	std::wstring_view exactTarget ;									// Request開始時だけ借用する秘密URL view。
	const NativeError beginError = request.beginGet( exactTarget) ;	// 一回GET開始結果。
	// Grantから秘密URLを開始できない場合は書込みを行わない。
	if( beginError != 0) {
		return beginError ;
	}

	const NativeError downloadError =
		download( exactTarget, request.payloadResourceId(), request.maximumBytes(), outputFile,
				 progressCallback, cancellationCallback) ;	// 共通の架空書込み結果。
	// 取消しと通常失敗をgrantの一回終端へ確定する。
	if( downloadError != 0) {
		const OfficialDownloadGrantState outcome =
			downloadError == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))
				? OfficialDownloadGrantState::CANCELLED
				: OfficialDownloadGrantState::FAILED ;								// 返却errorに対応する終端状態。
		const NativeError finishError = request.finish( outcome, downloadError) ;	// Grant終端結果。
		return finishError == 0 ? downloadError : finishError ;
	}

	const NativeError finishError =	// 保存済みfileへ結合するgrant成功終端結果。
		request.finish( OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION, 0) ;
	// Grantを成功終端できなければpublic宛先根拠を作らない。
	if( finishError != 0) {
		return finishError ;
	}

	destinationEvidence.addressCount	= 1U ;
	destinationEvidence.locallyResolved = true ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_acquisition_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool FakeAcquisitionTransport::hasSourceEvidence( const ScanSessionId	 scanSessionId,
												 const std::wstring_view providerId,
												 const std::wstring_view resourceId) const noexcept
{
	static_cast<void>( scanSessionId) ;
	static_cast<void>( providerId) ;
	static_cast<void>( resourceId) ;
	return evidence ;
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_acquisition_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError FakeNetworkCostReader::read( OfficialNetworkCostKind &cost) noexcept
{
	++readCalls ;
	cost = configuredCost ;
	return configuredError ;
}

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 単体試験用の有限取得予算を生成する。
 *
 * Testごとに必要な項目だけを上書きできる既定値を返す。
 * @return 小さい架空payload用のfile、Provider、session上限。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialAcquisitionLimits makeLimits() noexcept
{
	return OfficialAcquisitionLimits{.maximumFileBytes	   = 64U,
									 .maximumProviderBytes = 128U,
									 .maximumSessionBytes  = 256U,
									 .minimumFreeBytes	   = 0U,
									 .maximumProviderFiles = 4U,
									 .maximumSessionFiles  = 8U} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 単体試験用の公式payload取得要求を生成する。
 *
 * 文字列を所有せず、呼出し元test scope内だけ参照する。
 *
 * @param[in] providerId 組み込み公式Provider stable ID。
 * @param[in] url Fake transportへ渡す公式形式URL。
 * @param[in] fileName 保護workspace内の安全な相対file名。
 * @return Payload用途と64 byte上限を持つ取得要求。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialAcquisitionRequest makeRequest( const std::wstring_view providerId,
													 const std::wstring_view url,
													 const std::wstring_view fileName) noexcept
{
	return OfficialAcquisitionRequest{.url				 = url,
									  .providerId		 = providerId,
									  .resourceId		 = OFFICIAL_PAYLOAD_RESOURCE_ID,
									  .workspaceFileName = fileName,
									  .maximumFileBytes	 = 64U} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Acquisition試験用のRecord限定grantを発行する。
 * @param[out] grant 成功時に未使用grantを所有するobject。
 * @param[in] session Grantとroot evidenceを結合するscan session ID。
 * @param[in] grantId Session内で一意なopaque grant ID。
 * @param[in] recordEvidenceId Session内で一意なrecord証拠ID。
 * @param[in] publishedSha256 架空payloadに対して公開する64桁SHA-256。
 * @param[in] targetUrl Worker内だけで所有する架空完全URL。
 * @param[in] externalExpiryUtcSeconds 認識済み外部expiry。通常URLは未指定。
 * @param[in] publishedSizeBytes Recordが公開するexact byte数。
 * @param[in] publishedSha512 任意の公開SHA-512。
 * @param[in] downloadOnlyProfile 取得専用EXEへ変更する明示profile。既定は無効。
 * @return Record検証とgrant発行の成功時は0、失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError issueDelegatedGrant(
	RecordScopedDownloadGrant &grant, const ScanSessionId session, const std::uint64_t grantId,
	const std::uint64_t recordEvidenceId, std::wstring publishedSha256,
	std::wstring targetUrl = L"https://temporary.fixture.invalid/driver.zip?token=never-publish",
	const std::optional<std::uint64_t> externalExpiryUtcSeconds = std::nullopt,
	const std::uint64_t publishedSizeBytes = 3U, std::wstring publishedSha512 = {},
	const OfficialDownloadOnlyProfile downloadOnlyProfile = OfficialDownloadOnlyProfile::DISABLED)
{
	OfficialDistributionRecord record ;	// 架空Intel rootと一payloadを所有する型付きrecord。
	record.rootEvidence = OfficialSourceEvidence{
		.scanSessionId			= session,
		.acquisitionId			= recordEvidenceId + 100U,
		.providerId				= std::wstring{INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID},
		.policyId				= std::wstring{INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID},
		.resourceId				= std::wstring{OFFICIAL_LANDING_RESOURCE_ID},
		.redirectCount			= 0U,
		.originPolicyIndices	= {0U},
		.acquisition			= MeasurementAcquisition::NETWORK_BODY,
		.bodyAcquiredUtcSeconds = 19'000U,
		.originValidatedUtcSeconds = 19'001U,
		.cachePermitted			   = false} ;
	record.recordEvidenceId = recordEvidenceId ;
	record.parserId			= L"acquisition-fixture-parser-v1" ;
	record.parserRevision	= 1U ;
	record.recordRoute		= L"acquisition-fixture-route" ;
	record.recordKey		= L"acquisition-fixture-record" ;
	record.productFamily	= L"Fictional Ethernet Family" ;
	record.operatingSystem	= L"Windows 11 x64" ;
	record.architecture		= OfficialDistributionArchitecture::WINDOWS_X64 ;
	record.packageVersion	= L"1.0.0" ;
	record.publishedDate	= L"2026-09-01" ;
	record.terms			= OfficialDistributionTerms::CONFIRMED_NO_CONSENT ;
	record.payloads.push_back( OfficialDistributionPayloadRecord{
		.resourceId				  = std::wstring{OFFICIAL_PAYLOAD_RESOURCE_ID},
		.payloadOrdinal			  = 0U,
		.kind					  = OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE,
		.fileDisplayName		  = L"fictional-driver.zip",
		.publishedSizeBytes		  = publishedSizeBytes,
		.publishedSha256		  = std::move( publishedSha256),
		.publishedSha512		  = std::move( publishedSha512),
		.publisher				  = L"Fictional Device Vendor",
		.expectedContentType	  = L"application/zip",
		.maximumBytes			  = 64U,
		.externalExpiryUtcSeconds = externalExpiryUtcSeconds,
		.targetUrl				  = SecretOfficialUrl{std::move( targetUrl)}}) ;
	record.resolvedUtcSeconds = 19'002U ;
	// 明示したfixtureだけをEXE取得専用へ変換する。
	if( downloadOnlyProfile != OfficialDownloadOnlyProfile::DISABLED) {
		auto &payload				= record.payloads.front() ;	// 架空EXEのmetadata。
		payload.kind				= OfficialDistributionPayloadKind::OFFICIAL_INSTALLER ;
		payload.fileDisplayName		= L"fictional-driver.exe" ;
		payload.expectedContentType = L"application/octet-stream" ;
		// 不正profileを既存ZIPへfallbackしない。
		if( !setOfficialDownloadOnlyProfile( payload, downloadOnlyProfile)) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}
	}

	OfficialDistributionRecordEvidence evidence ;			// URL非保持のrecord検証結果。
	const NativeError				   validationError =	// Grant発行前のrecord検証結果。
		validateOfficialDistributionRecord( record, evidence) ;
	// 不正recordからgrantを発行しない。
	if( validationError != 0) {
		return validationError ;
	}

	return grant.issue( record, evidence, 0U, grantId, 20'000U, 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Record限定grantだけを権限として持つ取得要求を作る。
 * @param[in,out] grant 取得完了まで生存する未使用grant。
 * @param[in] grantId 利用者選択が保持するopaque grant ID。
 * @param[in] fileName 保護workspace内の安全な相対file名。
 * @param[in] nowUtcSeconds Claim直前に返す架空UTC秒。
 * @return 固定URL、Provider、resource、size、hashを持たない委譲要求。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialAcquisitionRequest makeDelegatedRequest(
	RecordScopedDownloadGrant &grant, const std::uint64_t grantId, const std::wstring_view fileName,
	const std::uint64_t nowUtcSeconds = 20'010U)
{
	return OfficialAcquisitionRequest{
		.workspaceFileName = fileName,
		.delegatedGrant	   = &grant,
		.delegatedGrantId  = grantId,
		.delegatedUtcNow   = [nowUtcSeconds]() { return nowUtcSeconds ; }} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 非通信HTTP fixtureをRecord限定Acquisitionへ一回接続する。
 * @param[in,out] fixture WinHTTP、DNS、時計と応答列を所有するfixture。
 * @param[in] sessionId 新規workspaceと取得ledgerのscan session ID。
 * @param[in] grantId 発行して選択するopaque grant ID。
 * @param[in] recordEvidenceId 発行元recordのopaque証拠ID。
 * @param[in] fileName 保護workspace内の安全な相対file名。
 * @param[in] targetUrl Grantだけが所有する架空完全URL。
 * @param[out] workspace 成功fileを保持し、失敗時の削除を照合する領域。
 * @param[out] session 成功容量を保持するAcquisition ledger。
 * @param[out] grant 取得終端状態を保持する一回grant。
 * @param[out] result AcquisitionのURL非保持結果。
 * @param[in] publishedSha256 空なら`abc`のSHA-256、非空ならrecordへ固定する公開値。
 * @param[in] publishedSizeBytes Recordが公開するexact byte数。
 * @return 初期化、grant発行、取得の最初の失敗、または全成功時0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError runDelegatedHttpAcquisition(
	DelegatedHttpFixture &fixture, const ScanSessionId sessionId, const std::uint64_t grantId,
	const std::uint64_t recordEvidenceId, const std::wstring_view fileName, std::wstring targetUrl,
	OfficialDownloadWorkspace &workspace, OfficialAcquisitionSession &session,
	RecordScopedDownloadGrant &grant, OfficialAcquisitionResult &result,
	std::wstring publishedSha256 = {}, const std::uint64_t publishedSizeBytes = 3U)
{
	const NativeError workspaceError =	// 一件のHTTP fixture専用workspace開始結果。
		workspace.initialize( L"delegated-http-test", sessionId) ;
	// Workspaceを保護できなければfile取得を開始しない。
	if( workspaceError != 0) {
		return workspaceError ;
	}

	const NativeError sessionError =
		// Ledger開始結果。
		session.initialize( sessionId, makeLimits()) ;
	// 有限予算を開始できなければgrantを発行しない。
	if( sessionError != 0) {
		return sessionError ;
	}

	// 公開値が指定されない通常fixtureだけ`abc`の既知SHA-256を使用する。
	if( publishedSha256.empty()) {
		publishedSha256 = L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ;
	}

	const NativeError issueError =	// 架空recordから一回grantを発行した結果。
		issueDelegatedGrant( grant, sessionId, grantId, recordEvidenceId, std::move( publishedSha256),
							std::move( targetUrl), std::nullopt, publishedSizeBytes) ;
	// Recordまたはgrant検証が失敗した場合はHTTP clientを作らない。
	if( issueError != 0) {
		return issueError ;
	}

	activeDelegatedHttpFixture = &fixture ;
	OfficialHttpClient client( makeDelegatedHttpTransport()) ;	// Production検証を使う非通信client。
	OfficialHttpAcquisitionTransport transport( client) ;		// AcquisitionへのHTTP adapter。
	FakeNetworkCostReader			 costReader ;				// 無制限networkを返すcost境界。
	const OfficialAcquisitionRequest request =
		// URL非保持の委譲要求。
		makeDelegatedRequest( grant, grantId, fileName) ;
	const NativeError acquisitionError = session.acquire(
		request, workspace, transport, costReader, []( const std::uint64_t, const std::uint64_t) {},
		[&fixture]() { return fixture.cancellationRequested ; }, result) ;	// 統合取得結果。
	activeDelegatedHttpFixture = nullptr ;
	return acquisitionError ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定pathにfileが存在するか確認する。
 *
 * Cleanup結果だけを確認し、pathをtest出力へ記録しない。
 *
 * @param[in] path Workspace内の絶対file path。
 * @return 通常fileまたはdirectoryが存在する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool fileExists( const std::wstring &path) noexcept
{
	return GetFileAttributesW( path.c_str()) != INVALID_FILE_ATTRIBUTES ;
}

//------------------------------------------------------------------------------
/**
 * @brief Workspace要素の保護DACLを検証する。
 *
 * SDDL文字列を比較せず、OSが構築したACEと継承flagを検証する。
 *
 * @param[in] path Workspace内のfileまたはdirectory絶対path。
 * @param[in] inheritanceRequired 子へのACE継承を要求する場合true。
 * @return SYSTEM／Administratorsだけの保護DACLなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasRestrictedWorkspaceAcl( std::wstring path, const bool inheritanceRequired)
{
	PACL				 discretionaryAcl{} ;	// Security descriptor内の非所有DACL pointer。
	PSECURITY_DESCRIPTOR descriptor{} ;			// LocalFreeで解放する取得descriptor。
	const DWORD			 queryError =
		GetNamedSecurityInfoW( path.data(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
							  nullptr, &discretionaryAcl, nullptr, &descriptor) ;	// DACL取得結果。
	// DACL照会成功と期待する二件のACEを確認した初期検証状態。
	bool valid = queryError == ERROR_SUCCESS && descriptor != nullptr &&
				 discretionaryAcl != nullptr && discretionaryAcl->AceCount == 2U ;
	SECURITY_DESCRIPTOR_CONTROL control{} ;		// DACL保護flagを含むdescriptor control。
	DWORD						revision{} ;	// GetSecurityDescriptorControlが返すrevision。
	// DACLが継承から保護されていない場合はworkspaceの保護検証を失敗とする。
	if( valid && (GetSecurityDescriptorControl( descriptor, &control, &revision) == FALSE ||
				 (control & SE_DACL_PROTECTED) == 0U)) {
		valid = false ;
	}

	// SYSTEMのwell-known SIDを生成する、DWORD alignmentを持つbuffer。
	std::array<DWORD, SECURITY_MAX_SID_SIZE / sizeof( DWORD)> systemSidBuffer{} ;
	DWORD													 systemSidSize =
		// SYSTEM SID受信buffer byte数。
		static_cast<DWORD>( sizeof( systemSidBuffer)) ;
	PSID systemSid = systemSidBuffer.data() ;	// EqualSidへ渡すSYSTEM SID。
	// Administratorsのwell-known SIDを生成する、DWORD alignmentを持つbuffer。
	std::array<DWORD, SECURITY_MAX_SID_SIZE / sizeof( DWORD)> administratorsSidBuffer{} ;
	DWORD administratorsSidSize = static_cast<DWORD>(
		// Administrators SID受信buffer byte数。
		sizeof( administratorsSidBuffer)) ;
	PSID administratorsSid = administratorsSidBuffer.data() ;	// EqualSidへ渡すAdministrators SID。
	// 許可対象の既知SIDを構築できなければACL比較を成立としない。
	if( valid &&
	   (CreateWellKnownSid( WinLocalSystemSid, nullptr, systemSid, &systemSidSize) == FALSE ||
		CreateWellKnownSid( WinBuiltinAdministratorsSid, nullptr, administratorsSid,
						   &administratorsSidSize) == FALSE)) {
		valid = false ;
	}

	bool systemFound{} ;			// SYSTEM full access ACEを確認した場合true。
	bool administratorsFound{} ;	// Administrators full access ACEを確認した場合true。
	// 二つの許可ACEだけを走査し、未知SID、deny、権限不足を拒否する。
	for( DWORD index = 0U; valid && index < discretionaryAcl->AceCount; ++index) {
		void *rawAce{} ;	// GetAceが返すdescriptor内の非所有ACE pointer。
		// ACEを読み取れないACLを検証済みとして扱わない。
		if( GetAce( discretionaryAcl, index, &rawAce) == FALSE || rawAce == nullptr) {
			valid = false ;
			break ;
		}

		const auto *header = static_cast<const ACE_HEADER *>( rawAce) ;	// ACE共通header。
		const BYTE	requiredFlags =
			// 子へ必要な継承flag。
			static_cast<BYTE>( OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) ;
		// 許可ACE以外や必要な継承flagを持たないACEを拒否する。
		if( header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
		   (inheritanceRequired && (header->AceFlags & requiredFlags) != requiredFlags)) {
			valid = false ;
			break ;
		}

		const auto *allowed = static_cast<const ACCESS_ALLOWED_ACE *>( rawAce) ;	// 許可ACE。
		// 期待する完全access権限と異なるACEを拒否する。
		if( allowed->Mask != FILE_ALL_ACCESS) {
			valid = false ;
			break ;
		}

		PSID aceSid = const_cast<DWORD *>( &allowed->SidStart) ;	// Descriptor内の非所有SID。
		// SYSTEMのACEを識別し、期待する主体の存在を集約する。
		if( EqualSid( aceSid, systemSid) != FALSE) {
			// SYSTEMのACEが重複する構成を期待どおりのDACLとして扱わない。
			if( systemFound) {
				valid = false ;
			}

			systemFound = true ;
		}
		// AdministratorsのACEを識別し、期待する主体の存在を集約する。
		else if( EqualSid( aceSid, administratorsSid) != FALSE) {
			// AdministratorsのACEが重複する構成を期待どおりのDACLとして扱わない。
			if( administratorsFound) {
				valid = false ;
			}

			administratorsFound = true ;
		} else {
			valid = false ;
		}
	}

	// APIから受け取ったsecurity descriptorがある場合にだけ解放する。
	if( descriptor != nullptr) {
		static_cast<void>( LocalFree( descriptor)) ;
	}

	return valid && systemFound && administratorsFound ;
}

//------------------------------------------------------------------------------
/**
 * @brief Workspaceのroot／子要素DACL継承を検証する。
 *
 * 外部writerが作成するfileまで保護DACLを継承することを実物確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testWorkspaceSecurity( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// DACL検証対象の一時workspace。
	// ACL試験用の保護workspaceを開始した結果。
	const NativeError		  initializeError = workspace.initialize( L"acl-test", 8'801U) ;
	DRIVERCRATE_EXPECT( context, initializeError == 0) ;
	// 保護workspaceを初期化できなければACLの詳細検証を続けない。
	if( initializeError != 0) {
		return ;
	}

	const std::wstring rootProbe	 = workspace.path( L"root-probe.bin") ;	// Root取得用path。
	const std::size_t  rootSeparator = rootProbe.find_last_of( L'\\') ;		// Root終端位置。
	DRIVERCRATE_EXPECT( context, rootSeparator != std::wstring::npos) ;
	// rootの区切りを取得できない場合は不正な部分pathを構築しない。
	if( rootSeparator == std::wstring::npos) {
		return ;
	}

	const std::wstring root = rootProbe.substr( 0U, rootSeparator) ;	// Workspace root path。
	DRIVERCRATE_EXPECT( context, hasRestrictedWorkspaceAcl( root, true)) ;

	HANDLE file{INVALID_HANDLE_VALUE} ;	// Workspaceからownershipを受け取る試験file handle。
	// 入れ子directory配下の試験fileを作成した結果。
	const NativeError createError = workspace.createFile( L"nested\\probe.bin", file) ;
	DRIVERCRATE_EXPECT( context, createError == 0) ;
	// 試験fileを作成できなければ子要素ACLの検証を中止する。
	if( createError != 0) {
		return ;
	}

	const BOOL closeSucceeded = CloseHandle( file) ;	// DACL照会前のhandle close結果。
	DRIVERCRATE_EXPECT( context, closeSucceeded != FALSE) ;

	const std::wstring filePath		 = workspace.path( L"nested\\probe.bin") ;	// 子file絶対path。
	const std::size_t  fileSeparator = filePath.find_last_of( L'\\') ;			// 子directory終端位置。
	DRIVERCRATE_EXPECT( context, fileSeparator != std::wstring::npos) ;
	// fileの親directoryを分離できなければ誤った対象のACLを調べない。
	if( fileSeparator == std::wstring::npos) {
		return ;
	}

	const std::wstring nestedDirectory =
		// 明示DACLを持つ子directory。
		filePath.substr( 0U, fileSeparator) ;
	DRIVERCRATE_EXPECT( context, hasRestrictedWorkspaceAcl( nestedDirectory, true)) ;
	DRIVERCRATE_EXPECT( context, hasRestrictedWorkspaceAcl( filePath, false)) ;

	std::wstring	  externalPath ;	// 外部writerが新規作成する予約済み絶対path。
	// 外部APIへ渡す未作成file pathを保護領域内へ予約した結果。
	const NativeError prepareError =
		workspace.prepareExternalFile( L"external\\probe.bin", externalPath) ;
	DRIVERCRATE_EXPECT( context, prepareError == 0) ;
	// 外部展開先を予約できなければ書込みを開始しない。
	if( prepareError != 0) {
		return ;
	}

	HANDLE externalFile =	// SetupAPI相当でsecurity attributesを直接指定しないfile。
		CreateFileW( externalPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW,
					FILE_ATTRIBUTE_NORMAL, nullptr) ;
	DRIVERCRATE_EXPECT( context, externalFile != INVALID_HANDLE_VALUE) ;
	// 試験用外部fileを開けなかった場合は予約を破棄して検証を中止する。
	if( externalFile == INVALID_HANDLE_VALUE) {
		static_cast<void>( workspace.discardFile( L"external\\probe.bin")) ;
		return ;
	}

	const BOOL externalCloseSucceeded = CloseHandle( externalFile) ;	// 所有handleのclose結果。
	DRIVERCRATE_EXPECT( context, externalCloseSucceeded != FALSE) ;
	const NativeError adoptError =
		// 同期外部writer完了結果。
		workspace.adoptFile( L"external\\probe.bin", 0U) ;
	DRIVERCRATE_EXPECT( context, adoptError == 0) ;
	// 保護領域への取込み成功後にだけ外部生成fileのACLを検証する。
	if( adoptError == 0) {
		DRIVERCRATE_EXPECT( context, hasRestrictedWorkspaceAcl( externalPath, false)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Session初期化の有限上限を検証する。
 *
 * 0のsession IDと包含関係が逆転した上限を拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testInitializationLimits( TestContext &context)
{
	OfficialAcquisitionSession		zeroSession ;			// 0のsession IDを拒否する対象。
	const OfficialAcquisitionLimits valid = makeLimits() ;	// 正常な有限予算。
	DRIVERCRATE_EXPECT( context, zeroSession.initialize( 0U, valid) != 0) ;

	OfficialAcquisitionLimits invalid = valid ;	// File上限がProvider上限を超える不正予算。
	invalid.maximumFileBytes		  = invalid.maximumProviderBytes + 1U ;
	OfficialAcquisitionSession invalidSession ;	// 不正予算を拒否する対象。
	DRIVERCRATE_EXPECT( context, invalidSession.initialize( 1U, invalid) != 0) ;

	OfficialAcquisitionSession validSession ;	// 一度だけ初期化できる正常対象。
	DRIVERCRATE_EXPECT( context, validSession.initialize( 1U, valid) == 0) ;
	DRIVERCRATE_EXPECT( context, validSession.initialize( 2U, valid) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式fileを検査対象としてhash固定できることを検証する。
 *
 * 公開metadataがなくてもlocal SHA-256を必須で算出する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testSuccessfulAcquisition( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 成功fileをscope終了まで所有する領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"acquire-test", 101U) == 0) ;
	OfficialAcquisitionSession session ;	// 一つのscan session用取得ledger。
	DRIVERCRATE_EXPECT( context, session.initialize( 101U, makeLimits()) == 0) ;
	FakeAcquisitionTransport		 transport ;	// `abc`を保存して根拠ありと返す境界。
	FakeNetworkCostReader			 costReader ;	// Unrestrictedを返すcost境界。
	const OfficialAcquisitionRequest request =
		makeRequest( NVIDIA_PROVIDER_ID, L"https://us.download.nvidia.com/fixture.bin",
					L"success.bin") ;	// 正常な架空取得要求。
	OfficialAcquisitionResult result ;	// 取得後の監査前状態。
	const NativeError		  error = session.acquire(
		request, workspace, transport, costReader, []( const std::uint64_t, const std::uint64_t) {},
		{}, result) ;	// 取得結果。

	DRIVERCRATE_EXPECT( context, error == 0) ;
	DRIVERCRATE_EXPECT( context, result.state == OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION) ;
	DRIVERCRATE_EXPECT( context, result.scanSessionId == 101U) ;
	DRIVERCRATE_EXPECT( context, result.acquisitionId == 1U) ;
	DRIVERCRATE_EXPECT( context, result.byteCount == 3U) ;
	DRIVERCRATE_EXPECT( context,
					   result.sha256 ==
						   L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") ;
	DRIVERCRATE_EXPECT( context, !result.publishedSizeVerified) ;
	DRIVERCRATE_EXPECT( context, !result.publishedSha256Verified) ;
	DRIVERCRATE_EXPECT( context, fileExists( result.inspectionPath)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Record限定GETの成功固定とpartial file削除を検証する。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testDelegatedAcquisitionAndCleanup( TestContext &context)
{
	constexpr ScanSessionId sessionId	= 110U ;	// 三つの委譲取得を結合するscan session。
	const std::wstring		correctHash =			// Fake payload `abc`の公開SHA-256。
		L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ;
	OfficialDownloadWorkspace workspace ;	// 成功fileと失敗file名を隔離する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"delegated-acquire-test", sessionId) == 0) ;
	OfficialAcquisitionSession session ;	// Record限定取得を成功予算へ計上するledger。
	DRIVERCRATE_EXPECT( context, session.initialize( sessionId, makeLimits()) == 0) ;
	FakeNetworkCostReader	 costReader ;	// 無制限networkを返す境界。
	FakeAcquisitionTransport transport ;	// `abc`を書き込むRecord限定transport。
	// 固定URL ledgerに依存しないことを確認する設定。
	transport.evidence = false ;

	RecordScopedDownloadGrant successGrant ;	// 一回の成功取得に使うgrant。
	DRIVERCRATE_EXPECT( context,
					   issueDelegatedGrant( successGrant, sessionId, 501U, 901U, correctHash) == 0) ;
	const OfficialAcquisitionRequest successRequest =
		// URL非保持要求。
		makeDelegatedRequest( successGrant, 501U, L"delegated-success.bin") ;
	OfficialAcquisitionResult successResult ;	// 由来と検査pathを保持する成功結果。
	const NativeError		  successError = session.acquire(
		successRequest, workspace, transport, costReader,
		[]( const std::uint64_t, const std::uint64_t) {}, {}, successResult) ;	// 成功取得結果。
	DRIVERCRATE_EXPECT( context, successError == 0) ;
	DRIVERCRATE_EXPECT( context,
					   successResult.state == OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION) ;
	DRIVERCRATE_EXPECT( context, successResult.delegatedRecord) ;
	DRIVERCRATE_EXPECT( context, successResult.recordEvidenceId == 901U) ;
	DRIVERCRATE_EXPECT( context, successResult.downloadGrantId == 501U) ;
	DRIVERCRATE_EXPECT( context, successResult.grantReresolutionCount == 0U) ;
	DRIVERCRATE_EXPECT( context, successResult.validatedDestinationAddressCount == 1U) ;
	DRIVERCRATE_EXPECT( context, successResult.destinationLocallyResolved) ;
	DRIVERCRATE_EXPECT( context, successResult.publishedSizeVerified) ;
	DRIVERCRATE_EXPECT( context, successResult.publishedSha256Verified) ;
	DRIVERCRATE_EXPECT( context, transport.lastMaximumBytes == 3U) ;
	DRIVERCRATE_EXPECT( context, fileExists( successResult.inspectionPath)) ;
	DRIVERCRATE_EXPECT( context,
					   successGrant.metadata().state == OfficialDownloadGrantState::CONSUMED) ;
	DRIVERCRATE_EXPECT( context, successGrant.metadata().outcome ==
									OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION) ;
	const std::wstring publicResultText =	// URLを含み得る公開文字列fieldの結合値。
		successResult.providerId + successResult.resourceId + successResult.sha256 ;
	DRIVERCRATE_EXPECT( context,
					   publicResultText.find( L"temporary.fixture.invalid") == std::wstring::npos) ;
	DRIVERCRATE_EXPECT( context, publicResultText.find( L"never-publish") == std::wstring::npos) ;

	RecordScopedDownloadGrant exceptionGrant ;	// Transport例外の終端を確認するgrant。
	DRIVERCRATE_EXPECT(
		context, issueDelegatedGrant( exceptionGrant, sessionId, 502U, 902U, correctHash) == 0) ;
	const OfficialAcquisitionRequest exceptionRequest =
		// 例外要求。
		makeDelegatedRequest( exceptionGrant, 502U, L"delegated-exception.bin") ;
	const std::wstring exceptionPath =
		// Partial削除確認path。
		workspace.path( exceptionRequest.workspaceFileName) ;
	transport.throwAfterWrite = true ;
	OfficialAcquisitionResult exceptionResult ;	// 例外を変換した失敗結果。
	DRIVERCRATE_EXPECT( context, session.acquire(
									exceptionRequest, workspace, transport, costReader,
									[]( const std::uint64_t, const std::uint64_t) {}, {},
									exceptionResult) != 0) ;
	DRIVERCRATE_EXPECT( context, exceptionResult.state == OfficialAcquisitionState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, !fileExists( exceptionPath)) ;
	DRIVERCRATE_EXPECT( context,
					   exceptionGrant.metadata().state == OfficialDownloadGrantState::CONSUMED) ;
	DRIVERCRATE_EXPECT( context,
					   exceptionGrant.metadata().outcome == OfficialDownloadGrantState::FAILED) ;
	transport.throwAfterWrite = false ;

	RecordScopedDownloadGrant cancellationGrant ;	// Transport取消しの終端を確認するgrant。
	DRIVERCRATE_EXPECT(
		context, issueDelegatedGrant( cancellationGrant, sessionId, 503U, 903U, correctHash) == 0) ;
	const OfficialAcquisitionRequest cancellationRequest =
		// 取消し要求。
		makeDelegatedRequest( cancellationGrant, 503U, L"delegated-cancelled.bin") ;
	const std::wstring cancellationPath =
		// Partial削除確認path。
		workspace.path( cancellationRequest.workspaceFileName) ;
	transport.cancelAfterWrite = true ;
	std::uint32_t cancellationChecks{} ;			// Session preflightとtransportの取消し照会回数。
	OfficialAcquisitionResult cancellationResult ;	// 取消し終端結果。
	DRIVERCRATE_EXPECT( context, session.acquire(
									cancellationRequest, workspace, transport, costReader,
									[]( const std::uint64_t, const std::uint64_t) {},
									[&cancellationChecks]() {
										++cancellationChecks ;
										return cancellationChecks >= 3U ;
									},
									cancellationResult) != 0) ;
	DRIVERCRATE_EXPECT( context, cancellationResult.state == OfficialAcquisitionState::CANCELLED) ;
	DRIVERCRATE_EXPECT( context, !fileExists( cancellationPath)) ;
	DRIVERCRATE_EXPECT( context,
					   cancellationGrant.metadata().state == OfficialDownloadGrantState::CONSUMED) ;
	DRIVERCRATE_EXPECT( context, cancellationGrant.metadata().outcome ==
									OfficialDownloadGrantState::CANCELLED) ;
	DRIVERCRATE_EXPECT( context, transport.delegatedDownloadCalls == 3U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Record限定grantのbinding混在と公開hash不一致を拒否する。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testDelegatedBindingAndMetadataRejection( TestContext &context)
{
	constexpr ScanSessionId sessionId	= 111U ;	// 拒否要求を結合するscan session。
	const std::wstring		correctHash =			// Fake payload `abc`の公開SHA-256。
		L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ;
	OfficialDownloadWorkspace workspace ;	// 拒否fileの不在を確認する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"delegated-reject-test", sessionId) == 0) ;
	OfficialAcquisitionSession session ;	// 不正bindingを成功予算へ計上しないledger。
	DRIVERCRATE_EXPECT( context, session.initialize( sessionId, makeLimits()) == 0) ;
	FakeNetworkCostReader	  costReader ;	// 無制限networkを返す境界。
	FakeAcquisitionTransport  transport ;	// 呼出し有無とpartial書込みを再現する境界。

	RecordScopedDownloadGrant mixedGrant ;	// 固定Provider混在要求で消費されないgrant。
	DRIVERCRATE_EXPECT( context,
					   issueDelegatedGrant( mixedGrant, sessionId, 504U, 904U, correctHash) == 0) ;
	OfficialAcquisitionRequest mixedRequest =
		// 基準の委譲要求。
		makeDelegatedRequest( mixedGrant, 504U, L"delegated-mixed.bin") ;
	mixedRequest.providerId = INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ;
	OfficialAcquisitionResult mixedResult ;	// 排他的variant違反の拒否結果。
	DRIVERCRATE_EXPECT( context,
					   session.acquire(
						   mixedRequest, workspace, transport, costReader,
						   []( const std::uint64_t, const std::uint64_t) {}, {}, mixedResult) != 0) ;
	DRIVERCRATE_EXPECT( context, mixedResult.state == OfficialAcquisitionState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, transport.delegatedDownloadCalls == 0U) ;
	DRIVERCRATE_EXPECT( context,
					   mixedGrant.metadata().state == OfficialDownloadGrantState::GRANT_ISSUED) ;
	DRIVERCRATE_EXPECT( context, !fileExists( workspace.path( L"delegated-mixed.bin"))) ;

	RecordScopedDownloadGrant badHashGrant ;	// 公開hash不一致を持つ一回grant。
	DRIVERCRATE_EXPECT(
		context, issueDelegatedGrant(
					 badHashGrant, sessionId, 505U, 905U,
					 L"0000000000000000000000000000000000000000000000000000000000000000") == 0) ;
	const OfficialAcquisitionRequest badHashRequest =
		// Hash拒否要求。
		makeDelegatedRequest( badHashGrant, 505U, L"delegated-bad-hash.bin") ;
	const std::wstring badHashPath =
		// 破棄確認path。
		workspace.path( badHashRequest.workspaceFileName) ;
	OfficialAcquisitionResult badHashResult ;	// Hash拒否結果。
	DRIVERCRATE_EXPECT( context, session.acquire(
									badHashRequest, workspace, transport, costReader,
									[]( const std::uint64_t, const std::uint64_t) {}, {},
									badHashResult) != 0) ;
	DRIVERCRATE_EXPECT( context, badHashResult.state == OfficialAcquisitionState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, !fileExists( badHashPath)) ;
	DRIVERCRATE_EXPECT( context, badHashGrant.metadata().outcome ==
									OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION) ;
}

//------------------------------------------------------------------------------
/**
 * @brief OF05の正当な未登録CDNと固定payloadへの一方向遷移を全hop検証する。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testOf05DelegatedHttpSuccessfulRoutes( TestContext &context)
{
	DelegatedHttpFixture dynamicFixture ;	// 同じdynamic origin内で二回redirectする応答列。
	dynamicFixture.responses = {
		DelegatedHttpResponse{.status	= HTTP_STATUS_REDIRECT,
							  .location = L"https://temporary.fixture.invalid/step-two",
							  .body		= {},
							  .declared = std::nullopt},
		DelegatedHttpResponse{.status	= HTTP_STATUS_REDIRECT_KEEP_VERB,
							  .location = L"https://temporary.fixture.invalid/step-three",
							  .body		= {},
							  .declared = std::nullopt},
		DelegatedHttpResponse{}} ;
	OfficialDownloadWorkspace  dynamicWorkspace ;	// 成功fileを所有する保護領域。
	OfficialAcquisitionSession dynamicSession ;		// 成功取得を計上するledger。
	RecordScopedDownloadGrant  dynamicGrant ;		// Dynamic routeの一回grant。
	OfficialAcquisitionResult  dynamicResult ;		// URL非保持の成功結果。
	const NativeError		   dynamicError = runDelegatedHttpAcquisition(
		 dynamicFixture, 120U, 601U, 1'001U, L"dynamic-success.bin",
		 L"https://temporary.fixture.invalid/step-one?token=secret", dynamicWorkspace,
		 dynamicSession, dynamicGrant, dynamicResult) ;	// 二redirectの統合取得結果。
	DRIVERCRATE_EXPECT( context, dynamicError == 0) ;
	DRIVERCRATE_EXPECT( context,
					   dynamicResult.state == OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION) ;
	DRIVERCRATE_EXPECT( context, dynamicFixture.sends == 3U) ;
	DRIVERCRATE_EXPECT( context, dynamicFixture.connectedHosts.size() == 3U) ;
	DRIVERCRATE_EXPECT( context, (dynamicFixture.connectedHosts ==
								 std::vector<std::wstring>{L"temporary.fixture.invalid",
														   L"temporary.fixture.invalid",
														   L"temporary.fixture.invalid"})) ;
	DRIVERCRATE_EXPECT( context, (dynamicFixture.requestedPaths ==
								 std::vector<std::wstring>{L"/step-one?token=secret", L"/step-two",
														   L"/step-three"})) ;
	DRIVERCRATE_EXPECT( context, dynamicFixture.resolvedHosts == dynamicFixture.connectedHosts) ;
	DRIVERCRATE_EXPECT( context, dynamicResult.validatedDestinationAddressCount == 3U) ;
	DRIVERCRATE_EXPECT( context, dynamicResult.destinationLocallyResolved) ;
	DRIVERCRATE_EXPECT( context,
					   dynamicResult.providerId == INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, dynamicGrant.metadata().policyId ==
									INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID) ;
	DRIVERCRATE_EXPECT( context, dynamicGrant.payloadView().targetUrl.empty()) ;
	DRIVERCRATE_EXPECT( context, dynamicFixture.safeRequest) ;
	DRIVERCRATE_EXPECT( context, dynamicFixture.redirectDisabled == 3U) ;
	DRIVERCRATE_EXPECT( context, dynamicFixture.highLogon == 3U) ;
	DRIVERCRATE_EXPECT( context, dynamicFixture.opened == dynamicFixture.closed) ;
	DRIVERCRATE_EXPECT( context, fileExists( dynamicResult.inspectionPath)) ;

	DelegatedHttpFixture fixedFixture ;	// Dynamic起点から固定Intel payloadへ移る応答列。
	fixedFixture.responses = {
		DelegatedHttpResponse{.status	= HTTP_STATUS_REDIRECT,
							  .location = L"https://downloadmirror.intel.com/final-driver.zip",
							  .body		= {},
							  .declared = std::nullopt},
		DelegatedHttpResponse{}} ;
	OfficialDownloadWorkspace  fixedWorkspace ;	// 成功fileを所有する別保護領域。
	OfficialAcquisitionSession fixedSession ;	// 固定遷移成功を計上するledger。
	RecordScopedDownloadGrant  fixedGrant ;		// 一方向遷移のgrant。
	OfficialAcquisitionResult  fixedResult ;	// 一方向遷移の成功結果。
	const NativeError		   fixedError = runDelegatedHttpAcquisition(
		 fixedFixture, 121U, 602U, 1'002U, L"fixed-transition.bin",
		 L"https://temporary.fixture.invalid/start", fixedWorkspace, fixedSession, fixedGrant,
		 fixedResult) ;	// Dynamicからallowlistへの統合取得結果。
	DRIVERCRATE_EXPECT( context, fixedError == 0) ;
	DRIVERCRATE_EXPECT( context, (fixedFixture.connectedHosts ==
								 std::vector<std::wstring>{L"temporary.fixture.invalid",
														   L"downloadmirror.intel.com"})) ;
	DRIVERCRATE_EXPECT( context, fixedFixture.resolvedHosts == fixedFixture.connectedHosts) ;
	DRIVERCRATE_EXPECT( context, fixedResult.validatedDestinationAddressCount == 2U) ;
	DRIVERCRATE_EXPECT( context, fixedFixture.sends == 2U) ;
	DRIVERCRATE_EXPECT( context, fixedFixture.safeRequest) ;
	DRIVERCRATE_EXPECT( context, fixedFixture.opened == fixedFixture.closed) ;
	DRIVERCRATE_EXPECT( context, fixedGrant.metadata().outcome ==
									OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Hop期限、private宛先、redirect違反、取消し、通信失敗を拒否する。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testDelegatedHttpFailureCleanup( TestContext &context)
{
	DelegatedHttpFixture	   privateFixture ;		// Private IPv4へ解決する起点fixture。
	OfficialDownloadWorkspace  privateWorkspace ;	// 拒否file名を隔離する保護領域。
	OfficialAcquisitionSession privateSession ;		// 拒否を成功計上しないledger。
	RecordScopedDownloadGrant  privateGrant ;		// Private宛先で拒否するgrant。
	OfficialAcquisitionResult  privateResult ;		// Private宛先拒否結果。
	DRIVERCRATE_EXPECT( context, runDelegatedHttpAcquisition(
									privateFixture, 122U, 603U, 1'003U, L"private.bin",
									L"https://private.fixture.invalid/driver.zip", privateWorkspace,
									privateSession, privateGrant, privateResult) != 0) ;
	DRIVERCRATE_EXPECT( context, privateResult.state == OfficialAcquisitionState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, privateFixture.opened == 0U && privateFixture.sends == 0U) ;
	DRIVERCRATE_EXPECT( context, privateFixture.resolvedHosts.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, !fileExists( privateWorkspace.path( L"private.bin"))) ;
	DRIVERCRATE_EXPECT( context, privateGrant.metadata().outcome ==
									OfficialDownloadGrantState::TARGET_REJECTED) ;

	DelegatedHttpFixture openRedirectFixture ;	// 未登録の別originへ転送する応答列。
	openRedirectFixture.responses = {
		DelegatedHttpResponse{.status	= HTTP_STATUS_REDIRECT,
							  .location = L"https://advertising.fixture.invalid/driver.zip",
							  .body		= {},
							  .declared = std::nullopt},
		DelegatedHttpResponse{}} ;
	OfficialDownloadWorkspace  openRedirectWorkspace ;	// Open redirect拒否file用の保護領域。
	OfficialAcquisitionSession openRedirectSession ;	// 拒否を成功計上しないledger。
	RecordScopedDownloadGrant  openRedirectGrant ;		// Exact起点だけに発行したgrant。
	OfficialAcquisitionResult  openRedirectResult ;		// 未登録別originの拒否結果。
	DRIVERCRATE_EXPECT( context,
					   runDelegatedHttpAcquisition(
						   openRedirectFixture, 128U, 609U, 1'009U, L"open-redirect.bin",
						   L"https://temporary.fixture.invalid/start", openRedirectWorkspace,
						   openRedirectSession, openRedirectGrant, openRedirectResult) != 0) ;
	DRIVERCRATE_EXPECT( context, openRedirectFixture.sends == 1U) ;
	DRIVERCRATE_EXPECT( context, openRedirectFixture.resolvedHosts.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, !fileExists( openRedirectWorkspace.path( L"open-redirect.bin"))) ;
	DRIVERCRATE_EXPECT( context, openRedirectGrant.metadata().outcome ==
									OfficialDownloadGrantState::TARGET_REJECTED) ;

	DelegatedHttpFixture cycleFixture ;	// Exact起点へ戻る循環Locationを返す応答列。
	cycleFixture.responses = {
		DelegatedHttpResponse{.status	= HTTP_STATUS_REDIRECT,
							  .location = L"https://temporary.fixture.invalid/cycle",
							  .body		= {},
							  .declared = std::nullopt},
		DelegatedHttpResponse{}} ;
	OfficialDownloadWorkspace  cycleWorkspace ;	// 循環拒否file用の保護領域。
	OfficialAcquisitionSession cycleSession ;	// 循環を成功計上しないledger。
	RecordScopedDownloadGrant  cycleGrant ;		// Exact起点だけに発行したgrant。
	OfficialAcquisitionResult  cycleResult ;	// 循環検出の拒否結果。
	DRIVERCRATE_EXPECT( context, runDelegatedHttpAcquisition(
									cycleFixture, 129U, 610U, 1'010U, L"cycle.bin",
									L"https://temporary.fixture.invalid/cycle", cycleWorkspace,
									cycleSession, cycleGrant, cycleResult) != 0) ;
	DRIVERCRATE_EXPECT( context, cycleFixture.sends == 1U) ;
	DRIVERCRATE_EXPECT( context, cycleFixture.resolvedHosts.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, !fileExists( cycleWorkspace.path( L"cycle.bin"))) ;
	DRIVERCRATE_EXPECT( context, cycleGrant.metadata().outcome ==
									OfficialDownloadGrantState::TARGET_REJECTED) ;

	DelegatedHttpFixture deadlineFixture ;	// 二hop目が30秒余裕を失う応答列。
	deadlineFixture.responses = {
		DelegatedHttpResponse{.status	= HTTP_STATUS_REDIRECT,
							  .location = L"https://temporary.fixture.invalid/too-late",
							  .body		= {},
							  .declared = std::nullopt},
		DelegatedHttpResponse{}} ;
	deadlineFixture.utcSeconds = {20'010U, 20'871U} ;
	OfficialDownloadWorkspace  deadlineWorkspace ;	// 期限切れfile名を隔離する領域。
	OfficialAcquisitionSession deadlineSession ;	// 期限切れを計上しないledger。
	RecordScopedDownloadGrant  deadlineGrant ;		// 二hop目で期限切れとなるgrant。
	OfficialAcquisitionResult  deadlineResult ;		// 期限切れ結果。
	DRIVERCRATE_EXPECT( context, runDelegatedHttpAcquisition(
									deadlineFixture, 123U, 604U, 1'004U, L"deadline.bin",
									L"https://temporary.fixture.invalid/start", deadlineWorkspace,
									deadlineSession, deadlineGrant, deadlineResult) != 0) ;
	DRIVERCRATE_EXPECT( context, deadlineFixture.sends == 1U) ;
	DRIVERCRATE_EXPECT( context, deadlineFixture.resolvedHosts.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, !fileExists( deadlineWorkspace.path( L"deadline.bin"))) ;
	DRIVERCRATE_EXPECT( context, deadlineGrant.metadata().outcome ==
									OfficialDownloadGrantState::GRANT_EXPIRED) ;

	DelegatedHttpFixture excessiveFixture ;	// 三回目のdynamic redirectを返す応答列。
	excessiveFixture.responses = {
		DelegatedHttpResponse{.status	= HTTP_STATUS_REDIRECT,
							  .location = L"https://temporary.fixture.invalid/two",
							  .body		= {},
							  .declared = std::nullopt},
		DelegatedHttpResponse{.status	= HTTP_STATUS_REDIRECT,
							  .location = L"https://temporary.fixture.invalid/three",
							  .body		= {},
							  .declared = std::nullopt},
		DelegatedHttpResponse{.status	= HTTP_STATUS_REDIRECT,
							  .location = L"https://temporary.fixture.invalid/four",
							  .body		= {},
							  .declared = std::nullopt}} ;
	OfficialDownloadWorkspace  excessiveWorkspace ;	// Redirect拒否file名を隔離する領域。
	OfficialAcquisitionSession excessiveSession ;	// Redirect拒否を計上しないledger。
	RecordScopedDownloadGrant  excessiveGrant ;		// Redirect過大で拒否するgrant。
	OfficialAcquisitionResult  excessiveResult ;	// Redirect過大結果。
	DRIVERCRATE_EXPECT( context, runDelegatedHttpAcquisition(
									excessiveFixture, 124U, 605U, 1'005U, L"excessive.bin",
									L"https://temporary.fixture.invalid/one", excessiveWorkspace,
									excessiveSession, excessiveGrant, excessiveResult) != 0) ;
	DRIVERCRATE_EXPECT( context, excessiveFixture.sends == 3U) ;
	DRIVERCRATE_EXPECT( context, !fileExists( excessiveWorkspace.path( L"excessive.bin"))) ;
	DRIVERCRATE_EXPECT( context, excessiveGrant.metadata().outcome ==
									OfficialDownloadGrantState::TARGET_REJECTED) ;

	DelegatedHttpFixture reverseFixture ;	// 固定hostからdynamicへ戻そうとする応答列。
	reverseFixture.responses = {
		DelegatedHttpResponse{.status	= HTTP_STATUS_REDIRECT,
							  .location = L"https://downloadmirror.intel.com/fixed-step",
							  .body		= {},
							  .declared = std::nullopt},
		DelegatedHttpResponse{.status	= HTTP_STATUS_REDIRECT,
							  .location = L"https://temporary.fixture.invalid/forbidden-return",
							  .body		= {},
							  .declared = std::nullopt}} ;
	OfficialDownloadWorkspace  reverseWorkspace ;	// 逆向き拒否file名を隔離する領域。
	OfficialAcquisitionSession reverseSession ;		// 逆向き拒否を計上しないledger。
	RecordScopedDownloadGrant  reverseGrant ;		// 固定hostで終端しなかったgrant。
	OfficialAcquisitionResult  reverseResult ;		// 逆向き拒否結果。
	DRIVERCRATE_EXPECT( context, runDelegatedHttpAcquisition(
									reverseFixture, 125U, 606U, 1'006U, L"reverse.bin",
									L"https://temporary.fixture.invalid/start", reverseWorkspace,
									reverseSession, reverseGrant, reverseResult) != 0) ;
	DRIVERCRATE_EXPECT( context, reverseFixture.sends == 2U) ;
	DRIVERCRATE_EXPECT( context, (reverseFixture.connectedHosts ==
								 std::vector<std::wstring>{L"temporary.fixture.invalid",
														   L"downloadmirror.intel.com"})) ;
	DRIVERCRATE_EXPECT( context, reverseFixture.resolvedHosts == reverseFixture.connectedHosts) ;
	DRIVERCRATE_EXPECT( context, !fileExists( reverseWorkspace.path( L"reverse.bin"))) ;

	DelegatedHttpFixture readFailureFixture ;	// 一byte保存後のReadData失敗fixture。
	readFailureFixture.chunk	  = 1U ;
	readFailureFixture.failReadAt = 2U ;
	OfficialDownloadWorkspace  readFailureWorkspace ;	// Partial削除確認領域。
	OfficialAcquisitionSession readFailureSession ;		// 通信失敗を計上しないledger。
	RecordScopedDownloadGrant  readFailureGrant ;		// 通信失敗で閉じるgrant。
	OfficialAcquisitionResult  readFailureResult ;		// 通信失敗結果。
	DRIVERCRATE_EXPECT( context, runDelegatedHttpAcquisition(
									readFailureFixture, 126U, 607U, 1'007U, L"read-failure.bin",
									L"https://temporary.fixture.invalid/read", readFailureWorkspace,
									readFailureSession, readFailureGrant, readFailureResult) != 0) ;
	DRIVERCRATE_EXPECT( context, readFailureFixture.reads == 2U) ;
	DRIVERCRATE_EXPECT( context, !fileExists( readFailureWorkspace.path( L"read-failure.bin"))) ;
	DRIVERCRATE_EXPECT( context,
					   readFailureGrant.metadata().outcome == OfficialDownloadGrantState::FAILED) ;

	DelegatedHttpFixture cancellationFixture ;	// 一byte保存後の取消しfixture。
	cancellationFixture.chunk			= 1U ;
	cancellationFixture.cancelAfterRead = 2U ;
	OfficialDownloadWorkspace  cancellationWorkspace ;	// Partial取消し削除確認領域。
	OfficialAcquisitionSession cancellationSession ;	// 取消しを計上しないledger。
	RecordScopedDownloadGrant  cancellationGrant ;		// 取消しで閉じるgrant。
	OfficialAcquisitionResult  cancellationResult ;		// 取消し結果。
	DRIVERCRATE_EXPECT( context,
					   runDelegatedHttpAcquisition(
						   cancellationFixture, 127U, 608U, 1'008U, L"http-cancelled.bin",
						   L"https://temporary.fixture.invalid/cancel", cancellationWorkspace,
						   cancellationSession, cancellationGrant, cancellationResult) != 0) ;
	DRIVERCRATE_EXPECT( context, cancellationFixture.reads == 2U) ;
	DRIVERCRATE_EXPECT( context, !fileExists( cancellationWorkspace.path( L"http-cancelled.bin"))) ;
	DRIVERCRATE_EXPECT( context, cancellationResult.state == OfficialAcquisitionState::CANCELLED) ;
	DRIVERCRATE_EXPECT( context, cancellationGrant.metadata().outcome ==
									OfficialDownloadGrantState::CANCELLED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief OF09の公開size・hash不一致とHTML error本文を候補化前に拒否する。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testOf09DelegatedMetadataAndBodyRejection( TestContext &context)
{
	DelegatedHttpFixture sizeFixture ;	// 公開3 byteに対して4 byteを返す応答。
	sizeFixture.responses = {DelegatedHttpResponse{
		.status = HTTP_STATUS_OK, .location = std::nullopt, .body = "abcd", .declared = L"4"}} ;
	OfficialDownloadWorkspace  sizeWorkspace ;	// Size拒否file用の保護領域。
	OfficialAcquisitionSession sizeSession ;	// Size拒否を成功計上しないledger。
	RecordScopedDownloadGrant  sizeGrant ;		// 公開3 byteだけを許可するgrant。
	OfficialAcquisitionResult  sizeResult ;		// 過大本文の拒否結果。
	DRIVERCRATE_EXPECT( context, runDelegatedHttpAcquisition(
									sizeFixture, 130U, 611U, 1'011U, L"bad-size.bin",
									L"https://temporary.fixture.invalid/bad-size", sizeWorkspace,
									sizeSession, sizeGrant, sizeResult) != 0) ;
	DRIVERCRATE_EXPECT( context, sizeResult.state == OfficialAcquisitionState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, !fileExists( sizeWorkspace.path( L"bad-size.bin"))) ;
	DRIVERCRATE_EXPECT( context, sizeGrant.metadata().outcome == OfficialDownloadGrantState::FAILED) ;

	DelegatedHttpFixture	   hashFixture ;	// `abc`と異なる公開SHA-256を持つ応答。
	OfficialDownloadWorkspace  hashWorkspace ;	// Hash拒否file用の保護領域。
	OfficialAcquisitionSession hashSession ;	// Hash拒否を成功計上しないledger。
	RecordScopedDownloadGrant  hashGrant ;		// 不一致公開hashへ結合するgrant。
	OfficialAcquisitionResult  hashResult ;		// 取得後hash拒否結果。
	DRIVERCRATE_EXPECT( context,
					   runDelegatedHttpAcquisition( hashFixture, 131U, 612U, 1'012U, L"bad-hash.bin",
												   L"https://temporary.fixture.invalid/bad-hash",
												   hashWorkspace, hashSession, hashGrant,
												   hashResult, std::wstring( 64U, L'0')) != 0) ;
	DRIVERCRATE_EXPECT( context, hashResult.state == OfficialAcquisitionState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, !fileExists( hashWorkspace.path( L"bad-hash.bin"))) ;
	DRIVERCRATE_EXPECT( context, hashGrant.metadata().outcome ==
									OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION) ;

	DelegatedHttpFixture htmlFixture ;	// 公開size・hashと一致するHTML error本文。
	htmlFixture.responses = {DelegatedHttpResponse{.status	 = HTTP_STATUS_OK,
												   .location = std::nullopt,
												   .body	 = "<html>error</html>",
												   .declared = L"18"}} ;
	OfficialDownloadWorkspace  htmlWorkspace ;	// 内容検査までHTMLを所有する保護領域。
	OfficialAcquisitionSession htmlSession ;	// 取得成功だけを記録するledger。
	RecordScopedDownloadGrant  htmlGrant ;		// HTML本文の実identityと一致するgrant。
	OfficialAcquisitionResult  htmlResult ;		// 内容合格を意味しない取得成功結果。
	const std::wstring		   htmlSha256 =
		L"dd2ca3ce12d394a083a8e70964fa8dc986a112f8b2451b5ec7285c6c5fbc32eb" ;	// HTML本文のSHA-256。
	DRIVERCRATE_EXPECT( context, runDelegatedHttpAcquisition(
									htmlFixture, 132U, 613U, 1'013U, L"html-error.bin",
									L"https://temporary.fixture.invalid/html-error", htmlWorkspace,
									htmlSession, htmlGrant, htmlResult, htmlSha256, 18U) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   htmlResult.state == OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION) ;
	DRIVERCRATE_EXPECT( context,
					   htmlResult.publishedSizeVerified && htmlResult.publishedSha256Verified) ;
	DelegatedOfficialPackageInput input ;	// URLを除いた共通内容検査入力。
	DRIVERCRATE_EXPECT( context,
					   makeDelegatedOfficialPackageInput( htmlResult, htmlGrant, input) == 0) ;
	CommonDriverPackageInspection inspection ;	// HTMLをZIPとして受理しない全体結果。
	DRIVERCRATE_EXPECT( context,
					   inspectDelegatedOfficialDriverPackage( 132U, input, inspection) != 0) ;
	DRIVERCRATE_EXPECT( context, inspection.error != 0 && inspection.infs.empty()) ;
	DRIVERCRATE_EXPECT( context, htmlGrant.payloadView().targetUrl.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASUS metadataを有限取得計画とG11-Bへ接続する。
 *
 * 固定ASUS Provider／payload policyと公開SHA-256を使用して検査用取得し、候補状態を生成しない境界を確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testAsusPackageAcquisition( TestContext &context)
{
	const AsusDriverPageEntry entry{
		.category	 = L"LAN",
		.opaqueId	 = L"1@66@7@8@52@5@DRV_LAN_Fictional_W11_64_V1.zip",
		.title		 = L"Fictional ASUS LAN Driver",
		.version	 = L"1.0.0",
		.releaseDate = L"2025/12/31",
		.downloadUrl = L"https://dlcdnets.asus.com/pub/ASUS/mb/04LAN/"
					   L"DRV_LAN_Fictional_W11_64_V1.zip",
		.sha256				  = L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		.maximumDownloadBytes = 64U} ;					// `abc`と一致する架空ASUS metadata。
	std::vector<AsusPackageAcquisitionPlanEntry> plan ;	// G11-Bへ渡す内部取得計画。
	DRIVERCRATE_EXPECT( context, makeAsusPackageAcquisitionPlan(
									std::span<const AsusDriverPageEntry>( &entry, 1U), plan) == 0) ;
	DRIVERCRATE_EXPECT( context, plan.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, !plan.empty() && plan[0].workspaceFileName == L"payload-001.zip") ;

	OfficialDownloadWorkspace workspace ;	// 成功した架空ASUS fileを所有する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"asus-acquire-test", 109U) == 0) ;
	OfficialAcquisitionSession session ;	// ASUS取得量を計上するscan session ledger。
	DRIVERCRATE_EXPECT( context, session.initialize( 109U, makeLimits()) == 0) ;
	FakeAcquisitionTransport  transport ;	// `abc`と公式取得根拠を返す架空境界。
	FakeNetworkCostReader	  costReader ;	// Unrestricted networkを返す架空境界。
	OfficialAcquisitionResult result ;		// URLを含まない検査前取得結果。
	const NativeError		  error = acquireAsusPackageForInspection(
		plan[0], false, session, workspace, transport, costReader,
		[]( const std::uint64_t, const std::uint64_t) {}, {}, result) ;	// ASUS取得結果。
	DRIVERCRATE_EXPECT( context, error == 0) ;
	DRIVERCRATE_EXPECT( context, result.state == OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION) ;
	DRIVERCRATE_EXPECT( context, result.providerId == ASUS_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, result.resourceId == OFFICIAL_PAYLOAD_RESOURCE_ID) ;
	DRIVERCRATE_EXPECT( context, result.publishedSha256Verified) ;
	DRIVERCRATE_EXPECT( context, !result.publishedSizeVerified) ;

	std::vector<AsusDriverPageEntry> duplicateEntries{entry, entry} ;	// 重複URL／ID入力。
	DRIVERCRATE_EXPECT( context, makeAsusPackageAcquisitionPlan( duplicateEntries, plan) != 0) ;
	DRIVERCRATE_EXPECT( context, plan.empty()) ;
	AsusDriverPageEntry wrongOrigin = entry ;	// ASUS以外のhostへ差し替えた入力。
	wrongOrigin.downloadUrl =
		L"https://example.test/pub/ASUS/mb/04LAN/DRV_LAN_Fictional_W11_64_V1.zip" ;
	DRIVERCRATE_EXPECT( context,
					   makeAsusPackageAcquisitionPlan(
						   std::span<const AsusDriverPageEntry>( &wrongOrigin, 1U), plan) != 0) ;
	DRIVERCRATE_EXPECT( context, plan.empty()) ;
	AsusDriverPageEntry encodedTraversal = entry ;	// Percent encodingを含む曖昧なpath入力。
	encodedTraversal.downloadUrl =
		L"https://dlcdnets.asus.com/pub/ASUS/%2e%2e/DRV_LAN_Fictional_W11_64_V1.zip" ;
	DRIVERCRATE_EXPECT( context,
					   makeAsusPackageAcquisitionPlan(
						   std::span<const AsusDriverPageEntry>( &encodedTraversal, 1U), plan) != 0) ;
	DRIVERCRATE_EXPECT( context, plan.empty()) ;
	std::vector<AsusDriverPageEntry> excessiveEntries( 65U, entry) ;	// 計画件数上限超過入力。
	DRIVERCRATE_EXPECT( context, makeAsusPackageAcquisitionPlan( excessiveEntries, plan) != 0) ;
	DRIVERCRATE_EXPECT( context, plan.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公開metadataと取得根拠の不一致を拒否する。
 *
 * Hash不一致と根拠欠落でpartial fileを直ちに削除する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testMetadataAndEvidenceRejection( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 拒否fileの削除を確認する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"acquire-test", 102U) == 0) ;
	OfficialAcquisitionSession session ;	// 二つの拒否要求を処理するledger。
	DRIVERCRATE_EXPECT( context, session.initialize( 102U, makeLimits()) == 0) ;
	FakeAcquisitionTransport   transport ;	// `abc`を保存する取得境界。
	FakeNetworkCostReader	   costReader ;	// Networkを許可するcost境界。
	OfficialAcquisitionRequest hashRequest =
		makeRequest( NVIDIA_PROVIDER_ID, L"https://us.download.nvidia.com/fixture.bin",
					L"bad-hash.bin") ;	// 不一致公開hashを持たせる要求。
	hashRequest.publishedSize = 3U ;
	hashRequest.publishedSha256 =
		L"0000000000000000000000000000000000000000000000000000000000000000" ;
	const std::wstring hashPath = workspace.path( hashRequest.workspaceFileName) ;	// 確認path。
	OfficialAcquisitionResult hashResult ;											// Hash不一致時の結果。
	DRIVERCRATE_EXPECT( context,
					   session.acquire(
						   hashRequest, workspace, transport, costReader,
						   []( const std::uint64_t, const std::uint64_t) {}, {}, hashResult) != 0) ;
	DRIVERCRATE_EXPECT( context, hashResult.state == OfficialAcquisitionState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, !fileExists( hashPath)) ;

	transport.evidence = false ;
	const OfficialAcquisitionRequest evidenceRequest =
		makeRequest( NVIDIA_PROVIDER_ID, L"https://us.download.nvidia.com/fixture.bin",
					L"no-evidence.bin") ;	// 取得根拠なしとする要求。
	const std::wstring evidencePath =
		// 確認path。
		workspace.path( evidenceRequest.workspaceFileName) ;
	OfficialAcquisitionResult evidenceResult ;	// 根拠欠落時の結果。
	DRIVERCRATE_EXPECT( context, session.acquire(
									evidenceRequest, workspace, transport, costReader,
									[]( const std::uint64_t, const std::uint64_t) {}, {},
									evidenceResult) != 0) ;
	DRIVERCRATE_EXPECT( context, evidenceResult.state == OfficialAcquisitionState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, !fileExists( evidencePath)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 制限networkへの明示同意を必須にすることを検証する。
 *
 * Restrictedとcost照会失敗を無断でdownloadへ進めない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testNetworkConsent( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 同意後の成功fileを所有する領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"acquire-test", 103U) == 0) ;
	OfficialAcquisitionSession session ;	// Cost同意状態を検証するledger。
	DRIVERCRATE_EXPECT( context, session.initialize( 103U, makeLimits()) == 0) ;
	FakeAcquisitionTransport transport ;	// 呼出し有無を記録する取得境界。
	FakeNetworkCostReader	 costReader ;	// Restrictedを返すcost境界。
	costReader.configuredCost = OfficialNetworkCostKind::RESTRICTED ;
	OfficialAcquisitionRequest request =
		makeRequest( NVIDIA_PROVIDER_ID, L"https://us.download.nvidia.com/fixture.bin",
					L"metered.bin") ;	// 初回はnetwork同意なしの要求。
	OfficialAcquisitionResult waiting ;	// 同意待ちを保持する結果。
	DRIVERCRATE_EXPECT( context,
					   session.acquire(
						   request, workspace, transport, costReader,
						   []( const std::uint64_t, const std::uint64_t) {}, {}, waiting) != 0) ;
	DRIVERCRATE_EXPECT( context,
					   waiting.state == OfficialAcquisitionState::AWAITING_NETWORK_CONSENT) ;
	DRIVERCRATE_EXPECT( context, transport.downloadCalls == 0U) ;

	request.restrictedNetworkApproved = true ;
	OfficialAcquisitionResult approved ;	// 今回限りの同意後に取得する結果。
	DRIVERCRATE_EXPECT( context,
					   session.acquire(
						   request, workspace, transport, costReader,
						   []( const std::uint64_t, const std::uint64_t) {}, {}, approved) == 0) ;
	DRIVERCRATE_EXPECT( context, transport.downloadCalls == 1U) ;

	OfficialDownloadWorkspace unknownWorkspace ;	// Cost失敗要求を隔離する保護領域。
	DRIVERCRATE_EXPECT( context, unknownWorkspace.initialize( L"acquire-test", 104U) == 0) ;
	OfficialAcquisitionSession unknownSession ;	// Cost失敗を確認する別ledger。
	DRIVERCRATE_EXPECT( context, unknownSession.initialize( 104U, makeLimits()) == 0) ;
	FakeNetworkCostReader unknownReader ;	// OS cost照会失敗を再現する境界。
	unknownReader.configuredCost  = OfficialNetworkCostKind::UNKNOWN ;
	unknownReader.configuredError = static_cast<NativeError>( E_NOTIMPL) ;
	const OfficialAcquisitionRequest unknownRequest =
		makeRequest( NVIDIA_PROVIDER_ID, L"https://us.download.nvidia.com/fixture.bin",
					L"unknown-cost.bin") ;		// Cost照会失敗で同意なしの要求。
	OfficialAcquisitionResult unknownResult ;	// Cost失敗時の同意待ち結果。
	DRIVERCRATE_EXPECT( context, unknownSession.acquire(
									unknownRequest, unknownWorkspace, transport, unknownReader,
									[]( const std::uint64_t, const std::uint64_t) {}, {},
									unknownResult) != 0) ;
	DRIVERCRATE_EXPECT( context,
					   unknownResult.state == OfficialAcquisitionState::AWAITING_NETWORK_CONSENT) ;
	DRIVERCRATE_EXPECT( context, unknownResult.networkCostError != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 取消しとtransport例外でpartial fileを破棄する。
 *
 * 書込み後の取消しと任意例外をworker境界へ漏らさない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testCancellationAndExceptionCleanup( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 失敗fileの削除を確認する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"acquire-test", 105U) == 0) ;
	OfficialAcquisitionSession session ;	// 取消しと例外要求を処理するledger。
	DRIVERCRATE_EXPECT( context, session.initialize( 105U, makeLimits()) == 0) ;
	FakeNetworkCostReader	 costReader ;	// Networkを許可するcost境界。

	FakeAcquisitionTransport cancelledTransport ;	// 書込み後に取消す取得境界。
	cancelledTransport.cancelAfterWrite = true ;
	const OfficialAcquisitionRequest cancelledRequest =
		makeRequest( NVIDIA_PROVIDER_ID, L"https://us.download.nvidia.com/fixture.bin",
					L"cancelled.bin") ;	// Partial fileを作る取消し要求。
	const std::wstring cancelledPath =
		// 削除確認path。
		workspace.path( cancelledRequest.workspaceFileName) ;
	std::uint32_t			  cancellationChecks{} ;	// Sessionとtransportからの取消し確認回数。
	OfficialAcquisitionResult cancelledResult ;			// 取消し後の結果。
	DRIVERCRATE_EXPECT( context, session.acquire(
									cancelledRequest, workspace, cancelledTransport, costReader,
									[]( const std::uint64_t, const std::uint64_t) {},
									[&cancellationChecks]() {
										++cancellationChecks ;
										return cancellationChecks >= 3U ;
									},
									cancelledResult) != 0) ;
	DRIVERCRATE_EXPECT( context, cancelledResult.state == OfficialAcquisitionState::CANCELLED) ;
	DRIVERCRATE_EXPECT( context, !fileExists( cancelledPath)) ;

	FakeAcquisitionTransport throwingTransport ;	// 書込み後に例外を送出する境界。
	throwingTransport.throwAfterWrite = true ;
	const OfficialAcquisitionRequest throwingRequest =
		makeRequest( NVIDIA_PROVIDER_ID, L"https://us.download.nvidia.com/fixture.bin",
					L"exception.bin") ;	// Partial fileを作る例外要求。
	const std::wstring throwingPath =
		// 削除確認path。
		workspace.path( throwingRequest.workspaceFileName) ;
	OfficialAcquisitionResult throwingResult ;	// 例外を変換した失敗結果。
	DRIVERCRATE_EXPECT( context, session.acquire(
									throwingRequest, workspace, throwingTransport, costReader,
									[]( const std::uint64_t, const std::uint64_t) {}, {},
									throwingResult) != 0) ;
	DRIVERCRATE_EXPECT( context, throwingResult.state == OfficialAcquisitionState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, !fileExists( throwingPath)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider予算とdisk reserveを取得前に検証する。
 *
 * 予約量、file件数、空き容量違反でtransportを呼ばない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testBudgetAndDiskRejection( TestContext &context)
{
	OfficialAcquisitionLimits countLimits = makeLimits() ;	// 一fileだけ許可する予算。
	countLimits.maximumProviderFiles	  = 1U ;
	OfficialDownloadWorkspace countWorkspace ;	// 一件目の成功fileを所有する領域。
	DRIVERCRATE_EXPECT( context, countWorkspace.initialize( L"acquire-test", 106U) == 0) ;
	OfficialAcquisitionSession countSession ;	// Provider file数を計上するledger。
	DRIVERCRATE_EXPECT( context, countSession.initialize( 106U, countLimits) == 0) ;
	FakeAcquisitionTransport		 countTransport ;	// 呼出し数を記録する取得境界。
	FakeNetworkCostReader			 costReader ;		// Networkを許可するcost境界。
	const OfficialAcquisitionRequest firstRequest =
		makeRequest( NVIDIA_PROVIDER_ID, L"https://us.download.nvidia.com/fixture.bin",
					L"first.bin") ;			// Provider内一件目の要求。
	OfficialAcquisitionResult firstResult ;	// 一件目の成功結果。
	DRIVERCRATE_EXPECT( context,
					   countSession.acquire(
						   firstRequest, countWorkspace, countTransport, costReader,
						   []( const std::uint64_t, const std::uint64_t) {}, {}, firstResult) == 0) ;
	const OfficialAcquisitionRequest secondRequest =
		makeRequest( NVIDIA_PROVIDER_ID, L"https://us.download.nvidia.com/fixture.bin",
					L"second.bin") ;			// Provider file数超過要求。
	OfficialAcquisitionResult secondResult ;	// 上限超過時の拒否結果。
	DRIVERCRATE_EXPECT( context,
					   countSession.acquire(
						   secondRequest, countWorkspace, countTransport, costReader,
						   []( const std::uint64_t, const std::uint64_t) {}, {}, secondResult) != 0) ;
	DRIVERCRATE_EXPECT( context, secondResult.state == OfficialAcquisitionState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, countTransport.downloadCalls == 1U) ;

	OfficialAcquisitionLimits byteLimits = makeLimits() ;	// Sessionへ5 byteだけ許可する予算。
	byteLimits.maximumFileBytes			 = 4U ;
	byteLimits.maximumProviderBytes		 = 5U ;
	byteLimits.maximumSessionBytes		 = 5U ;
	OfficialDownloadWorkspace byteWorkspace ;	// 一件目の3 byte fileを所有する領域。
	DRIVERCRATE_EXPECT( context, byteWorkspace.initialize( L"acquire-test", 107U) == 0) ;
	OfficialAcquisitionSession byteSession ;	// 複数Providerのsession byteを計上するledger。
	DRIVERCRATE_EXPECT( context, byteSession.initialize( 107U, byteLimits) == 0) ;
	FakeAcquisitionTransport   byteTransport ;	// 三byteの取得呼出し数を記録する境界。
	OfficialAcquisitionRequest nvidiaRequest =
		makeRequest( NVIDIA_PROVIDER_ID, L"https://us.download.nvidia.com/fixture.bin",
					L"nvidia.bin") ;	// Session内一件目の3 byte要求。
	nvidiaRequest.maximumFileBytes = 4U ;
	nvidiaRequest.publishedSize	   = 3U ;
	OfficialAcquisitionResult nvidiaResult ;	// Session内一件目の成功結果。
	DRIVERCRATE_EXPECT( context,
					   byteSession.acquire(
						   nvidiaRequest, byteWorkspace, byteTransport, costReader,
						   []( const std::uint64_t, const std::uint64_t) {}, {}, nvidiaResult) == 0) ;
	OfficialAcquisitionRequest dellRequest =
		makeRequest( DELL_PROVIDER_ID, L"https://dl.dell.com/fixture.bin",
					L"dell.bin") ;	// Provider単体上限内だがsession byteを超える要求。
	dellRequest.maximumFileBytes = 4U ;
	dellRequest.publishedSize	 = 3U ;
	OfficialAcquisitionResult dellResult ;	// Session byte超過時の拒否結果。
	DRIVERCRATE_EXPECT( context,
					   byteSession.acquire(
						   dellRequest, byteWorkspace, byteTransport, costReader,
						   []( const std::uint64_t, const std::uint64_t) {}, {}, dellResult) != 0) ;
	DRIVERCRATE_EXPECT( context, dellResult.state == OfficialAcquisitionState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, byteTransport.downloadCalls == 1U) ;

	OfficialAcquisitionLimits diskLimits = makeLimits() ;	// 空き容量を残せない予算。
	diskLimits.minimumFreeBytes			 = std::numeric_limits<std::uint64_t>::max() ;
	OfficialDownloadWorkspace diskWorkspace ;	// Disk拒否時に空のままの領域。
	DRIVERCRATE_EXPECT( context, diskWorkspace.initialize( L"acquire-test", 108U) == 0) ;
	OfficialAcquisitionSession diskSession ;	// Disk reserveを検証するledger。
	DRIVERCRATE_EXPECT( context, diskSession.initialize( 108U, diskLimits) == 0) ;
	FakeAcquisitionTransport		 diskTransport ;	// 呼ばれないことを確認する取得境界。
	const OfficialAcquisitionRequest diskRequest =
		makeRequest( DELL_PROVIDER_ID, L"https://dl.dell.com/fixture.bin",
					L"disk-full.bin") ;		// Disk reserve違反要求。
	OfficialAcquisitionResult diskResult ;	// Disk拒否結果。
	DRIVERCRATE_EXPECT( context,
					   diskSession.acquire(
						   diskRequest, diskWorkspace, diskTransport, costReader,
						   []( const std::uint64_t, const std::uint64_t) {}, {}, diskResult) != 0) ;
	DRIVERCRATE_EXPECT( context, diskResult.state == OfficialAcquisitionState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, diskTransport.downloadCalls == 0U) ;
}

/** @brief 固定と委譲でSHA-512の必須照合と失敗file回収を検証します。
 * @param[in,out] context Assertion集計先。
 */
void testPublishedSha512Acquisition( TestContext &context)
{
	const std::wstring correct256 =
		L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ;	// abcのSHA-256。
	const std::wstring correct512 =
		// abcのSHA-512。
		L"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" ;
	// 固定URLとrecord委譲の両経路へ同じhash条件を適用する。
	for( const bool delegated : {false, true}) {
		// 0単独、1両方、2大文字、3不一致512、4不正512、5不一致256、6混在権限を比較する。
		for( std::uint32_t variant = 0U; variant < 7U; ++variant) {
			const ScanSessionId sessionId =
				950U + variant + (delegated ? 10U : 0U) ;	// 独立session。
			OfficialDownloadWorkspace workspace ;			// 部分file回収を照合する保護領域。
			DRIVERCRATE_EXPECT( context,
							   workspace.initialize( L"sha512-acquisition", sessionId) == 0) ;
			OfficialAcquisitionSession session ;	// 既存64 byte有限予算。
			DRIVERCRATE_EXPECT( context, session.initialize( sessionId, makeLimits()) == 0) ;
			std::wstring hash256 = variant == 0U ? L"" : correct256 ;	// 公開256値。
			std::wstring hash512 = correct512 ;							// 公開512値。
			// 大文字だけの差異は受理する。
			if( variant == 2U) {
				std::ranges::transform( hash512, hash512.begin(), []( wchar_t ch) {
					return ch >= L'a' && ch <= L'f' ? static_cast<wchar_t>( ch - L'a' + L'A') : ch ;
				}) ;
			}

			// 正しい256で誤った512を隠さない。
			if( variant == 3U) {
				hash512[0] = L'0' ;
			}

			// 不正hexは通信前に拒否する。
			if( variant == 4U) {
				hash512[0] = L'g' ;
			}

			// 正しい512で誤った256を隠さない。
			if( variant == 5U) {
				hash256[0] = L'0' ;
			}

			RecordScopedDownloadGrant grant ;	// 委譲時だけ発行する一回権限。
			auto					  request =
				makeRequest( NVIDIA_PROVIDER_ID, L"https://us.download.nvidia.com/fixture.bin",
							L"hash.bin") ;	// 固定取得要求。
			request.publishedSha256 = hash256 ;
			request.publishedSha512 = hash512 ;
			// Grant要求には公開hashを直書きせず、検証済みrecordから導出する。
			if( delegated) {
				const auto issueError =
					issueDelegatedGrant( grant, sessionId, 701U, 801U, hash256,
										L"https://temporary.fixture.invalid/driver.zip",
										std::nullopt, 3U, hash512) ;	// 発行結果。
				DRIVERCRATE_EXPECT( context, (issueError == 0) == (variant != 4U)) ;
				// 不正recordから取得要求を作らない。
				if( issueError != 0) {
					continue ;
				}

				request = makeDelegatedRequest( grant, 701U, L"hash.bin") ;
				// Grantと固定hashの混在を専用反例にする。
				if( variant == 6U) {
					request.publishedSha512 = hash512 ;
				}
			}

			FakeAcquisitionTransport  transport ;	// abcだけを返す非通信境界。
			FakeNetworkCostReader	  cost ;		// 無制限の架空回線。
			OfficialAcquisitionResult result ;		// 公開hash別の照合結果。
			const auto				  error = session.acquire(
				   request, workspace, transport, cost, []( std::uint64_t, std::uint64_t) {}, {},
				   result) ;														// 取得全体の実際の結果。
			const bool success = variant < 3U || (!delegated && variant == 6U) ;	// 固定した期待値。
			DRIVERCRATE_EXPECT( context, (error == 0) == success) ;
			DRIVERCRATE_EXPECT( context, result.publishedSha512Verified == success) ;
			DRIVERCRATE_EXPECT( context,
							   result.publishedSha256Verified == (success && variant != 0U)) ;
			DRIVERCRATE_EXPECT( context, fileExists( workspace.path( L"hash.bin")) == success) ;
			// 成功時の内部identityは公開512だけでもSHA-256を維持する。
			if( success) {
				DRIVERCRATE_EXPECT( context, result.sha256 == correct256) ;
			}

			// 構文・権限拒否は通信せず、hash不一致はfileを受け取った後に拒否する。
			if( variant == 4U || (delegated && variant == 6U)) {
				DRIVERCRATE_EXPECT( context, transport.downloadCalls == 0U &&
												transport.delegatedDownloadCalls == 0U) ;
			}

			// どちらの公開hashが不一致でも同じCRC診断を保持する。
			if( variant == 3U || variant == 5U) {
				DRIVERCRATE_EXPECT(
					context, error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CRC))) ;
			}
		}
	}
}

/**
 * @brief 三つの取得専用profileを実file書込みfakeで確認し、内容検査への流用を拒否します。
 * @param[in,out] context Assertion集計先。
 * @note 本文はabcの3 byteです。大容量転送やEXE構造の実測ではありません。
 */
void testDownloadOnlyAcquisition( TestContext &context)
{
	const std::wstring correctHash =
		L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ;	// abcの公開hash。
	const std::array profiles{OfficialDownloadOnlyProfile::STANDARD_128_MIB,
							  OfficialDownloadOnlyProfile::EXTENDED_512_MIB,
							  OfficialDownloadOnlyProfile::LARGE_2_GIB} ;	// 許可する有限profile。
	// 三profileごとに成功・hash不一致・不足ledger・取消しを独立評価する。
	for( const auto profile : profiles) {
		// 小さなfakeの四経路をそれぞれ独立したsessionで検証する。
		for( unsigned variant = 0U; variant < 4U; ++variant) {
			const ScanSessionId sessionId = 330U + variant ;								// Scopeごとに独立したsession。
			const auto			maximum	  = officialDownloadOnlyMaximumBytes( profile) ;	// 固定上限。
			OfficialDownloadWorkspace workspace ;											// 架空fileを終了時に回収するowner。
			DRIVERCRATE_EXPECT( context,
							   workspace.initialize( L"download-only-test", sessionId) == 0) ;
			OfficialAcquisitionSession session ;						// 新profileを明示する有限ledger。
			const auto limit = variant == 2U ? maximum - 1U : maximum ;	// 一byte不足の反例。
			DRIVERCRATE_EXPECT(
				context, session.initialize( sessionId, {limit, limit, limit, 1024U, 1U, 1U}) == 0) ;
			RecordScopedDownloadGrant grant ;	// Kindと上限に結合する一回権限。
			DRIVERCRATE_EXPECT(
				context, issueDelegatedGrant( grant, sessionId, 901U, 801U,
											 variant == 1U ? std::wstring( 64U, L'0') : correctHash,
											 L"https://temporary.fixture.invalid/driver.exe",
											 std::nullopt, 3U, {}, profile) == 0) ;
			FakeAcquisitionTransport  transport ;									// abcだけを返す非通信I/O。
			FakeNetworkCostReader	  cost ;										// 非課金の架空回線。
			OfficialAcquisitionResult result ;										// 未検査の取得結果。
			const auto		 utc	   = []() { return std::uint64_t{20'010U} ; } ;	// 固定有効時刻。
			const auto		 cancelled = [variant]() { return variant == 3U ; } ;	// 取消し反例。
			const std::array rejectedProfiles{
				OfficialDownloadOnlyProfile::DISABLED,
				profile == OfficialDownloadOnlyProfile::STANDARD_128_MIB
					? OfficialDownloadOnlyProfile::EXTENDED_512_MIB
					: OfficialDownloadOnlyProfile::STANDARD_128_MIB} ;	// 未指定と別予算の拒否。
			// 型と明示profileの不一致は回線照会・grant消費・架空転送も始めず拒否する。
			for( const auto rejectedProfile : rejectedProfiles) {
				DRIVERCRATE_EXPECT( context, acquireGrantedOfficialPayload(
												session, workspace, transport, cost, grant, utc,
												false, cancelled, result, rejectedProfile) ==
												static_cast<NativeError>( E_INVALIDARG)) ;
				DRIVERCRATE_EXPECT( context, result.state == OfficialAcquisitionState::REJECTED &&
												cost.readCalls == 0U &&
												transport.delegatedDownloadCalls == 0U &&
												transport.downloadCalls == 0U) ;
				DRIVERCRATE_EXPECT( context, grant.metadata().state ==
												OfficialDownloadGrantState::GRANT_ISSUED) ;
			}

			const auto error =
				acquireGrantedOfficialPayload( session, workspace, transport, cost, grant, utc,
											  false, cancelled, result, profile) ;	// 本番bridge。
			DRIVERCRATE_EXPECT( context, (error == 0) == (variant == 0U)) ;
			DRIVERCRATE_EXPECT( context,
							   fileExists( workspace.path( L"payload.bin")) == (variant == 0U)) ;
			DRIVERCRATE_EXPECT( context, !fileExists( workspace.path( L"payload.zip"))) ;
			// 成功はbyte取得だけであり、内容検査能力を付与しない。
			if( variant == 0U) {
				DRIVERCRATE_EXPECT( context, result.byteCount == 3U &&
												result.sha256 == correctHash &&
												result.publishedSha256Verified) ;
				DRIVERCRATE_EXPECT( context, transport.lastMaximumBytes == 3U &&
												transport.delegatedDownloadCalls == 1U) ;
				DelegatedOfficialPackageInput package ;	// INF検査への誤接続を拒否。
				DRIVERCRATE_EXPECT( context,
								   makeDelegatedOfficialPackageInput( result, grant, package) != 0) ;
				DRIVERCRATE_EXPECT( context, package.archive.inspectionPath.empty()) ;
			}

			// 予算不足と取消しはpayload処理前に停止する。
			if( variant >= 2U) {
				DRIVERCRATE_EXPECT( context, transport.downloadCalls == 0U &&
												transport.delegatedDownloadCalls == 0U) ;
			}

			// Hash不一致を形式検査エラーや成功へ置換しない。
			if( variant == 1U) {
				DRIVERCRATE_EXPECT(
					context, error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CRC))) ;
			}
		}
	}
}

/**
 * @brief 所有する架空取得fileだけを改変し、元byte再確認を試験する。
 * @param[in] path 当該fixtureの保護workspace内file。
 * @param[in] bytes 最大四byteの生成済み架空本文。
 * @return 完全書込み成功ならtrue。handleはscope終了で解放する。
 */
bool overwriteAcquiredEvidenceFixture( const std::wstring &path, std::string_view bytes)
{
	const HANDLE opened =
		CreateFileW( path.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
					nullptr) ;	// 自身のfixtureだけを変更する。
	// 無効handleをRAII所有者へ渡さない。
	if( opened == INVALID_HANDLE_VALUE) {
		return false ;
	}

	std::unique_ptr<void, decltype( &CloseHandle)> file( opened, CloseHandle) ;	// 同期所有するwriter。
	DWORD										  written{} ;					// 四byte以下の完全書込み数。
	return WriteFile( file.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &written,
					 nullptr) &&
		   written == bytes.size() ;
}

/**
 * @brief 固定resourceの取得証拠を、公開結果と別sessionから偽造できないことを検証する。
 * @param[in,out] context 専用targetのassertion集計先。
 */
void testSealedFixedAcquisitionEvidence( TestContext &context)
{
	static_assert( !std::is_copy_constructible_v<OfficialAcquiredFileEvidence>) ;
	static_assert( !std::is_copy_assignable_v<OfficialAcquiredFileEvidence>) ;
	static_assert( !std::is_aggregate_v<OfficialAcquiredFileEvidence>) ;
	static_assert( std::is_nothrow_move_assignable_v<OfficialAcquiredFileEvidence>) ;
	OfficialDownloadWorkspace workspace ;		// 全架空取得を単独所有する元領域。
	OfficialDownloadWorkspace otherWorkspace ;	// 同byteでも位置の違う別領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"sealed-acquired-test", 8101U) == 0) ;
	DRIVERCRATE_EXPECT( context, otherWorkspace.initialize( L"sealed-acquired-other", 8101U) == 0) ;
	OfficialAcquisitionSession	 session ;	// 元証拠の私有issuerを所有する。
	OfficialAcquiredFileEvidence empty ;	// 既定無効証拠。
	DRIVERCRATE_EXPECT( context, !empty.issuerAlive()) ;
	DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( workspace, 1U, empty) != 0) ;
	DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( empty, workspace) != 0) ;
	DRIVERCRATE_EXPECT( context, session.initialize( 8101U, makeLimits()) == 0) ;
	DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( workspace, 0U, empty) != 0) ;
	DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( workspace, 1U, empty) != 0) ;
	FakeAcquisitionTransport transport ;	// abcだけの架空本文、実通信しない。
	FakeNetworkCostReader	 cost ;			// 同意状態の再現に実NLMを使わない。
	const auto				 firstRequest =
		makeRequest( NVIDIA_PROVIDER_ID, L"https://us.download.nvidia.com/fixture.bin",
					L"first.bin") ;		// 組み込みresource形式のfixture。
	OfficialAcquisitionResult result ;	// UIへ渡さない公開取得metadata。
	DRIVERCRATE_EXPECT( context, session.acquire(
									firstRequest, workspace, transport, cost,
									[]( std::uint64_t, std::uint64_t) {}, {}, result) == 0) ;
	OfficialAcquiredFileEvidence first ;	// 完全成功した元fileだけの証拠。
	DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( workspace, 1U, first) == 0) ;
	DRIVERCRATE_EXPECT( context, first.issuerAlive()) ;
	DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( first, workspace) == 0) ;
	DRIVERCRATE_EXPECT( context, first.observation().sha256 == result.sha256) ;
	DRIVERCRATE_EXPECT( context, first.observation().byteCount == 3U) ;
	DRIVERCRATE_EXPECT( context, !first.observation().delegatedRecord) ;
	DRIVERCRATE_EXPECT( context,
					   std::ranges::all_of( first.recordFingerprint().bytes, []( std::byte value) {
						   // 固定resource取得へrecordの証拠を捏造しない。
						   return value == std::byte{} ;
					   })) ;
	const auto originalPath = result.inspectionPath ;	// 改変対象は元fixtureだけ。
	const auto originalHash = result.sha256 ;			// 公開値と私有成功値の独立性を照合する。
	result.sha256			= L"forged" ;
	result.inspectionPath	= otherWorkspace.path( L"first.bin") ;
	result.acquisitionId	= 999U ;
	result.delegatedRecord	= true ;
	DRIVERCRATE_EXPECT( context,
					   session.bindAcquiredFile( workspace, result.acquisitionId, empty) != 0) ;
	DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( workspace, 1U, empty) == 0) ;
	DRIVERCRATE_EXPECT( context, empty.observation().sha256 == originalHash) ;
	DRIVERCRATE_EXPECT( context, empty.observation().inspectionPath == originalPath) ;
	DRIVERCRATE_EXPECT( context, !empty.observation().delegatedRecord) ;
	DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( otherWorkspace, 1U, empty) != 0) ;
	DRIVERCRATE_EXPECT( context, !empty.issuerAlive()) ;
	DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( first, otherWorkspace) != 0) ;
	OfficialAcquisitionSession otherSession ;	// 同じ数値IDでも別issuerである。
	DRIVERCRATE_EXPECT( context, otherSession.initialize( 8101U, makeLimits()) == 0) ;
	OfficialAcquisitionResult otherResult ;	// 同byte・同数値IDの別成功取得。
	DRIVERCRATE_EXPECT( context, otherSession.acquire(
									firstRequest, otherWorkspace, transport, cost,
									[]( std::uint64_t, std::uint64_t) {}, {}, otherResult) == 0) ;
	OfficialAcquiredFileEvidence other ;	// 別sessionが発行する正当な架空証拠。
	DRIVERCRATE_EXPECT( context, otherSession.bindAcquiredFile( otherWorkspace, 1U, other) == 0) ;
	DRIVERCRATE_EXPECT( context, other.observation().sha256 == originalHash) ;
	DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( other, otherWorkspace) != 0) ;
	DRIVERCRATE_EXPECT( context, otherSession.verifyAcquiredFile( first, workspace) != 0) ;
	DRIVERCRATE_EXPECT( context, overwriteAcquiredEvidenceFixture( originalPath, "abcd")) ;
	DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( first, workspace) ==
									static_cast<NativeError>( TRUST_E_BAD_DIGEST)) ;
	DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( workspace, 1U, empty) != 0) ;
	DRIVERCRATE_EXPECT( context, !empty.issuerAlive()) ;
	DRIVERCRATE_EXPECT( context, overwriteAcquiredEvidenceFixture( originalPath, "abd")) ;
	DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( first, workspace) ==
									static_cast<NativeError>( TRUST_E_BAD_DIGEST)) ;
	DRIVERCRATE_EXPECT( context, overwriteAcquiredEvidenceFixture( originalPath, "abc")) ;
	DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( first, workspace) == 0) ;
	{
		const HANDLE writer = CreateFileW(
			originalPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) ;	// 本fixtureの既存writerだけを保持する。
		DRIVERCRATE_EXPECT( context, writer != INVALID_HANDLE_VALUE) ;
		// 作成失敗を無効RAII handleへ渡さない。
		if( writer != INVALID_HANDLE_VALUE) {
			std::unique_ptr<void, decltype( &CloseHandle)> owned(
				writer, CloseHandle) ;	// 終了時に必ず解放する。
			DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( first, workspace) ==
											HRESULT_FROM_WIN32( ERROR_SHARING_VIOLATION)) ;
			DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( workspace, 1U, empty) != 0) ;
			DRIVERCRATE_EXPECT( context, !empty.issuerAlive()) ;
		}
	}
	DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( first, workspace) == 0) ;
	OfficialAcquiredFileEvidence moved( std::move( first)) ;	// 移動元では再照合できない。
	DRIVERCRATE_EXPECT( context, !first.issuerAlive()) ;
	DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( first, workspace) != 0) ;
	DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( moved, workspace) == 0) ;
	OfficialAcquiredFileEvidence assigned ;	// move代入の所有先。
	assigned = std::move( moved) ;
	DRIVERCRATE_EXPECT( context, !moved.issuerAlive()) ;
	DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( assigned, workspace) == 0) ;
	transport.bytes = "xyz" ;
	const auto secondRequest =
		makeRequest( NVIDIA_PROVIDER_ID, L"https://us.download.nvidia.com/fixture.bin",
					L"second.bin") ;	// 次の成功file。
	DRIVERCRATE_EXPECT( context, session.acquire(
									secondRequest, workspace, transport, cost,
									[]( std::uint64_t, std::uint64_t) {}, {}, result) == 0) ;
	DRIVERCRATE_EXPECT( context, result.acquisitionId == 2U) ;
	DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( workspace, 1U, empty) != 0) ;
	DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( assigned, workspace) == 0) ;
	OfficialAcquiredFileEvidence second ;	// 成功直後にだけ新規発行できる次の証拠。
	DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( workspace, 2U, second) == 0) ;
	DRIVERCRATE_EXPECT( context, second.observation().sha256 != originalHash) ;
	transport.evidence = false ;
	const auto failedRequest =
		makeRequest( NVIDIA_PROVIDER_ID, L"https://us.download.nvidia.com/fixture.bin",
					L"failed.bin") ;	// 根拠不在のfileは既存cleanupへ戻す。
	DRIVERCRATE_EXPECT( context, session.acquire(
									failedRequest, workspace, transport, cost,
									[]( std::uint64_t, std::uint64_t) {}, {}, result) != 0) ;
	DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( workspace, 3U, empty) != 0) ;
	DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( workspace, 2U, empty) == 0) ;
	DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( assigned, workspace) == 0) ;
	transport.evidence		  = true ;
	transport.throwAfterWrite = true ;
	DRIVERCRATE_EXPECT( context, session.acquire(
									failedRequest, workspace, transport, cost,
									[]( std::uint64_t, std::uint64_t) {}, {}, result) != 0) ;
	DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( workspace, 3U, empty) != 0) ;
	DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( workspace, 2U, empty) == 0) ;
	transport.throwAfterWrite = false ;
	NativeError reentrantBind{} ;	// 取得中の発行拒否診断。
	NativeError reentrantVerify{} ;	// 取得中の再照合拒否診断。
	const auto	thirdRequest =
		makeRequest( NVIDIA_PROVIDER_ID, L"https://us.download.nvidia.com/fixture.bin",
					L"third.bin") ;	// 再入試験後に成功させるfile。
	DRIVERCRATE_EXPECT( context,
					   session.acquire(
						   thirdRequest, workspace, transport, cost,
						   [&]( std::uint64_t, std::uint64_t) {
							   // 全借用値が生存する同期callbackだけで、取得中の再入を再現する。
							   reentrantBind   = session.bindAcquiredFile( workspace, 2U, empty) ;
							   reentrantVerify = session.verifyAcquiredFile( second, workspace) ;
						   },
						   {}, result) == 0) ;
	DRIVERCRATE_EXPECT( context, reentrantBind != 0 && reentrantVerify != 0) ;
	DRIVERCRATE_EXPECT( context, !empty.issuerAlive()) ;
	DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( second, workspace) == 0) ;
	DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( workspace, 2U, empty) != 0) ;
	DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( workspace, 3U, empty) == 0) ;
	OfficialAcquiredFileEvidence orphan ;			// 発行者破棄後にもmetadataだけ残る証拠。
	OfficialDownloadWorkspace	 orphanWorkspace ;	// 元fileは発行session終了後も所有する。
	DRIVERCRATE_EXPECT( context, orphanWorkspace.initialize( L"sealed-acquired-orphan", 8101U) == 0) ;
	auto owner = std::make_unique<OfficialAcquisitionSession>() ;	// 破棄を明示できる発行session。
	DRIVERCRATE_EXPECT( context, owner->initialize( 8101U, makeLimits()) == 0) ;
	DRIVERCRATE_EXPECT( context, owner->acquire(
									firstRequest, orphanWorkspace, transport, cost,
									[]( std::uint64_t, std::uint64_t) {}, {}, result) == 0) ;
	DRIVERCRATE_EXPECT( context, owner->bindAcquiredFile( orphanWorkspace, 1U, orphan) == 0) ;
	DRIVERCRATE_EXPECT( context, orphan.issuerAlive()) ;
	DRIVERCRATE_EXPECT( context, owner->verifyAcquiredFile( orphan, orphanWorkspace) == 0) ;
	owner.reset() ;
	DRIVERCRATE_EXPECT( context, !orphan.issuerAlive()) ;
	DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( orphan, orphanWorkspace) != 0) ;
	DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( empty, workspace) == 0) ;
}

/**
 * @brief Record限定grantの成功IDとfingerprintを封印し、旧grant再使用を拒否する。
 * @param[in,out] context 専用targetのassertion集計先。
 */
void testSealedDelegatedAcquisitionEvidence( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// Record成功fileだけを所有する架空領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"sealed-acquired-grant", 8102U) == 0) ;
	OfficialAcquisitionSession session ;	// Record成功を発行issuerへ結合する。
	DRIVERCRATE_EXPECT( context, session.initialize( 8102U, makeLimits()) == 0) ;
	RecordScopedDownloadGrant grant ;	// 一回の架空record限定GET。
	DRIVERCRATE_EXPECT( context, issueDelegatedGrant( grant, 8102U, 71U, 81U, {}) == 0) ;
	const auto fingerprint = grant.metadata().recordFingerprint ;	// 成功前のstable field固定値。
	FakeAcquisitionTransport transport ;							// 真のHTTPや署名を確認したと扱わない架空転送。
	FakeNetworkCostReader	 cost ;									// 実NLM照会をしない。
	const auto				 request =
		// 秘密URLを出力しない要求。
		makeDelegatedRequest( grant, 71U, L"grant.bin") ;
	OfficialAcquisitionResult result ;	// 通常の公開結果は証拠発行の入力ではない。
	DRIVERCRATE_EXPECT( context, session.acquire(
									request, workspace, transport, cost,
									[]( std::uint64_t, std::uint64_t) {}, {}, result) == 0) ;
	OfficialAcquiredFileEvidence evidence ;	// 成功grantと実fileを結合した証拠。
	DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( workspace, 1U, evidence) == 0) ;
	DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( evidence, workspace) == 0) ;
	DRIVERCRATE_EXPECT( context, evidence.observation().delegatedRecord) ;
	DRIVERCRATE_EXPECT( context, evidence.observation().recordEvidenceId == 81U) ;
	DRIVERCRATE_EXPECT( context, evidence.observation().downloadGrantId == 71U) ;
	DRIVERCRATE_EXPECT( context, evidence.observation().destinationLocallyResolved) ;
	DRIVERCRATE_EXPECT( context, evidence.observation().validatedDestinationAddressCount == 1U) ;
	DRIVERCRATE_EXPECT( context, evidence.recordFingerprint().bytes == fingerprint.bytes) ;
	DRIVERCRATE_EXPECT( context, std::ranges::any_of( fingerprint.bytes, []( std::byte value) {
						   // Record指紋は未検査の全zeroではない。
						   return value != std::byte{} ;
					   })) ;
	result.recordEvidenceId = 999U ;
	result.downloadGrantId	= 999U ;
	DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( workspace, 1U, evidence) == 0) ;
	DRIVERCRATE_EXPECT( context, evidence.observation().recordEvidenceId == 81U) ;
	DRIVERCRATE_EXPECT( context, evidence.observation().downloadGrantId == 71U) ;
	const auto reused =
		// 終端済みgrantは消費予算へ戻さない。
		makeDelegatedRequest( grant, 71U, L"reused.bin") ;
	DRIVERCRATE_EXPECT( context, session.acquire(
									reused, workspace, transport, cost,
									[]( std::uint64_t, std::uint64_t) {}, {}, result) != 0) ;
	OfficialAcquiredFileEvidence failed ;	// 再使用失敗から新しい証拠を生成しない。
	DRIVERCRATE_EXPECT( context, session.bindAcquiredFile( workspace, 2U, failed) != 0) ;
	DRIVERCRATE_EXPECT( context, !failed.issuerAlive()) ;
	DRIVERCRATE_EXPECT( context, session.verifyAcquiredFile( evidence, workspace) == 0) ;
}

} // namespace

/** @see official_acquisition_tests.h 宣言側の契約を正本とする。 */
void runOfficialAcquiredFileEvidenceTests( TestContext &context)
{
	testSealedFixedAcquisitionEvidence( context) ;
	testSealedDelegatedAcquisitionEvidence( context) ;
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_acquisition_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOfficialAcquisitionTests( TestContext &context)
{
	testDownloadOnlyAcquisition( context) ;
	testPublishedSha512Acquisition( context) ;
	testWorkspaceSecurity( context) ;
	testInitializationLimits( context) ;
	testSuccessfulAcquisition( context) ;
	testDelegatedAcquisitionAndCleanup( context) ;
	testDelegatedBindingAndMetadataRejection( context) ;
	testOf05DelegatedHttpSuccessfulRoutes( context) ;
	testDelegatedHttpFailureCleanup( context) ;
	testOf09DelegatedMetadataAndBodyRejection( context) ;
	testAsusPackageAcquisition( context) ;
	testMetadataAndEvidenceRejection( context) ;
	testNetworkConsent( context) ;
	testCancellationAndExceptionCleanup( context) ;
	testBudgetAndDiskRejection( context) ;
}

/** @brief 真署名lookupから既存preparation・同grant・fake HTTP・seal・通常検査を確認します。
 * @param[in,out] context 共通assertion集計先。
 * @param[in] lookup 真署名・隔離reloadから構築した不変lookup。
 * @param[in] nowUtc 固定信頼UTC。
 * @param[in] scenario 0は通常、1は計算hash不一致、2はsize不一致、3は保留、4はCDN、6は未知hash／sizeです。
 */
void runSignedIndexAcquisitionAdapterTests( TestContext									 &context,
										   std::shared_ptr<const SignedIndexRecordLookup> lookup,
										   const std::chrono::sys_seconds				  nowUtc,
										   const unsigned								  scenario)
{
	const int				 firstAssertion = context.assertionCount() ;	// この統合groupの有限集計。
	const int				 firstFailure	= context.failureCount() ;		// 旧groupの失敗を消しません。
	const IndexLookupContext current{71U, 72U, 73U} ;						// 署名fixtureと同じworker context。
	const std::uint64_t		 now =
		// 固定信頼UTC秒。
		static_cast<std::uint64_t>( nowUtc.time_since_epoch().count()) ;
	const OfficialPreparationLimits limits{64U, 128U, 256U, 2U, 4U} ;	// 小さな有限予約予算。
	std::uint32_t					fakeSends{} ;						// この署名snapshotだけのfake送信実績。
	// 正常snapshotは10種のHTTP／lease境界、他record条件は一回だけ確認します。
	for( unsigned mode = 0U; mode < (scenario == 0U ? 10U : 1U); ++mode) {
		SignedIndexAcquisitionAdapter product ;	// 製品能力policyは空のままです。
		DRIVERCRATE_EXPECT( context, product.begin( lookup, current, IndexTargetOs::WINDOWS_11,
												  nowUtc) == E_ACCESSDENIED) ;
		SignedIndexAcquisitionAdapter adapter ;	// 非公開fixed fixture capabilityだけを使用します。
		DRIVERCRATE_EXPECT( context,
						   signed_index_acquisition_detail::Access::beginFixture(
							   adapter, lookup, current, IndexTargetOs::WINDOWS_11, nowUtc) == 0) ;
		SignedIndexPreparationDescription description ;	// URL非保持の元計画snapshot。
		const NativeError				  describeError =
			// 同関係記述結果。
			adapter.describe( 0U, current, nowUtc, limits, description) ;
		// 規約／条件未接続と旧v1を同意不要や取得正常へ変更しません。
		if( scenario == 3U) {
			DRIVERCRATE_EXPECT( context, describeError == E_NOTIMPL && !description.target &&
											!description.reason.empty()) ;
			break ;
		}

		DRIVERCRATE_EXPECT( context, describeError == 0 && description.target.has_value()) ;
		// Fixture不成立で部分正常を参照しません。
		if( !description.target) {
			break ;
		}

		IndexLookupContext stale = current ;	// Inventoryだけ異なる公開context。
		++stale.inventoryGeneration ;
		SignedIndexPreparationDescription refused ;	// 拒否時にtargetを残さない確認先。
		DRIVERCRATE_EXPECT( context, adapter.describe( 0U, stale, nowUtc, limits, refused) != 0 &&
										!refused.target) ;
		const OfficialPreparationTarget target =
			*description.target ;	// Workerが保持する完全snapshot。
		auto copiedRecord =
			lookup->snapshot()
				.schemaReceipt()
				.records()[lookup->relations()[0].recordIndex] ;	// 公開record DTOの自由な複写。
		auto copiedRelation	  = lookup->relations()[0] ;			// 公開relation DTOの自由な複写。
		copiedRecord.sourceId = "forged-self-declaration" ;
		copiedRecord.recordSha256[0] ^= 1U ;
		copiedRelation.sourceId = copiedRecord.sourceId ;
		++copiedRelation.context.scanSessionId ;
		OfficialPreparationSession preparation ;									// 実承認と一回active taskの元owner。
		OfficialPreparationPlan plan{current.scanSessionId, 1U, limits, {target}} ;	// 有限一件計画。
		DRIVERCRATE_EXPECT( context, preparation.initialize( std::move( plan)) ==
										OfficialPreparationError::NONE) ;
		OfficialPreparationTask	  fabricated{81U, current.scanSessionId, 1U, target,
											 false} ;	// 承認／claim前の公開DTO自己申告。
		RecordScopedDownloadGrant fabricatedGrant ;		// 自己申告からは発行できません。
		DRIVERCRATE_EXPECT( context, adapter.claimApprovedRecord( preparation, fabricated, current,
																now, fabricatedGrant) != 0 &&
										fabricatedGrant.metadata().state ==
											OfficialDownloadGrantState::NOT_REQUESTED) ;
		const OfficialPreparationApproval approval{
			81U,
			current.scanSessionId,
			1U,
			limits,
			{{target, true, false, false,
			  false}}} ;								// 明示的取得承認だけ。同意不要をEULA同意へ偽装しません。
		OfficialAcquisitionSession acquisitionSession ;	// 同scanの共通file ledger。
		DRIVERCRATE_EXPECT( context,
						   acquisitionSession.initialize( current.scanSessionId, makeLimits()) == 0) ;
		OfficialDownloadWorkspace workspace ;	// 自作の保護一時fileだけを所有します。
		DRIVERCRATE_EXPECT(
			context, workspace.initialize( L"signed-index-fixture", current.scanSessionId) == 0) ;
		DelegatedHttpFixture fixture ;	// 既存の完全WinHTTP／DNS／UTC fake。
		fixture.utcSeconds.assign( 6U, now) ;
		fixture.responses[0].body	  = std::string{"PK\x05\x06", 4U} + std::string( 18U, '\0') ;
		fixture.responses[0].declared = L"22" ;
		// 公開宛先の構文を私設DNS応答の許可と誤解しません。
		if( mode == 1U) {
			fixture.privateDns = true ;
		}

		// 未記載のLocationは次のDNS／HTTPより前に拒否します。
		if( mode == 2U) {
			fixture.responses[0].status	  = HTTP_STATUS_REDIRECT ;
			fixture.responses[0].location = L"https://unlisted.fixture.example/driver.zip" ;
		}

		// 30秒開始余裕を失う時刻は新hopを送信しません。
		if( mode == 4U) {
			fixture.utcSeconds.assign( 6U, now + 872U) ;
		}

		// 期待media type不一致では本文を保存しません。
		if( mode == 6U) {
			fixture.responses[0].contentType = L"text/html" ;
		}

		// 公表hash不一致は型とHTTP200だけで合格にしません。
		if( mode == 7U) {
			fixture.responses[0].body	  = "abc" ;
			fixture.responses[0].declared = L"3" ;
		}

		// 元WinHTTP failureを取消しやhash拒否へまとめません。
		if( mode == 8U) {
			fixture.failReadAt = 1U ;
		}

		// 時計確認不能をgrant発行時の成功で補完しません。
		if( mode == 9U) {
			fixture.utcSeconds.assign( 6U, 0U) ;
		}

		activeDelegatedHttpFixture = &fixture ;
		OfficialHttpClient client(
			// 同じ製品HTTP実装の全低位I/Oだけをfakeへ置換。
			makeDelegatedHttpTransport()) ;
		OfficialHttpAcquisitionTransport transport( client) ;			// 同じ共通取得transport。
		FakeNetworkCostReader			 costReader ;					// 実回線APIを呼ばない無制限fake。
		OfficialAcquisitionResult		 acquired ;						// 実保護file取得の結果。
		NativeError						 inputError = E_UNEXPECTED ;	// 共通入力結合の到達診断。
		// 同期executorが実claimしたtaskだけを借用し、全捕捉はこのscope内に限ります。
		const auto						 acquire = [&]( const OfficialPreparationTask &task,
								   const PreparationCancellation &) {
			  OfficialPreparationTask modified = task ;	// 公開task複写の改変は能力になりません。
			  modified.target.releaseIdentity +=
				  std::wstring{copiedRecord.sourceId.begin(), copiedRecord.sourceId.end()} ;
			  RecordScopedDownloadGrant modifiedGrant ;	// 改変自己申告の拒否先。
			  DRIVERCRATE_EXPECT( context, adapter.claimApprovedRecord( preparation, modified, current,
																						  now, modifiedGrant) != 0) ;
			  RecordScopedDownloadGrant
				  modifiedRelationGrant ;	// 公開relationの同scan自己申告は元lookupを置換できません。
			  DRIVERCRATE_EXPECT( context, adapter.claimApprovedRecord( preparation, task,
																						  copiedRelation.context, now,
																						  modifiedRelationGrant) != 0 &&
																  modifiedRelationGrant.metadata().state ==
																	  OfficialDownloadGrantState::NOT_REQUESTED) ;
			  RecordScopedDownloadGrant grant ;	// 従来と同じ一回grant型。
			  const NativeError			grantError = adapter.claimApprovedRecord(
				  preparation, task, current, now, grant) ;	// 実承認＋封印元recordの発行。
			  DRIVERCRATE_EXPECT(
				  context, grantError == 0 &&
							   grant.metadata().origin ==
								   OfficialDownloadGrantOrigin::SIGNED_INDEX_COLLECTOR_ATTESTATION &&
							   grant.metadata().expiresUtcSeconds == now + 900U) ;
			  RecordScopedDownloadGrant repeated ;	// 同recordの再発行を禁止します。
			  DRIVERCRATE_EXPECT( context, adapter.claimApprovedRecord( preparation, task, current, now,
																						  repeated) != 0) ;
			  SignedIndexAcquisitionAdapter
				  secondAdapter ;	// 別issuerによる同active taskの再発行も禁止します。
			  DRIVERCRATE_EXPECT( context, signed_index_acquisition_detail::Access::beginFixture(
											  secondAdapter, lookup, current,
											  IndexTargetOs::WINDOWS_11, nowUtc) == 0) ;
			  SignedIndexPreparationDescription
				  secondDescription ;	// 同snapshotと同じ公開targetを再記述します。
			  DRIVERCRATE_EXPECT( context, secondAdapter.describe( 0U, current, nowUtc, limits,
																					 secondDescription) == 0) ;
			  RecordScopedDownloadGrant secondGrant ;	// 元preparationの一回予約を迂回できません。
			  DRIVERCRATE_EXPECT( context, secondAdapter.claimApprovedRecord(
											  preparation, task, current, now, secondGrant) != 0) ;
			  // Snapshot共有所有が残っていても元issuer失効後は取得しません。
			  if( mode == 3U) {
				  adapter.invalidate() ;
			  }

			  OfficialAcquisitionRequest request ;	// URLやhostを持たない同grant要求。
			  request.workspaceFileName = L"index-payload.zip" ;
			  request.delegatedGrant	= &grant ;
			  request.delegatedGrantId	= grant.metadata().grantId ;
			  request.delegatedUtcNow	= [now]() {
				return now ;
			  } ; // 固定信頼clockだけを借用せずcaptureします。
			  const NativeError acquireError = acquisitionSession.acquire(
				  request, workspace, transport, costReader, []( std::uint64_t, std::uint64_t) {},
				  [mode]() { return mode == 5U ; }, acquired) ;	// 同共通取得の実呼出し。
			  // 正常byteの共通sealだけを既存内容検査入力へ接続します。
			  if( acquireError == 0) {
				  OfficialAcquiredFileEvidence evidence ;	// 公開DTOから生成できない元file seal。
				  DRIVERCRATE_EXPECT( context, acquisitionSession.bindAcquiredFile(
												  workspace, acquired.acquisitionId, evidence) == 0) ;
				  IndexedDriverArchiveHint hint ;	// 原index／record／実archiveの独立hash。
				  DriverArchiveInput	   input ;	// 既存の通常内容検査入力。
				  inputError = adapter.bindInspectionInput( task, current, now, acquisitionSession,
																			   workspace, evidence, hint, input) ;
				  // 監視PCの計算hashとsizeは公表hashとは別に拒否します。
				  if( scenario == 1U || scenario == 2U) {
					  DRIVERCRATE_EXPECT( context, inputError == HRESULT_FROM_WIN32( ERROR_CRC) &&
																		  input.inspectionPath.empty()) ;
					  return OfficialPreparationTransferResult{OfficialPreparationItemState::REJECTED,
															   inputError, 0U} ;
				  }

				  DRIVERCRATE_EXPECT(
					  context, inputError == 0 &&
								   matchesIndexedDriverArchiveHint( current.scanSessionId, hint, input,
																					   OfficialDriverArchiveFormat::ZIP)) ;
				  IndexedDriverPackageInspection
					  inspected ;	// 通常のINF／CAT検査結果。空ZIPは候補合格ではありません。
				  const NativeError inspectionError = inspectIndexedDriverPackage(
					  current.scanSessionId, hint, input, OfficialDriverArchiveFormat::ZIP,
					  inspected) ;	// 原byte再検査後の空ZIPはdriver候補ではありません。
				  DRIVERCRATE_EXPECT(
					  context,
					  inspected.inputBound &&
						  inspectionError == HRESULT_FROM_WIN32( ERROR_TOO_MANY_OPEN_FILES) &&
						  inspected.state == IndexedDriverInspectionState::INSPECTION_FAILED &&
						  inspected.inspection.infs.empty()) ;
				  std::cout << "Signed index empty ZIP inspection error: " << inspectionError << '\n' ;
				  DRIVERCRATE_EXPECT(
					  context,
					  acquired.recordOrigin ==
							  OfficialDownloadGrantOrigin::SIGNED_INDEX_COLLECTOR_ATTESTATION &&
						  !acquired.publishedSizeVerified &&
						  acquired.publishedSha256Verified == (scenario != 6U) &&
						  acquired.byteCount == 22U && acquired.destinationLocallyResolved) ;
				  return OfficialPreparationTransferResult{
					  OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0, acquired.byteCount} ;
			  }

			  // 元WinHTTP診断の保持を確認します。
			  if( mode == 8U) {
				  DRIVERCRATE_EXPECT( context, acquireError ==
																	  HRESULT_FROM_WIN32( ERROR_WINHTTP_CONNECTION_ERROR)) ;
			  }

			  return OfficialPreparationTransferResult{acquired.state ==
															   OfficialAcquisitionState::CANCELLED
																			   ? OfficialPreparationItemState::CANCELLED
																			   : OfficialPreparationItemState::REJECTED,
													   acquireError, 0U} ;
		} ;
		const auto executed = executeOfficialPreparation(
			preparation, approval, acquire, {}, []( const OfficialPreparationProgress &) {
			}) ; // 実承認・一回task・取得・対象別結果の同executor。
		activeDelegatedHttpFixture = nullptr ;
		DRIVERCRATE_EXPECT( context, executed.approvalError == OfficialPreparationError::NONE &&
										executed.items.size() == 1U &&
										preparation.state() == OfficialPreparationState::COMPLETED) ;
		// 正例が同seal・共通検査入力へ到達したことを実結果で確認します。
		if( mode == 0U && (scenario == 0U || scenario == 4U || scenario == 6U)) {
			DRIVERCRATE_EXPECT( context,
							   inputError == 0 &&
								   executed.items[0].result.state ==
									   OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION &&
								   fixture.sends == 1U) ;
		}
		// 非正常例を全体取得成功として表示しません。
		else {
			DRIVERCRATE_EXPECT( context,
							   !executed.items.empty() &&
								   executed.items[0].result.state !=
									   OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION &&
								   executed.items[0].result.error != 0) ;
		}

		DRIVERCRATE_EXPECT( context, fixture.safeRequest && fixture.opened == fixture.closed) ;
		// DNS拒否・lease失効・取消し・期限／時計拒否は送信0です。
		if( mode == 1U || mode == 3U || mode == 4U || mode == 5U || mode == 9U) {
			DRIVERCRATE_EXPECT( context, fixture.sends == 0U) ;
		}

		fakeSends += fixture.sends ;
	}

	std::cout << "Signed index acquisition adapter assertions: "
			  << context.assertionCount() - firstAssertion
			  << ", failures: " << context.failureCount() - firstFailure
			  << ", fake sends: " << fakeSends << ", native fallback: 0, scenario: " << scenario
			  << '\n' ;
}

namespace {
/** @brief 非通信の同scan関係を通常commandへ返す有限resolverです。 */
class WorkerAcquisitionResolver final : public IndexPublicIdResolver {
public:
	/** @brief 元scan contextと前半の対象外関係数を固定します。
	 * @param[in] context 同workerの元scan context。
	 * @param[in] skip 完了不一致へ残す先頭callback数。
	 */
	WorkerAcquisitionResolver( IndexLookupContext context, std::size_t skip)
		: context_( context), skip_( skip)
	{
	}
	/** @brief 全presentが一つというfixtureだけを一意opaqueへ照合します。
	 * @param[in] kind 使用しない公開種別。
	 * @param[in] id 使用しない公開ID。外部送信しません。
	 * @param[in] guid 使用しない公開class。
	 * @param[in] context 原scan context。
	 * @param[in] present 全opaque集合。
	 * @return 前半は完了不一致、後半は一意関係。Windows適合ではありません。
	 */
	IndexPublicIdResolution resolve( IndexPnpIdKind kind, std::string_view id, std::string_view guid,
									IndexLookupContext			  context,
									std::span<const std::wstring> present) const override
	{
		static_cast<void>( kind) ;
		static_cast<void>( id) ;
		static_cast<void>( guid) ;
		IndexPublicIdResolution result{.context	  = context,
									   .completed = context == context_} ;	// 元観測だけです。
		// Batch境界より後にだけ正常対象を残し、global relation位置の衝突を検出します。
		if( calls_++ >= skip_ && present.size() == 1U) {
			result.devices.push_back( present.front()) ;
		}

		return result ;
	}

private:
	/// 全field一致が必要な元scan context。
	IndexLookupContext	context_ ;
	/// 対象外へ残す先頭callback数。
	std::size_t			skip_{} ;
	/// 同workerだけが更新する確定callback数。
	mutable std::size_t calls_{} ;
} ;

/** @brief 実inventoryと導入を呼ばない通常command用Providerです。 */
class WorkerAcquisitionProvider final : public IUpdateProvider, public IIndexScanInventory {
public:
	/** @brief 対象外関係数だけを固定します。
	 * @param[in] skip 最初に完了不一致を返す関係数。
	 * @param[in] providerTargets 元Provider計画の人工対象数。0または1です。
	 * @param[in] providerCalls 元Provider acquire callbackの実呼出し集計先。
	 * @param[in] maximumProviderFiles 同scanのProvider別予約数。通常2、例外試験3です。
	 */
	WorkerAcquisitionProvider( std::size_t skip, std::size_t providerTargets,
							  std::shared_ptr<std::atomic_uint32_t> providerCalls,
							  std::uint32_t							maximumProviderFiles = 2U)
		: skip_( skip), providerTargets_( providerTargets), providerCalls_( std::move( providerCalls)),
		  maximumProviderFiles_( maximumProviderFiles)
	{
	}
	/** @brief 現在sessionの空candidate集合を正常scan結果として返します。
	 * @param[in] sessionId 実worker発行session。
	 * @param[in] options 使用しないscan設定。
	 * @param[in] progress 実確定したProvider段階の通知。
	 * @return 導入候補を生成しない正常fixture。
	 */
	ScanResult scan( ScanSessionId sessionId, const ScanOptions &options,
					const ProviderProgressCallback &progress) override
	{
		static_cast<void>( options) ;
		session_ = sessionId ;
		++generation_ ;
		progress( {ProviderStage::MERGING_CANDIDATES, 100U, 1U, 1U}) ;
		ScanResult result ;	// 宣言順の公開DTOへ確定値だけを格納します。
		result.scanSessionId = sessionId ;
		result.succeeded	 = true ;
		result.outcome		 = OutcomeCode::SUCCESS ;
		return result ;
	}
	/** @brief 同commandの完全contextと全opaqueを返します。
	 * @param[in] operationId 元scanの実operation。
	 * @param[out] context 元operation／session／inventory。
	 * @param[out] present 架空の全present集合。
	 * @return 同workerだけが使用する非通信resolver。
	 */
	std::unique_ptr<IndexPublicIdResolver> indexScanInventory(
		OperationId operationId, IndexLookupContext &context,
		std::vector<std::wstring> &present) override
	{
		context = {operationId, session_, generation_} ;
		present = {L"worker-index-device"} ;
		return std::make_unique<WorkerAcquisitionResolver>( context, skip_) ;
	}
	/** @brief 小さな同scan予約枠を索引と共有します。
	 * @param[in] sessionId 同scanのsession。
	 * @param[in] planId 実worker発行計画ID。
	 * @return 人工Provider対象一件までの固定有限計画。索引も同じ上限へ追加します。
	 */
	std::optional<OfficialPreparationPlan> preparationPlan( ScanSessionId sessionId,
														   std::uint64_t planId) override
	{
		OfficialPreparationPlan plan{
			sessionId,
			planId,
			{4096U, 4096ULL * maximumProviderFiles_, 16384U, maximumProviderFiles_, 4U},
			{}} ;	// 同scan枠。
		// 索引と既存Providerの対象が共通256枠へ合算される有限一件だけの人工計画です。
		if( providerTargets_ == 1U) {
			OfficialPreparationTarget target ;	// URLも実fileもない非索引対象。
			target.identity		   = L"original-provider-target" ;
			target.providerId	   = PROLIFIC_OFFICIAL_PROVIDER_ID ;
			target.resourceId	   = L"fixture-payload" ;
			target.releaseIdentity = L"fixture-release" ;
			target.parserRevision  = 1U ;
			target.maximumBytes	   = 100U ;
			target.deviceCount	   = 1U ;
			target.terms		   = OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
			plan.targets.push_back( std::move( target)) ;
		}

		return plan ;
	}
	/** @brief 非索引対象の既存Provider dispatchだけを観測します。
	 * @param[in] task 実executorがclaimした元Provider対象。
	 * @param[in] cancellation 使用しない協調取消し照会。
	 * @return 非実fileの合成取得結果。索引の実内容正例には使用しません。
	 */
	OfficialPreparationTransferResult acquireForInspection(
		const OfficialPreparationTask &task, const PreparationCancellation &cancellation) override
	{
		static_cast<void>( cancellation) ;
		// 索引taskが既存Providerへ誤dispatchされた場合は合成成功へ変更しません。
		if( task.target.providerId != PROLIFIC_OFFICIAL_PROVIDER_ID ||
		   task.target.identity != L"original-provider-target") {
			return {OfficialPreparationItemState::REJECTED,
					static_cast<NativeError>( E_ACCESSDENIED), 0U} ;
		}

		++*providerCalls_ ;
		return {OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0U, 100U} ;
	}
	/** @brief 禁止された実導入を一切行わず拒否します。
	 * @param[in] sessionId 使用しないsession。
	 * @param[in] identities 使用しない選択。
	 * @param[in] parent 使用しないWindow。
	 * @param[in] progress 使用しない通知。
	 * @return 実導入なしの拒否。
	 */
	InstallResult install( ScanSessionId sessionId, std::span<const std::wstring> identities,
						  std::uintptr_t parent, const ProviderProgressCallback &progress) override
	{
		static_cast<void>( sessionId) ;
		static_cast<void>( identities) ;
		static_cast<void>( parent) ;
		static_cast<void>( progress) ;
		return {.installOutcome = OutcomeCode::FAILURE, .installError = E_ACCESSDENIED} ;
	}

private:
	/// 完了不一致へ残す前半関係数。
	std::size_t							  skip_{} ;
	/// 共通上限へ合算する人工Provider対象数。
	std::size_t							  providerTargets_{} ;
	/// 元Provider callbackだけの共有実呼出し集計。
	std::shared_ptr<std::atomic_uint32_t> providerCalls_ ;
	/// 例外後の三番目も予約可能なProvider別の有限file数。
	std::uint32_t						  maximumProviderFiles_{} ;
	/// 現在の実worker session。
	ScanSessionId						  session_{} ;
	/// Scanごとに更新する人工inventory世代。
	std::uint64_t						  generation_{} ;
} ;

/** @brief 誤った復旧API呼出しも拒否する非通信fixtureです。 */
class WorkerAcquisitionRestore final : public IRestorePointService {
public:
	/** @brief 復元ポイントを作らず拒否します。
	 * @param[in] description 使用しない説明。
	 * @return 誤呼出しの診断。
	 */
	RestorePointOperationResult begin( std::wstring_view description) noexcept override
	{
		static_cast<void>( description) ;
		return {.error = E_ACCESSDENIED} ;
	}
	/** @brief 実復旧終了APIも呼びません。
	 * @param[in] sequence 使用しない番号。
	 * @return 誤呼出しの診断。
	 */
	RestorePointOperationResult complete( std::int64_t sequence) noexcept override
	{
		static_cast<void>( sequence) ;
		return {.error = E_ACCESSDENIED} ;
	}
} ;

/** @brief 実queueを3秒以内だけ読み、進捗の単調性も確認します。
 * @param[in,out] context UI役threadのassertion所有者。
 * @param[in,out] worker 実command queueとworker。
 * @param[in] kind 待つ終端種類。
 * @param[in] operationId 待つ操作ID。
 * @return 同operationの終端。未到着はnulloptです。
 */
std::optional<WorkerEvent> waitIndexWorkerEvent( TestContext &context, ProviderWorker &worker,
												WorkerEventKind kind, OperationId operationId)
{
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3} ;	// 有限待機。
	std::uint32_t lastPercent{} ;														// 同operationの確定進捗だけです。
	// 同期worker終端か3秒まで、短いread-only queue確認を繰り返します。
	while( std::chrono::steady_clock::now() < deadline) {
		// 有限queue内の同operationだけを確認し、他の結果を混同しません。
		for( auto &event : worker.takeEvents()) {
			// 遅延した別operationはこのfixtureの期待終端ではありません。
			if( event.operationId != operationId) {
				continue ;
			}

			// 実確定件数からのscan進捗が逆行しないことを確認します。
			if( event.kind == WorkerEventKind::PROGRESS) {
				DRIVERCRATE_EXPECT( context, event.progress.percentComplete >= lastPercent &&
												event.progress.percentComplete <= 100U) ;
				lastPercent = event.progress.percentComplete ;
			}

			// 取得進捗は実確定件数の範囲だけを使います。
			if( event.kind == WorkerEventKind::PREPARATION_PROGRESS) {
				DRIVERCRATE_EXPECT( context, event.preparationProgress.completed <=
												event.preparationProgress.total) ;
			}

			// 同種類の終端だけを所有してUI役へ戻します。
			if( event.kind == kind) {
				return std::move( event) ;
			}
		}

		std::this_thread::sleep_for( std::chrono::milliseconds{2}) ;
	}

	return std::nullopt ;
}
} // namespace

/** @brief 真署名隔離storeから実command・承認・grant・非空INF内容へ接続します。
 * @param[in,out] context 共通assertion集計先。
 * @param[in] store 真署名原byteを保存した隔離store。製品rootへ置きません。
 * @param[in] nowUtc 固定信頼UTC。
 * @param[in] zip 文法上有効なINF・参照SYS・未署名CATを含む原非空ZIP。
 * @param[in] recordCount 署名recordの有限件数。
 * @param[in] skip 前半の完了不一致数。batch境界の後で対象を作れます。
 * @note 元十四条件を保持し、取消しは五秒以内の低位phase同期で送信前と開始済みに分けます。
 * Fixtureの非atomic観測は、元終端eventの取得またはworker停止の同期完了後だけ読みます。
 */
void runNormalIndexWorkerAcquisitionTests( TestContext					   &context,
										  std::shared_ptr<SignedIndexStore> store,
										  std::chrono::sys_seconds nowUtc, const std::string &zip,
										  std::size_t recordCount, std::size_t skip)
{
	const auto	  firstAssertion = context.assertionCount() ;	// 今回の実worker groupだけの開始値。
	const auto	  firstFailure	 = context.failureCount() ;		// 原失敗を消しません。
	std::uint32_t totalSends{} ;								// 完全fake HTTPの実送信数だけです。
	DRIVERCRATE_EXPECT( context, recordCount >= 3U && skip <= recordCount) ;
	// 三件予約の材料が欠けた場合は、無効な減算やcontainer参照へ進みません。
	if( recordCount < 3U || skip > recordCount) {
		return ;
	}

	// 元十四条件を残し、開始済み送信への協調取消し一条件だけを追加します。
	for( unsigned mode = 0U; mode < 15U; ++mode) {
		const auto modeFirstFailure = context.failureCount() ;		// 同条件だけの原失敗数を保持します。
		const bool exceptionMode	= mode >= 9U && mode <= 12U ;	// 内部factory例外だけです。
		const auto activeSkip =
			mode >= 9U ? std::min( skip, recordCount - 3U) : skip ;				// 三件を確保します。
		const std::uint32_t throwAt = mode == 11U || mode == 12U ? 2U : 1U ;	// 一回だけ送出します。
		auto httpFactories	= std::make_shared<std::atomic_uint32_t>( 0U) ;		// Grant後の生成回数。
		auto costFactories	= std::make_shared<std::atomic_uint32_t>( 0U) ;		// 同内部依存の生成回数。
		auto enteredFactory = std::make_shared<std::atomic_bool>( false) ;		// 停止の同期観測。
		auto releaseFactory =
			std::make_shared<std::atomic_bool>( false) ;	// 取得許可を持たない試験信号。
		auto fixture =
			std::make_shared<DelegatedHttpFixture>() ;	// 実workerだけがI/O状態を更新します。
		auto cancelPhase =
			std::make_shared<WorkerAcquisitionPhase>() ;	// 低位phaseだけを保持します。
		// 開始済み送信の観測を送信前取消しと別条件へ保持します。
		if( mode == 14U) {
			fixture->afterSend = [cancelPhase]() { return cancelPhase->hold() ; } ;
		}

		const auto now =
			// 同固定信頼秒。
			static_cast<std::uint64_t>( nowUtc.time_since_epoch().count()) ;
		fixture->utcSeconds.assign( 512U, now) ;
		fixture->responses.assign( 4U, DelegatedHttpResponse{}) ;
		// 例外前後と新scanの承認済み対象だけへ同じ非空原containerを返します。
		for( auto &response : fixture->responses) {
			response.body	  = zip ;
			response.declared = std::to_wstring( zip.size()) ;
		}

		// 一正常と一失敗を混在させ、取得成功を全体成功へ置き換えません。
		if( mode == 1U) {
			fixture->responses[1].body	   = "changed" ;
			fixture->responses[1].declared = L"7" ;
		}

		auto expired =
			std::make_shared<std::atomic_bool>( false) ;	// UTC変化だけの非authority試験信号。
		provider_worker_index_detail::Services services{
			.load =
				[store]( std::optional<std::chrono::sys_seconds> time) {
					return store->reload( time) ;
				},
			.utc =
				[nowUtc, expired]() {
					return std::optional<std::chrono::sys_seconds>{
						nowUtc + (expired->load() ? std::chrono::days{15} : std::chrono::days{0})} ;
				},
			.monotonic = []() { return std::chrono::steady_clock::now() ; },
			.targetOs  = []() { return std::optional<IndexTargetOs>{IndexTargetOs::WINDOWS_11} ; },
			.httpTransport =
				[fixture, mode, throwAt, httpFactories, enteredFactory, releaseFactory,
				 cancelPhase]() {
					const auto calls =
						// 成功した実grant claimの後だけ到達します。
						++*httpFactories ;
					// 元取消し条件はtransport生成より前で保持し、取消し後の送信0を確定します。
					if( mode == 4U && !cancelPhase->hold()) {
						throw std::runtime_error( "synthetic pre-transport phase timeout") ;
					}

					// 同期factory中の停止を観測できるよう、最大一秒だけ内部信号を待ちます。
					if( mode == 13U) {
						enteredFactory->store( true) ;
						const auto deadline = std::chrono::steady_clock::now() +
											  std::chrono::seconds{1} ;	// 有限待機。
						// UI役の停止開始後に解除するか一秒で終了し、実I/Oへ進みません。
						while( !releaseFactory->load() &&
							  std::chrono::steady_clock::now() < deadline) {
							std::this_thread::sleep_for( std::chrono::milliseconds{2}) ;
						}

						throw std::runtime_error( "synthetic delayed HTTP factory failure") ;
					}

					// CommonHTTP内で吸収されるtransport例外ではなく、grant後のfactory例外を再現します。
					if( (mode == 9U || mode == 11U) && calls == throwAt) {
						throw std::runtime_error( "synthetic HTTP factory failure after grant") ;
					}

					activeDelegatedHttpFixture = fixture.get() ;
					return makeDelegatedHttpTransport() ;
				},
			.costReader =
				[mode, throwAt, costFactories]() {
					const auto calls = ++*costFactories ;	// HTTP生成後かつ実send前の境界。
					// Cost factoryの例外でも同じ取得能力を失効する必要があります。
					if( (mode == 10U || mode == 12U) && calls == throwAt) {
						throw std::runtime_error( "synthetic cost factory failure after grant") ;
					}

					return std::make_unique<FakeNetworkCostReader>() ;
				}} ; // 完全fakeだけです。
		const auto providerTargets =
			// 混在計画だけ既存Provider一件を保持します。
			mode == 8U || mode == 12U ? 1U : 0U ;
		const std::uint32_t providerFiles = mode >= 9U ? 3U : 2U ;	// 自然budget拒否と分離します。
		auto				providerCalls =
			std::make_shared<std::atomic_uint32_t>( 0U) ;	// 実導入もHTTPも呼びません。
		auto worker = provider_worker_index_detail::Access::createAcquisitionFixture(
			[activeSkip, providerTargets, providerCalls, providerFiles]() {
				return std::make_unique<WorkerAcquisitionProvider>( activeSkip, providerTargets,
																   providerCalls, providerFiles) ;
			},
			[]() { return std::make_unique<WorkerAcquisitionRestore>() ; },
			// 実queue。
			std::move( services)) ;
		DRIVERCRATE_EXPECT( context, worker != nullptr) ;
		// 不完全fixtureを製品workerへfallbackしません。
		if( !worker) {
			break ;
		}

		DRIVERCRATE_EXPECT( context, worker->requestScan( 10U)) ;
		auto scanned = waitIndexWorkerEvent( context, *worker, WorkerEventKind::SCAN_COMPLETED,
											10U) ;	// 原scan。
		DRIVERCRATE_EXPECT( context,
						   scanned && scanned->scanResult.succeeded &&
							   scanned->indexSummary.processedRecords == recordCount &&
							   scanned->preparationPlan &&
							   scanned->indexPreparation.plannedTargets ==
								   std::min( 256U - providerTargets,
											static_cast<unsigned>( recordCount - activeSkip))) ;
		// 正常計画の欠損を拒否fixtureの成功へ補完しません。
		if( !scanned || !scanned->preparationPlan) {
			worker->stop() ;
			continue ;
		}

		const auto &plan = *scanned->preparationPlan ;	// UIへ発行した同scan固定計画。
		// Assertion後も空vectorを無条件に参照せず、材料欠損では安全に試験を中止します。
		if( plan.targets.size() <= providerTargets) {
			worker->stop() ;
			continue ;
		}

		// 例外対象の後にも予約可能な索引taskを残し、budget自然拒否を失効合格にしません。
		if( exceptionMode) {
			DRIVERCRATE_EXPECT( context, plan.targets.size() >= providerTargets + 3U &&
											plan.limits.maximumProviderFiles == 3U &&
											plan.limits.maximumProviderBytes == 12288U &&
											plan.limits.maximumSessionFiles == 4U &&
											plan.limits.maximumSessionBytes == 16384U) ;
			// 期待の材料欠損では、後続taskの無条件参照を避けます。
			if( plan.targets.size() < providerTargets + 3U) {
				worker->stop() ;
				continue ;
			}
		}

		DRIVERCRATE_EXPECT( context, plan.targets[providerTargets].identity ==
										L"index-acquisition-" + std::to_wstring( activeSkip)) ;
		DRIVERCRATE_EXPECT( context,
						   plan.targets.size() <= 256U &&
							   scanned->indexPreparation.capacityRejectedRelations ==
								   (recordCount - activeSkip > 256U - providerTargets
										? recordCount - activeSkip - (256U - providerTargets)
										: 0U)) ;
		OfficialPreparationApproval approval{
			20U, plan.scanSessionId, plan.planId, plan.limits, {}} ;	// 新operation。
		// 例外条件では予算内の索引三件と元Provider、それ以外は最初の二件を明示選択します。
		for( std::size_t i = 0U; i < plan.targets.size(); ++i) {
			approval.decisions.push_back( {plan.targets[i],
										  i < (exceptionMode ? 3U + providerTargets : 2U), false,
										  false, false}) ;
		}

		// Stale planは実active taskへ進めません。
		if( mode == 2U) {
			++approval.planId ;
		}

		// 同scanの上限変更も新しい承認authorityとして受理しません。
		if( mode == 7U) {
			--approval.limits.maximumSessionBytes ;
		}

		// 原snapshot共有寿命が残っていても信頼UTC期限は再照合します。
		if( mode == 3U) {
			expired->store( true) ;
		}

		// 新scanを先に確定し、元scanの承認を拒否させます。
		if( mode == 5U) {
			DRIVERCRATE_EXPECT( context, worker->requestScan( 15U)) ;
			DRIVERCRATE_EXPECT( context, waitIndexWorkerEvent( context, *worker,
															 WorkerEventKind::SCAN_COMPLETED, 15U)
											.has_value()) ;
		}

		// 導入開始は未使用索引取得能力を失効し、実導入は拒否fixtureから呼びません。
		if( mode == 6U) {
			const std::array<std::wstring, 1U> selection{L"unused-index-selection"} ;	// 非実候補。
			DRIVERCRATE_EXPECT(
				context, worker->requestInstall( 15U, plan.scanSessionId, selection, nullptr,
												InstallProtectionMode::WINDOWS_RESTORE_POINT)) ;
			const auto installed =
				waitIndexWorkerEvent( context, *worker, WorkerEventKind::INSTALL_COMPLETED,
									 15U) ;	// 復旧拒否またはOS mode拒否。
			DRIVERCRATE_EXPECT( context, installed && installed->installResult.installOutcome !=
														 OutcomeCode::SUCCESS) ;
		}

		DRIVERCRATE_EXPECT( context, worker->requestPreparation( approval)) ;
		std::cout << "INDEX_WORKER_PHASE mode=" << mode
				  << " phase=queued httpFactories=" << httpFactories->load()
				  << " costFactories=" << costFactories->load() << '\n' ;
		// 明示した低位phaseへ到達してから同operationだけを取消し、別scanへ波及しません。
		if( mode == 4U || mode == 14U) {
			const bool reached = cancelPhase->entered.try_acquire_for(
				std::chrono::seconds{5}) ;	// 指定phase到達の同期です。
			DRIVERCRATE_EXPECT( context, reached) ;
			std::cout << "INDEX_WORKER_PHASE mode=" << mode
					  << " phase=" << (mode == 4U ? "before-transport-held" : "send-started-held")
					  << " reached=" << reached << '\n' ;
			DRIVERCRATE_EXPECT( context, worker->requestPreparationCancel( 20U)) ;
			cancelPhase->released.release() ;
			std::cout << "INDEX_WORKER_PHASE mode=" << mode
					  << " phase=cancel-requested httpFactories=" << httpFactories->load()
					  << " costFactories=" << costFactories->load() << '\n' ;
		}

		std::optional<WorkerEvent> prepared ;	// 実executorの確定結果をUI役だけが所有します。
		// Factoryが実active taskの内部まで進んだ後に停止し、その後の遅延終端を読みます。
		if( mode == 13U) {
			const auto deadline =
				// 開始待ち上限。
				std::chrono::steady_clock::now() + std::chrono::seconds{1} ;
			// 実factory到達か一秒まで待ち、未到達を成功へ補完しません。
			while( !enteredFactory->load() && std::chrono::steady_clock::now() < deadline) {
				std::this_thread::sleep_for( std::chrono::milliseconds{2}) ;
			}

			DRIVERCRATE_EXPECT( context, enteredFactory->load()) ;
			// 停止のjoinを解く有限信号だけを別threadから送り、取得authorityは追加しません。
			std::thread releaser{[releaseFactory]() {
				std::this_thread::sleep_for( std::chrono::milliseconds{20}) ;
				releaseFactory->store( true) ;
			}} ;
			worker->stop() ;
			releaser.join() ;
			DRIVERCRATE_EXPECT( context, releaseFactory->load() && !worker->requestScan( 30U) &&
											!worker->requestPreparation( approval)) ;
			// 停止後に到着した同operationの有限eventを回収し、別commandへ適用しません。
			for( auto &event : worker->takeEvents()) {
				DRIVERCRATE_EXPECT( context, event.operationId == 20U) ;
				// 一件だけの確定終端を所有し、進捗を終端へ昇格しません。
				if( event.kind == WorkerEventKind::PREPARATION_COMPLETED) {
					DRIVERCRATE_EXPECT( context, !prepared.has_value()) ;
					prepared = std::move( event) ;
				}
			}

			DRIVERCRATE_EXPECT( context, httpFactories->load() == 1U &&
											costFactories->load() == 0U && fixture->sends == 0U) ;
		} else {
			prepared =
				waitIndexWorkerEvent( context, *worker, WorkerEventKind::PREPARATION_COMPLETED, 20U) ;
		}

		DRIVERCRATE_EXPECT( context, prepared.has_value()) ;

		// 初回／先行内容確定後の内部例外は元の項目失敗を保持し、三番目の能力を拒否します。
		if( prepared && exceptionMode) {
			const auto	beforeSends = fixture->sends ;				// 以後の追加送信を比較する確定値。
			const auto	beforeHttp	= httpFactories->load() ;		// 後続factoryの再呼出し検出。
			const auto	beforeCost	= costFactories->load() ;		// 同cost依存の検出。
			const auto &items = prepared->preparationResult.items ;	// 共通executorの原項目結果。
			const auto	failed =
				std::ranges::find_if( items, [&]( const OfficialPreparationItem &item) {
					return item.identity == plan.targets[providerTargets + throwAt - 1U].identity ;
				}) ; // 元例外対象。
			const auto following =
				std::ranges::find_if( items, [&]( const OfficialPreparationItem &item) {
					return item.identity == plan.targets[providerTargets + 2U].identity ;
				}) ; // 元予算内で承認済みの後続対象。
			DRIVERCRATE_EXPECT( context, prepared->preparationResult.approvalError ==
												OfficialPreparationError::NONE &&
											prepared->preparationResult.controlError == 0U &&
											failed != items.end() && following != items.end()) ;
			// 期待失敗の後も、見つからない項目を参照しません。
			if( failed != items.end() && following != items.end()) {
				DRIVERCRATE_EXPECT(
					context,
					failed->result.state == OfficialPreparationItemState::FAILURE &&
						failed->result.error == static_cast<NativeError>( E_UNEXPECTED) &&
						failed->result.byteCount == 0U &&
						following->result.state == OfficialPreparationItemState::REJECTED &&
						following->result.error == static_cast<NativeError>( E_ACCESSDENIED) &&
						following->result.byteCount == 0U) ;
			}

			DRIVERCRATE_EXPECT(
				context, beforeSends == throwAt - 1U && beforeHttp == throwAt &&
							 beforeCost == (mode == 9U || mode == 11U ? throwAt - 1U : throwAt) &&
							 prepared->indexPreparation.authorityError ==
								 static_cast<NativeError>( E_ACCESSDENIED)) ;
			// 先行確定結果は能力失効と別の同event所有へ保持します。
			if( throwAt == 2U) {
				const auto &content = prepared->indexPreparation.items ;	// 非機密の保持結果。
				DRIVERCRATE_EXPECT( context,
								   !content.empty() && content.front().inputBound &&
									   content.front().content ==
										   IndexedDriverInspectionState::INSPECTION_COMPLETED &&
									   content.front().inventoryFileCount == 3U &&
									   content.front().infCount == 1U &&
									   content.front().parsedInfCount == 1U &&
									   content.front().signatureRejectedInfCount == 1U &&
									   content.front().acceptedInfCount == 0U &&
									   content.front().firstInfRejection != 0U) ;
			}

			// 元Provider対象の成功を索引例外で消さず、異なるroutingを維持します。
			if( providerTargets == 1U) {
				const auto original =
					std::ranges::find_if( items, []( const OfficialPreparationItem &item) {
						return item.identity == L"original-provider-target" ;
					}) ; // 元Providerの一件。
				DRIVERCRATE_EXPECT( context,
								   original != items.end() &&
									   original->result.state ==
										   OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION &&
									   original->result.error == 0U && providerCalls->load() == 1U) ;
			}

			approval.operationId = 25U ;
			DRIVERCRATE_EXPECT( context, worker->requestPreparation( approval)) ;
			const auto replay =
				waitIndexWorkerEvent( context, *worker, WorkerEventKind::PREPARATION_COMPLETED,
									 25U) ;	// 新operationも再承認しません。
			DRIVERCRATE_EXPECT( context, replay &&
											replay->preparationResult.approvalError !=
												OfficialPreparationError::NONE &&
											httpFactories->load() == beforeHttp &&
											costFactories->load() == beforeCost &&
											fixture->sends == beforeSends) ;

			DRIVERCRATE_EXPECT( context, worker->requestScan( 30U)) ;
			const auto restarted =
				waitIndexWorkerEvent( context, *worker, WorkerEventKind::SCAN_COMPLETED,
									 30U) ;	// 新scanだけで能力を作り直します。
			DRIVERCRATE_EXPECT( context,
							   restarted && restarted->preparationPlan &&
								   restarted->scanResult.scanSessionId > plan.scanSessionId) ;
			// 新しい材料の欠損を成功へ補完せず、同scanの計画だけを使用します。
			if( restarted && restarted->preparationPlan) {
				const auto &newPlan = *restarted->preparationPlan ;	// 新scanの完全計画。
				OfficialPreparationApproval resume{40U,
												   newPlan.scanSessionId,
												   newPlan.planId,
												   newPlan.limits,
												   {}} ;	// 元の予算契約を維持します。
				// 一件の索引だけを選び、旧Provider同意や旧grantを流用しません。
				for( std::size_t i = 0U; i < newPlan.targets.size(); ++i) {
					resume.decisions.push_back(
						{newPlan.targets[i], i == providerTargets, false, false, false}) ;
				}

				DRIVERCRATE_EXPECT( context, worker->requestPreparation( resume)) ;
				const auto resumed =
					waitIndexWorkerEvent( context, *worker, WorkerEventKind::PREPARATION_COMPLETED,
										 40U) ;	// 正常再開の確定結果。
				DRIVERCRATE_EXPECT(
					context, resumed &&
								 resumed->preparationResult.approvalError ==
									 OfficialPreparationError::NONE &&
								 resumed->indexPreparation.items.size() == 1U &&
								 resumed->indexPreparation.items.front().inputBound &&
								 resumed->indexPreparation.items.front().parsedInfCount == 1U &&
								 resumed->indexPreparation.items.front().acceptedInfCount == 0U &&
								 fixture->sends == beforeSends + 1U &&
								 httpFactories->load() == beforeHttp + 1U &&
								 costFactories->load() == beforeCost + 1U) ;
			}

			// 旧operationの結果DTOは新scanによる秘密所有解放後も変化しません。
			if( throwAt == 2U) {
				DRIVERCRATE_EXPECT(
					context,
					!prepared->indexPreparation.items.empty() &&
						prepared->indexPreparation.items.front().inputBound &&
						prepared->indexPreparation.items.front().signatureRejectedInfCount == 1U) ;
			}

			std::cout << "Index exception boundary mode: " << mode << ", reserved index tasks: 3"
					  << ", HTTP factories before new scan: " << beforeHttp
					  << ", cost factories before new scan: " << beforeCost
					  << ", fake sends before new scan: " << beforeSends ;
			// 診断labelを期待値で代替せず、実項目の状態と元errorをそのまま表示します。
			if( failed != items.end() && following != items.end()) {
				std::cout << ", original item state/error: "
						  << static_cast<unsigned>( failed->result.state) << '/'
						  << failed->result.error << ", later item state/error: "
						  << static_cast<unsigned>( following->result.state) << '/'
						  << following->result.error ;
			}

			std::cout << ", candidate success: 0\n" ;
		}

		// 同approvalの新operation再送でもclaim済みtaskと元grantを再使用できません。
		if( prepared && mode == 0U) {
			approval.operationId = 25U ;
			DRIVERCRATE_EXPECT( context, worker->requestPreparation( approval)) ;
			const auto replay =
				waitIndexWorkerEvent( context, *worker, WorkerEventKind::PREPARATION_COMPLETED,
									 25U) ;	// 同scan/planでも使用済みです。
			DRIVERCRATE_EXPECT( context, replay && replay->preparationResult.approvalError !=
													  OfficialPreparationError::NONE) ;
		}

		// 同handleの安全終端を待ってからfakeI/O実績を確認します。
		worker->stop() ;
		DRIVERCRATE_EXPECT( context, !cancelPhase->timedOut.load()) ;
		totalSends += fixture->sends ;
		DRIVERCRATE_EXPECT( context, fixture->safeRequest && fixture->opened == fixture->closed) ;
		// 正常fixtureは取得と実byte内容検査を独立に確定し、原scan操作を新取得操作へ変更しません。
		if( prepared && (mode == 0U || mode == 8U)) {
			const auto &summary = prepared->indexPreparation ;	// 通常UIへ渡す同eventの有限DTO。
			DRIVERCRATE_EXPECT( context, summary.operationId == 20U &&
											summary.scanSessionId == plan.scanSessionId &&
											summary.planId == plan.planId &&
											summary.items.size() == (mode == 8U ? 1U : 2U) &&
											prepared->preparationResult.approvalError ==
												OfficialPreparationError::NONE) ;
			DRIVERCRATE_EXPECT( context, fixture->sends == (mode == 8U ? 1U : 2U)) ;
			// 非空driver containerの実発見INFと未署名CAT拒否を未知から分離します。
			for( const auto &item : summary.items) {
				DRIVERCRATE_EXPECT(
					context,
					item.acquisition == OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION &&
						item.acquisitionError == 0U && item.inputBound &&
						item.content == IndexedDriverInspectionState::INSPECTION_COMPLETED &&
						item.contentError == 0U && item.inventoryFileCount == 3U &&
						item.infCount == 1U && item.acceptedInfCount == 0U &&
						item.parsedInfCount == 1U && item.signatureRejectedInfCount == 1U &&
						item.firstInfRejection != 0U) ;
				std::cout << "Normal index worker content: files " << item.inventoryFileCount
						  << ", INF " << item.infCount << ", parsed " << item.parsedInfCount
						  << ", signature rejected " << item.signatureRejectedInfCount
						  << ", accepted " << item.acceptedInfCount << ", rejection "
						  << item.firstInfRejection << '\n' ;
			}
		}

		// 部分転送失敗では最初の確定内容と二番目の元取得拒否を残します。
		if( prepared && mode == 1U) {
			DRIVERCRATE_EXPECT( context,
							   prepared->indexPreparation.items.size() == 2U &&
								   prepared->indexPreparation.items[0].inputBound &&
								   prepared->indexPreparation.items[1].acquisitionError != 0U &&
								   prepared->indexPreparation.items[1].content ==
									   IndexedDriverInspectionState::NOT_STARTED) ;
		}

		// Stale・期限・送信前phaseでの取消し・新scanの拒否は送信0を維持します。
		if( mode >= 2U && mode <= 7U) {
			std::cout << "INDEX_WORKER_PHASE mode=" << mode
					  << " phase=terminal sends=" << fixture->sends
					  << " httpFactories=" << httpFactories->load()
					  << " costFactories=" << costFactories->load() << '\n' ;
			DRIVERCRATE_EXPECT( context, fixture->sends == 0U) ;
		}

		// 開始済み送信を取り消せたとせず、本文読取りと後続送信が停止した事実を確認します。
		if( mode == 14U) {
			DRIVERCRATE_EXPECT( context, fixture->sends == 1U && fixture->reads == 0U &&
											httpFactories->load() == 1U &&
											costFactories->load() == 1U) ;
		}

		// 両取消しphaseで元選択の二項目を取消しへ確定し、検査成功を発行しません。
		if( prepared && (mode == 4U || mode == 14U)) {
			const auto &items =
				prepared->preparationResult.items ;	// 同operation終端が所有する原項目です。
			DRIVERCRATE_EXPECT(
				context,
				prepared->preparationResult.approvalError == OfficialPreparationError::NONE &&
					items.size() == plan.targets.size() && items.size() >= 2U &&
					items[0].result.state == OfficialPreparationItemState::CANCELLED &&
					items[1].result.state == OfficialPreparationItemState::CANCELLED &&
					prepared->preparationResult.auditReports.empty()) ;
			std::cout << "INDEX_WORKER_CANCEL_RESULT mode=" << mode << " sends=" << fixture->sends
					  << " reads=" << fixture->reads
					  << " auditReports=" << prepared->preparationResult.auditReports.size()
					  << '\n' ;
		}

		DRIVERCRATE_EXPECT( context, providerCalls->load() == (providerTargets == 1U ? 1U : 0U)) ;

		DRIVERCRATE_EXPECT( context,
						   !worker->requestScan( 30U) && !worker->requestPreparation( approval)) ;
		static_cast<void>( worker->takeEvents()) ;
		DRIVERCRATE_EXPECT( context, worker->takeEvents().empty()) ;
		std::cout << "INDEX_WORKER_MODE mode=" << mode
				  << " failures=" << context.failureCount() - modeFirstFailure
				  << " sends=" << fixture->sends << " terminal=1\n" ;
	}

	// 同executorで例外後に別Provider対象も続行できることを索引能力試験と独立して確認します。
	auto continuedCalls = std::make_shared<std::atomic_uint32_t>( 0U) ;		// 元Providerのcallback実績。
	WorkerAcquisitionProvider continuedProvider{0U, 1U, continuedCalls} ;	// 実I/Oを行いません。
	auto continuedPlan = continuedProvider.preparationPlan( 100U, 101U) ;	// 正当な人工Provider計画。
	DRIVERCRATE_EXPECT( context, continuedPlan && continuedPlan->targets.size() == 1U) ;
	// 材料不成立ではcontainerを参照せず、原assertion失敗を保持します。
	if( continuedPlan && continuedPlan->targets.size() == 1U) {
		auto throwing			 = continuedPlan->targets.front() ;	// 例外を送出する先行人工対象。
		throwing.identity		 = L"synthetic-throwing-provider-target" ;
		throwing.releaseIdentity = L"synthetic-throwing-provider-release" ;
		continuedPlan->targets.insert( continuedPlan->targets.begin(), std::move( throwing)) ;
		OfficialPreparationApproval approval{102U,
											 continuedPlan->scanSessionId,
											 continuedPlan->planId,
											 continuedPlan->limits,
											 {}} ;	// 計画全文と同予算の承認。
		// 二対象だけを明示承認し、例外後も既存Providerを未選択へ変更しません。
		for( const auto &target : continuedPlan->targets) {
			approval.decisions.push_back( {target, true, false, false, false}) ;
		}

		OfficialPreparationSession session ;	// 実共通executorの状態機械。
		DRIVERCRATE_EXPECT( context, session.initialize( std::move( *continuedPlan)) ==
										OfficialPreparationError::NONE) ;
		const auto result = executeOfficialPreparation(
			session, approval,
			[&continuedProvider]( const OfficialPreparationTask &task,
								 const PreparationCancellation &cancelled) {
				// 一対象の内部例外を元E_UNEXPECTEDへ変換し、後続dispatchを維持させます。
				if( task.target.identity == L"synthetic-throwing-provider-target") {
					throw std::runtime_error( "synthetic preceding provider failure") ;
				}

				return continuedProvider.acquireForInspection( task, cancelled) ;
			},
			[]() { return false ; }, []( const OfficialPreparationProgress &) {}) ;	// 非通信。
		DRIVERCRATE_EXPECT( context, result.approvalError == OfficialPreparationError::NONE &&
										result.controlError == 0U && result.items.size() == 2U &&
										continuedCalls->load() == 1U) ;
		// 期待失敗の後も不足したcontainerを参照しません。
		if( result.items.size() == 2U) {
			DRIVERCRATE_EXPECT(
				context,
				result.items[0].result.state == OfficialPreparationItemState::FAILURE &&
					result.items[0].result.error == static_cast<NativeError>( E_UNEXPECTED) &&
					result.items[1].result.state ==
						OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION &&
					result.items[1].result.error == 0U && result.items[1].result.byteCount == 100U) ;
		}

		std::cout
			<< "Executor exception continuation: original E_UNEXPECTED, later provider calls: "
			<< continuedCalls->load() << ", real I/O: 0\n" ;
	}

	std::cout << "Normal index worker acquisition assertions: "
			  << context.assertionCount() - firstAssertion
			  << ", failures: " << context.failureCount() - firstFailure
			  << ", fake sends: " << totalSends << ", native fallback: 0\n" ;
}

// 独立した取得証拠targetへ通常候補・指定導入fixtureの依存を持ち込まない。
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
/** @see signed_index_candidate_binding_tests.h */
void runNormalSignedIndexCandidateBindingTests( TestContext						&context,
											   std::shared_ptr<SignedIndexStore> store,
											   const std::chrono::sys_seconds	 nowUtc,
											   const std::string &zip, const bool network)
{
	auto fixture = std::make_shared<DelegatedHttpFixture>() ;	// 完全fake HTTPの同worker状態です。
	fixture->utcSeconds.assign( 4096U,
							   static_cast<std::uint64_t>( nowUtc.time_since_epoch().count())) ;
	fixture->responses.assign( 8U, DelegatedHttpResponse{}) ;
	// 実原ZIP byteと期待sizeを毎回同じ取得policyへ返します。
	for( auto &response : fixture->responses) {
		response.body	  = zip ;
		response.declared = std::to_wstring( zip.size()) ;
	}

	provider_worker_index_detail::Services services{
		.load	   = [store]( auto time) { return store->reload( time) ; },
		.utc	   = [nowUtc]() { return std::optional{nowUtc} ; },
		.monotonic = []() { return std::chrono::steady_clock::now() ; },
		.targetOs  = []() { return std::optional{IndexTargetOs::WINDOWS_11} ; },
		.httpTransport =
			[fixture]() {
				activeDelegatedHttpFixture = fixture.get() ;
				return makeDelegatedHttpTransport() ;
			},
		.costReader =
			[]() {
				return std::make_unique<FakeNetworkCostReader>() ;
			}} ; // Native fallbackはありません。
	runSignedIndexCandidateBindingTests( context, std::move( services), zip, network) ;
	DRIVERCRATE_EXPECT( context, fixture->safeRequest && fixture->opened == fixture->closed) ;
}
#endif	// defined(DRIVERCRATE_INTERNAL_INDEX_TESTS)
} // namespace drivercrate::test
