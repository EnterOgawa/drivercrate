//------------------------------------------------------------------------------
/**
 * @file official_http_client.cpp
 * @brief 公式配布元限定HTTP client実装。
 * @version 01.19.02
 * @date 2026/09/23
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  明示的なcatalog非cache検証modeを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  URL policyと受信上限検証強化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Catalog cacheとETag再検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  UTF-8 BOM除去追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Scan session取得根拠記録追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  有限redirect経路検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Payload取消し境界追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  固定form POSTのmetadata取得を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  拒否HTTP statusの診断値を保持。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  実HTTP／cache取得経路の根拠を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Record限定のpublic宛先GET境界を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  Dynamic同一originと固定payload redirect境界を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  各HTTP hop開始直前のgrant期限検証を追加。
 * Ver.01.03.01 Shunji Ogawa  2026/09/15  Delegated本文受信へ同じ低位I/O表を引き継ぐよう修正。
 * Ver.01.04.00 Shunji Ogawa  2026/09/15  公式HTTPの透明な製品識別User-Agentへ統一。
 * Ver.01.05.00 Shunji Ogawa  2026/09/22  Live HTMLの公開宛先・MIME・取消しGETを追加。
 * Ver.01.05.01 Shunji Ogawa  2026/09/22  成功したHTMLのraw受信byte数を公開する。
 * Ver.01.05.02 Shunji Ogawa  2026/09/22  Live探索開始前のsource session照合を追加。
 * Ver.01.05.03 Shunji Ogawa  2026/09/22  Live HTMLのContent-Length改ざんを拒否。
 * Ver.01.06.00 Shunji Ogawa  2026/09/23  全区間取得接続と公式module根拠付き許諾境界を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/09/25  取得grantを発行しない収集用304応答を追加。
 * Ver.01.08.00 Shunji Ogawa  2026/09/25  429／503の有限Retry-After観測を追加。
 * Ver.01.09.00 Shunji Ogawa  2026/09/27  有限DNS・収集GET制御と厳密本文終端を追加。
 * Ver.01.10.00 Shunji Ogawa  2026/10/06  収集検査のprivate共通HTTP経路を追加。
 * Ver.01.11.00 Shunji Ogawa  2026/10/12  署名索引の共通取得境界と既存経路の区別を追加。
 * Ver.01.12.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.12.01 Shunji Ogawa  2026/10/12  default/delete宣言の所有権と非実行契約を補足。
 * Ver.01.13.00 Shunji Ogawa  2026/10/14  明示収集だけへ検証済み200原byteを返す。
 * Ver.01.14.00 Shunji Ogawa  2026/10/14  共通HTML許諾と監視側の一意な非実行script参照を追加。
 * Ver.01.15.00 Shunji Ogawa  2026/10/15  期待媒体型と単一UTF-8 charsetを本文非変換で照合。
 * Ver.01.16.00 Shunji Ogawa  2026/10/16  固定署名索引の用途限定HTTPと共有期限を追加。
 * Ver.01.17.00 Shunji Ogawa  2026/10/20  監視専用manifest媒体型と私有九send上限を追加。
 * Ver.01.18.00 Shunji Ogawa  2026/10/23  収集HTML原byteのhashと同取得UTC観測を任意返却。
 * Ver.01.19.00 Shunji Ogawa  2026/10/23  同じ収集send/readと全保存終端の私有観測を追加。
 * Ver.01.19.01 Shunji Ogawa  2026/10/23  収集専用の超過検出読取りを残上限と1byteへ制限。
 * Ver.01.19.02 Shunji Ogawa  2026/10/24  必須解析の型・有限所有buffer・失敗制御を明示。
 * </pre>
 *
 * @note WinHTTP handleは本file内のRAII wrapperが所有します。Catalog cacheが破損した場合は破棄し、stale fallbackを行わず公式
 *       originへ再接続します。Metadata専用modeでは破損cacheから自動再取得せず拒否します。
 */
//------------------------------------------------------------------------------

#include "platform/official_http_client.h"
#include "platform/official_html_terms.h"
#include "platform/official_collector_dns.h"
#include "platform/signed_index_manifest.h"

#include "core/metadata_search_budget.h"
#include "core/official_source_policy.h"
#include "platform/official_catalog_cache.h"
#include "platform/official_file_verifier.h"

#include <Windows.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {

/** @brief この翻訳単位の実HTTPだけが転送観測を更新します。
 * @note 外部headerに定義せず、JSONや成功boolからの完了生成を認めません。
 */
class CollectorHttpTransferRecorder final {
public:
	/** @brief 同段階を未完了へ初期化します。
	 * @param[out] observation 同期呼出しより長生きする出力です。
	 * @param[in] stage PAGEまたはPAYLOADです。
	 */
	CollectorHttpTransferRecorder( CollectorHttpTransferObservation &observation,
								  CollectorHttpTransferStage		stage) noexcept
		: observation_( observation)
	{
		observation_		= {} ;
		observation_.stage_ = stage ;
	}
	/** @brief 実send呼出しの直前に一回だけ記録します。 */
	void attempting() noexcept
	{
		++observation_.attemptedRequests_ ;
	}
	/** @brief 成功したreadData直後の本文量を保存します。
	 * @param[in] bytes 同じAPIが返した実byteです。
	 */
	void read( std::uint32_t bytes) noexcept
	{
		observation_.bodyBytesRead_ += bytes ;
	}
	/** @brief 同じ実responseの数値statusを保存します。
	 * @param[in] status 未受信0またはHTTP statusです。
	 */
	void status( std::uint32_t status) noexcept
	{
		observation_.terminalStatus_ = status ;
	}
	/** @brief 全受信・宣言長・保存・取消し確認後だけ完了を確定します。 */
	void complete() noexcept
	{
		observation_.completion_ = CollectorHttpTransferCompletion::COMPLETE ;
	}

private:
	/// 同期HTTPの呼出し元が所有する出力です。
	CollectorHttpTransferObservation &observation_ ;
} ;

#ifdef DRIVERCRATE_REGISTRY_JOB_TESTING
// 完全fakeの専用targetだけに存在し、通常HTTPのOS I/Oを変更しません。
thread_local decltype( &FlushFileBuffers) OfficialHttpClient::collectorFlushProbe_{} ;
#endif
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

// 本番の不変I/O表。Test用依存がない経路だけが参照する。
const OfficialHttpTransport NATIVE_HTTP_TRANSPORT{} ;

constexpr DWORD RESOLVE_TIMEOUT_MILLISECONDS = 15'000 ;								// DNS名前解決timeout（millisecond）。
constexpr DWORD CONNECT_TIMEOUT_MILLISECONDS = 30'000 ;								// TCP/TLS接続timeout（millisecond）。
constexpr DWORD SEND_TIMEOUT_MILLISECONDS	 = 30'000 ;								// Request送信timeout（millisecond）。
constexpr DWORD RECEIVE_TIMEOUT_MILLISECONDS = 60'000 ;								// Response受信timeout（millisecond）。
constexpr DWORD READ_BUFFER_BYTES			 = 64U * 1024U ;						// 一回のWinHTTP読取りbuffer byte数。
constexpr std::uint64_t CATALOG_MAXIMUM_AGE_SECONDS		= 6ULL * 60ULL * 60ULL ;	// Fresh期限6時間。
constexpr std::size_t	MAXIMUM_SOURCE_EVIDENCE_ENTRIES = 4096U ;					// 一Provider sessionの取得上限。
constexpr std::size_t	MAXIMUM_ETAG_CHARACTERS = 512U ;							// 条件付きrequestへ許可するETag上限。
constexpr std::size_t	MAXIMUM_REDIRECT_URL_CHARACTERS = 8192U ;					// Location URL文字数上限。
constexpr std::uint32_t MAXIMUM_REDIRECTS				= 5U ;						// Application全体のredirect回数上限。
constexpr DWORD			PERMANENT_REDIRECT_STATUS		= 308U ;					// RFC 7538の永続redirect status。
constexpr std::size_t	MAXIMUM_FORM_BODY_BYTES			= 2U * 1024U ;				// 固定form POST bodyの上限。
constexpr std::size_t	MAXIMUM_FORM_FIELDS				= 8U ;						// 一つのformで許可するfield数上限。
constexpr std::uint64_t FILE_TIME_UNITS_PER_SECOND = 10'000'000ULL ;				// FILETIMEの一秒当たり単位。
constexpr std::uint64_t UNIX_EPOCH_FILE_TIME =
	116'444'736'000'000'000ULL ;	// 1601年から1970年までのFILETIME単位差。
constexpr wchar_t HTTP_USER_AGENT[] =
	L"Mozilla/5.0 (compatible; DriverCrate/0.1.0; "
	L"+https://github.com/EnterOgawa/drivercrate)" ;	// 端末情報を含まない共通製品識別子。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 現在UTCをUnix秒へ変換する。
 *
 * @return 1970年起点のUTC秒。System時刻がepoch前の場合は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint64_t currentUtcSeconds() noexcept
{
	FILETIME value{} ;	// Windowsが設定する現在UTC。
	GetSystemTimeAsFileTime( &value) ;
	ULARGE_INTEGER combined{} ;	// FILETIMEの上下DWORDを結合する値。
	combined.LowPart  = value.dwLowDateTime ;
	combined.HighPart = value.dwHighDateTime ;
	return combined.QuadPart >= UNIX_EPOCH_FILE_TIME
			   ? (combined.QuadPart - UNIX_EPOCH_FILE_TIME) / FILE_TIME_UNITS_PER_SECOND
			   : 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 成功したnetwork本文取得の非機密な時刻根拠を作る。
 *
 * @param[in] cachePermitted 当該catalog APIでcacheを許可した場合だけtrue。
 * @return 本文取得とorigin検証を同じ確定時刻へ結び付けた根拠。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialHttpAcquisitionObservation networkObservation(
	const bool cachePermitted) noexcept
{
	const std::uint64_t now = currentUtcSeconds() ;	// 応答本文の処理完了後に確定するUTC。
	return {.acquisition			   = MeasurementAcquisition::NETWORK_BODY,
			.bodyAcquiredUtcSeconds	   = now,
			.originValidatedUtcSeconds = now,
			.cachePermitted			   = cachePermitted} ;
}

/**
 * @brief HINTERNETを生成したbackendのclose関数で解放するRAII wrapperである。
 */
class InternetHandle final {
public:
	//------------------------------------------------------------------------------
	/**
     * @brief HINTERNET ownershipを取得する。
     *
     * @param[in] value WinHTTP APIが返したhandle。
     * @param[in] transport 生成元I/O表。Close関数をcopyし、表の寿命へ依存しない。
     */
	//------------------------------------------------------------------------------
	explicit InternetHandle( const HINTERNET				 value,
							const OfficialHttpTransport &transport = NATIVE_HTTP_TRANSPORT) noexcept
		: value_( value), close_( transport.closeHandle)
	{
	}

	//------------------------------------------------------------------------------
	/**
     * @brief 所有するHINTERNETを解放する。
     */
	//------------------------------------------------------------------------------
	~InternetHandle()
	{
		// 無効な値を解放APIへ渡さず、保持している有効なresourceの後始末を行う。
		if( value_ != nullptr) {
			close_( value_) ;
		}
	}

	// 同一WinHTTP handleを重複解放しないようcopyを禁止する。
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	InternetHandle( const InternetHandle &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	InternetHandle &operator=( const InternetHandle &) = delete ;

	//------------------------------------------------------------------------------
	/**
     * @brief HINTERNET ownershipを移動する。
     *
     * @param[in,out] other 移動元。呼出し後は空になる。
     */
	//------------------------------------------------------------------------------
	InternetHandle( InternetHandle &&other) noexcept
		: value_( std::exchange( other.value_, nullptr)), close_( other.close_)
	{
	}

	//------------------------------------------------------------------------------
	/**
     * @brief 既存handleを解放してHINTERNET ownershipを移動する。
     *
     * self moveを許容し、現在のhandleを重複解放しない。
     *
     * @param[in,out] other 移動元。呼出し後は空になる。
     * @return 移動先object自身。
     */
	//------------------------------------------------------------------------------
	InternetHandle &operator=( InternetHandle &&other) noexcept
	{
		// 自己 move では所有 handle を解放せず、異なる object 間だけ所有権を移す。
		if( this != &other) {
			// 無効な値を解放APIへ渡さず、保持している有効なresourceの後始末を行う。
			if( value_ != nullptr) {
				close_( value_) ;
			}

			value_ = std::exchange( other.value_, nullptr) ;
			close_ = other.close_ ;
		}

		return *this ;
	}

	//------------------------------------------------------------------------------
	/**
     * @brief 所有handleを返す。
     * @return ownershipを移さないHINTERNET。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] HINTERNET get() const noexcept
	{
		return value_ ;
	}

	//------------------------------------------------------------------------------
	/**
     * @brief handleが有効かを判定する。
     * @return handleがnullでない場合は`true`。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] bool valid() const noexcept
	{
		return value_ != nullptr ;
	}

private:
	/// 生成元backendのclose関数で解放する所有handle。
	HINTERNET					  value_{} ;
	/// Handleを生成したbackendの解放関数。生成元表の寿命へ依存しない。
	decltype( &WinHttpCloseHandle) close_{WinHttpCloseHandle} ;
} ;

/**
 * @brief 検証済みURLをWinHttpConnect/OpenRequestへ渡すcomponentへ分解した値である。
 */
struct ParsedUrl {
	/// 小文字へ正規化した接続先host。
	std::wstring  host ;
	/// pathとqueryを連結したrequest target。
	std::wstring  pathQuery ;
	/// 検証済みHTTPS port。
	INTERNET_PORT port{} ;
	/// 一意に一致したallowlist entry index。
	std::uint32_t originPolicyIndex{} ;
} ;

/**
 * @brief Dynamic targetのhost・path・query一時領域をscope終了時に消去します。
 */
class SecretParsedUrlScope final {
public:
	/**
	 * @brief 消去対象componentを借用します。
	 * @param[in,out] parsed Scopeより長生きするdynamic URL component。
	 */
	explicit SecretParsedUrlScope( ParsedUrl &parsed) noexcept : parsed_( parsed)
	{
	}

	/**
	 * @brief Hostとpath／queryの使用済みbuffersをzero clearします。
	 */
	~SecretParsedUrlScope() noexcept
	{
		// 確保済みhost bufferだけをWindowsの消去primitiveへ渡す。
		if( !parsed_.host.empty()) {
			SecureZeroMemory( parsed_.host.data(), parsed_.host.size() * sizeof( wchar_t)) ;
		}

		// Tokenを含み得るpath／query bufferも同じscopeで消去する。
		if( !parsed_.pathQuery.empty()) {
			SecureZeroMemory( parsed_.pathQuery.data(), parsed_.pathQuery.size() * sizeof( wchar_t)) ;
		}

		parsed_.host.clear() ;
		parsed_.pathQuery.clear() ;
		parsed_.port			  = 0U ;
		parsed_.originPolicyIndex = 0U ;
	}

	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	SecretParsedUrlScope( const SecretParsedUrlScope &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	SecretParsedUrlScope &operator=( const SecretParsedUrlScope &) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	SecretParsedUrlScope( SecretParsedUrlScope &&) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	SecretParsedUrlScope &operator=( SecretParsedUrlScope &&) = delete ;

private:
	/// Scope終了時に文字bufferを消去する所有外component。
	ParsedUrl &parsed_ ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをHRESULT bit patternへ変換する。
 *
 * @param[in] error GetLastErrorが返したWin32 error。
 * @return NativeErrorで保持できるHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

/**
 * @brief 新modeだけ残deadlineを同期APIの有限timeoutへ反映する。
 * @param[in] handle Sessionまたはrequestの非所有handle。
 * @param[in,out] execution 専用context。Nullは通常経路。
 * @param[in] initial trueなら通常経路にも従来timeoutを初期設定する。
 * @param[in] transport Handleを生成したI/O表。本呼出し中だけ借用する。
 * @param[in,out] indexControl 非null時だけ固定索引の残期限も適用します。
 * @return 設定成功0、取消し・期限・API失敗は元診断。
 */
[[nodiscard]] NativeError setRequestTimeouts(
	HINTERNET handle, MetadataSearchExecutionContext *execution, const bool initial = false,
	const OfficialHttpTransport &transport	  = NATIVE_HTTP_TRANSPORT,
	SignedIndexHttpControl		*indexControl = nullptr) noexcept
{
	// 従来経路へchunkごとの追加APIを持ち込まない。
	if( execution == nullptr && !initial && indexControl == nullptr) {
		return 0 ;
	}

	int remaining = static_cast<int>( RECEIVE_TIMEOUT_MILLISECONDS) ;	// 最大phaseより長くしない。
	// 索引だけ同一90秒期限を毎同期APIへ反映します。
	if( indexControl != nullptr) {
		remaining = indexControl->timeoutMilliseconds( remaining) ;
		// 0を無限timeoutとしてOSへ渡しません。
		if( remaining <= 0) {
			return indexControl->stopped ;
		}
	}

	// 新modeは毎回同じcontextの期限・取消しを再確認する。
	if( execution != nullptr) {
		const auto error = execution->checkpoint() ;	// 最初の停止診断。
		// 既に停止した操作へtimeout設定や通信を追加しない。
		if( error != 0) {
			return error ;
		}

		remaining = execution->timeoutMilliseconds( remaining) ;
		// 0 timeoutをWinHTTPへ渡すと無限になるため、呼出し自体を拒否する。
		if( remaining <= 0) {
			const auto stopped = execution->checkpoint() ;	// 期限または取消しを保持。
			return stopped != 0 ? stopped : nativeErrorFromWin32( ERROR_TIMEOUT) ;
		}
	}

	// 四つのphaseを各従来値と残期限の小さい方へ制限する。
	if( transport.setTimeouts(
		   handle, std::min( remaining, static_cast<int>( RESOLVE_TIMEOUT_MILLISECONDS)),
		   std::min( remaining, static_cast<int>( CONNECT_TIMEOUT_MILLISECONDS)),
		   std::min( remaining, static_cast<int>( SEND_TIMEOUT_MILLISECONDS)),
		   std::min( remaining, static_cast<int>( RECEIVE_TIMEOUT_MILLISECONDS))) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	return 0 ;
}

/** @brief 同期text取得が例外で終了してもresource予約を終了する。 */
class MetadataResourceScope final {
public:
	/**
     * @brief 新modeのlogical resourceを一つだけ開始する。
     * @param[in,out] execution 借用context。Nullは通常経路。
     * @param[in] maximumBytes Providerが指定した本文上限。
     */
	MetadataResourceScope( MetadataSearchExecutionContext *execution,
						  const std::uint64_t			  maximumBytes)
		: execution_( execution),
		  error_( execution != nullptr ? execution->beginResource( maximumBytes) : 0)
	{
	}
	/** @brief 成功して開始した予約だけを終了する。消費を返却しない。 */
	~MetadataResourceScope()
	{
		// Begin失敗時に外側の有効resourceを閉じない。
		if( execution_ != nullptr && error_ == 0) {
			execution_->finishResource() ;
		}
	}
	/**
	 * @brief 予約開始時に固定した診断値を返します。
	 * @return 予約成功時は0、開始拒否時は元NativeErrorです。
	 * @note 借用contextへ再照会せず、resource予約の開始・終了は行いません。
	 */
	[[nodiscard]] NativeError error() const noexcept
	{
		return error_ ;
	}

private:
	/// 同期取得中だけ借用するcontext。
	MetadataSearchExecutionContext *execution_{} ;
	/// 開始時に固定した診断。
	NativeError						error_{} ;
} ;

/**
 * @brief Cache本文も新modeの実処理byteとして一回だけ計数する。
 * @param[in,out] execution Nullは通常経路。
 * @param[in] bytes Cacheの有限本文byte数。
 * @return 計数成功0、取消し・予算超過は診断値。
 */
[[nodiscard]] NativeError chargeCachedMetadata( MetadataSearchExecutionContext *execution,
											   std::uint64_t				   bytes)
{
	// 通常cacheの従来動作を変更しない。
	if( execution == nullptr) {
		return 0 ;
	}

	// 本文をtransportと同じ有界chunkとして予算へ渡す。
	while( bytes != 0U) {
		const auto allowance = execution->readAllowance( static_cast<std::uint32_t>(
			std::min<std::uint64_t>( bytes, READ_BUFFER_BYTES))) ;	// 今回の処理上限。
		// 許容量がない場合はcache本文を成功として再利用しない。
		if( allowance == 0U) {
			const auto error = execution->checkpoint() ;	// 最初の停止原因。
			return error != 0 ? error : static_cast<NativeError>( E_UNEXPECTED) ;
		}

		const auto error = execution->consumeBytes( allowance) ;	// Cache利用も返却しない。
		// 予算超過probeをparserへ渡さず、そのresourceを拒否する。
		if( error != 0) {
			return error ;
		}

		bytes -= allowance ;
	}

	return execution->checkpoint() ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASCII hostを大文字小文字を区別しない表現へ正規化する。
 *
 * 国際化domainを許可しないallowlist照合用hostを作成する。
 *
 * @param[in] host WinHttpCrackUrlが返したhost。
 * @return ASCII大文字を小文字へ変換したhost。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizeHost( const std::wstring_view host)
{
	std::wstring normalized( host) ;	// Allowlist照合用のmutable host。
	// DNS hostのASCII大文字だけを小文字へ変換する。
	std::transform( normalized.begin(), normalized.end(), normalized.begin(),
				   []( const wchar_t character) {
					   return character >= L'A' && character <= L'Z'
								  ? static_cast<wchar_t>( character - L'A' + L'a')
								  : character ;
				   }) ;
	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASCII DNS名が公式host policyに使用できるか検証する。
 *
 * 空label、label端hyphen、Unicode類似文字を拒否する。
 *
 * @param[in] host 先頭dotを含まないDNS host名。
 * @return DNS label長とASCII文字条件を満たす場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidDnsName( const std::wstring_view host) noexcept
{
	// 空名、DNS 全長超過、先頭または末尾の dot を持つ host は拒否する。
	if( host.empty() || host.size() > 253 || host.front() == L'.' || host.back() == L'.') {
		return false ;
	}

	std::size_t labelLength{} ;				// 現在DNS labelのASCII文字数。
	bool		labelStartsWithHyphen{} ;	// 現在label先頭がhyphenの場合true。
	wchar_t		previous{} ;				// Label終端hyphen検出用の直前文字。
	// DNS 名を label 単位で検査し、許可文字と長さ・hyphen 境界を確認する。
	for( const wchar_t character : host) {
		// Dot ごとに直前 label を確定し、次の label の状態へ移る。
		if( character == L'.') {
			// 空 label、長さ超過、先頭または末尾 hyphen を拒否する。
			if( labelLength == 0 || labelLength > 63 || labelStartsWithHyphen || previous == L'-') {
				return false ;
			}

			labelLength			  = 0 ;
			labelStartsWithHyphen = false ;
			previous			  = character ;
			continue ;
		}

		// 許可hostの構成文字として受理するASCII英数字かを示す。
		const bool asciiAlphanumeric = (character >= L'a' && character <= L'z') ||
									   (character >= L'A' && character <= L'Z') ||
									   (character >= L'0' && character <= L'9') ;
		// ASCII 英数字と hyphen 以外は公式 host policy に受理しない。
		if( !asciiAlphanumeric && character != L'-') {
			return false ;
		}

		// Label の最初の文字だけで先頭 hyphen の有無を記録する。
		if( labelLength == 0) {
			labelStartsWithHyphen = character == L'-' ;
		}

		++labelLength ;
		previous = character ;
	}

	return labelLength != 0 && labelLength <= 63 && !labelStartsWithHyphen && previous != L'-' ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式host allowlist全体を検証する。
 *
 * 空entry、wildcard、Unicode、重複policyをfail-closedで拒否する。
 *
 * @param[in] allowedHosts 完全一致hostまたはdot付きsuffix群。
 * @return 全entryが正しく重複しない場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validateHostAllowlist( const std::span<const std::wstring_view> allowedHosts)
{
	// 空 allowlist を全 host 許可として解釈せず拒否する。
	if( allowedHosts.empty()) {
		return false ;
	}

	std::unordered_set<std::wstring> normalizedEntries ;	// 重複検出用policy entry集合。
	normalizedEntries.reserve( allowedHosts.size()) ;
	// 各 allowlist 項目の DNS 形式と正規化後の重複を調べる。
	for( const std::wstring_view allowed : allowedHosts) {
		const bool suffix = !allowed.empty() && allowed.front() == L'.' ;		// Domain suffix指定。
		const std::wstring_view host = suffix ? allowed.substr( 1) : allowed ;	// 検証対象DNS名。
		// Suffix 指定を除いた host 部分が有効な DNS 名でなければ拒否する。
		if( !isValidDnsName( host)) {
			return false ;
		}

		std::wstring normalized = normalizeHost( host) ;	// 重複比較用小文字host。
		// Suffix 指定を正規化後にも残し、完全一致 policy と区別する。
		if( suffix) {
			normalized.insert( normalized.begin(), L'.') ;
		}

		// 同じ正規化済み項目が重複する曖昧な policy は拒否する。
		if( !normalizedEntries.insert( std::move( normalized)).second) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief hostに一意に一致するorigin policy indexを取得する。
 *
 * 0件と重複一致を拒否し、opaque経路を一意に記録する。
 *
 * @param[in] host 小文字へ正規化済みの接続先host。
 * @param[in] allowedHosts 完全一致hostまたは先頭`.`付きsuffix。
 * @param[out] originPolicyIndex 一意に一致したentry index。
 * @return 一件だけ一致した場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool findAllowedHostIndex( const std::wstring_view					 host,
										const std::span<const std::wstring_view> allowedHosts,
										std::uint32_t							&originPolicyIndex)
{
	bool found{} ;	// 一件のentryが一致した場合true。
	// indexは検査中entryと、成功時に記録するopaque origin位置を示す。
	for( std::size_t index = 0U; index < allowedHosts.size(); ++index) {
		const std::wstring_view allowed = allowedHosts[index] ;					// 現在検査するpolicy entry。
		const std::wstring		normalizedAllowed = normalizeHost( allowed) ;	// Policy比較値。
		bool					matches{} ;										// 現在entryにhostが一致する場合true。
		// Suffix 記号のない policy は host 全体の完全一致で照合する。
		if( normalizedAllowed.front() != L'.') {
			matches = host == normalizedAllowed ;
		} else {
			const std::wstring_view base =	// Dotを除いた公式base domain。
				std::wstring_view( normalizedAllowed).substr( 1) ;
			matches = host == base ||
					  (host.size() > normalizedAllowed.size() && host.ends_with( normalizedAllowed)) ;
		}

		// 一致しない policy は origin の候補数へ加えない。
		if( !matches) {
			continue ;
		}

		// 複数entryへ一致する曖昧なpolicyは通信前に拒否する。
		if( found || index > std::numeric_limits<std::uint32_t>::max()) {
			return false ;
		}

		originPolicyIndex = static_cast<std::uint32_t>( index) ;
		found			  = true ;
	}

	return found ;
}

//------------------------------------------------------------------------------
/**
 * @brief HTTPS exact URLをallowlistと無関係なWinHTTP componentへ分解する。
 * @param[in] url 検証する絶対URL。
 * @param[out] parsed 成功時のhost、path／query、443番port。
 * @return HTTPS、443番、ASCII DNS host、credential・fragmentなしなら0、それ以外はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError parseHttpsUrlComponents( const std::wstring_view url, ParsedUrl &parsed)
{
	// 空 URL、長さ上限超過、fragment 付き URL を拒否する。
	if( url.empty() || url.size() > MAXIMUM_REDIRECT_URL_CHARACTERS ||
	   url.find( L'#') != std::wstring_view::npos) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 制御文字を含む URL は解釈の相違を避けるため拒否する。
	if( std::any_of( url.begin(), url.end(), []( const wchar_t character) {
		   return character <= 0x1f || character == 0x7f ;
	   })) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	URL_COMPONENTS components{} ;	// WinHttpCrackUrlが設定するURL component位置。
	components.dwStructSize		 = sizeof( components) ;
	components.dwHostNameLength	 = static_cast<DWORD>( -1) ;
	components.dwUrlPathLength	 = static_cast<DWORD>( -1) ;
	components.dwExtraInfoLength = static_cast<DWORD>( -1) ;
	components.dwUserNameLength	 = static_cast<DWORD>( -1) ;
	components.dwPasswordLength	 = static_cast<DWORD>( -1) ;
	// URL を構造へ分解できなければ request を作成しない。
	if( WinHttpCrackUrl( url.data(), static_cast<DWORD>( url.size()), 0, &components) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// HTTPS 標準 port と host を必須にし、URL 内 credential を拒否する。
	if( components.nScheme != INTERNET_SCHEME_HTTPS ||
	   components.nPort != INTERNET_DEFAULT_HTTPS_PORT || components.dwHostNameLength == 0 ||
	   components.dwUserNameLength != 0 || components.dwPasswordLength != 0) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const std::wstring host =	// CrackUrl入力buffer内のhost範囲を所有文字列へ複写する。
		normalizeHost( std::wstring_view( components.lpszHostName, components.dwHostNameLength)) ;
	// Unicode、IP literal、不正labelをnetwork requestへ渡さない。
	if( !isValidDnsName( host)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	std::wstring pathQuery ;	// Requestへ渡すpathとqueryの所有文字列。
	// Path のない URL は origin の root への request とする。
	if( components.dwUrlPathLength == 0) {
		pathQuery = L"/" ;
	} else {
		pathQuery.assign( components.lpszUrlPath, components.dwUrlPathLength) ;
	}

	// Query 等の追加部分がある場合は検証済み path に保持する。
	if( components.dwExtraInfoLength != 0) {
		pathQuery.append( components.lpszExtraInfo, components.dwExtraInfoLength) ;
	}

	parsed.host				 = host ;
	parsed.pathQuery		 = std::move( pathQuery) ;
	parsed.port				 = components.nPort ;
	parsed.originPolicyIndex = 0U ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief HTTPS URLを検証してWinHTTP用componentへ分解する。
 * @param[in] url 検証する絶対URL。
 * @param[in] allowedHosts 許可する公式host。
 * @param[out] parsed 成功時の接続component。
 * @return 成功時は0、検証失敗時はE_ACCESSDENIEDまたはE_INVALIDARG。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError parseHttpsUrl( const std::wstring_view					 url,
										const std::span<const std::wstring_view> allowedHosts,
										ParsedUrl								&parsed)
{
	// 不正allowlistの場合はURLの一部だけを採用しない。
	if( !validateHostAllowlist( allowedHosts)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	ParsedUrl		  validated ;												// Allowlist一致後にだけ出力へ移すcomponent。
	const NativeError parseError = parseHttpsUrlComponents( url, validated) ;	// 共通HTTPS検証結果。
	// 基本URL検証失敗時はallowlist照合を行わない。
	if( parseError != 0) {
		return parseError ;
	}

	std::uint32_t originPolicyIndex{} ;	// 一意に一致したorigin entry index。
	// 一意の許可originに一致するhostだけを受理する。
	if( !findAllowedHostIndex( validated.host, allowedHosts, originPolicyIndex)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	validated.originPolicyIndex = originPolicyIndex ;
	parsed						= std::move( validated) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのURLを検証しopaque redirect経路へ追加する。
 *
 * Hostとrequest targetの同一経路を再度通る循環を拒否する。
 *
 * @param[in] url 起点またはLocationの絶対URL。
 * @param[in] allowedHosts resourceの組み込みhost群。
 * @param[in,out] visitedRequests 循環検出用の正規化済み経路。
 * @param[in,out] originPolicyIndices 検証済みorigin index群。
 * @param[out] parsed 成功時のWinHTTP接続component。
 * @return URL検証と経路追加成功時は0、失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError appendValidatedRouteUrl(
	const std::wstring_view url, const std::span<const std::wstring_view> allowedHosts,
	std::unordered_set<std::wstring> &visitedRequests,
	std::vector<std::uint32_t> &originPolicyIndices, ParsedUrl &parsed)
{
	const NativeError parseError = parseHttpsUrl( url, allowedHosts, parsed) ;	// URL検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( parseError != 0) {
		return parseError ;
	}

	const std::wstring requestKey =
		parsed.host + L"\n" + parsed.pathQuery ;	// Host大小文字差を除いた循環検出key。
	// 訪問済み request への redirect は循環として拒否する。
	if( !visitedRequests.insert( requestKey).second) {
		return nativeErrorFromWin32( ERROR_WINHTTP_REDIRECT_FAILED) ;
	}

	originPolicyIndices.push_back( parsed.originPolicyIndex) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief HTTP statusが追跡対象redirectか判定する。
 *
 * 300と305は追跡せず、301、302、303、307、308だけを扱う。
 *
 * @param[in] status HTTP response status code。
 * @return GETの手動追跡を許可するstatusなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isRedirectStatus( const DWORD status) noexcept
{
	return status == HTTP_STATUS_MOVED || status == HTTP_STATUS_REDIRECT ||
		   status == HTTP_STATUS_REDIRECT_METHOD || status == HTTP_STATUS_REDIRECT_KEEP_VERB ||
		   status == PERMANENT_REDIRECT_STATUS ;
}

//------------------------------------------------------------------------------
/**
 * @brief Redirect responseのLocation URLを取得する。
 *
 * 空、過大、制御文字を拒否する。HTTPSとhostは後段で検証する。
 *
 * @param[in] request 受信済みredirect response handle。
 * @param[out] location 成功時の絶対Location URL。
 * @param[in] transport Handleを生成したI/O表。本呼出し中だけ借用する。
 * @return 有限のLocation取得成功時は0、失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError queryRedirectLocation(
	const HINTERNET request, std::wstring &location,
	const OfficialHttpTransport &transport = NATIVE_HTTP_TRANSPORT)
{
	location.clear() ;
	DWORD bytes{} ;	// Location文字列に必要なUTF-16 byte数。
	transport.queryHeaders( request, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
						   WINHTTP_NO_OUTPUT_BUFFER, &bytes, WINHTTP_NO_HEADER_INDEX) ;
	// Location 長を取得できない応答と許可上限を超える redirect 先を拒否する。
	if( GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes < sizeof( wchar_t) ||
	   bytes > (MAXIMUM_REDIRECT_URL_CHARACTERS + 1U) * sizeof( wchar_t)) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE)) ;
	}

	std::wstring value( bytes / sizeof( wchar_t), L'\0') ;	// Location受信buffer。
	// Location 本体の取得失敗を Windows の診断値で返す。
	if( transport.queryHeaders( request, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
							  value.data(), &bytes, WINHTTP_NO_HEADER_INDEX) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	value.resize( bytes / sizeof( wchar_t)) ;
	// Header API が付加した末尾 NUL を文字列比較の対象から除く。
	while( !value.empty() && value.back() == L'\0') {
		value.pop_back() ;
	}

	// 空、長すぎる、または制御文字を含む Location は追跡しない。
	if( value.empty() || value.size() > MAXIMUM_REDIRECT_URL_CHARACTERS ||
	   std::any_of( value.begin(), value.end(), []( const wchar_t character) {
		   return character <= 0x1f || character == 0x7f ;
	   })) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE)) ;
	}

	location = std::move( value) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定form POST bodyの構造を検証する。
 *
 * CR/LF、非ASCII、不完全percent escape、空fieldを拒否し、request bodyをheaderや別protocolへ解釈させない。
 *
 * @param[in] body ASCIIでpercent encode済みのform body。
 * @return 有限なkey=value列だけで構成される場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidFormBody( const std::string_view body) noexcept
{
	// 空、上限外または空fieldを拒否する。
	if( body.empty() || body.size() > MAXIMUM_FORM_BODY_BYTES || body.front() == '&' ||
	   body.back() == '&') {
		return false ;
	}

	std::size_t fieldCount{1U} ;	// 現在までに確認したform field数。
	bool		hasAssignment{} ;	// 現在fieldで一つの'='を確認した場合true。
	// 全byteを有限回確認し、ASCII formの最小構造以外を拒否する。
	for( std::size_t index = 0U; index < body.size(); ++index) {
		const char character = body[index] ;	// 現在検証するASCII byte。
		// Field 区切りでは直前の assignment を検証し、件数上限を確認する。
		if( character == '&') {
			// 値のないfieldまたはfield数上限超過を拒否する。
			if( !hasAssignment || ++fieldCount > MAXIMUM_FORM_FIELDS) {
				return false ;
			}

			hasAssignment = false ;
			continue ;
		}

		// Assignment 記号では key/value の欠落と重複を検査する。
		if( character == '=') {
			// 空key、空valueまたは複数assignmentを拒否する。
			if( hasAssignment || index == 0U || body[index - 1U] == '&' ||
			   index + 1U == body.size() || body[index + 1U] == '&') {
				return false ;
			}

			hasAssignment = true ;
			continue ;
		}

		// Percent encodeせずform componentへ置けるASCII文字の場合true。
		const bool unreserved =
			(character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '.' ||
			character == '_' || character == '~' || character == '+' ;
		// Form で許可する非予約文字は escape 検証を必要としない。
		if( unreserved) {
			continue ;
		}

		// Form component外文字または不完全escapeを拒否する。
		if( character != '%' || index + 2U >= body.size()) {
			return false ;
		}

		const auto isHex = []( const char value) {
			return (value >= '0' && value <= '9') || (value >= 'A' && value <= 'F') ||
				   (value >= 'a' && value <= 'f') ;
		} ; // Percent escapeを構成できるASCII hex判定。
		// 不正percent escapeを拒否する。
		if( !isHex( body[index + 1U]) || !isHex( body[index + 2U])) {
			return false ;
		}

		index += 2U ;
	}

	return hasAssignment ;
}

//------------------------------------------------------------------------------
/**
 * @brief 検証済みURLへ自動redirect禁止GET requestを作成する。
 *
 * system proxyを使用し、redirectはLocation検証前に追跡しない。資格情報はWinHTTP既定のIntranet限定MEDIUM policyを明示する。
 *
 * @param[in] parsed 検証済みURL component。
 * @param[out] session 作成したWinHTTP session。
 * @param[out] connection 作成した接続handle。
 * @param[out] request 応答受信開始済みrequest handle。
 * @param[in] ifNoneMatch 空または検証済みETag。
 * @param[out] status HTTP 200、条件付き304または追跡対象3xx。
 * @param[in,out] execution 専用予算。Nullは従来の通常GET。
 * @param[in] transport 生成元I/O表。所有handleは同表のclose関数を保持する。
 * @param[in] autoLogonPolicy Serverへの既定credential利用policy。Dynamic targetはHIGHを必須とする。
 * @param[in] collectorMetadata Cookieを無効にする収集専用要求。
 * @param[in,out] indexControl 索引用途だけの共有期限と送信上限です。
 * @param[in,out] collectorTransfer 収集専用の実send/status記録先です。
 * @param[in] collectorCancellation 収集専用の送信直前取消しです。
 * @return 検査対象status受信時は0、失敗時はHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError openGetRequest(
	const ParsedUrl &parsed, InternetHandle &session, InternetHandle &connection,
	InternetHandle &request, const std::wstring_view ifNoneMatch, DWORD &status,
	MetadataSearchExecutionContext *execution		= nullptr,
	const OfficialHttpTransport	   &transport		= NATIVE_HTTP_TRANSPORT,
	const DWORD						autoLogonPolicy = WINHTTP_AUTOLOGON_SECURITY_LEVEL_MEDIUM,
	const bool collectorMetadata = false, SignedIndexHttpControl *indexControl = nullptr,
	CollectorHttpTransferRecorder  *collectorTransfer	  = nullptr,
	const HttpCancellationCallback *collectorCancellation = nullptr)
{
	status = 0 ;
	// 長さ超過または印字可能 ASCII 以外を含む ETag は header に使用しない。
	if( ifNoneMatch.size() > MAXIMUM_ETAG_CHARACTERS ||
	   std::any_of( ifNoneMatch.begin(), ifNoneMatch.end(),
				   []( const wchar_t character) { return character < 0x20 || character > 0x7e ; })) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	InternetHandle createdSession(	// System proxyを利用するWinHTTP session。
		transport.open( HTTP_USER_AGENT, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
					   WINHTTP_NO_PROXY_BYPASS, 0),
		transport) ;
	// WinHTTP session を確保できなければ request 作成を中止する。
	if( !createdSession.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 有限 timeout を設定できなければ通信を開始しない。
	const NativeError timeoutError =
		setRequestTimeouts( createdSession.get(), execution, true, transport, indexControl) ;
	// 有限timeoutを設定できないhandleから通信を始めない。
	if( timeoutError != 0) {
		return timeoutError ;
	}

	InternetHandle createdConnection(	// 検証済みhostへのconnection handle。
		transport.connect( createdSession.get(), parsed.host.c_str(), parsed.port, 0), transport) ;
	// 許可 host への connection を作成できなければ中止する。
	if( !createdConnection.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	InternetHandle createdRequest(	// HTTPS GET request handle。
		transport.openRequest( createdConnection.get(), L"GET", parsed.pathQuery.c_str(), nullptr,
							  WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
							  WINHTTP_FLAG_SECURE),
		transport) ;
	// GET request handle を作成できなければ送信しない。
	if( !createdRequest.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	DWORD redirectPolicy =	// 30xをapplicationで検証するため自動追跡しない。
		WINHTTP_OPTION_REDIRECT_POLICY_NEVER ;
	// 自動 redirect 禁止を設定できなければ手動検証境界を保てないため中止する。
	if( transport.setOption( createdRequest.get(), WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy,
						   sizeof( redirectPolicy)) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	DWORD appliedAutoLogonPolicy = autoLogonPolicy ;	// WinHTTPが借りるmutable option buffer。
	// 自動 logon の制限を設定できなければ通信を開始しない。
	if( transport.setOption( createdRequest.get(), WINHTTP_OPTION_AUTOLOGON_POLICY,
						   &appliedAutoLogonPolicy, sizeof( autoLogonPolicy)) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 継続収集は個人化cookieと中間cacheの未検証な鮮度を使用しない。
	if( collectorMetadata) {
		DWORD disabled = WINHTTP_DISABLE_COOKIES ;								// Cookie保存・送信を無効にする。
		constexpr std::wstring_view header = L"Cache-Control: no-cache\r\n" ;	// 再検証要求。
		// 設定できなければ条件を弱めて送信しない。
		if( !transport.setOption( createdRequest.get(), WINHTTP_OPTION_DISABLE_FEATURE, &disabled,
								sizeof( disabled)) ||
		   !transport.addHeaders( createdRequest.get(), header.data(),
								 static_cast<DWORD>( header.size()),
								 WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE)) {
			return nativeErrorFromWin32( GetLastError()) ;
		}
	}

	constexpr std::wstring_view
		ACCEPT_HEADER =	// 公式metadataとbinaryの両方を許可するAccept header。
		L"Accept: application/json, application/xml, text/xml, application/octet-stream, */*\r\n" ;
	// 固定 Accept header の設定失敗は request 全体の失敗とする。
	if( transport.addHeaders( createdRequest.get(), ACCEPT_HEADER.data(),
							static_cast<DWORD>( ACCEPT_HEADER.size()),
							WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 検証済み ETag が指定された場合だけ条件付き取得 header を加える。
	if( !ifNoneMatch.empty()) {
		const std::wstring conditionalHeader =	// 検証済みETagの条件付きrequest header。
			L"If-None-Match: " + std::wstring( ifNoneMatch) + L"\r\n" ;
		// 条件付き取得 header を設定できなければ別条件で送信しない。
		if( transport.addHeaders( createdRequest.get(), conditionalHeader.c_str(),
								static_cast<DWORD>( conditionalHeader.size()),
								WINHTTP_ADDREQ_FLAG_ADD_IF_NEW) == FALSE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}
	}

	// 送信直前の残期限に拘束したtimeout設定結果。
	const NativeError sendTimeoutError =
		setRequestTimeouts( createdRequest.get(), execution, false, transport, indexControl) ;
	// 送信前の期限切れやtimeout設定失敗を隠さない。
	if( sendTimeoutError != 0) {
		return sendTimeoutError ;
	}

	// Timeout設定失敗を送信数へ加えず、最後の同期設定後にcost・取消し・予算を照合する。
	if( execution != nullptr) {
		const NativeError permissionError = execution->beforeHttpAttempt() ;	// 直後の実送信の許可。
		// 未同意・停止・予算上限を送信後の警告へ弱めない。
		if( permissionError != 0) {
			return permissionError ;
		}
	}

	// 用途が私有固定した索引send上限を実送信の直前だけに課金します。
	if( indexControl != nullptr) {
		const auto stopped = indexControl->checkpoint() ;	// 実送信前の同一停止です。
		// 不許可sendを通信成功へ数えません。
		if( stopped != 0 || indexControl->sends >= indexControl->sendLimit()) {
			return stopped != 0 ? stopped : static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		++indexControl->sends ;
	}

	// 収集は最後の設定後にも取消しを確認し、実sendに入る試行だけを数えます。
	if( collectorTransfer != nullptr) {
		// Callback障害も未送信のUNKNOWNへ残します。
		if( collectorCancellation != nullptr) {
			try {
				// 実送信前の取消しを試行済みへ数えません。
				if( *collectorCancellation && (*collectorCancellation)()) {
					return nativeErrorFromWin32( ERROR_CANCELLED) ;
				}
			} catch( ...) {
				return E_UNEXPECTED ;
			}
		}

		collectorTransfer->attempting() ;
	}

	// 送信に失敗した場合は通信の診断値を返す。
	if( transport.sendRequest( createdRequest.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
							 WINHTTP_NO_REQUEST_DATA, 0, 0, 0) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 送信完了後に再確認した応答待機の設定結果。
	const NativeError receiveTimeoutError =
		setRequestTimeouts( createdRequest.get(), execution, false, transport, indexControl) ;
	// 送信待機中に生じた取消しや期限を応答待機前に検査する。
	if( receiveTimeoutError != 0) {
		return receiveTimeoutError ;
	}

	// 応答開始の元診断を保持する。
	if( transport.receiveResponse( createdRequest.get(), nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 索引の同期応答待機中の停止もstatusより先に確定します。
	if( indexControl != nullptr && indexControl->checkpoint() != 0) {
		return indexControl->stopped ;
	}

	// 同期応答待機中の停止をstatusや本文の成功より先に確定する。
	if( execution != nullptr) {
		const auto stopped = execution->checkpoint() ;	// 応答開始後の協調停止。
		// 停止後はheader・bodyへ進まない。
		if( stopped != 0) {
			return stopped ;
		}
	}

	DWORD statusBytes = sizeof( status) ;	// Status code受信buffer byte数。
	// HTTP status を取得できない応答は成功として扱わない。
	if( transport.queryHeaders(
		   createdRequest.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
		   WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusBytes, WINHTTP_NO_HEADER_INDEX) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const NativeError statusError =	// 拒否statusを本文取得前に元の数値付きで返す。
		validateOfficialHttpResponseStatus( status, !ifNoneMatch.empty(), true) ;
	// 拒否statusも同じ実HTTP観測へ残します。
	if( collectorTransfer != nullptr) {
		collectorTransfer->status( status) ;
	}

	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( statusError != 0) {
		// 収集専用429／503のheader観測だけに所有handleを引き渡す。本文は受理しない。
		if( collectorMetadata && (status == 429U || status == 503U)) {
			session	   = std::move( createdSession) ;
			connection = std::move( createdConnection) ;
			request	   = std::move( createdRequest) ;
		}

		return statusError ;
	}

	session	   = std::move( createdSession) ;
	connection = std::move( createdConnection) ;
	request	   = std::move( createdRequest) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 検証済みURLへredirect禁止form POST requestを作成する。
 *
 * system proxyを使用し、redirect、cache、cookie処理を追加せず固定metadata formだけを同期送信する。
 *
 * @param[in] parsed 検証済みURL component。
 * @param[in] formBody 有限なASCII form body。
 * @param[out] session 作成したWinHTTP session。
 * @param[out] connection 作成した接続handle。
 * @param[out] request HTTP 200を受信済みのrequest handle。
 * @return HTTP 200受信時は0、検証またはWinHTTP失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError openPostFormRequest( const ParsedUrl		&parsed,
											  const std::string_view formBody,
											  InternetHandle &session, InternetHandle &connection,
											  InternetHandle &request)
{
	// 不正bodyでは接続しない。
	if( !isValidFormBody( formBody)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	InternetHandle createdSession(	// System proxyを利用するWinHTTP session。
		WinHttpOpen( HTTP_USER_AGENT, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
					WINHTTP_NO_PROXY_BYPASS, 0)) ;
	// POST 用 WinHTTP session の作成失敗時は通信を開始しない。
	if( !createdSession.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// POST の有限 timeout 設定に失敗した場合は中止する。
	if( WinHttpSetTimeouts( createdSession.get(), RESOLVE_TIMEOUT_MILLISECONDS,
						  CONNECT_TIMEOUT_MILLISECONDS, SEND_TIMEOUT_MILLISECONDS,
						  RECEIVE_TIMEOUT_MILLISECONDS) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	InternetHandle createdConnection(	// 検証済みhostへのconnection handle。
		WinHttpConnect( createdSession.get(), parsed.host.c_str(), parsed.port, 0)) ;
	// POST の接続 handle を作成できなければ送信しない。
	if( !createdConnection.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	InternetHandle createdRequest(	// HTTPS POST request handle。
		WinHttpOpenRequest( createdConnection.get(), L"POST", parsed.pathQuery.c_str(), nullptr,
						   WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE)) ;
	// POST request handle の作成失敗を呼出し元へ返す。
	if( !createdRequest.valid()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	DWORD redirectPolicy =	// POST先変更を許可しない自動redirect policy。
		WINHTTP_OPTION_REDIRECT_POLICY_NEVER ;
	// POST の自動 redirect を禁止できなければ送信を許可しない。
	if( WinHttpSetOption( createdRequest.get(), WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy,
						sizeof( redirectPolicy)) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	DWORD autoLogonPolicy =	// Default資格情報をIntranet requestだけへ許可する安全level。
		WINHTTP_AUTOLOGON_SECURITY_LEVEL_MEDIUM ;
	// POST の自動 logon 制限が成立しなければ通信を中止する。
	if( WinHttpSetOption( createdRequest.get(), WINHTTP_OPTION_AUTOLOGON_POLICY, &autoLogonPolicy,
						sizeof( autoLogonPolicy)) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	constexpr std::wstring_view HEADERS =
		L"Accept: application/json\r\n"
		L"Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n" ;	// 固定header。
	// 固定 POST header を設定できなければ不完全な request を送信しない。
	if( WinHttpAddRequestHeaders( createdRequest.get(), HEADERS.data(),
								static_cast<DWORD>( HEADERS.size()),
								WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 同期WinHttpSendRequestは呼出し中だけbodyを読み、内容を書き換えないためconstを外す。
	void *const requestBody = const_cast<char *>( formBody.data()) ;	// 所有外の送信buffer。
	const DWORD bodyBytes	= static_cast<DWORD>( formBody.size()) ;	// 2 KiB以下の送信byte数。
	// POST の送信または応答開始に失敗したら診断値を保持する。
	if( WinHttpSendRequest( createdRequest.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, requestBody,
						  bodyBytes, bodyBytes, 0) == FALSE ||
	   WinHttpReceiveResponse( createdRequest.get(), nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	DWORD status{} ;						// ResponseのHTTP status code。
	DWORD statusBytes = sizeof( status) ;	// Status code受信buffer byte数。
	// POST 応答の status を確認できなければ正常応答と仮定しない。
	if( WinHttpQueryHeaders(
		   createdRequest.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
		   WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusBytes, WINHTTP_NO_HEADER_INDEX) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const NativeError statusError =	// POSTは200だけを許可し、redirectもHTTP errorとして返す。
		validateOfficialHttpResponseStatus( status, false, false) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( statusError != 0) {
		return statusError ;
	}

	session	   = std::move( createdSession) ;
	connection = std::move( createdConnection) ;
	request	   = std::move( createdRequest) ;
	return 0 ;
}

/**
 * @brief Payload取得時のredirect hop間でも共通の取消し境界を適用する。
 * Payload取得の取消し要求を安全に確認する。
 * Callback例外をHTTP処理境界から漏らさずfail-closedにする。
 * @param[in] cancellationCallback 空または取消し状態の確認先。
 * @return 継続時は0、取消し時はERROR_CANCELLED由来HRESULT、callback例外時はE_UNEXPECTED。
 */
[[nodiscard]] NativeError checkCancellation(
	const HttpCancellationCallback &cancellationCallback) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 公式origin間の有限redirectを手動追跡する。
 *
 * WinHTTPの自動redirectを使用せず、全Locationを通信前にHTTPS、port、credential、host、回数、循環で検証する。
 *
 * @param[in] url 起点の絶対HTTPS URL。
 * @param[in] allowedHosts resourceに許可するorigin群。
 * @param[in] maximumRedirects 追跡可能な30x回数。
 * @param[in] ifNoneMatch 起点にだけ送る検証済みETag。
 * @param[in] cancellationCallback 空または取消し状態の確認先。
 * @param[out] session 最終responseのWinHTTP session。
 * @param[out] connection 最終responseのconnection。
 * @param[out] request 受信済み最終response request。
 * @param[out] status 許可済み最終HTTP status。
 * @param[out] originPolicyIndices 起点から最終originのindex列。
 * @param[in,out] execution 新modeの送信予算・cost・期限。Nullは従来の通常GET。
 * @param[in] transport 各hopに共通のI/O表。生成したhandleへclose関数をcopyする。
 * @param[in] requirePublicSameOrigin trueなら各hopの全DNS宛先と起点originを検証する。
 * @param[out] finalUrl 非nullなら成功した最終response URL。失敗時は空。
 * @param[in] collectorMetadata 収集専用のcookie無効化と失敗status観測。
 * @param[in,out] collectorTransfer 収集専用の実send/status記録先です。
 * @return 最終response確定時は0、不正遷移または失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError openGetRequestFollowingRedirects(
	const std::wstring_view url, const std::span<const std::wstring_view> allowedHosts,
	const std::uint32_t maximumRedirects, const std::wstring_view ifNoneMatch,
	const HttpCancellationCallback &cancellationCallback, InternetHandle &session,
	InternetHandle &connection, InternetHandle &request, DWORD &status,
	std::vector<std::uint32_t>	   &originPolicyIndices,
	MetadataSearchExecutionContext *execution = nullptr,
	const OfficialHttpTransport	   &transport = NATIVE_HTTP_TRANSPORT,
	const bool requirePublicSameOrigin = false, std::wstring *finalUrl = nullptr,
	const bool					   collectorMetadata = false,
	CollectorHttpTransferRecorder *collectorTransfer = nullptr)
{
	status = 0U ;
	originPolicyIndices.clear() ;
	// 失敗時に古い最終URLを次page解決へ再利用させない。
	if( finalUrl != nullptr) {
		finalUrl->clear() ;
	}

	// Redirect 回数の要求が共通上限を超える場合は受理しない。
	if( maximumRedirects > MAXIMUM_REDIRECTS) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::wstring					 currentUrl( url) ;	// 現在requestする起点またはLocation URL。
	std::wstring					 firstHost ;		// Live HTMLだけの起点host。
	INTERNET_PORT					 firstPort{} ;		// Live HTMLだけの起点HTTPS port。
	std::unordered_set<std::wstring> visitedRequests ;	// 正規化済み循環検出key集合。
	visitedRequests.reserve( static_cast<std::size_t>( maximumRedirects) + 1U) ;
	originPolicyIndices.reserve( static_cast<std::size_t>( maximumRedirects) + 1U) ;
	// 起点と最大5回のLocationを順に検証し、最終responseで終了する。
	while( true) {
		const NativeError cancellationError =
			// 次hop接続前の取消し確認結果。
			checkCancellation( cancellationCallback) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( cancellationError != 0) {
			return cancellationError ;
		}

		ParsedUrl		  parsed ;	// 現在URLの検証済みcomponent。
		const NativeError routeError =
			appendValidatedRouteUrl( currentUrl, allowedHosts, visitedRequests, originPolicyIndices,
									parsed) ;	// 経路追加結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( routeError != 0) {
			return routeError ;
		}

		// Live HTMLの起点originを最初の検証済みURLから固定する。
		if( requirePublicSameOrigin && firstHost.empty()) {
			firstHost = parsed.host ;
			firstPort = parsed.port ;
		}

		// 別originへのredirectは許可host内でも通信前に止める。
		if( requirePublicSameOrigin && (parsed.host != firstHost || parsed.port != firstPort)) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		// Host名だけではpublicを保証しないため、各hopの全DNS addressを確認する。
		if( requirePublicSameOrigin) {
			OfficialPublicDestinationEvidence destination ;	// URLを持たない検証結果。
			// 全DNS addressの判定結果。元診断のまま返す。
			const NativeError				  destinationError = validatePublicOfficialDestination(
				parsed.host, transport.resolveDestination, destination) ;
			// Private／loopbackまたは解決失敗時は一byteも送信しない。
			if( destinationError != 0) {
				return destinationError ;
			}
		}

		// DNS後、handle生成前の取消し結果。
		const NativeError postResolveCancellation = checkCancellation( cancellationCallback) ;
		// DNS確認後に取消されたhopへWinHTTP handleを作成しない。
		if( postResolveCancellation != 0) {
			return postResolveCancellation ;
		}

		InternetHandle			currentSession( nullptr) ;		// 現在hopのsession handle。
		InternetHandle			currentConnection( nullptr) ;	// 現在hopのconnection handle。
		InternetHandle			currentRequest( nullptr) ;		// 現在hopのresponse handle。
		DWORD					currentStatus{} ;				// 現在hopのHTTP status。
		const std::wstring_view requestEtag =
			// 起点専用ETag。
			originPolicyIndices.size() == 1U ? ifNoneMatch : std::wstring_view{} ;
		const NativeError requestError =
			openGetRequest( parsed, currentSession, currentConnection, currentRequest, requestEtag,
						   currentStatus, execution, transport,
						   requirePublicSameOrigin ? WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH
												   : WINHTTP_AUTOLOGON_SECURITY_LEVEL_MEDIUM,
						   collectorMetadata, nullptr, collectorTransfer,
						   &cancellationCallback) ;	// 現在hop受信結果。
		// 元のHTTP失敗と未通信を収集台帳で区別する。
		if( collectorMetadata) {
			status = currentStatus ;
		}

		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( requestError != 0) {
			// 収集専用の失敗headerを読む場合だけhandleを親へ引き継ぐ。
			if( collectorMetadata && currentRequest.valid()) {
				session	   = std::move( currentSession) ;
				connection = std::move( currentConnection) ;
				request	   = std::move( currentRequest) ;
			}

			return requestError ;
		}

		// 応答待機から復帰した時点の取消し結果。
		const NativeError postResponseCancellation = checkCancellation( cancellationCallback) ;
		// 同期応答待ち中に取消された場合はstatusやredirectを公開しない。
		if( postResponseCancellation != 0) {
			return postResponseCancellation ;
		}

		// Redirect 以外の応答に到達したら handle 群と status の所有権を返す。
		if( !isRedirectStatus( currentStatus)) {
			session	   = std::move( currentSession) ;
			connection = std::move( currentConnection) ;
			request	   = std::move( currentRequest) ;
			status	   = currentStatus ;
			// 本文の基準URLを成功responseと同じhopへ固定する。
			if( finalUrl != nullptr) {
				*finalUrl = currentUrl ;
			}

			return 0 ;
		}

		const std::size_t redirectCount = originPolicyIndices.size() - 1U ;	// 完了hop数。
		// 許可回数を使い切った redirect は追加 request を作らず中止する。
		if( redirectCount >= maximumRedirects) {
			return nativeErrorFromWin32( ERROR_WINHTTP_REDIRECT_FAILED) ;
		}

		std::wstring	  location ;	// 次hopとして未検証のLocation URL。
		const NativeError locationError =
			// Location取得結果。
			queryRedirectLocation( currentRequest.get(), location, transport) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( locationError != 0) {
			return locationError ;
		}

		currentUrl = std::move( location) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Live textのContent-Typeを用途別のUTF-8へ厳密に限定します。
 * @param[in] request 最終HTTP 200 response handle。
 * @param[in] transport Handleと同じ低位I/O表。
 * @param[in] script 非実行script用MIMEとcharset省略を認める場合true。
 * @param[in] collectorHtml 収集検査HTMLだけでcharset省略を認める場合true。既定はfalse。
 * @return HTMLは明示UTF-8または明示収集の省略、scriptは既知MIMEと省略またはUTF-8宣言なら0。
 * @note 不明charset、重複charset、MIME欠損、制御文字、過大headerを拒否します。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateLiveHtmlContentType( const HINTERNET			   request,
													  const OfficialHttpTransport &transport,
													  const bool				   script,
													  const bool collectorHtml = false)
{
	DWORD bytes{} ;	// WinHTTPが返すUTF-16 header長。
	transport.queryHeaders( request, WINHTTP_QUERY_CONTENT_TYPE, WINHTTP_HEADER_NAME_BY_INDEX,
						   WINHTTP_NO_OUTPUT_BUFFER, &bytes, WINHTTP_NO_HEADER_INDEX) ;
	// 欠損、取得失敗、不正長、過大headerを本文読取り前に拒否する。
	if( GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes < sizeof( wchar_t) ||
	   bytes > 257U * sizeof( wchar_t) || bytes % sizeof( wchar_t) != 0U) {
		return nativeErrorFromWin32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
	}

	std::wstring value( bytes / sizeof( wchar_t), L'\0') ;	// Header本体の有限buffer。
	// 一回目と同じサイズまでのheaderだけを受理する。
	if( transport.queryHeaders( request, WINHTTP_QUERY_CONTENT_TYPE, WINHTTP_HEADER_NAME_BY_INDEX,
							  value.data(), &bytes, WINHTTP_NO_HEADER_INDEX) == FALSE ||
	   bytes > value.size() * sizeof( wchar_t) || bytes % sizeof( wchar_t) != 0U) {
		return nativeErrorFromWin32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
	}

	value.resize( bytes / sizeof( wchar_t)) ;
	// WinHTTPの終端NULを一つだけ除去する。
	if( !value.empty() && value.back() == L'\0') {
		value.pop_back() ;
	}

	// NULや非ASCII controlを含むheaderは曖昧な解釈になるため拒否する。
	if( value.empty() || value.size() > 256U ||
	   std::any_of( value.begin(), value.end(),
				   []( const wchar_t character) { return character < 0x20 || character > 0x7e ; })) {
		return nativeErrorFromWin32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
	}

	// Media typeとparameterを大文字小文字に依存せず比較する。
	std::transform( value.begin(), value.end(), value.begin(), []( const wchar_t character) {
		return character >= L'A' && character <= L'Z'
				   ? static_cast<wchar_t>( character + (L'a' - L'A'))
				   : character ;
	}) ;
	const auto trim = []( const std::wstring_view part) {
		std::size_t begin = 0U ;			// Parameter先頭の空白除去位置。
		std::size_t end	  = part.size() ;	// Parameter末尾の空白除去位置。
		// HTTPのspaceとtabだけを両端から除く。
		while( begin < end && (part[begin] == L' ' || part[begin] == L'\t')) {
			++begin ;
		}

		// Header末尾のspaceとtabだけを除く。
		while( end > begin && (part[end - 1U] == L' ' || part[end - 1U] == L'\t')) {
			--end ;
		}

		return part.substr( begin, end - begin) ;
	} ; // 呼出し中だけ元headerを借用する空白除去。
	const std::size_t firstSemicolon = value.find( L';') ;								// MIMEとparameterの境界。
	const auto mime = trim( std::wstring_view( value).substr( 0U, firstSemicolon)) ;	// 用途別MIME。
	// 通常HTMLのcharset必須を維持し、MIME自体は用途別の厳密集合へ限定する。
	if( script ? (mime != L"application/javascript" && mime != L"text/javascript")
			  : mime != L"text/html") {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// Scriptと明示収集HTMLの宣言省略時も原byteをstrict UTF-8検証する。
	if( firstSemicolon == std::wstring::npos) {
		return script || collectorHtml ? 0 : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// 空parameterや末尾区切りを暗黙のcharset指定へ変換しない。
	if( firstSemicolon + 1U == value.size() || value.back() == L';') {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	bool		charsetSeen = false ;				// UTF-8 charsetを一度だけ確認した場合true。
	std::size_t begin		= firstSemicolon + 1U ;	// 次parameter先頭。
	// セミコロンで区切られた全parameterを検査する。
	while( begin < value.size()) {
		const std::size_t end = value.find( L';', begin) ;	// 現parameter末尾。
		// 空白を除いた現在のContent-Type parameter。
		const auto		  part	= trim( std::wstring_view( value).substr( begin, end - begin)) ;
		const std::size_t equal = part.find( L'=') ;	// Name/value境界。
		// 空または等号なしparameterはContent-Typeの曖昧さとして拒否する。
		if( part.empty() || equal == std::wstring_view::npos || equal == 0U) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const auto name			  = trim( part.substr( 0U, equal)) ;	// Parameter名。
		const auto parameterValue = trim( part.substr( equal + 1U)) ;	// Parameter値。
		// 最初のvertical sliceでは唯一のcharset parameterだけを許可する。
		if( name != L"charset" || charsetSeen ||
		   (parameterValue != L"utf-8" && parameterValue != L"\"utf-8\"")) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		charsetSeen = true ;

		// 最後のparameterまで消費したら終了する。
		if( end == std::wstring::npos) {
			break ;
		}

		begin = end + 1U ;
	}

	return charsetSeen ? 0 : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Content-Lengthを64-bit値として取得する。
 *
 * DWORD上限を超えるpayloadも扱えるようheader文字列を解析する。
 *
 * @param[in] request 応答受信開始済みrequest handle。
 * @param[in] transport Handleを生成したI/O表。本呼出し中だけ借用する。
 * @param[out] error Null以外では不正headerと元API失敗を返す。欠損は成功とする。
 * @param[out] declared Null以外では明示0も含む正常な宣言長を取得した場合true。
 * @return 取得できたbyte数。不明または不正な場合は0。Error指定時は診断と合わせて判定する。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint64_t queryContentLength(
	const HINTERNET request, const OfficialHttpTransport &transport = NATIVE_HTTP_TRANSPORT,
	NativeError *error = nullptr, bool *declared = nullptr) noexcept
{
	// 任意の診断先を初期化し、欠損と明示0を区別する。
	if( error != nullptr) {
		*error = 0 ;
	}

	// 長さを正常解析するまで、明示された値として扱わない。
	if( declared != nullptr) {
		*declared = false ;
	}

	DWORD characters{} ;	// Headerの必要byte数。数値用固定bufferより大きければ拒否する。
	transport.queryHeaders( request, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX,
						   WINHTTP_NO_OUTPUT_BUFFER, &characters, WINHTTP_NO_HEADER_INDEX) ;
	const auto queryError = GetLastError() ;	// 最初のAPI診断を保持する。
	// Header欠損だけを長さ不明として許す。他の異常は新modeで拒否する。
	if( queryError != ERROR_INSUFFICIENT_BUFFER) {
		// 欠損以外のAPI失敗を、診断を要求した呼出し側へ返す。
		if( error != nullptr && queryError != ERROR_WINHTTP_HEADER_NOT_FOUND) {
			*error =
				nativeErrorFromWin32( queryError == ERROR_SUCCESS ? ERROR_INVALID_DATA : queryError) ;
		}

		return 0U ;
	}

	std::array<wchar_t, 21> buffer{} ;	// uint64十進20桁と終端。応答長でheapを確保しない。
	// 巨大・奇数byte・空のheaderを固定bufferへ渡さない。
	if( characters < sizeof( wchar_t) || characters > sizeof( buffer) ||
	   characters % sizeof( wchar_t) != 0U) {
		// 不正な確保要求を新modeの明示的な拒否として残す。
		if( error != nullptr) {
			*error = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		return 0U ;
	}

	DWORD available = static_cast<DWORD>( sizeof( buffer)) ;	// 入力時は確保済みbyte数。
	// Header本体の失敗と不正な返却長を通常の長さへ変換しない。
	if( transport.queryHeaders( request, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX,
							  buffer.data(), &available, WINHTTP_NO_HEADER_INDEX) == FALSE) {
		const auto bodyError = GetLastError() ;	// 本文照会APIが返した診断を失わない。
		// 診断を求めた新modeだけを元のAPI失敗で停止する。
		if( error != nullptr) {
			*error =
				nativeErrorFromWin32( bodyError == ERROR_SUCCESS ? ERROR_INVALID_DATA : bodyError) ;
		}

		return 0U ;
	}

	// 成功応答でも確保容量外またはUTF-16として不正なbyte長を使用しない。
	if( available > sizeof( buffer) || available % sizeof( wchar_t) != 0U) {
		// 確保済みbuffer外の読取りを防いだ診断を返す。
		if( error != nullptr) {
			*error = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		return 0U ;
	}

	std::wstring_view value( buffer.data(),
							available / sizeof( wchar_t)) ;	// APIがcopyした範囲だけを解析する。
	// APIが含めた終端NULだけを末尾から除く。
	while( !value.empty() && value.back() == L'\0') {
		value.remove_suffix( 1U) ;
	}

	// 空headerは正しい明示0ではない。
	if( value.empty()) {
		// 数字のないheaderを不明長へ弱めない。
		if( error != nullptr) {
			*error = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		return 0U ;
	}

	std::uint64_t length{} ;	// 検証済み桁だけを加える十進値。
	// 各ASCII数字をoverflow検査付きで加算する。
	for( const auto character : value) {
		// 数字以外と次の十進加算でoverflowする値を拒否する。
		if( character < L'0' || character > L'9' ||
		   length > (std::numeric_limits<std::uint64_t>::max() -
					 static_cast<std::uint64_t>( character - L'0')) /
						10U) {
			// 数値として扱えない元headerを新modeで診断可能にする。
			if( error != nullptr) {
				*error = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			return 0U ;
		}

		length = length * 10U + static_cast<std::uint64_t>( character - L'0') ;
	}

	// 正しい十進値を確認した後にだけ明示0も既知長として扱う。
	if( declared != nullptr) {
		*declared = true ;
	}

	return length ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError checkCancellation(
	const HttpCancellationCallback &cancellationCallback) noexcept
{
	// 取消し callback がない場合は取消し要求なしとして継続する。
	if( !cancellationCallback) {
		return 0 ;
	}

	try {
		return cancellationCallback() ? nativeErrorFromWin32( ERROR_CANCELLED)
									  : static_cast<NativeError>( 0) ;
	} catch( ...) {
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief WinHTTP response bodyを上限付きで反復取得する。
 *
 * Content-Lengthと実受信量を別々に上限検証し、chunkを順序通りconsumerへ渡す。
 *
 * @param[in] request 応答受信開始済みrequest handle。
 * @param[in] maximumBytes 許可する総受信byte数。
 * @param[in] consumer 各受信chunkを処理する呼出し先。
 * @param[in] progressCallback 受信進捗通知先。
 * @param[in] cancellationCallback 空または取消し状態の確認先。
 * @param[in,out] execution 新modeの予算と協調停止。Nullは従来の受信契約。
 * @param[in] transport Handleを生成したI/O表。本呼出し中だけ借用する。
 * @param[in] strictContentLength trueなら宣言0と不正な長さも拒否する。
 * @param[in,out] indexControl 索引用途だけの共有期限と原byte課金です。
 * @param[in,out] collectorTransfer 収集専用の同readData実byte記録先です。
 * @return 全chunk処理成功時は0、失敗時はHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
template <typename Consumer>
[[nodiscard]] NativeError consumeResponse(
	const HINTERNET request, const std::uint64_t maximumBytes, Consumer &&consumer,
	const HttpDownloadProgressCallback &progressCallback,
	const HttpCancellationCallback	   &cancellationCallback,
	MetadataSearchExecutionContext	   *execution = nullptr,
	const OfficialHttpTransport		   &transport = NATIVE_HTTP_TRANSPORT,
	const bool strictContentLength = false, SignedIndexHttpControl *indexControl = nullptr,
	CollectorHttpTransferRecorder *collectorTransfer = nullptr)
{
	// ゼロの受信上限は有効な取得要求として受理しない。
	if( maximumBytes == 0) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	NativeError			lengthError{} ;		// 厳密modeで不正headerを拒否する診断。
	bool				declaredLength{} ;	// 明示0と長さ欠損を区別する。
	const std::uint64_t expected = queryContentLength(
		request, transport, execution != nullptr || strictContentLength ? &lengthError : nullptr,
		&declaredLength) ;	// 判明した総受信byte数。
	// 不正な宣言長を長さ不明へ変換して受信を続けない。
	if( lengthError != 0) {
		return lengthError ;
	}

	// 新modeでは宣言長も残予算へ照合し、未受信byteを消費へ加算しない。
	if( execution != nullptr) {
		const auto budgetError = execution->validateDeclaredBodyLength( expected) ;	// 早期拒否結果。
		// 申告本文長が残予算を超えた場合は受信を開始しない。
		if( budgetError != 0) {
			return budgetError ;
		}
	}

	// 宣言長が受信上限を超える応答は本文の取得前に拒否する。
	if( expected > maximumBytes) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
	}

	std::vector<std::byte> buffer( READ_BUFFER_BYTES) ;	// Heap上のWinHTTP受信buffer。
	std::uint64_t		   receivedTotal{} ;			// 現在までの実受信byte数。
	progressCallback( 0, expected) ;
	NativeError cancellationError =
		// Response取得前の取消し確認結果。
		checkCancellation( cancellationCallback) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( cancellationError != 0) {
		return cancellationError ;
	}

	// ResponseがEOFへ到達するまで利用可能chunkを有限sizeで処理する。
	while( true) {
		// Data照会前の取消し確認結果。
		cancellationError = checkCancellation( cancellationCallback) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( cancellationError != 0) {
			return cancellationError ;
		}

		DWORD			  available{} ;	// WinHTTPが現在読み取れると報告したbyte数。
		const NativeError queryTimeoutError =
			// 次APIの残期限。
			setRequestTimeouts( request, execution, false, transport, indexControl) ;
		// 同期照会へ入る前に最新の残期限を反映する。
		if( queryTimeoutError != 0) {
			return queryTimeoutError ;
		}

		// 受信可能量を照会できなければ通信失敗として中止する。
		if( transport.queryAvailable( request, &available) == FALSE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		// 収集の同期待機中取消しをEOF完了へ変換しません。
		if( collectorTransfer != nullptr) {
			cancellationError = checkCancellation( cancellationCallback) ;
			// 未完段階の予約はUNKNOWNのままにします。
			if( cancellationError != 0) {
				return cancellationError ;
			}
		}

		// 同期待機中の取消し・期限をEOF成功やcache保存へ読み替えない。
		if( execution != nullptr) {
			const auto stopped = execution->checkpoint() ;	// API復帰直後の停止確認。
			// 次の読取りや正常終端より停止を優先する。
			if( stopped != 0) {
				return stopped ;
			}
		}

		// 索引の待機後取消し・期限をEOF成功へ変換しません。
		if( indexControl != nullptr && indexControl->checkpoint() != 0) {
			return indexControl->stopped ;
		}

		// 受信可能な data がなくなった時点で応答本文の終端とする。
		if( available == 0) {
			break ;
		}

		DWORD remaining = available ;	// 現在available範囲で未取得のbyte数。
		// 一回のDataAvailable範囲を64 KiB以下のchunkへ分割して処理する。
		while( remaining != 0) {
			cancellationError =
				// Chunk読取り前の取消し確認結果。
				checkCancellation( cancellationCallback) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( cancellationError != 0) {
				return cancellationError ;
			}

			const DWORD requested =
				execution != nullptr
					? execution->readAllowance( std::min<DWORD>( remaining, READ_BUFFER_BYTES))
				: indexControl != nullptr ? static_cast<DWORD>( std::min<std::uint64_t>(
												std::min<DWORD>( remaining, READ_BUFFER_BYTES),
												maximumBytes - receivedTotal + 1U))
				: collectorTransfer != nullptr
					? static_cast<DWORD>( std::min<std::uint64_t>(
						  std::min<DWORD>( remaining, READ_BUFFER_BYTES),
						  std::min<std::uint64_t>( maximumBytes - receivedTotal, READ_BUFFER_BYTES) +
							  1U))
					: std::min<DWORD>( remaining,
									  READ_BUFFER_BYTES) ;	// 残予算とprobeに制限した要求量。
			// 取消し・期限後の0 byte要求を正常終端へ読み替えない。
			if( requested == 0U) {
				return execution != nullptr ? execution->checkpoint()
											: static_cast<NativeError>( E_UNEXPECTED) ;
			}

			DWORD			  received{} ;	// 今回WinHttpReadDataが返したbyte数。
			const NativeError readTimeoutError =
				// 本文待機の残期限。
				setRequestTimeouts( request, execution, false, transport, indexControl) ;
			// Chunkごとに期限・取消しを再確認する。
			if( readTimeoutError != 0) {
				return readTimeoutError ;
			}

			// 本文の読取りが失敗した場合は Windows の診断値を返す。
			if( transport.readData( request, buffer.data(), requested, &received) == FALSE) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			// 保存拒否・取消し・cap超過でも、APIが返した本文実数を失いません。
			if( collectorTransfer != nullptr) {
				collectorTransfer->read( received) ;
			}

			// 索引の実受信probeも課金し、停止後はconsumerへ渡しません。
			if( indexControl != nullptr) {
				indexControl->receivedBytes += received ;
				// API待機中の取消しや期限を原byte発行へ変えません。
				if( indexControl->checkpoint() != 0) {
					return indexControl->stopped ;
				}
			}

			// Backendが要求量を超えたと報告した場合はspanや残量計算へ使用しない。
			if( received > requested) {
				return nativeErrorFromWin32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
			}

			// 保存前に失敗分も含めて消費し、超過probeをconsumerへ渡さない。
			if( execution != nullptr) {
				const NativeError budgetError = execution->consumeBytes( received) ;	// 実読取り消費。
				// 失敗byteも消費へ残し、本文とprobeをconsumerへ渡さない。
				if( budgetError != 0) {
					return budgetError ;
				}
			}

			// 受信可能とされた data を読み取れない応答は不正として拒否する。
			if( received == 0) {
				return static_cast<NativeError>(
					HRESULT_FROM_WIN32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE)) ;
			}

			// 加算の overflow を避けつつ、累積受信量が上限内に収まることを確認する。
			if( received > maximumBytes || receivedTotal > maximumBytes - received) {
				return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
			}

			cancellationError =
				// Chunk保存前の取消し確認結果。
				checkCancellation( cancellationCallback) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( cancellationError != 0) {
				return cancellationError ;
			}

			const NativeError consumeError =	// Consumerによる保存または蓄積結果。
				consumer( std::span<const std::byte>( buffer.data(), received)) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( consumeError != 0) {
				return consumeError ;
			}

			receivedTotal += received ;
			remaining -= received ;
			progressCallback( receivedTotal, expected) ;
		}
	}

	// 有効な宣言長がある場合は累積受信量との完全一致を必須とする。
	if( (expected != 0 || ((execution != nullptr || strictContentLength) && declaredLength)) &&
	   receivedTotal != expected) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_HANDLE_EOF)) ;
	}

	// 空の応答本文は有効な取得結果として返さない。
	if( receivedTotal == 0) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief ResponseのETagを条件付きrequest用に取得する。
 *
 * Cache最適化専用の任意値として扱い、取得失敗はrequest失敗にしない。CR/LF等は保存せずheader injectionを防止する。
 *
 * @param[in] request 応答受信開始済みrequest handle。
 * @param[in] transport Handleを生成したI/O表。本呼出し中だけ借用する。
 * @return 512文字以内のvisible ASCII ETag。欠落または不正時は空。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring queryEtag( const HINTERNET			  request,
									 const OfficialHttpTransport &transport = NATIVE_HTTP_TRANSPORT)
{
	DWORD bytes{} ;	// ETag文字列に必要なUTF-16 byte数。
	transport.queryHeaders( request, WINHTTP_QUERY_ETAG, WINHTTP_HEADER_NAME_BY_INDEX,
						   WINHTTP_NO_OUTPUT_BUFFER, &bytes, WINHTTP_NO_HEADER_INDEX) ;
	// ETag の長さ照会失敗と上限超過では条件付き取得情報を返さない。
	if( GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes < sizeof( wchar_t) ||
	   bytes > (MAXIMUM_ETAG_CHARACTERS + 1U) * sizeof( wchar_t)) {
		return {} ;
	}

	std::wstring etag( bytes / sizeof( wchar_t), L'\0') ;	// Header受信buffer。
	// ETag 本体を取得できなければ空値を返して再利用しない。
	if( transport.queryHeaders( request, WINHTTP_QUERY_ETAG, WINHTTP_HEADER_NAME_BY_INDEX,
							  etag.data(), &bytes, WINHTTP_NO_HEADER_INDEX) == FALSE) {
		return {} ;
	}

	etag.resize( bytes / sizeof( wchar_t)) ;
	// ETag の末尾から API が付加した終端 NUL だけを除く。
	while( !etag.empty() && etag.back() == L'\0') {
		etag.pop_back() ;
	}

	const bool safe =	// 条件付きrequestへ再利用できるvisible ASCIIだけならtrue。
		etag.size() <= MAXIMUM_ETAG_CHARACTERS &&
		std::all_of( etag.begin(), etag.end(),
					[]( const wchar_t character) { return character >= 0x20 && character <= 0x7e ; }) ;
	return safe ? etag : std::wstring{} ;
}

//------------------------------------------------------------------------------
/**
 * @brief UTF-8 bodyをNULなしUTF-16へ変換する。
 *
 * GETとPOSTで同じBOM、encoding、NUL拒否境界を使用する。
 *
 * @param[in] bytes 上限確認済みのresponse body。
 * @param[out] text 成功時のUTF-16 text。失敗時は空。
 * @return 厳密なUTF-8変換成功時は0、空または不正時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError decodeUtf8Body( const std::span<const std::byte> bytes, std::wstring &text)
{
	text.clear() ;
	std::size_t offset{} ;	// 任意UTF-8 BOMを除いた本文先頭byte位置。
	// UTF-8 BOM がある本文では BOM を除いた内容を変換する。
	if( bytes.size() >= 3U && bytes[0] == static_cast<std::byte>( 0xefU) &&
	   bytes[1] == static_cast<std::byte>( 0xbbU) && bytes[2] == static_cast<std::byte>( 0xbfU)) {
		offset = 3U ;
	}

	const std::size_t inputBytes = bytes.size() - offset ;	// UTF-8変換対象byte数。
	// 空の本文と文字列変換 API の長さ上限を超える入力は拒否する。
	if( inputBytes == 0U || inputBytes > static_cast<std::size_t>( std::numeric_limits<int>::max())) {
		return static_cast<NativeError>(
			HRESULT_FROM_WIN32( inputBytes == 0U ? ERROR_INVALID_DATA : ERROR_FILE_TOO_LARGE)) ;
	}

	// Win32 APIがbyte列をchar pointerとして要求する境界に限り型を読み替える。
	const auto *const utf8 =
		reinterpret_cast<const char *>( bytes.data() + offset) ;	// 読み取り専用変換入力。
	const int required =											// 厳密なUTF-8からUTF-16への変換に必要な文字数。
		MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, utf8, static_cast<int>( inputBytes),
							nullptr, 0) ;
	// UTF-8 検証または出力文字数の照会に失敗した場合は中止する。
	if( required <= 0) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	std::wstring decoded( static_cast<std::size_t>( required), L'\0') ;	// UTF-16変換先。
	// 照会した文字数どおりに UTF-16 へ変換できなければ受理しない。
	if( MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, utf8, static_cast<int>( inputBytes),
						   decoded.data(), required) != required) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 埋込み NUL を含む本文は後続 parser での切詰めを避けるため拒否する。
	if( decoded.find( L'\0') != std::wstring::npos) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
	}

	text = std::move( decoded) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式catalog本文をcacheとETag再検証付きで取得する。
 *
 * Fresh cacheはhash検証後に返す。Stale cacheはETagがある場合だけ条件付きrequestを行い、network失敗時は再利用しない。非cache modeでも全URL・
 * TLS・応答上限を同じ経路で検証する。
 *
 * @param[in] url 公式catalogの絶対HTTPS URL。
 * @param[in] useCatalogCache falseならcacheを読み書きしない。
 * @param[in] allowedHosts 公式host allowlist。
 * @param[in] maximumRedirects 許可するredirect回数。
 * @param[in] maximumBytes 応答body上限byte数。
 * @param[in] progressCallback 受信進捗通知先。
 * @param[out] content 成功時の空ではない本文。
 * @param[out] originPolicyIndices 成功時のopaque origin経路。
 * @param[out] observation 成功時に実利用したnetwork／cache経路とUTC。
 * @param[in,out] execution 新modeの返却しない本文・送信予算。Nullは従来経路。
 * @param[in] transport 同期HTTP処理中に借用する生成元I/O表。
 * @param[in] cacheAccess Null以外ではcache処理を全て注入先へ委譲し、既定cacheと混用しない。
 * @return 取得成功時は0、URL、HTTP、size失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError fetchCatalogResource(
	const bool useCatalogCache, const std::wstring_view url,
	const std::span<const std::wstring_view> allowedHosts, const std::uint32_t maximumRedirects,
	const std::uint64_t maximumBytes, const HttpDownloadProgressCallback &progressCallback,
	std::vector<std::byte> &content, std::vector<std::uint32_t> &originPolicyIndices,
	OfficialHttpAcquisitionObservation &observation,
	MetadataSearchExecutionContext	   *execution	= nullptr,
	const OfficialHttpTransport		   &transport	= NATIVE_HTTP_TRANSPORT,
	const OfficialHttpCacheAccess	   *cacheAccess = nullptr)
{
	content.clear() ;
	originPolicyIndices.clear() ;
	observation = {} ;
	// Redirect 上限、取得上限、必須進捗 callback が不正なら取得を開始しない。
	if( maximumRedirects > MAXIMUM_REDIRECTS || maximumBytes == 0 || !progressCallback) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	ParsedUrl		  parsed ;													// Networkまたはcache使用前に検証するURL component。
	const NativeError parseError = parseHttpsUrl( url, allowedHosts, parsed) ;	// URL検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( parseError != 0) {
		return parseError ;
	}

	originPolicyIndices.push_back( parsed.originPolicyIndex) ;

	OfficialCatalogCache cache ;		// ProgramData内の管理者保護catalog cache。
	CatalogCacheEntry	 cached ;		// Cache照会結果。
	const NativeError	 cacheError =	// Cacheは可用性最適化でありnetworkの代替正本ではない。
		   useCatalogCache
			   ? (cacheAccess != nullptr
					  ? cacheAccess->load( url, maximumBytes, CATALOG_MAXIMUM_AGE_SECONDS, cached)
					  : cache.load( url, maximumBytes, CATALOG_MAXIMUM_AGE_SECONDS, cached))
			   : 0 ;
	// 新modeは破損cacheから自動でnetworkを再取得しない。
	if( execution != nullptr &&
	   (cacheError != 0 || cached.state == CatalogCacheState::INVALIDATED)) {
		return cacheError != 0 ? cacheError
							   : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
	}

	// 有効期間内の cache が正常に読めた場合だけ、その本文を取得結果に使う。
	if( cacheError == 0 && cached.state == CatalogCacheState::FRESH) {
		const auto budgetError =
			// Cache本文の消費。
			chargeCachedMetadata( execution, cached.content.size()) ;
		// 取消しや予算停止したcache本文を成功として公開しない。
		if( budgetError != 0) {
			return budgetError ;
		}

		progressCallback( cached.content.size(), cached.content.size()) ;
		content		= std::move( cached.content) ;
		observation = {.acquisition				  = MeasurementAcquisition::FRESH_CACHE,
					   .originValidatedUtcSeconds = cached.validatedUtcSeconds,
					   .cachePermitted			  = true} ;
		return 0 ;
	}

	const std::wstring conditionalEtag =	// Staleで検証済みETagがある場合だけ送信する値。
		cacheError == 0 && cached.state == CatalogCacheState::STALE ? cached.etag : std::wstring{} ;

	InternetHandle	  session( nullptr) ;		// Requestと同じ期間保持するsession handle。
	InternetHandle	  connection( nullptr) ;	// Requestと同じ期間保持するconnection handle。
	InternetHandle	  request( nullptr) ;		// Response bodyを読み取るrequest handle。
	DWORD			  status{} ;				// 許可済みHTTP response status。
	const NativeError requestError =			// 条件付きまたは通常GETとredirect追跡結果。
		openGetRequestFollowingRedirects( url, allowedHosts, maximumRedirects, conditionalEtag, {},
										 session, connection, request, status, originPolicyIndices,
										 execution, transport) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( requestError != 0) {
		return requestError ;
	}

	// Not Modified 応答では再検証対象の cache 本文を確認して再利用する。
	if( status == HTTP_STATUS_NOT_MODIFIED) {
		// 対応する stale 本文がない 304 応答は正常な再検証として受理しない。
		if( cached.state != CatalogCacheState::STALE || cached.content.empty()) {
			// Cache 使用が有効な場合だけ不整合な保存済み項目を破棄する。
			if( useCatalogCache) {
				// 非cache試験では既存cacheを変更しない。
				// 注入cacheと既定cacheを同じrunで混用しない。
				if( cacheAccess != nullptr) {
					cacheAccess->discard( url) ;
				} else {
					cache.discard( url) ;
				}
			}

			return static_cast<NativeError>(
				HRESULT_FROM_WIN32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE)) ;
		}

		const auto budgetError =
			// 304でも本文は一回だけ。
			chargeCachedMetadata( execution, cached.content.size()) ;
		// 304でも今回の本文予算に入らないcacheを成功へ変換しない。
		if( budgetError != 0) {
			return budgetError ;
		}

		progressCallback( cached.content.size(), cached.content.size()) ;
		// 304はoriginによる再検証成功なので時刻を更新する。保存失敗でも今回本文は検証済みである。
		static_cast<void>( cacheAccess != nullptr
							  ? cacheAccess->store( url, cached.content, conditionalEtag)
							  : cache.store( url, cached.content, conditionalEtag)) ;
		content		= std::move( cached.content) ;
		observation = {.acquisition				  = MeasurementAcquisition::REVALIDATED_CACHE,
					   .originValidatedUtcSeconds = currentUtcSeconds(),
					   .cachePermitted			  = true} ;
		return 0 ;
	}

	const std::wstring responseEtag = queryEtag( request.get(), transport) ;	// 任意のresponse ETag。
	std::vector<std::byte> received ;											// 上限内で蓄積するnetwork response body。
	const std::uint64_t	   expected =
		// Reserve用Content-Length。
		queryContentLength( request.get(), transport) ;
	// 宣言長が取得上限と address 空間内に収まる場合だけ先行確保する。
	if( expected <= maximumBytes && expected <= std::numeric_limits<std::size_t>::max()) {
		received.reserve( static_cast<std::size_t>( expected)) ;
	}

	// 応答bodyの有限受信結果。蓄積先参照は同期callback中だけ借用する。
	const NativeError receiveError = consumeResponse(
		request.get(), maximumBytes,
		[&received]( const std::span<const std::byte> chunk) {
			received.insert( received.end(), chunk.begin(), chunk.end()) ;
			return static_cast<NativeError>( 0) ;
		},
		progressCallback, {}, execution, transport) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( receiveError != 0) {
		return receiveError ;
	}

	// 現行cache形式は最終origin経路を保持しないため、redirect済み本文は再利用しない。
	if( useCatalogCache && originPolicyIndices.size() == 1U) {
		// Cache保存失敗は検証済みnetwork応答を失敗へ変えず、次回再取得で回復させる。
		static_cast<void>( cacheAccess != nullptr ? cacheAccess->store( url, received, responseEtag)
												 : cache.store( url, received, responseEtag)) ;
	}

	content		= std::move( received) ;
	observation = networkObservation( useCatalogCache) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定form POSTで公式metadataを取得する。
 *
 * POST応答をcacheせず、一つの検証済みoriginだけを記録する。
 *
 * @param[in] url 固定metadata endpointの絶対HTTPS URL。
 * @param[in] allowedHosts 完全一致の公式委譲host群。
 * @param[in] formBody 検証するASCII form body。
 * @param[in] maximumBytes 応答body上限byte数。
 * @param[out] content 成功時の空でないresponse body。
 * @param[out] originPolicyIndices 成功時のopaque origin経路。
 * @param[out] observation 成功時のnetwork本文取得経路とUTC。
 * @return HTTP 200の有限body取得時は0、失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError fetchPostFormResource(
	const std::wstring_view url, const std::span<const std::wstring_view> allowedHosts,
	const std::string_view formBody, const std::uint64_t maximumBytes,
	std::vector<std::byte> &content, std::vector<std::uint32_t> &originPolicyIndices,
	OfficialHttpAcquisitionObservation &observation)
{
	content.clear() ;
	originPolicyIndices.clear() ;
	observation = {} ;
	// 不正上限またはbodyでは接続しない。
	if( maximumBytes == 0U || !isValidFormBody( formBody)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	ParsedUrl		  parsed ;													// 接続前に検証する固定POST endpoint component。
	const NativeError parseError = parseHttpsUrl( url, allowedHosts, parsed) ;	// URL検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( parseError != 0) {
		return parseError ;
	}

	originPolicyIndices.push_back( parsed.originPolicyIndex) ;
	InternetHandle	  session( nullptr) ;		// Requestと同じ期間保持するsession handle。
	InternetHandle	  connection( nullptr) ;	// Requestと同じ期間保持するconnection handle。
	InternetHandle	  request( nullptr) ;		// Response bodyを読み取るrequest handle。
	const NativeError requestError =
		// POST受信結果。
		openPostFormRequest( parsed, formBody, session, connection, request) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( requestError != 0) {
		return requestError ;
	}

	std::vector<std::byte> received ;									// 上限内で蓄積するPOST response body。
	const std::uint64_t expected = queryContentLength( request.get()) ;	// Reserve用Content-Length。
	// POST 応答の宣言長が許可範囲内の場合だけ buffer を先行確保する。
	if( expected <= maximumBytes && expected <= std::numeric_limits<std::size_t>::max()) {
		received.reserve( static_cast<std::size_t>( expected)) ;
	}

	const NativeError receiveError = consumeResponse(
		request.get(), maximumBytes,
		[&received]( const std::span<const std::byte> chunk) {
			received.insert( received.end(), chunk.begin(), chunk.end()) ;
			return static_cast<NativeError>( 0) ;
		},
		[]( const std::uint64_t, const std::uint64_t) {}, {}) ;	// 有限body取得結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( receiveError != 0) {
		return receiveError ;
	}

	content		= std::move( received) ;
	observation = networkObservation( false) ;
	return 0 ;
}

/** @brief 新modeだけの所有handleとAPI前後の制御です。旧RAIIは変更しません。 */
class ControlledCollectorRequest final {
public:
	/** @brief 同期worker内で依存を借用します。
	 * @param[in] api 完全なWinHTTP依存表。
	 * @param[in,out] control 同じworkerの制御。
	 */
	ControlledCollectorRequest( const OfficialHttpTransport	&api,
							   OfficialCollectorHttpControl &control)
		: api_( api), control_( control)
	{
	}
	/** @brief 例外時も所有者threadで残handleを解放します。 */
	~ControlledCollectorRequest()
	{
		close() ;
	}
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	ControlledCollectorRequest( const ControlledCollectorRequest &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	ControlledCollectorRequest &operator=( const ControlledCollectorRequest &) = delete ;
	/** @brief 公式検証済みcomponentへ一度だけGETを送ります。
	 * @param[in] parsed 共通parserで検証済みURL。
	 * @param[in] tag 検証済み条件付きETag。
	 * @return 応答受信開始に成功した場合true。
	 */
	bool						open( const ParsedUrl &parsed, std::wstring_view tag)
	{
		// Handleを作る前にも停止と期限を検査する。
		if( !checkpoint( CollectorIoStage::OPEN)) {
			return false ;
		}

		session_			  = api_.open( HTTP_USER_AGENT, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
										  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0) ;
		const DWORD openError = session_ == nullptr ? GetLastError() : 0U ;	// API直後の原値。
		// Session失敗ではconnectionを作らない。
		if( session_ == nullptr) {
			nativeFailure( openError, CollectorIoStage::OPEN) ;
			return false ;
		}

		control_.setNativeReleased( false) ;
		// 接続前にsessionの全phaseを有限化する。
		if( !ready( session_, CollectorIoStage::OPEN)) {
			return false ;
		}

		connection_				 = api_.connect( session_, parsed.host.c_str(), parsed.port, 0) ;
		const DWORD connectError = connection_ == nullptr ? GetLastError() : 0U ;	// 原接続error。
		// 取得したsessionだけを後始末する。
		if( connection_ == nullptr) {
			nativeFailure( connectError, CollectorIoStage::OPEN) ;
			return false ;
		}

		// Request作成前に同期API復帰中の停止を確認する。
		if( !ready( session_, CollectorIoStage::OPEN)) {
			return false ;
		}

		request_ =
			api_.openRequest( connection_, L"GET", parsed.pathQuery.c_str(), nullptr,
							 WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) ;
		const DWORD requestError = request_ == nullptr ? GetLastError() : 0U ;	// 原生成error。
		// Null handleでoption設定しない。
		if( request_ == nullptr) {
			nativeFailure( requestError, CollectorIoStage::OPEN) ;
			return false ;
		}

		DWORD redirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER ;		// 自動追跡0。
		DWORD logon	   = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH ;	// 自動資格情報禁止。
		DWORD disabled = WINHTTP_DISABLE_COOKIES ;					// Cookieの送受信禁止。
		// 設定失敗を条件緩和へ読み替えない。各呼出しに期限確認を行う。
		if( !option( WINHTTP_OPTION_REDIRECT_POLICY, redirect) ||
		   !option( WINHTTP_OPTION_AUTOLOGON_POLICY, logon) ||
		   !option( WINHTTP_OPTION_DISABLE_FEATURE, disabled) ||
		   !header( L"Cache-Control: no-cache\r\n") ||
		   !header(
			   L"Accept: application/json, application/xml, text/xml, application/octet-stream, */*\r\n")) {
			return false ;
		}

		// 条件付きheaderは共通validatorに合格した場合だけ設定する。
		if( !tag.empty() && !header( L"If-None-Match: " + std::wstring( tag) + L"\r\n",
								   WINHTTP_ADDREQ_FLAG_ADD_IF_NEW)) {
			return false ;
		}

		// Timeout設定はSEND確定より先に行う。SEND開始を二度宣言しない。
		if( !ready( request_, CollectorIoStage::OPEN) ||
		   control_.begin( CollectorIoStage::SEND, SEND_TIMEOUT_MILLISECONDS) == 0U ||
		   !control_.noteSendCall()) {
			return false ;
		}

		const BOOL sent =
			api_.sendRequest( request_, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0,
							 0, 0) ;							// 明示送信はこの一箇所・最大一回。
		const DWORD sendError = sent ? 0U : GetLastError() ;	// 直後の原値。
		// ERROR_WINHTTP_RESEND_REQUEST等も再送しない。
		if( !sent) {
			nativeFailure( sendError, CollectorIoStage::SEND, true) ;
			return false ;
		}

		// 送信復帰後の停止を応答待機へ進む前に受理する。
		if( !ready( request_, CollectorIoStage::RECEIVE)) {
			return false ;
		}

		const BOOL	received	 = api_.receiveResponse( request_, nullptr) ;	// 同期応答待機。
		const DWORD receiveError = received ? 0U : GetLastError() ;				// 他API前の原値。
		// 応答待機失敗時は本文全量を未知として扱う。
		if( !received) {
			nativeFailure( receiveError, CollectorIoStage::RECEIVE, true) ;
			return false ;
		}

		return checkpoint( CollectorIoStage::HEADERS) ;
	}
	/** @brief Statusまたは有限文字列headerを同じ制御で照会します。
	 * @param[in] query WinHTTPの固定query値。
	 * @param[out] buffer 借用buffer。長さprobeではnull。
	 * @param[in,out] bytes Buffer容量と実長。
	 * @param[in,out] index 同名header位置。Statusではnull。
	 * @return API成否。期待される欠損・容量照会は終端にしません。
	 */
	BOOL queryHeader( DWORD query, void *buffer, DWORD *bytes, DWORD *index)
	{
		// Header APIにも正数の残期限を設定する。
		if( !ready( request_, CollectorIoStage::HEADERS)) {
			SetLastError( ERROR_OPERATION_ABORTED) ;
			return FALSE ;
		}

		const BOOL	success = api_.queryHeaders( request_, query, WINHTTP_HEADER_NAME_BY_INDEX,
												buffer, bytes, index) ;	// Header照会。
		const DWORD error	= success ? 0U : GetLastError() ;			// 期待errorも先に保存。
		// 長さprobeだけに二種類の非終端errorを許す。Status・実値読取りの失敗は原値を残す。
		const bool	expectedProbe =
			buffer == nullptr && (query & WINHTTP_QUERY_FLAG_NUMBER) == 0U &&
			(error == ERROR_INSUFFICIENT_BUFFER || error == ERROR_WINHTTP_HEADER_NOT_FOUND) ;
		// 本照会失敗をheader欠損へ変えて成功させない。
		if( !success && !expectedProbe) {
			nativeFailure( error, CollectorIoStage::HEADERS) ;
		}

		// 途中取消しで読み取れたheaderを有効根拠にしない。
		const bool running = checkpoint( CollectorIoStage::HEADERS) ;	// 同期復帰後の再確認。
		SetLastError( error) ;
		return running ? success : FALSE ;
	}
	/** @brief 残予算を超えない要求で本文を厳密に受信します。
	 * @param[in] maximum 予約に結合した本文上限。
	 * @param[in] expected 厳密Content-Length。ない場合はnull。
	 * @param[out] bytes 成功readだけのraw byte列。
	 * @return 完全な本文の場合true。上限外probeはしません。
	 */
	bool body( std::uint64_t maximum, std::optional<std::uint64_t> expected,
			  std::vector<std::byte> &bytes)
	{
		std::vector<std::byte> buffer(
			READ_BUFFER_BYTES) ;	// 同じ有限容量をゼロ初期化し、呼出し中だけ所有する。
		// 全体期限を毎回確認し、EOFまたは厳密長まで反復する。
		for( ;;) {
			// 正当な長さによる区切りが成立すれば追加probeは不要。
			if( expected && bytes.size() == *expected) {
				return true ;
			}

			// Queryは残0でも超過／未確認を区別するため一度だけ行う。
			if( !ready( request_, CollectorIoStage::QUERY)) {
				return false ;
			}

			DWORD		available{} ;												// APIが返す現在の本文可用量。
			const BOOL	queried	   = api_.queryAvailable( request_, &available) ;	// 同期query。
			const DWORD queryError = queried ? 0U : GetLastError() ;				// 原値を先に保存。
			// Query失敗は既知下限を残して全量を未知へ変更する。
			if( !queried) {
				nativeFailure( queryError, CollectorIoStage::QUERY, true) ;
				return false ;
			}

			// Query0をここでEOF扱いにしない。
			if( !checkpoint( CollectorIoStage::QUERY)) {
				return false ;
			}

			const auto remaining = maximum - bytes.size() ;	// 計数済み受信を引いた上限。
			// 上限外の一byte読取りを行わず、超過と未確認を区別する。
			if( remaining == 0U) {
				reject( available != 0U ? CollectorIoCause::BODY_LIMIT
									   : CollectorIoCause::BODY_INCOMPLETE,
					   available != 0U ? ERROR_FILE_TOO_LARGE : ERROR_HANDLE_EOF,
					   CollectorIoStage::QUERY) ;
				return false ;
			}

			// WinHTTPの本文区切りと異なる可用量は曖昧な長さとして拒否する。
			if( expected && available > *expected - bytes.size()) {
				reject( CollectorIoCause::BODY_INCOMPLETE, ERROR_INVALID_DATA,
					   CollectorIoStage::QUERY) ;
				return false ;
			}

			const DWORD requested = static_cast<DWORD>( std::min<std::uint64_t>(
				std::min<DWORD>( available == 0U ? READ_BUFFER_BYTES : available, READ_BUFFER_BYTES),
				remaining)) ;	// 正数かつ残予算以下。
			// 読取り直前にも残期限を反映する。
			if( !ready( request_, CollectorIoStage::READ)) {
				return false ;
			}

			DWORD		count{} ;	// 成功APIの実受信量。
			// 成功readの計数より前に保持するAPI成否。
			const BOOL	read	  = api_.readData( request_, buffer.data(), requested, &count) ;
			const DWORD readError = read ? 0U : GetLastError() ;	// 他APIより先の保存。
			// 失敗readの出力countを成功受信量へ合算しない。
			if( !read) {
				nativeFailure( readError, CollectorIoStage::READ, true) ;
				return false ;
			}

			// 成功readは取消し・consumerより先に計数する。
			if( !control_.noteRead( requested, count) || !checkpoint( CollectorIoStage::READ)) {
				return false ;
			}

			// 正数要求に対する成功0だけをEOFとする。
			if( expected && count > *expected - bytes.size()) {
				reject( CollectorIoCause::BODY_INCOMPLETE, ERROR_INVALID_DATA,
					   CollectorIoStage::READ) ;
				return false ;
			}

			// 正数要求の成功0だけを本文の終端根拠にする。
			if( count == 0U) {
				// 明示長より短い本文を正常終端にしない。
				if( expected && bytes.size() != *expected) {
					reject( CollectorIoCause::BODY_INCOMPLETE, ERROR_HANDLE_EOF,
						   CollectorIoStage::READ) ;
					return false ;
				}

				return true ;
			}

			bytes.insert( bytes.end(), buffer.begin(), buffer.begin() + count) ;
		}
	}
	/** @brief 全handleを一回ずつ所有者が解放します。繰返し呼出しは何もしません。 */
	void close()
	{
		bool released = control_.snapshot().nativeReleased ;	// DNS解放失敗を覆さない。
		// 所有handleがあれば全解放の結果をここで観測する。
		if( request_ != nullptr || connection_ != nullptr || session_ != nullptr) {
			released = true ;
		}

		// Requestからsessionへ親子順に一度だけ閉じる。
		for( auto *slot : {&request_, &connection_, &session_}) {
			HINTERNET handle = std::exchange( *slot, nullptr) ;	// 再解放を禁止する所有権移動。
			// 未生成handleをAPIへ渡さない。
			if( handle == nullptr) {
				continue ;
			}

			const BOOL	closed = api_.closeHandle( handle) ;	// 同じ生成元APIで所有者解放。
			const DWORD error  = closed ? 0U : GetLastError() ;	// Close後の原値。
			// 解放失敗を正常完了へ変換しない。追加retryもしない。
			if( !closed) {
				released = false ;
				control_.fail(
					CollectorIoCause::SETUP,
					{CollectorIoErrorDomain::WIN32_ERROR, error, CollectorIoStage::CLEANUP}, false) ;
			}
		}

		control_.setNativeReleased( released) ;
	}
	/** @brief Native errorでない有限拒否理由を設定します。
	 * @param[in] cause 終端原因。
	 * @param[in] code 固定分類code。
	 * @param[in] stage 検出段階。
	 */
	void reject( CollectorIoCause cause, DWORD code, CollectorIoStage stage)
	{
		control_.fail( cause, {CollectorIoErrorDomain::PARSER, code, stage}, false) ;
	}

private:
	/** @brief 停止・二clockを確認します。
	 * @param[in] stage API境界。
	 * @return 続行可能ならtrue。
	 */
	bool checkpoint( CollectorIoStage stage)
	{
		return control_.begin( stage, RECEIVE_TIMEOUT_MILLISECONDS) != 0U ;
	}
	/** @brief 残時間を全phaseへclampします。
	 * @param[in] handle Sessionまたはrequest。
	 * @param[in] stage 次API段階。
	 * @return 正数timeout設定・後検査が成功した場合true。
	 */
	bool ready( HINTERNET handle, CollectorIoStage stage)
	{
		const auto remaining = control_.begin( stage, RECEIVE_TIMEOUT_MILLISECONDS) ;	// 残ms。
		// 0 timeoutをOSへ渡さない。
		if( remaining == 0U) {
			return false ;
		}

		// 後続APIで元errorを失わないための成否。
		const BOOL success = api_.setTimeouts(
			handle, static_cast<int>( std::min<DWORD>( remaining, RESOLVE_TIMEOUT_MILLISECONDS)),
			static_cast<int>( std::min<DWORD>( remaining, CONNECT_TIMEOUT_MILLISECONDS)),
			static_cast<int>( std::min<DWORD>( remaining, SEND_TIMEOUT_MILLISECONDS)),
			static_cast<int>( std::min<DWORD>( remaining, RECEIVE_TIMEOUT_MILLISECONDS))) ;
		const DWORD error = success ? 0U : GetLastError() ;	// 設定失敗の原値。
		// Timeout設定失敗では対象APIを呼ばない。
		if( !success) {
			nativeFailure( error, stage) ;
			return false ;
		}

		return checkpoint( stage) ;
	}
	/** @brief 固定DWORD optionを設定します。
	 * @param[in] optionId 固定option番号。
	 * @param[in] value 設定する値。
	 * @return 設定できた場合true。
	 */
	bool option( DWORD optionId, DWORD value)
	{
		// Option設定も前後で停止を確認する。
		if( !ready( request_, CollectorIoStage::OPEN)) {
			return false ;
		}

		// 後続APIで元errorを失わないための成否。
		const BOOL	success = api_.setOption( request_, optionId, &value, sizeof( value)) ;
		const DWORD error	= success ? 0U : GetLastError() ;	// 設定の原値。
		// 失敗したoptionを省略して通信を続けない。
		if( !success) {
			nativeFailure( error, CollectorIoStage::OPEN) ;
			return false ;
		}

		return checkpoint( CollectorIoStage::OPEN) ;
	}
	/** @brief 固定headerを設定します。
	 * @param[in] value 検証済みASCII header。
	 * @param[in] flags 固定追加方式。
	 * @return 設定成功ならtrue。
	 */
	bool header( std::wstring_view value,
				DWORD			  flags = WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE)
	{
		// Header追加前の有限待機と停止確認。
		if( !ready( request_, CollectorIoStage::OPEN)) {
			return false ;
		}

		// 後続APIで元errorを失わないための成否。
		const BOOL success =
			api_.addHeaders( request_, value.data(), static_cast<DWORD>( value.size()), flags) ;
		const DWORD error = success ? 0U : GetLastError() ;	// 元code。
		// 設定失敗で異なるrequestを送らない。
		if( !success) {
			nativeFailure( error, CollectorIoStage::OPEN) ;
			return false ;
		}

		return checkpoint( CollectorIoStage::OPEN) ;
	}
	/** @brief API原値を分類と副診断に保持します。
	 * @param[in] error 直後のGetLastError。
	 * @param[in] stage 失敗API段階。
	 * @param[in] unknown 本文全量が未知ならtrue。
	 */
	void nativeFailure( DWORD error, CollectorIoStage stage, bool unknown = false)
	{
		control_.fail( CollectorIoCause::HTTP, {CollectorIoErrorDomain::WIN32_ERROR, error, stage},
					  unknown) ;
	}
	/// 同scope中だけ借用する完全API表。
	const OfficialHttpTransport	 &api_ ;
	/// 同scope中だけ借用する台帳非依存interface。
	OfficialCollectorHttpControl &control_ ;
	/// 所有session。Nullは未生成または解放済み。
	HINTERNET					  session_{} ;
	/// 所有connection。
	HINTERNET					  connection_{} ;
	/// 所有request。
	HINTERNET					  request_{} ;
} ;

/** @brief 重複を含む有限headerを結合し、欠損と読取り失敗を区別します。
 * @param[in] request 旧callerの所有外handle。Controlled使用時はnullを許します。
 * @param[in] query 固定WinHTTP query値。
 * @param[in] transport Handleを生成した完全I/O表。
 * @param[out] present 非nullならheader存在を返します。
 * @param[in,out] controlled 新modeの制御。Nullは旧callerと同じ照会です。
 * @return 正常な有限文字列、欠損は空文字、不正または失敗はnullopt。
 */
[[nodiscard]] std::optional<std::wstring> collectorHeader(
	const HINTERNET request, const DWORD query, const OfficialHttpTransport &transport,
	bool *present = nullptr, ControlledCollectorRequest *controlled = nullptr)
{
	// 欠損と存在する空headerを呼出し元が区別できるようにする。
	if( present != nullptr) {
		*present = false ;
	}

	std::wstring combined ;	// 最大2048文字のheader群。
	DWORD		 index{} ;	// WinHTTPが更新する同名header位置。
	// 重複headerも有限件数ですべて検証する。
	for( unsigned count = 0U; count < 8U; ++count) {
		DWORD probeIndex = index ;	// 長さ照会で元位置を消費しない。
		DWORD bytes{} ;				// 終端を含むbyte長。
		// 新modeだけ各APIへ期限と原errorの制御を通す。旧callerの照会は不変。
		if( controlled != nullptr) {
			controlled->queryHeader( query, nullptr, &bytes, &probeIndex) ;
		} else {
			transport.queryHeaders( request, query, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &bytes,
								   &probeIndex) ;
		}

		const DWORD error = GetLastError() ;	// 長さ照会の元診断。
		// 欠損は空、または全同名header読取り完了を意味する。
		if( error == ERROR_WINHTTP_HEADER_NOT_FOUND) {
			return combined ;
		}

		// 不正長や不明な応答を再検証へ使用しない。
		if( error != ERROR_INSUFFICIENT_BUFFER || bytes < 2U || bytes > 4098U || bytes % 2U != 0U) {
			return std::nullopt ;
		}

		std::wstring value( bytes / sizeof( wchar_t), L'\0') ;	// 有限受信buffer。
		const DWORD	 before = index ;							// 前進しないI/Oを拒否する。
		// 本照会は次の同名header位置へ進める。
		if( !(controlled != nullptr
				 ? controlled->queryHeader( query, value.data(), &bytes, &index)
				 : transport.queryHeaders( request, query, WINHTTP_HEADER_NAME_BY_INDEX,
										  value.data(), &bytes, &index)) ||
		   index <= before || bytes % 2U != 0U || bytes / 2U > value.size()) {
			return std::nullopt ;
		}

		value.resize( bytes / 2U) ;
		// 本照会成功後だけ存在を確定する。
		if( present != nullptr) {
			*present = true ;
		}

		// APIが付けた末尾終端だけを除く。
		if( !value.empty() && value.back() == L'\0') {
			value.pop_back() ;
		}

		// 改行・埋込みNUL等を許可しない。
		if( std::any_of( value.begin(), value.end(),
					   []( wchar_t c) { return c < 0x20 || c > 0x7e ; })) {
			return std::nullopt ;
		}

		// 複数行を一つのlistとして扱う。
		if( count != 0U) {
			combined += L"," ;
		}

		combined += value ;
		// 合計上限を超えた応答は条件付き再利用しない。
		if( combined.size() > 2048U) {
			return std::nullopt ;
		}
	}

	return std::nullopt ;
}

/** @brief 秘密を保存せずRetry-Afterを有限の秒数またはUTCへ変換します。
 * @param[in] request HTTP 429／503の応答handle。
 * @param[in] transport 同じhandleを所有するI/O。
 * @param[out] observation 形式不明は要確認、欠損は追加指定なし。
 * @param[in,out] controlled 新modeだけの所有request制御。Nullは旧callerです。
 * @param[in] headerUtcMillis 新modeの元header観測UTC。旧callerでは使用しません。
 * @param[out] absoluteMillis 新modeの待機期限。欠損・不正では更新しません。Nullは旧callerです。
 */
void collectorRetryAfter( HINTERNET request, const OfficialHttpTransport &transport,
						 CollectorHttpObservation	  &observation,
						 ControlledCollectorRequest	  *controlled	   = nullptr,
						 std::uint64_t				   headerUtcMillis = 0U,
						 std::optional<std::uint64_t> *absoluteMillis  = nullptr)
{
	bool	   present{} ;	// 空値を欠損と区別する存在flag。
	const auto header =
		// 有限同名header。
		collectorHeader( request, WINHTTP_QUERY_RETRY_AFTER, transport, &present, controlled) ;
	// 読取り不能を待機なしへ変換しない。
	if( !header) {
		observation.retryAfterNeedsReview = true ;
		return ;
	}

	// 欠損時はcollectorの日次間隔に従う。
	if( !present) {
		return ;
	}

	const auto		   first = header->find_first_not_of( L' ') ;	// OWS開始。
	const auto		   last	 = header->find_last_not_of( L' ') ;	// OWS終端。
	const std::wstring value = first == std::wstring::npos
								   ? L""
								   : header->substr( first, last - first + 1U) ;	// 解析用非保存値。
	// 有限のdelay-secondsを桁ごとに検証する。
	if( !value.empty() &&
	   std::all_of( value.begin(), value.end(), []( wchar_t c) { return c >= L'0' && c <= L'9' ; })) {
		std::uint64_t delay{} ;	// 最大30日の待機秒数。
		// 乗算前に上限を確認してoverflowと短縮を防ぐ。
		for( const wchar_t c : value) {
			const auto digit = static_cast<std::uint64_t>( c - L'0') ;	// 一桁。
			// 過大指定は自動解除しない。
			if( delay > (2592000U - digit) / 10U) {
				observation.retryAfterNeedsReview = true ;
				return ;
			}

			delay = delay * 10U + digit ;
		}

		observation.retryAfterDelaySeconds = delay ;
		// 新modeだけは明示0秒も含め元millisecondへ一回結合する。
		if( absoluteMillis != nullptr) {
			*absoluteMillis = headerUtcMillis + delay * 1000U ;
		}

		return ;
	}

	SYSTEMTIME date{} ;										// HTTP日付のUTC暦日。
	FILETIME   file{} ;										// 正しい暦日の整数時刻。
	wchar_t	   canonical[WINHTTP_TIME_FORMAT_BUFSIZE]{} ;	// IMF-fixdate再構築。
	// 部分parse、旧形式、余分なfield、曜日不一致を要確認へ送る。
	if( value.size() != 29U || !WinHttpTimeToSystemTime( value.c_str(), &date) ||
	   !SystemTimeToFileTime( &date, &file) || !FileTimeToSystemTime( &file, &date) ||
	   !WinHttpTimeFromSystemTime( &date, canonical) || value != canonical) {
		observation.retryAfterNeedsReview = true ;
		return ;
	}

	const std::uint64_t ticks = (static_cast<std::uint64_t>( file.dwHighDateTime) << 32U) |
								file.dwLowDateTime ;		// 100ns UTC。
	constexpr std::uint64_t epoch = 116444736000000000ULL ;	// Unix epoch差分。
	// Epoch以前はすでに過ぎた指定として日次間隔だけを要求する。
	observation.retryAfterUtcSeconds = ticks <= epoch ? 0U : (ticks - epoch) / 10000000U ;
	// HTTP-dateのUTCは秒境界であり、元指定をmillisecondへ変換する。
	if( absoluteMillis != nullptr) {
		*absoluteMillis = observation.retryAfterUtcSeconds * 1000U ;
	}
}

/** @brief 固定requestと同じ表現だけを再検証可能にします。
 * @param[in] request 旧callerの所有外handle。Controlled使用時はnullを許します。
 * @param[in] transport 同じhandleの完全I/O表。
 * @param[in,out] controlled 新modeの所有request制御。Nullは旧callerです。
 * @return Cache-ControlとVaryが固定表現を許す場合true。
 */
[[nodiscard]] bool collectorAllowsRevalidation( const HINTERNET				request,
											   const OfficialHttpTransport &transport,
											   ControlledCollectorRequest  *controlled = nullptr)
{
	const auto vary = collectorHeader( request, WINHTTP_QUERY_VARY, transport, nullptr,
									  controlled) ;	// 表現選択header。
	const auto cache =
		// 保存制限。
		collectorHeader( request, WINHTTP_QUERY_CACHE_CONTROL, transport, nullptr, controlled) ;
	// Header確認不能は無条件200取得へ限定する。
	if( !vary || !cache) {
		return false ;
	}

	std::wstring lowerCache = *cache ;	// ASCII小文字化したpolicy。
	std::transform( lowerCache.begin(), lowerCache.end(), lowerCache.begin(), []( wchar_t c) {
		return c >= L'A' && c <= L'Z' ? static_cast<wchar_t>( c + L'a' - L'A') : c ;
	}) ;
	// 保守的に部分一致でも条件付き保存を止める。
	if( lowerCache.find( L"no-store") != std::wstring::npos ||
	   lowerCache.find( L"private") != std::wstring::npos) {
		return false ;
	}

	std::size_t offset{} ;	// Vary listの現在位置。
	// 既定headerだけなら次回も表現選択条件が同じ。
	while( offset < vary->size()) {
		const auto	 end = vary->find( L',', offset) ;	// 今回のlist区切り。
		std::wstring token =
			// 一要素。
			vary->substr( offset, end == std::wstring::npos ? end : end - offset) ;
		const auto first = token.find_first_not_of( L' ') ;	// 前の空白を除く。
		const auto last	 = token.find_last_not_of( L' ') ;	// 後の空白を除く。
		token = first == std::wstring::npos ? L"" : token.substr( first, last - first + 1U) ;
		std::transform( token.begin(), token.end(), token.begin(), []( wchar_t c) {
			return c >= L'A' && c <= L'Z' ? static_cast<wchar_t>( c + L'a' - L'A') : c ;
		}) ;
		// Cookieや未知の個人化条件を固定と推測しない。
		if( token != L"accept" && token != L"accept-encoding" && token != L"accept-language" &&
		   token != L"user-agent" && token != L"host") {
			return false ;
		}

		// 最終要素で停止する。
		if( end == std::wstring::npos) {
			break ;
		}

		offset = end + 1U ;
	}

	return true ;
}

} // namespace

/** @see official_http_client.h */
bool isCollectorEntityTag( std::wstring_view value) noexcept
{
	// 有限ASCII subsetだけを永続化する。
	if( value.size() > 256U) {
		return false ;
	}

	// 弱いvalidatorもIf-None-Matchの再確認に使用できる。
	if( value.starts_with( L"W/")) {
		value.remove_prefix( 2U) ;
	}

	// 空のopaque値と不正なquoteを拒否する。
	if( value.size() < 3U || value.front() != L'"' || value.back() != L'"') {
		return false ;
	}

	value.remove_prefix( 1U) ;
	value.remove_suffix( 1U) ;
	return std::all_of( value.begin(), value.end(), []( wchar_t c) {
		return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9') ||
			   c == L'.' || c == L'_' || c == L':' || c == L'-' ;
	}) ;
}

/** @see official_http_client.h */
NativeError OfficialHttpClient::getCollectorMetadataForSource(
	const std::wstring_view url, const std::wstring_view resourceId,
	const std::uint64_t maximumBytes, const std::wstring_view entityTag, std::wstring &text,
	CollectorHttpObservation &observation, std::string *raw)
{
	text.clear() ;
	observation = {} ;
	// 明示出力も304・拒否では古い原本文を残しません。
	if( raw != nullptr) {
		raw->clear() ;
	}

	// 既存cacheや他要求のevidenceを収集再検証へ混在させない。
	if( useCatalogCache_ || metadataExecution_ != nullptr || !sourceEvidence_.empty() ||
	   maximumBytes == 0U || maximumBytes > 8U * 1024U * 1024U ||
	   (!entityTag.empty() && !isCollectorEntityTag( entityTag))) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::span<const std::wstring_view> hosts ;			// 登録済みsourceのhost集合。
	std::uint32_t					   redirects{} ;	// 固定上限。
	const NativeError				   sourceError =
		// Source検証。
		resolveSourceHosts( resourceId, hosts, redirects) ;
	// Payload用途や未登録sessionには使えない。
	if( sourceError != 0 ||
	   (!sourceResourceHasKind( resourceId, OfficialSourceResourceKind::LANDING_PAGE) &&
		!sourceResourceHasKind( resourceId, OfficialSourceResourceKind::METADATA))) {
		return sourceError != 0 ? sourceError : static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const auto &transport = testTransport_ ? *testTransport_ : NATIVE_HTTP_TRANSPORT ;	// 固定I/O。
	InternetHandle session( nullptr), connection( nullptr), request( nullptr) ;			// 今回専用handle。
	DWORD		   status{} ;															// 元のHTTP状態。
	std::vector<std::uint32_t> origins ;												// 有限redirect根拠。
	const NativeError		   requestError = openGetRequestFollowingRedirects(
		 url, hosts, redirects, entityTag, {}, session, connection, request, status, origins,
		 nullptr, transport, true, nullptr, true) ;	// 応答開始。
	observation.status = status >= 100U && status <= 599U ? status : 0U ;
	// HTTP失敗は同じ試行で再送しない。
	if( requestError != 0) {
		// 失敗bodyを読み込まず待機指定だけを保持する。
		if( request.valid() && (status == 429U || status == 503U)) {
			collectorRetryAfter( request.get(), transport, observation) ;
		}

		return requestError ;
	}

	const auto tag =
		// 全ETag header。
		collectorHeader( request.get(), WINHTTP_QUERY_ETAG, transport) ;
	const bool reusable = origins.size() == 1U && tag && isCollectorEntityTag( *tag) &&
						  // 再確認可能な同じ表現。
						  collectorAllowsRevalidation( request.get(), transport) ;
	// 304は本文・取得grantのevidenceを一切発行しない。
	if( status == HTTP_STATUS_NOT_MODIFIED) {
		// 指定したvalidator以外への再確認成功を禁止する。
		if( !reusable || entityTag.empty() || *tag != entityTag) {	// 指定したvalidatorとの完全一致。
			return nativeErrorFromWin32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
		}

		observation.entityTag = *tag ;
		return 0 ;
	}

	// 200以外にbody成功を与えない。
	if( status != HTTP_STATUS_OK) {
		return nativeErrorFromWin32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
	}

	std::vector<std::byte> received ;	// 上限内のraw本文。自己保存せず明示出力だけへ返す。
	const NativeError	   bodyError = consumeResponse(
		 request.get(), maximumBytes,
		 [&received]( const std::span<const std::byte> chunk) {
			 received.insert( received.end(), chunk.begin(), chunk.end()) ;
			 return static_cast<NativeError>( 0) ;
		 },
		 []( std::uint64_t, std::uint64_t) {}, {}, nullptr, transport, true) ;	// 厳密な本文受信。
	// 不完全本文はhashやevidenceへ進めない。
	if( bodyError != 0) {
		return bodyError ;
	}

	std::wstring	  decoded ;												// 検証済みUTF-8の文字列。
	const NativeError decodeError = decodeUtf8Body( received, decoded) ;	// 不正UTF-8拒否。
	// NULや不正encodingをparserへ渡さない。
	if( decodeError != 0) {
		return decodeError ;
	}

	std::wstring	  hash ;	// 原byteの指紋。
	const NativeError hashError = computeCollectorMetadataSha256(
		std::string_view( reinterpret_cast<const char *>( received.data()), received.size()),
		hash) ;	// CNG計算。
	// 本文根拠を確定する前にhashを得る。
	if( hashError != 0) {
		return hashError ;
	}

	const NativeError evidenceError =
		// 実200証拠。
		appendSourceEvidence( resourceId, origins, networkObservation( false)) ;
	// 完全なnetwork body以外には通常adapterの根拠を発行しない。
	if( evidenceError != 0) {
		return evidenceError ;
	}

	observation.bodySha256 = std::move( hash) ;
	observation.entityTag  = reusable ? *tag : L"" ;
	// 文字列の再符号化ではなく、同じhash検証済み原byteだけを返します。
	if( raw != nullptr) {
		// SDK byte bufferの非owning境界だけを文字byte viewとして借用します。
		raw->assign( reinterpret_cast<const char *>( received.data()), received.size()) ;
	}

	text = std::move( decoded) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
/** @see official_http_client.h */
NativeError OfficialHttpClient::getControlledCollectorMetadataForSource(
	std::wstring_view url, std::wstring_view resourceId, std::uint64_t maximumBytes,
	std::wstring_view entityTag, OfficialCollectorHttpControl &control,
	const OfficialCollectorDnsApi &dnsApi, std::wstring &text,
	CollectorControlledHttpObservation &observation)
{
	text.clear() ;
	observation		 = {} ;
	const auto	&api = testTransport_ ? *testTransport_ : NATIVE_HTTP_TRANSPORT ;	// 元の完全I/O表。
	std::wstring decoded ;															// 解放確認までは呼出し側へ出さない。
	std::wstring hash ;																// 200のraw byteだけをhashする。
	std::wstring reusableTag ;														// 検証済みETag。
	// 元HRESULTを失わない共通拒否。Captureは同期scope中だけ有効。
	const auto	 reject = [&]( NativeError error, CollectorIoCause cause, CollectorIoStage stage) {
		  control.fail(
			  cause,
			  {CollectorIoErrorDomain::HRESULT_ERROR, static_cast<std::uint32_t>( error), stage},
			  false) ;
		  return collectorControlError( control) ;
	} ;
	try {
		// 無効依存・別用途・既に使用されたsessionではDNSへ進まない。
		if( useCatalogCache_ || metadataExecution_ != nullptr || !sourceEvidence_.empty() ||
		   maximumBytes == 0U || maximumBytes > 8U * 1024U * 1024U ||
		   (!entityTag.empty() && !isCollectorEntityTag( entityTag)) || !api.open || !api.connect ||
		   !api.openRequest || !api.setTimeouts || !api.setOption || !api.addHeaders ||
		   !api.sendRequest || !api.receiveResponse || !api.queryHeaders || !api.queryAvailable ||
		   !api.readData || !api.closeHandle || control.snapshot().sends != 0U) {
			return reject( static_cast<NativeError>( E_INVALIDARG), CollectorIoCause::SETUP,
						  CollectorIoStage::SETUP) ;
		}

		// Claim済みで生存中の予約だけに共通HTTPを接続する。
		if( control.begin( CollectorIoStage::SETUP, RECEIVE_TIMEOUT_MILLISECONDS) == 0U) {
			return collectorControlError( control) ;
		}

		std::span<const std::wstring_view> hosts ;			// 組み込み公式originだけ。
		std::uint32_t					   redirects{} ;	// 旧policy値は読むが新modeで追跡しない。
		const auto						   sourceError =
			// 共通source検証。
			resolveSourceHosts( resourceId, hosts, redirects) ;
		// Payload用途からこの入口を使わない。
		if( sourceError != 0U ||
		   (!sourceResourceHasKind( resourceId, OfficialSourceResourceKind::LANDING_PAGE) &&
			!sourceResourceHasKind( resourceId, OfficialSourceResourceKind::METADATA))) {
			return reject( sourceError != 0U ? sourceError
											: static_cast<NativeError>( E_ACCESSDENIED),
						  CollectorIoCause::SETUP, CollectorIoStage::SETUP) ;
		}

		ParsedUrl  parsed ;											// URLは同期scope内だけ。
		const auto urlError = parseHttpsUrl( url, hosts, parsed) ;	// 既存共通origin判定。
		// 不正URLをDNS名だけで承認しない。
		if( urlError != 0U) {
			return reject( urlError, CollectorIoCause::SETUP, CollectorIoStage::SETUP) ;
		}

		OfficialPublicDestinationEvidence destination ;	// 全address検証の非機密結果。
		// 有限DNSと全public宛先判定の元結果。
		const auto						  dnsError =
			resolveCollectorPublicDestination( parsed.host, control, dnsApi, destination) ;
		// DNS後の取消し・期限・解放失敗からWinHTTPへ進まない。
		if( dnsError != 0U) {
			return dnsError ;
		}

		{
			ControlledCollectorRequest request( api, control) ;	// 全handleを本threadで解放する。
			// Scoped lambdaを抜けた後に必ず解放結果を検査する。Scope外へhandleを渡さない。
			const auto				   receive = [&]() -> NativeError {
				// 一回GETを開始できなければstatus・本文へ進まない。
				if( !request.open( parsed, entityTag)) {
					return collectorControlError( control) ;
				}

				DWORD status{} ;						// 原HTTP status。
				DWORD statusBytes = sizeof( status) ;	// 数値statusの固定容量。
				// Status照会失敗は未観測のまま保持する。
				if( !request.queryHeader( WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
														&status, &statusBytes, nullptr)) {
					return collectorControlError( control) ;
				}

				// HTTP範囲外を成功statusとして記録しない。
				if( status < 100U || status > 599U || statusBytes != sizeof( status)) {
					return reject( static_cast<NativeError>( E_INVALIDARG), CollectorIoCause::HTTP,
												  CollectorIoStage::HEADERS) ;
				}

				observation.status = status ;
				// Retry-Afterの相対値を結合するheader観測時刻を固定する。
				if( !control.noteHeaders()) {
					return collectorControlError( control) ;
				}

				// 429／503は本文なしで同じ厳密Retry-After parserへ接続する。
				if( status == 429U || status == 503U) {
					collectorRetryAfter( nullptr, api, observation, &request,
														control.snapshot().headerUtcMillis.value(),
														&observation.retryAfterUtcMillis) ;
					// Header読取り中の停止を無視してHTTP拒否へ置換しない。
					if( control.snapshot().cause != CollectorIoCause::NONE) {
						return collectorControlError( control) ;
					}

					// 新応答では正確なabsoluteMillisを正本とし、後段の秒再結合を禁止する。
					observation.retryAfterDelaySeconds = 0U ;
					observation.retryAfterUtcSeconds   = 0U ;
				}

				// 自動redirect／認証retryを一切許可しない。
				if( status != 200U && (status != 304U || entityTag.empty())) {
					control.fail( CollectorIoCause::HTTP,
												 {CollectorIoErrorDomain::HTTP, status, CollectorIoStage::HEADERS},
												 false) ;
					return collectorControlError( control) ;
				}

				const auto tag = collectorHeader( nullptr, WINHTTP_QUERY_ETAG, api, nullptr,
																 &request) ;	// 有限tag。
				const bool reusable = tag && isCollectorEntityTag( *tag) &&
									  // 固定表現の再利用条件。
									  collectorAllowsRevalidation( nullptr, api, &request) ;
				// Native error・取消しが発生した照会を単なるcache不可へ弱めない。
				if( control.snapshot().cause != CollectorIoCause::NONE) {
					return collectorControlError( control) ;
				}

				// 304は本文hash・取得根拠を作らずvalidatorだけを返す。
				if( status == 304U) {
					// 元requestと異なるvalidatorを受理しない。
					if( !reusable || *tag != entityTag) {
						request.reject( CollectorIoCause::HTTP, ERROR_INVALID_DATA,
													   CollectorIoStage::HEADERS) ;
						return collectorControlError( control) ;
					}

					reusableTag = *tag ;
					return 0U ;
				}

				bool	   hasLength{} ;	// 欠損と空値を区別する。
				bool	   hasTransfer{} ;	// Content-Length併存の検査。
				bool	   hasCoding{} ;	// 圧縮を長さだけで成功にしない。
				// 単一Content-Lengthの有限文字列。欠損と不正を区別する。
				const auto length = collectorHeader( nullptr, WINHTTP_QUERY_CONTENT_LENGTH, api,
																	&hasLength, &request) ;
				// 本文区切りの併存検査に使うTransfer-Encoding。
				const auto transfer = collectorHeader( nullptr, WINHTTP_QUERY_TRANSFER_ENCODING, api,
																	  &hasTransfer, &request) ;
				// 圧縮変換を長さ完了へ読み替えないためのContent-Encoding。
				const auto coding = collectorHeader( nullptr, WINHTTP_QUERY_CONTENT_ENCODING, api,
																	&hasCoding, &request) ;
				// 不正／重複長や区切り矛盾をheader欠損へ変換しない。
				if( !length || !transfer || !coding || (hasLength && hasTransfer) ||
				   (hasTransfer && *transfer != L"chunked") ||
				   (hasCoding && *coding != L"identity")) {
					request.reject( CollectorIoCause::HTTP, ERROR_INVALID_DATA,
												   CollectorIoStage::HEADERS) ;
					return collectorControlError( control) ;
				}

				std::optional<std::uint64_t> expected ;	// 厳密な単一長だけ値を持つ。
				// 宣言長はASCII数字だけを上限付きで読む。
				if( hasLength) {
					std::uint64_t value{} ;	// overflow前に検査する累積値。
					// 空長は不正であり長さ欠損ではない。
					if( length->empty()) {
						request.reject( CollectorIoCause::HTTP, ERROR_INVALID_DATA,
													   CollectorIoStage::HEADERS) ;
						return collectorControlError( control) ;
					}

					// 全文字を調べ、重複結合comma・符号等を拒否する。
					for( const auto digit : *length) {
						// 数字でない宣言長は本文を読む前に止める。
						if( digit < L'0' || digit > L'9') {
							request.reject( CollectorIoCause::HTTP, ERROR_INVALID_DATA,
														   CollectorIoStage::HEADERS) ;
							return collectorControlError( control) ;
						}

						const auto number =
							// 現在の一桁。
							static_cast<std::uint64_t>( digit - L'0') ;
						// 有限上限を超えた宣言を切り詰めて使わない。
						if( value > (std::numeric_limits<std::uint64_t>::max() - number) / 10U) {
							request.reject( CollectorIoCause::BODY_LIMIT, ERROR_FILE_TOO_LARGE,
														   CollectorIoStage::HEADERS) ;
							return collectorControlError( control) ;
						}

						value = value * 10U + number ;
					}

					// 宣言超過と空200を本文なしで拒否する。
					if( value > maximumBytes || value == 0U) {
						request.reject( value == 0U ? CollectorIoCause::BODY_INCOMPLETE
																   : CollectorIoCause::BODY_LIMIT,
									   value == 0U ? ERROR_HANDLE_EOF : ERROR_FILE_TOO_LARGE,
									   CollectorIoStage::HEADERS) ;
						return collectorControlError( control) ;
					}

					expected = value ;
				}

				std::vector<std::byte> raw ;	// 本文上限内の一時byte列。
				// 完全な終端確認前にdecode・hashへ進まない。
				if( !request.body( maximumBytes, expected, raw)) {
					return collectorControlError( control) ;
				}

				// Decode前後も同じ全体期限を使用する。
				if( control.begin( CollectorIoStage::DECODE, RECEIVE_TIMEOUT_MILLISECONDS) == 0U) {
					return collectorControlError( control) ;
				}

				const auto decodeError = decodeUtf8Body( raw, decoded) ;	// 共通の厳密UTF-8。
				// 不正encodingの原HRESULTを保持する。
				if( decodeError != 0U) {
					return reject( decodeError, CollectorIoCause::PARSER, CollectorIoStage::DECODE) ;
				}

				// Hashを別予算・別期限で実行しない。
				if( control.begin( CollectorIoStage::HASH, RECEIVE_TIMEOUT_MILLISECONDS) == 0U) {
					return collectorControlError( control) ;
				}

				// CNG境界のbyte viewはrawの所有scope内だけで借用する。
				const auto hashError = computeCollectorMetadataSha256(
					std::string_view( reinterpret_cast<const char *>( raw.data()), raw.size()), hash) ;
				// 共通hash失敗を固定hashで補完しない。
				if( hashError != 0U) {
					return reject( hashError, CollectorIoCause::PARSER, CollectorIoStage::HASH) ;
				}

				reusableTag = reusable ? *tag : L"" ;
				return 0U ;
			} ;
			const auto error = receive() ;	// API／解析の元結果。
			request.close() ;
			// 解放失敗を成功へ上書きしない。
			if( error != 0U ||
			   control.begin( CollectorIoStage::CLEANUP, RECEIVE_TIMEOUT_MILLISECONDS) == 0U) {
				return collectorControlError( control) ;
			}
		}
		// HTTP成功だけでは最終COMPLETE／公式parserのOBSERVEDにしない。
		text				   = std::move( decoded) ;
		observation.bodySha256 = std::move( hash) ;
		observation.entityTag  = std::move( reusableTag) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return reject( static_cast<NativeError>( E_OUTOFMEMORY), CollectorIoCause::SETUP,
					  control.snapshot().stage) ;
	} catch( ...) {
		return reject( static_cast<NativeError>( E_FAIL), CollectorIoCause::SETUP,
					  control.snapshot().stage) ;
	}
}

/** @see official_http_client.h */
OfficialHttpClient::OfficialHttpClient( const bool useCatalogCache) noexcept
	: useCatalogCache_( useCatalogCache)
{
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialHttpClient::OfficialHttpClient( OfficialHttpTransport transport) noexcept
	: useCatalogCache_( false), testTransport_( std::move( transport))
{
}

/** @see official_http_client.h */
OfficialHttpClient::OfficialHttpClient( MetadataSearchExecutionContext &execution,
									   const bool					   useCatalogCache) noexcept
	: useCatalogCache_( useCatalogCache), metadataExecution_( &execution)
{
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialHttpClient::OfficialHttpClient( MetadataSearchExecutionContext &execution,
									   OfficialHttpTransport		   transport,
									   const OfficialHttpCacheAccess  *cacheAccess) noexcept
	: useCatalogCache_( cacheAccess != nullptr), metadataExecution_( &execution),
	  testTransport_( std::move( transport)), testCacheAccess_( cacheAccess)
{
}

/** @see official_http_client.h */
bool OfficialHttpClient::usesCatalogCache() const noexcept
{
	return useCatalogCache_ ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool matchesOfficialPayloadContentType( const std::wstring_view value,
									   const std::wstring_view expected) noexcept
{
	// 不明な型、過大header、parameter付き期待値や複数値を受理しません。
	if( expected.empty() || expected.size() > 128U || value.empty() || value.size() > 256U ||
	   expected.find_first_of( L";, \t\r\n") != std::wstring_view::npos ||
	   !value.starts_with( expected)) {
		return false ;
	}

	// 元headerの全文字を検査し、制御文字・非ASCIIを拒否します。
	for( const auto character : value) {
		// CRLF、NUL、非ASCIIを曖昧なparameterへ読み替えません。
		if( character < 0x20 || character > 0x7e) {
			return false ;
		}
	}

	// 従来のbare媒体型の完全一致をそのまま維持します。
	if( value == expected) {
		return true ;
	}

	auto parameter = value.substr( expected.size()) ;	// 基底型に続く未変更の短命viewです。
	// 媒体型直後のHTTP spaceだけを読み飛ばします。
	while( !parameter.empty() && parameter.front() == L' ') {
		parameter.remove_prefix( 1U) ;
	}

	// 型名の前方一致や空白だけを型一致へ昇格しません。
	if( parameter.empty() || parameter.front() != L';') {
		return false ;
	}

	parameter.remove_prefix( 1U) ;
	// 単一parameterの先頭spaceだけを除きます。
	while( !parameter.empty() && parameter.front() == L' ') {
		parameter.remove_prefix( 1U) ;
	}

	// 単一parameter末尾のHTTP spaceだけを除きます。
	while( !parameter.empty() && parameter.back() == L' ') {
		parameter.remove_suffix( 1U) ;
	}

	const auto equalAscii = [parameter]( const std::wstring_view expectedParameter) {
		// 大小文字以外の構文差や余分なparameterを受理しません。
		if( parameter.size() != expectedParameter.size()) {
			return false ;
		}

		// 固定のUTF-8 charset構文を全文字比較します。
		for( std::size_t index = 0U; index < parameter.size(); ++index) {
			const auto character = parameter[index] ;	// 原ASCIIの一文字です。
			const auto lower	 = character >= L'A' && character <= L'Z'
									   ? static_cast<wchar_t>( character + (L'a' - L'A'))
									   : character ;	// ASCII caseだけを比較します。
			// 異なる値や区切りをUTF-8宣言へ補完しません。
			if( lower != expectedParameter[index]) {
				return false ;
			}
		}

		return true ;
	} ; // 元viewを本関数中だけ借用し、payload byteを変更しません。
	return equalAscii( L"charset=utf-8") || equalAscii( L"charset=\"utf-8\"") ;
}

/** @see src/platform/official_http_client.h 宣言側の契約を正本とする。 */
NativeError validateOfficialHttpResponseStatus( const std::uint32_t status,
											   const bool		   allowNotModified,
											   const bool		   allowRedirects) noexcept
{
	// HTTP statusではない値を16-bit codeへ切り詰めて別の診断にしない。
	if( status < 100U || status > 599U) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE)) ;
	}

	// 受理しても、本文・cache・redirect先の検証は呼出し元が後段で行う。
	if( status == HTTP_STATUS_OK || (allowNotModified && status == HTTP_STATUS_NOT_MODIFIED) ||
	   (allowRedirects && isRedirectStatus( static_cast<DWORD>( status)))) {
		return 0 ;
	}

	return static_cast<NativeError>(
		MAKE_HRESULT( SEVERITY_ERROR, FACILITY_HTTP, static_cast<DWORD>( status))) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError validateOfficialHttpsUrl( const std::wstring_view				  url,
									 const std::span<const std::wstring_view> allowedHosts) noexcept
{
	try {
		ParsedUrl parsed ;	// 検証成功時だけ設定される一時component。
		return parseHttpsUrl( url, allowedHosts, parsed) ;
	} catch( ...) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError validateOfficialHttpsRedirectChain(
	const std::span<const std::wstring_view> urls,
	const std::span<const std::wstring_view> allowedHosts, const std::uint32_t maximumRedirects,
	std::vector<std::uint32_t> &originPolicyIndices) noexcept
{
	originPolicyIndices.clear() ;
	// 空の経路と許可回数を超える redirect 列を通信前に拒否する。
	if( urls.empty() || maximumRedirects > MAXIMUM_REDIRECTS ||
	   urls.size() - 1U > maximumRedirects) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		std::unordered_set<std::wstring> visitedRequests ;	// 正規化済み循環検出key集合。
		std::vector<std::uint32_t>		 validatedIndices ;	// 成功時にだけ公開するindex列。
		visitedRequests.reserve( urls.size()) ;
		validatedIndices.reserve( urls.size()) ;
		// urlは起点から最終originまで順番に検証する現在の絶対URLである。
		for( const std::wstring_view url : urls) {
			ParsedUrl		  parsed ;	// 現在URLの検証済みcomponent。
			const NativeError error =
				appendValidatedRouteUrl( url, allowedHosts, visitedRequests, validatedIndices,
										parsed) ;	// 現在URL検証結果。
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}
		}

		originPolicyIndices = std::move( validatedIndices) ;
		return 0 ;
	} catch( ...) {
		originPolicyIndices.clear() ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialHttpClient::beginSourceSession( const ScanSessionId	   scanSessionId,
												   const std::wstring_view providerId)
{
	// 内部試験の不完全I/O表を既定Windows APIへ補完しない。
	if( testTransport_) {
		const auto &api = *testTransport_ ;	// Clientが所有する不変table。
		// 一つでも欠損したbackendをnative APIで補完すると非通信境界が崩れるため拒否する。
		if( !api.open || !api.connect || !api.openRequest || !api.setTimeouts || !api.setOption ||
		   !api.addHeaders || !api.sendRequest || !api.receiveResponse || !api.queryHeaders ||
		   !api.queryAvailable || !api.readData || !api.closeHandle ||
		   (testCacheAccess_ &&
			(!testCacheAccess_->load || !testCacheAccess_->store || !testCacheAccess_->discard))) {
			invalidateSourceSession() ;
			return static_cast<NativeError>( E_INVALIDARG) ;
		}
	}

	invalidateSourceSession() ;
	// 有効な scan session と Provider を持たない監査開始は拒否する。
	if( scanSessionId == 0U || providerId.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 専用contextを別session・未選択Providerへ転用しない。
	if( metadataExecution_ != nullptr && (metadataExecution_->scanSessionId() != scanSessionId ||
										 metadataExecution_->activeProviderId() != providerId)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 組込み取得元 policy の整合性が成立しなければ監査を開始しない。
	if( !validateBuiltInOfficialSourcePolicies()) {
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}

	const OfficialSourcePolicy *const policy =
		// Providerの組み込みpolicy。
		officialSourcePolicyForProvider( providerId) ;
	// 登録済み policy と Provider ID が一致する監査だけを受理する。
	if( policy == nullptr || policy->providerId != providerId) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	try {
		sourceProviderId_ = providerId ;
	} catch( ...) {
		invalidateSourceSession() ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	sourceScanSessionId_ = scanSessionId ;
	nextAcquisitionId_	 = 1U ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void OfficialHttpClient::invalidateSourceSession() noexcept
{
	sourceEvidence_.clear() ;
	sourceProviderId_.clear() ;
	sourceScanSessionId_ = 0U ;
	nextAcquisitionId_	 = 1U ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::span<const OfficialSourceEvidence> OfficialHttpClient::sourceEvidence() const noexcept
{
	return sourceEvidence_ ;
}

/** @see src/platform/official_http_client.h */
bool OfficialHttpClient::matchesSourceSession( const ScanSessionId	  scanSessionId,
											  const std::wstring_view providerId) const noexcept
{
	return scanSessionId != 0U && scanSessionId == sourceScanSessionId_ && !providerId.empty() &&
		   providerId == sourceProviderId_ ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool OfficialHttpClient::hasSourceEvidence( const ScanSessionId	   scanSessionId,
										   const std::wstring_view providerId,
										   const std::wstring_view resourceId) const noexcept
{
	// 現在 session・Provider・resource に結び付かない取得根拠は使用しない。
	if( scanSessionId == 0U || scanSessionId != sourceScanSessionId_ || providerId.empty() ||
	   providerId != sourceProviderId_ || resourceId.empty()) {
		return false ;
	}

	bool		  found{} ;			// 指定resourceを一件以上確認した場合true。
	std::uint64_t expectedId{1U} ;	// 現在entryへ期待する連続取得番号。
	// Ledger全体を検証し、一部だけ有効な壊れたsessionを採用しない。
	for( const OfficialSourceEvidence &evidence : sourceEvidence_) {
		// Ledger の各根拠が有効で、session と連番が連続していることを確認する。
		if( !isValidOfficialSourceEvidence( evidence) ||
		   evidence.scanSessionId != sourceScanSessionId_ ||
		   evidence.providerId != sourceProviderId_ || evidence.acquisitionId != expectedId) {
			return false ;
		}

		found = found || evidence.resourceId == resourceId ;
		++expectedId ;
	}

	return found && nextAcquisitionId_ == expectedId ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialHttpClient::resolveSourceHosts( const std::wstring_view			   resourceId,
												   std::span<const std::wstring_view> &allowedHosts,
												   std::uint32_t &maximumRedirects) const noexcept
{
	allowedHosts	 = {} ;
	maximumRedirects = 0U ;
	// Context終端後に残ったclientから新しい通信を開始しない。
	if( metadataExecution_ != nullptr &&
	   (metadataExecution_->scanSessionId() != sourceScanSessionId_ ||
		metadataExecution_->activeProviderId() != sourceProviderId_)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 監査 session または取得 ID が無効な状態では resource を解決しない。
	if( sourceScanSessionId_ == 0U || sourceProviderId_.empty() || resourceId.empty() ||
	   nextAcquisitionId_ == 0U) {
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}

	// 取得根拠の保持上限を超える要求は ledger を拡張せず拒否する。
	if( sourceEvidence_.size() >= MAXIMUM_SOURCE_EVIDENCE_ENTRIES) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	const OfficialSourcePolicy *const policy =
		// 現在Providerのpolicy。
		officialSourcePolicyForProvider( sourceProviderId_) ;
	// Provider の取得元 policy がない場合は host を推測しない。
	if( policy == nullptr) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const OfficialSourceResourcePolicy *const resource =
		// 用途別の取得境界。
		findOfficialSourceResource( *policy, resourceId) ;
	// Resource 定義または許可 host がない要求は network へ渡さない。
	if( resource == nullptr || resource->allowedHosts.empty()) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	allowedHosts	 = resource->allowedHosts ;
	maximumRedirects = resource->maximumRedirects ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool OfficialHttpClient::sourceResourceHasKind( const std::wstring_view			resourceId,
											   const OfficialSourceResourceKind kind) const noexcept
{
	const OfficialSourcePolicy *const policy =
		// 現在Providerのpolicy。
		officialSourcePolicyForProvider( sourceProviderId_) ;
	// Provider policy がない場合は resource の用途を一致と扱わない。
	if( policy == nullptr) {
		return false ;
	}

	const OfficialSourceResourcePolicy *const resource =
		// 用途を検証するresource。
		findOfficialSourceResource( *policy, resourceId) ;
	return resource != nullptr && resource->kind == kind ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialHttpClient::appendSourceEvidence(
	const std::wstring_view resourceId, const std::span<const std::uint32_t> originPolicyIndices,
	const OfficialHttpAcquisitionObservation &observation) noexcept
{
	std::span<const std::wstring_view> allowedHosts ;		// Sessionとresourceの再検証結果。
	std::uint32_t					   maximumRedirects{} ;	// Resourceに登録されたredirect上限。
	const NativeError				   resolveError =
		// Policy解決結果。
		resolveSourceHosts( resourceId, allowedHosts, maximumRedirects) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( resolveError != 0) {
		return resolveError ;
	}

	const OfficialSourcePolicy *const policy =
		// 現在Providerのpolicy。
		officialSourcePolicyForProvider( sourceProviderId_) ;
	// 取得元 policy を失った状態では成功根拠を ledger に追加しない。
	if( policy == nullptr) {
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}

	// Origin 経路が空または許可 redirect 回数を超える根拠は拒否する。
	if( originPolicyIndices.empty() || originPolicyIndices.size() > MAXIMUM_REDIRECTS + 1U ||
	   originPolicyIndices.size() - 1U > maximumRedirects) {
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}

	try {
		const std::size_t redirectCount =	// 起点を除いた実redirect回数。
			originPolicyIndices.size() - 1U ;
		OfficialSourceEvidence evidence{
			.scanSessionId		 = sourceScanSessionId_,
			.acquisitionId		 = nextAcquisitionId_,
			.providerId			 = sourceProviderId_,
			.policyId			 = std::wstring( policy->id),
			.resourceId			 = std::wstring( resourceId),
			.redirectCount		 = static_cast<std::uint32_t>( redirectCount),
			.originPolicyIndices = std::vector<std::uint32_t>(
				// 成功取得根拠。
				originPolicyIndices.begin(), originPolicyIndices.end()),
			.acquisition			   = observation.acquisition,
			.bodyAcquiredUtcSeconds	   = observation.bodyAcquiredUtcSeconds,
			.originValidatedUtcSeconds = observation.originValidatedUtcSeconds,
			.cachePermitted			   = observation.cachePermitted} ;
		// 組み立てた取得根拠の整合性を検証し、不正な ledger 項目を残さない。
		if( !isValidOfficialSourceEvidence( evidence)) {
			return static_cast<NativeError>( E_UNEXPECTED) ;
		}

		sourceEvidence_.push_back( std::move( evidence)) ;
	} catch( ...) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	++nextAcquisitionId_ ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialHttpClient::getUtf8TextForSource( const std::wstring_view url,
													 const std::wstring_view resourceId,
													 const std::uint64_t	 maximumBytes,
													 std::wstring			&text)
{
	std::span<const std::wstring_view> allowedHosts ;		// 用途別の組み込みhost群。
	std::uint32_t					   maximumRedirects{} ;	// Resourceに登録されたredirect上限。
	const NativeError				   resolveError =
		// Policy解決結果。
		resolveSourceHosts( resourceId, allowedHosts, maximumRedirects) ;
	// 取得先を解決できなければ既存 text を消して失敗を返す。
	if( resolveError != 0) {
		text.clear() ;
		return resolveError ;
	}

	// Landing page と metadata 以外の resource を text 取得へ流用しない。
	if( !sourceResourceHasKind( resourceId, OfficialSourceResourceKind::LANDING_PAGE) &&
	   !sourceResourceHasKind( resourceId, OfficialSourceResourceKind::METADATA)) {
		text.clear() ;
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 同じ公式hostでも任意pathやpayload URLをmetadata用途名で要求させない。
	if( metadataExecution_ != nullptr) {
		const auto fixedUrl =
			// 正本の固定起点。
			officialMetadataEndpoint( sourceProviderId_, resourceId) ;
		// 未対応起点と一文字でも異なるURLはcache・resource計数・通信より前に拒否する。
		if( fixedUrl.empty() || url != fixedUrl) {
			text.clear() ;
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}
	}

	const MetadataResourceScope resourceScope( metadataExecution_,
											  maximumBytes) ;	// 全return・例外で終端する予約。
	// 予算や取消しで開始できなかったresourceは要求しない。
	if( resourceScope.error() != 0) {
		text.clear() ;
		return resourceScope.error() ;
	}

	std::vector<std::uint32_t>		   originPolicyIndices ;	// 成功したopaque origin経路。
	OfficialHttpAcquisitionObservation observation ;			// 実際のnetwork／cache取得経路。
	const NativeError				   downloadError =
		getUtf8Text( url, allowedHosts, maximumRedirects, maximumBytes, text, originPolicyIndices,
					observation) ;	// Text取得とUTF-8検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( downloadError != 0) {
		return downloadError ;
	}

	// Decode待機中の取消し後に本文と成功ledgerを公開しない。
	if( metadataExecution_ != nullptr) {
		const auto stopped = metadataExecution_->checkpoint() ;	// 公開直前の停止確認。
		// 停止後にdecode済み本文や取得ledgerを発行しない。
		if( stopped != 0) {
			text.clear() ;
			return stopped ;
		}
	}

	const NativeError evidenceError =
		// 根拠確定結果。
		appendSourceEvidence( resourceId, originPolicyIndices, observation) ;
	// 取得根拠を保持できなければ、本文だけを成功結果として残さない。
	if( evidenceError != 0) {
		text.clear() ;
	}

	return evidenceError ;
}

//------------------------------------------------------------------------------
/** @see src/platform/official_http_client.h */
//------------------------------------------------------------------------------
NativeError OfficialHttpClient::getLiveHtmlPageForSource(
	const std::wstring_view url, const std::wstring_view resourceId,
	const HttpCancellationCallback &cancellation, std::wstring &text, std::wstring &finalUrl,
	std::uint64_t *const byteCount)
{
	return getLiveTextForSource( url, resourceId, cancellation, false, text, finalUrl, byteCount,
								nullptr) ;
}

/** @see src/platform/official_http_client.h */
NativeError OfficialHttpClient::getLiveScriptMetadataForSource(
	const std::wstring_view url, const std::wstring_view resourceId,
	const HttpCancellationCallback &cancellation, std::string &raw)
{
	std::wstring decoded ;	// 共通decoderの検証結果。実行には使用しない。
	std::wstring finalUrl ;	// 共通取得で検証する同一origin URL。
	return getLiveTextForSource( url, resourceId, cancellation, true, decoded, finalUrl, nullptr,
								&raw) ;
}

/** @see official_http_client.h */
NativeError OfficialHttpClient::getCollectorLinkedScriptForSource(
	const std::wstring_view pageUrl, const std::wstring_view page, const std::wstring_view url,
	const std::wstring_view resourceId, const HttpCancellationCallback &cancellation,
	std::string &raw)
{
	raw.clear() ;
	std::span<const std::wstring_view> hosts ;			// 現sourceの元用途hostだけです。
	std::uint32_t					   redirects{} ;	// Scriptは元policyもredirect0を必要とします。
	const auto						   resolved =
		// 元resourceの検査です。
		resolveSourceHosts( resourceId, hosts, redirects) ;
	const auto pageEnd	 = pageUrl.find( L'/', 8U) ;	// 原公式originの境界です。
	const auto scriptEnd = url.find( L'/', 8U) ;		// 原script originの境界です。
	// 任意URLや別originを保存pageのlink根拠へ混入させません。
	if( resolved != 0U || redirects != 0U || pageEnd == pageUrl.npos || scriptEnd == url.npos ||
	   pageUrl.substr( 0U, pageEnd) != url.substr( 0U, scriptEnd) ||
	   url.find_first_of( L"?#") != url.npos || validateOfficialHttpsUrl( pageUrl, hosts) != 0U ||
	   validateOfficialHttpsUrl( url, hosts) != 0U ||
	   !hasSingleStaticHtmlScriptReference( page, url, url.substr( scriptEnd))) {
		return resolved != 0U ? resolved : static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	std::wstring decoded ;	// 実行しない厳密UTF-8の一時値です。
	std::wstring finalUrl ;	// 共通HTTPが検査する同originです。
	return getLiveTextForSource( url, resourceId, cancellation, true, decoded, finalUrl, nullptr,
								&raw, true) ;
}

/** @see src/platform/official_http_client.h */
NativeError OfficialHttpClient::getLiveTextForSource(
	const std::wstring_view url, const std::wstring_view resourceId,
	const HttpCancellationCallback &cancellation, const bool script, std::wstring &text,
	std::wstring &finalUrl, std::uint64_t *const byteCount, std::string *const raw,
	const bool linkedLandingScript)
{
	text.clear() ;
	finalUrl.clear() ;
	// 原byte出力にも失敗前の古い結果を残さない。
	if( raw != nullptr) {
		raw->clear() ;
	}

	// 失敗した応答の部分byte数をpage予算の成功値へ流用しない。
	if( byteCount != nullptr) {
		*byteCount = 0U ;
	}

	// Metadata専用contextの固定endpoint・予算契約をlive遷移へ流用しない。
	if( metadataExecution_ != nullptr) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	std::span<const std::wstring_view> allowedHosts ;		// 現sessionの用途別公式host。
	std::uint32_t					   maximumRedirects{} ;	// 現resourceの有限redirect回数。
	// 現sessionの公式resource／hostの照合結果。
	const NativeError resolveError = resolveSourceHosts( resourceId, allowedHosts, maximumRedirects) ;
	// Sessionまたはresourceを解決できない要求はnetworkへ進めない。
	if( resolveError != 0) {
		return resolveError ;
	}

	// Scriptの取得ではmetadata用途とredirect禁止を追加で要求する。
	if( script &&
	   (maximumRedirects != 0U ||
		(!sourceResourceHasKind( resourceId, OfficialSourceResourceKind::METADATA) &&
		 !(linkedLandingScript &&
		   sourceResourceHasKind( resourceId, OfficialSourceResourceKind::LANDING_PAGE))))) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// Payloadや署名resourceをHTML表示用途へ読み替えない。
	if( !sourceResourceHasKind( resourceId, OfficialSourceResourceKind::LANDING_PAGE) &&
	   !sourceResourceHasKind( resourceId, OfficialSourceResourceKind::METADATA)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const OfficialHttpTransport &transport =
		testTransport_ ? *testTransport_ : NATIVE_HTTP_TRANSPORT ;	// 同一requestに固定したI/O表。
	InternetHandle			   session( nullptr) ;					// 最終hopのWinHTTP session。
	InternetHandle			   connection( nullptr) ;				// 最終hopのconnection。
	InternetHandle			   request( nullptr) ;					// 最終HTTP response。
	DWORD					   status{} ;							// 最終HTTP status。
	std::vector<std::uint32_t> originPolicyIndices ;				// 起点から最終hopの公式policy index。
	std::wstring			   receivedUrl ;						// 親だけへ返すredirect後URL。
	// 公式hopの応答開始結果。元errorを保持する。
	const NativeError		   requestError = openGetRequestFollowingRedirects(
		 url, allowedHosts, maximumRedirects, {}, cancellation, session, connection, request, status,
		 originPolicyIndices, nullptr, transport, true, &receivedUrl) ;
	// 各hopの公開宛先・同一origin・取消しに失敗した本文を公開しない。
	if( requestError != 0) {
		return requestError ;
	}

	// HTML取得は条件付き304やbinary responseを成功としない。
	if( status != HTTP_STATUS_OK) {
		return nativeErrorFromWin32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
	}

	// HTMLまたは非実行scriptの用途別MIME検証結果。
	const NativeError mimeError = validateLiveHtmlContentType( request.get(), transport, script) ;
	// Content-Type／charset確認前に本文を読み始めない。
	if( mimeError != 0) {
		return mimeError ;
	}

	const std::uint64_t maximumBytes = script ? 64U * 1024U : 2U * 1024U * 1024U ;	// 用途別raw上限。
	std::vector<std::byte> received ;												// 上限内のnetwork本文。
	// 有限raw本文の受信結果。失敗時は根拠を発行しない。
	const NativeError	   bodyError = consumeResponse(
		 request.get(), maximumBytes,
		 [&received]( const std::span<const std::byte> chunk) {
			 received.insert( received.end(), chunk.begin(), chunk.end()) ;
			 return static_cast<NativeError>( 0) ;
		 },
		 []( const std::uint64_t, const std::uint64_t) {}, cancellation, nullptr, transport, true) ;
	// 取消し、長さ超過、途中失敗を部分HTMLとして扱わない。
	if( bodyError != 0) {
		return bodyError ;
	}

	std::wstring	  decoded ;	// 厳密UTF-8から変換した一page本文。
	// 共通UTF-8変換の元HRESULT。
	const NativeError decodeError = decodeUtf8Body( received, decoded) ;
	// 不正UTF-8・埋込みNULをHTML normalizerへ渡さない。
	if( decodeError != 0) {
		return decodeError ;
	}

	std::string rawCopy ;	// Evidence確定前に割当てを完了する原byte copy。
	// Hash照合用の出力はUTF-16から再符号化せず原byteを保持する。
	if( raw != nullptr) {
		rawCopy.reserve( received.size()) ;
		// Byte順とBOMを含む応答全体をそのまま複製する。
		for( const auto byte : received) {
			rawCopy.push_back( static_cast<char>( byte)) ;
		}
	}

	// 取得根拠の確定直前に観測した取消し結果。
	const NativeError finalCancellation = checkCancellation( cancellation) ;
	// Decode完了後の取消しにも成功ledgerを発行しない。
	if( finalCancellation != 0) {
		return finalCancellation ;
	}

	// 検証済み実取得だけをsessionへ結合した結果。
	const NativeError evidenceError =
		appendSourceEvidence( resourceId, originPolicyIndices, networkObservation( false)) ;
	// 取得根拠を確定できない本文・最終URLは公開しない。
	if( evidenceError != 0) {
		return evidenceError ;
	}

	text	 = std::move( decoded) ;
	finalUrl = std::move( receivedUrl) ;
	// 成功根拠と同じ応答の原byteだけを公開する。
	if( raw != nullptr) {
		*raw = std::move( rawCopy) ;
	}

	// 成功したraw本文の実byte数だけを親の合計予算へ渡す。
	if( byteCount != nullptr) {
		*byteCount = received.size() ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialHttpClient::postFormUtf8TextForSource( const std::wstring_view url,
														  const std::wstring_view resourceId,
														  const std::string_view  formBody,
														  const std::uint64_t	  maximumBytes,
														  std::wstring			 &text)
{
	text.clear() ;
	// 初期metadata専用経路にはPOSTを登録していない。別APIへのfallbackを拒否する。
	if( metadataExecution_ != nullptr) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	std::span<const std::wstring_view> allowedHosts ;		// 用途別の組み込みhost群。
	std::uint32_t					   maximumRedirects{} ;	// 0だけを許可するpolicy値。
	const NativeError				   resolveError =
		// Policy解決結果。
		resolveSourceHosts( resourceId, allowedHosts, maximumRedirects) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( resolveError != 0) {
		return resolveError ;
	}

	// POST用途混同とredirect許可を拒否する。
	if( maximumRedirects != 0U ||
	   !sourceResourceHasKind( resourceId, OfficialSourceResourceKind::METADATA)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	std::vector<std::byte>			   bytes ;					// POST responseのUTF-8 body。
	std::vector<std::uint32_t>		   originPolicyIndices ;	// 成功した一originのopaque index。
	OfficialHttpAcquisitionObservation observation ;			// Cacheを使用しないPOSTの実取得経路。
	const NativeError				   fetchError =
		fetchPostFormResource( url, allowedHosts, formBody, maximumBytes, bytes, originPolicyIndices,
							  observation) ;	// 取得結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( fetchError != 0) {
		return fetchError ;
	}

	const NativeError decodeError = decodeUtf8Body( bytes, text) ;	// 厳密なUTF-8変換結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( decodeError != 0) {
		return decodeError ;
	}

	const NativeError evidenceError =
		// 取得根拠確定結果。
		appendSourceEvidence( resourceId, originPolicyIndices, observation) ;
	// POST の取得根拠を保持できなければ metadata 本文を破棄する。
	if( evidenceError != 0) {
		text.clear() ;
	}

	return evidenceError ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialHttpClient::downloadCatalogForSource(
	const std::wstring_view url, const std::wstring_view resourceId,
	const std::uint64_t maximumBytes, const HANDLE outputFile,
	const HttpDownloadProgressCallback &progressCallback)
{
	// 専用modeはbinary保存先handleを受理しない。
	if( metadataExecution_ != nullptr) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	std::span<const std::wstring_view> allowedHosts ;		// 用途別の組み込みhost群。
	std::uint32_t					   maximumRedirects{} ;	// Resourceに登録されたredirect上限。
	const NativeError				   resolveError =
		// Policy解決結果。
		resolveSourceHosts( resourceId, allowedHosts, maximumRedirects) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( resolveError != 0) {
		return resolveError ;
	}

	// Binary catalog では metadata と detached signature の用途だけを許可する。
	if( !sourceResourceHasKind( resourceId, OfficialSourceResourceKind::METADATA) &&
	   !sourceResourceHasKind( resourceId, OfficialSourceResourceKind::DETACHED_SIGNATURE)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	std::vector<std::uint32_t>		   originPolicyIndices ;	// 成功したopaque origin経路。
	OfficialHttpAcquisitionObservation observation ;			// 実際のnetwork／cache取得経路。
	const NativeError				   downloadError = downloadCatalogToFile(
		 url, allowedHosts, maximumRedirects, maximumBytes, outputFile, progressCallback,
		 originPolicyIndices, observation) ;	// Catalog取得結果。
	return downloadError == 0 ? appendSourceEvidence( resourceId, originPolicyIndices, observation)
							  : downloadError ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialHttpClient::downloadForSource(
	const std::wstring_view url, const std::wstring_view resourceId,
	const std::uint64_t maximumBytes, const HANDLE outputFile,
	const HttpDownloadProgressCallback &progressCallback,
	const HttpCancellationCallback	   &cancellationCallback)
{
	// 行flagやresource名にかかわらず専用modeからpayloadを取得しない。
	if( metadataExecution_ != nullptr) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	std::span<const std::wstring_view> allowedHosts ;		// 用途別の組み込みhost群。
	std::uint32_t					   maximumRedirects{} ;	// Resourceに登録されたredirect上限。
	const NativeError				   resolveError =
		// Policy解決結果。
		resolveSourceHosts( resourceId, allowedHosts, maximumRedirects) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( resolveError != 0) {
		return resolveError ;
	}

	// Payload 用 resource として登録されていない対象は取得しない。
	if( !sourceResourceHasKind( resourceId, OfficialSourceResourceKind::PAYLOAD)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	std::vector<std::uint32_t> originPolicyIndices ;	// 成功したopaque origin経路。
	const NativeError		   downloadError = downloadToFile(
		 url, allowedHosts, maximumRedirects, maximumBytes, outputFile, progressCallback,
		 cancellationCallback, originPolicyIndices) ;	// Payload取得結果。
	// Payloadはcatalog cacheを使わず、成功時だけnetwork本文の確定時刻を作る。
	const OfficialHttpAcquisitionObservation observation =
		downloadError == 0 ? networkObservation( false) : OfficialHttpAcquisitionObservation{} ;
	return downloadError == 0 ? appendSourceEvidence( resourceId, originPolicyIndices, observation)
							  : downloadError ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialHttpClient::downloadDelegatedGet(
	OfficialDelegatedGetRequest &request, const HANDLE outputFile,
	const HttpDownloadProgressCallback &progressCallback,
	const HttpCancellationCallback	   &cancellationCallback,
	OfficialPublicDestinationEvidence  &destinationEvidence)
{
	destinationEvidence = {} ;
	const OfficialHttpTransport &transport =
		testTransport_ ? *testTransport_ : NATIVE_HTTP_TRANSPORT ;	// 一requestで固定するI/O表。
	// 終端と秘密消去の成功時だけ元診断を返す失敗経路。
	const auto finishFailure = [&request]( const OfficialDownloadGrantState outcome,
										  const NativeError				   error) noexcept {
		const NativeError finishError =
			// Grantとrequestの終端結果。
			request.finish( outcome, error) ;
		return finishError == 0 ? error : finishError ;
	} ;

	// Ready request、保存先、callback、WinHTTP表、resolverのどれかが欠ければ送信しない。
	if( request.state() != OfficialDelegatedGetState::READY || outputFile == nullptr ||
	   outputFile == INVALID_HANDLE_VALUE || !progressCallback || !transport.open ||
	   !transport.connect || !transport.openRequest || !transport.setTimeouts ||
	   !transport.setOption || !transport.addHeaders || !transport.sendRequest ||
	   !transport.receiveResponse || !transport.queryHeaders || !transport.queryAvailable ||
	   !transport.readData || !transport.closeHandle || !transport.resolveDestination ||
	   (testTransport_ && !transport.utcNow)) {
		const NativeError invalid =
			// 入力またはI/O表の診断。
			static_cast<NativeError>( E_INVALIDARG) ;
		// Claim済みのREADY requestだけは失敗終端と秘密消去を必須にする。
		if( request.state() == OfficialDelegatedGetState::READY) {
			return finishFailure( OfficialDownloadGrantState::FAILED, invalid) ;
		}

		return invalid ;
	}

	std::wstring_view exactTarget ;									// Requestの一回開始中だけ借りる秘密完全URL。
	const NativeError beginError = request.beginGet( exactTarget) ;	// 一回GET開始結果。
	// 同じrequestの再開始または所有権不整合を送信しない。
	if( beginError != 0) {
		return beginError ;
	}

	try {
		const OfficialSourcePolicy *const policy = officialSourcePolicyForProvider(
			// Grantに再結合した組み込みpolicy。
			request.providerId()) ;
		const OfficialSourceResourcePolicy *const payloadResource =
			policy == nullptr
				? nullptr
				: findOfficialSourceResource(
					  *policy, request.payloadResourceId()) ;	// Cross-originで使う固定payload境界。
		const bool signedIndex = request.origin() ==
								 OfficialDownloadGrantOrigin::
									 SIGNED_INDEX_COLLECTOR_ATTESTATION ;	// 私有grantが決めた出自。
		// Grant発行後もProviderとpayload resource用途を組み込みregistryへ再照合する。
		if( !signedIndex && (policy == nullptr || payloadResource == nullptr ||
							payloadResource->kind != OfficialSourceResourceKind::PAYLOAD ||
							payloadResource->allowedHosts.empty() ||
							payloadResource->maximumRedirects > MAXIMUM_REDIRECTS)) {
			return finishFailure( OfficialDownloadGrantState::TARGET_REJECTED,
								 static_cast<NativeError>( E_ACCESSDENIED)) ;
		}

		InternetHandle	  session( nullptr) ;		// 最終responseのsystem proxy session。
		InternetHandle	  connection( nullptr) ;	// 最終responseのconnection handle。
		InternetHandle	  response( nullptr) ;		// 本文を受信する最終response handle。
		SecretOfficialUrl redirectTarget ;			// 現在のLocationから得た秘密完全URL。
		SecretOfficialUrl dynamicOrigin ;			// 未登録起点の小文字host。
		std::vector<SecretOfficialUrl>
			visitedRequests ;	// 循環検出後にzero clearするhost／path key。
		visitedRequests.reserve( MAXIMUM_REDIRECTS + 1U) ;
		std::uint32_t redirectCount{} ;			// 全originを通算した完了redirect数。
		std::uint32_t dynamicRedirectCount{} ;	// 未登録originから発生したredirect数。
		std::uint32_t fixedRedirectCount{} ;	// 固定payload originから発生したredirect数。
		std::uint32_t validatedAddressCount{} ;	// 全hopでpublicと確定したaddress合計。
		bool		  fixedRoute{} ;			// 固定payload allowlistへ移行済みの場合true。
		DWORD		  finalStatus{} ;			// 本文を読む最終HTTP status。

		// Exact targetと最大5回のLocationを順に検証し、最終responseで終了する。
		while( true) {
			const std::uint64_t hopUtcSeconds =
				testTransport_ ? transport.utcNow() : currentUtcSeconds() ;	// Hop開始直前UTC。
			const NativeError deadlineError =
				// 30秒安全余裕の再検証結果。
				request.validateStartDeadline( hopUtcSeconds) ;
			// 期限不足または時計異常後にURL解析・DNS・HTTP処理を開始しない。
			if( deadlineError != 0) {
				const OfficialDownloadGrantState outcome =
					hopUtcSeconds == 0U
						? OfficialDownloadGrantState::FAILED
						: OfficialDownloadGrantState::GRANT_EXPIRED ;	// 時計と期限を分離。
				return finishFailure( outcome, deadlineError) ;
			}

			const std::wstring_view currentTarget =
				// 現在hopの秘密URL。
				redirectCount == 0U ? exactTarget : redirectTarget.view() ;
			ParsedUrl				   parsed ;					// 現在hopの秘密host・path・query。
			const SecretParsedUrlScope parsedScope( parsed) ;	// 参照終了時にcomponentを消去。
			const NativeError		   parseError = parseHttpsUrlComponents(
				 currentTarget, parsed) ;	// HTTPS・443・credentialなしの検証結果。
			// 一hopでも基本URL構文が不正なら後続hopを作らない。
			if( parseError != 0) {
				return finishFailure( OfficialDownloadGrantState::TARGET_REJECTED, parseError) ;
			}

			// 索引由来は同じDNS／HTTPへ進む前に封印したexact URL順だけを受理する。
			if( signedIndex &&
			   request.validateSignedIndexHop( currentTarget, redirectCount, false) != 0) {
				return finishFailure( OfficialDownloadGrantState::TARGET_REJECTED, E_ACCESSDENIED) ;
			}

			std::uint32_t fixedOriginIndex{} ;	// 一意に一致した固定payload host index。
			const bool	  inFixedAllowlist =
				!signedIndex && findAllowedHostIndex( parsed.host, payloadResource->allowedHosts,
													 fixedOriginIndex) ;	// 固定origin照合結果。
			// 従来live起点のdynamic／fixed境界は索引branchの権限で変更しない。
			if( !signedIndex) {
				// 起点が固定payload hostでない場合はそのoriginを動的直結対象として固定する。
				if( redirectCount == 0U) {
					fixedRoute = inFixedAllowlist ;
					// 未登録起点のhostだけを後続の同一origin照合用に秘密保持する。
					if( !fixedRoute) {
						dynamicOrigin.replace( std::wstring{parsed.host}) ;
					}
				} else {
					// 固定payloadへ移行後はallowlist外originへ戻るredirectを拒否する。
					if( fixedRoute && !inFixedAllowlist) {
						return finishFailure( OfficialDownloadGrantState::TARGET_REJECTED,
											 static_cast<NativeError>( E_ACCESSDENIED)) ;
					}

					// Dynamic origin中は同一hostか、審査済み固定payload hostへの一方向移行だけを許可する。
					if( !fixedRoute && parsed.host != dynamicOrigin.view() && !inFixedAllowlist) {
						return finishFailure( OfficialDownloadGrantState::TARGET_REJECTED,
											 static_cast<NativeError>( E_ACCESSDENIED)) ;
					}

					// 審査済み固定hostへ到達した後はdynamic originを再許可しない。
					if( !fixedRoute && inFixedAllowlist) {
						fixedRoute = true ;
					}
				}
			}

			std::wstring requestKey = parsed.host + L"\n" + parsed.pathQuery ;	// 秘密循環検出key。
			const bool	 alreadyVisited =
				std::any_of( visitedRequests.begin(), visitedRequests.end(),
							[&requestKey]( const SecretOfficialUrl &visited) {
								return visited.view() == requestKey ;
							}) ; // Host・path・queryが完全一致する既訪問判定。
			// 同じrequest targetへの循環は回数以内でも拒否する。
			if( alreadyVisited) {
				SecureZeroMemory( requestKey.data(), requestKey.size() * sizeof( wchar_t)) ;
				return finishFailure( OfficialDownloadGrantState::TARGET_REJECTED,
									 nativeErrorFromWin32( ERROR_WINHTTP_REDIRECT_FAILED)) ;
			}

			visitedRequests.emplace_back( std::move( requestKey)) ;
			OfficialPublicDestinationEvidence hopDestination ;	// 現在hopのURL非保持宛先結果。
			const NativeError				  destinationError =
				validatePublicOfficialDestination( parsed.host, transport.resolveDestination,
												  hopDestination) ;	// 現在hopのSSRF宛先検証結果。
			// 全addressがpublicでないhopへはsystem proxy経由でも送信しない。
			if( destinationError != 0) {
				return finishFailure( OfficialDownloadGrantState::TARGET_REJECTED, destinationError) ;
			}

			validatedAddressCount += hopDestination.addressCount ;
			const NativeError cancellationError = checkCancellation(
				cancellationCallback) ;	// 現在hopのWinHTTP session作成前取消し結果。
			// 取消し後にproxyまたはdestinationへのhandleを作らない。
			if( cancellationError != 0) {
				return finishFailure( OfficialDownloadGrantState::CANCELLED, cancellationError) ;
			}

			InternetHandle	  currentSession( nullptr) ;	// 現在hopのsystem proxy session。
			InternetHandle	  currentConnection( nullptr) ;	// 現在hopのconnection handle。
			InternetHandle	  currentResponse( nullptr) ;	// 現在hopのresponse handle。
			DWORD			  currentStatus{} ;				// 現在hopのHTTP status。
			const NativeError requestError = openGetRequest(
				parsed, currentSession, currentConnection, currentResponse, {}, currentStatus,
				nullptr, transport,
				WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH) ;	// 既定credentialを使わないGET結果。
			// HTTP API失敗で部分fileを成功として閉じない。
			if( requestError != 0) {
				return finishFailure( OfficialDownloadGrantState::FAILED, requestError) ;
			}

			// Redirect以外のresponseに到達したら所有handleとstatusを本文受信へ移す。
			if( !isRedirectStatus( currentStatus)) {
				session		= std::move( currentSession) ;
				connection	= std::move( currentConnection) ;
				response	= std::move( currentResponse) ;
				finalStatus = currentStatus ;
				break ;
			}

			// Application全体の5 redirect上限を超えるLocationは読み取らない。
			if( redirectCount >= MAXIMUM_REDIRECTS) {
				return finishFailure( OfficialDownloadGrantState::TARGET_REJECTED,
									 nativeErrorFromWin32( ERROR_WINHTTP_REDIRECT_FAILED)) ;
			}

			// 固定payload originからのredirectはresourceの審査済み上限までに限る。
			if( !signedIndex && fixedRoute) {
				// 現在responseが固定resourceの上限を使い切った場合はLocationを追跡しない。
				if( fixedRedirectCount >= payloadResource->maximumRedirects) {
					return finishFailure( OfficialDownloadGrantState::TARGET_REJECTED,
										 nativeErrorFromWin32( ERROR_WINHTTP_REDIRECT_FAILED)) ;
				}

				++fixedRedirectCount ;
			}
			// 旧dynamic起点だけへ従来の2回制限を適用する。
			else if( !signedIndex) {
				// 旧dynamic起点だけへ従来の2回制限を適用する。
				// 未登録originから開始するredirectはcross-origin移行を含め最大2回に限る。
				if( dynamicRedirectCount >= 2U) {
					return finishFailure( OfficialDownloadGrantState::TARGET_REJECTED,
										 nativeErrorFromWin32( ERROR_WINHTTP_REDIRECT_FAILED)) ;
				}

				++dynamicRedirectCount ;
			}

			std::wstring	  location ;	// WinHTTP responseから取り出す未検証の秘密Location。
			const NativeError locationError = queryRedirectLocation(
				// 有限Location取得結果。
				currentResponse.get(), location, transport) ;
			// Location取得失敗時は現在responseの本文や別URLを使わない。
			if( locationError != 0) {
				return finishFailure( OfficialDownloadGrantState::TARGET_REJECTED, locationError) ;
			}

			redirectTarget.replace( std::move( location)) ;
			++redirectCount ;
		}

		const NativeError statusError = validateOfficialHttpResponseStatus(
			finalStatus, false, false) ;	// Redirect以外の最終200限定結果。
		// 401／403を含む拒否statusの本文をpayloadとして保存しない。
		if( statusError != 0) {
			const bool refreshableStatus = redirectCount == 0U &&
										   request.canReresolveExpiringTarget() &&
										   (finalStatus == HTTP_STATUS_DENIED ||
											// 最初のexpiring GETだけ再解決候補。
											finalStatus == HTTP_STATUS_FORBIDDEN) ;
			return finishFailure( refreshableStatus ? OfficialDownloadGrantState::GRANT_EXPIRED
												   : OfficialDownloadGrantState::FAILED,
								 statusError) ;
		}

		// 索引routeの途中に200を返す応答を別の最終payloadへ読み替えない。
		if( signedIndex &&
		   request.validateSignedIndexHop( redirectCount == 0U ? exactTarget : redirectTarget.view(),
										  redirectCount, true) != 0) {
			return finishFailure( OfficialDownloadGrantState::TARGET_REJECTED, E_ACCESSDENIED) ;
		}

		// 索引の期待media typeは共通の有限header readerで実最終応答へ照合する。
		if( signedIndex) {
			const auto contentType = collectorHeader( response.get(), WINHTTP_QUERY_CONTENT_TYPE,
													 transport) ;	// 原最終header。
			// 欠損・重複・形式不一致では本文を保存しない。
			if( !contentType ||
			   !matchesOfficialPayloadContentType( *contentType, request.expectedContentType())) {
				return finishFailure( OfficialDownloadGrantState::TARGET_REJECTED,
									 HRESULT_FROM_WIN32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE)) ;
			}
		}

		const NativeError receiveError = consumeResponse(
			response.get(), request.maximumBytes(),
			[outputFile]( const std::span<const std::byte> chunk) {
				DWORD written{} ;	// 今回のchunkでfileへ書込み済みのbyte数。
				// 受信chunkの書込み失敗をHTTP成功へ変換しない。
				if( WriteFile( outputFile, chunk.data(), static_cast<DWORD>( chunk.size()), &written,
							 nullptr) == FALSE) {
					return nativeErrorFromWin32( GetLastError()) ;
				}

				// Partial writeを完全なpayloadとして扱わない。
				if( written != static_cast<DWORD>( chunk.size())) {
					return nativeErrorFromWin32( ERROR_WRITE_FAULT) ;
				}

				return static_cast<NativeError>( 0) ;
			},
			progressCallback, cancellationCallback, nullptr, transport) ;
		// 取消しとそれ以外の受信／保存失敗を別のgrant結果へ保持する。
		if( receiveError != 0) {
			const NativeError cancelled =
				// 取消し固定診断。
				static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
			const OfficialDownloadGrantState outcome =
				receiveError == cancelled ? OfficialDownloadGrantState::CANCELLED
										  : OfficialDownloadGrantState::FAILED ;	// 受信終端区分。
			return finishFailure( outcome, receiveError) ;
		}

		// File systemに受信内容を固定できなければ検査用取得成功にしない。
		if( FlushFileBuffers( outputFile) == FALSE) {
			return finishFailure( OfficialDownloadGrantState::FAILED,
								 nativeErrorFromWin32( GetLastError())) ;
		}

		const NativeError finishError = request.finish(
			OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION, 0) ;	// Grant成功と秘密URL消去結果。
		// Request終端を固定できなければ受信成功だけを返さない。
		if( finishError != 0) {
			return finishError ;
		}

		destinationEvidence.addressCount	= validatedAddressCount ;
		destinationEvidence.locallyResolved = true ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return finishFailure( OfficialDownloadGrantState::FAILED,
							 static_cast<NativeError>( E_OUTOFMEMORY)) ;
	} catch( ...) {
		// Callbackや内部境界の未知例外をworker外へ漏らさずgrantを閉じる。
		return finishFailure( OfficialDownloadGrantState::FAILED, static_cast<NativeError>( E_FAIL)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialHttpClient::getUtf8Text( const std::wstring_view					 url,
											const std::span<const std::wstring_view> allowedHosts,
											const std::uint32_t maximumRedirects,
											const std::uint64_t maximumBytes, std::wstring &text,
											std::vector<std::uint32_t>		   &originPolicyIndices,
											OfficialHttpAcquisitionObservation &observation) const
{
	text.clear() ;
	originPolicyIndices.clear() ;
	observation = {} ;
	std::vector<std::byte> bytes ;	// Cacheまたはnetworkから取得したUTF-8 body。
	const std::uint64_t	   effectiveLimit =
		   metadataExecution_ != nullptr ? std::min( maximumBytes, MetadataSearchLimits{}.resourceBytes)
										 : maximumBytes ;	// Cache読取りも固定上限以内。
	const NativeError fetchError =							// Cacheを含むcatalog取得結果。
		fetchCatalogResource(
			useCatalogCache_, url, allowedHosts, maximumRedirects, effectiveLimit,
			[]( const std::uint64_t, const std::uint64_t) {}, bytes, originPolicyIndices,
			observation, metadataExecution_,
			testTransport_ ? *testTransport_ : NATIVE_HTTP_TRANSPORT, testCacheAccess_) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( fetchError != 0) {
		return fetchError ;
	}

	return decodeUtf8Body( bytes, text) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialHttpClient::downloadCatalogToFile(
	const std::wstring_view url, const std::span<const std::wstring_view> allowedHosts,
	const std::uint32_t maximumRedirects, const std::uint64_t maximumBytes, const HANDLE outputFile,
	const HttpDownloadProgressCallback &progressCallback,
	std::vector<std::uint32_t>		   &originPolicyIndices,
	OfficialHttpAcquisitionObservation &observation) const
{
	originPolicyIndices.clear() ;
	observation = {} ;
	// 出力 handle、callback、redirect・取得上限の不正を保存前に拒否する。
	if( outputFile == nullptr || outputFile == INVALID_HANDLE_VALUE || !progressCallback ||
	   maximumRedirects > MAXIMUM_REDIRECTS || maximumBytes == 0) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::vector<std::byte> content ;	// Cacheまたはnetworkから取得したbinary catalog。
	const NativeError	   fetchError =	// Catalog取得とcache検証結果。
		fetchCatalogResource( useCatalogCache_, url, allowedHosts, maximumRedirects, maximumBytes,
							 progressCallback, content, originPolicyIndices, observation) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( fetchError != 0) {
		return fetchError ;
	}

	// WriteFile の長さ範囲を超える catalog は narrowing せず拒否する。
	if( content.size() > std::numeric_limits<DWORD>::max()) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	DWORD written{} ;	// WriteFileが保存したcatalog byte数。
	// Catalog 本文の書込み失敗を Windows の診断値で返す。
	if( WriteFile( outputFile, content.data(), static_cast<DWORD>( content.size()), &written,
				 nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 本文の全 byte を保存できなければ書込み成功と扱わない。
	if( written != static_cast<DWORD>( content.size())) {
		return nativeErrorFromWin32( ERROR_WRITE_FAULT) ;
	}

	// Catalog 出力の flush 失敗も保存失敗として返す。
	if( FlushFileBuffers( outputFile) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_http_client.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialHttpClient::downloadToFile(
	const std::wstring_view url, const std::span<const std::wstring_view> allowedHosts,
	const std::uint32_t maximumRedirects, const std::uint64_t maximumBytes, const HANDLE outputFile,
	const HttpDownloadProgressCallback &progressCallback,
	const HttpCancellationCallback	   &cancellationCallback,
	std::vector<std::uint32_t> &originPolicyIndices, const bool collectorInspection,
	CollectorHttpTransferObservation *transfer) const
{
	originPolicyIndices.clear() ;
	CollectorHttpTransferObservation ignored ;	// 観測不要の旧callerにも同じ保存処理を使います。
	CollectorHttpTransferRecorder	 recorder(
		   transfer != nullptr ? *transfer : ignored,
		CollectorHttpTransferStage::PAYLOAD) ;	// 完了はflush後だけです。
	// 無効な保存先と取得 policy・callback の不備を送信前に拒否する。
	if( maximumRedirects > MAXIMUM_REDIRECTS || maximumBytes == 0 || outputFile == nullptr ||
	   outputFile == INVALID_HANDLE_VALUE || !progressCallback ||
	   (transfer != nullptr && !collectorInspection) ||
	   (collectorInspection && maximumRedirects > 2U)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const NativeError cancellationError =
		// Network開始前の取消し確認結果。
		checkCancellation( cancellationCallback) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( cancellationError != 0) {
		return cancellationError ;
	}

	InternetHandle	  session( nullptr) ;		// Requestと同じ期間保持するsession handle。
	InternetHandle	  connection( nullptr) ;	// Requestと同じ期間保持するconnection handle。
	InternetHandle	  request( nullptr) ;		// Response bodyを読み取るrequest handle。
	DWORD			  status{} ;				// Payload requestで許可するHTTP 200 status。
	const auto		 &transport	   = collectorInspection && testTransport_
										 ? *testTransport_
										 : NATIVE_HTTP_TRANSPORT ;	// 旧経路へ試験表を流用しない。
	const NativeError requestError = openGetRequestFollowingRedirects(
		url, allowedHosts, maximumRedirects, {}, cancellationCallback, session, connection, request,
		status, originPolicyIndices, nullptr, transport, collectorInspection, nullptr,
		collectorInspection, collectorInspection ? &recorder : nullptr) ;	// 新収集検査だけの観測。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( requestError != 0) {
		return requestError ;
	}

	const NativeError statusError =	// Payload最終応答も200だけを許可し、部分応答を拒否する。
		validateOfficialHttpResponseStatus( status, false, false) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( statusError != 0) {
		return statusError ;
	}

	const NativeError receiveError = consumeResponse(
		request.get(), maximumBytes,
		[outputFile]( const std::span<const std::byte> chunk) {
			DWORD written{} ;	// WriteFileが保存したchunk byte数。
			// 受信 chunk の書込み失敗時は payload 保存を中止する。
			if( WriteFile( outputFile, chunk.data(), static_cast<DWORD>( chunk.size()), &written,
						 nullptr) == FALSE) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			// Chunk の一部しか書けなければ完全な payload として扱わない。
			if( written != static_cast<DWORD>( chunk.size())) {
				return nativeErrorFromWin32( ERROR_WRITE_FAULT) ;
			}

			return static_cast<NativeError>( 0) ;
		},
		progressCallback, cancellationCallback, nullptr, transport, collectorInspection, nullptr,
		collectorInspection ? &recorder : nullptr) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( receiveError != 0) {
		return receiveError ;
	}

	// 保存終了前の取消しとcallback障害を元診断のまま保持します。
	if( collectorInspection) {
		const auto cancelled = checkCancellation( cancellationCallback) ;	// 同終端の元診断です。
		// Callback例外のE_UNEXPECTEDを取消しへ置き換えません。
		if( cancelled != 0) {
			return cancelled ;
		}
	}

	auto flush = &FlushFileBuffers ;	// 同じ取得handleの全保存を確定するOS境界です。
#ifdef DRIVERCRATE_REGISTRY_JOB_TESTING
	// 故障注入は専用targetの収集保存だけへ限定します。
	if( collectorInspection && collectorFlushProbe_ != nullptr) {
		flush = collectorFlushProbe_ ;
	}
#endif
	// Payload 出力を flush できなければ取得完了を返さない。
	if( flush( outputFile) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// Flush待機中の取消しを完全精算へ進めません。
	if( collectorInspection) {
		const auto cancelled = checkCancellation( cancellationCallback) ;	// 終端の同じ停止です。
		// 停止診断を成功に上書きしません。
		if( cancelled != 0) {
			return cancelled ;
		}

		recorder.complete() ;
	}

	return 0 ;
}

/** @see OfficialHttpClient 宣言側の契約を正本とする。 */
NativeError OfficialHttpClient::getCollectorInspectionPage(
	std::wstring_view url, std::wstring_view host, const HttpCancellationCallback &cancellation,
	std::wstring &text, std::wstring &finalUrl, CollectorInspectionPageObservation *observation,
	CollectorHttpTransferObservation *transfer, std::vector<std::byte> *raw)
{
	text.clear() ;
	finalUrl.clear() ;
	CollectorHttpTransferObservation ignored ;	// 旧callerも実I/Oの意味は同じです。
	CollectorHttpTransferRecorder	 recorder(
		   transfer != nullptr ? *transfer : ignored,
		CollectorHttpTransferStage::PAGE) ;	// 未送信を含めUNKNOWNから始めます。
	// 原本文を旧proofから引き継ぎません。
	if( raw != nullptr) {
		raw->clear() ;
	}

	// 失敗や再使用時に以前の成功観測を残しません。
	if( observation != nullptr) {
		*observation = {} ;
	}

	const std::array<std::wstring_view, 1U> hosts{host} ;	// 外部定義のexact一hostだけ。
	// Cache・metadata専用・旧ledger付きclientを収集scopeへ流用しない。
	if( useCatalogCache_ || metadataExecution_ != nullptr || sourceScanSessionId_ != 0U ||
	   validateOfficialHttpsUrl( url, hosts) != 0) {
		return E_ACCESSDENIED ;
	}

	const auto &transport = testTransport_ ? *testTransport_ : NATIVE_HTTP_TRANSPORT ;	// 同じI/O表。
	// 不完全fixtureをnativeで補完せず、HTTP handle作成前に拒否する。
	if( !transport.open || !transport.connect || !transport.openRequest || !transport.setTimeouts ||
	   !transport.setOption || !transport.addHeaders || !transport.sendRequest ||
	   !transport.receiveResponse || !transport.queryHeaders || !transport.queryAvailable ||
	   !transport.readData || !transport.closeHandle || !transport.resolveDestination) {
		return E_INVALIDARG ;
	}

	InternetHandle			   session( nullptr) ;		// 全returnで回収するHTTP所有者。
	InternetHandle			   connection( nullptr) ;	// 同じ起点の接続。
	InternetHandle			   request( nullptr) ;		// 最終response。
	DWORD					   status{} ;				// 成功200だけを本文へ渡す。
	std::vector<std::uint32_t> origins ;				// 非永続の最大三hop。
	std::wstring			   receivedUrl ;			// 同じ応答の相対link base。
	auto					   error = openGetRequestFollowingRedirects(
		  url, hosts, 2U, {}, cancellation, session, connection, request, status, origins, nullptr,
		  transport, true, &receivedUrl, true, &recorder) ;	// 共通GET。
	// 同一origin・全public・HTTP200確認前に本文を認定しない。
	if( error != 0 || status != HTTP_STATUS_OK) {
		return error != 0 ? error : HRESULT_FROM_WIN32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
	}

	error = validateLiveHtmlContentType( request.get(), transport, false, true) ;
	// HTML以外・不正charsetは有限受信前に拒否する。
	if( error != 0) {
		return error ;
	}

	std::vector<std::byte> body ;	// 上限2 MiBの原HTTP本文。
	error = consumeResponse(
		request.get(), 2ULL * 1024ULL * 1024ULL,
		[&body]( const std::span<const std::byte> chunk) {
			body.insert( body.end(), chunk.begin(), chunk.end()) ;
			return static_cast<NativeError>( 0) ;
		},
		[]( std::uint64_t, std::uint64_t) {}, cancellation, nullptr, transport, true, nullptr,
		&recorder) ;
	// 部分本文をparserへ渡さない。
	if( error != 0) {
		return error ;
	}

	std::wstring decoded ;	// 全復号後だけ公開する本文。
	error = decodeUtf8Body( body, decoded) ;
	// 不正UTF-8・取消し後には成功本文を設定しない。
	if( error == 0) {
		error = checkCancellation( cancellation) ;
	}

	std::wstring bodyHash ;	// 任意観測を要求した同原byteだけのhashです。
	// 復号後文字列を再encodeして原HTTP hashと取り違えません。
	if( error == 0 && observation != nullptr) {
		// std::byte領域を文字aliasで借用し、同じ原byteを変更せずCNGへ渡します。
		error = computeCollectorMetadataSha256(
			{reinterpret_cast<const char *>( body.data()), body.size()}, bodyHash) ;
	}

	// 実受信・MIME・全復号成功後だけ同じcallerへ渡す。
	if( error == 0) {
		text	 = std::move( decoded) ;
		finalUrl = std::move( receivedUrl) ;
		// 同じ取得で確定した有限値だけを公開します。
		if( observation != nullptr) {
			observation->httpStatus = status ;
			observation->bodyBytes	= body.size() ;
			observation->bodySha256 = std::move( bodyHash) ;
			observation->observedAtUtc =
				std::chrono::floor<std::chrono::seconds>( std::chrono::system_clock::now()) ;
			observation->finalUrl = finalUrl ;
			observation->requestCount =
				transfer != nullptr ? transfer->attemptedRequests() : ignored.attemptedRequests() ;
		}

		// 完全な同一取得の原byteだけをproof所有者へ移します。
		if( raw != nullptr) {
			*raw = std::move( body) ;
		}

		recorder.complete() ;
	}

	return error ;
}

/** @see OfficialHttpClient 宣言側の契約を正本とします。 */
NativeError OfficialHttpClient::getSignedIndexTermsDocument(
	const std::wstring_view url, const std::wstring_view host, const std::uint64_t exactBytes,
	const bool html, const HttpCancellationCallback &cancellation, std::string &raw,
	std::wstring &text)
{
	raw.clear() ;
	text.clear() ;
	const std::array<std::wstring_view, 1U> hosts{host} ;	// 元adapterが検証した一hostだけです。
	// 規約用途をcacheや既存source ledgerへ混入せず、元有限容量を必要とします。
	if( useCatalogCache_ || metadataExecution_ != nullptr || sourceScanSessionId_ != 0U ||
	   exactBytes == 0U || exactBytes > 256ULL * 1024ULL ||
	   validateOfficialHttpsUrl( url, hosts) != 0U) {
		return E_ACCESSDENIED ;
	}

	const auto &transport =
		testTransport_ ? *testTransport_ : NATIVE_HTTP_TRANSPORT ;	// 同元I/Oです。
	// 完全fixtureの欠損をnativeの通信で補完しません。
	if( !transport.open || !transport.connect || !transport.openRequest || !transport.setTimeouts ||
	   !transport.setOption || !transport.addHeaders || !transport.sendRequest ||
	   !transport.receiveResponse || !transport.queryHeaders || !transport.queryAvailable ||
	   !transport.readData || !transport.closeHandle || !transport.resolveDestination) {
		return E_INVALIDARG ;
	}

	InternetHandle			   session( nullptr) ;		// 同期GETの所有sessionです。
	InternetHandle			   connection( nullptr) ;	// 同originの所有接続です。
	InternetHandle			   request( nullptr) ;		// exact応答の所有handleです。
	DWORD					   status{} ;				// HTTP200だけを受理します。
	std::vector<std::uint32_t> origins ;				// redirect0の原宛先検証結果です。
	auto error = openGetRequestFollowingRedirects( url, hosts, 0U, {}, cancellation, session,
												  connection, request, status, origins, nullptr,
												  transport, true, nullptr, true) ;	// 共通GETです。
	// 全public DNSと応答成立の前に規約本文を認定しません。
	if( error != 0U || status != HTTP_STATUS_OK) {
		return error != 0U ? error
						   : static_cast<NativeError>(
								 HRESULT_FROM_WIN32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE)) ;
	}

	const auto mime =
		// 全同名headerです。
		collectorHeader( request.get(), WINHTTP_QUERY_CONTENT_TYPE, transport) ;
	// HTMLは別の共通MIME検査へ進め、plainのexact MIME契約を保持します。
	if( !mime || (html ? validateLiveHtmlContentType( request.get(), transport, false) != 0U
					  : *mime != L"text/plain; charset=utf-8")) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
	}

	std::vector<std::byte> body ;	// 元exact容量以下のRAM原byteです。
	const std::uint64_t	   maximumBytes =
		   html ? 256ULL * 1024ULL : exactBytes ;	// 明示用途別の原byte上限です。
	error = consumeResponse(
		request.get(), maximumBytes,
		[&body]( const std::span<const std::byte> chunk) {
			body.insert( body.end(), chunk.begin(), chunk.end()) ;
			return static_cast<NativeError>( 0U) ;
		},
		[]( std::uint64_t, std::uint64_t) {}, cancellation, nullptr, transport,
		true) ;	// 同期中だけbodyを借用します。
	// 部分本文や元長不一致を同意不要へ変換しません。
	if( error != 0U || body.empty() || (!html && body.size() != exactBytes)) {
		return error != 0U ? error : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CRC)) ;
	}

	std::wstring decoded ;	// 全byte受信後だけの厳密UTF-8出力です。
	error = decodeUtf8Body( body, decoded) ;
	// 取消し後に全文を発行しません。
	if( error == 0U) {
		error = checkCancellation( cancellation) ;
	}

	// 全共通検証成立後だけRAMの原byteと全文を一緒に返します。
	if( error == 0U) {
		raw.assign( reinterpret_cast<const char *>( body.data()),
				   // 非所有byte境界のlossless表現です。
				   body.size()) ;
		text = std::move( decoded) ;
	}

	return error ;
}

/** @see OfficialHttpClient宣言側の契約を正本とします。 */
NativeError OfficialHttpClient::getSignedIndexCurrent( SignedIndexHttpControl &control,
													  std::vector<std::byte> &raw,
													  std::uint32_t			 &status)
{
	return getSignedIndexBytes(
		L"https://raw.githubusercontent.com/EnterOgawa/drivercrate/driver-index/index/current.json",
		SignedIndexRole::CURRENT, INDEX_ENVELOPE_MAX_BYTES, control, raw, status) ;
}
/** @see OfficialHttpClient宣言側の契約を正本とします。 */
NativeError OfficialHttpClient::getSignedIndexAsset( const AuthenticatedIndexManifest &manifest,
													SignedIndexHttpControl			 &control,
													std::vector<std::byte>			 &raw,
													std::uint32_t					 &status)
{
	const auto &asset = manifest.data().asset ;	// 署名済みのimmutable識別だけです。
	// Move元や任意asset名を固定Release以外へ投影しません。
	if( asset.tag.empty() || asset.name != "index.json.gz" || asset.sizeBytes == 0U ||
	   asset.sizeBytes > INDEX_ASSET_MAX_BYTES) {
		raw.clear() ;
		status = 0 ;
		return E_INVALIDARG ;
	}

	const std::wstring url = L"https://github.com/EnterOgawa/drivercrate/releases/download/" +
							 std::wstring( asset.tag.begin(), asset.tag.end()) +
							 L"/index.json.gz" ;	// Codec認証済みASCII tagです。
	return getSignedIndexBytes( url, SignedIndexRole::GZIP, asset.sizeBytes, control, raw, status) ;
}
/** @see OfficialHttpClient宣言側の契約を正本とします。 */
NativeError OfficialHttpClient::getSignedIndexManifestAsset(
	const AuthenticatedIndexManifest &manifest, SignedIndexHttpControl &control,
	std::vector<std::byte> &raw, std::uint32_t &status)
{
	const auto &asset = manifest.data().asset ;	// Codecで認証済みのimmutable tagです。
	// Move済みreceiptや異なるassetを固定manifest取得へ流用しません。
	if( asset.tag.empty() || asset.name != "index.json.gz") {
		raw.clear() ;
		status = 0U ;
		return E_INVALIDARG ;
	}

	const std::wstring url = L"https://github.com/EnterOgawa/drivercrate/releases/download/" +
							 std::wstring( asset.tag.begin(), asset.tag.end()) +
							 L"/manifest.json" ;	// 任意URL入力なしです。
	return getSignedIndexBytes( url, SignedIndexRole::MANIFEST, INDEX_ENVELOPE_MAX_BYTES, control,
							   raw, status) ;
}
/** @see OfficialHttpClient宣言側の契約を正本とします。 */
NativeError OfficialHttpClient::getSignedIndexBytes(
	const std::wstring_view url, const SignedIndexRole role, const std::uint64_t maximumBytes,
	SignedIndexHttpControl &control, std::vector<std::byte> &raw, std::uint32_t &status)
{
	raw.clear() ;
	status			   = 0 ;
	const bool current = role == SignedIndexRole::CURRENT ;	// 通常currentのredirect0を維持します。
	// 署名索引の用途を通常cache、metadata context、Provider ledgerへ混入しません。
	if( useCatalogCache_ || metadataExecution_ != nullptr || sourceScanSessionId_ != 0U ||
	   maximumBytes == 0U) {
		return E_ACCESSDENIED ;
	}

	const auto &transport =
		testTransport_ ? *testTransport_ : NATIVE_HTTP_TRANSPORT ;	// 同一所有者の全I/O表です。
	// Fixture欠損をnative通信で補完しません。
	if( !transport.open || !transport.connect || !transport.openRequest || !transport.setTimeouts ||
	   !transport.setOption || !transport.addHeaders || !transport.sendRequest ||
	   !transport.receiveResponse || !transport.queryHeaders || !transport.queryAvailable ||
	   !transport.readData || !transport.closeHandle || !transport.resolveDestination) {
		return E_INVALIDARG ;
	}

	const std::array<std::wstring_view, 3U> hosts{
		L"raw.githubusercontent.com", L"github.com",
		L"release-assets.githubusercontent.com"} ;		// 索引用途だけのexact originです。
	std::wstring					 currentUrl( url) ;	// 期限付きqueryはこの同期処理のRAMだけです。
	std::unordered_set<std::wstring> visited ;			// 同じURLへの循環を送信前に拒否します。
	std::vector<std::uint32_t>		 origins ;			// 固有hopだけの非機密な検査indexです。
	// Currentは一回、assetは最大三redirectの四hopで必ず終了します。
	for( std::uint32_t hop = 0U; hop < 4U; ++hop) {
		// DNS/handle生成前に同じ停止を確認します。
		if( control.checkpoint() != 0) {
			return control.stopped ;
		}

		ParsedUrl			 parsed ;				// 共通parserが検査した借用先です。
		SecretParsedUrlScope clearParsed( parsed) ;	// CDN queryを通常stateへ残しません。
		auto				 error = appendValidatedRouteUrl( currentUrl, hosts, visited, origins,
															 parsed) ;	// 共通HTTPS/host/循環検査です。
		// 用途違い、任意port、current redirect、CDNからGitHubへの逆戻りを送信前に拒否します。
		if( error != 0 || parsed.port != INTERNET_DEFAULT_HTTPS_PORT ||
		   (current && (hop != 0U || parsed.host != hosts[0] || currentUrl != url)) ||
		   (!current &&
			((hop == 0U && parsed.host != hosts[1]) || (hop != 0U && parsed.host != hosts[2])))) {
			return error != 0 ? error : static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		OfficialPublicDestinationEvidence destination ;	// URLを持たない全address検査結果です。
		error = validatePublicOfficialDestination( parsed.host, transport.resolveDestination,
												  destination) ;
		// Private/DNS拒否を別の接続やcacheへ迂回しません。
		if( error != 0) {
			return error ;
		}

		// Resolver待機中の取消し・期限を送信前に再確認します。
		if( control.checkpoint() != 0) {
			return control.stopped ;
		}

		InternetHandle session( nullptr) ;		// 現hopだけの所有sessionです。
		InternetHandle connection( nullptr) ;	// 現hopだけの所有接続です。
		InternetHandle request( nullptr) ;		// 現hopだけの所有requestです。
		DWORD		   observed{} ;				// ABIに合うHTTP status格納先です。
		error  = openGetRequest( parsed, session, connection, request, {}, observed, nullptr,
								transport, WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH, true, &control) ;
		status = observed ;
		// 元HTTP/WinHTTP診断を保持し、部分本文を返しません。
		if( error != 0) {
			return error ;
		}

		// 索引のredirectだけをexact CDNへ有限追跡します。
		if( isRedirectStatus( observed)) {
			// Currentは追跡0、assetも上限到達時に追加送信しません。
			if( current || hop >= 3U) {
				return nativeErrorFromWin32( ERROR_WINHTTP_REDIRECT_FAILED) ;
			}

			std::wstring location ;	// 同一応答の未検査Locationです。
			error = queryRedirectLocation( request.get(), location, transport) ;
			// 欠損・過大・不正Locationで別導線を探索しません。
			if( error != 0) {
				return error ;
			}

			currentUrl = std::move( location) ;
			continue ;
		}

		// 無条件GETの304やHTML errorをfresh成功にしません。
		if( observed != HTTP_STATUS_OK) {
			return nativeErrorFromWin32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
		}

		const auto mime		= collectorHeader( request.get(), WINHTTP_QUERY_CONTENT_TYPE,
											  transport) ;	// 全同名MIMEを厳密照合します。
		const auto encoding = collectorHeader( request.get(), WINHTTP_QUERY_CONTENT_ENCODING,
											  transport) ;	// 圧縮転送の自動解釈をしません。
		// 未知encoding、HTML、MIME parameter差を拒否します。
		if( !mime || !encoding || (!encoding->empty() && *encoding != L"identity") ||
		   (current ? !(matchesOfficialPayloadContentType( *mime, L"application/json") ||
						matchesOfficialPayloadContentType( *mime, L"text/plain"))
					: (role == SignedIndexRole::MANIFEST
						   ? !(matchesOfficialPayloadContentType( *mime, L"application/json") ||
							   *mime == L"application/octet-stream")
						   : !(*mime == L"application/gzip" || *mime == L"application/x-gzip" ||
							   *mime == L"application/octet-stream")))) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		std::vector<std::byte>		   body ;	// 上限+1 probeをconsumerへ渡さない所有本文です。
		const HttpCancellationCallback cancellation = [&control]() {
			return control.checkpoint() != 0 ;
		} ; // 元停止はcontrol側へ保持します。
		error = consumeResponse(
			request.get(), maximumBytes,
			[&body]( const std::span<const std::byte> chunk) {
				body.insert( body.end(), chunk.begin(), chunk.end()) ;
				return static_cast<NativeError>( 0) ;
			},
			[]( std::uint64_t, std::uint64_t) {}, cancellation, nullptr, transport, true, &control) ;
		// 期限・取消しは共通bool callbackによる診断へ丸めません。
		if( control.checkpoint() != 0) {
			return control.stopped ;
		}

		// 部分受信・長さ矛盾・空本文は発行しません。
		if( error != 0 || body.empty()) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		raw = std::move( body) ;
		return 0 ;
	}

	return nativeErrorFromWin32( ERROR_WINHTTP_REDIRECT_FAILED) ;
}

} // namespace drivercrate
