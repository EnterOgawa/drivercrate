//------------------------------------------------------------------------------
/**
 * @file official_http_client.h
 * @brief 公式配布元限定HTTP client定義。
 * @version 01.16.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Resourceごとの実取得経路と時刻を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  URL policy検証公開。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Catalog cacheとETag再検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  UTF-8 BOM除去追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Scan session取得根拠記録追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  有限redirect経路検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Payload取得取消し境界追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  固定form POSTのmetadata取得を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  HTTP status診断の共通契約を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
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
 * Ver.01.04.00 Shunji Ogawa  2026/09/22  実HTML専用の公開宛先・MIME・取消しGET契約を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/09/22  Live page session用の実受信byte数を返す。
 * Ver.01.05.01 Shunji Ogawa  2026/09/22  Live探索開始前のsource session照合を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/09/23  全区間取得接続と公式module根拠付き許諾境界を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/09/25  取得grantを発行しない収集用304応答を追加。
 * Ver.01.08.00 Shunji Ogawa  2026/09/25  429／503の有限Retry-After観測を追加。
 * Ver.01.09.00 Shunji Ogawa  2026/09/27  台帳非依存の有限収集HTTP入口を追加。
 * Ver.01.10.00 Shunji Ogawa  2026/10/06  収集検査のprivate共通HTTP経路を追加。
 * Ver.01.11.00 Shunji Ogawa  2026/10/12  署名索引の共通取得境界と既存経路の区別を追加。
 * Ver.01.12.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.12.01 Shunji Ogawa  2026/10/12  default/delete宣言の所有権と非実行契約を補足。
 * Ver.01.12.02 Shunji Ogawa  2026/10/13  観測field説明を完全な宣言開始前へ配置。
 * Ver.01.13.00 Shunji Ogawa  2026/10/14  明示収集だけへ検証済み200原byteを返す。
 * Ver.01.14.00 Shunji Ogawa  2026/10/14  共通HTML許諾と監視側の一意な非実行script参照を追加。
 * Ver.01.15.00 Shunji Ogawa  2026/10/15  期待媒体型と単一UTF-8 charsetの非変換照合を追加。
 * Ver.01.15.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.16.00 Shunji Ogawa  2026/10/16  固定署名索引の匿名GETと共通期限境界を追加。
 * </pre>
 *
 * @note HTTPS、host allowlist、応答上限を強制して公式metadataとpayloadを取得します。Catalogだけを期限とETag付きでcacheし、payloadは保
 *       存しません。Form POSTは有限なASCII bodyを送信し、cacheせず取得根拠を記録します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_source_policy.h"
#include "core/update_types.h"
#include "platform/official_delegated_http_request.h"
#include "platform/official_http_transport.h"

#include <Windows.h>

#include <cstdint>
#include <cstddef>
#include <chrono>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

/** @brief 期待媒体型と単一UTF-8 charsetだけを有限な原headerへ照合します。
 * @param[in] value 重複を結合済みのContent-Type原値です。最大256文字の印字可能ASCIIです。
 * @param[in] expected 署名recordが指定した空でない媒体型です。parameterや複数値を含めません。
 * @return 基底型の完全一致と、省略または単一UTF-8 charsetだけの場合trueです。
 * @note 通信・文字変換を行いません。未知parameter・重複・複数値・制御文字を拒否します。
 */
[[nodiscard]] bool matchesOfficialPayloadContentType( std::wstring_view value,
													 std::wstring_view expected) noexcept ;

/** @brief Workerが所有するmetadata専用の予算と取消し状態。 */
class MetadataSearchExecutionContext ;
class OfficialCollectorHttpControl ;
struct OfficialCollectorDnsApi ;
class LocalCollectorHttpClient ;
class CollectorInspectionAcquisition ;
class AuthenticatedIndexManifest ;
namespace signed_index_refresh_detail {
struct Access ;
}

//------------------------------------------------------------------------------
// HTTP型定義。
//------------------------------------------------------------------------------

/**
 * @brief Download済みbyte数とContent-Lengthを通知する関数。
 */
using HttpDownloadProgressCallback = std::function<void( std::uint64_t, std::uint64_t)> ;

/**
 * @brief trueを返した時点でpayload取得を安全に中止する確認関数。
 */
using HttpCancellationCallback = std::function<bool()> ;

/** @brief 固定索引二resourceだけで共有する90秒の協調停止状態です。 */
struct SignedIndexHttpControl {
	/// 所有workerの非blocking取消し確認先です。
	HttpCancellationCallback							   cancellation ;
	/// 製品はsteady_clock、内部fixtureは完全fakeの単調時計です。
	std::function<std::chrono::steady_clock::time_point()> monotonicNow ;
	/// 同一refreshの固定終端です。途中で延長しません。
	std::chrono::steady_clock::time_point				   deadline ;
	/// 実send開始回数です。上限5を送信前に確認します。
	std::uint32_t										   sends{} ;
	/// 受信した原byte数です。拒否probeも含みます。
	std::uint64_t										   receivedBytes{} ;
	/// 最初の取消し・期限・時計障害を保持します。
	NativeError											   stopped{} ;
	/** @brief 同じ取消しと単調期限を再確認します。
	 * @return 継続0、停止時は最初の元HRESULTです。
	 */
	[[nodiscard]] NativeError							   checkpoint() noexcept ;
	/** @brief 同期APIのtimeoutを正の残millisecondへ制限します。
	 * @param[in] maximum 既存phaseの正の上限です。
	 * @return 継続時の正数。停止時0はAPIへ渡しません。
	 */
	[[nodiscard]] int timeoutMilliseconds( int maximum) noexcept ;
} ;

/** @brief 一回のHTTP／cache処理から確定した非機密な取得経路である。 */
struct OfficialHttpAcquisitionObservation {
	/// 実際に本文を得た経路。
	MeasurementAcquisition		 acquisition{MeasurementAcquisition::UNKNOWN} ;
	/// Network本文を取得したUTC。Cacheでは空を許す。
	std::optional<std::uint64_t> bodyAcquiredUtcSeconds ;
	/// Origin応答または保存済み検証のUTC。
	std::optional<std::uint64_t> originValidatedUtcSeconds ;
	/// このresource取得でcacheを許可した場合だけtrue。
	bool						 cachePermitted{} ;
} ;

/** @brief 収集専用GETの観測です。304には本文取得根拠を付与しません。 */
struct CollectorHttpObservation {
	/// 429／503の再試行待ち秒数。日付・欠損時は0。
	std::uint64_t retryAfterDelaySeconds{} ;
	/// 429／503の絶対UTC指定。秒数・欠損時は0。
	std::uint64_t retryAfterUtcSeconds{} ;
	/// 重複、不明形式、上限超過の待機指定で自動再試行を止める場合true。
	bool		  retryAfterNeedsReview{} ;
	/// HTTP 200または304。HTTP errorの場合も数値を保持し、未受信は0です。
	std::uint32_t status{} ;
	/// 次回送信可能な単一ETag。再検証できない応答では空です。
	std::wstring  entityTag ;
	/// 200の原byte SHA-256。304・失敗は空です。
	std::wstring  bodySha256 ;
} ;

/** @brief 新制御付きGETだけの観測です。旧応答の時刻表現を変更しません。 */
struct CollectorControlledHttpObservation : CollectorHttpObservation {
	/// Header観測UTCへ一回結合した待機期限。欠損・要確認はnull、明示0秒も観測時刻を保持します。
	std::optional<std::uint64_t> retryAfterUtcMillis ;
} ;

/** @brief 収集台帳に保存できる有限ETag構文を検証します。
 * @param[in] value 単一の引用符付きASCII tag。空と複数tagを拒否します。
 * @return ADR 0212の文字集合と256文字上限を満たす場合true。
 */
[[nodiscard]] bool		  isCollectorEntityTag( std::wstring_view value) noexcept ;

/**
 * @brief 受信済みHTTP statusを検証し、拒否statusをHRESULTに保持する。
 * 受信済みHTTP statusの受理条件と拒否診断値を確定する。
 * ADR 0133のstatusだけを受理し、通信・本文読取りを行わない。元のWinHTTP API errorをこの関数へ入力してはならない。
 * @param[in] status HTTP responseの数値status。100～599以外は不正値とする。 受信済みの数値status。100～599が有効範囲。
 * @param[in] allowNotModified If-None-Matchを送信したGETの場合だけtrue。 条件付きGETの場合だけtrue。
 * @param[in] allowRedirects 後段でLocationを検証するGETの各hopの場合だけtrue。 後段でLocationを検証する場合だけtrue。
 * @return 受理時は0。拒否時はFACILITY_HTTPとstatusを持つ失敗HRESULT。数値が不正な場合はWinHTTPの
 *         ERROR_WINHTTP_INVALID_SERVER_RESPONSE由来HRESULT。 受理時0、拒否時はHTTP statusを保持する失敗HRESULT。不正数値はWinHTTP無効
 *         応答error由来のHRESULT。
 * @note 200、明示許可時の304、301／302／303／307／308だけを受理する。受理は本文検証、redirect先の許可、cache整合性、取得根拠の成立を意味しない。
 */
[[nodiscard]] NativeError validateOfficialHttpResponseStatus( std::uint32_t status,
															 bool		   allowNotModified,
															 bool		   allowRedirects) noexcept ;

/**
 * @brief 絶対HTTPS URLが公式host allowlist内か通信せず検証する。
 * 絶対HTTPS URLを公式host allowlistへ照合する。
 * Network requestを作らず、実取得と同じURL parserを使用する。
 * @param[in] url 検証する絶対URL。
 * @param[in] allowedHosts 許可する完全一致hostまたは先頭`.`付きdomain suffix。 完全一致hostまたはdot付きsuffix群。
 * @return 検証成功時は0、不正policyまたは境界外URLはHRESULT bit pattern。
 */
[[nodiscard]] NativeError validateOfficialHttpsUrl(
	std::wstring_view url, std::span<const std::wstring_view> allowedHosts) noexcept ;

/**
 * @brief 起点とredirect先URL列を公式host allowlistへ照合する。
 * 公式HTTPS redirect経路を通信せず検証する。
 * Productionの手動redirect追跡と同じURL・循環検証を使用する。
 * @param[in] urls 起点を先頭とし、redirect順に並ぶ絶対HTTPS URL群。 起点とLocationをredirect順に並べたURL群。
 * @param[in] allowedHosts 許可する完全一致hostまたは先頭`.`付きdomain suffix。 resourceに許可するorigin群。
 * @param[in] maximumRedirects 許可するredirect回数。Application上限は5回。
 * @param[out] originPolicyIndices 成功時のURLごとのallowlist index。 成功時のopaque origin経路。
 * @return 全URLと回数の検証成功時は0、失敗時はHRESULT bit pattern。 全URLの検証成功時は0、不正経路はHRESULT。
 */
[[nodiscard]] NativeError validateOfficialHttpsRedirectChain(
	std::span<const std::wstring_view> urls, std::span<const std::wstring_view> allowedHosts,
	std::uint32_t maximumRedirects, std::vector<std::uint32_t> &originPolicyIndices) noexcept ;

/**
 * @brief 公式配布元のHTTPS resourceをhost allowlist付きで取得するclientである。
 *
 * @note WinHTTPのsystem proxy設定を使用する。Redirectは自動追跡せず、全遷移を
 * resource policyへ照合する。平文HTTPとallowlist外hostは拒否する。
 * 受信済みHTTP statusの拒否はFACILITY_HTTPのHRESULTとし、WinHTTP API失敗と区別する。
 */
class OfficialHttpClient final {
public:
	/**
	 * @brief 取得根拠を保持していないHTTP clientを作成する。
	 * 既定は通常cacheを維持し、falseでも公式取得の監査を省略しない。
	 * @param[in] useCatalogCache trueは通常cache、falseは読取り・保存なしの公式GET。 trueだけcatalog cacheを利用する。
	 * @note falseでもhost、TLS、応答上限、schemaの各検証境界は変更しない。
	 */
	explicit OfficialHttpClient( bool useCatalogCache = true) noexcept ;

	/**
	 * @brief Metadata専用の用途と予算へ固定したclientを作成する。
	 * @param[in,out] execution Clientの寿命全体で有効なworker所有context。
	 * @param[in] useCatalogCache trueだけ通常metadata cacheを利用する。
	 * @note この構築経路ではpayload・binary保存・POSTを拒否する。
	 */
	explicit OfficialHttpClient( MetadataSearchExecutionContext &execution,
								bool							useCatalogCache = true) noexcept ;

	/**
	 * @brief Metadata専用の共通処理へ非通信I/Oを注入する内部試験constructor。
	 * @param[in,out] execution Clientより長生きする専用context。
	 * @param[in] transport 同じWinHTTP ABIを持つ完全な呼出し表。値をcopyして保持する。
	 * @param[in] cacheAccess Nullはcache無効。非nullはclientより長生きする完全な不変I/O表。
	 * @note UI、Provider request、設定fileからこの依存を指定しない。通常経路へのfallbackはない。
	 */
	OfficialHttpClient( MetadataSearchExecutionContext &execution, OfficialHttpTransport transport,
					   const OfficialHttpCacheAccess *cacheAccess = nullptr) noexcept ;

	/**
	 * @brief Record限定GETとlive HTML GETの非通信fixtureへ完全なI/O表を注入します。
	 * @param[in] transport WinHTTP ABIとdestination resolverを持つ完全な呼出し表。
	 * @note Source sessionの開始は呼出し側が行います。低位I/O表を他経路へ流用しません。
	 */
	explicit OfficialHttpClient( OfficialHttpTransport transport) noexcept ;

	/**
	 * @brief Catalog cacheの読取り・保存を許可する設定か返す。
	 * 不変の取得設定だけを返し、HTTPやcache I/Oは発生させない。
	 * @return 通常のcache有効modeはtrue、非cache検証modeはfalse。 Cache有効modeならtrue、非cache検証modeならfalse。
	 */
	[[nodiscard]] bool usesCatalogCache() const noexcept ;

	/**
     * @brief 保持中の取得根拠を破棄する。
     */
	~OfficialHttpClient() = default ;

	// Scan sessionの取得根拠を単独所有するためcopy/moveを禁止する。
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	OfficialHttpClient( const OfficialHttpClient &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	OfficialHttpClient &operator=( const OfficialHttpClient &) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	OfficialHttpClient( OfficialHttpClient &&) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	OfficialHttpClient		 &operator=( OfficialHttpClient &&) = delete ;

	/**
	 * @brief 公式network Providerの取得根拠sessionを開始する。
	 * 公式取得元の監査sessionを開始する。
	 * 以前の取得根拠を必ず失効させ、組み込みpolicyだけを使用する。
	 * @param[in] scanSessionId 呼出し側が割り当てた0ではないscan session ID。
	 * @param[in] providerId 組み込みsource policyを持つProvider stable ID。 公式network Providerのstable ID。
	 * @return 開始成功時は0、不正IDまたはpolicy不整合時はHRESULT bit pattern。
	 * @note 既存sessionと取得根拠は成功・失敗にかかわらず先に失効させる。
	 */
	[[nodiscard]] NativeError beginSourceSession( ScanSessionId	   scanSessionId,
												 std::wstring_view providerId) ;

	/**
	 * @brief 現在の取得根拠sessionと全取得根拠を失効させる。
	 * 公式取得元の監査sessionを失効させる。
	 * Session、Provider、取得連番と全取得根拠を同時に破棄する。
	 */
	void					  invalidateSourceSession() noexcept ;

	/**
	 * @brief 現在sessionで成功した公式resource取得根拠を登録順で返す。
	 * 現在sessionの公式取得根拠を返す。
	 * URL、host、端末情報を含まないread-only viewだけを返す。
	 * @return Clientの次回変更まで有効なURLを含まない取得根拠群。 次にclient状態を変更するまで有効な取得根拠群。
	 */
	[[nodiscard]] std::span<const OfficialSourceEvidence> sourceEvidence() const noexcept ;

	/**
	 * @brief 現在の取得根拠session identityを通信せず照合します。
	 * @param[in] scanSessionId 0でない現在scan session ID。
	 * @param[in] providerId 組み込みProvider stable ID。
	 * @return 現sessionと完全一致する場合true。
	 */
	[[nodiscard]] bool matchesSourceSession( ScanSessionId	  scanSessionId,
											std::wstring_view providerId) const noexcept ;

	/**
	 * @brief 現在sessionが指定resourceの有効な取得根拠を保持するか検証する。
	 * 指定resourceの公式取得根拠を保持するか検証する。
	 * 連番欠落、別session、別Provider、不正policyを全て拒否する。
	 * @param[in] scanSessionId 照合するscan session ID。
	 * @param[in] providerId 照合するProvider stable ID。
	 * @param[in] resourceId 必須とする用途別resource ID。 必須とするresource ID。
	 * @return Ledger全体と指定resourceが有効な場合は`true`。
	 */
	[[nodiscard]] bool hasSourceEvidence( ScanSessionId scanSessionId, std::wstring_view providerId,
										 std::wstring_view resourceId) const noexcept ;

	/**
	 * @brief 現在のsource session policyでUTF-8 catalogを取得して根拠を記録する。
	 * Source policy付きUTF-8 textを取得する。
	 * Source session解決から根拠確定までを一つの操作にする。
	 * @param[in] url 取得する絶対HTTPS URL。
	 * @param[in] resourceId Policyに登録済みのmetadata resource ID。 組み込みmetadata resource ID。
	 * @param[in] maximumBytes 応答bodyの上限byte数。 応答body上限byte数。
	 * @param[out] text 成功時のUTF-16 text。失敗時は空にする。
	 * @return 取得と根拠記録の成功時は0、失敗時はHRESULT bit pattern。 取得、変換、根拠記録の成功時は0、失敗時はHRESULT。
	 */
	[[nodiscard]] NativeError getUtf8TextForSource( std::wstring_view url,
												   std::wstring_view resourceId,
												   std::uint64_t maximumBytes, std::wstring &text) ;

	/** @brief 収集専用の条件付きGETで200本文または304観測を返します。
     * @param[in] url 組み込みsourceから再構築した公式起点。
     * @param[in] resourceId 現sessionのlandingまたはmetadata用途。
     * @param[in] maximumBytes 1～8 MiBの本文上限。
     * @param[in] entityTag 空、または呼出側が保存射影へ再結合したETag。
     * @param[out] text 200の厳密UTF-8本文。304・失敗は空です。
     * @param[out] observation 数値HTTP状態と200の指紋。失敗でもstatusだけ保持します。
     * @param[out] raw 非null時だけ200の原byteを返します。304・失敗時は空です。通常logへ渡しません。
     * @return 成功0、拒否・通信失敗はHRESULT。
     * @note 非cache・空ledgerのsession専用。304をsourceEvidenceへ追加しません。
     */
	[[nodiscard]] NativeError getCollectorMetadataForSource(
		std::wstring_view url, std::wstring_view resourceId, std::uint64_t maximumBytes,
		std::wstring_view entityTag, std::wstring &text, CollectorHttpObservation &observation,
		std::string *raw = nullptr) ;

	/**
	 * @brief 公式metadata scriptを実行せず有限取得します。
	 * @param[in] url 公式metadata URL。
	 * @param[in] resourceId 現sessionのmetadata用途。
	 * @param[in] cancellation 取消しcallback。
	 * @param[out] raw 厳密UTF-8検証済みの原byte列。失敗時は空。
	 * @return 成功0、拒否HRESULT。64 KiB／redirect 0／公開DNSを要求します。
	 */
	[[nodiscard]] NativeError getLiveScriptMetadataForSource(
		std::wstring_view url, std::wstring_view resourceId,
		const HttpCancellationCallback &cancellation, std::string &raw) ;
	/** @brief 保存した公式pageの一意なscript参照を監視側だけで有限取得します。
	 * @param[in] pageUrl 同sourceの原公式page URLです。実HTTPのfresh観測へ更新しません。
	 * @param[in] page 同pageの検証済み保存bodyです。Textarea/script内部の偽参照を認めません。
	 * @param[in] url 同originの一意な実srcへ一致する静的script URLです。
	 * @param[in] resourceId 現sourceのLANDING_PAGEまたはMETADATA用途です。
	 * @param[in] cancellation 有限な協調停止です。
	 * @param[out] raw Script MIME/厳密UTF-8/64KiB/redirect0成功時だけ原byteです。
	 * @return 成功0、未対応/拒否/通信失敗は元HRESULTです。
	 * @note Scriptを実行せず、同意・取得grant・payload能力は発行しません。
	 */
	[[nodiscard]] NativeError getCollectorLinkedScriptForSource(
		std::wstring_view pageUrl, std::wstring_view page, std::wstring_view url,
		std::wstring_view resourceId, const HttpCancellationCallback &cancellation,
		std::string &raw) ;

	/**
	 * @brief 公式sourceの静的UTF-8 HTMLをcacheなしで有限GETします。
	 * @param[in] url Policy内の絶対HTTPS page URL。
	 * @param[in] resourceId 既存source sessionのlandingまたはmetadata用途ID。
	 * @param[in] cancellation 空または各hop・受信中の取消し確認先。
	 * @param[out] text 成功時だけNULなしUTF-16 HTML。失敗時は空。
	 * @param[out] finalUrl 成功時だけredirect後の絶対URL。親broker専用でworkerへ渡さない。
	 * @param[out] byteCount 非nullなら成功時のraw本文byte数。失敗時は0。
	 * @return 公開宛先・同一origin・HTTP 200・UTF-8 HTML・取得根拠が全て成立した場合0。
	 * @note 一page 2 MiB、redirect最大5回。HTML構造・link用途・総page予算は後段で検証します。
	 */
	[[nodiscard]] NativeError getLiveHtmlPageForSource( std::wstring_view			   url,
													   std::wstring_view			   resourceId,
													   const HttpCancellationCallback &cancellation,
													   std::wstring &text, std::wstring &finalUrl,
													   std::uint64_t *byteCount = nullptr) ;

	/**
	 * @brief 現在のsource session policyで固定form POSTのUTF-8 metadataを取得する。
	 * Source policy付きform POSTでUTF-8 metadataを取得する。
	 * Redirectとcacheを使わず、成功した一POSTごとに取得根拠を記録する。Form bodyはUIまたはlogへ渡さない。
	 * @param[in] url 取得する絶対HTTPS URL。 固定metadata endpointの絶対HTTPS URL。
	 * @param[in] resourceId Policyに登録済みのmetadata resource ID。 組み込みMetadata resource ID。
	 * @param[in] formBody 2 KiB以下のASCII form body。機密値を含めてはならない。
	 * @param[in] maximumBytes 応答bodyの上限byte数。 応答body上限byte数。
	 * @param[out] text 成功時のUTF-16 text。失敗時は空にする。 成功時のNULを含まないUTF-16 text。
	 * @return 取得、UTF-8変換、取得根拠記録の成功時は0、失敗時はHRESULT bit pattern。 取得、変換、根拠記録の成功時は0、失敗時はHRESULT。
	 * @note Redirectとcacheを使用せず、`application/x-www-form-urlencoded`だけを送信する。
	 */
	[[nodiscard]] NativeError postFormUtf8TextForSource( std::wstring_view url,
														std::wstring_view resourceId,
														std::string_view  formBody,
														std::uint64_t	  maximumBytes,
														std::wstring	 &text) ;

	/**
	 * @brief 現在のsource session policyでbinary catalogを保存して根拠を記録する。
	 * Source policy付きbinary catalogを取得する。
	 * Cache再検証を含む成功後だけopaque取得根拠を確定する。
	 * @param[in] url 取得する絶対HTTPS URL。
	 * @param[in] resourceId Policyに登録済みのmetadataまたは署名resource ID。 Metadataまたは署名resource ID。
	 * @param[in] maximumBytes 応答bodyの上限byte数。 応答body上限byte数。
	 * @param[in] outputFile 書込み可能で現在位置が先頭の所有外file handle。 書込み可能な所有外file handle。
	 * @param[in] progressCallback 保存済みbyte数と総byte数の通知先。 保存進捗通知先。
	 * @return 取得、保存、根拠記録の成功時は0、失敗時はHRESULT bit pattern。
	 */
	[[nodiscard]] NativeError downloadCatalogForSource(
		std::wstring_view url, std::wstring_view resourceId, std::uint64_t maximumBytes,
		HANDLE outputFile, const HttpDownloadProgressCallback &progressCallback) ;

	/**
	 * @brief 現在のsource session policyでpayloadを保存して根拠を記録する。
	 * Source policy付きpayloadを取得する。
	 * Payload保存成功後だけ同じscan sessionへ根拠を追加する。
	 * @param[in] url 取得する絶対HTTPS URL。
	 * @param[in] resourceId Policyに登録済みのpayload resource ID。 組み込みpayload resource ID。
	 * @param[in] maximumBytes 応答bodyの上限byte数。 応答body上限byte数。
	 * @param[in] outputFile 書込み可能で現在位置が先頭の所有外file handle。 書込み可能な所有外file handle。
	 * @param[in] progressCallback 受信済みbyte数と判明した総byte数の通知先。 保存進捗通知先。
	 * @param[in] cancellationCallback 空または取消し状態を返す非blocking関数。 空または取消し状態の確認先。
	 * @return 取得、保存、根拠記録の成功時は0、失敗時はHRESULT bit pattern。
	 */
	[[nodiscard]] NativeError downloadForSource(
		std::wstring_view url, std::wstring_view resourceId, std::uint64_t maximumBytes,
		HANDLE outputFile, const HttpDownloadProgressCallback &progressCallback,
		const HttpCancellationCallback &cancellationCallback = {}) ;

	/**
	 * @brief Record限定grantが所有するexact targetへ有限のGET取得を行います。
	 * @param[in,out] request Claim済みgrantのURLを所有する`READY` request。成否にかかわらず消費します。
	 * @param[in] outputFile 書込み可能で現在位置が先頭の所有外file handle。
	 * @param[in] progressCallback 受信済みbyte数と判明した総byte数の通知先。
	 * @param[in] cancellationCallback 空または取消し状態を返す非blocking関数。
	 * @param[out] destinationEvidence 成功時にだけURL非保持の宛先検証結果。
	 * @return 全hop検証・HTTP 200・有限受信・flush・grant終端の全成功時は0、それ以外はHRESULT bit pattern。
	 * @note Dynamic同一originは2回、固定payload hostへの一方向移行だけを許可します。System・per-user proxy設定を尊重し、serverの既定credential、Cookie、Referer、root固有header、bodyを送信しません。
	 * 索引attestation出自だけは同grantの私有封印exact route・失効leaseを再照合します。
	 * 一般のhost追加や公開DTO自己申告ではこのbranchを作れません。毎hopの公開DNSと実byte検査を維持します。
	 */
	[[nodiscard]] NativeError downloadDelegatedGet(
		OfficialDelegatedGetRequest &request, HANDLE outputFile,
		const HttpDownloadProgressCallback &progressCallback,
		const HttpCancellationCallback	   &cancellationCallback,
		OfficialPublicDestinationEvidence  &destinationEvidence) ;

private:
	friend struct signed_index_refresh_detail::Access ;
	/** @brief 固定currentを匿名・redirect0・96KiBで取得します。
	 * @param[in,out] control 同refreshの共有停止・送信・受信状態です。
	 * @param[out] raw 成功時だけ原byteです。失敗時空です。
	 * @param[out] status 失敗時も実観測HTTP statusを保持します。
	 * @return 全HTTP検査成功0、拒否時は元HRESULTです。
	 */
	[[nodiscard]] NativeError getSignedIndexCurrent( SignedIndexHttpControl &control,
													std::vector<std::byte> &raw,
													std::uint32_t		   &status) ;
	/** @brief 認証済みmanifest由来の固定immutable assetだけを取得します。
	 * @param[in] manifest 製品または内部RAM検証が発行した不変receiptです。
	 * @param[in,out] control currentと同じ有限状態です。
	 * @param[out] raw 成功時だけ原圧縮byteです。
	 * @param[out] status 実観測HTTP statusです。
	 * @return 用途・全hop・本文検査成功0、拒否HRESULTです。
	 */
	[[nodiscard]] NativeError getSignedIndexAsset( const AuthenticatedIndexManifest &manifest,
												  SignedIndexHttpControl		   &control,
												  std::vector<std::byte>		   &raw,
												  std::uint32_t					   &status) ;
	/** @brief 索引専用policyを共通URL/DNS/request/streamへ適用します。
	 * @param[in] url 固定currentか認証済みassetの起点だけです。
	 * @param[in] current current用途ではredirectを拒否します。
	 * @param[in] maximumBytes 元codecの正の上限です。
	 * @param[in,out] control 同一refreshの協調停止状態です。
	 * @param[out] raw 全成功時の所有原byteです。
	 * @param[out] status 失敗時も保持する実HTTP statusです。
	 * @return 成功0、元拒否診断です。通常cache/ledgerは使いません。
	 */
	[[nodiscard]] NativeError getSignedIndexBytes( std::wstring_view url, bool current,
												  std::uint64_t			  maximumBytes,
												  SignedIndexHttpControl &control,
												  std::vector<std::byte> &raw,
												  std::uint32_t			 &status) ;
	friend class LocalCollectorHttpClient ;
	friend class CollectorInspectionAcquisition ;
	friend class SignedIndexAcquisitionAdapter ;
	/** @brief 認証adapterだけが固定した同origin規約を原byteのまま取得します。
	 * @param[in] url 元認証textDocumentのexact静的URLです。
	 * @param[in] host 同公式起点へ照合済みのexact DNS hostです。
	 * @param[in] exactBytes 1～256KiBの元本文byte数です。
	 * @param[in] html 明示HTMLの原page取得の場合trueです。使用時上限は256KiBです。
	 * @param[in] cancellation 同workerの協調停止です。
	 * @param[out] raw 全受信成功時だけ原byteを保持します。失敗時は空です。
	 * @param[out] text 全受信・厳密UTF-8成功時だけ全文です。失敗時は空です。
	 * @return HTTPS/public DNS/redirect0/HTTP200/固定MIME/全長成功0、拒否時は元HRESULTです。
	 * @note Cache、通常ledger、永続保存を使用せず、任意公開URL入口にはしません。
	 */
	[[nodiscard]] NativeError getSignedIndexTermsDocument(
		std::wstring_view url, std::wstring_view host, std::uint64_t exactBytes, bool html,
		const HttpCancellationCallback &cancellation, std::string &raw, std::wstring &text) ;
	/** @brief 収集adapterの実HTMLをpublic宛先・同一originで有限取得する。
	 * @param[in] url 検査済み起点URL。
	 * @param[in] host 小文字exact host。
	 * @param[in] cancellation 同じ取消し。
	 * @param[out] text 成功200の厳密UTF-8本文。失敗時空。
	 * @param[out] finalUrl 同じ成功本文の実最終URL。相対hrefのbase専用で、失敗時空。
	 * @return 全受信成功0、拒否HRESULT。組み込みledgerを発行しない。
	 */
	[[nodiscard]] NativeError getCollectorInspectionPage(
		std::wstring_view url, std::wstring_view host, const HttpCancellationCallback &cancellation,
		std::wstring &text, std::wstring &finalUrl) ;
	/** @brief 永続permitを照合した開発用adapterだけが使う有限GETです。
	 * @param[in] url 共通builderから再構築した公式URL。
	 * @param[in] resourceId 現sessionのmetadata用途。
	 * @param[in] maximumBytes 予約済みの正数本文上限。
	 * @param[in] entityTag 空または厳密な単一validator。
	 * @param[in,out] control 同期workerのclaim済み制御。最終finishは行いません。
	 * @param[in] dnsApi 欠損を許さない有限DNS依存。
	 * @param[out] text 成功時だけ厳密UTF-8復号した本文。304・失敗は空。
	 * @param[out] observation status／待機は失敗時も保持。本文hashは200成功時だけ。
	 * @return 有限受信・decode／hash・所有者解放成功0、拒否HRESULT。
	 * @note Grant・通常取得根拠・OBSERVEDを発行せず、redirect・再送も行いません。
	 */
	[[nodiscard]] NativeError getControlledCollectorMetadataForSource(
		std::wstring_view url, std::wstring_view resourceId, std::uint64_t maximumBytes,
		std::wstring_view entityTag, OfficialCollectorHttpControl &control,
		const OfficialCollectorDnsApi &dnsApi, std::wstring &text,
		CollectorControlledHttpObservation &observation) ;

	/**
	 * @brief Live HTMLと非実行scriptの共通取得境界です。
	 * @param[in] url 公式URL。
	 * @param[in] resourceId 現sessionの用途。
	 * @param[in] cancellation 有限取消し。
	 * @param[in] script Script MIME／64 KiB／redirect 0を要求する場合true。
	 * @param[out] text 厳密UTF-8復号結果。
	 * @param[out] finalUrl 最終URL。
	 * @param[out] byteCount 成功したraw byte数。省略可。
	 * @param[out] raw 原byte列。省略可。
	 * @param[in] linkedLandingScript 保存pageの一意な同origin参照を別入口で検査した場合だけtrueです。
	 * @return 成功0、拒否HRESULT。
	 */
	[[nodiscard]] NativeError getLiveTextForSource( std::wstring_view			   url,
												   std::wstring_view			   resourceId,
												   const HttpCancellationCallback &cancellation,
												   bool script, std::wstring &text,
												   std::wstring &finalUrl, std::uint64_t *byteCount,
												   std::string *raw,
												   bool			linkedLandingScript = false) ;

	/**
	 * @brief UTF-8 catalog resourceを上限とcache再検証付きで取得する。
	 * UTF-8 text resourceを上限付きで取得する。
	 * UTF-8の妥当性と応答上限を検証してから出力を更新する。
	 * @param[in] url 取得する絶対HTTPS URL。
	 * @param[in] allowedHosts 接続を許可する完全一致hostまたは先頭`.`付きdomain suffix。 許可する公式host。
	 * @param[in] maximumRedirects 許可する有限redirect回数。 許可するredirect回数。
	 * @param[in] maximumBytes 応答bodyの上限byte数。
	 * @param[out] text 成功時のUTF-16 text。失敗時は空にする。
	 * @param[out] originPolicyIndices 成功時の起点から最終originまでのopaque index群。 成功時のopaque origin経路。
	 * @param[out] observation 成功時に実利用したnetwork／cache経路とUTC。
	 * @return 成功時は0、失敗時はHRESULT bit pattern。
	 * @note UTF-8 BOMは任意で一つだけ許可し、戻り値から除去する。
	 */
	[[nodiscard]] NativeError getUtf8Text( std::wstring_view					 url,
										  std::span<const std::wstring_view> allowedHosts,
										  std::uint32_t						 maximumRedirects,
										  std::uint64_t maximumBytes, std::wstring &text,
										  std::vector<std::uint32_t>		 &originPolicyIndices,
										  OfficialHttpAcquisitionObservation &observation) const ;

	/**
	 * @brief Binary catalogをcache再検証して呼出し側のfile handleへ保存する。
	 * Binary catalogをcache再検証してfileへ保存する。
	 * Cache本文もProviderの署名・hash検証へ渡す保護一時fileへ毎回複写し、cacheだけを信頼判定に使用しない。
	 * @param[in] url 取得する絶対HTTPS URL。
	 * @param[in] allowedHosts 接続を許可する完全一致hostまたは先頭`.`付きdomain suffix。 許可する公式host。
	 * @param[in] maximumRedirects 許可する有限redirect回数。 許可するredirect回数。
	 * @param[in] maximumBytes 応答bodyの上限byte数。 応答body上限byte数。
	 * @param[in] outputFile 書込み可能で現在位置が先頭の所有外file handle。 書込み可能な所有外file handle。
	 * @param[in] progressCallback 保存済みbyte数と総byte数の通知先。 保存進捗通知先。
	 * @param[out] originPolicyIndices 成功時の起点から最終originまでのopaque index群。 成功時のopaque origin経路。
	 * @param[out] observation 成功時に実利用したnetwork／cache経路とUTC。
	 * @return 保存とflush成功時は0、失敗時はHRESULT bit pattern。
	 * @note 呼出し後もcatalogのschema、hash、署名等をProviderが毎回再検証する。
	 */
	[[nodiscard]] NativeError downloadCatalogToFile(
		std::wstring_view url, std::span<const std::wstring_view> allowedHosts,
		std::uint32_t maximumRedirects, std::uint64_t maximumBytes, HANDLE outputFile,
		const HttpDownloadProgressCallback &progressCallback,
		std::vector<std::uint32_t>		   &originPolicyIndices,
		OfficialHttpAcquisitionObservation &observation) const ;

	/**
	 * @brief HTTPS payloadを呼出し側が所有するfile handleへ保存する。
	 * HTTPS payloadをfile handleへ保存する。
	 * 呼出し側がCREATE_NEWで作成したfileへ順次保存する。
	 * @param[in] url 取得する絶対HTTPS URL。
	 * @param[in] allowedHosts 接続を許可する完全一致hostまたは先頭`.`付きdomain suffix。 許可する公式host。
	 * @param[in] maximumRedirects 許可する有限redirect回数。 許可するredirect回数。
	 * @param[in] maximumBytes 応答bodyの上限byte数。
	 * @param[in] outputFile 書込み可能で現在位置が先頭の所有外file handle。 書込み可能な所有外file handle。
	 * @param[in] progressCallback 受信済みbyte数と判明した総byte数の通知先。 受信進捗通知先。
	 * @param[in] cancellationCallback 空または取消し状態を返す非blocking関数。 空または取消し状態の確認先。
	 * @param[out] originPolicyIndices 成功時の起点から最終originまでのopaque index群。 成功時のopaque origin経路。
	 * @param[in] collectorInspection 収集検査だけでpublic同一origin・cookie／credential無効を追加する。
	 * @return 保存とflush成功時は0、失敗時はHRESULT bit pattern。
	 */
	[[nodiscard]] NativeError downloadToFile( std::wstring_view					url,
											 std::span<const std::wstring_view> allowedHosts,
											 std::uint32_t						maximumRedirects,
											 std::uint64_t maximumBytes, HANDLE outputFile,
											 const HttpDownloadProgressCallback &progressCallback,
											 const HttpCancellationCallback &cancellationCallback,
											 std::vector<std::uint32_t>		&originPolicyIndices,
											 bool collectorInspection = false) const ;

	/**
	 * @brief 現在sessionのresource policyを検証してhost群を返す。
	 * 現在sessionのresource hostを解決する。
	 * 表示値またはURLからProviderとresourceを推測しない。
	 * @param[in] resourceId 解決する用途別resource ID。
	 * @param[out] allowedHosts 成功時のprocess lifetime中有効なhost群。 成功時の組み込みhost群。
	 * @param[out] maximumRedirects 成功時の有限redirect上限。
	 * @return 解決成功時は0、不正session、上限、未知resource時はHRESULT bit pattern。 解決成功時は0、不正session、上限、未知ID時は
	 *         HRESULT。
	 */
	[[nodiscard]] NativeError resolveSourceHosts( std::wstring_view					 resourceId,
												 std::span<const std::wstring_view> &allowedHosts,
												 std::uint32_t &maximumRedirects) const noexcept ;

	/**
	 * @brief 現在Providerのresourceが指定用途と一致するか判定する。
	 * Resourceが指定用途と一致するか判定する。
	 * Metadata APIでpayload hostを使用する用途混同を拒否する。
	 * @param[in] resourceId 検証する用途別resource ID。 検証するresource ID。
	 * @param[in] kind 呼出APIが要求するresource用途。 呼出APIが要求する用途。
	 * @return 組み込みpolicyの用途が一致する場合は`true`。
	 */
	[[nodiscard]] bool		  sourceResourceHasKind( std::wstring_view		   resourceId,
													OfficialSourceResourceKind kind) const noexcept ;

	/**
	 * @brief 成功したresource取得を現在sessionのledgerへ追加する。
	 * 成功した公式resource取得をledgerへ追加する。
	 * HTTP処理全体が成功した後だけ連番付きopaque根拠を確定する。
	 * @param[in] resourceId 取得時に検証した用途別resource ID。 取得時に検証したresource ID。
	 * @param[in] originPolicyIndices 起点から最終originまでのopaque index群。 検証済みopaque origin経路。
	 * @param[in] observation 本文取得処理が確定した実経路・時刻・cache許可値。
	 * @return 追加成功時は0、不整合または記憶域不足時はHRESULT bit pattern。
	 */
	[[nodiscard]] NativeError appendSourceEvidence(
		std::wstring_view resourceId, std::span<const std::uint32_t> originPolicyIndices,
		const OfficialHttpAcquisitionObservation &observation) noexcept ;

	/// 成功取得だけを保持する有限ledger。
	std::vector<OfficialSourceEvidence>	 sourceEvidence_ ;
	/// trueだけcatalog cacheを使用する。PayloadとPOSTには影響しない。
	const bool							 useCatalogCache_ ;
	/// 非nullならmetadata専用。借用先はclientより長生きする。
	MetadataSearchExecutionContext		*metadataExecution_{} ;
	/// 内部試験だけの所有API表。値なしは従来Windows APIを使用する。
	std::optional<OfficialHttpTransport> testTransport_ ;
	/// 内部試験だけの非所有cache I/O。Nullで実cacheへfallbackしない。
	const OfficialHttpCacheAccess		*testCacheAccess_{} ;
	/// 現在ledgerに対応するProvider stable ID。
	std::wstring						 sourceProviderId_ ;
	/// 現在ledgerに対応するscan session ID。
	ScanSessionId						 sourceScanSessionId_{} ;
	/// 次の成功取得へ割り当てる1始まり連番。
	std::uint64_t						 nextAcquisitionId_{1} ;
} ;

} // namespace drivercrate
