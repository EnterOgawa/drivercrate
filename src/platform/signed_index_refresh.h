//------------------------------------------------------------------------------
/**
 * @file signed_index_refresh.h
 * @brief 固定署名索引のrefreshと非機密な保存観測を定義します。
 * @version 01.00.00
 * @date 2026/10/16
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/16  固定currentと原子storeの有限接続を追加。
 * </pre>
 * @note URL・snapshot・候補・grantを通常summaryへ保持しません。
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/official_http_client.h"
#include "platform/signed_index_store.h"
#include "platform/signed_index_manifest_internal.h"
#include <chrono>
#include <functional>
#include <optional>
#include <span>
#include <string_view>

namespace drivercrate {
/** @brief 通信成功、明示cache、停止と拒否を区別します。 */
enum class IndexRefreshStatus {
	/// 全検査と保存snapshot確認が成功しました。
	REFRESHED,
	/// 更新失敗を保持した現在有効なcache観測です。
	AUTHENTICATED_CACHE,
	/// 元HTTPまたは通信診断を保持します。
	HTTP_FAILED,
	/// 信頼UTCがありません。
	TIME_UNAVAILABLE,
	/// 署名・key・時刻・意味の拒否です。
	MANIFEST_REJECTED,
	/// 原gzipのsize/hash/展開の拒否です。
	ASSET_REJECTED,
	/// 原record/schema/使用時期限の拒否です。
	RECORDS_REJECTED,
	/// 最新head再確認または保存の拒否です。
	STORE_FAILED,
	/// 同workerの協調停止です。commit事実とは別です。
	CANCELLED,
	/// 同refreshの固定期限です。
	TIMED_OUT,
	/// 依存欠損・確保・例外を成功にしません。
	INTERNAL_FAILURE
} ;
/** @brief Snapshot能力を含まないstore結果の要約です。 */
struct IndexRefreshStoreObservation {
	/// 実store区分です。
	IndexStoreStatus						 status{IndexStoreStatus::STATE_REJECTED} ;
	/// 原commit事実です。
	IndexStoreCommitDisposition				 commit{IndexStoreCommitDisposition::NO_CHANGE} ;
	/// 元保存診断です。
	NativeError								 error{} ;
	/// 元世代/署名拒否です。
	std::optional<SignedIndexManifestStatus> manifestStatus ;
	/// 実store由来の高水位です。
	std::optional<std::uint64_t>			 persistedGeneration ;
	/// 現在有効なsnapshotを観測した事実だけです。能力ではありません。
	bool									 usableSnapshot{} ;
} ;
/** @brief UIへ渡せる非機密な観測です。候補や許可ではありません。 */
struct IndexRefreshSummary {
	/// 終端区分です。
	IndexRefreshStatus							status{IndexRefreshStatus::INTERNAL_FAILURE} ;
	/// Cache利用時も元refresh失敗を保持します。
	NativeError									error{} ;
	/// 停止判定後も元HTTP/WinHTTP失敗を独立保持します。
	NativeError									httpError{} ;
	/// 最後に実観測したHTTP statusです。
	std::uint32_t								httpStatus{} ;
	/// 実送信開始回数です。
	std::uint32_t								sends{} ;
	/// 拒否probeを含む原受信数です。
	std::uint64_t								receivedBytes{} ;
	/// 原manifest拒否です。
	std::optional<SignedIndexManifestStatus>	manifestStatus ;
	/// 原asset拒否です。
	std::optional<IndexAssetBytesStatus>		assetStatus ;
	/// 原schema拒否です。
	std::optional<IndexRecordsStatus>			recordsStatus ;
	/// 認証したmanifest世代です。
	std::optional<std::uint64_t>				attemptedGeneration ;
	/// commitの確定/不確定を独立保持します。
	IndexRefreshStoreObservation				store ;
	/// 明示再認証の結果です。
	std::optional<IndexRefreshStoreObservation> cache ;
	/// Fresh成功とは区別します。
	bool										usedAuthenticatedCache{} ;
} ;
/** @brief 固定GitHubと固定保護storeだけを同期workerでrefreshします。
 * @param[in] cancellation 同worker寿命中の非blocking取消しです。空は取消しなしです。
 * @return 元失敗・commit事実・明示cacheを保持する非機密summaryです。
 * @note 呼出しはnetwork/保存を行います。UIからURL/path/trustを指定できません。
 */
[[nodiscard]] IndexRefreshSummary refreshFixedSignedIndex(
	const HttpCancellationCallback &cancellation = {}) noexcept ;

namespace signed_index_refresh_detail {
/** @brief 内部非通信fixtureの全依存です。製品設定へ投影しません。 */
struct Services {
	/// Fixtureでは完全表を必須にします。
	std::optional<OfficialHttpTransport>					 transport ;
	/// 信頼UTCです。
	std::function<std::optional<std::chrono::sys_seconds>()> utcNow ;
	/// 単調時計です。
	std::function<std::chrono::steady_clock::time_point()>	 monotonicNow ;
	/// 保存能力はcallback内だけです。
	std::function<IndexRefreshStoreObservation( const IndexRecordsSchemaReceipt &, std::string_view,
											   std::span<const std::byte>,
											   std::optional<std::chrono::sys_seconds>)>
																						 commit ;
	/// 現在の再認証です。
	std::function<IndexRefreshStoreObservation( std::optional<std::chrono::sys_seconds>)> reload ;
	/// RAM public keyだけを呼出し中借用します。
	std::span<const signed_index_detail::TrustKey> fixtureTrust ;
} ;
/** @brief 製品固定入口と完全fixtureを分ける内部接続です。 */
struct Access {
	/** @brief 完全fakeの全依存で同じHTTP/codec/glueを実行します。
	 * @param[in] services 呼出し中有効な全依存とRAM public trustです。
	 * @param[in] cancellation 同fixtureの協調停止です。
	 * @return 非機密summaryだけです。snapshotやgrantを作りません。
	 */
	[[nodiscard]] static IndexRefreshSummary forTest(
		const Services &services, const HttpCancellationCallback &cancellation = {}) noexcept ;
	/** @brief 共通実装へ固定clientと検査済み依存を渡します。
	 * @param[in,out] client 専用非cache clientです。
	 * @param[in] services 固定製品または完全fake依存です。
	 * @param[in] cancellation 同workerの停止確認です。
	 * @return 元診断を保持する非機密summaryです。
	 */
	[[nodiscard]] static IndexRefreshSummary execute(
		OfficialHttpClient &client, const Services &services,
		const HttpCancellationCallback &cancellation) noexcept ;
} ;
}
} // namespace drivercrate
