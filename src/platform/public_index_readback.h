//------------------------------------------------------------------------------
/**
 * @file public_index_readback.h
 * @brief 監視PC専用の固定三resource匿名readbackと非機密reportを定義します。
 * @version 01.00.00
 * @date 2026/10/20
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/20  元二byteへの固定三resource匿名確認を追加。
 * </pre>
 * @note URL、credential、path、取得本文をreportへ渡さず、storeとcacheを書きません。
 * @see docs/adr/0385-public-anonymous-index-readback.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/official_http_client.h"
#include "platform/signed_index_manifest_internal.h"
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate {

/** @brief 原resourceの未着手、完全一致、失敗を区別します。 */
enum class PublicIndexResourceState {
	/// 送信処理を開始していません。
	NOT_STARTED,
	/// HTTPと原byteの完全一致が成立しました。
	COMPLETE,
	/// 元HTTP、byteまたは停止診断を保持します。
	FAILED
} ;
/** @brief 任意例外文を含まない匿名確認の終了段階です。 */
enum class PublicIndexFailureStage {
	/// 全検証が成功しました。
	NONE,
	/// 閉CLIの型または個数を拒否しました。
	ARGUMENTS,
	/// 保護された元二fileを読めませんでした。
	INPUT,
	/// 元署名または固定trustを拒否しました。
	TRUST,
	/// UTC不明、後退または期限を拒否しました。
	TIME,
	/// 固定currentの取得を拒否しました。
	CURRENT,
	/// 固定manifest assetの取得を拒否しました。
	MANIFEST_ASSET,
	/// 固定gzip assetの取得を拒否しました。
	GZIP_ASSET,
	/// 元gzipまたはrecords codecを拒否しました。
	CONTENT,
	/// 同じoperationの取消しを観測しました。
	CANCELLED
} ;
/** @brief URLと本文を保持しない一resourceの実観測です。 */
struct PublicIndexResourceObservation {
	/// 未着手を完了へ補完しません。
	PublicIndexResourceState   state{PublicIndexResourceState::NOT_STARTED} ;
	/// 元HTTP statusです。未観測は0です。
	std::uint32_t			   httpStatus{} ;
	/// 同resourceの実send開始回数です。
	std::uint32_t			   sends{} ;
	/// 上限拒否probeを含む原受信数です。
	std::uint64_t			   receivedBytes{} ;
	/// COMPLETE時だけ実原byteの小文字SHAです。
	std::optional<std::string> sha256 ;
	/// 元HRESULT bit patternです。
	NativeError				   nativeError{} ;
} ;
/** @brief 成功資格を自己発行しない閉native stdout用の実観測値です。 */
struct PublicIndexReadbackReport {
	/// 三resourceと全codecの成功時だけtrueです。
	bool										   verified{} ;
	/// 最初のUTCです。不明だけnulloptです。
	std::optional<std::chrono::sys_seconds>		   startedAtUtc ;
	/// 終了時のUTCです。不明だけnulloptです。
	std::optional<std::chrono::sys_seconds>		   completedAtUtc ;
	/// 元単調時計差です。超過をclampしません。
	std::optional<std::uint64_t>				   elapsedMilliseconds ;
	/// Current、immutable manifest、immutable gzipの固定順です。
	std::array<PublicIndexResourceObservation, 3U> resources ;
	/// 実sendの三resource合計です。最大9です。
	std::uint32_t								   sends{} ;
	/// Probe込みの三resource合計です。
	std::uint64_t								   receivedBytes{} ;
	/// 最初の元HRESULTです。UNKNOWNでは非0です。
	NativeError				nativeError{static_cast<NativeError>( E_INVALIDARG)} ;
	/// 任意入力を含まない固定失敗段階です。
	PublicIndexFailureStage failureStage{PublicIndexFailureStage::ARGUMENTS} ;
} ;
/** @brief 閉modeの個数とASCII十進残時間をfile読取前に検査します。
 * @param[in] count 実行file名込みで正確に5です。
 * @param[in] args count個の借用wide文字列です。
 * @param[out] milliseconds 成功時だけ1..90000の残時間です。
 * @return 固定mode、個数、非空path、残時間が成立した場合trueです。
 */
[[nodiscard]] bool publicIndexReadbackArguments( int count, wchar_t *const args[],
												std::uint32_t &milliseconds) noexcept ;
/** @brief 固定公開trustで元二byteと匿名三resourceを現在UTC検証します。
 * @param[in] envelope 保護readerから得た96KiB以下の原envelopeです。
 * @param[in] gzip 保護readerから得た16MiB以下の原gzipです。
 * @param[in] milliseconds 親が渡した元の正の残時間です。最大90000です。
 * @param[in] operationStarted 保護reader開始前に一度だけ採取した単調開始です。
 * @param[in] operationStartedAtUtc 同じ入口で採取した元UTCです。
 * @return 元診断、部分resource、同時計の実観測だけです。
 * @note 同期worker専用です。保存、cache、credential、任意URL入力はありません。
 */
[[nodiscard]] PublicIndexReadbackReport readbackFixedPublicIndex(
	std::string_view envelope, std::string_view gzip, std::uint32_t milliseconds,
	std::chrono::steady_clock::time_point operationStarted,
	std::chrono::sys_seconds			  operationStartedAtUtc) noexcept ;
/** @brief 閉enumと原数値から順序固定10fieldのASCII JSONを生成します。
 * @param[in] report 同じnative実行が所有する非機密観測です。
 * @return 改行を持たない64KiB以下のcanonical JSONです。
 * @throws std::runtime_error 時刻またはdigestが閉wireに一致しない場合です。
 */
[[nodiscard]] std::string publicIndexReadbackJson( const PublicIndexReadbackReport &report) ;

namespace public_index_readback_detail {
/** @brief 全fake依存を必須にする内部test専用の注入値です。 */
struct Services {
	/// 欠損時は実WinHTTPへfallbackしません。
	std::optional<OfficialHttpTransport>					 transport ;
	/// fixtureが所有する信頼UTCです。
	std::function<std::optional<std::chrono::sys_seconds>()> utcNow ;
	/// fixtureが所有する単調時計です。
	std::function<std::chrono::steady_clock::time_point()>	 monotonicNow ;
	/// 製品は保護reader前の元開始、fixture省略時はexecute入口です。
	std::optional<std::chrono::steady_clock::time_point>	 operationStarted ;
	/// 上記開始と同じ入口の元UTCです。二つを同時に指定します。
	std::optional<std::chrono::sys_seconds>					 operationStartedAtUtc ;
	/// RAM public trustだけです。製品入口はcompiled trustを使います。
	std::span<const signed_index_detail::TrustKey>			 trust ;
} ;
/** @brief 私有HTTP roleとmonitor profileへ接続する唯一のglueです。 */
struct Access {
	/** @brief 全fake I/Oと既存の実native codecで同じ実装を検査します。
	 * @param[in] services 欠損を許さない全fake依存です。
	 * @param[in] envelope 期待原envelopeです。
	 * @param[in] gzip 期待原gzipです。
	 * @param[in] milliseconds 1..90000の共有期限です。
	 * @param[in] cancellation 同fixtureだけの取消しです。
	 * @return URLや本文を持たない実観測です。
	 */
	[[nodiscard]] static PublicIndexReadbackReport forTest(
		const Services &services, std::string_view envelope, std::string_view gzip,
		std::uint32_t milliseconds, const HttpCancellationCallback &cancellation = {}) noexcept ;
	/** @brief 固定clientと検査済み依存を三resourceへ一度だけ適用します。
	 * @param[in,out] client 非cacheの固定clientです。
	 * @param[in] services 製品固定または完全fakeの依存です。
	 * @param[in] envelope 期待原envelopeです。
	 * @param[in] gzip 期待原gzipです。
	 * @param[in] milliseconds 共有期限です。
	 * @param[in] cancellation 同operationの取消しです。
	 * @return 部分取得を保持する非機密観測です。
	 */
	[[nodiscard]] static PublicIndexReadbackReport execute(
		OfficialHttpClient &client, const Services &services, std::string_view envelope,
		std::string_view gzip, std::uint32_t milliseconds,
		const HttpCancellationCallback &cancellation) noexcept ;
} ;
}
} // namespace drivercrate
