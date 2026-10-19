//------------------------------------------------------------------------------
/**
 * @file metadata_search_budget.cpp
 * @brief 検索予算・制限回線同意・取消しの純粋実装。
 * @version 01.00.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  Metadata専用検索の契約を追加。
 * </pre>
 *
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#include "core/metadata_search_budget.h"

#include <algorithm>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace drivercrate {
namespace {

// Windowsから独立して扱うHRESULT bit pattern。
constexpr NativeError INVALID_ARGUMENT = std::bit_cast<NativeError>( 0x80070057U) ;
// 明示していない通信とresource用途の拒否。
constexpr NativeError ACCESS_DENIED = std::bit_cast<NativeError>( 0x80070005U) ;
// 協調取消しの診断。
constexpr NativeError CANCELLED_ERROR = std::bit_cast<NativeError>( 0x800704C7U) ;
// Monotonic期限切れの診断。
constexpr NativeError TIMEOUT_ERROR = std::bit_cast<NativeError>( 0x800705B4U) ;
// 有限予算を使い切った診断。
constexpr NativeError BUDGET_ERROR = std::bit_cast<NativeError>( 0x800700DFU) ;
// Callbackまたはclockの内部失敗。
constexpr NativeError INTERNAL_ERROR = std::bit_cast<NativeError>( 0x80004005U) ;

/**
 * @brief テスト予算が製品上限を拡大しないか確認する。
 * @param[in] limits 注入された予算。
 * @return 正の値で全項目が製品上限以下ならtrue。
 */
bool				  validLimits( const MetadataSearchLimits &limits) noexcept
{
	const MetadataSearchLimits maximum ;	// 製品固定値。
	return limits.resourceBytes > 0U && limits.resourceBytes <= maximum.resourceBytes &&
		   limits.providerBytes >= limits.resourceBytes &&
		   limits.providerBytes <= maximum.providerBytes &&
		   limits.sessionBytes >= limits.providerBytes &&
		   limits.sessionBytes <= maximum.sessionBytes && limits.providerResources > 0U &&
		   limits.providerResources <= maximum.providerResources &&
		   limits.sessionResources >= limits.providerResources &&
		   limits.sessionResources <= maximum.sessionResources && limits.providerAttempts > 0U &&
		   limits.providerAttempts <= maximum.providerAttempts &&
		   limits.sessionAttempts >= limits.providerAttempts &&
		   limits.sessionAttempts <= maximum.sessionAttempts && limits.providerMilliseconds > 0U &&
		   limits.providerMilliseconds <= maximum.providerMilliseconds &&
		   limits.sessionMilliseconds >= limits.providerMilliseconds &&
		   limits.sessionMilliseconds <= maximum.sessionMilliseconds ;
}

} // namespace

/** @see metadata_search_budget.h */
MetadataSearchExecutionContext::MetadataSearchExecutionContext(
	const ScanSessionId scanSessionId, MetadataSearchRequest request,
	MetadataSearchCancellation cancellation, MetadataSearchClock clock,
	MetadataNetworkCostReader readCost, const MetadataSearchLimits limits)
	: scanSessionId_( scanSessionId), request_( std::move( request)),
	  cancellation_( std::move( cancellation)), clock_( std::move( clock)),
	  readCost_( std::move( readCost)), limits_( limits)
{
	// 固定policy以外や拡大予算を受理しない。
	if( scanSessionId_ == 0U || request_.policyId != METADATA_SEARCH_POLICY_ID ||
	   request_.policyRevision != METADATA_SEARCH_POLICY_REVISION || !validLimits( limits_)) {
		static_cast<void>( stop( MetadataSearchReason::FAILED, INVALID_ARGUMENT, true)) ;
	}

	sessionStart_ = now() ;
	providers_.reserve( METADATA_SEARCH_PROVIDER_LIMIT) ;
}

/** @see metadata_search_budget.h */
std::uint64_t MetadataSearchExecutionContext::now() noexcept
{
	try {
		const auto current = clock_ ? clock_()
									: static_cast<std::uint64_t>(
										  std::chrono::duration_cast<std::chrono::milliseconds>(
											  std::chrono::steady_clock::now().time_since_epoch())
											  .count()) ;	// 単調時計。
		// 注入時計の逆行を負の経過時間として許可しない。
		if( current < lastNow_) {
			static_cast<void>( stop( MetadataSearchReason::FAILED, INTERNAL_ERROR, true)) ;
			return lastNow_ ;
		}

		lastNow_ = current ;
	} catch( ...) {
		static_cast<void>( stop( MetadataSearchReason::FAILED, INTERNAL_ERROR, true)) ;
	}

	return lastNow_ ;
}

/** @see metadata_search_budget.h */
NativeError MetadataSearchExecutionContext::stop( const MetadataSearchReason reason,
												 const NativeError			error,
												 const bool					session) noexcept
{
	// 全体の最初の停止を後続の成功・失敗で上書きしない。
	if( session && !sessionReason_) {
		sessionReason_ = reason ;
		sessionError_  = error ;
	}

	// 現在Providerの主因も一回だけ固定する。
	if( providerActive_ && !providerReason_) {
		providerReason_ = reason ;
		providerError_	= error ;
	}

	return sessionReason_ ? sessionError_ : providerError_ ;
}

/** @see metadata_search_budget.h */
NativeError MetadataSearchExecutionContext::checkpoint() noexcept
{
	// 既存の全体停止は後から変更しない。
	if( sessionReason_) {
		return sessionError_ ;
	}

	try {
		// 同時成立のcheckpointでは取消しを先に観測する。
		if( cancellation_ && cancellation_()) {
			return stop( MetadataSearchReason::CANCELLED, CANCELLED_ERROR, true) ;
		}
	} catch( ...) {
		return stop( MetadataSearchReason::FAILED, INTERNAL_ERROR, true) ;
	}

	const auto current = now() ;	// 同じcheckpointで使用する一時刻。
	// 時計取得失敗を経過0の継続にしない。
	if( sessionReason_) {
		return sessionError_ ;
	}

	// Session期限は個別期限より先に全体停止を確定する。
	if( current - sessionStart_ >= limits_.sessionMilliseconds) {
		return stop( MetadataSearchReason::DEADLINE_EXCEEDED, TIMEOUT_ERROR, true) ;
	}

	// 個別停止の主因を期限検出で上書きしない。
	if( providerReason_) {
		return providerError_ ;
	}

	// Provider待機時間を有限にし、他Providerへ個別deadlineを継承しない。
	if( providerActive_ && current - providerStart_ >= limits_.providerMilliseconds) {
		return stop( MetadataSearchReason::DEADLINE_EXCEEDED, TIMEOUT_ERROR, false) ;
	}

	return 0 ;
}

/** @see metadata_search_budget.h */
NativeError MetadataSearchExecutionContext::beginProvider( const std::wstring_view providerId)
{
	// 再入、未選択、重複、過大なProvider実行を拒否する。
	if( providerActive_ || providerId.empty() ||
	   providers_.size() >= METADATA_SEARCH_PROVIDER_LIMIT ||
	   std::count( request_.enabledProviderIds.begin(), request_.enabledProviderIds.end(),
				  providerId) != 1 ||
	   std::any_of( providers_.begin(), providers_.end(), [providerId]( const auto &provider) {
		   return provider.providerId == providerId ;
	   })) {
		return INVALID_ARGUMENT ;
	}

	providerReason_.reset() ;
	providerError_	 = 0 ;
	const auto error = checkpoint() ;	// 後続開始前の全体停止確認。
	// 全体停止後は新しいProviderを開始しない。
	if( error != 0) {
		return error ;
	}

	providers_.push_back( {.providerId = std::wstring( providerId)}) ;
	providerActive_ = true ;
	providerStart_	= lastNow_ ;
	return 0 ;
}

/** @see metadata_search_budget.h */
void MetadataSearchExecutionContext::finishProvider( const MetadataSearchReason reason,
													const NativeError		   error) noexcept
{
	// 未開始Providerの終端で直前summaryを変更しない。
	if( !providerActive_) {
		return ;
	}

	auto &provider	= providers_.back() ;	// 一度だけ確定する現在summary。
	provider.reason = providerReason_.value_or( reason) ;
	provider.error	= providerReason_ ? providerError_ : error ;
	providerActive_ = false ;
	resourceActive_ = false ;
	providerReason_.reset() ;
	providerError_ = 0 ;
}

/** @see metadata_search_budget.h */
NativeError MetadataSearchExecutionContext::beginResource( const std::uint64_t maximumBytes) noexcept
{
	// Provider外やresourceの再入を許可しない。
	if( !providerActive_ || resourceActive_ || maximumBytes == 0U) {
		return INVALID_ARGUMENT ;
	}

	const auto error = checkpoint() ;	// 予約前の停止確認。
	// 停止済みの場合は消費を増やさず呼出しを拒否する。
	if( error != 0) {
		return error ;
	}

	auto &provider = providers_.back() ;	// 個別の返却しない消費量。
	// 同時上限ではsession側を先に停止する。
	if( usage_.logicalResources >= limits_.sessionResources ||
	   usage_.bodyBytes >= limits_.sessionBytes) {
		return stop( MetadataSearchReason::BUDGET_EXCEEDED, BUDGET_ERROR, true) ;
	}

	// 個別上限を他Providerの残予算から借りない。
	if( provider.usage.logicalResources >= limits_.providerResources ||
	   provider.usage.bodyBytes >= limits_.providerBytes) {
		return stop( MetadataSearchReason::BUDGET_EXCEEDED, BUDGET_ERROR, false) ;
	}

	++usage_.logicalResources ;
	++provider.usage.logicalResources ;
	resourceActive_ = true ;
	resourceLimit_	= std::min( maximumBytes, limits_.resourceBytes) ;
	resourceBytes_	= 0U ;
	return 0 ;
}

/** @see metadata_search_budget.h */
void MetadataSearchExecutionContext::finishResource() noexcept
{
	resourceActive_ = false ;
}

/** @see metadata_search_budget.h */
NativeError MetadataSearchExecutionContext::beforeHttpAttempt() noexcept
{
	// 専用resourceを開始せず直接送信する経路を拒否する。
	if( !providerActive_ || !resourceActive_) {
		return INVALID_ARGUMENT ;
	}

	const auto error = checkpoint() ;	// Cost API前の停止確認。
	// 既に停止していればcostも照会しない。
	if( error != 0) {
		return error ;
	}

	MetadataNetworkCost cost ;	// 未注入・失敗は未知のまま。
	try {
		// Cost readerは送信ごとに呼び、前回の制限なしを使い回さない。
		if( readCost_) {
			cost = readCost_() ;
		}
	} catch( ...) {
		cost.error = INTERNAL_ERROR ;
	}

	// Cost待機中に発生した取消し・期限を送信前に確認する。
	const auto afterCost = checkpoint() ;
	// Cost照会の完了を取消しや期限より優先して送信しない。
	if( afterCost != 0) {
		return afterCost ;
	}

	// 明確な制限なし以外は今回限りの追加同意を必須にする。
	if( (!cost.unrestricted || cost.error != 0) && !request_.restrictedNetworkApproved) {
		return stop( MetadataSearchReason::NETWORK_NOT_APPROVED,
					cost.error != 0 ? cost.error : ACCESS_DENIED, false) ;
	}

	auto &provider = providers_.back() ;	// 同じProviderの明示試行を加算する。
	// 全体送信上限はredirectでリセットしない。
	if( usage_.httpAttempts >= limits_.sessionAttempts) {
		return stop( MetadataSearchReason::BUDGET_EXCEEDED, BUDGET_ERROR, true) ;
	}

	// 一Providerだけが全体送信予算を消費しない。
	if( provider.usage.httpAttempts >= limits_.providerAttempts) {
		return stop( MetadataSearchReason::BUDGET_EXCEEDED, BUDGET_ERROR, false) ;
	}

	++usage_.httpAttempts ;
	++provider.usage.httpAttempts ;
	return 0 ;
}

/** @see metadata_search_budget.h */
std::uint64_t MetadataSearchExecutionContext::remainingBodyBytes() const noexcept
{
	// Resource外から本文を渡すことを許可しない。
	if( !providerActive_ || !resourceActive_) {
		return 0U ;
	}

	return std::min( {resourceLimit_ - resourceBytes_,
					 limits_.providerBytes - providers_.back().usage.bodyBytes,
					 limits_.sessionBytes - usage_.bodyBytes}) ;
}

/** @see metadata_search_budget.h */
NativeError MetadataSearchExecutionContext::validateDeclaredBodyLength(
	const std::uint64_t bytes) noexcept
{
	const auto error = checkpoint() ;	// 受信前の主停止理由。
	// Resource外や既に停止済みの呼出しを許可しない。
	if( !providerActive_ || !resourceActive_ || error != 0) {
		return error != 0 ? error : INVALID_ARGUMENT ;
	}

	// 宣言長が残予算を超えた時点で受信しない。実消費は増やさない。
	if( bytes > remainingBodyBytes()) {
		return stop( MetadataSearchReason::BUDGET_EXCEEDED, BUDGET_ERROR,
					bytes > limits_.sessionBytes - usage_.bodyBytes) ;
	}

	return 0 ;
}

/** @see metadata_search_budget.h */
std::uint32_t MetadataSearchExecutionContext::readAllowance( const std::uint32_t requested) noexcept
{
	// 失効・取消し後は一byte probeも新しく開始しない。
	if( !providerActive_ || !resourceActive_ || checkpoint() != 0) {
		return 0U ;
	}

	return static_cast<std::uint32_t>(
		std::min<std::uint64_t>( requested, remainingBodyBytes() + 1U)) ;
}

/** @see metadata_search_budget.h */
NativeError MetadataSearchExecutionContext::consumeBytes( const std::uint64_t bytes) noexcept
{
	// 呼出し側は許可済みread量を守り、不正量を成功として渡せない。
	if( !providerActive_ || !resourceActive_ || bytes > remainingBodyBytes() + 1U) {
		return INVALID_ARGUMENT ;
	}

	const auto remaining = remainingBodyBytes() ;			// 三段階の最小残量。
	const auto retained	 = std::min( bytes, remaining) ;	// 保存できる本文。失敗時も消費を維持。
	auto	  &provider	 = providers_.back() ;				// 同じ処理の個別消費量。
	resourceBytes_ += retained ;
	provider.usage.bodyBytes += retained ;
	usage_.bodyBytes += retained ;

	// 超過一byteは保存せず、上限到達を観測した証拠だけを残す。
	if( bytes > remaining) {
		++usage_.probeBytes ;
		++provider.usage.probeBytes ;
		return stop( MetadataSearchReason::BUDGET_EXCEEDED, BUDGET_ERROR,
					usage_.bodyBytes >= limits_.sessionBytes) ;
	}

	// API待機中に取り消されても受信済み消費を返却しない。
	return checkpoint() ;
}

/** @see metadata_search_budget.h */
int MetadataSearchExecutionContext::timeoutMilliseconds( const int maximumMilliseconds) noexcept
{
	// 0はAPIへ渡すと無限待機なので呼出し前の拒否に使う。
	if( maximumMilliseconds <= 0 || checkpoint() != 0) {
		return 0 ;
	}

	auto remaining = limits_.sessionMilliseconds - (lastNow_ - sessionStart_) ;	// 全体残時間。
	// 個別期限も同じ一時刻から制約する。
	if( providerActive_) {
		remaining = std::min( remaining, limits_.providerMilliseconds - (lastNow_ - providerStart_)) ;
	}

	return static_cast<int>(
		std::min<std::uint64_t>( remaining, static_cast<std::uint64_t>( maximumMilliseconds))) ;
}

/** @see metadata_search_budget.h */
bool MetadataSearchExecutionContext::sessionStopped() const noexcept
{
	return sessionReason_.has_value() ;
}
/** @see metadata_search_budget.h */
std::optional<MetadataSearchReason> MetadataSearchExecutionContext::sessionStopReason()
	const noexcept
{
	return sessionReason_ ;
}
/** @see metadata_search_budget.h */
std::optional<MetadataSearchReason> MetadataSearchExecutionContext::providerStopReason()
	const noexcept
{
	return providerReason_ ;
}
/** @see metadata_search_budget.h */
MetadataSearchUsage MetadataSearchExecutionContext::usage() const noexcept
{
	return usage_ ;
}
/** @see metadata_search_budget.h */
const std::vector<MetadataProviderSummary> &MetadataSearchExecutionContext::providers()
	const noexcept
{
	return providers_ ;
}
/** @see metadata_search_budget.h */
std::uint64_t MetadataSearchExecutionContext::elapsedMilliseconds() noexcept
{
	return now() - sessionStart_ ;
}
/** @see metadata_search_budget.h */
ScanSessionId MetadataSearchExecutionContext::scanSessionId() const noexcept
{
	return scanSessionId_ ;
}
/** @see metadata_search_budget.h */
std::wstring_view MetadataSearchExecutionContext::activeProviderId() const noexcept
{
	return providerActive_ ? std::wstring_view( providers_.back().providerId) : std::wstring_view{} ;
}

/** @see metadata_search_budget.h */
const MetadataSearchRequest &MetadataSearchExecutionContext::request() const noexcept
{
	return request_ ;
}

} // namespace drivercrate
