//------------------------------------------------------------------------------
/**
 * @file metadata_search_budget.cpp
 * @brief 検索予算・制限回線同意・取消しの純粋実装。
 * @version 01.00.01
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
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
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

//------------------------------------------------------------------------------
/**
 * @brief テスト予算が製品上限を拡大しないか確認する。
 * @param[in] limits 注入された予算。
 * @return 正の値で全項目が製品上限以下ならtrue。
 */
//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
/**
 * @brief 有限policyへ拘束した一sessionのcontextを構築する。
 * @param[in] scanSessionId 非ゼロのworker発行session。
 * @param[in] request 事前検証済み要求。所有copyする。
 * @param[in] cancellation 同期の非blocking取消し照会。空は取消しなし。
 * @param[in] clock Test用時計。空はsteady_clock。
 * @param[in] readCost 送信ごとのcost照会。空は未知。
 * @param[in] limits 製品上限以下の予算。拡大や0は拒否。
 */
//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
/**
 * @brief 注入時計を読む。失敗・逆行は全体停止にする。
 * @return 単調性を検証した現在millisecond。
 */
//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
/**
 * @brief 最初の停止原因と診断を個別または全体へ固定する。
 * @param[in] reason 停止原因。
 * @param[in] error 保持するnative診断。
 * @param[in] session trueは後続Providerも停止。
 * @return 実際に保持した診断値。
 */
//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
/**
 * @brief Cancelとdeadlineを確認し、最初に観測した主因を固定する。
 * @return 継続できれば0、停止原因のnative診断値。
 */
//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
/**
 * @brief 選択済みProviderを一度だけ開始し、個別予算を用意する。
 * @param[in] providerId Requestへ明示したstable ID。
 * @return 成功0。未知、重複、停止済みは診断値。
 */
//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
/**
 * @brief Providerの個別終端を確定する。既に観測した停止原因は保持する。
 * @param[in] reason 呼出側が得た終端理由。
 * @param[in] error 元のnative診断。既存の主因を上書きしない。
 */
//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
/**
 * @brief 一つのlogical resourceを予約する。Cacheも一回と数える。
 * @param[in] maximumBytes Provider固有上限。固定上限との小さい方を使う。
 * @return 成功0、停止または予算超過時は診断値。
 */
//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
/**
 * @brief 同期resource呼出しの終端を通知する。消費量を返却しない。
 */
//------------------------------------------------------------------------------
void MetadataSearchExecutionContext::finishResource() noexcept
{
	resourceActive_ = false ;
}

//------------------------------------------------------------------------------
/**
 * @brief Cost・取消し・予算を照合し、一つの明示送信試行を計数する。
 * @return 送信許可時0、未同意・停止・予算超過時は診断値。
 */
//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
/**
 * @brief 現在resourceとProviderとsessionの本文残量の最小値。
 * @return Resource、Provider、sessionの本文残byteの最小値。
 */
//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
/**
 * @brief 宣言済み本文長が残予算を超える場合、本文受信前に停止する。
 * @param[in] bytes 拒否の参考だけに使うContent-Length。0は未知。
 * @return 上限内または未知なら0。超過は消費を創作せず予算停止。
 */
//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
/**
 * @brief 読取り前に許可するbyte数を返す。上限判定用probeは最大一byte。
 * @param[in] requested Transportが要求した上限。
 * @return 今回読み取れる量。0は停止済みまたは不正な呼出し。
 */
//------------------------------------------------------------------------------
std::uint32_t MetadataSearchExecutionContext::readAllowance( const std::uint32_t requested) noexcept
{
	// 失効・取消し後は一byte probeも新しく開始しない。
	if( !providerActive_ || !resourceActive_ || checkpoint() != 0) {
		return 0U ;
	}

	return static_cast<std::uint32_t>(
		std::min<std::uint64_t>( requested, remainingBodyBytes() + 1U)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実受信またはcache本文を計数する。失敗時も返却しない。
 * @param[in] bytes ReadAllowance以下の実受信量。Cacheも同じ上限で分割する。
 * @return 上限内なら0。Probeを受信した場合は予算超過。
 */
//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
/**
 * @brief 残deadlineで有限phase timeoutを切り詰める。
 * @param[in] maximumMilliseconds 既存WinHTTP phaseの正の上限。
 * @return 正のtimeout。停止済みは0で、APIを呼んではならない。
 */
//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
/**
 * @brief 全体停止を観測済みならtrue。個別停止だけではfalse。
 * @return 全sessionの停止を観測済みならtrue。未停止または個別Provider停止だけならfalse。
 */
//------------------------------------------------------------------------------
bool MetadataSearchExecutionContext::sessionStopped() const noexcept
{
	return sessionReason_.has_value() ;
}
//------------------------------------------------------------------------------
/**
 * @brief 全体の主停止理由。停止していなければ値なし。
 * @return 全体停止時の主理由。全体が停止していなければnullopt。
 */
//------------------------------------------------------------------------------
std::optional<MetadataSearchReason> MetadataSearchExecutionContext::sessionStopReason()
	const noexcept
{
	return sessionReason_ ;
}
//------------------------------------------------------------------------------
/**
 * @brief 現在Providerの最初の停止理由。継続中は値なし。
 * @return 現在Providerの最初の停止理由。継続中はnullopt。
 */
//------------------------------------------------------------------------------
std::optional<MetadataSearchReason> MetadataSearchExecutionContext::providerStopReason()
	const noexcept
{
	return providerReason_ ;
}
//------------------------------------------------------------------------------
/**
 * @brief 一sessionの返却しない総消費量。
 * @return 取得時点の総消費量のcopy。予算の返却や内部状態の変更は行いません。
 */
//------------------------------------------------------------------------------
MetadataSearchUsage MetadataSearchExecutionContext::usage() const noexcept
{
	return usage_ ;
}
//------------------------------------------------------------------------------
/**
 * @brief 実行済みProviderのsummary。次変更までの非所有view。
 * @return 実行済みsummary列への非所有参照。次のcontext変更まで要素・viewを保持できる。
 */
//------------------------------------------------------------------------------
const std::vector<MetadataProviderSummary> &MetadataSearchExecutionContext::providers()
	const noexcept
{
	return providers_ ;
}
//------------------------------------------------------------------------------
/**
 * @brief Worker開始からのmonotonic経過millisecond。
 * @return Worker開始からの単調経過millisecond。注入時計の失敗・逆行は停止状態へ反映する。
 */
//------------------------------------------------------------------------------
std::uint64_t MetadataSearchExecutionContext::elapsedMilliseconds() noexcept
{
	return now() - sessionStart_ ;
}
//------------------------------------------------------------------------------
/**
 * @brief Contextへ拘束したworker session。
 * @return Contextが保持するworker scan session ID。
 */
//------------------------------------------------------------------------------
ScanSessionId MetadataSearchExecutionContext::scanSessionId() const noexcept
{
	return scanSessionId_ ;
}
//------------------------------------------------------------------------------
/**
 * @brief 現在のProvider ID。未開始または終端後は空。
 * @return 現在Provider IDの非所有view。未開始・終端後は空。Contextの次変更まで有効。
 */
//------------------------------------------------------------------------------
std::wstring_view MetadataSearchExecutionContext::activeProviderId() const noexcept
{
	return providerActive_ ? std::wstring_view( providers_.back().providerId) : std::wstring_view{} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Contextが所有する今回の要求。Context破棄まで有効な非所有参照。
 * @return Contextが所有する今回要求への非所有参照。Context破棄まで有効。
 */
//------------------------------------------------------------------------------
const MetadataSearchRequest &MetadataSearchExecutionContext::request() const noexcept
{
	return request_ ;
}

} // namespace drivercrate
