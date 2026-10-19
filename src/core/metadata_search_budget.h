//------------------------------------------------------------------------------
/**
 * @file metadata_search_budget.h
 * @brief 検索sessionの有限予算と協調停止契約。
 * @version 01.01.02
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
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  十Provider用の件数予算へ更新。
 * Ver.01.01.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.01.02   Shunji Ogawa  2026/10/16 使用量とsession取得の戻り値を正本宣言へ補足。
 * </pre>
 *
 * @see docs/adr/0153-intel-ethernet-windows11-provider-integration.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/metadata_search_types.h"
#include "core/update_types.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <string_view>
#include <vector>

namespace drivercrate {

/** @brief 製品では固定、testでは縮小だけを許す予算。 */
struct MetadataSearchLimits {
	/// 一resourceの本文byte上限。
	std::uint64_t resourceBytes{2U * 1024U * 1024U} ;
	/// 一Providerの本文byte上限。
	std::uint64_t providerBytes{4U * 1024U * 1024U} ;
	/// 全sessionの本文byte上限。
	std::uint64_t sessionBytes{32U * 1024U * 1024U} ;
	/// 一Providerのlogical resource数上限。
	std::uint32_t providerResources{2U} ;
	/// 全sessionのlogical resource数上限。
	std::uint32_t sessionResources{20U} ;
	/// 一Providerの明示送信試行上限。
	std::uint32_t providerAttempts{12U} ;
	/// 全sessionの明示送信試行上限。
	std::uint32_t sessionAttempts{120U} ;
	/// 一Providerの経過millisecond上限。
	std::uint64_t providerMilliseconds{90000U} ;
	/// Inventoryを含むsession経過millisecond上限。
	std::uint64_t sessionMilliseconds{300000U} ;
} ;

/** @brief Windowsのcost照会で確定した最小情報。 */
struct MetadataNetworkCost {
	/// trueの場合だけ制限なしを確認できた。
	bool		unrestricted{} ;
	/// Cost照会APIの元診断。取得不能を制限なしへ変えない。
	NativeError error{} ;
} ;

/**
 * @brief Testではmonotonic millisecondを注入する。Productionではsteady_clockを使う。
 */
using MetadataSearchClock = std::function<std::uint64_t()> ;
/**
 * @brief trueは取消し要求。参照先atomicの寿命はcontext全体を包含する。
 */
using MetadataSearchCancellation = std::function<bool()> ;
/**
 * @brief 送信直前に実回線のcostを照会する。未注入は未知扱い。
 */
using MetadataNetworkCostReader = std::function<MetadataNetworkCost()> ;

/**
 * @brief 一worker内だけで直列使用する、返却しない検索予算と協調停止。
 * @note Callbackの参照先はcontextより長生きする。UI threadで操作しない。
 */
class MetadataSearchExecutionContext final {
public:
	/**
     * @brief 有限policyへ拘束した一sessionのcontextを構築する。
     * @param[in] scanSessionId 非ゼロのworker発行session。
     * @param[in] request 事前検証済み要求。所有copyする。
     * @param[in] cancellation 同期の非blocking取消し照会。空は取消しなし。
     * @param[in] clock Test用時計。空はsteady_clock。
     * @param[in] readCost 送信ごとのcost照会。空は未知。
     * @param[in] limits 製品上限以下の予算。拡大や0は拒否。
     */
	MetadataSearchExecutionContext( ScanSessionId scanSessionId, MetadataSearchRequest request,
								   MetadataSearchCancellation cancellation = {},
								   MetadataSearchClock		  clock		   = {},
								   MetadataNetworkCostReader  readCost	   = {},
								   MetadataSearchLimits		  limits	   = {}) ;

	/**
     * @brief 選択済みProviderを一度だけ開始し、個別予算を用意する。
     * @param[in] providerId Requestへ明示したstable ID。
     * @return 成功0。未知、重複、停止済みは診断値。
     */
	[[nodiscard]] NativeError beginProvider( std::wstring_view providerId) ;

	/**
     * @brief Providerの個別終端を確定する。既に観測した停止原因は保持する。
     * @param[in] reason 呼出側が得た終端理由。
     * @param[in] error 元のnative診断。既存の主因を上書きしない。
     */
	void finishProvider( MetadataSearchReason reason, NativeError error = 0) noexcept ;

	/**
     * @brief 一つのlogical resourceを予約する。Cacheも一回と数える。
     * @param[in] maximumBytes Provider固有上限。固定上限との小さい方を使う。
     * @return 成功0、停止または予算超過時は診断値。
     */
	[[nodiscard]] NativeError	beginResource( std::uint64_t maximumBytes) noexcept ;

	/** @brief 同期resource呼出しの終端を通知する。消費量を返却しない。 */
	void						finishResource() noexcept ;

	/**
     * @brief Cancelとdeadlineを確認し、最初に観測した主因を固定する。
     * @return 継続できれば0、停止原因のnative診断値。
     */
	[[nodiscard]] NativeError	checkpoint() noexcept ;

	/**
     * @brief Cost・取消し・予算を照合し、一つの明示送信試行を計数する。
     * @return 送信許可時0、未同意・停止・予算超過時は診断値。
     */
	[[nodiscard]] NativeError	beforeHttpAttempt() noexcept ;

	/**
	 * @brief 宣言済み本文長が残予算を超える場合、本文受信前に停止する。
	 * @param[in] bytes 拒否の参考だけに使うContent-Length。0は未知。
	 * @return 上限内または未知なら0。超過は消費を創作せず予算停止。
	 */
	[[nodiscard]] NativeError	validateDeclaredBodyLength( std::uint64_t bytes) noexcept ;

	/**
     * @brief 読取り前に許可するbyte数を返す。上限判定用probeは最大一byte。
     * @param[in] requested Transportが要求した上限。
     * @return 今回読み取れる量。0は停止済みまたは不正な呼出し。
     */
	[[nodiscard]] std::uint32_t readAllowance( std::uint32_t requested) noexcept ;

	/**
     * @brief 実受信またはcache本文を計数する。失敗時も返却しない。
     * @param[in] bytes ReadAllowance以下の実受信量。Cacheも同じ上限で分割する。
     * @return 上限内なら0。Probeを受信した場合は予算超過。
     */
	[[nodiscard]] NativeError	consumeBytes( std::uint64_t bytes) noexcept ;

	/**
     * @brief 残deadlineで有限phase timeoutを切り詰める。
     * @param[in] maximumMilliseconds 既存WinHTTP phaseの正の上限。
     * @return 正のtimeout。停止済みは0で、APIを呼んではならない。
     */
	[[nodiscard]] int			timeoutMilliseconds( int maximumMilliseconds) noexcept ;

	/**
	 * @brief 全体停止を観測済みならtrue。個別停止だけではfalse。
	 * @return 全sessionの停止を観測済みならtrue。未停止または個別Provider停止だけならfalse。
	 */
	[[nodiscard]] bool			sessionStopped() const noexcept ;
	/**
	 * @brief 全体の主停止理由。停止していなければ値なし。
	 * @return 全体停止時の主理由。全体が停止していなければnullopt。
	 */
	[[nodiscard]] std::optional<MetadataSearchReason>		  sessionStopReason() const noexcept ;
	/**
	 * @brief 現在Providerの最初の停止理由。継続中は値なし。
	 * @return 現在Providerの最初の停止理由。継続中はnullopt。
	 */
	[[nodiscard]] std::optional<MetadataSearchReason>		  providerStopReason() const noexcept ;
	/**
	 * @brief 一sessionの返却しない総消費量。
	 * @return 取得時点の総消費量のcopy。予算の返却や内部状態の変更は行いません。
	 */
	[[nodiscard]] MetadataSearchUsage						  usage() const noexcept ;
	/**
	 * @brief 実行済みProviderのsummary。次変更までの非所有view。
	 * @return 実行済みsummary列への非所有参照。次のcontext変更まで要素・viewを保持できる。
	 */
	[[nodiscard]] const std::vector<MetadataProviderSummary> &providers() const noexcept ;
	/**
	 * @brief Worker開始からのmonotonic経過millisecond。
	 * @return Worker開始からの単調経過millisecond。注入時計の失敗・逆行は停止状態へ反映する。
	 */
	[[nodiscard]] std::uint64_t								  elapsedMilliseconds() noexcept ;
	/**
	 * @brief Contextへ拘束したworker session。
	 * @return Contextが保持するworker scan session ID。
	 */
	[[nodiscard]] ScanSessionId								  scanSessionId() const noexcept ;
	/**
	 * @brief 現在のProvider ID。未開始または終端後は空。
	 * @return 現在Provider IDの非所有view。未開始・終端後は空。Contextの次変更まで有効。
	 */
	[[nodiscard]] std::wstring_view							  activeProviderId() const noexcept ;
	/**
	 * @brief Contextが所有する今回の要求。Context破棄まで有効な非所有参照。
	 * @return Contextが所有する今回要求への非所有参照。Context破棄まで有効。
	 */
	[[nodiscard]] const MetadataSearchRequest				 &request() const noexcept ;

private:
	/**
     * @brief 注入時計を読む。失敗・逆行は全体停止にする。
     * @return 単調性を検証した現在millisecond。
     */
	[[nodiscard]] std::uint64_t now() noexcept ;
	/**
     * @brief 最初の停止原因と診断を個別または全体へ固定する。
     * @param[in] reason 停止原因。
     * @param[in] error 保持するnative診断。
     * @param[in] session trueは後続Providerも停止。
     * @return 実際に保持した診断値。
     */
	NativeError stop( MetadataSearchReason reason, NativeError error, bool session) noexcept ;
	/**
	 * @brief 現在resourceとProviderとsessionの本文残量の最小値。
	 * @return Resource、Provider、sessionの本文残byteの最小値。
	 */
	[[nodiscard]] std::uint64_t			 remainingBodyBytes() const noexcept ;

	/// 一意なworker session。
	ScanSessionId						 scanSessionId_{} ;
	/// 今回だけの選択と通信許可。
	MetadataSearchRequest				 request_ ;
	/// 現在operationのatomicを読むcallback。
	MetadataSearchCancellation			 cancellation_ ;
	/// Testまたはsteady_clockによる単調時計。
	MetadataSearchClock					 clock_ ;
	/// 送信直前のcost読取り。
	MetadataNetworkCostReader			 readCost_ ;
	/// 製品上限以下へ確定した予算。
	MetadataSearchLimits				 limits_ ;
	/// 全体で消費したbyteとrequest。
	MetadataSearchUsage					 usage_ ;
	/// 実行したProviderごとの停止理由と消費量。
	std::vector<MetadataProviderSummary> providers_ ;
	/// 現在のProviderが未終端の場合true。
	bool								 providerActive_{} ;
	/// 一つの同期resource呼出し内だけtrue。
	bool								 resourceActive_{} ;
	/// 現在resourceの本文上限。
	std::uint64_t						 resourceLimit_{} ;
	/// 現在resourceで読み取った本文byte数。
	std::uint64_t						 resourceBytes_{} ;
	/// Session開始時刻。
	std::uint64_t						 sessionStart_{} ;
	/// 現在Provider開始時刻。
	std::uint64_t						 providerStart_{} ;
	/// 時計逆行を検出する前回値。
	std::uint64_t						 lastNow_{} ;
	/// 一度確定した全体停止原因。
	std::optional<MetadataSearchReason>	 sessionReason_ ;
	/// 全体停止の最初の診断値。
	NativeError							 sessionError_{} ;
	/// 現在Providerの主停止原因。
	std::optional<MetadataSearchReason>	 providerReason_ ;
	/// 現在Providerの最初の診断値。
	NativeError							 providerError_{} ;
} ;

} // namespace drivercrate
