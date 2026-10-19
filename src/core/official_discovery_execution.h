//------------------------------------------------------------------------------
/**
 * @file official_discovery_execution.h
 * @brief 共通route planを通常／metadata目的へ渡す有限実行契約。
 * @version 01.02.01
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Purpose伝達と専用／汎用継続を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/09/15  開始時bindingとrequestの再照合を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  通信未許可summaryとProvider結果変換を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  Fresh cache優先とroute別通信許可を追加。
 * Ver.01.02.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 本関数はregistrationのresolverだけを同期呼出しし、network権限やpayload権限を補完しません。
 * Resolverは受け取ったrequest purposeと別工程の有限予算に従う責務を持ちます。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_discovery_planner.h"

#include <functional>
#include <optional>
#include <span>

namespace drivercrate {

/**
 * @brief 現在requestと固定root routeだけからfresh cache summaryを返す任意callbackです。
 */
using OfficialDiscoveryRouteCacheLookup =
	std::function<std::optional<OfficialDiscoveryRouteSummary>( const OfficialDiscoveryRequest &,
															   const OfficialDiscoveryRoute &)> ;

/**
 * @brief 検証済みplanを専用、汎用の順で実行して非機密summaryへ集約する。
 * @param[in] binding 呼出側が保持する開始時binding。
 * @param[in] request 呼出側が保持する開始時request。
 * @param[in] plan 同じbinding、request、inventoryへ結合したroute plan。
 * @param[in] devices Plan生成時と同じraw ID非保持hint集合。
 * @param[in] registrations Plan生成時と同じmatcher／resolver registration集合。
 * @param[in] descriptors Provider registryの正本または同じ合成copy。
 * @param[in] cacheLookup Fresh positive／negativeだけを返す任意のURL非保持cache照会です。
 * @param[in] resolverApproved Cache miss時の固定root resolver実行が今回許可される場合trueです。
 * @return 全入力と結果が妥当ならsummary。開始契約を再現できない場合は値なし。
 * @throws std::bad_alloc 実行用hintまたはsummary領域を確保できない場合。
 * @note `FORCE_REFRESH`ではcache callbackを呼びません。Fresh cacheはresolverより先に使用し、miss時だけ
 *       `resolverApproved`を確認します。Cacheからdownload grantまたは導入権限を復元しません。
 */
[[nodiscard]] std::optional<OfficialDiscoverySummary> runOfficialDiscoveryRoutePlan(
	const OfficialDiscoveryBinding &binding, const OfficialDiscoveryRequest &request,
	const OfficialDiscoveryRoutePlan &plan, std::span<const OfficialDiscoveryDeviceHint> devices,
	std::span<const OfficialDiscoveryRegistration> registrations,
	std::span<const ProviderDescriptor>			   descriptors,
	OfficialDiscoveryRouteCacheLookup cacheLookup = {}, bool resolverApproved = true) ;

/**
 * @brief Resolverを呼ばず全routeを同じ制御終端へ確定する。
 * @param[in] binding 呼出側が保持する開始時binding。
 * @param[in] request 呼出側が保持する開始時request。
 * @param[in] plan 同じbinding、request、inventoryへ結合したroute plan。
 * @param[in] devices Plan生成時と同じraw ID非保持hint集合。
 * @param[in] registrations Plan生成時と同じregistration集合。
 * @param[in] descriptors Provider registryの正本または同じ合成copy。
 * @param[in] state Network未許可、予算到達または取消しの制御終端。
 * @return 全入力と制御状態が妥当ならURL非保持summary。それ以外は値なし。
 * @throws std::bad_alloc Summary領域を確保できない場合。
 * @note 回線確認等でHTTP開始前に停止した全routeを候補0件へ縮退させず保持します。
 */
[[nodiscard]] std::optional<OfficialDiscoverySummary> makeOfficialDiscoveryControlSummary(
	const OfficialDiscoveryBinding &binding, const OfficialDiscoveryRequest &request,
	const OfficialDiscoveryRoutePlan &plan, std::span<const OfficialDiscoveryDeviceHint> devices,
	std::span<const OfficialDiscoveryRegistration> registrations,
	std::span<const ProviderDescriptor> descriptors, OfficialDiscoveryRouteState state) ;

/**
 * @brief 共通route summaryから一つのProviderの通常scan結果を構築する。
 * @param[in] scanSessionId 現在の通常scan session ID。
 * @param[in] providerId 変換対象の自動探索Provider stable ID。
 * @param[in] devices Plan生成時と同じraw ID非保持hint集合。
 * @param[in] plan 実行または制御終端へ使用したroute plan。
 * @param[in] summary Planと一対一に結合した非機密summary。
 * @param[in] descriptors Provider registryの正本または同じ合成copy。
 * @return 候補を発行せず到達状態とcoverageを保持する結果。入力不整合時は値なし。
 * @throws std::bad_alloc Coverageの一意性領域を確保できない場合。
 * @note Recordとpackageの解決はpayload取得または候補成立ではないため、packageがある場合も
 * `PAYLOAD_NOT_APPROVED`で返します。
 */
[[nodiscard]] std::optional<ScanResult> makeOfficialDiscoveryProviderScanResult(
	ScanSessionId scanSessionId, std::wstring_view providerId,
	std::span<const OfficialDiscoveryDeviceHint> devices, const OfficialDiscoveryRoutePlan &plan,
	const OfficialDiscoverySummary &summary, std::span<const ProviderDescriptor> descriptors) ;

} // namespace drivercrate
