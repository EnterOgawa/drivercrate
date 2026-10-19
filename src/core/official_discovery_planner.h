//------------------------------------------------------------------------------
/**
 * @file official_discovery_planner.h
 * @brief 公式自動探索registrationと端末内route planの契約。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Registration検証と決定的route plannerを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Purpose伝達と専用adapter欠損集合を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  Cache失効用parser identityをregistrationへ追加。
 * Ver.01.02.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note Plannerはmatcherだけを端末内で呼び、resolver、network、cache、payload処理を開始しません。
 * Registrationとplanはraw ID、URL、host、path、serialを保持しません。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_discovery.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {

// 初期実装でnetworkへ送信できるhint fieldは存在しない。
inline constexpr std::uint32_t OFFICIAL_DISCOVERY_NETWORK_HINT_NONE = 0U ;

/**
 * @brief 借用hintを表示値だけで判定する例外非送出の端末内matcher。
 */
using OfficialDiscoveryHintMatcher = bool ( *)( const OfficialDiscoveryDeviceHint &) noexcept ;

/**
 * @brief 06c以降で固定rootの解決結果を返すcallback。Plannerは呼び出さない。
 */
using OfficialDiscoveryRecordResolver = std::function<OfficialDiscoveryRouteSummary(
	const OfficialDiscoveryRequest &, const OfficialDiscoveryRoute &,
	std::span<const OfficialDiscoveryDeviceHint>)> ;

/**
 * @brief 一つの公式Provider、source policy、固定rootと実行adapterを結合する。
 */
struct OfficialDiscoveryRegistration {
	/// Provider registryのstable ID。
	std::wstring					providerId ;
	/// Provider descriptorと完全一致する公式source policy ID。
	std::wstring					sourcePolicyId ;
	/// Policy内のlandingまたはmetadata resource ID。
	std::wstring					rootResourceId ;
	/// Cacheを生成するrecord parserのstable ID。
	std::wstring					parserId ;
	/// Cache失効に使用するrecord parserの単調revision。
	std::uint32_t					parserRevision{} ;
	/// 専用adapterまたは汎用固定root parserの種別。
	OfficialDiscoveryRouteKind		kind{OfficialDiscoveryRouteKind::DEDICATED} ;
	/// Bus、class、manufacturer等を端末内で判定する純粋関数。
	OfficialDiscoveryHintMatcher	matcher{} ;
	/// 固定rootだけを解決する実行callback。Plannerでは存在だけを検証する。
	OfficialDiscoveryRecordResolver resolver ;
	/// Networkへ送信できるhint field mask。初期実装は0だけを許可する。
	std::uint32_t					networkHintFields{OFFICIAL_DISCOVERY_NETWORK_HINT_NONE} ;
} ;

/**
 * @brief 一つのbindingとrequestから決定したraw ID非保持route planを表す。
 */
struct OfficialDiscoveryRoutePlan {
	/// Operation、scan session、inventory generationの開始時binding。
	OfficialDiscoveryBinding			binding ;
	/// Provider範囲と権限を固定した要求の所有copy。
	OfficialDiscoveryRequest			request ;
	/// 全present nodeを一つのsnapshotへ変換できた場合だけtrue。
	bool								inventoryComplete{} ;
	/// 入力した重複なしpresent device件数。
	std::uint32_t						deviceCount{} ;
	/// 専用を先、汎用を後に並べた重複なしroute。
	std::vector<OfficialDiscoveryRoute> routes ;
	/// 汎用固定rootだけへ対応し、専用adapterを持たないopaque device identity。
	std::vector<std::wstring>			dedicatedUnavailableDeviceIdentities ;
	/// 選択済み固定rootへ一件も対応しなかったopaque device identity。
	std::vector<std::wstring>			noTrustedRootDeviceIdentities ;
} ;

/**
 * @brief 自動探索registration全体をProvider registryと公式source policyへ照合する。
 * @param[in] registrations 一回の実行に使用するregistration snapshot。
 * @param[in] descriptors Provider registryの正本または合成copy。
 * @return 全自動探索Providerを一意な固定rootと非空callbackへ結合できる場合true。
 */
[[nodiscard]] bool validateOfficialDiscoveryRegistrations(
	std::span<const OfficialDiscoveryRegistration> registrations,
	std::span<const ProviderDescriptor>			   descriptors) noexcept ;

/**
 * @brief 有限hintを専用、汎用の順で固定公式rootへまとめる。
 * @param[in] binding Operation、scan session、inventory generationの開始時binding。
 * @param[in] request Provider範囲と権限を固定した検証対象request。
 * @param[in] inventoryComplete 全present nodeを表現できた場合true。
 * @param[in] devices 同じscan sessionの重複なしraw ID非保持hint。
 * @param[in] registrations 検証済みであることを再確認する実行registration。
 * @param[in] descriptors Provider registryの正本または合成copy。
 * @return 全入力が妥当でroute上限内なら所有plan。不正または上限超過は値なし。
 * @throws std::bad_alloc Planまたは検証領域を確保できない場合。
 * @note Matcherだけを呼び、resolver、HTTP、cache、payload処理は呼び出さない。
 */
[[nodiscard]] std::optional<OfficialDiscoveryRoutePlan> makeOfficialDiscoveryRoutePlan(
	const OfficialDiscoveryBinding &binding, const OfficialDiscoveryRequest &request,
	bool inventoryComplete, std::span<const OfficialDiscoveryDeviceHint> devices,
	std::span<const OfficialDiscoveryRegistration> registrations,
	std::span<const ProviderDescriptor>			   descriptors) ;

/**
 * @brief 公開前のplanを開始時snapshotとregistrationへ完全一致で再結合する。
 * @param[in] binding 開始時のoperation、scan session、inventory generation。
 * @param[in] request 開始時のProvider範囲と権限。
 * @param[in] devices 開始時のraw ID非保持hint集合。
 * @param[in] registrations 計画時と同じ実行registration集合。
 * @param[in] descriptors Provider registryの正本または合成copy。
 * @param[in] plan 検証する所有plan。
 * @return 件数、順序、root、group、未route deviceが全て整合する場合true。
 * @throws std::bad_alloc 検証用の一意性またはgroup領域を確保できない場合。
 */
[[nodiscard]] bool isOfficialDiscoveryRoutePlanValid(
	const OfficialDiscoveryBinding &binding, const OfficialDiscoveryRequest &request,
	std::span<const OfficialDiscoveryDeviceHint>   devices,
	std::span<const OfficialDiscoveryRegistration> registrations,
	std::span<const ProviderDescriptor> descriptors, const OfficialDiscoveryRoutePlan &plan) ;

} // namespace drivercrate
