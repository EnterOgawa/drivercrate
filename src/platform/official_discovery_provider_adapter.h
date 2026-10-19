//------------------------------------------------------------------------------
/**
 * @file official_discovery_provider_adapter.h
 * @brief 審査済みProviderを公式自動探索registrationへ接続する契約。
 * @version 01.01.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Intel Windows 11固定root registrationを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Cache失効用parser identityをregistrationへ結合。
 * </pre>
 *
 * @note RegistrationはProvider worker内の秘密record sessionを借用します。Device hintは端末内matcher
 *       だけで使用し、resolverまたはnetwork requestへ渡しません。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_discovery_planner.h"
#include "platform/official_discovery_record_adapter.h"

#include <optional>
#include <span>
#include <vector>

namespace drivercrate {

/**
 * @brief Intel Ethernet Windows 11固定rootの端末内route対象を判定する。
 * @param[in] hint Raw PnP IDを含まない一deviceの有限hint。
 * @return PCI上のNet classと審査済みIntel Ethernet表示系列が一致する場合true。
 * @note 本結果は探索先の選択だけに使用し、PnP適合、最新版、推奨または導入可能性を意味しません。
 */
[[nodiscard]] bool matchesIntelEthernetWindows11OfficialDiscoveryHint(
	const OfficialDiscoveryDeviceHint &hint) noexcept ;

/**
 * @brief 組み込みProvider正本から検証済み公式自動探索registrationを作成する。
 * @param[in,out] recordSession Composite workerがregistrationより長く所有する秘密record session。
 * @param[in] intelEthernetWindows11Resolver Intel固定rootだけを処理する型付きresolver。
 * @param[in] cancellation 同じworker operationの非blocking取消し照会。
 * @param[in] descriptors Provider registryの正本または同じ合成copy。
 * @return 全Provider、source policy、root、callbackが一致するregistration集合。不正時は値なし。
 * @throws std::bad_alloc Registrationまたはcallbackの所有領域を確保できない場合。
 * @warning 戻り値はrecordSessionとresolverが参照する依存関係より先に破棄してください。
 */
[[nodiscard]] std::optional<std::vector<OfficialDiscoveryRegistration>>
makeBuiltInOfficialDiscoveryRegistrations(
	OfficialDiscoveryRecordAdapterSession &recordSession,
	OfficialDiscoveryFixedRootResolver	   intelEthernetWindows11Resolver,
	OfficialRecordResolutionCancellation   cancellation,
	std::span<const ProviderDescriptor>	   descriptors) ;

} // namespace drivercrate
