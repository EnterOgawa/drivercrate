//------------------------------------------------------------------------------
/**
 * @file official_discovery_inventory.h
 * @brief Present inventoryを非機密な公式自動探索hintへ変換する境界。
 * @version 01.00.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Bus分類とrouting hint変換を追加。
 * </pre>
 *
 * @note Native enumeratorまたはinstance IDは分類関数の呼出し中だけ借用し、戻り値、
 * hint、UI、network、cache、通常logへ複製しません。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_discovery.h"
#include "platform/official_catalog_device.h"

#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace drivercrate {

/**
 * @brief Native enumeratorまたはinstance IDを有限busへ分類して元文字列を破棄する。
 * @param[in] nativeIdentity Worker内だけで借用するenumeratorまたはinstance ID。
 * @return 既知prefix、OTHER、欠損／不正時のUNKNOWNのいずれか。
 * @note 大小文字だけを正規化し、部分一致または表示名からbusを推測しない。
 */
[[nodiscard]] OfficialDiscoveryDeviceBus classifyOfficialDiscoveryDeviceBus(
	std::wstring_view nativeIdentity) noexcept ;

/**
 * @brief 完全なpresent inventoryをraw ID非保持のrouting hint集合へ変換する。
 * @param[in] scanSessionId 全観測を結合する0ではないscan session ID。
 * @param[in] inventoryComplete 全present nodeを上限内で表現できた場合true。
 * @param[in] devices Driver Store現在行から構築した非機密snapshot。
 * @return 入力全体が妥当なら同順の所有hint集合。不完全・重複・不正時は値なし。
 * @throws std::bad_alloc 所有hint領域を確保できない場合。
 */
[[nodiscard]] std::optional<std::vector<OfficialDiscoveryDeviceHint>>
makeOfficialDiscoveryDeviceHints( ScanSessionId scanSessionId, bool inventoryComplete,
								 std::span<const OfficialCatalogDevice> devices) ;

} // namespace drivercrate
