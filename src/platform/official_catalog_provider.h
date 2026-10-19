//------------------------------------------------------------------------------
/**
 * @file official_catalog_provider.h
 * @brief 公式vendor catalog Provider契約定義。
 * @version 01.00.01
 * @date 2026/09/01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Catalog Hardware ID local照合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note Hardware IDをnetworkへ渡さず、公式vendor catalogを追加できる契約を定義します。Provider固有metadataは各実装のscan session内
 *       だけに保持します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_provider.h"
#include "platform/official_catalog_device.h"

#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate {

//------------------------------------------------------------------------------
// 公式vendor catalog Provider契約定義。
//------------------------------------------------------------------------------

/**
 * @brief 公式catalog側のHardware IDをlocal deviceへ解決する、network非接続の照合関数。
 */
using LocalHardwareIdMatcher = std::function<std::optional<std::wstring>( std::wstring_view)> ;

/**
 * @brief Local device snapshotをhardware makerの公式catalogへ照合する契約である。
 *
 * @note 実装はHardware ID、instance ID、serial numberをnetworkへ送信してはならない。取得元、
 * schema、payload署名、適用性、EULA、rollbackの境界はProvider別ADRへ記録する。
 */
class IOfficialCatalogProvider {
public:
	/**
     * @brief Providerをinterface経由で安全に破棄する。
     */
	virtual ~IOfficialCatalogProvider() = default ;

	/**
     * @brief 非機密device snapshotに対応する公式driver releaseを検索する。
     * @param[in] scanSessionId 呼出し側が割り当てた0ではないsession ID。
     * @param[in] devices Driver Store列挙から得た非機密device snapshot群。
     * @param[in] hardwareIdMatcher 公式catalog側IDをlocal deviceへ解決する照合関数。
     * @param[in] progressCallback 検索段階、件数、完了率の通知先。
     * @return 取得元を明示した候補または取得失敗を含むscan結果。
     * @note matcherへ渡すIDは取得済みcatalog由来であり、local IDをnetworkへ送信しない。
     */
	[[nodiscard]] virtual ScanResult	scan( ScanSessionId							scanSessionId,
											 std::span<const OfficialCatalogDevice> devices,
											 const LocalHardwareIdMatcher		   &hardwareIdMatcher,
											 const ProviderProgressCallback &progressCallback) = 0 ;

	/**
     * @brief 選択された公式releaseを再検証して取得・導入する。
     * @param[in] scanSessionId 選択元のscan session ID。
     * @param[in] identities Providerがscan時に発行したopaque identity群。
     * @param[in] parentWindowNative Installer UIの親Windowを表す値。
     * @param[in] progressCallback Download、検証、installの進捗通知先。
     * @return 選択候補ごとのdownload/install結果。
     */
	[[nodiscard]] virtual InstallResult install(
		ScanSessionId scanSessionId, std::span<const std::wstring> identities,
		std::uintptr_t parentWindowNative, const ProviderProgressCallback &progressCallback) = 0 ;
} ;

} // namespace drivercrate
