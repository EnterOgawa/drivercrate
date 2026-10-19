//------------------------------------------------------------------------------
/**
 * @file official_catalog_device.h
 * @brief 公式catalog照合用device値型定義。
 * @version 01.02.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  現在driver provider追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  端末内binding fingerprint追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  端末内探索用の有限device観測を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  元enumeratorを破棄した有限bus分類を追加。
 * </pre>
 *
 * @note Driver Store列挙結果から公式catalog Providerへ渡せる非機密device情報を定義します。Native IDは含めず、端末内HMACもnetworkへ渡しま
 *       せん。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <optional>
#include <string>

namespace drivercrate {

//------------------------------------------------------------------------------
// 公式catalog照合用値型定義。
//------------------------------------------------------------------------------

/**
 * @brief 公式catalogの製品名照合に使用する一つの現在device snapshotである。
 */
struct OfficialCatalogDevice {
	/// Scan session内のopaque device identity。
	std::wstring					 deviceIdentity ;
	/// SetupAPIが返したdevice表示名。
	std::wstring					 model ;
	/// SetupAPIが返したdevice製造元。
	std::wstring					 manufacturer ;
	/// Windows setup class表示名。
	std::wstring					 driverClass ;
	/// Windows標準class icon用GUID。
	std::wstring					 deviceClassGuid ;
	/// 現在driver packageのProvider表示名。
	std::wstring					 currentProvider ;
	/// 現在使用中のWindows driver version。
	std::wstring					 currentVersion ;
	/// 現在使用中driverの日付。
	std::wstring					 currentDate ;
	/// 端末固有keyで生成したworker内限定HMAC。Network、UI、logへ渡さない。
	std::wstring					 localBindingFingerprint ;
	/// 現在構成の有限観測。端末内の探索制御専用でHTTP・通常logへ送らない。
	std::optional<DeviceObservation> deviceObservation ;
	/// 元enumerator文字列を破棄した端末内探索用の有限bus分類。
	OfficialDiscoveryDeviceBus		 discoveryBus{OfficialDiscoveryDeviceBus::UNKNOWN} ;
} ;

} // namespace drivercrate
