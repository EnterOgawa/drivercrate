//------------------------------------------------------------------------------
/**
 * @file driver_store_inventory_transport.h
 * @brief 現在属性列挙の決定的SetupAPI試験境界。
 * @version 01.01.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  現在属性列挙だけの借用API表を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Devnode statusのread-only試験境界を追加。
 * </pre>
 *
 * @note 既定はWindows API。内部fixtureは現在属性scan以外へ使用しない。
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#pragma once

#include <Windows.h>
#include <SetupAPI.h>
#include <cfgmgr32.h>

namespace drivercrate {

/** @brief 現在PnP属性の低位I/O。列挙・上限・公開判定はProvider実装に残す。 */
struct DriverStoreInventoryTransport {
	/// 現在存在するPnP集合を作成する。
	decltype( &SetupDiGetClassDevsW)			open{SetupDiGetClassDevsW} ;
	/// 同じ集合をindexで列挙する。
	decltype( &SetupDiEnumDeviceInfo)		enumerate{SetupDiEnumDeviceInfo} ;
	/// 現在driverとdeviceの有限propertyを読み取る。
	decltype( &SetupDiGetDevicePropertyW)	property{SetupDiGetDevicePropertyW} ;
	/// Worker内でのみ使用する有限instance IDを読み取る。
	decltype( &SetupDiGetDeviceInstanceIdW)	instanceId{SetupDiGetDeviceInstanceIdW} ;
	/// 同じbackendが生成した集合を解放する。
	decltype( &SetupDiDestroyDeviceInfoList) close{SetupDiDestroyDeviceInfoList} ;
	/// Devnode statusとproblem codeを同じread-only照会で取得する。
	decltype( &CM_Get_DevNode_Status)		nodeStatus{CM_Get_DevNode_Status} ;
} ;

} // namespace drivercrate
