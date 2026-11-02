//------------------------------------------------------------------------------
/**
 * @file hardware_refresh_internal.h
 * @brief ハードウェア再検出を完全fakeで検証する低位API表です。
 * @version 01.00.00
 * @date 2026/10/28
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/28  Nativeへ補完しない再検出fixtureを追加。
 * </pre>
 *
 * @note 欠損表と実API混在を拒否し、fixtureで実OS再検出や権限変更を行いません。
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/hardware_refresh.h"
#include <Windows.h>
#include <cfgmgr32.h>

namespace drivercrate::hardware_refresh_detail {
/** @brief 権限・root・再検出の完全低位表です。各pointerを明示指定します。 */
struct Transport {
	/// 対象processの非所有pseudo HANDLE照会です。
	decltype( &GetCurrentProcess)	  process{} ;
	/// Tokenを開き、返却HANDLEをcloseへ渡します。
	decltype( &OpenProcessToken)		  openToken{} ;
	/// 必要な権限のLUIDを照会します。
	decltype( &LookupPrivilegeValueW)  lookupPrivilege{} ;
	/// 元属性を保存して一権限を変更・復帰します。
	decltype( &AdjustTokenPrivileges)  adjustPrivilege{} ;
	/// 元のWin32診断値を読みます。
	decltype( &GetLastError)			  lastError{} ;
	/// AdjustTokenPrivilegesの成功診断を初期化します。
	decltype( &SetLastError)			  setError{} ;
	/// 所有token HANDLEだけを閉じます。
	decltype( &CloseHandle)			  closeToken{} ;
	/// Local rootを照会します。
	decltype( &CM_Locate_DevNodeW)	  locateRoot{} ;
	/// 同期再検出を一回要求します。
	decltype( &CM_Reenumerate_DevNode) reenumerate{} ;
} ;
/** @brief 完全fakeのみを許可する内部試験入口です。 */
struct Access {
	/** @brief 実API不在の完全表で製品と同じ順序・権限復帰を実行します。
	 * @param[in] calls 呼出し完了まで借用する完全fake表です。
	 * @return 欠損/混在はE_INVALIDARGで失敗しAPIを一つも呼びません。
	 */
	[[nodiscard]] static HardwareRefreshResult refresh( const Transport &calls) noexcept ;
} ;
} // namespace drivercrate::hardware_refresh_detail
