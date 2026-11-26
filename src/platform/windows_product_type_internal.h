//------------------------------------------------------------------------------
/**
 * @file windows_product_type_internal.h
 * @brief host観測の完全SDK依存を非公開の同期境界へ固定します
 * @version 01.00.00
 * @date 2026/11/18
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/18  新規作成
 * </pre>
 * @note fixture依存の欠落を実OS APIへfallbackしません
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/windows_product_type.h"
#pragma push_macro( "GetObject")
#include <Windows.h>
#ifdef GetObject
#undef GetObject
#endif
namespace drivercrate {
/** @brief SDK署名をそのまま使用する完全observer依存です */
struct WindowsHostPlatformApi {
	/// process内の非所有moduleを取得する同期関数です
	decltype( &::GetModuleHandleW)	 module{} ;
	/// RtlGetVersionの元addressを取得する同期関数です
	decltype( &::GetProcAddress)		 entry{} ;
	/// 直前Win32失敗の原codeだけを読む関数です
	decltype( &::GetLastError)		 lastError{} ;
	/// native architectureを返すvoid関数です。架空のBOOLを使いません
	decltype( &::GetNativeSystemInfo) architecture{} ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief 明示した完全SDK依存だけで一回のhost観測を行います
 * @param[in] api 呼出し中だけ借用する全関数です。欠落をnativeへ補完しません
 * @return 元code/domainと成功fieldです。依存欠落/例外はUNOBSERVEDです
 * @note I/Oやversion失敗時は別APIや過去観測を使用しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] WindowsHostPlatformObservation observeWindowsHostPlatform(
	const WindowsHostPlatformApi &api) noexcept ;
} // namespace drivercrate
#pragma pop_macro( "GetObject")
