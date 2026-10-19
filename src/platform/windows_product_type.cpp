//------------------------------------------------------------------------------
/**
 * @file windows_product_type.cpp
 * @brief Windows client／server種別判定実装。
 * @version 01.00.00
 * @date 2026/09/02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  実OS build番号取得を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Product SKU取得を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Version Helper、RtlGetVersion、GetProductInfoで実OS条件を判定します。判定不能時は復元保護、公式検索、前回観測の条件を緩和しません。
 */
//------------------------------------------------------------------------------

#include "platform/windows_product_type.h"

#include <Windows.h>

#include <VersionHelpers.h>

#include <cstdint>

namespace drivercrate {

//------------------------------------------------------------------------------
/**
 * @see src/platform/windows_product_type.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isWindowsServer() noexcept
{
	return IsWindowsServer() != FALSE ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/windows_product_type.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::uint32_t currentWindowsBuildNumber() noexcept
{
	const HMODULE ntdll = GetModuleHandleW( L"ntdll.dll") ;	// 非所有module handle。
	// 既存 ntdll が取得できなければ OS build を不明として返す。
	if( ntdll == nullptr) {
		return 0U ;
	}

	using RtlGetVersionFunction = LONG( WINAPI *)( PRTL_OSVERSIONINFOW) ;	// NTDLL関数署名。
	// Win32関数addressを対応する公式ABI署名へ変換する境界。
	const auto rtlGetVersion = reinterpret_cast<RtlGetVersionFunction>(
		// 非所有のprocess内関数pointer。
		GetProcAddress( ntdll, "RtlGetVersion")) ;
	// Version 照会の entry point がない環境では build を推測しない。
	if( rtlGetVersion == nullptr) {
		return 0U ;
	}

	RTL_OSVERSIONINFOW version{} ;	// RtlGetVersionが設定する実OS version。
	version.dwOSVersionInfoSize = sizeof( version) ;
	// 実 version の取得失敗またはゼロ build は不明値として返す。
	if( rtlGetVersion( &version) != 0 || version.dwBuildNumber == 0UL) {
		return 0U ;
	}

	return static_cast<std::uint32_t>( version.dwBuildNumber) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/windows_product_type.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::uint32_t currentWindowsProductSku() noexcept
{
	DWORD productSku{} ;	// GetProductInfoが返すWindows edition識別値。
	// Product SKU を取得できない場合は不明値を返して edition を推測しない。
	if( GetProductInfo( 10U, 0U, 0U, 0U, &productSku) == FALSE || productSku == PRODUCT_UNDEFINED) {
		return 0U ;
	}

	return static_cast<std::uint32_t>( productSku) ;
}

} // namespace drivercrate
