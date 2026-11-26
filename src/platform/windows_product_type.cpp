//------------------------------------------------------------------------------
/**
 * @file windows_product_type.cpp
 * @brief Windows client／server種別判定実装
 * @version 01.01.00
 * @date 2026/09/02
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
 *
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  実OS build番号取得を追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Product SKU取得を追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.00.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.01.00 Shunji Ogawa  2026/11/18  P3同scan fullhost観測と取得直前拒否を接続
 * </pre>
 *
 * @note Version Helper、RtlGetVersion、GetProductInfoで実OS条件を判定します。判定不能時は復元保護、公式検索、前回観測の条件を緩和しません
 */
//------------------------------------------------------------------------------

#include "platform/windows_product_type.h"
#include "platform/windows_product_type_internal.h"

#include <Windows.h>

#include <VersionHelpers.h>

#include <cstdint>

namespace drivercrate {

//------------------------------------------------------------------------------
/**
 * @brief 既復旧modeと互換のVersion Helper boolをそのまま返します
 * @return IsWindowsServerの非FALSEでtrueです。VerifyVersionInfoWの拒否理由を分離しません
 * @note 既復旧意味を保持します。false/trueから新fullhostの成功や六fieldを合成しません
 */
//------------------------------------------------------------------------------
bool isWindowsServer() noexcept
{
	return IsWindowsServer() != FALSE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実行中Windowsのmajor build番号を取得する。Processに既に存在するntdllのRtlGetVersionを使用し、固定OS向け公式配布を別世代へ表示しないため
 *        に使用する
 * @return 取得できたbuild番号。判定不能、0、32bit超過の場合は0。 実行中Windowsのmajor build番号。判定不能時は0
 * @note Manifestによるversion仮想化を避けるためworker内のOS境界判定に使用する
 */
//------------------------------------------------------------------------------
std::uint32_t currentWindowsBuildNumber() noexcept
{
	const HMODULE ntdll = GetModuleHandleW( L"ntdll.dll") ;	// 非所有module handle
	// 既存 ntdll が取得できなければ OS build を不明として返す
	if( ntdll == nullptr) {
		return 0U ;
	}

	using RtlGetVersionFunction = LONG( WINAPI *)( PRTL_OSVERSIONINFOW) ;	// NTDLL関数署名
	// Win32関数addressを対応する公式ABI署名へ変換する境界
	const auto rtlGetVersion = reinterpret_cast<RtlGetVersionFunction>(
		// 非所有のprocess内関数pointer
		GetProcAddress( ntdll, "RtlGetVersion")) ;
	// Version 照会の entry point がない環境では build を推測しない
	if( rtlGetVersion == nullptr) {
		return 0U ;
	}

	RTL_OSVERSIONINFOW version{} ;	// RtlGetVersionが設定する実OS version
	version.dwOSVersionInfoSize = sizeof( version) ;
	// 実 version の取得失敗またはゼロ build は不明値として返す
	if( rtlGetVersion( &version) != 0 || version.dwBuildNumber == 0UL) {
		return 0U ;
	}

	return static_cast<std::uint32_t>( version.dwBuildNumber) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実行中Windowsのproduct SKUを取得する。Windows 10以降の10.0 versionを指定して実product SKUを取得し、edition変更時に前回
 *        release観測を失効可能にする
 * @return GetProductInfoが返したPRODUCT_*値。取得不能または未定義時は0。 GetProductInfoが返すPRODUCT_*値。取得不能時は0
 * @note 端末内OS fingerprintへedition差を反映するためだけに使用する
 */
//------------------------------------------------------------------------------
std::uint32_t currentWindowsProductSku() noexcept
{
	DWORD productSku{} ;	// GetProductInfoが返すWindows edition識別値
	// Product SKU を取得できない場合は不明値を返して edition を推測しない
	if( GetProductInfo( 10U, 0U, 0U, 0U, &productSku) == FALSE || productSku == PRODUCT_UNDEFINED) {
		return 0U ;
	}

	return static_cast<std::uint32_t>( productSku) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 明示した完全SDK依存だけで一回のhost観測を行います
 * @param[in] api 呼出し中だけ借用する全関数です。欠落をnativeへ補完しません
 * @return 元code/domainと成功fieldです。依存欠落/例外はUNOBSERVEDです
 * @note GetNativeSystemInfoはvoidです。未知architectureは後段のローカル判定へ渡します
 */
//------------------------------------------------------------------------------
WindowsHostPlatformObservation observeWindowsHostPlatform(
	const WindowsHostPlatformApi &api) noexcept
{
	WindowsHostPlatformObservation result ;	// 元観測を成功へ補完しない初期値です
	result.stage = WindowsHostObservationStage::DEPENDENCY ;
	// 完全fake依存の欠落を実APIへ切り替えません
	if( !api.module || !api.entry || !api.lastError || !api.architecture) {
		return result ;
	}

	try {
		const auto module = api.module( L"ntdll.dll") ;	// 元の非所有handleです
		// NULLという失敗と元error0も独立に保持します
		if( !module) {
			result.rawBits = api.lastError() ;
			result.state   = WindowsHostObservationState::API_FAILED ;
			result.domain  = WindowsHostErrorDomain::WIN32_CODE ;
			result.stage   = WindowsHostObservationStage::MODULE ;
			return result ;
		}

		const auto address = api.entry( module, "RtlGetVersion") ;	// SDK ABIへ変換する元addressです
		// 解決失敗直後のWin32 bit patternを変換しません
		if( !address) {
			result.rawBits = api.lastError() ;
			result.state   = WindowsHostObservationState::API_FAILED ;
			result.domain  = WindowsHostErrorDomain::WIN32_CODE ;
			result.stage   = WindowsHostObservationStage::ENTRY ;
			return result ;
		}

		using VersionFunction = LONG( WINAPI *)( PRTL_OSVERSIONINFOW) ;	// 元SDKのRtl署名です
		const auto versionFunction =
			reinterpret_cast<VersionFunction>( address) ;	// 公式ABIの境界だけです
		OSVERSIONINFOEXW version{} ;						// product/suiteまで元APIから取得します
		version.dwOSVersionInfoSize = sizeof( version) ;
		const auto status =
			// 原NTSTATUSです
			versionFunction( reinterpret_cast<PRTL_OSVERSIONINFOW>( &version)) ;
		result.rawBits = static_cast<std::uint32_t>( status) ;
		result.domain  = WindowsHostErrorDomain::NTSTATUS ;
		result.stage   = WindowsHostObservationStage::VERSION ;
		// 非0の元statusをHRESULTや別のversion成功へ変更しません
		if( status != 0) {
			result.state = WindowsHostObservationState::API_FAILED ;
			return result ;
		}

		SYSTEM_INFO information{} ;	// compile architectureでなく実native情報です
		api.architecture( &information) ;
		result.value =
			WindowsHostPlatform{version.dwMajorVersion, version.dwMinorVersion,
								version.dwBuildNumber,	information.wProcessorArchitecture,
								version.wProductType,	version.wSuiteMask} ;
		result.state = WindowsHostObservationState::OBSERVED ;
		return result ;
	} catch( ...) {
		// 依存例外はnative errorを捏造せず、ローカルUNKNOWNへ渡します
		return {} ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 一回のSDK version/architecture観測を返します
 * @return 元status/domain/bitsと六fieldです。API失敗/例外は成功へ補完しません
 * @note legacy bool/build/SKUの実行bodyや復旧意味を変更しません
 */
//------------------------------------------------------------------------------
WindowsHostPlatformObservation observeWindowsHostPlatform() noexcept
{
	return observeWindowsHostPlatform( WindowsHostPlatformApi{
		&::GetModuleHandleW, &::GetProcAddress, &::GetLastError, &::GetNativeSystemInfo}) ;
}
} // namespace drivercrate
