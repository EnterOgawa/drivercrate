//------------------------------------------------------------------------------
/**
 * @file main.cpp
 * @brief DriverCrateエントリーポイント。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Header control初期化追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  関数comment形式統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  未使用progress class初期化削除。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Windows entry pointとprocess全体のUI初期化を実装します。
 */
//------------------------------------------------------------------------------

#include "app/main_window.h"
#include "app/resource.h"

#include <CommCtrl.h>
#include <Windows.h>

#include <string>

namespace {

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Process 初期化中に表示する resource 文字列を読み込む。
 *
 * @param[in] instance resource を持つ application module instance。
 * @param[in] resourceId 読み込む文字列 resource ID。
 * @return 読み込んだ文字列。resource がない場合は空文字列。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring loadString( const HINSTANCE instance, const UINT resourceId)
{
	constexpr int MAXIMUM_RESOURCE_CHARACTERS = 512 ;										// 起動error文字列の最大UTF-16文字数。
	std::wstring  value( static_cast<std::size_t>( MAXIMUM_RESOURCE_CHARACTERS), L'\0') ;	// 受信領域。
	// 終端nullを除いてLoadStringWが格納したUTF-16文字数。
	const int length = LoadStringW( instance, resourceId, value.data(), MAXIMUM_RESOURCE_CHARACTERS) ;
	// resourceを読めない場合は空文字列を返し、未初期化bufferをdialogへ渡さない。
	if( length <= 0) {
		return {} ;
	}

	value.resize( static_cast<std::size_t>( length)) ;
	return value ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief DPI-aware Win32 application を初期化して message loopを開始する。
 *
 * @param[in] instance application module instance。
 * @param[in] previousInstance Win32 互換用の未使用値。
 * @param[in] commandLine process command line の executable名以外の部分。
 * @param[in] showCommand 初期 Window 表示 command。
 * @return process exit code。
 */
//------------------------------------------------------------------------------
int WINAPI wWinMain( _In_ HINSTANCE instance, _In_opt_ HINSTANCE previousInstance,
					_In_ LPWSTR commandLine, _In_ int showCommand)
{
	static_cast<void>( previousInstance) ;
	static_cast<void>( commandLine) ;

	// manifest と合わせて Per-Monitor V2 を明示し、失敗時は system DPI behavior を維持する。
	static_cast<void>( SetProcessDpiAwarenessContext( DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) ;

	INITCOMMONCONTROLSEX commonControls{} ;	// 初期化対象のcommon control class指定。
	commonControls.dwSize = sizeof( commonControls) ;
	commonControls.dwICC  = ICC_TREEVIEW_CLASSES | ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES ;
	// 標準controlを初期化できなければ、UI構築を続けず利用者へ理由を表示する。
	if( InitCommonControlsEx( &commonControls) == FALSE) {
		// 利用者へ表示する初期化失敗理由。
		const std::wstring errorMessage = loadString( instance, IDS_COMMON_CONTROLS_ERROR) ;
		const std::wstring errorTitle	= loadString( instance, IDS_ERROR_TITLE) ;	// Dialog title。
		MessageBoxW( nullptr, errorMessage.c_str(), errorTitle.c_str(), MB_OK | MB_ICONERROR) ;
		return 1 ;
	}

	drivercrate::MainWindow window ;	// Process lifetime内でtop-level Windowを所有するobject。
	// main Windowを作成できない場合はworker操作を開始せず、初期化失敗を通知する。
	if( !window.create( instance)) {
		// 利用者へ表示するWindow作成失敗理由。
		const std::wstring errorMessage = loadString( instance, IDS_MAIN_WINDOW_ERROR) ;
		const std::wstring errorTitle	= loadString( instance, IDS_ERROR_TITLE) ;	// Dialog title。
		MessageBoxW( nullptr, errorMessage.c_str(), errorTitle.c_str(), MB_OK | MB_ICONERROR) ;
		return 1 ;
	}

	return window.run( showCommand) ;
}
