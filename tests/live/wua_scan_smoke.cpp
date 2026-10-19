//------------------------------------------------------------------------------
/**
 * @file wua_scan_smoke.cpp
 * @brief WUA読み取り専用試験。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  関数comment形式統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Scan進捗callback追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 実端末のWindows Update serviceへ読み取り専用scanを実行します。Network接続を伴いますがdownload/installを行いません。Update
 *       titleや端末固有情報を出力しません。
 */
//------------------------------------------------------------------------------

#include "platform/com_raii.h"
#include "platform/windows_error.h"
#include "platform/windows_update_provider.h"

#include <Windows.h>

#include <iostream>

//------------------------------------------------------------------------------
/**
 * @brief COM MTA で WUA scan を一回実行し、個人情報を含まない結果だけを返す。
 * @return scan 成功時は 0、初期化または scan 失敗時は 1。
 */
//------------------------------------------------------------------------------
int wmain()
{
	const drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;	// Test threadのCOM MTA。
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		std::wcerr << L"COM initialization failed: "
				   << drivercrate::formatNativeError(
						  static_cast<drivercrate::NativeError>( apartment.result()))
				   << L'\n' ;
		return 1 ;
	}

	drivercrate::WindowsUpdateProvider			provider ;	// 端末既定serviceを使用するWUA provider。
	const drivercrate::ProviderProgressCallback progressCallback =
		[]( const drivercrate::ProviderProgress &progress) {
			static_cast<void>( progress) ;
		} ; // 読み取り専用scanの進捗受理先。
	const drivercrate::ScanResult result =
		// 読み取り専用online scan結果。
		provider.scan( 1, {}, progressCallback) ;
	// WUA検索の失敗を更新なしと区別し、Windowsの診断値を残して試験を終了する。
	if( !result.succeeded) {
		std::wcerr << L"WUA scan failed: " << drivercrate::formatNativeError( result.error) << L'\n' ;
		return 1 ;
	}

	std::wcout << L"WUA scan succeeded. Applicable driver update count: "
			   << result.candidates.size() << L'\n' ;
	return 0 ;
}
