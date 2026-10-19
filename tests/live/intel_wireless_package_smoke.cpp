//------------------------------------------------------------------------------
/**
 * @file intel_wireless_package_smoke.cpp
 * @brief Intel Wireless公式ZIP読み取り専用live検証。
 * @version 01.00.00
 * @date 2026/09/03
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 利用者がIntelの利用許諾へ同意して取得したZIPを変更せず検査します。Path、PnP ID、title、payload内容を出力せず、driver installもしません。
 */
//------------------------------------------------------------------------------

#include "platform/intel_wireless_package.h"
#include "platform/official_download_workspace.h"

#include <cstdio>

//------------------------------------------------------------------------------
/**
 * @brief Intel Wireless公式ZIPのread-only live検証を実行する。
 *
 * Production共通componentでZIP、INF、CAT、全member、署名、publisher、OS、x64を検証し、件数だけを表示する。
 *
 * @param[in] argumentCount 実行file名を含むargument数。
 * @param[in] arguments 一件の利用者指定Intel公式ZIP path。
 * @return 全package検証成功時0、検証失敗時1、引数不正時2。
 */
//------------------------------------------------------------------------------
int wmain( const int argumentCount, wchar_t *arguments[])
{
	// 明示されたZIP一件だけを検証対象とし、引数が不正なら展開や監査を開始しない。
	if( argumentCount != 2 || arguments == nullptr || arguments[1] == nullptr ||
	   arguments[1][0] == L'\0') {
		std::wprintf( L"Usage: intel_wireless_package_smoke <official-driver-zip>\n") ;
		return 2 ;
	}

	drivercrate::OfficialDownloadWorkspace	  workspace ;	// 検証中の複製fileと展開file所有領域。
	drivercrate::IntelWirelessPackageContents contents ;	// 検証成功時の非表示metadata。
	const drivercrate::NativeError			  error = drivercrate::inspectIntelWirelessPackageFile(
		   arguments[1], 1, workspace, contents) ;	// Production共通検証結果。
	// 公式ZIPの検証に失敗した場合は、診断値を報告して実package試験を不合格にする。
	if( error != 0) {
		std::wprintf( L"Intel Wireless package verification failed: 0x%08X\n",
					 static_cast<unsigned int>( error)) ;
		return 1 ;
	}

	std::wprintf( L"Intel Wireless package verification succeeded: %zu INF package(s).\n",
				 contents.packages.size()) ;
	return 0 ;
}
