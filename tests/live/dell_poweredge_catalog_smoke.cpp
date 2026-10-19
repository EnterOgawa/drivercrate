//------------------------------------------------------------------------------
/**
 * @file dell_poweredge_catalog_smoke.cpp
 * @brief Dell PowerEdge公式catalog読み取り専用試験。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  HTTP client可変性修正。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Dell公式Enterprise Catalogとdetached signatureだけを取得し、固定鍵、GZip、XML schemaを検証します。Payloadと端末
 *       inventoryは扱いません。
 */
//------------------------------------------------------------------------------

#include "platform/com_raii.h"
#include "platform/dell_server_catalog_parser.h"
#include "platform/dell_server_catalog_source.h"
#include "platform/official_http_client.h"
#include "platform/windows_error.h"

#include <Windows.h>

#include <iostream>
#include <vector>

//------------------------------------------------------------------------------
/**
 * @brief Dell PowerEdge catalogの署名とschemaを読み取り専用で検証する。
 *
 * 固定sample model/buildをlocal送信せずXML内だけで照合し、DUPのdownloadまたはinstallは実行しない。
 * @return 公式署名、GZip、既知Server sample解析成功時は0。
 */
//------------------------------------------------------------------------------
int wmain()
{
	const drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;	// MSXML/CNG用COM MTA。
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		std::wcerr << L"COM initialization failed.\n" ;
		return 1 ;
	}

	drivercrate::OfficialHttpClient				   client ;	// 取得根拠を記録する公式HTTP client。
	const drivercrate::DellServerCatalogLoadResult catalog = drivercrate::loadDellServerCatalog(
		client, 1, []( const drivercrate::ProviderProgress &) {}) ;	// 取得・署名検証結果。
	// 公式catalogの取得・検証に失敗した場合は、その内容でschema試験を続けない。
	if( catalog.error != 0) {
		std::wcerr << L"Dell PowerEdge catalog validation failed: "
				   << drivercrate::formatNativeError( catalog.error) << L'\n' ;
		return 1 ;
	}

	std::vector<drivercrate::DellServerDriverRelease> releases ;	// Sample適合driver群。
	const drivercrate::NativeError parseError = drivercrate::parseDellServerCatalog(
		catalog.xml, L"PowerEdge R760", 20348, releases) ;	// Schema／適用性検証結果。
	// schema検証に成功してdriver行も確認できた場合だけ、catalog検証を合格とする。
	if( parseError != 0 || releases.empty()) {
		std::wcerr << L"Dell PowerEdge catalog schema validation failed: "
				   << drivercrate::formatNativeError( parseError) << L'\n' ;
		return 1 ;
	}

	std::wcout << L"Dell PowerEdge catalog OpenPGP, GZip, and schema validation succeeded. "
			   << L"Sample driver releases: " << releases.size() << L'\n' ;
	return 0 ;
}
