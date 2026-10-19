//------------------------------------------------------------------------------
/**
 * @file amd_catalog_smoke.cpp
 * @brief AMD公式Web読み取り専用試験。
 * @version 01.00.00
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 固定AMD公式pageのschemaと取得根拠だけを確認します。端末inventory、Hardware ID、serial numberを送信せず、payloadを取得または実行し
 *       ません。
 */
//------------------------------------------------------------------------------

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/amd_catalog_parser.h"
#include "platform/com_raii.h"
#include "platform/official_http_client.h"
#include "platform/windows_error.h"

#include <Windows.h>

#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view DRIVER_INDEX_URL =
	L"https://www.amd.com/en/support/download/drivers.html" ;	// 固定AMD探索起点。
constexpr std::wstring_view REFERENCE_PRODUCT =
	L"AMD Radeon RX 7900 XTX" ;	// Schema確認に使う公開製品名。

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief AMD公式製品一覧と代表製品pageを読み取り専用で検証する。
 *
 * 固定pageだけを取得し、download URLを表示または取得せず、実driver installを行わない。
 * @return 取得元、schema、代表製品照合の全成功時は0、それ以外は1。
 */
//------------------------------------------------------------------------------
int wmain()
{
	const drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;	// Windows JSON用COM MTA。
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		std::wcerr << L"COM initialization failed.\n" ;
		return 1 ;
	}

	drivercrate::OfficialHttpClient client ;	// System proxyを使用する公式HTTP client。
	drivercrate::NativeError		error =
		// 根拠session開始結果。
		client.beginSourceSession( 1U, drivercrate::AMD_PROVIDER_ID) ;
	std::wstring indexHtml ;	// UTF-16変換済みAMD製品選択page。
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = client.getUtf8TextForSource( DRIVER_INDEX_URL,
											drivercrate::OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
											2ULL * 1024ULL * 1024ULL, indexHtml) ;
	}

	// 公式製品一覧を取得できなければ、空の応答を候補なしとして合格にしない。
	if( error != 0) {
		std::wcerr << L"AMD product index connection failed: "
				   << drivercrate::formatNativeError( error) << L'\n' ;
		return 1 ;
	}

	std::vector<drivercrate::AmdProductPage> products ;	// 検証済み末端製品一覧。
	// 製品一覧のschemaが変わった場合は、推測で製品pageを選ばず検証を中止する。
	if( !drivercrate::parseAmdProductIndexHtml( indexHtml, products)) {
		std::wcerr << L"AMD product index schema validation failed.\n" ;
		return 1 ;
	}

	drivercrate::AmdProductPage product ;	// 一意に照合した代表製品page。
	// 代表製品を一意に特定できない一覧では、別製品の結果で試験を代替しない。
	if( !drivercrate::findAmdProductPage( products, REFERENCE_PRODUCT, product)) {
		std::wcerr << L"AMD reference product was not found uniquely.\n" ;
		return 1 ;
	}

	std::wstring productHtml ;	// UTF-16変換済み代表製品page。
	error = client.getUtf8TextForSource( product.url,
										drivercrate::OFFICIAL_SECONDARY_METADATA_RESOURCE_ID,
										4ULL * 1024ULL * 1024ULL, productHtml) ;
	// 製品pageの通信失敗をparserや適用性の問題と混同せず、診断値を報告する。
	if( error != 0) {
		std::wcerr << L"AMD product page connection failed: "
				   << drivercrate::formatNativeError( error) << L'\n' ;
		return 1 ;
	}

	std::vector<drivercrate::AmdDriverPageEntry> entries ;	// Windows 11配布表示群。
	// 対象OSのdriver行を検証できない応答は、この代表製品のlive検証を合格にしない。
	if( !drivercrate::parseAmdDriverPageHtml( productHtml, L"Windows 11 - 64-Bit Edition", entries) ||
	   entries.empty()) {
		std::wcerr << L"AMD product page schema validation failed.\n" ;
		return 1 ;
	}

	// 二つのmetadata取得根拠を要求し、本体を取得していない検索境界も同時に確認する。
	if( !client.hasSourceEvidence( 1U, drivercrate::AMD_PROVIDER_ID,
								 drivercrate::OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ||
	   !client.hasSourceEvidence( 1U, drivercrate::AMD_PROVIDER_ID,
								 drivercrate::OFFICIAL_SECONDARY_METADATA_RESOURCE_ID) ||
	   client.hasSourceEvidence( 1U, drivercrate::AMD_PROVIDER_ID,
								drivercrate::OFFICIAL_PAYLOAD_RESOURCE_ID)) {
		std::wcerr << L"AMD source evidence boundary validation failed.\n" ;
		return 1 ;
	}

	std::wcout << L"AMD official page schemas succeeded. Products: " << products.size()
			   << L", Windows 11 display entries: " << entries.size() << L'\n' ;
	return 0 ;
}
