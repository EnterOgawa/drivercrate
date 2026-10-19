//------------------------------------------------------------------------------
/**
 * @file vaio_catalog_parser_tests.cpp
 * @brief VAIO公式catalog parser単体試験実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  Registry実取得長の回帰試験を追加。
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
 * @note 実model、実URL、実Hardware IDを使用せず、schema変更時の拒否を含むoffline testを実行します。
 */
//------------------------------------------------------------------------------

#include "vaio_catalog_parser_tests.h"

#include "platform/com_raii.h"
#include "platform/vaio_catalog_parser.h"
#include "platform/vaio_update_provider.h"
#include "test_framework.h"

#include <Windows.h>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 試験data定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view HASH =
	L"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ;	// 架空hash。

//------------------------------------------------------------------------------
// 内部試験関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Global modelだけを抽出することを検証する。
 *
 * 非Global recordを除外し、大文字model codeを保持する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testModels( TestContext &context)
{
	// Global区分の異なる二つの架空VAIO modelを含む一覧JSON。
	constexpr std::wstring_view JSON = LR"([{"ModelName":"VJT123","Global":"Y"},)"
									   LR"({"ModelName":"VJL456","Global":""}])" ;
	std::vector<VaioModel> models ;	// Parserが設定するGlobal model集合。
	DRIVERCRATE_EXPECT( context, parseVaioModelCatalog( JSON, models) == 0) ;
	DRIVERCRATE_EXPECT( context, models.size() == 1) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( models.size() == 1) {
		DRIVERCRATE_EXPECT( context, models.front().code == L"VJT123") ;
	}

	// Model codeと照合する、架空のlocal表示値集合。
	const std::vector<std::wstring>	  localValues{L"VAIO VJT123C11N", L"Test Board"} ;
	// 公式model一覧とlocal表示値の照合結果。未一致では値なし。
	const std::optional<std::wstring> matched = matchVaioModelCode( models, localValues) ;
	DRIVERCRATE_EXPECT( context, matched.has_value()) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( matched.has_value()) {
		DRIVERCRATE_EXPECT( context, *matched == L"VJT123") ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Pre-installed driverのmodel／category対応を検証する。
 *
 * Model集合、Table 1、許可HTML除去後のtitleを確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testPreinstalled( TestContext &context)
{
	// 対象modelと登録商標表記を含む架空driver一覧JSON。
	constexpr std::wstring_view JSON =
		LR"([{"ModelName":"VJT123,VJT124","Table-No":"1",)"
		LR"("CategoryID":"wlan","ProgramName":"Test<sup>&reg;</sup> Wireless Driver"}])" ;
	std::vector<VaioPreinstalledDriver> drivers ;	// Parserが設定するdriver表項目群。
	DRIVERCRATE_EXPECT( context, parseVaioPreinstalledCatalog( JSON, drivers) == 0) ;
	DRIVERCRATE_EXPECT( context, drivers.size() == 1) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( drivers.size() == 1) {
		DRIVERCRATE_EXPECT( context, drivers.front().models.size() == 2) ;
		DRIVERCRATE_EXPECT( context, drivers.front().categoryId == L"wlan") ;
		DRIVERCRATE_EXPECT( context, drivers.front().title == L"Test Wireless Driver") ;
		DRIVERCRATE_EXPECT( context, drivers.front().tableOne) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Driver updateだけを完全metadata付きで抽出することを検証する。
 *
 * Firmware、無効recordを除外し、OSのperiod区切りを許可する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testUpdates( TestContext &context)
{
	// 版数・対象model・OS・hashの結合を検証する架空配布metadata。
	const std::wstring json =
		LR"([{"CategoryID":"wlan","ProgramName":"Test Wireless Driver ",)"
		LR"("Version":"2.3.4.5 ","Date":"2026/09/02","SoftwareID":"SP001234",)"
		LR"("FileSize":"123456","SHA256":")" +
		std::wstring( HASH) +
		LR"(","ApplicableModel":"VJT123,VJT124","ApplicableOS":)"
		LR"("Windows 11.Windows 10","NA":"","DownloadReferenceUrl":)"
		LR"("https://dlcdnglobal.support.vaio.com/supportfiles-global/update/SP001234.exe"},)"
		LR"({"CategoryID":"bios","ProgramName":"Test BIOS","Version":"1.0",)"
		LR"("Date":"2026/09/02","SoftwareID":"SP001235","FileSize":"1",)"
		LR"("SHA256":"","ApplicableModel":"VJT123","ApplicableOS":"Windows 11",)"
		LR"("NA":"","DownloadReferenceUrl":""},)"
		LR"({"CategoryID":"graphics","ProgramName":"Old Driver","Version":"1.0",)"
		LR"("Date":"2026/09/02","SoftwareID":"SP001236","FileSize":"1",)"
		LR"("SHA256":"","ApplicableModel":"VJT123","ApplicableOS":"Windows 11",)"
		LR"("NA":"x","DownloadReferenceUrl":""}])" ;
	std::vector<VaioDriverRelease> releases ;	// Parserが設定するdriver release群。
	DRIVERCRATE_EXPECT( context, parseVaioUpdateCatalog( json, releases) == 0) ;
	DRIVERCRATE_EXPECT( context, releases.size() == 1) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( releases.size() == 1) {
		const VaioDriverRelease &release = releases.front() ;	// 検証対象release。
		DRIVERCRATE_EXPECT( context, release.categoryId == L"wlan") ;
		DRIVERCRATE_EXPECT( context, release.version == L"2.3.4.5") ;
		DRIVERCRATE_EXPECT( context, release.models.size() == 2) ;
		DRIVERCRATE_EXPECT( context, release.osNames.size() == 2) ;
		DRIVERCRATE_EXPECT( context, release.sha256 == HASH) ;
		DRIVERCRATE_EXPECT( context, release.size == 123456) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief URL、hash、markup、duplicateの不正を拒否することを検証する。
 *
 * 第三者payloadと任意HTMLを候補metadataへ入れない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testRejections( TestContext &context)
{
	// 許可されない取得URLを含む配布metadataの拒否用入力。
	const std::wstring unsafeUrl =
		LR"([{"CategoryID":"graphics","ProgramName":"Test Driver",)"
		LR"("Version":"1.0","Date":"2026/09/02","SoftwareID":"SP001234",)"
		LR"("FileSize":"123","SHA256":")" +
		std::wstring( HASH) +
		LR"(","ApplicableModel":"VJT123","ApplicableOS":"Windows 11",)"
		LR"("NA":"","DownloadReferenceUrl":"https://example.invalid/SP001234.exe"}])" ;
	std::vector<VaioDriverRelease> releases ;	// 拒否時に空となる出力群。
	DRIVERCRATE_EXPECT( context, parseVaioUpdateCatalog( unsafeUrl, releases) != 0) ;
	DRIVERCRATE_EXPECT( context, releases.empty()) ;

	// Driver名に不正なHTML markupを含む拒否用metadata。
	constexpr std::wstring_view MARKUP =
		LR"([{"ModelName":"VJT123","Table-No":"1","CategoryID":"wlan",)"
		LR"("ProgramName":"<script>bad</script> Driver"}])" ;
	std::vector<VaioPreinstalledDriver> drivers ;	// Markup拒否時に空となる出力群。
	DRIVERCRATE_EXPECT( context, parseVaioPreinstalledCatalog( MARKUP, drivers) != 0) ;
	DRIVERCRATE_EXPECT( context, drivers.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Category、maker、classで一意なlocal deviceを解決する試験。
 *
 * Versionに依存せずIntel Wi-Fiだけを選び、曖昧一致を拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testDeviceMatching( TestContext &context)
{
	const std::vector<OfficialCatalogDevice> devices{
		{.deviceIdentity  = L"device-a",
		 .model			  = L"Test Intel Wireless Adapter",
		 .manufacturer	  = L"Intel",
		 .driverClass	  = L"Network",
		 .deviceClassGuid = L"{4d36e972-e325-11ce-bfc1-08002be10318}",
		 .currentProvider = L"Intel",
		 .currentVersion  = L"1.0"},
		{.deviceIdentity  = L"device-b",
		 .model			  = L"Test Realtek Ethernet Adapter",
		 .manufacturer	  = L"Realtek",
		 .driverClass	  = L"Network",
		 .deviceClassGuid = L"{4d36e972-e325-11ce-bfc1-08002be10318}",
		 .currentProvider = L"Realtek",
		 .currentVersion  = L"9.9"}} ;	// 架空local device群。
	const std::optional<std::wstring> matched =
		// 結果。
		matchVaioDriverDevice( L"wlan", L"Intel Wireless LAN Driver", devices) ;
	DRIVERCRATE_EXPECT( context, matched.has_value()) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( matched.has_value()) {
		DRIVERCRATE_EXPECT( context, *matched == L"device-a") ;
	}

	std::vector<OfficialCatalogDevice> ambiguous = devices ;	// 同一categoryを重複させるdevice群。
	ambiguous.push_back( {.deviceIdentity  = L"device-c",
						 .model			  = L"Second Intel Wi-Fi Adapter",
						 .manufacturer	  = L"Intel",
						 .driverClass	  = L"Network",
						 .deviceClassGuid = L"{4d36e972-e325-11ce-bfc1-08002be10318}",
						 .currentProvider = L"Intel",
						 .currentVersion  = L"2.0"}) ;
	DRIVERCRATE_EXPECT(
		context,
		!matchVaioDriverDevice( L"wlan", L"Intel Wireless LAN Driver", ambiguous).has_value()) ;
	DRIVERCRATE_EXPECT( context, !matchVaioDriverDevice( L"bios", L"Test BIOS", devices).has_value()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Registryの確保長と実取得長の差を検証する。
 *
 * 12 byte確保／10 byte取得を架空文字列で再現し、型・上限・終端不正の拒否を維持する。実registryは読み書きしない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testRegistryResultLength( TestContext &context)
{
	std::array<wchar_t, 6> buffer{L'T', L'E', L'S', L'T', L'\0', L'\0'} ;	// 余分な1文字を含む領域。
	std::wstring		   value = L"previous" ;							// 成功時の値と拒否時の消去を検証する出力。
	DRIVERCRATE_EXPECT( context, decodeVaioRegistryString( buffer, 10U, REG_SZ, value) == 0) ;
	DRIVERCRATE_EXPECT( context, value == L"TEST") ;
	buffer.back() = L'X' ;
	DRIVERCRATE_EXPECT( context, decodeVaioRegistryString( buffer, 10U, REG_SZ, value) == 0) ;
	DRIVERCRATE_EXPECT( context, value == L"TEST") ;
	DRIVERCRATE_EXPECT( context, decodeVaioRegistryString( buffer, 12U, REG_SZ, value) != 0) ;
	DRIVERCRATE_EXPECT( context, value.empty()) ;
	buffer.back() = L'\0' ;
	DRIVERCRATE_EXPECT( context, decodeVaioRegistryString( buffer, 12U, REG_SZ, value) != 0) ;
	DRIVERCRATE_EXPECT( context, value.empty()) ;
	buffer[1] = L'\0' ;
	DRIVERCRATE_EXPECT( context, decodeVaioRegistryString( buffer, 10U, REG_SZ, value) != 0) ;
	DRIVERCRATE_EXPECT( context, value.empty()) ;
	buffer[1] = L'E' ;
	// 空、半文字、領域超過、受信上限超過、整数最大値の拒否fixture。
	constexpr std::array<std::uint32_t, 6> INVALID_LENGTHS{0U, 1U, 9U, 14U, 32770U, 0xffffffffU} ;
	// 終端なし、奇数byte、確保領域超過、絶対上限超過を拒否する。
	for( const std::uint32_t length : INVALID_LENGTHS) {
		value = L"previous" ;
		DRIVERCRATE_EXPECT( context, decodeVaioRegistryString( buffer, length, REG_SZ, value) != 0) ;
		DRIVERCRATE_EXPECT( context, value.empty()) ;
	}

	DRIVERCRATE_EXPECT( context, decodeVaioRegistryString( {}, 2U, REG_SZ, value) != 0) ;
	DRIVERCRATE_EXPECT( context, decodeVaioRegistryString( buffer, 10U, REG_MULTI_SZ, value) != 0) ;
	DRIVERCRATE_EXPECT( context, decodeVaioRegistryString( buffer, 10U, REG_BINARY, value) != 0) ;
	const std::array<wchar_t, 1> emptyValue{L'\0'} ;	// 正規の空REG_SZは従来どおり許容する。
	DRIVERCRATE_EXPECT( context, decodeVaioRegistryString( emptyValue, 2U, REG_SZ, value) == 0) ;
	DRIVERCRATE_EXPECT( context, value.empty()) ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/vaio_catalog_parser_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runVaioCatalogParserTests( TestContext &context)
{
	const ComApartment apartment( COINIT_MULTITHREADED) ;	// Windows.Data.Json用COM lifetime。
	DRIVERCRATE_EXPECT( context, SUCCEEDED( apartment.result())) ;
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		return ;
	}

	testModels( context) ;
	testPreinstalled( context) ;
	testUpdates( context) ;
	testRejections( context) ;
	testDeviceMatching( context) ;
	testRegistryResultLength( context) ;
}

} // namespace drivercrate::test
