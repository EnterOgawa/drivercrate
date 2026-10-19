//------------------------------------------------------------------------------
/**
 * @file asrock_catalog_parser_tests.cpp
 * @brief ASRock公式Web parser単体試験実装。
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
 * @note 架空HTMLとdevice snapshotだけでmodel／OS／class／maker境界を検証します。Payloadを取得または実行しません。
 */
//------------------------------------------------------------------------------

#include "asrock_catalog_parser_tests.h"

#include "platform/asrock_catalog_parser.h"
#include "platform/asrock_update_provider.h"
#include "test_framework.h"

#include <Windows.h>

#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 試験data定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view CATALOG_FIXTURE = LR"(
<html><table class="Download"><thead><tr><th>Model</th><th>Description</th>
<th>OS</th><th>Date</th><th>Size</th><th>Download</th></tr></thead><tbody>
<tr><td><a href="/MB/AMD/Fictional Board/index.asp#Download">Fictional Board</a></td>
<td>MediaTek Bluetooth driver ver:1.1147.0.613</td>
<td>Windows&reg; 10 64bit<br>Windows&reg; 11 64bit</td><td>8/31/2026</td>
<td>5.25MB</td><td><a href="/MB/AMD/Fictional Board/index.asp#Download">Download</a></td></tr>
<tr><td>Fictional Board</td><td>Realtek Lan driver ver:10.079.0421.2026</td>
<td>Windows&#174; 11 64bit</td><td>8/31/2026</td><td>4.72MB</td><td>Download</td></tr>
<tr><td>Fictional Board</td><td>AMD chipset driver ver:8.08.20.2050</td>
<td>Windows 11 64bit</td><td>8/31/2026</td><td>75MB</td><td>Download</td></tr>
<tr><td>Another Board</td><td>Realtek Lan driver ver:1.0</td>
<td>Windows 11 64bit</td><td>8/31/2026</td><td>1MB</td><td>Download</td></tr>
</tbody></table></html>)" ;	// 現行六列構造を模した架空公式一覧。

//------------------------------------------------------------------------------
// 内部試験関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief ModelとOSに一致する表示情報抽出を検証する。
 *
 * BluetoothとLANだけを採用し、chipsetと他modelを除外する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void						testMatchingEntries( TestContext &context)
{
	std::vector<AsrockDriverPageEntry> entries ;	// Parserが返す架空表示情報群。
	DRIVERCRATE_EXPECT( context, parseAsrockLatestDriverHtml( CATALOG_FIXTURE, L"Fictional Board",
															L"Windows 11 64bit", entries)) ;
	DRIVERCRATE_EXPECT( context, entries.size() == 2U) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( entries.size() != 2U) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, entries[0].title == L"MediaTek Bluetooth driver") ;
	DRIVERCRATE_EXPECT( context, entries[0].version == L"1.1147.0.613") ;
	DRIVERCRATE_EXPECT( context, entries[0].vendorKey == L"MEDIATEK") ;
	DRIVERCRATE_EXPECT( context, entries[0].kind == AsrockDriverKind::BLUETOOTH) ;
	DRIVERCRATE_EXPECT( context, entries[1].title == L"Realtek Lan driver") ;
	DRIVERCRATE_EXPECT( context, entries[1].releaseDate == L"8/31/2026") ;
	DRIVERCRATE_EXPECT( context, entries[1].sizeText == L"4.72MB") ;
}

//------------------------------------------------------------------------------
/**
 * @brief Local deviceへの表示関連付け境界を検証する。
 *
 * Driver classとmakerが両方一致しないdeviceを拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testDeviceMatching( TestContext &context)
{
	std::vector<AsrockDriverPageEntry> entries ;	// 照合に使用する表示情報群。
	DRIVERCRATE_EXPECT( context, parseAsrockLatestDriverHtml( CATALOG_FIXTURE, L"Fictional Board",
															L"Windows 11 64bit", entries)) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( entries.size() != 2U) {
		return ;
	}

	const OfficialCatalogDevice mediatekBluetooth{
		.deviceIdentity	 = L"device-1",
		.model			 = L"MediaTek Fictional Bluetooth Adapter",
		.manufacturer	 = L"MediaTek Inc.",
		.driverClass	 = L"Bluetooth",
		.deviceClassGuid = L"{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}",
		.currentProvider = L"MediaTek",
		.currentVersion	 = L"1.0",
		.currentDate	 = L"2025/01/01"} ;	// Classとmakerが一致する架空device。
	const OfficialCatalogDevice wrongClass{
		.deviceIdentity	 = L"device-2",
		.model			 = L"MediaTek Fictional Network Adapter",
		.manufacturer	 = L"MediaTek Inc.",
		.driverClass	 = L"Net",
		.deviceClassGuid = L"{4d36e972-e325-11ce-bfc1-08002be10318}",
		.currentProvider = L"MediaTek",
		.currentVersion	 = L"1.0",
		.currentDate	 = L"2025/01/01"} ;	// Makerだけ一致する架空device。
	const OfficialCatalogDevice wrongVendor{
		.deviceIdentity	 = L"device-3",
		.model			 = L"Fictional Bluetooth Adapter",
		.manufacturer	 = L"Fictional Vendor",
		.driverClass	 = L"Bluetooth",
		.deviceClassGuid = L"{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}",
		.currentProvider = L"Fictional Vendor",
		.currentVersion	 = L"1.0",
		.currentDate	 = L"2025/01/01"} ;	// Classだけ一致する架空device。
	DRIVERCRATE_EXPECT( context, asrockEntryMatchesDevice( entries[0], mediatekBluetooth)) ;
	DRIVERCRATE_EXPECT( context, !asrockEntryMatchesDevice( entries[0], wrongClass)) ;
	DRIVERCRATE_EXPECT( context, !asrockEntryMatchesDevice( entries[0], wrongVendor)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不正schemaと表示値を拒否することを検証する。
 *
 * Challenge page、列欠損、未知OS、破損entity／日付／sizeを拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testRejections( TestContext &context)
{
	std::vector<AsrockDriverPageEntry> entries ;	// 拒否時に空となる受信先。
	entries.push_back( {.title = L"stale"}) ;
	DRIVERCRATE_EXPECT( context, !parseAsrockLatestDriverHtml( L"<html>Request unsuccessful.</html>",
															 L"Fictional Board",
															 L"Windows 11 64bit", entries)) ;
	DRIVERCRATE_EXPECT( context, entries.empty()) ;

	// 必要なDownload cellが欠けたdriver行の拒否用HTML。
	constexpr std::wstring_view MISSING_CELL =
		LR"(<table class="Download"><tr><td>Fictional Board</td>)"
		LR"(<td>Realtek Lan driver ver:1.0</td><td>Windows 11 64bit</td>)"
		LR"(<td>8/31/2026</td><td>1MB</td></tr></table>)" ;
	DRIVERCRATE_EXPECT( context, !parseAsrockLatestDriverHtml( MISSING_CELL, L"Fictional Board",
															 L"Windows 11 64bit", entries)) ;
	DRIVERCRATE_EXPECT( context, !parseAsrockLatestDriverHtml( CATALOG_FIXTURE, L"Fictional Board",
															 L"Windows 12 64bit", entries)) ;

	// 許可していないHTML entityを含む製品名の拒否用入力。
	constexpr std::wstring_view UNKNOWN_ENTITY =
		LR"(<table class="Download"><tr><td>Fictional&copy; Board</td>)"
		LR"(<td>Realtek Lan driver ver:1.0</td><td>Windows 11 64bit</td>)"
		LR"(<td>8/31/2026</td><td>1MB</td><td>Download</td></tr></table>)" ;
	DRIVERCRATE_EXPECT( context, !parseAsrockLatestDriverHtml( UNKNOWN_ENTITY, L"Fictional Board",
															 L"Windows 11 64bit", entries)) ;

	// 暦上存在しない日付を含むdriver行の拒否用HTML。
	constexpr std::wstring_view INVALID_DATE =
		LR"(<table class="Download"><tr><td>Fictional Board</td>)"
		LR"(<td>Realtek Lan driver ver:1.0</td><td>Windows 11 64bit</td>)"
		LR"(<td>2/30/2026</td><td>1MB</td><td>Download</td></tr></table>)" ;
	DRIVERCRATE_EXPECT( context, !parseAsrockLatestDriverHtml( INVALID_DATE, L"Fictional Board",
															 L"Windows 11 64bit", entries)) ;

	// 容量を確定できないdriver行の拒否用HTML。
	constexpr std::wstring_view INVALID_SIZE =
		LR"(<table class="Download"><tr><td>Fictional Board</td>)"
		LR"(<td>Realtek Lan driver ver:1.0</td><td>Windows 11 64bit</td>)"
		LR"(<td>8/31/2026</td><td>unknown</td><td>Download</td></tr></table>)" ;
	DRIVERCRATE_EXPECT( context, !parseAsrockLatestDriverHtml( INVALID_SIZE, L"Fictional Board",
															 L"Windows 11 64bit", entries)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示専用Providerがinstallを拒否することを検証する。
 *
 * Provider直接呼出しでもpayload取得へ進まないことを確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testInstallRejection( TestContext &context)
{
	AsrockUpdateProvider			provider ;							// 表示専用install拒否の試験対象。
	const std::vector<std::wstring> identities{L"fictional-identity"} ;	// 架空選択ID。
	const InstallResult				result = provider.install(
		1U, identities, 0U, []( const ProviderProgress &) {}) ;	// 直接install要求結果。
	DRIVERCRATE_EXPECT( context, !result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.downloadOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, result.downloadError == static_cast<NativeError>( E_NOTIMPL)) ;
	DRIVERCRATE_EXPECT( context, result.installOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, result.installError == static_cast<NativeError>( E_NOTIMPL)) ;
	DRIVERCRATE_EXPECT( context, result.updates.empty()) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/asrock_catalog_parser_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runAsrockCatalogParserTests( TestContext &context)
{
	testMatchingEntries( context) ;
	testDeviceMatching( context) ;
	testRejections( context) ;
	testInstallRejection( context) ;
}

} // namespace drivercrate::test
