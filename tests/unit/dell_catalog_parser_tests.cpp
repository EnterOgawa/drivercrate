//------------------------------------------------------------------------------
/**
 * @file dell_catalog_parser_tests.cpp
 * @brief Dell公式catalog parser単体試験実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 架空の最小Dell schemaを使用し、model/OS/x64/Hardware ID/hash/pathとDTD拒否を検証します。Networkおよび実driver
 *       installは行いません。
 */
//------------------------------------------------------------------------------

#include "dell_catalog_parser_tests.h"

#include "platform/com_raii.h"
#include "platform/dell_catalog_parser.h"
#include "test_framework.h"

#include <Windows.h>

#include <string>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 試験data定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view HASH =
	L"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ;	// 架空SHA-256。

//------------------------------------------------------------------------------
// 内部試験関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Dell indexのmodel完全一致とmetadata抽出を検証する。
 *
 * 空白と大小文字差だけを吸収し、部分一致とunsafe pathを拒否する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testIndex( TestContext &context)
{
	// 対象modelと子catalogを結ぶ、架空ManifestIndex XML。
	const std::wstring xml =
		LR"(<?xml version="1.0" encoding="utf-16"?><ManifestIndex xmlns="openmanage/cm/dm">)"
		LR"(<GroupManifest><SupportedSystems><Brand><Model systemID="ABCD">)"
		LR"(<Display lang="en">Test Model 9000</Display></Model></Brand></SupportedSystems>)"
		LR"(<ManifestInformation path="FOLDER00000001M/1/Test_ABCD.cab" size="1234">)"
		LR"(<Cryptography><Hash algorithm="SHA256">)" +
		std::wstring( HASH) +
		LR"(</Hash></Cryptography></ManifestInformation></GroupManifest></ManifestIndex>)" ;
	DellPlatformCatalogReference reference ;	// Parserが設定するplatform CAB参照。
	DRIVERCRATE_EXPECT( context, parseDellCatalogIndex( xml, L"test-model 9000", reference) == 0) ;
	DRIVERCRATE_EXPECT( context, reference.path == L"FOLDER00000001M/1/Test_ABCD.cab") ;
	DRIVERCRATE_EXPECT( context, reference.size == 1234) ;
	DRIVERCRATE_EXPECT( context, reference.sha256 == HASH) ;
	DRIVERCRATE_EXPECT( context, parseDellCatalogIndex( xml, L"Model 9000", reference) != 0) ;

	std::wstring	  unsafe = xml ;												// Parent traversalへ改変するindex XML。
	const std::size_t path	 = unsafe.find( L"FOLDER00000001M/1/Test_ABCD.cab") ;	// Path位置。
	DRIVERCRATE_EXPECT( context, path != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( path != std::wstring::npos) {
		unsafe.replace( path, std::wstring_view( L"FOLDER00000001M/1/Test_ABCD.cab").size(),
					   L"../Test_ABCD.cab") ;
		DRIVERCRATE_EXPECT( context,
						   parseDellCatalogIndex( unsafe, L"Test Model 9000", reference) != 0) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Dell platform catalogの適用性とID変換を検証する。
 *
 * Driver、model、Windows 11 x64、PCI/PnP、SHA-256を満たすreleaseだけを出力する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testPlatformCatalog( TestContext &context)
{
	// Driverの版数・配布物・対象条件を保持する、架空Manifest XML。
	const std::wstring xml =
		LR"(<?xml version="1.0" encoding="utf-16"?><Manifest xmlns="openmanage/cm/dm">)"
		LR"(<SoftwareComponent releaseID="A1B2C" releaseDate="September 02, 2026")"
		LR"( vendorVersion="9.10.11.12" dellVersion="A03")"
		LR"( path="FOLDER00000002M/1/Test-Driver_A1B2C_WIN_9.10.11.12_A03.EXE")"
		LR"( size="4567"><Name><Display lang="en">Test Network Driver</Display></Name>)"
		LR"(<ComponentType value="DRVR"><Display lang="en">Driver</Display></ComponentType>)"
		LR"(<SupportedDevices><Device><PCIInfo vendorID="1A2B" deviceID="3C4D")"
		LR"( subVendorID="5E6F" subDeviceID="7081"/></Device><Device><PnPInfo>)"
		LR"(<PNPID>1A2B</PNPID><PnPProductID>3C4D</PnPProductID></PnPInfo></Device>)"
		LR"(</SupportedDevices><SupportedSystems><Brand><Model systemID="ABCD">)"
		LR"(<Display lang="en">Test Model 9000</Display></Model></Brand></SupportedSystems>)"
		LR"(<SupportedOperatingSystems><OperatingSystem osCode="W11P")"
		LR"( osArch="x64"><Display lang="en">Windows 11 64-bit</Display></OperatingSystem>)"
		LR"(</SupportedOperatingSystems><Criticality value="2"><Display lang="en">Urgent)"
		LR"(</Display></Criticality><Cryptography><Hash algorithm="SHA256">)" +
		std::wstring( HASH) + LR"(</Hash></Cryptography></SoftwareComponent></Manifest>)" ;
	std::vector<DellDriverRelease> releases ;	// Parserが設定する架空release群。
	DRIVERCRATE_EXPECT( context,
					   parseDellPlatformCatalog( xml, L"Test Model 9000", true, releases) == 0) ;
	DRIVERCRATE_EXPECT( context, releases.size() == 1) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( releases.size() == 1) {
		DRIVERCRATE_EXPECT( context, releases.front().releaseId == L"A1B2C") ;
		DRIVERCRATE_EXPECT( context, releases.front().version == L"9.10.11.12") ;
		DRIVERCRATE_EXPECT( context, releases.front().recommended) ;
		DRIVERCRATE_EXPECT( context, releases.front().hardwareIds.size() == 4) ;
	}

	DRIVERCRATE_EXPECT( context,
					   parseDellPlatformCatalog( xml, L"Test Model 9000", false, releases) == 0) ;
	DRIVERCRATE_EXPECT( context, releases.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief DTDを含むDell XMLがfail-closedになることを検証する。
 *
 * External entityを参照しない内部DTDでもProhibitDTDで拒否する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testDtdRejection( TestContext &context)
{
	// DTDを含むcatalogを拒否するためのXML fixture。
	constexpr std::wstring_view XML =
		LR"(<?xml version="1.0"?><!DOCTYPE ManifestIndex [<!ENTITY model "Test">]>)"
		LR"(<ManifestIndex xmlns="openmanage/cm/dm"></ManifestIndex>)" ;
	DellPlatformCatalogReference reference ;	// 変更されないことを期待する出力値。
	DRIVERCRATE_EXPECT( context, parseDellCatalogIndex( XML, L"Test Model 9000", reference) != 0) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/dell_catalog_parser_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runDellCatalogParserTests( TestContext &context)
{
	const ComApartment apartment( COINIT_MULTITHREADED) ;	// MSXML 6.0用COM lifetime。
	DRIVERCRATE_EXPECT( context, SUCCEEDED( apartment.result())) ;
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		return ;
	}

	testIndex( context) ;
	testPlatformCatalog( context) ;
	testDtdRejection( context) ;
}

} // namespace drivercrate::test
