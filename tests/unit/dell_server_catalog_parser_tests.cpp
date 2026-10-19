//------------------------------------------------------------------------------
/**
 * @file dell_server_catalog_parser_tests.cpp
 * @brief Dell PowerEdge catalog parser単体試験実装。
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
 * @note 実model、Hardware ID、download URLを含まない架空XMLだけを使用します。
 */
//------------------------------------------------------------------------------

#include "dell_server_catalog_parser_tests.h"

#include "platform/dell_server_catalog_parser.h"
#include "test_framework.h"

#include <Windows.h>
#include <objbase.h>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {

constexpr std::wstring_view VALID_CATALOG = LR"(<?xml version="1.0" encoding="utf-16"?>
<Manifest baseLocation="downloads.dell.com">
  <SoftwareComponent releaseID="ABC12" releaseDate="September 02, 2026"
      vendorVersion="2.3.4" dellVersion="A01" packageType="LW64"
      path="FOLDER00000001M/1/Network_Driver_ABC12_WN64_2.3.4_A01.EXE"
      size="123456" rebootRequired="true"
      hash="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      hashAlgorithm="SHA256">
    <Name><Display lang="en">Fictional Network Driver</Display></Name>
    <ComponentType value="DRVR"><Display lang="en">Driver</Display></ComponentType>
    <SupportedDevices>
      <Device><PCIInfo vendorID="1234" deviceID="5678"
          subVendorID="1028" subDeviceID="0001"/></Device>
    </SupportedDevices>
    <SupportedSystems>
      <Brand><Display lang="en">PowerEdge</Display>
        <Model><Display lang="en">R9000</Display></Model>
      </Brand>
    </SupportedSystems>
    <SupportedOperatingSystems>
      <OperatingSystem osCode="W22SE" osVendor="Microsoft" osArch="x64"
          buildNumber="20348">
        <Display lang="en">Microsoft - Windows Server 2022 LTSC - Standard</Display>
      </OperatingSystem>
    </SupportedOperatingSystems>
    <Criticality value="1"><Display lang="en">Recommended</Display></Criticality>
  </SoftwareComponent>
  <SoftwareComponent releaseID="BIOS1" packageType="LW64">
    <ComponentType value="BIOS"><Display lang="en">BIOS</Display></ComponentType>
  </SoftwareComponent>
</Manifest>)" ;	// 一件の架空PowerEdge driverを含む正常catalog。

//------------------------------------------------------------------------------
/**
 * @brief Model／Server build／PCI ID一致driverを抽出する。
 *
 * BIOSを除外し、DUP metadataとSUBSYS付きIDを保持する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testValidCatalog( TestContext &context)
{
	std::vector<DellServerDriverRelease> releases ;	// Parserが設定するdriver群。
	DRIVERCRATE_EXPECT(
		context, parseDellServerCatalog( VALID_CATALOG, L"PowerEdge R9000", 20348, releases) == 0) ;
	DRIVERCRATE_EXPECT( context, releases.size() == 1) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( releases.size() != 1) {
		return ;
	}

	const DellServerDriverRelease &release = releases.front() ;	// 検証対象release。
	DRIVERCRATE_EXPECT( context, release.releaseId == L"ABC12") ;
	DRIVERCRATE_EXPECT( context, release.version == L"2.3.4") ;
	DRIVERCRATE_EXPECT( context, release.size == 123456) ;
	DRIVERCRATE_EXPECT( context, release.recommended) ;
	DRIVERCRATE_EXPECT( context, release.rebootRequired) ;
	DRIVERCRATE_EXPECT( context, std::find( release.hardwareIds.begin(), release.hardwareIds.end(),
										  L"PCI\\VEN_1234&DEV_5678&SUBSYS_00011028") !=
									release.hardwareIds.end()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Model、build、OS用途の不一致を候補0件にすることを検証する。
 *
 * 部分model、別Server build、Azure Stack HCIを推測採用しない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testApplicability( TestContext &context)
{
	std::vector<DellServerDriverRelease> releases ;	// 各不一致caseの出力。
	DRIVERCRATE_EXPECT(
		context, parseDellServerCatalog( VALID_CATALOG, L"PowerEdge R900", 20348, releases) == 0) ;
	DRIVERCRATE_EXPECT( context, releases.empty()) ;
	DRIVERCRATE_EXPECT(
		context, parseDellServerCatalog( VALID_CATALOG, L"PowerEdge R9000", 26100, releases) == 0) ;
	DRIVERCRATE_EXPECT( context, releases.empty()) ;

	std::wstring	   hciCatalog( VALID_CATALOG) ;	// Server表示をHCIへ置換するcatalog copy。
	// Server OS名の照合に使用する、明示したLTSC edition表記。
	const std::wstring serverText = L"Microsoft - Windows Server 2022 LTSC - Standard" ;
	const std::size_t  position	  = hciCatalog.find( serverText) ;	// OS表示の置換位置。
	DRIVERCRATE_EXPECT( context, position != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( position != std::wstring::npos) {
		hciCatalog.replace( position, serverText.size(), L"Microsoft - Azure Stack HCI") ;
		DRIVERCRATE_EXPECT(
			context, parseDellServerCatalog( hciCatalog, L"PowerEdge R9000", 20348, releases) == 0) ;
		DRIVERCRATE_EXPECT( context, releases.empty()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Relevant driverの危険なpayload metadataを拒否する。
 *
 * Model／OS一致componentのpath traversalを全catalog失敗にする。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testMetadataRejection( TestContext &context)
{
	std::wstring	   invalid( VALID_CATALOG) ;	// Pathだけを改ざんするcatalog copy。
	// DUP相対pathの正常条件を確認する架空配布path。
	const std::wstring safePath = L"FOLDER00000001M/1/Network_Driver_ABC12_WN64_2.3.4_A01.EXE" ;
	const std::size_t  position = invalid.find( safePath) ;	// Path置換位置。
	DRIVERCRATE_EXPECT( context, position != std::wstring::npos) ;
	// 変形箇所がない場合は範囲外編集を避けて詳細検証を中止する。
	if( position == std::wstring::npos) {
		return ;
	}

	invalid.replace( position, safePath.size(), L"../driver.exe") ;
	std::vector<DellServerDriverRelease> releases ;	// 失敗時に空であるべき出力。
	DRIVERCRATE_EXPECT( context,
					   parseDellServerCatalog( invalid, L"PowerEdge R9000", 20348, releases) != 0) ;
	DRIVERCRATE_EXPECT( context, releases.empty()) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/dell_server_catalog_parser_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runDellServerCatalogParserTests( TestContext &context)
{
	const HRESULT initialization = CoInitializeEx( nullptr, COINIT_MULTITHREADED) ;	// COM MTA結果。
	DRIVERCRATE_EXPECT( context, SUCCEEDED( initialization)) ;
	// COM初期化に失敗したthreadではparser試験を開始しない。
	if( FAILED( initialization)) {
		return ;
	}

	testValidCatalog( context) ;
	testApplicability( context) ;
	testMetadataRejection( context) ;
	CoUninitialize() ;
}

} // namespace drivercrate::test
