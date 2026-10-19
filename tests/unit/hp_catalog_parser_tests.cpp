//------------------------------------------------------------------------------
/**
 * @file hp_catalog_parser_tests.cpp
 * @brief HP公式catalog parser単体試験実装。
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
 * @note 架空dataだけでPlatform／OS照合、driver分離、SoftPaq検証、DTD拒否を確認します。実端末inventoryとnetworkへ接続しません。
 */
//------------------------------------------------------------------------------

#include "hp_catalog_parser_tests.h"

#include "platform/com_raii.h"
#include "platform/hp_catalog_parser.h"
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

constexpr std::wstring_view HASH =
	L"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ;	// 架空hash。

//------------------------------------------------------------------------------
// 内部試験関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Platform ID、x64、buildに一致する参照抽出を検証する。
 *
 * 一致entryだけをURL構築可能な有限値へ変換する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testPlatformCatalog( TestContext &context)
{
	// PlatformとOS buildの一致を検証する架空ImagePal XML。
	constexpr std::wstring_view XML =
		LR"(<?xml version="1.0"?><ImagePal><Platform><ProductName>Test PC</ProductName>)"
		LR"(<OS><OSVersion>11.0</OSVersion><OSArchitecture>64</OSArchitecture>)"
		LR"(<OSReleaseIdFilename>24H2</OSReleaseIdFilename><OSBuildId>26100</OSBuildId>)"
		LR"(</OS><SystemID>8A05</SystemID></Platform></ImagePal>)" ;
	HpPlatformReference reference ;	// Parserが設定するplatform reference。
	DRIVERCRATE_EXPECT( context, parseHpPlatformCatalog( XML, L"8a05", 26100, reference) == 0) ;
	DRIVERCRATE_EXPECT( context, reference.systemId == L"8A05") ;
	DRIVERCRATE_EXPECT( context, reference.osVersion == L"11.0") ;
	DRIVERCRATE_EXPECT( context, reference.releaseId == L"24h2") ;
	DRIVERCRATE_EXPECT( context, reference.osBuild == 26100) ;
	DRIVERCRATE_EXPECT( context, parseHpPlatformCatalog( XML, L"8A05", 22631, reference) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Driver SoftPaqとDeviceId対応の抽出を検証する。
 *
 * Firmwareを除外し、driverのhash、URL、推奨度、IDを保持する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testReferenceCatalog( TestContext &context)
{
	// SystemInfoと配布metadataの結合を検証する架空ImagePal XML。
	const std::wstring xml =
		LR"(<?xml version="1.0"?><ImagePal><HPReference>Yes</HPReference><SystemInfo><System>)"
		LR"(<SystemID>8A05</SystemID><OSArchitecture>64-bit</OSArchitecture>)"
		LR"(<OSBuildNumber>26100</OSBuildNumber><DisplayVersion>24H2</DisplayVersion>)"
		LR"(</System></SystemInfo><Solutions><UpdateInfo><Id>sp123456</Id>)"
		LR"(<Name>Test Network Driver</Name><Category>Driver - Network</Category>)"
		LR"(<Description>This package contains only a test driver.</Description>)"
		LR"(<Version>9.8.7.6</Version><Vendor>Test Vendor</Vendor>)"
		LR"(<ReleaseType>Recommended</ReleaseType>)"
		LR"(<SilentInstall>untrusted.exe /silent</SilentInstall>)"
		LR"(<Url>ftp.hp.com/pub/softpaq/sp123001-123500/sp123456.exe</Url><SHA256>)" +
		std::wstring( HASH) +
		LR"(</SHA256><Size>123456</Size><DateReleased>2026-09-02</DateReleased>)"
		LR"(</UpdateInfo><UpdateInfo><Id>sp123457</Id><Name>Mixed Driver</Name>)"
		LR"(<Category>Driver - Network</Category><Description>This package contains drivers )"
		LR"(and firmware.</Description>)"
		LR"(</UpdateInfo><UpdateInfo><Id>sp654321</Id><Name>Test Firmware</Name>)"
		LR"(<Category>Firmware</Category></UpdateInfo></Solutions><Devices><Device>)"
		LR"(<DeviceId>PCI\VEN_1A2B&amp;DEV_3C4D</DeviceId><Solutions>)"
		LR"(<UpdateInfo IdRef="sp123456"/><UpdateInfo IdRef="sp123457"/>)"
		LR"(<UpdateInfo IdRef="sp654321"/>)"
		LR"(</Solutions></Device></Devices></ImagePal>)" ;
	const HpPlatformReference	 reference{.systemId  = L"8A05",
										   .osVersion = L"11.0",
										   .releaseId = L"24h2",
										   .osBuild	  = 26100} ;	// 期待platform値。
	std::vector<HpDriverRelease> releases ;							// Parserが設定するdriver SoftPaq群。
	DRIVERCRATE_EXPECT( context, parseHpReferenceCatalog( xml, reference, releases) == 0) ;
	DRIVERCRATE_EXPECT( context, releases.size() == 1) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( releases.size() == 1) {
		const HpDriverRelease &release = releases.front() ;	// 検証対象driver metadata。
		DRIVERCRATE_EXPECT( context, release.softpaqId == L"sp123456") ;
		DRIVERCRATE_EXPECT( context, release.version == L"9.8.7.6") ;
		DRIVERCRATE_EXPECT( context, release.recommended) ;
		DRIVERCRATE_EXPECT( context, release.installerUrl == L"https://ftp.hp.com/pub/softpaq/"
															L"sp123001-123500/sp123456.exe") ;
		DRIVERCRATE_EXPECT( context, release.sha256 == HASH) ;
		DRIVERCRATE_EXPECT( context, release.hardwareIds.size() == 1) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief DTDとallowlist外payloadを拒否することを検証する。
 *
 * External entityと第三者URLをdriver metadataへ入れない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testRejections( TestContext &context)
{
	// DTDを含む入力を拒否するための架空catalog。
	constexpr std::wstring_view DTD =
		LR"(<?xml version="1.0"?><!DOCTYPE ImagePal [<!ENTITY value "8A05">]>)"
		LR"(<ImagePal><Platform><OS><OSVersion>11.0</OSVersion>)"
		LR"(<OSArchitecture>64</OSArchitecture><OSReleaseIdFilename>24H2</OSReleaseIdFilename>)"
		LR"(<OSBuildId>26100</OSBuildId></OS><SystemID>&value;</SystemID></Platform></ImagePal>)" ;
	HpPlatformReference platform ;	// DTD拒否時に有効化されない出力値。
	DRIVERCRATE_EXPECT( context, parseHpPlatformCatalog( DTD, L"8A05", 26100, platform) != 0) ;

	// 安全条件を満たさない配布情報を含む拒否用catalog。
	const std::wstring unsafe =
		LR"(<ImagePal><HPReference>Yes</HPReference><SystemInfo><System>)"
		LR"(<SystemID>8A05</SystemID><OSArchitecture>64-bit</OSArchitecture>)"
		LR"(<OSBuildNumber>26100</OSBuildNumber><DisplayVersion>24H2</DisplayVersion>)"
		LR"(</System></SystemInfo><Solutions><UpdateInfo><Id>sp123456</Id>)"
		LR"(<Name>Test Driver</Name><Category>Driver</Category><Version>1.0</Version>)"
		LR"(<Description>This package contains only a test driver.</Description>)"
		LR"(<Vendor>Test</Vendor><ReleaseType>Routine</ReleaseType>)"
		LR"(<Url>https://example.invalid/sp123456.exe</Url><SHA256>)" +
		std::wstring( HASH) +
		LR"(</SHA256><Size>1</Size><DateReleased>2026-09-02</DateReleased>)"
		LR"(</UpdateInfo></Solutions><Devices><Device><DeviceId>PCI\VEN_1A2B</DeviceId>)"
		LR"(<Solutions><UpdateInfo IdRef="sp123456"/></Solutions></Device></Devices></ImagePal>)" ;
	const HpPlatformReference	 reference{.systemId  = L"8A05",
										   .osVersion = L"11.0",
										   .releaseId = L"24h2",
										   .osBuild	  = 26100} ;	// 期待platform値。
	std::vector<HpDriverRelease> releases ;							// 不正URLで空のままにする出力群。
	DRIVERCRATE_EXPECT( context, parseHpReferenceCatalog( unsafe, reference, releases) != 0) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/hp_catalog_parser_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runHpCatalogParserTests( TestContext &context)
{
	const ComApartment apartment( COINIT_MULTITHREADED) ;	// MSXML 6.0用COM lifetime。
	DRIVERCRATE_EXPECT( context, SUCCEEDED( apartment.result())) ;
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		return ;
	}

	testPlatformCatalog( context) ;
	testReferenceCatalog( context) ;
	testRejections( context) ;
}

} // namespace drivercrate::test
