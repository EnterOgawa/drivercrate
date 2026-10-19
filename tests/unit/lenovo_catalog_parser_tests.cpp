//------------------------------------------------------------------------------
/**
 * @file lenovo_catalog_parser_tests.cpp
 * @brief Lenovo公式catalog parser単体試験実装。
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
 * @note 架空のLenovo model catalogとdescriptorを用いてURL、hash、driver種別、Hardware ID、任意command非採用、DTD拒否を検証しま
 *       す。
 */
//------------------------------------------------------------------------------

#include "lenovo_catalog_parser_tests.h"

#include "platform/com_raii.h"
#include "platform/lenovo_catalog_parser.h"
#include "test_framework.h"

#include <Windows.h>

#include <optional>
#include <string>
#include <string_view>
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
 * @brief Model catalogの件数、URL、hash抽出を検証する。
 *
 * 許可hostのdescriptorだけを一意な参照へ変換する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testModelCatalog( TestContext &context)
{
	// Package descriptor URLとhashを結ぶ、架空一覧XML。
	const std::wstring xml =
		LR"(<?xml version="1.0" encoding="utf-8"?><packages count="1"><package>)"
		LR"(<location>https://download.lenovo.com/pccbbs/test/test_driver_2_.xml</location>)"
		LR"(<category>Test Devices</category><checksum type="sha256">)" +
		std::wstring( HASH) + LR"(</checksum></package></packages>)" ;
	std::vector<LenovoCatalogReference> references ;	// Parserが設定するdescriptor参照群。
	DRIVERCRATE_EXPECT( context, parseLenovoModelCatalog( xml, references) == 0) ;
	DRIVERCRATE_EXPECT( context, references.size() == 1) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( references.size() == 1) {
		DRIVERCRATE_EXPECT( context,
						   references.front().descriptorUrl ==
							   L"https://download.lenovo.com/pccbbs/test/test_driver_2_.xml") ;
		DRIVERCRATE_EXPECT( context, references.front().category == L"Test Devices") ;
		DRIVERCRATE_EXPECT( context, references.front().sha256 == HASH) ;
	}

	std::wstring	  unsafe = xml ;									// Allowlist外hostへ改変するcatalog。
	const std::size_t host	 = unsafe.find( L"download.lenovo.com") ;	// Host文字列位置。
	DRIVERCRATE_EXPECT( context, host != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( host != std::wstring::npos) {
		unsafe.replace( host, std::wstring_view( L"download.lenovo.com").size(), L"example.invalid") ;
		DRIVERCRATE_EXPECT( context, parseLenovoModelCatalog( unsafe, references) != 0) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Driver descriptorの適用性metadata抽出を検証する。
 *
 * Driver種別、推奨度、再起動、payload、Hardware IDだけを抽出し、任意commandを結果へ含めない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testDriverDescriptor( TestContext &context)
{
	// 版数・再起動・適用条件を検証する架空Package descriptor。
	const std::wstring xml =
		LR"(<?xml version="1.0" encoding="utf-8"?>)"
		LR"(<Package id="test01" version="9.8.7.6" hide="False">)"
		LR"(<Title><Desc id="EN">Test Network Driver</Desc></Title>)"
		LR"(<Severity type="2"/><ReleaseDate>2026-09-02</ReleaseDate>)"
		LR"(<Reboot type="3"/><PackageType type="2"/>)"
		LR"(<Install><Cmdline>untrusted.exe /silent</Cmdline></Install>)"
		LR"(<DetectInstall><_Driver><HardwareID>PCI\VEN_1A2B&amp;DEV_3C4D</HardwareID>)"
		LR"(</_Driver></DetectInstall><Dependencies><_PnPID>)"
		LR"(PCI\VEN_1A2B&amp;DEV_3C4D</_PnPID></Dependencies>)"
		LR"(<Files><Installer><File><Name>test01.exe</Name><CRC>)" +
		std::wstring( HASH) +
		LR"(</CRC><Size>123456</Size></File></Installer></Files>)"
		LR"(<SigningTime>2026/09/02 12:34:56</SigningTime></Package>)" ;
	std::optional<LenovoDriverRelease> release ;	// Parserが設定するdriver metadata。
	DRIVERCRATE_EXPECT(
		context, parseLenovoPackageDescriptor(
					 xml, L"https://download.lenovo.com/pccbbs/test/test01_2_.xml", release) == 0) ;
	DRIVERCRATE_EXPECT( context, release.has_value()) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( release.has_value()) {
		DRIVERCRATE_EXPECT( context, release->packageId == L"test01") ;
		DRIVERCRATE_EXPECT( context, release->version == L"9.8.7.6") ;
		DRIVERCRATE_EXPECT( context, release->recommended) ;
		DRIVERCRATE_EXPECT( context, release->rebootMayBeRequired) ;
		DRIVERCRATE_EXPECT( context, release->installerUrl ==
										L"https://download.lenovo.com/pccbbs/test/test01.exe") ;
		DRIVERCRATE_EXPECT( context, release->size == 123456) ;
		DRIVERCRATE_EXPECT( context, release->hardwareIds.size() == 1) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 非driver descriptorとDTDを安全に処理することを検証する。
 *
 * Firmwareは候補化せず、DTDを含むXMLはfail-closedで拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testRejections( TestContext &context)
{
	// Driver以外のpackage分類を検証する最小XML fixture。
	constexpr std::wstring_view FIRMWARE =
		LR"(<?xml version="1.0"?><Package><PackageType type="1"/></Package>)" ;
	std::optional<LenovoDriverRelease> release ;	// 非driver時に空のままの結果。
	DRIVERCRATE_EXPECT(
		context,
		parseLenovoPackageDescriptor(
			FIRMWARE, L"https://download.lenovo.com/pccbbs/test/firmware_2_.xml", release) == 0) ;
	DRIVERCRATE_EXPECT( context, !release.has_value()) ;

	// DTDを使用する一覧を拒否するためのXML fixture。
	constexpr std::wstring_view DTD =
		LR"(<?xml version="1.0"?><!DOCTYPE packages [<!ENTITY value "1">]>)"
		LR"(<packages count="&value;"></packages>)" ;
	std::vector<LenovoCatalogReference> references ;	// 変更されないことを期待する出力値。
	DRIVERCRATE_EXPECT( context, parseLenovoModelCatalog( DTD, references) != 0) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/lenovo_catalog_parser_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runLenovoCatalogParserTests( TestContext &context)
{
	const ComApartment apartment( COINIT_MULTITHREADED) ;	// MSXML 6.0用COM lifetime。
	DRIVERCRATE_EXPECT( context, SUCCEEDED( apartment.result())) ;
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		return ;
	}

	testModelCatalog( context) ;
	testDriverDescriptor( context) ;
	testRejections( context) ;
}

} // namespace drivercrate::test
