//------------------------------------------------------------------------------
/**
 * @file wch_serial_package_tests.cpp
 * @brief WCH USB serial利用者指定ZIP検証単体試験実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  CH342／CH343系PnP ID境界試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 実driverを導入せず、署名済みINFで確認したPnP IDだけを候補化する境界を決定的に検証します。
 */
//------------------------------------------------------------------------------

#include "wch_serial_package_tests.h"

#include "platform/official_download_workspace.h"
#include "platform/wch_serial_package.h"
#include "test_framework.h"

#include <array>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief WCH署名済みINFの固定USB IDを受理することを検証する。
 *
 * 現行CH341SER INF 4.0の全固定IDをcase非依存で確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testSupportedHardwareIds( TestContext &context)
{
	// CH341SER 4.0のNTamd64 model sectionにある重複なしPnP ID群。
	constexpr std::array SUPPORTED_IDS{
		L"USB\\VID_1A86&PID_7523", L"USB\\VID_1A86&PID_5523", L"USB\\VID_1A86&PID_7522",
		L"USB\\VID_1A86&PID_E523", L"USB\\VID_4348&PID_5523", L"USB\\VID_4348&PID_5523&REV_0250"} ;
	// 固定allowlistの全IDを個別に確認する。
	for( const wchar_t *const hardwareId : SUPPORTED_IDS) {
		DRIVERCRATE_EXPECT( context, isWchSerialCandidateHardwareId( hardwareId)) ;
	}

	DRIVERCRATE_EXPECT( context, isWchSerialCandidateHardwareId( L"usb\\vid_1a86&pid_7523")) ;
}

//------------------------------------------------------------------------------
/**
 * @brief WCH固定範囲外のUSB IDを拒否することを検証する。
 *
 * Custom VID／PID、suffix追加、部分一致、別busを拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testRejectedHardwareIds( TestContext &context)
{
	// CH341SERの既知境界違反を網羅する拒否PnP ID群。
	constexpr std::array REJECTED_IDS{
		L"USB\\VID_1A86&PID_7524",			L"USB\\VID_1A86&PID_7523&REV_0400",
		L"USB\\VID_4348&PID_5523&REV_0251", L"USB\\VID_1A86&PID_752",
		L"USB\\VID_1A86&PID_75230",			L"PCI\\VEN_1A86&DEV_7523",
		L"USB\\VID_0000&PID_7523",			L"USB\\VID_1A86&PID_7523&MI_00"} ;
	// 固定allowlistにない各形式を部分一致させないことを確認する。
	for( const wchar_t *const hardwareId : REJECTED_IDS) {
		DRIVERCRATE_EXPECT( context, !isWchSerialCandidateHardwareId( hardwareId)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief WCH CH343SER 2.2の固定USB IDを受理することを検証する。
 *
 * NTamd64 model sectionの全40 IDをcase非依存で確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testMultiSupportedHardwareIds( TestContext &context)
{
	// CH343SER 2.2のNTamd64 model sectionにある重複なしPnP ID群。
	constexpr std::array SUPPORTED_IDS{
		L"USB\\VID_1A86&PID_55D2&MI_00", L"USB\\VID_1A86&PID_55D2&MI_02",
		L"USB\\VID_1A86&PID_55D3",		 L"USB\\VID_1A86&PID_55D4",
		L"USB\\VID_1A86&PID_55D5&MI_00", L"USB\\VID_1A86&PID_55D5&MI_02",
		L"USB\\VID_1A86&PID_55D5&MI_04", L"USB\\VID_1A86&PID_55D5&MI_06",
		L"USB\\VID_1A86&PID_55D6",		 L"USB\\VID_1A86&PID_55D7&MI_00",
		L"USB\\VID_1A86&PID_55D7&MI_02", L"USB\\VID_1A86&PID_55D8",
		L"USB\\VID_1A86&PID_55DA&MI_00", L"USB\\VID_1A86&PID_55DA&MI_02",
		L"USB\\VID_1A86&PID_55DB&MI_00", L"USB\\VID_1A86&PID_55DD&MI_00",
		L"USB\\VID_1A86&PID_55DE&MI_00", L"USB\\VID_1A86&PID_55DE&MI_02",
		L"USB\\VID_1A86&PID_55DF&MI_00", L"USB\\VID_1A86&PID_55DF&MI_02",
		L"USB\\VID_1A86&PID_55DF&MI_04", L"USB\\VID_1A86&PID_55DF&MI_06",
		L"USB\\VID_1A86&PID_55E7&MI_00", L"USB\\VID_1A86&PID_55E7&MI_01",
		L"USB\\VID_1A86&PID_55E8&MI_00", L"USB\\VID_1A86&PID_55E8&MI_02",
		L"USB\\VID_1A86&PID_55E8&MI_04", L"USB\\VID_1A86&PID_55E8&MI_06",
		L"USB\\VID_1A86&PID_55E9",		 L"USB\\VID_1A86&PID_55EA&MI_00",
		L"USB\\VID_1A86&PID_55EA&MI_02", L"USB\\VID_1A86&PID_55EB&MI_00",
		L"USB\\VID_1A86&PID_55EC&MI_00", L"USB\\VID_1A86&PID_55EC&MI_02",
		L"USB\\VID_1A86&PID_55EF&MI_00", L"USB\\VID_1A86&PID_55EF&MI_02",
		L"USB\\VID_1A86&PID_55EF&MI_04", L"USB\\VID_1A86&PID_55EF&MI_06",
		L"USB\\VID_1A86&PID_5610&MI_01", L"USB\\VID_1A86&PID_7523&REV_8234"} ;
	// 固定allowlistの全IDを個別に確認する。
	for( const wchar_t *const hardwareId : SUPPORTED_IDS) {
		DRIVERCRATE_EXPECT( context, isWchMultiSerialCandidateHardwareId( hardwareId)) ;
	}

	DRIVERCRATE_EXPECT( context, isWchMultiSerialCandidateHardwareId( L"usb\\vid_1a86&pid_55d3")) ;
}

//------------------------------------------------------------------------------
/**
 * @brief WCH CH343SER固定範囲外のUSB IDを拒否することを検証する。
 *
 * Comment化ID、interface省略、suffix、別busを拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testMultiRejectedHardwareIds( TestContext &context)
{
	// 既知の境界違反を網羅する拒否PnP ID群。
	constexpr std::array REJECTED_IDS{
		L"USB\\VID_1A86&PID_55EB&MI_02", L"USB\\VID_1A86&PID_55D2",
		L"USB\\VID_1A86&PID_55D3&MI_00", L"USB\\VID_1A86&PID_55D3&REV_0100",
		L"USB\\VID_1A86&PID_55D",		 L"USB\\VID_1A86&PID_55D30",
		L"PCI\\VEN_1A86&DEV_55D3",		 L"USB\\VID_0000&PID_55D3"} ;
	// 固定allowlistにない各形式を部分一致させないことを確認する。
	for( const wchar_t *const hardwareId : REJECTED_IDS) {
		DRIVERCRATE_EXPECT( context, !isWchMultiSerialCandidateHardwareId( hardwareId)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 不正な利用者選択入力を候補なしで拒否することを検証する。
 *
 * 空pathとsession 0でworkspaceを使用せず結果を公開しない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testInvalidInput( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 初期化されていない保護workspace。
	WchSerialPackageContents  contents ;	// 失敗時は段階以外を保持しない結果。
	DRIVERCRATE_EXPECT( context, inspectWchSerialPackageFile( {}, 0, workspace, contents) != 0) ;
	DRIVERCRATE_EXPECT( context, contents.archiveSha256.empty()) ;
	DRIVERCRATE_EXPECT( context, contents.entries.empty()) ;
	DRIVERCRATE_EXPECT( context, contents.packages.empty()) ;
	DRIVERCRATE_EXPECT( context, contents.verificationStage ==
									UserSelectedInfPackageVerificationStage::NOT_STARTED) ;

	WchSerialPackageContents multiContents ;	// CH343SER失敗時の非公開結果。
	DRIVERCRATE_EXPECT( context,
					   inspectWchMultiSerialPackageFile( {}, 0, workspace, multiContents) != 0) ;
	DRIVERCRATE_EXPECT( context, multiContents.archiveSha256.empty()) ;
	DRIVERCRATE_EXPECT( context, multiContents.entries.empty()) ;
	DRIVERCRATE_EXPECT( context, multiContents.packages.empty()) ;
	DRIVERCRATE_EXPECT( context, multiContents.verificationStage ==
									UserSelectedInfPackageVerificationStage::NOT_STARTED) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/wch_serial_package_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runWchSerialPackageTests( TestContext &context)
{
	testSupportedHardwareIds( context) ;
	testRejectedHardwareIds( context) ;
	testMultiSupportedHardwareIds( context) ;
	testMultiRejectedHardwareIds( context) ;
	testInvalidInput( context) ;
}

} // namespace drivercrate::test
