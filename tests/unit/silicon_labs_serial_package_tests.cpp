//------------------------------------------------------------------------------
/**
 * @file silicon_labs_serial_package_tests.cpp
 * @brief Silicon Labs CP210x利用者指定ZIP検証単体試験実装。
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
 * @note Networkや実driverを使用せず、固定14 IDの完全一致とfail-closed入力を検証します。
 */
//------------------------------------------------------------------------------

#include "silicon_labs_serial_package_tests.h"

#include "platform/official_download_workspace.h"
#include "platform/silicon_labs_serial_package.h"
#include "test_framework.h"

#include <array>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief CP210x 11.5.0の全標準USB IDを受理することを検証する。
 *
 * NTamd64 model sectionの14 IDを大小文字非依存で受理する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testSupportedHardwareIds( TestContext &context)
{
	constexpr std::array SUPPORTED_IDS{
		L"USB\\VID_10C4&PID_EA60",		 L"USB\\VID_10C4&PID_EA63",
		L"USB\\VID_10C4&PID_EA70&MI_00", L"USB\\VID_10C4&PID_EA70&MI_01",
		L"USB\\VID_10C4&PID_EA71&MI_00", L"USB\\VID_10C4&PID_EA71&MI_01",
		L"USB\\VID_10C4&PID_EA71&MI_02", L"USB\\VID_10C4&PID_EA71&MI_03",
		L"USB\\VID_10C4&PID_EA7A&MI_00", L"USB\\VID_10C4&PID_EA7A&MI_01",
		L"USB\\VID_10C4&PID_EA7B&MI_00", L"USB\\VID_10C4&PID_EA7B&MI_01",
		L"USB\\VID_10C4&PID_EA7B&MI_02", L"USB\\VID_10C4&PID_EA7B&MI_03",
	} ; // 署名済みINFが列挙する固定ID群。
	// 全標準IDを一件ずつ完全一致で確認する。
	for( const wchar_t *const hardwareId : SUPPORTED_IDS) {
		DRIVERCRATE_EXPECT( context, isSiliconLabsSerialCandidateHardwareId( hardwareId)) ;
	}

	DRIVERCRATE_EXPECT( context, isSiliconLabsSerialCandidateHardwareId( L"usb\\vid_10c4&pid_ea60")) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Customまたは不正なUSB IDを拒否することを検証する。
 *
 * VID／PID変更、interface省略、revision追加、部分一致を候補化しないことを確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testUnsupportedHardwareIds( TestContext &context)
{
	constexpr std::array REJECTED_IDS{
		L"USB\\VID_0000&PID_EA60",			L"USB\\VID_10C4&PID_EA61",
		L"USB\\VID_10C4&PID_EA6",			L"USB\\VID_10C4&PID_EA600",
		L"USB\\VID_10C4&PID_EA60&REV_0100", L"USB\\VID_10C4&PID_EA70",
		L"USB\\VID_10C4&PID_EA70&MI_0",		L"USB\\VID_10C4&PID_EA70&MI_02",
		L"USB\\VID_10C4&PID_EA71&MI_04",	L"USB\\VID_10C4&PID_EA7A&MI_00&EXTRA_01",
		L"XUSB\\VID_10C4&PID_EA60",
	} ; // 固定INF scope外または構文不正なID群。
	// 全拒否例を走査し、一件でも部分一致で受理されないことを確認する。
	for( const wchar_t *const hardwareId : REJECTED_IDS) {
		DRIVERCRATE_EXPECT( context, !isSiliconLabsSerialCandidateHardwareId( hardwareId)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 不正なpackage入力を副作用なしで拒否することを検証する。
 *
 * 空pathと0 sessionを拒否し、呼出前の架空結果を残さない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testInvalidPackageInput( TestContext &context)
{
	OfficialDownloadWorkspace		 workspace ;	// 初期化されてはならない出力領域。
	SiliconLabsSerialPackageContents contents ;		// 失敗時に空へ戻す検証結果。
	contents.archiveSize   = 1U ;
	contents.archiveSha256 = L"fictional" ;
	const NativeError error =
		// 入力拒否結果。
		inspectSiliconLabsSerialPackageFile( L"", 0, workspace, contents) ;
	DRIVERCRATE_EXPECT( context, error != 0) ;
	DRIVERCRATE_EXPECT( context, contents.archiveSize == 0U) ;
	DRIVERCRATE_EXPECT( context, contents.archiveSha256.empty()) ;
	DRIVERCRATE_EXPECT( context, contents.entries.empty()) ;
	DRIVERCRATE_EXPECT( context, contents.packages.empty()) ;
	DRIVERCRATE_EXPECT( context, contents.verificationStage ==
									UserSelectedInfPackageVerificationStage::NOT_STARTED) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/silicon_labs_serial_package_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runSiliconLabsSerialPackageTests( TestContext &context)
{
	testSupportedHardwareIds( context) ;
	testUnsupportedHardwareIds( context) ;
	testInvalidPackageInput( context) ;
}

} // namespace drivercrate::test
