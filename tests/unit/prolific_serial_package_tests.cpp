//------------------------------------------------------------------------------
/**
 * @file prolific_serial_package_tests.cpp
 * @brief Prolific Serial利用者指定ZIP検証単体試験実装。
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
 * @note Networkや実driverを使用せず、標準USB IDの完全一致とfail-closed入力を検証します。
 */
//------------------------------------------------------------------------------

#include "prolific_serial_package_tests.h"

#include "platform/official_download_workspace.h"
#include "platform/prolific_serial_package.h"
#include "test_framework.h"

#include <array>
#include <string>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 公式page掲載の標準USB IDを受理することを検証する。
 *
 * 全掲載PIDと正規のREV／MI componentを大小文字非依存で受理することを確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testSupportedHardwareIds( TestContext &context)
{
	// Prolific serial packageで明示対応するPIDの境界試験用集合。
	constexpr std::array SUPPORTED_PIDS{L"2303", L"2304", L"2323", L"23A3", L"23B3",
										L"23C3", L"23D3", L"23E3", L"23F3"} ;
	// 公式pageに列挙された全PIDを固定VIDとの完全一致で確認する。
	for( const wchar_t *const pid : SUPPORTED_PIDS) {
		const std::wstring hardwareId =
			// 現在検証する標準USB ID。
			std::wstring( L"USB\\VID_067B&PID_") + pid ;
		DRIVERCRATE_EXPECT( context, isProlificSerialCandidateHardwareId( hardwareId)) ;
	}

	DRIVERCRATE_EXPECT( context,
					   isProlificSerialCandidateHardwareId( L"usb\\vid_067b&pid_2303&rev_0400")) ;
	DRIVERCRATE_EXPECT(
		context, isProlificSerialCandidateHardwareId( L"USB\\VID_067B&PID_23A3&REV_0100&MI_00")) ;
	DRIVERCRATE_EXPECT( context,
					   isProlificSerialCandidateHardwareId( L"USB\\VID_067B&PID_23B3&MI_01")) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未掲載または不正なUSB IDを拒否することを検証する。
 *
 * VID／PIDの部分一致、未掲載PID、不正桁、任意suffixを候補化しないことを確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testUnsupportedHardwareIds( TestContext &context)
{
	constexpr std::array REJECTED_IDS{
		L"USB\\VID_0000&PID_2303",
		L"USB\\VID_067B&PID_2320",
		L"USB\\VID_067B&PID_230",
		L"USB\\VID_067B&PID_23030",
		L"USB\\VID_067B&PID_2303&REV_040",
		L"USB\\VID_067B&PID_2303&REV_04G0",
		L"USB\\VID_067B&PID_2303&MI_0",
		L"USB\\VID_067B&PID_2303&MI_000",
		L"USB\\VID_067B&PID_2303&MI_00&REV_0400",
		L"USB\\VID_067B&PID_2303&REV_0400&MI_00&EXTRA_01",
		L"XUSB\\VID_067B&PID_2303",
	} ; // 公式scope外または構文不正なID一覧。
	// 全拒否例を走査し、一件でも部分一致で受理されないことを確認する。
	for( const wchar_t *const hardwareId : REJECTED_IDS) {
		DRIVERCRATE_EXPECT( context, !isProlificSerialCandidateHardwareId( hardwareId)) ;
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
	OfficialDownloadWorkspace	  workspace ;	// 初期化されてはならない出力領域。
	ProlificSerialPackageContents contents ;	// 失敗時に空へ戻す検証結果。
	contents.archiveSize	= 1U ;
	contents.archiveSha256	= L"fictional" ;
	const NativeError error = inspectProlificSerialPackageFile( L"", 0, workspace,
															   contents) ;	// 入力拒否結果。
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
 * @see tests/unit/prolific_serial_package_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runProlificSerialPackageTests( TestContext &context)
{
	testSupportedHardwareIds( context) ;
	testUnsupportedHardwareIds( context) ;
	testInvalidPackageInput( context) ;
}

} // namespace drivercrate::test
