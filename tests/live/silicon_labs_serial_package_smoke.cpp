//------------------------------------------------------------------------------
/**
 * @file silicon_labs_serial_package_smoke.cpp
 * @brief Silicon Labs CP210x公式ZIP読み取り専用live検証。
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
 * @note 利用者がSilicon Labs公式pageから取得したCP210x ZIPを変更せず検査します。設定scriptと別architecture binaryを展開せず、driver
 *       installもしません。
 */
//------------------------------------------------------------------------------

#include "platform/official_download_workspace.h"
#include "platform/silicon_labs_serial_package.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <string>
#include <string_view>

namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::uint64_t		EXPECTED_ARCHIVE_SIZE = 290710ULL ;	// 審査した公式ZIPのbyte数。
// 明示的なread-only試験で照合する、対象archiveの固定期待SHA-256。
constexpr std::wstring_view EXPECTED_ARCHIVE_SHA256 =
	L"7cba499e944f0cd6c6de4a3c80a4646e9b0307d6704bcfa155a11f05774345e8" ;
constexpr std::array EXPECTED_FILES{std::wstring_view( L"silabser.inf"),
									std::wstring_view( L"silabser.cat"),
									// Production policyが展開する固定file群。
									std::wstring_view( L"x64\\silabser.sys")} ;
constexpr std::array EXCLUDED_FILES{
	std::wstring_view( L"UpdateParam.bat"), std::wstring_view( L"UpdateParameters.reg"),
	std::wstring_view( L"arm\\silabser.sys"), std::wstring_view( L"arm64\\silabser.sys"),
	// Workspaceへ作成してはならないentry群。
	std::wstring_view( L"x86\\silabser.sys")} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 固定file選択境界を検証する。
 *
 * ZIP内のscriptや別architectureをinstall境界へ混入させない。
 *
 * @param[in] contents Production検証が返した選択entry群。
 * @return 固定3 fileが一度ずつ存在し、hash保持済みなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasExpectedSelectedFiles(
	const drivercrate::SiliconLabsSerialPackageContents &contents)
{
	// 選択済みfileの数が固定閉包と違う場合は、余分な展開や欠落を見逃さない。
	if( contents.entries.size() != EXPECTED_FILES.size()) {
		return false ;
	}

	// 固定fileごとに一件だけ検証結果へ現れることを確認する。
	for( const std::wstring_view expectedPath : EXPECTED_FILES) {
		const auto count =
			std::ranges::count( contents.entries, expectedPath,
							   &drivercrate::OfficialZipEntry::relativePath) ;	// 固定pathの件数。
		// 各必須fileが一件だけ選択されたことを要求し、重複や欠落を拒否する。
		if( count != 1) {
			return false ;
		}
	}

	// Install直前差替え検出に必要なSHA-256が全entryへあることを確認する。
	return std::ranges::all_of( contents.entries, []( const drivercrate::OfficialZipEntry &entry) {
		return entry.sha256.size() == 64U ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択外fileがworkspaceに存在しないことを検証する。
 *
 * BAT、REG、ARM、ARM64、x86 SYSを展開・実行しない境界を確認。
 *
 * @param[in] workspace Production検証が所有する保護一時領域。
 * @return 固定選択外fileが一つも存在しない場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool excludesNonDriverFiles( const drivercrate::OfficialDownloadWorkspace &workspace)
{
	// 既知の選択外entryがworkspace内へ作成されていないことを確認する。
	for( const std::wstring_view relativePath : EXCLUDED_FILES) {
		const std::wstring path = workspace.path( relativePath) ;	// 存在確認だけに使う絶対path。
		// 選択外fileが展開されていないことを確認し、workspace pathを解決できない場合も不合格にする。
		if( path.empty() || GetFileAttributesW( path.c_str()) != INVALID_FILE_ATTRIBUTES) {
			return false ;
		}
	}

	return true ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief Silicon Labs CP210x公式ZIPのread-only live検証を実行する。
 *
 * 既知公式sampleとProduction verifierを検証し、保護領域の一byte差替えもinstall直前検証で拒否させる。
 *
 * @param[in] argumentCount 実行file名を含むargument数。
 * @param[in] arguments 一件の利用者指定CP210x公式ZIP path。
 * @return 固定package検証・再検証成功時0、失敗時1、引数不正時2。
 */
//------------------------------------------------------------------------------
int wmain( const int argumentCount, wchar_t *arguments[])
{
	// 公式ZIP一件を明示させ、空引数や過剰な引数では展開を開始しない。
	if( argumentCount != 2 || arguments == nullptr || arguments[1] == nullptr ||
	   arguments[1][0] == L'\0') {
		std::wprintf( L"Usage: silicon_labs_serial_package_smoke <official-cp210x-zip>\n") ;
		return 2 ;
	}

	drivercrate::OfficialDownloadWorkspace		  workspace ;	// 選択展開fileの所有領域。
	drivercrate::SiliconLabsSerialPackageContents contents ;	// 検証済みpackage metadata。
	drivercrate::NativeError error = drivercrate::inspectSiliconLabsSerialPackageFile(
		arguments[1], 1, workspace, contents) ;	// Production共通検証結果。
	// 固定archiveの同一性と選択閉包を照合し、余分な非driver fileの展開も検出する。
	if( error != 0 || contents.archiveSize != EXPECTED_ARCHIVE_SIZE ||
	   contents.archiveSha256 != EXPECTED_ARCHIVE_SHA256 || contents.packages.size() != 1U ||
	   !hasExpectedSelectedFiles( contents) || !excludesNonDriverFiles( workspace)) {
		std::wprintf( L"Silicon Labs CP210x verification failed: 0x%08X, stage %u\n",
					 static_cast<unsigned int>( error),
					 static_cast<unsigned int>( contents.verificationStage)) ;
		return 1 ;
	}

	const drivercrate::OfficialInfPackage &package = contents.packages.front() ;	// 固定INF情報。
	// 代表packageの明示版とID件数を確認し、別内容での合格を防ぐ。
	if( package.driverVersion != L"11.5.0.417" || package.hardwareIds.size() != 14U) {
		std::wprintf( L"Silicon Labs CP210x metadata boundary failed.\n") ;
		return 1 ;
	}

	error = drivercrate::reverifySiliconLabsSerialInfPackage(
		workspace, contents.entries, package) ;	// Install直前相当の再検証結果。
	// 改変前の再検証が成立しなければ、改変検出の確認へ進めない。
	if( error != 0) {
		std::wprintf( L"Silicon Labs CP210x re-verification failed: 0x%08X\n",
					 static_cast<unsigned int>( error)) ;
		return 1 ;
	}

	const std::wstring tamperPath =
		// 保護workspace内だけの差替え対象。
		workspace.path( L"x64\\silabser.sys") ;
	const HANDLE tamperFile =
		CreateFileW( tamperPath.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
					nullptr) ;	// Test終了時にworkspaceと共に破棄するfile handle。
	// 展開memberを変更用に開けない場合は、改変済みという前提で試験を続けない。
	if( tamperFile == INVALID_HANDLE_VALUE) {
		std::wprintf( L"Silicon Labs CP210x tamper test could not open the member.\n") ;
		return 1 ;
	}

	constexpr BYTE REPLACEMENT_BYTE = 0U ;	// PE header先頭を確実に変える置換byte。
	DWORD		   written{} ;				// WriteFileが実際に変更したbyte数。
	const BOOL	   writeResult =
		WriteFile( tamperFile, &REPLACEMENT_BYTE, sizeof( REPLACEMENT_BYTE), &written,
				  nullptr) ;	// 保護workspaceだけに対する一byte差替え結果。
	CloseHandle( tamperFile) ;
	// 指定した改変byteを書き込めなければ、改変拒否を確認したとは扱わない。
	if( writeResult == FALSE || written != sizeof( REPLACEMENT_BYTE)) {
		std::wprintf( L"Silicon Labs CP210x tamper test could not modify the member.\n") ;
		return 1 ;
	}

	error = drivercrate::reverifySiliconLabsSerialInfPackage(
		workspace, contents.entries, package) ;	// 差替え後に期待する拒否結果。
	// 変更したmemberの再検証が成功したら、内容の改変を見逃す退行として失敗にする。
	if( error == 0) {
		std::wprintf( L"Silicon Labs CP210x accepted a modified member.\n") ;
		return 1 ;
	}

	std::wprintf( L"Silicon Labs CP210x verification succeeded: %zu INF, %zu selected files.\n",
				 contents.packages.size(), contents.entries.size()) ;
	return 0 ;
}
