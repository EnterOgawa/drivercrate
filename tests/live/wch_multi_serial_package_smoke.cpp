//------------------------------------------------------------------------------
/**
 * @file wch_multi_serial_package_smoke.cpp
 * @brief WCH CH343SER公式ZIP読み取り専用live検証。
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
 * @note 利用者がWCH公式pageから取得したCH343SER.ZIPを変更せず検査します。選択外EXE／libraryを展開せず、Path、PnP ID、payloadを出力しません。
 */
//------------------------------------------------------------------------------

#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "platform/wch_serial_package.h"

#include <Windows.h>

#include <array>
#include <cstdio>
#include <string>
#include <string_view>

namespace {

constexpr std::array ACCEPTED_SIGNERS{
	// 許可signer。
	std::wstring_view( L"Microsoft Windows Hardware Compatibility Publisher")} ;
constexpr std::array SIGNED_MEMBER_NAMES{
	std::wstring_view( L"CH343M64.sys"), std::wstring_view( L"CH343PORTS.dll"),
	std::wstring_view( L"CH343PORTSA64.dll"), std::wstring_view( L"CH343PT.DLL"),
	std::wstring_view( L"CH343PTA64.DLL"), std::wstring_view( L"CH343S64.sys"),
	// 固定subtree内で署名を持つmember名群。
	std::wstring_view( L"CH343SER.sys")} ;

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief WCH CH343SER公式ZIPのread-only live検証を実行する。
 *
 * Production共通componentで固定archive、x64 INF、署名を検証し、保護workspaceの一byte差替えも拒否させる。
 *
 * @param[in] argumentCount 実行file名を含むargument数。
 * @param[in] arguments 一件の利用者指定WCH公式ZIP path。
 * @return 選択package検証・再検証成功時0、失敗時1、引数不正時2。
 */
//------------------------------------------------------------------------------
int wmain( const int argumentCount, wchar_t *arguments[])
{
	// CH343SERのZIPを一件だけ明示させ、引数不備では実fileを処理しない。
	if( argumentCount != 2 || arguments == nullptr || arguments[1] == nullptr ||
	   arguments[1][0] == L'\0') {
		std::wprintf( L"Usage: wch_multi_serial_package_smoke <official-ch343ser-zip>\n") ;
		return 2 ;
	}

	drivercrate::OfficialDownloadWorkspace workspace ;	// 選択展開fileの所有領域。
	drivercrate::WchSerialPackageContents  contents ;	// 検証済みpackage metadata。
	drivercrate::NativeError			   error = drivercrate::inspectWchMultiSerialPackageFile(
		  arguments[1], 1, workspace, contents) ;	// Production共通検証結果。
	// package検証に失敗した場合は固定memberの診断だけを補い、不完全な監査を合格にしない。
	if( error != 0 || contents.packages.size() != 1U) {
		std::wprintf( L"WCH CH343SER verification failed: 0x%08X, stage %u\n",
					 static_cast<unsigned int>( error),
					 static_cast<unsigned int>( contents.verificationStage)) ;
		// 固定memberだけを再検証し、端末情報を出さず署名失敗箇所を診断する。
		for( const std::wstring_view memberName : SIGNED_MEMBER_NAMES) {
			std::wstring relativePath = L"CH343SER\\Driver\\WIN 1X\\" ;	// 固定subtree内相対path。
			relativePath.append( memberName) ;
			const std::wstring			   path = workspace.path( relativePath) ;	// 保護file path。
			const drivercrate::NativeError memberError =
				// 署名結果。
				drivercrate::verifyAuthenticodePublisher( path, ACCEPTED_SIGNERS) ;
			std::wprintf( L"  fixed member %.*ls: 0x%08X\n", static_cast<int>( memberName.size()),
						 memberName.data(), static_cast<unsigned int>( memberError)) ;
		}

		return 1 ;
	}

	constexpr std::wstring_view SELECTED_PREFIX =
		L"CH343SER\\Driver\\WIN 1X\\" ;	// Production policyの固定path prefix。
	// 選択外EXE／libraryや未hash entryが検証結果へ混入していないことを確認する。
	for( const drivercrate::OfficialZipEntry &entry : contents.entries) {
		// 選択subtree外やEXE・LIBの混入とhash欠落を検出し、driver閉包の境界を確認する。
		if( !entry.relativePath.starts_with( SELECTED_PREFIX) ||
		   entry.relativePath.ends_with( L".exe") || entry.relativePath.ends_with( L".EXE") ||
		   entry.relativePath.ends_with( L".lib") || entry.relativePath.ends_with( L".LIB") ||
		   entry.sha256.size() != 64U) {
			std::wprintf( L"WCH CH343SER package selection boundary failed.\n") ;
			return 1 ;
		}
	}

	error = drivercrate::reverifyWchMultiSerialInfPackage(
		workspace, contents.entries, contents.packages.front()) ;	// Install直前相当の再検証。
	// 展開後の再検証が成立しなければ、改変試験の前提が満たせないため中止する。
	if( error != 0) {
		std::wprintf( L"WCH CH343SER re-verification failed: 0x%08X\n",
					 static_cast<unsigned int>( error)) ;
		return 1 ;
	}

	const std::wstring tamperPath =
		// 一時workspace内の試験対象。
		workspace.path( L"CH343SER\\Driver\\WIN 1X\\CH343S64.sys") ;
	const HANDLE tamperFile =
		CreateFileW( tamperPath.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
					nullptr) ;	// Test終了時にworkspaceと共に破棄するfile handle。
	// 固定memberを変更用に開けなかった場合は、改変検出を確認済みにしない。
	if( tamperFile == INVALID_HANDLE_VALUE) {
		std::wprintf( L"WCH CH343SER tamper test could not open the fixed member.\n") ;
		return 1 ;
	}

	constexpr BYTE REPLACEMENT_BYTE = 0U ;	// PE headerの先頭を確実に変える置換byte。
	DWORD		   written{} ;				// WriteFileが実際に変更したbyte数。
	const BOOL	   writeResult =
		WriteFile( tamperFile, &REPLACEMENT_BYTE, sizeof( REPLACEMENT_BYTE), &written,
				  nullptr) ;	// 保護workspaceだけに対する一byte差替え結果。
	CloseHandle( tamperFile) ;
	// 変更を全byte書き込めない場合は、改変後の検証を行ったと扱わない。
	if( writeResult == FALSE || written != sizeof( REPLACEMENT_BYTE)) {
		std::wprintf( L"WCH CH343SER tamper test could not modify the fixed member.\n") ;
		return 1 ;
	}

	error = drivercrate::reverifyWchMultiSerialInfPackage(
		workspace, contents.entries, contents.packages.front()) ;	// 差替え後の拒否結果。
	// 改変されたmemberを受理する結果は、閉包整合性の退行として拒否する。
	if( error == 0) {
		std::wprintf( L"WCH CH343SER accepted a modified member.\n") ;
		return 1 ;
	}

	std::wprintf( L"WCH CH343SER verification succeeded: %zu INF package(s), %zu selected files.\n",
				 contents.packages.size(), contents.entries.size()) ;
	return 0 ;
}
