//------------------------------------------------------------------------------
/**
 * @file wch_serial_package_smoke.cpp
 * @brief WCH CH341SER公式ZIP読み取り専用live検証。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  署名失敗のmember診断追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Scan後差替え拒否試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 利用者がWCH公式pageから取得したCH341SER.ZIPを変更せず検査します。選択外EXEを展開せず、Path、PnP ID、payload内容、driverを出力しません。
 */
//------------------------------------------------------------------------------

#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "platform/wch_serial_package.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <string>
#include <string_view>

namespace {

constexpr std::array ACCEPTED_SIGNERS{
	// 許可signer。
	std::wstring_view( L"Microsoft Windows Hardware Compatibility Publisher")} ;
constexpr std::array SIGNED_MEMBER_NAMES{
	std::wstring_view( L"CH341M64.sys"), std::wstring_view( L"CH341PORTS.DLL"),
	std::wstring_view( L"CH341PORTSA64.DLL"), std::wstring_view( L"CH341PT.DLL"),
	std::wstring_view( L"CH341PTA64.DLL"), std::wstring_view( L"CH341S64.sys"),
	// 公式ZIP内で埋込み署名を持つ固定member名群。
	std::wstring_view( L"CH341SER.sys")} ;

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief WCH CH341SER公式ZIPのread-only live検証を実行する。
 *
 * Production共通componentでZIP全体を事前検査し、現行subtree、INF、CAT、全参照file、publisher、x64を検証する。
 *
 * @param[in] argumentCount 実行file名を含むargument数。
 * @param[in] arguments 一件の利用者指定WCH公式ZIP path。
 * @return 選択package検証・再検証成功時0、失敗時1、引数不正時2。
 */
//------------------------------------------------------------------------------
int wmain( const int argumentCount, wchar_t *arguments[])
{
	// CH341SERのZIPを一件だけ明示させ、引数不備では実fileを検証しない。
	if( argumentCount != 2 || arguments == nullptr || arguments[1] == nullptr ||
	   arguments[1][0] == L'\0') {
		std::wprintf( L"Usage: wch_serial_package_smoke <official-ch341ser-zip>\n") ;
		return 2 ;
	}

	drivercrate::OfficialDownloadWorkspace workspace ;	// 選択展開fileの所有領域。
	drivercrate::WchSerialPackageContents  contents ;	// 検証済みpackage metadata。
	drivercrate::NativeError			   error = drivercrate::inspectWchSerialPackageFile(
		  arguments[1], 1, workspace, contents) ;	// Production共通検証結果。
	// package検証が成立しなければ固定memberの署名診断を補い、部分成功を合格にしない。
	if( error != 0 || contents.packages.size() != 1U) {
		std::wprintf( L"WCH package verification failed: 0x%08X, stage %u\n",
					 static_cast<unsigned int>( error),
					 static_cast<unsigned int>( contents.verificationStage)) ;
		// 固定memberだけを再検証し、端末情報や選択pathを出さず署名失敗箇所を診断する。
		for( const std::wstring_view memberName : SIGNED_MEMBER_NAMES) {
			std::wstring relativePath = L"CH341SER\\WIN 1X\\" ;	// 固定subtree内相対path。
			relativePath.append( memberName) ;
			const std::wstring path = workspace.path( relativePath) ;	// 診断対象の保護file path。
			const drivercrate::NativeError memberError =
				// 署名結果。
				drivercrate::verifyAuthenticodePublisher( path, ACCEPTED_SIGNERS) ;
			std::wprintf( L"  fixed member %.*ls: 0x%08X\n", static_cast<int>( memberName.size()),
						 memberName.data(), static_cast<unsigned int>( memberError)) ;
		}

		return 1 ;
	}

	constexpr std::wstring_view SELECTED_PREFIX =
		L"CH341SER\\WIN 1X\\" ;	// Production policyが選択する固定path prefix。
	// 選択外EXEや旧Windows fileが検証済みentryへ混入していないことを確認する。
	for( const drivercrate::OfficialZipEntry &entry : contents.entries) {
		// 選択subtree外やEXEの展開とhash欠落を検出し、driver-onlyの選択境界を確認する。
		if( !entry.relativePath.starts_with( SELECTED_PREFIX) ||
		   entry.relativePath.ends_with( L".exe") || entry.relativePath.ends_with( L".EXE") ||
		   entry.sha256.size() != 64U) {
			std::wprintf( L"WCH package selection boundary failed.\n") ;
			return 1 ;
		}
	}

	// Scan後の差替えを想定し、INFをinstall直前と同じ規則で再検証する。
	error = drivercrate::reverifyWchSerialInfPackage( workspace, contents.entries,
													 contents.packages.front()) ;
	// 改変前の再検証が成立しない場合は、改変拒否の試験へ進めない。
	if( error != 0) {
		std::wprintf( L"WCH package re-verification failed: 0x%08X\n",
					 static_cast<unsigned int>( error)) ;
		return 1 ;
	}

	const std::wstring tamperPath =
		// 一時workspace内の試験対象。
		workspace.path( L"CH341SER\\WIN 1X\\CH341S64.sys") ;
	const HANDLE tamperFile =
		CreateFileW( tamperPath.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
					nullptr) ;	// Test終了時にworkspaceと共に破棄するfile handle。
	// 固定memberを開けなければ、変更済みという前提で試験を続けない。
	if( tamperFile == INVALID_HANDLE_VALUE) {
		std::wprintf( L"WCH tamper test could not open the fixed member.\n") ;
		return 1 ;
	}

	constexpr BYTE REPLACEMENT_BYTE = 0U ;	// PE headerの先頭を確実に変える置換byte。
	DWORD		   written{} ;				// WriteFileが実際に変更したbyte数。
	const BOOL	   writeResult =
		WriteFile( tamperFile, &REPLACEMENT_BYTE, sizeof( REPLACEMENT_BYTE), &written,
				  nullptr) ;	// 保護workspaceだけに対する1 byte差替え結果。
	CloseHandle( tamperFile) ;
	// 指定した改変を書き込めなかった場合は、改変検出を確認済みにしない。
	if( writeResult == FALSE || written != sizeof( REPLACEMENT_BYTE)) {
		std::wprintf( L"WCH tamper test could not modify the fixed member.\n") ;
		return 1 ;
	}

	error = drivercrate::reverifyWchSerialInfPackage( workspace, contents.entries,
													 contents.packages.front()) ;
	// 変更されたmemberの誤受入れを、再検証の退行として報告する。
	if( error == 0) {
		std::wprintf( L"WCH package re-verification accepted a modified member.\n") ;
		return 1 ;
	}

	std::wprintf( L"WCH package verification succeeded: %zu INF package(s), %zu selected files.\n",
				 contents.packages.size(), contents.entries.size()) ;
	return 0 ;
}
