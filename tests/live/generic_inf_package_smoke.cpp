//------------------------------------------------------------------------------
/**
 * @file generic_inf_package_smoke.cpp
 * @brief 汎用署名済みINF ZIP読み取り専用live検証。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Mixed ZIP拒否試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 公式CP210x packageからdriver-onlyの3 fileだけを再梱包した試験ZIPを汎用production検証器へ渡します。Network、download、
 *       installは行いません。
 */
//------------------------------------------------------------------------------

#include "platform/generic_inf_package.h"
#include "platform/official_download_workspace.h"

#include <Windows.h>

#include <cstdio>
#include <string>

//------------------------------------------------------------------------------
/**
 * @brief 汎用署名済みINF ZIPのproduction検証を実行する。
 *
 * Provider名を事前allowlistへ固定せず、Ports class、WHCP signer、CAT member、4要素版、PnP IDをproduction codeで検証する。第2
 * 引数がある場合はmixed ZIPの拒否も確認する。
 *
 * @param[in] argumentCount 実行file名を含むargument数。
 * @param[in] arguments 第1引数はdriver-only CP210x ZIP path。第2引数は任意の拒否対象mixed ZIP path。
 * @return Package検証と差替え拒否成功時0、失敗時1、引数不正時2。
 */
//------------------------------------------------------------------------------
int wmain( const int argumentCount, wchar_t *arguments[])
{
	// 検証するZIPと任意の拒否試験ZIPだけを受け付け、引数不備では実fileを処理しない。
	if( (argumentCount != 2 && argumentCount != 3) || arguments == nullptr ||
	   arguments[1] == nullptr || arguments[1][0] == L'\0') {
		std::wprintf( L"Usage: generic_inf_package_smoke <driver-only-zip> [rejected-mixed-zip]\n") ;
		return 2 ;
	}

	// 追加の混在ZIPが明示された場合だけ、そのpackageを拒否できるか検証する。
	if( argumentCount == 3) {
		// 任意の拒否試験を指定したのにpathが欠ける場合は、試験済みとせず使用法エラーにする。
		if( arguments[2] == nullptr || arguments[2][0] == L'\0') {
			std::wprintf( L"Rejected mixed ZIP path is empty.\n") ;
			return 2 ;
		}

		drivercrate::OfficialDownloadWorkspace rejectedWorkspace ;	// 拒否対象の展開領域。
		drivercrate::GenericInfPackageContents rejectedContents ;	// 拒否対象の検証結果。
		const drivercrate::NativeError rejectedError = drivercrate::inspectGenericInfPackageFile(
			arguments[2], 12, rejectedWorkspace,
			rejectedContents) ;	// Mixed packageに期待する拒否結果。
		// 混在packageの誤受入れ、または検証完了への誤昇格をlive試験の失敗とする。
		if( rejectedError == 0 ||
		   rejectedContents.verificationStage ==
			   drivercrate::UserSelectedInfPackageVerificationStage::COMPLETED) {
			std::wprintf( L"Generic INF verifier accepted a mixed package.\n") ;
			return 1 ;
		}
	}

	drivercrate::OfficialDownloadWorkspace workspace ;	// 選択ZIPと展開fileの所有領域。
	drivercrate::GenericInfPackageContents contents ;	// 汎用検証済みpackage metadata。
	drivercrate::NativeError			   error = drivercrate::inspectGenericInfPackageFile(
		  arguments[1], 11, workspace, contents) ;	// Production汎用検証結果。
	// 全検証段階と期待した閉包・package件数がそろった場合だけ正常fixtureを合格とする。
	if( error != 0 ||
	   contents.verificationStage !=
		   drivercrate::UserSelectedInfPackageVerificationStage::COMPLETED ||
	   contents.entries.size() != 3U || contents.packages.size() != 1U) {
		std::wprintf( L"Generic INF verification failed: 0x%08X, stage %u\n",
					 static_cast<unsigned int>( error),
					 static_cast<unsigned int>( contents.verificationStage)) ;
		return 1 ;
	}

	const drivercrate::OfficialInfPackage &package = contents.packages.front() ;	// CP210x INF。
	// 代表packageのclass・publisher・版・ID数を照合し、異なる内容での見かけの合格を防ぐ。
	if( package.className != L"Ports" || package.providerName != L"Silicon Laboratories Inc." ||
	   package.driverVersion != L"11.5.0.417" || package.hardwareIds.size() != 14U) {
		std::wprintf( L"Generic INF metadata boundary failed.\n") ;
		return 1 ;
	}

	error = drivercrate::reverifyGenericInfPackage( workspace, contents.entries,
												   package) ;	// Install直前相当の再検証結果。
	// 未改変packageの再検証が失敗した場合は、改変検出試験へ進めない。
	if( error != 0) {
		std::wprintf( L"Generic INF re-verification failed: 0x%08X\n",
					 static_cast<unsigned int>( error)) ;
		return 1 ;
	}

	const std::wstring tamperPath =
		// 保護workspace内だけの差替え対象。
		workspace.path( L"x64\\silabser.sys") ;
	const HANDLE tamperFile =
		CreateFileW( tamperPath.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
					nullptr) ;	// Scope内で閉じる差替え試験handle。
	// 改変用の展開memberを開けない場合は、改変拒否を確認したと報告しない。
	if( tamperFile == INVALID_HANDLE_VALUE) {
		std::wprintf( L"Generic INF tamper test could not open the member.\n") ;
		return 1 ;
	}

	constexpr BYTE REPLACEMENT_BYTE = 0U ;	// PE header先頭を変更する置換byte。
	DWORD		   written{} ;				// WriteFileが変更したbyte数。
	const BOOL	   writeResult =
		WriteFile( tamperFile, &REPLACEMENT_BYTE, sizeof( REPLACEMENT_BYTE), &written,
				  nullptr) ;	// 保護workspaceだけを変更する試験結果。
	CloseHandle( tamperFile) ;
	// 試験用の変更を書き込めなかった場合は、改変されたという前提で検証を続けない。
	if( writeResult == FALSE || written != sizeof( REPLACEMENT_BYTE)) {
		std::wprintf( L"Generic INF tamper test could not modify the member.\n") ;
		return 1 ;
	}

	error = drivercrate::reverifyGenericInfPackage( workspace, contents.entries,
												   package) ;	// 差替え後に期待する拒否結果。
	// 変更済みmemberの再検証が成功したら、閉包の改変を見逃す退行として失敗にする。
	if( error == 0) {
		std::wprintf( L"Generic INF verifier accepted a modified member.\n") ;
		return 1 ;
	}

	std::wprintf( L"Generic INF verification succeeded: %zu INF, %zu files.\n",
				 contents.packages.size(), contents.entries.size()) ;
	return 0 ;
}
