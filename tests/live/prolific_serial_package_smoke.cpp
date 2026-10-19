//------------------------------------------------------------------------------
/**
 * @file prolific_serial_package_smoke.cpp
 * @brief Prolific Serial公式ZIP読み取り専用live検証。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  公式候補PID境界の集計診断追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 利用者がProlific公式pageから取得したZIPを変更せず検査します。Path、PnP ID、title、payload内容を出力せず、driver installもしません。
 */
//------------------------------------------------------------------------------

#include "platform/official_download_workspace.h"
#include "platform/prolific_serial_package.h"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <string>

//------------------------------------------------------------------------------
/**
 * @brief Prolific Serial公式ZIPのread-only live検証を実行する。
 *
 * Production共通componentで外側・内側ZIP、INF、CAT、publisher、OS、x64を検証し、件数だけを表示する。
 *
 * @param[in] argumentCount 実行file名を含むargument数。
 * @param[in] arguments 一件の利用者指定Prolific公式ZIP path。
 * @return 全package検証・再検証成功時0、失敗時1、引数不正時2。
 */
//------------------------------------------------------------------------------
int wmain( const int argumentCount, wchar_t *arguments[])
{
	// 検証対象ZIPを一件だけ明示させ、引数の欠落時には実fileを処理しない。
	if( argumentCount != 2 || arguments == nullptr || arguments[1] == nullptr ||
	   arguments[1][0] == L'\0') {
		std::wprintf( L"Usage: prolific_serial_package_smoke <official-driver-zip>\n") ;
		return 2 ;
	}

	drivercrate::OfficialDownloadWorkspace	   workspace ;	// 検証用複製・展開fileの所有領域。
	drivercrate::ProlificSerialPackageContents contents ;	// 検証済みpackage metadata。
	drivercrate::NativeError error = drivercrate::inspectProlificSerialPackageFile(
		arguments[1], 1, workspace, contents) ;	// Production共通検証結果。
	// 実packageを一件以上検証できた場合だけ、ZIP検証経路を合格とする。
	if( error != 0 || contents.packages.empty()) {
		std::wprintf( L"Prolific Serial package verification failed: 0x%08X, stage %u\n",
					 static_cast<unsigned int>( error),
					 static_cast<unsigned int>( contents.verificationStage)) ;
		return 1 ;
	}

	std::size_t acceptedIdCount{} ;	// 公式候補の標準PID条件を満たすcatalog側ID数。
	std::size_t excludedIdCount{} ;	// 内容署名とは別に候補化対象外となるcatalog側ID数。
	// Scan後の差替えを想定し、全INFをinstall直前と同じ規則で再検証する。
	for( const drivercrate::OfficialInfPackage &package : contents.packages) {
		// 署名済みcatalog側IDのうち、既存の候補化条件へ完全一致する数。
		const auto accepted =
			std::ranges::count_if( package.hardwareIds, []( const std::wstring &id) {
				return drivercrate::isProlificSerialCandidateHardwareId( id) ;
			}) ;
		// ID本文を診断へ出さず、署名済みINFに候補対象外IDが含まれるかだけを示す。
		acceptedIdCount += static_cast<std::size_t>( accepted) ;
		excludedIdCount += package.hardwareIds.size() - static_cast<std::size_t>( accepted) ;
		error = drivercrate::reverifyProlificSerialInfPackage( workspace, contents.entries, package) ;
		// 展開後の再検証が失敗した場合は、初回検証の成功だけで試験を合格にしない。
		if( error != 0) {
			std::wprintf( L"Prolific Serial package re-verification failed: 0x%08X\n",
						 static_cast<unsigned int>( error)) ;
			return 1 ;
		}
	}

	std::wprintf( L"Prolific Serial package verification succeeded: %zu INF package(s), "
				 L"accepted IDs %zu, excluded IDs %zu.\n",
				 contents.packages.size(), acceptedIdCount, excludedIdCount) ;
	return 0 ;
}
