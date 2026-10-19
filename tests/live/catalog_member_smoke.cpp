//------------------------------------------------------------------------------
/**
 * @file catalog_member_smoke.cpp
 * @brief Catalog member読み取り専用live検証。
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
 * @note 利用者が指定したCATとmemberを変更せず、Windows trust検証だけを行います。Pathやdevice情報は出力せず、成功可否と診断codeだけを表示します。
 */
//------------------------------------------------------------------------------

#include "platform/official_file_verifier.h"

#include <cstdio>
#include <span>
#include <string>
#include <vector>

//------------------------------------------------------------------------------
/**
 * @brief Catalog member live検証を実行する。
 *
 * 実driverを導入せず、指定fileのcatalog membershipとtrustをproduction共通componentで読み取り専用検証する。
 *
 * @param[in] argumentCount 実行file名を含むargument数。
 * @param[in] arguments CAT pathと一つ以上のmember path。
 * @return 検証成功時0、検証失敗時1、引数不正時2。
 */
//------------------------------------------------------------------------------
int wmain( const int argumentCount, wchar_t *arguments[])
{
	// catalogと比較memberが指定されていない場合は、実fileの検証を開始しない。
	if( argumentCount < 3 || arguments == nullptr) {
		std::wprintf( L"Usage: catalog_member_smoke <catalog> <member> [member...]\n") ;
		return 2 ;
	}

	std::vector<std::wstring> memberPaths ;	// 検証対象memberの絶対path群。
	memberPaths.reserve( static_cast<std::size_t>( argumentCount - 2)) ;
	// 実行file名とCAT pathを除く全argumentをmemberとして保持する。
	for( int index = 2; index < argumentCount; ++index) {
		// 欠落したmember引数をAPIへ渡さず、呼出し方法の誤りとして終了する。
		if( arguments[index] == nullptr) {
			return 2 ;
		}

		memberPaths.emplace_back( arguments[index]) ;
	}

	const drivercrate::NativeError error = drivercrate::verifyOfficialCatalogMembers(
		arguments[1], std::span<const std::wstring>( memberPaths)) ;	// Trust検証結果。
	// member検証の失敗を診断値付きで報告し、署名検証が成立したとは扱わない。
	if( error != 0) {
		std::wprintf( L"Catalog member verification failed: 0x%08X\n",
					 static_cast<unsigned int>( error)) ;
		return 1 ;
	}

	std::wprintf( L"Catalog member verification succeeded.\n") ;
	return 0 ;
}
