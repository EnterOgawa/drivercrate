//------------------------------------------------------------------------------
/**
 * @file asrock_system_identity_tests.cpp
 * @brief ASRock local system識別単体試験実装。
 * @version 01.00.00
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 実registryやnetworkへ接続せず、架空の非機密表示値だけを使用します。
 */
//------------------------------------------------------------------------------

#include "asrock_system_identity_tests.h"

#include "platform/asrock_system_identity.h"
#include "test_framework.h"

#include <string>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 内部試験関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief ASRock baseboard要求を検証する。
 *
 * Custom PC相当ではboard modelを選び固定URLだけを使用する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testAsrockBaseboard( TestContext &context)
{
	AsrockCatalogRequest request ;		// 構築した固定一覧要求。
	bool				 applicable{} ;	// ASRock clientの判定結果。
	DRIVERCRATE_EXPECT( context, makeAsrockCatalogRequest(
									L"System manufacturer", L"System Product Name", L"ASRock",
									L"B650M Pro RS WiFi", 26'100U, false, request, applicable)) ;
	DRIVERCRATE_EXPECT( context, applicable) ;
	DRIVERCRATE_EXPECT( context, request.boardModel == L"B650M Pro RS WiFi") ;
	DRIVERCRATE_EXPECT( context, request.osName == L"Windows 11 64bit") ;
	DRIVERCRATE_EXPECT( context,
					   request.pageUrl == L"https://www.asrock.com/support/index.asp?cat=Drivers") ;
	DRIVERCRATE_EXPECT( context, request.pageUrl.find( request.boardModel) == std::wstring::npos) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASRock system productのfallbackを検証する。
 *
 * Baseboard値欠損時だけASRock system productを使用する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testAsrockSystemProduct( TestContext &context)
{
	AsrockCatalogRequest request ;		// 構築した固定一覧要求。
	bool				 applicable{} ;	// ASRock clientの判定結果。
	DRIVERCRATE_EXPECT( context, makeAsrockCatalogRequest( L"ASRock Inc.", L"Fictional Mini PC", L"",
														 L"", 19'045U, false, request, applicable)) ;
	DRIVERCRATE_EXPECT( context, applicable) ;
	DRIVERCRATE_EXPECT( context, request.boardModel == L"Fictional Mini PC") ;
	DRIVERCRATE_EXPECT( context, request.osName == L"Windows 10 64bit") ;
}

//------------------------------------------------------------------------------
/**
 * @brief 対象外systemを検証する。
 *
 * 他社端末とWindows Serverでは固定一覧を取得しない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testNotApplicableSystems( TestContext &context)
{
	AsrockCatalogRequest request ;			// 各対象外判定後の空要求。
	bool				 applicable{true} ;	// 呼出しでfalseへ更新される対象。
	DRIVERCRATE_EXPECT( context, makeAsrockCatalogRequest( L"Fictional Systems", L"Model 1",
														 L"Fictional Boards", L"Board 1", 26'100U,
														 false, request, applicable)) ;
	DRIVERCRATE_EXPECT( context, !applicable) ;
	DRIVERCRATE_EXPECT( context, request.pageUrl.empty()) ;

	DRIVERCRATE_EXPECT( context, makeAsrockCatalogRequest( L"ASRock", L"Server Model", L"ASRock",
														 L"Server Board", 26'100U, true, request,
														 applicable)) ;
	DRIVERCRATE_EXPECT( context, !applicable) ;
	DRIVERCRATE_EXPECT( context, request.pageUrl.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不正ASRock識別値を検証する。
 *
 * Generic／Unicode modelと未対応buildをfail-closedにする。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testInvalidAsrockValues( TestContext &context)
{
	AsrockCatalogRequest request ;			// 拒否後に空であるべき要求。
	bool				 applicable{true} ;	// 拒否時にfalseであるべき状態。
	DRIVERCRATE_EXPECT( context, !makeAsrockCatalogRequest( L"ASRock", L"System Product Name",
														  L"ASRock", L"Default string", 26'100U,
														  false, request, applicable)) ;
	DRIVERCRATE_EXPECT( context, !applicable) ;

	DRIVERCRATE_EXPECT( context, !makeAsrockCatalogRequest( L"", L"", L"ASRock", L"Board 日本語",
														  26'100U, false, request, applicable)) ;
	DRIVERCRATE_EXPECT( context, !applicable) ;

	DRIVERCRATE_EXPECT( context, !makeAsrockCatalogRequest( L"", L"", L"ASRock", L"Board 1", 9'999U,
														  false, request, applicable)) ;
	DRIVERCRATE_EXPECT( context, !applicable) ;

	DRIVERCRATE_EXPECT( context, makeAsrockCatalogRequest( L"ASRock日本", L"Model 1", L"", L"",
														 26'100U, false, request, applicable)) ;
	DRIVERCRATE_EXPECT( context, !applicable) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/asrock_system_identity_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runAsrockSystemIdentityTests( TestContext &context)
{
	testAsrockBaseboard( context) ;
	testAsrockSystemProduct( context) ;
	testNotApplicableSystems( context) ;
	testInvalidAsrockValues( context) ;
}

} // namespace drivercrate::test
