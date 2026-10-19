//------------------------------------------------------------------------------
/**
 * @file asus_system_identity_tests.cpp
 * @brief ASUS local system識別単体試験実装。
 * @version 01.02.00
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
 * Ver.01.01.00 Shunji Ogawa  2026/09/20  Registry確保容量と実size差の回帰を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/24  公開model明示の正規pageと拒否条件を検証。
 * </pre>
 *
 * @note 実registryやnetworkへ接続せず、架空の非機密表示値だけを使用します。
 */
//------------------------------------------------------------------------------

#include "asus_system_identity_tests.h"

#include "platform/asus_system_identity.h"
#include "test_framework.h"

#include <array>
#include <string>

namespace drivercrate::test {
namespace {

/**
 * @brief API返却sizeと確保容量の差、および不正文字列の拒否を再現する。
 * @param[in,out] context Assertion集計先。
 */
void testRegistryReturnedSize( TestContext &context)
{
	const std::array<wchar_t, 6> buffer{L'A', L'S', L'U', L'S', L'\0', L'\0'} ;	// 架空取得値と余白。
	std::wstring				 value = L"stale" ;								// 成否ごとの出力確認先。
	DRIVERCRATE_EXPECT( context, decodeAsusRegistryString( buffer, 10U, value)) ;
	DRIVERCRATE_EXPECT( context, value == L"ASUS") ;
	DRIVERCRATE_EXPECT( context, !decodeAsusRegistryString( buffer, 12U, value)) ;
	DRIVERCRATE_EXPECT( context, value.empty()) ;
	DRIVERCRATE_EXPECT( context, !decodeAsusRegistryString( buffer, 0U, value)) ;
	DRIVERCRATE_EXPECT( context, !decodeAsusRegistryString( buffer, 9U, value)) ;
	DRIVERCRATE_EXPECT( context, !decodeAsusRegistryString( buffer, 14U, value)) ;
	DRIVERCRATE_EXPECT( context, !decodeAsusRegistryString( buffer, 8U, value)) ;
	DRIVERCRATE_EXPECT( context, !decodeAsusRegistryString( buffer, 32'770U, value)) ;
	const std::array<wchar_t, 1> empty{L'\0'} ;	// 空REG_SZは任意値として許可する。
	DRIVERCRATE_EXPECT( context, decodeAsusRegistryString( empty, 2U, value)) ;
	DRIVERCRATE_EXPECT( context, value.empty()) ;
	const std::array<wchar_t, 4> embedded{L'A', L'\0', L'B', L'\0'} ;	// 途中NUL後の文字を隠さない。
	DRIVERCRATE_EXPECT( context, !decodeAsusRegistryString( embedded, 8U, value)) ;
	const std::array<wchar_t, 7> dirtyTail{L'A',  L'S', L'U', L'S',
										   L'\0', L'X', L'Y'} ;	// 範囲外は本文でない。
	DRIVERCRATE_EXPECT( context, decodeAsusRegistryString( dirtyTail, 10U, value)) ;
	DRIVERCRATE_EXPECT( context, value == L"ASUS") ;
	const std::wstring maximum( 16'384U, L'\0') ;	// 最大容量でも途中NULは拒否する。
	DRIVERCRATE_EXPECT( context, !decodeAsusRegistryString( maximum, 32'768U, value)) ;
}

//------------------------------------------------------------------------------
// 内部試験関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief ASUS system model要求を検証する。
 *
 * ASUS notebook相当ではsystem modelとWindows 11を選ぶ。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testAsusSystemModel( TestContext &context)
{
	AsusSupportPageRequest request ;		// 構築した公式page要求。
	bool				   applicable{} ;	// ASUS clientの判定結果。
	DRIVERCRATE_EXPECT( context, makeAsusSupportPageRequest(
									L"ASUSTeK COMPUTER INC.", L"H7600ZW", L"ASUSTeK COMPUTER INC.",
									L"Fictional Board", 26'100U, false, request, applicable)) ;
	DRIVERCRATE_EXPECT( context, applicable) ;
	DRIVERCRATE_EXPECT( context, request.model == L"H7600ZW") ;
	DRIVERCRATE_EXPECT( context, request.osName == L"Windows 11 64-bit") ;
	DRIVERCRATE_EXPECT( context, request.pageUrl ==
									L"https://www.asus.com/supportonly/h7600zw/helpdesk_download/") ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASUS baseboard model要求を検証する。
 *
 * 自作PC相当ではboard modelを選び予約文字をdata化する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testAsusBaseboardModel( TestContext &context)
{
	AsusSupportPageRequest request ;		// 構築した公式page要求。
	bool				   applicable{} ;	// ASUS clientの判定結果。
	DRIVERCRATE_EXPECT( context, makeAsusSupportPageRequest(
									L"System manufacturer", L"System Product Name", L"ASUS",
									L"PRIME B760-PLUS D4", 19'045U, false, request, applicable)) ;
	DRIVERCRATE_EXPECT( context, applicable) ;
	DRIVERCRATE_EXPECT( context, request.model == L"PRIME B760-PLUS D4") ;
	DRIVERCRATE_EXPECT( context, request.osName == L"Windows 10 64-bit") ;
	DRIVERCRATE_EXPECT(
		context, request.pageUrl ==
					 L"https://www.asus.com/supportonly/prime%20b760-plus%20d4/helpdesk_download/") ;
}

//------------------------------------------------------------------------------
/**
 * @brief 対象外systemを検証する。
 *
 * 他社端末とWindows Serverではrequestを構築しない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testNotApplicableSystems( TestContext &context)
{
	AsusSupportPageRequest request ;			// 各対象外判定後の空要求。
	bool				   applicable{true} ;	// 呼出しでfalseへ更新される対象。
	DRIVERCRATE_EXPECT( context, makeAsusSupportPageRequest( L"Fictional Systems", L"Model 1",
														   L"Fictional Boards", L"Board 1", 26'100U,
														   false, request, applicable)) ;
	DRIVERCRATE_EXPECT( context, !applicable) ;
	DRIVERCRATE_EXPECT( context, request.pageUrl.empty()) ;

	DRIVERCRATE_EXPECT( context, makeAsusSupportPageRequest( L"ASUS", L"Server Model", L"ASUS",
														   L"Server Board", 26'100U, true, request,
														   applicable)) ;
	DRIVERCRATE_EXPECT( context, !applicable) ;
	DRIVERCRATE_EXPECT( context, request.pageUrl.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不正ASUS識別値を検証する。
 *
 * Generic／Unicode modelと未対応buildをfail-closedにする。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testInvalidAsusValues( TestContext &context)
{
	AsusSupportPageRequest request ;			// 拒否後に空であるべき要求。
	bool				   applicable{true} ;	// 拒否時にfalseであるべき状態。
	DRIVERCRATE_EXPECT( context, !makeAsusSupportPageRequest( L"ASUS", L"System Product Name",
															L"ASUS", L"Default string", 26'100U,
															false, request, applicable)) ;
	DRIVERCRATE_EXPECT( context, !applicable) ;

	DRIVERCRATE_EXPECT( context, !makeAsusSupportPageRequest( L"ASUS", L"Model 日本語", L"", L"",
															26'100U, false, request, applicable)) ;
	DRIVERCRATE_EXPECT( context, !applicable) ;

	DRIVERCRATE_EXPECT( context, !makeAsusSupportPageRequest( L"ASUS", L"Model 1", L"", L"", 9'999U,
															false, request, applicable)) ;
	DRIVERCRATE_EXPECT( context, !applicable) ;

	DRIVERCRATE_EXPECT( context, !makeAsusSupportPageRequest( L"ASUS", L"System Product Name",
															L"Fictional Boards", L"Model 1",
															26'100U, false, request, applicable)) ;
	DRIVERCRATE_EXPECT( context, !applicable) ;

	DRIVERCRATE_EXPECT( context, makeAsusSupportPageRequest( L"ASUS日本", L"Model 1", L"", L"",
														   26'100U, false, request, applicable)) ;
	DRIVERCRATE_EXPECT( context, !applicable) ;
}

/**
 * @brief 端末registryに依存しない公開model要求と拒否を確認します。
 * @param[in,out] context Assertion集計先。
 */
void testPublicModelPageRequest( TestContext &context)
{
	AsusSupportPageRequest request ;	// 公開modelからだけ構築する公式page。
	DRIVERCRATE_EXPECT( context, makeAsusPublicModelSupportPageRequest(
									L"FICTIONAL TEST", L"Windows 11 64-bit", request)) ;
	DRIVERCRATE_EXPECT( context, request.model == L"FICTIONAL TEST") ;
	DRIVERCRATE_EXPECT( context, request.osName == L"Windows 11 64-bit") ;
	DRIVERCRATE_EXPECT( context,
					   request.pageUrl ==
						   L"https://www.asus.com/supportonly/fictional%20test/helpdesk_download/") ;
	DRIVERCRATE_EXPECT( context, makeAsusPublicModelSupportPageRequest(
									L"FICTIONAL TEST", L"Windows 10 64-bit", request)) ;
	DRIVERCRATE_EXPECT( context, request.osName == L"Windows 10 64-bit") ;
	DRIVERCRATE_EXPECT( context, !makeAsusPublicModelSupportPageRequest( L"FICTIONAL TEST",
																	   L"Windows Server", request)) ;
	DRIVERCRATE_EXPECT( context, request.pageUrl.empty()) ;
	DRIVERCRATE_EXPECT( context, !makeAsusPublicModelSupportPageRequest(
									L"https://example.invalid/", L"Windows 11 64-bit", request)) ;
	DRIVERCRATE_EXPECT( context, request.pageUrl.empty()) ;
	DRIVERCRATE_EXPECT( context, !makeAsusPublicModelSupportPageRequest(
									L"System Product Name", L"Windows 11 64-bit", request)) ;
	DRIVERCRATE_EXPECT( context, request.pageUrl.empty()) ;
	DRIVERCRATE_EXPECT( context, !makeAsusPublicModelSupportPageRequest(
									L"FICTIONAL 日本", L"Windows 11 64-bit", request)) ;
	DRIVERCRATE_EXPECT( context, request.pageUrl.empty()) ;
	DRIVERCRATE_EXPECT( context, !makeAsusPublicModelSupportPageRequest(
									L"PCI_VEN_1234", L"Windows 11 64-bit", request)) ;
	DRIVERCRATE_EXPECT( context, request.pageUrl.empty()) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/asus_system_identity_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runAsusSystemIdentityTests( TestContext &context)
{
	testRegistryReturnedSize( context) ;
	testAsusSystemModel( context) ;
	testAsusBaseboardModel( context) ;
	testNotApplicableSystems( context) ;
	testInvalidAsusValues( context) ;
	testPublicModelPageRequest( context) ;
}

} // namespace drivercrate::test
