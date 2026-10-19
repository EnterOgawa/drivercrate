//------------------------------------------------------------------------------
/**
 * @file nvidia_catalog_parser_tests.cpp
 * @brief NVIDIA公式catalog parser単体試験実装。
 * @version 01.00.00
 * @date 2026/09/01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  世代hintの短命入力回帰試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  URL／IDと直接導入の拒否試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  XML security拒否試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Notebook区分試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Networkへ接続せず、固定したschema最小例と不正応答を検証します。
 */
//------------------------------------------------------------------------------

#include "nvidia_catalog_parser_tests.h"

#include "platform/com_raii.h"
#include "platform/nvidia_catalog_parser.h"
#include "platform/nvidia_update_provider.h"
#include "test_framework.h"

#include <Windows.h>

#include <array>
#include <string>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 内部試験関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief NVIDIA lookup XMLの正常系とfail-closed条件を検証する。
 *
 * 共通MSXML境界を初期化し、DTDと数字以外のIDを拒否する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testLookupXml( TestContext &context)
{
	const ComApartment apartment( COINIT_MULTITHREADED) ;	// Lookup XML用COM lifetime。
	DRIVERCRATE_EXPECT( context, SUCCEEDED( apartment.result())) ;
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		return ;
	}

	// LookupValueと名前付きentityの正常解析を確認する合成XML。
	constexpr std::wstring_view XML =
		LR"(<?xml version="1.0"?><LookupValueSearch><LookupValues>)"
		LR"(<LookupValue><Name>GeForce RTX 30 Series &amp; Test</Name>)"
		LR"(<Value>120</Value></LookupValue></LookupValues></LookupValueSearch>)" ;
	std::vector<NvidiaLookupValue> values ;	// Parserが設定するlookup値群。
	DRIVERCRATE_EXPECT( context, parseNvidiaLookupXml( XML, values)) ;
	DRIVERCRATE_EXPECT( context, values.size() == 1) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( values.size() == 1) {
		DRIVERCRATE_EXPECT( context, values.front().name == L"GeForce RTX 30 Series & Test") ;
		DRIVERCRATE_EXPECT( context, values.front().value == L"120") ;
	}

	// 数値IDにentityが混入したlookupの拒否用XML。
	constexpr std::wstring_view INVALID_XML =
		LR"(<?xml version="1.0"?><LookupValueSearch><LookupValue>)"
		LR"(<Name>製品</Name><Value>12&amp;3</Value></LookupValue></LookupValueSearch>)" ;
	DRIVERCRATE_EXPECT( context, !parseNvidiaLookupXml( INVALID_XML, values)) ;
	DRIVERCRATE_EXPECT( context, values.empty()) ;

	// DTDでIDを生成するlookupを拒否するXML fixture。
	constexpr std::wstring_view DTD_XML =
		LR"(<?xml version="1.0"?><!DOCTYPE LookupValueSearch [<!ENTITY id "120">]>)"
		LR"(<LookupValueSearch><LookupValue><Name>Test</Name><Value>&id;</Value>)"
		LR"(</LookupValue></LookupValueSearch>)" ;
	DRIVERCRATE_EXPECT( context, !parseNvidiaLookupXml( DTD_XML, values)) ;
	DRIVERCRATE_EXPECT( context, values.empty()) ;

	// 期待rootが別要素に包まれたlookupを拒否するXML fixture。
	constexpr std::wstring_view WRONG_ROOT =
		LR"(<?xml version="1.0"?><Envelope><LookupValueSearch><LookupValue>)"
		LR"(<Name>Test</Name><Value>120</Value></LookupValue>)"
		LR"(</LookupValueSearch></Envelope>)" ;
	DRIVERCRATE_EXPECT( context, !parseNvidiaLookupXml( WRONG_ROOT, values)) ;
	DRIVERCRATE_EXPECT( context, values.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief NVIDIA driver JSONの必須fieldとpercent decodeを検証する。
 *
 * COM MTA上で最小releaseを解析し、必須field欠損とURL／download IDの差替えを拒否する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testDriverJson( TestContext &context)
{
	const ComApartment apartment( COINIT_MULTITHREADED) ;	// Windows.Data.Json用COM lifetime。
	DRIVERCRATE_EXPECT( context, SUCCEEDED( apartment.result())) ;
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		return ;
	}

	// NVIDIA driverの版数・公開日・取得先を解析する合成JSON。
	constexpr std::wstring_view JSON =
		LR"({"Success":"1","IDS":[{"downloadInfo":{"Success":"1",)"
		LR"("ID":"278153","Name":"GeForce%20Game%20Ready%20Driver",)"
		LR"("Version":"616.56","ReleaseDateTime":"Wed%20Aug%2026%2C%202026",)"
		LR"("DetailsURL":"https://www.nvidia.com/en-us/drivers/details/278153/",)"
		LR"("DownloadURL":"https://us.download.nvidia.com/Windows/driver.exe",)"
		LR"("DownloadURLFileSize":"984.3 MB","IsWHQL":"1","IsCRD":"0",)"
		LR"("IsActive":"1","Is64Bit":"1"}}]})" ;
	std::vector<NvidiaDriverEntry> entries ;	// Parserが設定するdriver release群。
	DRIVERCRATE_EXPECT( context, parseNvidiaDriverJson( JSON, entries)) ;
	DRIVERCRATE_EXPECT( context, entries.size() == 1) ;
	DRIVERCRATE_EXPECT( context, entries.front().name == L"GeForce Game Ready Driver") ;
	DRIVERCRATE_EXPECT( context, entries.front().version == L"616.56") ;
	DRIVERCRATE_EXPECT( context, entries.front().releaseDate == L"Wed Aug 26, 2026") ;
	DRIVERCRATE_EXPECT( context, entries.front().whql) ;
	DRIVERCRATE_EXPECT( context, entries.front().x64) ;

	// 必須download metadataが欠けた応答を拒否するJSON fixture。
	constexpr std::wstring_view INCOMPLETE_JSON =
		LR"({"Success":"1","IDS":[{"downloadInfo":{"Success":"1","ID":"1"}}]})" ;
	DRIVERCRATE_EXPECT( context, !parseNvidiaDriverJson( INCOMPLETE_JSON, entries)) ;
	DRIVERCRATE_EXPECT( context, entries.empty()) ;

	std::wstring	  mismatchedId( JSON) ;							// Details pageだけ別download IDへ差し替える応答。
	const std::size_t detailsId = mismatchedId.find( L"/278153/") ;	// Details IDの位置。
	DRIVERCRATE_EXPECT( context, detailsId != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( detailsId != std::wstring::npos) {
		mismatchedId.replace( detailsId, std::wstring_view( L"/278153/").size(), L"/278154/") ;
		DRIVERCRATE_EXPECT( context, !parseNvidiaDriverJson( mismatchedId, entries)) ;
		DRIVERCRATE_EXPECT( context, entries.empty()) ;
	}

	std::wstring	  spoofedDetailsHost( JSON) ;									// 完全一致hostに見える偽装details URL。
	const std::size_t detailsHost = spoofedDetailsHost.find( L"www.nvidia.com") ;	// Host位置。
	DRIVERCRATE_EXPECT( context, detailsHost != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( detailsHost != std::wstring::npos) {
		spoofedDetailsHost.replace( detailsHost, std::wstring_view( L"www.nvidia.com").size(),
								   L"www.nvidia.com.example.invalid") ;
		DRIVERCRATE_EXPECT( context, !parseNvidiaDriverJson( spoofedDetailsHost, entries)) ;
		DRIVERCRATE_EXPECT( context, entries.empty()) ;
	}

	std::wstring	  spoofedPayloadHost( JSON) ;	// NVIDIA suffixに見える偽装payload URL。
	const std::size_t payloadHost =					// Payload hostの位置。
		spoofedPayloadHost.find( L"us.download.nvidia.com") ;
	DRIVERCRATE_EXPECT( context, payloadHost != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( payloadHost != std::wstring::npos) {
		spoofedPayloadHost.replace( payloadHost, std::wstring_view( L"us.download.nvidia.com").size(),
								   L"us.download.nvidia.com.example.invalid") ;
		DRIVERCRATE_EXPECT( context, !parseNvidiaDriverJson( spoofedPayloadHost, entries)) ;
		DRIVERCRATE_EXPECT( context, entries.empty()) ;
	}

	std::wstring	  nonExecutablePayload( JSON) ;								// Driver以外の拡張子を返すpayload URL。
	const std::size_t extension = nonExecutablePayload.find( L"driver.exe") ;	// File名位置。
	DRIVERCRATE_EXPECT( context, extension != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( extension != std::wstring::npos) {
		nonExecutablePayload.replace( extension, std::wstring_view( L"driver.exe").size(),
									 L"driver.zip") ;
		DRIVERCRATE_EXPECT( context, !parseNvidiaDriverJson( nonExecutablePayload, entries)) ;
		DRIVERCRATE_EXPECT( context, entries.empty()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief NVIDIA表示専用Providerの直接install拒否を検証する。
 *
 * Registryを迂回した直接呼出しでもnetworkや実行へ進まず、Downloadとinstallの双方を未実装として拒否する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testDisplayOnlyInstallRejection( TestContext &context)
{
	NvidiaUpdateProvider			  provider ;					// 直接install拒否を確認する表示専用Provider。
	const std::array<std::wstring, 1> identities{L"nvidia:1:0:0"} ;	// 拒否対象identity。
	const ProviderProgressCallback	  progressCallback = []( const ProviderProgress &) {
	   } ; // 呼び出されてはならない進捗通知先。
	const InstallResult result =	// Networkを使用しない直接install要求の結果。
		provider.install( 1U, identities, 0U, progressCallback) ;

	DRIVERCRATE_EXPECT( context, !result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.downloadOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, result.downloadError == static_cast<NativeError>( E_NOTIMPL)) ;
	DRIVERCRATE_EXPECT( context, result.installOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, result.installError == static_cast<NativeError>( E_NOTIMPL)) ;
	DRIVERCRATE_EXPECT( context, result.updates.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows版からNVIDIA表示版への変換規則を検証する。
 *
 * NVIDIAが末尾componentへ符号化した5桁を表示版へ戻す。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testNvidiaVersion( TestContext &context)
{
	DRIVERCRATE_EXPECT( context, nvidiaVersionFromWindowsVersion( L"32.0.15.9186") == L"591.86") ;
	DRIVERCRATE_EXPECT( context, nvidiaVersionFromWindowsVersion( L"31.0.15.5244") == L"552.44") ;
	DRIVERCRATE_EXPECT( context, nvidiaVersionFromWindowsVersion( L"31.0.15") == L"") ;
	DRIVERCRATE_EXPECT( context, nvidiaVersionFromWindowsVersion( L"31.0.15.5244.") == L"") ;
	DRIVERCRATE_EXPECT( context, nvidiaVersionFromWindowsVersion( L"31.a.15.5244") == L"") ;
}

//------------------------------------------------------------------------------
/**
 * @brief NVIDIA公式lookup名のnotebook区分を検証する。
 *
 * Productまたはseriesの明示語だけを判定し、Desktopを除外する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testNvidiaNotebookProduct( TestContext &context)
{
	DRIVERCRATE_EXPECT(
		context, isNvidiaNotebookProduct( L"GeForce RTX 5090 Laptop GPU", L"GeForce RTX 50 Series")) ;
	DRIVERCRATE_EXPECT( context, isNvidiaNotebookProduct( L"GeForce RTX 4090",
														L"GeForce RTX 40 Series (Notebooks)")) ;
	DRIVERCRATE_EXPECT( context,
					   !isNvidiaNotebookProduct( L"GeForce RTX 5090", L"GeForce RTX 50 Series")) ;
	DRIVERCRATE_EXPECT( context, !isNvidiaNotebookProduct( L"", L"")) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 短命な入力と長い数字列でも所有値を返すことを確認する。Hintは照会順だけに使用し、適用性判定とは扱わない。
 *
 * @param[in,out] context 決定的assertionの集計先。
 */
//------------------------------------------------------------------------------
void testNvidiaGenerationHint( TestContext &context)
{
	DRIVERCRATE_EXPECT( context, nvidiaProductGenerationKey( L"NVIDIA GeForce RTX 4090") == L"RTX40") ;
	DRIVERCRATE_EXPECT( context,
					   nvidiaProductGenerationKey( L"GeForce RTX 4090 Laptop GPU") == L"RTX40") ;
	DRIVERCRATE_EXPECT( context, nvidiaProductGenerationKey( L"GeForce GTX 980") == L"GTX900") ;
	DRIVERCRATE_EXPECT( context, nvidiaProductGenerationKey( L"GeForce MX450") == L"MX400") ;
	DRIVERCRATE_EXPECT( context, nvidiaProductGenerationKey( L"NVS 810") == L"NVS800") ;
	DRIVERCRATE_EXPECT( context, nvidiaProductGenerationKey( L"GeForce RTX").empty()) ;
	DRIVERCRATE_EXPECT( context, nvidiaProductGenerationKey( L"Unknown").empty()) ;
	DRIVERCRATE_EXPECT( context, nvidiaProductGenerationKey( L"").empty()) ;
	const std::wstring retained =	// 呼出し終了時に破棄される長い合成入力から得た所有値。
		nvidiaProductGenerationKey( std::wstring( L"GeForce RTX 409012345678901234567890")) ;
	DRIVERCRATE_EXPECT( context, retained == L"RTX40") ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/nvidia_catalog_parser_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runNvidiaCatalogParserTests( TestContext &context)
{
	testLookupXml( context) ;
	testDriverJson( context) ;
	testDisplayOnlyInstallRejection( context) ;
	testNvidiaVersion( context) ;
	testNvidiaNotebookProduct( context) ;
	testNvidiaGenerationHint( context) ;
}

} // namespace drivercrate::test
