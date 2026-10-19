//------------------------------------------------------------------------------
/**
 * @file amd_catalog_parser_tests.cpp
 * @brief AMD公式Web parser単体試験実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  現行公式製品page経路試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 架空HTMLだけを使用し、完全一致、driver分類、schema逸脱拒否を確認します。Payloadを取得または実行しません。
 */
//------------------------------------------------------------------------------

#include "amd_catalog_parser_tests.h"

#include "platform/amd_catalog_parser.h"
#include "platform/amd_update_provider.h"
#include "platform/com_raii.h"
#include "test_framework.h"

#include <Windows.h>

#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 試験data定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view PRODUCT_URL =
	L"https://www.amd.com/en/support/downloads/drivers.html/graphics/"
	L"fictional/fictional-series/amd-radeon-rx-7900-xtx.html" ;	// 架空製品page。
constexpr std::wstring_view PRODUCT_INDEX =
	LR"(<html><div data-component="coveo-browse-documentation" data-json=")"
	LR"({&#34;productTypes&#34;:[{&#34;title&#34;:&#34;Graphics&#34;,)"
	LR"(&#34;items&#34;:[{&#34;title&#34;:&#34;AMD Radeon&#8482; RX 7900 XTX&#34;,)"
	LR"(&#34;url&#34;:&#34;https://www.amd.com/en/support/downloads/drivers.html/)"
	LR"(graphics/fictional/fictional-series/amd-radeon-rx-7900-xtx.html&#34;}]}]}"
       ></div></html>)" ;	// 埋込みJSON付き架空起点HTML。

//------------------------------------------------------------------------------
// 内部試験関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 製品treeと完全一致照合を検証する。
 *
 * 数値entityの商標を復号し、部分一致と重複一致を拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testProductIndex( TestContext &context)
{
	std::vector<AmdProductPage> products ;	// Parserが返す架空末端製品一覧。
	DRIVERCRATE_EXPECT( context, parseAmdProductIndexHtml( PRODUCT_INDEX, products)) ;
	DRIVERCRATE_EXPECT( context, products.size() == 1U) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( products.size() != 1U) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, products.front().title == L"AMD Radeon™ RX 7900 XTX") ;
	DRIVERCRATE_EXPECT( context, products.front().url == PRODUCT_URL) ;

	AmdProductPage matched ;	// 完全一致した製品page受信先。
	DRIVERCRATE_EXPECT( context,
					   findAmdProductPage( products, L"AMD Radeon(TM) RX 7900 XTX", matched)) ;
	DRIVERCRATE_EXPECT( context, matched.url == PRODUCT_URL) ;
	DRIVERCRATE_EXPECT( context, !findAmdProductPage( products, L"Radeon RX 7900 XTX", matched)) ;

	std::vector<AmdProductPage> duplicate = products ;	// 曖昧一致を作る製品一覧。
	duplicate.push_back( products.front()) ;
	DRIVERCRATE_EXPECT( context, !findAmdProductPage( duplicate, L"AMD Radeon RX 7900 XTX", matched)) ;

	// 追加の公式製品path分類を検証する、製品一覧の合成HTML。
	constexpr std::wstring_view EXTENDED_PATHS =
		LR"(<div data-component="coveo-browse-documentation" data-json=")"
		LR"({&#34;productTypes&#34;:[{&#34;title&#34;:&#34;Alveo U200&#34;,)"
		LR"(&#34;url&#34;:&#34;https://www.amd.com/en/support/downloads/)"
		LR"(alveo-downloads.html/accelerators/alveo/u200.html&#34;},{)"
		LR"(&#34;title&#34;:&#34;Solarflare X2522&#34;,&#34;url&#34;:&#34;)"
		LR"(https://www.amd.com/en/support/downloads/solarflare-downloads.html/)"
		LR"(ethernet-adapters/x2-series/x2522.html&#34;}]}" ></div>)" ;
	DRIVERCRATE_EXPECT( context, parseAmdProductIndexHtml( EXTENDED_PATHS, products)) ;
	DRIVERCRATE_EXPECT( context, products.size() == 2U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows x64 driver表示情報の抽出を検証する。
 *
 * Adrenalinだけを採用し、Auto-DetectとRGB toolを除外する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testDriverEntries( TestContext &context)
{
	// Driver行と自動検出utilityを区別するための合成HTML。
	constexpr std::wstring_view		HTML = LR"(
<section id="amd_support_driver_list">
<div class="accordion-item"><h3>Windows 11 - 64-Bit Edition</h3>
<article class="container-fluid driver-download-details">
<h4>Auto-Detect and Install</h4></article>
<article class="container-fluid driver-download-details">
<h4>AMD Software: Adrenalin Edition</h4>
<strong>Revision Number</strong><p>Adrenalin 26.8.1 (WHQL Recommended)</p>
<strong>File Size</strong><p>849.5 MB</p>
<strong>Release Date</strong><p>2026-08-20</p>
<a href="https://drivers.amd.com/drivers/fictional-driver.exe"
 aria-label="Download fictional driver">Download</a></article>
<article class="container-fluid driver-download-details">
<h4>AMD Ryzen RGB Tool</h4></article>
</div><div class="accordion-item"><h3>Windows 10 - 64-Bit Edition</h3></div>
</section>)" ;
	std::vector<AmdDriverPageEntry> entries ;	// Parserが返す表示metadata群。
	DRIVERCRATE_EXPECT( context,
					   parseAmdDriverPageHtml( HTML, L"Windows 11 - 64-Bit Edition", entries)) ;
	DRIVERCRATE_EXPECT( context, entries.size() == 1U) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( entries.size() != 1U) {
		return ;
	}

	const AmdDriverPageEntry &entry = entries.front() ;	// 検証する採用entry。
	DRIVERCRATE_EXPECT( context, entry.title == L"AMD Software: Adrenalin Edition") ;
	DRIVERCRATE_EXPECT( context, entry.revision == L"Adrenalin 26.8.1 (WHQL Recommended)") ;
	DRIVERCRATE_EXPECT( context, entry.releaseDate == L"2026-08-20") ;
	DRIVERCRATE_EXPECT( context, entry.maximumDownloadBytes == 890'765'312ULL) ;
	DRIVERCRATE_EXPECT( context, entry.whqlRecommended) ;
	DRIVERCRATE_EXPECT( context, !entry.whqlOptional) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不正schemaと取得元を拒否することを検証する。
 *
 * 非公式URL、欠損日付、未知OS区分で部分結果を返さない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testRejections( TestContext &context)
{
	// 製品URLが未許可hostを指す場合の拒否用HTML。
	constexpr std::wstring_view WRONG_HOST =
		LR"(<div data-component="coveo-browse-documentation" data-json=")"
		LR"({&#34;productTypes&#34;:[{&#34;title&#34;:&#34;AMD Test&#34;,)"
		LR"(&#34;url&#34;:&#34;https://mirror.example.test/test.html&#34;}]}"
           ></div>)" ;
	std::vector<AmdProductPage> products ;	// 拒否時に空へ戻す製品一覧。
	products.push_back( {.title = L"stale", .url = std::wstring( PRODUCT_URL)}) ;
	DRIVERCRATE_EXPECT( context, !parseAmdProductIndexHtml( WRONG_HOST, products)) ;
	DRIVERCRATE_EXPECT( context, products.empty()) ;

	// 公式host内でも未登録の取得pathを拒否するためのHTML。
	constexpr std::wstring_view UNREGISTERED_OFFICIAL_PATH =
		LR"(<div data-component="coveo-browse-documentation" data-json=")"
		LR"({&#34;productTypes&#34;:[{&#34;title&#34;:&#34;AMD Test&#34;,)"
		LR"(&#34;url&#34;:&#34;https://www.amd.com/en/support/downloads/)"
		LR"(unregistered.html/graphics/test.html&#34;}]}" ></div>)" ;
	DRIVERCRATE_EXPECT( context, !parseAmdProductIndexHtml( UNREGISTERED_OFFICIAL_PATH, products)) ;
	DRIVERCRATE_EXPECT( context, products.empty()) ;

	// 必須の公開日が欠けたdriver行を再現するHTML。
	constexpr std::wstring_view		MISSING_DATE = LR"(
<section id="amd_support_driver_list">
<div class="accordion-item"><h3>Windows 11 - 64-Bit Edition</h3>
<article class="container-fluid driver-download-details">
<h4>AMD Software: PRO Edition</h4>
<strong>Revision Number</strong><p>PRO Edition 26.Q3</p>
<strong>File Size</strong><p>1 GB</p>
<a href="https://drivers.amd.com/drivers/fictional-pro.zip"
 aria-label="Download fictional pro">Download</a></article>
</div><div class="accordion-item"><h3>Windows 10 - 64-Bit Edition</h3></div>
</section>)" ;
	std::vector<AmdDriverPageEntry> entries ;	// 拒否時に空を維持するentry群。
	DRIVERCRATE_EXPECT(
		context, !parseAmdDriverPageHtml( MISSING_DATE, L"Windows 11 - 64-Bit Edition", entries)) ;
	DRIVERCRATE_EXPECT( context, entries.empty()) ;
	DRIVERCRATE_EXPECT( context, !parseAmdDriverPageHtml( MISSING_DATE, L"Windows 12", entries)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示専用Providerがinstallを拒否することを検証する。
 *
 * Provider直接呼出しでもdownload／installへ進まないことをnetworkへ接続せず確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testInstallRejection( TestContext &context)
{
	AmdUpdateProvider				provider ;							// 表示専用install拒否の試験対象。
	const std::vector<std::wstring> identities{L"fictional-identity"} ;	// 架空選択ID。
	const InstallResult				result = provider.install(
		1U, identities, 0U, []( const ProviderProgress &) {}) ;	// 直接install要求結果。
	DRIVERCRATE_EXPECT( context, !result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.downloadOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, result.downloadError == static_cast<NativeError>( E_NOTIMPL)) ;
	DRIVERCRATE_EXPECT( context, result.installOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, result.installError == static_cast<NativeError>( E_NOTIMPL)) ;
	DRIVERCRATE_EXPECT( context, result.updates.empty()) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/amd_catalog_parser_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runAmdCatalogParserTests( TestContext &context)
{
	const ComApartment apartment( COINIT_MULTITHREADED) ;	// Windows JSON用COM MTA。
	DRIVERCRATE_EXPECT( context, SUCCEEDED( apartment.result())) ;
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		return ;
	}

	testProductIndex( context) ;
	testDriverEntries( context) ;
	testRejections( context) ;
	testInstallRejection( context) ;
}

} // namespace drivercrate::test
