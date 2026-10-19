//------------------------------------------------------------------------------
/**
 * @file intel_collector_identity_parser_tests.cpp
 * @brief Intel公開製品identityの所属・復号・衝突・有限上限試験。
 * @version 01.03.01
 * @date 2026/09/28
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  有限Intel製品identity解析を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/28  実pageの非採用構文と行内拒否fixtureを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/28  公開名の端末ID形状を拒否するfixtureを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/28  制御付きcore全checkpointの停止・例外fixtureを追加。
 * Ver.01.03.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 関連階層は閉鎖を検証し、公式GETとのbindingは呼出し側の別責務です。
 * @see docs/adr/0221-collector-official-product-identity.md
 */
//------------------------------------------------------------------------------

#include "intel_collector_identity_parser_tests.h"
#include "collector_parser_test_control.h"

#include "platform/intel_collector_identity_parser.h"

#include <cstddef>
#include <string>
#include <string_view>

namespace drivercrate::test {
namespace {

// 固定配布起点は構造fixtureであり、通信や公式証拠の生成には使用しない。
constexpr std::wstring_view START =
	LR"(<html><head><meta charset="utf-8"><link rel="canonical" href="https://www.intel.com/content/www/us/en/download/727998/intel-network-adapter-driver-for-microsoft-windows-11.html"></head><body>)"
	LR"(<main id="primary-content"><div data-bundle-id="downloadcenter.components.content.dcPageBanner" class="dc-page-banner">)"
	LR"(<div class="dc-page-banner-actions-action-id"><label class="dc-page-banner-actions-action__label">ID</label>)"
	LR"(<span class="dc-page-banner-actions-action__value">727998</span></div></div>)"
	LR"(<div data-bundle-id="downloadcenter.components.content.dcPageContainer" class="dc-page-container container">)"
	LR"(<div class="dc-page-container__body"><div class="dc-page-container__body--left-panel">)"
	LR"(<div class="dc-page-available-downloads-hero"><br><input disabled></div>)" ;
// 専用divと直接見出し・ulの開始。
constexpr std::wstring_view LIST_START =
	LR"(<div data-bundle-id="downloadcenter.components.content.dcPageOtherValidProducts" class="dc-page-detailed-other-valid-products">)"
	LR"(<h2 class="dc-page-detailed-other-valid-products__title">This download is valid for the product(s) listed below.</h2>)"
	LR"(<ul class="dc-page-detailed-other-valid-products-panel">)" ;
constexpr std::wstring_view END = L"</div></div></div></main></body></html>" ;	// 左panelから閉じる。
// 一製品行の単純anchor構造。
constexpr std::wstring_view ROW_PREFIX =
	LR"(<li class="dc-page-detailed-other-valid-products-panel__product"><a class="dc-page-detailed-other-valid-products-panel__product--fixed" href=")" ;

/**
 * @brief 架空SKUと製品名の一行を生成します。
 * @param[in] sku 公開SKUの合成値。
 * @param[in] name Entityを含められる合成表示。
 * @return 一つの閉鎖済みli。
 */
[[nodiscard]] std::wstring row( std::wstring_view sku, std::wstring_view name)
{
	return std::wstring( ROW_PREFIX) + L"/content/www/us/en/products/sku/" + std::wstring( sku) +
		   L"/fixture-adapter/downloads.html\">" + std::wstring( name) + L"</a></li>" ;
}

/**
 * @brief 一覧と配布所属を持つ合成本文を生成します。
 * @param[in] rows 合成li列。
 * @return 閉鎖済み本文。
 */
[[nodiscard]] std::wstring page( std::wstring_view rows)
{
	return std::wstring( START) + std::wstring( LIST_START) + std::wstring( rows) + L"</ul></div>" +
		   std::wstring( END) ;
}

/**
 * @brief 合成本文の一箇所だけを置換します。
 * @param[in] text 元本文の所有値。
 * @param[in] oldValue 元fixtureに存在する文字列。
 * @param[in] newValue 差替え文字列。
 * @return 改変本文。
 */
[[nodiscard]] std::wstring replace( std::wstring text, std::wstring_view oldValue,
								   std::wstring_view newValue)
{
	const auto position = text.find( oldValue) ;	// 固定fixture内の変更位置。
	// Fixture自体の誤りを正常ページの再試験で隠さない。
	if( position == text.npos) {
		return {} ;
	}

	text.replace( position, oldValue.size(), newValue) ;
	return text ;
}

/**
 * @brief 全体拒否が部分identityを残さないことを確認します。
 * @param[in,out] context Assertion集計。
 * @param[in] html 合成本文。
 * @param[in] status 期待する第一状態。
 */
void expectEmpty( TestContext &context, std::wstring_view html, IntelCollectorIdentityStatus status)
{
	const auto result = parseIntelCollectorProductIdentity( html) ;	// 無通信の実parser結果。
	DRIVERCRATE_EXPECT( context, result.status == status) ;
	DRIVERCRATE_EXPECT( context, result.products.empty() && result.seen == 0U &&
									result.collisions == 0U && result.rejected == 0U &&
									result.duplicates == 0U) ;
}

/**
 * @brief 基本所属とscript／footer等の偽装を検証します。
 * @param[in,out] context Assertion集計。
 */
void testOwnership( TestContext &context)
{
	const auto rows	  = row( L"900001", L"Fixture® Adapter X1") ;	// 架空製品だけの原行。
	const auto good	  = page( rows) ;								// 基準本文。
	const auto result = parseIntelCollectorProductIdentity( good) ;	// 基準の無通信解析。
	DRIVERCRATE_EXPECT( context, result.status == IntelCollectorIdentityStatus::ACCEPTED) ;
	DRIVERCRATE_EXPECT( context, result.seen == 1U && result.products.size() == 1U &&
									result.products[0].sku == L"900001" &&
									result.products[0].comparisonName == L"Fixture® Adapter X1") ;
	// 実pageの非採用navigationにある表示用の未escape「<」を一文字だけ許します。
	DRIVERCRATE_EXPECT(
		context,
		parseIntelCollectorProductIdentity(
			replace( good, L"<main id=\"primary-content\">",
					L"<span class=\"visually-hidden\"><</span><main id=\"primary-content\">"))
				.status == IntelCollectorIdentityStatus::ACCEPTED) ;
	// 許諾modalと同じ空装飾spanは閉じるが、一覧行内なら単純anchor契約で拒否します。
	DRIVERCRATE_EXPECT( context, parseIntelCollectorProductIdentity(
									replace( good, L"<br>", L"<span class=\"icon\"/><br>"))
										.status == IntelCollectorIdentityStatus::ACCEPTED) ;
	expectEmpty( context, replace( good, L"<br>", L"<span><</span><br>"),
				IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	const auto malformedRow = parseIntelCollectorProductIdentity( replace(
		good, L"Fixture® Adapter X1</a>", L"Fixture® <span/>Adapter X1</a>")) ;	// 一覧の子要素。
	DRIVERCRATE_EXPECT( context,
					   malformedRow.status == IntelCollectorIdentityStatus::PARTIAL_REJECTED &&
						   malformedRow.products.empty() && malformedRow.rejected == 1U) ;
	const auto extra = std::wstring( LIST_START) + rows + L"</ul></div>" ;	// 偽装する専用一覧。
	// 同じmainでも左panelを離れた一覧を配布heroへ結ばない。
	expectEmpty( context,
				std::wstring( START) + L"</div></div></div>" + extra + L"</main></body></html>",
				IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	// 解析対象外の領域へ同じ一覧文字列を埋める。
	const auto ignored =
		L"<!--" + extra + L"--><script>const fixture='" + extra + L"';</script><style>" + extra +
		L"</style><template><template>" + extra +
		L"</template><script>const t='</template>';</script></template><textarea>" + extra +
		L"</textarea>" ;
	DRIVERCRATE_EXPECT(
		context, parseIntelCollectorProductIdentity( replace( good, L"</body>", ignored + L"</body>"))
						 .status == IntelCollectorIdentityStatus::ACCEPTED) ;
	expectEmpty( context,
				std::wstring( START) + L"<template>" + extra + L"</template>" + std::wstring( END),
				IntelCollectorIdentityStatus::IDENTITY_UNKNOWN) ;
	expectEmpty( context,
				std::wstring( START) + L"<script>" + extra + L"</script>" + std::wstring( END),
				IntelCollectorIdentityStatus::IDENTITY_UNKNOWN) ;
	expectEmpty( context,
				std::wstring( START) + std::wstring( END.substr( 0U, END.size() - 14U)) + L"<footer>" +
					extra + L"</footer></body></html>",
				IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	expectEmpty( context, replace( good, L"</body>", L"<footer>" + extra + L"</footer></body>"),
				IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	expectEmpty( context, replace( good, L">727998<", L">727999<"),
				IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	expectEmpty( context, replace( good, L"/download/727998/", L"/download/727999/"),
				IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	expectEmpty(
		context,
		replace( good, L"<meta charset=\"utf-8\">", L"<meta charset=\"utf-8\" CHARSET=\"utf-8\">"),
		IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	expectEmpty(
		context,
		replace( good, L"</head>", LR"(<link rel="canonical" href="https://example.test/"></head>)"),
		IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	expectEmpty( context,
				replace( good, L"class=\"dc-page-container container\"",
						L"class=\"dc-page-container-other\""),
				IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	expectEmpty( context, replace( good, L"</ul></div>", L"</ul></div>" + extra),
				IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	expectEmpty( context, replace( good, L"</ul></div>", L"</ul><button>More</button></div>"),
				IntelCollectorIdentityStatus::PAGINATION_INCOMPLETE) ;
	expectEmpty( context,
				replace( good, L"</ul>", L"<a href=\"https://example.test/next\">Next</a></ul>"),
				IntelCollectorIdentityStatus::PAGINATION_INCOMPLETE) ;
	expectEmpty( context, replace( good, L"</main>", L""),
				IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	expectEmpty( context, replace( good, L"</a></li>", L"</li></a>"),
				IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	expectEmpty( context,
				replace( good, L"<main id=\"primary-content\">", L"<main id=\"primary-content\"/>"),
				IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	// 閉鎖済みの入れ子anchorを含む個別不正行。
	const auto nested =
		parseIntelCollectorProductIdentity( page( replace( rows, L"</a>", L"<a>Fake</a></a>"))) ;
	// 構造が閉じていても入れ子anchorを平坦化して受理しない。
	DRIVERCRATE_EXPECT( context, nested.status == IntelCollectorIdentityStatus::PARTIAL_REJECTED &&
									nested.rejected == 1U && nested.products.empty()) ;
}

/**
 * @brief 復号・NFC・文字差保持と危険な表示を検証します。
 * @param[in,out] context Assertion集計。
 */
void testNames( TestContext &context)
{
	const auto normal = parseIntelCollectorProductIdentity(
		page( row( L"910001", L"\tFixture&reg;&nbsp; A&amp;B &#x2122;\r\n OCP 3.0&nbsp;") +
			 row( L"910002", L"Fixture Cafe\u0301") +
			 // Named・numeric・NFC。
			 row( L"910003", L"Fixture &#128512;"))) ;
	DRIVERCRATE_EXPECT( context, normal.status == IntelCollectorIdentityStatus::ACCEPTED &&
									normal.products.size() == 3U) ;
	// 先行assert失敗時にも範囲外参照を起こさない。
	if( normal.products.size() == 3U) {
		DRIVERCRATE_EXPECT( context, normal.products[0].comparisonName == L"Fixture® A&B ™ OCP 3.0") ;
		DRIVERCRATE_EXPECT( context, normal.products[1].displayName == L"Fixture Cafe\u0301" &&
										normal.products[1].comparisonName == L"Fixture Café") ;
		DRIVERCRATE_EXPECT( context, normal.products[2].comparisonName == L"Fixture \U0001F600") ;
	}

	// 未知entity、無効Unicode、controls、URL／markupを一行ずつ隔離する。
	for( const std::wstring_view name :
		{L"Fixture &unknown;", L"Fixture &amp", L"Fixture &#0;", L"Fixture &#xD800;",
		 L"Fixture &#x110000;", L"Fixture &#x7f;", L"Fixture &#x85;", L"Fixture &lt;b&gt;",
		 L"https:&#47;&#47;example.test", L"Fixture &#12;", L"Fixture \xD800", L"Fixture \xDC00",
		 L"Fixture &#x;", L"Fixture &#99999999;", L"VEN_1234", L"vid_1234", L"SUBSYS_12345678",
		 L"token=fictional", L"folder/file"}) {
		const auto result =
			// 個別不正の解析。
			parseIntelCollectorProductIdentity( page( row( L"910005", name))) ;
		DRIVERCRATE_EXPECT(
			context, result.status == IntelCollectorIdentityStatus::PARTIAL_REJECTED &&
						 result.seen == 1U && result.rejected == 1U && result.products.empty()) ;
	}

	DRIVERCRATE_EXPECT(
		context,
		parseIntelCollectorProductIdentity( page( row( L"910010", std::wstring( 256U, L'X')))).status ==
			IntelCollectorIdentityStatus::ACCEPTED) ;
	DRIVERCRATE_EXPECT(
		context,
		parseIntelCollectorProductIdentity( page( row( L"910010", std::wstring( 257U, L'X')))).status ==
			IntelCollectorIdentityStatus::PARTIAL_REJECTED) ;
	const auto differences = parseIntelCollectorProductIdentity(
		page( row( L"910020", L"Fixture OCP 3.0") + row( L"910021", L"Fixture OCP 2.0") +
			 // 大小文字と世代差。
			 row( L"910022", L"fixture OCP 3.0"))) ;
	DRIVERCRATE_EXPECT( context, differences.products.size() == 3U && differences.collisions == 0U) ;
}

/**
 * @brief SKU pathと双方向衝突・重複の全行隔離を検証します。
 * @param[in,out] context Assertion集計。
 */
void testKeysAndCollisions( TestContext &context)
{
	const auto normalRow = row( L"920001", L"Fixture A") ;	// 基準の架空製品。
	const auto absolute =
		// 許可absolute。
		replace( normalRow, L"href=\"/", L"href=\"https://www.intel.com/") ;
	DRIVERCRATE_EXPECT( context, parseIntelCollectorProductIdentity( page( absolute)).status ==
									IntelCollectorIdentityStatus::ACCEPTED) ;
	// Keyの0・先頭0・過大・非数値を拒否し、固定製品DBに依存しない。
	for( const std::wstring_view key : {L"0", L"01", L"12345678901", L"1a", L"-1", L""}) {
		DRIVERCRATE_EXPECT(
			context,
			parseIntelCollectorProductIdentity( page( row( key, L"Fixture A"))).rejected == 1U) ;
	}

	DRIVERCRATE_EXPECT(
		context, parseIntelCollectorProductIdentity( page( row( L"9999999999", L"Future Adapter")))
						 .products.size() == 1U) ;
	// Href形状を一つずつ逸脱させ、URLを補修しない。
	for( const std::wstring_view path :
		{L"https://www.intel.com.evil.test/content/www/us/en/products/sku/920001/a/downloads.html",
		 L"https://www.intel.com:443/content/www/us/en/products/sku/920001/a/downloads.html",
		 L"https://user@www.intel.com/content/www/us/en/products/sku/920001/a/downloads.html",
		 L"/content/www/us/en/products/sku/920001/../downloads.html",
		 L"/content/www/us/en/products/sku/920001/%61/downloads.html",
		 L"/content/www/us/en/products/sku/920001/A/downloads.html",
		 L"/content/www/us/en/products/sku/920001/a/downloads.html?x=1",
		 L"/content/www/us/en/products/sku/920001/a/downloads.html#x",
		 L"/content/www/us/en/products/sku/920001//downloads.html"}) {
		const auto bad = std::wstring( ROW_PREFIX) + std::wstring( path) +
						 L"\">Fixture A</a></li>" ;	// 一href変異。
		DRIVERCRATE_EXPECT( context, parseIntelCollectorProductIdentity( page( bad)).rejected == 1U) ;
	}

	const auto duplicate =
		// 同値2行。
		parseIntelCollectorProductIdentity( page( normalRow + normalRow)) ;
	DRIVERCRATE_EXPECT( context, duplicate.status == IntelCollectorIdentityStatus::ACCEPTED &&
									duplicate.seen == 2U && duplicate.duplicates == 1U &&
									duplicate.products.size() == 1U) ;
	const auto chain = normalRow + normalRow + row( L"920001", L"Fixture B") +
					   row( L"920002", L"Fixture B") +
					   // 同key別名→同名別key。
					   row( L"920003", L"Independent C") ;
	const auto collision = parseIntelCollectorProductIdentity( page( chain)) ;	// 全行隔離後の結果。
	DRIVERCRATE_EXPECT( context,
					   collision.status == IntelCollectorIdentityStatus::PARTIAL_REJECTED &&
						   collision.seen == 5U && collision.collisions == 4U &&
						   collision.duplicates == 0U && collision.products.size() == 1U &&
						   collision.products[0].sku == L"920003") ;
	// 原行を逆順にしても隔離対象は変わらない。
	const auto reversed = parseIntelCollectorProductIdentity(
		page( row( L"920003", L"Independent C") + row( L"920002", L"Fixture B") +
			 row( L"920001", L"Fixture B") + normalRow + normalRow)) ;
	DRIVERCRATE_EXPECT( context, reversed.collisions == collision.collisions &&
									reversed.products.size() == 1U &&
									reversed.products[0].sku == L"920003") ;
	const auto nfcCollision =
		parseIntelCollectorProductIdentity( page( row( L"930001", L"Fixture Café") +
												// NFC後の同名別key。
												row( L"930002", L"Fixture Cafe\u0301"))) ;
	DRIVERCRATE_EXPECT( context, nfcCollision.collisions == 2U && nfcCollision.products.empty()) ;
}

/**
 * @brief 各有限予算と境界直後の終端検査を検証します。
 * @param[in,out] context Assertion集計。
 */
void testLimits( TestContext &context)
{
	std::wstring rows ;	// 固定名表を使わない最大1024架空行。
	// 上限まで全行を一意にして切捨てを検出する。
	for( std::size_t index = 1U; index <= 1024U; ++index) {
		const auto key = std::to_wstring( index) ;	// 架空SKUと名のsuffix。
		rows += row( key, L"Fixture " + key) ;
	}

	const auto maximum = parseIntelCollectorProductIdentity( page( rows)) ;	// 上限ちょうどの完了結果。
	DRIVERCRATE_EXPECT( context, maximum.status == IntelCollectorIdentityStatus::ACCEPTED &&
									maximum.seen == 1024U && maximum.products.size() == 1024U) ;
	expectEmpty( context, page( rows + row( L"9999", L"Overflow")),
				IntelCollectorIdentityStatus::LIMIT_EXCEEDED) ;
	expectEmpty( context, replace( page( rows), L"</ul>", L""),
				IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	expectEmpty( context, std::wstring( 4U * 1024U * 1024U + 1U, L' '),
				IntelCollectorIdentityStatus::LIMIT_EXCEEDED) ;
	const auto good = page( row( L"940001", L"Fixture A")) ;	// 他上限検査の基準。
	expectEmpty( context, good + std::wstring( 1U, L'\0'),
				IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	std::wstring attributes ;	// 独立した64属性。
	// 同名衝突を避けて属性数の境界だけを測る。
	for( std::size_t index = 0U; index < 64U; ++index) {
		attributes += L" data-" + std::to_wstring( index) + L"=\"x\"" ;
	}

	DRIVERCRATE_EXPECT( context, parseIntelCollectorProductIdentity(
									replace( good, L"<br>", L"<br" + attributes + L">"))
										.status == IntelCollectorIdentityStatus::ACCEPTED) ;
	expectEmpty( context, replace( good, L"<br>", L"<br" + attributes + L" overflow=\"x\">"),
				IntelCollectorIdentityStatus::LIMIT_EXCEEDED) ;
	expectEmpty( context,
				replace( good, L"<br>", L"<br data-x=\"" + std::wstring( 16384U, L'x') + L"\">"),
				IntelCollectorIdentityStatus::LIMIT_EXCEEDED) ;
	std::wstring deep ;		// 65層を作る開始tag列。
	std::wstring closing ;	// 対応する閉鎖列。
	// 関連main内で深さ上限を超えさせる。
	for( std::size_t index = 0U; index < 65U; ++index) {
		deep += L"<div>" ;
		closing += L"</div>" ;
	}

	expectEmpty( context, replace( good, L"<br>", deep + closing),
				IntelCollectorIdentityStatus::LIMIT_EXCEEDED) ;
	std::wstring tags ;	// Tag数だけを超過させる無所属void列。
	// Body上限以内でtag予算を独立検証する。
	for( std::size_t index = 0U; index < 65536U; ++index) {
		tags += L"<br>" ;
	}

	expectEmpty( context, replace( good, L"</body>", tags + L"</body>"),
				IntelCollectorIdentityStatus::LIMIT_EXCEEDED) ;
}

/**
 * @brief 起点偽装と予算ちょうどの受理を追加検証します。
 * @param[in,out] context Assertion集計。
 */
void testHostileStructureAndExactLimits( TestContext &context)
{
	const auto good = page( row( L"950001", L"Fixture A")) ;	// 境界検査の基準。
	expectEmpty( context, replace( good, L"</head>", L"<base href=\"https://example.test/\"></head>"),
				IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	expectEmpty( context, replace( good, L"<body>", L"<footer><body>"),
				IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	expectEmpty( context, replace( good, L"<body>", L"<body><plaintext>ignored</plaintext>"),
				IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	expectEmpty( context,
				replace( good, L"</head>", L"<script><!--<SCRIPT></script></script></head>"),
				IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	expectEmpty( context, replace( good, L"<ul class=", L"<ul data-total-pages=\"2\" class="),
				IntelCollectorIdentityStatus::PAGINATION_INCOMPLETE) ;
	expectEmpty(
		context,
		replace(
			good, L"data-bundle-id=\"downloadcenter.components.content.dcPageOtherValidProducts\"",
			L"hidden data-bundle-id=\"downloadcenter.components.content.dcPageOtherValidProducts\""),
		IntelCollectorIdentityStatus::PAGINATION_INCOMPLETE) ;
	const auto tag = L"<br data-x=\"" + std::wstring( 16384U - 14U, L'x') + L"\">" ;	// 全長16,384。
	DRIVERCRATE_EXPECT( context,
					   tag.size() == 16384U &&
						   parseIntelCollectorProductIdentity( replace( good, L"<br>", tag)).status ==
							   IntelCollectorIdentityStatus::ACCEPTED) ;
	DRIVERCRATE_EXPECT( context, parseIntelCollectorProductIdentity(
									good + std::wstring( 4U * 1024U * 1024U - good.size(), L' '))
										.status == IntelCollectorIdentityStatus::ACCEPTED) ;
	std::wstring nested ;	// Heroまで7層、追加57層で上限64。
	std::wstring closed ;	// 上限までの対応終了tag。
	// 関連範囲の最深位置ちょうどを構成する。
	for( std::size_t index = 0U; index < 57U; ++index) {
		nested += L"<div>" ;
		closed += L"</div>" ;
	}

	DRIVERCRATE_EXPECT(
		context,
		parseIntelCollectorProductIdentity( replace( good, L"<br>", nested + closed)).status ==
			IntelCollectorIdentityStatus::ACCEPTED) ;
	expectEmpty( context, replace( good, L"<br>", nested + L"<div></div>" + closed),
				IntelCollectorIdentityStatus::LIMIT_EXCEEDED) ;
	std::size_t originalTags = 0U ;	// 基準fixtureのmarkup数。
	// Literal内の山括弧は基準fixtureでは全て実tagに対応する。
	for( const auto ch : good) {
		// 開始と終了を区別せず予算に数える。
		if( ch == L'<') {
			++originalTags ;
		}
	}

	std::wstring extraTags ;	// 上限までの追加void列。
	// 合計65,536tagにして境界の受理を確認する。
	for( std::size_t index = originalTags; index < 65536U; ++index) {
		extraTags += L"<br>" ;
	}

	DRIVERCRATE_EXPECT( context, parseIntelCollectorProductIdentity(
									replace( good, L"</body>", extraTags + L"</body>"))
										.status == IntelCollectorIdentityStatus::ACCEPTED) ;
	const std::wstring prefix = L"/content/www/us/en/products/sku/950001/" ;	// 公開SKU path。
	const std::wstring suffix = L"/downloads.html" ;							// 許可終端。
	const auto		   path =
		prefix + std::wstring( 2048U - prefix.size() - suffix.size(), L'a') + suffix ;	// 上限href。
	DRIVERCRATE_EXPECT( context,
					   parseIntelCollectorProductIdentity(
						   page( std::wstring( ROW_PREFIX) + path + L"\">Fixture A</a></li>"))
							   .status == IntelCollectorIdentityStatus::ACCEPTED) ;
	DRIVERCRATE_EXPECT( context, parseIntelCollectorProductIdentity(
									page( std::wstring( ROW_PREFIX) + prefix + L"a" +
										 path.substr( prefix.size()) + L"\">Fixture A</a></li>"))
										.rejected == 1U) ;
}

/** @brief 制御付き本番coreの全checkpointと終了分類を検証します。
 * @param[in,out] context Assertion集計。
 */
void testControlledIdentity( TestContext &context)
{
	const auto html =
		// 正常二行。
		page( row( L"900001", L"Fixture A") + row( L"900002", L"Fixture B")) ;
	IntelCollectorIdentityResult result ;	// 成否ごとに再初期化される所有値。
	testParserCheckpoints(
		context,
		[&]( OfficialCollectorHttpControl &control) {
			return parseIntelCollectorProductIdentityControlled( html, {}, control, result) ;
		},
		[&] { return result.products.empty() && result.seen == 0U ; }) ;
	ParserTestControl missing ;	// 未掲載は障害ではありません。
	DRIVERCRATE_EXPECT( context, parseIntelCollectorProductIdentityControlled(
									L"<html><head></head><body></body></html>", {}, missing, result)
										.status == CollectorParserStatus::COMPLETED) ;
	DRIVERCRATE_EXPECT( context, result.status == IntelCollectorIdentityStatus::IDENTITY_UNKNOWN) ;
	ParserTestControl malformed ;	// 壊れた構造はUNKNOWNと分けます。
	DRIVERCRATE_EXPECT( context, parseIntelCollectorProductIdentityControlled( L"<html><head>", {},
																			 malformed, result)
										.status == CollectorParserStatus::REJECTED) ;
	ParserTestControl  limit ;									// 明示本文上限。
	const std::wstring huge( 4U * 1024U * 1024U + 1U, L'x') ;	// 上限を一文字だけ超える。
	DRIVERCRATE_EXPECT(
		context, parseIntelCollectorProductIdentityControlled( huge, {}, limit, result).status ==
					 CollectorParserStatus::LIMIT_EXCEEDED) ;
	const auto lengthy =
		replace( html, L"</body>",
				L"<script>" + std::wstring( 8192U, L'x') + L"</script><template><p>" +
					// 長いrawとtemplate。
					std::wstring( 1024U, L' ') + L"</p></template></body>") ;
	testParserCheckpoints(
		context,
		[&]( OfficialCollectorHttpControl &control) {
			return parseIntelCollectorProductIdentityControlled( lengthy, {}, control, result) ;
		},
		[&] { return result.products.empty() && result.seen == 0U ; }) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @copydoc drivercrate::test::runIntelCollectorIdentityParserTests
 */
//------------------------------------------------------------------------------
void runIntelCollectorIdentityParserTests( TestContext &context)
{
	testControlledIdentity( context) ;
	testOwnership( context) ;
	testNames( context) ;
	testKeysAndCollisions( context) ;
	testLimits( context) ;
	testHostileStructureAndExactLimits( context) ;
}

} // namespace drivercrate::test
