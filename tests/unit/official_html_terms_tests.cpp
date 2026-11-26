//------------------------------------------------------------------------------
/**
 * @file official_html_terms_tests.cpp
 * @brief 公式規約の全文変換、改変と書式の拒否を架空入力で検査します
 * @version 01.02.00
 * @date 2026/10/14
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/14  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.00.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.01.00 Shunji Ogawa  2026/11/22  独立規約の限定CSPと表示属性の境界を回帰
 * Ver.01.02.00 Shunji Ogawa  2026/11/23  RTFのUnicodeと非実行の拒否境界を検査
 * </pre>
 *
 * @note 架空原byteだけをRAMで確認します。実device/HTTP/署名鍵/store/導入は使用しません
 * @see docs/adr/0339-common-static-html-terms-binding.md
 */
//------------------------------------------------------------------------------
#include "platform/official_html_terms.h"
#include "platform/official_rtf_terms.h"
#include "platform/signed_index_acquisition_descriptor_internal.h"
#include "platform/common_driver_package.h"
#include "platform/official_driver_package.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"

#include <array>
#include <cstddef>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <windows.h>

namespace {

// 固定条件の有限集計です
unsigned					assertions{} ;
// 後続成功で隠さない原失敗の集計です
unsigned					failures{} ;
// 架空の一payload URLです
constexpr std::string_view	PAYLOAD = "https://cdn.example.com/driver.zip" ;
// 原公開改訂です。package版やURLを代用しません
constexpr std::wstring_view REVISION = L"Example License [v2026.10.14]" ;

//------------------------------------------------------------------------------
/**
 * @brief 一つの事前固定した期待を集計します
 * @param[in] value その条件が全て成立する場合trueです
 */
//------------------------------------------------------------------------------
void						expect( const bool value)
{
	++assertions ;
	// 失敗条件を後続の成功へ除外しません
	if( !value) {
		++failures ;
		std::printf( "FAIL assertion=%u\n", assertions) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同原byteから共通digestを固定型へ写します
 * @param[in] bytes 架空の完全UTF-8です
 * @return 共通hashの固定32byteです。API失敗は期待失敗へ残します
 */
//------------------------------------------------------------------------------
[[nodiscard]] drivercrate::IndexManifestSha256 digest( const std::string_view bytes)
{
	std::wstring hash ;	// 同原byteからの共通digestです
	expect( drivercrate::computeBytesSha256( bytes, hash) == 0U && hash.size() == 64U) ;
	drivercrate::IndexManifestSha256 result{} ;	// 部分成功を許可として使用しない架空値です
	// 完全hashだけを固定byteへ写します
	if( hash.size() == 64U) {
		// 全32byteを既知小文字hexから読みます
		for( std::size_t index{}; index < result.size(); ++index) {
			const auto digit = []( const wchar_t value) {
				// 共通digestの既知字句だけを同期変換します
				return value <= L'9' ? value - L'0' : value - L'a' + 10 ;
			} ; // 原digestだけを借用する純粋変換です
			result[index] = static_cast<std::uint8_t>( digit( hash[index * 2U]) * 16 +
													  digit( hash[index * 2U + 1U])) ;
		}
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空Unicode本文を厳密UTF-8 byteへ写します
 * @param[in] value 有限な架空原文書/全文です
 * @return 欠損なく符号化した架空byteです
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string bytes( const std::wstring_view value)
{
	const int count = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
										  static_cast<int>( value.size()), nullptr, 0, nullptr,
										  nullptr) ;	// 架空byteの必要容量です
	expect( count > 0) ;
	// 失敗を代替文字へ変換しません
	if( count <= 0) {
		return {} ;
	}

	std::string result( static_cast<std::size_t>( count), '\0') ;	// 完全な架空UTF-8出力です
	expect( WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
							   static_cast<int>( value.size()), result.data(), count, nullptr,
							   nullptr) == count) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定共通selector集合を作ります
 * @return 未認証の架空selectorです。取得能力は持ちません
 */
//------------------------------------------------------------------------------
[[nodiscard]] drivercrate::IndexHtmlTermsExtraction extraction()
{
	drivercrate::IndexHtmlTermsExtraction value ;	// 固定した架空の要素集合です
	value.profile			= "TEXTAREA_HTML_DOCUMENT_V1" ;
	value.selector			= {"textarea", "id", "terms"} ;
	value.containerSelector = {"div", "id", "consent"} ;
	value.linkSelector		= {"button", "data-modal", "one"} ;
	value.payloadAttribute	= "data-href" ;
	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ架空pageへ一つの原文書とpayload操作を結合します
 * @param[in] document 完全な架空HTML文書です
 * @return 原pageです。本文を再整形しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring page( const std::wstring_view document)
{
	return L"<html><body><div id=\"consent\"><div><textarea id=\"terms\">" +
		   std::wstring( document) +
		   L"</textarea></div></div><button data-modal=\"one\" "
		   L"data-href=\"https://cdn.example.com/driver.zip\">Download</button></body></html>" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つの原文字列置換だけを行う固定改変fixtureです
 * @tparam String find/replaceを備える合成文字列型です
 * @param[in] value 架空原入力です
 * @param[in] from 事前固定した一意な元文字列です
 * @param[in] to 改変文字列です
 * @return 改変入力です。置換位置欠損は期待失敗へ残します
 */
//------------------------------------------------------------------------------
template <class String>
[[nodiscard]] String replace( String value, const String &from, const String &to)
{
	const auto offset = value.find( from) ;	// 固定改変位置です
	expect( offset != value.npos) ;
	// 不存在位置を別位置の改変へ変換しません
	if( offset != value.npos) {
		value.replace( offset, from.size(), to) ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同原文書/全文と周辺markup・本文・別recordの正負を確認します
 */
//------------------------------------------------------------------------------
void runHtml()
{
	constexpr std::wstring_view DOCUMENT =
		L"<html lang=\"en\"><head><title>Example License [v2026.10.14]</title><style>p{color:black}</style>"
		L"<link rel=\"stylesheet\" type=\"text/css\" href=\"/static/style.css\"/></head><body style=\"font-size:10pt\">"
		L"<p>Full &amp; complete <b>terms</b>.</p><ul><li>One&#160;condition.</li></ul>"
		L"<script type=\"text/javascript\" src=\"/static/inert.js\"></script></body></html>" ;	// 切り詰めない架空全文です
	// 同原selectorへ結合する架空hashです
	auto								  binding  = extraction() ;
	const auto							  original = page( DOCUMENT) ;	// 固定分母の正常pageです
	drivercrate::HtmlTermsTextObservation observation ;					// 正例で独立に抽出する全文です
	expect( drivercrate::extractStaticHtmlTerms( original, binding, PAYLOAD, REVISION, observation) ==
		   0U) ;
	expect( observation.document == DOCUMENT &&
		   observation.text.find( L"Full & complete terms.") != observation.text.npos) ;
	const auto documentBytes  = bytes( observation.document) ;	// 同原文書byteです
	const auto textBytes	  = bytes( observation.text) ;		// 同抽出全文byteです
	binding.documentSha256	  = digest( documentBytes) ;
	binding.documentSizeBytes = documentBytes.size() ;
	binding.textSha256		  = digest( textBytes) ;
	binding.textSizeBytes	  = textBytes.size() ;
	std::wstring verified ;	// 全hash検査後だけの全文です
	expect( drivercrate::verifyStaticHtmlTerms( original, binding, PAYLOAD, REVISION, verified) ==
			   0U &&
		   verified == observation.text) ;
	const auto surrounding = replace(
		original, std::wstring{L"<body>"},
		std::wstring{
			L"<body><span><</span><p>unrelated surrounding markup</p>"}) ;	// 規約外の可視記号とmarkupだけの変化です
	expect( drivercrate::verifyStaticHtmlTerms( surrounding, binding, PAYLOAD, REVISION, verified) ==
			   0U &&
		   verified == observation.text) ;
	const std::array<std::wstring, 10U> REJECTED{
		replace( original, std::wstring{L"complete"}, std::wstring{L"changed"}),
		replace( original, std::wstring{L"color:black"}, std::wstring{L"color:blue"}),
		replace( original, std::wstring{L"https://cdn.example.com/driver.zip"},
				std::wstring{L"https://cdn.example.com/other.zip"}),
		replace( original, std::wstring{L"<div id=\"consent\">"},
				std::wstring{L"<div id=\"different\">"}),
		original +
			L"<button data-modal=\"one\" data-href=\"https://cdn.example.com/driver.zip\"></button>",
		original + L"<textarea id=\"terms\">unrelated</textarea>",
		replace( original, std::wstring{L"data-modal=\"one\""},
				std::wstring{L"data-modal=\"one\" data-modal=\"one\""}),
		replace( original, std::wstring{L"&amp;"}, std::wstring{L"&unknown;"}),
		replace( original, std::wstring{L"<p>Full"}, std::wstring{L"<iframe>Full"}),
		page(
			// 本文/原文書/関係/一意性の固定拒否分母です
			L"<html><head><title>Example License [v2026.10.14]</title></head><body></body></html>")} ;
	// 全固定拒否を一度ずつ実行し、部分全文が返らないことも確認します
	for( const auto &invalid : REJECTED) {
		verified = L"sentinel" ;
		expect( drivercrate::verifyStaticHtmlTerms( invalid, binding, PAYLOAD, REVISION, verified) !=
				   0U &&
			   verified.empty()) ;
	}

	expect( drivercrate::verifyStaticHtmlTerms( original, binding, PAYLOAD, L"Other revision",
											  verified) != 0U &&
		   verified.empty()) ;
	++binding.textSizeBytes ;
	expect( drivercrate::verifyStaticHtmlTerms( original, binding, PAYLOAD, REVISION, verified) !=
		   0U) ;
	--binding.textSizeBytes ;
	binding.textSha256[0] ^= 1U ;
	expect( drivercrate::verifyStaticHtmlTerms( original, binding, PAYLOAD, REVISION, verified) !=
		   0U) ;
	const auto hidden =
		L"<!--<textarea id=\"terms\">fake</textarea>-->" + original ;	// コメントの偽要素です
	binding.textSha256[0] ^= 1U ;
	expect( drivercrate::verifyStaticHtmlTerms( hidden, binding, PAYLOAD, REVISION, verified) == 0U) ;
	expect( drivercrate::hasSingleStaticHtmlScriptReference(
		original + L"<script src=\"/binding.js\"></script>", L"https://example.com/binding.js",
		L"/binding.js")) ;
	expect( !drivercrate::hasSingleStaticHtmlScriptReference(
		original + L"<!--<script src=\"/binding.js\"></script>-->",
		L"https://example.com/binding.js", L"/binding.js")) ;
	expect( !drivercrate::hasSingleStaticHtmlScriptReference(
		original + L"<script src=\"/binding.js\"></script><script src=\"/binding.js\"></script>",
		L"https://example.com/binding.js", L"/binding.js")) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 静的独立規約だけの外側CSP・表示属性と原文書の完全照合を確認します
 */
//------------------------------------------------------------------------------
void runStaticSectionLayout()
{
	drivercrate::IndexHtmlTermsExtraction binding ;	// 架空の独立規約だけを選ぶ宣言です
	binding.profile	 = "STATIC_HTML_SECTION_V1" ;
	binding.selector = {"div", "id", "fixture-license"} ;
	// 元の属性と改訂を持つ架空の独立規約です
	const std::wstring section =
		L"<div id=\"fixture-license\"><h2 data-rg-n=\"TitleText\">Example License [v2026.10.14]</h2>"
		L"<div data-rg-n=\"BodyText\" data-eb-item-id=\"layout#c1\"><p>Full terms.</p></div></div>" ;
	// 同じ長さの試験を組み立てるための開始属性です
	const std::wstring cspStart =
		L"<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; " ;
	const std::wstring cspEnd =
		L"\" data-report-uri=\"https://example.com/report\">" ;	// 非実行の報告先属性です
	const auto csp = [&cspStart, &cspEnd]( const std::size_t length) {
		return cspStart + std::wstring( length - cspStart.size() - cspEnd.size(), L'x') + cspEnd ;
	} ; // 試験中だけ固定外枠を借用し、指定どおりの長さの架空要素を作ります
	const auto document = [&section]( const std::wstring &head) {
		return L"<html><head>" + head + L"</head><body>" + section + L"</body></html>" ;
	} ; // 試験中だけ同じ原セクションを借用します
	const auto extended = document( csp( 9762U)) ;		// 元HTMLと同じ長さの架空のCSPです
	drivercrate::HtmlTermsTextObservation observation ;	// 同じ原文書と抽出全文です
	expect( drivercrate::extractStaticHtmlTerms( extended, binding, PAYLOAD, REVISION, observation) ==
			   0U &&
		   observation.document == section &&
		   observation.text.find( L"Full terms.") != observation.text.npos) ;
	const auto originalText	  = observation.text ;		// 表示属性を含まない同じ全文です
	const auto sectionUtf8	  = bytes( section) ;		// 表示属性を含む同じ原セクションです
	const auto textUtf8		  = bytes( originalText) ;	// 原セクションとは別に照合する全文です
	binding.documentSha256	  = digest( sectionUtf8) ;
	binding.documentSizeBytes = sectionUtf8.size() ;
	binding.textSha256		  = digest( textUtf8) ;
	binding.textSizeBytes	  = textUtf8.size() ;
	std::wstring verified ;	// 原文書と全文の照合が成功した表示用全文です
	expect( drivercrate::verifyStaticHtmlTerms( extended, binding, PAYLOAD, REVISION, verified) ==
			   0U &&
		   verified == originalText) ;

	// 既定のタグ上限と、明示CSPだけに適用する拡張の終端を確認します
	for( const auto length : {4096U, 4097U, 16384U}) {
		expect( drivercrate::extractStaticHtmlTerms( document( csp( length)), binding, PAYLOAD,
												   REVISION, observation) == 0U) ;
	}

	const auto altered =
		replace( extended, std::wstring{L"layout#c1"},
				std::wstring{L"layout#c2"}) ;	// 可読全文が変わらない原属性の変更です
	expect( drivercrate::extractStaticHtmlTerms( altered, binding, PAYLOAD, REVISION, observation) ==
			   0U &&
		   observation.text == originalText) ;
	expect( drivercrate::verifyStaticHtmlTerms( altered, binding, PAYLOAD, REVISION, verified) !=
			   0U &&
		   verified.empty()) ;

	const auto longCsp = csp( 9762U) ;	// 拒否対照に共通する外枠の長い宣言です
	// title中の非要素を独立規約の二つ目の選択先として扱いません
	expect(
		drivercrate::extractStaticHtmlTerms( document( L"<title>" + section + L"</title>" + longCsp),
											binding, PAYLOAD, REVISION, observation) == 0U) ;
	const auto otherTag = L"<div" + std::wstring( 4092U, L' ') +
						  L">" ;	// 末尾の空白を含めて通常上限を1文字超える要素です
	const std::array<std::wstring, 16U> REJECTED{
		document( csp( 16385U)),
		document( otherTag),
		document(
			replace( longCsp, std::wstring{L"Content-Security-Policy"}, std::wstring{L"refresh"})),
		document( replace( longCsp, std::wstring{L"data-report-uri"}, std::wstring{L"data-other"})),
		document( replace( longCsp, std::wstring{L"https://"}, std::wstring{L"http://"})),
		document( replace( longCsp, std::wstring{L"\" data-report-uri"},
						 std::wstring{L"\"data-report-uri"})),
		document( replace( longCsp, std::wstring{L"content=\""},
						 std::wstring{L"content=\"x\" content=\""})),
		document( replace( longCsp, std::wstring{L"/report\">"},
						 std::wstring{L"/report\" data-other=\"x\">"})),
		document( longCsp.substr( 0U, longCsp.size() - 2U)),
		L"<html><head></head><body>" + longCsp + section + L"</body></html>",
		L"<html><head></head><body><div id=\"fixture-license\">" + longCsp +
			L"<p>Example License [v2026.10.14]</p></div></body></html>",
		document( longCsp) + section,
		replace( extended, std::wstring{L"data-rg-n=\"TitleText\""},
				std::wstring{L"data-other=\"x\""}),
		replace( extended, std::wstring{L"data-rg-n=\"TitleText\""},
				std::wstring{L"onclick=\"invalid\""}),
		replace( extended, std::wstring{L"layout#c1"}, std::wstring{L"layout c1"}),
		replace( extended, std::wstring{L"layout#c1"},
				// 構造の固定拒否集合です
				std::wstring( 65U, L'x'))} ;
	// 独立規約が部分抽出を返さないことまで確認します
	for( const auto &invalid : REJECTED) {
		expect( drivercrate::extractStaticHtmlTerms( invalid, binding, PAYLOAD, REVISION,
												   observation) != 0U &&
			   observation.document.empty() && observation.text.empty()) ;
	}

	const auto withLink =
		extended +
		L"<a href=\"https://example.com/license\">License</a>" ;	// 既存リンク検査の対照です
	expect( !drivercrate::hasStaticHtmlDocumentLink( withLink, "https://example.com/license")) ;
	expect( !drivercrate::visitPublicHtmlTags( withLink, []( const auto &) { return true ; })) ;
	expect( drivercrate::extractStaticHtmlTerms( longCsp + page( section), extraction(), PAYLOAD,
											   REVISION, observation) != 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Descriptor testだけで使う元Known textを要求型で読みます
 * @param[in,out] reader 同原descriptorのreaderです
 * @return 元Unknown理由または明示値です。能力へ昇格させません
 */
//------------------------------------------------------------------------------
[[nodiscard]] drivercrate::IndexObservedValue<std::string> readText(
	drivercrate::signed_index_acquisition::DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 3U> FIELDS{"state", "value",
													  "reason"} ;	// 固定Known textです
	std::array<std::string, 3U>				   fields ;				// 元要求型です
	reader.object( FIELDS, [&]( const std::size_t field) { fields[field] = reader.text( 512U) ; }) ;
	drivercrate::IndexObservedValue<std::string> result ;	// 元申告だけです
	// このtestは明示KNOWNだけを値として保持します
	if( fields[0] == "KNOWN") {
		result.value = fields[1] ;
	}

	result.reason = fields[2] ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 完全な原descriptor文法を共通native readerへ渡します
 * @param[in] document 原textDocumentの固定JSONです
 * @return 同意必須の全schemaが成功した場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool schema( const std::string_view document)
{
	const std::string value =
		std::string{
			R"({"schema":"driver-index-acquisition-v1","state":"UNKNOWN","reason":"unconfirmed route","payloadUrl":"","fileName":"","format":"UNKNOWN","expectedContentType":"","maximumBytes":0,"route":[],"terms":{"state":"ACCEPTANCE_REQUIRED","reason":"","evidenceUrl":"https://example.com/page","evidenceSha256":")"} +
		std::string( 64U, '1') +
		R"(","revisionKind":"VENDOR_LITERAL","revision":"Example License [v2026.10.14]","textDocument":)" +
		std::string( document) +
		// 固定元申告です
		R"(},"prerequisites":{"state":"UNKNOWN","reason":"not yet checked","items":[]},"publisher":{"state":"UNKNOWN","value":"","reason":"not inspected"},"attestation":null})" ;
	try {
		drivercrate::signed_index_acquisition::DescriptorReader reader(
			value,
			drivercrate::IndexRecordsStatus::INVALID_EVIDENCE) ;	// 原UTF-8/深さ/集合を使います
		const auto decoded = drivercrate::signed_index_acquisition::readDescriptor(
			reader, readText) ;	// 本物codecです
		reader.finish() ;
		return decoded.terms.textDocument.has_value() ;
	} catch( const drivercrate::signed_index_json::Failure<drivercrate::IndexRecordsStatus> &) {
		return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Plainの既存exact形とHTMLの全必須fieldを確認します
 */
//------------------------------------------------------------------------------
void runSchema()
{
	const std::string hash( 64U, '1') ;	// 架空の非秘密元hashです
	const std::string plain =
		R"({"url":"https://example.com/page","sha256":")" + hash +
		R"(","sizeBytes":20,"contentType":"text/plain; charset=utf-8"})" ;	// 旧四fieldです
	expect( schema( plain)) ;
	const std::string html = replace(
		plain, std::string{R"(text/plain; charset=utf-8"})"},
		std::string{
			R"(text/html; charset=utf-8","htmlExtraction":{"profile":"TEXTAREA_HTML_DOCUMENT_V1","selector":{"tag":"textarea","attribute":"id","value":"terms"},"containerSelector":{"tag":"div","attribute":"id","value":"consent"},"linkSelector":{"tag":"button","attribute":"data-modal","value":"one"},"payloadAttribute":"data-href","documentSha256":")"} +
			hash + R"(","documentSizeBytes":100,"textSha256":")" + hash +
			R"(","textSizeBytes":80,"bindingEvidenceUrl":"https://example.com/binding.js","bindingEvidenceSha256":")" +
			hash + R"("}})") ;	// 明示HTMLの全fieldです
	expect( schema( html)) ;
	expect( !schema( replace( plain, std::string{"text/plain"}, std::string{"text/html"}))) ;
	expect( !schema( replace( html, std::string{"text/html"}, std::string{"text/plain"}))) ;
	expect( !schema( replace( html, std::string{R"("textSizeBytes":80,)"}, std::string{}))) ;
	expect( !schema( replace( html, std::string{R"("textSizeBytes":80)"},
						   std::string{R"("textSizeBytes":"80")"}))) ;
	expect( !schema(
		replace( html, std::string{R"("textSizeBytes":80)"}, std::string{R"("textSizeBytes":0)"}))) ;
	expect( !schema( replace( html, std::string{R"("profile":"TEXTAREA_HTML_DOCUMENT_V1")"},
						   std::string{R"("profile":"UNKNOWN")"}))) ;
	expect( !schema( replace( html, std::string{R"("payloadAttribute":"data-href")"},
						   std::string{R"("payloadAttribute":"onclick")"} + R"(,"unknown":true)"))) ;
	expect( !schema(
		replace( html, std::string{R"("tag":"textarea")"}, std::string{R"("tag":"iframe")"}))) ;
	expect( !schema(
		replace( html, std::string{R"("attribute":"id")"}, std::string{R"("attribute":"ID")"}))) ;
	expect( !schema( replace( html, std::string{R"("selector":)"},
						   std::string{R"("selector":null,"selector":)"}))) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未保護/未取得入力を一INF成功へ変換しない追加拒否を確認します
 */
//------------------------------------------------------------------------------
void runSelectedInfRejection()
{
	drivercrate::DriverArchiveInput			   input ;		// 保護archiveや取得証拠を持たない架空入力です
	drivercrate::CommonDriverPackageInspection inspection ;	// 拒否後も成功INFを残しません
	constexpr std::array<std::wstring_view, 5U> INF_NAMES{
		L"", L"../fake.inf", L"C:/fake.inf", L"fake.sys", L"fake.inf"} ;	// 固定拒否分母です
	// 各未取得入力を一度だけ検査し、正常INFが発行されないことを確認します
	for( const auto name : INF_NAMES) {
		const auto error = drivercrate::inspectSelectedCommonDriverPackage(
			input, drivercrate::OfficialDriverArchiveFormat::ZIP, name,
			inspection) ;	// 本物入口です
		expect( error != 0U && inspection.infs.empty()) ;
	}

	input.scanSessionId = 1U ;
	input.byteCount		= 128ULL * 1024ULL * 1024ULL + 1U ;
	expect( drivercrate::inspectSelectedCommonDriverPackage(
			   input, drivercrate::OfficialDriverArchiveFormat::ZIP, L"fake.inf", inspection) !=
			   0U &&
		   inspection.infs.empty()) ;
	input.byteCount = 1U ;
	expect( drivercrate::inspectSelectedCommonDriverPackage(
			   input, static_cast<drivercrate::OfficialDriverArchiveFormat>( 99U), L"fake.inf",
			   inspection) != 0U &&
		   inspection.infs.empty()) ;
	expect( drivercrate::inspectSelectedCommonDriverPackage(
			   input, drivercrate::OfficialDriverArchiveFormat::ZIP, std::wstring( 261U, L'a'),
			   inspection) != 0U &&
		   inspection.infs.empty()) ;
	expect( drivercrate::inspectSelectedCommonDriverPackage(
			   input, drivercrate::OfficialDriverArchiveFormat::ZIP, L"fake.inf", inspection,
			   [] { return true ; }) ==
			   static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) &&
		   inspection.infs.empty()) ;
	drivercrate::OfficialDownloadWorkspace workspace ;	// 未初期化の保護領域です
	drivercrate::OfficialInfPackage		   package ;	// 元INF/CATを持たない架空metadataです
	std::wstring publisher = L"sentinel" ;				// 拒否後に偽signerが残らないことを要求します
	expect( drivercrate::readWindowsInfPackagePublisher( workspace, package, publisher) != 0U &&
		   publisher.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じUTF-16文字列へ表示するRTFの正例と、本文を返さない形式を確認します
 * @note 元配布の本文は保存せず、英日とマルチバイト代替は架空文を使います
 */
//------------------------------------------------------------------------------
void runRtf()
{
	const auto decode = []( const std::string_view raw, std::wstring &body) {
		return drivercrate::decodeOfficialRtfTerms( std::as_bytes( std::span{raw}), body) ;
	} ; // 原バイトを複製せず、変換中だけ生存する入力位置を渡します
	std::wstring			   body = L"old" ;	// 前回結果を成功・拒否の両経路で置き換える出力です
	constexpr std::string_view MIXED =
		// 元段落、書式のscope、引用符とサロゲートを混ぜた正例です
		R"rtf({\rtf1\ansi\ansicpg1252 1. \{\u21069?{\uc2\u24460\'ab\'a9}\u26085?\}\line\tab\'93\rquote\'94\par\par\uc0\u-10179\u-8704})rtf" ;
	expect( decode( MIXED, body) && body == L"1. {前後日}\r\n\t\u201c\u2019\u201d\r\n\r\n\U0001f600") ;
	constexpr std::array<std::string_view, 16> INVALID{
		R"({\rtf1\ansi terms{\object data}})",
		R"({\rtf1\ansi terms{\pict data}})",
		R"({\rtf1\ansi terms{\field{\*\fldinst data}}})",
		R"({\rtf1\ansi{\info\object data}terms})",
		R"({\rtf1\ansi terms{\*\unknown extra}})",
		R"({\rtf1\ansi terms\v hidden})",
		R"({\rtf1\ansi terms\pn number})",
		R"({\rtf1\ansi terms\itap1 table})",
		R"({\rtf1\ansi terms\rtlch alternate})",
		R"({\rtf1\ansi terms\bin10})",
		R"({\rtf1\ansi terms\uc2\u65?})",
		R"({\rtf1\ansi terms\uc0\u0})",
		R"({\rtf1\ansi terms\uc0\u-10179})",
		R"({\rtf1\ansi terms\uc0\u8238})",
		R"({\rtf1\ansi\ansicpg1252 terms\'81})",
		R"({\rtf1\ansi terms)"} ;	// 埋込み作用、本文消失、書式・文字集合の不明と閉じの欠落です
	// 各拒否で前回の結果も部分本文も残らないことを確認します
	for( const auto raw : INVALID) {
		body = L"old" ;
		expect( !decode( raw, body) && body.empty()) ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 固定した公式規約のHTML、RTF、schemaと一INFの拒否条件を検査します
 * @return 全期待成功0、原失敗が一件以上あれば1です
 */
//------------------------------------------------------------------------------
int main()
{
	runHtml() ;
	runRtf() ;
	runStaticSectionLayout() ;
	runSchema() ;
	runSelectedInfRejection() ;
	std::printf( "HTML_TERMS assertions=%u failures=%u realHttp=0 realDevice=0 realInstall=0\n",
				assertions, failures) ;
	return failures == 0U ? 0 : 1 ;
}
