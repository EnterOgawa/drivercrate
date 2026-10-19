//------------------------------------------------------------------------------
/**
 * @file official_html_terms_tests.cpp
 * @brief 架空HTML許諾の一意性・全文・改変とstrict schemaを決定的に検査します。
 * @version 01.00.00
 * @date 2026/10/14
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/14  共通HTML/plain契約と一INF入力拒否の固定分母を追加。
 * </pre>
 *
 * @note 架空原byteだけをRAMで確認します。実device/HTTP/署名鍵/store/導入は使用しません。
 * @see docs/adr/0339-common-static-html-terms-binding.md
 */
//------------------------------------------------------------------------------
#include "platform/official_html_terms.h"
#include "platform/signed_index_acquisition_descriptor_internal.h"
#include "platform/common_driver_package.h"
#include "platform/official_driver_package.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"

#include <array>
#include <cstdio>
#include <string>
#include <string_view>
#include <windows.h>

namespace {

// 固定条件の有限集計です。
unsigned					assertions{} ;
// 後続成功で隠さない原失敗の集計です。
unsigned					failures{} ;
// 架空の一payload URLです。
constexpr std::string_view	PAYLOAD = "https://cdn.example.com/driver.zip" ;
// 原公開改訂です。package版やURLを代用しません。
constexpr std::wstring_view REVISION = L"Example License [v2026.10.14]" ;

/** @brief 一つの事前固定した期待を集計します。
 * @param[in] value その条件が全て成立する場合trueです。
 */
void						expect( const bool value)
{
	++assertions ;
	// 失敗条件を後続の成功へ除外しません。
	if( !value) {
		++failures ;
		std::printf( "FAIL assertion=%u\n", assertions) ;
	}
}

/** @brief 同原byteから共通digestを固定型へ写します。
 * @param[in] bytes 架空の完全UTF-8です。
 * @return 共通hashの固定32byteです。API失敗は期待失敗へ残します。
 */
[[nodiscard]] drivercrate::IndexManifestSha256 digest( const std::string_view bytes)
{
	std::wstring hash ;	// 同原byteからの共通digestです。
	expect( drivercrate::computeBytesSha256( bytes, hash) == 0U && hash.size() == 64U) ;
	drivercrate::IndexManifestSha256 result{} ;	// 部分成功を許可として使用しない架空値です。
	// 完全hashだけを固定byteへ写します。
	if( hash.size() == 64U) {
		// 全32byteを既知小文字hexから読みます。
		for( std::size_t index{}; index < result.size(); ++index) {
			const auto digit = []( const wchar_t value) {
				// 共通digestの既知字句だけを同期変換します。
				return value <= L'9' ? value - L'0' : value - L'a' + 10 ;
			} ; // 原digestだけを借用する純粋変換です。
			result[index] = static_cast<std::uint8_t>( digit( hash[index * 2U]) * 16 +
													  digit( hash[index * 2U + 1U])) ;
		}
	}

	return result ;
}

/** @brief 架空Unicode本文を厳密UTF-8 byteへ写します。
 * @param[in] value 有限な架空原文書/全文です。
 * @return 欠損なく符号化した架空byteです。
 */
[[nodiscard]] std::string bytes( const std::wstring_view value)
{
	const int count = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
										  static_cast<int>( value.size()), nullptr, 0, nullptr,
										  nullptr) ;	// 架空byteの必要容量です。
	expect( count > 0) ;
	// 失敗を代替文字へ変換しません。
	if( count <= 0) {
		return {} ;
	}

	std::string result( static_cast<std::size_t>( count), '\0') ;	// 完全な架空UTF-8出力です。
	expect( WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
							   static_cast<int>( value.size()), result.data(), count, nullptr,
							   nullptr) == count) ;
	return result ;
}

/** @brief 固定共通selector集合を作ります。
 * @return 未認証の架空selectorです。取得能力は持ちません。
 */
[[nodiscard]] drivercrate::IndexHtmlTermsExtraction extraction()
{
	drivercrate::IndexHtmlTermsExtraction value ;	// 固定した架空の要素集合です。
	value.profile			= "TEXTAREA_HTML_DOCUMENT_V1" ;
	value.selector			= {"textarea", "id", "terms"} ;
	value.containerSelector = {"div", "id", "consent"} ;
	value.linkSelector		= {"button", "data-modal", "one"} ;
	value.payloadAttribute	= "data-href" ;
	return value ;
}

/** @brief 同じ架空pageへ一つの原文書とpayload操作を結合します。
 * @param[in] document 完全な架空HTML文書です。
 * @return 原pageです。本文を再整形しません。
 */
[[nodiscard]] std::wstring page( const std::wstring_view document)
{
	return L"<html><body><div id=\"consent\"><div><textarea id=\"terms\">" +
		   std::wstring( document) +
		   L"</textarea></div></div><button data-modal=\"one\" "
		   L"data-href=\"https://cdn.example.com/driver.zip\">Download</button></body></html>" ;
}

/** @brief 一つの原文字列置換だけを行う固定改変fixtureです。
 * @param[in] value 架空原入力です。
 * @param[in] from 事前固定した一意な元文字列です。
 * @param[in] to 改変文字列です。
 * @return 改変入力です。置換位置欠損は期待失敗へ残します。
 */
template <class String>
[[nodiscard]] String replace( String value, const String &from, const String &to)
{
	const auto offset = value.find( from) ;	// 固定改変位置です。
	expect( offset != value.npos) ;
	// 不存在位置を別位置の改変へ変換しません。
	if( offset != value.npos) {
		value.replace( offset, from.size(), to) ;
	}

	return value ;
}

/** @brief 同原文書/全文と周辺markup・本文・別recordの正負を確認します。 */
void runHtml()
{
	constexpr std::wstring_view DOCUMENT =
		L"<html lang=\"en\"><head><title>Example License [v2026.10.14]</title><style>p{color:black}</style>"
		L"<link rel=\"stylesheet\" type=\"text/css\" href=\"/static/style.css\"/></head><body style=\"font-size:10pt\">"
		L"<p>Full &amp; complete <b>terms</b>.</p><ul><li>One&#160;condition.</li></ul>"
		L"<script type=\"text/javascript\" src=\"/static/inert.js\"></script></body></html>" ;	// 切り詰めない架空全文です。
	// 同原selectorへ結合する架空hashです。
	auto								  binding  = extraction() ;
	const auto							  original = page( DOCUMENT) ;	// 固定分母の正常pageです。
	drivercrate::HtmlTermsTextObservation observation ;					// 正例で独立に抽出する全文です。
	expect( drivercrate::extractStaticHtmlTerms( original, binding, PAYLOAD, REVISION, observation) ==
		   0U) ;
	expect( observation.document == DOCUMENT &&
		   observation.text.find( L"Full & complete terms.") != observation.text.npos) ;
	const auto documentBytes  = bytes( observation.document) ;	// 同原文書byteです。
	const auto textBytes	  = bytes( observation.text) ;		// 同抽出全文byteです。
	binding.documentSha256	  = digest( documentBytes) ;
	binding.documentSizeBytes = documentBytes.size() ;
	binding.textSha256		  = digest( textBytes) ;
	binding.textSizeBytes	  = textBytes.size() ;
	std::wstring verified ;	// 全hash検査後だけの全文です。
	expect( drivercrate::verifyStaticHtmlTerms( original, binding, PAYLOAD, REVISION, verified) ==
			   0U &&
		   verified == observation.text) ;
	const auto surrounding = replace(
		original, std::wstring{L"<body>"},
		std::wstring{
			L"<body><span><</span><p>unrelated surrounding markup</p>"}) ;	// 規約外の可視記号とmarkupだけの変化です。
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
			// 本文/原文書/関係/一意性の固定拒否分母です。
			L"<html><head><title>Example License [v2026.10.14]</title></head><body></body></html>")} ;
	// 全固定拒否を一度ずつ実行し、部分全文が返らないことも確認します。
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
		L"<!--<textarea id=\"terms\">fake</textarea>-->" + original ;	// コメントの偽要素です。
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

/** @brief Descriptor testだけで使う元Known textを要求型で読みます。
 * @param[in,out] reader 同原descriptorのreaderです。
 * @return 元Unknown理由または明示値です。能力へ昇格させません。
 */
[[nodiscard]] drivercrate::IndexObservedValue<std::string> readText(
	drivercrate::signed_index_acquisition::DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 3U> FIELDS{"state", "value",
													  "reason"} ;	// 固定Known textです。
	std::array<std::string, 3U>				   fields ;				// 元要求型です。
	reader.object( FIELDS, [&]( const std::size_t field) { fields[field] = reader.text( 512U) ; }) ;
	drivercrate::IndexObservedValue<std::string> result ;	// 元申告だけです。
	// このtestは明示KNOWNだけを値として保持します。
	if( fields[0] == "KNOWN") {
		result.value = fields[1] ;
	}

	result.reason = fields[2] ;
	return result ;
}

/** @brief 完全な原descriptor文法を共通native readerへ渡します。
 * @param[in] document 原textDocumentの固定JSONです。
 * @return 同意必須の全schemaが成功した場合trueです。
 */
[[nodiscard]] bool schema( const std::string_view document)
{
	const std::string value =
		std::string{
			R"({"schema":"driver-index-acquisition-v1","state":"UNKNOWN","reason":"unconfirmed route","payloadUrl":"","fileName":"","format":"UNKNOWN","expectedContentType":"","maximumBytes":0,"route":[],"terms":{"state":"ACCEPTANCE_REQUIRED","reason":"","evidenceUrl":"https://example.com/page","evidenceSha256":")"} +
		std::string( 64U, '1') +
		R"(","revisionKind":"VENDOR_LITERAL","revision":"Example License [v2026.10.14]","textDocument":)" +
		std::string( document) +
		// 固定元申告です。
		R"(},"prerequisites":{"state":"UNKNOWN","reason":"not yet checked","items":[]},"publisher":{"state":"UNKNOWN","value":"","reason":"not inspected"},"attestation":null})" ;
	try {
		drivercrate::signed_index_acquisition::DescriptorReader reader(
			value,
			drivercrate::IndexRecordsStatus::INVALID_EVIDENCE) ;	// 原UTF-8/深さ/集合を使います。
		const auto decoded = drivercrate::signed_index_acquisition::readDescriptor(
			reader, readText) ;	// 本物codecです。
		reader.finish() ;
		return decoded.terms.textDocument.has_value() ;
	} catch( const drivercrate::signed_index_json::Failure<drivercrate::IndexRecordsStatus> &) {
		return false ;
	}
}

/** @brief Plainの既存exact形とHTMLの全必須fieldを確認します。 */
void runSchema()
{
	const std::string hash( 64U, '1') ;	// 架空の非秘密元hashです。
	const std::string plain =
		R"({"url":"https://example.com/page","sha256":")" + hash +
		R"(","sizeBytes":20,"contentType":"text/plain; charset=utf-8"})" ;	// 旧四fieldです。
	expect( schema( plain)) ;
	const std::string html = replace(
		plain, std::string{R"(text/plain; charset=utf-8"})"},
		std::string{
			R"(text/html; charset=utf-8","htmlExtraction":{"profile":"TEXTAREA_HTML_DOCUMENT_V1","selector":{"tag":"textarea","attribute":"id","value":"terms"},"containerSelector":{"tag":"div","attribute":"id","value":"consent"},"linkSelector":{"tag":"button","attribute":"data-modal","value":"one"},"payloadAttribute":"data-href","documentSha256":")"} +
			hash + R"(","documentSizeBytes":100,"textSha256":")" + hash +
			R"(","textSizeBytes":80,"bindingEvidenceUrl":"https://example.com/binding.js","bindingEvidenceSha256":")" +
			hash + R"("}})") ;	// 明示HTMLの全fieldです。
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

/** @brief 未保護/未取得入力を一INF成功へ変換しない追加拒否を確認します。 */
void runSelectedInfRejection()
{
	drivercrate::DriverArchiveInput input ;						// 保護archiveや取得証拠を持たない架空入力です。
	drivercrate::CommonDriverPackageInspection	inspection ;	// 拒否後も成功INFを残しません。
	constexpr std::array<std::wstring_view, 5U> INF_NAMES{
		L"", L"../fake.inf", L"C:/fake.inf", L"fake.sys", L"fake.inf"} ;	// 固定拒否分母です。
	// 各未取得入力を一度だけ検査し、正常INFが発行されないことを確認します。
	for( const auto name : INF_NAMES) {
		const auto error = drivercrate::inspectSelectedCommonDriverPackage(
			input, drivercrate::OfficialDriverArchiveFormat::ZIP, name,
			inspection) ;	// 本物入口です。
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
	drivercrate::OfficialDownloadWorkspace workspace ;	// 未初期化の保護領域です。
	drivercrate::OfficialInfPackage		   package ;	// 元INF/CATを持たない架空metadataです。
	std::wstring publisher = L"sentinel" ;				// 拒否後に偽signerが残らないことを要求します。
	expect( drivercrate::readWindowsInfPackagePublisher( workspace, package, publisher) != 0U &&
		   publisher.empty()) ;
}

} // namespace

/** @brief 固定した共通HTML/plain/schema/一INF拒否条件を一度ずつ検査します。
 * @return 全期待成功0、原失敗が一件以上あれば1です。
 */
int main()
{
	runHtml() ;
	runSchema() ;
	runSelectedInfRejection() ;
	std::printf( "HTML_TERMS assertions=%u failures=%u realHttp=0 realDevice=0 realInstall=0\n",
				assertions, failures) ;
	return failures == 0U ? 0 : 1 ;
}
