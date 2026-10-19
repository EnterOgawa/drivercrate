//------------------------------------------------------------------------------
/**
 * @file asix_catalog_parser_tests.cpp
 * @brief ASIX AX88179A公式検索単体試験実装。
 * @version 01.00.00
 * @date 2026/09/06
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX候補発行と指定導入の共通接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  未監査reportと失効後の再利用拒否を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX検索snapshotとrank callback境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  二page完了順序・承認・取得根拠拒否を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Provider取得準備snapshot試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Terms解析と取得前record結合試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  数値配布IDとRelease差分試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 固定公式host形式と架空配布ID・Terms本文・opaque device IDだけを使用します。実payload、Hardware ID、instance path、実
 *       Terms本文はfixtureへ保存しません。
 */
//------------------------------------------------------------------------------

#include "asix_catalog_parser_tests.h"

#include "core/candidate_audit.h"
#include "core/official_preparation_operation.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/asix_catalog_parser.h"
#include "platform/asix_update_provider.h"
#include "platform/official_prepared_acquisition.h"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {

// 現行公式pageの必須構造だけを再現し、実在するfile IDを含めない合成fixture。
constexpr std::wstring_view VALID_PAGE =
	LR"(<html><h1 class="txt_cover_title">AX88179A</h1>)"
	LR"(<p>USB 3.2 Gen1 to Gigabit Ethernet Controller</p>)"
	LR"(<h3 class="list_p">Software &amp; Tools</h3>)"
	LR"(<a href="https://www.asix.com.tw/en/useterm">Terms Of Use</a>)"
	LR"(<div class="table_item"><div class="left"><p>Windows 11 64-bit Driver</p>)"
	LR"(<span>For x64 CPU platform, HLK/WHCK certified</span></div><div class="right">)"
	LR"(<p>Version<br/>4.22.1.0</p><p>Release Date<br/>2026-01-15</p>)"
	LR"(<p>File Size<br/>129.5 KB</p><a class="nocg" )"
	LR"(data-href="https://www.asix.com.tw/en/support/download/file/9001"></a></div></div>)"
	LR"(<div class="table_item"><div class="left">)"
	LR"(<p>Windows 11 64-bit HLK/WHCK drivers setup program</p></div></div>)"
	LR"(<div class="table_item"><div class="left"><p>Windows 11 ARM 64-bit Driver</p>)"
	LR"(</div></div>)"
	LR"(<div class="table_item"><div class="left"><p>Windows 10 64-bit Driver</p>)"
	LR"(<span>For x64 CPU platform, HLK/WHCK certified</span></div><div class="right">)"
	LR"(<p>Version<br/>4.20.1.0</p><p>Release Date<br/>2026-01-15</p>)"
	LR"(<p>File Size<br/>129.2 KB</p><a class="nocg" )"
	LR"(data-href="https://www.asix.com.tw/en/support/download/file/9002"></a></div></div>)"
	LR"(<div class="table_item"><div class="left"><p>Windows 8 64-bit Driver</p>)"
	LR"(</div></div></html>)" ;
// 現行Terms mainのtag、親子関係、四見出しだけを架空文で再現する合成fixture。
constexpr std::wstring_view VALID_TERMS =
	LR"(<html><body><main><div class="inside_bg"><section class="container">)"
	LR"(<div class="tit_wrap"><p class="title">TERMS OF USE</p>)"
	LR"(<p>Synthetic notice.<br>Read before use.</p></div>)"
	LR"(<article class="text_wrap"><div class="txt_contant">)"
	LR"(<section><h3 class="txt_title">Terms</h3>)"
	LR"(<p>Synthetic terms &amp; conditions.</p>)"
	LR"(<ul class="list"><li>Keep this synthetic notice.</li></ul></section>)"
	LR"(<section><h3 class="txt_title">Account/Password Policy</h3>)"
	LR"(<p>No real account terms are copied.</p></section>)"
	LR"(<section><h3 class="txt_title">Trademark</h3>)"
	LR"(<p>Synthetic trademark notice.</p></section>)"
	LR"(<section><h3 class="txt_title">Disclaimer</h3>)"
	LR"(<p>Synthetic disclaimer.</p></section>)"
	LR"(</div></article></section></div></main><footer>Not part of the terms.</footer>)"
	LR"(</body></html>)" ;
constexpr ScanSessionId SESSION = 71U ;	// 合成ASIX検索で使用するsession ID。

//------------------------------------------------------------------------------
/**
 * @brief Hardware ID、instance path、serial numberを含めない。
 *
 * @param[in] identity 架空のopaque device identity。
 * @return ASIX AX88179Aを示す非機密snapshotの所有値。
 */
//------------------------------------------------------------------------------
OfficialCatalogDevice	asixDevice( std::wstring identity)
{
	OfficialCatalogDevice device ;	// 試験ごとに変更できるlocal snapshot。
	device.deviceIdentity  = std::move( identity) ;
	device.manufacturer	   = L"ASIX Electronics Corp." ;
	device.model		   = L"ASIX AX88179A USB Ethernet Adapter" ;
	device.driverClass	   = L"Net" ;
	device.deviceClassGuid = L"{4d36e972-e325-11ce-bfc1-08002be10318}" ;
	return device ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つのx64 driver行と数値配布IDを解析し、clientごとに一行を選択する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testValidPageAndOsSelection( TestContext &context)
{
	AsixAx88179aCatalog catalog ;	// 二OS分のparser出力。
	DRIVERCRATE_EXPECT( context, parseAsixAx88179aProductPage( VALID_PAGE, catalog)) ;
	DRIVERCRATE_EXPECT( context, catalog.windows10.version == L"4.20.1.0") ;
	DRIVERCRATE_EXPECT( context, catalog.windows10.releaseKey == L"9002") ;
	DRIVERCRATE_EXPECT( context, catalog.windows10.displaySize == L"129.2 KB") ;
	DRIVERCRATE_EXPECT( context, catalog.windows10.downloadUrl ==
									L"https://www.asix.com.tw/en/support/download/file/9002") ;
	DRIVERCRATE_EXPECT( context, catalog.windows11.version == L"4.22.1.0") ;
	DRIVERCRATE_EXPECT( context, catalog.windows11.releaseKey == L"9001") ;
	DRIVERCRATE_EXPECT( context, catalog.windows11.releaseDate == L"2026-01-15") ;

	AsixDriverPageEntry entry ;	// OS選択後の表示情報。
	DRIVERCRATE_EXPECT( context, selectAsixAx88179aWindowsEntry( catalog, false, 19'045U, entry)) ;
	DRIVERCRATE_EXPECT( context, entry.family == AsixWindowsClientFamily::WINDOWS10_X64) ;
	DRIVERCRATE_EXPECT( context, selectAsixAx88179aWindowsEntry( catalog, false, 22'000U, entry)) ;
	DRIVERCRATE_EXPECT( context, entry.family == AsixWindowsClientFamily::WINDOWS11_X64) ;
	DRIVERCRATE_EXPECT( context, !selectAsixAx88179aWindowsEntry( catalog, true, 26'100U, entry)) ;
	DRIVERCRATE_EXPECT( context, !selectAsixAx88179aWindowsEntry( catalog, false, 0U, entry)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空Terms全文とOS別製品行を算出識別子付き取得前recordへ結合する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testTermsPageAndReleaseJoin( TestContext &context)
{
	AsixTermsSnapshot terms ;	// 正常な架空Termsから得る全文snapshot。
	DRIVERCRATE_EXPECT( context, parseAsixTermsPage( VALID_TERMS, terms)) ;
	DRIVERCRATE_EXPECT( context, terms.text.starts_with( L"TERMS OF USE\r\nSynthetic notice.")) ;
	DRIVERCRATE_EXPECT( context,
					   terms.text.find( L"Synthetic terms & conditions.") != std::wstring::npos) ;
	DRIVERCRATE_EXPECT( context, terms.text.find( L"Not part of the terms.") == std::wstring::npos) ;
	DRIVERCRATE_EXPECT( context, terms.text.find( L'<') == std::wstring::npos) ;
	DRIVERCRATE_EXPECT( context, terms.revision.starts_with( L"DriverCrate content SHA-256: ")) ;

	OfficialReleaseRecord windows11 ;	// Windows 11向けのTerms結合済み配布record。
	DRIVERCRATE_EXPECT( context, makeAsixAx88179aPreparedRelease( VALID_PAGE, VALID_TERMS, false,
																26'100U, windows11)) ;
	DRIVERCRATE_EXPECT( context, windows11.family == OfficialReleaseFamily::ASIX_AX88179A) ;
	DRIVERCRATE_EXPECT( context, windows11.releaseKey == L"9001") ;
	DRIVERCRATE_EXPECT( context, windows11.fileName.empty()) ;
	DRIVERCRATE_EXPECT( context, windows11.packageVersion == L"4.22.1.0") ;
	DRIVERCRATE_EXPECT( context, windows11.publishedDate == L"2026-01-15") ;
	DRIVERCRATE_EXPECT( context, !windows11.publishedSizeBytes.has_value()) ;
	DRIVERCRATE_EXPECT( context, windows11.publishedSha256.empty()) ;
	DRIVERCRATE_EXPECT( context,
					   windows11.license == OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD) ;
	DRIVERCRATE_EXPECT( context, windows11.eulaRevision == terms.revision) ;
	DRIVERCRATE_EXPECT( context, windows11.eulaText == terms.text) ;
	DRIVERCRATE_EXPECT( context, windows11.parserRevision == 2U) ;
	DRIVERCRATE_EXPECT( context, validPreparedReleaseIdentity( windows11)) ;

	OfficialReleaseRecord windows10 ;	// 同じ二pageから選択するWindows 10向けrecord。
	DRIVERCRATE_EXPECT( context, makeAsixAx88179aPreparedRelease( VALID_PAGE, VALID_TERMS, false,
																19'045U, windows10)) ;
	DRIVERCRATE_EXPECT( context, windows10.releaseKey == L"9002") ;
	DRIVERCRATE_EXPECT( context, windows10.packageVersion == L"4.20.1.0") ;
	DRIVERCRATE_EXPECT( context, windows10.eulaRevision == windows11.eulaRevision) ;

	std::wstring	  changedTerms( VALID_TERMS) ;	// 本文一文字列を変更する別snapshot。
	const std::size_t disclaimer =
		// 架空Disclaimer本文の置換位置。
		changedTerms.find( L"Synthetic disclaimer.") ;
	DRIVERCRATE_EXPECT( context, disclaimer != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( disclaimer != std::wstring::npos) {
		changedTerms.replace( disclaimer, std::wstring_view( L"Synthetic disclaimer.").size(),
							 L"Changed synthetic disclaimer.") ;
		AsixTermsSnapshot changed ;	// 変更後本文から得る別の算出識別子。
		DRIVERCRATE_EXPECT( context, parseAsixTermsPage( changedTerms, changed)) ;
		DRIVERCRATE_EXPECT( context, changed.revision != terms.revision) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 見出し、tag、entity、容量、Terms参照またはOS境界の変更を拒否する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testTermsPageRejections( TestContext &context)
{
	AsixTermsSnapshot snapshot ;											// 各不正入力後に初期値へ戻るべき出力。
	std::wstring	  missingHeading( VALID_TERMS) ;						// 必須Trademark見出しを変更したpage。
	const std::size_t heading = missingHeading.find( L">Trademark</h3>") ;	// 見出し位置。
	DRIVERCRATE_EXPECT( context, heading != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( heading != std::wstring::npos) {
		missingHeading.replace( heading, std::wstring_view( L">Trademark</h3>").size(),
							   L">Changed heading</h3>") ;
		DRIVERCRATE_EXPECT( context, !parseAsixTermsPage( missingHeading, snapshot)) ;
	}

	std::wstring	  duplicateHeading( VALID_TERMS) ;	// Terms見出しmarkerを二つ持つpage。
	const std::size_t termsHeading =
		// 挿入基準位置。
		duplicateHeading.find( L"<h3 class=\"txt_title\">Terms</h3>") ;
	DRIVERCRATE_EXPECT( context, termsHeading != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( termsHeading != std::wstring::npos) {
		duplicateHeading.insert( termsHeading, L"<h3 class=\"txt_title\">Terms</h3>") ;
		DRIVERCRATE_EXPECT( context, !parseAsixTermsPage( duplicateHeading, snapshot)) ;
	}

	std::wstring	  unknownTag( VALID_TERMS) ;	// 許可表にないstrong tagを持つpage。
	const std::size_t paragraph =
		// 置換対象段落位置。
		unknownTag.find( L"<p>Synthetic disclaimer.</p>") ;
	DRIVERCRATE_EXPECT( context, paragraph != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( paragraph != std::wstring::npos) {
		unknownTag.replace( paragraph, std::wstring_view( L"<p>Synthetic disclaimer.</p>").size(),
						   L"<strong>Synthetic disclaimer.</strong>") ;
		DRIVERCRATE_EXPECT( context, !parseAsixTermsPage( unknownTag, snapshot)) ;
	}

	std::wstring	  unknownAttribute( VALID_TERMS) ;	// 既知pに未許可class属性を加えたpage。
	const std::size_t attributed =
		// 置換対象段落位置。
		unknownAttribute.find( L"<p>Synthetic disclaimer.</p>") ;
	DRIVERCRATE_EXPECT( context, attributed != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( attributed != std::wstring::npos) {
		unknownAttribute.replace( attributed,
								 std::wstring_view( L"<p>Synthetic disclaimer.</p>").size(),
								 L"<p class=\"changed\">Synthetic disclaimer.</p>") ;
		DRIVERCRATE_EXPECT( context, !parseAsixTermsPage( unknownAttribute, snapshot)) ;
	}

	std::wstring	  unknownEntity( VALID_TERMS) ;				// 許可表にないnamed entityを持つpage。
	const std::size_t entity = unknownEntity.find( L"&amp;") ;	// 既知entityの置換位置。
	DRIVERCRATE_EXPECT( context, entity != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( entity != std::wstring::npos) {
		unknownEntity.replace( entity, std::wstring_view( L"&amp;").size(), L"&copy;") ;
		DRIVERCRATE_EXPECT( context, !parseAsixTermsPage( unknownEntity, snapshot)) ;
	}

	std::wstring	  unbalanced( VALID_TERMS) ;					// Article閉じtagをdivへ変更したpage。
	const std::size_t article = unbalanced.find( L"</article>") ;	// 閉じtagの置換位置。
	DRIVERCRATE_EXPECT( context, article != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( article != std::wstring::npos) {
		unbalanced.replace( article, std::wstring_view( L"</article>").size(), L"</div>") ;
		DRIVERCRATE_EXPECT( context, !parseAsixTermsPage( unbalanced, snapshot)) ;
	}

	const std::wstring oversized( 300U * 1024U, L' ') ;	// Terms page入力上限を超える合成文字列。
	DRIVERCRATE_EXPECT( context, !parseAsixTermsPage( oversized, snapshot)) ;
	DRIVERCRATE_EXPECT( context, snapshot.text.empty()) ;
	DRIVERCRATE_EXPECT( context, snapshot.revision.empty()) ;

	std::wstring				missingLink( VALID_PAGE) ;	// 製品pageから固定Terms参照を除いた入力。
	constexpr std::wstring_view LINK =
		L"<a href=\"https://www.asix.com.tw/en/useterm\">Terms Of Use</a>" ;	// 除去対象link。
	const std::size_t link = missingLink.find( LINK) ;							// 固定Terms参照の位置。
	DRIVERCRATE_EXPECT( context, link != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( link != std::wstring::npos) {
		missingLink.erase( link, LINK.size()) ;
		OfficialReleaseRecord rejected ;	// 失敗時に初期値へ戻る配布record。
		DRIVERCRATE_EXPECT( context, !makeAsixAx88179aPreparedRelease( missingLink, VALID_TERMS,
																	 false, 26'100U, rejected)) ;
		DRIVERCRATE_EXPECT( context, rejected.family == OfficialReleaseFamily::UNKNOWN) ;
	}

	OfficialReleaseRecord server ;	// Windows Serverを別client行へfallbackしない確認出力。
	DRIVERCRATE_EXPECT(
		context, !makeAsixAx88179aPreparedRelease( VALID_PAGE, VALID_TERMS, true, 26'100U, server)) ;
	DRIVERCRATE_EXPECT( context, server.family == OfficialReleaseFamily::UNKNOWN) ;
	DRIVERCRATE_EXPECT(
		context, !makeAsixAx88179aPreparedRelease( VALID_PAGE, VALID_TERMS, false, 0U, server)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 別製品、別host、ARM、重複、壊れた日付とendpoint欠落を拒否する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testRejectedPages( TestContext &context)
{
	AsixAx88179aCatalog catalog ;									// 各拒否後に初期値であるべき出力。
	std::wstring		wrongProduct( VALID_PAGE) ;					// AX88179Bへ置換した別製品page。
	const std::size_t	product = wrongProduct.find( L"AX88179A") ;	// 製品名の置換位置。
	DRIVERCRATE_EXPECT( context, product != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( product != std::wstring::npos) {
		wrongProduct.replace( product, std::wstring_view( L"AX88179A").size(), L"AX88179B") ;
		DRIVERCRATE_EXPECT( context, !parseAsixAx88179aProductPage( wrongProduct, catalog)) ;
	}

	std::wstring	  wrongHost( VALID_PAGE) ;						// ASIX類似名の第三者host。
	const std::size_t host = wrongHost.find( L"www.asix.com.tw") ;	// 最初のhost位置。
	DRIVERCRATE_EXPECT( context, host != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( host != std::wstring::npos) {
		wrongHost.replace( host, 15U, L"www.asix.example") ;
		DRIVERCRATE_EXPECT( context, !parseAsixAx88179aProductPage( wrongHost, catalog)) ;
	}

	std::wstring	  arm( VALID_PAGE) ;									// 対象x64説明をARMへ置換した行。
	const std::size_t certification = arm.find( L"For x64 CPU platform") ;	// 説明の開始位置。
	DRIVERCRATE_EXPECT( context, certification != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( certification != std::wstring::npos) {
		arm.replace( certification, 20U, L"For ARM CPU platform") ;
		DRIVERCRATE_EXPECT( context, !parseAsixAx88179aProductPage( arm, catalog)) ;
	}

	std::wstring	  duplicate( VALID_PAGE) ;					// Windows 11 driver行名を二件持つpage。
	const std::size_t insert = duplicate.find( L"</html>") ;	// 二件目の挿入位置。
	DRIVERCRATE_EXPECT( context, insert != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( insert != std::wstring::npos) {
		duplicate.insert( insert,
						 LR"(<div class="table_item"><p>Windows 11 64-bit Driver</p></div>)") ;
		DRIVERCRATE_EXPECT( context, !parseAsixAx88179aProductPage( duplicate, catalog)) ;
	}

	std::wstring	  badDate( VALID_PAGE) ;				// Calendar schema外の日付表示。
	const std::size_t date = badDate.find( L"2026-01-15") ;	// 最初の日付の置換位置。
	DRIVERCRATE_EXPECT( context, date != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( date != std::wstring::npos) {
		badDate.replace( date, std::wstring_view( L"2026-01-15").size(), L"2026/01/15") ;
		DRIVERCRATE_EXPECT( context, !parseAsixAx88179aProductPage( badDate, catalog)) ;
	}

	std::wstring				missingEndpoint( VALID_PAGE) ;	// 固定endpoint pathを持たない行。
	constexpr std::wstring_view ENDPOINT =
		L"/en/support/download/file/9001" ;							// Fixture内の置換対象path。
	const std::size_t endpoint = missingEndpoint.find( ENDPOINT) ;	// Endpointの置換位置。
	DRIVERCRATE_EXPECT( context, endpoint != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( endpoint != std::wstring::npos) {
		missingEndpoint.replace( endpoint, ENDPOINT.size(), L"/en/support/download/other/9001") ;
		DRIVERCRATE_EXPECT( context, !parseAsixAx88179aProductPage( missingEndpoint, catalog)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 対象deviceだけが通信へ進み、観測差分付きの表示専用候補を一件生成する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testDeviceProbeAndScan( TestContext &context)
{
	OfficialCatalogDevice device = asixDevice( L"asix-net") ;	// 正常なlocal probe入力。
	DRIVERCRATE_EXPECT( context, isAsixAx88179aDevice( device)) ;
	device.model = L"ASIX AX88279 USB Ethernet Adapter" ;
	DRIVERCRATE_EXPECT( context, !isAsixAx88179aDevice( device)) ;
	device			   = asixDevice( L"asix-net") ;
	device.driverClass = L"Ports" ;
	DRIVERCRATE_EXPECT( context, !isAsixAx88179aDevice( device)) ;
	device = asixDevice( L"asix-net") ;
	device.driverClass.clear() ;
	DRIVERCRATE_EXPECT( context, !isAsixAx88179aDevice( device)) ;
	device = asixDevice( L"asix-net") ;
	device.deviceClassGuid.clear() ;
	DRIVERCRATE_EXPECT( context, !isAsixAx88179aDevice( device)) ;

	const std::array			devices{asixDevice( L"asix-net")} ;	// 一台の合成AX88179A inventory。
	std::size_t					reads{} ;							// 固定page readerの呼出し回数。
	const AsixProductPageReader reader = [&reads]( const ScanSessionId, std::wstring &html) {
		++reads ;
		html.assign( VALID_PAGE) ;
		return NativeError{0} ;
	} ; // Networkを使用せず合成pageを返す取得境界。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {} ;	// 通知は破棄する。
	std::size_t					   evaluations{} ;									// Release観測評価境界の呼出し回数。
	const AsixReleaseObservationEvaluator evaluator =
		[&context, &evaluations](
			const OfficialCatalogDevice &evaluatedDevice,
			const OfficialReleaseRecord &release) -> std::optional<ReleaseObservationDifference> {
		++evaluations ;
		DRIVERCRATE_EXPECT( context, evaluatedDevice.deviceIdentity == L"asix-net") ;
		DRIVERCRATE_EXPECT( context, release.family == OfficialReleaseFamily::ASIX_AX88179A) ;
		DRIVERCRATE_EXPECT( context, release.releaseKey == L"9001") ;
		DRIVERCRATE_EXPECT( context, release.fileName.empty()) ;
		DRIVERCRATE_EXPECT( context, release.license == OfficialReleaseLicense::UNRESOLVED) ;
		return ReleaseObservationDifference::METADATA_UNCHANGED ;
	} ; // Worker内情報を確認し、非機密差分だけを候補へ返すfake。
	const ScanResult windows11 =
		scanAsixAx88179aProductPage( SESSION, devices, false, 26'100U, reader, progress,
									evaluator) ;	// Windows 11 client検索と観測差分反映。
	DRIVERCRATE_EXPECT( context, windows11.succeeded) ;
	DRIVERCRATE_EXPECT( context, windows11.state == ProviderScanState::CANDIDATES_AVAILABLE) ;
	DRIVERCRATE_EXPECT( context, windows11.candidates.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, reads == 1U) ;
	DRIVERCRATE_EXPECT( context, evaluations == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( windows11.candidates.size() == 1U) {
		const UpdateCandidate &candidate = windows11.candidates[0] ;	// 生成された表示行。
		DRIVERCRATE_EXPECT( context, candidate.providerId == ASIX_AX88179A_PROVIDER_ID) ;
		DRIVERCRATE_EXPECT( context, candidate.title.find( L"4.22.1.0") != std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, candidate.version.empty()) ;
		DRIVERCRATE_EXPECT( context, !candidate.installable) ;
		DRIVERCRATE_EXPECT( context, !candidate.recommended) ;
		DRIVERCRATE_EXPECT( context, candidate.releaseObservationDifference ==
										ReleaseObservationDifference::METADATA_UNCHANGED) ;
		DRIVERCRATE_EXPECT( context, !candidate.allContentCached) ;
		DRIVERCRATE_EXPECT( context, candidate.action == DriverAction::NONE) ;
		DRIVERCRATE_EXPECT( context,
						   candidate.sourceLocation.find( L"www.asix.com.tw") != std::wstring::npos) ;
		const ProviderDescriptor *descriptor{} ;	// ASIX候補を検証するRegistry定義。
		// 組み込み定義からstable IDが完全一致する一件だけを参照する。
		for( const ProviderDescriptor &candidateDescriptor : builtInProviderDescriptors()) {
			// ASIXのstable IDに対応するregistry定義だけを候補監査に使用する。
			if( candidateDescriptor.id == ASIX_AX88179A_PROVIDER_ID) {
				descriptor = &candidateDescriptor ;
				break ;
			}
		}

		DRIVERCRATE_EXPECT( context, descriptor != nullptr) ;
		// registry定義が取得できた場合にだけ候補の監査整合性を検証する。
		if( descriptor != nullptr) {
			DRIVERCRATE_EXPECT( context, isCandidateAuditValid( candidate, *descriptor)) ;
			UpdateCandidate invalidDifference = candidate ;	// 定義外差分を持つ拒否対象行。
			invalidDifference.releaseObservationDifference = ReleaseObservationDifference::INVALID ;
			DRIVERCRATE_EXPECT( context, !isCandidateAuditValid( invalidDifference, *descriptor)) ;
		}
	}

	const ScanResult windows10 = scanAsixAx88179aProductPage(
		SESSION + 1U, devices, false, 19'045U, reader, progress) ;	// Windows 10 client検索。
	DRIVERCRATE_EXPECT( context, windows10.candidates.size() == 1U) ;
	DRIVERCRATE_EXPECT( context,
					   windows10.candidates[0].title.find( L"4.20.1.0") != std::wstring::npos) ;
	DRIVERCRATE_EXPECT( context, reads == 2U) ;
	DRIVERCRATE_EXPECT(
		context,
		scanAsixAx88179aProductPage( SESSION + 2U, devices, true, 26'100U, reader, progress).state ==
			ProviderScanState::NOT_APPLICABLE) ;
	DRIVERCRATE_EXPECT( context, reads == 2U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二page保持、二deviceの一配布物集約、単調計画と失効を非通信で確認する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testPreparedProviderSnapshot( TestContext &context)
{
	const std::array			devices{asixDevice( L"asix-net-a"),
								// 同じ配布物に関係する二device。
								asixDevice( L"asix-net-b")} ;
	std::size_t					productReads{} ;	// 合成製品page readerの呼出し回数。
	std::size_t					termsReads{} ;		// 合成Terms page readerの呼出し回数。
	const AsixProductPageReader productReader = [&productReads]( const ScanSessionId,
																std::wstring &html) {
		++productReads ;
		html.assign( VALID_PAGE) ;
		return NativeError{0} ;
	} ; // Networkを使用せず同じ架空製品pageを返す境界。
	const AsixTermsPageReader termsReader = [&termsReads]( const ScanSessionId, std::wstring &html) {
		++termsReads ;
		html.assign( VALID_TERMS) ;
		return NativeError{0} ;
	} ; // Networkを使用せず同じ架空Terms pageを返す境界。
	std::uint32_t lastPercent{} ;	// 二page確認前に完了へ進まないことを確認する進捗。
	const ProviderProgressCallback progress = [&context, &productReads, &termsReads,
											   &lastPercent]( const ProviderProgress &value) {
		lastPercent = value.percentComplete ;
		// 完了通知までに製品pageとTermsの両方を取得したことを確認する。
		if( value.percentComplete == 100U) {
			DRIVERCRATE_EXPECT( context, productReads > 0U) ;
			DRIVERCRATE_EXPECT( context, termsReads > 0U) ;
		}
	} ; // 実通信なしでTerms確認と検索完了の順序を検証する境界。
	std::size_t observations{} ;	// 二page結合済みrecordを評価したdevice数。
	const AsixReleaseObservationEvaluator evaluator =
		[&context, &observations, &termsReads](
			const OfficialCatalogDevice &,
			const OfficialReleaseRecord &release) -> std::optional<ReleaseObservationDifference> {
		++observations ;
		DRIVERCRATE_EXPECT( context, termsReads == 1U) ;
		DRIVERCRATE_EXPECT( context, release.parserRevision == 2U) ;
		DRIVERCRATE_EXPECT( context,
						   release.license == OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD) ;
		DRIVERCRATE_EXPECT( context, !release.eulaText.empty()) ;
		return ReleaseObservationDifference::FIRST_OBSERVATION ;
	} ; // 旧表示recordのrevision・未結合Termsを観測へ渡さない確認境界。
	std::size_t rankAuditCalls{} ;	// 取得前には0であるべきPnP／rank監査callback呼出し数。
	const OfficialInfRankAuditor rankAuditor =
		[&rankAuditCalls]( const ScanSessionId, const std::wstring_view,
						  const OfficialDownloadWorkspace &, const OfficialInfPackage &,
						  OfficialDriverRankAudit &) -> NativeError {
		++rankAuditCalls ;
		return static_cast<NativeError>( E_UNEXPECTED) ;
	} ; // C3では保持だけを行い、取得前の誤呼出しを失敗として検出する境界。
	AsixUpdateProvider provider( rankAuditor) ;	// Worker threadでPnP監査境界を所有するProvider。
	const ScanResult   scan = provider.scanWithPreparedPageReaders(
		  SESSION, devices, false, 26'100U, productReader, termsReader, progress,
		  evaluator) ;	// Windows 11向け二page結合scan。
	DRIVERCRATE_EXPECT( context, scan.succeeded) ;
	DRIVERCRATE_EXPECT( context, scan.state == ProviderScanState::CANDIDATES_AVAILABLE) ;
	DRIVERCRATE_EXPECT( context, scan.candidates.size() == 2U) ;
	DRIVERCRATE_EXPECT( context, productReads == 1U) ;
	DRIVERCRATE_EXPECT( context, termsReads == 1U) ;
	DRIVERCRATE_EXPECT( context, lastPercent == 100U) ;
	DRIVERCRATE_EXPECT( context, observations == 2U) ;
	DRIVERCRATE_EXPECT( context, rankAuditCalls == 0U) ;

	const std::vector<OfficialPreparationTarget> first =
		// 最初の未承認計画。
		provider.preparationTargets( SESSION, 7U) ;
	DRIVERCRATE_EXPECT( context, first.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( first.size() == 1U) {
		const OfficialPreparationTarget &target = first.front() ;	// 二device集約済み対象。
		DRIVERCRATE_EXPECT( context, target.providerId == ASIX_AX88179A_PROVIDER_ID) ;
		DRIVERCRATE_EXPECT( context, target.identity ==
										std::wstring( ASIX_AX88179A_PROVIDER_ID) + L":prepare:7") ;
		DRIVERCRATE_EXPECT( context, target.releaseIdentity ==
										std::wstring( ASIX_AX88179A_PROVIDER_ID) + L":release:71:0") ;
		DRIVERCRATE_EXPECT( context, target.resourceId == OFFICIAL_PAYLOAD_RESOURCE_ID) ;
		DRIVERCRATE_EXPECT( context, target.parserRevision == 2U) ;
		DRIVERCRATE_EXPECT( context, target.maximumBytes == 8ULL * 1024ULL * 1024ULL) ;
		DRIVERCRATE_EXPECT( context, target.deviceCount == 2U) ;
		DRIVERCRATE_EXPECT( context, target.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED) ;
		DRIVERCRATE_EXPECT( context, !target.eulaRevision.empty()) ;
		DRIVERCRATE_EXPECT( context, !target.eulaText.empty()) ;
		DRIVERCRATE_EXPECT( context, target.requiresPrerequisiteConfirmation) ;
		DRIVERCRATE_EXPECT( context,
						   !provider.preparationAuditReport( SESSION, target.identity).has_value()) ;
		DRIVERCRATE_EXPECT(
			context, !provider.preparationAuditReport( SESSION + 1U, target.identity).has_value()) ;

		OfficialPreparationSession approvalSession ;	// 実取得を行わない共通承認validator。
		DRIVERCRATE_EXPECT( context,
						   approvalSession.initialize(
							   {SESSION, 7U, DEFAULT_OFFICIAL_PREPARATION_LIMITS, {target}}) ==
							   OfficialPreparationError::NONE) ;
		OfficialPreparationApproval approval ;	// 対象全文と前提確認を含む利用者判断の合成値。
		approval.operationId   = 1U ;
		approval.scanSessionId = SESSION ;
		approval.planId		   = 7U ;
		approval.limits		   = DEFAULT_OFFICIAL_PREPARATION_LIMITS ;
		approval.decisions	   = {{.target = target, .acquire = true, .eulaAccepted = true}} ;
		DRIVERCRATE_EXPECT( context,
						   approvalSession.approve( approval) != OfficialPreparationError::NONE) ;
		DRIVERCRATE_EXPECT( context, !approvalSession.claimNext().has_value()) ;
		approval.decisions.front().prerequisitesConfirmed = true ;
		DRIVERCRATE_EXPECT( context,
						   approvalSession.approve( approval) == OfficialPreparationError::NONE) ;
		const auto task = approvalSession.claimNext() ;	// 同意・前提確認後にだけ発行されるtask。
		DRIVERCRATE_EXPECT( context, task.has_value()) ;
		// 承認済みtaskを得た場合にだけ、取得根拠を持たないreaderの拒否を検証する。
		if( task) {
			const auto transfer =
				// 架空readerに根拠なし。
				provider.acquireForInspection( *task, {}) ;
			DRIVERCRATE_EXPECT( context, transfer.state == OfficialPreparationItemState::REJECTED) ;
			DRIVERCRATE_EXPECT( context, transfer.error == static_cast<NativeError>( E_INVALIDARG)) ;
			DRIVERCRATE_EXPECT(
				context, !provider.preparationAuditReport( SESSION, target.identity).has_value()) ;
		}
	}

	DRIVERCRATE_EXPECT( context, provider.preparationTargets( SESSION, 7U).empty()) ;
	DRIVERCRATE_EXPECT( context, provider.preparationTargets( SESSION, 6U).empty()) ;
	DRIVERCRATE_EXPECT( context, provider.preparationTargets( SESSION, 0U).empty()) ;

	std::vector<OfficialPreparationTarget> otherThreadTargets ;	// 別threadからの拒否結果。
	std::thread							   otherThread( [&provider, &otherThreadTargets] {
		   otherThreadTargets = provider.preparationTargets( SESSION, 8U) ;
	   }) ; // 所有thread違反。
	otherThread.join() ;
	DRIVERCRATE_EXPECT( context, otherThreadTargets.empty()) ;
	std::thread invalidationThread(
		[&provider] { provider.invalidateScanSession() ; }) ;	// 別threadからの寿命操作拒否。
	invalidationThread.join() ;
	DRIVERCRATE_EXPECT( context, provider.preparationTargets( SESSION + 1U, 8U).empty()) ;
	const std::vector<OfficialPreparationTarget> second =
		// 拒否で消費されなかった次計画。
		provider.preparationTargets( SESSION, 8U) ;
	DRIVERCRATE_EXPECT( context, second.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( second.size() == 1U && first.size() == 1U) {
		DRIVERCRATE_EXPECT( context, second.front().deviceCount == 2U) ;
		DRIVERCRATE_EXPECT( context, second.front().identity != first.front().identity) ;
		DRIVERCRATE_EXPECT( context,
						   second.front().releaseIdentity == first.front().releaseIdentity) ;
	}

	const AsixTermsPageReader failedTermsReader = []( const ScanSessionId,
													 std::wstring &) -> NativeError {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	} ; // Terms取得失敗を返す境界。
	const ScanResult failed = provider.scanWithPreparedPageReaders(
		SESSION + 1U, devices, false, 26'100U, productReader, failedTermsReader,
		progress) ;	// 新scan失敗による旧snapshot失効確認。
	DRIVERCRATE_EXPECT( context, !failed.succeeded) ;
	DRIVERCRATE_EXPECT( context, failed.candidates.empty()) ;
	DRIVERCRATE_EXPECT( context, provider.preparationTargets( SESSION, 9U).empty()) ;

	const ScanResult replacement = provider.scanWithPreparedPageReaders(
		SESSION + 2U, devices, false, 26'100U, productReader, termsReader,
		progress) ;	// 新sessionで作り直すsnapshot。
	DRIVERCRATE_EXPECT( context, replacement.succeeded) ;
	DRIVERCRATE_EXPECT( context, provider.preparationTargets( SESSION + 2U, 8U).empty()) ;
	DRIVERCRATE_EXPECT( context, provider.preparationTargets( SESSION + 2U, 9U).size() == 1U) ;
	provider.invalidateScanSession() ;
	DRIVERCRATE_EXPECT( context, provider.preparationTargets( SESSION + 2U, 10U).empty()) ;
	DRIVERCRATE_EXPECT(
		context, !provider
					  .preparationAuditReport(
						  SESSION + 2U, std::wstring( ASIX_AX88179A_PROVIDER_ID) + L":prepare:9")
					  .has_value()) ;
	DRIVERCRATE_EXPECT( context, rankAuditCalls == 0U) ;

	AsixUpdateProvider missingRankProvider ;	// PnP監査境界を持たない拒否対象Provider。
	const ScanResult   missingRankScan = missingRankProvider.scanWithPreparedPageReaders(
		  SESSION + 3U, devices, false, 26'100U, productReader, termsReader,
		  progress) ;	// 表示検索は成立しても取得計画を許可しないscan。
	DRIVERCRATE_EXPECT( context, missingRankScan.succeeded) ;
	DRIVERCRATE_EXPECT( context, missingRankProvider.preparationTargets( SESSION + 3U, 10U).empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Terms失敗で完了・観測へ進まず、対象外で二pageとも取得しないことを確認する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testPreparedScanFailureOrder( TestContext &context)
{
	AsixUpdateProvider			provider ;										// 架空reader以外の通信を呼ばないProvider。
	const std::array			devices{asixDevice( L"asix-failure-device")} ;	// 一台の対象snapshot。
	std::size_t					reads{} ;										// 対象外では増加しないpage読込み回数。
	const AsixProductPageReader productReader = [&reads]( const ScanSessionId, std::wstring &html) {
		++reads ;
		html.assign( VALID_PAGE) ;
		return NativeError{0} ;
	} ; // 合成製品page取得境界。
	const AsixTermsPageReader malformed = [&reads]( const ScanSessionId, std::wstring &html) {
		++reads ;
		html = L"<html><main>Unknown terms.</main></html>" ;
		return NativeError{0} ;
	} ; // 未知Termsを成功した通信として返す境界。
	bool						   completed{} ;	// 一度でも100%へ達した場合true。
	const ProviderProgressCallback progress = [&completed]( const ProviderProgress &value) {
		completed = completed || value.percentComplete == 100U ;
	} ; // 完了順序の確認境界。
	std::size_t observations{} ;	// 不成立Termsでは0であるべき観測呼出し数。
	const AsixReleaseObservationEvaluator evaluator =
		[&observations](
			const OfficialCatalogDevice &,
			const OfficialReleaseRecord &) -> std::optional<ReleaseObservationDifference> {
		++observations ;
		return ReleaseObservationDifference::FIRST_OBSERVATION ;
	} ; // 成立前の観測開始を検出する境界。
	// Termsのschema拒否が全体失敗へ反映された結果。
	const ScanResult rejected = provider.scanWithPreparedPageReaders(
		SESSION, devices, false, 26'100U, productReader, malformed, progress, evaluator) ;
	// Metadata拒否時は部分候補・準備target・進捗完了・観測を残さない。
	DRIVERCRATE_EXPECT( context, rejected.state == ProviderScanState::METADATA_REJECTED) ;
	DRIVERCRATE_EXPECT( context, rejected.candidates.empty()) ;
	DRIVERCRATE_EXPECT( context, !completed) ;
	DRIVERCRATE_EXPECT( context, observations == 0U) ;
	DRIVERCRATE_EXPECT( context, reads == 2U) ;
	DRIVERCRATE_EXPECT( context, provider.preparationTargets( SESSION, 1U).empty()) ;
	const AsixTermsPageReader throwing = []( const ScanSessionId, std::wstring &) -> NativeError {
		throw std::runtime_error( "synthetic terms failure") ;
	} ; // 例外診断の変換確認境界。
	const ScanResult failed = provider.scanWithPreparedPageReaders(
		SESSION + 1U, devices, false, 26'100U, productReader, throwing, progress,
		evaluator) ;	// Terms readerの例外を診断値へ変換した結果。
	// Reader例外がworker境界へ漏れず、成功進捗と観測を生成しないことを確認する。
	DRIVERCRATE_EXPECT( context, failed.state == ProviderScanState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, failed.error == static_cast<NativeError>( E_UNEXPECTED)) ;
	DRIVERCRATE_EXPECT( context, failed.candidates.empty()) ;
	DRIVERCRATE_EXPECT( context, !completed) ;
	DRIVERCRATE_EXPECT( context, observations == 0U) ;
	const std::size_t beforeServer = reads ;	// 対象外scan開始前の呼出し数。
	const ScanResult  server	   = provider.scanWithPreparedPageReaders(
		   SESSION + 2U, devices, true, 26'100U, productReader, malformed,
		   progress) ;	// Serverではpageを取得しない対象外結果。
	DRIVERCRATE_EXPECT( context, server.state == ProviderScanState::NOT_APPLICABLE) ;
	DRIVERCRATE_EXPECT( context, reads == beforeServer) ;
	DRIVERCRATE_EXPECT( context, provider.preparationTargets( SESSION + 2U, 1U).empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 重複identity、metadata破損、直接installを成功として扱わない。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testFailClosedContracts( TestContext &context)
{
	const std::array			duplicateDevices{asixDevice( L"duplicate"),
										 // 重複opaque identity。
										 asixDevice( L"duplicate")} ;
	std::size_t					reads{} ;	// 不正inventoryでは0であるべきreader呼出し回数。
	const AsixProductPageReader reader = [&reads]( const ScanSessionId, std::wstring &html) {
		++reads ;
		html.assign( VALID_PAGE) ;
		return NativeError{0} ;
	} ; // 合成page reader。
	const ProviderProgressCallback progress	 = []( const ProviderProgress &) {} ;	// 通知は破棄する。
	const ScanResult			   duplicate = scanAsixAx88179aProductPage(
		  SESSION, duplicateDevices, false, 26'100U, reader, progress) ;	// 拒否対象scan。
	DRIVERCRATE_EXPECT( context, !duplicate.succeeded) ;
	DRIVERCRATE_EXPECT( context, duplicate.error == static_cast<NativeError>( E_INVALIDARG)) ;
	DRIVERCRATE_EXPECT( context, reads == 0U) ;

	const std::array			devices{asixDevice( L"asix-net")} ;	// 正常inventory。
	const AsixProductPageReader rejectedReader = []( const ScanSessionId, std::wstring &html) {
		html = L"<html></html>" ;
		return NativeError{0} ;
	} ; // Schema不成立pageを返すreader。
	const ScanResult rejected = scanAsixAx88179aProductPage(
		SESSION + 1U, devices, false, 26'100U, rejectedReader, progress) ;	// Metadata拒否scan。
	DRIVERCRATE_EXPECT( context, rejected.state == ProviderScanState::METADATA_REJECTED) ;
	DRIVERCRATE_EXPECT( context, rejected.candidates.empty()) ;

	AsixUpdateProvider	provider ;											// 直接install拒否を確認する導入未対応Provider。
	const InstallResult install = provider.install( SESSION, {}, 0U, {}) ;	// OS変更を伴わない拒否。
	DRIVERCRATE_EXPECT( context, install.downloadError == static_cast<NativeError>( E_INVALIDARG)) ;
	DRIVERCRATE_EXPECT( context, install.installError == static_cast<NativeError>( E_INVALIDARG)) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/asix_catalog_parser_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runAsixCatalogParserTests( TestContext &context)
{
	testValidPageAndOsSelection( context) ;
	testTermsPageAndReleaseJoin( context) ;
	testTermsPageRejections( context) ;
	testRejectedPages( context) ;
	testDeviceProbeAndScan( context) ;
	testPreparedProviderSnapshot( context) ;
	testPreparedScanFailureOrder( context) ;
	testFailClosedContracts( context) ;
}

} // namespace drivercrate::test
