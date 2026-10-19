//------------------------------------------------------------------------------
/**
 * @file intel_ethernet_server_page_parser_tests.cpp
 * @brief Intel Ethernet Server／Windows 11 record単体試験実装。
 * @version 01.08.02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernetの取得前提確認と選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  許諾全文・配布結合・変更拒否fixtureを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Windows 11 record adapter試験を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  正式origin、descriptor、grant接続を検証。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  現行plain text配布版表記の回帰試験を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/15  無関係なtextareaとの共存回帰を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/09/23  Intel ZIP三系列とlist形式許諾・改変拒否を検証。
 * Ver.01.06.00 Shunji Ogawa  2026/09/28  同一本文の収集候補・三状態と通常record fieldを検証。
 * Ver.01.07.00 Shunji Ogawa  2026/09/28  複数軸三状態・300対象上限・旧指紋を検証。
 * Ver.01.08.00 Shunji Ogawa  2026/09/28  制御付きcore全checkpointの停止・例外fixtureを追加。
 * Ver.01.08.01 Shunji Ogawa  2026/10/02  AI依存を撤去し非AI共通処理と試験を維持。
 * Ver.01.08.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 現行pageと同じ必須labelを持つ合成fixtureで、別host、別OS、重複を拒否します。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#include "intel_ethernet_server_page_parser_tests.h"
#include "collector_parser_test_control.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/intel_download_license_parser.h"
#include "platform/intel_ethernet_server_page_parser.h"
#include "platform/intel_ethernet_windows11_record_adapter.h"
#include "platform/intel_wireless_page_parser.h"
#include "platform/official_record_utilities.h"
#include "platform/official_download_grant.h"
#include "platform/official_record_payload_routing.h"
#include "platform/official_release_discovery_provider.h"
#include "platform/official_release_metadata.h"

#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {

// 現行公式pageの必須表示だけを再現し、実在するpayload識別子を含めない合成fixture。
constexpr std::wstring_view VALID_PAGE =
	LR"(<html><h1>Intel® Network Adapter Driver for Windows Server 2025*</h1>)"
	LR"(<p>Intel requires an accepted license agreement in order to download this file.</p>)"
	LR"(<h2>Available Downloads</h2>)"
	LR"(<button data-href="https://downloadmirror.intel.com/900001/)"
	LR"(Wired_driver_31.2.2_x64.zip">Wired_driver_31.2.2_x64.zip</button>)"
	LR"(<li>Windows Server 2025 family*</li><li>Size: 38.6 MB</li>)"
	LR"(<li>SHA256: 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF</li>)"
	LR"(<h2>Detailed Description</h2>)"
	LR"(<p><strong>Driver Package:</strong> Wired_driver_31.2.2_x64.zip</p></html>)" ;

// Intel 727998で確認したWin11、E610-XT2、公開hashの関係だけを非通信fixtureへ固定する。
constexpr std::wstring_view WINDOWS11_PAGE =
	LR"(<html><h1>Intel® Network Adapter Driver for Microsoft Windows 11*</h1>)"
	LR"(<p>Intel requires an accepted license agreement in order to download this file.</p>)"
	LR"(<h2>Available Downloads</h2>)"
	LR"(<button data-href="https://downloadmirror.intel.com/900011/)"
	LR"(Wired_driver_31.2.2_x64.zip">Wired_driver_31.2.2_x64.zip</button>)"
	LR"(<li>Windows 11 Family*</li><li>Size: 38.6 MB</li>)"
	LR"(<li>SHA256: 2CBFF42AA02519E49F02D8E95A6572C44310E97FE67C42E299F2ABA6EA9344F5</li>)"
	LR"(<h2>Detailed Description</h2>)"
	LR"(<p><strong>Driver Package:</strong> Wired_driver_31.2.2_x64.zip</p>)"
	LR"(<h2>This download is valid for the product(s) listed below.</h2>)"
	LR"(<a>Intel® Ethernet Network Adapter E610-XT2</a></html>)" ;

constexpr ScanSessionId		WINDOWS11_SESSION		= 711U ;	// Adapter入力の架空scan session。
constexpr std::uint64_t		WINDOWS11_BODY_UTC		= 20'000U ;	// 架空root本文取得UTC秒。
constexpr std::uint64_t		WINDOWS11_VALIDATED_UTC = 20'001U ;	// 架空origin検証UTC秒。
constexpr std::uint64_t		WINDOWS11_RESOLVED_UTC	= 20'002U ;	// 架空record固定UTC秒。

// 公式許諾を転載しない、表示変換専用の架空文書title。
constexpr std::wstring_view LICENSE_TITLE = L"Intel Fixture License Agreement [v2030.01.02]" ;
// 複数セル、段落、引用符、数値参照を含む架空本文。
constexpr std::wstring_view LICENSE_BODY =
	LR"(<table><tbody><tr><td style="width: 50.0%;"><p><b>Fixture terms.</b></p>)"
	LR"(<p>&quot;Alpha&quot; &amp; Beta &#169;</p></td><td><div>Second cell.)"
	LR"(<br />Final clause.</div></td></tr></tbody></table>)" ;

//------------------------------------------------------------------------------
/**
 * @brief 実際の配布物も許諾文も使わず、確認した構造だけを再現します。
 *
 * @param[in] body 合成許諾bodyの内側。呼出し中だけ参照する。
 * @return 一つのZIP buttonと埋込み許諾を持つ所有page。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring licensePage( const std::wstring_view body)
{
	std::wstring page( VALID_PAGE) ;	// 独立したテスト入力。
	page.insert( page.find( L"data-href="), L"data-modal-id=\"1\" ") ;
	// 公式HTML構造へ架空本文を埋め込んだテスト専用文書。
	const std::wstring document =
		L"<textarea id=\"content-raw\" class=\"license-modal-content_body_license-text-raw\""
		L" tabindex=\"0\"><html lang=\"en\"><head><title>" +
		std::wstring( LICENSE_TITLE) + L"</title></head><body>" + std::wstring( body) +
		L"</body></html></textarea>" ;
	page.insert( page.find( L"<h2>Available Downloads"), document) ;
	return page ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows 11 record構造へ架空EULA本文を結合します。
 * @param[in] body 合成許諾bodyの内側。呼出し中だけ参照します。
 * @return 一つのWin11 ZIP buttonと埋込み許諾を持つ所有page。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring windows11LicensePage( const std::wstring_view body)
{
	std::wstring page( WINDOWS11_PAGE) ;	// 独立したWindows 11テスト入力。
	page.insert( page.find( L"data-href="), L"data-modal-id=\"1\" ") ;
	const std::wstring document =
		L"<textarea id=\"content-raw\" class=\"license-modal-content_body_license-text-raw\""
		L" tabindex=\"0\"><html lang=\"en\"><head><title>" +
		std::wstring( LICENSE_TITLE) + L"</title></head><body>" + std::wstring( body) +
		L"</body></html></textarea>" ;	// 架空EULA document。
	page.insert( page.find( L"<h2>Available Downloads"), document) ;
	return page ;
}

/**
 * @brief 配布parserと専用製品一覧parserへ同じ合成本文を渡すfixtureです。
 * @return 同じrelease・製品一覧を含む所有fixture HTML。元fixtureに必要なbuttonがなければ空。
 */
[[nodiscard]] std::wstring windows11CollectorPage()
{
	std::wstring release = windows11LicensePage( LICENSE_BODY) ;	// 旧parserも受け入れる許諾fixture。
	// 旧fixtureの外側htmlだけを除きます。
	release.erase( 0U, 6U) ;
	release.erase( release.size() - 7U) ;
	const auto button = release.find( L"<button data-modal-id=") ;	// 唯一の配布button。
	// Fixtureが変化したら別HTMLを推測生成しません。
	if( button == release.npos) {
		return {} ;
	}

	release.insert( button + 8U, L"class=\"dc-page-available-downloads-hero-button__cta\" ") ;
	return LR"(<html><head><meta charset="utf-8"><link rel="canonical" href="https://www.intel.com/content/www/us/en/download/727998/intel-network-adapter-driver-for-microsoft-windows-11.html"></head><body>)"
		   LR"(<main id="primary-content"><div data-bundle-id="downloadcenter.components.content.dcPageBanner" class="dc-page-banner">)"
		   LR"(<div class="dc-page-banner-actions-action-id"><label class="dc-page-banner-actions-action__label">ID</label>)"
		   LR"(<span class="dc-page-banner-actions-action__value">727998</span></div></div>)"
		   LR"(<div data-bundle-id="downloadcenter.components.content.dcPageContainer" class="dc-page-container container">)"
		   LR"(<div class="dc-page-container__body"><div class="dc-page-container__body--left-panel">)"
		   LR"(<div class="dc-page-available-downloads-hero">)" +
		   release + L"</div>" +
		   LR"(<div data-bundle-id="downloadcenter.components.content.dcPageOtherValidProducts" class="dc-page-detailed-other-valid-products">)"
		   LR"(<h2 class="dc-page-detailed-other-valid-products__title">This download is valid for the product(s) listed below.</h2>)"
		   LR"(<ul class="dc-page-detailed-other-valid-products-panel">)"
		   LR"(<li class="dc-page-detailed-other-valid-products-panel__product"><a class="dc-page-detailed-other-valid-products-panel__product--fixed" href="/content/www/us/en/products/sku/900001/fixture-adapter/downloads.html">Fixture® Adapter X1</a></li>)"
		   L"</ul></div></div></div></div></main></body></html>" ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows 11 adapterへ渡すURL非保持の架空root evidenceを作ります。
 * @return Network本文、非cache、landing用途を示す架空evidence。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialSourceEvidence windows11RootEvidence()
{
	return OfficialSourceEvidence{
		.scanSessionId			= WINDOWS11_SESSION,
		.acquisitionId			= 1U,
		.providerId				= std::wstring{INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID},
		.policyId				= std::wstring{INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID},
		.resourceId				= std::wstring{OFFICIAL_LANDING_RESOURCE_ID},
		.redirectCount			= 0U,
		.originPolicyIndices	= {0U},
		.acquisition			= MeasurementAcquisition::NETWORK_BODY,
		.bodyAcquiredUtcSeconds = WINDOWS11_BODY_UTC,
		.originValidatedUtcSeconds = WINDOWS11_VALIDATED_UTC,
		.cachePermitted			   = false} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全セルの本文・許諾版・配布物が同じrecordへ結合されることを確認します。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testLicenseSnapshot( TestContext &context)
{
	const std::wstring				page = licensePage( LICENSE_BODY) ;	// 架空の完全許諾page。
	IntelEthernetServerPageMetadata metadata ;							// 系列parserのsnapshot結果。
	DRIVERCRATE_EXPECT( context, parseIntelEthernetServerDownloadPage( page, metadata)) ;
	DRIVERCRATE_EXPECT( context, metadata.eulaRevision == LICENSE_TITLE) ;
	DRIVERCRATE_EXPECT( context, metadata.eulaText.find( L"Fixture terms.") != std::wstring::npos) ;
	DRIVERCRATE_EXPECT( context,
					   metadata.eulaText.find( L"\"Alpha\" & Beta \u00a9") != std::wstring::npos) ;
	DRIVERCRATE_EXPECT( context, metadata.eulaText.find( L"Second cell.\r\nFinal clause.") !=
									std::wstring::npos) ;
	DRIVERCRATE_EXPECT( context, metadata.eulaText.find( L"<table>") == std::wstring::npos) ;

	std::wstring withUnrelatedTextarea( page) ;	// 同一pageの別入力欄を持つ現行構造です。
	withUnrelatedTextarea.insert( withUnrelatedTextarea.find( L"<textarea id=\"content-raw\""),
								 L"<textarea id=\"unrelated\"></textarea>") ;
	DRIVERCRATE_EXPECT( context,
					   parseIntelEthernetServerDownloadPage( withUnrelatedTextarea, metadata)) ;

	OfficialReleaseRecord record ;	// 共通処理へ渡す許諾付き配布情報。
	DRIVERCRATE_EXPECT(
		context,
		parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025, page, record)) ;
	DRIVERCRATE_EXPECT( context, record.eulaText == metadata.eulaText) ;
	DRIVERCRATE_EXPECT( context, record.eulaRevision == metadata.eulaRevision) ;
	DRIVERCRATE_EXPECT( context, record.parserRevision == 2U) ;
	DRIVERCRATE_EXPECT( context, record.downloadUrl == metadata.downloadUrl) ;
	DRIVERCRATE_EXPECT( context, record.publishedSha256 == metadata.sha256) ;
	const auto targets = makeReleasePreparationTargets( record, 1U, 1U, 1U) ;	// 未同意の取得対象。
	DRIVERCRATE_EXPECT( context, targets.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( targets.size() == 1U) {
		DRIVERCRATE_EXPECT( context, targets[0].eulaText == metadata.eulaText) ;
		DRIVERCRATE_EXPECT( context, targets[0].eulaRevision == metadata.eulaRevision) ;
		DRIVERCRATE_EXPECT( context, targets[0].requiresPrerequisiteConfirmation) ;
		DRIVERCRATE_EXPECT( context,
						   targets[0].terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED) ;
		DRIVERCRATE_EXPECT( context, targets[0].maximumBytes == 128ULL * 1024ULL * 1024ULL) ;
	}

	const std::wstring scripted = licensePage(
		std::wstring( LICENSE_BODY) +
		LR"(<script type="text/javascript" src="/etc.clientlibs/intel/clientlibs/bundles/)"
		LR"(resources/js/fixture.dcPageScript.1234.bundle.js"></script>)") ;	// 既知の末尾空script構造。
	DRIVERCRATE_EXPECT( context, parseIntelEthernetServerDownloadPage( scripted, metadata)) ;
	DRIVERCRATE_EXPECT( context, record.eulaText == metadata.eulaText) ;
	std::wstring styled( page) ;	// 実pageと同じ空styleとCSS参照を持つ合成head。
	styled.insert( styled.find( L"</head>"),
				  LR"(<style>li { }</style><link rel="stylesheet" type="text/css" href=")"
				  LR"(/etc.clientlibs/intel/clientlibs/bundles/resources/css/)"
				  LR"(fixture.dcPageStyle.1234.bundle.css"/>)") ;
	DRIVERCRATE_EXPECT( context, parseIntelEthernetServerDownloadPage( styled, metadata)) ;
	DRIVERCRATE_EXPECT( context, record.eulaText == metadata.eulaText) ;
}

/** @brief 同一本文の一候補・複数target三状態とrootなし境界を確認します。 */
void testCollectorMetadataAssessment( TestContext &context)
{
	const std::wstring	  page = windows11CollectorPage() ;	// 一本文の合成入力。
	OfficialReleaseRecord probeRelease ;					// 旧parserが同じ本文を受け取る対照。
	DRIVERCRATE_EXPECT( context,
					   parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11,
												  page, probeRelease)) ;
	DRIVERCRATE_EXPECT( context, parseIntelCollectorProductIdentity( page).status ==
									IntelCollectorIdentityStatus::ACCEPTED) ;
	DRIVERCRATE_EXPECT(
		context,
		parseIntelCollectorProductIdentityForPayload( page, probeRelease.downloadUrl).status ==
			IntelCollectorIdentityStatus::ACCEPTED) ;
	const std::array<IntelCollectorTargetQuery, 8U> targets{
		// 製品・目的・OS等の三状態集合。
		{{L"match", L"Intel", L"Fixture® Adapter X1", L"NETWORK_ADAPTER", L"Ethernet",
		  L"Windows 11", L"x64", L""},
		 {L"unlisted", L"Intel", L"Fixture® Adapter X2", L"NETWORK_ADAPTER", L"Ethernet",
		  L"Windows 11", L"x64", L""},
		 {L"maker", L"ASUS", L"Fixture® Adapter X1", L"NETWORK_ADAPTER", L"Ethernet", L"Windows 11",
		  L"x64", L""},
		 {L"purpose", L"Intel", L"Fixture® Adapter X1", L"NETWORK_ADAPTER", L"Wi-Fi", L"Windows 11",
		  L"x64", L""},
		 {L"os", L"Intel", L"Fixture® Adapter X1", L"NETWORK_ADAPTER", L"Ethernet", L"Windows 10",
		  L"x64", L""},
		 {L"arch", L"Intel", L"Fixture® Adapter X1", L"NETWORK_ADAPTER", L"Ethernet", L"Windows 11",
		  L"arm64", L""},
		 {L"chip", L"Intel", L"Fixture® Adapter X1", L"NETWORK_ADAPTER", L"Ethernet", L"Windows 11",
		  L"x64", L"I226"},
		 {L"invalid", L"Intel", L"https://bad.example/a", L"NETWORK_ADAPTER", L"Ethernet",
		  L"Windows 11", L"x64", L""}}} ;
	IntelCollectorMetadataAssessment result ;	// 証拠なしの一時判定。
	DRIVERCRATE_EXPECT(
		context, inspectIntelCollectorMetadataPage( page, targets, WINDOWS11_RESOLVED_UTC, result)) ;
	DRIVERCRATE_EXPECT( context, result.releaseParsed) ;
	DRIVERCRATE_EXPECT( context, result.candidate.has_value()) ;
	DRIVERCRATE_EXPECT( context, result.identity.status == IntelCollectorIdentityStatus::ACCEPTED) ;
	DRIVERCRATE_EXPECT( context, result.targets.size() == targets.size()) ;
	// 不成立時は後続要素参照を避けて安全に試験を終えます。
	if( result.targets.size() != targets.size() || !result.candidate) {
		return ;
	}

	DRIVERCRATE_EXPECT( context,
					   result.targets[0].state == IntelCollectorTargetState::MATCH &&
						   result.targets[0].reason == IntelCollectorTargetReason::MATCHED &&
						   result.targets[0].sku == L"900001" &&
						   result.targets[0].candidateOrdinal == 0U) ;
	DRIVERCRATE_EXPECT( context, result.targets[1].state == IntelCollectorTargetState::UNKNOWN &&
									result.targets[1].reason ==
										IntelCollectorTargetReason::PRODUCT_UNLISTED) ;
	DRIVERCRATE_EXPECT( context, result.targets[2].state == IntelCollectorTargetState::NO_MATCH &&
									result.targets[2].reason ==
										IntelCollectorTargetReason::PRODUCT_CONFLICT) ;
	DRIVERCRATE_EXPECT( context, result.targets[3].state == IntelCollectorTargetState::NO_MATCH &&
									result.targets[3].reason ==
										IntelCollectorTargetReason::PURPOSE_CONFLICT) ;
	DRIVERCRATE_EXPECT( context,
					   result.targets[4].state == IntelCollectorTargetState::NO_MATCH &&
						   result.targets[4].reason == IntelCollectorTargetReason::OS_CONFLICT) ;
	DRIVERCRATE_EXPECT( context, result.targets[5].state == IntelCollectorTargetState::NO_MATCH &&
									result.targets[5].reason ==
										IntelCollectorTargetReason::ARCHITECTURE_CONFLICT) ;
	DRIVERCRATE_EXPECT( context,
					   result.targets[6].state == IntelCollectorTargetState::UNKNOWN &&
						   result.targets[6].reason == IntelCollectorTargetReason::CHIP_UNKNOWN) ;
	DRIVERCRATE_EXPECT( context,
					   result.targets[7].state == IntelCollectorTargetState::UNKNOWN &&
						   result.targets[7].reason == IntelCollectorTargetReason::INVALID_QUERY) ;
	DRIVERCRATE_EXPECT( context, result.candidate->payloads.size() == 1U &&
									result.candidate->packageVersion == L"31.2.2" &&
									result.candidate->recordEvidenceId == 1U) ;
	OfficialReleaseRecord	   normalRelease ;	// 通常recordとの同一field比較入力。
	OfficialDistributionRecord normalRecord ;	// 既存root検証を通る対照。
	DRIVERCRATE_EXPECT( context,
					   parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11,
												  page, normalRelease)) ;
	DRIVERCRATE_EXPECT( context, adaptIntelEthernetWindows11DistributionRecord(
									std::move( normalRelease), windows11RootEvidence(), 2U,
									WINDOWS11_RESOLVED_UTC, normalRecord)) ;
	DRIVERCRATE_EXPECT( context,
					   normalRecord.packageVersion == result.candidate->packageVersion &&
						   normalRecord.parserId == result.candidate->parserId &&
						   normalRecord.parserRevision == result.candidate->parserRevision &&
						   normalRecord.eulaText == result.candidate->eulaText &&
						   normalRecord.payloads.size() == result.candidate->payloads.size() &&
						   normalRecord.payloads[0].publishedSha256 ==
							   result.candidate->payloads[0].publishedSha256) ;

	auto conflicting			= targets[0] ;	// 不明製品でも明示OS矛盾を隠しません。
	conflicting.model			= L"Unlisted Fixture" ;
	conflicting.operatingSystem = L"Windows 10" ;
	const std::array conflictTargets{conflicting} ;	// 複数軸の優先順位。
	DRIVERCRATE_EXPECT( context, inspectIntelCollectorMetadataPage( page, conflictTargets,
																  WINDOWS11_RESOLVED_UTC, result)) ;
	DRIVERCRATE_EXPECT( context,
					   result.targets.size() == 1U &&
						   result.targets[0].state == IntelCollectorTargetState::NO_MATCH &&
						   result.targets[0].reason == IntelCollectorTargetReason::OS_CONFLICT) ;

	// UNKNOWN軸が先にあっても後続の矛盾を見落としません。
	const std::array<IntelCollectorTargetQuery, 6U> combinations{
		{{L"unknown-purpose-arch", L"Intel", L"Fixture® Adapter X1", L"NETWORK_ADAPTER", L"Other",
		  L"Windows 11", L"arm64", L""},
		 {L"unknown-os-arch", L"Intel", L"Fixture® Adapter X1", L"NETWORK_ADAPTER", L"Ethernet",
		  L"Other", L"x86", L""},
		 {L"unknown-product-purpose", L"Intel", L"Unknown", L"NETWORK_ADAPTER", L"Wi-Fi",
		  L"Windows 10", L"x86", L""},
		 {L"unknown-everywhere", L"Intel", L"Unknown", L"NETWORK_ADAPTER", L"Other", L"Other",
		  L"Other", L"Chip"},
		 {L"purpose-first", L"Intel", L"Fixture® Adapter X1", L"NETWORK_ADAPTER", L"Other",
		  L"Other", L"Other", L"Chip"},
		 {L"invalid-unicode", L"Intel", L"Fixture® Adapter X1", L"NETWORK_ADAPTER", L"\xd800",
		  L"Windows 10", L"x64", L""}}} ;	// 不正queryからはNO_MATCHを作りません。
	const std::array expectedReasons{IntelCollectorTargetReason::ARCHITECTURE_CONFLICT,
									 IntelCollectorTargetReason::ARCHITECTURE_CONFLICT,
									 IntelCollectorTargetReason::PURPOSE_CONFLICT,
									 IntelCollectorTargetReason::PRODUCT_UNLISTED,
									 IntelCollectorTargetReason::PURPOSE_UNKNOWN,
									 IntelCollectorTargetReason::INVALID_QUERY} ;	// 固定oracle。
	DRIVERCRATE_EXPECT( context, inspectIntelCollectorMetadataPage( page, combinations,
																  WINDOWS11_RESOLVED_UTC, result)) ;
	DRIVERCRATE_EXPECT( context, result.targets.size() == combinations.size()) ;
	// 元分母を維持した判定と第一理由を両方確認します。
	for( std::size_t index = 0U; index < result.targets.size() && index < combinations.size();
		++index) {
		DRIVERCRATE_EXPECT( context, result.targets[index].reason == expectedReasons[index] &&
										result.targets[index].state ==
											(index < 3U ? IntelCollectorTargetState::NO_MATCH
														: IntelCollectorTargetState::UNKNOWN)) ;
	}

	std::vector<std::wstring> keys ;	// Queryのview寿命を保持する300公開key。
	keys.reserve( 301U) ;
	std::vector<IntelCollectorTargetQuery> manyTargets ;	// 一本文へ結ぶ最大集合。
	manyTargets.reserve( 301U) ;
	// 同じ公式recordを300件の対象へ結んでも配布候補を複製しません。
	for( std::size_t index = 0U; index < 301U; ++index) {
		keys.push_back( L"public-" + std::to_wstring( index)) ;
		auto query		= targets[0] ;	// 製品は同じ、対象keyだけが異なる要求。
		query.targetKey = keys.back() ;
		manyTargets.push_back( query) ;
	}

	DRIVERCRATE_EXPECT(
		context, inspectIntelCollectorMetadataPage(
					 page, std::span<const IntelCollectorTargetQuery>{manyTargets}.first( 300U),
					 WINDOWS11_RESOLVED_UTC, result)) ;
	DRIVERCRATE_EXPECT( context, result.candidate && result.targets.size() == 300U) ;
	// 全対象の参照先が一つであることを確認します。
	for( const auto &target : result.targets) {
		DRIVERCRATE_EXPECT( context, target.candidateOrdinal == 0U &&
										target.state == IntelCollectorTargetState::MATCH) ;
	}

	DRIVERCRATE_EXPECT( context, !inspectIntelCollectorMetadataPage( page, manyTargets,
																   WINDOWS11_RESOLVED_UTC, result)) ;
	DRIVERCRATE_EXPECT( context, result.targets.empty() && !result.candidate) ;
	auto duplicate		   = targets ;	// 同一keyを二対象に与える拒否条件。
	duplicate[1].targetKey = duplicate[0].targetKey ;
	DRIVERCRATE_EXPECT( context, !inspectIntelCollectorMetadataPage( page, duplicate,
																   WINDOWS11_RESOLVED_UTC, result)) ;
	DRIVERCRATE_EXPECT( context, result.targets.empty() && !result.candidate) ;
	std::wstring				wrongHero = page ;	// 配布parserは維持してhero所属だけ壊す。
	constexpr std::wstring_view CTA =
		L"dc-page-available-downloads-hero-button__cta" ;	// 固定class。
	const auto heroButton = wrongHero.find( CTA) ;			// 差替え位置。
	// 配布buttonが失われてもrelease単独の成功では候補にしません。
	if( heroButton != wrongHero.npos) {
		wrongHero.replace( heroButton, CTA.size(), L"different-button") ;
	}

	OfficialReleaseRecord heroRelease ;	// Release parserだけの成立を確認します。
	DRIVERCRATE_EXPECT( context,
					   parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11,
												  wrongHero, heroRelease)) ;
	DRIVERCRATE_EXPECT( context, inspectIntelCollectorMetadataPage( wrongHero, targets,
																  WINDOWS11_RESOLVED_UTC, result)) ;
	DRIVERCRATE_EXPECT( context,
					   !result.candidate && !result.releaseParsed &&
						   result.targets[0].state == IntelCollectorTargetState::UNKNOWN &&
						   result.identity.status == IntelCollectorIdentityStatus::SCHEMA_REJECTED) ;
	std::wstring noRelease = page ;							// 公開hash欠損の反例。
	const auto	 marker	   = noRelease.find( L"SHA256:") ;	// 唯一のhash label。
	// 配布情報欠測を一覧の一致へ転用しません。
	if( marker != noRelease.npos) {
		noRelease.replace( marker, 7U, L"MISSING") ;
	}

	DRIVERCRATE_EXPECT( context, inspectIntelCollectorMetadataPage( noRelease, targets,
																  WINDOWS11_RESOLVED_UTC, result)) ;
	DRIVERCRATE_EXPECT( context,
					   !result.candidate &&
						   result.targets[0].reason == IntelCollectorTargetReason::RELEASE_UNKNOWN) ;
	std::wstring noTerms = page ;	// 一覧と配布識別は正しいが許諾本文を欠く入力。
	noTerms.replace( noTerms.find( LICENSE_BODY), LICENSE_BODY.size(), L"") ;
	DRIVERCRATE_EXPECT( context, inspectIntelCollectorMetadataPage( noTerms, targets,
																  WINDOWS11_RESOLVED_UTC, result)) ;
	DRIVERCRATE_EXPECT( context, !result.candidate &&
									result.targets[0].reason ==
										IntelCollectorTargetReason::RELEASE_UNKNOWN &&
									!result.targets[0].candidateOrdinal) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 許諾版が同じでも本文や配布hashの変更がrecord差分になることを確認します。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testLicenseRecordChanges( TestContext &context)
{
	const std::wstring	  page = licensePage( LICENSE_BODY) ;	// 変更前の架空page。
	OfficialReleaseRecord original ;							// 再確認前に保持するsnapshot。
	DRIVERCRATE_EXPECT( context,
					   parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025,
												  page, original)) ;
	// 一度に一fieldだけを変更する架空差分の組。
	constexpr std::array CHANGES{
		std::array{std::wstring_view( L"Final clause."), std::wstring_view( L"Changed clause.")},
		std::array{std::wstring_view( L"2030.01.02"), std::wstring_view( L"2031.02.03")},
		std::array{std::wstring_view( L"SHA256: 0"), std::wstring_view( L"SHA256: F")}} ;
	// 各変更後のpageは解析できるが、承認前のrecordと一致してはならない。
	for( const auto &change : CHANGES) {
		std::wstring changed( page) ;	// 独立した変更後page。
		changed.replace( changed.find( change[0]), change[0].size(), change[1]) ;
		OfficialReleaseRecord current ;	// 再解析した変更後snapshot。
		DRIVERCRATE_EXPECT(
			context, parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025,
												changed, current)) ;
		DRIVERCRATE_EXPECT( context, current != original) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 別modal・別URL・偽属性・重複・不正終端を全文付き成功にしません。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testLicenseBindingRejection( TestContext &context)
{
	const std::wstring	 page = licensePage( LICENSE_BODY) ;	// 差替え元の正常page。
	// 全文表示を保証できない構造の置換組。
	constexpr std::array CHANGES{
		std::array{std::wstring_view( L"data-modal-id=\"1\""),
				   std::wstring_view( L"data-modal-id=\"2\"")},
		std::array{std::wstring_view( L"data-modal-id=\"1\""),
				   std::wstring_view( L"class=' data-modal-id=\"1\" '")},
		std::array{std::wstring_view( L"</textarea>"), std::wstring_view( L"</textarea-broken>")},
		std::array{std::wstring_view( L"id=\"content-raw\""),
				   std::wstring_view( L"id=\"content-raw\" id=\"content-raw\"")},
		std::array{std::wstring_view( L"</body></html>"),
				   std::wstring_view( L"</body><p>lost clause</p></html>")},
		std::array{std::wstring_view( L"</head>"), std::wstring_view( L"<p>lost clause</p></head>")},
		std::array{std::wstring_view( L"</head>"),
				   std::wstring_view( L"<script>inline()</script></head>")},
		std::array{std::wstring_view( L"</head>"),
				   std::wstring_view( L"<style>li { content: 'clause'; }</style></head>")},
		std::array{std::wstring_view( L"[v2030.01.02]"), std::wstring_view( L"[draft]")}} ;
	// 不正な許諾欄が存在したら、本文なしの表示metadataへ戻さず拒否する。
	for( const auto &change : CHANGES) {
		std::wstring changed( page) ;	// 今回の不正page。
		changed.replace( changed.find( change[0]), change[0].size(), change[1]) ;
		IntelEthernetServerPageMetadata metadata ;	// 失敗後は全fieldが初期値。
		metadata.eulaText = L"previous snapshot" ;
		DRIVERCRATE_EXPECT( context, !parseIntelEthernetServerDownloadPage( changed, metadata)) ;
		DRIVERCRATE_EXPECT( context, metadata.eulaText.empty() && metadata.downloadUrl.empty()) ;
	}

	std::wstring revision = L"old" ;	// 失敗時に消去される許諾版。
	std::wstring text	  = L"old" ;	// 失敗時に消去される本文。
	DRIVERCRATE_EXPECT(
		context, !parseIntelDownloadLicense(
					 page, L"https://downloadmirror.intel.com/900002/other.zip", revision, text)) ;
	DRIVERCRATE_EXPECT( context, revision.empty() && text.empty()) ;
	DRIVERCRATE_EXPECT( context,
					   !parseIntelDownloadLicense(
						   page + page,
						   L"https://downloadmirror.intel.com/900001/Wired_driver_31.2.2_x64.zip",
						   revision, text)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 非表示になり得る未知構造や不完全な本文を受理しません。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testLicenseBodyRejection( TestContext &context)
{
	// 既知本文構造からの逸脱とUnicodeの不正を表す架空body。
	constexpr std::array BODIES{
		std::wstring_view( L"<p><b>broken</p></b>"),
		std::wstring_view( L"<p>unknown &surprise;</p>"),
		std::wstring_view( L"<p>unknown &verylongunknownentity;</p>"),
		std::wstring_view( L"<p>incomplete &#123</p>"),
		std::wstring_view( L"<p>&#0;</p>"),
		std::wstring_view( L"<p>&#xD800;</p>"),
		std::wstring_view( L"<p>&#x110000;</p>"),
		std::wstring_view( L"<p>&#x202E;</p>"),
		std::wstring_view( L"<p>\x0001 control</p>"),
		std::wstring_view( L"<p></p>"),
		std::wstring_view( L"<p><img src='missing clause' /></p>"),
		std::wstring_view( L"<p onclick='action'>clause</p>"),
		std::wstring_view( L"<p>text</p><script>inline()</script>"),
		std::wstring_view( LR"(<p>text</p><script type="text/javascript" src=")"
						  LR"(https://example.invalid/code.bundle.js"></script>)"),
		std::wstring_view( LR"(<p>text</p><script type="text/javascript" src=")"
						  LR"(/etc.clientlibs/intel/clientlibs/bundles/resources/js/)"
						  LR"(fixture.bundle.js"></script><p>lost clause</p>)")} ;
	// 全例で出力が空であることを確認し、直前snapshotの再利用を防ぐ。
	for( const std::wstring_view body : BODIES) {
		IntelEthernetServerPageMetadata metadata ;	// 拒否結果の出力先。
		DRIVERCRATE_EXPECT( context,
						   !parseIntelEthernetServerDownloadPage( licensePage( body), metadata)) ;
		DRIVERCRATE_EXPECT( context, metadata.eulaText.empty()) ;
	}

	const std::wstring				oversized( 65537U, L'A') ;	// 表示上限を超える本文。
	IntelEthernetServerPageMetadata metadata ;					// 容量・深さ拒否の出力先。
	DRIVERCRATE_EXPECT( context,
					   !parseIntelEthernetServerDownloadPage( licensePage( oversized), metadata)) ;
	std::wstring deep ;	// 上限より深いtag stackを要求する入力。
	// 65段は許可上限64を超え、本文サイズ内でも拒否される。
	for( std::size_t depth = 0U; depth < 65U; ++depth) {
		deep += L"<div>" ;
	}

	deep += L"clause" ;
	// 入れ子自体は整合させ、深さ制限が拒否理由になるようにする。
	for( std::size_t depth = 0U; depth < 65U; ++depth) {
		deep += L"</div>" ;
	}

	DRIVERCRATE_EXPECT( context, !parseIntelEthernetServerDownloadPage( licensePage( deep), metadata)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現行形式と同じServer 2025 x64 ZIP情報を欠落なく取得する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testValidPage( TestContext &context)
{
	IntelEthernetServerPageMetadata metadata ;	// Parserが設定する表示専用metadata。
	DRIVERCRATE_EXPECT( context, parseIntelEthernetServerDownloadPage( VALID_PAGE, metadata)) ;
	DRIVERCRATE_EXPECT( context, metadata.version == L"31.2.2") ;
	DRIVERCRATE_EXPECT( context, metadata.fileName == L"Wired_driver_31.2.2_x64.zip") ;
	DRIVERCRATE_EXPECT( context,
					   metadata.downloadUrl ==
						   L"https://downloadmirror.intel.com/900001/Wired_driver_31.2.2_x64.zip") ;
	DRIVERCRATE_EXPECT( context, metadata.displaySize == L"38.6 MB") ;
	DRIVERCRATE_EXPECT( context, metadata.sha256.size() == 64U) ;
	DRIVERCRATE_EXPECT( context, metadata.requiresEula) ;
	DRIVERCRATE_EXPECT( context, metadata.eulaText.empty() && metadata.eulaRevision.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 特定の現行版へ固定せず、同一形式の明示新版を解析する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testReleaseChange( TestContext &context)
{
	std::wstring changed( VALID_PAGE) ;	// 全版表示を同じ架空新版へ変更するpage。
	std::size_t	 position{} ;			// 次に置換する版の開始位置。
	// Fixture内の全ての版表記を同じ長さの新版へ置換する。
	while( (position = changed.find( L"31.2.2", position)) != std::wstring::npos) {
		changed.replace( position, 6U, L"32.1.0") ;
		position += 6U ;
	}

	IntelEthernetServerPageMetadata metadata ;	// 新版解析結果。
	DRIVERCRATE_EXPECT( context, parseIntelEthernetServerDownloadPage( changed, metadata)) ;
	DRIVERCRATE_EXPECT( context, metadata.version == L"32.1.0") ;
}

//------------------------------------------------------------------------------
/**
 * @brief 別host、別OS、別architecture、重複、hash欠落を推測せず拒否する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testRejectedPages( TestContext &context)
{
	IntelEthernetServerPageMetadata metadata ;					// 各拒否後に空であるべき結果。
	std::wstring					wrongHost( VALID_PAGE) ;	// Intel類似名の第三者host。
	wrongHost.replace( wrongHost.find( L"downloadmirror.intel.com"),
					  std::wstring_view( L"downloadmirror.intel.com").size(),
					  L"downloadmirror.intel.example") ;
	DRIVERCRATE_EXPECT( context, !parseIntelEthernetServerDownloadPage( wrongHost, metadata)) ;
	DRIVERCRATE_EXPECT( context, metadata.downloadUrl.empty()) ;

	std::wstring wrongOs( VALID_PAGE) ;	// Server 2022へ置換した別OS page。
	wrongOs.replace( wrongOs.find( L"Windows Server 2025 family"),
					std::wstring_view( L"Windows Server 2025 family").size(),
					L"Windows Server 2022 family") ;
	DRIVERCRATE_EXPECT( context, !parseIntelEthernetServerDownloadPage( wrongOs, metadata)) ;

	std::wstring x86( VALID_PAGE) ;	// x64 suffixを持たない配布。
	std::size_t	 position{} ;		// Fixture内の全suffixを置換する位置。
	// 全file名をx86形式へ変更し、表示整合だけで受理されないことを確認する。
	while( (position = x86.find( L"_x64.zip", position)) != std::wstring::npos) {
		x86.replace( position, 8U, L"_x86.zip") ;
		position += 8U ;
	}

	DRIVERCRATE_EXPECT( context, !parseIntelEthernetServerDownloadPage( x86, metadata)) ;

	std::wstring	  duplicate( VALID_PAGE) ;						// 同じ対象ZIP URLを二件含む曖昧なpage。
	const std::size_t insertion = duplicate.find( L"</button>") ;	// 二件目の挿入位置。
	DRIVERCRATE_EXPECT( context, insertion != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( insertion != std::wstring::npos) {
		duplicate.insert( insertion, LR"(<a href="https://downloadmirror.intel.com/900002/)"
									LR"(Wired_driver_31.2.2_x64.zip">duplicate</a>)") ;
		DRIVERCRATE_EXPECT( context, !parseIntelEthernetServerDownloadPage( duplicate, metadata)) ;
	}

	std::wstring missingHash( VALID_PAGE) ;	// 必須hash labelを欠くpage。
	missingHash.replace( missingHash.find( L"SHA256:"), 7U, L"Digest:") ;
	DRIVERCRATE_EXPECT( context, !parseIntelEthernetServerDownloadPage( missingHash, metadata)) ;

	std::wstring	  mismatchedDescription( VALID_PAGE) ;	// 説明欄だけ別版の曖昧な配布。
	const std::size_t descriptionVersion =
		// Buttonより後の説明欄の版位置。
		mismatchedDescription.rfind( L"31.2.2") ;
	mismatchedDescription.replace( descriptionVersion, 6U, L"31.2.1") ;
	DRIVERCRATE_EXPECT( context,
					   !parseIntelEthernetServerDownloadPage( mismatchedDescription, metadata)) ;

	std::wstring nbspDescription( VALID_PAGE) ;	// 実pageと同じ強調label末尾NBSP。
	nbspDescription.insert( nbspDescription.find( L"</strong>"), L" \u00a0") ;
	DRIVERCRATE_EXPECT( context, parseIntelEthernetServerDownloadPage( nbspDescription, metadata)) ;

	DRIVERCRATE_EXPECT( context, !parseIntelEthernetServerDownloadPage( L"<html></html>", metadata)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Intel 727998のWin11 metadataをEULA・hash保持のdistribution recordへ変換します。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testWindows11DistributionRecord( TestContext &context)
{
	const std::wstring page = windows11LicensePage( LICENSE_BODY) ;	// 架空URLを持つ727998形状。
	IntelEthernetDownloadPageMetadata metadata ;					// 専用page parserの直接結果。
	DRIVERCRATE_EXPECT( context, parseIntelEthernetWindows11DownloadPage( page, metadata)) ;
	DRIVERCRATE_EXPECT( context, metadata.version == L"31.2.2") ;
	DRIVERCRATE_EXPECT( context, metadata.fileName == L"Wired_driver_31.2.2_x64.zip") ;
	DRIVERCRATE_EXPECT( context, metadata.displaySize == L"38.6 MB") ;
	DRIVERCRATE_EXPECT( context,
					   metadata.sha256 ==
						   L"2CBFF42AA02519E49F02D8E95A6572C44310E97FE67C42E299F2ABA6EA9344F5") ;
	DRIVERCRATE_EXPECT( context, metadata.eulaRevision == LICENSE_TITLE) ;
	DRIVERCRATE_EXPECT( context, metadata.eulaText.find( L"Fixture terms.") != std::wstring::npos) ;

	OfficialReleaseRecord release ;	// 既存共通release parserを経たadapter入力。
	DRIVERCRATE_EXPECT(
		context,
		parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11, page, release)) ;
	DRIVERCRATE_EXPECT( context, release.family == OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11) ;
	DRIVERCRATE_EXPECT( context, release.parserRevision == 3U) ;
	DRIVERCRATE_EXPECT( context, !release.publishedSizeBytes) ;
	const std::wstring expectedEula	  = release.eulaText ;			// 移動後recordとの同値確認用snapshot。
	const OfficialSourceEvidence root = windows11RootEvidence() ;	// URL非保持の架空root証拠。
	OfficialDistributionRecord	 distribution ;						// URL秘密所有の変換結果。
	DRIVERCRATE_EXPECT( context,
					   adaptIntelEthernetWindows11DistributionRecord(
						   std::move( release), root, 1U, WINDOWS11_RESOLVED_UTC, distribution)) ;
	DRIVERCRATE_EXPECT( context, release.downloadUrl.empty()) ;
	DRIVERCRATE_EXPECT( context, distribution.recordEvidenceId == 1U) ;
	DRIVERCRATE_EXPECT( context, distribution.parserId == L"intel-ethernet-windows11-page") ;
	DRIVERCRATE_EXPECT( context, distribution.parserRevision == 3U) ;
	DRIVERCRATE_EXPECT( context, distribution.recordRoute == L"intel-download-record") ;
	DRIVERCRATE_EXPECT( context, distribution.recordKey == L"727998") ;
	DRIVERCRATE_EXPECT( context, distribution.productFamily == L"Intel Ethernet Network Adapters") ;
	DRIVERCRATE_EXPECT( context, distribution.operatingSystem == L"Microsoft Windows 11") ;
	DRIVERCRATE_EXPECT( context, distribution.packageVersion == L"31.2.2") ;
	DRIVERCRATE_EXPECT( context,
					   distribution.terms == OfficialDistributionTerms::ACCEPTANCE_REQUIRED) ;
	DRIVERCRATE_EXPECT( context, distribution.eulaRevision == LICENSE_TITLE) ;
	DRIVERCRATE_EXPECT( context, distribution.eulaText == expectedEula) ;
	DRIVERCRATE_EXPECT( context, distribution.payloads.size() == 1U) ;
	// 一payloadを得た場合だけURL秘密所有と公開metadataの同値性を検証する。
	if( distribution.payloads.size() == 1U) {
		const OfficialDistributionPayloadRecord &payload = distribution.payloads[0] ;	// ZIP行。
		DRIVERCRATE_EXPECT( context,
						   payload.kind == OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE) ;
		DRIVERCRATE_EXPECT( context, payload.fileDisplayName == L"Wired_driver_31.2.2_x64.zip") ;
		DRIVERCRATE_EXPECT( context, !payload.publishedSizeBytes) ;
		DRIVERCRATE_EXPECT( context,
						   payload.publishedSha256 ==
							   L"2CBFF42AA02519E49F02D8E95A6572C44310E97FE67C42E299F2ABA6EA9344F5") ;
		DRIVERCRATE_EXPECT( context, payload.publisher.empty()) ;
		DRIVERCRATE_EXPECT( context, payload.expectedContentType == L"application/zip") ;
		DRIVERCRATE_EXPECT( context, payload.maximumBytes == 128ULL * 1'024ULL * 1'024ULL) ;
		DRIVERCRATE_EXPECT(
			context, payload.targetUrl.view() ==
						 L"https://downloadmirror.intel.com/900011/Wired_driver_31.2.2_x64.zip") ;
	}

	OfficialDistributionRecordEvidence evidence ;	// URLを保持しないrecord検証証拠。
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( distribution, evidence) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   officialRecordFingerprint( evidence) ==
						   "60e8e331663fc75f9958c832bf7776b85d5c9f2e48777e7f9d5fbc01be546fc4") ;
	DRIVERCRATE_EXPECT( context, evidence.rootEvidence.providerId ==
									INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID) ;
	std::vector<OfficialRecordPayloadDescriptor> descriptors ;	// UIへ渡せる方式別説明。
	DRIVERCRATE_EXPECT( context, describeOfficialDistributionRecordPayloads( distribution, evidence,
																		   descriptors) == 0) ;
	DRIVERCRATE_EXPECT( context, descriptors.size() == 1U) ;
	// 一payloadを説明できた場合だけ方式と未接続executorを確認する。
	if( descriptors.size() == 1U) {
		const OfficialRecordPayloadDescriptor &descriptor = descriptors[0] ;	// URL非保持の公開情報。
		DRIVERCRATE_EXPECT( context,
						   descriptor.route == OfficialRecordPayloadRoute::COMMON_INF_INSPECTION) ;
		DRIVERCRATE_EXPECT( context, descriptor.downloadGrantSupported &&
										descriptor.contentInspectorAvailable &&
										!descriptor.executorAvailable) ;
		DRIVERCRATE_EXPECT( context, descriptor.fileDisplayName == metadata.fileName) ;
	}

	RecordScopedDownloadGrant grant ;	// 同じrecord一payloadに限定する短命grant。
	DRIVERCRATE_EXPECT( context, grant.issue( distribution, evidence, 0U, 11U,
											WINDOWS11_RESOLVED_UTC + 1U, 0U) == 0) ;
	DRIVERCRATE_EXPECT( context, distribution.payloads[0].targetUrl.empty()) ;
	DRIVERCRATE_EXPECT(
		context, grant.metadata().providerId == INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID &&
					 grant.metadata().state == OfficialDownloadGrantState::GRANT_ISSUED) ;
	DRIVERCRATE_EXPECT( context, grant.payloadView().targetUrl.empty()) ;
}

/**
 * @brief 現行pageのplain text配布版表記だけを有限に受理することを確認します。
 * @param[in,out] context Assertionの集計先です。
 */
void testWindows11PlainDescription( TestContext &context)
{
	std::wstring page( WINDOWS11_PAGE) ;	// Strong要素を現行plain text構造へ置換する入力です。
	// 従来の強調要素付き説明欄です。
	const std::wstring_view strong =
		L"<strong>Driver Package:</strong> Wired_driver_31.2.2_x64.zip" ;
	// 現行のplain textとNBSPで構成する説明欄です。
	const std::wstring_view plain	 = L"Driver Package:\u00a0 Wired_driver_31.2.2_x64.zip" ;
	const std::size_t		position = page.find( strong) ;	// 一意な説明欄の置換位置です。
	DRIVERCRATE_EXPECT( context, position != std::wstring::npos) ;
	// Fixture構築に成功した場合だけ対象構造を置換する。
	if( position != std::wstring::npos) {
		page.replace( position, strong.size(), plain) ;
	}

	IntelEthernetDownloadPageMetadata metadata ;	// 現行構造の解析結果です。
	DRIVERCRATE_EXPECT( context, parseIntelEthernetWindows11DownloadPage( page, metadata)) ;
	DRIVERCRATE_EXPECT( context, metadata.fileName == L"Wired_driver_31.2.2_x64.zip") ;

	std::wstring	  nested( page) ;							// 未確認tagを配布版の前へ置く拒否入力です。
	const std::size_t nestedPosition = nested.find( plain) ;	// Plain説明欄の一意な位置です。
	DRIVERCRATE_EXPECT( context, nestedPosition != std::wstring::npos) ;
	// Fixture構築に成功した場合だけtag混入を作る。
	if( nestedPosition != std::wstring::npos) {
		nested.replace( nestedPosition, plain.size(),
					   L"Driver Package:<em>Wired_driver_31.2.2_x64.zip</em>") ;
	}

	DRIVERCRATE_EXPECT( context, !parseIntelEthernetWindows11DownloadPage( nested, metadata)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Family、file、hash、EULA、size、root時刻の不一致をadapterで拒否します。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testWindows11DistributionRecordRejections( TestContext &context)
{
	const std::wstring page = windows11LicensePage( LICENSE_BODY) ;	// 正常形から一fieldずつ壊す入力。
	OfficialReleaseRecord baseline ;								// 全拒否fixtureの基準release。
	DRIVERCRATE_EXPECT( context,
					   parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11,
												  page, baseline)) ;
	const OfficialSourceEvidence root = windows11RootEvidence() ;	// 正常root binding。
	OfficialDistributionRecord	 output ;							// 失敗時に初期値へ戻る出力。

	OfficialReleaseRecord		 wrongFamily = baseline ;	// Server familyへ差し替えたrelease。
	wrongFamily.family						 = OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025 ;
	DRIVERCRATE_EXPECT(
		context, !adaptIntelEthernetWindows11DistributionRecord( std::move( wrongFamily), root, 2U,
																WINDOWS11_RESOLVED_UTC, output)) ;

	OfficialReleaseRecord wrongFile = baseline ;	// Versionと一致しないbasename。
	wrongFile.fileName				= L"Wired_driver_31.2.1_x64.zip" ;
	DRIVERCRATE_EXPECT(
		context, !adaptIntelEthernetWindows11DistributionRecord( std::move( wrongFile), root, 3U,
																WINDOWS11_RESOLVED_UTC, output)) ;

	OfficialReleaseRecord badHash = baseline ;	// 短縮された公開hash。
	badHash.publishedSha256.pop_back() ;
	DRIVERCRATE_EXPECT( context, !adaptIntelEthernetWindows11DistributionRecord(
									std::move( badHash), root, 4U, WINDOWS11_RESOLVED_UTC, output)) ;

	OfficialReleaseRecord missingEula = baseline ;	// 同意対象本文を欠くrelease。
	missingEula.eulaText.clear() ;
	DRIVERCRATE_EXPECT(
		context, !adaptIntelEthernetWindows11DistributionRecord( std::move( missingEula), root, 5U,
																WINDOWS11_RESOLVED_UTC, output)) ;

	OfficialReleaseRecord excessiveSize = baseline ;	// 共通payload上限を超えるexact size。
	excessiveSize.publishedSizeBytes	= 128ULL * 1'024ULL * 1'024ULL + 1U ;
	DRIVERCRATE_EXPECT(
		context, !adaptIntelEthernetWindows11DistributionRecord( std::move( excessiveSize), root, 6U,
																WINDOWS11_RESOLVED_UTC, output)) ;

	DRIVERCRATE_EXPECT( context, !adaptIntelEthernetWindows11DistributionRecord(
									OfficialReleaseRecord{baseline}, root, 7U,
									WINDOWS11_VALIDATED_UTC - 1U, output)) ;
	DRIVERCRATE_EXPECT( context, output.recordEvidenceId == 0U && output.payloads.empty()) ;

	std::wstring wrongProductPage( page) ;	// E610-XT2掲載を別製品へ変えたpage。
	wrongProductPage.replace( wrongProductPage.find( L"E610-XT2"), 8U, L"E610-XT4") ;
	IntelEthernetDownloadPageMetadata metadata ;	// Win11 profile拒否時の初期値出力。
	DRIVERCRATE_EXPECT( context,
					   !parseIntelEthernetWindows11DownloadPage( wrongProductPage, metadata)) ;
	DRIVERCRATE_EXPECT( context, metadata.downloadUrl.empty()) ;
	DRIVERCRATE_EXPECT( context, !parseIntelEthernetWindows11DownloadPage( VALID_PAGE, metadata)) ;
}

/**
 * @brief 三familyで変換を共有し、同意・root・file改変を非通信で拒否します。
 * @param[in,out] context Assertion集計先。
 */
void testSharedIntelZipAdapter( TestContext &context)
{
	// 製品ごとのURLを手書きで成功へ誘導せず、既存fixtureの版を共有する。
	for( const auto family :
		{OfficialReleaseFamily::INTEL_WIFI, OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025,
		 OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11}) {
		const auto *definition = officialSourceDefinition( family) ;	// 組み込み根拠。
		auto		root	   = windows11RootEvidence() ;				// 架空network本文取得証拠。
		root.providerId		   = definition->providerId ;
		root.policyId		   = definition->sourceId ;
		OfficialReleaseRecord release ;	// 別familyを混ぜない元metadata。
		DRIVERCRATE_EXPECT(
			context, parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11,
												windows11LicensePage( LICENSE_BODY), release)) ;
		release.family = family ;
		release.parserRevision =
			family == OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11 ? 3U : 2U ;
		// Wi-Fiだけは既存parserが要求するdriver-only basenameへ変える。
		if( family == OfficialReleaseFamily::INTEL_WIFI) {
			release.fileName = L"WiFi-31.2.2-Driver64-Win10-Win11.zip" ;
		}

		release.downloadUrl = L"https://downloadmirror.intel.com/900099/" + release.fileName ;
		OfficialDistributionRecord record ;	// 秘密所有の結果。
		DRIVERCRATE_EXPECT( context,
						   adaptIntelZipDistributionRecord( OfficialReleaseRecord{release}, root, 1U,
														   WINDOWS11_RESOLVED_UTC, record)) ;
		OfficialDistributionRecordEvidence evidence ;	// 共通grant前検証。
		DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( record, evidence) == 0 &&
										record.recordKey == definition->productKey &&
										record.payloads.size() == 1U) ;
		// 一要因ずつ破損させ、成功recordの残存も拒否する。
		for( unsigned mutation = 0U; mutation < 7U; ++mutation) {
			auto bad	 = release ;	// 元releaseを変更しないコピー。
			auto badRoot = root ;		// 元rootを変更しないコピー。
			// 型、名前、hash、同意、Provider、policy、parser版の各境界を検査する。
			switch( mutation) {
				// 未知系列を拒否する。
				case 0U:
					bad.family = OfficialReleaseFamily::UNKNOWN ;
					// 未知系列。
					break ;

				// 公開版とbasenameの不一致を拒否する。
				case 1U:
					bad.fileName = L"wrong.zip" ;
					// 公開版の不一致。
					break ;

				// 不完全な公開hashを拒否する。
				case 2U:
					bad.publishedSha256.pop_back() ;
					// 不完全hash。
					break ;

				// 同意本文の欠落を拒否する。
				case 3U:
					bad.eulaText.clear() ;
					// 本文なし。
					break ;

				// 別Providerの取得根拠を拒否する。
				case 4U:
					badRoot.providerId = L"wrong-provider" ;
					// 起点の差替え。
					break ;

				// 別policyの取得根拠を拒否する。
				case 5U:
					badRoot.policyId = L"wrong-policy" ;
					// Policyの差替え。
					break ;

				// 未確認parser版を拒否する。
				default:
					++bad.parserRevision ;
					// 未確認parser版。
					break ;
			}

			DRIVERCRATE_EXPECT( context,
							   !adaptIntelZipDistributionRecord( std::move( bad), badRoot, 1U,
																WINDOWS11_RESOLVED_UTC, record) &&
								   record.payloads.empty()) ;
		}
	}

	std::wstring page = licensePage(
		// List形式の架空許諾。
		L"<ul><li>Fixture terms <a href=\"https://example.test/terms\" target=\"_blank\">Reference</a></li></ul>") ;
	page.replace( page.find( LICENSE_TITLE), LICENSE_TITLE.size(),
				 L"Deprecated: Intel Fixture License [v2030.01.02]") ;
	page.replace( page.find( L"<html lang=\"en\"><head>"), 22U, L"<html lang=\"en\"> \n<head>") ;
	page.replace( page.find( L"</head><body>"), 13U, L"</head> \n<body>") ;
	std::wstring revision ;	// 明示改訂名。
	std::wstring terms ;	// 許諾原文を省略していないことの確認。
	DRIVERCRATE_EXPECT(
		context, parseIntelDownloadLicense(
					 page, L"https://downloadmirror.intel.com/900001/Wired_driver_31.2.2_x64.zip",
					 revision, terms)) ;
	DRIVERCRATE_EXPECT( context, revision.starts_with( L"Deprecated:") &&
									terms.find( L"https://example.test/terms") != terms.npos &&
									terms.find( L"Reference") != terms.npos) ;
	page.replace( page.find( L"https://example.test/terms"), 26U, L"javascript:alert(1)") ;
	DRIVERCRATE_EXPECT(
		context, !parseIntelDownloadLicense(
					 page, L"https://downloadmirror.intel.com/900001/Wired_driver_31.2.2_x64.zip",
					 revision, terms)) ;
}

/** @brief 配布・許諾・identity・全対象の下位例外を実coreで検査します。
 * @param[in,out] context Assertion集計。
 */
void testControlledIntelMetadata( TestContext &context)
{
	const auto html = windows11CollectorPage() ;	// 同一本文の架空配布・許諾・一覧。
	const std::array<IntelCollectorTargetQuery, 2U> targets{
		{{L"one", L"Intel", L"Fixture® Adapter X1", L"NETWORK_ADAPTER", L"Ethernet", L"Windows 11",
		  L"x64", L""},
		 {L"two", L"Intel", L"Unknown", L"NETWORK_ADAPTER", L"Ethernet", L"Windows 11", L"x64",
		  L""}}} ;								// 一致と未掲載の全分母。
	IntelCollectorMetadataAssessment result ;	// 本番所有結果。
	testParserCheckpoints(
		context,
		[&]( OfficialCollectorHttpControl &control) {
			return inspectIntelCollectorMetadataPageControlled(
				html, targets, WINDOWS11_RESOLVED_UTC, control, result) ;
		},
		[&] {
			return !result.candidate && result.targets.empty() && result.identity.products.empty() ;
		}) ;
	ParserTestControl normal ;	// 型付き入口の正常結果。
	DRIVERCRATE_EXPECT( context, inspectIntelCollectorMetadataPageControlled(
									html, targets, WINDOWS11_RESOLVED_UTC, normal, result)
										.status == CollectorParserStatus::COMPLETED) ;
	DRIVERCRATE_EXPECT( context, result.releaseParsed && result.candidate &&
									result.targets.size() == 2U &&
									result.targets[0].state == IntelCollectorTargetState::MATCH &&
									result.targets[1].state == IntelCollectorTargetState::UNKNOWN) ;
	ParserTestControl noRelease ;	// 配布未掲載は実装障害ではありません。
	DRIVERCRATE_EXPECT( context, inspectIntelCollectorMetadataPageControlled(
									L"<html><head></head><body></body></html>", targets,
									WINDOWS11_RESOLVED_UTC, noRelease, result)
										.status == CollectorParserStatus::COMPLETED) ;
	DRIVERCRATE_EXPECT( context, !result.candidate && result.targets.size() == 2U) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/intel_ethernet_server_page_parser_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runIntelEthernetServerPageParserTests( TestContext &context)
{
	testControlledIntelMetadata( context) ;
	testSharedIntelZipAdapter( context) ;
	testValidPage( context) ;
	testReleaseChange( context) ;
	testRejectedPages( context) ;
	testLicenseSnapshot( context) ;
	testLicenseRecordChanges( context) ;
	testLicenseBindingRejection( context) ;
	testLicenseBodyRejection( context) ;
	testWindows11DistributionRecord( context) ;
	testWindows11PlainDescription( context) ;
	testWindows11DistributionRecordRejections( context) ;
	testCollectorMetadataAssessment( context) ;
}

} // namespace drivercrate::test
