//------------------------------------------------------------------------------
/**
 * @file intel_download_only_page_tests.cpp
 * @brief 取得専用Intel heroの非通信試験です。
 * @version 01.01.02
 * @date 2026/09/23
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/23  複数hash・予算・根拠・許諾の拒否境界を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/23  全区間取得接続と公式module根拠付き許諾境界を追加。
 * Ver.01.01.01 Shunji Ogawa  2026/10/02  AI依存を撤去し非AI共通処理と試験を維持。
 * Ver.01.01.02 Shunji Ogawa  2026/10/12  共通索引を含む31登録でも開発用Intel ID非登録を確認。
 * </pre>
 */
//------------------------------------------------------------------------------

#include "intel_download_only_page_tests.h"
#include "test_framework.h"
#include "core/provider_registry.h"
#include "core/official_source_policy.h"
#include "platform/intel_download_only_page.h"
#include "platform/intel_download_license_parser.h"
#include "platform/official_file_verifier.h"
#include <algorithm>
#include <array>
#include <string>
#include <utility>

namespace drivercrate::test {
namespace {
/**
 * @brief 架空EXEと架空EULAで実pageの構造だけを再現します。
 * @param[in] sha512 SHA-512だけを公開する場合true。
 * @return Networkへ送信しないHTML fixture。
 */
[[nodiscard]] std::wstring page( const bool sha512)
{
	return std::wstring( LR"(<html><body><h2>Available Downloads</h2>
<div class="dc-page-available-downloads-hero component" data-component="download-hero" data-component-id="1">
<button data-modal-id="1" data-href="https://downloadmirror.intel.com/123456/Example-driver.exe"><span>Download</span><span>Example-driver.exe</span></button>
<ul class="dc-page-available-downloads-hero-details-list">
<li>Windows 11*, Windows 10, 64-bit*</li><li>Size: 3.0 MB</li><li>)") +
		   (sha512 ? L"SHA512: " + std::wstring( 128U, L'A')
				   : L"SHA256: " + std::wstring( 64U, L'b')) +
		   LR"(</li></ul></div><h2 class="dc-page-detailed-description__title">Detailed Description</h2>
<textarea id="content-raw" class="license-modal-content_body_license-text-raw" tabindex="0"><html lang="en"><head><title>Intel Fixture License Agreement [v2030.01.02]</title></head><body><p>Fictional evaluation terms.</p></body></html></textarea></body></html>)" ;
}
/**
 * @brief 同一GETの架空公式根拠を作ります。
 * @param[in] source 明示評価起点。
 * @return Network本文と有限時刻を持つ根拠。
 */
[[nodiscard]] OfficialSourceEvidence evidence( const IntelDownloadOnlySource source)
{
	OfficialSourceEvidence result ;	// 架空session。
	result.scanSessionId			 = 71U ;
	result.acquisitionId			 = 1U ;
	result.providerId				 = INTEL_DOWNLOAD_DEVELOPMENT_PROVIDER_ID ;
	result.policyId					 = INTEL_DOWNLOAD_DEVELOPMENT_POLICY_ID ;
	result.resourceId				 = intelDownloadOnlySourceDefinition( source)->resourceId ;
	result.originPolicyIndices		 = {0U} ;
	result.acquisition				 = MeasurementAcquisition::NETWORK_BODY ;
	result.bodyAcquiredUtcSeconds	 = 1000U ;
	result.originValidatedUtcSeconds = 1000U ;
	return result ;
}

/**
 * @brief 二起点・三予算・二hashを共通parserで確認します。
 * @param[in,out] context assertion集計先。
 */
void positive( TestContext &context)
{
	// 事前の製品family登録を増やさず共通HTTPだけへ接続する。
	DRIVERCRATE_EXPECT( context, builtInProviderDescriptors().size() == 31U) ;
	DRIVERCRATE_EXPECT( context,
					   std::ranges::none_of( builtInProviderDescriptors(), []( const auto &value) {
						   return value.id == INTEL_DOWNLOAD_DEVELOPMENT_PROVIDER_ID ;
					   })) ;
	DRIVERCRATE_EXPECT( context, officialSourcePolicyForProvider(
									INTEL_DOWNLOAD_DEVELOPMENT_PROVIDER_ID) != nullptr) ;
	DRIVERCRATE_EXPECT( context, validateBuiltInOfficialSourcePolicies()) ;
	// 同じ構造を両familyで使い、payload名や版をDB登録しない。
	for( const auto source :
		{IntelDownloadOnlySource::BLUETOOTH, IntelDownloadOnlySource::ARC_GRAPHICS}) {
		// 明示した有限三profileだけを試験する。
		for( const auto profile : {OfficialDownloadOnlyProfile::STANDARD_128_MIB,
								  OfficialDownloadOnlyProfile::EXTENDED_512_MIB,
								  OfficialDownloadOnlyProfile::LARGE_2_GIB}) {
			// SHA256とSHA512を独立に受理する。
			for( const bool sha512 : {false, true}) {
				OfficialDistributionRecord record ;		// 成功後の移動先。
				std::uint32_t			   stage{} ;	// 数値拒否段階。
				DRIVERCRATE_EXPECT( context, parseIntelDownloadOnlyPage( source, page( sha512),
																	   evidence( source), profile,
																	   1001U, record, stage)) ;
				DRIVERCRATE_EXPECT( context, stage == 0U) ;
				DRIVERCRATE_EXPECT( context, record.payloads.size() == 1U) ;
				// 失敗fixtureで範囲外参照を行わない。
				if( record.payloads.empty()) {
					continue ;
				}

				DRIVERCRATE_EXPECT( context, officialDownloadOnlyFormat( record.payloads.front()) ==
												OfficialDownloadOnlyFormat::WINDOWS_EXE) ;
				DRIVERCRATE_EXPECT( context, record.payloads.front().maximumBytes ==
												officialDownloadOnlyMaximumBytes( profile)) ;
				DRIVERCRATE_EXPECT( context,
								   !record.payloads.front().publishedSizeBytes.has_value()) ;
				DRIVERCRATE_EXPECT( context,
								   record.payloads.front().publishedSha512.empty() != sha512) ;
				DRIVERCRATE_EXPECT( context,
								   record.payloads.front().publishedSha256.empty() == sha512) ;
				OfficialDistributionRecordEvidence binding ;	// 共通record検証の証拠。
				DRIVERCRATE_EXPECT( context,
								   validateOfficialDistributionRecord( record, binding) == 0) ;
				record.payloads.front().kind = OfficialDistributionPayloadKind::OFFICIAL_INSTALLER ;
				record.payloads.front().maximumBytes = 128ULL * 1024ULL * 1024ULL ;
				DRIVERCRATE_EXPECT( context,
								   validateOfficialDistributionRecord( record, binding) != 0) ;
			}
		}
	}
}

/**
 * @brief 欠落・曖昧さ・別起点・許諾変化を部分成功にしないことを確認します。
 * @param[in,out] context assertion集計先。
 */
void negative( TestContext &context)
{
	const auto valid = page( false) ;	// 共通の正常fixture。
	// 各改変を独立に適用し、一つの欠落を他条件の合格で補わない。
	for( const auto &change :
		std::array{std::pair{L"download-hero", L"other-hero"},
				   std::pair{L"data-modal-id=\"1\"", L"data-modal-id=\"2\""},
				   std::pair{L"SHA256:", L"Digest:"}, std::pair{L"SHA256:", L"SHA256: SHA256:"},
				   std::pair{L"Windows 11*", L"Unknown OS"}, std::pair{L"64-bit", L"32-bit"},
				   std::pair{L"downloadmirror.intel.com", L"untrusted.invalid"},
				   std::pair{L"/123456/", L"/not-a-record/"},
				   std::pair{L"Example-driver.exe", L"Example-driver.zip"},
				   std::pair{L"<span>Example-driver.exe", L"<span>Different.exe"},
				   std::pair{L"content-raw", L"content-missing"},
				   std::pair{L"Fictional evaluation terms.", L"<script>bad</script>"},
				   std::pair{L"SHA256: b", L"SHA256: z"}}) {
		auto changed = valid ;	// 独立した改変入力。
		changed.replace( changed.find( change.first), std::wstring_view( change.first).size(),
						change.second) ;
		OfficialDistributionRecord record ;		// 失敗時は空。
		std::uint32_t			   stage{} ;	// 内容なしの拒否診断。
		DRIVERCRATE_EXPECT(
			context, !parseIntelDownloadOnlyPage( IntelDownloadOnlySource::BLUETOOTH, changed,
												 evidence( IntelDownloadOnlySource::BLUETOOTH),
												 OfficialDownloadOnlyProfile::STANDARD_128_MIB,
												 1001U, record, stage)) ;
		DRIVERCRATE_EXPECT( context, stage != 0U && record.payloads.empty()) ;
	}

	// 根拠・時刻・予算の独立した破損を全て拒否する。
	for( unsigned variant = 0U; variant < 7U; ++variant) {
		auto		  root	  = evidence( IntelDownloadOnlySource::BLUETOOTH) ;	// 正常GET根拠。
		auto		  profile = OfficialDownloadOnlyProfile::STANDARD_128_MIB ;	// 明示予算。
		auto		  html	  = valid ;											// HTMLの独立copy。
		std::uint64_t now	  = 1001U ;											// 根拠より後の解決時刻。
		// 一条件だけを壊し、拒否理由を混ぜない。
		switch( variant) {
			// 別resourceを混ぜない。
			case 0U:
				root.resourceId = OFFICIAL_PRIMARY_METADATA_RESOURCE_ID ;
				break ;

			// 別Providerの根拠を混ぜない。
			case 1U:
				root.providerId = INTEL_WIFI_OFFICIAL_PROVIDER_ID ;
				break ;

			// Cache根拠へ退行しない。
			case 2U:
				root.cachePermitted = true ;
				break ;

			// 明示予算の欠落を拒否する。
			case 3U:
				profile = OfficialDownloadOnlyProfile::DISABLED ;
				break ;

			// 解決時刻の逆転を拒否する。
			case 4U:
				now = 999U ;
				break ;

			// 複数heroを縮退させない。
			case 5U:
				html += L"<div data-component=\"download-hero\">" ;
				break ;

			// NULを黙って切り詰めない。
			case 6U:
				html += L'\0' ;
				break ;

			// 有限fixture範囲外には追加操作を行わない。
			default:
				break ;
		}

		OfficialDistributionRecord record ;		// 失敗出力。
		std::uint32_t			   stage{} ;	// 数値診断。
		DRIVERCRATE_EXPECT( context,
						   !parseIntelDownloadOnlyPage( IntelDownloadOnlySource::BLUETOOTH, html,
													   root, profile, now, record, stage)) ;
		DRIVERCRATE_EXPECT( context, record.payloads.empty()) ;
	}

	DRIVERCRATE_EXPECT( context, intelDownloadOnlySourceDefinition(
									static_cast<IntelDownloadOnlySource>( 99)) == nullptr) ;
}
/**
 * @brief 空欄を単独許可せず、公式module観測と実要素へ結合します。
 * @param[in,out] context assertion集計先。
 */
void emptyTerms( TestContext &context)
{
	auto	   html		 = page( true) ;							// 実コードを転載しない構造fixture。
	const auto bodyStart = html.find( L"<html lang=\"en\">") ;		// 埋込み文書の開始。
	const auto bodyEnd	 = html.find( L"</textarea>", bodyStart) ;	// 空欄にする文書終端。
	html.erase( bodyStart, bodyEnd - bodyStart) ;
	html.insert( html.find( L"data-modal-id="), L"class=\"available-download-button__cta\" ") ;
	html += L"<script type=\"text/javascript\" src=\"" +
			std::wstring( INTEL_DOWNLOAD_BEHAVIOR_PATH) + L"\"></script>" ;
	const auto root = evidence( IntelDownloadOnlySource::ARC_GRAPHICS) ;	// Fresh HTML根拠。
	IntelDownloadBehaviorObservation behavior ;								// Fake HTTPの独立観測。
	behavior.evidence				= root ;
	behavior.evidence.acquisitionId = 2U ;
	behavior.sha256					= INTEL_DOWNLOAD_BEHAVIOR_SHA256 ;
	behavior.byteCount				= 5556U ;
	OfficialDistributionRecord record ;		// 解析成功時だけ公開するrecord。
	std::uint32_t			   stage{} ;	// 数値診断。
	const auto				   parse = [&]( const std::wstring					  &input,
						   const IntelDownloadBehaviorObservation *proof) {
		return parseIntelDownloadOnlyPage( IntelDownloadOnlySource::ARC_GRAPHICS, input, root,
														  OfficialDownloadOnlyProfile::LARGE_2_GIB, 1001U, record,
														  stage, proof) ;
	} ; // 同一根拠へ固定した試験入口。
	DRIVERCRATE_EXPECT( context, !parse( html, nullptr) && stage == 5U) ;
	DRIVERCRATE_EXPECT( context, parse( html, &behavior)) ;
	DRIVERCRATE_EXPECT( context, record.terms == OfficialDistributionTerms::CONFIRMED_NO_CONSENT &&
									record.eulaText.empty() && record.eulaRevision.empty() &&
									record.parserRevision == 2U) ;
	DRIVERCRATE_EXPECT( context, record.recordRoute.find( INTEL_DOWNLOAD_BEHAVIOR_SHA256) !=
									record.recordRoute.npos) ;
	std::wstring revision, text ;	// 既存の非空EULA parserの失敗出力。
	DRIVERCRATE_EXPECT(
		context,
		!parseIntelDownloadLicense(
			html, L"https://downloadmirror.intel.com/123456/Example-driver.exe", revision, text)) ;
	// 各構造改変を一つずつ適用し、別の合格条件で補わない。
	for( const auto &change : std::array{
			std::pair{L"data-modal-id=\"1\"", L"data-isconfidential=\"true\" data-modal-id=\"1\""},
			std::pair{L"available-download-button__cta", L"other-button"},
			std::pair{L"></textarea>", L">Unknown terms</textarea>"},
			std::pair{L".d5fff54a.bundle.js", L".changed.bundle.js"},
			std::pair{L"<script type=", L"<!--<script type="},
			std::pair{L"<textarea ", L"<script><textarea "},
			std::pair{L"<button ", L"<!--<button "},
			std::pair{L"<button ", L"<template><button "}}) {
		auto changed = html ;	// 独立した不正入力。
		changed.replace( changed.find( change.first), std::wstring_view( change.first).size(),
						change.second) ;
		DRIVERCRATE_EXPECT( context, !parse( changed, &behavior)) ;
		DRIVERCRATE_EXPECT( context, record.payloads.empty()) ;
	}

	// 同時に囲む偽要素も実要素へ昇格させない。
	for( const auto &frame :
		{std::pair{L"<!--", L"-->"}, std::pair{L"<script>", L"</script>"},
		 std::pair{L"<template>", L"</template>"}, std::pair{L"<textarea>", L"</textarea>"}}) {
		DRIVERCRATE_EXPECT( context, !parse( frame.first + html + frame.second, &behavior)) ;
	}

	// Hash・session・取得順・用途・fresh時刻の独立改変を拒否する。
	for( unsigned variant = 0U; variant < 12U; ++variant) {
		auto changed = behavior ;	// 正常module観測のcopy。
		// 一回の反例につき一つの結合だけを破る。
		switch( variant) {
			// Module変更。
			case 0U:
				changed.sha256[0] = L'0' ;
				break ;

			// Size変更。
			case 1U:
				++changed.byteCount ;
				break ;

			// 別session。
			case 2U:
				++changed.evidence.scanSessionId ;
				break ;

			// 取得順逆転。
			case 3U:
				changed.evidence.acquisitionId = 1U ;
				break ;

			// 別Provider。
			case 4U:
				changed.evidence.providerId = L"other" ;
				break ;

			// 別policy。
			case 5U:
				changed.evidence.policyId = L"other" ;
				break ;

			// 別用途。
			case 6U:
				changed.evidence.resourceId = OFFICIAL_PAYLOAD_RESOURCE_ID ;
				break ;

			// Redirect。
			case 7U:
				changed.evidence.redirectCount = 1U ;
				break ;

			// Cache許可。
			case 8U:
				changed.evidence.cachePermitted = true ;
				break ;

			// 時刻欠測。
			case 9U:
				changed.evidence.bodyAcquiredUtcSeconds.reset() ;
				break ;

			// 将来時刻。
			case 10U:
				changed.evidence.bodyAcquiredUtcSeconds = 1002U ;
				break ;

			// Origin不一致。
			case 11U:
				changed.evidence.originPolicyIndices = {1U} ;
				break ;

			// 範囲外はない。
			default:
				break ;
		}

		DRIVERCRATE_EXPECT( context, !parse( html, &changed) && record.payloads.empty()) ;
	}

	std::wstring hash ;	// 共通memory SHAの独立known-answer。
	DRIVERCRATE_EXPECT(
		context, computeBytesSha256( "abc", hash) == 0 &&
					 hash == L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") ;
	DRIVERCRATE_EXPECT( context, computeBytesSha256( "", hash) != 0 && hash.empty()) ;
	DRIVERCRATE_EXPECT( context,
					   computeBytesSha256( std::string( 1048577U, 'x'), hash) != 0 && hash.empty()) ;
	DRIVERCRATE_EXPECT(
		context, computeBytesSha256( "abd", hash) == 0 &&
					 hash != L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") ;
}
} // namespace

/** @see intel_download_only_page_tests.h */
void runIntelDownloadOnlyPageTests( TestContext &context)
{
	emptyTerms( context) ;
	positive( context) ;
	negative( context) ;
}
} // namespace drivercrate::test
