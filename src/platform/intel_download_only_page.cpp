//------------------------------------------------------------------------------
/**
 * @file intel_download_only_page.cpp
 * @brief Intel download heroと許諾を取得専用recordへ結合します。
 * @version 01.01.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/23  共通EXE解析と公開hash結合を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/23  全区間取得接続と公式module根拠付き許諾境界を追加。
 * </pre>
 */
//------------------------------------------------------------------------------

#include "platform/intel_download_only_page.h"

#include "core/official_source_policy.h"
#include "platform/intel_download_license_parser.h"

#include <algorithm>
#include <array>
#include <new>
#include <optional>
#include <utility>

namespace drivercrate {
namespace {
// 固定公式起点であり、配布版・payload URL・hashを保持しない。
constexpr std::array<IntelDownloadOnlySourceDefinition, 2> SOURCES{
	{{L"https://www.intel.com/content/www/us/en/download/18649/intel-wireless-bluetooth-drivers-for-windows-10-and-windows-11.html",
	  OFFICIAL_LANDING_RESOURCE_ID, L"Intel Wireless Bluetooth", L"18649"},
	 {L"https://www.intel.com/content/www/us/en/download/785597/intel-arc-graphics-windows.html",
	  OFFICIAL_PRIMARY_METADATA_RESOURCE_ID, L"Intel Arc Graphics", L"785597"}}} ;

/**
 * @brief 一意な開始markerから最初の終端までの有限部分を借用します。
 * @param[in] input 検証する領域。
 * @param[in] begin 一意でなければならない開始marker。
 * @param[in] end 終端marker。
 * @param[in] maximum 内側の文字数上限。
 * @return 曖昧さのない部分。欠落・重複・過大は値なし。
 */
[[nodiscard]] std::optional<std::wstring_view> between( const std::wstring_view input,
													   const std::wstring_view begin,
													   const std::wstring_view end,
													   const std::size_t	   maximum)
{
	const auto start = input.find( begin) ;	// 一意性を調べる開始位置。
	// 重複markerを先頭優先で採用しない。
	if( start == input.npos || input.find( begin, start + begin.size()) != input.npos) {
		return std::nullopt ;
	}

	const auto first = start + begin.size() ;		// 借用領域の開始。
	const auto last	 = input.find( end, first) ;	// 最初の終端。
	// 未終端・空・過大を部分結果にしない。
	if( last == input.npos || last == first || last - first > maximum) {
		return std::nullopt ;
	}

	return input.substr( first, last - first) ;
}

/**
 * @brief 公開SHA値をそのまま取得し、欠落と不正を区別します。
 * @param[in] details 同一heroの詳細list。
 * @param[in] label SHA256またはSHA512のlabel。
 * @param[in] length 必要なhex桁数。
 * @param[out] value 有効な公開値。欠落時は空。
 * @return 欠落または一意な有効値の場合true。
 */
[[nodiscard]] bool readHash( const std::wstring_view details, const std::wstring_view label,
							const std::size_t length, std::wstring &value)
{
	value.clear() ;
	// 片方のalgorithmだけが公表されるpageを許容する。
	if( details.find( label) == details.npos) {
		return true ;
	}

	const auto found = between( details, label, L"</li>", length + 16U) ;	// Label後の一行。
	// 前後空白以外のHTMLや不完全hashを採用しない。
	if( !found) {
		return false ;
	}

	const auto first = found->find_first_not_of( L" \t\r\n") ;	// 先頭空白以外。
	const auto last	 = found->find_last_not_of( L" \t\r\n") ;	// 末尾空白以外。
	// Exact hex長以外を切り詰めない。
	if( first == found->npos || last - first + 1U != length) {
		return false ;
	}

	const auto hash = found->substr( first, length) ;	// 公開hex。
	// 大小文字ASCII hexだけを受理する。
	if( !std::ranges::all_of( hash, []( wchar_t ch) {
		   return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f') ||
				  (ch >= L'A' && ch <= L'F') ;
	   })) {
		return false ;
	}

	value.assign( hash) ;
	return true ;
}
} // namespace

/** @see intel_download_only_page.h */
const IntelDownloadOnlySourceDefinition *intelDownloadOnlySourceDefinition(
	const IntelDownloadOnlySource source) noexcept
{
	const auto index = static_cast<std::size_t>( source) ;	// 固定二起点の位置。
	return index < SOURCES.size() ? &SOURCES[index] : nullptr ;
}

/** @see intel_download_only_page.h */
bool parseIntelDownloadOnlyPage( const IntelDownloadOnlySource source, const std::wstring_view html,
								const OfficialSourceEvidence	 &rootEvidence,
								const OfficialDownloadOnlyProfile profile,
								const std::uint64_t				  resolvedUtcSeconds,
								OfficialDistributionRecord &record, std::uint32_t &failureStage,
								const IntelDownloadBehaviorObservation *const behavior)
{
	record		 = {} ;
	failureStage = 1U ;
	try {
		const auto *definition = intelDownloadOnlySourceDefinition( source) ;	// 固定起点。
		// 未知起点・予算・別source根拠を通信結果へ補完しない。
		if( definition == nullptr || officialDownloadOnlyMaximumBytes( profile) == 0U ||
		   html.empty() || html.size() > 2U * 1024U * 1024U || html.find( L'\0') != html.npos ||
		   rootEvidence.providerId != INTEL_DOWNLOAD_DEVELOPMENT_PROVIDER_ID ||
		   rootEvidence.policyId != INTEL_DOWNLOAD_DEVELOPMENT_POLICY_ID ||
		   rootEvidence.resourceId != definition->resourceId) {
			return false ;
		}

		failureStage	= 2U ;
		const auto hero = between(
			html,
			L"<div class=\"dc-page-available-downloads-hero component\" data-component=\"download-hero\" data-component-id=\"1\">",
			L"<h2 class=\"dc-page-detailed-description__title\">", 32768U) ;	// 一配布領域。
		// 複数配布heroを一recordへ縮退しない。
		if( !hero || html.find( L"data-component=\"download-hero\"") !=
						html.rfind( L"data-component=\"download-hero\"")) {
			return false ;
		}

		const auto details =
			between( *hero, L"<ul class=\"dc-page-available-downloads-hero-details-list\">",
					L"</ul>", 4096U) ;											// 同じ詳細。
		const auto button = between( *hero, L"<button ", L"</button>", 8192U) ;	// 唯一の操作。
		// 詳細とbuttonの欠落・重複を拒否する。
		if( !details || !button) {
			return false ;
		}

		failureStage   = 3U ;
		const auto url = between( *button, L"data-href=\"", L"\"", 2048U) ;			// 親だけが保持するURL。
		constexpr std::wstring_view PREFIX = L"https://downloadmirror.intel.com/" ;	// 公式配布host。
		// Query・redirect URL・別hostからEXE名を推測しない。
		if( !url || !url->starts_with( PREFIX)) {
			return false ;
		}

		const auto path	 = url->substr( PREFIX.size()) ;	// 公開配布番号とbasename。
		const auto slash = path.find( L'/') ;				// 数値directoryとfileの境界。
		// 配布番号は数字一componentだけを認める。
		if( slash == path.npos || slash == 0U || slash > 12U ||
		   !std::ranges::all_of( path.substr( 0U, slash),
								[]( wchar_t ch) { return ch >= L'0' && ch <= L'9' ; })) {
			return false ;
		}

		const auto name = path.substr( slash + 1U) ;	// 保存pathへは使わない表示basename。
		// EXE拡張子と有限ASCII basenameを要求する。
		if( name.size() < 5U || name.size() > 260U || !name.ends_with( L".exe") ||
		   !std::ranges::all_of( name,
								[]( wchar_t ch) {
									return (ch >= L'0' && ch <= L'9') ||
										   (ch >= L'a' && ch <= L'z') ||
										   (ch >= L'A' && ch <= L'Z') || ch == L'_' || ch == L'-' ||
										   ch == L'.' ;
								}) ||
		   button->find( std::wstring( L">") + std::wstring( name) + L"</span>") == button->npos) {
			return false ;
		}

		failureStage = 4U ;
		// Windows 11と64-bitの公開記載を要求する。概算sizeはexact byteへ変換しない。
		if( details->find( L"Windows 11") == details->npos ||
		   (details->find( L"64-bit") == details->npos &&
			html.find( L"<li>Microsoft Windows* 11-64 - ") == html.npos)) {
			return false ;
		}

		OfficialDistributionPayloadRecord payload ;	// 同一heroから得た取得専用payload。
		payload.kind				= OfficialDistributionPayloadKind::OFFICIAL_INSTALLER ;
		payload.resourceId			= OFFICIAL_PAYLOAD_RESOURCE_ID ;
		payload.fileDisplayName		= name ;
		payload.expectedContentType = L"application/octet-stream" ;
		// 両hashがあれば両方を保持し、一方の不正をもう一方で回避しない。
		if( !readHash( *details, L"SHA256:", 64U, payload.publishedSha256) ||
		   !readHash( *details, L"SHA512:", 128U, payload.publishedSha512) ||
		   !setOfficialDownloadOnlyProfile( payload, profile)) {
			return false ;
		}

		failureStage = 5U ;
		OfficialDistributionRecord parsed ;	// 全条件が成立してから移動するrecord。
		const bool fullTerms = parseIntelDownloadLicense( html, *url, parsed.eulaRevision,
														 parsed.eulaText) ;	// 非空EULAの既存契約。
		// 空欄は既知moduleと同一GET系列の公開構造を別途確認した場合だけ扱う。
		if( !fullTerms) {
			// 不明module、別session、cache、redirect、時刻欠落を根拠へ補完しない。
			if( behavior == nullptr || behavior->byteCount != 5556U ||
			   behavior->sha256 != INTEL_DOWNLOAD_BEHAVIOR_SHA256 ||
			   behavior->evidence.scanSessionId != rootEvidence.scanSessionId ||
			   behavior->evidence.acquisitionId <= rootEvidence.acquisitionId ||
			   behavior->evidence.providerId != rootEvidence.providerId ||
			   behavior->evidence.policyId != rootEvidence.policyId ||
			   behavior->evidence.resourceId != OFFICIAL_PRIMARY_METADATA_RESOURCE_ID ||
			   behavior->evidence.redirectCount != 0U ||
			   behavior->evidence.originPolicyIndices != std::vector<std::uint32_t>{0U} ||
			   behavior->evidence.acquisition != MeasurementAcquisition::NETWORK_BODY ||
			   behavior->evidence.cachePermitted || !behavior->evidence.bodyAcquiredUtcSeconds ||
			   !behavior->evidence.originValidatedUtcSeconds ||
			   *behavior->evidence.bodyAcquiredUtcSeconds !=
				   *behavior->evidence.originValidatedUtcSeconds ||
			   !rootEvidence.bodyAcquiredUtcSeconds ||
			   *behavior->evidence.bodyAcquiredUtcSeconds < *rootEvidence.bodyAcquiredUtcSeconds ||
			   *behavior->evidence.bodyAcquiredUtcSeconds > resolvedUtcSeconds ||
			   !matchesIntelPublicEmptyDownloadLicense( html, *url, INTEL_DOWNLOAD_BEHAVIOR_PATH)) {
				return false ;
			}
		}

		parsed.rootEvidence		  = rootEvidence ;
		parsed.recordEvidenceId	  = 1U ;
		parsed.parserId			  = L"intel-download-hero-exe" ;
		parsed.parserRevision	  = fullTerms ? 1U : 2U ;
		parsed.recordRoute		  = fullTerms ? L"intel-download-hero"
											  : L"intel-download-hero-module-" +
												std::wstring( INTEL_DOWNLOAD_BEHAVIOR_SHA256) ;
		parsed.recordKey		  = definition->recordKey ;
		parsed.productFamily	  = definition->productFamily ;
		parsed.operatingSystem	  = L"Windows 11" ;
		parsed.architecture		  = OfficialDistributionArchitecture::WINDOWS_X64 ;
		parsed.terms			  = fullTerms ? OfficialDistributionTerms::ACCEPTANCE_REQUIRED
											  : OfficialDistributionTerms::CONFIRMED_NO_CONSENT ;
		parsed.resolvedUtcSeconds = resolvedUtcSeconds ;
		payload.targetUrl		  = SecretOfficialUrl{std::wstring( *url)} ;
		parsed.payloads.push_back( std::move( payload)) ;
		failureStage = 6U ;
		OfficialDistributionRecordEvidence validation ;	// 共通境界の再検証。
		// 時刻・根拠・hash・予算・許諾の不整合を部分recordで返さない。
		if( validateOfficialDistributionRecord( parsed, validation) != 0) {
			return false ;
		}

		record		 = std::move( parsed) ;
		failureStage = 0U ;
		return true ;
	} catch( const std::bad_alloc &) {
		record = {} ;
		return false ;
	}
}
} // namespace drivercrate
