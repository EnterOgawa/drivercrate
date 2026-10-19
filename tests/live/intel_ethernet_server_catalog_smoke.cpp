//------------------------------------------------------------------------------
/**
 * @file intel_ethernet_server_catalog_smoke.cpp
 * @brief Intel Ethernet Server公式検索の読み取り専用live検証。
 * @version 01.00.00
 * @date 2026/09/08
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  検索失敗時のHTTP statusと根拠を表示。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  固定ASCII診断と出力失敗を検査。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 固定Intel公式pageを既存HTTP、Parser、検索helperで検証します。架空の非機密device表示だけを端末内で使い、networkへ送信しません。Payload取得
 *       、PnP変更、driver導入、EULA同意は行いません。
 */
//------------------------------------------------------------------------------

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/com_raii.h"
#include "platform/official_http_client.h"
#include "platform/official_release_discovery_provider.h"
#include "platform/official_release_metadata.h"
#include "support/live_search_diagnostics.h"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr drivercrate::ScanSessionId SCAN_SESSION_ID = 1U ;		// Live検索専用の一時session ID。
constexpr std::uint32_t WINDOWS_SERVER2025_BUILD	 = 26100U ;	// 対象OS境界の公開major build。

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief Intel Ethernet Server公式pageを読み取り専用で検証する。
 *
 * Server 2025条件と架空の表示名を端末内だけで検索helperへ渡す。HTTP要求は組み込み固定URLだけとし、payloadを取得しない。失敗時も本文・URLを含まない件数と取得根拠の
 * 有無を表示する。
 * @return 取得根拠、schema、検索、診断出力の全成功時0。失敗時1。
 */
//------------------------------------------------------------------------------
int wmain()
{
	const drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;	// Test threadのCOM MTA。
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		std::cerr << "COM initialization failed.\n" ;
		return 1 ;
	}

	drivercrate::OfficialHttpClient	   client ;					// System proxyを使用する公式HTTP client。
	drivercrate::OfficialReleaseRecord observedRecord ;			// 解析後に検査するworker内metadata copy。
	std::size_t						   metadataReadCount{} ;	// 固定landing readerの呼出し回数。
	bool metadataRejected{} ;									// trueの場合は取得後の解析または取得根拠の検証で拒否された。
	const drivercrate::OfficialReleaseMetadataReader reader =
		[&client, &observedRecord, &metadataReadCount,
		 &metadataRejected]( const drivercrate::OfficialReleaseFamily family,
							const drivercrate::ScanSessionId		 session,
							drivercrate::OfficialReleaseRecord &release, bool &rejected) {
			++metadataReadCount ;
			const drivercrate::NativeError error = drivercrate::readOfficialReleaseMetadata(
				family, session, client, release, rejected) ;	// 固定公式landingの取得結果。
			metadataRejected = rejected ;
			// 取得とmetadata検証の両方が成功したrecordだけを、後続のschema照合用に保持する。
			if( error == 0 && !rejected) {
				// 呼出し終了後の非機密schema検証用に所有copyを残す。
				observedRecord = release ;
			}

			return error ;
		} ; // Productionと同じHTTP、source policy、Parserを使用する同期reader。

	const std::array							devices{drivercrate::OfficialCatalogDevice{
								   .deviceIdentity = L"intel-ethernet-live-fixture",
								   .model		 = L"Intel(R) Ethernet Network Adapter E810-CQDA2",
								   .manufacturer = L"Intel",
								   .driverClass	 = L"Net",
								   .deviceClassGuid = L"{4d36e972-e325-11ce-bfc1-08002be10318}",
								   .currentProvider = L"Intel",
								   .currentVersion	= L"",
								   .currentDate		= L"",
								   .localBindingFingerprint = L"",
	   }} ; // Hardware IDを含まず、networkへ渡らない一件の架空表示snapshot。
	drivercrate::ProviderProgress				lastProgress{} ;	// 最後に確定した検索進捗。
	const drivercrate::ProviderProgressCallback progressCallback =
		[&lastProgress]( const drivercrate::ProviderProgress &progress) {
			lastProgress = progress ;
		} ; // 端末情報を保持しない進捗受理先。

	const drivercrate::ScanResult result = drivercrate::scanOfficialReleaseMetadata(
		drivercrate::OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025, SCAN_SESSION_ID, devices,
		true, reader, progressCallback,
		WINDOWS_SERVER2025_BUILD) ;	// Payloadを取得しない表示検索結果。
	const bool hasLandingEvidence = client.hasSourceEvidence(
		SCAN_SESSION_ID, drivercrate::INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID,
		drivercrate::
			OFFICIAL_LANDING_RESOURCE_ID) ;	// 今回のlanding取得・根拠確定が成功した場合true。
	const bool hasPayloadEvidence = client.hasSourceEvidence(
		SCAN_SESSION_ID, drivercrate::INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID,
		drivercrate::
			OFFICIAL_PAYLOAD_RESOURCE_ID) ;	// 読み取り専用検索で存在してはならない取得根拠。
	// 検索結果から非機密の所有値だけを抜き出し、URLやlocalized messageを渡さない。
	const drivercrate::test::LiveSearchDiagnostics diagnostics{
		.error			  = result.error,
		.metadataReads	  = metadataReadCount,
		.metadataRejected = metadataRejected,
		.candidates		  = result.candidates.size(),
		.landingEvidence  = hasLandingEvidence,
		.payloadEvidence  = hasPayloadEvidence,
	} ;
	// 故障した出力先をclearまたは再試行せず、検索成功とも表示しない。
	if( !drivercrate::test::writeLiveSearchDiagnostics( std::cerr, diagnostics)) {

		return 1 ;
	}

	// 本体を取得しない検索試験でpayload根拠が生成されたら、境界違反として中止する。
	if( hasPayloadEvidence) {
		// 検索成否より先に非取得境界の破損を拒否する。
		std::cerr << "Intel Ethernet read-only search unexpectedly has payload evidence.\n" ;
		return 1 ;
	}

	// 一対象一候補の検索とmetadata読取りが成立しなければ、代表経路を合格にしない。
	if( !result.succeeded || result.error != 0 ||
	   result.state != drivercrate::ProviderScanState::CANDIDATES_AVAILABLE ||
	   result.coverage.eligibleDeviceCount != 1U || result.coverage.assessedDeviceCount != 1U ||
	   result.candidates.size() != 1U || metadataReadCount != 1U || metadataRejected) {
		// 先行recordの値を正本とし、403をproxy errorやmetadata拒否へ推測変換しない。
		std::cerr << "Intel Ethernet official search failed.\n" ;
		return 1 ;
	}

	const drivercrate::UpdateCandidate &candidate = result.candidates.front() ;	// 表示専用候補。
	// 公式web表示候補に導入権限やINF版を付与する退行を拒否し、取得元とdeviceも照合する。
	if( candidate.providerId != drivercrate::INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID ||
	   candidate.deviceIdentity != devices.front().deviceIdentity || candidate.identity.empty() ||
	   candidate.packageIdentity.empty() || candidate.sourceName.empty() ||
	   candidate.sourceLocation != L"www.intel.com" || !candidate.version.empty() ||
	   candidate.discoveryBasis != drivercrate::CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ||
	   candidate.action != drivercrate::DriverAction::NONE || candidate.installable ||
	   candidate.recommended || candidate.current) {
		std::cerr << "Intel Ethernet search returned an unsafe candidate state.\n" ;
		return 1 ;
	}

	// 配布版・本体情報・hash・利用条件を確認し、不完全な公式pageの受入れを検出する。
	if( observedRecord.family != drivercrate::OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025 ||
	   observedRecord.parserRevision < 2U || observedRecord.packageVersion.empty() ||
	   observedRecord.fileName.empty() || observedRecord.downloadUrl.empty() ||
	   observedRecord.displaySize.empty() || observedRecord.publishedSha256.size() != 64U ||
	   observedRecord.publishedSha256.find_first_not_of( L"0123456789ABCDEF") !=
		   std::wstring::npos ||
	   observedRecord.license != drivercrate::OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD ||
	   observedRecord.eulaRevision.empty() || observedRecord.eulaText.empty()) {
		std::cerr << "Intel Ethernet official page schema validation failed.\n" ;
		return 1 ;
	}

	// 公式page取得根拠と確定した全件進捗を要求し、表示だけの成功を防ぐ。
	if( !hasLandingEvidence ||
	   lastProgress.stage != drivercrate::ProviderStage::SEARCHING_OFFICIAL_CATALOGS ||
	   lastProgress.percentComplete != 100U || lastProgress.completedItems != 1U ||
	   lastProgress.totalItems != 1U) {
		std::cerr << "Intel Ethernet source evidence or progress validation failed.\n" ;
		return 1 ;
	}

	std::cout << "Intel Ethernet official search succeeded. Candidates: "
			  << result.candidates.size() << ", parser revision: " << observedRecord.parserRevision
			  << ".\n" ;
	std::cout.flush() ;
	return std::cout.good() ? 0 : 1 ;
}
