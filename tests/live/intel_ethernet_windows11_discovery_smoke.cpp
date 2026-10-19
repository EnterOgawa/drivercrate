//------------------------------------------------------------------------------
/**
 * @file intel_ethernet_windows11_discovery_smoke.cpp
 * @brief E610実機の公式自動探索を通常scan経路で検証する読取り専用live試験。
 * @version 01.00.00
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Metadata限定の試験C入口を追加。
 * </pre>
 *
 * @note CompositeUpdateProviderが列挙したpresent deviceのraw PnP IDを外部へ送信せず、
 *       組み込みIntel固定rootのmetadataだけを取得します。Cacheは明示的に迂回します。
 *       Payload取得、EULA同意、staging、driver／installer実行は行いません。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 * @see docs/vendor-provider-roadmap.md
 */
//------------------------------------------------------------------------------

#include "core/provider_registry.h"
#include "platform/com_raii.h"
#include "platform/composite_update_provider.h"

#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>

namespace {

//------------------------------------------------------------------------------
// Live試験の固定binding。
//------------------------------------------------------------------------------

constexpr drivercrate::ScanSessionId SCAN_SESSION_ID	 = 61U ;	// 試験Cのscan session ID。
constexpr drivercrate::OperationId	 TEST_OPERATION_ID	 = 61U ;	// Metadata承認のoperation ID。
constexpr std::uint64_t				 PREPARATION_PLAN_ID = 1U ;		// 空計画確認用のplan ID。

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief E610を含む実inventoryからIntel Windows 11公式recordを自動探索します。
 *
 * Driver Store列挙とIntel公式自動探索だけを有効にし、制限回線を含むmetadata通信を今回だけ
 * 許可します。Fresh cacheを使わず試験Bと同じ固定rootを再確認し、公開summary、候補行、
 * 準備対象0件を照合します。
 *
 * @param[in] argumentCount 実行file名を含む引数数です。
 * @param[in] arguments `--metadata-only-force-refresh`だけを受理します。
 * @return 自動探索・安全な表示候補・payload非取得境界が成立した場合は0、検証失敗は1、
 *         引数不正は2です。
 */
//------------------------------------------------------------------------------
int wmain( const int argumentCount, wchar_t *arguments[])
{
	// 明示optionのない実行をnetwork承認へ変換しない。
	if( arguments == nullptr || argumentCount != 2 || arguments[1] == nullptr ||
	   std::wstring_view( arguments[1]) != L"--metadata-only-force-refresh") {
		std::wcerr << L"Usage: drivercrate_intel_ethernet_windows11_discovery_smoke "
					  L"--metadata-only-force-refresh\n" ;
		return 2 ;
	}

	const drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;	// Worker相当のCOM MTA。
	// COM初期化失敗時はdevice列挙とnetwork処理を開始しない。
	if( FAILED( apartment.result())) {
		std::cerr << "COM initialization failed.\n" ;
		return 1 ;
	}

	drivercrate::ScanOptions options ;	// 今回だけの二Provider明示設定。
	options.useDefaultProviders = false ;
	options.enabledProviderIds	= {
		 std::wstring( drivercrate::DRIVER_STORE_PROVIDER_ID),
		 std::wstring( drivercrate::INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID)} ;
	options.officialDiscoveryApproval = drivercrate::OfficialDiscoveryScanApproval{
		.operationId		  = TEST_OPERATION_ID,
		.inspectionPermission = drivercrate::OfficialDiscoveryInspectionPermission::METADATA_ONLY,
		.restrictedNetworkApproved = true,
		.cacheMode				   = drivercrate::OfficialDiscoveryCacheMode::FORCE_REFRESH} ;
	// Registry、固定予算、Provider集合に不整合があるbuildではscanを開始しない。
	if( !drivercrate::validateScanOptions( options)) {
		std::cerr << "Automatic discovery scan options are invalid.\n" ;
		return 1 ;
	}

	drivercrate::ProviderProgress				lastProgress{} ;	// 最後に確定した全体進捗です。
	const drivercrate::ProviderProgressCallback progress =
		[&lastProgress]( const drivercrate::ProviderProgress &current) {
			lastProgress = current ;
		} ; // 非機密の段階と件数だけを保持します。
	drivercrate::CompositeUpdateProvider provider ;	// 製品通常scanと同じProvider集約です。
	const drivercrate::ScanResult		 result =
		// OSを変更しない実inventory検索です。
		provider.scan( SCAN_SESSION_ID, options, progress) ;
	const auto report =
		std::find_if( result.providerReports.begin(), result.providerReports.end(),
					 []( const drivercrate::ProviderScanReport &entry) {
						 return entry.descriptor.id ==
								drivercrate::INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID ;
					 }) ; // 自動探索Providerの公開報告です。
	const drivercrate::OfficialDiscoverySummary *const summary =
		// 今回の非機密route summaryです。
		provider.officialDiscoverySummary() ;
	const auto preparation = provider.preparationPlan(
		SCAN_SESSION_ID, PREPARATION_PLAN_ID) ;	// 空であるべき取得計画です。

	std::size_t officialCandidateCount{} ;	// Intel自動探索が公開した表示行数です。
	bool		unsafeCandidate{} ;			// 一件でも選択・導入可能ならtrueです。
	// Intelの候補だけを数え、metadata限定の安全状態を一件ずつ確認する。
	for( const drivercrate::UpdateCandidate &candidate : result.candidates) {
		// Driver Store等の別Provider候補は今回の自動探索集計へ含めない。
		if( candidate.providerId != drivercrate::INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID) {
			continue ;
		}

		++officialCandidateCount ;
		// 取得前表示行を選択可能、推奨、現在版または操作付きへ昇格させない。
		if( candidate.identity.empty() || candidate.deviceIdentity.empty() ||
		   candidate.packageIdentity.empty() || candidate.installable || candidate.recommended ||
		   candidate.current || candidate.action != drivercrate::DriverAction::NONE) {
			unsafeCandidate = true ;
		}
	}

	// 失敗時もURL、title、device identityを出さず、有限状態と件数だけを残す。
	if( report == result.providerReports.end() || summary == nullptr ||
	   summary->routes.size() != 1U) {
		std::cerr << "Automatic discovery did not return its complete public summary.\n" ;
		return 1 ;
	}

	const drivercrate::OfficialDiscoveryRouteSummary &route =
		// 一つのIntel固定root route結果です。
		summary->routes.front() ;
	std::cout << "E610 automatic discovery C: aggregate_success=" << (result.succeeded ? 1 : 0)
			  << ", aggregate_error=" << result.error
			  << ", provider_state=" << static_cast<std::uint32_t>( report->state)
			  << ", provider_error=" << report->error
			  << ", eligible=" << report->coverage.eligibleDeviceCount
			  << ", assessed=" << report->coverage.assessedDeviceCount
			  << ", route_state=" << static_cast<std::uint32_t>( route.state)
			  << ", records=" << route.recordCount << ", packages=" << route.packageCount
			  << ", candidates=" << officialCandidateCount
			  << ", preparation_targets=" << (preparation ? preparation->targets.size() : 0U)
			  << ", payload_transfers=0, eula_acceptances=0.\n" ;

	// 通常scan成功、強制再確認route、E610対象、record一件、表示専用行の一致を合格条件にする。
	if( !result.succeeded || result.error != 0 || report->error != 0 ||
	   report->state != drivercrate::ProviderScanState::CANDIDATES_AVAILABLE ||
	   report->coverage.eligibleDeviceCount == 0U ||
	   report->coverage.assessedDeviceCount != report->coverage.eligibleDeviceCount ||
	   report->candidateCount != officialCandidateCount || officialCandidateCount == 0U ||
	   summary->binding.operationId != TEST_OPERATION_ID ||
	   summary->binding.scanSessionId != SCAN_SESSION_ID || !summary->inventoryComplete ||
	   summary->request.inspectionPermission !=
		   drivercrate::OfficialDiscoveryInspectionPermission::METADATA_ONLY ||
	   summary->request.cacheMode != drivercrate::OfficialDiscoveryCacheMode::FORCE_REFRESH ||
	   route.providerId != drivercrate::INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID ||
	   route.kind != drivercrate::OfficialDiscoveryRouteKind::DEDICATED ||
	   route.state != drivercrate::OfficialDiscoveryRouteState::DEDICATED_RESOLVED ||
	   route.error != 0 || route.deviceCount != report->coverage.eligibleDeviceCount ||
	   route.recordCount != 1U || route.packageCount != 1U || unsafeCandidate || preparation ||
	   lastProgress.percentComplete != 100U) {
		std::cerr << "E610 automatic discovery C validation failed.\n" ;
		return 1 ;
	}

	std::cout.flush() ;
	return std::cout.good() ? 0 : 1 ;
}
