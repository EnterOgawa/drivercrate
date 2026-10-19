//------------------------------------------------------------------------------
/**
 * @file nvidia_display_catalog_smoke.cpp
 * @brief NVIDIA Display公式表示検索のread-only live検証。
 * @version 01.00.00
 * @date 2026/09/09
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  固定Providerの専用live検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 実OSと架空のDisplay表示snapshotで、本番Providerの固定metadataを検索します。実inventoryを列挙・送信せず、payload取得、許諾同意、導入を
 *       行いません。本試験は明示有効化したtargetの手動実行だけとし、CTestへ登録しません。
 */
//------------------------------------------------------------------------------

#include "core/provider_registry.h"
#include "core/update_types.h"
#include "platform/com_raii.h"
#include "platform/nvidia_update_provider.h"
#include "platform/official_catalog_device.h"
#include "platform/windows_product_type.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_set>

namespace drivercrate::test {
//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief COM MTAで本番Providerを一回検索する。実inventoryは列挙せず、合成Desktop／Laptop表示の各現行・過去版とOEM境界を確認する。
 * @return 検索・表示専用契約・進捗・出力の全成功時0。拒否・失敗時1。
 */
//------------------------------------------------------------------------------
int runNvidiaDisplayReadOnlySearch()
{
	const ComApartment apartment( COINIT_MULTITHREADED) ;	// 本番Providerを所有する試験threadのMTA。
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		std::cerr << "COM initialization failed.\n" ;
		// 未初期化のCOM境界で公式parserを呼ばない。
		return 1 ;
	}

	const bool			windowsServer = isWindowsServer() ;				// OS種別だけを端末内で確認する。
	const std::uint32_t windowsBuild  = currentWindowsBuildNumber() ;	// 実OSの公開build番号。
	// Client専用試験をServerや対象外OSでは実行せず、架空のOS条件で通信しない。
	if( windowsServer || windowsBuild < 10'240U) {
		std::cerr << "Unsupported test OS; no network request issued.\n" ;
		// Client用試験を架空OSやServerの合格に置き換えない。
		return 1 ;
	}

	const std::array devices{
		OfficialCatalogDevice{.deviceIdentity  = L"display-live-fixture-desktop",
							  .model		   = L"NVIDIA GeForce RTX 4090",
							  .manufacturer	   = L"NVIDIA",
							  .driverClass	   = L"Display",
							  .deviceClassGuid = L"{4d36e968-e325-11ce-bfc1-08002be10318}",
							  .currentProvider = L"NVIDIA"},
		OfficialCatalogDevice{.deviceIdentity  = L"display-live-fixture-laptop",
							  .model		   = L"NVIDIA GeForce RTX 4090 Laptop GPU",
							  .manufacturer	   = L"NVIDIA",
							  .driverClass	   = L"Display",
							  .deviceClassGuid = L"{4d36e968-e325-11ce-bfc1-08002be10318}",
							  .currentProvider = L"NVIDIA"},
	} ; // 生PnP IDと現在版を持たない、固定製品表示の合成inventory。
	ProviderProgress			   lastProgress{} ;			// 本番Providerが最後に確定した進捗。
	std::size_t					   progressCalls{} ;		// 検索段階の通知回数。
	bool						   progressValid = true ;	// 全通知が上限と単調性に一致する場合true。
	const ProviderProgressCallback progressCallback =
		[&lastProgress, &progressCalls, &progressValid]( const ProviderProgress &progress) {
			++progressCalls ;
			progressValid = progressValid &&
							progress.stage == ProviderStage::SEARCHING_OFFICIAL_CATALOGS &&
							progress.percentComplete >= lastProgress.percentComplete &&
							progress.percentComplete <= 100U &&
							progress.completedItems >= lastProgress.completedItems &&
							progress.completedItems <= progress.totalItems ;
			lastProgress = progress ;
		} ; // 時間による推測ではなく本番検索の確定進捗を確認する。
	NvidiaUpdateProvider provider( false) ;	// Catalog cacheを読み書きせず、通常の公式境界で取得する。
	const ScanResult	 result =
		// Metadataだけを取得する一回の検索。
		provider.scan( 1U, devices, {}, progressCallback) ;
	const ProviderScanState resolvedState =
		// 本体と同じregistryの状態解決結果。
		resolveProviderScanState( result, true) ;

	// URL、応答本文、候補名、合成identityは出力せず、固定ASCIIと集計値だけを表示する。
	std::cout << "catalog_cache=0, windows_server=" << windowsServer
			  << ", windows_build=" << windowsBuild << ", candidates=" << result.candidates.size()
			  << ", resolved_state=" << static_cast<unsigned int>( resolvedState)
			  << ", progress=" << lastProgress.percentComplete
			  << ", progress_calls=" << progressCalls << ", error=0x" << std::hex << std::setw( 8)
			  << std::setfill( '0') << static_cast<std::uint32_t>( result.error) << std::dec << "\n" ;
	// 全対象の検索・候補数・進捗がそろわなければ、片channelだけの成功を合格にしない。
	if( !result.succeeded || result.error != 0 || result.outcome != OutcomeCode::SUCCESS ||
	   resolvedState != ProviderScanState::CANDIDATES_AVAILABLE || result.scanSessionId != 1U ||
	   result.candidates.empty() || result.candidates.size() > 20U * devices.size() ||
	   result.coverage.eligibleDeviceCount != devices.size() ||
	   result.coverage.assessedDeviceCount != devices.size() || !progressValid ||
	   lastProgress.percentComplete != 100U || lastProgress.completedItems != devices.size() ||
	   lastProgress.totalItems != devices.size() || progressCalls != devices.size() + 1U) {
		std::cerr << "NVIDIA Display metadata search failed.\n" ;
		// 候補0件や片channel失敗を成功として扱わない。
		return 1 ;
	}

	std::unordered_set<std::wstring> identities ;				// 全候補のopaque identity重複検出集合。
	std::array<std::unordered_set<std::wstring>, 2> packages ;	// Device別download ID重複検出集合。
	std::array<std::unordered_set<std::wstring>, 2> versions ;	// Device別の明示release版の集合。
	// 全候補を元の合成deviceへ対応付け、取得・導入能力が付加されていないことを確認する。
	for( const UpdateCandidate &candidate : result.candidates)	// 現在検査中の表示専用候補。
	{
		const auto device = std::find_if(
			devices.begin(), devices.end(), [&candidate]( const OfficialCatalogDevice &entry) {
				return entry.deviceIdentity == candidate.deviceIdentity ;
			}) ; // 対応する合成device。
		// 入力にないdeviceの候補を混ぜず、合成fixtureとの対応を一意に確認する。
		if( device == devices.end()) {
			std::cerr << "Unknown NVIDIA Display candidate device.\n" ;
			// 入力にないdeviceの候補を件数へ混入させない。
			return 1 ;
		}

		const std::size_t index =
			// DesktopまたはLaptopの位置。
			static_cast<std::size_t>( device - devices.begin()) ;
		// 現在版不明の候補を更新や導入可能と推測せず、NotebookのOEM未検証表示も必須にする。
		if( candidate.providerId != NVIDIA_PROVIDER_ID || candidate.identity.empty() ||
		   !identities.insert( candidate.identity).second || candidate.packageIdentity.empty() ||
		   !packages[index].insert( candidate.packageIdentity).second || candidate.title.empty() ||
		   candidate.version.empty() || candidate.driverDate.empty() ||
		   candidate.model != device->model || candidate.driverClass != L"Display" ||
		   candidate.sourceName.empty() || candidate.sourceLocation.empty() ||
		   candidate.action != DriverAction::REINSTALL ||
		   candidate.defaultPreference != CandidateDefaultPreference::NONE ||
		   candidate.discoveryBasis != CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG ||
		   candidate.installable || candidate.recommended || candidate.current ||
		   candidate.eulaAccepted || candidate.allContentCached ||
		   (index == 1U &&
			candidate.sourceLocation.find( L"OEM固有構成は未検証") == std::wstring::npos)) {
			std::cerr << "Unsafe NVIDIA Display candidate contract.\n" ;
			// 現在版不明で更新を推測せず、NotebookをOEM検証済みにしない。
			return 1 ;
		}

		versions[index].insert( candidate.version) ;
	}

	// 双方の合成deviceで現行・過去の複数版を保持し、片側の検出漏れを拒否する。
	for( std::size_t index = 0U; index < devices.size(); ++index)	// 検査対象deviceの有限位置。
	{
		// 各deviceに複数版の履歴が有限範囲で返ることを要求し、最新版一件だけで合格にしない。
		if( packages[index].size() < 2U || packages[index].size() > 20U ||
		   versions[index].size() < 2U) {
			std::cerr << "NVIDIA Display history coverage failed.\n" ;
			return 1 ;
		}
	}

	std::cout << "desktop_candidates=" << packages[0].size()
			  << ", laptop_candidates=" << packages[1].size()
			  << ", desktop_versions=" << versions[0].size()
			  << ", laptop_versions=" << versions[1].size() << "\n" ;
	std::cout << "NVIDIA Display read-only search passed; synthetic devices only; "
				 "no payload, no install.\n" ;
	std::cout.flush() ;
	std::cerr.flush() ;
	return std::cout.good() && std::cerr.good() ? 0 : 1 ;
}
} // namespace drivercrate::test

//------------------------------------------------------------------------------
/**
 * @brief 例外をthread entryから漏らさず、例外本文も出力しない。Targetを明示実行した場合だけ公式metadataへ接続する。
 * @return 全検証成功時0。検索・出力失敗または例外時1。
 */
//------------------------------------------------------------------------------
int wmain()
{
	try {
		return drivercrate::test::runNvidiaDisplayReadOnlySearch() ;
	} catch( ...) {
		std::cerr << "NVIDIA Display live search raised an exception.\n" ;
		return 1 ;
	}
}
