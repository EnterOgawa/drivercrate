//------------------------------------------------------------------------------
/**
 * @file nvidia_winof2_catalog_smoke.cpp
 * @brief NVIDIA Networking公式表示検索のread-only live検証。
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
 * @note 実OSと架空のNet表示snapshotで、本番Providerの固定metadataを検索します。実inventoryを列挙・送信せず、payload取得、許諾同意、導入を行いませ
 *       ん。本試験は明示有効化したtargetの手動実行だけとし、CTestへ登録しません。
 */
//------------------------------------------------------------------------------

#include "core/provider_registry.h"
#include "core/update_types.h"
#include "platform/com_raii.h"
#include "platform/nvidia_winof2_catalog_parser.h"
#include "platform/nvidia_winof2_update_provider.h"
#include "platform/official_catalog_device.h"
#include "platform/windows_product_type.h"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>

namespace drivercrate::test {
//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief COM MTAで本番Providerを一回検索し、二つの架空表示候補を確認する。実機適用性、INF版、実導入の合格とは扱わない。
 * @return 検索・表示専用契約・進捗・出力の全成功時0。拒否・失敗時1。
 */
//------------------------------------------------------------------------------
int runNvidiaWinof2ReadOnlySearch()
{
	const ComApartment apartment( COINIT_MULTITHREADED) ;	// Providerを所有する試験threadのMTA。
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		std::cerr << "COM initialization failed.\n" ;
		// COM未初期化で本番network境界を呼ばない。
		return 1 ;
	}

	const bool				windowsServer = isWindowsServer() ;				// OS種別だけを端末内で確認する。
	const std::uint32_t		windowsBuild  = currentWindowsBuildNumber() ;	// 公開OSへの対応値。
	NvidiaWinof2OsSelection os ;											// 既存parserが定義する固定OS選択肢。
	// 実OSに対応しない場合は通信せず、架空のServer条件で検索成功を作らない。
	if( !selectNvidiaWinof2Os( windowsServer, windowsBuild, os)) {
		std::cerr << "Unsupported test OS; no network request issued.\n" ;
		// 対象外の実OSを検索成功や架空のServerへ置き換えない。
		return 1 ;
	}

	const std::array devices{
		OfficialCatalogDevice{.deviceIdentity  = L"winof2-live-fixture-a",
							  .model		   = L"NVIDIA ConnectX-6 Adapter",
							  .manufacturer	   = L"NVIDIA",
							  .driverClass	   = L"Net",
							  .deviceClassGuid = L"{4d36e972-e325-11ce-bfc1-08002be10318}",
							  .currentProvider = L"NVIDIA"},
		OfficialCatalogDevice{.deviceIdentity  = L"winof2-live-fixture-b",
							  .model		   = L"Mellanox ConnectX-5 Adapter",
							  .manufacturer	   = L"Mellanox",
							  .driverClass	   = L"Net",
							  .deviceClassGuid = L"{4d36e972-e325-11ce-bfc1-08002be10318}",
							  .currentProvider = L"Mellanox"},
	} ; // 生PnP IDを持たず、networkへ送信しない二件の合成inventory。
	ProviderProgress			   lastProgress{} ;			// 最後に確定した処理段階だけを保持する。
	std::size_t					   progressCalls{} ;		// 段階と候補処理の通知件数。
	bool						   progressValid = true ;	// 単調性または上限の違反がなければtrue。
	const ProviderProgressCallback progressCallback =
		[&lastProgress, &progressCalls, &progressValid]( const ProviderProgress &progress) {
			++progressCalls ;
			progressValid =
				progressValid && progress.stage == ProviderStage::SEARCHING_OFFICIAL_CATALOGS &&
				progress.percentComplete >= lastProgress.percentComplete &&
				progress.percentComplete <= 100U && progress.completedItems <= progress.totalItems ;
			lastProgress = progress ;
		} ; // 待ち時間ではなく、本番Providerからの確定進捗を検査する。
	NvidiaWinof2UpdateProvider provider ;	// System proxy・固定origin policyを使用する本番境界。
	const ScanResult		   result =
		// Metadataだけを取得する一回の検索。
		provider.scan( 1U, devices, {}, progressCallback) ;

	// 固定ASCII、OS種別／build、件数、状態、native errorだけを出力する。
	std::cout << "windows_server=" << windowsServer << ", windows_build=" << windowsBuild
			  << ", candidates=" << result.candidates.size()
			  << ", state=" << static_cast<unsigned int>( result.state)
			  << ", progress=" << lastProgress.percentComplete
			  << ", progress_calls=" << progressCalls << ", error=0x" << std::hex << std::setw( 8)
			  << std::setfill( '0') << static_cast<std::uint32_t>( result.error) << std::dec << "\n" ;
	// 全入力deviceの候補と完了進捗がそろった場合だけ、検索経路の検証を合格にする。
	if( !result.succeeded || result.error != 0 ||
	   result.state != ProviderScanState::CANDIDATES_AVAILABLE || result.scanSessionId != 1U ||
	   result.candidates.size() != devices.size() ||
	   result.coverage.eligibleDeviceCount != devices.size() ||
	   result.coverage.assessedDeviceCount != devices.size() || !progressValid ||
	   lastProgress.percentComplete != 100U || lastProgress.completedItems != devices.size() ||
	   lastProgress.totalItems != devices.size() || progressCalls != 9U) {
		std::cerr << "NVIDIA Networking metadata search failed.\n" ;
		// 候補0件、途中応答、未完進捗を検索検証の合格として扱わない。
		return 1 ;
	}

	// 二候補を独立検査し、同じpackageの表示を導入可能なdriverへ昇格していないことを確認する。
	for( std::size_t index = 0U; index < devices.size(); ++index)	// 合成deviceと表示候補の位置。
	{
		const UpdateCandidate &candidate = result.candidates[index] ;	// 検査中の表示専用行。
		// metadata検索だけで取得・監査・導入が完了した表示にならないことを確認する。
		if( candidate.providerId != NVIDIA_WINOF2_PROVIDER_ID || candidate.identity.empty() ||
		   candidate.deviceIdentity != devices[index].deviceIdentity ||
		   candidate.packageIdentity.empty() || candidate.title.empty() ||
		   candidate.sourceName.empty() || candidate.sourceLocation.empty() ||
		   !candidate.version.empty() || candidate.action != DriverAction::NONE ||
		   candidate.defaultPreference != CandidateDefaultPreference::NONE ||
		   candidate.discoveryBasis != CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG ||
		   candidate.installable || candidate.recommended || candidate.current ||
		   candidate.eulaAccepted || candidate.allContentCached) {
			std::cerr << "Unsafe NVIDIA Networking display candidate.\n" ;
			// 取得と監査が未完了の候補に対する選択・導入能力を拒否する。
			return 1 ;
		}
	}

	// 同じ配布物でもdevice別候補のIDは分離し、packageのIDだけを共有することを要求する。
	if( result.candidates[0].identity == result.candidates[1].identity ||
	   result.candidates[0].packageIdentity != result.candidates[1].packageIdentity) {
		std::cerr << "NVIDIA Networking candidate/package identity mismatch.\n" ;
		// 同じ実metadataでもdevice別候補を潰さず、同じpackageを共有する。
		return 1 ;
	}

	provider.invalidateScanSession() ;
	std::cout << "NVIDIA Networking read-only search passed; synthetic devices only; "
				 "no payload, no install.\n" ;
	std::cout.flush() ;
	std::cerr.flush() ;
	return std::cout.good() && std::cerr.good() ? 0 : 1 ;
}
} // namespace drivercrate::test

//------------------------------------------------------------------------------
/**
 * @brief Thread entryから例外を漏らさず、機密値を含む例外本文は表示しない。Targetを明示実行した場合だけnetworkへ接続する。
 * @return 全検証成功時0。検索・出力失敗または例外時1。
 */
//------------------------------------------------------------------------------
int wmain()
{
	try {
		return drivercrate::test::runNvidiaWinof2ReadOnlySearch() ;
	} catch( ...) {
		std::cerr << "NVIDIA Networking live search raised an exception.\n" ;
		return 1 ;
	}
}
