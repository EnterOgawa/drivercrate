//------------------------------------------------------------------------------
/**
 * @file wch_serial_provider_smoke.cpp
 * @brief WCH CH341SER区分C Provider読み取り専用live検証。
 * @version 01.00.00
 * @date 2026/09/03
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Driver Store列挙と利用者指定WCH ZIPの検証・local照合だけをcomposite scanで実行します。Network、download、installは行いませ
 *       ん。
 */
//------------------------------------------------------------------------------

#include "core/provider_registry.h"
#include "platform/com_raii.h"
#include "platform/composite_update_provider.h"

#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>

//------------------------------------------------------------------------------
/**
 * @brief WCH CH341SER区分C Providerのscan接続を検証する。
 *
 * 対応実機がない場合も`NO_CANDIDATES`を正常結果として扱い、metadata拒否やroute未接続と区別する。
 *
 * @param[in] argumentCount 実行file名を含むargument数。
 * @param[in] arguments 一件の利用者指定WCH公式ZIP path。
 * @return Package検証、local照合、Provider reportが正常なら0。
 */
//------------------------------------------------------------------------------
int wmain( const int argumentCount, wchar_t *arguments[])
{
	// CH341SER ZIP一件を入力に限定し、引数が不正ならProviderを開始しない。
	if( argumentCount != 2 || arguments == nullptr || arguments[1] == nullptr ||
	   arguments[1][0] == L'\0') {
		std::wprintf( L"Usage: wch_serial_provider_smoke <official-ch341ser-zip>\n") ;
		return 2 ;
	}

	const drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;	// Scan threadのCOM MTA。
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		std::wprintf( L"COM initialization failed: 0x%08X\n",
					 static_cast<unsigned int>( apartment.result())) ;
		return 1 ;
	}

	drivercrate::ScanOptions options ;	// Driver StoreとWCHだけを有効にする明示設定。
	options.useDefaultProviders = false ;
	options.enabledProviderIds	= {std::wstring( drivercrate::DRIVER_STORE_PROVIDER_ID),
								   std::wstring( drivercrate::WCH_SERIAL_PACKAGE_PROVIDER_ID)} ;
	options.userSelectedFiles.push_back(
		{.providerId = std::wstring( drivercrate::WCH_SERIAL_PACKAGE_PROVIDER_ID),
		 .path		 = arguments[1]}) ;

	drivercrate::ProviderStage lastStage =
		drivercrate::ProviderStage::SCANNING_DEVICES ;			// 最後に通知されたscan段階。
	std::uint32_t								lastPercent{} ;	// 最後に確定した全体進捗率。
	const drivercrate::ProviderProgressCallback progressCallback =
		[&lastStage, &lastPercent]( const drivercrate::ProviderProgress &progress) {
			lastStage	= progress.stage ;
			lastPercent = progress.percentComplete ;
		} ; // 端末情報を保持しない進捗受理先。

	drivercrate::CompositeUpdateProvider provider ;	// Productionと同じaggregate provider。
	const drivercrate::ScanResult		 result =
		// Read-only composite scan結果。
		provider.scan( 3, options, progressCallback) ;
	// 検索に失敗した段階と診断値を報告し、正常な候補なしと混同しない。
	if( !result.succeeded) {
		std::wprintf( L"WCH provider scan failed: 0x%08X, stage %u, percent %u\n",
					 static_cast<unsigned int>( result.error), static_cast<unsigned int>( lastStage),
					 lastPercent) ;
		return 1 ;
	}

	const auto report = std::find_if( result.providerReports.begin(), result.providerReports.end(),
									 []( const drivercrate::ProviderScanReport &current) {
										 return current.descriptor.id ==
												drivercrate::WCH_SERIAL_PACKAGE_PROVIDER_ID ;
									 }) ; // WCH routeのProvider別結果。
	// Providerの正常報告と全対象の評価を要求し、未評価のまま合格にしない。
	if( report == result.providerReports.end() || report->error != 0 ||
	   (report->state != drivercrate::ProviderScanState::NO_CANDIDATES &&
		report->state != drivercrate::ProviderScanState::CANDIDATES_AVAILABLE) ||
	   report->coverage.assessedDeviceCount != report->coverage.eligibleDeviceCount) {
		std::wprintf( L"WCH provider report validation failed.\n") ;
		return 1 ;
	}

	std::size_t candidateCount{} ;	// WCH Providerが返した候補数。
	// 候補がある実機では区分C、初期選択なし、明示選択可能の境界を検証する。
	for( const drivercrate::UpdateCandidate &candidate : result.candidates) {
		// CH341SER区分C以外の候補を、このProviderの検証件数へ含めない。
		if( candidate.providerId != drivercrate::WCH_SERIAL_PACKAGE_PROVIDER_ID) {
			continue ;
		}

		// 明示版と導入可否を照合し、利用者指定fileが既定推奨へ昇格しないことを確認する。
		if( candidate.discoveryBasis !=
			   drivercrate::CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE ||
		   candidate.defaultPreference != drivercrate::CandidateDefaultPreference::NONE ||
		   candidate.recommended || !candidate.installable || candidate.version.empty()) {
			std::wprintf( L"WCH provider returned an unsafe candidate state.\n") ;
			return 1 ;
		}

		++candidateCount ;
	}

	// Provider報告の件数と実候補行の数を照合し、欠落や重複を検出する。
	if( candidateCount != report->candidateCount) {
		std::wprintf( L"WCH provider candidate count is inconsistent.\n") ;
		return 1 ;
	}

	std::wprintf( L"WCH provider scan succeeded: eligible %llu, candidates %zu.\n",
				 static_cast<unsigned long long>( report->coverage.eligibleDeviceCount),
				 candidateCount) ;
	return 0 ;
}
