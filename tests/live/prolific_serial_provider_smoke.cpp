//------------------------------------------------------------------------------
/**
 * @file prolific_serial_provider_smoke.cpp
 * @brief Prolific Serial区分C Provider読み取り専用live検証。
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
 * @note Driver Store列挙と利用者指定Prolific ZIPの検証・local照合だけをcomposite scanで実行します。Network、download、install
 *       は行いません。
 */
//------------------------------------------------------------------------------

#include "core/provider_registry.h"
#include "platform/com_raii.h"
#include "platform/composite_update_provider.h"
#include "platform/windows_error.h"

#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>

//------------------------------------------------------------------------------
/**
 * @brief Prolific Serial区分C Providerのscan接続を検証する。
 *
 * 対応実機がない場合も`NO_CANDIDATES`を正常結果として扱い、metadata拒否やroute未接続と区別する。
 *
 * @param[in] argumentCount 実行file名を含むargument数。
 * @param[in] arguments 一件の利用者指定Prolific公式ZIP path。
 * @return Package検証、local照合、Provider reportが正常なら0。
 */
//------------------------------------------------------------------------------
int wmain( const int argumentCount, wchar_t *arguments[])
{
	// 明示したZIP一件以外を入力へ広げず、引数不備ではProvider検証を開始しない。
	if( argumentCount != 2 || arguments == nullptr || arguments[1] == nullptr ||
	   arguments[1][0] == L'\0') {
		std::wprintf( L"Usage: prolific_serial_provider_smoke <official-driver-zip>\n") ;
		return 2 ;
	}

	const drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;	// Scan threadのCOM MTA。
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		std::wprintf( L"COM initialization failed: 0x%08X\n",
					 static_cast<unsigned int>( apartment.result())) ;
		return 1 ;
	}

	drivercrate::ScanOptions options ;	// Driver StoreとProlificだけを有効にする明示設定。
	options.useDefaultProviders = false ;
	options.enabledProviderIds	= {std::wstring( drivercrate::DRIVER_STORE_PROVIDER_ID),
								   std::wstring( drivercrate::PROLIFIC_SERIAL_PACKAGE_PROVIDER_ID)} ;
	options.userSelectedFiles.push_back(
		{.providerId = std::wstring( drivercrate::PROLIFIC_SERIAL_PACKAGE_PROVIDER_ID),
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
		provider.scan( 2, options, progressCallback) ;
	// scanの失敗を候補なしとは扱わず、失敗段階と診断値を報告する。
	if( !result.succeeded) {
		std::wprintf( L"Prolific provider scan failed: 0x%08X, stage %u, percent %u\n",
					 static_cast<unsigned int>( result.error), static_cast<unsigned int>( lastStage),
					 lastPercent) ;
		return 1 ;
	}

	const auto report = std::find_if( result.providerReports.begin(), result.providerReports.end(),
									 []( const drivercrate::ProviderScanReport &current) {
										 return current.descriptor.id ==
												drivercrate::PROLIFIC_SERIAL_PACKAGE_PROVIDER_ID ;
									 }) ; // Prolific routeのProvider別結果。
	// 全対象の評価とProvider報告の正常性を要求し、未評価を正常な候補なしにしない。
	if( report == result.providerReports.end() || report->error != 0 ||
	   (report->state != drivercrate::ProviderScanState::NO_CANDIDATES &&
		report->state != drivercrate::ProviderScanState::CANDIDATES_AVAILABLE) ||
	   report->coverage.assessedDeviceCount != report->coverage.eligibleDeviceCount) {
		std::wprintf( L"Prolific provider report validation failed.\n") ;
		return 1 ;
	}

	std::size_t candidateCount{} ;	// Prolific Providerが返した候補数。
	// 候補がある実機では区分C、初期選択なし、明示選択可能の境界を検証する。
	for( const drivercrate::UpdateCandidate &candidate : result.candidates) {
		// 別Providerの候補をProlific区分Cの合格件数へ含めない。
		if( candidate.providerId != drivercrate::PROLIFIC_SERIAL_PACKAGE_PROVIDER_ID) {
			continue ;
		}

		// 利用者指定fileの候補を既定推奨へ昇格させず、明示版と導入可否の契約を照合する。
		if( candidate.discoveryBasis !=
			   drivercrate::CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE ||
		   candidate.defaultPreference != drivercrate::CandidateDefaultPreference::NONE ||
		   candidate.recommended || !candidate.installable || candidate.version.empty()) {
			std::wprintf( L"Prolific provider returned an unsafe candidate state.\n") ;
			return 1 ;
		}

		++candidateCount ;
	}

	// 報告件数と実候補の数を照合し、候補の欠落や重複を検出する。
	if( candidateCount != report->candidateCount) {
		std::wprintf( L"Prolific provider candidate count is inconsistent.\n") ;
		return 1 ;
	}

	std::wprintf( L"Prolific provider scan succeeded: eligible %llu, candidates %zu.\n",
				 static_cast<unsigned long long>( report->coverage.eligibleDeviceCount),
				 candidateCount) ;
	return 0 ;
}
