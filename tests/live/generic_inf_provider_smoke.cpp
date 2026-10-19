//------------------------------------------------------------------------------
/**
 * @file generic_inf_provider_smoke.cpp
 * @brief 汎用署名済みINF Provider読み取り専用live検証。
 * @version 01.01.00
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
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  共通内容検査・八軸・表示専用の本番接続検証へ移行。
 * </pre>
 *
 * @note Driver Store列挙と汎用ZIP／CABの検証・Windows適合照合だけをCompositeで実行します。
 *       Network Provider、download、driver installは呼びません。署名検証時のOS trust照会は維持します。
 */
//------------------------------------------------------------------------------

#include "core/provider_registry.h"
#include "core/candidate_assessment.h"
#include "platform/com_raii.h"
#include "platform/composite_update_provider.h"

#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>

//------------------------------------------------------------------------------
/**
 * @brief 汎用署名済みINF Providerのscan接続を検証する。
 *
 * 対応実機がない場合も候補なしと失敗を分け、取得元未証明・八軸の実証拠・表示専用を確認する。
 *
 * @param[in] argumentCount 実行file名を含むargument数。
 * @param[in] arguments 利用者が明示した元ZIP／CABのlocal絶対path。
 * @return Package検証、local照合、Provider reportが正常なら0。
 */
//------------------------------------------------------------------------------
int wmain( const int argumentCount, wchar_t *arguments[])
{
	// 検証対象のZIPを一件だけ明示させ、空引数や複数指定からscanを開始しない。
	if( argumentCount != 2 || arguments == nullptr || arguments[1] == nullptr ||
	   arguments[1][0] == L'\0') {
		std::wprintf( L"Usage: generic_inf_provider_smoke <local-zip-or-cab>\n") ;
		return 2 ;
	}

	const drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;	// Scan threadのCOM MTA。
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		std::wprintf( L"COM initialization failed: 0x%08X\n",
					 static_cast<unsigned int>( apartment.result())) ;
		return 1 ;
	}

	drivercrate::ScanOptions options ;	// Driver Storeと汎用INFだけを有効にする設定。
	options.useDefaultProviders = false ;
	options.enabledProviderIds	= {
		 std::wstring( drivercrate::DRIVER_STORE_PROVIDER_ID),
		 std::wstring( drivercrate::GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID)} ;
	options.userSelectedFiles.push_back(
		{.providerId = std::wstring( drivercrate::GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID),
		 .path		 = arguments[1]}) ;

	drivercrate::ProviderStage lastStage =
		drivercrate::ProviderStage::SCANNING_DEVICES ;			// 最後に通知されたscan段階。
	std::uint32_t								lastPercent{} ;	// 最後に確定した全体進捗率。
	const drivercrate::ProviderProgressCallback progressCallback =
		[&lastStage, &lastPercent]( const drivercrate::ProviderProgress &progress) {
			lastStage	= progress.stage ;
			lastPercent = progress.percentComplete ;
		} ; // 端末識別情報を保持しない進捗受理先。

	drivercrate::CompositeUpdateProvider provider ;	// Productionと同じaggregate Provider。
	const drivercrate::ScanResult		 result =
		// Read-only composite scan結果。
		provider.scan( 12, options, progressCallback) ;
	// Provider検索失敗を候補なしの正常終了と区別し、失敗段階と診断を報告する。
	if( !result.succeeded) {
		std::wprintf( L"Generic INF provider scan failed: 0x%08X, stage %u, percent %u\n",
					 static_cast<unsigned int>( result.error), static_cast<unsigned int>( lastStage),
					 lastPercent) ;
		return 1 ;
	}

	// 実行結果から汎用INF Providerの報告だけを参照するiterator。
	const auto report = std::find_if( result.providerReports.begin(), result.providerReports.end(),
									 []( const drivercrate::ProviderScanReport &current) {
										 return current.descriptor.id ==
												drivercrate::GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID ;
									 }) ;
	// 個別INFの内容拒否は部分結果へ残し、候補なしと全体失敗を区別する。
	if( report == result.providerReports.end() ||
	   (report->state != drivercrate::ProviderScanState::NO_CANDIDATES &&
		report->state != drivercrate::ProviderScanState::CANDIDATES_AVAILABLE)) {
		std::wprintf( L"Generic INF provider report validation failed.\n") ;
		return 1 ;
	}

	std::size_t candidateCount{} ;	// 汎用Providerが返した候補数。
	// 対応実機候補が取得元未証明の区分Cで、自動選択されないことを確認する。
	for( const drivercrate::UpdateCandidate &candidate : result.candidates) {
		// 別Providerの候補を汎用INF Providerの合格件数へ含めない。
		if( candidate.providerId != drivercrate::GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID) {
			continue ;
		}

		// 利用者指定fileの取得元未証明と表示専用を維持し、内容・Windows適合の証拠を確認する。
		if( candidate.discoveryBasis !=
			   drivercrate::CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE ||
		   candidate.defaultPreference != drivercrate::CandidateDefaultPreference::NONE ||
		   candidate.recommended || candidate.installable || !candidate.assessment ||
		   !drivercrate::isCandidateAssessmentBound( *candidate.assessment, 12U, candidate.identity,
													candidate.deviceIdentity,
													candidate.packageIdentity) ||
		   candidate.assessment->signature.state != drivercrate::CandidateAssessmentState::PASSED ||
		   candidate.assessment->applicability.state !=
			   drivercrate::CandidateAssessmentState::PASSED ||
		   candidate.sourceLocation.find( L"取得元未証明") == std::wstring::npos) {
			std::wprintf( L"Generic INF provider returned an unsafe candidate state.\n") ;
			return 1 ;
		}

		++candidateCount ;
	}

	// Provider報告と実候補行の件数を一致させ、候補の欠落や重複を検出する。
	if( candidateCount != report->candidateCount) {
		std::wprintf( L"Generic INF provider candidate count is inconsistent.\n") ;
		return 1 ;
	}

	std::wprintf(
		L"Generic INF provider scan succeeded: eligible %llu, candidates %zu, diagnostic 0x%08X.\n",
		static_cast<unsigned long long>( report->coverage.eligibleDeviceCount), candidateCount,
		static_cast<unsigned int>( report->error)) ;
	return 0 ;
}
