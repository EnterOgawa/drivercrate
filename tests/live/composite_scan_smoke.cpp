//------------------------------------------------------------------------------
/**
 * @file composite_scan_smoke.cpp
 * @brief 複合provider読み取り専用試験。
 * @version 01.00.00
 * @date 2026/09/01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  NetXtreme-E表示専用検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公式2経路とfamily別予算を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  CP210x公式取得とserial共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  関数comment形式統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Scan進捗callback追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  公式vendor Provider集計追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Registry状態とpackage ID検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  同一版取得元注釈検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Local coverage検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Manufacturer／class集計検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  NVIDIA対象実機回帰条件追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  失敗時Provider集計診断追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  失敗時の最終進捗診断追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  失敗時のProvider数値診断追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  明示指定のProlific検査用取得試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  VAIO個別失敗を部分成功で見逃さない。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 全組み込みProviderを統合する読み取り専用scanを検証します。Network接続を伴い、明示option時だけProlific検査用ZIPを取得します。Driver
 *       installと復元ポイント作成は行いません。Update titleや端末固有情報を出力しません。
 */
//------------------------------------------------------------------------------

#include "core/provider_registry.h"
#include "platform/com_raii.h"
#include "platform/composite_update_provider.h"
#include "platform/windows_error.h"

#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <unordered_set>

//------------------------------------------------------------------------------
/**
 * @brief aggregate scan を一回実行し、秘密情報を含まない集計値だけを出力する。
 *
 * aggregate scan を一回実行し、秘密情報を含まない集計値だけを出力する。明示optionは課金／不明networkを含むZIP取得を許可する。WCHは最大4 MiB、Prolific
 * ／CP210xは最大32 MiBとする。今回だけ許可する。Install／EULAへの同意には使用しない。
 *
 * @param[in] argumentCount 実行file名を含む引数数。
 * @param[in] arguments serial検査option指定時だけ取得を許可。
 * @return scan 成功かつ全 candidate の source/device identityが設定済みなら0。検証失敗は1、引数不正は2。
 */
//------------------------------------------------------------------------------
int wmain( const int argumentCount, wchar_t *arguments[])
{
	// 未知optionを黙って取得同意へ変換しない。
	if( arguments == nullptr || argumentCount < 1 || argumentCount > 2 ||
	   (argumentCount == 2 && (arguments[1] == nullptr ||
							   (std::wstring_view( arguments[1]) != L"--prolific-inspection" &&
								std::wstring_view( arguments[1]) != L"--silabs-inspection" &&
								std::wstring_view( arguments[1]) != L"--wch-inspection" &&
								std::wstring_view( arguments[1]) != L"--wch-multi-inspection" &&
								std::wstring_view( arguments[1]) != L"--broadcom-discovery")))) {
		std::wcerr << L"Usage: drivercrate_composite_scan_smoke "
					  L"[--prolific-inspection | --silabs-inspection | "
					  L"--wch-inspection | --wch-multi-inspection | --broadcom-discovery]\n" ;
		return 2 ;
	}

	drivercrate::ScanOptions options ;	// 既定検索、公式ZIP検査またはBroadcom表示専用検索。
	const bool				 broadcomDiscovery = argumentCount == 2 &&
								   // Payloadは取得しない。
								   std::wstring_view( arguments[1]) == L"--broadcom-discovery" ;
	// 追加optionが指定された場合だけ明示Provider集合を構成し、同意対象を限定する。
	if( argumentCount == 2) {
		options.useDefaultProviders = false ;
		options.prolificInspectionApproved =
			std::wstring_view( arguments[1]) == L"--prolific-inspection" ;
		options.siliconLabsInspectionApproved =
			std::wstring_view( arguments[1]) == L"--silabs-inspection" ;
		options.wchInspectionApproved = std::wstring_view( arguments[1]) == L"--wch-inspection" ;
		options.wchMultiInspectionApproved =
			std::wstring_view( arguments[1]) == L"--wch-multi-inspection" ;
		// 既定Providerは維持し、明示された追加Provider一つだけを有効にする。
		for( const drivercrate::ProviderDescriptor &descriptor :
			drivercrate::builtInProviderDescriptors()) {
			// 既定有効またはoptionで明示したProviderだけを検索集合へ追加する。
			if( descriptor.enabledByDefault ||
			   (options.prolificInspectionApproved &&
				descriptor.id == drivercrate::PROLIFIC_OFFICIAL_PROVIDER_ID) ||
			   (options.siliconLabsInspectionApproved &&
				descriptor.id == drivercrate::SILICON_LABS_OFFICIAL_PROVIDER_ID) ||
			   (options.wchInspectionApproved &&
				descriptor.id == drivercrate::WCH_OFFICIAL_PROVIDER_ID) ||
			   (options.wchMultiInspectionApproved &&
				descriptor.id == drivercrate::WCH_MULTI_OFFICIAL_PROVIDER_ID) ||
			   (broadcomDiscovery &&
				descriptor.id == drivercrate::BROADCOM_NET_XTREME_PROVIDER_ID)) {
				options.enabledProviderIds.emplace_back( descriptor.id) ;
			}
		}
	}

	const drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;	// Test threadのCOM MTA。
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		std::wcerr << L"COM initialization failed: "
				   << drivercrate::formatNativeError(
						  static_cast<drivercrate::NativeError>( apartment.result()))
				   << L'\n' ;
		return 1 ;
	}

	drivercrate::CompositeUpdateProvider provider ;	// 全組み込み取得元のaggregate provider。
	drivercrate::ProviderStage			 lastStage =
		drivercrate::ProviderStage::SCANNING_DEVICES ;			// 最後に通知された処理段階。
	std::uint32_t								lastPercent{} ;	// 最後に確定した全体進捗率。
	const drivercrate::ProviderProgressCallback progressCallback =
		[&lastStage, &lastPercent]( const drivercrate::ProviderProgress &progress) {
			lastStage	= progress.stage ;
			lastPercent = progress.percentComplete ;
		} ; // 読み取り専用scanの進捗受理先。
	const drivercrate::ScanResult result =
		// 導入しないaggregate scan結果。
		provider.scan( 1, options, progressCallback) ;
	// 集約検索が失敗した場合は機密情報を出さず、Provider別の状態と数値診断を残す。
	if( !result.succeeded) {
		std::cerr << "Failure diagnostic: reports=" << result.providerReports.size()
				  << ", stage=" << static_cast<std::uint32_t>( lastStage)
				  << ", percent=" << lastPercent << '\n' ;
		std::size_t reportIndex{} ;	// Registry順で出力するProvider報告index。
		// Localeに左右されず、Provider不整合を特定できる数値だけを出力する。
		for( const drivercrate::ProviderScanReport &report : result.providerReports) {
			std::cerr << "Report " << reportIndex++
					  << ": state=" << static_cast<std::uint32_t>( report.state)
					  << ", eligible=" << report.coverage.eligibleDeviceCount
					  << ", assessed=" << report.coverage.assessedDeviceCount
					  << ", candidates=" << report.candidateCount << ", error=" << report.error
					  << '\n' ;
		}

		std::wcerr << L"Composite scan failed: " << drivercrate::formatNativeError( result.error)
				   << L'\n' ;
		// 端末情報を出力せず、失敗位置の切分けに必要なProvider集計だけを表示する。
		for( const drivercrate::ProviderScanReport &report : result.providerReports) {
			std::wcerr << L"Provider " << report.descriptor.id << L": state="
					   << static_cast<std::uint32_t>( report.state) << L", eligible="
					   << report.coverage.eligibleDeviceCount << L", assessed="
					   << report.coverage.assessedDeviceCount << L", candidates="
					   << report.candidateCount << L", error="
					   << drivercrate::formatNativeError( report.error) << L'\n' ;
		}

		return 1 ;
	}

	// 無効や対象外も含む全Provider報告がそろわなければ、集約結果を合格にしない。
	if( result.providerReports.size() != drivercrate::builtInProviderDescriptors().size()) {
		std::wcerr << L"Composite scan returned an incomplete provider report.\n" ;
		return 1 ;
	}

	// Provider別coverageの対象／判定件数が端末内集計として矛盾しないことを確認する。
	for( const drivercrate::ProviderScanReport &report : result.providerReports) {
		// 成否とは別に、候補なし／無効／監査拒否を識別できる集計値を残す。
		std::wcout << L"Provider " << report.descriptor.id << L": state="
				   << static_cast<std::uint32_t>( report.state) << L", eligible="
				   << report.coverage.eligibleDeviceCount << L", assessed="
				   << report.coverage.assessedDeviceCount << L", candidates="
				   << report.candidateCount << L", error=" << report.error << L'\n' ;
		// Providerのcoverage件数に矛盾があれば、表示集計の正常性を保証しない。
		if( !drivercrate::isValidProviderCoverage( report.coverage)) {
			std::wcerr << L"Composite scan returned invalid local coverage.\n" ;
			return 1 ;
		}

		// 対象外判定前のVAIO読取り誤拒否をaggregateの部分成功で隠さない。
		if( report.descriptor.id == drivercrate::VAIO_PROVIDER_ID && report.error != 0) {
			std::wcerr << L"VAIO provider regression returned an individual error.\n" ;
			return 1 ;
		}

		// 明示試験したProviderが失敗してもaggregateの部分成功で合格にしない。
		if( ((options.prolificInspectionApproved &&
			 report.descriptor.id == drivercrate::PROLIFIC_OFFICIAL_PROVIDER_ID) ||
			(options.siliconLabsInspectionApproved &&
			 report.descriptor.id == drivercrate::SILICON_LABS_OFFICIAL_PROVIDER_ID) ||
			(options.wchInspectionApproved &&
			 report.descriptor.id == drivercrate::WCH_OFFICIAL_PROVIDER_ID) ||
			(options.wchMultiInspectionApproved &&
			 report.descriptor.id == drivercrate::WCH_MULTI_OFFICIAL_PROVIDER_ID) ||
			(broadcomDiscovery &&
			 report.descriptor.id == drivercrate::BROADCOM_NET_XTREME_PROVIDER_ID)) &&
		   (report.error != 0 ||
			(report.state != drivercrate::ProviderScanState::NOT_APPLICABLE &&
			 report.state != drivercrate::ProviderScanState::NO_CANDIDATES &&
			 report.state != drivercrate::ProviderScanState::CANDIDATES_AVAILABLE))) {
			std::wcerr << L"Explicit official provider did not complete successfully.\n" ;
			return 1 ;
		}
	}

	const auto nvidiaReport =	// NVIDIA対象実機のProvider別回帰結果。
		std::find_if( result.providerReports.begin(), result.providerReports.end(),
					 []( const drivercrate::ProviderScanReport &report) {
						 return report.descriptor.id == drivercrate::NVIDIA_PROVIDER_ID ;
					 }) ;
	// NVIDIAの候補がなくても報告行は必須とし、Provider未実行の見落としを防ぐ。
	if( nvidiaReport == result.providerReports.end()) {
		std::wcerr << L"Composite scan did not return the NVIDIA provider report.\n" ;
		return 1 ;
	}

	std::unordered_set<std::wstring> devices ;				// 重複を除いたopaque device identity集合。
	std::unordered_set<std::wstring> sources ;				// 重複を除いた取得元名称集合。
	std::size_t						 installableCount{} ;	// 明示選択可能な全候補数。
	std::size_t	  recommendedInstallableCount{} ;			// 初期選択されるProvider推奨候補数。
	std::size_t	  equivalentSourceGroupCount{} ;			// 同一版として注釈された取得元group数。
	std::uint64_t currentDeviceCount{} ;					// Local coverageの母数となる現在版device数。
	std::uint64_t nvidiaCandidateCount{} ;					// NVIDIA Providerが返した表示候補数。
	// 秘密metadataを出力せず、公開DTOの必須項目と集計値だけを検証する。
	for( const drivercrate::UpdateCandidate &candidate : result.candidates) {
		// deviceと取得元、packageを特定できない候補が混入した集約結果を拒否する。
		if( candidate.deviceIdentity.empty() || candidate.sourceName.empty() ||
		   candidate.providerId.empty() || candidate.packageIdentity.empty()) {
			std::wcerr << L"Composite scan returned candidate without source/device metadata.\n" ;
			return 1 ;
		}

		devices.insert( candidate.deviceIdentity) ;
		sources.insert( candidate.sourceName) ;
		installableCount += candidate.installable ? 1U : 0U ;
		recommendedInstallableCount += candidate.installable && candidate.recommended ? 1U : 0U ;
		currentDeviceCount += candidate.current ? 1U : 0U ;
		// NVIDIA候補だけに固有metadataの要件を確認し、専用の候補数へ集計する。
		if( candidate.providerId == drivercrate::NVIDIA_PROVIDER_ID) {
			// NVIDIAの更新候補を現在版扱いにせず、明示版と取得元が欠ける通知を拒否する。
			if( candidate.current || candidate.version.empty() || candidate.sourceName.empty() ||
			   candidate.sourceLocation.empty()) {
				std::wcerr << L"NVIDIA provider returned incomplete candidate metadata.\n" ;
				return 1 ;
			}

			++nvidiaCandidateCount ;
		}

		// 同一版取得元groupのない候補には、複数取得元の整合検査を適用しない。
		if( candidate.equivalentSourceCount <= 1U) {
			continue ;
		}

		// 導入可能な明示版候補以外へ同一版の取得元注釈を付ける退行を検出する。
		if( candidate.current || !candidate.installable || candidate.version.empty() ||
		   candidate.action == drivercrate::DriverAction::NONE) {
			std::wcerr << L"Composite scan returned invalid equivalent-source annotation.\n" ;
			return 1 ;
		}

		std::unordered_set<std::wstring> equivalentProviders ;			// 同一版を提示したProvider集合。
		std::size_t						 annotatedCandidateCount{} ;	// 同じgroup注釈の候補数。
		std::size_t						 preferredCandidateCount{} ;	// 既定取得元の候補数。
		// 全候補を一度ずつ照合し、同じdevice・版・操作の取得元数と初期選択数を集計する。
		for( const drivercrate::UpdateCandidate &equivalentCandidate : result.candidates) {
			// 異なるdevice・版・操作の候補を同じ取得元groupの件数へ混ぜない。
			if( equivalentCandidate.equivalentSourceCount <= 1U ||
			   equivalentCandidate.deviceIdentity != candidate.deviceIdentity ||
			   equivalentCandidate.version != candidate.version ||
			   equivalentCandidate.action != candidate.action) {
				continue ;
			}

			++annotatedCandidateCount ;
			preferredCandidateCount += equivalentCandidate.preferredSource ? 1U : 0U ;
			equivalentProviders.insert( equivalentCandidate.providerId) ;
		}

		// 取得元数が実候補と一致しない、または既定取得元が一件でない注釈を拒否する。
		if( annotatedCandidateCount != candidate.equivalentSourceCount ||
		   equivalentProviders.size() != candidate.equivalentSourceCount ||
		   preferredCandidateCount != 1U) {
			std::wcerr << L"Composite scan returned inconsistent equivalent-source annotation.\n" ;
			return 1 ;
		}

		equivalentSourceGroupCount += candidate.preferredSource ? 1U : 0U ;
	}

	std::uint64_t coverageDeviceCount{} ;	// Manufacturer／class集計に含まれたdevice合計。
	// 取得元別の候補到達device数が各groupのpresent device数を超えないことを検証する。
	for( const drivercrate::LocalCoverageEntry &entry : result.localCoverage) {
		// 候補到達数が母数を超える集計と、母数合計の整数上限超過を検出する。
		if( entry.candidateDeviceCount > entry.deviceCount ||
		   entry.managedCandidateDeviceCount > entry.deviceCount ||
		   entry.officialCandidateDeviceCount > entry.deviceCount ||
		   entry.userSelectedCandidateDeviceCount > entry.deviceCount ||
		   entry.localCandidateDeviceCount > entry.deviceCount ||
		   entry.deviceCount > std::numeric_limits<std::uint64_t>::max() - coverageDeviceCount) {
			std::wcerr << L"Composite scan returned invalid manufacturer/class coverage.\n" ;
			return 1 ;
		}

		coverageDeviceCount += entry.deviceCount ;
	}

	// メーカー別集計で現在deviceを落としたり重複させたりしていないことを確認する。
	if( coverageDeviceCount != currentDeviceCount) {
		std::wcerr << L"Composite scan returned incomplete manufacturer/class coverage.\n" ;
		return 1 ;
	}

	// NVIDIAのProvider報告と実際に返った候補行の件数を一致させる。
	if( nvidiaReport->candidateCount != nvidiaCandidateCount) {
		std::wcerr << L"NVIDIA provider report does not match its candidate count.\n" ;
		return 1 ;
	}

	// 対応deviceがあるのに未評価または失敗したNVIDIA検索を、候補なしの合格にしない。
	if( nvidiaReport->coverage.eligibleDeviceCount > 0 &&
	   (nvidiaReport->coverage.assessedDeviceCount == 0 ||
		nvidiaReport->state == drivercrate::ProviderScanState::DISABLED ||
		nvidiaReport->state == drivercrate::ProviderScanState::NOT_APPLICABLE ||
		nvidiaReport->state == drivercrate::ProviderScanState::FAILURE ||
		nvidiaReport->state == drivercrate::ProviderScanState::METADATA_REJECTED)) {
		std::wcerr << L"NVIDIA provider did not assess the supported-device regression set.\n" ;
		return 1 ;
	}

	std::wcout << L"Composite scan succeeded. Devices: " << devices.size() << L", candidates: "
			   << result.candidates.size() << L", sources: " << sources.size() << L", selectable: "
			   << installableCount << L", recommended updates: " << recommendedInstallableCount
			   << L", equivalent-source groups: " << equivalentSourceGroupCount
			   << L", coverage devices: " << coverageDeviceCount << L", coverage groups: "
			   << result.localCoverage.size() << L", NVIDIA eligible/assessed/candidates: "
			   << nvidiaReport->coverage.eligibleDeviceCount << L"/"
			   << nvidiaReport->coverage.assessedDeviceCount << L"/" << nvidiaCandidateCount
			   << L'\n' ;
	return 0 ;
}
