//------------------------------------------------------------------------------
/**
 * @file install_diagnostic_tests.cpp
 * @brief WUA取得段階と復元最終guardの匿名投影をfakeで確認します
 * @version 01.00.11
 * @date 2026/11/12
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/12  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/11/12  WUA検索終端の状態契約と診断改訂値を整合
 * Ver.01.00.02 Shunji Ogawa  2026/11/12  外側tupleの取得予約と開始拒否の原理由を接続
 * Ver.01.00.03 Shunji Ogawa  2026/11/12  導入前保護失敗に結合した一回の明示復元なし続行を接続
 * Ver.01.00.04 Shunji Ogawa  2026/11/13  元適用性errorへ固定失敗leafとcode由来だけを接続
 * Ver.01.00.05 Shunji Ogawa  2026/11/13  bounded opaque PnP IDのrank照合と限定回帰を接続
 * Ver.01.00.06 Shunji Ogawa  2026/11/13  Needs AddRegの元拒否leafを既匿名診断へ接続
 * Ver.01.00.07 Shunji Ogawa  2026/11/13  847kの検証済みSYSTEM媒体作用と限定資格を接続
 * Ver.01.00.08 Shunji Ogawa  2026/11/13  847pの通常件数枠と原予算境界を整合
 * Ver.01.00.09 Shunji Ogawa  2026/11/13  847p9の型付きSYSTEM全作用と全選択資格を接続
 * Ver.01.00.10 Shunji Ogawa  2026/11/14  導入後の推奨表示から処理済み対象だけを除外
 * Ver.01.00.11 Shunji Ogawa  2026/11/15  既存temp親の所有一意leafへfixtureを限定しcwd依存を除去
 * </pre>
 * @note 新規fixtureと完全fakeだけを使い、実WUA/driver/復元/設定へ作用しません
 * @see docs/adr/0427-local-anonymous-scan-diagnostics.md
 */
//------------------------------------------------------------------------------

#include "core/protected_install.h"
#include "platform/windows_restore_point_service.h"
#include "platform/local_scan_diagnostics.h"
#include "platform/local_diagnostic_log.h"
#include "platform/provider_worker.h"
#include "core/provider_registry.h"
#include "protected_install_tests.h"
#include "test_framework.h"
#include "app/resource.h"
#include <Windows.h>
#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <format>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <vector>
namespace {
using namespace drivercrate ;
namespace fs = std::filesystem ;
unsigned checks{} ;	// 非対話で原失敗を数値だけに残します
//------------------------------------------------------------------------------
/**
 * @brief 原期待をassert dialogなしで確認します
 * @param[in] valid 成立すべき固定条件です
 */
//------------------------------------------------------------------------------
void	 check( const bool valid)
{
	++checks ;
	// 一失敗を正常へ補完しません
	if( !valid) {
		std::printf( "DIAGNOSTIC_CHECK_FAILED=%u\n", checks) ;
		throw std::runtime_error( "FIXTURE") ;
	}
}
/** @brief 個別DTOだけを返し、本番Provider APIを呼ばないfakeです */
class Provider final : public IUpdateProvider {
public:
	/// fixtureが明示した元4件結果です
	InstallResult value ;
	/// coreがProviderへ入った回数です
	unsigned	  calls{} ;
	/**
  * @brief 通常scanを行わず空の固定結果だけを返します
  * @param[in] session 架空sessionです
  * @param[in] options 使用しない設定です
  * @param[in] progress 呼ばないcallbackです
  * @return 架空sessionへ結ぶ空結果です
  */
	ScanResult	  scan( const ScanSessionId session, const ScanOptions &options,
					   const ProviderProgressCallback &progress) override
	{
		static_cast<void>( options) ;
		static_cast<void>( progress) ;
		return {.scanSessionId = session} ;
	}
	/**
  * @brief 元選択順のfake結果だけを複製します
  * @param[in] session 架空sessionです
  * @param[in] identities 生文字列は元結合だけに使います
  * @param[in] parent 呼ばないnative親です
  * @param[in] progress 呼ばないcallbackです
  * @return 設定済み元DTOです。native作用はありません
  */
	InstallResult install( const ScanSessionId				  session,
						  const std::span<const std::wstring> identities,
						  const std::uintptr_t				  parent,
						  const ProviderProgressCallback	 &progress) override
	{
		static_cast<void>( session) ;
		static_cast<void>( identities) ;
		static_cast<void>( parent) ;
		static_cast<void>( progress) ;
		++calls ;
		return value ;
	}
} ;
/** @brief 完全fakeの復元呼出し/一覧だけを所有します */
struct RestoreState {
	/// BEGIN/END後のどちらで消失させるかを0/2/3で指定します
	unsigned missing{} ;
	/// 一覧の呼出し回数です
	unsigned lists{} ;
	/// 実APIの代替BEGIN回数です
	unsigned begins{} ;
	/// 実APIの代替END回数です
	unsigned ends{} ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief 完全fakeの復元serviceを構築します
 * @param[in] state callback寿命へ共有する架空状態です
 * @return 実WMI/時計/復元APIへfallbackしないserviceです
 */
//------------------------------------------------------------------------------
std::unique_ptr<IRestorePointService> restore( const std::shared_ptr<RestoreState> &state)
{
	restore_point_detail::Calls calls ;	// 全callbackを明示します
	calls.clock = [] {
		return restore_point_detail::Clock{2000000000LL, 20330518U} ;
	} ; // 架空UTC/local日だけです
	calls.points = [state]( auto &points) {	// 元番号/時刻はlogへ出しません
		++state->lists ;
		points.clear() ;
		// 指定した一phaseだけで実在を欠かせます
		if( state->lists != state->missing) {
			points.push_back( {710001, 1999999900LL}) ;
		}

		return NativeError{} ;
	} ;
	calls.begin = [state]( auto) {
		++state->begins ;
		return RestorePointOperationResult{.outcome		   = OutcomeCode::SUCCESS,
										   .sequenceNumber = 710001} ;
	} ; // 元scopeだけを模擬します
	calls.end = [state]( auto sequence) {
		++state->ends ;
		return RestorePointOperationResult{.outcome		   = OutcomeCode::SUCCESS,
										   .sequenceNumber = sequence} ;
	} ; // 実ENDを呼びません
	calls.lock = []( auto &lease) {
		lease = std::make_shared<int>( 0) ;
		return NativeError{} ;
	} ; // fixture内のscope寿命だけです
	calls.loadMemo = []( auto &memo) {
		memo = {} ;
		return NativeError{} ;
	} ; // 原状態を読みません
	// fileを作りません
	calls.saveMemo = []( const auto &) { return NativeError{} ; } ;
	return restore_point_detail::createFixture( calls) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元scanの非連続位置から選んだ4件のDTOを作ります
 * @param[in] stage 同じerrorを区別する固定地点です
 * @return 元選択順の人工失敗です。実COMの実測ではありません
 */
//------------------------------------------------------------------------------
InstallResult fourResults( const WuaDownloadStage stage)
{
	const std::array<unsigned, 4> sourceIndices{2, 7, 9,
												12} ;	// 元scan位置とselection位置を同一視しません
	InstallResult				  result ;				// 作用や資格を含みません
	result.downloadOutcome = OutcomeCode::FAILURE ;
	result.downloadError   = static_cast<NativeError>( 0x80070057U) ;
	// 非連続元indexの選択順へordinal1..4を結び、0..3 result順を維持します
	for( std::size_t at = 0; at < sourceIndices.size(); ++at) {
		const std::uint64_t ordinal =
			stage == WuaDownloadStage::INPUT || stage == WuaDownloadStage::COLLECTION_CREATE ||
					stage == WuaDownloadStage::DOWNLOAD
				? 0U
				: (stage == WuaDownloadStage::UPDATE_RESULT ||
						   stage == WuaDownloadStage::UPDATE_RESULT_CODE ||
						   stage == WuaDownloadStage::UPDATE_HRESULT ||
						   stage == WuaDownloadStage::UPDATE_OUTCOME
					   ? at + 1U
					   : 2U) ;	// 全体0/個別選択/準備失敗2を独立に与えます
		result.updates.push_back(
			{.identity		  = L"PRIVATE_SENTINEL_UPDATE_" + std::to_wstring( sourceIndices[at]),
			 .downloadOutcome = OutcomeCode::FAILURE,
			 .downloadError	  = static_cast<NativeError>( 0x80070057U),
			 .wuaDownloadDiagnostic = {stage, static_cast<NativeError>( 0x80070057U), ordinal,
									   sourceIndices.size()}}) ;
	}

	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief fixtureの既二slotだけを読み戻します
 * @param[in] folder 自分で作ったfixture rootです
 * @return 一般出力しない原log byteです
 */
//------------------------------------------------------------------------------
std::string bytes( const fs::path &folder)
{
	std::string value ;	// privacyの検査専用です
	// 既二slot以外を列挙しません
	for( const auto name : {L"scan-0.log", L"scan-1.log"}) {
		std::ifstream input( folder / L"log" / name, std::ios::binary) ;	// fixtureだけです
		value.append( std::istreambuf_iterator<char>( input), std::istreambuf_iterator<char>()) ;
	}

	return value ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元4件と各固定API地点の伝達・privacy・保存失敗非干渉を確認します
 * @param[in] base 作成済み新規fixtureの親です
 */
//------------------------------------------------------------------------------
void projections( const fs::path &base)
{
	const std::array stages{WuaDownloadStage::INPUT,
							WuaDownloadStage::COLLECTION_CREATE,
							WuaDownloadStage::EULA_STATUS,
							WuaDownloadStage::EULA_ACCEPT,
							WuaDownloadStage::DOWNLOAD,
							WuaDownloadStage::UPDATE_RESULT,
							WuaDownloadStage::UPDATE_RESULT_CODE,
							WuaDownloadStage::UPDATE_HRESULT,
							WuaDownloadStage::UPDATE_OUTCOME,
							WuaDownloadStage::ORIGIN_GUID} ;	// 同57を段階で区別します
	// 各phaseとBEGIN後/END後の欠測だけを独立fixtureへ投影します
	for( unsigned variant = 0; variant < 14U; ++variant) {
		const auto folder = base / std::to_wstring( variant) ;	// 各失敗原byteを独立させます
		check( fs::create_directory( folder)) ;
		LocalDiagnosticLog log ;	// 本番logへ接続しません
		// 全投影を検査するfixtureだけはwriterのtry-lock競合を既pauseで除きます
		local_diagnostic_detail::Access::startPaused( log, folder.native()) ;
		log.append( DiagnosticRecord{}) ;
		check( log.status().state != DiagnosticStorageState::FAILED) ;
		Provider provider ;	// 元結果をcoreへ渡します
		provider.value = fourResults( stages[variant < 10U ? variant : 4U]) ;
		// 原returnの57とGUID APIの異なる元HRESULTを独立に保持します
		if( variant == 9U) {
			// 各元選択の診断だけを別codeへ設定し、downloadErrorは変更しません
			for( auto &item : provider.value.updates) {
				item.wuaDownloadDiagnostic.error = static_cast<NativeError>( 0x800401f3U) ;
			}
		}

		// 元WUA取消しは成功や別errorへ変換しません
		if( variant == 13U) {
			provider.value.downloadOutcome = OutcomeCode::ABORTED ;
			provider.value.downloadError   = static_cast<NativeError>( E_ABORT) ;
			// 各個別の元ABORTED/原errorを投影します
			for( auto &item : provider.value.updates) {
				item.downloadOutcome			 = OutcomeCode::ABORTED ;
				item.downloadError				 = static_cast<NativeError>( E_ABORT) ;
				item.wuaDownloadDiagnostic.error = static_cast<NativeError>( E_ABORT) ;
			}
		}

		auto state	   = std::make_shared<RestoreState>() ;	// 元BEGIN/ENDを数値で確認します
		state->missing = variant == 10U ? 2U : variant == 11U ? 3U : 0U ;
		const auto					 service = restore( state) ;	// 本番APIへfallbackしません
		std::vector<std::wstring>	 ids ;							// 生値はcoreの元結合だけです
		std::vector<UpdateCandidate> candidates ;					// 匿名providerの結合用です
		// 元人工4件の順を変えません
		for( const auto &item : provider.value.updates) {
			ids.push_back( item.identity) ;
			UpdateCandidate candidate ;	// 生値のsentinelが出ないことを確認します
			candidate.identity	 = item.identity ;
			candidate.providerId = WINDOWS_UPDATE_PROVIDER_ID ;
			candidate.title		 = L"PRIVATE_SENTINEL_TITLE" ;
			candidates.push_back( candidate) ;
		}

		const auto result = installWithRestorePoint(
			provider, *service, 91, ids, 0, []( const auto &) {}, L"synthetic") ;	// 実導入は0です
		check( state->begins == 1 && state->ends == 1) ;
		check( provider.calls == (variant == 10U ? 0U : 1U)) ;
		check( isRestorePointProtectionValid( result) == (variant != 10U && variant != 11U)) ;
		check( restorePointProtectionIssue( result) ==
			  (variant == 10U	? RestorePointProtectionIssue::BEFORE_NOT_VERIFIED
			   : variant == 11U ? RestorePointProtectionIssue::AFTER_NOT_VERIFIED
								: RestorePointProtectionIssue::NONE)) ;
		WorkerEvent event ;	// 同一終端を投影します
		event.operationId	= 92 ;
		event.installResult = result ;
		// 保存不能は後の診断だけに注入します
		if( variant == 12U) {
			local_diagnostic_detail::Access::fail( log, DiagnosticStorageStage::WRITE) ;
		}

		recordInstallDiagnostics( event, 91, candidates, 3, &log) ;
		const auto resource = variant == 10U || variant == 11U
								  ? IDS_RESTORE_VERIFICATION_ERROR
								  : IDS_RESULT_FAILURE ;	// 独立した画像分岐の期待です
		recordInstallFeedbackDiagnostics( event.operationId, resource,
										 result.restorePointProtection.error, false, &log) ;
		// 本人判断の全固定段階を同じ匿名sinkへ投影し、保存失敗も非干渉で扱います
		if( variant == 0U || variant == 12U) {
			// 提示/中止/判断/両受理拒否/実行の閉集合だけを記録します
			for( unsigned stage{};
				stage <= static_cast<unsigned>( RestoreContinuationStage::EXECUTED); ++stage) {
				recordRestoreContinuationDiagnostics(
					93U, static_cast<RestoreContinuationStage>( stage), 92U,
					static_cast<NativeError>( 0x80070422U), 4U, 0U, &log) ;
			}
		}

		local_diagnostic_detail::Access::resume( log) ;
		check( local_diagnostic_detail::Access::drain( log)) ;
		log.stop() ;
		check( provider.calls == (variant == 10U ? 0U : 1U) && state->ends == 1) ;
		const auto raw = bytes( folder) ;	// 通常出力へ出しません
		check( raw.find( "PRIVATE_SENTINEL") == std::string::npos &&
			  raw.find( "sequenceNumber") == std::string::npos &&
			  raw.find( "createdUtc") == std::string::npos) ;
		// 原WRITE失敗は成功した診断へ数えません
		if( variant == 12U) {
			check( log.status().state == DiagnosticStorageState::FAILED) ;
			continue ;
		}

		// 生文字列なしの元失敗/新操作/元codeと全固定段階を独立照合します
		if( variant == 0U) {
			check( raw.find( "event=restore_continuation provider=application operation=93") !=
					  std::string::npos &&
				  raw.find( "failedOperation=92") != std::string::npos &&
				  raw.find( "error=" + std::to_string( static_cast<NativeError>( 0x80070422U))) !=
					  std::string::npos) ;
		}

		check( raw.find( "event=restore_final") != std::string::npos &&
			  raw.find( "event=install_feedback") != std::string::npos) ;
		check( raw.find( "diagnosticRevision=12") != std::string::npos &&
			  raw.find( "run=" + std::to_string( localDiagnosticRunId())) != std::string::npos) ;
		check( raw.find( "status=" + std::to_string( resource) + " error=") != std::string::npos) ;
		// Provider前の欠測はWUAを開始した診断を作りません
		if( variant == 10U) {
			check( raw.find( "event=wua_download") == std::string::npos) ;
		} else {
			// 各元selection ordinalと同stage/errorを独立に照合します
			for( unsigned ordinal = 1; ordinal <= 4; ++ordinal) {
				check( raw.find(
						  "stage=" +
						  std::to_string(
							  static_cast<unsigned>( stages[variant < 10U ? variant : 4U])) +
						  " ordinal=" +
						  std::to_string( stages[variant < 10U ? variant : 4U] ==
													 WuaDownloadStage::DOWNLOAD ||
												 stages[variant < 10U ? variant : 4U] ==
													 WuaDownloadStage::INPUT ||
												 stages[variant < 10U ? variant : 4U] ==
													 WuaDownloadStage::COLLECTION_CREATE
											 ? 0U
											 : (stages[variant < 10U ? variant : 4U] ==
															WuaDownloadStage::UPDATE_RESULT ||
														stages[variant < 10U ? variant : 4U] ==
															WuaDownloadStage::UPDATE_RESULT_CODE ||
														stages[variant < 10U ? variant : 4U] ==
															WuaDownloadStage::UPDATE_HRESULT ||
														stages[variant < 10U ? variant : 4U] ==
															WuaDownloadStage::UPDATE_OUTCOME
													? ordinal
													: 2U)) +
						  " total=4 processed=" + std::to_string( ordinal)) != std::string::npos) ;
			}
		}

		// 原DTOのcancelと解析API値を診断で改作しません
		if( variant == 13U) {
			check( event.installResult.updates.front().downloadOutcome == OutcomeCode::ABORTED &&
				  raw.find( "error=" + std::to_string( static_cast<NativeError>( E_ABORT))) !=
					  std::string::npos) ;
		}

		// 異なる原API値と既downloadErrorの両方が残ることを確認します
		if( variant == 9U) {
			check( raw.find( "error=" + std::to_string( static_cast<NativeError>( 0x800401f3U))) !=
					  std::string::npos &&
				  raw.find( "downloadError=2147942487") != std::string::npos) ;
		}

		check( event.installResult.updates.size() == 4 && !event.installResult.succeeded) ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 最終guardの未記録だった各fieldを独立期待へ照合します
 */
//------------------------------------------------------------------------------
void guardMatrix()
{
	Provider provider ;	// 原4件の取得失敗だけです
	provider.value	   = fourResults( WuaDownloadStage::DOWNLOAD) ;
	const auto state   = std::make_shared<RestoreState>() ;	// 正当な保護結果だけを作ります
	const auto service = restore( state) ;					// 完全fakeであり本番APIへfallbackしません
	const std::array<std::wstring, 4> ids{
		L"PRIVATE_SENTINEL_UPDATE_2", L"PRIVATE_SENTINEL_UPDATE_7", L"PRIVATE_SENTINEL_UPDATE_9",
		L"PRIVATE_SENTINEL_UPDATE_12"} ;	// 元人工4件と同じ順です
	const auto valid = installWithRestorePoint(
		provider, *service, 1, ids, 0, []( const auto &) {}, L"fake") ;	// 実復元APIを呼びません
	check( isRestorePointProtectionValid( valid)) ;
	const std::array expected{
		RestorePointProtectionIssue::BEFORE_NOT_VERIFIED,
		RestorePointProtectionIssue::AFTER_NOT_VERIFIED,
		RestorePointProtectionIssue::VERIFICATION,
		RestorePointProtectionIssue::PROTECTION_ERROR,
		RestorePointProtectionIssue::SEQUENCE,
		RestorePointProtectionIssue::CREATION_TIME,
		RestorePointProtectionIssue::LOCAL_DAY,
		RestorePointProtectionIssue::NATIVE_STATE,
		RestorePointProtectionIssue::NATIVE_ERROR,
		RestorePointProtectionIssue::SEQUENCE_BINDING} ;	// 元boolの不成立を固定理由へ結びます
	// 一fieldだけを欠かせ、別の成功flagで補完しないことを確認します
	for( unsigned at = 0; at < expected.size(); ++at) {
		auto value = valid ;	// 原positiveを毎回保全します
		// 元guardに必要なfieldを一つずつ欠かせます
		switch( at) {
			// Provider前の実在なしです
			case 0:
				value.restorePointProtection.verifiedBefore = false ;
				// Provider前の実在なしです
				break ;

			// scope後の実在なしです
			case 1:
				value.restorePointProtection.verifiedAfter = false ;
				// scope後の実在なしです
				break ;

			// 元検証失敗です
			case 2:
				value.restorePointProtection.verification = OutcomeCode::FAILURE ;
				// 元検証失敗です
				break ;

			// 原errorです
			case 3:
				value.restorePointProtection.error = static_cast<NativeError>( 0x80070490U) ;
				// 原errorです
				break ;

			// 番号不成立です
			case 4:
				value.restorePointProtection.sequenceNumber = 0 ;
				// 番号不成立です
				break ;

			// 作成時刻不成立です
			case 5:
				value.restorePointProtection.createdUtc = 0 ;
				// 作成時刻不成立です
				break ;

			// 元日付なしです
			case 6:
				value.restorePointProtection.localDay = 0 ;
				// 元日付なしです
				break ;

			// END未実行です
			case 7:
				value.restorePointProtection.nativeEndCalled = false ;
				// END未実行です
				break ;

			// 原END errorです
			case 8:
				value.restorePointCompletion.error = static_cast<NativeError>( E_FAIL) ;
				// 原END errorです
				break ;

			// 別番号です
			case 9:
				++value.restorePointCompletion.sequenceNumber ;
				// 別番号です
				break ;

			default:
				// 有限配列の範囲外へ進みません
				break ;
		}

		check( !isRestorePointProtectionValid( value) &&
			  restorePointProtectionIssue( value) == expected[at]) ;
	}
}
}
//------------------------------------------------------------------------------
/**
 * @brief 既保護fakeと追加匿名投影だけを有限実行します
 * @return 全期待成立0、原失敗1です
 * @note Cwdに依存せず既存temp親の新規一意leafだけを所有/削除します。親不明/既存leafは拒否します
 * 実WUA/driver/restore/Windows設定/本番logへ作用しません
 */
//------------------------------------------------------------------------------
int main()
{
	SetErrorMode( SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) ;
	try {
		drivercrate::test::TestContext context ;	// 既保護契約の期待をそのまま再利用します
		drivercrate::test::runProtectedInstallTests( context) ;
		check( context.failureCount() == 0) ;
		std::error_code error ;												// 既存temp親の照会失敗を新規親の作成へ補いません
		auto parent = fs::temp_directory_path( error).lexically_normal() ;	// 共有親は借用します
		// Windows tempの末尾separatorだけを除き、同じ親との比較を安定させます
		if( parent.filename().empty()) {
			parent = parent.parent_path() ;
		}

		check( !error && parent.is_absolute() && fs::is_directory( parent, error) && !error) ;
		const auto base =
			(parent / std::format( L"839-diag-{}-{}", GetCurrentProcessId(), GetTickCount64()))
				.lexically_normal() ;	// 作成成功したこの一意leafだけを所有します
		check( base.parent_path() == parent && fs::create_directory( base)) ;
		projections( base) ;
		guardMatrix() ;
		// 共有temp親や既存leafを削除せず、新規所有したbaseだけを片付けます
		check( base.parent_path() == parent && fs::remove_all( base) > 0) ;
		std::printf(
			"INSTALL_DIAGNOSTICS checks=%u protectedChecks=%d failures=0 realWua=0 nativeInstall=0 realRestore=0\n",
			checks, context.assertionCount()) ;
		return 0 ;
	} catch( ...) {
		std::printf( "INSTALL_DIAGNOSTICS_FAILED checks=%u\n", checks) ;
		return 1 ;
	}
}
