//------------------------------------------------------------------------------
/**
 * @file protected_install_tests.cpp
 * @brief 復元ポイント保護付きinstall単体試験実装
 * @version 01.01.04
 * @date 2026/09/01
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  保護付き進捗試験追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Windows Server専用経路試験追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/10  最新実確認の選択表示と日内復元保護の実在再利用を接続
 * Ver.01.01.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.01.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.01.03 Shunji Ogawa  2026/11/12  導入前保護失敗に結合した一回の明示復元なし続行を接続
 * Ver.01.01.04 Shunji Ogawa  2026/11/14  日次memo試験を既存temp親の新規一意leafへ限定
 * </pre>
 *
 * @note fake Providerとfake復元ポイントサービスだけを使用します。SRSetRestorePointW、download、driver installは呼び出しません
 */
//------------------------------------------------------------------------------

#include "protected_install_tests.h"
#include "core/operation_controller.h"

#include "core/protected_install.h"
#include "platform/windows_restore_point_service.h"
#include <Windows.h>
#include "platform/official_release_observation_store.h"
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <iostream>
#include "test_framework.h"

#include <array>
#include <algorithm>
#include <utility>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// Fake型定義
//------------------------------------------------------------------------------

/**
 * @brief 呼出結果と回数を制御できる復元ポイントサービスfakeである
 */
class FakeRestorePointService final : public IRestorePointService {
public:
	/// 元fieldが正常でも未許可区分をProvider前に拒否するための注入値です
	RestorePointDisposition		 disposition{RestorePointDisposition::WINDOWS_SELECTED_POINT} ;
	/// 同fakeの実行済みcallbackからだけ作る明示観測です
	RestorePointProtectionResult fakeProtection_{.disposition =
													 RestorePointDisposition::UNAVAILABLE} ;
	/**
	 * @brief 完全fakeの原開始/終了に対応した観測を返します
	 * @return 本番APIを呼ばない観測です
	 */
	[[nodiscard]] RestorePointProtectionResult protection() const noexcept override
	{
		return fakeProtection_ ;
	}

	/// 実BEGIN成功後のProvider前実在検証へ与える元errorです
	NativeError					beforeVerificationError{} ;
	/// Begin戻り値
	RestorePointOperationResult beginResult{.outcome = OutcomeCode::SUCCESS, .sequenceNumber = 100} ;
	/// Complete戻り値
	RestorePointOperationResult completeResult{.outcome		   = OutcomeCode::SUCCESS,
											   .sequenceNumber = 100} ;
	/// Begin呼出し回数
	int							beginCount{} ;
	/// Complete呼出し回数
	int							completeCount{} ;

	/**
	 * @brief 設定済み開始結果を返し、呼出し回数を記録する
	 * @param[in] description 試験対象が渡した復元ポイント説明
	 * @return `beginResult`の複製。 beginResultの複製
	 */
	[[nodiscard]] RestorePointOperationResult begin(
		std::wstring_view description) noexcept override ;

	/**
	 * @brief 設定済み終了結果を返し、呼出し回数を記録する
	 * @param[in] sequenceNumber 試験対象が渡した識別番号
	 * @return `completeResult`の複製。 completeResultの複製
	 */
	[[nodiscard]] RestorePointOperationResult complete(
		std::int64_t sequenceNumber) noexcept override ;
} ;

/**
 * @brief 成功または例外を制御できるdriver Provider fakeである
 */
class FakeUpdateProvider final : public IUpdateProvider {
public:
	/// Providerが偽造してもwrapperが実保護へ採用しない観測です
	RestorePointProtectionResult providerProtection ;
	/// trueの場合はinstallから型付き例外を送出する
	bool						 throwOnInstall{} ;
	/// Install呼出し回数
	int							 installCount{} ;

	/**
	 * @brief 本試験では使用しない既定scan結果を返す
	 * @param[in] scanSessionId 呼出し側が指定したsession ID
	 * @param[in] options 本試験では未使用のscan条件
	 * @param[in] progressCallback 未使用の進捗通知先
	 * @return 未開始のscan結果
	 */
	[[nodiscard]] ScanResult	 scan( ScanSessionId scanSessionId, const ScanOptions &options,
									  const ProviderProgressCallback &progressCallback) override ;

	/**
	 * @brief 選択候補の成功結果を返すか、設定により例外を送出する
	 * install呼出しを記録し、例外設定時は結果を返さず送出する
	 * @param[in] scanSessionId 選択元session ID
	 * @param[in] identities 選択されたopaque identity群
	 * @param[in] parentWindowNative 未使用の親Window値
	 * @param[in] progressCallback 進捗通知callback
	 * @return 全候補成功のinstall結果
	 */
	[[nodiscard]] InstallResult	 install( ScanSessionId					 scanSessionId,
										 std::span<const std::wstring>	 identities,
										 std::uintptr_t					 parentWindowNative,
										 const ProviderProgressCallback &progressCallback) override ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 設定済み開始結果を返し、呼出し回数を記録する
 * @param[in] description 試験対象が渡した復元ポイント説明
 * @return `beginResult`の複製。 beginResultの複製
 */
//------------------------------------------------------------------------------
RestorePointOperationResult FakeRestorePointService::begin(
	const std::wstring_view description) noexcept
{
	const auto result = [&]() noexcept -> RestorePointOperationResult {
		static_cast<void>( description) ;
		++beginCount ;
		return beginResult ;
	}() ; // 元fake API結果とcounterはそのままです
	fakeProtection_ = {.disposition	   = disposition,
					   .verification   = result.outcome == OutcomeCode::SUCCESS &&
												 result.error == 0 && result.sequenceNumber > 0
											 ? OutcomeCode::SUCCESS
											 : OutcomeCode::FAILURE,
					   .error		   = result.error,
					   .sequenceNumber = result.sequenceNumber,
					   .createdUtc	   = 1,
					   .localDay	   = 20261110U,
					   .verifiedBefore = result.outcome == OutcomeCode::SUCCESS &&
										 result.error == 0 && result.sequenceNumber > 0,
					   .nativeBeginCalled = true} ;
	// 実BEGINは所有したまま、元実在確認の未成立だけを合成します
	if( beforeVerificationError != 0U) {
		fakeProtection_.verifiedBefore = false ;
		fakeProtection_.verification   = OutcomeCode::FAILURE ;
		fakeProtection_.error		   = beforeVerificationError ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 設定済み終了結果を返し、呼出し回数を記録する
 * @param[in] sequenceNumber 試験対象が渡した識別番号
 * @return `completeResult`の複製。 completeResultの複製
 */
//------------------------------------------------------------------------------
RestorePointOperationResult FakeRestorePointService::complete(
	const std::int64_t sequenceNumber) noexcept
{
	const auto result = [&]() noexcept -> RestorePointOperationResult {
		++completeCount ;
		RestorePointOperationResult result = completeResult ;	// Fake設定の戻り値
		result.sequenceNumber			   = sequenceNumber ;
		return result ;
	}() ; // 元fake API結果とcounterはそのままです
	fakeProtection_.nativeEndCalled = true ;
	fakeProtection_.verifiedAfter	= result.outcome == OutcomeCode::SUCCESS && result.error == 0 &&
									result.sequenceNumber == fakeProtection_.sequenceNumber ;
	fakeProtection_.verification = fakeProtection_.verifiedBefore && fakeProtection_.verifiedAfter
									   ? OutcomeCode::SUCCESS
									   : OutcomeCode::FAILURE ;
	// fakeの終了診断を実在確認へそのまま保持します
	if( result.error != 0) {
		fakeProtection_.error = result.error ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 本試験では使用しない既定scan結果を返す
 * @param[in] scanSessionId 呼出し側が指定したsession ID
 * @param[in] options 本試験では未使用のscan条件
 * @param[in] progressCallback 未使用の進捗通知先
 * @return 未開始のscan結果
 */
//------------------------------------------------------------------------------
ScanResult FakeUpdateProvider::scan( const ScanSessionId scanSessionId, const ScanOptions &options,
									const ProviderProgressCallback &progressCallback)
{
	static_cast<void>( options) ;
	static_cast<void>( progressCallback) ;
	return {.scanSessionId = scanSessionId} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択候補の成功結果を返すか、設定により例外を送出する。install呼出しを記録し、例外設定時は結果を返さず送出する
 * @param[in] scanSessionId 選択元session ID
 * @param[in] identities 選択されたopaque identity群
 * @param[in] parentWindowNative 未使用の親Window値
 * @param[in] progressCallback 進捗通知callback
 * @return 全候補成功のinstall結果
 */
//------------------------------------------------------------------------------
InstallResult FakeUpdateProvider::install( const ScanSessionId				  scanSessionId,
										  const std::span<const std::wstring> identities,
										  const std::uintptr_t				  parentWindowNative,
										  const ProviderProgressCallback	 &progressCallback)
{
	static_cast<void>( scanSessionId) ;
	static_cast<void>( parentWindowNative) ;
	++installCount ;
	// Provider例外を注入し、開始済み復元ポイントが終了されることを検証する
	if( throwOnInstall) {
		throw std::runtime_error( "synthetic provider failure") ;
	}

	progressCallback( {.stage		  = ProviderStage::DOWNLOADING,
					  .completedItems = 0,
					  .totalItems	  = identities.size()}) ;
	progressCallback( {.stage		   = ProviderStage::INSTALLING,
					  .percentComplete = 100,
					  .completedItems  = identities.size(),
					  .totalItems	   = identities.size()}) ;
	InstallResult result{} ;	// 全選択候補の成功結果
	result.succeeded			  = true ;
	result.downloadOutcome		  = OutcomeCode::SUCCESS ;
	result.installOutcome		  = OutcomeCode::SUCCESS ;
	result.restorePointProtection = providerProtection ;
	result.updates.reserve( identities.size()) ;

	// 入力順を維持して全候補の成功結果を作成する
	for( const std::wstring &identity : identities) {
		result.updates.push_back( {.identity		   = identity,
								  .downloadOutcome = OutcomeCode::SUCCESS,
								  .installOutcome  = OutcomeCode::SUCCESS}) ;
	}

	return result ;
}

//------------------------------------------------------------------------------
// 内部試験関数定義
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 復元ポイントで囲んだ正常install結果を検証する
 *
 * Begin、Provider、Completeが一回ずつ成功し結果へ記録されることを検証する
 *
 * @param[in,out] context assertion集計先
 */
//------------------------------------------------------------------------------
void testSuccessfulProtectedInstall( TestContext &context)
{
	FakeUpdateProvider			   provider ;								// 成功Provider fake
	FakeRestorePointService		   restoreService ;							// 成功復元ポイントfake
	const std::array			   identities{std::wstring( L"driver-a")} ;	// 選択候補
	std::vector<ProviderProgress>  progressEvents ;							// 保護付きoperationが通知した進捗列
	const ProviderProgressCallback callback = [&progressEvents]( const ProviderProgress &progress) {
		progressEvents.push_back( progress) ;
	} ; // 進捗通知を記録するcallback

	const InstallResult result =
		installWithRestorePoint( provider, restoreService, 1, identities, 0, callback,
								L"DriverCrate test") ;	// 保護付き実行結果
	DRIVERCRATE_EXPECT( context, result.succeeded) ;
	DRIVERCRATE_EXPECT( context, provider.installCount == 1) ;
	DRIVERCRATE_EXPECT( context, restoreService.beginCount == 1) ;
	DRIVERCRATE_EXPECT( context, restoreService.completeCount == 1) ;
	DRIVERCRATE_EXPECT( context, result.restorePointCreation.outcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, result.restorePointCompletion.outcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, !progressEvents.empty()) ;
	DRIVERCRATE_EXPECT( context,
					   progressEvents.front().stage == ProviderStage::VERIFYING_RESTORE_POINT) ;
	DRIVERCRATE_EXPECT( context,
					   progressEvents.back().stage == ProviderStage::FINALIZING_RESTORE_POINT) ;
	DRIVERCRATE_EXPECT( context, progressEvents.back().percentComplete == 100) ;
	std::uint32_t previousPercentage{} ;	// 単調増加を比較する直前の全体完了率
	// 保護付きoperationの全進捗が0～100で後退しないことを検証する
	for( const ProviderProgress &progress : progressEvents) {
		DRIVERCRATE_EXPECT( context, progress.percentComplete >= previousPercentage) ;
		DRIVERCRATE_EXPECT( context, progress.percentComplete <= 100) ;
		previousPercentage = progress.percentComplete ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 復元ポイント開始失敗時のfail-closed動作を検証する
 *
 * Begin失敗時はProviderとCompleteを呼ばず全候補を未開始で返すことを検証する
 *
 * @param[in,out] context assertion集計先
 */
//------------------------------------------------------------------------------
void testRestorePointCreationFailure( TestContext &context)
{
	FakeUpdateProvider		provider ;			// 呼ばれてはならないProvider fake
	FakeRestorePointService restoreService ;	// Begin失敗を返すfake
	restoreService.beginResult = {.outcome = OutcomeCode::FAILURE, .error = 5} ;
	const std::array			   identities{std::wstring( L"driver-a")} ;	// 選択候補
	const ProviderProgressCallback callback = []( const ProviderProgress &progress) {
		static_cast<void>( progress) ;
	} ; // 進捗通知を受理するcallback

	const InstallResult result =
		installWithRestorePoint( provider, restoreService, 1, identities, 0, callback,
								L"DriverCrate test") ;	// Fail-closed結果
	DRIVERCRATE_EXPECT( context, !result.succeeded) ;
	DRIVERCRATE_EXPECT( context, provider.installCount == 0) ;
	DRIVERCRATE_EXPECT( context, restoreService.completeCount == 0) ;
	DRIVERCRATE_EXPECT( context, result.updates.size() == identities.size()) ;
	DRIVERCRATE_EXPECT( context, result.updates[0].downloadOutcome == OutcomeCode::NOT_STARTED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 復元ポイント終了失敗を全体失敗へ反映することを検証する
 *
 * Provider成功を保持しつつ、Complete失敗を全体成功として表示しないことを検証する
 *
 * @param[in,out] context assertion集計先
 */
//------------------------------------------------------------------------------
void testRestorePointCompletionFailure( TestContext &context)
{
	FakeUpdateProvider		provider ;			// 成功Provider fake
	FakeRestorePointService restoreService ;	// Complete失敗を返すfake
	restoreService.completeResult = {.outcome = OutcomeCode::FAILURE, .error = 6} ;
	const std::array			   identities{std::wstring( L"driver-a")} ;	// 選択候補
	const ProviderProgressCallback callback = []( const ProviderProgress &progress) {
		static_cast<void>( progress) ;
	} ; // 進捗通知を受理するcallback

	const InstallResult result =
		installWithRestorePoint( provider, restoreService, 1, identities, 0, callback,
								L"DriverCrate test") ;	// 終了失敗付き結果
	DRIVERCRATE_EXPECT( context, !result.succeeded) ;
	DRIVERCRATE_EXPECT( context, restoreService.completeCount == 1) ;
	DRIVERCRATE_EXPECT( context, result.updates[0].installOutcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, result.restorePointCompletion.outcome == OutcomeCode::FAILURE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider例外時にも復元ポイントを終了することを検証する
 *
 * Provider例外を失敗結果へ変換し、開始済み復元ポイントへのCompleteを一回実行することを検証する
 *
 * @param[in,out] context assertion集計先
 */
//------------------------------------------------------------------------------
void testProviderExceptionCompletesRestorePoint( TestContext &context)
{
	FakeUpdateProvider provider ;	// 例外を送出するProvider fake
	provider.throwOnInstall = true ;
	FakeRestorePointService		   restoreService ;							// 成功復元ポイントfake
	const std::array			   identities{std::wstring( L"driver-a")} ;	// 選択候補
	const ProviderProgressCallback callback = []( const ProviderProgress &progress) {
		static_cast<void>( progress) ;
	} ; // 進捗通知を受理するcallback

	const InstallResult result =
		installWithRestorePoint( provider, restoreService, 1, identities, 0, callback,
								L"DriverCrate test") ;	// 例外変換後の結果
	DRIVERCRATE_EXPECT( context, !result.succeeded) ;
	DRIVERCRATE_EXPECT( context, restoreService.completeCount == 1) ;
	DRIVERCRATE_EXPECT( context, result.downloadOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, result.restorePointCompletion.outcome == OutcomeCode::SUCCESS) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows Server専用installが復元ポイントを要求しないことを検証する
 *
 * Server専用関数がProviderを実行し、復元ポイント結果をNotStartedのまま保持することを検証する
 *
 * @param[in,out] context assertion集計先
 */
//------------------------------------------------------------------------------
void testServerInstallWithoutRestorePoint( TestContext &context)
{
	FakeUpdateProvider provider ;	// 成功Provider fake
	provider.providerProtection = {.disposition		  = RestorePointDisposition::NEW_POINT_VERIFIED,
								   .verification	  = OutcomeCode::SUCCESS,
								   .sequenceNumber	  = 70,
								   .createdUtc		  = 1,
								   .localDay		  = 20261110U,
								   .verifiedBefore	  = true,
								   .verifiedAfter	  = true,
								   .nativeBeginCalled = true,
								   .nativeEndCalled	  = true} ;
	const std::array			   identities{std::wstring( L"driver-a")} ;	// 選択候補
	std::vector<ProviderProgress>  progressEvents ;							// Providerが通知した進捗列
	const ProviderProgressCallback callback = [&progressEvents]( const ProviderProgress &progress) {
		progressEvents.push_back( progress) ;
	} ; // 進捗通知を記録するcallback

	const InstallResult result = installWithoutRestorePointOnServer( provider, 1, identities, 0,
																	callback) ;	// Server専用実行結果
	DRIVERCRATE_EXPECT( context, result.succeeded) ;
	DRIVERCRATE_EXPECT( context, provider.installCount == 1) ;
	DRIVERCRATE_EXPECT( context, result.protectionMode ==
									InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT) ;
	DRIVERCRATE_EXPECT( context, result.restorePointCreation.outcome == OutcomeCode::NOT_STARTED) ;
	DRIVERCRATE_EXPECT( context, result.restorePointCompletion.outcome == OutcomeCode::NOT_STARTED) ;
	DRIVERCRATE_EXPECT( context, progressEvents.size() == 2) ;
	DRIVERCRATE_EXPECT( context, progressEvents.front().stage == ProviderStage::DOWNLOADING) ;
	DRIVERCRATE_EXPECT( context, progressEvents.back().stage == ProviderStage::INSTALLING) ;
	DRIVERCRATE_EXPECT( context,
					   isRestorePointProtectionValid( result) &&
						   result.restorePointProtection.verification == OutcomeCode::NOT_STARTED &&
						   !result.restorePointProtection.nativeBeginCalled &&
						   !result.restorePointProtection.nativeEndCalled) ;
	auto forged										= result ;	// Serverの未実行を捏造するDTOだけです
	forged.restorePointProtection.nativeBeginCalled = true ;
	DRIVERCRATE_EXPECT( context, !isRestorePointProtectionValid( forged)) ;
	forged.restorePointProtection.nativeBeginCalled = false ;
	forged.restorePointProtection.nativeEndCalled	= true ;
	DRIVERCRATE_EXPECT( context, !isRestorePointProtectionValid( forged)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows Server専用installのProvider例外変換を検証する
 *
 * 復元ポイントなし経路でもProvider例外を結果へ変換し、Server専用modeを失わないことを検証する
 *
 * @param[in,out] context assertion集計先
 */
//------------------------------------------------------------------------------
void testServerProviderException( TestContext &context)
{
	FakeUpdateProvider provider ;	// 例外を送出するProvider fake
	provider.throwOnInstall = true ;
	const std::array			   identities{std::wstring( L"driver-a")} ;	// 選択候補
	const ProviderProgressCallback callback = []( const ProviderProgress &progress) {
		static_cast<void>( progress) ;
	} ; // 進捗通知を受理するcallback

	// Fake ProviderをServer保護modeで実行した結果。実復元ポイントや導入は行わない
	const InstallResult result =
		installWithoutRestorePointOnServer( provider, 1, identities, 0, callback) ;
	DRIVERCRATE_EXPECT( context, !result.succeeded) ;
	DRIVERCRATE_EXPECT( context, provider.installCount == 1) ;
	DRIVERCRATE_EXPECT( context, result.protectionMode ==
									InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT) ;
	DRIVERCRATE_EXPECT( context, result.downloadOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, result.restorePointCreation.outcome == OutcomeCode::NOT_STARTED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief OS種別ごとのinstall保護方針を検証する
 *
 * Clientの復元ポイント回避とServerの非support API使用を許可しないpolicy matrixを検証する
 *
 * @param[in,out] context assertion集計先
 */
//------------------------------------------------------------------------------
void testInstallProtectionPolicy( TestContext &context)
{
	DRIVERCRATE_EXPECT( context, isInstallProtectionModeAllowed(
									false, InstallProtectionMode::WINDOWS_RESTORE_POINT)) ;
	DRIVERCRATE_EXPECT( context, !isInstallProtectionModeAllowed(
									false, InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT)) ;
	DRIVERCRATE_EXPECT( context, !isInstallProtectionModeAllowed(
									true, InstallProtectionMode::WINDOWS_RESTORE_POINT)) ;
	DRIVERCRATE_EXPECT( context, isInstallProtectionModeAllowed(
									true, InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT)) ;
	DRIVERCRATE_EXPECT(
		context, !isInstallProtectionModeAllowed( true, static_cast<InstallProtectionMode>( 999))) ;
}

/** @brief 日内保護の完全fakeだけを共有し、本番WMI/時計/メモへfallbackしません */
struct DailyRestoreFixture {
	/// 固定UTCとlocal日付です
	restore_point_detail::Clock				 now{2000000000LL, 20330518U} ;
	/// Windows一覧の代わりとなる所有pointです
	std::vector<restore_point_detail::Point> points ;
	/// 一件の不変原時刻memoです
	RestorePointDayMemo						 memo ;
	/// 実native APIの代替callback回数です
	unsigned								 begins{} ;
	/// 実native ENDの代替回数です
	unsigned								 ends{} ;
	/// WMIの代替callback回数です
	unsigned								 queries{} ;
	/// 既排他の代わりに同scopeだけ所有します
	bool									 locked{} ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief 必須callbackを全て明示する復元fakeを構築します
 * @param[in] state 同fixture寿命の所有状態です
 * @return production fallbackのない完全表です
 */
//------------------------------------------------------------------------------
restore_point_detail::Calls dailyRestoreCalls( std::shared_ptr<DailyRestoreFixture> state)
{
	restore_point_detail::Calls calls ;	// 全fieldを明示します
	calls.clock	 = [state] { return state->now ; } ;
	calls.points = [state]( auto &points) {
		++state->queries ;
		points = state->points ;
		return NativeError{} ;
	} ;
	calls.begin = [state]( auto) {
		++state->begins ;
		// 前回と重ならないfake sequenceを発行します
		const auto sequence =
			state->points.empty()
				? 70LL
				: std::ranges::max( state->points, {}, &restore_point_detail::Point::sequenceNumber)
						  .sequenceNumber +
					  1 ;
		state->points.push_back( {sequence, state->now.utc}) ;
		return RestorePointOperationResult{.outcome		   = OutcomeCode::SUCCESS,
										   .sequenceNumber = sequence} ;
	} ;
	calls.end = [state]( auto sequence) {
		++state->ends ;
		return RestorePointOperationResult{.outcome		   = OutcomeCode::SUCCESS,
										   .sequenceNumber = sequence} ;
	} ;
	calls.lock = [state]( auto &lease) {
		// 同じfake排他を並行取得できないことを確認します
		if( state->locked) {
			return static_cast<NativeError>( 0x80070020U) ;
		}

		state->locked = true ;
		lease		  = std::shared_ptr<void>( new int{}, [state]( void *value) {
			delete static_cast<int *>( value) ;
			state->locked = false ;
		}) ;
		return NativeError{} ;
	} ;
	calls.loadMemo = [state]( auto &memo) {
		memo = state->memo ;
		return NativeError{} ;
	} ;
	calls.saveMemo = [state]( const auto &memo) {
		state->memo = memo ;
		return NativeError{} ;
	} ;
	return calls ;
}
//------------------------------------------------------------------------------
/**
 * @brief 初回/同日二操作/再起動相当の原point再利用を製品保護経路で確認します
 * @param[in,out] context 原assertion集計先です
 */
//------------------------------------------------------------------------------
void testDailyRestorePositive( TestContext &context)
{
	auto state = std::make_shared<DailyRestoreFixture>() ;	// 本番stateを読みません
	auto service =
		// 完全fakeだけです
		restore_point_detail::createFixture( dailyRestoreCalls( state)) ;
	FakeUpdateProvider			   provider ;								// 実driverを呼びません
	const std::array			   ids{std::wstring( L"daily-update")} ;	// 架空な一対象です
	const ProviderProgressCallback progress = []( const auto &) {} ;		// 同期の有限通知です
	DRIVERCRATE_EXPECT( context, service != nullptr) ;
	// 不完全fixtureを実サービスへ置き換えません
	if( !service) {
		return ;
	}

	const auto first = installWithRestorePoint( provider, *service, 1U, ids, 0U, progress,
											   L"fixture") ;	// 初回準備です
	DRIVERCRATE_EXPECT( context, first.succeeded && isRestorePointProtectionValid( first)) ;
	DRIVERCRATE_EXPECT( context, first.restorePointProtection.disposition ==
										RestorePointDisposition::NEW_POINT_VERIFIED &&
									first.restorePointCreation.outcome == OutcomeCode::SUCCESS &&
									first.restorePointCompletion.outcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, state->begins == 1U && state->ends == 1U &&
									state->memo.sequenceNumber == 70 && !state->locked) ;
	const auto created	= state->memo.createdUtc ;	// 再利用で書き換えない原時刻です
	const auto prepared = state->memo.preparedUtc ;	// 初回正常準備時刻です
	++state->now.utc ;
	const auto second = installWithRestorePoint( provider, *service, 1U, ids, 0U, progress,
												L"fixture") ;	// 同日明示二回目です
	DRIVERCRATE_EXPECT( context, second.succeeded && isRestorePointProtectionValid( second)) ;
	DRIVERCRATE_EXPECT( context,
					   second.restorePointProtection.disposition ==
							   RestorePointDisposition::SAME_DAY_REUSED &&
						   second.restorePointCreation.outcome == OutcomeCode::NOT_STARTED &&
						   second.restorePointCompletion.outcome == OutcomeCode::NOT_STARTED &&
						   !second.restorePointProtection.nativeBeginCalled &&
						   !second.restorePointProtection.nativeEndCalled) ;
	DRIVERCRATE_EXPECT( context, state->begins == 1U && state->ends == 1U &&
									state->memo.createdUtc == created &&
									state->memo.preparedUtc == prepared) ;
	service.reset() ;
	service =
		// 再起動相当の新objectです
		restore_point_detail::createFixture( dailyRestoreCalls( state)) ;
	const auto restarted = installWithRestorePoint( provider, *service, 1U, ids, 0U, progress,
												   L"fixture") ;	// 永続memoと実在の双方が必要です
	DRIVERCRATE_EXPECT( context,
					   restarted.succeeded && restarted.restorePointProtection.disposition ==
												  RestorePointDisposition::SAME_DAY_REUSED) ;
	DRIVERCRATE_EXPECT( context,
					   state->begins == 1U && state->ends == 1U && provider.installCount == 3) ;
	DRIVERCRATE_EXPECT( context, !restore_point_detail::createFixture( {})) ;
	std::cout << "DAILY_RESTORE first=1 sameDay=1 restart=1 nativeBegin=" << state->begins
			  << " nativeEnd=" << state->ends << " realRestore=0 realWMI=0 productionMemo=0\n" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 日内保護の有限16条件を完全fakeで確認します
 * @param[in,out] context 原assertionです
 */
//------------------------------------------------------------------------------
void testDailyRestoreBoundaries( TestContext &context)
{
	const std::array			   ids{std::wstring( L"daily-boundary")} ;	// 架空対象だけです
	const ProviderProgressCallback progress = []( const auto &) {} ;		// 実worker/Windowsを呼びません
	// 他の実在fieldが正常でも、旧/未知/未成立の区分ではProviderを呼びません
	for( const auto disposition :
		{RestorePointDisposition::UNAVAILABLE, static_cast<RestorePointDisposition>( 0x7fff),
		 RestorePointDisposition::NATIVE_TRANSACTION}) {
		FakeUpdateProvider		provider ;	// 実変更APIを持たないcounterです
		FakeRestorePointService service ;	// 受理したBEGINは元sequenceへEND一回を返します
		service.disposition = disposition ;
		const auto result	= installWithRestorePoint( provider, service, 1U, ids, 0U, progress,
													  L"fixture") ;	// Provider前の拒否です
		DRIVERCRATE_EXPECT( context,
						   !result.succeeded && provider.installCount == 0 &&
							   service.beginCount == 1 && service.completeCount == 1 &&
							   result.restorePointCreation.outcome == OutcomeCode::SUCCESS &&
							   result.restorePointCompletion.outcome == OutcomeCode::SUCCESS) ;
	}

	// 固定16条件を全て独立したfake状態で確認します
	for( unsigned variant = 0; variant < 16U; ++variant) {
		auto	   state	  = std::make_shared<DailyRestoreFixture>() ;	// 各ケースで独立所有します
		auto	   calls	  = dailyRestoreCalls( state) ;					// 常に完全fakeです
		const auto denied	  = static_cast<NativeError>( 0x80070005U) ;	// 固定拒否です
		const auto unexpected = static_cast<NativeError>( 0x8000FFFFU) ;	// 固定例外診断です
		// 一条件だけを変え元のnative counterと期待を維持します
		switch( variant) {
			case 0:	// 日替りの旧memoは再利用しません
				state->points = {{70, state->now.utc - 86400}} ;
				state->memo	  = {20330517U, 70, state->now.utc - 86400, state->now.utc - 86300} ;
				break ;

			case 1:	// OSが前日pointを返しても新規作成と偽りません
				state->points = {{70, state->now.utc - 46800}} ;
				calls.begin	  = [state]( auto) {
					  ++state->begins ;
					  return RestorePointOperationResult{.outcome		 = OutcomeCode::SUCCESS,
														 .sequenceNumber = 70} ;
				} ;
				break ;

			case 2:	// 正当な同日memoでもpoint消失は新規準備を要求します
				state->memo = {state->now.localDay, 70, state->now.utc - 3600,
							   state->now.utc - 3500} ;
				break ;

			case 3:	// 壊れたmemoはWindows実在の代替ではありません
				calls.loadMemo = []( auto &memo) {
					memo = {} ;
					return static_cast<NativeError>( 0x8007000DU) ;
				} ;
				break ;

			case 4:	// Memo読取拒否だけで実native準備を妨げません
				calls.loadMemo = [denied]( auto &memo) {
					memo = {} ;
					return denied ;
				} ;
				break ;

			case 5:	// 保存失敗だけで実導入成功を失敗へ改作しません
				calls.saveMemo = [denied]( const auto &) { return denied ; } ;
				break ;

			case 6:	// BEGIN失敗ではProviderもENDも呼びません
				calls.begin = [state, denied]( auto) {
					++state->begins ;
					return RestorePointOperationResult{.outcome = OutcomeCode::FAILURE,
													   .error	= denied} ;
				} ;
				break ;

			case 7:	// BEGIN後のpoint欠測でも元ENDを一回閉じます
				calls.points = [state]( auto &points) {
					++state->queries ;
					points = state->queries >= 2U ? std::vector<restore_point_detail::Point>{}
												  : state->points ;
					return NativeError{} ;
				} ;
				break ;

			case 8:	// END失敗は個別driver成功を保持したまま保護エラーです
				calls.end = [state, denied]( auto sequence) {
					++state->ends ;
					return RestorePointOperationResult{.outcome		   = OutcomeCode::FAILURE,
													   .error		   = denied,
													   .sequenceNumber = sequence} ;
				} ;
				break ;

			case 9:	// 明確な他operationのbusyだけを拒否します
				calls.lock = []( auto &lease) {
					lease.reset() ;
					return static_cast<NativeError>( 0x80070020U) ;
				} ;
				break ;

			case 10:	// Memo用lockのI/O拒否はnative準備へ進みます
				calls.lock = [denied]( auto &lease) {
					lease.reset() ;
					return denied ;
				} ;
				break ;

			case 11:	// 未来のpointは既存sequenceでも利用しません
				state->points = {{70, state->now.utc + 1}} ;
				calls.begin	  = [state]( auto) {
					  ++state->begins ;
					  return RestorePointOperationResult{.outcome		 = OutcomeCode::SUCCESS,
														 .sequenceNumber = 70} ;
				} ;
				break ;

			case 12:	// BEGIN後のWMI例外でもnative結果を改作せずEND一回です
				calls.points = [state]( auto &points) {
					++state->queries ;
					// 実BEGIN後の二回目一覧だけを例外にします
					if( state->queries == 2U) {
						throw std::runtime_error( "fake point read") ;
					}

					points = state->points ;
					return NativeError{} ;
				} ;
				break ;

			case 13:	// 保存例外も最適化の診断だけです
				calls.saveMemo = []( const auto &) -> NativeError {
					throw std::runtime_error( "fake memo save") ;
				} ;
				break ;

			case 14:	// Memo lock例外でもproduction fallbackせず明示fake nativeへ進みます
				calls.lock = []( auto &) -> NativeError {
					throw std::runtime_error( "fake memo lock") ;
				} ;
				break ;

			case 15:	// Windows一覧自体が読めなければ保護未成立です
				calls.points = [state, denied]( auto &points) {
					++state->queries ;
					points.clear() ;
					return denied ;
				} ;
				break ;
		}

		auto service =
			// 各profileを独立に検査します
			restore_point_detail::createFixture( std::move( calls)) ;
		FakeUpdateProvider provider ;	// 実導入API0です
		DRIVERCRATE_EXPECT( context, service != nullptr) ;
		// fixture生成失敗は失敗のまま後段を実行しません
		if( !service) {
			continue ;
		}

		const auto result	= installWithRestorePoint( provider, *service, 1U, ids, 0U, progress,
													  L"fixture") ;	// 元製品経路です
		const bool expected = variant <= 5U || variant == 10U || variant == 13U ||
							  // 保護が成立する固定集合です
							  variant == 14U ;
		DRIVERCRATE_EXPECT( context, result.succeeded == expected) ;
		const unsigned providers =
			expected || variant == 8U ? 1U : 0U ;	// END失敗でも実個別結果は保持します
		DRIVERCRATE_EXPECT( context, provider.installCount == static_cast<int>( providers)) ;
		DRIVERCRATE_EXPECT( context, state->begins == (variant == 9U || variant == 15U ? 0U : 1U)) ;
		DRIVERCRATE_EXPECT(
			context, state->ends == (variant == 6U || variant == 9U || variant == 15U ? 0U : 1U)) ;
		DRIVERCRATE_EXPECT( context, !state->locked) ;
		// 保護成立の正例だけが全結果検証も通ることを確認します
		if( expected) {
			DRIVERCRATE_EXPECT( context, isRestorePointProtectionValid( result)) ;
		}

		// OSが前日pointを返しても元作成時刻を保持します
		if( variant == 1U) {
			DRIVERCRATE_EXPECT( context, result.restorePointProtection.disposition ==
												RestorePointDisposition::WINDOWS_SELECTED_POINT &&
											result.restorePointProtection.createdUtc ==
												state->now.utc - 46800 &&
											state->memo.createdUtc == state->now.utc - 46800) ;
		}

		// メモの読書やlock I/O診断だけでdriver成功を変更しません
		if( variant == 3U || variant == 4U || variant == 5U || variant == 10U || variant == 13U ||
		   variant == 14U) {
			DRIVERCRATE_EXPECT( context,
							   result.restorePointProtection.memoError != 0 &&
								   result.updates.front().installOutcome == OutcomeCode::SUCCESS) ;
		}

		// 実BEGIN後の確認失敗でも元native成功とEND一回を保持します
		if( variant == 7U || variant == 12U) {
			DRIVERCRATE_EXPECT(
				context, result.restorePointCreation.outcome == OutcomeCode::SUCCESS &&
							 result.restorePointCompletion.outcome == OutcomeCode::SUCCESS &&
							 result.restorePointProtection.verification == OutcomeCode::FAILURE) ;
		}

		// END失敗で実導入成功を消さないことを確認します
		if( variant == 8U) {
			DRIVERCRATE_EXPECT( context,
							   result.updates.front().installOutcome == OutcomeCode::SUCCESS &&
								   result.restorePointCompletion.outcome == OutcomeCode::FAILURE &&
								   state->memo.sequenceNumber == 0) ;
		}

		// busyまたは実在不明の条件では変更APIを呼びません
		if( variant == 9U || variant == 15U) {
			DRIVERCRATE_EXPECT(
				context, result.restorePointCreation.outcome == OutcomeCode::NOT_STARTED &&
							 result.restorePointCompletion.outcome == OutcomeCode::NOT_STARTED) ;
		}

		// callback例外の元診断を非authorityメモの診断へ残します
		if( variant == 13U || variant == 14U) {
			DRIVERCRATE_EXPECT( context, result.restorePointProtection.memoError == unexpected) ;
		}

		std::cout << "DAILY_BOUNDARY case=" << variant << " begin=" << state->begins
				  << " end=" << state->ends << " provider=" << provider.installCount
				  << " succeeded=" << result.succeeded
				  << " realRestore=0 realWMI=0 productionMemo=0\n" ;
	}

	// 明示callbackの欠落を全七fieldで拒否します
	for( unsigned missing = 0; missing < 7U; ++missing) {
		auto state = std::make_shared<DailyRestoreFixture>() ;	// 本番stateなしです
		auto calls = dailyRestoreCalls( state) ;				// 一fieldだけ欠落させます
		// 一つ欠けたcallbackからも実APIへfallbackしないことを確認します
		switch( missing) {
			// 時計callbackの欠測を拒否します
			case 0:
				calls.clock = {} ;
				break ;

			// 実在一覧callbackの欠測を拒否します
			case 1:
				calls.points = {} ;
				break ;

			// native開始callbackの欠測を拒否します
			case 2:
				calls.begin = {} ;
				break ;

			// native終了callbackの欠測を拒否します
			case 3:
				calls.end = {} ;
				break ;

			// 排他callbackの欠測を拒否します
			case 4:
				calls.lock = {} ;
				break ;

			// メモ読取callbackの欠測を拒否します
			case 5:
				calls.loadMemo = {} ;
				break ;

			// メモ保存callbackの欠測を拒否します
			case 6:
				calls.saveMemo = {} ;
				break ;
		}

		DRIVERCRATE_EXPECT( context, !restore_point_detail::createFixture( std::move( calls)) &&
										state->begins == 0U && state->ends == 0U &&
										state->queries == 0U && !state->locked) ;
	}

	// bare成功と実行済みnativeを装う偽reuseを拒否します
	InstallResult forged ;	// 外部操作を行わないvalidator入力です
	forged.restorePointCreation	  = {.outcome = OutcomeCode::SUCCESS, .sequenceNumber = 70} ;
	forged.restorePointCompletion = {.outcome = OutcomeCode::SUCCESS, .sequenceNumber = 70} ;
	DRIVERCRATE_EXPECT( context, !isRestorePointProtectionValid( forged)) ;
	forged.restorePointProtection = {.disposition	 = RestorePointDisposition::SAME_DAY_REUSED,
									 .verification	 = OutcomeCode::SUCCESS,
									 .sequenceNumber = 70,
									 .createdUtc	 = 1,
									 .localDay		 = 20261110U,
									 .verifiedBefore = true,
									 .verifiedAfter	 = true} ;
	DRIVERCRATE_EXPECT( context, !isRestorePointProtectionValid( forged)) ;
	forged.restorePointCreation					 = {} ;
	forged.restorePointCompletion				 = {} ;
	forged.restorePointProtection.verifiedBefore = false ;
	DRIVERCRATE_EXPECT( context, !isRestorePointProtectionValid( forged)) ;
	// 同一pointの元scope中は別serviceの実排他を受理しません
	auto parallel = std::make_shared<DailyRestoreFixture>() ;								// fake排他を二serviceで共有します
	auto first	  = restore_point_detail::createFixture( dailyRestoreCalls( parallel)) ;	// 元ownerです
	auto second	  = restore_point_detail::createFixture( dailyRestoreCalls( parallel)) ;	// 別操作です
	const auto		   begun = first->begin( L"fixture") ;									// Provider前の保護scopeだけを保持します
	FakeUpdateProvider provider ;															// busyなら呼ばれません
	const auto		   busy = installWithRestorePoint( provider, *second, 1U, ids, 0U, progress,
													  L"fixture") ;	// blind retryなしです
	DRIVERCRATE_EXPECT( context, !busy.succeeded && provider.installCount == 0 &&
									parallel->begins == 1U && parallel->ends == 0U) ;
	DRIVERCRATE_EXPECT( context,
					   first->complete( begun.sequenceNumber).outcome == OutcomeCode::SUCCESS &&
						   parallel->ends == 1U && !parallel->locked) ;
	DRIVERCRATE_EXPECT( context,
					   first->complete( begun.sequenceNumber).outcome == OutcomeCode::FAILURE &&
						   parallel->ends == 1U) ;
	// UTC逆行は同serviceの既観測下限へ照合します
	auto clock	 = std::make_shared<DailyRestoreFixture>() ;							// 環境clockを変更しません
	auto service = restore_point_detail::createFixture( dailyRestoreCalls( clock)) ;	// 独立scopeです
	const auto initial = installWithRestorePoint( provider, *service, 1U, ids, 0U, progress,
												 L"fixture") ;	// 正の元結果です
	--clock->now.utc ;
	const auto rollback = installWithRestorePoint( provider, *service, 1U, ids, 0U, progress,
												  L"fixture") ;	// 新たな結果だけが未成立です
	DRIVERCRATE_EXPECT( context, initial.succeeded && !rollback.succeeded &&
									provider.installCount == 1 && clock->begins == 1U &&
									clock->ends == 1U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 明示所有した私有fixture rootだけで固定memoのbyteと排他を確認します
 * @param[in,out] context 元assertionの集計先です
 * @note ProgramData/実WMI/復元APIを使いません。削除は既存temp親の新規所有した一意leafだけです
 */
//------------------------------------------------------------------------------
void testDailyRestoreMemoFiles( TestContext &context)
{
	std::error_code error ;	// Cwdや共有outの存在に依存しない既存temp親の照会結果です
	auto			parent =
		// 変更しない許可親です
		std::filesystem::temp_directory_path( error).lexically_normal() ;
	// Windows tempの末尾separatorだけを除き、同じ親とのpath比較を安定させます
	if( parent.filename().empty()) {
		parent = parent.parent_path() ;
	}

	const bool parentReady = !error && parent.is_absolute() &&
							 std::filesystem::is_directory( parent, error) &&
							 !error ;	// 不明な親を新規作成しません
	DRIVERCRATE_EXPECT( context, parentReady) ;
	// 親不明を別folder作成や既存root利用へ補いません
	if( !parentReady) {
		return ;
	}

	const auto root =
		(parent / (L"daily-restore-fixture-" + std::to_wstring( GetCurrentProcessId()) + L"-" +
				   std::to_wstring( GetTickCount64())))
			.lexically_normal() ;	// この試験だけが新規所有します
	const bool owned = root.parent_path() == parent &&
					   // 既存rootへ書込みません
					   std::filesystem::create_directory( root) ;
	DRIVERCRATE_EXPECT( context, owned) ;
	// 新規所有できなければ既存rootへ触りません
	if( !owned) {
		return ;
	}

	OfficialReleaseObservationStore store( root.wstring()) ;	// 非productionの明示rootです
	std::shared_ptr<void>			first ;						// 実file排他のscopeです
	std::shared_ptr<void>			second ;					// 並行要求は成功へ補完しません
	DRIVERCRATE_EXPECT( context, store.lockDailyRestoreMemo( first) == 0 && first) ;
	DRIVERCRATE_EXPECT( context, store.lockDailyRestoreMemo( second) != 0 && !second) ;
	first.reset() ;
	DRIVERCRATE_EXPECT( context, store.lockDailyRestoreMemo( second) == 0 && second) ;
	RestorePointDayMemo read ;	// 不在はreuse根拠なしです
	DRIVERCRATE_EXPECT( context, store.loadDailyRestoreMemo( read) == 0 && read.sequenceNumber == 0) ;
	const RestorePointDayMemo memo{20261110U, 70, 2000000000LL - 30,
								   2000000000LL} ;	// 原時刻を再発行しません
	DRIVERCRATE_EXPECT( context, store.storeDailyRestoreMemo( memo) == 0) ;
	DRIVERCRATE_EXPECT(
		context, store.loadDailyRestoreMemo( read) == 0 && read.localDay == memo.localDay &&
					 read.sequenceNumber == memo.sequenceNumber &&
					 read.createdUtc == memo.createdUtc && read.preparedUtc == memo.preparedUtc) ;
	const auto		  path = root / L"restore-day.memo" ;	// 固定file以外をmemoにしません
	std::ifstream	  input( path, std::ios::binary) ;		// 原byteを保全します
	const std::string original{std::istreambuf_iterator<char>( input),
							   std::istreambuf_iterator<char>()} ;	// 72byteだけです
	input.close() ;
	DRIVERCRATE_EXPECT( context, original.size() == 72U) ;
	{
		std::fstream corrupt( path, std::ios::binary | std::ios::in |
									   std::ios::out) ;	// 自分のfixtureだけを一byte変えます
		corrupt.put( 'X') ;
	}
	DRIVERCRATE_EXPECT( context, store.loadDailyRestoreMemo( read) != 0 && read.sequenceNumber == 0 &&
									store.storeDailyRestoreMemo( memo) != 0) ;
	{
		std::ifstream corrupt( path, std::ios::binary) ;	// 不正原byteが残ることを確認します
		DRIVERCRATE_EXPECT( context, corrupt.get() == 'X') ;
	}
	{
		std::ofstream restore( path, std::ios::binary |
										std::ios::trunc) ;	// 自分が保全した原byteだけを戻します
		restore.write( original.data(), static_cast<std::streamsize>( original.size())) ;
	}
	{
		std::ofstream stage( root / L"restore-day.stage",
							std::ios::binary) ;	// 未所有stageの代替入力です
		stage << "keep" ;
	}
	DRIVERCRATE_EXPECT( context, store.storeDailyRestoreMemo( memo) != 0 &&
									std::filesystem::file_size( root / L"restore-day.stage") == 4U &&
									store.loadDailyRestoreMemo( read) == 0 &&
									read.sequenceNumber == memo.sequenceNumber) ;
	second.reset() ;
	// 解決済み絶対pathはtemp親の今回新規所有rootだけです
	DRIVERCRATE_EXPECT( context,
					   root.parent_path() == parent && std::filesystem::remove_all( root) > 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実共通保護停止/原所有から一回だけのclient明示続行を確認します
 * @param[in,out] context 元assertion集計です
 * @note Provider/復元serviceは既完全fakeであり実driver/復元/通信は0です
 */
//------------------------------------------------------------------------------
void testExplicitRestoreContinuation( TestContext &context)
{
	const std::array<std::wstring, 2> identities{L"fictional-a", L"fictional-b"} ;	// 完全元選択です
	const ProviderProgressCallback	  progress = []( const auto &) {} ;				// 進捗は導入許可にしません
	// 元BEGIN/所有END/取消し等の固定した八条件だけを共通処理へ通します
	for( unsigned mode{}; mode < 8U; ++mode) {
		FakeUpdateProvider		provider ;							// 呼出回数は実共通wrapperで数えます
		FakeRestorePointService restore ;							// 既復元fakeだけです
		const bool				owned = mode == 2U || mode == 3U ;	// Provider前実在確認失敗です
		// 所有済みBEGIN後だけENDの成功/失敗を合成します
		if( owned) {
			restore.beforeVerificationError = static_cast<NativeError>( 0x80070490U) ;
			// END失敗へ復元なし再導入を提示しません
			if( mode == 3U) {
				restore.completeResult = {.outcome = OutcomeCode::FAILURE,
										  .error   = static_cast<NativeError>( 0x80070005U)} ;
			}
		} else {
			const std::array<NativeError, 8> errors{
				static_cast<NativeError>( 0x80070422U), static_cast<NativeError>( 0x80070490U), 0U,
				0U, static_cast<NativeError>( 0x800704C7U), static_cast<NativeError>( 0x80070576U),
				static_cast<NativeError>( 0x800700AAU),
				// 原数値を置換しません
				static_cast<NativeError>( 0x8000FFFFU)} ;
			restore.beginResult = {.outcome = OutcomeCode::FAILURE, .error = errors[mode]} ;
		}

		const auto failed = installWithRestorePoint( provider, restore, 7U, identities, 0U, progress,
													L"fixture") ;	// 実共通Provider前停止です
		DRIVERCRATE_EXPECT( context,
						   provider.installCount == 0 && failed.restoreStoppedBeforeProvider) ;
		DRIVERCRATE_EXPECT( context,
						   restore.beginCount == 1 && restore.completeCount == (owned ? 1 : 0)) ;
		InstallRetentionSummary retained{
			.operationId   = 2U,
			.scanSessionId = 7U,
			.candidates	   = {{identities[0], L"device-a"},
							  {identities[1], L"device-b"}}} ;	// 元所有だけです
		RestoreContinuation pending ;							// 製品と同じ短命状態です
		const bool			eligible = mode < 3U ;				// 422/490と所有END成功だけです
		DRIVERCRATE_EXPECT( context,
						   pending.offer( 2U, 7U, identities, failed, &retained) == eligible) ;
		DRIVERCRATE_EXPECT( context, pending.matches( 2U, 7U, identities) == eligible) ;
		// 対象外は状態を保持せずProviderへ到達しません
		if( !eligible) {
			DRIVERCRATE_EXPECT( context, !pending.consume( 2U, 7U, identities)) ;
			continue ;
		}

		const auto original = pending.consume( 2U, 7U, identities) ;	// 一回消費する原保護errorです
		DRIVERCRATE_EXPECT( context, original && !pending.consume( 2U, 7U, identities)) ;
		const auto continued = installExplicitlyWithoutRestorePoint(
			provider, 7U, identities, 0U, progress, 2U,
			*original) ;	// 復元serviceを渡さない実共通導入経路です
		DRIVERCRATE_EXPECT( context, provider.installCount == 1 && continued.succeeded &&
										continued.restoreFailureOperationId == 2U &&
										continued.restoreFailureError == *original) ;
		DRIVERCRATE_EXPECT( context,
						   restore.beginCount == 1 && restore.completeCount == (owned ? 1 : 0)) ;
		DRIVERCRATE_EXPECT( context, isExplicitNoRestoreResultValid( continued, 2U, *original) &&
										!isRestorePointProtectionValid( continued)) ;
		DRIVERCRATE_EXPECT( context, failed.restorePointCreation.error ==
										(owned ? NativeError{} : *original)) ;
		// 元失敗/原保持のどの改変も提示へ昇格させません
		for( unsigned mutation{}; mutation < 9U; ++mutation) {
			auto changed = failed ;		// 原結果は変更しません
			auto owner	 = retained ;	// 原ownerは変更しません
			// 一つの拒否境界ずつ変更し、期待を保ちます
			switch( mutation) {
				// Provider入口到達後は個別NOT_STARTEDでも拒否します
				case 0:
					owner.providerEntered = true ;
					break ;

				// 別操作の所有票は拒否します
				case 1:
					owner.operationId = 99U ;
					break ;

				// 別scanの所有票は拒否します
				case 2:
					owner.scanSessionId = 99U ;
					break ;

				// 元選択の一件を失った場合は拒否します
				case 3:
					owner.candidates.pop_back() ;
					break ;

				// 公開DTOだけの自己申告では提示しません
				case 4:
					changed.restoreStoppedBeforeProvider = false ;
					break ;

				// 取得開始の事実があれば拒否します
				case 5:
					changed.updates[0].downloadOutcome = OutcomeCode::FAILURE ;
					break ;

				// Server modeへ偽装しません
				case 6:
					changed.protectionMode = InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT ;
					break ;

				// 未分類scopeを拒否します
				case 7:
					changed.restorePointProtection.disposition =
						static_cast<RestorePointDisposition>( 99) ;
					break ;

				// 重複したownerは全件保持を証明しません
				case 8:
					owner.candidates.push_back( owner.candidates.front()) ;
					break ;
			}

			DRIVERCRATE_EXPECT( context, !pending.offer( 2U, 7U, identities, changed, &owner)) ;
		}
	}

	// UIの既定/close/Esc/TaskDialog失敗を同じ純粋判定へ通します
	DRIVERCRATE_EXPECT(
		context, !isRestoreContinuationChoiceConfirmed( 0U, 2) &&
					 !isRestoreContinuationChoiceConfirmed( 0U, 0) &&
					 !isRestoreContinuationChoiceConfirmed( static_cast<NativeError>( 0x80004005U),
														   RESTORE_CONTINUATION_BUTTON_ID) &&
					 isRestoreContinuationChoiceConfirmed( 0U, RESTORE_CONTINUATION_BUTTON_ID)) ;
	DRIVERCRATE_EXPECT( context,
					   isInstallProtectionModeAllowed(
						   false, InstallProtectionMode::CLIENT_EXPLICIT_WITHOUT_RESTORE_POINT) &&
						   !isInstallProtectionModeAllowed(
							   true, InstallProtectionMode::CLIENT_EXPLICIT_WITHOUT_RESTORE_POINT)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実controllerの原失敗終端からfresh一回判断と拒否を検証します
 * @param[in,out] context 元assertion集計です
 */
//------------------------------------------------------------------------------
void testRestoreContinuationController( TestContext &context)
{
	const std::array<std::wstring, 2> identities{L"fictional-a", L"fictional-b"} ;	// 完全元選択です
	// 正例と旧判断/別選択/別scan/取消し/終了/新operationの有限境界です
	for( unsigned mode{}; mode < 9U; ++mode) {
		OperationController controller ;					// 製品と同じ状態機械です
		const auto			scan = controller.beginScan() ;	// 新scanだけを発行します
		// 原scanの二候補だけを示す終端です
		ScanResult			result{
					 .succeeded = true, .scanSessionId = 7U, .outcome = OutcomeCode::SUCCEEDED_WITH_ERRORS} ;
		// 既scanに表示された二候補だけを許可します
		for( const auto &id : identities) {
			result.candidates.push_back(
				{.identity = id, .deviceIdentity = L"device-" + id, .installable = true}) ;
		}

		DRIVERCRATE_EXPECT( context, controller.completeScan( scan.operationId, result)) ;
		// 元controllerが発行した導入操作です
		const auto begin = controller.beginInstall( 7U, identities, InstallConfirmation::CONFIRMED) ;
		DRIVERCRATE_EXPECT( context, begin.accepted) ;
		FakeUpdateProvider		provider ;	// 導入未開始の元失敗を共通保護処理で作ります
		FakeRestorePointService restore ;	// 失敗BEGINはEND0です
		restore.beginResult = {.outcome = OutcomeCode::FAILURE,
							   .error	= static_cast<NativeError>( 0x80070422U)} ;
		// 共通保護処理の実Provider前停止です
		const auto failed = installWithRestorePoint(
			provider, restore, 7U, identities, 0U, []( const auto &) {}, L"fixture") ;
		// 原選択全件だけの元所有証明です
		InstallRetentionSummary retained{
			.operationId   = begin.operationId,
			.scanSessionId = 7U,
			.candidates	   = {{identities[0], L"device-" + identities[0]},
							  {identities[1], L"device-" + identities[1]}}} ;
		DRIVERCRATE_EXPECT( context,
						   controller.completeInstall( begin.operationId, failed, &retained, true)) ;
		DRIVERCRATE_EXPECT( context,
						   controller.canContinueWithoutRestore( begin.operationId, identities)) ;
		// 非導入の別動作/取消しは元提示を失効させます
		if( mode == 4U) {
			controller.discardRestoreContinuation() ;
		}

		// 当該一回の原scopeを維持して、この拒否条件だけを検証します
		if( mode == 5U) {
			controller.stop() ;
		}

		// 当該一回の原scopeを維持して、この拒否条件だけを検証します
		if( mode == 6U) {
			static_cast<void>( controller.beginScan()) ;
		}

		// 当該一回の原scopeを維持して、この拒否条件だけを検証します
		if( mode == 7U) {
			// 別操作による提示失効を確認する空要求です
			OfficialPreparationApproval empty ;
			static_cast<void>( controller.beginPreparation( empty)) ;
		}

		// 当該一回の原scopeを維持して、この拒否条件だけを検証します
		if( mode == 8U) {
			static_cast<void>(
				controller.beginInstall( 7U, identities, InstallConfirmation::NOT_CONFIRMED)) ;
		}

		const auto selected =
			mode == 1U ? std::span<const std::wstring>( identities).first( 1U)
					   : std::span<const std::wstring>( identities) ;	// 変更選択を旧判断へ足しません
		// 原失敗の一回判断を消費する新operationです
		const auto continued = controller.beginInstall(
			mode == 2U ? 99U : 7U, selected,
			mode == 3U ? InstallConfirmation::NOT_CONFIRMED : InstallConfirmation::CONFIRMED,
			InstallProtectionMode::CLIENT_EXPLICIT_WITHOUT_RESTORE_POINT, begin.operationId) ;
		DRIVERCRATE_EXPECT( context, continued.accepted == (mode == 0U)) ;
		// 再送や拒否後の復活は許しません
		if( mode != 0U) {
			DRIVERCRATE_EXPECT(
				context, !controller.canContinueWithoutRestore( begin.operationId, identities)) ;
			continue ;
		}

		DRIVERCRATE_EXPECT( context,
						   continued.operationId > begin.operationId && provider.installCount == 0) ;
		// 当該明示modeの個別実結果です
		const auto installed = installExplicitlyWithoutRestorePoint(
			provider, 7U, identities, 0U, []( const auto &) {}, begin.operationId,
			static_cast<NativeError>( 0x80070422U)) ;
		DRIVERCRATE_EXPECT( context, controller.completeInstall( continued.operationId, installed) &&
										controller.lastInstallSucceeded() &&
										provider.installCount == 1 && restore.beginCount == 1 &&
										restore.completeCount == 0) ;
		DRIVERCRATE_EXPECT(
			context,
			!controller
				 .beginInstall( 7U, identities, InstallConfirmation::CONFIRMED,
							   InstallProtectionMode::CLIENT_EXPLICIT_WITHOUT_RESTORE_POINT,
							   begin.operationId)
				 .accepted) ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 復元ポイント保護付きinstall処理の単体試験を実行する。fakeだけを使用して正常、開始失敗、終了失敗、例外経路を検証する
 * @param[in,out] context assertion集計先
 */
//------------------------------------------------------------------------------
void runProtectedInstallTests( TestContext &context)
{
	testExplicitRestoreContinuation( context) ;
	testRestoreContinuationController( context) ;
	testSuccessfulProtectedInstall( context) ;
	testRestorePointCreationFailure( context) ;
	testRestorePointCompletionFailure( context) ;
	testProviderExceptionCompletesRestorePoint( context) ;
	testServerInstallWithoutRestorePoint( context) ;
	testServerProviderException( context) ;
	testInstallProtectionPolicy( context) ;
	testDailyRestorePositive( context) ;
	testDailyRestoreBoundaries( context) ;
	testDailyRestoreMemoFiles( context) ;
}

} // namespace drivercrate::test
