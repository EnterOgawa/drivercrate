//------------------------------------------------------------------------------
/**
 * @file protected_install_tests.cpp
 * @brief 復元ポイント保護付きinstall単体試験実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  保護付き進捗試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Windows Server専用経路試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note fake Providerとfake復元ポイントサービスだけを使用します。SRSetRestorePointW、download、driver installは呼び出しません。
 */
//------------------------------------------------------------------------------

#include "protected_install_tests.h"

#include "core/protected_install.h"
#include "test_framework.h"

#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// Fake型定義。
//------------------------------------------------------------------------------

/**
 * @brief 呼出結果と回数を制御できる復元ポイントサービスfakeである。
 */
class FakeRestorePointService final : public IRestorePointService {
public:
	/// Begin戻り値。
	RestorePointOperationResult beginResult{.outcome = OutcomeCode::SUCCESS, .sequenceNumber = 100} ;
	/// Complete戻り値。
	RestorePointOperationResult completeResult{.outcome		   = OutcomeCode::SUCCESS,
											   .sequenceNumber = 100} ;
	/// Begin呼出し回数。
	int							beginCount{} ;
	/// Complete呼出し回数。
	int							completeCount{} ;

	/**
	 * @brief 設定済み開始結果を返し、呼出し回数を記録する。
	 * @param[in] description 試験対象が渡した復元ポイント説明。
	 * @return `beginResult`の複製。 beginResultの複製。
	 */
	[[nodiscard]] RestorePointOperationResult begin(
		std::wstring_view description) noexcept override ;

	/**
	 * @brief 設定済み終了結果を返し、呼出し回数を記録する。
	 * @param[in] sequenceNumber 試験対象が渡した識別番号。
	 * @return `completeResult`の複製。 completeResultの複製。
	 */
	[[nodiscard]] RestorePointOperationResult complete(
		std::int64_t sequenceNumber) noexcept override ;
} ;

/**
 * @brief 成功または例外を制御できるdriver Provider fakeである。
 */
class FakeUpdateProvider final : public IUpdateProvider {
public:
	/// trueの場合はinstallから型付き例外を送出する。
	bool						throwOnInstall{} ;
	/// Install呼出し回数。
	int							installCount{} ;

	/**
	 * @brief 本試験では使用しない既定scan結果を返す。
	 * @param[in] scanSessionId 呼出し側が指定したsession ID。
	 * @param[in] progressCallback 未使用の進捗通知先。
	 * @param[in] options 本試験では未使用のscan条件。
	 * @return 未開始のscan結果。
	 */
	[[nodiscard]] ScanResult	scan( ScanSessionId scanSessionId, const ScanOptions &options,
									 const ProviderProgressCallback &progressCallback) override ;

	/**
	 * @brief 選択候補の成功結果を返すか、設定により例外を送出する。
	 * install呼出しを記録し、例外設定時は結果を返さず送出する。
	 * @param[in] scanSessionId 選択元session ID。
	 * @param[in] identities 選択されたopaque identity群。
	 * @param[in] parentWindowNative 未使用の親Window値。
	 * @param[in] progressCallback 進捗通知callback。
	 * @return 全候補成功のinstall結果。
	 */
	[[nodiscard]] InstallResult install( ScanSessionId					scanSessionId,
										std::span<const std::wstring>	identities,
										std::uintptr_t					parentWindowNative,
										const ProviderProgressCallback &progressCallback) override ;
} ;

//------------------------------------------------------------------------------
/**
 * @see tests/unit/protected_install_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
RestorePointOperationResult FakeRestorePointService::begin(
	const std::wstring_view description) noexcept
{
	static_cast<void>( description) ;
	++beginCount ;
	return beginResult ;
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/protected_install_tests.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
RestorePointOperationResult FakeRestorePointService::complete(
	const std::int64_t sequenceNumber) noexcept
{
	++completeCount ;
	RestorePointOperationResult result = completeResult ;	// Fake設定の戻り値。
	result.sequenceNumber			   = sequenceNumber ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see tests/unit/protected_install_tests.cpp 宣言側の契約を正本とする。
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
 * @see tests/unit/protected_install_tests.cpp 宣言側の契約を正本とする。
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
	// Provider例外を注入し、開始済み復元ポイントが終了されることを検証する。
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
	InstallResult result{} ;	// 全選択候補の成功結果。
	result.succeeded	   = true ;
	result.downloadOutcome = OutcomeCode::SUCCESS ;
	result.installOutcome  = OutcomeCode::SUCCESS ;
	result.updates.reserve( identities.size()) ;

	// 入力順を維持して全候補の成功結果を作成する。
	for( const std::wstring &identity : identities) {
		result.updates.push_back( {.identity		   = identity,
								  .downloadOutcome = OutcomeCode::SUCCESS,
								  .installOutcome  = OutcomeCode::SUCCESS}) ;
	}

	return result ;
}

//------------------------------------------------------------------------------
// 内部試験関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 復元ポイントで囲んだ正常install結果を検証する。
 *
 * Begin、Provider、Completeが一回ずつ成功し結果へ記録されることを検証する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testSuccessfulProtectedInstall( TestContext &context)
{
	FakeUpdateProvider			   provider ;								// 成功Provider fake。
	FakeRestorePointService		   restoreService ;							// 成功復元ポイントfake。
	const std::array			   identities{std::wstring( L"driver-a")} ;	// 選択候補。
	std::vector<ProviderProgress>  progressEvents ;							// 保護付きoperationが通知した進捗列。
	const ProviderProgressCallback callback = [&progressEvents]( const ProviderProgress &progress) {
		progressEvents.push_back( progress) ;
	} ; // 進捗通知を記録するcallback。

	const InstallResult result =
		installWithRestorePoint( provider, restoreService, 1, identities, 0, callback,
								L"DriverCrate test") ;	// 保護付き実行結果。
	DRIVERCRATE_EXPECT( context, result.succeeded) ;
	DRIVERCRATE_EXPECT( context, provider.installCount == 1) ;
	DRIVERCRATE_EXPECT( context, restoreService.beginCount == 1) ;
	DRIVERCRATE_EXPECT( context, restoreService.completeCount == 1) ;
	DRIVERCRATE_EXPECT( context, result.restorePointCreation.outcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, result.restorePointCompletion.outcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, !progressEvents.empty()) ;
	DRIVERCRATE_EXPECT( context,
					   progressEvents.front().stage == ProviderStage::CREATING_RESTORE_POINT) ;
	DRIVERCRATE_EXPECT( context,
					   progressEvents.back().stage == ProviderStage::FINALIZING_RESTORE_POINT) ;
	DRIVERCRATE_EXPECT( context, progressEvents.back().percentComplete == 100) ;
	std::uint32_t previousPercentage{} ;	// 単調増加を比較する直前の全体完了率。
	// 保護付きoperationの全進捗が0～100で後退しないことを検証する。
	for( const ProviderProgress &progress : progressEvents) {
		DRIVERCRATE_EXPECT( context, progress.percentComplete >= previousPercentage) ;
		DRIVERCRATE_EXPECT( context, progress.percentComplete <= 100) ;
		previousPercentage = progress.percentComplete ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 復元ポイント開始失敗時のfail-closed動作を検証する。
 *
 * Begin失敗時はProviderとCompleteを呼ばず全候補を未開始で返すことを検証する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testRestorePointCreationFailure( TestContext &context)
{
	FakeUpdateProvider		provider ;			// 呼ばれてはならないProvider fake。
	FakeRestorePointService restoreService ;	// Begin失敗を返すfake。
	restoreService.beginResult = {.outcome = OutcomeCode::FAILURE, .error = 5} ;
	const std::array			   identities{std::wstring( L"driver-a")} ;	// 選択候補。
	const ProviderProgressCallback callback = []( const ProviderProgress &progress) {
		static_cast<void>( progress) ;
	} ; // 進捗通知を受理するcallback。

	const InstallResult result =
		installWithRestorePoint( provider, restoreService, 1, identities, 0, callback,
								L"DriverCrate test") ;	// Fail-closed結果。
	DRIVERCRATE_EXPECT( context, !result.succeeded) ;
	DRIVERCRATE_EXPECT( context, provider.installCount == 0) ;
	DRIVERCRATE_EXPECT( context, restoreService.completeCount == 0) ;
	DRIVERCRATE_EXPECT( context, result.updates.size() == identities.size()) ;
	DRIVERCRATE_EXPECT( context, result.updates[0].downloadOutcome == OutcomeCode::NOT_STARTED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 復元ポイント終了失敗を全体失敗へ反映することを検証する。
 *
 * Provider成功を保持しつつ、Complete失敗を全体成功として表示しないことを検証する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testRestorePointCompletionFailure( TestContext &context)
{
	FakeUpdateProvider		provider ;			// 成功Provider fake。
	FakeRestorePointService restoreService ;	// Complete失敗を返すfake。
	restoreService.completeResult = {.outcome = OutcomeCode::FAILURE, .error = 6} ;
	const std::array			   identities{std::wstring( L"driver-a")} ;	// 選択候補。
	const ProviderProgressCallback callback = []( const ProviderProgress &progress) {
		static_cast<void>( progress) ;
	} ; // 進捗通知を受理するcallback。

	const InstallResult result =
		installWithRestorePoint( provider, restoreService, 1, identities, 0, callback,
								L"DriverCrate test") ;	// 終了失敗付き結果。
	DRIVERCRATE_EXPECT( context, !result.succeeded) ;
	DRIVERCRATE_EXPECT( context, restoreService.completeCount == 1) ;
	DRIVERCRATE_EXPECT( context, result.updates[0].installOutcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, result.restorePointCompletion.outcome == OutcomeCode::FAILURE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider例外時にも復元ポイントを終了することを検証する。
 *
 * Provider例外を失敗結果へ変換し、開始済み復元ポイントへのCompleteを一回実行することを検証する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testProviderExceptionCompletesRestorePoint( TestContext &context)
{
	FakeUpdateProvider provider ;	// 例外を送出するProvider fake。
	provider.throwOnInstall = true ;
	FakeRestorePointService		   restoreService ;							// 成功復元ポイントfake。
	const std::array			   identities{std::wstring( L"driver-a")} ;	// 選択候補。
	const ProviderProgressCallback callback = []( const ProviderProgress &progress) {
		static_cast<void>( progress) ;
	} ; // 進捗通知を受理するcallback。

	const InstallResult result =
		installWithRestorePoint( provider, restoreService, 1, identities, 0, callback,
								L"DriverCrate test") ;	// 例外変換後の結果。
	DRIVERCRATE_EXPECT( context, !result.succeeded) ;
	DRIVERCRATE_EXPECT( context, restoreService.completeCount == 1) ;
	DRIVERCRATE_EXPECT( context, result.downloadOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, result.restorePointCompletion.outcome == OutcomeCode::SUCCESS) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows Server専用installが復元ポイントを要求しないことを検証する。
 *
 * Server専用関数がProviderを実行し、復元ポイント結果をNotStartedのまま保持することを検証する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testServerInstallWithoutRestorePoint( TestContext &context)
{
	FakeUpdateProvider			   provider ;								// 成功Provider fake。
	const std::array			   identities{std::wstring( L"driver-a")} ;	// 選択候補。
	std::vector<ProviderProgress>  progressEvents ;							// Providerが通知した進捗列。
	const ProviderProgressCallback callback = [&progressEvents]( const ProviderProgress &progress) {
		progressEvents.push_back( progress) ;
	} ; // 進捗通知を記録するcallback。

	const InstallResult result = installWithoutRestorePointOnServer(
		provider, 1, identities, 0, callback) ;	// Server専用実行結果。
	DRIVERCRATE_EXPECT( context, result.succeeded) ;
	DRIVERCRATE_EXPECT( context, provider.installCount == 1) ;
	DRIVERCRATE_EXPECT( context, result.protectionMode ==
									InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT) ;
	DRIVERCRATE_EXPECT( context, result.restorePointCreation.outcome == OutcomeCode::NOT_STARTED) ;
	DRIVERCRATE_EXPECT( context, result.restorePointCompletion.outcome == OutcomeCode::NOT_STARTED) ;
	DRIVERCRATE_EXPECT( context, progressEvents.size() == 2) ;
	DRIVERCRATE_EXPECT( context, progressEvents.front().stage == ProviderStage::DOWNLOADING) ;
	DRIVERCRATE_EXPECT( context, progressEvents.back().stage == ProviderStage::INSTALLING) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows Server専用installのProvider例外変換を検証する。
 *
 * 復元ポイントなし経路でもProvider例外を結果へ変換し、Server専用modeを失わないことを検証する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testServerProviderException( TestContext &context)
{
	FakeUpdateProvider provider ;	// 例外を送出するProvider fake。
	provider.throwOnInstall = true ;
	const std::array			   identities{std::wstring( L"driver-a")} ;	// 選択候補。
	const ProviderProgressCallback callback = []( const ProviderProgress &progress) {
		static_cast<void>( progress) ;
	} ; // 進捗通知を受理するcallback。

	// Fake ProviderをServer保護modeで実行した結果。実復元ポイントや導入は行わない。
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
 * @brief OS種別ごとのinstall保護方針を検証する。
 *
 * Clientの復元ポイント回避とServerの非support API使用を許可しないpolicy matrixを検証する。
 *
 * @param[in,out] context assertion集計先。
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

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/protected_install_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runProtectedInstallTests( TestContext &context)
{
	testSuccessfulProtectedInstall( context) ;
	testRestorePointCreationFailure( context) ;
	testRestorePointCompletionFailure( context) ;
	testProviderExceptionCompletesRestorePoint( context) ;
	testServerInstallWithoutRestorePoint( context) ;
	testServerProviderException( context) ;
	testInstallProtectionPolicy( context) ;
}

} // namespace drivercrate::test
