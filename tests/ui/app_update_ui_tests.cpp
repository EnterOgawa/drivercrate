//------------------------------------------------------------------------------
/**
 * @file app_update_ui_tests.cpp
 * @brief App更新の非通信MainWindow境界を確認します。
 * @version 01.00.02
 * @date 2026/11/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/11  App専用の通知付き更新を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * Ver.01.00.02 Shunji Ogawa  2026/11/11  取消しterminalのUI受領を次の直接commandより先に確認。
 * </pre>
 * @note 実driver/HTTP/Explorer/Setupを呼ばず同じUIだけを操作します。
 * @see docs/adr/0481-app-inno-setup-and-update-checks.md
 */
//------------------------------------------------------------------------------
#include "app_update_ui_tests.h"
#include "app/main_window.h"
#include "app/resource.h"
#include "support/metadata_ui_fixture.h"
#include <atomic>
#include <functional>
#include <memory>

namespace drivercrate {
namespace {
/** @brief App更新の共有counterと有限待機です。 */
struct AppUiState {
	/// 確認回数です。
	std::atomic_uint checks{} ;
	/// 同意後の取得回数です。
	std::atomic_uint downloads{} ;
	/// 引継ぎ要求回数です。
	std::atomic_uint launches{} ;
	/// close中の取消しを試します。
	std::atomic_bool holdChecks{} ;
	/// 取得中のdriver開始拒否を試します。
	std::atomic_bool holdDownloads{true} ;
} ;
/** @brief 更新を完全fakeで返すUI専用backendです。 */
class UiBackend final : public AppUpdateBackend {
public:
	/**
	 * @brief Window/workerでcounterだけを共有します。
	 * @param[in] state 完全fakeの共有状態です。
	 */
	explicit UiBackend( std::shared_ptr<AppUiState> state) : state_( std::move( state))
	{
	}
	/**
	 * @brief 架空の新版だけを返します。
	 * @param[in] cancellation 同じ操作の取消しです。
	 * @return 実行権限を持たない宣言です。
	 */
	AppUpdateEvent check( const AppUpdateCancellation &cancellation) noexcept override
	{
		++state_->checks ;
		// close取消しを確認しながら最大3000回待機します。実時間の固定上界は保証しません。
		for( unsigned count{}; state_->holdChecks && !cancellation() && count < 3000U; ++count) {
			Sleep( 1U) ;
		}

		AppUpdateEvent event ;	// 非機密DTOだけです。
		event.release = AppUpdateRelease{{{1U, 0U, 6U}}, 1U, std::string( 64U, 'a')} ;
		return event ;
	}
	/**
	 * @brief 明示同意後だけ取得を数えます。
	 * @param[in] release 元の完全宣言です。
	 * @param[in] cancellation 同じ取得の取消しです。
	 * @return 固定成功または取消しです。
	 */
	AppUpdateFailure download( const AppUpdateRelease	  &release,
							  const AppUpdateCancellation &cancellation) noexcept override
	{
		static_cast<void>( release) ;
		++state_->downloads ;
		// 取消しを確認しながらSleep(1)を最大3000回行います。実時間の3秒上界ではありません。
		for( unsigned count{}; state_->holdDownloads && !cancellation() && count < 3000U; ++count) {
			Sleep( 1U) ;
		}

		return cancellation() ? AppUpdateFailure{AppUpdateFailureKind::CANCELLED,
												 HRESULT_FROM_WIN32( ERROR_CANCELLED), 0U, 0U}
							  : AppUpdateFailure{} ;
	}
	/**
	 * @brief 引継ぎ回数を記録し、固定のLAUNCH失敗を返すUI fakeです。
	 * @param[in] release 使用しない架空の宣言です。検証しません。
	 * @param[in] cancellation 使用せず呼び出さない取消し関数です。
	 * @return 常にLAUNCH/E_ACCESSDENIEDです。
	 * @note 実Explorer・process起動・取消し確認を行いません。失敗後のWindow保持は外側の試験で確認します。
	 */
	AppUpdateFailure launch( const AppUpdateRelease		&release,
							const AppUpdateCancellation &cancellation) noexcept override
	{
		static_cast<void>( release) ;
		static_cast<void>( cancellation) ;
		++state_->launches ;
		return {AppUpdateFailureKind::LAUNCH, E_ACCESSDENIED, 0U, 0U} ;
	}

private:
	/// workerが終了するまでだけ共有します。
	std::shared_ptr<AppUiState> state_ ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief 同じprivate desktopのmessageだけを有限に処理します。
 * @param[in] done 終端の純粋照会です。
 * @return 外側の期限確認を続けられる間にdoneがtrueを返した場合true、期限判定でloopを終えた場合falseです。
 * @note GetTickCount64の約5秒期限を外側loopで検査します。message処理・doneやOS呼出しの所要時間まで5秒に制限しません。
 */
//------------------------------------------------------------------------------
bool until( const std::function<bool()> &done)
{
	const auto end = GetTickCount64() + 5000U ;	// fixture一段階だけの期限です。
	// 決定的な終端までだけUIを動かします。
	while( GetTickCount64() < end) {
		MSG message{} ;	// 現threadだけのmessageです。
		// 溜まった通知を有限phaseの間に処理します。
		while( PeekMessageW( &message, nullptr, 0U, 0U, PM_REMOVE)) {
			// 試験中の一Windowのquitはprocess外へ転用しません。
			if( message.message != WM_QUIT) {
				TranslateMessage( &message) ;
				DispatchMessageW( &message) ;
			}
		}

		// 終端後に余分な要求を送りません。
		if( done()) {
			return true ;
		}

		Sleep( 1U) ;
	}

	return false ;
}
}
/** @brief 内部targetだけで通常MainWindowを直接確認します。 */
struct MainWindowAppUpdateTestAccess {
	/**
	 * @brief 元driver state/operationと更新stateの非混線を確認します。
	 * @param[in,out] context 固定期待の集計先です。
	 */
	static void run( test::TestContext &context)
	{
		auto driver =
			std::make_shared<test::MetadataUiState>() ;		// nativeへfallbackしないProviderです。
		auto	   app = std::make_shared<AppUiState>() ;	// App専用counterです。
		MainWindow window ;									// 製品と同じUIです。
		window.testProviderFactory_		 = test::metadataUiProviderFactory( driver) ;
		window.testRestorePointFactory_	 = test::metadataUiRestoreFactory( driver) ;
		window.testAppUpdateBackend_	 = std::make_unique<UiBackend>( app) ;
		window.testAppUpdateDecision_	 = false ;
		window.testAppUpdateAllowHidden_ = true ;
		const auto scan = window.controller_.beginScan() ;	// Providerを呼ばないbusy状態です。
		DRIVERCRATE_EXPECT( context, scan.accepted) ;
		DRIVERCRATE_EXPECT( context, window.create( GetModuleHandleW( nullptr))) ;
		// Window作成失敗時は無効なhandleへ進みません。
		if( !window.window_) {
			return ;
		}

		DRIVERCRATE_EXPECT( context, until( [&]() { return window.pendingAppUpdate_.has_value() ; })) ;
		DRIVERCRATE_EXPECT( context, app->checks == 1U && window.testAppUpdatePrompts_ == 0U) ;
		DRIVERCRATE_EXPECT( context, app->downloads == 0U && app->launches == 0U) ;
		DRIVERCRATE_EXPECT( context, window.controller_.activeOperationId() == scan.operationId &&
										window.controller_.state() == ApplicationState::SCANNING) ;
		window.preparationReviewOpen_ = true ;
		ScanResult ended ;	// fakeの失敗終端でbusyだけを解除します。
		ended.outcome = OutcomeCode::FAILURE ;
		ended.error	  = E_FAIL ;
		DRIVERCRATE_EXPECT( context, window.controller_.completeScan( scan.operationId, ended)) ;
		window.pollAppUpdates() ;
		DRIVERCRATE_EXPECT( context, window.testAppUpdatePrompts_ == 0U) ;
		window.preparationReviewOpen_ = false ;
		window.pollAppUpdates() ;
		DRIVERCRATE_EXPECT( context, window.testAppUpdatePrompts_ == 1U && app->downloads == 0U) ;
		DRIVERCRATE_EXPECT( context, window.appUpdates_->stage() == AppUpdateStage::IDLE) ;
		const auto operation =
			// App更新で不変の元operationです。
			window.controller_.activeOperationId() ;
		window.testAppUpdateDecision_ = true ;
		DRIVERCRATE_EXPECT( context, window.handleAppUpdateCommand( IDM_APP_UPDATE_CHECK)) ;
		DRIVERCRATE_EXPECT( context, until( [&]() { return app->downloads == 1U ; })) ;
		DRIVERCRATE_EXPECT( context, !IsWindowEnabled( window.scanButton_) &&
										!IsWindowEnabled( window.installButton_)) ;
		SendMessageW( window.window_, WM_COMMAND, MAKEWPARAM( IDC_SCAN, BN_CLICKED), 0) ;
		DRIVERCRATE_EXPECT( context, driver->normalCalls == 0U &&
										window.controller_.activeOperationId() == operation) ;
		DRIVERCRATE_EXPECT( context, window.handleAppUpdateCommand( IDM_APP_UPDATE_CHECK)) ;
		DRIVERCRATE_EXPECT( context, until( [&]() { return !window.appUpdateActive() ; })) ;
		// workerのIDLE公開だけでなく、同じUIへ取消しterminalを受領させます。
		window.processAppUpdateEvents() ;
		DRIVERCRATE_EXPECT( context, app->launches == 0U && IsWindow( window.window_) &&
										window.appUpdates_->stage() == AppUpdateStage::IDLE &&
										IsWindowEnabled( window.scanButton_) &&
										window.testAppUpdateFailures_ == 0U) ;
		app->holdDownloads = false ;
		DRIVERCRATE_EXPECT( context, window.handleAppUpdateCommand( IDM_APP_UPDATE_CHECK)) ;
		DRIVERCRATE_EXPECT( context, until( [&]() {
							   return app->launches == 1U && window.testAppUpdateFailures_ == 1U ;
						   })) ;
		DRIVERCRATE_EXPECT( context,
						   IsWindow( window.window_) && IsWindowEnabled( window.scanButton_)) ;
		DRIVERCRATE_EXPECT( context, window.controller_.activeOperationId() == operation) ;
		app->holdChecks = true ;
		DRIVERCRATE_EXPECT( context, window.handleAppUpdateCommand( IDM_APP_UPDATE_CHECK)) ;
		DRIVERCRATE_EXPECT( context, until( [&]() {
							   return window.appUpdates_->stage() == AppUpdateStage::CHECKING ;
						   })) ;
		const auto hwnd = window.window_ ;	// close終端だけを観測します。
		SendMessageW( hwnd, WM_CLOSE, 0U, 0) ;
		DRIVERCRATE_EXPECT( context, until( [&]() { return !IsWindow( hwnd) ; })) ;
		DRIVERCRATE_EXPECT( context, driver->normalCalls == 0U && driver->metadataCalls == 0U &&
										driver->restoreCalls == 0U && app->launches == 1U) ;
	}
} ;
namespace test {
//------------------------------------------------------------------------------
/**
 * @brief 通知/driver busy/modal/取消し/引継ぎ失敗/closeを確認します。
 * @param[in,out] context 固定期待の集計先です。
 */
//------------------------------------------------------------------------------
void runAppUpdateUiTests( TestContext &context)
{
	MainWindowAppUpdateTestAccess::run( context) ;
}
}
}
