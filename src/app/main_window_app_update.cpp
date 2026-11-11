//------------------------------------------------------------------------------
/**
 * @file main_window_app_update.cpp
 * @brief App更新menu・通知・通常終了への接続を実装します。
 * @version 01.00.01
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
 * </pre>
 * @note Providerのbusy/modal中は通知/引継ぎを保留し、取得同意前にSetupを取りません。
 * @see docs/adr/0481-app-inno-setup-and-update-checks.md
 */
//------------------------------------------------------------------------------
#include "app/main_window.h"
#include "app/resource.h"
#include "platform/windows_error.h"
#include "drivercrate_version.h"
#include <array>
#include <utility>

namespace drivercrate {
//------------------------------------------------------------------------------
/**
 * @brief App専用menu/worker/timerを初期化します。
 * @return menu構築成功はtrue。通信失敗とは独立です。
 */
//------------------------------------------------------------------------------
bool MainWindow::initializeAppUpdates()
{
	const auto menu = CreateMenu() ;		// Windowに所有移転するmenuです。
	const auto help = CreatePopupMenu() ;	// menuが所有する子menuです。
	// 部分生成時にmenuを漏らしません。
	if( !menu || !help) {
		// 成功した片方だけを解放します。
		if( menu) {
			DestroyMenu( menu) ;
		}

		// 未移転の子だけを解放します。
		if( help) {
			DestroyMenu( help) ;
		}

		return false ;
	}

	AppendMenuW( help, MF_STRING, IDM_APP_UPDATE_CHECK, loadString( IDS_APP_UPDATE_CHECK).c_str()) ;
	AppendMenuW( help, MF_STRING | MF_CHECKED, IDM_APP_UPDATE_AUTO,
				loadString( IDS_APP_UPDATE_AUTO).c_str()) ;
	AppendMenuW( menu, MF_POPUP, reinterpret_cast<UINT_PTR>( help),
				loadString( IDS_APP_UPDATE_HELP).c_str()) ;
	// Windowへ所有移転できなければ生成物を回収します。
	if( !SetMenu( window_, menu)) {
		DestroyMenu( menu) ;
		return false ;
	}
#if defined( DRIVERCRATE_INTERNAL_UI_TESTS)
	// 既UI fixtureから実HTTPを発生させません。
	if( !testAppUpdateBackend_) {
		EnableMenuItem( help, IDM_APP_UPDATE_CHECK, MF_BYCOMMAND | MF_GRAYED) ;
		return true ;
	}

	appUpdates_ = std::make_unique<AppUpdateService>( window_, APP_UPDATE_MESSAGE,
													 std::move( testAppUpdateBackend_)) ;
#else
	// 設定/workerだけの障害でdriver機能を停止しません。
	try {
		static_cast<void>( loadAppUpdatePreference( appUpdateAutomatic_)) ;
		appUpdates_ =
			std::make_unique<AppUpdateService>( window_, APP_UPDATE_MESSAGE, makeAppUpdateBackend()) ;
	} catch( ...) {
		appUpdateAutomatic_ = false ;
		EnableMenuItem( help, IDM_APP_UPDATE_CHECK, MF_BYCOMMAND | MF_GRAYED) ;
	}
#endif
	CheckMenuItem( help, IDM_APP_UPDATE_AUTO,
				  MF_BYCOMMAND | (appUpdateAutomatic_ ? MF_CHECKED : MF_UNCHECKED)) ;
	// App起動中だけ有限timerを保持します。
	if( appUpdates_) {
		SetTimer( window_, APP_UPDATE_TIMER, 1000U, nullptr) ;
		pollAppUpdates() ;
	}

	return true ;
}
//------------------------------------------------------------------------------
/**
 * @brief 新規driver操作と同時にしない取得/引継ぎ中か返します。
 * @return 取得/ready/引継ぎ中はtrueです。
 */
//------------------------------------------------------------------------------
bool MainWindow::appUpdateActive() const noexcept
{
	// workerがない時は通常driver操作だけを使えます。
	if( !appUpdates_) {
		return false ;
	}

	const auto stage = appUpdates_->stage() ;	// 一回だけの同期snapshotです。
	return stage == AppUpdateStage::DOWNLOADING || stage == AppUpdateStage::READY ||
		   stage == AppUpdateStage::HANDING_OFF ;
}
//------------------------------------------------------------------------------
/**
 * @brief 既Providerのbusy/modalがないか確認します。
 * @return 通知/引継ぎを許せる場合だけtrueです。
 */
//------------------------------------------------------------------------------
bool MainWindow::canPresentAppUpdate() const noexcept
{
	const auto state = controller_.state() ;	// Providerだけの既stateです。
	const bool idle	 = state == ApplicationState::IDLE || state == ApplicationState::SCAN_READY ||
					  state == ApplicationState::COMPLETED ||
					  // 終端も許可します。
					  state == ApplicationState::FAILURE ;
	GUITHREADINFO gui{} ;	// popup/menu中の通知を避けます。
	gui.cbSize = sizeof( gui) ;
	// modal/停止/driver作用中は旧操作を保ちます。
	if( !idle || closing_ || closeAfterAppUpdate_ || preparationReviewOpen_ || metadataReviewOpen_ ||
	   appUpdateReviewOpen_ || !IsWindowEnabled( window_) ||
	   (GetGUIThreadInfo( 0U, &gui) && (gui.flags & (GUI_INMENUMODE | GUI_POPUPMENUMODE)) != 0U)) {
		return false ;
	}
#if defined( DRIVERCRATE_INTERNAL_UI_TESTS)
	// 決定的fixtureだけが隠しWindowで境界を確認します。
	if( testAppUpdateAllowHidden_) {
		return true ;
	}
#endif
	return IsWindowVisible( window_) && !IsIconic( window_) && GetForegroundWindow() == window_ ;
}
//------------------------------------------------------------------------------
/**
 * @brief 起動/周期/確定結果をUI threadで確認します。
 */
//------------------------------------------------------------------------------
void MainWindow::pollAppUpdates()
{
	processAppUpdateEvents() ;
	// 無効/終了/未受領の提示中には自動要求を積みません。
	if( !appUpdates_ || !appUpdateAutomatic_ || closing_ || closeAfterAppUpdate_ ||
	   pendingAppUpdate_) {
		return ;
	}

	const auto now = GetTickCount64() ;	// sleep中に送信せず復帰後一回だけです。
	// 実際に受理した確認から24hを予約します。
	if( appUpdateSchedule_.due( now) && appUpdates_->requestCheck( false)) {
		appUpdateSchedule_.attempted( now) ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 元数値と固定の操作説明だけを表示します。
 * @param[in] failure App更新だけの確定結果です。
 */
//------------------------------------------------------------------------------
void MainWindow::showAppUpdateFailure( const AppUpdateFailure &failure)
{
#if defined( DRIVERCRATE_INTERNAL_UI_TESTS)
	++testAppUpdateFailures_ ;
	// fixtureの明示decisionがある時だけ実modalを省きます。
	if( testAppUpdateDecision_) {
		return ;
	}
#endif
	const auto message = loadString( IDS_APP_UPDATE_FAILED) + L"\r\n" +
						 std::to_wstring( static_cast<unsigned>( failure.kind)) + L" / HTTP " +
						 std::to_wstring( failure.httpStatus) + L" / " +
						 // 元数値だけです。
						 formatNativeError( failure.error) ;
	MessageBoxW( window_, message.c_str(), loadString( IDS_APP_TITLE).c_str(),
				MB_OK | MB_ICONWARNING) ;
}
//------------------------------------------------------------------------------
/**
 * @brief App専用menu commandを処理します。
 * @param[in] command 固定menu IDです。
 * @return App更新commandならtrueです。
 */
//------------------------------------------------------------------------------
bool MainWindow::handleAppUpdateCommand( const UINT command)
{
	// 固定二項目以外を処理しません。
	if( command != IDM_APP_UPDATE_CHECK && command != IDM_APP_UPDATE_AUTO) {
		return false ;
	}

	// modal/終了後の外部messageを更新同意へ変換しません。
	if( closing_ || closeAfterAppUpdate_ || appUpdateReviewOpen_ || !appUpdates_ ||
	   !IsWindowEnabled( window_)) {
		return true ;
	}

	// 自動確認boolだけを保存します。
	if( command == IDM_APP_UPDATE_AUTO) {
		const bool selected = !appUpdateAutomatic_ ;	// 今回の選択です。
#if defined( DRIVERCRATE_INTERNAL_UI_TESTS)
		NativeError error{} ;	// fixtureは設定fileへ書きません。
#else
		const auto error = saveAppUpdatePreference( selected) ;	// 同配置だけです。
#endif
		// 保存失敗は既設定を変えません。
		if( error != 0) {
			showAppUpdateFailure( {AppUpdateFailureKind::SETTINGS, error, 0U, 0U}) ;
			return true ;
		}

		appUpdateAutomatic_ = selected ;
		CheckMenuItem( GetMenu( window_), IDM_APP_UPDATE_AUTO,
					  MF_BYCOMMAND | (selected ? MF_CHECKED : MF_UNCHECKED)) ;
		return true ;
	}

	const auto stage = appUpdates_->stage() ;	// 確認と取得取消しを区別します。
	// 元App操作だけを取り消します。driver操作は変更しません。
	if( stage == AppUpdateStage::CHECKING || stage == AppUpdateStage::DOWNLOADING) {
		appUpdates_->cancel() ;
		return true ;
	}

	// 取得/引継ぎ中に別確認を重ねません。
	if( appUpdateActive()) {
		return true ;
	}

	pendingAppUpdate_.reset() ;
	static_cast<void>( appUpdates_->requestCheck( true)) ;
	return true ;
}
//------------------------------------------------------------------------------
/**
 * @brief 確定したApp更新結果を安全なidle時だけ表示します。
 */
//------------------------------------------------------------------------------
void MainWindow::processAppUpdateEvents()
{
	// 既UI fixtureや終了後にnative更新を補完しません。
	if( !appUpdates_ || closing_) {
		return ;
	}

	auto next = appUpdates_->takeEvent() ;	// URLを含まない確定DTOです。
	// 取消し/失敗後は次の明示確認captionへ戻します。
	if( !appUpdateActive()) {
		ModifyMenuW( GetMenu( window_), IDM_APP_UPDATE_CHECK, MF_BYCOMMAND | MF_STRING,
					IDM_APP_UPDATE_CHECK, loadString( IDS_APP_UPDATE_CHECK).c_str()) ;
	}

	// 一件だけをbusy/modal終了まで保持します。
	if( next) {
		pendingAppUpdate_ = std::move( next) ;
	}

	// 取消し終端後に通常終了へ戻し、UI threadで待機joinしません。
	if( closeAfterAppUpdate_ && pendingAppUpdate_) {
		closeAfterAppUpdate_ = false ;
		pendingAppUpdate_.reset() ;
		requestClose() ;
		return ;
	}

	// 未受領/driver busy/modal中には通知/引継ぎをしません。
	if( !pendingAppUpdate_ || !canPresentAppUpdate()) {
		return ;
	}

	auto event = std::move( *pendingAppUpdate_) ;	// 今回表示する一結果です。
	pendingAppUpdate_.reset() ;
	// App取得失敗時は元driverの結果帯と選択を保ちます。
	if( event.failure.kind != AppUpdateFailureKind::NONE) {
		// App取得前に保持した結果帯だけを戻します。
		if( !appUpdatePreviousStatus_.empty()) {
			setStatus( appUpdatePreviousStatus_, false) ;
			appUpdatePreviousStatus_.clear() ;
		}

		updateCommandState() ;
		// 自動確認だけの失敗/明示取消しはmodalを重ねません。
		if( event.manual && event.failure.kind != AppUpdateFailureKind::CANCELLED) {
			showAppUpdateFailure( event.failure) ;
		}

		return ;
	}

	// 確認は通知で止まり、明示選択前には取得しません。
	if( event.operation == AppUpdateStage::CHECKING) {
		// 手動確認だけに正常な同版以下を案内します。
		if( !event.release) {
			// 内部fixtureで不要なmodalを開きません。
			if( event.manual) {
#if defined( DRIVERCRATE_INTERNAL_UI_TESTS)
				// 未指定fixtureだけが実際の標準案内を表示します。
				if( !testAppUpdateDecision_) {
#endif
					MessageBoxW( window_, loadString( IDS_APP_UPDATE_CURRENT).c_str(),
								loadString( IDS_APP_TITLE).c_str(), MB_OK | MB_ICONINFORMATION) ;
#if defined( DRIVERCRATE_INTERNAL_UI_TESTS)
				}
#endif
			}

			return ;
		}

		appUpdateReviewOpen_ = true ;
		bool accepted{} ;	// 明示結果だけを同意にします。
#if defined( DRIVERCRATE_INTERNAL_UI_TESTS)
		++testAppUpdatePrompts_ ;
		// 指定fixtureだけは決定的な選択を返します。
		if( testAppUpdateDecision_) {
			accepted = *testAppUpdateDecision_ ;
		} else {
#endif
			const auto version = formatAppVersion( event.release->version) ;	// 公開版だけです。
			const auto content = loadString( IDS_APP_UPDATE_AVAILABLE) + L"\r\n" +
								 DRIVERCRATE_VERSION_WSTRING + L" → " +
								 // 元/新の版です。
								 std::wstring( version.begin(), version.end()) ;
			const auto yes = loadString( IDS_APP_UPDATE_INSTALL) ;	// 明示選択のcaptionです。
			const auto no  = loadString( IDS_APP_UPDATE_LATER) ;	// 見送るcaptionです。
			const std::array<TASKDIALOG_BUTTON, 2U> buttons{
				{{IDYES, yes.c_str()}, {IDNO, no.c_str()}}} ;		// 固定二択です。
			TASKDIALOGCONFIG dialog{} ;								// 元Windowに結合した標準dialogです。
			const auto		 title = loadString( IDS_APP_TITLE) ;	// dialog終了まで保持します。
			dialog.cbSize		   = sizeof( dialog) ;
			dialog.hwndParent	   = window_ ;
			dialog.dwFlags		   = TDF_ALLOW_DIALOG_CANCELLATION ;
			dialog.pszWindowTitle  = title.c_str() ;
			dialog.pszContent	   = content.c_str() ;
			dialog.cButtons		   = static_cast<UINT>( buttons.size()) ;
			dialog.pButtons		   = buttons.data() ;
			dialog.nDefaultButton  = IDNO ;
			int selected{} ;	// 不成立は同意しません。
			accepted = SUCCEEDED( TaskDialogIndirect( &dialog, &selected, nullptr, nullptr)) &&
					   selected == IDYES ;
#if defined( DRIVERCRATE_INTERNAL_UI_TESTS)
		}
#endif
		appUpdateReviewOpen_ = false ;
		// 元提示への明示同意後だけを取得へ渡します。
		if( accepted && canPresentAppUpdate() && appUpdates_->requestDownload()) {
			const int length =
				// 既結果帯の有限copyです。
				std::min( GetWindowTextLengthW( status_), 4096) ;
			appUpdatePreviousStatus_.assign( static_cast<std::size_t>( length) + 1U, L'\0') ;
			appUpdatePreviousStatus_.resize( static_cast<std::size_t>(
				GetWindowTextW( status_, appUpdatePreviousStatus_.data(), length + 1))) ;
			setStatus( loadString( IDS_APP_UPDATE_DOWNLOADING), false) ;
			ModifyMenuW( GetMenu( window_), IDM_APP_UPDATE_CHECK, MF_BYCOMMAND | MF_STRING,
						IDM_APP_UPDATE_CHECK, loadString( IDS_APP_UPDATE_CANCEL).c_str()) ;
			updateCommandState() ;
		} else {
			appUpdates_->dismiss() ;
		}

		return ;
	}

	// 取得済み元宣言を再検査して通常userへ渡します。
	if( event.operation == AppUpdateStage::DOWNLOADING) {
		static_cast<void>( appUpdates_->requestLaunch()) ;
		return ;
	}

	// 引継ぎ要求の成功後だけ正常終了します。Setup完了成功とは表示しません。
	if( event.operation == AppUpdateStage::HANDING_OFF) {
		requestClose() ;
	}
}
}
