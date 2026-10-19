//------------------------------------------------------------------------------
/**
 * @file scan_measurement_smoke.cpp
 * @brief 固定条件のread-only scanを明示実行する計測入口。
 * @version 01.00.01
 * @date 2026/09/10
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Worker経由の一回scanと非機密計測出力を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  本文出力前の拒否地点を固定診断へ分離。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note 引数なしとdescribeではWorkerを構築しません。Run時もscan一回だけを要求し、
 *       準備、payload取得、EULA受諾、driver導入、PnP変更、復元ポイント作成を要求しません。
 *       通常catalog cacheと保護されたrelease観測storeの既存scan副作用は維持します。
 * @see docs/adr/0140-read-only-scan-measurement-run.md
 */
//------------------------------------------------------------------------------

#include "core/operation_controller.h"
#include "core/scan_measurement.h"
#include "platform/provider_worker.h"
#include "support/scan_measurement_diagnostics.h"

#include "drivercrate_version.h"

#include <Windows.h>

#include <array>
#include <cstdint>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

//------------------------------------------------------------------------------
// 計測入口定数定義。
//------------------------------------------------------------------------------

constexpr wchar_t WINDOW_CLASS_NAME[] =
	L"DriverCrate.ScanMeasurementSmoke" ;							// Message-only window専用class名。
constexpr UINT		WORKER_NOTIFICATION_MESSAGE = WM_APP + 0x74U ;	// Worker event到着通知。
constexpr DWORD		MESSAGE_WAIT_MILLISECONDS	= 250U ;			// UI messageを処理する最大待機間隔。
constexpr ULONGLONG SCAN_WAIT_LIMIT_MILLISECONDS =
	30ULL * 60ULL * 1000ULL ;	// 診断入口がscan完了通知を待つ上限。

constexpr int			EXIT_SUCCESSFUL_REPORT = 0 ;	// 条件表示または全成功report。
constexpr int			EXIT_SCAN_FAILURE	   = 1 ;	// 初期化またはscan失敗。
constexpr int			EXIT_ARGUMENT_FAILURE  = 2 ;	// 引数または固定profile拒否。
constexpr int			EXIT_REPORT_FAILURE	   = 3 ;	// Snapshot、容量または出力契約違反。
constexpr int			EXIT_PARTIAL_REPORT	   = 4 ;	// 有効reportを伴う部分成功。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/** @brief Worker通知の受信期間だけmessage-only HWNDを所有する。 */
class MessageOnlyWindow final {
public:
	/** @brief Window classを登録し、表示されないmessage-only Windowを作成する。 */
	MessageOnlyWindow() noexcept
	{
		instance_ = GetModuleHandleW( nullptr) ;
		// Module handleを取得できないprocessではWindow classを登録しない。
		if( instance_ == nullptr) {
			return ;
		}

		WNDCLASSEXW windowClass{} ;	// Test process内だけで使用するWindow class定義。
		windowClass.cbSize		  = sizeof( windowClass) ;
		windowClass.lpfnWndProc	  = &MessageOnlyWindow::windowProcedure ;
		windowClass.hInstance	  = instance_ ;
		windowClass.lpszClassName = WINDOW_CLASS_NAME ;
		const ATOM atom			  = RegisterClassExW( &windowClass) ;	// 今回のclass登録結果。
		// 予期しない登録失敗時は既存classへ接続せず初期化失敗にする。
		if( atom == 0U) {
			return ;
		}

		registered_ = true ;
		window_ = CreateWindowExW( 0U, WINDOW_CLASS_NAME, L"", 0U, 0, 0, 0, 0, HWND_MESSAGE, nullptr,
								  instance_, nullptr) ;
		// Window生成失敗時もdestructorが今回登録したclassを解除する。
		if( window_ == nullptr) {
			return ;
		}
	}

	/** @brief HWNDを破棄し、今回登録したclassを解除する。 */
	~MessageOnlyWindow() noexcept
	{
		// Worker停止後にだけ所有Windowを破棄する呼出し順をmain側で維持する。
		if( window_ != nullptr) {
			DestroyWindow( window_) ;
			window_ = nullptr ;
		}

		// 今回のprocessが登録したclassだけを解除する。
		if( registered_ && instance_ != nullptr) {
			UnregisterClassW( WINDOW_CLASS_NAME, instance_) ;
			registered_ = false ;
		}
	}

	// HWNDとclass登録の単独所有を維持するためcopy/moveを禁止する。
	/**
	 * @brief HWND破棄とwindow class登録の解除責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	MessageOnlyWindow( const MessageOnlyWindow &) = delete ;
	/**
	 * @brief HWND破棄とwindow class登録の解除責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	MessageOnlyWindow &operator=( const MessageOnlyWindow &) = delete ;
	/**
	 * @brief HWND破棄とwindow class登録の解除責務を元の通知windowに留めるため、移動構築を禁止する。
	 */
	MessageOnlyWindow( MessageOnlyWindow &&) = delete ;
	/**
	 * @brief 元の通知windowへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	MessageOnlyWindow &operator=( MessageOnlyWindow &&) = delete ;

	/**
	 * @brief Workerへ渡すmessage-only Windowを返す。
	 * @return 構築成功時の非所有HWND。失敗時はnullptr。
	 */
	[[nodiscard]] HWND get() const noexcept
	{
		return window_ ;
	}

private:
	/**
	 * @brief WorkerのPostMessageを通常queue処理へ渡すWindow callback。
	 * @param[in] window 呼出し元message-only Window。
	 * @param[in] message 配送されたmessage ID。
	 * @param[in] wordParameter message固有値。本入口では使用しない。
	 * @param[in] longParameter message固有値。本入口では使用しない。
	 * @return DefWindowProcWが返す処理結果。
	 * @note C++ exceptionをWin32 callback境界へ漏らしません。
	 */
	static LRESULT CALLBACK windowProcedure( HWND window, UINT message, WPARAM wordParameter,
											LPARAM longParameter) noexcept
	{
		return DefWindowProcW( window, message, wordParameter, longParameter) ;
	}

	/// Window class登録を所有するmodule handle。
	HINSTANCE instance_{} ;
	/// Worker停止まで所有するmessage-only HWND。
	HWND	  window_{} ;
	/// trueの場合はdestructorがclass登録を解除する。
	bool	  registered_{} ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

/**
 * @brief Process message queueを空になるまで処理する。
 * @return WM_QUITを受けず全messageを配送できた場合true。
 */
[[nodiscard]] bool dispatchPendingMessages() noexcept
{
	MSG message{} ;	// 現在取り出したthread message。
	// Queueに存在するmessageだけを有限に取り出し、Worker結果待機中もdispatchする。
	while( PeekMessageW( &message, nullptr, 0U, 0U, PM_REMOVE) != FALSE) {
		// Process終了要求をscan成功へ変換せず、呼出し側へ失敗を返す。
		if( message.message == WM_QUIT) {
			return false ;
		}

		TranslateMessage( &message) ;
		DispatchMessageW( &message) ;
	}

	return true ;
}

/**
 * @brief Worker eventから同じoperationの唯一のscan完了を取得する。
 * @param[in] events UI threadへownershipを移した到着順event集合。
 * @param[in] operationId 待機中のscan operation ID。
 * @param[in,out] result 初回完了時だけscan結果を移す。既存値がある場合は重複を拒否する。
 * @return 異種完了、別operationまたは重複完了がない場合true。
 */
[[nodiscard]] bool consumeWorkerEvents( std::vector<drivercrate::WorkerEvent>   events,
									   const drivercrate::OperationId		   operationId,
									   std::optional<drivercrate::ScanResult> &result)
{
	// Progressは確定値の通知として消費し、完了eventだけを結果へ移す。
	for( drivercrate::WorkerEvent &event : events) {
		// 今回要求していない準備・導入eventはworker protocol違反として拒否する。
		if( event.kind == drivercrate::WorkerEventKind::INSTALL_COMPLETED ||
		   event.kind == drivercrate::WorkerEventKind::PREPARATION_PROGRESS ||
		   event.kind == drivercrate::WorkerEventKind::PREPARATION_COMPLETED) {
			return false ;
		}

		// Progress eventは経過時間から補間せず、今回の入口では表示せず破棄する。
		if( event.kind == drivercrate::WorkerEventKind::PROGRESS) {
			// 別operationのprogressも現在値へ適用しない。
			if( event.operationId != operationId) {
				return false ;
			}

			continue ;
		}

		// Scan完了は同じoperationの一件だけを受理する。
		if( event.kind != drivercrate::WorkerEventKind::SCAN_COMPLETED ||
		   event.operationId != operationId || result.has_value()) {
			return false ;
		}

		result = std::move( event.scanResult) ;
		// 任意のpreparation planは所有eventと共に破棄し、取得要求へ変換しない。
	}

	return true ;
}

/**
 * @brief 本文未出力の拒否理由を一回だけ表示し、report失敗codeを返す。
 * @param[in] reason Snapshotを参照せずに確定した固定拒否理由。
 * @return 診断I/Oの成否にかかわらずcode 3。
 */
[[nodiscard]] int reportFailure(
	const drivercrate::test::ScanMeasurementFailureReason reason) noexcept
{
	// 診断失敗でもcode 3を維持し、別streamや再試行で出力を補わない。
	static_cast<void>( drivercrate::test::writeScanMeasurementFailure( std::cout, reason)) ;
	return EXIT_REPORT_FAILURE ;
}

/**
 * @brief 通常ProviderWorkerへ一回scanだけを要求し、完全計測reportを出力する。
 * @param[in] options 開始前に解決済みの固定profile。
 * @return ADR 0140の終了code 0、1、3または4。
 */
[[nodiscard]] int runBaselineScan( const drivercrate::ScanOptions &options)
{
	MessageOnlyWindow window ;	// Workerより長寿命のmessage-only通知先。
	// 通知先を作成できない場合はProviderやCOM workerを構築しない。
	if( window.get() == nullptr) {
		return EXIT_SCAN_FAILURE ;
	}

	drivercrate::OperationController controller ;						// UI thread専用のoperation検証状態。
	const drivercrate::BeginResult	 begin = controller.beginScan() ;	// 唯一のscan開始結果。
	// Controllerが非ゼロoperationを発行できない場合はworkerを開始しない。
	if( !begin.accepted || begin.operationId == 0U) {
		return EXIT_SCAN_FAILURE ;
	}

	std::optional<drivercrate::ScanResult> scanResult ;	// Workerから受け取る唯一の完了結果。
	bool protocolValid = true ;							// falseの場合は異種・別operation eventを検出済み。
	bool timedOut	   = false ;						// trueの場合は完了を得ても成功へ変換しない。
	{
		drivercrate::ProviderWorker worker( window.get(),
										   WORKER_NOTIFICATION_MESSAGE) ;	// 通常worker。
		// 固定profileを一回queueへ登録できなければscan開始失敗として停止する。
		if( !worker.requestScan( begin.operationId, options)) {
			worker.stop() ;
			return EXIT_SCAN_FAILURE ;
		}

		const ULONGLONG started = GetTickCount64() ;	// 待機上限だけに使う単調時刻。
		// Scan完了、protocol違反、message失敗または待機上限まで有限間隔で処理する。
		while( !scanResult.has_value() && protocolValid && !timedOut) {
			const DWORD waitResult = MsgWaitForMultipleObjectsEx(
				0U, nullptr, MESSAGE_WAIT_MILLISECONDS, QS_ALLINPUT,
				MWMO_INPUTAVAILABLE) ;	// Window messageまたは有限timeout。
			// Wait API自体の失敗をscan結果として扱わない。
			if( waitResult == WAIT_FAILED) {
				protocolValid = false ;
				break ;
			}

			// 到着messageを処理し、Window close等の終了要求を無視しない。
			if( !dispatchPendingMessages()) {
				protocolValid = false ;
				break ;
			}

			protocolValid = consumeWorkerEvents( worker.takeEvents(), begin.operationId, scanResult) ;
			// 経過時間だけで進捗を増やさず、上限到達を成功や取消完了へ変換しない。
			if( !scanResult.has_value() &&
			   GetTickCount64() - started >= SCAN_WAIT_LIMIT_MILLISECONDS) {
				timedOut = true ;
			}
		}

		// 実行中WUAを強制終了せず自然完了を待ち、Windowより先にworkerを停止する。
		worker.stop() ;
	}

	// 診断待機上限は既存のscan失敗codeを維持する。
	if( timedOut) {
		controller.stop() ;
		return EXIT_SCAN_FAILURE ;
	}

	// 受信protocol違反を固定理由へ変換し、event内容は出力しない。
	if( !protocolValid) {
		controller.stop() ;
		return reportFailure(
			drivercrate::test::ScanMeasurementFailureReason::WORKER_EVENT_REJECTED) ;
	}

	// 未取得の完了結果を参照せず固定理由で終了する。
	if( !scanResult.has_value()) {
		controller.stop() ;
		return reportFailure( drivercrate::test::ScanMeasurementFailureReason::SCAN_RESULT_MISSING) ;
	}

	// 同じoperationの完了をControllerへ適用できない場合はsnapshot契約違反とする。
	if( !controller.completeScan( begin.operationId, scanResult.value())) {
		controller.stop() ;
		return reportFailure( drivercrate::test::ScanMeasurementFailureReason::CONTROLLER_REJECTED) ;
	}

	// Scan自体が失敗した場合は不完全なmeasurement reportを出力しない。
	if( !scanResult->succeeded) {
		controller.stop() ;
		return EXIT_SCAN_FAILURE ;
	}

	// 完了通知が受理されても候補session拒否でREADYにならない場合を区別する。
	if( controller.state() != drivercrate::ApplicationState::SCAN_READY) {
		controller.stop() ;
		return reportFailure( drivercrate::test::ScanMeasurementFailureReason::CONTROLLER_REJECTED) ;
	}

	// Workerが計測を公開しなかった結果を0件reportへ変換しない。
	if( !scanResult->measurement.has_value()) {
		controller.stop() ;
		return reportFailure( drivercrate::test::ScanMeasurementFailureReason::MEASUREMENT_MISSING) ;
	}

	// 計測が存在しても公開validatorまたはControllerが拒否した場合を区別する。
	if( !drivercrate::isPublishedScanMeasurementValid( begin.operationId, scanResult.value()) ||
	   controller.scanMeasurement() == nullptr) {
		controller.stop() ;
		return reportFailure(
			drivercrate::test::ScanMeasurementFailureReason::PUBLISHED_MEASUREMENT_REJECTED) ;
	}

	const drivercrate::test::ScanMeasurementReportStatus status =
		drivercrate::test::writeScanMeasurementReport( std::cout, begin.operationId,
													  DRIVERCRATE_VERSION_WSTRING, options,
													  // 完全構築後の一回ASCII出力結果。
													  scanResult.value()) ;
	controller.stop() ;
	// Report出力区分をADR 0140の固定終了codeへ一対一で変換する。
	switch( status) {
		// 全成功reportはcode 0へ変換する。
		case drivercrate::test::ScanMeasurementReportStatus::SUCCESS:
			return EXIT_SUCCESSFUL_REPORT ;
		// 部分成功reportは個別失敗を保持するcode 4へ変換する。
		case drivercrate::test::ScanMeasurementReportStatus::PARTIAL_SUCCESS:
			return EXIT_PARTIAL_REPORT ;
		// Snapshotまたは容量拒否はreport違反のcode 3へ変換する。
		case drivercrate::test::ScanMeasurementReportStatus::CONTRACT_REJECTED:
			return reportFailure(
				drivercrate::test::ScanMeasurementFailureReason::REPORT_CONTRACT_REJECTED) ;
		// I/O失敗もreport未成立のcode 3へ変換する。
		case drivercrate::test::ScanMeasurementReportStatus::OUTPUT_FAILED:
			return EXIT_REPORT_FAILURE ;
	}

	return EXIT_REPORT_FAILURE ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 固定profileを表示するか、明示optionで一回read-only scanを実行する。
 * @param[in] argumentCount 実行file名を含む引数数。
 * @param[in] arguments Processが所有するNUL終端wide引数配列。
 * @return ADR 0140で定義した0から4の終了code。
 * @note 未知・重複・任意Provider・URL・path optionはworker構築前に拒否します。
 */
//------------------------------------------------------------------------------
int wmain( const int argumentCount, wchar_t *arguments[])
{
	try {
		// Process契約外の引数配列と二つ以上のoptionをallocation前に拒否する。
		if( arguments == nullptr || argumentCount < 1 || argumentCount > 2) {
			return EXIT_ARGUMENT_FAILURE ;
		}

		std::array<std::wstring_view, 1>   argumentViews{} ;	// 実行file名を除く最大一引数。
		std::span<const std::wstring_view> commandArguments ;	// Parserへ借用する0または1引数。
		// 一つのoptionがある場合はnullを拒否してviewへ変換する。
		if( argumentCount == 2) {
			// Null引数を空optionとして受理しない。
			if( arguments[1] == nullptr) {
				return EXIT_ARGUMENT_FAILURE ;
			}

			argumentViews[0] = arguments[1] ;
			commandArguments = argumentViews ;
		}

		const drivercrate::test::ScanMeasurementCommand command =
			// 副作用なし分類。
			drivercrate::test::parseScanMeasurementArguments( commandArguments) ;
		// 未知または任意入力をProvider／COM／cache初期化前に拒否する。
		if( command == drivercrate::test::ScanMeasurementCommand::REJECTED) {
			return EXIT_ARGUMENT_FAILURE ;
		}

		// 条件表示ではprofileを検証するだけでworkerを構築しない。
		if( command == drivercrate::test::ScanMeasurementCommand::DESCRIBE_BASELINE) {
			std::string description ;	// Registry driftとI/O失敗を区別する事前構築結果。
			// 固定profile不一致は引数・profile拒否の終了codeへ対応させる。
			if( !drivercrate::test::buildBaselineScanDescription( description)) {
				return EXIT_ARGUMENT_FAILURE ;
			}

			return drivercrate::test::writeBaselineScanDescription( std::cout)
					   ? EXIT_SUCCESSFUL_REPORT
					   : EXIT_REPORT_FAILURE ;
		}

		drivercrate::ScanOptions options ;	// 全検証後だけWorkerへ渡す固定profile。
		// Registry drift、未知ID、重複または同意矛盾をscan開始前に拒否する。
		if( !drivercrate::test::resolveBaselineScanOptions( options)) {
			return EXIT_ARGUMENT_FAILURE ;
		}

		return runBaselineScan( options) ;
	} catch( ...) {
		// AllocationまたはWindows初期化例外を秘密情報なしの初期化失敗へ変換する。
		return EXIT_SCAN_FAILURE ;
	}
}
