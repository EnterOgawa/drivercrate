//------------------------------------------------------------------------------
/**
 * @file metadata_search_smoke.cpp
 * @brief 明示集合だけを一回実行する情報検索専用の診断入口。
 * @version 01.00.01
 * @date 2026/09/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  情報検索専用の非機密出力契約を追加。
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note 任意の端末表示値・URL・path・EULA本文を出力しない。
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#include "core/metadata_search_report.h"
#include "core/operation_controller.h"
#include "platform/provider_worker.h"

#include "drivercrate_version.h"

#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
std::atomic_bool cancellationRequested{} ;			// Console callbackから主threadへ送る取消し信号。
constexpr UINT	 WORKER_MESSAGE = WM_APP + 0x75U ;	// 所有message-only Windowへの通知。

/**
 * @brief Ctrl+Cを強制終了でなく協調取消しへ変換する。
 * @param[in] controlType Windowsが通知したconsole event。
 * @return Ctrl+C／Breakだけを処理した場合TRUE。他の終了規則はWindowsへ委譲する。
 */
BOOL WINAPI		 consoleControl( const DWORD controlType) noexcept
{
	// Console閉鎖やshutdownは短時間のOS終了規則を独自に回避しない。
	if( controlType != CTRL_C_EVENT && controlType != CTRL_BREAK_EVENT) {
		return FALSE ;
	}

	cancellationRequested.store( true) ;
	return TRUE ;
}

/** @brief Workerより長く生存するmessage-only HWNDとconsole handlerを所有する。 */
class DiagnosticWindow final {
public:
	/** @brief Windowを非表示で生成し、成功した登録だけを所有する。 */
	DiagnosticWindow() noexcept
	{
		window_ = CreateWindowExW( 0U, L"STATIC", L"", 0U, 0, 0, 0, 0, HWND_MESSAGE, nullptr,
								  GetModuleHandleW( nullptr), nullptr) ;
		// HWNDがない場合はhandlerも開始せず初期化失敗を返す。
		if( window_) {
			handler_ = SetConsoleCtrlHandler( consoleControl, TRUE) != FALSE ;
		}
	}
	/** @brief Worker停止後に通知先を破棄し、今回登録したhandlerだけを解除する。 */
	~DiagnosticWindow() noexcept
	{
		// 自分で登録した取消しhandlerだけを解除する。
		if( handler_) {
			static_cast<void>( SetConsoleCtrlHandler( consoleControl, FALSE)) ;
		}

		// HWND破棄はWorkerのjoin後に限定する。
		if( window_) {
			static_cast<void>( DestroyWindow( window_)) ;
		}
	}
	/**
	 * @brief 通知先HWNDと取消しhandlerの解除責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	DiagnosticWindow( const DiagnosticWindow &) = delete ;
	/**
	 * @brief 通知先HWNDと取消しhandlerの解除責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	DiagnosticWindow &operator=( const DiagnosticWindow &) = delete ;
	/** @brief 初期化済みの通知先を借用する。@return 失敗時はnullptr。 */
	HWND			  get() const noexcept
	{
		return window_ ;
	}

private:
	/// Worker停止まで所有する通知先。作成失敗はnull。
	HWND window_{} ;
	/// 今回console handlerを登録した場合だけtrue。
	bool handler_{} ;
} ;

/**
 * @brief 完全構築済みの有限reportを一回だけ書き込む。
 * @param[in] value 最大1 MiBの非機密ASCII出力。
 * @return 全byte書込みとflushが成功した場合true。部分writeを再送しない。
 */
bool writeOutput( const std::string &value)
{
	// 過大または空出力を成功として扱わない。
	if( value.empty() || value.size() > drivercrate::METADATA_SEARCH_REPORT_MAXIMUM_BYTES) {
		return false ;
	}

	std::cout.write( value.data(), static_cast<std::streamsize>( value.size())) ;
	std::cout.flush() ;
	return static_cast<bool>( std::cout) ;
}

/**
 * @brief 固定の拒否分類だけを出力し、端末や引数の内容を漏らさない。
 * @param[in] reason 呼出元の固定literalだけの拒否理由。
 * @return 入力・結果・出力拒否を表す3。
 */
int reject( const std::string_view reason)
{
	static_cast<void>( writeOutput(
		"record=metadata_search_failure\nschema_revision=1\nreason=" + std::string( reason) + "\n")) ;
	return 3 ;
}

/**
 * @brief UIと同じWorker／Controller境界から情報検索を一回だけ実行する。
 * @param[in] request 解析済みの非空・専用集合と今回の回線判断。
 * @return 全正常0、有効な部分／失敗／取消しreportは2、有効reportなしは3。
 */
int runOnce( const drivercrate::MetadataSearchRequest &request)
{
	DiagnosticWindow window ;	// この所有者より先にWorkerを破棄する。
	// 通知先を用意できなければ列挙や通信を開始しない。
	if( !window.get()) {
		return reject( "notification_initialization_failed") ;
	}

	drivercrate::OperationController controller ;					// 製品UIと同じ専用状態機械。
	const auto begin = controller.beginMetadataSearch( request) ;	// 条件を固定した一操作。
	// 登録driftは実行集合を減らす理由にせず全体拒否する。
	if( !begin.accepted) {
		return reject( "request_rejected") ;
	}

	drivercrate::ProviderWorker worker( window.get(), WORKER_MESSAGE) ;	// COM MTAの所有者。
	// Command受付失敗で通常scanへ切り替えない。
	if( !worker.requestMetadataSearch( begin.operationId, request)) {
		return reject( "worker_request_rejected") ;
	}

	std::optional<drivercrate::ScanResult> result ;	// 同じ操作の確定結果だけを保持する。
	bool cancelSent{} ;								// 同じoperationへ一回だけ取消しを通知する。
	bool eventRejected{} ;							// 不正な別用途の終端を受理しない。
	// Contextの300秒deadlineと利用者取消しで協調停止し、同期APIを強制終了しない。
	while( !result && !eventRejected) {
		// Ctrl+Cは新規runや通常scanの中止へ転用しない。
		if( cancellationRequested.load() && !cancelSent) {
			cancelSent = worker.requestMetadataSearchCancel( begin.operationId) ;
			// 受付が確定した取消しだけをUI状態にも反映する。
			if( cancelSent) {
				static_cast<void>( controller.markMetadataSearchCancelling( begin.operationId)) ;
			}
		}

		// 有限な到着queueを一巡し、同じoperationの専用終端だけを採用する。
		for( auto &event : worker.takeEvents()) {
			// 別operationの通知を今回の計測へ混入させない。
			if( event.operationId != begin.operationId) {
				eventRejected = true ;
				break ;
			}

			// Progressは結果件数として出力しない。
			if( event.kind == drivercrate::WorkerEventKind::PROGRESS) {
				continue ;
			}

			// 準備・導入・通常scanの終端は専用runでは契約違反になる。
			if( event.kind != drivercrate::WorkerEventKind::METADATA_SEARCH_COMPLETED || result) {
				eventRejected = true ;
				break ;
			}

			result = std::move( event.scanResult) ;
		}

		// 完了した後に待機や取消しを追加しない。
		if( result || eventRejected) {
			break ;
		}

		const DWORD wait = MsgWaitForMultipleObjectsEx(
			0U, nullptr, 250U, QS_ALLINPUT,
			MWMO_INPUTAVAILABLE) ;	// 非表示Windowの通知も処理する有限待機。
		// 待機API失敗時もworker.stopが安全地点まで待つ。
		if( wait == WAIT_FAILED) {
			eventRejected = true ;
			break ;
		}

		MSG message{} ;	// 主threadの有限queueをdispatchする。
		// その時点で到着済みのmessageだけを処理する。
		while( PeekMessageW( &message, nullptr, 0U, 0U, PM_REMOVE) != FALSE) {
			// 終了要求を新しい検索へ変換せず取消しへ送る。
			if( message.message == WM_QUIT) {
				cancellationRequested.store( true) ;
				continue ;
			}

			static_cast<void>( TranslateMessage( &message)) ;
			static_cast<void>( DispatchMessageW( &message)) ;
		}
	}

	worker.stop() ;
	// Eventやsummaryが欠けた場合は0件の有効測定を生成しない。
	if( eventRejected || !result || !controller.completeMetadataSearch( begin.operationId, *result) ||
	   !controller.metadataSearchSummary()) {
		return reject( "result_contract_rejected") ;
	}

	std::string report ;	// 全検証後に一回だけ外へ出す非機密本文。
	// CMake版・request・snapshotを完全一致させる。
	if( !drivercrate::buildMetadataSearchReport( begin.operationId, DRIVERCRATE_VERSION_WSTRING,
											   request, *result, report)) {
		return reject( "report_contract_rejected") ;
	}

	// 部分write後に別の診断を同じstreamへ追記しない。
	if( !writeOutput( report)) {
		return 3 ;
	}

	return result->outcome == drivercrate::OutcomeCode::SUCCESS ? 0 : 2 ;
}
} // namespace

/**
 * @brief 引数なしでは条件表示だけを行うtest専用入口。
 * @param[in] argumentCount Windowsが渡す引数数。最大131個。
 * @param[in] arguments Process lifetime中有効な引数。先頭は実行file名で出力しない。
 * @return 条件表示または全正常0、有効な非正常report2、契約／出力拒否3。
 */
int wmain( const int argumentCount, wchar_t **arguments)
{
	try {
		// 過大な引数列をcopyする前に拒否する。
		if( argumentCount < 1 || argumentCount > 131 || !arguments) {
			return reject( "arguments_rejected") ;
		}

		std::vector<std::wstring_view> inputs ;	// argvの借用viewだけを解析期間中保持する。
		// 実行file名を除いた各引数を最大131個まで収集する。
		for( int index = 1; index < argumentCount; ++index) {
			// Nullを空のProvider IDへ補完しない。
			if( !arguments[index]) {
				return reject( "arguments_rejected") ;
			}

			inputs.emplace_back( arguments[index]) ;
		}

		const auto command = drivercrate::parseMetadataSearchArguments( inputs) ;	// I/O前の純粋検証。
		// 条件表示ではWorker、cost API、cache、deviceを初期化しない。
		if( command.kind == drivercrate::MetadataSearchCommandKind::DESCRIBE) {
			std::string description ;	// 固定値だけの完全な説明。
			return drivercrate::buildMetadataSearchDescription( description) &&
						   writeOutput( description)
					   ? 0
					   : 3 ;
		}

		// 不明な引数を表示したり自動で既定集合へ代用したりしない。
		if( command.kind != drivercrate::MetadataSearchCommandKind::RUN) {
			return reject( "arguments_rejected") ;
		}

		return runOnce( command.request) ;
	} catch( ...) {
		// 例外内容は任意のpath等を含み得るため出力しない。
		return reject( "unexpected_failure") ;
	}
}
