//------------------------------------------------------------------------------
/**
 * @file main_window_metadata_search.cpp
 * @brief 情報検索の対象確認・協調取消し・表示専用結果。
 * @version 01.00.02
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
 * Ver.01.00.01 Shunji Ogawa  2026/09/15  対応Provider件数に依存しない説明へ更新。
 * Ver.01.00.02  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note 一覧は端末内で表示し、詳細診断には端末識別値・URL・path・EULA本文を含めない。
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#include "app/main_window.h"

#include "app/resource.h"
#include "core/metadata_search.h"
#include "core/provider_registry.h"
#include "platform/windows_error.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <initializer_list>
#include <numeric>
#include <string>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

/**
 * @brief Resourceの位置placeholderへ表示値を一回ずつ代入する。
 * @param[in] text 信頼できるresource由来の書式。
 * @param[in] fields 数値またはresource由来の各表示値。
 * @return 位置指定を置換した所有文字列。
 */
std::wstring formatMetadataFields( std::wstring								text,
								  const std::initializer_list<std::wstring> fields)
{
	std::size_t index{} ;	// Resourceの0始まりplaceholder番号。
	// 固定個数の表示値だけを置換し、挿入値を再帰的な書式として解釈しない。
	for( const auto &field : fields) {
		const auto token	= L"{" + std::to_wstring( index++) + L"}" ;	// 対応する固定placeholder。
		const auto position = text.find( token) ;						// 元resourceにある一回の置換位置。
		// 未指定placeholderは任意値の追加表示へ変換しない。
		if( position != std::wstring::npos) {
			text.replace( position, token.size(), field) ;
		}
	}

	return text ;
}

/**
 * @brief 有限の非機密結果を標準read-only editへ表示する。
 * @param[in] dialog 同期dialogの非所有handle。
 * @param[in] message Windows message。
 * @param[in] wordParameter Button ID。
 * @param[in] longParameter 初期化時だけ有効な所有文字列の借用pointer。
 * @return 処理済みならTRUE。
 */
INT_PTR CALLBACK metadataDetailsProc( const HWND dialog, const UINT message,
									 const WPARAM wordParameter,
									 const LPARAM longParameter) noexcept
{
	// 表示本文を一回copyし、dialog外へ借用pointerを保存しない。
	if( message == WM_INITDIALOG) {
		// DialogBoxParamの同期期間だけ生存する呼出元の文字列である。
		const auto *text = reinterpret_cast<const std::wstring *>( longParameter) ;
		// 必須の本文を表示できなければ不完全な成功画面を残さない。
		if( !text || !SetDlgItemTextW( dialog, IDC_METADATA_DETAIL_TEXT, text->c_str())) {
			EndDialog( dialog, -1) ;
			return TRUE ;
		}

		SendDlgItemMessageW( dialog, IDC_METADATA_DETAIL_TEXT, EM_SETSEL, 0, 0) ;
		return TRUE ;
	}

	// Enter、Escape、closeはいずれも表示終了だけを行う。
	if( message == WM_CLOSE || (message == WM_COMMAND && (LOWORD( wordParameter) == IDOK ||
														 LOWORD( wordParameter) == IDCANCEL))) {
		EndDialog( dialog, IDOK) ;
		return TRUE ;
	}

	return FALSE ;
}

/** @brief 同期dialogの間だけ所有する、今回限りの情報検索条件。 */
struct MetadataDialogState {
	/// 同期呼出し中に生存する非所有MainWindow。
	MainWindow				*owner{} ;
	/// 承認時だけ返す明示集合と回線判断。既定は全未選択。
	MetadataSearchRequest	 request ;
	/// 表示行から正本registryへ対応するindex。別Provider一覧を持たない。
	std::vector<std::size_t> registrationIndexes ;
	/// Listview初期化中の通知で利用者選択を処理しない。
	bool					 initializing{true} ;
} ;

/** @brief 例外を含む同期dialog終了時に再入禁止flagを戻す。 */
class MetadataDialogReviewScope final {
public:
	/** @brief 呼出し期間だけflagを有効にする。@param[in,out] flag 同期scopeより長生きする借用flag。 */
	explicit MetadataDialogReviewScope( bool &flag) noexcept : flag_( flag)
	{
		flag_ = true ;
	}
	/** @brief Window操作へ戻る前に再入禁止を解除する。 */
	~MetadataDialogReviewScope() noexcept
	{
		flag_ = false ;
	}
	/**
	 * @brief 再入禁止flagの解除責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	MetadataDialogReviewScope( const MetadataDialogReviewScope &) = delete ;
	/**
	 * @brief 再入禁止flagの解除責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	MetadataDialogReviewScope &operator=( const MetadataDialogReviewScope &) = delete ;

private:
	/// UI threadだけが操作する借用flag。
	bool &flag_ ;
} ;

} // namespace

/** @see src/app/main_window.h */
INT_PTR CALLBACK MainWindow::metadataSearchDialogProc( const HWND dialog, const UINT message,
													  const WPARAM wordParameter,
													  const LPARAM longParameter) noexcept
{
	try {
		// DWLP_USERはこの同期dialogの期間だけ生存するstack上の非所有snapshotである。
		auto *state =
			message == WM_INITDIALOG
				? reinterpret_cast<MetadataDialogState *>( longParameter)
				: reinterpret_cast<MetadataDialogState *>( GetWindowLongPtrW( dialog, DWLP_USER)) ;
		// 初期化前または所有元がない通知からrequestを作らない。
		if( !state || !state->owner) {
			return FALSE ;
		}

		const auto descriptors = builtInProviderDescriptors() ;				// 正本のprocess lifetime view。
		const HWND list = GetDlgItem( dialog, IDC_METADATA_PROVIDER_LIST) ;	// Dialog所有の標準一覧。
		// 現在のcheckだけを数え、前runの設定や同意を読み込まない。
		const auto updateCount = [state, descriptors, dialog, list]() {
			std::size_t count{} ;	// 今回checkした専用Provider数。
			// 最大64登録の表示indexを正本へ照合する。
			for( std::size_t row = 0U; row < state->registrationIndexes.size(); ++row) {
				const auto index = state->registrationIndexes[row] ;	// 正本の非機密index。
				// 非対応の必須inventoryや通常機能を公式選択へ数えない。
				if( index < descriptors.size() && isMetadataSearchProvider( descriptors[index]) &&
				   ListView_GetItemState( list, static_cast<int>( row), LVIS_STATEIMAGEMASK) ==
					   INDEXTOSTATEIMAGEMASK( 2)) {
					++count ;
				}
			}

			const auto caption = state->owner->formatResource( IDS_METADATA_SELECTED_COUNT,
															  // Resourceだけから構築する件数説明。
															  std::to_wstring( count)) ;
			SetDlgItemTextW( dialog, IDC_METADATA_SELECTION_STATUS, caption.c_str()) ;
			EnableWindow( GetDlgItem( dialog, IDYES), count != 0U) ;
		} ;

		// 正本descriptorから対応Providerを先に並べ、その他も未対応理由付きで残す。
		if( message == WM_INITDIALOG) {
			// 表示が不完全なら通信同意を取得しない。
			if( !list || descriptors.empty() ||
			   descriptors.size() > METADATA_SEARCH_PROVIDER_LIMIT) {
				EndDialog( dialog, IDCANCEL) ;
				return TRUE ;
			}

			SetLastError( ERROR_SUCCESS) ;
			// Win32のpointer-sized storageへ借用pointerを同期期間だけ保持する。
			if( SetWindowLongPtrW( dialog, DWLP_USER, reinterpret_cast<LONG_PTR>( state)) == 0 &&
			   GetLastError() != ERROR_SUCCESS) {
				EndDialog( dialog, IDCANCEL) ;
				return TRUE ;
			}

			state->request = {} ;
			state->registrationIndexes.resize( descriptors.size()) ;
			std::iota( state->registrationIndexes.begin(), state->registrationIndexes.end(), 0U) ;
			std::stable_sort( state->registrationIndexes.begin(), state->registrationIndexes.end(),
							 [descriptors]( const auto left, const auto right) {
								 return isMetadataSearchProvider( descriptors[left]) >
										isMetadataSearchProvider( descriptors[right]) ;
							 }) ;
			ListView_SetExtendedListViewStyle( list, LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT |
														LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP) ;
			RECT bounds{} ;	// DPI反映済みのlistview物理幅。
			GetClientRect( list, &bounds) ;
			const std::array<UINT, 2> columns{IDS_SOURCE_LABEL,
											  IDS_METADATA_MODE_COLUMN} ;	// 固定見出し。
			// 左にProvider名、右にこのmodeの対応可否を表示する。
			for( std::size_t index = 0U; index < columns.size(); ++index) {
				auto title =
					// 同期挿入中だけ有効なcaption。
					state->owner->loadString( columns[index]) ;
				LVCOLUMNW column{} ;	// 標準listviewの一column。
				column.mask	   = LVCF_TEXT | LVCF_WIDTH ;
				column.pszText = title.data() ;
				column.cx	   = static_cast<int>( bounds.right * (index == 0U ? 58 : 40) / 100) ;
				// 見出しや用途列の欠落を許可して選択を受け取らない。
				if( ListView_InsertColumn( list, static_cast<int>( index), &column) == -1) {
					EndDialog( dialog, IDCANCEL) ;
					return TRUE ;
				}
			}

			// 全registryを同じindex対応で一回だけ表示する。
			for( std::size_t row = 0U; row < state->registrationIndexes.size(); ++row) {
				const auto &descriptor = descriptors[state->registrationIndexes[row]] ;	// 固定登録。
				std::wstring title = descriptor.displayName ;							// Windowsが同期copyする所有文字列。
				LVITEMW		 item{} ;													// Provider行の追加条件。
				item.mask	 = LVIF_TEXT ;
				item.iItem	 = static_cast<int>( row) ;
				item.pszText = title.data() ;
				// 一行欠けた一覧ではIndexと同意を対応付けられないため中止する。
				if( ListView_InsertItem( list, &item) != static_cast<int>( row)) {
					EndDialog( dialog, IDCANCEL) ;
					return TRUE ;
				}

				const bool supported = isMetadataSearchProvider( descriptor) ;	// 専用能力の判定。
				auto	   mode		 = state->owner->loadString(
					   supported ? IDS_METADATA_SUPPORTED
					   : descriptor.id == DRIVER_STORE_PROVIDER_ID
						   ? IDS_METADATA_INVENTORY_DEPENDENCY
						   : IDS_METADATA_UNSUPPORTED) ;	// 通常機能の廃止と誤解させない説明。
				LVITEMW description{} ;						// 第二columnも表示できたことを検査する。
				description.iSubItem = 1 ;
				description.pszText	 = mode.data() ;
				// 用途の説明なしに選択可能な行を残さない。
				if( SendMessageW( list, LVM_SETITEMTEXTW, row,
								reinterpret_cast<LPARAM>( &description)) == FALSE) {
					EndDialog( dialog, IDCANCEL) ;
					return TRUE ;
				}

				ListView_SetItemState( list, static_cast<int>( row),
									  supported ? INDEXTOSTATEIMAGEMASK( 1) : 0U,
									  LVIS_STATEIMAGEMASK) ;
			}

			CheckDlgButton( dialog, IDC_METADATA_NETWORK_APPROVAL, BST_UNCHECKED) ;
			state->initializing = false ;
			updateCount() ;
			SetFocus( list) ;
			return FALSE ;
		}

		// 標準listviewのkeyboard／mouse操作も専用能力へ拘束する。
		if( message == WM_NOTIFY && !state->initializing && longParameter != 0) {
			// Win32が同期通知中だけ所有するNMHDR。Callback後に保存しない。
			const auto *notice = reinterpret_cast<const NMHDR *>( longParameter) ;
			// 他controlの通知をlistviewの状態変更として解釈しない。
			if( notice->hwndFrom == list && notice->code == LVN_ITEMCHANGING) {
				// 同じ通知bufferをWindows定義の詳細構造として参照する。
				const auto *change = reinterpret_cast<const NMLISTVIEW *>( longParameter) ;
				// 未対応行はstate imageを復活させず、keyboard Spaceによるcheckも拒否する。
				if( (change->uChanged & LVIF_STATE) != 0U &&
				   ((change->uNewState ^ change->uOldState) & LVIS_STATEIMAGEMASK) != 0U &&
				   (change->iItem < 0 ||
					static_cast<std::size_t>( change->iItem) >= state->registrationIndexes.size() ||
					!isMetadataSearchProvider(
						descriptors[state->registrationIndexes[static_cast<std::size_t>(
							change->iItem)]]))) {
					SetWindowLongPtrW( dialog, DWLP_MSGRESULT, TRUE) ;
					return TRUE ;
				}
			}

			// 確定した状態変更の後でだけ選択件数と開始可否を更新する。
			if( notice->hwndFrom == list && notice->code == LVN_ITEMCHANGED) {
				updateCount() ;
				return TRUE ;
			}
		}

		// 明示開始時に、表示した有限集合からだけ新しいrequestを作る。
		if( message == WM_COMMAND && LOWORD( wordParameter) == IDYES) {
			MetadataSearchRequest request ;	// 前回同意を継承しない一回限りのcopy。
			// 全表示行を正本indexへ照合し、未選択行を実行集合へ含めない。
			for( std::size_t row = 0U; row < state->registrationIndexes.size(); ++row) {
				// Checkなしの行は依存inventoryも含めて明示集合へ追加しない。
				if( ListView_GetItemState( list, static_cast<int>( row), LVIS_STATEIMAGEMASK) !=
				   INDEXTOSTATEIMAGEMASK( 2)) {
					continue ;
				}

				const auto &descriptor =
					descriptors[state->registrationIndexes[row]] ;	// 選択した正本。
				// UIのdisable表示だけに依存せず未対応checkの注入を拒否する。
				if( !isMetadataSearchProvider( descriptor)) {
					return TRUE ;
				}

				request.enabledProviderIds.push_back( descriptor.id) ;
			}

			request.restrictedNetworkApproved =
				IsDlgButtonChecked( dialog, IDC_METADATA_NETWORK_APPROVAL) == BST_CHECKED ;
			// 未選択・登録矛盾では開始buttonへの合成commandも受理しない。
			if( !validateMetadataSearchRequest( request, descriptors)) {
				return TRUE ;
			}

			state->request = std::move( request) ;
			EndDialog( dialog, IDYES) ;
			return TRUE ;
		}

		// 閉じる操作とEscapeを検索の承認へ変換しない。
		if( message == WM_CLOSE || (message == WM_COMMAND && LOWORD( wordParameter) == IDCANCEL)) {
			EndDialog( dialog, IDCANCEL) ;
			return TRUE ;
		}

		return FALSE ;
	} catch( ...) {
		// 文字列確保や初期化例外をWin32境界へ漏らさず、同意未取得のまま中止する。
		EndDialog( dialog, IDCANCEL) ;
		return TRUE ;
	}
}

/** @see src/app/main_window.h */
bool MainWindow::showMetadataSearchDialog( MetadataSearchRequest &request)
{
	// 他の確認中に再入して今回の同意対象を差し替えない。
	if( metadataReviewOpen_ || preparationReviewOpen_ || closing_) {
		return false ;
	}

	MetadataDialogReviewScope review( metadataReviewOpen_) ;	// 全正常・例外終了で再入flagを解除。
	MetadataDialogState		  state{.owner = this} ;			// Dialogより長生きするstack所有snapshot。
	// LPARAMに渡す非所有pointerは同期DialogBoxが終了するまで有効である。
	const INT_PTR			  response =
		DialogBoxParamW( instance_, MAKEINTRESOURCEW( IDD_METADATA_SEARCH), window_,
						metadataSearchDialogProc, reinterpret_cast<LPARAM>( &state)) ;
	// Resource作成失敗を未選択の正常な取消しと区別して通知する。
	if( response == -1) {
		const DWORD error = GetLastError() ;	// Dialog生成直後の元診断。
		// 任意Provider文字列を含めない、表示生成失敗の診断本文。
		const auto	text = loadString( IDS_METADATA_FAILED) + L"\n\n" +
						  formatNativeError( static_cast<NativeError>(
							  error == ERROR_SUCCESS ? E_UNEXPECTED : HRESULT_FROM_WIN32( error))) ;
		MessageBoxW( window_, text.c_str(), loadString( IDS_METADATA_DIALOG_TITLE).c_str(),
					MB_OK | MB_ICONERROR) ;
	}

	// 明示開始と完全な入力契約がそろった場合だけ呼出元の要求を置き換える。
	if( response != IDYES ||
	   !validateMetadataSearchRequest( state.request, builtInProviderDescriptors())) {
		return false ;
	}

	request = std::move( state.request) ;
	return true ;
}

/** @see src/app/main_window.h */
void MainWindow::handleMetadataSearchCommand()
{
	// Modal確認・終了待ち中の合成commandも新しい同意へ変換しない。
	if( closing_ || metadataReviewOpen_ || preparationReviewOpen_ || closeAfterMetadataSearch_) {
		return ;
	}

	const auto state = controller_.state() ;	// 今回の検索を開始する前のUI状態。
	// 同じ専用operationの開始buttonは協調取消しの操作へ切り替える。
	if( controller_.scanPurpose() == ScanPurpose::METADATA_ONLY &&
	   state == ApplicationState::SCANNING) {
		cancelMetadataSearch() ;
		return ;
	}

	// 処理中に条件dialogを開かず、完了状態だけから新しい要求を受け取る。
	if( state != ApplicationState::IDLE && state != ApplicationState::SCAN_READY &&
	   state != ApplicationState::COMPLETED && state != ApplicationState::FAILURE) {
		return ;
	}

	MetadataSearchRequest request ;	// 全未選択・制限回線の許可なしで開始する今回の条件。
	// 取消しや不正な条件では旧sessionを失効させない。
	if( !showMetadataSearchDialog( request)) {
		return ;
	}

	const auto begin = controller_.beginMetadataSearch( request) ;	// 要求検証と旧権限の失効。
	// 状態機械が拒否した要求はworkerへ送信しない。
	if( !begin.accepted) {
		return ;
	}

	preparationApproval_ = {} ;
	preparationResultText_.clear() ;
	providerReports_.clear() ;
	candidates_.clear() ;
	candidateSelected_.clear() ;
	localCoverage_.clear() ;
	scanOutcome_		 = OutcomeCode::NOT_STARTED ;
	showRecommendedOnly_ = false ;
	SendMessageW( recommendedOnlyCheckbox_, BM_SETCHECK, BST_UNCHECKED, 0) ;
	populateCandidates( candidates_) ;
	SetWindowTextW( header_, loadString( IDS_METADATA_HEADER).c_str()) ;
	updateMetadataSearchColumns() ;
	updateProviderSourcesCaption() ;
	setStatus( loadString( IDS_METADATA_SCANNING), true) ;
	updateCommandState() ;
	// Queue拒否も同じ専用完了経路で失敗へ移し、通常scanへfallbackしない。
	if( !worker_ || !worker_->requestMetadataSearch( begin.operationId, std::move( request))) {
		WorkerEvent failure ;	// 表示用summaryを持たない専用の拒否event。
		failure.kind			   = WorkerEventKind::METADATA_SEARCH_COMPLETED ;
		failure.operationId		   = begin.operationId ;
		failure.scanResult.purpose = ScanPurpose::METADATA_ONLY ;
		failure.scanResult.outcome = OutcomeCode::FAILURE ;
		failure.scanResult.error   = static_cast<NativeError>( E_UNEXPECTED) ;
		processMetadataSearchCompleted( failure) ;
	}
}

/** @see src/app/main_window.h */
void MainWindow::cancelMetadataSearch()
{
	const auto operation = controller_.activeOperationId() ;	// 同operationだけを取消し対象にする。
	// 取消し待ちを重ねても終了確認flagと表示は更新できるようにする。
	if( controller_.scanPurpose() != ScanPurpose::METADATA_ONLY ||
	   (controller_.state() != ApplicationState::SCANNING &&
		controller_.state() != ApplicationState::CANCELLING_METADATA_SEARCH)) {
		return ;
	}

	// 完了eventが既にqueueにある場合も、その受信までWindowを維持する。
	if( worker_) {
		static_cast<void>( worker_->requestMetadataSearchCancel( operation)) ;
	}

	static_cast<void>( controller_.markMetadataSearchCancelling( operation)) ;
	SetWindowTextW( status_, loadString( IDS_METADATA_CANCELLING).c_str()) ;
	InvalidateRect( status_, nullptr, TRUE) ;
	updateCommandState() ;
}

/** @see src/app/main_window.h */
void MainWindow::processMetadataSearchCompleted( const WorkerEvent &event)
{
	// 型・用途・operationを通常完了と混用せず、旧eventを表示へ適用しない。
	if( event.kind != WorkerEventKind::METADATA_SEARCH_COMPLETED ||
	   !controller_.completeMetadataSearch( event.operationId, event.scanResult)) {
		return ;
	}

	const bool valid = controller_.metadataSearchSummary() != nullptr ;	// 全体契約の検証結果。
	candidates_.clear() ;
	providerReports_.clear() ;
	localCoverage_.clear() ;
	// 成功だけでなく取消し・失敗の有効な部分結果も表示専用で保持する。
	if( valid) {
		candidates_		 = event.scanResult.candidates ;
		providerReports_ = event.scanResult.providerReports ;
		localCoverage_	 = event.scanResult.localCoverage ;
	}

	candidateSelected_.assign( candidates_.size(), false) ;
	scanOutcome_ = valid ? event.scanResult.outcome : OutcomeCode::FAILURE ;
	populateCandidates( candidates_) ;
	updateMetadataSearchStatus() ;
	updateCommandState() ;
	// 構造不正とqueue拒否は検索0件の成功にせず、安全な再実行方法と診断を示す。
	if( !valid && !closeAfterMetadataSearch_) {
		const auto text =
			loadString( IDS_METADATA_FAILED) + L"\n\n" +
			formatNativeError(
				event.scanResult.error == 0
					? static_cast<NativeError>( E_INVALIDARG)
					: event.scanResult.error) ;	// 任意Provider文字列を使わない固定説明。
		MessageBoxW( window_, text.c_str(), loadString( IDS_METADATA_DETAILS).c_str(),
					MB_OK | MB_ICONERROR) ;
	}

	// 完了eventの受理後にだけjoinとHWND破棄へ進む。
	if( closeAfterMetadataSearch_) {
		closeAfterMetadataSearch_ = false ;
		requestClose() ;
	}
}

/** @see src/app/main_window.h */
void MainWindow::updateMetadataSearchColumns()
{
	const bool metadata = controller_.scanPurpose() == ScanPurpose::METADATA_ONLY ;	// 見出しの用途。
	const std::array<std::pair<int, UINT>, 2> columns{
		{{2, metadata ? IDS_METADATA_DISTRIBUTION_COLUMN : IDS_COLUMN_CANDIDATE_VERSION},
		 {5,
		  metadata ? IDS_METADATA_DISTRIBUTION_DATE : IDS_COLUMN_DATE}}} ;	// 同じ列位置だけを更新。
	// 版と日付だけを用途に合わせ、列幅・利用者sortは維持する。
	for( const auto &[index, resource] : columns) {
		auto	text = loadString( resource) ;	// 同期Header message中だけ借用するcaption。
		HDITEMW item{} ;						// Captionだけの変更条件。
		item.mask	 = HDI_TEXT ;
		item.pszText = text.data() ;
		Header_SetItem( treeHeader_, index, &item) ;
	}
}

/** @see src/app/main_window.h */
std::wstring MainWindow::metadataSearchReasonText( const MetadataSearchReason reason) const
{
	// 新modeの停止と非実行を通常の更新有無へ置き換えない。
	switch( reason) {
		// 正常終端でも適用性と最新性は未確認と明示する。
		case MetadataSearchReason::COMPLETED:
			return loadString( IDS_METADATA_COMPLETED) ;
		// 取消し前に確定した部分情報を保持していることを示す。
		case MetadataSearchReason::CANCELLED:
			return loadString( IDS_METADATA_CANCELLED) ;
		// 固定予算による停止を通信障害と区別する。
		case MetadataSearchReason::BUDGET_EXCEEDED:
			return loadString( IDS_METADATA_BUDGET_STOP) ;
		// Deadlineの到達を即時停止の保証とは表現しない。
		case MetadataSearchReason::DEADLINE_EXCEEDED:
			return loadString( IDS_METADATA_DEADLINE_STOP) ;
		// 今回限りの制限回線許可がない非実行を示す。
		case MetadataSearchReason::NETWORK_NOT_APPROVED:
			return loadString( IDS_METADATA_NETWORK_BLOCKED) ;
		// 全体停止後の非実行を正常0件として表示しない。
		case MetadataSearchReason::NOT_RUN_AFTER_STOP:
			return loadString( IDS_METADATA_NOT_RUN) ;
		// 専用requestにないProviderは今回の未選択として表示する。
		case MetadataSearchReason::NOT_SELECTED:
			return loadString( IDS_PROVIDER_DISABLED) ;
		// Local probeまたは実OSの対象外を全hardware非対応と断定しない。
		case MetadataSearchReason::NOT_APPLICABLE:
			return loadString( IDS_PROVIDER_NOT_APPLICABLE) ;
		// 安全な再確認と再検索の案内を残す。
		case MetadataSearchReason::FAILED:
			return loadString( IDS_METADATA_FAILED) ;
		// 未知値を成功へ補完しない。
		default:
			return loadString( IDS_VALUE_UNKNOWN) ;
	}
}

/** @see src/app/main_window.h */
void MainWindow::updateMetadataSearchStatus()
{
	const auto *summary = controller_.metadataSearchSummary() ;	// 検証済み結果の非所有snapshot。
	// 完全なsummaryがない場合は情報0行を成功として案内しない。
	if( !summary) {
		setStatus( loadString( IDS_METADATA_FAILED), false) ;
		return ;
	}

	auto reason = metadataSearchReasonText( summary->reason) ;	// 主停止原因を保持する説明。
	// Provider単位の失敗を全体のCOMPLETED理由で隠さない。
	if( summary->reason == MetadataSearchReason::COMPLETED && scanOutcome_ != OutcomeCode::SUCCESS) {
		reason = loadString( IDS_METADATA_PARTIAL) ;
	}

	const auto current = static_cast<std::size_t>(
		std::count_if( candidates_.begin(), candidates_.end(), []( const auto &candidate) {
			return candidate.current ;
		})) ; // 現在属性の表示行数。
	setStatus( formatMetadataFields( loadString( IDS_METADATA_SUMMARY),
								   {reason, std::to_wstring( current),
									std::to_wstring( candidates_.size() - current)}),
			  false) ;
}

/** @see src/app/main_window.h */
void MainWindow::showMetadataSearchDetails() const
{
	const auto *summary = controller_.metadataSearchSummary() ;	// 次の明示検索まで保持する条件。
	// 未検証または未実行の値から詳細診断を生成しない。
	if( !summary) {
		MessageBoxW( window_, loadString( IDS_METADATA_FAILED).c_str(),
					loadString( IDS_METADATA_DETAILS).c_str(), MB_OK | MB_ICONWARNING) ;
		return ;
	}

	std::wstring text = loadString( IDS_METADATA_VIEW_ONLY) + L"\r\n\r\n" +
						metadataSearchReasonText( summary->reason) +
						L"\r\n" ;	// 端末内だけの非機密詳細。
	text += formatMetadataFields( loadString( IDS_METADATA_DETAIL_CONDITIONS),
								 {loadString( summary->request.restrictedNetworkApproved
												 ? IDS_METADATA_APPROVED
												 : IDS_METADATA_NOT_APPROVED)}) +
			L"\r\n" ;
	text += formatMetadataFields(
				loadString( IDS_METADATA_DETAIL_INVENTORY),
				{loadString( summary->inventoryComplete ? IDS_METADATA_INVENTORY_COMPLETE
													   : IDS_METADATA_INVENTORY_PARTIAL),
				 std::to_wstring( summary->elapsedMilliseconds)}) +
			L"\r\n" ;
	// 計測は同じoperationで検証済みのsnapshotだけを表示する。
	if( const auto *measurement = controller_.scanMeasurement()) {
		const auto inventory =
			formatMeasurementCount( measurement->inventory.enumeratedDeviceCount) + L" / " +
			formatMeasurementCount( measurement->inventory.representedDeviceCount) + L" / " +
			formatMeasurementCount(
				measurement->inventory.unrepresentedDeviceCount) ;	// 観測・D・未収録の確定度。
		text += formatResource( IDS_MEASUREMENT_INVENTORY, inventory) + L"\r\n" +
				formatResource( IDS_MEASUREMENT_NETWORK_OFFICIAL,
							   formatStageMeasurement( measurement->network.official)) +
				L"\r\n" + loadString( IDS_MEASUREMENT_EXPLANATION) + L"\r\n" ;
	}

	const auto formatUsage = [this]( const MetadataSearchUsage &usage) {
		return formatMetadataFields(
			loadString( IDS_METADATA_PROVIDER_USAGE),
			{std::to_wstring( usage.bodyBytes), std::to_wstring( usage.probeBytes),
			 std::to_wstring( usage.logicalResources), std::to_wstring( usage.httpAttempts)}) ;
	} ; // 成功resource数とは独立した実消費量。
	text += formatUsage( summary->usage) + L"\r\n\r\n" ;
	// 全registryを正本順に示し、未選択と未対応も省略しない。
	for( const auto &descriptor : builtInProviderDescriptors()) {
		const auto found = std::find_if( summary->providers.begin(), summary->providers.end(),
										[&descriptor]( const auto &provider) {
											return provider.providerId == descriptor.id ;
										}) ; // 正本IDの対応。
		// 完全検証後のsnapshotでも未知の対応を推測して表示しない。
		if( found == summary->providers.end()) {
			continue ;
		}

		text +=
			descriptor.displayName + L"\r\n" + metadataSearchReasonText( found->reason) + L"\r\n" ;
		const auto report = std::find_if( providerReports_.begin(), providerReports_.end(),
										 [&descriptor]( const auto &entry) {
											 return entry.descriptor.id == descriptor.id ;
										 }) ; // 対応する既存分類。
		// 元のProvider失敗分類とHRESULTも主停止理由とは別に残す。
		if( report != providerReports_.end()) {
			text += providerStateText( report->state) + L" / " + formatNativeError( found->error) +
					L"\r\n" ;
		}

		text += formatUsage( found->usage) + L"\r\n\r\n" ;
	}

	// LPARAMの借用pointerは同期dialogが本文をcopyする間だけ使用する。
	const auto result = DialogBoxParamW(
		instance_, MAKEINTRESOURCEW( IDD_METADATA_DETAILS), window_, metadataDetailsProc,
		reinterpret_cast<LPARAM>( &text)) ;	// 標準editで選択・読み上げ・scrollを提供。
	// 表示生成失敗を空の正常詳細画面にしない。
	if( result == -1) {
		MessageBoxW( window_, loadString( IDS_METADATA_FAILED).c_str(),
					loadString( IDS_METADATA_DETAILS).c_str(), MB_OK | MB_ICONERROR) ;
	}
}

} // namespace drivercrate
