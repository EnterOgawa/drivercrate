//------------------------------------------------------------------------------
/**
 * @file main_window_preparation.cpp
 * @brief 公式配布物の取得確認と結果表示。
 * @version 01.04.00
 * @date 2026/09/06
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  候補一覧の原子的反映を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  候補発行状態と0件理由の表示を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  EULAの取得前提確認を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  監査合格候補の一覧反映を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の表示境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  EULA本文と取得再確認の境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得確認・取消し・結果表示を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  準備後もscan時点の計測snapshotを保持。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  同一EULA groupの一回表示を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  取得後監査で未取得時の候補詳細を失効。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  同operation索引の取得・内容・未接続結果を表示。
 * Ver.01.03.01 Shunji Ogawa  2026/10/12  索引summaryの元結果照合と有限内容状態の拒否を補強。
 * Ver.01.04.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * </pre>
 *
 * @note UI thread専用です。Payload URL・端末識別子は非表示で、EULA内のURLは文字列に限ります。
 */
//------------------------------------------------------------------------------

#include "app/main_window.h"

#include "app/resource.h"
#include "core/candidate_source_group.h"
#include "core/local_coverage.h"
#include "core/official_preparation.h"
#include "core/provider_registry.h"
#include "platform/windows_error.h"

#include <CommCtrl.h>
#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {
//------------------------------------------------------------------------------
/**
 * @brief 未知状態を成功へ変換せず、取得失敗として表示する。
 *
 * @param[in] state 検証済みの対象別終端状態。
 * @return 限定された取得状態を表すresource ID。
 */
//------------------------------------------------------------------------------
UINT preparationStateResource( const OfficialPreparationItemState state) noexcept
{
	// 未選択・取得済み・同意待ち・取消・拒否・失敗を個別のresourceへ変換する。
	switch( state) {
		// 未選択項目を取得失敗と区別して表示する。
		case OfficialPreparationItemState::NOT_SELECTED:
			return IDS_PREPARATION_NOT_SELECTED ;
		// 取得完了は内容監査待ちの表示とし、導入済みと扱わない。
		case OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION:
			return IDS_PREPARATION_ACQUIRED ;
		// 通信条件の同意待ちを取得中や失敗と区別する。
		case OfficialPreparationItemState::AWAITING_NETWORK_CONSENT:
			return IDS_PREPARATION_AWAITING_NETWORK ;
		// 協調取消しされた項目を専用状態で表示する。
		case OfficialPreparationItemState::CANCELLED:
			return IDS_PREPARATION_CANCELLED ;
		// 取得前提等の拒否を実行失敗と区別する。
		case OfficialPreparationItemState::REJECTED:
			return IDS_PREPARATION_REJECTED ;
		// その他と未知の状態は取得失敗として表示する。
		default:
			return IDS_PREPARATION_ITEM_FAILED ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 未知状態を候補ありまたは候補なし成功へ変換せず、発行失敗として表示する。
 *
 * @param[in] state 検証済みの候補発行到達状態。
 * @return 候補あり、未着手、対象なし、失敗を区別するresource ID。
 */
//------------------------------------------------------------------------------
UINT preparationPublicationResource(
	const OfficialPreparationCandidatePublicationState state) noexcept
{
	// 候補発行未実施・発行済み・適格候補なし・失敗を区別して表示する。
	switch( state) {
		// 候補公開を開始していない状態を専用表示にする。
		case OfficialPreparationCandidatePublicationState::NOT_STARTED:
			return IDS_PREPARATION_PUBLICATION_NOT_STARTED ;
		// 監査を経て候補を公開できた場合は準備完了を表示する。
		case OfficialPreparationCandidatePublicationState::CANDIDATES_PUBLISHED:
			return IDS_PREPARATION_AUDIT_READY ;
		// 公開できる組合せがない状態を実行失敗と区別する。
		case OfficialPreparationCandidatePublicationState::NO_ELIGIBLE_CANDIDATES:
			return IDS_PREPARATION_PUBLICATION_NONE ;
		// 未知の公開状態を候補あり・なしの成功へ変換しない。
		default:
			return IDS_PREPARATION_PUBLICATION_FAILED ;
	}
}

/**
 * @brief 一つの共有EULA tokenへ結合した今回だけのUI判断を保持する。
 */
struct ReviewedPreparationEula {
	/// Worker計画が発行した同一scan内だけのopaque group token。
	std::uint64_t token{} ;
	/// Group全対象で完全一致させるProvider stable ID。
	std::wstring  providerId ;
	/// Group全対象で完全一致させる元規約出典主体です。
	std::wstring  sourceSubject ;
	/// Group全対象で完全一致させるEULA revision。
	std::wstring  revision ;
	/// Group全対象で完全一致させるEULA本文。
	std::wstring  text ;
	/// 全文dialogで今回明示同意した場合だけtrue。
	bool		  accepted{} ;
} ;

/**
 * @brief 索引workerが実際に返す取得stateの変換だけを元transferへ対応させます。
 * @param[in] state 独立summaryが申告した取得終端。
 * @return 現workerと同じ元transfer状態。未開始・定義外は値なしです。
 */
std::optional<OfficialPreparationItemState> indexTransferState( const OfficialAcquisitionState state)
{
	// 取得成功・取消し・拒否を同名終端へ、その他の実失敗をFAILUREへ対応させます。
	switch( state) {
		// 実取得成功だけを取得済みへ結びます。
		case OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION:
			return OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION ;
		// 元取消しを一般失敗へ改変しません。
		case OfficialAcquisitionState::CANCELLED:
			return OfficialPreparationItemState::CANCELLED ;
		// 元拒否を実行失敗へ改変しません。
		case OfficialAcquisitionState::REJECTED:
			return OfficialPreparationItemState::REJECTED ;
		// 現索引workerはnetwork同意待ちも共通executorのFAILUREへ変換します。
		case OfficialAcquisitionState::AWAITING_NETWORK_CONSENT:
		// 実取得失敗も同じ共通executor終端へ対応させます。
		case OfficialAcquisitionState::FAILURE:
			return OfficialPreparationItemState::FAILURE ;
		// 未開始または定義外の申告から終端を補完しません。
		default:
			return std::nullopt ;
	}
}

/**
 * @brief 通常検査の有限件数と独立した内容段階の整合を確認します。
 * @param[in] item 同じ原承認とtransferへ別途照合する一結果。
 * @return 通常file／INF上限、状態、errorと入力結合が整合する場合trueです。
 * @note 構造解析・署名合格を実証せず、画面への結果受理だけを判定します。
 */
bool validIndexContentSummary( const IndexPreparationItemSummary &item)
{
	// 計算前に包含と上限を確認し、合計overflowと存在しないINF件数を拒否します。
	if( item.inventoryFileCount > 4096U || item.infCount > 128U ||
	   item.infCount > item.inventoryFileCount || item.parsedInfCount > item.infCount ||
	   item.acceptedInfCount > item.parsedInfCount ||
	   item.signatureRejectedInfCount > item.parsedInfCount ||
	   item.acceptedInfCount != item.parsedInfCount - item.signatureRejectedInfCount ||
	   item.contentError > 0 || item.firstInfRejection > 0) {
		return false ;
	}

	const bool countsEmpty = item.inventoryFileCount == 0U && item.infCount == 0U &&
							 item.parsedInfCount == 0U && item.acceptedInfCount == 0U &&
							 item.signatureRejectedInfCount == 0U &&
							 // 全体未完了で保持しない個別結果。
							 item.firstInfRejection == 0 ;
	// 未取得の内容段階から件数、入力結合または診断を合成しません。
	if( item.acquisition != OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION) {
		return item.content == IndexedDriverInspectionState::NOT_STARTED &&
			   item.contentError == 0 && !item.inputBound && countsEmpty ;
	}

	// 取得成功後の入力拒否、取消し、全体失敗、完了を元内容契約のまま分けます。
	switch( item.content) {
		// 入力拒否は元byte結合なしの独立errorです。
		case IndexedDriverInspectionState::INPUT_REJECTED:
			return item.contentError < 0 && !item.inputBound && countsEmpty ;
		// 取消しと全体失敗では入力結合の観測を保ち、部分INFは表示所有しません。
		case IndexedDriverInspectionState::CANCELLED:
		// 全体失敗も同じ部分INF破棄契約を使用します。
		case IndexedDriverInspectionState::INSPECTION_FAILED:
			return item.contentError < 0 && countsEmpty ;
		// 検査完了は入力結合とerror0だけへ結び、個別署名拒否を許可します。
		case IndexedDriverInspectionState::INSPECTION_COMPLETED:
			return item.inputBound && item.contentError == 0 ;
		// Installer検査は標準INF件数へ水増しせず、独立した内容到達だけを受理します。
		case IndexedDriverInspectionState::INSTALLER_INSPECTION_COMPLETED:
			return item.inputBound && item.contentError == 0 && countsEmpty ;
		// 未開始または定義外を内容完了の代わりに受理しません。
		default:
			return false ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
INT_PTR CALLBACK MainWindow::preparationEulaDialogProc( const HWND dialog, const UINT message,
													   const WPARAM wordParameter,
													   const LPARAM longParameter) noexcept
{
	// dialog初期化時にだけ対象snapshotから同意本文と確認条件を設定する。
	if( message == WM_INITDIALOG) {
		// DialogBoxParamWが同期dialog中だけ保持する自object内snapshotへの非所有pointer。
		const auto *target = reinterpret_cast<const OfficialPreparationTarget *>( longParameter) ;
		// 対象またはEULA本文・revisionが不正な場合は同意dialogを取消で閉じる。
		if( target == nullptr || target->terms != OfficialPreparationTerms::ACCEPTANCE_REQUIRED ||
		   !validPreparationEulaText( target->eulaText) || target->eulaRevision.empty()) {
			EndDialog( dialog, IDCANCEL) ;
			return TRUE ;
		}

		const HWND body = GetDlgItem( dialog, IDC_PREPARATION_EULA_TEXT) ;	// Read-only全文control。
		SendMessageW( body, EM_SETLIMITTEXT, MAXIMUM_PREPARATION_EULA_CHARACTERS, 0) ;
		// EULA全文とrevisionを表示できなければ同意を受理しない。
		const auto revisionLabel =
			target->eulaSourceSubject.empty()
				? target->eulaRevision
				: target->eulaSourceSubject + L"\r\n" +
					  target->eulaRevision ;	// 元出典と改訂を本文と同時に表示します。
		// 原全文・出典・改訂を表示できない場合は同意を拒否します。
		if( SetDlgItemTextW( dialog, IDC_PREPARATION_EULA_REVISION, revisionLabel.c_str()) == FALSE ||
		   SetWindowTextW( body, target->eulaText.c_str()) == FALSE ||
		   GetWindowTextLengthW( body) != static_cast<int>( target->eulaText.size())) {
			// 本文を表示できなければ同意buttonを使わせない。
			EndDialog( dialog, IDCANCEL) ;
			return TRUE ;
		}

		// 同期dialog内には要否だけを保持し、対象pointerや許諾を永続保存しない。
		SetLastError( ERROR_SUCCESS) ;
		const bool combinedPrerequisite =
			target->requiresPrerequisiteConfirmation &&
			target->providerId !=
				SIGNED_INDEX_PROVIDER_ID ;	// 既存Providerの複合確認だけを維持します。
		// 前提条件の確認要否を保存できなければ同意を受理しない。
		if( SetWindowLongPtrW( dialog, DWLP_USER, combinedPrerequisite ? 1 : 0) == 0 &&
		   GetLastError() != ERROR_SUCCESS) {
			// 確認要否を保持できない場合は同意を受理しない。
			EndDialog( dialog, IDCANCEL) ;
			return TRUE ;
		}

		ShowWindow( GetDlgItem( dialog, IDC_PREPARATION_PREREQUISITE_NOTE),
				   combinedPrerequisite ? SW_SHOW : SW_HIDE) ;
		ShowWindow( GetDlgItem( dialog, IDC_PREPARATION_PREREQUISITES),
				   combinedPrerequisite ? SW_SHOW : SW_HIDE) ;
		CheckDlgButton( dialog, IDC_PREPARATION_PREREQUISITES, BST_UNCHECKED) ;
		EnableWindow( GetDlgItem( dialog, IDYES), !combinedPrerequisite) ;
		// Enterを取得許諾の自動同意にしない。
		SetFocus( GetDlgItem( dialog, IDCANCEL)) ;
		return FALSE ;
	}

	// 前提条件checkboxの操作に合わせて同意buttonの利用可否を更新する。
	if( message == WM_COMMAND && LOWORD( wordParameter) == IDC_PREPARATION_PREREQUISITES &&
	   HIWORD( wordParameter) == BN_CLICKED) {
		EnableWindow( GetDlgItem( dialog, IDYES),
					 GetWindowLongPtrW( dialog, DWLP_USER) == 0 ||
						 IsDlgButtonChecked( dialog, IDC_PREPARATION_PREREQUISITES) == BST_CHECKED) ;
		return TRUE ;
	}

	// 同意または取消commandを受けたときに前提条件を再検証して終了する。
	if( message == WM_COMMAND &&
	   (LOWORD( wordParameter) == IDYES || LOWORD( wordParameter) == IDCANCEL)) {
		// Buttonの無効表示だけでなく、未確認の同意commandも拒否する。
		if( LOWORD( wordParameter) == IDYES && GetWindowLongPtrW( dialog, DWLP_USER) != 0 &&
		   IsDlgButtonChecked( dialog, IDC_PREPARATION_PREREQUISITES) != BST_CHECKED) {
			return TRUE ;
		}

		EndDialog( dialog, LOWORD( wordParameter)) ;
		return TRUE ;
	}

	// windowを閉じる操作をEULAへの同意として扱わない。
	if( message == WM_CLOSE) {
		EndDialog( dialog, IDCANCEL) ;
		return TRUE ;
	}

	return FALSE ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool MainWindow::confirmPreparationEula( const OfficialPreparationTarget &target) const
{
	// 本文・改訂識別子の欠落を同意不要と解釈しない。
	if( target.terms != OfficialPreparationTerms::ACCEPTANCE_REQUIRED ||
	   !validPreparationEulaText( target.eulaText) || target.eulaRevision.empty()) {
		return false ;
	}

	// Win32のuser parameterへ渡すpointerは本同期dialogが閉じるまで有効である。
	const INT_PTR response =
		DialogBoxParamW( instance_, MAKEINTRESOURCEW( IDD_PREPARATION_EULA), window_,
						preparationEulaDialogProc, reinterpret_cast<LPARAM>( &target)) ;
	// dialog自体を作成できない場合は同意未取得のまま診断値を表示する。
	if( response == -1) {
		const DWORD error = GetLastError() ;	// Resource／dialog作成失敗の診断値を直ちに保持する。
		MessageBoxW( window_,
					formatNativeError( static_cast<NativeError>( error == ERROR_SUCCESS
																   ? E_UNEXPECTED
																   : HRESULT_FROM_WIN32( error)))
						.c_str(),
					loadString( IDS_PREPARATION_TITLE).c_str(), MB_OK | MB_ICONERROR) ;
	}

	return response == IDYES ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring MainWindow::formatPreparationTarget( const OfficialPreparationTarget &target,
												 const std::size_t				  index) const
{
	std::wstring provider = target.providerId ;	// 未知の名称を推測しない取得元表示。
	// 登録済みProviderの表示名だけを使用し、別のメーカー一覧を保持しない。
	for( const ProviderDescriptor &descriptor : builtInProviderDescriptors()) {
		// 対象Providerと一致するregistryの正式表示名を採用する。
		if( descriptor.id == target.providerId) {
			provider = descriptor.displayName ;
			break ;
		}
	}

	// 取得許可の理由、または未確定／本文未提示の拒否理由を示すresource。
	const UINT terms = target.terms == OfficialPreparationTerms::CONFIRMED_NO_CONSENT
						   ? IDS_PREPARATION_ELIGIBLE
						   : (target.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED
								  ? IDS_PREPARATION_EULA_READY
								  : IDS_PREPARATION_UNRESOLVED) ;
	// 条件説明は取得許可の根拠ではなく、拒否理由を含む表示である。
	return formatResource( IDS_PREPARATION_TARGET, std::to_wstring( index + 1U)) + L": " + provider +
		   L"\r\n" + formatResource( IDS_PREPARATION_REFERENCE, target.releaseIdentity) + L"\r\n" +
		   formatResource( IDS_PREPARATION_DEVICES, std::to_wstring( target.deviceCount)) + L"\r\n" +
		   formatResource( IDS_PREPARATION_CAP, std::to_wstring( target.maximumBytes)) + L"\r\n" +
		   loadString( terms) +
		   (target.eulaSourceSubject.empty()
				? L""
				: L"\r\n" + formatResource( IDS_INDEX_TERMS_SUBJECT, target.eulaSourceSubject)) +
		   (target.prerequisiteText.empty() ? L"" : L"\r\n" + target.prerequisiteText) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
int MainWindow::showPreparationDialog( const std::wstring &content, const std::wstring &details,
									  const bool select, bool &network) const
{
	const std::wstring title   = loadString( IDS_PREPARATION_TITLE) ;			// 取得と導入を区別するtitle。
	const std::wstring acquire = loadString( IDS_PREPARATION_SELECT) ;			// 取得を選ぶbutton caption。
	const std::wstring skip	   = loadString( IDS_PREPARATION_SKIP) ;			// 取得しないbutton caption。
	const std::wstring verification = loadString( IDS_PREPARATION_NETWORK) ;	// 対象限定の同意文。
	// Captionは本同期dialog中だけ参照され、取得拒否を既定buttonとする。
	const std::array<TASKDIALOG_BUTTON, 2> buttons{
		{{IDYES, acquire.c_str()}, {IDNO, skip.c_str()}}} ;
	// Custom buttonは本同期dialog中だけ文字列を参照する。
	TASKDIALOGCONFIG dialog{} ;	// 標準dialog設定。内部pointerは本呼出し中だけ有効。
	dialog.cbSize	  = sizeof( dialog) ;
	dialog.hwndParent = window_ ;
	dialog.hInstance  = instance_ ;
	dialog.dwFlags = TDF_SIZE_TO_CONTENT | TDF_ALLOW_DIALOG_CANCELLATION | TDF_EXPANDED_BY_DEFAULT ;
	dialog.dwCommonButtons = select ? TDCBF_CANCEL_BUTTON : (TDCBF_OK_BUTTON | TDCBF_CANCEL_BUTTON) ;
	dialog.pszWindowTitle  = title.c_str() ;
	dialog.pszMainInstruction	  = title.c_str() ;
	dialog.pszContent			  = content.c_str() ;
	dialog.pszExpandedInformation = details.empty() ? nullptr : details.c_str() ;
	dialog.nDefaultButton		  = select ? IDNO : IDCANCEL ;
	// 取得対象を選ぶdialogにだけ選択buttonとnetwork同意欄を設ける。
	if( select) {
		dialog.cButtons			   = static_cast<UINT>( buttons.size()) ;
		dialog.pButtons			   = buttons.data() ;
		dialog.pszVerificationText = verification.c_str() ;
	}

	int			  selected{} ;															// Task Dialogが返すbutton ID。
	BOOL		  checked{} ;															// network checkboxは既定未選択。
	const HRESULT error = TaskDialogIndirect( &dialog, &selected, nullptr, &checked) ;	// 表示結果。
	network				= SUCCEEDED( error) && select && selected == IDYES && checked != FALSE ;
	// 確認dialogの表示失敗は診断を示して取消扱いにする。
	if( FAILED( error)) {
		MessageBoxW( window_, formatNativeError( static_cast<NativeError>( error)).c_str(),
					title.c_str(), MB_OK | MB_ICONERROR) ;
		// 表示失敗を取得同意として扱わない。
		return IDCANCEL ;
	}

	return selected ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::handlePreparationCommand()
{
	// Modal確認の再入と終了開始後の新規操作を拒否する。
	if( preparationReviewOpen_ || closing_) {
		return ;
	}

	// 取得中の再操作は新規取得ではなく現在処理への取消要求とする。
	if( controller_.state() == ApplicationState::PREPARING) {
		// 稼働中workerがある場合にだけ準備処理の協調取消を送る。
		if( worker_ != nullptr) {
			static_cast<void>( worker_->requestPreparationCancel( controller_.activeOperationId())) ;
		}

		static_cast<void>( controller_.markPreparationCancelling( controller_.activeOperationId())) ;
		SetWindowTextW( status_, loadString( IDS_PREPARATION_CANCELLING).c_str()) ;
		updateCommandState() ;
		// Worker完了通知まではscan／installを許可しない。
		return ;
	}

	// scan結果確定または失敗状態以外では新たな準備確認を始めない。
	if( controller_.state() != ApplicationState::SCAN_READY &&
	   controller_.state() != ApplicationState::FAILURE) {
		return ;
	}

	preparationReviewOpen_ = true ;
	try {
		// 未使用の準備計画がある場合は対象ごとの確認へ進む。
		if( controller_.preparationPlan() != nullptr) {
			beginPreparationReview() ;
		}
		// 新しい計画がなく結果だけが残る場合は閲覧専用で表示する。
		else if( !preparationResultText_.empty()) {
			bool ignored{} ;	// 閲覧dialogからnetwork承認を取得しない。
			static_cast<void>( showPreparationDialog( loadString( IDS_PREPARATION_TITLE),
													preparationResultText_, false, ignored)) ;
		}
	} catch( ...) {
		// Win32境界の既存例外処理へ渡す前に再入guardを解く。
		preparationReviewOpen_ = false ;
		throw ;
	}

	preparationReviewOpen_ = false ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::beginPreparationReview()
{
	const OfficialPreparationPlan *plan = controller_.preparationPlan() ;	// 同期確認中の非所有計画。
	// 有効な準備計画がない状態では確認対象を組み立てない。
	if( plan == nullptr) {
		return ;
	}

	OfficialPreparationApproval approval ;	// 最終確認まで操作IDを持たない全対象判断。
	approval.scanSessionId = plan->scanSessionId ;
	approval.planId		   = plan->planId ;
	approval.limits		   = plan->limits ;
	std::wstring details ;	// 最大256対象から作る端末内の明細。
	// 全対象を未選択で固定し、拒否した対象も承認snapshotへ残す。
	for( std::size_t index = 0; index < plan->targets.size(); ++index) {
		approval.decisions.push_back( {.target = plan->targets[index]}) ;
		details += formatPreparationTarget( plan->targets[index], index) + L"\r\n\r\n" ;
	}

	const std::wstring capacities =	// 予約上限を実転送サイズと混同しない表示。
		std::to_wstring( plan->limits.maximumFileBytes) + L" / " +
		std::to_wstring( plan->limits.maximumProviderBytes) + L" / " +
		std::to_wstring( plan->limits.maximumSessionBytes) ;
	const std::wstring counts = std::to_wstring( plan->limits.maximumProviderFiles) + L" / " +
								// 件数予算。
								std::to_wstring( plan->limits.maximumSessionFiles) ;
	const std::wstring overview = loadString( IDS_PREPARATION_INTRO) + L"\r\n\r\n" +
								  formatResource( IDS_PREPARATION_LIMITS, capacities) + L"\r\n" +
								  // 最初に提示する全体条件。
								  formatResource( IDS_PREPARATION_FILES, counts) ;
	bool ignored{} ;	// 閲覧時にはnetwork承認を使用しない。
	// 一覧確認を取消した場合は何も取得しない。
	if( showPreparationDialog( overview, details, false, ignored) != IDOK) {
		return ;
	}

	std::uint32_t						 selected{} ;		// 最終確認へ表示する取得対象数。
	std::vector<ReviewedPreparationEula> reviewedEulas ;	// 同一tokenの再表示を防ぐ短命判断。
	reviewedEulas.reserve( approval.decisions.size()) ;
	// EULAが必要な対象は全文を表示し、当該対象への同意がある場合だけ取得可否へ進める。
	for( std::size_t index = 0; index < approval.decisions.size(); ++index) {
		OfficialPreparationDecision &decision = approval.decisions[index] ;	// 一対象への今回の判断。
		bool						 eulaAccepted{} ;						// 今回の対象本文にだけ有効な明示同意。
		// EULA同意が必要な対象は本文確認を経てから選択へ組み込む。
		if( decision.target.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED) {
			const auto reviewed = std::find_if(
				reviewedEulas.begin(), reviewedEulas.end(), [&decision]( const auto &entry) {
					return decision.target.sharedEulaToken != 0U &&
						   entry.token == decision.target.sharedEulaToken ;
				}) ; // 同じworker group tokenへの先行判断。
			// 共有tokenの二件目以降はProvider、revision、本文の完全一致を再確認する。
			if( reviewed != reviewedEulas.end()) {
				// Token衝突やsnapshot差替えでは先行同意を別本文へ流用せず確認全体を中止する。
				if( reviewed->providerId != decision.target.providerId ||
				   reviewed->sourceSubject != decision.target.eulaSourceSubject ||
				   reviewed->revision != decision.target.eulaRevision ||
				   reviewed->text != decision.target.eulaText) {
					setStatus( loadString( IDS_PREPARATION_ERROR), false) ;
					return ;
				}

				eulaAccepted = reviewed->accepted ;
			} else {
				// 全文への今回判断。
				eulaAccepted = confirmPreparationEula( decision.target) ;
				// 0は従来対象なので共有せず、非zero tokenだけを一回判断へ固定する。
				if( decision.target.sharedEulaToken != 0U) {
					reviewedEulas.push_back( {.token			= decision.target.sharedEulaToken,
											 .providerId	= decision.target.providerId,
											 .sourceSubject = decision.target.eulaSourceSubject,
											 .revision		= decision.target.eulaRevision,
											 .text			= decision.target.eulaText,
											 .accepted		= eulaAccepted}) ;
				}
			}

			// 本文拒否では同じgroupの全対象を未選択のまま維持する。
			if( !eulaAccepted) {
				continue ;
			}
		}
		// 条件未確定の場合は取得の選択肢を表示しない。
		else if( decision.target.terms != OfficialPreparationTerms::CONFIRMED_NO_CONSENT) {
			continue ;
		}

		bool prerequisites = !decision.target.requiresPrerequisiteConfirmation ||
							 (decision.target.providerId != SIGNED_INDEX_PROVIDER_ID &&
							  eulaAccepted) ;	// EULAと独立した今回判断です。
		// 索引の具体的条件は同意不要でも表示し、別の明示判断へ結びます。
		if( decision.target.requiresPrerequisiteConfirmation &&
		   decision.target.providerId == SIGNED_INDEX_PROVIDER_ID) {
			prerequisites = MessageBoxW( window_,
										(loadString( IDS_INDEX_PREREQUISITE_CONFIRM) + L"\r\n\r\n" +
										 decision.target.prerequisiteText)
											.c_str(),
										loadString( IDS_PREPARATION_TITLE).c_str(),
										MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) == IDYES ;
			// 未確認条件の対象だけを未選択へ保持し、他対象の権限を合算しません。
			if( !prerequisites) {
				continue ;
			}
		}

		bool	  network{} ;						// この対象だけに有効なnetwork同意。
		const int response = showPreparationDialog(	// 対象別の取得可否。
			loadString( IDS_PREPARATION_INTRO), formatPreparationTarget( decision.target, index),
			true, network) ;
		// 全体取消しでは先に選んだ対象も未送信のまま破棄する。
		if( response == IDCANCEL) {
			return ;
		}

		decision.acquire				   = response == IDYES ;
		decision.eulaAccepted			   = decision.acquire && eulaAccepted ;
		decision.restrictedNetworkApproved = decision.acquire && network ;
		// 確認必須dialogは未チェックでは成功しない。未選択には確認値を残さない。
		decision.prerequisitesConfirmed =
			decision.acquire && prerequisites && decision.target.requiresPrerequisiteConfirmation ;
		selected += decision.acquire ? 1U : 0U ;
	}

	// 承認対象が一件もない場合は取得を開始せず選択なしを案内する。
	if( selected == 0) {
		setStatus( loadString( IDS_PREPARATION_NONE), false) ;
		return ;
	}

	// 件数の最終確認に同意がなければ準備取得を開始しない。
	if( MessageBoxW( window_,
				   formatResource( IDS_PREPARATION_CONFIRM, std::to_wstring( selected)).c_str(),
				   loadString( IDS_PREPARATION_TITLE).c_str(),
				   MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) {
		return ;
	}

	// 状態遷移後のcopy例外でworker未送信のまま停止しないよう、表示snapshotを先に確保する。
	preparationApproval_	= approval ;
	const BeginResult begin = controller_.beginPreparation( approval) ;	// UI側の全snapshot照合。
	// 状態機械が開始を拒否した場合は承認を破棄し、理由を表示する。
	if( !begin.accepted) {
		preparationApproval_   = {} ;
		preparationResultText_ = formatResource( IDS_PREPARATION_BEGIN_ERROR,
												std::to_wstring( static_cast<int>( begin.error))) ;
		setStatus( preparationResultText_, false) ;
		MessageBoxW( window_, preparationResultText_.c_str(),
					loadString( IDS_PREPARATION_TITLE).c_str(), MB_OK | MB_ICONWARNING) ;
		return ;
	}

	preparationApproval_.operationId = begin.operationId ;
	preparationTotal_				 = selected ;
	preparationCompleted_			 = 0 ;
	preparationResultText_.clear() ;
	setStatus(
		formatResource( IDS_PREPARATION_PROGRESS, L"0 / " + std::to_wstring( selected) + L" (0%)"),
		true) ;
	updateCommandState() ;
	bool queued{} ;	// 有限queueが取得commandを受理した場合true。
	try {
		queued = worker_ != nullptr && worker_->requestPreparation( approval) ;
	} catch( ...) {
		// Queue用copyの例外も未実行の制御エラーとして完了し、同意を自動再送しない。
		queued = false ;
	}

	// workerへの登録失敗を未実行の完了通知へ変換して処理中状態を残さない。
	if( !queued) {
		OfficialPreparationOperationResult failure ;	// 未実行を表す合成完了通知。
		failure.operationId	  = begin.operationId ;
		failure.scanSessionId = approval.scanSessionId ;
		failure.planId		  = approval.planId ;
		failure.controlError  = static_cast<NativeError>( E_UNEXPECTED) ;
		processPreparationCompleted( failure) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::processPreparationProgress( const WorkerEvent &event)
{
	// 古い操作、総件数変更、範囲外、逆行する進捗を適用しない。
	if( event.operationId != controller_.activeOperationId() ||
	   (controller_.state() != ApplicationState::PREPARING &&
		controller_.state() != ApplicationState::CANCELLING_PREPARATION) ||
	   event.preparationProgress.total != preparationTotal_ || preparationTotal_ == 0 ||
	   event.preparationProgress.completed > preparationTotal_ ||
	   event.preparationProgress.completed < preparationCompleted_) {
		return ;
	}

	preparationCompleted_		= event.preparationProgress.completed ;
	const std::uint32_t percent = preparationCompleted_ * 100U / preparationTotal_ ;	// 最大256件。
	const std::wstring	counts	= std::to_wstring( preparationCompleted_) + L" / " +
								std::to_wstring( preparationTotal_) + L" (" +
								// 確定件数。
								std::to_wstring( percent) + L"%)" ;
	setStatus( formatResource( IDS_PREPARATION_PROGRESS, counts) +
				  (controller_.state() == ApplicationState::CANCELLING_PREPARATION
					   ? L" / " + loadString( IDS_PREPARATION_CANCELLING)
					   : L""),
			  true) ;
	statusPercentage_ = percent ;
	InvalidateRect( status_, nullptr, TRUE) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/app/main_window.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void MainWindow::processPreparationCompleted( const OfficialPreparationOperationResult &result,
											 const IndexPreparationSummary			  &indexSummary)
{
	// 古いsession／planの通知は現在のUIを変更しない。
	if( !controller_.completePreparation( result, candidates_)) {
		return ;
	}

	const auto indexTargetCount	  = static_cast<std::size_t>( std::ranges::count_if(
		  preparationApproval_.decisions, []( const OfficialPreparationDecision &value) {
			  return value.target.providerId == SIGNED_INDEX_PROVIDER_ID ;
		  })) ; // 未選択も含む元計画の索引対象数。
	const auto selectedIndexCount = static_cast<std::size_t>( std::ranges::count_if(
		preparationApproval_.decisions, []( const OfficialPreparationDecision &value) {
			return value.target.providerId == SIGNED_INDEX_PROVIDER_ID && value.acquire ;
		})) ; // 確定内容通知を持ち得る元選択数。
	bool	   indexBound =
		controller_.state() != ApplicationState::FAILURE &&
		result.approvalError == OfficialPreparationError::NONE &&
		indexSummary.operationId == result.operationId &&
		indexSummary.scanSessionId == result.scanSessionId &&
		indexSummary.planId == result.planId && indexSummary.items.size() <= 256U &&
		indexSummary.items.size() <= selectedIndexCount && indexSummary.plannedTargets <= 256U &&
		indexSummary.plannedTargets == indexTargetCount && indexSummary.authorityError <= 0 &&
		indexSummary.unavailableRelations <= 32768U &&
		indexSummary.capacityRejectedRelations <= 32768U &&
		indexSummary.plannedTargets <= 32768U - indexSummary.unavailableRelations &&
		indexSummary.capacityRejectedRelations <=
			32768U - indexSummary.unavailableRelations -
				indexSummary.plannedTargets ;			// 原計画と同じ有限な全lookup件数。
	std::vector<std::wstring_view> indexIdentities ;	// 画面へ適用する一意opaqueだけを借用します。
	// 全有限結果を元承認・取得結果へ照合し、一件不正なら索引表示全体を拒否します。
	for( const auto &item : indexSummary.items) {
		// 上限拒否や先行不整合の後は巨大な追加通知を反復せず全体拒否を維持します。
		if( !indexBound) {
			break ;
		}

		const auto decision = std::ranges::find_if(
			preparationApproval_.decisions, [&item]( const OfficialPreparationDecision &value) {
				return value.target.providerId == SIGNED_INDEX_PROVIDER_ID &&
					   value.target.identity == item.targetIdentity ;
			}) ; // 索引取得用途だけの元対象snapshot。
		const auto transfer =
			std::ranges::find_if( result.items, [&]( const OfficialPreparationItem &value) {
				return value.identity == item.targetIdentity ;
			}) ; // 同計画の確定取得結果。
		indexBound &=
			decision != preparationApproval_.decisions.end() && transfer != result.items.end() &&
			validIndexContentSummary( item) &&
			std::ranges::find( indexIdentities, item.targetIdentity) == indexIdentities.end() ;
		// 欠落した元結果への参照から表示許可を補完しません。
		if( decision == preparationApproval_.decisions.end() || transfer == result.items.end()) {
			continue ;
		}

		const auto expectedTransfer = indexTransferState( item.acquisition) ;	// 現workerの確定変換。
		indexBound &= decision->acquire && item.acquisitionError == transfer->result.error &&
					  expectedTransfer && *expectedTransfer == transfer->result.state ;
		// 取得成功の内容到達は共通executorが確定した取得成功とだけ結合します。
		if( item.acquisition == OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION) {
			indexBound &=
				transfer->result.state == OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION &&
				item.acquisitionError == 0U &&
				((item.content != IndexedDriverInspectionState::INSPECTION_COMPLETED &&
				  item.content != IndexedDriverInspectionState::INSTALLER_INSPECTION_COMPLETED) ||
				 (item.inputBound && item.contentError == 0U)) ;
		} else {
			indexBound &=
				transfer->result.state != OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION &&
				item.content == IndexedDriverInspectionState::NOT_STARTED && !item.inputBound &&
				item.infCount == 0U ;
		}

		indexIdentities.push_back( item.targetIdentity) ;
	}

	// 同planの未変更有限summaryだけを次scanまで表示所有します。
	if( indexBound) {
		indexPreparationSummary_ = indexSummary ;
	} else {
		indexPreparationSummary_ = {} ;
	}

	// 完了結果を状態機械が失敗とした場合は正常完了の説明を使用しない。
	if( controller_.state() == ApplicationState::FAILURE) {
		preparationResultText_ = loadString( IDS_PREPARATION_FAILED) + L"\r\n" +
								 formatNativeError( static_cast<NativeError>( E_UNEXPECTED)) ;
	} else {
		preparationResultText_ = loadString( IDS_PREPARATION_INTRO) + L"\r\n\r\n" ;
		// 承認検証または処理制御のerrorを対象別結果と併せて表示する。
		if( result.approvalError != OfficialPreparationError::NONE || result.controlError != 0) {
			preparationResultText_ +=
				formatResource( IDS_PREPARATION_ERROR,
							   std::to_wstring( static_cast<int>( result.approvalError)) + L" / " +
								   formatNativeError( result.controlError)) +
				L"\r\n\r\n" ;
		}

		// 検証済みの取得結果と独立した監査件数を、開始時の固定対象へ戻して表示する。
		for( std::size_t index = 0; index < preparationApproval_.decisions.size(); ++index) {
			// 結果の表示名と上限を取得する開始時の固定対象。
			const OfficialPreparationDecision &decision = preparationApproval_.decisions[index] ;
			// 対象snapshotに対応する一意の結果。
			const auto item = std::find_if( result.items.begin(), result.items.end(),
										   [&]( const OfficialPreparationItem &entry) {
											   return entry.identity == decision.target.identity ;
										   }) ;
			// 承認／制御エラーの結果欠落を成功で補わない。
			if( item == result.items.end()) {
				continue ;
			}

			preparationResultText_ +=
				formatPreparationTarget( decision.target, index) + L"\r\n" +
				loadString( preparationStateResource( item->result.state)) + L"\r\n" +
				formatResource( IDS_PREPARATION_ACTUAL, std::to_wstring( item->result.byteCount)) +
				(item->result.error != 0 ? L"\r\n" + formatNativeError( item->result.error) : L"") +
				L"\r\n\r\n" ;
			// 同じ対象だけの監査結果を取得結果の直後へ表示する。
			for( const OfficialPreparationAuditReport &report : result.auditReports) {
				// 別対象の監査結果を現在の対象説明へ混在させない。
				if( report.targetIdentity != item->identity) {
					continue ;
				}

				preparationResultText_ +=
					loadString( preparationPublicationResource( report.publication.state)) + L"\r\n" +
					loadString( IDS_AUDIT_CONTENT_LABEL) +
					formatCandidateAuditGate( report.content, IDS_AUDIT_CONTENT_PASSED,
											 IDS_AUDIT_CONTENT_PENDING) +
					L"\r\n" +
					formatResource( IDS_PREPARATION_AUDIT_INF,
								   std::to_wstring( report.acceptedInfCount) + L" / " +
									   std::to_wstring( report.infCount)) +
					L"\r\n" + loadString( IDS_AUDIT_SYSTEM_LABEL) +
					formatCandidateAuditGate( report.applicability, IDS_AUDIT_SYSTEM_PASSED,
											 IDS_AUDIT_SYSTEM_PENDING) +
					L"\r\n" +
					formatResource( IDS_PREPARATION_AUDIT_PAIRS,
								   std::to_wstring( report.applicablePairCount) + L" / " +
									   std::to_wstring( report.examinedPairCount) + L" / " +
									   std::to_wstring( report.failedPairCount)) +
					L"\r\n" +
					formatResource( IDS_PREPARATION_PUBLICATION_COUNTS,
								   std::to_wstring( report.publication.examinedPairCount) + L" / " +
									   std::to_wstring( report.publication.publishedCount) + L" / " +
									   std::to_wstring( report.publication.excludedPairCount)) +
					L"\r\n" ;
				// 新たな候補が発行された対象にだけその件数を表示する。
				if( !report.publishedCandidates.empty()) {
					preparationResultText_ +=
						formatResource( IDS_PREPARATION_CANDIDATES,
									   std::to_wstring( report.publishedCandidates.size())) +
						L"\r\n" ;
				}

				// 診断値だけを表示し、INF名・path・hardware IDを含めない。
				for( const NativeError error :
					{report.contentError, report.firstContentRejection, report.applicabilityError,
					 report.firstPairError, report.publication.firstError}) {
					// 対象に診断値がある場合は失敗原因を追跡できる数値を付記する。
					if( error != 0) {
						preparationResultText_ += formatNativeError( error) + L"\r\n" ;
					}
				}

				preparationResultText_ += L"\r\n" ;
			}
		}

		// 監査reportがある場合は候補と選択の複製を検証してから一括反映する。
		if( !result.auditReports.empty()) {
			std::vector<UpdateCandidate> nextCandidates =
				candidates_ ;										// 成功時だけ反映する複製一覧。
			std::vector<bool> nextSelected = candidateSelected_ ;	// 既存選択と新規未選択の複製状態。
			// 候補数と選択状態数の不一致を黙認せず反映処理を中止する。
			if( nextCandidates.size() != nextSelected.size()) {
				throw std::logic_error( "invalid prepared candidate selection state") ;
			}

			// 全行を書き換える前に非所有索引を確保し、行ごとの全件探索を避ける。
			std::unordered_map<std::wstring_view, const OfficialPreparationCandidateAudit *>
				updates ;	// Reportの所有値を本呼出し中だけ参照する監査索引。
			// Controllerが全件照合した一意な監査行を索引化する。
			for( const OfficialPreparationAuditReport &report : result.auditReports) {
				// UI stateへpointerを保持せず、複製一覧の更新中だけ参照する。
				for( const OfficialPreparationCandidateAudit &row : report.candidates) {
					updates.emplace( row.identity, &row) ;
				}
			}

			// 既存順序とselectionを維持し、監査と取得済みflagだけを複製へ反映する。
			for( UpdateCandidate &candidate : nextCandidates) {
				const auto updated = updates.find( candidate.identity) ;	// 同じ行の監査結果。
				// 対象に対応する監査reportがある既存候補だけを取得済み状態へ更新する。
				if( updated != updates.end()) {
					candidate.audit			   = updated->second->audit ;
					candidate.allContentCached = true ;
					// Scan時点の未取得評価を取得後の現在値として表示しない。
					if( candidate.assessment && candidate.assessment->acquisition.reason ==
												   CandidateAssessmentReason::NOT_ACQUIRED) {
						candidate.assessment.reset() ;
					}
				}
			}

			// Controllerが検証済みの候補だけを未選択で複製一覧の末尾へ追加する。
			for( const OfficialPreparationAuditReport &report : result.auditReports) {
				// Report内の発行順を保ち、一候補ごとに選択なしを明示する。
				for( const UpdateCandidate &candidate : report.publishedCandidates) {
					nextCandidates.push_back( candidate) ;
					nextSelected.push_back( false) ;
				}
			}

			// 全候補のannotationを消し、同一版取得元groupを複製上で再計算する。
			for( UpdateCandidate &candidate : nextCandidates) {
				candidate.equivalentSourceCount = 1U ;
				candidate.preferredSource		= true ;
			}

			const auto sourceGroups = groupEquivalentCandidateSources(
				nextCandidates, builtInProviderDescriptors()) ;	// 全表示候補の取得元group。
			// 同一版取得元groupを検証できない候補集合はUIへ反映しない。
			if( !sourceGroups.has_value()) {
				throw std::logic_error( "invalid prepared candidate source group") ;
			}

			// 同一device／action／明示versionの取得元数と既定表示元だけを注釈する。
			for( const CandidateSourceGroup &group : sourceGroups.value()) {
				const auto sourceCount = static_cast<std::uint32_t>(
					// 同一版の明示取得元数。
					group.candidateIndexes.size()) ;
				// Group内の全候補へ同じ件数と一つの既定表示元を設定する。
				for( const std::size_t candidateIndex : group.candidateIndexes) {
					UpdateCandidate &candidate = nextCandidates.at( candidateIndex) ;	// 注釈対象。
					candidate.equivalentSourceCount = sourceCount ;
					candidate.preferredSource = candidateIndex == group.preferredCandidateIndex ;
				}
			}

			auto coverage = aggregateLocalCoverage(
				nextCandidates, builtInProviderDescriptors()) ;	// 反映後の端末内到達集計。
			// 到達件数の整合を検証できない場合は候補集合の反映を中止する。
			if( !coverage.has_value()) {
				throw std::logic_error( "invalid prepared candidate coverage") ;
			}

			// 追加候補で従来到達件数だけを更新し、scan完了時点の段階別計測は数え直さない。
			if( !preserveLocalCoverageMeasurements( localCoverage_, coverage.value())) {
				throw std::logic_error( "invalid prepared candidate measurement groups") ;
			}

			// 全検証後だけ一覧を一括反映する。
			candidates_		   = std::move( nextCandidates) ;
			candidateSelected_ = std::move( nextSelected) ;
			localCoverage_	   = std::move( coverage.value()) ;
			// 一括反映した同じ一覧でTreeTableを再構築する。
			populateCandidates( candidates_) ;
		}
	}

	bool indexIncomplete = indexTargetCount != 0U &&
						   (!indexBound || indexSummary.items.size() < selectedIndexCount ||
							indexSummary.unavailableRelations != 0U ||
							indexSummary.capacityRejectedRelations != 0U) ;	// 未確認も保持します。
	// 同じ取得結果を保持しても、不正summaryの破棄を内容検査成功へ昇格しません。
	if( indexTargetCount != 0U && !indexBound) {
		preparationResultText_ +=
			loadString( IDS_INDEX_CONTENT_FAILED) + L"\r\n" + loadString( IDS_INDEX_ROUTING_PENDING) +
			L"\r\n" + formatNativeError( static_cast<NativeError>( E_UNEXPECTED)) + L"\r\n\r\n" ;
	}

	// 同じ操作へ再照合した有限内容結果を、取得成功とは独立に表示します。
	for( const auto &item : indexPreparationSummary_.items) {
		const auto decision = std::ranges::find_if(
			preparationApproval_.decisions, [&item]( const OfficialPreparationDecision &value) {
				return value.target.identity == item.targetIdentity ;
			}) ; // 検証済みの元承認内位置だけを表示します。
		preparationResultText_ +=
			formatResource( IDS_INDEX_CONTENT_ITEM,
						   std::to_wstring( static_cast<std::size_t>(
											   decision - preparationApproval_.decisions.begin()) +
										   1U)) +
			L"\r\n" ;
		const auto contentStatus =
			(item.content == IndexedDriverInspectionState::INSPECTION_COMPLETED ||
			 item.content == IndexedDriverInspectionState::INSTALLER_INSPECTION_COMPLETED)
				? IDS_INDEX_CONTENT_COMPLETED
				: IDS_INDEX_CONTENT_FAILED ;	// 検査完了は個別合格と異なります。
		preparationResultText_ +=
			loadString( contentStatus) + L"\r\n" +
			formatResource( IDS_INDEX_CONTENT_COUNTS,
						   std::to_wstring( item.inventoryFileCount) + L" / " +
							   std::to_wstring( item.infCount) + L" / " +
							   std::to_wstring( item.parsedInfCount) + L" / " +
							   std::to_wstring( item.signatureRejectedInfCount) + L" / " +
							   std::to_wstring( item.acceptedInfCount)) +
			L"\r\n" ;
		// 内容HRESULTと個別拒否を取得エラーで置換しません。
		for( const auto error : {item.acquisitionError, item.contentError, item.firstInfRejection}) {
			// 実診断値がある段階だけを数値で付記します。
			if( error != 0U) {
				preparationResultText_ += formatNativeError( error) + L"\r\n" ;
			}
		}

		indexIncomplete |=
			item.content == IndexedDriverInspectionState::INSTALLER_INSPECTION_COMPLETED
				? item.contentError != 0 || !item.inputBound
				: item.content != IndexedDriverInspectionState::INSPECTION_COMPLETED ||
					  item.infCount == 0U || item.acceptedInfCount != item.infCount ;
		preparationResultText_ += loadString( IDS_INDEX_ROUTING_PENDING) + L"\r\n\r\n" ;
	}

	setStatus( loadString( controller_.state() == ApplicationState::FAILURE ||
								 result.approvalError != OfficialPreparationError::NONE ||
								 result.controlError != 0
							 ? IDS_PREPARATION_FAILED
						 : indexIncomplete ? IDS_INDEX_CONTENT_PARTIAL
										   : IDS_PREPARATION_DONE),
			  false) ;
	updateCommandState() ;
	// 準備完了待ちの終了要求がある場合は通常のwindow終了処理へ戻す。
	if( closeAfterPreparation_) {
		closeAfterPreparation_ = false ;
		// 完了後は長時間取得がなく、通常のworker停止とWindow破棄へ戻せる。
		PostMessageW( window_, WM_CLOSE, 0, 0) ;
		return ;
	}

	// 内部targetの隠したfixtureは同じ確定本文とcontrolを観測し、modalを起動しません。
#if defined( DRIVERCRATE_INTERNAL_UI_TESTS)
	// 内部fixtureの確定本文検査では同期dialogを起動しません。
	if( testSuppressPreparationResultDialog_) {
		return ;
	}
#endif

	bool ignored{} ;	// 結果dialogで追加の取得同意を要求しない。
	static_cast<void>( showPreparationDialog( loadString( IDS_PREPARATION_TITLE),
											preparationResultText_, false, ignored)) ;
}

} // namespace drivercrate
