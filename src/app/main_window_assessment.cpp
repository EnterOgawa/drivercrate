//------------------------------------------------------------------------------
/**
 * @file main_window_assessment.cpp
 * @brief Device観測と候補詳細のread-only表示。
 * @version 01.03.00
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  登録状態・検証理由・方式の詳細表示を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  構成役割とpackage内検査範囲を表示。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * </pre>
 *
 * @note UI thread限定。固定理由と診断だけを表示し、取得・導入・同意を実行しない。
 * @see docs/adr/0150-device-observation-and-candidate-assessment-contract.md
 */
//------------------------------------------------------------------------------

#include "app/main_window.h"
#include "app/resource.h"
#include "core/candidate_audit.h"

#include <array>
#include <utility>

namespace drivercrate {
namespace {

// 読取り状態とresourceの有限対応。Enum順はここだけで対応させる。
constexpr std::array<UINT, 7> READ_RESOURCES{IDS_DEVICE_READ_NOT_READ, IDS_DEVICE_READ_VALUE,
											 IDS_DEVICE_READ_EMPTY,	   IDS_DEVICE_READ_MISSING,
											 IDS_DEVICE_READ_FAILED,   IDS_DEVICE_READ_INVALID,
											 IDS_DEVICE_READ_LIMIT} ;
// 詳細の成否を過大評価しない固定表示。
constexpr std::array<UINT, 7> STATE_RESOURCES{
	IDS_ASSESSMENT_STATE_NOT_CHECKED, IDS_ASSESSMENT_STATE_PASSED,
	IDS_ASSESSMENT_STATE_REJECTED,	  IDS_ASSESSMENT_STATE_FAILED,
	IDS_ASSESSMENT_STATE_UNSUPPORTED, IDS_ASSESSMENT_STATE_NOT_APPLICABLE,
	IDS_ASSESSMENT_STATE_WINDOWS} ;
// 未実装を含む方式名。名称だけではexecutorを許可しない。
constexpr std::array<UINT, 5> METHOD_RESOURCES{
	IDS_ASSESSMENT_METHOD_UNKNOWN, IDS_ASSESSMENT_METHOD_WINDOWS, IDS_ASSESSMENT_METHOD_INF,
	IDS_ASSESSMENT_METHOD_INSTALLER, IDS_ASSESSMENT_METHOD_MANUAL} ;
// Enumの各主理由に対する固定文。Page本文・URLを合成しない。
constexpr std::array<UINT, 30> REASON_RESOURCES{IDS_ASSESSMENT_REASON_NOT_EXAMINED,
												IDS_ASSESSMENT_REASON_VALIDATED,
												IDS_ASSESSMENT_REASON_WINDOWS,
												IDS_ASSESSMENT_REASON_API_FAILURE,
												IDS_ASSESSMENT_REASON_FORMAT,
												IDS_ASSESSMENT_REASON_ORIGIN_UNKNOWN,
												IDS_ASSESSMENT_REASON_USER,
												IDS_ASSESSMENT_REASON_ORIGIN_REJECTED,
												IDS_ASSESSMENT_REASON_DELEGATION,
												IDS_ASSESSMENT_REASON_NOT_ACQUIRED,
												IDS_ASSESSMENT_REASON_MISSING_FILE,
												IDS_ASSESSMENT_REASON_HASH,
												IDS_ASSESSMENT_REASON_SIGNATURE,
												IDS_ASSESSMENT_REASON_PUBLISHER,
												IDS_ASSESSMENT_REASON_PNP,
												IDS_ASSESSMENT_REASON_OS,
												IDS_ASSESSMENT_REASON_ARCH,
												IDS_ASSESSMENT_REASON_RANK,
												IDS_ASSESSMENT_REASON_LEGACY,
												IDS_ASSESSMENT_REASON_SAME,
												IDS_ASSESSMENT_REASON_NOT_RECOMMENDED,
												IDS_ASSESSMENT_REASON_FIRMWARE,
												IDS_ASSESSMENT_REASON_MIXED,
												IDS_ASSESSMENT_REASON_NO_REQUIREMENT,
												IDS_ASSESSMENT_REASON_REQUIREMENT_MISSING,
												IDS_ASSESSMENT_REASON_REQUIREMENT_UNKNOWN,
												IDS_ASSESSMENT_REASON_EXECUTOR,
												IDS_ASSESSMENT_REASON_SCOPE,
												IDS_INDEX_INSTALLER_SELECTION,
												IDS_INDEX_INSTALLER_SCOPE} ;
// 必須性と独立した役割の名称。
constexpr std::array<UINT, 5>  ROLE_RESOURCES{
	 IDS_ASSESSMENT_ROLE_BASE, IDS_ASSESSMENT_ROLE_EXTENSION, IDS_ASSESSMENT_ROLE_COMPONENT,
	 IDS_ASSESSMENT_ROLE_UTILITY, IDS_ASSESSMENT_ROLE_FIRMWARE} ;
static_assert( REASON_RESOURCES.size() ==
			  static_cast<std::size_t>( CandidateAssessmentReason::INSTALLER_SCOPE_ATTESTED) + 1U) ;

/**
 * @brief 不正enumでも範囲外参照せず固定resourceへ変換する。
 * @tparam Enum 表示対象の有限enum。
 * @tparam Size 固定対応表の要素数。
 * @param[in] value 表示対象。
 * @param[in] resources 対応表。
 * @return 定義済みresource、または矛盾説明のresource。
 */
template <typename Enum, std::size_t Size>
UINT resourceFor( const Enum value, const std::array<UINT, Size> &resources) noexcept
{
	const auto index = static_cast<std::size_t>( value) ;	// 未知値は上限で拒否する。
	return index < resources.size() ? resources[index] : IDS_ASSESSMENT_INCONSISTENT ;
}

/** @brief 同期dialog中だけ生存する表示用の所有値。 */
struct DetailDialogText {
	/// 固定resourceから取得する見出し。
	std::wstring title ;
	/// 同じsnapshotから作るread-only本文。
	std::wstring content ;
} ;

/**
 * @brief 標準editへ有限本文をcopyし、閉じる操作だけを処理する。
 * @param[in] dialog 同期dialogの借用handle。
 * @param[in] message Windows通知。
 * @param[in] wordParameter Button ID。
 * @param[in] longParameter 初期化時だけDetailDialogTextを借用する。
 * @return 処理済みの場合TRUE。
 */
INT_PTR CALLBACK detailDialogProc( const HWND dialog, const UINT message, const WPARAM wordParameter,
								  const LPARAM longParameter) noexcept
{
	// 同期期間中だけの所有文字列をcontrolへcopyし、pointerを保存しない。
	if( message == WM_INITDIALOG) {
		// DialogBoxParamWの境界だけで型を戻す。呼出し中は所有値が生存する。
		const auto *text = reinterpret_cast<const DetailDialogText *>( longParameter) ;
		// 必須の表示を設定できなければ空の成功画面を残さない。
		if( text == nullptr || !SetWindowTextW( dialog, text->title.c_str()) ||
		   !SetDlgItemTextW( dialog, IDC_METADATA_DETAIL_TEXT, text->content.c_str())) {
			EndDialog( dialog, -1) ;
			return TRUE ;
		}

		SendDlgItemMessageW( dialog, IDC_METADATA_DETAIL_TEXT, EM_SETSEL, 0, 0) ;
		return TRUE ;
	}

	// Enter・Escape・閉じるは表示終了のみであり同意へ変換しない。
	if( message == WM_CLOSE || (message == WM_COMMAND && (LOWORD( wordParameter) == IDOK ||
														 LOWORD( wordParameter) == IDCANCEL))) {
		EndDialog( dialog, IDOK) ;
		return TRUE ;
	}

	return FALSE ;
}
} // namespace

/** @see src/app/main_window.h */
std::wstring MainWindow::formatDeviceObservation( const UpdateCandidate &candidate) const
{
	// 観測未収集をdriver導入済みへ補完しない。
	if( !candidate.deviceObservation) {
		return loadString( IDS_DEVICE_OBSERVATION_MISSING) ;
	}

	// 古い型や異なるdeviceからの矛盾した観測を正常表示しない。
	if( !isCandidateDetailsValid( candidate)) {
		return loadString( IDS_ASSESSMENT_INCONSISTENT) ;
	}

	const auto	&observed = *candidate.deviceObservation ;	// 同じ現在構成の観測。
	std::wstring text = loadString( observed.driverPresence == DeviceDriverPresence::NOT_INSTALLED
									   ? IDS_DEVICE_PRESENCE_NOT_INSTALLED
								   : observed.driverPresence == DeviceDriverPresence::REGISTERED
									   ? IDS_DEVICE_PRESENCE_REGISTERED
									   : IDS_DEVICE_PRESENCE_UNKNOWN) ;	// 存在と動作成否を分離する。
	// 有効な問題codeがある場合だけWindowsの観測を付記する。
	if( observed.node.problemCode) {
		text += L" / " +
				formatResource( IDS_DEVICE_PROBLEM, std::to_wstring( *observed.node.problemCode)) ;
	}

	// Status API失敗を問題なしと表示しない。
	if( observed.node.read.state != DevicePropertyReadState::VALUE) {
		text += L" / " + loadString( IDS_DEVICE_STATUS_UNVERIFIED) ;
	}

	const std::array<const DevicePropertyReadStatus *, 10> reads{
		&observed.friendlyName,	   &observed.deviceDescription, &observed.manufacturer,
		&observed.deviceClass,	   &observed.driverKey,			&observed.infName,
		&observed.provider,		   &observed.version,			&observed.date,
		&observed.instanceIdentity} ;	// 固定属性。
	// 任意属性の不存在と実読取り失敗を区別し、失敗の要約を一回だけ付記する。
	for( const auto *read : reads) {
		// 失敗・不正・上限は詳細で元診断を示す。
		if( read->state == DevicePropertyReadState::FAILED ||
		   read->state == DevicePropertyReadState::INVALID_DATA ||
		   read->state == DevicePropertyReadState::LIMIT_REACHED) {
			text += L" / " + loadString( IDS_DEVICE_ATTRIBUTE_FAILURE) ;
			break ;
		}
	}

	return text ;
}

/** @see src/app/main_window.h */
std::wstring MainWindow::formatCandidateDetails( const UpdateCandidate &candidate) const
{
	// 表示に必要な結合を失った候補では原因を推測しない。
	if( !isCandidateDetailsValid( candidate)) {
		return loadString( IDS_ASSESSMENT_INCONSISTENT) ;
	}

	std::wstring text =
		// 本文は全てこの関数が所有する。
		formatCandidateText( candidate) + L"\r\n\r\n" ;
	const auto diagnosticText = [this]( const DeviceDiagnostic &diagnostic) {
		const UINT resource =
			diagnostic.domain == DeviceDiagnosticDomain::WINDOWS_ERROR ? IDS_DIAGNOSTIC_WIN32
			: diagnostic.domain == DeviceDiagnosticDomain::CONFIGURATION_MANAGER
				? IDS_DIAGNOSTIC_CONFIGRET
				: IDS_DIAGNOSTIC_HRESULT ;	// Windowsの生messageに含まれるpathを取り込まない。
		std::wstring value = L" [" + loadString( resource) + L": " +
							 // 固定幅codeのみ。
							 std::to_wstring( diagnostic.code) + L"]" ;
		// 権限拒否は安全な再確認が必要な失敗として明示する。
		if( diagnostic.domain == DeviceDiagnosticDomain::WINDOWS_ERROR &&
		   diagnostic.code == ERROR_ACCESS_DENIED) {
			value += L" " + loadString( IDS_DEVICE_ACCESS_DENIED) ;
		}

		// Win32のdevice消失を固定の説明へ対応させる。
		if( diagnostic.domain == DeviceDiagnosticDomain::WINDOWS_ERROR &&
		   diagnostic.code == ERROR_NO_SUCH_DEVINST) {
			value += L" " + loadString( IDS_DEVICE_DISAPPEARED) ;
		}

		return value ;
	} ; // thisは同期整形中だけ借用し、lambdaを保存しない。
	// 現在構成行は実行候補の検証と分離して属性観測を表示する。
	if( candidate.current) {
		text += formatDeviceObservation( candidate) + L"\r\n" +
				loadString( IDS_DEVICE_OBSERVATION_NOTE) + L"\r\n" ;
		// 未収集の観測を架空の属性成功で補完しない。
		if( candidate.deviceObservation) {
			const auto &observed =
				*candidate.deviceObservation ;	// 同じscanの固定属性だけを借用する。
			const std::array<std::pair<UINT, const DevicePropertyReadStatus *>, 11> reads{
				{{IDS_DEVICE_FIELD_NODE, &observed.node.read},
				 {IDS_DEVICE_FIELD_FRIENDLY, &observed.friendlyName},
				 {IDS_DEVICE_FIELD_DESCRIPTION, &observed.deviceDescription},
				 {IDS_DEVICE_FIELD_MANUFACTURER, &observed.manufacturer},
				 {IDS_DEVICE_FIELD_CLASS, &observed.deviceClass},
				 {IDS_DEVICE_FIELD_KEY, &observed.driverKey},
				 {IDS_DEVICE_FIELD_INF, &observed.infName},
				 {IDS_DEVICE_FIELD_PROVIDER, &observed.provider},
				 {IDS_DEVICE_FIELD_VERSION, &observed.version},
				 {IDS_DEVICE_FIELD_DATE, &observed.date},
				 {IDS_DEVICE_FIELD_IDENTITY,
				  &observed
					   .instanceIdentity}}} ;	// 生のkey・INF path・instance IDを表示せず成否だけにする。
			// 固定属性を一回ずつ整形し、欠損と読取り失敗を区別する。
			for( const auto &[label, read] : reads) {
				text += L"\r\n" + loadString( label) + L": " +
						loadString( resourceFor( read->state, READ_RESOURCES)) ;
				// 診断を持つ非成功状態だけに元codeを付記する。
				if( read->diagnostic.domain != DeviceDiagnosticDomain::NONE) {
					text += diagnosticText( read->diagnostic) ;
				}
			}
		}
	} else {
		// 旧Providerの詳細未収集を個別の署名・依存合格へ変換しない。
		if( !candidate.assessment) {
			text += loadString( IDS_ASSESSMENT_UNCOLLECTED) ;
		} else {
			const auto &detail = *candidate.assessment ;	// 所有候補が保持する固定八軸。
			text +=
				loadString( IDS_ASSESSMENT_COMPONENT_ROLE) + L": " +
				loadString( detail.componentRole ? resourceFor( *detail.componentRole, ROLE_RESOURCES)
												: IDS_ASSESSMENT_UNCOLLECTED) +
				L"\r\n" ;
			// 共通localの条件なし判定はpackage内の静的検査範囲に限定して説明する。
			if( detail.componentRole &&
			   (candidate.discoveryBasis == CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE ||
				candidate.discoveryBasis ==
					CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION)) {
				text += loadString( IDS_ASSESSMENT_PACKAGE_SCOPE) + L"\r\n" ;
			}

			text += loadString( IDS_ASSESSMENT_AXIS_METHOD) + L": " +
					loadString( resourceFor( detail.installMethod, METHOD_RESOURCES)) + L" / " +
					loadString( detail.executorAvailable ? IDS_ASSESSMENT_EXECUTOR_AVAILABLE
														: IDS_ASSESSMENT_EXECUTOR_UNAVAILABLE) ;
			const std::array<std::pair<UINT, const CandidateAssessmentFinding *>, 8> axes{
				{{IDS_ASSESSMENT_AXIS_ORIGIN, &detail.origin},
				 {IDS_ASSESSMENT_AXIS_ACQUISITION, &detail.acquisition},
				 {IDS_ASSESSMENT_AXIS_SIGNATURE, &detail.signature},
				 {IDS_ASSESSMENT_AXIS_APPLICABILITY, &detail.applicability},
				 {IDS_ASSESSMENT_AXIS_SELECTION, &detail.windowsSelection},
				 {IDS_ASSESSMENT_AXIS_DRIVER_ONLY, &detail.driverOnly},
				 {IDS_ASSESSMENT_AXIS_REQUIREMENTS, &detail.requirements},
				 {IDS_ASSESSMENT_AXIS_METHOD,
				  &detail.method}}} ;	// 根拠の生情報を含まない主理由の借用。
			// 全八軸を同じ形式で表示し、拒否と確認失敗を分ける。
			for( const auto &[label, finding] : axes) {
				text += L"\r\n" + loadString( label) + L": " +
						loadString( resourceFor( finding->state, STATE_RESOURCES)) + L" — " +
						loadString( resourceFor( finding->reason, REASON_RESOURCES)) ;
				// 元API診断がある場合だけ固定codeを付記する。
				if( finding->diagnostic) {
					text += diagnosticText( *finding->diagnostic) ;
				}
			}

			// 最大16件の明示条件は、任意条件と不足・必要値未知を分けて示す。
			for( const auto &requirement : detail.explicitRequirements) {
				text += L"\r\n  " + loadString( resourceFor( requirement.role, ROLE_RESOURCES)) +
						L" / " +
						loadString( requirement.required ? IDS_ASSESSMENT_REQUIRED
														: IDS_ASSESSMENT_OPTIONAL) +
						L": " +
						loadString( requirement.state == CandidateRequirementState::SATISFIED
									   ? IDS_ASSESSMENT_REQUIREMENT_SATISFIED
								   : requirement.state == CandidateRequirementState::UNSATISFIED
									   ? IDS_ASSESSMENT_REQUIREMENT_UNSATISFIED
									   : IDS_ASSESSMENT_REQUIREMENT_UNVERIFIED) ;
			}
		}
	}

	text += L"\r\n\r\n" + loadString( IDS_ASSESSMENT_NEXT) ;
	// 導入後の保持画面は現在の観測値でなく失効したscanの履歴と明示する。
	if( controller_.scanPurpose() != ScanPurpose::METADATA_ONLY &&
	   controller_.scanSessionId() == 0U) {
		text += L"\r\n" + loadString( IDS_MEASUREMENT_EXPIRED) ;
	}

	return text ;
}

/** @see src/app/main_window.h */
std::wstring MainWindow::formatCandidateAssessment( const UpdateCandidate &candidate) const
{
	// 旧Providerの集約合格から個別検査を捏造しない。
	if( !candidate.assessment) {
		return loadString( IDS_ASSESSMENT_UNCOLLECTED) ;
	}

	// 不正な結合を一覧の合格表現へ流さない。
	if( !isCandidateDetailsValid( candidate)) {
		return loadString( IDS_ASSESSMENT_INCONSISTENT) ;
	}

	const auto	&detail = *candidate.assessment ;	// 同一候補が所有する詳細。
	std::wstring text =
		// 方式は実行許可とは別。
		loadString( resourceFor( detail.installMethod, METHOD_RESOURCES)) ;
	const std::array<const CandidateAssessmentFinding *, 8> axes{
		&detail.origin,			  &detail.acquisition,
		&detail.signature,		  &detail.applicability,
		&detail.windowsSelection, &detail.driverOnly,
		&detail.requirements,	  &detail.method} ;	// 固定順の主理由。
	// 最初の未完了軸だけを一覧へ追加し、全詳細はread-only画面に残す。
	for( const auto *finding : axes) {
		// 合格・委譲・検査済み非該当は保留理由にしない。
		if( finding->state != CandidateAssessmentState::PASSED &&
		   finding->state != CandidateAssessmentState::MANAGED_BY_WINDOWS &&
		   finding->state != CandidateAssessmentState::NOT_APPLICABLE) {
			text += L" / " + loadString( resourceFor( finding->reason, REASON_RESOURCES)) ;
			break ;
		}
	}

	return text ;
}

/** @see src/app/main_window.h */
bool MainWindow::showSelectedCandidateDetails() const
{
	// 処理中または未作成のTreeViewからmodal表示を開始しない。
	if( updateTree_ == nullptr || IsWindowEnabled( updateTree_) == FALSE) {
		return false ;
	}

	TVITEMW item{} ;	// 選択された標準controlのrow parameterだけを読む。
	item.mask  = TVIF_PARAM ;
	item.hItem = TreeView_GetSelection( updateTree_) ;
	// 選択されていない行や消失したitemを参照しない。
	if( item.hItem == nullptr || TreeView_GetItem( updateTree_, &item) == FALSE) {
		return false ;
	}

	const auto *row = treeRowFromParameter( item.lParam) ;	// 本関数がdialogを開く前だけ借用する。
	// 分類・device親のdouble clickは標準の展開操作に残す。
	if( row == nullptr || row->kind != TreeRowKind::CANDIDATE ||
	   row->candidateIndex >= candidates_.size()) {
		return false ;
	}

	const DetailDialogText text{
		loadString( IDS_ASSESSMENT_TITLE),
		formatCandidateDetails(
			candidates_[row->candidateIndex])} ;	// 再入しても候補vectorを借用し続けない。
	// 同期dialog呼出しの間だけtextが生存するため、Win32境界でpointerを渡せる。
	const INT_PTR result = DialogBoxParamW(
		instance_, MAKEINTRESOURCEW( IDD_METADATA_DETAILS), window_, detailDialogProc,
		reinterpret_cast<LPARAM>( &text)) ;	// 本文はread-only editへcopyされる。
	// 標準templateを作成できない場合も、同じ本文の表示だけへfallbackする。
	if( result == -1) {
		MessageBoxW( window_, text.content.c_str(), text.title.c_str(), MB_OK | MB_ICONINFORMATION) ;
	}

	return true ;
}

} // namespace drivercrate
