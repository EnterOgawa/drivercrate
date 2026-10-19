//------------------------------------------------------------------------------
/**
 * @file operation_controller_tests.cpp
 * @brief OperationController単体試験実装。
 * @version 01.02.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Install最終確認取消し試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得確認と独立した操作状態を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  関数comment形式統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  復元ポイント状態試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  反復進捗状態試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  手動再scan遷移試験明確化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Windows Server保護mode試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Scan計測snapshotの寿命と独立拒否試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  準備・導入・終了時の計測寿命試験を拡張。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  観測結合と初回actionの登録拒否を検証。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  通常scanの取消し待ちとABORTED終端を検証。
 * </pre>
 *
 * @note 正常遷移、stale result、およびidentityのfail-closed検証を試験します。
 */
//------------------------------------------------------------------------------

#include "operation_controller_tests.h"

#include "core/operation_controller.h"
#include "test_framework.h"

#include <array>
#include <initializer_list>
#include <string>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 内部試験関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 指定 identity を持つ成功 scan result を作成する。
 *
 * @param[in] sessionId 0 ではない scan session ID。
 * @param[in] identities candidate identity 群。
 * @return UI metadata を最小限にした scan result。
 */
//------------------------------------------------------------------------------
[[nodiscard]] ScanResult makeSuccessfulScan( const ScanSessionId						  sessionId,
											const std::initializer_list<std::wstring> identities)
{
	ScanResult result{} ;	// 指定identity群を含む正常scan結果。
	result.succeeded	 = true ;
	result.scanSessionId = sessionId ;
	result.outcome		 = OutcomeCode::SUCCESS ;
	result.candidates.reserve( identities.size()) ;

	// test が指定した順序と重複を維持し、controller 側の検証対象を正確に作る。
	for( const std::wstring &identity : identities) {
		result.candidates.push_back( {.identity		 = identity,
									 .deviceIdentity = L"device-" + identity,
									 .title			 = L"テスト用ドライバー",
									 .installable	 = true}) ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief Controllerへ渡せる一deviceの有効な段階別計測付きscan結果を作る。
 * @param[in] operationId Scan開始時にControllerが発行したoperation ID。
 * @param[in] sessionId Workerが発行したscan session ID。
 * @return 現在版一行、導入候補一行、固定snapshotを持つ結果。
 */
//------------------------------------------------------------------------------
[[nodiscard]] ScanResult makeSuccessfulMeasuredScan( const OperationId	operationId,
													const ScanSessionId sessionId)
{
	ScanResult result = makeSuccessfulScan( sessionId, {L"current", L"update"}) ;	// 二表示行。
	result.candidates[0].deviceIdentity = L"device" ;
	result.candidates[0].manufacturer	= L"Fixture" ;
	result.candidates[0].driverClass	= L"Net" ;
	result.candidates[0].version		= L"1.0" ;
	result.candidates[0].current		= true ;
	result.candidates[0].installable	= false ;
	result.candidates[1].deviceIdentity = L"device" ;
	ScanMeasurement measurement ;	// Scan完了時点の一device計測。
	measurement.context.operationId					  = operationId ;
	measurement.context.scanSessionId				  = sessionId ;
	measurement.context.applicationVersion			  = L"0.1.0" ;
	measurement.inventory.enumeratedDeviceCount		  = {1U, MeasurementExtent::EXACT} ;
	measurement.inventory.representedDeviceCount	  = {1U, MeasurementExtent::EXACT} ;
	measurement.inventory.unrepresentedDeviceCount	  = {0U, MeasurementExtent::EXACT} ;
	measurement.inventory.missingManufacturerCount	  = {0U, MeasurementExtent::EXACT} ;
	measurement.inventory.missingClassCount			  = {0U, MeasurementExtent::EXACT} ;
	measurement.inventory.missingCurrentVersionCount  = {0U, MeasurementExtent::EXACT} ;
	measurement.inventory.detailedEnumerationComplete = true ;
	result.measurement								  = measurement ;
	result.localCoverage							  = {{.manufacturer = L"Fixture",
														  .driverClass	= L"Net",
														  .deviceCount	= 1U,
														  .measurement	= NetworkCoverageMeasurement{}}} ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief scan 開始から候補受理までの基本遷移を検証する。
 *
 * @param[in,out] context assertion 集計先。
 */
//------------------------------------------------------------------------------
void testScanSuccess( TestContext &context)
{
	OperationController controller ;						// 基本scan遷移の試験対象。
	const BeginResult	begin = controller.beginScan() ;	// Scan開始受付結果。
	DRIVERCRATE_EXPECT( context, begin.accepted) ;
	DRIVERCRATE_EXPECT( context, begin.operationId != 0) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::SCANNING) ;

	// Controllerへ反映する二候補の正常scan結果。
	const ScanResult scan = makeSuccessfulScan( 10, {L"update-a#1", L"update-b#2"}) ;
	DRIVERCRATE_EXPECT( context, controller.completeScan( begin.operationId, scan)) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::SCAN_READY) ;
	DRIVERCRATE_EXPECT( context, controller.scanSessionId() == 10) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 計測snapshotをoperationへ拘束し、不正計測だけを拒否して新scanまで保持する。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testScanMeasurementLifetime( TestContext &context)
{
	OperationController controller ;						// 有効snapshotの寿命を確認する状態機械。
	const BeginResult	begin = controller.beginScan() ;	// 計測へ拘束するoperation。
	const ScanResult	scan =
		// 同じoperationの有効結果。
		makeSuccessfulMeasuredScan( begin.operationId, 101U) ;
	DRIVERCRATE_EXPECT( context, controller.completeScan( begin.operationId, scan)) ;
	DRIVERCRATE_EXPECT( context, controller.scanMeasurement() != nullptr) ;
	const std::array<std::wstring, 1U> selection{L"update"} ;	// 同じdeviceの導入候補。
	const BeginResult				   install = controller.beginInstall(
		 101U, selection, InstallConfirmation::CONFIRMED) ;	// 同じsessionの合成導入操作。
	DRIVERCRATE_EXPECT( context, install.accepted) ;
	DRIVERCRATE_EXPECT( context, controller.scanMeasurement() != nullptr) ;
	InstallResult installed ;	// Scan snapshotを履歴として残す正常な合成導入結果。
	installed.protectionMode		 = InstallProtectionMode::WINDOWS_RESTORE_POINT ;
	installed.restorePointCreation	 = {.outcome = OutcomeCode::SUCCESS, .sequenceNumber = 42} ;
	installed.restorePointCompletion = {.outcome = OutcomeCode::SUCCESS, .sequenceNumber = 42} ;
	installed.succeeded				 = true ;
	installed.downloadOutcome		 = OutcomeCode::SUCCESS ;
	installed.installOutcome		 = OutcomeCode::SUCCESS ;
	installed.updates.push_back( {.identity		  = L"update",
								 .downloadOutcome = OutcomeCode::SUCCESS,
								 .installOutcome  = OutcomeCode::SUCCESS}) ;
	DRIVERCRATE_EXPECT( context, controller.completeInstall( install.operationId, installed)) ;
	DRIVERCRATE_EXPECT( context, controller.scanSessionId() == 0U) ;
	DRIVERCRATE_EXPECT( context, controller.scanMeasurement() != nullptr) ;

	OperationController invalidController ;								// 計測だけが不正なscanを確認する別状態機械。
	const BeginResult	invalidBegin = invalidController.beginScan() ;	// 現在のoperation。
	ScanResult			invalid =
		// 別operationの計測。
		makeSuccessfulMeasuredScan( invalidBegin.operationId + 1U, 102U) ;
	DRIVERCRATE_EXPECT( context, invalidController.completeScan( invalidBegin.operationId, invalid)) ;
	DRIVERCRATE_EXPECT( context, invalidController.state() == ApplicationState::SCAN_READY) ;
	DRIVERCRATE_EXPECT( context, invalidController.scanMeasurement() == nullptr) ;
	DRIVERCRATE_EXPECT(
		context,
		invalidController.beginInstall( 102U, selection, InstallConfirmation::CONFIRMED).accepted) ;

	OperationController rescanController ;						// 新scanによるsnapshot破棄を確認する状態機械。
	const BeginResult	first = rescanController.beginScan() ;	// 最初のscan operation。
	DRIVERCRATE_EXPECT( context,
					   rescanController.completeScan(
						   first.operationId, makeSuccessfulMeasuredScan( first.operationId, 103U))) ;
	DRIVERCRATE_EXPECT( context, rescanController.scanMeasurement() != nullptr) ;
	DRIVERCRATE_EXPECT( context, rescanController.beginScan().accepted) ;
	DRIVERCRATE_EXPECT( context, rescanController.scanMeasurement() == nullptr) ;

	OperationController closingController ;							// Window close相当のstopでsnapshotを破棄する状態機械。
	const BeginResult	closing = closingController.beginScan() ;	// 終了前に完了させるscan操作。
	const ScanResult	closingScan =
		// 終了時に破棄する有効snapshot。
		makeSuccessfulMeasuredScan( closing.operationId, 104U) ;
	DRIVERCRATE_EXPECT( context, closingController.completeScan( closing.operationId, closingScan)) ;
	closingController.stop() ;
	DRIVERCRATE_EXPECT( context, closingController.scanMeasurement() == nullptr) ;
	DRIVERCRATE_EXPECT( context, !closingController.completeScan( closing.operationId, closingScan)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 古い operation ID の scan resultが現在状態を変更しないことを検証する。
 *
 * @param[in,out] context assertion 集計先。
 */
//------------------------------------------------------------------------------
void testStaleScanResultIsRejected( TestContext &context)
{
	OperationController controller ;										// Stale result拒否の試験対象。
	const BeginResult	begin = controller.beginScan() ;					// 現在有効なscan開始結果。
	const ScanResult	scan  = makeSuccessfulScan( 11, {L"update-a#1"}) ;	// 遅延扱いする結果。

	DRIVERCRATE_EXPECT( context, !controller.completeScan( begin.operationId + 1, scan)) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::SCANNING) ;
	DRIVERCRATE_EXPECT( context, controller.scanSessionId() == 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常scanの取消し待ちが同じoperationのABORTED結果だけを受理することを検証する。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testScanCancellation( TestContext &context)
{
	OperationController controller ;						// 通常scan取消しの試験対象。
	const BeginResult	begin = controller.beginScan() ;	// 現在の通常scan operation。
	DRIVERCRATE_EXPECT( context, !controller.markScanCancelling( begin.operationId + 1U)) ;
	DRIVERCRATE_EXPECT( context, controller.markScanCancelling( begin.operationId)) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::CANCELLING_SCAN) ;
	DRIVERCRATE_EXPECT( context, controller.beginScan().error == BeginError::BUSY) ;

	ScanResult aborted ;	// Workerが協調取消しを確認した通常scan終端。
	aborted.purpose = ScanPurpose::STANDARD ;
	aborted.outcome = OutcomeCode::ABORTED ;
	DRIVERCRATE_EXPECT( context, controller.completeScan( begin.operationId, aborted)) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::IDLE) ;
	DRIVERCRATE_EXPECT( context, controller.scanSessionId() == 0U) ;

	const BeginResult malformedBegin = controller.beginScan() ;	// 不正成功通知用の次operation。
	DRIVERCRATE_EXPECT( context, controller.markScanCancelling( malformedBegin.operationId)) ;
	const ScanResult malformed = makeSuccessfulScan( 12U, {}) ;	// 取消し後の成功偽装結果。
	DRIVERCRATE_EXPECT( context, controller.completeScan( malformedBegin.operationId, malformed)) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::FAILURE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief duplicate または空 identity を含む Provider resultを公開しないことを検証する。
 *
 * @param[in,out] context assertion 集計先。
 */
//------------------------------------------------------------------------------
void testInvalidScanIdentityIsRejected( TestContext &context)
{
	OperationController duplicateController ;								// 重複identity拒否の試験対象。
	const BeginResult	duplicateBegin = duplicateController.beginScan() ;	// Scan開始結果。
	// 同一identityを二件含む不正result。
	const ScanResult	duplicateScan = makeSuccessfulScan( 12, {L"update-a#1", L"update-a#1"}) ;
	DRIVERCRATE_EXPECT( context,
					   duplicateController.completeScan( duplicateBegin.operationId, duplicateScan)) ;
	DRIVERCRATE_EXPECT( context, duplicateController.state() == ApplicationState::FAILURE) ;

	OperationController emptyController ;								// 空identity拒否の試験対象。
	const BeginResult	emptyBegin = emptyController.beginScan() ;		// Scan開始結果。
	const ScanResult	emptyScan  = makeSuccessfulScan( 13, {L""}) ;	// 空identityを含む不正result。
	DRIVERCRATE_EXPECT( context, emptyController.completeScan( emptyBegin.operationId, emptyScan)) ;
	DRIVERCRATE_EXPECT( context, emptyController.state() == ApplicationState::FAILURE) ;

	OperationController outcomeController ;								// Outcome矛盾拒否の試験対象。
	const BeginResult	outcomeBegin = outcomeController.beginScan() ;	// Scan開始結果。
	// succeededとFailed outcomeが矛盾するresult。
	ScanResult			inconsistentScan = makeSuccessfulScan( 18, {L"update-a#1"}) ;
	inconsistentScan.outcome			 = OutcomeCode::FAILURE ;
	DRIVERCRATE_EXPECT( context,
					   outcomeController.completeScan( outcomeBegin.operationId, inconsistentScan)) ;
	DRIVERCRATE_EXPECT( context, outcomeController.state() == ApplicationState::FAILURE) ;

	OperationController deviceController ;								// Device identity欠損拒否の試験対象。
	const BeginResult	deviceBegin = deviceController.beginScan() ;	// Scan開始結果。
	// Device identityを後で空にする不正result。
	ScanResult			missingDeviceScan = makeSuccessfulScan( 19, {L"update-a#1"}) ;
	missingDeviceScan.candidates[0].deviceIdentity.clear() ;
	DRIVERCRATE_EXPECT( context,
					   deviceController.completeScan( deviceBegin.operationId, missingDeviceScan)) ;
	DRIVERCRATE_EXPECT( context, deviceController.state() == ApplicationState::FAILURE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief scan failure と 0 件成功を別 state として扱うことを検証する。
 *
 * scan failure と 0 件成功を別 stateとして扱うことを検証する。
 *
 * @param[in,out] context assertion 集計先。
 */
//------------------------------------------------------------------------------
void testEmptyScanAndFailedScanAreDistinct( TestContext &context)
{
	OperationController emptyController ;							// 0件成功を検証する試験対象。
	const BeginResult	emptyBegin = emptyController.beginScan() ;	// Scan開始結果。
	const ScanResult	emptyScan  = makeSuccessfulScan( 14, {}) ;	// 候補0件の正常result。
	DRIVERCRATE_EXPECT( context, emptyController.completeScan( emptyBegin.operationId, emptyScan)) ;
	DRIVERCRATE_EXPECT( context, emptyController.state() == ApplicationState::SCAN_READY) ;

	OperationController failedController ;								// Provider失敗を検証する試験対象。
	const BeginResult	failedBegin = failedController.beginScan() ;	// Scan開始結果。
	ScanResult			failedScan{} ;									// succeeded=falseのProvider失敗result。
	failedScan.outcome = OutcomeCode::FAILURE ;
	failedScan.error   = -1 ;
	DRIVERCRATE_EXPECT( context, failedController.completeScan( failedBegin.operationId, failedScan)) ;
	DRIVERCRATE_EXPECT( context, failedController.state() == ApplicationState::FAILURE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief empty、stale、unknown、duplicate selection が installを開始しないことを検証する。
 *
 * @param[in,out] context assertion 集計先。
 */
//------------------------------------------------------------------------------
void testInstallSelectionValidation( TestContext &context)
{
	OperationController controller ;							// Install selection検証の試験対象。
	const BeginResult	scanBegin = controller.beginScan() ;	// Scan開始結果。
	// 選択元となる二候補の正常result。
	const ScanResult	scan = makeSuccessfulScan( 15, {L"update-a#1", L"update-b#1"}) ;
	DRIVERCRATE_EXPECT( context, controller.completeScan( scanBegin.operationId, scan)) ;

	const std::vector<std::wstring> emptySelection ;	// EmptySelectionを発生させる空集合。
	const BeginResult				empty =
		// 拒否結果。
		controller.beginInstall( 15, emptySelection, InstallConfirmation::CONFIRMED) ;
	DRIVERCRATE_EXPECT( context, !empty.accepted) ;
	DRIVERCRATE_EXPECT( context, empty.error == BeginError::EMPTY_SELECTION) ;

	const std::array  staleSelection{std::wstring( L"update-a#1")} ;	// 古いsession用selection。
	const BeginResult stale =
		// 拒否結果。
		controller.beginInstall( 99, staleSelection, InstallConfirmation::CONFIRMED) ;
	DRIVERCRATE_EXPECT( context, !stale.accepted) ;
	DRIVERCRATE_EXPECT( context, stale.error == BeginError::STALE_SCAN_SESSION) ;

	const std::array  unknownSelection{std::wstring( L"update-c#1")} ;	// 未表示identity集合。
	const BeginResult unknown =
		// 拒否結果。
		controller.beginInstall( 15, unknownSelection, InstallConfirmation::CONFIRMED) ;
	DRIVERCRATE_EXPECT( context, !unknown.accepted) ;
	DRIVERCRATE_EXPECT( context, unknown.error == BeginError::UNKNOWN_IDENTITY) ;

	// 同一identityを二回含むselection。
	const std::array  duplicateSelection{std::wstring( L"update-a#1"), std::wstring( L"update-a#1")} ;
	const BeginResult duplicate = controller.beginInstall(
		15, duplicateSelection, InstallConfirmation::CONFIRMED) ;	// 拒否結果。
	DRIVERCRATE_EXPECT( context, !duplicate.accepted) ;
	DRIVERCRATE_EXPECT( context, duplicate.error == BeginError::DUPLICATE_IDENTITY) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::SCAN_READY) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 最終確認の取消しと定義外値をoperation ID発行前に拒否し、現在のscan候補を変更せずworker送信可能状態へ進めない。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testInstallConfirmationIsRequired( TestContext &context)
{
	OperationController controller ;							// 最終確認拒否の試験対象。
	const BeginResult	scanBegin = controller.beginScan() ;	// Scan開始結果。
	const ScanResult	scan =
		// 確認対象となる一候補のscan結果。
		makeSuccessfulScan( 26, {L"driver-a"}) ;
	DRIVERCRATE_EXPECT( context, controller.completeScan( scanBegin.operationId, scan)) ;
	const OperationId operationBefore =
		// 取消し前の最後のoperation ID。
		controller.activeOperationId() ;
	const std::array  selection{std::wstring( L"driver-a")} ;	// 表示中の正常な選択集合。

	const BeginResult cancelled = controller.beginInstall(
		26, selection, InstallConfirmation::NOT_CONFIRMED) ;	// Dialog取消しを表す開始要求。
	DRIVERCRATE_EXPECT( context, !cancelled.accepted) ;
	DRIVERCRATE_EXPECT( context, cancelled.operationId == 0U) ;
	DRIVERCRATE_EXPECT( context, cancelled.error == BeginError::CONFIRMATION_REQUIRED) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::SCAN_READY) ;
	DRIVERCRATE_EXPECT( context, controller.scanSessionId() == 26U) ;
	DRIVERCRATE_EXPECT( context, controller.activeOperationId() == operationBefore) ;

	const BeginResult invalid = controller.beginInstall(
		26, selection, static_cast<InstallConfirmation>( 999)) ;	// 定義外の確認状態。
	DRIVERCRATE_EXPECT( context, !invalid.accepted) ;
	DRIVERCRATE_EXPECT( context, invalid.operationId == 0U) ;
	DRIVERCRATE_EXPECT( context, invalid.error == BeginError::CONFIRMATION_REQUIRED) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::SCAN_READY) ;
	DRIVERCRATE_EXPECT( context, controller.activeOperationId() == operationBefore) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在使用中など表示専用 candidate を install対象として受理しないことを検証する。
 *
 * @param[in,out] context assertion 集計先。
 */
//------------------------------------------------------------------------------
void testNonInstallableCandidateIsRejected( TestContext &context)
{
	OperationController controller ;							// 表示専用候補拒否の試験対象。
	const BeginResult	scanBegin = controller.beginScan() ;	// Scan開始結果。
	// 現在版とinstallable候補を含むscan結果。
	ScanResult			scan	   = makeSuccessfulScan( 20, {L"current-driver", L"update-a#1"}) ;
	scan.candidates[0].installable = false ;
	DRIVERCRATE_EXPECT( context, controller.completeScan( scanBegin.operationId, scan)) ;

	const std::array  currentSelection{std::wstring( L"current-driver")} ;	// 表示専用選択。
	const BeginResult install =
		// 拒否結果。
		controller.beginInstall( 20, currentSelection, InstallConfirmation::CONFIRMED) ;
	DRIVERCRATE_EXPECT( context, !install.accepted) ;
	DRIVERCRATE_EXPECT( context, install.error == BeginError::UNKNOWN_IDENTITY) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::SCAN_READY) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同一 device の複数 driver 候補を一 operationで受理しないことを検証する。
 *
 * @param[in,out] context assertion 集計先。
 */
//------------------------------------------------------------------------------
void testDuplicateDeviceSelectionIsRejected( TestContext &context)
{
	OperationController controller ;													// 同一device複数版拒否の試験対象。
	const BeginResult	scanBegin = controller.beginScan() ;							// Scan開始結果。
	ScanResult			scan = makeSuccessfulScan( 21, {L"driver-a", L"driver-b"}) ;	// 二候補結果。
	scan.candidates[1].deviceIdentity = scan.candidates[0].deviceIdentity ;
	DRIVERCRATE_EXPECT( context, controller.completeScan( scanBegin.operationId, scan)) ;

	// 同一deviceに関連付けた複数版のselection。
	const std::array  selection{std::wstring( L"driver-a"), std::wstring( L"driver-b")} ;
	const BeginResult install =
		// 拒否結果。
		controller.beginInstall( 21, selection, InstallConfirmation::CONFIRMED) ;
	DRIVERCRATE_EXPECT( context, !install.accepted) ;
	DRIVERCRATE_EXPECT( context, install.error == BeginError::DUPLICATE_DEVICE_SELECTION) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::SCAN_READY) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 有効 selection の download、install、完了遷移と identity失効を検証する。
 *
 * @param[in,out] context assertion 集計先。
 */
//------------------------------------------------------------------------------
void testInstallLifecycle( TestContext &context)
{
	OperationController controller ;							// Install lifecycleの試験対象。
	const BeginResult	scanBegin = controller.beginScan() ;	// Scan開始結果。
	// 選択元となる二候補の正常result。
	const ScanResult	scan = makeSuccessfulScan( 16, {L"update-a#1", L"update-b#1"}) ;
	DRIVERCRATE_EXPECT( context, controller.completeScan( scanBegin.operationId, scan)) ;

	const std::array  selection{std::wstring( L"update-b#1")} ;	// Install対象一件。
	const BeginResult install =
		// Install開始結果。
		controller.beginInstall( 16, selection, InstallConfirmation::CONFIRMED) ;
	DRIVERCRATE_EXPECT( context, install.accepted) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::CREATING_RESTORE_POINT) ;
	DRIVERCRATE_EXPECT( context, controller.markDownloading( install.operationId)) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::DOWNLOADING) ;
	DRIVERCRATE_EXPECT( context, controller.markDownloading( install.operationId)) ;
	DRIVERCRATE_EXPECT( context, controller.markInstalling( install.operationId)) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::INSTALLING) ;
	DRIVERCRATE_EXPECT( context, controller.markInstalling( install.operationId)) ;
	InstallResult installResult{} ;	// 全段階成功を表すProvider result。
	installResult.restorePointCreation	 = {.outcome = OutcomeCode::SUCCESS, .sequenceNumber = 42} ;
	installResult.restorePointCompletion = {.outcome = OutcomeCode::SUCCESS, .sequenceNumber = 42} ;
	installResult.succeeded				 = true ;
	installResult.downloadOutcome		 = OutcomeCode::SUCCESS ;
	installResult.installOutcome		 = OutcomeCode::SUCCESS ;
	installResult.updates.push_back( {.identity		  = L"update-b#1",
									 .downloadOutcome = OutcomeCode::SUCCESS,
									 .installOutcome  = OutcomeCode::SUCCESS}) ;
	DRIVERCRATE_EXPECT( context, controller.completeInstall( install.operationId, installResult)) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::COMPLETED) ;
	DRIVERCRATE_EXPECT( context, controller.scanSessionId() == 0) ;

	const BeginResult repeat =
		// 再要求。
		controller.beginInstall( 16, selection, InstallConfirmation::CONFIRMED) ;
	DRIVERCRATE_EXPECT( context, !repeat.accepted) ;
	DRIVERCRATE_EXPECT( context, repeat.error == BeginError::NO_SCAN_RESULT) ;
	const BeginResult manualScan = controller.beginScan() ;	// 利用者操作相当の新規scan開始結果。
	DRIVERCRATE_EXPECT( context, manualScan.accepted) ;
	DRIVERCRATE_EXPECT( context, manualScan.operationId != install.operationId) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::SCANNING) ;
}

//------------------------------------------------------------------------------
/**
 * @brief selection と一致しない Provider successを失敗として適用することを検証する。
 *
 * @param[in,out] context assertion 集計先。
 */
//------------------------------------------------------------------------------
void testInvalidInstallSuccessIsRejected( TestContext &context)
{
	OperationController controller ;							// 不一致success拒否の試験対象。
	const BeginResult	scanBegin = controller.beginScan() ;	// Scan開始結果。
	// 選択元となる二候補の正常result。
	const ScanResult	scan = makeSuccessfulScan( 17, {L"update-a#1", L"update-b#1"}) ;
	DRIVERCRATE_EXPECT( context, controller.completeScan( scanBegin.operationId, scan)) ;

	const std::array  selection{std::wstring( L"update-a#1")} ;	// 実際のinstall selection。
	const BeginResult install =
		// Install開始結果。
		controller.beginInstall( 17, selection, InstallConfirmation::CONFIRMED) ;
	DRIVERCRATE_EXPECT( context, install.accepted) ;

	InstallResult invalidResult{} ;	// 未選択identityを成功とする不正Provider result。
	invalidResult.restorePointCreation	 = {.outcome = OutcomeCode::SUCCESS, .sequenceNumber = 43} ;
	invalidResult.restorePointCompletion = {.outcome = OutcomeCode::SUCCESS, .sequenceNumber = 43} ;
	invalidResult.succeeded				 = true ;
	invalidResult.downloadOutcome		 = OutcomeCode::SUCCESS ;
	invalidResult.installOutcome		 = OutcomeCode::SUCCESS ;
	invalidResult.updates.push_back( {.identity		  = L"update-b#1",
									 .downloadOutcome = OutcomeCode::SUCCESS,
									 .installOutcome  = OutcomeCode::SUCCESS}) ;
	DRIVERCRATE_EXPECT( context, controller.completeInstall( install.operationId, invalidResult)) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::FAILURE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 復元ポイント開始失敗をinstall開始前の状態から完了できることを検証する。
 *
 * 復元ポイント作成中のfail-closed結果を受理し、Provider段階へ進まずFailedへ遷移することを検証する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testRestorePointFailureLifecycle( TestContext &context)
{
	OperationController controller ;											// 復元失敗遷移の試験対象。
	const BeginResult	scanBegin = controller.beginScan() ;					// Scan開始結果。
	const ScanResult	scan	  = makeSuccessfulScan( 22, {L"driver-a"}) ;	// 選択元候補。
	DRIVERCRATE_EXPECT( context, controller.completeScan( scanBegin.operationId, scan)) ;

	const std::array  selection{std::wstring( L"driver-a")} ;	// Install対象一件。
	const BeginResult install =
		// Install開始結果。
		controller.beginInstall( 22, selection, InstallConfirmation::CONFIRMED) ;
	DRIVERCRATE_EXPECT( context, install.accepted) ;
	InstallResult result{} ;	// 復元ポイント作成失敗による未開始結果。
	result.restorePointCreation = {.outcome = OutcomeCode::FAILURE, .error = 5} ;
	result.updates.push_back( {.identity = L"driver-a"}) ;
	DRIVERCRATE_EXPECT( context, controller.completeInstall( install.operationId, result)) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::FAILURE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows Server専用保護modeの正常完了を検証する。
 *
 * 復元ポイント結果がNotStartedのServer専用成功だけを受理し、scan sessionを失効させることを検証する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testServerInstallLifecycle( TestContext &context)
{
	OperationController controller ;											// Server遷移の試験対象。
	const BeginResult	scanBegin = controller.beginScan() ;					// Scan開始結果。
	const ScanResult	scan	  = makeSuccessfulScan( 23, {L"driver-a"}) ;	// 選択元候補。
	DRIVERCRATE_EXPECT( context, controller.completeScan( scanBegin.operationId, scan)) ;

	const std::array  selection{std::wstring( L"driver-a")} ;	// Install対象一件。
	const BeginResult install = controller.beginInstall(
		23, selection, InstallConfirmation::CONFIRMED,
		InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT) ;	// Install開始結果。
	DRIVERCRATE_EXPECT( context, install.accepted) ;
	DRIVERCRATE_EXPECT( context, controller.markDownloading( install.operationId)) ;
	DRIVERCRATE_EXPECT( context, controller.markInstalling( install.operationId)) ;

	InstallResult result{} ;	// Server専用の全段階成功結果。
	result.protectionMode  = InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT ;
	result.succeeded	   = true ;
	result.downloadOutcome = OutcomeCode::SUCCESS ;
	result.installOutcome  = OutcomeCode::SUCCESS ;
	result.updates.push_back( {.identity		   = L"driver-a",
							  .downloadOutcome = OutcomeCode::SUCCESS,
							  .installOutcome  = OutcomeCode::SUCCESS}) ;
	DRIVERCRATE_EXPECT( context, controller.completeInstall( install.operationId, result)) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::COMPLETED) ;
	DRIVERCRATE_EXPECT( context, controller.scanSessionId() == 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 開始時と異なるinstall保護modeの成功を拒否する。
 *
 * Server専用operationへclient用成功結果を返してもCompletedへ遷移しないことを検証する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testInstallProtectionModeMismatch( TestContext &context)
{
	OperationController controller ;											// Mode不一致の試験対象。
	const BeginResult	scanBegin = controller.beginScan() ;					// Scan開始結果。
	const ScanResult	scan	  = makeSuccessfulScan( 24, {L"driver-a"}) ;	// 選択元候補。
	DRIVERCRATE_EXPECT( context, controller.completeScan( scanBegin.operationId, scan)) ;

	const std::array  selection{std::wstring( L"driver-a")} ;	// Install対象一件。
	const BeginResult install = controller.beginInstall(
		24, selection, InstallConfirmation::CONFIRMED,
		InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT) ;	// Install開始結果。
	DRIVERCRATE_EXPECT( context, install.accepted) ;

	InstallResult result{} ;	// Client用保護modeを持つ不正な成功結果。
	result.restorePointCreation	  = {.outcome = OutcomeCode::SUCCESS, .sequenceNumber = 45} ;
	result.restorePointCompletion = {.outcome = OutcomeCode::SUCCESS, .sequenceNumber = 45} ;
	result.succeeded			  = true ;
	result.downloadOutcome		  = OutcomeCode::SUCCESS ;
	result.installOutcome		  = OutcomeCode::SUCCESS ;
	result.updates.push_back( {.identity		   = L"driver-a",
							  .downloadOutcome = OutcomeCode::SUCCESS,
							  .installOutcome  = OutcomeCode::SUCCESS}) ;
	DRIVERCRATE_EXPECT( context, controller.completeInstall( install.operationId, result)) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::FAILURE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 定義外のinstall保護modeを開始前に拒否する。
 *
 * 列挙外の値でOS別回復契約を迂回できないことを検証する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testInvalidInstallProtectionMode( TestContext &context)
{
	OperationController controller ;											// 不正mode拒否の試験対象。
	const BeginResult	scanBegin = controller.beginScan() ;					// Scan開始結果。
	const ScanResult	scan	  = makeSuccessfulScan( 25, {L"driver-a"}) ;	// 選択元候補。
	DRIVERCRATE_EXPECT( context, controller.completeScan( scanBegin.operationId, scan)) ;

	const std::array  selection{std::wstring( L"driver-a")} ;	// Install対象一件。
	const BeginResult install =
		controller.beginInstall( 25, selection, InstallConfirmation::CONFIRMED,
								// 不正modeの開始結果。
								static_cast<InstallProtectionMode>( 999)) ;
	DRIVERCRATE_EXPECT( context, !install.accepted) ;
	DRIVERCRATE_EXPECT( context, install.error == BeginError::INVALID_PROTECTION_MODE) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::SCAN_READY) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二重 operation と停止後の開始を拒否することを検証する。
 *
 * @param[in,out] context assertion 集計先。
 */
//------------------------------------------------------------------------------
void testBusyAndStoppingRejection( TestContext &context)
{
	OperationController controller ;							// BusyとStopping拒否の試験対象。
	const BeginResult	firstScan = controller.beginScan() ;	// 最初のscan開始結果。
	DRIVERCRATE_EXPECT( context, firstScan.accepted) ;

	const BeginResult secondScan = controller.beginScan() ;	// Scan中の二重開始結果。
	DRIVERCRATE_EXPECT( context, !secondScan.accepted) ;
	DRIVERCRATE_EXPECT( context, secondScan.error == BeginError::BUSY) ;

	controller.stop() ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::STOPPING) ;
	const BeginResult stoppedScan = controller.beginScan() ;	// Stop後の開始結果。
	DRIVERCRATE_EXPECT( context, !stoppedScan.accepted) ;
	DRIVERCRATE_EXPECT( context, stoppedScan.error == BeginError::STOPPING) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実network、device、復元ポイントへ接続しない。
 * @return 架空の二配布物を持つ計画。
 */
//------------------------------------------------------------------------------
OfficialPreparationPlan makeControllerPreparationPlan()
{
	OfficialPreparationPlan plan ;	// Controllerの表示snapshot照合に使用する合成計画。
	plan.scanSessionId = 1 ;
	plan.planId		   = 1 ;
	plan.limits		   = {100, 200, 300, 2, 3} ;
	plan.targets = {{L"target-one", L"prolific-official", L"payload", L"release-one", 1, 100, 1,
					 OfficialPreparationTerms::CONFIRMED_NO_CONSENT, L""},
					{L"target-two", L"prolific-official", L"payload", L"release-two", 1, 100, 1,
					 OfficialPreparationTerms::CONFIRMED_NO_CONSENT, L""}} ;
	return plan ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未選択対象もsnapshotに残し、install選択とは共有しない。
 *
 * @param[in] plan 対象別判断を作る合成計画。
 * @return 最初だけを選択した未採番の承認。
 */
//------------------------------------------------------------------------------
OfficialPreparationApproval makeControllerPreparationApproval( const OfficialPreparationPlan &plan)
{
	OfficialPreparationApproval approval ;	// UIがworker送信前に作る承認。
	approval.scanSessionId = plan.scanSessionId ;
	approval.planId		   = plan.planId ;
	approval.limits		   = plan.limits ;
	approval.decisions	   = {{plan.targets[0], true, false, false},
							  {plan.targets[1], false, false, false}} ;
	return approval ;
}

//------------------------------------------------------------------------------
/**
 * @brief 取得済みは検査用の状態であり、driver導入の成功ではない。
 *
 * @param[in] approval Controller受理後の採番済み承認。
 * @return 最初を取得し、二番目を取得しない確定結果。
 */
//------------------------------------------------------------------------------
OfficialPreparationOperationResult makeControllerPreparationResult(
	const OfficialPreparationApproval &approval)
{
	OfficialPreparationOperationResult result ;	// 正当な完了と変造結果の基準値。
	result.operationId	 = approval.operationId ;
	result.scanSessionId = approval.scanSessionId ;
	result.planId		 = approval.planId ;
	result.approvalError = OfficialPreparationError::NONE ;
	result.items		 = {{approval.decisions[0].target.identity,
							 {OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0, 50}},
							{approval.decisions[1].target.identity,
							 {OfficialPreparationItemState::NOT_SELECTED, 0, 0}}} ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 取得と導入の排他、取消し待ち、導入選択の保持を検証する。
 *
 * @param[in,out] context 内部試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testPreparationLifecycleAndInstallIndependence( TestContext &context)
{
	OperationController controller ;					// 今回の取得操作を管理するUI状態。
	const BeginResult	scan = controller.beginScan() ;	// 表示候補を保持する検索操作。
	DRIVERCRATE_EXPECT( context,
					   controller.completeScan( scan.operationId,
											   makeSuccessfulMeasuredScan( scan.operationId, 1U))) ;
	DRIVERCRATE_EXPECT( context, controller.scanMeasurement() != nullptr) ;
	const OfficialPreparationPlan plan = makeControllerPreparationPlan() ;	// 有効な合成取得計画。
	DRIVERCRATE_EXPECT( context, controller.setPreparationPlan( scan.operationId, plan)) ;
	OfficialPreparationApproval approval = makeControllerPreparationApproval( plan) ;	// 部分選択。

	DRIVERCRATE_EXPECT( context, controller.beginPreparation( approval).accepted) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::PREPARING) ;
	DRIVERCRATE_EXPECT( context, controller.preparationPlan() == nullptr) ;
	DRIVERCRATE_EXPECT( context, controller.beginScan().error == BeginError::BUSY) ;
	const std::array<std::wstring, 1> selection{L"update"} ;	// 取得とは別のinstall候補選択。
	DRIVERCRATE_EXPECT(
		context, controller.beginInstall( 1, selection, InstallConfirmation::CONFIRMED).error ==
					 BeginError::BUSY) ;
	DRIVERCRATE_EXPECT( context, !controller.markDownloading( approval.operationId)) ;
	DRIVERCRATE_EXPECT( context, !controller.markInstalling( approval.operationId)) ;
	DRIVERCRATE_EXPECT( context, !controller.markPreparationCancelling( approval.operationId + 1)) ;
	DRIVERCRATE_EXPECT( context, controller.markPreparationCancelling( approval.operationId)) ;
	DRIVERCRATE_EXPECT( context, controller.beginScan().error == BeginError::BUSY) ;
	DRIVERCRATE_EXPECT( context,
					   controller.completePreparation( makeControllerPreparationResult( approval))) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::SCAN_READY) ;
	DRIVERCRATE_EXPECT( context, controller.scanSessionId() == 1) ;
	DRIVERCRATE_EXPECT( context, controller.scanMeasurement() != nullptr) ;
	DRIVERCRATE_EXPECT( context, controller.preparationPlan() == nullptr) ;
	DRIVERCRATE_EXPECT( context,
					   controller.beginPreparation( approval).error == BeginError::NO_SCAN_RESULT) ;
	DRIVERCRATE_EXPECT(
		context, controller.beginInstall( 1, selection, InstallConfirmation::CONFIRMED).accepted) ;
	DRIVERCRATE_EXPECT( context, controller.scanMeasurement() != nullptr) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不正snapshot、全拒否、古い承認を送信前に拒否する。
 *
 * @param[in,out] context 内部試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testPreparationApprovalRejection( TestContext &context)
{
	OperationController controller ;					// 今回の取得操作を管理するUI状態。
	const BeginResult	scan = controller.beginScan() ;	// 表示候補を保持する検索操作。
	DRIVERCRATE_EXPECT( context,
					   controller.completeScan( scan.operationId, makeSuccessfulScan( 1, {L"one"}))) ;
	const OfficialPreparationPlan plan = makeControllerPreparationPlan() ;	// 有効な合成取得計画。
	DRIVERCRATE_EXPECT( context, controller.setPreparationPlan( scan.operationId, plan)) ;
	OfficialPreparationApproval approval = makeControllerPreparationApproval( plan) ;	// 部分選択。

	OfficialPreparationApproval invalid = approval ;	// 各拒否条件だけを変える承認copy。
	invalid.decisions[0].acquire		= false ;
	DRIVERCRATE_EXPECT( context,
					   controller.beginPreparation( invalid).error == BeginError::EMPTY_SELECTION) ;
	invalid				  = approval ;
	invalid.scanSessionId = 2 ;
	DRIVERCRATE_EXPECT( context, controller.beginPreparation( invalid).error ==
									BeginError::STALE_SCAN_SESSION) ;
	invalid									 = approval ;
	invalid.decisions[0].target.maximumBytes = 99 ;
	DRIVERCRATE_EXPECT( context, controller.beginPreparation( invalid).error ==
									BeginError::INVALID_PREPARATION) ;
	DRIVERCRATE_EXPECT( context, invalid.operationId == 0) ;
	invalid				= approval ;
	invalid.operationId = 10 ;
	DRIVERCRATE_EXPECT( context, controller.beginPreparation( invalid).error ==
									BeginError::INVALID_PREPARATION) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::SCAN_READY) ;
	DRIVERCRATE_EXPECT( context, controller.beginPreparation( approval).accepted) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 別操作、別session、別planと停止後の結果を破棄する。
 *
 * @param[in,out] context 内部試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testPreparationStaleCompletion( TestContext &context)
{
	OperationController controller ;					// 今回の取得操作を管理するUI状態。
	const BeginResult	scan = controller.beginScan() ;	// 表示候補を保持する検索操作。
	DRIVERCRATE_EXPECT( context,
					   controller.completeScan( scan.operationId, makeSuccessfulScan( 1, {L"one"}))) ;
	const OfficialPreparationPlan plan = makeControllerPreparationPlan() ;	// 有効な合成取得計画。
	DRIVERCRATE_EXPECT( context, controller.setPreparationPlan( scan.operationId, plan)) ;
	OfficialPreparationApproval approval = makeControllerPreparationApproval( plan) ;	// 部分選択。

	DRIVERCRATE_EXPECT( context, controller.beginPreparation( approval).accepted) ;
	// Stale条件だけを変更するための正当な完了snapshot。
	const OfficialPreparationOperationResult expected = makeControllerPreparationResult( approval) ;
	// 正当な完了を変造するcopyで、三つのidentity境界を個別に検証する。
	OfficialPreparationOperationResult		 stale = expected ;
	++stale.operationId ;
	DRIVERCRATE_EXPECT( context, !controller.completePreparation( stale)) ;
	stale = expected ;
	++stale.scanSessionId ;
	DRIVERCRATE_EXPECT( context, !controller.completePreparation( stale)) ;
	stale = expected ;
	++stale.planId ;
	DRIVERCRATE_EXPECT( context, !controller.completePreparation( stale)) ;
	DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::PREPARING) ;
	controller.stop() ;
	DRIVERCRATE_EXPECT( context, !controller.completePreparation( expected)) ;
	DRIVERCRATE_EXPECT( context,
					   controller.beginPreparation( approval).error == BeginError::STOPPING) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 重複、未選択取得、欠落、非終端、容量矛盾を成功表示しない。
 *
 * @param[in,out] context 内部試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testPreparationInvalidResults( TestContext &context)
{
	// 八種類の不正結果はそれぞれ新しいcontrollerで検証する。
	for( int scenario = 0; scenario < 8; ++scenario) {
		OperationController controller ;					// 今回の取得操作を管理するUI状態。
		const BeginResult	scan = controller.beginScan() ;	// 表示候補を保持する検索操作。
		DRIVERCRATE_EXPECT(
			context, controller.completeScan( scan.operationId, makeSuccessfulScan( 1, {L"one"}))) ;
		const OfficialPreparationPlan plan =
			// 有効な合成取得計画。
			makeControllerPreparationPlan() ;
		DRIVERCRATE_EXPECT( context, controller.setPreparationPlan( scan.operationId, plan)) ;
		OfficialPreparationApproval approval =
			// 部分選択。
			makeControllerPreparationApproval( plan) ;

		DRIVERCRATE_EXPECT( context, controller.beginPreparation( approval).accepted) ;
		// 一条件だけを変造し、矛盾した成功を拒否する検証用結果。
		OfficialPreparationOperationResult result = makeControllerPreparationResult( approval) ;
		// 一条件だけを変えて結果契約違反の原因を分離する。
		switch( scenario) {
			// 同じ対象identityを重複して返すworker結果を検証する。
			case 0:
				result.items[1].identity = result.items[0].identity ;
				break ;

			// 未選択対象へ取得済み結果を流用した場合を検証する。
			case 1:
				result.items[1].result = result.items[0].result ;
				break ;

			// 必要な項目結果が欠落している通知を検証する。
			case 2:
				result.items.pop_back() ;
				break ;

			// 処理中の項目を含む通知を、完了として表示しないことを検証する。
			case 3:
				result.items[0].result.state = OfficialPreparationItemState::IN_PROGRESS ;
				break ;

			// 承認した容量を超えた取得結果の拒否を検証する。
			case 4:
				result.items[0].result.byteCount = 101 ;
				break ;

			// 成功状態と失敗診断が混在する矛盾を検証する。
			case 5:
				result.items[0].result.error = -1 ;
				break ;

			// 失敗状態に診断値がない矛盾を検証する。
			case 6:
				result.items[0].result = {OfficialPreparationItemState::FAILURE, 0, 0} ;
				break ;

			// 承認拒否を伴う結果を、全成功として表示しないことを検証する。
			default:
				result.approvalError = OfficialPreparationError::INVALID_APPROVAL ;
				break ;
		}

		DRIVERCRATE_EXPECT( context, controller.completePreparation( result)) ;
		DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::FAILURE) ;
		DRIVERCRATE_EXPECT( context, controller.scanSessionId() == 0) ;
		DRIVERCRATE_EXPECT( context, controller.preparationPlan() == nullptr) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 取得失敗、取消し、承認拒否、制御系例外でも導入候補を保持する。
 *
 * @param[in,out] context 内部試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testPreparationTerminalFailures( TestContext &context)
{
	// 取得失敗をinstall失敗に誤変換せず、再scanが自動開始されないことを確認する。
	for( int scenario = 0; scenario < 5; ++scenario) {
		OperationController controller ;					// 今回の取得操作を管理するUI状態。
		const BeginResult	scan = controller.beginScan() ;	// 表示候補を保持する検索操作。
		DRIVERCRATE_EXPECT(
			context, controller.completeScan( scan.operationId, makeSuccessfulScan( 1, {L"one"}))) ;
		const OfficialPreparationPlan plan =
			// 有効な合成取得計画。
			makeControllerPreparationPlan() ;
		DRIVERCRATE_EXPECT( context, controller.setPreparationPlan( scan.operationId, plan)) ;
		OfficialPreparationApproval approval =
			// 部分選択。
			makeControllerPreparationApproval( plan) ;

		// 部分結果のscenarioでは二件目も選択して成功・失敗の混在を作る。
		if( scenario == 4) {
			approval.decisions[1].acquire = true ;	// 取得成功と失敗が混在する部分結果を作る。
		}

		DRIVERCRATE_EXPECT( context, controller.beginPreparation( approval).accepted) ;
		// 取得成功以外も既存scanを保持する、終端状態の検証用結果。
		OfficialPreparationOperationResult result = makeControllerPreparationResult( approval) ;
		// 各結果で保持されるscanと消費済み計画の違いを検証する。
		if( scenario < 2) {
			result.items[0].result = {scenario == 0 ? OfficialPreparationItemState::FAILURE
													: OfficialPreparationItemState::CANCELLED,
									  -1, 0} ;
		}
		// 部分結果のscenarioでは二件目だけを取得失敗にする。
		else if( scenario == 4) {
			result.items[1].result = {OfficialPreparationItemState::FAILURE, -1, 0} ;
		} else {
			result.items.clear() ;
			// 承認拒否のscenarioでは予算超過を注入して候補保持を確認する。
			if( scenario == 2) {
				result.approvalError = OfficialPreparationError::BUDGET_EXCEEDED ;
			} else {
				result.controlError = -1 ;
			}
		}

		DRIVERCRATE_EXPECT( context, controller.completePreparation( result)) ;
		DRIVERCRATE_EXPECT( context, controller.state() == ApplicationState::SCAN_READY) ;
		DRIVERCRATE_EXPECT( context, controller.scanSessionId() == 1) ;
		DRIVERCRATE_EXPECT( context, controller.preparationPlan() == nullptr) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 未解決条件と検索／導入による旧計画の失効を確認する。
 *
 * @param[in,out] context 内部試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testPreparationPlanInvalidation( TestContext &context)
{
	// 新検索とinstall開始を別controllerで検証し、planの再利用を許可しない。
	for( int scenario = 0; scenario < 2; ++scenario) {
		OperationController controller ;					// 今回の取得操作を管理するUI状態。
		const BeginResult	scan = controller.beginScan() ;	// 表示候補を保持する検索操作。
		DRIVERCRATE_EXPECT(
			context, controller.completeScan( scan.operationId, makeSuccessfulScan( 1, {L"one"}))) ;
		const OfficialPreparationPlan plan =
			// 有効な合成取得計画。
			makeControllerPreparationPlan() ;
		DRIVERCRATE_EXPECT( context, controller.setPreparationPlan( scan.operationId, plan)) ;
		OfficialPreparationApproval approval =
			// 部分選択。
			makeControllerPreparationApproval( plan) ;

		DRIVERCRATE_EXPECT( context, !controller.setPreparationPlan( scan.operationId, plan)) ;
		// 再scan開始により旧準備計画が失効する経路を選ぶ。
		if( scenario == 0) {
			DRIVERCRATE_EXPECT( context, controller.beginScan().accepted) ;
		} else {
			const std::array<std::wstring, 1> selection{L"one"} ;	// 元のinstall選択。
			DRIVERCRATE_EXPECT(
				context,
				controller.beginInstall( 1, selection, InstallConfirmation::CONFIRMED).accepted) ;
		}

		DRIVERCRATE_EXPECT( context, controller.preparationPlan() == nullptr) ;
		DRIVERCRATE_EXPECT( context, !controller.setPreparationPlan( scan.operationId, plan)) ;
	}

	OperationController unresolved ;					// 条件未確認の本番Intelと同じ承認拒否を確認する。
	const BeginResult	scan = unresolved.beginScan() ;	// 未解決計画を付随させる検索。
	DRIVERCRATE_EXPECT( context,
					   unresolved.completeScan( scan.operationId, makeSuccessfulScan( 1, {}))) ;
	OfficialPreparationPlan plan = makeControllerPreparationPlan() ;	// 未確定条件へ変更する計画。
	plan.targets[0].terms		 = OfficialPreparationTerms::UNRESOLVED ;
	DRIVERCRATE_EXPECT( context, unresolved.setPreparationPlan( scan.operationId, plan)) ;
	OfficialPreparationApproval approval =
		// 不正な取得選択。
		makeControllerPreparationApproval( plan) ;
	DRIVERCRATE_EXPECT( context, unresolved.beginPreparation( approval).error ==
									BeginError::INVALID_PREPARATION) ;
	DRIVERCRATE_EXPECT( context, unresolved.state() == ApplicationState::SCAN_READY) ;
}

/**
 * @brief 代表観測の古い結合・重複・初回導入への偽装を状態機械で拒否する。
 * @param[in,out] context Assertion集計先。
 */
void testObservationRegistration( TestContext &context)
{
	// 同じ正常結果を起点に、一つの拒否理由だけを各試行へ注入する。
	for( unsigned scenario = 0U; scenario < 6U; ++scenario) {
		OperationController controller ;									// 実Providerを持たない一回の状態機械。
		const auto			start = controller.beginScan() ;				// 生成済みoperationへの完了通知。
		auto  result		  = makeSuccessfulScan( 83U, {L"current"}) ;	// 名前と版を要求しない代表。
		auto &row			  = result.candidates.front() ;					// 追加時以外だけ借用する。
		row.current			  = true ;
		row.installable		  = false ;
		row.discoveryBasis	  = CandidateDiscoveryBasis::LOCAL_INVENTORY ;
		row.deviceObservation = DeviceObservation{} ;
		row.deviceObservation->scanSessionId  = 83U ;
		row.deviceObservation->deviceIdentity = row.deviceIdentity ;
		// 正常、stale、別device、非local、重複代表、初回偽装を分離する。
		switch( scenario) {
			// 未収集属性を持つ観測も正常表示対象とする。
			case 0U:
				break ;

			// 別検索の観測を新しい検索で受理しない。
			case 1U:
				row.deviceObservation->scanSessionId = 84U ;
				break ;

			// 別deviceの観測を流用しない。
			case 2U:
				row.deviceObservation->deviceIdentity = L"other-device" ;
				break ;

			// 公式Providerがlocal観測の正本にならない。
			case 3U:
				row.discoveryBasis = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
				break ;

			// 同じdeviceの代表行は候補IDが異なっても一つだけとする。
			case 4U:
				result.candidates.push_back( row) ;
				result.candidates.back().identity = L"second-current" ;
				break ;

			// 初回actionは旧flagを持つだけでは実行可能にしない。
			default:
				row.current = false ;
				row.deviceObservation.reset() ;
				row.action		= DriverAction::INITIAL_INSTALL ;
				row.installable = true ;
				break ;
		}

		DRIVERCRATE_EXPECT( context, start.accepted) ;
		DRIVERCRATE_EXPECT( context, controller.completeScan( start.operationId, result)) ;
		DRIVERCRATE_EXPECT( context,
						   controller.state() == (scenario == 0U ? ApplicationState::SCAN_READY
																 : ApplicationState::FAILURE)) ;
		const std::array<std::wstring, 1> selection{L"current"} ;	// 表示行への不正選択。
		DRIVERCRATE_EXPECT(
			context,
			!controller.beginInstall( 83U, selection, InstallConfirmation::CONFIRMED).accepted) ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/operation_controller_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOperationControllerTests( TestContext &context)
{
	testScanSuccess( context) ;
	testScanMeasurementLifetime( context) ;
	testStaleScanResultIsRejected( context) ;
	testScanCancellation( context) ;
	testInvalidScanIdentityIsRejected( context) ;
	testEmptyScanAndFailedScanAreDistinct( context) ;
	testInstallSelectionValidation( context) ;
	testInstallConfirmationIsRequired( context) ;
	testNonInstallableCandidateIsRejected( context) ;
	testDuplicateDeviceSelectionIsRejected( context) ;
	testInstallLifecycle( context) ;
	testInvalidInstallSuccessIsRejected( context) ;
	testRestorePointFailureLifecycle( context) ;
	testServerInstallLifecycle( context) ;
	testInstallProtectionModeMismatch( context) ;
	testInvalidInstallProtectionMode( context) ;
	testBusyAndStoppingRejection( context) ;
	testPreparationLifecycleAndInstallIndependence( context) ;
	testPreparationApprovalRejection( context) ;
	testPreparationStaleCompletion( context) ;
	testPreparationInvalidResults( context) ;
	testPreparationTerminalFailures( context) ;
	testPreparationPlanInvalidation( context) ;
	testObservationRegistration( context) ;
}

} // namespace drivercrate::test
