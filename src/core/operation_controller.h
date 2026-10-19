//------------------------------------------------------------------------------
/**
 * @file operation_controller.h
 * @brief 操作状態管理定義。
 * @version 01.01.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Install最終確認の明示契約を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の表示境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得確認と独立した操作状態を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  復元ポイント状態追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  反復進捗通知受理追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Server用install保護mode追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Scan計測snapshotの照合と寿命管理を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  通常scanの協調取消し待ち状態を追加。
 * </pre>
 *
 * @note UI操作とProvider resultの順序を検証する状態機械を定義します。本classはUI thread専用であり、内部lockingを行いません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_preparation_operation.h"
#include "core/update_types.h"

#include <optional>

#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace drivercrate {

//------------------------------------------------------------------------------
// 操作状態型定義。
//------------------------------------------------------------------------------

/**
 * @brief DriverCrate の利用者向け operation state を表す。
 */
enum class ApplicationState {
	/// Operation未開始または次のscanを開始できる状態。
	IDLE,
	/// Providerがdriver候補を検索中の状態。
	SCANNING,
	/// 通常scanの協調取消しを要求し、確定結果を待つ状態。
	CANCELLING_SCAN,
	/// Scan候補を表示しselectionを受理できる状態。
	SCAN_READY,
	/// 選択した公式配布物を検査用に取得中の状態。
	PREPARING,
	/// 協調取消しを要求し、取得の確定結果を待つ状態。
	CANCELLING_PREPARATION,
	/// 情報検索の協調取消しを要求し、表示専用の確定結果を待つ状態。
	CANCELLING_METADATA_SEARCH,
	/// Driver変更前のWindows復元ポイント作成中の状態。
	CREATING_RESTORE_POINT,
	/// 選択候補のpayload取得またはcache検証中の状態。
	DOWNLOADING,
	/// 選択候補をsystemへ適用中の状態。
	INSTALLING,
	/// 導入成功または情報検索の表示専用終端。Purposeと終了理由を併せて判定する。
	COMPLETED,
	/// Scan、復元ポイント、installのいずれかが失敗した状態。
	FAILURE,
	/// 新規operationを拒否してworker停止を待つ状態。
	STOPPING,
} ;

/**
 * @brief Install対象と注意事項に対する今回限りの利用者確認状態を表す。
 */
enum class InstallConfirmation {
	/// 利用者が承認していない、または確認dialogを取り消した。
	NOT_CONFIRMED,
	/// 表示中の選択集合と注意事項を利用者が明示承認した。
	CONFIRMED,
} ;

/**
 * @brief operation 開始を拒否した理由を表す。
 */
enum class BeginError {
	/// Operation開始を受理した。
	NONE,
	/// 別operationを実行中である。
	BUSY,
	/// 有効なscan候補が存在しない。
	NO_SCAN_RESULT,
	/// UIが古いscan sessionを指定した。
	STALE_SCAN_SESSION,
	/// Install対象が一件も選択されていない。
	EMPTY_SELECTION,
	/// 同一candidate identityが複数指定された。
	DUPLICATE_IDENTITY,
	/// 同じdeviceから複数候補が指定された。
	DUPLICATE_DEVICE_SELECTION,
	/// 現在表示していないidentityが指定された。
	UNKNOWN_IDENTITY,
	/// Install最終確認が明示承認されていない。
	CONFIRMATION_REQUIRED,
	/// 定義外のinstall保護方針が指定された。
	INVALID_PROTECTION_MODE,
	/// 取得計画または対象別承認の照合に失敗した。
	INVALID_PREPARATION,
	/// 情報検索の明示集合または固定policyが不正である。
	INVALID_METADATA_SEARCH,
	/// 単調増加operation IDを安全に割り当てられない。
	ID_EXHAUSTED,
	/// Application停止開始後にoperationが要求された。
	STOPPING,
} ;

/**
 * @brief operation 開始の受付結果を表す。
 */
struct BeginResult {
	/// trueの場合はoperationを開始済みである。
	bool		accepted{} ;
	/// 受理したoperationのID。拒否時は0。
	OperationId operationId{} ;
	/// 拒否理由。受理時はNone。
	BeginError	error{BeginError::NONE} ;
} ;

/**
 * @brief 検索・検査用取得・導入の排他状態と、各操作identityの有効範囲を検証する。
 */
class OperationController final {
public:
	/**
	 * @brief 新しい scan operation を開始する。
	 * @return 受付時は新しい operation ID、拒否時は理由を含む結果。
	 */
	[[nodiscard]] BeginResult beginScan() ;

	/**
	 * @brief 同じ通常scanだけを協調取消し結果待ちへ移す。
	 * @param[in] operationId Workerへ取消しを要求した操作ID。
	 * @return 現在の通常scanへ適用した場合true。
	 */
	[[nodiscard]] bool		  markScanCancelling( OperationId operationId) noexcept ;

	/**
	 * @brief 新しい表示専用検索を受理し、旧候補・取得計画・同意を失効する。
	 * @param[in] request 今回だけの明示集合と通信判断。
	 * @return 開始した操作IDまたは拒否理由。拒否時は旧状態を変更しない。
	 */
	[[nodiscard]] BeginResult beginMetadataSearch( const MetadataSearchRequest &request) ;

	/**
	 * @brief 同じ情報検索だけを取消し結果待ちへ移す。
	 * @param[in] operationId Workerへ取消しを要求した操作ID。
	 * @return 現在の情報検索へ適用した場合true。
	 */
	[[nodiscard]] bool		  markMetadataSearchCancelling( OperationId operationId) noexcept ;

	/**
	 * @brief 情報検索の全snapshotを検証し、導入権限なしの終端へ移す。
	 * @param[in] operationId 完了対象の操作ID。
	 * @param[in] result Workerから受け取った情報検索結果。
	 * @return 現在操作を処理した場合true。不正結果はFAILUREとしsummaryを保持しない。
	 */
	[[nodiscard]] bool completeMetadataSearch( OperationId operationId, const ScanResult &result) ;

	/**
	 * @brief Provider から返された scan 完了を現在の operation へ反映する。
	 * Provider から返された scan 完了を現在の operationへ反映する。 注記: 遅延した古い resultは状態を変更せず拒否する。現在 operation の不正な成功
	 * 結果は`FAILURE` として適用する。
	 * @param[in] operationId 完了対象の operation ID。
	 * @param[in] result Provider が返した scan 結果。
	 * @return 現在の operation に適用した場合は `true`。
	 * @note 遅延した古い result は状態を変更せず拒否する。現在 operation の不正な成功結果は`FAILURE` として適用する。
	 */
	[[nodiscard]] bool completeScan( OperationId operationId, const ScanResult &result) ;

	/**
	 * @brief 現在の scan 候補から install operation を開始する。
	 * @param[in] scanSessionId 選択元として UI が保持する scan session ID。
	 * @param[in] identities 利用者が選択した opaque update identity 群。 利用者が選択した opaque update identity群。
	 * @param[in] confirmation 表示中の選択集合に対する今回限りの最終確認状態。 選択集合への今回限りの最終確認状態。
	 * @param[in] protectionMode OSと利用者確認に対応するinstall保護方針。 OS別のinstall保護方針。
	 * @return 受付時は新しい operation ID、拒否時は理由を含む結果。
	 */
	[[nodiscard]] BeginResult beginInstall(
		ScanSessionId scanSessionId, std::span<const std::wstring> identities,
		InstallConfirmation	  confirmation,
		InstallProtectionMode protectionMode = InstallProtectionMode::WINDOWS_RESTORE_POINT) ;

	/**
	 * @brief 復元ポイント開始後に現在のoperationをdownload段階へ進める。
	 * @param[in] operationId 対象operation ID。
	 * @return 現在の復元ポイント作成operationに適用した場合は`true`。
	 */
	[[nodiscard]] bool markDownloading( OperationId operationId) ;

	/**
	 * @brief 復元ポイント開始またはdownload完了後にinstall段階へ進める。
	 * @param[in] operationId 対象 operation ID。
	 * @return 現在の保護付きoperationに適用した場合は`true`。
	 */
	[[nodiscard]] bool markInstalling( OperationId operationId) ;

	/**
	 * @brief install operation の最終結果を状態へ反映する。
	 * install operation の最終結果を状態へ反映する。 注記:成功結果は開始時 selection と identityが完全一致する場合だけ受理する。
	 * @param[in] operationId 対象 operation ID。
	 * @param[in] result workerが返した復元ポイントとupdateごとの最終結果。
	 * @return 現在の operation に適用した場合は `true`。
	 * @note 成功結果は開始時 selection と identity が完全一致する場合だけ受理する。
	 */
	[[nodiscard]] bool completeInstall( OperationId operationId, const InstallResult &result) ;

	/**
	 * @brief 成功した検索に付随する取得計画を固定する。
	 * 同じ検索への計画差替えを許可せず、既存承認coreで形式と予算を検証する。
	 * @param[in] operationId 計画を受け取ったscan操作ID。 計画を受領した検索操作ID。
	 * @param[in] plan workerが検証した有限計画。 workerが発行した計画。
	 * @return 現在のscanへ初めて有効計画を保持した場合true。 有効計画を現在の検索へ固定した場合true。
	 */
	[[nodiscard]] bool setPreparationPlan( OperationId					 operationId,
										  const OfficialPreparationPlan &plan) ;

	/**
	 * @brief 未使用の取得計画をUI確認用に参照する。
	 * 状態変更をまたいで返却pointerを保存しない。
	 * @return 計画なしはnullptr。次の状態変更まで有効な非所有pointer。 未使用計画、またはnullptr。所有権はcontrollerが保持する。
	 */
	[[nodiscard]] const OfficialPreparationPlan *preparationPlan() const noexcept ;

	/**
	 * @brief 全対象の判断を照合して取得操作を開始する。
	 * 取得選択はinstall選択から独立させ、workerとは別にsnapshotを照合する。
	 * @param[in,out] approval 操作IDが0の承認。受理時だけ新操作IDを反映する。 全対象判断。操作IDは0を要求し、受理時に採番する。
	 * @return 開始結果。不正承認ではworkerへ送信しない。 受理した操作ID、または拒否理由。
	 */
	[[nodiscard]] BeginResult beginPreparation( OfficialPreparationApproval &approval) ;

	/**
	 * @brief 取得取消し要求後の待機状態へ移行する。
	 * workerの確定結果まで排他を維持する。
	 * @param[in] operationId 取消し対象の取得操作ID。 取消し要求を送信した取得操作ID。
	 * @return 現在の取得操作を取消し待ちへ変更した場合true。 現在の取得を取消し待ちへ変更した場合true。
	 */
	[[nodiscard]] bool		  markPreparationCancelling( OperationId operationId) noexcept ;

	/**
	 * @brief 取得完了を検証し、導入状態を変更せず元の一覧へ戻す。
	 * 監査reportを全件照合し、全監査合格として発行された候補だけを現在scanの導入許可集合へ追加する。
	 * @param[in] result operation／scan／planと対象別の確定結果。 同じoperation／scan／planの取得完了と監査report。
	 * @param[in] candidates 表示済み候補。監査reportがある場合は必須。変更しない。 同じscanの表示候補。監査reportがある場合は必須。
	 * @return 現在操作の結果を処理した場合true。不正内容はFailedとして適用する。 現在操作ならtrue。不正内容はFailedへ遷移し、旧操作はfalse。
	 */
	[[nodiscard]] bool		  completePreparation( const OfficialPreparationOperationResult &result,
												  std::span<const UpdateCandidate> candidates = {}) ;

	/**
	 * @brief 新しい operation を拒否する停止状態へ移行する。
	 */
	void					  stop() noexcept ;

	/**
	 * @brief 現在の application state を返す。
	 * @return 現在 state。
	 */
	[[nodiscard]] ApplicationState			   state() const noexcept ;

	/**
	 * @brief 現在有効な scan session ID を返す。
	 * @return scan result がない場合は 0。
	 */
	[[nodiscard]] ScanSessionId				   scanSessionId() const noexcept ;

	/**
	 * @brief 最後に受理したscan完了時点の段階別計測を参照する。
	 * @return 有効な公開計測への非所有pointer。未接続・不正・新scan中はnullptr。
	 * @note 準備操作で再計数せず、install後は失効済みscanの履歴として保持する。
	 */
	[[nodiscard]] const ScanMeasurement		  *scanMeasurement() const noexcept ;

	/** @brief 現在または最後の検索の権限種別を返す。@return 結果行のフラグと独立した用途。 */
	[[nodiscard]] ScanPurpose				   scanPurpose() const noexcept ;

	/** @brief 検証済みの情報検索終端を参照する。@return 次の状態変更まで借用できる値。未保持はnullptr。 */
	[[nodiscard]] const MetadataSearchSummary *metadataSearchSummary() const noexcept ;

	/**
	 * @brief 現在実行中または最後に完了した operation ID を返す。
	 * @return operation 未開始の場合は 0。
	 */
	[[nodiscard]] OperationId				   activeOperationId() const noexcept ;

private:
	/**
	 * @brief 0 と重複しない次の operation ID を割り当てる。
	 * @param[out] operationId 割り当てた ID。
	 * @return ID を割り当てられた場合は `true`。
	 */
	[[nodiscard]] bool					   allocateOperationId( OperationId &operationId) noexcept ;

	/// UI threadでのみ使用する承認検証。worker側でも独立して再照合する。
	OfficialPreparationSession			   preparationSession_ ;
	/// 未使用計画の表示snapshot。
	std::optional<OfficialPreparationPlan> preparationPlan_ ;
	/// 取得完了を検証する開始時の全対象判断。
	OfficialPreparationApproval			   activePreparation_ ;
	/// 現在の利用者向けoperation state。
	ApplicationState					   state_{ApplicationState::IDLE} ;
	/// 実行中または最後に完了したoperation ID。
	OperationId							   activeOperationId_{} ;
	/// 次回割り当てる0以外のoperation ID。
	OperationId							   nextOperationId_{1} ;
	/// 現在有効なscan session ID。未scan時は0。
	ScanSessionId						   scanSessionId_{} ;
	/// 最後に受理したscan完了時点の計測。
	std::optional<ScanMeasurement>		   scanMeasurement_ ;
	/// 候補フラグや成功値から推測しない、現在検索の権限。
	ScanPurpose							   scanPurpose_{ScanPurpose::STANDARD} ;
	/// 開始時の要求copy。完了packetの自己申告とは独立。
	std::optional<MetadataSearchRequest>   metadataSearchRequest_ ;
	/// 公開境界で検証済みの表示専用終端。次検索で消去する。
	std::optional<MetadataSearchSummary>   metadataSearchSummary_ ;
	/// 表示を許可した候補identity集合。
	std::unordered_set<std::wstring>	   candidateIdentities_ ;
	/// 候補からdeviceへの対応。
	std::unordered_map<std::wstring, std::wstring> candidateDevices_ ;
	/// Install対象identity集合。
	std::unordered_set<std::wstring>			   activeInstallIdentities_ ;
	/// 現在のinstall開始時に固定し、worker結果との一致を検証する回復保護方針。
	InstallProtectionMode						   activeInstallProtectionMode_{
		 InstallProtectionMode::WINDOWS_RESTORE_POINT} ;
} ;

} // namespace drivercrate
