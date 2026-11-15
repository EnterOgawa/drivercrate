//------------------------------------------------------------------------------
/**
 * @file local_scan_diagnostics.h
 * @brief 通常scanの非機密summaryだけを匿名診断へ投影します
 * @version 01.02.05
 * @date 2026/11/03
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/03  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/08  匿名導入診断と保存状態・元数値の有限確認を追加
 * Ver.01.02.00 Shunji Ogawa  2026/11/08  準備不成立後の元表示保持と段階別匿名診断を追加
 * Ver.01.02.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.02.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.02.03 Shunji Ogawa  2026/11/12  取得APIと復元最終判定の匿名診断を補完
 * Ver.01.02.04 Shunji Ogawa  2026/11/12  外側tupleの取得予約と開始拒否の原理由を接続
 * Ver.01.02.05 Shunji Ogawa  2026/11/12  導入前保護失敗に結合した一回の明示復元なし続行を接続
 * </pre>
 * @note 元DTOや候補の文字列をserializeせず、表示条件も変更しません
 * @see docs/adr/0427-local-anonymous-scan-diagnostics.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/local_diagnostic_log.h"
#include "core/update_types.h"
#include <cstdint>
#include <span>

namespace drivercrate {
/** @brief 復元なし続行の本人判断/受理と実行を分ける固定段階です */
enum class RestoreContinuationStage {
	/// 元保護失敗/保持証明を満たして提示しました
	OFFERED,
	/// 既定/中止/close/dialog失敗で続行しません
	DECLINED,
	/// 本人が今回の復元なし続行を選びました
	SELECTED,
	/// Controllerが新operationへ一回判断を受理しました
	CONTROLLER_ACCEPTED,
	/// Controller又はqueueが今回の続行を拒否しました
	CONTROLLER_REJECTED,
	/// Workerが実OS/原所有/元preflightを再検証しました
	WORKER_ACCEPTED,
	/// Workerの再照合で拒否しました
	WORKER_REJECTED,
	/// 当該client明示modeでProviderを実行しました。成功とは別です
	EXECUTED,
} ;
//------------------------------------------------------------------------------
/**
 * @brief 元保護失敗と本人判断/今回の続行段階を匿名記録します
 * @param[in] operation 今回の操作です。提示時は元失敗操作です
 * @param[in] stage 実制御点だけの固定段階です
 * @param[in] failedOperation 元の失敗操作です
 * @param[in] failureError 元保護errorです。未照合は0です
 * @param[in] selectedCount 完全選択の件数です
 * @param[in] rejectionError 今回の拒否原errorです。未拒否/未記録は0です
 * @param[in,out] sink 内部試験の匿名保存先です。nullはprocess loggerです
 * @note 文字列/復元point番号を受けず、保存失敗は実行や判断を変更しません
 */
//------------------------------------------------------------------------------
void recordRestoreContinuationDiagnostics( OperationId operation, RestoreContinuationStage stage,
										  OperationId failedOperation, NativeError failureError,
										  std::size_t		  selectedCount,
										  NativeError		  rejectionError = 0U,
										  LocalDiagnosticLog *sink			 = nullptr) noexcept ;

struct WorkerEvent ;
struct BeginResult ;
//------------------------------------------------------------------------------
/**
 * @brief 受理済み終端eventのenum/数値だけを記録します
 * @param[in] event 同operationへ受理された元event。文字列は参照しません
 * @param[in] applicationState 元状態機械の固定区分
 * @param[in] measurementAccepted Controllerのsnapshot受理事実
 * @param[in,out] sink 内部試験だけの保存先。nullptrは製品process logger
 */
//------------------------------------------------------------------------------
void recordScanDiagnostics( const WorkerEvent &event, std::int32_t applicationState,
						   bool measurementAccepted, LocalDiagnosticLog *sink = nullptr) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief Install要求または受理開始の固定件数を記録します
 * @param[in] operation 元操作連番。要求は現scan、受理開始は新installです
 * @param[in] candidates 元所有候補。文字列はserializeしません
 * @param[in] indexes 実行要求に使う元indexです
 * @param[in] accepted controllerが開始を受理した事実です
 * @param[in,out] sink 内部試験だけの保存先。nullptrはprocess logger
 */
//------------------------------------------------------------------------------
void recordInstallSelectionDiagnostics( OperationId						operation,
									   std::span<const UpdateCandidate> candidates,
									   std::span<const std::size_t> indexes, bool accepted,
									   LocalDiagnosticLog *sink = nullptr) noexcept ;
struct OfficialPreparationApproval ;
struct OfficialPreparationOperationResult ;
struct IndexPreparationSummary ;
/** @brief 原codeの無いUI拒否も区別する閉じた導入継続理由です */
enum class PreparationContinuationReason {
	/// 全件照合を通過し、通常の導入入口へ進みます
	READY,
	/// 元意図と解決結果の件数が一致しません
	COUNT_MISMATCH,
	/// 元選択に検査後の一意な候補がありません
	NOT_READY,
	/// 元選択に複数の検証済み候補があります
	AMBIGUOUS,
	/// 新たに旧版切替と判明しました
	DOWNGRADE,
	/// 元表示候補がありません
	SOURCE_MISSING,
	/// 解決結果が元選択と一致しません
	ORIGINAL_MISMATCH,
	/// 解決した候補が表示集合にありません
	CANDIDATE_MISSING,
	/// 解決候補が実行可能な候補ではありません
	CANDIDATE_NOT_INSTALLABLE,
	/// 解決候補が別deviceへ結合しています
	DEVICE_MISMATCH,
	/// 同deviceに複数の解決候補があります
	DUPLICATE_DEVICE,
	/// 表示行と元選択を安全に結合できません
	SELECTION_REJECTED,
	/// 同操作の索引内容summaryを受理できません
	INDEX_SUMMARY_REJECTED,
	/// 元操作またはscan文脈が一致しません
	CONTEXT_REJECTED,
	/// 利用者が準備を取り消しました
	CANCELLED,
} ;
/** @brief 選択target内での数値診断段階です */
enum class PreparationDiagnosticStage {
	/// 元取得結果です
	TRANSFER,
	/// 全体内容検査です
	CONTENT,
	/// 最初の内容拒否です
	CONTENT_REJECTION,
	/// 全体適用性検査です
	APPLICABILITY,
	/// 最初の組合せ拒否です
	PAIR_REJECTION,
	/// 検証済み候補の発行結果です
	PUBLICATION,
	/// 元索引byteの内容結果です
	INDEX_CONTENT,
	/// 最初の索引INF拒否です
	INDEX_INF_REJECTION,
	/// 索引の元取得結果です
	INDEX_ACQUISITION,
	/// 索引補助HTTPの実観測値です
	INDEX_HTTP,
	/// 全計画と投影省略の件数です
	SUMMARY,
} ;
//------------------------------------------------------------------------------
/**
 * @brief 準備開始/受理終端の件数と元codeだけを記録します
 * @param[in] approval 元承認。identity等は出力しません
 * @param[in] result nullptrは開始、非nullは受理された終端です
 * @param[in] applicationState 元controller区分です
 * @param[in,out] sink 内部試験の保存先
 */
//------------------------------------------------------------------------------
void recordPreparationDiagnostics( const OfficialPreparationApproval		   &approval,
								  const OfficialPreparationOperationResult *result,
								  std::int32_t								applicationState,
								  LocalDiagnosticLog *sink = nullptr) noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief 受理済み選択targetと解決意図を各先頭16件まで原数値へ投影します
 * @param[in] approval 元計画と選択です。本文を出力しません
 * @param[in] result controllerが受理した同操作終端です
 * @param[in] verifiedIndex 元操作と全件照合済みのsummaryだけです。不成立はnullptr
 * @param[in,out] sink 内部試験の保存先です
 */
//------------------------------------------------------------------------------
void recordPreparationResultDiagnostics( const OfficialPreparationApproval		 &approval,
										const OfficialPreparationOperationResult &result,
										const IndexPreparationSummary			 *verifiedIndex,
										LocalDiagnosticLog *sink = nullptr) noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief 元codeを創作せずUI継続の固定理由と件数だけを記録します
 * @param[in] operation 元準備操作です
 * @param[in] reason 固定の継続区分です
 * @param[in] intentCount 元選択数です
 * @param[in] readyCount 元READY数です。取得成功数ではありません
 * @param[in,out] sink 内部試験の保存先です
 */
//------------------------------------------------------------------------------
void recordPreparationContinuationDiagnostics( OperationId					operation,
											  PreparationContinuationReason reason,
											  std::size_t intentCount, std::size_t readyCount,
											  LocalDiagnosticLog *sink = nullptr) noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief 元個別/role/保護/事後観測を匿名数値へ投影します
 * @param[in] event controllerが受理した同operationの終端です
 * @param[in] scanSession 元の失効前scan。表示照合だけに使います
 * @param[in] candidates 失効flag変更前の元候補です。生文字列は記録しません
 * @param[in] applicationState 元controller区分です
 * @param[in,out] sink 内部試験の保存先
 */
//------------------------------------------------------------------------------
void recordInstallDiagnostics( const WorkerEvent &event, ScanSessionId scanSession,
							  std::span<const UpdateCandidate> candidates,
							  std::int32_t					   applicationState,
							  LocalDiagnosticLog			  *sink = nullptr) noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief 表示直前の実resourceと元errorを同operationへ匿名記録します
 * @param[in] operation 受理した元Install操作です
 * @param[in] resourceId 実本文に使用した固定resource IDです
 * @param[in] error 同本文で表示する元errorです。一般結果だけは0です
 * @param[in] succeeded Controllerの実最終成功値です
 * @param[in,out] sink 内部fixtureだけの既匿名sinkです
 * @note 保存失敗をUI/導入結果へ返しません
 */
//------------------------------------------------------------------------------
void recordInstallFeedbackDiagnostics( OperationId operation, std::uint32_t resourceId,
									  NativeError error, bool succeeded,
									  LocalDiagnosticLog *sink = nullptr) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief workerへ送らなかった取得承認の元理由と予算を匿名記録します
 * @param[in] operation 現scanの操作連番です。拒否した取得の新操作IDではありません
 * @param[in] approval 当該未承認snapshotです。文字列をserializeしません
 * @param[in] begin 同じcontroller呼出しのfreshな拒否結果です
 * @param[in,out] sink 内部fixtureだけの保存先です。nullptrは既process sinkです
 * @note accepted結果は記録しません。保存不能は操作へ伝播しません
 */
//------------------------------------------------------------------------------
void recordPreparationBeginRejectedDiagnostics( OperationId						  operation,
											   const OfficialPreparationApproval &approval,
											   const BeginResult				 &begin,
											   LocalDiagnosticLog *sink = nullptr) noexcept ;

}
