//------------------------------------------------------------------------------
/**
 * @file official_prepared_acquisition.h
 * @brief 承認済み配布物の再確認と共通取得。
 * @version 01.00.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  ASIX配布IDと算出許諾本文識別子を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  配布物の再確認付き取得を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note Worker内で保持情報を再確認してから共通取得層を呼び、導入許可を発行しません。
 */
//------------------------------------------------------------------------------

#pragma once
#include "core/official_preparation_operation.h"
#include "platform/official_acquisition.h"
#include "platform/official_release_metadata.h"
#include <functional>
#include <string>
#include <string_view>
namespace drivercrate {
class OfficialDownloadWorkspace ;
/**
 * @brief 固定sourceの再確認境界。UI指定URLを引数にせず、workerが起点を固定する。
 */
using PreparedReleaseRefresh = std::function<NativeError( OfficialReleaseRecord &, bool &)> ;
/**
 * @brief 共通取得層だけを差替える内部試験境界。UI／pluginから登録しない。
 */
using PreparedReleaseAcquire =
	std::function<NativeError( const OfficialAcquisitionRequest &, const PreparationCancellation &,
							  OfficialAcquisitionResult &)> ;

/**
 * @brief 配布系列ごとの公式identityが取得前の有限規則を満たすか検証する。
 * ASIXだけはfile名の代わりに公式pageの数値IDと固定URLを要求し、他系列のfile名必須条件を変更しない。
 * @param[in] release Workerが同一scanで保持する公式配布情報。 Workerが保持する公式配布情報。
 * @return ASIXは数値配布IDと固定URL、既知の他系列は空でないfile名を持つ場合true。 系列固有の配布identityが有限規則を満たす場合true。
 * @note ASIXだけにfile名なしを許可し、URLや表示名からIDを組み立てない。
 */
[[nodiscard]] bool validPreparedReleaseIdentity( const OfficialReleaseRecord &release) noexcept ;

/**
 * @brief 公開改訂番号がない許諾本文から表示用の算出識別子を作成する。
 * 公開改訂番号のない本文を正確なUTF-8 byte列で識別する。Hashだけで本文の完全一致確認を置き換えず、Vendor公表revisionとも区別する。
 * @param[in] eulaText 表示・同意に使用する正規化済みUTF-16全文。
 * @param[out] revision 成功時の種別prefix付き小文字SHA-256。失敗時は空。
 * @return 成功時は0、本文検証、UTF-8変換またはCNG失敗時はHRESULT bit pattern。 成功時は0、本文、変換、記憶域またはCNG失敗時はHRESULT bit
 *         pattern。
 * @note 本文をUTF-8へ一意変換して識別する。Vendor公表revisionとは表示上も区別する。
 */
[[nodiscard]] NativeError						makeComputedEulaRevision( std::wstring_view eulaText,
																		 std::wstring	  &revision) noexcept ;

/**
 * @brief 承認済みtaskと配布情報を照合・再確認し、成功時だけ取得境界を呼ぶ。
 * 公開metadata変更時は新URLへ追従しない。呼出し側は失効照合済みのclaimだけを渡す。
 * @param[in] task workerが一度だけclaimした承認済みtask。 一度だけclaimした承認済み対象。
 * @param[in] expected 同じ計画に固定した対象snapshot。UIから再構築しない。 計画に固定したworker側snapshot。
 * @param[in] retained 当該対象へ結合したworker所有の公式配布情報。 その対象へ結合した公式配布情報。
 * @param[in] refresh 固定公式起点の再確認。取得根拠の確認は呼出し側が担当する。 同じ公式起点から再確認するcallback。
 * @param[in] acquire 共通取得層を呼ぶ同期callback。合成test以外で迂回実装しない。 共通取得境界または内部testのfake。
 * @param[in] cancellation 取消し照会。空は外部信号なし。 空または取得取消し照会。
 * @param[out] acquisition 取得を開始した場合のworker内結果。UIへ渡さない。 取得処理のworker専用結果。
 * @return UIへ返せる取得状態。監査合格・導入可能を意味しない。 再確認と取得の終端状態。
 * @note 呼出し側がplan／sessionの失効と一度限りのclaimを保証する。
 */
[[nodiscard]] OfficialPreparationTransferResult revalidateAndAcquireRelease(
	const OfficialPreparationTask &task, const OfficialPreparationTarget &expected,
	const OfficialReleaseRecord &retained, const PreparedReleaseRefresh &refresh,
	const PreparedReleaseAcquire &acquire, const PreparationCancellation &cancellation,
	OfficialAcquisitionResult &acquisition) ;
/**
 * @brief 再確認付き取得を既存の公式取得sessionへ接続する。
 * 実取得は既存共通層に委ね、UI進捗は外側executorで対象確定件数として通知する。
 * @param[in] task 一度だけclaimしたtask。 Claim済み対象。
 * @param[in] expected 計画に固定した対象。 固定計画の対象snapshot。
 * @param[in] retained workerに保持した配布情報。 workerが保持する公式配布情報。
 * @param[in] refresh 固定公式起点からの再確認callback。 公式根拠を確認する再取得callback。
 * @param[in,out] session 初期化済みの公式取得ledger。 初期化済み取得ledger。
 * @param[in,out] workspace 初期化済みの保護保存領域。成功fileを所有し続ける。
 * @param[in,out] transport 公式source sessionを保持する共通取得transport。 共通公式source transport。
 * @param[in,out] costReader Windowsの課金状態照会境界。 課金状態の照会境界。
 * @param[in] cancellation 取得途中にも使用する取消し照会。 協調取消し照会。
 * @param[out] acquisition 次の内容監査に用いるworker専用取得結果。 内容監査へ渡すworker専用結果。
 * @return 元の取得／再確認エラーを保持する終端状態。 既存の公式取得と再確認に基づく終端状態。
 * @note UI threadで呼ばず、workspaceと公式根拠を監査が終わるまで保持する。
 */
[[nodiscard]] OfficialPreparationTransferResult acquirePreparedRelease(
	const OfficialPreparationTask &task, const OfficialPreparationTarget &expected,
	const OfficialReleaseRecord &retained, const PreparedReleaseRefresh &refresh,
	OfficialAcquisitionSession &session, OfficialDownloadWorkspace &workspace,
	IOfficialAcquisitionTransport &transport, IOfficialNetworkCostReader &costReader,
	const PreparationCancellation &cancellation, OfficialAcquisitionResult &acquisition) ;
} // namespace drivercrate
