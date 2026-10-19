//------------------------------------------------------------------------------
/**
 * @file update_provider.h
 * @brief Driver update provider契約定義。
 * @version 01.01.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  取得後候補発行と失効契約を明確化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の表示境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  EULA本文とpayload URLの境界を明確化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得計画とworker実行を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  件数付き進捗通知追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Install後session契約明確化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Provider選択付きscan追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索専用の型と拒否境界を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  通常scanの協調取消し境界を追加。
 * Ver.01.01.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note Driver updateの検索、download、およびinstallを抽象化します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_preparation_operation.h"
#include "core/update_types.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {

/** @brief Metadata専用検索のworker内予算と協調停止context。 */
class MetadataSearchExecutionContext ;

//------------------------------------------------------------------------------
// Provider型定義。
//------------------------------------------------------------------------------

/**
 * @brief 長時間処理の段階、実処理件数、および全体完了率を通知する関数。
 */
using ProviderProgressCallback = std::function<void( const ProviderProgress &)> ;
/**
 * @brief 同一通常scanのみが参照する非blockingな協調取消し照会。
 */
using ProviderScanCancellation = std::function<bool()> ;

/**
 * @brief driver update の検索、download、install を提供する同期 interface である。
 *
 * @note 実装は専用 worker thread から直列に呼び出される。UI thread から直接呼び出さない。
 */
class IUpdateProvider {
public:
	/**
     * @brief 実装固有の scan session と resource を解放する。
     */
	virtual ~IUpdateProvider() = default ;

	/**
	 * @brief Payload非取得の専用検索。未対応は通常scanへfallbackせず拒否する。
	 * @param[in] scanSessionId Worker発行の専用session。
	 * @param[in] request 明示選択と今回限りの通信許可。
	 * @param[in,out] execution 同期呼出し中だけ借用する予算・取消しcontext。
	 * @param[in] progressCallback 確定した進捗の通知先。
	 * @return 表示専用結果。既定実装はE_NOTIMPLを返し副作用を起こさない。
	 */
	[[nodiscard]] virtual ScanResult scanMetadataOnly(
		ScanSessionId scanSessionId, const MetadataSearchRequest &request,
		MetadataSearchExecutionContext &execution,
		const ProviderProgressCallback &progressCallback) ;

	/**
	 * @brief 同じscanで保持した配布情報から取得計画を生成する。
	 * Scanだけに対応する既存Providerへ新しい取得を暗黙追加しない。
	 * @param[in] scanSessionId 有効な検索session。 計画を要求する検索session。
	 * @param[in] planId workerが割り当てた0ではない新計画ID。 workerが発行した新計画ID。
	 * @return Payload URLを含まない計画。EULA内の公開URLはplain textとして保持できる。対象なし／未対応の場合はnullopt。 未対応を示すnullopt。
	 */
	[[nodiscard]] virtual std::optional<OfficialPreparationPlan> preparationPlan(
		ScanSessionId scanSessionId, std::uint64_t planId) ;

	/**
	 * @brief 承認済みtaskを検査用に取得する。既定実装は拒否する。
	 * 取得・監査・導入の成功を返さず、networkも実行しない。
	 * @param[in] task workerが一度だけclaimした照合token。 承認された取得token。未対応のため使用しない。
	 * @param[in] cancellation 転送中に照会する協調取消し信号。 未対応のため呼ばない取消し照会。
	 * @return 検査用取得の結果。監査合格／導入成功ではない。 E_NOTIMPLを伴うRejected。
	 * @note 同期呼出し中だけtaskとcallbackを参照し、別threadや後続操作へ保持しない。
	 */
	[[nodiscard]] virtual OfficialPreparationTransferResult acquireForInspection(
		const OfficialPreparationTask &task, const PreparationCancellation &cancellation) ;

	/**
	 * @brief 取得結果と同じscanの非機密監査reportを返す。既定実装は空。
	 * 未実施の監査結果を推測せず、既存Providerの動作を変更しない。
	 * @param[in] result Workerが確定した取得対象別結果。 既定実装では参照しない取得結果。
	 * @return 取得成功対象に対応する監査report。全監査合格時は未選択候補を含められる。 未接続を表す空report集合。
	 * @note 候補を含めるProviderは、同じscanのinstall routingも原子的に保持する。
	 */
	[[nodiscard]] virtual std::vector<OfficialPreparationAuditReport> preparationAuditReports(
		const OfficialPreparationOperationResult &result) ;

	/**
	 * @brief 次scan開始またはinstall終端時に、取得準備の保持物と発行候補のroutingを解放する。
	 * @note 既定実装は取得計画用の情報を持たず、既存scan／install状態へ触れない。
	 */
	virtual void					 invalidatePreparation() noexcept ;

	/**
     * @brief 現在の端末、構成済み更新元、local 履歴から driver 候補を検索する。
     * @param[in] scanSessionId 呼出し側が割り当てた 0 ではない session ID。
     * @param[in] options 今回有効にする組み込みProvider設定。
     * @param[in] progressCallback 段階、処理件数、および全体完了率の通知先。
     * @return 候補または失敗情報を含む scan 結果。
     * @note 成功時、Provider は同じ session ID を後続の `install` で検証できる状態を保持する。
     */
	[[nodiscard]] virtual ScanResult scan( ScanSessionId scanSessionId, const ScanOptions &options,
										  const ProviderProgressCallback &progressCallback) = 0 ;

	/**
	 * @brief 通常scanに同一operation限定の協調取消し照会を渡す。
	 * @param[in] scanSessionId 呼出し側が割り当てた0ではないsession ID。
	 * @param[in] options 今回有効にする組み込みProvider設定と一scan承認。
	 * @param[in] cancellation 同期呼出し中だけ借用する非blocking取消し照会。
	 * @param[in] progressCallback 段階、処理件数、および全体完了率の通知先。
	 * @return 候補または取消しを含む失敗情報を持つscan結果。
	 * @note 既实装Provider用の既定実装は権限を補完せず`scan`へ委譲します。
	 */
	[[nodiscard]] virtual ScanResult scanWithCancellation(
		ScanSessionId scanSessionId, const ScanOptions &options,
		const ProviderScanCancellation &cancellation,
		const ProviderProgressCallback &progressCallback) ;

	/**
     * @brief 現在の scan session から明示選択された driver を必要に応じて download/install する。
     * @param[in] scanSessionId 選択元の scan session ID。
     * @param[in] identities UI に提示済みの opaque update identity 群。
     * @param[in] parentWindowNative Windows dialog の親 HWND を整数表現で渡す値。
     * @param[in] progressCallback 段階、処理件数、および全体完了率の通知先。
     * @return update ごとの download/install 結果。
     * @note 失敗または部分成功を含め、呼出し後は同じ session を再利用できない。次の install
     * を行う場合は、利用者が明示的に新しい scan を開始する必要がある。
     */
	[[nodiscard]] virtual InstallResult install(
		ScanSessionId scanSessionId, std::span<const std::wstring> identities,
		std::uintptr_t parentWindowNative, const ProviderProgressCallback &progressCallback) = 0 ;
} ;

} // namespace drivercrate
