//------------------------------------------------------------------------------
/**
 * @file official_preparation_audit.h
 * @brief 取得後監査の非機密表示契約。
 * @version 01.01.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  候補発行結果の非機密状態と件数を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  監査合格候補の検証境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の表示境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.01.01 Shunji Ogawa  2026/10/15  全体内容INF数とWindows照合予算を分離。
 * </pre>
 *
 * @note 取得成功と独立した監査結果を扱い、全監査合格時だけ新規候補を検証します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {
// Payload全体の内容件数上限。Device別の必要INF導入計画数ではありません。
inline constexpr std::uint32_t OFFICIAL_PREPARATION_MAXIMUM_INF_COUNT = 4096U ;
// 旧32 INF×4096deviceの最大仕事量を維持する、一reportの総照合予算です。
inline constexpr std::uint32_t OFFICIAL_PREPARATION_MAXIMUM_PAIR_COUNT = 131072U ;

struct OfficialPreparationOperationResult ;
struct OfficialPreparationApproval ;

/** @brief 既存の表示専用候補に反映する監査状態。導入権限は含めない。 */
struct OfficialPreparationCandidateAudit {
	/// 同じscanで提示済みのopaque候補ID。
	std::wstring		 identity ;
	/// 内容とdevice別適用性。InstallはBlockedのまま。
	CandidateAuditStatus audit ;
} ;

/** @brief 取得後監査に合格した組合せから選択候補を発行した結果を表す。 */
enum class OfficialPreparationCandidatePublicationState {
	/// 監査未合格等により候補発行処理を開始していない。
	NOT_STARTED,
	/// 一件以上の候補と保持routingを同時に確定した。
	CANDIDATES_PUBLISHED,
	/// 全組合せを確認したが発行可能な候補がなかった。
	NO_ELIGIBLE_CANDIDATES,
	/// 内部構造または発行境界の失敗により全候補を破棄した。
	FAILURE,
} ;

/** @brief URLやPnP IDを含めず、候補発行の到達状態と有限件数を表す。 */
struct OfficialPreparationCandidatePublication {
	/// 候補0件の理由を未着手、対象なし、処理失敗へ分離する状態。
	OfficialPreparationCandidatePublicationState state{
		OfficialPreparationCandidatePublicationState::NOT_STARTED} ;
	/// 発行可否を確認した監査合格組合せ数。
	std::uint32_t examinedPairCount{} ;
	/// 候補とroutingを同時に確定した件数。
	std::uint32_t publishedCount{} ;
	/// 発行せず除外した監査合格組合せ数。
	std::uint32_t excludedPairCount{} ;
	/// 最初の除外または全体失敗HRESULT。該当なしは0。
	NativeError	  firstError{} ;
} ;

/** @brief 一つの取得成功対象に対応する、workerからUIへの独立した監査結果。 */
struct OfficialPreparationAuditReport {
	/// 利用者が取得承認した計画内のopaque対象ID。
	std::wstring								   targetIdentity ;
	/// 取得を実行したregistryのstable ID。
	std::wstring								   providerId ;
	/// 内容監査の到達状態。
	CandidateAuditGateState						   content{CandidateAuditGateState::PENDING} ;
	/// 全組合せの集計状態。
	CandidateAuditGateState						   applicability{CandidateAuditGateState::PENDING} ;
	/// 全体処理のHRESULT。正常終了または未開始は0。
	NativeError									   contentError{} ;
	/// 最初のINF拒否理由。拒否なしは0。
	NativeError									   firstContentRejection{} ;
	/// 全体処理のHRESULT。正常終了または未開始は0。
	NativeError									   applicabilityError{} ;
	/// 最初の個別PnP照合失敗。失敗なしは0。
	NativeError									   firstPairError{} ;
	/// 内容監査が確認したINF数。
	std::uint32_t								   infCount{} ;
	/// Payload全体で署名と全参照fileに合格した最大4096 INF。Device適合数ではない。
	std::uint32_t								   acceptedInfCount{} ;
	/// 標準INF件数と別に専用署名/作用範囲/元device guardを検査した引継ぎ方式です。
	bool										   installerHandoff{} ;
	/// 監査したINFとdeviceの組合せ数。
	std::uint32_t								   examinedPairCount{} ;
	/// G11-Dに合格した組合せ数。device数ではない。
	std::uint32_t								   applicablePairCount{} ;
	/// OS API等で判断できなかった組合せ数。
	std::uint32_t								   failedPairCount{} ;
	/// 最大4096件の既存表示行。
	std::vector<OfficialPreparationCandidateAudit> candidates ;
	/// 候補0件理由を含む発行集計。
	OfficialPreparationCandidatePublication		   publication ;
	/// trueの場合は全監査合格組合せから選択可能候補を発行する処理まで完了した。
	bool										   candidatePublicationAttempted{} ;
	/// 同じscanへ追加する最大4096件の全監査合格候補。既存候補を上書きしない。
	std::vector<UpdateCandidate>				   publishedCandidates ;
} ;

/**
 * @brief 一つの取得後監査reportが発行する新規候補を既存scanへ照合する。
 * 既存候補、Provider能力、device対応、監査状態および同版重複を照合する。
 * @param[in] report Providerが同じ取得成功対象から生成した監査report。 取得後監査と発行候補。
 * @param[in] candidates 同じscanで既に表示した候補。変更しない。 同じscanの既存表示候補。
 * @return 未発行状態または全候補が監査・Provider・device境界と一致する場合true。 未発行または全候補が既存scanへ安全に追加できる場合true。
 * @note 候補発行済みの場合は、既存ID上書きと同一Provider内の同device／同版重複を拒否する。
 */
[[nodiscard]] bool validatePreparationCandidatePublication(
	const OfficialPreparationAuditReport &report, std::span<const UpdateCandidate> candidates) ;

/**
 * @brief 承認済み取得結果と表示専用候補に結び付く監査reportだけを受理する。
 * 有限のID対応と監査状態を確認する。候補や導入権限を変更しない。
 * @param[in] result Operation／scan／planに拘束した確定結果。 取得完了と独立した監査report。
 * @param[in] approval 開始時に固定した対象別取得判断。 同一操作の固定承認。
 * @param[in] candidates 同じscanでUIに提示済みの候補。変更しない。 UIの既存候補。参照は本呼出し中だけ有効。
 * @return 未接続の空report、または全reportと全行が整合する場合true。 全件整合または空reportならtrue。不整合はfalse。
 * @note 発行候補を含む場合は全候補を検証する。件数・ID・状態の矛盾は全件拒否する。
 */
[[nodiscard]] bool validatePreparationAuditReports( const OfficialPreparationOperationResult &result,
												   const OfficialPreparationApproval &approval,
												   std::span<const UpdateCandidate>	  candidates) ;
} // namespace drivercrate
