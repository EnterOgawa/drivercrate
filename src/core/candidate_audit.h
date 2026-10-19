//------------------------------------------------------------------------------
/**
 * @file candidate_audit.h
 * @brief Driver候補監査状態の生成と整合性検証。
 * @version 01.01.00
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  表示専用公式探索状態追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式全監査合格状態追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  詳細assessmentと代表行の整合性検証を追加。
 * </pre>
 *
 * @note 候補の取得経路ごとに監査状態を生成し、scan session登録前にinstall可否との矛盾をfail-closedで拒否します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <span>

namespace drivercrate {

/**
 * @brief WUAまたはWindows標準APIへ監査を委譲する候補状態を生成する。
 * WUAまたはWindows標準APIへの委譲をDriverCrate独自の監査合格と表現せず、表示専用行だけinstallを禁止する。
 * @param[in] displayOnly 現在版等の表示専用候補の場合は`true`。 現在版等の表示専用候補なら`true`。
 * @return Windows管理経路とinstall準備状態を明示した監査状態。
 */
[[nodiscard]] CandidateAuditStatus makeWindowsManagedCandidateAudit( bool displayOnly) noexcept ;

/**
 * @brief 公式metadata確認済みでpayload監査前の候補状態を生成する。
 * Catalogとlocal deviceのProvider固有照合は保持するが、G11-C／D未接続の候補を選択可能にしない。
 * @return 由来確認済み、download／内容監査待ち、Provider照合済み、install禁止の状態。 由来確認済み、取得／内容監査待ち、Provider照合済みの状態。
 */
[[nodiscard]] CandidateAuditStatus makeOfficialMetadataCandidateAudit() noexcept ;

/**
 * @brief 公式取得物が由来、download、内容およびsystem監査を全て通過した状態を生成する。
 * 登録済み公式originから取得し、G11-B～Dを通過した候補だけへ設定する。個別gateを呼出し側で推測して組み立てない。
 * @return 全監査gate合格済みでinstall可能な状態。
 */
[[nodiscard]] CandidateAuditStatus makeOfficialReadyCandidateAudit() noexcept ;

/**
 * @brief 公式page由来だけを確認した表示専用候補状態を生成する。
 * 公式pageとlocal表示名の照合をPnP適用性合格へ昇格せず、配布情報だけを表示できる状態を生成する。
 * @return 由来確認済み、download／内容／system監査待ち、install禁止の状態。 由来確認済み、download／内容／system監査待ちの禁止状態。
 */
[[nodiscard]] CandidateAuditStatus makeOfficialDiscoveryCandidateAudit() noexcept ;

/**
 * @brief 利用者が指定し静的package監査を通過した候補状態を生成する。
 * 利用者指定fileを公式由来へ昇格せず、既存package検証とProvider固有照合が完了した範囲だけを記録する。
 * @return 取得元未証明、内容監査済み、Provider照合済みの状態。 取得元未証明、静的内容監査済みの候補状態。
 */
[[nodiscard]] CandidateAuditStatus makeUserSelectedCandidateAudit() noexcept ;

/**
 * @brief 候補監査状態とProvider経路、表示／install可否の整合性を検証する。
 * 定義外enumと過大な成功表現を拒否し、URLや表示名から不足状態を推測しない。
 * @param[in] candidate Scan sessionへ登録する候補。
 * @param[in] descriptor 候補を生成した登録済みProvider定義。 候補を生成したProviderのregistry定義。
 * @return 全enumと取得経路別の状態が矛盾しない場合は`true`。 経路、監査状態、表示／install可否が整合する場合は`true`。
 */
[[nodiscard]] bool				   isCandidateAuditValid( const UpdateCandidate	  &candidate,
														 const ProviderDescriptor &descriptor) noexcept ;

/**
 * @brief 観測・詳細assessment・初回actionを既存候補へ照合する。
 * @param[in] candidate 同じscanの候補。
 * @param[in] scanSessionId 現在session。0は候補自身との内部結合だけを検証する。
 * @return 新詳細の結合・集約auditとの整合性・表示専用条件を満たせばtrue。
 * @note 値なしの旧Providerを詳細合格へ補完しない。既存audit自体の検証は別途必須。
 */
[[nodiscard]] bool				   isCandidateDetailsValid( const UpdateCandidate &candidate,
														   ScanSessionId		  scanSessionId = 0U) noexcept ;

/**
 * @brief 全代表行の一意性と観測・詳細のsessionを検証する。
 * @param[in] candidates 同じ結果の全候補。
 * @param[in] scanSessionId 0ではない結果のsession。
 * @return 全代表行が一device一行で新詳細が正しく結合する場合true。
 * @note 一時索引の確保失敗もfalseで返す。既存の候補ID・Provider監査を置き換えない。
 */
[[nodiscard]] bool isCandidateDetailsSetValid( std::span<const UpdateCandidate> candidates,
											  ScanSessionId scanSessionId) noexcept ;

} // namespace drivercrate
