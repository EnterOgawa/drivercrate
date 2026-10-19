//------------------------------------------------------------------------------
/**
 * @file asus_driver_package_audit.h
 * @brief ASUS監査の互換契約。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の共通接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 既存ASUSのhash必須条件を維持し、共通監査へ委譲します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/official_driver_package_audit.h"
#include <span>

namespace drivercrate {

/** @brief 共通監査型のASUS互換名である。 */
using AsusOfficialInfRankAuditor = OfficialInfRankAuditor ;
/** @brief 共通監査型のASUS互換名である。 */
using AsusDriverPackageAuditState = OfficialDriverPackageAuditState ;
/** @brief 共通監査型のASUS互換名である。 */
using AsusDriverPackageAuditSummary = OfficialDriverPackageAuditSummary ;
/** @brief 共通監査型のASUS互換名である。 */
using AsusDriverPackageAuditRequest = OfficialDriverPackageAuditRequest ;
/** @brief 共通監査型のASUS互換名である。 */
using AsusAuditedInfPackage = OfficialAuditedInfPackage ;
/** @brief 共通監査型のASUS互換名である。 */
using AsusRankApprovedInfTarget = OfficialRankApprovedInfTarget ;
/** @brief 共通監査型のASUS互換名である。 */
using AsusDriverApplicabilityState = OfficialDriverApplicabilityState ;
/** @brief 共通監査型のASUS互換名である。 */
using AsusDriverApplicabilitySummary = OfficialDriverApplicabilitySummary ;
/** @brief 共通監査型のASUS互換名である。 */
using AsusDriverPackageAudit = OfficialDriverPackageAudit ;

/**
 * @brief 取得済みASUS ZIP／CABの全INFを内容監査する。
 * ASUS用APIから他profileへ公開hash条件を迂回させない。
 * @param[in] request G11-B取得結果、ASUS公開hashおよび外側archive形式。 ASUSの公開hash付き取得結果。
 * @param[out] audit 監査件数とCAT／publisher検証済みの非boot-critical INF閉包群。 全INFの内容監査と保持閉包。
 * @return 全archive処理完了時は0、取得identityまたは全体処理失敗時はHRESULT。 全体処理成功時0、拒否・失敗時はHRESULT。
 * @note 個別INFの拒否は全INFを確認するため処理を継続し、summaryへ件数を残す。
 * @note 外側にINFがなくnested ZIP／CABが一件だけある場合は、その一段内側を監査する。
 */
[[nodiscard]] NativeError auditAsusDriverPackage( const AsusDriverPackageAuditRequest &request,
												 AsusDriverPackageAudit				 &audit) ;

/**
 * @brief 内容監査済みASUS INFを現在scanのlocal deviceとG11-D監査する。
 * 共通監査へ委譲し、非適用と個別API失敗を区別する。
 * @param[in] scanSessionId Device inventoryと同じ0ではないscan session ID。 内容監査と同一の検索session。
 * @param[in] devices Hardware IDを含まない現在device snapshot群。 現在deviceの非機密snapshot。
 * @param[in] rankAuditor Driver Storeのread-only PnP／Rank監査関数。 同じworkerのWindows標準照合。
 * @param[in,out] audit 内容監査合格INFと、成功時に追加するG11-D合格組合せ。 内容監査結果と適用性の反映先。
 * @return 全組合せを確認した場合は0、入力または全体処理失敗時はHRESULT。 全体処理成功時0、拒否・失敗時はHRESULT。
 * @note 個別SetupAPI失敗または非適用後も残りを確認し、`APPLICABLE`だけを保持する。
 */
[[nodiscard]] NativeError auditAsusDriverApplicability(
	ScanSessionId scanSessionId, std::span<const OfficialCatalogDevice> devices,
	const AsusOfficialInfRankAuditor &rankAuditor, AsusDriverPackageAudit &audit) ;

/**
 * @brief 内容監査済みASUS INF閉包をinstall直前に完全再検証する。
 * 既存ASUSの導入直前再検証を同じprofileで行う。
 * @param[in] auditedPackage Scan時に固定した保護workspace、file hashおよびINF metadata。 ASUSの内容監査から保持した閉包。
 * @return 全file、INF構造、CAT member、publisherがscan時と一致する場合は0。 再照合成功時0、拒否・失敗時はHRESULT。
 * @note 管理者権限を持つ競合processによるscan後の差替えをSetupAPI呼出し前に拒否する。
 */
[[nodiscard]] NativeError reverifyAsusAuditedInfPackage(
	const AsusAuditedInfPackage &auditedPackage) ;

} // namespace drivercrate
