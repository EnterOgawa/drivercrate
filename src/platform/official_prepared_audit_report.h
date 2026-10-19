//------------------------------------------------------------------------------
/**
 * @file official_prepared_audit_report.h
 * @brief 公式取得後監査の非機密report共通生成契約。
 * @version 01.00.00
 * @date 2026/09/08
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 固定profile、同一scan、既存候補IDだけからURL・path・PnP IDを含まないreportを作ります。Provider固有の対象製品判定、候補発行および導入
 *       routingは呼出し側の責務です。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_preparation_audit.h"
#include "platform/official_catalog_device.h"
#include "platform/official_driver_package_audit.h"

#include <span>
#include <string>
#include <string_view>

namespace drivercrate {

/**
 * @brief 固定profileの監査結果を検索時の既存候補行へ反映する非機密reportを作る。
 * 件数、identity、profile、合格組合せを検証し、URL・path・PnP IDを出力しない。入力矛盾時は例外で全体拒否し、候補発行や導入状態を作らない。
 * @param[in] profile 取得Providerと監査済み閉包へ完全一致を要求する登録済みprofile。 固定Providerと閉包へ要求する登録済みprofile。
 * @param[in] session 監査対象を取得した0ではない検索session。 監査対象を取得した検索session。
 * @param[in] targetIdentity 利用者が取得を承認した最大128文字のopaque対象ID。 取得承認済みのopaque対象ID。
 * @param[in] devices 検索候補順に保持した1～4,096件の一意なdevice snapshot。 検索候補順の非機密device snapshot。
 * @param[in] candidateIdentities devicesと同じ順序・件数の一意な既存候補ID。 同じ順序の既存候補ID。
 * @param[in] audit 同一取得物の内容・PnP／rank監査結果。 内容・PnP／rank監査結果と保持閉包。
 * @return 既存候補の監査fieldだけを持つ非機密report。
 * @throws std::logic_error 未知profile、session、件数、identityまたは監査構造が不正な場合。
 * @note DeviceがProviderの対象製品かは呼出し側が先に確認する。本関数は候補を発行しない。
 */
[[nodiscard]] OfficialPreparationAuditReport makeOfficialPreparedAuditReport(
	OfficialDriverAuditProfile profile, ScanSessionId session, std::wstring_view targetIdentity,
	std::span<const OfficialCatalogDevice> devices,
	std::span<const std::wstring> candidateIdentities, const OfficialDriverPackageAudit &audit) ;

} // namespace drivercrate
