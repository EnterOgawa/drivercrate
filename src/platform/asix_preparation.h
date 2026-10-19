//------------------------------------------------------------------------------
/**
 * @file asix_preparation.h
 * @brief ASIX取得済みdriver packageの内容・適用性監査契約。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX候補発行と指定導入の共通接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX既存候補用の共通report wrapperを追加。
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
 * @note ASIX固定profileで取得物を共通監査し、PnP IDとpathをworker外へ公開しません。監査と、明示選択される候補発行・指定導入の契約を分離します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_preparation_audit.h"
#include "core/official_preparation_operation.h"
#include "platform/official_acquisition.h"
#include "platform/official_bound_preparation.h"
#include "platform/official_catalog_device.h"
#include "platform/official_driver_package_audit.h"

#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

/**
 * @brief ASIXの同一scan取得物を共通内容監査と端末内PnP／rank監査へ接続する。
 * ASIX固定Net profileで全INFを監査し、署名合格後だけ端末内で照合する。候補発行、driver stagingまたは導入は行わない。個別INFの全拒否は戻り値0と監査状態で区別する
 * 。
 * @param[in] scanSessionId 保持deviceと取得結果に共通する0ではない検索session。 保持deviceと取得結果に共通する検索session。
 * @param[in] acquisition ASIX公式取得境界が保持する検査用取得結果。 同じworkerが所有するASIX公式取得結果。
 * @param[in] expectedSha256 公式metadataの公開SHA-256。未掲載の場合は空。 公開hash。未掲載の場合は空。
 * @param[in] devices 同じscanでASIX AX88179Aへ照合した1～4,096件のdevice群。 同一scanでASIX AX88179Aへ照合済みのdevice群。
 * @param[in] rankAuditor 同じworkerが所有するDriver StoreのPnP／rank監査関数。 Windows標準PnP／rank監査。
 * @param[in] cancellation 空または非blockingの協調取消し照会。
 * @param[out] audit 内容と適用性の独立した結果。候補や導入許可は作らない。 内容・適用性の結果と単独所有閉包。
 * @return 全INF確認または成功時は0、入力拒否・全体処理失敗時はHRESULT。
 * @note 製品表示は対象範囲の事前確認に限り、適用性はPnP／rank監査を正本とする。
 * @note 個別INFの全拒否は0を返す場合があり、`audit.summary.state`で区別する。
 */
[[nodiscard]] NativeError auditAsixAx88179aPreparedPackage(
	ScanSessionId scanSessionId, const OfficialAcquisitionResult &acquisition,
	std::wstring_view expectedSha256, std::span<const OfficialCatalogDevice> devices,
	const OfficialInfRankAuditor &rankAuditor, const PreparationCancellation &cancellation,
	OfficialDriverPackageAudit &audit) ;

/**
 * @brief ASIX監査結果を検索時の既存候補行へ反映する非機密reportへ変換する。
 * ASIX対象を全件検証してから固定profileの共通helperへ集約を委譲する。候補発行・導入routing・現在版の更新は行わない。
 * @param[in] session 監査対象を取得した0ではない検索session。 監査対象を取得した検索session。
 * @param[in] targetIdentity 利用者が取得を承認したopaque対象ID。 承認済み取得対象のopaque ID。
 * @param[in] devices 検索候補順に保持したASIX対象device snapshot。 検索候補順のASIX対象device snapshot。
 * @param[in] candidateIdentities devicesと同じ順序の既存opaque候補ID。 同じ順序の既存候補ID。
 * @param[in] audit 同一取得物の内容・PnP／rank監査結果。 内容・PnP／rank監査結果と保持閉包。
 * @return 既存候補の監査fieldだけを持ち、新規候補を発行しないreport。 既存候補の監査fieldだけを持つ非機密report。
 * @throws std::logic_error ASIX対象、identityまたは監査構造が不正な場合。
 */
[[nodiscard]] OfficialPreparationAuditReport makeAsixPreparationAuditReport(
	ScanSessionId session, std::wstring_view targetIdentity,
	std::span<const OfficialCatalogDevice> devices,
	std::span<const std::wstring> candidateIdentities, const OfficialDriverPackageAudit &audit) ;

/**
 * @brief ASIX固定profileで監査合格候補とbinding付きroutingを一括発行する。
 * 固定ASIX profile以外を呼出側から指定できないwrapperである。
 * @param[in] session 同じ取得物とdeviceの検索session。 同一scanの識別子。
 * @param[in] acquisitionId 検証済み外側取得ID。 検証済み取得ID。
 * @param[in] byteCount 外側取得物の実測byte数。 外側fileの実測byte数。
 * @param[in] devices ASIX対象device snapshot。 ASIX対象snapshot。
 * @param[in] audit 内容とPnP／rank監査結果。 内容・rank監査結果。
 * @param[in] binder 現在driverとWindows nodeを固定する境界。 現在状態とnodeを固定する境界。
 * @param[in] releaser 未commit bindingの非throw破棄境界。 未commit tokenの非throw破棄境界。
 * @param[in,out] report 既存行reportへ発行結果を追加する。 発行状態と候補を追加する既存report。
 * @param[out] targets 全件検証後に返すrouting。入力は空。 全件検証後のrouting。入力は空。
 * @note 拒否理由はreportに記録する。 失敗はpublicationへ記録する。
 */
void publishAsixPreparedCandidates(
	ScanSessionId session, std::uint64_t acquisitionId, std::uint64_t byteCount,
	std::span<const OfficialCatalogDevice> devices, const OfficialDriverPackageAudit &audit,
	const OfficialInfInstallBinder &binder, const OfficialInfInstallBindingReleaser &releaser,
	OfficialPreparationAuditReport &report, BoundPreparedInstallTargets &targets) noexcept ;

/**
 * @brief ASIXの保持候補をclient限定のbinding付き再監査・導入へ渡す。
 * 復旧保護確立後に呼び、client限定の固定profileで共通executorへ渡す。
 * @param[in] context 呼出し中だけ参照する取得物、閉包、routing、実OS。 保持物と実OSの非所有参照。
 * @param[in] identities 利用者が選択した候補ID。一device一候補。 明示選択ID。
 * @param[in] reverifier 共通CAT／全file再検証境界。 閉包再監査境界。
 * @param[in] rankAuditor 現在PnP／rank再取得境界。 現在rankの再確認境界。
 * @param[in] installer Binding再照合と指定device導入境界。 Binding再検証付き指定導入。
 * @param[in] parentWindowNative Windows導入dialogの親Window。 導入dialog親Window。
 * @param[in] progressCallback 確定段階の通知先。 確定進捗通知先。
 * @return 選択順の個別結果。保持物はProviderが終了後に失効する。 入力順の個別結果。失敗を候補ごとに保持する。
 */
[[nodiscard]] InstallResult executeAsixPreparedInstall(
	const BoundPreparedInstallContext &context, std::span<const std::wstring> identities,
	const PreparedInfReverifier &reverifier, const OfficialInfRankAuditor &rankAuditor,
	const OfficialBoundInfInstaller &installer, std::uintptr_t parentWindowNative,
	const ProviderProgressCallback &progressCallback) ;

} // namespace drivercrate
