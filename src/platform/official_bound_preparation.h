//------------------------------------------------------------------------------
/**
 * @file official_bound_preparation.h
 * @brief 公式INFのbinding付き候補と導入契約。
 * @version 01.00.00
 * @date 2026/09/09
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  IntelとASIXの共通契約を抽出。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 審査済み二profileに限定し、秘密bindingはworker内だけで所有します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_preparation_audit.h"
#include "platform/official_catalog_device.h"
#include "platform/official_inf_install_binding.h"
#include "platform/official_prepared_install.h"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

namespace drivercrate {
/**
 * @brief Intel公式READMEが明示した非対応OEMを完全一致で識別する。
 * 部分一致や別名推測を行わず、ADR 0132の既知非対応だけを除外する。
 * @param[in] model Local inventoryの製品表示名。外部へ送信しない。
 * @return 大文字小文字を除いて既知の二表示と一致する場合true。 既知の二つのHPE非対応表示と大文字小文字を除き完全一致ならtrue。
 * @note 共通候補発行とIntel監査reportで同じ除外規則を共有する。
 */
[[nodiscard]] bool isKnownUnsupportedIntelEthernetModel( std::wstring_view model) noexcept ;

/** @brief 監査済みINFと一scan限定のWindows nodeを結ぶ保持routing。 */
struct BoundPreparedInstallTarget {
	/// 共通再監査へ渡すINFとdeviceの対応。
	PreparedInfInstallTarget  prepared ;
	/// 現在driverと対象nodeを固定したworker内token。
	OfficialInfInstallBinding binding ;
} ;
/** @brief 候補IDから保持INFとbindingへ解決するworker内索引。 */
using BoundPreparedInstallTargets = std::unordered_map<std::wstring, BoundPreparedInstallTarget> ;

/** @brief 取得物とbindingを導入呼出し中だけ参照する非所有context。 */
struct BoundPreparedInstallContext {
	/// 保持候補の検索session。
	ScanSessionId							   scanSessionId{} ;
	/// 保持した公式取得結果。nullは拒否する。
	const OfficialAcquisitionResult			  *acquisition{} ;
	/// Provider所有routing。nullは拒否する。
	const BoundPreparedInstallTargets		  *targets{} ;
	/// 保護workspace付き閉包。
	std::span<const OfficialAuditedInfPackage> auditedPackages ;
	/// 実OSがServerならtrue。
	bool									   windowsServer{} ;
	/// 実OSのmajor build。0は拒否する。
	std::uint32_t							   windowsBuild{} ;
	/// Providerが公式取得根拠を確認した場合だけtrue。
	bool									   sourceEvidenceConfirmed{} ;
} ;

/**
 * @brief 合格した組合せから未選択候補とbinding付きroutingを一括発行する。
 * 既知profileの合格組合せを有限処理し、失敗時は未commit tokenを破棄する。
 * @param[in] profile Intel Ethernet Server 2025またはASIX AX88179Aの固定profile。 二つの固定profileに限る。
 * @param[in] session 取得・device・監査が共有する検索session。 同一scanの識別子。
 * @param[in] acquisitionId 検証済み外側取得物のopaque ID。 検証済み取得ID。
 * @param[in] maximumDownloadBytes 外側取得物の実測byte数。 取得したbyte数。
 * @param[in] devices 同じscanで保持する対象device。 同じscanのdevice snapshot。
 * @param[in] audit 内容・PnP／rank監査結果。 内容とrankの監査結果。
 * @param[in] bindingCreator 現在driverとWindows nodeを固定する境界。 現在driverとnodeを固定する境界。
 * @param[in] bindingReleaser 未commit tokenを破棄する例外を投げない境界。 未commit tokenの非throw破棄境界。
 * @param[in,out] report 既存行の監査report。発行状態と候補を追加する。 監査reportへ候補と発行結果を追加する。
 * @param[out] installTargets 成功時だけ返すrouting。入力時は空であること。 全件検証後に返すrouting。入力は空。
 * @note 拒否はreportのpublicationへ記録する。 失敗はpublicationへ記録する。
 */
void publishBoundPreparedCandidates( OfficialDriverAuditProfile profile, ScanSessionId session,
									std::uint64_t acquisitionId, std::uint64_t maximumDownloadBytes,
									std::span<const OfficialCatalogDevice>	 devices,
									const OfficialDriverPackageAudit		&audit,
									const OfficialInfInstallBinder			&bindingCreator,
									const OfficialInfInstallBindingReleaser &bindingReleaser,
									OfficialPreparationAuditReport			&report,
									BoundPreparedInstallTargets &installTargets) noexcept ;

/**
 * @brief 固定profileの保持routingを再監査して指定device導入境界へ接続する。
 * 固定profileと全routingを先に照合する。保持物の失効はProviderが行う。
 * @param[in] profile Intel Ethernet Server 2025またはASIX AX88179Aの固定profile。 固定ProviderとOSの選択値。
 * @param[in] context 同じworkerで保持する取得物・閉包・binding。 呼出し中に有効な保持物の非所有参照。
 * @param[in] identities 明示選択した候補ID。一device一候補。 利用者が選択した候補ID。
 * @param[in] reverifier 共通CAT／全file再検証callback。 閉包再検証callback。
 * @param[in] rankAuditor 現在PnP／rankの再監査callback。 現在rank再取得callback。
 * @param[in] boundInstaller Bindingを再照合するstaging／指定導入callback。 固定bindingによる指定導入callback。
 * @param[in] parentWindowNative 導入dialogの親Window値。
 * @param[in] progressCallback 確定済み段階の通知先。 確定段階の通知先。
 * @return 選択順の個別結果。外側再確認と導入を区別する。 入力順の個別結果。失敗を候補ごとに保持する。
 * @note 復旧保護はworkerが先に確立し、Providerは結果確定後に保持物を失効させる。
 */
[[nodiscard]] InstallResult executeBoundPreparedInstall(
	OfficialDriverAuditProfile profile, const BoundPreparedInstallContext &context,
	std::span<const std::wstring> identities, const PreparedInfReverifier &reverifier,
	const OfficialInfRankAuditor &rankAuditor, const OfficialBoundInfInstaller &boundInstaller,
	std::uintptr_t parentWindowNative, const ProviderProgressCallback &progressCallback) ;
} // namespace drivercrate
