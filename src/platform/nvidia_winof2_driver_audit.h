//------------------------------------------------------------------------------
/**
 * @file nvidia_winof2_driver_audit.h
 * @brief WinOF-2閉包の内容・PnP監査と候補発行定義。
 * @version 01.00.00
 * @date 2026/09/07
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 公式取得identityへ拘束したWinOF-2閉包だけを共通CAT、PnP、rank監査へ接続します。導入routing未接続のため候補のinstallは許可しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/nvidia_winof2_driver_package.h"
#include "platform/official_acquisition.h"
#include "platform/official_catalog_device.h"
#include "platform/official_driver_package_audit.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {

/** @brief 保持閉包を同じprofileで再検証するworker内の差替え可能な試験境界である。 */
using NvidiaWinof2ClosureReverifier = std::function<NativeError( const OfficialAuditedInfPackage &)> ;

/** @brief WinOF-2固有取得identityと共通内容・適用性監査を結合して所有する。 */
struct NvidiaWinof2DriverAudit {
	/// 外側取得、MSI閉包、local deviceに共通するsession。
	ScanSessionId			   scanSessionId{} ;
	/// 外側公式payloadの取得連番。
	std::uint64_t			   sourceAcquisitionId{} ;
	/// 閉包作成時に固定した内側MSI SHA-256。
	std::wstring			   databaseSha256 ;
	/// 監査した固定6系列内の論理INF名。
	std::wstring			   selectedInfPath ;
	/// 共通CAT、PnP、rank監査結果と所有閉包。
	OfficialDriverPackageAudit package ;
} ;

/**
 * @brief 非機密deviceがWinOF-2内容監査の対象classとmakerに属するか確認する。
 * Local対象を限定する予備判定であり、PnP適合性は確定しない。
 * @param[in] device 同一scanで列挙した外部送信しないdevice snapshot。 同一scanの非機密device snapshot。
 * @return Mellanox／NVIDIA maker、許可class、opaque identityが揃う場合true。 Maker、class、identity、modelが監査対象条件
 *         を満たす場合true。
 * @note 表示名による対象絞込みであり、PnP適合性はrank auditorだけが確定する。
 */
[[nodiscard]] bool		  isNvidiaWinof2AuditDevice( const OfficialCatalogDevice &device) noexcept ;

/**
 * @brief WinOF-2閉包を公式取得identity、CAT、Windows x64、local PnP、rankで監査する。
 * 内容再検証を共通実装へ固定し、Provider固有の緩和を許さない。
 * @param[in] acquisition 外側WinOF-2 EXEの公開hash照合済み公式取得結果。 公開hash照合済み外側EXE取得結果。
 * @param[in] workspace 選択INF、CAT、参照fileを単独所有する保護workspace。 選択driver閉包の単独所有領域。
 * @param[in] driverClosure MSI identityへ拘束したG12-X5-02e3の閉包結果。 MSIと取得元に拘束した閉包。
 * @param[in] devices 同じscanでWinOF-2対象に絞った最大4096件のdevice snapshot。 WinOF-2対象に絞ったlocal device群。
 * @param[in] rankAuditor 同じworkerのWindows標準PnP／rank監査関数。
 * @param[out] audit 取得identity、内容・適用性結果と、成功時に所有権を移す閉包。 合格閉包、適用対象、件数、診断値。
 * @return 全gate監査完了時は0、identity、内容または処理失敗時はHRESULT。 全監査完了時0、identity、内容または処理失敗時はHRESULT。
 * @note 内容再検証は共通`reverifyOfficialAuditedInfPackage`へ固定する。
 */
[[nodiscard]] NativeError auditNvidiaWinof2DriverClosure(
	const OfficialAcquisitionResult			  &acquisition,
	std::unique_ptr<OfficialDownloadWorkspace> workspace, NvidiaWinof2DriverClosure driverClosure,
	std::span<const OfficialCatalogDevice> devices, const OfficialInfRankAuditor &rankAuditor,
	NvidiaWinof2DriverAudit &audit) ;

/**
 * @brief WinOF-2監査の内容再検証だけを差し替えて決定的単体testを実行する。
 * CAT合格前にPnP監査を呼ばず、失敗時は閉包所有権を破棄する。
 * @param[in] acquisition 外側WinOF-2 EXEの架空または固定済み取得結果。 公開hash照合済み外側EXE取得結果。
 * @param[in] workspace 選択driver閉包を単独所有する保護workspace。 選択driver閉包の単独所有領域。
 * @param[in] driverClosure MSI identityへ拘束した閉包結果。 MSIと取得元に拘束した閉包。
 * @param[in] devices 同じscanでWinOF-2対象に絞ったdevice snapshot群。 WinOF-2対象に絞ったlocal device群。
 * @param[in] reverifier CAT、publisher、Windows x64結果を返す試験境界。 共通内容・CAT再検証関数。
 * @param[in] rankAuditor PnP／rank結果を返す試験境界。 Windows標準PnP／rank監査関数。
 * @param[out] audit 取得identity、内容・適用性結果と、成功時に所有権を移す閉包。 合格閉包、適用対象、件数、診断値。
 * @return 全gate監査完了時は0、identity、内容または処理失敗時はHRESULT。 全監査完了時0、identity、内容または処理失敗時はHRESULT。
 * @note Product codeは本関数を呼ばず、固定再検証を使う通常関数を使用する。
 */
[[nodiscard]] NativeError auditNvidiaWinof2DriverClosureForTesting(
	const OfficialAcquisitionResult			  &acquisition,
	std::unique_ptr<OfficialDownloadWorkspace> workspace, NvidiaWinof2DriverClosure driverClosure,
	std::span<const OfficialCatalogDevice> devices, const NvidiaWinof2ClosureReverifier &reverifier,
	const OfficialInfRankAuditor &rankAuditor, NvidiaWinof2DriverAudit &audit) ;

/**
 * @brief 全内容・PnP／rank監査合格組合せをsession拘束済みの選択不能候補へ変換する。
 * INF明示値だけを表示し、EULA・導入routing未接続をBlockedで保持する。
 * @param[in] acquisition 監査時と同じ外側公式取得identity。
 * @param[in] devices 監査時と同じWinOF-2対象device snapshot群。 監査時と同じlocal device snapshot群。
 * @param[in] audit 全gate合格組合せと単独所有閉包。 内容、PnP、rank合格組合せと保持閉包。
 * @return 同device／同版を重複排除した監査済み候補。 同device／同版を重複排除した選択不能候補。
 * @throws std::logic_error 入力identity、監査状態または保持関係が不整合な場合。
 * @note EULAと導入routing未接続のため全候補をBlocked、非推奨、非installableにする。
 */
[[nodiscard]] std::vector<UpdateCandidate> makeNvidiaWinof2AuditedCandidates(
	const OfficialAcquisitionResult &acquisition, std::span<const OfficialCatalogDevice> devices,
	const NvidiaWinof2DriverAudit &audit) ;

} // namespace drivercrate
