//------------------------------------------------------------------------------
/**
 * @file official_record_utilities.h
 * @brief 公式recordの指紋表記とgrant限定取得の共通契約。
 * @version 01.00.00
 * @date 2026/10/02
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  旧AI adapterの非AI共通処理を移設。
 * </pre>
 *
 * @note Fingerprint byte列と既存grant・容量・進捗検証を維持し、推論や導入は行いません。
 * @see docs/adr/0224-remove-ai-and-local-index-distribution.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/official_acquisition.h"
#include "platform/official_download_grant.h"

#include <string>

namespace drivercrate {

//------------------------------------------------------------------------------
// 公式record共通処理。
//------------------------------------------------------------------------------

/**
 * @brief 非機密record fingerprintを小文字hexへ変換します。
 * @param[in] evidence 検証済みrecord証拠。呼出し中だけ借用します。
 * @return 元byte順を維持した固定64文字のfingerprint。
 * @note Record検証は行わず、与えられたSHA-256 byte列を表記します。
 */
[[nodiscard]] std::string officialRecordFingerprint(
	const OfficialDistributionRecordEvidence &evidence) ;

/**
 * @brief 既存grant限定取得と進捗一致を同じ同期境界で検証します。
 * @param[in,out] session 呼出しthreadが所有する有限取得session。
 * @param[in,out] workspace 保護保存先。共通取得器が失敗時のfile回収を担当します。
 * @param[in,out] transport 同期取得に使うHTTP境界。
 * @param[in,out] costReader 回線costの照会境界。
 * @param[in,out] grant 同じsessionへ発行済みの一回取得権限。
 * @param[in] utcClock 共通grantが要求する現在UTC秒の照会。同期呼出し中だけ借用します。
 * @param[in] networkApproved 制限／不明回線への今回の明示同意。
 * @param[in] cancellation 非blocking取消し照会。
 * @param[out] result URL非保持の取得結果。拒否時も状態とHRESULTを設定します。
 * @param[in] downloadOnlyProfile 取得専用型だけに要求する明示profile。既定は無効。
 * @return 共通取得と進捗identity一致時0、それ以外は元のHRESULT。
 * @note 型とprofile不一致は回線照会・grant消費・network開始前に拒否します。
 * @warning 成功は検査用byte取得だけであり、実行・内容合格・導入許可ではありません。
 */
[[nodiscard]] NativeError acquireGrantedOfficialPayload(
	OfficialAcquisitionSession &session, OfficialDownloadWorkspace &workspace,
	IOfficialAcquisitionTransport &transport, IOfficialNetworkCostReader &costReader,
	RecordScopedDownloadGrant &grant, const std::function<std::uint64_t()> &utcClock,
	bool networkApproved, const HttpCancellationCallback &cancellation,
	OfficialAcquisitionResult  &result,
	OfficialDownloadOnlyProfile downloadOnlyProfile = OfficialDownloadOnlyProfile::DISABLED) ;

} // namespace drivercrate
