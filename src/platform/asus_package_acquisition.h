//------------------------------------------------------------------------------
/**
 * @file asus_package_acquisition.h
 * @brief ASUS公式driver package検査用取得定義。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note ASUS公式pageで検証したURLとSHA-256を、候補化せずG11-Bの有限取得へ接続します。取得結果はworker内だけに保持し、system監査を迂回しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/asus_catalog_parser.h"
#include "platform/official_acquisition.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {

class OfficialDownloadWorkspace ;

//------------------------------------------------------------------------------
// ASUS検査用取得計画定義。
//------------------------------------------------------------------------------

/**
 * @brief ASUS公式pageの一driver archiveをG11-Bへ渡す内部取得計画である。
 *
 * @note URL、公開hashおよびopaque IDはscan sessionのworker内だけに保持し、UIまたはlogへ
 * 渡してはならない。
 */
struct AsusPackageAcquisitionPlanEntry {
	/// ASUS metadata recordとの照合に使用する内部ID。
	std::wstring  opaqueId ;
	/// 固定ASUS CDN上の検証済みHTTPS URL。
	std::wstring  downloadUrl ;
	/// ASUS pageが公開した小文字64桁SHA-256。
	std::wstring  publishedSha256 ;
	/// 元file名を使用しない保護領域内の固定相対名。
	std::wstring  workspaceFileName ;
	/// 丸め公開sizeに余裕を加えた取得上限byte数。
	std::uint64_t maximumFileBytes{} ;
} ;

/**
 * @brief ASUS parser結果から有限で重複のない検査用取得計画を構築する。
 * ASUS parser結果から有限取得計画を構築する。
 * Origin、hash、size、opaque IDを再検証し、外部file名を使用しない有限計画へ固定する。
 * @param[in] entries 同一model／OSの検証済みASUS page entry群。 同一model／OSの検証済みpage entry群。
 * @param[out] plan 成功時の取得順を維持した内部計画。失敗時は空にする。 成功時の内部取得計画。
 * @return 構築成功時は0、不正値、重複または件数超過時はHRESULT bit pattern。
 * @note 本関数はdownloadを開始せず、候補またはinstall可能状態を生成しない。
 */
[[nodiscard]] NativeError makeAsusPackageAcquisitionPlan(
	std::span<const AsusDriverPageEntry>		  entries,
	std::vector<AsusPackageAcquisitionPlanEntry> &plan) ;

/**
 * @brief 一つのASUS計画entryをG11-Bの保護workspaceへ検査用取得する。
 * ASUS package一件をG11-Bへ検査用取得する。
 * Provider／resource IDを呼出し側に選ばせず、ASUS公式payload policyと公開SHA-256へ固定して共通取得を実行する。
 * @param[in] entry 検証済みASUS取得計画entry。
 * @param[in] restrictedNetworkApproved 今回だけRestricted／Unknown networkを許可する状態。 今回だけのcost同意。
 * @param[in,out] session 初期化済みのscan session共通取得ledger。 初期化済みscan session取得ledger。
 * @param[in,out] workspace 初期化済みで成功fileを所有する保護領域。
 * @param[in,out] transport ASUS source session開始済みの公式取得境界。 ASUS source session開始済み取得境界。
 * @param[in,out] costReader Machine-wide network cost照会境界。
 * @param[in] progressCallback 確定済み受信byte数の通知先。 確定済み受信進捗通知先。
 * @param[in] cancellationCallback 空または取消し状態を返す非blocking関数。 取消し状態確認先。
 * @param[out] result 成功または失敗の監査前取得状態。URLを含まない。 URLを含まない監査前取得状態。
 * @return `ACQUIRED_FOR_INSPECTION`到達時は0、それ以外はHRESULT bit pattern。 検査対象固定成功時は0、それ以外はHRESULT。
 * @note 取得成功は候補、PnP適用可能またはinstall可能を意味しない。
 */
[[nodiscard]] NativeError acquireAsusPackageForInspection(
	const AsusPackageAcquisitionPlanEntry &entry, bool restrictedNetworkApproved,
	OfficialAcquisitionSession &session, OfficialDownloadWorkspace &workspace,
	IOfficialAcquisitionTransport &transport, IOfficialNetworkCostReader &costReader,
	const HttpDownloadProgressCallback &progressCallback,
	const HttpCancellationCallback &cancellationCallback, OfficialAcquisitionResult &result) ;

} // namespace drivercrate
