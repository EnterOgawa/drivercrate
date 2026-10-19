//------------------------------------------------------------------------------
/**
 * @file official_prepared_install.h
 * @brief 監査済み公式INFの共通導入契約。
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
 * @note 公式取得後の監査に合格したINFだけを再検証し、Providerが固定したWindows標準導入境界へ渡します。保持物の所有と失効は呼出側が担います。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_driver_rank.h"
#include "core/update_provider.h"
#include "platform/official_acquisition.h"
#include "platform/official_driver_package_audit.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

namespace drivercrate {

/**
 * @brief 再検証済みINFをDriver Storeの指定deviceへ導入する関数である。
 *
 * @note 入力pathとopaque device IDは呼出し中だけ有効であり、callback外へ保持しない。
 */
using PreparedVerifiedInfInstaller =
	std::function<NativeError( ScanSessionId, std::wstring_view, std::wstring_view,
							  std::wstring_view, std::wstring_view, std::uintptr_t, bool &)> ;

/**
 * @brief 保持INF閉包を導入直前に同じ監査条件で再検証する関数である。
 */
using PreparedInfReverifier = std::function<NativeError( const OfficialAuditedInfPackage &)> ;

/**
 * @brief 共通executorへ固定する組み込みProviderとpayload resourceを表す。
 */
struct PreparedInfInstallPolicy {
	/// 呼出側wrapperが固定する組み込みProvider ID。
	std::wstring_view providerId ;
	/// 同じProviderのpayload用途resource ID。
	std::wstring_view resourceId ;
} ;

/**
 * @brief 一つの発行候補を保持INF、device、取得後rankへ結び付けるroutingである。
 */
struct PreparedInfInstallTarget {
	/// 同じ外側取得物を束ねるopaque package ID。
	std::wstring			packageIdentity ;
	/// Scan session内のopaque local device ID。
	std::wstring			deviceIdentity ;
	/// 保持監査結果内のINF閉包index。
	std::size_t				auditedPackageIndex{} ;
	/// 取得後監査時の完全比較対象。
	OfficialDriverRankAudit rankAudit ;
} ;

/**
 * @brief 発行済み候補の導入再検証に必要な非所有worker contextである。
 */
struct PreparedInfInstallContext {
	/// 候補を発行した現在scan session。
	ScanSessionId													  scanSessionId{} ;
	/// 外側fileのsize／hash snapshot。
	const OfficialAcquisitionResult									 *acquisition{} ;
	/// 全候補が共有するopaque package ID。
	std::wstring_view												  packageIdentity ;
	/// 発行済み候補IDから保持INF／deviceへのProvider所有routing。
	const std::unordered_map<std::wstring, PreparedInfInstallTarget> *targets{} ;
	/// Providerが次scanまたは導入結果確定まで所有する監査済みINF閉包群。
	std::span<const OfficialAuditedInfPackage>						  auditedPackages ;
	/// trueの場合だけ公式payload取得根拠を確認済み。
	bool															  sourceEvidenceConfirmed{} ;
} ;

/**
 * @brief 発行済み監査合格候補を再検証し、個別にWindows標準導入境界へ渡す。
 * 本番とtestで同じ検証順序を使い、全監査合格候補だけをinstallerへ渡す。保持物の失効はProviderが結果確定後に行う。
 * @param[in] policy 固定Provider／payload resourceの許可組合せ。 固定Provider／payload resource組合せ。
 * @param[in] context 同じworker呼出し中だけ有効な取得物・閉包・routing。 Worker所有の取得物・閉包・routing。
 * @param[in] identities 利用者が一device一候補で明示選択したopaque ID群。 明示選択された監査合格候補ID群。
 * @param[in] reverifier 本番では共通INF閉包再検証だけを渡す必須関数。 保持INF閉包の共通再検証。
 * @param[in] rankAuditor 現在PnP／rankを再取得する必須関数。 現在PnP／rankの再監査。
 * @param[in] installer 再検証合格INFだけを導入する必須関数。 再検証合格INFのWindows標準導入境界。
 * @param[in] parentWindowNative Windows導入dialogの親Window値。
 * @param[in] progressCallback 確定した外側file検証・候補処理の進捗通知先。 確定した処理段階の通知先。
 * @return Downloadとinstallを分離した入力順の個別結果。 外側file、INF、rank再検証と導入を分離した入力順の結果。
 * @note Policy、公式根拠とroutingはProvider workerが構成し、UI入力から作成してはならない。
 * @note 本関数は保持物を解放しない。呼出側が結果または例外の確定後に失効させる。
 */
[[nodiscard]] InstallResult executePreparedInfInstall(
	const PreparedInfInstallPolicy &policy, const PreparedInfInstallContext &context,
	std::span<const std::wstring> identities, const PreparedInfReverifier &reverifier,
	const OfficialInfRankAuditor &rankAuditor, const PreparedVerifiedInfInstaller &installer,
	std::uintptr_t parentWindowNative, const ProviderProgressCallback &progressCallback) ;

} // namespace drivercrate
