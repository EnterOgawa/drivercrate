//------------------------------------------------------------------------------
/**
 * @file collector_setup_admission.h
 * @brief 既存native writerと全旧requestの非共有作用域を保持します。
 * @version 01.00.00
 * @date 2026/10/17
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/17 非作成writerと全旧request射影を接続。
 * </pre>
 *
 * @note 単一setup監督が同期使用し、通信や共有native予算の予約を行いません。
 * @see docs/adr/0357-collector-explicit-run-and-system-transport.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "local_collector_legacy.h"
#include "local_collector_state_store.h"

#include <Windows.h>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace drivercrate {

/** @brief 子終了までnative writerと検証済み旧作用域を所有します。 */
struct CollectorSetupAdmission {
	/// 非作成で取得した排他writer。最後のowner破棄まで保持します。
	std::shared_ptr<LocalCollectorStateStore> store ;
	/// 全旧run・pointer・cooldownの検証済み観測です。
	CollectorLegacySnapshot					  snapshot ;
	/// GETとactual URLを同じ式でhashした非共有比較集合です。
	std::vector<std::wstring>				  requestHashes ;
	/// 全native requestのactual hostをhashしたgroup footprintです。
	std::vector<std::wstring>				  hostHashes ;
} ;

/** @brief 既存保護storeを非作成でlockし、全旧v4作用域を検査します。
 * @param[in] root 既存native専用rootの正規絶対path。
 * @param[in] utcMillis 信頼するOS時計のUTC millisecond。
 * @param[out] admission 成功時だけの所有leaseと全作用域。失敗時は空です。
 * @param[out] reason 拒否時の固定理由。URLやpathを含めません。
 * @return 成功0、未知mode／破損13、競合などは元Win32 error。
 * @note campaign・segmented・未知予約を部分検査で許可しません。実HTTPは行いません。
 */
[[nodiscard]] DWORD acquireCollectorSetupAdmission( const std::filesystem::path &root,
												   std::uint64_t				utcMillis,
												   CollectorSetupAdmission	   &admission,
												   std::wstring				   &reason) noexcept ;

} // namespace drivercrate
