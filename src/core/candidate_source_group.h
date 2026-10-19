//------------------------------------------------------------------------------
/**
 * @file candidate_source_group.h
 * @brief 同一版取得元候補group定義。
 * @version 01.00.00
 * @date 2026/09/02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  候補別既定選択根拠対応。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 明示版が完全一致する異なるProvider候補を関連付けます。候補行、package、install routingは統合せず、利用者が取得元を選択できる状態を維持します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstddef>
#include <optional>
#include <span>
#include <vector>

namespace drivercrate {

/**
 * @brief 同一device／同一版として関連付けた異なる取得元候補群を表す。
 */
struct CandidateSourceGroup {
	/// 元candidate vector内の取得元別index群。
	std::vector<std::size_t> candidateIndexes ;
	/// 既定選択する元candidate index。
	std::size_t				 preferredCandidateIndex{} ;
} ;

/**
 * @brief 明示版が完全一致する異なるProvider候補を取得元groupへまとめる。
 * 明示版が同じ異なるProvider候補を取得元groupへまとめる。
 * 行やroutingを削除せず、同一版内の既定取得元だけを決定する。
 * @param[in] candidates 集約済みscan候補。候補行と順序は変更しない。
 * @param[in] providers Stable IDと信頼境界を持つProvider registry。 Stable IDと信頼境界を持つregistry。
 * @return 正常時は初出順group。不正ID、重複候補、未知Provider時は`std::nullopt`。 正常時は初出順group。不正入力時は`std::nullopt`。
 * @note 現在版、選択不能、版欠損、操作なし、同一Provider内重複、操作分類不一致はgroup化しない。
 */
[[nodiscard]] std::optional<std::vector<CandidateSourceGroup>> groupEquivalentCandidateSources(
	std::span<const UpdateCandidate> candidates, std::span<const ProviderDescriptor> providers) ;

} // namespace drivercrate
