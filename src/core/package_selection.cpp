//------------------------------------------------------------------------------
/**
 * @file package_selection.cpp
 * @brief Provider package選択group実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Candidate選択を初出package順へ決定的にgroup化します。
 */
//------------------------------------------------------------------------------

#include "core/package_selection.h"

#include <unordered_map>
#include <unordered_set>

namespace drivercrate {

//------------------------------------------------------------------------------
/**
 * @see src/core/package_selection.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::optional<std::vector<PackageSelectionGroup>> groupPackageSelection(
	const std::span<const PackageSelectionEntry> entries)
{
	// 空選択から実行用package集合を作らず、対象なしを明示して返す。
	if( entries.empty()) {
		return std::nullopt ;
	}

	std::vector<PackageSelectionGroup> groups ;	// 初出package順の戻り値。
	groups.reserve( entries.size()) ;
	std::unordered_map<std::wstring, std::size_t> packageIndexes ;		// Package別group index。
	std::unordered_set<std::wstring>			  candidateIdentities ;	// Candidate重複検出集合。
	// 選択順に全候補を一度ずつ検証し、同じpackageを初出の一つの実行枠へまとめる。
	for( const PackageSelectionEntry &entry : entries) {
		// 候補やpackageのID欠落と重複選択を拒否し、取得・実行単位の照合を保つ。
		if( entry.candidateIdentity.empty() || entry.packageIdentity.empty() ||
		   !candidateIdentities.insert( entry.candidateIdentity).second) {
			return std::nullopt ;
		}

		// packageは共有payload groupの位置、insertedは初出としてgroup作成が必要な場合true。
		const auto [package, inserted] =
			packageIndexes.try_emplace( entry.packageIdentity, groups.size()) ;
		// 初めて選ばれたpackageだけに実行枠を作り、複数deviceへの同じ本体を一回へまとめる。
		if( inserted) {
			groups.push_back( {.packageIdentity = entry.packageIdentity}) ;
		}

		groups[package->second].candidateIdentities.push_back( entry.candidateIdentity) ;
	}

	return groups ;
}

} // namespace drivercrate
