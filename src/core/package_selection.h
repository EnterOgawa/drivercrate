//------------------------------------------------------------------------------
/**
 * @file package_selection.h
 * @brief Provider package選択group定義。
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
 * @note 複数deviceが同一payloadを選択した場合の重複実行をProvider共通で防ぎます。Package IDはopaque値として扱い、URLや端末識別情報を解釈しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include <optional>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {

/**
 * @brief 一つのcandidateとProviderが検証したpackage IDの対応を表す。
 */
struct PackageSelectionEntry {
	/// Scan session内だけで有効な候補identity。
	std::wstring candidateIdentity ;
	/// 同一payloadを表すProvider固有opaque ID。
	std::wstring packageIdentity ;
} ;

/**
 * @brief 一回のdownload／installへまとめるcandidate群を表す。
 */
struct PackageSelectionGroup {
	/// Groupを識別するopaque package ID。
	std::wstring			  packageIdentity ;
	/// 元の選択順を維持する候補群。
	std::vector<std::wstring> candidateIdentities ;
} ;

/**
 * @brief Candidate選択を初出package順へまとめる。
 * Package初出順と各group内のcandidate選択順を維持する。
 * @param[in] entries Providerがscan時metadataから構築したcandidateとpackageの対応。 Candidateとpackageの検証済み対応。
 * @return 正常時は重複packageをまとめたgroup。空値またはcandidate重複時は`std::nullopt`。 正常時はgroup集合。不正identityまたは
 *         package時は空。
 */
[[nodiscard]] std::optional<std::vector<PackageSelectionGroup>> groupPackageSelection(
	std::span<const PackageSelectionEntry> entries) ;

} // namespace drivercrate
