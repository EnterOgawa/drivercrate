//------------------------------------------------------------------------------
/**
 * @file package_selection_tests.cpp
 * @brief Package選択group単体試験実装。
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
 * @note 実installerを起動せず、opaque package IDのgroup化だけを試験します。
 */
//------------------------------------------------------------------------------

#include "package_selection_tests.h"

#include "core/package_selection.h"
#include "test_framework.h"

#include <array>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
/**
 * @brief 同一packageのcandidateを一つのgroupへまとめることを検証する。
 *
 * Package初出順とgroup内のcandidate選択順を確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testGrouping( TestContext &context)
{
	// 複数候補で共有するpayloadを一groupへまとめる正常入力。
	const std::array entries{
		PackageSelectionEntry{.candidateIdentity = L"device-a", .packageIdentity = L"dup-1"},
		PackageSelectionEntry{.candidateIdentity = L"device-b", .packageIdentity = L"dup-2"},
		PackageSelectionEntry{.candidateIdentity = L"device-c", .packageIdentity = L"dup-1"}} ;
	const auto groups = groupPackageSelection( entries) ;	// 重複packageを含む選択結果。
	DRIVERCRATE_EXPECT( context, groups.has_value()) ;
	DRIVERCRATE_EXPECT( context, groups->size() == 2) ;
	DRIVERCRATE_EXPECT( context, (*groups)[0].packageIdentity == L"dup-1") ;
	DRIVERCRATE_EXPECT( context, (*groups)[0].candidateIdentities.size() == 2) ;
	DRIVERCRATE_EXPECT( context, (*groups)[0].candidateIdentities[0] == L"device-a") ;
	DRIVERCRATE_EXPECT( context, (*groups)[0].candidateIdentities[1] == L"device-c") ;
	DRIVERCRATE_EXPECT( context, (*groups)[1].packageIdentity == L"dup-2") ;
	DRIVERCRATE_EXPECT( context, (*groups)[1].candidateIdentities[0] == L"device-b") ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不正なpackage選択を拒否することを検証する。
 *
 * 空集合、空ID、candidate重複をfail-closedで拒否する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testInvalidEntries( TestContext &context)
{
	// 選択0件の境界を確認する空の入力集合。
	const std::vector<PackageSelectionEntry> empty ;
	DRIVERCRATE_EXPECT( context, !groupPackageSelection( empty).has_value()) ;

	// Package identityが欠けた選択を拒否する入力。
	const std::array missingPackage{
		PackageSelectionEntry{.candidateIdentity = L"device-a", .packageIdentity = L""}} ;
	DRIVERCRATE_EXPECT( context, !groupPackageSelection( missingPackage).has_value()) ;

	// 同じ候補が別packageへ重複登録された場合の拒否用入力。
	const std::array duplicateCandidate{
		PackageSelectionEntry{.candidateIdentity = L"device-a", .packageIdentity = L"dup-1"},
		PackageSelectionEntry{.candidateIdentity = L"device-a", .packageIdentity = L"dup-2"}} ;
	DRIVERCRATE_EXPECT( context, !groupPackageSelection( duplicateCandidate).has_value()) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/package_selection_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runPackageSelectionTests( TestContext &context)
{
	testGrouping( context) ;
	testInvalidEntries( context) ;
}

} // namespace drivercrate::test
