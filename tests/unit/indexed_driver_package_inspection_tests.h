//------------------------------------------------------------------------------
/**
 * @file indexed_driver_package_inspection_tests.h
 * @brief 索引hint結合の架空回帰入口。
 * @version 01.00.00
 * @date 2026/10/05
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/05  索引hintと通常検査の非導入接続を追加。
 * </pre>
 *
 * @note 実driver・実署名・network・導入へ依存しない。
 * @see docs/adr/0262-index-hint-to-acquired-package-inspection.md
 */
//------------------------------------------------------------------------------

#pragma once

namespace drivercrate::test {

class TestContext ;

/**
 * @brief 索引hintのidentity・取消し・架空byte拒否を検証する。
 * @param[in,out] context 呼出し側が所有するassertion集計。
 */
void runIndexedDriverPackageInspectionTests( TestContext &context) ;

} // namespace drivercrate::test
