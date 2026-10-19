//------------------------------------------------------------------------------
/**
 * @file maintenance_inf_structure_main.cpp
 * @brief 架空INFによる保守構造と既存package境界の非実行回帰を起動する。
 * @version 01.00.00
 * @date 2026/10/07
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/07  既存package回帰と保守構造の限定targetを追加。
 * </pre>
 *
 * @note 非通信の架空INF/CATだけを使用する。実device列挙・staging・導入は呼ばない。
 */
//------------------------------------------------------------------------------

#include "official_driver_package_tests.h"
#include "test_framework.h"

#include <iostream>

/**
 * @brief 架空INFの決定的回帰を起動し実行件数と失敗件数を表示する。
 * @return 全assertion成功0、例外または不一致1。
 */
int main()
{
	drivercrate::test::TestContext context ;	// このprocessだけの有限なassertion集計。
	try {
		drivercrate::test::runOfficialDriverPackageTests( context) ;
	} catch( ...) {
		std::cerr << "Synthetic INF structure fixture failed.\n" ;
		return 1 ;
	}

	std::cout << "Assertions: " << context.assertionCount()
			  << ", failures: " << context.failureCount() << '\n' ;
	return context.failureCount() == 0 ? 0 : 1 ;
}
