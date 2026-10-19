//------------------------------------------------------------------------------
/**
 * @file acquired_file_evidence_main.cpp
 * @brief 封印取得証拠の非通信・非導入試験を独立実行する。
 * @version 01.00.00
 * @date 2026/10/06
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  封印取得証拠の独立試験入口を追加。
 * </pre>
 *
 * @note 架空transportだけを用い、実通信・署名・PnP・導入を扱わない。
 * @see docs/adr/0273-session-sealed-acquired-file-evidence.md
 */
//------------------------------------------------------------------------------
#include "official_acquisition_tests.h"
#include "test_framework.h"

#include <iostream>

/**
 * @brief 封印取得証拠の所有権と失敗境界を検査する。
 * @return 全成功0、assertionまたは例外失敗1。
 */
int main()
{
	try {
		drivercrate::test::TestContext context ;	// 本processのassertion集計。
		drivercrate::test::runOfficialAcquiredFileEvidenceTests( context) ;
		std::cout << "Sealed acquisition assertions: " << context.assertionCount()
				  << ", failures: " << context.failureCount() << '\n' ;
		return context.failureCount() == 0 ? 0 : 1 ;
	} catch( ...) {
		// Raw path・URL・本文を出さず、失敗終了値で例外を保持する。
		std::cerr << "Sealed acquisition fixture failure.\n" ;
		return 1 ;
	}
}
