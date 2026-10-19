//------------------------------------------------------------------------------
/**
 * @file windows_update_provider_tests.cpp
 * @brief Windows Update Provider単体試験実装。
 * @version 01.01.00
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
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  WUA／WSUS既定service選択の回帰試験を追加。
 * </pre>
 *
 * @note 実Windows Updateへ接続せず、表示前のfirmware除外条件を検証します。
 */
//------------------------------------------------------------------------------

#include "windows_update_provider_tests.h"

#include "platform/windows_update_provider.h"
#include "test_framework.h"

#include <string>

namespace drivercrate::test {

//------------------------------------------------------------------------------
/**
 * @see tests/unit/windows_update_provider_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runWindowsUpdateProviderTests( TestContext &context)
{
	DRIVERCRATE_EXPECT( context, windowsUpdateServerSelection() == ssDefault) ;
	DRIVERCRATE_EXPECT( context, isWuaDriverCandidateAllowed( L"Display", L"Test Display Driver")) ;
	DRIVERCRATE_EXPECT( context, isWuaDriverCandidateAllowed( L"System", L"Test Interface Driver")) ;
	DRIVERCRATE_EXPECT( context, !isWuaDriverCandidateAllowed( L"", L"Test Driver")) ;
	DRIVERCRATE_EXPECT( context, !isWuaDriverCandidateAllowed( L"Display", L"")) ;
	DRIVERCRATE_EXPECT( context, !isWuaDriverCandidateAllowed( L"Firmware", L"Test Update")) ;
	DRIVERCRATE_EXPECT( context, !isWuaDriverCandidateAllowed( L"System Firmware", L"Test Update")) ;
	DRIVERCRATE_EXPECT( context, !isWuaDriverCandidateAllowed( L"System", L"Test - UEFI - Update")) ;
	DRIVERCRATE_EXPECT( context, !isWuaDriverCandidateAllowed( L"System", L"Test BIOS Update")) ;
	DRIVERCRATE_EXPECT( context, !isWuaDriverCandidateAllowed( L"System", L"Test FiRmWaRe Update")) ;
	const std::wstring oversizedClass( 4097U, L'A') ;	// WUA metadata上限を超えるclass。
	DRIVERCRATE_EXPECT( context, !isWuaDriverCandidateAllowed( oversizedClass, L"Test Driver")) ;
}

} // namespace drivercrate::test
