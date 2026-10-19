//------------------------------------------------------------------------------
/**
 * @file windows_error.h
 * @brief Windows error表示定義。
 * @version 01.00.00
 * @date 2026/09/01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Native errorを秘密情報なしで表示するhelperを定義します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <string>

namespace drivercrate {

/**
 * @brief native error を固定幅 hexadecimal code と system message に整形する。
 * native errorを固定幅codeとsystem messageへ整形する。
 * native errorを利用者向けの診断文字列へ整形します。文字列構築に失敗した場合は固定のfallback文字列を返します。
 * @param[in] error HRESULT または Win32 error の 32-bit 値。 HRESULTまたはWin32 errorの32-bit値。
 * @return 例外を投げずに表示可能な文字列。 例外を外へ漏らさない固定幅codeとsystem messageの文字列。
 */
[[nodiscard]] std::wstring formatNativeError( NativeError error) noexcept ;

} // namespace drivercrate
