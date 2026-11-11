//------------------------------------------------------------------------------
/**
 * @file windows_error.cpp
 * @brief Windows error表示実装。
 * @version 01.00.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  関数comment形式統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 *
 * @note HRESULTまたはWin32 errorを秘密情報を含まない表示文字列へ変換します。
 */
//------------------------------------------------------------------------------

#include "platform/windows_error.h"

#include <Windows.h>

#include <array>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

namespace drivercrate {

//------------------------------------------------------------------------------
// 公開関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief native error を固定幅 hexadecimal code と system message に整形する。native errorを固定幅codeとsystem
 *        messageへ整形する。native errorを利用者向けの診断文字列へ整形します。文字列構築に失敗した場合は固定のfallback文字列を返します。
 * @param[in] error HRESULT または Win32 error の 32-bit 値。 HRESULTまたはWin32 errorの32-bit値。
 * @return 例外を投げずに表示可能な文字列。 例外を外へ漏らさない固定幅codeとsystem messageの文字列。
 */
//------------------------------------------------------------------------------
std::wstring formatNativeError( const NativeError error) noexcept
{
	try {
		constexpr DWORD MESSAGE_BUFFER_CHARACTERS = 1024 ;			// System message最大UTF-16文字数。
		std::array<wchar_t, MESSAGE_BUFFER_CHARACTERS> message{} ;	// FormatMessage受信領域。
		// Insertを解釈せずOS登録済みmessageだけを取得するflag。
		const DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS ;
		// 終端nullを除いて取得したUTF-16文字数。失敗時は0。
		const DWORD length =
			FormatMessageW( flags, nullptr, static_cast<DWORD>( error), 0, message.data(),
						   static_cast<DWORD>( message.size()), nullptr) ;

		std::wstring messageText ;	// 末尾改行を除いたOS system message。
		// System message を取得できた場合だけ、API 由来の末尾改行を除いて保持する。
		if( length > 0) {
			messageText.assign( message.data(), length) ;

			// FormatMessage が付加する改行だけを除き、本文中の文字は変更しない。
			while( !messageText.empty() &&
				  (messageText.back() == L'\r' || messageText.back() == L'\n')) {
				messageText.pop_back() ;
			}
		}

		std::wostringstream output ;	// 固定幅codeとsystem messageを構築するstream。
		output << L"0x" << std::uppercase << std::hex << std::setw( 8) << std::setfill( L'0')
			   << static_cast<std::uint32_t>( error) ;
		// System message が存在する場合だけ診断 code に説明を付加する。
		if( !messageText.empty()) {
			output << L" - " << messageText ;
		}

		return output.str() ;
	} catch( ...) {
		// 診断文字列の確保失敗を application boundary から例外として漏らさない。
		return L"エラーコードを表示できませんでした。" ;
	}
}

} // namespace drivercrate
