//------------------------------------------------------------------------------
/**
 * @file windows_update_identity_internal.h
 * @brief WUAの原UUID全長を非ProgID parserへ限定します
 * @version 01.00.00
 * @date 2026/11/13
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/13  新規作成
 * </pre>
 *
 * @note 原BSTR/query/revisionを変更せず、任意ProgIDを解決しません
 * @see docs/adr/0491-typed-system-needs-effects-and-complete-selection-qualification.md
 */
//------------------------------------------------------------------------------
#pragma once
#include <Windows.h>
#include <combaseapi.h>
#include <string>
#include <string_view>

namespace drivercrate::windows_update_detail {
//------------------------------------------------------------------------------
/**
 * @brief 原UUID全36又は38文字を厳密に消費し非ProgID APIで検証します
 * @param[in] value SysStringLen等で得た元全長です。埋込NULも切り捨てません
 * @param[out] result 成功時のGUIDです。失敗時は零です
 * @return 厳密なASCII UUID成功S_OK、不正形E_INVALIDARG又は元IID parserのHRESULTです
 * @note 括弧補完は検証用copyだけで、元queryへ渡す文字列は変更しません
 */
//------------------------------------------------------------------------------
inline HRESULT parseIdentity( std::wstring_view value, GUID &result)
{
	result = {} ;
	// 対応括弧以外のprefix/suffixを読み飛ばしません
	if( value.size() == 38U && value.front() == L'{' && value.back() == L'}') {
		value = value.substr( 1U, 36U) ;
	}
	// 後続の別型/文脈だけを判定し、未確認を既定へ変換しません
	else if( value.size() != 36U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
		return E_INVALIDARG ;
	}

	// 全桁が固定hyphen又はASCII hexであることを要求します
	for( std::size_t index = 0U; index < value.size(); ++index) {
		const auto c	  = value[index] ;	// 元field/型の全消費を確認する局所位置又は閉じた分類です
		const bool hyphen = index == 8U || index == 13U || index == 18U ||
							// 元field/型の全消費を確認する局所位置又は閉じた分類です
							index == 23U ;
		// NUL/Unicode桁/空白/ProgIDを別名へ解決しません
		if( hyphen ? c != L'-'
				  : !((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') ||
					  (c >= L'A' && c <= L'F'))) {
			return E_INVALIDARG ;
		}
	}

	const std::wstring parsed = L"{" + std::wstring{value} +
								L"}" ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
	return IIDFromString( parsed.c_str(), &result) ;
}
} // namespace drivercrate::windows_update_detail
