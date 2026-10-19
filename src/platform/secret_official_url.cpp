//------------------------------------------------------------------------------
/**
 * @file secret_official_url.cpp
 * @brief Record限定download grantの秘密URL所有型を実装します。
 * @version 01.00.00
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Move-only所有と破棄前消去を実装。
 * </pre>
 *
 * @note Windowsの最適化されない消去関数を使用し、本objectの所有範囲だけを消去します。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#include "platform/secret_official_url.h"

#include <Windows.h>

namespace drivercrate {

//------------------------------------------------------------------------------
// SecretOfficialUrl実装。
//------------------------------------------------------------------------------

SecretOfficialUrl::SecretOfficialUrl( std::wstring &&value) noexcept
{
	value_.swap( value) ;
	secureClear( value) ;
}

SecretOfficialUrl::~SecretOfficialUrl() noexcept
{
	clear() ;
}

SecretOfficialUrl::SecretOfficialUrl( SecretOfficialUrl &&other) noexcept
{
	value_.swap( other.value_) ;
	other.clear() ;
}

SecretOfficialUrl &SecretOfficialUrl::operator=( SecretOfficialUrl &&other) noexcept
{
	// 自己移動では現在の秘密値を維持し、同じbufferを誤って消去しない。
	if( this != &other) {
		clear() ;
		value_.swap( other.value_) ;
		other.clear() ;
	}

	return *this ;
}

void SecretOfficialUrl::replace( std::wstring &&value) noexcept
{
	clear() ;
	value_.swap( value) ;
	secureClear( value) ;
}

void SecretOfficialUrl::clear() noexcept
{
	secureClear( value_) ;
}

std::wstring_view SecretOfficialUrl::view() const noexcept
{
	return value_ ;
}

bool SecretOfficialUrl::empty() const noexcept
{
	return value_.empty() ;
}

void SecretOfficialUrl::secureClear( std::wstring &value) noexcept
{
	// 空文字列ではdataを変更せず、既に消去済みの状態だけを維持する。
	if( !value.empty()) {
		SecureZeroMemory( value.data(), value.size() * sizeof( wchar_t)) ;
	}

	value.clear() ;
}

} // namespace drivercrate
