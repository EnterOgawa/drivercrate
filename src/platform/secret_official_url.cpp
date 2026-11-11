//------------------------------------------------------------------------------
/**
 * @file secret_official_url.cpp
 * @brief Record限定download grantの秘密URL所有型を実装します。
 * @version 01.00.01
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
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
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

//------------------------------------------------------------------------------
/**
 * @brief 呼出し側が移動した文字列bufferを秘密値として引き取ります。
 * @param[in] value Provider worker内で構築したURL。引数objectは本呼出しで消費します。
 * @post `view()`は移動前のvalueと同じ文字列を参照します。
 * @note URLの妥当性や公式由来は検証せず、所有権だけを制限します。
 */
//------------------------------------------------------------------------------
SecretOfficialUrl::SecretOfficialUrl( std::wstring &&value) noexcept
{
	value_.swap( value) ;
	secureClear( value) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 所有するURL文字列を消去して解放します。
 */
//------------------------------------------------------------------------------
SecretOfficialUrl::~SecretOfficialUrl() noexcept
{
	clear() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 別objectの秘密URL所有権を移動します。
 * @param[in,out] other 所有権を失い空になる移動元。
 * @post `other.empty()`はtrueです。
 */
//------------------------------------------------------------------------------
SecretOfficialUrl::SecretOfficialUrl( SecretOfficialUrl &&other) noexcept
{
	value_.swap( other.value_) ;
	other.clear() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在値を消去して別objectの秘密URL所有権を移動します。
 * @param[in,out] other 所有権を失い空になる移動元。自己代入も許可します。
 * @return このobjectへの参照。
 * @post 自己代入でない場合、`other.empty()`はtrueです。
 */
//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
/**
 * @brief 現在値を消去し、呼出し側が移動した文字列bufferへ置き換えます。
 * @param[in] value Provider worker内で構築した新しいURL。引数objectは本呼出しで消費します。
 * @post `view()`は移動前のvalueと同じ文字列を参照します。
 */
//------------------------------------------------------------------------------
void SecretOfficialUrl::replace( std::wstring &&value) noexcept
{
	clear() ;
	value_.swap( value) ;
	secureClear( value) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 所有する有効文字を消去し、空の状態へ戻します。
 * @post `empty()`はtrueです。
 */
//------------------------------------------------------------------------------
void SecretOfficialUrl::clear() noexcept
{
	secureClear( value_) ;
}

//------------------------------------------------------------------------------
/**
 * @brief HTTP境界が呼出し中だけ借用できるURL viewを返します。
 * @return 次の非const操作またはobject破棄まで有効な非所有view。
 * @warning 戻り値を保存、表示、記録または例外文へ複写してはなりません。
 */
//------------------------------------------------------------------------------
std::wstring_view SecretOfficialUrl::view() const noexcept
{
	return value_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 秘密URLが設定されていないか確認します。
 * @return 有効文字が0文字の場合true。
 */
//------------------------------------------------------------------------------
bool SecretOfficialUrl::empty() const noexcept
{
	return value_.empty() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つの所有文字列の有効領域をWindowsのsecure eraseで消去します。
 * @param[in,out] value 消去して空にする文字列。
 * @post `value.empty()`はtrueです。
 */
//------------------------------------------------------------------------------
void SecretOfficialUrl::secureClear( std::wstring &value) noexcept
{
	// 空文字列ではdataを変更せず、既に消去済みの状態だけを維持する。
	if( !value.empty()) {
		SecureZeroMemory( value.data(), value.size() * sizeof( wchar_t)) ;
	}

	value.clear() ;
}

} // namespace drivercrate
