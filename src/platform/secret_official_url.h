//------------------------------------------------------------------------------
/**
 * @file secret_official_url.h
 * @brief Record限定download grantの秘密URL所有型を定義します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Move-only秘密URL所有型を追加。
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note Provider worker thread内だけで所有し、URLをcore DTO、UI、log、cacheまたは例外文へ渡しません。
 *       C++ runtimeやHTTP stackが内部で作る一時copyの消去は保証せず、本型が所有する有効文字列だけを
 *       破棄・置換前に消去します。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#pragma once

#include <string>
#include <string_view>

namespace drivercrate {

//------------------------------------------------------------------------------
// 秘密URL所有型定義。
//------------------------------------------------------------------------------

/**
 * @brief 一つの公式recordから得たdownload URLをcopy禁止で所有します。
 * @note 一objectは同じProvider worker threadだけで使用します。Stream出力、比較、暗黙変換は提供しません。
 */
class SecretOfficialUrl final {
public:
	/**
	 * @brief 秘密値を持たないobjectを作成します。
	 * @post `empty()`はtrueです。
	 */
	SecretOfficialUrl() noexcept = default ;

	/**
	 * @brief 呼出し側が移動した文字列bufferを秘密値として引き取ります。
	 * @param[in] value Provider worker内で構築したURL。引数objectは本呼出しで消費します。
	 * @post `view()`は移動前のvalueと同じ文字列を参照します。
	 * @note URLの妥当性や公式由来は検証せず、所有権だけを制限します。
	 */
	explicit SecretOfficialUrl( std::wstring &&value) noexcept ;

	/**
	 * @brief 所有するURL文字列を消去して解放します。
	 */
	~SecretOfficialUrl() noexcept ;

	/**
	 * @brief 秘密URL文字列の所有状態の二重管理を防ぐため、コピー構築を禁止する。
	 */
	SecretOfficialUrl( const SecretOfficialUrl &) = delete ;
	/**
	 * @brief 秘密URL文字列の所有状態を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	SecretOfficialUrl &operator=( const SecretOfficialUrl &) = delete ;

	/**
	 * @brief 別objectの秘密URL所有権を移動します。
	 * @param[in,out] other 所有権を失い空になる移動元。
	 * @post `other.empty()`はtrueです。
	 */
	SecretOfficialUrl( SecretOfficialUrl &&other) noexcept ;

	/**
	 * @brief 現在値を消去して別objectの秘密URL所有権を移動します。
	 * @param[in,out] other 所有権を失い空になる移動元。自己代入も許可します。
	 * @return このobjectへの参照。
	 * @post 自己代入でない場合、`other.empty()`はtrueです。
	 */
	SecretOfficialUrl			   &operator=( SecretOfficialUrl &&other) noexcept ;

	/**
	 * @brief 現在値を消去し、呼出し側が移動した文字列bufferへ置き換えます。
	 * @param[in] value Provider worker内で構築した新しいURL。引数objectは本呼出しで消費します。
	 * @post `view()`は移動前のvalueと同じ文字列を参照します。
	 */
	void							replace( std::wstring &&value) noexcept ;

	/**
	 * @brief 所有する有効文字を消去し、空の状態へ戻します。
	 * @post `empty()`はtrueです。
	 */
	void							clear() noexcept ;

	/**
	 * @brief HTTP境界が呼出し中だけ借用できるURL viewを返します。
	 * @return 次の非const操作またはobject破棄まで有効な非所有view。
	 * @warning 戻り値を保存、表示、記録または例外文へ複写してはなりません。
	 */
	[[nodiscard]] std::wstring_view view() const noexcept ;

	/**
	 * @brief 秘密URLが設定されていないか確認します。
	 * @return 有効文字が0文字の場合true。
	 */
	[[nodiscard]] bool				empty() const noexcept ;

private:
	/**
	 * @brief 一つの所有文字列の有効領域をWindowsのsecure eraseで消去します。
	 * @param[in,out] value 消去して空にする文字列。
	 * @post `value.empty()`はtrueです。
	 */
	static void	 secureClear( std::wstring &value) noexcept ;

	/// Provider worker内だけで保持する完全なdownload URL。
	std::wstring value_ ;
} ;

} // namespace drivercrate
