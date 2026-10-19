//------------------------------------------------------------------------------
/**
 * @file com_raii.h
 * @brief COM resource管理定義。
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
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note COM apartmentとBSTRのlifetimeを管理するRAII型を定義します。
 */
//------------------------------------------------------------------------------

#pragma once

#include <Windows.h>

#include <OleAuto.h>

#include <string_view>

namespace drivercrate {

//------------------------------------------------------------------------------
// Resource管理型定義。
//------------------------------------------------------------------------------

/**
 * @brief 現在 thread の COM 初期化と解放を対にする。
 */
class ComApartment final {
public:
	/**
     * @brief 指定した apartment model で COM を初期化する。
     * @param[in] concurrencyModel `CoInitializeEx` に渡す apartment model。
     */
	//------------------------------------------------------------------------------
	explicit ComApartment( const DWORD concurrencyModel) noexcept
		: result_( CoInitializeEx( nullptr, concurrencyModel)), initialized_( SUCCEEDED( result_))
	{
	}

	/**
     * @brief 初期化に成功していた場合だけ現在 thread の COM を解放する。
     */
	//------------------------------------------------------------------------------
	~ComApartment()
	{
		// このobjectが成功させたCOM初期化に対してだけ終了通知を行う。
		if( initialized_) {
			CoUninitialize() ;
		}
	}

	// 現在threadのCOM初期化回数を重複管理しないようcopy/moveを禁止する。
	/**
	 * @brief COM初期化に対応する終了責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	ComApartment( const ComApartment &) = delete ;
	/**
	 * @brief COM初期化に対応する終了責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	ComApartment &operator=( const ComApartment &) = delete ;
	/**
	 * @brief COM初期化に対応する終了責務を初期化したthreadのscopeに留めるため、移動構築を禁止する。
	 */
	ComApartment( ComApartment &&) = delete ;
	/**
	 * @brief 初期化したthreadのscopeへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	ComApartment		 &operator=( ComApartment &&) = delete ;

	/**
     * @brief `CoInitializeEx` の HRESULT を返す。
     * @return COM 初期化結果。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] HRESULT result() const noexcept
	{
		return result_ ;
	}

private:
	/// CoInitializeExが返した初期化結果。
	HRESULT result_ ;
	/// trueの場合だけdestructorでCoUninitializeを呼び出す。
	bool	initialized_ ;
} ;

/**
 * @brief `SysAllocStringLen` で確保した BSTR を所有する。
 */
class UniqueBstr final {
public:
	/**
     * @brief BSTR を所有しない空の object を作成する。
     */
	UniqueBstr() noexcept = default ;

	/**
     * @brief 指定文字列を複製した BSTR を作成する。
     * @param[in] value 複製元の UTF-16 文字列。
     */
	//------------------------------------------------------------------------------
	explicit UniqueBstr( const std::wstring_view value)
		: value_( SysAllocStringLen( value.data(), static_cast<UINT>( value.size())))
	{
	}

	/**
     * @brief 所有中の BSTR を解放する。
     */
	//------------------------------------------------------------------------------
	~UniqueBstr()
	{
		SysFreeString( value_) ;
	}

	// 同一BSTRを重複解放しないようcopyを禁止する。
	/**
	 * @brief BSTRの解放責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	UniqueBstr( const UniqueBstr &) = delete ;
	/**
	 * @brief BSTRの解放責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	UniqueBstr &operator=( const UniqueBstr &) = delete ;

	/**
     * @brief 別 object から BSTR ownership を移動する。
     * @param[in,out] other 移動後に空になる object。
     */
	//------------------------------------------------------------------------------
	UniqueBstr( UniqueBstr &&other) noexcept : value_( other.release())
	{
	}

	/**
     * @brief 現在値を解放し、別 object から BSTR ownership を移動する。
     * @param[in,out] other 移動後に空になる object。
     * @return この object への参照。
     */
	//------------------------------------------------------------------------------
	UniqueBstr &operator=( UniqueBstr &&other) noexcept
	{
		// 自己moveで保持中BSTRを解放してしまわないよう別objectの場合だけ移動する。
		if( this != &other) {
			reset( other.release()) ;
		}

		return *this ;
	}

	/**
     * @brief 所有 BSTR を返す。
     * @return 所有していない BSTR view。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] BSTR get() const noexcept
	{
		return value_ ;
	}

	/**
     * @brief COM getter が新しい BSTR を格納する address を返す。
     * @return 空の所有 slot の address。
     * @pre 呼出し前にこの object が BSTR を所有していないこと。
     * COM getter が新しい BSTR を格納する address を返す。事前条件: 呼出し前にこの object が BSTRを所有していないこと。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] BSTR *put() noexcept
	{
		reset() ;
		return &value_ ;
	}

	/**
     * @brief 現在の BSTR ownership を放棄する。
     * @return 呼出し側が解放責任を引き継ぐ BSTR。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] BSTR release() noexcept
	{
		BSTR released = value_ ;	// 呼出し側へownershipを移すBSTR。
		value_		  = nullptr ;
		return released ;
	}

	/**
     * @brief 現在値を解放して新しい BSTR を所有する。
     * @param[in] value 新しく所有する BSTR。
     */
	//------------------------------------------------------------------------------
	void reset( BSTR value = nullptr) noexcept
	{
		// 同じBSTRの再設定では解放せず、異なる所有値へ変更する場合だけ旧値を解放する。
		if( value_ != value) {
			SysFreeString( value_) ;
			value_ = value ;
		}
	}

private:
	/// SysFreeStringで解放する所有BSTR。空の場合はnullptr。
	BSTR value_{} ;
} ;

} // namespace drivercrate
