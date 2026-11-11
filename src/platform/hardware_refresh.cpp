//------------------------------------------------------------------------------
/**
 * @file hardware_refresh.cpp
 * @brief 一時権限を元へ戻すWindows root再検出を実装します。
 * @version 01.00.01
 * @date 2026/10/28
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/28  一回の同期再検出と完全fake境界を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 *
 * @note 同期APIからの復帰を待ち、無条件retryとdriver導入完了の推測は行いません。
 * @see docs/adr/0419-hardware-refresh-before-update-search.md
 */
//------------------------------------------------------------------------------
#include "platform/hardware_refresh_internal.h"
#include <Windows.h>
#include <cfgmgr32.h>
#include <memory>

namespace drivercrate {
namespace {
using hardware_refresh_detail::Transport ;
// Production入口だけが参照する固定表です。
const Transport NATIVE_CALLS{GetCurrentProcess,		OpenProcessToken,	LookupPrivilegeValueW,
							 AdjustTokenPrivileges, GetLastError,		SetLastError,
							 CloseHandle,			CM_Locate_DevNodeW, CM_Reenumerate_DevNode} ;

/** @brief 所有tokenを、その取得に使用した同じ低位表で閉じます。 */
struct TokenCloser {
	/// 閉鎖完了まで借用する低位表です。
	const Transport *calls{} ;
	/**
	 * @brief 所有tokenを閉じます。
	 * @param[in] token 非nullの所有HANDLEです。
	 */
	void			 operator()( void *token) const noexcept
	{
		static_cast<void>( calls->closeToken( token)) ;
	}
} ;

//------------------------------------------------------------------------------
/**
 * @brief 権限有効化後にlocal root再検出を一回実行します。
 * @param[in] calls 呼出し期間中有効な完全表です。
 * @return 元CONFIGRETを維持した再検出結果です。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HardwareRefreshResult reenumerateRoot( const Transport &calls) noexcept
{
	DEVINST			root{} ;	// この呼出しだけのlocal root HANDLE値です。
	const CONFIGRET located =
		// 元値です。
		calls.locateRoot( &root, nullptr, CM_LOCATE_DEVNODE_NORMAL) ;
	// Root不明のまま再検出を実行しません。
	if( located != CR_SUCCESS) {
		return {false, HardwareRefreshStage::LOCATE_ROOT,
				HardwareRefreshErrorDomain::CONFIGURATION_MANAGER,
				static_cast<NativeError>( located)} ;
	}

	const CONFIGRET refreshed =
		// 一回だけです。
		calls.reenumerate( root, CM_REENUMERATE_SYNCHRONOUS) ;
	return {refreshed == CR_SUCCESS, HardwareRefreshStage::REENUMERATE,
			refreshed == CR_SUCCESS ? HardwareRefreshErrorDomain::NONE
									: HardwareRefreshErrorDomain::CONFIGURATION_MANAGER,
			static_cast<NativeError>( refreshed)} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元token属性を保存・復帰してroot再検出を行います。
 * @param[in] calls 全APIを持ち、戻るまで有効な表です。
 * @return 主失敗と復帰失敗を分離した結果です。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HardwareRefreshResult performRefresh( const Transport &calls) noexcept
{
	HANDLE rawToken{} ;	// 成功後はRAIIへ所有権を移します。
	// 現process tokenを開けない場合は権限変更やCM APIを呼びません。
	if( !calls.openToken( calls.process(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &rawToken)) {
		return {false, HardwareRefreshStage::OPEN_TOKEN, HardwareRefreshErrorDomain::WINDOWS_ERROR,
				static_cast<NativeError>( calls.lastError())} ;
	}

	const std::unique_ptr<void, TokenCloser> token{rawToken,
												   TokenCloser{&calls}} ;	// 所有tokenです。
	TOKEN_PRIVILEGES						 requested{} ;					// 一権限だけを有効化する固定要求です。
	requested.PrivilegeCount		   = 1U ;
	requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED ;
	// 名前照会失敗ではtokenの状態を変更しません。
	if( !calls.lookupPrivilege( nullptr, SE_LOAD_DRIVER_NAME, &requested.Privileges[0].Luid)) {
		return {false, HardwareRefreshStage::ENABLE_PRIVILEGE,
				HardwareRefreshErrorDomain::WINDOWS_ERROR,
				static_cast<NativeError>( calls.lastError())} ;
	}

	TOKEN_PRIVILEGES previous{} ;	// 実際に変更された一権限だけの元属性です。
	DWORD			 returned{} ;	// PreviousStateの実必要byte数です。
	calls.setError( ERROR_SUCCESS) ;
	const BOOL adjusted =
		calls.adjustPrivilege( token.get(), FALSE, &requested, sizeof( previous), &previous,
							  &returned) ;				// BOOL成功だけでは権限保有を確定しません。
	const DWORD			  error = calls.lastError() ;	// 別APIより先に元値を保持します。
	HardwareRefreshResult result{false, HardwareRefreshStage::ENABLE_PRIVILEGE,
								 HardwareRefreshErrorDomain::WINDOWS_ERROR,
								 // 失敗を元領域のまま保持します。
								 static_cast<NativeError>( error)} ;
	// 権限付与が完全成功した場合だけCMへ進みます。
	if( adjusted && error == ERROR_SUCCESS) {
		result = reenumerateRoot( calls) ;
	}

	// 実際に変更された属性だけを元に戻し、元から有効な権限を無効化しません。
	if( adjusted && previous.PrivilegeCount != 0U) {
		calls.setError( ERROR_SUCCESS) ;
		const BOOL	restored	 = calls.adjustPrivilege( token.get(), FALSE, &previous, 0U, nullptr,
														 nullptr) ;	// 元LUID/属性をそのまま返します。
		const DWORD restoreError = calls.lastError() ;				// 主失敗とは別に保存します。
		// 復帰不成立を同期再検出成功で隠しません。
		if( !restored || restoreError != ERROR_SUCCESS) {
			result.restoreError = static_cast<NativeError>(
				restoreError == ERROR_SUCCESS ? ERROR_GEN_FAILURE : restoreError) ;
			// 主処理が成功なら復帰失敗を主結果にも使用します。
			if( result.succeeded) {
				result.stage  = HardwareRefreshStage::RESTORE_PRIVILEGE ;
				result.domain = HardwareRefreshErrorDomain::WINDOWS_ERROR ;
				result.error  = result.restoreError ;
			}

			result.succeeded = false ;
		}
	}

	return result ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 既存token権限を一時使用し、local rootの同期再検出を一回実行します。
 * @return 元error領域・値と権限復帰結果。失敗時の自動retryはありません。
 * @note Blocking処理です。Productionの通常検索workerからだけ呼び、UIから呼びません。
 */
//------------------------------------------------------------------------------
HardwareRefreshResult refreshHardware() noexcept
{
	return performRefresh( NATIVE_CALLS) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実API不在の完全表で製品と同じ順序・権限復帰を実行します。
 * @param[in] calls 呼出し完了まで借用する完全fake表です。
 * @return 欠損/混在はE_INVALIDARGで失敗しAPIを一つも呼びません。
 */
//------------------------------------------------------------------------------
HardwareRefreshResult hardware_refresh_detail::Access::refresh( const Transport &calls) noexcept
{
	// 不完全表・native混在を呼出し前に拒否し、欠損APIを製品表で補いません。
	if( !calls.process || calls.process == NATIVE_CALLS.process || !calls.openToken ||
	   calls.openToken == NATIVE_CALLS.openToken || !calls.lookupPrivilege ||
	   calls.lookupPrivilege == NATIVE_CALLS.lookupPrivilege || !calls.adjustPrivilege ||
	   calls.adjustPrivilege == NATIVE_CALLS.adjustPrivilege || !calls.lastError ||
	   calls.lastError == NATIVE_CALLS.lastError || !calls.setError ||
	   calls.setError == NATIVE_CALLS.setError || !calls.closeToken ||
	   calls.closeToken == NATIVE_CALLS.closeToken || !calls.locateRoot ||
	   calls.locateRoot == NATIVE_CALLS.locateRoot || !calls.reenumerate ||
	   calls.reenumerate == NATIVE_CALLS.reenumerate) {
		return {false, HardwareRefreshStage::OPEN_TOKEN, HardwareRefreshErrorDomain::HRESULT_VALUE,
				static_cast<NativeError>( E_INVALIDARG)} ;
	}

	return performRefresh( calls) ;
}
} // namespace drivercrate
