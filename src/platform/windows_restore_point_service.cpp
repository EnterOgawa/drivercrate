//------------------------------------------------------------------------------
/**
 * @file windows_restore_point_service.cpp
 * @brief Windows復元ポイントサービス実装。
 * @version 01.00.02
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
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * Ver.01.00.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note MicrosoftのSystem Restore契約に従いCOM securityを初期化し、SrClient.dllのSRSetRestorePointWを動的に呼び出します。
 *       System Restore無効、Safe Mode、非対応OSでは変更を行わず失敗を返します。
 */
//------------------------------------------------------------------------------

#include "platform/windows_restore_point_service.h"

#include <AccCtrl.h>
#include <AclAPI.h>
#include <ObjBase.h>
#include <SrRestorePtApi.h>
#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 内部定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t SID_COUNT = 5U ;	// COM callbackを許可するwell-known SID数。
constexpr std::size_t SID_WORD_COUNT =
	(SECURITY_MAX_SID_SIZE + sizeof( ULONGLONG) - 1U) / sizeof( ULONGLONG) ;	// SID格納word数。

/**
 * @brief 最大長SIDのalignment付き格納領域。
 */
using SidBuffer = std::array<ULONGLONG, SID_WORD_COUNT> ;
/**
 * @brief 遅延解決したSRSetRestorePointWを、Windows標準の署名のまま呼び出す関数型。
 */
using SrSetRestorePointFunction = BOOL( WINAPI *)( PRESTOREPOINTINFOW, PSTATEMGRSTATUS) ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorを共通native error表現へ変換する。
 *
 * @param[in] error GetLastErrorまたはWin32 APIが返した値。
 * @return HRESULTへ変換した32-bit error bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError win32Error( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief System Restore statusを失敗native errorへ変換する。
 *
 * API失敗時にstatusが0でも成功値へ変換しないよう、ERROR_GEN_FAILUREへ正規化する。
 *
 * @param[in] status STATEMGRSTATUSが返したWin32 error。
 * @return 0以外のHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError restorePointError( const DWORD status) noexcept
{
	return win32Error( status == ERROR_SUCCESS ? ERROR_GEN_FAILURE : status) ;
}

//------------------------------------------------------------------------------
/**
 * @brief System Restore callbackに必要なprocess COM securityを設定する。
 *
 * LocalService、NetworkService、SELF、LocalSystem、Administratorsからのlocal COM callbackだけを許可する。Provider
 * COM object生成前のworker threadから一度だけ呼ぶ。
 * @return 成功時は0、失敗時はHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError initializeComSecurity() noexcept
{
	// MicrosoftのSystem Restore sampleが要求するSID順序。
	constexpr std::array<WELL_KNOWN_SID_TYPE, SID_COUNT> SID_TYPES{
		WinBuiltinAdministratorsSid, WinLocalServiceSid, WinNetworkServiceSid, WinSelfSid,
		WinLocalSystemSid} ;

	SECURITY_DESCRIPTOR securityDescriptor{} ;	// CoInitializeSecurityへ渡すabsolute descriptor。
	// COM security 用 descriptor の初期化失敗時は保護設定を中止する。
	if( InitializeSecurityDescriptor( &securityDescriptor, SECURITY_DESCRIPTOR_REVISION) == FALSE) {
		return win32Error( GetLastError()) ;
	}

	std::array<SidBuffer, SID_COUNT>		sidBuffers{} ;		// 各well-known SIDの固定格納領域。
	std::array<EXPLICIT_ACCESSW, SID_COUNT> accessEntries{} ;	// Local COM実行許可ACE群。

	// 全SIDを固定領域へ生成し、同じlocal execute権限のACEへ関連付ける。
	for( std::size_t index = 0; index < SID_COUNT; ++index) {
		DWORD sidSize = static_cast<DWORD>( sizeof( SidBuffer)) ;	// 現在SID bufferのbyte数。
		// 許可主体の well-known SID を作成できなければ ACL を構築しない。
		if( CreateWellKnownSid( SID_TYPES[index], nullptr, sidBuffers[index].data(), &sidSize) ==
		   FALSE) {
			return win32Error( GetLastError()) ;
		}

		EXPLICIT_ACCESSW &entry				   = accessEntries[index] ;	// 現在SIDへ設定するACE。
		entry.grfAccessPermissions			   = COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL ;
		entry.grfAccessMode					   = SET_ACCESS ;
		entry.grfInheritance				   = NO_INHERITANCE ;
		entry.Trustee.pMultipleTrustee		   = nullptr ;
		entry.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE ;
		entry.Trustee.TrusteeForm			   = TRUSTEE_IS_SID ;
		entry.Trustee.TrusteeType			   = TRUSTEE_IS_GROUP ;
		// Trustee APIがmutable文字pointerでSIDを受け取る境界であり、文字列として参照しない。
		entry.Trustee.ptstrName = reinterpret_cast<LPWSTR>( sidBuffers[index].data()) ;
	}

	PACL		accessControlList{} ;	// SetEntriesInAclWがLocalAllocし、本関数が解放するACL。
	const DWORD aclError =
		SetEntriesInAclW( static_cast<ULONG>( accessEntries.size()), accessEntries.data(), nullptr,
						 &accessControlList) ;	// ACL構築結果。
	// ACL 作成の失敗または出力欠落時は確保済み領域を解放して拒否する。
	if( aclError != ERROR_SUCCESS || accessControlList == nullptr) {
		LocalFree( accessControlList) ;
		return win32Error( aclError != ERROR_SUCCESS ? aclError : ERROR_INVALID_ACL) ;
	}

	NativeError result{} ;	// Descriptor設定またはCoInitializeSecurityの最終結果。
	// Descriptor の owner を設定できない場合はその失敗を保持する。
	if( SetSecurityDescriptorOwner( &securityDescriptor, sidBuffers[0].data(), FALSE) == FALSE) {
		result = win32Error( GetLastError()) ;
	}
	// Descriptor の group を設定できない場合は security 初期化を中止する。
	else if( SetSecurityDescriptorGroup( &securityDescriptor, sidBuffers[0].data(), FALSE) == FALSE) {
		result = win32Error( GetLastError()) ;
	}
	// 必要な DACL を設定できない場合は不完全な descriptor を使用しない。
	else if( SetSecurityDescriptorDacl( &securityDescriptor, TRUE, accessControlList, FALSE) ==
			FALSE) {
		result = win32Error( GetLastError()) ;
	} else {
		// System Restore service callbackだけに必要なlocal execution権限をprocessへ設定する。
		const HRESULT securityResult = CoInitializeSecurity(
			&securityDescriptor, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
			RPC_C_IMP_LEVEL_IDENTIFY, nullptr, EOAC_DISABLE_AAA | EOAC_NO_CUSTOM_MARSHAL,
			nullptr) ;	// COM設定結果。
		result = SUCCEEDED( securityResult) ? 0 : static_cast<NativeError>( securityResult) ;
	}

	LocalFree( accessControlList) ;
	return result ;
}

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief SrClient.dllを動的に使用して復元ポイントを開始・終了する。
 */
class WindowsRestorePointService final : public IRestorePointService {
public:
	/**
	 * @brief COM securityとSrClient.dll entry pointを初期化する。
	 * Provider COM object生成前にprocess-wide securityを設定し、API利用不能時は後続beginをfail-closedにする。
	 */
	WindowsRestorePointService() noexcept ;

	/**
	 * @brief 読み込んだSrClient.dllを解放する。
	 */
	~WindowsRestorePointService() override ;

	// DLL handleを単独所有するためcopy/moveを禁止する。
	/**
	 * @brief SrClient.dllの解放責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	WindowsRestorePointService( const WindowsRestorePointService &) = delete ;
	/**
	 * @brief SrClient.dllの解放責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	WindowsRestorePointService &operator=( const WindowsRestorePointService &) = delete ;
	/**
	 * @brief SrClient.dllの解放責務を読み込んだservice instanceに留めるため、移動構築を禁止する。
	 */
	WindowsRestorePointService( WindowsRestorePointService &&) = delete ;
	/**
	 * @brief 読み込んだservice instanceへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	WindowsRestorePointService				 &operator=( WindowsRestorePointService &&) = delete ;

	/**
	 * @brief BEGIN_SYSTEM_CHANGEで復元ポイントを開始する。
	 * 初期化失敗、System Restore無効、Safe Mode、非対応OSでは失敗を返し、Provider installを開始させない。
	 * @param[in] description Windowsの復元UIへ表示する説明。
	 * @return 開始結果と成功時のsequence number。
	 */
	[[nodiscard]] RestorePointOperationResult begin(
		std::wstring_view description) noexcept override ;

	/**
	 * @brief END_SYSTEM_CHANGEで開始済み復元ポイントを終了する。
	 * Driver処理の成否にかかわらず通常の終了を通知する。終了失敗時も既に行われたdriver変更は取り消さない。
	 * @param[in] sequenceNumber `begin`が返した識別番号。 beginが返した識別番号。
	 * @return 終了結果。
	 */
	[[nodiscard]] RestorePointOperationResult complete(
		std::int64_t sequenceNumber) noexcept override ;

private:
	/// FreeLibraryで解放するSrClient.dll handle。
	HMODULE					  module_{} ;
	/// DLL lifetime内だけ有効なAPI pointer。
	SrSetRestorePointFunction setRestorePoint_{} ;
	/// COM securityまたはDLL初期化失敗。成功時は0。
	NativeError				  initializationError_{} ;
} ;

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/windows_restore_point_service.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
WindowsRestorePointService::WindowsRestorePointService() noexcept
	: initializationError_( initializeComSecurity())
{
	// COM security の初期化に失敗した場合は復元ポイント API を読み込まない。
	if( initializationError_ != 0) {
		return ;
	}

	module_ = LoadLibraryW( L"SrClient.dll") ;
	// SrClient module を読み込めなければ初期化失敗を保持する。
	if( module_ == nullptr) {
		initializationError_ = win32Error( GetLastError()) ;
		return ;
	}

	const FARPROC procedure =
		// DLLから取得したuntyped entry point。
		GetProcAddress( module_, "SRSetRestorePointW") ;
	// 復元ポイントの entry point が見つからなければ service を使用可能にしない。
	if( procedure == nullptr) {
		initializationError_ = win32Error( GetLastError()) ;
		return ;
	}

	// Windows APIが規定する同一signatureへ変換し、module_のlifetime内だけ使用する。
	setRestorePoint_ = reinterpret_cast<SrSetRestorePointFunction>( procedure) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/windows_restore_point_service.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
WindowsRestorePointService::~WindowsRestorePointService()
{
	// 読み込んだ SrClient module がある場合だけ所有参照を解放する。
	if( module_ != nullptr) {
		FreeLibrary( module_) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/windows_restore_point_service.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
RestorePointOperationResult WindowsRestorePointService::begin(
	const std::wstring_view description) noexcept
{
	// 初期化失敗または API 欠落時は復元ポイント開始を成功にしない。
	if( initializationError_ != 0 || setRestorePoint_ == nullptr) {
		// 復元ポイント開始境界の型不明例外を表すE_UNEXPECTEDのbit pattern。
		constexpr NativeError UNEXPECTED_ERROR = static_cast<NativeError>( 0x8000FFFFU) ;
		return {.outcome = OutcomeCode::FAILURE,
				.error	 = initializationError_ != 0 ? initializationError_ : UNEXPECTED_ERROR} ;
	}

	RESTOREPOINTINFOW restorePointInfo{} ;	// BEGIN_SYSTEM_CHANGE入力構造体。
	restorePointInfo.dwEventType	  = BEGIN_SYSTEM_CHANGE ;
	restorePointInfo.dwRestorePtType  = DEVICE_DRIVER_INSTALL ;
	restorePointInfo.llSequenceNumber = 0 ;
	// 固定長Windows API領域へ終端nullを残して説明を切り詰める。
	const std::size_t copyCount =
		(std::min)( description.size(), std::size( restorePointInfo.szDescription) - 1U) ;
	std::copy_n( description.data(), copyCount, restorePointInfo.szDescription) ;
	restorePointInfo.szDescription[copyCount] = L'\0' ;

	STATEMGRSTATUS status{} ;	// System Restore serviceが返す状態とsequence number。
	// 復元ポイント開始 API の失敗時は status と返された番号を保持する。
	if( setRestorePoint_( &restorePointInfo, &status) == FALSE) {
		return {.outcome		= OutcomeCode::FAILURE,
				.error			= restorePointError( status.nStatus),
				.sequenceNumber = status.llSequenceNumber} ;
	}

	return {.outcome = OutcomeCode::SUCCESS, .error = 0, .sequenceNumber = status.llSequenceNumber} ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/windows_restore_point_service.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
RestorePointOperationResult WindowsRestorePointService::complete(
	const std::int64_t sequenceNumber) noexcept
{
	// API 欠落または無効な復元ポイント番号では終了通知を受理しない。
	if( setRestorePoint_ == nullptr || sequenceNumber <= 0) {
		// 不正な復元ポイント終了要求を拒否するE_INVALIDARGのbit pattern。
		constexpr NativeError INVALID_ARGUMENT = static_cast<NativeError>( 0x80070057U) ;
		return {.outcome = OutcomeCode::FAILURE,
				.error	 = initializationError_ != 0 ? initializationError_ : INVALID_ARGUMENT} ;
	}

	RESTOREPOINTINFOW restorePointInfo{} ;	// END_SYSTEM_CHANGE入力構造体。
	restorePointInfo.dwEventType	  = END_SYSTEM_CHANGE ;
	restorePointInfo.dwRestorePtType  = DEVICE_DRIVER_INSTALL ;
	restorePointInfo.llSequenceNumber = sequenceNumber ;

	STATEMGRSTATUS status{} ;	// System Restore serviceが返す終了状態。
	// 復元ポイント終了の失敗時も開始済み番号を結果に保持する。
	if( setRestorePoint_( &restorePointInfo, &status) == FALSE) {
		return {.outcome		= OutcomeCode::FAILURE,
				.error			= restorePointError( status.nStatus),
				.sequenceNumber = sequenceNumber} ;
	}

	return {.outcome = OutcomeCode::SUCCESS, .error = 0, .sequenceNumber = sequenceNumber} ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/windows_restore_point_service.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::unique_ptr<IRestorePointService> makeWindowsRestorePointService()
{
	return std::make_unique<WindowsRestorePointService>() ;
}

} // namespace drivercrate
