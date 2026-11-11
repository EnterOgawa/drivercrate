//------------------------------------------------------------------------------
/**
 * @file windows_restore_point_service.cpp
 * @brief Windows復元ポイントサービス実装。
 * @version 01.01.01
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
 * Ver.01.01.00 Shunji Ogawa  2026/11/10  最新実確認の選択表示と日内復元保護の実在再利用を接続。
 * Ver.01.01.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 *
 * @note MicrosoftのSystem Restore契約に従いCOM securityを初期化し、SrClient.dllのSRSetRestorePointWを動的に呼び出します。
 *       System Restore無効、Safe Mode、非対応OSでは変更を行わず失敗を返します。
 */
//------------------------------------------------------------------------------

#include "platform/windows_restore_point_service.h"
#include "platform/official_release_observation_store.h"
#include <Wbemidl.h>
#include <OleAuto.h>
#include <wrl/client.h>
#include <optional>
#include <string>

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
/**
 * @brief Windows local暦日とUTC秒を同じ準備時点で得ます。
 * @return 実時刻です。
 */
//------------------------------------------------------------------------------
[[nodiscard]] restore_point_detail::Clock readRestoreClock()
{
	FILETIME utc{} ;	// 実UTCです。
	GetSystemTimeAsFileTime( &utc) ;
	SYSTEMTIME local{} ;	// 日付はUTC日ではありません。
	GetLocalTime( &local) ;
	ULARGE_INTEGER ticks{} ;	// Windows epochから秒へ変換します。
	ticks.LowPart  = utc.dwLowDateTime ;
	ticks.HighPart = utc.dwHighDateTime ;
	return {static_cast<std::int64_t>( ticks.QuadPart / 10000000ULL) - 11644473600LL,
			static_cast<std::uint32_t>( local.wYear * 10000U + local.wMonth * 100U + local.wDay)} ;
}
//------------------------------------------------------------------------------
/**
 * @brief WMI日時の原offsetをUTC秒へ解釈します。
 * @param[in] value Windows CreationTimeです。
 * @return 不正時は空です。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::int64_t> restoreCreationUtc( std::wstring_view value)
{
	// 固定CIM日時形式とoffset符号以外を拒否します。
	if( value.size() != 25U || value[14] != L'.' || (value[21] != L'+' && value[21] != L'-')) {
		return {} ;
	}

	const auto number = [&]( std::size_t first, std::size_t count) -> std::optional<unsigned> {
		unsigned result{} ;	// 数値のみ受理します。
		// 指定された有限桁だけを数値として読みます。
		for( std::size_t i = first; i < first + count; ++i) {
			// 日時の未知文字を数値へ補完しません。
			if( value[i] < L'0' || value[i] > L'9') {
				return {} ;
			}

			result = result * 10U + static_cast<unsigned>( value[i] - L'0') ;
		}

		return result ;
	} ;
	// 元CIM日時の年です。
	const auto year = number( 0, 4) ;
	// 元CIM日時の月です。
	const auto month = number( 4, 2) ;
	const auto day	 = number( 6, 2) ;	// 原暦日です。
	// 元CIM日時の時です。
	const auto hour = number( 8, 2) ;
	// 元CIM日時の分です。
	const auto minute = number( 10, 2) ;
	const auto second = number( 12, 2) ;	// 原時刻です。
	// 原timezoneの分offsetです。
	const auto offset = number( 22, 3) ;
	const auto micros = number( 15, 6) ;	// 元timezone offsetです。
	// 欠測や不正timezone offsetを拒否します。
	if( !year || !month || !day || !hour || !minute || !second || !offset || !micros ||
	   *offset > 840U) {
		return {} ;
	}

	SYSTEMTIME time{} ;	// Windowsの暦日検査を使います。
	time.wYear	 = static_cast<WORD>( *year) ;
	time.wMonth	 = static_cast<WORD>( *month) ;
	time.wDay	 = static_cast<WORD>( *day) ;
	time.wHour	 = static_cast<WORD>( *hour) ;
	time.wMinute = static_cast<WORD>( *minute) ;
	time.wSecond = static_cast<WORD>( *second) ;
	FILETIME ft{} ;	// UTCとみなした元wall-clockです。
	// Windowsが拒否する暦日を実在時刻へ変換しません。
	if( !SystemTimeToFileTime( &time, &ft)) {
		return {} ;
	}

	ULARGE_INTEGER ticks{} ;	// 元符号付きoffsetだけを引きます。
	ticks.LowPart  = ft.dwLowDateTime ;
	ticks.HighPart = ft.dwHighDateTime ;
	return static_cast<std::int64_t>( ticks.QuadPart / 10000000ULL) - 11644473600LL +
		   (value[21] == L'+' ? -1 : 1) * static_cast<std::int64_t>( *offset) * 60LL ;
}
//------------------------------------------------------------------------------
/**
 * @brief SystemRestore一覧だけを有限read-only照会します。
 * @param[out] points 元sequence/CreationTimeだけです。
 * @return 原HRESULTです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRestorePoints( std::vector<restore_point_detail::Point> &points)
{
	points.clear() ;
	Microsoft::WRL::ComPtr<IWbemLocator> locator ;	// 同worker apartmentだけです。
	auto error = CoCreateInstance( CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
								  // SDK WMIです。
								  IID_PPV_ARGS( &locator)) ;
	// WMI locator生成失敗を一覧0件へ変換しません。
	if( FAILED( error)) {
		return static_cast<NativeError>( error) ;
	}

	Microsoft::WRL::ComPtr<IWbemServices> service ;		// root/defaultだけを開きます。
	BSTR space = SysAllocString( L"ROOT\\DEFAULT") ;	// 外部文字列を送りません。
	// namespace文字列の確保失敗を返します。
	if( !space) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	error = locator->ConnectServer( space, nullptr, nullptr, nullptr, WBEM_FLAG_CONNECT_USE_MAX_WAIT,
								   nullptr, nullptr, &service) ;
	SysFreeString( space) ;
	// Root Defaultへ接続できなければ保護取得を止めます。
	if( FAILED( error)) {
		return static_cast<NativeError>( error) ;
	}

	error =
		CoSetProxyBlanket( service.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
						  RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE) ;
	// 同workerのWMI読取認証が成立することを要求します。
	if( FAILED( error)) {
		return static_cast<NativeError>( error) ;
	}

	BSTR language = SysAllocString( L"WQL") ;	// 固定queryだけです。
	BSTR query	  = SysAllocString(
		   L"SELECT SequenceNumber, CreationTime FROM SystemRestore") ;	// hardware inventoryではありません。
	// query用の確保失敗では取得済みBSTRを解放します。
	if( !language || !query) {
		SysFreeString( language) ;
		SysFreeString( query) ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	Microsoft::WRL::ComPtr<IEnumWbemClassObject> rows ;	// 一directionのread-only cursorです。
	error = service->ExecQuery(
		language, query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &rows) ;
	SysFreeString( language) ;
	SysFreeString( query) ;
	// query失敗を実在pointなしへ変換しません。
	if( FAILED( error)) {
		return static_cast<NativeError>( error) ;
	}

	const auto deadline = GetTickCount64() + 10000ULL ;	// 列挙全体を10秒に制限します。
	// Windows一覧は元1024件と全体期限の内側だけを読みます。
	for( std::size_t index = 0; index <= 1024U; ++index) {
		Microsoft::WRL::ComPtr<IWbemClassObject> row ;						// 一pointだけの所有です。
		ULONG									 count{} ;					// 無限waitを行いません。
		const auto								 now = GetTickCount64() ;	// 無制限に再waitしません。
		// 一覧読取の全体期限を延長しません。
		if( now >= deadline) {
			return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT)) ;
		}

		error = rows->Next( static_cast<long>( deadline - now), 1, &row, &count) ;
		// 正式な一覧終端だけを成功として返します。
		if( error == static_cast<HRESULT>( WBEM_S_FALSE) && count == 0) {
			return 0 ;
		}

		// 未到達・不正件数・上限超過を実在確認失敗にします。
		if( FAILED( error) || count != 1 || !row || index == 1024U) {
			return static_cast<NativeError>( FAILED( error) ? error
														  : HRESULT_FROM_WIN32( ERROR_TIMEOUT)) ;
		}

		// WMIが返すsequenceのVARIANTです。
		VARIANT sequence ;
		VARIANT created ;	// 元BSTRをscopeで解放します。
		VariantInit( &sequence) ;
		VariantInit( &created) ;
		error					= row->Get( L"SequenceNumber", 0, &sequence, nullptr, nullptr) ;
		const auto createdError = row->Get( L"CreationTime", 0, &created, nullptr,
										   nullptr) ;	// 番号だけでpointを補いません。
		const auto time			= created.vt == VT_BSTR && created.bstrVal
									  ? restoreCreationUtc( std::wstring_view( created.bstrVal,
																			 SysStringLen( created.bstrVal)))
									  : std::nullopt ;	// 元時刻です。
		const auto id			= sequence.vt == VT_UI4	 ? static_cast<std::int64_t>( sequence.ulVal)
								  : sequence.vt == VT_I4 ? static_cast<std::int64_t>( sequence.lVal)
														 : 0LL ;	// 不正型は拒否します。
		VariantClear( &created) ;
		VariantClear( &sequence) ;
		// 元sequenceと作成時刻の両読取成功を要求します。
		if( FAILED( error) || FAILED( createdError) || id <= 0 || !time || *time <= 0) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		points.push_back( {id, *time}) ;
	}

	return static_cast<NativeError>( E_UNEXPECTED) ;
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
	 * @brief 実在pointで保護を準備し、同日再利用と実BEGINを分ける。
	 * 保護未成立ではProvider installを開始させない。再利用ではnative BEGINを呼ばない。
	 * @param[in] description Windowsの復元UIへ表示する説明。
	 * @return 実native結果または再利用時NOT_STARTEDと元sequence。実在事実はprotectionで返す。
	 */
	[[nodiscard]] RestorePointOperationResult begin(
		std::wstring_view description) noexcept override ;

	/**
	 * @brief 元scopeの実在を再確認し、実BEGIN所有時だけENDを一回通知する。
	 * 終了失敗時も既に行われたdriver変更は取り消さない。日内reuseではnative ENDを呼ばない。
	 * @param[in] sequenceNumber `begin`が返した識別番号。 beginが返した識別番号。
	 * @return 終了結果。
	 */
	[[nodiscard]] RestorePointOperationResult complete(
		std::int64_t sequenceNumber) noexcept override ;

	/**
	 * @brief 全callback検査済みの内部fixtureを所有します。
	 * @param[in] calls productionを含まない完全fakeです。
	 */
	explicit WindowsRestorePointService( restore_point_detail::Calls calls)
		: calls_( std::move( calls))
	{
	}
	/**
	 * @brief 最後の実在確認を返します。
	 * @return 再利用/元時刻/保存診断です。
	 */
	[[nodiscard]] RestorePointProtectionResult protection() const noexcept override
	{
		return protection_ ;
	}

private:
	/**
	 * @brief 実BEGINだけを呼びます。
	 * @param[in] description 元説明。
	 * @return 原native結果。
	 */
	[[nodiscard]] RestorePointOperationResult nativeBegin( std::wstring_view description) noexcept ;
	/**
	 * @brief 実ENDだけを呼びます。
	 * @param[in] sequenceNumber 元番号。
	 * @return 原native結果。
	 */
	[[nodiscard]] RestorePointOperationResult nativeEnd( std::int64_t sequenceNumber) noexcept ;
	/// 全callbackを明示した同service専用表です。
	restore_point_detail::Calls				  calls_ ;
	/// 実排他の所有者です。保護scopeの終了まで保持します。
	std::shared_ptr<void>					  lease_ ;
	/// 最後の実在確認です。
	RestorePointProtectionResult protection_{.disposition = RestorePointDisposition::UNAVAILABLE} ;
	/// 完了済みRAM memo。保存失敗でも実在照合後だけ同日再利用できます。
	RestorePointDayMemo			 memo_ ;
	/// 同service内のclock逆行を拒否する下限です。
	std::int64_t				 lastUtc_{} ;
	/// 同scopeが実BEGINを受理した場合だけtrueです。
	bool						 nativeOwned_{} ;
	/// Memo I/Oの利用可否です。保護取得そのものの前提ではありません。
	bool						 memoUsable_{} ;
	/// 同scopeの成功した実BEGIN番号です。
	std::int64_t				 activeSequence_{} ;

	/// FreeLibraryで解放するSrClient.dll handle。
	HMODULE						 module_{} ;
	/// DLL lifetime内だけ有効なAPI pointer。
	SrSetRestorePointFunction	 setRestorePoint_{} ;
	/// COM securityまたはDLL初期化失敗。成功時は0。
	NativeError					 initializationError_{} ;
} ;

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief COM securityとSrClient.dll entry pointを初期化する。Provider COM object生成前にprocess-wide securityを設
 *        定し、API利用不能時は後続beginをfail-closedにする。
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
	try {
		calls_.clock  = readRestoreClock ;
		calls_.points = readRestorePoints ;
		calls_.begin  = [this]( auto description) { return nativeBegin( description) ; } ;
		calls_.end	  = [this]( auto sequence) { return nativeEnd( sequence) ; } ;
		auto store =
			std::make_shared<OfficialReleaseObservationStore>() ;	// 固定ProgramData用途だけです。
		calls_.lock		= [store]( auto &lease) { return store->lockDailyRestoreMemo( lease) ; } ;
		calls_.loadMemo = [store]( auto &memo) { return store->loadDailyRestoreMemo( memo) ; } ;
		calls_.saveMemo = [store]( const auto &memo) { return store->storeDailyRestoreMemo( memo) ; } ;

	} catch( ...) {
		initializationError_ = static_cast<NativeError>( E_OUTOFMEMORY) ;
		calls_				 = {} ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 読み込んだSrClient.dllを解放する。
 */
//------------------------------------------------------------------------------
WindowsRestorePointService::~WindowsRestorePointService()
{
	// 終了済みでない所有scopeだけを一度閉じます。
	if( lease_ && activeSequence_ > 0) {
		static_cast<void>( complete( activeSequence_)) ;
	}

	lease_.reset() ;
	// 読み込んだ SrClient module がある場合だけ所有参照を解放する。
	if( module_ != nullptr) {
		FreeLibrary( module_) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 実BEGINだけを呼びます。
 * @param[in] description 元説明。
 * @return 原native結果。
 */
//------------------------------------------------------------------------------
RestorePointOperationResult WindowsRestorePointService::nativeBegin(
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
	if( setRestorePoint_( &restorePointInfo, &status) == FALSE || status.nStatus != ERROR_SUCCESS) {
		return {.outcome		= OutcomeCode::FAILURE,
				.error			= restorePointError( status.nStatus),
				.sequenceNumber = status.llSequenceNumber} ;
	}

	return {.outcome = OutcomeCode::SUCCESS, .error = 0, .sequenceNumber = status.llSequenceNumber} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実ENDだけを呼びます。
 * @param[in] sequenceNumber 元番号。
 * @return 原native結果。
 */
//------------------------------------------------------------------------------
RestorePointOperationResult WindowsRestorePointService::nativeEnd(
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
	if( setRestorePoint_( &restorePointInfo, &status) == FALSE || status.nStatus != ERROR_SUCCESS) {
		return {.outcome		= OutcomeCode::FAILURE,
				.error			= restorePointError( status.nStatus),
				.sequenceNumber = sequenceNumber} ;
	}

	return {.outcome = OutcomeCode::SUCCESS, .error = 0, .sequenceNumber = sequenceNumber} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実在pointで保護を準備し、同日再利用と実BEGINを分ける。保護未成立ではProvider installを開始させない。再利用ではnative BEGINを呼ばない。
 * @param[in] description Windowsの復元UIへ表示する説明。
 * @return 実native結果または再利用時NOT_STARTEDと元sequence。実在事実はprotectionで返す。
 */
//------------------------------------------------------------------------------
RestorePointOperationResult WindowsRestorePointService::begin(
	const std::wstring_view description) noexcept
{
	// 同serviceで保護scopeを重ねません。
	if( lease_) {
		return {.outcome = OutcomeCode::FAILURE,
				.error	 = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_BUSY))} ;
	}

	protection_ = {.disposition = RestorePointDisposition::UNAVAILABLE} ;
	try {
		// 初期化不良や不完全fakeを実APIへfallbackしません。
		if( initializationError_ != 0 || !calls_.clock || !calls_.points || !calls_.begin ||
		   !calls_.end || !calls_.lock || !calls_.loadMemo || !calls_.saveMemo) {
			return {.outcome = OutcomeCode::FAILURE,
					.error	 = initializationError_ ? initializationError_
													: static_cast<NativeError>( E_INVALIDARG)} ;
		}

		const auto now = calls_.clock() ;	// 実local日とUTCを別々に扱います。
		// 元時計下限に反する準備時刻を拒否します。
		if( now.utc <= 0 || now.localDay < 20000101U || now.utc < lastUtc_) {
			return {.outcome = OutcomeCode::FAILURE,
					.error	 = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIME_SKEW))} ;
		}

		lastUtc_			 = now.utc ;
		protection_.localDay = now.localDay ;
		NativeError error{} ;	// Memo I/Oは非authorityな最適化です。
		try {
			error = calls_.lock( lease_) ;
		} catch( ...) {
			error = static_cast<NativeError>( E_UNEXPECTED) ;
		}

		// 明確な他operationの排他busyではnative準備へ進みません。
		if( error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_SHARING_VIOLATION)) ||
		   error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_LOCK_VIOLATION)) ||
		   error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_BUSY))) {
			lease_.reset() ;
			return {.outcome = OutcomeCode::FAILURE, .error = error} ;
		}

		// 成功flagだけで実排他ownerなしを受理しません。
		if( error == 0 && !lease_) {
			return {.outcome = OutcomeCode::FAILURE,
					.error	 = static_cast<NativeError>( E_INVALIDARG)} ;
		}

		memoUsable_			  = error == 0 && lease_ != nullptr ;
		protection_.memoError = error ;
		// これはscope寿命だけであり実排他取得の偽装ではありません。
		if( !lease_) {
			lease_ = std::make_shared<int>( 0) ;
		}

		std::vector<restore_point_detail::Point> before ;	// 原Windows一覧です。
		error = calls_.points( before) ;
		// Windows一覧の読取失敗ではProvider前に停止します。
		if( error != 0) {
			lease_.reset() ;
			protection_.error = error ;
			return {.outcome = OutcomeCode::FAILURE, .error = error} ;
		}

		RestorePointDayMemo stored ;							// 壊れたmemoを実在の代替へしません。
		NativeError			memoError = protection_.memoError ;	// 読取不可は再利用根拠なしです。
		// 実memo排他が利用可能な場合だけ永続メモを読みます。
		if( memoUsable_) {
			try {
				memoError = calls_.loadMemo( stored) ;
			} catch( ...) {
				memoError = static_cast<NativeError>( E_UNEXPECTED) ;
			}
		}

		// メモ不使用の元診断は保護の成否と別に残します。
		if( memoError != 0) {
			protection_.memoError = memoError ;
		}

		const auto valid = [&]( const RestorePointDayMemo &memo) {
			return memo.localDay == now.localDay && memo.sequenceNumber > 0 &&
				   memo.createdUtc > 0 && memo.createdUtc <= memo.preparedUtc &&
				   memo.preparedUtc <= now.utc &&
				   std::ranges::count_if( before, [&]( const auto &point) {
					   return point.sequenceNumber == memo.sequenceNumber &&
							  point.createdUtc == memo.createdUtc ;
				   }) == 1 ;
		} ; // 毎回実在へ結合します。
		// 同local日と現在実在に結合したメモだけを再利用します。
		if( (memoError == 0 && valid( stored)) || valid( memo_)) {
			const auto memo =
				// 永続値とRAMを捏造しません。
				memoError == 0 && valid( stored) ? stored : memo_ ;
			protection_.disposition	   = RestorePointDisposition::SAME_DAY_REUSED ;
			protection_.verification   = OutcomeCode::SUCCESS ;
			protection_.sequenceNumber = memo.sequenceNumber ;
			protection_.createdUtc	   = memo.createdUtc ;
			protection_.verifiedBefore = true ;
			activeSequence_			   = memo.sequenceNumber ;
			return {.sequenceNumber = memo.sequenceNumber} ;
		}

		protection_.nativeBeginCalled = true ;
		const auto result = calls_.begin( description) ;	// この明示操作で一回だけ試行します。
		// 元native開始が成功していなければscopeを成立させません。
		if( result.outcome != OutcomeCode::SUCCESS || result.sequenceNumber <= 0) {
			lease_.reset() ;
			return result ;
		}

		nativeOwned_			   = true ;
		activeSequence_			   = result.sequenceNumber ;
		protection_.sequenceNumber = result.sequenceNumber ;
		std::vector<restore_point_detail::Point> after ;	// API TRUEからpoint存在を推測しません。
		error				   = calls_.points( after) ;
		const auto observedNow = calls_.clock() ;	// BEGIN後の実観測時刻で未来値を判定します。
		const auto point	   = std::ranges::find(
			  after, result.sequenceNumber,
			  &restore_point_detail::Point::sequenceNumber) ;	// 選ばれた番号だけです。
		// 返却番号の一意な実在と時計整合を確認します。
		if( error != 0 || point == after.end() ||
		   std::ranges::count( after, result.sequenceNumber,
							  &restore_point_detail::Point::sequenceNumber) != 1 ||
		   point->createdUtc <= 0 || point->createdUtc > observedNow.utc ||
		   observedNow.utc < now.utc) {
			protection_.verification = OutcomeCode::FAILURE ;
			protection_.error =
				error ? error : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_FOUND)) ;
			return result ;
		}

		const bool existed		   = std::ranges::any_of( before, [&]( const auto &prior) {
			return prior.sequenceNumber == point->sequenceNumber &&
				   prior.createdUtc == point->createdUtc ;
		}) ; // 元pointかを原一覧へ照合します。
		protection_.disposition	   = !existed && point->createdUtc >= now.utc
										 ? RestorePointDisposition::NEW_POINT_VERIFIED
										 : RestorePointDisposition::WINDOWS_SELECTED_POINT ;
		protection_.verification   = OutcomeCode::SUCCESS ;
		protection_.createdUtc	   = point->createdUtc ;
		protection_.verifiedBefore = true ;
		return result ;
	} catch( ...) {
		protection_.verification = OutcomeCode::FAILURE ;
		protection_.error		 = static_cast<NativeError>( E_UNEXPECTED) ;
		// 実BEGIN所有前の例外では終了通知を捏造しません。
		if( !nativeOwned_) {
			lease_.reset() ;
			activeSequence_ = 0 ;
		}

		return {.outcome		= nativeOwned_ ? OutcomeCode::SUCCESS : OutcomeCode::FAILURE,
				.error			= nativeOwned_ ? 0 : protection_.error,
				.sequenceNumber = activeSequence_} ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 元scopeの実在を再確認し、実BEGIN所有時だけENDを一回通知する。終了失敗時も既に行われたdriver変更は取り消さない。日内reuseではnative ENDを呼ばない。
 * @param[in] sequenceNumber `begin`が返した識別番号。 beginが返した識別番号。
 * @return 終了結果。
 */
//------------------------------------------------------------------------------
RestorePointOperationResult WindowsRestorePointService::complete(
	const std::int64_t sequenceNumber) noexcept
{
	// 元所有番号と異なるcompleteや遅延completeを拒否します。
	if( !lease_ || sequenceNumber <= 0 || sequenceNumber != activeSequence_) {
		return {.outcome		= OutcomeCode::FAILURE,
				.error			= static_cast<NativeError>( E_INVALIDARG),
				.sequenceNumber = sequenceNumber} ;
	}

	RestorePointOperationResult result{.sequenceNumber =
										   sequenceNumber} ;	// 再利用はnative未実行のままです。
	const bool					owned = nativeOwned_ ;			// 元BEGINだけを一回閉じます。
	nativeOwned_					  = false ;
	try {
		// 実BEGINを所有したscopeだけがnative ENDを呼びます。
		if( owned) {
			protection_.nativeEndCalled = true ;
			result						= calls_.end( sequenceNumber) ;
		}

		const auto now = calls_.clock() ;					// 原作成時刻をnowへ変更しません。
		std::vector<restore_point_detail::Point> points ;	// 終了時にも実在を照合します。
		const auto error = calls_.points( points) ;			// 元scopeだけの確認です。
		const bool exists =
			error == 0 && now.utc >= lastUtc_ && protection_.createdUtc > 0 &&
			protection_.createdUtc <= now.utc &&
			std::ranges::count_if( points, [&]( const auto &p) {
				return p.sequenceNumber == sequenceNumber && p.createdUtc == protection_.createdUtc ;
			}) == 1 ; // 同pointだけを受理します。
		lastUtc_				  = (std::max)( lastUtc_, now.utc) ;
		protection_.verifiedAfter = exists ;
		// 終了時の実在が欠ければ元導入結果と別の保護診断にします。
		if( !exists) {
			protection_.verification = OutcomeCode::FAILURE ;
			// 先行した元診断がなければ終了時の欠測を記録します。
			if( protection_.error == 0) {
				protection_.error =
					error ? error : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_FOUND)) ;
			}
		}

		// 正常ENDと開始前後の実在が揃った場合だけ日内メモを保存します。
		if( owned && result.outcome == OutcomeCode::SUCCESS && result.error == 0 &&
		   protection_.verifiedBefore && exists) {
			memo_ = {protection_.localDay, sequenceNumber, protection_.createdUtc, now.utc} ;
			// 保存失敗は実導入成否と別です。
			if( memoUsable_) {
				try {
					// 最適化メモだけの保存診断です。
					const auto saveError = calls_.saveMemo( memo_) ;
					// 先行するメモ診断を保存成功で消しません。
					if( saveError != 0 || protection_.memoError == 0) {
						protection_.memoError = saveError ;
					}
				} catch( ...) {
					protection_.memoError = static_cast<NativeError>( E_UNEXPECTED) ;
				}
			}
		}
	} catch( ...) {
		protection_.verification = OutcomeCode::FAILURE ;
		protection_.error		 = static_cast<NativeError>( E_UNEXPECTED) ;
		// 実END callback例外を未実行成功へ変換しません。
		if( owned && result.outcome == OutcomeCode::NOT_STARTED) {
			result = {.outcome		  = OutcomeCode::FAILURE,
					  .error		  = protection_.error,
					  .sequenceNumber = sequenceNumber} ;
		}
	}

	activeSequence_ = 0 ;
	lease_.reset() ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在のworker COM apartmentでWindows復元ポイントサービスを生成する。Provider COM object生成前に生成し、process-wide COM
 *        securityとSystem Restore APIを初期化する。
 * @return 呼出し側が単独所有するサービス。初期化失敗は`begin`の結果として返す。
 * @note Provider COM objectの生成前に呼び出し、process-wide COM securityを設定する。
 */
//------------------------------------------------------------------------------
std::unique_ptr<IRestorePointService> makeWindowsRestorePointService()
{
	return std::make_unique<WindowsRestorePointService>() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全callbackが明示された内部fixtureだけを生成します。
 * @param[in] calls 完全fake。未指定時は一切実APIを呼ばず拒否します。
 * @return 完全表ならservice、不完全ならnullptrです。
 */
//------------------------------------------------------------------------------
std::unique_ptr<IRestorePointService> restore_point_detail::createFixture( Calls calls)
{
	// 不完全表ではCOM/WMI/ProgramData/実復元APIへ一切fallbackしません。
	if( !calls.clock || !calls.points || !calls.begin || !calls.end || !calls.lock ||
	   !calls.loadMemo || !calls.saveMemo) {
		return {} ;
	}

	return std::make_unique<WindowsRestorePointService>( std::move( calls)) ;
}

} // namespace drivercrate
