//------------------------------------------------------------------------------
/**
 * @file inf_dependency_native.cpp
 * @brief 実path・署名・OSを固定する非実行INF依存adapterの実装。
 * @version 01.06.02
 * @date 2026/10/06
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  handle固定・明示節・CAT／inboxと再確認を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/06  製品に含めない同期API障害注入境界を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/06  封印所有者の使用中固定へpackage由来を接続。
 * Ver.01.03.00 Shunji Ogawa  2026/10/06  封印CATの原位置・size・hashだけを署名根拠にする。
 * Ver.01.04.00 Shunji Ogawa  2026/10/07  到達file用途の有限観測と不在以外の節読取診断を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/13  元共通閉包と完全内部APIから選択依存と有限効果を再検査。
 * Ver.01.06.00 Shunji Ogawa  2026/10/15  正確なNeeds設置文脈から有限HKR設定を全行検査。
 * Ver.01.06.01 Shunji Ogawa  2026/10/15  Needs効果の宣言契約をCopyFilesとAddRegへ整合。
 * Ver.01.06.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 共通内容factoryの私有選択節へ接続します。旧引数経路のpackage由来は未検査を維持します。
 * @see docs/adr/0270-read-only-inf-dependency-native-adapter.md
 */
//------------------------------------------------------------------------------

#include "platform/inf_dependency_native.h"
#include "platform/inf_dependency_native_internal.h"
#include "platform/common_driver_package.h"
#include "platform/driver_package_signature_internal.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "platform/official_inf_archive_binding.h"
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
#include "support/inf_dependency_native_test_api.h"
#endif

#include <Windows.h>
#include <SetupAPI.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace inf_dependency_native_detail {
namespace {
thread_local const Api *ownedApi{} ;	// 同threadの所有scopeだけを借用します。
}
/** @see inf_dependency_native_internal.h 宣言側の所有契約を正本とします。 */
ScopedFixture::ScopedFixture( Api api) : api_( std::move( api))
{
	ownedApi = &api_ ;
}
/** @see inf_dependency_native_internal.h 宣言側の解放契約を正本とします。 */
ScopedFixture::~ScopedFixture()
{
	ownedApi = nullptr ;
}
/** @see inf_dependency_native_internal.h 宣言側の借用契約を正本とします。 */
const Api *activeApi() noexcept
{
	return ownedApi ;
}
#ifdef DRIVERCRATE_INTERNAL_INDEX_TESTS
/** @see inf_dependency_native_internal.h 宣言側の完全表契約を正本とします。 */
std::unique_ptr<ScopedFixture> Access::create( Api api)
{
	// 欠落表と二重scopeを実nativeへ補完しません。
	if( ownedApi != nullptr || !api.version || !api.windowsDirectory || !api.infSignature ||
	   !api.catalogSignature || !api.driverStore) {
		return {} ;
	}

	return std::unique_ptr<ScopedFixture>( new ScopedFixture( std::move( api))) ;
}
#endif
} // namespace inf_dependency_native_detail
namespace {
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
thread_local const test::InfDependencyNativeTestApi
	*testApi{} ;	// 専用targetの一同期runだけを借用する。
#endif
constexpr std::uint64_t MAX_INF_BYTES	= 4U * 1024U * 1024U ;		// 一INFの実byte上限。
constexpr std::uint64_t MAX_CAT_BYTES	= 32U * 1024U * 1024U ;		// 一CATの有限上限。
constexpr std::uint64_t MAX_TOTAL_BYTES = 128U * 1024U * 1024U ;	// 全固定fileの累積上限。
constexpr std::size_t	MAX_FILES		= 256U ;					// INF・CAT・対応Storeを含む固定file上限。

/** @brief Windows ordinalで有限path／明示名を比較する。
 * @param[in] left 一方の有限名称。
 * @param[in] right 他方の有限名称。
 * @return 大小文字を除いて一致する場合true。
 */
bool					equalName( std::wstring_view left, std::wstring_view right)
{
	return left.size() < MAX_PATH && right.size() < MAX_PATH &&
		   CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

/** @brief 一相対componentのdevice aliasを拒否する。
 * @param[in] part 末尾正規化を含まない一component。
 * @return 予約device名の場合true。
 */
bool reservedName( std::wstring_view part)
{
	const auto base = part.substr( 0U, part.find( L'.')) ;	// 拡張子前のdevice名。
	return equalName( base, L"CON") || equalName( base, L"PRN") || equalName( base, L"AUX") ||
		   equalName( base, L"CONIN$") || equalName( base, L"CONOUT$") || equalName( base, L"NUL") ||
		   (base.size() == 4U &&
			((base[3] >= L'1' && base[3] <= L'9') || base[3] == L'\u00b9' || base[3] == L'\u00b2' ||
			 base[3] == L'\u00b3') &&
			(equalName( base.substr( 0U, 3U), L"COM") || equalName( base.substr( 0U, 3U), L"LPT"))) ;
}

/** @brief 元Win32失敗をHRESULTへ変換する。
 * @param[in] error 最初のWin32診断値。
 * @return 非零HRESULT。診断欠損はE_FAIL。
 */
NativeError winError( DWORD error)
{
	return error == 0U ? E_FAIL : HRESULT_FROM_WIN32( error) ;
}

/** @brief 明示openの不在だけを後続の検証失敗から分離する。
 * @param[in] error CreateFileWの直後の元診断。
 * @param[out] missing 任意の不在観測出力。file／path不在の場合だけtrue。
 * @return 元の失敗HRESULT。
 */
NativeError openError( DWORD error, bool *missing)
{
	// 有効handle取得後の属性・hash・CAT等の失敗から不在を生成しない。
	if( missing != nullptr) {
		*missing = error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ;
	}

	return winError( error) ;
}

/** @brief 初回／終了の実OS情報を取得する。注入は専用targetだけで有効。
 * @param[out] version EX layoutのversion・product type。
 * @param[out] native OSのnative architecture。
 * @return 取得0、APIの失敗HRESULT。
 */
NativeError nativeVersion( OSVERSIONINFOEXW &version, SYSTEM_INFO &native)
{
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
	// このthreadの明示API集合だけを同期借用する。
	if( testApi != nullptr) {
		return testApi->version( version, native) ;
	}
#endif
	// 所有された完全内部表以外は固定native経路です。
	if( const auto api = inf_dependency_native_detail::activeApi() ; api != nullptr) {
		return api->version( version, native) ;
	}

	using VersionFunction = LONG( WINAPI *)( OSVERSIONINFOEXW *) ;	// RtlGetVersionのEX対応ABI。
	const HMODULE module  = GetModuleHandleW( L"ntdll.dll") ;		// process内の非所有module。
	// Windows関数addressを公式layoutの同期署名へ変換するAPI境界。
	const auto	  query = module == nullptr ? nullptr
											: reinterpret_cast<VersionFunction>( GetProcAddress(
												  module, "RtlGetVersion")) ;	// 非所有の関数pointer。
	// 関数不在または照会失敗を未知OSとして止める。
	if( query == nullptr || query( &version) != 0) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	GetNativeSystemInfo( &native) ;
	return 0 ;
}

/** @brief OS起点を取得する。環境変数や任意入力を使用しない。
 * @param[out] path 成功時の終端を除いた有限位置。
 * @return 取得0、容量またはAPI失敗HRESULT。
 */
NativeError nativeWindowsDirectory( std::wstring &path)
{
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
	// このthreadの明示API集合だけを同期借用する。
	if( testApi != nullptr) {
		return testApi->windowsDirectory( path) ;
	}
#endif
	// 起点だけを任意の製品設定へ公開しません。
	if( const auto api = inf_dependency_native_detail::activeApi() ; api != nullptr) {
		return api->windowsDirectory( path) ;
	}

	std::array<wchar_t, MAX_PATH> windows{} ;	// 実Windows位置の有限buffer。
	const UINT					  count =
		// 明示OS起点。
		GetWindowsDirectoryW( windows.data(), static_cast<UINT>( windows.size())) ;
	// 過長や空の起点を有効なprefixにしない。
	if( count == 0U || count >= windows.size()) {
		return count == 0U ? winError( GetLastError()) : E_INVALIDARG ;
	}

	path.assign( windows.data(), count) ;
	return 0 ;
}

/** @brief INF自身の現OS署名情報を取得する。
 * @param[in] path 固定INFの絶対位置。
 * @param[in,out] signer cbSizeを設定した有限応答。
 * @return 署名情報取得0、元の失敗HRESULT。
 */
NativeError nativeInfSignature( const std::wstring &path, SP_INF_SIGNER_INFO_W &signer)
{
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
	// 架空署名を実trust処理へ渡さない専用compile境界。
	if( testApi != nullptr) {
		return testApi->infSignature( path, signer) ;
	}
#endif
	// 同workerの完全表を使用し、不完全な実署名混在を行いません。
	if( const auto api = inf_dependency_native_detail::activeApi() ; api != nullptr) {
		return api->infSignature( path, signer) ;
	}

	return driver_package_signature_detail::setupVerifyInf( path.c_str(), nullptr, &signer)
			   ? 0
			   : winError( GetLastError()) ;
}

/** @brief 同じCATとINF memberを共通署名検証へ渡す。
 * @param[in] catalog 安全に固定したCAT位置。
 * @param[in] members 同期借用するINF member集合。
 * @return 検証0、元の失敗HRESULT。
 */
NativeError nativeCatalogSignature( const std::wstring			&catalog,
								   std::span<const std::wstring> members)
{
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
	// 専用targetでは必須callbackでOS trust通信を置換する。
	if( testApi != nullptr) {
		return testApi->catalogSignature( catalog, members) ;
	}
#endif
	// 全memberを同じ低位表へ渡します。
	if( const auto api = inf_dependency_native_detail::activeApi() ; api != nullptr) {
		return api->catalogSignature( catalog, members) ;
	}

	return verifyOfficialCatalogMembers( catalog, members) ;
}

/** @brief 現OSの対応Store位置を有限に取得する。
 * @param[in] path 固定INF位置。
 * @param[out] location 成功時の有限対応位置。
 * @return 照会0、応答不正または元の失敗HRESULT。
 */
NativeError nativeDriverStore( const std::wstring &path, std::wstring &location)
{
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
	// 元INFへの対応変更だけを注入し、実byte読取は置換しない。
	if( testApi != nullptr) {
		return testApi->driverStore( path, location) ;
	}
#endif
	// 対応Storeだけを実SYSTEMへfallbackしません。
	if( const auto api = inf_dependency_native_detail::activeApi() ; api != nullptr) {
		return api->driverStore( path, location) ;
	}

	std::array<wchar_t, MAX_PATH> store{} ;		// OS対応位置の有限buffer。
	DWORD						  required{} ;	// 終端を含む必要容量。
	// 失敗を空の成功応答へ変換しない。
	if( !SetupGetInfDriverStoreLocationW( path.c_str(), nullptr, nullptr, store.data(),
										static_cast<DWORD>( store.size()), &required)) {
		return winError( GetLastError()) ;
	}

	// 元APIの不正終端と容量超過を止める。
	if( required == 0U || required > store.size() || store[required - 1U] != L'\0') {
		return E_UNEXPECTED ;
	}

	location.assign( store.data(), required - 1U) ;
	return 0 ;
}

/** @brief 開いたhandleの実属性を取得する。
 * @param[in] handle 同期借用する固定handle。
 * @param[out] attributes 実属性または専用targetの架空応答。
 * @return 照会0、元の失敗HRESULT。
 */
NativeError nativeAttributes( HANDLE handle, FILE_ATTRIBUTE_TAG_INFO &attributes)
{
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
	// 任意属性注入がない場合は実APIを維持する。
	if( testApi != nullptr && testApi->attributes) {
		return testApi->attributes( handle, attributes) ;
	}
#endif
	return GetFileInformationByHandleEx( handle, FileAttributeTagInfo, &attributes,
										sizeof( attributes))
			   ? 0
			   : winError( GetLastError()) ;
}

/** @brief Windows handleを単独所有して全return経路で閉じる。 */
struct HandleCloser {
	/** @brief 有効な所有handleを閉じる。
	 * @param[in] value 所有する一handle。
	 */
	void operator()( void *value) const noexcept
	{
		// nullptrは未取得、INVALID_HANDLE_VALUEは取得失敗で解放しない。
		if( value != nullptr && value != INVALID_HANDLE_VALUE) {
			CloseHandle( value) ;
		}
	}
} ;
/**
 * @brief 所有handleのRAII型。
 */
using Handle = std::unique_ptr<void, HandleCloser> ;

/** @brief 固定fileと全祖先のhandle・原hashを所有する。 */
struct PinnedFile {
	/// 正規化せず確認したlocal絶対位置。
	std::wstring			   path ;
	/// run中のrenameを拒否する全祖先directory。
	std::vector<Handle>		   parents ;
	/// 書込み／削除を共有しない通常file。
	Handle					   file ;
	/// 開始時のvolume・file identityとsize。
	BY_HANDLE_FILE_INFORMATION information{} ;
	/// 原byteの小文字SHA-256。
	std::wstring			   sha256 ;
	/// 1以上の固定size。
	std::uint64_t			   bytes{} ;
} ;

/** @brief pathとhandleの同じ位置・種類を確認する。
 * @param[in] handle 固定済みのfile／directory。
 * @param[in] path 終端付き通常DOS位置。
 * @param[in] directory directoryを期待する場合true。
 * @return 境界一致0、reparse・位置差・API失敗のHRESULT。
 */
NativeError checkHandle( HANDLE handle, const std::wstring &path, bool directory)
{
	FILE_ATTRIBUTE_TAG_INFO attributes{} ;	// Handleが示す実属性。
	// 名前の属性だけでreparseや異なる種類を採用しない。
	const auto attributeError = nativeAttributes( handle, attributes) ;	// 属性の独立照会。
	// 元API診断を後続位置検査で消さない。
	if( attributeError != 0) {
		return attributeError ;
	}

	// Reparseの最終参照先を通常fileとして読み替えない。
	if( (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U ||
	   ((attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) != directory) {
		return HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
	}

	std::array<wchar_t, MAX_PATH + 4U> finalPath{} ;	// DOS接頭辞を含む有限最終位置。
	const DWORD						   count =
		GetFinalPathNameByHandleW( handle, finalPath.data(), static_cast<DWORD>( finalPath.size()),
								  FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;	// 実位置。
	// 異なる位置や過長応答は固定済みpathへ結合できない。
	if( count == 0U || count >= finalPath.size()) {
		return count == 0U ? winError( GetLastError()) : HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
	}

	const std::wstring_view name( finalPath.data(), count) ;	// 終端を除く応答。
	return name.starts_with( L"\\\\?\\") && equalName( name.substr( 4U), path)
			   ? 0
			   : HRESULT_FROM_WIN32( ERROR_FILE_INVALID) ;
}

/** @brief 開始と終了の物理file・size・時刻を比較する。
 * @param[in] left 開始観測。
 * @param[in] right 再観測。
 * @return 同じfile・size・最終書込時刻の場合true。
 */
bool sameFile( const BY_HANDLE_FILE_INFORMATION &left, const BY_HANDLE_FILE_INFORMATION &right)
{
	return left.dwVolumeSerialNumber == right.dwVolumeSerialNumber &&
		   left.nFileIndexHigh == right.nFileIndexHigh &&
		   left.nFileIndexLow == right.nFileIndexLow && left.nFileSizeHigh == right.nFileSizeHigh &&
		   left.nFileSizeLow == right.nFileSizeLow &&
		   left.ftLastWriteTime.dwHighDateTime == right.ftLastWriteTime.dwHighDateTime &&
		   left.ftLastWriteTime.dwLowDateTime == right.ftLastWriteTime.dwLowDateTime ;
}

/** @brief 実OS version・product typeとnative x64を取得する。
 * @param[in] observationId 非零のrun世代。
 * @param[out] context 成功時の実OS文脈。
 * @return 完了0、未知OSまたはAPI失敗のHRESULT。
 */
NativeError currentContext( std::uint64_t observationId, InfDependencyContext &context)
{
	OSVERSIONINFOEXW version{} ;	// 実versionとproduct type。
	version.dwOSVersionInfoSize = sizeof( version) ;
	SYSTEM_INFO native{} ;									// OSのnative architecture。
	const auto	error = nativeVersion( version, native) ;	// 開始／終了の独立OS照会。
	// 元APIの失敗後に構造体の零値から文脈を生成しない。
	if( error != 0) {
		return error ;
	}

	// 未知product typeをclientと推測せず、x64以外も拒否する。
	if( version.dwMajorVersion == 0U || version.dwBuildNumber == 0U || observationId == 0U ||
	   native.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 ||
	   (version.wProductType != VER_NT_WORKSTATION && version.wProductType != VER_NT_SERVER &&
		version.wProductType != VER_NT_DOMAIN_CONTROLLER)) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	context = {version.dwMajorVersion,
			   version.dwMinorVersion,
			   version.dwBuildNumber,
			   0x8664U,
			   version.wProductType != VER_NT_WORKSTATION,
			   observationId} ;
	return 0 ;
}

/** @brief 全値が同じOS／run文脈であることを確認する。
 * @param[in] left 開始値。
 * @param[in] right 再確認値。
 * @return 全field一致の場合true。
 */
bool sameContext( const InfDependencyContext &left, const InfDependencyContext &right)
{
	return left.major == right.major && left.minor == right.minor && left.build == right.build &&
		   left.machine == right.machine && left.windowsServer == right.windowsServer &&
		   left.observationId == right.observationId ;
}

/** @brief 一INF handleを所有する。Appendや導入を行わない。 */
struct InfCloser {
	/** @brief 単独のINF解析handleを閉じる。
	 * @param[in] value 所有する有効handle。
	 */
	void operator()( void *value) const noexcept
	{
		SetupCloseInfFile( value) ;
	}
} ;
/**
 * @brief 単独INFのRAII型。
 */
using InfHandle = std::unique_ptr<void, InfCloser> ;

/** @brief fieldの原値を有限bufferへ取得する。
 * @param[in,out] line SetupAPIの同期context。
 * @param[in] index keyは0、valueは1以上。
 * @param[out] value 成功時の有限field。
 * @return 完了0、過長またはSetupAPI失敗のHRESULT。
 */
NativeError field( INFCONTEXT &line, DWORD index, std::wstring &value)
{
	std::array<wchar_t, 255U> buffer{} ;	// 最大254文字と終端。
	DWORD					  required{} ;	// SetupAPI応答の必要容量。
	// 過長名を切り捨てて別のfile／節へ照合しない。
	if( !SetupGetStringFieldW( &line, index, buffer.data(), static_cast<DWORD>( buffer.size()),
							 &required)) {
		return winError( GetLastError()) ;
	}

	// 終端不正や過大の応答も全体拒否する。
	if( required == 0U || required > buffer.size() || buffer[required - 1U] != L'\0') {
		return E_UNEXPECTED ;
	}

	value.assign( buffer.data(), required - 1U) ;
	return 0 ;
}

/** @brief Needs到達先のAddRegを明示文脈と全行の有限policyへ照合します。
 * @param[in] inf 同同期の検証済みdocument読取handleです。
 * @param[in,out] line 元到達節のAddReg行です。呼出し中だけ借用します。
 * @param[in] contexts DDInstallは1、HWは2、未対応文脈は4のbit集合です。
 * @param[in,out] registryRows 全Needsの累積行数です。4096を上限とします。
 * @return 全行確認0、元読取または未対応のHRESULTです。書込みは行いません。
 */
NativeError verifyNeedsAddReg( const HINF inf, INFCONTEXT &line, const unsigned char contexts,
							  std::size_t &registryRows)
{
	const DWORD references = SetupGetFieldCount( &line) ;	// 一AddRegの全参照数です。
	// 未選択・Services等の未対応文脈と過大参照を切り捨てません。
	if( contexts == 0U || (contexts & ~3U) != 0U || references == 0U || references > 64U ||
	   registryRows > 4096U) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// 正確な同documentの全参照先を読み、後続の不正行も拒否します。
	for( DWORD reference = 1U; reference <= references; ++reference) {
		std::wstring section ;									// 元AddRegの完全な参照節名です。
		auto		 error = field( line, reference, section) ;	// 有限な同元field読取です。
		// 欠損・制御文字を任意節の指定へ変換しません。
		if( error != 0U || section.empty() || section.find_first_of( L"[]\r\n") != section.npos) {
			return error != 0U ? error : E_INVALIDARG ;
		}

		const auto security = section + L".security" ;	// 未採用のACL作用を検出する正確な節です。
		SetLastError( ERROR_SUCCESS) ;
		const LONG securityRows = SetupGetLineCountW( inf, security.c_str()) ;	// 空節も作用宣言です。
		// security宣言を通常設定値へ縮約しません。
		if( securityRows >= 0) {
			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}

		const DWORD securityError = GetLastError() ;	// 不在以外のAPI失敗です。
		// 不正なsecurity節読取を不在へ補完しません。
		if( securityError != ERROR_SUCCESS && securityError != ERROR_SECTION_NOT_FOUND) {
			return winError( securityError) ;
		}

		const LONG rows = SetupGetLineCountW( inf, section.c_str()) ;	// 同元節の全行数です。
		// 累積4096行を読み始める前に検査し、欠損節を空設定へ変換しません。
		if( rows < 0 || static_cast<std::size_t>( rows) > 4096U - registryRows) {
			return rows < 0 ? HRESULT_FROM_WIN32( ERROR_SECTION_NOT_FOUND)
							: HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		// 全行のroot・型・値を確認し、一つでも未対応なら全効果を拒否します。
		for( LONG row = 0L; row < rows; ++row) {
			INFCONTEXT setting{} ;	// 同元registry設定の一行です。
			// 別節や不完全な行を先頭行で補完しません。
			if( !SetupGetLineByIndexW( inf, section.c_str(), static_cast<DWORD>( row), &setting)) {
				return winError( GetLastError()) ;
			}

			const DWORD fields = SetupGetFieldCount( &setting) ;	// 一つの値だけの最大5fieldです。
			// 削除/複数binary等の別構文を切り捨てて許可しません。
			if( fields < 3U || fields > 5U) {
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}

			std::array<std::wstring, 5U> values ;	// 全fieldを有限長で所有します。
			// flagsや値も含め全fieldを読むため、途中の長さ違反を省略しません。
			for( DWORD index = 1U; index <= fields; ++index) {
				error = field( setting, index, values[index - 1U]) ;
				// 全fieldの元取得失敗を保持します。
				if( error != 0U) {
					return error ;
				}
			}

			// HKR以外は同device設定の範囲へ補完しません。
			if( !equalName( values[0], L"HKR")) {
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}

			const auto &subkey = values[1] ;	// 同文脈の相対registry keyだけです。
			std::size_t begin{} ;				// 空subkeyは元相対rootを表します。
			// 空以外の全componentで絶対指定・制御文字・親移動を拒否します。
			while( begin < subkey.size()) {
				const auto end = subkey.find( L'\\', begin) ;	// 元component境界です。
				// 正規化前の同componentだけを同期借用します。
				const auto part =
					std::wstring_view( subkey).substr( begin, end == subkey.npos ? end : end - begin) ;
				// registry keyをpath正規化で別の有効keyへ変えません。
				if( part.empty() || part == L"." || part == L".." ||
				   std::ranges::any_of( part, []( const wchar_t value) {
					   return value < L' ' || value > L'~' || value == L'/' || value == L':' ;
				   })) {
					return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
				}

				begin = end == subkey.npos ? subkey.size() : end + 1U ;
			}

			// 末尾separatorも別のkeyへ暗黙補正しません。
			if( !subkey.empty() && subkey.back() == L'\\') {
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}

			constexpr std::array<std::wstring_view, 9U> SPECIAL_VALUES{
				L"CoInstallers32", L"Installer32", L"EnumPropPages32", L"UpperFilters",
				L"LowerFilters",   L"Security",	   L"DeviceLoader",	   L"Run",
				L"RunOnce"} ;	// 実行/ACL/filterを通常設定へ混ぜません。
			// 既知の別作用登録は一device内でも別検証を必要とします。
			if( std::ranges::any_of( SPECIAL_VALUES,
								   [&]( const auto name) { return equalName( values[2], name) ; })) {
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}

			int flags{} ;	// 省略/空flagsの既定REG_SZです。
			// 数値flagsの解析失敗を0へ変換しません。
			if( !values[3].empty() && !SetupGetIntField( &setting, 4U, &flags)) {
				return E_INVALIDARG ;
			}

			// 型以外の変更flag、未採用型、削除やkey権限変更を拒否します。
			if( flags != 0 && flags != 0x00010001 && flags != 0x00020000) {
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}

			int dword{} ;	// DWORDの全値をWindowsの同じ数値parserへ照合します。
			// 不正型や欠損DWORDを文字列として許可しません。
			if( flags == 0x00010001 && (fields != 5U || !SetupGetIntField( &setting, 5U, &dword))) {
				return E_INVALIDARG ;
			}

			std::wstring lower = values[4] ;	// 実行file参照を検出する端末内copyです。
			// ASCIIの大小文字だけを同値化し、元値は出力しません。
			for( auto &value : lower) {
				value = value >= L'A' && value <= L'Z' ? static_cast<wchar_t>( value - L'A' + L'a')
													   : value ;
			}

			// 未照合のfile登録を単なる設定文字列へ弱めません。
			if( lower.find( L".exe") != lower.npos || lower.find( L".dll") != lower.npos ||
			   lower.find( L".sys") != lower.npos || lower.find( L".com") != lower.npos) {
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}

			++registryRows ;
		}
	}

	return 0U ;
}

/** @brief 元選択seedから正確なNeeds辺だけへHKRの設置文脈を伝播します。
 * @param[in] result 解決と全証拠を別に確認済みの同graphです。
 * @param[in] seeds 元DDInstallと実在付随節です。先頭が基本選択です。
 * @param[in] rootIdentity 同graphの元内容documentです。
 * @return sectionsと同順の文脈bitです。未到達は0、未対応の経路は4を保持します。
 */
std::vector<unsigned char> needsRegistryContexts( const InfDependencyNativeResult	&result,
												 const std::span<const std::wstring> seeds,
												 const std::uint64_t				 rootIdentity)
{
	std::vector<unsigned char> contexts(
		// 同graphの固定ordinalです。
		result.dependency.sections.size()) ;
	std::vector<std::size_t> pending ;	// 各bitの追加時だけ処理し最大3×1024項目です。
	// 同rootの実在seedだけに文脈を付け、節名のsuffixから別INFを推測しません。
	for( std::size_t index = 0U; index < result.dependency.sections.size(); ++index) {
		const auto &section = result.dependency.sections[index] ;	// 元訪問節です。
		// 別documentや未選択節はseedへ昇格しません。
		if( section.identity == rootIdentity &&
		   std::ranges::find( seeds, section.section) != seeds.end()) {
			contexts[index] = equalName( section.section, seeds.front())			   ? 1U
							  : equalName( section.section, seeds.front() + L".HW") ? 2U
																				   : 4U ;
			pending.push_back( index) ;
		}
	}

	// 有限graphの元参照だけを辿り、混在する未対応文脈も消しません。
	for( std::size_t position = 0U; position < pending.size(); ++position) {
		const auto source = pending[position] ;	// 直前に文脈が増えた同元節です。
		// 元Needsの全参照を処理し、共通節へ複数文脈が流れた事実を保持します。
		for( const auto &edge : result.dependency.edges) {
			// Include自体は設置文脈を持つ効果節ではありません。
			if( edge.directive != InfDependencyDirective::NEEDS ||
			   edge.sourceIdentity != result.dependency.sections[source].identity ||
			   !equalName( edge.sourceSection, result.dependency.sections[source].section)) {
				continue ;
			}

			// 元target identityと完全節名の一意な対象だけへ伝播します。
			for( std::size_t target = 0U; target < contexts.size(); ++target) {
				const auto &section = result.dependency.sections[target] ;	// 元対象節です。
				const auto	merged	= static_cast<unsigned char>(
					  contexts[target] | contexts[source]) ;	// 全incoming文脈です。
				// 新bitがない共有節は再処理しません。
				if( section.identity == edge.targetIdentity &&
				   equalName( section.section, edge.target) && merged != contexts[target]) {
					contexts[target] = merged ;
					pending.push_back( target) ;
				}
			}
		}
	}

	return contexts ;
}

/** @brief 実loaderの固定documentと署名根拠。 */
struct NativeDocument {
	/// 共通核へ渡す独立証拠。
	InfDependencyDocument	   value ;
	/// 固定INF fileの安定位置。
	std::size_t				   fileIndex{} ;
	/// 未取得ならMAX_FILESの署名CAT位置。
	std::size_t				   catalogIndex{MAX_FILES} ;
	/// 未取得ならMAX_FILESの対応Driver Store INF位置。
	std::size_t				   storeIndex{MAX_FILES} ;
	/// SetupAPIが返した元署名分類。maskしない。
	DWORD					   signerScore{SIGNERSCORE_UNKNOWN} ;
	/// 元診断を保持する独立finding。
	InfDependencyNativeFinding finding ;
} ;

/** @brief 一同期runのfile固定・OS根拠とcallbackを所有する。 */
class NativeLoader {
public:
	/** @brief 保護workspaceと閉じたmember一覧を同期借用する。
	 * @param[in] workspace package所有領域。
	 * @param[in] members 全INF memberの固定一覧。
	 * @param[in] context 開始OS観測。
	 * @param[in] binding 使用中固定の封印所有者。旧経路ではnullptr。
	 * @param[in] session 同じ生存issuer。旧経路ではnullptr。
	 * @param[in] archiveWorkspace 元取得領域。旧経路ではnullptr。
	 * @param[in] content 元Common検査の所有結果。旧経路ではnullptr。
	 * @param[out] diagnostic 元HRESULTを変更しない任意の数値診断です。
	 */
	NativeLoader( const OfficialDownloadWorkspace			&workspace,
				 std::span<const InfDependencyPackageMember> members,
				 const InfDependencyContext &context, const OfficialInfArchiveBinding *binding,
				 const OfficialAcquisitionSession *session,
				 const OfficialDownloadWorkspace  *archiveWorkspace,
				 const CommonInfInspection		  *content	  = nullptr,
				 RequiredInfBindingDiagnostic	  *diagnostic = nullptr)
		: workspace_( workspace), members_( members), context_( context), binding_( binding),
		  session_( session), archiveWorkspace_( archiveWorkspace), content_( content),
		  diagnostic_( diagnostic)
	{
	}
	/** @brief rootを固定し共通核と全根拠の再確認へ接続する。
	 * @param[in] rootIndex 開始member位置。
	 * @param[in] seeds 明示節群。
	 * @param[out] result 全成功時だけ保持する非実行結果。
	 * @return 完了0、最初のHRESULT。
	 */
	NativeError run( std::size_t rootIndex, std::span<const std::wstring> seeds,
					InfDependencyNativeResult &result) ;

private:
	/// 呼出し終了まで有効なpackage所有者。
	const OfficialDownloadWorkspace			   &workspace_ ;
	/// 呼出し中固定される全INF member。
	std::span<const InfDependencyPackageMember> members_ ;
	/// run開始時のOSと観測ID。
	InfDependencyContext						context_ ;
	/// 呼出し終了まで全元／派生fileを固定する非所有の封印結果。旧経路はnullptr。
	const OfficialInfArchiveBinding			   *binding_ ;
	/// 封印結果を発行した非所有の生存issuer。旧経路はnullptr。
	const OfficialAcquisitionSession		   *session_ ;
	/// 非所有の元取得領域。旧経路はnullptr。
	const OfficialDownloadWorkspace			   *archiveWorkspace_ ;
	/// 私有factoryだけが渡す、全byteとCATを前後確認する元内容です。
	const CommonInfInspection				   *content_ ;
	/// 同期callだけが所有する任意の非機密診断先です。実行可否へ読み込みません。
	RequiredInfBindingDiagnostic			   *diagnostic_ ;
	/// run中保持するINF・CAT・対応Store file。最大256。
	std::vector<std::unique_ptr<PinnedFile>>	files_ ;
	/// 共通核と同じ一意document。最大64。
	std::vector<NativeDocument>					documents_ ;
	/// 全固定fileの累積実byte。最大128 MiB。
	std::uint64_t								totalBytes_{} ;
	/// APIで取得した現在Windows directory。
	std::wstring								windows_ ;
	/// Workspace内のroot基準位置。
	std::wstring								packageRoot_ ;

	/** @brief fileと全祖先を安全に固定し実hashを計算する。
	 * @param[in] path 検査対象の通常絶対位置。
	 * @param[in] maximumBytes 一file上限。
	 * @param[out] index 成功時の固定file位置。
	 * @param[out] missing 明示openの不在だけを返す任意出力。nullptr可。
	 * @return 完了0、path・容量・読取失敗のHRESULT。
	 */
	NativeError		pin( const std::wstring &path, std::uint64_t maximumBytes, std::size_t &index,
						bool *missing = nullptr) ;
	/** @brief 固定fileのpath・identity・hashを再確認する。
	 * @param[in] index 安定したfile位置。
	 * @return 全一致0、改変／API失敗のHRESULT。
	 */
	NativeError		recheckFile( std::size_t index) ;
	/** @brief byte固定した一INFと署名／system由来を保持する。
	 * @param[in] path 候補の実位置。
	 * @param[in] member package期待member。systemではnullptr。
	 * @param[out] document 成功時の共通snapshot。
	 * @param[out] fileMissing INF自身の明示openで不在を観測した場合だけtrue。nullptr可。
	 * @return 存在観測完了0、byte／path等の全体失敗HRESULT。
	 */
	NativeError		observe( const std::wstring &path, const InfDependencyPackageMember *member,
							InfDependencyDocument &document, bool *fileMissing = nullptr) ;
	/** @brief 署名と由来の根拠をbyte固定する。失敗もfindingに残す。
	 * @param[in,out] document 安定したINF snapshotと根拠位置。
	 * @return 境界確認完了0、固定fileの重大失敗HRESULT。
	 */
	NativeError		trust( NativeDocument &document) ;
	/** @brief 検証済み署名のCAT位置・完全score・memberを終了時に再確認する。
	 * @param[in] document 開始時に固定した署名根拠。
	 * @return 全一致0、失効・根拠変更・API失敗のHRESULT。
	 */
	NativeError		recheckTrust( const NativeDocument &document) ;
	/** @brief 同節Includeの明示候補を全照会する。
	 * @param[in] source 元の固定document。
	 * @param[in] target 有限Include相対名。
	 * @param[out] output 全照会成功時の候補。
	 * @return 完了0、最初の全体HRESULT。
	 */
	NativeError		lookup( const InfDependencyDocument &source, std::wstring_view target,
						   InfDependencyLookup &output) ;
	/** @brief 一固定INFの明示節からInclude／Needsだけを読む。
	 * @param[in] document 固定snapshot。
	 * @param[in] name 原明示節名。
	 * @param[out] output 完了時の存在状態と有限参照。
	 * @return 完了0、構文・容量・改変のHRESULT。
	 */
	NativeError		section( const InfDependencyDocument &document, std::wstring_view name,
							InfDependencySection &output) ;
	/** @brief 共通identityから固定documentを取得する。
	 * @param[in] identity 非零のrun内identity。
	 * @return 存在すれば借用pointer、不明ならnullptr。
	 */
	NativeDocument *find( std::uint64_t identity) ;
	/** @brief Needs先の有限CopyFilesを実byteとCATへ結合し、AddRegの到達効果を検査します。
	 * @param[in] result 解決済みの同run graphです。
	 * @param[in] seeds 元選択DDInstallと実在付随節です。
	 * @return 全効果確認0、未知・欠損・署名・byte差のHRESULTです。
	 */
	NativeError		verifyNeedsEffects( const InfDependencyNativeResult &result,
									   std::span<const std::wstring>	seeds) ;
	/** @brief 全到達節とVersion／sourceのfile用途を非実行で観測する。
	 * @param[in,out] result 全体成功前のgraphと有限用途観測。
	 * @return 全行観測成功0、入力・読取・容量・元byte差のHRESULT。
	 * @note payload位置と全member署名は解決せず、実SYSTEM fileを複写しない。
	 */
	NativeError		observeFileUses( InfDependencyNativeResult &result) ;
} ;

} // namespace

/** @see src/platform/inf_dependency_native.h 宣言側の契約を正本とする。 */
bool validInfDependencyPath( std::wstring_view path, bool absolute) noexcept
{
	// 通常DOS位置以外や埋込みNULを正規化で救済しない。
	if( path.empty() || path.size() >= MAX_PATH ||
	   (absolute &&
		(path.size() < 4U || path[1] != L':' || path[2] != L'\\' ||
		 !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'))))) {
		return false ;
	}

	std::size_t begin = absolute ? 3U : 0U ;	// driveを除いたcomponent開始。
	// 全componentでpath切替・device aliasと末尾正規化を拒否する。
	while( begin < path.size()) {
		const auto end	= path.find( L'\\', begin) ;									// 次componentの境界。
		const auto part = path.substr( begin, end == path.npos ? end : end - begin) ;	// 有限借用。
		// ASCII相対名と絶対位置の制御・予約文字を確認する。
		if( part.empty() || part == L"." || part == L".." || part.back() == L'.' ||
		   part.back() == L' ' || reservedName( part) ||
		   std::ranges::any_of( part, [absolute]( wchar_t value) {
			   // 相対名は既存workspaceと同じASCII境界に限定する。
			   return value < L' ' || value == 0x7f || (!absolute && value > 0x7e) ||
					  std::wstring_view( L"/:<>|\"?*%").find( value) != std::wstring_view::npos ;
		   })) {
			return false ;
		}

		// 最後のcomponentを確認したら完了する。
		if( end == path.npos) {
			return true ;
		}

		begin = end + 1U ;
	}

	return false ;
}

namespace {
/** @see NativeLoader 宣言側の契約を正本とする。 */
NativeError NativeLoader::pin( const std::wstring &path, std::uint64_t maximumBytes,
							  std::size_t &index, bool *missing)
{
	// 再確認・属性等の失敗をopen不在へ変換しない初期値。
	if( missing != nullptr) {
		*missing = false ;
	}

	// Cached pathも要求size境界を変更しない。
	for( std::size_t position = 0U; position < files_.size(); ++position) {
		// 同じ確認済みpathだけを再利用する。
		if( equalName( files_[position]->path, path)) {
			index = position ;
			return files_[position]->bytes <= maximumBytes
					   ? recheckFile( position)
					   : HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}
	}

	// 過大集合と任意pathからfileを開かない。
	if( !validInfDependencyPath( path, true) || files_.size() >= MAX_FILES) {
		return E_INVALIDARG ;
	}

	auto pinned	 = std::make_unique<PinnedFile>() ;	// run全体へ移す単独所有者。
	pinned->path = path ;
	// 祖先をrootから順に固定し、子を開く前にreparseを拒否する。
	for( std::size_t end = 3U; end < path.size(); ++end) {
		// Component境界だけをdirectoryとして確認する。
		if( end != 3U && path[end] != L'\\') {
			continue ;
		}

		const std::wstring parent = path.substr( 0U, end) ;	// drive rootは終端separatorを含む。
		// 子を開く間のrenameを拒否する祖先handle。
		Handle			   handle( CreateFileW(
			parent.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
			OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;
		// Directoryを固定できなければ子の読取りへ進まない。
		if( handle.get() == INVALID_HANDLE_VALUE) {
			return openError( GetLastError(), missing) ;
		}

		const auto error = checkHandle( handle.get(), parent, true) ;	// 実位置・属性の一致。
		// Reparseや位置差の根拠を後続成功で消さない。
		if( error != 0) {
			return error ;
		}

		pinned->parents.push_back( std::move( handle)) ;
	}

	pinned->file.reset(
		CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
					FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)) ;
	// File不在と既存writerとの競合を元診断で返す。
	if( pinned->file.get() == INVALID_HANDLE_VALUE) {
		return openError( GetLastError(), missing) ;
	}

	NativeError error = checkHandle( pinned->file.get(), path, false) ;	// 実fileの固定境界。
	// File属性・identity取得を成功条件に含める。
	if( error != 0 || !GetFileInformationByHandle( pinned->file.get(), &pinned->information)) {
		return error != 0 ? error : winError( GetLastError()) ;
	}

	pinned->bytes = (static_cast<std::uint64_t>( pinned->information.nFileSizeHigh) << 32U) |
					pinned->information.nFileSizeLow ;
	// size上限をhash読取前に確認し、全固定byte予算にも含める。
	if( pinned->bytes == 0U || pinned->bytes > maximumBytes ||
	   pinned->bytes > MAX_TOTAL_BYTES - totalBytes_) {
		return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
	}

	error = computeFileSha256( path, pinned->sha256) ;
	// 固定失敗のfileをcacheへ入れない。
	if( error != 0) {
		return error ;
	}

	index = files_.size() ;
	totalBytes_ += pinned->bytes ;
	files_.push_back( std::move( pinned)) ;
	return recheckFile( index) ;
}

/** @see NativeLoader 宣言側の契約を正本とする。 */
NativeError NativeLoader::recheckFile( std::size_t index)
{
	const auto				  &file = *files_.at( index) ;					// 同期run内の安定所有者。
	BY_HANDLE_FILE_INFORMATION information{} ;								// 終了時の物理identity。
	NativeError error = checkHandle( file.file.get(), file.path, false) ;	// 位置と種類の再確認。
	// Byte再確認前にfile差替えを止める。
	if( error != 0 || !GetFileInformationByHandle( file.file.get(), &information)) {
		return error != 0 ? error : winError( GetLastError()) ;
	}

	// 同hashに見えても異なる物理fileや書込時刻への差替えを許可しない。
	if( !sameFile( file.information, information)) {
		return HRESULT_FROM_WIN32( ERROR_FILE_INVALID) ;
	}

	std::wstring hash ;	// 完全byteの終了hash。
	error = computeFileSha256( file.path, hash) ;
	return error != 0 ? error : (hash == file.sha256 ? 0 : HRESULT_FROM_WIN32( ERROR_FILE_INVALID)) ;
}

/** @see NativeLoader 宣言側の契約を正本とする。 */
NativeDocument *NativeLoader::find( std::uint64_t identity)
{
	const auto found = std::ranges::find_if( documents_, [identity]( const auto &document) {
		// Nameやhashからidentityを推測しない。
		return document.value.identity == identity ;
	}) ;
	return found == documents_.end() ? nullptr : &*found ;
}

/** @see NativeLoader 宣言側の契約を正本とする。 */
NativeError NativeLoader::observe( const std::wstring			   &path,
								  const InfDependencyPackageMember *member,
								  InfDependencyDocument &document, bool *fileMissing)
{
	std::size_t file{} ;	// 候補INFの固定file位置。
	NativeError error =
		// 明示不在とbyte結合を分離する。
		pin( path, MAX_INF_BYTES, file, fileMissing) ;
	// 実byteが読めない場合を存在観測へ弱めない。
	if( error != 0) {
		return error ;
	}

	// 抽出器が保持した実期待値と結合する。
	if( member != nullptr &&
	   (files_[file]->sha256 != member->sha256 || files_[file]->bytes != member->byteCount)) {
		return HRESULT_FROM_WIN32( ERROR_FILE_INVALID) ;
	}

	// 位置の境界分類。由来検証の成功とは別の値。
	const auto origin =
		member == nullptr ? InfDependencyOrigin::SYSTEM : InfDependencyOrigin::PACKAGE ;
	// 同じ物理fileの別名だけを共有し、同hashの別fileを合併しない。
	for( const auto &prior : documents_) {
		// 物理identityは開いた実handleから比較する。
		if( sameFile( files_[prior.fileIndex]->information, files_[file]->information)) {
			// 別の由来へ同identityを持ち替えない。
			if( prior.value.origin != origin) {
				return HRESULT_FROM_WIN32( ERROR_FILE_INVALID) ;
			}

			document = prior.value ;
			return 0 ;
		}
	}

	// 核に到達する前にも全documentの有限数を確認する。
	if( documents_.size() >= 64U) {
		return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
	}

	NativeDocument observed ;	// 全検査後にだけ共有するsnapshot。
	observed.fileIndex		   = file ;
	observed.value.identity	   = documents_.size() + 1U ;
	observed.value.sha256	   = files_[file]->sha256 ;
	observed.value.byteCount   = files_[file]->bytes ;
	observed.value.origin	   = origin ;
	observed.value.byteBinding = InfDependencyEvidence::VERIFIED ;
	observed.value.context	   = context_ ;
	observed.finding.identity  = observed.value.identity ;
	error					   = trust( observed) ;
	// 固定fileの重大失敗では部分snapshotを残さない。
	if( error != 0) {
		return error ;
	}

	// 封印経路の全集合固定はrun前後に再確認し、署名の成否から由来を推測しない。
	if( member != nullptr && (binding_ != nullptr || content_ != nullptr)) {
		observed.value.provenance = InfDependencyEvidence::VERIFIED ;
	}

	documents_.push_back( std::move( observed)) ;
	document = documents_.back().value ;
	return 0 ;
}

/** @see NativeLoader 宣言側の契約を正本とする。 */
NativeError NativeLoader::trust( NativeDocument &document)
{
	const std::wstring	 path = files_[document.fileIndex]->path ;	// callback内の安定した原位置。
	SP_INF_SIGNER_INFO_W signer{} ;									// 現OSの署名根拠と完全score。
	signer.cbSize = sizeof( signer) ;
	// Windows署名の失敗は存在と分離して元findingに残す。
	const auto signatureError = nativeInfSignature( path, signer) ;	// 元APIの独立診断。
	// 検証失敗でも実byteの存在観測は維持する。
	if( signatureError != 0) {
		document.value.signature		= InfDependencyEvidence::FAILED ;
		document.finding.signatureError = signatureError ;
		return 0 ;
	}

	// 各固定array内の実終端を確認し、NUL以後の未使用slot値を終端の代替条件にしません。
	if( std::wstring_view{signer.CatalogFile, MAX_PATH}.find( L'\0') == std::wstring_view::npos ||
	   std::wstring_view{signer.DigitalSigner, MAX_PATH}.find( L'\0') == std::wstring_view::npos ||
	   signer.CatalogFile[0] == L'\0' || signer.DigitalSigner[0] == L'\0') {
		return E_UNEXPECTED ;
	}

	document.signerScore = signer.SignerScore ;
	const std::wstring catalog( signer.CatalogFile) ;	// 出力しないCATの実位置。
	const auto		   under = [&catalog]( const std::wstring &root) {
		// Root文字列だけの前方一致で別directoryを許可しない。
		return catalog.size() > root.size() &&
			   equalName( std::wstring_view( catalog).substr( 0U, root.size()), root) ;
	} ; // 末尾separator付きの認証範囲だけへ借用照合する。
	const bool allowed = document.value.origin == InfDependencyOrigin::PACKAGE
							 ? under( packageRoot_)
							 : (under( windows_ + L"\\System32\\CatRoot\\") ||
								under( windows_ + L"\\System32\\DriverStore\\FileRepository\\") ||
								// 同じ署名用途の有限領域。
								under( windows_ + L"\\WinSxS\\Catalogs\\")) ;
	// 無関係CATを開かず、signature未充足と存在を分ける。
	if( !allowed || !validInfDependencyPath( catalog, true)) {
		document.value.signature		= InfDependencyEvidence::FAILED ;
		document.finding.signatureError = HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
		return 0 ;
	}

	const OfficialZipEntry *sealedCatalog = nullptr ;	// 封印経路の原CAT metadataの同期借用。
	// 共通内容経路も同保護閉包に元CATがある場合だけ使用します。
	if( document.value.origin == InfDependencyOrigin::PACKAGE && content_ != nullptr) {
		const auto relative =
			// 元CAT相対位置です。
			std::wstring_view( catalog).substr( packageRoot_.size()) ;
		const auto found = std::ranges::find_if( content_->closure.entries, [&]( const auto &entry) {
			return equalName( entry.relativePath, relative) ;
		}) ; // 元の閉じた一覧です。
		// 後付けCATを元署名根拠へ昇格しません。
		if( found == content_->closure.entries.end()) {
			return HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
		}

		sealedCatalog = &*found ;
	}

	// package CATを原container由来の固定一覧へ限定し、後から追加したCATを使わない。
	if( document.value.origin == InfDependencyOrigin::PACKAGE && binding_ != nullptr) {
		const auto relative =
			// 原相対位置。
			std::wstring_view( catalog).substr( packageRoot_.size()) ;
		const auto found =
			std::ranges::find_if( binding_->catalogs(), [&relative]( const auto &member) {
				// 私有封印結果の原位置だけをordinalで照合する。
				return equalName( member.relativePath, relative) ;
			}) ; // bindingは同期runの全期間不変。
		// 未封印CATを署名済みとせず、独立した取得由来はそのまま保持する。
		if( found == binding_->catalogs().end()) {
			document.value.signature		= InfDependencyEvidence::FAILED ;
			document.finding.signatureError = HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
			return 0 ;
		}

		sealedCatalog = &*found ;
	}

	NativeError error = pin( catalog, MAX_CAT_BYTES, document.catalogIndex) ;	// 署名根拠byteの固定。
	// CAT固定の競合・容量・改変を単なる署名不足へ弱めない。
	if( error != 0) {
		return error ;
	}

	// 固定したCATを元size／hashへ一致させ、署名callbackの名前だけで認定しない。
	if( sealedCatalog != nullptr &&
	   (files_[document.catalogIndex]->bytes != sealedCatalog->uncompressedSize ||
		files_[document.catalogIndex]->sha256 != sealedCatalog->sha256)) {
		return TRUST_E_BAD_DIGEST ;
	}

	const std::array<std::wstring, 1U> memberPaths{path} ;	// INF自身だけのmember確認。
	error = nativeCatalogSignature( catalog, memberPaths) ;
	document.value.signature =
		error == 0 ? InfDependencyEvidence::VERIFIED : InfDependencyEvidence::FAILED ;
	document.finding.signatureError = error ;
	// Package公式由来はこのadapterから昇格させない。別scoreも標準INFと推測しない。
	if( error != 0 || document.value.origin != InfDependencyOrigin::SYSTEM ||
	   signer.SignerScore != SIGNERSCORE_INBOX) {
		return 0 ;
	}

	std::wstring storePath ;	// 現在Driver Storeの有限対応位置。
	error = nativeDriverStore( path, storePath) ;
	// 元APIの不正応答は未確認へ弱めない。
	if( error == E_UNEXPECTED) {
		return error ;
	}

	// OSの対応情報がない場合は存在・署名を維持し、由来だけ未検査にする。
	if( error != 0) {
		document.finding.provenanceError = error ;
		return 0 ;
	}

	const std::wstring storeRoot =
		windows_ + L"\\System32\\DriverStore\\FileRepository\\" ;	// 固定用途root。
	// Storeの明示範囲外をsystem由来と認定しない。
	if( storePath.size() <= storeRoot.size() ||
	   !equalName( std::wstring_view( storePath).substr( 0U, storeRoot.size()), storeRoot) ||
	   !validInfDependencyPath( storePath, true)) {
		return HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
	}

	error = pin( storePath, MAX_INF_BYTES, document.storeIndex) ;
	// 対応byteを安全に固定できない結果から由来を生成しない。
	if( error != 0) {
		return error ;
	}

	const auto &original = *files_[document.fileIndex] ;	// 原INF snapshot。
	const auto &stored	 = *files_[document.storeIndex] ;	// OS対応先の固定byte。
	const bool	matched =
		// 完全byte結合。
		original.sha256 == stored.sha256 && original.bytes == stored.bytes ;
	document.value.provenance =
		matched ? InfDependencyEvidence::VERIFIED : InfDependencyEvidence::FAILED ;
	document.finding.provenanceError = matched ? 0 : HRESULT_FROM_WIN32( ERROR_FILE_INVALID) ;
	return 0 ;
}

/** @see NativeLoader 宣言側の契約を正本とする。 */
NativeError NativeLoader::recheckTrust( const NativeDocument &document)
{
	// 未確認／失敗の根拠は再照会で昇格させず、正の証拠だけを失効確認する。
	if( document.value.signature != InfDependencyEvidence::VERIFIED) {
		return 0 ;
	}

	SP_INF_SIGNER_INFO_W signer{} ;	// 終了時の独立した署名応答。
	signer.cbSize	 = sizeof( signer) ;
	const auto &path = files_[document.fileIndex]->path ;	// 固定INFの有限位置。
	// 現在の署名検証失敗後は開始時の成功を使わない。
	const auto	error = nativeInfSignature( path, signer) ;	// 終了時の独立した診断。
	// 検証済み署名の現在の失敗を保持する。
	if( error != 0) {
		return error ;
	}

	// CAT差・分類差と不正終端を同一の証拠とみなさない。
	if( document.catalogIndex == MAX_FILES ||
	   std::wstring_view{signer.CatalogFile, MAX_PATH}.find( L'\0') == std::wstring_view::npos ||
	   std::wstring_view{signer.DigitalSigner, MAX_PATH}.find( L'\0') == std::wstring_view::npos ||
	   signer.CatalogFile[0] == L'\0' || signer.DigitalSigner[0] == L'\0' ||
	   signer.SignerScore != document.signerScore ||
	   !equalName( signer.CatalogFile, files_[document.catalogIndex]->path)) {
		return HRESULT_FROM_WIN32( ERROR_FILE_INVALID) ;
	}

	const std::array<std::wstring, 1U> memberPaths{path} ;	// 同じINF自身だけを再確認する。
	return nativeCatalogSignature( files_[document.catalogIndex]->path, memberPaths) ;
}

/** @see NativeLoader 宣言側の契約を正本とする。 */
NativeError NativeLoader::lookup( const InfDependencyDocument &source, std::wstring_view target,
								 InfDependencyLookup &output)
{
	output = {} ;
	// 核が扱える相対名でも、nativeで扱えない表現は未検査を維持する。
	if( !validInfDependencyPath( target, false)) {
		return 0 ;
	}

	const auto original = find( source.identity) ;	// 既知identityだけを解決する。
	// 未知sourceをpath合成へ進めない。
	if( original == nullptr) {
		return E_INVALIDARG ;
	}

	const std::wstring sourcePath =
		files_[original->fileIndex]->path ;	// vector再配置から独立した原位置。
	const std::wstring parent =
		// 元directory。
		sourcePath.substr( 0U, sourcePath.find_last_of( L'\\') + 1U) ;
	InfDependencyLookup found ;	// 全照会成功時だけ移す一時結果。
	found.checked	  = true ;
	const auto append = [&found]( const InfDependencyDocument &document) {
		// 物理共有による同identityの別名は候補を水増ししない。
		if( std::ranges::none_of( found.documents, [&document]( const auto &prior) {
			   // 原identityだけを共有根拠にする。
			   return prior.identity == document.identity ;
		   })) {
			found.documents.push_back( document) ;
		}
	} ; // この照会結果だけへ同期追加する借用callback。
	// 閉じたpackage一覧から、元親またはrootに明示された候補だけを調べる。
	for( const auto &member : members_) {
		const std::wstring path =
			// 認証済み相対memberからの固定位置。
			workspace_.path( member.relativePath) ;
		// 全directoryのbasename探索で無関係INFを混入させない。
		if( !equalName( path, parent + std::wstring( target)) &&
		   !equalName( path, packageRoot_ + std::wstring( target))) {
			continue ;
		}

		InfDependencyDocument document ;									// 一候補の独立観測。
		const auto			  error = observe( path, &member, document) ;	// 実memberへ結合する。
		// 不正memberを候補なしへ変換しない。
		if( error != 0) {
			return error ;
		}

		append( document) ;
	}

	const std::array<std::wstring, 2U> roots{windows_ + L"\\INF\\",
											 windows_ + L"\\System32\\"} ;	// 明示探索範囲。
	// 現OSの二つの明示位置を別々に照会し、複数存在を隠さない。
	for( const auto &root : roots) {
		InfDependencyDocument document ;		// system候補の実snapshot。
		bool				  fileMissing{} ;	// 元INF位置の明示openだけの不在観測。
		const auto			  error =
			// 任意diskへfallbackしない。
			observe( root + std::wstring( target), nullptr, document, &fileMissing) ;
		// 照会済み不在だけは欠落候補として保持する。
		if( fileMissing && (error == HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND) ||
						   error == HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND))) {
			continue ;
		}

		// 競合・reparse・権限・容量の失敗を未発見にしない。
		if( error != 0) {
			return error ;
		}

		append( document) ;
	}

	output = std::move( found) ;
	return 0 ;
}

/** @see NativeLoader 宣言側の契約を正本とする。 */
NativeError NativeLoader::section( const InfDependencyDocument &document, std::wstring_view name,
								  InfDependencySection &output)
{
	output			  = {} ;
	const auto stored = find( document.identity) ;	// 核が既に固定したdocument。
	// 差替えた入力やbyte未結合のdocumentを直接読まない。
	if( stored == nullptr || stored->value.sha256 != document.sha256 ||
	   stored->value.byteCount != document.byteCount || name.empty() || name.size() > 254U) {
		return E_INVALIDARG ;
	}

	const auto error = recheckFile( stored->fileIndex) ;	// 読取前の再確認。
	// Path／byteの再確認失敗後に解析を続けない。
	if( error != 0) {
		return error ;
	}

	// 単独の絶対位置だけを開く非実行解析handle。
	const HINF opened = SetupOpenInfFileW( files_[stored->fileIndex]->path.c_str(), nullptr,
										  INF_STYLE_WIN4, nullptr) ;
	// 解析失敗を節なしへ変換しない。
	if( opened == INVALID_HANDLE_VALUE) {
		return winError( GetLastError()) ;
	}

	InfHandle		   inf( opened) ;		// 単独INFだけを所有しAppendしない。
	const std::wstring sectionName( name) ;	// 明示名の終端付きcopy。
	SetLastError( ERROR_SUCCESS) ;
	const LONG lines =
		// 空節と不存在を分離する。
		SetupGetLineCountW( inf.get(), sectionName.c_str()) ;
	// API契約の不存在を明示して返す。
	if( lines == -1L) {
		const DWORD lastError = GetLastError() ;	// 直後の不在またはAPI診断。
		// 不在以外のAPI失敗をMISSINGへ弱めない。
		if( lastError != ERROR_SUCCESS && lastError != ERROR_SECTION_NOT_FOUND) {
			return winError( lastError) ;
		}

		output.state = InfDependencyReadState::MISSING ;
		return 0 ;
	}

	// 過大本文を一部だけのgraphへ変換しない。
	if( lines < 0L || lines > 4096L) {
		return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
	}

	InfDependencySection observed ;	// 全field成功後だけ返すsnapshot。
	observed.state = InfDependencyReadState::PRESENT ;
	// 確定した有限行数だけを解析し、他directiveの本文は保持しない。
	for( LONG ordinal = 0L; ordinal < lines; ++ordinal) {
		INFCONTEXT line{} ;	// 一行だけの同期context。
		// 途中の解析失敗で部分参照を返さない。
		if( !SetupGetLineByIndexW( inf.get(), sectionName.c_str(), static_cast<DWORD>( ordinal),
								 &line)) {
			return winError( GetLastError()) ;
		}

		std::wstring key ;								// 一明示keyだけ。
		const auto	 keyError = field( line, 0U, key) ;	// 本文全体のcopyは行わない。
		// 非keyのdata行にはInclude／Needsの作用を推測しない。
		if( keyError == HRESULT_FROM_WIN32( ERROR_INVALID_PARAMETER) ||
		   keyError == HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) {
			continue ;
		}

		// API失敗を無関係行として隠さない。
		if( keyError != 0) {
			return keyError ;
		}

		const bool include = equalName( key, L"Include") ;	// 関連directiveの明示一致。
		// その他directiveの作用完全性は引き続き未検査。
		if( !include && !equalName( key, L"Needs")) {
			continue ;
		}

		const DWORD fields = SetupGetFieldCount( &line) ;	// 一行の有限field数。
		// 空directiveもINVALID_REFERENCEの分母へ残す。
		if( fields == 0U) {
			// 空fieldも累積辺上限を越えて追加しない。
			if( observed.references.size() >= 4096U) {
				return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
			}

			observed.references.push_back(
				{include ? InfDependencyDirective::INCLUDE : InfDependencyDirective::NEEDS, {}}) ;
			continue ;
		}

		// 個別と累積の双方の有限上限を適用する。
		if( fields > 4096U - observed.references.size()) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		// 原field順で、空名や不正名も核へ渡して理由を保持する。
		for( DWORD index = 1U; index <= fields; ++index) {
			std::wstring target ;									// 最大254文字の一明示参照。
			const auto	 fieldError = field( line, index, target) ;	// 原値だけ。
			// 一fieldの容量・API失敗でも部分snapshotを返さない。
			if( fieldError != 0) {
				return fieldError ;
			}

			observed.references.push_back(
				{include ? InfDependencyDirective::INCLUDE : InfDependencyDirective::NEEDS,
				 std::move( target)}) ;
		}
	}

	output = std::move( observed) ;
	return recheckFile( stored->fileIndex) ;
}

/** @see NativeLoader 宣言側の契約を正本とする。 */
NativeError NativeLoader::observeFileUses( InfDependencyNativeResult &result)
{
	std::vector<InfDependencyVisitedSection> pending =
		result.dependency.sections ;	// 同じ到達節の所有copy。
	const auto append = [&pending]( std::uint64_t identity, const std::wstring &name) {
		// 全graphとmetadataを同じ1,024節予算へ拘束し、重複を再走査しない。
		if( std::ranges::none_of( pending, [identity, &name]( const auto &section) {
			   return section.identity == identity && equalName( section.section, name) ;
		   })) {
			pending.push_back( {identity, name, InfDependencyReadState::NOT_CHECKED}) ;
		}
	} ; // 同期観測中だけpendingを借用する。
	// 全発見INFのVersionとsourceを観測し、到達payloadの不在を推測しない。
	for( const auto &document : result.dependency.documents) {
		append( document.identity, L"Version") ;
		append( document.identity, L"SourceDisksFiles.amd64") ;
		append( document.identity, L"SourceDisksFiles") ;
	}

	// metadata追加を別runへ分割して節予算を回避しない。
	if( pending.size() > 1024U) {
		return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
	}

	std::size_t totalLines{} ;	// 全到達節とmetadataで共有する4,096行上限。
	// 固定された各documentの原明示節だけを読む。suffix補完をしない。
	for( const auto &section : pending) {
		const auto stored = find( section.identity) ;	// 同runで固定済みのINF。
		// 未知identityを新しいfile探索へ変換しない。
		if( stored == nullptr) {
			return E_INVALIDARG ;
		}

		const auto before = recheckFile( stored->fileIndex) ;	// 元byteの読取前確認。
		// 元byte差があれば全体の部分観測を破棄する。
		if( before != 0) {
			return before ;
		}

		InfHandle inf( SetupOpenInfFileW( files_[stored->fileIndex]->path.c_str(), nullptr,
										INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
										nullptr)) ;	// 単独読取だけの所有handle。
		// INF再読取失敗をfile用途不在へ変換しない。
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return winError( GetLastError()) ;
		}

		SetLastError( ERROR_SUCCESS) ;
		const LONG count = SetupGetLineCountW( inf.get(), section.section.c_str()) ;	// 確定行数。
		// 任意API失敗を明示節不在として消さない。
		if( count < 0L) {
			const DWORD error = GetLastError() ;	// 原節照会診断。
			// 文書化された不在だけを有限な欠落観測として保持する。
			if( count != -1L || (error != ERROR_SUCCESS && error != ERROR_SECTION_NOT_FOUND)) {
				return winError( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
			}

			continue ;
		}

		// 実在節の全行を共同予算へ含め、途中までの用途集合を返さない。
		if( static_cast<std::size_t>( count) > 4096U - totalLines) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		totalLines += static_cast<std::size_t>( count) ;
		// 全行をindexで取得し、正常終端と途中読取失敗を取り違えない。
		for( LONG ordinal = 0L; ordinal < count; ++ordinal) {
			INFCONTEXT line{} ;	// この原行だけのcontext。
			// 一行でも読取不能なら部分file用途を公開しない。
			if( SetupGetLineByIndexW( inf.get(), section.section.c_str(), static_cast<DWORD>( ordinal),
									&line) == FALSE) {
				return winError( GetLastError()) ;
			}

			std::wstring key ;								// 原用途key。data行では空。
			const auto	 keyError = field( line, 0U, key) ;	// 単独の元field取得。
			// 無key dataの仕様以外のAPI失敗を無関係行にしない。
			if( keyError != 0 && keyError != HRESULT_FROM_WIN32( ERROR_INVALID_PARAMETER) &&
			   keyError != HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) {
				return keyError ;
			}

			const bool source = equalName( section.section, L"SourceDisksFiles") ||
								// 明示sourceの原行。
								equalName( section.section, L"SourceDisksFiles.amd64") ;
			const bool knownNonFile =
				std::ranges::any_of( std::array<std::wstring_view, 26U>{L"Signature",
																	   L"Class",
																	   L"ClassGuid",
																	   L"Provider",
																	   L"DriverVer",
																	   L"CatalogFile",
																	   L"CatalogFile.NT",
																	   L"CatalogFile.ntamd64",
																	   L"PnpLockdown",
																	   L"Include",
																	   L"Needs",
																	   L"FeatureScore",
																	   L"ServiceType",
																	   L"StartType",
																	   L"ErrorControl",
																	   L"DisplayName",
																	   L"Description",
																	   L"LoadOrderGroup",
																	   L"Dependencies",
																	   L"BootFlags",
																	   L"KmdfLibraryVersion",
																	   L"UmdfLibraryVersion",
																	   L"UmdfServiceOrder",
																	   L"ComponentIDs",
																	   L"Characteristics",
																	   L"BusType"},
									[&key]( const auto name) {
										return equalName( key, name) ;
									}) ; // 既知非file用途の明示集合。
			const bool use =
				!knownNonFile || source || key.empty() || equalName( key, L"LayoutFile") ||
				equalName( key, L"CopyFiles") || equalName( key, L"CopyINF") ||
				equalName( key, L"ServiceBinary") || equalName( key, L"UmdfServiceBinary") ||
				equalName( key, L"EventMessageFile") || equalName( key, L"EventCategoryFile") ||
				equalName( key, L"EventParameterFile") || equalName( key, L"AddReg") ||
				// 具体用途。
				equalName( key, L"RegisterDlls") || equalName( key, L"UnregisterDlls") ;
			// metadataやInclude／Needsをpayload位置へ読み替えない。
			if( !use) {
				continue ;
			}

			const DWORD fields = SetupGetFieldCount( &line) ;	// 原用途の有限field数。
			// field上限を切り詰めて未知参照を消さない。
			if( fields > 64U) {
				return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
			}

			// 明示多値と空宣言を原順で全て残す。
			for( DWORD index = source ? 0U : 1U;
				index <= (source ? 0U : (std::max)( fields, DWORD{1U})); ++index) {
				std::wstring target ;	// 原値。位置解決やsystem file取得は行わない。
				const auto	 error =
					  (!source && fields == 0U) ? 0 : field( line, index, target) ;	// 一値。
				// 読取不能用途を空の無参照へ変換しない。
				if( error != 0) {
					return error ;
				}

				// 未解釈用途も最大4,096の累積保持量へ含める。
				if( result.fileUses.size() >= 4096U) {
					return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
				}

				result.fileUses.push_back(
					{section.identity, section.section,
					 source ? L"SourceDisksFiles" : (key.empty() ? L"DataRowsNotInterpreted" : key),
					 std::move( target)}) ;
			}
		}
	}

	return 0 ;
}

/** @see NativeLoader 宣言側の契約を正本とする。 */
NativeError NativeLoader::verifyNeedsEffects( const InfDependencyNativeResult	&result,
											 const std::span<const std::wstring> seeds)
{
	std::size_t registryRows{} ;	// 全Needsの元累積予算です。
	// 私有診断へ元graphの数値だけを写し、未解決と未検証rootを分離します。
	if( diagnostic_) {
		diagnostic_->stage				  = 100U ;
		diagnostic_->referencesResolved	  = result.dependency.plan.referencesResolved ;
		diagnostic_->rootEvidenceVerified = result.dependency.plan.rootEvidenceVerified ;
		diagnostic_->rootSignatureError	  = documents_.front().finding.signatureError ;
		// 未解決辺をすべて数え、一件目の具体理由だけを保持します。
		for( const auto &edge : result.dependency.edges) {
			// 成功した参照を未解決へ計上しません。
			if( edge.state != InfDependencyState::RESOLVED_PACKAGE &&
			   edge.state != InfDependencyState::RESOLVED_SYSTEM) {
				++diagnostic_->unresolvedReferenceCount ;
				// 一件目の元reasonを後続の別診断で上書きしません。
				if( diagnostic_->unresolvedReferenceCount == 1U) {
					diagnostic_->firstReferenceReason = static_cast<std::uint32_t>( edge.reason) ;
				}
			}
		}

		// 同同期で固定した依存証拠の最初の失敗だけを残します。
		for( std::size_t index = 1U; index < documents_.size(); ++index) {
			const auto &finding = documents_[index].finding ;	// 元依存の独立診断です。
			// 未観測0を成功へ読み替えず、元の非零値だけを保存します。
			if( diagnostic_->firstDependencySignatureError == 0U) {
				diagnostic_->firstDependencySignatureError = finding.signatureError ;
			}

			// 署名と由来の失敗を一つの欄へまとめません。
			if( diagnostic_->firstDependencyProvenanceError == 0U) {
				diagnostic_->firstDependencyProvenanceError = finding.provenanceError ;
			}
		}
	}

	// 未解決辺や未検査rootを空の効果集合へ変換しません。
	if( !result.dependency.plan.referencesResolved || !result.dependency.plan.rootEvidenceVerified) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// 元選択からの設置文脈を全正確なNeeds辺へ結合します。
	const auto registryContexts =
		needsRegistryContexts( result, seeds, documents_.front().value.identity) ;

	// Needsで要求された正確な節だけを作用検査します。
	for( std::size_t ordinal = 0U; ordinal < result.dependency.sections.size(); ++ordinal) {
		const auto &visited = result.dependency.sections[ordinal] ;	// 同元graphの正確な節です。
		const bool	needed	= std::ranges::any_of( result.dependency.edges, [&]( const auto &edge) {
			  return edge.directive == InfDependencyDirective::NEEDS &&
					 edge.targetIdentity == visited.identity &&
					 equalName( edge.target, visited.section) ;
		  }) ; // 非選択節を混入しません。
		// seedの既存base効果は元内容検査を維持します。
		if( !needed) {
			continue ;
		}

		const auto document = find( visited.identity) ;	// 同runの固定documentです。
		// 存在・由来・署名を別々に必要とします。
		if( document == nullptr || visited.state != InfDependencyReadState::PRESENT ||
		   document->value.signature != InfDependencyEvidence::VERIFIED ||
		   document->value.provenance != InfDependencyEvidence::VERIFIED) {
			// 参照解決後の対象証拠の不足を別段階へ保持します。
			if( diagnostic_) {
				diagnostic_->stage = 110U ;
			}

			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}

		const auto documentIndex =
			// 同所有vectorの位置です。
			static_cast<std::size_t>( document - documents_.data()) ;
		const auto fileIndex = document->fileIndex ;	// vector再配置から独立した位置です。
		const HINF opened	 = SetupOpenInfFileW( files_[fileIndex]->path.c_str(), nullptr,
												 INF_STYLE_WIN4, nullptr) ;	// 同固定INFだけです。
		// 不正INFを無作用へ変換しません。
		if( opened == INVALID_HANDLE_VALUE) {
			return winError( GetLastError()) ;
		}

		InfHandle  inf( opened) ;	// この節の読取handleです。
		const LONG count =
			// 全効果行の有限数です。
			SetupGetLineCountW( inf.get(), visited.section.c_str()) ;
		// 欠損と過大を切り詰めません。
		if( count < 0 || count > 4096L) {
			return E_INVALIDARG ;
		}

		// 全行を既知の有限効果へ分離します。
		for( LONG row = 0; row < count; ++row) {
			INFCONTEXT line{} ;	// 同じ明示節の一行です。
			// 部分読取後の成功を許可しません。
			if( !SetupGetLineByIndexW( inf.get(), visited.section.c_str(), static_cast<DWORD>( row),
									 &line)) {
				return winError( GetLastError()) ;
			}

			std::wstring key ;								// 元directiveです。
			auto		 error = field( line, 0U, key) ;	// 同節の元読取診断です。
			// 未読keyを空効果にしません。
			if( error != 0) {
				return error ;
			}

			// 参照の充足は既存graphが独立に全検査しています。
			if( equalName( key, L"Include") || equalName( key, L"Needs")) {
				continue ;
			}

			// 元選択文脈のHKR設定だけを全行検査し、後続directiveも省略しません。
			if( equalName( key, L"AddReg")) {
				// 読取・root・flag・型の拒否を元段階へ保持します。
				if( diagnostic_) {
					diagnostic_->stage = 121U ;
				}

				error = verifyNeedsAddReg( inf.get(), line, registryContexts[ordinal], registryRows) ;
				// 一部の正常行で未対応行や文脈不足を隠しません。
				if( error != 0U) {
					return error ;
				}

				// 完了した全参照行の件数だけを診断へ保持します。
				if( diagnostic_) {
					diagnostic_->verifiedRegistryRowCount = registryRows ;
				}

				continue ;
			}

			// 未解釈service等を無作用へ救済しません。
			if( !equalName( key, L"CopyFiles")) {
				// 未対応効果の名称そのものをlogへ出しません。
				if( diagnostic_) {
					diagnostic_->stage = equalName( key, L"AddReg")		 ? 121U
										 : equalName( key, L"AddService") ? 122U
																		 : 123U ;
				}

				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}

			const DWORD fields = SetupGetFieldCount( &line) ;	// 有限copy参照数です。
			// 空copyと過大を未検査のまま認定しません。
			if( fields == 0U || fields > 64U) {
				return E_INVALIDARG ;
			}

			// 各copy listの全対象を元sourceとCATへ結合します。
			for( DWORD item = 1U; item <= fields; ++item) {
				std::wstring list ;	// 元@fileまたは正確なcopy節です。
				error = field( line, item, list) ;
				// 名前欠損を省略しません。
				if( error != 0 || list.empty()) {
					return error != 0 ? error : E_INVALIDARG ;
				}

				std::vector<std::wstring> names ;	// 最大4096の全非rename copyです。
				// 直接copyでは単一basenameだけを保持します。
				if( list.front() == L'@') {
					names.push_back( list.substr( 1U)) ;
				} else {
					const LONG rows =
						// 正確な元copy節です。
						SetupGetLineCountW( inf.get(), list.c_str()) ;
					// 欠損・空list・過大を成功へ変換しません。
					if( rows <= 0 || rows > 4096L) {
						return E_INVALIDARG ;
					}

					// rename/tmp/flagsを全行で確認します。
					for( LONG position = 0; position < rows; ++position) {
						INFCONTEXT copy{} ;	// 元copy data行です。
						// 一行欠損でも部分成功を返しません。
						if( !SetupGetLineByIndexW( inf.get(), list.c_str(),
												 static_cast<DWORD>( position), &copy)) {
							return winError( GetLastError()) ;
						}

						const DWORD values = SetupGetFieldCount( &copy) ;	// 最大四fieldです。
						// 未採用の余分なcopy effectを切り捨てません。
						if( values == 0U || values > 4U) {
							return E_INVALIDARG ;
						}

						std::wstring name ;	// 宛先basenameです。
						error = field( copy, 1U, name) ;
						// 読取失敗を空fileへ変換しません。
						if( error != 0) {
							return error ;
						}

						// 全任意fieldも有限な原値へ固定します。
						for( DWORD value = 2U; value <= values; ++value) {
							std::wstring option ;	// rename/tmp/flagsの原値です。
							error = field( copy, value, option) ;
							// 非rename・非一時名・flags0だけの有限policyです。
							if( error != 0 ||
							   (!option.empty() && !((value == 2U && equalName( option, name)) ||
													 (value == 4U && option == L"0")))) {
								return error != 0 ? error : HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
							}
						}

						names.push_back( std::move( name)) ;
					}
				}

				// 各payloadの同byteと同CATを確認します。
				for( const auto &name : names) {
					// 相対pathや空名をbasenameへ正規化しません。
					if( !validInfDependencyPath( name, false) ||
					   name.find( L'\\') != std::wstring::npos) {
						return E_INVALIDARG ;
					}

					std::wstring source ;	// 同HINF/source IDの完全file subdirです。
					std::wstring media ;	// 同HINF/source IDの完全媒体位置です。
					error = readOfficialInfSourceDirectories( inf.get(), name, source, media) ;
					// source欠損・曖昧・不安全をroot fallbackで補完しません。
					if( error != 0 || (!source.empty() && !validInfDependencyPath( source, false)) ||
					   (!media.empty() && !validInfDependencyPath( media, false))) {
						return error != 0 ? error : E_INVALIDARG ;
					}

					const auto &fixed  = documents_[documentIndex] ;	// 安定した同documentです。
					const bool	system = fixed.value.origin ==
										InfDependencyOrigin::SYSTEM ;	// 同観測で確認した由来です。
					// SYSTEM由来には同byte対応Storeが必須です。
					if( system && fixed.storeIndex == MAX_FILES) {
						return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
					}

					const auto original = files_[system ? fixed.storeIndex : fixed.fileIndex]
											  ->path ;	// 同元source起点です。
					std::wstring path =
						// 元INF親だけです。
						original.substr( 0U, original.find_last_of( L'\\') + 1U) ;
					// 完全取得した両directoryだけを結合します。
					if( !media.empty()) {
						path += media + L"\\" ;
					}

					// 同じsource subdirを保持します。
					if( !source.empty()) {
						path += source + L"\\" ;
					}

					path += name ;
					std::size_t payload{} ;	// 固定した実sourceです。
					error = pin( path, MAX_TOTAL_BYTES, payload) ;
					// 実sourceがなければ導入効果を認定しません。
					if( error != 0) {
						return error ;
					}

					std::vector<std::wstring> members{path} ;	// 同CATで検査する実memberです。
					// PACKAGEは元保護閉包の全byte検査へ結合します。
					if( !system) {
						const auto relative = std::wstring_view( path).substr(
							// 同保護root相対位置です。
							packageRoot_.size()) ;
						const auto expected =
							std::ranges::find_if( content_->closure.entries, [&]( const auto &entry) {
								return equalName( entry.relativePath, relative) ;
							}) ; // 元閉包にないpayloadを足しません。
						// 元size/hashの両方を一致させます。
						if( expected == content_->closure.entries.end() ||
						   expected->sha256 != files_[payload]->sha256 ||
						   expected->uncompressedSize != files_[payload]->bytes) {
							return TRUST_E_BAD_DIGEST ;
						}
					} else {
						INFCONTEXT destination{} ;	// 同INFの元宛先定義です。
						const auto destinationKey = list.front() == L'@'
														? L"DefaultDestDir"
														: list.c_str() ;	// 元copyの宛先keyです。
						// 明示list宛先、次に同INF既定だけを使います。
						if( !SetupFindFirstLineW( inf.get(), L"DestinationDirs", destinationKey,
												&destination) &&
						   !SetupFindFirstLineW( inf.get(), L"DestinationDirs", L"DefaultDestDir",
												&destination)) {
							return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
						}

						int dirId{} ;	// Windowsの明示DIRIDです。
						// 有限なWindows/System32とdrivers以外は未確認です。
						if( !SetupGetIntField( &destination, 1U, &dirId) ||
						   (dirId != 11 && dirId != 12) || SetupGetFieldCount( &destination) > 2U) {
							return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
						}

						std::wstring subdir ;	// 任意の同INF宛先subdirです。
						// subdirは安全な相対値だけを使用します。
						if( SetupGetFieldCount( &destination) == 2U) {
							error = field( destination, 2U, subdir) ;
							// 取得失敗と境界外を止めます。
							if( error != 0 ||
							   (!subdir.empty() && !validInfDependencyPath( subdir, false))) {
								return error != 0 ? error : E_INVALIDARG ;
							}
						}

						std::wstring installed =
							windows_ + (dirId == 12 ? L"\\System32\\drivers\\"
													: L"\\System32\\") ;	// 実提供先です。
						// 同じ明示宛先を保持します。
						if( !subdir.empty()) {
							installed += subdir + L"\\" ;
						}

						installed += name ;
						std::size_t existing{} ;	// Windows既存fileです。コピーしません。
						error = pin( installed, MAX_TOTAL_BYTES, existing) ;
						// 同byteの既提供が確認できなければSYSTEM効果未充足です。
						if( error != 0 || files_[payload]->sha256 != files_[existing]->sha256 ||
						   files_[payload]->bytes != files_[existing]->bytes) {
							return error != 0 ? error : TRUST_E_BAD_DIGEST ;
						}

						members.push_back( installed) ;
					}

					error = nativeCatalogSignature(
						files_[documents_[documentIndex].catalogIndex]->path, members) ;
					// INF署名だけでpayload署名を合格にしません。
					if( error != 0) {
						return error ;
					}
				}
			}
		}
	}

	return 0 ;
}

/** @see NativeLoader 宣言側の契約を正本とする。 */
NativeError NativeLoader::run( std::size_t rootIndex, std::span<const std::wstring> seeds,
							  InfDependencyNativeResult &result)
{
	// 元全byte/metadata/CATの成功をenumだけから作りません。
	if( content_ != nullptr) {
		const auto error = reverifyCommonDriverInf( *content_) ;	// 元内容の再検査結果です。
		// 独立した元検査が失敗した場合はnative graphを作りません。
		if( error != 0) {
			return error ;
		}
	}

	// 私有入口だけが供給する生存issuerと全固定集合を、native使用前に再確認する。
	if( binding_ != nullptr) {
		const auto error =
			// 独立した公式由来確認。
			binding_->verify( *session_, *archiveWorkspace_) ;
		// 署名や節の成功で失効した取得根拠を救済しない。
		if( error != 0) {
			return error ;
		}
	}

	const auto directoryError = nativeWindowsDirectory( windows_) ;	// 実OS起点の独立診断。
	// 環境変数から別のWindows領域を指定させない。
	if( directoryError != 0) {
		return directoryError ;
	}

	const std::wstring first =
		// 初期化済み領域の確認。
		workspace_.path( members_.front().relativePath) ;
	// 過短pathと不正なWindows起点を採用しない。
	if( first.size() <= members_.front().relativePath.size() ||
	   !validInfDependencyPath( windows_, true)) {
		return E_INVALIDARG ;
	}

	packageRoot_ = first.substr( 0U, first.size() - members_.front().relativePath.size()) ;
	InfDependencyDocument root ;	// 固定済み開始snapshot。
	// 最初の失敗を保持して終了まで上書きしない診断値。
	NativeError			  error =
		observe( workspace_.path( members_[rootIndex].relativePath), &members_[rootIndex], root) ;
	// Root固定失敗ではcallbackを作成しない。
	if( error != 0) {
		return error ;
	}

	InfDependencyOperations operations ;	// この同期loaderだけを借用するcallback。
	operations.lookup = [this]( const auto &source, auto target, auto &lookupResult) {
		// Worker同期runだけでthisを借用する。
		return lookup( source, target, lookupResult) ;
	} ;
	operations.readSection = [this]( const auto &document, auto name, auto &sectionResult) {
		// 同じ固定byteにだけ明示節を照会する。
		return section( document, name, sectionResult) ;
	} ;
	operations.recheck = [this]( const auto &document) {
		// Snapshotの差替えとOS差は終了前に全体拒否する。
		const auto stored = find( document.identity) ;	// 固定rootまたは発見候補。
		// 未知identityと証拠差替えの再確認を拒否する。
		if( stored == nullptr || stored->value.sha256 != document.sha256 ||
		   stored->value.byteCount != document.byteCount ||
		   !sameContext( stored->value.context, document.context) ||
		   stored->value.origin != document.origin ||
		   stored->value.signature != document.signature ||
		   stored->value.provenance != document.provenance ||
		   stored->value.byteBinding != document.byteBinding) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		return recheckFile( stored->fileIndex) ;
	} ;
	InfDependencyNativeResult observed ;	// 全native再確認後にだけ公開する結果。
	error = resolveInfDependencies( root, seeds, operations, observed.dependency) ;
	// 共通核の拒否・容量・例外の部分graphを返さない。
	if( error != 0) {
		return error ;
	}

	error = observeFileUses( observed) ;
	// file用途の途中読取・容量失敗で部分graphを成功へ変換しない。
	if( error != 0) {
		return error ;
	}

	// 旧read-only観測は昇格せず、私有共通経路だけで独立効果を全検査します。
	if( content_ != nullptr) {
		error = verifyNeedsEffects( observed, seeds) ;
		// 辺解決だけで未検査の効果を成功にしません。
		if( error != 0) {
			return error ;
		}
	}

	// INF以外の署名CAT・対応Storeも終了時に全て再確認する。
	for( std::size_t index = 0U; index < files_.size(); ++index) {
		error = recheckFile( index) ;
		// 全根拠の一つでもbyte差があれば全体拒否する。
		if( error != 0) {
			return error ;
		}
	}

	// 現在OSへの対応位置と完全scoreを再確認し、別根拠へ転用しない。
	for( const auto &document : documents_) {
		error = recheckTrust( document) ;
		// 署名の失効とCAT／完全score差を元の成功値で隠さない。
		if( error != 0) {
			return error ;
		}

		// 由来未検査に対応Store根拠を捏造しない。
		if( document.storeIndex != MAX_FILES) {
			std::wstring current ;	// 対応位置の終了観測。
			error = nativeDriverStore( files_[document.fileIndex]->path, current) ;
			// 対応変更・照会失敗を旧根拠で補完しない。
			if( error != 0) {
				return error ;
			}

			// 対応位置の変更や不正終端を止める。
			if( !validInfDependencyPath( current, true) ||
			   !equalName( current, files_[document.storeIndex]->path)) {
				return HRESULT_FROM_WIN32( ERROR_FILE_INVALID) ;
			}
		}

		observed.findings.push_back( document.finding) ;
	}

	InfDependencyContext current ;	// 終了時のOS文脈。
	error = currentContext( context_.observationId, current) ;
	// 監視PCの別OS・別世代を旧文脈へ戻さない。
	if( error != 0 || !sameContext( context_, current)) {
		return error != 0 ? error : HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) ;
	}

	// OS・署名・参照の終了再確認後も同じ取得根拠を再確認する。
	if( binding_ != nullptr) {
		error = binding_->verify( *session_, *archiveWorkspace_) ;
		// 途中でissuerが失効した場合は確認済みgraphを返さない。
		if( error != 0) {
			return error ;
		}
	}

	observed.fixedFileCount = files_.size() ;
	// 全SYSTEM根拠の再確認後にも元保護閉包を再検査します。
	if( content_ != nullptr) {
		error = reverifyCommonDriverInf( *content_) ;
		// 途中改変を開始時の成功で隠しません。
		if( error != 0) {
			return error ;
		}
	}

	observed.fixedByteCount = totalBytes_ ;
	result					= std::move( observed) ;
	return 0 ;
}

} // namespace

namespace {
/** @brief 旧経路と封印私有経路で共用する有限native入口。
 * @param[in] workspace 閉じたpackage所有領域。
 * @param[in] members 全INFの固定一覧。
 * @param[in] rootIndex 開始INF位置。
 * @param[in] seeds 明示節群。
 * @param[in] observationId 非零の観測世代。
 * @param[out] result 全成功時だけのsnapshot。
 * @param[in] binding 封印所有者。旧経路ではnullptr。
 * @param[in] session 生存issuer。bindingと同時にだけ指定する。
 * @param[in] archiveWorkspace 元領域。bindingと同時にだけ指定する。
 * @return 観測完了0、不正入力・path・byte・OS・例外のHRESULT。
 */
NativeError inspectNativeInfDependenciesImpl(
	const OfficialDownloadWorkspace &workspace, std::span<const InfDependencyPackageMember> members,
	std::size_t rootIndex, std::span<const std::wstring> seeds, std::uint64_t observationId,
	InfDependencyNativeResult &result, const OfficialInfArchiveBinding *binding,
	const OfficialAcquisitionSession *session, const OfficialDownloadWorkspace *archiveWorkspace)
{
	result = {} ;
	try {
		// 未初期化・過大・未知rootや観測IDから結果を作らない。
		if( members.empty() || members.size() > 64U || rootIndex >= members.size() ||
		   observationId == 0U || (binding == nullptr) != (session == nullptr) ||
		   (binding == nullptr) != (archiveWorkspace == nullptr)) {
			return E_INVALIDARG ;
		}

		// 全memberの閉じた一覧と原hash／sizeを処理開始前に検査する。
		for( std::size_t index = 0U; index < members.size(); ++index) {
			const auto &member = members[index] ;	// 固定一覧の一member。
			// 安全相対INFだけを受理し、短い名称の末尾参照を避ける。
			if( !validInfDependencyPath( member.relativePath, false) ||
			   member.relativePath.size() < 5U ||
			   !equalName(
				   std::wstring_view( member.relativePath).substr( member.relativePath.size() - 4U),
				   L".inf") ||
			   member.byteCount == 0U || member.byteCount > MAX_INF_BYTES ||
			   member.sha256.size() != 64U || std::ranges::any_of( member.sha256, []( wchar_t value) {
				   // 小文字hex以外を元hashへcanonical化しない。
				   return !((value >= L'0' && value <= L'9') || (value >= L'a' && value <= L'f')) ;
			   })) {
				return E_INVALIDARG ;
			}

			// Case衝突を別memberとみなして候補を水増ししない。
			for( std::size_t prior = 0U; prior < index; ++prior) {
				// Windowsの同位置を重複登録した一覧は閉じていない。
				if( equalName( members[prior].relativePath, member.relativePath)) {
					return E_INVALIDARG ;
				}
			}
		}

		InfDependencyContext context ;											// 同期runの実OS snapshot。
		const auto			 error = currentContext( observationId, context) ;	// 実OSの取得。
		// 未知OSの起点を推測して解析しない。
		if( error != 0) {
			return error ;
		}

		NativeLoader loader( workspace, members, context, binding, session,
							archiveWorkspace) ;	// 全native根拠の単独所有者。
		return loader.run( rootIndex, seeds, result) ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_FAIL ;
	}
}
} // namespace

NativeError inspectNativeInfDependencies( const OfficialDownloadWorkspace			&workspace,
										 std::span<const InfDependencyPackageMember> members,
										 std::size_t rootIndex, std::span<const std::wstring> seeds,
										 std::uint64_t				observationId,
										 InfDependencyNativeResult &result)
{
	return inspectNativeInfDependenciesImpl( workspace, members, rootIndex, seeds, observationId,
											result, nullptr, nullptr, nullptr) ;
}

NativeError AcquiredInfNativeAccess::inspect( const OfficialInfArchiveBinding  &binding,
											 const OfficialAcquisitionSession &session,
											 const OfficialDownloadWorkspace  &archiveWorkspace,
											 std::size_t					   rootIndex,
											 std::span<const std::wstring>	   seeds,
											 std::uint64_t					   observationId,
											 InfDependencyNativeResult		  &result)
{
	result = {} ;
	// 空結果をworkspace参照へ変換せず、成功boolから入口を作らない。
	if( binding.workspace() == nullptr) {
		return E_INVALIDARG ;
	}

	return inspectNativeInfDependenciesImpl( *binding.workspace(), binding.members(), rootIndex,
											seeds, observationId, result, &binding, &session,
											&archiveWorkspace) ;
}

/** @see inf_dependency_native.h 宣言側の選択内容契約を正本とします。 */
NativeError CommonInfNativeAccess::inspect( const CommonInfInspection	&inspected,
										   const OfficialInfPackage		&selected,
										   InfDependencyNativeResult	&result,
										   RequiredInfBindingDiagnostic *diagnostic)
{
	result					= {} ;
	const auto contentError = reverifyCommonDriverInf( inspected) ;	// 全元byteと署名です。
	// 私有元所有者なしで由来を作りません。
	if( contentError != 0 || inspected.workspace == nullptr ||
	   selected.selectedBasicSection.empty()) {
		return contentError != 0 ? contentError : E_INVALIDARG ;
	}

	try {
		const auto original =
			selected.infRelativePath == inspected.closure.packages.front().infRelativePath
				? &inspected.closure.packages.front()
				: nullptr ;	// 元baseまたは元importを照合します。
		const auto imported =
			std::ranges::find_if( inspected.requiredInfPackages, [&]( const auto &package) {
				return package.infRelativePath == selected.infRelativePath ;
			}) ; // 同元内容だけです。
		// 元基本INFまたは元署名importだけを選択情報の再解析対象へ借用します。
		const auto source =
			original != nullptr
				? original
				: (imported != inspected.requiredInfPackages.end() ? &*imported : nullptr) ;
		// 任意のINFへ選択節を転用しません。
		if( source == nullptr) {
			return E_INVALIDARG ;
		}

		OfficialInfPackage current ;	// 同OS選択を元byteから再解析します。
		// 同元inventoryを維持するWindows選択関係の再解析診断です。
		auto			   error =
			inspectSelectedOfficialInfRelations( *inspected.workspace, inspected.closure.entries,
												*source, selected.selectedBasicSection, current) ;
		// 別OS節や選択機能の差を旧成功で補完しません。
		if( error != 0 || current.selectedInstallSection != selected.selectedInstallSection ||
		   current.activeRequiredInfPaths != selected.activeRequiredInfPaths) {
			return error != 0 ? error : HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) ;
		}

		std::vector<InfDependencyPackageMember> members ;	// 元保護閉包の全INFです。
		std::size_t								root = 0U ;	// 正確な開始位置です。
		// 全固定INFを元size/hashから構築します。
		for( const auto &entry : inspected.closure.entries) {
			// データfileをINFへ読み替えません。
			if( entry.relativePath.size() < 5U ||
			   !equalName(
				   std::wstring_view( entry.relativePath).substr( entry.relativePath.size() - 4U),
				   L".inf")) {
				continue ;
			}

			// Rootは元相対pathの完全一致だけです。
			if( entry.relativePath == selected.infRelativePath) {
				root = members.size() ;
			}

			members.push_back( {entry.relativePath, entry.sha256, entry.uncompressedSize}) ;
		}

		// 不在rootを先頭INFへ救済しません。
		if( members.empty() || root >= members.size() ||
		   members[root].relativePath != selected.infRelativePath) {
			return E_INVALIDARG ;
		}

		const HINF opened =
			SetupOpenInfFileW( inspected.workspace->path( selected.infRelativePath).c_str(), nullptr,
							  INF_STYLE_WIN4, nullptr) ;	// 非実行の選択seed確認です。
		// 解析不能のまま任意seedを作りません。
		if( opened == INVALID_HANDLE_VALUE) {
			return winError( GetLastError()) ;
		}

		InfHandle				  inf( opened) ;							// 同同期呼出しで解析handleを閉じる所有者です。
		std::vector<std::wstring> seeds{selected.selectedInstallSection} ;	// exact同OS選択節です。
		// 同じ選択節に付属し実在する節だけをseedへ追加します。
		for( const auto suffix :
			{L".HW", L".Services", L".CoInstallers", L".Interfaces", L".Components", L".Software",
			 L".Wdf", L".Events", L".LogConfigOverride"}) {
			const auto name = selected.selectedInstallSection + suffix ;	// 同選択節です。
			SetLastError( ERROR_SUCCESS) ;
			const LONG lines =
				// 同exact節の実在観測です。
				SetupGetLineCountW( inf.get(), name.c_str()) ;
			// 空節と不存在を区別して保持します。
			if( lines >= 0) {
				seeds.push_back( name) ;
			}
			// 不存在以外の読取失敗を付属節なしへ補完しません。
			else if( GetLastError() != ERROR_SUCCESS && GetLastError() != ERROR_SECTION_NOT_FOUND) {
				return winError( GetLastError()) ;
			}
		}

		InfDependencyContext context ;	// 同scan観測と実OSです。
		error = currentContext( inspected.scanSessionId, context) ;
		// 未観測文脈を固定値へ補完しません。
		if( error != 0) {
			return error ;
		}

		NativeLoader loader( *inspected.workspace, members, context, nullptr, nullptr, nullptr,
							&inspected, diagnostic) ;	// 全byteを同期固定します。
		return loader.run( root, seeds, result) ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_FAIL ;
	}
}
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
namespace test {
/** @see tests/support/inf_dependency_native_test_api.h 宣言側の契約を正本とします。 */
std::vector<unsigned char> inspectNeedsRegistryContextsForTest(
	const InfDependencyNativeResult &result, const std::span<const std::wstring> seeds,
	const std::uint64_t rootIdentity)
{
	return needsRegistryContexts( result, seeds, rootIdentity) ;
}

/** @see tests/support/inf_dependency_native_test_api.h 宣言側の契約を正本とします。 */
NativeError inspectNeedsAddRegForTest( const std::wstring &path, const unsigned char contexts,
									  std::size_t &registryRows)
{
	const HINF opened =
		// 架空入力だけです。
		SetupOpenInfFileW( path.c_str(), nullptr, INF_STYLE_WIN4, nullptr) ;
	// 有効な実読取handleがないfixtureを成功へ補完しません。
	if( opened == INVALID_HANDLE_VALUE) {
		return winError( GetLastError()) ;
	}

	InfHandle  inf( opened) ;	// 同同期で閉じる読取専用所有者です。
	INFCONTEXT line{} ;			// 架空Installの元AddReg行です。
	// 別節や欠損したAddRegを先頭行へ補完しません。
	if( !SetupFindFirstLineW( inf.get(), L"Install", L"AddReg", &line)) {
		return winError( GetLastError()) ;
	}

	return verifyNeedsAddReg( inf.get(), line, contexts, registryRows) ;
}

/** @see tests/support/inf_dependency_native_test_api.h 宣言側の契約を正本とする。 */
NativeError inspectInfDependenciesWithTestApi( const InfDependencyNativeTestApi			 &api,
											  const OfficialDownloadWorkspace			 &workspace,
											  std::span<const InfDependencyPackageMember> members,
											  std::size_t								  rootIndex,
											  std::span<const std::wstring>				  seeds,
											  std::uint64_t				 observationId,
											  InfDependencyNativeResult &result)
{
	result = {} ;
	// 必須callback不在で実OS trustへfallbackせず、再入slotも借用しない。
	if( !api.version || !api.windowsDirectory || !api.infSignature || !api.catalogSignature ||
	   !api.driverStore || testApi != nullptr) {
		return E_INVALIDARG ;
	}

	/** @brief 全return／例外経路でthread-local借用を解除する。 */
	struct TestApiScope {
		/** @brief 同期借用を解除する。callbackの所有権を持たない。 */
		~TestApiScope()
		{
			testApi = nullptr ;
		}
	} ;
	testApi = &api ;
	const TestApiScope scope ;	// この同期runだけの解除責任。
	return inspectNativeInfDependencies( workspace, members, rootIndex, seeds, observationId,
										result) ;
}

NativeError inspectAcquiredInfDependenciesWithTestApi(
	const InfDependencyNativeTestApi &api, const OfficialInfArchiveBinding &binding,
	const OfficialAcquisitionSession &session, const OfficialDownloadWorkspace &archiveWorkspace,
	std::size_t rootIndex, std::span<const std::wstring> seeds, std::uint64_t observationId,
	InfDependencyNativeResult &result)
{
	result = {} ;
	// 架空APIの欠損と再入を、実OS署名へのfallbackで補わない。
	if( !api.version || !api.windowsDirectory || !api.infSignature || !api.catalogSignature ||
	   !api.driverStore || testApi != nullptr) {
		return E_INVALIDARG ;
	}

	/** @brief 全失敗／例外でもこの同期呼出しのAPI借用を解除する。 */
	struct AcquiredApiScope {
		/** @brief 非所有のthread-local slotを空にする。 */
		~AcquiredApiScope()
		{
			testApi = nullptr ;
		}
	} ;
	testApi = &api ;
	const AcquiredApiScope scope ;	// 成功・拒否・例外すべてのslot回収責任。
	return binding.inspectDependencies( session, archiveWorkspace, rootIndex, seeds, observationId,
									   result) ;
}
} // namespace test
#endif
} // namespace drivercrate
