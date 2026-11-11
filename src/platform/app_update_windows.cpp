//------------------------------------------------------------------------------
/**
 * @file app_update_windows.cpp
 * @brief 通常userのSetup取得・検査・Explorer引継ぎを実装します。
 * @version 01.00.01
 * @date 2026/11/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/11  App専用の通知付き更新を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 * @note 専用cacheの固定二fileだけを扱い、管理者AppのtokenでSetupを実行しません。
 * @see docs/adr/0481-app-inno-setup-and-update-checks.md
 */
//------------------------------------------------------------------------------
#include "platform/app_update_service_internal.h"
#include "platform/com_raii.h"
#include "platform/official_file_verifier.h"
#include "drivercrate_version.h"
#include <exdisp.h>
#include <shlobj.h>
#include <shldisp.h>
#include <shlguid.h>
#include <wrl/client.h>
#include <winver.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {
/** @brief Windows handleの単独所有を解放します。 */
struct HandleCloser {
	/**
	 * @brief 有効な実handleだけを閉じます。
	 * @param[in] value 解放する所有handleです。
	 */
	void operator()( void *value) const noexcept
	{
		// 無効sentinelをWindowsへ渡しません。
		if( value && value != INVALID_HANDLE_VALUE) {
			CloseHandle( value) ;
		}
	}
} ;
/** @brief nullを空所有とするWindows handleです。 */
using Handle = std::unique_ptr<void, HandleCloser> ;
//------------------------------------------------------------------------------
/**
 * @brief Windows失敗を元数値のまま分類します。
 * @param[in] kind 操作に対応する固定分類です。
 * @param[in] error 元Win32 errorです。
 * @return 表示用の固定結果です。
 */
//------------------------------------------------------------------------------
AppUpdateFailure failed( const AppUpdateFailureKind kind,
						const DWORD				   error = GetLastError()) noexcept
{
	return {kind, HRESULT_FROM_WIN32( error), 0U, 0U} ;
}
//------------------------------------------------------------------------------
/**
 * @brief 実moduleの絶対位置だけを返します。
 * @return 有限の実path。不明は例外です。
 * @throws std::runtime_error 実module pathの取得または長さ確認に失敗した場合です。
 * @throws std::bad_alloc 所有pathの確保に失敗した場合です。
 */
//------------------------------------------------------------------------------
std::filesystem::path modulePath()
{
	std::wstring text( 32768U, L'\0') ;	// 実moduleの有限受信先です。
	const auto	 length =
		// 実長です。
		GetModuleFileNameW( nullptr, text.data(), static_cast<DWORD>( text.size())) ;
	// 不明な位置をcwdから補いません。
	if( length == 0U || length >= text.size()) {
		throw std::runtime_error( "module") ;
	}

	text.resize( length) ;
	return std::filesystem::path( text) ;
}
//------------------------------------------------------------------------------
/**
 * @brief Disk上の通常file/directoryを検査します。
 * @param[in] file 開いた非所有handleです。
 * @param[in] directory Directoryを要求する場合はtrueです。
 * @return 再解析点/複数link等がない場合だけtrueです。
 */
//------------------------------------------------------------------------------
bool regular( const HANDLE file, const bool directory = false) noexcept
{
	BY_HANDLE_FILE_INFORMATION info{} ;	// 同じhandleの属性です。
	return file && file != INVALID_HANDLE_VALUE && GetFileType( file) == FILE_TYPE_DISK &&
		   GetFileInformationByHandle( file, &info) &&
		   (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0U &&
		   ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) == directory &&
		   (directory || info.nNumberOfLinks == 1U) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 使用中のcache folderをpinし再解析点を拒否します。
 * @param[in] path 所有するApp専用folderです。
 * @return 通常folderの所有handle。不正は空です。
 */
//------------------------------------------------------------------------------
Handle openFolder( const std::filesystem::path &path)
{
	Handle result( CreateFileW( path.c_str(), FILE_READ_ATTRIBUTES,
							  FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
							  FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
							  nullptr)) ;	// renameを防ぎます。
	// 再解析点の先や通常fileを保存先にしません。
	if( !regular( result.get(), true)) {
		// 属性拒否を成功codeとして返しません。
		if( result && result.get() != INVALID_HANDLE_VALUE) {
			SetLastError( ERROR_INVALID_DATA) ;
		}

		return {} ;
	}

	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief 通常fileを検査してから初期化し、link先をtruncateしません。
 * @param[in] path 固定された自己管理fileです。
 * @return read/writeの所有handle。不正は空です。
 */
//------------------------------------------------------------------------------
Handle mutableFile( const std::filesystem::path &path)
{
	Handle result( CreateFileW( path.c_str(), GENERIC_READ | GENERIC_WRITE, 0U, nullptr, OPEN_ALWAYS,
							  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
							  nullptr)) ;	// 検査前には切詰めません。
	// link/使用中/非disk fileには書きません。
	if( !regular( result.get())) {
		// 属性拒否には固定の不正data値を保持します。
		if( result && result.get() != INVALID_HANDLE_VALUE) {
			SetLastError( ERROR_INVALID_DATA) ;
		}

		return {} ;
	}

	const LARGE_INTEGER zero{} ;	// 先頭からの位置です。
	// 同じhandleの検査後だけを初期化します。
	if( !SetFilePointerEx( result.get(), zero, nullptr, FILE_BEGIN) || !SetEndOfFile( result.get())) {
		return {} ;
	}

	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief 任意resource文字列を有限の版情報から読みます。
 * @param[in] bytes 読取り済みversion resourceです。
 * @param[in] name 固定のfield名です。
 * @return 最初の宣言言語の値。不足は空です。
 */
//------------------------------------------------------------------------------
std::wstring versionString( std::vector<std::byte> &bytes, const wchar_t *name)
{
	/** @brief version resourceの宣言言語とcodepageです。 */
	struct Translation {
		/// resourceの言語です。
		WORD language ;
		/// resourceのcodepageです。
		WORD codepage ;
	} ;
	Translation *translations{} ;	// VerQueryValueが同buffer内を借用します。
	UINT		 length{} ;			// translationの実byte数です。
	// 固定の言語を推測せず実resourceを使います。
	if( !VerQueryValueW( bytes.data(), L"\\VarFileInfo\\Translation",
					   reinterpret_cast<void **>( &translations), &length) ||
	   !translations || length < sizeof( Translation) || length > 16U * sizeof( Translation)) {
		return {} ;
	}

	wchar_t query[160]{} ;	// 固定fieldだけの有限queryです。
	// 言語/codepageと既知fieldを安全に連結します。
	if( swprintf_s( query, L"\\StringFileInfo\\%04x%04x\\%s", translations[0].language,
				  translations[0].codepage, name) < 0) {
		return {} ;
	}

	wchar_t *value{} ;		// 元buffer内の非所有文字列です。
	UINT	 characters{} ;	// 終端を含む実文字数です。
	// resource欠損や過大文字列を受理しません。
	if( !VerQueryValueW( bytes.data(), query, reinterpret_cast<void **>( &value), &characters) ||
	   !value || characters < 2U || characters > 256U || value[characters - 1U] != L'\0') {
		return {} ;
	}

	std::wstring result( value,
						characters - 1U) ;	// Inno標準resourceの末尾ASCII paddingだけを除きます。
	// 発行元や任意のUnicode文字を正規化せず、Setupの固定fieldだけを照合します。
	while( !result.empty() && result.back() == L' ') {
		result.pop_back() ;
	}

	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元宣言に一致する署名済みApp Setupだけを認めます。
 * @param[in] path 書換え/削除を禁止して保持したfileです。
 * @param[in] release 元の同意と一致する宣言です。
 * @return 全検査成功または最初の元失敗です。
 */
//------------------------------------------------------------------------------
AppUpdateFailure verifyInstaller( const std::filesystem::path &path, const AppUpdateRelease &release)
{
	std::wstring hash ;												// 通常logへ渡さない実hashです。
	auto		 error = computeFileSha256( path.native(), hash) ;	// 共通SHA-256です。
	// 元の実byte以外は署名検査へ進めません。
	if( error != 0 || hash != std::wstring( release.sha256.begin(), release.sha256.end())) {
		return {AppUpdateFailureKind::VERIFICATION,
				error != 0 ? error : static_cast<NativeError>( TRUST_E_BAD_DIGEST), 0U, 0U} ;
	}

	WIN32_FILE_ATTRIBUTE_DATA data{} ;	// exact sizeを再照合します。
	// 元の正数sizeを維持します。
	if( !GetFileAttributesExW( path.c_str(), GetFileExInfoStandard, &data) ||
	   ((static_cast<std::uint64_t>( data.nFileSizeHigh) << 32U) | data.nFileSizeLow) !=
		   release.sizeBytes) {
		return failed( AppUpdateFailureKind::VERIFICATION, ERROR_INVALID_DATA) ;
	}

	const std::array<std::wstring_view, 1U> publishers{
		L"ENTER SYSTEM, K.K."} ;	// 期待する発行元です。
	error =
		// OS chain/revocationを維持します。
		verifyAuthenticodePublisher( path.native(), publishers) ;
	// 未署名/別発行元/不明な署名へfallbackしません。
	if( error != 0) {
		return {AppUpdateFailureKind::VERIFICATION, error, 0U, 0U} ;
	}

	DWORD	   ignored{} ;													// Windowsが使用しない互換値です。
	const auto size = GetFileVersionInfoSizeW( path.c_str(), &ignored) ;	// 実version resourceです。
	// 任意サイズを確保せず必要な小さいresourceだけを読みます。
	if( size == 0U || size > 65536U) {
		return failed( AppUpdateFailureKind::VERIFICATION, ERROR_INVALID_DATA) ;
	}

	std::vector<std::byte> bytes( size) ;	// version resourceを所有します。
	// 署名済みfileの数値版と製品役割を検査します。
	if( !GetFileVersionInfoW( path.c_str(), 0U, size, bytes.data())) {
		return failed( AppUpdateFailureKind::VERIFICATION) ;
	}

	VS_FIXEDFILEINFO *fixed{} ;			// VerQueryValueが同buffer内を借用します。
	UINT			  fixedBytes{} ;	// 実構造体長です。
	const auto		  expectedMs = (static_cast<DWORD>( release.version.parts[0]) << 16U) |
							release.version.parts[1] ;								// major/minorです。
	const auto expectedLs = static_cast<DWORD>( release.version.parts[2]) << 16U ;	// patch/0です。
	// Inno外側のPE machineをApp用AMD64条件で誤拒否しません。
	if( !VerQueryValueW( bytes.data(), L"\\", reinterpret_cast<void **>( &fixed), &fixedBytes) ||
	   !fixed || fixedBytes < sizeof( VS_FIXEDFILEINFO) || fixed->dwSignature != VS_FFI_SIGNATURE ||
	   fixed->dwFileVersionMS != expectedMs || fixed->dwFileVersionLS != expectedLs ||
	   fixed->dwProductVersionMS != expectedMs || fixed->dwProductVersionLS != expectedLs ||
	   versionString( bytes, L"ProductName") != L"DriverCrate" ||
	   versionString( bytes, L"FileDescription") != L"DriverCrate Setup") {
		return failed( AppUpdateFailureKind::VERIFICATION, ERROR_INVALID_DATA) ;
	}

	return {} ;
}
//------------------------------------------------------------------------------
/**
 * @brief Explorerと同じ元userのLocalAppDataを取得します。
 * @param[out] root 成功時だけのuser領域です。
 * @return OS成功0、元errorのHRESULTです。
 */
//------------------------------------------------------------------------------
NativeError explorerUserRoot( std::wstring &root)
{
	root.clear() ;
	DWORD	   processId{} ;				// 同sessionのdesktop Explorerです。
	const auto window = GetShellWindow() ;	// 現対話desktopの非所有windowです。
	// Explorerのない環境で管理者子起動へ退避しません。
	if( !window || !GetWindowThreadProcessId( window, &processId)) {
		return HRESULT_FROM_WIN32( ERROR_NOT_FOUND) ;
	}

	Handle process(
		// token照会だけです。
		OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId)) ;
	HANDLE rawToken{} ;	// 成功後だけRAIIへ移します。
	// 資格入力やtoken変更をせず元userを照会します。
	if( !process || !OpenProcessToken( process.get(), TOKEN_QUERY | TOKEN_IMPERSONATE, &rawToken)) {
		return HRESULT_FROM_WIN32( GetLastError()) ;
	}

	Handle	   token( rawToken) ;	// Explorer userの非変更tokenです。
	PWSTR	   path{} ;				// WindowsがCoTaskMemで返します。
	const auto result = SHGetKnownFolderPath( FOLDERID_LocalAppData, KF_FLAG_DONT_VERIFY,
											 // 元userのrootです。
											 token.get(), &path) ;
	// 元userを確定できない時は別領域へ配置しません。
	if( FAILED( result)) {
		return result ;
	}

	root = path ;
	CoTaskMemFree( path) ;
	return 0 ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元user領域内の同じ配置へ通常Setupを渡します。
 * @param[in] setup 保護handleで保持した正規Setupです。
 * @param[in] directory 元Appの絶対配置です。
 * @return Explorer要求の結果。Setupの完了結果ではありません。
 */
//------------------------------------------------------------------------------
AppUpdateFailure launchFromExplorer( const std::filesystem::path &setup,
									const std::filesystem::path &directory)
{
	using Microsoft::WRL::ComPtr ;
	std::wstring userRoot ;											// 元userのLocalAppDataだけです。
	auto		 error	= explorerUserRoot( userRoot) ;				// 別管理者のHKCUを採用しません。
	const auto	 target = directory.lexically_normal().native() ;	// 固定DIR引数にする実App配置です。
	// この元userの領域内でのみ同じApp配置を指定します。
	if( error != 0 || target.size() <= userRoot.size() ||
	   CompareStringOrdinal( target.data(), static_cast<int>( userRoot.size()), userRoot.data(),
							static_cast<int>( userRoot.size()), TRUE) != CSTR_EQUAL ||
	   target[userRoot.size()] != L'\\' || target.find( L'"') != std::wstring::npos) {
		return {AppUpdateFailureKind::LAUNCH,
				error != 0 ? error : HRESULT_FROM_WIN32( ERROR_BAD_PATHNAME), 0U, 0U} ;
	}

	ComPtr<IShellWindows> windows ;	// 元Explorerのautomation境界です。
	error =
		CoCreateInstance( CLSID_ShellWindows, nullptr, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS( &windows)) ;
	// Explorerの生成失敗を管理者実行で補いません。
	if( FAILED( error)) {
		return {AppUpdateFailureKind::LAUNCH, error, 0U, 0U} ;
	}

	VARIANT location{} ;	// desktopを指定する固定variantです。
	location.vt	  = VT_I4 ;
	location.lVal = CSIDL_DESKTOP ;
	VARIANT			  empty{} ;			// 未指定のrootです。
	long			  windowHandle{} ;	// FindWindowSWが返す互換値です。
	ComPtr<IDispatch> dispatch ;		// 元Explorer desktopです。
	error = windows->FindWindowSW( &location, &empty, SWC_DESKTOP, &windowHandle, SWFO_NEEDDISPATCH,
								  &dispatch) ;
	ComPtr<IServiceProvider>	 provider ;		// 同じdesktop processのserviceです。
	ComPtr<IShellBrowser>		 browser ;		// 同じdesktop browserです。
	ComPtr<IShellView>			 view ;			// 同じdesktop viewです。
	ComPtr<IDispatch>			 background ;	// viewのautomationです。
	ComPtr<IShellFolderViewDual> folder ;		// Explorer由来であることを維持します。
	ComPtr<IDispatch>			 application ;	// 同じExplorerのShell.Applicationです。
	ComPtr<IShellDispatch2>		 shell ;		// 固定Setupの起動先です。
	// 完全な既desktop経路が成立した時だけ起動します。
	if( FAILED( error) || !dispatch || FAILED( error = dispatch.As( &provider)) ||
	   FAILED( error = provider->QueryService( SID_STopLevelBrowser, IID_PPV_ARGS( &browser))) ||
	   FAILED( error = browser->QueryActiveShellView( &view)) ||
	   FAILED( error = view->GetItemObject( SVGIO_BACKGROUND, IID_PPV_ARGS( &background))) ||
	   FAILED( error = background.As( &folder)) ||
	   FAILED( error = folder->get_Application( &application)) ||
	   FAILED( error = application.As( &shell))) {
		return {AppUpdateFailureKind::LAUNCH, FAILED( error) ? error : E_UNEXPECTED, 0U, 0U} ;
	}

	const std::wstring parameters =
		L"/DIR=\"" + target + L"\"" ;			// 検証した同配置だけの固定引数です。
	const UniqueBstr file( setup.native()) ;	// 既RAIIでCOM呼出し中だけ所有します。
	const UniqueBstr args( parameters) ;		// 任意入力を含みません。
	const UniqueBstr cwd( directory.native()) ;	// 同配置です。
	// 確保失敗では一部の引数で起動しません。
	if( !file.get() || !args.get() || !cwd.get()) {
		return {AppUpdateFailureKind::LAUNCH, E_OUTOFMEMORY, 0U, 0U} ;
	}

	VARIANT arguments{} ;	// ShellExecuteが借用するBSTRです。
	arguments.vt	  = VT_BSTR ;
	arguments.bstrVal = args.get() ;
	VARIANT working{} ;	// 同配置の作業directoryです。
	working.vt		= VT_BSTR ;
	working.bstrVal = cwd.get() ;
	VARIANT show{} ;	// 通常の可視wizardです。
	show.vt	  = VT_I4 ;
	show.lVal = SW_SHOWNORMAL ;
	error	  = shell->ShellExecute( file.get(), arguments, working, empty, show) ;
	return FAILED( error) ? AppUpdateFailure{AppUpdateFailureKind::LAUNCH, error, 0U, 0U}
						 : AppUpdateFailure{} ;
}
/** @brief このthread内だけの公式HTTP/署名/Setupを所有します。 */
class NativeBackend final : public AppUpdateBackend {
public:
	/**
	 * @brief 製品の実API経路を作ります。
	 */
	NativeBackend() : appPath_( modulePath()), current_( *parseAppVersion( DRIVERCRATE_VERSION_STRING))
	{
	}
	/**
	 * @brief 完全fixtureだけを所有します。
	 * @param[in] fixture 非通信の完全I/Oです。
	 */
	explicit NativeBackend( app_update_detail::Fixture fixture)
		: appPath_( fixture.appPath), current_( fixture.current), fixture_( std::move( fixture))
	{
	}
	/**
	 * @brief 正式Releaseだけを確認し、実行物は取得しません。
	 * @param[in] cancellation 同じ操作の取消し照会です。
	 * @return 確認結果。ドライバーへの作用を持ちません。
	 * @note 製品backendは固定Release metadataだけを共通HTTPで確認します。完全fixtureでは指定transportを使い、Setup本体は取得しません。
	 */
	AppUpdateEvent check( const AppUpdateCancellation &cancellation) noexcept override
	{
		AppUpdateEvent event ;	// 失敗でも固定結果を返します。
		try {
			// 元配布先待機を手動確認でも回避しません。
			if( std::chrono::steady_clock::now() < notBefore_) {
				event.failure = {AppUpdateFailureKind::WAIT, HRESULT_FROM_WIN32( ERROR_RETRY), 0U,
								 0U} ;
				return event ;
			}

			app_update_detail::HttpResult result ;	// 数値と成功metadataだけです。
			const auto					  error =
				// EXE取得は行いません。
				fetch( nullptr, nullptr, cancellation, result) ;
			// 部分本文やHTTP拒否はJSONへ渡しません。
			if( error != 0) {
				event.failure = httpFailure( error, result, cancellation) ;
				return event ;
			}

			event.failure = parseAppUpdateReleaseJson( result.metadata, current_, event.release) ;
		} catch( ...) {
			event.failure = {AppUpdateFailureKind::METADATA, E_UNEXPECTED, 0U, 0U} ;
		}

		return event ;
	}
	/**
	 * @brief 明示同意した一件だけを取得・検査します。
	 * @param[in] release 元確認の完全宣言です。
	 * @param[in] cancellation 同じ操作の取消し照会です。
	 * @return 取得・検査結果。成功時だけ保護したfileを保持します。
	 * @note 製品backendは同じApp配置の一時fileへ取得・検証します。完全fixtureでは指定transport/verifyを使い、検査成功から起動までを一操作へ省略しません。
	 */
	AppUpdateFailure download( const AppUpdateRelease	  &release,
							  const AppUpdateCancellation &cancellation) noexcept override
	{
		try {
			locked_.reset() ;
			acquired_.reset() ;
			// 同意後の新待機/取消しも取得前に確認します。
			if( cancellation()) {
				return failed( AppUpdateFailureKind::CANCELLED, ERROR_CANCELLED) ;
			}

			// 取得前に宣言と配布先待機を再検査します。
			if( !validAppUpdateRelease( release) || release.version <= current_ ||
			   std::chrono::steady_clock::now() < notBefore_) {
				return failed( AppUpdateFailureKind::WAIT, ERROR_RETRY) ;
			}

			const auto directory = appPath_.parent_path() ;		// 実Appの配置です。
			auto	   root		 = openFolder( directory) ;		// 保存先のrenameを禁止します。
			const auto cachePath = directory / L".app-update" ;	// 自己管理した固定cacheです。
			// 通常folderを確定してからcacheを作ります。
			if( !root || (!CreateDirectoryW( cachePath.c_str(), nullptr) &&
						 GetLastError() != ERROR_ALREADY_EXISTS)) {
				return failed( AppUpdateFailureKind::STORAGE) ;
			}

			auto cache = openFolder( cachePath) ;	// 再解析点を拒否します。
			// 既cacheの不明な属性へ書きません。
			if( !cache) {
				return failed( AppUpdateFailureKind::STORAGE, ERROR_INVALID_DATA) ;
			}

			const auto part =
				cachePath / L"DriverCrateSetup-windows-x64.exe.part" ;	// 固定partです。
			auto file = mutableFile( part) ;							// 検査してから初期化します。
			// 使用中/複数linkには書きません。
			if( !file) {
				return failed( AppUpdateFailureKind::STORAGE) ;
			}

			app_update_detail::HttpResult result ;	// 数値だけのHTTP結果です。
			const auto					  error =
				// 元tupleだけのstreamです。
				fetch( &release, file.get(), cancellation, result) ;
			// 不完全な取得を実行候補にしません。
			if( error != 0 || !FlushFileBuffers( file.get())) {
				const auto failure =
					error != 0 ? httpFailure( error, result, cancellation)
							   : failed( AppUpdateFailureKind::STORAGE) ;	// 元失敗を保持します。
				file.reset() ;
				static_cast<void>( DeleteFileW( part.c_str())) ;
				return failure ;
			}

			file.reset() ;
			const auto setup =
				cachePath / L"DriverCrateSetup-windows-x64.exe" ;	// 唯一の保留Setupです。
			// 旧cacheが使用中なら通常の失敗にし、強制終了しません。
			if( !MoveFileExW( part.c_str(), setup.c_str(),
							MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
				return failed( AppUpdateFailureKind::STORAGE) ;
			}

			Handle read( CreateFileW( setup.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
									OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT,
									nullptr)) ;	// 書換え/削除を禁止して検査します。
			// 通常fileの同じbyteだけを検査します。
			if( !regular( read.get())) {
				return failed( AppUpdateFailureKind::STORAGE, ERROR_INVALID_DATA) ;
			}

			const auto verified = fixture_ ? fixture_->verify( setup, release)
										   : verifyInstaller( setup, release) ;	// 完全境界です。
			// 検査失敗/取消しをreadyへ進めません。
			if( verified.kind != AppUpdateFailureKind::NONE || cancellation()) {
				return verified.kind != AppUpdateFailureKind::NONE
						   ? verified
						   : failed( AppUpdateFailureKind::CANCELLED, ERROR_CANCELLED) ;
			}

			locked_	  = std::move( read) ;
			cache_	  = std::move( cache) ;
			root_	  = std::move( root) ;
			acquired_ = release ;
			return {} ;
		} catch( ...) {
			return {AppUpdateFailureKind::STORAGE, E_UNEXPECTED, 0U, 0U} ;
		}
	}
	/**
	 * @brief 保護したfileを再検査して通常userへ渡します。
	 * @param[in] release 元同意と取得に一致する宣言です。
	 * @param[in] cancellation 引継ぎ前の取消し照会です。
	 * @return 引継ぎ要求の結果。Setup完了結果ではありません。
	 * @note 製品backendはbyte/署名/版を再検査して元Explorerへ渡します。完全fixtureでは指定launchだけを呼び、Windowsの起動へfallbackしません。
	 */
	AppUpdateFailure launch( const AppUpdateRelease		&release,
							const AppUpdateCancellation &cancellation) noexcept override
	{
		try {
			// 前回起動のcacheや別宣言は実行しません。
			if( !locked_ || !acquired_ || *acquired_ != release || cancellation()) {
				return failed( AppUpdateFailureKind::CANCELLED, ERROR_CANCELLED) ;
			}

			const auto setup = appPath_.parent_path() / L".app-update" /
							   L"DriverCrateSetup-windows-x64.exe" ;	// 元fileだけです。
			const auto verified =
				fixture_ ? fixture_->verify( setup, release)
						 : verifyInstaller( setup, release) ;	// 引継ぎ直前にも再検査します。
			// 遅いtrust完了後の取消しも実行へ戻しません。
			if( verified.kind != AppUpdateFailureKind::NONE || cancellation()) {
				return verified.kind != AppUpdateFailureKind::NONE
						   ? verified
						   : failed( AppUpdateFailureKind::CANCELLED, ERROR_CANCELLED) ;
			}

			return fixture_ ? fixture_->launch( setup, appPath_.parent_path())
							: launchFromExplorer( setup, appPath_.parent_path()) ;
		} catch( ...) {
			return {AppUpdateFailureKind::LAUNCH, E_UNEXPECTED, 0U, 0U} ;
		}
	}

private:
	/**
	 * @brief 完全な一用途だけを共通HTTPへ渡します。
	 * @param[in] release Nullはmetadata、非nullはSetupです。
	 * @param[in] output Setup専用の書込みhandleです。
	 * @param[in] cancellation 同操作の取消しです。
	 * @param[out] result HTTPの最小結果です。
	 * @return 元のHTTP/OS診断です。
	 */
	NativeError fetch( const AppUpdateRelease *release, HANDLE output,
					  const AppUpdateCancellation	&cancellation,
					  app_update_detail::HttpResult &result)
	{
		OfficialHttpClient				  native( false) ;	// Provider cache/ledgerを使いません。
		std::optional<OfficialHttpClient> injected ;		// 完全fixtureだけのclientです。
		// 部分fixtureからnativeへfallbackしません。
		if( fixture_) {
			injected.emplace( fixture_->transport) ;
		}

		SignedIndexHttpControl control ;	// 元indexとの共有はないHTTP一回の制御です。
		control.cancellation = cancellation ;
		control.monotonicNow = []() {
			return std::chrono::steady_clock::now() ;
		} ; // App専用の現在単調時刻です。
		control.deadline = std::chrono::steady_clock::now() +
						   (release ? std::chrono::seconds( 120) : std::chrono::seconds( 15)) ;
		const auto error = app_update_detail::Access::http(
			injected ? *injected : native, release, output, control, result) ;	// 固定用途です。
		// 観測待機を次の手動/自動送信の下限へ反映します。
		if( result.retryAfterSeconds != 0U) {
			const auto now = std::chrono::steady_clock::now() ;	// 待機を観測した単調時刻です。
			notBefore_	   = result.retryAfterSeconds > 31536000U
								 ? std::chrono::steady_clock::time_point::max()
								 : now + std::chrono::seconds( result.retryAfterSeconds) ;
		}

		return error ;
	}
	/**
	 * @brief HTTP失敗を取消しと区別して返します。
	 * @param[in] error 元のHTTP/OS数値です。
	 * @param[in] result 実観測statusと待機です。
	 * @param[in] cancellation 同操作の取消しです。
	 * @return 最初の分類と元の数値です。
	 */
	AppUpdateFailure httpFailure( const NativeError					  error,
								 const app_update_detail::HttpResult &result,
								 const AppUpdateCancellation		 &cancellation) const
	{
		return {cancellation() ? AppUpdateFailureKind::CANCELLED : AppUpdateFailureKind::NETWORK,
				error, result.status, result.retryAfterSeconds} ;
	}
	/// 実Appの配置からだけcache/Setupの位置を作ります。
	std::filesystem::path					  appPath_ ;
	/// このAppの数値版です。
	AppVersion								  current_ ;
	/// 明示内部fixtureだけに存在します。
	std::optional<app_update_detail::Fixture> fixture_ ;
	/// 取得成功の完全宣言です。
	std::optional<AppUpdateRelease>			  acquired_ ;
	/// 引継ぎまで実byteを保護します。
	Handle									  locked_ ;
	/// cache folderのrenameを防ぎます。
	Handle									  cache_ ;
	/// App rootのrenameを防ぎます。
	Handle									  root_ ;
	/// 元HTTP待機をprocess内で維持します。
	std::chrono::steady_clock::time_point	  notBefore_{} ;
} ;
}
//------------------------------------------------------------------------------
/**
 * @brief 任意URLを受け取らず固定用途だけを要求します。
 * @param[in,out] client cacheなしの専用clientです。
 * @param[in] release nullは固定latest、非nullは固定Setupです。
 * @param[in] output Setup時だけの書込みfileです。
 * @param[in,out] control この一回だけの期限/取消しです。
 * @param[out] result status/待機と成功metadataです。
 * @return 共通HTTPの元診断値です。
 */
//------------------------------------------------------------------------------
NativeError app_update_detail::Access::http( OfficialHttpClient	   &client,
											const AppUpdateRelease *release, const HANDLE output,
											SignedIndexHttpControl &control, HttpResult &result)
{
	return client.getAppUpdateResource( release, output, control, result) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 全てをfakeへ置換したbackendを構築します。
 * @param[in] fixture 完全なI/Oと所有配置です。
 * @return 完全backend。欠損は例外で拒否します。
 * @throws std::invalid_argument 配置が不正、必須seam欠損、または実通信APIが残る場合です。
 * @throws std::bad_alloc 完全fixture backendの確保に失敗した場合です。
 */
//------------------------------------------------------------------------------
std::unique_ptr<AppUpdateBackend> app_update_detail::Access::fixtureBackend( Fixture fixture)
{
	const auto nativeResolver = fixture.transport.resolveDestination.target<
		// 既定resolverをfixtureに残しません。
		decltype( &resolveOfficialDestinationWithWindows)>() ;
	// 完全な非通信取得・検証・起動を要求します。
	if( fixture.appPath.empty() || !fixture.appPath.is_absolute() || !fixture.verify ||
	   !fixture.launch || !fixture.transport.open || fixture.transport.open == WinHttpOpen ||
	   !fixture.transport.connect || fixture.transport.connect == WinHttpConnect ||
	   !fixture.transport.sendRequest || fixture.transport.sendRequest == WinHttpSendRequest ||
	   !fixture.transport.readData || fixture.transport.readData == WinHttpReadData ||
	   !fixture.transport.resolveDestination ||
	   (nativeResolver && *nativeResolver == resolveOfficialDestinationWithWindows)) {
		throw std::invalid_argument( "fixture") ;
	}

	return std::make_unique<NativeBackend>( std::move( fixture)) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 既Windows APIを使う公式backendを生成します。
 * @return 所有backend。確保失敗は例外です。
 */
//------------------------------------------------------------------------------
std::unique_ptr<AppUpdateBackend> makeAppUpdateBackend()
{
	return std::make_unique<NativeBackend>() ;
}
//------------------------------------------------------------------------------
/**
 * @brief 任意boolだけの現在配置設定を読みます。
 * @param[out] enabled 不在はtrue。不正/失敗はfalseです。
 * @return 成功0、設定fileを扱えない場合は元数値です。
 */
//------------------------------------------------------------------------------
NativeError loadAppUpdatePreference( bool &enabled) noexcept
{
	enabled = false ;
	try {
		const auto path =
			// 任意URLは受けません。
			modulePath().parent_path() / L"DriverCrate.settings.ini" ;
		Handle file( CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
								FILE_FLAG_OPEN_REPARSE_POINT,
								nullptr)) ;	// 読む間は変更を拒否します。
		// 開けない原因を不正形式へ丸めず、不在だけ既定有効にします。
		if( file.get() == INVALID_HANDLE_VALUE) {
			const auto error = GetLastError() ;	// CreateFileの元診断です。
			// 不在だけが通常の既定設定です。
			if( error == ERROR_FILE_NOT_FOUND) {
				enabled = true ;
				return 0 ;
			}

			return HRESULT_FROM_WIN32( error) ;
		}

		// 不明なfileを正常設定にしません。
		if( !regular( file.get())) {
			return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		}

		LARGE_INTEGER size{} ;	// 小さい設定だけを読みます。
		// Size照会失敗は元のOS codeを返します。
		if( !GetFileSizeEx( file.get(), &size)) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		// 過大/空の設定を読取りません。
		if( size.QuadPart <= 0 || size.QuadPart > 128) {
			return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		}

		std::string text( static_cast<std::size_t>( size.QuadPart),
						 '\0') ;	// 任意本文は外へ出しません。
		DWORD		received{} ;	// 実読取り長です。
		// API読取り失敗は元のOS codeを返します。
		if( !ReadFile( file.get(), text.data(), static_cast<DWORD>( text.size()), &received,
					 nullptr)) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		// 部分読取りを既定有効へ変換しません。
		if( received != text.size()) {
			return HRESULT_FROM_WIN32( ERROR_READ_FAULT) ;
		}

		// 自分で保存するbool以外を設定として解釈しません。
		if( text == "[updates]\nenabled=true\n" || text == "[updates]\r\nenabled=true\r\n") {
			enabled = true ;
			return 0 ;
		}

		// 明示無効も正常設定です。
		if( text == "[updates]\nenabled=false\n" || text == "[updates]\r\nenabled=false\r\n") {
			return 0 ;
		}

		return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
	} catch( ...) {
		return E_UNEXPECTED ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 自動確認boolを現在配置に保存します。
 * @param[in] enabled 保存する設定です。URL等は保存しません。
 * @return 保存成功0、失敗時は元数値です。
 */
//------------------------------------------------------------------------------
NativeError saveAppUpdatePreference( const bool enabled) noexcept
{
	try {
		const auto root		 = modulePath().parent_path() ;	// 実配置です。
		auto	   directory = openFolder( root) ;			// 同じfolderを保持します。
		// cwdや別rootへ保存しません。
		if( !directory) {
			return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		}

		const auto path = root / L"DriverCrate.settings.ini" ;	// 自己管理boolです。
		const auto temporary =
			root / L"DriverCrate.settings.ini.tmp" ;	// 同volumeの固定一時fileです。
		auto file = mutableFile( temporary) ;			// 通常fileだけを初期化します。
		// 不明fileへ書きません。
		if( !file) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		const std::string_view text =
			enabled ? "[updates]\nenabled=true\n" : "[updates]\nenabled=false\n" ;	// 固定本文です。
		DWORD written{} ;															// 実保存長です。
		// 書込み失敗は元のOS codeを返します。
		if( !WriteFile( file.get(), text.data(), static_cast<DWORD>( text.size()), &written,
					  nullptr)) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		// 完全保存だけをflushへ進めます。
		if( written != text.size()) {
			return HRESULT_FROM_WIN32( ERROR_WRITE_FAULT) ;
		}

		// flush失敗も元のOS codeを返します。
		if( !FlushFileBuffers( file.get())) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		file.reset() ;
		// 一時fileだけを同名設定へ置き換えます。
		if( !MoveFileExW( temporary.c_str(), path.c_str(),
						MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		return 0 ;
	} catch( ...) {
		return E_UNEXPECTED ;
	}
}
}
