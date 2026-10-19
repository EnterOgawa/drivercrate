//------------------------------------------------------------------------------
/**
 * @file dell_server_update_provider.cpp
 * @brief Dell PowerEdge公式driver Provider実装。
 * @version 01.00.00
 * @date 2026/09/02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式取得元policy registry接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式HTTP取得根拠記録追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式取得根拠session照合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  OEM既定選択根拠追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  公式構造化探索経路追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  候補監査状態追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Dell PowerEdge／Windows Server x64以外では無通信で対象外とします。DUPはcatalog宣言size、SHA-256、Dell
 *       Authenticodeを実行直前に検証します。
 */
//------------------------------------------------------------------------------

#include "platform/dell_server_update_provider.h"

#include "core/candidate_audit.h"
#include "core/official_source_policy.h"
#include "core/package_selection.h"
#include "core/provider_registry.h"
#include "platform/dell_server_catalog_parser.h"
#include "platform/dell_server_catalog_source.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "platform/windows_product_type.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cwctype>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::array<std::wstring_view, 2> DELL_PUBLISHERS{
	L"Dell Technologies Inc.", L"Dell Inc."} ;	// 許可するAuthenticode publisher。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief Local registryから得る非機密なPowerEdge system識別値である。
 */
struct DellServerSystemIdentity {
	/// SMBIOS由来system manufacturer。
	std::wstring  manufacturer ;
	/// SMBIOS由来system product name。
	std::wstring  model ;
	/// CurrentBuildNumberの検証済み10進値。
	std::uint32_t windowsBuild{} ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをNativeErrorへ変換する。
 *
 * Provider共通の32-bit診断値へ元のerrorを保持する。
 *
 * @param[in] error GetLastErrorまたは検証用Win32 error code。
 * @return HRESULT_FROM_WIN32で変換したbit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示名を大文字英数字だけの比較keyへ変換する。
 *
 * 空白とpunctuation差だけを吸収し、部分一致用途には使わない。
 *
 * @param[in] value Registryまたはcatalogの表示名。
 * @return 区切りを除いて大文字化した完全一致key。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizeName( const std::wstring_view value)
{
	std::wstring normalized ;	// 比較に必要な英数字だけを保持するkey。
	normalized.reserve( value.size()) ;
	// Unicode英数字を順序通り保持し、大小文字差を除去する。
	for( const wchar_t character : value) {
		// 英数字と判定された文字だけを大文字keyへ含め、メーカーとmodelを比較する。
		if( std::iswalnum( character) != 0) {
			normalized.push_back( static_cast<wchar_t>( std::towupper( character))) ;
		}
	}

	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief RegistryのREG_SZ値を上限付きで取得する。
 *
 * SMBIOS表示値とWindows buildだけを読み、Service Tagは読まない。
 *
 * @param[in] root 所有しないroot registry handle。
 * @param[in] subkey 読取り対象subkey。
 * @param[in] valueName 取得するREG_SZ value名。
 * @param[out] value 成功時の終端nullを除く文字列。
 * @return 成功時は0、型不一致、上限超過、API失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRegistryString( const HKEY root, const std::wstring_view subkey,
											 const std::wstring_view valueName, std::wstring &value)
{
	value.clear() ;
	const std::wstring subkeyString( subkey) ;			// RegGetValue用終端null付きsubkey。
	const std::wstring valueNameString( valueName) ;	// RegGetValue用終端null付きvalue名。
	DWORD			   bytes{} ;						// 終端null込み必要byte数。
	LSTATUS			   status = RegGetValueW( root, subkeyString.c_str(), valueNameString.c_str(),
											 RRF_RT_REG_SZ, nullptr, nullptr, &bytes) ;	// Size取得結果。
	// registry値の長さ照会失敗を診断値のまま返す。
	if( status != ERROR_SUCCESS) {
		return nativeErrorFromWin32( static_cast<DWORD>( status)) ;
	}

	// 空のUTF-16表現、奇数byte、4096-byte超過のregistry値を拒否する。
	if( bytes < sizeof( wchar_t) || bytes > 4096 || bytes % sizeof( wchar_t) != 0) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::wstring buffer( bytes / sizeof( wchar_t), L'\0') ;	// 終端null込み受信buffer。
	status = RegGetValueW( root, subkeyString.c_str(), valueNameString.c_str(), RRF_RT_REG_SZ,
						  nullptr, buffer.data(), &bytes) ;
	// registry本文の取得失敗を同じ診断値で返す。
	if( status != ERROR_SUCCESS) {
		return nativeErrorFromWin32( static_cast<DWORD>( status)) ;
	}

	// REG_SZ終端nullだけを除去する。
	while( !buffer.empty() && buffer.back() == L'\0') {
		buffer.pop_back() ;
	}

	// 空または途中NULを含むregistry文字列を識別情報として受理しない。
	if( buffer.empty() || buffer.find( L'\0') != std::wstring::npos) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	value = std::move( buffer) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Local systemが対応Dell PowerEdgeかを判定する。
 *
 * Dell以外はmodelやbuildを読まず無通信の対象外として返す。
 *
 * @param[out] identity Dell時のmanufacturer、model、build。
 * @param[out] applicable Dell PowerEdge表示ならtrue。
 * @return 判定成功時は0、registry値不正時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readDellServerIdentity( DellServerSystemIdentity &identity,
												 bool					  &applicable)
{
	identity   = {} ;
	applicable = false ;
	// PowerEdge対象をlocal値で照合するために読み取るSMBIOS由来registry key。
	constexpr std::wstring_view BIOS_KEY = L"HARDWARE\\DESCRIPTION\\System\\BIOS" ;
	NativeError error = readRegistryString( HKEY_LOCAL_MACHINE, BIOS_KEY, L"SystemManufacturer",
										   identity.manufacturer) ;	// Manufacturer取得結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	const std::wstring manufacturerKey = normalizeName( identity.manufacturer) ;	// Maker key。
	// 審査済みDellメーカー表記に一致しないsystemを対象外にする。
	if( manufacturerKey != L"DELLINC" && manufacturerKey != L"DELLCOMPUTERCORPORATION" &&
	   manufacturerKey != L"DELLTECHNOLOGIES") {
		return 0 ;
	}

	error = readRegistryString( HKEY_LOCAL_MACHINE, BIOS_KEY, L"SystemProductName", identity.model) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	// PowerEdge系列を示さないmodelはServer Providerの対象外にする。
	if( !normalizeName( identity.model).starts_with( L"POWEREDGE")) {
		return 0 ;
	}

	std::wstring buildText ;	// Windows CurrentBuildNumberの10進文字列。
	error =
		readRegistryString( HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
						   L"CurrentBuildNumber", buildText) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	std::uint32_t build{} ;	// Overflow検証中のWindows build値。
	// 全桁を10進値へ変換し、32-bit overflowを検出する。
	for( const wchar_t character : buildText) {
		// Windows buildのASCII数字以外を不正dataとして拒否する。
		if( character < L'0' || character > L'9') {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const std::uint32_t digit = static_cast<std::uint32_t>( character - L'0') ;	// 現在桁。
		// Windows buildの桁追加でuint32範囲を超える前に拒否する。
		if( build > (std::numeric_limits<std::uint32_t>::max() - digit) / 10U) {
			return nativeErrorFromWin32( ERROR_ARITHMETIC_OVERFLOW) ;
		}

		build = build * 10U + digit ;
	}

	// 未確定を表すゼロbuildを実OS条件として使用しない。
	if( build == 0) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	identity.windowsBuild = build ;
	applicable			  = true ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 数字dot形式versionをcomponent群へ変換する。
 *
 * Recommendation判定へ曖昧なlexical比較を使用しない。
 *
 * @param[in] value Catalogまたは現在driver version。
 * @return 1～8 componentの数値群。形式不正時は<tt>std::nullopt</tt>。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::vector<std::uint64_t>> parseVersion( const std::wstring_view value)
{
	// 空または過長のversionを数値比較へ渡さない。
	if( value.empty() || value.size() > 128) {
		return std::nullopt ;
	}

	std::vector<std::uint64_t> parts ;		// Dot区切りversion component群。
	std::uint64_t			   part{} ;		// 現在componentの数値。
	bool					   hasDigit{} ;	// 現在componentに数字があればtrue。
	// 全文字を走査し、dotごとにoverflow検証済みcomponentを確定する。
	for( const wchar_t character : value) {
		// dotで現在componentを確定し、次の数値要素へ進める。
		if( character == L'.') {
			// 空componentと八要素を超えるversionを受理しない。
			if( !hasDigit || parts.size() >= 7) {
				return std::nullopt ;
			}

			parts.push_back( part) ;
			part	 = 0 ;
			hasDigit = false ;
			continue ;
		}

		// versionの数値要素にASCII数字以外を許可しない。
		if( character < L'0' || character > L'9') {
			return std::nullopt ;
		}

		const std::uint64_t digit = static_cast<std::uint64_t>( character - L'0') ;	// 現在桁。
		// version componentの桁追加でuint64範囲を超える前に拒否する。
		if( part > (std::numeric_limits<std::uint64_t>::max() - digit) / 10ULL) {
			return std::nullopt ;
		}

		part	 = part * 10ULL + digit ;
		hasDigit = true ;
	}

	// 末尾がdotで終わる不完全なversionを受理しない。
	if( !hasDigit) {
		return std::nullopt ;
	}

	parts.push_back( part) ;
	return parts ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つの数字versionを大小比較する。
 *
 * 不足componentを0として比較し、文字列桁数差に依存しない。
 *
 * @param[in] left 比較左辺version。
 * @param[in] right 比較右辺version。
 * @return 左辺が小なら-1、同値0、大なら1、解析不能時nullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<int> compareVersions( const std::wstring_view left,
												 const std::wstring_view right)
{
	const auto leftParts  = parseVersion( left) ;	// 左辺component群。
	const auto rightParts = parseVersion( right) ;	// 右辺component群。
	// 両versionを解析できなければ大小を推測しない。
	if( !leftParts.has_value() || !rightParts.has_value()) {
		return std::nullopt ;
	}

	const std::size_t count = std::max( leftParts->size(), rightParts->size()) ;	// 比較桁数。
	// 同じindexのcomponentを比較し、最初の差で大小を確定する。
	for( std::size_t index = 0; index < count; ++index) {
		const std::uint64_t leftPart =
			index < leftParts->size() ? (*leftParts)[index] : 0 ;	// 左component。
		const std::uint64_t rightPart =
			index < rightParts->size() ? (*rightParts)[index] : 0 ;	// 右component。
		// 最初に差があるcomponentで左側が小さいことを確定する。
		if( leftPart < rightPart) {
			return -1 ;
		}

		// 最初に差があるcomponentで左側が大きいことを確定する。
		if( leftPart > rightPart) {
			return 1 ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Dell候補のdriver操作分類を決定する。
 *
 * 数値比較不能な異種表記はReinstallとし自動選択しない。
 *
 * @param[in] candidate Dell vendorVersion。
 * @param[in] current SetupAPIが返した現在version。
 * @return Update、Reinstall、Downgradeのいずれか。
 */
//------------------------------------------------------------------------------
[[nodiscard]] DriverAction classifyAction( const std::wstring_view candidate,
										  const std::wstring_view current)
{
	const std::optional<int> comparison = compareVersions( candidate, current) ;	// 比較結果。
	// 比較不能なversionは通常更新へ昇格せず明示再導入に分類する。
	if( !comparison.has_value()) {
		return DriverAction::REINSTALL ;
	}

	// 候補版が現在版より大きいと確定した場合だけ更新へ分類する。
	if( comparison.value() > 0) {
		return DriverAction::UPDATE ;
	}

	return comparison.value() < 0 ? DriverAction::DOWNGRADE : DriverAction::REINSTALL ;
}

//------------------------------------------------------------------------------
/**
 * @brief Dell DUPを保護workspaceへ取得する。
 *
 * Payload cacheを使用せず、固定basenameのCREATE_NEW fileへ保存する。
 *
 * @param[in] client 公式HTTP client。
 * @param[in] url 検証済みDell DUP URL。
 * @param[in] maximumBytes Catalog宣言exact size。
 * @param[in] workspace 作成済み保護workspace。
 * @param[in] callback Download byte進捗通知先。
 * @return Downloadとhandle close成功時は0、失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError downloadPayload( OfficialHttpClient &client, const std::wstring_view url,
										  const std::uint64_t				  maximumBytes,
										  OfficialDownloadWorkspace			 &workspace,
										  const HttpDownloadProgressCallback &callback)
{
	HANDLE		file{INVALID_HANDLE_VALUE} ;							// CloseHandleで解放するDUP file handle。
	NativeError error = workspace.createFile( L"driver.exe", file) ;	// File作成結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	error =
		client.downloadForSource( url, OFFICIAL_PAYLOAD_RESOURCE_ID, maximumBytes, file, callback) ;
	// 取得中の失敗を上書きせず、fileのcloseだけが失敗した場合に記録する。
	if( CloseHandle( file) == FALSE && error == 0) {
		error = nativeErrorFromWin32( GetLastError()) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief Dell DUPを対話起動して終了を待つ。
 *
 * Silent optionを渡さず、DellのEULA、警告、選択UIを維持する。
 *
 * @param[in] path Hash・署名検証済みDUP絶対path。
 * @return Process exit code 0なら0、それ以外はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError runInstaller( const std::wstring_view path)
{
	std::wstring application( path) ;	// CreateProcessへ渡す終端null付きpath。
	STARTUPINFOW startup{} ;			// 既定process startup設定。
	startup.cb = sizeof( startup) ;
	PROCESS_INFORMATION process{} ;	// CloseHandleで解放するprocess/thread handle。
	// 検証済みDUPを起動できない場合はOSの診断値を返す。
	if( CreateProcessW( application.data(), nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr,
					  &startup, &process) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	CloseHandle( process.hThread) ;
	const DWORD waitResult = WaitForSingleObject( process.hProcess, INFINITE) ;	// 終了待機結果。
	NativeError result{} ;														// Process終了状態を反映する結果。
	// DUPの終了待ちが正常に完了しない場合は待機失敗を保持する。
	if( waitResult != WAIT_OBJECT_0) {
		result = nativeErrorFromWin32( GetLastError()) ;
	} else {
		DWORD exitCode{} ;	// Dell DUP process exit code。
		// 終了codeを取得できないDUPを導入成功としない。
		if( GetExitCodeProcess( process.hProcess, &exitCode) == FALSE) {
			result = nativeErrorFromWin32( GetLastError()) ;
		}
		// DUPが非ゼロ終了した場合はそのcodeを導入診断として保持する。
		else if( exitCode != 0) {
			result = nativeErrorFromWin32( exitCode) ;
		}
	}

	CloseHandle( process.hProcess) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのPowerEdge DUPを取得・検証・対話導入する。
 *
 * HTTPS、size、hash、Dell署名を再検証してから対話起動する。
 *
 * @param[in] client 公式HTTP client。
 * @param[in] sessionId 現在scan session ID。
 * @param[in] identity UI候補opaque identity。
 * @param[in] url Dell公式DUP URL。
 * @param[in] size Catalog宣言exact byte数。
 * @param[in] sha256 Catalog宣言SHA-256。
 * @param[in] rebootRequired Catalogの再起動宣言。
 * @param[in] progressCallback Download/install進捗通知先。
 * @return 個別download/install結果。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UpdateExecutionResult installTarget(
	OfficialHttpClient &client, const ScanSessionId sessionId, const std::wstring_view identity,
	const std::wstring_view url, const std::uint64_t size, const std::wstring_view sha256,
	const bool rebootRequired, const ProviderProgressCallback &progressCallback)
{
	UpdateExecutionResult result ;	// UI候補と対応する個別実行結果。
	result.identity = identity ;
	OfficialDownloadWorkspace workspace ;	// Scope終了時にDUPを削除する保護workspace。
	const NativeError		  workspaceError =
		// 作成結果。
		workspace.initialize( L"dell-server-dup", sessionId) ;
	// 保護workspaceの準備失敗時は取得・導入をともに未成功として返す。
	if( workspaceError != 0) {
		result.downloadOutcome = OutcomeCode::FAILURE ;
		result.downloadError   = workspaceError ;
		result.installOutcome  = OutcomeCode::FAILURE ;
		result.installError	   = workspaceError ;
		return result ;
	}

	NativeError downloadError = downloadPayload(
		client, url, size, workspace,
		[&progressCallback]( const std::uint64_t received, const std::uint64_t total) {
			const std::uint32_t percent =
				total == 0 ? 0
						   : static_cast<std::uint32_t>( std::min<std::uint64_t>(
								 80, received > total ? 80 : received * 80 / total)) ;	// 0～80%値。
			progressCallback( {.stage		   = ProviderStage::DOWNLOADING,
							  .percentComplete = percent,
							  .completedItems  = received,
							  .totalItems	   = total}) ;
		}) ; // DUP download結果。
	// 転送成功でも現在sessionの公式payload取得根拠がなければ拒否する。
	if( downloadError == 0 && !client.hasSourceEvidence( sessionId, DELL_POWER_EDGE_PROVIDER_ID,
													   OFFICIAL_PAYLOAD_RESOURCE_ID)) {
		downloadError = static_cast<NativeError>( E_UNEXPECTED) ;
	}

	// DUP取得が失敗した場合は導入を呼ばず同じ原因を個別結果へ残す。
	if( downloadError != 0) {
		result.downloadOutcome = OutcomeCode::FAILURE ;
		result.downloadError   = downloadError ;
		result.installOutcome  = OutcomeCode::FAILURE ;
		result.installError	   = downloadError ;
		return result ;
	}

	result.downloadOutcome = OutcomeCode::SUCCESS ;
	progressCallback( {.stage = ProviderStage::DOWNLOADING, .percentComplete = 85}) ;
	const std::wstring installer = workspace.path( L"driver.exe") ;	// 検証・起動対象path。
	const NativeError  verificationError =
		verifyOfficialFile( installer, {.expectedSize = size, .expectedSha256 = sha256},
						   DELL_PUBLISHERS) ;	// MetadataとAuthenticode検証結果。
	// file検証が失敗した場合は取得成功と区別して導入失敗を返す。
	if( verificationError != 0) {
		result.installOutcome = OutcomeCode::FAILURE ;
		result.installError	  = verificationError ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::INSTALLING, .percentComplete = 90}) ;
	const NativeError installError = runInstaller( installer) ;	// 対話DUP実行結果。
	// DUPの対話導入が失敗した場合は取得成功を維持して導入診断を返す。
	if( installError != 0) {
		result.installOutcome = OutcomeCode::FAILURE ;
		result.installError	  = installError ;
		return result ;
	}

	result.installOutcome = OutcomeCode::SUCCESS ;
	result.rebootRequired = rebootRequired ;
	progressCallback( {.stage		   = ProviderStage::INSTALLING,
					  .percentComplete = 100,
					  .completedItems  = 1,
					  .totalItems	   = 1}) ;
	return result ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/dell_server_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult DellServerUpdateProvider::scan( const ScanSessionId scanSessionId,
										  const std::span<const OfficialCatalogDevice> devices,
										  const LocalHardwareIdMatcher	 &hardwareIdMatcher,
										  const ProviderProgressCallback &progressCallback)
{
	invalidateScanSession() ;
	ScanResult result ;	// PowerEdge公式catalogのscan結果。
	result.scanSessionId = scanSessionId ;
	result.outcome		 = OutcomeCode::FAILURE ;
	result.state		 = ProviderScanState::FAILURE ;
	// sessionと端末内ID照合・進捗callbackが揃わないscan要求を拒否する。
	if( scanSessionId == 0 || !hardwareIdMatcher || !progressCallback) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	// ClientではServer専用のPowerEdge検索を行わず対象外を返す。
	if( !isWindowsServer()) {
		result.succeeded = true ;
		result.outcome	 = OutcomeCode::SUCCESS ;
		result.state	 = ProviderScanState::NOT_APPLICABLE ;
		scanSessionId_	 = scanSessionId ;
		progressCallback(
			{.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 100}) ;
		return result ;
	}

	DellServerSystemIdentity system ;												// Registry由来の非機密system識別値。
	bool					 applicable{} ;											// Dell PowerEdge表示ならtrue。
	NativeError				 error = readDellServerIdentity( system, applicable) ;	// 判定結果。
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	// 対応するDell PowerEdgeでなければ通信せず対象外を返す。
	if( !applicable) {
		result.succeeded = true ;
		result.outcome	 = OutcomeCode::SUCCESS ;
		result.state	 = ProviderScanState::NOT_APPLICABLE ;
		scanSessionId_	 = scanSessionId ;
		progressCallback(
			{.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 100}) ;
		return result ;
	}

	result.coverage.eligibleDeviceCount = devices.size() ;
	error = httpClient_.beginSourceSession( scanSessionId, DELL_POWER_EDGE_PROVIDER_ID) ;
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	DellServerCatalogLoadResult catalog =
		// 取得結果。
		loadDellServerCatalog( httpClient_, scanSessionId, progressCallback) ;
	// catalog取得・検証の失敗をmetadata拒否と処理失敗に分けて返す。
	if( catalog.error != 0) {
		result.state = catalog.metadataRejected ? ProviderScanState::METADATA_REJECTED
												: ProviderScanState::FAILURE ;
		result.error = catalog.error ;
		return result ;
	}

	std::vector<DellServerDriverRelease> releases ;	// Model/OS/x64検証済みdriver群。
	error = parseDellServerCatalog( catalog.xml, system.model, system.windowsBuild, releases) ;
	// Enterprise catalogの解析失敗をmetadata拒否として返す。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
					  .percentComplete = 75,
					  .completedItems  = 0,
					  .totalItems	   = releases.size()}) ;

	std::unordered_map<std::wstring, const OfficialCatalogDevice *>
		deviceMetadata ;	// Opaque identityからUI snapshotへの索引。
	deviceMetadata.reserve( devices.size()) ;
	// Candidate表示値をlocal照合結果から引けるよう一device一entryで索引化する。
	for( const OfficialCatalogDevice &device : devices) {
		deviceMetadata.try_emplace( device.deviceIdentity, &device) ;
	}

	std::size_t						 ordinal{} ;		// Candidate identity用session内連番。
	std::unordered_set<std::wstring> assessedDevices ;	// PCI IDがlocal一致したdevice集合。
	// 全releaseのcatalog PCI IDをlocal mapへ照合し、対応deviceごとに候補化する。
	for( const DellServerDriverRelease &release : releases) {
		std::unordered_set<std::wstring> matchedDevices ;	// このDUPへ一致したdevice集合。
		// catalog側の有限なID群だけを端末内matcherへ渡して対象deviceを解決する。
		for( const std::wstring &catalogId : release.hardwareIds) {
			const std::optional<std::wstring> matched = hardwareIdMatcher( catalogId) ;	// Local結果。
			// 端末内で解決できたopaque device identityだけを対象集合へ加える。
			if( matched.has_value()) {
				matchedDevices.insert( matched.value()) ;
			}
		}

		// 重複を除いた対象deviceごとに保持metadataを照合し、候補を構築する。
		for( const std::wstring &deviceIdentity : matchedDevices) {
			const auto metadata = deviceMetadata.find( deviceIdentity) ;	// Snapshot検索結果。
			// 現在のdevice snapshotにない照合結果を候補へ変換しない。
			if( metadata == deviceMetadata.end()) {
				continue ;
			}

			assessedDevices.insert( deviceIdentity) ;
			const OfficialCatalogDevice &device = *metadata->second ;	// 対応local device。
			UpdateCandidate				 candidate ;					// UIへ渡すPowerEdge公式release候補。
			candidate.identity = L"dell-server:" + std::to_wstring( scanSessionId) + L":" +
								 std::to_wstring( ordinal++) ;
			candidate.deviceIdentity = device.deviceIdentity ;
			candidate.providerId	 = std::wstring( DELL_POWER_EDGE_PROVIDER_ID) ;
			candidate.packageIdentity =
				L"dell-server-dup:" + release.releaseId + L":" + release.sha256 ;
			candidate.title =
				release.title + L" " + release.version + L" (" + release.dellVersion + L")" ;
			candidate.manufacturer		   = device.manufacturer ;
			candidate.model				   = device.model ;
			candidate.driverClass		   = device.driverClass ;
			candidate.deviceClassGuid	   = device.deviceClassGuid ;
			candidate.provider			   = L"Dell Technologies Inc." ;
			candidate.version			   = release.version ;
			candidate.driverDate		   = release.releaseDate ;
			candidate.sourceName		   = L"Dell PowerEdge 公式Enterpriseカタログ" ;
			candidate.sourceLocation	   = L"Dell公式 HTTPS（downloads.dell.com）" ;
			candidate.maximumDownloadBytes = release.size ;
			candidate.action			   = classifyAction( release.version, device.currentVersion) ;
			candidate.discoveryBasis	   = CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG ;
			candidate.audit				   = makeOfficialMetadataCandidateAudit() ;
			candidate.current			   = false ;
			candidate.recommended		   = false ;
			candidate.installable		   = false ;
			candidate.eulaAccepted		   = false ;
			candidate.allContentCached	   = false ;
			candidate.rebootMayBeRequired  = release.rebootRequired ;
			candidate.browseOnly		   = !release.recommended ;

			InstallTarget target ;	// Install時に再検証するDUP metadata。
			target.packageIdentity = candidate.packageIdentity ;
			target.releaseId	   = release.releaseId ;
			target.downloadUrl	   = L"https://downloads.dell.com/" + release.path ;
			target.sha256		   = release.sha256 ;
			target.deviceIdentity  = device.deviceIdentity ;
			target.size			   = release.size ;
			target.rebootRequired  = release.rebootRequired ;
			// 全G11 gate未接続の表示候補をProvider直接呼出しでも導入させない。
			if( candidate.installable) {
				installTargets_.emplace( candidate.identity, std::move( target)) ;
			}

			result.candidates.push_back( std::move( candidate)) ;
		}
	}

	std::unordered_map<std::wstring, std::size_t> recommendations ;	// Device別最高推奨index。
	// Recommended/Urgentかつ現在版より新しい候補からdevice別最高versionを選ぶ。
	for( std::size_t index = 0; index < result.candidates.size(); ++index) {
		const UpdateCandidate &candidate = result.candidates[index] ;	// 現在検査中候補。
		// install可能な通常更新だけを推奨候補の選定に使用する。
		if( !candidate.installable || candidate.action != DriverAction::UPDATE ||
		   candidate.browseOnly) {
			continue ;
		}

		const auto current = recommendations.find( candidate.deviceIdentity) ;	// 現在推奨候補。
		// 当該deviceの最初の通常更新を推奨比較の基準として保持する。
		if( current == recommendations.end()) {
			recommendations.emplace( candidate.deviceIdentity, index) ;
			continue ;
		}

		const std::optional<int> comparison =
			compareVersions( candidate.version,
							result.candidates[current->second].version) ;	// Version比較結果。
		// 比較可能でより大きい版に限ってdeviceの推奨候補を置き換える。
		if( comparison.has_value() && comparison.value() > 0) {
			current->second = index ;
		}
	}

	// 一deviceにつき一つだけ初期選択可能な推奨flagを設定する。
	for( const auto &[deviceIdentity, index] : recommendations) {
		static_cast<void>( deviceIdentity) ;
		result.candidates[index].recommended	   = true ;
		result.candidates[index].defaultPreference = CandidateDefaultPreference::OEM_VALIDATED ;
	}

	progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
					  .percentComplete = 100,
					  .completedItems  = releases.size(),
					  .totalItems	   = releases.size()}) ;
	result.succeeded = true ;
	result.outcome	 = OutcomeCode::SUCCESS ;
	result.state	 = result.candidates.empty() ? ProviderScanState::NO_CANDIDATES
												 : ProviderScanState::CANDIDATES_AVAILABLE ;
	result.coverage.assessedDeviceCount = assessedDevices.size() ;
	// catalogと分離署名の取得根拠が揃わなければsessionと候補を破棄する。
	if( !httpClient_.hasSourceEvidence( scanSessionId, DELL_POWER_EDGE_PROVIDER_ID,
									  OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ||
	   !httpClient_.hasSourceEvidence( scanSessionId, DELL_POWER_EDGE_PROVIDER_ID,
									  OFFICIAL_DETACHED_SIGNATURE_RESOURCE_ID)) {
		invalidateScanSession() ;
		result.candidates.clear() ;
		result.succeeded = false ;
		result.outcome	 = OutcomeCode::FAILURE ;
		result.state	 = ProviderScanState::SOURCE_REJECTED ;
		result.error	 = static_cast<NativeError>( E_UNEXPECTED) ;
		return result ;
	}

	scanSessionId_ = scanSessionId ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/dell_server_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult DellServerUpdateProvider::install( const ScanSessionId					scanSessionId,
												const std::span<const std::wstring> identities,
												const std::uintptr_t			parentWindowNative,
												const ProviderProgressCallback &progressCallback)
{
	static_cast<void>( parentWindowNative) ;
	InstallResult result ;	// PowerEdge選択全体の実行結果。
	// 実Server・現在session・選択・通知先・取得根拠が揃わない導入を拒否する。
	if( !isWindowsServer() || scanSessionId == 0 || scanSessionId != scanSessionId_ ||
	   identities.empty() || !progressCallback ||
	   !httpClient_.hasSourceEvidence( scanSessionId, DELL_POWER_EDGE_PROVIDER_ID,
									  OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ||
	   !httpClient_.hasSourceEvidence( scanSessionId, DELL_POWER_EDGE_PROVIDER_ID,
									  OFFICIAL_DETACHED_SIGNATURE_RESOURCE_ID)) {
		result.downloadOutcome = OutcomeCode::FAILURE ;
		result.downloadError   = static_cast<NativeError>( E_INVALIDARG) ;
		result.installOutcome  = OutcomeCode::FAILURE ;
		result.installError	   = static_cast<NativeError>( E_INVALIDARG) ;
		invalidateScanSession() ;
		return result ;
	}

	std::unordered_set<std::wstring>   uniqueIdentities ;	// 選択identity重複検証集合。
	std::unordered_set<std::wstring>   uniqueDevices ;		// 一device一候補検証集合。
	std::vector<PackageSelectionEntry> packageEntries ;		// CandidateとDUPの対応群。
	packageEntries.reserve( identities.size()) ;
	// System変更前に全選択targetをfail-closedで検証する。
	for( const std::wstring &identity : identities) {
		const auto target = installTargets_.find( identity) ;	// Scan時target検索結果。
		// 未知候補、重複identity、同device二選択をpackage取得前に拒否する。
		if( target == installTargets_.end() || !uniqueIdentities.insert( identity).second ||
		   !uniqueDevices.insert( target->second.deviceIdentity).second) {
			result.downloadOutcome = OutcomeCode::FAILURE ;
			result.downloadError   = static_cast<NativeError>( E_INVALIDARG) ;
			result.installOutcome  = OutcomeCode::FAILURE ;
			result.installError	   = static_cast<NativeError>( E_INVALIDARG) ;
			invalidateScanSession() ;
			return result ;
		}

		packageEntries.push_back(
			{.candidateIdentity = identity, .packageIdentity = target->second.packageIdentity}) ;
	}

	const auto packageGroups = groupPackageSelection( packageEntries) ;	// 重複排除済みDUP群。
	// package identityの集約が不正ならsessionを失効させて全選択を拒否する。
	if( !packageGroups.has_value()) {
		result.downloadOutcome = OutcomeCode::FAILURE ;
		result.downloadError   = static_cast<NativeError>( E_INVALIDARG) ;
		result.installOutcome  = OutcomeCode::FAILURE ;
		result.installError	   = static_cast<NativeError>( E_INVALIDARG) ;
		invalidateScanSession() ;
		return result ;
	}

	std::size_t downloaded{} ;	// Download成功candidate数。
	std::size_t installed{} ;	// Install成功candidate数。
	std::unordered_map<std::wstring, UpdateExecutionResult>
		executionResults ;	// Candidate identity別のDUP実行結果。
	executionResults.reserve( identities.size()) ;
	// 初出package順に公式DUPを一度だけ取得・検証・対話実行する。
	for( std::size_t packageIndex = 0; packageIndex < packageGroups->size(); ++packageIndex) {
		const std::vector<std::wstring> &package =
			(*packageGroups)[packageIndex].candidateIdentities ;			// 同一DUP候補群。
		const std::wstring	&representative = package.front() ;				// DUP実行に使う先頭identity。
		const InstallTarget &target = installTargets_.at( representative) ;	// 検証済みtarget。
		const std::uint32_t	 base	= static_cast<std::uint32_t>(
			   packageIndex * 100 / packageGroups->size()) ;	// Package開始percent。
		const std::uint32_t end = static_cast<std::uint32_t>(
			(packageIndex + 1) * 100 / packageGroups->size()) ;	// Package完了percent。
		const ProviderProgressCallback itemProgress = [&progressCallback, base,
													   end]( const ProviderProgress &progress) {
			ProviderProgress aggregate = progress ;	// 選択全体へ変換する進捗値。
			aggregate.percentComplete =
				std::min<std::uint32_t>( 100, base + progress.percentComplete * (end - base) / 100) ;
			progressCallback( aggregate) ;
		} ; // Package内進捗を全体percentへ写像するcallback。
		const UpdateExecutionResult packageResult = installTarget(
			httpClient_, scanSessionId, representative, target.downloadUrl, target.size,
			target.sha256, target.rebootRequired, itemProgress) ;	// 一回だけ実行するDUP結果。
		// 一つのDUP process結果を、このpackageを選択した各device候補へ関連付ける。
		for( const std::wstring &identity : package) {
			UpdateExecutionResult update = packageResult ;	// Identityだけ置換する候補別結果。
			update.identity				 = identity ;
			// packageの個別結果が取得成功の候補だけをdownload成功件数へ含める。
			if( update.downloadOutcome == OutcomeCode::SUCCESS) {
				++downloaded ;
			}

			// install成功だけを集計し、成功候補の再起動要求を全体へ引き継ぐ。
			if( update.installOutcome == OutcomeCode::SUCCESS) {
				++installed ;
				result.rebootRequired = result.rebootRequired || update.rebootRequired ;
			} else {
				// 最初のdownload診断を後続候補の失敗で上書きしない。
				if( result.downloadError == 0 && update.downloadError != 0) {
					result.downloadError = update.downloadError ;
				}

				// 最初のinstall診断を後続候補の失敗で上書きしない。
				if( result.installError == 0 && update.installError != 0) {
					result.installError = update.installError ;
				}
			}

			executionResults.emplace( identity, std::move( update)) ;
		}
	}

	result.updates.reserve( identities.size()) ;
	// Provider実行順ではなく利用者が選択したcandidate順へ結果を戻す。
	for( const std::wstring &identity : identities) {
		result.updates.push_back( std::move( executionResults.at( identity))) ;
	}

	result.succeeded = installed == identities.size() ;
	result.downloadOutcome =
		downloaded == identities.size()
			? OutcomeCode::SUCCESS
			: (downloaded == 0 ? OutcomeCode::FAILURE : OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
	result.installOutcome =
		installed == identities.size()
			? OutcomeCode::SUCCESS
			: (installed == 0 ? OutcomeCode::FAILURE : OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
	invalidateScanSession() ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/dell_server_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void DellServerUpdateProvider::invalidateScanSession() noexcept
{
	httpClient_.invalidateSourceSession() ;
	installTargets_.clear() ;
	scanSessionId_ = 0 ;
}

} // namespace drivercrate
