//------------------------------------------------------------------------------
/**
 * @file vaio_update_provider.cpp
 * @brief VAIO Global公式driver Provider実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  Registryの確保長と実取得長の混同を修正。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  OEM既定選択根拠追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  公式構造化探索経路追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式取得元policy registry接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式HTTP取得根拠記録追加。
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
 * @note VAIO公式の固定HTTPS JSONだけを取得し、model、OS、driver category、local device、payload hashを検証します。任意
 *       commandは実行しません。
 */
//------------------------------------------------------------------------------

#include "platform/vaio_update_provider.h"

#include "core/candidate_audit.h"
#include "core/official_source_policy.h"
#include "core/package_selection.h"
#include "core/provider_registry.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "platform/vaio_catalog_parser.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
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

constexpr std::wstring_view MODELS_URL =
	L"https://support.vaio.com/products/Models.json" ;	// Global model正本。
constexpr std::wstring_view PREINSTALLED_URL =
	L"https://support.vaio.com/global/sustaining/preinstDriversGlobal.json" ;	// Model driver表。
constexpr std::wstring_view UPDATES_URL =
	L"https://support.vaio.com/global/sustaining/UpdateListGlobal.json" ;		// Update正本。
constexpr std::uint64_t MAXIMUM_MODELS_BYTES	   = 512ULL * 1024ULL ;			// Models JSON上限。
constexpr std::uint64_t MAXIMUM_PREINSTALLED_BYTES = 2ULL * 1024ULL * 1024ULL ;	// Driver表上限。
constexpr std::uint64_t MAXIMUM_UPDATES_BYTES	   = 1ULL * 1024ULL * 1024ULL ;	// Update JSON上限。
constexpr std::uint64_t MAXIMUM_INSTALLER_BYTES =
	4ULL * 1024ULL * 1024ULL * 1024ULL ;	// VAIO payload上限。
constexpr std::array<std::wstring_view, 1> VAIO_PUBLISHERS{
	L"VAIO Corporation"} ;	// Authenticode許可publisher。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief Local registryから取得する非機密なVAIO system識別値である。
 */
struct VaioSystemIdentity {
	/// Model code照合用のSMBIOS表示値群。
	std::vector<std::wstring> modelValues ;
	/// `Windows 10`または`Windows 11`。
	std::wstring			  osName ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをNativeErrorへ変換する。
 *
 * 元のWin32診断値をProvider共通型へ保持する。
 *
 * @param[in] error Win32 APIが返したerror code。
 * @return HRESULT_FROM_WIN32で変換したbit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Registryの文字列値を上限付きで取得する。
 *
 * SMBIOS表示値とWindows buildだけを読み、serial値は読まない。
 *
 * @param[in] root 所有しないroot registry handle。
 * @param[in] subkey 読取り対象subkey。
 * @param[in] valueName REG_SZ value名。
 * @param[out] value 成功時の終端nullを除く文字列。
 * @return 成功時は0、型不一致・上限超過・API失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRegistryString( const HKEY root, const std::wstring_view subkey,
											 const std::wstring_view valueName, std::wstring &value)
{
	value.clear() ;
	std::wstring keyName( subkey) ;			// RegGetValue用終端null付きsubkey。
	std::wstring registryName( valueName) ;	// RegGetValue用終端null付きvalue名。
	DWORD		 type{} ;					// 取得したregistry型。
	DWORD		 bytes{} ;					// 終端nullを含む必要byte数。
	LSTATUS status = RegGetValueW( root, keyName.c_str(), registryName.c_str(), RRF_RT_REG_SZ, &type,
								  nullptr, &bytes) ;	// 必要size取得結果。
	// Registry の必要量照会に失敗した場合は返された status を保持する。
	if( status != ERROR_SUCCESS) {
		return nativeErrorFromWin32( static_cast<DWORD>( status)) ;
	}

	constexpr DWORD MAXIMUM_REGISTRY_BYTES = 32U * 1024U ;	// 一つの表示値上限。
	// REG_SZ 以外、長さ範囲外、UTF-16 単位に合わない値を拒否する。
	if( type != REG_SZ || bytes < sizeof( wchar_t) || bytes > MAXIMUM_REGISTRY_BYTES ||
	   bytes % sizeof( wchar_t) != 0) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::wstring buffer( bytes / sizeof( wchar_t), L'\0') ;	// 終端nullを含む取得buffer。
	status = RegGetValueW( root, keyName.c_str(), registryName.c_str(), RRF_RT_REG_SZ, &type,
						  // Registry読取り結果。
						  buffer.data(), &bytes) ;
	// Registry 本体の読取りに失敗した場合は部分文字列を使用しない。
	if( status != ERROR_SUCCESS) {
		return nativeErrorFromWin32( static_cast<DWORD>( status)) ;
	}

	// 容量照会より短い結果を許容するが、実データ内の不正なNULは拒否する。
	return decodeVaioRegistryString( buffer, bytes, type, value) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示文字列を大文字英数字だけの比較keyへ変換する。
 *
 * Maker名の空白とpunctuation差だけを吸収する。
 *
 * @param[in] value Registryの表示文字列。
 * @return ASCII英数字を大文字化した比較key。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizeName( const std::wstring_view value)
{
	std::wstring normalized ;	// 比較に必要なASCII英数字だけを保持するkey。
	normalized.reserve( value.size()) ;
	// ASCII英数字を順序どおり保持し、大小文字差を除去する。
	for( const wchar_t character : value) {
		// ASCII 小文字を比較 key 用の大文字へ変換する。
		if( character >= L'a' && character <= L'z') {
			normalized.push_back( static_cast<wchar_t>( character - L'a' + L'A')) ;
		}
		// 大文字英字と数字を比較 key にそのまま残す。
		else if( (character >= L'A' && character <= L'Z') ||
				(character >= L'0' && character <= L'9')) {
			normalized.push_back( character) ;
		}
	}

	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief Local端末がVAIO client PCか判定してmodel表示値を取得する。
 *
 * Serial numberを読まず、maker不一致時は追加registryを読まず対象外とする。
 *
 * @param[out] identity 成功時のmodel表示値とWindows名。
 * @param[out] applicable VAIO client PCの場合`true`。
 * @return 成功時は0、registry不正または未対応OS時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readVaioSystemIdentity( VaioSystemIdentity &identity, bool &applicable)
{
	identity   = {} ;
	applicable = false ;
	// VAIO system makerとmodelを読取り専用で照合するregistry key。
	constexpr std::wstring_view BIOS_KEY = L"HARDWARE\\DESCRIPTION\\System\\BIOS" ;
	std::wstring				manufacturer ;	// SMBIOS System Manufacturer表示値。
	// SystemManufacturerの読取りから端末照合へ引き継ぐ診断値。
	NativeError					error =
		readRegistryString( HKEY_LOCAL_MACHINE, BIOS_KEY, L"SystemManufacturer", manufacturer) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	const std::wstring maker = normalizeName( manufacturer) ;	// Maker比較key。
	// VAIO 製造元でない端末は対象外とし、model 照会を続けない。
	if( maker != L"VAIO" && maker != L"VAIOCORPORATION") {
		return 0 ;
	}

	// 製品表示名の補完に使用するSMBIOS由来registry値名の優先順。
	constexpr std::array<std::wstring_view, 3> MODEL_NAMES{L"SystemProductName", L"SystemSKU",
														   L"BaseBoardProduct"} ;
	// Serialを含まない三つのSMBIOS表示値だけをmodel照合候補として取得する。
	for( const std::wstring_view valueName : MODEL_NAMES) {
		std::wstring value ;	// 現在registryから取得するmodel表示値。
		error = readRegistryString( HKEY_LOCAL_MACHINE, BIOS_KEY, valueName, value) ;
		// 存在しない任意の model 表示値は他の local 値の探索へ進む。
		if( error == nativeErrorFromWin32( ERROR_FILE_NOT_FOUND)) {
			continue ;
		}

		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		// 取得できた非空の model 表示値だけを照合用 inventory に残す。
		if( !value.empty()) {
			identity.modelValues.push_back( std::move( value)) ;
		}
	}

	// 利用できる model 表示値が一つもない場合は対象 model を推測しない。
	if( identity.modelValues.empty()) {
		return nativeErrorFromWin32( ERROR_NOT_FOUND) ;
	}

	// 対象OSのbuildを読取り専用で取得するregistry key。
	constexpr std::wstring_view WINDOWS_KEY = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ;
	std::wstring				buildText ;	// CurrentBuildNumber文字列。
	error = readRegistryString( HKEY_LOCAL_MACHINE, WINDOWS_KEY, L"CurrentBuildNumber", buildText) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	std::uint64_t build{} ;	// 十進変換中のWindows build番号。
	// 空または表記上限を超える Windows build 値を拒否する。
	if( buildText.empty() || buildText.size() > 10) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// Build番号をoverflow検証付きで変換する。
	for( const wchar_t character : buildText) {
		// Build 表記に十進数字以外がある場合は OS 名を推測しない。
		if( character < L'0' || character > L'9') {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const std::uint64_t digit = static_cast<std::uint64_t>( character - L'0') ;	// 現在桁。
		// Build の次桁を加える前に数値 overflow を検出する。
		if( build > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
			return nativeErrorFromWin32( ERROR_ARITHMETIC_OVERFLOW) ;
		}

		build = build * 10 + digit ;
	}

	// Windows 11 の build 境界以上はその公式 OS 表示名へ対応付ける。
	if( build >= 22'000) {
		identity.osName = L"Windows 11" ;
	}
	// Windows 10 の build 範囲は対応する公式 OS 表示名へ分類する。
	else if( build >= 10'240) {
		identity.osName = L"Windows 10" ;
	} else {
		return nativeErrorFromWin32( ERROR_OLD_WIN_VERSION) ;
	}

	applicable = true ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つの数字dot versionを大小比較する。
 *
 * 1～8個の数字componentだけを比較し、異種表記を推測しない。
 *
 * @param[in] left 比較左辺version。
 * @param[in] right 比較右辺version。
 * @return 左辺が小なら-1、同値0、大なら1、解析不能時nullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<int> compareVersions( const std::wstring_view left,
												 const std::wstring_view right)
{
	const auto parse =
		[]( const std::wstring_view value) -> std::optional<std::vector<std::uint64_t>> {
		// 空または表記上限を超える version は比較不能として返す。
		if( value.empty() || value.size() > 128) {
			return std::nullopt ;
		}

		std::vector<std::uint64_t> parts ;		// 変換済みversion component群。
		std::uint64_t			   part{} ;		// 現在component数値。
		bool					   hasDigit{} ;	// 現在componentに数字がある場合true。
		// Dotごとにoverflow検証済みcomponentを確定する。
		for( const wchar_t character : value) {
			// Dot ごとに数値成分を確定し、次の version 成分を読み取る。
			if( character == L'.') {
				// 空の数値成分と許可成分数を超える区切りを拒否する。
				if( !hasDigit || parts.size() >= 7) {
					return std::nullopt ;
				}

				parts.push_back( part) ;
				part	 = 0 ;
				hasDigit = false ;
				continue ;
			}

			// Version 成分内の十進数字以外を拒否する。
			if( character < L'0' || character > L'9') {
				return std::nullopt ;
			}

			const std::uint64_t digit = static_cast<std::uint64_t>( character - L'0') ;	// 現在桁。
			// 次桁の加算で 64-bit を超える version 成分を拒否する。
			if( part > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
				return std::nullopt ;
			}

			part	 = part * 10 + digit ;
			hasDigit = true ;
		}

		// 最後の version 成分が空なら比較値を生成しない。
		if( !hasDigit) {
			return std::nullopt ;
		}

		parts.push_back( part) ;
		return parts ;
	} ;
	const auto leftParts  = parse( left) ;	// 左辺component群。
	const auto rightParts = parse( right) ;	// 右辺component群。
	// どちらかの version を解析できなければ大小関係を推測しない。
	if( !leftParts.has_value() || !rightParts.has_value()) {
		return std::nullopt ;
	}

	const std::size_t count = std::max( leftParts->size(), rightParts->size()) ;	// 比較桁数。
	// 最初に異なるcomponentで大小を確定する。
	for( std::size_t index = 0; index < count; ++index) {
		// 比較する左版数の現在成分。省略された末尾成分は0として扱う。
		const std::uint64_t leftPart = index < leftParts->size() ? (*leftParts)[index] : 0 ;
		// 比較する右版数の現在成分。省略された末尾成分は0として扱う。
		const std::uint64_t rightPart = index < rightParts->size() ? (*rightParts)[index] : 0 ;
		// 最初に異なる数値成分で version の大小関係を確定する。
		if( leftPart != rightPart) {
			return leftPart < rightPart ? -1 : 1 ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief VAIO候補のdriver操作分類を決定する。
 *
 * 数値比較不能な複合versionはReinstallとして自動選択しない。
 *
 * @param[in] candidate VAIO driver version。
 * @param[in] current SetupAPIが返した現在version。
 * @return Update、Reinstall、Downgradeのいずれか。
 */
//------------------------------------------------------------------------------
[[nodiscard]] DriverAction classifyAction( const std::wstring_view candidate,
										  const std::wstring_view current)
{
	const std::optional<int> comparison = compareVersions( candidate, current) ;	// 比較結果。
	// Version を比較できない候補は通常更新と断定せず再導入に分類する。
	if( !comparison.has_value()) {
		return DriverAction::REINSTALL ;
	}

	// 候補 version の方が大きい場合は更新に分類する。
	if( *comparison > 0) {
		return DriverAction::UPDATE ;
	}

	// 候補 version の方が小さい場合は旧版への切替に分類する。
	if( *comparison < 0) {
		return DriverAction::DOWNGRADE ;
	}

	return DriverAction::REINSTALL ;
}

//------------------------------------------------------------------------------
/**
 * @brief VAIO installerを対話起動して終了を待つ。
 *
 * Silent optionを渡さず、VAIO installerの同意UIを維持する。
 *
 * @param[in] path Hash・署名検証済みinstaller絶対path。
 * @param[out] rebootRequired Exit code 3010の場合`true`。
 * @return Process exit code 0または3010なら0、それ以外はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError runInstaller( const std::wstring_view path, bool &rebootRequired)
{
	rebootRequired = false ;
	std::wstring application( path) ;	// CreateProcessへ渡す終端null付きpath。
	STARTUPINFOW startup{} ;			// 既定process startup設定。
	startup.cb = sizeof( startup) ;
	PROCESS_INFORMATION process{} ;	// CloseHandleで解放するprocess/thread handle。
	// 確認対象 installer を起動できなければ Windows の診断値を返す。
	if( CreateProcessW( application.data(), nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr,
					  &startup, &process) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	CloseHandle( process.hThread) ;
	const DWORD waitResult = WaitForSingleObject( process.hProcess, INFINITE) ;	// 終了待機結果。
	NativeError result{} ;														// Process終了状態を反映する結果。
	// Process の正常な終了待ちが成立しない場合は待機失敗を保持する。
	if( waitResult != WAIT_OBJECT_0) {
		result = waitResult == WAIT_FAILED ? nativeErrorFromWin32( GetLastError())
										   : static_cast<NativeError>( E_FAIL) ;
	} else {
		DWORD exitCode{} ;	// VAIO installer process exit code。
		// Process の終了 code を取得できなければ導入成功と仮定しない。
		if( GetExitCodeProcess( process.hProcess, &exitCode) == FALSE) {
			result = nativeErrorFromWin32( GetLastError()) ;
		}
		// 再起動を要求する正常終了 code は再起動必要として保持する。
		else if( exitCode == ERROR_SUCCESS_REBOOT_REQUIRED) {
			rebootRequired = true ;
		}
		// その他の非成功終了 code を導入失敗の診断値へ変換する。
		else if( exitCode != ERROR_SUCCESS) {
			result = nativeErrorFromWin32( exitCode) ;
		}
	}

	CloseHandle( process.hProcess) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのVAIO payloadを取得・検証・対話導入する。
 *
 * 保護file、HTTPS、size、hash、VAIO署名を再検証して起動する。
 *
 * @param[in] client 公式host限定HTTP client。
 * @param[in] sessionId 現在scan session ID。
 * @param[in] identity UI候補opaque identity。
 * @param[in] url VAIO公式payload URL。
 * @param[in] size JSON宣言byte数。
 * @param[in] sha256 JSON宣言SHA-256。
 * @param[in] progressCallback Download/install進捗通知先。
 * @return 個別download/install結果。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UpdateExecutionResult installTarget(
	OfficialHttpClient &client, const ScanSessionId sessionId, const std::wstring_view identity,
	const std::wstring_view url, const std::uint64_t size, const std::wstring_view sha256,
	const ProviderProgressCallback &progressCallback)
{
	UpdateExecutionResult result ;	// UI候補と対応する個別実行結果。
	result.identity = identity ;
	OfficialDownloadWorkspace workspace ;											// Scope終了時にpayloadを削除する一時領域。
	const NativeError workspaceError = workspace.initialize( L"vaio", sessionId) ;	// 作成結果。
	// 取得 workspace の作成失敗は download と install の両段階へ明示する。
	if( workspaceError != 0) {
		result.downloadOutcome = OutcomeCode::FAILURE ;
		result.downloadError   = workspaceError ;
		result.installOutcome  = OutcomeCode::FAILURE ;
		result.installError	   = workspaceError ;
		return result ;
	}

	HANDLE			  file{INVALID_HANDLE_VALUE} ;									// CloseHandleで解放するdownload先file。
	const NativeError createError = workspace.createFile( L"driver.exe", file) ;	// 作成結果。
	// Payload 保存先の作成失敗時は network 取得と導入へ進まない。
	if( createError != 0) {
		result.downloadOutcome = OutcomeCode::FAILURE ;
		result.downloadError   = createError ;
		result.installOutcome  = OutcomeCode::FAILURE ;
		result.installError	   = createError ;
		return result ;
	}

	NativeError downloadError = client.downloadForSource(
		url, OFFICIAL_PAYLOAD_RESOURCE_ID, std::min( size, MAXIMUM_INSTALLER_BYTES), file,
		[&progressCallback]( const std::uint64_t received, const std::uint64_t total) {
			const std::uint32_t percent =
				total == 0 ? 0
						   : static_cast<std::uint32_t>( std::min<std::uint64_t>(
								 80, received > total ? 80 : received * 80 / total)) ;	// 進捗率。
			progressCallback( {.stage		   = ProviderStage::DOWNLOADING,
							  .percentComplete = percent,
							  .completedItems  = received,
							  .totalItems	   = total}) ;
		}) ;
	const BOOL		  closeResult = CloseHandle( file) ;	// Download file close結果。
	const NativeError closeError =
		// Close失敗結果。
		closeResult == FALSE ? nativeErrorFromWin32( GetLastError()) : 0 ;
	// 通信が成功しても同 session の公式取得根拠がない payload を受理しない。
	if( downloadError == 0 &&
	   !client.hasSourceEvidence( sessionId, VAIO_PROVIDER_ID, OFFICIAL_PAYLOAD_RESOURCE_ID)) {
		downloadError = static_cast<NativeError>( E_UNEXPECTED) ;
	}

	// Download または close の失敗を取得失敗とし、元の取得 error を優先する。
	if( downloadError != 0 || closeResult == FALSE) {
		const NativeError error = downloadError != 0 ? downloadError : closeError ;	// 最終失敗。
		result.downloadOutcome	= OutcomeCode::FAILURE ;
		result.downloadError	= error ;
		result.installOutcome	= OutcomeCode::FAILURE ;
		result.installError		= error ;
		return result ;
	}

	result.downloadOutcome = OutcomeCode::SUCCESS ;
	progressCallback( {.stage = ProviderStage::DOWNLOADING, .percentComplete = 85}) ;
	const std::wstring installer = workspace.path( L"driver.exe") ;	// 検証・起動対象path。
	const NativeError  verificationError =
		verifyOfficialFile( installer, {.expectedSize = size, .expectedSha256 = sha256},
						   VAIO_PUBLISHERS) ;	// Metadataとpublisher検証結果。
	// 取得物の検証失敗は download 成功と分離して導入失敗として返す。
	if( verificationError != 0) {
		result.installOutcome = OutcomeCode::FAILURE ;
		result.installError	  = verificationError ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::INSTALLING, .percentComplete = 90}) ;
	bool			  installerReboot{} ;											// Installer exit codeが要求した再起動状態。
	const NativeError installError = runInstaller( installer, installerReboot) ;	// 実行結果。
	// Installer の失敗を導入結果へ残し、取得成功と混同しない。
	if( installError != 0) {
		result.installOutcome = OutcomeCode::FAILURE ;
		result.installError	  = installError ;
		return result ;
	}

	result.installOutcome = OutcomeCode::SUCCESS ;
	result.rebootRequired = installerReboot ;
	progressCallback( {.stage		   = ProviderStage::INSTALLING,
					  .percentComplete = 100,
					  .completedItems  = 1,
					  .totalItems	   = 1}) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief Collectionが指定文字列を完全一致で含むか判定する。
 *
 * ModelとOSの部分一致を避ける共通比較を提供する。
 *
 * @param[in] values 検索対象文字列集合。
 * @param[in] expected 完全一致させる値。
 * @return 一件以上一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool contains( const std::span<const std::wstring> values,
							const std::wstring_view				expected) noexcept
{
	return std::find( values.begin(), values.end(), expected) != values.end() ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/vaio_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError decodeVaioRegistryString( const std::span<const wchar_t> buffer,
									 const std::uint32_t returnedBytes, const std::uint32_t type,
									 std::wstring &value)
{
	value.clear() ;
	constexpr std::uint32_t MAXIMUM_REGISTRY_BYTES = 32U * 1024U ;	// VAIO読取りと同じbyte上限。
	// 再取得時の型変更、奇数byte、領域外参照を値として受け入れない。
	if( type != REG_SZ || returnedBytes < sizeof( wchar_t) ||
	   returnedBytes > MAXIMUM_REGISTRY_BYTES || returnedBytes % sizeof( wchar_t) != 0U ||
	   returnedBytes / sizeof( wchar_t) > buffer.size()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::wstring_view text( buffer.data(), returnedBytes / sizeof( wchar_t)) ;	// 有効範囲だけのview。
	// 実取得範囲内の終端を必須にする。
	if( text.back() != L'\0') {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	text.remove_suffix( 1U) ;
	// 隠れた後続文字列を黙って切り捨てない。
	if( text.find( L'\0') != std::wstring_view::npos) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	value.assign( text) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/vaio_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult VaioUpdateProvider::scan( const ScanSessionId							 scanSessionId,
									const std::span<const OfficialCatalogDevice> devices,
									const LocalHardwareIdMatcher				&hardwareIdMatcher,
									const ProviderProgressCallback				&progressCallback)
{
	static_cast<void>( hardwareIdMatcher) ;
	invalidateScanSession() ;
	ScanResult result ;	// VAIO Provider単独のscan結果。
	result.scanSessionId = scanSessionId ;
	result.state		 = ProviderScanState::FAILURE ;
	result.outcome		 = OutcomeCode::FAILURE ;
	// 無効な scan session と必須進捗 callback の欠落を拒否する。
	if( scanSessionId == 0 || !progressCallback) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 0}) ;
	VaioSystemIdentity system ;													// Localで検証したmodel表示値とOS名。
	bool			   applicable{} ;											// VAIO client PCの場合true。
	NativeError		   error = readVaioSystemIdentity( system, applicable) ;	// 判定結果。
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	// Local 端末が VAIO 対象条件外なら公式 catalog を取得せず完了する。
	if( !applicable) {
		result.succeeded = true ;
		result.state	 = ProviderScanState::NOT_APPLICABLE ;
		result.outcome	 = OutcomeCode::SUCCESS ;
		progressCallback(
			{.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 100}) ;
		return result ;
	}

	result.coverage.eligibleDeviceCount = devices.size() ;

	error = httpClient_.beginSourceSession( scanSessionId, VAIO_PROVIDER_ID) ;
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	std::wstring modelsJson ;	// UTF-16変換済みModels.json。
	error = httpClient_.getUtf8TextForSource( MODELS_URL, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
											 MAXIMUM_MODELS_BYTES, modelsJson) ;
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	std::vector<VaioModel> models ;	// 検証済みGlobal model集合。
	error = parseVaioModelCatalog( modelsJson, models) ;
	// Model metadata の解析失敗は候補なしではなく metadata 拒否として返す。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	const std::optional<std::wstring> model =
		// Local model照合結果。
		matchVaioModelCode( models, system.modelValues) ;
	// 公式 model を一意に解決できなければ対象外として scan を完了する。
	if( !model.has_value()) {
		result.succeeded = true ;
		result.state	 = ProviderScanState::NOT_APPLICABLE ;
		result.outcome	 = OutcomeCode::SUCCESS ;
		progressCallback(
			{.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 100}) ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 20}) ;

	std::wstring preinstalledJson ;	// UTF-16変換済みpre-installed driver JSON。
	error =
		httpClient_.getUtf8TextForSource( PREINSTALLED_URL, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
										 MAXIMUM_PREINSTALLED_BYTES, preinstalledJson) ;
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	std::vector<VaioPreinstalledDriver> preinstalled ;	// 検証済みmodel/category表。
	error = parseVaioPreinstalledCatalog( preinstalledJson, preinstalled) ;
	// Pre-installed metadata の解析失敗を scan 結果へ明示する。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 45}) ;

	std::wstring updatesJson ;	// UTF-16変換済みupdate JSON。
	error = httpClient_.getUtf8TextForSource( UPDATES_URL, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
											 MAXIMUM_UPDATES_BYTES, updatesJson) ;
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	std::vector<VaioDriverRelease> releases ;	// 検証済みdriver update群。
	error = parseVaioUpdateCatalog( updatesJson, releases) ;
	// Update metadata の解析失敗を候補なしの成功に置き換えない。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 70}) ;

	std::unordered_map<std::wstring, const OfficialCatalogDevice *> deviceMetadata ;	// Device索引。
	deviceMetadata.reserve( devices.size()) ;
	// Candidate構築時にopaque identityから表示metadataを取得できるよう索引化する。
	for( const OfficialCatalogDevice &device : devices) {
		deviceMetadata.try_emplace( device.deviceIdentity, &device) ;
	}

	std::unordered_map<std::wstring, std::wstring> categoryTitles ;	// Model別driver title集合。
	// Table 1に存在する現在modelのdriver分類だけをUpdate審査へ渡す。
	for( const VaioPreinstalledDriver &driver : preinstalled) {
		// 対象 table・model・driver category に一致しない初期配布情報を除外する。
		if( !driver.tableOne || !contains( driver.models, *model) ||
		   !isVaioDriverCategory( driver.categoryId)) {
			continue ;
		}

		auto [position, inserted] =
			// Category登録結果。
			categoryTitles.try_emplace( driver.categoryId, driver.title) ;
		// 同じ category の既存 title にない名称だけを表示照合情報へ追加する。
		if( !inserted && position->second.find( driver.title) == std::wstring::npos) {
			position->second += L" / " + driver.title ;
		}
	}

	std::size_t						 ordinal{} ;		// Candidate identity用連番。
	std::unordered_set<std::wstring> assessedDevices ;	// 一意照合できたdevice集合。
	// Model、OS、Table 1 categoryが一致するreleaseを一意なlocal deviceへ解決する。
	for( const VaioDriverRelease &release : releases) {
		const auto preinstalledTitle = categoryTitles.find( release.categoryId) ;	// Table照合結果。
		// Model・OS・初期配布 category の対応が成立しない release を除外する。
		if( !contains( release.models, *model) || !contains( release.osNames, system.osName) ||
		   preinstalledTitle == categoryTitles.end()) {
			continue ;
		}

		const std::wstring matchTitle =
			release.title + L" / " + preinstalledTitle->second ;	// Maker照合用公式title。
		const std::optional<std::wstring> deviceIdentity =
			// 一意device。
			matchVaioDriverDevice( release.categoryId, matchTitle, devices) ;
		// 一意の local device に解決できない release は候補を発行しない。
		if( !deviceIdentity.has_value()) {
			continue ;
		}

		const auto metadata = deviceMetadata.find( *deviceIdentity) ;	// Device表示metadata。
		// 解決済み device の metadata がない場合は候補の詳細を推測しない。
		if( metadata == deviceMetadata.end()) {
			continue ;
		}

		assessedDevices.insert( *deviceIdentity) ;
		const OfficialCatalogDevice &device = *metadata->second ;	// 対応local snapshot。
		UpdateCandidate				 candidate ;					// UIへ渡すVAIO候補。
		candidate.identity =
			L"vaio:" + std::to_wstring( scanSessionId) + L":" + std::to_wstring( ordinal++) ;
		candidate.deviceIdentity  = device.deviceIdentity ;
		candidate.providerId	  = std::wstring( VAIO_PROVIDER_ID) ;
		candidate.packageIdentity = L"vaio-package:" + release.softwareId + L":" + release.sha256 ;
		candidate.title			  = release.title + L" " + release.version ;
		candidate.manufacturer	  = device.manufacturer ;
		candidate.model			  = device.model ;
		candidate.driverClass	  = device.driverClass ;
		candidate.deviceClassGuid = device.deviceClassGuid ;
		candidate.provider		  = L"VAIO Corporation" ;
		candidate.version		  = release.version ;
		candidate.driverDate	  = release.releaseDate ;
		candidate.sourceName	  = L"VAIO Global 公式ドライバーカタログ" ;
		candidate.sourceLocation =
			L"VAIO公式 HTTPS（support.vaio.com / dlcdnglobal.support.vaio.com）" ;
		candidate.maximumDownloadBytes = release.size ;
		candidate.action			   = classifyAction( release.version, device.currentVersion) ;
		candidate.current			   = false ;
		candidate.recommended		   = false ;
		candidate.defaultPreference	   = CandidateDefaultPreference::NONE ;
		candidate.discoveryBasis	   = CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG ;
		candidate.audit				   = makeOfficialMetadataCandidateAudit() ;
		candidate.installable		   = false ;
		candidate.eulaAccepted		   = false ;
		candidate.allContentCached	   = false ;
		candidate.rebootMayBeRequired  = true ;
		candidate.browseOnly		   = candidate.action != DriverAction::UPDATE ;

		InstallTarget target ;	// Install時に再検証するpayload metadata。
		target.packageIdentity = candidate.packageIdentity ;
		target.downloadUrl	   = release.installerUrl ;
		target.sha256		   = release.sha256 ;
		target.deviceIdentity  = device.deviceIdentity ;
		target.size			   = release.size ;
		// 全G11 gate未接続の表示候補をProvider直接呼出しでも導入させない。
		if( candidate.installable) {
			installTargets_.emplace( candidate.identity, std::move( target)) ;
		}

		result.candidates.push_back( std::move( candidate)) ;
	}

	progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
					  .percentComplete = 100,
					  .completedItems  = releases.size(),
					  .totalItems	   = releases.size()}) ;
	result.succeeded = true ;
	result.state	 = result.candidates.empty() ? ProviderScanState::NO_CANDIDATES
												 : ProviderScanState::CANDIDATES_AVAILABLE ;
	result.outcome	 = OutcomeCode::SUCCESS ;
	result.coverage.assessedDeviceCount = assessedDevices.size() ;
	// 候補公開前に公式 metadata の取得根拠を再確認し、欠落時は session ごと失効させる。
	if( !httpClient_.hasSourceEvidence( scanSessionId, VAIO_PROVIDER_ID,
									  OFFICIAL_PRIMARY_METADATA_RESOURCE_ID)) {
		invalidateScanSession() ;
		result.candidates.clear() ;
		result.succeeded = false ;
		result.state	 = ProviderScanState::SOURCE_REJECTED ;
		result.outcome	 = OutcomeCode::FAILURE ;
		result.error	 = static_cast<NativeError>( E_UNEXPECTED) ;
		return result ;
	}

	scanSessionId_ = scanSessionId ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/vaio_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult VaioUpdateProvider::install( const ScanSessionId				  scanSessionId,
										  const std::span<const std::wstring> identities,
										  const std::uintptr_t				  parentWindowNative,
										  const ProviderProgressCallback	 &progressCallback)
{
	static_cast<void>( parentWindowNative) ;
	InstallResult result ;	// VAIO選択全体の実行結果。
	// 現 session、非空選択、進捗通知、取得根拠が揃わない導入要求を拒否する。
	if( scanSessionId == 0 || scanSessionId != scanSessionId_ || identities.empty() ||
	   !progressCallback ||
	   !httpClient_.hasSourceEvidence( scanSessionId, VAIO_PROVIDER_ID,
									  OFFICIAL_PRIMARY_METADATA_RESOURCE_ID)) {
		result.downloadOutcome = OutcomeCode::FAILURE ;
		result.downloadError   = static_cast<NativeError>( E_INVALIDARG) ;
		result.installOutcome  = OutcomeCode::FAILURE ;
		result.installError	   = static_cast<NativeError>( E_INVALIDARG) ;
		invalidateScanSession() ;
		return result ;
	}

	std::unordered_set<std::wstring>   uniqueIdentities ;	// 選択identity重複検証集合。
	std::unordered_set<std::wstring>   uniqueDevices ;		// 一device一候補の重複検証集合。
	std::vector<PackageSelectionEntry> packageEntries ;		// Candidateとpayloadの対応群。
	packageEntries.reserve( identities.size()) ;
	// System変更前に全選択targetをfail-closedで検証する。
	for( const std::wstring &identity : identities) {
		const auto target = installTargets_.find( identity) ;	// Scan時target検索結果。
		// 未知候補、重複 ID、同じ device の重複選択を system 変更前に拒否する。
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

	const auto packageGroups = groupPackageSelection( packageEntries) ;	// 重複排除済みpayload群。
	// Package 単位の正規化が成立しない要求は session を失効させて拒否する。
	if( !packageGroups.has_value()) {
		invalidateScanSession() ;
		result.downloadOutcome = OutcomeCode::FAILURE ;
		result.downloadError   = static_cast<NativeError>( E_INVALIDARG) ;
		result.installOutcome  = OutcomeCode::FAILURE ;
		result.installError	   = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	std::size_t downloaded{} ;													// Downloadが成功した候補数。
	std::size_t installed{} ;													// Installまで成功した候補数。
	std::unordered_map<std::wstring, UpdateExecutionResult> executionResults ;	// 候補別結果。
	executionResults.reserve( identities.size()) ;
	// 初出package順に公式payloadを一度だけ取得・検証・対話実行する。
	for( std::size_t packageIndex = 0; packageIndex < packageGroups->size(); ++packageIndex) {
		const std::vector<std::wstring> &package =
			(*packageGroups)[packageIndex].candidateIdentities ;			// 同一payload候補群。
		const std::wstring	&representative = package.front() ;				// 実行に使う先頭identity。
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
		} ;
		const UpdateExecutionResult packageResult =
			installTarget( httpClient_, scanSessionId, representative, target.downloadUrl,
						  target.size, target.sha256, itemProgress) ;	// 一回だけの実行結果。
		// 一つのprocess結果を、このpayloadを選択した各candidateへ関連付ける。
		for( const std::wstring &identity : package) {
			UpdateExecutionResult update = packageResult ;	// Candidate別結果copy。
			update.identity				 = identity ;
			// 取得成功候補だけを download 完了件数へ加える。
			if( update.downloadOutcome == OutcomeCode::SUCCESS) {
				++downloaded ;
			}

			// 導入成功候補だけを install 完了件数へ加え、その再起動要否を集約する。
			if( update.installOutcome == OutcomeCode::SUCCESS) {
				++installed ;
				result.rebootRequired = result.rebootRequired || update.rebootRequired ;
			} else {
				// 全体に取得 error がない場合だけ最初の個別取得失敗を保持する。
				if( result.downloadError == 0 && update.downloadError != 0) {
					result.downloadError = update.downloadError ;
				}

				// 全体に導入 error がない場合だけ最初の個別導入失敗を保持する。
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
 * @see src/platform/vaio_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void VaioUpdateProvider::invalidateScanSession() noexcept
{
	httpClient_.invalidateSourceSession() ;
	installTargets_.clear() ;
	scanSessionId_ = 0 ;
}

} // namespace drivercrate
