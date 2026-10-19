//------------------------------------------------------------------------------
/**
 * @file hp_update_provider.cpp
 * @brief HP公式SoftPaq Provider実装。
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
 * @note HP公式HTTPSから署名付きplatform listとreference CABを取得し、driver category、Platform／OS、Hardware ID、
 *       payload hashを検証します。Reference内の任意commandは実行せず、検証済みSoftPaqを対話起動します。
 */
//------------------------------------------------------------------------------

#include "platform/hp_update_provider.h"

#include "core/candidate_audit.h"
#include "core/official_source_policy.h"
#include "core/package_selection.h"
#include "core/provider_registry.h"
#include "platform/hp_catalog_parser.h"
#include "platform/official_catalog_validation.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"

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

constexpr std::wstring_view PLATFORM_LIST_URL =
	L"https://hpia.hpcloud.hp.com/ref/platformList.cab" ;								// 署名付きplatform list。
constexpr std::array<std::wstring_view, 1> HP_PUBLISHERS{L"HP Inc."} ;					// 許可publisher。
constexpr std::uint64_t MAXIMUM_PLATFORM_LIST_CAB_BYTES = 8ULL * 1024ULL * 1024ULL ;	// CAB上限。
constexpr std::uint64_t MAXIMUM_REFERENCE_CAB_BYTES		= 32ULL * 1024ULL * 1024ULL ;	// CAB上限。
constexpr std::uint64_t MAXIMUM_PLATFORM_LIST_XML_BYTES = 16ULL * 1024ULL * 1024ULL ;	// XML上限。
constexpr std::uint64_t MAXIMUM_REFERENCE_XML_BYTES		= 64ULL * 1024ULL * 1024ULL ;	// XML上限。
constexpr std::uint64_t MAXIMUM_INSTALLER_BYTES =
	4ULL * 1024ULL * 1024ULL * 1024ULL ;	// SoftPaq上限。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief Local registryから得る非機密なHP system識別値である。
 */
struct HpSystemIdentity {
	/// BaseBoardProduct由来の4桁大文字hex Platform ID。
	std::wstring  systemId ;
	/// CurrentBuildNumber由来のWindows build番号。
	std::uint32_t osBuild{} ;
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
 * @brief 表示名を大文字英数字だけの比較keyへ変換する。
 *
 * 空白とpunctuation差だけを吸収し、部分一致には使用しない。
 *
 * @param[in] value Registryの表示文字列。
 * @return 区切りを除いて大文字化した比較key。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizeName( const std::wstring_view value)
{
	std::wstring normalized ;	// 比較に必要な英数字だけを保持するkey。
	normalized.reserve( value.size()) ;
	// Unicode英数字を順序通り保持し、大小文字差を除去する。
	for( const wchar_t character : value) {
		// 表示名の英数字だけを比較keyへ残し、表記上の区切り差を除く。
		if( std::iswalnum( character) != 0) {
			normalized.push_back( static_cast<wchar_t>( std::towupper( character))) ;
		}
	}

	return normalized ;
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
								  nullptr, &bytes) ;	// Size取得結果。
	// registry値の属性照会失敗を元の診断値で返す。
	if( status != ERROR_SUCCESS) {
		return nativeErrorFromWin32( static_cast<DWORD>( status)) ;
	}

	constexpr DWORD MAXIMUM_REGISTRY_BYTES = 4096 ;	// 表示文字列の安全な上限。
	// 文字列型、byte上限、文字境界が整合しないregistry値を拒否する。
	if( type != REG_SZ || bytes < sizeof( wchar_t) || bytes > MAXIMUM_REGISTRY_BYTES ||
	   bytes % sizeof( wchar_t) != 0) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::vector<wchar_t> buffer( bytes / sizeof( wchar_t)) ;	// Registry文字列受信buffer。
	status = RegGetValueW( root, keyName.c_str(), registryName.c_str(), RRF_RT_REG_SZ, &type,
						  // 値取得結果。
						  buffer.data(), &bytes) ;
	// registry本文の取得失敗を元の診断値で返す。
	if( status != ERROR_SUCCESS) {
		return nativeErrorFromWin32( static_cast<DWORD>( status)) ;
	}

	// 終端のないregistry文字列を後続の比較へ渡さない。
	if( buffer.empty() || buffer.back() != L'\0') {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	value.assign( buffer.data()) ;
	return value.empty() ? nativeErrorFromWin32( ERROR_INVALID_DATA) : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Local systemが対応HP client PCか判定する。
 *
 * Manufacturer不一致とServerは対象外としnetworkへ接続しない。Serial numberやHardware IDは読み取らない。
 *
 * @param[out] identity 成功時のPlatform IDとWindows build。
 * @param[out] applicable HP client PCの場合`true`。
 * @return 判定成功時は0、HP端末の必須値不正時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readHpSystemIdentity( HpSystemIdentity &identity, bool &applicable)
{
	identity   = {} ;
	applicable = false ;
	// HP system makerとmodelを読取り専用で取得するregistry key。
	constexpr std::wstring_view BIOS_KEY = L"HARDWARE\\DESCRIPTION\\System\\BIOS" ;
	std::wstring				manufacturer ;	// SMBIOS由来system manufacturer。
	// SystemManufacturerの読取りからsystem識別へ引き継ぐ診断値。
	NativeError					error =
		readRegistryString( HKEY_LOCAL_MACHINE, BIOS_KEY, L"SystemManufacturer", manufacturer) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	const std::wstring manufacturerKey = normalizeName( manufacturer) ;	// 完全一致用key。
	// 既知のHP製造者表記でない端末をこのProviderの対象にしない。
	if( manufacturerKey != L"HP" && manufacturerKey != L"HPINC" &&
	   manufacturerKey != L"HEWLETTPACKARD" && manufacturerKey != L"HEWLETTPACKARDCOMPANY") {
		return 0 ;
	}

	// 現在OSのbuildを読取り専用で取得するregistry key。
	constexpr std::wstring_view WINDOWS_KEY = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ;
	std::wstring				installationType ;	// Windows client/server分類。
	error =
		readRegistryString( HKEY_LOCAL_MACHINE, WINDOWS_KEY, L"InstallationType", installationType) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	// Windows client以外をHP client catalogの対象にしない。
	if( normalizeName( installationType) != L"CLIENT") {
		return 0 ;
	}

	std::wstring boardProduct ;	// SMBIOS BaseBoard ProductのPlatform ID候補。
	error = readRegistryString( HKEY_LOCAL_MACHINE, BIOS_KEY, L"BaseBoardProduct", boardProduct) ;
	// 基板製品IDの取得失敗や固定長不一致をmetadata失敗として返す。
	if( error != 0 || boardProduct.size() != 4) {
		return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	identity.systemId.reserve( boardProduct.size()) ;
	// 4文字をASCII hexadecimalとして検証し、大文字へ正規化する。
	for( const wchar_t character : boardProduct) {
		// platform IDの数字はそのまま照合値へ保持する。
		if( character >= L'0' && character <= L'9') {
			identity.systemId.push_back( character) ;
		}
		// 小文字hexをcatalog照合用の大文字へ揃える。
		else if( character >= L'a' && character <= L'f') {
			identity.systemId.push_back( static_cast<wchar_t>( character - L'a' + L'A')) ;
		}
		// 大文字hexは正規形として保持する。
		else if( character >= L'A' && character <= L'F') {
			identity.systemId.push_back( character) ;
		} else {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}
	}

	std::wstring buildText ;	// Windows CurrentBuildNumber原文。
	error = readRegistryString( HKEY_LOCAL_MACHINE, WINDOWS_KEY, L"CurrentBuildNumber", buildText) ;
	// OS buildの取得失敗、空値、桁数超過を拒否する。
	if( error != 0 || buildText.empty() || buildText.size() > 10) {
		return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::uint64_t build{} ;	// Decimal変換したWindows build番号。
	// 全桁をoverflow検証しながらdecimalへ変換する。
	for( const wchar_t character : buildText) {
		// OS buildに10進数字以外を許容しない。
		if( character < L'0' || character > L'9') {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const std::uint64_t digit = static_cast<std::uint64_t>( character - L'0') ;	// 現在桁。
		// 次の桁を加える前にOS buildの32-bit overflowを検出する。
		if( build > (std::numeric_limits<std::uint32_t>::max() - digit) / 10) {
			return nativeErrorFromWin32( ERROR_ARITHMETIC_OVERFLOW) ;
		}

		build = build * 10 + digit ;
	}

	constexpr std::uint64_t MINIMUM_WINDOWS10_BUILD = 10240 ;	// 対応Windows 10下限。
	// 対応最小build未満のWindowsをこのProviderの対象にしない。
	if( build < MINIMUM_WINDOWS10_BUILD) {
		return 0 ;
	}

	identity.osBuild = static_cast<std::uint32_t>( build) ;
	applicable		 = true ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式URLを保護一時fileへ取得する。
 *
 * Redirect、平文HTTP、host変更は共通clientが拒否する。
 *
 * @param[in] client 公式host限定HTTP client。
 * @param[in] url HP公式HTTPS URL。
 * @param[in] resourceId Policyで照合するresource ID。
 * @param[in] maximumBytes 応答body上限byte数。
 * @param[in,out] workspace CREATE_NEWする保護一時領域。
 * @param[in] name 外部入力を含まない固定basename。
 * @param[in] catalog Metadata cacheを使用する場合`true`。
 * @param[in] progressCallback 受信byte進捗通知先。
 * @return Downloadとhandle close成功時は0、失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError downloadFile( OfficialHttpClient &client, const std::wstring_view url,
									   const std::wstring_view	  resourceId,
									   const std::uint64_t		  maximumBytes,
									   OfficialDownloadWorkspace &workspace,
									   const std::wstring_view name, const bool catalog,
									   const HttpDownloadProgressCallback &progressCallback)
{
	HANDLE			  file{INVALID_HANDLE_VALUE} ;						// CloseHandleで解放するdownload先file。
	const NativeError createError = workspace.createFile( name, file) ;	// File作成結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( createError != 0) {
		return createError ;
	}

	const NativeError downloadError =
		catalog
			? client.downloadCatalogForSource( url, resourceId, maximumBytes, file, progressCallback)
			: client.downloadForSource( url, resourceId, maximumBytes, file,
									   progressCallback) ;	// HTTP取得結果。
	const BOOL closeResult = CloseHandle( file) ;			// File close結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( downloadError != 0) {
		return downloadError ;
	}

	return closeResult == FALSE ? nativeErrorFromWin32( GetLastError()) : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 数字dot形式versionをcomponent群へ変換する。
 *
 * Recommendation判定へ曖昧なlexical比較を使用しない。
 *
 * @param[in] value WindowsまたはHP driver version。
 * @return 1～8 componentの数値群。形式不正時は<tt>std::nullopt</tt>。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::vector<std::uint64_t>> parseVersion( const std::wstring_view value)
{
	// 空または長すぎる版を数値比較の対象にしない。
	if( value.empty() || value.size() > 128) {
		return std::nullopt ;
	}

	std::vector<std::uint64_t> parts ;		// Dot区切りで変換したversion component群。
	std::uint64_t			   part{} ;		// 現在componentの数値。
	bool					   hasDigit{} ;	// 現在componentに一桁以上あればtrue。
	// 全文字を走査し、dotごとにoverflow検証済みcomponentを確定する。
	for( const wchar_t character : value) {
		// dotで版要素を確定し、次の数値要素へ進む。
		if( character == L'.') {
			// 空要素と許可数を超える版構成を拒否する。
			if( !hasDigit || parts.size() >= 7) {
				return std::nullopt ;
			}

			parts.push_back( part) ;
			part	 = 0 ;
			hasDigit = false ;
			continue ;
		}

		// 版要素に10進数字以外を含めない。
		if( character < L'0' || character > L'9') {
			return std::nullopt ;
		}

		const std::uint64_t digit = static_cast<std::uint64_t>( character - L'0') ;	// 現在桁。
		// 版要素の64-bit overflowを桁追加前に検出する。
		if( part > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
			return std::nullopt ;
		}

		part	 = part * 10 + digit ;
		hasDigit = true ;
	}

	// 末尾が空要素の版を数値版として採用しない。
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
	// どちらかの版を数値化できない場合は大小関係を推測しない。
	if( !leftParts.has_value() || !rightParts.has_value()) {
		return std::nullopt ;
	}

	const std::size_t count = std::max( leftParts->size(), rightParts->size()) ;	// 比較桁数。
	// 同じindexのcomponentを比較し、最初の差で大小を確定する。
	for( std::size_t index = 0; index < count; ++index) {
		// 比較する左版数の現在成分。欠けた末尾成分は0として扱う。
		const std::uint64_t leftPart = index < leftParts->size() ? (*leftParts)[index] : 0 ;
		// 比較する右版数の現在成分。欠けた末尾成分は0として扱う。
		const std::uint64_t rightPart = index < rightParts->size() ? (*rightParts)[index] : 0 ;
		// 最初に異なる数値要素が小さい側を旧版と判定する。
		if( leftPart < rightPart) {
			return -1 ;
		}

		// 最初に異なる数値要素が大きい側を新版と判定する。
		if( leftPart > rightPart) {
			return 1 ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief HP候補のdriver操作分類を決定する。
 *
 * 数値比較不能な異種表記はReinstallとし自動選択しない。
 *
 * @param[in] candidate HP driver version。
 * @param[in] current SetupAPIが返した現在version。
 * @return Update、Reinstall、Downgradeのいずれか。
 */
//------------------------------------------------------------------------------
[[nodiscard]] DriverAction classifyAction( const std::wstring_view candidate,
										  const std::wstring_view current)
{
	const std::optional<int> comparison = compareVersions( candidate, current) ;	// 比較結果。
	// 比較不能な版を通常更新とせず、明示選択の再導入分類に置く。
	if( !comparison.has_value()) {
		return DriverAction::REINSTALL ;
	}

	// 比較可能な候補版が現在版を上回る場合だけ通常更新に分類する。
	if( comparison.value() > 0) {
		return DriverAction::UPDATE ;
	}

	// 候補版が現在版を下回る場合は旧版への切替として区別する。
	if( comparison.value() < 0) {
		return DriverAction::DOWNGRADE ;
	}

	return DriverAction::REINSTALL ;
}

//------------------------------------------------------------------------------
/**
 * @brief HP SoftPaqを対話起動して終了を待つ。
 *
 * Reference内commandやsilent optionを渡さず、HPの同意UIと警告を維持する。
 *
 * @param[in] path Hash・署名検証済みSoftPaq絶対path。
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
	// SoftPaqを起動できなければWindows診断値を返す。
	if( CreateProcessW( application.data(), nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr,
					  &startup, &process) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	CloseHandle( process.hThread) ;
	const DWORD waitResult = WaitForSingleObject( process.hProcess, INFINITE) ;	// 終了待機結果。
	NativeError result{} ;														// Process終了状態を反映する結果。
	// process終了待機の失敗を導入成功として扱わない。
	if( waitResult != WAIT_OBJECT_0) {
		result = nativeErrorFromWin32( GetLastError()) ;
	} else {
		DWORD exitCode{} ;	// HP SoftPaq process exit code。
		// process終了codeを取得できなければ導入結果を推測しない。
		if( GetExitCodeProcess( process.hProcess, &exitCode) == FALSE) {
			result = nativeErrorFromWin32( GetLastError()) ;
		}
		// 再起動を要する成功codeを再起動要否へ反映する。
		else if( exitCode == ERROR_SUCCESS_REBOOT_REQUIRED) {
			rebootRequired = true ;
		}
		// 正常終了以外のcodeを導入診断値として返す。
		else if( exitCode != ERROR_SUCCESS) {
			result = nativeErrorFromWin32( exitCode) ;
		}
	}

	CloseHandle( process.hProcess) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのHP SoftPaqを取得・検証・対話導入する。
 *
 * 保護file、HTTPS、size、hash、HP署名を再検証して対話起動する。
 *
 * @param[in] client 公式host限定HTTP client。
 * @param[in] sessionId 現在scan session ID。
 * @param[in] identity UI候補opaque identity。
 * @param[in] url HP公式SoftPaq URL。
 * @param[in] size Reference宣言byte数。
 * @param[in] sha256 Reference宣言SHA-256。
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
	// Scope終了時にpayloadを削除する一時領域。
	OfficialDownloadWorkspace workspace ;
	const NativeError		  workspaceError = workspace.initialize( L"hp", sessionId) ;	// 作成結果。
	// 専用workspaceを確保できなければ取得と導入を失敗として中止する。
	if( workspaceError != 0) {
		result.downloadOutcome = OutcomeCode::FAILURE ;
		result.downloadError   = workspaceError ;
		result.installOutcome  = OutcomeCode::FAILURE ;
		result.installError	   = workspaceError ;
		return result ;
	}

	NativeError downloadError = downloadFile(
		client, url, OFFICIAL_PAYLOAD_RESOURCE_ID, std::min( size, MAXIMUM_INSTALLER_BYTES),
		workspace, L"driver.exe", false,
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
	// 取得成功だけで信用せず、同じsessionの公式payload取得証拠を要求する。
	if( downloadError == 0 &&
	   !client.hasSourceEvidence( sessionId, HP_PROVIDER_ID, OFFICIAL_PAYLOAD_RESOURCE_ID)) {
		downloadError = static_cast<NativeError>( E_UNEXPECTED) ;
	}

	// 取得または取得元証拠の失敗時はpayloadを導入しない。
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
						   HP_PUBLISHERS) ;	// Metadataとpublisher検証結果。
	// 取得済みpayloadの検証失敗をdownload成功と分けて導入結果へ残す。
	if( verificationError != 0) {
		result.installOutcome = OutcomeCode::FAILURE ;
		result.installError	  = verificationError ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::INSTALLING, .percentComplete = 90}) ;
	bool			  installerReboot{} ;											// SoftPaq exit codeが要求した再起動状態。
	const NativeError installError = runInstaller( installer, installerReboot) ;	// 実行結果。
	// SoftPaq導入の失敗を個別結果へ保持する。
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

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/hp_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult HpUpdateProvider::scan( const ScanSessionId						   scanSessionId,
								  const std::span<const OfficialCatalogDevice> devices,
								  const LocalHardwareIdMatcher				  &hardwareIdMatcher,
								  const ProviderProgressCallback			  &progressCallback)
{
	invalidateScanSession() ;
	ScanResult result ;	// HP Provider単独のscan結果。
	result.scanSessionId = scanSessionId ;
	result.state		 = ProviderScanState::FAILURE ;
	result.outcome		 = OutcomeCode::FAILURE ;
	// 有効なsession、端末内matcher、進捗通知先がないscanを拒否する。
	if( scanSessionId == 0 || !hardwareIdMatcher || !progressCallback) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 0}) ;
	HpSystemIdentity system ;												// Localで検証したPlatform IDとWindows build。
	bool			 applicable{} ;											// HP client PCの場合true。
	NativeError		 error = readHpSystemIdentity( system, applicable) ;	// 判定結果。
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	// 対応HP clientでない端末は検索失敗ではなく対象外として完了する。
	if( !applicable) {
		result.succeeded = true ;
		result.state	 = ProviderScanState::NOT_APPLICABLE ;
		result.outcome	 = OutcomeCode::SUCCESS ;
		progressCallback(
			{.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 100}) ;
		return result ;
	}

	result.coverage.eligibleDeviceCount = devices.size() ;

	error = httpClient_.beginSourceSession( scanSessionId, HP_PROVIDER_ID) ;
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	OfficialDownloadWorkspace workspace ;	// 署名付きCABとXMLを保持する保護一時領域。
	error = workspace.initialize( L"hp-scan", scanSessionId) ;
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	error = downloadFile( httpClient_, PLATFORM_LIST_URL, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
						 MAXIMUM_PLATFORM_LIST_CAB_BYTES, workspace, L"platform-list.cab", true,
						 []( const std::uint64_t, const std::uint64_t) {}) ;
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 15}) ;
	const std::wstring platformCab = workspace.path( L"platform-list.cab") ;	// CAB絶対path。
	error						   = verifyAuthenticodePublisher( platformCab, HP_PUBLISHERS) ;
	// catalogの検証失敗を候補なしではなくmetadata拒否として返す。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	const std::wstring platformXmlPath = workspace.path( L"platform-list.xml") ;	// 展開先。
	error =
		extractOfficialCatalogXml( platformCab, platformXmlPath, MAXIMUM_PLATFORM_LIST_XML_BYTES) ;
	// catalogの検証失敗を候補なしではなくmetadata拒否として返す。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	std::wstring platformXml ;	// 厳格UTF-8変換済みplatform list XML。
	error = readOfficialUtf8Xml( platformXmlPath, MAXIMUM_PLATFORM_LIST_XML_BYTES, platformXml) ;
	// catalogの検証失敗を候補なしではなくmetadata拒否として返す。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	HpPlatformReference reference ;	// Platform ID／buildへ一致したreference値。
	error = parseHpPlatformCatalog( platformXml, system.systemId, system.osBuild, reference) ;
	// 端末対応referenceがない場合は対象外として検索を完了する。
	if( error == nativeErrorFromWin32( ERROR_NOT_FOUND)) {
		result.succeeded = true ;
		result.state	 = ProviderScanState::NOT_APPLICABLE ;
		result.outcome	 = OutcomeCode::SUCCESS ;
		progressCallback(
			{.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 100}) ;
		return result ;
	}

	// reference照合の不正を対象外と区別してmetadata拒否として返す。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 35}) ;

	std::wstring lowerSystemId = reference.systemId ;	// URL用小文字Platform ID。
	std::transform(
		lowerSystemId.begin(), lowerSystemId.end(), lowerSystemId.begin(),
		[]( const wchar_t character) { return static_cast<wchar_t>( std::towlower( character)) ; }) ;
	const std::wstring referenceUrl = L"https://hpia.hpcloud.hp.com/ref/" + lowerSystemId + L"/" +
									  lowerSystemId + L"_64_" + reference.osVersion + L"." +
									  reference.releaseId +
									  L".cab" ;	// 検証済みplatform値だけから構築するURL。
	error = downloadFile( httpClient_, referenceUrl, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
						 MAXIMUM_REFERENCE_CAB_BYTES, workspace, L"reference.cab", true,
						 []( const std::uint64_t, const std::uint64_t) {}) ;
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	const std::wstring referenceCab = workspace.path( L"reference.cab") ;	// Reference CAB path。
	error							= verifyAuthenticodePublisher( referenceCab, HP_PUBLISHERS) ;
	// referenceの検証失敗をmetadata拒否として保持する。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 55}) ;
	const std::wstring referenceXmlPath = workspace.path( L"reference.xml") ;	// 展開先XML。
	error = extractOfficialCatalogXml( referenceCab, referenceXmlPath, MAXIMUM_REFERENCE_XML_BYTES) ;
	// referenceの検証失敗をmetadata拒否として保持する。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	std::wstring referenceXml ;	// 厳格UTF-8変換済みHP reference XML。
	error = readOfficialUtf8Xml( referenceXmlPath, MAXIMUM_REFERENCE_XML_BYTES, referenceXml) ;
	// referenceの検証失敗をmetadata拒否として保持する。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	std::vector<HpDriverRelease> releases ;	// Platform／OS／device対応済みdriver SoftPaq群。
	error = parseHpReferenceCatalog( referenceXml, reference, releases) ;
	// referenceの検証失敗をmetadata拒否として保持する。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	std::unordered_map<std::wstring, const OfficialCatalogDevice *>
		deviceMetadata ;	// Opaque device表示metadata索引。
	deviceMetadata.reserve( devices.size()) ;
	// Matcher結果から表示metadataを引けるようopaque identityで索引化する。
	for( const OfficialCatalogDevice &device : devices) {
		deviceMetadata.try_emplace( device.deviceIdentity, &device) ;
	}

	std::size_t						 ordinal{} ;		// Candidate identity用session内連番。
	std::unordered_set<std::wstring> assessedDevices ;	// Catalog IDがlocal一致したdevice集合。
	// 全SoftPaqのcatalog DeviceIdをlocal mapへ完全一致させ、deviceごとに候補化する。
	for( const HpDriverRelease &release : releases) {
		std::unordered_set<std::wstring> matchedDevices ;	// このSoftPaqへ一致したdevice群。
		// catalog側IDだけを端末内matcherへ渡して対応deviceを集める。
		for( const std::wstring &catalogId : release.hardwareIds) {
			const std::optional<std::wstring> matched = hardwareIdMatcher( catalogId) ;	// Local結果。
			// 端末内で解決できたopaque identityだけを重複なく保持する。
			if( matched.has_value()) {
				matchedDevices.insert( matched.value()) ;
			}
		}

		// 照合済みdeviceごとに表示metadataと対応候補を構築する。
		for( const std::wstring &deviceIdentity : matchedDevices) {
			const auto metadata = deviceMetadata.find( deviceIdentity) ;	// 表示metadata検索結果。
			// scan snapshotに表示metadataがないdeviceから候補を作らない。
			if( metadata == deviceMetadata.end()) {
				continue ;
			}

			assessedDevices.insert( deviceIdentity) ;
			const OfficialCatalogDevice &device = *metadata->second ;	// 対応local snapshot。
			UpdateCandidate				 candidate ;					// UIへ渡すHP公式SoftPaq候補。
			candidate.identity =
				L"hp:" + std::to_wstring( scanSessionId) + L":" + std::to_wstring( ordinal++) ;
			candidate.deviceIdentity  = device.deviceIdentity ;
			candidate.providerId	  = std::wstring( HP_PROVIDER_ID) ;
			candidate.packageIdentity = L"hp-softpaq:" + release.softpaqId + L":" + release.sha256 ;
			candidate.title			  = release.title + L" " + release.version ;
			candidate.manufacturer	  = device.manufacturer ;
			candidate.model			  = device.model ;
			candidate.driverClass	  = device.driverClass ;
			candidate.deviceClassGuid = device.deviceClassGuid ;
			candidate.provider		  = release.vendor ;
			candidate.version		  = release.version ;
			candidate.driverDate	  = release.releaseDate ;
			candidate.sourceName	  = L"HP 公式SoftPaqカタログ" ;
			candidate.sourceLocation  = L"HP公式 HTTPS（hpia.hpcloud.hp.com / ftp.hp.com）" ;
			candidate.maximumDownloadBytes = release.size ;
			candidate.action			   = classifyAction( release.version, device.currentVersion) ;
			candidate.discoveryBasis	   = CandidateDiscoveryBasis::OFFICIAL_STRUCTURED_CATALOG ;
			candidate.audit				   = makeOfficialMetadataCandidateAudit() ;
			candidate.current			   = false ;
			candidate.recommended		   = false ;
			candidate.installable		   = false ;
			candidate.eulaAccepted		   = false ;
			candidate.allContentCached	   = false ;
			candidate.rebootMayBeRequired  = true ;
			candidate.browseOnly		   = !release.recommended ;

			InstallTarget target ;	// Install時に再検証するSoftPaq metadata。
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
	}

	std::unordered_map<std::wstring, std::size_t> recommendations ;	// Device別推奨候補index。
	// HPがCritical／Recommendedとし現在版より新しい候補からdevice別最高versionを選ぶ。
	for( std::size_t index = 0; index < result.candidates.size(); ++index) {
		const UpdateCandidate &candidate = result.candidates[index] ;	// 現在検査中候補。
		// 導入可能な通常更新だけを推奨の比較対象にする。
		if( !candidate.installable || candidate.action != DriverAction::UPDATE ||
		   candidate.browseOnly) {
			continue ;
		}

		const auto current = recommendations.find( candidate.deviceIdentity) ;	// 現在推奨候補。
		// deviceの最初の適格候補を推奨比較の基準として登録する。
		if( current == recommendations.end()) {
			recommendations.emplace( candidate.deviceIdentity, index) ;
			continue ;
		}

		const std::optional<int> comparison =
			compareVersions( candidate.version,
							result.candidates[current->second].version) ;	// Version比較結果。
		// 数値比較で新版と確認できた候補だけに推奨を更新する。
		if( comparison.has_value() && comparison.value() > 0) {
			current->second = index ;
		}
	}

	// Deviceごとに一つだけ初期選択可能な推奨更新flagを設定する。
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
	result.state	 = result.candidates.empty() ? ProviderScanState::NO_CANDIDATES
												 : ProviderScanState::CANDIDATES_AVAILABLE ;
	result.outcome	 = OutcomeCode::SUCCESS ;
	result.coverage.assessedDeviceCount = assessedDevices.size() ;
	// 一次metadataの公式取得証拠が失われていれば候補とsessionを破棄する。
	if( !httpClient_.hasSourceEvidence( scanSessionId, HP_PROVIDER_ID,
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
 * @see src/platform/hp_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult HpUpdateProvider::install( const ScanSessionId					scanSessionId,
										const std::span<const std::wstring> identities,
										const std::uintptr_t				parentWindowNative,
										const ProviderProgressCallback	   &progressCallback)
{
	static_cast<void>( parentWindowNative) ;
	InstallResult result ;	// HP選択全体の実行結果。
	// session、選択、通知先、取得元証拠が揃わない導入要求を全件拒否する。
	if( scanSessionId == 0 || scanSessionId != scanSessionId_ || identities.empty() ||
	   !progressCallback ||
	   !httpClient_.hasSourceEvidence( scanSessionId, HP_PROVIDER_ID,
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
		// 未知候補、重複候補、一deviceへの複数指定を導入前に拒否する。
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
	// 検証済みpackage identityで選択をまとめられなければ全件拒否する。
	if( !packageGroups.has_value()) {
		invalidateScanSession() ;
		result.downloadOutcome = OutcomeCode::FAILURE ;
		result.downloadError   = static_cast<NativeError>( E_INVALIDARG) ;
		result.installOutcome  = OutcomeCode::FAILURE ;
		result.installError	   = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	std::size_t downloaded{} ;	// Downloadが成功した候補数。
	std::size_t installed{} ;	// Installまで成功した候補数。
	std::unordered_map<std::wstring, UpdateExecutionResult>
		executionResults ;	// Candidate identity別に複製したpayload実行結果。
	executionResults.reserve( identities.size()) ;
	// 初出package順に公式SoftPaqを一度だけ取得・検証・対話実行する。
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
		// 一つのprocess結果を、このSoftPaqを選択した各device候補へ関連付ける。
		for( const std::wstring &identity : package) {
			UpdateExecutionResult update = packageResult ;	// Candidate別結果copy。
			update.identity				 = identity ;
			// download成功だけを取得成功件数へ集計する。
			if( update.downloadOutcome == OutcomeCode::SUCCESS) {
				++downloaded ;
			}

			// 導入成功件数と成功候補の再起動要否を集約する。
			if( update.installOutcome == OutcomeCode::SUCCESS) {
				++installed ;
				result.rebootRequired = result.rebootRequired || update.rebootRequired ;
			} else {
				// 最初のdownload失敗を後続候補の診断値で上書きしない。
				if( result.downloadError == 0 && update.downloadError != 0) {
					result.downloadError = update.downloadError ;
				}

				// 最初のinstall失敗を後続候補の診断値で上書きしない。
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
 * @see src/platform/hp_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void HpUpdateProvider::invalidateScanSession() noexcept
{
	httpClient_.invalidateSourceSession() ;
	installTargets_.clear() ;
	scanSessionId_ = 0 ;
}

} // namespace drivercrate
