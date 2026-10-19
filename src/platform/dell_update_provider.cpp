//------------------------------------------------------------------------------
/**
 * @file dell_update_provider.cpp
 * @brief Dell公式driver Provider実装。
 * @version 01.00.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Package単位実行統合。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Metadata拒否状態追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  共通file検証へ移行。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Catalog cache適用。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Local coverage集計追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  共通CAB検証へ移行。
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
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note Dell PCだけを対象に署名済み公式catalogを取得し、端末情報を送信せずlocal照合します。DUPはsize、SHA-256、Dell署名を再検証して対話実行します。
 */
//------------------------------------------------------------------------------

#include "platform/dell_update_provider.h"

#include "core/candidate_audit.h"
#include "core/official_source_policy.h"
#include "core/package_selection.h"
#include "core/provider_registry.h"
#include "platform/dell_catalog_parser.h"
#include "platform/official_catalog_validation.h"
#include "platform/official_file_verifier.h"

#include <Windows.h>
#include <sddl.h>

#include <algorithm>
#include <array>
#include <cstddef>
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

constexpr std::wstring_view CATALOG_INDEX_URL =
	L"https://downloads.dell.com/catalog/CatalogIndexPC.cab" ;	// Dell PC index URL。
constexpr std::array<std::wstring_view, 2> DELL_PUBLISHERS{
	L"Dell Technologies Inc.", L"Dell Inc."} ;									// 許可するAuthenticode publisher完全一致値。
constexpr std::uint64_t MAXIMUM_INDEX_CAB_BYTES = 8ULL * 1024ULL * 1024ULL ;	// Index CAB上限。
constexpr std::uint64_t MAXIMUM_PLATFORM_CAB_BYTES =
	32ULL * 1024ULL * 1024ULL ;															// Platform CAB上限。
constexpr std::uint64_t		MAXIMUM_EXPANDED_XML_BYTES = 64ULL * 1024ULL * 1024ULL ;	// XML上限。
constexpr std::wstring_view WORKSPACE_DACL =
	L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)" ;	// SYSTEM/Administrators限定DACL。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief Local registryから得る非機密なDell system識別値である。
 */
struct DellSystemIdentity {
	/// SMBIOS由来system manufacturer。
	std::wstring manufacturer ;
	/// SMBIOS由来system product name。
	std::wstring model ;
	/// CurrentBuildNumberがWindows 11範囲ならtrue。
	bool		 windows11{} ;
} ;

/**
 * @brief Win32 errorをProvider共通HRESULT bit patternへ変換する。
 * Win32 errorをHRESULT bit patternへ変換する。
 * Win32失敗理由をProvider共通表現へ変換する。
 * @param[in] error GetLastErrorまたはWin32 API error code。
 * @return NativeErrorで保持できるHRESULT bit pattern。
 */
[[nodiscard]] NativeError nativeErrorFromWin32( DWORD error) noexcept ;

/**
 * @brief 保護directoryと既知の一時fileだけをscope終了時に削除するRAII objectである。
 */
class TemporaryWorkspace  final {
public:
	 /**
     * @brief 空のworkspaceを作成する。
     */
	 TemporaryWorkspace() = default ;

	 //------------------------------------------------------------------------------
	 /**
     * @brief 保持する既知fileとdirectoryをbest-effortで削除する。
     *
     * 自身が作成した固定名file以外を列挙、再帰削除しない。
     */
	 //------------------------------------------------------------------------------
	 ~TemporaryWorkspace()
	 {
		 // 作成可能な固定名だけを削除し、予期しないfilesystem entryへ触れない。
		 for( const std::wstring_view name :
			 {L"index.cab", L"index.xml", L"platform.cab", L"platform.xml", L"driver.exe"}) {
			 const std::wstring file = path( name) ;	// 削除対象の既知file絶対path。
			 // 保持中の既知file pathだけを終了時のcleanup対象にする。
			 if( !file.empty()) {
				 DeleteFileW( file.c_str()) ;
			 }
		 }

		 // 作成済みdirectoryがある場合にだけその空directoryを削除する。
		 if( !directory_.empty()) {
			 RemoveDirectoryW( directory_.c_str()) ;
		 }
	 }

	 // Handle/path ownershipとdirectoryを単独管理するためcopy/moveを禁止する。
	 /**
	  * @brief 一時directoryと既知fileの削除責務の二重管理を防ぐため、コピー構築を禁止する。
	  */
	 TemporaryWorkspace( const TemporaryWorkspace &) = delete ;
	 /**
	  * @brief 一時directoryと既知fileの削除責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	  */
	 TemporaryWorkspace &operator=( const TemporaryWorkspace &) = delete ;
	 /**
	  * @brief 一時directoryと既知fileの削除責務を元のworkspace ownerに留めるため、移動構築を禁止する。
	  */
	 TemporaryWorkspace( TemporaryWorkspace &&) = delete ;
	 /**
	  * @brief 元のworkspace ownerへの結合を保つため、移動代入による管理状態の置換を禁止する。
	  */
	 TemporaryWorkspace		  &operator=( TemporaryWorkspace &&) = delete ;

	 //------------------------------------------------------------------------------
	 /**
     * @brief Windows Temp配下へ保護workspaceを作成する。
     *
     * SYSTEMとAdministratorsだけが利用できるdirectoryを32回以内のCREATE_NEW相当試行で作成する。
     *
     * @param[in] sessionId 衝突回避名へ含めるscan session ID。
     * @return 作成成功時は0、全試行失敗時はHRESULT bit pattern。
     */
	 //------------------------------------------------------------------------------
	 [[nodiscard]] NativeError initialize( const ScanSessionId sessionId)
	 {
		 std::array<wchar_t, MAX_PATH> windowsDirectory{} ;	// Windows directory受信buffer。
		 const UINT					   characters =			// 終端nullを除くWindows directory文字数。
			 GetWindowsDirectoryW( windowsDirectory.data(),
								  static_cast<UINT>( windowsDirectory.size())) ;
		 // Windows directoryの取得に失敗またはbuffer不足ならworkspaceを作らない。
		 if( characters == 0 || characters >= windowsDirectory.size()) {
			 return nativeErrorFromWin32( GetLastError()) ;
		 }

		 PSECURITY_DESCRIPTOR descriptor{} ;	// LocalFreeで解放するsecurity descriptor。
		 // 保護DACLを構築できなければ緩い権限でworkspaceを作らない。
		 if( ConvertStringSecurityDescriptorToSecurityDescriptorW(
				WORKSPACE_DACL.data(), SDDL_REVISION_1, &descriptor, nullptr) == FALSE) {
			 return nativeErrorFromWin32( GetLastError()) ;
		 }

		 SECURITY_ATTRIBUTES attributes{} ;	// CreateDirectoryへ渡す保護DACL。
		 attributes.nLength				 = sizeof( attributes) ;
		 attributes.lpSecurityDescriptor = descriptor ;
		 attributes.bInheritHandle		 = FALSE ;

		 NativeError		result = nativeErrorFromWin32( ERROR_FILE_EXISTS) ;	// 最終作成結果。
		 const std::wstring root   =											// 管理者権限processが利用するWindows Temp path。
			 std::wstring( windowsDirectory.data(), characters) + L"\\Temp" ;
		 // PID、session、試行番号を組み合わせ、既存directoryを再利用しない。
		 for( std::uint32_t attempt = 0; attempt < 32; ++attempt) {
			 const std::wstring candidate =	// 今回CREATE_NEWするdirectory絶対path。
				 root + L"\\DriverCrate-dell-" + std::to_wstring( GetCurrentProcessId()) + L"-" +
				 std::to_wstring( sessionId) + L"-" + std::to_wstring( attempt) ;
			 // 保護directoryを新規作成できた名前だけを所有領域として確定する。
			 if( CreateDirectoryW( candidate.c_str(), &attributes) != FALSE) {
				 directory_ = candidate ;
				 result		= 0 ;
				 break ;
			 }

			 const DWORD error = GetLastError() ;	// CreateDirectory失敗理由。
			 // 名前競合以外の作成失敗では再試行せず原因を保持する。
			 if( error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) {
				 result = nativeErrorFromWin32( error) ;
				 break ;
			 }
		 }

		 LocalFree( descriptor) ;
		 return result ;
	 }

	 //------------------------------------------------------------------------------
	 /**
     * @brief 固定名一時fileをCREATE_NEWで開く。
     *
     * Workspace外path、separator、既存fileを受理しない。
     *
     * @param[in] name Providerが定義した固定basename。
     * @param[out] handle 成功時のread/write所有handle。
     * @return 作成成功時は0、失敗時はHRESULT bit pattern。
     */
	 //------------------------------------------------------------------------------
	 [[nodiscard]] NativeError createFile( const std::wstring_view name, HANDLE &handle) const
	 {
		 handle = INVALID_HANDLE_VALUE ;
		 // 未初期化領域と空・区切り付きfile名をCREATE_NEWへ渡さない。
		 if( directory_.empty() || name.empty() || name.find( L'\\') != std::wstring_view::npos ||
			name.find( L'/') != std::wstring_view::npos) {
			 return static_cast<NativeError>( E_INVALIDARG) ;
		 }

		 const std::wstring file = path( name) ;	// CREATE_NEW対象絶対path。
		 handle =
			 CreateFileW( file.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr,
						 CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN, nullptr) ;
		 return handle == INVALID_HANDLE_VALUE ? nativeErrorFromWin32( GetLastError()) : 0 ;
	 }

	 //------------------------------------------------------------------------------
	 /**
     * @brief Workspace内固定名の絶対pathを返す。
     *
     * 呼出し側はProvider定義済みbasenameだけを渡す。
     *
     * @param[in] name Separatorを含まない固定basename。
     * @return Workspace未作成時は空、それ以外は絶対path。
     */
	 //------------------------------------------------------------------------------
	 [[nodiscard]] std::wstring path( const std::wstring_view name) const
	 {
		 return directory_.empty() ? std::wstring{} : directory_ + L"\\" + std::wstring( name) ;
	 }

private:
	 /// Destructorで削除する保護directory絶対path。
	 std::wstring directory_ ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @see src/platform/dell_update_provider.cpp 宣言側の契約を正本とする。
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
 * @param[in] value Registry、catalog、certificateの表示名。
 * @return 区切りを除いて大文字化した完全一致key。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizeName( const std::wstring_view value)
{
	std::wstring normalized ;	// 比較に必要な英数字だけを保持するkey。
	normalized.reserve( value.size()) ;
	// Unicode英数字を順序通り保持し、大小文字差を除去する。
	for( const wchar_t character : value) {
		// 英数字だけを大文字比較keyへ含めてlocal表示名を照合する。
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
	const std::wstring subkeyString( subkey) ;			// RegGetValue用終端null付きsubkey。
	const std::wstring valueNameString( valueName) ;	// RegGetValue用終端null付きvalue名。
	DWORD			   bytes{} ;						// REG_SZ取得に必要な終端null込みbyte数。
	LSTATUS			   status = RegGetValueW( root, subkeyString.c_str(), valueNameString.c_str(),
											 RRF_RT_REG_SZ, nullptr, nullptr, &bytes) ;	// Size取得結果。
	// registry長さ照会の失敗を診断値として返す。
	if( status != ERROR_SUCCESS) {
		return nativeErrorFromWin32( static_cast<DWORD>( status)) ;
	}

	// 空のUTF-16表現、奇数byte、容量上限超過のregistry値を拒否する。
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

	// 取得buffer末尾の終端NULだけを取り除き、途中NULは後段で拒否する。
	while( !buffer.empty() && buffer.back() == L'\0') {
		buffer.pop_back() ;
	}

	// 空または途中NULのあるregistry表示値を識別に使用しない。
	if( buffer.empty() || buffer.find( L'\0') != std::wstring::npos) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	value = std::move( buffer) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Local systemが対応Dell PCかを判定する。
 *
 * Dell以外はmodelやcatalogを読まず正常な対象外として返す。
 *
 * @param[out] identity Dell時のmanufacturer、model、Windows世代。
 * @param[out] dellSystem ManufacturerがDellを示す場合true。
 * @return 判定成功時は0、registry値不正時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readDellSystemIdentity( DellSystemIdentity &identity, bool &dellSystem)
{
	identity   = {} ;
	dellSystem = false ;
	// Dell system makerとmodelを読取り専用で照合するregistry key。
	constexpr std::wstring_view BIOS_KEY = L"HARDWARE\\DESCRIPTION\\System\\BIOS" ;
	// SystemManufacturerの読取りからsystem照合へ引き継ぐ診断値。
	NativeError error = readRegistryString( HKEY_LOCAL_MACHINE, BIOS_KEY, L"SystemManufacturer",
										   identity.manufacturer) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	const std::wstring manufacturerKey = normalizeName( identity.manufacturer) ;	// Maker比較key。
	// 審査済みDellメーカー表記に一致しないsystemを対象外にする。
	if( manufacturerKey != L"DELLINC" && manufacturerKey != L"DELLCOMPUTERCORPORATION" &&
	   manufacturerKey != L"DELLTECHNOLOGIES") {
		return 0 ;
	}

	dellSystem = true ;
	error = readRegistryString( HKEY_LOCAL_MACHINE, BIOS_KEY, L"SystemProductName", identity.model) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	std::wstring buildText ;	// Windows CurrentBuildNumberの10進文字列。
	error =
		readRegistryString( HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
						   L"CurrentBuildNumber", buildText) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	std::uint64_t build{} ;	// Overflow検証済みWindows build number。
	// Windows build文字列をASCII 10進値として厳密に変換する。
	for( const wchar_t character : buildText) {
		// Windows buildのASCII数字以外を不正dataとして拒否する。
		if( character < L'0' || character > L'9') {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const std::uint64_t digit = static_cast<std::uint64_t>( character - L'0') ;	// 現在桁。
		// Windows buildの桁追加でuint64上限を超える前に拒否する。
		if( build > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
			return nativeErrorFromWin32( ERROR_ARITHMETIC_OVERFLOW) ;
		}

		build = build * 10 + digit ;
	}

	// Windows 10の最低buildより古いOSに公式Client要求を作らない。
	if( build < 10240) {
		return nativeErrorFromWin32( ERROR_OLD_WIN_VERSION) ;
	}

	identity.windows11 = build >= 22000 ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名済みCABから単一XMLを展開する。
 *
 * Multi-cab、複数XML、path付きentryをfail-closedで拒否する。
 *
 * @param[in] cabPath 署名検証済みCAB絶対path。
 * @param[in] outputPath Workspace内の未作成XML絶対path。
 * @return 一つのXMLを展開できた場合は0、それ以外はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError extractCatalogXml( const std::wstring_view cabPath,
											const std::wstring_view outputPath)
{
	return extractOfficialCatalogXml( cabPath, outputPath, MAXIMUM_EXPANDED_XML_BYTES) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 展開済みUTF-16 XMLを上限付きで読み取る。
 *
 * 64 MiB以下、偶数byte、UTF-16LE BOMまたは`<`開始を必須にする。
 *
 * @param[in] path Workspace内XML絶対path。
 * @param[out] xml 成功時のBOMを除くUTF-16文字列。
 * @return 成功時は0、size/encoding/read失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readUtf16Xml( const std::wstring_view path, std::wstring &xml)
{
	return readOfficialUtf16Xml( path, MAXIMUM_EXPANDED_XML_BYTES, xml) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式URLを保護一時fileへ取得する。
 *
 * CREATE_NEW fileだけへ書込み、redirectとhost変更はclientが拒否する。DUP payloadはcacheせずcatalogだけを再利用する。
 *
 * @param[in] client 公式host allowlist付きHTTP client。
 * @param[in] url downloads.dell.comのHTTPS URL。
 * @param[in] maximumBytes Catalogまたは固定上限byte数。
 * @param[in] workspace 保存先保護workspace。
 * @param[in] name 保存する固定basename。
 * @param[in] catalog trueの場合はcatalog cacheを使用する。
 * @param[in] progressCallback 受信byte進捗通知先。
 * @return Downloadとhandle close成功時は0、失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError downloadFile( OfficialHttpClient &client, const std::wstring_view url,
									   const std::uint64_t		 maximumBytes,
									   const TemporaryWorkspace &workspace,
									   const std::wstring_view name, const bool catalog,
									   const HttpDownloadProgressCallback &progressCallback)
{
	HANDLE			  file{INVALID_HANDLE_VALUE} ;						// CloseHandleで解放するdownload先file。
	const NativeError createError = workspace.createFile( name, file) ;	// CREATE_NEW結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( createError != 0) {
		return createError ;
	}

	const NativeError downloadError =	// Catalogだけ永続cacheを使用する取得結果。
		catalog ? client.downloadCatalogForSource( url, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
												  maximumBytes, file, progressCallback)
				: client.downloadForSource( url, OFFICIAL_PAYLOAD_RESOURCE_ID, maximumBytes, file,
										   progressCallback) ;
	const BOOL closeResult = CloseHandle( file) ;	// Download先fileのclose結果。
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
 * @param[in] value WindowsまたはDell vendor version。
 * @return 1～8 componentの数値群。形式不正時は<tt>std::nullopt</tt>。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::vector<std::uint64_t>> parseVersion( const std::wstring_view value)
{
	// 空または過長のversionを数値比較へ渡さない。
	if( value.empty() || value.size() > 128) {
		return std::nullopt ;
	}

	std::vector<std::uint64_t> parts ;		// Dot区切りで変換したversion component群。
	std::uint64_t			   part{} ;		// 現在componentの数値。
	bool					   hasDigit{} ;	// 現在componentに一桁以上あればtrue。
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
		// version componentの桁追加でuint64上限を超える前に拒否する。
		if( part > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
			return std::nullopt ;
		}

		part	 = part * 10 + digit ;
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
		// 比較する左版数の現在成分。省略された末尾成分は0として扱う。
		const std::uint64_t leftPart = index < leftParts->size() ? (*leftParts)[index] : 0 ;
		// 比較する右版数の現在成分。省略された末尾成分は0として扱う。
		const std::uint64_t rightPart = index < rightParts->size() ? (*rightParts)[index] : 0 ;
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
 * 数値比較不能な異種表記は安全側でReinstallとし自動選択しない。
 *
 * @param[in] candidate Dell vendorVersion。
 * @param[in] current SetupAPIが返した現在version。
 * @return Update、Reinstall、Downgradeのいずれか。
 */
//------------------------------------------------------------------------------
[[nodiscard]] DriverAction classifyAction( const std::wstring_view candidate,
										  const std::wstring_view current)
{
	const std::optional<int> comparison = compareVersions( candidate, current) ;	// 数値比較結果。
	// 比較不能なversionを通常更新へ昇格せず明示再導入へ分類する。
	if( !comparison.has_value()) {
		return DriverAction::REINSTALL ;
	}

	// 候補版が現在版より大きいと確定した場合だけ更新へ分類する。
	if( comparison.value() > 0) {
		return DriverAction::UPDATE ;
	}

	// 候補版が現在版より小さいと確定した場合だけ旧版へ分類する。
	if( comparison.value() < 0) {
		return DriverAction::DOWNGRADE ;
	}

	return DriverAction::REINSTALL ;
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
	// DUPの終了待ちが正常完了しない場合は待機失敗を保持する。
	if( waitResult != WAIT_OBJECT_0) {
		result = nativeErrorFromWin32( GetLastError()) ;
	} else {
		DWORD exitCode{} ;	// Dell DUP process exit code。
		// 終了codeを取得できないDUPを導入成功としない。
		if( GetExitCodeProcess( process.hProcess, &exitCode) == FALSE) {
			result = nativeErrorFromWin32( GetLastError()) ;
		}
		// DUPの非ゼロ終了codeを導入診断として保持する。
		else if( exitCode != 0) {
			result = nativeErrorFromWin32( exitCode) ;
		}
	}

	CloseHandle( process.hProcess) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのDell候補を取得・検証・対話導入する。
 *
 * 保護一時file、HTTPS、size、hash、Dell署名を再検証してから対話起動する。
 *
 * @param[in] client 公式host限定HTTP client。
 * @param[in] sessionId 現在scan session ID。
 * @param[in] identity UI候補opaque identity。
 * @param[in] releaseId Dell英数字release ID。
 * @param[in] url Dell公式DUP URL。
 * @param[in] size Catalog宣言byte数。
 * @param[in] sha256 Catalog宣言SHA-256。
 * @param[in] progressCallback Download/install進捗通知先。
 * @return 個別download/install結果。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UpdateExecutionResult installTarget(
	OfficialHttpClient &client, const ScanSessionId sessionId, const std::wstring_view identity,
	const std::wstring_view releaseId, const std::wstring_view url, const std::uint64_t size,
	const std::wstring_view sha256, const ProviderProgressCallback &progressCallback)
{
	UpdateExecutionResult result ;	// UI候補と対応する個別実行結果。
	result.identity = identity ;
	TemporaryWorkspace workspace ;											// Scope終了時にDUPを削除する保護workspace。
	const NativeError  workspaceError = workspace.initialize( sessionId) ;	// 作成結果。
	// 保護workspaceの準備失敗時は取得も導入も開始しない。
	if( workspaceError != 0) {
		result.downloadOutcome = OutcomeCode::FAILURE ;
		result.downloadError   = workspaceError ;
		result.installOutcome  = OutcomeCode::FAILURE ;
		result.installError	   = workspaceError ;
		return result ;
	}

	static_cast<void>( releaseId) ;
	NativeError downloadError = downloadFile(
		client, url, size, workspace, L"driver.exe", false,
		[&progressCallback]( const std::uint64_t received, const std::uint64_t total) {
			const std::uint32_t percent =	// Downloadを個別operation 0～80%へ変換する値。
				total == 0 ? 0
						   : static_cast<std::uint32_t>( std::min<std::uint64_t>(
								 80, received > total ? 80 : received * 80 / total)) ;
			progressCallback( {.stage		   = ProviderStage::DOWNLOADING,
							  .percentComplete = percent,
							  .completedItems  = received,
							  .totalItems	   = total}) ;
		}) ;
	// 転送成功でも現在sessionの公式payload取得根拠がなければ拒否する。
	if( downloadError == 0 &&
	   !client.hasSourceEvidence( sessionId, DELL_PROVIDER_ID, OFFICIAL_PAYLOAD_RESOURCE_ID)) {
		downloadError = static_cast<NativeError>( E_UNEXPECTED) ;
	}

	// DUP取得に失敗した場合は導入を呼ばず同じ原因を個別結果へ残す。
	if( downloadError != 0) {
		result.downloadOutcome = OutcomeCode::FAILURE ;
		result.downloadError   = downloadError ;
		result.installOutcome  = OutcomeCode::FAILURE ;
		result.installError	   = downloadError ;
		return result ;
	}

	result.downloadOutcome = OutcomeCode::SUCCESS ;
	progressCallback( {.stage = ProviderStage::DOWNLOADING, .percentComplete = 85}) ;
	const std::wstring installer		 = workspace.path( L"driver.exe") ;	// 検証・起動対象path。
	const NativeError  verificationError =									// 共通metadata chainとpublisher検証結果。
		verifyOfficialFile( installer, {.expectedSize = size, .expectedSha256 = sha256},
						   DELL_PUBLISHERS) ;
	// file検証失敗は取得成功と区別して導入失敗として返す。
	if( verificationError != 0) {
		result.installOutcome = OutcomeCode::FAILURE ;
		result.installError	  = verificationError ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::INSTALLING, .percentComplete = 90}) ;
	const NativeError installError = runInstaller( installer) ;	// 対話DUP実行結果。
	// 対話導入失敗は取得成功を維持したままinstall診断へ反映する。
	if( installError != 0) {
		result.installOutcome = OutcomeCode::FAILURE ;
		result.installError	  = installError ;
		return result ;
	}

	result.installOutcome = OutcomeCode::SUCCESS ;
	result.rebootRequired = true ;
	progressCallback( {.stage		   = ProviderStage::INSTALLING,
					  .percentComplete = 100,
					  .completedItems  = 1,
					  .totalItems	   = 1}) ;
	return result ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/dell_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult DellUpdateProvider::scan( const ScanSessionId							 scanSessionId,
									const std::span<const OfficialCatalogDevice> devices,
									const LocalHardwareIdMatcher				&hardwareIdMatcher,
									const ProviderProgressCallback				&progressCallback)
{
	invalidateScanSession() ;
	ScanResult result ;	// Dell公式catalogのscan結果。
	result.scanSessionId = scanSessionId ;
	result.outcome		 = OutcomeCode::FAILURE ;
	// 未発行sessionと端末内matcher欠落を通信前に拒否する。
	if( scanSessionId == 0 || !hardwareIdMatcher) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 0}) ;
	DellSystemIdentity system ;													// Local registry由来の非機密system識別値。
	bool			   dellSystem{} ;											// 対応Dell manufacturerならtrue。
	NativeError		   error = readDellSystemIdentity( system, dellSystem) ;	// 判定結果。
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	// 非Dell systemは外部通信を行わず対象外として完了する。
	if( !dellSystem) {
		// 非Dell端末は外部通信を行わず、候補0件の正常scanとして完了する。
		result.succeeded = true ;
		result.outcome	 = OutcomeCode::SUCCESS ;
		result.state	 = ProviderScanState::NOT_APPLICABLE ;
		scanSessionId_	 = scanSessionId ;
		progressCallback(
			{.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 100}) ;
		return result ;
	}

	result.coverage.eligibleDeviceCount = devices.size() ;

	error = httpClient_.beginSourceSession( scanSessionId, DELL_PROVIDER_ID) ;
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	TemporaryWorkspace workspace ;	// Catalog一式をscope終了時に削除する保護workspace。
	error = workspace.initialize( scanSessionId) ;
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	error = downloadFile( httpClient_, CATALOG_INDEX_URL, MAXIMUM_INDEX_CAB_BYTES, workspace,
						 L"index.cab", true, []( const std::uint64_t, const std::uint64_t) {}) ;
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 15}) ;
	const std::wstring indexCab = workspace.path( L"index.cab") ;	// Index CAB絶対path。
	error						= verifyAuthenticodePublisher( indexCab, DELL_PUBLISHERS) ;
	// index署名検証に失敗した場合はmetadata拒否として後続解析を止める。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	const std::wstring indexXmlPath = workspace.path( L"index.xml") ;	// 展開先XML path。
	error							= extractCatalogXml( indexCab, indexXmlPath) ;
	// index展開に失敗した場合はmetadata拒否として部分内容を使用しない。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	std::wstring indexXml ;	// 上限・encoding検証済みindex XML。
	error = readUtf16Xml( indexXmlPath, indexXml) ;
	// index XML読込みに失敗した場合はmetadata拒否として返す。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	DellPlatformCatalogReference reference ;	// Model完全一致のplatform CAB参照。
	error = parseDellCatalogIndex( indexXml, system.model, reference) ;
	// 対象catalog参照を検証できなければmetadata拒否として返す。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	// platform CABの公表容量が取得上限を超える場合は取得しない。
	if( reference.size > MAXIMUM_PLATFORM_CAB_BYTES) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 35}) ;
	const std::wstring platformUrl =	// 固定Dell HTTPS originと検証済み相対path。
		L"https://downloads.dell.com/" + reference.path ;
	error = downloadFile( httpClient_, platformUrl, reference.size, workspace, L"platform.cab", true,
						 []( const std::uint64_t, const std::uint64_t) {}) ;
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	const std::wstring platformCab = workspace.path( L"platform.cab") ;	// Platform CAB path。

	error = verifyOfficialFile( platformCab,
							   {.expectedSize = reference.size, .expectedSha256 = reference.sha256},
							   DELL_PUBLISHERS) ;
	// platform CABのfile検証に失敗した場合はmetadata拒否として返す。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	progressCallback( {.stage = ProviderStage::SEARCHING_OFFICIAL_CATALOGS, .percentComplete = 55}) ;
	const std::wstring platformXmlPath = workspace.path( L"platform.xml") ;	// 展開先XML path。

	error = extractCatalogXml( platformCab, platformXmlPath) ;
	// platform CAB展開に失敗した場合はmetadata拒否として返す。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	std::wstring platformXml ;	// 上限・encoding検証済みplatform XML。
	error = readUtf16Xml( platformXmlPath, platformXml) ;
	// platform XML読込みに失敗した場合はmetadata拒否として返す。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	std::vector<DellDriverRelease> releases ;	// Model/OS/x64検証済みdriver release群。
	error = parseDellPlatformCatalog( platformXml, system.model, system.windows11, releases) ;
	// platform release解析に失敗した場合は部分候補を生成しない。
	if( error != 0) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = error ;
		return result ;
	}

	std::unordered_map<std::wstring, const OfficialCatalogDevice *>
		deviceMetadata ;	// Opaque device索引。
	deviceMetadata.reserve( devices.size()) ;
	// UI metadataをHardware ID照合結果から引けるようopaque identityで索引化する。
	for( const OfficialCatalogDevice &device : devices) {
		deviceMetadata.try_emplace( device.deviceIdentity, &device) ;
	}

	std::size_t						 ordinal{} ;		// Dell candidate identity用session内連番。
	std::unordered_set<std::wstring> assessedDevices ;	// Catalog IDがlocal一致したdevice集合。
	// 全releaseのcatalog IDをlocal mapへ完全一致させ、対応deviceごとに候補化する。
	for( const DellDriverRelease &release : releases) {
		std::unordered_set<std::wstring> matchedDevices ;	// このDUPへ一致したopaque device群。
		// catalog側の有限なID群だけを端末内matcherへ渡して対象deviceを解決する。
		for( const std::wstring &catalogId : release.hardwareIds) {
			const std::optional<std::wstring> matched = hardwareIdMatcher( catalogId) ;	// Local結果。
			// 端末内で解決できたopaque device identityだけを対象集合へ加える。
			if( matched.has_value()) {
				matchedDevices.insert( matched.value()) ;
			}
		}

		// 重複を除いたdeviceごとに保持metadataを照合して表示候補を作る。
		for( const std::wstring &deviceIdentity : matchedDevices) {
			const auto metadata = deviceMetadata.find( deviceIdentity) ;	// 表示metadata検索結果。
			// 現在device snapshotに存在しない照合結果は候補化しない。
			if( metadata == deviceMetadata.end()) {
				continue ;
			}

			assessedDevices.insert( deviceIdentity) ;
			const OfficialCatalogDevice &device = *metadata->second ;	// 対応local snapshot。
			UpdateCandidate				 candidate ;					// UIへ渡すDell公式release候補。
			candidate.identity =
				L"dell:" + std::to_wstring( scanSessionId) + L":" + std::to_wstring( ordinal++) ;
			candidate.deviceIdentity  = device.deviceIdentity ;
			candidate.providerId	  = std::wstring( DELL_PROVIDER_ID) ;
			candidate.packageIdentity = L"dell-dup:" + release.releaseId + L":" + release.sha256 ;
			candidate.title =
				release.title + L" " + release.version + L" (" + release.dellVersion + L")" ;
			candidate.manufacturer		   = device.manufacturer ;
			candidate.model				   = device.model ;
			candidate.driverClass		   = device.driverClass ;
			candidate.deviceClassGuid	   = device.deviceClassGuid ;
			candidate.provider			   = L"Dell Technologies Inc." ;
			candidate.version			   = release.version ;
			candidate.driverDate		   = release.releaseDate ;
			candidate.sourceName		   = L"Dell 公式ドライバーカタログ" ;
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
			candidate.rebootMayBeRequired  = true ;
			candidate.browseOnly		   = !release.recommended ;

			InstallTarget target ;	// Install時に再検証するDUP metadata。
			target.packageIdentity = candidate.packageIdentity ;
			target.releaseId	   = release.releaseId ;
			target.downloadUrl	   = L"https://downloads.dell.com/" + release.path ;
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

	std::unordered_map<std::wstring, std::size_t> recommendations ;	// Device別の最新推奨候補index。
	// DellがRecommended/Urgentとし現在版より新しい候補からdevice別最高versionを選ぶ。
	for( std::size_t index = 0; index < result.candidates.size(); ++index) {
		const UpdateCandidate &candidate = result.candidates[index] ;	// 現在検査中候補。
		// install可能な通常更新だけを推奨候補の選定に使用する。
		if( !candidate.installable || candidate.action != DriverAction::UPDATE ||
		   candidate.browseOnly) {
			continue ;
		}

		const auto current = recommendations.find( candidate.deviceIdentity) ;	// 現在の推奨候補。
		// 当該deviceの最初の通常更新を推奨比較の基準として保持する。
		if( current == recommendations.end()) {
			recommendations.emplace( candidate.deviceIdentity, index) ;
			continue ;
		}

		const std::optional<int> comparison =	// 新候補と現在推奨のversion比較結果。
			compareVersions( candidate.version, result.candidates[current->second].version) ;
		// 比較可能でより大きい版だけをdeviceの新しい推奨候補にする。
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
	result.succeeded					= true ;
	result.outcome						= OutcomeCode::SUCCESS ;
	result.coverage.assessedDeviceCount = assessedDevices.size() ;
	// 公式catalog取得根拠がなければsessionを失効させて候補を全て破棄する。
	if( !httpClient_.hasSourceEvidence( scanSessionId, DELL_PROVIDER_ID,
									  OFFICIAL_PRIMARY_METADATA_RESOURCE_ID)) {
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
 * @see src/platform/dell_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult DellUpdateProvider::install( const ScanSessionId				  scanSessionId,
										  const std::span<const std::wstring> identities,
										  const std::uintptr_t				  parentWindowNative,
										  const ProviderProgressCallback	 &progressCallback)
{
	static_cast<void>( parentWindowNative) ;
	InstallResult result ;	// Dell選択全体の実行結果。
	// 現在session・非空選択・公式取得根拠が揃わないinstall要求を拒否する。
	if( scanSessionId == 0 || scanSessionId != scanSessionId_ || identities.empty() ||
	   !httpClient_.hasSourceEvidence( scanSessionId, DELL_PROVIDER_ID,
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
	std::vector<PackageSelectionEntry> packageEntries ;		// CandidateとDUPの対応群。
	packageEntries.reserve( identities.size()) ;
	// System変更前に全選択targetをfail-closedで検証する。
	for( const std::wstring &identity : identities) {
		const auto target = installTargets_.find( identity) ;	// Scan時target検索結果。
		// 未知候補・重複identity・同device二選択を取得開始前に拒否する。
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
	// package集約が不正ならsessionを失効させて全選択を拒否する。
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
		executionResults ;	// Candidate identity別に複製したDUP実行結果。
	executionResults.reserve( identities.size()) ;
	// 初出package順に公式DUPを一度だけ取得・検証・対話実行する。
	for( std::size_t packageIndex = 0; packageIndex < packageGroups->size(); ++packageIndex) {
		const std::vector<std::wstring> &package =
			(*packageGroups)[packageIndex].candidateIdentities ;			// 同一DUP候補群。
		const std::wstring	&representative = package.front() ;				// DUP実行に使う先頭identity。
		const InstallTarget &target = installTargets_.at( representative) ;	// 検証済みtarget。
		const std::uint32_t	 base	=										// 全体進捗内の現在package開始percent。
			static_cast<std::uint32_t>( packageIndex * 100 / packageGroups->size()) ;
		const std::uint32_t end =	// 現在package完了時のpercent。
			static_cast<std::uint32_t>( (packageIndex + 1) * 100 / packageGroups->size()) ;
		const ProviderProgressCallback itemProgress = [&progressCallback, base,
													   end]( const ProviderProgress &progress) {
			ProviderProgress aggregate = progress ;	// 選択全体へ変換する進捗値。
			aggregate.percentComplete =
				std::min<std::uint32_t>( 100, base + progress.percentComplete * (end - base) / 100) ;
			progressCallback( aggregate) ;
		} ;
		const UpdateExecutionResult packageResult =	// 一回だけ実行するDell DUP結果。
			installTarget( httpClient_, scanSessionId, representative, target.releaseId,
						  target.downloadUrl, target.size, target.sha256, itemProgress) ;
		// 一つのDUP process結果を、このpackageを選択した各device候補へ関連付ける。
		for( const std::wstring &identity : package) {
			UpdateExecutionResult update =
				packageResult ;	// Candidate別にidentityだけを置換する結果。
			update.identity = identity ;
			// 実際にdownload成功となった候補だけを取得成功件数へ数える。
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
 * @see src/platform/dell_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void DellUpdateProvider::invalidateScanSession() noexcept
{
	httpClient_.invalidateSourceSession() ;
	installTargets_.clear() ;
	scanSessionId_ = 0 ;
}

} // namespace drivercrate
