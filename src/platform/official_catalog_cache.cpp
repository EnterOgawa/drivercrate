//------------------------------------------------------------------------------
/**
 * @file official_catalog_cache.cpp
 * @brief 公式catalog cache実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Cache検証UTCの読取り値を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note Production rootへ保護DACLを設定し、reparse pointを拒否します。本文とmetadataは別一時fileから置換し、途中終了時の不整合を次回破棄します。
 */
//------------------------------------------------------------------------------

#include "platform/official_catalog_cache.h"

#include <Windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shlobj.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view CACHE_DIRECTORY_NAME	   = L"CatalogCache" ;	// Cache末端directory名。
constexpr std::wstring_view PRODUCT_DIRECTORY_NAME	   = L"DriverCrate" ;	// Product directory名。
constexpr std::string_view	METADATA_MAGIC			   = "DCC1" ;			// Metadata format識別子。
constexpr std::uint64_t		FILE_TIME_UNITS_PER_SECOND = 10'000'000ULL ;	// FILETIMEの1秒当たり単位。
constexpr std::uint64_t		UNIX_EPOCH_FILE_TIME =
	116'444'736'000'000'000ULL ;								// 1601年から1970年までのFILETIME単位差。
constexpr std::uint64_t MAXIMUM_METADATA_BYTES	= 2'048ULL ;	// Sidecar読取り上限。
constexpr std::size_t	SHA256_CHARACTERS		= 64U ;			// SHA-256 hex文字数。
constexpr std::size_t	MAXIMUM_ETAG_CHARACTERS = 512U ;		// 保存するETag文字上限。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief BCrypt algorithm handleをscope終了時に閉じるRAII wrapperである。
 */
class AlgorithmHandle	final {
public:
	  //------------------------------------------------------------------------------
	  /**
     * @brief 空のalgorithm handle wrapperを作成する。
     *
     * BCryptOpenAlgorithmProviderの出力先を初期化する。
     */
	  //------------------------------------------------------------------------------
	  AlgorithmHandle() = default ;

	  //------------------------------------------------------------------------------
	  /**
     * @brief 所有algorithm handleを閉じる。
     *
     * 有効なhandleだけをBCryptCloseAlgorithmProviderへ渡す。
     */
	  //------------------------------------------------------------------------------
	  ~AlgorithmHandle()
	  {
		  // 無効な値を解放APIへ渡さず、保持している有効なresourceの後始末を行う。
		  if( value_ != nullptr) {
			  BCryptCloseAlgorithmProvider( value_, 0) ;
		  }
	  }

	  // 同一algorithm handleを重複解放しないようcopyとmoveを禁止する。
	  /**
	   * @brief CNG algorithm HANDLEの解放責務の二重管理を防ぐため、コピー構築を禁止する。
	   */
	  AlgorithmHandle( const AlgorithmHandle &) = delete ;
	  /**
	   * @brief CNG algorithm HANDLEの解放責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	   */
	  AlgorithmHandle &operator=( const AlgorithmHandle &) = delete ;
	  /**
	   * @brief CNG algorithm HANDLEの解放責務を元のalgorithm ownerに留めるため、移動構築を禁止する。
	   */
	  AlgorithmHandle( AlgorithmHandle &&) = delete ;
	  /**
	   * @brief 元のalgorithm ownerへの結合を保つため、移動代入による管理状態の置換を禁止する。
	   */
	  AlgorithmHandle				  &operator=( AlgorithmHandle &&) = delete ;

	  //------------------------------------------------------------------------------
	  /**
     * @brief BCrypt API用の出力addressを返す。
     *
     * 空objectへ一度だけalgorithm handleを設定するために使用する。
     * @return 所有handle data memberのaddress。
     */
	  //------------------------------------------------------------------------------
	  [[nodiscard]] BCRYPT_ALG_HANDLE *put() noexcept
	  {
		  return &value_ ;
	  }

	  //------------------------------------------------------------------------------
	  /**
     * @brief 所有algorithm handleを返す。
     *
     * BCryptHashへ現在のSHA-256 providerを渡す。
     * @return ownershipを移さないalgorithm handle。
     */
	  //------------------------------------------------------------------------------
	  [[nodiscard]] BCRYPT_ALG_HANDLE get() const noexcept
	  {
		  return value_ ;
	  }

private:
	  /// BCryptCloseAlgorithmProviderで解放するhandle。
	  BCRYPT_ALG_HANDLE value_{} ;
} ;

/**
 * @brief Sidecarから検証後に取り出すcache metadataである。
 */
struct CacheMetadata {
	/// Network検証完了時のUTC FILETIME値。
	std::uint64_t validatedFileTime{} ;
	/// 本文の完全一致byte数。
	std::uint64_t contentSize{} ;
	/// 本文の小文字SHA-256 ASCII hex。
	std::string	  sha256 ;
	/// 条件付きrequestへ使用できる任意ETag。
	std::wstring  etag ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをHRESULT bit patternへ変換する。
 *
 * Win32 errorを失わずplatform共通結果型へ変換する。
 *
 * @param[in] error GetLastErrorまたはWin32 APIが返したerror。
 * @return NativeErrorで保持できるHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief NTSTATUSをHRESULT bit patternへ変換する。
 *
 * CNG失敗codeを診断可能な形式で保持する。
 *
 * @param[in] status BCrypt APIが返したNTSTATUS。
 * @return NativeErrorで保持できるHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromNt( const NTSTATUS status) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在UTCをFILETIME整数へ変換する。
 *
 * Cache期限をlocal timeやtimezoneに依存させない。
 * @return 1601年起点100 nanosecond単位の現在UTC。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint64_t currentFileTime() noexcept
{
	FILETIME value{} ;	// GetSystemTimeAsFileTimeが設定するUTC時刻。
	GetSystemTimeAsFileTime( &value) ;
	ULARGE_INTEGER combined{} ;	// FILETIMEの上下DWORDを結合する値。
	combined.LowPart  = value.dwLowDateTime ;
	combined.HighPart = value.dwHighDateTime ;
	return combined.QuadPart ;
}

//------------------------------------------------------------------------------
/**
 * @brief Byte列のSHA-256を小文字ASCII hexへ変換する。
 *
 * Cache keyと本文整合性へ同じSHA-256実装を使用する。
 *
 * @param[in] bytes Hash対象byte列。
 * @param[out] sha256 成功時の64桁小文字ASCII hex。
 * @return 成功時は0、CNGまたは入力上限失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError sha256Hex( const std::span<const std::byte> bytes, std::string &sha256)
{
	sha256.clear() ;
	// hash APIのbyte長型を超える入力を拒否する。
	if( bytes.size() > std::numeric_limits<ULONG>::max()) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	AlgorithmHandle algorithm ;	// SHA-256 algorithm providerの所有object。
	NTSTATUS status = BCryptOpenAlgorithmProvider( algorithm.put(), BCRYPT_SHA256_ALGORITHM, nullptr,
												  0) ;	// Provider開始結果。
	// 暗号APIの失敗をNT診断値から変換して返す。
	if( !BCRYPT_SUCCESS( status)) {
		return nativeErrorFromNt( status) ;
	}

	constexpr ULONG				  HASH_BYTES = 32U ;	// SHA-256 digest byte数。
	std::array<UCHAR, HASH_BYTES> digest{} ;			// BCryptHashが設定するdigest。
	auto *const					  input =				// CNG ABIへ渡す読取り専用byte先頭。
		const_cast<PUCHAR>( reinterpret_cast<const UCHAR *>( bytes.data())) ;
	status = BCryptHash( algorithm.get(), nullptr, 0, input, static_cast<ULONG>( bytes.size()),
						digest.data(), static_cast<ULONG>( digest.size())) ;
	// 暗号APIの失敗をNT診断値から変換して返す。
	if( !BCRYPT_SUCCESS( status)) {
		return nativeErrorFromNt( status) ;
	}

	// SHA-256の各nibbleを小文字の十六進ASCIIへ変換する固定対応。
	constexpr std::array<char, 16> HEX_DIGITS{'0', '1', '2', '3', '4', '5', '6', '7',
											  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'} ;
	std::string					   encoded ;	// Digestを二文字ずつ格納する結果候補。
	encoded.reserve( SHA256_CHARACTERS) ;
	// 全digest byteを固定長の小文字hexへ変換する。
	for( const UCHAR value : digest) {
		encoded.push_back( HEX_DIGITS[value >> 4U]) ;
		encoded.push_back( HEX_DIGITS[value & 0x0fU]) ;
	}

	sha256 = std::move( encoded) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief URLからcache file basenameを作成する。
 *
 * URL自体をfile名やmetadataへ保存せず、SHA-256だけを使用する。
 *
 * @param[in] url 公式resourceの完全なURL。
 * @param[out] key 成功時の64文字ASCII basename。
 * @return 成功時は0、不正入力またはCNG失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError cacheKey( const std::wstring_view url, std::wstring &key)
{
	key.clear() ;
	// 空またはbyte長換算がAPI範囲を超えるURLからcache keyを作らない。
	if( url.empty() || url.size() > std::numeric_limits<ULONG>::max() / sizeof( wchar_t)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// UTF-16 code unit列をprocess内で一貫したkey materialとして扱う。
	const auto *const				 data = reinterpret_cast<const std::byte *>( url.data()) ;
	const std::span<const std::byte> bytes( data, url.size() * sizeof( wchar_t)) ;	// URL byte列。
	std::string						 encoded ;										// SHA-256 ASCII。
	const NativeError				 error = sha256Hex( bytes, encoded) ;			// Hash結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	key.assign( encoded.begin(), encoded.end()) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Directoryが実在する通常directoryか確認する。
 *
 * Elevated processのcache書込み先をreparse pointへ移さない。
 *
 * @param[in] path 検証する絶対directory path。
 * @return 通常directoryなら0、欠落またはreparse時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateDirectory( const std::wstring_view path)
{
	const std::wstring owned( path) ;										// API用終端null付きpath。
	const DWORD		   attributes = GetFileAttributesW( owned.c_str()) ;	// File属性。
	// cache directoryの属性を取得できなければ利用しない。
	if( attributes == INVALID_FILE_ATTRIBUTES) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 通常directory以外や再解析点をcache rootにしない。
	if( (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
	   (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
		return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Production directoryへ保護DACLを設定する。
 *
 * SYSTEMとbuilt-in Administratorsだけへfull accessを許可する。
 *
 * @param[in] path 所有者変更を行わない既存directory path。
 * @return DACL設定成功時は0、security API失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError protectDirectory( const std::wstring_view path)
{
	constexpr std::wstring_view SECURITY_DESCRIPTOR =
		L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" ;	// 子へ継承する保護DACL。
	PSECURITY_DESCRIPTOR descriptor{} ;				// LocalFreeで解放するSDDL変換結果。
	// 保護DACL用security descriptorを作れなければ設定を中止する。
	if( ConvertStringSecurityDescriptorToSecurityDescriptorW(
		   SECURITY_DESCRIPTOR.data(), SDDL_REVISION_1, &descriptor, nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	BOOL	   present{} ;		// DescriptorにDACLが存在すればTRUE。
	BOOL	   defaulted{} ;	// Default DACL由来ならTRUE。
	PACL	   dacl{} ;			// Descriptor lifetime中有効な非所有ACL。
	// Security descriptorからDACLを取得できたかを示すWin32結果。
	const BOOL gotDacl = GetSecurityDescriptorDacl( descriptor, &present, &dacl, &defaulted) ;
	static_cast<void>( defaulted) ;
	DWORD error = ERROR_INVALID_SECURITY_DESCR ;	// DACL取得失敗時の既定error。
	// 有効なDACLを取得できた場合だけdirectoryへ適用する。
	if( gotDacl != FALSE && present != FALSE && dacl != nullptr) {
		std::wstring owned( path) ;	// SetNamedSecurityInfo用mutable終端null付きpath。
		error =
			SetNamedSecurityInfoW( owned.data(), SE_FILE_OBJECT,
								  DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
								  nullptr, nullptr, dacl, nullptr) ;
	}

	LocalFree( descriptor) ;
	return error == ERROR_SUCCESS ? 0 : nativeErrorFromWin32( error) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常directoryを作成して必要なDACLを設定する。
 *
 * 既存pathもreparse検証し、pre-createによるpath置換を拒否する。
 *
 * @param[in] path 作成または再利用する絶対path。
 * @param[in] protect trueの場合はproduction保護DACLを設定する。
 * @return 作成、検証、DACL設定成功時は0、それ以外はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError ensureDirectory( const std::wstring_view path, const bool protect)
{
	const std::wstring owned( path) ;	// CreateDirectory用終端null付きpath。
	// directory作成失敗時は既存directoryと他の失敗を区別する。
	if( CreateDirectoryW( owned.c_str(), nullptr) == FALSE) {
		const DWORD error = GetLastError() ;	// 既存directoryか判定する作成error。
		// 既存directory以外の作成失敗は診断値を保持して返す。
		if( error != ERROR_ALREADY_EXISTS) {
			return nativeErrorFromWin32( error) ;
		}
	}

	const NativeError validationError = validateDirectory( path) ;	// Reparse等の検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( validationError != 0) {
		return validationError ;
	}

	return protect ? protectDirectory( path) : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Cache rootを初期化する。
 *
 * ProductionではProgramData直下から二段を検証して保護する。
 *
 * @param[in] overridePath 空または試験用絶対path。
 * @param[out] root 成功時の通常directory絶対path。
 * @return Root利用可能時は0、known folderまたはACL失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError initializeRoot( const std::wstring_view overridePath, std::wstring &root)
{
	root.clear() ;
	// 明示overrideがある場合は指定rootを通常directoryとして確認する。
	if( !overridePath.empty()) {
		root = overridePath ;
		return ensureDirectory( root, false) ;
	}

	PWSTR		  programDataRaw{} ;	// CoTaskMemFreeで解放するknown-folder path。
	const HRESULT folderResult =		// ProgramData取得結果。
		SHGetKnownFolderPath( FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr, &programDataRaw) ;
	// 失敗の診断値を共通の表現へ保ったまま返し、未完了の結果で後続処理を進めない。
	if( FAILED( folderResult)) {
		return static_cast<NativeError>( folderResult) ;
	}

	std::wstring productRoot( programDataRaw) ;	// DriverCrate directoryの親path。
	CoTaskMemFree( programDataRaw) ;
	productRoot.append( L"\\").append( PRODUCT_DIRECTORY_NAME) ;
	NativeError error = ensureDirectory( productRoot, true) ;	// Product root初期化結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	root = productRoot ;
	root.append( L"\\").append( CACHE_DIRECTORY_NAME) ;
	error = ensureDirectory( root, true) ;
	// root初期化に失敗した場合は不完全なpathを公開しない。
	if( error != 0) {
		root.clear() ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief Cache entry pathを構築する。
 *
 * 検証済み固定要素だけを連結しpath traversalを作らない。
 *
 * @param[in] root 検証済みcache root。
 * @param[in] key SHA-256 basename。
 * @param[in] extension 固定dot付き拡張子。
 * @return Cache root配下の完全path。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring entryPath( const std::wstring_view root, const std::wstring_view key,
									 const std::wstring_view extension)
{
	std::wstring path( root) ;	// 末尾へbasenameと拡張子を追加する結果。
	path.append( L"\\").append( key).append( extension) ;
	return path ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常fileを上限付きで読み取る。
 *
 * Reparse pointと空fileを拒否し、単一allocationで読み取る。
 *
 * @param[in] path Cache root配下のfile path。
 * @param[in] maximumBytes 読取り上限byte数。
 * @param[out] content 成功時のfile全体。
 * @return 読取り成功時は0、size／reparse／I/O失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readFile( const std::wstring_view path, const std::uint64_t maximumBytes,
								   std::vector<std::byte> &content)
{
	content.clear() ;
	const std::wstring owned( path) ;	// CreateFile用終端null付きpath。
	const HANDLE	   file = CreateFileW(
		  owned.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
		  nullptr) ;	// CloseHandleで解放する所有handle。
	// cache fileを開けなければ読込みを中止する。
	if( file == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	FILE_ATTRIBUTE_TAG_INFO tagInfo{} ;	// Reparse属性とtagの取得先。
	LARGE_INTEGER			size{} ;	// File全体のsigned byte数。
	const BOOL gotAttributes = GetFileInformationByHandleEx( file, FileAttributeTagInfo, &tagInfo,
															// 属性取得結果。
															sizeof( tagInfo)) ;
	const BOOL gotSize		 = GetFileSizeEx( file, &size) ;	// Size取得結果。
	// 通常file属性、非空size、byte上限を確認し、不正入力のhandleを閉じて返す。
	if( gotAttributes == FALSE || gotSize == FALSE ||
	   (tagInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
	   (tagInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 || size.QuadPart <= 0 ||
	   static_cast<std::uint64_t>( size.QuadPart) > maximumBytes ||
	   static_cast<std::uint64_t>( size.QuadPart) > std::numeric_limits<DWORD>::max()) {
		// 属性・長さのAPI失敗は元のWin32診断を、内容不正はINVALID_DATAを保持する。
		const DWORD error =
			gotAttributes == FALSE || gotSize == FALSE ? GetLastError() : ERROR_INVALID_DATA ;
		CloseHandle( file) ;
		return nativeErrorFromWin32( error) ;
	}

	std::vector<std::byte> loaded( static_cast<std::size_t>( size.QuadPart)) ;	// File buffer。
	DWORD				   bytesRead{} ;										// ReadFileが返したbyte数。
	const BOOL	readResult = ReadFile( file, loaded.data(), static_cast<DWORD>( loaded.size()),
									  &bytesRead, nullptr) ;						// 全体読取り結果。
	const DWORD readError  = readResult != FALSE ? ERROR_SUCCESS : GetLastError() ;	// 保存error。
	CloseHandle( file) ;
	// 読込みAPI失敗と途中EOFを完全なcache本文として扱わない。
	if( readResult == FALSE || bytesRead != static_cast<DWORD>( loaded.size())) {
		return nativeErrorFromWin32( readResult == FALSE ? readError : ERROR_HANDLE_EOF) ;
	}

	content = std::move( loaded) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Byte列を新規fileへ保存してflushする。
 *
 * CREATE_NEWで既存fileを上書きせず、partial writeを拒否する。
 *
 * @param[in] path 未作成である一時file path。
 * @param[in] content 空ではない保存内容。
 * @return 保存とflush成功時は0、それ以外はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError writeNewFile( const std::wstring_view			path,
									   const std::span<const std::byte> content)
{
	// 空または書込みAPIの長さ型を超える本文を保存しない。
	if( content.empty() || content.size() > std::numeric_limits<DWORD>::max()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring owned( path) ;	// CreateFile用終端null付きpath。
	const HANDLE	   file = CreateFileW( owned.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
										  FILE_ATTRIBUTE_NORMAL, nullptr) ;	// 所有handle。
	// 新規cache fileを作れなければ既存fileへ上書きしない。
	if( file == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	DWORD		written{} ;	// WriteFileが保存したbyte数。
	const BOOL	writeResult = WriteFile( file, content.data(), static_cast<DWORD>( content.size()),
										&written, nullptr) ;							// 全体書込み結果。
	const DWORD writeError	= writeResult != FALSE ? ERROR_SUCCESS : GetLastError() ;	// 保存error。
	const BOOL	flushResult = writeResult != FALSE && written == static_cast<DWORD>( content.size())
								  ? FlushFileBuffers( file)
								  : FALSE ;												// Durable化結果。
	const DWORD flushError	= flushResult != FALSE ? ERROR_SUCCESS : GetLastError() ;	// 保存error。
	CloseHandle( file) ;
	// 書込み失敗や部分書込みを保存成功として返さない。
	if( writeResult == FALSE || written != static_cast<DWORD>( content.size())) {
		return nativeErrorFromWin32( writeResult == FALSE ? writeError : ERROR_WRITE_FAULT) ;
	}

	return flushResult != FALSE ? 0 : nativeErrorFromWin32( flushError) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ETagをrequest headerとsidecarへ保存可能か検証する。
 *
 * CR/LF、Unicode、control文字によるheader injectionを拒否する。
 *
 * @param[in] etag Response由来またはsidecar由来のETag。
 * @return 空または安全なvisible ASCIIだけなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafeEtag( const std::wstring_view etag) noexcept
{
	return etag.size() <= MAXIMUM_ETAG_CHARACTERS &&
		   std::all_of( etag.begin(), etag.end(), []( const wchar_t character) {
			   return character >= 0x20 && character <= 0x7e ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Metadataの一行を取得する。
 *
 * CRを許可せず、formatをplatform改行差へ依存させない。
 *
 * @param[in] text Sidecar全体。
 * @param[in,out] offset 次の行の開始位置。
 * @param[out] line 改行を含まない現在行。
 * @return LF終端行を一つ取得できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool nextLine( const std::string_view text, std::size_t &offset,
							std::string_view &line) noexcept
{
	// metadata末尾を越えて次の行を取得しない。
	if( offset >= text.size()) {
		return false ;
	}

	const std::size_t end = text.find( '\n', offset) ;	// 現在行のLF位置。
	// 終端改行がないmetadata行を不完全として拒否する。
	if( end == std::string_view::npos) {
		return false ;
	}

	line   = text.substr( offset, end - offset) ;
	offset = end + 1 ;
	return line.find( '\r') == std::string_view::npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief 10進整数をoverflow検証付きで取得する。
 *
 * Localeや符号を受理しないsidecar専用変換を行う。
 *
 * @param[in] text 空ではないASCII 10進文字列。
 * @param[out] value 成功時の64-bit値。
 * @return 全文字をoverflowなしで変換できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool parseUnsigned( const std::string_view text, std::uint64_t &value) noexcept
{
	value = 0 ;
	// 空文字列を0のmetadata値へ代用しない。
	if( text.empty()) {
		return false ;
	}

	const char *const			 begin	= text.data() ;							// from_chars入力先頭。
	const char *const			 end	= begin + text.size() ;					// from_chars入力終端。
	const std::from_chars_result result = std::from_chars( begin, end, value) ;	// 変換結果。
	return result.ec == std::errc{} && result.ptr == end ;
}

//------------------------------------------------------------------------------
/**
 * @brief Sidecarを厳密なcache metadataへ変換する。
 *
 * 余分な行や非ASCII値を受理せず、曖昧なfallbackを行わない。
 *
 * @param[in] content 上限内で読み取ったsidecar byte列。
 * @param[out] metadata 成功時の検証済みmetadata。
 * @return Version、行数、型、hash、ETagが全て正しい場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool parseMetadata( const std::span<const std::byte> content, CacheMetadata &metadata)
{
	const auto *const	   begin = reinterpret_cast<const char *>( content.data()) ;	// ASCII先頭。
	const std::string_view text( begin, content.size()) ;								// Sidecar全体view。
	std::size_t			   offset{} ;													// 次に読むline位置。
	std::string_view	   magic ;														// Format識別行。
	std::string_view	   validated ;													// 検証時刻行。
	std::string_view	   size ;														// 本文size行。
	std::string_view	   hash ;														// SHA-256行。
	std::string_view	   etag ;														// ETag行。
	// sidecarの行数、magic、hash長が固定schemaに一致することを要求する。
	if( !nextLine( text, offset, magic) || !nextLine( text, offset, validated) ||
	   !nextLine( text, offset, size) || !nextLine( text, offset, hash) ||
	   !nextLine( text, offset, etag) || offset != text.size() || magic != METADATA_MAGIC ||
	   hash.size() != SHA256_CHARACTERS) {
		return false ;
	}

	const bool validHash =	// SHA-256はcanonical小文字hexだけを許可する。
		std::all_of( hash.begin(), hash.end(), []( const char character) {
			return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') ;
		}) ;
	// hash、時刻、非空本文size、ETag上限を検証する。
	if( !validHash || !parseUnsigned( validated, metadata.validatedFileTime) ||
	   !parseUnsigned( size, metadata.contentSize) || metadata.contentSize == 0 ||
	   etag.size() > MAXIMUM_ETAG_CHARACTERS) {
		return false ;
	}

	std::wstring decodedEtag ;	// ASCIIから一対一変換するETag候補。
	decodedEtag.reserve( etag.size()) ;
	// 全ETag byteをvisible ASCIIとして検証しUTF-16へ変換する。
	for( const char character : etag) {
		const unsigned char value = static_cast<unsigned char>( character) ;	// 符号なし比較値。
		// ETag metadataに制御文字や非ASCII文字を許容しない。
		if( value < 0x20U || value > 0x7eU) {
			return false ;
		}

		decodedEtag.push_back( static_cast<wchar_t>( value)) ;
	}

	metadata.sha256.assign( hash) ;
	metadata.etag = std::move( decodedEtag) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Cache metadata sidecarを構築する。
 *
 * 現在UTCを保存し、URLや端末情報をmetadataへ含めない。
 *
 * @param[in] contentSize 本文byte数。
 * @param[in] sha256 本文の小文字SHA-256。
 * @param[in] etag 検証済みの任意visible ASCII ETag。
 * @return DCC1形式のASCII sidecar byte列。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<std::byte> buildMetadata( const std::uint64_t	   contentSize,
												   const std::string_view  sha256,
												   const std::wstring_view etag)
{
	std::string text ;	// LF区切りのsidecar候補。
	text.reserve( 256U + etag.size()) ;
	text.append( METADATA_MAGIC).push_back( '\n') ;
	text.append( std::to_string( currentFileTime())).push_back( '\n') ;
	text.append( std::to_string( contentSize)).push_back( '\n') ;
	text.append( sha256).push_back( '\n') ;
	// ETagはis_safe_etag通過済みのASCIIだけを一対一で保存する。
	for( const wchar_t character : etag) {
		text.push_back( static_cast<char>( character)) ;
	}

	text.push_back( '\n') ;
	const auto *const begin = reinterpret_cast<const std::byte *>( text.data()) ;	// Byte先頭。
	return std::vector<std::byte>( begin, begin + text.size()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Cache entryをpath指定で削除する。
 *
 * 破損entryを再利用しないことを優先し、削除errorは返さない。
 *
 * @param[in] bodyPath 本文file path。
 * @param[in] metadataPath Sidecar file path。
 */
//------------------------------------------------------------------------------
void discardPaths( const std::wstring_view bodyPath, const std::wstring_view metadataPath) noexcept
{
	const std::wstring body( bodyPath) ;			// DeleteFile用本文path。
	const std::wstring metadata( metadataPath) ;	// DeleteFile用sidecar path。
	DeleteFileW( body.c_str()) ;
	DeleteFileW( metadata.c_str()) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_catalog_cache.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialCatalogCache::OfficialCatalogCache( std::wstring rootOverride)
	: rootOverride_( std::move( rootOverride))
{
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_catalog_cache.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialCatalogCache::load( const std::wstring_view url,
									   const std::uint64_t	   maximumBytes,
									   const std::uint64_t	   maximumAgeSeconds,
									   CatalogCacheEntry	  &entry) const
{
	entry = {} ;
	// URL、本文上限、寿命の時刻単位換算範囲を読み込み前に検証する。
	if( url.empty() || maximumBytes == 0 ||
	   maximumAgeSeconds > std::numeric_limits<std::uint64_t>::max() / FILE_TIME_UNITS_PER_SECOND) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::wstring root ;											// 初期化済みcache root。
	NativeError	 error = initializeRoot( rootOverride_, root) ;	// Root初期化結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	std::wstring key ;	// URLのSHA-256 basename。
	error = cacheKey( url, key) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	const std::wstring bodyPath		  = entryPath( root, key, L".body") ;			// 本文path。
	const std::wstring metadataPath	  = entryPath( root, key, L".meta") ;			// Sidecar path。
	const DWORD		   bodyAttributes = GetFileAttributesW( bodyPath.c_str()) ;		// 本文存在状態。
	const DWORD metadataAttributes	  = GetFileAttributesW( metadataPath.c_str()) ;	// Meta存在状態。
	// 本文とsidecarが揃わないcacheは残片を破棄して未登録として扱う。
	if( bodyAttributes == INVALID_FILE_ATTRIBUTES || metadataAttributes == INVALID_FILE_ATTRIBUTES) {
		// Orphanも次回entryと混ざらないようbest-effortで削除する。
		discardPaths( bodyPath, metadataPath) ;
		return 0 ;
	}

	std::vector<std::byte> metadataContent ;	// 上限内のsidecar byte列。
	error = readFile( metadataPath, MAXIMUM_METADATA_BYTES, metadataContent) ;
	CacheMetadata metadata ;	// Parse済みsidecar値。
	// sidecar不正や本文上限超過時はcacheを失効させる。
	if( error != 0 || !parseMetadata( metadataContent, metadata) ||
	   metadata.contentSize > maximumBytes) {
		discardPaths( bodyPath, metadataPath) ;
		entry.state = CatalogCacheState::INVALIDATED ;
		return 0 ;
	}

	std::vector<std::byte> body ;	// Sizeとreparse検証済み本文候補。
	error = readFile( bodyPath, maximumBytes, body) ;
	// 本文取得失敗やsidecarとのsize不一致はcacheを失効させる。
	if( error != 0 || body.size() != metadata.contentSize) {
		discardPaths( bodyPath, metadataPath) ;
		entry.state = CatalogCacheState::INVALIDATED ;
		return 0 ;
	}

	std::string actualHash ;	// 本文から再計算するSHA-256。
	error = sha256Hex( body, actualHash) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	// 本文hashの不一致や安全でないETagを持つcacheを破棄する。
	if( actualHash != metadata.sha256 || !isSafeEtag( metadata.etag)) {
		discardPaths( bodyPath, metadataPath) ;
		entry.state = CatalogCacheState::INVALIDATED ;
		return 0 ;
	}

	const std::uint64_t now		   = currentFileTime() ;								// Fresh判定時点のUTC FILETIME。
	const std::uint64_t maximumAge = maximumAgeSeconds * FILE_TIME_UNITS_PER_SECOND ;	// 期限。
	entry.state					   = maximumAgeSeconds != 0 && now >= metadata.validatedFileTime &&
							 now - metadata.validatedFileTime <= maximumAge
										 ? CatalogCacheState::FRESH
										 : CatalogCacheState::STALE ;
	entry.content				   = std::move( body) ;
	entry.etag					   = std::move( metadata.etag) ;
	// Unix epoch以降の検証時刻だけを非機密な計測UTCへ変換する。
	if( metadata.validatedFileTime >= UNIX_EPOCH_FILE_TIME) {
		entry.validatedUtcSeconds =
			(metadata.validatedFileTime - UNIX_EPOCH_FILE_TIME) / FILE_TIME_UNITS_PER_SECOND ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_catalog_cache.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialCatalogCache::store( const std::wstring_view			 url,
										const std::span<const std::byte> content,
										const std::wstring_view			 etag) const
{
	// 空のURL・本文や書込み範囲超過をcache保存前に拒否する。
	if( url.empty() || content.empty() || content.size() > std::numeric_limits<DWORD>::max()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::wstring root ;											// 初期化済みcache root。
	NativeError	 error = initializeRoot( rootOverride_, root) ;	// Root初期化結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	std::wstring key ;	// URLのSHA-256 basename。
	error = cacheKey( url, key) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	std::string hash ;	// 本文の小文字SHA-256。
	error = sha256Hex( content, hash) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	const std::wstring_view		 safeEtag = isSafeEtag( etag) ? etag : std::wstring_view{} ;	// ETag。
	const std::vector<std::byte> metadata =														// 現在時刻を含むsidecar。
		buildMetadata( content.size(), hash, safeEtag) ;
	const std::wstring bodyPath		= entryPath( root, key, L".body") ;	// 最終本文path。
	const std::wstring metadataPath = entryPath( root, key, L".meta") ;	// 最終meta path。
	const std::wstring suffix		= L"." + std::to_wstring( GetCurrentProcessId()) + L"." +
								// 一時file識別suffix。
								std::to_wstring( GetCurrentThreadId()) ;
	const std::wstring temporaryBody	 = bodyPath + suffix + L".tmp" ;		// 一時本文path。
	const std::wstring temporaryMetadata = metadataPath + suffix + L".tmp" ;	// 一時meta path。
	DeleteFileW( temporaryBody.c_str()) ;
	DeleteFileW( temporaryMetadata.c_str()) ;
	error = writeNewFile( temporaryBody, content) ;
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		error = writeNewFile( temporaryMetadata, metadata) ;
	}

	// 先行保存が成功した場合だけ本文の置換を行い、失敗診断を保持する。
	if( error == 0 && MoveFileExW( temporaryBody.c_str(), bodyPath.c_str(),
								 MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
		error = nativeErrorFromWin32( GetLastError()) ;
	}

	// 本文置換まで成功した場合だけsidecarを置換する。
	if( error == 0 && MoveFileExW( temporaryMetadata.c_str(), metadataPath.c_str(),
								 MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
		error = nativeErrorFromWin32( GetLastError()) ;
	}

	DeleteFileW( temporaryBody.c_str()) ;
	DeleteFileW( temporaryMetadata.c_str()) ;
	// 部分commitの失敗時は本文とsidecarを可能な範囲で破棄する。
	if( error != 0) {
		// Partial commitは次回loadのhash不一致で破棄されるが、現在も可能な範囲で除去する。
		discardPaths( bodyPath, metadataPath) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_catalog_cache.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void OfficialCatalogCache::discard( const std::wstring_view url) const noexcept
{
	try {
		std::wstring root ;	// 利用可能なcache root。
		// rootを解決できない場合は削除対象pathを推測しない。
		if( initializeRoot( rootOverride_, root) != 0) {
			return ;
		}

		std::wstring key ;	// URLのSHA-256 basename。
		// URLのcache keyを決定できなければ別fileを削除しない。
		if( cacheKey( url, key) != 0) {
			return ;
		}

		const std::wstring bodyPath		= entryPath( root, key, L".body") ;	// 本文path。
		const std::wstring metadataPath = entryPath( root, key, L".meta") ;	// Sidecar path。
		discardPaths( bodyPath, metadataPath) ;
	} catch( ...) {
		// Best-effort削除境界でallocation例外をprocessへ伝播させない。
	}
}

} // namespace drivercrate
