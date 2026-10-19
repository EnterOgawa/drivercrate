//------------------------------------------------------------------------------
/**
 * @file official_catalog_validation.cpp
 * @brief 公式catalog共通schema／CAB検証実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  UTF-8 XML読取り追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note CAB展開先は呼出し側の保護workspaceに限定します。XMLのvendor固有schemaを推測せず、共通security envelopeだけをfail-closedで検証し
 *       ます。
 */
//------------------------------------------------------------------------------

#include "platform/official_catalog_validation.h"

#include "platform/com_raii.h"

#include <SetupAPI.h>
#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t  MAXIMUM_CAB_ENTRY_CHARACTERS			  = 255 ;	// CAB内basename文字数上限。
constexpr std::int32_t MAXIMUM_XML_ELEMENT_DEPTH			  = 64 ;	// MSXML要素nesting上限。
constexpr std::size_t  MAXIMUM_SELECTION_NAMESPACE_CHARACTERS = 4096 ;	// XPath宣言上限。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief SetupIterateCabinet callbackへ渡す単一XML抽出状態である。
 */
struct CabinetExtractionContext {
	/// CAB内XMLの固定展開先絶対path。
	std::wstring  outputPath ;
	/// Providerが許容する展開後byte数上限。
	std::uint64_t maximumBytes{} ;
	/// 一つ目の許可XMLを選択済みならtrue。
	bool		  selected{} ;
	/// 選択XMLの展開完了通知を受けた場合true。
	bool		  extracted{} ;
	/// 複数XML等を検出して拒否する場合true。
	bool		  invalid{} ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorを共通NativeErrorへ変換する。
 *
 * 元のWin32失敗理由をProvider共通表現へ保持する。
 *
 * @param[in] error GetLastErrorまたはWin32 API error code。
 * @return HRESULT_FROM_WIN32で変換したNativeError。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief HRESULTを共通NativeErrorへ変換する。
 *
 * MSXML診断値を失わずProvider層へ返す。
 *
 * @param[in] error COM APIが返したHRESULT。
 * @return Bit patternを維持したNativeError。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeError( const HRESULT error) noexcept
{
	return static_cast<NativeError>( error) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Local drive上の絶対pathかを判定する。
 *
 * UNC、device path、relative pathをCAB展開境界へ入れない。
 *
 * @param[in] path Win32 file APIへ渡すpath。
 * @return `C:\\...`形式で埋込みnullがなければ`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isLocalAbsolutePath( const std::wstring_view path) noexcept
{
	// local drive絶対pathの形式に合わない値や埋込NULを拒否する。
	if( path.size() < 3 || path[1] != L':' || path[2] != L'\\' ||
	   path.find( L'\0') != std::wstring_view::npos) {
		return false ;
	}

	const wchar_t drive = path.front() ;	// ASCII drive letter候補。
	return (drive >= L'A' && drive <= L'Z') || (drive >= L'a' && drive <= L'z') ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常fileの実byte数と属性を検証する。
 *
 * Directoryとreparse pointを拒否し、展開前宣言値を信用しない。
 *
 * @param[in] path 検証対象file絶対path。
 * @param[in] maximumBytes 0より大きい許容byte数上限。
 * @param[out] size 成功時の実byte数。
 * @return 通常fileかつsize範囲内なら0、それ以外はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateRegularFile( const std::wstring_view path,
											  const std::uint64_t maximumBytes, std::uint64_t &size)
{
	size = 0 ;
	// 空、埋込NUL付きpath、無効byte上限をfile検証前に拒否する。
	if( path.empty() || path.find( L'\0') != std::wstring_view::npos || maximumBytes == 0) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring		  filePath( path) ;	// GetFileAttributesEx用終端null付きpath。
	WIN32_FILE_ATTRIBUTE_DATA attributes{} ;	// File種別と64-bit size。
	// file属性の取得失敗を元の診断値で返す。
	if( GetFileAttributesExW( filePath.c_str(), GetFileExInfoStandard, &attributes) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// Catalog入力として通常file以外やreparse経路を拒否する属性mask。
	constexpr DWORD REJECTED_ATTRIBUTES = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT ;
	// 禁止属性を持つfileを通常のcatalog入力として扱わない。
	if( (attributes.dwFileAttributes & REJECTED_ATTRIBUTES) != 0) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	ULARGE_INTEGER length{} ;	// High/Lowを結合した実file size。
	length.LowPart	= attributes.nFileSizeLow ;
	length.HighPart = attributes.nFileSizeHigh ;
	size			= length.QuadPart ;
	// 空または上限超過のfile sizeを拒否し、出力sizeを無効にする。
	if( size == 0 || size > maximumBytes) {
		size = 0 ;
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief SetupAPI CAB通知を単一XML抽出へ変換する。
 *
 * 単一の平坦XMLだけを選び、multi-cabとcallback例外を拒否する。
 *
 * @param[in,out] context CabinetExtractionContextへの非所有pointer。
 * @param[in] notification SetupAPI notification code。
 * @param[in] parameter1 通知別SetupAPI構造体pointer値。
 * @param[in] parameter2 未使用の通知別値。
 * @return 通知契約に対応するFILEOP値、NO_ERRORまたはWin32 error。
 */
//------------------------------------------------------------------------------
UINT CALLBACK cabinetCallback( const PVOID context, const UINT notification,
							  const UINT_PTR parameter1, const UINT_PTR parameter2)
{
	static_cast<void>( parameter2) ;
	try {
		auto *state = static_cast<CabinetExtractionContext *>( context) ;	// 非所有抽出状態。
		// callback状態がなければCAB処理を中止する。
		if( state == nullptr) {
			return notification == SPFILENOTIFY_FILEINCABINET ? FILEOP_ABORT : ERROR_INVALID_DATA ;
		}

		// CAB内file通知で単一XMLとしての条件を確認する。
		if( notification == SPFILENOTIFY_FILEINCABINET) {
			auto *information =
				reinterpret_cast<FILE_IN_CABINET_INFO_W *>( parameter1) ;	// CAB entry情報。
			// 欠落またはerror付きentry情報を抽出対象にしない。
			if( information == nullptr || information->NameInCabinet == nullptr ||
			   information->Win32Error != NO_ERROR) {
				state->invalid = true ;
				return FILEOP_ABORT ;
			}

			const std::wstring_view name( information->NameInCabinet) ;	// CAB内entry名。
			const bool				xml = name.size() >= 4 &&
							 // XML判定。
							 _wcsnicmp( name.data() + name.size() - 4, L".xml", 4) == 0 ;
			// XML以外のCAB entryを展開しない。
			if( !xml) {
				return FILEOP_SKIP ;
			}

			// 複数XML、許可外entry、過大な出力pathを拒否する。
			if( state->selected ||
			   !isAllowedOfficialCatalogEntry( name, information->FileSize, state->maximumBytes) ||
			   state->outputPath.size() >= MAX_PATH) {
				state->invalid = true ;
				return FILEOP_ABORT ;
			}

			// 出力pathの安全なcopyに失敗した場合は抽出を中止する。
			if( wcscpy_s( information->FullTargetName, MAX_PATH, state->outputPath.c_str()) != 0) {
				state->invalid = true ;
				return FILEOP_ABORT ;
			}

			state->selected = true ;
			return FILEOP_DOIT ;
		}

		// 抽出完了通知を選択済みXMLの予約先へ照合する。
		if( notification == SPFILENOTIFY_FILEEXTRACTED) {
			const auto *paths = reinterpret_cast<const FILEPATHS_W *>( parameter1) ;	// 展開結果情報。
			// 未選択、二重完了、抽出失敗、出力先不一致を拒否する。
			if( !state->selected || state->extracted || paths == nullptr ||
			   paths->Win32Error != ERROR_SUCCESS || paths->Target == nullptr ||
			   _wcsicmp( paths->Target, state->outputPath.c_str()) != 0) {
				state->invalid = true ;
				return ERROR_INVALID_DATA ;
			}

			state->extracted = true ;
			return NO_ERROR ;
		}

		// 追加CABを必要とする分割archiveを追跡しない。
		if( notification == SPFILENOTIFY_NEEDNEWCABINET) {
			state->invalid = true ;
			return ERROR_INVALID_DATA ;
		}

		return NO_ERROR ;
	} catch( ...) {
		// Win32 callback ABIを越えてexceptionを伝播させず、通知契約に従って中止する。
		return notification == SPFILENOTIFY_FILEINCABINET ? FILEOP_ABORT : ERROR_INVALID_DATA ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief MSXML propertyへ論理値を設定する。
 *
 * VARIANTとBSTRのlifetimeを局所化して設定する。
 *
 * @param[in,out] document 設定対象MSXML document。
 * @param[in] name 固定MSXML property名。
 * @param[in] value 設定する論理値。
 * @return MSXMLが返したHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT setBooleanProperty( IXMLDOMDocument2 &document, const std::wstring_view name,
										 const bool value)
{
	UniqueBstr propertyName( name) ;	// setProperty呼出し中だけ所有するproperty名。
	VARIANT	   property{} ;				// 所有resourceを持たないBOOL property値。
	VariantInit( &property) ;
	property.vt		 = VT_BOOL ;
	property.boolVal = value ? VARIANT_TRUE : VARIANT_FALSE ;
	return document.setProperty( propertyName.get(), property) ;
}

//------------------------------------------------------------------------------
/**
 * @brief MSXML propertyへ32-bit整数を設定する。
 *
 * XML sizeと要素深度の有限上限をVT_I4で設定する。
 *
 * @param[in,out] document 設定対象MSXML document。
 * @param[in] name 固定MSXML property名。
 * @param[in] value 0以上の設定値。
 * @return MSXMLが返したHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT setIntegerProperty( IXMLDOMDocument2 &document, const std::wstring_view name,
										 const std::int32_t value)
{
	UniqueBstr propertyName( name) ;	// setProperty呼出し中だけ所有するproperty名。
	VARIANT	   property{} ;				// 所有resourceを持たない整数property値。
	VariantInit( &property) ;
	property.vt	  = VT_I4 ;
	property.lVal = value ;
	return document.setProperty( propertyName.get(), property) ;
}

//------------------------------------------------------------------------------
/**
 * @brief MSXML propertyへ文字列を設定する。
 *
 * XPath namespace等のBSTR ownershipを局所化する。
 *
 * @param[in,out] document 設定対象MSXML document。
 * @param[in] name 固定MSXML property名。
 * @param[in] value 呼出し中有効なUTF-16設定値。
 * @return MSXMLが返したHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] HRESULT setStringProperty( IXMLDOMDocument2 &document, const std::wstring_view name,
										const std::wstring_view value)
{
	UniqueBstr propertyName( name) ;	// setProperty呼出し中だけ所有するproperty名。
	UniqueBstr propertyValue( value) ;	// VARIANTが呼出し中に参照する設定値。
	VARIANT	   property{} ;				// BSTRを非所有参照する設定用VARIANT。
	VariantInit( &property) ;
	property.vt		 = VT_BSTR ;
	property.bstrVal = propertyValue.get() ;
	return document.setProperty( propertyName.get(), property) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_catalog_validation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAllowedOfficialCatalogEntry( const std::wstring_view entryName,
												 const std::uint64_t	 expandedBytes,
												 const std::uint64_t maximumExpandedBytes) noexcept
{
	// XML名の長さ、拡張子、非空展開sizeと上限を確認する。
	if( entryName.size() < 5 || entryName.size() > MAXIMUM_CAB_ENTRY_CHARACTERS ||
	   expandedBytes == 0 || maximumExpandedBytes == 0 || expandedBytes > maximumExpandedBytes ||
	   _wcsnicmp( entryName.data() + entryName.size() - 4, L".xml", 4) != 0) {
		return false ;
	}

	constexpr std::wstring_view REJECTED_CHARACTERS = L"<>:\"/\\|?*" ;	// Windows予約文字。
	// Basename全体を検査し、separator、control文字、末尾空白を拒否する。
	for( const wchar_t character : entryName) {
		// 制御文字や禁止path文字を含むXML名を拒否する。
		if( character < L' ' || REJECTED_CHARACTERS.find( character) != std::wstring_view::npos) {
			return false ;
		}
	}

	const std::wstring_view stem = entryName.substr( 0, entryName.size() - 4) ;	// 拡張子前の名前。
	return !stem.empty() && stem != L"." && stem != L".." && stem.back() != L' ' &&
		   stem.back() != L'.' ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_catalog_validation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError extractOfficialCatalogXml( const std::wstring_view cabPath,
													const std::wstring_view outputPath,
													const std::uint64_t		maximumExpandedBytes)
{
	// 入力と出力のlocal絶対path、展開上限、path長を事前に検証する。
	if( !isLocalAbsolutePath( cabPath) || !isLocalAbsolutePath( outputPath) ||
	   maximumExpandedBytes == 0 || outputPath.size() >= MAX_PATH) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring output( outputPath) ;	// Win32 API用終端null付き展開先path。
	// 既存の出力fileをcatalog抽出で上書きしない。
	if( GetFileAttributesW( output.c_str()) != INVALID_FILE_ATTRIBUTES) {
		return nativeErrorFromWin32( ERROR_ALREADY_EXISTS) ;
	}

	const DWORD outputError = GetLastError() ;	// 未作成確認時のWin32結果。
	// 出力先不存在以外の属性取得失敗は診断値を保持して返す。
	if( outputError != ERROR_FILE_NOT_FOUND && outputError != ERROR_PATH_NOT_FOUND) {
		return nativeErrorFromWin32( outputError) ;
	}

	CabinetExtractionContext context ;	// Callbackと共有する単一XML抽出状態。
	context.outputPath	 = output ;
	context.maximumBytes = maximumExpandedBytes ;
	const std::wstring cab( cabPath) ;	// SetupIterateCabinet用終端null付きCAB path。
	// CAB列挙・展開のOS API完了結果。Callback内の診断とは別に確認する。
	const BOOL		   iterated = SetupIterateCabinetW( cab.c_str(), 0, cabinetCallback, &context) ;
	const DWORD iterationError	= iterated != FALSE ? ERROR_SUCCESS : GetLastError() ;	// API結果。
	// 単一XMLの正常抽出を確認できなければ今回の出力を破棄する。
	if( iterated == FALSE || !context.selected || !context.extracted || context.invalid) {
		DeleteFileW( output.c_str()) ;
		return context.invalid
				   ? nativeErrorFromWin32( ERROR_INVALID_DATA)
				   : nativeErrorFromWin32( iterationError != ERROR_SUCCESS ? iterationError
																		  : ERROR_INVALID_DATA) ;
	}

	std::uint64_t	  actualSize{} ;	// 展開後にfilesystemから確認する実byte数。
	// 展開後fileの通常属性と有限長を再確認した結果。
	const NativeError fileError = validateRegularFile( outputPath, maximumExpandedBytes, actualSize) ;
	// 抽出後fileの検証失敗時は出力を破棄する。
	if( fileError != 0) {
		DeleteFileW( output.c_str()) ;
		return fileError ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_catalog_validation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readOfficialUtf16Xml( const std::wstring_view path,
											   const std::uint64_t maximumBytes, std::wstring &xml)
{
	xml.clear() ;
	std::uint64_t	  bytes{} ;	// Filesystemから確認したXML実byte数。
	// UTF-16読込み前にfile属性とbyte上限を確認した結果。
	const NativeError sizeError = validateRegularFile( path, maximumBytes, bytes) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( sizeError != 0) {
		return sizeError ;
	}

	// UTF-16文字境界や読み込みAPIのbyte範囲に合わないXMLを拒否する。
	if( bytes < sizeof( wchar_t) || bytes % sizeof( wchar_t) != 0 ||
	   bytes > std::numeric_limits<DWORD>::max()) {
		return nativeErrorFromWin32( ERROR_NO_UNICODE_TRANSLATION) ;
	}

	const std::wstring filePath( path) ;	// CreateFile用終端null付きpath。
	// 読取り専用で開く一時所有handle。後続のRAII wrapperへ引き渡す。
	const HANDLE rawFile = CreateFileW( filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
									   OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr) ;
	// UTF-16 XMLを開けなければ読み込みを中止する。
	if( rawFile == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const auto closeFile = []( void *const handle) noexcept {
		// 無効な値を解放APIへ渡さず、保持している有効なresourceの後始末を行う。
		if( handle != nullptr) {
			CloseHandle( handle) ;
		}
	} ; // Scope終了時に読取りhandleを一度だけ閉じるdeleter。
	const std::unique_ptr<void, decltype( closeFile)> file( rawFile, closeFile) ;	// 所有handle。
	std::vector<std::byte> buffer( static_cast<std::size_t>( bytes)) ;				// XML byte buffer。
	DWORD				   read{} ;													// ReadFile結果byte数。
	// XML読込み失敗を元のWindows診断値で返す。
	if( ReadFile( file.get(), buffer.data(), static_cast<DWORD>( bytes), &read, nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 宣言size分を読めない途中EOFを拒否する。
	if( read != bytes) {
		return nativeErrorFromWin32( ERROR_HANDLE_EOF) ;
	}

	std::wstring decoded( buffer.size() / sizeof( wchar_t), L'\0') ;	// UTF-16LE code unit列。
	std::memcpy( decoded.data(), buffer.data(), buffer.size()) ;
	// 先頭のUTF-16 BOMだけを本文から取り除く。
	if( !decoded.empty() && decoded.front() == 0xfeff) {
		decoded.erase( decoded.begin()) ;
	}

	// 空、markupで始まらない、埋込NUL付きの復号結果を拒否する。
	if( decoded.empty() || decoded.front() != L'<' || decoded.find( L'\0') != std::wstring::npos) {
		return nativeErrorFromWin32( ERROR_NO_UNICODE_TRANSLATION) ;
	}

	xml = std::move( decoded) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_catalog_validation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readOfficialUtf8Xml( const std::wstring_view path,
											  const std::uint64_t maximumBytes, std::wstring &xml)
{
	xml.clear() ;
	std::uint64_t	  bytes{} ;	// Filesystemから確認したXML実byte数。
	// UTF-8読込み前にfile属性とbyte上限を確認した結果。
	const NativeError sizeError = validateRegularFile( path, maximumBytes, bytes) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( sizeError != 0) {
		return sizeError ;
	}

	// UTF-8変換と読込みAPI双方の長さ型に収まることを要求する。
	if( bytes > static_cast<std::uint64_t>( std::numeric_limits<int>::max()) ||
	   bytes > static_cast<std::uint64_t>( std::numeric_limits<DWORD>::max())) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	const std::wstring filePath( path) ;	// CreateFile用終端null付きpath。
	// 読取り専用で開く一時所有handle。後続のRAII wrapperへ引き渡す。
	const HANDLE rawFile = CreateFileW( filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
									   OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr) ;
	// UTF-8 XMLを開けなければ読み込みを中止する。
	if( rawFile == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const auto closeFile = []( void *const handle) noexcept {
		// 無効な値を解放APIへ渡さず、保持している有効なresourceの後始末を行う。
		if( handle != nullptr) {
			CloseHandle( handle) ;
		}
	} ; // Scope終了時に読取りhandleを一度だけ閉じるdeleter。
	const std::unique_ptr<void, decltype( closeFile)> file( rawFile, closeFile) ;	// 所有handle。
	std::vector<char> buffer( static_cast<std::size_t>( bytes)) ;					// UTF-8 byte buffer。
	DWORD			  read{} ;														// ReadFile結果byte数。
	// UTF-8 XML読込み失敗を元の診断値で返す。
	if( ReadFile( file.get(), buffer.data(), static_cast<DWORD>( bytes), &read, nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 宣言sizeまで読み切れないUTF-8 XMLを拒否する。
	if( read != bytes) {
		return nativeErrorFromWin32( ERROR_HANDLE_EOF) ;
	}

	std::size_t offset{} ;	// 任意UTF-8 BOMを除いた先頭byte位置。
	// 先頭にあるUTF-8 BOMだけを変換対象から除く。
	if( buffer.size() >= 3 && static_cast<unsigned char>( buffer[0]) == 0xefU &&
	   static_cast<unsigned char>( buffer[1]) == 0xbbU &&
	   static_cast<unsigned char>( buffer[2]) == 0xbfU) {
		offset = 3 ;
	}

	// BOM後にXML開始文字がなければ別形式の入力として拒否する。
	if( offset >= buffer.size() || buffer[offset] != '<') {
		return nativeErrorFromWin32( ERROR_NO_UNICODE_TRANSLATION) ;
	}

	const int inputCharacters = static_cast<int>( buffer.size() - offset) ;	// 変換対象byte数。
	// 厳密UTF-8変換に必要なUTF-16文字数。0は変換失敗。
	const int required = MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, buffer.data() + offset,
											 inputCharacters, nullptr, 0) ;
	// UTF-8変換の必要文字数を取得できなければ診断値を返す。
	if( required <= 0) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	std::wstring decoded( static_cast<std::size_t>( required), L'\0') ;	// UTF-16変換先。
	// 確保済み出力へ実際に変換できたUTF-16文字数。要求長と照合する。
	const int converted = MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, buffer.data() + offset,
											  inputCharacters, decoded.data(), required) ;
	// 変換長不一致、空本文、XML開始不正、埋込NULを拒否する。
	if( converted != required || decoded.empty() || decoded.front() != L'<' ||
	   decoded.find( L'\0') != std::wstring::npos) {
		return nativeErrorFromWin32( ERROR_NO_UNICODE_TRANSLATION) ;
	}

	xml = std::move( decoded) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_catalog_validation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError loadOfficialXmlDocument(
	const std::wstring_view xmlUtf16, const OfficialXmlPolicy &policy,
	Microsoft::WRL::ComPtr<IXMLDOMDocument2> &document)
{
	document.Reset() ;
	// XML本文、文字数上限、namespace設定の長さとNULを事前検証する。
	if( policy.maximumCharacters == 0 ||
	   policy.maximumCharacters > static_cast<std::size_t>( std::numeric_limits<UINT>::max()) ||
	   policy.selectionNamespaces.size() > MAXIMUM_SELECTION_NAMESPACE_CHARACTERS ||
	   xmlUtf16.empty() || xmlUtf16.size() > policy.maximumCharacters ||
	   xmlUtf16.find( L'\0') != std::wstring_view::npos ||
	   policy.selectionNamespaces.find( L'\0') != std::wstring_view::npos) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	constexpr std::size_t CHARACTERS_PER_XML_SIZE_UNIT = 1024 ;	// MaxXMLSizeの文字block数。
	const std::size_t	  xmlSizeUnits				   =		// 入力上限を1024文字単位へ切上げた値。
		(policy.maximumCharacters + CHARACTERS_PER_XML_SIZE_UNIT - 1) /
		CHARACTERS_PER_XML_SIZE_UNIT ;
	constexpr std::size_t MAXIMUM_XML_SIZE_UNITS = 4'194'303 ;	// MSXML 6.0設定上限。
	// MSXMLのsize単位と設定値の整数範囲に収まることを要求する。
	if( xmlSizeUnits == 0 || xmlSizeUnits > MAXIMUM_XML_SIZE_UNITS ||
	   xmlSizeUnits > static_cast<std::size_t>( std::numeric_limits<std::int32_t>::max())) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	Microsoft::WRL::ComPtr<IXMLDOMDocument2> created ;	// 設定完了後に出力へ移すDOM。
	HRESULT result = CoCreateInstance( CLSID_DOMDocument60, nullptr, CLSCTX_INPROC_SERVER,
									  // DOM生成結果。
									  IID_PPV_ARGS( &created)) ;
	// DOM作成に失敗した場合はXMLを解析しない。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	result = created->put_async( VARIANT_FALSE) ;
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = created->put_validateOnParse( VARIANT_FALSE) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = created->put_resolveExternals( VARIANT_FALSE) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = setBooleanProperty( *created.Get(), L"ProhibitDTD", true) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = setBooleanProperty( *created.Get(), L"UseInlineSchema", false) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = setIntegerProperty( *created.Get(), L"MaxElementDepth", MAXIMUM_XML_ELEMENT_DEPTH) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = setIntegerProperty( *created.Get(), L"MaxXMLSize",
									static_cast<std::int32_t>( xmlSizeUnits)) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( SUCCEEDED( result)) {
		result = setStringProperty( *created.Get(), L"SelectionLanguage", L"XPath") ;
	}

	// 先行設定が成功しnamespace指定がある場合だけ選択用namespaceを設定する。
	if( SUCCEEDED( result) && !policy.selectionNamespaces.empty()) {
		result =
			setStringProperty( *created.Get(), L"SelectionNamespaces", policy.selectionNamespaces) ;
	}

	// 安全設定に失敗したDOMへXMLを読み込まない。
	if( FAILED( result)) {
		return nativeError( result) ;
	}

	UniqueBstr xml( xmlUtf16) ;	// loadXML呼出し中だけ所有する入力BSTR。
	// XML用BSTRを確保できなければmemory不足を返す。
	if( xml.get() == nullptr) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	VARIANT_BOOL loaded{} ;	// Well-formedかつsecurity policy内ならVARIANT_TRUE。
	result = created->loadXML( xml.get(), &loaded) ;
	// API失敗またはload結果不成功ならDOMを公開しない。
	if( FAILED( result) || loaded != VARIANT_TRUE) {
		return nativeError( FAILED( result) ? result : E_FAIL) ;
	}

	document = std::move( created) ;
	return 0 ;
}

} // namespace drivercrate
