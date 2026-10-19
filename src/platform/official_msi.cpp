//------------------------------------------------------------------------------
/**
 * @file official_msi.cpp
 * @brief 公式MSI stream取得・cabinet mapping実装。
 * @version 01.00.00
 * @date 2026/09/06
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Read-only MSI stream取得境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Media／File mapping照会を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 入力MSIのsizeとSHA-256を処理前後に確認し、parameter queryで選択したstream保存とMedia／File mapping照会だけを行います。失敗時は部分
 *       出力を破棄し、MSIやcustom actionを実行しません。
 */
//------------------------------------------------------------------------------

#include "platform/official_msi.h"

#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"

#include <Msi.h>
#include <MsiQuery.h>
#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t	MAXIMUM_STREAM_NAME_CHARACTERS	   = 62U ;				// MSI仕様上のstream名上限。
constexpr std::size_t	MAXIMUM_MEDIA_CABINET_CHARACTERS   = 255U ;				// `Media.Cabinet` data型上限。
constexpr std::size_t	MAXIMUM_FILE_IDENTIFIER_CHARACTERS = 72U ;				// `File` primary key上限。
constexpr std::size_t	MAXIMUM_FILE_NAME_CHARACTERS	   = 255U ;				// `FileName` data型上限。
constexpr std::uint32_t MAXIMUM_READ_BUFFER_BYTES		   = 1024U * 1024U ;	// 一回の読取り上限。
constexpr std::uint32_t MAXIMUM_FILE_TABLE_ROWS			   = 32767U ;			// MSI標準のFile row上限。
constexpr wchar_t		STREAM_QUERY[] =
	L"SELECT `Name`, `Data` FROM `_Streams` WHERE `Name` = ?" ;	// 固定SELECT文。
// MediaをDiskId順に列挙する固定SELECT文。
constexpr wchar_t MEDIA_QUERY[] =
	L"SELECT `DiskId`, `LastSequence`, `Cabinet` FROM `Media` ORDER BY `DiskId`" ;
// 一つのMedia sequence範囲だけを取得する固定parameter SELECT文。
constexpr wchar_t FILE_QUERY[] = L"SELECT `File`, `FileName`, `FileSize`, `Sequence` FROM `File` "
								 L"WHERE `Sequence` > ? AND `Sequence` <= ? ORDER BY `Sequence`" ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 元の診断値をProvider共通結果へ保持する。
 *
 * @param[in] error Windows Installerまたはfile APIのerror code。
 * @return HRESULT_FROM_WIN32で変換したbit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Localeに依存せず「.msi」拡張子を比較する。
 *
 * @param[in] character MSI拡張子を構成するASCII文字。
 * @return `A`～`Z`は小文字、それ以外は入力値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] wchar_t asciiLower( const wchar_t character) noexcept
{
	return character >= L'A' && character <= L'Z' ? static_cast<wchar_t>( character - L'A' + L'a')
												  : character ;
}

//------------------------------------------------------------------------------
/**
 * @brief CWD依存、UNC、device path、埋込みnull、別形式を拒否する。
 *
 * @param[in] path Windows Installerへ渡す入力path。
 * @return Local drive上の絶対「.msi」 pathなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isLocalAbsoluteMsiPath( const std::wstring_view path) noexcept
{
	// Drive 絶対 path でない入力と埋込み NUL を持つ MSI path を拒否する。
	if( path.size() < 7U || path[1] != L':' || path[2] != L'\\' ||
	   path.find( L'\0') != std::wstring_view::npos) {
		return false ;
	}

	const wchar_t drive = path.front() ;	// ASCII drive letter候補。
	// Drive 文字が ASCII 英字でない path を拒否する。
	if( !((drive >= L'A' && drive <= L'Z') || (drive >= L'a' && drive <= L'z'))) {
		return false ;
	}

	constexpr std::wstring_view EXTENSION = L".msi" ;									// 許可する入力拡張子。
	const std::wstring_view extension = path.substr( path.size() - EXTENSION.size()) ;	// 末尾拡張子。
	// indexは現在比較する`.msi`拡張子内の文字位置。
	// Extension全桁をASCII小文字へ正規化して比較する。
	for( std::size_t index = 0U; index < EXTENSION.size(); ++index) {
		// 大文字小文字を無視して MSI 拡張子と一致しない対象を拒否する。
		if( asciiLower( extension[index]) != EXTENSION[index]) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Parameter queryでも不要な制御文字やpath表現を受理しない。
 *
 * @param[in] value Providerが固定した選択stream名。
 * @return 1～62文字の許可ASCIIだけなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafeStreamName( const std::wstring_view value) noexcept
{
	// 空または上限を超える stream 名は query parameter に渡さない。
	if( value.empty() || value.size() > MAXIMUM_STREAM_NAME_CHARACTERS) {
		return false ;
	}

	// characterは現在検証するstream名内の一文字。
	// 全文字を検証し、固定識別に不要なUnicode、quote、separatorを拒否する。
	for( const wchar_t character : value) {
		const bool uppercase = character >= L'A' && character <= L'Z' ;	// ASCII大文字。
		const bool lowercase = character >= L'a' && character <= L'z' ;	// ASCII小文字。
		const bool digit	 = character >= L'0' && character <= L'9' ;	// ASCII数字。
		const bool punctuation =
			// 許可記号。
			character == L'.' || character == L'-' || character == L'_' ;
		// Stream 名に許可しない文字があれば parameter query でも拒否する。
		if( !uppercase && !lowercase && !digit && !punctuation) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Reparse pointをWindows Installerへ渡さず、hashまで確認する。
 *
 * @param[in] path 入力MSIのlocal絶対path。
 * @param[in] expectedSize 外側展開時に固定したMSI byte数。
 * @param[in] expectedSha256 外側展開時に固定したMSI SHA-256。
 * @param[in] maximumDatabaseBytes MSI全体へ適用する有限上限。
 * @return 通常MSIとidentityが全て一致する場合は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateDatabaseFile( const std::wstring_view path,
											   const std::uint64_t	   expectedSize,
											   const std::wstring_view expectedSha256,
											   const std::uint64_t	   maximumDatabaseBytes)
{
	// MSI 絶対 path、期待 size、期待 hash の検証根拠が不正なら中止する。
	if( !isLocalAbsoluteMsiPath( path) || expectedSize == 0U || expectedSize > maximumDatabaseBytes ||
	   expectedSha256.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring		  terminatedPath( path) ;	// Win32 API用のnull終端path。
	WIN32_FILE_ATTRIBUTE_DATA attributes{} ;			// 入力fileの属性と64-bit size。
	// Database の属性を取得できなければ Windows Installer へ渡さない。
	if( GetFileAttributesExW( terminatedPath.c_str(), GetFileExInfoStandard, &attributes) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	constexpr DWORD REJECTED_ATTRIBUTES =
		FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT ;	// MSIで拒否する属性。
	// Reparse point 等の禁止属性を持つ database は拒否する。
	if( (attributes.dwFileAttributes & REJECTED_ATTRIBUTES) != 0U) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	ULARGE_INTEGER actualSize{} ;	// HighとLowを結合した入力file byte数。
	actualSize.LowPart	= attributes.nFileSizeLow ;
	actualSize.HighPart = attributes.nFileSizeHigh ;
	// 空または許可上限を超える database は内容を照会しない。
	if( actualSize.QuadPart == 0U || actualSize.QuadPart > maximumDatabaseBytes) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	return verifyOfficialFileMetadata(
		path, {.expectedSize = expectedSize, .expectedSha256 = expectedSha256}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows Installerへ固定上限bufferだけを渡し、切詰めを拒否する。
 *
 * @param[in] record 読取り対象のMSI record handle。
 * @param[in] field 1から始まる文字列field番号。
 * @param[in] maximumCharacters 終端nullを除く文字数上限。
 * @param[in] allowNull null fieldを空文字列として許可する場合true。
 * @param[out] value 成功時の文字列。失敗時は空。
 * @return 上限内のfield取得成功時は0、nullまたはAPI失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRecordString( const MSIHANDLE record, const UINT field,
										   const std::size_t maximumCharacters,
										   const bool allowNull, std::wstring &value)
{
	value.clear() ;
	// 無効な record・field と buffer 長の範囲外を API 呼出し前に拒否する。
	if( record == 0U || field == 0U || maximumCharacters == 0U ||
	   maximumCharacters >= std::numeric_limits<DWORD>::max()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// NULL field は呼出し側が明示して許可した場合だけ空値として受理する。
	if( MsiRecordIsNull( record, field) != FALSE) {
		return allowNull ? 0 : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	try {
		std::vector<wchar_t> buffer( maximumCharacters + 1U) ;			// 終端nullを含む固定上限受信域。
		DWORD	   characters = static_cast<DWORD>( buffer.size()) ;	// 入力容量と出力文字数。
		const UINT result =
			// Field取得結果。
			MsiRecordGetStringW( record, field, buffer.data(), &characters) ;
		// 文字列取得の失敗と上限超過を拒否し、切詰め値を返さない。
		if( result != ERROR_SUCCESS || characters > maximumCharacters) {
			return nativeErrorFromWin32( result == ERROR_SUCCESS ? ERROR_INVALID_DATA : result) ;
		}

		value.assign( buffer.data(), characters) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Path、空要素、制御文字、Windowsで末尾が曖昧な名前を拒否する。
 *
 * @param[in] value CAB entryまたは論理file名候補。
 * @param[in] maximumCharacters 対象field仕様の文字数上限。
 * @return 有限ASCII一要素として安全な場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafeMsiFileComponent( const std::wstring_view value,
										  const std::size_t		  maximumCharacters) noexcept
{
	// 空、長さ超過、dot 要素、末尾 dot を持つ曖昧な file 名は拒否する。
	if( value.empty() || value.size() > maximumCharacters || value == L"." || value == L".." ||
	   value.back() == L'.') {
		return false ;
	}

	// characterは現在検証するMSI file名の一文字。
	// WinOF-2実物に必要なASCII英数字と限定記号だけを全桁検証する。
	for( const wchar_t character : value) {
		const bool uppercase = character >= L'A' && character <= L'Z' ;	// ASCII大文字。
		const bool lowercase = character >= L'a' && character <= L'z' ;	// ASCII小文字。
		const bool digit	 = character >= L'0' && character <= L'9' ;	// ASCII数字。
		const bool punctuation =
			// 許可記号。
			character == L'.' || character == L'-' || character == L'_' ;
		// 許可した file 名文字以外を含む要素は path として使用しない。
		if( !uppercase && !lowercase && !digit && !punctuation) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief CAB primary keyからINFが参照する論理名への対応を確定する。
 *
 * @param[in] value `short|long`または単独名のFileName field。
 * @param[out] fileName 成功時の安全なlong name。
 * @return 一意で安全なlong name取得時は0、不正形式はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError parseMsiFileName( const std::wstring_view value, std::wstring &fileName)
{
	fileName.clear() ;
	const std::size_t separator = value.find( L'|') ;	// Short nameとlong nameの区切り位置。
	// 短名と長名の区切りが複数ある FileName は曖昧な形式として拒否する。
	if( separator != std::wstring_view::npos &&
	   value.find( L'|', separator + 1U) != std::wstring_view::npos) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const std::wstring_view selected =
		// 論理名。
		separator == std::wstring_view::npos ? value : value.substr( separator + 1U) ;
	// 選択した論理 file 名が安全な単一要素でなければ拒否する。
	if( !isSafeMsiFileComponent( selected, MAXIMUM_FILE_NAME_CHARACTERS)) {
		return nativeErrorFromWin32( ERROR_INVALID_NAME) ;
	}

	try {
		fileName.assign( selected) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Windows上で同じ出力になるprimary key重複を検出する。
 *
 * @param[in] left 比較する一方のMSIまたはCAB file名。
 * @param[in] right 比較する他方のMSIまたはCAB file名。
 * @return 大文字小文字を無視して完全一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool fileNamesEqual( const std::wstring_view left,
								  const std::wstring_view right) noexcept
{
	// 比較 API の文字数範囲を超える名前は一致と扱わない。
	if( left.size() > static_cast<std::size_t>( std::numeric_limits<int>::max()) ||
	   right.size() > static_cast<std::size_t>( std::numeric_limits<int>::max())) {
		return false ;
	}

	return CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全Media rowを順に検証し、前rowのLastSequenceから範囲を作る。
 *
 * @param[in] database Read-onlyで開いたMSI database handle。
 * @param[in] streamName `#`なしの固定embedded cabinet名。
 * @param[out] firstSequence 成功時の最初のFile.Sequence。
 * @param[out] lastSequence 成功時の最後のFile.Sequence。
 * @return 一つのMedia rowへ完全一致した場合は0、拒否時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectCabinetMediaRange( const MSIHANDLE		   database,
												   const std::wstring_view streamName,
												   std::uint32_t		  &firstSequence,
												   std::uint32_t		  &lastSequence)
{
	firstSequence = 0U ;
	lastSequence  = 0U ;
	std::wstring expectedCabinet( L"#") ;	// Media.Cabinetへ完全一致させる値。
	expectedCabinet.append( streamName) ;
	PMSIHANDLE view ;															// Media tableの固定SELECTを所有するview handle。
	UINT	   result = MsiDatabaseOpenViewW( database, MEDIA_QUERY, &view) ;	// View作成結果。
	// Win32の失敗原因を共通診断値に変換して返し、エラーを失わずに後続処理を止める。
	if( result != ERROR_SUCCESS) {
		return nativeErrorFromWin32( result) ;
	}

	result = MsiViewExecute( view, 0U) ;
	// Win32の失敗原因を共通診断値に変換して返し、エラーを失わずに後続処理を止める。
	if( result != ERROR_SUCCESS) {
		return nativeErrorFromWin32( result) ;
	}

	int	 previousDiskId{} ;			// DiskId昇順を確認する直前rowの値。
	int	 previousLastSequence{} ;	// 現在mediaの先頭を決める直前row終端。
	bool found{} ;					// 固定cabinetを一件取得済みの場合true。
	// 全Media rowを有限なdatabase result順に読み、重複cabinetと逆行を拒否する。
	while( true) {
		PMSIHANDLE record ;	// 現在Media rowを所有するrecord handle。
		result = MsiViewFetch( view, &record) ;
		// Media row の列挙終端を正常な loop 終了として扱う。
		if( result == ERROR_NO_MORE_ITEMS) {
			break ;
		}

		// Win32の失敗原因を共通診断値に変換して返し、エラーを失わずに後続処理を止める。
		if( result != ERROR_SUCCESS) {
			return nativeErrorFromWin32( result) ;
		}

		const int diskId			  = MsiRecordGetInteger( record, 1U) ;	// 現在rowのDiskId。
		const int currentLastSequence = MsiRecordGetInteger( record, 2U) ;	// 現在rowのLastSequence。
		// NULL、負の sequence、順序逆転を持つ Media row は拒否する。
		if( diskId == MSI_NULL_INTEGER || currentLastSequence == MSI_NULL_INTEGER ||
		   diskId <= previousDiskId || currentLastSequence < previousLastSequence ||
		   currentLastSequence < 0) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		std::wstring	  cabinet ;	// Nullを空として受ける現在rowのCabinet値。
		const NativeError stringError =
			readRecordString( record, 3U, MAXIMUM_MEDIA_CABINET_CHARACTERS, true,
							 cabinet) ;	// Cabinet文字列取得結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( stringError != 0) {
			return stringError ;
		}

		// 要求した CAB の row だけから対象 File sequence 範囲を確定する。
		if( cabinet == expectedCabinet) {
			// 対象 CAB の重複と空の sequence 範囲は一意に解決できないため拒否する。
			if( found || currentLastSequence <= previousLastSequence) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			firstSequence = static_cast<std::uint32_t>( previousLastSequence + 1) ;
			lastSequence  = static_cast<std::uint32_t>( currentLastSequence) ;
			found		  = true ;
		}

		previousDiskId		 = diskId ;
		previousLastSequence = currentLastSequence ;
	}

	result = MsiViewClose( view) ;
	// Win32の失敗原因を共通診断値に変換して返し、エラーを失わずに後続処理を止める。
	if( result != ERROR_SUCCESS) {
		return nativeErrorFromWin32( result) ;
	}

	return found ? 0 : nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
}

//------------------------------------------------------------------------------
/**
 * @brief File primary keyをCAB名、FileNameのlong nameを論理名にする。
 *
 * @param[in] database Read-onlyで開いたMSI database handle。
 * @param[in] firstSequence Mediaが示す最初のFile.Sequence。
 * @param[in] lastSequence Mediaが示す最後のFile.Sequence。
 * @param[in] policy 一file sizeとrow件数の有限上限。
 * @param[out] files 成功時のSequence昇順mapping。
 * @return 全rowの名前、size、順序、一意性検証成功時は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectCabinetFileRows( const MSIHANDLE	 database,
												 const std::uint32_t firstSequence,
												 const std::uint32_t lastSequence,
												 const OfficialMsiCabinetInventoryPolicy  &policy,
												 std::vector<OfficialMsiCabinetFileEntry> &files)
{
	files.clear() ;
	// File tableの固定範囲SELECTを所有するview handle。
	PMSIHANDLE view ;
	UINT	   result = MsiDatabaseOpenViewW( database, FILE_QUERY, &view) ;	// View作成結果。
	// Win32の失敗原因を共通診断値に変換して返し、エラーを失わずに後続処理を止める。
	if( result != ERROR_SUCCESS) {
		return nativeErrorFromWin32( result) ;
	}

	PMSIHANDLE parameters( MsiCreateRecord( 2U)) ;	// Sequence下限と上限を持つparameter record。
	// Query parameter record を確保できなければ照会を開始しない。
	if( parameters == 0U) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	result = MsiRecordSetInteger( parameters, 1U, static_cast<int>( firstSequence - 1U)) ;
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiRecordSetInteger( parameters, 2U, static_cast<int>( lastSequence)) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiViewExecute( view, parameters) ;
	}

	// Win32の失敗原因を共通診断値に変換して返し、エラーを失わずに後続処理を止める。
	if( result != ERROR_SUCCESS) {
		return nativeErrorFromWin32( result) ;
	}

	files.reserve( policy.maximumFileCount) ;
	std::uint32_t previousSequence = firstSequence - 1U ;	// 直前rowのSequence。
	// 対象Media範囲の全File rowを読み、途中結果を公開せずmappingを構築する。
	while( true) {
		PMSIHANDLE record ;	// 現在File rowを所有するrecord handle。
		result = MsiViewFetch( view, &record) ;
		// 対象 File row を全て読み終えた時点で列挙を終了する。
		if( result == ERROR_NO_MORE_ITEMS) {
			break ;
		}

		// File row 取得の失敗時は途中までの一覧を破棄する。
		if( result != ERROR_SUCCESS) {
			files.clear() ;
			return nativeErrorFromWin32( result) ;
		}

		// 許可 file 件数を超えた場合は部分一覧を残さず拒否する。
		if( files.size() >= policy.maximumFileCount) {
			files.clear() ;
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		std::wstring cabinetName ;	// `File` primary keyから得るCAB entry名。
		NativeError	 error = readRecordString( record, 1U, MAXIMUM_FILE_IDENTIFIER_CHARACTERS, false,
											  cabinetName) ;	// Primary key取得結果。
		std::wstring rawFileName ;								// Short／long表現を含む元のFileName field。
		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = readRecordString( record, 2U, MAXIMUM_FILE_NAME_CHARACTERS, false, rawFileName) ;
		}

		std::wstring targetName ;	// INFが参照する安全なlong file名。
		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = parseMsiFileName( rawFileName, targetName) ;
		}

		const int  rawFileSize = MsiRecordGetInteger( record, 3U) ;	// FileSize field。
		const int  rawSequence = MsiRecordGetInteger( record, 4U) ;	// Sequence field。
		const bool duplicate   =									// Windows上で同一となるCAB primary keyが存在する状態。
			std::ranges::any_of( files, [&cabinetName]( const OfficialMsiCabinetFileEntry &entry) {
				return fileNamesEqual( entry.cabinetRelativePath, cabinetName) ;
			}) ;
		// 取得 error、名前・size・sequence の不正、重複を拒否して一覧を破棄する。
		if( error != 0 || !isSafeMsiFileComponent( cabinetName, MAXIMUM_FILE_IDENTIFIER_CHARACTERS) ||
		   rawFileSize == MSI_NULL_INTEGER || rawFileSize < 0 ||
		   static_cast<std::uint64_t>( rawFileSize) > policy.maximumSingleFileBytes ||
		   rawSequence == MSI_NULL_INTEGER || rawSequence <= 0 ||
		   static_cast<std::uint32_t>( rawSequence) < firstSequence ||
		   static_cast<std::uint32_t>( rawSequence) > lastSequence ||
		   static_cast<std::uint32_t>( rawSequence) <= previousSequence || duplicate) {
			files.clear() ;
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		files.push_back( OfficialMsiCabinetFileEntry{std::move( cabinetName), std::move( targetName),
													static_cast<std::uint64_t>( rawFileSize),
													static_cast<std::uint32_t>( rawSequence)}) ;
		previousSequence = static_cast<std::uint32_t>( rawSequence) ;
	}

	result = MsiViewClose( view) ;
	// 照会終了に失敗した場合と対象 file がない場合は有効な対応表を返さない。
	if( result != ERROR_SUCCESS || files.empty()) {
		files.clear() ;
		return nativeErrorFromWin32( result == ERROR_SUCCESS ? ERROR_INVALID_DATA : result) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 短い書込みでも残量が0になるまで同じbufferを前方へ進める。
 *
 * @param[in] file Workspaceが所有する書込み可能file handle。
 * @param[in] content MSI APIが返した今回のstream内容。
 * @return 全byte書込み成功時は0、無効handleまたは失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError writeComplete( const HANDLE				file,
										const std::span<const char> content) noexcept
{
	// 無効な出力 handle では stream の書込みを受理しない。
	if( file == nullptr || file == INVALID_HANDLE_VALUE) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::size_t offset{} ;	// 次に保存するcontent内のbyte位置。
	// WriteFileのDWORD範囲内で、今回受信した全byteを順に保存する。
	while( offset < content.size()) {
		const DWORD requested = static_cast<DWORD>( std::min<std::size_t>(
			// 今回の要求長。
			content.size() - offset, std::numeric_limits<DWORD>::max())) ;
		DWORD		written{} ;	// 今回WriteFileが保存したbyte数。
		// 書込み失敗または進捗停止を検出したら無限反復せず中止する。
		if( WriteFile( file, content.data() + offset, requested, &written, nullptr) == FALSE ||
		   written == 0U) {
			DWORD error = GetLastError() ;	// WriteFileが設定した診断値。
			// 書込み停止に診断値がない場合も成功にせず書込み失敗へ変換する。
			if( error == ERROR_SUCCESS) {
				error = ERROR_WRITE_FAULT ;
			}

			return nativeErrorFromWin32( error) ;
		}

		offset += written ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 短いstream、停滞、宣言長を越えるdataをfail-closedで拒否する。
 *
 * @param[in] record 選択済み`Name`、`Data`を持つrecord handle。
 * @param[in] expectedSize `MsiRecordDataSize`が返したbyte数。
 * @param[in,out] buffer 一回の読取りに再利用する有限buffer。
 * @param[in] output Workspaceが所有する書込みfile handle。
 * @return 宣言長、EOF、完全書込みが一致する場合は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readRecordStream( const MSIHANDLE record, const std::uint64_t expectedSize,
										   const std::span<char> buffer,
										   const HANDLE			 output) noexcept
{
	// Record、宣言長、作業 buffer、出力 handle の不備を読取り前に拒否する。
	if( record == 0U || expectedSize == 0U || buffer.empty() || output == nullptr ||
	   output == INVALID_HANDLE_VALUE) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::uint64_t processed{} ;	// Fileへ完全保存済みのstream byte数。
	// 宣言長を上限として前方へ進み、待ち時間だけで進捗を増やさない。
	while( processed < expectedSize) {
		const std::uint64_t remaining = expectedSize - processed ;	// 未読の宣言byte数。
		const DWORD			requested = static_cast<DWORD>(
			std::min<std::uint64_t>( remaining, buffer.size())) ;	// 今回の有限要求長。
		DWORD	   transferred = requested ;						// 入力はbuffer長、出力は実際の読取りbyte数。
		const UINT result =
			// Stream読取り結果。
			MsiRecordReadStream( record, 2U, buffer.data(), &transferred) ;
		// Win32の失敗原因を共通診断値に変換して返し、エラーを失わずに後続処理を止める。
		if( result != ERROR_SUCCESS) {
			return nativeErrorFromWin32( result) ;
		}

		// 停滞または要求量・残量を超える読取りは不正 stream として拒否する。
		if( transferred == 0U || transferred > requested || transferred > remaining) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const NativeError writeError =
			// 保存結果。
			writeComplete( output, std::span<const char>( buffer.data(), transferred)) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( writeError != 0) {
			return writeError ;
		}

		processed += transferred ;
		// 短い読取りが宣言長の完了前に起きた場合は欠落として拒否する。
		if( transferred < requested && processed != expectedSize) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}
	}

	std::array<char, 1> trailing{} ;									// 宣言長直後に余剰dataがないことを確認する一byte buffer。
	DWORD	   trailingSize = static_cast<DWORD>( trailing.size()) ;	// EOF probeの入出力byte数。
	const UINT trailingResult =
		// EOF確認結果。
		MsiRecordReadStream( record, 2U, trailing.data(), &trailingSize) ;
	return trailingResult == ERROR_SUCCESS && trailingSize == 0U
			   ? 0
			   : nativeErrorFromWin32( trailingResult == ERROR_SUCCESS ? ERROR_INVALID_DATA
																	  : trailingResult) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既存fileへ触れず、破棄失敗時はworkspace destructorへ委ねる。
 *
 * @param[in] error 呼出側へ保持する最初の失敗診断値。
 * @param[in,out] workspace 今回作成したfileを追跡する保護領域。
 * @param[in] relativePath 今回作成した出力の相対path。
 * @param[out] entry 公開してはならない部分結果。
 * @return Cleanup結果で上書きしない最初の失敗診断値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError discardFailedOutput( const NativeError			 error,
											  OfficialDownloadWorkspace &workspace,
											  const std::wstring_view	 relativePath,
											  OfficialMsiStreamEntry	&entry) noexcept
{
	entry = {} ;
	try {
		static_cast<void>( workspace.discardFile( relativePath)) ;
	} catch( const std::bad_alloc &) {
		// Path処理のmemory不足時も一次errorを維持し、destructorの既知file回収へ委ねる。
	}

	return error ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_msi.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError extractOfficialMsiStream( const OfficialMsiStreamExtractionRequest &request,
									 const OfficialMsiStreamExtractionPolicy  &policy,
									 OfficialDownloadWorkspace				  &workspace,
									 OfficialMsiStreamEntry					  &entry)
{
	entry = {} ;
	bool outputCreated{} ;	// trueの場合は例外時に今回の出力を破棄する。
	try {
		// 取得上限と database・stream・保存先の検証条件が揃わない要求を拒否する。
		if( policy.maximumDatabaseBytes == 0U || policy.maximumStreamBytes == 0U ||
		   policy.readBufferBytes == 0U || policy.readBufferBytes > MAXIMUM_READ_BUFFER_BYTES ||
		   !isLocalAbsoluteMsiPath( request.databasePath) || request.expectedDatabaseSize == 0U ||
		   request.expectedDatabaseSize > policy.maximumDatabaseBytes ||
		   request.expectedDatabaseSha256.empty() || !isSafeStreamName( request.streamName) ||
		   request.outputRelativePath.empty()) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		const std::wstring lockedDatabasePath( request.databasePath) ;	// Lock用null終端MSI path。
		const HANDLE	   rawDatabaseGuard =
			CreateFileW( lockedDatabasePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
						OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT,
						nullptr) ;	// 処理中の置換と変更を拒否する所有handle。
		// Database 保護用 handle を開けなければ query を開始しない。
		if( rawDatabaseGuard == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		const auto closeDatabaseGuard = []( void *const handle) noexcept {
			// 無効な値を解放APIへ渡さず、保持している有効なresourceの後始末を行う。
			if( handle != nullptr && handle != INVALID_HANDLE_VALUE) {
				CloseHandle( handle) ;
			}
		} ; // 全終了経路でidentity固定handleを閉じるdeleter。
		const std::unique_ptr<void, decltype( closeDatabaseGuard)> databaseGuard(
			rawDatabaseGuard, closeDatabaseGuard) ;	// MSI処理中のidentity固定handle所有者。
		FILE_ATTRIBUTE_TAG_INFO databaseTag{} ;		// Handleが指すfile属性とreparse tag。
		// 開いた database の属性を確認できなければ解析を中止する。
		if( GetFileInformationByHandleEx( databaseGuard.get(), FileAttributeTagInfo, &databaseTag,
										sizeof( databaseTag)) == FALSE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		constexpr DWORD REJECTED_DATABASE_ATTRIBUTES =
			FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT ;	// Lock後も拒否する属性。
		// 禁止属性の database は読取り専用 query にも渡さない。
		if( (databaseTag.FileAttributes & REJECTED_DATABASE_ATTRIBUTES) != 0U) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		NativeError error = validateDatabaseFile(
			request.databasePath, request.expectedDatabaseSize, request.expectedDatabaseSha256,
			policy.maximumDatabaseBytes) ;	// Open前のMSI identity結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		std::uint64_t streamSize{} ;	// 選択recordが宣言したstream byte数。
		{
			const std::wstring streamName( request.streamName) ;	// Parameter用null終端stream名。
			PMSIHANDLE		   database ;							// Scope終了時に閉じるread-only MSI database handle。
			UINT msiResult = MsiOpenDatabaseW( lockedDatabasePath.c_str(), MSIDBOPEN_READONLY,
											  &database) ;	// Open結果。
			// Database を開く処理の失敗を Windows Installer の診断値で返す。
			if( msiResult != ERROR_SUCCESS) {
				return nativeErrorFromWin32( msiResult) ;
			}

			PMSIHANDLE view ;	// 固定SELECT queryの所有view handle。
			msiResult = MsiDatabaseOpenViewW( database, STREAM_QUERY, &view) ;
			// 固定 query の準備に失敗した場合は実行へ進まない。
			if( msiResult != ERROR_SUCCESS) {
				return nativeErrorFromWin32( msiResult) ;
			}

			PMSIHANDLE parameter( MsiCreateRecord( 1U)) ;	// Stream名一件だけを持つparameter record。
			// Stream 名用の parameter record を確保できなければ中止する。
			if( parameter == 0U) {
				return static_cast<NativeError>( E_OUTOFMEMORY) ;
			}

			msiResult = MsiRecordSetStringW( parameter, 1U, streamName.c_str()) ;
			// Query parameter の設定に失敗したら未設定のまま実行しない。
			if( msiResult != ERROR_SUCCESS) {
				return nativeErrorFromWin32( msiResult) ;
			}

			msiResult = MsiViewExecute( view, parameter) ;
			// Parameter query の実行失敗をそのまま返す。
			if( msiResult != ERROR_SUCCESS) {
				return nativeErrorFromWin32( msiResult) ;
			}

			PMSIHANDLE record ;	// 一致したNameとData streamを所有するrecord handle。
			msiResult = MsiViewFetch( view, &record) ;
			// 対象 stream が見つからない場合は file 未検出として通知する。
			if( msiResult == ERROR_NO_MORE_ITEMS) {
				return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
			}

			// 対象 row の取得失敗を成功や未検出に混同しない。
			if( msiResult != ERROR_SUCCESS) {
				return nativeErrorFromWin32( msiResult) ;
			}

			std::array<wchar_t, MAXIMUM_STREAM_NAME_CHARACTERS + 1U> actualName{} ;	// Name受信域。
			DWORD													 actualNameCharacters =
				// 入力容量、出力文字数。
				static_cast<DWORD>( actualName.size()) ;
			msiResult = MsiRecordGetStringW( record, 1U, actualName.data(), &actualNameCharacters) ;
			// 実 stream 名を上限内で取得できなければ照合を中止する。
			if( msiResult != ERROR_SUCCESS ||
			   actualNameCharacters > MAXIMUM_STREAM_NAME_CHARACTERS) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			const std::wstring_view actualNameView(
				// 実際に返されたstream名。
				actualName.data(), actualNameCharacters) ;
			// 要求と異なる stream 名および NULL data field を拒否する。
			if( actualNameView != request.streamName || MsiRecordIsNull( record, 2U) != FALSE) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// MSIが宣言するbinary stream長。
			streamSize = MsiRecordDataSize( record, 2U) ;
			// 空の stream は有効な埋込み CAB として扱わない。
			if( streamSize == 0U) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// Stream の宣言長が policy 上限を超える場合は展開しない。
			if( streamSize > policy.maximumStreamBytes) {
				return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
			}

			std::uint64_t availableBytes{} ;	// Workspace volumeでprocessが利用可能なbyte数。
			error = workspace.queryAvailableBytes( availableBytes) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}

			// 保存先の空き領域が stream 長未満の場合は出力作成を中止する。
			if( availableBytes < streamSize) {
				return nativeErrorFromWin32( ERROR_DISK_FULL) ;
			}

			std::vector<char> buffer( policy.readBufferBytes) ;	// MSI読取りで再利用する有限buffer。
			HANDLE			  rawOutput{INVALID_HANDLE_VALUE} ;	// Workspaceが返す所有file handle。
			error = workspace.createFile( request.outputRelativePath, rawOutput) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}

			outputCreated		 = true ;
			const auto closeFile = []( void *const handle) noexcept {
				// 無効な値を解放APIへ渡さず、保持している有効なresourceの後始末を行う。
				if( handle != nullptr && handle != INVALID_HANDLE_VALUE) {
					CloseHandle( handle) ;
				}
			} ; // 例外または早期終了時に出力handleを閉じるdeleter。
			std::unique_ptr<void, decltype( closeFile)> output( rawOutput,
															  closeFile) ;	// 出力handle所有者。
			const NativeError						   readError =
				// 完全取得結果。
				readRecordStream( record, streamSize, buffer, output.get()) ;
			const HANDLE closingOutput = output.release() ;									// Close結果を確認する所有handle。
			const BOOL	 closed		   = CloseHandle( closingOutput) ;						// Hash前の明示close結果。
			const DWORD	 closeError = closed != FALSE ? ERROR_SUCCESS : GetLastError() ;	// 診断値。
			// 読取りまたは close に失敗した出力は破棄し、元の失敗を優先して返す。
			if( readError != 0 || closed == FALSE) {
				return discardFailedOutput( readError != 0 ? readError
														  : nativeErrorFromWin32( closeError),
										   workspace, request.outputRelativePath, entry) ;
			}

			PMSIHANDLE duplicateRecord ;	// 固定keyに二件目がないことを確認するrecord handle。
			msiResult = MsiViewFetch( view, &duplicateRecord) ;
			// 余分な row または列挙 error があれば一意性を保証できない出力を破棄する。
			if( msiResult != ERROR_NO_MORE_ITEMS) {
				const NativeError duplicateError =
					msiResult == ERROR_SUCCESS ? nativeErrorFromWin32( ERROR_DUP_NAME)
											   : nativeErrorFromWin32( msiResult) ;	// 拒否理由。
				return discardFailedOutput( duplicateError, workspace, request.outputRelativePath,
										   entry) ;
			}

			msiResult = MsiViewClose( view) ;
			// Query の終了に失敗した場合も作成済み出力を成功結果として残さない。
			if( msiResult != ERROR_SUCCESS) {
				return discardFailedOutput( nativeErrorFromWin32( msiResult), workspace,
										   request.outputRelativePath, entry) ;
			}
		}

		error = validateDatabaseFile(
			request.databasePath, request.expectedDatabaseSize, request.expectedDatabaseSha256,
			policy.maximumDatabaseBytes) ;	// Stream取得後のMSI identity再検証結果。
		// 出力検証の失敗時は作成した file と結果 entry を取り消す。
		if( error != 0) {
			return discardFailedOutput( error, workspace, request.outputRelativePath, entry) ;
		}

		const std::wstring outputPath =
			// Hash対象のworkspace絶対path。
			workspace.path( request.outputRelativePath) ;
		// 検証済み出力 path を解決できない場合は出力を破棄する。
		if( outputPath.empty()) {
			return discardFailedOutput( static_cast<NativeError>( E_UNEXPECTED), workspace,
									   request.outputRelativePath, entry) ;
		}

		error = verifyOfficialFileMetadata(
			outputPath, {.expectedSize = streamSize, .expectedSha256 = {}}) ;	// 出力size結果。
		// 後続検証の失敗を受けた出力は利用可能な entry として残さない。
		if( error != 0) {
			return discardFailedOutput( error, workspace, request.outputRelativePath, entry) ;
		}

		std::wstring sha256 ;	// 保存済みstream全体の小文字SHA-256。
		error = computeFileSha256( outputPath, sha256) ;
		// 完了までに検出した失敗時は出力を破棄し、元の診断値を返す。
		if( error != 0) {
			return discardFailedOutput( error, workspace, request.outputRelativePath, entry) ;
		}

		OfficialMsiStreamEntry completed{std::wstring( request.streamName),
										 std::wstring( request.outputRelativePath), streamSize,
										 // 全検査済みの公開結果。
										 std::move( sha256)} ;
		entry		  = std::move( completed) ;
		outputCreated = false ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		// Memory 不足時に出力作成済みなら、部分 file も取り消す。
		if( outputCreated) {
			return discardFailedOutput( static_cast<NativeError>( E_OUTOFMEMORY), workspace,
									   request.outputRelativePath, entry) ;
		}

		entry = {} ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_msi.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError inspectOfficialMsiCabinetInventory( const OfficialMsiCabinetInventoryRequest &request,
											   const OfficialMsiCabinetInventoryPolicy	&policy,
											   OfficialMsiCabinetInventory				&inventory)
{
	inventory = {} ;
	// File table の件数・size 上限と database・stream の指定を照会前に検証する。
	if( policy.maximumDatabaseBytes == 0U || policy.maximumSingleFileBytes == 0U ||
	   policy.maximumFileCount == 0U || policy.maximumFileCount > MAXIMUM_FILE_TABLE_ROWS ||
	   !isLocalAbsoluteMsiPath( request.databasePath) || request.expectedDatabaseSize == 0U ||
	   request.expectedDatabaseSize > policy.maximumDatabaseBytes ||
	   request.expectedDatabaseSha256.empty() || !isSafeStreamName( request.streamName)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		const std::wstring databasePath( request.databasePath) ;	// LockとMSI API用の絶対path。
		const HANDLE	   rawDatabaseGuard =
			CreateFileW( databasePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
						FILE_FLAG_OPEN_REPARSE_POINT,
						nullptr) ;	// 照会中の変更と置換を拒否する所有handle。
		// Database を保護する handle が取得できなければ対応表を作成しない。
		if( rawDatabaseGuard == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		const auto closeDatabaseGuard = []( void *const handle) noexcept {
			// 無効な値を解放APIへ渡さず、保持している有効なresourceの後始末を行う。
			if( handle != nullptr && handle != INVALID_HANDLE_VALUE) {
				CloseHandle( handle) ;
			}
		} ; // 全終了経路でidentity固定handleを閉じるdeleter。
		const std::unique_ptr<void, decltype( closeDatabaseGuard)> databaseGuard(
			rawDatabaseGuard, closeDatabaseGuard) ;	// Identity固定handle所有者。
		FILE_ATTRIBUTE_TAG_INFO databaseTag{} ;		// Handleが指す属性とreparse tag。
		// 開いた database の属性を確認できなければ File table を照会しない。
		if( GetFileInformationByHandleEx( databaseGuard.get(), FileAttributeTagInfo, &databaseTag,
										sizeof( databaseTag)) == FALSE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		constexpr DWORD REJECTED_DATABASE_ATTRIBUTES =
			FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT ;	// 拒否する入力属性。
		// 禁止属性の database は File table の読取り対象にも許可しない。
		if( (databaseTag.FileAttributes & REJECTED_DATABASE_ATTRIBUTES) != 0U) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		NativeError error = validateDatabaseFile(
			request.databasePath, request.expectedDatabaseSize, request.expectedDatabaseSha256,
			policy.maximumDatabaseBytes) ;	// 照会前identity結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		OfficialMsiCabinetInventory inspected ;	// 全照会成功後だけ公開する一時結果。
		inspected.streamName = request.streamName ;
		{
			PMSIHANDLE database ;	// Scope終了時に閉じるread-only MSI database handle。
			const UINT openResult = MsiOpenDatabaseW( databasePath.c_str(), MSIDBOPEN_READONLY,
													 &database) ;	// Read-only database open結果。
			// Read-only database open の失敗を呼出し元へ返す。
			if( openResult != ERROR_SUCCESS) {
				return nativeErrorFromWin32( openResult) ;
			}

			std::uint32_t firstSequence{} ;	// Embedded cabinetの最初のFile.Sequence。
			std::uint32_t lastSequence{} ;	// Embedded cabinetの最後のFile.Sequence。
			error =
				inspectCabinetMediaRange( database, request.streamName, firstSequence, lastSequence) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}

			error = inspectCabinetFileRows( database, firstSequence, lastSequence, policy,
										   inspected.files) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}
		}
		error = validateDatabaseFile( request.databasePath, request.expectedDatabaseSize,
									 request.expectedDatabaseSha256,
									 policy.maximumDatabaseBytes) ;	// 照会後identity再検証結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		inventory = std::move( inspected) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		inventory = {} ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( const std::length_error &) {
		inventory = {} ;
		return static_cast<NativeError>( E_INVALIDARG) ;
	}
}

} // namespace drivercrate
