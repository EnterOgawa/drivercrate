//------------------------------------------------------------------------------
/**
 * @file official_validation_tests.cpp
 * @brief 公式取得元共通検証単体試験実装。
 * @version 01.01.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Catalog cache破損試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  XML／CAB共通境界試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  UTF-8 BOM XML試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  手動redirect経路試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  HTTP status保持と受理境界の試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Cache検証UTCの保持試験を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/23  SHA-512既知値・入力失敗・出力消去を検証。
 * </pre>
 *
 * @note Test用fileだけを一時作成し、HTTP requestやinstallerを実行しません。
 */
//------------------------------------------------------------------------------

#include "official_validation_tests.h"

#include "platform/com_raii.h"
#include "platform/official_catalog_cache.h"
#include "platform/official_catalog_validation.h"
#include "platform/official_file_verifier.h"
#include "platform/official_http_client.h"
#include "test_framework.h"

#include <Windows.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
/**
 * @brief HTTP応答の受理範囲と拒否statusの診断保持を検証する。
 *
 * 403と407を区別し、条件付き304、redirect、未許可statusを試す。実際のGET／POSTが使用する関数へ数値だけを入力する。
 *
 * @param[in,out] context 非通信fixtureのassertion集計先。
 */
//------------------------------------------------------------------------------
void testHttpResponseStatus( TestContext &context)
{
	constexpr std::array CONDITIONS{false, true} ;	// 条件付きGETとredirect許可の全組合せ。
	constexpr std::array<std::uint32_t, 5> REDIRECTS{301U, 302U, 303U, 307U,
													 308U} ;	// 現行で手動追跡する五status。
	constexpr std::array<std::uint32_t, 9> OTHER_RESPONSES{
		100U, 199U, 201U, 204U, 206U,
		299U, 300U, 305U, 399U} ;	// HTTPとして有効でもmetadata／payloadを受理しない応答。
	struct RejectedStatus {
		std::uint32_t status ;		// WinHTTPから受け取る数値status。
		NativeError	  expected ;	// MicrosoftのHRESULT表現と照合する期待値。
	} ;
	constexpr std::array REJECTED_STATUSES{
		RejectedStatus{403U, static_cast<NativeError>( HTTP_E_STATUS_FORBIDDEN)},
		RejectedStatus{404U, static_cast<NativeError>( HTTP_E_STATUS_NOT_FOUND)},
		RejectedStatus{407U, static_cast<NativeError>( HTTP_E_STATUS_PROXY_AUTH_REQ)},
		RejectedStatus{429U, static_cast<NativeError>( 0x801901ADU)},
		RejectedStatus{500U, static_cast<NativeError>( HTTP_E_STATUS_SERVER_ERROR)},
		RejectedStatus{503U, static_cast<NativeError>( HTTP_E_STATUS_SERVICE_UNAVAIL)},
		RejectedStatus{599U, static_cast<NativeError>( 0x80190257U)}} ;	// 種類と有効上限の拒否例。
	constexpr std::array<std::uint32_t, 5> INVALID_STATUSES{
		0U, 99U, 600U, 0x10000U + 200U,
		std::numeric_limits<std::uint32_t>::max()} ;	// 範囲外と切詰めで200に化け得る値。
	constexpr NativeError INVALID_RESPONSE = static_cast<NativeError>(
		// HTTP status不明の従来診断。
		HRESULT_FROM_WIN32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE)) ;

	// 条件付きrequestの有無を切り替え、304を無条件成功にしないことを確認する。
	for( const bool allowNotModified : CONDITIONS) {
		// GET各hopとPOST／最終payloadの計四policy条件で同じ拒否規則を確認する。
		for( const bool allowRedirects : CONDITIONS) {
			DRIVERCRATE_EXPECT( context, validateOfficialHttpResponseStatus( 200U, allowNotModified,
																		   allowRedirects) == 0) ;
			const NativeError notModified = validateOfficialHttpResponseStatus(
				304U, allowNotModified, allowRedirects) ;	// 未変更応答のpolicy別結果。
			DRIVERCRATE_EXPECT( context,
							   notModified ==
								   (allowNotModified ? 0 : static_cast<NativeError>( 0x80190130U))) ;
			// Locationを後段で検証する場合だけ五つのredirectを受理する。
			for( const std::uint32_t status : REDIRECTS) {
				const NativeError result = validateOfficialHttpResponseStatus(
					status, allowNotModified, allowRedirects) ;	// 現在statusの実際の判定。
				DRIVERCRATE_EXPECT( context, (result == 0) == allowRedirects) ;
				// redirectを許可しない条件では拒否statusがHTTP診断として保持されることを確認する。
				if( !allowRedirects) {
					// 拒否でもstatusを保持し、POSTのredirectを通信障害に置換しない。
					DRIVERCRATE_EXPECT(
						context, HRESULT_FACILITY( result) == FACILITY_HTTP &&
									 static_cast<std::uint32_t>( HRESULT_CODE( result)) == status &&
									 FAILED( result)) ;
				}
			}

			// 未許可の2xx等が成功扱いになる拡張を検出する。
			for( const std::uint32_t status : OTHER_RESPONSES) {
				const NativeError result = validateOfficialHttpResponseStatus(
					status, allowNotModified, allowRedirects) ;	// 成功へ変換してはならない応答。
				DRIVERCRATE_EXPECT( context,
								   HRESULT_FACILITY( result) == FACILITY_HTTP &&
									   static_cast<std::uint32_t>( HRESULT_CODE( result)) == status &&
									   FAILED( result)) ;
			}

			// 取得拒否、proxy認証、rate limit、server障害を違う診断値として残す。
			for( const RejectedStatus &rejected : REJECTED_STATUSES) {
				const NativeError result = validateOfficialHttpResponseStatus(
					rejected.status, allowNotModified, allowRedirects) ;	// 元statusの拒否結果。
				DRIVERCRATE_EXPECT( context, result == rejected.expected) ;
				DRIVERCRATE_EXPECT( context, result != INVALID_RESPONSE) ;
			}

			// 不正statusをHTTP由来HRESULTの下位16 bitへ切り詰めないことを確認する。
			for( const std::uint32_t status : INVALID_STATUSES) {
				DRIVERCRATE_EXPECT( context, validateOfficialHttpResponseStatus(
												status, allowNotModified, allowRedirects) ==
												INVALID_RESPONSE) ;
			}
		}
	}
}

//------------------------------------------------------------------------------
// 試験data定義。
//------------------------------------------------------------------------------

// Windows MakeCabで架空の`catalog.xml`一件を格納した95-byte CAB fixture。
constexpr auto SINGLE_XML_CAB = std::to_array<unsigned char>(
	{0x4D, 0x53, 0x43, 0x46, 0x00, 0x00, 0x00, 0x00, 0x5F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x2C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
	 0x5A, 0x04, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x0B, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x5D, 0xB5, 0x53, 0x20, 0x00, 0x63, 0x61, 0x74, 0x61,
	 0x6C, 0x6F, 0x67, 0x2E, 0x78, 0x6D, 0x6C, 0x00, 0xCB, 0x2A, 0xC5, 0x0A, 0x0F, 0x00, 0x0B, 0x00,
	 0x43, 0x4B, 0xB3, 0x71, 0x4E, 0x2C, 0x49, 0xCC, 0xC9, 0x4F, 0xD7, 0xB7, 0xE3, 0x02, 0x00}) ;

// Windows MakeCabで架空XMLを二件格納した130-byte CAB fixture。
constexpr auto MULTIPLE_XML_CAB = std::to_array<unsigned char>(
	{0x4D, 0x53, 0x43, 0x46, 0x00, 0x00, 0x00, 0x00, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00, 0x02, 0x00,
	 0x00, 0x00, 0x55, 0x08, 0x00, 0x00, 0x63, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x0B,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x5D, 0xB5, 0x53, 0x20, 0x00,
	 0x63, 0x61, 0x74, 0x61, 0x6C, 0x6F, 0x67, 0x2E, 0x78, 0x6D, 0x6C, 0x00, 0x0A, 0x00, 0x00,
	 0x00, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x5D, 0xB5, 0x53, 0x20, 0x00, 0x73, 0x65,
	 0x63, 0x6F, 0x6E, 0x64, 0x2E, 0x78, 0x6D, 0x6C, 0x00, 0x7D, 0xE6, 0xFF, 0x0F, 0x17, 0x00,
	 0x15, 0x00, 0x43, 0x4B, 0xB3, 0x71, 0x4E, 0x2C, 0x49, 0xCC, 0xC9, 0x4F, 0xD7, 0xB7, 0xE3,
	 0xB2, 0x09, 0x4E, 0x4D, 0xCE, 0xCF, 0x4B, 0x01, 0xB2, 0x00}) ;

//------------------------------------------------------------------------------
/**
 * @brief SHA-256試験用の3-byte一時fileを作成する。
 *
 * GetTempFileNameWが作成したfileだけを試験終了時に削除する。
 *
 * @param[out] path 成功時の一時file絶対path。
 * @return `abc`を保存できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool createTestFile( std::wstring &path)
{
	path.clear() ;
	std::array<wchar_t, MAX_PATH> directory{} ;	// Windows一時directory受信buffer。
	const DWORD					  directoryLength =
		// 文字数。
		GetTempPathW( static_cast<DWORD>( directory.size()), directory.data()) ;
	// 一時directoryのpathが空またはbufferを超える場合はfileを作成しない。
	if( directoryLength == 0 || directoryLength >= static_cast<DWORD>( directory.size())) {
		return false ;
	}

	std::array<wchar_t, MAX_PATH> temporaryPath{} ;	// 作成済み一時file path。
	// 一意な一時file名を取得できなければhash fixtureを作らない。
	if( GetTempFileNameW( directory.data(), L"DCT", 0, temporaryPath.data()) == 0) {
		return false ;
	}

	// 架空内容を書き込む一時fileの所有handle。試験内でCloseHandleする。
	const HANDLE file = CreateFileW( temporaryPath.data(), GENERIC_WRITE, 0, nullptr,
									TRUNCATE_EXISTING, FILE_ATTRIBUTE_TEMPORARY, nullptr) ;
	// 書込み用fileを開けなければ今回の一時fileを削除して失敗とする。
	if( file == INVALID_HANDLE_VALUE) {
		DeleteFileW( temporaryPath.data()) ;
		return false ;
	}

	constexpr std::array<char, 3> CONTENT{'a', 'b', 'c'} ;	// 既知SHA-256のfile内容。
	DWORD						  written{} ;				// WriteFileが保存したbyte数。
	// 固定fixture内容をfileへ書き込んだWin32結果。実書込み長と別に確認する。
	const BOOL					  succeeded =
		WriteFile( file, CONTENT.data(), static_cast<DWORD>( CONTENT.size()), &written, nullptr) ;
	CloseHandle( file) ;
	// 保存失敗または短い書込みでは不完全なhash fixtureを削除する。
	if( succeeded == FALSE || written != static_cast<DWORD>( CONTENT.size())) {
		DeleteFileW( temporaryPath.data()) ;
		return false ;
	}

	path = temporaryPath.data() ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Catalog cache試験用の空directoryを作成する。
 *
 * ProductionのProgramData cacheへ触れず、試験終了時に削除する。
 *
 * @param[out] path 成功時の試験専用directory絶対path。
 * @return 一時fileを空directoryへ置換できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool createTestDirectory( std::wstring &path)
{
	path.clear() ;
	std::array<wchar_t, MAX_PATH> directory{} ;	// Windows一時directory受信buffer。
	const DWORD					  directoryLength =
		// 文字数。
		GetTempPathW( static_cast<DWORD>( directory.size()), directory.data()) ;
	// 一時directoryのpathを確定できなければcache試験領域を作らない。
	if( directoryLength == 0 || directoryLength >= static_cast<DWORD>( directory.size())) {
		return false ;
	}

	std::array<wchar_t, MAX_PATH> temporaryPath{} ;	// GetTempFileNameが作成する一時path。
	// 一時名取得からdirectory作成までのいずれかが失敗したら未確保の領域を使わない。
	if( GetTempFileNameW( directory.data(), L"DCC", 0, temporaryPath.data()) == 0 ||
	   DeleteFileW( temporaryPath.data()) == FALSE ||
	   CreateDirectoryW( temporaryPath.data(), nullptr) == FALSE) {
		return false ;
	}

	path = temporaryPath.data() ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定した試験fileへbyte列を新規保存する。
 *
 * Production cacheへ触れず、共通readerのencodingを試験する。
 *
 * @param[in] path 試験directory内の未作成file絶対path。
 * @param[in] bytes 保存する1 byte以上の固定試験data。
 * @return 全byteをCREATE_NEW fileへ保存できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool writeTestBytes( const std::wstring_view		   path,
								  const std::span<const std::byte> bytes)
{
	// 空またはWin32書込み上限を超えるbyte列はfixtureとして保存しない。
	if( bytes.empty() || bytes.size() > static_cast<std::size_t>( MAXDWORD)) {
		return false ;
	}

	const std::wstring owned( path) ;	// CreateFile用終端null付き試験path。
	// 新規fixture fileを排他的に作成した所有handle。試験内でCloseHandleする。
	const HANDLE	   file = CreateFileW( owned.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
										  FILE_ATTRIBUTE_TEMPORARY, nullptr) ;
	// 試験fileを開けなければ書込みを開始しない。
	if( file == INVALID_HANDLE_VALUE) {
		return false ;
	}

	DWORD	   written{} ;	// WriteFileが保存したbyte数。
	// 指定byte列を書き込んだWin32結果。実書込み長と別に確認する。
	const BOOL succeeded =
		WriteFile( file, bytes.data(), static_cast<DWORD>( bytes.size()), &written, nullptr) ;
	CloseHandle( file) ;
	return succeeded != FALSE && written == bytes.size() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 試験cache内の指定拡張子fileを一つ取得する。
 *
 * SHA-256 basenameをtestへ公開せず破損入力fileを特定する。
 *
 * @param[in] root 試験専用cache directory。
 * @param[in] extension `*.body`等の固定検索pattern。
 * @param[out] path 成功時のfile絶対path。
 * @return 通常fileを一つ取得できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool findCacheFile( const std::wstring_view root, const std::wstring_view extension,
								 std::wstring &path)
{
	path.clear() ;
	const std::wstring pattern = std::wstring( root) + L"\\*" + std::wstring( extension) ;	// 検索式。
	WIN32_FIND_DATAW   data{} ;																// FindFirstFileが設定するfile情報。
	const HANDLE search = FindFirstFileW( pattern.c_str(), &data) ;							// FindClose対象search handle。
	// 該当するfileの列挙を開始できない場合はpathを返さない。
	if( search == INVALID_HANDLE_VALUE) {
		return false ;
	}

	FindClose( search) ;
	// directoryをcache本文fileとして返さない。
	if( (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
		return false ;
	}

	path = std::wstring( root) + L"\\" + data.cFileName ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 試験cache directoryと直下fileを削除する。
 *
 * 試験が作成した直下fileだけを削除し、再帰削除を行わない。
 *
 * @param[in] root createTestDirectoryが作成したdirectory。
 */
//------------------------------------------------------------------------------
void removeTestDirectory( const std::wstring_view root)
{
	const std::wstring pattern = std::wstring( root) + L"\\*" ;				// 直下entry検索pattern。
	WIN32_FIND_DATAW   data{} ;												// 現在列挙中のentry情報。
	const HANDLE	   search = FindFirstFileW( pattern.c_str(), &data) ;	// FindClose対象handle。
	// 列挙handleを取得できた場合にだけ試験領域直下のcleanupを行う。
	if( search != INVALID_HANDLE_VALUE) {
		BOOL more = TRUE ;	// 次のentryがある間TRUE。
		// 試験領域直下の有限なentryを列挙終端まで順番に確認する。
		while( more != FALSE) {
			const std::wstring_view name( data.cFileName) ;	// 現在entryのbasename。
			// 相対directory記号と子directoryを除外し、直下の通常fileだけを削除する。
			if( name != L"." && name != L".." &&
			   (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
				const std::wstring filePath =	// Test root直下の削除対象file。
					std::wstring( root) + L"\\" + data.cFileName ;
				DeleteFileW( filePath.c_str()) ;
			}

			more = FindNextFileW( search, &data) ;
		}

		FindClose( search) ;
	}

	const std::wstring owned( root) ;	// RemoveDirectory用終端null付きpath。
	RemoveDirectoryW( owned.c_str()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Catalog cacheの期限、ETag、破損破棄を検証する。
 *
 * Networkを使用せずfresh／stale、ETag検証、hash不一致時のfail-closed破棄を確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testCatalogCache( TestContext &context)
{
	std::wstring root ;									// Test終了時に削除するcache root。
	const bool	 created = createTestDirectory( root) ;	// Root作成結果。
	DRIVERCRATE_EXPECT( context, created) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( !created) {
		return ;
	}

	OfficialCatalogCache			 cache( root) ;	// Production ACLを使用しない試験cache。
	// URL境界検証だけに使用し、実通信を行わない架空取得先。
	constexpr std::wstring_view		 URL = L"https://downloads.example.com/catalog.bin" ;
	constexpr std::array<char, 3>	 CONTENT{'a', 'b', 'c'} ;							// 正常本文。
	const std::span<const std::byte> content = std::as_bytes( std::span( CONTENT)) ;	// Byte view。
	DRIVERCRATE_EXPECT( context, cache.store( URL, content, L"\"revision-1\"") == 0) ;

	CatalogCacheEntry entry ;	// Cache load結果。
	DRIVERCRATE_EXPECT( context, cache.load( URL, 16, 3'600, entry) == 0) ;
	DRIVERCRATE_EXPECT( context, entry.state == CatalogCacheState::FRESH) ;
	DRIVERCRATE_EXPECT( context, entry.validatedUtcSeconds.has_value() &&
									entry.validatedUtcSeconds.value() != 0U) ;
	DRIVERCRATE_EXPECT( context, entry.etag == L"\"revision-1\"") ;
	DRIVERCRATE_EXPECT( context, entry.content.size() == CONTENT.size()) ;
	DRIVERCRATE_EXPECT( context, std::equal( entry.content.begin(), entry.content.end(),
										   content.begin(), content.end())) ;

	DRIVERCRATE_EXPECT( context, cache.load( URL, 16, 0, entry) == 0) ;
	DRIVERCRATE_EXPECT( context, entry.state == CatalogCacheState::STALE) ;
	DRIVERCRATE_EXPECT( context, entry.validatedUtcSeconds.has_value()) ;

	std::wstring bodyPath ;												// Hash不一致を作るcache本文path。
	const bool	 foundBody = findCacheFile( root, L".body", bodyPath) ;	// 検索結果。
	DRIVERCRATE_EXPECT( context, foundBody) ;
	// 保存cache本文が見つかった場合にだけhash不一致の内容へ差し替える。
	if( foundBody) {
		const HANDLE file = CreateFileW( bodyPath.c_str(), GENERIC_WRITE, 0, nullptr,
										TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL,
										nullptr) ;	// CloseHandle対象handle。
		DRIVERCRATE_EXPECT( context, file != INVALID_HANDLE_VALUE) ;
		// 本文fileを書込み用に開けた場合にだけ破損byteを保存する。
		if( file != INVALID_HANDLE_VALUE) {
			constexpr std::array<char, 3> CORRUPT{'a', 'b', 'd'} ;	// Hash不一致本文。
			DWORD						  written{} ;				// WriteFileが保存したbyte数。
			DRIVERCRATE_EXPECT( context,
							   WriteFile( file, CORRUPT.data(), static_cast<DWORD>( CORRUPT.size()),
										 &written, nullptr) != FALSE) ;
			CloseHandle( file) ;
		}
	}

	DRIVERCRATE_EXPECT( context, cache.load( URL, 16, 3'600, entry) == 0) ;
	DRIVERCRATE_EXPECT( context, entry.state == CatalogCacheState::INVALIDATED) ;
	DRIVERCRATE_EXPECT( context, entry.content.empty()) ;
	DRIVERCRATE_EXPECT( context, !findCacheFile( root, L".body", bodyPath)) ;

	DRIVERCRATE_EXPECT( context, cache.store( URL, content, L"bad\r\nheader") == 0) ;
	DRIVERCRATE_EXPECT( context, cache.load( URL, 16, 3'600, entry) == 0) ;
	DRIVERCRATE_EXPECT( context, entry.state == CatalogCacheState::FRESH) ;
	DRIVERCRATE_EXPECT( context, entry.etag.empty()) ;
	removeTestDirectory( root) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 共通MSXML security envelopeの拒否条件を検証する。
 *
 * DTD、malformed XML、上限超過、過大nestingをfail-closedで拒否する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testOfficialXmlDocument( TestContext &context)
{
	const ComApartment apartment( COINIT_MULTITHREADED) ;	// MSXML 6.0用COM lifetime。
	DRIVERCRATE_EXPECT( context, SUCCEEDED( apartment.result())) ;
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		return ;
	}

	Microsoft::WRL::ComPtr<IXMLDOMDocument2> document ;	// 共通loaderが設定するDOM。
	DRIVERCRATE_EXPECT(
		context, loadOfficialXmlDocument( L"<Catalog/>", {.maximumCharacters = 64}, document) == 0) ;
	DRIVERCRATE_EXPECT( context, document != nullptr) ;

	// DTDを含むXMLの拒否を検証する合成入力。
	constexpr std::wstring_view DTD =
		LR"(<!DOCTYPE Catalog [<!ENTITY item "driver">]><Catalog>&item;</Catalog>)" ;
	DRIVERCRATE_EXPECT( context,
					   loadOfficialXmlDocument( DTD, {.maximumCharacters = 256}, document) != 0) ;
	DRIVERCRATE_EXPECT( context, document == nullptr) ;
	DRIVERCRATE_EXPECT(
		context, loadOfficialXmlDocument( L"<Catalog>", {.maximumCharacters = 64}, document) != 0) ;
	DRIVERCRATE_EXPECT(
		context, loadOfficialXmlDocument( L"<Catalog/>", {.maximumCharacters = 4}, document) != 0) ;

	std::wstring deepXml ;	// MaxElementDepth超過を作るwell-formed XML。
	// 65階層を順に開き、MSXML共通上限64を一つ超過させる。
	for( std::size_t depth = 0; depth < 65; ++depth) {
		deepXml += L"<n>" ;
	}

	// 開始tagと同数を閉じ、深度以外はwell-formedにする。
	for( std::size_t depth = 0; depth < 65; ++depth) {
		deepXml += L"</n>" ;
	}

	DRIVERCRATE_EXPECT( context, loadOfficialXmlDocument(
									deepXml, {.maximumCharacters = deepXml.size()}, document) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 共通CAB entry規則とUTF XML readerを検証する。
 *
 * Path付きentry、size逸脱、不正CAB、odd byte、埋込みnullをnetworkなしで拒否する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testOfficialCatalogArchive( TestContext &context)
{
	DRIVERCRATE_EXPECT( context, isAllowedOfficialCatalogEntry( L"catalog.xml", 20, 20)) ;
	DRIVERCRATE_EXPECT( context, isAllowedOfficialCatalogEntry( L"Catalog.XML", 1, 20)) ;
	DRIVERCRATE_EXPECT( context, !isAllowedOfficialCatalogEntry( L"folder\\catalog.xml", 20, 20)) ;
	DRIVERCRATE_EXPECT( context, !isAllowedOfficialCatalogEntry( L"../catalog.xml", 20, 20)) ;
	DRIVERCRATE_EXPECT( context, !isAllowedOfficialCatalogEntry( L"..xml", 20, 20)) ;
	DRIVERCRATE_EXPECT( context, !isAllowedOfficialCatalogEntry( L"catalog .xml", 20, 20)) ;
	DRIVERCRATE_EXPECT( context, !isAllowedOfficialCatalogEntry( L"catalog.json", 20, 20)) ;
	DRIVERCRATE_EXPECT( context, !isAllowedOfficialCatalogEntry( L"catalog.xml", 0, 20)) ;
	DRIVERCRATE_EXPECT( context, !isAllowedOfficialCatalogEntry( L"catalog.xml", 21, 20)) ;

	std::wstring invalidCab ;								// 3-byte非CAB試験file。
	const bool	 cabCreated = createTestFile( invalidCab) ;	// 作成結果。
	DRIVERCRATE_EXPECT( context, cabCreated) ;
	std::wstring root ;										// XML reader試験directory。
	const bool	 rootCreated = createTestDirectory( root) ;	// 作成結果。
	DRIVERCRATE_EXPECT( context, rootCreated) ;
	// fixtureの一方が未作成なら作成済みの側を片付けて検証を中止する。
	if( !cabCreated || !rootCreated) {
		// 作成済みCABだけを前提失敗時のcleanup対象にする。
		if( cabCreated) {
			DeleteFileW( invalidCab.c_str()) ;
		}

		// 作成済み試験directoryだけを前提失敗時のcleanup対象にする。
		if( rootCreated) {
			removeTestDirectory( root) ;
		}

		return ;
	}

	const std::wstring singleCab = root + L"\\single.cab" ;	// 単一XML CAB path。
	DRIVERCRATE_EXPECT( context,
					   writeTestBytes( singleCab, std::as_bytes( std::span( SINGLE_XML_CAB)))) ;
	const std::wstring output = root + L"\\extracted.xml" ;	// 単一XMLの未作成出力path。
	DRIVERCRATE_EXPECT( context, extractOfficialCatalogXml( singleCab, output, 1024) == 0) ;
	WIN32_FILE_ATTRIBUTE_DATA extracted{} ;	// 共通展開で作成されたXML file情報。
	DRIVERCRATE_EXPECT(
		context, GetFileAttributesExW( output.c_str(), GetFileExInfoStandard, &extracted) != FALSE) ;
	DRIVERCRATE_EXPECT( context, extracted.nFileSizeHigh == 0 && extracted.nFileSizeLow == 11) ;
	DeleteFileW( output.c_str()) ;

	const std::wstring multipleCab = root + L"\\multiple.cab" ;	// 複数XML CAB path。
	DRIVERCRATE_EXPECT( context,
					   writeTestBytes( multipleCab, std::as_bytes( std::span( MULTIPLE_XML_CAB)))) ;
	DRIVERCRATE_EXPECT( context, extractOfficialCatalogXml( multipleCab, output, 1024) != 0) ;
	DRIVERCRATE_EXPECT( context, GetFileAttributesW( output.c_str()) == INVALID_FILE_ATTRIBUTES) ;

	const std::wstring invalidOutput = root + L"\\invalid.xml" ;	// 不正CABの出力path。
	DRIVERCRATE_EXPECT( context, extractOfficialCatalogXml( invalidCab, invalidOutput, 1024) != 0) ;
	DRIVERCRATE_EXPECT( context,
					   GetFileAttributesW( invalidOutput.c_str()) == INVALID_FILE_ATTRIBUTES) ;
	DRIVERCRATE_EXPECT( context, extractOfficialCatalogXml( L"relative.cab", invalidOutput, 1024) ==
									static_cast<NativeError>( E_INVALIDARG)) ;

	constexpr std::array<wchar_t, 11> VALID_XML{static_cast<wchar_t>( 0xfeff),
												L'<',
												L'C',
												L'a',
												L't',
												L'a',
												L'l',
												L'o',
												L'g',
												L'/',
												L'>'} ;						// BOM付き`<Catalog/>`。
	const std::wstring				  validPath = root + L"\\valid.xml" ;	// 正常UTF-16LE試験path。
	DRIVERCRATE_EXPECT( context, writeTestBytes( validPath, std::as_bytes( std::span( VALID_XML)))) ;
	std::wstring xml ;	// 共通readerが設定するBOM除去済みXML。
	DRIVERCRATE_EXPECT( context, readOfficialUtf16Xml( validPath, 1024, xml) == 0) ;
	DRIVERCRATE_EXPECT( context, xml == L"<Catalog/>") ;

	constexpr std::array<unsigned char, 13> UTF8_XML{
		0xefU, 0xbbU, 0xbfU, '<', 'C', 'a', 't',
		'a',   'l',	  'o',	 'g', '/', '>'} ;				// 任意BOM付きUTF-8 `<Catalog/>`。
	const std::wstring utf8Path = root + L"\\utf8.xml" ;	// 正常UTF-8試験path。
	DRIVERCRATE_EXPECT( context, writeTestBytes( utf8Path, std::as_bytes( std::span( UTF8_XML)))) ;
	DRIVERCRATE_EXPECT( context, readOfficialUtf8Xml( utf8Path, 1024, xml) == 0) ;
	DRIVERCRATE_EXPECT( context, xml == L"<Catalog/>") ;

	constexpr std::array<char, 3> ODD_BYTES{'<', '\0', 'x'} ;		// UTF-16にならない奇数byte列。
	const std::wstring			  oddPath = root + L"\\odd.xml" ;	// Odd byte試験path。
	DRIVERCRATE_EXPECT( context, writeTestBytes( oddPath, std::as_bytes( std::span( ODD_BYTES)))) ;
	DRIVERCRATE_EXPECT( context, readOfficialUtf16Xml( oddPath, 1024, xml) != 0) ;

	constexpr std::array<wchar_t, 5> EMBEDDED_NULL{L'<', L'x', L'\0', L'/',
												   L'>'} ;				// 埋込みnull XML。
	const std::wstring				 nullPath = root + L"\\null.xml" ;	// 埋込みnull試験path。
	DRIVERCRATE_EXPECT( context, writeTestBytes( nullPath, std::as_bytes( std::span( EMBEDDED_NULL)))) ;
	DRIVERCRATE_EXPECT( context, readOfficialUtf16Xml( nullPath, 1024, xml) != 0) ;

	DeleteFileW( invalidCab.c_str()) ;
	removeTestDirectory( root) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式HTTPS URLとhost allowlistの拒否条件を検証する。
 *
 * 通信せずscheme、port、credential、suffix、policyを確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testHttpsUrlPolicy( TestContext &context)
{
	// Hostの完全一致だけを許可するpolicy fixture。
	constexpr std::array EXACT_HOSTS{std::wstring_view( L"downloads.example.com")} ;
	DRIVERCRATE_EXPECT( context,
					   validateOfficialHttpsUrl( L"https://downloads.example.com/driver.exe?x=1",
												EXACT_HOSTS) == 0) ;
	DRIVERCRATE_EXPECT( context, validateOfficialHttpsUrl(
									L"https://DOWNLOADS.EXAMPLE.COM/driver.exe", EXACT_HOSTS) == 0) ;
	DRIVERCRATE_EXPECT( context, validateOfficialHttpsUrl( L"http://downloads.example.com/driver.exe",
														 EXACT_HOSTS) != 0) ;
	DRIVERCRATE_EXPECT( context,
					   validateOfficialHttpsUrl( L"https://downloads.example.com:444/driver.exe",
												EXACT_HOSTS) != 0) ;
	DRIVERCRATE_EXPECT( context,
					   validateOfficialHttpsUrl( L"https://user@downloads.example.com/driver.exe",
												EXACT_HOSTS) != 0) ;
	DRIVERCRATE_EXPECT(
		context, validateOfficialHttpsUrl( L"https://downloads.example.com/driver.exe#fragment",
										  EXACT_HOSTS) != 0) ;
	DRIVERCRATE_EXPECT( context,
					   validateOfficialHttpsUrl( L"https://evil-downloads.example.com/driver.exe",
												EXACT_HOSTS) != 0) ;

	// 明示suffix配下のhostだけを許可するpolicy fixture。
	constexpr std::array SUFFIX_HOSTS{std::wstring_view( L".download.example.com")} ;
	DRIVERCRATE_EXPECT( context, validateOfficialHttpsUrl( L"https://download.example.com/driver.exe",
														 SUFFIX_HOSTS) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   validateOfficialHttpsUrl( L"https://cdn.download.example.com/driver.exe",
												SUFFIX_HOSTS) == 0) ;
	DRIVERCRATE_EXPECT(
		context, validateOfficialHttpsUrl( L"https://download.example.com.evil.test/driver.exe",
										  SUFFIX_HOSTS) != 0) ;

	// 未対応wildcard表記を拒否するhost policy fixture。
	constexpr std::array INVALID_HOSTS{std::wstring_view( L"*.example.com")} ;
	// 大小文字だけが異なる重複hostを検出するpolicy fixture。
	constexpr std::array DUPLICATE_HOSTS{std::wstring_view( L"example.com"),
										 std::wstring_view( L"EXAMPLE.COM")} ;
	DRIVERCRATE_EXPECT( context,
					   validateOfficialHttpsUrl( L"https://example.com/", INVALID_HOSTS) != 0) ;
	DRIVERCRATE_EXPECT( context,
					   validateOfficialHttpsUrl( L"https://example.com/", DUPLICATE_HOSTS) != 0) ;
	DRIVERCRATE_EXPECT( context,
					   validateOfficialHttpsUrl( L"https://example.com/",
												std::span<const std::wstring_view>{}) != 0) ;
	const std::wstring oversizedUrl =	// Application上限を超える絶対HTTPS URL。
		L"https://downloads.example.com/" + std::wstring( 8192U, L'a') ;
	DRIVERCRATE_EXPECT( context, validateOfficialHttpsUrl( oversizedUrl, EXACT_HOSTS) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式HTTPS redirect経路の拒否条件を検証する。
 *
 * 通信せず全hopのhost、上限、循環とopaque origin列を確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testHttpsRedirectPolicy( TestContext &context)
{
	constexpr std::array	   ALLOWED_HOSTS{std::wstring_view( L"origin.example.com"),
										 // 許可origin群。
										 std::wstring_view( L".cdn.example.com")} ;
	constexpr std::array	   VALID_URLS{std::wstring_view( L"https://origin.example.com/start"),
									  // 正常経路。
									  std::wstring_view( L"https://files.cdn.example.com/package")} ;
	std::vector<std::uint32_t> originIndices{99U} ;	// 成功時に置換されるopaque origin列。
	NativeError error = validateOfficialHttpsRedirectChain( VALID_URLS, ALLOWED_HOSTS, 1U,
														   originIndices) ;	// 正常経路の検証結果。
	DRIVERCRATE_EXPECT( context, error == 0) ;
	DRIVERCRATE_EXPECT( context, originIndices == std::vector<std::uint32_t>( {0U, 1U})) ;

	constexpr std::array DIRECT_URL{	// Redirectなしの正常経路。
									std::wstring_view( L"https://origin.example.com/start")} ;
	error = validateOfficialHttpsRedirectChain( DIRECT_URL, ALLOWED_HOSTS, 0U,
											   originIndices) ;	// Redirectなしの検証結果。
	DRIVERCRATE_EXPECT( context, error == 0) ;
	DRIVERCRATE_EXPECT( context, originIndices == std::vector<std::uint32_t>( {0U})) ;

	error = validateOfficialHttpsRedirectChain( VALID_URLS, ALLOWED_HOSTS, 0U,
											   originIndices) ;	// 上限超過経路の検証結果。
	DRIVERCRATE_EXPECT( context, error != 0) ;
	DRIVERCRATE_EXPECT( context, originIndices.empty()) ;

	constexpr std::array UNKNOWN_ORIGIN_URLS{
		std::wstring_view( L"https://origin.example.com/start"),
		// 未登録遷移先。
		std::wstring_view( L"https://unregistered.example.net/package")} ;
	error = validateOfficialHttpsRedirectChain( UNKNOWN_ORIGIN_URLS, ALLOWED_HOSTS, 1U,
											   originIndices) ;	// 未登録hostの検証結果。
	DRIVERCRATE_EXPECT( context, error != 0) ;
	DRIVERCRATE_EXPECT( context, originIndices.empty()) ;

	constexpr std::array INSECURE_URLS{std::wstring_view( L"https://origin.example.com/start"),
									   // 非HTTPS遷移先。
									   std::wstring_view( L"http://files.cdn.example.com/package")} ;
	error = validateOfficialHttpsRedirectChain( INSECURE_URLS, ALLOWED_HOSTS, 1U,
											   originIndices) ;	// 非HTTPS経路の検証結果。
	DRIVERCRATE_EXPECT( context, error != 0) ;
	DRIVERCRATE_EXPECT( context, originIndices.empty()) ;

	constexpr std::array RELATIVE_URLS{std::wstring_view( L"https://origin.example.com/start"),
									   // 相対Location経路。
									   std::wstring_view( L"/package")} ;
	error = validateOfficialHttpsRedirectChain( RELATIVE_URLS, ALLOWED_HOSTS, 1U,
											   originIndices) ;	// 相対URLの検証結果。
	DRIVERCRATE_EXPECT( context, error != 0) ;
	DRIVERCRATE_EXPECT( context, originIndices.empty()) ;

	constexpr std::array CYCLE_URLS{std::wstring_view( L"https://origin.example.com/start"),
									// 正規化後の循環経路。
									std::wstring_view( L"https://ORIGIN.EXAMPLE.COM/start")} ;
	error = validateOfficialHttpsRedirectChain( CYCLE_URLS, ALLOWED_HOSTS, 1U,
											   originIndices) ;	// 循環経路の検証結果。
	DRIVERCRATE_EXPECT( context, error != 0) ;
	DRIVERCRATE_EXPECT( context, originIndices.empty()) ;

	constexpr std::array AMBIGUOUS_HOSTS{std::wstring_view( L"origin.example.com"),
										 // 重複する境界。
										 std::wstring_view( L".example.com")} ;
	error = validateOfficialHttpsRedirectChain( DIRECT_URL, AMBIGUOUS_HOSTS, 0U,
											   originIndices) ;	// Origin重複の検証結果。
	DRIVERCRATE_EXPECT( context, error != 0) ;
	DRIVERCRATE_EXPECT( context, originIndices.empty()) ;

	error =
		validateOfficialHttpsRedirectChain( std::span<const std::wstring_view>{}, ALLOWED_HOSTS, 0U,
										   originIndices) ;	// 空経路の検証結果。
	DRIVERCRATE_EXPECT( context, error != 0) ;
	DRIVERCRATE_EXPECT( context, originIndices.empty()) ;
	error = validateOfficialHttpsRedirectChain( DIRECT_URL, ALLOWED_HOSTS, 6U,
											   originIndices) ;	// 実装上限超過policyの検証結果。
	DRIVERCRATE_EXPECT( context, error != 0) ;
	DRIVERCRATE_EXPECT( context, originIndices.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief File sizeとSHA-256共通検証を確認する。
 *
 * 既知hash一致とsize、hash、policy不一致の拒否を確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testFileMetadata( TestContext &context)
{
	std::wstring path ;								// Test終了時に削除する一時file path。
	const bool	 created = createTestFile( path) ;	// 3-byte file作成結果。
	DRIVERCRATE_EXPECT( context, created) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( !created) {
		return ;
	}

	// 固定入力のSHA-256計算と照合する既知の期待digest。
	constexpr std::wstring_view SHA256 =
		L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ;
	std::wstring actualHash ;	// 共通CNG verifierが返すhash。
	DRIVERCRATE_EXPECT( context, computeFileSha256( path, actualHash) == 0) ;
	DRIVERCRATE_EXPECT( context, actualHash == SHA256) ;
	DRIVERCRATE_EXPECT( context, verifyOfficialFileMetadata(
									path, {.expectedSize = 3, .expectedSha256 = SHA256}) == 0) ;
	DRIVERCRATE_EXPECT( context, verifyOfficialFileMetadata(
									path, {.expectedSize = 4, .expectedSha256 = SHA256}) != 0) ;
	DRIVERCRATE_EXPECT(
		context,
		verifyOfficialFileMetadata(
			path, {.expectedSize = 3,
				   .expectedSha256 =
					   L"0000000000000000000000000000000000000000000000000000000000000000"}) != 0) ;
	DRIVERCRATE_EXPECT( context, verifyOfficialFileMetadata(
									path, {.expectedSize = 3, .expectedSha256 = L"invalid"}) != 0) ;
	DRIVERCRATE_EXPECT( context, verifyOfficialFileMetadata( path, {}) != 0) ;

	// SHA-512の独立した既知値と失敗時出力を確認する。
	DRIVERCRATE_EXPECT( context, computeFileSha512( path, actualHash) == 0) ;
	DRIVERCRATE_EXPECT(
		context,
		actualHash ==
			L"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f") ;
	DRIVERCRATE_EXPECT( context, computeFileSha512( L"", actualHash) != 0) ;
	DRIVERCRATE_EXPECT( context, actualHash.empty()) ;
	DRIVERCRATE_EXPECT(
		context, computeFileSha512( std::wstring_view( L"invalid\0file", 12U), actualHash) != 0) ;
	DRIVERCRATE_EXPECT( context, actualHash.empty()) ;

	// Publisher名の正常照合を検証する架空許可集合。
	constexpr std::array PUBLISHERS{std::wstring_view( L"Test Publisher")} ;
	DRIVERCRATE_EXPECT( context, verifyAuthenticodePublisher( path, PUBLISHERS) != 0) ;
	// 大小文字だけが異なる重複publisherを検出する入力集合。
	constexpr std::array DUPLICATE_PUBLISHERS{std::wstring_view( L"Test Publisher"),
											  std::wstring_view( L"test publisher")} ;
	DRIVERCRATE_EXPECT( context, verifyAuthenticodePublisher( path, DUPLICATE_PUBLISHERS) ==
									static_cast<NativeError>( E_INVALIDARG)) ;
	// 埋込みnullを含むpublisher名を拒否する入力集合。
	constexpr std::array INVALID_PUBLISHERS{std::wstring_view( L"Test\0Publisher", 14)} ;
	DRIVERCRATE_EXPECT( context, verifyAuthenticodePublisher( path, INVALID_PUBLISHERS) ==
									static_cast<NativeError>( E_INVALIDARG)) ;
	DRIVERCRATE_EXPECT( context,
					   verifyAuthenticodePublisher( path, std::span<const std::wstring_view>{}) ==
						   static_cast<NativeError>( E_INVALIDARG)) ;
	DRIVERCRATE_EXPECT(
		context,
		verifyOfficialFile( path, {.expectedSize = 3, .expectedSha256 = SHA256}, PUBLISHERS) != 0) ;
	const std::string appended( 150000U, 'a') ;	// 64 KiBを二度跨ぐ既知byte列。
	const HANDLE	  appendFile =
		CreateFileW( path.c_str(), FILE_APPEND_DATA, 0U, nullptr, OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL, nullptr) ;	// 既存abcに追記する試験handle。
	DRIVERCRATE_EXPECT( context, appendFile != INVALID_HANDLE_VALUE) ;
	// File作成失敗時に無効handleを使用しない。
	if( appendFile != INVALID_HANDLE_VALUE) {
		DWORD written{} ;	// 追記した確定byte数。
		DRIVERCRATE_EXPECT( context, WriteFile( appendFile, appended.data(),
											  static_cast<DWORD>( appended.size()), &written,
											  nullptr) != FALSE) ;
		DRIVERCRATE_EXPECT( context, written == appended.size()) ;
		DRIVERCRATE_EXPECT( context, CloseHandle( appendFile) != FALSE) ;
		DRIVERCRATE_EXPECT( context, computeFileSha512( path, actualHash) == 0) ;
		DRIVERCRATE_EXPECT(
			context,
			actualHash ==
				L"000e216b5a9193272d3e91687cf328813d6b4598f2d21a83f75a280dc7ea1c7052efe84d570820317fa11bdf95eb68a6c30395d56f537f5524fd7d8a38b1fb5a") ;
	}

	DeleteFileW( path.c_str()) ;
	DRIVERCRATE_EXPECT( context, computeFileSha512( path, actualHash) != 0) ;
	DRIVERCRATE_EXPECT( context, actualHash.empty()) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_validation_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOfficialValidationTests( TestContext &context)
{
	testHttpResponseStatus( context) ;
	testHttpsUrlPolicy( context) ;
	testHttpsRedirectPolicy( context) ;
	testFileMetadata( context) ;
	testCatalogCache( context) ;
	testOfficialXmlDocument( context) ;
	testOfficialCatalogArchive( context) ;
}

} // namespace drivercrate::test
