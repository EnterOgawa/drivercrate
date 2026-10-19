//------------------------------------------------------------------------------
/**
 * @file collector_setup_transport.cpp
 * @brief OS API固定curlを実byteと共通cached-only署名検証へ結合します。
 * @version 01.00.01
 * @date 2026/10/17
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/17 OS固定curlの有限検証とhandle保持を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/17 観測済みOS curl署名者を専用policyへ追加し試験と共有。
 * </pre>
 *
 * @note OS trustやACLを変更せず、共通署名実装を再利用します。
 * @see docs/adr/0357-collector-explicit-run-and-system-transport.md
 */
//------------------------------------------------------------------------------
#include "collector_setup_transport.h"
#include "official_file_verifier.h"
#include <Windows.h>
#include <array>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace drivercrate {
namespace {
/** @brief 秘密pathを含めず最初の検査失敗を通知します。
 * @param[in] valid 必須条件。
 * @param[in] stage 固定診断名。
 * @param[in] code 保存済み元APIまたはtrust error。意味拒否は0。
 * @throws std::runtime_error 不成立。
 */
void transportRequire( const bool valid, const char *stage, const std::uint32_t code = 0U)
{
	// 取得不能や信頼不足を別pathへのfallbackにしない。
	if( !valid) {
		std::printf( "SYSTEM_TRANSPORT_ERROR stage=%s code=0x%08lx\n", stage,
					static_cast<unsigned long>( code)) ;
		throw std::runtime_error( stage) ;
	}
}

/** @brief 同じ実fileを子終了後に解放します。
 * @param[in] handle 所有する有効file handle。
 */
void closeTransport( void *handle) noexcept
{
	const BOOL	closed = CloseHandle( handle) ;								// 最終解放結果。
	const DWORD error  = closed == FALSE ? GetLastError() : ERROR_SUCCESS ;	// 元code。
	// Destructorから例外を漏らさず固定診断だけを残す。
	if( closed == FALSE) {
		std::printf( "SYSTEM_TRANSPORT_CLOSE code=%lu\n", static_cast<unsigned long>( error)) ;
	}
}
} // namespace

namespace collector_setup_transport_detail {
NativeError verifyCachedSystemCurlPublisherStage( const std::wstring_view path)
{
	// 固定OS curlだけの完全名群。共通chain・失効検証の成功を受理の前提にする。
	constexpr std::array<std::wstring_view, 4U> PUBLISHERS = {
		L"Microsoft Windows", L"Microsoft Corporation", L"Microsoft Windows Publisher",
		L"Microsoft 3rd Party Application Component"} ;
	return verifyAuthenticodePublisherCachedOnly( path, PUBLISHERS) ;
}
} // namespace collector_setup_transport_detail

CollectorSetupTransport prepareCollectorSetupTransport()
{
	std::array<wchar_t, 32768> system{} ;	// 環境変数を使わないOS directory。
	const UINT				   length =
		// 実文字数。
		GetSystemDirectoryW( system.data(), static_cast<UINT>( system.size())) ;
	const DWORD directoryError = length == 0U ? GetLastError() : ERROR_SUCCESS ;	// 元code。
	transportRequire( length != 0U, "SYSTEM_DIRECTORY", directoryError) ;
	transportRequire( length < system.size(), "SYSTEM_DIRECTORY_SIZE") ;
	const std::filesystem::path path =
		// 唯一の対象。
		std::filesystem::path( system.data()) / L"curl.exe" ;
	const HANDLE raw =
		CreateFileW( path.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
					OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;	// 実byteを保持。
	const DWORD openError =
		// 元code。
		raw == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS ;
	transportRequire( raw != INVALID_HANDLE_VALUE, "SYSTEM_CURL_OPEN", openError) ;
	const std::shared_ptr<void> file( raw, closeTransport) ;							// 全経路で一回だけ解放する。
	BY_HANDLE_FILE_INFORMATION	info{} ;												// 同じ実fileの属性とlink数。
	const BOOL	queried			 = GetFileInformationByHandle( file.get(), &info) ;		// 実属性照会。
	const DWORD informationError = queried == FALSE ? GetLastError() : ERROR_SUCCESS ;	// 元code。
	transportRequire( queried != FALSE, "SYSTEM_CURL_INFORMATION", informationError) ;
	transportRequire(
		(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0U &&
			info.nNumberOfLinks > 0U && info.nFileSizeHigh == 0U && info.nFileSizeLow > 0U &&
			info.nFileSizeLow <= 16777216U,
		"SYSTEM_CURL_FILE") ;
	std::array<wchar_t, 32768> finalPath{} ;	// 実handleの正規path。
	const DWORD				   finalLength = GetFinalPathNameByHandleW(
		   file.get(), finalPath.data(), static_cast<DWORD>( finalPath.size()),
		   FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;								// 実文字数。
	const DWORD finalError = finalLength == 0U ? GetLastError() : ERROR_SUCCESS ;	// 元code。
	transportRequire( finalLength != 0U, "SYSTEM_CURL_FINAL_PATH", finalError) ;
	transportRequire( finalLength > 4U && finalLength < finalPath.size(), "SYSTEM_CURL_FINAL_SIZE") ;
	const int compared =
		// 実path一致。
		CompareStringOrdinal( finalPath.data() + 4U, -1, path.c_str(), -1, TRUE) ;
	const DWORD compareError = compared == 0 ? GetLastError() : ERROR_SUCCESS ;	// 元code。
	transportRequire( compared != 0, "SYSTEM_CURL_COMPARE", compareError) ;
	transportRequire( compared == CSTR_EQUAL, "SYSTEM_CURL_PATH") ;
	std::wstring	  hash ;												// 固定実byteの共通SHA-256。
	const NativeError hashError = computeFileSha256( path.native(), hash) ;	// 共通hash結果。
	transportRequire( hashError == 0, "SYSTEM_CURL_HASH", static_cast<std::uint32_t>( hashError)) ;
	const NativeError trustError =
		// 共通署名結果。
		collector_setup_transport_detail::verifyCachedSystemCurlPublisherStage( path.native()) ;
	transportRequire( trustError == 0, "SYSTEM_CURL_TRUST", static_cast<std::uint32_t>( trustError)) ;
	return {path, hash, file} ;
}
} // namespace drivercrate
