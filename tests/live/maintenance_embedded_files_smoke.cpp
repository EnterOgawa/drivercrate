//------------------------------------------------------------------------------
/**
 * @file maintenance_embedded_files_smoke.cpp
 * @brief 明示local EXEの署名と内蔵表を非実行で検査する保守tool。
 * @version 01.00.01
 * @date 2026/10/05
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/05  元hash・publisherと静的表観測を追加。
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 起動引数はlocal path・期待hash・publisherだけです。入力実行、取得、導入、端末列挙は行いません。
 *       WinTrustのtrust照会は維持し、原入力へのwrite／delete共有を禁止します。
 * @see docs/adr/0260-maintenance-pe-flat-file-table.md
 */
//------------------------------------------------------------------------------

#include "platform/maintenance_embedded_file_table.h"
#include "platform/official_file_verifier.h"

#include <Windows.h>

#include <array>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace {

/**
 * @brief Scope内だけの読取りhandle所有者。
 */
using OwnedHandle = std::unique_ptr<void, decltype( &CloseHandle)> ;

/**
 * @brief 原stageとHRESULTを入力内容なしでJSON出力する。
 * @param[in] stage 固定ASCII stage。外部入力は渡しません。
 * @param[in] error 元失敗値。
 * @return 不合格のprocess終了値2。
 */
int reject( const char *stage, const drivercrate::NativeError error) noexcept
{
	std::printf( "{\"state\":\"REJECTED\",\"stage\":\"%s\",\"error\":%lu}\n", stage,
				static_cast<unsigned long>( static_cast<std::uint32_t>( error))) ;
	return 2 ;
}

/**
 * @brief Local入力を不変handleで固定し、既存共通署名と表構造を検査する。
 * @param[in] count OS引数数。四個だけを受理します。
 * @param[in] arguments 呼出し中だけ借用するOS引数。絶対pathを出力しません。
 * @return 全成功0、引数・I/O・署名・構造拒否2。
 */
int inspect( const int count, wchar_t **arguments)
{
	// 引数不足と余分な操作指定を拒否する。
	if( count != 4) {
		return reject( "ARGUMENTS", E_INVALIDARG) ;
	}

	const std::filesystem::path path( arguments[1]) ;			// 明示local入力path。
	const std::wstring			expectedHash( arguments[2]) ;	// 原EXE期待identity。
	const std::wstring_view		publisher( arguments[3]) ;		// 明示署名者。公式由来は別証拠。
	// Drive付きlocal絶対pathだけを使用し、remote取得toolにしない。
	if( !path.is_absolute() || path.root_name().native().size() != 2U ||
	   expectedHash.size() != 64U || publisher.empty() || publisher.size() > 256U) {
		return reject( "ARGUMENTS", E_INVALIDARG) ;
	}

	const HANDLE opened = CreateFileW(
		path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr) ;	// 書込み共有なし。
	// Open失敗では原Windows値を保持する。
	if( opened == INVALID_HANDLE_VALUE) {
		return reject( "OPEN", HRESULT_FROM_WIN32( GetLastError())) ;
	}

	OwnedHandle handle( opened, CloseHandle) ;	// 検査と出力完了まで入力identityを固定する。
	BY_HANDLE_FILE_INFORMATION information{} ;	// 同じhandleの属性とsize。
	// Disk通常file以外と64 MiB超過を署名処理へ渡さない。
	if( GetFileType( handle.get()) != FILE_TYPE_DISK ||
	   !GetFileInformationByHandle( handle.get(), &information) ||
	   (information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
		   0U ||
	   information.nFileSizeHigh != 0U || information.nFileSizeLow == 0U ||
	   information.nFileSizeLow > 64U * 1024U * 1024U) {
		return reject( "INPUT_BOUNDARY", E_INVALIDARG) ;
	}

	const std::array publishers{publisher} ;	// 共通署名検査の唯一の期待publisher。
	const drivercrate::OfficialFileMetadataPolicy policy{information.nFileSizeLow,
														 expectedHash} ;	// Sizeと全hash必須。
	const drivercrate::NativeError				  signature =
		// 共通検査。
		drivercrate::verifyOfficialFile( path.native(), policy, publishers) ;
	// ShellによるValid観測で共通署名拒否を上書きしない。
	if( signature != 0) {
		return reject( "SOURCE_SIGNATURE", signature) ;
	}

	std::vector<std::byte> bytes( information.nFileSizeLow) ;	// 有限な原入力を一度だけ保持する。
	DWORD				   read{} ;								// 同じ固定handleから読んだ原byte数。
	// 短いreadとI/O失敗を構造成功へ変換しない。
	if( !ReadFile( handle.get(), bytes.data(), information.nFileSizeLow, &read, nullptr) ||
	   read != bytes.size()) {
		return reject( "READ", HRESULT_FROM_WIN32( ERROR_READ_FAULT)) ;
	}

	drivercrate::MaintenanceEmbeddedFileTable layout ;	// 導入型と非互換の構造観測。
	const drivercrate::NativeError			  structure =
		// 有限解析。
		drivercrate::inspectMaintenanceEmbeddedFileTable( bytes, layout) ;
	// 構造不合格ではfile名や部分表を公開しない。
	if( structure != 0) {
		return reject( "STRUCTURE", structure) ;
	}

	std::wstring				   currentHash ;	// 読み取り後にも期待identityを確認する。
	const drivercrate::NativeError recheck =
		// 元hash再確認。
		drivercrate::computeFileSha256( path.native(), currentHash) ;
	// 不変handleとpathの再照合が成功した結果だけを出す。
	if( recheck != 0 || currentHash != expectedHash) {
		return reject( "SOURCE_RECHECK", recheck != 0 ? recheck : E_INVALIDARG) ;
	}

	std::printf(
		"{\"state\":\"STRUCTURE_VERIFIED\",\"sourceSignatureVerified\":true,"
		"\"installAuthorized\":false,\"tableOffset\":%zu,\"blobOffset\":%zu,\"blobBytes\":%zu,\"files\":[",
		layout.tableOffset, layout.blobOffset, layout.blobBytes) ;
	// 検査済みASCII flat名と原範囲だけを順番に出力する。
	for( std::size_t index = 0U; index < layout.files.size(); ++index) {
		const drivercrate::MaintenanceEmbeddedFile &file =
			layout.files[index] ;	// 同じ所有表の一項目。
		std::printf( "%s{\"name\":\"%s\",\"offset\":%zu,\"bytes\":%zu}", index == 0U ? "" : ",",
					file.name.c_str(), file.offset, file.bytes) ;
	}

	std::puts( "]}") ;
	return std::fflush( stdout) == 0 ? 0 : 2 ;
}

} // namespace

/**
 * @brief 明示local診断を例外境界内で実行する。
 * @param[in] count OS引数数。
 * @param[in] arguments OS所有の引数列。
 * @return 検査成功0、拒否または例外2。
 */
int wmain( const int count, wchar_t **arguments)
{
	try {
		return inspect( count, arguments) ;
	} catch( ...) {
		return reject( "EXCEPTION", E_UNEXPECTED) ;
	}
}
