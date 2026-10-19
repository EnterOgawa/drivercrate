//------------------------------------------------------------------------------
/**
 * @file nvidia_winof2_driver_package.cpp
 * @brief NVIDIA WinOF-2 MSI driver閉包選択実装。
 * @version 01.00.00
 * @date 2026/09/07
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  MSI内CABのdriver閉包選択を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  取得元identityの後段拘束を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note MSIのMedia／File mappingとCAB全entryを照合し、許可した一INFが参照するfileだけを論理名で分離します。MSI、EXE、custom actionは実行
 *       しません。
 */
//------------------------------------------------------------------------------

#include "platform/nvidia_winof2_driver_package.h"

#include "platform/official_download_workspace.h"
#include "platform/official_driver_package.h"
#include "platform/official_file_verifier.h"

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

constexpr std::wstring_view CABINET_STREAM_NAME = L"Data1.cab" ;	// 固定embedded CAB名。
constexpr std::wstring_view CABINET_WORKSPACE_TAG =
	L"winof2-msi-cabinet" ;	// MSI stream専用workspace識別子。
constexpr std::wstring_view RAW_WORKSPACE_TAG =
	L"winof2-cab-raw" ;												// CAB primary key名file専用workspace識別子。
constexpr std::uint32_t MAXIMUM_COPY_BUFFER_BYTES = 1024U * 1024U ;	// 一回の複写上限。

constexpr std::array	ALLOWED_INF_NAMES{
	   std::wstring_view( L"mlx5.inf"),		  std::wstring_view( L"mlx5mux.inf"),
	   std::wstring_view( L"mlx5muxp.inf"),	  std::wstring_view( L"MlxRshimBus.inf"),
	   std::wstring_view( L"MlxRshimCom.inf"), std::wstring_view( L"MlxRshimEth.inf"),
} ; // WinOF-2でdriver閉包選択を許可する論理INF名。

constexpr std::array ACCEPTED_CLASSES{
	std::wstring_view( L"Net"),
	std::wstring_view( L"NetTrans"),
	std::wstring_view( L"System"),
	std::wstring_view( L"Ports"),
} ; // WinOF-2の6 INFで許可するPnP class。

constexpr std::array ACCEPTED_PROVIDERS{
	std::wstring_view( L"Mellanox"),
	std::wstring_view( L"Mellanox Technologies Ltd."),
} ; // WinOF-2の6 INFで確認済みのProvider表示名。

constexpr std::array ACCEPTED_SIGNATURES{
	std::wstring_view( L"$Windows NT$"),
} ; // Windows x64標準INFで許可するSignature値。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 元の診断値をProvider共通結果へ保持する。
 *
 * @param[in] error Fileまたは検証処理のWin32 error code。
 * @return HRESULT_FROM_WIN32で変換したbit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windowsで同じfileとなる選択、mapping、重複を照合する。
 *
 * @param[in] left 比較する一方の論理名またはCAB名。
 * @param[in] right 比較する他方の論理名またはCAB名。
 * @return 大文字小文字を無視して完全一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool pathsEqual( const std::wstring_view left, const std::wstring_view right) noexcept
{
	// Windows path比較APIの長さ型を超える入力を拒否する。
	if( left.size() > static_cast<std::size_t>( std::numeric_limits<int>::max()) ||
	   right.size() > static_cast<std::size_t>( std::numeric_limits<int>::max())) {
		return false ;
	}

	return CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

//------------------------------------------------------------------------------
/**
 * @brief 任意のMSI FileNameをdriver候補として選択させない。
 *
 * @param[in] path 利用者またはProviderが選択した論理INF名。
 * @return 固定6系列の一つと完全一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAllowedInf( const std::wstring_view path) noexcept
{
	return std::ranges::any_of( ALLOWED_INF_NAMES, [path]( const std::wstring_view allowed) noexcept {
		return pathsEqual( path, allowed) ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同名のx64／ARM64等がある場合は推測で一方を選ばない。
 *
 * @param[in] mappings Media／File tableから得た順序付き対応群。
 * @param[in] targetPath INFが参照する論理file名。
 * @return 一件だけ一致したmappingへの非所有pointer。その他はnull。
 */
//------------------------------------------------------------------------------
[[nodiscard]] const OfficialMsiCabinetFileEntry *findUniqueMapping(
	const std::span<const OfficialMsiCabinetFileEntry> mappings,
	const std::wstring_view							   targetPath) noexcept
{
	const OfficialMsiCabinetFileEntry *found{} ;	// 現在までに一件だけ一致したmapping。
	// 全mappingを確認し、二件目の同名を曖昧として拒否する。
	for( const OfficialMsiCabinetFileEntry &mapping : mappings) {
		// 目的のlogical pathに一致しないmappingを除外する。
		if( !pathsEqual( mapping.targetRelativePath, targetPath)) {
			continue ;
		}

		// 同じlogical pathへの複数mappingを曖昧なまま選択しない。
		if( found != nullptr) {
			return nullptr ;
		}

		found = &mapping ;
	}

	return found ;
}

//------------------------------------------------------------------------------
/**
 * @brief MSI表示名だけを信用せず、実CAB内容との対応を確定する。
 *
 * @param[in] inventory MSI Media／File tableの固定mapping。
 * @param[in] cabEntries 既存CAB parserで事前検証した全entry。
 * @return 件数、順序、primary key、sizeが全て一致する場合は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateCabinetMapping(
	const OfficialMsiCabinetInventory	   &inventory,
	const std::span<const OfficialZipEntry> cabEntries) noexcept
{
	// CAB stream名とMSI・実CABのfile件数が一致することを確認する。
	if( inventory.streamName != CABINET_STREAM_NAME || inventory.files.empty() ||
	   inventory.files.size() != cabEntries.size()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// indexはMSI Sequence順とCAB格納順を同じ位置で照合する。
	for( std::size_t index = 0U; index < inventory.files.size(); ++index) {
		const OfficialMsiCabinetFileEntry &mapping	= inventory.files[index] ;	// MSI側entry。
		const OfficialZipEntry			  &cabEntry = cabEntries[index] ;		// CAB側entry。
		// 各mappingのCAB内pathと展開sizeを実entryへ照合する。
		if( !pathsEqual( mapping.cabinetRelativePath, cabEntry.relativePath) ||
		   mapping.uncompressedSize != cabEntry.uncompressedSize) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief INF内のCAT／SourceDisksFiles参照をMSI論理名へ照合可能にする。
 *
 * @param[in] mappings CABと照合済みのMSI file mapping。
 * @param[out] entries FileNameとsizeだけを持つ論理inventory。
 */
//------------------------------------------------------------------------------
void makeLogicalInventory( const std::span<const OfficialMsiCabinetFileEntry> mappings,
						  std::vector<OfficialZipEntry>						&entries)
{
	entries.clear() ;
	entries.reserve( mappings.size()) ;
	// 各MSI rowを順序どおり論理名entryへ変換し、重複名は後段の一意解決で拒否する。
	for( const OfficialMsiCabinetFileEntry &mapping : mappings) {
		entries.push_back(
			OfficialZipEntry{mapping.targetRelativePath, mapping.uncompressedSize, {}}) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief INF、CAT、複数sectionで共有される参照fileの重複を除く。
 *
 * @param[in,out] paths 選択順を維持する一意論理path群。
 * @param[in] path INF解析で確定した追加候補。
 */
//------------------------------------------------------------------------------
void appendUniquePath( std::vector<std::wstring> &paths, const std::wstring_view path)
{
	// 既存pathと同一でない参照fileだけを閉包へ追加する。
	if( std::ranges::none_of( paths, [path]( const std::wstring &current) noexcept {
		   return pathsEqual( current, path) ;
	   })) {
		paths.emplace_back( path) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同名architectureや欠落fileを推測せず、書込み前に拒否する。
 *
 * @param[in] mappings CABと照合済みのMSI file mapping。
 * @param[in] closurePaths INF、CAT、参照fileの論理path群。
 * @param[in] policy 閉包file数と合計sizeの有限上限。
 * @param[out] resolved 各論理pathに一意なmapping pointer群。
 * @param[out] closureBytes 成功時の閉包合計byte数。
 * @return 全pathが一意に解決され有限上限内なら0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError resolveClosureMappings(
	const std::span<const OfficialMsiCabinetFileEntry> mappings,
	const std::span<const std::wstring> closurePaths, const NvidiaWinof2DriverClosurePolicy &policy,
	std::vector<const OfficialMsiCabinetFileEntry *> &resolved, std::uint64_t &closureBytes)
{
	resolved.clear() ;
	closureBytes = 0U ;
	// 空またはfile件数上限を超える閉包を解決しない。
	if( closurePaths.empty() || closurePaths.size() > policy.maximumClosureFiles) {
		return nativeErrorFromWin32( ERROR_TOO_MANY_NAMES) ;
	}

	resolved.reserve( closurePaths.size()) ;
	// 全論理pathを一意mappingへ解決し、合計sizeをoverflowなしで加算する。
	for( const std::wstring &path : closurePaths) {
		const OfficialMsiCabinetFileEntry *mapping =
			// 現在pathの一意mapping。
			findUniqueMapping( mappings, path) ;
		// 一意mappingの欠落やbyte上限超過時は部分解決結果を破棄する。
		if( mapping == nullptr ||
		   mapping->uncompressedSize > policy.maximumClosureBytes - closureBytes) {
			resolved.clear() ;
			closureBytes = 0U ;
			return mapping == nullptr ? nativeErrorFromWin32( ERROR_FILE_NOT_FOUND)
									  : nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
		}

		resolved.push_back( mapping) ;
		closureBytes += mapping->uncompressedSize ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 短い書込みでも残量が0になるまで同じbufferを前方へ進める。
 *
 * @param[in] file Workspaceが所有する書込み可能file handle。
 * @param[in] content 今回読み取ったsource file内容。
 * @return 全byte書込み成功時は0、失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError writeComplete( const HANDLE					 file,
										const std::span<const std::byte> content) noexcept
{
	std::size_t offset{} ;	// 次に保存するcontent内のbyte位置。
	// WriteFileのDWORD範囲内で、今回受信した全byteを順に保存する。
	while( offset < content.size()) {
		const DWORD requested = static_cast<DWORD>( std::min<std::size_t>(
			// 今回の要求長。
			content.size() - offset, std::numeric_limits<DWORD>::max())) ;
		DWORD		written{} ;	// 今回WriteFileが保存したbyte数。
		// 書込み失敗や進捗0を検出して無限再送を防ぐ。
		if( WriteFile( file, content.data() + offset, requested, &written, nullptr) == FALSE ||
		   written == 0U) {
			DWORD error = GetLastError() ;	// WriteFileが返した診断値。
			// 失敗経路で診断値が成功のままなら書込み失敗へ補正する。
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
 * @brief CREATE_NEWで既存fileを守り、失敗時は今回の出力だけ破棄する。
 *
 * @param[in] rawWorkspace CABが生名で展開したfile所有領域。
 * @param[in] rawEntry CAB展開で固定したsizeとSHA-256。
 * @param[in] mapping 生名から論理名へのMSI mapping。
 * @param[in] bufferBytes 一回の複写に使う有限buffer byte数。
 * @param[in,out] outputWorkspace 論理名fileを所有する保護領域。
 * @param[out] outputEntry 成功時の論理名、size、SHA-256。
 * @return 前後identityと完全複写成功時は0、失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError copyMappedFile( const OfficialDownloadWorkspace   &rawWorkspace,
										 const OfficialZipEntry			   &rawEntry,
										 const OfficialMsiCabinetFileEntry &mapping,
										 const std::uint32_t				bufferBytes,
										 OfficialDownloadWorkspace		   &outputWorkspace,
										 OfficialZipEntry				   &outputEntry)
{
	outputEntry = {} ;
	// raw entryとmappingの対応、hash、copy buffer上限を処理前に検証する。
	if( !pathsEqual( rawEntry.relativePath, mapping.cabinetRelativePath) ||
	   rawEntry.uncompressedSize != mapping.uncompressedSize || rawEntry.sha256.empty() ||
	   bufferBytes == 0U || bufferBytes > MAXIMUM_COPY_BUFFER_BYTES) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	bool outputCreated{} ;	// trueの場合は例外または失敗時に論理名fileを破棄する。
	try {
		std::vector<std::byte> buffer( bufferBytes) ;	// 複写全体で再利用する有限buffer。
		const std::wstring	   sourcePath =
			// 生CAB entryの絶対path。
			rawWorkspace.path( rawEntry.relativePath) ;
		// 保護workspace内でsourceを解決できなければ複製しない。
		if( sourcePath.empty()) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		const HANDLE rawSource =
			CreateFileW( sourcePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
						FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;	// 置換を拒否するsource handle。
		// source fileを開けなければ元の診断値を返す。
		if( rawSource == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		const auto closeHandle = []( void *const handle) noexcept {
			// 無効な値を解放APIへ渡さず、保持している有効なresourceの後始末を行う。
			if( handle != nullptr && handle != INVALID_HANDLE_VALUE) {
				CloseHandle( handle) ;
			}
		} ; // 全終了経路で有効なfile handleを閉じるdeleter。
		const std::unique_ptr<void, decltype( closeHandle)> source( rawSource,
																  closeHandle) ;	// Source所有者。
		NativeError										   error =
			verifyOfficialFileMetadata( sourcePath, {.expectedSize = rawEntry.uncompressedSize,
													// 複写前identity結果。
													.expectedSha256 = rawEntry.sha256}) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		HANDLE rawOutput{INVALID_HANDLE_VALUE} ;	// 論理名で新規作成する所有file handle。
		error = outputWorkspace.createFile( mapping.targetRelativePath, rawOutput) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		outputCreated = true ;
		std::unique_ptr<void, decltype( closeHandle)> output( rawOutput,
															closeHandle) ;	// 出力handle所有者。
		std::uint64_t								 processed{} ;			// 完全複写済みのbyte数。
		// 固定sizeを上限としてsourceを前方へ読み、待ち時間だけで進捗を増やさない。
		while( processed < rawEntry.uncompressedSize) {
			const std::uint64_t remaining = rawEntry.uncompressedSize - processed ;	// 残量。
			const DWORD			requested = static_cast<DWORD>(
				std::min<std::uint64_t>( remaining, buffer.size())) ;	// 今回の読取り要求長。
			DWORD	   transferred{} ;									// ReadFileが返した実byte数。
			const BOOL readSucceeded =
				ReadFile( source.get(), buffer.data(), requested, &transferred,
						 nullptr) ;	// 今回の同期読取り結果。
			const DWORD readError =
				readSucceeded != FALSE ? ERROR_SUCCESS : GetLastError() ;	// 失敗時の診断値。
			// 読み込み失敗、途中EOF、要求を超える転送量を検出して複製を中止する。
			if( readSucceeded == FALSE || transferred == 0U || transferred > requested) {
				error =
					nativeErrorFromWin32( readError == ERROR_SUCCESS ? ERROR_HANDLE_EOF : readError) ;
				break ;
			}

			error =
				writeComplete( output.get(), std::span<const std::byte>( buffer.data(), transferred)) ;
			// 書込み失敗後は後続bufferの複製を続けない。
			if( error != 0) {
				break ;
			}

			processed += transferred ;
		}

		const HANDLE closingOutput	= output.release() ;			// Close結果を確認する所有handle。
		const BOOL	 closeSucceeded = CloseHandle( closingOutput) ;	// Hash前のclose結果。
		// 先行失敗がない場合だけclose失敗を最終診断へ反映する。
		if( error == 0 && closeSucceeded == FALSE) {
			error = nativeErrorFromWin32( GetLastError()) ;
		}

		const std::wstring outputPath =
			// 検証対象の論理名絶対path。
			outputWorkspace.path( mapping.targetRelativePath) ;
		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = verifyOfficialFileMetadata(
				outputPath, {.expectedSize	 = rawEntry.uncompressedSize,
							 .expectedSha256 = rawEntry.sha256}) ;	// 複写後identity結果。
		}

		// 複製または検証失敗時は今回作成した出力だけを破棄する。
		if( error != 0) {
			static_cast<void>( outputWorkspace.discardFile( mapping.targetRelativePath)) ;
			outputCreated = false ;
			return error ;
		}

		outputEntry	  = OfficialZipEntry{mapping.targetRelativePath, mapping.uncompressedSize,
										 rawEntry.sha256} ;	// 完全検証済み論理entry。
		outputCreated = false ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		// 例外時も今回作成済みの出力だけをcleanup対象にする。
		if( outputCreated) {
			try {
				static_cast<void>( outputWorkspace.discardFile( mapping.targetRelativePath)) ;
			} catch( ...) {
				// Memory不足時のcleanup失敗はworkspace destructorの既知file回収へ委ねる。
			}
		}

		outputEntry = {} ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( const std::length_error &) {
		// 例外時も今回作成済みの出力だけをcleanup対象にする。
		if( outputCreated) {
			try {
				static_cast<void>( outputWorkspace.discardFile( mapping.targetRelativePath)) ;
			} catch( ...) {
				// 長さ異常時のcleanup失敗はworkspace destructorの既知file回収へ委ねる。
			}
		}

		outputEntry = {} ;
		return static_cast<NativeError>( E_INVALIDARG) ;
	} catch( ...) {
		// 例外時も今回作成済みの出力だけをcleanup対象にする。
		if( outputCreated) {
			try {
				static_cast<void>( outputWorkspace.discardFile( mapping.targetRelativePath)) ;
			} catch( ...) {
				// 型不明例外時もcleanupを優先し、残存fileはworkspace所有のまま維持する。
			}
		}

		outputEntry = {} ;
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 逆順cleanupを一件の失敗で止めず、destructor回収も維持する。
 *
 * @param[in,out] workspace 今回のfileを所有する保護領域。
 * @param[in] paths 作成成功順の論理相対path群。
 */
//------------------------------------------------------------------------------
void discardCreatedFiles( OfficialDownloadWorkspace				 &workspace,
						 const std::span<const std::wstring_view> paths) noexcept
{
	// indexは最後に作成したfileから逆順に破棄する位置。
	for( std::size_t index = paths.size(); index > 0U; --index) {
		try {
			static_cast<void>( workspace.discardFile( paths[index - 1U])) ;
		} catch( ...) {
			// Cleanup例外は外へ漏らさず、残りfileとworkspace destructorの回収を続ける。
		}
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_winof2_driver_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError extractNvidiaWinof2DriverClosure( const NvidiaWinof2DriverClosureRequest &request,
											 const NvidiaWinof2DriverClosurePolicy	&policy,
											 OfficialDownloadWorkspace				&workspace,
											 NvidiaWinof2DriverClosure				&result)
{
	result = {} ;
	// session、取得identity、選択INF、各上限を閉包抽出前に検証する。
	if( request.scanSessionId == 0U || request.sourceAcquisitionId == 0U ||
	   request.workspaceTag.empty() || !isAllowedInf( request.selectedInfPath) ||
	   policy.maximumHardwareIds == 0U || policy.maximumSourceFiles == 0U ||
	   policy.maximumClosureFiles == 0U || policy.maximumClosureBytes == 0U ||
	   policy.copyBufferBytes == 0U || policy.copyBufferBytes > MAXIMUM_COPY_BUFFER_BYTES) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::vector<std::wstring_view> createdPaths ;	// 失敗時に逆順破棄する論理名file群。
	try {
		createdPaths.reserve( policy.maximumClosureFiles) ;
		OfficialMsiCabinetInventory inventory ;	// MSI Media／File tableの順序付きmapping。
		const OfficialMsiCabinetInventoryRequest inventoryRequest{
			request.databasePath, request.expectedDatabaseSize, request.expectedDatabaseSha256,
			CABINET_STREAM_NAME} ;	// 固定CAB mapping要求。
		// MSI内CAB inventoryの静的検査からpackage閉包確認へ引き継ぐ診断値。
		NativeError error = inspectOfficialMsiCabinetInventory(
			inventoryRequest, policy.msiInventoryPolicy, inventory) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		OfficialDownloadWorkspace cabinetWorkspace ;	// 中間Data1.cabだけを所有する保護領域。
		error = cabinetWorkspace.initialize( CABINET_WORKSPACE_TAG, request.scanSessionId) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		const OfficialMsiStreamExtractionRequest streamRequest{
			request.databasePath, request.expectedDatabaseSize, request.expectedDatabaseSha256,
			CABINET_STREAM_NAME, CABINET_STREAM_NAME} ;	// 固定Data1.cab取得要求。
		OfficialMsiStreamEntry cabinetEntry ;			// 取得した中間CABのsizeとSHA-256。
		error = extractOfficialMsiStream( streamRequest, policy.msiStreamPolicy, cabinetWorkspace,
										 cabinetEntry) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		const std::wstring cabinetPath =
			// CAB絶対path。
			cabinetWorkspace.path( cabinetEntry.relativePath) ;
		// CABの保護pathを解決できない内部不整合を拒否する。
		if( cabinetPath.empty()) {
			return static_cast<NativeError>( E_UNEXPECTED) ;
		}

		const HANDLE rawCabinetGuard =
			CreateFileW( cabinetPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
						FILE_FLAG_OPEN_REPARSE_POINT,
						nullptr) ;	// 全CAB監査中の変更と置換を拒否する所有handle。
		// CABを読み保護できなければ抽出を開始しない。
		if( rawCabinetGuard == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		const auto closeCabinetGuard = []( void *const handle) noexcept {
			// 無効な値を解放APIへ渡さず、保持している有効なresourceの後始末を行う。
			if( handle != nullptr && handle != INVALID_HANDLE_VALUE) {
				CloseHandle( handle) ;
			}
		} ; // 全終了経路でCAB identity固定handleを閉じるdeleter。
		const std::unique_ptr<void, decltype( closeCabinetGuard)> cabinetGuard(
			rawCabinetGuard, closeCabinetGuard) ;	// CAB identity固定handle所有者。
		error = verifyOfficialFileMetadata(
			cabinetPath, {.expectedSize	  = cabinetEntry.streamSize,
						  .expectedSha256 = cabinetEntry.sha256}) ;	// CAB監査前identity結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		std::vector<OfficialZipEntry> cabEntries ;	// 既存CAB parserが検証した全entry。
		error = inspectOfficialCab( cabinetPath, policy.cabPolicy, cabEntries) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		error = validateCabinetMapping( inventory, cabEntries) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		const OfficialMsiCabinetFileEntry *selectedInf =
			// 選択INF mapping。
			findUniqueMapping( inventory.files, request.selectedInfPath) ;
		// 選択INFを一意かつ許可名で解決できなければ抽出しない。
		if( selectedInf == nullptr || !isAllowedInf( selectedInf->targetRelativePath)) {
			return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
		}

		OfficialDownloadWorkspace rawWorkspace ;	// 選択CAB entryを生名で所有する保護領域。
		error = rawWorkspace.initialize( RAW_WORKSPACE_TAG, request.scanSessionId) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		const std::wstring_view selectedRawPath =
			selectedInf->cabinetRelativePath ;					// CABから先行展開するINF primary key。
		const std::array selectedRawPaths{selectedRawPath} ;	// 一INFだけの生名選択集合。
		std::vector<OfficialZipEntry> rawInfEntries ;			// 生名で展開したINFとSHA-256。
		error = extractOfficialCabFiles( cabinetPath, policy.cabPolicy, selectedRawPaths,
										rawWorkspace, rawInfEntries) ;
		// 選択INFの抽出が成功して一件に確定することを要求する。
		if( error != 0 || rawInfEntries.size() != 1U) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		error = workspace.initialize( request.workspaceTag, request.scanSessionId) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		std::vector<OfficialZipEntry> extractedEntries ;	// 論理名へ複写済みの閉包entry群。
		extractedEntries.reserve( policy.maximumClosureFiles) ;
		OfficialZipEntry logicalInfEntry ;	// 論理名へ複写した選択INF entry。
		error = copyMappedFile( rawWorkspace, rawInfEntries.front(), *selectedInf,
							   policy.copyBufferBytes, workspace, logicalInfEntry) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		createdPaths.push_back( selectedInf->targetRelativePath) ;
		extractedEntries.push_back( logicalInfEntry) ;

		std::vector<OfficialZipEntry> logicalInventory ;	// MSI FileNameを使う全file inventory。
		makeLogicalInventory( inventory.files, logicalInventory) ;
		const OfficialInfInspectionPolicy infPolicy{
			.maximumHardwareIds			= policy.maximumHardwareIds,
			.maximumSourceFiles			= policy.maximumSourceFiles,
			.acceptedClasses			= ACCEPTED_CLASSES,
			.acceptedProviders			= ACCEPTED_PROVIDERS,
			.acceptedSignatures			= ACCEPTED_SIGNATURES,
			.acceptAnyProvider			= false,
			.requireDriverBinary		= true,
			.rejectUnreferencedPrograms = false,
			.rejectInstallActions		= true,
		} ; // WinOF-2 driver閉包だけへ固定するINF構造policy。
		OfficialInfPackage package ;	// 選択INFの構造と論理参照file結果。
		error = inspectOfficialInfPackage( workspace, logicalInventory,
										  selectedInf->targetRelativePath, infPolicy, package) ;
		// 閉包構築の先行失敗時は今回の作成fileを破棄する。
		if( error != 0) {
			discardCreatedFiles( workspace, createdPaths) ;
			return error ;
		}

		std::vector<std::wstring> closurePaths ;	// INF、CAT、参照fileの一意論理path群。
		closurePaths.reserve( policy.maximumClosureFiles) ;
		appendUniquePath( closurePaths, package.infRelativePath) ;
		appendUniquePath( closurePaths, package.catalogRelativePath) ;
		// 選択INFが列挙した全source fileを閉包へ追加する。
		for( const std::wstring &sourceFile : package.sourceFiles) {
			appendUniquePath( closurePaths, sourceFile) ;
		}

		std::vector<const OfficialMsiCabinetFileEntry *> closureMappings ;	// Path別mapping。
		std::uint64_t closureBytes{} ;										// 書込み前に確定する閉包合計byte数。
		error = resolveClosureMappings( inventory.files, closurePaths, policy, closureMappings,
									   closureBytes) ;
		// 閉包構築の先行失敗時は今回の作成fileを破棄する。
		if( error != 0) {
			discardCreatedFiles( workspace, createdPaths) ;
			return error ;
		}

		std::uint64_t availableBytes{} ;	// Output volumeで現在利用可能なbyte数。
		error = workspace.queryAvailableBytes( availableBytes) ;
		// 残り展開量と空き容量が整合しなければ作成済みfileを破棄する。
		if( error != 0 || closureBytes < logicalInfEntry.uncompressedSize ||
		   availableBytes < closureBytes - logicalInfEntry.uncompressedSize) {
			discardCreatedFiles( workspace, createdPaths) ;
			return error != 0 ? error : nativeErrorFromWin32( ERROR_DISK_FULL) ;
		}

		std::vector<std::wstring_view> remainingRawPaths ;						// INF以外の生CAB entry名群。
		std::vector<const OfficialMsiCabinetFileEntry *> remainingMappings ;	// 対応mapping群。
		remainingRawPaths.reserve( closureMappings.size() - 1U) ;
		remainingMappings.reserve( closureMappings.size() - 1U) ;
		// 選択INFは複写済みのため、CATと参照fileだけを追加展開する。
		for( const OfficialMsiCabinetFileEntry *const mapping : closureMappings) {
			// 先に抽出したINFを除き、残りの参照fileだけを追加抽出へ回す。
			if( !pathsEqual( mapping->targetRelativePath, selectedInf->targetRelativePath)) {
				remainingRawPaths.push_back( mapping->cabinetRelativePath) ;
				remainingMappings.push_back( mapping) ;
			}
		}

		std::vector<OfficialZipEntry> rawRemainingEntries ;	// 生名のCATと参照file群。
		// 未抽出の参照fileがある場合だけCAB追加抽出を行う。
		if( !remainingRawPaths.empty()) {
			error = extractOfficialCabFiles( cabinetPath, policy.cabPolicy, remainingRawPaths,
											rawWorkspace, rawRemainingEntries) ;
			// 追加抽出の失敗やmapping件数不一致時は今回の出力を全て破棄する。
			if( error != 0 || rawRemainingEntries.size() != remainingMappings.size()) {
				discardCreatedFiles( workspace, createdPaths) ;
				return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}
		}

		// 各生名fileを同じ位置のMSI論理名へ複写し、identityを固定する。
		for( std::size_t index = 0U; index < rawRemainingEntries.size(); ++index) {
			OfficialZipEntry logicalEntry ;	// 現在複写する論理名entry。
			error =
				copyMappedFile( rawWorkspace, rawRemainingEntries[index], *remainingMappings[index],
							   policy.copyBufferBytes, workspace, logicalEntry) ;
			// 参照file処理の失敗時は今回の作成fileを破棄する。
			if( error != 0) {
				discardCreatedFiles( workspace, createdPaths) ;
				return error ;
			}

			createdPaths.push_back( remainingMappings[index]->targetRelativePath) ;
			extractedEntries.push_back( std::move( logicalEntry)) ;
		}

		error = verifyOfficialFileMetadata(
			cabinetPath, {.expectedSize	  = cabinetEntry.streamSize,
						  .expectedSha256 = cabinetEntry.sha256}) ;	// CAB監査後identity結果。
		// 参照file処理の失敗時は今回の作成fileを破棄する。
		if( error != 0) {
			discardCreatedFiles( workspace, createdPaths) ;
			return error ;
		}

		std::vector<OfficialZipEntry> orderedEntries ;	// 閉包論理path順の検証済みentry群。
		orderedEntries.reserve( closurePaths.size()) ;
		// 全閉包pathが一度だけ複写され、有効hashを保持することを確認する。
		for( const std::wstring &path : closurePaths) {
			const auto entry = std::ranges::find_if(
				extractedEntries, [&path]( const OfficialZipEntry &current) noexcept {
					return pathsEqual( current.relativePath, path) ;
				}) ; // 対応する複写済みentry。
			// 参照entryやhashが欠ける不完全な閉包を公開しない。
			if( entry == extractedEntries.end() || entry->sha256.empty()) {
				discardCreatedFiles( workspace, createdPaths) ;
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			orderedEntries.push_back( *entry) ;
		}

		OfficialDriverClosure closure ;	// 全検証成功後だけ結果へ移すdriver閉包。
		closure.entries = std::move( orderedEntries) ;
		closure.packages.push_back( std::move( package)) ;
		closure.archiveDepth	   = 1U ;
		closure.expandedBytes	   = closureBytes ;
		result.scanSessionId	   = request.scanSessionId ;
		result.sourceAcquisitionId = request.sourceAcquisitionId ;
		result.databaseSize		   = request.expectedDatabaseSize ;
		result.databaseSha256	   = request.expectedDatabaseSha256 ;
		result.selectedInfPath	   = selectedInf->targetRelativePath ;
		result.cabinetFileCount	   = inventory.files.size() ;
		result.closure			   = std::move( closure) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		discardCreatedFiles( workspace, createdPaths) ;
		result = {} ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( const std::length_error &) {
		discardCreatedFiles( workspace, createdPaths) ;
		result = {} ;
		return static_cast<NativeError>( E_INVALIDARG) ;
	} catch( ...) {
		discardCreatedFiles( workspace, createdPaths) ;
		result = {} ;
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}
}

} // namespace drivercrate
