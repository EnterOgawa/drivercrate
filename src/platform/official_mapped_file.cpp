//------------------------------------------------------------------------------
/**
 * @file official_mapped_file.cpp
 * @brief 固定入力と私有file-backed mappingを実装する。
 * @version 01.00.00
 * @date 2026/11/03
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/03  有界file mappingと固定handleの所有を追加。
 * </pre>
 *
 * @note 入力のwrite/deleteを許可せず、出力はCREATE_NEWされた自身のfileだけを後始末する。
 */
//------------------------------------------------------------------------------
#include "platform/official_mapped_file.h"
#include "platform/official_download_workspace.h"

#include <Windows.h>
#include <limits>
#include <new>
#include <utility>
#include <string>
#include <vector>

namespace drivercrate {

/** @brief view、mapping、file、先祖固定handleを逆順解放する所有状態。 */
struct OfficialMappedFile::State {
	/// 入力または出力fileを固定するhandle。
	HANDLE					   file{INVALID_HANDLE_VALUE} ;
	/// viewの元となる所有mapping。
	HANDLE					   mapping{} ;
	/// mappingの先頭。未取得ならnull。
	void					  *view{} ;
	/// 実file byte数。
	std::size_t				   length{} ;
	/// rename/reparse差替えを防ぐ先祖directoryの固定handle。
	std::vector<HANDLE>		   parents ;
	/// 出力時だけ借用する所有workspace。
	OfficialDownloadWorkspace *workspace{} ;
	/// createで自身が生成した相対file名。入力時は空。
	std::wstring			   name ;
	/** @brief 全resourceを解放して最初のOS診断を返す。
     * @return 元の最初の失敗HRESULT。再呼出し時は0。
     */
	NativeError				   release() noexcept
	{
		NativeError error{} ;	// 最初の解放診断だけを保持します。
		// Win32失敗の直後に元診断を取り込みます。
		const auto	record = [&]( BOOL success) noexcept {
			 // 後続cleanupの成功で先の失敗を隠しません。
			 if( !success && error == 0) {
				 const auto native = GetLastError() ;	// 元APIの診断です。
				 error = HRESULT_FROM_WIN32( native == ERROR_SUCCESS ? ERROR_GEN_FAILURE : native) ;
			 }
		 } ;
		// viewを失効させてからmapping/fileを閉じます。
		if( view != nullptr) {
			record( UnmapViewOfFile( view)) ;
			view = nullptr ;
		}

		// 有効なmappingだけを一度閉じます。
		if( mapping != nullptr) {
			record( CloseHandle( mapping)) ;
			mapping = nullptr ;
		}

		// 所有fileの終了診断を保持します。
		if( file != INVALID_HANDLE_VALUE) {
			record( CloseHandle( file)) ;
			file = INVALID_HANDLE_VALUE ;
		}

		// 固定した先祖だけを逆順に閉じます。
		for( auto parent = parents.rbegin(); parent != parents.rend(); ++parent) {
			record( CloseHandle( *parent)) ;
		}

		parents.clear() ;
		// 自身の新規fileだけを所有workspaceから回収します。
		if( workspace != nullptr && !name.empty()) {
			try {
				const auto discarded = workspace->discardFile( name) ;	// 元所有者の回収診断です。
				// 先行errorを保持し、後続の回収失敗も成功へ丸めません。
				if( error == 0) {
					error = discarded ;
				}
			} catch( const std::bad_alloc &) {
				// workspaceの追跡を残して最終回収へ委ねます。
				if( error == 0) {
					error = E_OUTOFMEMORY ;
				}
			}
		}

		workspace = nullptr ;
		name.clear() ;
		return error ;
	}
	/** @brief 取得途中も含めbest-effortで自身のresourceだけを回収する。 */
	~State()
	{
		static_cast<void>( release()) ;
	}
} ;

/** @see src/platform/official_mapped_file.h 宣言側の契約を正本とする。 */
OfficialMappedFile::OfficialMappedFile() noexcept = default ;
/** @see src/platform/official_mapped_file.h 宣言側の契約を正本とする。 */
OfficialMappedFile::~OfficialMappedFile() = default ;

/** @see src/platform/official_mapped_file.h 宣言側の契約を正本とする。 */
NativeError OfficialMappedFile::open( std::wstring_view path, std::uint64_t maximumBytes)
{
	// 既存ownerの上書きやlocal絶対path以外を拒否します。
	if( state_ || maximumBytes == 0U || path.size() < 4U || path.size() > 32767U ||
	   path[1] != L':' || path[2] != L'\\' || path.find( L':', 2U) != path.npos ||
	   path.find( L'\0') != path.npos ||
	   !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'))) {
		return E_INVALIDARG ;
	}

	try {
		auto			   state = std::make_unique<State>() ;	// 全取得成功まで非公開のownerです。
		const std::wstring input( path) ;						// Win32用の完全終端です。
		// Rootから先祖を固定し、既存junctionを辿りません。
		for( std::size_t end = 3U; end < input.size(); ++end) {
			// directoryの境界だけを開きます。
			if( end != 3U && input[end] != L'\\') {
				continue ;
			}

			const auto	 parent = input.substr( 0U, end) ;	// 元の先祖pathです。
			// 先祖directoryを固定する所有handleです。
			const HANDLE handle = CreateFileW(
				parent.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
				OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;
			// 未取得handleを固定済みへ数えません。
			if( handle == INVALID_HANDLE_VALUE) {
				return HRESULT_FROM_WIN32( GetLastError()) ;
			}

			BY_HANDLE_FILE_INFORMATION info{} ;	// 同handleの実属性です。
			// 同じhandleの属性取得結果です。
			const BOOL				   known = GetFileInformationByHandle( handle, &info) ;
			// 再解析先やdirectory以外を入力の先祖にしません。
			if( !known || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U ||
			   (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U) {
				CloseHandle( handle) ;
				return HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
			}

			try {
				state->parents.push_back( handle) ;
			} catch( const std::bad_alloc &) {
				CloseHandle( handle) ;
				throw ;
			}
		}

		state->file =
			CreateFileW( input.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
						FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr) ;
		// 固定入力を開けない場合はmappingを作りません。
		if( state->file == INVALID_HANDLE_VALUE) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		BY_HANDLE_FILE_INFORMATION info{} ;	// path照会ではなく固定handleの実属性です。
		// 不正属性の入力をmemoryへ公開しません。
		if( !GetFileInformationByHandle( state->file, &info) ||
		   (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
			   0U ||
		   info.nNumberOfLinks != 1U) {
			return HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
		}

		ULARGE_INTEGER size{} ;	// 64bitの実byte数です。
		size.LowPart  = info.nFileSizeLow ;
		size.HighPart = info.nFileSizeHigh ;
		// 宣言上限とaddress可能長を有限に保ちます。
		if( size.QuadPart == 0U || size.QuadPart > maximumBytes ||
		   size.QuadPart > std::numeric_limits<std::size_t>::max()) {
			return HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE) ;
		}

		state->length  = static_cast<std::size_t>( size.QuadPart) ;
		state->mapping = CreateFileMappingW( state->file, nullptr, PAGE_READONLY, 0U, 0U, nullptr) ;
		// OSのmapping失敗をheap全読取りへfallbackしません。
		if( !state->mapping) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		state->view = MapViewOfFile( state->mapping, FILE_MAP_READ, 0U, 0U, state->length) ;
		// 全view取得成功までownerを外へ渡しません。
		if( !state->view) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		state_ = std::move( state) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

/** @see src/platform/official_mapped_file.h 宣言側の契約を正本とする。 */
NativeError OfficialMappedFile::create( OfficialDownloadWorkspace &workspace, std::wstring_view name,
									   std::uint64_t bytes, std::uint64_t maximumBytes)
{
	// 共同quotaと一要求の有限枠は呼出側でも固定します。
	if( state_ || bytes == 0U || bytes > maximumBytes ||
	   bytes > std::numeric_limits<std::size_t>::max()) {
		return E_INVALIDARG ;
	}

	try {
		std::uint64_t available{} ;	// quotaを反映した同volumeの空きです。
		// 同volumeでの有限容量照会の元診断です。
		const auto	  capacity = workspace.queryAvailableBytes( available) ;
		// 不明容量や不足を大きなsparse fileで回避しません。
		if( capacity != 0 || bytes > available) {
			return capacity != 0 ? capacity : HRESULT_FROM_WIN32( ERROR_DISK_FULL) ;
		}

		auto state		   = std::make_unique<State>() ;	// 部分取得も回収するownerです。
		state->name		   = name ;
		const auto created = workspace.createFile( name, state->file) ;	// 既知新規fileだけです。
		// 既存fileやlinkを上書きしません。
		if( created != 0) {
			return created ;
		}

		state->workspace = &workspace ;
		state->length	 = static_cast<std::size_t>( bytes) ;
		state->mapping	 = CreateFileMappingW( state->file, nullptr, PAGE_READWRITE,
											  static_cast<DWORD>( bytes >> 32U),
											  static_cast<DWORD>( bytes & 0xffffffffU), nullptr) ;
		// 確保失敗時も所有fileだけを回収します。
		if( !state->mapping) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		state->view = MapViewOfFile( state->mapping, FILE_MAP_WRITE, 0U, 0U, state->length) ;
		// 失敗を大容量heap確保へfallbackしません。
		if( !state->view) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		state_ = std::move( state) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

/** @see src/platform/official_mapped_file.h 宣言側の契約を正本とする。 */
std::span<const std::byte> OfficialMappedFile::bytes() const noexcept
{
	return state_ ? std::span<const std::byte>{static_cast<const std::byte *>( state_->view),
											   state_->length}
				  : std::span<const std::byte>{} ;
}
/** @see src/platform/official_mapped_file.h 宣言側の契約を正本とする。 */
std::span<std::byte> OfficialMappedFile::writableBytes() noexcept
{
	return state_ && state_->workspace
			   ? std::span<std::byte>{static_cast<std::byte *>( state_->view), state_->length}
			   : std::span<std::byte>{} ;
}
/** @see src/platform/official_mapped_file.h 宣言側の契約を正本とする。 */
NativeError OfficialMappedFile::close() noexcept
{
	// 明示closeはdestructorと異なり最初の元診断を呼出側へ返します。
	if( !state_) {
		return 0 ;
	}

	const auto error = state_->release() ;	// 全resourceを一度だけ失効させます。
	state_.reset() ;
	return error ;
}
} // namespace drivercrate
