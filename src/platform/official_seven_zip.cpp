//------------------------------------------------------------------------------
/**
 * @file official_seven_zip.cpp
 * @brief 公式7z package有限展開実装。
 * @version 01.00.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  有限memory decoder境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  保護workspace選択展開を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Solid選択展開量の事前判定を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  選択量評価とmetadata allocationを分離。
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
 * @note LZMA SDKをread-only memory streamと有限allocatorの内側で使用します。選択fileが要求するsolid folder量をdecodeとfile作
 *       成より前に判定します。
 */
//------------------------------------------------------------------------------

#include "platform/official_seven_zip.h"

#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"

#include <Windows.h>

#include <7z.h>
#include <7zCrc.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t	SEVEN_ZIP_HEADER_BYTES		  = 32U ;					// 7z最小Signature Header長。
constexpr std::size_t	MAXIMUM_COMPONENT_CHARACTERS  = 96U ;					// 一path componentの固定上限。
constexpr UInt32		COPY_METHOD					  = 0x00000000U ;			// 7z Copy coder識別値。
constexpr UInt32		LZMA_METHOD					  = 0x00030101U ;			// 7z LZMA coder識別値。
constexpr UInt32		LZMA2_METHOD				  = 0x00000021U ;			// 7z LZMA2 coder識別値。
constexpr UInt32		X86_BCJ_METHOD				  = 0x03030103U ;			// 7z x86 BCJ filter識別値。
constexpr UInt32		X86_BCJ2_METHOD				  = 0x0303011bU ;			// 7z x86 BCJ2 filter識別値。
constexpr std::uint32_t MINIMUM_LZMA_DICTIONARY_BYTES = 4096U ;					// SDKが補正する最小辞書長。
constexpr UInt32		NO_FOLDER_INDEX = std::numeric_limits<UInt32>::max() ;	// Folderなしの値。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief SDK allocationに付加し、解放時に保持量を戻すheaderを表す。
 */
struct alignas( std::max_align_t) AllocationHeader {
	/// 上限計算へ含めたSDK要求byte数。
	std::size_t requestedSize ;
} ;

/**
 * @brief LZMA SDKの一allocatorに適用する同時保持量を管理する。
 */
struct BoundedAllocator {
	/// SDKへ公開するcallback table。必ず先頭に置く。
	ISzAlloc	interface ;
	/// 同時保持できる要求byte数上限。
	std::size_t maximumActiveBytes ;
	/// 一回で受理する要求byte数上限。
	std::size_t maximumSingleBytes ;
	/// 現在SDKへ貸し出している要求byte数。
	std::size_t activeBytes ;
	/// trueの場合はpolicy上限により拒否した。
	bool		limitExceeded ;
} ;

/**
 * @brief 所有しないarchive byte列をSDKのseek可能streamとして公開する。
 */
struct MemoryLookStream {
	/// SDKへ公開するcallback table。必ず先頭に置く。
	ILookInStream interface ;
	/// 呼出し中だけ有効なread-only archive先頭。
	const Byte	 *data ;
	/// Archive全体のbyte数。
	std::size_t	  size ;
	/// 次にLookまたはReadする0-origin位置。
	std::size_t	  position ;
} ;

/**
 * @brief Archive内のpath衝突確認で、fileと親directoryを区別する。
 */
enum class ArchiveNodeKind {
	/// 子nodeを保持できるdirectory。
	DIRECTORY,
	/// 子nodeを持てない通常file。
	FILE,
} ;

/**
 * @brief 正規化したarchive pathについて、種別と明示entryの既出状態を保持する。
 */
struct ArchiveNode {
	/// Windows上で衝突判定するnode種別。
	ArchiveNodeKind kind ;
	/// trueの場合は同名entryを既に一件受理済み。
	bool			explicitEntry ;
} ;

/**
 * @brief Workspaceから受け取ったfile handleをscope内で単独所有する。
 */
class UniqueFile final {
public:
	//------------------------------------------------------------------------------
	/**
     * @brief WorkspaceがCREATE_NEWで作成したhandleのscope管理を始める。
     *
     * @param[in] handle CloseHandleで解放する所有file handle。
     */
	//------------------------------------------------------------------------------
	explicit UniqueFile( const HANDLE handle) noexcept : handle_( handle)
	{
	}

	//------------------------------------------------------------------------------
	/**
     * @brief 所有file handleを解放する。
     *
     * 明示closeされていない有効handleを一度だけ解放する。
     */
	//------------------------------------------------------------------------------
	~UniqueFile()
	{
		// 無効な値を解放APIへ渡さず、保持している有効なresourceの後始末を行う。
		if( handle_ != INVALID_HANDLE_VALUE) {
			CloseHandle( handle_) ;
		}
	}

	/**
	 * @brief file HANDLEの解放責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	UniqueFile( const UniqueFile &) = delete ;
	/**
	 * @brief file HANDLEの解放責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	UniqueFile &operator=( const UniqueFile &) = delete ;
	/**
	 * @brief file HANDLEの解放責務を取得したfile ownerに留めるため、移動構築を禁止する。
	 */
	UniqueFile( UniqueFile &&) = delete ;
	/**
	 * @brief 取得したfile ownerへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	UniqueFile			&operator=( UniqueFile &&) = delete ;

	//------------------------------------------------------------------------------
	/**
     * @brief 所有file handleを参照する。
     *
     * 同期WriteFileへ貸し出す有効handleを返す。
     * @return 本instanceが所有するhandle。所有権は移動しない。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] HANDLE get() const noexcept
	{
		return handle_ ;
	}

	/**
	 * @brief 所有handleを明示的に閉じる。
	 * 所有file handleを明示的に閉じる。
	 * Hash計算またはcleanupより前にhandleを閉じ、二重解放を防ぐ。
	 * @return 成功または既に閉じている場合は0、CloseHandle失敗時はHRESULT。
	 */
	[[nodiscard]] NativeError close() noexcept ;

private:
	/// Destructorまたはcloseで解放する所有handle。
	HANDLE handle_{INVALID_HANDLE_VALUE} ;
} ;

static_assert( offsetof( BoundedAllocator, interface) == 0U) ;
static_assert( offsetof( MemoryLookStream, interface) == 0U) ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをNativeErrorへ変換する。
 *
 * SDK固有値をProvider共通の診断表現へ公開するために使う。
 *
 * @param[in] error 検証または展開失敗を表すWin32 error code。
 * @return HRESULT_FROM_WIN32で変換したbit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_seven_zip.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError UniqueFile::close() noexcept
{
	// 所有 handle がない場合は二重 close を行わず正常終了する。
	if( handle_ == INVALID_HANDLE_VALUE) {
		return 0 ;
	}

	const HANDLE handle = handle_ ;	// 今回CloseHandleへ渡す所有handle。
	handle_				= INVALID_HANDLE_VALUE ;
	// CloseHandle が失敗した場合は解放失敗の診断値を返す。
	if( CloseHandle( handle) == FALSE) {
		DWORD error = GetLastError() ;	// CloseHandleが設定した診断値。
		// Close 失敗に診断値がない場合も成功と扱わず無効 handle の失敗とする。
		if( error == ERROR_SUCCESS) {
			error = ERROR_INVALID_HANDLE ;
		}

		return nativeErrorFromWin32( error) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Allocator interfaceから所有状態を取得する。
 *
 * C callback境界で先頭memberのpointer-interconvertibilityを使用する。外部allocatorを本callbackへ渡してはならない。
 *
 * @param[in] interface 本fileが初期化したcallback table先頭。
 * @return callback tableを先頭memberに持つallocator状態への参照。
 */
//------------------------------------------------------------------------------
[[nodiscard]] BoundedAllocator &allocatorFromInterface( ISzAllocPtr interface) noexcept
{
	// LZMA SDKのC callbackはcontext引数を持たないため、先頭memberから所有構造へ戻す。
	return *reinterpret_cast<BoundedAllocator *>( const_cast<ISzAlloc *>( interface)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief SDK用memoryを有限に確保する。
 *
 * 一要求、合計、加算overflowを確認し、C境界から例外を出さない。
 *
 * @param[in,out] interface 同時保持量を管理するallocator interface。
 * @param[in] size SDKが要求するbyte数。
 * @return 成功時は最大alignmentを満たす所有memory、失敗時はnullptr。
 */
//------------------------------------------------------------------------------
[[nodiscard]] void *allocateBoundedSdkMemory( ISzAllocPtr interface, const std::size_t size) noexcept
{
	// Allocator context の欠落とゼロ長要求では memory を確保しない。
	if( interface == nullptr || size == 0U) {
		return nullptr ;
	}

	BoundedAllocator &allocator = allocatorFromInterface( interface) ;	// 所有上限状態。
	// 単一・累積確保上限と管理 header を含む size overflow を検出して拒否する。
	if( allocator.activeBytes > allocator.maximumActiveBytes ||
	   size > allocator.maximumSingleBytes ||
	   size > allocator.maximumActiveBytes - allocator.activeBytes ||
	   size > std::numeric_limits<std::size_t>::max() - sizeof( AllocationHeader)) {
		allocator.limitExceeded = true ;
		return nullptr ;
	}

	void *const allocation =
		// SDKへ貸し出すheader付きmemory。
		std::malloc( sizeof( AllocationHeader) + size) ;
	// Memory 確保に失敗した場合は管理情報を書き込まず null を返す。
	if( allocation == nullptr) {
		return nullptr ;
	}

	auto *const header	  = static_cast<AllocationHeader *>( allocation) ;	// 解放時に参照するheader。
	header->requestedSize = size ;
	allocator.activeBytes += size ;
	return header + 1 ;
}

//------------------------------------------------------------------------------
/**
 * @brief SDK用memoryを解放する。
 *
 * SDKが返却した要求sizeを現在保持量から除き、一度だけ解放する。
 *
 * @param[in,out] interface 同時保持量を管理するallocator interface。
 * @param[in] address 本allocatorが返した所有memory。nullptr可。
 */
//------------------------------------------------------------------------------
void freeBoundedSdkMemory( ISzAllocPtr interface, void *address) noexcept
{
	// Allocator context または解放対象がない場合は所有 memory に触れない。
	if( interface == nullptr || address == nullptr) {
		return ;
	}

	BoundedAllocator &allocator = allocatorFromInterface( interface) ;		// 所有上限状態。
	auto *const header = static_cast<AllocationHeader *>( address) - 1 ;	// 確保時に付加したheader。
	// 管理対象の残量を超えない解放量だけを累積確保量から差し引く。
	if( header->requestedSize <= allocator.activeBytes) {
		allocator.activeBytes -= header->requestedSize ;
	} else {
		// SDK外からのpointerは契約違反のため、保持量を安全側へ固定する。
		allocator.activeBytes = 0U ;
	}

	std::free( header) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Memory stream interfaceから所有状態を取得する。
 *
 * C callback境界で先頭memberのpointer-interconvertibilityを使用し、archiveの所有権は移動しない。
 *
 * @param[in] interface 本fileが初期化したcallback table先頭。
 * @return callback tableを先頭memberに持つstream状態への参照。
 */
//------------------------------------------------------------------------------
[[nodiscard]] MemoryLookStream &streamFromInterface( ILookInStreamPtr interface) noexcept
{
	// LZMA SDKのC callbackはcontext引数を持たないため、先頭memberから所有構造へ戻す。
	return *reinterpret_cast<MemoryLookStream *>( const_cast<ILookInStream *>( interface)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Memory streamの現在位置を参照する。
 *
 * Positionを進めず、archive末尾を超えない範囲だけを公開する。
 *
 * @param[in,out] interface 現在位置を保持するstream interface。
 * @param[out] buffer 現在位置から始まる非所有read-only領域。
 * @param[in,out] size 入力は要求上限、出力は連続参照可能なbyte数。
 * @return 正常時はSZ_OK、引数不正時はSZ_ERROR_PARAM。
 */
//------------------------------------------------------------------------------
[[nodiscard]] SRes lookMemoryStream( ILookInStreamPtr interface, const void **buffer,
									std::size_t *size) noexcept
{
	// Stream と出力先の必須 pointer が欠ける参照要求を拒否する。
	if( interface == nullptr || buffer == nullptr || size == nullptr) {
		return SZ_ERROR_PARAM ;
	}

	MemoryLookStream &stream = streamFromInterface( interface) ;	// 現在のstream状態。
	// 現在位置が stream 末尾を超える不正状態では data を参照しない。
	if( stream.position > stream.size) {
		return SZ_ERROR_PARAM ;
	}

	const std::size_t available = stream.size - stream.position ;	// 末尾までの残りbyte数。
	*size						= std::min( *size, available) ;
	*buffer						= stream.data + stream.position ;
	return SZ_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief Memory streamの現在位置を進める。
 *
 * SDKがLookで確認した範囲外へpositionを移動させない。
 *
 * @param[in,out] interface 現在位置を保持するstream interface。
 * @param[in] offset 直前のLook範囲内で進めるbyte数。
 * @return 正常時はSZ_OK、末尾超過または引数不正はSZ_ERROR_PARAM。
 */
//------------------------------------------------------------------------------
[[nodiscard]] SRes skipMemoryStream( ILookInStreamPtr interface, const std::size_t offset) noexcept
{
	// Stream context がない位置更新要求を拒否する。
	if( interface == nullptr) {
		return SZ_ERROR_PARAM ;
	}

	MemoryLookStream &stream = streamFromInterface( interface) ;	// 現在のstream状態。
	// 現在位置が stream の範囲外なら残量計算を行わない。
	if( stream.position > stream.size) {
		return SZ_ERROR_PARAM ;
	}

	// Skip 量が残り data を超える場合は位置を変更しない。
	if( offset > stream.size - stream.position) {
		return SZ_ERROR_PARAM ;
	}

	stream.position += offset ;
	return SZ_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief Memory streamからbyte列を読み取る。
 *
 * Archive末尾で短い読取りを返し、positionを実読取り分進める。
 *
 * @param[in,out] interface 現在位置を保持するstream interface。
 * @param[out] buffer 読取りbyteの呼出し側所有領域。
 * @param[in,out] size 入力は領域長、出力は実際に読み取ったbyte数。
 * @return 正常時はSZ_OK、引数不正時はSZ_ERROR_PARAM。
 */
//------------------------------------------------------------------------------
[[nodiscard]] SRes readMemoryStream( ILookInStreamPtr interface, void *buffer,
									std::size_t *size) noexcept
{
	// Stream、長さ出力、必要な読取り buffer の欠落を拒否する。
	if( interface == nullptr || size == nullptr || (buffer == nullptr && *size != 0U)) {
		return SZ_ERROR_PARAM ;
	}

	MemoryLookStream &stream = streamFromInterface( interface) ;	// 現在のstream状態。
	// 読取り位置が stream 範囲外の場合は不正 parameter とする。
	if( stream.position > stream.size) {
		return SZ_ERROR_PARAM ;
	}

	const std::size_t available = stream.size - stream.position ;	// 末尾までの残りbyte数。
	const std::size_t readSize	= std::min( *size, available) ;		// 今回複写するbyte数。
	// 実読取り量がある場合だけ buffer へ byte 列をコピーする。
	if( readSize != 0U) {
		std::memcpy( buffer, stream.data + stream.position, readSize) ;
	}

	stream.position += readSize ;
	*size = readSize ;
	return SZ_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief Memory streamの絶対位置を計算する。
 *
 * 符号付き加減算のoverflowを避けてseek範囲を検証する。
 *
 * @param[in] current 現在位置。
 * @param[in] size Archive全体のbyte数。
 * @param[in] requested Originからの符号付き移動量。
 * @param[in] origin SDKが指定した基準位置。
 * @param[out] result 成功時の0以上size以下の絶対位置。
 * @return Archive内または末尾位置へ移動できる場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool calculateSeekPosition( const std::size_t current, const std::size_t size,
										 const Int64 requested, const ESzSeek origin,
										 std::size_t &result) noexcept
{
	// 既に範囲外の現在位置から seek 先を計算しない。
	if( current > size) {
		return false ;
	}

	std::size_t base{} ;	// Originが示す移動前の絶対位置。
	// 先頭・現在・末尾の seek 原点を選び、未知 origin を拒否する。
	switch( origin) {
		// 先頭基準のseekは、stream開始位置からoffsetを評価する。
		case SZ_SEEK_SET:
			base = 0U ;
			break ;

		// 相対seekは、現在位置を基準として境界を評価する。
		case SZ_SEEK_CUR:
			base = current ;
			break ;

		// 末尾基準のseekは、stream長を基準として境界を評価する。
		case SZ_SEEK_END:
			base = size ;
			break ;

		// 未知のseek基準から、移動先の絶対位置を推測しない。
		default:
			return false ;
	}

	// 非負の移動量は原点から末尾までの範囲で前進させる。
	if( requested >= 0) {
		const std::uint64_t forward = static_cast<std::uint64_t>( requested) ;	// 前進byte数。
		// 前進量が原点からの残量を超える seek は拒否する。
		if( forward > static_cast<std::uint64_t>( size - base)) {
			return false ;
		}

		result = base + static_cast<std::size_t>( forward) ;
		return true ;
	}

	const std::uint64_t backward =
		// INT64_MINでも安全な後退量。
		static_cast<std::uint64_t>( -(requested + 1)) + 1U ;
	// 後退量が原点より大きい場合は先頭より前へ移動させない。
	if( backward > static_cast<std::uint64_t>( base)) {
		return false ;
	}

	result = base - static_cast<std::size_t>( backward) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Memory streamをseekする。
 *
 * Archive外へのseekを拒否し、成功時だけpositionを更新する。
 *
 * @param[in,out] interface 現在位置を保持するstream interface。
 * @param[in,out] position 入力は移動量、出力は新しい絶対位置。
 * @param[in] origin 移動量の基準位置。
 * @return 正常時はSZ_OK、範囲または引数不正時はSZ_ERROR_PARAM。
 */
//------------------------------------------------------------------------------
[[nodiscard]] SRes seekMemoryStream( ILookInStreamPtr interface, Int64 *position,
									const ESzSeek origin) noexcept
{
	// Stream context または位置の入出力先がない seek を拒否する。
	if( interface == nullptr || position == nullptr) {
		return SZ_ERROR_PARAM ;
	}

	MemoryLookStream &stream = streamFromInterface( interface) ;	// 現在のstream状態。
	std::size_t		  target{} ;									// 検証後の絶対位置。
	// 要求位置を安全な範囲へ解決できなければ現在位置を変更しない。
	if( !calculateSeekPosition( stream.position, stream.size, *position, origin, target)) {
		return SZ_ERROR_PARAM ;
	}

	stream.position = target ;
	*position		= static_cast<Int64>( target) ;
	return SZ_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief LZMA SDKのCRC tableを一度だけ初期化する。
 *
 * C++のthread-safe static初期化で同時初回呼出しを直列化する。
 */
//------------------------------------------------------------------------------
void ensureCrcTableInitialized() noexcept
{
	static const bool INITIALIZED = []() noexcept {
		CrcGenerateTable() ;
		return true ;
	}() ; // Process内で一度だけ完了するSDK CRC table初期化結果。
	static_cast<void>( INITIALIZED) ;
}

/**
 * @brief SDK database、allocator、展開cacheの解放をscope終了時に保証する。
 */
class SevenZipReader final {
public:
	//------------------------------------------------------------------------------
	/**
     * @brief Read-only streamと二つの有限allocatorでSDK databaseを開く。
     *
     * @param[in] archive Instance存続中に有効な7z全byte列。
     * @param[in] policy 事前検証済みのallocator上限。
     */
	//------------------------------------------------------------------------------
	SevenZipReader( const std::span<const std::byte>		   archive,
				   const OfficialSevenZipExtractionPolicy &policy) noexcept
	{
		mainAllocator_.interface.Alloc	  = allocateBoundedSdkMemory ;
		mainAllocator_.interface.Free	  = freeBoundedSdkMemory ;
		mainAllocator_.maximumActiveBytes = static_cast<std::size_t>( policy.maximumAllocatorBytes) ;
		mainAllocator_.maximumSingleBytes =
			static_cast<std::size_t>( policy.maximumSingleAllocationBytes) ;

		temporaryAllocator_.interface.Alloc = allocateBoundedSdkMemory ;
		temporaryAllocator_.interface.Free	= freeBoundedSdkMemory ;
		temporaryAllocator_.maximumActiveBytes =
			static_cast<std::size_t>( policy.maximumAllocatorBytes) ;
		temporaryAllocator_.maximumSingleBytes =
			static_cast<std::size_t>( policy.maximumSingleAllocationBytes) ;

		stream_.interface.Look = lookMemoryStream ;
		stream_.interface.Skip = skipMemoryStream ;
		stream_.interface.Read = readMemoryStream ;
		stream_.interface.Seek = seekMemoryStream ;
		// std::byteとSDK Byteは共に一byte型であり、read-only C API境界だけでviewを変換する。
		stream_.data = reinterpret_cast<const Byte *>( archive.data()) ;
		stream_.size = archive.size() ;
		SzArEx_Init( &database_) ;
		ensureCrcTableInitialized() ;
		openResult_ = SzArEx_Open( &database_, &stream_.interface, &mainAllocator_.interface,
								  &temporaryAllocator_.interface) ;
	}

	//------------------------------------------------------------------------------
	/**
     * @brief 7z readerを終了する。
     *
     * 展開cacheとdatabase allocationを対応allocatorへ返却する。
     */
	//------------------------------------------------------------------------------
	~SevenZipReader()
	{
		ISzAlloc_Free( &mainAllocator_.interface, extractedBuffer_) ;
		SzArEx_Free( &database_, &mainAllocator_.interface) ;
	}

	/**
	 * @brief 7z database・展開cacheとallocatorの対応の二重管理を防ぐため、コピー構築を禁止する。
	 */
	SevenZipReader( const SevenZipReader &) = delete ;
	/**
	 * @brief 7z database・展開cacheとallocatorの対応を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	SevenZipReader &operator=( const SevenZipReader &) = delete ;
	/**
	 * @brief 7z database・展開cacheとallocatorの対応を元の7z readerに留めるため、移動構築を禁止する。
	 */
	SevenZipReader( SevenZipReader &&) = delete ;
	/**
	 * @brief 元の7z readerへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	SevenZipReader	  &operator=( SevenZipReader &&) = delete ;

	//------------------------------------------------------------------------------
	/**
     * @brief Archive open結果を取得する。
     *
     * 呼出し側で上限拒否flagと合わせてNativeErrorへ変換する。
     * @return `SzArEx_Open`が返したSDK result code。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] SRes openResult() const noexcept
	{
		return openResult_ ;
	}

	//------------------------------------------------------------------------------
	/**
     * @brief Allocation上限拒否の有無を取得する。
     *
     * 実memory不足と入力起因の上限超過を診断上で区別する。
     * @return いずれかのallocatorがpolicy上限で拒否した場合は`true`。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] bool limitExceeded() const noexcept
	{
		return mainAllocator_.limitExceeded || temporaryAllocator_.limitExceeded ;
	}

	//------------------------------------------------------------------------------
	/**
     * @brief Open済みSDK databaseを参照する。
     *
     * Open成功後のpreflight中だけmetadataを参照させる。
     * @return 本instanceが所有するSDK databaseへのconst参照。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] const CSzArEx &database() const noexcept
	{
		return database_ ;
	}

	//------------------------------------------------------------------------------
	/**
     * @brief 指定entryをSDKで展開する。
     *
     * Buffer所有権をinstanceへ保持し、呼出し側へは渡さない。
     *
     * @param[in] archiveIndex Preflight済みの通常file index。
     * @param[out] offset 成功時のsolid block内file開始位置。
     * @param[out] processedSize 成功時のfile byte数。
     * @return SDKの展開およびCRC検証結果。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] SRes extract( const UInt32 archiveIndex, std::size_t &offset,
							   std::size_t &processedSize) noexcept
	{
		return SzArEx_Extract( &database_, &stream_.interface, archiveIndex, &blockIndex_,
							  &extractedBuffer_, &extractedBufferSize_, &offset, &processedSize,
							  &mainAllocator_.interface, &temporaryAllocator_.interface) ;
	}

	//------------------------------------------------------------------------------
	/**
     * @brief 展開済みsolid blockを参照する。
     *
     * SDK所有bufferの所有権を移さず、検証後の複写だけに使う。
     * @return 次のextractまたはdestructorまで有効なread-only byte列。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] std::span<const Byte> extractedBlock() const noexcept
	{
		return {extractedBuffer_, extractedBufferSize_} ;
	}

private:
	/// Databaseと展開buffer用有限allocator。
	BoundedAllocator mainAllocator_{} ;
	/// Openとdecode作業用有限allocator。
	BoundedAllocator temporaryAllocator_{} ;
	/// 呼出し側archiveを所有しないSDK stream。
	MemoryLookStream stream_{} ;
	/// Main allocatorで所有する7z metadata。
	CSzArEx			 database_{} ;
	/// Archive openのSDK result code。
	SRes			 openResult_{SZ_ERROR_FAIL} ;
	/// Extract cacheが保持するfolder index。
	UInt32			 blockIndex_{NO_FOLDER_INDEX} ;
	/// Main allocator所有のsolid block buffer。
	Byte			*extractedBuffer_{} ;
	/// Solid block bufferのbyte数。
	std::size_t		 extractedBufferSize_{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief Metadata上限とdecoder allocation上限を独立に検証し、SDKへnarrowingして渡す前に型範囲を確認する。
 *
 * @param[in] archive 検証対象7z全byte列。
 * @param[in] policy 呼出側が固定した有限上限。
 * @return 整合する有限policyは0、不正値または入力超過はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validatePolicy( const std::span<const std::byte>		 archive,
										 const OfficialSevenZipExtractionPolicy &policy) noexcept
{
	// ゼロ上限と相互に矛盾する展開・確保 policy を SDK 呼出し前に拒否する。
	if( policy.maximumArchiveBytes == 0U || policy.maximumSingleFileBytes == 0U ||
	   policy.maximumTotalExpandedBytes == 0U || policy.maximumSolidBlockBytes == 0U ||
	   policy.maximumDictionaryBytes == 0U || policy.maximumAllocatorBytes == 0U ||
	   policy.maximumSingleAllocationBytes == 0U || policy.maximumEntryCount == 0U ||
	   policy.maximumPathCharacters == 0U ||
	   policy.maximumSingleFileBytes > policy.maximumTotalExpandedBytes ||
	   policy.maximumSingleFileBytes > policy.maximumSolidBlockBytes ||
	   policy.maximumSingleAllocationBytes > policy.maximumAllocatorBytes) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	constexpr std::uint64_t MAXIMUM_SIZE =
		// size_t上限。
		static_cast<std::uint64_t>( std::numeric_limits<std::size_t>::max()) ;
	constexpr std::uint64_t MAXIMUM_SEEK =
		// SDK seek上限。
		static_cast<std::uint64_t>( std::numeric_limits<Int64>::max()) ;
	// Address 空間で表現できない archive・展開・確保上限を拒否する。
	if( policy.maximumArchiveBytes > MAXIMUM_SIZE || policy.maximumSingleFileBytes > MAXIMUM_SIZE ||
	   policy.maximumSolidBlockBytes > MAXIMUM_SIZE ||
	   policy.maximumAllocatorBytes > MAXIMUM_SIZE ||
	   policy.maximumSingleAllocationBytes > MAXIMUM_SIZE) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 最小 7z header より短い入力は archive として扱わない。
	if( archive.size() < SEVEN_ZIP_HEADER_BYTES) {
		return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
	}

	// Archive が取得上限または seek の表現範囲を超える場合は拒否する。
	if( static_cast<std::uint64_t>( archive.size()) > policy.maximumArchiveBytes ||
	   static_cast<std::uint64_t>( archive.size()) > MAXIMUM_SEEK) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASCII文字を小文字へ変換する。
 *
 * Localeに依存しないWindows名衝突keyを構築する。
 *
 * @param[in] value 検証済みASCII文字。
 * @return `A`～`Z`は小文字、それ以外は入力値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] wchar_t asciiLower( const wchar_t value) noexcept
{
	// ASCII 大文字だけを小文字へ変換し、その他の文字は保持する。
	if( value >= L'A' && value <= L'Z') {
		return static_cast<wchar_t>( value - L'A' + L'a') ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windowsで禁止するpath文字か判定する。
 *
 * Separator以外のcomponent文字をfile作成前に限定する。
 *
 * @param[in] value 検査するASCII文字。
 * @return 制御文字またはWindows禁止記号の場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isForbiddenPathCharacter( const wchar_t value) noexcept
{
	return value < L' ' || value == L'<' || value == L'>' || value == L':' || value == L'"' ||
		   value == L'|' || value == L'?' || value == L'*' ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows予約device名か判定する。
 *
 * Windowsで通常fileとして安全に作成できないDOS device名を拒否する。
 *
 * @param[in] component Separatorを含まない検証対象名。
 * @return 拡張子の有無にかかわらず予約名の場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isReservedComponent( const std::wstring_view component)
{
	const std::size_t		dot	 = component.find( L'.') ;		// 拡張子より前のdevice名範囲。
	const std::wstring_view stem = component.substr( 0U, dot) ;	// 小文字化前のbasename。
	std::wstring			lowered ;							// Locale非依存で小文字化したbasename。
	lowered.reserve( stem.size()) ;
	// 予約名比較のため、basenameだけをASCII小文字へ変換する。
	for( const wchar_t character : stem) {
		lowered.push_back( asciiLower( character)) ;
	}

	// 固定の Windows 予約 device 名を通常 path 要素として使用させない。
	if( lowered == L"con" || lowered == L"prn" || lowered == L"aux" || lowered == L"nul") {
		return true ;
	}

	return lowered.size() == 4U && (lowered.starts_with( L"com") || lowered.starts_with( L"lpt")) &&
		   lowered[3] >= L'1' && lowered[3] <= L'9' ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのpath componentを検証する。
 *
 * 空、dot、末尾dot／space、固定長超過、予約名を拒否する。
 *
 * @param[in] component Separatorを含まないASCII名。
 * @return Windowsで安全な通常名として受理できる場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validatePathComponent( const std::wstring_view component)
{
	// 空・長さ超過・dot 要素・曖昧な末尾・予約名を持つ path 要素を拒否する。
	if( component.empty() || component.size() > MAXIMUM_COMPONENT_CHARACTERS || component == L"." ||
	   component == L".." || component.back() == L'.' || component.back() == L' ' ||
	   isReservedComponent( component)) {
		return false ;
	}

	// Component内の全文字がWindowsの通常名として利用できることを確認する。
	for( const wchar_t character : component) {
		// 禁止文字を含む path 要素は出力名として受理しない。
		if( isForbiddenPathCharacter( character)) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief SDK entry名を安全な相対pathへ変換する。
 *
 * UTF-16名をSDKから取得し、file作成に不適切な表現を拒否する。
 *
 * @param[in] database Open済みSDK database。
 * @param[in] archiveIndex 読み取るentry index。
 * @param[in] maximumCharacters 終端を除くpath文字数上限。
 * @param[out] path 成功時の`\\`区切りASCII相対path。
 * @return 安全な相対pathは0、文字、終端、component不正はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError parseEntryPath( const CSzArEx &database, const UInt32 archiveIndex,
										 const std::uint32_t maximumCharacters, std::wstring &path)
{
	path.clear() ;
	const std::size_t nameUnits =
		// 終端を含むUTF-16単位数。
		SzArEx_GetFileNameUtf16( &database, archiveIndex, nullptr) ;
	// 空名または policy の文字数上限を超える entry 名を拒否する。
	if( nameUnits <= 1U || nameUnits - 1U > maximumCharacters) {
		return nativeErrorFromWin32( ERROR_FILENAME_EXCED_RANGE) ;
	}

	std::vector<UInt16> name( nameUnits) ;	// SDKがUTF-16名を書き込む一時領域。
	// 予定した文字数と終端を取得できない SDK entry 名を拒否する。
	if( SzArEx_GetFileNameUtf16( &database, archiveIndex, name.data()) != nameUnits ||
	   name.back() != 0U) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::wstring parsed ;		// 全検証成功まで非公開の正規化path。
	std::wstring component ;	// 現在検証中のseparator間component。
	parsed.reserve( nameUnits - 1U) ;
	component.reserve( std::min<std::size_t>( nameUnits - 1U, MAXIMUM_COMPONENT_CHARACTERS)) ;
	// 終端を除く全UTF-16単位をASCIIとして検証し、separatorを統一する。
	for( std::size_t index = 0U; index + 1U < nameUnits; ++index) {
		const UInt16 unit = name[index] ;	// 現在のUTF-16 code unit。
		// 埋込み NUL と非 ASCII の entry 名は許可する path 表現へ変換しない。
		if( unit == 0U || unit > 0x7fU) {
			return nativeErrorFromWin32( ERROR_INVALID_NAME) ;
		}

		const wchar_t character = static_cast<wchar_t>( unit) ;	// 検証済みASCII文字。
		// Path 区切りごとに要素を検証し、Windows の区切りへ統一する。
		if( character == L'\\' || character == L'/') {
			// 中間 path 要素の安全性が成立しなければ entry 全体を拒否する。
			if( !validatePathComponent( component)) {
				return nativeErrorFromWin32( ERROR_INVALID_NAME) ;
			}

			parsed.append( component) ;
			parsed.push_back( L'\\') ;
			component.clear() ;
			continue ;
		}

		// 要素内の禁止文字は正規化で救済せず拒否する。
		if( isForbiddenPathCharacter( character)) {
			return nativeErrorFromWin32( ERROR_INVALID_NAME) ;
		}

		component.push_back( character) ;
	}

	// 最後の path 要素も検証し、空の末尾や危険な file 名を許可しない。
	if( !validatePathComponent( component)) {
		return nativeErrorFromWin32( ERROR_INVALID_NAME) ;
	}

	parsed.append( component) ;
	path = std::move( parsed) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief PathをWindows衝突keyへ変換する。
 *
 * Archive内のcase-insensitiveな重複と親子衝突を検出する。
 *
 * @param[in] path 検証済みASCII相対pathまたはcomponent。
 * @return Locale非依存で小文字化した同一長のkey。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring makePathKey( const std::wstring_view path)
{
	std::wstring key ;	// 小文字化したWindows衝突key。
	key.reserve( path.size()) ;
	// 検証済みASCII pathを順序とseparatorを維持して小文字化する。
	for( const wchar_t character : path) {
		key.push_back( asciiLower( character)) ;
	}

	return key ;
}

//------------------------------------------------------------------------------
/**
 * @brief Archive pathを衝突mapへ登録する。
 *
 * Windowsのcase-insensitive名前解決で上書きとなる構造を拒否する。
 *
 * @param[in] path 検証済み相対path。
 * @param[in] directory trueの場合は明示directory entry。
 * @param[in,out] nodes 先行entryと暗黙親directoryの衝突map。
 * @return 新しい非衝突pathは0、重複またはfile／directory衝突はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError registerArchivePath( const std::wstring_view path, const bool directory,
											  std::map<std::wstring, ArchiveNode> &nodes)
{
	std::size_t	 componentStart{} ;	// 現在componentのpath内開始位置。
	std::wstring cumulative ;		// 現在位置までの小文字化済み相対path。
	// Separator単位で暗黙親directoryと最後の明示entryを順に登録する。
	while( componentStart < path.size()) {
		const std::size_t separator		 = path.find( L'\\', componentStart) ;		// 次のseparator位置。
		const bool		  finalComponent = separator == std::wstring_view::npos ;	// 最終要素判定。
		const std::size_t componentEnd =
			finalComponent ? path.size() : separator ;	// 現在componentの終端位置。
		const std::wstring componentKey =
			makePathKey( path.substr( componentStart,
									componentEnd - componentStart)) ;	// 小文字component。
		// 先行要素がある場合だけ path 区切りを挿入して累積名を構築する。
		if( !cumulative.empty()) {
			cumulative.push_back( L'\\') ;
		}

		cumulative.append( componentKey) ;
		const ArchiveNodeKind expectedKind =
			finalComponent && !directory ? ArchiveNodeKind::FILE
										 : ArchiveNodeKind::DIRECTORY ;	// 現在nodeの期待種別。
		auto [node, inserted] = nodes.try_emplace(
			cumulative, ArchiveNode{expectedKind, finalComponent}) ;	// 登録または既存node。
		// 既存 path node では file/directory 種別と明示 entry の重複を照合する。
		if( !inserted) {
			// 種別衝突と同じ最終 entry の重複は上書きを許可せず拒否する。
			if( node->second.kind != expectedKind ||
			   (finalComponent && node->second.explicitEntry)) {
				return nativeErrorFromWin32( ERROR_ALREADY_EXISTS) ;
			}

			// 暗黙の親 directory が明示 entry として現れた場合はその状態を記録する。
			if( finalComponent) {
				node->second.explicitEntry = true ;
			}
		}

		// 最終要素の登録を終えたら path 分解 loop を終了する。
		if( finalComponent) {
			break ;
		}

		componentStart = separator + 1U ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Coder property rangeを検証する。
 *
 * Property pointerを構築する前に加算overflowと範囲を確認する。
 *
 * @param[in] coder SDKが解析したcoder情報。
 * @param[in] encodedSize Folder metadata全体のbyte数。
 * @return Property rangeがfolder metadata内に収まる場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasCoderProperties( const CSzCoderInfo &coder,
									  const std::size_t	  encodedSize) noexcept
{
	return coder.PropsOffset <= encodedSize &&
		   static_cast<std::size_t>( coder.PropsSize) <= encodedSize - coder.PropsOffset ;
}

//------------------------------------------------------------------------------
/**
 * @brief Main coderのmethodとdictionaryを検証する。
 *
 * SDK decode前にCopy／LZMA／LZMA2と辞書量だけへ限定する。
 *
 * @param[in] coder 検証対象のmain coder。
 * @param[in] folderData Folder metadata先頭。
 * @param[in] encodedSize Folder metadataのbyte数。
 * @param[in] maximumDictionary 許可するdictionary byte数上限。
 * @return 許可methodとpropertyは0、未知、形式、上限違反はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateMainCoder( const CSzCoderInfo &coder, const Byte *folderData,
											const std::size_t	encodedSize,
											const std::uint64_t maximumDictionary) noexcept
{
	// 単一 stream と有効な property 領域を持たない主 coder を拒否する。
	if( coder.NumStreams != 1U || !hasCoderProperties( coder, encodedSize)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// 無圧縮方式では追加 property がない場合だけ受理する。
	if( coder.MethodID == COPY_METHOD) {
		return coder.PropsSize == 0U ? 0 : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const Byte *const properties = folderData + coder.PropsOffset ;	// 検証済みproperty先頭。
	std::uint64_t	  dictionarySize{} ;							// Propertyが要求するdictionary byte数。
	// LZMA 方式では固定 property から辞書長を取り出す。
	if( coder.MethodID == LZMA_METHOD) {
		// LZMA property の長さと先頭 parameter の許可範囲を検証する。
		if( coder.PropsSize != 5U || properties[0] >= 9U * 5U * 5U) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const std::uint32_t encodedDictionary =
			static_cast<std::uint32_t>( properties[1]) |
			(static_cast<std::uint32_t>( properties[2]) << 8U) |
			(static_cast<std::uint32_t>( properties[3]) << 16U) |
			(static_cast<std::uint32_t>( properties[4]) << 24U) ;	// Little-endian辞書長。
		dictionarySize = std::max( encodedDictionary, MINIMUM_LZMA_DICTIONARY_BYTES) ;
	}
	// LZMA2 方式では単一 property から辞書長を計算する。
	else if( coder.MethodID == LZMA2_METHOD) {
		// LZMA2 property の長さと値が定義範囲外なら拒否する。
		if( coder.PropsSize != 1U || properties[0] > 40U) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const unsigned int property = properties[0] ;	// LZMA2 dictionary property値。
		dictionarySize				= property == 40U ? std::numeric_limits<std::uint32_t>::max()
													  : static_cast<std::uint64_t>( 2U | (property & 1U))
												<< (property / 2U + 11U) ;
	} else {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	return dictionarySize <= maximumDictionary ? 0 : nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Folder coder構造を許可集合へ限定する。
 *
 * 単一main、main＋x86 BCJ、SDK既定BCJ2の三構造だけを受理する。
 *
 * @param[in] folder SDKが解析したfolder構造。
 * @param[in] folderData Folder metadata先頭。
 * @param[in] encodedSize Folder metadataのbyte数。
 * @param[in] maximumDictionary 許可するdictionary byte数上限。
 * @return 許可構造は0、未知codec、filterまたはtopologyはHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateFolderCoders( const CSzFolder &folder, const Byte *folderData,
											   const std::size_t   encodedSize,
											   const std::uint64_t maximumDictionary) noexcept
{
	// 単一 coder の folder は filter のない単一入力構造として検証する。
	if( folder.NumCoders == 1U) {
		// 単一 coder に余分な入力や bond がある構造を拒否する。
		if( folder.NumPackStreams != 1U || folder.PackStreams[0] != 0U || folder.NumBonds != 0U) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		return validateMainCoder( folder.Coders[0], folderData, encodedSize, maximumDictionary) ;
	}

	// 二つの coder は主 coder と x86 BCJ filter の固定接続だけを検証する。
	if( folder.NumCoders == 2U) {
		const CSzCoderInfo &filter = folder.Coders[1] ;	// Main coder後のx86 filter。
		// 許可した BCJ の方式・property・接続順と異なる構造は未対応として拒否する。
		if( folder.NumPackStreams != 1U || folder.PackStreams[0] != 0U || folder.NumBonds != 1U ||
		   folder.Bonds[0].InIndex != 1U || folder.Bonds[0].OutIndex != 0U ||
		   filter.MethodID != X86_BCJ_METHOD || filter.NumStreams != 1U || filter.PropsSize != 0U ||
		   !hasCoderProperties( filter, encodedSize)) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		return validateMainCoder( folder.Coders[0], folderData, encodedSize, maximumDictionary) ;
	}

	// 四つの coder は三入力の主 coder 群と BCJ2 の固定接続だけを検証する。
	if( folder.NumCoders == 4U) {
		const CSzCoderInfo &filter = folder.Coders[3] ;	// 三streamを結合するBCJ2 filter。
		// BCJ2 の入力数・接続順・filter 条件が許可構造と異なる場合は拒否する。
		if( folder.NumPackStreams != 4U || folder.PackStreams[0] != 2U ||
		   folder.PackStreams[1] != 6U || folder.PackStreams[2] != 1U ||
		   folder.PackStreams[3] != 0U || folder.NumBonds != 3U || folder.Bonds[0].InIndex != 5U ||
		   folder.Bonds[0].OutIndex != 0U || folder.Bonds[1].InIndex != 4U ||
		   folder.Bonds[1].OutIndex != 1U || folder.Bonds[2].InIndex != 3U ||
		   folder.Bonds[2].OutIndex != 2U || filter.MethodID != X86_BCJ2_METHOD ||
		   filter.NumStreams != 4U || filter.PropsSize != 0U ||
		   !hasCoderProperties( filter, encodedSize)) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		// BCJ2の三つのmain stream全てへ同じcodecとdictionary制限を適用する。
		for( UInt32 coderIndex = 0U; coderIndex < 3U; ++coderIndex) {
			const NativeError error =
				validateMainCoder( folder.Coders[coderIndex], folderData, encodedSize,
								  maximumDictionary) ;	// 現在main coderの検証結果。
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}
		}

		return 0 ;
	}

	return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全folderのcodecと展開量を検証する。
 *
 * 選択entry以外を含む全folderを展開前にfail-closedで確認する。
 *
 * @param[in] database Open済みSDK database。
 * @param[in] policy Dictionaryとsolid blockの有限上限。
 * @return 全folderが許可範囲なら0、形式、codec、上限違反はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateFolders( const CSzArEx							 &database,
										  const OfficialSevenZipExtractionPolicy &policy) noexcept
{
	const CSzAr &archive = database.db ;	// Folder metadataを保持するSDK archive。
	// Folder が存在するのに必要な metadata 配列が欠ける archive を拒否する。
	if( archive.NumFolders != 0U &&
	   (archive.FoCodersOffsets == nullptr || archive.CodersData == nullptr ||
		archive.FoToMainUnpackSizeIndex == nullptr)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// 選択外entryのfolderも含め、全codec、dictionary、solid sizeを検証する。
	for( UInt32 folderIndex = 0U; folderIndex < archive.NumFolders; ++folderIndex) {
		const std::size_t begin = archive.FoCodersOffsets[folderIndex] ;	// Metadata開始offset。
		const std::size_t end =
			archive.FoCodersOffsets[static_cast<std::size_t>( folderIndex) + 1U] ;	// 終端offset。
		// Coder data の終了位置が開始位置より前なら長さを計算しない。
		if( end < begin) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const Byte *const folderData = archive.CodersData + begin ;					// 現folder metadata先頭。
		CSzData			  encoded{folderData, end - begin} ;						// SDK folder parser入力。
		CSzFolder		  folder{} ;												// SDKが復元するcoder構造。
		const SRes		  parseResult = SzGetNextFolderItem( &folder, &encoded) ;	// Folder解析結果。
		// Folder 解析の失敗、未消費 data、出力 stream の不一致を拒否する。
		if( parseResult != SZ_OK || encoded.Size != 0U ||
		   folder.UnpackStream != archive.FoToMainUnpackSizeIndex[folderIndex]) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const NativeError coderError =
			validateFolderCoders( folder, folderData, end - begin,
								 policy.maximumDictionaryBytes) ;	// 許可codec検証結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( coderError != 0) {
			return coderError ;
		}

		const UInt64 unpackSize =
			// Solid blockの展開後byte数。
			SzAr_GetFolderUnpackSize( &archive, folderIndex) ;
		// Solid block の展開 size が許可上限を超える folder は展開しない。
		if( unpackSize > policy.maximumSolidBlockBytes) {
			return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief SDK resultをNativeErrorへ変換する。
 *
 * 上限拒否を通常のmemory不足より優先し、未知失敗を成功にしない。
 *
 * @param[in] result SDKが返したresult code。
 * @param[in] limitExceeded 有限allocatorが拒否したかの判定。
 * @return 正常時0、分類を維持したHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError translateSdkError( const SRes result, const bool limitExceeded) noexcept
{
	// Allocator 上限到達は一般の memory 不足と分けて size 超過として返す。
	if( limitExceeded) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	// SDK の正常終了は NativeError の成功値へ変換する。
	if( result == SZ_OK) {
		return 0 ;
	}

	// SDK の失敗種別を対応する memory・CRC・形式・I/O の診断値へ変換する。
	switch( result) {
		// decoderのmemory不足を、呼出側が識別できるHRESULTへ対応させる。
		case SZ_ERROR_MEM:
			return static_cast<NativeError>( E_OUTOFMEMORY) ;
		// CRC不一致は、読取り失敗と区別した整合性エラーとして返す。
		case SZ_ERROR_CRC:
			return nativeErrorFromWin32( ERROR_CRC) ;
		// 未対応方式は、壊れたarchiveと区別して返す。
		case SZ_ERROR_UNSUPPORTED:
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		// archive形式でない入力は、形式不正として返す。
		case SZ_ERROR_NO_ARCHIVE:
			return nativeErrorFromWin32( ERROR_BAD_FORMAT) ;
		// 入力の途中終端は、EOFの診断値として保持する。
		case SZ_ERROR_INPUT_EOF:
			return nativeErrorFromWin32( ERROR_HANDLE_EOF) ;
		// decoderの読取り失敗は、読取り障害の診断値へ対応させる。
		case SZ_ERROR_READ:
			return nativeErrorFromWin32( ERROR_READ_FAULT) ;
		// 不正な内容は、共通のデータ拒否結果へ合流する。
		case SZ_ERROR_DATA:
		// decoder引数の不整合も、成功にせずデータ拒否へ合流する。
		case SZ_ERROR_PARAM:
		// decoderの一般失敗は、共通のデータ拒否へ合流する。
		case SZ_ERROR_FAIL:
		// archive構造の破損は、共通のデータ拒否へ合流する。
		case SZ_ERROR_ARCHIVE:
		// 未知のSDK結果は、正常終了へ読み替えず不正データとして返す。
		default:
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Open済み7z全体を事前検証する。
 *
 * Folderと全entryを検証し、全成功後にだけ一覧を公開する。
 *
 * @param[in,out] reader 有限allocator内のSDK reader。
 * @param[in] policy 全entryとfolderへ適用する有限上限。
 * @param[out] entries 成功時の通常file一覧。
 * @return 全metadataが安全なら0、形式、path、重複、容量違反はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError preflightArchive( SevenZipReader						  &reader,
										   const OfficialSevenZipExtractionPolicy &policy,
										   std::vector<OfficialSevenZipEntry>	  &entries)
{
	entries.clear() ;
	const NativeError openError =
		// SDK open結果。
		translateSdkError( reader.openResult(), reader.limitExceeded()) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( openError != 0) {
		return openError ;
	}

	const CSzArEx &database = reader.database() ;	// Open済みarchive metadata。
	// 空 archive と entry 件数超過を区別して事前検証を拒否する。
	if( database.NumFiles == 0U || database.NumFiles > policy.maximumEntryCount) {
		return database.NumFiles == 0U ? nativeErrorFromWin32( ERROR_FILE_NOT_FOUND)
									   : nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	// Entry の size・種別・folder 対応の必須配列が欠ける archive を拒否する。
	if( database.UnpackPositions == nullptr || database.IsDirs == nullptr ||
	   database.FileToFolder == nullptr) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const NativeError folderError = validateFolders( database, policy) ;	// 全folder検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( folderError != 0) {
		return folderError ;
	}

	std::map<std::wstring, ArchiveNode> nodes ;					// Windows名衝突検出map。
	std::vector<OfficialSevenZipEntry>	inspected ;				// 全成功まで非公開の通常file一覧。
	std::uint64_t						totalExpandedBytes{} ;	// 通常fileの展開後size合計。
	inspected.reserve( database.NumFiles) ;
	// Directoryを含む全entryのpath、size、folder対応をarchive順に検証する。
	for( UInt32 archiveIndex = 0U; archiveIndex < database.NumFiles; ++archiveIndex) {
		const bool	 directory = SzArEx_IsDir( &database, archiveIndex) != 0 ;	// Entry種別。
		const UInt64 fileSize  = SzArEx_GetFileSize( &database, archiveIndex) ;	// 展開後size。
		// Directory entry に file data が宣言されている不整合を拒否する。
		if( directory && fileSize != 0U) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// 通常 file の宣言展開長が単一 file 上限を超える場合は拒否する。
		if( !directory && fileSize > policy.maximumSingleFileBytes) {
			return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
		}

		std::wstring	  path ;	// 検証後に公開候補へ移す正規化相対path。
		// Archive entryの相対pathを有限長で検証した結果。
		const NativeError pathError =
			parseEntryPath( database, archiveIndex, policy.maximumPathCharacters, path) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( pathError != 0) {
			return pathError ;
		}

		const NativeError collisionError =
			// Case-insensitive衝突検証結果。
			registerArchivePath( path, directory, nodes) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( collisionError != 0) {
			return collisionError ;
		}

		// Directory は path 衝突確認後に file 展開量の集計から除外する。
		if( directory) {
			continue ;
		}

		// 累積展開量へ加える前に全体上限からの残量を確認する。
		if( fileSize > policy.maximumTotalExpandedBytes - totalExpandedBytes) {
			return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
		}

		const UInt32 folderIndex = database.FileToFolder[archiveIndex] ;	// Entryのfolder index。
		// Data を持つ file の folder 欠落と範囲外 folder index を拒否する。
		if( (fileSize != 0U && folderIndex == NO_FOLDER_INDEX) ||
		   (folderIndex != NO_FOLDER_INDEX && folderIndex >= database.db.NumFolders)) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		totalExpandedBytes += fileSize ;
		inspected.push_back(
			OfficialSevenZipEntry{archiveIndex, std::move( path), fileSize, std::wstring{}}) ;
	}

	// 検証可能な通常 file が一つもない archive は対象なしとして返す。
	if( inspected.empty()) {
		return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
	}

	entries = std::move( inspected) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Decodeまたはfile作成前に選択集合をfail-closedで正規化する。
 *
 * @param[in] requested 呼出側が指定したarchive index集合。
 * @param[in] maximumEntryCount 一回で受理するindex件数上限。
 * @param[in] inspected 同じarchiveの検証済み通常file一覧。
 * @param[out] selected 成功時の昇順で重複のないindex集合。
 * @return 全indexが一意な通常fileを指す場合は0、拒否時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateAndSortSelectedIndices(
	const std::span<const std::uint32_t> requested, const std::uint32_t maximumEntryCount,
	const std::span<const OfficialSevenZipEntry> inspected, std::vector<std::uint32_t> &selected)
{
	selected.clear() ;
	// 空の展開選択を受理せず、無選択から全件展開へ変更しない。
	if( requested.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 選択件数が policy 上限を超える場合は正規化前に拒否する。
	if( requested.size() > maximumEntryCount) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	selected.assign( requested.begin(), requested.end()) ;
	std::ranges::sort( selected) ;
	const auto duplicate = std::ranges::adjacent_find( selected) ;	// 最初の重複index位置。
	// 重複選択があれば正規化結果を破棄し、同じ file の二重出力を防ぐ。
	if( duplicate != selected.end()) {
		selected.clear() ;
		return nativeErrorFromWin32( ERROR_ALREADY_EXISTS) ;
	}

	// 全選択indexが同じpreflight結果の通常fileを指すことを確認する。
	for( const std::uint32_t selectedIndex : selected) {
		const bool present = std::ranges::any_of(
			inspected, [selectedIndex]( const OfficialSevenZipEntry &entry) noexcept {
				return entry.archiveIndex == selectedIndex ;
			}) ; // 通常file存在判定。
		// 検証済み一覧にない選択は集合全体を破棄して拒否する。
		if( !present) {
			selected.clear() ;
			return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Packed dataを読まず、FileToFolderとunpack sizeだけからSDKが必要とする連続buffer量を算出する。
 *
 * @param[in] database Preflight済みのSDK database。
 * @param[in] selectedIndices 一意性と存在を検証済みのindex集合。
 * @param[in] maximumSingleAllocationBytes 現decoderの一要求上限。
 * @param[out] assessment 成功時の一意folder要求と上限判定。
 * @return 算出成功時は0、metadata矛盾または加算overflow時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError assessPreflightedSelection(
	const CSzArEx &database, const std::span<const std::uint32_t> selectedIndices,
	const std::uint64_t					 maximumSingleAllocationBytes,
	OfficialSevenZipSelectionAssessment &assessment)
{
	assessment = {} ;
	std::map<UInt32, std::uint32_t> selectedFolders ;	// Folder別の選択file件数。
	// 各選択fileをSDKがdecodeするfolderへ集約し、0-byteのfolderなしfileを除外する。
	for( const std::uint32_t selectedIndex : selectedIndices) {
		// Archive の file 数を超える選択 index は必要量計算へ渡さない。
		if( selectedIndex >= database.NumFiles) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const UInt32 folderIndex = database.FileToFolder[selectedIndex] ;	// SDK folder index。
		// Folder を持たない entry は空 file であることを確認して計算から除く。
		if( folderIndex == NO_FOLDER_INDEX) {
			// Folder がないのに非ゼロ size を持つ entry は不正として拒否する。
			if( SzArEx_GetFileSize( &database, selectedIndex) != 0U) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			continue ;
		}

		// 選択 file が参照する folder index の範囲外を拒否する。
		if( folderIndex >= database.db.NumFolders) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		auto folder = selectedFolders.find( folderIndex) ;	// 既出folderの件数位置。
		// 初めて参照する folder は選択一件として登録する。
		if( folder == selectedFolders.end()) {
			selectedFolders.emplace( folderIndex, 1U) ;
			continue ;
		}

		// 同一 folder の選択件数が counter 上限に達したら加算しない。
		if( folder->second == std::numeric_limits<std::uint32_t>::max()) {
			return nativeErrorFromWin32( ERROR_ARITHMETIC_OVERFLOW) ;
		}

		++folder->second ;
	}

	OfficialSevenZipSelectionAssessment calculated ;	// 全成功まで非公開の算出結果。
	calculated.folders.reserve( selectedFolders.size()) ;
	// Folder index順に一度だけunpack sizeを加算し、solid共有fileの重複計上を防ぐ。
	for( const auto &selectedFolder : selectedFolders) {
		const UInt32 folderIndex = selectedFolder.first ;	// 今回公開するfolder index。
		const UInt64 unpackSize =
			// Folder全体のdecode量。
			SzAr_GetFolderUnpackSize( &database.db, folderIndex) ;
		// 必要な展開量の合計が 64-bit を超える場合は計算を中止する。
		if( unpackSize >
		   std::numeric_limits<std::uint64_t>::max() - calculated.totalRequiredUncompressedBytes) {
			return nativeErrorFromWin32( ERROR_ARITHMETIC_OVERFLOW) ;
		}

		calculated.totalRequiredUncompressedBytes += unpackSize ;
		calculated.folders.push_back(
			OfficialSevenZipFolderRequirement{folderIndex, unpackSize, selectedFolder.second}) ;
		// Solid block の必要連続領域が単一確保上限を超える選択を分類する。
		if( unpackSize > maximumSingleAllocationBytes) {
			calculated.disposition = OfficialSevenZipSelectionDisposition::SOLID_BLOCK_TOO_LARGE ;
		}
	}

	assessment = std::move( calculated) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 事前検証済みentryをSDK bufferへ展開する。
 *
 * SDK所有権を移さず、完全検証した選択file範囲だけを貸し出す。
 *
 * @param[in,out] reader 全archiveをpreflight済みの有限reader。
 * @param[in] entry 同じreaderから得た通常file metadata。
 * @param[out] content 次のextractまで有効なSDK所有byte列。
 * @return CRC、size、buffer範囲が一致した場合は0、拒否時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError extractPreflightedEntry( SevenZipReader			  &reader,
												  const OfficialSevenZipEntry &entry,
												  std::span<const Byte>		  &content)
{
	content = {} ;
	std::size_t		  offset{} ;		// SDK solid block内の選択file開始位置。
	std::size_t		  processedSize{} ;	// SDKがCRC検証した選択file byte数。
	// 一entryの展開結果。Offsetと展開済み長の整合確認とは別に保持する。
	const SRes		  extractResult = reader.extract( entry.archiveIndex, offset, processedSize) ;
	const NativeError extractError =
		// SDK展開結果。
		translateSdkError( extractResult, reader.limitExceeded()) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( extractError != 0) {
		return extractError ;
	}

	const std::span<const Byte> block = reader.extractedBlock() ;	// SDK所有solid block全体。
	// 展開結果の size と block 内の範囲が宣言値に一致しなければ拒否する。
	if( processedSize != entry.uncompressedSize || offset > block.size() ||
	   processedSize > block.size() - offset) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	content = block.subspan( offset, processedSize) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 展開済みbyte列をfileへ完全に書き込む。
 *
 * DWORD上限ごとに前方へ進み、短い書込みも残量が0まで続ける。
 *
 * @param[in] file Workspaceが新規作成した所有中のfile handle。
 * @param[in] content SDKがCRC検証した選択file内容。
 * @return 全byte書込み成功時は0、無効handleまたは書込み失敗はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError writeExtractedFile( const HANDLE				 file,
											 const std::span<const Byte> content) noexcept
{
	// 無効な出力 handle へ展開結果を書き込まない。
	if( file == nullptr || file == INVALID_HANDLE_VALUE) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::size_t offset{} ;	// 次にfileへ保存するcontent内の位置。
	// WriteFileのDWORD上限単位で、検証済みfileの全byteを順に保存する。
	while( offset < content.size()) {
		const DWORD requested = static_cast<DWORD>( std::min<std::size_t>(
			// 今回の要求byte数。
			content.size() - offset, std::numeric_limits<DWORD>::max())) ;
		DWORD		written{} ;	// WriteFileが今回保存したbyte数。
		// 書込み失敗または進捗停止を検出した時点で出力を中止する。
		if( WriteFile( file, content.data() + offset, requested, &written, nullptr) == FALSE ||
		   written == 0U) {
			DWORD error = GetLastError() ;	// WriteFileが設定した診断値。
			// 進捗停止に診断値がない場合も成功にせず書込み失敗とする。
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
 * @brief 今回作成したworkspace fileを逆順に破棄する。
 *
 * 一次errorを保持するbest-effort rollbackであり、破棄失敗fileはworkspaceの追跡に残してdestructorで再試行する。
 *
 * @param[in,out] workspace File所有とdestructor fallbackを持つ領域。
 * @param[in] created 今回createFileに成功したentryの順序付き参照。
 */
//------------------------------------------------------------------------------
void cleanupCreatedFiles( OfficialDownloadWorkspace							&workspace,
						 const std::span<const OfficialSevenZipEntry *const> created) noexcept
{
	std::size_t remaining = created.size() ;	// 逆順で未処理の作成file数。
	// 子fileを先に処理できるよう、今回の作成順とは逆に既知pathだけを破棄する。
	while( remaining != 0U) {
		--remaining ;
		try {
			static_cast<void>( workspace.discardFile( created[remaining]->relativePath)) ;
		} catch( const std::bad_alloc &) {
			// Path変換用memory不足時も追跡を維持し、workspace destructorへ回収を委ねる。
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 選択展開を失敗として終了する。
 *
 * 部分結果を消去し、既存workspace要素を触らず今回分だけ戻す。
 *
 * @param[in] error 呼出側へ保持する最初の失敗診断値。
 * @param[in,out] workspace 今回作成分を追跡する保護領域。
 * @param[in] created 今回createFileに成功したentry群。
 * @param[out] entries 公開してはならない選択結果。
 * @return Cleanup結果で上書きしない最初の失敗診断値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError failSelectedExtraction(
	const NativeError error, OfficialDownloadWorkspace &workspace,
	const std::span<const OfficialSevenZipEntry *const> created,
	std::vector<OfficialSevenZipEntry>				   &entries) noexcept
{
	entries.clear() ;
	cleanupCreatedFiles( workspace, created) ;
	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 事前検証済みの選択file群をworkspaceへ展開する。
 *
 * Archive順に一readerを使用し、途中失敗時は今回作成分だけを逆順破棄する。
 *
 * @param[in,out] reader 全archiveをpreflight済みの有限reader。
 * @param[in] inspected Archive順の検証済み通常file一覧。
 * @param[in] selectedIndices 昇順で重複のない存在確認済みindex。
 * @param[in,out] workspace 選択fileをCREATE_NEWで所有する保護領域。
 * @param[out] entries 全成功時だけ公開するSHA-256付き一覧。
 * @return 全選択fileのCRC、書込み、close、hash成功時は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError extractPreflightedEntries(
	SevenZipReader &reader, const std::span<const OfficialSevenZipEntry> inspected,
	const std::span<const std::uint32_t> selectedIndices, OfficialDownloadWorkspace &workspace,
	std::vector<OfficialSevenZipEntry> &entries)
{
	entries.clear() ;
	std::vector<const OfficialSevenZipEntry *> created ;	// 今回作成済みfileのrollback参照。
	try {
		created.reserve( selectedIndices.size()) ;
		std::vector<OfficialSevenZipEntry> completed ;	// 全成功まで非公開の選択結果。
		completed.reserve( selectedIndices.size()) ;
		// Archive順に選択indexだけを展開し、solid block cacheを再利用する。
		for( const OfficialSevenZipEntry &entry : inspected) {
			// 選択集合に含まれない検証済み entry は展開しない。
			if( !std::ranges::binary_search( selectedIndices, entry.archiveIndex)) {
				continue ;
			}

			std::span<const Byte> content ;	// 次のextractまで有効な選択file内容。
			const NativeError	  extractError =
				// SDK CRCとrange検証結果。
				extractPreflightedEntry( reader, entry, content) ;
			// Decode 失敗時は今回作成済みの出力を取り消す。
			if( extractError != 0) {
				return failSelectedExtraction( extractError, workspace, created, entries) ;
			}

			HANDLE			  rawFile{INVALID_HANDLE_VALUE} ;	// Workspaceが作成する所有file handle。
			const NativeError createError =
				// CREATE_NEW境界の結果。
				workspace.createFile( entry.relativePath, rawFile) ;
			// 出力 file の作成失敗時はそれまでの選択出力も取り消す。
			if( createError != 0) {
				return failSelectedExtraction( createError, workspace, created, entries) ;
			}

			UniqueFile file( rawFile) ;	// 書込みと明示closeまでのhandle所有者。
			created.push_back( &entry) ;
			const NativeError writeError =
				// 完全書込み結果。
				writeExtractedFile( file.get(), content) ;
			// 書込み失敗時は handle を閉じて部分出力を破棄する。
			if( writeError != 0) {
				static_cast<void>( file.close()) ;
				return failSelectedExtraction( writeError, workspace, created, entries) ;
			}

			const NativeError closeError = file.close() ;	// Hash前の書込みhandle終了結果。
			// 出力の close 失敗も展開全体の失敗として後始末する。
			if( closeError != 0) {
				return failSelectedExtraction( closeError, workspace, created, entries) ;
			}

			OfficialSevenZipEntry completedEntry = entry ;	// Hash追加後に公開するentry。
			const std::wstring	  extractedPath =
				// 保護領域内の展開済み絶対path。
				workspace.path( entry.relativePath) ;
			// 作成済み file の検証用 path が解決できなければ出力を取り消す。
			if( extractedPath.empty()) {
				return failSelectedExtraction( static_cast<NativeError>( E_UNEXPECTED), workspace,
											  created, entries) ;
			}

			const NativeError hashError =
				// 内容識別結果。
				computeFileSha256( extractedPath, completedEntry.sha256) ;
			// 展開 file の hash を確定できなければ利用可能な出力として残さない。
			if( hashError != 0) {
				return failSelectedExtraction( hashError, workspace, created, entries) ;
			}

			completed.push_back( std::move( completedEntry)) ;
		}

		entries = std::move( completed) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return failSelectedExtraction( static_cast<NativeError>( E_OUTOFMEMORY), workspace, created,
									  entries) ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_seven_zip.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError inspectOfficialSevenZip( const std::span<const std::byte>		archive,
									const OfficialSevenZipExtractionPolicy &policy,
									std::vector<OfficialSevenZipEntry>	   &entries)
{
	entries.clear() ;
	const NativeError policyError = validatePolicy( archive, policy) ;	// 入力と上限の検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( policyError != 0) {
		return policyError ;
	}

	try {
		SevenZipReader reader( archive, policy) ;	// Scope内でSDK resourceを所有するreader。
		return preflightArchive( reader, policy, entries) ;
	} catch( const std::bad_alloc &) {
		entries.clear() ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_seven_zip.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError assessOfficialSevenZipSelection(
	const std::span<const std::byte> archive, const OfficialSevenZipExtractionPolicy &policy,
	const std::span<const std::uint32_t> selectedArchiveIndices,
	OfficialSevenZipSelectionAssessment &assessment)
{
	assessment					  = {} ;
	const NativeError policyError = validatePolicy( archive, policy) ;	// 入力と上限の検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( policyError != 0) {
		return policyError ;
	}

	// 必要量評価でも空選択を全件選択として解釈しない。
	if( selectedArchiveIndices.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 選択件数が policy 上限を超える場合は事前評価を拒否する。
	if( selectedArchiveIndices.size() > policy.maximumEntryCount) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	try {
		// Decode出力用の個別上限をmetadata構築へ誤適用しない有限policy。
		OfficialSevenZipExtractionPolicy metadataPolicy = policy ;
		metadataPolicy.maximumSingleAllocationBytes		= policy.maximumAllocatorBytes ;
		SevenZipReader reader( archive, metadataPolicy) ;	// Packed dataをdecodeしないSDK reader。
		std::vector<OfficialSevenZipEntry> inspected ;		// 全archiveの検証済み通常file一覧。
		// Archive全体の事前構造検査結果。選択index検証の前に確認する。
		const NativeError preflightError = preflightArchive( reader, policy, inspected) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( preflightError != 0) {
			return preflightError ;
		}

		std::vector<std::uint32_t> selected ;	// 昇順で重複のない検証済みindex集合。
		// 選択indexの上限・重複・存在を照合し、展開順へ並べた結果。
		const NativeError		   selectionError = validateAndSortSelectedIndices(
			 selectedArchiveIndices, policy.maximumEntryCount, inspected, selected) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( selectionError != 0) {
			return selectionError ;
		}

		return assessPreflightedSelection( reader.database(), selected,
										  policy.maximumSingleAllocationBytes, assessment) ;
	} catch( const std::bad_alloc &) {
		assessment = {} ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_seven_zip.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError extractOfficialSevenZipFile( const std::span<const std::byte>		archive,
										const OfficialSevenZipExtractionPolicy &policy,
										const std::uint32_t						archiveIndex,
										std::vector<std::byte>				   &content)
{
	content.clear() ;
	const NativeError policyError = validatePolicy( archive, policy) ;	// 入力と上限の検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( policyError != 0) {
		return policyError ;
	}

	try {
		SevenZipReader reader( archive, policy) ;		// Scope内でSDK resourceを所有するreader。
		std::vector<OfficialSevenZipEntry> entries ;	// 再preflightした通常file一覧。
		// 展開予算の評価前に行う、archive全体の事前検査結果。
		const NativeError preflightError = preflightArchive( reader, policy, entries) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( preflightError != 0) {
			return preflightError ;
		}

		const auto selected =
			std::ranges::find_if( entries, [archiveIndex]( const OfficialSevenZipEntry &entry) {
				return entry.archiveIndex == archiveIndex ;
			}) ; // 選択entry。
		// 検証済み entry に要求 index がない場合は展開しない。
		if( selected == entries.end()) {
			return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
		}

		const std::array selectedIndices{archiveIndex} ;	// 一件展開前のfolder量判定入力。
		OfficialSevenZipSelectionAssessment assessment ;	// Decode前の一意folder要求。
		// 選択範囲に必要なdecoder allocationを事前評価した結果。
		const NativeError					assessmentError = assessPreflightedSelection(
			  reader.database(), selectedIndices, policy.maximumSingleAllocationBytes, assessment) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( assessmentError != 0) {
			return assessmentError ;
		}

		// 必要な solid block が単一確保上限を超える場合は decode しない。
		if( assessment.disposition == OfficialSevenZipSelectionDisposition::SOLID_BLOCK_TOO_LARGE) {
			return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
		}

		std::span<const Byte> extractedView ;	// 次のextractまで有効なSDK所有file内容。
		const NativeError	  extractError =
			// CRCとrange検証結果。
			extractPreflightedEntry( reader, *selected, extractedView) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( extractError != 0) {
			return extractError ;
		}

		std::vector<std::byte> extracted( extractedView.size()) ;	// 成功まで非公開の内容copy。
		// 非空の展開結果だけを所有 buffer へコピーする。
		if( !extractedView.empty()) {
			std::memcpy( extracted.data(), extractedView.data(), extractedView.size()) ;
		}

		content = std::move( extracted) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		content.clear() ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_seven_zip.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError extractOfficialSevenZipFiles(
	const std::span<const std::byte> archive, const OfficialSevenZipExtractionPolicy &policy,
	const std::span<const std::uint32_t> selectedArchiveIndices,
	OfficialDownloadWorkspace &workspace, std::vector<OfficialSevenZipEntry> &entries)
{
	entries.clear() ;
	const NativeError policyError = validatePolicy( archive, policy) ;	// 入力と上限の検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( policyError != 0) {
		return policyError ;
	}

	// 空の出力選択は file 作成前に拒否する。
	if( selectedArchiveIndices.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 出力選択が件数上限を超える場合は file を作成しない。
	if( selectedArchiveIndices.size() > policy.maximumEntryCount) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	try {
		SevenZipReader					   reader( archive, policy) ;	// 一回だけ開く有限SDK reader。
		std::vector<OfficialSevenZipEntry> inspected ;					// 再preflightする通常file一覧。
		// 実際の選択展開前に行う、archive全体の事前検査結果。
		const NativeError preflightError = preflightArchive( reader, policy, inspected) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( preflightError != 0) {
			return preflightError ;
		}

		std::vector<std::uint32_t> selected ;	// 昇順で重複のない検証済みindex集合。
		// 選択展開対象のindexを検証し、archive順へ整えた結果。
		const NativeError		   selectionError = validateAndSortSelectedIndices(
			 selectedArchiveIndices, policy.maximumEntryCount, inspected, selected) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( selectionError != 0) {
			return selectionError ;
		}

		OfficialSevenZipSelectionAssessment assessment ;	// File作成前の一意folder要求。
		// 選択展開で使用するdecoder memoryが上限内かを評価した結果。
		const NativeError					assessmentError = assessPreflightedSelection(
			  reader.database(), selected, policy.maximumSingleAllocationBytes, assessment) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( assessmentError != 0) {
			return assessmentError ;
		}

		// 選択に必要な連続展開領域を確保できない場合は事前に拒否する。
		if( assessment.disposition == OfficialSevenZipSelectionDisposition::SOLID_BLOCK_TOO_LARGE) {
			return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
		}

		return extractPreflightedEntries( reader, inspected, selected, workspace, entries) ;
	} catch( const std::bad_alloc &) {
		entries.clear() ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

} // namespace drivercrate
