//------------------------------------------------------------------------------
/**
 * @file official_gzip.cpp
 * @brief 公式GZip catalog展開実装。
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
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note Network由来GZipを一つのmemberとして厳密に検証します。入力fileと出力handleの所有権は呼出し側にあり、失敗時に候補metadataを返しません。
 */
//------------------------------------------------------------------------------

#include "platform/official_gzip.h"

#include <miniz.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t  MINIMUM_GZIP_BYTES = 18 ;	// 固定header、空Deflate、trailerの最小長。
constexpr std::byte	   GZIP_MAGIC_FIRST{0x1f} ;		// GZip識別子の先頭byte。
constexpr std::byte	   GZIP_MAGIC_SECOND{0x8b} ;	// GZip識別子の二番目byte。
constexpr std::byte	   DEFLATE_METHOD{0x08} ;		// RFC 1952で許可するDeflate compression method。
constexpr std::uint8_t FLAG_HEADER_CRC = 0x02 ;		// Header CRC16が存在するflag。
constexpr std::uint8_t FLAG_EXTRA	   = 0x04 ;		// Extra fieldが存在するflag。
constexpr std::uint8_t FLAG_NAME	   = 0x08 ;		// Original file nameが存在するflag。
constexpr std::uint8_t FLAG_COMMENT	   = 0x10 ;		// Commentが存在するflag。
constexpr std::uint8_t RESERVED_FLAGS  = 0xe0 ;		// 受理しない予約済みflag群。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief CloseHandleでfile handleを解放する最小RAII wrapperである。
 */
class UniqueFile	   final {
public:
	  //------------------------------------------------------------------------------
	  /**
     * @brief file handleの所有権を受け取り、RAII管理を開始する。
     *
     * @param[in] handle CloseHandleで解放するfile handle。
     */
	  //------------------------------------------------------------------------------
	  explicit UniqueFile( const HANDLE handle) noexcept : handle_( handle)
	  {
	  }

	  //------------------------------------------------------------------------------
	  /**
     * @brief 所有file handleを解放する。
     *
     * 有効なhandleだけを一度CloseHandleする。
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
	  UniqueFile		  &operator=( UniqueFile &&) = delete ;

	  //------------------------------------------------------------------------------
	  /**
     * @brief 所有中のhandleをWindows API呼出し用に参照する。
     * @return 呼出し側へ所有権を移さないfile handle。
     */
	  //------------------------------------------------------------------------------
	  [[nodiscard]] HANDLE get() const noexcept
	  {
		  return handle_ ;
	  }

private:
	  /// Destructorで解放する所有file handle。
	  HANDLE handle_{INVALID_HANDLE_VALUE} ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをNativeErrorへ変換する。
 *
 * 元の診断値をProvider共通型へ保持する。
 *
 * @param[in] error GetLastErrorまたは検証用Win32 error code。
 * @return HRESULT_FROM_WIN32で変換したbit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Little-endian 16-bit値を読み取る。
 *
 * Alignmentに依存するcastを使用せず一byteずつ復元する。
 *
 * @param[in] input 検証済みbyte列。
 * @param[in] offset 2 byteを読める検証済みoffset。
 * @return Little-endianから復元した16-bit値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint16_t readU16Le( const std::span<const std::byte> input,
									  const std::size_t				   offset) noexcept
{
	const std::uint16_t low	 = std::to_integer<std::uint8_t>( input[offset]) ;		// 下位byte。
	const std::uint16_t high = std::to_integer<std::uint8_t>( input[offset + 1]) ;	// 上位byte。
	return static_cast<std::uint16_t>( low | static_cast<std::uint16_t>( high << 8U)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Little-endian 32-bit値を読み取る。
 *
 * Alignmentとhost endianに依存せず一byteずつ復元する。
 *
 * @param[in] input 検証済みbyte列。
 * @param[in] offset 4 byteを読める検証済みoffset。
 * @return Little-endianから復元した32-bit値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint32_t readU32Le( const std::span<const std::byte> input,
									  const std::size_t				   offset) noexcept
{
	std::uint32_t value{} ;	// 入力から復元する値。
	// 4 byteを下位側から順に配置する。
	for( std::size_t index = 0; index < 4; ++index) {
		const std::uint32_t part =
			std::to_integer<std::uint8_t>( input[offset + index]) ;	// 現在byte。
		value |= part << static_cast<unsigned int>( index * 8U) ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief Null終端GZip optional fieldを読み飛ばす。
 *
 * 外部文字列を解釈またはpathへ使用せず、有限範囲だけを走査する。
 *
 * @param[in] input GZip container全体。
 * @param[in] trailerOffset Trailer開始位置。
 * @param[in,out] offset Field開始位置。成功時は終端直後。
 * @return Trailerより前にnull終端を検出した場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool skipZeroTerminated( const std::span<const std::byte> input,
									  const std::size_t trailerOffset, std::size_t &offset) noexcept
{
	// Trailer境界までを走査し、最初のnull byteだけをterminatorとして扱う。
	while( offset < trailerOffset) {
		// Optional field の終端 NUL を消費した位置を次の読取り開始位置とする。
		if( input[offset] == std::byte{}) {
			++offset ;
			return true ;
		}

		++offset ;
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief File全体を上限付きbyte列へ読み取る。
 *
 * Reparse pointと非disk fileを拒否し、署名済みinputだけを読む。
 *
 * @param[in] path 読取り対象のlocal絶対path。
 * @param[in] maximumBytes 読取りを許可する最大byte数。
 * @param[out] bytes 成功時のfile全体。失敗時は空。
 * @return 成功時は0、通常file以外、上限超過、I/O失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readFileBytes( const std::wstring_view path,
										const std::uint64_t		maximumBytes,
										std::vector<std::byte> &bytes)
{
	bytes.clear() ;
	// 空 path、ゼロ上限、address 空間を超える読取り上限は受理しない。
	if( path.empty() || maximumBytes == 0 ||
	   maximumBytes > static_cast<std::uint64_t>( std::numeric_limits<std::size_t>::max())) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring pathString( path) ;	// Win32 API用の終端null付きpath。
	const UniqueFile   file( CreateFileW(
		  pathString.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
		  nullptr)) ;	// 読取り専用所有handle。
	// GZip 入力を開けなければ、Windows の診断値を返す。
	if( file.get() == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	FILE_ATTRIBUTE_TAG_INFO tagInfo{} ;	// Reparse point判定用属性。
	// 開いた入力の属性を確認できなければ内容を読み取らない。
	if( GetFileInformationByHandleEx( file.get(), FileAttributeTagInfo, &tagInfo, sizeof( tagInfo)) ==
	   FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// Reparse point と disk 以外の入力は通常 file として扱わない。
	if( (tagInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
	   GetFileType( file.get()) != FILE_TYPE_DISK) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	LARGE_INTEGER fileSize{} ;	// GZip fileの符号付きbyte数。
	// File size を確定できなければ読取りを開始しない。
	if( GetFileSizeEx( file.get(), &fileSize) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 空の入力と展開前の取得上限を超える file を拒否する。
	if( fileSize.QuadPart <= 0 || static_cast<std::uint64_t>( fileSize.QuadPart) > maximumBytes) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	try {
		bytes.resize( static_cast<std::size_t>( fileSize.QuadPart)) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	std::size_t offset{} ;	// 次に読込む出力buffer offset。
	// DWORD上限ごとの有限chunkでfile sizeと同数のbyteを読み取る。
	while( offset < bytes.size()) {
		const DWORD requested = static_cast<DWORD>( std::min<std::size_t>(
			// 今回の要求byte数。
			bytes.size() - offset, std::numeric_limits<DWORD>::max())) ;
		DWORD		received{} ;	// ReadFileが返した実読取りbyte数。
		// 読取り失敗時は部分 data を破棄し、Windows の診断値を返す。
		if( ReadFile( file.get(), bytes.data() + offset, requested, &received, nullptr) == FALSE) {
			bytes.clear() ;
			return nativeErrorFromWin32( GetLastError()) ;
		}

		// 予定した長さより早い終端では部分 data を正常結果にしない。
		if( received == 0) {
			bytes.clear() ;
			return nativeErrorFromWin32( ERROR_HANDLE_EOF) ;
		}

		offset += received ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Byte列全体をfile handleへ書き込む。
 *
 * 新規fileの先頭からDWORD上限ごとの有限chunkで書込む。
 *
 * @param[in] outputFile 呼出し側が所有する書込み可能handle。
 * @param[in] bytes 書込み対象byte列。
 * @return 全byteを書込めた場合は0、失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError writeFileBytes( const HANDLE					  outputFile,
										 const std::span<const std::byte> bytes)
{
	// 無効な出力 handle と空の出力 data は書込み前に拒否する。
	if( outputFile == nullptr || outputFile == INVALID_HANDLE_VALUE || bytes.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	LARGE_INTEGER beginning{} ;	// File先頭を表すoffset 0。
	// 出力を先頭から切り詰められなければ既存内容と混在させない。
	if( SetFilePointerEx( outputFile, beginning, nullptr, FILE_BEGIN) == FALSE ||
	   SetEndOfFile( outputFile) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	std::size_t offset{} ;	// 次に書込むinput offset。
	// DWORD上限ごとの有限chunkで全byteを書き込む。
	while( offset < bytes.size()) {
		const DWORD requested = static_cast<DWORD>( std::min<std::size_t>(
			// 今回の要求byte数。
			bytes.size() - offset, std::numeric_limits<DWORD>::max())) ;
		DWORD		written{} ;	// WriteFileが返した実書込みbyte数。
		// 書込み API が失敗したら、その診断値で処理を中止する。
		if( WriteFile( outputFile, bytes.data() + offset, requested, &written, nullptr) == FALSE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		// 書込みが進まない場合は無限反復せず書込み失敗とする。
		if( written == 0) {
			return nativeErrorFromWin32( ERROR_WRITE_FAULT) ;
		}

		offset += written ;
	}

	return 0 ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_gzip.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError decompressOfficialGzip( const std::span<const std::byte> compressed,
								   const std::uint64_t				maximumExpandedBytes,
								   std::vector<std::byte>		   &expanded)
{
	expanded.clear() ;
	// 最小構造未満の入力と表現できない展開上限は受理しない。
	if( compressed.size() < MINIMUM_GZIP_BYTES || maximumExpandedBytes == 0 ||
	   maximumExpandedBytes > static_cast<std::uint64_t>( std::numeric_limits<std::size_t>::max())) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// GZip magic と DEFLATE 方式が一致しない入力を拒否する。
	if( compressed[0] != GZIP_MAGIC_FIRST || compressed[1] != GZIP_MAGIC_SECOND ||
	   compressed[2] != DEFLATE_METHOD) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const std::uint8_t flags = std::to_integer<std::uint8_t>( compressed[3]) ;	// GZip header flag。
	// 予約 flag を使用する GZip は未対応形式として拒否する。
	if( (flags & RESERVED_FLAGS) != 0) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const std::size_t trailerOffset = compressed.size() - 8 ;	// CRC32/ISIZE開始位置。
	std::size_t		  offset		= 10 ;						// Optional field開始位置。
	// Extra field が宣言された場合だけ、長さを検証して読み飛ばす。
	if( (flags & FLAG_EXTRA) != 0) {
		// Extra field 長の読取りが trailer へ侵入しないことを確認する。
		if( offset + 2 > trailerOffset) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const std::size_t extraLength = readU16Le( compressed, offset) ;	// Extra field長。
		offset += 2 ;
		// Extra field 本体が trailer より前に収まらなければ拒否する。
		if( extraLength > trailerOffset - offset) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		offset += extraLength ;
	}

	// File name field が終端 NUL まで収まらなければ拒否する。
	if( (flags & FLAG_NAME) != 0 && !skipZeroTerminated( compressed, trailerOffset, offset)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// Comment field が終端 NUL まで収まらなければ拒否する。
	if( (flags & FLAG_COMMENT) != 0 && !skipZeroTerminated( compressed, trailerOffset, offset)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// Header CRC が宣言されている場合だけ、格納値と計算値を照合する。
	if( (flags & FLAG_HEADER_CRC) != 0) {
		// Header CRC の領域が trailer と重なる入力を拒否する。
		if( offset + 2 > trailerOffset) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const mz_ulong headerCrc =
			mz_crc32( MZ_CRC32_INIT, reinterpret_cast<const unsigned char *>( compressed.data()),
					 offset) ;	// Header CRC32。
		// Header CRC が一致しない入力は展開処理へ渡さない。
		if( readU16Le( compressed, offset) != static_cast<std::uint16_t>( headerCrc & 0xffffU)) {
			return nativeErrorFromWin32( ERROR_CRC) ;
		}

		offset += 2 ;
	}

	// Optional field の後に圧縮 data が残っていない入力を拒否する。
	if( offset >= trailerOffset) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const std::uint32_t expectedCrc = readU32Le( compressed, trailerOffset) ;	// Trailer CRC32。
	const std::uint32_t expectedSize =
		// Trailer展開後size。
		readU32Le( compressed, trailerOffset + 4) ;
	// 宣言された展開 size がゼロまたは許可上限を超える入力を拒否する。
	if( expectedSize == 0 || expectedSize > maximumExpandedBytes) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	std::vector<std::byte> output ;	// 全検証成功まで公開しない展開結果。
	try {
		output.resize( expectedSize) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	mz_stream stream{} ;	// Raw Deflate一memberの展開状態。
	stream.next_in	 = reinterpret_cast<const unsigned char *>( compressed.data() + offset) ;
	stream.avail_in	 = static_cast<unsigned int>( trailerOffset - offset) ;
	stream.next_out	 = reinterpret_cast<unsigned char *>( output.data()) ;
	stream.avail_out = static_cast<unsigned int>( output.size()) ;
	// Raw DEFLATE decoder を初期化できなければ展開を開始しない。
	if( mz_inflateInit2( &stream, -MZ_DEFAULT_WINDOW_BITS) != MZ_OK) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const int inflateResult = mz_inflate( &stream, MZ_FINISH) ;	// Deflate完了状態。
	const int endResult		= mz_inflateEnd( &stream) ;			// Miniz state終了結果。
	// 正常終端、全入力消費、宣言出力 size の全てが成立した場合だけ受理する。
	if( inflateResult != MZ_STREAM_END || endResult != MZ_OK ||
	   stream.total_in != trailerOffset - offset || stream.total_out != output.size()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const mz_ulong actualCrc =
		mz_crc32( MZ_CRC32_INIT, reinterpret_cast<const unsigned char *>( output.data()),
				 // 展開結果CRC32。
				 output.size()) ;
	// 展開 data の CRC が trailer と一致しなければ出力を受理しない。
	if( actualCrc != expectedCrc) {
		return nativeErrorFromWin32( ERROR_CRC) ;
	}

	expanded = std::move( output) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_gzip.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError decompressOfficialGzipFile( const std::wstring_view inputPath,
									   const std::uint64_t	   maximumCompressedBytes,
									   const std::uint64_t	   maximumExpandedBytes,
									   const HANDLE			   outputFile)
{
	std::vector<std::byte> compressed ;	// 上限検証済みGZip file全体。
	NativeError			   error =
		// File読取り結果。
		readFileBytes( inputPath, maximumCompressedBytes, compressed) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	std::vector<std::byte> expanded ;	// CRC/ISIZE検証済み展開結果。
	error = decompressOfficialGzip( compressed, maximumExpandedBytes, expanded) ;
	return error == 0 ? writeFileBytes( outputFile, expanded) : error ;
}

} // namespace drivercrate
