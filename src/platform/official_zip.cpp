//------------------------------------------------------------------------------
/**
 * @file official_zip.cpp
 * @brief 公式ZIP package安全展開実装。
 * @version 01.00.02
 * @date 2026/09/03
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  固定subdirectory選択展開追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  固定file集合の選択展開追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  展開fileのSHA-256確定追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/15  Windows区切りZIPを正規化して全path検査へ接続。
 * Ver.01.00.02  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note ZIP metadataを全件検証してから、CRC検証付きstream展開を行います。Archive名を絶対pathへ直接連結せず、保護workspace境界を再検証します。
 */
//------------------------------------------------------------------------------

#include "platform/official_zip.h"

#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"

#include <Windows.h>
#include <miniz.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
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

constexpr std::size_t MAXIMUM_ARCHIVE_PATH_BYTES   = 160 ;		// 受理するentry相対pathの最大byte数。
constexpr std::size_t MAXIMUM_PATH_COMPONENT_BYTES = 96 ;		// 一path要素の最大byte数。
constexpr mz_uint16	  UNIX_HOST_SYSTEM			   = 3 ;		// ZIP made-byのUnix識別値。
constexpr mz_uint32	  UNIX_FILE_TYPE_MASK		   = 0170000U ;	// Unix modeのfile type mask。
constexpr mz_uint32	  UNIX_REGULAR_FILE			   = 0100000U ;	// Unix modeの通常file type。
constexpr mz_uint32	  UNIX_DIRECTORY			   = 0040000U ;	// Unix modeのdirectory type。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief ZIP内のpath衝突確認で、fileと親directoryを区別する。
 */
enum class ZipNodeKind {
	/// 親要素として別entryを保持できるdirectory。
	DIRECTORY,
	/// 子要素または同名nodeを許可しない通常file。
	FILE,
} ;

/**
 * @brief 大文字小文字を含む元pathと種別を保持し、Windows上の衝突を検出する。
 */
struct ZipNode {
	/// Windows上で衝突判定するnode種別。
	ZipNodeKind kind ;
	/// 最初に確認した大文字小文字を保持する相対path。
	std::string exactName ;
} ;

/**
 * @brief 検証済みの公開entryを、同じarchive内の展開対象indexへ結び付ける。
 */
struct ParsedZipEntry {
	/// Miniz central directory上のentry index。
	mz_uint			 archiveIndex ;
	/// 呼出し側へ公開できる検証済み情報。
	OfficialZipEntry publicEntry ;
} ;

/**
 * @brief 展開callbackが借用する出力handleと、連続書込み位置・最初の失敗を保持する。
 */
struct ExtractionContext {
	/// Workspaceが所有権を呼出し側へ渡した出力handle。
	HANDLE		  file ;
	/// 次に受理する連続出力offset。
	std::uint64_t nextOffset ;
	/// Callback内で最初に発生したWin32 error。
	NativeError	  error ;
} ;

/**
 * @brief Miniz ZIP readerの終了処理を保証する。
 */
class ZipReader final {
public:
	//------------------------------------------------------------------------------
	/**
     * @brief Memory readerを初期化し、失敗状態もinstance内へ保持する。
     *
     * @param[in] archive Reader存続中に有効なZIP全byte列。
     */
	//------------------------------------------------------------------------------
	explicit ZipReader( const std::span<const std::byte> archive) noexcept
	{
		mz_zip_zero_struct( &archive_) ;
		initialized_ = mz_zip_reader_init_mem( &archive_, archive.data(), archive.size(), 0) != 0 ;
	}

	//------------------------------------------------------------------------------
	/**
     * @brief ZIP readerを終了する。
     *
     * 初期化済みreaderの内部allocationだけを解放する。
     */
	//------------------------------------------------------------------------------
	~ZipReader()
	{
		// 初期化に成功した ZIP reader だけを終了処理へ渡す。
		if( initialized_) {
			mz_zip_reader_end( &archive_) ;
		}
	}

	/**
	 * @brief ZIP内部allocationの終了責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	ZipReader( const ZipReader &) = delete ;
	/**
	 * @brief ZIP内部allocationの終了責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	ZipReader &operator=( const ZipReader &) = delete ;
	/**
	 * @brief ZIP内部allocationの終了責務を初期化したZIP readerに留めるため、移動構築を禁止する。
	 */
	ZipReader( ZipReader &&) = delete ;
	/**
	 * @brief 初期化したZIP readerへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	ZipReader		  &operator=( ZipReader &&) = delete ;

	//------------------------------------------------------------------------------
	/**
     * @brief Reader初期化結果を取得する。
     *
     * 呼出し側が無効なreaderへMiniz APIを呼ばないために使う。
     * @return Central directoryを読めた場合は`true`。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] bool valid() const noexcept
	{
		return initialized_ ;
	}

	//------------------------------------------------------------------------------
	/**
     * @brief Miniz readerを参照する。
     *
     * 所有権を移さず、現在scope内の検証と展開にだけ使用する。
     * @return 本instanceが所有するMiniz readerへの参照。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] mz_zip_archive &get() noexcept
	{
		return archive_ ;
	}

private:
	/// Destructorで終了するMiniz reader状態。
	mz_zip_archive archive_{} ;
	/// `true`の場合だけreader終了処理を行う。
	bool		   initialized_{} ;
} ;

/**
 * @brief File handleのCloseHandleを保証する。
 */
class UniqueFile final {
public:
	//------------------------------------------------------------------------------
	/**
     * @brief Workspaceから受け取ったhandleのscope管理を開始する。
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
	UniqueFile &operator=( UniqueFile &&) = delete ;

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
 * Provider共通結果に元の診断値を保持する。
 *
 * @param[in] error Win32 APIまたは検証用error code。
 * @return HRESULT_FROM_WIN32で変換したbit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASCII文字列を小文字へ変換する。
 *
 * Windows file systemの大文字小文字無視による衝突を検出する。
 *
 * @param[in] value 検証済みの表示不能情報を含まないASCII文字列。
 * @return A～Zだけを小文字化した比較用文字列。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string asciiLower( const std::string_view value)
{
	std::string result( value) ;	// 変換結果を所有する比較key。
	std::transform( result.begin(), result.end(), result.begin(), []( const char character) {
		return character >= 'A' && character <= 'Z' ? static_cast<char>( character + ('a' - 'A'))
													: character ;
	}) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief ZIP path要素が安全なWindows通常名か検証する。
 *
 * Dot component、禁止文字、末尾dot／space、DOS device名を拒否する。
 *
 * @param[in] value Slashを含まないASCII path要素。
 * @return Windowsで通常file名として安全な場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafeZipComponent( const std::string_view value) noexcept
{
	// 空・長すぎる・dot 要素・曖昧な末尾を持つ ZIP path 要素を拒否する。
	if( value.empty() || value.size() > MAXIMUM_PATH_COMPONENT_BYTES || value == "." ||
	   value == ".." || value.back() == '.' || value.back() == ' ') {
		return false ;
	}

	// 全byteを検証し、alternate separatorやADSを構成できる文字を拒否する。
	for( const unsigned char character : value) {
		// 印字可能 ASCII 以外と Windows path の禁止文字を拒否する。
		if( character < 0x20U || character > 0x7eU ||
		   std::string_view( "<>:\"\\|?*").find( static_cast<char>( character)) !=
			   std::string_view::npos) {
			return false ;
		}
	}

	const std::string stem = asciiLower( value.substr( 0, value.find( '.'))) ;	// 予約名判定用stem。
	// 拡張子を除いた名前が Windows の固定予約名なら拒否する。
	if( stem == "con" || stem == "prn" || stem == "aux" || stem == "nul") {
		return false ;
	}

	// COM1等の番号付きWindows予約device名を拒否するための条件。
	const bool numberedDevice = stem.size() == 4 && stem[3] >= '1' && stem[3] <= '9' ;
	return !numberedDevice || (stem.substr( 0, 3) != "com" && stem.substr( 0, 3) != "lpt") ;
}

//------------------------------------------------------------------------------
/**
 * @brief ZIP entry名を安全なWorkspace相対pathへ変換する。
 *
 * Archive文字encodingを推測せず、安全なASCII subsetだけをWindows pathへ変換する。
 *
 * @param[in] rawPath Central directoryが保持するentry名。
 * @param[in] directory Directory entryの場合は`true`。
 * @param[out] relativePath 成功時の`\\`区切りASCII相対path。
 * @param[out] comparisonKey 成功時の小文字`/`区切り比較key。
 * @return 成功時は0、不正名またはpath traversalはHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError parseZipPath( const std::string_view rawPath, const bool directory,
									   std::wstring &relativePath, std::string &comparisonKey)
{
	relativePath.clear() ;
	comparisonKey.clear() ;
	// 空・上限超過・絶対 path・逆 slash・埋込み NUL を持つ entry 名を拒否する。
	if( rawPath.empty() || rawPath.size() > MAXIMUM_ARCHIVE_PATH_BYTES || rawPath.front() == '/' ||
	   rawPath.front() == '\\' || rawPath.find( '\\') != std::string_view::npos ||
	   rawPath.find( '\0') != std::string_view::npos) {
		return nativeErrorFromWin32( ERROR_INVALID_NAME) ;
	}

	std::string_view path = rawPath ;	// Directory終端slashを除いた検証対象。
	// Directory entry の末尾区切りだけを除いて要素を検証する。
	if( directory && path.back() == '/') {
		path.remove_suffix( 1) ;
	}

	// 末尾区切りの除去後も空または余分な区切りがある名前を拒否する。
	if( path.empty() || path.back() == '/') {
		return nativeErrorFromWin32( ERROR_INVALID_NAME) ;
	}

	std::size_t beginning{} ;	// 現在検証するpath要素の開始位置。
	// Slashごとに全path要素を検証し、Windows用separatorへ変換する。
	while( beginning < path.size()) {
		const std::size_t separator = path.find( '/', beginning) ;	// 次のslash位置。
		const std::size_t ending =
			// 要素終端位置。
			separator == std::string_view::npos ? path.size() : separator ;
		const std::string_view component =
			// 現在のpath要素。
			path.substr( beginning, ending - beginning) ;
		// 各 path 要素が安全な Windows 通常名でなければ entry を拒否する。
		if( !isSafeZipComponent( component)) {
			return nativeErrorFromWin32( ERROR_INVALID_NAME) ;
		}

		// 先行要素がある場合だけ Windows の区切りを追加する。
		if( !relativePath.empty()) {
			relativePath.push_back( L'\\') ;
		}

		// 検証済みASCIIだけを同じcode pointのwchar_tへ変換する。
		for( const unsigned char character : component) {
			relativePath.push_back( static_cast<wchar_t>( character)) ;
		}

		beginning = ending + 1 ;
	}

	comparisonKey = asciiLower( path) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows上で衝突しないZIP nodeを登録する。
 *
 * Case違い、file／directory同名、file配下のentryを拒否する。
 *
 * @param[in] exactPath 元のcaseを保持する検証済み相対path。
 * @param[in] key 小文字化した比較key。
 * @param[in] kind 登録するfileまたはdirectory種別。
 * @param[in,out] nodes 既知nodeと新規nodeの登録先。
 * @return 衝突なく登録できた場合は0、重複または親file時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError registerZipNode( const std::string_view exactPath,
										  const std::string_view key, const ZipNodeKind kind,
										  std::map<std::string, ZipNode> &nodes)
{
	std::size_t separator = key.find( '/') ;	// 次に確認する親directory終端。
	// 全親directoryを登録し、途中に通常fileが存在しないことを確認する。
	while( separator != std::string_view::npos) {
		const std::string parentKey( key.substr( 0, separator)) ;			// 親の比較key。
		const std::string parentExact( exactPath.substr( 0, separator)) ;	// 親の元表記。
		const auto		  existing = nodes.find( parentKey) ;				// 既存親node。
		// 既存の親 node では directory 種別と厳密な表記の一致を確認する。
		if( existing != nodes.end()) {
			// 親 path の file 衝突または大文字小文字だけ異なる表記を拒否する。
			if( existing->second.kind != ZipNodeKind::DIRECTORY ||
			   existing->second.exactName != parentExact) {
				return nativeErrorFromWin32( ERROR_DUP_NAME) ;
			}
		} else {
			nodes.emplace( parentKey, ZipNode{ZipNodeKind::DIRECTORY, parentExact}) ;
		}

		separator = key.find( '/', separator + 1) ;
	}

	const auto existing = nodes.find( std::string( key)) ;	// 同じWindows pathの既存node。
	// 同じ出力 key が既にある場合は同一 directory の再出現だけを検討する。
	if( existing != nodes.end()) {
		// 表記も種別も同一の directory は既存 node を再利用する。
		if( kind == ZipNodeKind::DIRECTORY && existing->second.kind == ZipNodeKind::DIRECTORY &&
		   existing->second.exactName == exactPath) {
			return 0 ;
		}

		return nativeErrorFromWin32( ERROR_DUP_NAME) ;
	}

	nodes.emplace( std::string( key), ZipNode{kind, std::string( exactPath)}) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Unix由来entryが通常fileまたはdirectoryか検証する。
 *
 * Unix modeを持たないentryはWindows通常fileとして扱い、明示された特殊file typeだけを拒否する。
 *
 * @param[in] status Minizが復元したcentral directory情報。
 * @return Symlink等の特殊fileでなければ`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasSafeEntryType( const mz_zip_archive_file_stat &status) noexcept
{
	const mz_uint16 hostSystem =
		// 作成元OS識別値。
		static_cast<mz_uint16>( status.m_version_made_by >> 8U) ;
	// Unix 由来以外の entry には Unix mode の種別解釈を適用しない。
	if( hostSystem != UNIX_HOST_SYSTEM) {
		return true ;
	}

	const mz_uint32 fileType =
		(status.m_external_attr >> 16U) & UNIX_FILE_TYPE_MASK ;	// Unix modeのfile type。
	return fileType == 0 || fileType == UNIX_REGULAR_FILE || fileType == UNIX_DIRECTORY ;
}

//------------------------------------------------------------------------------
/**
 * @brief ZIP全entryを展開前に検証する。
 *
 * 一件でも不正なら候補を返さず、展開処理を開始させない。
 *
 * @param[in] archive ZIP container全byte列。
 * @param[in] policy Providerが固定した有限上限。
 * @param[in,out] reader `archive`を参照する初期化済みreader。
 * @param[out] entries 成功時の通常file一覧。
 * @return 全entryが安全なら0、不正形式または上限違反はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError parseZipEntries( const std::span<const std::byte>	 archive,
										  const OfficialZipExtractionPolicy &policy,
										  ZipReader &reader, std::vector<ParsedZipEntry> &entries)
{
	entries.clear() ;
	// 空 archive とゼロ・相互矛盾のある展開上限を事前検証で拒否する。
	if( archive.empty() || policy.maximumArchiveBytes == 0 || policy.maximumSingleFileBytes == 0 ||
	   policy.maximumTotalExpandedBytes == 0 || policy.maximumEntryCount == 0 ||
	   policy.maximumSingleFileBytes > policy.maximumTotalExpandedBytes) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// ZIP 全体の size が取得上限を超える場合は entry を解析しない。
	if( archive.size() > policy.maximumArchiveBytes) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	// Reader の初期化が成立しない ZIP は不正 data として拒否する。
	if( !reader.valid()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	mz_zip_archive &zip		   = reader.get() ;							// 検証対象reader。
	const mz_uint	entryCount = mz_zip_reader_get_num_files( &zip) ;	// 全entry数。
	// 空または上限超過の entry 集合は展開対象として受理しない。
	if( entryCount == 0 || entryCount > policy.maximumEntryCount) {
		return nativeErrorFromWin32( ERROR_TOO_MANY_OPEN_FILES) ;
	}

	std::map<std::string, ZipNode> nodes ;					// Windows上のpath衝突検出表。
	std::uint64_t				   totalExpandedBytes{} ;	// 通常fileの展開後byte数合計。
	try {
		entries.reserve( entryCount) ;
		// Central directoryの全entryを有限上限内で検証する。
		for( mz_uint index = 0; index < entryCount; ++index) {
			mz_zip_archive_file_stat status{} ;	// 現在entryのcentral directory情報。
			// Entry 情報の取得失敗、未対応・暗号化形式、危険な種別を拒否する。
			if( mz_zip_reader_file_stat( &zip, index, &status) == 0 || status.m_is_supported == 0 ||
			   status.m_is_encrypted != 0 || !hasSafeEntryType( status)) {
				entries.clear() ;
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			std::array<char, MAXIMUM_ARCHIVE_PATH_BYTES + 2> nameBuffer{} ;	// Entry名buffer。
			const mz_uint									 required =
				// Nullを含む必要byte数。
				mz_zip_reader_get_filename( &zip, index, nullptr, 0) ;
			// Entry 名を許可 buffer 内で完全に取得できなければ一覧を破棄する。
			if( required <= 1 || required > nameBuffer.size() ||
			   mz_zip_reader_get_filename( &zip, index, nameBuffer.data(),
										  static_cast<mz_uint>( nameBuffer.size())) != required) {
				entries.clear() ;
				return nativeErrorFromWin32( ERROR_INVALID_NAME) ;
			}

			std::string canonicalPath( nameBuffer.data(),
									  required - 1) ;	// 同じWindows pathの一意表記。
			// 区切りだけを統一し、逸脱・空要素・ADS・衝突は従来の全件検査で拒否する。
			std::replace( canonicalPath.begin(), canonicalPath.end(), '\\', '/') ;
			const bool directory = status.m_is_directory != 0 ||
								   (canonicalPath.ends_with( '/') && status.m_uncomp_size == 0 &&
									status.m_comp_size == 0 &&
									// 空entryだけをdirectoryへ正規化する。
									status.m_crc32 == 0) ;
			std::wstring relativePath ;		// Workspace用相対path。
			std::string	 comparisonKey ;	// Case無視衝突判定key。
			NativeError	 error =
				// Path結果。
				parseZipPath( canonicalPath, directory, relativePath, comparisonKey) ;
			// Entry path の検証に失敗した場合は途中までの一覧を残さない。
			if( error != 0) {
				entries.clear() ;
				return error ;
			}

			error = registerZipNode(
				canonicalPath.ends_with( '/') ? canonicalPath.substr( 0, canonicalPath.size() - 1)
											 : canonicalPath,
				comparisonKey, directory ? ZipNodeKind::DIRECTORY : ZipNodeKind::FILE, nodes) ;
			// Path node の登録に失敗した場合は衝突を含む一覧全体を拒否する。
			if( error != 0) {
				entries.clear() ;
				return error ;
			}

			// Directory entry は path 確認後に通常 file の展開量集計から除く。
			if( directory) {
				continue ;
			}

			// 単一 file と累積展開量の上限を超える ZIP は一覧ごと拒否する。
			if( status.m_uncomp_size > policy.maximumSingleFileBytes ||
			   status.m_uncomp_size > policy.maximumTotalExpandedBytes - totalExpandedBytes) {
				entries.clear() ;
				return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
			}

			totalExpandedBytes += status.m_uncomp_size ;
			entries.push_back( ParsedZipEntry{
				index, OfficialZipEntry{std::move( relativePath), status.m_uncomp_size}}) ;
		}
	} catch( const std::bad_alloc &) {
		entries.clear() ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	return entries.empty() ? nativeErrorFromWin32( ERROR_INVALID_DATA) : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定選択directoryをZIP path規則で検証する。
 *
 * Entryと同じcomponent規則を適用し、呼出側policyによるtraversalやalternate separatorを許可しない。
 *
 * @param[in] subdirectory `\\`区切りの固定相対directory。
 * @return 安全なASCII相対directoryの場合は0、それ以外はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateSubdirectory( const std::wstring_view subdirectory)
{
	// 空・先頭区切り・末尾区切りを持つ選択 directory は受理しない。
	if( subdirectory.empty() || subdirectory.front() == L'\\' || subdirectory.back() == L'\\') {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		std::string rawPath ;	// `parseZipPath`へ渡す`/`区切りASCII表現。
		rawPath.reserve( subdirectory.size() + 1U) ;
		// Wide文字をASCIIだけへ限定し、APIで許可するseparatorだけを変換する。
		for( const wchar_t character : subdirectory) {
			// Windows の区切りを ZIP の検証用区切りへ変換する。
			if( character == L'\\') {
				rawPath.push_back( '/') ;
				continue ;
			}

			// 選択 directory の非 ASCII・制御文字・混在区切りを拒否する。
			if( character < 0x20 || character > 0x7e || character == L'/') {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			rawPath.push_back( static_cast<char>( character)) ;
		}

		rawPath.push_back( '/') ;
		std::wstring	  parsedPath ;		// Entry規則を適用したWindows相対path。
		std::string		  comparisonKey ;	// 検証APIが返す未使用のcase無視比較key。
		const NativeError error =
			// 構文検証結果。
			parseZipPath( rawPath, true, parsedPath, comparisonKey) ;
		// Path 検証が失敗する場合と往復変換で表記が変わる指定を拒否する。
		if( error != 0 || parsedPath != subdirectory) {
			return error != 0 ? error : static_cast<NativeError>( E_INVALIDARG) ;
		}

		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 固定選択file path集合をZIP path規則で検証する。
 *
 * Entryと同じcomponent規則を適用し、case差の重複、directory表現、alternate separatorを展開前に拒否する。
 *
 * @param[in] selectedFiles `\\`区切りの固定相対file path群。
 * @return 一件以上の安全で重複しないpath集合なら0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateSelectedFiles(
	const std::span<const std::wstring_view> selectedFiles)
{
	// 空の file 選択を全件取得として解釈しない。
	if( selectedFiles.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		std::vector<std::string> comparisonKeys ;	// Case無視重複検出用の正規化path群。
		comparisonKeys.reserve( selectedFiles.size()) ;
		// 全選択pathへZIP entryと同じ構文および重複規則を適用する。
		for( const std::wstring_view selectedFile : selectedFiles) {
			// 空名または directory 形式の区切りを持つ file 指定を拒否する。
			if( selectedFile.empty() || selectedFile.front() == L'\\' ||
			   selectedFile.back() == L'\\') {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			std::string rawPath ;	// `parseZipPath`へ渡す`/`区切りASCII表現。
			rawPath.reserve( selectedFile.size()) ;
			// Wide文字をASCIIへ限定し、許可したseparatorだけを変換する。
			for( const wchar_t character : selectedFile) {
				// 選択 file の Windows 区切りを ZIP 検証用に変換する。
				if( character == L'\\') {
					rawPath.push_back( '/') ;
					continue ;
				}

				// 選択 file の制御文字・非 ASCII・混在区切りを拒否する。
				if( character < 0x20 || character > 0x7e || character == L'/') {
					return static_cast<NativeError>( E_INVALIDARG) ;
				}

				rawPath.push_back( static_cast<char>( character)) ;
			}

			std::wstring	  parsedPath ;		// Entry規則を適用したWindows相対path。
			std::string		  comparisonKey ;	// ASCII case無視比較用の正規化key。
			const NativeError error =
				// 構文結果。
				parseZipPath( rawPath, false, parsedPath, comparisonKey) ;
			// Path の不正、往復表記の不一致、同じ出力 key の重複を拒否する。
			if( error != 0 || parsedPath != selectedFile ||
			   std::ranges::find( comparisonKeys, comparisonKey) != comparisonKeys.end()) {
				return error != 0 ? error : static_cast<NativeError>( E_INVALIDARG) ;
			}

			comparisonKeys.push_back( std::move( comparisonKey)) ;
		}

		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Entryが固定directoryの子孫か判定する。
 *
 * Component境界を必須とし、同じ文字で始まる別directoryを選択しない。空directoryは全entryを選択する。
 *
 * @param[in] path 事前検証済みZIP file相対path。
 * @param[in] subdirectory 検証済み固定相対directory。
 * @return Windows上で大文字小文字を無視して子孫の場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSubdirectoryEntry( const std::wstring_view path,
									   const std::wstring_view subdirectory) noexcept
{
	// Directory 絞込みが未指定なら entry の場所による除外を行わない。
	if( subdirectory.empty()) {
		return true ;
	}

	// Prefix の後が区切りでない path は指定 directory の子孫と扱わない。
	if( path.size() <= subdirectory.size() || path[subdirectory.size()] != L'\\') {
		return false ;
	}

	// Locale非依存ASCII比較でWindows file systemと同じcase差を吸収する。
	for( std::size_t index = 0; index < subdirectory.size(); ++index) {
		const wchar_t left	= path[index] >= L'A' && path[index] <= L'Z'
								  ? static_cast<wchar_t>( path[index] - L'A' + L'a')
								  : path[index] ;	// Entry側の小文字化ASCII。
		const wchar_t right = subdirectory[index] >= L'A' && subdirectory[index] <= L'Z'
								  ? static_cast<wchar_t>( subdirectory[index] - L'A' + L'a')
								  : subdirectory[index] ;	// Policy側の小文字化ASCII。
		// 正規化済み prefix の文字が一致しなければ子孫条件を不成立とする。
		if( left != right) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief ZIP entryが固定選択file集合に含まれるか判定する。
 *
 * Prefix一致を許さず、指定した一つの通常fileだけを選ぶ。
 *
 * @param[in] path 事前検証済みZIP file相対path。
 * @param[in] selectedFiles 検証済み固定相対file path群。
 * @return Windows上のASCII case差を除いて完全一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSelectedFile( const std::wstring_view				   path,
								  const std::span<const std::wstring_view> selectedFiles) noexcept
{
	return std::ranges::any_of( selectedFiles, [path]( const std::wstring_view selected) noexcept {
		return path.size() == selected.size() &&
			   std::ranges::equal(
				   path, selected, []( const wchar_t left, const wchar_t right) noexcept {
					   const wchar_t normalizedLeft = left >= L'A' && left <= L'Z'
														  ? static_cast<wchar_t>( left - L'A' + L'a')
														  : left ;	// Entry側の小文字化ASCII。
					   const wchar_t normalizedRight =
						   right >= L'A' && right <= L'Z'
							   ? static_cast<wchar_t>( right - L'A' + L'a')
							   : right ;	// Policy側の小文字化ASCII。
					   return normalizedLeft == normalizedRight ;
				   }) ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Miniz展開byte列をWorkspace fileへ書き込む。
 *
 * 連続offsetだけをDWORD上限単位で書込み、例外を外へ出さない。
 *
 * @param[in,out] opaque `ExtractionContext`への非所有pointer。
 * @param[in] fileOffset Entry先頭からの出力offset。
 * @param[in] bytes Miniz所有の展開済みbyte列。
 * @param[in] byteCount 今回の書込みbyte数。
 * @return 全byteを書込めた場合は`byteCount`、失敗時は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] size_t writeExtractedBytes( void *opaque, const mz_uint64 fileOffset,
										 const void *bytes, const size_t byteCount) noexcept
{
	// 書込み context と非空 data の pointer が欠ける callback を拒否する。
	if( opaque == nullptr || (bytes == nullptr && byteCount != 0)) {
		return 0 ;
	}

	auto &context = *static_cast<ExtractionContext *>( opaque) ;	// 呼出し側の書込み状態。
	// 既存失敗または連続しない出力 offset があれば追加書込みを行わない。
	if( context.error != 0 || fileOffset != context.nextOffset) {
		return 0 ;
	}

	const auto *source = static_cast<const std::byte *>( bytes) ;	// 今回byte列の先頭。
	std::size_t offset{} ;											// 今回byte列内の次の書込み位置。
	// WriteFileのDWORD上限ごとに全byteを順序どおり書き込む。
	while( offset < byteCount) {
		const DWORD requested = static_cast<DWORD>( std::min<std::size_t>(
			byteCount - offset, std::numeric_limits<DWORD>::max())) ;	// 今回の要求byte数。
		DWORD		written{} ;											// WriteFileが実際に保存したbyte数。
		// 書込み失敗・進捗停止時は context に診断値を残して展開を停止する。
		if( WriteFile( context.file, source + offset, requested, &written, nullptr) == FALSE ||
		   written == 0) {
			DWORD error = GetLastError() ;	// WriteFileが設定した診断値。
			// 停止に診断値がない場合も成功扱いせず書込み失敗へ変換する。
			if( error == ERROR_SUCCESS) {
				error = ERROR_WRITE_FAULT ;
			}

			context.error = nativeErrorFromWin32( error) ;
			return 0 ;
		}

		offset += written ;
		context.nextOffset += written ;
	}

	return byteCount ;
}

//------------------------------------------------------------------------------
/**
 * @brief 事前検証済みZIP entryを選択して展開する。
 *
 * 選択外entryを作成せず、途中失敗時は公開結果を空に保つ。
 *
 * @param[in,out] zip 入力archiveを参照する初期化済みMiniz reader。
 * @param[in] parsedEntries ZIP全体の事前検証済み通常file群。
 * @param[in] subdirectory 空または展開を許可する固定directory。
 * @param[in] selectedFiles 空または展開を許可する固定file群。
 * @param[in,out] workspace 選択fileを単独所有する保護領域。
 * @param[out] entries 全選択file成功時だけ公開する一覧。
 * @return 一件以上の選択fileをCRC検証付きで展開した場合は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError extractParsedEntries(
	mz_zip_archive &zip, const std::span<const ParsedZipEntry> parsedEntries,
	const std::wstring_view subdirectory, const std::span<const std::wstring_view> selectedFiles,
	OfficialDownloadWorkspace &workspace, std::vector<OfficialZipEntry> &entries)
{
	entries.clear() ;
	try {
		// 固定file選択では全指定pathの存在を確認し、部分展開を開始しない。
		for( const std::wstring_view selectedFile : selectedFiles) {
			const std::array selection{selectedFile} ;	// 一件だけの選択view。
			const bool		 present = std::ranges::any_of(
				  parsedEntries, [&selection]( const ParsedZipEntry &entry) noexcept {
					  return isSelectedFile( entry.publicEntry.relativePath, selection) ;
				  }) ; // 現在の固定path存在判定。
			// 要求した file が検証済み一覧にない場合は出力作成前に拒否する。
			if( !present) {
				return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
			}
		}

		std::vector<OfficialZipEntry> selectedEntries ;	// 成功まで非公開の選択file群。
		selectedEntries.reserve( parsedEntries.size()) ;
		// Archive順を維持し、policyが選択した通常fileだけを作成する。
		for( const ParsedZipEntry &entry : parsedEntries) {
			const bool selected =
				selectedFiles.empty()
					? isSubdirectoryEntry( entry.publicEntry.relativePath, subdirectory)
					: isSelectedFile( entry.publicEntry.relativePath,
									 selectedFiles) ;	// 選択判定。
			// 選択条件に一致しない entry は出力しない。
			if( !selected) {
				continue ;
			}

			{
				HANDLE			  rawFile = INVALID_HANDLE_VALUE ;	// Workspaceが作成する所有handle。
				// 保護workspaceに一entryの新規出力先を作成した結果。
				const NativeError creationError =
					workspace.createFile( entry.publicEntry.relativePath, rawFile) ;
				// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
				if( creationError != 0) {
					return creationError ;
				}

				const UniqueFile  file( rawFile) ;			// 現在entryのhandle解放責任。
				ExtractionContext context{rawFile, 0, 0} ;	// Callbackへ渡す連続書込み状態。
				// 展開の失敗と宣言 size まで書けない結果を拒否し、I/O 診断値を優先する。
				if( mz_zip_reader_extract_to_callback( &zip, entry.archiveIndex, writeExtractedBytes,
													 &context, 0) == 0 ||
				   context.nextOffset != entry.publicEntry.uncompressedSize) {
					return context.error != 0 ? context.error
											  : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}
			}

			OfficialZipEntry   completedEntry = entry.publicEntry ;	// Hash確定後の公開値。
			const std::wstring extractedPath =
				// 保護領域内の展開済みpath。
				workspace.path( completedEntry.relativePath) ;
			// 展開後の検証用 path を解決できなければ成功結果へ追加しない。
			if( extractedPath.empty()) {
				return static_cast<NativeError>( E_UNEXPECTED) ;
			}

			const NativeError hashError =
				// 展開内容の識別結果。
				computeFileSha256( extractedPath, completedEntry.sha256) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( hashError != 0) {
				return hashError ;
			}

			selectedEntries.push_back( std::move( completedEntry)) ;
		}

		// 選択条件に合う通常 file がなければ対象未検出を返す。
		if( selectedEntries.empty()) {
			return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
		}

		entries = std::move( selectedEntries) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		entries.clear() ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_zip.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError inspectOfficialZip( const std::span<const std::byte>	  archive,
							   const OfficialZipExtractionPolicy &policy,
							   std::vector<OfficialZipEntry>	 &entries)
{
	entries.clear() ;
	ZipReader					reader( archive) ;	// Scope終了時に解放するreader。
	std::vector<ParsedZipEntry> parsedEntries ;		// 全検証成功まで非公開のentry群。
	const NativeError			error =
		// Preflight結果。
		parseZipEntries( archive, policy, reader, parsedEntries) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	try {
		entries.reserve( parsedEntries.size()) ;
		// Archive indexを除いた公開情報だけを元順序で複写する。
		for( const ParsedZipEntry &entry : parsedEntries) {
			entries.push_back( entry.publicEntry) ;
		}
	} catch( const std::bad_alloc &) {
		entries.clear() ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_zip.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError extractOfficialZip( const std::span<const std::byte>	  archive,
							   const OfficialZipExtractionPolicy &policy,
							   OfficialDownloadWorkspace		 &workspace,
							   std::vector<OfficialZipEntry>	 &entries)
{
	entries.clear() ;
	ZipReader					reader( archive) ;									// Scope終了時に解放するreader。
	std::vector<ParsedZipEntry> parsedEntries ;										// Preflight済み通常file群。
	NativeError error = parseZipEntries( archive, policy, reader, parsedEntries) ;	// Preflight結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	mz_zip_archive &zip = reader.get() ;	// CRC検証付き展開に使うreader。
	return extractParsedEntries( zip, parsedEntries, {}, {}, workspace, entries) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_zip.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError extractOfficialZipSubdirectory( const std::span<const std::byte>	  archive,
										   const OfficialZipExtractionPolicy &policy,
										   const std::wstring_view			  subdirectory,
										   OfficialDownloadWorkspace		 &workspace,
										   std::vector<OfficialZipEntry>	 &entries)
{
	entries.clear() ;
	const NativeError subdirectoryError =
		// 固定選択directoryの構文結果。
		validateSubdirectory( subdirectory) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( subdirectoryError != 0) {
		return subdirectoryError ;
	}

	ZipReader					reader( archive) ;	// Scope終了時に解放するreader。
	std::vector<ParsedZipEntry> parsedEntries ;		// ZIP全体の事前検証済みfile群。
	const NativeError			parseError =
		// 全entry検証結果。
		parseZipEntries( archive, policy, reader, parsedEntries) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( parseError != 0) {
		return parseError ;
	}

	mz_zip_archive &zip = reader.get() ;	// 選択entryのCRC検証付き展開に使うreader。
	return extractParsedEntries( zip, parsedEntries, subdirectory, {}, workspace, entries) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_zip.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError extractOfficialZipFiles( const std::span<const std::byte>		 archive,
									const OfficialZipExtractionPolicy		&policy,
									const std::span<const std::wstring_view> selectedFiles,
									OfficialDownloadWorkspace				&workspace,
									std::vector<OfficialZipEntry>			&entries)
{
	entries.clear() ;
	const NativeError selectionError =
		// 固定file集合の構文結果。
		validateSelectedFiles( selectedFiles) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( selectionError != 0) {
		return selectionError ;
	}

	ZipReader					reader( archive) ;	// Scope終了時に解放するreader。
	std::vector<ParsedZipEntry> parsedEntries ;		// ZIP全体の事前検証済みfile群。
	const NativeError			parseError =
		// 全entry検証結果。
		parseZipEntries( archive, policy, reader, parsedEntries) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( parseError != 0) {
		return parseError ;
	}

	mz_zip_archive &zip = reader.get() ;	// 選択entryのCRC検証付き展開に使うreader。
	return extractParsedEntries( zip, parsedEntries, {}, selectedFiles, workspace, entries) ;
}

} // namespace drivercrate
