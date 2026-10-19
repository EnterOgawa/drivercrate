//------------------------------------------------------------------------------
/**
 * @file official_sfx_structure_smoke.cpp
 * @brief 明示local EXEの署名・SFX構造と7z選択要求量を非実行で診断する。
 * @version 01.04.01
 * @date 2026/10/04
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/04  保守用の有限構造診断を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/04  明示大型選択と元member結合・共通INF検査を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/05  導入不許可のまま保守用sourceとCopyINFを棚卸し。
 * Ver.01.03.00 Shunji Ogawa  2026/10/05  保守用の有限分割取得と全参照CAT/member検査を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/05  直接CAT/member署名と未解決依存を別modeで観測。
 * Ver.01.04.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 入力を実行しない。inspectはmetadataだけ、selectは保護領域へ明示fileだけを展開する。
 *       導入・staging・端末列挙を呼ばず、親runnerが180秒／900秒wall timeを制限する。
 *       選択ZIPは研究専用であり、内容検査成功も導入許可・実機適合を意味しない。
 * @see docs/adr/0243-maintenance-sfx-structure-and-selection-budget.md
 * @see docs/adr/0245-maintenance-batched-reference-content-verification.md
 * @see docs/adr/0246-maintenance-relative-references-and-direct-content.md
 */
//------------------------------------------------------------------------------

#include "platform/official_download_workspace.h"
#include "platform/official_driver_package.h"
#include "platform/official_file_verifier.h"
#include "platform/official_seven_zip.h"
#include "platform/official_sfx.h"

#include <Windows.h>
#include <miniz.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <limits>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 固定予算と所有型。
//------------------------------------------------------------------------------

constexpr std::uint64_t MIB = 1'024U * 1'024U ;	// 予算表のMiBをbyteへ変換する。
constexpr std::uint64_t GIB = 1'024U * MIB ;	// 予算表のGiBをbyteへ変換する。
/**
 * @brief Scope内のhandle所有者。
 */
using OwnedHandle = std::unique_ptr<void, decltype( &CloseHandle)> ;
constexpr std::array DISPLAY_CLASSES{	// 今回のGPU基本driverだけを受理する。
									 std::wstring_view( L"Display")} ;
constexpr std::array INF_SIGNATURES{std::wstring_view( L"$Windows NT$")} ;	// 現行x64 INF signature。
constexpr OfficialInfInspectionPolicy DISPLAY_POLICY{
	4096U, 8192U, DISPLAY_CLASSES, {},	 INF_SIGNATURES,
	true,  true,  false,		   true, false} ;	// 任意command拒否を維持し、外部依存は別観測。

/**
 * @brief 失敗stageと元HRESULTを部分合格なしで通知する。
 * @param[in] stage 内部の固定ASCII識別子。外部入力を渡さない。
 * @param[in] error 失敗を示す元HRESULT bit pattern。
 * @return 検査失敗の終了値2。
 */
int reject( const char *stage, const NativeError error) noexcept
{
	std::printf( "{\"state\":\"REJECTED\",\"stage\":\"%s\",\"error\":%lu}\n", stage,
				static_cast<unsigned long>( static_cast<std::uint32_t>( error))) ;
	return 2 ;
}

/**
 * @brief 検証済みASCII相対pathだけをJSON文字列へ変換する。
 * @param[in] path 既存7z preflightが検証したpath。呼出し中だけ借用する。
 * @return 引用符を含むJSON文字列。IDや入力絶対pathを受理しない。
 */
std::string quotedPath( const std::wstring_view path)
{
	std::string result = "\"" ;	// 全文構築後にだけ公開するpath表記。
	// 安全なASCII pathのJSON delimiterだけをescapeする。
	for( const wchar_t character : path) {
		// JSONの区切り文字をfile名として誤解させない。
		if( character == L'\\' || character == L'"') {
			result += '\\' ;
		}

		result += static_cast<char>( character) ;
	}

	result += '"' ;
	return result ;
}

/**
 * @brief 明示CSVを有限な一意index集合へ変換する。
 * @param[in] text ASCII数字とcommaだけの入力。呼出し中だけ借用する。
 * @param[out] indices 成功時の昇順index。失敗時は呼出し側が使用しない。
 * @return 非空・一意・uint32範囲・1,024件以下ならtrue。
 */
bool parseSelection( const std::wstring_view text, std::vector<std::uint32_t> &indices)
{
	// OS引数も有限にし、空を全件選択へ変換しない。
	if( text.empty() || text.size() > 11'264U) {
		return false ;
	}

	std::uint64_t number{} ;	// 現在のindex。加算前にuint32範囲を確認する。
	bool		  hasDigit{} ;	// 空要素と末尾commaを検出する。
	// 最終要素用delimiterを一度だけ補い、全indexを検証する。
	for( std::size_t position = 0U; position <= text.size(); ++position) {
		const wchar_t character =
			// 現在token文字。
			position == text.size() ? L',' : text[position] ;
		// 要素終端では値と件数を確認し、未検証の空要素を拒否する。
		if( character == L',') {
			// 無限要素や空tokenを選択として解釈しない。
			if( !hasDigit || indices.size() >= 1'024U) {
				return false ;
			}

			indices.push_back( static_cast<std::uint32_t>( number)) ;
			number	 = 0U ;
			hasDigit = false ;
			continue ;
		}

		// 符号、空白、指数、overflowを補正せず拒否する。
		if( character < L'0' || character > L'9' ||
		   number > (std::numeric_limits<std::uint32_t>::max() - (character - L'0')) / 10U) {
			return false ;
		}

		number	 = number * 10U + static_cast<std::uint64_t>( character - L'0') ;
		hasDigit = true ;
	}

	std::sort( indices.begin(), indices.end()) ;
	return std::adjacent_find( indices.begin(), indices.end()) == indices.end() ;
}

/**
 * @brief Absolute pathの既存ancestorにreparse pointを許可しない。
 * @param[in] path 存在してもしなくてもよい絶対path。
 * @return 既存ancestorが全て通常directoryならtrue。
 */
bool safeAncestors( const std::filesystem::path &path)
{
	// 相対pathの暗黙解決をしない。
	if( !path.is_absolute()) {
		return false ;
	}

	// Rootまでの全directoryでjunctionとsymlinkを拒否する。
	for( auto parent = path.parent_path(); !parent.empty(); parent = parent.parent_path()) {
		const DWORD attributes = GetFileAttributesW( parent.c_str()) ;	// 既存directoryの属性。
		// 存在しないparentとredirectするancestorを出力先として使わない。
		if( attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0U ||
		   (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) {
			return false ;
		}

		// Rootのparentは自身なので有限に終了する。
		if( parent == parent.parent_path()) {
			break ;
		}
	}

	return true ;
}

/** @brief callbackに渡す借用disk handleと有限容量を保持する。 */
struct ZipIo {
	/// Callback呼出し中だけ借用するseek可能handle。
	HANDLE		  handle{} ;
	/// 読書きoffsetと要求量の最大合計byte数。
	std::uint64_t maximumBytes{} ;
	/// Read callbackで正常に返した最大終端byte位置。
	std::uint64_t readExtent{} ;
	/// Unexpected EOFや読取りAPI失敗時true。正常EOFと区別する。
	bool		  readFailed{} ;
} ;

/**
 * @brief 検証済み保護fileを有限callbackで読む。
 * @param[in] opaque 呼出し中有効なZipIo。所有しない。
 * @param[in] offset fileの読み開始byte位置。
 * @param[out] buffer Miniz所有の要求量byte領域。
 * @param[in] count 要求byte数。1MiB以下に限定する。
 * @return 実読取り量、範囲外またはAPI失敗時0。例外を漏らさない。
 */
std::size_t readZipMember( void *opaque, const mz_uint64 offset, void *buffer,
						  const std::size_t count) noexcept
{
	auto &io = *static_cast<ZipIo *>( opaque) ;	// Minizから借用する同期context。
	// Callback容量超過とWin32 narrowingを防ぐ。
	if( offset > io.maximumBytes || count > MIB) {
		io.readFailed = true ;
		return 0U ;
	}

	const DWORD requested = static_cast<DWORD>(
		std::min<std::uint64_t>( count, io.maximumBytes - offset)) ;	// 最終chunkをclampする。
	// Minizの通常EOF要求だけを失敗なしの0として返す。
	if( requested == 0U) {
		return 0U ;
	}

	LARGE_INTEGER position{} ;	// Seek先。全profileがsigned 64bitより小さい。
	position.QuadPart = static_cast<LONGLONG>( offset) ;
	DWORD obtained{} ;	// APIが返した実読取り量。
	// EOF前の短い読取りを通常EOFとしてZIPへ記録させない。
	if( !SetFilePointerEx( io.handle, position, nullptr, FILE_BEGIN) ||
	   !ReadFile( io.handle, buffer, requested, &obtained, nullptr) || obtained != requested) {
		io.readFailed = true ;
		return 0U ;
	}

	io.readExtent = std::max<std::uint64_t>( io.readExtent, offset + obtained) ;
	return obtained ;
}

/**
 * @brief 新規ZIPへ有限callbackで書き込む。
 * @param[in] opaque 呼出し中有効なZipIo。所有しない。
 * @param[in] offset 出力開始byte位置。
 * @param[in] buffer Miniz所有のcount byte領域。
 * @param[in] count 要求byte数。1MiB以下に限定する。
 * @return 実書込み量、範囲外またはAPI失敗時0。例外を漏らさない。
 */
std::size_t writeSelectionZip( void *opaque, const mz_uint64 offset, const void *buffer,
							  const std::size_t count) noexcept
{
	const auto &io = *static_cast<const ZipIo *>( opaque) ;	// Minizから借用する同期context。
	// ZIP管理領域を含む出力上限をwriteより前に強制する。
	if( offset > io.maximumBytes || count > io.maximumBytes - offset || count > MIB) {
		return 0U ;
	}

	LARGE_INTEGER position{} ;	// 有限の書込みoffset。
	position.QuadPart = static_cast<LONGLONG>( offset) ;
	DWORD written{} ;	// 実書込みbyte数。
	return SetFilePointerEx( io.handle, position, nullptr, FILE_BEGIN) &&
				   WriteFile( io.handle, buffer, static_cast<DWORD>( count), &written, nullptr)
			   ? written
			   : 0U ;
}

/** @brief 自身が新規作成したZIPだけを失敗時に削除する。 */
class NewZip final {
public:
	/** @brief Miniz writerを空で準備する。 */
	NewZip()
	{
		mz_zip_zero_struct( &writer_) ;
	}
	/** @brief Writerとhandleを解放し、未確定の新規ZIPだけを削除する。 */
	~NewZip()
	{
		// 初期化したwriterだけを解放する。
		if( initialized_) {
			mz_zip_writer_end( &writer_) ;
		}

		// CREATE_NEW成功後の自身のfileだけがcleanup対象になる。
		if( (handle_ || readOnly_) && !keep_) {
			// Hash中は読取りだけを共有し、cleanup時に同一identityのDELETE handleへ取り直す。
			if( readOnly_) {
				handle_.reset() ;
				const HANDLE opened = CreateFileW(
					path_.c_str(), DELETE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
					OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;	// 失敗cleanup専用。
				// 消失したfileや他者へ置換されたpathを削除しない。
				if( opened == INVALID_HANDLE_VALUE) {
					std::fputs( "selection ZIP cleanup open failed\n", stderr) ;
					return ;
				}

				handle_.reset( opened) ;
				BY_HANDLE_FILE_INFORMATION current{} ;	// Cleanup対象の現在identity。
				// CREATE_NEW時の同じdisk fileだけを削除する。
				if( !GetFileInformationByHandle( handle_.get(), &current) ||
				   current.dwVolumeSerialNumber != identity_.dwVolumeSerialNumber ||
				   current.nFileIndexHigh != identity_.nFileIndexHigh ||
				   current.nFileIndexLow != identity_.nFileIndexLow) {
					std::fputs( "selection ZIP cleanup identity changed\n", stderr) ;
					return ;
				}
			}

			FILE_DISPOSITION_INFO disposition{TRUE} ;	// Handleに結合した削除指定。
			// Cleanup失敗は隠さずstderrへ固定診断を残す。
			if( !SetFileInformationByHandle( handle_.get(), FileDispositionInfo, &disposition,
										   sizeof( disposition))) {
				std::fputs( "selection ZIP cleanup failed\n", stderr) ;
			}
		}
	}
	/**
	 * @brief 保護workspaceの選択fileだけを新規ZIPへコピーする。
	 * @param[in] output 非存在のabsolute output path。
	 * @param[in] workspace 検証済みfileの所有者。同期呼出し中だけ借用する。
	 * @param[in] entries CRC・size・hash検証済みの選択file。
	 * @param[out] hash 成功したZIPのSHA-256。
	 * @param[out] bytes 成功したZIPのbyte数。
	 * @return 全コピーとhash成功0、既存file・I/O・ZIP失敗時HRESULT。
	 */
	NativeError write( const std::wstring &output, const OfficialDownloadWorkspace &workspace,
					  const std::span<const OfficialSevenZipEntry> entries, std::wstring &hash,
					  std::uint64_t &bytes)
	{
		// CREATE_NEW後のcleanup identityに結合する固定path。
		path_				= output ;
		const HANDLE opened = CreateFileW(
			output.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ, nullptr,
			CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;	// 新規だけ所有する。
		// 既存出力の削除や上書きを行わない。
		if( opened == INVALID_HANDLE_VALUE) {
			return static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
		}

		handle_.reset( opened) ;
		// 作成直後のidentityを取得できなければそのhandleで部分fileを破棄する。
		if( !GetFileInformationByHandle( handle_.get(), &identity_)) {
			return static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
		}

		io_					 = {handle_.get(), 2U * GIB + 16U * MIB} ;
		writer_.m_pWrite	 = &writeSelectionZip ;
		writer_.m_pIO_opaque = &io_ ;
		// Callback writerをheap全ZIP方式へfallbackしない。
		if( !mz_zip_writer_init( &writer_, 0U)) {
			return static_cast<NativeError>( E_FAIL) ;
		}

		initialized_ = true ;
		// 各memberを一度だけ有限callbackで書き、非選択fileを含めない。
		for( const OfficialSevenZipEntry &entry : entries) {
			const HANDLE member = CreateFileW(
				workspace.path( entry.relativePath).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
				OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;	// 保護fileの借用読取り。
			// 元member読取り失敗時に空fileを追加しない。
			if( member == INVALID_HANDLE_VALUE) {
				return static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
			}

			OwnedHandle input( member, &CloseHandle) ;					// Callback完了までfileを固定する。
			ZipIo		context{input.get(), entry.uncompressedSize} ;	// このmemberの実byte境界。
			std::string name ;											// ZIP相対path用の検証済みASCIIだけを保持する。
			// Windows separatorだけをZIPの相対separatorへ変換する。
			for( const wchar_t character : entry.relativePath) {
				name += character == L'\\' ? '/' : static_cast<char>( character) ;
			}

			// 再圧縮・全保持をせずstoredで研究用byteを保存する。
			if( !mz_zip_writer_add_read_buf_callback( &writer_, name.c_str(), &readZipMember,
													&context, entry.uncompressedSize, nullptr,
													nullptr, 0U, 0U, nullptr, 0U, nullptr, 0U) ||
			   context.readFailed || context.readExtent != entry.uncompressedSize) {
				return static_cast<NativeError>( E_FAIL) ;
			}
		}

		LARGE_INTEGER size{} ;	// 確定ZIPのsize。
		// 完了・flush・実size確認をすべて通ったZIPだけhashへ進める。
		if( !mz_zip_writer_finalize_archive( &writer_) || !FlushFileBuffers( handle_.get()) ||
		   !GetFileSizeEx( handle_.get(), &size) || size.QuadPart <= 0 ||
		   static_cast<std::uint64_t>( size.QuadPart) > io_.maximumBytes) {
			return static_cast<NativeError>( E_FAIL) ;
		}

		bytes = static_cast<std::uint64_t>( size.QuadPart) ;
		mz_zip_writer_end( &writer_) ;
		initialized_ = false ;
		handle_.reset() ;
		readOnly_		  = true ;
		const HANDLE read = CreateFileW( output.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
										OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT,
										nullptr) ;	// 共通hash中は書込み・削除を共有しない。
		// 完成fileを同じidentityで固定し直せない場合は合格にしない。
		if( read == INVALID_HANDLE_VALUE) {
			return static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
		}

		handle_.reset( read) ;
		BY_HANDLE_FILE_INFORMATION current{} ;	// 読取りhandleへ切替後のidentity。
		// 切替中の差替えを同一研究ZIPとして受理しない。
		if( !GetFileInformationByHandle( handle_.get(), &current) ||
		   current.dwVolumeSerialNumber != identity_.dwVolumeSerialNumber ||
		   current.nFileIndexHigh != identity_.nFileIndexHigh ||
		   current.nFileIndexLow != identity_.nFileIndexLow ||
		   (current.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
			   0U) {
			return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		}

		return computeFileSha256( output, hash) ;
	}
	/** @brief 全証拠出力成功後にだけ研究ZIPを保持する。 */
	void commit() noexcept
	{
		keep_ = true ;
	}

private:
	/// CREATE_NEW成功時だけ所有する出力handle。
	OwnedHandle				   handle_{nullptr, &CloseHandle} ;
	/// Callback writerの同期間有効な状態。
	mz_zip_archive			   writer_{} ;
	/// 出力handleと固定byte上限。
	ZipIo					   io_{} ;
	/// Writer初期化成功後だけtrue。
	bool					   initialized_{} ;
	/// 証拠のstdout出力・flush成功後だけtrue。
	bool					   keep_{} ;
	/// 共通hash検査前にread-only handleへ切り替えた場合true。
	bool					   readOnly_{} ;
	/// 自身がCREATE_NEWしたfileのcleanup用絶対path。
	std::wstring			   path_ ;
	/// CREATE_NEW直後に固定したvolumeとfile index。
	BY_HANDLE_FILE_INFORMATION identity_{} ;
} ;

/**
 * @brief SetupAPIの参照計画を元7zの全metadataへ結合する。
 * @param[in] workspace 取得済みINFを所有する保護領域。同期借用する。
 * @param[in] selected CRCとhashを検査した選択file。
 * @param[in] entries 全7z preflightのmetadata。未取得参照先も含む。
 * @return 個別INF hash・拒否・一意閉包metadataのJSON row群。内容署名合格を示さない。
 * @note 全PnP IDをRAMだけに保持する。欠落・危険動作を推測で回避しない。
 */
std::string planReferences( const OfficialDownloadWorkspace			   &workspace,
						   const std::span<const OfficialZipEntry>		selected,
						   const std::span<const OfficialSevenZipEntry> entries)
{
	std::vector<OfficialZipEntry> inventory ;	// 未取得参照先を含む元metadata。内容合格ではない。
	// 同じ全7z preflightの一覧だけをSetupAPIの閉包計画へ渡す。
	for( const OfficialSevenZipEntry &entry : entries) {
		inventory.push_back( {entry.relativePath, entry.uncompressedSize, {}}) ;
	}

	std::string references ;	// 参照計画と個別拒否。Device IDを含めない。
	// 取得済みINFだけを解析し、未取得参照先を元indexへ再照合する。
	for( const OfficialZipEntry &entry : selected) {
		std::wstring extension = std::filesystem::path( entry.relativePath)
									 .extension()
									 .wstring() ;	// INF判定だけに使用する。
		// ASCII拡張子を正規化する。
		for( wchar_t &character : extension) {
			// 大文字だけを同一file名の小文字へ変換する。
			if( character >= L'A' && character <= L'Z') {
				character += L'a' - L'A' ;
			}
		}

		// 非INF fileを構文解析へ渡さない。
		if( extension != L".inf") {
			continue ;
		}

		OfficialInfPackage package ;	// 全PnP IDと解決中の参照をRAMに限定する。
		NativeError error = inspectOfficialInfPackage( workspace, inventory, entry.relativePath,
													  DISPLAY_POLICY, package) ;	// 共通構造検査。
		std::string paths ;															// 全予算・元index再照合成功後だけ出力する閉包metadata。
		// SetupAPIが構造を拒否したINFの参照を推測しない。
		if( error == 0) {
			std::vector<std::wstring> requested{
				package.infRelativePath, package.catalogRelativePath} ;	// INFと対応CATを必ず含める。
			requested.insert( requested.end(), package.sourceFiles.begin(),
							 package.sourceFiles.end()) ;
			std::vector<std::uint32_t> resolved ;	// 大文字小文字を除く一意index。
			std::uint64_t			   total{} ;	// 選択閉包の有限合計byte。
			// 全参照を元metadataへ解決し、欠落や過大を部分計画へ変換しない。
			for( const std::wstring &relative : requested) {
				const auto found =
					std::find_if( entries.begin(), entries.end(),
								 [&relative]( const OfficialSevenZipEntry &candidate) {
									 return CompareStringOrdinal( relative.c_str(), -1,
																 candidate.relativePath.c_str(), -1,
																 TRUE) == CSTR_EQUAL ;
								 }) ; // 元entryのcase-insensitiveな完全一致解決。
				// 不存在・選択保存量・件数超過は閉包計画も拒否する。
				if( found == entries.end() || found->uncompressedSize > 2U * GIB - total ||
				   resolved.size() >= 1'024U) {
					error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
					paths.clear() ;
					break ;
				}

				// 共有参照を二重に保存しない。
				if( std::find( resolved.begin(), resolved.end(), found->archiveIndex) !=
				   resolved.end()) {
					continue ;
				}

				resolved.push_back( found->archiveIndex) ;
				total += found->uncompressedSize ;
				// JSON delimiterを要素間にだけ追加する。
				if( !paths.empty()) {
					paths += ',' ;
				}

				paths += "{\"index\":" + std::to_string( found->archiveIndex) +
						 ",\"path\":" + quotedPath( found->relativePath) +
						 ",\"bytes\":" + std::to_string( found->uncompressedSize) + "}" ;
			}
		}

		// 参照観測を合格内容検査へ変換せず、個別errorを保持する。
		if( !references.empty()) {
			references += ',' ;
		}

		references += "{\"infPath\":" + quotedPath( entry.relativePath) +
					  ",\"infSha256\":" + quotedPath( entry.sha256) +
					  ",\"error\":" + std::to_string( static_cast<std::uint32_t>( error)) +
					  ",\"closureEntries\":[" + paths + "],\"contentSignatureVerified\":false}" ;
	}

	return references ;
}

/**
 * @brief 導入検査と独立した保守参照を元metadataへ結合する。
 * @param[in] workspace 選択取得したINFの保護領域。同期借用する。
 * @param[in] selected byte検証済みの選択member群。
 * @param[in] entries 同じ元7zの全preflight metadata。
 * @return 非合格の棚卸しrow群。全参照閉包や署名の合格ではない。
 */
std::string inventoryReferences( const OfficialDownloadWorkspace				&workspace,
								const std::span<const OfficialZipEntry>		 selected,
								const std::span<const OfficialSevenZipEntry> entries)
{
	std::vector<OfficialZipEntry> inventory ;	// 未取得fileも含む同じ元inventory。
	// 外部pathを追加せず元metadataだけを渡す。
	for( const OfficialSevenZipEntry &entry : entries) {
		inventory.push_back( {entry.relativePath, entry.uncompressedSize, {}}) ;
	}

	std::string rows ;	// PnP IDを含まない保守参照JSON。
	// 実取得したINFだけを解析する。
	for( const OfficialZipEntry &entry : selected) {
		// 非INFを飛ばす。
		if( _wcsicmp( std::filesystem::path( entry.relativePath).extension().c_str(), L".inf") != 0) {
			continue ;
		}

		OfficialInfReferenceInventory	 facts ;	// 導入用packageと型を分けた非合格参照。
		const OfficialFileMetadataPolicy binding{entry.uncompressedSize,
												 entry.sha256} ;	// 読取前後の同一INF拘束。
		// Parserが参照したINFを実取得hashとsizeへ拘束する。
		if( verifyOfficialFileMetadata( workspace.path( entry.relativePath), binding) != 0) {
			throw std::runtime_error( "reference INF changed") ;
		}

		const NativeError error = inspectOfficialInfReferences(
			workspace, inventory, entry.relativePath, facts) ;	// 棚卸し結果。
		// 解析中の差替えを元hashの参照計画として保存しない。
		if( verifyOfficialFileMetadata( workspace.path( entry.relativePath), binding) != 0) {
			throw std::runtime_error( "reference INF changed") ;
		}

		std::string paths ;		// 同じinventoryへ完全一致した直接参照metadata。
		std::string children ;	// 実byte未確認のCopyINF参照。
		// 棚卸し完了した場合だけ集合を出力する。
		if( error == 0) {
			std::vector<std::wstring> requested{facts.infRelativePath,
												facts.catalogRelativePath} ;	// INFとCAT必須。
			requested.insert( requested.end(), facts.sourceFiles.begin(), facts.sourceFiles.end()) ;
			std::vector<std::uint32_t> seen ;	// 一意の元index集合。
			// 元archive metadataへ再照合する。
			for( const std::wstring &relative : requested) {
				const auto found = std::ranges::find_if(
					entries, [&relative]( const OfficialSevenZipEntry &candidate) {
						return CompareStringOrdinal( relative.c_str(), -1,
													candidate.relativePath.c_str(), -1,
													TRUE) == CSTR_EQUAL ;
					}) ; // 大小文字以外は完全一致。
				// 共有parserと元metadataの不整合を正常出力にしない。
				if( found == entries.end()) {
					throw std::runtime_error( "reference inventory changed") ;
				}

				// 共有参照を重複出力しない。
				if( std::ranges::find( seen, found->archiveIndex) != seen.end()) {
					continue ;
				}

				seen.push_back( found->archiveIndex) ;
				// 要素間にだけdelimiterを置く。
				if( !paths.empty()) {
					paths += ',' ;
				}

				paths += "{\"index\":" + std::to_string( found->archiveIndex) +
						 ",\"path\":" + quotedPath( found->relativePath) +
						 ",\"bytes\":" + std::to_string( found->uncompressedSize) + "}" ;
			}

			// 欠落したCopyINFも省略せず保持する。
			for( const std::wstring &child : facts.copyInfPaths) {
				// 要素間にだけdelimiterを置く。
				if( !children.empty()) {
					children += ',' ;
				}

				children += quotedPath( child) ;
			}
		}

		// 個別観測rowを区切る。
		if( !rows.empty()) {
			rows += ',' ;
		}

		rows += "{\"infPath\":" + quotedPath( entry.relativePath) +
				",\"infSha256\":" + quotedPath( entry.sha256) +
				",\"error\":" + std::to_string( static_cast<std::uint32_t>( error)) +
				",\"stage\":" + std::to_string( static_cast<unsigned>( facts.stage)) +
				",\"class\":" + quotedPath( facts.className) +
				",\"catalogPath\":" + quotedPath( facts.catalogRelativePath) +
				",\"directEntries\":[" + paths + "],\"copyInfPaths\":[" + children +
				"],\"externalDependencies\":" + (facts.hasExternalDependencies ? "true" : "false") +
				",\"installActionsError\":" +
				std::to_string( static_cast<std::uint32_t>( facts.installActionsError)) +
				",\"contentSignatureVerified\":false}" ;
	}

	return rows ;
}

/**
 * @brief 明示選択を保護展開し、個別INFの既存検査と研究ZIPへ接続する。
 * @param[in] archive 検証済み7z借用範囲。
 * @param[in] policy 明示大型mode専用の固定policy。
 * @param[in] selected 一意・昇順の明示index。
 * @param[in] entries 全preflightが通ったmetadata一覧。
 * @param[in] output 新規absolute ZIP path。
 * @param[in] inputHash 入力byteに結合したSHA-256。
 * @return 全展開・export成功0、境界違反・decode失敗2。内容合格は別field。
 */
int extractSelection( const std::span<const std::byte>			  archive,
					 const OfficialSevenZipExtractionPolicy		 &policy,
					 const std::span<const std::uint32_t>		  selected,
					 const std::span<const OfficialSevenZipEntry> entries,
					 const std::wstring &output, const std::wstring_view inputHash)
{
	std::uint64_t selectedBytes{} ;	// Exportするfileの合計。Solid要求量とは別の値。
	std::uint64_t infBytes{} ;		// 選択INFの合計読取り予算。
	std::size_t	  infCount{} ;		// 個別INF検査を行うか判断する件数。
	// 明示indexを全metadataへ完全一致させ、decode前に保存量を検証する。
	for( const std::uint32_t index : selected) {
		const auto found = std::find_if( entries.begin(), entries.end(),
										[index]( const OfficialSevenZipEntry &entry) {
											return entry.archiveIndex == index ;
										}) ; // 借用indexの一意解決。
		// 未定義indexと2GiB以上の保存を拒否する。
		if( found == entries.end() || found->uncompressedSize > 2U * GIB - selectedBytes) {
			return reject( "SELECTION_BUDGET", static_cast<NativeError>( E_INVALIDARG)) ;
		}

		selectedBytes += found->uncompressedSize ;
		std::wstring extension =
			// INF判定専用。
			std::filesystem::path( found->relativePath).extension().wstring() ;
		// 拡張子だけをlocale非依存で正規化する。
		for( wchar_t &character : extension) {
			// ASCII大文字を同じfile名の小文字へ変換する。
			if( character >= L'A' && character <= L'Z') {
				character += L'a' - L'A' ;
			}
		}

		// INFだけに小さい構文読取り予算を追加する。
		if( extension == L".inf") {
			++infCount ;
			infBytes += found->uncompressedSize ;
			// 多数INFや単一巨大INFをSetupAPIへ渡さない。
			if( found->uncompressedSize > 4U * MIB || infBytes > 64U * MIB || infCount > 512U) {
				return reject( "INF_BUDGET", static_cast<NativeError>( E_INVALIDARG)) ;
			}
		}
	}

	OfficialSevenZipSelectionAssessment assessment{} ;	// 固有folderのdecode要求。
	NativeError							error =
		// 共通preflight。
		assessOfficialSevenZipSelection( archive, policy, selected, assessment) ;
	// 3GiBを超えるsolidに合わせた自動増枠をしない。
	if( error != 0 ||
	   assessment.disposition != OfficialSevenZipSelectionDisposition::WITHIN_DECODER_LIMIT) {
		return reject( "SELECTION_ASSESSMENT",
					  error != 0 ? error : static_cast<NativeError>( E_OUTOFMEMORY)) ;
	}

	OfficialDownloadWorkspace workspace ;	// decodeと既存検査の間だけ保持する保護領域。
	error = workspace.initialize( L"maintenance-sfx", 1U) ;
	std::uint64_t  available{} ;		// Workspace volumeの空き容量。
	ULARGE_INTEGER outputAvailable{} ;	// 研究ZIP volumeの空き容量。
	// 二つの保存先を照会し、同一volumeでも二重保持＋8GiBを残す。
	if( error != 0 || (error = workspace.queryAvailableBytes( available)) != 0 ||
	   !GetDiskFreeSpaceExW( std::filesystem::path( output).parent_path().c_str(), &outputAvailable,
							nullptr, nullptr) ||
	   available < 2U * selectedBytes + 8U * GIB ||
	   outputAvailable.QuadPart < 2U * selectedBytes + 8U * GIB) {
		return reject( "DISK_BUDGET",
					  error != 0 ? error
								 : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_DISK_FULL))) ;
	}

	std::vector<OfficialSevenZipEntry> extracted ;	// CRCとSHA検証後だけ確定する選択file。
	error = extractOfficialSevenZipFiles( archive, policy, selected, workspace, extracted) ;
	// 部分抽出・CRC失敗・未知codecを成功ZIPへ変換しない。
	if( error != 0 || extracted.size() != selected.size()) {
		return reject( "SELECTION_DECODE", error != 0 ? error : static_cast<NativeError>( E_FAIL)) ;
	}

	std::string					  rows ;	// 元index、path、size、hashをまとめて公開する証拠。
	std::vector<OfficialZipEntry> closure ;	// 同じ検証済みfile一覧を共通INF検査へ渡す。
	// 選択byteのidentityを省略せず、全rowを構築する。
	for( const OfficialSevenZipEntry &entry : extracted) {
		// JSON delimiterは要素間だけへ入れる。
		if( !rows.empty()) {
			rows += ',' ;
		}

		rows += "{\"index\":" + std::to_string( entry.archiveIndex) +
				",\"path\":" + quotedPath( entry.relativePath) +
				",\"bytes\":" + std::to_string( entry.uncompressedSize) +
				",\"sha256\":" + quotedPath( entry.sha256) + "}" ;
		closure.push_back( {entry.relativePath, entry.uncompressedSize, entry.sha256}) ;
	}

	const std::string references =
		// 実byte未検証の参照計画。
		planReferences( workspace, closure, entries) ;
	const std::string maintenance =
		// 導入検査から独立した非実行棚卸し。
		inventoryReferences( workspace, closure, entries) ;
	std::string inspections ;	// 一つの明示INFだけの内容検査結果。IDを含めない。
	// 複数INFの先行取得を一つの参照閉包合格として扱わない。
	if( infCount == 1U) {
		// 一つの選択INFへだけ共通SetupAPIと同一CAT全member検査を行う。
		for( const OfficialZipEntry &entry : closure) {
			std::wstring extension =
				// INF判定専用。
				std::filesystem::path( entry.relativePath).extension().wstring() ;
			// ASCII拡張子を正規化する。
			for( wchar_t &character : extension) {
				// 大文字だけを小文字へ変換する。
				if( character >= L'A' && character <= L'Z') {
					character += L'a' - L'A' ;
				}
			}

			// 非INF memberは構文検査の入口にしない。
			if( extension != L".inf") {
				continue ;
			}

			OfficialInfPackage package ;	// IDと参照はRAMだけに保持し、scope終了時に破棄する。
			error = inspectOfficialInfPackage( workspace, closure, entry.relativePath,
											  DISPLAY_POLICY, package) ;
			const bool structureValid = error == 0 ;	// 内容署名検査へ進んだ事実だけを保持する。
			// 構造失敗をCAT検査成功で上書きしない。
			if( structureValid) {
				error = verifyWindowsInfPackageIntegrity( workspace, package) ;
			}

			inspections =
				"{\"infPath\":" + quotedPath( entry.relativePath) +
				",\"infSha256\":" + quotedPath( entry.sha256) + ",\"stage\":\"" +
				(structureValid ? "CATALOG_INTEGRITY" : "INF_STRUCTURE") +
				"\",\"error\":" + std::to_string( static_cast<std::uint32_t>( error)) +
				",\"verified\":" + (error == 0 ? "true" : "false") + ",\"externalDependencies\":" +
				(structureValid && package.hasExternalDependencies ? "true" : "false") + "}" ;
		}
	}

	NewZip		  zip ;				// 新規研究ZIPの成功確定と失敗cleanupの単独所有者。
	std::wstring  exportHash ;		// 完成ZIPのhash。元EXE hashとは別identity。
	std::uint64_t exportBytes{} ;	// 完成ZIPのbyte数。
	error = zip.write( output, workspace, extracted, exportHash, exportBytes) ;
	// ZIP保存失敗に内容合格だけを公開しない。
	if( error != 0) {
		return reject( "EXPORT_ZIP", error) ;
	}

	std::printf(
		"{\"state\":\"SELECTED_EXPORTED\",\"inputSha256\":%s,\"selectedBytes\":%llu,"
		"\"requiredDecodeBytes\":%llu,\"exportSha256\":%s,\"exportBytes\":%llu,\"entries\":[%s],"
		"\"contentInspections\":[%s],\"referenceInspections\":[%s],\"maintenanceReferences\":[%s],\"payloadDecoded\":true,\"installAuthorized\":false,\"publishable\":false}\n",
		quotedPath( inputHash).c_str(), static_cast<unsigned long long>( selectedBytes),
		static_cast<unsigned long long>( assessment.totalRequiredUncompressedBytes),
		quotedPath( exportHash).c_str(), static_cast<unsigned long long>( exportBytes), rows.c_str(),
		inspections.c_str(), references.c_str(), maintenance.c_str()) ;
	// 証拠JSONのflush成功後だけ研究ZIPを残す。
	if( std::fflush( stdout) != 0) {
		return 2 ;
	}

	zip.commit() ;
	return 0 ;
}

/**
 * @brief 明示論理閉包を有限batchで保護取得し、全INFの直接参照内容を検査する。
 * @param[in] archive 同じ署名済み入力内のpreflight済み7z。同期借用する。
 * @param[in] policy 保守大型decodeの固定予算。通常アプリへ転用しない。
 * @param[in] indices 親が元metadataへ結合した一意の明示index集合。
 * @param[in] entries 元archive全通常fileのmetadata。
 * @param[in] rootIndex 親の明示root INF index。選択集合内に必要である。
 * @param[in] inputHash 同じlocked入力のSHA-256。
 * @param[in] directOnly trueではrootの直接sourceだけを署名検証し、依存完成を常に未確認とする。
 * @return 全取得と観測出力成功0、予算・取得・参照不正2。内容拒否は個別rowへ残す。
 * @note 実取得byteは終了時にcleanupし、導入許可・実機適合を発行しない。
 */
int verifySelectionClosure( const std::span<const std::byte>				archive,
						   const OfficialSevenZipExtractionPolicy	   &policy,
						   const std::span<const std::uint32_t>			indices,
						   const std::span<const OfficialSevenZipEntry> entries,
						   const std::uint32_t rootIndex, const std::wstring &inputHash,
						   const bool directOnly)
{
	std::vector<const OfficialSevenZipEntry *>
				  requested ;	// 元metadata内の明示memberだけを借用する。
	std::uint64_t total{} ;		// 論理取得量。batchごとの量と区別する。
	std::uint64_t infBytes{} ;	// 解析する全INFの有限byte合計。
	std::size_t	  infCount{} ;	// 4MiB以下のINF件数。
	bool		  rootFound{} ;	// rootが選択済みINFである場合だけtrue。
	// 全選択と有限予算をfile作成前に確認する。
	for( const std::uint32_t index : indices) {
		const auto found =
			std::ranges::find_if( entries, [index]( const OfficialSevenZipEntry &entry) {
				return entry.archiveIndex == index ;
			}) ; // 明示indexに対応する元通常file。
		// 未知index、一file超過、論理総量超過は部分取得前に拒否する。
		if( found == entries.end() || found->uncompressedSize > 2U * GIB ||
		   found->uncompressedSize > 8U * GIB - total) {
			return reject( "CLOSURE_CAPACITY", static_cast<NativeError>( E_INVALIDARG)) ;
		}

		total += found->uncompressedSize ;
		requested.push_back( &*found) ;
		// 過大INFを取得してから解析不能として隠さない。
		if( _wcsicmp( std::filesystem::path( found->relativePath).extension().c_str(), L".inf") == 0) {
			++infCount ;
			infBytes += found->uncompressedSize ;
			// 全INFへ既存の個別・合計・件数境界を適用する。
			if( found->uncompressedSize == 0U || found->uncompressedSize > 4U * MIB ||
			   infBytes > 64U * MIB || infCount > 512U) {
				return reject( "CLOSURE_INF_BUDGET", static_cast<NativeError>( E_INVALIDARG)) ;
			}

			rootFound = rootFound || index == rootIndex ;
		}
	}

	// 空や非INF rootを全件取得へ変換しない。
	if( !rootFound || requested.empty()) {
		return reject( "CLOSURE_ROOT", static_cast<NativeError>( E_INVALIDARG)) ;
	}

	OfficialDownloadWorkspace workspace ;												// 本processだけの保護取得領域。
	NativeError error = workspace.initialize( L"sfxclosure", GetTickCount64() + 1U) ;	// 初期化結果。
	std::uint64_t available{} ;															// 同じvolumeの実空きbyte。
	// 容量不足を途中の部分取得へ変換しない。
	if( error != 0 || (error = workspace.queryAvailableBytes( available)) != 0 ||
	   available < total + 8U * GIB) {
		return reject( "CLOSURE_DISK_BUDGET",
					  error != 0 ? error
								 : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_DISK_FULL))) ;
	}

	std::vector<OfficialSevenZipEntry> acquired ;		// CRC・SHA検証済みの実取得member。
	std::size_t						   cursor{} ;		// 次batchの開始位置。
	std::size_t						   batchCount{} ;	// 全成功した有限batch数。
	// 同じ保護領域へ2GiB以下の明示batchだけを順番に取得する。
	while( cursor < requested.size()) {
		std::vector<std::uint32_t> batch ;			// このreaderだけの一意index。
		std::uint64_t			   batchBytes{} ;	// このbatchの保存量。
		// 一件を省略せず、次の有限batchへ送る。
		while( cursor < requested.size() &&
			  requested[cursor]->uncompressedSize <= 2U * GIB - batchBytes) {
			batch.push_back( requested[cursor]->archiveIndex) ;
			batchBytes += requested[cursor]->uncompressedSize ;
			++cursor ;
		}

		OfficialSevenZipSelectionAssessment assessment{} ;	// 実必要solid量の個別評価。
		error = assessOfficialSevenZipSelection( archive, policy, batch, assessment) ;
		// Metadata量とdecoder allocation可否を別に確認する。
		if( error != 0 ||
		   assessment.disposition != OfficialSevenZipSelectionDisposition::WITHIN_DECODER_LIMIT) {
			return reject( "CLOSURE_DECODE_BUDGET",
						  error != 0 ? error : static_cast<NativeError>( E_OUTOFMEMORY)) ;
		}

		std::vector<OfficialSevenZipEntry> obtained ;	// 一batch全成功時だけ受理する実byte証拠。
		error = extractOfficialSevenZipFiles( archive, policy, batch, workspace, obtained) ;
		// 展開・CRC・hash失敗を部分合格にしない。
		if( error != 0) {
			return reject( "CLOSURE_EXTRACT", error) ;
		}

		acquired.insert( acquired.end(), obtained.begin(), obtained.end()) ;
		++batchCount ;
	}

	std::vector<OfficialZipEntry> inventory ;	// 未取得参照も含む元の全metadata。
	std::vector<OfficialZipEntry> selected ;	// 実取得済みのhash付きmember。
	// 参照解析へは元preflightの一覧だけを渡す。
	for( const OfficialSevenZipEntry &entry : entries) {
		inventory.push_back( {entry.relativePath, entry.uncompressedSize, {}}) ;
	}

	// 実取得fileを解析前のhashへ拘束する。
	for( const OfficialSevenZipEntry &entry : acquired) {
		const OfficialFileMetadataPolicy binding{entry.uncompressedSize,
												 entry.sha256} ;	// 同じ元memberの実byte。
		// 保護領域の変更を参照検査へ流さない。
		if( verifyOfficialFileMetadata( workspace.path( entry.relativePath), binding) != 0) {
			return reject( "CLOSURE_MEMBER_CHANGED", static_cast<NativeError>( TRUST_E_BAD_DIGEST)) ;
		}

		selected.push_back( {entry.relativePath, entry.uncompressedSize, entry.sha256}) ;
	}

	const std::string maintenance =
		// 独立した参照観測。
		inventoryReferences( workspace, selected, entries) ;
	// 親のstdout上限を越える棚卸し本文を出力する前に拒否する。
	if( maintenance.size() > 8U * MIB) {
		return reject( "CLOSURE_OUTPUT_BUDGET",
					  static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE))) ;
	}

	std::string inspections ;	// 各INFの署名・全member検査結果。IDは含めない。
	// 非INFを実行せず、全取得済みINFの直接参照を個別検査する。
	for( const OfficialSevenZipEntry &entry : acquired) {
		// INF以外は解析対象ではない。
		if( _wcsicmp( std::filesystem::path( entry.relativePath).extension().c_str(), L".inf") != 0) {
			continue ;
		}

		// 直接modeは明示rootだけを検査し、取得した別INFの依存充足を推定しない。
		if( directOnly && entry.archiveIndex != rootIndex) {
			continue ;
		}

		OfficialInfReferenceInventory facts ;	// 導入とは別の保守参照。
		error = inspectOfficialInfReferences( workspace, inventory, entry.relativePath, facts) ;
		bool referencesAcquired =
			// 直接modeは全直接sourceとCAT、閉包modeはCopyINFも必須。
			error == 0 ;
		// 正常に解析できた全参照を実取得一覧へ結合する。
		if( referencesAcquired) {
			std::vector<std::wstring> paths{facts.infRelativePath,
											facts.catalogRelativePath} ;	// INFとCAT必須。
			paths.insert( paths.end(), facts.sourceFiles.begin(), facts.sourceFiles.end()) ;
			// 閉包modeでは旧契約どおり全CopyINFの実取得を必須とする。
			if( !directOnly) {
				paths.insert( paths.end(), facts.copyInfPaths.begin(), facts.copyInfPaths.end()) ;
			}

			// 未取得参照を元metadataの存在だけで合格にしない。
			for( const std::wstring &path : paths) {
				const bool present =
					std::ranges::any_of( acquired, [&path]( const OfficialSevenZipEntry &member) {
						return CompareStringOrdinal( path.c_str(), -1, member.relativePath.c_str(),
													-1, TRUE) == CSTR_EQUAL ;
					}) ; // 同一元memberの実取得一致。
				referencesAcquired = referencesAcquired && present ;
			}
		}

		// 参照欠落をCAT合格にしない。
		if( error == 0 && !referencesAcquired) {
			error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND)) ;
		}

		const NativeError referenceError = error ;	// 署名結果と構造・取得結果を分離する。
		// 全参照取得後だけWindows CATと全source memberを検証する。
		if( error == 0) {
			OfficialInfPackage package ;	// 署名検証呼出しだけの一時値。アプリへ返さない。
			package.infRelativePath		= facts.infRelativePath ;
			package.catalogRelativePath = facts.catalogRelativePath ;
			package.sourceFiles			= facts.sourceFiles ;
			error						= verifyWindowsInfPackageIntegrity( workspace, package) ;
		}

		// JSON delimiterはrow間だけに追加する。
		if( !inspections.empty()) {
			inspections += ',' ;
		}

		inspections +=
			"{\"infPath\":" + quotedPath( entry.relativePath) +
			",\"infSha256\":" + quotedPath( entry.sha256) +
			",\"referenceError\":" + std::to_string( static_cast<std::uint32_t>( referenceError)) +
			(directOnly ? ",\"directReferencesAcquired\":" : ",\"referencesAcquired\":") +
			(referencesAcquired ? "true" : "false") +
			",\"integrityError\":" + std::to_string( static_cast<std::uint32_t>( error)) +
			",\"contentSignatureVerified\":" + (error == 0 ? "true" : "false") + "}" ;
	}

	std::string rows ;	// 元member indexと全検査前後で一致した実byte hash。
	// 署名検査中の差替えを拒否し、全取得memberの結果を固定する。
	for( const OfficialSevenZipEntry &entry : acquired) {
		const OfficialFileMetadataPolicy binding{entry.uncompressedSize,
												 entry.sha256} ;	// 後段検査後の同じbyte。
		// 一件でも内容が変わったら合格JSONを出さない。
		if( verifyOfficialFileMetadata( workspace.path( entry.relativePath), binding) != 0) {
			return reject( "CLOSURE_MEMBER_CHANGED", static_cast<NativeError>( TRUST_E_BAD_DIGEST)) ;
		}

		// JSON array delimiterを要素間だけに追加する。
		if( !rows.empty()) {
			rows += ',' ;
		}

		rows += "{\"index\":" + std::to_string( entry.archiveIndex) +
				",\"path\":" + quotedPath( entry.relativePath) +
				",\"bytes\":" + std::to_string( entry.uncompressedSize) +
				",\"sha256\":" + quotedPath( entry.sha256) + "}" ;
	}

	std::printf(
		"{\"state\":\"%s\",\"inputSha256\":%s,\"rootIndex\":%lu,"
		"\"selectedBytes\":%llu,\"batches\":%zu,\"entries\":[%s],\"maintenanceReferences\":[%s],"
		"\"contentInspections\":[%s],\"payloadDecoded\":true,\"installAuthorized\":false,\"publishable\":false%s}\n",
		directOnly ? "DIRECT_CONTENT_OBSERVED" : "REFERENCE_CONTENT_OBSERVED",
		quotedPath( inputHash).c_str(), static_cast<unsigned long>( rootIndex),
		static_cast<unsigned long long>( total), batchCount, rows.c_str(), maintenance.c_str(),
		inspections.c_str(), directOnly ? ",\"dependencyClosureVerified\":false" : "") ;
	return std::fflush( stdout) == 0 ? 0 : 2 ;
}

/**
 * @brief 固定予算で一つの署名済みEXEを読み、全entryと選択folder量を診断する。
 * @param[in] path 絶対local path。入力の所有権は取得しない。
 * @param[in] expectedHash 取得証拠へ結合した小文字64桁SHA-256。
 * @param[in] vendor AMD、NVIDIA、ASUS wrapperの明示値。
 * @param[in] output select時の新規absolute ZIP path。他modeでは空。
 * @param[in] selection selectと署名検査modeの明示CSV。inspect時は空。
 * @param[in] rootSelection 署名検査modeの一件root index。他modeでは空。
 * @param[in] directOnly 明示verify-direct時だけtrue。
 * @return 観測出力成功0、検査失敗2。内容署名の個別結果と実機適用性は別に扱う。
 * @note Jobと入力handleは全終了経路で解放する。親はinspectを180秒、取得modeを900秒に制限する。
 */
int inspect( const std::wstring &path, const std::wstring_view expectedHash,
			const std::wstring_view vendor, const std::wstring &output,
			const std::wstring_view selection, const std::wstring_view rootSelection,
			const bool directOnly)
{
	const bool verifying = !rootSelection.empty() ;			// 明示論理閉包modeだけで分割取得する。
	const bool selecting = !output.empty() || verifying ;	// 明示modeだけで大型予算を許可する。
	std::vector<std::uint32_t> indices ;					// 未検証CSVはdecoderへ渡さない。
	std::vector<std::uint32_t> roots ;						// 一件のroot indexだけを受理する。
	// 選択modeの非存在出力・ancestor・indexを入力読取り前に確認する。
	if( selecting &&
	   (vendor == L"ASUS" || (!verifying && !safeAncestors( output)) || !safeAncestors( path) ||
		!parseSelection( selection, indices) ||
		(verifying && (!parseSelection( rootSelection, roots) || roots.size() != 1U)))) {
		return reject( "SELECTION_ARGUMENT", static_cast<NativeError>( E_INVALIDARG)) ;
	}

	// 既存出力へ書き込みもdecodeも行わない。
	if( !output.empty() && GetFileAttributesW( output.c_str()) != INVALID_FILE_ATTRIBUTES) {
		return reject( "OUTPUT_EXISTS",
					  static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_EXISTS))) ;
	}

	MEMORYSTATUSEX memory{} ;	// 選択mode開始時だけ観測する利用可能physical memory。
	memory.dwLength = sizeof( memory) ;
	// Metadata診断を自動大型展開へ変換せず、memory不足は明示停止する。
	if( selecting && (!GlobalMemoryStatusEx( &memory) || memory.ullAvailPhys < 16U * GIB)) {
		return reject( "PHYSICAL_MEMORY_BUDGET", static_cast<NativeError>( E_OUTOFMEMORY)) ;
	}

	// 相対pathと不正identityを暗黙に補正しない。
	if( !std::filesystem::path( path).is_absolute() || expectedHash.size() != 64U ||
	   (vendor != L"AMD" && vendor != L"NVIDIA" && vendor != L"ASUS")) {
		return reject( "ARGUMENT", static_cast<NativeError>( E_INVALIDARG)) ;
	}

	// 証拠hashに任意JSON文字や大文字表記を許可しない。
	for( const wchar_t character : expectedHash) {
		// 小文字hex以外はbyte検査を開始する前に拒否する。
		if( !((character >= L'0' && character <= L'9') ||
			 (character >= L'a' && character <= L'f'))) {
			return reject( "ARGUMENT", static_cast<NativeError>( E_INVALIDARG)) ;
		}
	}

	OwnedHandle							 job( CreateJobObjectW( nullptr, nullptr),
											 &CloseHandle) ;	// この検査器だけのmemory境界。
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{} ;				// committed memoryの固定上限。
	limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY ;
	limits.ProcessMemoryLimit				= static_cast<SIZE_T>( (selecting ? 12U : 4U) * GIB) ;
	// 予算の設定と所属のどちらかが失敗した場合は巨大入力を読まない。
	if( !job ||
	   !SetInformationJobObject( job.get(), JobObjectExtendedLimitInformation, &limits,
								sizeof( limits)) ||
	   !AssignProcessToJobObject( job.get(), GetCurrentProcess())) {
		return reject( "JOB_MEMORY_LIMIT",
					  static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError()))) ;
	}

	HANDLE opened = CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
								FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
								nullptr) ;	// 書込み・削除共有を許可しない読取りsnapshot。
	// 無効handleをRAIIへ入れず、元API失敗を保持する。
	if( opened == INVALID_HANDLE_VALUE) {
		return reject( "INPUT_OPEN", static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError()))) ;
	}

	OwnedHandle input( opened, &CloseHandle) ;	// Hash・署名・全metadata検査完了まで保持する。
	BY_HANDLE_FILE_INFORMATION information{} ;	// Endpointの型とサイズを取得する。
	// Disk以外とdirectory／reparse endpointはpayloadとして読まない。
	if( GetFileType( input.get()) != FILE_TYPE_DISK ||
	   !GetFileInformationByHandle( input.get(), &information) ||
	   (information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
		   0U) {
		return reject( "INPUT_TYPE", static_cast<NativeError>( E_INVALIDARG)) ;
	}

	const std::uint64_t size = (static_cast<std::uint64_t>( information.nFileSizeHigh) << 32U) |
							   information.nFileSizeLow ;	// 取得証拠と比較する入力byte数。
	// 巨大な確保より前に有限入力上限を検証する。
	if( size == 0U || size > 2U * GIB) {
		return reject( "INPUT_SIZE",
					  static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE))) ;
	}

	std::wstring actualHash ;									// 書込みを排除した同じ入力の内容identity。
	NativeError	 error = computeFileSha256( path, actualHash) ;	// 共通hash境界の元診断。
	// 別byteを取得済み証拠へ結合しない。
	if( error != 0 || actualHash != expectedHash) {
		return reject( "HASH", error != 0 ? error : static_cast<NativeError>( TRUST_E_BAD_DIGEST)) ;
	}

	constexpr std::array<std::wstring_view, 1> NVIDIA_PUBLISHERS{
		L"NVIDIA Corporation"} ;	// 固定publisher。
	constexpr std::array<std::wstring_view, 1> AMD_PUBLISHERS{
		L"Advanced Micro Devices"} ;	// 実物の有効署名で確認した完全一致表記。
	constexpr std::array<std::wstring_view, 1> ASUS_PUBLISHERS{
		L"ASUSTeK COMPUTER INC."} ;	// Wrapperだけに限定した完全一致表記。
	error = verifyAuthenticodePublisher(
		path, vendor == L"AMD"	  ? std::span<const std::wstring_view>( AMD_PUBLISHERS)
			  : vendor == L"ASUS" ? std::span<const std::wstring_view>( ASUS_PUBLISHERS)
								  : std::span<const std::wstring_view>( NVIDIA_PUBLISHERS)) ;
	// 公式URLや構造CRCから外側署名の合格を推定しない。
	if( error != 0) {
		return reject( "AUTHENTICODE", error) ;
	}

	std::vector<std::byte> bytes( static_cast<std::size_t>( size)) ;	// 全入力を一回だけ所有する。
	std::size_t			   consumed{} ;									// 読取り済みbyte数。Advertised sizeまでに限定する。
	// 入力全byteを1MiB単位で読み、短い読みと失敗を検出する。
	while( consumed < bytes.size()) {
		const DWORD requested = static_cast<DWORD>( std::min<std::size_t>(
			// Win32一回の読取り上限。
			static_cast<std::size_t>( MIB), bytes.size() - consumed)) ;
		DWORD		obtained{} ;	// APIが実際に返したbyte数。
		// 読取りAPI失敗と途中EOFを成功にしない。
		if( !ReadFile( input.get(), bytes.data() + consumed, requested, &obtained, nullptr) ||
		   obtained == 0U || obtained > requested) {
			return reject( "INPUT_READ",
						  static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_READ_FAULT))) ;
		}

		consumed += obtained ;
	}

	OfficialSfxLayout				  layout{} ;	// 全PE／7z境界検証の成功後だけ更新する。
	const OfficialSfxInspectionPolicy sfx{2U * GIB, 16U * MIB,
										  2U * GIB} ;	// 保守専用の固定入力予算。
	error = inspectOfficialSevenZipSfx( bytes, sfx, layout) ;
	// 別container形式を署名だけで既存decoderへ流さない。
	if( error != 0) {
		return reject( "SFX_LAYOUT", error) ;
	}

	const auto archive =
		std::span<const std::byte>( bytes).subspan( static_cast<std::size_t>( layout.archiveOffset),
												  // コピーせず検証済み7z範囲だけ借用する。
												  static_cast<std::size_t>( layout.archiveSize)) ;
	const OfficialSevenZipExtractionPolicy policy{2U * GIB,
												  4U * GIB,
												  8U * GIB,
												  4U * GIB,
												  128U * MIB,
												  selecting ? 4U * GIB : 512U * MIB,
												  selecting ? 3U * GIB : 256U * MIB,
												  32'768U,
												  1'024U} ;	// アプリのpolicyは変更しない。
	std::vector<OfficialSevenZipEntry>	   entries ;		// 全preflight成功後だけ出力する通常file一覧。
	error = inspectOfficialSevenZip( archive, policy, entries) ;
	// Path・codec・dictionary・宣言容量の失敗を部分一覧で隠さない。
	if( error != 0) {
		return reject( "SEVEN_ZIP_METADATA", error) ;
	}

	// 明示選択だけを保護展開へ渡し、通常構造診断は従来の出力を維持する。
	if( verifying) {
		return verifySelectionClosure( archive, policy, indices, entries, roots.front(), actualHash,
									  directOnly) ;
	}

	// 従来selectの保存量とZIP契約は変更しない。
	if( selecting) {
		return extractSelection( archive, policy, indices, entries, output, actualHash) ;
	}

	std::vector<std::uint32_t> selected ;	// 診断用のINF／CAT／SYS index。導入計画ではない。
	std::string				   rows ;		// 出力前に全rowを構築し、partial JSONの合格を防ぐ。
	std::uint64_t			   expanded{} ;	// 全通常fileの宣言展開量。Preflightで上限検証済み。
	// 全entryを一度ずつ走査して公開file配置と選択要求量を記録する。
	for( const OfficialSevenZipEntry &entry : entries) {
		expanded += entry.uncompressedSize ;
		std::wstring lower = entry.relativePath ;	// 拡張子判定だけのASCII正規化。
		// 固定ASCII英字だけを正規化し、locale依存のpath変換をしない。
		for( wchar_t &character : lower) {
			// 大文字英字を同じASCII file名の小文字へ変換する。
			if( character >= L'A' && character <= L'Z') {
				character += L'a' - L'A' ;
			}
		}

		// Driver関連拡張子だけの診断集合を作り、appを導入対象にしない。
		if( lower.ends_with( L".inf") || lower.ends_with( L".cat") || lower.ends_with( L".sys")) {
			selected.push_back( entry.archiveIndex) ;
		}

		// JSON arrayに余分な先頭delimiterを入れない。
		if( !rows.empty()) {
			rows += ',' ;
		}

		rows += "{\"index\":" + std::to_string( entry.archiveIndex) +
				",\"path\":" + quotedPath( entry.relativePath) +
				",\"bytes\":" + std::to_string( entry.uncompressedSize) + "}" ;
	}

	OfficialSevenZipSelectionAssessment assessment{} ;	// Metadataだけで計算する固有folder要求。
	// Driver entryがない場合は空選択を全件展開と解釈しない。
	if( !selected.empty()) {
		error = assessOfficialSevenZipSelection( archive, policy, selected, assessment) ;
		// 選択indexが検証済み一覧と一致しない場合は結果を公開しない。
		if( error != 0) {
			return reject( "SELECTION_ASSESSMENT", error) ;
		}
	}

	std::string folders ;	// 全folder要求を構築してからstdoutへ出す。
	// 固有folderだけを記録し、複数選択fileの共有量を二重加算しない。
	for( const OfficialSevenZipFolderRequirement &folder : assessment.folders) {
		// JSON array delimiterは要素間だけに置く。
		if( !folders.empty()) {
			folders += ',' ;
		}

		folders += "{\"index\":" + std::to_string( folder.folderIndex) +
				   ",\"bytes\":" + std::to_string( folder.uncompressedBytes) +
				   ",\"selectedFiles\":" + std::to_string( folder.selectedFileCount) + "}" ;
	}

	std::string hash ;	// 検証済み小文字ASCIIだけのhash。
	// Expected hashとの完全一致でASCII範囲が確定した64文字だけを変換する。
	for( const wchar_t character : actualHash) {
		hash.push_back( static_cast<char>( character)) ;
	}

	std::printf( "{\"state\":\"METADATA_VALID\",\"inputSha256\":\"%s\",\"inputBytes\":%llu,"
				"\"archiveOffset\":%llu,\"archiveBytes\":%llu,\"certificatePaddingBytes\":%llu,"
				"\"files\":%zu,\"declaredExpandedBytes\":%llu,\"selectedFiles\":%zu,"
				"\"decodeLimitBytes\":%llu,\"selectionDisposition\":\"%s\","
				"\"requiredDecodeBytes\":%llu,\"folders\":[%s],\"entries\":[%s],"
				"\"payloadDecoded\":false,\"contentSignatureVerified\":false}\n",
				hash.c_str(), static_cast<unsigned long long>( size),
				static_cast<unsigned long long>( layout.archiveOffset),
				static_cast<unsigned long long>( layout.archiveSize),
				static_cast<unsigned long long>( layout.certificatePaddingSize), entries.size(),
				static_cast<unsigned long long>( expanded), selected.size(),
				static_cast<unsigned long long>( policy.maximumSingleAllocationBytes),
				selected.empty() ? "NO_DRIVER_ENTRIES"
				: assessment.disposition ==
						OfficialSevenZipSelectionDisposition::SOLID_BLOCK_TOO_LARGE
					? "SOLID_BLOCK_TOO_LARGE"
					: "WITHIN_DECODER_LIMIT",
				static_cast<unsigned long long>( assessment.totalRequiredUncompressedBytes),
				folders.c_str(), rows.c_str()) ;
	return std::fflush( stdout) == 0 ? 0 : 2 ;
}

} // namespace
} // namespace drivercrate

/**
 * @brief 明示されたlocal EXEだけを保守構造診断へ渡す。
 * @param[in] argc inspectは5、selectと署名検査modeは7の固定引数数。
 * @param[in] argv OS所有のNULL終端Unicode引数。保持しない。
 * @return 成功0、mode不正2、memoryまたは例外失敗2。
 * @note 例外をentry pointから漏らさない。入力をprocessとして起動しない。
 */
int wmain( const int argc, wchar_t **argv)
{
	// 明示mode以外ではpayloadを一切読まない。
	if( !((argc == 5 && std::wstring_view( argv[1]) == L"--inspect") ||
		 (argc == 7 &&
		  (std::wstring_view( argv[1]) == L"--select" ||
		   std::wstring_view( argv[1]) == L"--verify-closure" ||
		   std::wstring_view( argv[1]) == L"--verify-direct") &&
		  argv[5][0] != L'\0'))) {
		return drivercrate::reject( "ARGUMENT", static_cast<drivercrate::NativeError>( E_INVALIDARG)) ;
	}

	try {
		const bool directOnly =
			// 明示直接内容検査。
			std::wstring_view( argv[1]) == L"--verify-direct" ;
		const bool verifying =
			// 新規modeを従来ZIP保存と分離する。
			std::wstring_view( argv[1]) == L"--verify-closure" || directOnly ;
		return drivercrate::inspect(
			argv[2], argv[3], argv[4], argc == 7 && !verifying ? argv[5] : L"",
			argc == 7 ? argv[6] : L"", verifying ? argv[5] : L"", directOnly) ;
	} catch( const std::bad_alloc &) {
		return drivercrate::reject( "ALLOCATION",
								   static_cast<drivercrate::NativeError>( E_OUTOFMEMORY)) ;
	} catch( ...) {
		return drivercrate::reject( "EXCEPTION", static_cast<drivercrate::NativeError>( E_FAIL)) ;
	}
}
