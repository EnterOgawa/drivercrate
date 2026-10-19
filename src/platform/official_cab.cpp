//------------------------------------------------------------------------------
/**
 * @file official_cab.cpp
 * @brief 公式CAB安全解析および選択展開実装。
 * @version 01.00.00
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Callback例外時の予約file破棄追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  複数展開fileの例外安全cleanup追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Cleanup fault-injection境界追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note SetupIterateCabinetWで全entryを事前列挙し、選択fileだけを非存在確認済みの保護workspace pathへ展開します。分割CABは拒否します。
 */
//------------------------------------------------------------------------------

#include "platform/official_cab.h"

#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"

#include <SetupAPI.h>
#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <iterator>
#include <limits>
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

constexpr std::size_t MAXIMUM_ARCHIVE_PATH_CHARACTERS	= 240U ;	// Workspace基準相対path上限。
constexpr std::size_t MAXIMUM_PATH_COMPONENT_CHARACTERS = 120U ;	// 一path要素の文字数上限。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief 一回のCAB列挙と選択展開状態をcallback間で保持する。
 */
struct CabinetIterationContext {
	/// 列挙全体に適用する非所有policy。
	const OfficialCabExtractionPolicy *policy{} ;
	/// 選択展開する固定path群。
	std::span<const std::wstring_view> selectedFiles ;
	/// 展開modeの出力を所有する領域。
	OfficialDownloadWorkspace		  *workspace{} ;
	/// 検証済み通常fileの列挙先。
	std::vector<OfficialZipEntry>	  *entries{} ;
	/// 大文字小文字無視の重複検出key群。
	std::vector<std::wstring>		   comparisonKeys ;
	/// 今回workspaceに作成した追跡対象path群。
	std::vector<std::wstring>		   createdFiles ;
	/// SetupAPIが完了通知した選択path群。
	std::vector<std::wstring>		   extractedFiles ;
	/// 次のFILEEXTRACTED通知を待つ相対path。
	std::wstring					   pendingRelativePath ;
	/// 次のFILEEXTRACTEDで照合する絶対path。
	std::wstring					   pendingTargetPath ;
	/// 次の展開完了時に照合するentry byte数。
	std::uint64_t					   pendingFileBytes{} ;
	/// 現在までの展開後公称byte数合計。
	std::uint64_t					   expandedBytes{} ;
	/// Callback内で最初に確定した失敗理由。
	NativeError						   error{} ;
	/// trueの場合は選択fileを作成する。
	bool							   extractSelected{} ;
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
 * @brief Pathがlocal drive上の絶対pathか検証する。
 *
 * CWD依存、UNC、device pathまたは埋込みnullをCAB境界へ入れない。
 *
 * @param[in] path SetupAPIへ渡すCAB file path。
 * @return `C:\\...`形式の絶対pathなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isLocalAbsolutePath( const std::wstring_view path) noexcept
{
	// local drive絶対pathの形式に合わない入力や埋込NULを拒否する。
	if( path.size() < 3U || path[1] != L':' || path[2] != L'\\' ||
	   path.find( L'\0') != std::wstring_view::npos) {
		return false ;
	}

	const wchar_t drive = path.front() ;	// ASCII drive letter候補。
	return (drive >= L'A' && drive <= L'Z') || (drive >= L'a' && drive <= L'z') ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASCII大文字を小文字へ変換する。
 *
 * Windows file systemの大文字小文字衝突検出に使用する。
 *
 * @param[in] character CAB pathを構成するASCII文字。
 * @return A～Zは小文字、それ以外は入力値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] wchar_t asciiLower( const wchar_t character) noexcept
{
	return character >= L'A' && character <= L'Z' ? static_cast<wchar_t>( character - L'A' + L'a')
												  : character ;
}

//------------------------------------------------------------------------------
/**
 * @brief CAB path要素が安全なWindows通常名か検証する。
 *
 * Dot component、ADS、禁止文字、DOS device名を拒否する。
 *
 * @param[in] value Separatorを含まないASCII path要素。
 * @return Workspaceに通常fileとして作成可能な場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafeComponent( const std::wstring_view value) noexcept
{
	// 空、過大、相対移動、末尾dot・空白を含むpath要素を拒否する。
	if( value.empty() || value.size() > MAXIMUM_PATH_COMPONENT_CHARACTERS || value == L"." ||
	   value == L".." || value.back() == L'.' || value.back() == L' ') {
		return false ;
	}

	// 各文字を確認し、Unicode別名やalternate data streamを許可しない。
	for( const wchar_t character : value) {
		// CAB path要素を印字可能ASCIIとWindows許可文字へ制限する。
		if( character < 0x20 || character > 0x7e ||
		   std::wstring_view( L"<>:\"|?*").find( character) != std::wstring_view::npos) {
			return false ;
		}
	}

	std::wstring stem( value.substr( 0, value.find( L'.'))) ;	// DOS予約名判定用stem。
	std::ranges::transform( stem, stem.begin(), asciiLower) ;
	// Windows予約device名を通常file名として作成しない。
	if( stem == L"con" || stem == L"prn" || stem == L"aux" || stem == L"nul") {
		return false ;
	}

	const bool numberedDevice =
		// COM1／LPT1形式。
		stem.size() == 4U && stem[3] >= L'1' && stem[3] <= L'9' ;
	return !numberedDevice || (stem.substr( 0, 3) != L"com" && stem.substr( 0, 3) != L"lpt") ;
}

//------------------------------------------------------------------------------
/**
 * @brief CAB entry名を安全なWorkspace相対pathへ変換する。
 *
 * Root、dot要素、空要素とWindows別名をfail-closedで拒否する。
 *
 * @param[in] rawPath CABが通知したentry名。
 * @param[out] relativePath 成功時の`\\`区切りASCII相対path。
 * @param[out] comparisonKey 大文字小文字無視の重複検出key。
 * @return 安全な通常file pathなら0、それ以外はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError parseCabPath( const std::wstring_view rawPath, std::wstring &relativePath,
									   std::wstring &comparisonKey)
{
	relativePath.clear() ;
	comparisonKey.clear() ;
	// 空、絶対、過大、未完のCAB pathをworkspace相対pathにしない。
	if( rawPath.empty() || rawPath.size() > MAXIMUM_ARCHIVE_PATH_CHARACTERS ||
	   rawPath.front() == L'\\' || rawPath.front() == L'/' ||
	   rawPath.find( L'\0') != std::wstring_view::npos || rawPath.back() == L'\\' ||
	   rawPath.back() == L'/') {
		return nativeErrorFromWin32( ERROR_INVALID_NAME) ;
	}

	std::size_t beginning{} ;	// 現在path要素の開始位置。
	// Separatorごとに全要素を検証して正規化pathへ追加する。
	while( beginning < rawPath.size()) {
		const std::size_t separator = rawPath.find_first_of( L"\\/", beginning) ;	// 次の区切り。
		const std::size_t ending	= separator == std::wstring_view::npos
										  ? rawPath.size()
										  : separator ;	// 現在要素の終了位置。
		const std::wstring_view component =
			// 現在検証する要素。
			rawPath.substr( beginning, ending - beginning) ;
		// 安全なWindows通常名でない要素を展開先pathへ含めない。
		if( !isSafeComponent( component)) {
			return nativeErrorFromWin32( ERROR_INVALID_NAME) ;
		}

		// 二つ目以降の要素にだけpath区切りを追加する。
		if( !relativePath.empty()) {
			relativePath.push_back( L'\\') ;
			comparisonKey.push_back( L'\\') ;
		}

		relativePath.append( component) ;
		std::ranges::transform( component, std::back_inserter( comparisonKey), asciiLower) ;
		// 最後のpath要素を処理したら分解を終える。
		if( separator == std::wstring_view::npos) {
			break ;
		}

		beginning = separator + 1U ;
	}

	return relativePath.empty() ? nativeErrorFromWin32( ERROR_INVALID_NAME) : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 絶対pathのCAB入力file属性とsizeを検証する。
 *
 * Directoryとreparse pointをSetupAPIへ渡さず拒否する。
 *
 * @param[in] path 検査対象CABの絶対path。
 * @param[in] maximumBytes 入力fileの有限上限byte数。
 * @return 空でない通常fileが上限内なら0、それ以外はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateArchiveFile( const std::wstring_view path,
											  const std::uint64_t	  maximumBytes)
{
	// local絶対pathと有限byte上限をCAB入力の前提にする。
	if( !isLocalAbsolutePath( path) || maximumBytes == 0) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring		  terminatedPath( path) ;	// Win32 APIに渡すnull終端付きpath。
	WIN32_FILE_ATTRIBUTE_DATA attributes{} ;			// 入力fileの種類と64-bit size。
	// CAB入力fileの属性取得失敗を元の診断値で返す。
	if( GetFileAttributesExW( terminatedPath.c_str(), GetFileExInfoStandard, &attributes) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	constexpr DWORD REJECTED_ATTRIBUTES =
		FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT ;	// CABで拒否する属性。
	// 禁止属性を持つfileをCAB入力として受理しない。
	if( (attributes.dwFileAttributes & REJECTED_ATTRIBUTES) != 0) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	ULARGE_INTEGER size{} ;	// HighとLowを結合した入力file byte数。
	size.LowPart  = attributes.nFileSizeLow ;
	size.HighPart = attributes.nFileSizeHigh ;
	return size.QuadPart == 0 || size.QuadPart > maximumBytes
			   ? nativeErrorFromWin32( ERROR_FILE_TOO_LARGE)
			   : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つのCAB相対pathが一致するか確認する。
 *
 * Windowsのordinal比較を使用し、prefix一致は行わない。
 *
 * @param[in] left 比較する一つ目の正規化済み相対path。
 * @param[in] right 比較する二つ目の正規化済み相対path。
 * @return 大文字小文字を除いて完全一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool pathsEqual( const std::wstring_view left, const std::wstring_view right) noexcept
{
	// Windows比較APIの長さ型を超えるpathを比較へ渡さない。
	if( left.size() > static_cast<std::size_t>( std::numeric_limits<int>::max()) ||
	   right.size() > static_cast<std::size_t>( std::numeric_limits<int>::max())) {
		return false ;
	}

	return CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択pathが現在CAB entryと一致するか確認する。
 *
 * Windows file systemの同一path規則で全選択値を照合する。
 *
 * @param[in] relativePath 正規化済みのCAB相対path。
 * @param[in] selectedFiles 呼出側が固定した選択path群。
 * @return 一つの選択pathと完全一致すれば`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSelected( const std::wstring_view				   relativePath,
							  const std::span<const std::wstring_view> selectedFiles) noexcept
{
	return std::ranges::any_of( selectedFiles,
							   [relativePath]( const std::wstring_view selected) noexcept {
								   return pathsEqual( relativePath, selected) ;
							   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Workspaceが追跡するCAB展開fileを一件破棄する。
 *
 * Best-effort cleanup境界から型付きworkspace処理へ戻す。Contextの有効期間は同期呼出し中に限定する。
 *
 * @param[in] context `OfficialDownloadWorkspace`を指す非所有値。
 * @param[in] relativePath Workspaceが追跡する検証済み相対path。
 * @return 破棄成功時は0、null contextまたは破棄失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError discardWorkspaceCabFile( void *const			  context,
												  const std::wstring_view relativePath)
{
	// 所有contextなしでworkspace fileを破棄しない。
	if( context == nullptr) {
		return static_cast<NativeError>( E_POINTER) ;
	}

	auto *const workspace =
		// 呼出側が保証する非所有workspace。
		static_cast<OfficialDownloadWorkspace *>( context) ;
	return workspace->discardFile( relativePath) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Callback例外時の予約fileを即時破棄する。
 *
 * 予約後のcontainer更新が例外となっても、partial fileをworkspaceのdestructorまで残さない。
 *
 * @param[in,out] context 予約中fileを保持するCAB列挙状態。
 * @return 予約がないか破棄成功時は0、cleanup失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError discardPendingExternalFile( CabinetIterationContext &context) noexcept
{
	NativeError result{} ;	// Callback ABIから外へ例外を漏らさなcleanup結果。
	// workspaceと予約先が揃う場合だけ未完了の外部出力をcleanupする。
	if( context.workspace != nullptr && !context.pendingRelativePath.empty() &&
	   !context.pendingTargetPath.empty()) {
		try {
			result = context.workspace->discardFile( context.pendingRelativePath) ;
		} catch( const std::bad_alloc &) {
			result = static_cast<NativeError>( E_OUTOFMEMORY) ;
		} catch( ...) {
			// Callback ABIで表現できないcleanup例外を一般失敗として保持する。
			result = static_cast<NativeError>( E_FAIL) ;
		}
	}

	context.pendingRelativePath.clear() ;
	context.pendingTargetPath.clear() ;
	context.pendingFileBytes = 0U ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief CAB展開で作成した全fileを可能な限り即時破棄する。
 *
 * 一fileのcleanup失敗または例外で残りの破棄を中断しない。削除失敗fileはworkspaceのdestructor追跡に残す。
 *
 * @param[in,out] context 今回作成した相対path群を保持する列挙状態。
 * @return 全fileの破棄成功時は0、失敗があれば最初のHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError discardCreatedExternalFiles( CabinetIterationContext &context) noexcept
{
	const OfficialCabFileDiscardOperation operation{
		.context  = context.workspace,
		.callback = discardWorkspaceCabFile,
	} ; // Workspace所有fileを同期破棄するcallback境界。
	const NativeError firstError = discardOfficialCabFilesBestEffort(
		context.createdFiles, operation) ;	// 全fileを試行した後の最初のcleanup失敗。
	context.createdFiles.clear() ;
	return firstError ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二回のCAB inventoryが完全一致するか確認する。
 *
 * 事前検査後に差し替えられたCABからfileを採用しない。
 *
 * @param[in] left 事前列挙で固定したentry群。
 * @param[in] right 選択展開時に再列挙したentry群。
 * @return 順序、path、展開後sizeが全て一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool inventoriesEqual( const std::span<const OfficialZipEntry> left,
									const std::span<const OfficialZipEntry> right) noexcept
{
	return left.size() == right.size() &&
		   std::ranges::equal(
			   left, right,
			   []( const OfficialZipEntry &first, const OfficialZipEntry &second) noexcept {
				   return first.uncompressedSize == second.uncompressedSize &&
						  pathsEqual( first.relativePath, second.relativePath) ;
			   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief CAB列挙entryを有限上限と選択条件で処理する。
 *
 * Callback ABI外へexceptionを漏らさず、分割CABと上限超過を拒否する。
 *
 * @param[in,out] context CabinetIterationContextへの非所有pointer。
 * @param[in] notification SetupAPI通知種類。
 * @param[in] parameter1 通知固有構造体のpointer値。
 * @param[in] parameter2 未使用の通知固有値。
 * @return 通知契約に対応するFILEOP値、NO_ERRORまたはWin32 error。
 */
//------------------------------------------------------------------------------
UINT CALLBACK cabinetCallback( const PVOID context, const UINT notification,
							  const UINT_PTR parameter1, const UINT_PTR parameter2)
{
	static_cast<void>( parameter2) ;
	try {
		auto *state = static_cast<CabinetIterationContext *>( context) ;	// 非所有の列挙状態。
		// callback状態が欠ける場合は列挙または抽出を中止する。
		if( state == nullptr || state->policy == nullptr || state->entries == nullptr) {
			return notification == SPFILENOTIFY_FILEINCABINET ? FILEOP_ABORT : ERROR_INVALID_DATA ;
		}

		// 別CABを要求する分割archiveを追跡しない。
		if( notification == SPFILENOTIFY_NEEDNEWCABINET) {
			state->error = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			return ERROR_NOT_SUPPORTED ;
		}

		// CAB内file通知ではpath、size、重複、選択範囲を検証する。
		if( notification == SPFILENOTIFY_FILEINCABINET) {
			auto *information =
				reinterpret_cast<FILE_IN_CABINET_INFO_W *>( parameter1) ;	// CAB entry情報。
			// 欠落またはerror付きのCAB entry情報を拒否する。
			if( information == nullptr || information->NameInCabinet == nullptr ||
			   information->Win32Error != NO_ERROR) {
				state->error = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				return FILEOP_ABORT ;
			}

			std::wstring relativePath ;		// 検証と正規化を完了したentry path。
			std::wstring comparisonKey ;	// 大文字小文字無視の重複検出key。
			state->error = parseCabPath( information->NameInCabinet, relativePath, comparisonKey) ;
			const bool duplicate =	// Windowsで同一fileとなるentry名が先に出現済み。
				std::ranges::find( state->comparisonKeys, comparisonKey) !=
				state->comparisonKeys.end() ;
			const bool totalOverflow =	// 現在entry追加で合計上限を超える状態。
				information->FileSize > state->policy->maximumTotalExpandedBytes ||
				state->expandedBytes >
					state->policy->maximumTotalExpandedBytes - information->FileSize ;
			// path不正、file数・byte上限超過、重複entryを検出して列挙を中止する。
			if( state->error != 0 || information->FileSize > state->policy->maximumSingleFileBytes ||
			   state->entries->size() >= state->policy->maximumEntryCount || totalOverflow ||
			   duplicate) {
				// 先行path診断がない場合だけ重複または容量超過を記録する。
				if( state->error == 0) {
					state->error =
						nativeErrorFromWin32( duplicate ? ERROR_DUP_NAME : ERROR_FILE_TOO_LARGE) ;
				}

				return FILEOP_ABORT ;
			}

			state->expandedBytes += information->FileSize ;
			state->comparisonKeys.push_back( std::move( comparisonKey)) ;
			state->entries->push_back( OfficialZipEntry{relativePath, information->FileSize, {}}) ;
			// 検査のみの場合と未選択fileは展開せず読み飛ばす。
			if( !state->extractSelected || !isSelected( relativePath, state->selectedFiles)) {
				return FILEOP_SKIP ;
			}

			// workspaceなしや前fileの未完了状態では新しい抽出を開始しない。
			if( state->workspace == nullptr || !state->pendingTargetPath.empty()) {
				state->error = nativeErrorFromWin32( ERROR_INVALID_STATE) ;
				return FILEOP_ABORT ;
			}

			state->pendingRelativePath = relativePath ;
			state->pendingFileBytes	   = information->FileSize ;
			state->error =
				state->workspace->prepareExternalFile( relativePath, state->pendingTargetPath) ;
			// 出力予約が失敗した場合はCAB抽出を中止する。
			if( state->error != 0) {
				return FILEOP_ABORT ;
			}

			state->createdFiles.push_back( relativePath) ;
			// 抽出先pathが空、長過ぎる、copy不能なら切り詰めず拒否する。
			if( state->pendingTargetPath.empty() || state->pendingTargetPath.size() >= MAX_PATH ||
			   wcscpy_s( information->FullTargetName, MAX_PATH, state->pendingTargetPath.c_str()) !=
				   0) {
				state->error = nativeErrorFromWin32( ERROR_FILENAME_EXCED_RANGE) ;
				return FILEOP_ABORT ;
			}

			return FILEOP_DOIT ;
		}

		// 抽出完了通知では予約先との一致を確認してworkspace所有へ取り込む。
		if( notification == SPFILENOTIFY_FILEEXTRACTED) {
			const auto *paths = reinterpret_cast<const FILEPATHS_W *>( parameter1) ;	// 展開結果。
			// 失敗通知や予約先と異なる抽出先を成功扱いしない。
			if( paths == nullptr || paths->Win32Error != ERROR_SUCCESS || paths->Target == nullptr ||
			   state->pendingTargetPath.empty() ||
			   _wcsicmp( paths->Target, state->pendingTargetPath.c_str()) != 0) {
				state->error = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				return ERROR_INVALID_DATA ;
			}

			state->error =
				state->workspace->adoptFile( state->pendingRelativePath, state->pendingFileBytes) ;
			// workspaceへの取り込みが失敗したfileを完了扱いしない。
			if( state->error != 0) {
				return ERROR_INVALID_DATA ;
			}

			state->extractedFiles.push_back( std::move( state->pendingRelativePath)) ;
			state->pendingTargetPath.clear() ;
			state->pendingFileBytes = 0 ;
			return NO_ERROR ;
		}

		return NO_ERROR ;
	} catch( const std::bad_alloc &) {
		auto *state =
			// 失敗理由を保存する非所有状態。
			static_cast<CabinetIterationContext *>( context) ;
		// callback例外時に状態が残っていれば予約fileを破棄して診断を保持する。
		if( state != nullptr) {
			const NativeError cleanupError =
				// 予約fileの即時破棄結果。
				discardPendingExternalFile( *state) ;
			state->error =
				cleanupError != 0 ? cleanupError : static_cast<NativeError>( E_OUTOFMEMORY) ;
		}

		return notification == SPFILENOTIFY_FILEINCABINET ? FILEOP_ABORT : ERROR_OUTOFMEMORY ;
	} catch( ...) {
		auto *state =
			// 不明失敗を保存する非所有状態。
			static_cast<CabinetIterationContext *>( context) ;
		// callback例外時に状態が残っていれば予約fileを破棄して診断を保持する。
		if( state != nullptr) {
			const NativeError cleanupError =
				// 予約fileの即時破棄結果。
				discardPendingExternalFile( *state) ;
			state->error = cleanupError != 0 ? cleanupError : static_cast<NativeError>( E_FAIL) ;
		}

		return notification == SPFILENOTIFY_FILEINCABINET ? FILEOP_ABORT : ERROR_INVALID_DATA ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief SetupAPIでCABを一回列挙する。
 *
 * Callback内の明示的失敗理由をGetLastErrorより優先して返す。
 *
 * @param[in] archivePath 検証済みCABの絶対path。
 * @param[in,out] context 列挙または展開の有限状態。
 * @return 全通知の処理成功時は0、callbackまたはSetupAPI失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError iterateCabinet( const std::wstring_view  archivePath,
										 CabinetIterationContext &context)
{
	const std::wstring terminatedPath( archivePath) ;	// SetupAPI用null終端付きCAB path。
	// 列挙API失敗時はcallbackの詳細診断を優先して返す。
	if( SetupIterateCabinetW( terminatedPath.c_str(), 0, cabinetCallback, &context) == FALSE) {
		return context.error != 0 ? context.error : nativeErrorFromWin32( GetLastError()) ;
	}

	// API成功でもcallback失敗や未完了予約が残る結果を拒否する。
	if( context.error != 0 || !context.pendingTargetPath.empty()) {
		return context.error != 0 ? context.error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択file path群の構文と一意性を検証する。
 *
 * CABを読む前に曖昧な選択とcase違いの重複を拒否する。
 *
 * @param[in] selectedFiles `\\`区切りの固定相対path群。
 * @return 一件以上の安全かつ一意なpath群なら0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateSelectedFiles(
	const std::span<const std::wstring_view> selectedFiles)
{
	// 空の選択集合を全file展開へ読み替えない。
	if( selectedFiles.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		std::vector<std::wstring> keys ;	// 検証済み選択pathの比較key群。
		keys.reserve( selectedFiles.size()) ;
		// 全選択pathの正規化結果と重複をfile作成前に確認する。
		for( const std::wstring_view selectedFile : selectedFiles) {
			std::wstring	  relativePath ;	// 現在選択値の正規化path。
			std::wstring	  comparisonKey ;	// 現在選択値の大文字小文字無視key。
			const NativeError error =
				// 構文検証結果。
				parseCabPath( selectedFile, relativePath, comparisonKey) ;
			// 非正規pathと大小文字を除く重複選択を拒否する。
			if( error != 0 || relativePath != selectedFile ||
			   std::ranges::find( keys, comparisonKey) != keys.end()) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			keys.push_back( std::move( comparisonKey)) ;
		}
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	return 0 ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_cab.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError discardOfficialCabFilesBestEffort(
	const std::span<const std::wstring>	   relativePaths,
	const OfficialCabFileDiscardOperation &operation) noexcept
{
	// 破棄callbackがない操作でcleanup成功を装わない。
	if( operation.callback == nullptr) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	NativeError firstError{} ;	// 全pathを処理した後に返す最初の失敗。
	// 各pathを独立して処理し、一件の失敗または例外でloopを中断しない。
	for( const std::wstring &relativePath : relativePaths) {
		NativeError error{} ;	// 現在pathの破棄結果または例外変換値。
		try {
			error = operation.callback( operation.context, relativePath) ;
		} catch( const std::bad_alloc &) {
			error = static_cast<NativeError>( E_OUTOFMEMORY) ;
		} catch( ...) {
			// Callback境界から漏らせない例外を一般失敗として保持する。
			error = static_cast<NativeError>( E_FAIL) ;
		}

		// 全fileのcleanupを続けながら最初の失敗だけを保持する。
		if( firstError == 0 && error != 0) {
			firstError = error ;
		}
	}

	return firstError ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_cab.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError inspectOfficialCab( const std::wstring_view			  archivePath,
							   const OfficialCabExtractionPolicy &policy,
							   std::vector<OfficialZipEntry>	 &entries)
{
	entries.clear() ;
	// archive、単一file、総byte、entry数に有限の上限を要求する。
	if( policy.maximumArchiveBytes == 0 || policy.maximumSingleFileBytes == 0 ||
	   policy.maximumTotalExpandedBytes == 0 || policy.maximumEntryCount == 0) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const NativeError fileError =
		// 入力file検証結果。
		validateArchiveFile( archivePath, policy.maximumArchiveBytes) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( fileError != 0) {
		return fileError ;
	}

	try {
		CabinetIterationContext context{
			.policy	 = &policy,
			.entries = &entries,
		} ; // 書込みを行わない事前列挙状態。
		const NativeError error = iterateCabinet( archivePath, context) ;	// CAB列挙結果。
		// 列挙失敗や空のCABでは部分inventoryを公開しない。
		if( error != 0 || entries.empty()) {
			entries.clear() ;
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		return 0 ;
	} catch( const std::bad_alloc &) {
		entries.clear() ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_cab.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError extractOfficialCabFiles( const std::wstring_view					 archivePath,
									const OfficialCabExtractionPolicy		&policy,
									const std::span<const std::wstring_view> selectedFiles,
									OfficialDownloadWorkspace				&workspace,
									std::vector<OfficialZipEntry>			&entries)
{
	entries.clear() ;
	const NativeError selectionError =
		// 選択pathの事前検証結果。
		validateSelectedFiles( selectedFiles) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( selectionError != 0) {
		return selectionError ;
	}

	std::vector<OfficialZipEntry> inspected ;									// 書込み前に確定したCAB全file群。
	NativeError error = inspectOfficialCab( archivePath, policy, inspected) ;	// 事前検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	// 各選択pathが事前検証済みCABへ一つずつ存在することを確認する。
	for( const std::wstring_view selectedFile : selectedFiles) {
		// 選択pathが事前inventoryに存在しなければ抽出しない。
		if( !std::ranges::any_of( inspected, [selectedFile]( const OfficialZipEntry &entry) noexcept {
			   return pathsEqual( entry.relativePath, selectedFile) ;
		   })) {
			return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
		}
	}

	std::vector<OfficialZipEntry> secondInspection ;	// 展開中に再検証するCAB全file群。
	CabinetIterationContext		  context{
			  .policy		   = &policy,
			  .selectedFiles   = selectedFiles,
			  .workspace	   = &workspace,
			  .entries		   = &secondInspection,
			  .extractSelected = true,
	  } ; // 選択展開を有効にした二回目の列挙状態。
	try {
		context.createdFiles.reserve( selectedFiles.size()) ;
		context.extractedFiles.reserve( selectedFiles.size()) ;
		error = iterateCabinet( archivePath, context) ;
		// 再列挙inventoryと抽出件数が事前検査に一致することを確認する。
		if( error == 0 && (context.extractedFiles.size() != selectedFiles.size() ||
						  !inventoriesEqual( inspected, secondInspection))) {
			error = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// 抽出失敗時は今回作成したfileだけを即時破棄する。
		if( error != 0) {
			// 今回作成したfileだけを即時破棄し、workspaceの再利用を可能にする。
			const NativeError cleanupError =
				// 全fileの即時破棄結果。
				discardCreatedExternalFiles( context) ;
			static_cast<void>( cleanupError) ;
			return error ;
		}

		entries.reserve( selectedFiles.size()) ;
		// 呼出側の選択順を維持して実sizeとSHA-256を固定する。
		for( const std::wstring_view selectedFile : selectedFiles) {
			const auto inspectedEntry = std::ranges::find_if(
				inspected, [selectedFile]( const OfficialZipEntry &entry) noexcept {
					return pathsEqual( entry.relativePath, selectedFile) ;
				}) ;																	// 対応entry。
			const std::wstring path = workspace.path( inspectedEntry->relativePath) ;	// 展開先。
			WIN32_FILE_ATTRIBUTE_DATA attributes{} ;									// 展開後の種類と実size。
			// 展開fileの保護pathを解決できなければ検証を中止する。
			if( path.empty()) {
				error = static_cast<NativeError>( E_INVALIDARG) ;
				break ;
			}

			// 展開fileの属性取得失敗を保持して検証を中止する。
			if( GetFileAttributesExW( path.c_str(), GetFileExInfoStandard, &attributes) == FALSE) {
				error = nativeErrorFromWin32( GetLastError()) ;
				break ;
			}

			// 展開結果が通常file以外へ変わっていたら拒否する。
			if( (attributes.dwFileAttributes &
				(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
				error = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				break ;
			}

			ULARGE_INTEGER size{} ;	// 展開後fileの64-bit byte数。
			size.LowPart  = attributes.nFileSizeLow ;
			size.HighPart = attributes.nFileSizeHigh ;
			// 展開後の実sizeが事前inventoryと異なる場合は拒否する。
			if( size.QuadPart != inspectedEntry->uncompressedSize) {
				error = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				break ;
			}

			OfficialZipEntry output = *inspectedEntry ;	// Hashを追加する選択済みentry。
			error					= computeFileSha256( path, output.sha256) ;
			// 展開fileの検証失敗後は成功entryの追加を続けない。
			if( error != 0) {
				break ;
			}

			entries.push_back( std::move( output)) ;
		}

		// 最終検証失敗時は公開entryと今回の出力fileを破棄する。
		if( error != 0) {
			entries.clear() ;
			const NativeError cleanupError =
				// 全fileの即時破棄結果。
				discardCreatedExternalFiles( context) ;
			static_cast<void>( cleanupError) ;
		}

		return error ;
	} catch( const std::bad_alloc &) {
		entries.clear() ;
		const NativeError cleanupError =
			// 例外後も継続する全file cleanup結果。
			discardCreatedExternalFiles( context) ;
		static_cast<void>( cleanupError) ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		entries.clear() ;
		const NativeError cleanupError =
			// 不明例外後の全file cleanup結果。
			discardCreatedExternalFiles( context) ;
		static_cast<void>( cleanupError) ;
		return static_cast<NativeError>( E_FAIL) ;
	}
}

} // namespace drivercrate
