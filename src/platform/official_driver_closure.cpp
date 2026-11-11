//------------------------------------------------------------------------------
/**
 * @file official_driver_closure.cpp
 * @brief 公式archiveの選択的driver閉包抽出実装。
 * @version 01.10.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  全file inventory境界追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  Nested entryのnull検証を明確化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  由来を持たない共通archive入力を分離。
 * Ver.01.02.00 Shunji Ogawa  2026/10/05  保守専用の内容閉包と従来の作用拒否を分離。
 * Ver.01.03.00 Shunji Ogawa  2026/10/05  保守EXE参照を限定し通常入口の拒否を固定。
 * Ver.01.04.00 Shunji Ogawa  2026/10/07  sourceなし構造と同節依存・具体file参照の有限抽出を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/13  元CopyINF到達集合を同保護workspaceへ有限展開。
 * Ver.01.06.00 Shunji Ogawa  2026/10/13  全潜在CopyINFのimport内容を必要機能と別に検査。
 * Ver.01.07.00 Shunji Ogawa  2026/11/03  共通公式packageの手動索引と選択内容検査を接続。
 * Ver.01.08.00 Shunji Ogawa  2026/11/03  有界large archiveと共有内容保持・標準serviceを接続。
 * Ver.01.09.00 Shunji Ogawa  2026/11/03  署名原範囲の非実行resource内容を接続。
 * Ver.01.10.00 Shunji Ogawa  2026/11/06  標準圧縮sourceの有限解凍と原/展開byte来歴を保持。
 * Ver.01.10.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 *
 * @note ZIP／CABの全entryを有限に事前検証し、INFを先に展開して参照閉包を確定後、CATと参照fileだけを追加展開します。
 */
//------------------------------------------------------------------------------

#include "platform/official_driver_closure.h"

#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "platform/official_seven_zip.h"
#include "platform/official_sfx.h"
#include "platform/official_mapped_file.h"
#include "platform/official_resource_content.h"

#include <Windows.h>
#include <SetupAPI.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <memory>
#include <functional>
#include <cstdint>
#include <iterator>
#include <limits>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {

/** @brief 一つの原入力と同じ出力領域だけへ結んだ内容共有状態。 */
struct DriverArchiveExtractionCache::State {
	/// 元入力pathの完全値。任意別入力へ再利用しない。
	std::wstring									   inputPath ;
	/// 同操作のscan identity。
	ScanSessionId									   scan{} ;
	/// 原入力の内容hash。
	std::wstring									   sha256 ;
	/// 原入力のbyte数。
	std::uint64_t									   bytes{} ;
	/// 元外側形式。
	OfficialDriverArchiveFormat						   format{} ;
	/// 共有元の完全なresource計画。
	std::shared_ptr<const OfficialResourceContentPlan> resourcePlan ;
	/// 原viewより先に破棄しない固定入力owner。
	OfficialMappedFile								   mapped ;
	/// 同操作の選択solidを保持するreader。
	OfficialSevenZipSession							   seven ;
	/// 全元entryの一度だけ検査した一覧。
	std::vector<OfficialZipEntry>					   inventory ;
	/// 同じworkspaceへ抽出した一意memberだけ。
	std::vector<OfficialZipEntry>					   extracted ;
	/// 同じ原入力・所有workspaceの標準圧縮sourceだけの変換来歴です。
	std::vector<OfficialCompressedDriverSource>		   compressedSources ;
	/// 同操作の共有出力領域。ownerはCommonInfInspection側。
	OfficialDownloadWorkspace						  *workspace{} ;
	/// 同じoutput workspaceを初期化した場合true。
	bool											   initialized{} ;
	/// 原7z readerの初期化成功。
	bool											   sevenReady{} ;
	/// 実保持した一意memberのbyte数。
	std::uint64_t									   retained{} ;
	/// 元同期操作の取消し照会。
	std::function<bool()>							   cancellation ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 原入力をまだ借用しない空ownerを作る。
 */
//------------------------------------------------------------------------------
DriverArchiveExtractionCache::DriverArchiveExtractionCache() noexcept = default ;
//------------------------------------------------------------------------------
/**
 * @brief 固定入力と私有solidを回収する。選択出力workspaceは借用する。
 */
//------------------------------------------------------------------------------
DriverArchiveExtractionCache::~DriverArchiveExtractionCache() = default ;
//------------------------------------------------------------------------------
/**
 * @brief 同一workspaceへ実保持した一意member byte数を返す。
 * @return 未抽出なら0、成功抽出済みの総byte数。
 */
//------------------------------------------------------------------------------
std::uint64_t DriverArchiveExtractionCache::retainedBytes() const noexcept
{
	return state ? state->retained : 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief solid outputの実mapped peakを返す。
 * @return headerを含む同時保持最大byte数。
 */
//------------------------------------------------------------------------------
std::uint64_t DriverArchiveExtractionCache::mappedPeakBytes() const noexcept
{
	return state ? state->seven.mappedPeakBytes() : 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 実decodeした一意solid block数を返す。
 * @return 未使用なら0。
 */
//------------------------------------------------------------------------------
std::size_t DriverArchiveExtractionCache::decodedBlockCount() const noexcept
{
	return state ? state->seven.decodedBlockCount() : 0U ;
}

namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view NESTED_WORKSPACE_TAG =
	L"driver-closure-nested" ;	// 一段archive専用workspace識別子。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief 現在検査するarchiveの形式と絶対pathを組み合わせる。
 */
struct ArchiveSource {
	/// 保護workspaceまたはG11-B領域内の絶対path。
	std::wstring									   path ;
	/// 解析方式。
	OfficialDriverArchiveFormat						   format{OfficialDriverArchiveFormat::ZIP} ;
	/// 同じflat原入力だけの同期共有cache。Nested解析ではnullへ戻す。
	DriverArchiveExtractionCache::State				  *cache{} ;
	/// 原recordに結合したresource計画。通常archiveは空。
	std::shared_ptr<const OfficialResourceContentPlan> resourcePlan ;
	/// 同じarchive操作だけで共有する固定親/inner owner。
	std::shared_ptr<OfficialResourceContentReader>	   resourceReader ;
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
 * CWD依存、UNC、device pathまたは埋込みnullを解析境界へ入れない。
 *
 * @param[in] path G11-Bまたはnested workspaceのarchive path。
 * @return `C:\\...`形式の絶対pathなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isLocalAbsolutePath( const std::wstring_view path) noexcept
{
	// local drive絶対pathの形式に合わない値や埋込NULを拒否する。
	if( path.size() < 3U || path[1] != L':' || path[2] != L'\\' ||
	   path.find( L'\0') != std::wstring_view::npos) {
		return false ;
	}

	const wchar_t drive = path.front() ;	// ASCII drive letter候補。
	return (drive >= L'A' && drive <= L'Z') || (drive >= L'a' && drive <= L'z') ;
}

//------------------------------------------------------------------------------
/**
 * @brief 大文字小文字を無視して文字列が完全一致するか判定する。
 *
 * Archive path、SHA-256、閉包pathの一意性判定に使用する。
 *
 * @param[in] left 比較する一方の文字列。
 * @param[in] right 比較する他方の文字列。
 * @return Windowsのordinal比較で完全一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool stringsEqual( const std::wstring_view left,
								const std::wstring_view right) noexcept
{
	// Windows文字列比較APIの長さ型を超える入力を拒否する。
	if( left.size() > static_cast<std::size_t>( std::numeric_limits<int>::max()) ||
	   right.size() > static_cast<std::size_t>( std::numeric_limits<int>::max())) {
		return false ;
	}

	return CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

//------------------------------------------------------------------------------
/**
 * @brief SHA-256文字列の構文を検証する。
 *
 * Prefix、短縮hash、空値を取得identityとして受理しない。
 *
 * @param[in] value G11-Bで固定したhash文字列。
 * @return 64桁のASCII十六進文字だけで構成されれば`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSha256( const std::wstring_view value) noexcept
{
	return value.size() == 64U && std::ranges::all_of( value, []( const wchar_t character) noexcept {
			   return (character >= L'0' && character <= L'9') ||
					  (character >= L'a' && character <= L'f') ||
					  (character >= L'A' && character <= L'F') ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Archive pathの最終拡張子を小文字化する。
 *
 * 一段nested archiveの形式とINF選択をcase非依存で判定する。
 *
 * @param[in] path 検証済みarchive相対path。
 * @return 最終dotから始まる小文字ASCII拡張子。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring lowerExtension( const std::wstring_view path)
{
	const std::size_t separator = path.find_last_of( L'\\') ;	// 最終directory separator位置。
	const std::size_t dot		= path.find_last_of( L'.') ;	// 最終dot位置。
	// file名部分にdotがないpathは拡張子なしとして扱う。
	if( dot == std::wstring_view::npos ||
	   (separator != std::wstring_view::npos && dot < separator)) {
		return {} ;
	}

	std::wstring extension( path.substr( dot)) ;	// 小文字化する拡張子。
	std::ranges::transform( extension, extension.begin(), []( const wchar_t character) noexcept {
		return character >= L'A' && character <= L'Z'
				   ? static_cast<wchar_t>( character - L'A' + L'a')
				   : character ;
	}) ;
	return extension ;
}

//------------------------------------------------------------------------------
/**
 * @brief 取得済みarchiveのsizeとSHA-256を再検証する。
 *
 * 解析前後の差替えを検出し、不一致時は結果を公開しない。
 *
 * @param[in] path 保護workspace内の通常file絶対path。
 * @param[in] expectedBytes 取得時に固定した実byte数。
 * @param[in] expectedSha256 取得時に固定した64桁hash。
 * @return 属性、size、SHA-256が全て一致する場合は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateArchiveIdentity( const std::wstring_view path,
												  const std::uint64_t	  expectedBytes,
												  const std::wstring_view expectedSha256)
{
	// local絶対path、非空期待size、有効SHA-256をarchive再検証の前提にする。
	if( !isLocalAbsolutePath( path) || expectedBytes == 0 || !isSha256( expectedSha256)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring		  terminatedPath( path) ;	// Win32 API用null終端付きpath。
	WIN32_FILE_ATTRIBUTE_DATA attributes{} ;			// 入力archiveの属性と実size。
	// archive属性を取得できなければ再検証を中止する。
	if( GetFileAttributesExW( terminatedPath.c_str(), GetFileExInfoStandard, &attributes) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 通常file以外へ変化したarchiveを拒否する。
	if( (attributes.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
	   0) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	ULARGE_INTEGER size{} ;	// HighとLowを結合した入力archive byte数。
	size.LowPart  = attributes.nFileSizeLow ;
	size.HighPart = attributes.nFileSizeHigh ;
	// archiveの実sizeが取得時の期待値と異なる場合は拒否する。
	if( size.QuadPart != expectedBytes) {
		return nativeErrorFromWin32( ERROR_FILE_INVALID) ;
	}

	std::wstring	  actualSha256 ;										// 現在fileから再計算した64桁SHA-256。
	const NativeError hashError = computeFileSha256( path, actualSha256) ;	// Hash計算結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( hashError != 0) {
		return hashError ;
	}

	return stringsEqual( actualSha256, expectedSha256) ? 0 : nativeErrorFromWin32( ERROR_CRC) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定通常fileをmapし、同期期間だけ原viewを借用する。
 * @param[in] source 同じ原入力へ結んだ形式とpath。
 * @param[in] policy 元入力の有限上限。
 * @param[in,out] local 単独callerのowner。共有時は使用しない。
 * @param[out] bytes 成功時だけ固定入力のview。
 * @return mapping成功0、失敗は元HRESULT。
 */
//------------------------------------------------------------------------------
NativeError mapArchive( const ArchiveSource &source, const OfficialDriverClosurePolicy &policy,
					   OfficialMappedFile &local, std::span<const std::byte> &bytes)
{
	auto &mapped = source.cache ? source.cache->mapped : local ;	// 同じ原fileのownerです。
	// 一操作の原入力を一度だけ固定します。
	if( mapped.bytes().empty()) {
		// 同じ入力・所有操作の元診断です。
		const auto error = mapped.open( source.path, policy.zipPolicy.maximumArchiveBytes) ;
		// mapping失敗を全量vectorへfallbackしません。
		if( error != 0) {
			return error ;
		}
	}

	bytes = mapped.bytes() ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定SFXの標準PE/7z範囲を非実行で検査してreaderへ結ぶ。
 * @param[in] source 同じ原SFXの固定位置。
 * @param[in] policy 宣言量と展開量の有限枠。
 * @param[in,out] localMap 単独callerだけの入力owner。
 * @param[in,out] localReader 単独callerだけの選択reader。
 * @param[out] reader 成功時だけ同操作のreaderを借用する。
 * @return 全形式検査成功0、失敗は元HRESULT。
 */
//------------------------------------------------------------------------------
NativeError prepareSevenReader( const ArchiveSource				 &source,
							   const OfficialDriverClosurePolicy &policy,
							   OfficialMappedFile &localMap, OfficialSevenZipSession &localReader,
							   OfficialSevenZipSession *&reader)
{
	reader =
		source.cache ? &source.cache->seven : &localReader ;	// 同じ原metadataとsolidのownerです。
	// 初期化済みの共有readerを別入力へ再bindしません。
	if( source.cache && source.cache->sevenReady) {
		return 0 ;
	}

	std::span<const std::byte> bytes ;	// 固定handle内の原viewです。
	// 同じ入力・所有操作の元診断です。
	auto					   error = mapArchive( source, policy, localMap, bytes) ;
	OfficialSfxLayout		   layout ;	// CRC確認済みの原7z範囲です。
	// mapping成功時だけ元PE/7z境界を調べます。
	if( error == 0) {
		error = inspectOfficialSevenZipSfx( bytes,
										   {policy.zipPolicy.maximumArchiveBytes,
											policy.zipPolicy.maximumArchiveBytes,
											policy.zipPolicy.maximumArchiveBytes},
										   layout) ;
	}

	// 未対応SFXから外部extractorやEXE実行へfallbackしません。
	if( error != 0) {
		return error ;
	}

	const OfficialSevenZipExtractionPolicy sevenPolicy{
		policy.zipPolicy.maximumArchiveBytes,
		policy.zipPolicy.maximumSingleFileBytes,
		policy.zipPolicy.maximumTotalExpandedBytes,
		policy.zipPolicy.maximumTotalExpandedBytes,
		64ULL * 1024ULL * 1024ULL,
		768ULL * 1024ULL * 1024ULL,
		128ULL * 1024ULL * 1024ULL,
		policy.zipPolicy.maximumEntryCount,
		260U,
		source.cache && policy.zipPolicy.maximumTotalExpandedBytes > 512ULL * 1024ULL * 1024ULL
			? 3ULL * 1024ULL * 1024ULL * 1024ULL
			: 0U} ;						// 同期共有選択だけがfile-backed枠を使用します。
	const std::function<bool()> empty ;	// 単独旧callerには取消しを補完しません。
	error = reader->initialize( bytes.subspan( static_cast<std::size_t>( layout.archiveOffset),
											 static_cast<std::size_t>( layout.archiveSize)),
							   sevenPolicy, source.cache ? source.cache->cancellation : empty) ;
	// 全元entryを検査したreaderだけを共有します。
	if( error == 0 && source.cache) {
		source.cache->sevenReady = true ;
	}

	return error ;
}

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 同一操作のresource readerを原親/計画へ一度だけ結ぶ。
 * @param[in] source 原入力と閉じた選択。
 * @return 全親子検証成功0、元HRESULT。
 */
//------------------------------------------------------------------------------
NativeError prepareResourceReader( const ArchiveSource &source)
{
	// 任意pathだけからrecipeを発行しない。
	if( !source.resourcePlan || !source.resourceReader) {
		return E_INVALIDARG ;
	}

	// 全検証済みownerだけを同じ同期操作内で再利用する。
	if( !source.resourceReader->entries().empty()) {
		return 0 ;
	}

	return source.resourceReader->initialize( source.path, *source.resourcePlan,
											 source.cache ? source.cache->cancellation
														  : std::function<bool()>{}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定元入力の形式ごとに全archive entryを事前検証します。
 * @param[in] source 形式・絶対pathと同操作の元resource/cacheを持つ固定入力です。
 * @param[in] policy ZIP/CAB/7zの有限上限です。
 * @param[out] entries 成功時に形式別の通常entry一覧を保持します。
 * @return 形式別検査に成功した場合0、非対応形式はE_INVALIDARG、ほかは元検査errorです。
 * @throws std::bad_alloc 所有するentry一覧の確保に失敗した場合です。
 * @note 元resource plan、CAB、7z SFX、ZIPへ分岐し、同操作のreader/cacheを同期中だけ使用します。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectNewArchive( const ArchiveSource				  &source,
											const OfficialDriverClosurePolicy &policy,
											std::vector<OfficialZipEntry>	  &entries)
{
	// 署名された原sliceからのflat roleを通常inventoryへ渡す。
	if( source.format == OfficialDriverArchiveFormat::PE_RESOURCE_CONTAINER) {
		const auto error = prepareResourceReader( source) ;	// 元親/CRC/hashの診断。
		// 不完全なrole inventoryを共通closureへ公開しない。
		if( error == 0) {
			entries.assign( source.resourceReader->entries().begin(),
						   source.resourceReader->entries().end()) ;
		}

		return error ;
	}

	// CAB形式は共通CAB検査へ委譲する。
	if( source.format == OfficialDriverArchiveFormat::CABINET) {
		return inspectOfficialCab( source.path, policy.cabPolicy, entries) ;
	}

	// 原SFXの全metadataを固定mappingで検査します。
	if( source.format == OfficialDriverArchiveFormat::SEVEN_ZIP_SFX) {
		OfficialMappedFile		 mapped ;	// 単独callerだけの固定入力です。
		OfficialSevenZipSession	 local ;	// 共有操作以外のreaderです。
		OfficialSevenZipSession *reader{} ;	// 成功時だけ同じ元readerを借用します。
		// 同じ入力・所有操作の元診断です。
		const auto				 error = prepareSevenReader( source, policy, mapped, local, reader) ;
		// 一つでも不正なら部分一覧を公開しません。
		if( error != 0) {
			return error ;
		}

		// 元相対名/sizeを共通INF closureへ渡します。
		for( const auto &entry : reader->entries()) {
			entries.push_back( {entry.relativePath, entry.uncompressedSize, entry.sha256}) ;
		}

		return 0 ;
	}

	// CAB以外ではZIPと明示された形式だけを許容する。
	if( source.format != OfficialDriverArchiveFormat::ZIP) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	OfficialMappedFile		   mapped ;	// 同期Miniz呼出しまで入力を固定します。
	std::span<const std::byte> bytes ;	// 原ZIPのread-only viewです。
	// 同じ入力・所有操作の元診断です。
	const auto				   error = mapArchive( source, policy, mapped, bytes) ;
	return error != 0 ? error : inspectOfficialZip( bytes, policy.zipPolicy, entries) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じflat入力の全metadataを一度だけ検査して共有する。
 * @param[in] source 元入力と同期cache。
 * @param[in] policy 全metadataの有限枠。
 * @param[out] entries 全検査済み一覧。失敗時は空。
 * @return 元parserの診断。
 */
//------------------------------------------------------------------------------
NativeError inspectArchive( const ArchiveSource &source, const OfficialDriverClosurePolicy &policy,
						   std::vector<OfficialZipEntry> &entries)
{
	// 同一入力の成功一覧だけを再利用します。
	if( source.cache && !source.cache->inventory.empty()) {
		entries = source.cache->inventory ;
		return 0 ;
	}

	const auto error = inspectNewArchive( source, policy, entries) ;	// 元形式parserの診断です。
	// 部分失敗を共有済みmetadataへ昇格しません。
	if( error == 0 && source.cache) {
		source.cache->inventory = entries ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief Archive形式ごとに固定file群だけを展開する。
 *
 * 選択外のutilityやapplicationをworkspaceへ書き出さない。
 *
 * @param[in] source 形式と絶対pathを持つarchive入力。
 * @param[in] policy ZIPとCABの有限上限。
 * @param[in] selectedFiles 展開を許可する固定相対path群。
 * @param[in,out] workspace 展開fileを所有する保護領域。
 * @param[out] entries 成功時の展開fileとSHA-256。
 * @return 全entry事前検証と選択fileの完全展開成功時は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError extractNewArchiveFiles(
	const ArchiveSource &source, const OfficialDriverClosurePolicy &policy,
	const std::span<const std::wstring_view> selectedFiles, OfficialDownloadWorkspace &workspace,
	std::vector<OfficialZipEntry> &entries)
{
	// 端末はresource treeを走査せず元role名だけを保存する。
	if( source.format == OfficialDriverArchiveFormat::PE_RESOURCE_CONTAINER) {
		const auto error = prepareResourceReader( source) ;	// 同じ原ownerの検査結果。
		return error != 0 ? error
						  : source.resourceReader->extract( selectedFiles, workspace, entries) ;
	}

	// CAB形式の選択file抽出を共通CAB処理へ委譲する。
	if( source.format == OfficialDriverArchiveFormat::CABINET) {
		return extractOfficialCabFiles( source.path, policy.cabPolicy, selectedFiles, workspace,
									   entries) ;
	}

	// 原SFXの共有readerから選択memberだけを非実行展開します。
	if( source.format == OfficialDriverArchiveFormat::SEVEN_ZIP_SFX) {
		OfficialMappedFile		 mapped ;	// 単独callerの固定入力です。
		OfficialSevenZipSession	 local ;	// 単独callerのreaderです。
		OfficialSevenZipSession *reader{} ;	// 元readerだけを借用します。
		// 同じ入力・所有操作の元診断です。
		auto					 error = prepareSevenReader( source, policy, mapped, local, reader) ;
		// 原形式不正では出力を作りません。
		if( error != 0) {
			return error ;
		}

		std::vector<std::uint32_t> indices ;	// 存在する元indexだけの集合です。
		// 元名の完全一致で選択し、先頭や別名へ補完しません。
		for( const auto name : selectedFiles) {
			const auto all = reader->entries() ;	// 全検査済み一覧です。
			// 検査済み一覧から元indexだけを借用します。
			const auto found = std::ranges::find_if(
				all, [&]( const auto &entry) { return stringsEqual( name, entry.relativePath) ; }) ;
			// 欠測memberのままdecoderへ進みません。
			if( found == all.end()) {
				return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
			}

			indices.push_back( found->archiveIndex) ;
		}

		std::vector<OfficialSevenZipEntry> extracted ;	// 全成功時だけ公開する選択結果です。
		error = reader->extract( indices, workspace, extracted) ;
		// CRC/保存/hash失敗の部分出力はdecoderが今回分だけ回収します。
		if( error != 0) {
			return error ;
		}

		// 元相対名と実hashを共通CAT検査へ保持します。
		for( const auto &entry : extracted) {
			entries.push_back( {entry.relativePath, entry.uncompressedSize, entry.sha256}) ;
		}

		return 0 ;
	}

	// CAB以外ではZIPと明示された形式だけを展開する。
	if( source.format != OfficialDriverArchiveFormat::ZIP) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	OfficialMappedFile		   mapped ;	// 同期Miniz呼出しまで入力を固定します。
	std::span<const std::byte> bytes ;	// 元ZIPのread-only viewです。
	// 同じ入力・所有操作の元診断です。
	const auto				   error = mapArchive( source, policy, mapped, bytes) ;
	return error != 0 ? error
					  : extractOfficialZipFiles( bytes, policy.zipPolicy, selectedFiles, workspace,
												entries) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Archive entry一覧から固定pathを取得する。
 *
 * Prefix一致を許可せず、parserが確定したpathだけを使用する。
 *
 * @param[in] entries 形式別parserで検証済みの通常file群。
 * @param[in] path 大文字小文字を除き完全一致させる相対path。
 * @return 一致entryへの非所有pointer。存在しない場合は`nullptr`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] const OfficialZipEntry *findEntry( const std::span<const OfficialZipEntry> entries,
												const std::wstring_view path) noexcept
{
	const auto found =
		std::ranges::find_if( entries, [path]( const OfficialZipEntry &entry) noexcept {
			return stringsEqual( entry.relativePath, path) ;
		}) ; // 完全一致entryのiterator。
	return found == entries.end() ? nullptr : &*found ;
}

//------------------------------------------------------------------------------
/**
 * @brief Nested archive pathから静的解析形式を確定する。
 *
 * Installerやその他archive形式を暗黙に解凍しない。
 *
 * @param[in] path 外側archiveの検証済みnested file path。
 * @param[out] format 「.zip」または「.cab」から確定した形式。
 * @return 対応形式の完全一致時は0、それ以外はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nestedArchiveFormat( const std::wstring_view	   path,
											  OfficialDriverArchiveFormat &format)
{
	const std::wstring extension = lowerExtension( path) ;	// 小文字化済み拡張子。
	// ZIP拡張子を静的ZIP解析へ対応付ける。
	if( extension == L".zip") {
		format = OfficialDriverArchiveFormat::ZIP ;
		return 0 ;
	}

	// CAB拡張子を静的CAB解析へ対応付ける。
	if( extension == L".cab") {
		format = OfficialDriverArchiveFormat::CABINET ;
		return 0 ;
	}

	// EXEは起動せず、後段でPE末尾7z構造が成立するものだけを読みます。
	if( extension == L".exe") {
		format = OfficialDriverArchiveFormat::SEVEN_ZIP_SFX ;
		return 0 ;
	}

	return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ所有workspaceの一意memberだけを追加抽出する。
 * @param[in] source 固定入力と同操作cache。
 * @param[in] policy 一閉包と共同保持の有限上限。
 * @param[in] selectedFiles 存在確認済みの元member集合。
 * @param[in,out] workspace 同じ操作が所有する出力領域。
 * @param[out] entries 全成功時だけ原hash付き選択結果。
 * @return 元抽出/再照合の診断。失敗時の新規出力は操作ownerが回収する。
 */
//------------------------------------------------------------------------------
NativeError extractArchiveFiles( const ArchiveSource				  &source,
								const OfficialDriverClosurePolicy &policy,
								std::span<const std::wstring_view> selectedFiles,
								OfficialDownloadWorkspace		  &workspace,
								std::vector<OfficialZipEntry>	  &entries)
{
	// 別workspaceやnestedの旧callerへ共有済みfileを渡しません。
	if( !source.cache || source.cache->workspace != &workspace) {
		return extractNewArchiveFiles( source, policy, selectedFiles, workspace, entries) ;
	}

	entries.clear() ;
	std::vector<std::wstring_view> missing ;		// 同じ原入力から未抽出のmemberだけです。
	std::uint64_t				   additional{} ;	// 新たな実保持量です。
	// 元選択を既存cacheまたは同じinventoryへ一意に解決します。
	for( const auto name : selectedFiles) {
		const auto cached = findEntry( source.cache->extracted, name) ;	// 検査済み元memberです。
		// 生存fileの変更を旧hashで成功にしません。
		if( cached != nullptr) {
			// 同じ入力・所有操作の元診断です。
			const auto error = verifyOfficialFileMetadata(
				workspace.path( cached->relativePath), {cached->uncompressedSize, cached->sha256}) ;
			// 変更された共有bodyは全操作の失敗です。
			if( error != 0) {
				return error ;
			}

			continue ;
		}

		const auto entry = findEntry( source.cache->inventory, name) ;	// 元metadataの宣言です。
		// 欠損と共同保持枠超過を一部成功へ縮約しません。
		if( !entry || source.cache->retained > policy.maximumClosureBytes ||
		   additional > policy.maximumClosureBytes - source.cache->retained ||
		   entry->uncompressedSize >
			   policy.maximumClosureBytes - source.cache->retained - additional) {
			return nativeErrorFromWin32( entry ? ERROR_FILE_TOO_LARGE : ERROR_FILE_NOT_FOUND) ;
		}

		additional += entry->uncompressedSize ;
		missing.push_back( entry->relativePath) ;
	}

	// 既存fileを再作成せず、新しいmemberだけを元decoderへ渡します。
	if( !missing.empty()) {
		std::vector<OfficialZipEntry> extracted ;	// 新規成功分だけです。
		// 同じ入力・所有操作の元診断です。
		const auto error = extractNewArchiveFiles( source, policy, missing, workspace, extracted) ;
		// CRCや保存失敗をcacheの正常fileで隠しません。
		if( error != 0) {
			return error ;
		}

		source.cache->retained += additional ;
		source.cache->extracted.insert( source.cache->extracted.end(),
									   std::make_move_iterator( extracted.begin()),
									   std::make_move_iterator( extracted.end())) ;
	}

	// 元選択順で同じ実memberを返します。
	for( const auto name : selectedFiles) {
		const auto entry = findEntry( source.cache->extracted, name) ;	// 全成功後の一意位置です。
		// 内部欠落を正常な空fileへ変換しません。
		if( !entry) {
			return E_UNEXPECTED ;
		}

		entries.push_back( *entry) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元INFの同位置標準圧縮sourceだけを有限に実体化します。
 * @param[in] source 原archiveと同操作cacheです。
 * @param[in] policy 原per-file/総量/深さ上限です。
 * @param[in,out] workspace 原/展開fileの同じ保護所有者です。
 * @param[in] infPath 先行抽出済みの元INF相対位置です。
 * @param[in] archiveDepth 原containerの既存展開深さです。
 * @param[in,out] inventory 原一覧に実検査済み派生entryだけを追加します。容量は呼出側が確保済みです。
 * @param[in,out] extracted 生存するINF/CAT/展開済み全参照fileの実hash付き一覧です。
 * @param[in,out] transforms 同閉包が使用した原/展開tupleです。
 * @return 全必要source実体化0、未知・曖昧・過大・解凍/実byte不一致はHRESULTです。
 * @note Windowsの同期解凍だけを使います。payloadを実行せず、CATは後段で必須です。
 */
//------------------------------------------------------------------------------
NativeError materializeCompressedDriverSources(
	const ArchiveSource &source, const OfficialDriverClosurePolicy &policy,
	OfficialDownloadWorkspace &workspace, std::wstring_view infPath,
	const std::uint32_t archiveDepth, std::vector<OfficialZipEntry> &inventory,
	std::vector<OfficialZipEntry>				&extracted,
	std::vector<OfficialCompressedDriverSource> &transforms)
{
	std::vector<std::wstring> expectedSources ;	// 同元INF/媒体に結合した全source位置です。
	auto error = readOfficialInfSourcePaths( workspace, infPath, policy.infPolicy.maximumSourceFiles,
											expectedSources) ;	// 原宣言診断です。
	// source位置の不成立を圧縮名の推測で救済しません。
	if( error != 0) {
		return error ;
	}

	std::vector<std::wstring> aliases ;	// 同INFから一度だけ抽出する原圧縮memberです。
	aliases.reserve( expectedSources.size()) ;
	// 元全sourceの同位置aliasだけを先に有限選択し、CABの反復全読取を避けます。
	for( const auto &expected : expectedSources) {
		const auto dot = expected.find_last_of( L'.') ;	// 元三文字拡張子の境界です。
		// 標準alias規則以外を別名検索へ広げません。
		if( dot == expected.npos || expected.size() - dot != 4U) {
			continue ;
		}

		auto alias	 = expected ;	// 同位置leaf末尾だけの対応です。
		alias.back() = L'_' ;
		// 元にないaliasと同cacheの実検査済み変換を新規抽出しません。
		if( findEntry( inventory, alias) == nullptr ||
		   (source.cache &&
			std::ranges::any_of( source.cache->compressedSources, [&]( const auto &value) {
				return stringsEqual( value.compressedEntry.relativePath, alias) ;
			}))) {
			continue ;
		}

		// 一つの原aliasを別名の二sourceへ割り当てません。
		if( std::ranges::any_of( aliases,
							   [&]( const auto &value) { return stringsEqual( value, alias) ; })) {
			return nativeErrorFromWin32( ERROR_DUP_NAME) ;
		}

		aliases.push_back( std::move( alias)) ;
	}

	std::vector<std::wstring_view> aliasViews ;	// 先行予約済み文字列の同期借用です。
	// 全aliasの所有位置が固定した後で有限selectorを作ります。
	for( const auto &alias : aliases) {
		aliasViews.push_back( alias) ;
	}

	std::vector<OfficialZipEntry> encodedSources ;	// 一CAB passの全原hash付き結果です。
	// 必要な原圧縮memberがあるときだけ同じ既存抽出境界を呼びます。
	if( !aliasViews.empty()) {
		error = extractArchiveFiles( source, policy, aliasViews, workspace, encodedSources) ;
		// 一原抽出の失敗を部分解凍で救済しません。
		if( error != 0 || encodedSources.size() != aliasViews.size()) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}
	}

	// 全原sourceに対して同directoryの一意な標準aliasだけを調べます。
	for( const auto &expected : expectedSources) {
		const auto separator = expected.find_last_of( L'\\') ;	// 元source leafの境界です。
		const auto dot		 = expected.find_last_of( L'.') ;	// 標準の三文字拡張子の開始です。
		// 標準圧縮名規則に該当しない位置は元の欠損検査へ残します。
		if( dot == expected.npos || (separator != expected.npos && dot < separator) ||
		   expected.size() - dot != 4U) {
			continue ;
		}

		auto alias			= expected ;	// 元INFの同一leafの末尾だけを標準記法へ対応させます。
		alias.back()		= L'_' ;
		const auto original = findEntry( inventory, alias) ;	// 原archiveに実在する同位置だけです。
		// 別directoryのbasenameを代用しません。
		if( original == nullptr) {
			continue ;
		}

		// 圧縮source一段を既存深さと有限派生件数へ含めます。
		if( archiveDepth >= policy.maximumNestedArchiveDepth ||
		   transforms.size() >= policy.maximumClosureFiles) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		const auto local = std::ranges::find_if( transforms, [&]( const auto &value) {
			return stringsEqual( value.compressedEntry.relativePath,
								alias) ;	// 同操作の既知変換だけです。
		}) ;
		// 一つの圧縮byteを二つの異なる宣言名へ割り当てません。
		if( local != transforms.end()) {
			// 同じ元位置の共有参照だけを再利用します。
			if( !stringsEqual( local->expandedEntry.relativePath, expected)) {
				return nativeErrorFromWin32( ERROR_DUP_NAME) ;
			}

			continue ;
		}

		// 同じ入力cacheの変換も原/展開実byteを再照合して再利用します。
		if( source.cache) {
			const auto cached =
				std::ranges::find_if( source.cache->compressedSources, [&]( const auto &value) {
					return stringsEqual( value.compressedEntry.relativePath,
										alias) ;	// 同payloadの原位置です。
				}) ;
			// 別名への再利用や実fileの改変を拒否します。
			if( cached != source.cache->compressedSources.end()) {
				// 同一変換と生存byteの完全一致を要求します。
				if( !stringsEqual( cached->expandedEntry.relativePath, expected) ||
				   cached->compressedEntry.uncompressedSize != original->uncompressedSize ||
				   verifyOfficialFileMetadata( workspace.path( expected),
											  {cached->expandedEntry.uncompressedSize,
											   cached->expandedEntry.sha256}) != 0) {
					return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				inventory.push_back( cached->expandedEntry) ;
				extracted.push_back( cached->expandedEntry) ;
				transforms.push_back( *cached) ;
				continue ;
			}
		}

		// 正規名と圧縮名の二候補を任意の先頭採用へ縮約しません。
		if( findEntry( inventory, expected) != nullptr ||
		   source.format != OfficialDriverArchiveFormat::CABINET ||
		   policy.maximumNestedArchiveDepth == 0U || original->uncompressedSize < 14U ||
		   original->uncompressedSize > policy.cabPolicy.maximumSingleFileBytes) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		const auto encoded = findEntry( encodedSources, alias) ;	// 一括抽出からの同元実byteです。
		// 原抽出の失敗をWindows解凍で隠しません。
		if( encoded == nullptr) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const auto encodedPath = workspace.path( alias) ;	// 解凍終了まで固定する元fileです。
		std::unique_ptr<void, decltype( &CloseHandle)> encodedHandle(
			CreateFileW( encodedPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
						FILE_FLAG_OPEN_REPARSE_POINT, nullptr),
			&CloseHandle) ;	// 置換/変更を拒否します。
		// 固定した通常元fileだけを読みます。
		if( encodedHandle.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		std::array<BYTE, 14U>		   header{} ;	// SZDDの固定headerだけです。
		DWORD						   read{} ;		// 実取得したheader byte数です。
		constexpr std::array<BYTE, 9U> SIGNATURE{
			'S', 'Z', 'D', 'D', 0x88U, 0xf0U, 0x27U, 0x33U, 'A'} ;	// Windows LZ方式Aの署名です。
		// 未知圧縮や不完全headerへ別decoderを試しません。
		if( !ReadFile( encodedHandle.get(), header.data(), static_cast<DWORD>( header.size()), &read,
					 nullptr) ||
		   read != header.size() ||
		   !std::equal( SIGNATURE.begin(), SIGNATURE.end(), header.begin()) ||
		   (header[9] != 0U && header[9] != static_cast<BYTE>( expected.back()))) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		std::array<wchar_t, 4096U> actualSource{} ;	// Windowsが確認する同じ元fileです。
		DWORD					   required{} ;		// 原APIの必要文字数です。
		DWORD					   sourceBytes{} ;	// 原圧縮fileの実byte数です。
		DWORD					   targetBytes{} ;	// Windowsが報告する展開後byte数です。
		UINT					   compression{} ;	// 原APIが確認した形式です。
		const auto				   declaredBytes =
			static_cast<DWORD>( header[10]) | (static_cast<DWORD>( header[11]) << 8U) |
			(static_cast<DWORD>( header[12]) << 16U) |
			(static_cast<DWORD>( header[13]) << 24U) ;	// 元little endian長です。
		// 同元path/形式/sizeの完全一致と既存上限を解凍前に要求します。
		if( !SetupGetFileCompressionInfoExW( encodedPath.c_str(), actualSource.data(),
										   static_cast<DWORD>( actualSource.size()), &required,
										   &sourceBytes, &targetBytes, &compression)) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		// 原API成功後だけ元形式・長さ・倍率を検査し、原失敗codeと分けます。
		if( compression != FILE_COMPRESSION_WINLZA ||
		   !stringsEqual( actualSource.data(), encodedPath) ||
		   sourceBytes != encoded->uncompressedSize || targetBytes == 0U ||
		   targetBytes != declaredBytes || targetBytes > policy.cabPolicy.maximumSingleFileBytes ||
		   targetBytes > policy.maximumClosureBytes ||
		   targetBytes > static_cast<std::uint64_t>( sourceBytes) * policy.maximumExpansionRatio) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		std::uint64_t retained{} ;	// この操作で実際に保持済みのbyte数です。
		// 非共有callerも先行metadata/sourceの保持を予算へ含めます。
		for( const auto &entry : extracted) {
			// 合算overflowを検出した場合は解凍を開始しません。
			if( retained > policy.maximumClosureBytes ||
			   entry.uncompressedSize > policy.maximumClosureBytes - retained) {
				return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
			}

			retained += entry.uncompressedSize ;
		}

		// 非共有callerも一括抽出した全原圧縮byteを実保持へ含めます。
		for( const auto &entry : encodedSources) {
			// 全原byteの合算overflowを解凍前に拒否します。
			if( retained > policy.maximumClosureBytes ||
			   entry.uncompressedSize > policy.maximumClosureBytes - retained) {
				return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
			}

			retained += entry.uncompressedSize ;
		}

		retained = source.cache ? source.cache->retained : retained ;
		// 最大予約量を実消費へ計上せず、残枠に収まる一解凍だけを実行します。
		if( retained > policy.maximumClosureBytes ||
		   targetBytes > policy.maximumClosureBytes - retained) {
			return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
		}

		std::wstring targetPath ;	// 同所有者が予約する非存在の原宣言名です。
		error = workspace.prepareExternalFile( expected, targetPath) ;
		// 衝突や親位置の不成立を上書きで救済しません。
		if( error != 0) {
			return error ;
		}

		const auto decompressionError = SetupDecompressOrCopyFileW(
			// Windows同期解凍だけです。
			encodedPath.c_str(), targetPath.c_str(), &compression) ;
		// 解凍失敗や形式変更を成功fileとしてadoptしません。
		if( decompressionError != ERROR_SUCCESS || compression != FILE_COMPRESSION_WINLZA) {
			return nativeErrorFromWin32( decompressionError != ERROR_SUCCESS ? decompressionError
																			: ERROR_INVALID_DATA) ;
		}

		error = workspace.adoptFile( expected, targetBytes) ;
		OfficialCompressedDriverSource transform ;	// 全確認後だけ公開する原/展開tupleです。
		transform.compressedEntry = *encoded ;
		transform.expandedEntry	  = {expected, targetBytes} ;
		transform.compressionType = compression ;
		// 解凍後の正確なsize/保護属性と完全SHA256を確認します。
		if( error == 0) {
			error = computeFileSha256( targetPath, transform.expandedEntry.sha256) ;
		}

		// 同じ原byteが解凍完了まで不変であることを再確認します。
		if( error == 0) {
			error =
				verifyOfficialFileMetadata( encodedPath, {transform.compressedEntry.uncompressedSize,
														 transform.compressedEntry.sha256}) ;
		}

		// 部分変換をinventoryやcacheへ公開しません。
		if( error != 0) {
			return error ;
		}

		encodedHandle.reset() ;
		error = workspace.discardFile( alias) ;
		// 元CABと型付き来歴を残し、所有中間fileの回収失敗を成功へ丸めません。
		if( error != 0) {
			return error ;
		}

		const auto originalBytes =
			transform.compressedEntry.uncompressedSize ;	// 今回回収した実保持量です。
		std::erase_if( encodedSources,
					  [&]( const auto &entry) { return stringsEqual( entry.relativePath, alias) ; }) ;
		inventory.push_back( transform.expandedEntry) ;
		extracted.push_back( transform.expandedEntry) ;
		transforms.push_back( transform) ;
		// 共有cacheには実際に保持した派生byteだけを追加します。
		if( source.cache) {
			source.cache->retained = source.cache->retained - originalBytes + targetBytes ;
			std::erase_if( source.cache->extracted, [&]( const auto &entry) {
				return stringsEqual( entry.relativePath, alias) ;
			}) ;
			source.cache->extracted.push_back( transform.expandedEntry) ;
			source.cache->compressedSources.push_back( std::move( transform)) ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Archive入力sizeと展開後合計の倍率を検証する。
 *
 * ZIP／CAB bombを個別／合計sizeと別の圧縮率gateで拒否する。
 *
 * @param[in] entries 形式別parserで検証済みの通常file群。
 * @param[in] archiveBytes Containerの実byte数。
 * @param[in] maximumRatio 展開後合計を許可する最大倍率。
 * @return 合計の整数overflowがなく許可倍率以下なら0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateExpansionRatio( const std::span<const OfficialZipEntry> entries,
												 const std::uint64_t archiveBytes,
												 const std::uint32_t maximumRatio)
{
	// 空inventory、入力byte数0、倍率上限0を拒否する。
	if( entries.empty() || archiveBytes == 0 || maximumRatio == 0) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::uint64_t expandedBytes{} ;	// 全entryの展開後byte数合計。
	// Parserが返した全通常fileのsizeをoverflowなしで加算する。
	for( const OfficialZipEntry &entry : entries) {
		// 展開byte数合算の64-bit overflowを加算前に防ぐ。
		if( entry.uncompressedSize > std::numeric_limits<std::uint64_t>::max() - expandedBytes) {
			return nativeErrorFromWin32( ERROR_ARITHMETIC_OVERFLOW) ;
		}

		expandedBytes += entry.uncompressedSize ;
	}

	const std::uint64_t completeMultiples = expandedBytes / archiveBytes ;	// 整数部の展開倍率。
	const bool hasRemainder = expandedBytes % archiveBytes != 0 ;			// 上方へ丸める余りの有無。
	return completeMultiples > maximumRatio || (completeMultiples == maximumRatio && hasRemainder)
			   ? nativeErrorFromWin32( ERROR_FILE_TOO_LARGE)
			   : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 閉包pathを大文字小文字無視で一度だけ追加する。
 *
 * 複数INFが共通CATやdriver binaryを参照する場合に重複を除く。
 *
 * @param[in,out] paths 選択順を維持する閉包path群。
 * @param[in] path 追加候補の検証済み相対path。
 */
//------------------------------------------------------------------------------
void appendUniquePath( std::vector<std::wstring> &paths, const std::wstring_view path)
{
	// 大小文字を除く未登録pathだけを閉包へ追加する。
	if( std::ranges::none_of( paths, [path]( const std::wstring &existing) noexcept {
		   return stringsEqual( existing, path) ;
	   })) {
		paths.emplace_back( path) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 閉包path群の存在、件数、合計sizeを検証する。
 *
 * 欠落file、整数overflow、過大な複数INF閉包を書込み前に拒否する。
 *
 * @param[in] sourceEntries Archive全体の検証済みfile群。
 * @param[in] closurePaths INFから確定した一意閉包path群。
 * @param[in] policy 閉包file数と展開後合計byte数上限。
 * @param[out] expandedBytes 成功時の閉包合計byte数。
 * @return 全pathが存在し有限上限内なら0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateClosureBudget(
	const std::span<const OfficialZipEntry> sourceEntries,
	const std::span<const std::wstring> closurePaths, const OfficialDriverClosurePolicy &policy,
	std::uint64_t &expandedBytes)
{
	expandedBytes = 0 ;
	// 空またはfile件数上限を超える閉包を拒否する。
	if( closurePaths.empty() || closurePaths.size() > policy.maximumClosureFiles) {
		return nativeErrorFromWin32( ERROR_TOO_MANY_NAMES) ;
	}

	// 全閉包pathをarchive inventoryへ再照合し、展開後合計をoverflowなしで加算する。
	for( const std::wstring &path : closurePaths) {
		const OfficialZipEntry *entry = findEntry( sourceEntries, path) ;	// 閉包pathの対応entry。
		// 閉包参照先がinventoryに存在しなければ採用しない。
		if( entry == nullptr) {
			return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
		}

		// 閉包の合計byte上限を超えるentryを加算前に拒否する。
		if( entry->uncompressedSize > policy.maximumClosureBytes - expandedBytes) {
			return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
		}

		expandedBytes += entry->uncompressedSize ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択INF pathをarchive inventoryの正式pathへ解決する。
 *
 * 未表示path、重複選択、INF以外の拡張子をfail-closedで拒否する。
 *
 * @param[in] entries 検査対象archiveの検証済みfile群。
 * @param[in] requestedPaths 呼出側が選択したINF相対path群。
 * @param[in] maximumInfCount 同時選択数の有限上限。
 * @param[out] resolvedPaths Inventoryが所有する正式path view群。
 * @return 一件以上の一意INFが完全一致で解決できた場合は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError resolveSelectedInfPaths(
	const std::span<const OfficialZipEntry>	 entries,
	const std::span<const std::wstring_view> requestedPaths, const std::size_t maximumInfCount,
	std::vector<std::wstring_view> &resolvedPaths)
{
	resolvedPaths.clear() ;
	// 選択INFの非空集合と有限件数上限を要求する。
	if( requestedPaths.empty() || maximumInfCount == 0 || requestedPaths.size() > maximumInfCount) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	resolvedPaths.reserve( requestedPaths.size()) ;
	// 各選択値をarchive inventoryに対して完全一致で解決する。
	for( const std::wstring_view requestedPath : requestedPaths) {
		const OfficialZipEntry *entry = findEntry( entries, requestedPath) ;	// 解決したINF entry。
		// 不存在、INF以外、重複の選択を拒否して部分解決結果を破棄する。
		if( entry == nullptr || lowerExtension( entry->relativePath) != L".inf" ||
		   std::ranges::any_of( resolvedPaths, [entry]( const std::wstring_view existing) noexcept {
			   return stringsEqual( existing, entry->relativePath) ;
		   })) {
			resolvedPaths.clear() ;
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		resolvedPaths.push_back( entry->relativePath) ;
	}

	return 0 ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 固定したarchiveを由来判定なしで有限一覧化する。
 * @param[in] request 保護fileの固定identityと解析対象。
 * @param[in] policy Archive、展開倍率、nested深度の有限上限。
 * @param[out] inventory 成功時の一覧。失敗時は空。
 * @return 全entryと解析前後のsize／hashが一致した場合0、それ以外はHRESULT。
 * @note Worker内でblockingする。結果は内容一覧だけで公式取得の証拠にならない。
 */
//------------------------------------------------------------------------------
NativeError inspectDriverArchiveInventory( const DriverArchiveInventoryRequest &request,
										  const OfficialDriverClosurePolicy	  &policy,
										  OfficialDriverArchiveInventory	  &inventory)
{
	inventory = {} ;
	// 内容入力、展開倍率、nested深度の前提を一覧化前に検証する。
	if( request.input == nullptr || policy.maximumExpansionRatio == 0U ||
	   policy.maximumNestedArchiveDepth > 1U ||
	   (!request.nestedArchivePath.empty() && policy.maximumNestedArchiveDepth == 0U)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const DriverArchiveInput &acquisition = *request.input ;	// 由来を表さない内容入力。
	// Sessionのない入力を一時領域の生成へ渡さない。
	if( acquisition.scanSessionId == 0U ||
	   ((request.archiveFormat == OfficialDriverArchiveFormat::PE_RESOURCE_CONTAINER) !=
		static_cast<bool>( acquisition.resourceContent)) ||
	   (acquisition.resourceContent &&
		(!request.nestedArchivePath.empty() ||
		 !validOfficialResourceContentPlan( *acquisition.resourceContent) ||
		 acquisition.resourceContent->rootBytes != acquisition.byteCount ||
		 acquisition.resourceContent->rootSha256 != acquisition.sha256))) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	NativeError error = validateArchiveIdentity( acquisition.inspectionPath, acquisition.byteCount,
												acquisition.sha256) ;	// 解析前のidentity検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	try {
		ArchiveSource source{
			acquisition.inspectionPath, request.archiveFormat, nullptr, acquisition.resourceContent,
			acquisition.resourceContent ? std::make_shared<OfficialResourceContentReader>()
										: nullptr} ;	// 現在一覧化するarchive。
		std::vector<OfficialZipEntry> entries ;			// 現在archiveの全通常file。
		OfficialDownloadWorkspace	  nestedWorkspace ;	// 一段nested fileの一時所有領域。
		std::wstring				  nestedSha256 ;	// 展開した一段nested fileのhash。
		std::uint64_t				  nestedBytes{} ;	// 展開した一段nested fileのbyte数。
		std::uint32_t				  archiveDepth{} ;	// 一覧化対象のarchive深度。

		error = inspectArchive( source, policy, entries) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		error =
			validateExpansionRatio( entries, acquisition.byteCount, policy.maximumExpansionRatio) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		// 内部archiveが明示された場合だけ一段の選択抽出を行う。
		if( !request.nestedArchivePath.empty()) {
			const OfficialZipEntry *nestedEntry =
				// 固定した内側archive entry。
				findEntry( entries, request.nestedArchivePath) ;
			OfficialDriverArchiveFormat nestedFormat{} ;	// 拡張子から固定する内側形式。
			// 一致するentryがない場合は、後続のpath参照へ進まずfail-closedで拒否する。
			if( nestedEntry == nullptr) {
				return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
			}

			error = nestedArchiveFormat( nestedEntry->relativePath, nestedFormat) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}

			error = nestedWorkspace.initialize( NESTED_WORKSPACE_TAG, acquisition.scanSessionId) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}

			const std::wstring_view nestedPath = nestedEntry->relativePath ;	// 選択file path。
			const std::array		selectedNested{nestedPath} ;				// 外側から展開する一件だけの集合。
			std::vector<OfficialZipEntry> extractedNested ;						// Hash付きnested file結果。
			error = extractArchiveFiles( source, policy, selectedNested, nestedWorkspace,
										extractedNested) ;
			// 内部archiveの抽出成功と一件への確定を要求する。
			if( error != 0 || extractedNested.size() != 1U) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			nestedSha256  = extractedNested.front().sha256 ;
			nestedBytes	  = extractedNested.front().uncompressedSize ;
			source.path	  = nestedWorkspace.path( extractedNested.front().relativePath) ;
			source.format = nestedFormat ;
			error		  = validateArchiveIdentity( source.path, nestedBytes, nestedSha256) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}

			entries.clear() ;
			error = inspectArchive( source, policy, entries) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}

			error = validateExpansionRatio( entries, nestedBytes, policy.maximumExpansionRatio) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}

			archiveDepth = 1U ;
		}

		// 一覧化後にも内外archiveのidentityを確認し、差替えを結果へ反映しない。
		if( archiveDepth == 1U) {
			error = validateArchiveIdentity( source.path, nestedBytes, nestedSha256) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}
		}

		error = validateArchiveIdentity( acquisition.inspectionPath, acquisition.byteCount,
										acquisition.sha256) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		inventory.entries	   = std::move( entries) ;
		inventory.archiveDepth = archiveDepth ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		inventory = {} ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( const std::length_error &) {
		inventory = {} ;
		return static_cast<NativeError>( E_INVALIDARG) ;
	}
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 一rootの構造・明示package候補・同節依存を元archiveの共同予算内で抽出する。
 * @param[in] source 固定した外側または一段内側archive。
 * @param[in] sourceEntries 全memberの閉じた一覧。
 * @param[in] selectedInfPaths 正式pathへ一意解決した一root。
 * @param[in] policy 元archive・閉包・内容の有限条件。
 * @param[in,out] workspace 一rootと到達package fileを単独所有する保護領域。
 * @param[in,out] extractedEntries 抽出済みINFと後段fileの累積固定一覧。
 * @param[out] closure 全体成功時の保守観測。未解決・FAILEDの独立状態も残す。
 * @return 観測成功0、元byte・path・累積容量・重大なAPI失敗のHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError collectMaintenanceClosure(
	const ArchiveSource &source, std::span<const OfficialZipEntry> sourceEntries,
	std::span<const std::wstring_view> selectedInfPaths, const OfficialDriverClosurePolicy &policy,
	OfficialDownloadWorkspace &workspace, std::vector<OfficialZipEntry> &extractedEntries,
	MaintenanceDriverClosure &closure) ;
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 共通の参照抽出境界を維持し、内容観測だけを保守専用解析へ固定する。
 * @param[in] request 元identityと選択INF。
 * @param[in] policy 有限の構文・展開条件。
 * @param[in,out] workspace 閉包を所有する未初期化領域。
 * @param[out] closure 全成功時だけ内容を保持する。
 * @param[in] maintenanceOnly trueは非実行の内容検査専用で、導入許可を発行しない。
 * @param[out] maintenance 保守専用結果。通常modeではnullptr、保守modeでは非null。
 * @return 参照と元identityが有効なら0、それ以外はHRESULT。
 */
//------------------------------------------------------------------------------
static NativeError extractDriverClosureImpl( const DriverClosureRequest		  &request,
											const OfficialDriverClosurePolicy &policy,
											OfficialDownloadWorkspace		  &workspace,
											OfficialDriverClosure			  &closure,
											const bool						   maintenanceOnly,
											MaintenanceDriverClosure *maintenance = nullptr)
{
	closure = {} ;
	// 内容入力、workspace tag、INF数、閉包容量、深度上限を抽出前に検証する。
	if( request.input == nullptr || request.workspaceTag.empty() || policy.maximumInfCount == 0 ||
	   policy.maximumClosureFiles == 0 || policy.maximumClosureBytes == 0 ||
	   policy.maximumExpansionRatio == 0 || policy.maximumNestedArchiveDepth > 1U ||
	   (!request.nestedArchivePath.empty() && policy.maximumNestedArchiveDepth == 0U)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const DriverArchiveInput &acquisition = *request.input ;	// 由来を表さない内容入力。
	// Sessionのない入力を一時領域の生成へ渡さない。
	if( acquisition.scanSessionId == 0U ||
	   ((request.archiveFormat == OfficialDriverArchiveFormat::PE_RESOURCE_CONTAINER) !=
		static_cast<bool>( acquisition.resourceContent)) ||
	   (acquisition.resourceContent &&
		(!request.nestedArchivePath.empty() ||
		 !validOfficialResourceContentPlan( *acquisition.resourceContent) ||
		 acquisition.resourceContent->rootBytes != acquisition.byteCount ||
		 acquisition.resourceContent->rootSha256 != acquisition.sha256))) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	NativeError error =
		validateArchiveIdentity( acquisition.inspectionPath, acquisition.byteCount,
								acquisition.sha256) ;	// 内容identityの解析前再検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	try {
		ArchiveSource source{
			acquisition.inspectionPath, request.archiveFormat, nullptr, acquisition.resourceContent,
			acquisition.resourceContent ? std::make_shared<OfficialResourceContentReader>()
										: nullptr} ;	// 実際にINFを検査するarchive。
		// flat入力だけを同一操作・同一workspaceのcacheへ結びます。
		if( request.cache && request.nestedArchivePath.empty() && !maintenanceOnly) {
			// 初回だけ元identityを固定し、別入力でのcache再利用を拒否します。
			if( !request.cache->state) {
				request.cache->state = std::make_unique<DriverArchiveExtractionCache::State>() ;
				auto &cached		 = *request.cache->state ;	// 全検証前の操作所有状態です。
				cached.inputPath	 = acquisition.inspectionPath ;
				cached.scan			 = acquisition.scanSessionId ;
				cached.sha256		 = acquisition.sha256 ;
				cached.bytes		 = acquisition.byteCount ;
				cached.format		 = request.archiveFormat ;
				cached.resourcePlan	 = acquisition.resourceContent ;
				cached.workspace	 = &workspace ;
				cached.cancellation	 = request.cache->cancellation ;
			}

			auto &cached = *request.cache->state ;	// 同じ入力へ結合済みの状態です。
			// 任意workspaceや別byteを共有結果へ混ぜません。
			if( cached.inputPath != acquisition.inspectionPath ||
			   cached.scan != acquisition.scanSessionId || cached.sha256 != acquisition.sha256 ||
			   cached.bytes != acquisition.byteCount || cached.format != request.archiveFormat ||
			   cached.workspace != &workspace ||
			   static_cast<bool>( cached.resourcePlan) !=
				   static_cast<bool>( acquisition.resourceContent) ||
			   (cached.resourcePlan && *cached.resourcePlan != *acquisition.resourceContent)) {
				return E_INVALIDARG ;
			}

			source.cache = &cached ;
			// CABを含め、原入力を全同期検査中write/delete共有なしで固定します。
			if( cached.mapped.bytes().empty()) {
				// 固定入力handleの取得結果です。
				const auto fixed =
					cached.mapped.open( source.path, policy.zipPolicy.maximumArchiveBytes) ;
				// 固定失敗では旧hash結果から部分成功を作りません。
				if( fixed != 0) {
					return fixed ;
				}
			}
		}

		std::vector<OfficialZipEntry> sourceEntries ;	// 検査対象archiveの全通常file。
		OfficialDownloadWorkspace nestedWorkspace ;		// 外側から一段archiveだけを分離する保護領域。
		std::wstring			  nestedSha256 ;		// 一段archiveの展開直後identity。
		std::uint64_t			  nestedBytes{} ;		// 一段archiveの展開後byte数。
		std::uint32_t			  archiveDepth{} ;		// 現在の検査対象archive深度。

		error = inspectArchive( source, policy, sourceEntries) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		error = validateExpansionRatio( sourceEntries, acquisition.byteCount,
									   policy.maximumExpansionRatio) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		// 内部archiveが明示された場合はその一件だけを抽出して解析する。
		if( !request.nestedArchivePath.empty()) {
			const OfficialZipEntry *nestedEntry =
				// 外側の選択archive entry。
				findEntry( sourceEntries, request.nestedArchivePath) ;
			OfficialDriverArchiveFormat nestedFormat{} ;	// 拡張子で固定する内側parser種別。
			error = nestedEntry == nullptr
						? nativeErrorFromWin32( ERROR_FILE_NOT_FOUND)
						: nestedArchiveFormat( nestedEntry->relativePath, nestedFormat) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}

			error = nestedWorkspace.initialize( NESTED_WORKSPACE_TAG, acquisition.scanSessionId) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}

			const std::wstring_view nestedPathView = nestedEntry->relativePath ;	// 抽出対象。
			const std::array		selectedNested{nestedPathView} ;				// 外側から書き出す一file。
			std::vector<OfficialZipEntry> extractedNested ;							// Hash付きの一段archive entry。
			error = extractArchiveFiles( source, policy, selectedNested, nestedWorkspace,
										extractedNested) ;
			// 内部archiveの抽出失敗や件数不一致を拒否する。
			if( error != 0 || extractedNested.size() != 1U) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			nestedSha256  = extractedNested.front().sha256 ;
			nestedBytes	  = extractedNested.front().uncompressedSize ;
			source.path	  = nestedWorkspace.path( extractedNested.front().relativePath) ;
			source.format = nestedFormat ;
			error		  = validateArchiveIdentity( source.path, nestedBytes, nestedSha256) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}

			sourceEntries.clear() ;
			error = inspectArchive( source, policy, sourceEntries) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}

			error =
				validateExpansionRatio( sourceEntries, nestedBytes, policy.maximumExpansionRatio) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}

			archiveDepth = 1U ;
		}

		// 派生source追加後もINF path viewの所有位置を固定します。
		if( policy.infPolicy.allowWindowsManagedDriverDataForContent) {
			// 有限閉包件数を超える派生名を予約しません。
			if( sourceEntries.size() > sourceEntries.max_size() - policy.maximumClosureFiles) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			sourceEntries.reserve( sourceEntries.size() + policy.maximumClosureFiles) ;
		}

		std::vector<std::wstring_view> selectedInfPaths ;	// Inventoryが所有する正式INF path群。
		error = resolveSelectedInfPaths( sourceEntries, request.selectedInfPaths,
										policy.maximumInfCount, selectedInfPaths) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		// 共有workspaceは同じ操作で一度だけ初期化します。
		error = source.cache && source.cache->initialized
					? 0
					: workspace.initialize( request.workspaceTag, acquisition.scanSessionId) ;
		// 初期化成功だけを同じ出力ownerへ保持します。
		if( error == 0 && source.cache) {
			source.cache->initialized = true ;
		}

		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		std::vector<OfficialZipEntry> extractedInfEntries ;	// 先行展開したINFとSHA-256。
		error =
			extractArchiveFiles( source, policy, selectedInfPaths, workspace, extractedInfEntries) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		OfficialInfInspectionPolicy infPolicy = policy.infPolicy ;	// 閉包選択用のINF検証条件。
		// 内容modeだけを保守構造へ接続し、通常parserの分岐とpolicyを変更しない。
		if( maintenanceOnly) {
			// 所有先のない保守観測を通常閉包へ暗黙変換しない。
			if( maintenance == nullptr) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			MaintenanceDriverClosure observed ;	// 全元archive再確認後だけ公開する結果。
			error = collectMaintenanceClosure( source, sourceEntries, selectedInfPaths, policy,
											  workspace, extractedInfEntries, observed) ;
			// 重大な全体失敗の部分閉包を返さない。
			if( error != 0) {
				return error ;
			}

			// 内側元archiveも変更なしへ固定してから内容結果を公開する。
			if( archiveDepth == 1U) {
				error = validateArchiveIdentity( source.path, nestedBytes, nestedSha256) ;
				// 元byte差を解析成功で救済しない。
				if( error != 0) {
					return error ;
				}
			}

			error = validateArchiveIdentity( acquisition.inspectionPath, acquisition.byteCount,
											acquisition.sha256) ;
			// 外側元identity差でも保守部分結果を全て破棄する。
			if( error != 0) {
				return error ;
			}

			observed.content.archiveDepth = archiveDepth ;
			*maintenance				  = std::move( observed) ;
			return 0 ;
		}

		infPolicy.rejectUnreferencedPrograms = false ;
		infPolicy.rejectInstallActions		 = !maintenanceOnly ;
		infPolicy.allowReferencedExecutablesForContent =
			policy.infPolicy.allowReferencedExecutablesForContent ;
		// 内容専用検査では作用の拒否を別軸にし、依存を実行・補完しない。
		if( maintenanceOnly) {
			infPolicy.rejectExternalDependencies = false ;
		}

		std::vector<OfficialInfPackage> packages ;						// 全選択INFの静的構造。
		std::vector<std::wstring>		closurePaths ;					// INF、CAT、参照fileの一意閉包path群。
		std::vector<OfficialCompressedDriverSource> compressedSources ;	// 同位置の原/展開byteです。
		packages.reserve( selectedInfPaths.size()) ;
		closurePaths.reserve( policy.maximumClosureFiles) ;
		const auto initialInfCount =
			// 元明示選択数です。追加参照と分けます。
			selectedInfPaths.size() ;
		// 元選択と検証したCopyINF到達先だけを最大八件まで同じ保護閉包へ取り込みます。
		for( std::size_t infOrdinal = 0U; infOrdinal < selectedInfPaths.size(); ++infOrdinal) {
			const std::wstring_view infPath =
				selectedInfPaths[infOrdinal] ;	// 再確保するview配列とは独立の借用です。
			// 新しいCopyINF参照先だけを先行抽出し、別workspaceへの検索を行いません。
			if( infOrdinal >= initialInfCount) {
				const std::array selectedChild{infPath} ;		// 同inventoryの実在相対pathです。
				std::vector<OfficialZipEntry> extractedChild ;	// 原byteのhash付き参照INFです。
				error =
					extractArchiveFiles( source, policy, selectedChild, workspace, extractedChild) ;
				// 参照先の欠損や抽出失敗を基本INFだけの成功へ変換しません。
				if( error != 0 || extractedChild.size() != 1U) {
					return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				extractedInfEntries.push_back( std::move( extractedChild.front())) ;
			}

			// 原INFの全sourceを同位置の標準圧縮名からだけ実体化します。
			if( infPolicy.allowWindowsManagedDriverDataForContent) {
				error = materializeCompressedDriverSources( source, policy, workspace, infPath,
														   archiveDepth, sourceEntries,
														   extractedInfEntries, compressedSources) ;
				// 圧縮sourceの不成立を元名の欠損として隠しません。
				if( error != 0) {
					return error ;
				}
			}

			OfficialInfPackage package ;	// 現在INFの全静的構造検証成功結果。
			auto			   currentInfPolicy =
				infPolicy ;					// rootと内容importのClass境界を同じcallへ限定します。
			std::wstring importedClass ;	// 同元INFの原Classだけです。
			std::array<std::wstring_view, 1U>
				importedClasses{} ;	// このcall中だけのWindows読取値です。
			// 独立CopyINFは全内容を検査しますが、root候補や別deviceの導入memberへ昇格しません。
			if( infOrdinal >= initialInfCount && infPolicy.allowWindowsManagedDriverDataForContent) {
				// 任意の独自Class表で通常PnP importを事前承認せず、元Windows構文を要求します。
				if( const auto classError =
					   readOfficialInfImportClass( workspace, infPath, importedClass) ;
				   classError != 0) {
					return classError ;
				}

				importedClasses.front()			 = importedClass ;
				currentInfPolicy.acceptedClasses = importedClasses ;
			}

			error = inspectOfficialInfPackage( workspace, sourceEntries, infPath, currentInfPolicy,
											  package) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}

			// 全節CopyINFのimport内容を検査します。独立baseの機能導入許可は発行しません。
			for( const auto &requiredPath : package.requiredInfPaths) {
				const auto child =
					// inventoryが所有する安定したpathです。
					findEntry( sourceEntries, requiredPath) ;
				// 未実在のCopyINFを内容署名から独立した未解決として元metadataへ残します。
				if( child == nullptr) {
					continue ;
				}

				// 共有参照は抽出を重複せず、循環判定は関係検査へ残します。
				if( std::ranges::none_of( selectedInfPaths, [&]( const auto existing) {
					   return stringsEqual( existing, requiredPath) ;
				   })) {
					// 有限構成上限を全製品の対応上限として扱いません。
					if( !infPolicy.allowRequiredDriverComponents || selectedInfPaths.size() >= 8U) {
						return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
					}

					selectedInfPaths.push_back( child->relativePath) ;
				}
			}

			appendUniquePath( closurePaths, package.infRelativePath) ;
			appendUniquePath( closurePaths, package.catalogRelativePath) ;
			// 現在INFの全参照fileをarchive順ではなくINF解析順に追加する。
			for( const std::wstring &sourceFile : package.sourceFiles) {
				appendUniquePath( closurePaths, sourceFile) ;
			}

			packages.push_back( std::move( package)) ;
		}

		std::uint64_t expandedBytes{} ;	// 上限検証で確定した閉包合計byte数。
		error = validateClosureBudget( sourceEntries, closurePaths, policy, expandedBytes) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		std::vector<std::wstring_view> remainingPaths ;	// INF以外のCATと参照file path群。
		remainingPaths.reserve( closurePaths.size()) ;
		// 先行展開済みINFを除き、閉包の残りfileを後段展開対象にする。
		for( const std::wstring &path : closurePaths) {
			// 先に抽出した選択INFを除き、残り参照fileだけを追加抽出へ回す。
			if( std::ranges::none_of( extractedInfEntries,
									[&path]( const OfficialZipEntry &entry) noexcept {
										return stringsEqual( path, entry.relativePath) ;
									})) {
				remainingPaths.push_back( path) ;
			}
		}

		std::vector<OfficialZipEntry> extractedRemaining ;	// CATと参照fileのHash付きentry群。
		// 未抽出の参照fileがある場合だけ追加抽出を行う。
		if( !remainingPaths.empty()) {
			error =
				extractArchiveFiles( source, policy, remainingPaths, workspace, extractedRemaining) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}
		}

		extractedInfEntries.insert( extractedInfEntries.end(),
								   std::make_move_iterator( extractedRemaining.begin()),
								   std::make_move_iterator( extractedRemaining.end())) ;

		std::vector<OfficialZipEntry> closureEntries ;	// 閉包path順に並べ直すHash付きentry群。
		closureEntries.reserve( closurePaths.size()) ;
		// 全閉包pathが実際に展開され、SHA-256が確定済みであることを検証する。
		for( const std::wstring &path : closurePaths) {
			const OfficialZipEntry *extracted =
				// 対応する展開済みentry。
				findEntry( extractedInfEntries, path) ;
			// 抽出entryや有効hashが欠ける不完全な閉包を公開しない。
			if( extracted == nullptr || !isSha256( extracted->sha256)) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			closureEntries.push_back( *extracted) ;
		}

		// nested抽出では内側archiveも取得時のsizeとhashへ再照合する。
		if( archiveDepth == 1U) {
			error = validateArchiveIdentity( source.path, nestedBytes, nestedSha256) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}
		}

		error = validateArchiveIdentity( acquisition.inspectionPath, acquisition.byteCount,
										acquisition.sha256) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		closure.entries			  = std::move( closureEntries) ;
		closure.packages		  = std::move( packages) ;
		closure.archiveDepth	  = archiveDepth ;
		closure.expandedBytes	  = expandedBytes ;
		closure.compressedSources = std::move( compressedSources) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		closure = {} ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( const std::length_error &) {
		closure = {} ;
		return static_cast<NativeError>( E_INVALIDARG) ;
	}
}

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 固定したarchiveから選択INFの内容閉包を非実行抽出する。
 * @param[in] request 保護fileの固定identityと選択INF群。
 * @param[in] policy Archive、INF、閉包の有限上限。
 * @param[in,out] workspace 未初期化の出力領域。生成fileをscope終了まで所有する。
 * @param[out] closure 全成功時だけ閉包を保持し、失敗時は空。
 * @return 静的検査と解析前後のsize／hash一致時0、それ以外はHRESULT。
 * @note Worker内でblockingする。署名、由来、PnP、導入許可は別の検証を必要とする。
 */
//------------------------------------------------------------------------------
NativeError extractDriverClosure( const DriverClosureRequest		   &request,
								 const OfficialDriverClosurePolicy &policy,
								 OfficialDownloadWorkspace		   &workspace,
								 OfficialDriverClosure			   &closure)
{
	return extractDriverClosureImpl( request, policy, workspace, closure, false) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 導入作用を実行せず、保守検証だけに使う内容閉包を抽出する。
 * @param[in] request 元hashへ固定したarchiveと一root INF選択。複数rootは今回未対応。
 * @param[in] policy 内容構文と参照・展開量の条件。導入作用を拒否する条件は別検査する。
 * @param[in,out] workspace 未初期化領域。生成物をscope終了まで単独所有する。
 * @param[out] closure 成功時の保守用内容。失敗時は空。
 * @return 有限観測と元identity再確認成功0。用途未対応・依存未解決も結果へ残す。全体失敗はHRESULT。
 * @note Blockingする。抽出成功は全参照・全署名の合格ではなく、通常導入の条件を変更しない。
 * @see docs/adr/0258-maintenance-package-verdict-separation.md
 */
//------------------------------------------------------------------------------
NativeError extractMaintenanceDriverClosure( const DriverClosureRequest		  &request,
											const OfficialDriverClosurePolicy &policy,
											OfficialDownloadWorkspace		  &workspace,
											MaintenanceDriverClosure		  &closure)
{
	closure = {} ;
	// 一閉包を複数runへ分けて依存予算をresetしない。
	if( request.selectedInfPaths.size() != 1U) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	OfficialDriverClosure unused ;	// 通常結果への暗黙転送をしない内部所有先。
	return extractDriverClosureImpl( request, policy, workspace, unused, true, &closure) ;
}

//------------------------------------------------------------------------------
/**
 * @brief G11-B取得済みZIP／CABの全通常fileを展開せず一覧化する。取得済み公式archiveの全通常fileを一覧化する。外側および任意の一段nested archiveを実行
 *        せず一覧化し、解析前後のsizeとSHA-256差替えを拒否する。
 * @param[in] request G11-B取得結果、archive形式および任意の一段nested選択。 G11-B取得結果、形式と一段nested選択。
 * @param[in] policy Archiveと展開倍率の有限上限。一段nestedの許可も含む。 Archive、展開倍率、nested深度の有限上限。
 * @param[out] inventory 成功時の全通常file一覧とarchive深度。 成功時の全通常file一覧と深度。
 * @return 一覧化成功時は0、identity差替え、構造または有限上限違反時はHRESULT。 全entryと取得identityの検証成功時は0。
 * @note 処理はblockingのためProvider worker threadで実行し、任意codeを起動しない。
 */
//------------------------------------------------------------------------------
NativeError inspectOfficialDriverArchiveInventory(
	const OfficialDriverArchiveInventoryRequest &request, const OfficialDriverClosurePolicy &policy,
	OfficialDriverArchiveInventory &inventory)
{
	inventory = {} ;
	// 従来公式APIへ取得結果のない要求を渡さない。
	if( request.acquisition == nullptr) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const OfficialAcquisitionResult &acquisition = *request.acquisition ;	// 公式取得adapterの入力。
	// Local入力を公式取得へ昇格させず、従来の取得identity契約を維持する。
	if( acquisition.state != OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ||
	   acquisition.error != 0 || acquisition.scanSessionId == 0 || acquisition.acquisitionId == 0 ||
	   acquisition.providerId.empty() || acquisition.resourceId.empty()) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	try {
		const DriverArchiveInput input{acquisition.scanSessionId, acquisition.inspectionPath,
									   acquisition.byteCount,
									   acquisition.sha256} ;	// 呼出し中だけ所有する内容identity。
		return inspectDriverArchiveInventory(
			{&input, request.archiveFormat, request.nestedArchivePath}, policy, inventory) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 取得済み公式ZIP／CABから選択INFのdriver閉包だけを抽出する。取得済み公式archiveから選択INFのdriver閉包を抽出する。INFだけを先行展開し、CATと参照
 *        fileの閉包確定後に追加展開する。
 * @param[in] request G11-B取得結果、一段nested選択、INF選択と出力識別子。 G11-B取得結果、nested archiveとINF選択。
 * @param[in] policy Archive、INF、閉包の有限上限と許可値。
 * @param[in,out] workspace 成功閉包を所有する未初期化の保護workspace。 成功閉包を所有する保護領域。
 * @param[out] closure 全検証成功時の選択file、INF構造、合計size。 全検証成功時の選択fileとINF構造。
 * @return 閉包の選択展開成功時は0、identity差替えまたは構造違反時はHRESULT。 選択的閉包の完全な抽出とidentity再検証成功時は0。
 * @note 処理はblockingのためProvider worker threadで実行し、任意codeを起動しない。
 */
//------------------------------------------------------------------------------
NativeError extractOfficialDriverClosure( const OfficialDriverClosureRequest &request,
										 const OfficialDriverClosurePolicy	&policy,
										 OfficialDownloadWorkspace			&workspace,
										 OfficialDriverClosure				&closure)
{
	closure = {} ;
	// 従来公式APIへ取得結果のない要求を渡さない。
	if( request.acquisition == nullptr) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const OfficialAcquisitionResult &acquisition = *request.acquisition ;	// 公式取得adapterの入力。
	// 公式入口は内容検査APIと別に取得identityを要求する。
	if( acquisition.state != OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ||
	   acquisition.error != 0 || acquisition.scanSessionId == 0 || acquisition.acquisitionId == 0 ||
	   acquisition.providerId.empty() || acquisition.resourceId.empty()) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	try {
		const DriverArchiveInput input{acquisition.scanSessionId, acquisition.inspectionPath,
									   acquisition.byteCount,
									   acquisition.sha256} ;	// 呼出し中だけ所有する内容identity。
		return extractDriverClosure( {&input, request.archiveFormat, request.nestedArchivePath,
									 request.selectedInfPaths, request.workspaceTag},
									policy, workspace, closure) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

namespace {
/** @brief 一閉包内のpackage候補と原明示seed。署名や導入を許可しない。 */
struct MaintenanceClosureCandidate {
	/// 元archive内の正式INF位置。
	std::wstring			  path ;
	/// 同節Needsから渡された明示名。独自suffixを加えない。
	std::vector<std::wstring> seeds ;
	/// 最後に棚卸ししたseed数。共有名の追加だけ再走査する。
	std::size_t				  inspectedSeedCount{} ;
	/// seedなしのInclude資料も一度だけsource／CATを確認した場合true。
	bool					  inspected{} ;
	/// 最新の原宣言と位置・不足観測。
	MaintenanceInfReferences  references ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 保守専用構造の全選択と同装飾付随節から原seedを一意に集める。
 * @param[in] structure 現在OSの全選択構造。
 * @return 実在を観測した原DDInstall／付随節だけの有限一意集合。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<std::wstring> maintenanceRootSeeds(
	const MaintenanceInfStructure &structure)
{
	std::vector<std::wstring>					seeds ;	// 同期呼出し後まで所有する原名。
	constexpr std::array<std::wstring_view, 9U> SUFFIXES{
		L".HW",		  L".Services", L".CoInstallers", L".Interfaces",		L".Components",
		L".Software", L".Wdf",		L".Events",		  L".LogConfigOverride"} ;	// 対応節集合。
	// 先頭モデルへ絞らず、全現在OS選択の実在節をseedへ残す。
	for( const auto &install : structure.installs) {
		// 未解決選択名を任意の元節へ補完しない。
		if( install.inventory.selectedInstallSection.empty()) {
			continue ;
		}

		appendUniquePath( seeds, install.inventory.selectedInstallSection) ;
		// parserが実在を確認した同装飾付随節だけを加える。
		for( const auto suffix : SUFFIXES) {
			const std::wstring name =
				install.inventory.selectedInstallSection + std::wstring( suffix) ;	// 原節。
			// 似たsuffixや他OSの節を推測して追加しない。
			if( std::ranges::any_of( install.inventory.visitedSections, [&name]( const auto &visited) {
				   return stringsEqual( visited, name) ;
			   })) {
				appendUniquePath( seeds, name) ;
			}
		}
	}

	return seeds ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既知署名FAILEDを独立診断と依存summaryへ保持する。
 * @param[in,out] closure 同じ一rootの観測結果。
 */
//------------------------------------------------------------------------------
void summarizeMaintenanceDependency( MaintenanceDriverClosure &closure)
{
	auto	   &summary = closure.structure.dependency ;	// 外向き射影前のworker内summary。
	const auto &graph	= closure.dependency.dependency ;	// 同runの全辺と独立証拠。
	summary.observedReferenceCount = graph.edges.size() ;
	summary.reason				   = InfDependencyReason::NONE ;
	summary.state =
		graph.edges.empty() && graph.plan.referencesResolved
			? MaintenanceInfDependencyState::NONE
			: (graph.plan.referencesResolved ? MaintenanceInfDependencyState::RESOLVED_CURRENT_OS
											 : MaintenanceInfDependencyState::OBSERVED) ;
	// 全拒否・不在辺も残し、先頭の成功で不足を隠さない。
	for( const auto &edge : graph.edges) {
		// 明示的不正・欠落・曖昧・循環は元理由付きUNRESOLVEDとする。
		if( edge.state == InfDependencyState::UNRESOLVED ||
		   edge.state == InfDependencyState::INVALID_REFERENCE) {
			summary.state  = MaintenanceInfDependencyState::UNRESOLVED ;
			summary.reason = edge.reason ;
		}
		// 証拠未確認は不適合へ潰さず、観測と元理由を保持する。
		else if( summary.reason == InfDependencyReason::NONE &&
				edge.reason != InfDependencyReason::NONE) {
			summary.reason = edge.reason ;
		}
	}

	bool unassessedDependencies = false ;	// 核のInclude／Needs以外の具体的依存用途。
	// コピーINFとcomponent宣言を核のNONEへ潰さず、元用途を分母へ残す。
	for( const auto &references : closure.references) {
		// CopyINFの全原fieldを別の依存用途として観測する。
		for( const auto &reference : references.inventory.references) {
			// native核が解析しないCopyINFを解決済み辺へ補完しない。
			if( reference.kind == OfficialInfInstallReferenceKind::COPY_INF) {
				++summary.observedReferenceCount ;
				unassessedDependencies = true ;
			}
		}

		// componentの予約を既知の基本driver依存解決へ転用しない。
		for( const auto &effect : references.inventory.effects) {
			// 明示component宣言だけを追加の未評価依存へ残す。
			if( stringsEqual( effect.directive, L"AddComponent")) {
				++summary.observedReferenceCount ;
				unassessedDependencies = true ;
			}
		}
	}

	// 既知の未解決理由は残し、核が扱わない具体依存をNONE／RESOLVEDへ昇格させない。
	if( unassessedDependencies) {
		// 既存の欠落・曖昧・循環の状態を未知で上書きしない。
		if( summary.state != MaintenanceInfDependencyState::UNRESOLVED) {
			summary.state = MaintenanceInfDependencyState::OBSERVED ;
		}

		// 証拠不足とは別の未解釈用途理由を保持する。
		if( summary.reason == InfDependencyReason::NONE) {
			summary.reason = InfDependencyReason::NOT_CHECKED ;
		}

		summary.error = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// 同OSの対象証拠を数え、root署名と全payloadを混同しない。
	for( const auto &document : graph.documents) {
		// 三証拠が独立に確認済みのdocumentだけを解決数へ含める。
		if( document.byteBinding == InfDependencyEvidence::VERIFIED &&
		   document.provenance == InfDependencyEvidence::VERIFIED &&
		   document.signature == InfDependencyEvidence::VERIFIED) {
			++summary.resolvedInfCount ;
		}

		// 既知の依存署名失敗を他の未解決や由来未確認で消さない。
		if( document.signature == InfDependencyEvidence::FAILED) {
			const auto finding =
				std::ranges::find_if( closure.dependency.findings, [&document]( const auto &item) {
					return item.identity == document.identity ;
				}) ; // 原HRESULT。
			const NativeError error =
				finding == closure.dependency.findings.end() || finding->signatureError == 0
					? static_cast<NativeError>( E_UNEXPECTED)
					: finding->signatureError ;	// 診断欠落も成功にしない。
			// 最初の既知FAILEDとその診断を保持する。
			if( closure.integrity.state != MaintenanceInspectionState::FAILED) {
				closure.integrity = {MaintenanceInspectionState::FAILED, error} ;
			}

			// 根拠不足の元診断をsummaryにも残し、resolved判定から独立させる。
			if( summary.error == 0) {
				summary.error = error ;
			}
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 一rootの構造・明示package候補・同節依存を元archiveの共同予算内で抽出する。
 * @param[in] source 固定した外側または一段内側archive。
 * @param[in] sourceEntries 全memberの閉じた一覧。
 * @param[in] selectedInfPaths 正式pathへ一意解決した一root。
 * @param[in] policy 元archive・閉包・内容の有限条件。
 * @param[in,out] workspace 一rootと到達package fileを単独所有する保護領域。
 * @param[in,out] extractedEntries 抽出済みINFと後段fileの累積固定一覧。
 * @param[out] closure 全体成功時の保守観測。未解決・FAILEDの独立状態も残す。
 * @return 観測成功0、元byte・path・累積容量・重大なAPI失敗のHRESULT。
 */
//------------------------------------------------------------------------------
NativeError collectMaintenanceClosure( const ArchiveSource				&source,
									  std::span<const OfficialZipEntry>	 sourceEntries,
									  std::span<const std::wstring_view> selectedInfPaths,
									  const OfficialDriverClosurePolicy &policy,
									  OfficialDownloadWorkspace			&workspace,
									  std::vector<OfficialZipEntry>		&extractedEntries,
									  MaintenanceDriverClosure			&closure)
{
	closure = {} ;
	// 一rootと最大128 INFの元一覧を切捨てず、過大入力を全体拒否する。
	if( selectedInfPaths.size() != 1U || std::ranges::count_if( sourceEntries, []( const auto &entry) {
											return lowerExtension( entry.relativePath) == L".inf" ;
										}) > 128) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	NativeError error =
		inspectMaintenanceInfStructure( workspace, sourceEntries, selectedInfPaths.front(),
									   policy.infPolicy, closure.structure) ;	// 全現在OSの保守構造。
	// 元入力・全体構文・容量失敗の部分構造を返さない。
	if( error != 0) {
		return error ;
	}

	const std::vector<std::wstring> rootSeeds =
		// 全実在選択。
		maintenanceRootSeeds( closure.structure) ;
	std::vector<MaintenanceClosureCandidate> candidates{
		{std::wstring( selectedInfPaths.front()), rootSeeds}} ;	// 一閉包の全候補、最大64。
	std::vector<std::wstring> closurePaths ;					// 実在する元memberの一意累積集合。
	appendUniquePath( closurePaths, selectedInfPaths.front()) ;
	std::size_t totalSections{} ;	// 全候補の棚卸しで共同消費する節数。
	std::size_t totalLines{} ;		// 全候補・再棚卸しを含む4,096行。
	std::size_t totalReferences{} ;	// 原local／依存／file用途の累積保持予算。
	bool		progress = true ;	// 新候補／明示seedの追加がなくなったら終了する。
	// 候補追加と共有seed変更を有限累積予算で固定点まで観測する。
	while( progress) {
		progress = false ;
		// 末尾へ増えた候補も同じ一閉包runで調べる。
		for( std::size_t index = 0U; index < candidates.size(); ++index) {
			// 同じ明示seed集合は再走査せず、循環で予算をresetしない。
			if( candidates[index].inspected &&
			   candidates[index].inspectedSeedCount == candidates[index].seeds.size()) {
				continue ;
			}

			const std::wstring path	 = candidates[index].path ;		// vector再確保から独立した原位置。
			const auto		   seeds = candidates[index].seeds ;	// 原明示seed集合の同期copy。
			MaintenanceInfReferences references ;					// 全体成功時だけcandidateへ移す。
			error = inspectMaintenanceInfReferences( workspace, sourceEntries, path, seeds,
													policy.infPolicy, references) ;
			// 途中読取・元byte差・path・容量失敗を部分閉包へ弱めない。
			if( error != 0) {
				return error ;
			}

			// 準備走査でも全候補を共同予算へ含め、再走査で上限をresetしない。
			if( references.inventory.visitedSections.size() > 1024U - totalSections ||
			   references.inventory.scannedLines > 4096U - totalLines ||
			   references.inventory.references.size() + references.files.size() >
				   4096U - totalReferences) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			totalSections += references.inventory.visitedSections.size() ;
			totalLines += references.inventory.scannedLines ;
			totalReferences += references.inventory.references.size() + references.files.size() ;
			// 依存資料のCAT未宣言・未発見を空pathへ変換して抽出しない。
			if( findEntry( sourceEntries, references.catalogRelativePath) != nullptr) {
				appendUniquePath( closurePaths, references.catalogRelativePath) ;
			}

			// 位置が元memberへ結べた用途だけを抽出し、未知用途は観測へ残す。
			for( const auto &file : references.files) {
				// LOCATEDは実byte署名ではなく、後段抽出対象の一意位置だけを表す。
				if( file.location == MaintenanceInfFileLocation::LOCATED) {
					appendUniquePath( closurePaths, file.relativePath) ;
				}
			}

			const auto		   separator = path.find_last_of( L'\\') ;	// 元INFのpackage相対親区切り。
			const std::wstring parent =
				separator == path.npos ? std::wstring{}
									   : path.substr( 0U, separator) ;	// vector更新から独立した元親。
			// 同節IncludeとCopyINFの原候補だけを閉じたmember一覧から集める。
			for( const auto &reference : references.inventory.references) {
				// local処理節を外部INF候補へ読み替えない。
				if( reference.kind != OfficialInfInstallReferenceKind::INCLUDE_INF &&
				   reference.kind != OfficialInfInstallReferenceKind::COPY_INF) {
					continue ;
				}

				const std::wstring child =
					parent.empty() ? reference.target
								   : reference.target.substr( parent.size() +
															 1U) ;	// parserが安全親へ結んだ原名。
				// 原親とpackage rootの全一致候補を残し、basename探索や先頭選択をしない。
				for( const auto &entry : sourceEntries) {
					// CopyINFは元親だけ、Includeは既存nativeと同じ元親／package rootの候補集合。
					if( !stringsEqual( entry.relativePath, reference.target) &&
					   !(reference.kind == OfficialInfInstallReferenceKind::INCLUDE_INF &&
						 stringsEqual( entry.relativePath, child))) {
						continue ;
					}

					// 一INF4 MiBと一依存run64候補を切捨てずに維持する。
					if( entry.uncompressedSize == 0U ||
					   entry.uncompressedSize > 4U * 1024U * 1024U) {
						return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
					}

					auto found = std::ranges::find_if( candidates, [&entry]( const auto &candidate) {
						return stringsEqual( candidate.path, entry.relativePath) ;
					}) ; // 同原memberは候補を共有する。
					// 新しい候補は元の共同file／byte予算で抽出する。
					if( found == candidates.end()) {
						// 必要候補64＋1を複数runへ分けて回避しない。
						if( candidates.size() >= 64U) {
							return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
						}

						appendUniquePath( closurePaths, entry.relativePath) ;
						std::uint64_t bytes{} ;	// 新候補を含む共同展開予算。
						error = validateClosureBudget( sourceEntries, closurePaths, policy, bytes) ;
						// 追加の前に元閉包予算を検査する。
						if( error != 0) {
							return error ;
						}

						const std::array<std::wstring_view, 1U> selected{
							entry.relativePath} ;					// この元候補だけ。
						std::vector<OfficialZipEntry> extracted ;	// Hash付き元INF。
						error = extractArchiveFiles( source, policy, selected, workspace, extracted) ;
						// 固定できない候補をmissingへ弱めない。
						if( error != 0 || extracted.size() != 1U) {
							return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
						}

						extractedEntries.push_back( std::move( extracted.front())) ;
						candidates.push_back( {entry.relativePath}) ;
						found	 = candidates.end() - 1 ;
						progress = true ;
					}

					// baseのIncludeをServicesへ借用せず、元節と一致したNeeds名だけを渡す。
					for( const auto &need : references.inventory.references) {
						// CopyINFへNeedsを割り当てず、同節Includeだけに明示seedを加える。
						if( reference.kind == OfficialInfInstallReferenceKind::INCLUDE_INF &&
						   stringsEqual( need.section, reference.section) &&
						   stringsEqual( need.directive, L"Needs")) {
							const std::size_t oldCount =
								// 同じ原seedの再追加を避ける。
								found->seeds.size() ;
							appendUniquePath( found->seeds, need.target) ;
							progress = progress || oldCount != found->seeds.size() ;
						}
					}
				}
			}

			candidates[index].references		 = std::move( references) ;
			candidates[index].inspected			 = true ;
			candidates[index].inspectedSeedCount = seeds.size() ;
		}
	}

	std::uint64_t expandedBytes{} ;	// 全実在package memberの共同byte予算。
	error = validateClosureBudget( sourceEntries, closurePaths, policy, expandedBytes) ;
	// 元閉包のfile数・byte数を後段でも検査する。
	if( error != 0) {
		return error ;
	}

	std::vector<std::wstring_view> remaining ;	// 既抽出INFを除いたCAT／payload位置。
	// 未抽出の一意fileだけを後段へ渡し、同fileの再書込みをしない。
	for( const auto &path : closurePaths) {
		// 先行抽出済みのINFを後段で上書きしない。
		if( findEntry( extractedEntries, path) == nullptr) {
			remaining.push_back( path) ;
		}
	}

	std::vector<OfficialZipEntry> extracted ;	// 後段fileの確定元byte。
	error = remaining.empty()
				? 0
				: extractArchiveFiles( source, policy, remaining, workspace, extracted) ;
	// 後段の読取・元byte失敗を部分閉包へ弱めない。
	if( error != 0) {
		return error ;
	}

	extractedEntries.insert( extractedEntries.end(), std::make_move_iterator( extracted.begin()),
							std::make_move_iterator( extracted.end())) ;
	std::vector<InfDependencyPackageMember> members ;	// 閉じた元候補集合。最大64。
	// 全package候補を元hash・sizeへ結び、裸local由来は昇格させない。
	for( auto &candidate : candidates) {
		const auto entry = findEntry( extractedEntries, candidate.path) ;	// 抽出時の固定metadata。
		// 未固定INFからnative候補を作らない。
		if( entry == nullptr || !isSha256( entry->sha256)) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		members.push_back( {entry->relativePath, entry->sha256, entry->uncompressedSize}) ;
		closure.references.push_back( std::move( candidate.references)) ;
	}

	// 根拠のないseedを捏造してNONEを作らず、実在root選択だけを一native runへ渡す。
	if( !rootSeeds.empty()) {
		error =
			inspectNativeInfDependencies( workspace, members, 0U, rootSeeds, 1U, closure.dependency) ;
		// 重大なnative読取・容量・OS差・改変では全体の部分観測を破棄する。
		if( error != 0) {
			return error ;
		}

		summarizeMaintenanceDependency( closure) ;
		// 認証済みSYSTEM参照だけの構造も、全payloadの成功とは別に分類する。
		if( closure.structure.sourceFileNames.empty() &&
		   closure.structure.contentKind == MaintenanceInfContentKind::UNKNOWN &&
		   closure.structure.dependency.state ==
			   MaintenanceInfDependencyState::RESOLVED_CURRENT_OS &&
		   closure.dependency.dependency.documents.size() > 1U &&
		   std::ranges::all_of(
			   std::span<const InfDependencyDocument>( closure.dependency.dependency.documents)
				   .subspan( 1U),
			   []( const auto &document) {
				   return document.origin == InfDependencyOrigin::SYSTEM &&
						  document.byteBinding == InfDependencyEvidence::VERIFIED &&
						  document.provenance == InfDependencyEvidence::VERIFIED &&
						  document.signature == InfDependencyEvidence::VERIFIED ;
			   })) {
			closure.structure.contentKind = MaintenanceInfContentKind::INBOX_DEPENDENCY ;
		}
	}

	std::uint64_t fixedBytes = closure.dependency.fixedByteCount ;	// nativeが固定した共同byte数。
	std::size_t fixedFiles = closure.dependency.fixedFileCount ;	// nativeの固定INF／CAT／Store集合。
	// 追加package payloadも同じ256 file／128 MiB予算へ含める。CATの重複は保守的に加算する。
	for( const auto &path : closurePaths) {
		const auto entry = findEntry( extractedEntries, path) ;	// 追加済み元memberの固定metadata。
		// hash不明・実byte差のentryを公開しない。
		if( entry == nullptr || !isSha256( entry->sha256)) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		error = verifyOfficialFileMetadata( workspace.path( path),
										   {entry->uncompressedSize, entry->sha256}) ;
		// 元member再照合に失敗した場合は全体を拒否する。
		if( error != 0) {
			return error ;
		}

		// 同hashの別fileを共有根拠にせず、追加memberを全て保守的に共同容量へ加える。
		{
			// 固定file上限と共同byte上限を加算前に検査し、run分割で回避しない。
			if( fixedFiles >= 256U || entry->uncompressedSize > 128U * 1024U * 1024U - fixedBytes) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			++fixedFiles ;
			fixedBytes += entry->uncompressedSize ;
		}

		closure.content.entries.push_back( *entry) ;
	}

	const auto		  &rootReferences = closure.references.front() ;	// 同じrootの具体的member候補。
	OfficialInfPackage package{closure.structure.infRelativePath,
							   closure.structure.catalogRelativePath,
							   closure.structure.className,
							   closure.structure.providerName,
							   closure.structure.driverDate,
							   closure.structure.driverVersion,
							   closure.structure.hardwareIds,
							   rootReferences.sourceFiles,
							   closure.structure.dependency.observedReferenceCount !=
								   0U} ;	// 署名member helper用metadata、導入認証ではない。
	error							= verifyWindowsInfPackageIntegrity( workspace, package) ;
	closure.structure.rootIntegrity = {error == 0 ? MaintenanceInspectionState::PASSED
												  : MaintenanceInspectionState::FAILED,
									   error} ;
	// rootの既知署名FAILEDを依存未確認やcoverage不足で消さない。
	if( error != 0) {
		closure.integrity = closure.structure.rootIntegrity ;
	}

	MaintenanceInfReferenceCoverage coverage =
		rootReferences.referenceCoverage ;	// 全到達fileの独立位置coverage。
	// 到達packageの位置未確定と未解釈用途も同じ全coverageへ含める。
	for( const auto &reference : closure.references) {
		// 一件でも未完了なら空閉包の成功へ昇格させない。
		if( reference.referenceCoverage != MaintenanceInfReferenceCoverage::COMPLETE) {
			coverage = MaintenanceInfReferenceCoverage::INCOMPLETE ;
		}
	}

	// 実SYSTEM INF自身の署名を全参照payload署名へ転用しない。未採用の探索候補節は欠落としない。
	if( rootSeeds.empty() || closure.dependency.dependency.documents.empty() ||
	   std::ranges::any_of(
		   closure.dependency.dependency.documents,
		   [&closure]( const auto &document) {
			   // graphを借用し、実Needs対象でないSYSTEM探索候補のpayload不足は合算しない。
			   return document.origin == InfDependencyOrigin::SYSTEM &&
					  std::ranges::any_of(
						  closure.dependency.dependency.edges, [&document]( const auto &edge) {
							  return edge.directive == InfDependencyDirective::NEEDS &&
									 edge.targetIdentity == document.identity ;
						  }) ;
		   }) ||
	   std::ranges::any_of( closure.dependency.dependency.edges,
						   []( const auto &edge) {
							   return edge.state == InfDependencyState::UNRESOLVED ||
									  edge.state == InfDependencyState::INVALID_REFERENCE ||
									  edge.state == InfDependencyState::NOT_CHECKED ||
									  edge.targetIdentity == 0U ;
						   }) ||
	   std::ranges::any_of( rootSeeds, [&closure]( const auto &seed) {
		   // rootと実seedを借用し、Include照会時の未採用候補節を判定対象から外す。
		   const auto selected = std::ranges::find_if(
			   closure.dependency.dependency.sections, [&closure, &seed]( const auto &section) {
				   return section.identity ==
							  closure.dependency.dependency.documents.front().identity &&
						  stringsEqual( section.section, seed) ;
			   }) ; // 実際に選択されたroot節の存在観測。
		   return selected == closure.dependency.dependency.sections.end() ||
				  selected->state != InfDependencyReadState::PRESENT ;
	   })) {
		coverage = MaintenanceInfReferenceCoverage::INCOMPLETE ;
	}

	closure.structure.referenceCoverage = coverage ;
	// rootと全file位置が揃った場合だけ全署名の追加確認へ進む。由来未確認と位置を混同しない。
	if( closure.integrity.state != MaintenanceInspectionState::FAILED &&
	   coverage == MaintenanceInfReferenceCoverage::COMPLETE) {
		bool complete = closure.structure.rootIntegrity.state ==
						MaintenanceInspectionState::PASSED ;	// rootの独立成功。
		// 全到達packageのpayloadを各INFのCAT memberとして検証する。
		for( std::size_t index = 1U; index < closure.references.size(); ++index) {
			const auto		  &reference = closure.references[index] ;	// 到達INFの全位置観測。
			OfficialInfPackage dependencyPackage ;						// 導入能力を持たない署名helper入力。
			dependencyPackage.infRelativePath	  = reference.infRelativePath ;
			dependencyPackage.catalogRelativePath = reference.catalogRelativePath ;
			dependencyPackage.sourceFiles		  = reference.sourceFiles ;
			error = verifyWindowsInfPackageIntegrity( workspace, dependencyPackage) ;
			// 既知の依存payload署名失敗を全未検査へ上書きしない。
			if( error != 0) {
				closure.integrity = {MaintenanceInspectionState::FAILED, error} ;
				complete		  = false ;
			}
		}

		// 全署名成功のみをPASSEDとし、部分成功はNOT_CHECKEDへ残す。
		if( complete) {
			closure.integrity = {MaintenanceInspectionState::PASSED, 0} ;
		}
	}

	closure.content.packages.push_back( std::move( package)) ;
	closure.content.expandedBytes = expandedBytes ;
	return 0 ;
}
} // namespace

} // namespace drivercrate
