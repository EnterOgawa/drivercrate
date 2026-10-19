//------------------------------------------------------------------------------
/**
 * @file intel_wireless_package.cpp
 * @brief Intel Wireless署名済みINF ZIP検証実装。
 * @version 01.00.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  利用者選択INF ZIP共通検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  一段nested ZIP安全展開追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  固定subdirectory選択検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  固定archive整合性検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  固定file集合の選択展開追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  汎用Provider名検証mode対応。
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
 * @note 利用者選択ZIPを共有なしで読み取り、保護workspace内の複製だけを展開・検証します。Intel Net class INFとMicrosoft WHCP署名以外は拒否します。
 */
//------------------------------------------------------------------------------

#include "platform/intel_wireless_package.h"

#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

// 利用者選択ZIPとして受理する圧縮dataの最大byte数。
constexpr std::uint64_t MAXIMUM_ARCHIVE_BYTES = 128ULL * 1024ULL * 1024ULL ;
// 一つの展開fileへ許可する最大byte数。
constexpr std::uint64_t MAXIMUM_SINGLE_FILE_BYTES = 64ULL * 1024ULL * 1024ULL ;
// ZIP全体の展開後最大byte数。
constexpr std::uint64_t MAXIMUM_EXPANDED_BYTES		 = 512ULL * 1024ULL * 1024ULL ;
constexpr std::uint32_t MAXIMUM_ENTRY_COUNT			 = 4096U ;						// ZIP内の通常file数上限。
constexpr std::size_t	MAXIMUM_INF_COUNT			 = 128U ;						// 一ZIP内のINF数上限。
constexpr std::size_t	MAXIMUM_HARDWARE_IDS_PER_INF = 1024U ;						// 一INFのPnP ID数上限。
constexpr std::size_t	MAXIMUM_SOURCE_FILES_PER_INF = 2048U ;						// 一INFのsource file数上限。
constexpr DWORD			READ_CHUNK_BYTES = 1024U * 1024U ;							// 選択fileを複製する一回の最大byte数。
constexpr std::wstring_view			  WORKSPACE_ARCHIVE_NAME = L"selected.zip" ;	// 保護copy名。

constexpr OfficialZipExtractionPolicy ZIP_POLICY{
	.maximumArchiveBytes	   = MAXIMUM_ARCHIVE_BYTES,
	.maximumSingleFileBytes	   = MAXIMUM_SINGLE_FILE_BYTES,
	.maximumTotalExpandedBytes = MAXIMUM_EXPANDED_BYTES,
	.maximumEntryCount		   = MAXIMUM_ENTRY_COUNT,
} ; // Intel driver-only ZIPへ適用する展開上限。

constexpr std::array ACCEPTED_CLASSES{std::wstring_view( L"Net")} ;		// 許可するsetup class。
constexpr std::array ACCEPTED_PROVIDERS{std::wstring_view( L"Intel")} ;	// 許可INF Provider。
constexpr std::array ACCEPTED_INF_SIGNATURES{							// Intel packageに許可するINF signature。
											 std::wstring_view( L"$Windows NT$")} ;
constexpr std::array ACCEPTED_SIGNERS{
	// CAT signer。
	std::wstring_view( L"Microsoft Windows Hardware Compatibility Publisher")} ;

constexpr OfficialInfInspectionPolicy INF_POLICY{
	.maximumHardwareIds = MAXIMUM_HARDWARE_IDS_PER_INF,
	.maximumSourceFiles = MAXIMUM_SOURCE_FILES_PER_INF,
	.acceptedClasses	= ACCEPTED_CLASSES,
	.acceptedProviders	= ACCEPTED_PROVIDERS,
	.acceptedSignatures = ACCEPTED_INF_SIGNATURES,
} ; // Intel Wireless INFへ適用する構造policy。

constexpr std::array COVERED_DRIVER_EXTENSIONS{std::wstring_view( L".inf"),
											   std::wstring_view( L".cat"),
											   // 全て検証済みINFへ所属させるdriver file拡張子。
											   std::wstring_view( L".sys")} ;

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief CloseHandleで解放する一つのfile handleを所有する。
 */
class UniqueFile	 final {
public:
	//------------------------------------------------------------------------------
	/**
     * @brief 有効・無効を問わずhandleを受け取りRAII管理を開始する。
     *
     * @param[in] handle 所有権を受け取るfile handle。
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
	UniqueFile			&operator=( UniqueFile &&) = delete ;

	//------------------------------------------------------------------------------
	/**
     * @brief Windows API呼出し中だけ所有handleを参照する。
     * @return 所有権を移さないfile handle。
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
 * 0を成功のまま保持し、診断用Win32 errorを失わない。
 *
 * @param[in] error Win32 error code。
 * @return HRESULT_FROM_WIN32で変換したbit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASCII pathを大文字小文字非依存の比較keyへ変換する。
 *
 * Locale依存変換を使わずZIP entryの重複確認規則と一致させる。
 *
 * @param[in] path ZIP検証済みASCII相対pathまたは拡張子。
 * @return ASCII英大文字を小文字化したpath。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizeAsciiPath( const std::wstring_view path)
{
	std::wstring normalized( path) ;	// 呼出し側入力を変更しない比較用copy。
	std::ranges::transform( normalized, normalized.begin(), []( const wchar_t character) {
		return character >= L'A' && character <= L'Z'
				   ? static_cast<wchar_t>( character - L'A' + L'a')
				   : character ;
	}) ;
	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief 文字列が正規のSHA-256 ASCII hexか判定する。
 *
 * 固定archive policyの誤記をpayload不一致と区別する。
 *
 * @param[in] value 検証するhash文字列。
 * @return 64桁のASCII 16進文字だけで構成される場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSha256Hex( const std::wstring_view value) noexcept
{
	// SHA-256の固定64桁に合わない値を拒否する。
	if( value.size() != 64U) {
		return false ;
	}

	// 全桁を有限回検査し、Unicodeの数字や区切り文字を許可しない。
	for( const wchar_t character : value) {
		const bool decimal = character >= L'0' && character <= L'9' ;	// ASCII数字判定。
		const bool lower   = character >= L'a' && character <= L'f' ;	// 小文字hex判定。
		const bool upper   = character >= L'A' && character <= L'F' ;	// 大文字hex判定。
		// ASCII hex以外を期待hashに含めない。
		if( !decimal && !lower && !upper) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つのSHA-256を大文字小文字非依存で完全一致させる。
 *
 * 大文字表記だけを許容し、短縮hashやprefix一致を拒否する。
 *
 * @param[in] left 検証済みまたは検証対象の左hash。
 * @param[in] right 検証済みまたは検証対象の右hash。
 * @return 両方が正規SHA-256で全桁一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool sha256Equal( const std::wstring_view left, const std::wstring_view right) noexcept
{
	return isSha256Hex( left) && isSha256Hex( right) &&
		   std::ranges::equal( left, right, []( const wchar_t lhs, const wchar_t rhs) noexcept {
			   const wchar_t leftLower	= lhs >= L'A' && lhs <= L'F' ? lhs - L'A' + L'a' : lhs ;
			   const wchar_t rightLower = rhs >= L'A' && rhs <= L'F' ? rhs - L'A' + L'a' : rhs ;
			   return leftLower == rightLower ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 利用者選択packageの整合性policyを検証する。
 *
 * Archive選択方式の矛盾、CAT modeへの固定hash混入、固定modeの空・不正hashを実file処理前にfail-closedで拒否する。
 *
 * @param[in] policy Providerが固定した整合性条件。
 * @return 矛盾のない既知modeなら0、それ以外は`E_INVALIDARG`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateIntegrityPolicy(
	const UserSelectedInfPackagePolicy &policy) noexcept
{
	// Directoryとfile集合の同時選択、およびnested ZIP内file選択を曖昧にしない。
	if( (!policy.archiveSubdirectory.empty() && !policy.archiveSelectedFiles.empty()) ||
	   (!policy.archiveSelectedFiles.empty() && policy.maximumNestedArchiveCount != 0U)) {

		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 整合性modeごとに必要な証拠と禁止する余剰指定を検証する。
	switch( policy.integrityMode) {
		// Catalog member 検証 mode に固定 archive・embedded 署名の別条件を混在させない。
		case UserSelectedInfPackageIntegrityMode::CATALOG_SHA256_MEMBERS:
			return policy.acceptedArchiveSha256.empty() && policy.embeddedSignatureFiles.empty()
					   ? 0
					   : static_cast<NativeError>( E_INVALIDARG) ;
		case UserSelectedInfPackageIntegrityMode::PINNED_ARCHIVE_AND_EMBEDDED_SIGNATURES:
			// 固定archive方式ではhashと埋込署名対象の両方を要求する。
			if( policy.acceptedArchiveSha256.empty() || policy.embeddedSignatureFiles.empty()) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			// Providerに埋め込む全hashを検査し、誤った一要素も黙って無視しない。
			for( const std::wstring_view hash : policy.acceptedArchiveSha256) {
				// allowlistへ不正なSHA-256表現を登録しない。
				if( !isSha256Hex( hash)) {
					return static_cast<NativeError>( E_INVALIDARG) ;
				}
			}

			// 署名対象pathの空値、null、重複を実file検証より前に拒否する。
			for( std::size_t index = 0; index < policy.embeddedSignatureFiles.size(); ++index) {
				const std::wstring_view path = policy.embeddedSignatureFiles[index] ;	// 現在path。
				const bool				duplicate = std::ranges::any_of(
					 policy.embeddedSignatureFiles.first( index),
					 [path]( const std::wstring_view previous) noexcept {
						 return path.size() == previous.size() &&
								std::ranges::equal(
									path, previous,
									[]( const wchar_t left, const wchar_t right) noexcept {
										const wchar_t leftLower =
											left >= L'A' && left <= L'Z'
															? static_cast<wchar_t>( left - L'A' + L'a')
															: left ;
										const wchar_t rightLower =
											right >= L'A' && right <= L'Z'
															? static_cast<wchar_t>( right - L'A' + L'a')
															: right ;
										return leftLower == rightLower ;
									}) ;
					 }) ; // 先行pathとのASCII case非依存重複状態。
				// 空、埋込NUL付き、重複の署名対象pathを拒否する。
				if( path.empty() || path.find( L'\0') != std::wstring_view::npos || duplicate) {
					return static_cast<NativeError>( E_INVALIDARG) ;
				}
			}

			return 0 ;
		// 未知の整合性検証 mode を弱い既定検証へ変更しない。
		default:
			return static_cast<NativeError>( E_INVALIDARG) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Archive hashをProvider固定allowlistへ照合する。
 *
 * CAT modeではhash固定を要求せず、固定modeだけ完全一致をpackage受理の前提にする。
 *
 * @param[in] actualSha256 保護copy全体から計算したSHA-256。
 * @param[in] policy Providerが固定した整合性条件。
 * @return Policyとhashが有効なら0、不一致は`TRUST_E_BAD_DIGEST`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyArchiveSha256( const std::wstring_view			  actualSha256,
											  const UserSelectedInfPackagePolicy &policy) noexcept
{
	const NativeError policyError = validateIntegrityPolicy( policy) ;	// Policy構造検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( policyError != 0) {
		return policyError ;
	}

	// CAT member照合方式ではarchive固定hashによる検証を追加しない。
	if( policy.integrityMode == UserSelectedInfPackageIntegrityMode::CATALOG_SHA256_MEMBERS) {
		return 0 ;
	}

	const bool accepted = std::ranges::any_of(
		policy.acceptedArchiveSha256, [actualSha256]( const std::wstring_view expected) noexcept {
			return sha256Equal( actualSha256, expected) ;
		}) ; // 固定hashの完全一致結果。
	return accepted ? 0 : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 展開済み全entryのSHA-256 snapshotを取得する。
 *
 * Install前の差替え検出に使用する全file snapshotを作成し、部分取得した結果は候補として公開しない。
 *
 * @param[in] workspace 展開fileを所有する保護workspace。
 * @param[in,out] entries 成功時にSHA-256を保持する全通常file。
 * @return 全entryのhash取得成功時は0、最初のfile/CNG失敗値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError captureEntrySha256( const OfficialDownloadWorkspace  &workspace,
											 const std::span<OfficialZipEntry> entries)
{
	// 空の展開集合から検証snapshotを作らない。
	if( entries.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// Archive構造検証済みの全通常fileを一件ずつ内容hashへ拘束する。
	for( OfficialZipEntry &entry : entries) {
		const std::wstring path = workspace.path( entry.relativePath) ;	// 展開file絶対path。
		// workspace内へ解決できないentryのhash取得を拒否する。
		if( path.empty()) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		const NativeError error = computeFileSha256( path, entry.sha256) ;	// Snapshot取得結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 展開済み全entryをscan時snapshotへ再照合する。
 *
 * 管理者権限を持つ競合processによるscan後差替えを、INF解析またはSetupAPI installへ進む前に拒否する。
 *
 * @param[in] workspace Scan時の展開fileを所有する保護workspace。
 * @param[in] entries Scan時のsizeとSHA-256を保持する全entry。
 * @return 全sizeとhashが一致する場合は0、最初の不一致または失敗値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError reverifyEntrySha256( const OfficialDownloadWorkspace		 &workspace,
											  const std::span<const OfficialZipEntry> entries)
{
	// 空の展開集合を再検証成功としない。
	if( entries.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 全entryをscan時の有限snapshotへ再照合し、部分一致を受理しない。
	for( const OfficialZipEntry &entry : entries) {
		const std::wstring path = workspace.path( entry.relativePath) ;	// 現在entry絶対path。
		// entry pathや保存hashが不正ならsnapshot照合を中止する。
		if( path.empty() || !isSha256Hex( entry.sha256)) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		const OfficialFileMetadataPolicy metadata{
			.expectedSize	= entry.uncompressedSize,
			.expectedSha256 = entry.sha256,
		} ; // Scan時に確定したsizeとhash。
		const NativeError error = verifyOfficialFileMetadata( path, metadata) ;	// 再照合結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Pathの小文字ASCII拡張子を取得する。
 *
 * 拡張子がない場合またはseparatorより前のdotは空を返す。
 *
 * @param[in] path 入力path。
 * @return 最終separator後の`.`から始まる小文字拡張子。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring lowerExtension( const std::wstring_view path)
{
	const std::size_t dot		= path.find_last_of( L'.') ;	// 最終dot位置。
	const std::size_t separator = path.find_last_of( L"\\/") ;	// 最終path separator位置。
	// file名部分にdotがないpathは拡張子なしとして扱う。
	if( dot == std::wstring_view::npos ||
	   (separator != std::wstring_view::npos && dot < separator)) {
		return {} ;
	}

	return normalizeAsciiPath( path.substr( dot)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Pathの最後のfile名を取得する。
 *
 * Package種別を署名対象file名で限定する比較に使用する。
 *
 * @param[in] path ZIP検証済みASCII相対path。
 * @return 最後のseparatorより後ろのfile名。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring_view fileName( const std::wstring_view path) noexcept
{
	const std::size_t separator = path.find_last_of( L"\\/") ;	// 最終separator位置。
	return separator == std::wstring_view::npos ? path : path.substr( separator + 1U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Intel Wireless固有の署名済みINF packageか判定する。
 *
 * 同じProvider、class、WHCP signerを持つIntel Ethernet INFをWireless候補として誤受理しない。命名変更時は拒否側へ倒す。
 *
 * @param[in] package 構造検証済みのIntel Net class INF。
 * @return Netwtw INF／SYSとIntel PCI IDを全て満たす場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isIntelWirelessPackage( const OfficialInfPackage &package)
{
	const std::wstring infName =
		// 小文字INF名。
		normalizeAsciiPath( fileName( package.infRelativePath)) ;
	// Intel Wireless INFの命名とHardware ID証拠を備えないpackageを除外する。
	if( !infName.starts_with( L"netwtw") || !infName.ends_with( L".inf") ||
	   package.hardwareIds.empty()) {
		return false ;
	}

	// 全model IDをIntel PCI deviceへ限定し、別vendorやgeneric class IDを許可しない。
	for( const std::wstring &hardwareId : package.hardwareIds) {
		// Intel PCI vendor以外のIDを含むpackageをWireless固有経路で扱わない。
		if( !normalizeAsciiPath( hardwareId).starts_with( L"pci\\ven_8086&")) {
			return false ;
		}
	}

	// 少なくとも一つの署名対象Netwtw SYSを要求し、INF名だけの偽装を拒否する。
	return std::ranges::any_of( package.sourceFiles, []( const std::wstring &sourceFile) {
		const std::wstring name = normalizeAsciiPath( fileName( sourceFile)) ;	// File名。
		return name.starts_with( L"netwtw") && name.ends_with( L".sys") ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 利用者選択fileを共有なしで読み保護workspaceへ複製する。
 *
 * Directory、reparse point、空file、上限超過、共有中fileを拒否し、検証対象を呼出し中に差し替えられないようにする。
 *
 * @param[in] selectedPath 利用者が選択したlocal ZIP path。
 * @param[in,out] workspace 複製fileを所有する保護領域。
 * @param[out] archive 成功時の固定済みZIP byte列。
 * @return 全byteを一度だけ読み書きできた場合は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError copySelectedArchive( const std::wstring_view	 selectedPath,
											  OfficialDownloadWorkspace &workspace,
											  std::vector<std::byte>	&archive)
{
	archive.clear() ;
	// 空、埋込NUL付き、ZIP以外の選択pathを取得前に拒否する。
	if( selectedPath.empty() || selectedPath.find( L'\0') != std::wstring_view::npos ||
	   lowerExtension( selectedPath) != L".zip") {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring selected( selectedPath) ;	// CreateFileW用null終端path。
	UniqueFile		   input( CreateFileW( selected.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING,
										 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
											 FILE_FLAG_SEQUENTIAL_SCAN,
										 nullptr)) ;	// 共有なしで固定した利用者選択file。
	// 利用者選択fileを開けなければ複製を開始しない。
	if( input.get() == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	BY_HANDLE_FILE_INFORMATION information{} ;	// Reparse、directory、size検証用metadata。
	// 開いたfileの属性取得失敗を診断値付きで返す。
	if( GetFileInformationByHandle( input.get(), &information) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// ディレクトリや再解析点を選択archiveとして読み込まない。
	if( (information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
	   0) {
		return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
	}

	LARGE_INTEGER size{} ;	// 選択fileの符号付きbyte数。
	// file sizeを取得できなければ読み込み量を推測しない。
	if( GetFileSizeEx( input.get(), &size) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 空、archive上限超過、address可能size超過のfileを拒否する。
	if( size.QuadPart <= 0 || static_cast<std::uint64_t>( size.QuadPart) > MAXIMUM_ARCHIVE_BYTES ||
	   static_cast<std::uint64_t>( size.QuadPart) >
		   static_cast<std::uint64_t>( std::numeric_limits<std::size_t>::max())) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	HANDLE outputHandle{INVALID_HANDLE_VALUE} ;	// Workspaceが作成し本関数が閉じる複製file handle。
	// 保護workspaceでarchive出力先を作成した結果。書込み開始前に確認する。
	const NativeError createError = workspace.createFile( WORKSPACE_ARCHIVE_NAME, outputHandle) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( createError != 0) {
		return createError ;
	}

	UniqueFile output( outputHandle) ;	// 全return経路で閉じる保護領域file。

	try {
		std::vector<std::byte> copied( static_cast<std::size_t>( size.QuadPart)) ;	// 固定入力全体。
		std::size_t			   offset{} ;											// 次に読み書きするarchive byte位置。
		// 1 MiB以下の有限chunkで、宣言sizeと同じbyte数だけ読み書きする。
		while( offset < copied.size()) {
			const std::size_t remaining = copied.size() - offset ;	// 未処理byte数。
			const DWORD		  requested = static_cast<DWORD>(
				  std::min<std::size_t>( remaining, READ_CHUNK_BYTES)) ;	// 今回要求するbyte数。
			DWORD read{} ;													// Inputから実際に読んだbyte数。
			// 選択fileの読み込み失敗は元のWindows診断値で返す。
			if( ReadFile( input.get(), copied.data() + offset, requested, &read, nullptr) == FALSE) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			// 要求byte数より短い読み込みを完全なarchiveとみなさない。
			if( read != requested) {
				return nativeErrorFromWin32( ERROR_HANDLE_EOF) ;
			}

			DWORD written{} ;	// 保護領域へ実際に書いたbyte数。
			// 保護workspaceへの書込み失敗や部分書込みを検出して中止する。
			if( WriteFile( output.get(), copied.data() + offset, requested, &written, nullptr) ==
				   FALSE ||
			   written != requested) {
				const DWORD error = GetLastError() ;	// WriteFile失敗または部分書込み診断値。
				return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_WRITE_FAULT : error) ;
			}

			offset += requested ;
		}

		archive = std::move( copied) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		archive.clear() ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 全driver entryが検証済みINFへ所属するか確認する。
 *
 * 未検査driverを同梱したarchiveを部分成功として受理しない。
 *
 * @param[in] entries ZIP内の全通常file。
 * @param[in] packages 署名検証済みINF package群。
 * @return 全INF、CAT、SYSが少なくとも一つの検証済みpackageに所属する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool allDriverEntriesAreCovered( const std::span<const OfficialZipEntry>	entries,
											  const std::span<const OfficialInfPackage> packages)
{
	std::unordered_set<std::wstring> covered ;	// 検証済みpackageに所属する正規化path集合。
	// 各packageのINF、CAT、現在x64用参照fileをcoverage集合へ追加する。
	for( const OfficialInfPackage &package : packages) {
		covered.insert( normalizeAsciiPath( package.infRelativePath)) ;
		covered.insert( normalizeAsciiPath( package.catalogRelativePath)) ;
		// 各INFの参照fileを正規化してdriver entryの所属集合へ追加する。
		for( const std::wstring &sourceFile : package.sourceFiles) {
			covered.insert( normalizeAsciiPath( sourceFile)) ;
		}
	}

	// Driverとして解釈される拡張子だけは未参照fileを一件も許可しない。
	for( const OfficialZipEntry &entry : entries) {
		const std::wstring extension = lowerExtension( entry.relativePath) ;	// 現在entry拡張子。
		// どの検証済みINFにも所属しないdriver entryを拒否する。
		if( std::ranges::find( COVERED_DRIVER_EXTENSIONS, extension) !=
			   COVERED_DRIVER_EXTENSIONS.end() &&
		   !covered.contains( normalizeAsciiPath( entry.relativePath))) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つのINF検証結果が完全一致するか確認する。
 *
 * PnP ID、参照file、version等の部分一致を差替え成功としない。
 *
 * @param[in] left Scan時に保持したINF metadata。
 * @param[in] right Install直前に再取得したINF metadata。
 * @return 全fieldと順序付きcollectionが一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool packagesEqual( const OfficialInfPackage &left,
								 const OfficialInfPackage &right) noexcept
{
	return left.infRelativePath == right.infRelativePath &&
		   left.catalogRelativePath == right.catalogRelativePath &&
		   left.className == right.className && left.providerName == right.providerName &&
		   left.driverDate == right.driverDate && left.driverVersion == right.driverVersion &&
		   left.hardwareIds == right.hardwareIds && left.sourceFiles == right.sourceFiles ;
}

//------------------------------------------------------------------------------
/**
 * @brief Policy指定方式で一つのINF package整合性を検証する。
 *
 * SHA-1 CATを一般fallbackとして受理せず、固定archive modeだけSetupAPI署名と全参照binary埋込み署名を組み合わせる。
 *
 * @param[in] workspace 展開fileを所有する保護workspace。
 * @param[in] package 構造とfamilyを検証済みのINF package。
 * @param[in] policy Provider固定の整合性方式とsigner。
 * @return 指定方式の全検証成功時は0、最初の違反または失敗値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyPackageIntegrity( const OfficialDownloadWorkspace	&workspace,
												 const OfficialInfPackage			&package,
												 const UserSelectedInfPackagePolicy &policy)
{
	// 整合性modeに対応するCAT member照合または固定archive方式を実行する。
	switch( policy.integrityMode) {
		// Catalog member mode では INF 閉包の共通整合性検証を実行する。
		case UserSelectedInfPackageIntegrityMode::CATALOG_SHA256_MEMBERS:
			return verifyOfficialInfPackageIntegrity( workspace, package, policy.signers) ;
		// 固定 archive mode では catalog 署名を確認後、指定 file の embedded 署名を検証する。
		case UserSelectedInfPackageIntegrityMode::PINNED_ARCHIVE_AND_EMBEDDED_SIGNATURES: {
			// INFに対応するCAT署名と許可publisherの検証結果。
			const NativeError catalogError =
				verifyOfficialInfCatalogSignature( workspace, package, policy.signers) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( catalogError != 0) {
				return catalogError ;
			}

			return verifyOfficialInfEmbeddedFileSignatures(
				workspace, package, policy.embeddedSignatureFiles, policy.signers) ;
		}
		// 未定義の検証 mode は package を受理せず拒否する。
		default:
			return static_cast<NativeError>( E_INVALIDARG) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 保護workspace内のZIPを上限付きで読み込む。
 *
 * 外側ZIPで検証したpathとsize以外を使用しない。
 *
 * @param[in] workspace 外側ZIPを展開した保護領域。
 * @param[in] entry 読み込む検証済み通常file entry。
 * @param[in] maximumSize 許可する読込みbyte数上限。
 * @param[out] archive 成功時のZIP byte列。
 * @return 宣言sizeと一致する全byteを読み込めた場合は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readWorkspaceArchive( const OfficialDownloadWorkspace &workspace,
											   const OfficialZipEntry		   &entry,
											   const std::uint64_t				maximumSize,
											   std::vector<std::byte>		   &archive)
{
	archive.clear() ;
	// 空、指定上限超過、address可能size超過の内部ZIPを拒否する。
	if( entry.uncompressedSize == 0 || entry.uncompressedSize > maximumSize ||
	   entry.uncompressedSize >
		   static_cast<std::uint64_t>( std::numeric_limits<std::size_t>::max())) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	const std::wstring path = workspace.path( entry.relativePath) ;	// 検証済みnested ZIP絶対path。
	// 保護workspace内で内部ZIPを解決できなければ読み込まない。
	if( path.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	UniqueFile input( CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
								 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
								 nullptr)) ;	// 保護workspace内の読取りhandle。
	// 内部ZIPを開けなければ読み込みを中止する。
	if( input.get() == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	LARGE_INTEGER size{} ;	// 実fileの符号付きbyte数。
	// 内部ZIPの実sizeを取得できなければ読み込みを開始しない。
	if( GetFileSizeEx( input.get(), &size) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 成功API後のstale GetLastErrorを返さず、size差替えを明示的に拒否する。
	if( size.QuadPart <= 0 || static_cast<std::uint64_t>( size.QuadPart) != entry.uncompressedSize) {

		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	archive.resize( static_cast<std::size_t>( entry.uncompressedSize)) ;
	std::size_t offset{} ;	// 次に読み込むarchive byte位置。
	// 1 MiB以下の有限chunkで宣言size分だけ読み込む。
	while( offset < archive.size()) {
		const std::size_t remaining = archive.size() - offset ;	// 未処理byte数。
		const DWORD		  requested = static_cast<DWORD>(
			  std::min<std::size_t>( remaining, READ_CHUNK_BYTES)) ;	// 今回要求するbyte数。
		DWORD read{} ;													// 実際に読み込んだbyte数。
		// 内部ZIPの読み込み失敗時は部分bufferを破棄する。
		if( ReadFile( input.get(), archive.data() + offset, requested, &read, nullptr) == FALSE) {
			archive.clear() ;
			return nativeErrorFromWin32( GetLastError()) ;
		}

		// 途中EOFのarchiveを完全な入力として公開しない。
		if( read != requested) {
			archive.clear() ;
			return nativeErrorFromWin32( ERROR_HANDLE_EOF) ;
		}

		offset += requested ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 展開済みentryの合計上限を検証する。
 *
 * Archiveごとの上限を合算することでnested ZIP bombを防ぐ。
 *
 * @param[in] entries 外側とnested ZIPの全通常file。
 * @param[in] policy entry数と展開後byte数の上限。
 * @return 全archive合計が上限内の場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool expandedEntriesFit( const std::span<const OfficialZipEntry> entries,
									  const OfficialZipExtractionPolicy		 &policy) noexcept
{
	// 合計entry数がpolicy上限を超える展開結果を拒否する。
	if( entries.size() > policy.maximumEntryCount) {
		return false ;
	}

	std::uint64_t total{} ;	// 全entryの展開後byte数合計。
	// 全entryの展開sizeをoverflowせず合算する。
	for( const OfficialZipEntry &entry : entries) {
		// 残り許容byte数を超えるentryを加算前に拒否する。
		if( entry.uncompressedSize > policy.maximumTotalExpandedBytes - total) {
			return false ;
		}

		total += entry.uncompressedSize ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Intel Wirelessの利用者選択ZIP検証条件を返す。
 *
 * Netwtw INFを一段のZIPとして検証し、nested ZIPを許可しない。
 * @return Process lifetime中有効なIntel固有policy。
 */
//------------------------------------------------------------------------------
[[nodiscard]] const UserSelectedInfPackagePolicy &intelPackagePolicy() noexcept
{
	static constexpr UserSelectedInfPackagePolicy POLICY{
		.workspaceTag			   = L"intel-wireless-package",
		.zipPolicy				   = ZIP_POLICY,
		.maximumInfCount		   = MAXIMUM_INF_COUNT,
		.maximumNestedArchiveCount = 0,
		.archiveSubdirectory	   = {},
		.archiveSelectedFiles	   = {},
		.integrityMode			   = UserSelectedInfPackageIntegrityMode::CATALOG_SHA256_MEMBERS,
		.acceptedArchiveSha256	   = {},
		.embeddedSignatureFiles	   = {},
		.infPolicy				   = INF_POLICY,
		.signers				   = ACCEPTED_SIGNERS,
		.packagePredicate		   = isIntelWirelessPackage,
	} ; // Intel Wireless固有の変更不可policy。
	return POLICY ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/user_selected_inf_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError inspectUserSelectedInfPackageFile( const std::wstring_view			  selectedPath,
											  const ScanSessionId				  scanSessionId,
											  const UserSelectedInfPackagePolicy &policy,
											  OfficialDownloadWorkspace			 &workspace,
											  UserSelectedInfPackageContents	 &contents)
{
	contents						 = {} ;
	const bool invalidProviderPolicy =	// 固定allowlistと汎用modeの矛盾状態。
		policy.infPolicy.acceptAnyProvider ? !policy.infPolicy.acceptedProviders.empty()
										   : policy.infPolicy.acceptedProviders.empty() ;
	// sessionとINF・provider・署名policyの必須条件を処理前に確認する。
	if( scanSessionId == 0 || policy.workspaceTag.empty() || policy.maximumInfCount == 0 ||
	   policy.infPolicy.acceptedClasses.empty() || invalidProviderPolicy ||
	   policy.signers.empty() || policy.packagePredicate == nullptr) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const NativeError policyError = validateIntegrityPolicy( policy) ;	// 整合性policy検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( policyError != 0) {
		return policyError ;
	}

	// 検証用workspaceの初期化からpackage検証へ引き継ぐ診断値。
	NativeError error = workspace.initialize( policy.workspaceTag, scanSessionId) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	try {
		std::vector<std::byte> archive ;	// 共有なしで保護領域へ複製した入力ZIP。
		error = copySelectedArchive( selectedPath, workspace, archive) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		contents.verificationStage = UserSelectedInfPackageVerificationStage::ARCHIVE_COPIED ;
		UserSelectedInfPackageContents inspected ;	// 全検証成功時だけ公開する結果。
		inspected.archiveSize		   = archive.size() ;
		const std::wstring archivePath = workspace.path( WORKSPACE_ARCHIVE_NAME) ;	// 複製ZIP path。
		error						   = computeFileSha256( archivePath, inspected.archiveSha256) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		error = verifyArchiveSha256( inspected.archiveSha256, policy) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		// 明示されたfile集合がある場合はその範囲だけを展開する。
		if( !policy.archiveSelectedFiles.empty()) {
			error = extractOfficialZipFiles( archive, policy.zipPolicy, policy.archiveSelectedFiles,
											workspace, inspected.entries) ;
		}
		// 部分directory指定がない場合はarchive全体の共通検証展開を使う。
		else if( policy.archiveSubdirectory.empty()) {
			error = extractOfficialZip( archive, policy.zipPolicy, workspace, inspected.entries) ;
		} else {
			error = extractOfficialZipSubdirectory( archive, policy.zipPolicy,
												   policy.archiveSubdirectory, workspace,
												   inspected.entries) ;
		}

		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		contents.verificationStage =
			UserSelectedInfPackageVerificationStage::OUTER_ARCHIVE_EXTRACTED ;

		// 外側archiveの一覧にINFがあり、一段nested archive探索を省略できるかを示す。
		const bool hasTopLevelInf =
			std::ranges::any_of( inspected.entries, []( const OfficialZipEntry &entry) {
				return lowerExtension( entry.relativePath) == L".inf" ;
			}) ;
		// 外側にINFがない場合だけ、許可範囲の一段nested ZIPとして検証する。
		if( !hasTopLevelInf) {
			std::vector<OfficialZipEntry> nestedArchives ;	// 外側ZIPが保持する一段のZIP群。
			// INFがない外側ZIPは、許可数以下のnested ZIP以外を受理しない。
			for( const OfficialZipEntry &entry : inspected.entries) {
				// 外側ZIPに別形式や許可数超過のnested archiveを認めない。
				if( lowerExtension( entry.relativePath) != L".zip" ||
				   nestedArchives.size() >= policy.maximumNestedArchiveCount) {
					return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}

				nestedArchives.push_back( entry) ;
			}

			// INFも内部ZIPもないarchiveをdriver packageとして扱わない。
			if( nestedArchives.empty()) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// 各nested ZIPを同じ上限で検証し、その中のZIPは受理しない。
			for( const OfficialZipEntry &nestedArchive : nestedArchives) {
				std::vector<std::byte> nestedBytes ;	// 保護領域から読み戻した内側ZIP。
				error = readWorkspaceArchive( workspace, nestedArchive,
											 policy.zipPolicy.maximumArchiveBytes, nestedBytes) ;
				// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
				if( error != 0) {
					return error ;
				}

				std::vector<OfficialZipEntry> nestedEntries ;	// 現在の内側ZIP展開結果。
				error = extractOfficialZip( nestedBytes, policy.zipPolicy, workspace, nestedEntries) ;
				// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
				if( error != 0) {
					return error ;
				}

				// 二段目以降のnested ZIPを拒否して展開深度を制限する。
				if( std::ranges::any_of( nestedEntries, []( const OfficialZipEntry &entry) {
					   return lowerExtension( entry.relativePath) == L".zip" ;
				   })) {
					return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}

				inspected.entries.insert( inspected.entries.end(),
										 std::make_move_iterator( nestedEntries.begin()),
										 std::make_move_iterator( nestedEntries.end())) ;
				// 内部ZIP展開後も合計entry数とbyte上限を適用する。
				if( !expandedEntriesFit( inspected.entries, policy.zipPolicy)) {
					return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
				}
			}
		}

		contents.verificationStage =
			UserSelectedInfPackageVerificationStage::ARCHIVE_STRUCTURE_VERIFIED ;
		error = captureEntrySha256( workspace, inspected.entries) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		std::vector<std::wstring_view> infPaths ;	// ZIP順を維持する全INF相対path view。
		infPaths.reserve( policy.maximumInfCount) ;
		// 外側と内側の全entryからINFを有限数だけ収集する。
		for( const OfficialZipEntry &entry : inspected.entries) {
			// INF以外のentryをpackage metadata解析から除外する。
			if( lowerExtension( entry.relativePath) != L".inf") {
				continue ;
			}

			// 検証対象INFの件数上限を超えるarchiveを拒否する。
			if( infPaths.size() >= policy.maximumInfCount) {
				return nativeErrorFromWin32( ERROR_TOO_MANY_NAMES) ;
			}

			infPaths.push_back( entry.relativePath) ;
		}

		// 対象INFが一つもない展開結果を採用しない。
		if( infPaths.empty()) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		inspected.packages.reserve( infPaths.size()) ;
		// 全INFに同じ構造とProvider family検証を適用する。
		for( const std::wstring_view infPath : infPaths) {
			OfficialInfPackage package ;	// 現在INFの全検証成功時だけ保持する構造。
			error = inspectOfficialInfPackage( workspace, inspected.entries, infPath,
											  policy.infPolicy, package) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}

			// 共通検証後もProvider固有のpackage条件に合わなければ拒否する。
			if( !policy.packagePredicate( package)) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			inspected.packages.push_back( std::move( package)) ;
		}

		contents.verificationStage =
			UserSelectedInfPackageVerificationStage::INF_METADATA_VALIDATED ;

		// 全INFへProviderが固定した一つの整合性方式を適用する。
		for( const OfficialInfPackage &package : inspected.packages) {
			error = verifyPackageIntegrity( workspace, package, policy) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}
		}

		contents.verificationStage =
			UserSelectedInfPackageVerificationStage::PACKAGE_INTEGRITY_VERIFIED ;
		// 全driver entryが検証済みINFに所属しないarchiveを拒否する。
		if( !allDriverEntriesAreCovered( inspected.entries, inspected.packages)) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		inspected.verificationStage = UserSelectedInfPackageVerificationStage::COMPLETED ;
		contents					= std::move( inspected) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		const UserSelectedInfPackageVerificationStage stage =
			contents.verificationStage ;	// Allocation失敗前に完了した安全な段階。
		contents				   = {} ;
		contents.verificationStage = stage ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/intel_wireless_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError inspectIntelWirelessPackageFile( const std::wstring_view		  selectedPath,
											const ScanSessionId			  scanSessionId,
											OfficialDownloadWorkspace	 &workspace,
											IntelWirelessPackageContents &contents)
{
	contents = {} ;
	// 無効なscan sessionへ利用者選択ZIPを登録しない。
	if( scanSessionId == 0) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// Intel無線package用の保護workspaceを開始した結果。
	NativeError error = workspace.initialize( L"intel-wireless-package", scanSessionId) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	try {
		std::vector<std::byte> archive ;	// 共有なしで読み保護領域へ複製したZIP byte列。
		error = copySelectedArchive( selectedPath, workspace, archive) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		IntelWirelessPackageContents inspected ;	// 全検証成功時だけ公開する一時結果。
		inspected.archiveSize		   = archive.size() ;
		const std::wstring archivePath = workspace.path( WORKSPACE_ARCHIVE_NAME) ;	// 複製ZIP path。
		error						   = computeFileSha256( archivePath, inspected.archiveSha256) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		error = extractOfficialZip( archive, ZIP_POLICY, workspace, inspected.entries) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		std::vector<std::wstring_view> infPaths ;	// ZIP順を維持する全INF相対path view。
		infPaths.reserve( MAXIMUM_INF_COUNT) ;
		// 全entryからINFを有限数だけ収集し、上限超過を部分検証へ縮退させない。
		for( const OfficialZipEntry &entry : inspected.entries) {
			// INF以外のentryをpackage metadata解析から除外する。
			if( lowerExtension( entry.relativePath) != L".inf") {
				continue ;
			}

			// 検証するINF数の上限を超えるZIPを拒否する。
			if( infPaths.size() >= MAXIMUM_INF_COUNT) {
				return nativeErrorFromWin32( ERROR_TOO_MANY_NAMES) ;
			}

			infPaths.push_back( entry.relativePath) ;
		}

		// 対象INFを含まないZIPをdriver packageとみなさない。
		if( infPaths.empty()) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		inspected.packages.reserve( infPaths.size()) ;
		// 全INFをIntel Net class、x64、CAT署名と全member hashの同じ境界で検証する。
		for( const std::wstring_view infPath : infPaths) {
			OfficialInfPackage package ;	// 現在INFの全検証成功時だけ保持する構造。
			error = inspectOfficialInfPackage( workspace, inspected.entries, infPath, INF_POLICY,
											  package) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}

			// 共通検証後もIntel Wireless固有条件に合わないpackageを拒否する。
			if( !isIntelWirelessPackage( package)) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			error = verifyOfficialInfPackageIntegrity( workspace, package, ACCEPTED_SIGNERS) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( error != 0) {
				return error ;
			}

			inspected.packages.push_back( std::move( package)) ;
		}

		// 検証済みINFに所属しないdriver entryの混入を拒否する。
		if( !allDriverEntriesAreCovered( inspected.entries, inspected.packages)) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		contents = std::move( inspected) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		contents = {} ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/intel_wireless_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError reverifyIntelWirelessInfPackage( const OfficialDownloadWorkspace		   &workspace,
											const std::span<const OfficialZipEntry> entries,
											const OfficialInfPackage			   &expected)
{
	OfficialInfPackage actual ;	// 現在fileから再取得するINF metadata。
	NativeError		   error =
		inspectOfficialInfPackage( workspace, entries, expected.infRelativePath, INF_POLICY,
								  actual) ;	// 構造再検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	error = verifyOfficialInfPackageIntegrity( workspace, actual, ACCEPTED_SIGNERS) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	return packagesEqual( expected, actual) ? 0 : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/user_selected_inf_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError reverifyUserSelectedInfPackage( const OfficialDownloadWorkspace		  &workspace,
										   const std::span<const OfficialZipEntry> entries,
										   const OfficialInfPackage				  &expected,
										   const UserSelectedInfPackagePolicy	  &policy)
{
	const bool invalidProviderPolicy =	// Scan時と同じProvider名modeの矛盾状態。
		policy.infPolicy.acceptAnyProvider ? !policy.infPolicy.acceptedProviders.empty()
										   : policy.infPolicy.acceptedProviders.empty() ;
	// 展開証拠とProvider・class・署名policyが揃わなければ再検証しない。
	if( entries.empty() || policy.infPolicy.acceptedClasses.empty() || invalidProviderPolicy ||
	   policy.signers.empty() || policy.packagePredicate == nullptr) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const NativeError policyError = validateIntegrityPolicy( policy) ;	// 整合性policy検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( policyError != 0) {
		return policyError ;
	}

	const std::wstring archivePath = workspace.path( WORKSPACE_ARCHIVE_NAME) ;	// 保護copy絶対path。
	std::wstring	   archiveSha256 ;											// Install直前の保護copy SHA-256。
	NativeError		   error = computeFileSha256( archivePath, archiveSha256) ;	// Archive再hash結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	error = verifyArchiveSha256( archiveSha256, policy) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	error = reverifyEntrySha256( workspace, entries) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	OfficialInfPackage actual ;	// 現在fileから再取得するINF metadata。
	error = inspectOfficialInfPackage( workspace, entries, expected.infRelativePath,
									  policy.infPolicy, actual) ;	// 構造結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	// 導入直前にも実INFがProvider固有条件を満たすことを要求する。
	if( !policy.packagePredicate( actual)) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	error = verifyPackageIntegrity( workspace, actual, policy) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	return packagesEqual( expected, actual) ? 0 : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
}

} // namespace drivercrate
