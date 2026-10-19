//------------------------------------------------------------------------------
/**
 * @file official_zip_tests.cpp
 * @brief 公式ZIP package安全展開単体試験実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  固定subdirectory選択展開試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  固定file集合の選択展開試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  展開file SHA-256試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/15  逆slash ZIPの正規化と危険path・衝突の回帰試験。
 * </pre>
 *
 * @note Minizでmemory上に架空ZIPを生成し、networkや実driverへ依存せず検証します。保護workspace外のpathは作成しません。
 */
//------------------------------------------------------------------------------

#include "official_zip_tests.h"

#include "platform/official_download_workspace.h"
#include "platform/official_zip.h"
#include "test_framework.h"

#include <Windows.h>
#include <miniz.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 試験data定義。
//------------------------------------------------------------------------------

/**
 * @brief ZIP境界試験へ格納する架空entryの名前・内容・属性を指定する。
 */
struct ZipFixtureEntry {
	/// ZIP central directoryへ保存するASCII相対path。
	std::string_view path ;
	/// Entryへ保存する架空byte列。
	std::string_view content ;
} ;

constexpr OfficialZipExtractionPolicy DEFAULT_POLICY{1024U * 1024U, 256U * 1024U, 512U * 1024U,
													 32U} ;	// 小さいfixture用の有限上限。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 架空entry群からmemory ZIPを生成する。
 *
 * Test process内だけでMiniz writerを使い、外部fileを作らない。
 *
 * @param[in] sourceEntries ZIPへ追加する架空entry群。
 * @param[out] archive 成功時のZIP container全byte列。
 * @return Central directoryを含むZIPを生成できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool createZipFixture( const std::span<const ZipFixtureEntry> sourceEntries,
									std::vector<std::byte>				  &archive)
{
	archive.clear() ;
	// entryのないZIP fixtureは作成対象にしない。
	if( sourceEntries.empty()) {
		return false ;
	}

	mz_zip_archive writer{} ;	// 終了処理が必要なMiniz writer状態。
	mz_zip_zero_struct( &writer) ;
	// ZIP writerを初期化できなければfixture生成を開始しない。
	if( mz_zip_writer_init_heap( &writer, 0, 0) == 0) {
		return false ;
	}

	// 指定順を維持して全架空entryを追加する。
	for( const ZipFixtureEntry &entry : sourceEntries) {
		// entry追加に失敗した場合はwriterを終了して部分archiveを破棄する。
		if( mz_zip_writer_add_mem( &writer, std::string( entry.path).c_str(), entry.content.data(),
								 entry.content.size(), MZ_BEST_COMPRESSION) == 0) {
			mz_zip_writer_end( &writer) ;
			return false ;
		}
	}

	void	   *bytes{} ;	// Miniz allocatorが所有する完成ZIPの先頭。
	std::size_t size{} ;	// 完成ZIPのbyte数。
	// 空または未確定のarchiveは返さずwriterを終了する。
	if( mz_zip_writer_finalize_heap_archive( &writer, &bytes, &size) == 0 || bytes == nullptr ||
	   size == 0) {
		mz_zip_writer_end( &writer) ;
		return false ;
	}

	try {
		const auto *beginning = static_cast<const std::byte *>( bytes) ;	// 完成ZIP先頭。
		archive.assign( beginning, beginning + size) ;
	} catch( ...) {
		// Miniz allocationを回収したうえで、test harnessへallocation失敗を通知する。
		mz_free( bytes) ;
		mz_zip_writer_end( &writer) ;
		throw ;
	}

	mz_free( bytes) ;
	return mz_zip_writer_end( &writer) != 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 安全な階層ZIPを事前検証して展開できることを検証する。
 *
 * INF／CAT／SYSを模したentryのpath、size、CRC、階層file作成を検証する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testValidOfficialZip( TestContext &context)
{
	constexpr ZipFixtureEntry ENTRIES[]{
		{"network/sample.inf", "[Version]\r\nSignature=\"$Windows NT$\"\r\n"},
		{"network/sample.cat", "fictional catalog"},
		{"network/x64/sample.sys", "fictional driver"},
	} ; // 安全な階層を持つ架空driver package。
	std::vector<std::byte> archive ;	// 生成したmemory ZIP。
	DRIVERCRATE_EXPECT( context, createZipFixture( ENTRIES, archive)) ;

	std::vector<OfficialZipEntry> inspected ;	// Preflightが返すfile一覧。
	DRIVERCRATE_EXPECT( context, inspectOfficialZip( archive, DEFAULT_POLICY, inspected) == 0) ;
	DRIVERCRATE_EXPECT( context, inspected.size() == 3) ;
	DRIVERCRATE_EXPECT( context, inspected[0].relativePath == L"network\\sample.inf") ;

	OfficialDownloadWorkspace workspace ;	// Scope終了時に展開fileを削除する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"zip-test", 1) == 0) ;
	DRIVERCRATE_EXPECT( context, workspace.path( L"..\\escape.inf").empty()) ;
	DRIVERCRATE_EXPECT( context, workspace.path( L"\\escape.inf").empty()) ;
	std::vector<OfficialZipEntry> extracted ;	// 全CRC検証後の展開file一覧。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialZip( archive, DEFAULT_POLICY, workspace, extracted) == 0) ;
	DRIVERCRATE_EXPECT( context, extracted.size() == inspected.size()) ;
	// 展開後の各fileに、入れ子archive識別で使用できるhashが確定される。
	for( const OfficialZipEntry &extractedEntry : extracted) {
		DRIVERCRATE_EXPECT( context, extractedEntry.sha256.size() == 64U) ;
	}

	const std::wstring sysPath =
		// 存在確認対象の絶対path。
		workspace.path( L"network\\x64\\sample.sys") ;
	WIN32_FILE_ATTRIBUTE_DATA attributes{} ;	// 展開済みSYS fixtureの属性。
	DRIVERCRATE_EXPECT( context, GetFileAttributesExW( sysPath.c_str(), GetFileExInfoStandard,
													 &attributes) != FALSE) ;
	DRIVERCRATE_EXPECT( context, attributes.nFileSizeLow == ENTRIES[2].content.size()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定directoryだけを選択して展開できることを検証する。
 *
 * ZIP全体を検証しつつ、選択外EXEと旧INFをfileとして作成せず現行driver subtreeだけを返すことを確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testSubdirectoryExtraction( TestContext &context)
{
	constexpr ZipFixtureEntry ENTRIES[]{
		{"bundle/current/driver.inf", "current inf"},
		{"bundle/current/driver.cat", "current catalog"},
		{"bundle/current/driver.sys", "current driver"},
		{"bundle/setup.exe", "unused executable"},
		{"bundle/legacy/driver.inf", "legacy inf"},
	} ; // 現行driverと選択外payloadを併せ持つ架空配布物。
	std::vector<std::byte> archive ;	// 生成したmemory ZIP。
	DRIVERCRATE_EXPECT( context, createZipFixture( ENTRIES, archive)) ;

	OfficialDownloadWorkspace workspace ;	// 選択fileだけを所有する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"zip-subdirectory-test", 1) == 0) ;
	std::vector<OfficialZipEntry> extracted ;	// 選択展開が返す現行driver file群。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialZipSubdirectory( archive, DEFAULT_POLICY, L"bundle\\current",
													  workspace, extracted) == 0) ;
	DRIVERCRATE_EXPECT( context, extracted.size() == 3) ;
	const std::wstring selectedPath =
		// 作成されるべき選択INF。
		workspace.path( L"bundle\\current\\driver.inf") ;
	const std::wstring executablePath =
		// 作成してはならない選択外EXE。
		workspace.path( L"bundle\\setup.exe") ;
	DRIVERCRATE_EXPECT( context,
					   GetFileAttributesW( selectedPath.c_str()) != INVALID_FILE_ATTRIBUTES) ;
	DRIVERCRATE_EXPECT( context,
					   GetFileAttributesW( executablePath.c_str()) == INVALID_FILE_ATTRIBUTES) ;

	OfficialDownloadWorkspace missingWorkspace ;	// 該当なしを検証する独立保護領域。
	DRIVERCRATE_EXPECT( context, missingWorkspace.initialize( L"zip-subdirectory-test", 2) == 0) ;
	std::vector<OfficialZipEntry> missing ;	// 失敗時に空であるべき選択結果。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialZipSubdirectory( archive, DEFAULT_POLICY, L"bundle\\absent",
													  missingWorkspace, missing) != 0) ;
	DRIVERCRATE_EXPECT( context, missing.empty()) ;

	OfficialDownloadWorkspace invalidWorkspace ;	// 不正policyを検証する独立保護領域。
	DRIVERCRATE_EXPECT( context, invalidWorkspace.initialize( L"zip-subdirectory-test", 3) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   extractOfficialZipSubdirectory( archive, DEFAULT_POLICY, L"bundle\\..",
													  invalidWorkspace, missing) != 0) ;
	DRIVERCRATE_EXPECT( context, missing.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定file集合だけを選択して展開できることを検証する。
 *
 * ZIP全体を検証しつつ、選択外scriptと別architecture SYSを作成せず、欠落、不正path、case違い重複を拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testSelectedFileExtraction( TestContext &context)
{
	constexpr ZipFixtureEntry ENTRIES[]{
		{"driver.inf", "current inf"},		{"driver.cat", "current catalog"},
		{"x64/driver.sys", "x64 driver"},	{"arm64/driver.sys", "arm64 driver"},
		{"configure.bat", "unused script"},
	} ; // 選択driverと除外対象を併せ持つ架空配布物。
	constexpr std::array   SELECTED_FILES{std::wstring_view( L"driver.inf"),
										  std::wstring_view( L"driver.cat"),
										  // 展開を許可する固定file群。
										  std::wstring_view( L"x64\\driver.sys")} ;
	std::vector<std::byte> archive ;	// 生成したmemory ZIP。
	DRIVERCRATE_EXPECT( context, createZipFixture( ENTRIES, archive)) ;

	OfficialDownloadWorkspace workspace ;	// 固定fileだけを所有する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"zip-file-selection-test", 1) == 0) ;
	std::vector<OfficialZipEntry> extracted ;	// 選択展開が返すfile群。
	DRIVERCRATE_EXPECT( context, extractOfficialZipFiles( archive, DEFAULT_POLICY, SELECTED_FILES,
														workspace, extracted) == 0) ;
	DRIVERCRATE_EXPECT( context, extracted.size() == SELECTED_FILES.size()) ;
	const std::wstring selectedPath = workspace.path( L"x64\\driver.sys") ;	// 作成されるべきx64 SYS。
	const std::wstring scriptPath =
		// 作成してはならない選択外script。
		workspace.path( L"configure.bat") ;
	DRIVERCRATE_EXPECT( context,
					   GetFileAttributesW( selectedPath.c_str()) != INVALID_FILE_ATTRIBUTES) ;
	DRIVERCRATE_EXPECT( context, GetFileAttributesW( scriptPath.c_str()) == INVALID_FILE_ATTRIBUTES) ;

	constexpr std::array	  MISSING{std::wstring_view( L"missing.inf")} ;	// 存在しない固定path。
	OfficialDownloadWorkspace missingWorkspace ;							// 欠落検証用の独立保護領域。
	DRIVERCRATE_EXPECT( context, missingWorkspace.initialize( L"zip-file-selection-test", 2) == 0) ;
	DRIVERCRATE_EXPECT( context, extractOfficialZipFiles( archive, DEFAULT_POLICY, MISSING,
														missingWorkspace, extracted) != 0) ;
	DRIVERCRATE_EXPECT( context, extracted.empty()) ;

	constexpr std::array	  DUPLICATE{std::wstring_view( L"driver.inf"),
									// Windows上で重複する固定path。
									std::wstring_view( L"DRIVER.INF")} ;
	OfficialDownloadWorkspace duplicateWorkspace ;	// 重複検証用の独立保護領域。
	DRIVERCRATE_EXPECT( context, duplicateWorkspace.initialize( L"zip-file-selection-test", 3) == 0) ;
	DRIVERCRATE_EXPECT( context, extractOfficialZipFiles( archive, DEFAULT_POLICY, DUPLICATE,
														duplicateWorkspace, extracted) != 0) ;
	DRIVERCRATE_EXPECT( context, extracted.empty()) ;

	constexpr std::array	  UNSAFE{std::wstring_view( L"..\\driver.inf")} ;	// Traversal path。
	OfficialDownloadWorkspace unsafeWorkspace ;									// 不正path検証用の独立保護領域。
	DRIVERCRATE_EXPECT( context, unsafeWorkspace.initialize( L"zip-file-selection-test", 4) == 0) ;
	DRIVERCRATE_EXPECT( context, extractOfficialZipFiles( archive, DEFAULT_POLICY, UNSAFE,
														unsafeWorkspace, extracted) != 0) ;
	DRIVERCRATE_EXPECT( context, extracted.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 危険なZIP entry名を拒否することを検証する。
 *
 * Traversal、absolute、ADS、case違い重複をfile作成前に拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testUnsafeZipPaths( TestContext &context)
{
	constexpr ZipFixtureEntry TRAVERSAL[]{{"../escape.inf", "x"}} ;				// 親directory逸脱名。
	constexpr ZipFixtureEntry ALTERNATE_STREAM[]{{"driver:evil.inf", "x"}} ;	// NTFS ADS名。
	constexpr ZipFixtureEntry DUPLICATE_CASE[]{
		{"driver/sample.inf", "a"},
		{"Driver/SAMPLE.inf", "b"},
	} ; // Windows上で同一になるcase違いentry群。
	const std::span<const ZipFixtureEntry> cases[]{TRAVERSAL, ALTERNATE_STREAM,
												   DUPLICATE_CASE} ;	// 拒否対象群。
	// 危険な各archiveを独立生成し、公開entryを残さないことを確認する。
	for( const std::span<const ZipFixtureEntry> entries : cases) {
		std::vector<std::byte> archive ;	// 現在caseのmemory ZIP。
		DRIVERCRATE_EXPECT( context, createZipFixture( entries, archive)) ;
		std::vector<OfficialZipEntry> inspected ;	// 失敗時に空であるべき結果。
		DRIVERCRATE_EXPECT( context, inspectOfficialZip( archive, DEFAULT_POLICY, inspected) != 0) ;
		DRIVERCRATE_EXPECT( context, inspected.empty()) ;
	}
}

/**
 * @brief Windows区切りの通常entryを受理し、正規化後の逸脱と衝突を拒否する。
 * @param[in,out] context Assertion集計先。
 * @note 架空ZIPだけを使用し、固定名の保護workspace以外へ展開しない。
 */
void testWindowsZipSeparators( TestContext &context)
{
	constexpr ZipFixtureEntry NORMAL[]{
		{"bundle\\x64\\sample.inf", "signed-placeholder"},
		{"bundle/x64/sample.sys", "binary-placeholder"},
		{"bundle\\empty\\", ""}} ;		// 同一directoryの非衝突fileと空directory。
	std::vector<std::byte> archive ;	// 再包装ではなく架空入力の生成先。
	DRIVERCRATE_EXPECT( context, createZipFixture( NORMAL, archive)) ;
	std::vector<OfficialZipEntry> inspected ;	// 正規化後の公開entry。
	DRIVERCRATE_EXPECT( context, inspectOfficialZip( archive, DEFAULT_POLICY, inspected) == 0) ;
	DRIVERCRATE_EXPECT( context, inspected.size() == 2U) ;
	// 正常な件数が確認できた場合だけ個別pathを参照する。
	if( inspected.size() == 2U) {
		DRIVERCRATE_EXPECT( context, inspected[0].relativePath == L"bundle\\x64\\sample.inf") ;
	}

	OfficialDownloadWorkspace workspace ;	// 既存directoryを再利用しない展開先。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"zip-separators", 32) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   extractOfficialZip( archive, DEFAULT_POLICY, workspace, inspected) == 0) ;
	DRIVERCRATE_EXPECT( context, inspected.size() == 2U) ;

	constexpr ZipFixtureEntry BACK_TRAVERSAL[]{{"bundle\\..\\escape.inf", "x"}} ;	// 親への逸脱。
	constexpr ZipFixtureEntry MIXED_TRAVERSAL[]{
		{"bundle/..\\escape.inf", "x"}} ;									// 混在区切りの逸脱。
	constexpr ZipFixtureEntry UNC[]{{"\\\\host\\share\\sample.inf", "x"}} ;	// UNCへの逸脱。
	constexpr ZipFixtureEntry DRIVE[]{{"C:\\sample.inf", "x"}} ;			// Drive絶対path。
	constexpr ZipFixtureEntry ADS[]{{"bundle\\sample.inf:stream", "x"}} ;	// NTFS別stream。
	constexpr ZipFixtureEntry EMPTY[]{{"bundle\\\\sample.inf", "x"}} ;		// 空path要素。
	constexpr ZipFixtureEntry RESERVED[]{{"bundle\\nul.inf", "x"}} ;		// Windows予約名。
	constexpr ZipFixtureEntry DUPLICATE[]{{"bundle\\sample.inf", "a"},
										  {"bundle/sample.inf", "b"}} ;	// 同一file。
	constexpr ZipFixtureEntry PARENT_FILE[]{{"bundle\\x64", "a"},
											{"bundle/x64/sample.inf", "b"}} ;	// 親file衝突。
	constexpr ZipFixtureEntry NONEMPTY_DIRECTORY[]{
		{"bundle\\hidden\\", "hidden-data"}} ;	// 名称だけでdataを無視させる入力。
	const std::span<const ZipFixtureEntry> cases[]{
		BACK_TRAVERSAL, MIXED_TRAVERSAL,   UNC, DRIVE, ADS, EMPTY, RESERVED, DUPLICATE,
		PARENT_FILE,	NONEMPTY_DIRECTORY} ;	// 正規化しても拒否する境界。
	// 全負例を別archiveで検査し、前の肯定結果が残らないことも確認する。
	for( const std::span<const ZipFixtureEntry> entries : cases) {
		DRIVERCRATE_EXPECT( context, createZipFixture( entries, archive)) ;
		DRIVERCRATE_EXPECT( context, inspectOfficialZip( archive, DEFAULT_POLICY, inspected) != 0) ;
		DRIVERCRATE_EXPECT( context, inspected.empty()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief ZIPの有限上限とCRC不一致を拒否することを検証する。
 *
 * Entry数、展開後総量、改ざん済み圧縮dataをfail-closedで拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testZipLimitsAndIntegrity( TestContext &context)
{
	constexpr ZipFixtureEntry ENTRIES[]{
		{"first.inf", "abc"},
		{"second.cat", "def"},
	} ; // 上限試験用の二file archive。
	std::vector<std::byte> archive ;	// 生成した正常memory ZIP。
	DRIVERCRATE_EXPECT( context, createZipFixture( ENTRIES, archive)) ;

	OfficialZipExtractionPolicy entryLimit = DEFAULT_POLICY ;	// Entry上限違反policy。
	entryLimit.maximumEntryCount		   = 1 ;
	std::vector<OfficialZipEntry> inspected ;	// 上限違反時に空であるべき結果。
	DRIVERCRATE_EXPECT( context, inspectOfficialZip( archive, entryLimit, inspected) != 0) ;

	OfficialZipExtractionPolicy sizeLimit = DEFAULT_POLICY ;	// 展開量上限違反policy。
	sizeLimit.maximumSingleFileBytes	  = 3 ;
	sizeLimit.maximumTotalExpandedBytes	  = 5 ;
	DRIVERCRATE_EXPECT( context, inspectOfficialZip( archive, sizeLimit, inspected) != 0) ;

	std::vector<std::byte> corrupted = archive ;	// 圧縮dataを一byte改ざんするfixture。
	// local headerの長さfieldを読める場合にだけ破損位置を計算する。
	if( corrupted.size() > 30) {
		const std::size_t nameLength =
			std::to_integer<std::uint8_t>( corrupted[26]) |
			(static_cast<std::size_t>( std::to_integer<std::uint8_t>( corrupted[27]))
			 << 8U) ;	// 最初のlocal headerが示すfile名byte数。
		const std::size_t extraLength =
			std::to_integer<std::uint8_t>( corrupted[28]) |
			(static_cast<std::size_t>( std::to_integer<std::uint8_t>( corrupted[29]))
			 << 8U) ;													// 最初のlocal headerが示すextra field byte数。
		const std::size_t dataOffset = 30 + nameLength + extraLength ;	// 圧縮data先頭。
		// 算出したdata位置がarchive内にある場合にだけ一bitを変更する。
		if( dataOffset < corrupted.size()) {
			corrupted[dataOffset] ^= std::byte{1} ;
		}
	}

	OfficialDownloadWorkspace workspace ;	// 部分fileもscope終了時に除去する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"zip-test", 2) == 0) ;
	std::vector<OfficialZipEntry> extracted ;	// 改ざん時に空であるべき展開結果。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialZip( corrupted, DEFAULT_POLICY, workspace, extracted) != 0) ;
	DRIVERCRATE_EXPECT( context, extracted.empty()) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_zip_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOfficialZipTests( TestContext &context)
{
	testValidOfficialZip( context) ;
	testSubdirectoryExtraction( context) ;
	testSelectedFileExtraction( context) ;
	testUnsafeZipPaths( context) ;
	testWindowsZipSeparators( context) ;
	testZipLimitsAndIntegrity( context) ;
}

} // namespace drivercrate::test
