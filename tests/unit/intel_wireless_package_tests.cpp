//------------------------------------------------------------------------------
/**
 * @file intel_wireless_package_tests.cpp
 * @brief Intel Wireless利用者指定ZIP検証単体試験実装。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Networkや実driverを使用せず、拡張子、ZIP構造、CAT署名をfail-closedで拒否することを検証します。Fixture pathと内容は試験終了時に削除します。
 */
//------------------------------------------------------------------------------

#include "intel_wireless_package_tests.h"

#include "platform/intel_wireless_package.h"
#include "platform/official_download_workspace.h"
#include "test_framework.h"

#include <Windows.h>
#include <miniz.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
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
 * @brief Intel package監査用の架空ZIPへ格納する名前と内容を指定する。
 */
struct ZipFixtureEntry {
	/// ZIPへ格納するASCII相対path。
	std::string_view path ;
	/// ZIPへ格納する架空byte列。
	std::string_view content ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 架空entry群からmemory ZIPを生成する。
 *
 * Miniz writerをtest process内だけで使用し、fileを作らない。
 *
 * @param[in] entries ZIPへ追加する架空entry群。
 * @param[out] archive 成功時のZIP全byte列。
 * @return 完成したZIPをmemoryへ生成できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool createZipFixture( const std::span<const ZipFixtureEntry> entries,
									std::vector<std::byte>				  &archive)
{
	archive.clear() ;
	// 試験用archiveには少なくとも一件のentryを要求する。
	if( entries.empty()) {
		return false ;
	}

	mz_zip_archive writer{} ;	// 終了処理が必要なMiniz writer状態。
	mz_zip_zero_struct( &writer) ;
	// ZIP writerを初期化できない場合はfixture生成を開始しない。
	if( mz_zip_writer_init_heap( &writer, 0, 0) == 0) {
		return false ;
	}

	// 指定順を維持して全entryをarchiveへ追加する。
	for( const ZipFixtureEntry &entry : entries) {
		const std::string path( entry.path) ;	// Miniz呼出し中にNUL終端を保証するpath。
		// entry追加に失敗した場合はwriterを終了し、部分archiveを返さない。
		if( mz_zip_writer_add_mem( &writer, path.c_str(), entry.content.data(), entry.content.size(),
								 MZ_BEST_COMPRESSION) == 0) {
			mz_zip_writer_end( &writer) ;
			return false ;
		}
	}

	void	   *bytes{} ;	// Miniz allocatorが所有する完成ZIPの先頭。
	std::size_t size{} ;	// 完成ZIPのbyte数。
	// 空または未確定のarchiveを拒否し、writerの資源を解放する。
	if( mz_zip_writer_finalize_heap_archive( &writer, &bytes, &size) == 0 || bytes == nullptr ||
	   size == 0) {
		mz_zip_writer_end( &writer) ;
		return false ;
	}

	try {
		const auto *beginning = static_cast<const std::byte *>( bytes) ;	// 完成ZIP先頭。
		archive.assign( beginning, beginning + size) ;
	} catch( ...) {
		// Miniz allocationを確実に回収してからallocation例外をtest harnessへ戻す。
		mz_free( bytes) ;
		mz_zip_writer_end( &writer) ;
		throw ;
	}

	mz_free( bytes) ;
	return mz_zip_writer_end( &writer) != 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保護workspaceへ一つの架空fileを書き込む。
 *
 * HandleをRAIIで閉じ、共有なし検査の前に書込みを完了する。
 *
 * @param[in,out] workspace Fileを所有して試験終了時に削除する領域。
 * @param[in] name Workspace内の安全な相対path。
 * @param[in] bytes 書き込む架空data。
 * @return 全byteを書き込み、handleを閉じられた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool writeFixtureFile( OfficialDownloadWorkspace		&workspace,
									const std::wstring_view			 name,
									const std::span<const std::byte> bytes)
{
	// 空の内容とWin32書込み長に収まらない内容をfixtureとして保存しない。
	if( bytes.empty() || bytes.size() > std::numeric_limits<DWORD>::max()) {
		return false ;
	}

	HANDLE rawHandle{} ;	// createFile成功後にRAIIへ移すfile handle。
	// 保護領域で有効なfile handleを得られなければ書込みへ進まない。
	if( workspace.createFile( name, rawHandle) != 0 || rawHandle == nullptr ||
	   rawHandle == INVALID_HANDLE_VALUE) {
		return false ;
	}

	const auto closeHandle = []( void *value) noexcept {
		// 有効なfile handleだけを所有権の終了時に解放する。
		if( value != nullptr && value != INVALID_HANDLE_VALUE) {
			static_cast<void>( CloseHandle( value)) ;
		}
	} ; // Scope終了時に所有file handleを閉じるdeleter。
	std::unique_ptr<void, decltype( closeHandle)> handle( rawHandle,
														closeHandle) ;	// 所有handle。
	DWORD										 written{} ;			// WriteFileが実際に書き込んだbyte数。
	const DWORD requested = static_cast<DWORD>( bytes.size()) ;			// 検証済み書込みbyte数。
	const bool	succeeded =
		WriteFile( handle.get(), bytes.data(), requested, &written, nullptr) != FALSE &&
		// 全byte書込みが完了した場合だけtrue。
		written == requested ;
	handle.reset() ;
	return succeeded ;
}

//------------------------------------------------------------------------------
/**
 * @brief 利用者指定fileの拡張子とZIP構造拒否を検証する。
 *
 * ZIP以外の拡張子とZIPでないbyte列を保護領域へ複製せず拒否し、結果metadataを空のまま維持することを確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testInputAndArchiveRejection( TestContext &context)
{
	OfficialDownloadWorkspace source ;	// 架空入力fileを所有する保護領域。
	DRIVERCRATE_EXPECT( context, source.initialize( L"intel-package-test", 7101) == 0) ;
	constexpr std::string_view INVALID_ARCHIVE = "not a zip archive" ;				// 架空入力data。
	const std::span invalidBytes = std::as_bytes( std::span( INVALID_ARCHIVE)) ;	// Byte view。
	DRIVERCRATE_EXPECT( context, writeFixtureFile( source, L"driver.txt", invalidBytes)) ;
	DRIVERCRATE_EXPECT( context, writeFixtureFile( source, L"driver.zip", invalidBytes)) ;

	OfficialDownloadWorkspace	 extensionTarget ;		// 拡張子拒否側の出力領域。
	IntelWirelessPackageContents extensionContents ;	// 拡張子拒否側の結果。
	DRIVERCRATE_EXPECT( context,
					   inspectIntelWirelessPackageFile( source.path( L"driver.txt"), 7102,
													   extensionTarget, extensionContents) != 0) ;
	DRIVERCRATE_EXPECT( context, extensionContents.entries.empty()) ;
	DRIVERCRATE_EXPECT( context, extensionContents.packages.empty()) ;

	OfficialDownloadWorkspace	 archiveTarget ;	// ZIP構造拒否側の出力領域。
	IntelWirelessPackageContents archiveContents ;	// ZIP構造拒否側の結果。
	DRIVERCRATE_EXPECT( context,
					   inspectIntelWirelessPackageFile( source.path( L"driver.zip"), 7103,
													   archiveTarget, archiveContents) != 0) ;
	DRIVERCRATE_EXPECT( context, archiveContents.entries.empty()) ;
	DRIVERCRATE_EXPECT( context, archiveContents.packages.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未署名Intel形式packageを拒否することを検証する。
 *
 * Net class、Intel Provider、x64 modelを装ったINFでも、信頼済みCAT署名がなければ候補metadataを返さないことを確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testUnsignedPackageRejection( TestContext &context)
{
	constexpr ZipFixtureEntry ENTRIES[]{
		{"wireless/netwtw99.inf",
		 "[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=Net\r\n"
		 "ClassGuid={4d36e972-e325-11ce-bfc1-08002be10318}\r\nProvider=Intel\r\n"
		 "CatalogFile=netwtw99.cat\r\nDriverVer=09/03/2026,1.2.3.4\r\n"
		 "[Manufacturer]\r\nIntel=Models,NTamd64.10.0\r\n"
		 "[Models.NTamd64.10.0]\r\nDevice=Install,PCI\\VEN_0001&DEV_0002\r\n"
		 "[Install]\r\nCopyFiles=DriverFiles\r\n[DriverFiles]\r\nnetwtw99.sys\r\n"
		 "[DestinationDirs]\r\nDriverFiles=12\r\n"
		 "[SourceDisksFiles]\r\nnetwtw99.sys=1\r\n"
		 "[SourceDisksNames]\r\n1=\"Fictional media\"\r\n"},
		{"wireless/netwtw99.cat", "fictional unsigned catalog"},
		{"wireless/netwtw99.sys", "fictional driver bytes"},
	} ; // 署名以外の主要構造を持つ架空package。
	std::vector<std::byte> archive ;	// 生成した架空ZIP全byte列。
	DRIVERCRATE_EXPECT( context, createZipFixture( ENTRIES, archive)) ;

	OfficialDownloadWorkspace source ;	// 架空入力ZIPを所有する保護領域。
	DRIVERCRATE_EXPECT( context, source.initialize( L"intel-package-test", 7201) == 0) ;
	DRIVERCRATE_EXPECT( context, writeFixtureFile( source, L"wireless.zip", archive)) ;

	OfficialDownloadWorkspace	 target ;	// Production検証が展開する別保護領域。
	IntelWirelessPackageContents contents ;	// 失敗時に空であるべき結果。
	DRIVERCRATE_EXPECT( context, inspectIntelWirelessPackageFile( source.path( L"wireless.zip"), 7202,
																target, contents) != 0) ;
	DRIVERCRATE_EXPECT( context, contents.archiveSha256.empty()) ;
	DRIVERCRATE_EXPECT( context, contents.entries.empty()) ;
	DRIVERCRATE_EXPECT( context, contents.packages.empty()) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/intel_wireless_package_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runIntelWirelessPackageTests( TestContext &context)
{
	testInputAndArchiveRejection( context) ;
	testUnsignedPackageRejection( context) ;
}

} // namespace drivercrate::test
