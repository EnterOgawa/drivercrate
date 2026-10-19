//------------------------------------------------------------------------------
/**
 * @file official_msi_tests.cpp
 * @brief 公式MSI stream選択取得単体試験実装。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Read-only MSI stream試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 小さい架空MSIとbinary streamだけを作成し、network、実driver、MSI install、custom actionへ依存せず選択取得と失敗cleanupを検
 *       証します。
 */
//------------------------------------------------------------------------------

#include "official_msi_tests.h"

#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "platform/official_msi.h"
#include "test_framework.h"

#include <Msi.h>
#include <MsiQuery.h>
#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 試験data定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view STREAM_NAME	  = L"Data1.cab" ;			// WinOF-2で固定するstream名。
constexpr std::wstring_view DATABASE_NAME = L"fixture.msi" ;		// 架空MSIのworkspace相対path。
constexpr std::wstring_view SOURCE_NAME	  = L"fixture-source.bin" ;	// Stream元の相対path。
constexpr OfficialMsiStreamExtractionPolicy POLICY{2U * 1024U * 1024U, 1024U * 1024U,
												   4096U} ;	// 小さい架空MSI用の有限上限。
constexpr std::array<std::byte, 16>			STREAM_CONTENT{
	std::byte{0x4d}, std::byte{0x53}, std::byte{0x43}, std::byte{0x46},
	std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
	std::byte{0x10}, std::byte{0x11}, std::byte{0x12}, std::byte{0x13},
	std::byte{0x20}, std::byte{0x21}, std::byte{0x22}, std::byte{0x23}} ;	// 架空CAB内容。

/**
 * @brief 架空MSIと内包streamについて、workspace内の位置・長さ・hashを保持する。
 */
struct MsiFixture {
	/// Workspace内の架空MSI絶対path。
	std::wstring  databasePath ;
	/// Commit後の架空MSI byte数。
	std::uint64_t databaseSize{} ;
	/// Commit後の架空MSI SHA-256。
	std::wstring  databaseSha256 ;
	/// Stream元fileのSHA-256。
	std::wstring  streamSha256 ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Workspaceへ小さい試験fileを完全に書き込む。
 *
 * 失敗時は今回作成したfileを破棄し、部分fileを残さない。
 *
 * @param[in,out] workspace Fileを新規作成し所有する保護領域。
 * @param[in] relativePath 作成する安全な相対path。
 * @param[in] content 一回のWriteFileで保存可能な小さい試験data。
 * @param[out] absolutePath 成功時のworkspace内絶対path。
 * @return 作成、完全書込み、close、path取得に成功した場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool writeWorkspaceFile( OfficialDownloadWorkspace		  &workspace,
									  const std::wstring_view		   relativePath,
									  const std::span<const std::byte> content,
									  std::wstring					  &absolutePath)
{
	absolutePath.clear() ;
	// 空の内容とWin32書込み長を超える内容をfixtureへ保存しない。
	if( content.empty() || content.size() > std::numeric_limits<DWORD>::max()) {
		return false ;
	}

	HANDLE file{INVALID_HANDLE_VALUE} ;	// Workspaceが返す所有file handle。
	// 保護領域でfileを作成できなければ書込みを開始しない。
	if( workspace.createFile( relativePath, file) != 0) {
		return false ;
	}

	DWORD	   written{} ;	// WriteFileが保存したbyte数。
	const BOOL writeSucceeded =
		WriteFile( file, content.data(), static_cast<DWORD>( content.size()), &written,
				  nullptr) ;							// 試験dataの書込み結果。
	const BOOL closeSucceeded = CloseHandle( file) ;	// 以後のhash用に閉じた結果。
	// 書込み・長さ・closeのいずれかが不正なら今回のfileを破棄する。
	if( writeSucceeded == FALSE || written != static_cast<DWORD>( content.size()) ||
	   closeSucceeded == FALSE) {
		static_cast<void>( workspace.discardFile( relativePath)) ;
		return false ;
	}

	absolutePath = workspace.path( relativePath) ;
	// 保存後の確定pathを取得できなければfixtureを破棄する。
	if( absolutePath.empty()) {
		static_cast<void>( workspace.discardFile( relativePath)) ;
		return false ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空MSIへ一つのbinary streamを登録する。
 *
 * Windows Installer databaseを書込むのはtest setupだけとし、production取得APIはread-onlyのまま検証する。
 *
 * @param[in,out] workspace 元fileとMSIを所有する保護領域。
 * @param[out] fixture 成功時のMSI identityとstream hash。
 * @return MSI作成、stream登録、commit、identity取得成功時は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool createMsiFixture( OfficialDownloadWorkspace &workspace, MsiFixture &fixture)
{
	fixture = {} ;
	std::wstring sourcePath ;	// MsiRecordSetStreamWへ渡す架空binary絶対path。
	// stream元fileとhashを揃えられなければMSIを構築しない。
	if( !writeWorkspaceFile( workspace, SOURCE_NAME, STREAM_CONTENT, sourcePath) ||
	   computeFileSha256( sourcePath, fixture.streamSha256) != 0) {
		return false ;
	}

	std::wstring databasePath ;	// MsiOpenDatabaseWが新規作成する予約済みpath。
	// MSI出力先を保護領域に予約できなければdatabaseを作成しない。
	if( workspace.prepareExternalFile( DATABASE_NAME, databasePath) != 0) {
		return false ;
	}

	bool databaseSucceeded{} ;	// 全MSI database操作が成功した場合true。
	{
		PMSIHANDLE database ;	// Scope終了時に閉じる書込みtest database handle。
		UINT	   result =
			// 作成結果。
			MsiOpenDatabaseW( databasePath.c_str(), MSIDBOPEN_CREATE, &database) ;
		// database作成に成功した場合にだけstream登録用viewを操作する。
		if( result == ERROR_SUCCESS) {
			constexpr wchar_t STREAM_VIEW_QUERY[] =
				L"SELECT `Name`, `Data` FROM `_Streams`" ;	// Stream登録用の固定SELECT文。
			PMSIHANDLE view ;								// Stream追加用の所有view handle。
			result = MsiDatabaseOpenViewW( database, STREAM_VIEW_QUERY, &view) ;
			// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
			if( result == ERROR_SUCCESS) {
				result = MsiViewExecute( view, 0U) ;
			}

			PMSIHANDLE record( MsiCreateRecord( 2U)) ;	// NameとDataを持つ挿入record。
			// view処理成功とrecord取得の両方を満たしてからstreamを登録する。
			if( result == ERROR_SUCCESS && record != 0U) {
				const std::wstring streamName( STREAM_NAME) ;	// API用null終端stream名。
				result = MsiRecordSetStringW( record, 1U, streamName.c_str()) ;
				// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
				if( result == ERROR_SUCCESS) {
					result = MsiRecordSetStreamW( record, 2U, sourcePath.c_str()) ;
				}

				// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
				if( result == ERROR_SUCCESS) {
					result = MsiViewModify( view, MSIMODIFY_INSERT, record) ;
				}

				// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
				if( result == ERROR_SUCCESS) {
					result = MsiViewClose( view) ;
				}

				// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
				if( result == ERROR_SUCCESS) {
					result = MsiDatabaseCommit( database) ;
				}
			}
			// 先行処理の失敗がない場合はrecord未取得を確保失敗として残す。
			else if( result == ERROR_SUCCESS) {
				result = ERROR_OUTOFMEMORY ;
			}
		}

		databaseSucceeded = result == ERROR_SUCCESS ;
	}
	// database構築が失敗した場合は部分MSIを保持しない。
	if( !databaseSucceeded) {
		static_cast<void>( workspace.discardFile( DATABASE_NAME)) ;
		return false ;
	}

	WIN32_FILE_ATTRIBUTE_DATA attributes{} ;	// Commit済みMSIの属性と64-bit size。
	// 完成MSIの属性を確認できない場合はfixtureを破棄する。
	if( GetFileAttributesExW( databasePath.c_str(), GetFileExInfoStandard, &attributes) == FALSE) {
		static_cast<void>( workspace.discardFile( DATABASE_NAME)) ;
		return false ;
	}

	ULARGE_INTEGER size{} ;	// HighとLowを結合したMSI byte数。
	size.LowPart  = attributes.nFileSizeLow ;
	size.HighPart = attributes.nFileSizeHigh ;
	// 空またはworkspaceへ取込みできないMSIをfixtureとして返さない。
	if( size.QuadPart == 0U || workspace.adoptFile( DATABASE_NAME, size.QuadPart) != 0) {
		static_cast<void>( workspace.discardFile( DATABASE_NAME)) ;
		return false ;
	}

	fixture.databasePath = std::move( databasePath) ;
	fixture.databaseSize = size.QuadPart ;
	return computeFileSha256( fixture.databasePath, fixture.databaseSha256) == 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Workspace相対pathに通常fileが存在するか確認する。
 *
 * 失敗caseが部分出力を残していないことを確認する。
 *
 * @param[in] workspace Pathを所有する保護領域。
 * @param[in] relativePath 存在確認する安全な相対path。
 * @return Reparse pointではない通常fileが存在する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool workspaceFileExists( const OfficialDownloadWorkspace &workspace,
									   const std::wstring_view			relativePath)
{
	const std::wstring path = workspace.path( relativePath) ;	// 確認対象の絶対path。
	// 未設定のpathをfile存在確認へ渡さない。
	if( path.empty()) {
		return false ;
	}

	const DWORD attributes = GetFileAttributesW( path.c_str()) ;	// 現在のfile属性。
	return attributes != INVALID_FILE_ATTRIBUTES &&
		   (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正常MSIから固定streamを選択取得する。
 *
 * Stream名、size、SHA-256と保護workspace出力を確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testValidStreamExtraction( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 架空MSIと出力を所有する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"msi-test", 1U) == 0) ;
	MsiFixture fixture ;	// Read-only入力にする架空MSI identity。
	DRIVERCRATE_EXPECT( context, createMsiFixture( workspace, fixture)) ;
	const OfficialMsiStreamExtractionRequest request{fixture.databasePath, fixture.databaseSize,
													 fixture.databaseSha256, STREAM_NAME,
													 L"selected\\Data1.cab"} ;	// 正常取得要求。
	OfficialMsiStreamEntry					 entry ;							// 取得結果。
	DRIVERCRATE_EXPECT( context, extractOfficialMsiStream( request, POLICY, workspace, entry) == 0) ;
	DRIVERCRATE_EXPECT( context, entry.streamName == STREAM_NAME) ;
	DRIVERCRATE_EXPECT( context, entry.relativePath == L"selected\\Data1.cab") ;
	DRIVERCRATE_EXPECT( context, entry.streamSize == STREAM_CONTENT.size()) ;
	DRIVERCRATE_EXPECT( context, entry.sha256 == fixture.streamSha256) ;
	DRIVERCRATE_EXPECT( context, workspaceFileExists( workspace, entry.relativePath)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未知streamと容量超過を拒否する。
 *
 * 固定名以外とstream上限超過でfileを作らないことを確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testStreamSelectionRejection( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 二つの拒否出力を監視する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"msi-test", 2U) == 0) ;
	MsiFixture fixture ;	// 拒否試験で共有する架空MSI identity。
	DRIVERCRATE_EXPECT( context, createMsiFixture( workspace, fixture)) ;
	const OfficialMsiStreamExtractionRequest unknownRequest{
		fixture.databasePath, fixture.databaseSize, fixture.databaseSha256, L"Unknown.cab",
		L"unknown.cab"} ;												// 存在しないstream要求。
	OfficialMsiStreamEntry entry{L"stale", L"stale", 1U, L"stale"} ;	// 消去確認用結果。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialMsiStream( unknownRequest, POLICY, workspace, entry) != 0) ;
	DRIVERCRATE_EXPECT( context, entry.streamName.empty()) ;
	DRIVERCRATE_EXPECT( context, !workspaceFileExists( workspace, L"unknown.cab")) ;

	OfficialMsiStreamExtractionPolicy smallPolicy = POLICY ;	// Streamだけを不足させる上限。
	smallPolicy.maximumStreamBytes				  = STREAM_CONTENT.size() - 1U ;
	const OfficialMsiStreamExtractionRequest oversizedRequest{
		fixture.databasePath, fixture.databaseSize, fixture.databaseSha256, STREAM_NAME,
		L"oversized.cab"} ;	// 上限超過stream要求。
	DRIVERCRATE_EXPECT(
		context, extractOfficialMsiStream( oversizedRequest, smallPolicy, workspace, entry) != 0) ;
	DRIVERCRATE_EXPECT( context, !workspaceFileExists( workspace, L"oversized.cab")) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 入力identity差替えと既存出力を拒否する。
 *
 * 誤SHA-256をopen前に拒否し、CREATE_NEWで既存fileを守る。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testIdentityAndOutputRejection( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// Identityと上書き拒否用の保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"msi-test", 3U) == 0) ;
	MsiFixture fixture ;	// 拒否試験で共有する架空MSI identity。
	DRIVERCRATE_EXPECT( context, createMsiFixture( workspace, fixture)) ;
	constexpr std::wstring_view WRONG_SHA256 =
		L"0000000000000000000000000000000000000000000000000000000000000000" ;	// 不一致hash。
	const OfficialMsiStreamExtractionRequest changedRequest{
		fixture.databasePath, fixture.databaseSize, WRONG_SHA256, STREAM_NAME,
		L"changed.cab"} ;			// 誤identity要求。
	OfficialMsiStreamEntry entry ;	// 失敗時に空を維持する結果。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialMsiStream( changedRequest, POLICY, workspace, entry) != 0) ;
	DRIVERCRATE_EXPECT( context, !workspaceFileExists( workspace, L"changed.cab")) ;

	constexpr std::array<std::byte, 4> EXISTING_CONTENT{
		std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}} ;	// 既存file内容。
	std::wstring existingPath ;													// 上書き拒否前後にhashを取得する絶対path。
	DRIVERCRATE_EXPECT(
		context, writeWorkspaceFile( workspace, L"existing.cab", EXISTING_CONTENT, existingPath)) ;
	std::wstring hashBefore ;	// 取得処理前の既存file SHA-256。
	DRIVERCRATE_EXPECT( context, computeFileSha256( existingPath, hashBefore) == 0) ;
	const OfficialMsiStreamExtractionRequest existingRequest{
		fixture.databasePath, fixture.databaseSize, fixture.databaseSha256, STREAM_NAME,
		L"existing.cab"} ;	// 既存出力と衝突する要求。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialMsiStream( existingRequest, POLICY, workspace, entry) != 0) ;
	std::wstring hashAfter ;	// 拒否後の既存file SHA-256。
	DRIVERCRATE_EXPECT( context, computeFileSha256( existingPath, hashAfter) == 0) ;
	DRIVERCRATE_EXPECT( context, hashAfter == hashBefore) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_msi_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOfficialMsiTests( TestContext &context)
{
	testValidStreamExtraction( context) ;
	testStreamSelectionRejection( context) ;
	testIdentityAndOutputRejection( context) ;
}

} // namespace drivercrate::test
