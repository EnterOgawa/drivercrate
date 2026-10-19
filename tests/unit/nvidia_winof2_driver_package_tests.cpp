//------------------------------------------------------------------------------
/**
 * @file nvidia_winof2_driver_package_tests.cpp
 * @brief NVIDIA WinOF-2 MSI driver閉包単体試験実装。
 * @version 01.00.00
 * @date 2026/09/07
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  MSI／CAB閉包fixtureを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  取得元identityの保持試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note MakeCabで一度生成した小さい固定CABを架空MSIへ格納し、任意codeを実行せずFile mappingとdriver-only閉包を検証します。
 */
//------------------------------------------------------------------------------

#include "nvidia_winof2_driver_package_tests.h"

#include "platform/nvidia_winof2_driver_package.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "test_framework.h"

#include <Msi.h>
#include <MsiQuery.h>
#include <Wincrypt.h>
#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 試験data定義。
//------------------------------------------------------------------------------

// MakeCabで生成した4 entry、790 bytesの固定CAB。
constexpr std::string_view CABINET_BASE64 = "TVNDRgAAAAAWAwAAAAAAACwAAAAAAAAAAwEBAAQAAACnDgAAmAAAAA"
											"EAAAAhAgAAAAAAAAAAJ13AOiAAbWx4NS5pbmY1ABoA"
											"AAAhAgAAAAAnXbw4IABtbHg1LmNhdDUAGQAAADsCAAAAACddvDggAG"
											"1seDUuc3lzNQAiAAAAVAIAAAAAJ128OCAAc2V0dXAu"
											"ZXhlLmtleQBRH2FsdgJ2AltWZXJzaW9uXQpTaWduYXR1cmU9IiRXaW"
											"5kb3dzIE5UJCIKQ2xhc3M9TmV0CkNsYXNzR3VpZD17"
											"NGQzNmU5NzItZTMyNS0xMWNlLWJmYzEtMDgwMDJiZTEwMzE4fQpQcm"
											"92aWRlcj0lUHJvdmlkZXJOYW1lJQpEcml2ZXJWZXI9"
											"MDkvMDcvMjAyNiwyNi43LjEuMApDYXRhbG9nRmlsZT1tbHg1LmNhdA"
											"oKW01hbnVmYWN0dXJlcl0KJVByb3ZpZGVyTmFtZSU9"
											"TW9kZWxzLE5UYW1kNjQKCltNb2RlbHMuTlRhbWQ2NF0KJURldmljZU"
											"5hbWUlPUluc3RhbGwsUk9PVFxEUklWRVJDUkFURV9G"
											"QUtFCgpbU291cmNlRGlza3NOYW1lcy5hbWQ2NF0KMT0lRGlza05hbW"
											"UlLCwsCgpbU291cmNlRGlza3NGaWxlcy5hbWQ2NF0K"
											"bWx4NS5zeXM9MQoKW0luc3RhbGwuTlRdCkNvcHlGaWxlcz1Ecml2ZX"
											"JDb3B5CgpbRHJpdmVyQ29weV0KbWx4NS5zeXMKCltT"
											"dHJpbmdzXQpQcm92aWRlck5hbWU9Ik1lbGxhbm94IFRlY2hub2xvZ2"
											"llcyBMdGQuIgpEZXZpY2VOYW1lPSJGaWN0aW9uYWwg"
											"V2luT0YtMiBOZXR3b3JrIERldmljZSIKRGlza05hbWU9IkZpY3Rpb2"
											"5hbCBEcml2ZXIgRGlzayIKZmljdGlvbmFsIGNhdGFs"
											"b2cgY29udGVudApmaWN0aW9uYWwgZHJpdmVyIGNvbnRlbnQKZmljdG"
											"lvbmFsIG1peGVkIGluc3RhbGxlciBjb250ZW50Cg==" ;

constexpr std::wstring_view DATABASE_NAME = L"winof2-fixture.msi" ;	// 架空MSI相対path。
constexpr std::wstring_view CABINET_SOURCE_NAME =
	L"winof2-fixture.cab" ;										// MSI streamへ登録するCAB相対path。
constexpr std::uint64_t					  CABINET_SIZE = 790U ;	// Base64 fixtureの復号後byte数。
constexpr std::uint64_t					  INF_SIZE	   = 545U ;	// CAB内の架空INF byte数。
constexpr std::uint64_t					  CATALOG_SIZE = 26U ;	// CAB内の架空CAT byte数。
constexpr std::uint64_t					  DRIVER_SIZE  = 25U ;	// CAB内の架空SYS byte数。
constexpr std::uint64_t					  SETUP_SIZE   = 34U ;	// CAB内の選択外EXE byte数。

constexpr NvidiaWinof2DriverClosurePolicy POLICY{
	.msiStreamPolicy	 = {2U * 1024U * 1024U, 1024U * 1024U, 4096U},
	.msiInventoryPolicy	 = {2U * 1024U * 1024U, 1024U * 1024U, 16U},
	.cabPolicy			 = {1024U * 1024U, 1024U * 1024U, 2U * 1024U * 1024U, 16U},
	.maximumHardwareIds	 = 16U,
	.maximumSourceFiles	 = 16U,
	.maximumClosureFiles = 8U,
	.maximumClosureBytes = 1024U * 1024U,
	.copyBufferBytes	 = 4096U,
} ; // 小さい架空WinOF-2 packageへ適用する有限上限。

/**
 * @brief 架空MSIのFile tableとCAB entryを、名前・展開長・順序で結び付ける。
 */
struct FileRowFixture {
	/// CAB entryと一致させるFile primary key。
	std::wstring_view cabinetName ;
	/// INFが参照するFileName long name。
	std::wstring_view targetName ;
	/// FileSizeへ登録する展開後byte数。
	std::uint64_t	  size{} ;
	/// CAB順と一致させるFile.Sequence。
	std::uint32_t	  sequence{} ;
} ;

/**
 * @brief 保護workspace内に作成した架空WinOF-2 MSIの位置と確定内容情報を保持する。
 */
struct Winof2Fixture {
	/// Workspace内の架空MSI絶対path。
	std::wstring  databasePath ;
	/// Commit後の架空MSI byte数。
	std::uint64_t databaseSize{} ;
	/// Commit後の架空MSI SHA-256。
	std::wstring  databaseSha256 ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Test source内の固定dataだけをWindows標準decoderへ渡す。
 *
 * @param[out] cabinet 成功時の固定CAB byte列。
 * @return 厳格Base64復号と期待size一致時は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool decodeCabinet( std::vector<unsigned char> &cabinet)
{
	cabinet.clear() ;
	// 固定base64 fixtureがWin32入力長を超える場合はdecodeしない。
	if( CABINET_BASE64.size() > std::numeric_limits<DWORD>::max()) {
		return false ;
	}

	DWORD required{} ;	// Base64復号後の必要byte数。
	// strict decodeに必要な長さが固定CABサイズと一致しなければ拒否する。
	if( CryptStringToBinaryA( CABINET_BASE64.data(), static_cast<DWORD>( CABINET_BASE64.size()),
							CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, nullptr, &required, nullptr,
							nullptr) == FALSE ||
	   static_cast<std::uint64_t>( required) != CABINET_SIZE) {
		return false ;
	}

	cabinet.resize( required) ;
	DWORD written = required ;	// 二回目呼出しの容量と実復号byte数。
	return CryptStringToBinaryA( CABINET_BASE64.data(), static_cast<DWORD>( CABINET_BASE64.size()),
								CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, cabinet.data(), &written,
								nullptr, nullptr) != FALSE &&
		   written == required ;
}

//------------------------------------------------------------------------------
/**
 * @brief 失敗時は今回作成したfileだけを破棄する。
 *
 * @param[in,out] workspace Fileを新規作成し所有する保護領域。
 * @param[in] relativePath 作成する安全な相対path。
 * @param[in] content 一回のWriteFileで保存可能な小さい試験data。
 * @param[out] absolutePath 成功時のworkspace内絶対path。
 * @return 作成、完全書込み、close、path取得成功時は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool writeWorkspaceFile( OfficialDownloadWorkspace			  &workspace,
									  const std::wstring_view			   relativePath,
									  const std::span<const unsigned char> content,
									  std::wstring						  &absolutePath)
{
	absolutePath.clear() ;
	// 空またはWin32書込み長を超える内容をfixtureへ保存しない。
	if( content.empty() || content.size() > std::numeric_limits<DWORD>::max()) {
		return false ;
	}

	HANDLE file{INVALID_HANDLE_VALUE} ;	// Workspaceが返す所有file handle。
	// 保護領域内にfileを作成できない場合は書込みを開始しない。
	if( workspace.createFile( relativePath, file) != 0) {
		return false ;
	}

	DWORD	   written{} ;	// WriteFileが保存したbyte数。
	const BOOL writeSucceeded =
		WriteFile( file, content.data(), static_cast<DWORD>( content.size()), &written,
				  nullptr) ;							// 試験dataの書込み結果。
	const BOOL closeSucceeded = CloseHandle( file) ;	// HashまたはMSI登録前のclose結果。
	// 書込み・長さ・closeのいずれかが不正なら今回のfixture fileを破棄する。
	if( writeSucceeded == FALSE || written != static_cast<DWORD>( content.size()) ||
	   closeSucceeded == FALSE) {
		static_cast<void>( workspace.discardFile( relativePath)) ;
		return false ;
	}

	absolutePath = workspace.path( relativePath) ;
	// 保存fileの確定pathを取得できない場合は今回のfileを破棄する。
	if( absolutePath.empty()) {
		static_cast<void>( workspace.discardFile( relativePath)) ;
		return false ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空fixtureのMedia／File table作成だけに使用する。
 *
 * @param[in] database Test setup用の書込みdatabase handle。
 * @param[in] sql 固定CREATE TABLE文。
 * @return View作成、実行、closeの最初のWindows Installer結果。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UINT executeSql( const MSIHANDLE database, const wchar_t *const sql)
{
	PMSIHANDLE view ;													// 固定DDLを所有するview handle。
	UINT	   result = MsiDatabaseOpenViewW( database, sql, &view) ;	// View作成結果。
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiViewExecute( view, 0U) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiViewClose( view) ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief Productionと異なり、test fixture生成時だけdatabaseへ書く。
 *
 * @param[in] database Test setup用の書込みdatabase handle。
 * @param[in] sourcePath 固定CABを保持するlocal絶対path。
 * @return `_Streams`への一件登録とview close結果。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UINT insertCabinetStream( const MSIHANDLE database, const std::wstring_view sourcePath)
{
	constexpr wchar_t QUERY[] = L"SELECT `Name`, `Data` FROM `_Streams`" ;		// 固定SELECT文。
	PMSIHANDLE		  view ;													// Stream挿入用の所有view handle。
	UINT			  result = MsiDatabaseOpenViewW( database, QUERY, &view) ;	// View作成結果。
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiViewExecute( view, 0U) ;
	}

	PMSIHANDLE		   record( MsiCreateRecord( 2U)) ;	// NameとDataを持つ挿入record。
	const std::wstring source( sourcePath) ;			// API用null終端CAB path。
	// 先行処理成功後にrecordを作成できなかった場合は確保失敗として返す。
	if( result == ERROR_SUCCESS && record == 0U) {
		result = ERROR_OUTOFMEMORY ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiRecordSetStringW( record, 1U, L"Data1.cab") ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiRecordSetStreamW( record, 2U, source.c_str()) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiViewModify( view, MSIMODIFY_INSERT, record) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiViewClose( view) ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief Sequence 1～4を一つのembedded Data1.cabへ拘束する。
 *
 * @param[in] database Test setup用の書込みdatabase handle。
 * @return Media row一件の登録とview close結果。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UINT insertMediaRow( const MSIHANDLE database)
{
	constexpr wchar_t QUERY[] =
		L"SELECT `DiskId`, `LastSequence`, `DiskPrompt`, `Cabinet`, `VolumeLabel`, `Source` "
		L"FROM `Media`" ;												// Media挿入用の固定SELECT文。
	PMSIHANDLE view ;													// Media row挿入用の所有view handle。
	UINT	   result = MsiDatabaseOpenViewW( database, QUERY, &view) ;	// View作成結果。
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiViewExecute( view, 0U) ;
	}

	PMSIHANDLE record( MsiCreateRecord( 6U)) ;	// Media全columnを持つ挿入record。
	// 先行処理成功後にMSI recordを作成できなかった場合は確保失敗とする。
	if( result == ERROR_SUCCESS && record == 0U) {
		result = ERROR_OUTOFMEMORY ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiRecordSetInteger( record, 1U, 1) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiRecordSetInteger( record, 2U, 4) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiRecordSetStringW( record, 4U, L"#Data1.cab") ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiViewModify( view, MSIMODIFY_INSERT, record) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiViewClose( view) ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief CAB entry順とMSI File.Sequenceを決定的に一致させる。
 *
 * @param[in] database Test setup用の書込みdatabase handle。
 * @param[in] fixture CAB primary key、論理名、size、sequence。
 * @return File row一件の登録とview close結果。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UINT insertFileRow( const MSIHANDLE database, const FileRowFixture &fixture)
{
	constexpr wchar_t QUERY[] =
		L"SELECT `File`, `Component_`, `FileName`, `FileSize`, `Version`, `Language`, "
		L"`Attributes`, `Sequence` FROM `File`" ;	// File挿入用の固定SELECT文。
	// MSIの整数fieldに収まらないfileサイズとsequenceはfixtureへ記録しない。
	if( fixture.size > static_cast<std::uint64_t>( std::numeric_limits<int>::max()) ||
	   fixture.sequence > static_cast<std::uint32_t>( std::numeric_limits<int>::max())) {
		return ERROR_INVALID_PARAMETER ;
	}

	PMSIHANDLE view ;													// File row挿入用の所有view handle。
	UINT	   result = MsiDatabaseOpenViewW( database, QUERY, &view) ;	// View作成結果。
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiViewExecute( view, 0U) ;
	}

	PMSIHANDLE		   record( MsiCreateRecord( 8U)) ;		// File全columnを持つ挿入record。
	const std::wstring cabinetName( fixture.cabinetName) ;	// API用null終端primary key。
	const std::wstring targetName( fixture.targetName) ;	// API用null終端FileName。
	// 先行処理成功後にfile用recordを作成できなかった場合は確保失敗とする。
	if( result == ERROR_SUCCESS && record == 0U) {
		result = ERROR_OUTOFMEMORY ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiRecordSetStringW( record, 1U, cabinetName.c_str()) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiRecordSetStringW( record, 2U, L"component") ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiRecordSetStringW( record, 3U, targetName.c_str()) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiRecordSetInteger( record, 4U, static_cast<int>( fixture.size)) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiRecordSetInteger( record, 7U, 16384) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiRecordSetInteger( record, 8U, static_cast<int>( fixture.sequence)) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiViewModify( view, MSIMODIFY_INSERT, record) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( result == ERROR_SUCCESS) {
		result = MsiViewClose( view) ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 書込みMSI APIはtest setupだけで使い、productionはread-only。
 *
 * @param[in,out] workspace CABとMSIを所有する保護領域。
 * @param[in] mismatchedSize trueならSYSのFileSizeを一byte増やす。
 * @param[in] duplicateTarget trueならEXEをmlx5.sysへ重複対応する。
 * @param[out] fixture 成功時のMSI絶対path、size、SHA-256。
 * @return CAB復号、MSI table構築、stream登録、identity取得成功時true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool createWinof2Fixture( OfficialDownloadWorkspace &workspace,
									   const bool mismatchedSize, const bool duplicateTarget,
									   Winof2Fixture &fixture)
{
	fixture = {} ;
	std::vector<unsigned char> cabinet ;	// Base64から復号した固定CAB byte列。
	// 固定CABをdecodeできない場合はMSI fixtureの構築を始めない。
	if( !decodeCabinet( cabinet)) {
		return false ;
	}

	std::wstring cabinetPath ;	// MSI stream登録に使うCAB絶対path。
	// CABを保護領域へ保存できない場合は参照先のないMSIを作らない。
	if( !writeWorkspaceFile( workspace, CABINET_SOURCE_NAME, cabinet, cabinetPath)) {
		return false ;
	}

	std::wstring databasePath ;	// MsiOpenDatabaseWが新規作成する予約済みpath。
	// MSI出力先を準備できない場合はdatabaseを作成しない。
	if( workspace.prepareExternalFile( DATABASE_NAME, databasePath) != 0) {
		return false ;
	}

	constexpr wchar_t CREATE_MEDIA[] =
		L"CREATE TABLE `Media` (`DiskId` SHORT NOT NULL, `LastSequence` SHORT NOT NULL, "
		L"`DiskPrompt` CHAR(64) LOCALIZABLE, `Cabinet` CHAR(255), `VolumeLabel` CHAR(32), "
		L"`Source` CHAR(72) PRIMARY KEY `DiskId`)" ;	// 標準Media列の試験table。
	constexpr wchar_t CREATE_FILE[] =
		L"CREATE TABLE `File` (`File` CHAR(72) NOT NULL, `Component_` CHAR(72) NOT NULL, "
		L"`FileName` CHAR(255) NOT NULL LOCALIZABLE, `FileSize` LONG NOT NULL, "
		L"`Version` CHAR(72), `Language` CHAR(20), `Attributes` SHORT, "
		L"`Sequence` SHORT NOT NULL PRIMARY KEY `File`)" ;	// 標準File列の試験table。
	const std::array fileRows{
		FileRowFixture{L"mlx5.inf5", L"mlx5.inf", INF_SIZE, 1U},
		FileRowFixture{L"mlx5.cat5", L"mlx5.cat", CATALOG_SIZE, 2U},
		FileRowFixture{L"mlx5.sys5", L"mlx5.sys", DRIVER_SIZE + (mismatchedSize ? 1U : 0U), 3U},
		FileRowFixture{L"setup.exe.key", duplicateTarget ? L"mlx5.sys" : L"setup.exe", SETUP_SIZE,
					   4U},
	} ; // CAB格納順と一致するFile mapping群。
	bool databaseSucceeded{} ;	// 全MSI database操作が成功した場合true。
	{
		PMSIHANDLE database ;	// Scope終了時に閉じる書込みtest database handle。
		UINT	   result =
			// 作成結果。
			MsiOpenDatabaseW( databasePath.c_str(), MSIDBOPEN_CREATE, &database) ;
		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( result == ERROR_SUCCESS) {
			result = executeSql( database, CREATE_MEDIA) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( result == ERROR_SUCCESS) {
			result = executeSql( database, CREATE_FILE) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( result == ERROR_SUCCESS) {
			result = insertCabinetStream( database, cabinetPath) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( result == ERROR_SUCCESS) {
			result = insertMediaRow( database) ;
		}

		// 全File rowをCAB格納順に登録し、一件の失敗で後続登録を止める。
		for( const FileRowFixture &row : fileRows) {
			// file行の登録に失敗した時点で後続の登録を止める。
			if( result != ERROR_SUCCESS) {
				break ;
			}

			result = insertFileRow( database, row) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( result == ERROR_SUCCESS) {
			result = MsiDatabaseCommit( database) ;
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
	// 空のMSIまたは保護領域へ取り込めないMSIをfixtureとして返さない。
	if( size.QuadPart == 0U || workspace.adoptFile( DATABASE_NAME, size.QuadPart) != 0) {
		static_cast<void>( workspace.discardFile( DATABASE_NAME)) ;
		return false ;
	}

	fixture.databasePath = std::move( databasePath) ;
	fixture.databaseSize = size.QuadPart ;
	// 完成MSIのhashを確定できない場合はfileと結果情報を破棄する。
	if( computeFileSha256( fixture.databasePath, fixture.databaseSha256) != 0) {
		static_cast<void>( workspace.discardFile( DATABASE_NAME)) ;
		fixture = {} ;
		return false ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Mixed file除外と失敗時cleanupを確認する。
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
 * @brief 4 entryを照合し、INF／CAT／SYSだけを論理名で保持する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testValidDriverClosure( TestContext &context)
{
	OfficialDownloadWorkspace input ;	// 架空MSIと元CABを所有する保護領域。
	DRIVERCRATE_EXPECT( context, input.initialize( L"winof2-test", 41U) == 0) ;
	Winof2Fixture fixture ;	// 正常なMedia／File mappingを持つMSI identity。
	DRIVERCRATE_EXPECT( context, createWinof2Fixture( input, false, false, fixture)) ;
	const NvidiaWinof2DriverClosureRequest request{
		fixture.databasePath, fixture.databaseSize,	   fixture.databaseSha256, 41U, 1U,
		L"mlx5.inf",		  L"winof2-closure-output"} ;	// 正常な一INF閉包要求。
	OfficialDownloadWorkspace output ;						// 成功閉包を所有する保護領域。
	NvidiaWinof2DriverClosure driverData ;					// CAB照合件数と選択閉包結果。
	DRIVERCRATE_EXPECT( context,
					   extractNvidiaWinof2DriverClosure( request, POLICY, output, driverData) == 0) ;
	DRIVERCRATE_EXPECT( context, driverData.cabinetFileCount == 4U) ;
	DRIVERCRATE_EXPECT( context, driverData.scanSessionId == 41U) ;
	DRIVERCRATE_EXPECT( context, driverData.sourceAcquisitionId == 1U) ;
	DRIVERCRATE_EXPECT( context, driverData.databaseSize == fixture.databaseSize) ;
	DRIVERCRATE_EXPECT( context, driverData.databaseSha256 == fixture.databaseSha256) ;
	DRIVERCRATE_EXPECT( context, driverData.selectedInfPath == L"mlx5.inf") ;
	DRIVERCRATE_EXPECT( context, driverData.closure.entries.size() == 3U) ;
	DRIVERCRATE_EXPECT( context, driverData.closure.packages.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, driverData.closure.packages.front().infRelativePath == L"mlx5.inf") ;
	DRIVERCRATE_EXPECT( context, workspaceFileExists( output, L"mlx5.inf")) ;
	DRIVERCRATE_EXPECT( context, workspaceFileExists( output, L"mlx5.cat")) ;
	DRIVERCRATE_EXPECT( context, workspaceFileExists( output, L"mlx5.sys")) ;
	DRIVERCRATE_EXPECT( context, !workspaceFileExists( output, L"setup.exe")) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 6系列以外を表示名から推測して展開しないことを確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testUnknownInfRejection( TestContext &context)
{
	OfficialDownloadWorkspace input ;	// 未知INF要求用の架空MSI所有領域。
	DRIVERCRATE_EXPECT( context, input.initialize( L"winof2-test", 42U) == 0) ;
	Winof2Fixture fixture ;	// 正常MSI identity。
	DRIVERCRATE_EXPECT( context, createWinof2Fixture( input, false, false, fixture)) ;
	const NvidiaWinof2DriverClosureRequest request{
		fixture.databasePath, fixture.databaseSize,	   fixture.databaseSha256, 42U, 2U,
		L"unknown.inf",		  L"winof2-unknown-output"} ;	// 許可6系列に含まれない要求。
	OfficialDownloadWorkspace output ;						// 拒否時に未初期化のままの領域。
	NvidiaWinof2DriverClosure driverData ;					// 拒否時に空であるべき結果。
	DRIVERCRATE_EXPECT( context,
					   extractNvidiaWinof2DriverClosure( request, POLICY, output, driverData) != 0) ;
	DRIVERCRATE_EXPECT( context, driverData.closure.entries.empty()) ;
	DRIVERCRATE_EXPECT( context, output.path( L"mlx5.inf").empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定sizeと異なる要求ではCABまたは出力を作成しない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testDatabaseIdentityRejection( TestContext &context)
{
	OfficialDownloadWorkspace input ;	// Identity不一致要求用の架空MSI所有領域。
	DRIVERCRATE_EXPECT( context, input.initialize( L"winof2-test", 45U) == 0) ;
	Winof2Fixture fixture ;	// 正常MSI identity。
	DRIVERCRATE_EXPECT( context, createWinof2Fixture( input, false, false, fixture)) ;
	const NvidiaWinof2DriverClosureRequest request{
		fixture.databasePath, fixture.databaseSize + 1U, fixture.databaseSha256, 45U, 3U,
		L"mlx5.inf",		  L"winof2-identity-output"} ;	// Sizeだけ差し替えた不正要求。
	OfficialDownloadWorkspace output ;						// 拒否時に未初期化のままの領域。
	NvidiaWinof2DriverClosure driverData ;					// 拒否時に空であるべき結果。
	DRIVERCRATE_EXPECT( context,
					   extractNvidiaWinof2DriverClosure( request, POLICY, output, driverData) != 0) ;
	DRIVERCRATE_EXPECT( context, driverData.closure.entries.empty()) ;
	DRIVERCRATE_EXPECT( context, output.path( L"mlx5.inf").empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief FileSize差と同一論理名への二重mappingをfail-closedにする。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testMappingRejection( TestContext &context)
{
	OfficialDownloadWorkspace sizeInput ;	// FileSize不一致MSIの所有領域。
	DRIVERCRATE_EXPECT( context, sizeInput.initialize( L"winof2-test", 43U) == 0) ;
	Winof2Fixture sizeFixture ;	// SYS sizeだけCABと異なるMSI identity。
	DRIVERCRATE_EXPECT( context, createWinof2Fixture( sizeInput, true, false, sizeFixture)) ;
	const NvidiaWinof2DriverClosureRequest sizeRequest{
		sizeFixture.databasePath,
		sizeFixture.databaseSize,
		sizeFixture.databaseSha256,
		43U,
		4U,
		L"mlx5.inf",
		L"winof2-size-output"} ;				// CABとのsize不一致要求。
	OfficialDownloadWorkspace sizeOutput ;		// 拒否時の出力領域。
	NvidiaWinof2DriverClosure sizeDriverData ;	// 拒否時に空であるべき結果。
	DRIVERCRATE_EXPECT( context, extractNvidiaWinof2DriverClosure( sizeRequest, POLICY, sizeOutput,
																 sizeDriverData) != 0) ;
	DRIVERCRATE_EXPECT( context, sizeDriverData.closure.entries.empty()) ;

	OfficialDownloadWorkspace duplicateInput ;	// 論理名重複MSIの所有領域。
	DRIVERCRATE_EXPECT( context, duplicateInput.initialize( L"winof2-test", 44U) == 0) ;
	Winof2Fixture duplicateFixture ;	// EXEをSYSと同名にしたMSI identity。
	DRIVERCRATE_EXPECT( context, createWinof2Fixture( duplicateInput, false, true, duplicateFixture)) ;
	const NvidiaWinof2DriverClosureRequest duplicateRequest{
		duplicateFixture.databasePath,
		duplicateFixture.databaseSize,
		duplicateFixture.databaseSha256,
		44U,
		5U,
		L"mlx5.inf",
		L"winof2-duplicate-output"} ;				// 曖昧な参照file mapping要求。
	OfficialDownloadWorkspace duplicateOutput ;		// 拒否時の出力領域。
	NvidiaWinof2DriverClosure duplicateDriverData ;	// 拒否時に空であるべき結果。
	DRIVERCRATE_EXPECT( context,
					   extractNvidiaWinof2DriverClosure( duplicateRequest, POLICY, duplicateOutput,
														duplicateDriverData) != 0) ;
	DRIVERCRATE_EXPECT( context, duplicateDriverData.closure.entries.empty()) ;
	DRIVERCRATE_EXPECT( context, !workspaceFileExists( duplicateOutput, L"mlx5.inf")) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/nvidia_winof2_driver_package_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runNvidiaWinof2DriverPackageTests( TestContext &context)
{
	testValidDriverClosure( context) ;
	testUnknownInfRejection( context) ;
	testDatabaseIdentityRejection( context) ;
	testMappingRejection( context) ;
}

} // namespace drivercrate::test
