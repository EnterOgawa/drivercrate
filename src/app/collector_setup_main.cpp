//------------------------------------------------------------------------------
/**
 * @file collector_setup_main.cpp
 * @brief 非昇格collectorの配置・検査・解除と現行workspace操作を振り分けます。
 * @version 01.14.00
 * @date 2026/10/26
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/30  非通信の手動セットアップとデータ保持解除を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/03  研究台帳・索引の同梱検査と保持copyを追加。
 * Ver.01.01.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.02.00 Shunji Ogawa  2026/10/16 研究snapshot v4と固定CPythonの明示v3配置を追加。
 * Ver.01.02.01 Shunji Ogawa  2026/10/16 長path取得を有限化し属性照会失敗とreparse拒否を区別。
 * Ver.01.03.00 Shunji Ogawa  2026/10/16 v4保護配置と明示非通信workspace操作を接続。
 * Ver.01.04.00 Shunji Ogawa  2026/10/17 v5と明示一回monitor同意を閉集合へ追加。
 * Ver.01.04.01 Shunji Ogawa  2026/10/17 v4非通信とv5明示runのdispatch説明を実装へ合わせる。
 * Ver.01.05.00 Shunji Ogawa  2026/10/17 非通信の原点選択と生きたnative admissionへ接続。
 * Ver.01.06.00 Shunji Ogawa  2026/10/20 v6閉包と導入済み固定ローカル索引入口を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/10/21 所有Taskの解除確認を管理file削除前へ接続。
 * Ver.01.08.00 Shunji Ogawa  2026/10/23 v6の現在user Task自動登録・同一版修復・解除を接続。
 * Ver.01.09.00 Shunji Ogawa  2026/10/23 配布検査の個別同意と非通信origin初期化を振分け。
 * Ver.01.10.00 Shunji Ogawa  2026/10/23 v7のdata閉包・importと別所有日次Taskを接続。
 * Ver.01.10.01 Shunji Ogawa  2026/10/24 現行仕様へ限定し旧版専用の入口・移動を整理。
 * Ver.01.11.00 Shunji Ogawa  2026/10/25 原workspace hashをreviewした非通信package切替を追加。
 * Ver.01.12.00 Shunji Ogawa  2026/10/26 明示停止申告付き一host reviewを非通信操作へ追加。
 * Ver.01.13.00 Shunji Ogawa  2026/10/26 未署名候補stagingを明示停止付き非通信操作へ追加。
 * Ver.01.14.00 Shunji Ogawa  2026/10/26 既知参考索引の完全集合を初期seedへ接続。
 * </pre>
 *
 * @note SHA-256は破損検知です。同じuserからの隔離・署名認証を保証しません。
 *       明示runは実原点・native lease付きの非共有PAGEへ限定し、実収集成功は未確認です。
 * @see docs/adr/0222-collector-setup-preview.md
 * @see docs/adr/0230-seeded-collector-setup-package.md
 * @see docs/adr/0353-collector-registry-runtime-package.md
 * @see docs/adr/0354-collector-setup-long-path-diagnostics.md
 */
//------------------------------------------------------------------------------

#include "platform/official_file_verifier.h"
#include "platform/collector_setup_workspace.h"
#include "platform/collector_user_task.h"
#include "drivercrate_version.h"

#include <Windows.h>
#include <ShlObj.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#include <array>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

/**
 * @brief JSON objectをWinRT参照で保持する。Copyは同じobjectを共有し、schema検証は利用側で行う。
 */
using JsonObject = winrt::Windows::Data::Json::JsonObject ;
/**
 * @brief JSON値をWinRT参照で保持する。所有byteの検証と型判定はreader側で行う。
 */
using JsonValue = winrt::Windows::Data::Json::JsonValue ;
namespace fs	= std::filesystem ;

// manifestに載せられるfile名を固定し、入力から削除対象を組み立てない。
constexpr std::array<std::wstring_view, 11> PAYLOAD_FILES{
	L"bin/DriverCrateCollector.exe",
	L"DriverCrateCollectorSetup.exe",
	L"config/targets.json",
	L"docs/adr/0209-local-first-recurring-driver-collector.md",
	L"LICENSE",
	L"THIRD_PARTY_NOTICES.md",
	L"README-collector.md",
	L"Install.cmd",
	L"Validate.cmd",
	L"Collect.cmd",
	L"Uninstall.cmd"} ;
// 研究seedの固定相対名。解除時の削除集合には追加しない。
constexpr std::array<std::wstring_view, 7> SEED_FILES{
	L"seed/collector-data/manifest.json",		  L"seed/collector-data/observations.json",
	L"seed/collector-data/payload-evidence.json", L"seed/collector-data/products.json",
	L"seed/collector-data/records.json",		  L"seed/collector-data/sources.json",
	L"seed/collector-data/index/drivers.json"} ;
// 現行snapshotの内側manifestをlocatorを含む固定7fileへ結合する。
constexpr std::array<std::wstring_view, 7> REGISTRY_RESEARCH_FILES{
	L"index/drivers.json", L"locators.json", L"observations.json", L"payload-evidence.json",
	L"products.json",	   L"records.json",	 L"sources.json"} ;
// 日次開始へ接続しない既存Python moduleの静的閉包。
constexpr std::array<std::wstring_view, 10> REGISTRY_MODULE_FILES{
	L"scripts/registry_daily_monitor.py",	 L"scripts/collector_locator_snapshot.py",
	L"scripts/collector_public_locators.py", L"scripts/collector_registry.py",
	L"scripts/registry_locator_requests.py", L"scripts/registry_monitor_http.py",
	L"scripts/registry_page_requests.py",	 L"scripts/collector_payload_evidence.py",
	L"scripts/collector_page_encoding.py",	 L"scripts/collector_published_hrefs.py"} ;
// 公式CPython 3.13.16 x64 embeddableの全file。入力JSONから実行対象を作らない。
constexpr std::array<std::wstring_view, 34> RUNTIME_FILES{
	L"runtime/LICENSE.txt",		L"runtime/_asyncio.pyd",	 L"runtime/_bz2.pyd",
	L"runtime/_ctypes.pyd",		L"runtime/_decimal.pyd",	 L"runtime/_elementtree.pyd",
	L"runtime/_hashlib.pyd",	L"runtime/_lzma.pyd",		 L"runtime/_multiprocessing.pyd",
	L"runtime/_overlapped.pyd", L"runtime/_queue.pyd",		 L"runtime/_socket.pyd",
	L"runtime/_sqlite3.pyd",	L"runtime/_ssl.pyd",		 L"runtime/_uuid.pyd",
	L"runtime/_wmi.pyd",		L"runtime/_zoneinfo.pyd",	 L"runtime/libcrypto-3.dll",
	L"runtime/libffi-8.dll",	L"runtime/libssl-3.dll",	 L"runtime/pyexpat.pyd",
	L"runtime/python.cat",		L"runtime/python.exe",		 L"runtime/python3.dll",
	L"runtime/python313._pth",	L"runtime/python313.dll",	 L"runtime/python313.zip",
	L"runtime/pythonw.exe",		L"runtime/select.pyd",		 L"runtime/sqlite3.dll",
	L"runtime/unicodedata.pyd", L"runtime/vcruntime140.dll", L"runtime/vcruntime140_1.dll",
	L"runtime/winsound.pyd"} ;
// runtime metadataもcompile時に固定し、外側manifestの書換えだけでは変更できない。
constexpr std::wstring_view RUNTIME_METADATA_HASH =
	L"00691561b72690d21156e5777ddc9fec9226353fd3b816e614894f9c6503942e" ;
// native resourceの解除確認文字列ID。
constexpr UINT UNINSTALL_CONFIRM = 102U ;
// native resourceのdialog見出しID。
constexpr UINT SETUP_TITLE = 103U ;
// native resourceの完了案内ID。
constexpr UINT SETUP_DONE = 104U ;
// 初期研究索引を通信・導入許可と区別する確認文。
constexpr UINT SEED_NOTICE = 105U ;
// 解除が完了しなかった場合の次操作案内。
constexpr UINT UNINSTALL_FAILED = 106U ;
// 現行配置と将来metadata通信への一回同意。
constexpr UINT USER_TASK_CONFIRM = 107U ;
// 登録途中の失敗と同じ導入先での安全な修復案内。
constexpr UINT INSTALL_FAILED = 108U ;
// 有効Taskの読戻しを完了した現行導入案内。
constexpr UINT USER_TASK_DONE = 109U ;

/** @brief 不成立の最初の有限stageを例外へ固定します。
 * @param[in] condition 成立が必要な条件。
 * @param[in] stage 個人情報を含まない固定診断名。
 * @throws std::runtime_error 条件不成立。
 */
void		   require( const bool condition, const char *stage)
{
	// 成功を推測せず最初の拒否を返す。
	if( !condition) {
		throw std::runtime_error( stage) ;
	}
}

/** @brief 自己EXEの親を有限長で取得します。
 * @return 正規化した絶対directory。
 * @throws std::runtime_error path取得拒否。
 */
fs::path packageRoot()
{
	std::vector<wchar_t> buffer( 32768U) ;	// 長い自己EXE pathも扱う有限WCHAR容量。
	const DWORD			 count =
		// 実文字数。
		GetModuleFileNameW( nullptr, buffer.data(), static_cast<DWORD>( buffer.size())) ;
	// 失敗と切詰めを区別せず受理することを避け、元errorを他APIより前に保存する。
	if( count == 0U || count >= buffer.size()) {
		const DWORD error = GetLastError() ;	// module path照会直後の元Win32 error。
		std::printf( "SETUP_PATH_DIAGNOSTIC stage=MODULE_PATH win32=%lu\n",
					static_cast<unsigned long>( error)) ;
		require( false, "MODULE_PATH") ;
	}

	return fs::path( buffer.data()).parent_path() ;
}

/** @brief 実行userの標準導入先を返します。
 * @return LocalAppData直下の専用workspace。
 * @throws winrt::hresult_error known folder照会失敗。
 */
fs::path defaultDirectory()
{
	PWSTR		  text{} ;	// OSが確保しCoTaskMemFreeで回収するpath。
	const HRESULT result =
		// 元API結果。
		SHGetKnownFolderPath( FOLDERID_LocalAppData, 0U, nullptr, &text) ;
	const std::unique_ptr<wchar_t, decltype( &CoTaskMemFree)> owner(
		text, &CoTaskMemFree) ;	// 例外時もOS確保領域を回収する。
	winrt::check_hresult( result) ;
	require( owner != nullptr, "DEFAULT_DIRECTORY") ;
	const fs::path base( owner.get()) ;	// RAII領域の生存中に所有pathへコピーする。
	return base / L"DriverCrate" / L"Collector" ;
}

/** @brief 固定driveと全祖先の非reparseを検査します。
 * @param[in] path 絶対directory候補。
 * @param[in] existing trueなら実在directoryを必須とする。
 * @return 正規化した同じdriveのpath。
 * @throws std::runtime_error path／drive／祖先拒否。
 */
fs::path checkedDirectory( const fs::path &path, const bool existing)
{
	const fs::path root = path.lexically_normal() ;	// reparseを解決しない字句正規形。
	require( path.is_absolute() && path.root_name().native().size() == 2U &&
				path.native().find( L':', 2U) == std::wstring::npos && root != root.root_path(),
			"DIRECTORY_PATH") ;
	// 元入力に含まれる相対componentを拒否する。
	for( const auto &component : path) {
		require( component != L".." && component != L".", "DIRECTORY_COMPONENT") ;
	}

	require( GetDriveTypeW( root.root_path().c_str()) == DRIVE_FIXED, "FIXED_DRIVE") ;
	fs::path probe = root ;	// 全祖先を順に検査するcursor。
	// 既存祖先を全て確認し、junctionを字句pathとして採用しない。
	while( !probe.empty()) {
		const DWORD attributes = GetFileAttributesW( probe.c_str()) ;	// 現在の属性。
		// 存在した祖先は通常directoryでなければ拒否する。
		if( attributes != INVALID_FILE_ATTRIBUTES) {
			require( (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0U &&
						(attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0U,
					"DIRECTORY_REPARSE") ;
		} else {
			const DWORD error = GetLastError() ;	// 欠損以外を隠さない元error。
			require( error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND,
					"DIRECTORY_ACCESS") ;
		}

		const fs::path parent = probe.parent_path() ;	// 次の祖先。
		// drive rootで有限に終了する。
		if( parent == probe) {
			break ;
		}

		probe = parent ;
	}

	require( !existing || fs::is_directory( root), "DIRECTORY_MISSING") ;
	return root ;
}

/** @brief 通常fileと有限sizeを検査します。
 * @param[in] path 読み取る固定file。
 * @param[in] maximum 許可する最大byte数。
 * @return 実byte数。
 * @throws std::runtime_error 属性／容量拒否。
 */
std::uintmax_t checkedFile( const fs::path &path, const std::uintmax_t maximum)
{
	const DWORD attributes = GetFileAttributesW( path.c_str()) ;	// 実file属性。
	require( attributes != INVALID_FILE_ATTRIBUTES &&
				(attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0U,
			"FILE_ATTRIBUTES") ;
	const auto bytes = fs::file_size( path) ;	// 実byte数。
	require( bytes <= maximum, "FILE_LIMIT") ;
	return bytes ;
}

/** @brief 固定fileのSHA-256を共通CNG処理で再計算します。
 * @param[in] path 有限の通常file。
 * @return 小文字64桁のSHA-256。
 * @throws std::runtime_error hash拒否。
 */
std::wstring hashFile( const fs::path &path)
{
	std::wstring digest ;	// 共通CNGの所有出力。
	require( drivercrate::computeFileSha256( path.native(), digest) == 0U, "FILE_HASH") ;
	return digest ;
}

/** @brief 有限UTF-8 objectをOSのJSON parserで読みます。
 * @param[in] path 通常JSON file。
 * @param[in] maximum 最大byte数。通常manifestは256 KiB、研究seedは16 MiB。
 * @return 所有JSON object。
 * @throws std::runtime_error I/O／容量拒否。
 * @throws winrt::hresult_error UTF-8／JSON拒否。
 */
JsonObject readObject( const fs::path &path, const std::uintmax_t maximum = 262144U)
{
	const auto	  size = checkedFile( path, maximum) ;				// JSON専用容量。
	std::string	  bytes( static_cast<std::size_t>( size), '\0') ;	// 実byte所有buffer。
	std::ifstream file( path, std::ios::binary) ;					// scope終了で閉じるreader。
	require( file.is_open() &&
				static_cast<bool>( file.read( bytes.data(), static_cast<std::streamsize>( size))),
			"JSON_READ") ;
	return JsonObject::Parse( winrt::to_hstring( bytes)) ;
}

/** @brief 明示package版に応じた固定copy集合を返します。
 * @param[in] includesReference 既知参考6fileの完全集合を含める場合だけtrue。
 * @return 所有vector。入力manifestのpathは採用しません。
 */
std::vector<std::wstring_view> payloadFiles( const bool includesReference = false)
{
	std::vector<std::wstring_view> files( PAYLOAD_FILES.begin(),
										 // 固定集合の所有copy。
										 PAYLOAD_FILES.end()) ;
	files.insert( files.end(), SEED_FILES.begin(), SEED_FILES.end()) ;
	files.emplace_back( L"seed/collector-data/locators.json") ;
	files.insert( files.end(), REGISTRY_MODULE_FILES.begin(), REGISTRY_MODULE_FILES.end()) ;
	files.emplace_back( L"runtime/python-runtime-manifest.json") ;
	files.insert( files.end(), RUNTIME_FILES.begin(), RUNTIME_FILES.end()) ;
	files.insert(
		files.end(),
		{L"scripts/collector_workspace.py", L"config/monitor-policy.json", L"Initialize.cmd",
		 L"Import.cmd", L"Export.cmd", L"scripts/collector_collection_profiles.py",
		 L"scripts/collector_distribution_pipeline.py", L"scripts/collector_distribution_data.py",
		 L"seed/distribution-data/manifest.json", L"seed/distribution-data/registry.json",
		 L"seed/distribution-data/locators.json",
		 L"seed/distribution-data/collection-profiles.json",
		 L"seed/distribution-data/research-index.json"}) ;

	// 参考ありの現行dataだけに固定六memberを追加し、未知pathを導入しません。
	if( includesReference) {
		files.insert( files.end(), {L"seed/distribution-data/reference.json",
								   L"seed/distribution-data/references/build-report.json",
								   L"seed/distribution-data/references/index.json",
								   L"seed/distribution-data/references/index.json.gz",
								   L"seed/distribution-data/references/manifest.raw.json",
								   L"seed/distribution-data/references/provenance.json"}) ;
	}

	return files ;
}

/** @brief manifest指紋の小文字SHA-256形式を検査します。
 * @param[in] value 所有元が呼出期間中生存する文字列。
 * @return 小文字hex64桁だけtrue。
 */
bool isSha256( const std::wstring_view value)
{
	// lambdaは借用中の一文字を検査し、外部状態をcaptureしない。
	return value.size() == 64U &&
		   std::all_of( value.begin(), value.end(), []( const wchar_t character) {
			   return (character >= L'0' && character <= L'9') ||
					  (character >= L'a' && character <= L'f') ;
		   }) ;
}

/** @brief 研究seedのbyte結合・schema・導入不可の境界を検査します。
 * @param[in] directory inventory検査済みpackageまたはworkspace。
 * @throws std::exception hash、schema、参照または研究境界の拒否。
 * @note 配置用検査であり、全台帳意味検証・観測者認証・通信許可を発行しません。
 */
void checkResearchSeed( const fs::path &directory)
{
	const fs::path	 root	  = directory / L"seed/collector-data" ;			// 固定の研究data root。
	const JsonObject manifest = readObject( root / L"manifest.json") ;			// 内側manifest。
	const auto		 revision = manifest.GetNamedString( L"revision") ;			// 配布台帳の世代。
	const auto		 asOf	  = manifest.GetNamedString( L"asOf") ;				// 配布台帳の確認日時。
	const auto registryHash	  = manifest.GetNamedString( L"registrySha256") ;	// 台帳正規byteの指紋。
	require( manifest.Size() == 8U &&
				manifest.GetNamedString( L"schema") == L"dc-portable-research-snapshot-v4" &&
				!revision.empty() && revision.size() <= 80U && asOf.size() == 20U &&
				isSha256( std::wstring_view( registryHash.c_str(), registryHash.size())),
			"SEED_SCHEMA") ;
	// v4を別schemaへ読み替えず、台帳v2と証拠・locatorの明示同梱を要求する。
	require( manifest.GetNamedString( L"registrySchema") == L"dc-public-driver-registry-v2" &&
				manifest.GetNamedBoolean( L"includesPayloadEvidence") &&
				manifest.GetNamedBoolean( L"includesPublicLocators"),
			"SEED_REGISTRY_SCHEMA") ;

	const auto	rows  = manifest.GetNamedArray( L"files") ;	// 内側の版別閉集合。
	const auto &files = REGISTRY_RESEARCH_FILES ;			// 現行の固定集合です。
	require( rows.Size() == files.size(), "SEED_COUNT") ;
	// 固定順序の全fileを容量とhashへ結合する。
	for( std::size_t index = 0U; index < files.size(); ++index) {
		const JsonObject row =
			// 現在のfile宣言。
			rows.GetAt( static_cast<std::uint32_t>( index)).GetObject() ;
		const double   bytes = row.GetNamedNumber( L"bytes") ;	// 有限整数byte数。
		const fs::path path	 = root / files[index] ;			// 固定集合からの読取り先。
		require( row.Size() == 3U && row.GetNamedString( L"path") == files[index] &&
					std::isfinite( bytes) && bytes >= 0.0 && bytes <= 16777216.0 &&
					std::floor( bytes) == bytes &&
					checkedFile( path, 16777216U) == static_cast<std::uintmax_t>( bytes) &&
					row.GetNamedString( L"sha256") == hashFile( path),
				"SEED_HASH") ;
	}

	std::array<JsonObject, 4>
		collections{} ;	// sources、products、records、observationsの所有object。
	constexpr std::array<std::wstring_view, 4> names{L"sources", L"products", L"records",
													 L"observations"} ;	// 既知collection名。
	// 全collectionのschema・世代・時刻を元manifestへ結合する。
	for( std::size_t index = 0U; index < names.size(); ++index) {
		const std::wstring name( names[index]) ;	// 現在の固定collection名。
		collections[index]	 = readObject( root / (name + L".json"), 16777216U) ;
		const auto &document = collections[index] ;	// 呼出scope内だけ借用するcollection。
		require( document.Size() == 4U &&
					document.GetNamedString( L"schema") == L"dc-public-driver-" + name + L"-v2" &&
					document.GetNamedString( L"revision") == revision &&
					document.GetNamedString( L"asOf") == asOf,
				"SEED_COLLECTION") ;
		static_cast<void>( document.GetNamedArray( L"items")) ;
	}

	const JsonObject index =
		// 導入許可のない研究索引。
		readObject( root / L"index/drivers.json", 16777216U) ;
	const JsonObject evidence =
		// Driver本体を含まない取得証拠。
		readObject( root / L"payload-evidence.json", 16777216U) ;
	require( index.Size() == 13U &&
				index.GetNamedString( L"schema") == L"dc-local-research-index-v3" &&
				index.GetNamedString( L"revision") == revision &&
				index.GetNamedBoolean( L"researchOnly") && !index.GetNamedBoolean( L"publishable") &&
				!index.GetNamedBoolean( L"installAuthorized") &&
				index.GetNamedString( L"applicability") == L"NOT_CHECKED" && evidence.Size() == 7U &&
				evidence.GetNamedString( L"schema") == L"dc-public-payload-evidence-v2" &&
				evidence.GetNamedString( L"registryRevision") == revision &&
				evidence.GetNamedString( L"registrySha256") == registryHash &&
				index.GetNamedString( L"asOf") == evidence.GetNamedString( L"asOf"),
			"SEED_RESEARCH_BOUNDARY") ;
	// locatorの公開研究境界と元台帳指紋を配置用に結合する。全意味検証は既存Pythonへ委ねる。
	const JsonObject locators =
		// 公開locator集合。
		readObject( root / L"locators.json", 16777216U) ;
	const JsonObject binding = locators.GetNamedObject( L"registry") ;	// 元台帳の公開指紋。
	require( index.GetNamedString( L"registrySchema") == L"dc-public-driver-registry-v2" &&
				locators.Size() == 8U &&
				locators.GetNamedString( L"schema") == L"dc-public-driver-locators-v2" &&
				locators.GetNamedBoolean( L"researchOnly") &&
				!locators.GetNamedBoolean( L"publishable") &&
				!locators.GetNamedBoolean( L"installAuthorized") && binding.Size() == 4U &&
				binding.GetNamedString( L"schema") == L"dc-public-driver-registry-v2" &&
				binding.GetNamedString( L"revision") == revision &&
				binding.GetNamedString( L"asOf") == asOf &&
				binding.GetNamedString( L"sha256") == registryHash,
			"SEED_LOCATOR_BINDING") ;
	static_cast<void>( locators.GetNamedArray( L"locators")) ;

	const auto products		  = collections[1].GetNamedArray( L"items") ;	// 元台帳の公開製品。
	const auto records		  = collections[2].GetNamedArray( L"items") ;	// 元の配布record。
	const auto indexedRecords = index.GetNamedArray( L"records") ;			// 検査状態を注釈したrecord。
	const auto counts = index.GetNamedObject( L"counts") ;					// 製品・record・実機実測を分けた件数。
	require( index.GetNamedArray( L"sources").Stringify() ==
					collections[0].GetNamedArray( L"items").Stringify() &&
				index.GetNamedArray( L"products").Stringify() == products.Stringify() &&
				indexedRecords.Size() == records.Size() &&
				counts.GetNamedNumber( L"targetProducts") == products.Size() &&
				counts.GetNamedNumber( L"distributionRecords") == records.Size() &&
				counts.GetNamedNumber( L"deviceApplicabilityMeasured") == 0.0 &&
				index.GetNamedObject( L"payloadEvidence").Stringify() == evidence.Stringify(),
			"SEED_INDEX_BINDING") ;
	// 内容検査で状態が変わったrecordも元の順序・identityを維持する。
	for( std::uint32_t recordIndex = 0U; recordIndex < records.Size(); ++recordIndex) {
		require( records.GetAt( recordIndex).GetObject().GetNamedString( L"id") ==
					indexedRecords.GetAt( recordIndex).GetObject().GetNamedString( L"id"),
				"SEED_RECORD_BINDING") ;
	}
}

/** @brief 配布EXEのPE32+とx64を確認します。
 * @param[in] path 配布するEXE。
 * @throws std::runtime_error PE／architecture拒否。
 */
void checkPe( const fs::path &path)
{
	const auto	  size = checkedFile( path, 67108864U) ;	// EXE上限64 MiB。
	std::ifstream file( path, std::ios::binary) ;			// 固定fileのreader。
	std::uint16_t magic{} ;									// DOS／optional header magic。
	std::uint32_t offset{} ;								// PE位置。
	std::uint32_t signature{} ;								// PE signature。
	std::uint16_t machine{} ;								// machine field。
	// Windows x64のlittle-endian固定整数objectへ、char readerから同じbyte数だけ読み込む。
	file.read( reinterpret_cast<char *>( &magic), sizeof( magic)) ;
	file.seekg( 0x3c) ;
	file.read( reinterpret_cast<char *>( &offset), sizeof( offset)) ;
	require( magic == 0x5a4dU && size >= 128U && offset >= 64U && offset <= 1048576U &&
				static_cast<std::uintmax_t>( offset) + 26U <= size,
			"PE_HEADER") ;
	file.seekg( offset) ;
	file.read( reinterpret_cast<char *>( &signature), sizeof( signature)) ;
	file.read( reinterpret_cast<char *>( &machine), sizeof( machine)) ;
	file.seekg( static_cast<std::streamoff>( offset) + 24) ;
	file.read( reinterpret_cast<char *>( &magic), sizeof( magic)) ;
	require( static_cast<bool>( file) && signature == 0x4550U && machine == 0x8664U &&
				magic == 0x20bU,
			"PE_X64") ;
}

/** @brief 固定CPython metadataへ全runtime byteを結合します。
 * @param[in] directory inventory検査済みのpackageまたはworkspace。
 * @throws std::exception 固定metadata、file、hashまたはx64の拒否。
 * @note Python・module・任意commandは起動しません。原配布の全fileを要求します。
 */
void checkRuntime( const fs::path &directory)
{
	const fs::path metadataPath =
		directory / L"runtime/python-runtime-manifest.json" ;	// 固定metadata。
	require( hashFile( metadataPath) == RUNTIME_METADATA_HASH, "RUNTIME_METADATA_HASH") ;
	const JsonObject metadata = readObject( metadataPath) ;			// 固定hashで確認した記述。
	const auto		 rows	  = metadata.GetNamedArray( L"files") ;	// 全34原fileの固定順序。
	require( metadata.Size() == 7U &&
				metadata.GetNamedString( L"schema") == L"dc-cpython-runtime-v1" &&
				metadata.GetNamedString( L"version") == L"3.13.16" &&
				metadata.GetNamedString( L"architecture") == L"x64" &&
				rows.Size() == RUNTIME_FILES.size(),
			"RUNTIME_SCHEMA") ;
	// 固定名と指紋を全件照合し、原配布の部分除去や追加を認めない。
	for( std::size_t index = 0U; index < RUNTIME_FILES.size(); ++index) {
		const std::wstring_view relative = RUNTIME_FILES[index] ;	// compile時の固定相対名。
		const fs::path			path	 = directory / relative ;	// 入力から組み立てない検査先。
		const JsonObject		row =
			// 固定順序の行。
			rows.GetAt( static_cast<std::uint32_t>( index)).GetObject() ;
		const double bytes = row.GetNamedNumber( L"bytes") ;	// 16 MiB以下の原file長。
		require( row.Size() == 3U && row.GetNamedString( L"path") == relative.substr( 8U) &&
					std::isfinite( bytes) && bytes >= 0.0 && bytes <= 16777216.0 &&
					std::floor( bytes) == bytes &&
					checkedFile( path, 16777216U) == static_cast<std::uintmax_t>( bytes) &&
					row.GetNamedString( L"sha256") == hashFile( path),
				"RUNTIME_FILE_HASH") ;
		// 拡張moduleも含め、native fileは全てPE32+ x64を要求する。
		if( relative.ends_with( L".exe") || relative.ends_with( L".dll") ||
		   relative.ends_with( L".pyd")) {
			checkPe( path) ;
		}

		// 四つの原PSF署名を非通信の共通policyへ結合する。
		if( (relative == L"runtime/python.exe" || relative == L"runtime/pythonw.exe" ||
			relative == L"runtime/python313.dll" || relative == L"runtime/python3.dll")) {
			const HANDLE raw =
				CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
							FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;	// 同じ原fileの変更を防ぐ。
			const DWORD openError =
				// 元code。
				raw == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS ;
			// 元fileを固定できない場合は署名検証前に拒否する。
			if( raw == INVALID_HANDLE_VALUE) {
				std::printf( "RUNTIME_CACHED_OPEN code=%lu\n",
							static_cast<unsigned long>( openError)) ;
				require( false, "RUNTIME_CACHED_OPEN") ;
			}

			// Lambdaは所有handleを一度だけ閉じ、解放失敗も固定診断へ残す。
			const std::shared_ptr<void> runtimeFile( raw, []( void *handle) noexcept {
				const BOOL	closed = CloseHandle( handle) ;	// 最終解放結果。
				const DWORD closeError =
					// 元code。
					closed == FALSE ? GetLastError() : ERROR_SUCCESS ;
				// Destructorから例外を出さず、元API失敗を通知する。
				if( closed == FALSE) {
					std::printf( "RUNTIME_CACHED_CLOSE code=%lu\n",
								static_cast<unsigned long>( closeError)) ;
				}
			}) ;
			BY_HANDLE_FILE_INFORMATION	information{} ;	// 同じ実fileの通常属性とlink数。
			const BOOL					queried =
				// 実照会。
				GetFileInformationByHandle( runtimeFile.get(), &information) ;
			const DWORD informationError =
				// 元code。
				queried == FALSE ? GetLastError() : ERROR_SUCCESS ;
			// 属性を取得できない状態を通常fileとして扱わない。
			if( queried == FALSE) {
				std::printf( "RUNTIME_CACHED_INFORMATION code=%lu\n",
							static_cast<unsigned long>( informationError)) ;
				require( false, "RUNTIME_CACHED_INFORMATION") ;
			}

			require( (information.dwFileAttributes &
					 (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0U &&
						information.nNumberOfLinks == 1U &&
						row.GetNamedString( L"sha256") == hashFile( path),
					"RUNTIME_CACHED_BYTE_BINDING") ;
			constexpr std::array<std::wstring_view, 1U> publishers{
				L"Python Software Foundation"} ;	// 原publisher。
			const auto error = drivercrate::verifyAuthenticodePublisherCachedOnly(
				// 共通cached-only結果。
				path.native(), publishers) ;
			// Cache不足等の元errorを固定診断へ保存してから停止する。
			if( error != 0) {
				std::printf( "RUNTIME_CACHED_SIGNATURE code=0x%08lx\n",
							static_cast<unsigned long>( error)) ;
			}

			require( error == 0, "RUNTIME_CACHED_SIGNATURE") ;
		}
	}
}

/** @brief 固定file集合とmanifest／receiptを検査します。
 * @param[in] directory 配布または導入済みworkspace。
 * @param[in] installed trueなら編集済みconfigと非公開workを保持する。
 * @param[in] retainMutableConfig 現行解除だけで設定内容を所有証明から外す場合true。
 * @return 実manifestのSHA-256。
 * @throws std::exception 最初の検査拒否。
 * @note 未知の導入後fileは削除しません。自己コードの認証ではありません。
 */
std::wstring checkBundle( const fs::path &directory, const bool installed,
						 const bool retainMutableConfig = false)
{
	const fs::path	 root	  = checkedDirectory( directory, true) ;			// 全祖先を検査したworkspace。
	const JsonObject manifest = readObject( root / L"package-manifest.json") ;	// 所有manifest。
	require( manifest.Size() == 5U &&
				manifest.GetNamedString( L"schema") == L"dc-collector-package-v7" &&
				manifest.GetNamedString( L"mode") == L"EXPLICIT_DISTRIBUTION_DATA_DAILY" &&
				manifest.GetNamedString( L"version") == DRIVERCRATE_VERSION_WSTRING &&
				manifest.GetNamedString( L"architecture") == L"x64",
			"MANIFEST_SCHEMA") ;
	require(
		!retainMutableConfig ||
			(installed && readObject( root / L"install-receipt.json").GetNamedString( L"schema") ==
							  L"dc-collector-install-receipt-v3"),
		"MUTABLE_CONFIG_UNINSTALL_SCOPE") ;
	std::set<fs::path> allowed ;	// 固定の相対file集合。
	const bool		   includesReference =
		// 固定二択です。
		manifest.GetNamedArray( L"files").Size() == payloadFiles( true).size() ;
	const auto files = payloadFiles( includesReference) ;	// 任意pathを含まない完全集合です。
	// 現在の固定file件数を読取り前に検査する。
	require( manifest.GetNamedArray( L"files").Size() == files.size() && fs::exists( root / L"seed"),
			"MANIFEST_COUNT") ;
	// 読取り前のinventoryにもcompile時の固定集合を使う。
	for( const auto relative : files) {
		allowed.emplace( relative) ;
	}

	allowed.insert( L"package-manifest.json") ;
	// 導入済みreceiptは後段で元manifestへ結合する。
	if( installed) {
		allowed.insert( L"install-receipt.json") ;
	}

	const auto inventoryFiles =
		// 診断番号の固定集合。
		files ;
	std::size_t entries{} ;	// 列挙したbundle要素数。
	// 未検証directoryへ再帰せず、workspace直下の有限bundleを列挙する。
	for( auto iterator = fs::recursive_directory_iterator( root);
		iterator != fs::recursive_directory_iterator{}; ++iterator) {
		const auto	  &entry	= *iterator ;								// 現在の有限要素。
		const fs::path relative = entry.path().lexically_relative( root) ;	// 実要素の相対path。
		require( ++entries <= 128U, "INVENTORY_LIMIT") ;
		const DWORD attributes = GetFileAttributesW( entry.path().c_str()) ;	// 実属性。
		// API失敗を実reparseと区別し、他APIを呼ぶ前に元errorを保存する。
		if( attributes == INVALID_FILE_ATTRIBUTES) {
			const DWORD error = GetLastError() ;	// 属性照会直後の元Win32 error。
			const auto	found = std::find( inventoryFiles.begin(), inventoryFiles.end(),
										  // 固定payloadとの対応。
										  relative.generic_wstring()) ;
			const auto	index =
				// 未登録は集合長。
				static_cast<std::size_t>( found - inventoryFiles.begin()) ;
			std::printf(
				"SETUP_PATH_DIAGNOSTIC win32=%lu entry=%zu payload_index=%zu path_chars=%zu\n",
				static_cast<unsigned long>( error), entries, index, entry.path().native().size()) ;
			require( false, "INVENTORY_ATTRIBUTES") ;
		}

		require( (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0U, "INVENTORY_REPARSE") ;
		// 通常bundle directory以外へは入らず、導入後の全workと未知directoryを保持する。
		if( entry.is_directory() && relative != L"bin" && relative != L"config" &&
		   relative != L"docs" && relative != fs::path( L"docs/adr") && relative != L"seed" &&
		   relative != fs::path( L"seed/collector-data") &&
		   relative != fs::path( L"seed/collector-data/index") &&
		   !(relative == fs::path( L"seed/distribution-data")) &&
		   !(includesReference && relative == fs::path( L"seed/distribution-data/references")) &&
		   !(relative == L"runtime" || relative == L"scripts")) {
			require( installed, "INVENTORY_DIRECTORY") ;
			require( relative.begin()->native() != L"seed" &&
						(relative.begin()->native() != L"runtime" &&
						 relative.begin()->native() != L"scripts"),
					"SEED_INVENTORY") ;
			iterator.disable_recursion_pending() ;
		}

		// 配布時だけ未知fileを拒否する。導入後の未知fileを削除対象へ加えない。
		if( !entry.is_directory() && (!installed || relative.begin()->native() == L"seed" ||
									 (relative.begin()->native() == L"runtime" ||
									  relative.begin()->native() == L"scripts"))) {
			require( allowed.contains( relative), "INVENTORY_EXTRA") ;
		}
	}

	const auto rows = manifest.GetNamedArray( L"files") ;	// 元順序の有限配列。
	require( rows.Size() == files.size() && fs::exists( root / L"seed"), "MANIFEST_COUNT") ;
	// 祖先と全bundle属性を確認後、固定fileだけを検証する。
	for( std::size_t index = 0U; index < files.size(); ++index) {
		const fs::path	 relative( files[index]) ;	// 固定相対名。
		const JsonObject row =
			// 元順序の記録。
			rows.GetAt( static_cast<std::uint32_t>( index)).GetObject() ;
		const double bytes = row.GetNamedNumber( L"bytes") ;	// 宣言byte数。
		require( row.Size() == 3U && row.GetNamedString( L"path") == files[index] &&
					std::isfinite( bytes) && bytes >= 0.0 && bytes <= 67108864.0 &&
					std::floor( bytes) == bytes,
				"MANIFEST_FILE") ;
		// 編集可能なconfigはnative validationへ渡し、package hashで上書きしない。
		if( installed && relative == fs::path( L"config/targets.json")) {
			// 現行解除ではJSONを読まず、通常file/実path/ACLだけを保持確認する。
			if( retainMutableConfig) {
				drivercrate::withCollectorSetupProtectedFile( root / relative, []() {
					// 設定内容を取得・修正せず、呼出し側の保護検査だけを使う。
				}) ;
			} else {
				static_cast<void>( readObject( root / relative)) ;
			}

			continue ;
		}

		require( checkedFile( root / relative, 67108864U) == static_cast<std::uintmax_t>( bytes) &&
					row.GetNamedString( L"sha256") == hashFile( root / relative),
				"PAYLOAD_HASH") ;
	}

	checkPe( root / L"bin/DriverCrateCollector.exe") ;
	checkPe( root / L"DriverCrateCollectorSetup.exe") ;
	checkResearchSeed( root) ;

	// 初期dataも閉manifestの原byte/hashへ結合し、package hashと混同しません。
	const fs::path data	 = root / L"seed/distribution-data" ;					// 基本または既知参考つき閉集合です。
	const auto	   inner = readObject( data / L"manifest.json", 16777216U) ;	// 有限JSONです。
	require( inner.Size() == 4U &&
				inner.GetNamedString( L"schema") == L"dc-collector-distribution-data-v1" &&
				inner.GetNamedBoolean( L"includesReference") == includesReference &&
				inner.GetNamedArray( L"files").Size() == (includesReference ? 10U : 4U) &&
				inner.GetNamedObject( L"inputHashes").Size() == 3U,
			"DISTRIBUTION_SEED_SCHEMA") ;
	std::vector<std::wstring_view> dataFiles{L"registry.json", L"locators.json",
											 L"collection-profiles.json",
											 L"research-index.json"} ;	// 基本四memberです。
	// 参考がある場合も既知の完全集合だけを原manifestへ結合します。
	if( includesReference) {
		dataFiles.insert( dataFiles.end(),
						 {L"reference.json", L"references/build-report.json",
						  L"references/index.json", L"references/index.json.gz",
						  L"references/manifest.raw.json", L"references/provenance.json"}) ;
	}

	// Nativeも固定memberの元hashを照合し、任意fileを入力から追加しません。
	for( const auto name : dataFiles) {
		bool found{} ;	// 各固定memberは一件だけです。
		// 基本または参考つきの固定entryを有限照合します。
		for( const auto &value : inner.GetNamedArray( L"files")) {
			const auto row = value.GetObject() ;	// 同梱manifestから借用します。
			// 同名の重複と原byte不一致を拒否します。
			if( row.GetNamedString( L"path") == name) {
				require( !found && row.Size() == 3U &&
							row.GetNamedString( L"sha256") == hashFile( data / name) &&
							row.GetNamedNumber( L"bytes") ==
								static_cast<double>( fs::file_size( data / name)),
						"DISTRIBUTION_SEED_HASH") ;
				found = true ;
			}
		}

		require( found, "DISTRIBUTION_SEED_FILE_SET") ;
	}

	// 参考を私有観測や通信許可として受理せず、元公開outputのhashへ結合します。
	if( includesReference) {
		const auto reference =
			// 参考境界の固定descriptorです。
			readObject( data / L"reference.json") ;
		require( reference.Size() == 10U &&
					reference.GetNamedString( L"schema") == L"dc-collector-public-reference-v1" &&
					!reference.GetNamedBoolean( L"privateEvidence") &&
					!reference.GetNamedBoolean( L"communicationAuthorized") &&
					reference.GetNamedObject( L"outputs").Size() == 5U,
				"DISTRIBUTION_REFERENCE_BOUNDARY") ;
		// 既知の公開五outputだけをdescriptorへ照合します。
		for( const auto name : {L"build-report.json", L"index.json", L"index.json.gz",
							   L"manifest.raw.json", L"provenance.json"}) {
			require( reference.GetNamedObject( L"outputs").GetNamedString( name) ==
						hashFile( data / L"references" / name),
					"DISTRIBUTION_REFERENCE_HASH") ;
		}
	}

	// Locatorの原byteを一致させ、取得証拠を含む旧索引と基礎研究索引を混同しません。
	require( hashFile( data / L"locators.json") ==
				hashFile( root / L"seed/collector-data/locators.json"),
			"DISTRIBUTION_SEED_REFERENCE") ;
	const auto registry = readObject( data / L"registry.json", 16777216U) ;	// 元の台帳です。
	const auto index	= readObject( data / L"research-index.json",
									 16777216U) ;	// 内容検査へ昇格しない基礎索引です。
	require( index.GetNamedBoolean( L"researchOnly") && !index.GetNamedBoolean( L"publishable") &&
				!index.GetNamedBoolean( L"installAuthorized") &&
				index.GetNamedString( L"revision") == registry.GetNamedString( L"revision"),
			"DISTRIBUTION_SEED_RESEARCH_BOUNDARY") ;
	// 元台帳の全集合をsnapshotへ、索引の三集合を元台帳へ結合します。
	for( const auto name : {L"sources", L"products", L"records", L"observations"}) {
		const auto collection =
			readObject( root / L"seed/collector-data" / (std::wstring( name) + L".json"),
					   16777216U) ;	// 既存検証済み集合です。
		require( registry.GetNamedArray( name).Stringify() ==
					collection.GetNamedArray( L"items").Stringify(),
				"DISTRIBUTION_SEED_REGISTRY_BINDING") ;
		// 基礎索引は観測集合以外をそのまま保持します。
		if( std::wstring_view( name) != L"observations") {
			require( index.GetNamedArray( name).Stringify() ==
						registry.GetNamedArray( name).Stringify(),
					"DISTRIBUTION_SEED_INDEX_BINDING") ;
		}
	}

	// 同梱profileの三原入力hashもnativeで独立照合します。
	for( const auto &entry :
		{std::pair{L"registry", L"registry.json"}, std::pair{L"locators", L"locators.json"},
		 std::pair{L"profiles", L"collection-profiles.json"}}) {
		require( inner.GetNamedObject( L"inputHashes").GetNamedString( entry.first) ==
					hashFile( data / entry.second),
				"DISTRIBUTION_SEED_INPUT_HASH") ;
	}

	checkRuntime( root) ;

	const std::wstring digest = hashFile( root / L"package-manifest.json") ;	// 元manifest指紋。
	// 導入後のreceiptを照合してから破壊的操作へ進む。
	if( installed) {
		const JsonObject receipt = readObject( root / L"install-receipt.json") ;	// 元導入記録。
		require( receipt.Size() == 3U &&
					receipt.GetNamedString( L"schema") == L"dc-collector-install-receipt-v3" &&
					receipt.GetNamedString( L"packageManifestSha256") == digest &&
					receipt.GetNamedString( L"installedUtc").size() >= 20U,
				"RECEIPT_BINDING") ;
	}

	return digest ;
}

/** @brief resource文字列を取得します。
 * @param[in] id 同梱resource ID。
 * @return 固定の日本語案内。
 * @throws std::runtime_error resource欠損。
 */
std::wstring message( const UINT id)
{
	std::array<wchar_t, 512> buffer{} ;	// 固定UI文字列の容量。
	const int				 count = LoadStringW( GetModuleHandleW( nullptr), id, buffer.data(),
												 // 実文字数。
												 static_cast<int>( buffer.size())) ;
	require( count > 0, "RESOURCE_MISSING") ;
	return std::wstring( buffer.data(), static_cast<std::size_t>( count)) ;
}

/** @brief 新規workspaceを作り、検査済みfileだけを配置します。
 * @param[in] package 配布directory。
 * @param[in] destination 新規導入先。
 * @throws std::exception 検査／copy／receipt失敗。途中fileは保持します。
 */
void install( const fs::path &package, const fs::path &destination)
{
	const bool installedSource =
		// 自己修復時だけ既存配置を読む。
		fs::exists( package / L"install-receipt.json") ;
	const std::wstring digest = checkBundle( package, installedSource) ;	// 配布の元指紋。
	const fs::path	   root	  = checkedDirectory( destination, false) ;		// 新規pathの全祖先。
	// 同一manifestの現行配置だけにTask修復を許し、program/config/stateをcopyし直さない。
	if( fs::exists( root)) {
		require( checkBundle( root, true) == digest &&
					readObject( root / L"install-receipt.json").GetNamedString( L"schema") ==
						L"dc-collector-install-receipt-v3",
				"USER_TASK_REPAIR_INSTALLATION") ;
		drivercrate::ensureInstalledCollectorUserTask( root, digest, [&]() {
			require( checkBundle( root, true) == digest, "USER_TASK_REPAIR_PACKAGE") ;
		}) ;
		return ;
	}

	require( !installedSource, "INSTALLED_SOURCE_COPY_UNSUPPORTED") ;
	require( !fs::exists( root), "EXISTING_DIRECTORY") ;
	// 現行rootを作成時から保護する。
	// OS既定先だけは、欠損する固定親一階層を同意後に保護作成する。
	if( root == defaultDirectory()) {
		drivercrate::prepareCollectorSetupDefaultParent( root.parent_path().parent_path()) ;
	}

	drivercrate::createCollectorSetupProtectedRoot( root) ;

	// 固定fileだけを新規copyし、既存fileを上書きしない。
	for( const auto relative :
		payloadFiles( fs::exists( package / L"seed/distribution-data/reference.json"))) {
		const fs::path target = root / relative ;	// 固定のcopy先。
		fs::create_directories( target.parent_path()) ;
		// SourceのACLをcopyせず、保護親から新規fileへ継承する。
		drivercrate::copyCollectorSetupProtectedFile( package / relative, target) ;
	}

	// Manifestも同じ新規作成境界へ通し、copy後の全byteを既存検査へ戻す。
	drivercrate::copyCollectorSetupProtectedFile( package / L"package-manifest.json",
												 root / L"package-manifest.json") ;

	require( checkBundle( root, false) == digest, "COPY_BINDING") ;
	fs::create_directories( root / L"work" / L"state") ;
	SYSTEMTIME now{} ;	// UTCの導入時刻。
	GetSystemTime( &now) ;
	std::array<wchar_t, 32> timestamp{} ;	// 固定ISO時刻容量。
	const int				count =
		swprintf_s( timestamp.data(), timestamp.size(), L"%04u-%02u-%02uT%02u:%02u:%02uZ", now.wYear,
				   now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond) ;	// 実文字数。
	require( count > 0, "RECEIPT_TIME") ;
	JsonObject receipt ;	// 導入成功を最後に固定する記録。
	receipt.SetNamedValue( L"schema",
						  JsonValue::CreateStringValue( L"dc-collector-install-receipt-v3")) ;
	receipt.SetNamedValue( L"packageManifestSha256", JsonValue::CreateStringValue( digest)) ;
	receipt.SetNamedValue( L"installedUtc", JsonValue::CreateStringValue( timestamp.data())) ;
	const std::string bytes = winrt::to_string( receipt.Stringify()) ;	// UTF-8の元byte。
	// 配置receiptもTask登録前にflushと保護読戻しを済ませる。
	drivercrate::writeCollectorSetupProtectedMetadata( root / L"install-receipt.json", bytes, false) ;

	require( checkBundle( root, true) == digest, "INSTALLED_BINDING") ;
	// 通常installは有効Taskの実読戻しが完了するまで成功へ進まない。
	drivercrate::ensureInstalledCollectorUserTask( root, digest, [&]() {
		require( checkBundle( root, true) == digest, "USER_TASK_INSTALLED_PACKAGE") ;
	}) ;
}

/** @brief 管理fileだけを非再帰削除し、設定・台帳・自己EXEを保持します。
 * @param[in] directory 検査する導入先。
 * @return 不存在を確認した解除Task数です。
 * @throws std::exception 検査または削除失敗。
 */
std::size_t uninstall( const fs::path &directory)
{
	const std::wstring digest = checkBundle( directory, true, true) ;	// 現行receiptだけです。
	const auto		   verify = [&]() {
		require( checkBundle( directory, true, true) == digest, "USER_TASK_UNINSTALL_PACKAGE") ;
	} ; // 両Taskの不存在確認まで同じpackageへ結合します。
	std::size_t removedTasks = drivercrate::removeInstalledCollectorUserTask(
		directory, digest, verify) ;	// 不存在を確認した件数です。
	removedTasks += drivercrate::removeInstalledCollectorUserTask( directory, digest, verify, true) ;

	std::printf( "SETUP_TASK_CLEANUP_COMPLETE tasks_deleted=%zu\n", removedTasks) ;
	static_cast<void>( checkBundle( directory, true, true)) ;
	// 固定管理fileだけを削除し、未知file・work・configを扱わない。
	for( const auto relative :
		payloadFiles( fs::exists( directory / L"seed/distribution-data/reference.json"))) {
		// Windowsの実行中EXEと、解除の案内入口も保持する。
		if( relative.starts_with( L"seed/") || relative == L"config/targets.json" ||
		   relative.starts_with( L"config/") || relative == L"DriverCrateCollectorSetup.exe" ||
		   relative == L"Uninstall.cmd") {
			continue ;
		}

		require( fs::remove( directory / relative), "REMOVE_FILE") ;
	}

	require( fs::remove( directory / L"package-manifest.json") &&
				fs::remove( directory / L"install-receipt.json"),
			"REMOVE_RECEIPT") ;
	return removedTasks ;
}
} // namespace

/** @brief 明示操作または日本語確認後に手動workspaceだけを変更します。
 * @param[in] count 引数数。
 * @param[in] args mode、任意directory、非対話の明示--yes。
 * @return 成功0、拒否2、利用者取消し3。
 * @note 配置／解除と停止workspace操作は非通信です。明示一回monitorは個別同意を要求し、
 *       未確認のnative共有scopeはHOLDです。通常installはnative日次metadata Taskを有効登録します。
 */
int wmain( const int count, wchar_t *args[])
{
	bool interactiveUninstall{} ;	// 対話解除だけで失敗案内を表示する。
	bool interactiveInstall{} ;		// 対話導入でも失敗を正常完了と混同させない。
	try {
		winrt::init_apartment() ;
		require( count >= 1 && count <= 6 && args != nullptr, "ARGUMENTS") ;
		const std::wstring_view requested =
			count > 1 ? args[1] : L"--install" ;	// 明示CLIの先行振分け。
		// 新Taskだけの固定dispatcherと初回payload/daily同意を旧onceから分けます。
		if( requested == L"--distribution-daily" || requested == L"--enable-distribution-daily") {
			const bool enable = requested == L"--enable-distribution-daily" ;	// 明示初回だけです。
			require( (enable && count == 4 &&
					 std::wstring_view( args[3]) == L"--confirm-daily-inspection-download") ||
						(!enable && count == 2),
					"DISTRIBUTION_DAILY_ARGUMENTS") ;
			const fs::path package = packageRoot() ;	// 導入済み自己packageだけです。
			const auto	   verify  = [&package]() {
				 require( readObject( package / L"package-manifest.json").GetNamedString( L"schema") ==
								 L"dc-collector-package-v7",
							 "DISTRIBUTION_DAILY_PACKAGE_VERSION") ;
				 static_cast<void>( checkBundle( package, true)) ;
			} ; // 同じbyte検査を同期借用します。
			const int result = drivercrate::runCollectorSetupDistributionDaily(
				package, enable ? fs::path( args[2]) : fs::path{}, enable,
				verify) ;	// 同じrun/buildへ接続します。
			// Task登録は明示opt-inが完了した時だけ行い、日次/copyでは行いません。
			if( enable && result == 0) {
				drivercrate::ensureInstalledCollectorUserTask(
					package, hashFile( package / L"package-manifest.json"), verify, true) ;
			}

			return result ;
		}

		// Data取込みは非通信で、同意receiptやTaskを発行しません。
		if( requested == L"--import-data") {
			require( count == 5 && std::wstring_view( args[4]) == L"--confirm-offline",
					"DATA_IMPORT_ARGUMENTS") ;
			const fs::path package = packageRoot() ;	// 自己packageだけです。
			const auto	   verify  = [&package]() {
				 require( readObject( package / L"package-manifest.json").GetNamedString( L"schema") ==
								 L"dc-collector-package-v7",
							 "DATA_IMPORT_PACKAGE_VERSION") ;
				 static_cast<void>( checkBundle( package, true)) ;
			} ; // 全byte検査だけを借用します。
			return drivercrate::runCollectorSetupWorkspace(
				package, L"import-data", fs::path( args[2]), fs::path( args[3]), verify) ;
		}

		// 配布検査の同意はmetadata同意から分け、固定二操作だけへ接続します。
		if( requested == L"--distribution-run-once" ||
		   requested == L"--initialize-distribution-origins") {
			const bool initialize =
				// 非通信初回登録です。
				requested == L"--initialize-distribution-origins" ;
			require(
				(initialize && count == 6 && std::wstring_view( args[5]) == L"--confirm-offline") ||
					(!initialize && count == 4 &&
					 std::wstring_view( args[3]) == L"--confirm-inspection-download"),
				"DISTRIBUTION_CONSENT_REQUIRED") ;
			const fs::path package = packageRoot() ;	// 自己導入package以外を受けません。
			// 既存package/receipt全検証を新経路も同じ親handle保持下で行います。
			const auto	   verify = [&package]() { static_cast<void>( checkBundle( package, true)) ; } ;
			return drivercrate::runCollectorSetupWorkspace(
				package, initialize ? L"initialize-distribution-origins" : L"distribution-run-once",
				fs::path( args[2]), initialize ? fs::path{} : fs::path( args[3]), verify,
				initialize ? fs::path( args[3]) : fs::path{},
				initialize ? fs::path( args[4]) : fs::path{}) ;
		}

		// 非通信操作と明示一回runを、対象と操作別同意の固定argvへ振り分ける。
		if( requested.starts_with( L"--workspace-")) {
			const std::wstring action( requested.substr( 12U)) ;		// 閉集合の操作名。
			const bool		   verify	  = action == L"verify" ;		// 非変更検査だけは同意flag不要。
			const bool		   initialize = action == L"initialize" ;	// 新規rootの非通信初期化。
			const bool		   runOnce	  = action == L"run-once" ;		// 一回だけの明示通信同意。
			const bool		   binding =
				// 停止済みの正式原点を非通信で選択する。
				action == L"bind-origins" ;
			const bool packageSwitch =
				// 原hashを別途reviewした非通信切替。
				action == L"switch-package" ;
			const bool heldReview =
				// 原因と現baselineを明示reviewします。
				action == L"review-held-host" ;
			const bool transfer = action == L"export" || action == L"import" ||
								  // 移設引数が必要な操作。
								  action == L"resume" || action == L"stage-candidate" ;
			require( verify || initialize || transfer || runOnce || binding || packageSwitch ||
						heldReview,
					"WORKSPACE_ACTION") ;
			require( (verify && count == 3) ||
						(runOnce && count == 4 &&
						 std::wstring_view( args[3]) == L"--confirm-monitor-once") ||
						(initialize && count == 4 &&
						 std::wstring_view( args[3]) == L"--confirm-offline") ||
						(transfer && count == 5 &&
						 std::wstring_view( args[4]) == L"--confirm-source-stopped") ||
						(binding && count == 6 &&
						 std::wstring_view( args[5]) == L"--confirm-source-stopped") ||
						((packageSwitch || heldReview) && count == 5 &&
						 std::wstring_view( args[4]) == L"--confirm-source-stopped"),
					"WORKSPACE_CONSENT_REQUIRED") ;
			const fs::path package = packageRoot() ;	// 自己EXEの導入済みpackageだけを使う。
			// 任意callbackを入力から作らず、既存の全payload/receipt検査を同期で借用する。
			const auto	   verifyPackage = [&package, &action]() {
				// Stagingだけは全byte検査済み未install packageを使い、Taskのためのinstallを要求しません。
				const bool installed =
					action != L"stage-candidate" ||
					fs::exists( package /
								   L"install-receipt.json") ;	// 存在したreceiptは通常検査します。
				static_cast<void>( checkBundle( package, installed)) ;
			} ;

			return drivercrate::runCollectorSetupWorkspace(
				package, action, fs::path( args[2]),
				transfer || runOnce || packageSwitch || heldReview ? fs::path( args[3]) : fs::path{},
				verifyPackage, binding ? fs::path( args[3]) : fs::path{},
				binding ? fs::path( args[4]) : fs::path{}) ;
		}

		require( count >= 1 && count <= 4 && args != nullptr, "ARGUMENTS") ;
		const std::wstring_view mode		 = count > 1 ? args[1] : L"--install" ;	// 明示した操作。
		const bool				checkPackage = mode == L"--check-package" ;			// 配布を非変更検査する。
		const bool checkInstalled = mode == L"--check-installed" ;					// 導入済みを非変更検査する。
		require( checkPackage || checkInstalled || mode == L"--install" || mode == L"--uninstall",
				"MODE") ;
		const fs::path directory = count > 2
									   ? fs::path( args[2])
									   : (checkPackage || checkInstalled || mode == L"--uninstall"
											  ? packageRoot()
											  : defaultDirectory()) ;	// 対象workspace。
		const bool	   yes =
			// 明示した非対話操作。
			count == 4 && std::wstring_view( args[3]) == L"--yes" ;
		require( count != 4 || yes, "CONFIRM_ARGUMENT") ;
		// 検査modeには確認やfile更新を加えない。
		if( checkPackage || checkInstalled) {
			static_cast<void>( checkBundle( directory, checkInstalled)) ;
			std::printf( "SETUP_CHECK_COMPLETE network=0 tasks=0\n") ;
			return 0 ;
		}

		const fs::path root =
			// 確認前の対象検査。
			checkedDirectory( directory, mode == L"--uninstall") ;
		const bool userTaskInstall = mode == L"--install" ;	// 現行setupのTask同意です。
		interactiveInstall		   = mode == L"--install" && !yes ;
		// 対話利用者は対象pathと変更範囲へ明示同意する。
		if( !yes) {
			const std::wstring seedNotice =
				// 同梱dataの案内です。
				mode == L"--install" ? L"\n" + message( SEED_NOTICE) : L"" ;

			const std::wstring prompt =
				message( mode == L"--install" ? USER_TASK_CONFIRM : UNINSTALL_CONFIRM) + seedNotice +
				L"\n\n" +
				// 選択対象に結合した確認文。
				root.native() ;
			// 拒否時はworkspaceを変更しない。
			if( MessageBoxW( nullptr, prompt.c_str(), message( SETUP_TITLE).c_str(),
						   MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) {
				return 3 ;
			}
		}

		std::size_t removedTasks{} ;	// 正常に不存在を確認した解除Task数。
		// 導入と解除を固定した別経路へ分ける。
		if( mode == L"--install") {
			install( packageRoot(), root) ;
		} else {
			interactiveUninstall = !yes ;
			removedTasks		 = uninstall( root) ;
		}

		std::printf(
			"SETUP_COMPLETE network=0 tasks=%zu tasks_registered=%u tasks_enabled=%u tasks_deleted=%zu installed_drivers=0 data_retained=1\n",
			userTaskInstall ? 1U : removedTasks, userTaskInstall ? 1U : 0U,
			userTaskInstall ? 1U : 0U, removedTasks) ;
		// 対話時だけ完了案内を示す。失敗を完了と表示しない。
		if( !yes) {
			MessageBoxW( nullptr, message( userTaskInstall ? USER_TASK_DONE : SETUP_DONE).c_str(),
						message( SETUP_TITLE).c_str(), MB_OK) ;
		}

		return 0 ;
	} catch( const fs::filesystem_error &error) {
		std::printf( "SETUP_REJECTED filesystem_error=%d network=0 task_cleanup=not_confirmed\n",
					error.code().value()) ;
	} catch( const std::exception &error) {
		std::printf( "SETUP_REJECTED stage=%s network=0 task_cleanup=not_confirmed\n", error.what()) ;
	} catch( const winrt::hresult_error &error) {
		std::printf( "SETUP_REJECTED hresult=%08x network=0 task_cleanup=not_confirmed\n",
					static_cast<unsigned int>( error.code().value)) ;
	} catch( ...) {
		std::printf( "SETUP_REJECTED stage=exception network=0 task_cleanup=not_confirmed\n") ;
	}

	// 非対話の自動fixtureを待たせず、利用者の明示解除失敗だけへ安全な次操作を案内する。
	if( interactiveUninstall || interactiveInstall) {
		std::array<wchar_t, 512U> notice{} ;	// 失敗経路で確保不要の固定resource容量。
		// resource取得まで失敗した場合は、元診断を保持して正常終了にしない。
		if( LoadStringW( GetModuleHandleW( nullptr),
					   interactiveInstall ? INSTALL_FAILED : UNINSTALL_FAILED, notice.data(),
					   static_cast<int>( notice.size())) > 0) {
			MessageBoxW( nullptr, notice.data(), L"DriverCrate Collector", MB_OK | MB_ICONERROR) ;
		}
	}

	return 2 ;
}
