//------------------------------------------------------------------------------
/**
 * @file collector_setup_workspace_tests.cpp
 * @brief 非通信workspaceのcomponent境界と保存済みAPI診断を決定的に検査します。
 * @version 01.07.00
 * @date 2026/10/24
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/17 component比較と明示fake診断の回帰を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/17 nativeの有限proxy環境保持を値非出力で検証。
 * Ver.01.02.00 Shunji Ogawa  2026/10/20 bootstrap保護境界と元DWORD終了値・timeoutを確認。
 * Ver.01.03.00 Shunji Ogawa  2026/10/20 自己EXEの親からbuildを固定し、呼出し元cwdに依存しない。
 * Ver.01.04.00 Shunji Ogawa  2026/10/20 embedded保存前の子親検査・固定と既存byte保持を追加。
 * Ver.01.04.01 Shunji Ogawa  2026/10/20 実childのOS由来drive・KnownFolder展開と親環境非継承を確認。
 * Ver.01.04.02 Shunji Ogawa  2026/10/21 二入口の固定file argvと空白packageの引用を確認。
 * Ver.01.04.03 Shunji Ogawa  2026/10/23 保護fileのseparator三表記と既存拒否境界を直接検査。
 * Ver.01.04.04 Shunji Ogawa  2026/10/24 現行仕様へ限定し旧版専用の入口・移動を整理。
 * Ver.01.04.05 Shunji Ogawa  2026/10/24 root直下Actionと継承child親の厳密な区別を確認。
 * Ver.01.04.06 Shunji Ogawa  2026/10/24  必須解析に合わせ同容量のOS path bufferをheap所有へ移す。
 * Ver.01.05.00 Shunji Ogawa  2026/10/25 保持workspace256MiBとpackage64MiBの実境界を検査。
 * Ver.01.06.00 Shunji Ogawa  2026/10/26 一host reviewの固定三入力と保護振分けを検査。
 * Ver.01.07.00 Shunji Ogawa  2026/10/26 候補stagingの重複・非空・原点欠損拒否を検査。
 * </pre>
 *
 * @note 内部helperを同一TUで検査し、製品CLIに故障注入を追加しません。
 * @see docs/adr/0356-collector-workspace-boundary-repairs.md
 */
//------------------------------------------------------------------------------

// 内部境界だけを検査する独立targetであり、製品targetへこのTUはlinkしない。
#include "platform/collector_setup_workspace.cpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <bit>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <windows.h>
#include <winioctl.h>

namespace drivercrate {
namespace {

/** @brief 固定stageの例外を要求し、実API故障を発生させません。
 * @param[in] operation 明示fake戻り値または意味拒否を検査する同期処理。
 * @param[in] stage 期待する固定stage。
 * @return 期待した例外を受け取った場合true。
 */
bool catchesStage( const std::function<void()> &operation, const std::string_view stage)
{
	try {
		operation() ;
	} catch( const std::runtime_error &error) {
		return error.what() == stage ;
	}

	return false ;
}

/** @brief 非重複とAPI診断の固定入力を一度ずつ検査します。
 * @return 全検査成功時0、失敗時1。
 */
int workspaceChecks()
{
	std::size_t		   failures{} ;												// 固定期待と異なる件数。
	const fs::path	   package = L"D:\\Artificial Package\\collector" ;			// 実fileを作らない引用回帰。
	const fs::path	   script = package / L"scripts/collector_workspace.py" ;	// 現行の固定入口です。
	const std::wstring expected = L" -I -B -S \"" + script.native() + L"\" \"" + package.native() +
								  L"\"" ;	// 空白を一argvとして保持する期待値です。
	failures += fileBootstrapArguments( package) != expected ;

	const fs::path				   first	= L"D:\\Fixture\\foo" ;	// 実fileには触れない比較入力。
	const std::array<fs::path, 4U> overlaps = {first, L"d:\\fixture\\FOO", L"D:\\Fixture",
											   L"D:\\Fixture\\foo\\child"} ;	// 同一と両方向親子。
	// 全比較は順序も反転し、一方の祖先だけを見落とさない。
	for( const fs::path &other : overlaps) {
		failures += !pathsOverlap( first, other) || !pathsOverlap( other, first) ;
	}

	const fs::path separate = L"D:\\Fixture\\foo-other" ;	// 似たprefixの兄弟。
	failures += pathsOverlap( first, separate) || pathsOverlap( separate, first) ;
	// 各lambdaは即時同期実行し、fakeのthread errorをhelperへ直接渡す。
	failures += !catchesStage(
		[] {
			SetLastError( ERROR_ACCESS_DENIED) ;
			requireBool( FALSE, "TEST_BOOL") ;
		},
		"TEST_BOOL") ;
	failures += !catchesStage(
		[] {
			SetLastError( ERROR_INVALID_DATA) ;
			requireStatus( ERROR_SHARING_VIOLATION, "TEST_DWORD") ;
		},
		"TEST_DWORD") ;
	failures += !catchesStage(
		[] {
			SetLastError( ERROR_INVALID_HANDLE) ;
			requireTokenSizeQuery( FALSE) ;
		},
		"WORKSPACE_TOKEN_SIZE_QUERY") ;
	failures += !catchesStage(
		[] {
			SetLastError( ERROR_ACCESS_DENIED) ;
			requireTokenSizeQuery( TRUE) ;
		},
		"WORKSPACE_TOKEN_SIZE_QUERY_RESULT") ;
	failures += !catchesStage(
		[] {
			SetLastError( ERROR_ACCESS_DENIED) ;
			require( false, "TEST_SEMANTIC") ;
		},
		"TEST_SEMANTIC") ;
	SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
	requireTokenSizeQuery( FALSE) ;
	requireBool( TRUE, "TEST_BOOL_SUCCESS") ;
	requireStatus( ERROR_SUCCESS, "TEST_DWORD_SUCCESS") ;
	std::wstring environment ;	// 本番と同じhelperで生成する非出力の環境block。
	appendProxyEnvironment( environment) ;
	// 呼出し元が設定した四種だけを比較し、値やcredentialをstdoutへ出さない。
	for( const auto name : {L"HTTPS_PROXY", L"HTTP_PROXY", L"ALL_PROXY", L"NO_PROXY"}) {
		std::array<wchar_t, 4096U> value{} ;	// 本番と同じ有限容量の一設定。
		SetLastError( ERROR_SUCCESS) ;
		const DWORD length = GetEnvironmentVariableW( name, value.data(),
													 // 親processの設定だけを照会する。
													 static_cast<DWORD>( value.size())) ;
		const DWORD error =
			// 未設定と実失敗を区別する。
			length == 0U ? GetLastError() : ERROR_SUCCESS ;
		const std::wstring prefix = std::wstring( name) + L"=" ;	// 比較する固定環境名。
		// 設定済み値はbyte相当の完全一致、未設定は欠損のままであることを要求する。
		if( length > 0U && length < value.size()) {
			failures += environment.find( prefix + value.data() + L'\0') == std::wstring::npos ;
		} else {
			failures +=
				error != ERROR_ENVVAR_NOT_FOUND || environment.find( prefix) != std::wstring::npos ;
		}
	}

	std::printf( "WORKSPACE_UNIT fake_only=1 cases=19 failures=%zu\n", failures) ;
	return failures == 0U ? 0 : 1 ;
}

/** @brief 新規保護rootと固定fake childで実helperの失敗境界を検査します。
 * @return 全検査成功時0、失敗時1。
 * @note 独自fixtureをbuild直下へ保持し、運用stateや通信は扱いません。
 */
int bootstrapChecks()
{
	std::size_t			 failures{} ;		// 固定期待との差を保持する。
	std::vector<wchar_t> module( 32768U) ;	// test EXEの自己pathを同容量・ゼロ初期値で所有する。
	const DWORD			 length =
		// 実文字数。
		GetModuleFileNameW( nullptr, module.data(), static_cast<DWORD>( module.size())) ;
	require( length > 0U && length < module.size(), "TEST_SELF_PATH") ;
	const fs::path executable( module.data()) ;							// 製品のpayloadを実行しない固定fake。
	const fs::path directory = executable.parent_path().parent_path() ;	// 唯一の既存build直下。
	// 親test processだけを偽装し、固定childがOS値と最小環境を使うことを実測する。
	for( const auto name : {L"SystemDrive", L"PATH", L"PYTHONPATH", L"PYTHONHOME", L"USERPROFILE",
						   L"APPDATA", L"LOCALAPPDATA", L"PROGRAMDATA", L"TEMP", L"TMP"}) {
		requireBool( SetEnvironmentVariableW( name, L"Z:\\parent-environment-fixture"),
					"TEST_PARENT_ENVIRONMENT") ;
	}

	failures +=
		executeSetupChild( executable, L" --fixture-environment", directory, 5000U, false) != 0U ;
	// 不適格なOS値を補正せず、drive射影の前提を固定入力で拒否する。
	for( const auto invalid :
		{L"", L"C:", L"C:\\", L"C:Windows", L"\\Windows", L"1:\\Windows", L"\\\\server\\Windows",
		 L"\\\\?\\C:\\Windows", L"C:/Windows", L"C:\\Windows:stream", L"%SystemDrive%\\Windows",
		 L"C:\\..\\Windows"}) {
		failures +=
			!catchesStage( [invalid]() { static_cast<void>( setupChildSystemDrive( invalid)) ; },
						  "SETUP_CHILD_SYSTEMDRIVE") ;
	}

	// 固定fakeの成功・拒否・取消し・未知値を一回ずつ実起動する。
	for( const auto &pair : std::array<std::pair<std::wstring_view, DWORD>, 4>{
			{{L" --fixture-success", 0U},
			 {L" --fixture-refused", 2U},
			 {L" --fixture-cancelled", 3U},
			 {L" --fixture-unknown", 0xC0000005U}}}) {
		const DWORD exit = executeSetupChild( executable, std::wstring( pair.first), directory, 5000U,
											 false) ;	// 元DWORD。
		failures += exit != pair.second ;
		failures += std::bit_cast<DWORD>( std::bit_cast<std::int32_t>( exit)) != pair.second ;
	}

	// 10msの有限待機を超えたfakeだけをjobで止め、成功へ変換しない。
	failures += !catchesStage(
		[&executable, &directory]() {
			static_cast<void>(
				executeSetupChild( executable, L" --fixture-sleep", directory, 10U, false)) ;
		},
		"SETUP_CHILD_WAIT_UNKNOWN") ;
	GUID id{} ;	// fixture専用の新規一意名。
	winrt::check_hresult( CoCreateGuid( &id)) ;
	std::array<wchar_t, 40> name{} ;	// 固定GUID容量。
	require( StringFromGUID2( id, name.data(), static_cast<int>( name.size())) > 0, "TEST_GUID") ;
	const fs::path root =
		directory / (L"collector-bootstrap-unit-" + std::wstring( name.data())) ;	// 自作fixtureだけ。
	createCollectorSetupProtectedRoot( root) ;
	failures +=
		!catchesStage( [&root]() { createCollectorSetupProtectedRoot( root) ; }, "WORKSPACE_EXISTS") ;
	const auto token = userToken() ;	// protected descriptorの実SID照合。
	// Windowsから受けた所有bufferのTOKEN_USERだけを読む。
	PSID	   user	   = reinterpret_cast<const TOKEN_USER *>( token.data())->User.Sid ;
	Handle	   checked = openChecked( root, true, false) ;	// 同じ実rootを固定する。
	checkSecurity( checked.get(), user, true, true) ;
	const fs::path target = root / L"retained.json" ;	// CREATE_NEWと保持の試験対象。
	copyCollectorSetupProtectedFile( executable, target) ;
	bool copyRejected{} ;	// 既存file上書きの例外だけを受理する。
	try {
		copyCollectorSetupProtectedFile( executable, target) ;
	} catch( const std::runtime_error &) {
		copyRejected = true ;
	}

	failures += !copyRejected || !fs::exists( target) ;
	const fs::path inherited = root / L"inherited" ;	// 継承DACLをroot用保護契約へ流用しない。
	fs::create_directory( inherited) ;
	Handle inheritedHandle = openChecked( inherited, true, false) ;	// 同じ実child。
	failures += !catchesStage(
		[&inheritedHandle, user]() { checkSecurity( inheritedHandle.get(), user, true, true) ; },
		"WORKSPACE_PROTECTED_DACL") ;
	failures += !catchesStage( [&target]() { createCollectorSetupProtectedRoot( target / L"child") ; },
							  "WORKSPACE_OBJECT") ;
	bool renameRejected{} ;	// 保持中rootのidentity置換をOSの共有契約で拒否する。
	try {
		fs::rename( root, directory / (root.filename().native() + L"-changed")) ;
	} catch( const fs::filesystem_error &) {
		renameRejected = true ;
	}

	failures += !renameRejected || !fs::exists( root) ;
	Handle file = openChecked( target, false, true) ;	// 単一link・pathとACLの実検査。
	checkSecurity( file.get(), user, false, false) ;
	const fs::path separatorParent =
		root / L"separator 収集 fixture" ;	// 空白とUnicodeを含む継承親。
	fs::create_directory( separatorParent) ;
	const fs::path separatorFile =
		separatorParent / L"保護 file.bin" ;	// 三表記で共有する同じ通常file。
	copyCollectorSetupProtectedFile( executable, separatorFile) ;
	const std::array<fs::path, 3> spellings{
		separatorFile, fs::path( separatorFile.generic_wstring()),
		root / L"separator 収集 fixture/保護 file.bin"} ;	// backslash、forward、混在の実入力。
	std::size_t protectedCalls{} ;						// 全検査に成功した同期callbackだけを数える。
	// 同じ通常fileの三表記を一度ずつ通し、借用入力の表記を変更しない。
	for( const auto &spelling : spellings) {
		const std::wstring original = spelling.native() ;	// 呼出し前の借用pathの原表記。
		withCollectorSetupProtectedFile( spelling, [&protectedCalls]() { ++protectedCalls ; }) ;
		failures += spelling.native() != original ;
	}

	failures += protectedCalls != spellings.size() ;
	// root直下のAction fileは親の完全protected契約を明示した場合だけ受理します。
	withCollectorSetupProtectedFile( target, [&protectedCalls]() { ++protectedCalls ; }, true) ;
	failures += protectedCalls != spellings.size() + 1U ;
	failures += !catchesStage( [&target]() { withCollectorSetupProtectedFile( target, [] {}) ; },
							  "WORKSPACE_CHILD_ACE") ;
	// 継承child親をprotected-rootへ読み替えて受理しません。
	failures += !catchesStage(
		[&separatorFile]() { withCollectorSetupProtectedFile( separatorFile, [] {}, true) ; },
		"WORKSPACE_PROTECTED_DACL") ;
	// dot componentを字句補正して別入力として受理しないことを直接確認する。
	for( const auto invalid : {L"separator 収集 fixture/./保護 file.bin",
							  L"separator 収集 fixture/../separator 収集 fixture/保護 file.bin"}) {
		failures += !catchesStage(
			[&root, invalid]() { withCollectorSetupProtectedFile( root / invalid, [] {}) ; },
			"WORKSPACE_HANDLE_PATH") ;
	}

	const fs::path linkedFile = separatorParent / L"linked.bin" ;	// 単一link拒否専用の独立file。
	copyCollectorSetupProtectedFile( executable, linkedFile) ;
	requireBool( CreateHardLinkW( (separatorParent / L"linked-alias.bin").c_str(), linkedFile.c_str(),
								nullptr),
				"TEST_FILE_HARDLINK") ;
	failures +=
		!catchesStage( [&linkedFile]() { withCollectorSetupProtectedFile( linkedFile, [] {}) ; },
					  "WORKSPACE_OBJECT") ;
	const std::array<CollectorSetupEmbeddedFile, 1> invalid{
		{{L"../outside", "x", L"x"}}} ;	// 保存前拒否用の架空table。
	failures += !catchesStage(
		[&invalid]() { static_cast<void>( runCollectorSetupEmbedded( invalid, {}, false)) ; },
		"EMBEDDED_COMPONENT") ;
	failures += !catchesStage( [] { static_cast<void>( runCollectorSetupEmbedded( {}, {}, false)) ; },
							  "EMBEDDED_COUNT") ;
	std::wstring hash ;	// 重複名の拒否へ到達するための正しい一byte hash。
	require( computeBytesSha256( "x", hash) == 0, "TEST_BYTE_HASH") ;
	const std::array<CollectorSetupEmbeddedFile, 2> duplicates{
		{{L"one", "x", hash}, {L"one", "x", hash}}} ;	// byteが正しくても同じ相対名を拒否する。
	failures += !catchesStage(
		[&duplicates]() { static_cast<void>( runCollectorSetupEmbedded( duplicates, {}, false)) ; },
		"EMBEDDED_PATH") ;
	const std::vector<CollectorSetupEmbeddedFile> oversizedCount(
		129U, duplicates.front()) ;	// entry上限直後を副作用前に拒否する。
	failures += !catchesStage(
		[&oversizedCount]() {
			static_cast<void>( runCollectorSetupEmbedded( oversizedCount, {}, false)) ;
		},
		"EMBEDDED_COUNT") ;
	std::string oversizedBytes( 67108865U, 'x') ;	// 実所有bufferで一file64MiB上限直後を確認する。
	const std::array<CollectorSetupEmbeddedFile, 1> oversizedFile{
		{{L"large", oversizedBytes, hash}}} ;	// hashを読むより前のsize拒否。
	failures += !catchesStage(
		[&oversizedFile]() {
			static_cast<void>( runCollectorSetupEmbedded( oversizedFile, {}, false)) ;
		},
		"EMBEDDED_SIZE") ;
	// 二file合計64MiB上限直後の実byteを保持する。
	oversizedBytes.resize( 33554433U) ;
	require( computeDriverContainerSha256( oversizedBytes, hash) == 0, "TEST_LARGE_HASH") ;
	const std::array<CollectorSetupEmbeddedFile, 2> oversizedTotal{
		{{L"first", oversizedBytes, hash},
		 {L"second", oversizedBytes, hash}}} ;	// 個別上限内でも総量を拒否する。
	failures += !catchesStage(
		[&oversizedTotal]() {
			static_cast<void>( runCollectorSetupEmbedded( oversizedTotal, {}, false)) ;
		},
		"EMBEDDED_SIZE") ;
	// 書込み権限のない実handleのflush失敗も元code付き拒否へ接続する。
	failures +=
		!catchesStage( [&file]() { requireBool( FlushFileBuffers( file.get()), "EMBEDDED_FLUSH") ; },
					  "EMBEDDED_FLUSH") ;
	const fs::path knownFolder =
		root / L"fake-known-folder" ;	// 実user KnownFolderを使わない一階層fixture。
	fs::create_directory( knownFolder) ;
	prepareCollectorSetupDefaultParent( knownFolder) ;
	Handle defaultParent =
		// 新規作成した固定親。
		openChecked( knownFolder / L"DriverCrate", true, false) ;
	checkSecurity( defaultParent.get(), user, true, true) ;
	const std::wstring parentIdentity =
		// 二度目も同じ実体を要求する。
		directoryIdentity( knownFolder / L"DriverCrate") ;
	prepareCollectorSetupDefaultParent( knownFolder) ;
	failures += parentIdentity != directoryIdentity( knownFolder / L"DriverCrate") ;
	const fs::path fileKnown =
		root / L"file-known-folder" ;	// 通常fileの固定親を拒否する独立fixture。
	fs::create_directory( fileKnown) ;
	copyCollectorSetupProtectedFile( executable, fileKnown / L"DriverCrate") ;
	failures += !catchesStage( [&fileKnown]() { prepareCollectorSetupDefaultParent( fileKnown) ; },
							  "WORKSPACE_OBJECT") ;
	const fs::path badKnown =
		root / L"bad-known-folder" ;	// 既存の不適格ACLを修復しない独立fixture。
	fs::create_directory( badKnown) ;
	PSECURITY_DESCRIPTOR badRaw{} ;	// 新規不適格child作成だけに使うdescriptor。
	requireBool( ConvertStringSecurityDescriptorToSecurityDescriptorW(
					L"D:P(A;OICI;FA;;;WD)", SDDL_REVISION_1, &badRaw, nullptr),
				"TEST_BAD_SDDL") ;
	const Memory		badDescriptor( badRaw) ;	// 照会領域をfixture作成後に解放する。
	SECURITY_ATTRIBUTES badAttributes{sizeof( SECURITY_ATTRIBUTES), badDescriptor.get(),
									  FALSE} ;	// 作成時から不適格にする。
	requireBool( CreateDirectoryW( (badKnown / L"DriverCrate").c_str(), &badAttributes),
				"TEST_BAD_PARENT") ;
	const fs::path badFile = badKnown / L"DriverCrate" / L"bad.bin" ;	// 不適格親から継承したfile。
	copyCollectorSetupProtectedFile( executable, badFile) ;
	failures += !catchesStage( [&badFile]() { withCollectorSetupProtectedFile( badFile, [] {}) ; },
							  "WORKSPACE_CHILD_DACL") ;
	failures += !catchesStage( [&badKnown]() { prepareCollectorSetupDefaultParent( badKnown) ; },
							  "WORKSPACE_PROTECTED_DACL") ;
	std::vector<Handle> savedParents ;	// 保存前に検査した親を全検査終了まで固定する。
	std::wstring		oneHash ;		// 新規保存する一byteだけの期待hash。
	require( computeBytesSha256( "x", oneHash) == 0, "TEST_SAVED_HASH") ;
	const CollectorSetupEmbeddedFile nested{L"checked-parent/nested/one.json", "x",
											oneHash} ;	// 固定相対名。
	writeEmbeddedFile( root, nested, user, savedParents) ;
	std::wstring savedHash ;	// 実保存byteの観測。
	failures +=
		computeFileSha256( (root / nested.path).native(), savedHash) != 0 || savedHash != oneHash ;
	failures += savedParents.size() != 3U ;
	bool parentRenameRejected{} ;	// 保存前保持した子親の置換をOS共有契約で拒否する。
	try {
		fs::rename( root / L"checked-parent", root / L"checked-parent-changed") ;
	} catch( const fs::filesystem_error &) {
		parentRenameRejected = true ;
	}

	failures += !parentRenameRejected || !fs::exists( root / L"checked-parent") ;
	bool savedOverwriteRejected{} ;	// CREATE_NEWの既存byte保持を実helperで確認する。
	try {
		writeEmbeddedFile( root, nested, user, savedParents) ;
	} catch( const std::runtime_error &) {
		savedOverwriteRejected = true ;
	}

	failures += !savedOverwriteRejected ||
				computeFileSha256( (root / nested.path).native(), savedHash) != 0 ||
				savedHash != oneHash ;
	const CollectorSetupEmbeddedFile fileParent{L"retained.json/blocked.json", "x",
												oneHash} ;	// 既存通常fileの親。
	failures += !catchesStage( [&]() { writeEmbeddedFile( root, fileParent, user, savedParents) ; },
							  "WORKSPACE_OBJECT") ;
	std::wstring originalHash ;	// 親として拒否する既存fileの原byte。
	require( computeFileSha256( executable.native(), originalHash) == 0, "TEST_ORIGINAL_HASH") ;
	failures += computeFileSha256( target.native(), savedHash) != 0 || savedHash != originalHash ;
	const CollectorSetupEmbeddedFile badParentFile{L"bad-known-folder/DriverCrate/blocked.json",
												   "x", oneHash} ;	// 不適格ACL。
	failures += !catchesStage( [&]() { writeEmbeddedFile( root, badParentFile, user, savedParents) ; },
							  "WORKSPACE_CHILD_DACL") ||
				fs::exists( root / badParentFile.path) ;
	const fs::path outside = root / L"junction-outside" ;	// 同じ自作fixture内だけのlink先。
	fs::create_directory( outside) ;
	copyCollectorSetupProtectedFile( executable, outside / L"guard.bin") ;
	const fs::path junction = root / L"junction-parent" ;	// 通常子親の位置へ作る試験専用reparse。
	requireBool( CreateDirectoryW( junction.c_str(), nullptr), "TEST_JUNCTION_DIRECTORY") ;
	const std::wstring substitute = L"\\??\\" + outside.native() ;	// Windows mount pointの固定形式。
	const std::wstring names =
		substitute + L'\0' + outside.native() + L'\0' ;					// 二つの終端付きpath。
	const std::size_t namesBytes = names.size() * sizeof( wchar_t) ;	// 有限fixtureの実byte数。
	require( namesBytes <= 60000U, "TEST_JUNCTION_SIZE") ;
	std::vector<DWORD> mountPoint( (16U + namesBytes + sizeof( DWORD) - 1U) /
								  // Win32境界の整列領域。
								  sizeof( DWORD)) ;
	mountPoint[0] = IO_REPARSE_TAG_MOUNT_POINT ;
	// SDKのmount point wire layoutをDWORD整列領域へ対応付け、可変長二pathだけを格納する。
	auto *words = reinterpret_cast<WORD *>( mountPoint.data()) ;	// 固定headerの16bit field view。
	words[2]	= static_cast<WORD>( 8U + namesBytes) ;
	words[4]	= 0U ;
	words[5]	= static_cast<WORD>( substitute.size() * sizeof( wchar_t)) ;
	words[6]	= static_cast<WORD>( (substitute.size() + 1U) * sizeof( wchar_t)) ;
	words[7]	= static_cast<WORD>( outside.native().size() * sizeof( wchar_t)) ;
	std::memcpy( mountPoint.data() + 4U, names.data(), namesBytes) ;
	const Handle junctionHandle = own(
		CreateFileW( junction.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
					OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
					nullptr)) ;	// fixtureだけの作成handle。
	DWORD returned{} ;			// 固定IOCTLの元出力。
	requireBool( DeviceIoControl( junctionHandle.get(), FSCTL_SET_REPARSE_POINT, mountPoint.data(),
								static_cast<DWORD>( 16U + namesBytes), nullptr, 0U, &returned,
								nullptr),
				"TEST_JUNCTION_CREATE") ;
	failures += !catchesStage(
		[&junction]() { withCollectorSetupProtectedFile( junction / L"guard.bin", [] {}) ; },
		"WORKSPACE_OBJECT") ;
	const CollectorSetupEmbeddedFile junctionFile{L"junction-parent/blocked.json", "x",
												  oneHash} ;	// link先へ保存しない。
	failures += !catchesStage( [&]() { writeEmbeddedFile( root, junctionFile, user, savedParents) ; },
							  "WORKSPACE_OBJECT") ||
				fs::exists( outside / L"blocked.json") ;
	failures += computeFileSha256( (outside / L"guard.bin").native(), savedHash) != 0 ||
				savedHash != originalHash ;
	const CollectorSetupEmbeddedFile rootFile{L"root-byte.json", "x",
											  oneHash} ;	// root直下も保存前root検査を通る。
	writeEmbeddedFile( root, rootFile, user, savedParents) ;
	failures +=
		computeFileSha256( (root / rootFile.path).native(), savedHash) != 0 || savedHash != oneHash ;
	std::printf( "BOOTSTRAP_UNIT cases=57 failures=%zu network=0 retained=1\n", failures) ;
	return failures == 0U ? 0 : 1 ;
}

/** @brief 自己所有三fileでreview入力の実handle固定と拒否境界を確認します。
 * @return 全固定期待が成立した場合0、不一致なら1。
 * @note 製品Pythonと実workspaceは使わず、唯一build配下に人工fileを保持します。
 */
int heldReviewInputChecks()
{
	std::size_t			 failures{} ;		// 固定期待との差です。
	std::vector<wchar_t> module( 32768U) ;	// 自己EXEから唯一buildを解決します。
	const DWORD			 length = GetModuleFileNameW( nullptr, module.data(),
													 // 元文字数です。
													 static_cast<DWORD>( module.size())) ;
	require( length > 0U && length < module.size(), "HOST_REVIEW_TEST_SELF") ;
	const fs::path build = fs::path( module.data()).parent_path().parent_path() ;	// 唯一buildです。
	const fs::path directory =
		build / (L"held-review-" + std::to_wstring( GetCurrentProcessId()) + L"-" +
				 // 既存fixtureを上書きしません。
				 std::to_wstring( GetTickCount64())) ;
	createCollectorSetupProtectedRoot( directory) ;
	const fs::path request = directory / L"review-request.json" ;	// 内容判断はPython試験で行います。
	distributionSave( request, "{}") ;
	distributionSave( directory / L"baseline.raw.html", "<html>baseline</html>") ;
	distributionSave( directory / L"current.raw.html", "<html>baseline</html>") ;
	std::vector<Handle> handles ;	// 各試験窓の実file/祖先を保持します。
	failures += lockHeldHostReviewInputs( request, handles) != fileHash( request) ;
	const HANDLE competing =
		CreateFileW( request.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL, nullptr) ;	// 同じfileへの競合writeを試します。
	const DWORD competingError =
		// 元codeです。
		competing == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS ;
	failures += competing != INVALID_HANDLE_VALUE || competingError != ERROR_SHARING_VIOLATION ;
	// 予期せず取得できた場合も所有handleを解放して次の固定試験へ進みます。
	if( competing != INVALID_HANDLE_VALUE) {
		CloseHandle( competing) ;
	}

	handles.clear() ;
	const fs::path link = directory / L"hardlink.html" ;	// 同じ通常fileの二重linkだけを作ります。
	requireBool( CreateHardLinkW( link.c_str(), (directory / L"baseline.raw.html").c_str(), nullptr),
				"HOST_REVIEW_TEST_LINK") ;
	failures += !catchesStage(
		[&request, &handles]() { static_cast<void>( lockHeldHostReviewInputs( request, handles)) ; },
		"WORKSPACE_OBJECT") ;
	handles.clear() ;
	require( fs::remove( link), "HOST_REVIEW_TEST_LINK_REMOVE") ;
	const fs::path oversized = directory / L"oversized.json" ;	// 64KiBを一byteだけ超えます。
	distributionSave( oversized, std::string( 65537U, 'x')) ;
	failures += !catchesStage(
		[&oversized, &handles]() {
			static_cast<void>( lockHeldHostReviewInputs( oversized, handles)) ;
		},
		"HOST_REVIEW_INPUT_LIMIT") ;
	handles.clear() ;
	failures += !catchesStage(
		[&directory, &handles]() {
			static_cast<void>( lockHeldHostReviewInputs( directory / L"current.raw.html", handles)) ;
		},
		"HOST_REVIEW_REQUEST_NAME") ;
	const fs::path package	 = directory / L"package" ;		// 既知保護packageの人工rootです。
	const fs::path workspace = directory / L"workspace" ;	// originを持たない既存rootです。
	createCollectorSetupProtectedRoot( package) ;
	createCollectorSetupProtectedRoot( workspace) ;
	// 入力親と変更rootの重複を、package検査やchild開始前に拒否します。
	failures += !catchesStage(
		[&package, &workspace, &request]() {
			static_cast<void>( runCollectorSetupWorkspace( package, L"review-held-host", workspace,
														 request, [] {})) ;
		},
		"HOST_REVIEW_INPUT_OVERLAP") ;
	const fs::path separatePackage =
		build / (directory.filename().native() + L"-package") ;	// 入力親と別の保護rootです。
	const fs::path separateWorkspace =
		build / (directory.filename().native() + L"-workspace") ;	// origin未作成です。
	createCollectorSetupProtectedRoot( separatePackage) ;
	createCollectorSetupProtectedRoot( separateWorkspace) ;
	// 新操作を閉集合で受理した後、専用origin欠損をchild開始前に拒否します。
	failures += !catchesStage(
		[&separatePackage, &separateWorkspace, &request]() {
			static_cast<void>( runCollectorSetupWorkspace( separatePackage, L"review-held-host",
														 separateWorkspace, request, [] {})) ;
		},
		"WORKSPACE_SWITCH_ORIGIN_REQUIRED") ;
	// 未署名受渡しも変更rootへ重ねず、未知の原点を初期化して受理しません。
	failures += !catchesStage(
		[&separatePackage, &separateWorkspace]() {
			static_cast<void>( runCollectorSetupWorkspace(
				separatePackage, L"stage-candidate", separateWorkspace, separateWorkspace, [] {})) ;
		},
		"WORKSPACE_OVERLAP") ;
	const fs::path stage =
		build / (directory.filename().native() + L"-stage") ;	// 自己所有の空受渡し先です。
	createCollectorSetupProtectedRoot( stage) ;
	// 専用originを欠いた状態では子を開始せず、stage先を空のまま保持します。
	failures += !catchesStage(
		[&separatePackage, &separateWorkspace, &stage]() {
			static_cast<void>( runCollectorSetupWorkspace( separatePackage, L"stage-candidate",
														 separateWorkspace, stage, [] {})) ;
		},
		"WORKSPACE_SWITCH_ORIGIN_REQUIRED") ;
	writeOrigin( stage / L"unknown.bin", "retained") ;
	// 非空の既存先は上書きも清掃もしません。
	failures += !catchesStage(
		[&separatePackage, &separateWorkspace, &stage]() {
			static_cast<void>( runCollectorSetupWorkspace( separatePackage, L"stage-candidate",
														 separateWorkspace, stage, [] {})) ;
		},
		"CANDIDATE_STAGE_NOT_EMPTY") ;
	std::printf( "HELD_REVIEW_AND_STAGING_INPUT_UNIT cases=10 failures=%zu http=0 tasks=0\n",
				failures) ;
	return failures == 0U ? 0 : 1 ;
}

/** @brief 実子環境でOS由来driveとKnownFolder展開、拒否変数の欠損を照合します。
 * @return 全条件成功時0、不一致時1。
 * @note pathや環境値を出力せず、KnownFolderを照会するだけでfileを作成しません。
 */
int environmentChildChecks()
{
	std::size_t			 failures{} ;		// 非出力の期待値比較の不一致数。
	std::vector<wchar_t> windows( 32768U) ;	// 子自身が照会するOS pathを同容量で所有する。
	const UINT			 length =
		// 実文字数。
		GetWindowsDirectoryW( windows.data(), static_cast<UINT>( windows.size())) ;
	require( length > 3U && length < windows.size(), "TEST_CHILD_WINDOWS") ;
	std::vector<wchar_t> value( 32768U) ;	// 一設定を同容量・ゼロ初期値の領域で比較する。
	const DWORD			 driveLength = GetEnvironmentVariableW( L"SystemDrive", value.data(),
															   // 親の偽装値と異なるOS driveを要求する。
															   static_cast<DWORD>( value.size())) ;
	failures += driveLength != 2U ||
				std::wstring_view( value.data()) != std::wstring_view( windows.data(), 2U) ;
	const DWORD rootLength = GetEnvironmentVariableW( L"SystemRoot", value.data(),
													 // OS由来directoryも完全一致する。
													 static_cast<DWORD>( value.size())) ;
	failures += rootLength != length || std::wstring_view( value.data()) != windows.data() ;
	// 任意pathとuser環境が固定childへ流入しないことを一設定ずつ照会する。
	for( const auto name : {L"PATH", L"PYTHONPATH", L"PYTHONHOME", L"USERPROFILE", L"APPDATA",
						   L"LOCALAPPDATA", L"PROGRAMDATA", L"TEMP", L"TMP", L"HTTPS_PROXY",
						   L"HTTP_PROXY", L"ALL_PROXY", L"NO_PROXY"}) {
		SetLastError( ERROR_SUCCESS) ;
		const DWORD copied = GetEnvironmentVariableW( name, value.data(),
													 // 値はstdoutへ出さない。
													 static_cast<DWORD>( value.size())) ;
		const DWORD error  = copied == 0U ? GetLastError() : ERROR_SUCCESS ;	// 直後のcode。
		failures += copied != 0U || error != ERROR_ENVVAR_NOT_FOUND ;
	}

	PWSTR		  raw{} ;	// OSが返すCommonAppDataの所有領域。
	const HRESULT result = SHGetKnownFolderPath( FOLDERID_ProgramData, KF_FLAG_DONT_VERIFY, nullptr,
												&raw) ;	// 実pipelineと同じ非作成flag。
	const std::unique_ptr<wchar_t, decltype( &CoTaskMemFree)> folder(
		raw, &CoTaskMemFree) ;	// 全終了経路で解放する。
	winrt::check_hresult( result) ;
	require( folder != nullptr, "TEST_CHILD_KNOWN_FOLDER") ;
	const fs::path common( folder.get()) ;	// 未展開値は絶対path条件へ通らない。
	failures += !common.is_absolute() || common.native().find( L'%') != std::wstring::npos ||
				common.root_name().native() != std::wstring_view( windows.data(), 2U) ;
	std::printf( "CHILD_ENVIRONMENT cases=16 failures=%zu network=0 writes=0\n", failures) ;
	return failures == 0U ? 0 : 1 ;
}

/** @brief 実保護rootと固定fake子で用途別容量と操作前後の同じ判定を確認します。
 * @return 全境界が期待どおりなら0、不一致なら1。
 * @note 自己所有fixtureを唯一build直下へ保持し、運用dataや本物Pythonを使用しません。
 */
int capacityChecks()
{
	std::size_t			 failures{} ;		// 固定境界との不一致数。
	std::vector<wchar_t> module( 32768U) ;	// 自己EXEの所有path buffer。
	const DWORD			 length =
		// 元文字数。
		GetModuleFileNameW( nullptr, module.data(), static_cast<DWORD>( module.size())) ;
	require( length > 0U && length < module.size(), "CAPACITY_TEST_SELF") ;
	const fs::path executable( module.data()) ;	// 製品Pythonではない専用fake image。
	GUID		   id{} ;						// 自己所有fixtureの一意名。
	winrt::check_hresult( CoCreateGuid( &id)) ;
	std::array<wchar_t, 40> name{} ;	// 固定GUID文字列容量。
	require( StringFromGUID2( id, name.data(), static_cast<int>( name.size())) > 0,
			"CAPACITY_TEST_GUID") ;
	const fs::path parent =
		executable.parent_path().parent_path() /
		(L"collector-capacity-unit-" + std::wstring( name.data())) ;	// 唯一build直下の試験親。
	createCollectorSetupProtectedRoot( parent) ;
	const fs::path package = parent / L"package" ;		// 全byte検査callbackだけをfakeとする。
	const fs::path root	   = parent / L"workspace" ;	// native事前/最終がともに検査する実root。
	createCollectorSetupProtectedRoot( package) ;
	createCollectorSetupProtectedRoot( root) ;
	fs::create_directory( package / L"runtime") ;
	fs::create_directory( package / L"scripts") ;
	copyCollectorSetupProtectedFile( executable, package / L"runtime/python.exe") ;
	writeOrigin( package / L"scripts/collector_workspace.py", "# fixed fake child only\n") ;
	const auto			token = userToken() ;	// 全実handle検査中に借用SIDを保持する。
	// OS token境界で返された所有bufferのTOKEN_USERだけを参照する。
	PSID				user = reinterpret_cast<const TOKEN_USER *>( token.data())->User.Sid ;
	std::vector<Handle> handles ;	// 検査終了後だけ解放してfixtureを更新する。
	// 各fileを16MiBちょうどで保持し、総64MiBのpackage従来境界を作る。
	for( unsigned index = 0U; index < 4U; ++index) {
		const fs::path file = root / (std::to_wstring( index) + L".bin") ;	// 一意な試験file。
		writeOrigin( file, "x") ;
		fs::resize_file( file, 16U * 1024U * 1024U) ;
	}

	inspectTree( root, user, true, handles, DISTRIBUTION_JSON_MAXIMUM_BYTES,
				PACKAGE_TOTAL_MAXIMUM_BYTES) ;
	handles.clear() ;
	const fs::path tail = root / L"4.bin" ;	// 総64MiBの直後一byte。
	writeOrigin( tail, "x") ;
	failures += !catchesStage(
		[&]() {
			inspectTree( root, user, true, handles, DISTRIBUTION_JSON_MAXIMUM_BYTES,
						PACKAGE_TOTAL_MAXIMUM_BYTES) ;
		},
		"WORKSPACE_BYTE_LIMIT") ;
	handles.clear() ;
	std::size_t verifiedPackages{} ;	// 本物package/通信へ進めない同期fake callbackの回数。
	const auto	verifyPackage = [&verifiedPackages]() {
		 ++verifiedPackages ;
	} ; // 呼出し全体で同期借用する。
	failures += runCollectorSetupWorkspace( package, L"verify", root, {}, verifyPackage) != 0 ;
	failures += verifiedPackages != 1U ;
	fs::resize_file( tail, 16U * 1024U * 1024U) ;
	// 全16fileの実合計を256MiBへ揃え、保持rootのちょうど境界を検査する。
	for( unsigned index = 5U; index < 16U; ++index) {
		const fs::path file = root / (std::to_wstring( index) + L".bin") ;	// 既存fileと重複しない。
		writeOrigin( file, "x") ;
		fs::resize_file( file, 16U * 1024U * 1024U) ;
	}

	// 定数の用途別契約は実行時比較へ渡さず、compile時に固定する。
	static_assert( WORKSPACE_TOTAL_MAXIMUM_BYTES == 268435456U) ;
	static_assert( PACKAGE_TOTAL_MAXIMUM_BYTES == 67108864U) ;
	failures += runCollectorSetupWorkspace( package, L"verify", root, {}, verifyPackage) != 0 ;
	const fs::path excess = root / L"one-byte-over.bin" ;	// 旧fileを減らさず超過を作る。
	writeOrigin( excess, "x") ;
	failures += !catchesStage(
		[&]() {
			static_cast<void>(
				runCollectorSetupWorkspace( package, L"verify", root, {}, verifyPackage)) ;
		},
		"WORKSPACE_BYTE_LIMIT") ;
	// 事前root検査より先のpackage検査だけが呼ばれる。
	failures += verifiedPackages != 3U ;
	const fs::path oversized = parent / L"oversized-file" ;	// 一file上限の独立fixture。
	createCollectorSetupProtectedRoot( oversized) ;
	writeOrigin( oversized / L"file.bin", "x") ;
	fs::resize_file( oversized / L"file.bin", 16777217U) ;
	failures += !catchesStage(
		[&]() {
			inspectTree( oversized, user, false, handles, DISTRIBUTION_JSON_MAXIMUM_BYTES,
						WORKSPACE_TOTAL_MAXIMUM_BYTES) ;
		},
		"WORKSPACE_BYTE_LIMIT") ;
	std::printf( "WORKSPACE_CAPACITY_UNIT cases=11 failures=%zu fake_child=1 network=0 retained=1\n",
				failures) ;
	return failures == 0U ? 0 : 1 ;
}
} // namespace
} // namespace drivercrate

/** @brief 非通信の固定helper試験を実行します。
 * @param[in] count test専用の固定fake modeの引数数。
 * @param[in] args test専用の固定fake mode。
 * @return 全検査成功時0、失敗時1。fake子では指定の固定終了値。
 */
int wmain( const int count, wchar_t *args[])
{
	// 本物native adapterの固定argvだけを受ける専用fake子であり、製品Pythonを実行しない。
	if( count == 9 && args != nullptr && std::wstring_view( args[1]) == L"-I" &&
	   std::wstring_view( args[2]) == L"-B" && std::wstring_view( args[3]) == L"-S" &&
	   std::wstring_view( args[6]) == L"verify") {
		std::printf( "WORKSPACE_CAPACITY_FAKE_CHILD network=0 writes=0\n") ;
		return 0 ;
	}

	// 固定fake子は製品CLIへ存在せず、実setupや通信を実行しない。
	if( count == 2 && args != nullptr) {
		const std::wstring_view mode( args[1]) ;	// test helperが固定した一mode。
		// 実child内だけでKnownFolderと固定環境を照合し、製品操作は実行しない。
		if( mode == L"--fixture-environment") {
			try {
				return drivercrate::environmentChildChecks() ;
			} catch( const std::exception &) {
				std::printf( "CHILD_ENVIRONMENT_EXCEPTION\n") ;
				return 1 ;
			}
		}

		// 成功の元0を実processで確認する。
		if( mode == L"--fixture-success") {
			return 0 ;
		}

		// 拒否の元2を実processで確認する。
		if( mode == L"--fixture-refused") {
			return 2 ;
		}

		// 取消しの元3を実processで確認する。
		if( mode == L"--fixture-cancelled") {
			return 3 ;
		}

		// crashを発生させず、未知のDWORD bit列だけを終了値にする。
		if( mode == L"--fixture-unknown") {
			ExitProcess( 0xC0000005U) ;
		}

		// 親の短いtimeoutでjob回収される待機専用fake。
		if( mode == L"--fixture-sleep") {
			Sleep( 1000U) ;
			return 0 ;
		}

		return 2 ;
	}

	try {
		return drivercrate::workspaceChecks() | drivercrate::bootstrapChecks() |
			   drivercrate::capacityChecks() | drivercrate::heldReviewInputChecks() ;
	} catch( const std::exception &error) {
		std::printf( "BOOTSTRAP_UNIT_EXCEPTION stage=%s\n", error.what()) ;
		return 1 ;
	} catch( ...) {
		std::printf( "BOOTSTRAP_UNIT_EXCEPTION stage=UNKNOWN\n") ;
		return 1 ;
	}
}
