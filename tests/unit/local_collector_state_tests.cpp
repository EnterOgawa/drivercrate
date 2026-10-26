//------------------------------------------------------------------------------
/**
 * @file local_collector_state_tests.cpp
 * @brief 非通信の実filesystem fixtureで収集台帳の権限境界を検証します。
 * @version 01.00.06
 * @date 2026/09/25
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/25  新規ACL、非変更拒否、制限token試験を追加。
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.00.02   Shunji Ogawa  2026/10/17 既存writerの正常再開と欠損非作成を確認。
 * Ver.01.00.03   Shunji Ogawa  2026/10/18 長いlegacy子の欠損・保存・再開と保護境界を検証。
 * Ver.01.00.04   Shunji Ogawa  2026/10/18 既知fixtureの回収I/Oを長path対応表記へ揃える。
 * Ver.01.00.05   Shunji Ogawa  2026/10/18 関数localのmount point wire型に所有権と配置契約を追記。
 * Ver.01.00.06 Shunji Ogawa  2026/10/24  必須解析に合わせ試験の所有・型・失敗制御を明示。
 * </pre>
 *
 * @note 自身で新規作成した架空台帳だけを変更します。networkと実driverを使いません。
 */
//------------------------------------------------------------------------------

#include "platform/local_collector_state_store.h"
#include "test_framework.h"

#include <aclapi.h>
#include <sddl.h>
#include <objbase.h>
#include <winioctl.h>
#include <array>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {

/** @brief fixtureで取得したWin32 handleを解放します。 */
struct HandleCloser {
	/** @brief nullへ正規化済みでない有効handleを閉じます。
     * @param[in] value unique_ptrが所有する有効handle。
     */
	void operator()( void *value) const noexcept
	{
		CloseHandle( value) ;
	}
} ;
/** @brief fixtureのsecurity descriptor等を解放します。 */
struct MemoryCloser {
	/** @brief APIから返ったLocalAlloc bufferを返します。
     * @param[in] value LocalFreeへ渡せる有効buffer。
     */
	void operator()( void *value) const noexcept
	{
		LocalFree( value) ;
	}
} ;
/**
 * @brief 所有したWindows handleをscope終端で解放する。解放手順と無効値はHandleCloserに従う。
 */
using Handle = std::unique_ptr<void, HandleCloser> ;
/**
 * @brief LocalAlloc系の所有領域をscope終端でLocalFreeへ返す。
 */
using Memory = std::unique_ptr<void, MemoryCloser> ;

/** @brief setup不成立をassertion成功のように続行しません。
 * @param[in] condition 必須setupが成功した場合true。
 * @throws std::runtime_error setup不成立の場合。
 */
void require( bool condition)
{
	// 必須fixtureを作れない環境では試験全体を失敗させる。
	if( !condition) {
		throw std::runtime_error( "collector fixture setup failed") ;
	}
}

/** @brief 既知fixture pathにだけ使うSDDLをAPIで構築します。
 * @param[in] sddl 終端null付きの試験用SDDL。
 * @return 構築したdescriptorのowner。
 */
[[nodiscard]] Memory descriptor( const wchar_t *sddl)
{
	// APIから返るdescriptorの一時所有。
	PSECURITY_DESCRIPTOR raw{} ;
	require( ConvertStringSecurityDescriptorToSecurityDescriptorW( sddl, SDDL_REVISION_1, &raw,
																 nullptr) != FALSE) ;
	return Memory( raw) ;
}

/** @brief 既存権限が書き換わっていないことを比較するための文字列を返します。
 * @param[in] path 自身が作成したfixtureのpath。
 * @return 出力せず比較にだけ使うownerとDACLのSDDL。
 */
[[nodiscard]] std::wstring securitySnapshot( const std::filesystem::path &path)
{
	// OSが返す実descriptor。
	PSECURITY_DESCRIPTOR raw{} ;
	require( GetNamedSecurityInfoW( path.c_str(), SE_FILE_OBJECT,
								  OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr,
								  nullptr, nullptr, nullptr, &raw) == ERROR_SUCCESS) ;
	// Descriptorをscope終了時に回収する。
	const Memory security( raw) ;
	// 比較にだけ使いログへ出さないSDDL。
	LPWSTR		 text{} ;
	require( ConvertSecurityDescriptorToStringSecurityDescriptorW(
				security.get(), SDDL_REVISION_1,
				OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &text, nullptr) != FALSE) ;
	// 文字列bufferの回収。
	const Memory allocation( text) ;
	return std::wstring( text) ;
}

/** @brief 自身が作ったfixtureのDACLだけを意図的に緩めます。
 * @param[in] path 変更を許可するfixtureのpath。
 * @param[in] directory trueなら子へ継承するflagを加えます。
 */
void broaden( const std::filesystem::path &path, bool directory)
{
	// 危険な既存root／fileを模擬するEveryone full control。
	const auto security = descriptor( directory ? L"D:P(A;OICI;FA;;;WD)" : L"D:P(A;;FA;;;WD)") ;
	require( SetFileSecurityW( path.c_str(),
							 DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
							 security.get()) != FALSE) ;
}

/** @brief 比較用の架空本文だけを通常fileから読みます。
 * @param[in] path 自身が作成した有限のfixture file。
 * @return fixtureの架空本文。
 */
[[nodiscard]] std::string contents( const std::filesystem::path &path)
{
	// 自身が新規作成した非秘密fixtureだけを読み取るstream。
	std::ifstream file( path, std::ios::binary) ;
	require( static_cast<bool>( file)) ;
	return std::string( std::istreambuf_iterator<char>( file), std::istreambuf_iterator<char>()) ;
}

/** @brief 初期ACLが緩いstagingを自身のfixture内だけに作成します。
 * @param[in] path 未存在のfixture file名。
 */
void writeBroadFixture( const std::filesystem::path &path)
{
	// Everyoneを許可する意図的な不正descriptor。
	const auto			security = descriptor( L"D:P(A;;FA;;;WD)") ;
	// 新規作成時から不正policyを与える。
	SECURITY_ATTRIBUTES attributes{sizeof( SECURITY_ATTRIBUTES), security.get(), FALSE} ;
	// 既存fileを上書きしないcreate-only handle。
	const HANDLE		raw = CreateFileW( path.c_str(), GENERIC_WRITE, 0U, &attributes, CREATE_NEW,
										  FILE_ATTRIBUTE_NORMAL, nullptr) ;
	require( raw != INVALID_HANDLE_VALUE) ;
	// fixture fileの回収。
	const Handle file( raw) ;
	// 書き換わっていないことを後で確認するbyte数。
	DWORD		 written{} ;
	require( WriteFile( file.get(), "keep-fixture", 12U, &written, nullptr) && written == 12U) ;
}

/** @brief 同じuserにEveryone制限SIDを加え、実openで追加のACL判定を通します。
 * @param[in,out] context 読取り・書込み拒否の集計先。
 * @param[in] file 正規のACLで作られたfixture file。
 */
void restrictedOpenChecks( TestContext &context, const std::filesystem::path &file)
{
	// 制限tokenの元となるprocess token。
	HANDLE rawToken{} ;
	require( OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &rawToken) !=
			FALSE) ;
	// Process tokenの単独所有。
	const Handle							token( rawToken) ;
	// 制限SIDを構築する有限buffer。
	std::array<BYTE, SECURITY_MAX_SID_SIZE> world{} ;
	// APIへ渡すSID buffer長。
	DWORD									worldBytes = static_cast<DWORD>( world.size()) ;
	require( CreateWellKnownSid( WinWorldSid, nullptr, world.data(), &worldBytes) != FALSE) ;
	// 通常user権限に加えてEveryoneの許可も必要とする制限。
	SID_AND_ATTRIBUTES restricting{world.data(), 0U} ;
	// 作成した制限token。
	HANDLE			   rawRestricted{} ;
	require( CreateRestrictedToken( token.get(), DISABLE_MAX_PRIVILEGE, 0U, nullptr, 0U, nullptr, 1U,
								  &restricting, &rawRestricted) != FALSE) ;
	// 制限tokenを試験終了時に閉じる。
	const Handle restricted( rawRestricted) ;
	require( ImpersonateLoggedOnUser( restricted.get()) != FALSE) ;
	// Revertまでallocationや例外を起こす操作を挟まず、元errorを即時保存する。
	const HANDLE readHandle = CreateFileW( file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
										  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) ;
	// 読取り拒否の元error。
	const DWORD	 readError = GetLastError() ;
	// 同じtokenで変更権限も要求する。
	const HANDLE writeHandle = CreateFileW( file.c_str(), GENERIC_WRITE, 0U, nullptr, OPEN_EXISTING,
										   FILE_ATTRIBUTE_NORMAL, nullptr) ;
	// 書込み拒否の元error。
	const DWORD	 writeError = GetLastError() ;
	// Assertionや出力より前に必ず元のthread identityへ戻す。
	const BOOL	 reverted = RevertToSelf() ;
	const bool	 readRejected =
		// 解放前に確定した元open拒否です。
		readHandle == INVALID_HANDLE_VALUE ;
	const bool writeRejected =
		// 解放後のhandle値を再利用しません。
		writeHandle == INVALID_HANDLE_VALUE ;
	// 万一openが成功してもresourceを回収する。
	if( readHandle != INVALID_HANDLE_VALUE) {
		CloseHandle( readHandle) ;
	}

	// 書込み成功時のhandleも回収する。
	if( writeHandle != INVALID_HANDLE_VALUE) {
		CloseHandle( writeHandle) ;
	}

	require( reverted != FALSE) ;
	DRIVERCRATE_EXPECT( context, readRejected && readError == ERROR_ACCESS_DENIED) ;
	DRIVERCRATE_EXPECT( context, writeRejected && writeError == ERROR_ACCESS_DENIED) ;
}

/** @brief 正常read/write、制限token、再開、同時writer、staging拒否を確認します。
 * @param[in,out] context 検証結果の集計先。
 * @param[in] root 未存在のscenario root。
 */
void normalAndStaging( TestContext &context, const std::filesystem::path &root)
{
	// 最初のwriterだけがlockを所有する。
	LocalCollectorStateStore store ;
	DRIVERCRATE_EXPECT( context, store.initialize( root, true) == ERROR_SUCCESS) ;
	DRIVERCRATE_EXPECT( context, store.write( L"runs/a.json", "old-checkpoint") == ERROR_SUCCESS) ;
	DRIVERCRATE_EXPECT( context, store.write( L"current/a.json", "pointer") == ERROR_SUCCESS) ;
	// 保持中のrootは親のDELETE_CHILD権限があってもrenameできない。
	DRIVERCRATE_EXPECT( context,
					   !MoveFileExW( root.c_str(), (root.parent_path() / L"renamed").c_str(), 0U)) ;
	DRIVERCRATE_EXPECT( context, !std::filesystem::exists( root.parent_path() / L"renamed")) ;
	// 読取り成功と未存在を分離する出力。
	std::string bytes ;
	// 同じ出力変数を再利用して初期化も検査する。
	bool		found{} ;
	DRIVERCRATE_EXPECT( context, store.read( L"runs/a.json", bytes, found) == ERROR_SUCCESS &&
									found && bytes == "old-checkpoint") ;
	DRIVERCRATE_EXPECT( context, store.read( L"runs/missing.json", bytes, found) == ERROR_SUCCESS &&
									!found && bytes.empty()) ;
	DRIVERCRATE_EXPECT( context, store.write( L"../escape.json", "bad") == ERROR_INVALID_PARAMETER) ;
	restrictedOpenChecks( context, root / L"runs/a.json") ;
	// 二つ目のwriterは同じlockを保持できない。
	LocalCollectorStateStore duplicate ;
	DRIVERCRATE_EXPECT( context, duplicate.initialize( root, true) == ERROR_SHARING_VIOLATION) ;
	// 起動後に不正stagingを置いても書込み時の検査で止める。
	const auto temporary = root / L"runs/a.json.tmp" ;
	writeBroadFixture( temporary) ;
	// 拒否前のDACLを記録する。
	const auto before = securitySnapshot( temporary) ;
	DRIVERCRATE_EXPECT( context,
					   store.write( L"runs/a.json", "new-checkpoint") == ERROR_ACCESS_DENIED) ;
	DRIVERCRATE_EXPECT( context, contents( temporary) == "keep-fixture") ;
	DRIVERCRATE_EXPECT( context, securitySnapshot( temporary) == before) ;
	DRIVERCRATE_EXPECT( context, store.read( L"runs/a.json", bytes, found) == ERROR_SUCCESS &&
									found && bytes == "old-checkpoint") ;
	require( DeleteFileW( temporary.c_str()) != FALSE) ;
	DRIVERCRATE_EXPECT( context, store.write( L"runs/a.json", "new-checkpoint") == ERROR_SUCCESS) ;
}

/** @brief 通常表記で260文字を超えるlegacy子の不在と保護I/Oを確認します。
 * @param[in,out] context 有限な非通信回帰の集計先。
 * @param[in] root GUID fixture内の未存在legacy root。
 * @throws std::runtime_error fixtureの長さまたはsecurity照会が成立しない場合。
 */
void longLegacyChild( TestContext &context, const std::filesystem::path &root)
{
	// safeRelativeの160文字上限内で、総pathだけを300～400文字に固定する。
	const auto relative = std::filesystem::path( L"current") / (std::wstring( 128U, L'a') + L".json") ;
	// 試験側の属性・ACL照会も同じ自作fileをextended表記で開く。
	const std::filesystem::path extended( L"\\\\?\\" + (root / relative).make_preferred().native()) ;
	// 実行環境差で短いpathの成功を長pathの合格へ数えない。
	require( (root / relative).native().size() >= 300U && (root / relative).native().size() <= 400U) ;
	std::wstring originalSecurity ;	// 作成後と再開後のowner／DACLを同値比較する。
	{
		LocalCollectorStateStore store ;	// 旧layoutのwriterだけを使用する。
		DRIVERCRATE_EXPECT( context, store.initialize( root, true) == ERROR_SUCCESS) ;
		std::string bytes = "must-clear" ;	// 不在readでも出力初期化を検査する。
		bool		found = true ;			// 既存値を不在へ戻すことを確認する。
		DRIVERCRATE_EXPECT( context, store.read( relative, bytes, found) == ERROR_SUCCESS && !found &&
										bytes.empty()) ;
		const DWORD attributes	= GetFileAttributesW( extended.c_str()) ;	// 非作成の実観測。
		const DWORD absentError = GetLastError() ;							// 次のAPIで不在2を失わない。
		DRIVERCRATE_EXPECT( context, attributes == INVALID_FILE_ATTRIBUTES &&
										absentError == ERROR_FILE_NOT_FOUND) ;
		std::vector<std::wstring> names ;	// 未存在照会前後の確定file一覧。
		DRIVERCRATE_EXPECT( context,
						   store.listCurrentNames( names) == ERROR_SUCCESS && names.empty()) ;
		DRIVERCRATE_EXPECT( context, store.write( relative, "legacy-checkpoint") == ERROR_SUCCESS) ;
		DRIVERCRATE_EXPECT( context, store.read( relative, bytes, found) == ERROR_SUCCESS && found &&
										bytes == "legacy-checkpoint") ;
		DRIVERCRATE_EXPECT( context,
						   store.listCurrentNames( names) == ERROR_SUCCESS &&
							   names == std::vector<std::wstring>{relative.filename().native()}) ;
		originalSecurity = securitySnapshot( extended) ;
		restrictedOpenChecks( context, extended) ;
		DRIVERCRATE_EXPECT( context, store.read( L"current/../escape.json", bytes, found) ==
											ERROR_INVALID_PARAMETER &&
										!found && bytes.empty()) ;
		DRIVERCRATE_EXPECT( context,
						   store.write( L"../escape.json", "bad") == ERROR_INVALID_PARAMETER) ;
		LocalCollectorStateStore duplicate ;	// 同じrootの二重writerを拒否する。
		DRIVERCRATE_EXPECT( context, duplicate.initialize( root, true) == ERROR_SHARING_VIOLATION) ;
	}
	{
		LocalCollectorStateStore reopened ;	// 非作成入口で同じ実fileを再監査する。
		DRIVERCRATE_EXPECT( context, reopened.initializeExistingWriter( root) == ERROR_SUCCESS) ;
		std::string bytes ;		// 再開後に実handleから取得する本文。
		bool		found{} ;	// 実readの存在状態。
		DRIVERCRATE_EXPECT( context, reopened.read( relative, bytes, found) == ERROR_SUCCESS &&
										found && bytes == "legacy-checkpoint") ;
		DRIVERCRATE_EXPECT( context, securitySnapshot( extended) == originalSecurity) ;
	}
}

/** @brief 既存の緩いrootを修復・更新せず拒否することを確認します。
 * @param[in,out] context 検証結果の集計先。
 * @param[in] root 未存在のscenario root。
 */
void unsafeRoot( TestContext &context, const std::filesystem::path &root)
{
	require( CreateDirectoryW( root.c_str(), nullptr) != FALSE) ;
	broaden( root, true) ;
	writeBroadFixture( root / L"marker.json") ;
	// 拒否前のACLを比較用に保持する。
	const auto				 before = securitySnapshot( root) ;
	// 非通信で初期化だけを試す。
	LocalCollectorStateStore store ;
	DRIVERCRATE_EXPECT( context, store.initialize( root, true) == ERROR_ACCESS_DENIED) ;
	DRIVERCRATE_EXPECT( context, store.initialize( root, false) == ERROR_ACCESS_DENIED) ;
	DRIVERCRATE_EXPECT( context, securitySnapshot( root) == before) ;
	DRIVERCRATE_EXPECT( context, contents( root / L"marker.json") == "keep-fixture") ;
	DRIVERCRATE_EXPECT( context, !std::filesystem::exists( root / L"collector.lock")) ;
	DRIVERCRATE_EXPECT( context, !std::filesystem::exists( root / L"runs")) ;
}

/** @brief directoryとfileの双方で子のACL緩和を検出します。
 * @param[in,out] context 検証結果の集計先。
 * @param[in] root 未存在のscenario root。
 * @param[in] directory trueなら子directory、falseならfileを不正化します。
 */
void unsafeChild( TestContext &context, const std::filesystem::path &root, bool directory)
{
	{
		// 正規のstate storeでfixtureを作る。
		LocalCollectorStateStore store ;
		require( store.initialize( root, true) == ERROR_SUCCESS) ;
		require( store.write( L"runs/a.json", "keep-child") == ERROR_SUCCESS) ;
	}
	// 意図的に不正化する自作fixtureのpath。
	const auto target = directory ? root / L"runs" : root / L"runs/a.json" ;
	broaden( target, directory) ;
	// 拒否でACLが修復されないことを照合する。
	const auto				 before = securitySnapshot( target) ;
	// 次回起動時の全階層監査。
	LocalCollectorStateStore store ;
	DRIVERCRATE_EXPECT( context, store.initialize( root, true) == ERROR_ACCESS_DENIED) ;
	DRIVERCRATE_EXPECT( context, securitySnapshot( target) == before) ;
	DRIVERCRATE_EXPECT( context, contents( root / L"runs/a.json") == "keep-child") ;
}

/** @brief 二つの名前を持つfileを台帳として再採用しません。
 * @param[in,out] context 検証結果の集計先。
 * @param[in] root 未存在のscenario root。
 */
void hardLink( TestContext &context, const std::filesystem::path &root)
{
	{
		// 署名でなく架空本文だけを保存する。
		LocalCollectorStateStore store ;
		require( store.initialize( root, true) == ERROR_SUCCESS) ;
		require( store.write( L"runs/a.json", "keep-link") == ERROR_SUCCESS) ;
	}
	require( CreateHardLinkW( (root / L"runs/alias.json").c_str(), (root / L"runs/a.json").c_str(),
							nullptr) != FALSE) ;
	// hard link数を実handleで検査する。
	LocalCollectorStateStore store ;
	DRIVERCRATE_EXPECT( context, store.initialize( root, true) == ERROR_ACCESS_DENIED) ;
	DRIVERCRATE_EXPECT( context, contents( root / L"runs/alias.json") == "keep-link") ;
}

/** @brief 同じfixture内の空directoryへjunctionを設定します。
 * @param[in] path 自作fixture内の空directory。
 * @param[in] target 同じfixture内の参照先directory。
 */
void makeJunction( const std::filesystem::path &path, const std::filesystem::path &target)
{
	// 実際のreparse pointを設定するためのdirectory handle。
	const HANDLE raw =
		CreateFileW( path.c_str(), GENERIC_WRITE, 0U, nullptr, OPEN_EXISTING,
					FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;
	require( raw != INVALID_HANDLE_VALUE) ;
	// junction設定後にhandleを閉じる。
	const Handle	   directory( raw) ;
	// Windows mount pointのsubstitute名。
	const std::wstring substitute = L"\\??\\" + target.native() ;
	// Print名には同じテスト用targetを使う。
	const std::wstring printable = target.native() ;
	// mount point形式の固定header。続けてUTF-16の二文字列を置く。
	/**
	 * @brief makeJunction内でmount point設定の固定16 byte wire headerを表します。
	 *
	 * header直後のUTF-16文字列領域を基準とするsubstitute名とprint名のoffsetと、
	 * 終端nullを含まないbyte長を保持します。bytesは先頭8 byteを除いた全data長です。
	 * @note 値だけを保持し、文字列・buffer・directory handleを所有しません。
	 *       headerをbufferへ複写し、DeviceIoControlの同期呼出しが戻るまで、
	 *       makeJunctionがbufferとhandleの寿命を維持します。
	 */
	struct JunctionHeader {
		/// mount pointのreparse tag。
		DWORD tag ;
		/// 先頭8 byteを除いたdata長。
		WORD  bytes ;
		/// 予約領域。
		WORD  reserved ;
		/// substitute文字列の開始offset。
		WORD  substituteOffset ;
		/// substitute文字列のbyte長。
		WORD  substituteBytes ;
		/// print文字列の開始offset。
		WORD  printOffset ;
		/// print文字列のbyte長。
		WORD  printBytes ;
	} ;
	static_assert( sizeof( JunctionHeader) == 16U) ;
	// 二つの文字列を終端null込みで収めるbuffer。
	std::vector<BYTE> buffer( 16U + (substitute.size() + printable.size() + 2U) * sizeof( wchar_t)) ;
	require( buffer.size() < MAXIMUM_REPARSE_DATA_BUFFER_SIZE) ;
	// APIの固定wire形式に限定したbyte長。
	const JunctionHeader header{IO_REPARSE_TAG_MOUNT_POINT,
								static_cast<WORD>( buffer.size() - 8U),
								0U,
								0U,
								static_cast<WORD>( substitute.size() * sizeof( wchar_t)),
								static_cast<WORD>( (substitute.size() + 1U) * sizeof( wchar_t)),
								static_cast<WORD>( printable.size() * sizeof( wchar_t))} ;
	std::memcpy( buffer.data(), &header, sizeof( header)) ;
	std::memcpy( buffer.data() + 16U, substitute.c_str(),
				(substitute.size() + 1U) * sizeof( wchar_t)) ;
	std::memcpy( buffer.data() + 16U + header.printOffset, printable.c_str(),
				(printable.size() + 1U) * sizeof( wchar_t)) ;
	// DeviceIoControlの返却byte数。
	DWORD returned{} ;
	require( DeviceIoControl( directory.get(), FSCTL_SET_REPARSE_POINT, buffer.data(),
							static_cast<DWORD>( buffer.size()), nullptr, 0U, &returned,
							nullptr) != FALSE) ;
}

/** @brief reparse経由で別領域へ書込まないことを実junctionで検証します。
 * @param[in,out] context 検証結果の集計先。
 * @param[in] root 未存在のscenario root。
 * @param[in] target fixture内の未存在junction参照先。
 */
void reparse( TestContext &context, const std::filesystem::path &root,
			 const std::filesystem::path &target)
{
	{
		// 空の正規領域を準備する。
		LocalCollectorStateStore store ;
		require( store.initialize( root, true) == ERROR_SUCCESS) ;
	}
	require( CreateDirectoryW( target.c_str(), nullptr) != FALSE) ;
	writeBroadFixture( target / L"marker.json") ;
	makeJunction( root / L"runs", target) ;
	// 対象dirを辿る前にreparseを拒否する。
	LocalCollectorStateStore store ;
	DRIVERCRATE_EXPECT( context, store.initialize( root, true) == ERROR_ACCESS_DENIED) ;
	DRIVERCRATE_EXPECT( context, contents( target / L"marker.json") == "keep-fixture") ;
	DRIVERCRATE_EXPECT( context, !std::filesystem::exists( target / L"collector.lock")) ;
}

/** @brief descriptor形式の許可外owner、null DACL、継承、未知ACEを確認します。
 * @param[in,out] context 検証結果の集計先。
 * @param[in] file 正規ACLを持つfixture file。
 */
void descriptorChecks( TestContext &context, const std::filesystem::path &file)
{
	// 既に作成した正規fileのsecurity descriptor。
	PSECURITY_DESCRIPTOR raw{} ;
	// 正規fileのownerは実行user。
	PSID				 owner{} ;
	require( GetNamedSecurityInfoW( file.c_str(), SE_FILE_OBJECT,
								  OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
								  nullptr, nullptr, nullptr, &raw) == ERROR_SUCCESS) ;
	// Descriptorとownerのborrowed lifetimeを揃える。
	const Memory valid( raw) ;
	DRIVERCRATE_EXPECT( context, isLocalCollectorDescriptorAllowed( valid.get(), owner, false)) ;
	DRIVERCRATE_EXPECT( context, !isLocalCollectorDescriptorAllowed( valid.get(), owner, true)) ;
	DRIVERCRATE_EXPECT( context, !isLocalCollectorDescriptorAllowed( nullptr, owner, false)) ;
	// ownerだけを許可外SIDへ変え、DACLが正しくても拒否されることを確認する。
	const auto original = securitySnapshot( file) ;
	// 元DACLをそのまま保持する文字列位置。
	const auto daclOffset = original.find( L"D:") ;
	require( daclOffset != std::wstring::npos) ;
	// ownerはEveryone、DACLは実際に作成された三principalのまま。
	const auto invalid = descriptor( (L"O:WD" + original.substr( daclOffset)).c_str()) ;
	DRIVERCRATE_EXPECT( context, !isLocalCollectorDescriptorAllowed( invalid.get(), owner, false)) ;
	// 許可外SIDを一件加えただけのDACLも拒否する。
	const auto extra = descriptor( (original + L"(A;;FR;;;WD)").c_str()) ;
	DRIVERCRATE_EXPECT( context, !isLocalCollectorDescriptorAllowed( extra.get(), owner, false)) ;
	// 形式上有効でもnull DACLは許可しない。
	const auto absent = descriptor( (original.substr( 0U, daclOffset) + L"D:PNO_ACCESS_CONTROL")
									   .c_str()) ;			// 実fileへ適用しないRAM内のnull DACL。
	PACL	   absentAcl{} ;								// NULLを空ACLと区別するOSの借用返却値。
	BOOL	   absentPresent{} ;							// DACLなしとは異なるpresent=trueを必須とする。
	BOOL	   absentDefaulted{} ;							// OSが返す元defaulted属性。
	SECURITY_DESCRIPTOR_CONTROL absentControl{} ;			// 保護bitを元負例と一致させる。
	DWORD						absentRevision{} ;			// Control照会が返す元revision。
	PSID						absentOwner{} ;				// 元fileのownerと一致するRAM内の借用SID。
	BOOL						absentOwnerDefaulted{} ;	// Owner照会の元属性。
	require( IsValidSecurityDescriptor( absent.get()) != FALSE) ;
	require( GetSecurityDescriptorDacl( absent.get(), &absentPresent, &absentAcl, &absentDefaulted) !=
				FALSE &&
			absentPresent != FALSE && absentAcl == nullptr) ;
	require( GetSecurityDescriptorControl( absent.get(), &absentControl, &absentRevision) != FALSE &&
			(absentControl & SE_DACL_PROTECTED) != 0U) ;
	require( GetSecurityDescriptorOwner( absent.get(), &absentOwner, &absentOwnerDefaulted) !=
				FALSE &&
			absentOwner != nullptr && EqualSid( absentOwner, owner) != FALSE) ;
	DRIVERCRATE_EXPECT( context, !isLocalCollectorDescriptorAllowed( absent.get(), owner, false)) ;
	// 未知ACEは元fileへ適用せず、メモリ上だけで変更する。
	PACL acl{} ;
	// DACLの存在flag。
	BOOL present{} ;
	// 既定DACLかをAPIから受け取る。
	BOOL defaulted{} ;
	require( GetSecurityDescriptorDacl( valid.get(), &present, &acl, &defaulted) && present && acl) ;
	// 先頭の通常allow ACEを固定形式として扱う。
	void *rawAce{} ;
	require( GetAce( acl, 0U, &rawAce) != FALSE) ;
	// OSが返した有効ACL内のACEだけを書き換える。
	auto *ace			= static_cast<ACCESS_ALLOWED_ACE *>( rawAce) ;
	ace->Header.AceType = ACCESS_DENIED_ACE_TYPE ;
	DRIVERCRATE_EXPECT( context, !isLocalCollectorDescriptorAllowed( valid.get(), owner, false)) ;
	ace->Header.AceType	 = ACCESS_ALLOWED_ACE_TYPE ;
	ace->Header.AceFlags = INHERITED_ACE ;
	DRIVERCRATE_EXPECT( context, !isLocalCollectorDescriptorAllowed( valid.get(), owner, false)) ;
	ace->Header.AceFlags = 0U ;
	// 保護解除もdiskへは適用せず、検証関数だけへ渡す。
	require( SetSecurityDescriptorControl( valid.get(), SE_DACL_PROTECTED, 0U) != FALSE) ;
	DRIVERCRATE_EXPECT( context, !isLocalCollectorDescriptorAllowed( valid.get(), owner, false)) ;
}

/** @brief 回収を許可した既知fixtureだけをextended DOS表記へ揃えます。
 * @param[in] path 回収rootの照合後に固定名から構築した絶対DOS path。
 * @return 同じ対象を示すbackslash付きextended path。
 * @pre 呼出し元は回収rootを照合し、junctionの参照先を辿らず回収します。
 */
[[nodiscard]] std::filesystem::path cleanupIoPath( const std::filesystem::path &path)
{
	return L"\\\\?\\" + std::filesystem::path( path).make_preferred().native() ;
}

/** @brief 自作fixtureだけの既知名を削除します。junction配下は列挙しません。
 * @param[in] base 新規作成したwork/state直下のfixture root。
 * @return 既知fileだけを削除し、空になったrootを削除できた場合true。
 */
[[nodiscard]] bool cleanup( const std::filesystem::path &base)
{
	// 完全pathが今回作成したwork/stateの一directoryであることを再照合する。
	const auto expectedParent = std::filesystem::current_path() / L"work/state" ;
	// 想定外のrootへcleanupしない。
	if( base.parent_path() != expectedParent ||
	   !base.filename().native().starts_with( L"collector-acl-fixture-")) {
		return false ;
	}

	// 本fixtureにだけ存在する固定scenario名。
	for( const auto *scenario :
		{L"fresh", L"legacy-long-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		 L"unsafe-root", L"unsafe-child", L"unsafe-file", L"hardlink", L"junction",
		 L"junction-target"}) {
		// 今回だけのscenario root。
		const auto root = base / scenario ;
		// 固定の二階層だけを掃除する。
		for( const auto *folder : {L"runs", L"current"}) {
			// 自作の子directory。
			const auto	directory = root / folder ;
			// reparse判定のための属性。
			const DWORD attributes = GetFileAttributesW( cleanupIoPath( directory).c_str()) ;
			// junctionは参照先に触れずjunction自体を削除する。
			if( attributes != INVALID_FILE_ATTRIBUTES &&
			   (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) {
				RemoveDirectoryW( cleanupIoPath( directory).c_str()) ;
				continue ;
			}

			// 書込みを行った既知名だけを削除する。
			for( const auto *name : {L"a.json", L"a.json.tmp", L"alias.json"}) {
				DeleteFileW( cleanupIoPath( directory / name).c_str()) ;
			}

			// 長path回帰の既知一名だけを削除し、未知fileは列挙・削除しない。
			if( std::wstring_view( scenario).starts_with( L"legacy-long-") &&
			   std::wstring_view( folder) == L"current") {
				const auto longFile = directory / (std::wstring( 128U, L'a') + L".json") ;	// 自作名。
				DeleteFileW( cleanupIoPath( longFile).c_str()) ;
			}

			RemoveDirectoryW( cleanupIoPath( directory).c_str()) ;
		}

		DeleteFileW( cleanupIoPath( root / L"collector.lock").c_str()) ;
		DeleteFileW( cleanupIoPath( root / L"marker.json").c_str()) ;
		RemoveDirectoryW( cleanupIoPath( root).c_str()) ;
	}

	return RemoveDirectoryW( cleanupIoPath( base).c_str()) != FALSE ;
}

} // namespace
} // namespace drivercrate::test

/** @brief 実filesystem上の非通信試験だけを起動します。
 * @return 全assertionとcleanupが成功すれば0、失敗1。
 */
int main()
{
	// 今回の非通信assertion集計。
	drivercrate::test::TestContext context ;
	// cleanup対象は自分が新規作成した一領域だけ。
	std::filesystem::path		   base ;
	try {
		// fixture名に使う衝突しないGUID。
		GUID id{} ;
		drivercrate::test::require( SUCCEEDED( CoCreateGuid( &id))) ;
		// GUIDの固定長文字列buffer。
		wchar_t text[40]{} ;
		drivercrate::test::require( StringFromGUID2( id, text, 40) != 0) ;
		base = std::filesystem::current_path() / L"work/state" /
			   (std::wstring( L"collector-acl-fixture-") + text) ;
		std::filesystem::create_directories( base.parent_path()) ;
		drivercrate::test::require( CreateDirectoryW( base.c_str(), nullptr) != FALSE) ;
		{
			// 検証modeの未存在rootは作成しない。
			drivercrate::LocalCollectorStateStore validate ;
			DRIVERCRATE_EXPECT( context,
							   validate.initialize( base / L"not-created", false) == ERROR_SUCCESS) ;
			DRIVERCRATE_EXPECT( context, !std::filesystem::exists( base / L"not-created")) ;
		}
		drivercrate::test::normalAndStaging( context, base / L"fresh") ;
		drivercrate::test::longLegacyChild(
			context,
			base / L"legacy-long-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") ;
		{
			// 非作成入口も既存正常台帳を使い、欠損rootを再初期化しない。
			drivercrate::LocalCollectorStateStore existing ;	// 同じ保護境界の既存writer。
			DRIVERCRATE_EXPECT( context,
							   existing.initializeExistingWriter( base / L"fresh") == ERROR_SUCCESS) ;
			drivercrate::LocalCollectorStateStore missing ;	// 欠損を作成しない別owner。
			DRIVERCRATE_EXPECT( context, missing.initializeExistingWriter( base / L"not-created") !=
											ERROR_SUCCESS) ;
			DRIVERCRATE_EXPECT( context, !std::filesystem::exists( base / L"not-created")) ;
		}
		{
			// 直前のwriter解放後は同じ状態を再開できる。
			drivercrate::LocalCollectorStateStore reopened ;
			DRIVERCRATE_EXPECT( context,
							   reopened.initialize( base / L"fresh", true) == ERROR_SUCCESS) ;
			// 再開したfileの本文。
			std::string bytes ;
			// 存在状態。
			bool		found{} ;
			DRIVERCRATE_EXPECT( context,
							   reopened.read( L"runs/a.json", bytes, found) == ERROR_SUCCESS &&
								   found && bytes == "new-checkpoint") ;
		}
		drivercrate::test::descriptorChecks( context, base / L"fresh/runs/a.json") ;
		drivercrate::test::unsafeRoot( context, base / L"unsafe-root") ;
		drivercrate::test::unsafeChild( context, base / L"unsafe-child", true) ;
		drivercrate::test::unsafeChild( context, base / L"unsafe-file", false) ;
		drivercrate::test::hardLink( context, base / L"hardlink") ;
		drivercrate::test::reparse( context, base / L"junction", base / L"junction-target") ;
		DRIVERCRATE_EXPECT( context, drivercrate::test::cleanup( base)) ;
	} catch( const std::exception &) {
		context.expect( false, "collector fixture exception", __FILE__, __LINE__) ;
		// 自作領域が確定している場合だけ非再帰cleanupを試す。
		if( !base.empty()) {
			static_cast<void>( drivercrate::test::cleanup( base)) ;
		}
	}

	std::cout << "Collector state tests: " << context.assertionCount() << " assertions, "
			  << context.failureCount() << " failures\n" ;
	return context.failureCount() == 0 ? 0 : 1 ;
}
