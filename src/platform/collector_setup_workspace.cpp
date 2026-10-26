//------------------------------------------------------------------------------
/**
 * @file collector_setup_workspace.cpp
 * @brief 保護実handleを保持して収集setupの固定Python操作へ接続します。
 * @version 01.12.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/16 保護rootと固定bootstrap・有限実行を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/17 非重複rootとAPI失敗code保持を修正。
 * Ver.01.01.00 Shunji Ogawa  2026/10/17 v5の信頼済み取得処理と明示一回操作を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/17 保護原点・native lease・継承pipeとproxy環境を接続。
 * Ver.01.02.01 Shunji Ogawa  2026/10/17 bind済み非通信verify／exportを同じ原点へ結合。
 * Ver.01.03.00 Shunji Ogawa  2026/10/20 resourceの保護新規保存とv6固定local-index起動を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/20 embeddedの全子親を保存前に成分別検査・handle保持。
 * Ver.01.04.01 Shunji Ogawa  2026/10/20 child用Windows directory照会の元Win32失敗codeを保持。
 * Ver.01.04.02 Shunji Ogawa  2026/10/20 OS由来DOS rootのSystemDriveを固定local child環境へ追加。
 * Ver.01.04.03 Shunji Ogawa  2026/10/21 同梱の固定scriptをisolatedな通常fileとして起動。
 * Ver.01.05.00 Shunji Ogawa  2026/10/23 新user Taskのrootとmetadataを既存ACL規則で検査。
 * Ver.01.05.01 Shunji Ogawa  2026/10/23 新file検査入口でseparator表記だけを実handleへ統一。
 * Ver.01.06.00 Shunji Ogawa  2026/10/23 配布専用origin・実子duplexと一回保護callerを接続。
 * Ver.01.06.01 Shunji Ogawa  2026/10/23 収集JSONの16MiB文脈を共通CNGへ結合し大きい実入力を受理。
 * Ver.01.06.02 Shunji Ogawa  2026/10/23 例外時も実子終端を確認するRAIIをnative lease解放前へ追加。
 * Ver.01.06.03 Shunji Ogawa  2026/10/23 run directoryと新祖先の実体・ACLを子終端まで固定。
 * Ver.01.07.00 Shunji Ogawa  2026/10/23 同結果のv2候補保存と実assemble/未署名共通検査を接続。
 * Ver.01.08.00 Shunji Ogawa  2026/10/23 active原byte固定と非通信data取込み・別日次同意を接続。
 * Ver.01.08.01 Shunji Ogawa  2026/10/24 現行仕様へ限定し旧版専用の入口・移動を整理。
 * Ver.01.08.02 Shunji Ogawa  2026/10/24 root直下Actionの親を明示protected契約へ区別。
 * Ver.01.08.03 Shunji Ogawa  2026/10/24  必須解析の型・有限所有buffer・失敗制御を明示。
 * Ver.01.09.00 Shunji Ogawa  2026/10/25 原descriptor非保存のleaseと同schema明示package切替を接続。
 * Ver.01.10.00 Shunji Ogawa  2026/10/25 完全PAGE原byteを原結果保存後の固定診断memberへ保持。
 * Ver.01.10.01 Shunji Ogawa  2026/10/25 保持workspace総量だけをpackageと別の256MiB予算へ分離。
 * Ver.01.11.00 Shunji Ogawa  2026/10/26 一hostの非通信reviewを非保存native leaseへ接続。
 * Ver.01.12.00 Shunji Ogawa  2026/10/26 未署名候補の非通信stagingを保持中leaseへ接続。
 * </pre>
 *
 * @note 同一user・SYSTEM・Administratorsを信頼し、既存ACLは修復しません。
 * @see docs/adr/0355-collector-protected-workspace-adapter.md
 */
//------------------------------------------------------------------------------
#include "collector_setup_workspace.h"
#include "collector_setup_transport.h"
#include "collector_setup_admission.h"
#include "official_file_verifier.h"
#include "collector_registry_job.h"
#include "local_driver_collector.h"
#include "signed_index_json_internal.h"
#include "unsigned_index_candidate.h"

#include "local_collector_state_store.h"

#include <Windows.h>
#include <ShlObj.h>
#include <AclAPI.h>
#include <sddl.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include <initializer_list>
#include <exception>

namespace drivercrate {
namespace {
namespace fs = std::filesystem ;
/** @brief 固定contextと保護local参照のJSON objectです。 */
using SetupJson = winrt::Windows::Data::Json::JsonObject ;
/** @brief 固定contextのJSON値です。 */
using SetupValue = winrt::Windows::Data::Json::JsonValue ;
/** @brief hash集合だけをchildへ渡すJSON配列です。 */
using SetupArray	 = winrt::Windows::Data::Json::JsonArray ;
using SetupJsonValue = winrt::Windows::Data::Json::IJsonValue ;	// 有限値の同期比較viewです。

// 全byte検証とhandle保持の対象である固定scriptだけを自然なfile入口として起動する。
constexpr std::wstring_view BOOTSTRAP = L"scripts/collector_workspace.py" ;

// 収集JSONの既存予算です。共通hash関数の大きい用途上限を代替値にしません。
constexpr std::size_t		DISTRIBUTION_JSON_MAXIMUM_BYTES = 16U * 1024U * 1024U ;

// Package/embedded一集合の従来総量です。保持世代の予算を入力へ流用しません。
constexpr std::uintmax_t	PACKAGE_TOTAL_MAXIMUM_BYTES = 64U * 1024U * 1024U ;

// 全保持世代・monitor・管理fileの合計です。世代数保証や自動削除は追加しません。
constexpr std::uintmax_t	WORKSPACE_TOTAL_MAXIMUM_BYTES = 256U * 1024U * 1024U ;

/** @brief 最初の拒否stageを個人情報なしの例外へ固定します。
 * @param[in] valid 必須条件。
 * @param[in] stage 固定診断名。
 * @throws std::runtime_error 不成立。
 */
void						require( const bool valid, const char *stage)
{
	// 不明な保護状態を成功へ変換しない。
	if( !valid) {
		throw std::runtime_error( stage) ;
	}
}

/** @brief 固定stageと保存済みAPI errorだけを通知します。
 * @param[in] stage 固定診断名。
 * @param[in] error 元APIの直後に保存したcode。
 * @note pathやSIDは出力しません。後始末失敗も例外を送出せず記録できます。
 */
void reportApiError( const char *stage, const DWORD error) noexcept
{
	std::printf( "WORKSPACE_NATIVE_ERROR stage=%s win32=%lu\n", stage,
				static_cast<unsigned long>( error)) ;
}

/** @brief 保存済みのAPI失敗を固定stageで拒否します。
 * @param[in] stage 固定診断名。
 * @param[in] error 元APIまたはDWORD戻り値の保存code。
 * @throws std::runtime_error 常に固定stageで失敗します。
 */
[[noreturn]] void failApi( const char *stage, const DWORD error)
{
	reportApiError( stage, error) ;
	throw std::runtime_error( stage) ;
}

/** @brief BOOL API失敗の直後に元codeを保持します。
 * @param[in] result 直前のBOOL API戻り値。
 * @param[in] stage 固定診断名。
 * @throws std::runtime_error FALSEの実codeを通知した場合。
 */
void requireBool( const BOOL result, const char *stage)
{
	const DWORD error = result == FALSE ? GetLastError() : ERROR_SUCCESS ;	// API直後のcode。
	// 意味拒否と区別して、実API失敗だけへ元codeを付ける。
	if( result == FALSE) {
		failApi( stage, error) ;
	}
}

/** @brief DWORD statusを返すAPIの元戻り値を検査します。
 * @param[in] error APIが返したstatus。GetLastErrorではありません。
 * @param[in] stage 固定診断名。
 * @throws std::runtime_error ERROR_SUCCESS以外。
 */
void requireStatus( const DWORD error, const char *stage)
{
	// DWORD戻り値を後続APIのthread errorで置換しない。
	if( error != ERROR_SUCCESS) {
		failApi( stage, error) ;
	}
}

/** @brief 必要容量照会の期待失敗と実API失敗を分けます。
 * @param[in] result 直前のGetTokenInformationサイズ照会結果。
 * @throws std::runtime_error 期待した容量不足以外の失敗または想定外の成功。
 */
void requireTokenSizeQuery( const BOOL result)
{
	const DWORD error = result == FALSE ? GetLastError() : ERROR_SUCCESS ;	// 照会直後のcode。
	// 容量不足以外の実失敗は元codeを保持して停止する。
	if( result == FALSE && error != ERROR_INSUFFICIENT_BUFFER) {
		failApi( "WORKSPACE_TOKEN_SIZE_QUERY", error) ;
	}

	require( result == FALSE, "WORKSPACE_TOKEN_SIZE_QUERY_RESULT") ;
}

/** @brief 標準handle取得の実失敗を直後に保存します。
 * @param[in] kind Windowsの固定標準handle種別。
 * @return 親の標準handle。consoleがない場合のNULLも保持します。
 * @throws std::runtime_error INVALID_HANDLE_VALUEを返す実API失敗。
 */
HANDLE standardHandle( const DWORD kind)
{
	const HANDLE handle = GetStdHandle( kind) ;												// 既存stdout等を借用する。
	const DWORD error = handle == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS ;	// 元code。
	// 標準streamなしのNULLと実API失敗を混同しない。
	if( handle == INVALID_HANDLE_VALUE) {
		failApi( "WORKSPACE_STANDARD_HANDLE", error) ;
	}

	return handle ;
}

/** @brief path componentの大文字小文字を区別しないordinal一致を求めます。
 * @param[in] first 比較するNULL終端文字列。
 * @param[in] second 比較するNULL終端文字列。
 * @return Windows ordinal比較で一致する場合true。
 * @throws std::runtime_error 比較API失敗。
 */
bool sameComponent( const wchar_t *first, const wchar_t *second)
{
	const int compared =
		// Windowsの大小文字規則。
		CompareStringOrdinal( first, -1, second, -1, TRUE) ;
	const DWORD error = compared == 0 ? GetLastError() : ERROR_SUCCESS ;	// 比較直後のcode。
	// 比較不能を不一致へ変換して重複rootを許可しない。
	if( compared == 0) {
		failApi( "WORKSPACE_COMPARE", error) ;
	}

	return compared == CSTR_EQUAL ;
}

/** @brief 同一または祖先子孫となるrootをcomponent単位で検出します。
 * @param[in] first 検査済み絶対path。
 * @param[in] second 検査済み絶対path。
 * @return 一方の全componentが他方の先頭に一致する場合true。
 * @note 文字列prefixだけが似た兄弟は一致しません。fileやdirectoryは作成しません。
 */
bool pathsOverlap( const fs::path &first, const fs::path &second)
{
	auto left  = first.begin() ;	// 先頭から比較するcomponent。
	auto right = second.begin() ;	// もう一方のcomponent。
	// 共通componentが終了するか、最初の相違で判定を確定する。
	while( left != first.end() && right != second.end()) {
		// componentが違う時点で、似たprefixでも別rootとする。
		if( !sameComponent( left->c_str(), right->c_str())) {
			return false ;
		}

		++left ;
		++right ;
	}

	return true ;
}

/** @brief 非追跡の属性照会と実reparse拒否を別の診断へ分けます。
 * @param[in] path 検査するentry。
 * @param[in] attributesStage 属性API失敗の固定stage。
 * @param[in] reparseStage 実reparseの固定stage。
 * @return 取得に成功した属性。
 * @throws std::runtime_error 属性照会失敗または実reparse。
 */
DWORD checkedAttributes( const fs::path &path, const char *attributesStage, const char *reparseStage)
{
	const std::wstring apiPath	  = path.native().size() >= 248U
										? L"\\\\?\\" + path.native()
										: path.native() ;					// 固定runの長pathも同じ実体です。
	const DWORD		   attributes = GetFileAttributesW( apiPath.c_str()) ;	// 非追跡の実属性。
	const DWORD		   error =
		// 元code。
		attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS ;
	// 属性未取得をreparseと誤診断しない。
	if( attributes == INVALID_FILE_ATTRIBUTES) {
		failApi( attributesStage, error) ;
	}

	require( (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0U, reparseStage) ;
	return attributes ;
}

/** @brief scope終端で所有handleを解放します。 */
struct HandleCloser {
	/** @brief 有効handleを一度閉じます。
     * @param[in] value 所有する有効handle。
     */
	void operator()( void *value) const noexcept
	{
		const BOOL	closed = CloseHandle( value) ;								// 所有handleの最終解放結果。
		const DWORD error  = closed == FALSE ? GetLastError() : ERROR_SUCCESS ;	// 解放直後のcode。
		// destructorから例外を出さず、失敗の診断だけを保持する。
		if( closed == FALSE) {
			reportApiError( "WORKSPACE_CLOSE", error) ;
		}
	}
} ;
/** @brief scope終端でLocalAlloc領域を解放します。 */
struct MemoryCloser {
	/** @brief 有効なLocalAlloc領域を返します。
     * @param[in] value 所有する領域。
     */
	void operator()( void *value) const noexcept
	{
		const HLOCAL remaining = LocalFree( value) ;	// 成功時はNULL。
		const DWORD	 error =
			 remaining != nullptr ? GetLastError() : ERROR_SUCCESS ;	// 解放直後のcode。
		// descriptorの回収失敗を無言で破棄しない。
		if( remaining != nullptr) {
			reportApiError( "WORKSPACE_FREE", error) ;
		}
	}
} ;
/** @brief Windows handleの単独所有型です。 */
using Handle = std::unique_ptr<void, HandleCloser> ;
/** @brief security descriptorの単独所有型です。 */
using Memory = std::unique_ptr<void, MemoryCloser> ;

/** @brief 有効handleだけをRAIIへ移します。
 * @param[in] raw APIから所有権を受け取るhandle。
 * @return 所有handle。
 * @throws std::runtime_error API失敗。
 */
Handle own( HANDLE raw)
{
	// 元APIのerrorを次の検査より前に保持する。
	if( raw == nullptr || raw == INVALID_HANDLE_VALUE) {
		const DWORD error = GetLastError() ;	// 元Win32 error。
		failApi( "WORKSPACE_HANDLE", error) ;
	}

	return Handle( raw) ;
}

/** @brief 呼出しprocessのuser SIDを所有byteとして取得します。
 * @return TOKEN_USERを含む所有buffer。
 * @throws std::runtime_error token照会失敗。
 */
std::vector<std::byte> userToken()
{
	HANDLE raw{} ;	// APIから受け取るtoken。
	requireBool( OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &raw), "WORKSPACE_TOKEN") ;
	const Handle token = own( raw) ;	// 全終了経路でtokenを閉じる。
	DWORD		 size{} ;				// TOKEN_USERの必要byte数。
	requireTokenSizeQuery( GetTokenInformation( token.get(), TokenUser, nullptr, 0, &size)) ;
	require( size > 0U && size <= 65536U, "WORKSPACE_TOKEN_SIZE") ;
	std::vector<std::byte> bytes( size) ;	// SIDを含む所有buffer。
	requireBool( GetTokenInformation( token.get(), TokenUser, bytes.data(), size, &size),
				"WORKSPACE_TOKEN_USER") ;
	return bytes ;
}

/** @brief UNC・ADS・相対componentを拒否します。
 * @param[in] path 利用者が明示した絶対path。
 * @throws std::runtime_error 不適格path。
 */
void checkPath( const fs::path &path)
{
	require( path.is_absolute() && path.root_name().native().size() == 2U &&
				path != path.root_path() && path.native().size() <= 2048U &&
				path.native().find( L':', 2U) == std::wstring::npos &&
				path.native().find_first_of( L"\"\r\n") == std::wstring::npos &&
				GetDriveTypeW( path.root_path().c_str()) == DRIVE_FIXED,
			"WORKSPACE_PATH") ;
	// 字句補正で別の入力を受理せず、全componentを一度検査する。
	for( const auto &part : path) {
		require( part != L"." && part != L".." && !part.empty(), "WORKSPACE_COMPONENT") ;
	}
}

/** @brief 同じ実handleの属性・最終path・単一linkを検査します。
 * @param[in] path 期待する絶対path。
 * @param[in] directory trueならdirectory。
 * @param[in] readonly trueなら書込み共有も禁止する。
 * @return 検査済みの所有handle。
 * @throws std::runtime_error 不一致またはAPI失敗。
 * @note directoryはFILE_LIST_DIRECTORY、immutable通常fileはFILE_READ_DATAを要求し、共有検査を有効にします。
 */
Handle openChecked( const fs::path &path, const bool directory, const bool readonly)
{
	const std::wstring apiPath = path.native().size() >= 248U
									 ? L"\\\\?\\" + path.native()
									 : path.native() ;	// 長pathも同じ実体で検査します。
	Handle			   handle =
		own( CreateFileW( apiPath.c_str(),
						FILE_READ_ATTRIBUTES | READ_CONTROL |
							(directory ? FILE_LIST_DIRECTORY : (readonly ? FILE_READ_DATA : 0U)),
						FILE_SHARE_READ | (readonly ? 0U : FILE_SHARE_WRITE), nullptr,
						OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
						nullptr)) ;		// 置換共有を許可しない。
	BY_HANDLE_FILE_INFORMATION info{} ;	// 実handleの属性とlink数。
	requireBool( GetFileInformationByHandle( handle.get(), &info), "WORKSPACE_OBJECT_INFORMATION") ;
	SetLastError( ERROR_SUCCESS) ;
	const DWORD type	  = GetFileType( handle.get()) ;									// UNKNOWNだけは失敗との区別が必要。
	const DWORD typeError = type == FILE_TYPE_UNKNOWN ? GetLastError() : ERROR_SUCCESS ;	// 元code。
	requireStatus( typeError, "WORKSPACE_OBJECT_TYPE") ;
	require( (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0U &&
				((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) == directory &&
				(directory || info.nNumberOfLinks == 1U) && type == FILE_TYPE_DISK,
			"WORKSPACE_OBJECT") ;
	std::vector<wchar_t> finalPath( 32768U) ;	// 実pathを同じ有限容量・ゼロ初期値で所有して照合する。
	const DWORD			 length = GetFinalPathNameByHandleW(
		 handle.get(), finalPath.data(), static_cast<DWORD>( finalPath.size()),
		 FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;							// 実文字数。
	const DWORD pathError = length == 0U ? GetLastError() : ERROR_SUCCESS ;	// 取得直後のcode。
	// 長さ0の実API失敗はcode自体が0でも意味拒否と分ける。
	if( length == 0U) {
		failApi( "WORKSPACE_HANDLE_PATH_QUERY", pathError) ;
	}

	require( length > 4U && length < finalPath.size() &&
				sameComponent( finalPath.data() + 4U, path.c_str()),
			"WORKSPACE_HANDLE_PATH") ;
	return handle ;
}

/** @brief ownerと三principalの明示または継承DACLを検査します。
 * @param[in] handle 検査する実handle。
 * @param[in] user 実行userの借用SID。
 * @param[in] directory trueならdirectory。
 * @param[in] root trueなら既存protected descriptor predicateを必須とする。
 * @throws std::runtime_error owner、DACL、mask、flagの不一致。
 */
void checkSecurity( HANDLE handle, PSID user, const bool directory, const bool root)
{
	PSECURITY_DESCRIPTOR raw{} ;	// OSがLocalAllocで返すdescriptor。
	PSID				 owner{} ;	// descriptor内の借用owner。
	PACL				 acl{} ;	// descriptor内の借用DACL。
								  // OwnerとDACLを同じ実handleから読み取った元Win32結果。
	const DWORD			 error = GetSecurityInfo( handle, SE_FILE_OBJECT,
												 OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
												 &owner, nullptr, &acl, nullptr, &raw) ;
	const Memory		 descriptor( raw) ;	// 例外でもOS領域を回収する。
	requireStatus( error, "WORKSPACE_SECURITY_QUERY") ;
	require( owner != nullptr && IsValidSid( owner) &&
				(EqualSid( owner, user) || IsWellKnownSid( owner, WinLocalSystemSid) ||
				 IsWellKnownSid( owner, WinBuiltinAdministratorsSid)) &&
				acl != nullptr && IsValidAcl( acl),
			"WORKSPACE_OWNER_DACL") ;
	// Rootの契約は既存predicateと完全に同じ三明示ACE・protected DACLとする。
	if( root) {
		require( isLocalCollectorDescriptorAllowed( descriptor.get(), user, directory),
				"WORKSPACE_PROTECTED_DACL") ;
		return ;
	}

	require( acl->AceCount == 3U, "WORKSPACE_CHILD_DACL") ;
	bool hasUser{} ;			// 継承先でも三principalがすべて必要。
	bool hasSystem{} ;			// SYSTEMの継承許可。
	bool hasAdministrators{} ;	// Administratorsの継承許可。
	// 三ACEの実effective権限だけを受理し、余分なprincipalやdenyで補正しない。
	for( DWORD index = 0; index < acl->AceCount; ++index) {
		void *rawAce{} ;	// ACL内の借用ACE。
		requireBool( GetAce( acl, index, &rawAce), "WORKSPACE_CHILD_ACE_QUERY") ;
		const auto *ace	  = static_cast<const ACCESS_ALLOWED_ACE *>( rawAce) ;	// Win32の固定ACE境界。
		const BYTE	flags = static_cast<BYTE>( INHERITED_ACE |
											  (directory ? OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
														 : 0U)) ;	// 作成時継承の期待flag。
		require( ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
					ace->Header.AceSize >= sizeof( ACCESS_ALLOWED_ACE) &&
					ace->Header.AceFlags == flags && ace->Mask == FILE_ALL_ACCESS,
				"WORKSPACE_CHILD_ACE") ;
		PSID sid = const_cast<DWORD *>( &ace->SidStart) ;	// 可変長SIDのAPI借用。
		require( IsValidSid( sid) != FALSE, "WORKSPACE_CHILD_SID") ;
		const bool isUser	= EqualSid( sid, user) != FALSE ;						// 実行userの一致。
		const bool isSystem = IsWellKnownSid( sid, WinLocalSystemSid) != FALSE ;	// SYSTEMの一致。
		const bool isAdministrators =
			// 管理者の一致。
			IsWellKnownSid( sid, WinBuiltinAdministratorsSid) != FALSE ;
		require( isUser || isSystem || isAdministrators, "WORKSPACE_CHILD_PRINCIPAL") ;
		hasUser |= isUser ;
		hasSystem |= isSystem ;
		hasAdministrators |= isAdministrators ;
	}

	require( hasUser && hasSystem && hasAdministrators, "WORKSPACE_CHILD_PRINCIPALS") ;
}

/** @brief 全祖先をreparseなしの実handleで削除共有せず固定します。
 * @param[in] path 既存directoryの絶対path。
 * @param[in,out] handles 呼出し全体で保持する所有handle集合。
 * @throws std::exception 祖先不一致。
 */
void lockAncestors( const fs::path &path, std::vector<Handle> &handles)
{
	const auto token = userToken() ;	// 祖先のowner照合中に保持するOS token。
	// TOKEN_USERはWindows APIが返すbufferの先頭にある。
	PSID	   user	   = reinterpret_cast<const TOKEN_USER *>( token.data())->User.Sid ;
	fs::path   current = path ;	// 親へ遡る有限cursor。
	// 各実directoryを固定し、drive rootで終了する。
	while( !current.empty()) {
		// drive rootの最終pathは末尾separatorのAPI差があるため属性とhandleだけを固定する。
		if( current == current.root_path()) {
			handles.push_back( own( CreateFileW(
				current.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL | FILE_LIST_DIRECTORY,
				FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
				FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr))) ;
			break ;
		}

		Handle handle = openChecked( current, true, false) ;	// 祖先の置換を拒否する実handle。
		PSECURITY_DESCRIPTOR raw{} ;							// 祖先の実descriptor。
		PSID				 owner{} ;							// 実descriptor内の借用owner。
		PACL				 acl{} ;							// 実descriptor内の借用DACL。
		const DWORD			 error = GetSecurityInfo( handle.get(), SE_FILE_OBJECT,
													 OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
													 &owner, nullptr, &acl, nullptr, &raw) ;	// 元結果。
		const Memory		 descriptor( raw) ;													// 既存ACLを変更せず照会領域だけ解放する。
		requireStatus( error, "WORKSPACE_ANCESTOR_SECURITY_QUERY") ;
		require( owner != nullptr && IsValidSid( owner) &&
					(EqualSid( owner, user) || IsWellKnownSid( owner, WinLocalSystemSid) ||
					 IsWellKnownSid( owner, WinBuiltinAdministratorsSid)) &&
					acl != nullptr && IsValidAcl( acl),
				"WORKSPACE_ANCESTOR_SECURITY") ;
		handles.push_back( std::move( handle)) ;
		current = current.parent_path() ;
	}
}

/** @brief 有限subtreeを実handleとowner/DACLで検査し、必要なら保持します。
 * @param[in] root protected root。
 * @param[in] user 実行userの借用SID。
 * @param[in] readonly trueならfile書込みを共有しない。
 * @param[in,out] handles 検査済みhandleの所有集合。
 * @param[in] maximumFileBytes 一fileの用途別上限。workspace/packageは16MiBです。
 * @param[in] maximumTotalBytes 全通常fileの用途別総量。保持workspaceだけ256MiBです。
 * @param[in] protectedRoot trueなら明示protected root、falseなら同じ三principalの継承childを要求します。
 * @throws std::exception 不適格entryまたは容量超過。
 */
void inspectTree( const fs::path &root, PSID user, const bool readonly, std::vector<Handle> &handles,
				 const std::uintmax_t maximumFileBytes, const std::uintmax_t maximumTotalBytes,
				 const bool protectedRoot = true)
{
	Handle rootHandle = openChecked( root, true, false) ;	// Root自身を先に固定する。
	checkSecurity( rootHandle.get(), user, true, protectedRoot) ;
	handles.push_back( std::move( rootHandle)) ;
	std::vector<fs::path> pending{root} ;	// 未検査directoryへ再帰しない有限queue。
	std::size_t			  entries{} ;		// 全entryの上限。
	std::uintmax_t		  total{} ;			// 全通常fileのbyte合計。
	// 実handleで通常directoryを確認した要素だけを深さ優先に展開する。
	while( !pending.empty()) {
		const fs::path directory = pending.back() ;	// 今回の検証済みdirectory。
		pending.pop_back() ;
		// 各childを一度だけ実handleへ結合してから、子directoryを予約する。
		for( const auto &entry : fs::directory_iterator( directory)) {
			require( ++entries <= 8192U, "WORKSPACE_ENTRY_LIMIT") ;
			const DWORD attributes	= checkedAttributes( entry.path(), "WORKSPACE_ATTRIBUTES",
														"WORKSPACE_REPARSE") ;			// 検査済み属性。
			const bool	isDirectory = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0U ;	// 実種別。
			Handle		handle		= openChecked( entry.path(), isDirectory,
												  readonly && !isDirectory) ;	// 検査と保持を共用する。
			checkSecurity( handle.get(), user, isDirectory, false) ;
			// 次の列挙は実handleで検査した通常directoryだけに限定する。
			if( isDirectory) {
				pending.push_back( entry.path()) ;
			} else {
				const auto size = entry.file_size() ;	// 通常file一個のbyte数。
				require( size <= maximumFileBytes && size <= maximumTotalBytes &&
							total <= maximumTotalBytes - size,
						"WORKSPACE_BYTE_LIMIT") ;
				total += size ;
			}

			handles.push_back( std::move( handle)) ;
		}
	}
}

/** @brief 固定embedded fileの全親を保存前に検査・保持し、新規byteだけを書き込みます。
 * @param[in] root 作成済みのprotected staging root。
 * @param[in] file 全table検査を終えた固定相対名と原byte。
 * @param[in] user 実行userの借用SID。
 * @param[in,out] handles 子process終了まで保持するrootと各子親の所有handle。
 * @throws std::exception 親の種別・実path・ACL差、既存file、書込みまたはflush失敗。
 * @note 親ACLを修復せず、拒否時の既存byteと新規部分fileを保持します。
 */
void writeEmbeddedFile( const fs::path &root, const CollectorSetupEmbeddedFile &file, PSID user,
					   std::vector<Handle> &handles)
{
	Handle rootHandle = openChecked( root, true, false) ;	// 保存前に同じ保護rootを固定する。
	checkSecurity( rootHandle.get(), user, true, true) ;
	handles.push_back( std::move( rootHandle)) ;
	const fs::path relative( file.path) ;	// 呼出し元で閉table検査済みの相対名。
	fs::path	   current = root ;			// 検査・保持済みの親から一成分だけ進める。
	// 各子directoryを作成または開き、次の成分やfileへ進む前に固定する。
	for( const auto &part : relative.parent_path()) {
		current /= part ;
		const BOOL	created = CreateDirectoryW( current.c_str(), nullptr) ;			// 検査済み親からACL継承。
		const DWORD error	= created != FALSE ? ERROR_SUCCESS : GetLastError() ;	// 直後の元code。
		// 既存objectは次の実handle検査へ渡し、その他の作成失敗は保存前に止める。
		if( error != ERROR_ALREADY_EXISTS) {
			requireStatus( error, "EMBEDDED_PARENT_CREATE") ;
		}

		Handle parent =
			// reparse・通常file・別実pathを拒否する。
			openChecked( current, true, false) ;
		checkSecurity( parent.get(), user, true, false) ;
		handles.push_back( std::move( parent)) ;
	}

	const fs::path target = root / relative ;	// 全親の実体を保持した固定file先。
	const Handle   output =
		own( CreateFileW( target.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_NEW,
						FILE_ATTRIBUTE_NORMAL, nullptr)) ;	// 上書き・既存link追跡をしない。
	DWORD written{} ;										// 完全書込みだけを受け付ける。
	requireBool( WriteFile( output.get(), file.bytes.data(), static_cast<DWORD>( file.bytes.size()),
						  &written, nullptr),
				"EMBEDDED_WRITE") ;
	require( written == file.bytes.size(), "EMBEDDED_WRITE_SIZE") ;
	requireBool( FlushFileBuffers( output.get()), "EMBEDDED_FLUSH") ;
}

/** @brief 固定child argvの一要素をWindows規則で引用します。
 * @param[in] value 引用する固定値または検査済みpath。
 * @return CommandLineToArgvW互換の一要素。
 */
std::wstring quote( const std::wstring_view value)
{
	std::wstring result = L"\"" ;	// 開始引用符。
	std::size_t	 slashes{} ;		// 引用符直前のbackslash数。
	// 各文字を一度走査し、引用符と末尾のbackslashだけを二重化する。
	for( const wchar_t letter : value) {
		// Backslashは次の文字まで保留する。
		if( letter == L'\\') {
			++slashes ;
			continue ;
		}

		result.append( slashes * (letter == L'\"' ? 2U : 1U), L'\\') ;
		slashes = 0U ;
		// 引用符を一argv内のliteralとして保持する。
		if( letter == L'\"') {
			result.push_back( L'\\') ;
		}

		result.push_back( letter) ;
	}

	result.append( slashes * 2U, L'\\') ;
	result.push_back( L'\"') ;
	return result ;
}

/** @brief 現行native入口の固定fileとpackageのargvを構成します。
 * @param[in] package 全byte検査済みでhandleを保持中の絶対package root。
 * @return 固定isolated option、絶対script、所属packageの引用済み引数。
 * @note 後続の操作引数と全体のargv上限検査は呼出側が保持します。
 */
std::wstring fileBootstrapArguments( const fs::path &package)
{
	const fs::path script = package / BOOTSTRAP ;	// 任意scriptを受けない。
	return L" -I -B -S " + quote( script.native()) + L" " + quote( package.native()) ;
}

/** @brief 実directoryのvolumeとfile indexを非公開identityへ固定します。
 * @param[in] root 検査済みの正規絶対path。
 * @return nativeと固定childで共用するSHA-256。
 * @throws std::exception 実handle・属性・hash検査失敗。
 */
std::wstring directoryIdentity( const fs::path &root)
{
	const Handle			   handle = openChecked( root, true, false) ;	// 同じdirectory実体。
	BY_HANDLE_FILE_INFORMATION info{} ;										// OSの実volumeとfile index。
	requireBool( GetFileInformationByHandle( handle.get(), &info), "ORIGIN_IDENTITY") ;
	const std::uint64_t index = (static_cast<std::uint64_t>( info.nFileIndexHigh) << 32U) |
								info.nFileIndexLow ;	// 完全64bit index。
	const std::string input =
		// 共通のASCII式。
		std::to_string( info.dwVolumeSerialNumber) + ":" + std::to_string( index) ;
	std::wstring hash ;	// 実体識別子を直接logへ出さない。
	require( computeBytesSha256( input, hash) == 0, "ORIGIN_IDENTITY_HASH") ;
	return hash ;
}

/** @brief 保護済みlocal参照を同じ有限file handleから読みます。
 * @param[in] path 既にtree検査した固定path。
 * @return 完全に読めたJSON object。
 * @throws std::exception 欠損・容量・実I/O・JSON失敗。
 */
SetupJson readOrigin( const fs::path &path)
{
	const Handle checked = openChecked( path, false, true) ;	// 読取り中の差替えを拒否する。
	const Handle file =
		own( CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
						FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;	// 固定byteの読取りhandle。
	LARGE_INTEGER size{} ;											// 読取り前に上限を検査する。
	requireBool( GetFileSizeEx( file.get(), &size), "ORIGIN_SIZE") ;
	require( size.QuadPart > 0 && size.QuadPart <= 262144, "ORIGIN_SIZE_LIMIT") ;
	std::string bytes( static_cast<std::size_t>( size.QuadPart), '\0') ;	// 有限の所有byte。
	DWORD		read{} ;													// 実際に読めたbyte数。
	requireBool(
		ReadFile( file.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &read, nullptr),
		"ORIGIN_READ") ;
	require( read == bytes.size(), "ORIGIN_READ_SIZE") ;
	return SetupJson::Parse( winrt::to_hstring( bytes)) ;
}

/** @brief 保護workspaceの固定参照を明示bind成功後だけ保存します。
 * @param[in] path 固定origin.json。
 * @param[in] bytes 同じnative markerへ保存したUTF-8本文。
 * @throws std::exception 書込み・flush・終端確定失敗。
 */
void writeOrigin( const fs::path &path, const std::string &bytes)
{
	const Handle file =
		own( CreateFileW( path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
						FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;	// 保護rootの作成時ACLを継承する。
	DWORD written{} ;												// 全byteの成功を要求する。
	requireBool(
		WriteFile( file.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &written, nullptr),
		"ORIGIN_WRITE") ;
	require( written == bytes.size(), "ORIGIN_WRITE_SIZE") ;
	requireBool( SetEndOfFile( file.get()), "ORIGIN_TRUNCATE") ;
	requireBool( FlushFileBuffers( file.get()), "ORIGIN_FLUSH") ;
}

/** @brief 三つの既存実rootをlocal bindingへ結合します。
 * @param[in] nativeRoot 非作成writerの原点。
 * @param[in] root 保護workspace。
 * @param[in] monitorRoot 選択された停止monitor正本。
 * @return pathと実identityを持つ非公開参照。
 */
SetupJson originBinding( const fs::path &nativeRoot, const fs::path &root,
						const fs::path &monitorRoot)
{
	SetupJson result ;	// 許可proofではない保護local参照。
	result.Insert( L"schema", SetupValue::CreateStringValue( L"dc-collector-monitor-origin-v1")) ;
	// 順序を固定した三rootの参照と実体を同じobjectへ保存する。
	for( const auto &entry : {std::pair{L"native", nativeRoot}, std::pair{L"workspace", root},
							 std::pair{L"monitor", monitorRoot}}) {
		const std::wstring prefix = entry.first ;	// 固定field prefix。
		result.Insert( prefix + L"Root", SetupValue::CreateStringValue( entry.second.native())) ;
		result.Insert( prefix + L"Identity",
					  SetupValue::CreateStringValue( directoryIdentity( entry.second))) ;
	}

	return result ;
}

/** @brief 一つの固定fileの実byte SHA-256をcontextへ結合します。
 * @param[in] path package内の検査済みfile。
 * @return 実byte SHA-256。
 * @throws std::exception hash検査失敗。
 */
std::wstring fileHash( const fs::path &path)
{
	std::wstring hash ;	// 検査済みpackage byteの結合。
	require( computeFileSha256( path.native(), hash) == 0, "NATIVE_CONTEXT_FILE_HASH") ;
	return hash ;
}

/** @brief 生きたnative leaseを固定child向けの有限contextへ射影します。
 * @param[in] package 検査済みpackage。
 * @param[in] origin 実rootへ結合したlocal参照。
 * @param[in] previous 移設の元正本。初回は空です。
 * @param[in] admission 保持中の実writerと全旧scope。
 * @param[in] utcMillis 発行時のOS UTC millisecond。
 * @param[in] action 固定操作。
 * @return 最大256KiBのUTF-8本文。公開・永続化しません。
 */
std::string admissionContext( const fs::path &package, const SetupJson &origin,
							 const SetupJson &previous, const CollectorSetupAdmission &admission,
							 const std::uint64_t utcMillis, const std::wstring_view action)
{
	SetupJson result ;	// pipeだけへ渡す一回context。
	result.Insert( L"schema", SetupValue::CreateStringValue( L"dc-collector-live-admission-v1")) ;
	result.Insert( L"operation", SetupValue::CreateStringValue( action)) ;
	result.Insert( L"nativeMode", SetupValue::CreateStringValue( L"VERIFIED_LEGACY_V4")) ;
	result.Insert( L"nativeDigest", SetupValue::CreateStringValue( admission.snapshot.digest)) ;
	result.Insert( L"nativeFileCount", SetupValue::CreateNumberValue( admission.snapshot.fileCount)) ;
	result.Insert( L"issuedAtUtcMillis",
				  SetupValue::CreateNumberValue( static_cast<double>( utcMillis))) ;
	// 子は原点とworkspaceの実identityを再照合する。
	for( const auto name : {L"workspaceIdentity", L"monitorIdentity", L"monitorRoot"}) {
		result.Insert( name, origin.Lookup( name)) ;
	}

	// 既存原点から移設するときだけ元正本を再検証させる。
	if( previous.Size() != 0U) {
		result.Insert( L"previousMonitorRoot", previous.Lookup( L"monitorRoot")) ;
		result.Insert( L"previousMonitorIdentity", previous.Lookup( L"monitorIdentity")) ;
	}

	result.Insert( L"packageManifestSha256",
				  SetupValue::CreateStringValue( fileHash( package / L"package-manifest.json"))) ;
	result.Insert( L"seedManifestSha256", SetupValue::CreateStringValue( fileHash(
											 package / L"seed/collector-data/manifest.json"))) ;
	result.Insert( L"policySha256",
				  SetupValue::CreateStringValue( fileHash( package / L"config/monitor-policy.json"))) ;
	// actual URLは出力せず、共通比較式のhash集合を渡す。
	for( const auto &entry : {std::pair{L"requestHashes", admission.requestHashes},
							 std::pair{L"hostHashes", admission.hostHashes}}) {
		SetupArray values ;	// 一種類の完全作用域。
		// 検証済み集合を順序を変えず配列へ射影する。
		for( const auto &value : entry.second) {
			values.Append( SetupValue::CreateStringValue( value)) ;
		}

		result.Insert( entry.first, values) ;
	}

	const std::string bytes = winrt::to_string( result.Stringify()) ;	// 永続化しない有限context。
	require( bytes.size() <= 262144U, "NATIVE_CONTEXT_SIZE") ;
	return bytes ;
}

/** @brief 通信子へ渡すproxy設定だけを元環境から有限に保持します。
 * @param[in,out] environment 二重NUL確定前の環境block。
 * @note 値はlogへ出力せず、OS/PAC設定は固定childが正式照会します。
 */
void appendProxyEnvironment( std::wstring &environment)
{
	// Windowsの環境名は大小文字非区別で、proxy四種だけを保持する。
	for( const auto name : {L"HTTPS_PROXY", L"HTTP_PROXY", L"ALL_PROXY", L"NO_PROXY"}) {
		SetLastError( ERROR_SUCCESS) ;
		const DWORD length = GetEnvironmentVariableW( name, nullptr, 0U) ;	// 値を出力しない容量照会。
		const DWORD error =
			// 未設定と実失敗を分ける。
			length == 0U ? GetLastError() : ERROR_SUCCESS ;
		// 未設定の場合だけ継承対象から外す。
		if( length == 0U && error == ERROR_ENVVAR_NOT_FOUND) {
			continue ;
		}

		require( length > 0U && length <= 4096U, "PROXY_ENVIRONMENT_SIZE") ;
		std::wstring value( length, L'\0') ;	// 短命の元設定値。
		const DWORD	 copied =
			// 再照会の実文字数。
			GetEnvironmentVariableW( name, value.data(), length) ;
		require( copied < length && copied + 1U == length, "PROXY_ENVIRONMENT_CHANGED") ;
		value.resize( copied) ;
		environment += std::wstring( name) + L"=" + value ;
		environment.push_back( L'\0') ;
	}
}
/** @brief OS取得Windows directoryの普通のDOS driveだけを子環境へ射影します。
 * @param[in] windowsDirectory GetWindowsDirectoryWの容量検査済み成功値。
 * @return 親環境を参照しない二文字のdrive名。
 * @throws std::runtime_error 非絶対DOS path、環境展開記号、相対component等の不適格値。
 * @note UNCやdevice pathを補正せず、子起動前に拒否します。
 */
[[nodiscard]] std::wstring setupChildSystemDrive( const std::wstring_view windowsDirectory)
{
	require( windowsDirectory.size() > 3U &&
				((windowsDirectory[0] >= L'A' && windowsDirectory[0] <= L'Z') ||
				 (windowsDirectory[0] >= L'a' && windowsDirectory[0] <= L'z')) &&
				windowsDirectory[1] == L':' && windowsDirectory[2] == L'\\' &&
				windowsDirectory.find( L':', 2U) == std::wstring_view::npos &&
				windowsDirectory.find( L'\0') == std::wstring_view::npos &&
				windowsDirectory.find_first_of( L"%\"\r\n/") == std::wstring_view::npos,
			"SETUP_CHILD_SYSTEMDRIVE") ;
	const fs::path directory( windowsDirectory) ;	// OS値を字句補正せず検査する。
	require( directory.is_absolute() && directory.root_name().native().size() == 2U,
			"SETUP_CHILD_SYSTEMDRIVE") ;
	// DOS root以外の相対成分が含まれる場合も子環境へ採用しない。
	for( const auto &part : directory) {
		require( !part.empty() && part != L"." && part != L"..", "SETUP_CHILD_SYSTEMDRIVE") ;
	}

	return std::wstring( windowsDirectory.substr( 0U, 2U)) ;
}

/** @brief 固定childをjob内で起動し、有限待機して元DWORD終了値を返します。
 * @param[in] executable 検証済み固定絶対EXE。
 * @param[in] arguments 引用済み固定argv列。
 * @param[in] directory 検証済み作業directory。
 * @param[in] timeoutMs 待機の上限ms。
 * @param[in] proxy trueなら既存proxy環境だけを引き継ぎます。
 * @return 元DWORD終了値。
 * @throws std::exception 起動／job／待機失敗。timeout後も部分fileは保持します。
 */
DWORD executeSetupChild( const fs::path &executable, const std::wstring &arguments,
						const fs::path &directory, const DWORD timeoutMs, const bool proxy)
{
	std::wstring command = quote( executable.native()) + arguments ;	// 変更可能なCreateProcess引数。
	std::vector<wchar_t> windows( 32768U) ;								// SystemRootをOSから取得する有限buffer。
	const UINT			 length =
		// 実文字数。
		GetWindowsDirectoryW( windows.data(), static_cast<UINT>( windows.size())) ;
	const DWORD windowsError = length == 0U ? GetLastError() : ERROR_SUCCESS ;	// API直後の元code。
	// 実API失敗の0と容量超過の意味拒否を分離し、元codeを失わない。
	if( length == 0U) {
		failApi( "SETUP_CHILD_SYSTEMROOT", windowsError) ;
	}

	require( length < windows.size(), "SETUP_CHILD_SYSTEMROOT") ;
	const std::wstring systemDrive =
		// OS由来の検査済みdrive。
		setupChildSystemDrive( std::wstring_view( windows.data(), length)) ;
	std::wstring environment = L"SystemRoot=" + std::wstring( windows.data()) ;	// 固定環境。
	environment.push_back( L'\0') ;
	environment += L"SystemDrive=" + systemDrive ;
	environment.push_back( L'\0') ;
	environment += L"PYTHONIOENCODING=utf-8" ;
	environment.push_back( L'\0') ;
	// 利用者のproxyだけを既存resolverへ引き継ぎ、PATH/PYTHONPATHは渡さない。
	if( proxy) {
		appendProxyEnvironment( environment) ;
	}

	environment.push_back( L'\0') ;
	const Handle group = own( CreateJobObjectW( nullptr, nullptr)) ;	// 例外時も全子孫を停止する。
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{} ;						// jobを閉じたときの停止契約。
	limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE ;
	requireBool( SetInformationJobObject( group.get(), JobObjectExtendedLimitInformation, &limits,
										static_cast<DWORD>( sizeof( limits))),
				"SETUP_CHILD_JOB") ;
	STARTUPINFOW startup{} ;	// 元の有限streamへ診断を返す。
	startup.cb		   = sizeof( startup) ;
	startup.dwFlags	   = STARTF_USESTDHANDLES ;
	startup.hStdInput  = standardHandle( STD_INPUT_HANDLE) ;
	startup.hStdOutput = standardHandle( STD_OUTPUT_HANDLE) ;
	startup.hStdError  = standardHandle( STD_ERROR_HANDLE) ;
	PROCESS_INFORMATION process{} ;	// 成功後にRAIIへ移す。
	requireBool( CreateProcessW( executable.c_str(), command.data(), nullptr, nullptr, TRUE,
							   CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | CREATE_SUSPENDED,
							   environment.data(), directory.c_str(), &startup, &process),
				"SETUP_CHILD_CREATE") ;
	const Handle child	= own( process.hProcess) ;	// 待機対象の実process。
	const Handle thread = own( process.hThread) ;	// 初期停止thread。
	const BOOL	 assigned =
		// 実行より前に結合する。
		AssignProcessToJobObject( group.get(), child.get()) ;
	const DWORD assignError = assigned == FALSE ? GetLastError() : ERROR_SUCCESS ;	// 元code。
	// 未結合childを動作させず停止し、元の割当て失敗を伝える。
	if( assigned == FALSE) {
		requireBool( TerminateProcess( child.get(), 2U), "SETUP_CHILD_UNASSIGNED_STOP") ;
		static_cast<void>( WaitForSingleObject( child.get(), 5000U)) ;
		failApi( "SETUP_CHILD_ASSIGN", assignError) ;
	}

	const DWORD resumed = ResumeThread( thread.get()) ;	// job結合後だけ実行する。
	// 再開失敗も元codeを失わずjobのRAIIで停止する。
	if( resumed == MAXDWORD) {
		failApi( "SETUP_CHILD_RESUME", GetLastError()) ;
	}

	const DWORD waited = WaitForSingleObject( child.get(), timeoutMs) ;	// 操作別の固定待機。
	// timeoutを成功へ変換せず、job停止と部分file保持へ進む。
	if( waited != WAIT_OBJECT_0) {
		const DWORD error = waited == WAIT_FAILED ? GetLastError() : WAIT_TIMEOUT ;	// 元結果。
		failApi( "SETUP_CHILD_WAIT_UNKNOWN", error) ;
	}

	DWORD exit{} ;	// DWORDを正規化せず返す。
	requireBool( GetExitCodeProcess( child.get(), &exit), "SETUP_CHILD_EXIT") ;
	std::printf( "SETUP_CHILD_COMPLETE exit=%lu\n", static_cast<unsigned long>( exit)) ;
	return exit ;
}
/** @brief 保護された配布用有限JSONを実handleから読みます。
 * @param[in] path 固定run memberまたは固定入力です。
 * @param[in] maximum 読取り前に検査するbyte上限です。
 * @return 同じhandleから完全に読んだ原byteです。
 */
std::string distributionRead( const fs::path	  &path,
							 const std::size_t maximum = DISTRIBUTION_JSON_MAXIMUM_BYTES)
{
	require( maximum > 0U && maximum <= DISTRIBUTION_JSON_MAXIMUM_BYTES, "DISTRIBUTION_JSON_LIMIT") ;
	fs::path preferred = path ;	// 元pathの意味を変えずseparator表記だけを統一します。
	preferred.make_preferred() ;
	const Handle checked =
		// 差替えとhardlinkを拒否する実fileです。
		openChecked( preferred, false, true) ;
	const auto token = userToken() ;	// ACL検査中だけSIDを保持します。
	// Win32が返したTOKEN_USER layoutから借用します。
	PSID	   user = reinterpret_cast<const TOKEN_USER *>( token.data())->User.Sid ;
	checkSecurity( checked.get(), user, false, false) ;
	const std::wstring apiPath = preferred.native().size() >= 248U
									 ? L"\\\\?\\" + preferred.native()
									 : preferred.native() ;	// 正規入力のAPI表記だけです。
	const Handle	   file =
		own( CreateFileW( apiPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
						FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;	// 同じ保護fileを読みます。
	LARGE_INTEGER size{} ;											// 読取り前の実byte数です。
	requireBool( GetFileSizeEx( file.get(), &size), "DISTRIBUTION_SIZE") ;
	require( size.QuadPart > 0 && static_cast<std::uint64_t>( size.QuadPart) <= maximum,
			"DISTRIBUTION_FILE_LIMIT") ;
	std::string bytes( static_cast<std::size_t>( size.QuadPart), '\0') ;	// 上限内の原byteです。
	DWORD		count{} ;													// 実読取り数です。
	requireBool(
		ReadFile( file.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &count, nullptr),
		"DISTRIBUTION_READ") ;
	require( count == bytes.size(), "DISTRIBUTION_READ_SIZE") ;
	return bytes ;
}

/** @brief 保持中transferの可搬参照をACL非移設のまま有限読取りします。
 * @param[in] path 同じimport操作が実handle固定した固定参照memberです。
 * @return 16MiB以下の元byte。通信許可や保護run証拠にはなりません。
 * @throws std::exception 通常file、hardlink、容量またはI/O不正。
 * @note 呼出し元が祖先と全transfer fileを子終了まで固定します。既存保護readerは変更しません。
 */
std::string distributionPortableRead( const fs::path &path)
{
	fs::path preferred = path ;	// 実最終pathのseparator表記へ合わせます。
	preferred.make_preferred() ;
	const Handle checked = openChecked( preferred, false, true) ;	// 通常file/単一linkを再確認します。
	const Handle file =
		own( CreateFileW( preferred.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
						FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;	// 置換/書込みを共有しません。
	LARGE_INTEGER size{} ;											// 先に有限長を検査します。
	requireBool( GetFileSizeEx( file.get(), &size), "DISTRIBUTION_PORTABLE_SIZE") ;
	require( size.QuadPart > 0 &&
				size.QuadPart <= static_cast<LONGLONG>( DISTRIBUTION_JSON_MAXIMUM_BYTES),
			"DISTRIBUTION_PORTABLE_LIMIT") ;
	std::string bytes( static_cast<std::size_t>( size.QuadPart), '\0') ;	// 元byteを所有します。
	DWORD		count{} ;													// 同handleから完全に読んだ件数です。
	requireBool(
		ReadFile( file.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &count, nullptr),
		"DISTRIBUTION_PORTABLE_READ") ;
	require( count == bytes.size(), "DISTRIBUTION_PORTABLE_READ_SIZE") ;
	return bytes ;
}

/** @brief 一host reviewの有限requestと固定raw二件を子終端まで固定します。
 * @param[in] request 明示された通常JSON fileの絶対pathです。
 * @param[in,out] handles 祖先と三fileの所有handleを追加し、呼出し側が子終了まで保持します。
 * @return 固定した64KiB以下requestの小文字SHA-256です。
 * @throws std::exception path、単一link、reparse、容量、共有競合または読取り失敗。
 * @note 可搬入力のACLを権限の根拠にせず、既存package/root/実leaseで変更権限を検査します。
 */
std::wstring lockHeldHostReviewInputs( const fs::path &request, std::vector<Handle> &handles)
{
	checkPath( request) ;
	require( request.filename() != L"baseline.raw.html" && request.filename() != L"current.raw.html",
			"HOST_REVIEW_REQUEST_NAME") ;
	lockAncestors( request.parent_path(), handles) ;
	std::wstring requestHash ;	// 同じ固定requestだけをcontextへ結合します。
	// 三file以外を走査せず、それぞれの実handleと読取り上限を固定します。
	for( const auto &path : {request, request.parent_path() / L"baseline.raw.html",
							request.parent_path() / L"current.raw.html"}) {
		handles.push_back( openChecked( path, false, true)) ;
		const auto raw		 = distributionPortableRead( path) ;	// 同じ共有拒否期間の原byteです。
		const bool isRequest = path == request ;					// JSONだけ64KiB上限です。
		require( raw.size() <= (isRequest ? 65536U : 1048576U), "HOST_REVIEW_INPUT_LIMIT") ;
		// requestの内容判断は同じlease内のPython validatorへ一度だけ委譲します。
		if( isRequest) {
			requestHash = fileHash( path) ;
		}
	}

	return requestHash ;
}

/** @brief 配布結果をCREATE_NEW・flush・読戻しで固定します。
 * @param[in] path 親が決めた固定run相対memberです。
 * @param[in] bytes 同runのnative原結果です。
 */
void distributionSave( const fs::path &path, const std::string_view bytes)
{
	require( !bytes.empty() && bytes.size() <= DISTRIBUTION_JSON_MAXIMUM_BYTES,
			"DISTRIBUTION_FILE_LIMIT") ;
	const std::wstring apiPath = path.native().size() >= 248U
									 ? L"\\\\?\\" + path.native()
									 : path.native() ;	// 固定run memberの長pathを保持します。
	{
		const Handle file =
			own( CreateFileW( apiPath.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_NEW,
							FILE_ATTRIBUTE_NORMAL, nullptr)) ;	// 保護親のACLだけを継承します。
		DWORD count{} ;											// 実保存byte数です。
		requireBool(
			WriteFile( file.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &count, nullptr),
			"DISTRIBUTION_WRITE") ;
		require( count == bytes.size(), "DISTRIBUTION_WRITE_SIZE") ;
		requireBool( FlushFileBuffers( file.get()), "DISTRIBUTION_FLUSH") ;
	}
	require( distributionRead( path) == bytes, "DISTRIBUTION_READBACK") ;
}

/** @brief 原byteのSHA-256を固定比較形式で返します。
 * @param[in] bytes 同じ保存・解析対象の1byte以上16MiB以下の原byteです。
 * @return 小文字SHA-256です。
 * @note 呼出前に収集JSON文脈を検査し、既存CNGの128MiB入口を再利用します。
 *       共通hashの用途上限でJSON予算を拡大せず、従来1/8MiB入口を変更しません。
 */
std::wstring distributionHash( const std::string_view bytes)
{
	require( !bytes.empty() && bytes.size() <= DISTRIBUTION_JSON_MAXIMUM_BYTES,
			"DISTRIBUTION_JSON_LIMIT") ;
	std::wstring hash ;	// 公開URL等を出力しない比較値です。
	require( computeDriverContainerSha256( bytes, hash) == 0, "DISTRIBUTION_HASH") ;
	return hash ;
}

/** @brief JSONの余剰fieldと欠損を同時に拒否します。
 * @param[in] object 検査対象の閉じたobjectです。
 * @param[in] fields 必須field集合です。
 */
void distributionFields( const SetupJson								  &object,
						const std::initializer_list<std::wstring_view> fields)
{
	require( object.Size() == fields.size(), "DISTRIBUTION_FIELDS") ;
	// 固定fieldを全て確認し、未知revisionを暗黙に受理しません。
	for( const auto field : fields) {
		require( object.HasKey( field), "DISTRIBUTION_FIELDS") ;
	}
}

/** @brief OSの現在UTCを有限millisecondで取得します。
 * @return 正のUTC millisecondです。
 */
std::uint64_t distributionUtc()
{
	const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
						 std::chrono::system_clock::now().time_since_epoch())
						 .count() ;	// OS時計の原値です。
	require( now > 0, "DISTRIBUTION_CLOCK") ;
	return static_cast<std::uint64_t>( now) ;
}

/** @brief native実履歴の全名を保存descriptorへ単調結合します。
 * @param[in,out] descriptor 初回originの保護descriptorです。
 * @param[in] runs 今回検査した全旧run名です。
 */
void distributionRetainLegacy( SetupJson &descriptor, const std::vector<std::wstring> &runs)
{
	const auto previous =
		// 既知履歴をfresh化しません。
		descriptor.GetNamedArray( L"legacyRunNames") ;
	// 一度確認した旧runが消えた場合は部分履歴を新規扱いしません。
	for( const auto &value : previous) {
		require( std::find( runs.begin(), runs.end(), value.GetString()) != runs.end(),
				"DISTRIBUTION_LEGACY_HISTORY_MISSING") ;
	}

	SetupArray names ;	// 次回の消失検査に使う全名です。
	// 既存validatorが完全に読んだ全run名だけを保持します。
	for( const auto &name : runs) {
		names.Append( SetupValue::CreateStringValue( name)) ;
	}

	descriptor.Insert( L"legacyRunNames", names) ;
}

/** @brief 初回完了と実identityを照合して専用native leaseを取得します。
 * @param[in] root 保護workspaceです。
 * @param[in] package 固定実行入力です。
 * @param[out] origin 同じ実rootに一致した両側参照です。
 * @param[out] pristine 空履歴の専用型である場合trueです。許可引数ではありません。
 * @param[in] retainHistory falseなら保存済みdescriptorとの完全一致を要求し、全byteを変更しません。
 * @return 同じ子終了まで所有するnative writerと全共有scopeです。
 */
CollectorSetupAdmission acquireCollectorDistributionAdmission( const fs::path &root,
															  const fs::path &package,
															  SetupJson &origin, bool &pristine,
															  const bool retainHistory = true)
{
	SetupJson  descriptor = SetupJson::Parse( winrt::to_hstring(
		 // 保護保存値です。
		 distributionRead( root / L"distribution-origin-init-v1.json", 262144U))) ;
	const auto originalDescriptor =
		// 非保存検査では履歴fieldの補完も拒否します。
		descriptor.Stringify() ;
	distributionFields( descriptor, {L"schema", L"phase", L"nativeRoot", L"nativeIdentity",
									L"workspaceRoot", L"workspaceIdentity", L"monitorRoot",
									L"monitorIdentity", L"initialPlanSha256", L"emptyFingerprint",
									L"legacyHistoryEverObserved", L"legacyRunNames"}) ;
	require( descriptor.GetNamedString( L"schema") == L"dc-collector-distribution-origin-init-v1" &&
				descriptor.GetNamedString( L"phase") == L"COMPLETE",
			"DISTRIBUTION_ORIGIN_INCOMPLETE") ;
	const auto initialHash =
		// 初回planの原hashです。
		descriptor.GetNamedString( L"initialPlanSha256") ;
	require( initialHash.size() == 64U &&
				initialHash == distributionHash(
								   distributionRead( root / L"distribution-initial-plan-v1.json")) &&
				descriptor.GetNamedString( L"emptyFingerprint") == distributionHash( "[]\n"),
			"DISTRIBUTION_INITIAL_PLAN_BINDING") ;
	const fs::path nativeRoot(
		// 正式選択済み原点です。
		descriptor.GetNamedString( L"nativeRoot").c_str()) ;
	const fs::path monitorRoot(
		// Active正本です。
		descriptor.GetNamedString( L"monitorRoot").c_str()) ;
	checkPath( nativeRoot) ;
	checkPath( monitorRoot) ;
	require( !pathsOverlap( nativeRoot, root) && !pathsOverlap( nativeRoot, package) &&
				!pathsOverlap( nativeRoot, monitorRoot) && !pathsOverlap( monitorRoot, package),
			"ORIGIN_OVERLAP") ;
	CollectorSetupAdmission result ;	// 全検証完了まで外へ出しません。
	result.store = std::make_shared<LocalCollectorStateStore>() ;
	requireStatus( result.store->initializeExistingWriter( nativeRoot), "DISTRIBUTION_NATIVE_WRITER") ;
	origin = originBinding( nativeRoot, root, monitorRoot) ;
	// 現在の全実体と初回descriptorを毎run比較します。
	for( const auto key : {L"nativeRoot", L"nativeIdentity", L"workspaceRoot", L"workspaceIdentity",
						  L"monitorRoot", L"monitorIdentity"}) {
		require( origin.GetNamedString( key) == descriptor.GetNamedString( key),
				"DISTRIBUTION_ORIGIN_CHANGED") ;
	}

	std::string marker ;	// 同じwriterが保護読取りした参照です。
	bool		found{} ;	// 消失をfreshへ降格しません。
	requireStatus( result.store->read( L"current/collector-monitor-origin-v1.json", marker, found),
				  "DISTRIBUTION_ORIGIN_READ") ;
	require( found && marker == winrt::to_string( origin.Stringify()) &&
				distributionRead( root / L"origin.json", 262144U) == marker,
			"DISTRIBUTION_ORIGIN_CHANGED") ;
	std::vector<std::wstring> current ;	// 未知modeを除外せず全名を読みます。
	std::vector<std::wstring> runs ;	// 過去に確認した履歴も比較します。
	requireStatus( result.store->listCurrentNames( current), "DISTRIBUTION_NATIVE_CURRENT") ;
	requireStatus( result.store->listRunNames( runs), "DISTRIBUTION_NATIVE_RUNS") ;
	const bool historyPresent =
		!runs.empty() || std::any_of( current.begin(), current.end(), []( const auto &name) {
			return name != L"collector-monitor-origin-v1.json" ;
		}) ; // 未知/不完全も履歴です。
	// 拒否する未知履歴でも観測した事実は単調保存し、後の消失でpristineへ戻しません。
	if( historyPresent || descriptor.GetNamedBoolean( L"legacyHistoryEverObserved")) {
		distributionRetainLegacy( descriptor, runs) ;
		descriptor.Insert( L"legacyHistoryEverObserved", SetupValue::CreateBooleanValue( true)) ;
		// 切替は既知履歴だけを読み、初回descriptorの原byteを再保存しません。
		if( retainHistory) {
			writeCollectorSetupProtectedMetadata( root / L"distribution-origin-init-v1.json",
												 winrt::to_string( descriptor.Stringify()), true) ;
		} else {
			require( descriptor.Stringify() == originalDescriptor,
					"WORKSPACE_SWITCH_NATIVE_HISTORY_UNREVIEWED") ;
		}
	}

	// Campaignとsegmentedの共有予約は本callerでは所有できません。
	for( const auto &names : {current, runs}) {
		// 元admissionと同じ全scopeを確認します。
		for( const auto &name : names) {
			require( !name.starts_with( L"campaign-") && name != L"collector-campaign-mode-v1.json",
					"NATIVE_SHARED_SCOPE_UNSUPPORTED") ;
		}
	}

	std::wstring reason ;	// 元validatorの固定拒否理由です。
	requireStatus(
		inspectLocalCollectorLegacy( *result.store, distributionUtc(), result.snapshot, reason),
		"DISTRIBUTION_LEGACY_INVALID") ;
	pristine = runs.empty() && current.size() == 1U &&
			   current.front() == L"collector-monitor-origin-v1.json" &&
			   result.snapshot.requests.empty() && result.snapshot.waits.empty() ;
	// legacy観測後は全空でもpristineへ戻りません。
	if( pristine) {
		require( !descriptor.GetNamedBoolean( L"legacyHistoryEverObserved") &&
					descriptor.GetNamedArray( L"legacyRunNames").Size() == 0U,
				"DISTRIBUTION_LEGACY_HISTORY_MISSING") ;
		result.snapshot.fileCount = 0U ;
	} else {
		require( !result.snapshot.requests.empty(), "NATIVE_REQUEST_SCOPE_MISSING") ;
		// 待機だけのscopeを元builderで証明できないときは非共有にしません。
		for( const auto &wait : result.snapshot.waits) {
			require(
				std::any_of( result.snapshot.requests.begin(), result.snapshot.requests.end(),
							[&wait]( const auto &request) { return request.group == wait.group ; }),
				"NATIVE_REQUEST_SCOPE_UNVERIFIED") ;
		}

		distributionRetainLegacy( descriptor, runs) ;
		descriptor.Insert( L"legacyHistoryEverObserved", SetupValue::CreateBooleanValue( true)) ;
		// 非保存検査では再確認によるbyte変更を行わず、不足した原記録を拒否します。
		if( retainHistory) {
			writeCollectorSetupProtectedMetadata( root / L"distribution-origin-init-v1.json",
												 winrt::to_string( descriptor.Stringify()), true) ;
		} else {
			require( descriptor.Stringify() == originalDescriptor,
					"WORKSPACE_SWITCH_NATIVE_HISTORY_UNREVIEWED") ;
		}
	}

	std::vector<LocalCollectorTarget> targets ;			// 現在native targetの将来共有scopeも常にHOLDします。
	std::wstring					  manifestHash ;	// 既存builderによる検証hashです。
	require( loadLocalCollectorManifest( package / L"config/targets.json", targets, manifestHash),
			"DISTRIBUTION_NATIVE_TARGETS") ;
	// 実旧requestと現在targetを同じ公式builderで結合します。
	for( const auto &target : targets) {
		LocalCollectorRequest request ;	// 端末由来URLは含みません。
		require( makeLocalCollectorRequest( target, request), "NATIVE_REQUEST_SCOPE_UNVERIFIED") ;
		result.snapshot.requests.push_back( std::move( request)) ;
	}

	std::set<std::wstring> requests ;	// 共通GET\nURL式の一意集合です。
	std::set<std::wstring> hosts ;		// 実公式hostの完全集合です。
	// 旧履歴と現在native targetの双方から予約host/requestを固定します。
	for( const auto &request : result.snapshot.requests) {
		const auto	 end  = request.url.find( L'/', 8U) ;		// authority終端です。
		std::wstring host = request.url.substr( 8U, end - 8U) ;	// Exact hostです。
		require( request.url.starts_with( L"https://") && !host.empty() &&
					host.find_first_of( L":@?#\\") == std::wstring::npos &&
					(request.group == L"asus" || request.group == L"intel"),
				"NATIVE_REQUEST_SCOPE_UNVERIFIED") ;
		std::transform( host.begin(), host.end(), host.begin(), []( const wchar_t value) {
			return value >= L'A' && value <= L'Z' ? static_cast<wchar_t>( value + (L'a' - L'A'))
												  : value ;
		}) ;
		requests.insert( distributionHash( "GET\n" + winrt::to_string( request.url))) ;
		hosts.insert( distributionHash( winrt::to_string( host))) ;
	}

	require( !requests.empty() && !hosts.empty(), "NATIVE_REQUEST_SCOPE_UNVERIFIED") ;
	result.requestHashes.assign( requests.begin(), requests.end()) ;
	result.hostHashes.assign( hosts.begin(), hosts.end()) ;
	return result ;
}
} // namespace

void withCollectorSetupProtectedRoot( const fs::path &root, const std::function<void()> &operation)
{
	checkPath( root) ;
	std::vector<Handle> held ;	// 操作中のrootと祖先の置換を拒否する。
	lockAncestors( root, held) ;
	const auto	 token = userToken() ;	// 同じprocess userのSIDを保持する。
	// Windowsが返したTOKEN_USERの先頭layoutだけを借用する。
	PSID		 user	= reinterpret_cast<const TOKEN_USER *>( token.data())->User.Sid ;
	const Handle handle = openChecked( root, true, false) ;	// 保護rootの実体。
	checkSecurity( handle.get(), user, true, true) ;
	operation() ;
}

void withCollectorSetupProtectedFile( const fs::path &path, const std::function<void()> &operation,
									 const bool protectedParent)
{
	fs::path preferred = path ;	// 呼出し元を変更せず、同じ入力のseparator表記だけを所有する。
	preferred.make_preferred() ;
	std::vector<Handle> ancestors ;	// 実入力の祖先を操作中保持する。
	lockAncestors( preferred.parent_path(), ancestors) ;
	const Handle checked = openChecked( preferred, false, true) ;	// 書込みと置換を共有しない。
	const auto	 token	 = userToken() ;							// current userのSIDを固定する。
	// OSのTOKEN_USER bufferからSIDだけを借用する。
	PSID		 user = reinterpret_cast<const TOKEN_USER *>( token.data())->User.Sid ;
	checkSecurity( checked.get(), user, false, false) ;
	const Handle parent =
		// 明示されたrootまたは継承childの役割で、直接の親を厳密に照合する。
		openChecked( preferred.parent_path(), true, false) ;
	checkSecurity( parent.get(), user, true, protectedParent) ;
	operation() ;
}

std::string readCollectorSetupProtectedMetadata( const fs::path &path)
{
	const Handle checked = openChecked( path, false, true) ;	// 単一linkと実pathを固定する。
	const auto	 token	 = userToken() ;						// 継承ACEの照合用SIDを保持する。
	// OSのTOKEN_USER bufferの先頭からSIDだけを借用する。
	PSID		 user = reinterpret_cast<const TOKEN_USER *>( token.data())->User.Sid ;
	checkSecurity( checked.get(), user, false, false) ;
	const Handle input =
		own( CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
						FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;	// 読取り実体。
	LARGE_INTEGER size{} ;											// 有限metadataのbyte数。
	requireBool( GetFileSizeEx( input.get(), &size), "TASK_METADATA_SIZE") ;
	require( size.QuadPart > 0 && size.QuadPart <= 65536, "TASK_METADATA_LIMIT") ;
	std::string bytes( static_cast<std::size_t>( size.QuadPart), '\0') ;	// 原byteを所有する。
	DWORD		count{} ;													// 実読取り数。
	requireBool(
		ReadFile( input.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &count, nullptr),
		"TASK_METADATA_READ") ;
	require( count == bytes.size(), "TASK_METADATA_EOF") ;
	return bytes ;
}

void writeCollectorSetupProtectedMetadata( const fs::path &path, const std::string_view bytes,
										  const bool replace)
{
	require( !bytes.empty() && bytes.size() <= 65536U, "TASK_METADATA_LIMIT") ;
	// 置換対象を保護検査し、任意の既存fileを暗黙に引き継がない。
	if( replace) {
		static_cast<void>( readCollectorSetupProtectedMetadata( path)) ;
	}

	GUID nonce{} ;	// 一時fileだけの衝突しない識別子。
	requireStatus( static_cast<DWORD>( CoCreateGuid( &nonce)), "TASK_METADATA_GUID") ;
	std::array<wchar_t, 40> text{} ;	// GUIDの固定容量。
	require( StringFromGUID2( nonce, text.data(), static_cast<int>( text.size())) > 0,
			"TASK_METADATA_GUID_TEXT") ;
	const fs::path temporary = path.native() + L"." + text.data() + L".tmp" ;	// 同じ保護親。
	{
		const Handle output =
			own( CreateFileW( temporary.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_NEW,
							FILE_ATTRIBUTE_NORMAL, nullptr)) ;	// 親の三principalを継承する。
		DWORD written{} ;										// 保存済みbyte数。
		requireBool( WriteFile( output.get(), bytes.data(), static_cast<DWORD>( bytes.size()),
							  &written, nullptr),
					"TASK_METADATA_WRITE") ;
		require( written == bytes.size(), "TASK_METADATA_SHORT_WRITE") ;
		requireBool( FlushFileBuffers( output.get()), "TASK_METADATA_FLUSH") ;
	}
	require( readCollectorSetupProtectedMetadata( temporary) == bytes, "TASK_METADATA_TEMP_READBACK") ;
	requireBool( MoveFileExW( temporary.c_str(), path.c_str(),
							MOVEFILE_WRITE_THROUGH | (replace ? MOVEFILE_REPLACE_EXISTING : 0U)),
				"TASK_METADATA_RENAME") ;
	require( readCollectorSetupProtectedMetadata( path) == bytes, "TASK_METADATA_READBACK") ;
}

void createCollectorSetupProtectedRoot( const fs::path &root)
{
	checkPath( root) ;
	require( !fs::exists( root), "WORKSPACE_EXISTS") ;
	std::vector<Handle> ancestors ;	// 作成中の祖先置換を拒否する。
	lockAncestors( root.parent_path(), ancestors) ;
	const auto token = userToken() ;	// descriptor作成と検査で共有するSID所有byte。
	// TOKEN_USERはOSが作った同一bufferの先頭構造体としてのみ読み取る。
	PSID	   user = reinterpret_cast<const TOKEN_USER *>( token.data())->User.Sid ;
	LPWSTR	   sidText{} ;	// LocalAllocで受け取るSID文字列。
	requireBool( ConvertSidToStringSidW( user, &sidText), "WORKSPACE_SID") ;
	const Memory	   sidOwner( sidText) ;	// 全終了経路でSID文字列を回収する。
	const std::wstring sddl =
		L"O:" + std::wstring( sidText) + L"D:P(A;OICI;FA;;;" + std::wstring( sidText) +
		L")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" ;	// 作成時だけに使う固定三principal。
	PSECURITY_DESCRIPTOR raw{} ;				// 作成用descriptor。
	requireBool( ConvertStringSecurityDescriptorToSecurityDescriptorW( sddl.c_str(), SDDL_REVISION_1,
																	 &raw, nullptr),
				"WORKSPACE_SDDL") ;
	const Memory		descriptor( raw) ;	// 作成完了後に回収する。
	SECURITY_ATTRIBUTES attributes{sizeof( SECURITY_ATTRIBUTES), descriptor.get(),
								   FALSE} ;	// handle非継承。
	requireBool( CreateDirectoryW( root.c_str(), &attributes), "WORKSPACE_CREATE") ;
	const Handle handle = openChecked( root, true, false) ;	// 同じ実対象で保護を確認する。
	checkSecurity( handle.get(), user, true, true) ;
}

void prepareCollectorSetupDefaultParent( const fs::path &localAppData)
{
	checkPath( localAppData) ;
	std::vector<Handle> handles ;	// 作成と既存ACL検査中の祖先置換を拒否する。
	lockAncestors( localAppData, handles) ;
	const fs::path parent = localAppData / L"DriverCrate" ;	// 再帰作成を許可しない固定一階層。
	// 欠損親だけを保護creatorで新規作成し、後段失敗でも自動削除しない。
	if( !fs::exists( parent)) {
		createCollectorSetupProtectedRoot( parent) ;
		std::printf( "SETUP_DEFAULT_PARENT created=1 retained_on_failure=1 network=0 tasks=0\n") ;
		return ;
	}

	const Handle handle = openChecked( parent, true, false) ;	// 既存の通常directoryだけを固定する。
	const auto	 token	= userToken() ;							// 実userの借用SIDを保つ。
	// OSが返したTOKEN_USERの先頭だけを参照する。
	PSID		 user = reinterpret_cast<const TOKEN_USER *>( token.data())->User.Sid ;
	PSECURITY_DESCRIPTOR raw{} ;	// 既存DACLの保護bitを読み、変更しない。
	const DWORD	 queried = GetSecurityInfo( handle.get(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
										   nullptr, nullptr, nullptr, nullptr, &raw) ;	// 元API結果。
	const Memory descriptor( raw) ;														// 全終了経路で照会領域を解放する。
	requireStatus( queried, "DEFAULT_PARENT_SECURITY") ;
	SECURITY_DESCRIPTOR_CONTROL control{} ;		// 既存descriptorの保護状態。
	DWORD						revision{} ;	// APIの固定出力。
	requireBool( GetSecurityDescriptorControl( descriptor.get(), &control, &revision),
				"DEFAULT_PARENT_CONTROL") ;
	checkSecurity( handle.get(), user, true, (control & SE_DACL_PROTECTED) != 0U) ;
	std::printf( "SETUP_DEFAULT_PARENT created=0 acl_changed=0 network=0 tasks=0\n") ;
}

void copyCollectorSetupProtectedFile( const fs::path &source, const fs::path &target)
{
	const Handle input =
		own( CreateFileW( source.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
						FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;	// Sourceは変更共有せず借用する。
	const Handle output = own( CreateFileW( target.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_NEW,
										  FILE_ATTRIBUTE_NORMAL,
										  nullptr)) ;	// DACLはsourceから複写せず保護親から継承する。
	std::vector<std::byte> buffer( 65536U) ;			// 同じ固定容量とゼロ初期値をcopy完了まで所有する。
	std::uint64_t		   total{} ;					// Copy済みbyte数。
	// 一file上限内で実byteを読み、EOFまたは最初のI/O失敗で終了する。
	for( ;;) {
		DWORD read{} ;	// 今回の実読取りbyte数。
		requireBool(
			ReadFile( input.get(), buffer.data(), static_cast<DWORD>( buffer.size()), &read, nullptr),
			"WORKSPACE_COPY_READ") ;
		// EOFだけをcopy完了として扱う。
		if( read == 0U) {
			break ;
		}

		require( total <= 16777216U - read, "WORKSPACE_COPY_LIMIT") ;
		total += read ;
		DWORD written{} ;	// 今回の実保存byte数。
		requireBool( WriteFile( output.get(), buffer.data(), read, &written, nullptr),
					"WORKSPACE_COPY_WRITE") ;
		require( written == read, "WORKSPACE_COPY_WRITE_SHORT") ;
	}

	requireBool( FlushFileBuffers( output.get()), "WORKSPACE_COPY_FLUSH") ;
}

std::int32_t runCollectorSetupEmbedded( const std::span<const CollectorSetupEmbeddedFile> files,
									   const fs::path &installRoot, const bool yes)
{
	require( !files.empty() && files.size() <= 128U, "EMBEDDED_COUNT") ;
	std::set<fs::path> paths ;		// 重複を入力byteより前に拒否する固定集合。
	std::uint64_t	   total{} ;	// overflowを起こさない実byte合計。
	// 全fileを保存前に検査し、未知相対名やhash差をstagingへ持ち込まない。
	for( const auto &file : files) {
		const fs::path relative( file.path) ;	// compile時tableからの相対名。
		require( !relative.empty() && !relative.is_absolute() && !relative.has_root_path() &&
					file.path.find_first_of( L":\\\"\r\n") == std::wstring_view::npos &&
					paths.insert( relative).second,
				"EMBEDDED_PATH") ;
		// 親参照・空成分・Windows末尾正規化の曖昧性を拒否する。
		for( const auto &part : relative) {
			require( part != L"." && part != L".." && !part.empty() &&
						part.native().back() != L'.' && part.native().back() != L' ',
					"EMBEDDED_COMPONENT") ;
		}

		require( !file.bytes.empty() && file.bytes.size() <= 67108864U &&
					total <= 67108864U - file.bytes.size(),
				"EMBEDDED_SIZE") ;
		total += file.bytes.size() ;
		std::wstring digest ;	// 128MiB共通CNGへ渡す前に用途上限64MiBを適用する。
		require( computeDriverContainerSha256( file.bytes, digest) == 0 && digest == file.sha256,
				"EMBEDDED_HASH") ;
	}

	require( paths.contains( L"DriverCrateCollectorSetup.exe") &&
				paths.contains( L"package-manifest.json"),
			"EMBEDDED_INNER_SETUP") ;
	PWSTR		  raw{} ;	// OSが返すKnownFolder path。
	const HRESULT folderResult =
		// 元結果。
		SHGetKnownFolderPath( FOLDERID_LocalAppData, 0U, nullptr, &raw) ;
	const std::unique_ptr<wchar_t, decltype( &CoTaskMemFree)> folder(
		raw, &CoTaskMemFree) ;	// OS領域の所有者。
	winrt::check_hresult( folderResult) ;
	require( folder != nullptr, "EMBEDDED_KNOWN_FOLDER") ;
	GUID id{} ;	// staging専用の新規一意名。
	winrt::check_hresult( CoCreateGuid( &id)) ;
	std::array<wchar_t, 40> guid{} ;	// 固定GUID文字列容量。
	require( StringFromGUID2( id, guid.data(), static_cast<int>( guid.size())) > 0, "EMBEDDED_GUID") ;
	const fs::path root = fs::path( folder.get()) / (L"DriverCrateCollectorSetup-" +
													// 新規専用root。
													std::wstring( guid.data())) ;
	createCollectorSetupProtectedRoot( root) ;
	std::printf( "SETUP_STAGING stagingRetained=true files=%zu\n", files.size()) ;
	std::vector<Handle> handles ;	// 子終了まで全祖先と実payloadを固定する。
	lockAncestors( root, handles) ;
	const auto token = userToken() ;	// 同じSIDでrootと継承childを検査する。
	// TOKEN_USERはOSが返した所有bufferの先頭だけを読む。
	PSID	   user = reinterpret_cast<const TOKEN_USER *>( token.data())->User.Sid ;
	// 固定tableの全fileだけをCREATE_NEWで保存する。
	for( const auto &file : files) {
		writeEmbeddedFile( root, file, user, handles) ;
	}

	// 作成済み全directory/fileを実ACL・identityと書込み非共有handleへ結合する。
	inspectTree( root, user, true, handles, PACKAGE_TOTAL_MAXIMUM_BYTES,
				PACKAGE_TOTAL_MAXIMUM_BYTES) ;
	// 実保存byteを再hashし、resource検査後の保存不整合を拒否する。
	for( const auto &file : files) {
		std::wstring digest ;	// 実file全体の指紋。
		require( computeFileSha256( (root / file.path).native(), digest) == 0 &&
					digest == file.sha256,
				"EMBEDDED_SAVED_HASH") ;
	}

	const fs::path inner = root / L"DriverCrateCollectorSetup.exe" ;	// shell/PATHを介さない固定EXE。
	const DWORD	   checked = executeSetupChild( inner, L" --check-package " + quote( root.native()),
											   root, 180000U, false) ;	// 全内部package検査。
	// 内部検査の非0を元bit列のまま返し、installへ進めない。
	if( checked != 0U) {
		return std::bit_cast<std::int32_t>( checked) ;
	}

	const fs::path destination = yes && installRoot.empty()
									 ? fs::path( folder.get()) / L"DriverCrate" / L"Collector"
									 : installRoot ;	// 明示yesでも内部setupに正確な既定先を渡す。
	std::wstring   arguments   = L" --install" ;		// 公開された固定installだけを委譲する。
	// 明示先をそのまま内部setupの既存検査へ渡す。
	if( !destination.empty()) {
		arguments += L" " + quote( destination.native()) ;
	}

	// --yesは明示先付きの場合だけCLIで許可される。
	if( yes) {
		arguments += L" --yes" ;
	}

	return std::bit_cast<std::int32_t>( executeSetupChild( inner, arguments, root, 180000U, false)) ;
}

// 保存窓の故障注入は専用test targetだけに存在します。
#ifdef DRIVERCRATE_DISTRIBUTION_TESTING
static std::function<void( std::wstring_view)>
	distributionInitializationProbe ;	// 同期test中だけ借用します。
#endif

/** @brief 新規originの非通信初期化を保存phaseから再開します。
 * @param[in] package 固定packageです。
 * @param[in] root 保護workspaceです。
 * @param[in] nativeRoot 明示選択したnative originです。
 * @param[in] monitorRoot 明示選択したmonitor originです。
 * @return 完了0です。失敗時は部分保護stateを保持して例外を返します。
 */
int initializeCollectorDistributionOrigins( const fs::path &package, const fs::path &root,
										   const fs::path &nativeRoot, const fs::path &monitorRoot)
{
	checkPath( nativeRoot) ;
	checkPath( monitorRoot) ;
	require( !pathsOverlap( nativeRoot, root) && !pathsOverlap( nativeRoot, package) &&
				!pathsOverlap( nativeRoot, monitorRoot) && !pathsOverlap( monitorRoot, package),
			"ORIGIN_OVERLAP") ;
	const fs::path descriptorPath =
		root / L"distribution-origin-init-v1.json" ;	// 非可搬の保護descriptorです。
	SetupJson descriptor ;								// 保存窓から同じ予定rootへだけ再開します。
	// 既知originを新rootへ差替えて待機をresetしません。
	if( fs::exists( root / L"origin.json")) {
		const auto previous = readOrigin( root / L"origin.json") ;	// 正式選択済みの実参照です。
		require( previous.GetNamedString( L"nativeRoot") == nativeRoot.native() &&
					previous.GetNamedString( L"monitorRoot") == monitorRoot.native(),
				"DISTRIBUTION_ORIGIN_REPLACEMENT") ;
	}

	// 完了済みも実identityを再照合し、未知schema/phaseを初回扱いしません。
	if( fs::exists( descriptorPath)) {
		descriptor = SetupJson::Parse( winrt::to_hstring( distributionRead( descriptorPath, 262144U))) ;
		distributionFields( descriptor,
						   {L"schema", L"phase", L"nativeRoot", L"nativeIdentity", L"workspaceRoot",
							L"workspaceIdentity", L"monitorRoot", L"monitorIdentity",
							L"initialPlanSha256", L"emptyFingerprint", L"legacyHistoryEverObserved",
							L"legacyRunNames"}) ;
		require( descriptor.GetNamedString( L"schema") ==
						L"dc-collector-distribution-origin-init-v1" &&
					descriptor.GetNamedString( L"nativeRoot") == nativeRoot.native() &&
					descriptor.GetNamedString( L"monitorRoot") == monitorRoot.native() &&
					descriptor.GetNamedString( L"workspaceIdentity") == directoryIdentity( root),
				"DISTRIBUTION_ORIGIN_CHANGED") ;
	} else {
		descriptor.Insert(
			L"schema", SetupValue::CreateStringValue( L"dc-collector-distribution-origin-init-v1")) ;
		descriptor.Insert( L"phase", SetupValue::CreateStringValue( L"PLANNED")) ;
		descriptor.Insert( L"nativeRoot", SetupValue::CreateStringValue( nativeRoot.native())) ;
		descriptor.Insert( L"monitorRoot", SetupValue::CreateStringValue( monitorRoot.native())) ;
		descriptor.Insert( L"workspaceRoot", SetupValue::CreateStringValue( root.native())) ;
		descriptor.Insert( L"workspaceIdentity",
						  SetupValue::CreateStringValue( directoryIdentity( root))) ;
		// 未作成identityと未確定planだけを空で表し、完了前の通信を拒否します。
		for( const auto key : {L"nativeIdentity", L"monitorIdentity", L"initialPlanSha256"}) {
			descriptor.Insert( key, SetupValue::CreateStringValue( L"")) ;
		}

		descriptor.Insert( L"emptyFingerprint",
						  SetupValue::CreateStringValue( distributionHash( "[]\n"))) ;
		descriptor.Insert( L"legacyHistoryEverObserved", SetupValue::CreateBooleanValue( false)) ;
		descriptor.Insert( L"legacyRunNames", SetupArray{}) ;
		writeCollectorSetupProtectedMetadata( descriptorPath,
											 winrt::to_string( descriptor.Stringify()), false) ;
#ifdef DRIVERCRATE_DISTRIBUTION_TESTING
		// 同じ実保存後だけ停止窓を再現します。
		if( distributionInitializationProbe) {
			distributionInitializationProbe( L"PLANNED") ;
		}
#endif
	}

	const auto phase = descriptor.GetNamedString( L"phase") ;	// 未知phaseから再開しません。
	require( phase == L"PLANNED" || phase == L"NATIVE_READY" || phase == L"MONITOR_READY" ||
				phase == L"COMPLETE",
			"DISTRIBUTION_ORIGIN_PHASE") ;
	LocalCollectorStateStore store ;			// 全保存窓の間も実native writerを保持します。
	std::vector<Handle>		 monitorAncestors ;	// 外部monitorも初期化中の祖先置換を拒否します。
	lockAncestors( fs::exists( monitorRoot) ? monitorRoot : monitorRoot.parent_path(),
				  monitorAncestors) ;
	// 登録済み実体が消えた場合は作成APIを再適用しません。
	if( descriptor.GetNamedString( L"nativeIdentity").empty() && !fs::exists( nativeRoot)) {
		requireStatus( store.initialize( nativeRoot, true), "DISTRIBUTION_NATIVE_INITIALIZE") ;
	} else {
		requireStatus( store.initializeExistingWriter( nativeRoot), "DISTRIBUTION_NATIVE_WRITER") ;
	}

	const auto nativeIdentity = directoryIdentity( nativeRoot) ;	// 同じ実体を次回へ結合します。
	require( descriptor.GetNamedString( L"nativeIdentity").empty() ||
				descriptor.GetNamedString( L"nativeIdentity") == nativeIdentity,
			"DISTRIBUTION_ORIGIN_CHANGED") ;
	std::vector<std::wstring> current ;	// 空集合または全legacyを厳密に判定します。
	std::vector<std::wstring> runs ;	// 消失した履歴をfreshにしません。
	requireStatus( store.listCurrentNames( current), "DISTRIBUTION_NATIVE_CURRENT") ;
	requireStatus( store.listRunNames( runs), "DISTRIBUTION_NATIVE_RUNS") ;
	const bool empty = runs.empty() && (current.empty() ||
										(current.size() == 1U &&
										 // 初回だけの既知集合です。
										 current.front() == L"collector-monitor-origin-v1.json")) ;
	// 既存の正式originなしで一部旧historyを初回登録しません。
	if( !empty) {
		require( fs::exists( root / L"origin.json"), "DISTRIBUTION_ORIGIN_NOT_EMPTY") ;
		CollectorLegacySnapshot snapshot ;	// 既存の全履歴validatorを使います。
		std::wstring			reason ;	// 固定拒否理由です。
		requireStatus( inspectLocalCollectorLegacy( store, distributionUtc(), snapshot, reason),
					  "DISTRIBUTION_LEGACY_INVALID") ;
		require( !snapshot.requests.empty(), "NATIVE_REQUEST_SCOPE_MISSING") ;
		distributionRetainLegacy( descriptor, runs) ;
		descriptor.Insert( L"legacyHistoryEverObserved", SetupValue::CreateBooleanValue( true)) ;
	} else {
		require( !descriptor.GetNamedBoolean( L"legacyHistoryEverObserved"),
				"DISTRIBUTION_LEGACY_HISTORY_MISSING") ;
	}

	descriptor.Insert( L"nativeIdentity", SetupValue::CreateStringValue( nativeIdentity)) ;
	// 完了originはmonitorに初期化を再適用せず、全実identityをそのまま確認します。
	if( phase != L"COMPLETE") {
		descriptor.Insert( L"phase", SetupValue::CreateStringValue( L"NATIVE_READY")) ;
		writeCollectorSetupProtectedMetadata( descriptorPath,
											 winrt::to_string( descriptor.Stringify()), true) ;
#ifdef DRIVERCRATE_DISTRIBUTION_TESTING
		// 完了した同じnative phaseからの非通信再開を検査します。
		if( distributionInitializationProbe) {
			distributionInitializationProbe( L"NATIVE_READY") ;
		}
#endif
		// 初回全空monitorだけを既存initializeで作り、HTTPを禁止した固定childで読戻します。
		if( empty || fs::exists( root / L"origin.json")) {
			const auto arguments = fileBootstrapArguments( package) +
								   L" initialize-distribution-origins " + quote( root.native()) +
								   L" " + quote( monitorRoot.native()) ;	// 固定の非通信actionです。
			require( executeSetupChild( package / L"runtime/python.exe", arguments, package, 180000U,
									  false) == 0U,
					"DISTRIBUTION_MONITOR_INITIALIZE") ;
		}
	}

	const auto monitorIdentity =
		// 既知実体の消滅/置換を拒否します。
		directoryIdentity( monitorRoot) ;
	const auto monitorToken = userToken() ;	// 保護monitorの実ACLを照合します。
	// OS所有のTOKEN_USER bufferからSIDだけを借用します。
	PSID	   monitorUser = reinterpret_cast<const TOKEN_USER *>( monitorToken.data())->User.Sid ;
	const auto monitorHandle =
		// 初回保存終端まで実体を保持します。
		openChecked( monitorRoot, true, false) ;
	checkSecurity( monitorHandle.get(), monitorUser, true, false) ;
	require( descriptor.GetNamedString( L"monitorIdentity").empty() ||
				descriptor.GetNamedString( L"monitorIdentity") == monitorIdentity,
			"DISTRIBUTION_ORIGIN_CHANGED") ;
	descriptor.Insert( L"monitorIdentity", SetupValue::CreateStringValue( monitorIdentity)) ;
	// 初回planは非通信childが原入力から作った保存済み実byteへ結合します。
	if( fs::exists( root / L"distribution-initial-plan-v1.json")) {
		const auto planHash = distributionHash(
			// 原初回planです。
			distributionRead( root / L"distribution-initial-plan-v1.json")) ;
		require( descriptor.GetNamedString( L"initialPlanSha256").empty() ||
					descriptor.GetNamedString( L"initialPlanSha256") == planHash,
				"DISTRIBUTION_INITIAL_PLAN_BINDING") ;
		descriptor.Insert( L"initialPlanSha256", SetupValue::CreateStringValue( planHash)) ;
	}

	const auto	origin		= originBinding( nativeRoot, root, monitorRoot) ;	// 両側同じ7fieldです。
	const auto	originBytes = winrt::to_string( origin.Stringify()) ;			// 初回保存の原byteです。
	std::string marker ;														// 保存済み側をfresh化しません。
	bool		found{} ;														// 保存窓の未保存だけを区別します。
	requireStatus( store.read( L"current/collector-monitor-origin-v1.json", marker, found),
				  "DISTRIBUTION_ORIGIN_READ") ;
	require( !found || marker == originBytes, "DISTRIBUTION_ORIGIN_CHANGED") ;
	descriptor.Insert( L"phase", SetupValue::CreateStringValue( L"MONITOR_READY")) ;
	writeCollectorSetupProtectedMetadata( descriptorPath, winrt::to_string( descriptor.Stringify()),
										 true) ;
#ifdef DRIVERCRATE_DISTRIBUTION_TESTING
	// 同じ両identity保存後の窓だけを停止します。
	if( distributionInitializationProbe) {
		distributionInitializationProbe( L"MONITOR_READY") ;
	}
#endif
	// Native側を先に確定し、片側保存後の停止は同じidentityで非通信再開します。
	if( !found) {
		requireStatus( store.write( L"current/collector-monitor-origin-v1.json", originBytes),
					  "DISTRIBUTION_ORIGIN_SAVE") ;
	}
#ifdef DRIVERCRATE_DISTRIBUTION_TESTING
	// Native片側保存後も、同じ実体の非通信resumeだけを許します。
	if( distributionInitializationProbe) {
		distributionInitializationProbe( L"NATIVE_MARKER") ;
	}
#endif
	// 既知workspace originがある場合は同じ原byteだけを許します。
	if( fs::exists( root / L"origin.json")) {
		require( distributionRead( root / L"origin.json", 262144U) == originBytes,
				"DISTRIBUTION_ORIGIN_CHANGED") ;
	} else {
		writeCollectorSetupProtectedMetadata( root / L"origin.json", originBytes, false) ;
	}
#ifdef DRIVERCRATE_DISTRIBUTION_TESTING
	// 両側保存後・完了descriptor前の停止を再現します。
	if( distributionInitializationProbe) {
		distributionInitializationProbe( L"WORKSPACE_MARKER") ;
	}
#endif
	marker.clear() ;
	found = false ;
	requireStatus( store.read( L"current/collector-monitor-origin-v1.json", marker, found),
				  "DISTRIBUTION_ORIGIN_READBACK") ;
	require( found && marker == originBytes, "DISTRIBUTION_ORIGIN_READBACK") ;
	descriptor.Insert( L"phase", SetupValue::CreateStringValue( L"COMPLETE")) ;
	writeCollectorSetupProtectedMetadata( descriptorPath, winrt::to_string( descriptor.Stringify()),
										 true) ;
	std::printf( "DISTRIBUTION_ORIGINS_COMPLETE network=0 tasks=0\n") ;
	return 0 ;
}

/** @brief 二つの有限JSON値を意味を変えず全fieldで比較します。
 * @param[in] first 元typed観測からの保存値です。
 * @param[in] second 同固定childのassemble値です。
 * @param[in] depth 再帰上限16の現在深さです。
 * @return field順だけを無視し、全値が一致する場合trueです。
 */
bool distributionSameJson( const SetupJsonValue &first, const SetupJsonValue &second,
						  const std::size_t depth = 0U)
{
	// 元schemaの有限深さを越える未知値は比較成立にしません。
	if( depth > 16U || first.ValueType() != second.ValueType()) {
		return false ;
	}

	// 既存固定schemaに現れるJSON型だけを同じ値で比較します。
	switch( first.ValueType()) {
		// 全fieldを完全照合します。
		case winrt::Windows::Data::Json::JsonValueType::Object: {
			const auto left	 = first.GetObject() ;	// 元objectを同期借用します。
			const auto right = second.GetObject() ;	// 比較先objectです。
			// 不足/余分fieldを同じ意味として扱いません。
			if( left.Size() != right.Size()) {
				return false ;
			}

			// 元全fieldを再帰比較し、途中不一致で停止します。
			for( const auto &item : left) {
				// 存在確認後だけ同keyを読み、欠損をnullへ補完しません。
				if( !right.HasKey( item.Key()) ||
				   !distributionSameJson( item.Value(), right.Lookup( item.Key()), depth + 1U)) {
					return false ;
				}
			}

			return true ;
		}
		// 元順序を保ちます。
		case winrt::Windows::Data::Json::JsonValueType::Array: {
			const auto left	 = first.GetArray() ;	// 元配列です。
			const auto right = second.GetArray() ;	// 比較先です。
			// 件数の切捨てや重複追加を拒否します。
			if( left.Size() != right.Size()) {
				return false ;
			}

			// 元全要素を同じ位置へ照合します。
			for( std::uint32_t index = 0U; index < left.Size(); ++index) {
				// 部分一致だけを成功へ変換しません。
				if( !distributionSameJson( left.GetAt( index), right.GetAt( index), depth + 1U)) {
					return false ;
				}
			}

			return true ;
		}
		case winrt::Windows::Data::Json::JsonValueType::String:	// 原文字列の完全一致です。
			return first.GetString() == second.GetString() ;
		case winrt::Windows::Data::Json::JsonValueType::Number:	// 元整数の完全一致です。
			return first.GetNumber() == second.GetNumber() ;
		case winrt::Windows::Data::Json::JsonValueType::Boolean:	// 不明をfalseへ補いません。
			return first.GetBoolean() == second.GetBoolean() ;
		case winrt::Windows::Data::Json::JsonValueType::Null:	// 明示nullだけが一致します。
			return true ;
		default:	// 未登録型を成功へ補いません。
			return false ;
	}
}

/** @brief 保護journalが参照する同run原snapshotを読戻します。
 * @param[in] monitorRoot 同じ保持中writerのrootです。
 * @param[in] runId path文字を含まない固定run IDです。
 * @return 原bytehashを照合したrun本文です。
 */
SetupJson distributionSavedRun( const fs::path &monitorRoot, const std::wstring_view runId)
{
	require( runId.size() == 36U && runId.starts_with( L"run-") &&
				runId.find_first_not_of( L"0123456789abcdef", 4U) == std::wstring_view::npos,
			"DISTRIBUTION_RUN_REFERENCE") ;
	const auto journal = SetupJson::Parse( winrt::to_hstring(
		// 同writerの原参照です。
		distributionRead( monitorRoot / L"distribution/journal.json"))) ;
	const auto reference =
		// 固定runだけです。
		journal.GetNamedObject( L"runs").GetNamedObject( runId) ;
	const auto digest = reference.GetNamedString( L"sha256") ;	// content-addressed原hashです。
	require( digest.size() == 64U &&
				std::wstring_view{digest}.find_first_not_of( L"0123456789abcdef") ==
					std::wstring_view::npos &&
				reference.GetNamedString( L"member") == L"state-" + digest + L".json",
			"DISTRIBUTION_RUN_REFERENCE") ;
	const auto bytes = distributionRead( monitorRoot / L"distribution/runs" / runId /
										// 外部pathを受けません。
										reference.GetNamedString( L"member").c_str()) ;
	require( distributionHash( bytes) == digest, "DISTRIBUTION_RUN_STATE_HASH") ;
	return SetupJson::Parse( winrt::to_hstring( bytes)) ;
}

/** @brief 同じnative親だけが固定childの予約から一回runnerを起動します。
 * @note 公開ctor・成功JSON再import・boolによるlease代用はありません。
 */
class CollectorRegistryJobProtectedCaller final {
private:
	friend int runCollectorSetupWorkspace( const fs::path &, std::wstring_view, const fs::path &,
										  const fs::path &, const std::function<void()> &,
										  const fs::path &, const fs::path &) ;
	friend class CollectorDistributionTestAccess ;
#ifdef DRIVERCRATE_DISTRIBUTION_TESTING
	/// 独立test targetだけが同じ通常runnerへ完全fake I/Oを接続します。
	static inline std::function<NativeError( const CollectorRegistryJob &, ScanSessionId,
											CollectorRunPageScope &, const CollectorRunPageProof *,
											std::uint64_t, std::chrono::steady_clock::time_point,
											CollectorRegistryJobResult &)>
																				executionProbe_ ;
	/// 保存済み予約破損・子停止はtestだけが同じ検証前に注入します。
	static inline std::function<void( const fs::path &, HANDLE, std::uint32_t)>	reservationProbe_ ;
	/// 専用testだけが子終端と保持中leaseの実状態を確認します。
	static inline std::function<void( HANDLE, const LocalCollectorStateStore &)> terminationProbe_ ;
#endif
	/** @brief 子handleより先に終端を確認し、確認中のnative writerを強所有します。 */
	class ChildLifetime final {
	public:
		/** @brief 同じcallerが所有する三resourceを解放順へ結合します。
		 * @param[in] group 同じ所有Jobです。guardより長く生存します。
		 * @param[in] child 同じ実childです。guardより長く生存します。
		 * @param[in] lease 同じ実native writerの強所有参照です。
		 */
		ChildLifetime( HANDLE group, HANDLE child, std::shared_ptr<LocalCollectorStateStore> lease)
			: group_( group), child_( child), lease_( std::move( lease))
		{
		}
		/** @brief 終端を有限確認してから通常のlease解放へ進みます。
		 * @note 終端不能は固定診断付き異常終了とし、例外unwindによる通常解放を続けません。
		 */
		~ChildLifetime() noexcept
		{
			// 親側拒否時はpipeを閉じるより先に同じ所有子を停止します。
			if( WaitForSingleObject( child_, 0U) != WAIT_OBJECT_0) {
				const BOOL stoppedJob =
					// 同じ所有Jobだけを停止します。
					TerminateJobObject( group_, 2U) ;
				const DWORD jobError =
					// 元停止診断です。
					stoppedJob == FALSE ? GetLastError() : ERROR_SUCCESS ;
				DWORD processError{} ;	// 未結合childと停止競合も同じHANDLEだけを扱います。
				// Job割当て前の起動失敗も、外部PIDへ展開せず所有childだけを止めます。
				if( WaitForSingleObject( child_, 0U) != WAIT_OBJECT_0 &&
				   !TerminateProcess( child_, 2U)) {
					processError = GetLastError() ;
				}

				const DWORD ended =
					// 同じ子終端の有限待機です。
					WaitForSingleObject( child_, 5000U) ;
				// OS異常の終端不明をleaseの通常解放/成功へ変換しません。
				if( ended != WAIT_OBJECT_0) {
					const DWORD waitError =
						// 元待機診断です。
						ended == WAIT_FAILED ? GetLastError() : WAIT_TIMEOUT ;
					std::fprintf( stderr,
								 "DISTRIBUTION_CHILD_STOP_UNKNOWN job=%lu process=%lu wait=%lu\n",
								 static_cast<unsigned long>( jobError),
								 static_cast<unsigned long>( processError),
								 static_cast<unsigned long>( waitError)) ;
					std::fflush( stderr) ;
					std::terminate() ;
				}
			}
#ifdef DRIVERCRATE_DISTRIBUTION_TESTING
			// 子終端後・handle/lease解放前の実状態だけを専用fixtureへ渡します。
			if( terminationProbe_) {
				terminationProbe_( child_, *lease_) ;
			}
#endif
		}
		/** @brief 停止責任の複写を禁止します。
		 * @param[in] other 複写しない所有境界です。
		 */
		ChildLifetime( const ChildLifetime &other) = delete ;
		/** @brief 停止責任の上書きを禁止します。
		 * @param[in] other 代入しない所有境界です。
		 * @return 呼出し不能です。
		 */
		ChildLifetime &operator=( const ChildLifetime &other) = delete ;

	private:
		/// 同じcallerの所有Jobをguard中だけ借用します。
		HANDLE									  group_ ;
		/// 同じ実child HANDLEをguard中だけ借用します。
		HANDLE									  child_ ;
		/// 子終端確認が終わるまで同じnative writerを強所有します。
		std::shared_ptr<LocalCollectorStateStore> lease_ ;
	} ;
	/** @brief 同じ実leaseと子の保存予約へ結合する複写不能な一回権限です。 */
	struct Permit final {
		/// 所有中の実native writerです。
		const LocalCollectorStateStore		 *lease ;
		/// 同じ固定childの実process HANDLEです。
		HANDLE								  child ;
		/// 同run内の実順序です。
		std::uint32_t						  ordinal ;
		/// 全入力へ結合した原job hashです。
		std::wstring						  jobHash ;
		/// flush/readbackした保護予約の原hashです。
		std::wstring						  reservationHash ;
		/// 実monitor directory identityです。
		std::wstring						  monitorIdentity ;
		/// 単調時計による延長しない期限です。
		std::chrono::steady_clock::time_point deadline ;
		/// 今回だけの縮小payload capです。
		std::uint64_t						  cap ;
		/// 成否にかかわらず一回だけ消費します。
		bool								  used{} ;
		/** @brief 同じ親の実検査後だけ固定します。
		 * @param[in] owner 保持中native storeです。
		 * @param[in] process 実child HANDLEです。
		 * @param[in] index 同runのjob順序です。
		 * @param[in] job 原job hashです。
		 * @param[in] reservation 保存済み予約hashです。
		 * @param[in] identity 実monitor identityです。
		 * @param[in] until 固定期限です。
		 * @param[in] maximum 今回payload capです。
		 */
		Permit( const LocalCollectorStateStore *owner, HANDLE process, std::uint32_t index,
			   std::wstring job, std::wstring reservation, std::wstring identity,
			   std::chrono::steady_clock::time_point until, std::uint64_t maximum)
			: lease( owner), child( process), ordinal( index), jobHash( std::move( job)),
			  reservationHash( std::move( reservation)), monitorIdentity( std::move( identity)),
			  deadline( until), cap( maximum)
		{
		}
		/** @brief 実行権限の複写を禁止します。
		 * @param[in] other 複写しない権限です。
		 */
		Permit( const Permit &other) = delete ;
		/** @brief 消費状態の上書きによる再実行を禁止します。
		 * @param[in] other 代入しない権限です。
		 * @return 呼出し不能です。
		 */
		Permit &operator=( const Permit &other) = delete ;
	} ;
	/** @brief 同じchildの実pipeで有限byteを送受信します。
	 * @param[in] pipe 一接続だけのduplexです。
	 * @param[in] child 実child HANDLEです。
	 * @param[in] deadline 全体期限です。
	 * @param[in,out] buffer 所有bufferです。同期完了まで借用します。
	 * @param[in] size 有限byte数です。
	 * @param[in] reading trueは読取り、falseは書込みです。
	 */
	static void transfer( HANDLE pipe, HANDLE child,
						 const std::chrono::steady_clock::time_point deadline, void *buffer,
						 const DWORD size, const bool reading)
	{
		DWORD offset{} ;	// 部分完了しても元buffer範囲内だけを扱います。
		// 元期限と同じ子の生存を各非同期I/Oへ適用します。
		while( offset < size) {
			const Handle event =
				// 完了eventです。
				own( CreateEventW( nullptr, TRUE, FALSE, nullptr)) ;
			OVERLAPPED operation{} ;	// 当該I/Oだけが使用します。
			operation.hEvent = event.get() ;
			DWORD	   count{} ;	// 同期または非同期の実byte数です。
			// Win32のbyte I/O境界だけに所有bufferのbyte viewを渡します。
			auto	  *bytes = static_cast<std::byte *>( buffer) ;	// 元所有bufferの有限viewです。
			const BOOL completed =
				reading ? ReadFile( pipe, bytes + offset, size - offset, &count, &operation)
						: WriteFile( pipe, bytes + offset, size - offset, &count,
									&operation) ;	// 実I/Oです。
			// 未完了I/Oだけを監督し、停止時は同じI/Oを取消してからbufferを解放します。
			if( completed == FALSE) {
				require( GetLastError() == ERROR_IO_PENDING, "DISTRIBUTION_PIPE_IO") ;
				const HANDLE waits[]{event.get(), child} ;	// Eventを先に評価します。
				DWORD		 waited = WAIT_TIMEOUT ;		// 元期限まで短い監督待機を繰り返します。
				// 同run期限・child死亡・当該I/O完了のいずれかまで待ちます。
				while( waited == WAIT_TIMEOUT && std::chrono::steady_clock::now() < deadline) {
					waited = WaitForMultipleObjects( 2U, waits, FALSE, 100U) ;
				}

				// 取消しI/Oが完了する前にstackのOVERLAPPEDを破棄しません。
				if( waited != WAIT_OBJECT_0) {
					static_cast<void>( CancelIoEx( pipe, &operation)) ;
					static_cast<void>( GetOverlappedResult( pipe, &operation, &count, TRUE)) ;
					require( false, "DISTRIBUTION_PIPE_STOPPED") ;
				}

				requireBool( GetOverlappedResult( pipe, &operation, &count, FALSE),
							"DISTRIBUTION_PIPE_RESULT") ;
			}

			require( count != 0U && count <= size - offset, "DISTRIBUTION_PIPE_EOF") ;
			offset += count ;
		}
	}
	/** @brief 長さ付きframeを読みます。
	 * @param[in] pipe 同child専用pipeです。
	 * @param[in] child 実child HANDLEです。
	 * @param[in] deadline 固定監督期限です。
	 * @return 1MiB以内のJSON objectです。
	 */
	static SetupJson receive( HANDLE pipe, HANDLE child,
							 std::chrono::steady_clock::time_point deadline)
	{
		std::uint32_t size{} ;	// x64 Windowsのlittle endian固定長です。
		transfer( pipe, child, deadline, &size, sizeof( size), true) ;
		require( size > 0U && size <= COLLECTOR_REGISTRY_JOB_MAX_BYTES, "DISTRIBUTION_FRAME_LIMIT") ;
		std::string bytes( size, '\0') ;	// 上限確認後だけ確保します。
		transfer( pipe, child, deadline, bytes.data(), size, true) ;
		return SetupJson::Parse( winrt::to_hstring( bytes)) ;
	}
	/** @brief 小さい固定応答だけを長さ付きで返します。
	 * @param[in] pipe 同child専用pipeです。
	 * @param[in] child 実child HANDLEです。
	 * @param[in] deadline 固定監督期限です。
	 * @param[in] message 公開本文を含まない応答です。
	 */
	static void send( HANDLE pipe, HANDLE child, std::chrono::steady_clock::time_point deadline,
					 const SetupJson &message)
	{
		std::string bytes =
			// 有限context/件数/hashだけです。
			winrt::to_string( message.Stringify()) ;
		require( bytes.size() <= COLLECTOR_REGISTRY_JOB_MAX_BYTES, "DISTRIBUTION_FRAME_LIMIT") ;
		std::uint32_t size = static_cast<std::uint32_t>( bytes.size()) ;	// 検査済み固定長です。
		transfer( pipe, child, deadline, &size, sizeof( size), false) ;
		transfer( pipe, child, deadline, bytes.data(), size, false) ;
	}
	/** @brief 同じ低位HTTP観測だけを小さい精算応答へ射影します。
	 * @param[in] transfer 同runの実runnerが所有する観測です。
	 * @return 当該I/Oの完了・実要求・実本文byte・statusです。
	 */
	static SetupJson observation( const CollectorHttpTransferObservation &transfer)
	{
		SetupJson value ;	// 公開JSONからCOMPLETEを生成する逆変換はありません。
		value.Insert( L"complete",
					 SetupValue::CreateBooleanValue( transfer.completion() ==
													CollectorHttpTransferCompletion::COMPLETE)) ;
		value.Insert( L"requests", SetupValue::CreateNumberValue( transfer.attemptedRequests())) ;
		value.Insert( L"bytes",
					 SetupValue::CreateNumberValue( static_cast<double>( transfer.bodyBytesRead()))) ;
		value.Insert( L"status", SetupValue::CreateNumberValue( transfer.terminalStatus())) ;
		return value ;
	}
	/** @brief 私有権限を消費し、同じMTA監督threadで通常runnerを一回実行します。
	 * @param[in,out] permit 検証済みの一回権限です。
	 * @param[in] job 原hashへ結合したjobです。
	 * @param[in] session 親採番の0でないsessionです。
	 * @param[in,out] scope 同runだけのPAGE所有者です。
	 * @param[in] proof 当該起点だけの任意PAGE証拠です。
	 * @param[in] cancel 親期限と実子停止を確認します。
	 * @param[out] result 同じ実取得と全INF検査の私有結果です。
	 * @return 通常runnerの元HRESULTです。
	 */
	static NativeError execute( Permit &permit, const CollectorRegistryJob &job,
							   const ScanSessionId session, CollectorRunPageScope &scope,
							   const CollectorRunPageProof	  *proof,
							   const HttpCancellationCallback &cancel,
							   CollectorRegistryJobResult	  &result)
	{
		require( !std::exchange( permit.used, true) && permit.lease != nullptr &&
					permit.lease->isWritable() &&
					WaitForSingleObject( permit.child, 0U) == WAIT_TIMEOUT &&
					job.sha256_ == permit.jobHash &&
					std::chrono::steady_clock::now() < permit.deadline,
				"DISTRIBUTION_PERMIT_REJECTED") ;
#ifdef DRIVERCRATE_DISTRIBUTION_TESTING
		// 完全fakeの通常runnerだけをtest TUへ接続し、製品CLIへ設定を公開しません。
		if( executionProbe_) {
			return executionProbe_( job, session, scope, proof, permit.cap, permit.deadline, result) ;
		}
#endif
		CollectorRegistryJobRunner			   runner ;	// 各jobに新session/workspaceを作ります。
		WindowsOfficialNetworkCostReader	   cost ;	// 製品は実OSの回線費用を再照会します。
		const CollectorRegistryExecutionLimits limits( permit.cap,
													  permit.deadline) ;	// 原jobは不変です。
		return runner.run( job, session, cost, cancel, limits, result, &scope, proof) ;
	}
	/** @brief 同じ完全PAGEの原byteだけを固定診断memberへ保存します。
	 * @param[in] runRoot 親が子終端まで実handle固定する保護runです。
	 * @param[in] ordinal 同runの一回job順序です。
	 * @param[in] job 元hashへ結合済みの同jobです。
	 * @param[in] source 同jobのexact公式起点です。
	 * @param[in,out] scope 同じ生存PAGE所有者です。
	 * @param[in] result 先に原JSONを保存した同取得結果です。
	 * @return 保存済み同scope証拠、完全PAGE欠測時はnullです。
	 * @throws std::exception 保存・観測照合の失敗。元結果と予約は保持します。
	 * @note 保存byteからproof/grantを復元せず、再符号化・HTML実行を行いません。
	 */
	static std::shared_ptr<const CollectorRunPageProof> savePageBody(
		const fs::path &runRoot, std::uint32_t ordinal, const CollectorRegistryJob &job,
		const CollectorInspectionSource &source, CollectorRunPageScope &scope,
		const CollectorRegistryJobResult &result)
	{
		const auto retained = scope.find( source) ;	// 同HTTPの私有所有本文だけです。
		// 不完全・過大・未取得応答から診断本文を補完しません。
		if( !retained) {
			return {} ;
		}

		try {
			const auto &page = retained->observation_ ;	// 同じ原byte/hash/実UTCです。
			require( scope.accepts( *retained, source) && !retained->raw_.empty() &&
						retained->raw_.size() <= 2U * 1024U * 1024U && page.httpStatus == 200U &&
						page.bodyBytes == retained->raw_.size() &&
						result.pageTransfer().stage() == CollectorHttpTransferStage::PAGE &&
						result.pageTransfer().completion() ==
							CollectorHttpTransferCompletion::COMPLETE &&
						result.pageTransfer().bodyBytesRead() == page.bodyBytes &&
						result.pageTransfer().terminalStatus() == page.httpStatus &&
						result.pageTransfer().attemptedRequests() == page.requestCount,
					"DISTRIBUTION_PAGE_BODY_OBSERVATION") ;
			const auto saved =
				// 原結果だけです。
				SetupJson::Parse( winrt::to_hstring( result.json())) ;
			const auto observed =
				// 外部入力ではありません。
				saved.GetNamedObject( L"pageObservation") ;
			require( saved.GetNamedString( L"jobSha256") == job.sha256_ &&
						observed.GetNamedNumber( L"httpStatus") == page.httpStatus &&
						observed.GetNamedNumber( L"bodyBytes") ==
							static_cast<double>( page.bodyBytes) &&
						observed.GetNamedString( L"bodySha256") == page.bodySha256 &&
						observed.GetNamedString( L"finalUrl") == page.finalUrl &&
						observed.GetNamedNumber( L"requestCount") == page.requestCount &&
						observed.GetNamedNumber( L"observedUtcSeconds") ==
							static_cast<double>( page.observedAtUtc.time_since_epoch().count()),
					"DISTRIBUTION_PAGE_BODY_BINDING") ;
			// byte所有vectorを文字復号せず、既存binary保存境界のchar viewへ借用します。
			const std::string_view raw( reinterpret_cast<const char *>( retained->raw_.data()),
									   retained->raw_.size()) ;
			require( distributionHash( raw) == page.bodySha256, "DISTRIBUTION_PAGE_BODY_HASH") ;
			distributionSave( runRoot / (L"page-" + std::to_wstring( ordinal) + L".body"), raw) ;
		} catch( const std::exception &error) {
			throw std::runtime_error( "DISTRIBUTION_PAGE_BODY_SAVE_FAILED: " +
									 std::string( error.what())) ;
		}

		return retained ;
	}
	/** @brief 同じ親の候補hashと実assemble byteを未署名共通検査へ結合します。
	 * @param[in] monitorRoot 同じ実writerのrootです。
	 * @param[in] runRoot 子終端まで実handle固定したrun directoryです。
	 * @param[in] runId 同じrunの固定IDです。
	 * @param[in] context 親が固定した原入力/producer/原点です。
	 * @param[in] settlements 同じ実結果objectから親が保持した全精算です。
	 * @param[in,out] message 固定FINISH要求と未署名receipt参照の応答です。
	 * @note 新実行permit、認証型、鍵操作を発行しません。
	 */
	static void validateBuild( const fs::path &monitorRoot, const fs::path &runRoot,
							  const std::wstring_view runId, const SetupJson &context,
							  const std::vector<SetupJson> &settlements, SetupJson &message)
	{
		const auto run	= distributionSavedRun( monitorRoot, runId) ;	// 子が保存済みの同じ正本です。
		const auto jobs = run.GetNamedArray( L"jobs") ;					// 全実行を含む分母です。
		require( run.GetNamedString( L"phase") == L"FINISHED" && jobs.Size() == settlements.size() &&
					run.GetNamedString( L"monitorIdentity") ==
						context.GetNamedString( L"monitorIdentity"),
				"DISTRIBUTION_FINISH_NOT_SAVED") ;
		std::set<std::uint32_t> fresh ;	// 全private成功候補をassembleへ必ず含めます。
		// 各精算と候補hashを親の同結果objectへ完全照合します。
		for( std::uint32_t index = 0U; index < jobs.Size(); ++index) {
			const auto	saved	 = jobs.GetAt( index).GetObject() ;	// 子の保存済み精算です。
			const auto &expected = settlements.at( index) ;			// 親の同I/O所有値です。
			// 結果/候補のすり替えや未精算を終了時にも受理しません。
			for( const auto field : {L"phase", L"chargedRequests", L"chargedBytes", L"resultSha256",
									L"candidateSha256", L"candidateRecords"}) {
				require( distributionSameJson( saved.Lookup( field), expected.Lookup( field)),
						"DISTRIBUTION_FINISH_RESULT_CHANGED") ;
			}

			// 空の検査成功を候補成功として数えません。
			if( expected.GetNamedNumber( L"candidateRecords") > 0.0) {
				fresh.insert( index) ;
			}
		}

		// 全失敗/空候補は旧headとassetを更新せず終了します。
		if( message.GetNamedValue( L"build").ValueType() ==
		   winrt::Windows::Data::Json::JsonValueType::Null) {
			require( fresh.empty(), "DISTRIBUTION_BUILD_MISSING") ;
			return ;
		}

		require( !fresh.empty(), "DISTRIBUTION_EMPTY_BUILD") ;
		const auto build = message.GetNamedObject( L"build") ;	// 任意pathを含まない固定参照です。
		distributionFields( build,
						   {L"generation", L"outputs", L"includedCandidates", L"priorHeadSha256"}) ;
		const auto outputs = build.GetNamedObject( L"outputs") ;	// 親が全byteを独立hash化します。
		distributionFields( outputs, {L"index.json", L"index.json.gz", L"manifest.raw.json",
									 L"build-report.json", L"provenance.json"}) ;
		// 保存済みの固定五fileだけを読み、出力hashを再確認します。
		for( const auto &entry : outputs) {
			require( distributionHash( distributionRead( runRoot / entry.Key().c_str())) ==
						entry.Value().GetString(),
					"DISTRIBUTION_BUILD_OUTPUT_HASH") ;
		}

		const auto manifest = distributionRead( runRoot / L"manifest.raw.json",
											   INDEX_MANIFEST_MAX_BYTES) ;	// 未署名原byteです。
		const auto gzip =
			// 既存16MiB読取枠を拡大しません。
			distributionRead( runRoot / L"index.json.gz") ;
		const auto now = std::chrono::floor<std::chrono::seconds>(
			// 実OS UTCです。
			std::chrono::system_clock::now()) ;
		const auto checked = validateUnsignedIndexCandidate(
			manifest, std::as_bytes( std::span<const char>{gzip.data(), gzip.size()}),
			now) ;	// 同じ値codecだけです。
		require( checked.receipt.has_value(), "DISTRIBUTION_UNSIGNED_CANDIDATE_REJECTED") ;
		const auto indexBytes =
			// GZipの実展開byteへ照合します。
			distributionRead( runRoot / L"index.json") ;
		require( signed_index_json::decodeHash( winrt::to_string( distributionHash( indexBytes)),
											  E_INVALIDARG) == checked.receipt->expandedSha256,
				"DISTRIBUTION_BUILD_EXPANDED_HASH") ;
		const auto index =
			// 全schemaは共通codecで検査済みです。
			SetupJson::Parse( winrt::to_hstring( indexBytes)) ;
		std::map<std::pair<std::wstring, std::wstring>, SetupJson>
										  expectedRecords ;		// 正確な元record値です。
		std::map<std::wstring, SetupJson> expectedSources ;		// 元pageごとに一sourceです。
		SetupArray						  expectedProvenance ;	// 参照順序を保持した全原観測です。
		// 新旧の元候補を原journal/原点/実producerへ再結合します。
		for( const auto &value : build.GetNamedArray( L"includedCandidates")) {
			const auto reference = value.GetObject() ;	// 閉じたrun-relative参照です。
			distributionFields( reference, {L"runId", L"ordinal", L"member", L"sha256"}) ;
			const auto originalRunId =
				// 字句はsavedRunで検査します。
				reference.GetNamedString( L"runId") ;
			const auto originalRun =
				// 同保護originです。
				distributionSavedRun( monitorRoot, originalRunId.c_str()) ;
			const auto originalOrdinal = reference.GetNamedNumber( L"ordinal") ;	// 最大32の整数です。
			require( originalOrdinal >= 0.0 && originalOrdinal < 32.0 &&
						std::floor( originalOrdinal) == originalOrdinal &&
						originalOrdinal < originalRun.GetNamedArray( L"jobs").Size(),
					"DISTRIBUTION_BUILD_REFERENCE") ;
			const auto ordinal =
				// 上限を確認済みです。
				static_cast<std::uint32_t>( originalOrdinal) ;
			const auto member =
				L"candidate-" + std::to_wstring( ordinal) + L".json" ;	// INF selectorではありません。
			const auto savedJob =
				// 元精算です。
				originalRun.GetNamedArray( L"jobs").GetAt( ordinal).GetObject() ;
			require( originalRun.GetNamedString( L"phase") == L"FINISHED" &&
						originalRun.GetNamedString( L"monitorIdentity") ==
							context.GetNamedString( L"monitorIdentity") &&
						reference.GetNamedString( L"member") == member &&
						savedJob.GetNamedString( L"candidateMember") == member &&
						savedJob.GetNamedString( L"candidateSha256") ==
							reference.GetNamedString( L"sha256"),
					"DISTRIBUTION_BUILD_REFERENCE") ;
			const auto candidateBytes =
				distributionRead( monitorRoot / L"distribution/runs" / originalRunId.c_str() /
								 member) ;	// 外部pathは受けません。
			require( distributionHash( candidateBytes) == reference.GetNamedString( L"sha256"),
					"DISTRIBUTION_BUILD_CANDIDATE_HASH") ;
			const auto candidate = SetupJson::Parse(
				// 親が元typed観測から保存した値です。
				winrt::to_hstring( candidateBytes)) ;
			const auto binding = candidate.GetNamedObject( L"binding") ;	// 元実producer/原点です。
			// 別rootへcopyしたreceiptや別producer byteを現在の観測へ昇格させません。
			for( const auto field : {L"monitorIdentity", L"producerHashes", L"packageManifestSha256",
									L"seedManifestSha256"}) {
				require( distributionSameJson( binding.Lookup( field), context.Lookup( field)),
						"DISTRIBUTION_BUILD_ORIGIN_OR_PRODUCER") ;
			}

			require( binding.GetNamedString( L"runId") == originalRunId &&
						binding.GetNamedNumber( L"ordinal") == ordinal &&
						candidate.GetNamedNumber( L"jobError") == 0.0 &&
						signed_index_json::utc(
							winrt::to_string( candidate.GetNamedString( L"validUntilUtc")),
							E_INVALIDARG) > now,
					"DISTRIBUTION_BUILD_OBSERVATION_EXPIRED") ;
			// 当該runの全private成功候補は一度だけ含めます。
			if( originalRunId == runId) {
				require( fresh.erase( ordinal) == 1U &&
							settlements.at( ordinal).GetNamedString( L"candidateSha256") ==
								reference.GetNamedString( L"sha256"),
						"DISTRIBUTION_BUILD_PRIVATE_RESULT") ;
			}

			// 元全recordを比較集合へ登録し、異なるrecordの重複は拒否します。
			for( const auto &recordValue : candidate.GetNamedArray( L"records")) {
				const auto record = recordValue.GetObject() ;	// 元v2値です。
				require( expectedRecords
							.emplace( std::pair{std::wstring{record.GetNamedString( L"sourceId")},
											   std::wstring{record.GetNamedString( L"recordId")}},
									 record)
							.second,
						"DISTRIBUTION_BUILD_RECORD_DUPLICATE") ;
			}

			// 同pageの新しい公式根拠だけを元候補の順で保持します。
			for( const auto &sourceValue : candidate.GetNamedArray( L"sources")) {
				const auto source = sourceValue.GetObject() ;	// 元source値です。
				expectedSources[std::wstring{source.GetNamedString( L"sourceId")}] = source ;
			}

			SetupJson provenance ;	// 全原観測と元参照を同値で保持します。
			provenance.Insert( L"reference", reference) ;
			provenance.Insert( L"observation", candidate) ;
			expectedProvenance.Append( provenance) ;
		}

		require( fresh.empty() && index.GetNamedArray( L"records").Size() == expectedRecords.size() &&
					index.GetNamedArray( L"sources").Size() == expectedSources.size(),
				"DISTRIBUTION_BUILD_DENOMINATOR") ;
		// 共通codec検査済みの実record原byteを元typed投影へ値一致させます。
		for( const auto &value : index.GetNamedArray( L"records")) {
			const auto entry = value.GetObject() ;	// 原Base64/hashは共通codec済みです。
			const auto raw	 = signed_index_json::decodeBase64(
				  winrt::to_string( entry.GetNamedString( L"recordBytesBase64")),
				  INDEX_RECORD_MAX_BYTES, E_INVALIDARG, E_INVALIDARG) ;	// 既存decoderを再利用します。
			const auto record = SetupJson::Parse(
				// 元byteだけのDOMです。
				winrt::to_hstring( std::string{raw.begin(), raw.end()})) ;
			const auto found = expectedRecords.find(
				{std::wstring{record.GetNamedString( L"sourceId")},
				 std::wstring{record.GetNamedString( L"recordId")}}) ;	// 完全identityだけです。
			require( found != expectedRecords.end() && distributionSameJson( found->second, record),
					"DISTRIBUTION_BUILD_RECORD_CHANGED") ;
			expectedRecords.erase( found) ;
		}

		// Sourceにも元候補以外の公式性申告を足させません。
		for( const auto &value : index.GetNamedArray( L"sources")) {
			const auto source = value.GetObject() ;	// 共通codec済みsourceです。
			const auto found  = expectedSources.find(
				 std::wstring{source.GetNamedString( L"sourceId")}) ;	// 元参照だけです。
			require( found != expectedSources.end() && distributionSameJson( found->second, source),
					"DISTRIBUTION_BUILD_SOURCE_CHANGED") ;
			expectedSources.erase( found) ;
		}

		const auto report = SetupJson::Parse( winrt::to_hstring(
			// 全分母報告です。
			distributionRead( runRoot / L"build-report.json"))) ;
		// 原対象/未profile/失敗jobを報告から除去させません。
		for( const auto field : {L"targets", L"unprofiledRecords", L"jobs"}) {
			require( distributionSameJson( report.Lookup( field), run.Lookup( field)),
					"DISTRIBUTION_BUILD_REPORT_CHANGED") ;
		}

		const auto provenance = SetupJson::Parse( winrt::to_hstring(
			// 全元metadataです。
			distributionRead( runRoot / L"provenance.json"))) ;
		require( distributionSameJson( provenance.Lookup( L"observations"), expectedProvenance) &&
					checked.receipt->manifest.generation == build.GetNamedNumber( L"generation"),
				"DISTRIBUTION_BUILD_PROVENANCE_CHANGED") ;
		const auto headPath =
			monitorRoot / L"distribution/candidate-head.json" ;	// 署名済high-waterとは別です。
		// 直列writer下の未署名headだけから単調採番します。
		if( fs::exists( headPath)) {
			const auto bytes = distributionRead( headPath) ;					// 旧原byteを延長しません。
			const auto head	 = SetupJson::Parse( winrt::to_hstring( bytes)) ;	// 元候補headです。
			require( distributionHash( bytes) == build.GetNamedString( L"priorHeadSha256") &&
						head.GetNamedNumber( L"generation") + 1.0 ==
							build.GetNamedNumber( L"generation"),
					"DISTRIBUTION_BUILD_GENERATION") ;
		} else {
			// 公開head未認証の初回候補を署名用確定世代とは扱いません。
			const auto historyPath =
				monitorRoot / L"distribution/portable-history.json" ;	// 非能力の旧世代です。
			const double floor =
				fs::exists( historyPath)
					? SetupJson::Parse( winrt::to_hstring( distributionRead( historyPath)))
						  .GetNamedNumber( L"maximumGeneration")
					: 0.0 ;	// 移設でも後退させません。
			require( build.GetNamedValue( L"priorHeadSha256").ValueType() ==
							winrt::Windows::Data::Json::JsonValueType::Null &&
						build.GetNamedNumber( L"generation") == floor + 1.0,
					"DISTRIBUTION_BUILD_GENERATION") ;
		}

		SetupJson validation ;	// 署名型や通信能力を持たない保存用receiptだけです。
		validation.Insert( L"schema",
						  SetupValue::CreateStringValue( L"dc-collector-unsigned-validation-v1")) ;
		validation.Insert( L"runId", SetupValue::CreateStringValue( runId)) ;
		validation.Insert( L"outputs", outputs) ;
		validation.Insert( L"unsigned", SetupValue::CreateBooleanValue( true)) ;
		validation.Insert( L"authenticated", SetupValue::CreateBooleanValue( false)) ;
		validation.Insert( L"recordCount", SetupValue::CreateNumberValue( static_cast<double>(
											  checked.receipt->quality.recordCount))) ;
		const auto bytes =
			// 認証結果と混同しない固定内容です。
			winrt::to_string( validation.Stringify()) ;
		distributionSave( runRoot / L"unsigned-validation.json", bytes) ;
		message.Insert( L"validationMember",
					   SetupValue::CreateStringValue( L"unsigned-validation.json")) ;
		message.Insert( L"validationSha256", SetupValue::CreateStringValue( distributionHash( bytes))) ;
	}
	/** @brief active世代の原pointerと全三入力を子終端まで固定します。
	 * @param[in] package 検査済みpackageです。
	 * @param[in] root 保護workspaceです。
	 * @param[out] held 呼出し側が子終端まで保持する実handleです。
	 * @return 同じmanifestへ結合した現行入力directoryです。
	 * @throws std::exception pointer、閉manifest、hashまたは実handle不正。
	 */
	static fs::path inputDirectory( const fs::path &package, const fs::path &root,
								   std::vector<Handle> &held)
	{
		fs::path	 selected ;	// 初回seedまたはactiveの固定directoryです。
		std::wstring expected ;	// Activeのmanifest hashです。
		// Activeがある場合は腐敗をseed fallbackへ変換しません。
		if( fs::exists( root / L"data")) {
			fs::path activePath =
				root / L"data/active.json" ;	// Win32の最終pathと同じseparatorへ固定します。
			activePath.make_preferred() ;
			held.push_back( openChecked( activePath, false, true)) ;
			const auto pointer = SetupJson::Parse( winrt::to_hstring(
				// 同じ保護原byteです。
				distributionRead( root / L"data/active.json"))) ;
			require( pointer.Size() == 2U &&
						pointer.GetNamedString( L"schema") == L"dc-collector-distribution-active-v1",
					"DISTRIBUTION_ACTIVE_SCHEMA") ;
			expected = pointer.GetNamedString( L"sha256") ;
			require( expected.size() == 64U &&
						std::all_of( expected.begin(), expected.end(),
									// Path componentへ使える小文字hashだけを受理します。
									[]( const wchar_t value) {
										return (value >= L'0' && value <= L'9') ||
											   (value >= L'a' && value <= L'f') ;
									}),
					"DISTRIBUTION_ACTIVE_HASH") ;
			selected = root / L"data/generations" / expected ;
		}
		// Activeが存在しない初回だけ同梱seedへ進みます。
		else {
			// 初回だけ同梱seedを使い、通常initialize/import後はactiveを使います。
			selected = package / L"seed/distribution-data" ;
		}

		selected.make_preferred() ;
		lockAncestors( selected, held) ;
		held.push_back( openChecked( selected / L"manifest.json", false, true)) ;
		const auto raw =
			// 子も同原hashを検証します。
			distributionRead( selected / L"manifest.json") ;
		require( expected.empty() || distributionHash( raw) == expected,
				"DISTRIBUTION_ACTIVE_MANIFEST_HASH") ;
		const auto manifest = SetupJson::Parse( winrt::to_hstring( raw)) ;	// 閉集合の根拠です。
		require( manifest.Size() == 4U &&
					manifest.GetNamedString( L"schema") == L"dc-collector-distribution-data-v1",
				"DISTRIBUTION_DATA_MANIFEST_SCHEMA") ;
		// 同じ三入力の書込み/削除共有を拒否し、親子原byteの一致を維持します。
		for( const auto &entry :
			{std::pair{L"registry", L"registry.json"}, std::pair{L"locators", L"locators.json"},
			 std::pair{L"profiles", L"collection-profiles.json"}}) {
			held.push_back( openChecked( selected / entry.second, false, true)) ;
			require( distributionHash( distributionRead( selected / entry.second)) ==
						manifest.GetNamedObject( L"inputHashes").GetNamedString( entry.first),
					"DISTRIBUTION_ACTIVE_INPUT_HASH") ;
		}

		return selected ;
	}
	/** @brief 検証済みpackageを固定child・一接続duplexで実行します。
	 * @param[in] package 全byteと実handle固定済みのpackageです。
	 * @param[in] root 保護workspaceです。
	 * @return 子の完全成功0、部分失敗/拒否2です。
	 */
	static int run( const fs::path &package, const fs::path &root)
	{
		SetupJson origin ;		// 両側実identityへ結合した原点です。
		bool	  pristine{} ;	// 完全空履歴の検査結果であり許可入力ではありません。
		auto	  admission =
			// 実leaseです。
			acquireCollectorDistributionAdmission( root, package, origin, pristine) ;
		const fs::path monitorRoot(
			// Active正本です。
			origin.GetNamedString( L"monitorRoot").c_str()) ;
		std::vector<Handle> held ;	// 子終了まで原点と祖先の置換を拒否します。
		lockAncestors( monitorRoot, held) ;
		const auto monitorToken = userToken() ;	// 実monitorのACLも再検査します。
		// WindowsのTOKEN_USER構造体から借用SIDだけを読みます。
		PSID monitorUser = reinterpret_cast<const TOKEN_USER *>( monitorToken.data())->User.Sid ;
		checkSecurity( held.front().get(), monitorUser, true, false) ;
		const fs::path dataDirectory = inputDirectory( package, root, held) ;	// 子終端までpinします。
		const auto	   started		 = std::chrono::steady_clock::now() ;		// 単調期限の起点です。
		const auto	   deadline = started + std::chrono::seconds( 600) ;		// 実通信runの最大期限です。
		const auto	   supervisor = started + std::chrono::seconds( 660) ;		// 終端余裕だけの期限です。
		SetupJson	   inputs ;													// 原byteの入力hashを親も独立計算します。
		std::vector<std::wstring> inputHashes ;									// PAGE scopeへ同じ順序で結合します。
		// producer/import側と同じ三つの固定入力だけを扱います。
		for( const auto &entry :
			{std::pair{L"registry", L"registry.json"}, std::pair{L"locators", L"locators.json"},
			 std::pair{L"profiles", L"collection-profiles.json"}}) {
			const fs::path inputPath = dataDirectory / entry.second ;				// 現行の閉manifest入力です。
			const auto	   hash = distributionHash( distributionRead( inputPath)) ;	// 原hashです。
			inputs.Insert( entry.first, SetupValue::CreateStringValue( hash)) ;
			inputHashes.push_back( hash) ;
		}

		// 新moduleがpackageの閉集合へ組み込まれていない旧配布からは通信しません。
		for( const auto file : {L"scripts/collector_distribution_pipeline.py",
							   L"scripts/collector_collection_profiles.py"}) {
			static_cast<void>( distributionRead( package / file)) ;
		}

		SetupJson producerHashes ;	// 実producer byteを候補とbuildへ結合します。
		producerHashes.Insert( L"native", SetupValue::CreateStringValue(
											 fileHash( package / L"DriverCrateCollectorSetup.exe"))) ;
		producerHashes.Insert(
			L"pipeline", SetupValue::CreateStringValue(
							 fileHash( package / L"scripts/collector_distribution_pipeline.py"))) ;
		producerHashes.Insert( L"profiles",
							  SetupValue::CreateStringValue(
								  fileHash( package / L"scripts/collector_collection_profiles.py"))) ;

		GUID		  guid{} ;								// 再接続不能な一回pipe/run nonceです。
		const HRESULT guidStatus = CoCreateGuid( &guid) ;	// GUID本文を読む前に元APIの成功を確定する。
		// 元の非zero拒否を維持し、未確定の出力byteをnonceへ変換しない。
		if( guidStatus != S_OK) {
			failApi( "DISTRIBUTION_GUID", static_cast<DWORD>( guidStatus)) ;
		}

		const auto *guidBytes =
			reinterpret_cast<const unsigned char *>( &guid) ;	// GUIDの所有byteだけを16進化します。
		std::wstring	  nonce ;								// path記号を含まない32文字です。
		constexpr wchar_t HEX[] = L"0123456789abcdef" ;			// 固定16進alphabetです。
		// GUID全16byteを固定32文字へ変換します。
		for( std::size_t index = 0U; index < sizeof( guid); ++index) {
			nonce.push_back( HEX[guidBytes[index] >> 4U]) ;
			nonce.push_back( HEX[guidBytes[index] & 15U]) ;
		}

		const std::wstring runId = L"run-" + nonce ;	// 同run全予約へ固定します。
		const std::wstring pipeName =
			L"\\\\.\\pipe\\DriverCrate-distribution-" + nonce ;	// 公開serverではありません。
		const Handle pipe = own( CreateNamedPipeW(
			pipeName.c_str(),
			PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
			PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1U,
			1048576U, 1048576U, 0U, nullptr)) ;	// 同user/親childだけをPID検査します。
		const Handle connectEvent =
			// 接続監督用eventです。
			own( CreateEventW( nullptr, TRUE, FALSE, nullptr)) ;
		OVERLAPPED connecting{} ;	// 接続完了まで保持します。
		connecting.hEvent = connectEvent.get() ;
		const Handle group =
			// 親死亡時に同子孫を停止します。
			own( CreateJobObjectW( nullptr, nullptr)) ;
		JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{} ;	// 強制停止は実installを含みません。
		limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE ;
		requireBool( SetInformationJobObject( group.get(), JobObjectExtendedLimitInformation, &limits,
											sizeof( limits)),
					"DISTRIBUTION_JOB") ;
		const fs::path executable = package / L"runtime/python.exe" ;	// 唯一の固定childです。
		std::wstring   command	  = quote( executable.native()) + fileBootstrapArguments( package) +
							   L" distribution-run-once " + quote( root.native()) +
							   L" --confirm-inspection-download --fixed-distribution-bridge " +
							   // 固定argvです。
							   quote( pipeName) ;
		std::vector<wchar_t> windows( 32768U) ;	// OSからだけSystemRootを得ます。
		const auto			 windowsLength =
			// 実長です。
			GetWindowsDirectoryW( windows.data(), static_cast<UINT>( windows.size())) ;
		require( windowsLength > 0U && windowsLength < windows.size(), "DISTRIBUTION_SYSTEMROOT") ;
		std::wstring environment =
			L"SystemRoot=" + std::wstring( windows.data()) ;	// PATH/PYTHONPATHは渡しません。
		environment.push_back( L'\0') ;
		environment += L"SystemDrive=" + setupChildSystemDrive( windows.data()) ;
		environment.push_back( L'\0') ;
		environment += L"PYTHONIOENCODING=utf-8" ;
		environment.push_back( L'\0') ;
		environment.push_back( L'\0') ;
		HANDLE outputRaw{} ;	// 同じ有限標準出力だけを明示継承します。
		requireBool( DuplicateHandle( GetCurrentProcess(), standardHandle( STD_OUTPUT_HANDLE),
									GetCurrentProcess(), &outputRaw, 0U, TRUE,
									DUPLICATE_SAME_ACCESS),
					"DISTRIBUTION_STDOUT") ;
		const Handle		output = own( outputRaw) ;	// Child起動後も親が回収します。
		SECURITY_ATTRIBUTES inheritable{sizeof( SECURITY_ATTRIBUTES), nullptr,
										TRUE} ;	// NUL入力だけです。
		const Handle		input =
			own( CreateFileW( L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &inheritable,
							OPEN_EXISTING, 0U, nullptr)) ;	// Contextは実named pipeを使います。
		SIZE_T attributeSize{} ;							// Win32の必要量照会です。
		static_cast<void>( InitializeProcThreadAttributeList( nullptr, 1U, 0U, &attributeSize)) ;
		std::vector<std::byte> attributes( attributeSize) ;	// 起動完了まで所有します。
		STARTUPINFOEXW		   startup{} ;					// 継承handle listで他handleの流入を禁止します。
		startup.StartupInfo.cb		   = sizeof( startup) ;
		startup.StartupInfo.dwFlags	   = STARTF_USESTDHANDLES ;
		startup.StartupInfo.hStdInput  = input.get() ;
		startup.StartupInfo.hStdOutput = output.get() ;
		startup.StartupInfo.hStdError  = output.get() ;
		// Win32が指定するopaque属性領域にだけcastします。
		startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>( attributes.data()) ;
		requireBool(
			InitializeProcThreadAttributeList( startup.lpAttributeList, 1U, 0U, &attributeSize),
			"DISTRIBUTION_ATTRIBUTE_LIST") ;
		const HANDLE handles[]{input.get(), output.get()} ;	// 固定二handleだけです。
		const BOOL	 updated = UpdateProcThreadAttribute(
			  startup.lpAttributeList, 0U, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
			  const_cast<HANDLE *>( handles), sizeof( handles), nullptr,
			  nullptr) ;	// APIは内容を変更しません。
		const DWORD attributeError =
			// 元codeです。
			updated == FALSE ? GetLastError() : ERROR_SUCCESS ;
		PROCESS_INFORMATION process{} ;	// 成功後RAIIへ移します。
		const BOOL			created =
			 updated != FALSE
						 ? CreateProcessW( executable.c_str(), command.data(), nullptr, nullptr, TRUE,
										  EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT |
											  CREATE_NO_WINDOW | CREATE_SUSPENDED,
										  environment.data(), package.c_str(), &startup.StartupInfo,
										  &process)
						 : FALSE ;	// 起動前に全入力固定済みです。
		const DWORD createError =
			// 解放前の元codeです。
			created == FALSE ? GetLastError() : ERROR_SUCCESS ;
		DeleteProcThreadAttributeList( startup.lpAttributeList) ;
		requireStatus( attributeError, "DISTRIBUTION_HANDLE_LIST") ;
		requireStatus( createError, "DISTRIBUTION_CHILD_CREATE") ;
		const Handle		child = own( process.hProcess) ;	// 全監督・permitが同じHANDLEを使います。
		const Handle		thread = own( process.hThread) ;	// Job結合後に一度だけ再開します。
		// 後宣言のChildLifetimeが先に子終端を確認するまで、runのdirectory handleを保持します。
		std::vector<Handle> runHeld ;
		const ChildLifetime lifetime(
			group.get(), child.get(),
			admission.store) ;	// 例外時もhandle/leaseより先に終端を確認します。
		// Job未結合の停止childは例外前に終了させます。
		if( !AssignProcessToJobObject( group.get(), child.get())) {
			const DWORD error = GetLastError() ;	// 停止APIより先に保持します。
			static_cast<void>( TerminateProcess( child.get(), 2U)) ;
			static_cast<void>( WaitForSingleObject( child.get(), 5000U)) ;
			failApi( "DISTRIBUTION_JOB_ASSIGN", error) ;
		}

		require( ResumeThread( thread.get()) != MAXDWORD, "DISTRIBUTION_CHILD_RESUME") ;
		const BOOL connected =
			// 実子起動後だけ非同期接続を開始します。
			ConnectNamedPipe( pipe.get(), &connecting) ;
		const DWORD connectError =
			// 元接続結果です。
			connected == FALSE ? GetLastError() : ERROR_SUCCESS ;
		require( connected != FALSE || connectError == ERROR_IO_PENDING ||
					connectError == ERROR_PIPE_CONNECTED,
				"DISTRIBUTION_PIPE_CONNECT") ;
		// 子が先に接続した場合も同じ一接続だけを確定します。
		if( connected != FALSE || connectError == ERROR_PIPE_CONNECTED) {
			requireBool( SetEvent( connectEvent.get()), "DISTRIBUTION_PIPE_CONNECTED_EVENT") ;
		}

		const HANDLE connectWaits[]{connectEvent.get(),
									// 他clientはPID検査で拒否します。
									child.get()} ;
		const DWORD	 connectedWait =
			// 初回接続の有限上限です。
			WaitForMultipleObjects( 2U, connectWaits, FALSE, 30000U) ;
		// 接続待機のstack領域を未完I/Oへ残しません。
		if( connectedWait != WAIT_OBJECT_0) {
			static_cast<void>( CancelIoEx( pipe.get(), &connecting)) ;
			DWORD ignored{} ;	// 取消し終端だけを待ちます。
			static_cast<void>( GetOverlappedResult( pipe.get(), &connecting, &ignored, TRUE)) ;
			require( false, "DISTRIBUTION_CHILD_CONNECT_TIMEOUT") ;
		}

		ULONG peer{} ;	// OSが返す実client PIDです。
		requireBool( GetNamedPipeClientProcessId( pipe.get(), &peer), "DISTRIBUTION_PIPE_PEER") ;
		require( peer == process.dwProcessId, "DISTRIBUTION_PIPE_PEER") ;
		// 実process imageを固定packageと比較します。
		std::vector<wchar_t> image( 32768U) ;
		DWORD				 imageLength = static_cast<DWORD>( image.size()) ;	// 出力容量です。
		requireBool( QueryFullProcessImageNameW( child.get(), 0U, image.data(), &imageLength),
					"DISTRIBUTION_CHILD_IMAGE") ;
		require( fs::path( image.data()) == executable &&
					fileHash( executable) == fileHash( image.data()),
				"DISTRIBUTION_CHILD_IMAGE") ;
		SetupJson context = SetupJson::Parse( winrt::to_hstring(
			admissionContext( package, origin, {}, admission, distributionUtc() / 1000U * 1000U,
							 L"distribution-run-once"))) ;	// 非永続contextです。
		context.Insert( L"protocol",
					   SetupValue::CreateStringValue( L"dc-collector-distribution-bridge-v1")) ;
		context.Insert( L"type", SetupValue::CreateStringValue( L"CONTEXT")) ;
		context.Insert( L"runId", SetupValue::CreateStringValue( runId)) ;
		context.Insert( L"inputHashes", inputs) ;
		context.Insert( L"producerHashes", producerHashes) ;
		context.Insert( L"nativeMode",
					   SetupValue::CreateStringValue( pristine ? L"VERIFIED_PRISTINE_V1"
															  : L"VERIFIED_LEGACY_V4")) ;
		context.Insert( L"originInitializationComplete", SetupValue::CreateBooleanValue( true)) ;
		context.Insert( L"legacyHistoryEverObserved", SetupValue::CreateBooleanValue( !pristine)) ;
		send( pipe.get(), child.get(), supervisor, context) ;
		// 同じ子停止/pipe破断/期限だけを全HTTP段へ同期伝播します。
		const HttpCancellationCallback cancel = [&]() {
			return WaitForSingleObject( child.get(), 0U) != WAIT_TIMEOUT ||
				   std::chrono::steady_clock::now() >= deadline ||
				   !PeekNamedPipe( pipe.get(), nullptr, 0U, nullptr, nullptr, nullptr) ;
		} ;
		std::unique_ptr<CollectorRunPageScope> scope ;	// BEGIN_RUN後だけ生成します。
		SetupJson			   plan ;					// 同固定childが全原入力から再計算したplanです。
		std::wstring		   planHash ;				// 一run中不変です。
		std::uint32_t		   sequence{} ;				// 全固定messageの単調連番です。
		std::uint32_t		   ordinal{} ;				// 各jobの実行順です。
		std::uint64_t		   chargedBytes{} ;			// 同I/O観測で精算済みの課金です。
		std::uint32_t		   chargedRequests{} ;		// 同I/O観測で精算済みの要求です。
		std::vector<SetupJson> settlements ;			// 次job前に永続精算を同結果へ照合します。
		const fs::path		   runRoot =
			monitorRoot / L"distribution" / L"runs" / runId ;	// 外部pathを受けません。
		bool finished{} ;										// FINISH_RUNまで他messageを受けます。
		// 最大32jobとBEGIN/FINISHだけを有限な同runで処理します。
		while( !finished) {
			SetupJson  message = receive( pipe.get(), child.get(), supervisor) ;	// 最大1MiBです。
			const auto type	   = message.GetNamedString( L"type") ;					// 固定四操作だけです。
			require( message.GetNamedString( L"protocol") == L"dc-collector-distribution-bridge-v1" &&
						message.GetNamedString( L"runId") == runId &&
						message.GetNamedNumber( L"sequence") == ++sequence,
					"DISTRIBUTION_FRAME_BINDING") ;
			// 明示中止はproofを破棄し、予約を取消しません。
			if( type == L"ABORT") {
				require( false, "DISTRIBUTION_CHILD_ABORT") ;
			}

			// 最初の一回だけ全入力・plan・分母を照合します。
			if( type == L"BEGIN_RUN") {
				distributionFields( message,
								   {L"protocol", L"type", L"sequence", L"runId", L"planHash"}) ;
				require( sequence == 1U && scope == nullptr, "DISTRIBUTION_BEGIN_REPLAY") ;
				lockAncestors( runRoot, runHeld) ;
				require( runHeld.size() >= 3U, "DISTRIBUTION_RUN_ANCESTORS") ;
				// runRoot、runs、distributionの新3directoryを実handleの順に保護照合します。
				for( std::size_t index = 0U; index < 3U; ++index) {
					checkSecurity( runHeld[index].get(), monitorUser, true, false) ;
				}

				const auto planBytes =
					// 保存済み原byteです。
					distributionRead( runRoot / L"plan.json") ;
				planHash = distributionHash( planBytes) ;
				require( message.GetNamedString( L"planHash") == planHash, "DISTRIBUTION_PLAN_HASH") ;
				plan = SetupJson::Parse( winrt::to_hstring( planBytes)) ;
				require( plan.GetNamedString( L"schema") == L"dc-collector-collection-plan-v1" &&
							plan.GetNamedArray( L"jobs").Size() <= 32U,
						"DISTRIBUTION_PLAN_SCHEMA") ;
				const auto profileDocument = SetupJson::Parse( winrt::to_hstring( distributionRead(
					dataDirectory / L"collection-profiles.json"))) ;	// 同原入力です。
				const auto registeredProfiles =
					// 全分母です。
					profileDocument.GetNamedArray( L"profiles") ;
				require( plan.GetNamedArray( L"targets").Size() == registeredProfiles.Size(),
						"DISTRIBUTION_DENOMINATOR") ;
				std::set<std::wstring> ids ;	// 二重/欠損profileを拒否します。
				// 全profile IDをplan分母と一致させます。
				for( const auto &value : registeredProfiles) {
					ids.insert( value.GetObject().GetNamedString( L"id").c_str()) ;
				}

				// 同じprofileを二重に数えて未評価を落としません。
				for( const auto &value : plan.GetNamedArray( L"targets")) {
					require( ids.erase( value.GetObject().GetNamedString( L"profileId").c_str()) == 1U,
							"DISTRIBUTION_DENOMINATOR") ;
				}

				require( ids.empty(), "DISTRIBUTION_DENOMINATOR") ;
				// 専用private ctorへ実lease/同child/全原入力を結合します。
				scope.reset( new CollectorRunPageScope(
					runId,
					static_cast<std::uint64_t>(
						reinterpret_cast<std::uintptr_t>( admission.store.get())),
					process.dwProcessId, inputHashes, planHash, deadline, cancel)) ;
			} else {
				require( scope != nullptr && message.GetNamedString( L"planHash") == planHash,
						"DISTRIBUTION_PLAN_BINDING") ;
				// FINISHは新実行を停止し、同run PAGEを永久失効します。
				if( type == L"FINISH_RUN") {
					distributionFields( message, {L"protocol", L"type", L"sequence", L"runId",
												 L"planHash", L"build"}) ;
					validateBuild( monitorRoot, runRoot, runId, context, settlements, message) ;
					scope->finish() ;
					finished = true ;
				} else {
					distributionFields( message, {L"protocol", L"type", L"sequence", L"runId",
												 L"planHash", L"ordinal", L"reservationSha256"}) ;
					require( type == L"EXECUTE_JOB" && ordinal < 32U &&
								message.GetNamedNumber( L"ordinal") == ordinal && !cancel(),
							"DISTRIBUTION_JOB_REPLAY") ;
#ifdef DRIVERCRATE_DISTRIBUTION_TESTING
					// 同じ固定子の保存後だけ故障を注入し、製品入口には露出しません。
					if( reservationProbe_) {
						reservationProbe_( runRoot, child.get(), ordinal) ;
					}
#endif
					const auto reservationBytes = distributionRead(
						runRoot / (L"reservation-" + std::to_wstring( ordinal) + L".json"),
						65536U) ;	// 原予約です。
					const auto reservationHash =
						// 読戻しhashです。
						distributionHash( reservationBytes) ;
					require( message.GetNamedString( L"reservationSha256") == reservationHash,
							"DISTRIBUTION_RESERVATION_HASH") ;
					const auto reservation =
						// 閉じた予約です。
						SetupJson::Parse( winrt::to_hstring( reservationBytes)) ;
					distributionFields(
						reservation,
						{L"schema",			 L"runId",			 L"planHash",	  L"inputHashes",
						 L"monitorIdentity", L"ordinal",		 L"jobSha256",	  L"pageKey",
						 L"payloadKey",		 L"pageHost",		 L"payloadHost",  L"attemptedAt",
						 L"nextDueAt",		 L"deadline",		 L"pageReused",	  L"pageRequests",
						 L"pageBytes",		 L"payloadRequests", L"payloadBytes", L"effectiveCap"}) ;
					require( reservation.GetNamedString( L"schema") ==
									L"dc-collector-distribution-reservation-v1" &&
								reservation.GetNamedString( L"runId") == runId &&
								reservation.GetNamedString( L"planHash") == planHash &&
								reservation.GetNamedNumber( L"ordinal") == ordinal &&
								reservation.GetNamedString( L"monitorIdentity") ==
									directoryIdentity( monitorRoot),
							"DISTRIBUTION_RESERVATION_BINDING") ;
					// objectのfield順ではなく、原入力三hashの値を完全比較します。
					for( const auto key : {L"registry", L"locators", L"profiles"}) {
						require( reservation.GetNamedObject( L"inputHashes").GetNamedString( key) ==
									inputs.GetNamedString( key),
								"DISTRIBUTION_INPUT_BINDING") ;
					}

					const auto jobBytes =
						distributionRead( runRoot / (L"job-" + std::to_wstring( ordinal) + L".json"),
										 COLLECTOR_REGISTRY_JOB_MAX_BYTES) ;	// 原jobです。
					const auto jobHash = distributionHash( jobBytes) ;			// 原条件を変更しません。
					require( reservation.GetNamedString( L"jobSha256") == jobHash,
							"DISTRIBUTION_JOB_HASH") ;
					CollectorRegistryJob job ;	// decode成功だけでは実行できません。
					require( parseCollectorRegistryJob( jobBytes, job) == 0,
							"DISTRIBUTION_JOB_INVALID") ;
					const auto jobJson =
						// 比較用だけです。
						SetupJson::Parse( winrt::to_hstring( jobBytes)) ;
					bool planned{} ;	// 計画外jobは受けません。
					// 固定planにある同じ原jobだけを一回実行します。
					for( const auto &value : plan.GetNamedArray( L"jobs")) {
						planned = planned || value.GetObject().Stringify() == jobJson.Stringify() ;
					}

					require( planned, "DISTRIBUTION_JOB_NOT_PLANNED") ;
					const auto sourceJson =
						// 同recordのexact導線です。
						jobJson.GetNamedObject( L"source") ;
					const CollectorInspectionSource source{
						sourceJson.GetNamedString( L"rootUrl").c_str(),
						sourceJson.GetNamedString( L"rootHost").c_str(),
						sourceJson.GetNamedString( L"payloadUrl").c_str(),
						sourceJson.GetNamedString( L"payloadHost").c_str(),
						// URL指定RPCではありません。
						sourceJson.GetNamedString( L"href").c_str()} ;
					const auto			proof = scope->find( source) ;	// 同runの実完全PAGEだけです。
					const std::uint64_t pageBytes =
						proof ? 0U : 2097153U ;								// 超過検出1byteも先払いします。
					const std::uint32_t pageRequests = proof ? 0U : 3U ;	// 二redirectを含みます。
					require( chargedBytes + pageBytes + 1U < 33554432U &&
								chargedRequests + pageRequests + 3U <= 64U,
							"DISTRIBUTION_RUN_BUDGET") ;
					const auto cap = std::min(
						static_cast<std::uint64_t>( jobJson.GetNamedNumber( L"maximumBytes")),
						33554432ULL - chargedBytes - pageBytes - 1U) ;	// 原jobを縮小するだけです。
					require( reservation.GetNamedNumber( L"effectiveCap") ==
									static_cast<double>( cap) &&
								reservation.GetNamedNumber( L"pageBytes") ==
									static_cast<double>( pageBytes) &&
								reservation.GetNamedNumber( L"pageRequests") == pageRequests &&
								reservation.GetNamedNumber( L"payloadBytes") ==
									static_cast<double>( cap + 1U) &&
								reservation.GetNamedNumber( L"payloadRequests") == 3U &&
								reservation.GetNamedBoolean( L"pageReused") == (proof != nullptr),
							"DISTRIBUTION_RESERVATION_BUDGET") ;
					// 既存native共有host/requestの予約をこの補助ledgerで迂回しません。
					for( const auto &entry : {std::pair{source.rootUrl, source.rootHost},
											 std::pair{source.payloadUrl, source.payloadHost}}) {
						require(
							std::find( admission.requestHashes.begin(),
									  admission.requestHashes.end(),
									  distributionHash( "GET\n" + winrt::to_string( entry.first))) ==
									admission.requestHashes.end() &&
								std::find( admission.hostHashes.begin(), admission.hostHashes.end(),
										  distributionHash( winrt::to_string( entry.second))) ==
									admission.hostHashes.end(),
							"NATIVE_SHARED_HOST_HELD") ;
					}

					const auto journal		= SetupJson::Parse( winrt::to_hstring( distributionRead(
						 monitorRoot /
						 L"distribution/journal.json"))) ;	// 同childが保存した正本です。
					const auto runReference = journal.GetNamedObject( L"runs").GetNamedObject(
						runId) ;	// 原bytehash参照です。
					const auto runStateHash =
						// 次job前に保存済み本文を読みます。
						runReference.GetNamedString( L"sha256") ;
					require( runReference.GetNamedString( L"member") ==
									L"state-" + runStateHash + L".json" &&
								runStateHash.size() == 64U &&
								std::all_of( runStateHash.begin(), runStateHash.end(),
											[]( wchar_t letter) {
												return (letter >= L'0' && letter <= L'9') ||
													   (letter >= L'a' && letter <= L'f') ;
											}),
							"DISTRIBUTION_RUN_REFERENCE") ;
					const auto runStateBytes =
						distributionRead( runRoot /
										 // 固定memberです。
										 runReference.GetNamedString( L"member").c_str()) ;
					require( distributionHash( runStateBytes) == runStateHash,
							"DISTRIBUTION_RUN_STATE_HASH") ;
					const auto savedRun =
						// 別runへ転用しません。
						SetupJson::Parse( winrt::to_hstring( runStateBytes)) ;
					const auto savedJobs =
						// 全先行予約が含まれます。
						savedRun.GetNamedArray( L"jobs") ;
					require( savedRun.GetNamedString( L"phase") == L"RUNNING" &&
								savedRun.GetNamedString( L"planHash") == planHash &&
								savedJobs.Size() == ordinal + 1U &&
								savedJobs.GetAt( ordinal).GetObject().GetNamedString( L"phase") ==
									L"RESERVED" &&
								savedJobs.GetAt( ordinal).GetObject().GetNamedString(
									L"reservationSha256") == reservationHash,
							"DISTRIBUTION_RESERVATION_NOT_SAVED") ;
					const auto attempted = signed_index_json::utc(
						winrt::to_string( reservation.GetNamedString( L"attemptedAt")),
						E_INVALIDARG) ;	// 実予約時刻です。
					const auto due = signed_index_json::utc(
						winrt::to_string( reservation.GetNamedString( L"nextDueAt")),
						E_INVALIDARG) ;	// 元24h待機です。
					const auto until = signed_index_json::utc(
						winrt::to_string( reservation.GetNamedString( L"deadline")),
						E_INVALIDARG) ;	// 子の保存run期限です。
					const auto nowUtc = std::chrono::sys_seconds(
						// 実OS時計です。
						std::chrono::seconds( distributionUtc() / 1000U)) ;
					require( attempted <= nowUtc &&
								nowUtc - attempted <= std::chrono::seconds( 600) &&
								due >= attempted + std::chrono::hours( 24) && until > nowUtc &&
								until <= attempted + std::chrono::seconds( 600) &&
								savedRun.GetNamedString( L"deadline") ==
									reservation.GetNamedString( L"deadline"),
							"DISTRIBUTION_RESERVATION_TIME") ;
					const auto requests =
						// 同writerが先行保存した恒久待機です。
						journal.GetNamedObject( L"requests") ;
					const auto stateEnvelope = SetupJson::Parse( winrt::to_hstring(
						// 既存PAGE正本です。
						distributionRead( monitorRoot / L"state.json"))) ;
					const auto state		 = stateEnvelope.GetNamedObject(
						L"payload") ;	// hashも同原正規JSONへ照合します。
					// PAGE/payload双方を当該実sourceの恒久key・hostへ結合します。
					for( const bool pageStage : {true, false}) {
						const auto key = distributionHash(
							"GET\n" + winrt::to_string( pageStage
														   ? source.rootUrl
														   : source.payloadUrl)) ;	// 元URL式です。
						const auto host = distributionHash(
							winrt::to_string( pageStage ? source.rootHost
													   : source.payloadHost)) ;	// exact host式です。
						require( reservation.GetNamedString( pageStage ? L"pageKey"
																	 : L"payloadKey") == key &&
									reservation.GetNamedString( pageStage ? L"pageHost"
																		 : L"payloadHost") == host,
								"DISTRIBUTION_REQUEST_KEY") ;
						require( requests.HasKey( key), "DISTRIBUTION_REQUEST_NOT_RESERVED") ;
						const auto request =
							// 必須の保存済み予約です。
							requests.GetNamedObject( key) ;
						const bool reused =
							pageStage && proof != nullptr ;	// 同run private proofだけが例外です。
						require( request.GetNamedString( L"hostSha256") == host &&
									request.GetNamedString( L"kind") ==
										(pageStage ? L"PAGE" : L"PAYLOAD"),
								"DISTRIBUTION_REQUEST_BINDING") ;
						// 借用時も元PAGEの24h試行は消さず、完全精算済みであることを要求します。
						if( reused) {
							require( request.GetNamedString( L"runId") == runId &&
										request.GetNamedString( L"phase") == L"SETTLED_ACTUAL",
									"DISTRIBUTION_REUSED_PAGE_STATE") ;
						} else {
							require( request.GetNamedString( L"runId") == runId &&
										request.GetNamedNumber( L"ordinal") == ordinal &&
										request.GetNamedString( L"phase") == L"RESERVED" &&
										request.GetNamedString( L"attemptedAt") ==
											reservation.GetNamedString( L"attemptedAt") &&
										request.GetNamedString( L"nextDueAt") ==
											reservation.GetNamedString( L"nextDueAt") &&
										request.GetNamedNumber( L"chargedRequests") ==
											(pageStage ? pageRequests : 3U) &&
										request.GetNamedNumber( L"chargedBytes") ==
											static_cast<double>( pageStage ? pageBytes : cap + 1U),
									"DISTRIBUTION_REQUEST_NOT_RESERVED") ;
						}

						const auto hostStates =
							// 既存要確認/Retry待機も保護します。
							state.GetNamedObject( L"hosts") ;
						// Host待機を新ledgerで迂回して実行しません。
						if( hostStates.HasKey( host)) {
							const auto hostState =
								// 原host待機です。
								hostStates.GetNamedObject( host) ;
							require(
								!hostState.GetNamedBoolean( L"held") &&
									signed_index_json::utc(
										winrt::to_string( hostState.GetNamedString( L"nextDueAt")),
										E_INVALIDARG) <= nowUtc,
								"DISTRIBUTION_HOST_HELD") ;
						}

						// 新PAGEは既存monitor IN_PROGRESSの全bindingへ結合します。
						if( pageStage) {
							const auto pageState = state.GetNamedObject( L"requests")
													   .GetNamedObject( key) ;	// 既存PAGE予約です。
							require( pageState.GetNamedString( L"hostSha256") == host &&
										pageState.GetNamedString( L"locatorSha256") ==
											distributionHash( winrt::to_string( source.rootUrl)) &&
										pageState.GetNamedString( L"outcome") ==
											(reused ? L"SUCCESS" : L"IN_PROGRESS"),
									"DISTRIBUTION_PAGE_NOT_RESERVED") ;
							// 新PAGE予約の元時刻/24h待機も同じ保護fileに保存済みである必要があります。
							if( !reused) {
								require( pageState.GetNamedString( L"attemptedAt") ==
												reservation.GetNamedString( L"attemptedAt") &&
											pageState.GetNamedString( L"nextDueAt") ==
												reservation.GetNamedString( L"nextDueAt"),
										"DISTRIBUTION_PAGE_NOT_RESERVED") ;
							}
						}
					}

					// 先行jobの実数残枠は、同じ実結果への永続一回精算を確認後だけ再使用します。
					for( std::uint32_t index = 0U; index < ordinal; ++index) {
						const auto previous =
							// 保存済み精算です。
							savedJobs.GetAt( index).GetObject() ;
						const auto expected = settlements.at( index) ;	// 親の同I/O私有観測です。
						require( previous.GetNamedString( L"phase") ==
										expected.GetNamedString( L"phase") &&
									previous.GetNamedNumber( L"chargedRequests") ==
										expected.GetNamedNumber( L"chargedRequests") &&
									previous.GetNamedNumber( L"chargedBytes") ==
										expected.GetNamedNumber( L"chargedBytes") &&
									previous.GetNamedString( L"resultSha256") ==
										expected.GetNamedString( L"resultSha256"),
								"DISTRIBUTION_SETTLEMENT_NOT_SAVED") ;
					}

					Permit permit( admission.store.get(), child.get(), ordinal, jobHash,
								  reservationHash, directoryIdentity( monitorRoot), deadline,
								  cap) ;	// 実lease/子/予約からのみ生成します。
					CollectorRegistryJobResult
							   result ;	// producerは後続工程でこの同objectだけから生成します。
					const auto status =
						execute( permit, job, static_cast<ScanSessionId>( ordinal + 1U), *scope,
								// 同じMTA threadの一回呼出しです。
								proof.get(), cancel, result) ;
					require( !result.json().empty() && !cancel(),
							"DISTRIBUTION_NATIVE_RESULT_MISSING") ;
					const std::wstring member =
						L"result-" + std::to_wstring( ordinal) + L".json" ;	// 固定memberだけです。
					distributionSave( runRoot / member, result.json()) ;
					const auto retained =
						// 原結果の成否と独立して同HTTPの完全本文を先に保持します。
						savePageBody( runRoot, ordinal, job, source, *scope, result) ;
					message.Insert( L"resultMember", SetupValue::CreateStringValue( member)) ;
					message.Insert( L"resultSha256",
								   SetupValue::CreateStringValue( distributionHash( result.json()))) ;
					require( result.observation_.has_value(),
							"DISTRIBUTION_TYPED_OBSERVATION_MISSING") ;
					CollectorDistributionCandidate projected ;	// 同じ結果objectだけのv2投影です。
					requireStatus( static_cast<DWORD>( makeCollectorDistributionRecords(
									  *result.observation_,
									  std::chrono::sys_seconds{
										  std::chrono::seconds{distributionUtc() / 1000U}},
									  projected)),
								  "DISTRIBUTION_PROJECTION_FAILED") ;
					auto candidate = SetupJson::Parse(
						// 保存用値へ元runを付記します。
						winrt::to_hstring( projected.json())) ;
					SetupJson binding ;	// 外部JSONから生存caller/観測を復元する用途はありません。
					binding.Insert( L"runId", SetupValue::CreateStringValue( runId)) ;
					binding.Insert( L"ordinal", SetupValue::CreateNumberValue( ordinal)) ;
					binding.Insert( L"planHash", SetupValue::CreateStringValue( planHash)) ;
					binding.Insert( L"inputHashes", inputs) ;
					// 全固定contextを親が所有する同じ値だけから結合します。
					for( const auto field : {L"monitorIdentity", L"packageManifestSha256",
											L"seedManifestSha256", L"producerHashes"}) {
						binding.Insert( field, context.Lookup( field)) ;
					}

					candidate.Insert( L"binding", binding) ;
					const auto candidateBytes =
						// 全元集合を保存します。
						winrt::to_string( candidate.Stringify()) ;
					const auto candidateMember =
						L"candidate-" + std::to_wstring( ordinal) + L".json" ;	// 同run固定名です。
					distributionSave( runRoot / candidateMember, candidateBytes) ;
					message.Insert( L"candidateMember",
								   SetupValue::CreateStringValue( candidateMember)) ;
					message.Insert( L"candidateSha256",
								   SetupValue::CreateStringValue( distributionHash( candidateBytes))) ;
					message.Insert( L"candidateRecords",
								   SetupValue::CreateNumberValue(
									   static_cast<double>( projected.recordCount()))) ;
					static_cast<void>( status) ;
					message.Insert( L"status",
								   SetupValue::CreateStringValue(
									   result.outcome_ == L"CONTENT_INSPECTED" ? L"SUCCESS"
																			   : result.outcome_)) ;
					message.Insert( L"reason", SetupValue::CreateStringValue( result.reason_)) ;
					bool projectionIncomplete =
						// 空成功を全成功にしません。
						projected.recordCount() == 0U ;
					// 他OS未観測や表現限界も全分母の部分失敗として保持します。
					for( const auto &value : candidate.GetNamedArray( L"outcomes")) {
						projectionIncomplete =
							projectionIncomplete ||
							value.GetObject().GetNamedString( L"reason") != L"PROJECTED" ;
					}

					// 取得/通常検査の元診断はresult fileへ保持し、投影不足を別理由へします。
					if( result.outcome_ == L"CONTENT_INSPECTED" && projectionIncomplete) {
						message.Insert( L"status",
									   SetupValue::CreateStringValue( projected.recordCount() == 0U
																		 ? L"NO_PROJECTED_RECORD"
																		 : L"PARTIAL_FAILURE")) ;
						message.Insert( L"reason",
									   SetupValue::CreateStringValue( L"PROJECTION_INCOMPLETE")) ;
					}

					message.Insert( L"page", observation( result.pageTransfer())) ;
					message.Insert( L"payload", observation( result.payloadTransfer())) ;
					message.Insert( L"pageProof",
								   SetupValue::CreateBooleanValue( retained != nullptr)) ;
					message.Insert( L"pageSha256",
								   SetupValue::CreateStringValue(
									   retained ? retained->observation_.bodySha256 : L"")) ;
					const bool pageComplete =
						result.pageTransfer().completion() ==
						CollectorHttpTransferCompletion::COMPLETE ;	// 同I/Oです。
					const bool payloadComplete =
						result.payloadTransfer().completion() ==
						CollectorHttpTransferCompletion::COMPLETE ;	// 同I/Oです。
					// 同じ実HTTPで完全精算した要求数だけを次jobの残枠へ返します。
					const auto jobRequests =
						(proof			? 0U
						 : pageComplete ? result.pageTransfer().attemptedRequests()
										: pageRequests) +
						(payloadComplete ? result.payloadTransfer().attemptedRequests() : 3U) ;
					// 未完段は検出用byteを含む予約最大課金を維持します。
					const auto chargedJobBytes =
						(proof			? 0U
						 : pageComplete ? result.pageTransfer().bodyBytesRead()
										: pageBytes) +
						(payloadComplete ? result.payloadTransfer().bodyBytesRead() : cap + 1U) ;
					chargedRequests += jobRequests ;
					chargedBytes += chargedJobBytes ;
					SetupJson settled ;	// 次jobへ実数を貸す前に保存読戻しを要求します。
					settled.Insert( L"phase",
								   SetupValue::CreateStringValue( pageComplete && payloadComplete
																	 ? L"SETTLED_ACTUAL"
																	 : L"SETTLED_MAXIMUM")) ;
					settled.Insert( L"chargedRequests", SetupValue::CreateNumberValue( jobRequests)) ;
					settled.Insert( L"chargedBytes", SetupValue::CreateNumberValue(
														static_cast<double>( chargedJobBytes))) ;
					settled.Insert( L"resultSha256", message.Lookup( L"resultSha256")) ;
					settled.Insert( L"candidateSha256", message.Lookup( L"candidateSha256")) ;
					settled.Insert( L"candidateRecords", message.Lookup( L"candidateRecords")) ;
					settlements.push_back( settled) ;
					++ordinal ;
				}
			}

			send( pipe.get(), child.get(), supervisor, message) ;
		}

		require( WaitForSingleObject( child.get(), 30000U) == WAIT_OBJECT_0,
				"DISTRIBUTION_CHILD_EXIT_TIMEOUT") ;
		DWORD exit{} ;	// 全HOLD/部分失敗を成功へ正規化しません。
		requireBool( GetExitCodeProcess( child.get(), &exit), "DISTRIBUTION_CHILD_EXIT") ;
		std::printf(
			"DISTRIBUTION_NATIVE_COMPLETE jobs=%lu requests=%lu child_exit=%lu producer=1 tasks=0\n",
			static_cast<unsigned long>( ordinal), static_cast<unsigned long>( chargedRequests),
			static_cast<unsigned long>( exit)) ;
		return exit == 0U ? 0 : 2 ;
	}
} ;

int runCollectorSetupWorkspace( const fs::path &package, const std::wstring_view action,
							   const fs::path &root, const fs::path &transfer,
							   const std::function<void()> &verifyPackage,
							   const fs::path &nativeOrigin, const fs::path &monitorOrigin)
{
	require( action == L"initialize" || action == L"verify" || action == L"export" ||
				action == L"import" || action == L"resume" || action == L"run-once" ||
				action == L"bind-origins" || action == L"distribution-run-once" ||
				action == L"initialize-distribution-origins" || action == L"import-data" ||
				action == L"switch-package" || action == L"review-held-host" ||
				action == L"stage-candidate",
			"WORKSPACE_ACTION") ;
	checkPath( package) ;
	checkPath( root) ;
	require( !pathsOverlap( package, root), "WORKSPACE_OVERLAP") ;
	const bool heldReview = action == L"review-held-host" ;	// 非通信の一host明示reviewだけです。
	const bool stageCandidate =
		// 原未署名byteの非通信受渡しだけです。
		action == L"stage-candidate" ;
	// operator入力を保護workspace/packageの変更対象と兼用しません。
	if( heldReview) {
		checkPath( transfer) ;
		require( !pathsOverlap( transfer.parent_path(), root) &&
					!pathsOverlap( transfer.parent_path(), package),
				"HOST_REVIEW_INPUT_OVERLAP") ;
	}

	// 移設rootも作成やpackage検査より前に全rootとの非重複を確定する。
	if( action == L"export" || action == L"import" || action == L"resume" ||
	   action == L"import-data" || stageCandidate) {
		checkPath( transfer) ;
		require( !pathsOverlap( transfer, root) && !pathsOverlap( transfer, package),
				"WORKSPACE_OVERLAP") ;
	}

	std::vector<Handle> packageHandles ;	// Runtime終了までpackageの置換と書込みを拒否する。
	lockAncestors( package, packageHandles) ;
	const auto token = userToken() ;	// 検査中に生存するTOKEN_USER。
	// Windows token境界の所有bufferをTOKEN_USERとして読む。
	PSID	   user = reinterpret_cast<const TOKEN_USER *>( token.data())->User.Sid ;
	inspectTree( package, user, true, packageHandles, DISTRIBUTION_JSON_MAXIMUM_BYTES,
				PACKAGE_TOTAL_MAXIMUM_BYTES) ;
	verifyPackage() ;
	std::vector<Handle> rootHandles ;	// 操作rootと祖先の置換を拒否する。
	lockAncestors( root.parent_path(), rootHandles) ;
	// 新規操作だけがprotected rootを作成し、既存先へは進まない。
	if( action == L"initialize" || action == L"import") {
		createCollectorSetupProtectedRoot( root) ;
	}

	inspectTree( root, user, false, rootHandles, DISTRIBUTION_JSON_MAXIMUM_BYTES,
				WORKSPACE_TOTAL_MAXIMUM_BYTES) ;
	// Monitorのimport staging renameを妨げないよう、root以外の検査handleを解放する。
	rootHandles.clear() ;
	lockAncestors( root, rootHandles) ;
	const bool packageSwitch = action == L"switch-package" ;	// 原bindingの例外はこの一操作だけです。
	// 原hashは事前reviewした小文字SHA-256だけとし、任意path/旧packageを引数にしません。
	if( packageSwitch) {
		require( transfer.native().size() == 64U &&
					std::all_of( transfer.native().begin(), transfer.native().end(),
								[]( const wchar_t letter) {
									return (letter >= L'0' && letter <= L'9') ||
										   (letter >= L'a' && letter <= L'f') ;
								}),
				"WORKSPACE_SWITCH_REVIEW_HASH") ;
		require( fileHash( root / L"workspace.json") == transfer.native(),
				"WORKSPACE_SWITCH_REVIEW_HASH") ;
	}

	// 新配布経路だけを専用origin・一接続callerへ振分け、metadata操作を拡張しません。
	if( action == L"distribution-run-once") {
		require( transfer == L"--confirm-inspection-download", "DISTRIBUTION_CONSENT_REQUIRED") ;
		return CollectorRegistryJobProtectedCaller::run( package, root) ;
	}

	// Origin初期化は非通信であり、既存run-onceの空request拒否を変更しません。
	if( action == L"initialize-distribution-origins") {
		return initializeCollectorDistributionOrigins( package, root, nativeOrigin, monitorOrigin) ;
	}

	const bool boundOffline =
		// 原点選択済みworkspaceの非通信操作を、同じ保護原点へ結びます。
		(action == L"verify" || action == L"export" || packageSwitch || heldReview ||
		 stageCandidate) &&
		fs::exists( root / L"origin.json") &&
		readOrigin( root / L"workspace.json").GetNamedString( L"schema") ==
			L"dc-collector-explicit-workspace-v1" ;
	const SetupJson offlineReference = boundOffline ? readOrigin( root / L"origin.json")
													: SetupJson{} ;	// 作成前にも同じ保護参照を使う。
	// 外部正本またはnative原点内へexport containerを作成する前に拒否する。
	if( boundOffline && (action == L"export" || stageCandidate)) {
		const fs::path nativeRoot(
			// 元native原点。
			offlineReference.GetNamedString( L"nativeRoot").c_str()) ;
		const fs::path monitorRoot(
			// Active正本。
			offlineReference.GetNamedString( L"monitorRoot").c_str()) ;
		checkPath( nativeRoot) ;
		checkPath( monitorRoot) ;
		require( !pathsOverlap( transfer, nativeRoot) && !pathsOverlap( transfer, monitorRoot),
				"ORIGIN_OVERLAP") ;
	}

	std::vector<Handle> transferHandles ;	// 入力snapshotの変更または出力親置換を拒否する。
	const std::wstring	reviewRequestHash = heldReview
												? lockHeldHostReviewInputs( transfer, transferHandles)
												: std::wstring{} ;	// 固定三fileです。
	// 事前作成済みの空通常directoryだけを保持し、既存ACLやfileを修復しません。
	if( stageCandidate) {
		lockAncestors( transfer, transferHandles) ;
		require( fs::is_directory( transfer) && fs::is_empty( transfer), "CANDIDATE_STAGE_NOT_EMPTY") ;
	}

	// 移設操作だけに固定transfer引数を要求する。
	if( action == L"export" || action == L"import" || action == L"resume" ||
	   action == L"import-data") {
		// Exportは新規protected containerへ既存monitorのsnapshot子を作る。
		if( action == L"export") {
			createCollectorSetupProtectedRoot( transfer) ;
			lockAncestors( transfer, transferHandles) ;
		} else {
			lockAncestors( transfer, transferHandles) ;
			// Portable inputはACLを移設条件にしないが全fileのhardlinkとreparseを拒否する。
			std::size_t count{} ;	// Snapshotの有限entry数。
			// 既存validatorに先行して実handleを保持し、全input byteの変更を防ぐ。
			for( auto iterator = fs::recursive_directory_iterator( transfer);
				iterator != fs::recursive_directory_iterator{}; ++iterator) {
				require( ++count <= 8192U && !iterator->is_symlink(), "WORKSPACE_TRANSFER_LIMIT") ;
				const DWORD attributes =
					checkedAttributes( iterator->path(), "WORKSPACE_TRANSFER_ATTRIBUTES",
									  "WORKSPACE_TRANSFER_REPARSE") ;	// 検査済み属性。
				transferHandles.push_back( openChecked(
					iterator->path(), (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0U, true)) ;
			}
		}
	}

	const fs::path executable = package / L"runtime/python.exe" ;	// 唯一許可する絶対child。
	// 参照索引は元発行時点の共通未署名codecでも検証し、期限を更新した許可にはしません。
	if( action == L"import-data" && fs::exists( transfer / L"reference.json")) {
		const auto manifestBytes =
			// 元原byteです。
			distributionPortableRead( transfer / L"references/manifest.raw.json") ;
		const auto gzip =
			// 実asset byteです。
			distributionPortableRead( transfer / L"references/index.json.gz") ;
		const auto manifest =
			// 元発行時刻だけを使います。
			SetupJson::Parse( winrt::to_hstring( manifestBytes)) ;
		const auto published =
			signed_index_json::utc( winrt::to_string( manifest.GetNamedString( L"publishedAtUtc")),
								   E_INVALIDARG) ;	// 新時刻を発行しません。
		const auto checked = validateUnsignedIndexCandidate(
			manifestBytes, std::as_bytes( std::span<const char>{gzip.data(), gzip.size()}),
			published) ;	// 未署名型だけです。
		require( checked.receipt.has_value(), "DISTRIBUTION_REFERENCE_UNSIGNED_CODEC") ;
	}

	const bool communication = action == L"run-once" ;		// 明示metadata通信だけです。
	const bool bindingAction = action == L"bind-origins" ;	// 原点選択は非通信の別操作。
	const bool liveAction =
		communication || bindingAction || boundOffline ;	// 同じ保護原点を必要とする操作。
	CollectorSetupAdmission admission ;						// 子完了まで保持する元storeの排他writer。
	SetupJson				origin ;						// 今回の実体へ結合する非公開local参照。
	SetupJson				previous ;						// 停止移設時だけ再照合する元正本。
	std::vector<Handle>		originHandles ;					// native以外の原点と祖先の置換も拒否する。
	std::string				context ;						// 継承pipeだけへ渡す非永続context。
	bool	   distributionPristine{} ;						// 専用非通信exportも空native原点を正しく保持します。
	const bool distributionOffline = boundOffline &&
									 // 新originだけです。
									 fs::exists( root / L"distribution-origin-init-v1.json") ;
	// 切替は既存の初回完了originだけを使い、未bind/未知rootを初期化して採用しません。
	if( packageSwitch || heldReview || stageCandidate) {
		require( distributionOffline, "WORKSPACE_SWITCH_ORIGIN_REQUIRED") ;
	}

	// 許可proofのcaller入力ではなく、保護されたlocal参照と実storeを必ず検査する。
	if( liveAction) {
		const SetupJson reference  = bindingAction ? SetupJson{}
									 : boundOffline
										 ? offlineReference
										 : readOrigin( root / L"origin.json") ;	// 既存binding。
		const fs::path	nativeRoot = bindingAction
										 ? nativeOrigin
										 : fs::path(
											   // 正式に選択された原点。
											   reference.GetNamedString( L"nativeRoot").c_str()) ;
		 const fs::path monitorRoot =
			 bindingAction
				 ? monitorOrigin
				 : fs::path( reference.GetNamedString( L"monitorRoot").c_str()) ;	// 履歴を持つ正本。
		checkPath( nativeRoot) ;
		checkPath( monitorRoot) ;
		require( !pathsOverlap( nativeRoot, root) && !pathsOverlap( nativeRoot, package) &&
					!pathsOverlap( nativeRoot, monitorRoot) && !pathsOverlap( monitorRoot, package),
				"ORIGIN_OVERLAP") ;
		lockAncestors( monitorRoot, originHandles) ;
		const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
								 std::chrono::system_clock::now().time_since_epoch())
								 .count() ;	// 実OS UTC時計。
		require( elapsed > 0, "NATIVE_CONTEXT_CLOCK") ;
		const auto	 now = static_cast<std::uint64_t>( elapsed) ;	// UTC millisecond。
		std::wstring reason ;										// 個人情報を含まない固定理由。
		// 専用originでは同じ実lease検査を使い、旧metadataの非空契約を緩めません。
		if( distributionOffline) {
			admission = acquireCollectorDistributionAdmission(
				root, package, origin, distributionPristine,
				!(packageSwitch || heldReview || stageCandidate)) ;
		}

		// 同じleaseの内側で原候補全fileを読取り専用handleへ固定し、変更資格を継承しません。
		if( stageCandidate) {
			rootHandles.push_back( openChecked( root / L"workspace.json", false, true)) ;
			static_cast<void>(
				CollectorRegistryJobProtectedCaller::inputDirectory( package, root, originHandles)) ;
			inspectTree( monitorRoot / L"distribution", user, true, originHandles,
						DISTRIBUTION_JSON_MAXIMUM_BYTES, WORKSPACE_TOTAL_MAXIMUM_BYTES, false) ;
		}

		const DWORD code = distributionOffline
							   ? ERROR_SUCCESS
							   : acquireCollectorSetupAdmission( nativeRoot, now, admission,
																reason) ;	// 非作成の完全旧検証です。
		// 不足modeや回収必要を新storeや人工残量で解除しない。
		if( code != ERROR_SUCCESS) {
			std::printf( "WORKSPACE_HOLD reason=%s win32=%lu http_requests=0\n",
						winrt::to_string( reason).c_str(), static_cast<unsigned long>( code)) ;
			return 2 ;
		}

		origin = originBinding( nativeRoot, root, monitorRoot) ;
		std::string marker ;	// 同じnative writer下で読む保護参照。
		bool		found{} ;	// 初回選択と欠損を区別する。
		requireStatus(
			admission.store->read( L"current/collector-monitor-origin-v1.json", marker, found),
			"NATIVE_ORIGIN_READ") ;
		// 初回以外はnative側のanchorも実identityへ結合し、workspace copyだけを許可しない。
		if( found) {
			previous = SetupJson::Parse( winrt::to_hstring( marker)) ;
			require( previous.GetNamedString( L"nativeIdentity") ==
							origin.GetNamedString( L"nativeIdentity") &&
						previous.GetNamedString( L"nativeRoot") == nativeRoot.native(),
					"NATIVE_ORIGIN_CHANGED") ;
			const fs::path oldMonitor(
				// 再結合で省略しない元正本。
				previous.GetNamedString( L"monitorRoot").c_str()) ;
			lockAncestors( oldMonitor, originHandles) ;
			require( directoryIdentity( oldMonitor) == previous.GetNamedString( L"monitorIdentity"),
					"MONITOR_ORIGIN_CHANGED") ;
		}

		// 開始とbind済み非通信操作は両保護参照と現在の全実体の一致を要求する。
		if( !bindingAction) {
			require( found && marker == winrt::to_string( reference.Stringify()) &&
						marker == winrt::to_string( origin.Stringify()),
					"ORIGIN_BINDING_REQUIRED") ;
		}

		// monitorの秒精度時計と同じ量子へ発行時刻だけを揃え、未来のstate検査は元millisecondで行う。
		context = admissionContext( package, origin, previous, admission, now - now % 1000U, action) ;
		// 専用非通信操作もnativeが確定した型と初回完了を固定childへ渡します。
		if( distributionOffline) {
			auto document = SetupJson::Parse( winrt::to_hstring( context)) ;	// 同じ非永続contextです。
			document.Insert( L"nativeMode", SetupValue::CreateStringValue(
											   distributionPristine ? L"VERIFIED_PRISTINE_V1"
																	: L"VERIFIED_LEGACY_V4")) ;
			document.Insert( L"originInitializationComplete", SetupValue::CreateBooleanValue( true)) ;
			document.Insert( L"legacyHistoryEverObserved",
							SetupValue::CreateBooleanValue( !distributionPristine)) ;
			context = winrt::to_string( document.Stringify()) ;
		}

		// 同childの非永続contextをreview済み原byteへ結び、通信操作への転用を拒否します。
		if( packageSwitch) {
			auto document =
				// 同じ保持中leaseだけです。
				SetupJson::Parse( winrt::to_hstring( context)) ;
			document.Insert( L"reviewedWorkspaceSha256",
							SetupValue::CreateStringValue( transfer.native())) ;
			context = winrt::to_string( document.Stringify()) ;
		}

		// review入力hashと実native identityを同じ保持中leaseから非永続contextへ固定します。
		if( heldReview) {
			auto document =
				// 他operationへ転用しません。
				SetupJson::Parse( winrt::to_hstring( context)) ;
			document.Insert( L"reviewRequestSha256",
							SetupValue::CreateStringValue( reviewRequestHash)) ;
			document.Insert( L"nativeIdentity", SetupValue::CreateStringValue(
												   origin.GetNamedString( L"nativeIdentity"))) ;
			context = winrt::to_string( document.Stringify()) ;
		}
	}

	const CollectorSetupTransport transport =
		communication ? prepareCollectorSetupTransport()
					  : CollectorSetupTransport{} ;	// 子終了まで実handleを保持する。
	Handle group ;									// 通信actionの全子孫を同じ有限実行へ結合する。
	Handle contextRead ;							// 固定childだけへ継承するanonymous pipe読取り端。
	Handle contextWrite ;							// 親だけが所有する一回書込み端。
	// Native leaseは生きた親と固定childだけを結ぶpipeから消費する。
	if( liveAction) {
		SECURITY_ATTRIBUTES attributes{sizeof( SECURITY_ATTRIBUTES), nullptr,
									   TRUE} ;	// 読取り端をchildへ継承する。
		HANDLE				read{} ;			// CreatePipeが返す所有handle。
		HANDLE				write{} ;			// 親側だけに残す所有handle。
		requireBool( CreatePipe( &read, &write, &attributes, 262144U), "NATIVE_CONTEXT_PIPE") ;
		contextRead	 = own( read) ;
		contextWrite = own( write) ;
		requireBool( SetHandleInformation( contextWrite.get(), HANDLE_FLAG_INHERIT, 0U),
					"NATIVE_CONTEXT_INHERIT") ;
	}

	// DNS子だけが親timeout後も残ることを防ぎ、非通信の起動契約は維持する。
	if( communication) {
		group = own( CreateJobObjectW( nullptr, nullptr)) ;
		JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{} ;	// 全子孫をjob終了時に停止する固定policy。
		limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE ;
		requireBool( SetInformationJobObject( group.get(), JobObjectExtendedLimitInformation, &limits,
											sizeof( limits)),
					"WORKSPACE_JOB_LIMIT") ;
	}

	std::wstring command = quote( executable.native()) + fileBootstrapArguments( package) + L" " +
						   quote( action) + L" " + quote( root.native()) + L" " +
						   // 検査済み有限argv。
						   quote( transfer.native()) ;
	// 通信操作だけが検証済みOS pathと実byte hashを固定argvへ追加する。
	if( communication) {
		command += L" " + quote( transport.executable.native()) + L" " + quote( transport.sha256) ;
	}

	require( command.size() < 32768U, "WORKSPACE_ARGV_LIMIT") ;
	std::vector<wchar_t> windows( 32768U) ;	// OS起点を環境変数から受け取らない。
	const UINT			 length =
		// 実文字数。
		GetWindowsDirectoryW( windows.data(), static_cast<UINT>( windows.size())) ;
	const DWORD windowsError = length == 0U ? GetLastError() : ERROR_SUCCESS ;	// API直後のcode。
	// 容量不足の長さと、API失敗の0を別に扱う。
	if( length == 0U) {
		failApi( "WORKSPACE_SYSTEMROOT", windowsError) ;
	}

	require( length > 0U && length < windows.size(), "WORKSPACE_SYSTEMROOT_LIMIT") ;
	std::wstring environment =
		L"SystemRoot=" + std::wstring( windows.data()) ;	// 固定環境だけを継承する。
	environment.push_back( L'\0') ;
	environment += L"PYTHONIOENCODING=utf-8" ;
	environment.push_back( L'\0') ;
	// 環境proxyを消失させず、値の意味は固定route resolverだけへ委ねる。
	if( communication) {
		appendProxyEnvironment( environment) ;
	}

	environment.push_back( L'\0') ;
	STARTUPINFOW startup{} ;	// 親の有限stdout/stderrへ結果だけを返す。
	startup.cb		   = sizeof( startup) ;
	startup.dwFlags	   = STARTF_USESTDHANDLES ;
	startup.hStdInput  = liveAction ? contextRead.get() : standardHandle( STD_INPUT_HANDLE) ;
	startup.hStdOutput = standardHandle( STD_OUTPUT_HANDLE) ;
	startup.hStdError  = standardHandle( STD_ERROR_HANDLE) ;
	PROCESS_INFORMATION process{} ;	// childとthreadをRAIIへ引き取る。
	requireBool( CreateProcessW( executable.c_str(), command.data(), nullptr, nullptr, TRUE,
							   CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW |
								   (communication ? CREATE_SUSPENDED : 0U),
							   environment.data(), package.c_str(), &startup, &process),
				"WORKSPACE_PROCESS") ;
	const Handle child	= own( process.hProcess) ;	// 操作別の有限上限で待つprocess。
	const Handle thread = own( process.hThread) ;	// 実行threadの所有権。
	std::optional<CollectorRegistryJobProtectedCaller::ChildLifetime>
		reviewLifetime ;	// 例外時もleaseより先に子終端を確認します。
	// 非通信reviewとstagingも同HANDLE停止guardを使い、pipe保存失敗時にwriterを先に解放しません。
	if( heldReview || stageCandidate) {
		reviewLifetime.emplace( group.get(), child.get(), admission.store) ;
	}

	contextRead.reset() ;
	// Lambdaはchildを同期借用し、job割当て／再開失敗でも孤立した停止processを残さない。
	const auto stopUnstarted = [&child]() {
		requireBool( TerminateProcess( child.get(), 2U), "WORKSPACE_JOB_STOP") ;
		const DWORD stopped	  = WaitForSingleObject( child.get(), 5000U) ;					// 停止完了の有限上限。
		const DWORD stopError = stopped == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS ;	// 元code。
		requireStatus( stopError, "WORKSPACE_JOB_STOP_WAIT") ;
		require( stopped == WAIT_OBJECT_0, "WORKSPACE_JOB_STOP_TIMEOUT") ;
	} ;
	// 実行前に全子孫の停止境界を固定し、割当て失敗で停止したchildを残さない。
	if( communication) {
		const BOOL assigned =
			// 同じjobへの結合結果。
			AssignProcessToJobObject( group.get(), child.get()) ;
		const DWORD assignError = assigned == FALSE ? GetLastError() : ERROR_SUCCESS ;	// 元code。
		// 割当て前の失敗はjobで回収できないため、停止してから元errorを通知する。
		if( assigned == FALSE) {
			reportApiError( "WORKSPACE_JOB_ASSIGN", assignError) ;
			stopUnstarted() ;
			failApi( "WORKSPACE_JOB_ASSIGN", assignError) ;
		}

		const DWORD resumed		= ResumeThread( thread.get()) ;								// 割当て成功後だけ実行する。
		const DWORD resumeError = resumed == MAXDWORD ? GetLastError() : ERROR_SUCCESS ;	// 元code。
		// 再開不能でもjob所有権の解放で全childを停止する。
		if( resumed == MAXDWORD) {
			reportApiError( "WORKSPACE_JOB_RESUME", resumeError) ;
			stopUnstarted() ;
			failApi( "WORKSPACE_JOB_RESUME", resumeError) ;
		}
	}

	// 再開済みの固定childへ有限contextを一回渡し、EOFを確定する。
	if( liveAction) {
		DWORD written{} ;	// 全contextの書込みを要求する。
		requireBool( WriteFile( contextWrite.get(), context.data(),
							  static_cast<DWORD>( context.size()), &written, nullptr),
					"NATIVE_CONTEXT_WRITE") ;
		require( written == context.size(), "NATIVE_CONTEXT_WRITE_SIZE") ;
		contextWrite.reset() ;
	}

	const DWORD waited =
		// 操作別の固定上限。
		WaitForSingleObject( child.get(), communication ? 660000U : 180000U) ;
	const DWORD waitError =
		// 待機直後のcode。
		waited == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS ;
	// 待機失敗やtimeoutでは部分stateを保持して子を終了する。
	if( waited != WAIT_OBJECT_0) {
		// 停止APIがthread errorを書き換える前に最初の待機失敗を通知する。
		if( waited == WAIT_FAILED) {
			reportApiError( "WORKSPACE_WAIT", waitError) ;
		}

		requireBool( TerminateProcess( child.get(), 2U), "WORKSPACE_STOP_FAILED") ;
		const DWORD stopped	  = WaitForSingleObject( child.get(), 5000U) ;					// Child停止完了の上限。
		const DWORD stopError = stopped == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS ;	// 元code。
		requireStatus( stopError, "WORKSPACE_STOP_WAIT") ;
		require( stopped == WAIT_OBJECT_0, "WORKSPACE_STOP_TIMEOUT") ;
		require( waited != WAIT_FAILED, "WORKSPACE_WAIT") ;
		require( false, "WORKSPACE_TIMEOUT") ;
	}

	DWORD exit{} ;	// 実際の子終了値。
	requireBool( GetExitCodeProcess( child.get(), &exit), "WORKSPACE_EXIT") ;
	// 既存validatorによる非通信確認が全成功した場合だけ、原点anchorを同じwriter下で確定する。
	if( bindingAction && exit == 0U) {
		const std::string bytes =
			// nativeとworkspaceで同一のlocal参照。
			winrt::to_string( origin.Stringify()) ;
		requireStatus( admission.store->write( L"current/collector-monitor-origin-v1.json", bytes),
					  "NATIVE_ORIGIN_SAVE") ;
		writeOrigin( root / L"origin.json", bytes) ;
	}

	std::vector<Handle> finalHandles ;	// Python作成物を同じ実ACL境界で確認する。
	inspectTree( root, user, false, finalHandles, DISTRIBUTION_JSON_MAXIMUM_BYTES,
				WORKSPACE_TOTAL_MAXIMUM_BYTES) ;
	// 通信操作の要求と実際の許可を混同せず、許可結果は子JSONへ残す。
	if( communication) {
		std::printf( "WORKSPACE_NATIVE_COMPLETE child_exit=%lu communication_action=1 tasks=0\n",
					static_cast<unsigned long>( exit)) ;
	} else {
		std::printf( "WORKSPACE_NATIVE_COMPLETE child_exit=%lu network_authorized=0 tasks=0\n",
					static_cast<unsigned long>( exit)) ;
	}

	return exit == 0U ? 0 : 2 ;
}

int runCollectorSetupDistributionDaily( const fs::path &package, const fs::path &workspace,
									   const bool					confirmed,
									   const std::function<void()> &verifyPackage)
{
	const fs::path consentPath =
		package / L"collector-distribution-daily-consent.json" ;	// Seedへ含めません。
	const auto scope =
		L"ACTIVE_STATIC_ZIP_CAB_INF_32JOBS_64REQUESTS_32MIB_600S_24H" ;	// dataで変更できません。
	fs::path selected ;													// 保護同意だけから得る実workspaceです。
	// 同じpackage/rootを固定し、コピーされた参照を別実体の許可へ変換しません。
	withCollectorSetupProtectedRoot( package, [&]() {
		verifyPackage() ;
		const auto manifest = distributionHash(
			// Package hashです。
			distributionRead( package / L"package-manifest.json")) ;
		// 明示操作だけが同意receiptを新規発行または同じrootへ更新します。
		if( confirmed) {
			require( !workspace.empty() && runCollectorSetupWorkspace( package, L"verify", workspace,
																	 {}, verifyPackage) == 0,
					"DISTRIBUTION_DAILY_WORKSPACE_VERIFY") ;
			selected = workspace ;
			withCollectorSetupProtectedRoot( selected, [&]() {
				require( fs::exists( selected / L"data/active.json"),
						"DISTRIBUTION_DAILY_ACTIVE_REQUIRED") ;
				SetupJson consent ;	// 有限な固定8fieldです。
				consent.Insert( L"schema", SetupValue::CreateStringValue(
											  L"dc-collector-distribution-daily-consent-v1")) ;
				consent.Insert( L"packageManifestSha256", SetupValue::CreateStringValue( manifest)) ;
				consent.Insert( L"packageIdentity",
							   SetupValue::CreateStringValue( directoryIdentity( package))) ;
				consent.Insert( L"workspace", SetupValue::CreateStringValue( selected.native())) ;
				consent.Insert( L"workspaceIdentity",
							   SetupValue::CreateStringValue( directoryIdentity( selected))) ;
				consent.Insert( L"scope", SetupValue::CreateStringValue( scope)) ;
				consent.Insert( L"inspectionDownloads", SetupValue::CreateBooleanValue( true)) ;
				consent.Insert( L"daily", SetupValue::CreateBooleanValue( true)) ;
				writeCollectorSetupProtectedMetadata(
					consentPath, winrt::to_string( consent.Stringify()), fs::exists( consentPath)) ;
			}) ;
			return ;
		}

		require( workspace.empty(), "DISTRIBUTION_DAILY_FIXED_ARGUMENTS") ;
		const auto consent = SetupJson::Parse( winrt::to_hstring( readCollectorSetupProtectedMetadata(
			consentPath))) ;	// 未同意なら子を起動せず拒否します。
		require( consent.Size() == 8U &&
					consent.GetNamedString( L"schema") ==
						L"dc-collector-distribution-daily-consent-v1" &&
					consent.GetNamedString( L"packageManifestSha256") == manifest &&
					consent.GetNamedString( L"packageIdentity") == directoryIdentity( package) &&
					consent.GetNamedString( L"scope") == scope &&
					consent.GetNamedBoolean( L"inspectionDownloads") &&
					consent.GetNamedBoolean( L"daily"),
				"DISTRIBUTION_DAILY_CONSENT_REQUIRED") ;
		selected = consent.GetNamedString( L"workspace").c_str() ;
		withCollectorSetupProtectedRoot( selected, [&]() {
			require( directoryIdentity( selected) == consent.GetNamedString( L"workspaceIdentity"),
					"DISTRIBUTION_DAILY_WORKSPACE_CHANGED") ;
		}) ;
	}) ;
	// 登録自体は非通信であり、日次だけが既存の同caller/run/buildへ到達します。
	if( confirmed) {
		std::printf( "DISTRIBUTION_DAILY_OPT_IN network=0 tasks=0\n") ;
		return 0 ;
	}

	return runCollectorSetupWorkspace( package, L"distribution-run-once", selected,
									  L"--confirm-inspection-download", verifyPackage) ;
}
} // namespace drivercrate
