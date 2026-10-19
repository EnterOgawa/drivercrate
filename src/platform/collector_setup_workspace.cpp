//------------------------------------------------------------------------------
/**
 * @file collector_setup_workspace.cpp
 * @brief 保護実handleを保持して収集setupの固定Python操作へ接続します。
 * @version 01.02.01
 * @date 2026/10/16
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

#include "local_collector_state_store.h"

#include <Windows.h>
#include <AclAPI.h>
#include <sddl.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {
namespace fs = std::filesystem ;
/** @brief 固定contextと保護local参照のJSON objectです。 */
using SetupJson = winrt::Windows::Data::Json::JsonObject ;
/** @brief 固定contextのJSON値です。 */
using SetupValue = winrt::Windows::Data::Json::JsonValue ;
/** @brief hash集合だけをchildへ渡すJSON配列です。 */
using SetupArray = winrt::Windows::Data::Json::JsonArray ;

// Pythonには検証済みの固定pathだけを渡し、user siteやPATHを使わない。
constexpr std::wstring_view BOOTSTRAP =
	L"import sys;from pathlib import Path;p=Path(sys.argv[1]);"
	L"sys.path[:]=[str(p/'runtime'/'python313.zip'),str(p/'runtime'),str(p/'scripts')];"
	L"import collector_workspace;sys.exit(collector_workspace.main(sys.argv[1:]))" ;

/** @brief 最初の拒否stageを個人情報なしの例外へ固定します。
 * @param[in] valid 必須条件。
 * @param[in] stage 固定診断名。
 * @throws std::runtime_error 不成立。
 */
void require( const bool valid, const char *stage)
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
	const DWORD attributes = GetFileAttributesW( path.c_str()) ;	// 非追跡の実属性。
	const DWORD error =
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
 */
Handle openChecked( const fs::path &path, const bool directory, const bool readonly)
{
	Handle handle =
		own( CreateFileW( path.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
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
	std::array<wchar_t, 32768> finalPath{} ;	// 実pathを有限容量で照合する。
	const DWORD				   length = GetFinalPathNameByHandleW(
		   handle.get(), finalPath.data(), static_cast<DWORD>( finalPath.size()),
		   FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;						// 実文字数。
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
			handles.push_back( own(
				CreateFileW( current.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
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
 * @throws std::exception 不適格entryまたは容量超過。
 */
void inspectTree( const fs::path &root, PSID user, const bool readonly, std::vector<Handle> &handles)
{
	Handle rootHandle = openChecked( root, true, false) ;	// Root自身を先に固定する。
	checkSecurity( rootHandle.get(), user, true, true) ;
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
				require( size <= 16777216U && total <= 67108864U - size, "WORKSPACE_BYTE_LIMIT") ;
				total += size ;
			}

			handles.push_back( std::move( handle)) ;
		}
	}
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
} // namespace

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

void copyCollectorSetupProtectedFile( const fs::path &source, const fs::path &target)
{
	const Handle input =
		own( CreateFileW( source.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
						FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;	// Sourceは変更共有せず借用する。
	const Handle output = own( CreateFileW( target.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_NEW,
										  FILE_ATTRIBUTE_NORMAL,
										  nullptr)) ;	// DACLはsourceから複写せず保護親から継承する。
	std::array<std::byte, 65536> buffer{} ;				// 固定copy容量。
	std::uint64_t				 total{} ;				// Copy済みbyte数。
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

int runCollectorSetupWorkspace( const fs::path &package, const std::wstring_view action,
							   const fs::path &root, const fs::path &transfer,
							   const std::function<void()> &verifyPackage,
							   const fs::path &nativeOrigin, const fs::path &monitorOrigin)
{
	require( action == L"initialize" || action == L"verify" || action == L"export" ||
				action == L"import" || action == L"resume" || action == L"run-once" ||
				action == L"bind-origins",
			"WORKSPACE_ACTION") ;
	checkPath( package) ;
	checkPath( root) ;
	require( !pathsOverlap( package, root), "WORKSPACE_OVERLAP") ;
	// 移設rootも作成やpackage検査より前に全rootとの非重複を確定する。
	if( action == L"export" || action == L"import" || action == L"resume") {
		checkPath( transfer) ;
		require( !pathsOverlap( transfer, root) && !pathsOverlap( transfer, package),
				"WORKSPACE_OVERLAP") ;
	}

	std::vector<Handle> packageHandles ;	// Runtime終了までpackageの置換と書込みを拒否する。
	lockAncestors( package, packageHandles) ;
	const auto token = userToken() ;	// 検査中に生存するTOKEN_USER。
	// Windows token境界の所有bufferをTOKEN_USERとして読む。
	PSID	   user = reinterpret_cast<const TOKEN_USER *>( token.data())->User.Sid ;
	inspectTree( package, user, true, packageHandles) ;
	verifyPackage() ;
	std::vector<Handle> rootHandles ;	// 操作rootと祖先の置換を拒否する。
	lockAncestors( root.parent_path(), rootHandles) ;
	// 新規操作だけがprotected rootを作成し、既存先へは進まない。
	if( action == L"initialize" || action == L"import") {
		createCollectorSetupProtectedRoot( root) ;
	}

	inspectTree( root, user, false, rootHandles) ;
	// Monitorのimport staging renameを妨げないよう、root以外の検査handleを解放する。
	rootHandles.clear() ;
	lockAncestors( root, rootHandles) ;
	const bool boundOffline =
		// 未bindのv4／v5だけは従来のworkspace内monitorを使用する。
		(action == L"verify" || action == L"export") && fs::exists( root / L"origin.json") &&
		readOrigin( root / L"workspace.json").GetNamedString( L"schema") ==
			L"dc-collector-explicit-workspace-v1" ;
	const SetupJson offlineReference = boundOffline ? readOrigin( root / L"origin.json")
													: SetupJson{} ;	// 作成前にも同じ保護参照を使う。
	// 外部正本またはnative原点内へexport containerを作成する前に拒否する。
	if( boundOffline && action == L"export") {
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
	// 移設操作だけに固定transfer引数を要求する。
	if( action == L"export" || action == L"import" || action == L"resume") {
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

	const fs::path executable	 = package / L"runtime/python.exe" ;	// 唯一許可する絶対child。
	const bool	   communication = action == L"run-once" ;				// 新v5の明示一回操作だけに限定する。
	const bool	   bindingAction = action == L"bind-origins" ;			// 原点選択は非通信の別操作。
	const bool	   liveAction =
		communication || bindingAction || boundOffline ;	// 同じ保護原点を必要とする操作。
	CollectorSetupAdmission admission ;						// 子完了まで保持する元storeの排他writer。
	SetupJson				origin ;						// 今回の実体へ結合する非公開local参照。
	SetupJson				previous ;						// 停止移設時だけ再照合する元正本。
	std::vector<Handle>		originHandles ;					// native以外の原点と祖先の置換も拒否する。
	std::string				context ;						// 継承pipeだけへ渡す非永続context。
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
		const DWORD	 code = acquireCollectorSetupAdmission( nativeRoot, now, admission,
														   reason) ;	// 非作成の完全旧検証。
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

	std::wstring command = quote( executable.native()) + L" -I -B -S -c " + quote( BOOTSTRAP) + L" " +
						   quote( package.native()) + L" " + quote( action) + L" " +
						   quote( root.native()) + L" " +
						   // 検査済み有限argv。
						   quote( transfer.native()) ;
	// 通信操作だけが検証済みOS pathと実byte hashを固定argvへ追加する。
	if( communication) {
		command += L" " + quote( transport.executable.native()) + L" " + quote( transport.sha256) ;
	}

	require( command.size() < 32768U, "WORKSPACE_ARGV_LIMIT") ;
	std::array<wchar_t, 32768> windows{} ;	// OS起点を環境変数から受け取らない。
	const UINT				   length =
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
	inspectTree( root, user, false, finalHandles) ;
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
} // namespace drivercrate
