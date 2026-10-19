//------------------------------------------------------------------------------
/**
 * @file local_collector_state_store.cpp
 * @brief 収集台帳を保護DACL付きで作成し、既存状態をhandleから検証します。
 * @version 01.12.02
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/25  作成時ACL・既存拒否・有限I/Oを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/25  完全SHA名と保護run列挙を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/27  単一campaign借用とwriter状態の照会を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/27  current列挙・各entry再検査とmode拒否を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/27  保護handleによる全entry容量集計を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/01  私有collection階層・親所有子と旧子writer拒否を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/02  実sizeの先払いraw読取りを追加。
 * Ver.01.07.00 Shunji Ogawa  2026/10/02  明示history付き子と強所有履歴の配置を追加。
 * Ver.01.08.00 Shunji Ogawa  2026/10/02  実HTTP所有0からの排他的freezeを実装。
 * Ver.01.09.00 Shunji Ogawa  2026/10/03  私有初回回復だけの専用ROOT配置を非作成で検査。
 * Ver.01.10.00 Shunji Ogawa  2026/10/03  ROOT未保存の連続準備prefix回復と検査を追加。
 * Ver.01.11.00 Shunji Ogawa  2026/10/03  非作成readerの私有handleと有限名監査を追加。
 * Ver.01.11.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.12.00   Shunji Ogawa  2026/10/17 非作成の既存writer取得を既存保護実装へ接続。
 * Ver.01.12.01   Shunji Ogawa  2026/10/17 writerの共通祖先検査と大小文字別名拒否を適用。
 * Ver.01.12.02   Shunji Ogawa  2026/10/18 検証済みlegacy pathも内部extended DOS表記へ統一。
 * </pre>
 *
 * @note 同じuserと管理者は信頼主体です。既存fileのACLを変更・修復しません。
 */
//------------------------------------------------------------------------------

#include "platform/local_collector_state_store.h"

#include <aclapi.h>
#include <sddl.h>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <new>
#include <utility>
#include <vector>

namespace drivercrate {
/** @brief 所有数と閉鎖bitを一つのatomic状態へ結合します。 */
struct CollectorStoreHttpActivity {
	/// 0は自由、1～64は実所有数、上位bitだけは閉鎖中です。
	std::atomic_uint32_t value{} ;
} ;
namespace {

// 所有0からだけ取得する排他的閉鎖bitです。
constexpr std::uint32_t HTTP_ACTIVITY_FROZEN = 0x80000000U ;
// 固定permit poolの保守的なprocess内登録上限です。
constexpr std::uint32_t HTTP_ACTIVITY_MAXIMUM = 64U ;

// 一fileのenvelope上限をbyteで固定する。
constexpr DWORD			MAXIMUM_BYTES = 2U * 1024U * 1024U ;
// 一階層を走査するentry上限。上限超過は削除せず拒否する。
constexpr std::size_t	MAXIMUM_ENTRIES = 4096U ;

/** @brief Pathに埋め込める完全小文字hashだけを受理します。
 * @param[in] value Collectionまたはsegmentのkey。
 * @return 64桁の小文字SHA-256表現ならtrue。
 */
bool					fullHash( std::wstring_view value)
{
	return value.size() == 64U && std::all_of( value.begin(), value.end(), []( wchar_t letter) {
			   return (letter >= L'0' && letter <= L'9') || (letter >= L'a' && letter <= L'f') ;
		   }) ;
}

/** @brief 有効なWin32 handleを一回だけ解放します。 */
struct HandleCloser {
	/** @brief unique_ptrが保持するhandleを閉じます。
     * @param[in] value nullでもINVALID_HANDLE_VALUEでもないhandle。
     */
	void operator()( void *value) const noexcept
	{
		CloseHandle( value) ;
	}
} ;
/** @brief LocalAlloc系APIから受け取ったbufferを解放します。 */
struct MemoryCloser {
	/** @brief unique_ptrが保持するLocalAlloc bufferを返します。
     * @param[in] value LocalFreeへ渡せる非null buffer。
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
using LocalMemory = std::unique_ptr<void, MemoryCloser> ;

/** @brief 列挙中の例外経路でもFind handleを閉じます。 */
struct FindCloser {
	/** @brief Find APIが返した有効handleを閉じます。
     * @param[in] value FindFirstFileが返した有効handle。
     */
	void operator()( void *value) const noexcept
	{
		FindClose( value) ;
	}
} ;

/** @brief INVALID_HANDLE_VALUEをunique_ptrの空状態へ正規化します。
 * @param[in] value 所有権を引き取るAPI返却handle。
 * @return scope終了時にhandleを閉じるowner。
 */
[[nodiscard]] Handle ownHandle( HANDLE value)
{
	return Handle( value == INVALID_HANDLE_VALUE ? nullptr : value) ;
}

/** @brief handleの実pathと属性を確認し、別参照・reparse・hard linkを拒否します。
 * @param[in] handle 以後のI/Oと共通に使用するborrowed handle。
 * @param[in] expected 期待するローカル絶対path。
 * @param[in] directory trueならdirectory、falseなら単一linkの通常file。
 * @return 照合成功0、拒否またはAPIのWin32 error。
 */
[[nodiscard]] DWORD checkObject( HANDLE handle, const std::filesystem::path &expected,
								bool directory)
{
	// 実際に開いた対象の属性とlink数を取得する。
	BY_HANDLE_FILE_INFORMATION info{} ;
	// 読み書きに使うhandleと属性検査を同じ対象へ結合する。
	if( !GetFileInformationByHandle( handle, &info)) {
		return GetLastError() ;
	}

	// 台帳にdirectory代入、reparse、別名hard linkを持ち込ませない。
	if( (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U ||
	   ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) != directory ||
	   (!directory && info.nNumberOfLinks != 1U) || GetFileType( handle) != FILE_TYPE_DISK) {
		return ERROR_ACCESS_DENIED ;
	}

	// 正規path用の有限buffer。Windowsの通常最大path長を超えない。
	std::wstring actual( 32768U, L'\0') ;
	// Handleから得た実pathの文字数。
	const DWORD	 length =
		GetFinalPathNameByHandleW( handle, actual.data(), static_cast<DWORD>( actual.size()),
								  FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;
	// 欠損または切詰めを一致と扱わない。
	if( length == 0U || length >= actual.size()) {
		return length == 0U ? GetLastError() : ERROR_FILENAME_EXCED_RANGE ;
	}

	actual.resize( length) ;
	// APIが返すDOS形式のextended pathへ比較対象を揃える。
	std::wstring wanted = L"\\\\?\\" + std::filesystem::path( expected).make_preferred().native() ;
	// Drive rootの末尾区切りだけの表現差を除く。
	while( !actual.empty() && actual.back() == L'\\') {
		actual.pop_back() ;
	}

	// 比較対象も同じ末尾規則へ揃える。
	while( !wanted.empty() && wanted.back() == L'\\') {
		wanted.pop_back() ;
	}

	return CompareStringOrdinal( actual.c_str(), -1, wanted.c_str(), -1, TRUE) == CSTR_EQUAL
			   ? ERROR_SUCCESS
			   : ERROR_ACCESS_DENIED ;
}

/** @brief root配下の有限なJSON名だけを受理します。
 * @param[in] relative 専用rootからの相対path。
 * @return runsまたはcurrent直下の有限ASCII JSON名ならtrue。
 */
[[nodiscard]] bool safeRelative( const std::filesystem::path &relative)
{
	// 二つの固定directory以外への書込みを拒否する。
	if( relative.parent_path() != L"runs" && relative.parent_path() != L"current") {
		return false ;
	}

	// root内で使用できる一file名。
	const std::wstring name = relative.filename().native() ;
	// 空、隠し相対path、過長、JSON以外を拒否する。
	if( name.empty() || name.front() == L'.' || name.size() > 160U || !name.ends_with( L".json")) {
		return false ;
	}

	return std::all_of( name.begin(), name.end(), []( wchar_t letter) {
		return (letter >= L'a' && letter <= L'z') || (letter >= L'0' && letter <= L'9') ||
			   letter == L'-' || letter == L'.' ;
	}) ;
}

} // namespace

/** @see local_collector_state_store.h */
bool isLocalCollectorDescriptorAllowed( PSECURITY_DESCRIPTOR descriptor, PSID userSid,
									   const bool directory) noexcept
{
	// OS API由来でも欠損・不正descriptorを受け入れない。
	if( descriptor == nullptr || userSid == nullptr || !IsValidSid( userSid) ||
	   !IsValidSecurityDescriptor( descriptor)) {
		return false ;
	}

	// Ownerが権限変更できる点も検証範囲へ含める。
	PSID						owner{} ;
	// OwnerとDACLのdefaulted flagをAPIから受け取る。
	BOOL						defaulted{} ;
	// Descriptorの制御bit。
	SECURITY_DESCRIPTOR_CONTROL control{} ;
	// Descriptorのrevision。
	DWORD						revision{} ;
	// 保護されていないDACLと許可外ownerを拒否する。
	if( !GetSecurityDescriptorOwner( descriptor, &owner, &defaulted) || owner == nullptr ||
	   !IsValidSid( owner) ||
	   !(EqualSid( owner, userSid) || IsWellKnownSid( owner, WinLocalSystemSid) ||
		 IsWellKnownSid( owner, WinBuiltinAdministratorsSid)) ||
	   !GetSecurityDescriptorControl( descriptor, &control, &revision) ||
	   (control & SE_DACL_PROTECTED) == 0U) {
		return false ;
	}

	// DACL自体と存在flagを検査する。
	PACL acl{} ;
	// null DACLを全拒否と誤認しないため存在状態を受け取る。
	BOOL present{} ;
	// 許可した三entry以外の権限表現を認めない。
	if( !GetSecurityDescriptorDacl( descriptor, &present, &acl, &defaulted) || !present ||
	   acl == nullptr || !IsValidAcl( acl) || acl->AceCount != 3U) {
		return false ;
	}

	// 三principalの明示許可が揃ったことを個別に記録する。
	bool user{} ;
	// SYSTEMに付与された明示許可。
	bool system{} ;
	// Administratorsに付与された明示許可。
	bool administrators{} ;
	// 有限の三ACEについて型、flag、権限、SIDをすべて照合する。
	for( DWORD index = 0U; index < acl->AceCount; ++index) {
		// GetAceが返す検証済みACL内のborrowed pointer。
		void *raw{} ;
		// ACE取得不能を未知の許可として受け入れない。
		if( !GetAce( acl, index, &raw)) {
			return false ;
		}

		// Win32 ACL境界で固定型のACEを読み取る。
		const auto *ace = static_cast<const ACCESS_ALLOWED_ACE *>( raw) ;
		// 通常allow以外の条件付き権限、継承、maskを拒否する。
		if( ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
		   ace->Header.AceSize < sizeof( ACCESS_ALLOWED_ACE) ||
		   ace->Header.AceFlags != (directory ? OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE : 0U) ||
		   ace->Mask != FILE_ALL_ACCESS) {
			return false ;
		}

		// ACCESS_ALLOWED_ACEの可変長SID領域をAPIへ渡す。
		PSID sid = const_cast<DWORD *>( &ace->SidStart) ;
		// ACL内の有効なSIDだけを同一性照合する。
		if( !IsValidSid( sid)) {
			return false ;
		}

		// UserがSYSTEMの場合には同じSIDが双方を満たす。
		const bool isUser = EqualSid( sid, userSid) != FALSE ;
		// SYSTEMのwell-known SIDとの一致。
		const bool isSystem = IsWellKnownSid( sid, WinLocalSystemSid) != FALSE ;
		// Administratorsのwell-known SIDとの一致。
		const bool isAdministrators = IsWellKnownSid( sid, WinBuiltinAdministratorsSid) != FALSE ;
		// 未知principalへのallowは権限の大小にかかわらず拒否する。
		if( !isUser && !isSystem && !isAdministrators) {
			return false ;
		}

		user |= isUser ;
		system |= isSystem ;
		administrators |= isAdministrators ;
	}

	return user && system && administrators ;
}

/** @brief process user、作成用descriptor、固定directory、writer lockを所有します。 */
struct LocalCollectorStateStore::State {
	/// 実HTTP所有と閉鎖を結合する、再初期化で引き継がない私有identity。
	std::shared_ptr<CollectorStoreHttpActivity> httpActivity{
		std::make_shared<CollectorStoreHttpActivity>()} ;
	/// 最後のI/Oの元Win32 error。
	DWORD									  error{} ;
	/// 固定した専用root。
	std::filesystem::path					  root ;
	/// 子handleを閉じるまで親rootとwriter lockを保持する強所有。
	std::shared_ptr<LocalCollectorStateStore> parentOwner ;
	/// 私有親初期化だけでsegments階層を受理する場合true。
	bool									  collectionLayout{} ;
	/// 明示した新子rootだけに固定history directoryを許す場合true。
	bool									  historyLayout{} ;
	/// TokenUserから取得したSIDを含むbuffer。
	std::vector<BYTE>						  tokenUser ;
	/// directory作成用の保護descriptor。
	LocalMemory								  directoryDescriptor ;
	/// file作成用の保護descriptor。
	LocalMemory								  fileDescriptor ;
	/// rootまでのancestorと二つの専用directoryを保持するhandle。
	std::vector<Handle>						  directories ;
	/// 共有を認めないwriter lock。
	Handle									  lock ;
	/// 通常read/writeを許可する初期化が完了した場合true。
	bool									  ready{} ;
	/// 同時に一つだけが保持する非所有campaign identity。
	const void								 *campaignBorrower{} ;
	/// 同じ監督が保持する一つの待機台帳の非所有identity。
	const void								 *waitBorrower{} ;

	/** @brief 検証済みstoreのpathを内部extended DOS表記へ揃えます。
	 * @param[in] path 検査済み絶対DOS path。
	 * @return backslashを揃えたextended表現。外部pathの受理条件は変更しません。
	 */
	std::wstring							  apiPath( const std::filesystem::path &path) const
	{
		return L"\\\\?\\" + std::filesystem::path( path).make_preferred().native() ;
	}

	/** @brief 初回marker欠損時のmetadata階層を非変更で検査します。
	 * @return 全階層が空0、非空13、第一Win32 error。
	 */
	DWORD emptyMetadata() const
	{
		// 既知三階層だけを非作成で調べます。
		for( const auto *name : {L"current", L"runs", L"segments", L"history"}) {
			// 旧layoutでは未許可のhistoryを初回の空検査へ取り込みません。
			if( std::wstring_view( name) == L"history" && !historyLayout) {
				continue ;
			}

			WIN32_FIND_DATAW entry{} ;	// 未知entryを初回登録へ含めません。
			const HANDLE	 raw = FindFirstFileW( apiPath( root / name / L"*").c_str(),
												  &entry) ;	// 同じ保護root内の列挙です。
			// 欠損階層とアクセス拒否を分けます。
			if( raw == INVALID_HANDLE_VALUE) {
				const DWORD code = GetLastError() ;	// 第一の照会errorです。
				// 完全初回の未作成directoryだけを許します。
				if( code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) {
					continue ;
				}

				return code ;
			}

			const std::unique_ptr<void, FindCloser> search( raw) ;	// 拒否でも回収します。
			// 自己／親以外が一件あれば初回登録を拒否します。
			do {
				const std::wstring item( entry.cFileName) ;	// 確認中だけの有限名です。
				// 元応答・staging・子を初回として捨てません。
				if( item != L"." && item != L"..") {
					return ERROR_INVALID_DATA ;
				}
			} while( FindNextFileW( raw, &entry)) ;
			const DWORD code = GetLastError() ;	// 列挙終了のcodeです。
			// API停止を空とみなしません。
			if( code != ERROR_NO_MORE_FILES) {
				return code ;
			}
		}

		return ERROR_SUCCESS ;
	}

	/** @brief 新metadata階層を作る前にmarkerを実handleで照合します。
	 * @param[in] expected 固定schemaの有限canonical本文。
	 * @return 完全一致または空初回0、別本文13、第一Win32 error。
	 */
	DWORD preflightMarker( std::string_view expected) const
	{
		Handle		file ;	// 属性・ACL検査を通る読取り専用ownerです。
		const DWORD code = openFile( root / L"current/collector-campaign-mode-v1.json", GENERIC_READ,
									FILE_SHARE_READ, false, file) ;	// 作成前の唯一markerです。
		// 初回欠損だけをmetadata空検査へ渡します。
		if( code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) {
			return emptyMetadata() ;
		}

		// I/O不明から作成へfallbackしません。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		LARGE_INTEGER size{} ;	// 同じ実handleのbyte長です。
		// 第一API errorを保持します。
		if( !GetFileSizeEx( file.get(), &size)) {
			return GetLastError() ;
		}

		// 固定長以外へallocationを拡張しません。
		if( size.QuadPart != static_cast<LONGLONG>( expected.size()) ||
		   expected.size() > MAXIMUM_BYTES) {
			return ERROR_INVALID_DATA ;
		}

		std::string bytes( expected.size(), '\0') ;	// 全成功後だけ比較する本文です。
		DWORD		read{} ;						// 実観測byte数です。
		// Read失敗を部分一致へ変換しません。
		if( !ReadFile( file.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &read, nullptr)) {
			return GetLastError() ;
		}

		return read == bytes.size() && bytes == expected ? ERROR_SUCCESS : ERROR_INVALID_DATA ;
	}

	/** @brief TokenUserのborrowed SIDを返します。
     * @return tokenUserの寿命に結合したSID。初期化前はnull。
     */
	[[nodiscard]] PSID userSid() const noexcept
	{
		return tokenUser.empty() ? nullptr
								 : reinterpret_cast<const TOKEN_USER *>( tokenUser.data())->User.Sid ;
	}

	/** @brief process実行userに結合した二種類の保護descriptorを作成します。
     * @return 成功0、impersonation拒否またはWin32 error。
     */
	[[nodiscard]] DWORD makeDescriptors()
	{
		// Impersonationがあればprocess identityとの差を拒否する。
		HANDLE rawThread{} ;
		// Tokenに成り代わっている状態で新しい台帳を作成しない。
		if( OpenThreadToken( GetCurrentThread(), TOKEN_QUERY, TRUE, &rawThread)) {
			const auto thread = ownHandle( rawThread) ;	// 検出tokenをscope終了時に閉じる。
			return ERROR_BAD_IMPERSONATION_LEVEL ;
		}

		// Token不在以外の照会失敗も通常状態へ読み替えない。
		if( GetLastError() != ERROR_NO_TOKEN) {
			return GetLastError() ;
		}

		// 現在processの実userを問い合わせるtoken。
		HANDLE rawToken{} ;
		// SIDが分からなければACLを推測して作成しない。
		if( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &rawToken)) {
			return GetLastError() ;
		}

		// query専用tokenの自動解放。
		const auto token = ownHandle( rawToken) ;
		// TokenUser bufferの必要byte数。
		DWORD	   required{} ;
		GetTokenInformation( token.get(), TokenUser, nullptr, 0U, &required) ;
		// SID用bufferを有限に制限する。
		if( required < sizeof( TOKEN_USER) || required > 65536U) {
			return ERROR_INVALID_DATA ;
		}

		tokenUser.resize( required) ;
		// 有効なprocess userだけを作成policyへ結合する。
		if( !GetTokenInformation( token.get(), TokenUser, tokenUser.data(), required, &required)) {
			return GetLastError() ;
		}

		// Windowsが変換するSID表記を借り受ける。
		LPWSTR rawSid{} ;
		// 許可ACLにはAPIから得たSID表記だけを使う。
		if( !ConvertSidToStringSidW( userSid(), &rawSid)) {
			return GetLastError() ;
		}

		// SID文字列の自動解放。
		const LocalMemory  sidMemory( rawSid) ;
		// 実行userのSID文字列。ログへ出さない。
		const std::wstring sid( rawSid) ;
		// Fileとdirectoryの二profileだけを作成する。
		for( const bool directory : {false, true}) {
			// 許可entryに使う継承flag。
			const std::wstring flags = directory ? L"OICI" : L"" ;
			// Ownerを実行userへ結合したprotected DACL。
			const std::wstring sddl = L"O:" + sid + L"D:P(A;" + flags + L";FA;;;" + sid + L")(A;" +
									  flags + L";FA;;;SY)(A;" + flags + L";FA;;;BA)" ;
			// OSが構築する自己相対descriptor。
			PSECURITY_DESCRIPTOR rawDescriptor{} ;
			// Descriptor生成失敗では保護なしにfallbackしない。
			if( !ConvertStringSecurityDescriptorToSecurityDescriptorW( sddl.c_str(), SDDL_REVISION_1,
																	 &rawDescriptor, nullptr)) {
				return GetLastError() ;
			}

			// 作成先種類に対応するdescriptorだけを保存する。
			if( directory) {
				directoryDescriptor.reset( rawDescriptor) ;
			} else {
				fileDescriptor.reset( rawDescriptor) ;
			}
		}

		return ERROR_SUCCESS ;
	}

	/** @brief 同じhandleからownerとDACLを取得して検証します。
     * @param[in] handle READ_CONTROLを持つborrowed handle。
     * @param[in] directory trueならOICI付きdirectory policyを要求します。
     * @return 検証成功0、拒否またはWin32 error。
     */
	[[nodiscard]] DWORD checkSecurity( HANDLE handle, bool directory) const
	{
		// OSが返すdescriptorの所有権を直後にRAIIへ移す。
		PSECURITY_DESCRIPTOR raw{} ;
		// READ_CONTROLを持つhandleから実際の権限を取得する。
		const DWORD			 result = GetSecurityInfo( handle, SE_FILE_OBJECT,
													  OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
													  nullptr, nullptr, nullptr, nullptr, &raw) ;
		// 失敗時に非null bufferが返っても回収する。
		const LocalMemory	 descriptor( raw) ;
		// ACL照会失敗は既定許可へ変換しない。
		if( result != ERROR_SUCCESS) {
			return result ;
		}

		return isLocalCollectorDescriptorAllowed( descriptor.get(), userSid(), directory)
				   ? ERROR_SUCCESS
				   : ERROR_ACCESS_DENIED ;
	}

	/** @brief directoryを開いて検証し、renameとdeleteを共有せず保持します。
     * @param[in] path 固定する一階層の絶対path。
     * @param[in] privateDirectory trueならownerと保護DACLも検証します。
     * @param[in] create trueなら欠損時だけdirectoryを作成します。
     * @return handle保持成功0、拒否またはWin32 error。
     */
	[[nodiscard]] DWORD pinDirectory( const std::filesystem::path &path, bool privateDirectory,
									 bool create)
	{
		// 作成時点から継承を止めるdescriptor。
		SECURITY_ATTRIBUTES attributes{sizeof( SECURITY_ATTRIBUTES), directoryDescriptor.get(),
									   FALSE} ;
		// 専用rootと子だけを保護し、既存ancestorのACLを変更しない。
		if( create &&
		   !CreateDirectoryW( apiPath( path).c_str(), privateDirectory ? &attributes : nullptr)) {
			// 衝突した既存directoryも後続の実handle検査へ進める。
			const DWORD createError = GetLastError() ;
			// 既存以外の作成失敗を保持する。
			if( createError != ERROR_ALREADY_EXISTS) {
				return createError ;
			}
		}

		// 必要な属性とprivate ACLだけを読み、削除共有を外す。
		auto handle = ownHandle( CreateFileW(
			apiPath( path).c_str(), FILE_READ_ATTRIBUTES | (privateDirectory ? READ_CONTROL : 0U),
			FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;
		// 開けないdirectoryを作成済みと推測しない。
		if( !handle) {
			return GetLastError() ;
		}

		// 実handleのpathと属性の検査結果。
		DWORD result = checkObject( handle.get(), path, true) ;
		// private directoryはownerとDACLも厳密に照合する。
		if( result == ERROR_SUCCESS && privateDirectory) {
			result = checkSecurity( handle.get(), true) ;
		}

		// 検証が揃ったhandleだけを保持する。
		if( result == ERROR_SUCCESS) {
			directories.push_back( std::move( handle)) ;
		}

		return result ;
	}

	/** @brief 既存fileを開き、新規の場合だけ作成時descriptorを付与します。
     * @param[in] path 固定したprivate directory内の絶対path。
     * @param[in] access READ_CONTROLに加えて要求する権限。
     * @param[in] share 呼出し元が許すread共有等のflag。
     * @param[in] create trueなら未存在fileだけをCREATE_NEWで作ります。
     * @param[out] handle 成功時の検証済みowner。失敗時もRAIIで解放します。
     * @return 成功0、拒否または元のWin32 error。
     */
	[[nodiscard]] DWORD openFile( const std::filesystem::path &path, DWORD access, DWORD share,
								 bool create, Handle &handle) const
	{
		handle = ownHandle(
			CreateFileW( apiPath( path).c_str(), access | READ_CONTROL, share, nullptr, OPEN_EXISTING,
						FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr)) ;
		// 未存在以外のerrorで作成へfallbackしない。
		if( !handle) {
			// 最初のopen失敗をcreate判定まで保存する。
			const DWORD openError = GetLastError() ;
			// 新規作成が許可され、fileだけが欠損している場合に限定する。
			if( !create || openError != ERROR_FILE_NOT_FOUND) {
				return openError ;
			}

			// 新規fileへ継承しない保護DACLを直接付ける。
			SECURITY_ATTRIBUTES attributes{sizeof( SECURITY_ATTRIBUTES), fileDescriptor.get(),
										   FALSE} ;
			handle = ownHandle( CreateFileW(
				apiPath( path).c_str(), access | READ_CONTROL, share, &attributes, CREATE_NEW,
				FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;
			// 競合や作成権限エラーを通常fileとして受理しない。
			if( !handle) {
				return GetLastError() ;
			}
		}

		// 読み書き前のobject検証。
		const DWORD objectError = checkObject( handle.get(), path, false) ;
		return objectError == ERROR_SUCCESS ? checkSecurity( handle.get(), false) : objectError ;
	}

	/** @brief 親直下の最大1024子containerを実handleで検査します。
	 * @param[out] names 成功時だけの固定順完全hash名。
	 * @return 成功0、容量68または元Win32 error。
	 */
	DWORD segmentNames( std::vector<std::wstring> &names)
	{
		names.clear() ;
		WIN32_FIND_DATAW entry{} ;	// Container名だけの有限列挙です。
		const HANDLE	 raw =
			// 列挙ownerへ移します。
			FindFirstFileW( apiPath( root / L"segments" / L"*").c_str(), &entry) ;
		// 空containerと照会errorを区別します。
		if( raw == INVALID_HANDLE_VALUE) {
			const DWORD code = GetLastError() ;	// 最初の照会errorを保持します。
			return code == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : code ;
		}

		const std::unique_ptr<void, FindCloser> enumeration( raw) ;	// 例外時も列挙を閉じます。
		std::vector<std::wstring>				result ;			// 全検証まで部分一覧を公開しません。
		// 最大1024の子directoryだけを属性とACLで照合します。
		do {
			const std::wstring name( entry.cFileName) ;	// 外部へ実pathを出しません。
			// 自己・親をcontainer数へ含めません。
			if( name == L"." || name == L"..") {
				continue ;
			}

			// 未知keyや容量超過を作成・修復せず拒否します。
			if( !fullHash( name)) {
				return ERROR_INVALID_NAME ;
			}

			// 上限を越えて旧containerを削除しません。
			if( result.size() == 1024U) {
				return ERROR_TOO_MANY_NAMES ;
			}

			const auto path = root / L"segments" / name ;	// 親でpinした階層に結合します。
			auto	   handle =
				ownHandle( CreateFileW( apiPath( path).c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
									  FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
									  FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
									  nullptr)) ;	// 一時検査owner。
			// 不明対象へ通常directoryとしてfallbackしません。
			if( !handle) {
				return GetLastError() ;
			}

			DWORD code = checkObject( handle.get(), path, true) ;	// 同じ実対象の属性と実path。
			// 属性成立後にownerと保護DACLを確認します。
			if( code == ERROR_SUCCESS) {
				code = checkSecurity( handle.get(), true) ;
			}

			// 検査不成立を部分成功にしません。
			if( code != ERROR_SUCCESS) {
				return code ;
			}

			result.push_back( name) ;
		} while( FindNextFileW( raw, &entry)) ;
		const DWORD code = GetLastError() ;	// 列挙終了か第一API errorです。
		// 完了以外の列挙停止を保持します。
		if( code != ERROR_NO_MORE_FILES) {
			return code ;
		}

		std::sort( result.begin(), result.end()) ;
		names = std::move( result) ;
		return ERROR_SUCCESS ;
	}

	/** @brief 既存台帳の有限階層を走査し、広いACLと未知entryを変更せず拒否します。
     * @param[in] path pin済みのprivate directory。
     * @param[in] top trueならroot、falseならrunsまたはcurrentの一段。
	 * @param[in] checkpointOnly 私有readerだけでmetadata内監査を後段の必要集合へ委譲する場合trueです。
     * @return 有限走査成功0、拒否またはWin32 error。
     */
	[[nodiscard]] DWORD auditDirectory( const std::filesystem::path &path, bool top,
									   const bool checkpointOnly = false)
	{
		// Find APIが返す一entry。
		WIN32_FIND_DATAW entry{} ;
		// 列挙handleはFindClose専用で閉じる。
		const HANDLE	 search = FindFirstFileW( apiPath( path / L"*").c_str(), &entry) ;
		// 空directoryだけは正常とする。
		if( search == INVALID_HANDLE_VALUE) {
			const DWORD result = GetLastError() ;	// 空とアクセス拒否を区別する。
			return result == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : result ;
		}

		// 列挙中にallocationが失敗しても検索handleを回収する。
		const std::unique_ptr<void, FindCloser> enumeration( search) ;

		// 列挙失敗・拒否を一度だけ確定する。
		DWORD									result = ERROR_SUCCESS ;
		// 二階層に限定した最大entry数。
		std::size_t								count{} ;
		// 固定階層を最大4096 entryまで検査する。
		do {
			// 今回のentry名。pathやSIDを外部出力しない。
			const std::wstring name( entry.cFileName) ;
			// 列挙の自己・親entryは処理しない。
			if( name == L"." || name == L"..") {
				continue ;
			}

			// 巨大台帳は上限を変える別契約まで拒否する。
			if( ++count > MAXIMUM_ENTRIES) {
				result = ERROR_TOO_MANY_NAMES ;
				break ;
			}

			// rootに認める子directoryは二つだけ。
			if( top && (name == L"runs" || name == L"current")) {
				result = pinDirectory( path / name, true, false) ;
				// 検証済みの子だけを一段走査する。
				if( result == ERROR_SUCCESS && !checkpointOnly) {
					result = auditDirectory( path / name, false) ;
				}
			}
			// 私有親のcontainerだけを保護して列挙します。
			else if( top && collectionLayout && name == L"segments") {
				// 私有親だけが子containerを許可し、旧応答は再生しません。
				result = pinDirectory( path / name, true, false) ;
				std::vector<std::wstring> names ;	// 部分検査の一覧を保持しません。
				// 固定したsegments配下のhash directoryを検査します。
				if( result == ERROR_SUCCESS) {
					result = segmentNames( names) ;
				}
			}
			// 明示した新子の固定履歴だけを同親でpinします。内部は履歴storeが検査します。
			else if( top && path == root && historyLayout && name == L"history") {
				result = pinDirectory( path / name, true, false) ;
			} else {
				// 再開時に残った既知のstaging名はJSON名へ戻して判定する。
				const std::wstring baseName =
					name.ends_with( L".json.tmp") ? name.substr( 0U, name.size() - 4U) : name ;
				// lockまたは二つの固定階層のJSONだけを扱う。
				if( (top && name != L"collector.lock") ||
				   (!top && !safeRelative( path.filename() / baseName))) {
					result = ERROR_INVALID_NAME ;
				} else {
					// 既存fileのACL検査中だけ保持する。
					Handle file ;
					result =
						openFile( path / name, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, false, file) ;
				}
			}

			// 失敗対象を修復・削除せず即時停止する。
			if( result != ERROR_SUCCESS) {
				break ;
			}
		} while( FindNextFileW( search, &entry)) ;
		// 列挙完了以外のAPI失敗を保持する。
		if( result == ERROR_SUCCESS && GetLastError() != ERROR_NO_MORE_FILES) {
			result = GetLastError() ;
		}

		return result ;
	}
} ;

/** @see local_collector_state_store.h */
LocalCollectorStateStore::LocalCollectorStateStore() : state_( std::make_unique<State>())
{
}
/** @see local_collector_state_store.h */
LocalCollectorStateStore::~LocalCollectorStateStore() = default ;

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::initialize( const std::filesystem::path &root, const bool writable)
{
	return initializeLegacy( root, writable, writable) ;
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::initializeExistingWriter( const std::filesystem::path &root)
{
	return initializeLegacy( root, true, false) ;
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::initializeLegacy( const std::filesystem::path &root,
												 const bool writable, const bool create)
{
	// 親所有子の再初期化で親能力を解放しません。
	if( state_->parentOwner) {
		return state_->error = ERROR_BUSY ;
	}

	// 固定historyを通常writerで直開きして親能力を迂回しません。
	if( writable && root.is_absolute() && root == root.lexically_normal() &&
	   CompareStringOrdinal( root.filename().c_str(), -1, L"history", -1, TRUE) == CSTR_EQUAL &&
	   CompareStringOrdinal( root.parent_path().parent_path().filename().c_str(), -1, L"segments",
							-1, TRUE) == CSTR_EQUAL) {
		const auto segmentName =
			// 大小文字同一の実配置を扱います。
			root.parent_path().filename().native() ;
		// 大文字hashの別表現でも固定historyを直接開く能力を与えません。
		if( segmentName.size() == 64U &&
		   std::all_of( segmentName.begin(), segmentName.end(), []( const wchar_t ch) {
			   return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f') ||
					  (ch >= L'A' && ch <= L'F') ;
		   })) {
			return state_->error = ERROR_INVALID_DATA ;
		}
	}

	const auto segmentName = root.filename().native() ;	// Windows別名を含む最終segment名。
	// 新階層の子を大小文字別名でも旧writerで直接開くことを拒否します。
	if( writable && root.is_absolute() && root == root.lexically_normal() &&
	   CompareStringOrdinal( root.parent_path().filename().c_str(), -1, L"segments", -1, TRUE) ==
		   CSTR_EQUAL &&
	   segmentName.size() == 64U &&
	   std::all_of( segmentName.begin(), segmentName.end(), []( const wchar_t ch) {
		   return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f') ||
				  (ch >= L'A' && ch <= L'F') ;
	   })) {
		const auto marker =
			// 親の存在marker。
			root.parent_path().parent_path() / L"current" / L"collector-campaign-mode-v1.json" ;
		const DWORD attributes = GetFileAttributesW(
			(L"\\\\?\\" + std::filesystem::path( marker).make_preferred().native())
				.c_str()) ;	// 自己申告本文は信用しません。
		// Markerがあれば旧子writerを許しません。
		if( attributes != INVALID_FILE_ATTRIBUTES) {
			return state_->error = ERROR_INVALID_DATA ;
		}

		const DWORD code = GetLastError() ;	// 欠損以外の照会失敗を保持します。
		// 不明権限をmarkerなしへ読み替えません。
		if( code != ERROR_FILE_NOT_FOUND && code != ERROR_PATH_NOT_FOUND) {
			return state_->error = code ;
		}
	}

	return initializeImpl( root, writable, false, {}, create) ;
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::initializeCollection( const std::filesystem::path &root,
													 std::string_view			  expected)
{
	return initializeImpl( root, true, true, {}, true, expected) ;
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::initializeOwnedSegment(
	const std::shared_ptr<LocalCollectorStateStore> &parent, std::wstring_view key, bool create,
	std::string_view expected, const bool withHistory)
{
	// 私有親writerを持たない子入口は成立させません。
	if( !parent || !parent->isWritable() || !parent->state_->collectionLayout || !fullHash( key)) {
		return ERROR_INVALID_PARAMETER ;
	}

	return initializeImpl( parent->root() / L"segments" / key, true, false, parent, create, expected,
						  withHistory) ;
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::initializeOwnedHistory(
	const std::shared_ptr<LocalCollectorStateStore> &segment, const bool create)
{
	// 専用子能力以外から任意pathを履歴へ採用しません。
	if( !segment || !segment->isWritable() || !segment->state_->historyLayout ||
	   !segment->state_->parentOwner) {
		return ERROR_INVALID_PARAMETER ;
	}

	return initializeImpl( segment->root() / L"history", true, false, segment, create) ;
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::initializeReadSegment(
	const std::shared_ptr<LocalCollectorStateStore> &parent, const std::wstring_view key)
{
	// 私有collection能力以外から任意子pathを開きません。
	if( !parent || !parent->isWritable() || !parent->state_->collectionLayout || !fullHash( key)) {
		return ERROR_INVALID_PARAMETER ;
	}

	return initializeImpl( parent->root() / L"segments" / key, true, false, parent, false, {}, true,
						  false, true) ;
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::initializeReadHistory(
	const std::shared_ptr<LocalCollectorStateStore> &segment)
{
	// 同親専用子以外へ通常mode欠損の例外を広げません。
	if( !segment || !segment->isWritable() || !segment->state_->historyLayout ||
	   !segment->state_->parentOwner) {
		return ERROR_INVALID_PARAMETER ;
	}

	return initializeImpl( segment->root() / L"history", true, false, segment, false, {}, false,
						  true, true) ;
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::initializeRecoveryHistory(
	const std::shared_ptr<LocalCollectorStateStore> &segment, const bool allowEmpty)
{
	// 親能力のない通常storeや旧子を専用回復の入口へ流用しません。
	if( !segment || !segment->isWritable() || !segment->state_->historyLayout ||
	   !segment->state_->parentOwner) {
		return ERROR_INVALID_PARAMETER ;
	}

	auto code = initializeImpl( segment->root() / L"history", true, false, segment, false, {}, false,
							   true) ;	// 欠損directory／lockを作成しません。
	// 第一保護／sharing errorを維持します。
	if( code != ERROR_SUCCESS) {
		return code ;
	}

	std::vector<std::wstring> current ;	// 固定一ROOT以外は受理しません。
	std::vector<std::wstring> runs ;	// 初期履歴に通常操作を混入させません。
	code = listCurrentNames( current) ;
	// 属性／ACLの第一失敗で停止します。
	if( code == ERROR_SUCCESS) {
		code = listRunNames( runs) ;
	}

	CollectorStoreUsage usage ;	// 残留stagingも実数に含めます。
	// 列挙と独立の同handle容量を確認します。
	if( code == ERROR_SUCCESS) {
		code = inspectUsage( usage) ;
	}

	std::string rootRaw ;	// 同じ一fileの実byteだけです。
	bool		found{} ;	// 欠損を新規ROOTへ補完しません。
	// 上限付きの一ROOTを別handleで読み、usageへ結合します。
	if( code == ERROR_SUCCESS) {
		code = read( L"current/segment-history-root-v1.json", rootRaw, found) ;
	}

	// ROOT一件・操作なし・完全実usage一致の配置だけを保存済み回復へ渡します。
	const bool rootShape = found &&
						   current == std::vector<std::wstring>{L"segment-history-root-v1.json"} &&
						   runs.empty() && usage.currentEntries == 1U && usage.runEntries == 0U &&
						   usage.bytes == rootRaw.size() ;
	// 空配置は準備回復に限り、全名とstagingを含む実容量0から判断します。
	const bool emptyShape = allowEmpty && !found && current.empty() && runs.empty() &&
							usage.currentEntries == 0U && usage.runEntries == 0U &&
							usage.bytes == 0U ;
	// Modeや未知名・操作・staging、実数不一致を非変更で拒否します。
	if( code == ERROR_SUCCESS && !rootShape && !emptyShape) {
		code = ERROR_INVALID_DATA ;
	}

	state_->ready		 = code == ERROR_SUCCESS ;
	return state_->error = code ;
}
/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::listSegments( std::vector<std::wstring> &names)
{
	// 通常rootへ新階層を追加しません。
	if( !isWritable() || !state_->collectionLayout) {
		names.clear() ;
		return state_->error = ERROR_INVALID_PARAMETER ;
	}

	return state_->error = state_->segmentNames( names) ;
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::initializeImpl( const std::filesystem::path &root,
											   const bool writable, const bool collection,
											   std::shared_ptr<LocalCollectorStateStore> parent,
											   const bool create, std::string_view expected,
											   const bool withHistory, const bool recoveryHistory,
											   const bool checkpointOnly)
{
	// 借用coreが参照するhandleとrootを途中で差し替えない。
	if( state_->campaignBorrower != nullptr || state_->waitBorrower != nullptr ||
	   state_->httpActivity->value.load( std::memory_order_acquire) != 0U || state_->parentOwner) {
		return state_->error = ERROR_BUSY ;
	}

	state_					 = std::make_unique<State>() ;
	state_->root			 = root.lexically_normal() ;
	state_->collectionLayout = collection ;
	state_->historyLayout	 = withHistory ;
	state_->parentOwner		 = std::move( parent) ;
	// UNC、相対path、device namespaceを受け入れない。
	if( !root.is_absolute() || root != state_->root || root.root_name().native().size() != 2U ||
	   root.native().find( L':', 2U) != std::wstring::npos) {
		return state_->error = ERROR_INVALID_NAME ;
	}

	// 永続ACLを持つローカル固定driveに限定する。
	DWORD volumeFlags{} ;
	// 非対応filesystemで保護が成功したと見せない。
	if( GetDriveTypeW( root.root_path().c_str()) != DRIVE_FIXED) {
		return state_->error = ERROR_NOT_SUPPORTED ;
	}

	// volume照会の実際の失敗は非対応と混同せず保持する。
	if( !GetVolumeInformationW( root.root_path().c_str(), nullptr, 0U, nullptr, nullptr, &volumeFlags,
							  nullptr, 0U)) {
		return state_->error = GetLastError() ;
	}

	// 永続DACLがないfilesystemへprivate台帳を置かない。
	if( (volumeFlags & FILE_PERSISTENT_ACLS) == 0U) {
		return state_->error = ERROR_NOT_SUPPORTED ;
	}

	state_->error = state_->makeDescriptors() ;
	// 作成policyを構築できなければ状態を触らない。
	if( state_->error != ERROR_SUCCESS) {
		return state_->error ;
	}

	// Drive rootから順にhandleを固定する。
	std::filesystem::path path = root.root_path() ;
	state_->error			   = state_->pinDirectory( path, false, false) ;
	// 固定できなければ後続のpath照合も成立しない。
	if( state_->error != ERROR_SUCCESS) {
		return state_->error ;
	}

	// 親を固定してから次の要素を作成・検査する。
	for( const auto &component : root.relative_path()) {
		path /= component ;
		// 最後の専用rootだけをprivateとする。
		const bool privateDirectory = path == root ;
		state_->error				= state_->pinDirectory(
			  path, privateDirectory, create && (privateDirectory || path == root.parent_path())) ;
		// 読取り検証は未存在領域を作成しない。
		if( !writable &&
		   (state_->error == ERROR_PATH_NOT_FOUND || state_->error == ERROR_FILE_NOT_FOUND)) {
			return state_->error = ERROR_SUCCESS ;
		}

		// reparse、別path、広いACL、API失敗をここで止める。
		if( state_->error != ERROR_SUCCESS) {
			return state_->error ;
		}
	}

	state_->error = state_->auditDirectory( root, true, checkpointOnly) ;
	// 既存の子fileまで検証する前には新しい子を作成しない。
	if( state_->error != ERROR_SUCCESS || !writable) {
		return state_->error ;
	}

	// 通常履歴は非空mode欠損を拒否し、私有回復だけは専用ROOTと全実usageを別に検査します。
	if( state_->parentOwner && state_->parentOwner->state_->historyLayout && !recoveryHistory) {
		Handle mode ;	// 同じ固定履歴の属性／ACLを検証する一時所有です。
		state_->error = state_->openFile( root / L"current/collector-campaign-mode-v1.json",
										 GENERIC_READ, FILE_SHARE_READ, false, mode) ;
		// 空初回だけが欠損modeから作成へ進めます。
		if( state_->error == ERROR_FILE_NOT_FOUND || state_->error == ERROR_PATH_NOT_FOUND) {
			state_->error = state_->emptyMetadata() ;
		}

		// Nonempty欠損・ACL・I/Oを修復しません。
		if( state_->error != ERROR_SUCCESS) {
			return state_->error ;
		}
	}

	// 新親／子の別modeを作成より先に拒否します。
	if( !expected.empty()) {
		state_->error = state_->preflightMarker( expected) ;
		// 不一致では元階層を増やしません。
		if( state_->error != ERROR_SUCCESS) {
			return state_->error ;
		}
	}

	// 必要な二階層だけを保護して作成します。
	for( const auto *name : {L"runs", L"current"}) {
		state_->error = state_->pinDirectory( root / name, true, create) ;
		// 作成不成立のままfile書込みへ進まない。
		if( state_->error != ERROR_SUCCESS) {
			return state_->error ;
		}
	}

	// 私有親だけに保護segmentsを追加します。
	if( collection) {
		state_->error = state_->pinDirectory( root / L"segments", true, create) ;
		// 子containerを固定できない状態でwriterを許しません。
		if( state_->error != ERROR_SUCCESS) {
			return state_->error ;
		}
	}

	state_->error = state_->openFile( root / L"collector.lock", GENERIC_READ | GENERIC_WRITE, 0U,
									 create, state_->lock) ;
	state_->ready = state_->error == ERROR_SUCCESS ;
	return state_->error ;
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::read( const std::filesystem::path &relative, std::string &bytes,
									 bool &found)
{
	std::uint64_t remaining = MAXIMUM_BYTES ;	// 旧一file上限をそのまま維持します。
	return read( relative, bytes, found, remaining) ;
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::read( const std::filesystem::path &relative, std::string &bytes,
									 bool &found, std::uint64_t &remaining)
{
	bytes.clear() ;
	found = false ;
	// pathとwriter契約が確定してから台帳本文を開く。
	if( !state_->ready || !safeRelative( relative)) {
		return state_->error = ERROR_INVALID_PARAMETER ;
	}

	// 検証と読取りに使う同一handle。
	Handle file ;
	state_->error =
		state_->openFile( state_->root / relative, GENERIC_READ, FILE_SHARE_READ, false, file) ;
	// fileの欠損だけを通常の初回状態として返す。
	if( state_->error == ERROR_FILE_NOT_FOUND) {
		return state_->error = ERROR_SUCCESS ;
	}

	// 権限拒否と内容欠損を混同しない。
	if( state_->error != ERROR_SUCCESS) {
		return state_->error ;
	}

	// 読取り上限に照合する実size。
	LARGE_INTEGER size{} ;
	// size照会失敗の元errorを保持する。
	if( !GetFileSizeEx( file.get(), &size)) {
		return state_->error = GetLastError() ;
	}

	// 空と過大なenvelopeを読み込まない。
	if( size.QuadPart <= 0 || size.QuadPart > MAXIMUM_BYTES) {
		return state_->error = ERROR_INVALID_DATA ;
	}

	// 同じ実sizeの予算を確保・読取りより先に予約します。
	if( static_cast<std::uint64_t>( size.QuadPart) > remaining) {
		return state_->error = ERROR_TOO_MANY_NAMES ;
	}

	remaining -= static_cast<std::uint64_t>( size.QuadPart) ;

	// 一括read後にだけ呼出し元へ渡すbuffer。
	std::string pending( static_cast<std::size_t>( size.QuadPart), '\0') ;
	// 実際に読んだbyte数。
	DWORD		readBytes{} ;
	// share writeを許していない同一fileから有限byteだけ読む。
	if( !ReadFile( file.get(), pending.data(), static_cast<DWORD>( pending.size()), &readBytes,
				 nullptr)) {
		return state_->error = GetLastError() ;
	}

	// 短いreadを完全なcheckpointと扱わない。
	if( readBytes != pending.size()) {
		return state_->error = ERROR_HANDLE_EOF ;
	}

	bytes				 = std::move( pending) ;
	found				 = true ;
	return state_->error = ERROR_SUCCESS ;
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::write( const std::filesystem::path &relative, std::string_view bytes)
{
	// 任意pathと上限外の内容をstaging作成前に拒否する。
	if( !state_->ready || !safeRelative( relative) || bytes.empty() || bytes.size() > MAXIMUM_BYTES) {
		return state_->error = ERROR_INVALID_PARAMETER ;
	}

	// 既存targetを置換してよいか検証する。
	Handle old ;
	state_->error = state_->openFile( state_->root / relative, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
									 false, old) ;
	// 欠損以外の拒否で既存targetを上書きしない。
	if( state_->error != ERROR_SUCCESS && state_->error != ERROR_FILE_NOT_FOUND) {
		return state_->error ;
	}

	old.reset() ;
	// 同じdirectoryに置く既知staging名。
	const std::filesystem::path temporary = state_->root / (relative.native() + L".tmp") ;
	// 作成または検証後にだけtruncateするstaging handle。
	Handle						file ;
	state_->error = state_->openFile( temporary, GENERIC_READ | GENERIC_WRITE, 0U, true, file) ;
	// stagingの広いACLやhard linkを変更しない。
	if( state_->error != ERROR_SUCCESS) {
		return state_->error ;
	}

	// 書込み位置を先頭へ固定するoffset。
	LARGE_INTEGER beginning{} ;
	// 検証した既存stagingだけをtruncateする。
	if( !SetFilePointerEx( file.get(), beginning, nullptr, FILE_BEGIN) || !SetEndOfFile( file.get())) {
		return state_->error = GetLastError() ;
	}

	// 実書込みbyte数。
	DWORD written{} ;
	// 本文を書いてからflushし、完了前にpointerを昇格させない。
	if( !WriteFile( file.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &written, nullptr)) {
		return state_->error = GetLastError() ;
	}

	// 部分writeを完全な世代として保存しない。
	if( written != bytes.size()) {
		return state_->error = ERROR_WRITE_FAULT ;
	}

	// 永続化要求が失敗した場合は旧targetを保持する。
	if( !FlushFileBuffers( file.get())) {
		return state_->error = GetLastError() ;
	}

	file.reset() ;
	// 検証済みのprivate directory内でだけ置換する。
	if( !MoveFileExW( state_->apiPath( temporary).c_str(),
					state_->apiPath( state_->root / relative).c_str(),
					MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
		return state_->error = GetLastError() ;
	}

	return state_->error = ERROR_SUCCESS ;
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::listRunNames( std::vector<std::wstring> &names)
{
	return listNames( L"runs", names) ;
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::listCurrentNames( std::vector<std::wstring> &names)
{
	return listNames( L"current", names) ;
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::listNames( const std::wstring_view	 directory,
										  std::vector<std::wstring> &names, std::size_t *entries,
										  std::uint64_t *bytes, const std::size_t maximumEntries)
{
	names.clear() ;
	// 任意の容量出力を失敗時にも初期化する。
	if( entries) {
		*entries = 0U ;
	}

	// 要求された場合だけbyte数の出力も初期化する。
	if( bytes) {
		*bytes = 0U ;
	}

	// 初期監査とwriter lockを取得していない列挙を拒否する。
	if( !state_->ready || (directory != L"runs" && directory != L"current") ||
	   maximumEntries > MAXIMUM_ENTRIES) {
		return state_->error = ERROR_INVALID_PARAMETER ;
	}

	// Win32列挙の一entryを固定上限へ入れる。
	WIN32_FIND_DATAW entry{} ;
	// 監査済みの固定directory直下だけを列挙する。
	const HANDLE	 search =
		FindFirstFileW( state_->apiPath( state_->root / directory / L"*").c_str(), &entry) ;
	// 空directoryとI/O失敗を分ける。
	if( search == INVALID_HANDLE_VALUE) {
		// Win32の元errorを保つ。
		const DWORD error	 = GetLastError() ;
		return state_->error = error == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : error ;
	}

	// 早期returnでも列挙handleを解放する。
	const std::unique_ptr<void, FindCloser> enumeration( search) ;
	std::size_t								entryCount{} ;	// stagingも含めた全entryの有限上限。
	std::uint64_t							byteCount{} ;	// 同じ保護handleから集計する実byte。
	// 同じ固定directoryのentryだけを有限走査する。
	do {
		// path成分のない一entry名。
		const std::wstring name( entry.cFileName) ;
		// 列挙の自己・親entryを対象外にする。
		if( name == L"." || name == L"..") {
			continue ;
		}

		// 大量entryで無制限にメモリを消費しない。
		if( ++entryCount > maximumEntries) {
			names.clear() ;
			return state_->error = ERROR_TOO_MANY_NAMES ;
		}

		// 初期監査済みであっても列挙時に再度固定名を確かめる。
		// 未知名は初期監査後の置換とみなして拒否する。
		const auto committedName = name.ends_with( L".json.tmp") ? name.substr( 0U, name.size() - 4U)
																: name ;	// stagingの元名も検査する。
		// 確定名とstagingの元名の両方を固定path契約へ照合する。
		if( !safeRelative( std::filesystem::path( directory) / committedName)) {
			names.clear() ;
			return state_->error = ERROR_INVALID_NAME ;
		}

		Handle file ;	// 同じhandleでowner・DACL・file属性を再確認する。
		state_->error = state_->openFile( state_->root / directory / name, FILE_READ_ATTRIBUTES,
										 FILE_SHARE_READ, false, file) ;
		// 初期監査後の権限・link・directory差替えも、部分一覧を返さず拒否する。
		if( state_->error != ERROR_SUCCESS) {
			names.clear() ;
			return state_->error ;
		}

		LARGE_INTEGER size{} ;	// 属性確認済みfileの長さ。
		// 別pathから長さを再取得しない。
		if( !GetFileSizeEx( file.get(), &size)) {
			names.clear() ;
			return state_->error = GetLastError() ;
		}

		// 全byte数のoverflowと5 GiB超を数値で拒否する。
		if( size.QuadPart < 0 ||
		   static_cast<std::uint64_t>( size.QuadPart) > 5ULL * 1024U * 1024U * 1024U - byteCount) {
			names.clear() ;
			return state_->error = ERROR_TOO_MANY_NAMES ;
		}

		byteCount += static_cast<std::uint64_t>( size.QuadPart) ;
		// staging fileを確定runとして返さない。
		if( name.ends_with( L".json")) {
			names.push_back( name) ;
		}
	} while( FindNextFileW( search, &entry)) ;
	// 列挙の正常完了と途中失敗を区別する。
	const DWORD finalError = GetLastError() ;
	// 途中失敗時は部分的な候補集合を返さない。
	if( finalError != ERROR_NO_MORE_FILES) {
		names.clear() ;
		return state_->error = finalError ;
	}

	// 同じ保存集合を決定的な順序で返す。
	std::sort( names.begin(), names.end()) ;
	// 完全列挙が成立した場合だけ容量を返す。
	if( entries) {
		*entries = entryCount ;
	}

	// 完全列挙が成立した場合だけ実byte数を返す。
	if( bytes) {
		*bytes = byteCount ;
	}

	return state_->error = ERROR_SUCCESS ;
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::inspectUsage( CollectorStoreUsage &usage)
{
	usage = {} ;
	CollectorStoreUsage		  result ;	// 成功時だけ返す全量集計。
	// 同じ保護列挙を使う一時name集合。
	std::vector<std::wstring> names ;
	std::uint64_t			  runBytes{} ;	// 保護列挙の出力。
	DWORD					  error =
		// 元I/O code。
		listNames( L"current", names, &result.currentEntries, &result.bytes) ;
	// 二directoryとも完全列挙が必要。
	if( error != 0U || (error = listNames( L"runs", names, &result.runEntries, &runBytes)) != 0U) {
		return error ;
	}

	// 全体の5 GiBも加算前に確認する。
	if( runBytes > 5ULL * 1024U * 1024U * 1024U - result.bytes) {
		return state_->error = ERROR_TOO_MANY_NAMES ;
	}

	result.bytes += runBytes ;
	usage				 = result ;
	return state_->error = ERROR_SUCCESS ;
}

/** @see local_collector_state_store.h */
DWORD rejectLocalCollectorCampaignMode( LocalCollectorStateStore &store)
{
	std::string bytes ;		// mode存在を読むだけで、旧callerへ内容を流用しない。
	bool		found{} ;	// 破損も欠損扱いにしない。
	const DWORD error = store.read( L"current/collector-campaign-mode-v1.json", bytes,
								   found) ;	// 保護handleの元診断。
	return error != ERROR_SUCCESS ? error : found ? ERROR_INVALID_DATA : ERROR_SUCCESS ;
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::lastError() const noexcept
{
	return state_->error ;
}

/** @see local_collector_state_store.h */
bool LocalCollectorStateStore::isWritable() const noexcept
{
	return state_->ready && static_cast<bool>( state_->lock) ;
}

/** @see local_collector_state_store.h */
const std::filesystem::path &LocalCollectorStateStore::root() const noexcept
{
	return state_->root ;
}

/** @see local_collector_http_activity.h */
CollectorStoreHttpLease::~CollectorStoreHttpLease()
{
	// 未発行の確保領域から登録を減算しません。
	if( armed_) {
		activity_->value.fetch_sub( 1U, std::memory_order_acq_rel) ;
	}
}
/** @see local_collector_http_activity.h */
CollectorStoreHttpFreeze::~CollectorStoreHttpFreeze()
{
	// 取得失敗した一時領域から他の閉鎖を解除しません。
	if( armed_) {
		activity_->value.store( 0U, std::memory_order_release) ;
	}
}
/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::checkHttpSupervisor() const noexcept
{
	return state_->httpActivity->value.load( std::memory_order_acquire) == HTTP_ACTIVITY_FROZEN
			   ? ERROR_BUSY
			   : ERROR_SUCCESS ;
}
/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::acquireHttpActivity(
	const void *borrower, std::shared_ptr<const CollectorStoreHttpLease> &lease) noexcept
{
	lease.reset() ;
	// 別writerや監督未成立から通信所有を登録しません。
	if( !isWritable() || !borrower || state_->campaignBorrower != borrower) {
		return ERROR_INVALID_PARAMETER ;
	}

	try {
		auto candidate =
			std::make_shared<CollectorStoreHttpLease>( CollectorStoreHttpLease::ConstructionKey{},
													  state_->httpActivity) ;	// 登録前に確保します。
		auto current =
			// 先着状態です。
			state_->httpActivity->value.load( std::memory_order_acquire) ;
		// 同じ監督threadで発行し、最大64のworker解放との競合だけを有限再確認します。
		for( std::uint32_t attempt = 0U; attempt <= HTTP_ACTIVITY_MAXIMUM; ++attempt) {
			// 閉鎖中の発行を永続予約より前に止めます。
			if( current == HTTP_ACTIVITY_FROZEN) {
				return ERROR_BUSY ;
			}

			// 65個目を作らず、既存の所有を保持します。
			if( current >= HTTP_ACTIVITY_MAXIMUM) {
				return ERROR_TOO_MANY_NAMES ;
			}

			// 同じatomic操作で発行と閉鎖を排他的にします。
			if( state_->httpActivity->value.compare_exchange_strong(
				   current, current + 1U, std::memory_order_acq_rel, std::memory_order_acquire)) {
				candidate->armed_ = true ;
				lease			  = std::move( candidate) ;
				return ERROR_SUCCESS ;
			}
		}

		return ERROR_BUSY ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}
/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::freezeHttpActivity(
	std::shared_ptr<const CollectorStoreHttpFreeze> &freeze) noexcept
{
	freeze.reset() ;
	// 読取り検証だけのstoreへ閉鎖能力を発行しません。
	if( !isWritable()) {
		return ERROR_INVALID_PARAMETER ;
	}

	// 終了前の監督をcaller観測だけで閉鎖しません。
	if( state_->campaignBorrower || state_->waitBorrower) {
		return ERROR_BUSY ;
	}

	try {
		auto candidate =
			std::make_shared<CollectorStoreHttpFreeze>( CollectorStoreHttpFreeze::ConstructionKey{},
													   state_->httpActivity) ;	// 閉鎖前の確保です。
		std::uint32_t expected = 0U ;											// 実所有0だけを許可します。
		// Pool／持出しcontrol／既存freezeを非変更で拒否します。
		if( !state_->httpActivity->value.compare_exchange_strong( expected, HTTP_ACTIVITY_FROZEN,
																std::memory_order_acq_rel,
																std::memory_order_acquire)) {
			return ERROR_BUSY ;
		}

		candidate->armed_ = true ;
		freeze			  = std::move( candidate) ;
		return ERROR_SUCCESS ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::borrowCampaign( const void *borrower) noexcept
{
	// 検証だけのstoreからwriter借用を作らない。
	if( borrower == nullptr || !isWritable()) {
		return ERROR_INVALID_PARAMETER ;
	}

	// 別coreだけでなく同じcoreからの二重取得も拒否する。
	if( state_->campaignBorrower != nullptr) {
		return ERROR_BUSY ;
	}

	state_->campaignBorrower = borrower ;
	return ERROR_SUCCESS ;
}

/** @see local_collector_state_store.h */
void LocalCollectorStateStore::releaseCampaign( const void *borrower) noexcept
{
	// 他の借用者が所有するleaseを解除しない。
	if( state_->campaignBorrower == borrower) {
		state_->campaignBorrower = nullptr ;
	}
}

/** @see local_collector_state_store.h */
DWORD LocalCollectorStateStore::borrowWaitLedger( const void *borrower) noexcept
{
	// 書込み可能な監督storeだけに待機制御を結合する。
	if( borrower == nullptr || !isWritable()) {
		return ERROR_INVALID_PARAMETER ;
	}

	// 別instanceから単調時計の基準を上書きしない。
	if( state_->waitBorrower != nullptr) {
		return ERROR_BUSY ;
	}

	state_->waitBorrower = borrower ;
	return ERROR_SUCCESS ;
}

/** @see local_collector_state_store.h */
void LocalCollectorStateStore::releaseWaitLedger( const void *borrower) noexcept
{
	// 自分の借用だけを解除する。
	if( state_->waitBorrower == borrower) {
		state_->waitBorrower = nullptr ;
	}
}

} // namespace drivercrate
