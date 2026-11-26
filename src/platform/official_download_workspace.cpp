//------------------------------------------------------------------------------
/**
 * @file official_download_workspace.cpp
 * @brief 公式配布file用保護一時領域実装
 * @version 01.03.00
 * @date 2026/10/24
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Package階層fileの安全な作成を追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  失敗file破棄と空き容量照会を追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  SetupAPI展開fileの所有取込み追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  子要素の保護DACL継承／再適用
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記
 * Ver.01.01.00 Shunji Ogawa  2026/10/24  現行nested member identityと原record完全tupleへ整合
 * Ver.01.01.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.02.00 Shunji Ogawa  2026/11/12  本人検査領域とsetup限定の公開親metadata権限へ整合
 * Ver.01.02.01 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.02.02 Shunji Ogawa  2026/11/20  本人CAB展開の元ファイル照合を追加
 * Ver.01.03.00 Shunji Ogawa  2026/11/23  本人検査領域の原スナップショット照合を追加
 * </pre>
 *
 * @note OS由来のWindows Tempまたは本人LocalAppDataへ保護領域を新規作成し、CREATE_NEWまたは同期外部writerの検証済みfileだけを追跡します
 */
//------------------------------------------------------------------------------

#include "platform/official_download_workspace.h"

#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <new>
#include <memory>
#include <string>
#include <string_view>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義
//------------------------------------------------------------------------------

constexpr std::wstring_view WORKSPACE_DACL =
	L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" ;				// 子へ継承する保護DACL
constexpr std::uint32_t MAXIMUM_CREATION_ATTEMPTS		 = 32 ;		// 名前衝突時の有限な再試行上限
constexpr std::size_t	MAXIMUM_RELATIVE_PATH_CHARACTERS = 160 ;	// 相対pathの文字数上限
constexpr std::size_t	MAXIMUM_COMPONENT_CHARACTERS	 = 96 ;		// 一path要素の文字数上限

//------------------------------------------------------------------------------
// 内部型定義
//------------------------------------------------------------------------------

/** @brief 本人検査用の元handleから照会したファイルの識別情報です */
struct InspectionFileIdentity {
	/// ボリュームと128bitファイルIDです
	FILE_ID_INFO   file{} ;
	/// 読取りと照合の対象となるファイル全体の長さです
	ULARGE_INTEGER size{} ;
} ;

/**
 * @brief Workspace要素へ同一の保護DACLを渡すSECURITY_ATTRIBUTES所有者である
 */
class WorkspaceSecurityAttributes final {
public:
	/**
	 * @brief security descriptorを持たない未初期化のworkspace属性ownerを作成する
	 */
	WorkspaceSecurityAttributes() = default ;

	//------------------------------------------------------------------------------
	/**
     * @brief 所有するsecurity descriptorを解放する
     *
     * SDDL変換成功後のLocalAlloc領域を一度だけ解放する
     */
	//------------------------------------------------------------------------------
	~WorkspaceSecurityAttributes()
	{
		// 所有するsecurity descriptorがある場合だけ解放する
		if( descriptor_ != nullptr) {
			static_cast<void>( LocalFree( descriptor_)) ;
		}
	}

	/**
	 * @brief security descriptorの解放責務の二重管理を防ぐため、コピー構築を禁止する
	 */
	WorkspaceSecurityAttributes( const WorkspaceSecurityAttributes &) = delete ;
	/**
	 * @brief security descriptorの解放責務を別個体の状態で上書きさせないため、コピー代入を禁止する
	 */
	WorkspaceSecurityAttributes &operator=( const WorkspaceSecurityAttributes &) = delete ;
	/**
	 * @brief security descriptorの解放責務を元の属性ownerに留めるため、移動構築を禁止する
	 */
	WorkspaceSecurityAttributes( WorkspaceSecurityAttributes &&) = delete ;
	/**
	 * @brief 元の属性ownerへの結合を保つため、移動代入による管理状態の置換を禁止する
	 */
	WorkspaceSecurityAttributes &operator=( WorkspaceSecurityAttributes &&) = delete ;

	//------------------------------------------------------------------------------
	/**
	 * @brief 元用途と有効userへ結んだ保護SECURITY_ATTRIBUTESを初期化します
     *
     * 既定はSYSTEM/Administrators、本人検査は有効token user/SYSTEMの二ACEだけを許可します
     * @param[in] mode workspaceの元保護用途です
     * @param[in] expectedUser 空または元user SIDです。異なる有効userを拒否します
     * @return SDDL変換成功時は0、再初期化またはWin32失敗時はHRESULT
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] NativeError	 initialize( const OfficialWorkspaceMode mode,
											const std::wstring_view		expectedUser = {})
	{
		// 既に初期化したdescriptorの再初期化を拒否する
		if( descriptor_ != nullptr) {
			return static_cast<NativeError>( E_UNEXPECTED) ;
		}

		std::wstring descriptorText( WORKSPACE_DACL) ;	// 既定consumerのdescriptorを維持します
		// 本人検査だけが現在の有効token userへ所有を固定します
		if( mode == OfficialWorkspaceMode::CURRENT_USER_INSPECTION) {
			HANDLE rawToken{} ;	// workerの偽装tokenを優先し、別userへの切替も検出します
			// token不存在以外の照会失敗をprocess token fallbackで隠しません
			if( !OpenThreadToken( GetCurrentThread(), TOKEN_QUERY, TRUE, &rawToken)) {
				const DWORD error = GetLastError() ;	// 有効tokenの原失敗です
				// 通常workerはprocess tokenを使用します
				if( error != ERROR_NO_TOKEN ||
				   !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &rawToken)) {
					return HRESULT_FROM_WIN32( error == ERROR_NO_TOKEN ? GetLastError() : error) ;
				}
			}

			const std::unique_ptr<void, decltype( &CloseHandle)> token(
				rawToken, CloseHandle) ;	// token ownerです
			DWORD needed{} ;				// 有限のSID buffer必要量です
			GetTokenInformation( token.get(), TokenUser, nullptr, 0, &needed) ;
			// 不明・過大なtoken情報を採用しません
			if( needed == 0 || needed > 65536) {
				return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
			}

			std::vector<std::byte> bytes( needed) ;	// OS返却TOKEN_USERを所有します
			// 有効userを完全に取得した場合だけSDDLを組み立てます
			if( !GetTokenInformation( token.get(), TokenUser, bytes.data(), needed, &needed)) {
				return HRESULT_FROM_WIN32( GetLastError()) ;
			}

			LPWSTR text{} ;	// LocalFreeで回収するSID文字列です
			// Win32境界でTOKEN_USERを取得し、外部入力をSIDにしません
			if( !ConvertSidToStringSidW( reinterpret_cast<TOKEN_USER *>( bytes.data())->User.Sid,
									   &text)) {
				return HRESULT_FROM_WIN32( GetLastError()) ;
			}

			const std::unique_ptr<void, decltype( &LocalFree)> memory(
				text, LocalFree) ;	// SID文字列ownerです
			user_ = text ;
			// 元workspaceと異なるuserで子作成・取込みを許可しません
			if( !expectedUser.empty() && user_ != expectedUser) {
				return E_ACCESSDENIED ;
			}

			descriptorText = L"O:" + user_ + L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + user_ + L")" ;
		}
		// 定義外modeへ既定の管理者descriptorを流用しません
		else if( mode != OfficialWorkspaceMode::ADMINISTRATOR) {
			// 未定義の保護用途を拒否します
			return E_INVALIDARG ;
		}

		// 保護DACLを構築できなければworkspace用属性を公開しない
		if( ConvertStringSecurityDescriptorToSecurityDescriptorW(
			   descriptorText.c_str(), SDDL_REVISION_1, &descriptor_, nullptr) == FALSE) {
			return static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
		}

		attributes_.nLength				 = sizeof( attributes_) ;
		attributes_.lpSecurityDescriptor = descriptor_ ;
		attributes_.bInheritHandle		 = FALSE ;
		return 0 ;
	}

	/**
	 * @brief 本人検査用descriptorへ固定したuser SIDを借用します
	 * @return 次の初期化または破棄まで有効な内部文字列です。既定modeは空です
	 */
	[[nodiscard]] const std::wstring &user() const noexcept
	{
		return user_ ;
	}

	/**
	 * @brief 通常file/directoryの元owner・protected DACLを変更せず照合します
	 * @param[in] path 既知の絶対pathです
	 * @param[in] directory directoryならtrueです
	 * @param[in] inherited 同期外部writer直後の継承DACLだけを許可する場合trueです
	 * @param[in] expectedFile 元handleで照会したファイルの完全IDと長さです。比較しない場合はnullptrです
	 * @return 同本人/SYSTEMの二ACEだけなら0、OS失敗または不正はHRESULTです
	 */
	[[nodiscard]] NativeError verifyPath( const std::wstring &path, const bool directory,
										 const bool					   inherited	= false,
										 const InspectionFileIdentity *expectedFile = nullptr) const
	{
		const std::unique_ptr<void, decltype( &CloseHandle)> file(
			CreateFileW( path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
						FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
						FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr),
			CloseHandle) ;					// 同objectを固定します
		BY_HANDLE_FILE_INFORMATION info{} ;	// 最終objectの種別です
		// 不可読・reparse・異種objectは既知pathでも採用しません
		if( file.get() == INVALID_HANDLE_VALUE || !GetFileInformationByHandle( file.get(), &info)) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		// 同期writerの出力をlinkとして追跡しません
		if( (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
		   ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory) {
			return E_ACCESSDENIED ;
		}

		// 既知pathを元handleが指す一リンクのファイルへ結びます
		if( expectedFile != nullptr) {
			FILE_ID_INFO id{} ;	// 現在の同名ファイルの完全IDです
			// 完全IDを読み取れないファイルシステムでは元ファイルとの一致を確認できません
			if( !GetFileInformationByHandleEx( file.get(), FileIdInfo, &id, sizeof( id))) {
				return HRESULT_FROM_WIN32( GetLastError()) ;
			}

			// 元と異なるファイル、複数リンク、元handleの照会後に長さが変わったファイルを拒否します
			if( id.VolumeSerialNumber != expectedFile->file.VolumeSerialNumber ||
			   !std::ranges::equal( id.FileId.Identifier, expectedFile->file.FileId.Identifier) ||
			   info.nNumberOfLinks != 1 || info.nFileSizeHigh != expectedFile->size.HighPart ||
			   info.nFileSizeLow != expectedFile->size.LowPart) {
				return E_ACCESSDENIED ;
			}
		}

		PSECURITY_DESCRIPTOR raw{} ;	// GetSecurityInfoの一括返却領域です
		PSID				 owner{} ;	// descriptor内の借用ownerです
		PACL				 acl{} ;	// descriptor内の借用DACLです
		const DWORD			 error = GetSecurityInfo( file.get(), SE_FILE_OBJECT,
													 OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
													 &owner, nullptr, &acl, nullptr, &raw) ;	// 原OS結果です
		const std::unique_ptr<void, decltype( &LocalFree)> memory(
			raw, LocalFree) ;	// 原descriptor ownerです
		// 取得失敗を値検査失敗へ置換しません
		if( error != ERROR_SUCCESS) {
			return HRESULT_FROM_WIN32( error) ;
		}

		PSID						expected{} ;	// 自身のSDから元ownerを借用します
		BOOL						defaulted{} ;	// OS descriptor既定flagです
		SECURITY_DESCRIPTOR_CONTROL control{} ;		// 保護状態です
		DWORD						revision{} ;	// descriptor版です
		// 未知owner・NULL DACL・余分ACE・保護解除を拒否します
		if( !GetSecurityDescriptorOwner( descriptor_, &expected, &defaulted) || !owner || !acl ||
		   !EqualSid( owner, expected) || acl->AceCount != 2 ||
		   !GetSecurityDescriptorControl( raw, &control, &revision) ||
		   (!inherited && !(control & SE_DACL_PROTECTED))) {
			return E_ACCESSDENIED ;
		}

		PACL expectedAcl{} ;	// 元descriptorの二principalです
		BOOL present{} ;		// 元DACL存在flagです
		// 内部descriptorを解釈できない場合もfail closedです
		if( !GetSecurityDescriptorDacl( descriptor_, &present, &expectedAcl, &defaulted) ||
		   !present || !expectedAcl) {
			return E_ACCESSDENIED ;
		}

		// 二ACEは元順序・full mask・SIDと一致する必要があります
		for( DWORD at = 0; at < 2; ++at) {
			void *entry{} ;		// 実ACEです
			void *wanted{} ;	// 期待ACEです
			// 破損ACLを解釈して書込みを許可しません
			if( !GetAce( acl, at, &entry) || !GetAce( expectedAcl, at, &wanted)) {
				return E_ACCESSDENIED ;
			}

			const auto *ace =
				// Win32 ACE layoutです
				static_cast<const ACCESS_ALLOWED_ACE *>( entry) ;
			const auto *target =
				// 同型の内部ACEです
				static_cast<const ACCESS_ALLOWED_ACE *>( wanted) ;
			// writer継承時だけflagsを許容し、権限/principal追加は拒否します
			if( ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Mask != target->Mask ||
			   (!inherited && ace->Header.AceFlags != target->Header.AceFlags) ||
			   !EqualSid( const_cast<DWORD *>( &ace->SidStart),
						 const_cast<DWORD *>( &target->SidStart))) {
				return E_ACCESSDENIED ;
			}
		}

		return 0 ;
	}

	//------------------------------------------------------------------------------
	/**
     * @brief 初期化済みSECURITY_ATTRIBUTESを参照する
     *
     * 呼出し先Win32 APIの同期呼出し中だけ内部値を貸し出す
     * @return 初期化済みの場合は非所有pointer、未初期化時はnullptr
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] SECURITY_ATTRIBUTES *get() noexcept
	{
		return descriptor_ == nullptr ? nullptr : &attributes_ ;
	}

	//------------------------------------------------------------------------------
	/**
     * @brief 既存fileへ保護DACLを再適用する
     *
     * 継承ACEだけに依存せず、取込み前にfile自身のDACLを保護する
     *
     * @param[in] path 同期外部writerが作成した絶対file path
     * @return 保護DACL適用成功時は0、未初期化またはWin32失敗時はHRESULT
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] NativeError applyDaclToPath( const std::wstring_view path) noexcept
	{
		// descriptor欠落、空path、埋込NUL付きpathへDACLを適用しない
		if( descriptor_ == nullptr || path.empty() || path.find( L'\0') != std::wstring_view::npos) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		const std::wstring			   nativePath( path) ;	// SetFileSecurityW用のnull終端path
		constexpr SECURITY_INFORMATION SECURITY_INFORMATION =
			DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION ;	// 保護DACL適用範囲
		// 既存fileのDACL保護に失敗した場合は診断値を返す
		if( SetFileSecurityW( nativePath.c_str(), SECURITY_INFORMATION, descriptor_) == FALSE) {
			return static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
		}

		return 0 ;
	}

private:
	/// 本人検査modeで有効tokenから取得した元SIDです
	std::wstring		 user_ ;
	/// LocalFreeで解放する自己相対descriptor
	PSECURITY_DESCRIPTOR descriptor_{} ;
	/// Win32作成APIへ渡す非継承handle設定
	SECURITY_ATTRIBUTES	 attributes_{} ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをNativeErrorへ変換する
 *
 * 元のWin32診断値をProvider共通型へ保持する
 *
 * @param[in] error Win32 APIが返したerror code
 * @return HRESULT_FROM_WIN32で変換したbit pattern
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider tagが安全なdirectory名要素か検証する
 *
 * 外部入力によるpath traversalや別directory指定を拒否する
 *
 * @param[in] value Provider実装が指定する短い識別子
 * @return 1～24文字の小文字ASCII英数字またはhyphenだけなら`true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafeProviderTag( const std::wstring_view value) noexcept
{
	// 空または過大なProvider tagをdirectory名へ使わない
	if( value.empty() || value.size() > 24) {
		return false ;
	}

	// 全文字を検証し、path区切りやUnicode類似文字を許可しない
	for( const wchar_t character : value) {
		const bool lowercase = character >= L'a' && character <= L'z' ;	// 小文字ASCII判定
		const bool digit	 = character >= L'0' && character <= L'9' ;	// 数字ASCII判定
		// Provider tagを小文字ASCII、数字、hyphenへ制限する
		if( !lowercase && !digit && character != L'-') {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Path要素がWindowsの安全な通常名か検証する
 *
 * Control文字、Windows禁止文字、末尾dot／space、DOS device名を拒否する
 *
 * @param[in] value Separatorを含まない一つのpath要素
 * @return 許可するASCII通常名で予約device名でなければ`true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafePathComponent( const std::wstring_view value) noexcept
{
	// 空、過大、相対移動、末尾dot・空白のpath要素を拒否する
	if( value.empty() || value.size() > MAXIMUM_COMPONENT_CHARACTERS || value == L"." ||
	   value == L".." || value.back() == L'.' || value.back() == L' ') {
		return false ;
	}

	// Archive名は表示目的でなくfile作成に使うため、曖昧なUnicode表現を許可しない
	for( const wchar_t character : value) {
		// path要素に非ASCII、制御文字、Windows禁止文字を許容しない
		if( character < 0x20 || character > 0x7e ||
		   std::wstring_view( L"<>:\"/\\|?*").find( character) != std::wstring_view::npos) {
			return false ;
		}
	}

	std::wstring stem( value.substr( 0, value.find( L'.'))) ;	// 予約名判定用の拡張子なし名称
	std::transform( stem.begin(), stem.end(), stem.begin(), []( const wchar_t character) {
		return character >= L'a' && character <= L'z'
				   ? static_cast<wchar_t>( character - (L'a' - L'A'))
				   : character ;
	}) ;
	// Windows予約device名を通常file名として作成しない
	if( stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL") {
		return false ;
	}

	// COM1等の番号付き予約device名を拒否するための末尾数字条件
	const bool numberedDevice = stem.size() == 4 && stem[3] >= L'1' && stem[3] <= L'9' ;
	return !numberedDevice || (stem.substr( 0, 3) != L"COM" && stem.substr( 0, 3) != L"LPT") ;
}

//------------------------------------------------------------------------------
/**
 * @brief Workspace相対pathを検証する
 *
 * Absolute path、UNC、ADS、空要素、path traversalを拒否する
 *
 * @param[in] value 指定区切りだけで階層を表す相対member
 * @param[in] separator 明示したslashまたはbackslash
 * @return 全要素が安全で長さ上限内の場合は`true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafeRelativePath( const std::wstring_view value,
									  const wchar_t			  separator) noexcept
{
	// 空、過大、絶対形式、末尾区切り、不正separatorを持つ相対pathを拒否する
	if( (separator != L'/' && separator != L'\\') || value.empty() ||
	   value.size() > MAXIMUM_RELATIVE_PATH_CHARACTERS || value.front() == separator ||
	   value.back() == separator ||
	   value.find( separator == L'/' ? L'\\' : L'/') != std::wstring_view::npos) {
		return false ;
	}

	std::size_t beginning{} ;	// 現在検証するpath要素の開始位置
	// Separatorごとに全path要素を有限走査する
	while( beginning < value.size()) {
		const std::size_t next = value.find( separator, beginning) ;	// 次のseparator位置
		const std::size_t ending =
			// 要素終端位置
			next == std::wstring_view::npos ? value.size() : next ;
		// 相対pathの全要素を安全な通常名へ制限する
		if( !isSafePathComponent( value.substr( beginning, ending - beginning))) {
			return false ;
		}

		beginning = ending + 1 ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 大文字小文字を無視して既知pathを検索する
 *
 * 自身が作成したdirectoryだけをcaseに依存せず再利用し、未知の既存pathを受理しない
 *
 * @param[in] paths Workspaceが作成済みの絶対path群
 * @param[in] value 検索する絶対path
 * @return Windows ordinal比較で同じpathが存在する場合は`true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool containsPath( const std::vector<std::wstring> &paths,
								const std::wstring_view			 value) noexcept
{
	// Workspaceが作成した少数のpathだけを比較する
	for( const std::wstring &path : paths) {
		// 大小文字を除いて一致する既知pathだけを存在扱いにする
		if( CompareStringOrdinal( path.data(), static_cast<int>( path.size()), value.data(),
								static_cast<int>( value.size()), TRUE) == CSTR_EQUAL) {
			return true ;
		}
	}

	return false ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief nativeと公開identityに共通する安全なarchive member文法だけを検査します
 * @param[in] value 原ASCII相対member。全体160文字、要素96文字までです
 * @param[in] separator nativeはbackslash、公開identityはslashを明示します
 * @return 全要素が安全で指定以外の区切りを含まない場合だけtrueです
 * @note 正規化、filesystem path構築、I/O、取得/導入許可の発行を行いません
 */
//------------------------------------------------------------------------------
bool isSafeOfficialArchiveMember( const std::wstring_view value, const wchar_t separator) noexcept
{
	return isSafeRelativePath( value, separator) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 作成済みfileとdirectoryをbest-effortで削除する。自身が追跡する絶対pathだけを削除し、列挙や再帰削除は行わない
 */
//------------------------------------------------------------------------------
OfficialDownloadWorkspace::~OfficialDownloadWorkspace()
{
	// 本人検査modeで親が置換・変更された場合、既知名でも別領域へ削除を進めません
	if( mode_ == OfficialWorkspaceMode::CURRENT_USER_INSPECTION) {
		try {
			// 元token/保護/非reparseを再確認できた領域だけを回収します
			if( !directory_.empty() && verifyDirectories() != 0) {
				return ;
			}
		} catch( const std::bad_alloc &) {
			// best-effort cleanupの照合不能時は未知領域を保持します
			return ;
		}
	}

	// 外部writerが完了通知前に失敗した場合の既知pathだけを削除する
	for( auto file = pendingFiles_.rbegin(); file != pendingFiles_.rend(); ++file) {
		DeleteFileW( file->c_str()) ;
	}

	// 作成順の逆順で既知fileだけを削除する
	for( auto file = files_.rbegin(); file != files_.rend(); ++file) {
		DeleteFileW( file->c_str()) ;
	}

	// 子を先に除去できるよう、作成順の逆順で既知directoryだけを削除する
	for( auto directory = directories_.rbegin(); directory != directories_.rend(); ++directory) {
		RemoveDirectoryW( directory->c_str()) ;
	}

	// 自身のworkspace directoryを保持している場合だけ最後に削除する
	if( !directory_.empty()) {
		RemoveDirectoryW( directory_.c_str()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief OS由来の親配下へ用途別に保護された固有directoryを作成します
 * 既定はWindows TempのSYSTEM/Administrators、collector明示inspectionはLocalAppDataの本人/SYSTEMです
 * @param[in] providerTag 小文字ASCII英数字とhyphenだけのProvider識別子。 安全なProvider識別子
 * @param[in] scanSessionId 0ではないscan session ID
 * @param[in] mode worker内の保護用途です。JSONや任意pathから指定しません
 * @return 成功時は0、入力またはWin32処理失敗時はHRESULT bit pattern
 */
//------------------------------------------------------------------------------
NativeError OfficialDownloadWorkspace::initialize( const std::wstring_view	  providerTag,
												  const ScanSessionId		  scanSessionId,
												  const OfficialWorkspaceMode mode)
{
	// 多重初期化、不正tag、無効sessionでworkspaceを作らない
	if( !directory_.empty() || !isSafeProviderTag( providerTag) || scanSessionId == 0) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::wstring root ;	// OS KnownFolderまたは既定Windows Tempだけを使います
	// 本人検査は環境変数や任意の親rootを採用しません
	if( mode == OfficialWorkspaceMode::CURRENT_USER_INSPECTION) {
		PWSTR		  raw{} ;	// OSが確保する現在userのLocalAppDataです
		const HRESULT folderError = SHGetKnownFolderPath( FOLDERID_LocalAppData, KF_FLAG_DEFAULT,
														 nullptr, &raw) ;	// OS原結果です
		const std::unique_ptr<void, decltype( &CoTaskMemFree)> memory(
			raw, CoTaskMemFree) ;	// KnownFolder文字列ownerです
		// OSが返さない領域を推測して作成しません
		if( FAILED( folderError) || !raw) {
			return FAILED( folderError) ? folderError : E_UNEXPECTED ;
		}

		root = raw ;
		const DWORD attributes =
			// 親自体の通常directory属性です
			GetFileAttributesW( root.c_str()) ;
		// KnownFolder自体がreparseなら別の保護境界へ迂回しません
		if( attributes == INVALID_FILE_ATTRIBUTES) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		// 既知folderでも異種objectやreparseは拒否します
		if( !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
		   (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
			return E_ACCESSDENIED ;
		}
	}
	// 通常consumerだけを既存Windows Tempへ接続します
	else if( mode == OfficialWorkspaceMode::ADMINISTRATOR) {
		std::array<wchar_t, MAX_PATH> windowsDirectory{} ;	// Windows directory受信buffer
		const UINT					  characters = GetWindowsDirectoryW(
			   // 文字数
			   windowsDirectory.data(), static_cast<UINT>( windowsDirectory.size())) ;
		// Windows directoryを完全に取得できなければ保存先を推測しない
		if( characters == 0 || characters >= windowsDirectory.size()) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		root = std::wstring( windowsDirectory.data(), characters) + L"\\Temp" ;
	} else {
		return E_INVALIDARG ;
	} // 未定義modeから権限を推測しません

	WorkspaceSecurityAttributes security ;										// Rootへ適用する保護DACL所有者
	const NativeError			securityError = security.initialize( mode) ;	// 元用途のSDDL変換結果
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( securityError != 0) {
		return securityError ;
	}

	NativeError result = nativeErrorFromWin32( ERROR_FILE_EXISTS) ;	// 最終作成結果
	// PID、session、試行番号を組み合わせ、既存directoryを再利用しない
	for( std::uint32_t attempt = 0; attempt < MAXIMUM_CREATION_ATTEMPTS; ++attempt) {
		const std::wstring candidate = root + L"\\DriverCrate-" + std::wstring( providerTag) + L"-" +
									   std::to_wstring( GetCurrentProcessId()) + L"-" +
									   std::to_wstring( scanSessionId) + L"-" +
									   // 今回作成する絶対path
									   std::to_wstring( attempt) ;
		// 保護directoryの新規作成に成功した候補だけを所有する
		if( CreateDirectoryW( candidate.c_str(), security.get()) != FALSE) {
			directory_ = candidate ;
			mode_	   = mode ;
			userSid_   = security.user() ;
			// 本人modeは作成結果そのもののowner/DACLを確認します
			if( mode_ == OfficialWorkspaceMode::CURRENT_USER_INSPECTION) {
				result = security.verifyPath( directory_, true) ;
				// 不正な新規objectを既存rootとして採用しません
				if( result != 0) {
					RemoveDirectoryW( directory_.c_str()) ;
					directory_.clear() ;
					return result ;
				}
			}

			result = 0 ;
			break ;
		}

		const DWORD error = GetLastError() ;	// CreateDirectory失敗理由
		// 名前衝突以外の作成失敗では別名retryを続けない
		if( error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) {
			result = nativeErrorFromWin32( error) ;
			break ;
		}
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 作成時に固定した保護用途を返します
 * @return 未初期化時はADMINISTRATOR、初期化後は元modeです
 * @note 導入許可ではありません。導入境界はinspection用途を拒否します
 */
//------------------------------------------------------------------------------
OfficialWorkspaceMode OfficialDownloadWorkspace::protectionMode() const noexcept
{
	return mode_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 本人検査modeの既知rootと子directoryの所有・保護・非reparseを照合します
 * @return 既定modeまたは全照合成功は0、不正・元token変更・OS失敗はHRESULTです
 * @note 未知pathの採用やDACL修復を行いません
 */
//------------------------------------------------------------------------------
NativeError OfficialDownloadWorkspace::verifyDirectories() const
{
	// 既定consumerの保護契約を変更しません
	if( mode_ == OfficialWorkspaceMode::ADMINISTRATOR) {
		return 0 ;
	}

	WorkspaceSecurityAttributes security ;					// 元userに結んだ照合descriptorです
	auto error = security.initialize( mode_, userSid_) ;	// token変更も拒否します
	// 元rootが一致した場合だけ既知子を検査します
	if( error == 0) {
		error = security.verifyPath( directory_, true) ;
	}

	// 一致する既知directory以外のpathを通ってfileを作りません
	for( const auto &directory : directories_) {
		// 最初の拒否原因を保持します
		if( error != 0) {
			break ;
		}

		error = security.verifyPath( directory, true) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一時領域内へ検証済み相対pathの新規fileを作成する。親directoryとfileを自身で新規作成し、作成済みpathだけをcleanup対象へ登録する
 * @param[in] name `\\`で階層を区切る安全なASCII相対path。 Provider内部で指定する安全なASCII相対path
 * @param[out] handle 成功時に呼出し側がCloseHandleするread/write handle。 成功時に呼出し側がCloseHandleするhandle
 * @return 成功時は0、既存file、入力、Win32処理失敗時はHRESULT bit pattern
 */
//------------------------------------------------------------------------------
NativeError OfficialDownloadWorkspace::createFile( const std::wstring_view name, HANDLE &handle)
{
	return createFile( name, handle, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
					  FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既存の保護DACLで、今回作成するファイルだけを所有記録へ追加します
 * @param[in] name 領域内の検証済み相対path
 * @param[out] handle 新規ファイルの所有handle
 * @param[in] access 新規handleの要求アクセス
 * @param[in] sharing 新規handleの共有条件
 * @param[in] attributes 新規ファイルの属性と作成フラグ
 * @return 成功時は0、既存ファイルや作成失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError OfficialDownloadWorkspace::createFile( const std::wstring_view name, HANDLE &handle,
												  const DWORD access, const DWORD sharing,
												  const DWORD attributes)
{
	handle = INVALID_HANDLE_VALUE ;
	// workspace未初期化や不正な相対名ではfileを作らない
	if( directory_.empty() || !isSafeOfficialArchiveMember( name, L'\\')) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const auto directoryError = verifyDirectories() ;	// 既知親の置換を検出します
	// 不正な親から追加のfileを作りません
	if( directoryError != 0) {
		return directoryError ;
	}

	WorkspaceSecurityAttributes security ;	// 子directory／fileへ適用する保護DACL所有者
	const NativeError			securityError =
		// 元用途のSDDL変換結果
		security.initialize( mode_, userSid_) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( securityError != 0) {
		return securityError ;
	}

	const std::wstring file = path( name) ;	// CREATE_NEW対象絶対path
	// 保護領域内の絶対pathを解決できなければ作成しない
	if( file.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::size_t beginning{} ;	// 次に処理する相対path要素の開始位置
	// File名の手前にある親directoryをroot側から新規作成する
	while( true) {
		const std::size_t separator = name.find( L'\\', beginning) ;	// 次の階層separator
		// 最後の要素へ達したら親directoryの作成を終える
		if( separator == std::wstring_view::npos) {
			break ;
		}

		const std::wstring parent =
			directory_ + L"\\" + std::wstring( name.substr( 0, separator)) ;	// 親絶対path
		// 未追跡の親directoryだけを新規作成して所有記録へ追加する
		if( !containsPath( directories_, parent)) {
			// 保護親directoryを作れなければ子fileを作らない
			if( CreateDirectoryW( parent.c_str(), security.get()) == FALSE) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			try {
				directories_.push_back( parent) ;
			} catch( const std::bad_alloc &) {
				RemoveDirectoryW( parent.c_str()) ;
				return static_cast<NativeError>( E_OUTOFMEMORY) ;
			}
		}

		beginning = separator + 1 ;
	}

	handle =
		CreateFileW( file.c_str(), access, sharing, security.get(), CREATE_NEW, attributes, nullptr) ;
	// 新規fileを作れなければhandleを返さず診断値を保持する
	if( handle == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	try {
		files_.push_back( file) ;
	} catch( const std::bad_alloc &) {
		// 追跡できないfileを残さず、呼出し側へ所有権を渡す前に回収する
		CloseHandle( handle) ;
		handle = INVALID_HANDLE_VALUE ;
		DeleteFileW( file.c_str()) ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 本人検査領域のCAB出力を排他的に新規作成します
 * @param[in] name 検証済み相対path
 * @param[out] handle 展開中にファイルの削除を拒否する読取りhandle
 * @return 本人所有の新規ファイル作成に成功すれば0、既存ファイルやOS失敗はHRESULT
 * @note SetupAPIの書込みを共有し、展開後の同一性照合までhandleを保持します
 */
//------------------------------------------------------------------------------
NativeError OfficialDownloadWorkspace::createCabinetOutput( const std::wstring_view name,
														   HANDLE				  &handle)
{
	handle = INVALID_HANDLE_VALUE ;
	// 本人検査だけが元の所有者を明示したCAB出力を使います
	if( mode_ != OfficialWorkspaceMode::CURRENT_USER_INSPECTION) {
		return E_INVALIDARG ;
	}

	// ファイルデータの読取り権限で削除共有の制限を有効にします
	return createFile( name, handle, READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_DATA,
					  FILE_SHARE_READ | FILE_SHARE_WRITE,
					  FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_OPEN_REPARSE_POINT) ;
}

//------------------------------------------------------------------------------
/**
 * @brief CAB展開完了時のファイルを作成時の所有とidentityへ照合します
 * @param[in] name 元の検証済み相対path
 * @param[in] handle 削除共有を外して保持する元の読取りhandle
 * @param[in] expectedBytes 元CAB entryが宣言する正確な展開後サイズ
 * @return 同一ファイルの保護とサイズを確認した場合は0、それ以外はHRESULT
 */
//------------------------------------------------------------------------------
NativeError OfficialDownloadWorkspace::verifyCabinetOutput( const std::wstring_view name,
														   const HANDLE			   handle,
														   const std::uint64_t expectedBytes) const
{
	return verifyTrackedInspectionFile( name, handle, expectedBytes) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 本人検査領域で追跡済みの元ファイルが読取りスナップショットと一致するか照合します
 * 現在の有効user、既知rootと子directoryの保護、対象の非再解析・一リンク・完全ID・長さ・保護DACLを確認します
 * @param[in] name 元ファイルを登録した安全な相対pathです
 * @param[in] handle 最終pathを照合済みで、FILE_SHARE_READだけを許す読取りhandleです。呼出し側から借用します
 * @param[in] expectedBytes 元スナップショットの正確な非零byte数です
 * @return 一致時は0、別用途・不正入力・照合失敗時は対応するHRESULTです。Win32 APIの失敗は元の診断値を保持します
 * @pre 呼出し側が対象と全親の通常種別・最終pathを確認し、各handleを検査完了まで保持します
 * @note 所有worker内で直列に呼びます。handleの読取り位置、所有追跡、ファイルとACLは変更しません
 */
//------------------------------------------------------------------------------
NativeError OfficialDownloadWorkspace::verifyInspectionSnapshot(
	const std::wstring_view name, const HANDLE handle, const std::uint64_t expectedBytes) const
{
	// 空ファイルからは原バイトの検査証拠を作りません
	if( expectedBytes == 0U) {
		return E_INVALIDARG ;
	}

	return verifyTrackedInspectionFile( name, handle, expectedBytes) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 本人検査領域の追跡済みfileを借用handleの完全IDと保護に照合します
 * @param[in] name 追跡済みfileの安全な相対pathです
 * @param[in] handle 削除共有を外して保持している照合元handleです
 * @param[in] expectedBytes 期待する正確なbyte数です。CAB出力の空ファイルを含みます
 * @return 元の有効user、既知親、対象の一リンク・ID・長さ・所有と保護が一致すれば0、それ以外はHRESULTです
 * @note 借用handleの状態や追跡・保護を変更せず、同一worker内で呼びます
 */
//------------------------------------------------------------------------------
NativeError OfficialDownloadWorkspace::verifyTrackedInspectionFile(
	const std::wstring_view name, const HANDLE handle, const std::uint64_t expectedBytes) const
{
	const auto target = path( name) ;	// 追跡済み対象と照合する絶対pathです
	// 他用途や元領域に記録されていないファイルは照合対象にしません
	if( mode_ != OfficialWorkspaceMode::CURRENT_USER_INSPECTION || !handle ||
	   handle == INVALID_HANDLE_VALUE || !containsPath( files_, target)) {
		return E_INVALIDARG ;
	}

	BY_HANDLE_FILE_INFORMATION info{} ;		// 呼出し側が保持する元ファイルの情報です
	InspectionFileIdentity	   original{} ;	// 元ファイルの完全IDと長さです
	// 元handleを照会できない場合はWin32の失敗を保持して拒否します
	if( !GetFileInformationByHandle( handle, &info) ||
	   !GetFileInformationByHandleEx( handle, FileIdInfo, &original.file, sizeof( original.file))) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	original.size.LowPart  = info.nFileSizeLow ;
	original.size.HighPart = info.nFileSizeHigh ;
	// リンク、異種ファイル、長さの不一致、無効なファイルIDを拒否します
	if( (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
	   info.nNumberOfLinks != 1 || original.size.QuadPart != expectedBytes ||
	   std::ranges::all_of( original.file.FileId.Identifier,
						   []( BYTE value) { return value == 0U ; })) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const auto directoryError = verifyDirectories() ;	// 元の親と有効userを再照合します
	// 元の親を確認できなければ対象ファイルを受理しません
	if( directoryError != 0) {
		return directoryError ;
	}

	WorkspaceSecurityAttributes security ;						// 元本人用の保護照合descriptorです
	const auto error = security.initialize( mode_, userSid_) ;	// 元token userへの結合結果です
	return error != 0 ? error : security.verifyPath( target, false, false, &original) ;
}

//------------------------------------------------------------------------------
/**
 * @brief SetupAPIが新規fileを作成できる追跡付き非存在pathを準備する。外部writer用の追跡付き非存在file pathを準備する。CREATE_NEWで衝突を検出した後に
 *        空fileを削除し、同期展開を待つ
 * @param[in] name `\\`で階層を区切る安全なASCII相対path。 SetupAPIに作成を許可する安全な相対path
 * @param[out] outputPath 成功時にSetupAPIへ渡すworkspace内絶対path。 成功時のworkspace内絶対path
 * @return 親directory、非存在、cleanup追跡の準備成功時は0。 親directory作成、非存在確定、予約追跡の成功時は0
 * @note 同期の外部writerだけに使用し、完了時は`adoptFile`を呼ぶ
 */
//------------------------------------------------------------------------------
NativeError OfficialDownloadWorkspace::prepareExternalFile( const std::wstring_view name,
														   std::wstring			  &outputPath)
{
	outputPath.clear() ;
	HANDLE		file{INVALID_HANDLE_VALUE} ;		// 非存在確定と親directory作成に使用する一時handle
	NativeError error = createFile( name, file) ;	// CREATE_NEWによるpath衝突検査結果
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( error != 0) {
		return error ;
	}

	// 予約用fileを閉じられなければそのfileを破棄して失敗を返す
	if( CloseHandle( file) == FALSE) {
		error = nativeErrorFromWin32( GetLastError()) ;
		static_cast<void>( discardFile( name)) ;
		return error ;
	}

	error = discardFile( name) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( error != 0) {
		return error ;
	}

	const std::wstring target = path( name) ;	// 外部writerが新規作成する絶対path
	// 空または二重予約の出力先を外部writerへ渡さない
	if( target.empty() || containsPath( pendingFiles_, target)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		outputPath = target ;
		pendingFiles_.push_back( target) ;
	} catch( const std::bad_alloc &) {
		outputPath.clear() ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 自身が作成した既知fileを直ちに削除して追跡対象から除く。自身が作成した既知fileを直ちに削除する。追跡済み絶対pathだけを削除し、失敗時はdestructor用追跡を維持す
 *        る。呼出し側は事前に全handleを閉じる
 * @param[in] name `createFile`または`prepareExternalFile`の検証済み相対path。 作成済みまたは外部writer用の検証済み相対path
 * @return 削除成功時は0、未知pathまたはWin32処理失敗時はHRESULT bit pattern
 * @note 呼出し前に対象fileの全handleを閉じる。未作成の予約解除も成功とする
 */
//------------------------------------------------------------------------------
NativeError OfficialDownloadWorkspace::discardFile( const std::wstring_view name)
{
	const auto directoryError = verifyDirectories() ;	// 親の置換を経た別fileを削除しません
	// 元保護を確認できなければ追跡を残して拒否します
	if( directoryError != 0) {
		return directoryError ;
	}

	const std::wstring target = path( name) ;	// 削除候補へ変換したworkspace内絶対path
	// 削除対象をworkspace内へ解決できなければ拒否する
	if( target.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	auto found = files_.end() ;	// 大文字小文字を無視して一致した追跡entry
	// fileは現在照合するworkspace所有pathを指す
	for( auto file = files_.begin(); file != files_.end(); ++file) {
		// 作成済み追跡fileと一致するpathだけを削除対象へ選ぶ
		if( CompareStringOrdinal( file->data(), static_cast<int>( file->size()), target.data(),
								static_cast<int>( target.size()), TRUE) == CSTR_EQUAL) {
			found = file ;
			break ;
		}
	}

	// 作成済みの所有fileは削除後に追跡記録から外す
	if( found != files_.end()) {
		// 削除失敗時は所有記録を残して診断値を返す
		if( DeleteFileW( found->c_str()) == FALSE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		files_.erase( found) ;
		return 0 ;
	}

	auto pending = pendingFiles_.end() ;	// 同期外部writer用の予約entry
	// 予約済みpath群から同一の絶対pathを探す
	for( auto file = pendingFiles_.begin(); file != pendingFiles_.end(); ++file) {
		// 作成済み集合にない対象は予約済みpathとの一致を確認する
		if( CompareStringOrdinal( file->data(), static_cast<int>( file->size()), target.data(),
								static_cast<int>( target.size()), TRUE) == CSTR_EQUAL) {
			pending = file ;
			break ;
		}
	}

	// 作成済みでも予約済みでもないfileを削除しない
	if( pending == pendingFiles_.end()) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 予約pathの削除では未作成と実削除失敗を区別する
	if( DeleteFileW( pending->c_str()) == FALSE) {
		const DWORD error = GetLastError() ;	// 未作成の予約pathであるかの診断値
		// 不存在以外の削除失敗は予約記録を残して返す
		if( error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
			return nativeErrorFromWin32( error) ;
		}
	}

	pendingFiles_.erase( pending) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief SetupAPIがworkspace内に作成したfileを検証して所有へ取り込む。SetupAPIが作成したfileをworkspace所有へ取り込む。同期SetupAPI
 *        callback直後に通常fileとsizeを検証し、保護DACLを再適用する。失敗時は未追跡fileを削除する
 * @param[in] name `prepareExternalFile`で予約した安全な相対path。 事前に親directoryと非存在を固定した相対path
 * @param[in] expectedBytes SetupAPIがCAB entryで通知した展開後byte数。 CAB entryが通知した展開後byte数
 * @return 通常fileのsize検証とcleanup追跡への登録成功時は0。 通常file、sizeおよび所有追跡登録の成功時は0
 * @note 通常fileとsizeを検証し、保護DACLの再適用失敗時はfileを削除する
 */
//------------------------------------------------------------------------------
NativeError OfficialDownloadWorkspace::adoptFile( const std::wstring_view name,
												 const std::uint64_t	 expectedBytes)
{
	const std::wstring target  = path( name) ;			// SetupAPIが作成したworkspace内絶対path
	auto			   pending = pendingFiles_.end() ;	// 取込み対象の予約entry
	// 解決可能な出力pathだけを予約集合へ照合する
	if( !target.empty()) {
		// 予約済みpathだけを同期外部writerの完了fileとして受理する
		for( auto file = pendingFiles_.begin(); file != pendingFiles_.end(); ++file) {
			// 予約pathと一致する外部writer出力だけを取り込み対象にする
			if( CompareStringOrdinal( file->data(), static_cast<int>( file->size()), target.data(),
									static_cast<int>( target.size()), TRUE) == CSTR_EQUAL) {
				pending = file ;
				break ;
			}
		}
	}

	// 未知予約、空path、既存所有fileの二重取り込みを拒否する
	if( target.empty() || pending == pendingFiles_.end() || containsPath( files_, target)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	WIN32_FILE_ATTRIBUTE_DATA attributes{} ;	// 展開fileの種類と64-bit size
	// 外部生成fileの属性取得失敗時は出力と予約を破棄する
	if( GetFileAttributesExW( target.c_str(), GetFileExInfoStandard, &attributes) == FALSE) {
		const NativeError error = nativeErrorFromWin32( GetLastError()) ;	// 完了file照会失敗
		DeleteFileW( target.c_str()) ;
		pendingFiles_.erase( pending) ;
		return error ;
	}

	// 通常file以外の外部出力をworkspace所有へ取り込まない
	if( (attributes.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
	   0) {
		DeleteFileW( target.c_str()) ;
		pendingFiles_.erase( pending) ;
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	ULARGE_INTEGER size{} ;	// HighとLowを結合した展開後file byte数
	size.LowPart  = attributes.nFileSizeLow ;
	size.HighPart = attributes.nFileSizeHigh ;
	// 期待byte数と異なる外部出力を破棄する
	if( size.QuadPart != expectedBytes) {
		DeleteFileW( target.c_str()) ;
		pendingFiles_.erase( pending) ;
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	WorkspaceSecurityAttributes security ;				// 外部生成fileへ再適用する保護DACL所有者
	NativeError securityError = verifyDirectories() ;	// 元親の保護が変われば取込みません
	// 元用途のdescriptorを用意します
	if( securityError == 0) {
		securityError = security.initialize( mode_, userSid_) ;
	}

	// 外部writerの元owner/二principal以外をDACL修復で隠しません
	if( securityError == 0 && mode_ == OfficialWorkspaceMode::CURRENT_USER_INSPECTION) {
		securityError = security.verifyPath( target, false, true) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない
	if( securityError == 0) {
		// File自身のDACL保護結果
		securityError = security.applyDaclToPath( target) ;
	}

	// 保護DACLを固定できない外部出力を破棄する
	if( securityError != 0) {
		// 保護DACLを固定できない外部生成fileはworkspace所有へ取り込まない
		DeleteFileW( target.c_str()) ;
		pendingFiles_.erase( pending) ;
		return securityError ;
	}

	try {
		files_.push_back( target) ;
	} catch( const std::bad_alloc &) {
		// Cleanup追跡できないfileを保護workspaceに残さない
		DeleteFileW( target.c_str()) ;
		pendingFiles_.erase( pending) ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	pendingFiles_.erase( pending) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Workspaceを置くvolumeで呼出しprocessが利用可能なbyte数を取得する。Workspace volumeの利用可能byte数を取得する。Workspaceと同じ
 *        volumeを対象とし、quotaを反映した値を返す
 * @param[out] availableBytes 成功時の利用可能byte数。失敗時は0。 成功時に呼出しprocessが利用可能なbyte数。失敗時は0
 * @return 取得成功時は0、未初期化またはWin32処理失敗時はHRESULT bit pattern
 */
//------------------------------------------------------------------------------
NativeError OfficialDownloadWorkspace::queryAvailableBytes(
	std::uint64_t &availableBytes) const noexcept
{
	availableBytes = 0U ;
	// workspace未初期化時に別volumeの空き容量を返さない
	if( directory_.empty()) {
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}

	ULARGE_INTEGER available{} ;	// 呼出しprocessがvolume上で利用できるbyte数
	// workspace volumeの空き容量取得失敗を診断値付きで返す
	if( GetDiskFreeSpaceExW( directory_.c_str(), &available, nullptr, nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	availableBytes = available.QuadPart ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 作成済み一時領域内の検証済み相対pathを絶対pathへ変換する。作成済みかどうかは判定せず、directory境界だけを保証する
 * @param[in] name `\\`で階層を区切る安全なASCII相対path。 Provider内部で指定する安全なASCII相対path
 * @return 有効な入力なら絶対path、それ以外は空文字列。 入力有効時は絶対path、それ以外は空文字列
 */
//------------------------------------------------------------------------------
std::wstring OfficialDownloadWorkspace::path( const std::wstring_view name) const
{
	// 未初期化または不正相対名から絶対pathを生成しない
	if( directory_.empty() || !isSafeOfficialArchiveMember( name, L'\\')) {
		return {} ;
	}

	const std::wstring result = directory_ + L"\\" + std::wstring( name) ;	// 変換後絶対path
	return result.size() < MAX_PATH ? result : std::wstring{} ;
}

} // namespace drivercrate
