//------------------------------------------------------------------------------
/**
 * @file official_download_workspace.cpp
 * @brief 公式配布file用保護一時領域実装。
 * @version 01.01.00
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Package階層fileの安全な作成を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  失敗file破棄と空き容量照会を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  SetupAPI展開fileの所有取込み追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  子要素の保護DACL継承／再適用。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * Ver.01.01.00 Shunji Ogawa  2026/10/24  現行nested member identityと原record完全tupleへ整合。
 * </pre>
 *
 * @note Windows Temp配下へ保護directoryを作成し、CREATE_NEW済みfileと同期SetupAPIが作成した検証済みfileだけを追跡します。
 */
//------------------------------------------------------------------------------

#include "platform/official_download_workspace.h"

#include <sddl.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <new>
#include <string>
#include <string_view>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view WORKSPACE_DACL =
	L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" ;						// 子へ継承する保護DACL。
constexpr std::uint32_t			  MAXIMUM_CREATION_ATTEMPTS = 32 ;			// 名前衝突時の有限な再試行上限。
constexpr std::size_t			  MAXIMUM_RELATIVE_PATH_CHARACTERS = 160 ;	// 相対pathの文字数上限。
constexpr std::size_t			  MAXIMUM_COMPONENT_CHARACTERS	   = 96 ;	// 一path要素の文字数上限。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief Workspace要素へ同一の保護DACLを渡すSECURITY_ATTRIBUTES所有者である。
 */
class WorkspaceSecurityAttributes final {
public:
	/**
	 * @brief security descriptorを持たない未初期化のworkspace属性ownerを作成する。
	 */
	WorkspaceSecurityAttributes() = default ;

	//------------------------------------------------------------------------------
	/**
     * @brief 所有するsecurity descriptorを解放する。
     *
     * SDDL変換成功後のLocalAlloc領域を一度だけ解放する。
     */
	//------------------------------------------------------------------------------
	~WorkspaceSecurityAttributes()
	{
		// 所有するsecurity descriptorがある場合だけ解放する。
		if( descriptor_ != nullptr) {
			static_cast<void>( LocalFree( descriptor_)) ;
		}
	}

	/**
	 * @brief security descriptorの解放責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	WorkspaceSecurityAttributes( const WorkspaceSecurityAttributes &) = delete ;
	/**
	 * @brief security descriptorの解放責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	WorkspaceSecurityAttributes &operator=( const WorkspaceSecurityAttributes &) = delete ;
	/**
	 * @brief security descriptorの解放責務を元の属性ownerに留めるため、移動構築を禁止する。
	 */
	WorkspaceSecurityAttributes( WorkspaceSecurityAttributes &&) = delete ;
	/**
	 * @brief 元の属性ownerへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	WorkspaceSecurityAttributes &operator=( WorkspaceSecurityAttributes &&) = delete ;

	//------------------------------------------------------------------------------
	/**
     * @brief 保護DACL付きSECURITY_ATTRIBUTESを初期化する。
     *
     * SYSTEM／Administratorsだけへfull accessを許可し、子へ同じACEを継承させる。
     * @return SDDL変換成功時は0、再初期化またはWin32失敗時はHRESULT。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] NativeError	 initialize() noexcept
	{
		// 既に初期化したdescriptorの再初期化を拒否する。
		if( descriptor_ != nullptr) {
			return static_cast<NativeError>( E_UNEXPECTED) ;
		}

		// 保護DACLを構築できなければworkspace用属性を公開しない。
		if( ConvertStringSecurityDescriptorToSecurityDescriptorW(
			   WORKSPACE_DACL.data(), SDDL_REVISION_1, &descriptor_, nullptr) == FALSE) {
			return static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
		}

		attributes_.nLength				 = sizeof( attributes_) ;
		attributes_.lpSecurityDescriptor = descriptor_ ;
		attributes_.bInheritHandle		 = FALSE ;
		return 0 ;
	}

	//------------------------------------------------------------------------------
	/**
     * @brief 初期化済みSECURITY_ATTRIBUTESを参照する。
     *
     * 呼出し先Win32 APIの同期呼出し中だけ内部値を貸し出す。
     * @return 初期化済みの場合は非所有pointer、未初期化時はnullptr。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] SECURITY_ATTRIBUTES *get() noexcept
	{
		return descriptor_ == nullptr ? nullptr : &attributes_ ;
	}

	//------------------------------------------------------------------------------
	/**
     * @brief 既存fileへ保護DACLを再適用する。
     *
     * 継承ACEだけに依存せず、取込み前にfile自身のDACLを保護する。
     *
     * @param[in] path 同期外部writerが作成した絶対file path。
     * @return 保護DACL適用成功時は0、未初期化またはWin32失敗時はHRESULT。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] NativeError applyDaclToPath( const std::wstring_view path) noexcept
	{
		// descriptor欠落、空path、埋込NUL付きpathへDACLを適用しない。
		if( descriptor_ == nullptr || path.empty() || path.find( L'\0') != std::wstring_view::npos) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		const std::wstring			   nativePath( path) ;	// SetFileSecurityW用のnull終端path。
		constexpr SECURITY_INFORMATION SECURITY_INFORMATION =
			DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION ;	// 保護DACL適用範囲。
		// 既存fileのDACL保護に失敗した場合は診断値を返す。
		if( SetFileSecurityW( nativePath.c_str(), SECURITY_INFORMATION, descriptor_) == FALSE) {
			return static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
		}

		return 0 ;
	}

private:
	/// LocalFreeで解放する自己相対descriptor。
	PSECURITY_DESCRIPTOR descriptor_{} ;
	/// Win32作成APIへ渡す非継承handle設定。
	SECURITY_ATTRIBUTES	 attributes_{} ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをNativeErrorへ変換する。
 *
 * 元のWin32診断値をProvider共通型へ保持する。
 *
 * @param[in] error Win32 APIが返したerror code。
 * @return HRESULT_FROM_WIN32で変換したbit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider tagが安全なdirectory名要素か検証する。
 *
 * 外部入力によるpath traversalや別directory指定を拒否する。
 *
 * @param[in] value Provider実装が指定する短い識別子。
 * @return 1～24文字の小文字ASCII英数字またはhyphenだけなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafeProviderTag( const std::wstring_view value) noexcept
{
	// 空または過大なProvider tagをdirectory名へ使わない。
	if( value.empty() || value.size() > 24) {
		return false ;
	}

	// 全文字を検証し、path区切りやUnicode類似文字を許可しない。
	for( const wchar_t character : value) {
		const bool lowercase = character >= L'a' && character <= L'z' ;	// 小文字ASCII判定。
		const bool digit	 = character >= L'0' && character <= L'9' ;	// 数字ASCII判定。
		// Provider tagを小文字ASCII、数字、hyphenへ制限する。
		if( !lowercase && !digit && character != L'-') {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Path要素がWindowsの安全な通常名か検証する。
 *
 * Control文字、Windows禁止文字、末尾dot／space、DOS device名を拒否する。
 *
 * @param[in] value Separatorを含まない一つのpath要素。
 * @return 許可するASCII通常名で予約device名でなければ`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafePathComponent( const std::wstring_view value) noexcept
{
	// 空、過大、相対移動、末尾dot・空白のpath要素を拒否する。
	if( value.empty() || value.size() > MAXIMUM_COMPONENT_CHARACTERS || value == L"." ||
	   value == L".." || value.back() == L'.' || value.back() == L' ') {
		return false ;
	}

	// Archive名は表示目的でなくfile作成に使うため、曖昧なUnicode表現を許可しない。
	for( const wchar_t character : value) {
		// path要素に非ASCII、制御文字、Windows禁止文字を許容しない。
		if( character < 0x20 || character > 0x7e ||
		   std::wstring_view( L"<>:\"/\\|?*").find( character) != std::wstring_view::npos) {
			return false ;
		}
	}

	std::wstring stem( value.substr( 0, value.find( L'.'))) ;	// 予約名判定用の拡張子なし名称。
	std::transform( stem.begin(), stem.end(), stem.begin(), []( const wchar_t character) {
		return character >= L'a' && character <= L'z'
				   ? static_cast<wchar_t>( character - (L'a' - L'A'))
				   : character ;
	}) ;
	// Windows予約device名を通常file名として作成しない。
	if( stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL") {
		return false ;
	}

	// COM1等の番号付き予約device名を拒否するための末尾数字条件。
	const bool numberedDevice = stem.size() == 4 && stem[3] >= L'1' && stem[3] <= L'9' ;
	return !numberedDevice || (stem.substr( 0, 3) != L"COM" && stem.substr( 0, 3) != L"LPT") ;
}

//------------------------------------------------------------------------------
/**
 * @brief Workspace相対pathを検証する。
 *
 * Absolute path、UNC、ADS、空要素、path traversalを拒否する。
 *
 * @param[in] value 指定区切りだけで階層を表す相対member。
 * @param[in] separator 明示したslashまたはbackslash。
 * @return 全要素が安全で長さ上限内の場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafeRelativePath( const std::wstring_view value,
									  const wchar_t			  separator) noexcept
{
	// 空、過大、絶対形式、末尾区切り、不正separatorを持つ相対pathを拒否する。
	if( (separator != L'/' && separator != L'\\') || value.empty() ||
	   value.size() > MAXIMUM_RELATIVE_PATH_CHARACTERS || value.front() == separator ||
	   value.back() == separator ||
	   value.find( separator == L'/' ? L'\\' : L'/') != std::wstring_view::npos) {
		return false ;
	}

	std::size_t beginning{} ;	// 現在検証するpath要素の開始位置。
	// Separatorごとに全path要素を有限走査する。
	while( beginning < value.size()) {
		const std::size_t next = value.find( separator, beginning) ;	// 次のseparator位置。
		const std::size_t ending =
			// 要素終端位置。
			next == std::wstring_view::npos ? value.size() : next ;
		// 相対pathの全要素を安全な通常名へ制限する。
		if( !isSafePathComponent( value.substr( beginning, ending - beginning))) {
			return false ;
		}

		beginning = ending + 1 ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 大文字小文字を無視して既知pathを検索する。
 *
 * 自身が作成したdirectoryだけをcaseに依存せず再利用し、未知の既存pathを受理しない。
 *
 * @param[in] paths Workspaceが作成済みの絶対path群。
 * @param[in] value 検索する絶対path。
 * @return Windows ordinal比較で同じpathが存在する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool containsPath( const std::vector<std::wstring> &paths,
								const std::wstring_view			 value) noexcept
{
	// Workspaceが作成した少数のpathだけを比較する。
	for( const std::wstring &path : paths) {
		// 大小文字を除いて一致する既知pathだけを存在扱いにする。
		if( CompareStringOrdinal( path.data(), static_cast<int>( path.size()), value.data(),
								static_cast<int>( value.size()), TRUE) == CSTR_EQUAL) {
			return true ;
		}
	}

	return false ;
}

} // namespace

/** @see official_download_workspace.h */
bool isSafeOfficialArchiveMember( const std::wstring_view value, const wchar_t separator) noexcept
{
	return isSafeRelativePath( value, separator) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_workspace.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialDownloadWorkspace::~OfficialDownloadWorkspace()
{
	// 外部writerが完了通知前に失敗した場合の既知pathだけを削除する。
	for( auto file = pendingFiles_.rbegin(); file != pendingFiles_.rend(); ++file) {
		DeleteFileW( file->c_str()) ;
	}

	// 作成順の逆順で既知fileだけを削除する。
	for( auto file = files_.rbegin(); file != files_.rend(); ++file) {
		DeleteFileW( file->c_str()) ;
	}

	// 子を先に除去できるよう、作成順の逆順で既知directoryだけを削除する。
	for( auto directory = directories_.rbegin(); directory != directories_.rend(); ++directory) {
		RemoveDirectoryW( directory->c_str()) ;
	}

	// 自身のworkspace directoryを保持している場合だけ最後に削除する。
	if( !directory_.empty()) {
		RemoveDirectoryW( directory_.c_str()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_workspace.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialDownloadWorkspace::initialize( const std::wstring_view providerTag,
												  const ScanSessionId	  scanSessionId)
{
	// 多重初期化、不正tag、無効sessionでworkspaceを作らない。
	if( !directory_.empty() || !isSafeProviderTag( providerTag) || scanSessionId == 0) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::array<wchar_t, MAX_PATH> windowsDirectory{} ;	// Windows directory受信buffer。
	const UINT					  characters = GetWindowsDirectoryW(
		   // 文字数。
		   windowsDirectory.data(), static_cast<UINT>( windowsDirectory.size())) ;
	// Windows directoryを完全に取得できなければ保存先を推測しない。
	if( characters == 0 || characters >= windowsDirectory.size()) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	WorkspaceSecurityAttributes security ;								// Rootへ適用する保護DACL所有者。
	const NativeError			securityError = security.initialize() ;	// SDDL変換結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( securityError != 0) {
		return securityError ;
	}

	NativeError		   result = nativeErrorFromWin32( ERROR_FILE_EXISTS) ;	// 最終作成結果。
	const std::wstring root =
		// 一時領域root。
		std::wstring( windowsDirectory.data(), characters) + L"\\Temp" ;
	// PID、session、試行番号を組み合わせ、既存directoryを再利用しない。
	for( std::uint32_t attempt = 0; attempt < MAXIMUM_CREATION_ATTEMPTS; ++attempt) {
		const std::wstring candidate = root + L"\\DriverCrate-" + std::wstring( providerTag) + L"-" +
									   std::to_wstring( GetCurrentProcessId()) + L"-" +
									   std::to_wstring( scanSessionId) + L"-" +
									   // 今回作成する絶対path。
									   std::to_wstring( attempt) ;
		// 保護directoryの新規作成に成功した候補だけを所有する。
		if( CreateDirectoryW( candidate.c_str(), security.get()) != FALSE) {
			directory_ = candidate ;
			result	   = 0 ;
			break ;
		}

		const DWORD error = GetLastError() ;	// CreateDirectory失敗理由。
		// 名前衝突以外の作成失敗では別名retryを続けない。
		if( error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) {
			result = nativeErrorFromWin32( error) ;
			break ;
		}
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_workspace.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialDownloadWorkspace::createFile( const std::wstring_view name, HANDLE &handle)
{
	handle = INVALID_HANDLE_VALUE ;
	// workspace未初期化や不正な相対名ではfileを作らない。
	if( directory_.empty() || !isSafeOfficialArchiveMember( name, L'\\')) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	WorkspaceSecurityAttributes security ;								// 子directory／fileへ適用する保護DACL所有者。
	const NativeError			securityError = security.initialize() ;	// SDDL変換結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( securityError != 0) {
		return securityError ;
	}

	const std::wstring file = path( name) ;	// CREATE_NEW対象絶対path。
	// 保護領域内の絶対pathを解決できなければ作成しない。
	if( file.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::size_t beginning{} ;	// 次に処理する相対path要素の開始位置。
	// File名の手前にある親directoryをroot側から新規作成する。
	while( true) {
		const std::size_t separator = name.find( L'\\', beginning) ;	// 次の階層separator。
		// 最後の要素へ達したら親directoryの作成を終える。
		if( separator == std::wstring_view::npos) {
			break ;
		}

		const std::wstring parent =
			directory_ + L"\\" + std::wstring( name.substr( 0, separator)) ;	// 親絶対path。
		// 未追跡の親directoryだけを新規作成して所有記録へ追加する。
		if( !containsPath( directories_, parent)) {
			// 保護親directoryを作れなければ子fileを作らない。
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
		CreateFileW( file.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, security.get(),
					CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN, nullptr) ;
	// 新規fileを作れなければhandleを返さず診断値を保持する。
	if( handle == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	try {
		files_.push_back( file) ;
	} catch( const std::bad_alloc &) {
		// 追跡できないfileを残さず、呼出し側へ所有権を渡す前に回収する。
		CloseHandle( handle) ;
		handle = INVALID_HANDLE_VALUE ;
		DeleteFileW( file.c_str()) ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_workspace.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialDownloadWorkspace::prepareExternalFile( const std::wstring_view name,
														   std::wstring			  &outputPath)
{
	outputPath.clear() ;
	HANDLE		file{INVALID_HANDLE_VALUE} ;		// 非存在確定と親directory作成に使用する一時handle。
	NativeError error = createFile( name, file) ;	// CREATE_NEWによるpath衝突検査結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	// 予約用fileを閉じられなければそのfileを破棄して失敗を返す。
	if( CloseHandle( file) == FALSE) {
		error = nativeErrorFromWin32( GetLastError()) ;
		static_cast<void>( discardFile( name)) ;
		return error ;
	}

	error = discardFile( name) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	const std::wstring target = path( name) ;	// 外部writerが新規作成する絶対path。
	// 空または二重予約の出力先を外部writerへ渡さない。
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
 * @see src/platform/official_download_workspace.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialDownloadWorkspace::discardFile( const std::wstring_view name)
{
	const std::wstring target = path( name) ;	// 削除候補へ変換したworkspace内絶対path。
	// 削除対象をworkspace内へ解決できなければ拒否する。
	if( target.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	auto found = files_.end() ;	// 大文字小文字を無視して一致した追跡entry。
	// fileは現在照合するworkspace所有pathを指す。
	for( auto file = files_.begin(); file != files_.end(); ++file) {
		// 作成済み追跡fileと一致するpathだけを削除対象へ選ぶ。
		if( CompareStringOrdinal( file->data(), static_cast<int>( file->size()), target.data(),
								static_cast<int>( target.size()), TRUE) == CSTR_EQUAL) {
			found = file ;
			break ;
		}
	}

	// 作成済みの所有fileは削除後に追跡記録から外す。
	if( found != files_.end()) {
		// 削除失敗時は所有記録を残して診断値を返す。
		if( DeleteFileW( found->c_str()) == FALSE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		files_.erase( found) ;
		return 0 ;
	}

	auto pending = pendingFiles_.end() ;	// 同期外部writer用の予約entry。
	// 予約済みpath群から同一の絶対pathを探す。
	for( auto file = pendingFiles_.begin(); file != pendingFiles_.end(); ++file) {
		// 作成済み集合にない対象は予約済みpathとの一致を確認する。
		if( CompareStringOrdinal( file->data(), static_cast<int>( file->size()), target.data(),
								static_cast<int>( target.size()), TRUE) == CSTR_EQUAL) {
			pending = file ;
			break ;
		}
	}

	// 作成済みでも予約済みでもないfileを削除しない。
	if( pending == pendingFiles_.end()) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 予約pathの削除では未作成と実削除失敗を区別する。
	if( DeleteFileW( pending->c_str()) == FALSE) {
		const DWORD error = GetLastError() ;	// 未作成の予約pathであるかの診断値。
		// 不存在以外の削除失敗は予約記録を残して返す。
		if( error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
			return nativeErrorFromWin32( error) ;
		}
	}

	pendingFiles_.erase( pending) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_workspace.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialDownloadWorkspace::adoptFile( const std::wstring_view name,
												 const std::uint64_t	 expectedBytes)
{
	const std::wstring target  = path( name) ;			// SetupAPIが作成したworkspace内絶対path。
	auto			   pending = pendingFiles_.end() ;	// 取込み対象の予約entry。
	// 解決可能な出力pathだけを予約集合へ照合する。
	if( !target.empty()) {
		// 予約済みpathだけを同期外部writerの完了fileとして受理する。
		for( auto file = pendingFiles_.begin(); file != pendingFiles_.end(); ++file) {
			// 予約pathと一致する外部writer出力だけを取り込み対象にする。
			if( CompareStringOrdinal( file->data(), static_cast<int>( file->size()), target.data(),
									static_cast<int>( target.size()), TRUE) == CSTR_EQUAL) {
				pending = file ;
				break ;
			}
		}
	}

	// 未知予約、空path、既存所有fileの二重取り込みを拒否する。
	if( target.empty() || pending == pendingFiles_.end() || containsPath( files_, target)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	WIN32_FILE_ATTRIBUTE_DATA attributes{} ;	// 展開fileの種類と64-bit size。
	// 外部生成fileの属性取得失敗時は出力と予約を破棄する。
	if( GetFileAttributesExW( target.c_str(), GetFileExInfoStandard, &attributes) == FALSE) {
		const NativeError error = nativeErrorFromWin32( GetLastError()) ;	// 完了file照会失敗。
		DeleteFileW( target.c_str()) ;
		pendingFiles_.erase( pending) ;
		return error ;
	}

	// 通常file以外の外部出力をworkspace所有へ取り込まない。
	if( (attributes.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
	   0) {
		DeleteFileW( target.c_str()) ;
		pendingFiles_.erase( pending) ;
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	ULARGE_INTEGER size{} ;	// HighとLowを結合した展開後file byte数。
	size.LowPart  = attributes.nFileSizeLow ;
	size.HighPart = attributes.nFileSizeHigh ;
	// 期待byte数と異なる外部出力を破棄する。
	if( size.QuadPart != expectedBytes) {
		DeleteFileW( target.c_str()) ;
		pendingFiles_.erase( pending) ;
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	WorkspaceSecurityAttributes security ;				// 外部生成fileへ再適用する保護DACL所有者。
	NativeError securityError = security.initialize() ;	// Security descriptor初期化結果。
	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( securityError == 0) {
		// File自身のDACL保護結果。
		securityError = security.applyDaclToPath( target) ;
	}

	// 保護DACLを固定できない外部出力を破棄する。
	if( securityError != 0) {
		// 保護DACLを固定できない外部生成fileはworkspace所有へ取り込まない。
		DeleteFileW( target.c_str()) ;
		pendingFiles_.erase( pending) ;
		return securityError ;
	}

	try {
		files_.push_back( target) ;
	} catch( const std::bad_alloc &) {
		// Cleanup追跡できないfileを保護workspaceに残さない。
		DeleteFileW( target.c_str()) ;
		pendingFiles_.erase( pending) ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	pendingFiles_.erase( pending) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_workspace.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialDownloadWorkspace::queryAvailableBytes(
	std::uint64_t &availableBytes) const noexcept
{
	availableBytes = 0U ;
	// workspace未初期化時に別volumeの空き容量を返さない。
	if( directory_.empty()) {
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}

	ULARGE_INTEGER available{} ;	// 呼出しprocessがvolume上で利用できるbyte数。
	// workspace volumeの空き容量取得失敗を診断値付きで返す。
	if( GetDiskFreeSpaceExW( directory_.c_str(), &available, nullptr, nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	availableBytes = available.QuadPart ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_workspace.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::wstring OfficialDownloadWorkspace::path( const std::wstring_view name) const
{
	// 未初期化または不正相対名から絶対pathを生成しない。
	if( directory_.empty() || !isSafeOfficialArchiveMember( name, L'\\')) {
		return {} ;
	}

	const std::wstring result = directory_ + L"\\" + std::wstring( name) ;	// 変換後絶対path。
	return result.size() < MAX_PATH ? result : std::wstring{} ;
}

} // namespace drivercrate
