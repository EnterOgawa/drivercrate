//------------------------------------------------------------------------------
/**
 * @file registered_driver_store_package_internal.cpp
 * @brief 現用INFに対応するDriver Store内の元パッケージを固定する
 * @version 01.16.00
 * @date 2026/11/19
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/19  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/22  登録済みストレージの選択節と元署名の読取り証拠を追加
 * Ver.01.02.00 Shunji Ogawa  2026/11/22  全現用登録からストレージ補助サービスの共有先を照合
 * Ver.01.03.00 Shunji Ogawa  2026/11/23  自動起動補助の署名付き元登録を読取り
 * Ver.01.04.00 Shunji Ogawa  2026/11/23  署名付き元登録から補助とイベントの現在観測を取得
 * Ver.01.05.00 Shunji Ogawa  2026/11/23  自動起動補助の署名付き元選択から電源定義を保持
 * Ver.01.06.00 Shunji Ogawa  2026/11/23  自動起動補助の明示イベントで資源省略と現在値を区別
 * Ver.01.07.00 Shunji Ogawa  2026/11/23  同じ登録の署名付き関連起動サービスの構成を保持
 * Ver.01.08.00 Shunji Ogawa  2026/11/23  元イベントDLLの明示宛先とサイズを署名元照合に保持
 * Ver.01.09.00 Shunji Ogawa  2026/11/23  現用同梱NVMeの選択、起動と電源の元証拠を読取る
 * Ver.01.10.00 Shunji Ogawa  2026/11/23  OEM登録の正逆対応と単一ブートの元署名を照合
 * Ver.01.11.00 Shunji Ogawa  2026/11/23  読取り未対応の現用INFを未導入と区別
 * Ver.01.12.00 Shunji Ogawa  2026/11/23  元の署名付き関連サービス値をOEM登録の証拠に含める
 * Ver.01.13.00 Shunji Ogawa  2026/11/27  現用Displayの公開INFと補助EXEの署名を照合
 * Ver.01.14.00 Shunji Ogawa  2026/11/27  現用SoftwareComponentの署名と主IDの実節を照合
 * Ver.01.15.00 Shunji Ogawa  2026/11/27  元の複数INFから指定した登録の実ファイルを確認
 * Ver.01.16.00 Shunji Ogawa  2026/11/27  同じStore元INFの保持済みファイル位置を照合
 * </pre>
 * @note 保持中の登録INFとファイルだけを同期照合し、対応先の変更を検出した場合は証拠を返さない
 */
//------------------------------------------------------------------------------
#include "platform/registered_driver_store_package_internal.h"
#include "platform/inf_dependency_native_internal.h"
#include "platform/official_download_workspace.h"
#include "platform/display_inf_scope_internal.h"
#include "platform/official_driver_package.h"
#include "platform/official_file_verifier.h"
#include "platform/official_mapped_file.h"
#include "platform/official_resource_content.h"
#include "platform/official_zip.h"
#include "platform/storage_inf_effects_internal.h"
#include "platform/system_inf_effects_internal.h"
#include <cfgmgr32.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <new>
#include <optional>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {
//------------------------------------------------------------------------------
/**
 * @brief Windowsのファイル照会失敗を非零のHRESULTに変換する
 * @param[in] error Windows診断。未報告なら0
 * @return 元診断またはERROR_INVALID_DATAのHRESULT
 */
//------------------------------------------------------------------------------
NativeError storeError( DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error ? error : ERROR_INVALID_DATA)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief パスをWindowsと同じ大文字小文字の規則で比較する
 * @param[in] left 比較するパス
 * @param[in] right 同じWindows環境の別の観測パス
 * @return 全文字が大文字小文字を除いて一致する場合true
 */
//------------------------------------------------------------------------------
bool sameStorePath( std::wstring_view left, std::wstring_view right) noexcept
{
	return left.size() == right.size() && left.size() <= 32767U &&
		   CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

/** @brief 読取り中のファイルまたはディレクトリのhandleを解放する */
struct CloseStoreFile {
	/**
	 * @brief 有効な所有handleを閉じる
	 * @param[in] file この操作が開いたhandle
	 */
	void operator()( HANDLE file) const noexcept
	{
		CloseHandle( file) ;
	}
} ;

/** @brief 確認した絶対パスと変更や移動を制限するhandle */
struct StoreFile {
	/// 照合対象の絶対パス
	std::wstring						  path ;
	/// この操作だけが持つ読取りhandle
	std::unique_ptr<void, CloseStoreFile> handle ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 保持したパスがWindowsの実解決先と一致することを確認する
 * @param[in] file この操作が開いたパスとhandle
 * @return 実解決先が一致する場合0、失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError checkPinnedStorePath( const StoreFile &file)
{
	std::array<wchar_t, 32768U> buffer{} ;	// 長い祖先を含むWindowsの最終パス
	const auto					length = GetFinalPathNameByHandleW(
		 file.handle.get(), buffer.data(), static_cast<DWORD>( buffer.size()),
		 FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;	// Windowsが解決した完全な文字数
	// 必要長の通知や失敗を確定したパスに変換しません
	if( length == 0U || length >= buffer.size()) {
		return storeError( length == 0U ? GetLastError() : ERROR_FILENAME_EXCED_RANGE) ;
	}

	std::wstring_view resolved( buffer.data(), length) ;	// Windowsが返した解決先だけを比較する
	// DOS形式のWindows接頭辞を除いて元の正規パスと比較します
	if( resolved.starts_with( L"\\\\?\\")) {
		resolved.remove_prefix( 4U) ;
	}

	return sameStorePath( resolved, file.path) ? 0U : storeError( ERROR_ACCESS_DENIED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 再解析点を通さずファイルまたは親を保持する
 * @param[in] path 照合する固定絶対パス
 * @param[in] directory 親ディレクトリを保持する場合true
 * @param[out] out 全照合が成立したパスとhandle
 * @return 正常な型と解決先なら0、それ以外はHRESULT
 */
//------------------------------------------------------------------------------
NativeError pinStoreFile( std::wstring path, bool directory, StoreFile &out)
{
	const DWORD access	= directory ? FILE_READ_ATTRIBUTES : GENERIC_READ ;	// 読取りに必要な権限
	const DWORD sharing = directory ? FILE_SHARE_READ | FILE_SHARE_WRITE
									: FILE_SHARE_READ ;	// 親の移動とファイルの変更を制限
	const DWORD flags	= FILE_FLAG_OPEN_REPARSE_POINT |
						(directory ? FILE_FLAG_BACKUP_SEMANTICS : 0U) ;	// 最後の再解析点を追跡しない
	const HANDLE handle = CreateFileW( path.c_str(), access, sharing, nullptr, OPEN_EXISTING, flags,
									  nullptr) ;	// 既存の通常ファイルまたは親だけを開く
	// ファイルを開けない場合は同名の別パスから補いません
	if( handle == INVALID_HANDLE_VALUE || !handle) {
		return storeError( GetLastError()) ;
	}

	StoreFile				   file{std::move( path),
					std::unique_ptr<void, CloseStoreFile>( handle)} ;	// 失敗時も閉じる一時所有
	BY_HANDLE_FILE_INFORMATION info{} ;									// 保持した実ファイルの元属性
	// 先に型と再解析点を調べてから実解決先と比較します
	if( !GetFileInformationByHandle( handle, &info)) {
		return storeError( GetLastError()) ;
	}

	// Driver Storeの同byteハードリンクは読取り保持で変更を防ぎます
	if( ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) != directory ||
	   (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) {
		return storeError( ERROR_ACCESS_DENIED) ;
	}

	const auto error = checkPinnedStorePath( file) ;	// 親の別名や元パスの不一致を確認する
	// 指定した場所に実在したhandleだけを移します
	if( error == 0U) {
		out = std::move( file) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同登録INFのDriver Store内の位置をWindowsから読む
 * @param[in] lookup 登録INFとDriver Storeを照会するAPI表
 * @param[in] registeredInf 既に検査した元登録INFパス
 * @param[out] path Windowsが返した元パス
 * @return 終端を確認できた場合0、失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError lookupStoreInf( const DriverStorePackageLookup &lookup,
						   const std::wstring &registeredInf, std::wstring &path)
{
	std::array<wchar_t, MAX_PATH> buffer ;	// 元Windows照会のMAX_PATH出力
	buffer.fill( L'\xFFFF') ;
	SetLastError( ERROR_SUCCESS) ;
	// OSが返す元パッケージを選び、類似するINFをディレクトリ走査で探しません
	if( !lookup.storeLocation( registeredInf.c_str(), nullptr, nullptr, buffer.data(),
							 static_cast<DWORD>( buffer.size()), nullptr)) {
		return storeError( GetLastError()) ;
	}

	const auto end = std::ranges::find( buffer, L'\0') ;	// OSが返した最初の終端
	// 空、未終端、部分結果を完全パスへ変換しません
	if( end == buffer.begin() || end == buffer.end()) {
		return storeError( ERROR_INVALID_DATA) ;
	}

	path.assign( buffer.begin(), end) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief Storeの元INFが同じ公開OEM INFへ逆引きされることを確認する
 * @param[in] lookup 同じWindowsの公開名を解決するAPI
 * @param[in] store 保護付きで照合するパッケージ内の元INF
 * @param[in] published 同じWindowsの正規公開INFの完全位置
 * @param[in] leaf Windowsが記録した公開名
 * @return 正確な公開名へ解決した場合0、元APIまたは対応不一致はHRESULT
 */
//------------------------------------------------------------------------------
NativeError checkOemPublishedName( const DriverStorePackageLookup &lookup, const std::wstring &store,
								  std::wstring_view published, std::wstring_view leaf)
{
	std::array<wchar_t, MAX_PATH> buffer ;	// 終端がないAPI結果を見分ける公開名バッファー
	buffer.fill( L'\xFFFF') ;
	// Store内部の元名から公開OEM番号を推測せず、同じWindowsの対応を取得する
	if( !lookup.publishedName( store.c_str(), buffer.data(), static_cast<DWORD>( buffer.size()),
							 nullptr)) {
		return storeError( GetLastError()) ;
	}

	const auto				end = std::ranges::find( buffer, L'\0') ;	// APIが書いた終端の位置
	const std::wstring_view actual( buffer.begin(), end) ;				// 省略していない元公開名
	// 同名の別ルート、別OEM番号、未終端を対応済みとしない
	if( end == buffer.end() || (!sameStorePath( actual, leaf) && !sameStorePath( actual, published))) {
		return storeError( ERROR_INVALID_NAME) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
// 登録済みストレージの読取り
//------------------------------------------------------------------------------

// 元の選択節から各行を原順で読み取る際の上限
constexpr LONG MAX_REGISTERED_SECTION_ROWS = 128L ;

/** @brief 自動起動補助の現在観測の同期出力先 */
struct RegisteredStorageCurrentRead {
	/// 登録元が指す二つの現在イベント
	StorageSystemEventSnapshot		  &events ;
	/// 登録元が指す現在補助と同じDriver Store内の実行ファイル
	StorageAutoStartAuxiliarySnapshot &auxiliary ;
} ;

/** @brief 同じ取得中だけ借用する、現在構成と正確な登録サービス名 */
struct RegisteredStorageObservation {
	/// 現用デバイスの関連サービス名
	std::wstring_view								  installedService ;
	/// 関連サービスと補助イベントの既取得観測。署名確認後に新規読取する場合はnullptr
	const std::array<StorageEventSourceSnapshot, 2U> *events ;
	/// 現在の実行ファイルと親の保護付き観測
	const ProtectedExecutableSnapshot				 &executable ;
	/// 自動起動補助の現在観測。従来のSystem32経路ではnullptr
	const StorageAutoStartAuxiliarySnapshot			 *automatic{} ;
	/// 署名確認後に現在値を読む場合の出力先。他の経路ではnullptr
	RegisteredStorageCurrentRead					 *current{} ;
} ;

/** @brief 同一の元INFをキャッシュなしで読む間だけSetupAPIのhandleを所有する */
struct CloseRegisteredInf {
	/**
	 * @brief 読取り専用の元INF handleを閉じる
	 * @param[in] inf 同じ読取りが所有する有効なhandle
	 */
	void operator()( HINF inf) const noexcept
	{
		SetupCloseInfFile( inf) ;
	}
} ;

//------------------------------------------------------------------------------
/**
 * @brief Windowsの現ルートをOEM INFとStoreの共通基準として読む
 * @param[in] lookup 同期中に有効なWindows照会表
 * @param[out] windows 末尾に区切りを持たない完全DOS path
 * @return 取得成功0、長さやパスが不正ならHRESULT
 */
//------------------------------------------------------------------------------
NativeError readStoreWindowsDirectory( const DriverStorePackageLookup &lookup, std::wstring &windows)
{
	std::array<wchar_t, MAX_PATH> root{} ;	// Windowsの完全なルートディレクトリ
	// 終端を除いた元Windowsパスの文字数
	const auto count = lookup.windowsDirectory( root.data(), static_cast<UINT>( root.size())) ;
	// 別ディレクトリを選べる短縮値、途中終端、非正規区切りを拒否する
	if( count <= 3U || count >= root.size() || root[count] != L'\0' || root[1] != L':' ||
	   root[2] != L'\\' || root[count - 1U] == L'\\' ||
	   std::find( root.begin(), root.begin() + count, L'\0') != root.begin() + count ||
	   std::find( root.begin(), root.begin() + count, L'/') != root.begin() + count) {
		return storeError( ERROR_INVALID_DATA) ;
	}

	windows.assign( root.data(), count) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元ファイルが属するWindows配下の祖先を上から順に保持する
 * @param[in] windows 同一操作のWindowsルート
 * @param[in] placed 構造検査済みのWindows配下ファイルの完全位置
 * @param[in,out] directories 変更・移動を防いで保持している既知の親
 * @return 全ての祖先を保持した場合0、最初の元診断はHRESULT
 */
//------------------------------------------------------------------------------
NativeError pinStoreAncestors( const std::wstring &windows, const std::wstring &placed,
							  std::vector<StoreFile> &directories)
{
	// Windowsルートから親まで、移動非共有で上から順に保持する
	for( auto pos = windows.size(); pos != placed.npos; pos = placed.find( L'\\', pos + 1U)) {
		const auto parent = placed.substr( 0U, pos) ;	// このファイルの祖先一つ
		// 先行ファイルが持つ同じ親は再度開かない
		if( std::ranges::none_of( directories,
								[&]( const auto &dir) { return sameStorePath( dir.path, parent) ; })) {
			// 今回の祖先を保持した成否
			const auto error = pinStoreFile( parent, true, directories.emplace_back()) ;
			// 最初の読取り失敗を後続の親で補わない
			if( error != 0U) {
				return error ;
			}
		}
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief SetupAPIの元INF位置が同一FileRepositoryの一パッケージ内に限定されるか確認する
 * @param[in] windows 同一操作のWindowsの正規ルート
 * @param[in] storeInf SetupAPIがOEM INFについて返した完全な元INF位置
 * @return 一つのパッケージ直下のINFならtrue
 */
//------------------------------------------------------------------------------
bool isRegisteredStoreInf( const std::wstring &windows, const std::wstring &storeInf)
{
	// 元INFが属する正規ルート
	const auto				repository = windows + L"\\System32\\DriverStore\\FileRepository\\" ;
	const auto				folderEnd  = storeInf.find_last_of( L'\\') ;	// 一パッケージの親の終端
	const std::wstring_view full{storeInf} ;								// OSが返した正規先全体
	return folderEnd != full.npos && folderEnd > repository.size() &&
		   sameStorePath( full.substr( 0U, repository.size()), repository) &&
		   full.find( L'\\', repository.size()) == folderEnd &&
		   isSafeOfficialArchiveMember( full.substr( repository.size()), L'\\') &&
		   sameStorePath( full.substr( full.size() - 4U), L".inf") ;
}

//------------------------------------------------------------------------------
/**
 * @brief 登録INF名をWindows INF直下の正確なoem番号に限定する
 * @param[in] value 選択デバイスのWindows登録名
 * @return OEM INF名の完全な文法を満たす場合true
 */
//------------------------------------------------------------------------------
bool isPublishedOemInf( std::wstring_view value)
{
	return value.size() >= 8U && value.size() <= 17U &&
		   sameStorePath( value.substr( 0U, 3U), L"oem") &&
		   sameStorePath( value.substr( value.size() - 4U), L".inf") &&
		   std::ranges::all_of( value.substr( 3U, value.size() - 7U),
							   []( wchar_t ch) { return ch >= L'0' && ch <= L'9' ; }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 付随節を連結しても安全な有限のINF節名を確認する
 * @param[in] section 登録名または元INFが指定する行の節参照
 * @return 既知の節名文字だけを含む場合true
 */
//------------------------------------------------------------------------------
bool isRegisteredSection( std::wstring_view section)
{
	return !section.empty() && section.size() <= 128U &&
		   std::ranges::all_of( section, []( wchar_t ch) {
			   return (ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z') ||
					  (ch >= L'0' && ch <= L'9') || ch == L'.' || ch == L'_' || ch == L'-' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元パッケージ直下の通常ファイル名であることを照合する
 * @param[in] leaf 元INFが指定したファイル名
 * @param[in] extension 照合する型の拡張子。ドットを含む
 * @return 一つの安全な名前で拡張子が一致した場合true
 */
//------------------------------------------------------------------------------
bool isRegisteredFileLeaf( std::wstring_view leaf, std::wstring_view extension)
{
	return leaf.size() > extension.size() && leaf.find_first_of( L"\\/") == leaf.npos &&
		   isSafeOfficialArchiveMember( leaf, L'\\') &&
		   sameStorePath( leaf.substr( leaf.size() - extension.size()), extension) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択節の元fieldをSetupAPIから終端まで読み取る
 * @param[in,out] row 同期中だけ使うSetupAPIの元行context
 * @param[in] index 0はkey、1以降は元fieldの番号
 * @param[out] value 成功時の展開済み完全値。明示空は空文字
 * @return 完全取得0、元診断や範囲の拒否はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readRegisteredField( INFCONTEXT &row, DWORD index, std::wstring &value)
{
	std::array<wchar_t, 4096U> buffer{} ;	// 展開後の有限な一field
	DWORD					   required{} ;	// 終端を含む元文字数
	// 部分出力、欠損、別環境の展開を値として保存しない
	if( !SetupGetStringFieldW( &row, index, buffer.data(), static_cast<DWORD>( buffer.size()),
							 &required)) {
		return storeError( GetLastError()) ;
	}

	// 元APIの報告長と実際の終端を照合する
	if( required == 0U || required > buffer.size() || buffer[required - 1U] != L'\0' ||
	   std::find( buffer.begin(), buffer.begin() + required - 1U, L'\0') !=
		   buffer.begin() + required - 1U) {
		return storeError( ERROR_INVALID_DATA) ;
	}

	value.assign( buffer.data(), required - 1U) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一意なスカラー欄を読み、存在しない欄と空値を区別する
 * @param[in] inf 同じ読取りだけが所有する正確な元INF
 * @param[in] section 同じ完全INFの元節名
 * @param[in] key 元の一意なdirective名
 * @param[out] value 元fieldが存在すればその完全値。不在の場合は空optional
 * @return 読取りまたは明示不在0、曖昧な元値と元API失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readRegisteredScalar( HINF inf, PCWSTR section, PCWSTR key,
								 std::optional<std::wstring> &value)
{
	INFCONTEXT row{} ;	// 最初の同キーを指す元行
	// 欄が無い場合だけ次の正式な優先欄へ進める
	if( !SetupFindFirstLineW( inf, section, key, &row)) {
		const auto error = GetLastError() ;	// 元の欠損または読取り診断
		return error == ERROR_LINE_NOT_FOUND ? 0U : storeError( error) ;
	}

	INFCONTEXT duplicate{} ;	// 同キーの重複を調べる元行
	// 一つであるべき欄を先頭だけに縮約しない
	if( SetupGetFieldCount( &row) != 1U || SetupFindNextMatchLineW( &row, key, &duplicate)) {
		return storeError( ERROR_INVALID_DATA) ;
	}

	return readRegisteredField( row, 1U, value.emplace()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元Versionが選ぶAMD64の正確なCATを同じStoreパッケージに結ぶ
 * @param[in] inf 同じ読取りで保持した元INF
 * @param[in] expectedClass 検査済みの対象クラス
 * @param[in] expectedGuid 検査済みの対象GUID
 * @param[out] catalog 正式優先順で選んだCATの安全なleaf
 * @return 正式クラスと同CATが確定した場合0、失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readRegisteredVersion( HINF inf, std::wstring_view expectedClass,
								  std::wstring_view expectedGuid, std::wstring &catalog)
{
	std::optional<std::wstring> className ;	// 元INFに記録された正式クラス
	std::optional<std::wstring> classGuid ;	// 同じ元INFのClass GUID
	// 元正式クラスの読取り結果
	auto						error = readRegisteredScalar( inf, L"Version", L"Class", className) ;
	// 片方の元クラス欄が不正なら別の欄で補わない
	if( error == 0U) {
		error = readRegisteredScalar( inf, L"Version", L"ClassGUID", classGuid) ;
	}

	// 同じ正式SCSIAdapterのクラス対だけを登録済み証拠に使う
	if( error != 0U || !className || !classGuid || !sameStorePath( *className, expectedClass) ||
	   !sameStorePath( *classGuid, expectedGuid)) {
		return error != 0U ? error : storeError( ERROR_CLASS_MISMATCH) ;
	}

	// 元INF読取りと同じAMD64、NT、無装飾の優先順で一意の欄を選ぶ
	for( const PCWSTR key : {L"CatalogFile.ntamd64", L"CatalogFile.NT", L"CatalogFile"}) {
		std::optional<std::wstring> value ;	// 元欄が在る場合だけ埋まるCAT名
		error = readRegisteredScalar( inf, L"Version", key, value) ;
		// 上位欄の読取りや文法が不明な場合は下位欄を使わない
		if( error != 0U || value) {
			// 同パッケージの一つの通常CATだけを受理する
			if( error != 0U || value->size() <= 4U || value->find( L'\\') != value->npos ||
			   !isSafeOfficialArchiveMember( *value, L'\\') ||
			   !sameStorePath( std::wstring_view{*value}.substr( value->size() - 4U), L".cat")) {
				return error != 0U ? error : storeError( ERROR_INVALID_NAME) ;
			}

			catalog = std::move( *value) ;
			return 0U ;
		}
	}

	return storeError( ERROR_LINE_NOT_FOUND) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元サービス構成を実行せず、対応するバイナリと既知の設定だけを読む
 * @param[in] inf 同じ読取りで保持する元INF
 * @param[in] section 元AddServiceが指定する一つの安全なサービス節
 * @param[in] associated 関連カーネルサービスの場合true
 * @param[out] service 同じ元節のバイナリと設定。呼出し側は成功後だけ使う
 * @param[in] automatic 自動起動補助の元構成を読むときtrue。独自Securityを拒否する
 * @param[out] group 自動起動補助に付随する元関連サービスのグループ。従来経路と補助ではnullptr
 * @return 元欄を読めた場合0、構文や未知作用の拒否はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readRegisteredService( HINF inf, const std::wstring &section, bool associated,
								  RegisteredStorageHelperEvidence &service, bool automatic,
								  std::wstring *group)
{
	const auto count = SetupGetLineCountW( inf, section.c_str()) ;	// 元サービスの全行数
	// 途中の欠損や過大な節を既定サービス設定へ変更しない
	if( count <= 0L || count > MAX_REGISTERED_SECTION_ROWS) {
		return count < 0L ? storeError( GetLastError()) : storeError( ERROR_INVALID_DATA) ;
	}

	std::vector<std::wstring> keys ;	// 一意であるべき元キーを保持する
	// サービス節の宣言を先頭から全て読み、既知の設定だけを記録する
	for( LONG ordinal = 0L; ordinal < count; ++ordinal) {
		INFCONTEXT	 row{} ;	// 同節の元行を指すcontext
		std::wstring key ;		// 現在のdirectiveの完全名
		// 元行が不明な場合は別の行へ進めない
		if( !SetupGetLineByIndexW( inf, section.c_str(), static_cast<DWORD>( ordinal), &row)) {
			return storeError( GetLastError()) ;
		}

		// 同じ元キーの完全な読取り結果
		const auto error = readRegisteredField( row, 0U, key) ;
		// 元キーの読み取り失敗を未知の設定へ置き換えない
		if( error != 0U) {
			return error ;
		}

		// AddRegは既存カーネルの別作用として扱い、補助サービスには認めない
		if( associated && sameStorePath( key, L"AddReg") && SetupGetFieldCount( &row) == 1U) {
			continue ;
		}

		// 予定外の構成や重複した設定を既定の値に縮約しない
		if( SetupGetFieldCount( &row) != 1U || std::ranges::any_of( keys, [&]( const auto &known) {
			   return sameStorePath( known, key) ;
		   })) {
			return storeError( ERROR_INVALID_DATA) ;
		}

		keys.push_back( key) ;

		// 元のスカラーを対応する値に結び付ける
		std::uint32_t *number = nullptr ;	// 整数型の元設定に対応する格納先
		std::wstring  *value  = nullptr ;	// 元文字列を保つ格納先
		// タイプと開始設定は実サービスを導入せず宣言から取る
		if( sameStorePath( key, L"ServiceType")) {
			number = &service.type ;
		}
		// 元開始種別を保持し、自動起動か要求時起動かを後で照合する
		else if( sameStorePath( key, L"StartType")) {
			number = &service.start ;
		}
		// 障害時の元設定を既定に置き換えない
		else if( sameStorePath( key, L"ErrorControl")) {
			number = &service.errorControl ;
		}
		// 実行ファイルは元文字列全体を読み、後から配置先と照合する
		else if( sameStorePath( key, L"ServiceBinary")) {
			value = &service.binary ;
		}
		// 元表示名を現在構成への照合に使えるようにする
		else if( sameStorePath( key, L"DisplayName")) {
			value = &service.display ;
		}
		// 表示名とは別に元の説明を保持する
		else if( sameStorePath( key, L"Description")) {
			value = &service.description ;
		}
		// 従来の補助サービスで指定されたSDDLは元文字列を保つ
		else if( !automatic && !associated && sameStorePath( key, L"Security")) {
			value = &service.security ;
		}
		// 自動起動補助に付随する関連サービスでは元グループを実値として取得する
		else if( associated && sameStorePath( key, L"LoadOrderGroup")) {
			// 従来経路の関連サービスは既存のカーネル照合に任せる
			if( !group) {
				continue ;
			}

			value = group ;
		} else {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}

		// 元型が要求するfieldを読み、欠損を0や空として保存しない
		if( number) {
			int raw{} ;	// SetupAPIが原表記から解決した完全整数
			// 負値をDWORDの有効なサービス値として扱わない
			if( !SetupGetIntField( &row, 1U, &raw) || raw < 0) {
				return storeError( ERROR_INVALID_DATA) ;
			}

			*number = static_cast<std::uint32_t>( raw) ;
		} else {
			// 同元設定を読んだ成否
			const auto read = readRegisteredField( row, 1U, *value) ;
			// 設定値の途中失敗は後続設定で上書きしない
			if( read != 0U) {
				return read ;
			}
		}
	}

	// BOOT_STARTとERROR_IGNOREの明示0を欠落と混同しない
	for( const auto mandatory : {L"ServiceType", L"StartType", L"ErrorControl", L"ServiceBinary"}) {
		// 同一サービス節に必須の四欄が実在しなければ拒否する
		if( std::ranges::none_of( keys,
								[&]( const auto &key) { return sameStorePath( key, mandatory) ; })) {
			return storeError( ERROR_LINE_NOT_FOUND) ;
		}
	}

	service.installSection = section ;
	return 0U ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 元の登録宣言と現在のSystemイベントの型・値・資源省略を確認する
 * @param[in] declared 同じ元選択から読んだ署名付きのイベント宣言
 * @param[in] current 型付きで確認済みの現在のイベントソース
 * @param[in] writesOnly 省略した資源を元が書く項目に含めない場合true
 * @return 現在の名前と元が指定する型・値が一致する場合true
 * @note 書かれない資源の署名元は別の現用登録で確認する
 */
//------------------------------------------------------------------------------
bool matchesRegisteredStorageEvent( const RegisteredStorageEventReference &declared,
								   const StorageEventSourceSnapshot		 &current,
								   bool									  writesOnly) noexcept
{
	// 元で省略された資源の有無と、元が明示するREG_EXPAND_SZを区別して照合する
	const bool message =
		declared.messageFile.empty()
			? writesOnly || (!current.messageFile && current.messageFileType == REG_NONE)
			: current.messageFileType == REG_EXPAND_SZ && current.messageFile &&
				  sameStorePath( *current.messageFile, declared.messageFile) ;
	return current.present && sameStorePath( current.name, declared.name) && message &&
		   current.typesSupported == declared.typesSupported &&
		   (!declared.categoryCount || current.categoryCount == declared.categoryCount) ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 元イベント宣言の型と値を現在観測された同名Systemイベントに結ぶ
 * @param[in] inf 同一登録の読取り中だけ有効な元INF
 * @param[in] section 元AddServiceから到達するイベント節
 * @param[in] name 同じAddServiceで宣言した元イベントの所有ソース名
 * @param[in] driverLeaf 同CATに結ぶSYS名
 * @param[in] current 既取得の現在観測。署名確認後に読取する場合はnullptr
 * @param[out] reference イベントを宣言した場合の元参照
 * @param[in] named 自動起動補助の明示イベントを読む場合true
 * @return 宣言と現在の値が矛盾しなければ0、それ以外はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readRegisteredEvent( HINF inf, const std::wstring &section, const std::wstring &name,
								const std::wstring							   &driverLeaf,
								const StorageEventSourceSnapshot			   *current,
								std::optional<RegisteredStorageEventReference> &reference,
								bool											named = false)
{
	// 現在見えている登録を元イベントの宣言なしで所有済みと扱わない
	if( section.empty()) {
		return current && current->present ? storeError( ERROR_NOT_SUPPORTED) : 0U ;
	}

	std::optional<std::wstring> list ;	// 同イベント節が直接所有する一つのAddReg参照
	// 元イベント一覧への参照診断
	const auto					error = readRegisteredScalar( inf, section.c_str(), L"AddReg", list) ;
	const auto					count = list && isRegisteredSection( *list)
											? SetupGetLineCountW( inf, list->c_str())
											: 0L ;	// 元イベント値の個数。不明な参照では0
	// 単一の正確なイベント参照だけを読み、別のキーや節を推測しない
	if( error != 0U || SetupGetLineCountW( inf, section.c_str()) != 1L ||
	   (count != 2L && !(named && count == 3L))) {
		return error != 0U ? error : storeError( ERROR_NOT_SUPPORTED) ;
	}

	RegisteredStorageEventReference made ;	// 型と値を二つとも確認した場合に限り移す
	made.name			= name ;
	made.installSection = section ;
	// 元設定を有限の原順で読み、重複や別の書込みを拒否する
	for( DWORD ordinal = 0U; ordinal < static_cast<DWORD>( count); ++ordinal) {
		INFCONTEXT	 row{} ;	// 元AddRegの一行
		std::wstring root ;		// イベントソース自身へ解決する元HKR
		std::wstring subkey ;	// 空以外は新たな作用を持つサブキー
		std::wstring key ;		// 二つの元イベント値の一方
		int			 flags{} ;	// 型と元AddRegフラグ
		// 名前と型を省略した登録や異なるキーへの書込みを許さない
		if( !SetupGetLineByIndexW( inf, list->c_str(), ordinal, &row) ||
		   SetupGetFieldCount( &row) != 5U || readRegisteredField( row, 1U, root) != 0U ||
		   readRegisteredField( row, 2U, subkey) != 0U || readRegisteredField( row, 3U, key) != 0U ||
		   !SetupGetIntField( &row, 4U, &flags) || !sameStorePath( root, L"HKR") || !subkey.empty()) {
			return storeError( ERROR_INVALID_DATA) ;
		}

		// 資源を宣言した場合はWindows標準DLLと同じCATの一ファイルへ結ぶ
		if( flags == 0x20000 && sameStorePath( key, L"EventMessageFile") &&
		   made.messageFile.empty()) {
			const std::wstring_view prefix{L"%SystemRoot%\\System32\\IoLogMsg.dll;"
										   L"%SystemRoot%\\System32\\"} ;		// 元資源の共通基点
			const auto read = readRegisteredField( row, 5U, made.messageFile) ;	// 元読取り結果
			// 別のWindows基点や単独のリソースを同じ原宣言と扱わない
			if( read != 0U || made.messageFile.size() <= prefix.size() ||
			   !sameStorePath( std::wstring_view{made.messageFile}.substr( 0U, prefix.size()),
							  prefix)) {
				return read != 0U ? read : storeError( ERROR_NOT_SUPPORTED) ;
			}

			// Windows標準DLLに続く元ファイルの場所
			const auto member = std::wstring_view{made.messageFile}.substr( prefix.size()) ;
			// 旧補助の資源はSystem32直下、関連サービスは同じSYS一つだけを参照する
			if( named && isRegisteredFileLeaf( member, L".dll") && member.find( L';') == member.npos &&
			   !sameStorePath( member, L"IoLogMsg.dll")) {
				made.resourceLeaf = member ;
			}
			// 他のDLLや別のSYSはこの元イベントの資源として扱わない
			else if( named || !sameStorePath( member, L"drivers\\" + driverLeaf)) {
				return storeError( ERROR_NOT_SUPPORTED) ;
			}
		}
		// 種別値は元のDWORDマスクを正確に保つ
		else if( flags == 0x10001 && sameStorePath( key, L"TypesSupported") &&
				made.typesSupported == 0U) {
			int types{} ;	// 元DWORDを既知範囲に限定して読む
			// 異なる型、欠損、未知の種別マスクを既定にしない
			if( !SetupGetIntField( &row, 5U, &types) || types != (named ? 31 : 7)) {
				return storeError( ERROR_NOT_SUPPORTED) ;
			}

			made.typesSupported = static_cast<std::uint32_t>( types) ;
		}
		// 明示イベントでは元カテゴリの一回のDWORD宣言を確認する
		else if( named && flags == 0x10001 && sameStorePath( key, L"CategoryCount") &&
				!made.categoryCount) {
			int categories{} ;	// 明示元イベントが宣言するカテゴリ数
			// カテゴリ型と元個数の違いは同じイベント作用にしない
			if( !SetupGetIntField( &row, 5U, &categories) || categories != 1) {
				return storeError( ERROR_NOT_SUPPORTED) ;
			}

			made.categoryCount = static_cast<std::uint32_t>( categories) ;
		} else {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}
	}

	// 実在するイベントは型を含む同じ元宣言に結び、同名だけでは確定しない
	if( (named ? !made.categoryCount : made.messageFile.empty()) || made.typesSupported == 0U ||
	   (current && current->present && !matchesRegisteredStorageEvent( made, *current))) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	reference = std::move( made) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元コピーをWindowsの実解決するコピー先と同じStore直下の媒体へ結ぶ
 * @param[in] inf 同じ読取りが保持する元INF
 * @param[in] list コピー節名。直接ファイルなら空
 * @param[in] leaf INFが指定したコピー元の正確なファイル名
 * @param[in] target 対象のサービスに結び付く完全なコピー先
 * @param[in] expectedDirId 許可した元DIRID。12はSYS、11はSystem32、13は元パッケージ
 * @return 元と宛先の両方が成立すれば0、元API失敗や不明な媒体はHRESULT
 */
//------------------------------------------------------------------------------
NativeError verifyRegisteredCopyLocation( HINF inf, const std::wstring &list,
										 const std::wstring &leaf, const std::wstring &target,
										 int expectedDirId)
{
	// 当該コピーの元DestinationDirs名
	const auto key = list.empty() ? L"DefaultDestDir" : list.c_str() ;
	INFCONTEXT destination{} ;	// 同コピーだけに適用される明示宛先
	INFCONTEXT duplicate{} ;	// 同キーの曖昧性を確認する
	int		   dirid{} ;		// 元のDIRID。未宣言や別directoryを補わない
	// DIRIDは元宛先欄から一意に得た正確な番号だけを使う
	if( !SetupFindFirstLineW( inf, L"DestinationDirs", key, &destination) ||
	   SetupGetFieldCount( &destination) != 1U || !SetupGetIntField( &destination, 1U, &dirid) ||
	   dirid != expectedDirId || SetupFindNextMatchLineW( &destination, key, &duplicate)) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	std::array<wchar_t, MAX_PATH> targetDirectory{} ;	// Native解決した完全コピー先の親
	DWORD						  required{} ;			// 元の終端込み必要長
	// 元DIRIDを別OS環境の手動置換で解決しない
	if( !SetupGetTargetPathW( inf, nullptr, list.empty() ? nullptr : list.c_str(),
							targetDirectory.data(), static_cast<DWORD>( targetDirectory.size()),
							&required) ||
	   required == 0U || required > targetDirectory.size() ||
	   targetDirectory[required - 1U] != L'\0' ||
	   (!(expectedDirId == 13 && sameStorePath( targetDirectory.data(), L".")) &&
		!sameStorePath( std::wstring( targetDirectory.data()) + L'\\' + leaf, target))) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	INFCONTEXT source{} ;	// 同コピーの元媒体行
	// Windowsの正式なAMD64優先で媒体行を読み、他の名前から補わない
	if( !SetupFindFirstLineW( inf, L"SourceDisksFiles.amd64", leaf.c_str(), &source) &&
	   !SetupFindFirstLineW( inf, L"SourceDisksFiles", leaf.c_str(), &source)) {
		return storeError( GetLastError()) ;
	}

	// 同名行が二つなら、現に見える同名ファイルだけで元を選ばない
	if( SetupFindNextMatchLineW( &source, leaf.c_str(), &duplicate)) {
		return storeError( ERROR_DUP_NAME) ;
	}

	std::array<wchar_t, MAX_PATH> subdir{} ;	// 元ファイルの媒体内subdirectory
	std::array<wchar_t, MAX_PATH> media{} ;		// 同じ媒体IDが記録する元root
	UINT						  sourceId{} ;	// Windowsが読んだ元媒体ID
	// この登録経路では両欄が明示的に同じパッケージの直下へ解決する場合だけ扱う
	if( !SetupGetSourceFileLocationW( inf, nullptr, leaf.c_str(), &sourceId, subdir.data(),
									static_cast<DWORD>( subdir.size()), nullptr) ||
	   !SetupGetSourceInfoW( inf, sourceId, SRCINFO_PATH, media.data(),
							static_cast<DWORD>( media.size()), nullptr)) {
		return storeError( GetLastError()) ;
	}

	const auto mediaKey = std::to_wstring( sourceId) ;	// 同媒体位置を宣言した元Key
	// 不明な元媒体を、空に初期化したNative出力だけから確定しない
	if( subdir.front() != L'\0' || media.front() != L'\0' ||
	   (!SetupFindFirstLineW( inf, L"SourceDisksNames.amd64", mediaKey.c_str(), &source) &&
		!SetupFindFirstLineW( inf, L"SourceDisksNames", mediaKey.c_str(), &source)) ||
	   SetupFindNextMatchLineW( &source, mediaKey.c_str(), &duplicate)) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元選択の直接SYSと該当時のSystem32コピーだけを一行ずつ照合する
 * @param[in] inf 同じ登録から開いた元INF
 * @param[in] section Windowsがこのデバイスに記録した実選択節
 * @param[in] kernelTarget 関連サービスに対応するSYSの完全宛先
 * @param[in] driverLeaf 同じ元カーネルサービスに結ぶSYS名
 * @param[in] helper 同じ元選択が宣言した補助サービス。不在ならSYS一行だけを確認する
 * @return 元コピーと対応先を照合できた場合0、未知の選択作用はHRESULT
 */
//------------------------------------------------------------------------------
NativeError verifyRegisteredCopies( HINF inf, const std::wstring &section,
								   const std::wstring &kernelTarget, const std::wstring &driverLeaf,
								   const std::optional<RegisteredStorageHelperEvidence> &helper)
{
	const auto count = SetupGetLineCountW( inf, section.c_str()) ;	// 選択実DDInstallの全行
	// 元選択が不存在の場合に基底節や類似節へ移らない
	if( count != (helper ? 2L : 1L)) {
		return count < 0L ? storeError( GetLastError()) : storeError( ERROR_NOT_SUPPORTED) ;
	}

	const auto	 direct = std::wstring{L"@"} + driverLeaf ;	// 直接SYSコピーの唯一の表記
	std::wstring helperList ;								// 補助EXEを宣言した一つのcopy list
	bool		 directFound = false ;						// 主SYSコピーを確認したか
	// 選択節の全行を照合し、他のInstall actionを無視しない
	for( LONG ordinal = 0L; ordinal < count; ++ordinal) {
		INFCONTEXT	 line{} ;	// 同DDInstallの一行
		std::wstring key ;		// 同行の元キー
		std::wstring value ;	// 選択した一つの元コピー参照
		// 導入済みの版で新たな未確認作用が見える場合は保留する
		if( !SetupGetLineByIndexW( inf, section.c_str(), static_cast<DWORD>( ordinal), &line) ||
		   SetupGetFieldCount( &line) != 1U || readRegisteredField( line, 0U, key) != 0U ||
		   readRegisteredField( line, 1U, value) != 0U || !sameStorePath( key, L"CopyFiles")) {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}

		// 主SYSの重複または無宣言のEXEコピーから所有を推測しない
		if( sameStorePath( value, direct) && !directFound) {
			directFound = true ;
		}
		// 元の補助サービスに対応する参照節を一度だけ保持する
		else if( helper && helperList.empty() && isRegisteredSection( value)) {
			helperList = std::move( value) ;
		} else {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}
	}

	// 主SYSを宣言した一つの直接コピーが必要
	if( !directFound) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	// 主SYSの元コピー照合結果
	const auto error = verifyRegisteredCopyLocation( inf, L"", driverLeaf, kernelTarget, 12) ;
	// 初回元診断または補助コピーの明示不在で終了する
	if( error != 0U || !helper) {
		return error ;
	}

	const auto helperSecurity = helperList + L".Security" ;	// コピー先ACLを指定し得る元付随節
	// 独自コピー権限の付随節は補助サービス所有の証拠に使わない
	if( helperList.empty() || SetupGetLineCountW( inf, helperList.c_str()) != 1L ||
	   SetupGetLineCountW( inf, helperSecurity.c_str()) >= 0L ||
	   GetLastError() != ERROR_SECTION_NOT_FOUND) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	// 読取り済み元EXEの正確なleaf
	const auto	 leaf = helper->binary.substr( helper->binary.find_last_of( L'\\') + 1U) ;
	INFCONTEXT	 row{} ;		// 元コピー節の唯一の行
	std::wstring target ;		// 元の正確なコピー先leaf
	std::wstring source ;		// 元の正確なコピー元leaf
	std::wstring temporary ;	// 明示空の一時コピー名
	int			 flags{} ;		// 元の完全コピー作用
	// 同名コピーの元欄と再起動時置換の元フラグだけをこの境界で扱う
	if( !SetupGetLineByIndexW( inf, helperList.c_str(), 0U, &row) || SetupGetFieldCount( &row) != 4U ||
	   readRegisteredField( row, 1U, target) != 0U || readRegisteredField( row, 2U, source) != 0U ||
	   readRegisteredField( row, 3U, temporary) != 0U || !SetupGetIntField( &row, 4U, &flags) ||
	   !sameStorePath( leaf, target) || !sameStorePath( leaf, source) || !temporary.empty() ||
	   flags != COPYFLG_FORCE_FILE_IN_USE) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	return verifyRegisteredCopyLocation( inf, helperList, leaf, helper->binary, 11) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 自動起動する元選択のSYS・補助EXE・該当するイベントDLLのコピーを確認する
 * @param[in] inf 同じ登録の元INF
 * @param[in] section デバイスに登録された正確なDDInstall節
 * @param[in] kernel 同じ元選択の関連サービス
 * @param[in] driverLeaf 関連サービスの元SYS名
 * @param[in] helper 照合済み補助EXEの完全位置を持つ元補助
 * @param[in] event 同じ選択の明示イベントと元資源。資源の省略ではDLLコピーを許さない
 * @return 元選択のすべてのコピーを照合できれば0、それ以外はHRESULT
 * @note 電源設定の内容と端末の既存状態は別の検査で扱う
 */
//------------------------------------------------------------------------------
NativeError verifyRegisteredAutomaticCopies( HINF inf, const std::wstring &section,
											const RegisteredStorageHelperEvidence &kernel,
											const std::wstring					  &driverLeaf,
											const RegisteredStorageHelperEvidence &helper,
											const RegisteredStorageEventReference &event)
{
	const auto count		= SetupGetLineCountW( inf, section.c_str()) ;	// 元選択の全宣言数
	const bool hasResource	= !event.resourceLeaf.empty() ;					// 旧DLLを検査する必要があるか
	const LONG requiredRows = hasResource ? 4L : 3L ;						// 必須コピーとFeatureScoreの行数
	// 必須行に加えて電源宣言は一行まで取り扱う
	if( count != requiredRows && count != requiredRows + 1L) {
		return count < 0L ? storeError( GetLastError()) : storeError( ERROR_NOT_SUPPORTED) ;
	}

	// 登録パッケージ直下に確定した補助EXE名
	const auto helperLeaf	  = helper.binary.substr( helper.binary.find_last_of( L'\\') + 1U) ;
	const auto direct		  = L"@" + helperLeaf ;	// 元補助に対応する一意の直接コピー
	bool	   copiedDriver	  = false ;				// 元関連SYSの署名媒体と宛先を照合済みか
	bool	   copiedHelper	  = false ;				// 元補助のDIRID 13宣言を照合済みか
	bool	   copiedResource = false ;				// 元資源DLLのSystem32宛先を照合済みか
	bool	   scored		  = false ;				// 元FeatureScoreの一意な宣言を見たか
	bool	   declaresPower  = false ;				// 電源設定の元参照が一行だけ存在するか
	// 元DDInstallの全行を確認し、追加のコピーや未知の作用を見落とさない
	for( LONG ordinal = 0L; ordinal < count; ++ordinal) {
		INFCONTEXT	 row{} ;	// 元DDInstallの現在行
		std::wstring key ;		// 元行のdirective
		// 読取りに失敗した行を飛ばして元コピーを確認しない
		if( !SetupGetLineByIndexW( inf, section.c_str(), static_cast<DWORD>( ordinal), &row) ||
		   readRegisteredField( row, 0U, key) != 0U) {
			return storeError( ERROR_INVALID_DATA) ;
		}

		// 電源宣言の既知の形と一意性を確認し、同じ署名の参照は共通の読取りで検査する
		if( !declaresPower && sameStorePath( key, L"AddPowerSetting") &&
		   SetupGetFieldCount( &row) == 6U) {
			declaresPower = true ;
			continue ;
		}

		// 同じ選択で既知の明示FeatureScoreだけを受け入れる
		if( !scored && sameStorePath( key, L"FeatureScore") && SetupGetFieldCount( &row) == 1U) {
			int score{} ;	// 元選択のFeatureScore
			// 異なる選択の評価値をこの元登録へ結び付けない
			if( !SetupGetIntField( &row, 1U, &score) || score != 0x80) {
				return storeError( ERROR_NOT_SUPPORTED) ;
			}

			scored = true ;
			continue ;
		}

		std::wstring copy ;	// 直接コピー名または同INFのコピー節
		// 残りは元選択が指定した単一のコピー参照だけを扱う
		if( !sameStorePath( key, L"CopyFiles") || SetupGetFieldCount( &row) != 1U ||
		   readRegisteredField( row, 1U, copy) != 0U) {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}

		// 補助EXEは元ドライバーと同じパッケージの直下で使う
		if( !copiedHelper && sameStorePath( copy, direct)) {
			// 元媒体とDefaultDestDirによる同パッケージ直下の照合結果
			const auto error =
				verifyRegisteredCopyLocation( inf, L"", helperLeaf, helper.binary, 13) ;
			// 現用EXEが同名でも、ディレクトリの原宣言が異なる場合は拒否する
			if( error != 0U) {
				return error ;
			}

			copiedHelper = true ;
			continue ;
		}

		const auto	 security = copy + L".Security" ;	// コピー先の保護を変更し得る元付随節
		std::wstring leaf ;								// 元コピー節の唯一の通常ファイル
		// 同名の単一コピーのみ許し、名前変更・フラグ・付随ACLを受け入れない
		if( !isRegisteredSection( copy) || SetupGetLineCountW( inf, copy.c_str()) != 1L ||
		   SetupGetLineCountW( inf, security.c_str()) >= 0L ||
		   GetLastError() != ERROR_SECTION_NOT_FOUND ||
		   !SetupGetLineByIndexW( inf, copy.c_str(), 0U, &row) || SetupGetFieldCount( &row) != 1U ||
		   readRegisteredField( row, 1U, leaf) != 0U) {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}

		// 同じ関連サービスを開始するSYSの唯一のコピー先を照合する
		if( !copiedDriver && sameStorePath( leaf, driverLeaf)) {
			// 関連サービスとDIRID 12のコピー先が同じか
			const auto error = verifyRegisteredCopyLocation( inf, copy, leaf, kernel.binary, 12) ;
			// 異なるシステム位置へのコピーで所有証拠を作らない
			if( error != 0U) {
				return error ;
			}

			copiedDriver = true ;
		}
		// 同じ元イベントが宣言した旧DLLも同じパッケージとSystem32へ結ぶ
		else if( hasResource && !copiedResource && sameStorePath( leaf, event.resourceLeaf)) {
			// 既定ディレクトリや別の場所をDLLの正規の登録先と扱わない
			if( !hasExplicitStorageEventCopyDestination( inf, copy)) {
				return storeError( ERROR_NOT_SUPPORTED) ;
			}

			std::array<wchar_t, MAX_PATH> dir{} ;	// Windowsが指定したSystem32の正確な位置
			// 終端を除く完全なWindowsシステムディレクトリ名の長さ
			const auto length = GetSystemDirectoryW( dir.data(), static_cast<UINT>( dir.size())) ;
			// 取得が成立した完全なSystem32を基準にする
			if( length == 0U || length >= dir.size()) {
				return storeError( ERROR_NOT_SUPPORTED) ;
			}

			// 元DLLのDIRID 11と宣言済み元媒体の照合結果
			const auto error =
				verifyRegisteredCopyLocation( inf, copy, leaf, dir.data() + (L"\\" + leaf), 11) ;
			// 元メッセージ資源のコピーに別のファイルを代入しない
			if( error != 0U) {
				return error ;
			}

			copiedResource = true ;
		} else {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}
	}

	return copiedDriver && copiedHelper && copiedResource == hasResource && scored
			   ? 0U
			   : storeError( ERROR_NOT_SUPPORTED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保護付きの同じINFから文脈に応じて元の全行と全欄を読み取る
 * @param[in] inf 呼出し中に保持する同じ署名INFの解析ハンドル
 * @param[in] source 選択と同じ署名文書に結ぶ正確な元節と文脈
 * @param[out] rows 全行の作業値。失敗時は呼出し側で破棄する
 * @return 元行を完全に読み取れた場合0、未知の保護・行形式・元読取り失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readRegisteredInfRows( HINF inf, const SystemInfSection &source,
								  std::vector<SystemInfRow> &rows)
{
	rows.clear() ;
	// 付随節の読取りへ進む前に元の名前を確認する
	if( !isRegisteredSection( source.name)) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	const auto security		 = source.name + L".Security" ;					// 追加の保護作用を持ち得る付随節
	const auto securityRows	 = SetupGetLineCountW( inf, security.c_str()) ;	// 付随節の有無
	const auto securityError = GetLastError() ;								// 不在または元読取り診断
	// 付随する保護宣言と読取り不能を電源定義の成立へ含めない
	if( securityRows >= 0L || securityError != ERROR_SECTION_NOT_FOUND) {
		return storeError( securityRows >= 0L ? ERROR_NOT_SUPPORTED : securityError) ;
	}

	const auto count = SetupGetLineCountW( inf, source.name.c_str()) ;	// 参照された元節の全行数
	// 通常の元節読取りと同じ上限を適用し、欠損を空節に置換しない
	if( count < 0L || count > 4096L) {
		return storeError( count < 0L ? GetLastError() : ERROR_BUFFER_OVERFLOW) ;
	}

	// 参照元と定義節の行を元の位置、キー、全fieldを保ったまま読み取る
	for( LONG ordinal = 0L; ordinal < count; ++ordinal) {
		INFCONTEXT line{} ;	// 同じINFにおける元行のSetupAPI context
		// 元節の一行を読み取れない場合は解析を中断する
		if( !SetupGetLineByIndexW( inf, source.name.c_str(), static_cast<DWORD>( ordinal), &line)) {
			return storeError( GetLastError()) ;
		}

		const auto fields = SetupGetFieldCount( &line) ;	// 省略を含む元行のfield数
		// 過大なfield数を先頭部分だけへ縮約しない
		if( fields > 64U) {
			return storeError( ERROR_BUFFER_OVERFLOW) ;
		}

		auto &row			= rows.emplace_back() ;	// 元順で共通解析に渡す一行
		row.ordinal			= static_cast<std::uint32_t>( ordinal) ;
		const auto keyError = readRegisteredField( line, 0U, row.key) ;	// 元directiveの完全読取り結果
		// 登録データ行ではSetupAPIの正式な無名だけを認める
		if( source.context == SystemInfContext::REGISTRY) {
			// 名前付きの登録行やその他の読取り失敗を無名へ置き換えない
			if( keyError != storeError( ERROR_INVALID_PARAMETER)) {
				return keyError != 0U ? keyError : storeError( ERROR_INVALID_DATA) ;
			}
		}
		// 他の節では不明なキーを行として確定しない
		else if( keyError != 0U) {
			return keyError ;
		}

		NativeError error{} ;	// 元fieldの先行診断
		// キーを確認した行からだけ、空欄を含むすべてのfieldを保持する
		for( DWORD index = 1U; error == 0U && index <= fields; ++index) {
			error = readRegisteredField( line, index, row.values.emplace_back()) ;
		}

		// 最初のキーまたはfieldの診断をそのまま返す
		if( error != 0U) {
			return error ;
		}
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名照合済みの元選択が直接参照する範囲型の電源定義を取得する
 * @param[in] inf 同じ元CATに結合済みの保持中INF
 * @param[in] section デバイスに記録された正確なDDInstall節
 * @param[out] settings 同じ元選択の全定義。元宣言が無い場合または失敗時は空
 * @return 全定義の読取りが成立すれば0、未知の参照や読取り失敗はHRESULT
 * @note 元選択の機器節に電源宣言や別節を取り込む指示があれば対応外とする
 */
//------------------------------------------------------------------------------
NativeError readRegisteredRangedPowerSettings( HINF inf, const std::wstring &section,
											  std::vector<RangedStoragePowerSetting> &settings)
{
	settings.clear() ;
	const auto hardware		 = section + L".HW" ;							// 元の実選択に付随する同INFの機器節
	const auto hardwareRows	 = SetupGetLineCountW( inf, hardware.c_str()) ;	// 同じ正確な機器節の行数
	const auto hardwareError = GetLastError() ;								// 機器節の不在または読取り診断
	// 機器節に元行がある場合は別文脈の電源作用と取り込みを確認する
	if( hardwareRows > 0L) {
		// 機器節から別の電源宣言が到達し得る場合は既知の基本節だけで証拠を作らない
		for( const auto *key : {L"AddPowerSetting", L"Include", L"Needs"}) {
			INFCONTEXT row{} ;	// 同節における対象directiveの最初の行
			// 機器節に現れた対象directiveはこの登録経路の対応範囲外とする
			if( SetupFindFirstLineW( inf, hardware.c_str(), key, &row)) {
				return storeError( ERROR_NOT_SUPPORTED) ;
			}

			const auto error = GetLastError() ;	// directiveの不在または実APIの失敗
			// 正式な行不在だけを元宣言なしとして扱う
			if( error != ERROR_LINE_NOT_FOUND) {
				return storeError( error) ;
			}
		}
	}
	// 元機器節が存在しない場合は基本節のみを読む。その他の読取り失敗は保持する
	else if( hardwareRows < 0L && hardwareError != ERROR_SECTION_NOT_FOUND) {
		return storeError( hardwareError) ;
	}

	constexpr std::uint64_t DOCUMENT = 1U ;	// 同じ登録を読む同期処理内の一つの元文書
	SystemInfEffectApi		api ;			// 保持中の同じINFに対する読取りだけを公開する
	// 同じ署名済みINFのhandleを同期の間だけ借り、共通解析へ正確な元行を渡す
	api.read = [inf]( const SystemInfSection	   &source,
					 std::vector<SystemInfRow> &rows) -> NativeError {
		rows.clear() ;
		// 同じINFの通常節として扱える名前だけを開く
		if( source.document != DOCUMENT || !isRegisteredSection( source.name)) {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}

		return readRegisteredInfRows( inf, source, rows) ;
	} ;

	const SystemInfSection selected{
		DOCUMENT, section, SystemInfContext::DEVICE, SystemInfContext::DEVICE, {}} ;	// 元実選択
	return readSelectedRangedStoragePowerSettings( selected, api, settings) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元実選択のAddServiceを関連カーネルと既知の補助サービスへ限定する
 * @param[in] inf 当該登録元の固定INF
 * @param[in] section Windowsが選択デバイスへ記録した実選択節
 * @param[in] intended 同じデバイスに使用する候補の対象サービスと宛先
 * @param[in] host 現用サービスの関係と保護された現在観測
 * @param[in] parent 登録元パッケージの末尾区切り付き正規絶対位置
 * @param[out] driverLeaf 関連カーネルサービスが宣言する通常SYSの名前
 * @param[out] bootService 自動起動補助に付随する元関連サービスの構成。元CATの照合前は公開しない
 * @param[in,out] made 元登録の部分結果。呼出し側は成功後だけ参照する
 * @return 元選択の対応を取得した場合0、構成が不明な場合はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readRegisteredSelectedServices( HINF inf, const std::wstring &section,
										   const SelectedStorageServiceFacts  &intended,
										   const RegisteredStorageObservation &host,
										   const std::wstring &parent, std::wstring &driverLeaf,
										   RegisteredStorageBootServiceEvidence &bootService,
										   RegisteredStoragePackageEvidence		&made)
{
	const auto serviceSection = section + L".Services" ;						// 元選択の専用Services節
	const auto count	 = SetupGetLineCountW( inf, serviceSection.c_str()) ;	// 元全AddService件数
	const bool automatic = host.automatic || host.current ;						// Driver Storeの自動起動補助を照合するか
	// 既知の単一関連サービスと一つの補助サービスだけを読む
	if( count < 1L || count > 2L || (automatic && count != 2L)) {
		return count < 0L ? storeError( GetLastError()) : storeError( ERROR_NOT_SUPPORTED) ;
	}

	std::array<std::wstring, 2U>	eventSections ;	// 関連、補助の順に元イベント参照を保持する
	RegisteredStorageHelperEvidence kernel ;		// 既存カーネルの元ServiceBinaryと型
	std::wstring					kernelGroup ;	// 自動起動補助に付随する元LoadOrderGroup
	std::wstring					namedSource ;	// 自動起動補助が指定した明示のSystemイベント源
	// Services節の全行を読み、明示された関係だけを保持する
	for( LONG ordinal = 0L; ordinal < count; ++ordinal) {
		INFCONTEXT	 row{} ;			// 同Services節の元行
		std::wstring key ;				// 同行の元directive
		std::wstring name ;				// 元AddServiceで指定した名前
		std::wstring installSection ;	// 元サービス構成節の明示参照
		int			 flags{} ;			// 関連サービスを決める元AddService flags
		// Include/Needs、DelServiceや追加のイベント指定を無視しない
		if( !SetupGetLineByIndexW( inf, serviceSection.c_str(), static_cast<DWORD>( ordinal), &row) ||
		   readRegisteredField( row, 0U, key) != 0U || !sameStorePath( key, L"AddService") ||
		   readRegisteredField( row, 1U, name) != 0U || !SetupGetIntField( &row, 2U, &flags) ||
		   readRegisteredField( row, 3U, installSection) != 0U ||
		   !isRegisteredSection( installSection)) {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}

		const bool associated = flags == SPSVCINST_ASSOCSERVICE ;	// 元がassociatedを指定するか
		const auto fields	  = SetupGetFieldCount( &row) ;			// 元AddServiceの欄数
		// 既存の暗黙イベントと、自動起動補助の明示名を別の構文として扱う
		if( automatic ? fields != (associated ? 4U : 6U) : (fields < 3U || fields > 4U)) {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}

		// INF選択に現れた名前を同じ役割の比較先と結び、名前だけの候補追加をしない
		if( (associated && (!kernel.name.empty() || !sameStorePath( name, host.installedService))) ||
		   (!associated &&
			(flags != 0 || made.helper ||
			 (automatic ? !isRegisteredSection( name) || sameStorePath( name, host.installedService)
						: !sameStorePath( name, intended.auxiliary->name))))) {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}

		auto &service = associated ? kernel : made.helper.emplace() ;	// 同元構成の格納先
		service.name  = std::move( name) ;
		// 元サービス構成の確定結果
		const auto error =
			readRegisteredService( inf, installSection, associated, service, automatic,
								  automatic && associated ? &kernelGroup : nullptr) ;
		// 同元役割の構成を全て読めなければ元証拠を確定しない
		if( error != 0U) {
			return error ;
		}

		auto &event = eventSections[associated ? 0U : 1U] ;	// 元AddServiceのイベント参照
		// 4欄目の元参照は完全節名を確認して保存する
		if( fields >= 4U &&
		   (readRegisteredField( row, 4U, event) != 0U || !isRegisteredSection( event))) {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}

		// 明示された同じSystemイベントだけを選択に結び、補助サービス名から作らない
		if( automatic && !associated) {
			std::wstring log ;	// 明示されたイベントログの元名
			// 別ログ・別イベント名と現在観測の取り違えを拒否する
			if( readRegisteredField( row, 5U, log) != 0U || !sameStorePath( log, L"System") ||
			   readRegisteredField( row, 6U, namedSource) != 0U || namedSource.empty() ||
			   (host.events &&
				(!sameStorePath( namedSource, intended.auxiliary->addServiceFields[5U]) ||
				 !sameStorePath( namedSource, (*host.events)[1U].name)))) {
				return storeError( ERROR_NOT_SUPPORTED) ;
			}
		}
	}

	// 元サービスの基本型と役割が同じカーネル基準に一致することを要求する
	if( kernel.name.empty() || kernel.type != SERVICE_KERNEL_DRIVER ||
	   kernel.start != intended.start || kernel.errorControl != intended.errorControl ||
	   (automatic ? host.events && !sameStorePath( kernel.name, (*host.events)[0U].name)
				  : !sameStorePath( kernel.binary, intended.binaryTarget))) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	// 自動起動補助に付随する元関連サービスは明示のSCSI Miniport起動型に限定する
	if( automatic &&
	   (kernel.start != SERVICE_BOOT_START || !sameStorePath( kernelGroup, L"SCSI Miniport"))) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	driverLeaf = kernel.binary.substr( kernel.binary.find_last_of( L'\\') + 1U) ;
	// 一つの実SYS以外を同CATの一行へ解決しない
	if( !isRegisteredFileLeaf( driverLeaf, L".sys")) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	// 補助の元宣言を確認したときだけ、役割に合う配置と開始種別を保持する
	if( made.helper) {
		auto &helper = *made.helper ;	// 同じ元選択の補助サービスの全基本設定
		// 汎用サービスの型や異なるエラー制御を同じ構成へ分類しない
		if( helper.type != SERVICE_WIN32_OWN_PROCESS ||
		   helper.errorControl != intended.auxiliary->errorControl) {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}

		// 自動起動の場合は相対元EXEを正確な登録パッケージにだけ解決する
		if( automatic) {
			// 元ServiceBinaryが指定した通常EXEの候補名
			const auto leaf		   = helper.binary.substr( helper.binary.find_last_of( L'\\') + 1U) ;
			const auto packagePath = parent + leaf ;	// 同じ登録に属する補助EXEの完全位置
			// 現在ディレクトリを基点にせず、元DIRID 13の表記または完全位置だけを扱う
			if( helper.start != SERVICE_AUTO_START || !isRegisteredFileLeaf( leaf, L".exe") ||
			   (!sameStorePath( helper.binary, L".\\" + leaf) &&
				!sameStorePath( helper.binary, packagePath))) {
				return storeError( ERROR_NOT_SUPPORTED) ;
			}

			helper.binary = packagePath ;
		}
		// 従来は元Securityとセットの要求時起動・System32宛先を照合する
		else if( helper.start != SERVICE_DEMAND_START || helper.security.empty() ||
				!sameStorePath( helper.binary, intended.auxiliary->copy.target)) {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}
	}

	// 関連サービスが元登録に宣言したイベントの照合結果
	auto error =
		readRegisteredEvent( inf, eventSections[0U], kernel.name, driverLeaf,
							host.events ? &(*host.events)[0U] : nullptr, made.eventReferences[0U]) ;
	// 関連イベントの失敗または補助イベントの元不在をそのまま返す
	if( error != 0U || !made.helper) {
		return error ;
	}

	error = readRegisteredEvent( inf, eventSections[1U], automatic ? namedSource : made.helper->name,
								driverLeaf, host.events ? &(*host.events)[1U] : nullptr,
								made.eventReferences[1U], automatic) ;
	// 読取りが成立した場合に限り、元選択の自動起動補助に必要な全コピーを照合する
	if( automatic && error == 0U) {
		error = verifyRegisteredAutomaticCopies( inf, section, kernel, driverLeaf, *made.helper,
												*made.eventReferences[1U]) ;
		// 元SYSのDIRID 12配置先を確認した場合だけ署名前の構成を保持する
		if( error == 0U) {
			made.installedService = std::move( kernel.name) ;
			bootService			  = {std::move( kernel.binary), std::move( kernelGroup), kernel.type,
									 kernel.start, kernel.errorControl} ;
		}
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元証拠に使うファイルを同じWindowsルートに保持して完全hashを取得する
 * @param[in] windows 保持する正確なWindowsルート
 * @param[in] path 同じルート配下で構造を確認した元ファイルの完全位置
 * @param[in,out] directories 全親の保持handle群
 * @param[in,out] files 全元ファイルの保持handle群
 * @param[out] sha256 同じ読み取りで得た完全なSHA-256
 * @return 元ファイルとpathの保持とhashを確認した場合0、失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError pinAndHashStoreEvidence( const std::wstring &windows, const std::wstring &path,
									std::vector<StoreFile> &directories,
									std::vector<StoreFile> &files, std::wstring &sha256)
{
	// 親から順に保持した成否
	auto error = pinStoreAncestors( windows, path, directories) ;
	// 同じWindowsの親を保持できた場合だけ正確な元ファイルを固定する
	if( error == 0U) {
		error = pinStoreFile( path, false, files.emplace_back()) ;
	}

	return error != 0U ? error : computeFileSha256( path, sha256) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実選択の関連起動サービスを一意なAddServiceと署名INFの元構成に結ぶ
 * @param[in] inf 元バイトを保護した一時INFの解析ハンドル
 * @param[in] section 元の実選択節
 * @param[in] name Windowsが同選択で関連付けている現在サービス
 * @param[out] boot 照合した起動種別・元配置と基本構成。失敗時は使用しない
 * @param[out] facts 指定時に同じ署名元の選択節と関連サービスの全欄を追加する。null可
 * @return 現用の名前と単一の元起動構成が合致して0、未知又は不成立はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readRegisteredSingleBootService( HINF inf, const std::wstring &section,
											std::wstring_view					  name,
											RegisteredStorageBootServiceEvidence &boot,
											SelectedStorageServiceFacts			 *facts = nullptr)
{
	const auto services = section + L".Services" ;						// 実選択の元サービス節だけを使う
	const auto count	= SetupGetLineCountW( inf, services.c_str()) ;	// 元全行。参照や追加行も含む
	// 別サービス、追加作用、別文書への切替を同じ単一選択にしない
	if( count != 1L) {
		return storeError( count < 0L ? GetLastError() : ERROR_NOT_SUPPORTED) ;
	}

	INFCONTEXT	 row{} ;		// 唯一のAddService候補
	std::wstring key ;			// 元行の種類
	std::wstring associated ;	// 元サービス名
	std::wstring install ;		// 元サービス構成への参照
	int			 flags{} ;		// 関連サービスを示す元の全flags
	// 元宣言とWindowsの現用名の双方が同じ関連サービスを示すことを確認する
	if( !SetupGetLineByIndexW( inf, services.c_str(), 0U, &row) || SetupGetFieldCount( &row) < 3U ||
	   SetupGetFieldCount( &row) > 4U || readRegisteredField( row, 0U, key) != 0U ||
	   !sameStorePath( key, L"AddService") || readRegisteredField( row, 1U, associated) != 0U ||
	   !sameStorePath( name, associated) || !SetupGetIntField( &row, 2U, &flags) ||
	   flags != SPSVCINST_ASSOCSERVICE || readRegisteredField( row, 3U, install) != 0U ||
	   !isRegisteredSection( install)) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	RegisteredStorageHelperEvidence service ;	// 既存の元構成リーダーと共用する一時値
	std::wstring					group ;		// 元LoadOrderGroupの完全文字列
	// 同じ元サービスの構成と配置を共通の読取りへ渡す
	const auto error = readRegisteredService( inf, install, true, service, true, &group) ;
	// 共有の汎用サービスと区別し、明示されたブートミニポートだけを証拠にする
	if( error != 0U || service.type != SERVICE_KERNEL_DRIVER ||
	   service.start != SERVICE_BOOT_START || !sameStorePath( group, L"SCSI Miniport")) {
		return error != 0U ? error : storeError( ERROR_NOT_SUPPORTED) ;
	}

	boot = {std::move( service.binary), std::move( group), service.type, service.start,
			service.errorControl} ;
	// 元作用の検査を行う場合も証拠と同じ一行から全欄を取得する
	if( facts) {
		facts->selectedInstallSection = section ;
		facts->servicesSection		  = services ;
		facts->name					  = associated ;
		facts->installSection		  = install ;
		facts->group				  = boot.group ;
		facts->binaryTarget			  = boot.binary ;
		facts->flags				  = static_cast<std::uint32_t>( flags) ;
		facts->type					  = boot.type ;
		facts->start				  = boot.start ;
		facts->errorControl			  = boot.errorControl ;
		const auto fields			  = SetupGetFieldCount( &row) ;	// 同じ関連AddServiceの全欄数
		// 空欄やイベント参照を短縮せずに元の順序で保持する
		for( DWORD index = 1U; index <= fields; ++index) {
			// 同じ関連宣言の一欄を完全に取得する
			const auto read =
				readRegisteredField( row, index, facts->addServiceFields.emplace_back()) ;
			// 途中で読めない行を正常な元構成として公開しない
			if( read != 0U) {
				return read ;
			}
		}
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 単一の元コピーにあるSYSを関連サービスと同じDIRID 12の位置へ照合する
 * @param[in] inf 保護付き元INFの一時解析ハンドル
 * @param[in] section 元の実選択節
 * @param[in] target 同じWindowsの関連サービスが示す正規の完全SYS位置
 * @param[in] leaf 同じStoreの通常SYS葉名
 * @return 一意な同名コピーが成立すれば0、別位置、元媒体、形式の不一致はHRESULT
 */
//------------------------------------------------------------------------------
NativeError verifyRegisteredSingleBootCopy( HINF inf, const std::wstring &section,
										   const std::wstring &target, const std::wstring &leaf)
{
	std::optional<std::wstring> copy ;	// 選択が指定した一つの元コピー参照
	// 元コピーの宣言を一意な欄として読む
	const auto error = readRegisteredScalar( inf, section.c_str(), L"CopyFiles", copy) ;
	// 複数の役割やコピー不在を同じ起動SYSの配置としない
	if( error != 0U || !copy) {
		return error != 0U ? error : storeError( ERROR_NOT_SUPPORTED) ;
	}

	// OEMの直接コピーと同梱の名前付きコピーのいずれも元の媒体へ結ぶ
	if( sameStorePath( *copy, std::wstring{L"@"} + leaf)) {
		return verifyRegisteredCopyLocation( inf, L"", leaf, target, 12) ;
	}

	const auto	 security = *copy + L".Security" ;	// 該当時はコピー側の保護を変える追加作用
	INFCONTEXT	 row{} ;							// 元コピー節の唯一の行
	std::wstring file ;								// 同じ名前の元コピー先
	std::wstring key ;								// コピーのデータ行に指定されてはならないキー
	// 同じファイルの一行に明示されるコピーだけを読み取る
	if( !isRegisteredSection( *copy) || SetupGetLineCountW( inf, copy->c_str()) != 1L ||
	   SetupGetLineCountW( inf, security.c_str()) >= 0L ||
	   GetLastError() != ERROR_SECTION_NOT_FOUND ||
	   !SetupGetLineByIndexW( inf, copy->c_str(), 0U, &row) ||
	   readRegisteredField( row, 0U, key) != storeError( ERROR_INVALID_PARAMETER) ||
	   readRegisteredField( row, 1U, file) != 0U || !sameStorePath( file, leaf)) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	// 実際のWindows同梱行で使う空ソース、空一時名、元の保護フラグを区別する
	if( SetupGetFieldCount( &row) != 1U) {
		std::wstring source ;	// 空なら元コピー先と同じSYS
		std::wstring temp ;		// 一時コピー名の元欄
		int			 flags{} ;	// 元が指定した保護されたWindowsドライバーのコピー
		// 要求する三欄を削ったり、名前変更や追加フラグとして扱ったりしない
		if( SetupGetFieldCount( &row) != 4U || readRegisteredField( row, 2U, source) != 0U ||
		   readRegisteredField( row, 3U, temp) != 0U || !source.empty() || !temp.empty() ||
		   !SetupGetIntField( &row, 4U, &flags) || flags != COPYFLG_PROTECTED_WINDOWS_DRIVER_FILE) {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}
	}

	return verifyRegisteredCopyLocation( inf, *copy, leaf, target, 12) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ元CATに属するソースSYSと配置済みSYSを保護されたSCMの関連構成へ結び付ける
 * @param[in] inf 同じ元INFの保護付き一時解析ハンドル
 * @param[in] publishedPath 保持して照合済みの公開INFの完全位置
 * @param[in,out] made 同じ選択に結ぶ元署名とサービスの作業結果。失敗時は公開しない
 * @param[in,out] directories 登録の最終照合まで保持する親群
 * @param[in,out] files 登録の最終照合まで保持する元と配置済みのSYS
 * @return 配置先、全バイト、元CAT、SCM構成のすべてが成立して0、失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readRegisteredSingleBootMedia( HINF inf, const std::wstring &publishedPath,
										  RegisteredSingleBootStorageEvidence &made,
										  std::vector<StoreFile>			  &directories,
										  std::vector<StoreFile>			  &files)
{
	auto &package = made.package ;					// 元配布、実選択、同じ関連サービスの作業値
	auto &boot	  = package.bootService.emplace() ;	// 元の単一ブート構成
	// 正確な元選択が要求する関連サービスだけを現在構成へ結ぶ
	auto  error = readRegisteredSingleBootService( inf, package.installedSection,
												  package.installedService, boot) ;
	// 元サービスの役割から起動SYSを一意に読めた場合だけ現物へ進む
	if( error != 0U) {
		return error ;
	}

	const auto separator = boot.binary.rfind( L'\\') ;	// 元SYS完全位置に属する葉の境界
	// 裸の名前から正規コピー先を推測しない
	if( separator == boot.binary.npos) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	const auto					   leaf = boot.binary.substr( separator + 1U) ;	// 元SYSの葉
	// OSが返す元Windowsルートと現在の同一登録を照合するAPI
	const DriverStorePackageLookup lookup{&GetSystemWindowsDirectoryW,
										  &SetupGetInfDriverStoreLocationW} ;
	std::wstring				   windows ;	// 同じOSから取得する正規のルート
	error = readStoreWindowsDirectory( lookup, windows) ;
	// 元INFとサービスは同じWindowsの正規パスに限定する
	if( error != 0U || !isRegisteredStoreInf( windows, package.storeInf) ||
	   !isRegisteredFileLeaf( leaf, L".sys") ||
	   !sameStorePath( boot.binary, windows + L"\\System32\\drivers\\" + leaf)) {
		return error != 0U ? error : storeError( ERROR_NOT_SUPPORTED) ;
	}

	error = verifyRegisteredSingleBootCopy( inf, package.installedSection, boot.binary, leaf) ;
	// 正確な同名コピーの根拠がある場合だけ、元パッケージ直下を開く
	if( error != 0U) {
		return error ;
	}

	package.storeDriverBinary =
		package.storeInf.substr( 0U, package.storeInf.rfind( L'\\') + 1U) + leaf ;
	error = pinAndHashStoreEvidence( windows, package.storeDriverBinary, directories, files,
									package.driverSha256) ;
	ProtectedExecutableSnapshot source ;	// 既に取得した証拠があればその完全な再観測
	// 元SYS自体のAMD64形式と保護を、同じ元位置で独立に確認する
	if( error == 0U) {
		error = readDriverStoreStorageDriverSnapshot( package.storeDriverBinary, source) ;
	}

	// 配置済み実体の保護だけを別ファイルである元SYSに継承しない
	if( error != 0U || !source.existing || source.existing->sha256 != package.driverSha256 ||
	   (made.source.existing && made.source != source)) {
		return error != 0U ? error : storeError( ERROR_RETRY) ;
	}

	made.source = std::move( source) ;
	std::wstring deployedHash ;	// 同じ保持中の配置SYSの完全ハッシュ
	// 実配置も保護し、元CATメンバーから別ファイルへ切り替わらないようにする
	error = pinAndHashStoreEvidence( windows, boot.binary, directories, files, deployedHash) ;

	// 元SYSと現在の全バイトが同じものだけを現在の起動証拠にする
	if( error != 0U || deployedHash != package.driverSha256) {
		return error != 0U ? error : TRUST_E_BAD_DIGEST ;
	}

	const std::array members{package.storeDriverBinary, boot.binary} ;	// 同じ保持CATへ結ぶ二つのSYS
	error = verifyOfficialCatalogMembersCachedOnly( package.storeCatalog, members) ;
	// 署名内容が確認できた場合に限り、保護付きの現在値と一致するかを読む
	if( error == 0U) {
		error = readSystem32StorageDriverSnapshot( boot.binary, made.deployed) ;
	}

	// Windowsからの正式不在や元照合に失敗したSYSを現在の起動構成に結ばない
	if( error != 0U || !made.deployed.existing || made.deployed.existing->sha256 != deployedHash) {
		return error != 0U ? error : storeError( ERROR_RETRY) ;
	}

	error				= readStorageServiceEvidence( package.installedService, made.service) ;
	const auto &service = made.service ;	// 保護と安定性を確認した現在のSCM構成
	// 名前、配置、起動種別と全基本構成は同じ署名INFの宣言へ照合する
	if( error != 0U || !sameStorePath( service.name, package.installedService) ||
	   !matchesStorageBootImage( service.binary, boot.binary) || service.type != boot.type ||
	   service.start != boot.start || service.errorControl != boot.errorControl ||
	   !sameStorePath( service.group, boot.group) || !service.dependencies.empty()) {
		return error != 0U ? error : storeError( ERROR_RETRY) ;
	}

	std::wstring freshStore ;	// 同じ公開INFを終端で再度解決した元の位置
	error = lookupStoreInf( lookup, publishedPath, freshStore) ;
	// 構成の読取り中に別のパッケージへ切り替わった証拠を返さない
	return error != 0U
			   ? error
			   : (sameStorePath( freshStore, package.storeInf) ? 0U : storeError( ERROR_RETRY)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じCATの検証後にだけ元登録が示した現在サービスとSystemイベントを読む
 * @param[in] windows 登録パッケージを保持した同じWindowsルート
 * @param[in,out] made 元CATで確認済みの同一登録。現在EXEとの一致時に元ハッシュを保持する
 * @param[in,out] directories 取得中に保持する正規パスの親
 * @param[in,out] files 取得中に保持する元ファイルと現在イベントDLL
 * @param[out] events 検証中一時的に所有する二つの現在イベント
 * @param[out] auxiliary 検証中一時的に所有する現在補助の全状態
 * @return 元と現在の観測を取り違えずに読めた場合0、失敗はHRESULT
 * @note 呼出し元が出力全体を完了時に確定する。設定変更や共有所有の判断はしない
 */
//------------------------------------------------------------------------------
NativeError readRegisteredCurrentStorageHost( const std::wstring				   &windows,
											 RegisteredStoragePackageEvidence  &made,
											 std::vector<StoreFile>			   &directories,
											 std::vector<StoreFile>			   &files,
											 StorageSystemEventSnapshot		   &events,
											 StorageAutoStartAuxiliarySnapshot &auxiliary)
{
	// 署名付き元が確認した二つのイベント名と補助名を現在観測へ使う
	auto error = readRegisteredNamedStorageEventSnapshot( made, events) ;
	// 正式不在と、照会や保護の不成立を区別する
	if( error != 0U) {
		return error ;
	}

	// 現在するイベントは元宣言の型と値に結び、名前だけで照合しない
	for( std::size_t index = 0U; index < events.events.size(); ++index) {
		// 名前付きイベントに省略された資源は現在値を保持し、署名元を後続で照合する
		if( events.events[index].present &&
		   !matchesRegisteredStorageEvent( *made.eventReferences[index], events.events[index],
										  index == 1U)) {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}
	}

	error = readRegisteredAutoStartStorageAuxiliarySnapshot( *made.helper, auxiliary) ;
	// 旧版の正確な補助名・実パスの照合が成り立たなければ別サービスへ進まない
	if( error != 0U) {
		return error ;
	}

	// 実在する場合だけ登録元の配置とバイトに結んだ証拠を持つ
	if( auxiliary.service) {
		made.helper->deployedSha256 = made.helper->sourceSha256 ;
	}

	auto &named = *made.eventReferences[1U] ;	// 元の明示イベントと署名済み現在資源
	// 現在のイベントが旧DLLを参照する場合は、保持した元CATメンバーと現物を照合する
	if( events.events[1U].present && !named.resourceLeaf.empty()) {
		const auto deployed =
			windows + L"\\System32\\" + named.resourceLeaf ;	// 同じWindows上の元宛先
		std::wstring hash ;										// 現在DLLの完全SHA-256
		error = pinAndHashStoreEvidence( windows, deployed, directories, files, hash) ;
		// 同じCATに属する保護された元ファイルの全バイトに一致する場合だけ採用する
		if( error != 0U || hash != named.resourceSha256) {
			return error != 0U ? error : storeError( ERROR_INVALID_DATA) ;
		}

		ProtectedExecutableSnapshot observed ;	// 現物の保護と置換検出に使う完全観測
		error = readSystem32StorageEventResourceSnapshot( deployed, observed) ;
		// 同じ元CATに結び付く保護付きの現物だけを登録側の証拠にする
		if( error != 0U || !observed.existing || observed.existing->sha256 != hash ||
		   observed.existing->bytes != named.resourceBytes) {
			return error != 0U ? error : storeError( ERROR_INVALID_DATA) ;
		}

		named.deployedResource = std::move( observed) ;
	}

	StorageSystemEventSnapshot fresh ;	// 補助とファイルの検査後の現在イベント
	error = readRegisteredNamedStorageEventSnapshot( made, fresh) ;
	// 途中で登録、型、保護又は制御セットが変わった場合は旧証拠を返さない
	return error != 0U || fresh != events ? (error != 0U ? error : storeError( ERROR_RETRY)) : 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択デバイスが現在使うOEM INFと署名済みStoreの元作用を読取照合する
 * @param[in] publishedInf 同じ選択デバイスのWindows INF直下のOEM INF名
 * @param[in] installedBasicSection 同じ選択デバイスにWindowsが記録する元基本節名
 * @param[in] installedSectionExtension 同じ選択デバイスにWindowsが記録する拡張。元不在の場合は空
 * @param[in] intended 同じ選択デバイスへの検査済み更新候補。対象の二サービス名と正確な配置先を結ぶ
 * @param[in] host 保護付きの元観測と同デバイスの正確な関連サービス名
 * @param[out] evidence 元登録、実選択、署名とファイル結合が成立した場合だけ保持する比較用証拠
 * @param[in] lookup 同じWindowsの正規ルートと登録位置を照会する内部API表
 * @return 読取りと照合が成立すれば0、元読取り失敗や不明構成はHRESULT
 * @note キャッシュ内の証明書情報を使い、サービス、登録済みファイル、レジストリを変更しない
 */
//------------------------------------------------------------------------------
NativeError readRegisteredStoragePackageEvidenceImpl( std::wstring_view publishedInf,
													 std::wstring_view installedBasicSection,
													 std::wstring_view installedSectionExtension,
													 const SelectedStorageServiceFacts	&intended,
													 const RegisteredStorageObservation &host,
													 RegisteredStoragePackageEvidence	&evidence,
													 const DriverStorePackageLookup		&lookup)
{
	evidence			 = {} ;
	const bool automatic = host.automatic || host.current ;	// 自動起動補助を照合する場合true
	// 同一デバイスの確定済みOEM leafと元節、補助付きSCSI候補でだけ登録証拠を読む
	if( !lookup.windowsDirectory || !lookup.storeLocation || !isPublishedOemInf( publishedInf) ||
	   !isRegisteredSection( installedBasicSection) ||
	   (!installedSectionExtension.empty() &&
		(!installedSectionExtension.starts_with( L'.') ||
		 !isRegisteredSection( installedSectionExtension.substr( 1U)))) ||
	   !intended.auxiliary || !sameStorePath( intended.className, L"SCSIAdapter") ||
	   !sameStorePath( intended.classGuid, L"{4d36e97b-e325-11ce-bfc1-08002be10318}")) {
		return storeError( ERROR_INVALID_PARAMETER) ;
	}

	// 六欄の自動起動選択と同じ役割の現在観測だけを新しい経路へ渡す
	if( automatic &&
	   (!isRegisteredSection( host.installedService) ||
		intended.auxiliary->type != SERVICE_WIN32_OWN_PROCESS ||
		intended.auxiliary->start != SERVICE_AUTO_START || intended.auxiliary->copy.dirid != 13 ||
		intended.auxiliary->addServiceFields.size() != 6U ||
		!sameStorePath( intended.auxiliary->addServiceFields[4U], L"System") ||
		intended.auxiliary->addServiceFields[5U].empty())) {
		return storeError( ERROR_INVALID_PARAMETER) ;
	}

	try {
		RegisteredStoragePackageEvidence made ;	// 完了するまで外へ公開しない元証拠
		made.publishedInf			   = publishedInf ;
		made.installedBasicSection	   = installedBasicSection ;
		made.installedSectionExtension = installedSectionExtension ;
		made.installedSection = made.installedBasicSection + made.installedSectionExtension ;
		std::wstring windows ;	// 同じ照会が返したOEM INFとStoreの共通ルート
		// 同Windowsルートの確定結果
		auto		 error = readStoreWindowsDirectory( lookup, windows) ;
		// OSの帰属が不明なら類似するWindowsルートを採用しない
		if( error != 0U || !isRegisteredSection( made.installedSection)) {
			return error != 0U ? error : storeError( ERROR_INVALID_PARAMETER) ;
		}

		// OEM公開INFが存在する固定の完全位置
		const auto registeredInf = windows + L"\\INF\\" + made.publishedInf ;
		error					 = lookupStoreInf( lookup, registeredInf, made.storeInf) ;
		// 登録INFが対応するFileRepository以外を検索しない
		if( error != 0U || !isRegisteredStoreInf( windows, made.storeInf)) {
			return error != 0U ? error : storeError( ERROR_ACCESS_DENIED) ;
		}

		std::vector<StoreFile> directories ;		// 祖先変更を抑止して保持する
		std::vector<StoreFile> files ;				// 証拠の読取りと署名確認の終了まで元byteを保持する
		std::wstring		   registeredSha256 ;	// Windows INF直下の公開INF全byte
		error =
			pinAndHashStoreEvidence( windows, registeredInf, directories, files, registeredSha256) ;
		// 公開INFを固定できた場合だけ、対応する元INFを同じ方法で照合する
		if( error == 0U) {
			error =
				pinAndHashStoreEvidence( windows, made.storeInf, directories, files, made.infSha256) ;
		}

		// 同名や同文に正規化したINFを同じ原byteとして扱わない
		if( error != 0U || registeredSha256 != made.infSha256) {
			return error != 0U ? error : storeError( ERROR_INVALID_DATA) ;
		}

		// 保持した同じ署名対象の元INFをSetupAPIで読み取るハンドル
		const auto handle = SetupOpenInfFileW( made.storeInf.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr) ;
		// PNFや別の登録から読取失敗を補完しない
		if( handle == INVALID_HANDLE_VALUE) {
			return storeError( GetLastError()) ;
		}

		const std::unique_ptr<void, CloseRegisteredInf> inf{handle} ;	// 同元INFの読取りcontext
		// 元FileRepositoryパッケージの親。DIRID 13の解決にも使う
		const auto	 parent = made.storeInf.substr( 0U, made.storeInf.find_last_of( L'\\') + 1U) ;

		std::wstring catalog ;								// 元Versionで明示される正確なCAT leaf
		std::wstring driver ;								// 元関連サービスが宣言した正確なSYS leaf
		RegisteredStorageBootServiceEvidence bootService ;	// 元CATの確認前は公開しない起動構成
		error = readRegisteredVersion( inf.get(), intended.className, intended.classGuid, catalog) ;
		// Windowsの元選択が示すDDInstallの特定に成功した場合だけ元構成を読む
		if( error == 0U) {
			error = readRegisteredSelectedServices( inf.get(), made.installedSection, intended, host,
												   parent, driver, bootService, made) ;
		}

		// System32経路でも同じ選択の有効なコピー根拠を署名照合の前に確認する
		if( error == 0U && !automatic) {
			error = verifyRegisteredCopies( inf.get(), made.installedSection, intended.binaryTarget,
										   driver, made.helper) ;
		}

		// 選択の不明点をCATの署名だけで救済しない
		if( error != 0U) {
			return error ;
		}

		made.storeCatalog	   = parent + catalog ;
		made.storeDriverBinary = parent + driver ;
		error = pinAndHashStoreEvidence( windows, made.storeCatalog, directories, files,
										made.catalogSha256) ;
		// 所有する元CATと同じStoreのSYSを保持する
		if( error == 0U) {
			error = pinAndHashStoreEvidence( windows, made.storeDriverBinary, directories, files,
											made.driverSha256) ;
		}

		// CATやSYSの失敗を部分証拠にしない
		if( error != 0U) {
			return error ;
		}

		// 同CATへ結び付ける元ファイル集合
		std::vector<std::wstring> members{made.storeInf, made.storeDriverBinary} ;
		// 元選択が補助を明示した場合だけその元EXEを同じ署名へ結ぶ
		if( made.helper) {
			auto	  &helper = *made.helper ;	// 元選択に結合した補助サービスとコピー
			// 選択が配置するEXEの正確なleaf
			const auto leaf = helper.binary.substr( helper.binary.find_last_of( L'\\') + 1U) ;
			// 同じStore直下の通常EXE以外を照会しない
			if( !isRegisteredFileLeaf( leaf, L".exe")) {
				return storeError( ERROR_NOT_SUPPORTED) ;
			}

			helper.storePath = parent + leaf ;
			error = pinAndHashStoreEvidence( windows, helper.storePath, directories, files,
											helper.sourceSha256) ;
			// 元EXEの欠損時にSystem32の同名ファイルから補わない
			if( error != 0U) {
				return error ;
			}

			members.push_back( helper.storePath) ;

			// 同名の自動起動補助が実在する場合は現在ファイルと元パッケージを厳密に結ぶ
			if( host.automatic && host.automatic->service &&
			   sameStorePath( host.automatic->service->config.name, helper.name)) {
				// 同名や同バイトを持つ別のFileRepositoryパッケージを同じ元と扱わない
				if( !sameStorePath( host.automatic->executablePath, helper.storePath) ||
				   !host.executable.existing ||
				   host.executable.existing->sha256 != helper.sourceSha256) {
					return storeError( ERROR_INVALID_DATA) ;
				}

				std::wstring				currentPath ;	// 保護を再読取りした現在の正確なパス
				ProtectedExecutableSnapshot fresh ;			// 保持中の元EXEと比較する現在観測
				error = readDriverStoreExecutableSnapshot( host.automatic->service->config.binary,
														  leaf, currentPath, fresh) ;
				// 元コマンドと現在位置・バイト・保護のいずれかの不一致で証拠を返さない
				if( error != 0U || !sameStorePath( currentPath, helper.storePath) ||
				   fresh != host.executable) {
					return error != 0U ? error : storeError( ERROR_RETRY) ;
				}

				helper.deployedSha256 = helper.sourceSha256 ;
			}
			// 従来のSystem32共有コピーは同じ元byteを持つ登録だけに結び付ける
			else if( !automatic && host.executable.existing &&
					host.executable.existing->sha256 == helper.sourceSha256) {
				std::wstring installedHash ;	// 保持したSystem32ファイルの全byte
				// 同じWindowsの正確なコピー先
				const auto	 nativeSystem32 = windows + L"\\System32\\" + leaf ;
				// 挿し替え用照会が指す別環境のファイルには現在の証拠を付けない
				if( !sameStorePath( helper.binary, nativeSystem32)) {
					return storeError( ERROR_NOT_SUPPORTED) ;
				}

				error = pinAndHashStoreEvidence( windows, helper.binary, directories, files,
												installedHash) ;
				// 同じ署名対象にできる現在ファイルだけを採る
				if( error != 0U || installedHash != helper.sourceSha256 ||
				   installedHash != host.executable.existing->sha256) {
					return error != 0U ? error : storeError( ERROR_INVALID_DATA) ;
				}

				System32ExecutableSnapshot fresh ;	// 保持した現在ファイルの同一性と保護
				error = readSystem32ExecutableSnapshot( helper.binary, fresh) ;
				// 同一hashの別fileや権限の変化も認めない
				if( error != 0U || fresh != host.executable) {
					return error != 0U ? error : storeError( ERROR_RETRY) ;
				}

				helper.deployedSha256 = std::move( installedHash) ;
				members.push_back( helper.binary) ;
			}
		}

		// 元が旧イベント資源を指定した場合だけ、元DLLと該当する現在DLLを同じCATへ結ぶ
		if( automatic && !made.eventReferences[1U]->resourceLeaf.empty()) {
			auto	  &event  = *made.eventReferences[1U] ;		// 同じ元サービスが宣言した旧イベント資源
			const auto source = parent + event.resourceLeaf ;	// 旧元DLLの正確なファイル位置
			error =
				pinAndHashStoreEvidence( windows, source, directories, files, event.resourceSha256) ;
			// 現在版の元宣言やシステム標準DLLで不足する旧元DLLを補わない
			if( error != 0U) {
				return error ;
			}

			LARGE_INTEGER size{} ;	// ハッシュを計算した同じ保持中の元DLLの完全長
			// 別ファイルから元サイズを補ったり、空DLLを署名元と扱ったりしない
			if( !GetFileSizeEx( files.back().handle.get(), &size) || size.QuadPart <= 0) {
				return storeError( ERROR_INVALID_DATA) ;
			}

			event.resourceBytes = static_cast<std::uint64_t>( size.QuadPart) ;
			OfficialMappedFile pinned ;	// 同じ元DLLをコードとしてロードせず読む所有マッピング
			error = pinned.open( source, 64ULL * 1024ULL * 1024ULL) ;
			// 元署名に結び付く同じ固定バイトだけをイベント資源として検査する
			if( error == 0U) {
				error = verifyOfficialEventMessageResourceDll( pinned.bytes()) ;
			}

			// 読取りまたは形式が不明なら現用資源所有の根拠としない
			if( error != 0U) {
				return error ;
			}

			members.push_back( source) ;
			// 現在イベントが同じ元DLLを参照している場合は、そのSystem32実体まで照合する
			if( host.events && (*host.events)[1U].present) {
				// 同じWindowsルートの観測対象となるDLLの完全パス
				const auto	 deployed = windows + L"\\System32\\" + event.resourceLeaf ;
				std::wstring actual ;	// 現在System32から保持したDLLの全byte
				error = pinAndHashStoreEvidence( windows, deployed, directories, files, actual) ;
				// 異なるDLLや欠損を旧イベントの根拠として使わない
				if( error != 0U || actual != event.resourceSha256) {
					return error != 0U ? error : storeError( ERROR_INVALID_DATA) ;
				}

				members.push_back( deployed) ;
			}
		}

		error = verifyOfficialCatalogMembersCachedOnly( made.storeCatalog, members) ;
		// 同じ元CATをキャッシュ内で信頼できる場合だけ元登録の安定性を確かめる
		if( error != 0U) {
			return error ;
		}

		// 同じ元CATのINFとSYSに結び付いた起動構成と実選択の電源定義を保持する
		if( automatic) {
			made.bootService = std::move( bootService) ;
			error			 = readRegisteredRangedPowerSettings( inf.get(), made.installedSection,
																 made.powerSettings) ;
			// 元宣言の欠損や不明な形式を確認済みの空集合として渡さない
			if( error != 0U) {
				return error ;
			}
		}

		StorageSystemEventSnapshot currentEvents ;				// 署名付き元を根拠とする現在イベントの一時結果
		StorageAutoStartAuxiliarySnapshot currentAuxiliary ;	// 同じ元の現在補助構成の一時結果
		// 現在観測を求めた呼出しでは署名確認後にだけ元登録の名前で読取を行う
		if( host.current) {
			error = readRegisteredCurrentStorageHost( windows, made, directories, files,
													 currentEvents, currentAuxiliary) ;
			// 安定した元と現在の全照合ができない場合は出力しない
			if( error != 0U) {
				return error ;
			}
		}

		std::wstring resolved ;	// 読取り完了時にWindowsが解決する同OEM INFの元パス
		error = lookupStoreInf( lookup, registeredInf, resolved) ;
		// 元登録の切り替わりは前の検証を再利用しない
		if( error != 0U || !sameStorePath( resolved, made.storeInf)) {
			return error != 0U ? error : storeError( ERROR_RETRY) ;
		}

		// 同じhandleで保持した全祖先と原ファイルが同じ解決先にあることを最後に確認する
		for( const auto *group : {&directories, &files}) {
			// 元pathごとに再解析や別名への切替がなかったことを確認する
			for( const auto &file : *group) {
				error = checkPinnedStorePath( file) ;
				// 最初の不一致診断を返し、部分証拠を使用しない
				if( error != 0U) {
					return error ;
				}
			}
		}

		// 署名元、実位置、取得した現在値が揃った後で同時に公開する
		if( host.current) {
			host.current->events	= std::move( currentEvents) ;
			host.current->auxiliary = std::move( currentAuxiliary) ;
		}

		evidence = std::move( made) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}
} // namespace

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 一つのOEM元ファイルを保持して独立の保護と全ハッシュを読む
 * @param[in] windows 正規の登録が属する同じWindowsルート
 * @param[in] path 検査済みの公開INF又はパッケージ内の正規位置
 * @param[in] store trueはStoreの元ファイル
 * @param[in,out] directories 内容照合終了まで保持する全親
 * @param[in,out] files 内容照合終了まで保持する各元ファイル
 * @param[out] snapshot 同じ元ファイルの現在保護とハッシュ
 * @return 読取り成功0、位置、保護、又は元読取り失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError inspectPinnedOemFile( const std::wstring &windows, const std::wstring &path, bool store,
								 std::vector<StoreFile> &directories, std::vector<StoreFile> &files,
								 ProtectedExecutableSnapshot &snapshot)
{
	auto error = pinStoreAncestors( windows, path, directories) ;	// 元位置を保持するまでの親の確認
	// 元位置と先行親を正しく保持できた場合だけ同じファイルを固定する
	if( error == 0U) {
		error = pinStoreFile( path, false, files.emplace_back()) ;
	}

	return error == 0U ? readProtectedRegisteredPackageSnapshot( path, store, snapshot) : error ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windowsが同じOEM INFから選ぶ実DDInstallを元の登録属性に照合する
 * @param[in] inf 元バイトと完全一致する保護付きINFの解析ハンドル
 * @param[in] basicSection Windowsが記録した元基本節
 * @param[in] installedSection 同じデバイスの元装飾を結合した実選択節
 * @return OSの選択と元節の実在が一致して0、別選択や読取り失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError confirmRegisteredOemSection( HINF inf, const std::wstring &basicSection,
										const std::wstring &installedSection)
{
	std::array<wchar_t, MAX_PATH> actual{} ;	// Windowsが読む実選択節と終端
	DWORD						  required{} ;	// 終端を含んだWindowsの応答長
	// 自前の装飾優先順で他の機器向けの節を採用しない
	if( !SetupDiGetActualSectionToInstallW( inf, basicSection.c_str(), actual.data(),
										  static_cast<DWORD>( actual.size()), &required, nullptr)) {
		return storeError( GetLastError()) ;
	}

	// 元基本節の返答だけでは実際にその節が存在することを証明できない
	if( required <= 1U || required > actual.size() || actual[required - 1U] != L'\0' ||
	   !sameStorePath( {actual.data(), required - 1U}, installedSection) ||
	   SetupGetLineCountW( inf, installedSection.c_str()) <= 0L) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名付きOEMの電源、局所値とイベントの到達範囲を元選択だけに限定する
 * @param[in] inf 同じ署名INFの保護付き解析ハンドル
 * @param[in] facts 同じCATに所属する単一ブートの元構成
 * @param[in,out] package 同じ元選択の電源・イベント証拠の作業値
 * @return 元作用がすべて成立して0、解析や署名付き資源の不明はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readRegisteredOemBootEffects( HINF inf, SelectedStorageServiceFacts facts,
										 RegisteredStoragePackageEvidence &package)
{
	constexpr std::uint64_t DOCUMENT = 1U ;					// 同じ署名文書からだけ参照を解決する
	using Context					 = SystemInfContext ;	// 同じ選択に隣接する三つの実文脈
	std::vector<SystemInfRow> serviceRows ;					// 同じサービス構成節の原順の全行
	const SystemInfSection	  service{DOCUMENT, facts.installSection, Context::SERVICE,
									  Context::SERVICE, facts.name} ;	// 関連サービスの元構成
	auto error = readRegisteredInfRows( inf, service, serviceRows) ;	// 全欄を保つ元読取り
	// 元サービスの確認を個別の後続設定で補完しない
	if( error != 0U) {
		return error ;
	}

	// 構成節の元行を既存の型付き作用検査へそのまま渡す
	for( auto &row : serviceRows) {
		facts.directives.push_back( {row.ordinal, std::move( row.key), std::move( row.values)}) ;
	}

	// 同じ選択に属する基本節・機器節・サービス節を起点とする
	const std::array seeds{
		SystemInfSection{
			DOCUMENT, facts.selectedInstallSection, Context::DEVICE, Context::DEVICE, {}},
		SystemInfSection{DOCUMENT,
						 facts.selectedInstallSection + L".HW",
						 Context::HARDWARE,
						 Context::HARDWARE,
						 {}},
		SystemInfSection{
			DOCUMENT, facts.servicesSection, Context::SERVICES, Context::SERVICES, {}}} ;
	std::size_t		   registryRows{} ;	// 元レジストリ到達行の累積上限用
	SystemInfEffectApi api ;			// 選択文書と固定Windows資源だけを読取る同期API
	api.registryRows = &registryRows ;
	// 読取り中の同じINFだけを借用し、別配布のコピー作用を認めない
	api.read = [inf]( const SystemInfSection	   &source,
					 std::vector<SystemInfRow> &rows) -> NativeError {
		// 他の文書へ移る参照から同じ作用集合を作らない
		if( source.document != DOCUMENT) {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}

		const auto read = readRegisteredInfRows( inf, source, rows) ;	// 一節の元全行
		// CopyINFは別パッケージを必要とするためこの単一CATへ含めない
		if( read == 0U && source.context == SystemInfContext::DEVICE &&
		   std::ranges::any_of(
			   rows, []( const auto &row) { return sameStorePath( row.key, L"CopyINF") ; })) {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}

		return read ;
	} ;
	// 同じ署名元にある既知のWindowsメッセージ資源だけを非実行で照合する
	api.module = []( std::uint64_t document, std::wstring_view resource) -> NativeError {
		// 署名元が任意のパスや異なるイベント資源を指定できないようにする
		if( document != DOCUMENT ||
		   !sameStorePath( resource, L"%SystemRoot%\\System32\\IoLogMsg.dll")) {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}

		std::array<wchar_t, MAX_PATH> directory{} ;	// 同じWindowsの正規System32
		// Windowsが返したネイティブ位置の完全長
		const auto					  length =
			GetSystemDirectoryW( directory.data(), static_cast<UINT>( directory.size())) ;
		// 別のWindowsを探して署名検証へ渡さない
		if( length == 0U || length >= directory.size()) {
			return storeError( length == 0U ? GetLastError() : ERROR_INSUFFICIENT_BUFFER) ;
		}

		WindowsSystemFileTrust trust ;	// 固定Windows資源の署名証拠
		return verifyWindowsSystemFileCachedOnly(
			std::wstring{directory.data(), length} + L"\\IoLogMsg.dll", trust) ;
	} ;

	StorageInfEffects effects ;	// 元電源と局所の宣言をまとめて検査する
	std::uint32_t	  stage{} ;	// 既存の元作用検査が返す固定区分
	error = inspectSingleBootStorageInfContentEffects( seeds, api, facts, effects, stage) ;
	// 同じ配布の作用が閉じている場合だけ、関連イベントの元宣言を保持する
	if( error == 0U) {
		error = readRegisteredEvent( inf, facts.addServiceFields[3U], facts.name, facts.binarySource,
									nullptr, package.eventReferences[0U]) ;
	}

	// 一部の成功で元宣言が有効になったことにしない
	if( error == 0U) {
		package.powerSettings	   = std::move( effects.powerSettings) ;
		package.bootRegistryValues = std::move( effects.singleBootRegistryValues) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保持したOEMの元CATと一意な元INF・SYSを照合し、同じ選択の作用を読む
 * @param[in] inf 元バイトと完全一致する保護付き解析ハンドル
 * @param[in] windows 正規の公開INFとStoreが属する同じWindows
 * @param[in] published 固定した公開OEM INFの完全位置
 * @param[in,out] directories 元CAT、INF、SYSを含む先行親の保持領域
 * @param[in,out] files 解析と現在観測が終わるまで保持する元ファイル
 * @param[in,out] made 元署名と正確な選択の作業結果
 * @param[in] current 配置済みSYSとSCMを同じWindowsから照合する場合true
 * @return CATと各元証拠の照合で0、未知の元作用と読取りの不成立はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readRegisteredOemBootPackage( HINF inf, const std::wstring &windows,
										 const std::wstring					 &published,
										 std::vector<StoreFile>				 &directories,
										 std::vector<StoreFile>				 &files,
										 RegisteredSingleBootStorageEvidence &made, bool current)
{
	auto &package = made.package ;	// 元INFと実選択の作業値
	auto  error =
		confirmRegisteredOemSection( inf, package.installedBasicSection,
									package.installedSection) ;	// 記録された節とOS実選択の一致
	// 別の実選択を配布元の署名だけで採用しない
	if( error != 0U) {
		return error ;
	}

	SelectedStorageServiceFacts facts ;	// 元サービスと到達する同じ署名作用
	facts.className = L"SCSIAdapter" ;
	facts.classGuid = L"{4d36e97b-e325-11ce-bfc1-08002be10318}" ;
	std::wstring catalog ;	// INFの元Classと対応するAMD64のCAT葉
	error = readRegisteredVersion( inf, facts.className, facts.classGuid, catalog) ;
	// 元INFが宣言しないCATや、下位欄への代替を同じ配布としない
	if( error != 0U) {
		return error ;
	}

	// 元INFの正規パッケージ直下の同じ位置をCATとSYSに使う
	const auto parent	 = package.storeInf.substr( 0U, package.storeInf.rfind( L'\\') + 1U) ;
	package.storeCatalog = parent + catalog ;
	ProtectedExecutableSnapshot catalogSnapshot ;	// 同じCATの保護と完全ハッシュ
	error = inspectPinnedOemFile( windows, package.storeCatalog, true, directories, files,
								 catalogSnapshot) ;
	// 検証中のCATを別のパッケージへ切り替えない
	if( error != 0U) {
		return error ;
	}

	package.catalogSha256 = catalogSnapshot.existing->sha256 ;
	const std::array infMembers{published, package.storeInf} ;	// 同一CATに属すべき両INF
	error = verifyOfficialCatalogMembersCachedOnly( package.storeCatalog, infMembers) ;
	// 同じ元CATに属する署名付きINFの作用だけを読む
	if( error != 0U) {
		return error ;
	}

	auto &boot = package.bootService.emplace() ;	// 同じ元選択が示す唯一のブート構成
	error = readRegisteredSingleBootService( inf, package.installedSection, package.installedService,
											boot, &facts) ;
	// 署名付きの関連サービスと端末の登録名を取り違えない
	if( error != 0U) {
		return error ;
	}

	const auto slash = boot.binary.rfind( L'\\') ;	// 元サービスが指定したSYS名の境界
	// 裸の元名を正規配置と推測しない
	if( slash == boot.binary.npos ||
	   !isRegisteredFileLeaf( std::wstring_view{boot.binary}.substr( slash + 1U), L".sys")) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	facts.binarySource = boot.binary.substr( slash + 1U) ;
	facts.binary	   = boot.binary ;
	error			   = verifyRegisteredSingleBootCopy( inf, package.installedSection, boot.binary,
														facts.binarySource) ;
	// 同じ明示コピーへ結合できた場合だけ、元SYSの署名を確認する
	if( error != 0U) {
		return error ;
	}

	package.storeDriverBinary = parent + facts.binarySource ;
	error = inspectPinnedOemFile( windows, package.storeDriverBinary, true, directories, files,
								 made.source) ;
	// 署名付き元パッケージの直下にある保護済みAMD64 SYSだけを扱う
	if( error != 0U) {
		return error ;
	}

	const std::array sysMembers{package.storeDriverBinary} ;	// 同じCATに結合した元SYS
	error = verifyOfficialCatalogMembersCachedOnly( package.storeCatalog, sysMembers) ;
	// 不一致のハッシュや署名を元作用へ渡さない
	if( error != 0U) {
		return error ;
	}

	package.driverSha256 = made.source.existing->sha256 ;
	facts.binarySha256	 = package.driverSha256 ;
	facts.binaryBytes	 = made.source.existing->bytes ;
	error				 = readRegisteredOemBootEffects( inf, std::move( facts), package) ;
	// 元署名と作用が成立した場合だけ同じ保持中の元ファイルから現在の配置を照合する
	if( error == 0U && current) {
		error = readRegisteredSingleBootMedia( inf, published, made, directories, files) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じWindowsの正逆OEM登録と元の単一ブートパッケージを固定する
 * @param[in] publishedInf Windowsが記録した公開OEM INF葉名
 * @param[in] basicSection 同じ機器の元基本節
 * @param[in] extension 同じ機器の節装飾。不在の場合は空
 * @param[in] installedService 同じ機器が使用する関連サービス名
 * @param[out] evidence すべての指定照合が完了した証拠。失敗時は空
 * @param[in] lookup 同じWindowsの正逆登録対応を解決する同期API
 * @param[in] current 実Windowsの現在のSCMと配置も照合する場合true
 * @return 照合が成立した場合0、未知の元署名や登録の変更はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readRegisteredOemSingleBootStorageImpl(
	std::wstring_view publishedInf, std::wstring_view basicSection, std::wstring_view extension,
	std::wstring_view installedService, RegisteredSingleBootStorageEvidence &evidence,
	const DriverStorePackageLookup &lookup, bool current)
{
	evidence = {} ;
	// 元の登録名、同じサービスおよび正逆の対応を確認できる場合だけ読取りを開始する
	if( !lookup.windowsDirectory || !lookup.storeLocation || !lookup.publishedName ||
	   !isPublishedOemInf( publishedInf) || !isRegisteredSection( basicSection) ||
	   !isRegisteredSection( installedService) ||
	   (!extension.empty() &&
		(!extension.starts_with( L'.') || !isRegisteredSection( extension.substr( 1U))))) {
		return E_INVALIDARG ;
	}

	try {
		RegisteredSingleBootStorageEvidence made ;						// 終端まで全条件を成立させる作業値
		auto							   &package = made.package ;	// 同じ機器と登録INFの元属性
		package.publishedInf						= publishedInf ;
		package.installedBasicSection				= basicSection ;
		package.installedSectionExtension			= extension ;
		package.installedSection =
			package.installedBasicSection + package.installedSectionExtension ;
		package.installedService = installedService ;
		std::wstring windows ;												// 同じWindowsの登録位置を保持する正規ルート
		auto		 error = readStoreWindowsDirectory( lookup, windows) ;	// Windowsが返す元ルート
		// 正規ルートと実選択の完全名が明確な場合だけ読み始める
		if( error != 0U || !isRegisteredSection( package.installedSection)) {
			return error != 0U ? error : E_INVALIDARG ;
		}

		// 同じWindowsのINF直下の公開名だけを読取りに使う
		const auto					published = windows + L"\\INF\\" + package.publishedInf ;
		std::vector<StoreFile>		directories ;		// 全原本と両対応が成立するまで保持する親
		std::vector<StoreFile>		files ;				// 解析終了まで名前変更や書込みを共有しないファイル
		ProtectedExecutableSnapshot publicSnapshot ;	// 公開INF自身の独立した保護とハッシュ
		error = inspectPinnedOemFile( windows, published, false, directories, files, publicSnapshot) ;
		// 公開INFが正しく保護されている場合だけ、その同じパスからStoreを正引きする
		if( error == 0U) {
			error = lookupStoreInf( lookup, published, package.storeInf) ;
		}

		// 正引きの結果は同じWindowsのFileRepositoryの一パッケージに限定する
		if( error != 0U || !isRegisteredStoreInf( windows, package.storeInf)) {
			return error != 0U ? error : storeError( ERROR_INVALID_NAME) ;
		}

		ProtectedExecutableSnapshot storeSnapshot ;	// Store元INFの独立した保護とハッシュ
		error = inspectPinnedOemFile( windows, package.storeInf, true, directories, files,
									 storeSnapshot) ;
		// 固定した同じ元INFが公開位置へ戻る場合だけ、登録された配布として比較する
		if( error == 0U) {
			error = checkOemPublishedName( lookup, package.storeInf, published, publishedInf) ;
		}

		// 公開INFとStore元INFのハッシュとバイト数を照合する
		if( error != 0U || publicSnapshot.existing->sha256 != storeSnapshot.existing->sha256 ||
		   publicSnapshot.existing->bytes != storeSnapshot.existing->bytes) {
			return error != 0U ? error : TRUST_E_BAD_DIGEST ;
		}

		OfficialMappedFile publicView ;	// 保護中の公開INF全体を比較する読取りマッピング
		OfficialMappedFile storeView ;	// 同じ署名元の解析を開始するための元バイト
		error = publicView.open( published, publicSnapshot.existing->bytes) ;
		// 両原本の全バイトを固定できた場合だけ比較する
		if( error == 0U) {
			error = storeView.open( package.storeInf, storeSnapshot.existing->bytes) ;
		}

		// 離れた二位置の原バイトが同じINFであることを確認する
		if( error != 0U || !std::ranges::equal( publicView.bytes(), storeView.bytes())) {
			return error != 0U ? error : TRUST_E_BAD_DIGEST ;
		}

		package.infSha256 = storeSnapshot.existing->sha256 ;
		const auto leaf	  = std::wstring_view{package.storeInf}.substr(
			  // Storeにあった元INFの正規の葉
			  package.storeInf.rfind( L'\\') + 1U) ;
		const auto original = storeView.bytes() ;	// 同じ元ファイルの借用バイト列
		const std::span<const std::uint8_t> bytes{
			// バイト列をコピーAPIの符号なしバイト型に合わせる。マッピングは処理終了まで保持する
			reinterpret_cast<const std::uint8_t *>( original.data()), original.size()} ;
		// Windowsの実INFではなく、保護した同じバイトの一時コピーだけを解析する
		error = inspectProtectedInfCopy(
			leaf, bytes, package.infSha256, [&]( const std::wstring &copy) -> NativeError {
				const auto handle = SetupOpenInfFileW(
					copy.c_str(), nullptr, INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr) ;
				// 保護した元バイトを開けなければ、公開INFの解析へ切り替えない
				if( handle == INVALID_HANDLE_VALUE) {
					return storeError( GetLastError()) ;
				}

				const std::unique_ptr<void, CloseRegisteredInf> inf{handle} ;	// 元INFの一時解析
				return readRegisteredOemBootPackage( inf.get(), windows, published, directories,
													files, made, current) ;
			}) ;
		// 同じ登録が終端まで維持された場合だけ元証拠を返す
		if( error != 0U) {
			return error ;
		}

		std::wstring freshStore ;	// 保持した全ファイルを使った後の正引き
		error = lookupStoreInf( lookup, published, freshStore) ;
		// 元の配布とは異なる対応を前の署名の成功で救済しない
		if( error != 0U || !sameStorePath( freshStore, package.storeInf)) {
			return error != 0U ? error : storeError( ERROR_RETRY) ;
		}

		error = checkOemPublishedName( lookup, freshStore, published, publishedInf) ;
		// 公開名の逆対応も終端まで同じ場合だけ観測全体を発行する
		if( error == 0U) {
			evidence = std::move( made) ;
		}

		return error ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief SCMの元バイナリが同じWindows内の署名済みSYS配置先を指すか照合する
 * @param[in] command SCMが返した完全値
 * @param[in] target 保護付き読取りで同じWindowsのdrivers直下と確認した正規絶対位置
 * @return 絶対位置又は同じWindowsに解決する既知表記に完全一致すればtrue
 */
//------------------------------------------------------------------------------
bool matchesStorageBootImage( std::wstring_view command, std::wstring_view target) noexcept
{
	// 通常の絶対位置は追加文字や引用符を除かず全体を照合する
	if( sameStorePath( command, target)) {
		return true ;
	}

	constexpr std::wstring_view parent{L"System32\\drivers\\"} ;	// 元コピー先の標準相対親
	const auto					slash = target.rfind( L'\\') ;		// ファイル名の前の区切り
	// 正規親と通常葉が判明する場合だけWindows起点の既知表記を比較する
	if( slash == target.npos || slash + 1U < parent.size()) {
		return false ;
	}

	const auto relativePath = target.substr( slash + 1U - parent.size()) ;	// 同じSYSへの相対表記
	// 元配置から独立した相対パスを解釈しない
	if( !sameStorePath( relativePath.substr( 0U, parent.size()), parent)) {
		return false ;
	}

	// 既知のルート接頭辞を一つだけ外し、その後も元位置に完全一致させる
	for( const std::wstring_view prefix : {L"\\SystemRoot\\", L"%SystemRoot%\\"}) {
		// 部分一致や他の環境変数で解決する起点を認めない
		if( sameStorePath( command.substr( 0U, prefix.size()), prefix)) {
			return sameStorePath( command.substr( prefix.size()), relativePath) ;
		}
	}

	return sameStorePath( command, relativePath) ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 固定したNVMeと別のPCI文書から選択作用、電源宣言と起動構成を読取る
 * @param[in] nvme 元バイトを保護したNVMeの一時解析ハンドル
 * @param[in] origin 保持中のNVMeの元CATと公開INFの証拠
 * @param[in,out] made 二つの署名文書、電源宣言と起動構成を結ぶ作業値。失敗時は公開しない
 * @return 元依存、電源宣言、起動構成が一致して0、不成立はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readRegisteredNvmeInboxSelection( HINF nvme, const WindowsSystemFileTrust &origin,
											 RegisteredSingleBootStorageEvidence &made)
{
	const auto local =
		// 必須のPCI節と同名の曖昧な局所節
		SetupGetLineCountW( nvme, L"PciForceSBR.HW") ;
	// 参照元にも同名節がある場合は、署名済みのPCIだけが所有すると扱わない
	if( local >= 0L || GetLastError() != ERROR_SECTION_NOT_FOUND) {
		return storeError( local >= 0L ? ERROR_DUP_NAME : GetLastError()) ;
	}

	// 依存文書の元ファイルと証拠を全作用の読取り終了まで保持する
	return inspectVerifiedWindowsInboxInf( L"pci.inf", [&]( std::wstring_view,
														  const WindowsSystemFileTrust &trust,
														  std::span<const std::uint8_t> bytes) {
		// 公開INFを解析用に開かず、署名済み原バイトのコピーだけをSetupAPIへ渡す
		return inspectProtectedInfCopy(
			L"pci.inf", bytes, trust.fileSha256, [&]( const std::wstring &copy) -> NativeError {
				const auto handle = SetupOpenInfFileW(
					copy.c_str(), nullptr, INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr) ;
				// 元と同一の一時ファイル以外の解析結果で補わない
				if( handle == INVALID_HANDLE_VALUE) {
					return storeError( GetLastError()) ;
				}

				const std::unique_ptr<void, CloseRegisteredInf> pci{handle} ;	// 同じ依存文書の解析
				constexpr std::uint64_t NVME = 1U ;								// 同じ同期処理に限定する元NVMeのID
				constexpr std::uint64_t PCI	 = 2U ;								// 同じ同期処理に限定する元PCIのID
				SystemInfEffectApi		api ;									// 署名を固定した二つの文書の行読取り
				api.storNvmeInboxDocument = NVME ;
				api.pciNvmeInboxDocument  = PCI ;
				// 各文書の解析ハンドルは同期の全行照合の間だけ借用する
				api.read = [&]( const SystemInfSection &source, std::vector<SystemInfRow> &rows) {
					// 既知の二文書以外の節を別のファイルから補完しない
					if( source.document != NVME && source.document != PCI) {
						return storeError( ERROR_NOT_SUPPORTED) ;
					}

					return readRegisteredInfRows( source.document == NVME ? nvme : pci.get(), source,
												 rows) ;
				} ;

				auto error = readVerifiedNvmeInboxPowerSettings( api, made.package.powerSettings) ;
				// PCI文書も元のまま保持した間に現在の起動構成と配置を照合する
				if( error == 0U) {
					std::vector<StoreFile> directories ;	// 配置の最終照合を行うまで保持する親
					std::vector<StoreFile> files ;			// 同じ元と配置のSYS
					error = readRegisteredSingleBootMedia( nvme, origin.filePath, made, directories,
														  files) ;
				}

				// 元選択全体が成立した場合に限り、PCIの署名を同じ証拠へ結ぶ
				if( error == 0U) {
					made.hardwareDependency = trust ;
				}

				return error ;
			}) ;
	}) ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 現用同梱NVMeの実節を元CAT、現在の起動サービス、配置SYSと電源宣言へ照合する
 * @param[in] publishedInf 同じ機器に現在登録されている公開INFの葉名
 * @param[in] selectedSection 基本節と装飾を合わせたWindowsの実選択
 * @param[in] installedService 同じ機器から独立して読んだ現在の関連サービス
 * @param[out] evidence 同じ文書と現在構成がすべて成立した場合だけ保持する証拠。失敗時は空
 * @return 元署名と役割の照合で0、未知の選択や不成立はHRESULT
 * @note 機器属性と選択の再読取り、全共有先、現在のローカル値や導入資格は呼出し側で確認する
 */
//------------------------------------------------------------------------------
NativeError readRegisteredInboxSingleBootStorageEvidence(
	std::wstring_view publishedInf, std::wstring_view selectedSection,
	std::wstring_view installedService, RegisteredSingleBootStorageEvidence &evidence)
{
	evidence = {} ;
	// 既存規則で確認する正確な選択と関連サービスだけを読み取る
	if( !sameStorePath( publishedInf, L"stornvme.inf") ||
	   !sameStorePath( selectedSection, L"Stornvme_Inst") ||
	   !sameStorePath( installedService, L"stornvme")) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	RegisteredSingleBootStorageEvidence made ;	// 同じ現用署名がすべて成立するまで保持する
	// 元のWindows INF、StoreとCATの同じ実体を保持してから解析する
	const auto							error = inspectVerifiedWindowsInboxInf(
		 publishedInf, [&]( std::wstring_view store, const WindowsSystemFileTrust &trust,
						   std::span<const std::uint8_t> bytes) {
			 auto &package = made.package ;	// 同じ元署名と選択の作業値
			 package.publishedInf		   = publishedInf ;
			 package.installedBasicSection = selectedSection ;
			 package.installedSection	   = selectedSection ;
			 package.installedService	   = installedService ;
			 package.storeInf			   = store ;
			 package.infSha256			   = trust.fileSha256 ;
			 package.storeCatalog		   = trust.catalogPath ;
			 package.catalogSha256		   = trust.catalogSha256 ;
			 // 元のINFキャッシュを削除せず、保護した同じバイトの一時コピーから読む
			 return inspectProtectedInfCopy(
				 publishedInf, bytes, trust.fileSha256,
				 [&]( const std::wstring &copy) -> NativeError {
					 const auto handle = SetupOpenInfFileW(
						 copy.c_str(), nullptr, INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr) ;
					 // 選択の解析失敗を類似文書へ切り替えない
					 if( handle == INVALID_HANDLE_VALUE) {
						 return storeError( GetLastError()) ;
					 }

					 const std::unique_ptr<void, CloseRegisteredInf> nvme{
						 handle} ;	// 元の同一バイトを解析
					 return readRegisteredNvmeInboxSelection( nvme.get(), trust, made) ;
				 }) ;
		 }) ;

	// 元作用、署名と現在の起動構成がそろった場合だけ同じ証拠を公開する
	if( error == 0U) {
		evidence = std::move( made) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正逆のOEM登録対応を選択節、元CAT、元SYSと元電源宣言へ結び付ける
 * @param[in] publishedInf Windowsが記録した公開OEM INF葉名
 * @param[in] basicSection 同じ機器の元基本節
 * @param[in] extension 同じ機器の節装飾。不在の場合は空
 * @param[in] installedService 同じ機器が使用する関連サービス名
 * @param[out] evidence 成功時は元署名、元SYSと元作用。現在SCMと配置先は未観測。失敗時は空
 * @param[in] lookup 同じWindowsのルートと正逆の登録対応を読む同期API
 * @return 元署名の照合で0、登録、取得、元作用の不成立はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readRegisteredOemSingleBootStorageOrigin( std::wstring_view publishedInf,
													 std::wstring_view basicSection,
													 std::wstring_view extension,
													 std::wstring_view installedService,
													 RegisteredSingleBootStorageEvidence &evidence,
													 const DriverStorePackageLookup		 &lookup)
{
	return readRegisteredOemSingleBootStorageImpl( publishedInf, basicSection, extension,
												  installedService, evidence, lookup, false) ;
}

//------------------------------------------------------------------------------
/**
 * @brief OEMの登録原本を実Windowsの現在のブートサービスと配置済みSYSまで照合する
 * @param[in] publishedInf 同じ機器の公開OEM INF葉名
 * @param[in] basicSection Windowsが記録した元基本節
 * @param[in] extension Windowsが記録した節装飾。不在の場合は空
 * @param[in] installedService 同じ機器が使用する関連サービス名
 * @param[out] evidence 現在のSCM、元SYS、配置と元署名が成立した証拠。失敗時は空
 * @return すべて成立時0、OEM形式ではない公開名はERROR_NOT_SUPPORTEDのHRESULT、それ以外は読取り診断
 * @note 同じ機器の属性は呼出側で再読取りし、共有構成の変更を許可しない
 */
//------------------------------------------------------------------------------
NativeError readRegisteredOemSingleBootStorageEvidence(
	std::wstring_view publishedInf, std::wstring_view basicSection, std::wstring_view extension,
	std::wstring_view installedService, RegisteredSingleBootStorageEvidence &evidence)
{
	evidence = {} ;
	// 他の同梱INFをOEMとして読み取らず、未対応の現用登録として返す
	if( !isPublishedOemInf( publishedInf)) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	const DriverStorePackageLookup lookup{
		// 実配置の観測はWindows自身の正逆対応に限定する
		&GetSystemWindowsDirectoryW, &SetupGetInfDriverStoreLocationW, &SetupGetInfPublishedNameW} ;
	return readRegisteredOemSingleBootStorageImpl( publishedInf, basicSection, extension,
												  installedService, evidence, lookup, true) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ現用機器の公開INFと元Store INFを固定する読み取り所有者
 */
//------------------------------------------------------------------------------
struct PinnedRegisteredInfPair {
	/// 同じWindowsの正規ルート
	std::wstring				windows ;
	/// 公開OEM INFの完全位置
	std::wstring				published ;
	/// その公開INFに対応する唯一のDriver Store内の完全位置
	std::wstring				storeInf ;
	/// 公開INFの保護と全ハッシュ
	ProtectedExecutableSnapshot publishedFile ;
	/// 元Store INFの保護と全ハッシュ
	ProtectedExecutableSnapshot storeFile ;
	/// 同じWindowsで保持する親ハンドル群
	std::vector<StoreFile>		directories ;
	/// 検査中に読み取りで固定する元ファイル群
	std::vector<StoreFile>		files ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief Windowsの公開名とStore内の元INFを双方向・内容一致で固定する
 * @param[in] lookup 同じWindowsのルート、Store位置、公開名を得る正規API
 * @param[in] publishedInf 元現用デバイスから読んだ検査済み公開OEM INF名
 * @param[out] source 成功まで非公開の元ファイル保護と保持ハンドル
 * @return 両位置と同一元バイトが成立して0、失敗、不一致はHRESULT
 */
//------------------------------------------------------------------------------
static NativeError pinRegisteredOemInfPair( const DriverStorePackageLookup &lookup,
										   std::wstring_view			   publishedInf,
										   PinnedRegisteredInfPair		  &source)
{
	auto error =
		// 同じWindowsの元ルートを確定する
		readStoreWindowsDirectory( lookup, source.windows) ;
	// 不明なWindowsの位置を推測して元配布を読み取らない
	if( error != 0U) {
		return error ;
	}

	source.published = source.windows + L"\\INF\\" + std::wstring{publishedInf} ;
	error = inspectPinnedOemFile( source.windows, source.published, false, source.directories,
								 source.files, source.publishedFile) ;
	// 公開側が保護されている場合だけWindowsでStore側を解決する
	if( error == 0U) {
		error = lookupStoreInf( lookup, source.published, source.storeInf) ;
	}

	// 同じWindowsのFileRepository内の一パッケージ直下INFにだけ進む
	if( error != 0U || !isRegisteredStoreInf( source.windows, source.storeInf)) {
		return error != 0U ? error : storeError( ERROR_INVALID_NAME) ;
	}

	error = inspectPinnedOemFile( source.windows, source.storeInf, true, source.directories,
								 source.files, source.storeFile) ;
	// 同じ公開OEM名への逆対応も必要とする
	if( error == 0U) {
		error = checkOemPublishedName( lookup, source.storeInf, source.published, publishedInf) ;
	}

	// 公開側を元パッケージと同じ内容に両方結び付ける
	if( error != 0U || source.publishedFile.existing->sha256 != source.storeFile.existing->sha256 ||
	   source.publishedFile.existing->bytes != source.storeFile.existing->bytes) {
		return error != 0U ? error : TRUST_E_BAD_DIGEST ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現用INFと同じ元ハンドルが保持されたまま公開名の正逆を再照合する
 * @param[in] lookup 元のWindows位置照会API
 * @param[in] publishedInf 元現用機器の公開INF名
 * @param[in] source 固定した元INFとStoreの関係・ハンドル
 * @return 同じ正逆対応の場合0、変化またはWindowsの元エラーはHRESULT
 */
//------------------------------------------------------------------------------
static NativeError recheckPinnedRegisteredOemInfPair( const DriverStorePackageLookup &lookup,
													 std::wstring_view				 publishedInf,
													 const PinnedRegisteredInfPair	&source)
{
	std::wstring freshStore ;													// 全ファイルを保持したまま再照会する正引き結果
	const auto error = lookupStoreInf( lookup, source.published, freshStore) ;	// 同じ元公開名の再解決
	// 別Storeへ変化した場合に元署名を新しい登録へ継承しない
	if( error != 0U || !sameStorePath( freshStore, source.storeInf)) {
		return error != 0U ? error : storeError( ERROR_RETRY) ;
	}

	return checkOemPublishedName( lookup, freshStore, source.published, publishedInf) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現用Displayの登録INFと同じ署名配布にある補助EXEを確認する
 * @param[in] publishedInf 当該現用デバイスから読んだ公開OEM INF名
 * @param[in] basicSection 同じデバイスの元基本節名
 * @param[in] extension 同じデバイスの実装飾。Windowsで未指定のとき空
 * @param[in] associatedService 同じデバイスの関連サービス名
 * @param[in] intended 署名候補から確認した更新対象の同名補助とイベント源
 * @param[out] evidence 成功時の元登録・同一CAT・完全ハッシュ。失敗時は空
 * @return 公開名の正逆・元byte・実選択・CATメンバー照合の成立で0、それ以外はHRESULT
 * @note 通信や登録を行わない。現SCM・イベント源と他デバイスの所有は後段で確認する
 */
//------------------------------------------------------------------------------
NativeError readRegisteredDisplayAuxiliaryPackage( const std::wstring_view publishedInf,
												  const std::wstring_view basicSection,
												  const std::wstring_view extension,
												  const std::wstring_view associatedService,
												  const OfficialDisplayAuxiliaryService &intended,
												  RegisteredDisplayAuxiliaryPackage		&evidence)
{
	// 現用の作業値と元候補を同じ格納へ重ねない
	if( &intended == &evidence.declaration) {
		return E_INVALIDARG ;
	}

	evidence = {} ;
	// 同じ現用機器の明確な公開名と実装飾だけを受ける
	if( !isPublishedOemInf( publishedInf) || !isRegisteredSection( basicSection) ||
	   !isRegisteredSection( associatedService) ||
	   (!extension.empty() &&
		(!extension.starts_with( L'.') || !isRegisteredSection( extension.substr( 1U))))) {
		return E_INVALIDARG ;
	}

	try {
		RegisteredDisplayAuxiliaryPackage made ;	// 全照合まで呼出し側へ出さない証拠
		made.publishedInf	   = publishedInf ;
		made.installedSection  = std::wstring{basicSection} + std::wstring{extension} ;
		made.associatedService = associatedService ;
		const DriverStorePackageLookup lookup{	// 正規Windowsルートと元登録の正逆対応にだけ使用する
											  &GetSystemWindowsDirectoryW,
											  &SetupGetInfDriverStoreLocationW,
											  &SetupGetInfPublishedNameW} ;
		// 連結後の実節もWindowsの元節名に限定する
		if( !isRegisteredSection( made.installedSection)) {
			return E_INVALIDARG ;
		}

		PinnedRegisteredInfPair source ;										// 公開名とStoreの元実体を保持する
		auto error = pinRegisteredOemInfPair( lookup, publishedInf, source) ;	// 同元の正逆照合診断
		// 他のINFから同じサービス名を推測して補わない
		if( error != 0U) {
			return error ;
		}

		made.storeInf = source.storeInf ;

		const auto handle = SetupOpenInfFileW( made.storeInf.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  nullptr) ;	// 同元byteの読取専用照会
		// 固定した元INFを開けない場合にPNFや別配布を使わない
		if( handle == INVALID_HANDLE_VALUE) {
			return storeError( GetLastError()) ;
		}

		const std::unique_ptr<void, CloseRegisteredInf> inf{handle} ;	// 元INFの解析所有者
		error = confirmRegisteredOemSection( inf.get(), std::wstring{basicSection},
											made.installedSection) ;
		std::wstring catalog ;	// 現用元INFが指定するAMD64用CATの一葉
		// 同じ実節のクラスと元CATを確認する
		if( error == 0U) {
			error = readRegisteredVersion( inf.get(), L"Display",
										  L"{4d36e968-e325-11ce-bfc1-08002be10318}", catalog) ;
		}

		// 既存側が同じ補助サービスとイベント源の両方を実選択節で宣言することを確認する
		if( error == 0U) {
			error = readRegisteredDisplayAuxiliaryDeclaration( made.storeInf, made.installedSection,
															  made.associatedService, intended,
															  made.declaration, &made.components) ;
		}

		// 選択にない補助や別ファイルを元CATで検査しない
		if( error != 0U) {
			return error ;
		}

		const auto parent =
			// 同パッケージの親
			made.storeInf.substr( 0U, made.storeInf.rfind( L'\\') + 1U) ;
		const auto catalogPath = parent + catalog ;	// 元CATに結合する完全位置
		made.executablePath	   = parent + made.declaration.binarySource ;
		error = inspectPinnedOemFile( source.windows, catalogPath, true, source.directories,
									 source.files, made.catalogFile) ;
		// 同じパッケージのサブディレクトリまで保持し、代替の実行ファイルを検査しない
		if( error == 0U) {
			error = pinAndHashStoreEvidence( source.windows, made.executablePath, source.directories,
											source.files, made.executableSha256) ;
		}

		// 元INFと補助EXEの両方を同じ信頼済みCATに結び、個別の署名結果で補完しない
		if( error == 0U) {
			const std::array members{made.storeInf,
									 made.executablePath} ;	// 同じ元CATの必須二メンバー
			error = verifyOfficialCatalogMembersCachedOnly( catalogPath, members) ;
		}

		// 検査中の元公開対応の差し替えを新しい所有と扱わない
		if( error == 0U) {
			error = recheckPinnedRegisteredOemInfPair( lookup, publishedInf, source) ;
		}

		// すべて同じパッケージへ結び付いた場合だけ後段の所有検査へ渡す
		if( error == 0U) {
			made.publishedFile = std::move( source.publishedFile) ;
			made.storeFile	   = std::move( source.storeFile) ;
			evidence		   = std::move( made) ;
		}

		return error ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 現用SWCの主ID・実DDInstall・署名配布をWindows登録から照合する
 * @param[in] publishedInf 当該present子の公開OEM INF名
 * @param[in] basicSection 当該present子のDriverInfSection。記録によっては装飾込み
 * @param[in] extension 当該現用の装飾。未指定は空
 * @param[in] hardwareId 現用子から観測した唯一の主Hardware ID
 * @param[out] evidence 全照合に成功した元署名・実節。失敗時は空
 * @return 公開名の正逆、同じバイト、現在Modelsと署名の照合成功で0、その他HRESULT
 * @note 読取専用。候補との共用判定、ソフトウェア実行、導入は行わない
 */
//------------------------------------------------------------------------------
NativeError readRegisteredSoftwareComponentPackage( std::wstring_view				   publishedInf,
												   std::wstring_view				   basicSection,
												   std::wstring_view				   extension,
												   std::wstring_view				   hardwareId,
												   RegisteredSoftwareComponentPackage &evidence)
{
	evidence = {} ;
	// 現用子の一意な公開名と基本節、実装飾が確定している場合にだけ照合する
	if( !isPublishedOemInf( publishedInf) || !isRegisteredSection( basicSection) ||
	   (!extension.empty() &&
		(!extension.starts_with( L'.') || !isRegisteredSection( extension.substr( 1U))))) {
		return E_INVALIDARG ;
	}

	try {
		RegisteredSoftwareComponentPackage made ;	// 署名元と現用選択を全て読むまで非公開
		made.installedSection = std::wstring{basicSection} + std::wstring{extension} ;
		const DriverStorePackageLookup lookup{
			&GetSystemWindowsDirectoryW, &SetupGetInfDriverStoreLocationW,
			&SetupGetInfPublishedNameW} ;										// 同じWindowsでの登録元の正逆対応
		PinnedRegisteredInfPair source ;										// 保護した公開とStoreの同じ元INFを保持する
		auto error = pinRegisteredOemInfPair( lookup, publishedInf, source) ;	// 同じ元INFの診断
		// 未確認または変更された公開名から別の子を採用しない
		if( error != 0U) {
			return error ;
		}

		error = verifyRegisteredSoftwareComponentModel( source.storeInf, hardwareId, basicSection,
													   made.installedSection) ;
		// 現用子の主Modelsと実選択に結合しない元INFは署名だけで採用しない
		if( error != 0U) {
			return error ;
		}

		const auto handle = SetupOpenInfFileW( source.storeInf.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  nullptr) ;	// 元CAT宣言を読む元実体
		// 既に固定したStore元INF以外を使わない
		if( handle == INVALID_HANDLE_VALUE) {
			return storeError( GetLastError()) ;
		}

		const std::unique_ptr<void, CloseRegisteredInf> inf{handle} ;	// 元INFのSetupAPI所有者
		std::wstring									catalog ;		// 同じ元INFが指定する一点のCAT
		error = readRegisteredVersion( inf.get(), L"SoftwareComponent",
									  L"{5c4c3332-344d-483c-8739-259e934c9cc8}", catalog) ;
		// 現用クラスの元CATが不成立なら個別の元ファイル信頼で代用しない
		if( error != 0U) {
			return error ;
		}

		const auto catalogPath = source.storeInf.substr( 0U, source.storeInf.rfind( L'\\') + 1U) +
								 catalog ;	// 同じ元パッケージのCAT完全位置
		error = inspectPinnedOemFile( source.windows, catalogPath, true, source.directories,
									 source.files, made.catalogFile) ;
		// 所有と保護が確認された元CATだけで現用子のINFを照合する
		if( error == 0U) {
			error = verifyOfficialCatalogMembersCachedOnly( catalogPath,
														   std::span{&source.storeInf, 1U}) ;
		}

		// 位置と元CATの照合後にWindowsの正逆対応も再確認する
		if( error == 0U) {
			error = recheckPinnedRegisteredOemInfPair( lookup, publishedInf, source) ;
		}

		// 保護、元署名、現在節が揃った場合だけ全証拠を渡す
		if( error == 0U) {
			made.publishedFile = std::move( source.publishedFile) ;
			made.storeFile	   = std::move( source.storeFile) ;
			made.storeInf	   = std::move( source.storeInf) ;
			evidence		   = std::move( made) ;
		}

		return error ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同じWindowsの保護された公開INFを読み、対象Displayの作用との重複を調べる
 * @param[in] leaf 今のWindowsから得た公開INFまたはInclude INFの単独名
 * @param[in] installedSection 現用機器の実DDInstall。空なら依存側と拡張の全節を保守的に調べる
 * @param[in] target 同じ選択のサービス名とApplicationイベント源
 * @param[out] result 読取り成功時の作用と外部依存。失敗時は空
 * @param[out] file 同じ読取り中に固定した公開INFの保護・同一性。失敗時は空
 * @return 元領域と全作用の読取り成功で0、その他HRESULT
 * @note 通常のWindows INFだけを読む。未知のパスや他のファイルを読み直さず、導入しない
 */
//------------------------------------------------------------------------------
NativeError readPublishedDisplayInfUse( std::wstring_view leaf, std::wstring_view installedSection,
									   const OfficialDisplayAuxiliaryService &target,
									   DisplayInfUse &result, ProtectedExecutableSnapshot &file)
{
	result = {} ;
	file   = {} ;
	// 型が決まった公開INF葉だけを扱い、任意パス指定を受けない
	if( !isRegisteredFileLeaf( leaf, L".inf") ||
	   (!installedSection.empty() && !isRegisteredSection( installedSection))) {
		return E_INVALIDARG ;
	}

	try {
		const DriverStorePackageLookup lookup{&GetSystemWindowsDirectoryW, nullptr,
											  nullptr} ;			// 固定ルートだけの正規照会
		std::wstring				   windows ;					// 指定元のWindowsルートを推測しない
		auto error = readStoreWindowsDirectory( lookup, windows) ;	// 同一Windowsのルート診断
		// Windowsルートが不明なら依存ファイルから補わない
		if( error != 0U) {
			return error ;
		}

		const auto path = windows + L"\\INF\\" + std::wstring{leaf} ;	// 規定公開位置の実INF
		std::vector<StoreFile>		directories ;						// 解析した公開INFの全祖先を保持
		std::vector<StoreFile>		files ;								// 解析終端まで元INFを変更非共有で保持
		ProtectedExecutableSnapshot held ;								// 同じ元INF実体の保護と全ハッシュ
		error = inspectPinnedOemFile( windows, path, false, directories, files, held) ;
		// Windows内の実ファイルを固定した場合だけSetupAPIの展開済み宣言を使う
		if( error != 0U) {
			return error ;
		}

		DisplayInfUse inspected ;	// 解析が不完全な場合に部分結果を公開しない
		error = inspectRegisteredDisplayInfUse( path, installedSection, target, inspected) ;
		// 同じ固定実体と解析結果の両方が揃った場合だけ返す
		if( error == 0U) {
			file   = std::move( held) ;
			result = std::move( inspected) ;
		}

		return error ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Windows公開領域にある標準形式の拡張INFの母集合を列挙する
 * @param[out] leaves 大小無視で一意な拡張INF単独名の昇順集合。失敗時は空
 * @return 全件のクラスを確認して0。不明または容量・列挙失敗はHRESULT
 * @note 適用関係不明時の保守的な読取対象であり、各拡張が現在導入済みとは判定しない
 */
//------------------------------------------------------------------------------
NativeError listPublishedExtensionInfs( std::vector<std::wstring> &leaves)
{
	leaves.clear() ;
	try {
		const DriverStorePackageLookup lookup{&GetSystemWindowsDirectoryW, nullptr,
											  nullptr} ;						// 固定ルートだけの正規照会
		std::wstring				   windows ;								// OS自身のINF領域を確定する
		const auto windowsError = readStoreWindowsDirectory( lookup, windows) ;	// 元Windows位置の診断
		// 環境変数から代替ルートを採用しない
		if( windowsError != 0U) {
			return windowsError ;
		}

		const auto directory = windows + L"\\INF" ;	// 同じWindowsの公開領域
		DWORD	   capacity{} ;						// APIが返す二重終端込み文字数
		// 列挙失敗を拡張の不存在へ変換しない
		if( !SetupGetInfFileListW( directory.c_str(), INF_STYLE_WIN4, nullptr, 0U, &capacity)) {
			return storeError( GetLastError()) ;
		}

		// 全INFの有限取得量に収まることを要求する
		if( capacity == 0U || capacity > 1U * 1024U * 1024U) {
			return storeError( ERROR_BUFFER_OVERFLOW) ;
		}

		std::vector<wchar_t> names( capacity, L'\xffff') ;	// 未書込みと正式終端を区別する
		DWORD				 actual{} ;						// 今回の全取得長
		// 途中失敗や容量増を部分的に成功として処理しない
		if( !SetupGetInfFileListW( directory.c_str(), INF_STYLE_WIN4, names.data(), capacity,
								 &actual)) {
			return storeError( GetLastError()) ;
		}

		// 列挙中のファイル集合の変化を成功としない
		if( actual != capacity || names.back() != L'\0') {
			return storeError( ERROR_RETRY) ;
		}

		constexpr GUID EXTENSION{
			0xe2f84ce7,
			0x8efa,
			0x411c,
			{0xaa, 0x69, 0x97, 0x45, 0x4c, 0xa4, 0xcb, 0x57}} ;	// Windowsの拡張セットアップクラス
		std::vector<std::wstring> found ;						// 全クラスを確定するまで公開しない
		auto					  cursor = names.cbegin() ;		// 次の完全な葉名の開始
		// Windowsが返した全件をクラス判定し、OEM・同梱を同じ母集合へ含める
		while( cursor != names.cend() && *cursor != L'\0') {
			const auto end = std::find( cursor, names.cend(), L'\0') ;	// 現在葉の完全な終端
			// 一件の未終端も部分列挙に変えない
			if( end == names.cend()) {
				return storeError( ERROR_INVALID_DATA) ;
			}

			const std::wstring leaf{cursor, end} ;	// Windowsが返した単独の元INF名
			cursor = end + 1U ;
			// 出力にあっても別ディレクトリへ誘導しない
			if( !isRegisteredFileLeaf( leaf, L".inf")) {
				return storeError( ERROR_INVALID_NAME) ;
			}

			const auto path = directory + L"\\" + leaf ;		// Windowsの公開INF完全位置
			GUID	   guid{} ;									// 元INFのクラスGUID
			std::array<wchar_t, MAX_CLASS_NAME_LEN> name{} ;	// 同じクラスの正式名
			// 明示クラスなしは元Windowsが示す非Extensionとして扱い、他の不明は維持する
			if( !SetupDiGetINFClassW( path.c_str(), &guid, name.data(),
									static_cast<DWORD>( name.size()), nullptr)) {
				const auto native = GetLastError() ;	// クラス照会が失敗した正式な理由
				// 内容破損または読取不能を正式なクラスなしに読み替えない
				if( native != ERROR_NO_ASSOCIATED_CLASS) {
					return storeError( native) ;
				}

				continue ;
			}

			const auto last	 = std::find( name.begin(), name.end(), L'\0') ;		// クラス完全名の終端
			const bool named = sameStorePath( {name.begin(), last}, L"Extension") ;	// 公式クラス名
			const bool typed = IsEqualGUID( guid, EXTENSION) != FALSE ;				// 公式クラスGUID
			// 不完全なクラスと矛盾するGUIDを母集合の確定から除外しない
			if( last == name.end() || typed != named) {
				return storeError( ERROR_INVALID_DATA) ;
			}

			// 公式クラス両方が確認できたINFだけを保守的な全拡張に含める
			if( typed) {
				std::wstring key = leaf ;	// Windowsの大小無視で一意化する照合用位置
				std::ranges::transform( key, key.begin(), []( wchar_t c) {
					return c >= L'A' && c <= L'Z' ? static_cast<wchar_t>( c + (L'a' - L'A')) : c ;
				}) ; // 許容葉はASCIIであり言語依存変換をしない
				found.push_back( std::move( key)) ;
			}
		}

		// 葉集合の最終終端の不足や余分なデータを拒否する
		if( cursor == names.cend() || cursor + 1U != names.cend()) {
			return storeError( ERROR_INVALID_DATA) ;
		}

		std::ranges::sort( found) ;
		// 同じ元INFの別表記を別の拡張としない
		if( std::ranges::adjacent_find( found) != found.end()) {
			return storeError( ERROR_DUP_NAME) ;
		}

		leaves = std::move( found) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 選択デバイスの公開OEM INFとSystem32補助の元署名を読取り照合する
 * @param[in] publishedInf 同じデバイスの公開OEM INF名
 * @param[in] installedBasicSection 同じデバイスの元基本節名
 * @param[in] installedSectionExtension Windowsの元節拡張。不在の場合は空
 * @param[in] intended 同じデバイスへの検査済みストレージ候補
 * @param[in] host 同じ二つのイベントとSystem32の現在ファイルの観測
 * @param[out] evidence 元署名と実選択の照合結果。失敗時は空
 * @param[in] lookup 同じWindowsと登録先を照会する内部API表
 * @return 成功0、元登録・完全性・署名の不成立はHRESULT
 * @note 現在の共有所有は全機器の確認で別に判断し、サービスを起動・変更しない
 */
//------------------------------------------------------------------------------
NativeError readRegisteredStoragePackageEvidence( std::wstring_view publishedInf,
												 std::wstring_view installedBasicSection,
												 std::wstring_view installedSectionExtension,
												 const SelectedStorageServiceFacts	&intended,
												 const StorageAuxiliaryHostSnapshot &host,
												 RegisteredStoragePackageEvidence	&evidence,
												 const DriverStorePackageLookup		&lookup)
{
	// 既存の対象サービスとイベントとファイルを同じ同期読取りへ結ぶ
	const RegisteredStorageObservation observed{intended.name, &host.events, host.executable} ;
	return readRegisteredStoragePackageEvidenceImpl( publishedInf, installedBasicSection,
													installedSectionExtension, intended, observed,
													evidence, lookup) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 自動起動補助が属する登録済みストレージの選択・元署名・現在ファイルを照合する
 * @param[in] publishedInf 現用デバイスのWindows INF直下にある公開OEM INF名
 * @param[in] installedBasicSection 同デバイスの実基本節
 * @param[in] installedSectionExtension 同デバイスに記録された実拡張。不存在では空
 * @param[in] installedService 同デバイスにWindowsが記録した現在関連サービス名
 * @param[in] intended 六欄の自動起動補助を宣言する署名済み更新候補
 * @param[in] host 同じ補助の現在SCM・Driver Store観測。正式不在では空
 * @param[in] events 現用関連サービスと明示Systemイベントの保護付き現在観測
 * @param[out] evidence 元INFとCATに結合した起動サービス、補助、イベント、電源定義の証拠。失敗時は空
 * @param[in] lookup 同じWindowsのルートと登録先を照会する内部API表
 * @return 確認した一つの元登録を読取照合できた場合0、失敗はHRESULT
 * @note 同名の現在補助が実在すれば元EXEの位置、全byte、保護を再確認する
 * @note 元CATの確認後に同じ実選択の電源定義を読み取る
 * @note キャッシュ内の信頼情報を使う。登録、起動、設定変更や共有所有の承認を行わない
 */
//------------------------------------------------------------------------------
NativeError readRegisteredAutomaticStoragePackageEvidence(
	std::wstring_view publishedInf, std::wstring_view installedBasicSection,
	std::wstring_view installedSectionExtension, std::wstring_view installedService,
	const SelectedStorageServiceFacts &intended, const StorageAutoStartAuxiliarySnapshot &host,
	const StorageSystemEventSnapshot &events, RegisteredStoragePackageEvidence &evidence,
	const DriverStorePackageLookup &lookup)
{
	// 同じ現在登録のサービス識別と明示名イベントの観測を保持する
	const RegisteredStorageObservation observed{installedService, &events.events, host.executable,
												&host} ;
	return readRegisteredStoragePackageEvidenceImpl( publishedInf, installedBasicSection,
													installedSectionExtension, intended, observed,
													evidence, lookup) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現用機器の署名付き登録から現在の自動起動補助とイベントを読み取る
 * @param[in] publishedInf 現用機器のWindows INF直下にある公開OEM INF名
 * @param[in] installedBasicSection 同じ機器の実基本節
 * @param[in] installedSectionExtension Windowsが記録した実拡張。不在では空
 * @param[in] installedService 同じ機器に実登録された現在関連サービス名
 * @param[in] intended 検査済みの自動起動補助付き更新候補
 * @param[out] package 元INF・CAT・起動サービス・電源定義と現在ファイルの照合証拠。失敗時は空
 * @param[out] events 元宣言が示した二つの現在イベント観測。失敗時は空
 * @param[out] auxiliary 元宣言が示した補助の保護付き観測。失敗時は空
 * @param[in] lookup Windowsルートと現在登録位置を照会する同期API表
 * @return 一つの登録と観測が成立すれば0、読取り・変更・照合不成立はHRESULT
 * @note 署名を照合してから同一登録の元名を照会する。導入や設定変更は行わない
 */
//------------------------------------------------------------------------------
NativeError readCurrentRegisteredAutomaticStoragePackageEvidence(
	std::wstring_view publishedInf, std::wstring_view installedBasicSection,
	std::wstring_view installedSectionExtension, std::wstring_view installedService,
	const SelectedStorageServiceFacts &intended, RegisteredStoragePackageEvidence &package,
	StorageSystemEventSnapshot &events, StorageAutoStartAuxiliarySnapshot &auxiliary,
	const DriverStorePackageLookup &lookup)
{
	events	  = {} ;
	auxiliary = {} ;
	RegisteredStorageCurrentRead current{events, auxiliary} ;	// 署名付き元を確認した後の観測出力
	const RegisteredStorageObservation observed{installedService, nullptr, auxiliary.executable,
												nullptr, &current} ;	// 同期中の入出力の借用
	return readRegisteredStoragePackageEvidenceImpl( publishedInf, installedBasicSection,
													installedSectionExtension, intended, observed,
													package, lookup) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じサービスを使う全現用機器の署名付き元登録と現在の共有構成を照合する
 * @param[in] host 予定した補助サービスとコピー先、二つのSystemイベントの安定した現在観測
 * @param[in] owners 各現用機器から取得した署名・実選択の証拠を全件同期借用する
 * @return 確認済みの新規配置先または共有所有で0、欠落・競合・読取り失敗はHRESULT
 * @note 異なる元ハッシュを持つ登録でも、既存ファイルを所有する登録と他の宣言の整合を要求する
 */
//------------------------------------------------------------------------------
NativeError verifyRegisteredStorageAuxiliaryOwnership(
	const StorageAuxiliaryHostSnapshot						&host,
	std::span<const RegisteredStoragePackageEvidence *const> owners)
{
	const auto &primaryEvent  = host.events[0U] ;			// 関連カーネルサービスの現在イベント
	const auto &helperEvent	  = host.events[1U] ;			// 独立した補助サービスの現在イベント
	const bool	helperPresent = host.service.has_value() ;	// SCMが補助サービスの存在を確認したか
	// 書込み途中や別の所有による一部ファイルだけの状態を認めない
	if( helperPresent != host.executable.existing.has_value() ||
	   helperPresent != helperEvent.present) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	bool primaryDeclared{} ;	// 現用の署名元が関連イベントを宣言したか
	bool helperDeclared{} ;		// 現用の署名元が補助を宣言したか
	bool deployedOwned{} ;		// 実EXEと同じCAT、名称と説明を裏付ける宣言を確認したか
	// 同名の別構成を許可せず、補助を宣言するすべての元登録を同じ現在値に照合する
	for( const auto *owner : owners) {
		// 一部の現用機器を情報欠損のまま除外しない
		if( !owner) {
			return storeError( ERROR_INVALID_DATA) ;
		}

		const auto &declaredPrimary = owner->eventReferences[0U] ;	// この元選択の関連イベント宣言
		// 実在のイベントを、元署名が指定した値と型に厳密に結ぶ
		if( declaredPrimary && !matchesRegisteredStorageEvent( *declaredPrimary, primaryEvent)) {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}

		primaryDeclared = primaryDeclared || declaredPrimary.has_value() ;

		// 補助が導入される前の版は、独立した補助の所有宣言を持たない
		if( !owner->helper) {
			continue ;
		}

		helperDeclared = true ;

		const auto &declared = *owner->helper ;				// この元選択で確認済みの起動方式と補助ファイル
		const auto &event	 = owner->eventReferences[1U] ;	// この元選択の補助イベント宣言
		// 元選択が補助を宣言するなら、配置漏れや別イベントを既知の所有としない
		if( !helperPresent || !event || !matchesRegisteredStorageEvent( *event, helperEvent)) {
			return storeError( ERROR_NOT_SUPPORTED) ;
		}

		const auto &service = *host.service ;	// 全所有者が共有する同じ実サービス観測
		// この機器の元登録と現在SCMの照合結果
		const auto	error = matchRegisteredStorageAuxiliaryService( service, declared) ;
		// 別アカウント・別パス・権限差などがあれば現在構成を引き継がない
		if( error != 0U) {
			return error ;
		}

		// 実状態と元CATの両方に結び付いた登録だけが共有ファイルの所有を示す
		if( declared.deployedSha256) {
			// 所有証拠が異なるファイルへの置換で失効していないことを確認する
			if( *declared.deployedSha256 != declared.sourceSha256 ||
			   *declared.deployedSha256 != host.executable.existing->sha256) {
				return storeError( ERROR_INVALID_DATA) ;
			}

			// 元表示名を省略した場合にWindowsが使うサービス名を含めた表示
			const auto &display = declared.display.empty() ? declared.name : declared.display ;
			deployedOwned		= deployedOwned || (service.config.display == display &&
												service.config.description == declared.description) ;
		}
	}

	// 名前が一致するだけのイベントや現用登録に属さない補助を引き継がない
	if( primaryDeclared != primaryEvent.present || helperDeclared != helperPresent) {
		return storeError( ERROR_NOT_SUPPORTED) ;
	}

	return helperPresent && !deployedOwned ? storeError( ERROR_INVALID_DATA) : 0U ;
}

/** @brief 同じ操作で保持したOEM登録位置と元パッケージ */
struct RegisteredDriverStorePackage::State {
	/// 操作全体で使うWindows照会の完全表
	DriverStorePackageLookup lookup ;
	/// 同操作が選んだWindows INF直下の登録INF
	std::wstring			 registeredInf ;
	/// Windowsから確認した元パッケージ内のINF
	std::wstring			 storeInf ;
	/// Windowsルートから各メンバーの親まで保持する
	std::vector<StoreFile>	 directories ;
	/// 元閉包と同byteと確認したINF、CAT、必要ファイル
	std::vector<StoreFile>	 files ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 未確認で空の保持状態を作る
 */
//------------------------------------------------------------------------------
RegisteredDriverStorePackage::RegisteredDriverStorePackage() noexcept = default ;

//------------------------------------------------------------------------------
/**
 * @brief 読取りに使ったファイルとディレクトリを解放する
 */
//------------------------------------------------------------------------------
RegisteredDriverStorePackage::~RegisteredDriverStorePackage() noexcept = default ;

//------------------------------------------------------------------------------
/**
 * @brief Windowsが返した登録先で元閉包の各ファイルを確認して保持する
 * @param[in] registeredInf 呼出し側が元INFと照合済みのWindows INF直下のOEM INF
 * @param[in] original 署名確認済みの選択元INFとCAT、必要ファイルの元位置
 * @param[in] entries 同じ閉包の展開済みファイルの長さとSHA-256
 * @param[in] lookup 登録先を照会する完全なAPI表
 * @return すべての原ファイルと配置先が同じ場合0、未知や不一致はHRESULT
 */
//------------------------------------------------------------------------------
NativeError RegisteredDriverStorePackage::pin( const std::wstring			   &registeredInf,
											  const OfficialInfPackage		   &original,
											  std::span<const OfficialZipEntry> entries,
											  const DriverStorePackageLookup   &lookup)
{
	state_.reset() ;
	// Windows照会と選択元INF・CAT・必要ファイルが全てある場合だけ読む
	if( !lookup.windowsDirectory || !lookup.storeLocation || original.sourceFiles.empty() ||
	   entries.size() != original.sourceFiles.size() + 2U ||
	   !isSafeOfficialArchiveMember( original.infRelativePath, L'\\')) {
		return storeError( ERROR_INVALID_PARAMETER) ;
	}

	try {
		std::array<wchar_t, MAX_PATH> root{} ;	// OEM INFとStoreで共通のWindowsルート
		const auto					  count = lookup.windowsDirectory(
			   // Windowsのルート文字数
			   root.data(), static_cast<UINT>( root.size())) ;
		// Windowsが返す絶対パスには配布物の相対名の文字制限を適用しません
		if( count <= 3U || count >= root.size() || root[count] != L'\0' || root[1] != L':' ||
		   root[2] != L'\\' || root[count - 1U] == L'\\' ||
		   std::find( root.begin(), root.begin() + count, L'\0') != root.begin() + count ||
		   std::find( root.begin(), root.begin() + count, L'/') != root.begin() + count) {
			return storeError( ERROR_INVALID_DATA) ;
		}

		const std::wstring windows( root.data(), count) ;			// 同じWindowsの正規ルート
		const auto		   infDirectory = windows + L"\\INF\\" ;	// OEM INFの置かれる固定ディレクトリ
		// OEM INFの位置は同じWindows INFの直下一件に限定します
		if( registeredInf.size() <= infDirectory.size() ||
		   !sameStorePath( std::wstring_view( registeredInf).substr( 0U, infDirectory.size()),
						  infDirectory) ||
		   !isSafeOfficialArchiveMember(
			   std::wstring_view( registeredInf).substr( infDirectory.size()), L'\\') ||
		   registeredInf.find( L'\\', infDirectory.size()) != registeredInf.npos) {
			return storeError( ERROR_ACCESS_DENIED) ;
		}

		auto pending		   = std::make_unique<State>() ;	// 全確認が終わるまで外へ出さない所有
		pending->lookup		   = lookup ;
		pending->registeredInf = registeredInf ;
		auto error =
			// OSが実際に対応付けたINF
			lookupStoreInf( lookup, registeredInf, pending->storeInf) ;
		// 不明な登録対応では同名の別パッケージを探しません
		if( error != 0U) {
			return error ;
		}

		const auto repository =
			windows + L"\\System32\\DriverStore\\FileRepository" ;	// Driver Storeの既知ルート
		const auto folderEnd =
			// Windowsが選んだパッケージ親の終端
			pending->storeInf.find_last_of( L'\\') ;
		const auto sourceSlash = original.infRelativePath.find_last_of( L'\\') ;	// 元INFの親の終端
		const auto sourceStart = sourceSlash == original.infRelativePath.npos
									 ? 0U
									 : sourceSlash + 1U ;	// 元パッケージ相対名の先頭
		// 同FileRepositoryで一つのパッケージの直下にある元INFだけを受理します
		if( folderEnd == pending->storeInf.npos || folderEnd <= repository.size() + 1U ||
		   !sameStorePath( std::wstring_view( pending->storeInf).substr( 0U, repository.size()),
						  repository) ||
		   pending->storeInf[repository.size()] != L'\\' ||
		   pending->storeInf.find( L'\\', repository.size() + 1U) != folderEnd ||
		   !isSafeOfficialArchiveMember(
			   std::wstring_view( pending->storeInf)
				   .substr( repository.size() + 1U, folderEnd - repository.size() - 1U),
			   L'\\') ||
		   !sameStorePath( std::wstring_view( pending->storeInf).substr( folderEnd + 1U),
						  std::wstring_view( original.infRelativePath).substr( sourceStart))) {
			return storeError( ERROR_ACCESS_DENIED) ;
		}

		const auto storeFolder =
			// 同パッケージだけに使う親
			pending->storeInf.substr( 0U, folderEnd + 1U) ;
		const std::wstring_view		   sourcePrefix( original.infRelativePath.data(),
													sourceStart) ;	// 同元INFの親
		std::vector<std::wstring_view> required{
			original.infRelativePath, original.catalogRelativePath} ;	// 閉包が期待する元位置
		required.insert( required.end(), original.sourceFiles.begin(), original.sourceFiles.end()) ;
		// 指定パッケージの各元ファイルを同じ相対位置で確認する
		for( const auto member : required) {
			// 同じ親の安全な相対位置だけを再構築します
			if( member.size() <= sourceStart ||
			   (sourceStart != 0U &&
				!sameStorePath( member.substr( 0U, sourceStart), sourcePrefix)) ||
			   !isSafeOfficialArchiveMember( member.substr( sourceStart), L'\\')) {
				return storeError( ERROR_INVALID_NAME) ;
			}

			const auto source = std::ranges::find_if( entries, [&]( const auto &entry) {
				return sameStorePath( entry.relativePath, member) ;
			}) ; // 元位置のサイズとSHA-256
			const auto placed =
				storeFolder + std::wstring( member.substr( sourceStart)) ;	// Store内の同じ相対位置
			// 欠損・重複した元位置を同じbyteの別fileで補いません
			if( source == entries.end() || source->sha256.size() != 64U ||
			   std::ranges::any_of( pending->files, [&]( const auto &file) {
				   return sameStorePath( file.path, placed) ;
			   })) {
				return storeError( ERROR_INVALID_DATA) ;
			}

			// Windowsルートからファイルの親まで、各ディレクトリを移動非共有で保持します
			for( auto pos = windows.size(); pos != placed.npos; pos = placed.find( L'\\', pos + 1U)) {
				const auto parent = placed.substr( 0U, pos) ;	// 同じパッケージの親の一つ
				// 同じ親は先行ファイルの保持を再利用します
				if( std::ranges::none_of( pending->directories, [&]( const auto &dir) {
					   return sameStorePath( dir.path, parent) ;
				   })) {
					error = pinStoreFile( parent, true, pending->directories.emplace_back()) ;
					// 先祖の再解析や移動を検出した場合はその時点で停止します
					if( error != 0U) {
						return error ;
					}
				}
			}

			error = pinStoreFile( placed, false, pending->files.emplace_back()) ;
			// Store側を変更非共有で保持した後、元ファイルの長さとSHA-256を照合します
			if( error == 0U) {
				error =
					verifyOfficialFileMetadata( placed, {source->uncompressedSize, source->sha256}) ;
			}

			// 同じINFでも別CATまたは別SYSを同じパッケージとして扱いません
			if( error != 0U) {
				return error ;
			}
		}

		state_ = std::move( pending) ;
		error  = verify() ;
		// 照会中にOEM INFの対応が変わったら、閉包の一部を残しません
		if( error != 0U) {
			state_.reset() ;
		}

		return error ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 全閉包から指定INFのCATと必須ファイルを選び、その正規登録内容を保持する
 * @param[in] registeredInf 適用前のWindows INF直下のOEM INF
 * @param[in] original 同じ元署名のINF、CATと必須ファイル
 * @param[in] entries 元の複数INFを含む署名確認済み媒体の長さとSHA-256
 * @param[in] lookup 同じWindowsの登録先と元ルートの照会表
 * @return 指定INFの全必須ファイルと登録先の照合成功で0、その他はHRESULT
 * @note INFごとの保護付き検査を行う。未完了状態を次に持ち越さない
 */
//------------------------------------------------------------------------------
NativeError RegisteredDriverStorePackage::pinFromClosure( const std::wstring		  &registeredInf,
														 const OfficialInfPackage &original,
														 std::span<const OfficialZipEntry> entries,
														 const DriverStorePackageLookup	  &lookup)
{
	state_.reset() ;
	try {
		std::vector<OfficialZipEntry> selected ;	// 指定INFが所有する元ファイルだけを保持する
		selected.reserve( original.sourceFiles.size() + 2U) ;
		// 複数INFを含む元の順序を維持して指定INFのファイルを選ぶ
		for( const auto &entry : entries) {
			const auto matches = [&entry]( const std::wstring &path) {
				return sameStorePath( entry.relativePath, path) ;
			} ; // 元のWindowsパスを大文字・小文字だけ無視して照合する
			// 同じINFのCATと必須ファイルを拾い、別INFのファイルを登録先の比較に加えない
			if( matches( original.infRelativePath) || matches( original.catalogRelativePath) ||
			   std::ranges::any_of( original.sourceFiles, matches)) {
				selected.push_back( entry) ;
			}
		}

		return pin( registeredInf, original, selected, lookup) ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief OEM INFの照会先と保持した実ファイルを導入直前に再確認する
 * @return 保持した同一ファイルと登録先が成立する場合0、未保持・不一致・失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError RegisteredDriverStorePackage::verify() const
{
	// 未成立の保持から導入直前の成功を返しません
	if( !state_) {
		return storeError( ERROR_INVALID_STATE) ;
	}

	try {
		std::wstring path ;	// 同じOEM INFに対する現在のWindowsの回答
		const auto	 error =
			// 元照会の成否
			lookupStoreInf( state_->lookup, state_->registeredInf, path) ;
		// 同じINFの別Storeディレクトリへ切り替わった場合は再確認を要求します
		if( error != 0U || !sameStorePath( path, state_->storeInf)) {
			return error != 0U ? error : storeError( ERROR_RETRY) ;
		}

		// 初回のhash照合から保ち続けた親とファイルの実解決先を確認します
		for( const auto *group : {&state_->directories, &state_->files}) {
			// 各handleは読み取り保持中なので全パスを確認するだけで再列挙は不要です
			for( const auto &file : *group) {
				const auto pathError = checkPinnedStorePath( file) ;	// 保持中の完全なパスへの照合
				// 親の変化や照会失敗では適用を止めます
				if( pathError != 0U) {
					return pathError ;
				}
			}
		}

		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 確認済みの同じStore元INFが指定された全ファイルを保持しているか照合する
 * @param[in] storeInf 独立に読んだ現在のStore元INF完全位置
 * @param[in] paths 元INFのパッケージ内にある必要ファイルの完全位置
 * @return 同一の元INFと空でない全ファイルが保持済みの場合true
 * @note 再読取りは行わない。保持の有効性はverifyで確認する
 */
//------------------------------------------------------------------------------
bool RegisteredDriverStorePackage::containsPinnedMembers(
	std::wstring_view storeInf, std::span<const std::wstring> paths) const noexcept
{
	return state_ && sameStorePath( state_->storeInf, storeInf) && !paths.empty() &&
		   std::ranges::all_of( paths, [&]( const auto &path) {
			   return std::ranges::any_of(
				   state_->files, [&]( const auto &file) { return sameStorePath( file.path, path) ; }) ;
		   }) ; // 保持中の元位置だけを新たなI/Oなしで比較する
}
} // namespace drivercrate
