//------------------------------------------------------------------------------
/**
 * @file official_driver_package.cpp
 * @brief 公式標準INF driver package検証実装。
 * @version 01.26.00
 * @date 2026/09/03
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  CAT member／PnP照合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  DriverVer日付取得追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  INF signature allowlist追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  参照file埋込み署名検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  汎用Provider名検証mode追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  SYS不要printer構造policy追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  圧縮実行program拒否追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  選択的driver閉包policy追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  INF section必要文字数の型修正。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  INF解析のstack使用量を削減。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Windows検証済みsignerの共通署名policyを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  明示依存の存在観測を内容署名から分離。
 * Ver.01.03.00 Shunji Ogawa  2026/10/04  無作用の空CoInstaller参照だけを有限検査で受理。
 * Ver.01.04.00 Shunji Ogawa  2026/10/05  非実行参照棚卸しと導入検査を別契約に分離。
 * Ver.01.05.00 Shunji Ogawa  2026/10/05  保守参照の先頭現在directory表記だけを正規化。
 * Ver.01.05.01 Shunji Ogawa  2026/10/05  空sourceでもINF自身のCAT member検証を必須にする。
 * Ver.01.06.00 Shunji Ogawa  2026/10/05  保守参照棚卸しで両方の標準INF識別子を受理。
 * Ver.01.07.00 Shunji Ogawa  2026/10/05  非圧縮EXEだけを保守参照byteとして限定受理。
 * Ver.01.08.00 Shunji Ogawa  2026/10/05  選択導入処理の非実行作用・参照棚卸しを追加。
 * Ver.01.09.00 Shunji Ogawa  2026/10/05  実測した節容量停止へ有限な共通棚卸し拡張を追加。
 * Ver.01.10.00 Shunji Ogawa  2026/10/06  選択処理の未解釈範囲を有限な不足観測へ分離。
 * Ver.01.11.00 Shunji Ogawa  2026/10/07  保守専用の全現在OS選択と厳密null service構造を解析。
 * Ver.01.12.00 Shunji Ogawa  2026/10/07  有限行読取と明示seedからのfile位置棚卸しを追加。
 * Ver.01.12.01 Shunji Ogawa  2026/10/07  keyなし登録行の禁止marker検査とAddSoftware拒否を補う。
 * Ver.01.13.00 Shunji Ogawa  2026/10/07  保守named serviceの必須構造と限定null認定を分離。
 * Ver.01.14.00 Shunji Ogawa  2026/10/07  保守binaryの展開済み位置を明示named導入先と元sourceへ限定照合。
 * Ver.01.14.01 Shunji Ogawa  2026/10/07  同HINF named13の非absolute展開を不正へ変換せず未対応保持。
 * Ver.01.15.00 Shunji Ogawa  2026/10/07  一意な到達named13の相対全targetを同名・同subdirの元sourceへ限定接続。
 * Ver.01.16.00 Shunji Ogawa  2026/10/08  同行eventlogの独立子Uを保持した最終参照だけでサービス名markerを分離。
 * Ver.01.17.00 Shunji Ogawa  2026/10/08  同元byteと全値・一意callerを証明した単一EventMessageFile位置を遅延接続。
 * Ver.01.18.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.19.00 Shunji Ogawa  2026/10/13  元現在OS選択のCopyINFと必要SWC関係を役割別に検査。
 * Ver.01.20.00 Shunji Ogawa  2026/10/13  Windows元node基本名からdevice別必要構成を解析。
 * Ver.01.21.00 Shunji Ogawa  2026/10/13  必要SWCのWin32 service参照EXEを同INFのコピーとsourceへ限定。
 * Ver.01.21.01 Shunji Ogawa  2026/10/13  展開済みServiceBinaryを同HINFの完全copy宛先へ照合。
 * Ver.01.21.02 Shunji Ogawa  2026/10/13  サービス節の列挙異常時に部分EXE集合を破棄。
 * Ver.01.22.00 Shunji Ogawa  2026/10/13  必要Win32 serviceの位置付きsourceと標準DIRID・正式flagsを限定接続。
 * Ver.01.23.00 Shunji Ogawa  2026/10/13  同INF媒体とfile相対位置を共通readerで内容検査へ結合。
 * Ver.01.24.00 Shunji Ogawa  2026/10/13  元媒体位置readerを選択Needs payload検査と共用。
 * Ver.01.25.00 Shunji Ogawa  2026/10/14  元Models節と公開ID種別の同INF読取りを追加。
 * Ver.01.26.00 Shunji Ogawa  2026/10/14  同Windows INF/CAT検査から実publisherの非許可metadataを追加。
 * </pre>
 *
 * @note SetupAPIをINF構文と現在platformの選択規則の正本とし、外部文字列からpathを直接生成せず、ZIP検証済みentryとの完全一致だけを受理します。
 */
//------------------------------------------------------------------------------

#include "platform/official_driver_package.h"
#include "platform/driver_package_signature_internal.h"

#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"

#include <SetupAPI.h>
#include <objbase.h>
#include <Windows.h>
#include <WinTrust.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t MAXIMUM_INF_FIELD_CHARACTERS	   = 4096U ;	// 一INF fieldの文字数上限。
constexpr std::size_t MAXIMUM_MODEL_SECTION_CHARACTERS = 256U ;		// Models section名上限。
constexpr std::size_t MAXIMUM_HARDWARE_ID_CHARACTERS   = 256U ;		// 一PnP IDの文字数上限。

// Archive内に未参照でも存在を許可しない従来のprogram拡張子群。
constexpr std::array<std::wstring_view, 31> REJECTED_UNREFERENCED_PROGRAM_EXTENSIONS{
	L".bat", L".cmd",  L".com",	 L".exe", L".hta", L".js",	L".jse", L".msi",
	L".ps1", L".psd1", L".psm1", L".reg", L".scr", L".vbe", L".vbs", L".wsf",
	L".ba_", L".cm_",  L".co_",	 L".ex_", L".ht_", L".j_",	L".js_", L".ms_",
	L".ps_", L".psd_", L".psm_", L".re_", L".sc_", L".vb_", L".ws_"} ;

// INF閉包から除外するprogram、installer、archive、firmware拡張子群。
constexpr std::array<std::wstring_view, 81> REJECTED_REFERENCED_EXTENSIONS{
	L".7z",			L".appx", L".appxbundle", L".bat",	L".bin",   L".bio", L".bz2", L".cab",
	L".cap",		L".cmd",  L".com",		  L".dfu",	L".dfuse", L".efi", L".elf", L".exe",
	L".fd",			L".fls",  L".ftf",		  L".fw",	L".gz",	   L".hex", L".hta", L".ihx",
	L".img",		L".iso",  L".js",		  L".jse",	L".kdz",   L".mbn", L".msi", L".msix",
	L".msixbundle", L".msp",  L".msu",		  L".ofp",	L".ova",   L".ovf", L".pac", L".pit",
	L".ps1",		L".psd1", L".psm1",		  L".qcow", L".qcow2", L".rar", L".reg", L".rom",
	L".scr",		L".sin",  L".tar",		  L".tgz",	L".tot",   L".txz", L".uf2", L".vbe",
	L".vbs",		L".vfd",  L".vhd",		  L".vhdx", L".vmdk",  L".wsf", L".xz",	 L".zip",
	L".ba_",		L".ca_",  L".cm_",		  L".co_",	L".ex_",   L".ht_", L".j_",	 L".js_",
	L".ms_",		L".ps_",  L".psd_",		  L".psm_", L".re_",   L".sc_", L".vb_", L".ws_",
	L".zi_"} ;

constexpr std::array<std::wstring_view, 8> REJECTED_INF_DIRECTIVES{
	L"AddSoftware",			L"CopyINF",
	L"RegisterDlls",		L"RunPostSetupCommands",
	L"RunPreSetupCommands", L"UnregisterDlls",
	L"UpdateInis",			L"UpdateIniFields"} ;	// 実行または外部登録directive。

constexpr std::size_t MAXIMUM_INF_SECTIONS = 4096U ;				// 一INFから静的解析するsection数上限。
constexpr LONG		  MAXIMUM_EMPTY_CO_INSTALLER_LINES		= 2L ;	// AddRegとCopyFiles各一行の上限。
constexpr DWORD		  MAXIMUM_EMPTY_CO_INSTALLER_REFERENCES = 16U ;	// 一指示の空節参照数上限。

constexpr std::size_t MAXIMUM_INSTALL_INVENTORY_SECTIONS = 1024U ;	// 非実行棚卸しの訪問節上限。
constexpr std::size_t MAXIMUM_INSTALL_INVENTORY_LINES	 = 4096U ;	// 各走査段階の累積行数上限。
constexpr std::size_t MAXIMUM_INSTALL_INVENTORY_ITEMS	 = 4096U ;	// 作用と参照それぞれの保持上限。
constexpr DWORD		  MAXIMUM_INSTALL_INVENTORY_FIELDS	 = 64U ;	// 一行の値field数上限。

/** @brief 棚卸しsectionの行形式。異なる形式で同じ節を再解釈しない。 */
enum class InstallInventorySectionKind {
	/// Directiveとその明示参照を読む。
	DIRECTIVES,
	/// AddReg／DelRegのregistry行を読む。
	REGISTRY,
	/// File list・command等の値を解釈せず有限行として読む。
	DATA_ROWS,
	/// 保守専用のCopyFiles listで明示source名を読む。
	COPY_FILE_ROWS,
} ;

/** @brief 同じINF内で有限走査するsectionと行形式。 */
struct InstallInventorySection {
	/// 元INF内のsection名。解析中だけ所有する。
	std::wstring				name ;
	/// section行の解釈区分。
	InstallInventorySectionKind kind{InstallInventorySectionKind::DIRECTIVES} ;
} ;

//------------------------------------------------------------------------------
// 内部class定義。
//------------------------------------------------------------------------------

/**
 * @brief SetupAPIのINF handleをscope終了時に閉じる。
 */
class UniqueInf final {
public:
	//------------------------------------------------------------------------------
	/**
     * @brief SetupOpenInfFileWの結果を受け取り、単独所有する。
     *
     * @param[in] handle SetupCloseInfFileで閉じる所有INF handle。
     */
	//------------------------------------------------------------------------------
	explicit UniqueInf( const HINF handle) noexcept : handle_( handle)
	{
	}

	//------------------------------------------------------------------------------
	/**
     * @brief INF handleを閉じる。
     *
     * 有効なINF handleだけを一度SetupCloseInfFileで閉じる。
     */
	//------------------------------------------------------------------------------
	~UniqueInf()
	{
		// 有効な所有INF handleだけを解放する。
		if( handle_ != INVALID_HANDLE_VALUE) {
			SetupCloseInfFile( handle_) ;
		}
	}

	/**
	 * @brief 所有INF handleの複製構築をコンパイル時に禁止します。
	 * @param[in] other 実行可能な呼出しを持たず、借用・変更・所有権移動を行わない元objectです。
	 * @note 削除宣言だけで関数本体やresource操作はありません。
	 */
	UniqueInf( const UniqueInf &other) = delete ;
	/**
	 * @brief 所有INF handleの複製代入をコンパイル時に禁止します。
	 * @param[in] other 実行可能な呼出しを持たず、借用・変更・所有権移動を行わない元objectです。
	 * @return 宣言された自己参照型です。削除宣言なので戻り値を生成しません。
	 * @note 削除宣言だけで関数本体やresource操作はありません。
	 */
	UniqueInf &operator=( const UniqueInf &other) = delete ;
	/**
	 * @brief 所有INF handleの移動構築をコンパイル時に禁止します。
	 * @param[in] other 実行可能な呼出しを持たず、借用・変更・所有権移動を行わない元objectです。
	 * @note 削除宣言だけで関数本体やresource操作はありません。
	 */
	UniqueInf( UniqueInf &&other) = delete ;
	/**
	 * @brief 所有INF handleの移動代入をコンパイル時に禁止します。
	 * @param[in] other 実行可能な呼出しを持たず、借用・変更・所有権移動を行わない元objectです。
	 * @return 宣言された自己参照型です。削除宣言なので戻り値を生成しません。
	 * @note 削除宣言だけで関数本体やresource操作はありません。
	 */
	UniqueInf		  &operator=( UniqueInf &&other) = delete ;

	//------------------------------------------------------------------------------
	/**
     * @brief INF handleを参照する。
     *
     * 所有権を移さず、現在scopeのSetupAPI呼出しだけに使用する。
     * @return 本instanceが所有するINF handle。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] HINF get() const noexcept
	{
		return handle_ ;
	}

private:
	/// Destructorで閉じる所有INF handle。
	HINF handle_{INVALID_HANDLE_VALUE} ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをNativeErrorへ変換する。
 *
 * Provider共通結果へ元の診断値を保持する。
 *
 * @param[in] error SetupAPIまたはfile APIが返したerror code。
 * @return HRESULT_FROM_WIN32で変換したbit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows ordinal規則で文字列を比較する。
 *
 * File名、INF識別子およびallowlistを同一規則で比較する。
 *
 * @param[in] left 比較する一方の文字列。
 * @param[in] right 比較する他方の文字列。
 * @return 大文字小文字を除き完全一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool stringsEqual( const std::wstring_view left,
								const std::wstring_view right) noexcept
{
	// Windows比較APIの長さ型を超える文字列を比較へ渡さない。
	if( left.size() > static_cast<std::size_t>( std::numeric_limits<int>::max()) ||
	   right.size() > static_cast<std::size_t>( std::numeric_limits<int>::max())) {
		return false ;
	}

	return CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

//------------------------------------------------------------------------------
/**
 * @brief 文字列が有限allowlistへ含まれるか確認する。
 *
 * 部分一致やUnicode正規化でProvider／classを拡張しない。
 *
 * @param[in] value 検証対象文字列。
 * @param[in] allowed 空を含まない許可文字列群。
 * @return 一つの許可値へ完全一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAllowedValue( const std::wstring_view				   value,
								  const std::span<const std::wstring_view> allowed) noexcept
{
	return std::ranges::any_of( allowed, [value]( const std::wstring_view candidate) {
		return stringsEqual( value, candidate) ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief INF contextの指定fieldを有限文字列として取得する。
 *
 * 必要長を先に取得し、固定長bufferによる切捨てを防ぐ。
 *
 * @param[in] context SetupAPIが返した有効なline context。
 * @param[in] fieldIndex 0がkey、1以降がvalueのfield番号。
 * @param[out] value 成功時のnull終端を除く展開済み文字列。
 * @return 成功時は0、不正fieldまたは上限超過時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readInfField( INFCONTEXT &context, const DWORD fieldIndex,
									   std::wstring &value)
{
	value.clear() ;
	DWORD required{} ;	// Null終端を含む必要文字数。
	// 必要長照会でbuffer不足以外の失敗を検出したら診断値を返す。
	if( SetupGetStringFieldW( &context, fieldIndex, nullptr, 0, &required) == FALSE &&
	   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 空または上限超過のINF fieldを取得しない。
	if( required <= 1 || required > MAXIMUM_INF_FIELD_CHARACTERS) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::vector<wchar_t> buffer ;	// SetupAPIから文字列を受信する有限buffer。
	try {
		buffer.resize( required) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	// INF field本文の取得失敗を元のWindows診断値で返す。
	if( SetupGetStringFieldW( &context, fieldIndex, buffer.data(), static_cast<DWORD>( buffer.size()),
							nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	value.assign( buffer.data()) ;
	return value.empty() ? nativeErrorFromWin32( ERROR_INVALID_DATA) : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief INF sectionの単一directive fieldを取得する。
 *
 * 必須directiveをSetupAPIのINF規則で検索する。
 *
 * @param[in] inf 読取り中のINF handle。
 * @param[in] section 検索するsection名。
 * @param[in] key 検索するdirective名。
 * @param[in] fieldIndex 取得するvalueのfield番号。
 * @param[out] value 成功時の展開済み文字列。
 * @return 成功時は0、欠落または不正field時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readInfDirective( const HINF inf, const wchar_t *const section,
										   const wchar_t *const key, const DWORD fieldIndex,
										   std::wstring &value)
{
	INFCONTEXT context{} ;	// 一致したdirectiveのline context。
	// 指定directiveを取得できなければ必須値を推測しない。
	if( SetupFindFirstLineW( inf, section, key, &context) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	return readInfField( context, fieldIndex, value) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ZIP検証済みentryに相対pathが存在するか確認する。
 *
 * INF由来pathが展開済みpackageの外へ出ないことを確認する。
 *
 * @param[in] entries ZIP central directoryで検証済みのfile群。
 * @param[in] relativePath Workspace基準の相対path。
 * @return 大文字小文字を除き完全一致するentryがある場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool containsEntry( const std::span<const OfficialZipEntry> entries,
								 const std::wstring_view				 relativePath) noexcept
{
	return std::ranges::any_of( entries, [relativePath]( const OfficialZipEntry &entry) {
		return stringsEqual( entry.relativePath, relativePath) ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 相対pathの拡張子を小文字ASCIIで取得する。
 *
 * 実行形式混入とSYS必須条件をcaseに依存せず判定する。
 *
 * @param[in] path ZIP検証済みのASCII相対path。
 * @return 最終要素のdotから始まる小文字拡張子。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring lowerExtension( const std::wstring_view path)
{
	const std::size_t separator = path.find_last_of( L'\\') ;	// 最終directory separator位置。
	const std::size_t dot		= path.find_last_of( L'.') ;	// 最終dot位置。
	// file名部分にdotがない相対pathは拡張子なしとして扱う。
	if( dot == std::wstring_view::npos ||
	   (separator != std::wstring_view::npos && dot < separator)) {
		return {} ;
	}

	std::wstring extension( path.substr( dot)) ;	// 小文字化する拡張子。
	std::transform( extension.begin(), extension.end(), extension.begin(),
				   []( const wchar_t character) {
					   return character >= L'A' && character <= L'Z'
								  ? static_cast<wchar_t>( character - L'A' + L'a')
								  : character ;
				   }) ;
	return extension ;
}

//------------------------------------------------------------------------------
/**
 * @brief 明示参照先とその装飾節が同INF内の空節であることを確認する。
 *
 * @param[in] inf 読取り中の借用INF handle。
 * @param[in] section Null終端された参照先section名。
 * @return 全参照先が存在する空節なら0、不正参照または非空節ならHRESULT。
 * @note 外部INFの読込みや再帰的参照解決を行わない。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateEmptyInfReference( const HINF inf, const wchar_t *section)
{
	const std::wstring_view reference( section) ;	// SetupAPIで展開した参照名。
	// 未解決文字列、直接file、空名や曖昧なsection名は許可しない。
	if( reference.empty() || reference.size() > MAXIMUM_MODEL_SECTION_CHARACTERS ||
	   !std::ranges::all_of( reference, []( const wchar_t character) noexcept {
		   return (character >= L'A' && character <= L'Z') ||
				  (character >= L'a' && character <= L'z') ||
				  (character >= L'0' && character <= L'9') || character == L'_' ||
				  character == L'.' || character == L'-' ;
	   })) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// 欠落節と非空節を空参照へ読み替えず、明示的な空節だけを認める。
	if( SetupGetLineCountW( inf, section) != 0) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U> name{} ;	// 装飾節の列挙領域。
	// 同じbase名から派生する装飾節にも処理行がないことを有限数で確認する。
	for( std::size_t index = 0; index < MAXIMUM_INF_SECTIONS; ++index) {
		UINT required{} ;	// 終端を含むsection名の必要文字数。
		// 正常終端だけを成功とし、過長名などのAPI失敗を保持する。
		if( SetupEnumInfSectionsW( inf, static_cast<UINT>( index), name.data(),
								 static_cast<UINT>( name.size()), &required) == FALSE) {
			const DWORD error = GetLastError() ;	// 列挙停止理由。
			return error == ERROR_NO_MORE_ITEMS ? 0 : nativeErrorFromWin32( error) ;
		}

		// 空名やbuffer外の応答を装飾節照合へ渡さない。
		if( required <= 1U || required > name.size()) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const std::wstring_view candidate( name.data()) ;	// 列挙された同INF内section名。
		// 装飾節の実登録やコピーを空base節で隠す構造は拒否する。
		if( candidate.size() > reference.size() && candidate[reference.size()] == L'.' &&
		   stringsEqual( candidate.substr( 0, reference.size()), reference) &&
		   SetupGetLineCountW( inf, name.data()) != 0) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}
	}

	return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 無作用のCoInstaller節だけを明示空参照で限定受理する。
 *
 * @param[in] inf 読取り中の借用INF handle。
 * @param[in] section Null終端されたCoInstallers節名。
 * @return 空節または各一行までのAddReg／CopyFiles空参照なら0、それ以外はHRESULT。
 * @note 各指示は最大16参照。実DLL登録、循環、外部依存、未知指示を解決・実行しない。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateEmptyCoInstallers( const HINF inf, const wchar_t *section)
{
	const LONG lineCount = SetupGetLineCountW( inf, section) ;	// 同名節を含む処理行数。
	// 参照行のない既存節は追加CoInstaller動作を持たない。
	if( lineCount == 0) {
		return 0 ;
	}

	// 既知二指示以上の処理や欠落節を空参照として解釈しない。
	if( lineCount < 0 || lineCount > MAXIMUM_EMPTY_CO_INSTALLER_LINES) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	INFCONTEXT line{} ;	// 有限数で読み取る指示行。
	// 観測済み行数に対する先頭取得失敗は不正データとする。
	if( SetupFindFirstLineW( inf, section, nullptr, &line) == FALSE) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	bool seenAddReg	   = false ;											// AddReg指示の重複拒否用。
	bool seenCopyFiles = false ;											// CopyFiles指示の重複拒否用。
	std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U> value{} ;	// keyまたは参照名。
	// 観測された最大二行を読み取り、既知指示とその全fieldを確認する。
	for( LONG lineIndex = 0; lineIndex < lineCount; ++lineIndex) {
		// 非key行や過長keyを許可済み指示へ読み替えない。
		if( SetupGetStringFieldW( &line, 0, value.data(), static_cast<DWORD>( value.size()),
								nullptr) == FALSE) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		const bool isAddReg	   = stringsEqual( value.data(), L"AddReg") ;		// 許可済み登録指示。
		const bool isCopyFiles = stringsEqual( value.data(), L"CopyFiles") ;	// 許可済みコピー指示。
		// 未知指示と重複指示を空参照の許可経路へ通さない。
		if( (!isAddReg && !isCopyFiles) || (isAddReg && seenAddReg) ||
		   (isCopyFiles && seenCopyFiles)) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		seenAddReg		   = seenAddReg || isAddReg ;
		seenCopyFiles	   = seenCopyFiles || isCopyFiles ;
		const DWORD fields = SetupGetFieldCount( &line) ;	// keyを除く参照field数。
		// 空または過大な参照集合を走査しない。
		if( fields == 0 || fields > MAXIMUM_EMPTY_CO_INSTALLER_REFERENCES) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		// 全参照を有限数で展開し、既存空節であることを確認する。
		for( DWORD field = 1U; field <= fields; ++field) {
			// 展開失敗や過長参照を無作用として受理しない。
			if( SetupGetStringFieldW( &line, field, value.data(), static_cast<DWORD>( value.size()),
									nullptr) == FALSE) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			const NativeError error = validateEmptyInfReference( inf, value.data()) ;	// 空参照判定。
			// 一つでも非空・不正なら節全体の受理を中止する。
			if( error != 0) {
				return error ;
			}
		}

		// 既知行数の途中で列挙が終わった場合は部分検証で成功にしない。
		if( lineIndex + 1 < lineCount && SetupFindNextLine( &line, &line) == FALSE) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief INFの既知の実行・software登録経路を静的検査する。
 *
 * Installerを起動せず全section名、行本文とdirective keyを有限数検査し、
 * 既知command・software導入、外部INF登録とRun／CoInstallers32登録を拒否する。
 * keyなしCopyFilesとregistry行も本文を検査し、一般unknownの無作用保証へは使わない。
 *
 * @param[in] inf 読取り中のINF handle。
 * @param[in] rejectExternalDependencies 未解決の外部依存を方式未対応として拒否する場合true。
 * @param[out] hasExternalDependencies 明示依存directiveを一件以上観測した場合true。充足を表さない。
 * @param[in] allowRequiredDriverComponents CopyINF/AddComponentを後段の有限関係検査へ残す場合true。
 * @return 禁止directiveがなく、CoInstaller節が無作用なら0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateInfInstallActions(
	const HINF inf, const bool rejectExternalDependencies, bool &hasExternalDependencies,
	const bool allowRequiredDriverComponents = false)
{
	hasExternalDependencies = false ;
	std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U>
									 sectionBuffer{} ;	// 現在section名の固定長受信領域。
	const std::unique_ptr<wchar_t[]> keyBuffer(
		// Directive key受信領域。
		new( std::nothrow) wchar_t[MAXIMUM_INF_FIELD_CHARACTERS]) ;
	const std::unique_ptr<wchar_t[]> lineBuffer(
		// 展開後line受信領域。
		new( std::nothrow) wchar_t[MAXIMUM_INF_FIELD_CHARACTERS]) ;
	// directive検査bufferを確保できなければ検証を開始しない。
	if( !keyBuffer || !lineBuffer) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	// SetupAPIが列挙するsectionを固定上限まで調べる。
	for( std::size_t sectionIndex = 0; sectionIndex < MAXIMUM_INF_SECTIONS; ++sectionIndex) {
		UINT required{} ;	// Null終端を含む現在section名の必要文字数。
		// INF section列挙の正常終端とAPI失敗を区別する。
		if( SetupEnumInfSectionsW( inf, static_cast<UINT>( sectionIndex), sectionBuffer.data(),
								 static_cast<UINT>( sectionBuffer.size()), &required) == FALSE) {
			const DWORD error = GetLastError() ;	// 列挙終了または構文失敗理由。
			return error == ERROR_NO_MORE_ITEMS ? 0 : nativeErrorFromWin32( error) ;
		}

		// 空またはbuffer範囲を超えるsection名を拒否する。
		if( required <= 1U || static_cast<std::size_t>( required) > sectionBuffer.size()) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const std::wstring_view		section( sectionBuffer.data()) ;	// 現在検査するsection名。
		constexpr std::wstring_view CO_INSTALLERS_SUFFIX =
			L".CoInstallers" ;	// 任意DLLを登録し得るsection suffix。
		// CoInstallers sectionは明示参照先が空の場合だけdriver-only経路で受理する。
		if( section.size() >= CO_INSTALLERS_SUFFIX.size() &&
		   stringsEqual( section.substr( section.size() - CO_INSTALLERS_SUFFIX.size()),
						CO_INSTALLERS_SUFFIX)) {
			const NativeError error =
				// 空参照判定。
				validateEmptyCoInstallers( inf, sectionBuffer.data()) ;
			// 実登録・コピー・未知動作を含む節は従来どおり拒否する。
			if( error != 0) {
				return error ;
			}
		}

		INFCONTEXT line{} ;	// 現在sectionで列挙するdirective line。
		// 先頭行を取得できないsectionはdirective走査を省略する。
		if( SetupFindFirstLineW( inf, sectionBuffer.data(), nullptr, &line) == FALSE) {
			continue ;
		}

		// 全line本文を先に検査し、keyなし登録行も既知禁止作用から除外する。
		do {
			DWORD lineCharacters{} ;	// Null終端を含む現在line全体の必要文字数。
			SetLastError( ERROR_SUCCESS) ;
			// INF行長の照会でbuffer不足以外の失敗を検出したら中止する。
			if( SetupGetLineTextW( &line, nullptr, nullptr, nullptr, nullptr, 0, &lineCharacters) ==
				   FALSE &&
			   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			// 空または上限超過のINF行を検査対象として採用しない。
			if( lineCharacters <= 1U || lineCharacters > MAXIMUM_INF_FIELD_CHARACTERS) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// INF行本文を取得できなければ実行経路検査を中止する。
			if( SetupGetLineTextW( &line, nullptr, nullptr, nullptr, lineBuffer.get(),
								 static_cast<DWORD>( MAXIMUM_INF_FIELD_CHARACTERS),
								 nullptr) == FALSE) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			const std::size_t lineLength =
				std::char_traits<wchar_t>::length( lineBuffer.get()) ;	// Null終端を除く文字数。
			std::transform( lineBuffer.get(), lineBuffer.get() + lineLength, lineBuffer.get(),
						   []( const wchar_t character) noexcept {
							   return character >= L'A' && character <= L'Z'
										  ? static_cast<wchar_t>( character - L'A' + L'a')
										  : character ;
						   }) ;
			const std::wstring_view lowerLine( lineBuffer.get(),
											  lineLength) ;	// 小文字化済みline。
			// CoInstallers登録やRun登録を含むINFをdriver-only経路から除外する。
			if( lowerLine.find( L"coinstallers32") != std::wstring_view::npos ||
			   lowerLine.find( L"\\currentversion\\run") != std::wstring_view::npos) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			DWORD keyCharacters{} ;	// Null終端を含むdirective keyの必要文字数。
			SetLastError( ERROR_SUCCESS) ;
			// key長の照会失敗時はkeyを持たない行とbuffer不足を区別する。
			if( SetupGetStringFieldW( &line, 0, nullptr, 0, &keyCharacters) == FALSE) {
				const DWORD keyError = GetLastError() ;	// 事前照会のSetupAPI結果。
				// 本文検証済みのCopyFiles・registry行はdirective key検査だけを省く。
				if( keyError != ERROR_INSUFFICIENT_BUFFER) {
					continue ;
				}
			}

			// 空または上限超過のdirective keyを拒否する。
			if( keyCharacters <= 1U || keyCharacters > MAXIMUM_INF_FIELD_CHARACTERS) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// directive key本文の取得失敗を保持して返す。
			if( SetupGetStringFieldW( &line, 0, keyBuffer.get(),
									static_cast<DWORD>( MAXIMUM_INF_FIELD_CHARACTERS),
									nullptr) == FALSE) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			const std::wstring_view key( keyBuffer.get()) ;	// 現在lineのdirective key。
			// 明示依存の存在だけを観測し、選択sectionや充足を推測しない。
			if( stringsEqual( key, L"Include") || stringsEqual( key, L"Needs") ||
			   stringsEqual( key, L"AddComponent") ||
			   (allowRequiredDriverComponents && stringsEqual( key, L"CopyINF"))) {
				hasExternalDependencies = true ;
				// 拒否policyを指定した既存経路では従来どおり解析を中止する。
				if( rejectExternalDependencies) {
					return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}
			}

			// 実行経路を作る禁止directiveを検出したらINFを拒否する。
			if( isAllowedValue( key, REJECTED_INF_DIRECTIVES) &&
			   !(allowRequiredDriverComponents && stringsEqual( key, L"CopyINF"))) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

		} while( SetupFindNextLine( &line, &line) != FALSE) ;
	}

	return nativeErrorFromWin32( ERROR_TOO_MANY_NAMES) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 相対pathの親directoryと子要素を結合する。
 *
 * 空のsource directoryは親を維持し、結果の安全性はworkspace.pathで再検証する。
 *
 * @param[in] parent 空またはseparatorで終わらない親相対path。
 * @param[in] child 空または結合する子相対path。
 * @return `\\`区切りで結合した相対path。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring joinRelativePath( const std::wstring_view parent,
											const std::wstring_view child)
{
	// 子要素が空の場合は親pathをそのまま保持する。
	if( child.empty()) {
		return std::wstring( parent) ;
	}

	// 親pathが空の場合は不要な先頭区切りを付けない。
	if( parent.empty()) {
		return std::wstring( child) ;
	}

	return std::wstring( parent) + L"\\" + std::wstring( child) ;
}

/**
 * @brief 保守相対参照の先頭にある現在directory表記だけを除く。
 * @param[in] relative SetupAPI取得済みの有限field。呼出し側が参照中の文字列を所有する。
 * @return 元文字列を借用するview。親参照・絶対path・内部dot等は変更せず後段で拒否する。
 * @note 単独dotは空directoryとする。CopyINFでは空参照として別途拒否する。
 */
[[nodiscard]] std::wstring_view stripReferenceCurrentDirectory( std::wstring_view relative) noexcept
{
	// 有限fieldの先頭にある明示現在directoryだけを取り除く。
	while( relative.starts_with( L".\\") || relative.starts_with( L"./")) {
		relative.remove_prefix( 2U) ;
	}

	return relative == L"." ? std::wstring_view{} : relative ;
}

//------------------------------------------------------------------------------
/**
 * @brief 大文字小文字を無視して一意な文字列を追加する。
 *
 * 同じPnP IDやfileを重複して上限消費しないために使う。
 *
 * @param[in,out] values 一意性を維持する文字列群。
 * @param[in] value 所有権を移して追加する候補文字列。
 * @return 新規追加した場合は`true`、既存値の場合は`false`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool appendUnique( std::vector<std::wstring> &values, std::wstring value)
{
	// 大小文字を除いて既存値と一致する場合は重複追加しない。
	if( std::ranges::any_of( values, [&value]( const std::wstring &current) {
		   return stringsEqual( current, value) ;
	   })) {
		return false ;
	}

	values.push_back( std::move( value)) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在platform用Models sectionからPnP IDを収集する。
 *
 * SetupDiGetActualModelsSectionをWindowsのTargetOSVersion選択規則の正本とし、x86専用sectionを候補化しない。
 *
 * @param[in] inf 読取り中のINF handle。
 * @param[in] maximumHardwareIds 保持する一意ID数上限。
 * @param[out] hardwareIds 成功時の現在OS／architecture用PnP ID群。
 * @param[out] published 新metadata用途だけの元節/種別です。Nullでは既存ID列だけを保持します。
 * @return 一件以上取得時は0、適用section欠落または上限超過時HRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError collectHardwareIds(
	const HINF inf, const std::size_t maximumHardwareIds, std::vector<std::wstring> &hardwareIds,
	std::vector<OfficialInfPublishedModelSection> *published = nullptr)
{
	hardwareIds.clear() ;
	// 新receiptの部分集合を別INFへ持ち越しません。
	if( published != nullptr) {
		published->clear() ;
	}

	INFCONTEXT manufacturer{} ;	// 現在処理するManufacturer line。
	// Manufacturer sectionがなければModels対応を推測しない。
	if( SetupFindFirstLineW( inf, L"Manufacturer", nullptr, &manufacturer) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 全manufacturerについて、現在platformにWindowsが選ぶModels sectionだけを調べる。
	do {
		DWORD required{} ;	// Null終端を含むModels section名の必要文字数。
		// 現在platform用Models sectionの必要長が取得不能または不正なら除外する。
		if( SetupDiGetActualModelsSectionW( &manufacturer, nullptr, nullptr, 0, &required, nullptr) ==
			   FALSE ||
		   required <= 1 || required > MAXIMUM_MODEL_SECTION_CHARACTERS) {
			continue ;
		}

		std::vector<wchar_t> sectionBuffer( required) ;	// Models section名の受信buffer。
		// 現在platform用Models sectionを取得できない項目を除外する。
		if( SetupDiGetActualModelsSectionW( &manufacturer, nullptr, sectionBuffer.data(),
										  static_cast<DWORD>( sectionBuffer.size()), nullptr,
										  nullptr) == FALSE) {
			continue ;
		}

		INFCONTEXT model{} ;	// 選択されたModels sectionの現在line。
		// 対象Models sectionに読取り可能な先頭行がなければ除外する。
		if( SetupFindFirstLineW( inf, sectionBuffer.data(), nullptr, &model) == FALSE) {
			continue ;
		}

		OfficialInfPublishedModelSection section ;	// 新metadata用途だけの原選択節です。
		// 既存callerへ新metadataの容量条件を追加しません。
		if( published != nullptr) {
			// 公開節の上限や重複を部分identityへ丸めません。
			if( published->size() >= 128U || std::ranges::any_of( *published, [&]( const auto &value) {
				   return value.modelSection == sectionBuffer.data() ;
			   })) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			section.modelSection = sectionBuffer.data() ;
		}

		// Models sectionの全lineからHardware IDとcompatible IDを取得する。
		do {
			const DWORD fields = SetupGetFieldCount( &model) ;	// Keyを除くfield数。
			// Models行に必要なinstall sectionとID fieldが揃わなければ拒否する。
			if( fields < 2) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// Field 1はinstall sectionであるため、field 2以降のPnP IDだけを保持する。
			for( DWORD field = 2; field <= fields; ++field) {
				std::wstring	  hardwareId ;	// 現在lineから展開したPnP ID。
				// Models行のPnP ID fieldを読み取った結果。適用対象へ登録する前に確認する。
				const NativeError readResult = readInfField( model, field, hardwareId) ;
				// PnP IDの取得失敗、長さ超過、区切り欠落を拒否する。
				if( readResult != 0 || hardwareId.size() > MAXIMUM_HARDWARE_ID_CHARACTERS ||
				   hardwareId.find( L'\\') == std::wstring::npos) {
					return readResult != 0 ? readResult : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				// 新receiptだけで元fieldのHardware/Compatible区分を保存します。
				if( published != nullptr) {
					static_cast<void>( appendUnique(
						field == 2U ? section.hardwareIds : section.compatibleIds, hardwareId)) ;
				}

				// 重複除去後のPnP ID数が上限を超えたら部分集合を破棄する。
				if( appendUnique( hardwareIds, std::move( hardwareId)) &&
				   hardwareIds.size() > maximumHardwareIds) {
					hardwareIds.clear() ;
					return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
				}
			}
		} while( SetupFindNextLine( &model, &model) != FALSE) ;
		// 一節の全行成功後だけ原節を新receiptへ結合します。
		if( published != nullptr) {
			published->push_back( std::move( section)) ;
		}
	} while( SetupFindNextLine( &manufacturer, &manufacturer) != FALSE) ;

	return hardwareIds.empty() ? nativeErrorFromWin32( ERROR_NOT_FOUND) : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同INFのsource IDへ結んだfile subdirと媒体pathを完全取得します。
 * @param[in] inf 同期呼出し中だけ借用する元INFです。
 * @param[in] fileName pathを含まない元source file名です。
 * @param[out] sourceDirectory 成功時は元file subdir、失敗時は空です。
 * @param[out] mediaDirectory 成功時は同source IDのinstallation-root相対媒体path、失敗時は空です。
 * @return 完全取得成功0、欠損・重複・過長・部分取得のHRESULTです。非zero原診断を維持します。
 * @pre 二つの出力は別の格納先であり、fileNameともaliasしないこと。
 * @note Windowsのamd64優先解決を使い、媒体root記法の先頭と末尾一backslashだけを相対意味へ変換します。
 *       保護workspaceとservice固有の安全path検査は呼出側で必須です。fileを取得・実行しません。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readInfSourceDirectories( HINF inf, const std::wstring &fileName,
												   std::wstring &sourceDirectory,
												   std::wstring &mediaDirectory)
{
	sourceDirectory.clear() ;
	mediaDirectory.clear() ;
	INFCONTEXT sourceLine{} ;	// Windowsと同じarchitecture優先の元行です。
	INFCONTEXT duplicate{} ;	// 同元keyの曖昧性だけを確認する借用contextです。
	// 別fileや別architectureの行から位置を補完しません。
	if( !SetupFindFirstLineW( inf, L"SourceDisksFiles.amd64", fileName.c_str(), &sourceLine) &&
	   !SetupFindFirstLineW( inf, L"SourceDisksFiles", fileName.c_str(), &sourceLine)) {
		const auto error = GetLastError() ;	// 元行読取り診断です。
		return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
	}

	// 同じ有効file名の競合を先頭行採用で隠しません。
	if( SetupFindNextMatchLineW( &sourceLine, fileName.c_str(), &duplicate)) {
		return nativeErrorFromWin32( ERROR_DUP_NAME) ;
	}

	UINT  sourceId{} ;	// 同INFのSourceDisksNamesを引く元媒体IDです。
	DWORD required{} ;	// 終端込みsource subdir必要文字数です。
	SetLastError( ERROR_SUCCESS) ;
	// 有限な二段取得の必要長照会以外の失敗を許可へ変換しません。
	if( !SetupGetSourceFileLocationW( inf, nullptr, fileName.c_str(), &sourceId, nullptr, 0U,
									&required) &&
	   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		const auto error = GetLastError() ;	// 補助API前の元診断です。
		return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
	}

	// 不正な必要長を部分位置や過大bufferへ変換しません。
	if( required == 0U || required > MAXIMUM_INF_FIELD_CHARACTERS) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	const UINT			 expectedSourceId = sourceId ;	// 二段で同媒体へのbindingを保持します。
	std::vector<wchar_t> source( required) ;			// 同期中だけ所有する有限subdirです。
	DWORD				 readRequired{} ;				// 二段目の完全必要長です。
	SetLastError( ERROR_SUCCESS) ;
	// 元媒体または完全値が取得できない場合は部分許可を公開しません。
	if( !SetupGetSourceFileLocationW( inf, nullptr, fileName.c_str(), &sourceId, source.data(),
									static_cast<DWORD>( source.size()), &readRequired)) {
		const auto error = GetLastError() ;	// 原取得診断です。
		return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
	}

	const auto sourceEnd = std::ranges::find( source, L'\0') ;	// 有限値の終端です。
	// 必要長・終端・source IDの一致だけで元file subdirを保持します。
	if( sourceId != expectedSourceId || sourceEnd == source.end() || readRequired != required ||
	   static_cast<std::size_t>( sourceEnd - source.begin()) + 1U != required) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const auto mediaKey = std::to_wstring( sourceId) ;	// Windowsの媒体ID keyです。
	INFCONTEXT mediaLine{} ;							// 同INF・同IDのarchitecture優先元媒体行です。
	// 別IDやrootへの暗黙fallbackで媒体欠損を隠しません。
	if( !SetupFindFirstLineW( inf, L"SourceDisksNames.amd64", mediaKey.c_str(), &mediaLine) &&
	   !SetupFindFirstLineW( inf, L"SourceDisksNames", mediaKey.c_str(), &mediaLine)) {
		const auto error = GetLastError() ;	// 元媒体行診断です。
		return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
	}

	// 同source IDの競合を名称一致や先頭行で救済しません。
	if( SetupFindNextMatchLineW( &mediaLine, mediaKey.c_str(), &duplicate)) {
		return nativeErrorFromWin32( ERROR_DUP_NAME) ;
	}

	DWORD mediaRequired{} ;	// 終端込み元媒体path必要文字数です。
	SetLastError( ERROR_SUCCESS) ;
	// 同IDの媒体位置が取得できない場合は空媒体を補完しません。
	if( !SetupGetSourceInfoW( inf, sourceId, SRCINFO_PATH, nullptr, 0U, &mediaRequired) &&
	   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		const auto error = GetLastError() ;	// 原媒体照会診断です。
		return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
	}

	// 媒体位置も有限な完全値だけを受信します。
	if( mediaRequired == 0U || mediaRequired > MAXIMUM_INF_FIELD_CHARACTERS) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	std::vector<wchar_t> media( static_cast<std::size_t>( mediaRequired) +
							   1U) ;			// 元必要長に末尾一区切り分だけ余裕を持つ有限領域です。
	DWORD				 mediaReadRequired{} ;	// 二段目の元媒体必要長です。
	SetLastError( ERROR_SUCCESS) ;
	// 部分取得は同名byteのsource許可へ昇格しません。
	if( !SetupGetSourceInfoW( inf, sourceId, SRCINFO_PATH, media.data(),
							static_cast<DWORD>( media.size()), &mediaReadRequired)) {
		const auto error = GetLastError() ;	// 原媒体取得診断です。
		return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
	}

	const auto mediaEnd = std::ranges::find( media, L'\0') ;	// 有限元媒体終端です。
	const auto mediaLength =
		// NULを含まない実媒体文字数です。
		static_cast<std::size_t>( mediaEnd - media.begin()) ;
	const bool trailingDelimiter = mediaLength == mediaRequired && mediaLength != 0U &&
								   // 実APIで必要長に含まれない末尾一区切りだけです。
								   media[mediaLength - 1U] == L'\\' ;
	// 通常のNUL一致または実観測した末尾一区切り差以外の部分値・長さ差を拒否します。
	if( mediaEnd == media.end() || mediaReadRequired != mediaRequired ||
	   (mediaLength + 1U != mediaRequired && !trailingDelimiter)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::wstring_view mediaPath( media.data(),
								mediaLength) ;	// 完全取得済みinstallation root相対値です。
	// 非空root-only媒体を正規化で空媒体へ変えず、元両出力を空のまま拒否します。
	if( !mediaPath.empty() &&
	   std::ranges::all_of( mediaPath, []( const wchar_t value) { return value == L'\\' ; })) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// quoted末尾区切りを同じ媒体directoryへ結び、途中の区切りや任意文字は削除しません。
	if( trailingDelimiter) {
		mediaPath.remove_suffix( 1U) ;
	}

	// 公式INFの一先頭backslashは媒体root相対です。UNCの二先頭は次の安全検査へ残します。
	if( mediaPath.starts_with( L"\\") && !mediaPath.starts_with( L"\\\\")) {
		mediaPath.remove_prefix( 1U) ;
	}

	// 両方の完全取得に成功した後だけ、同IDの位置を公開します。
	sourceDirectory.assign( source.data(), required - 1U) ;
	mediaDirectory.assign( mediaPath) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在architecture用SourceDisksFilesを検証する。
 *
 * x64装飾sectionを優先し、SetupGetSourceFileLocationが返すdirectoryをworkspace境界とZIP entryへ再照合する。Printer以外は呼出側
 * policyによりSYSを必須にする。
 *
 * @param[in] inf 読取り中のINF handle。
 * @param[in] workspace 安全な絶対path変換を行う保護workspace。
 * @param[in] entries ZIP検証済みfile群。
 * @param[in] infParent INFのworkspace基準親directory。
 * @param[in] maximumFiles 保持する一意参照file数上限。
 * @param[in] requireDriverBinary SYS参照を必須にする場合true。
 * @param[out] sourceFiles 成功時のworkspace基準参照file群。
 * @param[in] referenceSection nullなら従来の導入検査、非nullなら保守棚卸しの固定source節。
 * @param[in] allowReferencedExecutablesForContent 非圧縮EXEだけを内容検査に含める場合true。実行しない。
 * @param[in] serviceExecutables 同INFの必要SWC serviceと同節コピーを検査した相対source位置です。包括許可ではありません。
 * @return 全参照fileが存在しpolicyを満たす場合は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError collectSourceFiles(
	const HINF inf, const OfficialDownloadWorkspace &workspace,
	const std::span<const OfficialZipEntry> entries, const std::wstring_view infParent,
	const std::size_t maximumFiles, const bool requireDriverBinary,
	std::vector<std::wstring> &sourceFiles, const wchar_t *const referenceSection = nullptr,
	const bool							allowReferencedExecutablesForContent = false,
	const std::span<const std::wstring> serviceExecutables					 = {})
{
	sourceFiles.clear() ;
	INFCONTEXT source{} ;	// 現在処理するSourceDisksFiles line。
	// amd64用と共通のSourceDisksFilesのどちらもなければ参照fileを推測しない。
	if( referenceSection != nullptr
		   ? SetupFindFirstLineW( inf, referenceSection, nullptr, &source) == FALSE
		   : (SetupFindFirstLineW( inf, L"SourceDisksFiles.amd64", nullptr, &source) == FALSE &&
			  SetupFindFirstLineW( inf, L"SourceDisksFiles", nullptr, &source) == FALSE)) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	bool hasDriverBinary{} ;	// `true`の場合は少なくとも一つのSYSが存在する。
	// 現在architectureの全source fileを検証し、欠落を一件でも許可しない。
	do {
		std::wstring fileName ;										// SourceDisksFiles lineのkeyであるfile名。
		NativeError	 result = readInfField( source, 0, fileName) ;	// Key取得結果。
		// source file名の取得失敗やpath区切り混入を検出したら部分結果を破棄する。
		if( result != 0 || fileName.find_first_of( L"/\\") != std::wstring::npos) {
			sourceFiles.clear() ;
			return result != 0 ? result : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		std::wstring sourceDirectory ;	// 同INF・同source IDの完全file subdirです。
		std::wstring mediaDirectory ;	// 同じ媒体のinstallation-root相対pathです。
		result = readInfSourceDirectories( inf, fileName, sourceDirectory, mediaDirectory) ;
		// 通常導入でも媒体pathを捨てず、欠損・曖昧・部分取得の原診断を保持します。
		if( result != 0) {
			sourceFiles.clear() ;
			return result ;
		}

		const std::wstring_view mediaPath =
			referenceSection != nullptr
				? stripReferenceCurrentDirectory( mediaDirectory)
				: std::wstring_view( mediaDirectory) ;	// 保守だけの現在directory解決。
		const std::wstring_view fileDirectory =
			referenceSection != nullptr
				? stripReferenceCurrentDirectory( sourceDirectory)
				: std::wstring_view( sourceDirectory) ;							// 通常の元file subdirを保持します。
		std::wstring relativePath = joinRelativePath( infParent, mediaPath) ;	// 媒体基準位置。
		relativePath			  = joinRelativePath( relativePath, fileDirectory) ;
		relativePath			  = joinRelativePath( relativePath, fileName) ;
		// workspaceとinventoryの両方に存在しない参照fileを拒否する。
		if( workspace.path( relativePath).empty() || !containsEntry( entries, relativePath)) {
			sourceFiles.clear() ;
			return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
		}

		const std::wstring extension = lowerExtension( relativePath) ;	// 参照file拡張子。
		const bool serviceExecutable =									// 同INFのcopy全宛先へ結んだ位置付き元sourceだけです。
			extension == L".exe" && std::ranges::any_of( serviceExecutables, [&]( const auto &name) {
				return stringsEqual(
					name, joinRelativePath( joinRelativePath( mediaPath, fileDirectory), fileName)) ;
			}) ;
		// 保守内容EXEと同INFの必要service EXE以外は、参照program・archive・firmware拒否を維持します。
		if( referenceSection == nullptr &&
		   std::ranges::find( REJECTED_REFERENCED_EXTENSIONS, extension) !=
			   REJECTED_REFERENCED_EXTENSIONS.end() &&
		   !(allowReferencedExecutablesForContent && extension == L".exe") && !serviceExecutable) {
			sourceFiles.clear() ;
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		hasDriverBinary = hasDriverBinary || extension == L".sys" ;
		// 重複除去後の参照file数が上限を超えたら部分結果を破棄する。
		if( appendUnique( sourceFiles, std::move( relativePath)) &&
		   sourceFiles.size() > maximumFiles) {
			sourceFiles.clear() ;
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}
	} while( SetupFindNextLine( &source, &source) != FALSE) ;

	return !sourceFiles.empty() && (!requireDriverBinary || hasDriverBinary)
			   ? 0
			   : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
}

//------------------------------------------------------------------------------
/**
 * @brief INF用catalog file名を現在architecture向けに取得する。
 *
 * x64、NT、共通の順に有限探索し、複数候補を推測しない。
 *
 * @param[in] inf 読取り中のINF handle。
 * @param[out] catalogFile 成功時のdirectoryを含まないCAT file名。
 * @return 必須directive取得時は0、欠落またはpath不正時HRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readCatalogFile( const HINF inf, std::wstring &catalogFile)
{
	// x64固有、NT共通、無装飾の順でCAT指定を照合するkey集合。
	constexpr std::array KEYS{L"CatalogFile.ntamd64", L"CatalogFile.NT", L"CatalogFile"} ;
	NativeError			 result = nativeErrorFromWin32( ERROR_LINE_NOT_FOUND) ;	// 最終検索結果。
	// Platform固有directiveから共通directiveの順に最初の一件だけを取得する。
	for( const wchar_t *const key : KEYS) {
		result = readInfDirective( inf, L"Version", key, 1, catalogFile) ;
		// 優先順で最初に取得できたcatalog指定を採用する。
		if( result == 0) {
			break ;
		}
	}

	// catalog名の取得失敗、path要素混入、CAT以外の拡張子を拒否する。
	if( result != 0 || catalogFile.find_first_of( L"/\\") != std::wstring::npos ||
	   !stringsEqual( lowerExtension( catalogFile), L".cat")) {
		catalogFile.clear() ;
		return result != 0 ? result : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	return 0 ;
}

/**
 * @brief 空fieldも含め、棚卸しの一fieldを有限文字列へ読む。
 * @param[in,out] line SetupAPIから取得した借用行context。
 * @param[in] field 値を取得するfield番号。
 * @param[out] value 成功時の値。空も許可し、失敗時は空。
 * @return 読取成功0、過長またはSetupAPI失敗のHRESULT。
 */
[[nodiscard]] NativeError readInstallInventoryField( INFCONTEXT &line, DWORD field,
													std::wstring &value)
{
	value.clear() ;
	std::array<wchar_t, MAXIMUM_INF_FIELD_CHARACTERS> buffer{} ;	// 有限の同期受信領域。
	// 値の切捨てを認めず、空fieldとAPI失敗を区別する。
	if( SetupGetStringFieldW( &line, field, buffer.data(), static_cast<DWORD>( buffer.size()),
							nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	value = buffer.data() ;
	return 0 ;
}

/**
 * @brief Section名の長さと構文区切りを検証する。
 * @param[in] name 外部から取得したsection名。
 * @return 空・過長・NUL・path・構文区切りがない場合true。
 */
[[nodiscard]] bool validInstallInventorySectionName( std::wstring_view name) noexcept
{
	return !name.empty() && name.size() <= 254U &&
		   name.find_first_of( std::wstring_view( L"\0\r\n[]\\/", 7U)) == std::wstring_view::npos ;
}

/**
 * @brief Models所属を確認済みの導入名をWindowsの実在DDInstallへ解決する。
 * @param[in] inf 同期借用するINF handle。
 * @param[in] base 現OS用Modelsで確認した安全な導入名。
 * @param[out] selected 成功時だけ実在する節名を保持する。
 * @return Windows選択と実在確認成功0、選択失敗または節欠落のHRESULT。
 */
[[nodiscard]] NativeError resolveActualInstallInventorySection( HINF inf, const std::wstring &base,
															   std::wstring &selected)
{
	std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS> section{} ;	// 解決したDDInstall名。
	DWORD required{} ;													// APIが返すNUL込み文字数です。byte数ではありません。
	// Windowsの修飾選択を使用し、独自のarchitecture suffix推測を行わない。
	if( SetupDiGetActualSectionToInstallW( inf, base.c_str(), section.data(),
										 static_cast<DWORD>( section.size()), &required,
										 nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const auto end =
		// 固定文字容量内の実終端です。
		std::find( section.begin(), section.end(), L'\0') ;
	// 必要文字数と終端を確認し、未修飾fallbackの実在も別に要求します。
	if( required == 0U || required > section.size() || end == section.end() ||
	   !validInstallInventorySectionName(
		   std::wstring_view( section.data(), static_cast<std::size_t>( end - section.begin()))) ||
	   SetupGetLineCountW( inf, section.data()) < 0) {
		return nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND) ;
	}

	selected = section.data() ;
	return 0 ;
}

/**
 * @brief 現OS用Modelsに属する導入名をDDInstallの実在節へ解決する。
 * @param[in] inf 本呼出し中有効な読取専用handle。
 * @param[in] base 入力検証済みの導入名。
 * @param[out] selected 成功時だけ実在する選択節名を保持する。
 * @return Modelsとの一致と実在を確認した場合0、未登録・欠落・容量・API失敗のHRESULT。
 */
[[nodiscard]] NativeError selectInstallInventorySection( HINF inf, const std::wstring &base,
														std::wstring &selected)
{
	INFCONTEXT manufacturer{} ;	// 現OS向けModelsを選ぶメーカー行。
	// Modelsへの所属を確認できない入力を任意節指定として通さない。
	if( SetupFindFirstLineW( inf, L"Manufacturer", nullptr, &manufacturer) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	std::size_t lines{} ;		// メーカー行とModels行の累積上限消費。
	bool		found = false ;	// 少なくとも一つの現OS Modelsに導入名がある場合true。
	// 全メーカーを有限に調べ、旧OS・別architectureのModelsを使わない。
	do {
		// 先頭行から上限を消費し、メーカー行だけの過大入力も拒否する。
		if( ++lines > MAXIMUM_INSTALL_INVENTORY_LINES) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS> models{} ;	// 現OS用節名。
		// 現OSに選べないメーカーは対象外にし、別Modelsへfallbackしない。
		if( SetupDiGetActualModelsSectionW( &manufacturer, nullptr, models.data(),
										  static_cast<DWORD>( models.size()), nullptr,
										  nullptr) == FALSE) {
			const DWORD error = GetLastError() ;	// 対象外と容量・構文失敗を区別する。
			// 節選択の容量失敗を対象外として握り潰さない。
			if( error != ERROR_NO_COMPAT_DRIVERS && error != ERROR_SECTION_NOT_FOUND) {
				return nativeErrorFromWin32( error) ;
			}

			continue ;
		}

		INFCONTEXT model{} ;	// 選択されたModels内の行。
		// 欠落Modelsを現在の適合モデルと推測しない。
		if( SetupFindFirstLineW( inf, models.data(), nullptr, &model) == FALSE) {
			continue ;
		}

		// 導入名fieldだけを読み、PnP ID fieldを取得・保持しない。
		do {
			// 共有Modelsの再登場も走査量に数え、無制限な重複処理を止める。
			if( ++lines > MAXIMUM_INSTALL_INVENTORY_LINES) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			std::wstring	  name ;									// 比較中だけ所有する導入名。
			const NativeError error = readInfField( model, 1U, name) ;	// 必須fieldの取得結果。
			// 不正Models行を読み飛ばして部分集合の承認を行わない。
			if( error != 0 || SetupGetFieldCount( &model) < 2U ||
			   !validInstallInventorySectionName( name)) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			found = found || stringsEqual( name, base) ;
		} while( SetupFindNextLine( &model, &model) != FALSE) ;
	} while( SetupFindNextLine( &manufacturer, &manufacturer) != FALSE) ;
	// 現OSのModelsにない導入名をWindowsへ解決させない。
	if( !found) {
		return nativeErrorFromWin32( ERROR_NOT_FOUND) ;
	}

	return resolveActualInstallInventorySection( inf, base, selected) ;
}

/**
 * @brief ローカルsectionを一度だけ有限queueへ追加する。
 * @param[in,out] pending 単独所有する最大1,024節の走査queue。
 * @param[in] name 入力検証済みのsection名。
 * @param[in] kind section行形式。
 * @return 追加・同形式既存時0、矛盾形式・容量違反のHRESULT。
 */
[[nodiscard]] NativeError queueInstallInventorySection(
	std::vector<InstallInventorySection> &pending, const std::wstring &name,
	InstallInventorySectionKind kind)
{
	const auto prior = std::ranges::find_if( pending, [&name]( const InstallInventorySection &item) {
		return stringsEqual( item.name, name) ;
	}) ; // 共有・循環でも同じ節を繰り返し走査しない。
	// 同一節の二つの異なる解釈を黙って統合しない。
	if( prior != pending.end()) {
		return prior->kind == kind ? 0 : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// 1,024節を超える到達graphを部分成功として返さない。
	if( pending.size() >= MAXIMUM_INSTALL_INVENTORY_SECTIONS) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	pending.push_back( {name, kind}) ;
	return 0 ;
}

/**
 * @brief 棚卸しdirectiveの宣言種類を分類する。
 * @param[in] key 展開済みの有限key。値は参照しない。
 * @return 既知の宣言種類またはUNKNOWN_DIRECTIVE。
 */
[[nodiscard]] OfficialInfInstallEffectKind installInventoryEffectKind(
	std::wstring_view key) noexcept
{
	// 実行指示は内容署名や標準処理へ読み替えない。
	if( stringsEqual( key, L"RunPreSetupCommands") || stringsEqual( key, L"RunPostSetupCommands")) {
		return OfficialInfInstallEffectKind::COMMAND_EXECUTION ;
	}

	// DLL登録も任意codeに到達し得る独立した宣言として保持する。
	if( stringsEqual( key, L"RegisterDlls") || stringsEqual( key, L"UnregisterDlls")) {
		return OfficialInfInstallEffectKind::DLL_REGISTRATION ;
	}

	// 別INF取込みを通常のfile copyと区別する。
	if( stringsEqual( key, L"CopyINF")) {
		return OfficialInfInstallEffectKind::COPY_INF ;
	}

	// 参照の存在と外部依存充足を別に記録する。
	if( stringsEqual( key, L"Include") || stringsEqual( key, L"Needs") ||
	   stringsEqual( key, L"AddComponent")) {
		return OfficialInfInstallEffectKind::EXPLICIT_DEPENDENCY ;
	}

	constexpr std::array<std::wstring_view, 42> known{
		L"CopyFiles",
		L"AddReg",
		L"DelReg",
		L"DelFiles",
		L"RenFiles",
		L"BitReg",
		L"AddProperty",
		L"DelProperty",
		L"DriverVer",
		L"FeatureScore",
		L"ExcludeID",
		L"Reboot",
		L"LogConfig",
		L"ProfileItems",
		L"UpdateInis",
		L"UpdateIniFields",
		L"Ini2Reg",
		L"AddService",
		L"DelService",
		L"AddInterface",
		L"AddSoftware",
		L"KmdfService",
		L"UmdfService",
		L"UmdfServiceOrder",
		L"ServiceBinary",
		L"ServiceType",
		L"StartType",
		L"ErrorControl",
		L"DisplayName",
		L"Description",
		L"LoadOrderGroup",
		L"Dependencies",
		L"BootFlags",
		L"KmdfLibraryVersion",
		L"UmdfLibraryVersion",
		L"UmdfServiceBinary",
		L"UmdfDeviceGroup",
		L"UmdfDispatcher",
		L"ComponentIDs",
		L"SoftwareType",
		L"SoftwareId",
		L"EventMessageFile"} ;	// 既知宣言であって実行許可ではない。
	return isAllowedValue( key, known) ? OfficialInfInstallEffectKind::STANDARD_DIRECTIVE
									  : OfficialInfInstallEffectKind::UNKNOWN_DIRECTIVE ;
}

/**
 * @brief 現棚卸しが辿らない宣言範囲を既知種類へ分離する。
 * @param[in] key この行だけの有限directive名。
 * @param[in] values 値は同期借用し、本文を結果へ保存しない。
 * @return 一宣言の不足種類。該当なしも全構文の完全性を示さない。
 */
[[nodiscard]] std::optional<OfficialInfInstallCoverageKind> installInventoryCoverageKind(
	std::wstring_view key, std::span<const std::wstring> values)
{
	constexpr std::array<std::wstring_view, 7> unfollowed{
		L"AddProperty", L"DelProperty",		L"LogConfig", L"ProfileItems",
		L"UpdateInis",	L"UpdateIniFields", L"Ini2Reg"} ;	// 既知だが今回参照先を走査しない形式。
	// 宣言の認識と参照先解釈の完了を混同しない。
	if( isAllowedValue( key, unfollowed)) {
		return OfficialInfInstallCoverageKind::UNFOLLOWED_SECTION_REFERENCES ;
	}

	// 第4 fieldだけがevent-log節で、後続の種類や名称を節として扱わない。
	if( stringsEqual( key, L"AddService") && values.size() > 3U && !values[3].empty()) {
		return OfficialInfInstallCoverageKind::UNFOLLOWED_SERVICE_EVENTLOG ;
	}

	// 独立softwareの予約を標準driverだけの作用と認定しない。
	if( stringsEqual( key, L"AddSoftware")) {
		return OfficialInfInstallCoverageKind::SOFTWARE_INSTALLATION_NOT_ASSESSED ;
	}

	// 未知を無作用へ読み替えず、元作用enumと別の不足も保持する。
	if( installInventoryEffectKind( key) == OfficialInfInstallEffectKind::UNKNOWN_DIRECTIVE) {
		return OfficialInfInstallCoverageKind::UNKNOWN_DIRECTIVE ;
	}

	return std::nullopt ;
}

/** @brief 一INFの全選択が共同消費する有限走査予算。 */
struct MaintenanceStructureBudget {
	/// Models・Version・source・選択到達節の累積読取行数。
	std::size_t lines{} ;
	/// 全選択で訪問した節数。共有節の再観測も消費する。
	std::size_t sections{} ;
	/// 全選択で保持した作用数。
	std::size_t effects{} ;
	/// 全選択で保持した明示参照数。
	std::size_t references{} ;
	/// 全選択で保持したservice構造数。
	std::size_t services{} ;
	/// 全選択で保持した具体的診断数。
	std::size_t issues{} ;
	/// 全選択で保持した用途観測数。
	std::size_t fileUses{} ;
	/// 全選択で保持した未解釈作用の観測数。
	std::size_t coverageGaps{} ;
} ;

/** @brief 有限queueで到達したnamed copyの元destinationとsourceを保持する私有観測。 */
struct MaintenanceCopyDestination {
	/// 同じINFでCopyFilesから到達したlist名。
	std::wstring section ;
	/// 読取済み行の展開後destination名。導入先の充足証拠ではない。
	std::wstring destination ;
	/// 明示別名または省略時のdestinationと同名の元source名。
	std::wstring source ;
	/// 全値証明へ結合した同元raw行。通常readerでは未結合。
	std::size_t	 rawRow{MAXIMUM_INSTALL_INVENTORY_ITEMS} ;
} ;

/** @brief 同INFのnamed固有DestinationDirsとWindowsの非実行展開結果。 */
struct MaintenanceDestinationDirectory {
	/// 到達したnamed copy listと完全一致する元key。
	std::wstring  section ;
	/// 全数値解析に成功した明示DIRID。未対応値を既知directoryへ補完しない。
	std::uint32_t dirid{} ;
	/// DestinationDirsの安全相対subdir。媒体pathとは別の値。
	std::wstring  subdirectory ;
	/// 同HINFのSetupAPIが返した導入先directory。fileをopenしない。
	std::wstring  expandedDirectory ;
	/// 位置根拠の元診断。成功0、未対応とAPI失敗は非零。
	NativeError	  error{nativeErrorFromWin32( ERROR_NOT_SUPPORTED)} ;
	/// 元keyと全fieldを比較したraw行。
	std::size_t	  rawRow{MAXIMUM_INSTALL_INVENTORY_ITEMS} ;
	/// 同じ二段target APIの必要長・取得長・終端が一致した場合true。
	bool		  targetComplete{} ;
} ;

/** @brief 構築済み私有vectorを同期借用する一copyの位置根拠cache。 */
struct MaintenanceCopyBinding {
	/// 構築完了したcopiesの一行。cache使用中に元vectorを変更しない。
	const MaintenanceCopyDestination	  *copy{} ;
	/// 構築完了したdirectoriesの一意entry。未確定ではnull。
	const MaintenanceDestinationDirectory *directory{} ;
	/// 同HINFの展開済み全target。成功根拠がある場合だけ保持する。
	std::wstring						   fullTarget ;
	/// 同じ明示DIRID／subdir／destinationの全raw target。
	std::wstring						   rawTarget ;
	/// 未確定・重複・未対応の元診断。根拠一意なら0。
	NativeError							   error{nativeErrorFromWin32( ERROR_NOT_SUPPORTED)} ;
} ;

/**
 * @brief 失敗を未対応・合格で上書きしないよう個別構造結果を併合する。
 * @param[in,out] target 集約先。未検査から開始できる。
 * @param[in] source 一つの観測結果。診断値は最初の同段階を保持する。
 */
void mergeMaintenanceFinding( MaintenanceInspectionFinding		&target,
							 const MaintenanceInspectionFinding &source) noexcept
{
	// 最初の結果と、既知失敗への昇格だけを優先して元診断を保持する。
	if( target.state == MaintenanceInspectionState::NOT_CHECKED ||
	   (source.state == MaintenanceInspectionState::FAILED && target.state != source.state) ||
	   (source.state == MaintenanceInspectionState::UNSUPPORTED &&
		target.state == MaintenanceInspectionState::PASSED)) {
		target = source ;
	}
}

/**
 * @brief 元宣言へ結合した個別診断を保持し選択parserへ射影する。
 * @param[in,out] install この選択だけの構造観測。
 * @param[in] section 元の節名。同期借用して所有copyへ移す。
 * @param[in] directive 元のdirective名。
 * @param[in] reason 具体的な未対応または不正理由。
 * @param[in] finding 元HRESULTを持つ独立結果。
 */
void addMaintenanceIssue( MaintenanceInfInstallStructure &install, const std::wstring &section,
						 const std::wstring &directive, MaintenanceInfStructureReason reason,
						 MaintenanceInspectionFinding finding)
{
	install.issues.push_back( {section, directive, reason, finding}) ;
	mergeMaintenanceFinding( install.parser, finding) ;
}

/**
 * @brief 展開後の全flags fieldを厳密なuint32十進／十六進へ変換する。
 * @param[in] value SetupAPIが選択localeで展開した全field。借用のみ。
 * @param[out] flags 成功時だけ更新する。失敗時に0や2を補完しない。
 * @param[out] reason 失敗時の具体的理由。成功時の値は使用しない。
 * @return 数値成功PASSED、未展開・未対応表現UNSUPPORTED、不正・overflowはFAILED。
 * @note 元Strings単値がWindows内で切捨てられていないことまでは検証しない。
 */
[[nodiscard]] MaintenanceInspectionFinding parseMaintenanceFlags(
	std::wstring_view value, std::uint32_t &flags, MaintenanceInfStructureReason &reason) noexcept
{
	// 残ったtokenを未定義・循環のどちらとも数値へ補完しない。
	if( value.find( L'%') != std::wstring_view::npos) {
		reason = MaintenanceInfStructureReason::UNRESOLVED_FLAGS_TOKEN ;
		return {MaintenanceInspectionState::UNSUPPORTED, nativeErrorFromWin32( ERROR_NOT_SUPPORTED)} ;
	}

	// Windowsの符号付き許可表現を今回のunsigned形式へ黙って補正しない。
	if( value.starts_with( L"+")) {
		reason = MaintenanceInfStructureReason::FLAGS_FORMAT_NOT_SUPPORTED ;
		return {MaintenanceInspectionState::UNSUPPORTED, nativeErrorFromWin32( ERROR_NOT_SUPPORTED)} ;
	}

	std::uint32_t radix = 10U ;	// 0x prefixの場合だけ基数を切り替える。
	// 十六進を明示したfieldのprefixだけを除き、残り全文を検査する。
	if( value.starts_with( L"0x") || value.starts_with( L"0X")) {
		radix = 16U ;
		value.remove_prefix( 2U) ;
	}

	// 明示空flagsとprefixだけでは数値を確定できない。
	if( value.empty()) {
		reason = MaintenanceInfStructureReason::MISSING_SERVICE_FIELD ;
		return {MaintenanceInspectionState::FAILED, nativeErrorFromWin32( ERROR_INVALID_DATA)} ;
	}

	std::uint32_t parsed{} ;	// 全文字成功まで出力へ反映しない。
	// 全桁を一度ずつ解析し、不正文字または追加前overflowで終了する。
	for( const wchar_t character : value) {
		std::uint32_t digit = radix ;	// 未対応文字は基数以上として拒否する。
		// ASCII十進数字だけを数値へ変換する。
		if( character >= L'0' && character <= L'9') {
			digit = static_cast<std::uint32_t>( character - L'0') ;
		}
		// 十六進の大文字A～Fを同じ数値へ変換する。
		else if( radix == 16U && character >= L'A' && character <= L'F') {
			digit = static_cast<std::uint32_t>( character - L'A') + 10U ;
		}
		// 十六進の小文字a～fも別の桁表現として扱う。
		else if( radix == 16U && character >= L'a' && character <= L'f') {
			digit = static_cast<std::uint32_t>( character - L'a') + 10U ;
		}

		// 負号・空白・非数値を全field検査で拒否し、部分数値を返さない。
		if( digit >= radix) {
			reason = MaintenanceInfStructureReason::INVALID_FLAGS_NUMBER ;
			return {MaintenanceInspectionState::FAILED, nativeErrorFromWin32( ERROR_INVALID_DATA)} ;
		}

		// 乗算・加算の前にuint32上限を判定し、wraparoundを成功としない。
		if( parsed > (std::numeric_limits<std::uint32_t>::max() - digit) / radix) {
			reason = MaintenanceInfStructureReason::FLAGS_OVERFLOW ;
			return {MaintenanceInspectionState::FAILED,
					nativeErrorFromWin32( ERROR_ARITHMETIC_OVERFLOW)} ;
		}

		parsed = parsed * radix + digit ;
	}

	flags = parsed ;
	return {MaintenanceInspectionState::PASSED, 0} ;
}

/** @brief 元のqueryと実readを補助APIより前に捕捉する私有記録。 */
struct MaintenanceFieldRead {
	/// 元必要長queryのBOOL。
	BOOL  query{} ;
	/// query直後の元error。
	DWORD queryError{} ;
	/// queryの終端込み必要長。
	DWORD required{} ;
	/// 元実readのBOOL。
	BOOL  read{} ;
	/// read直後の元error。
	DWORD readError{} ;
	/// 実readの終端込み必要長。
	DWORD readRequired{} ;
	/// 有限buffer内で終端を確認した場合true。
	bool  terminated{} ;
} ;

/**
 * @brief 空を許可する既存readerへ必要長の上限確認を付ける。
 * @param[in,out] line 同期借用するSetupAPI行。
 * @param[in] field 値field番号。0はkey。
 * @param[out] value 成功時の全展開値。失敗時は空。
 * @param[out] proof 非nullなら同じ二呼出しの元結果を捕捉する。通常構造読取はnull。
 * @return 成功0、終端込み4,096文字超過はERROR_BUFFER_OVERFLOW、読取失敗は元HRESULT。
 */
[[nodiscard]] NativeError readMaintenanceField( INFCONTEXT &line, DWORD field, std::wstring &value,
											   MaintenanceFieldRead *proof = nullptr)
{
	value.clear() ;
	// Windowsが返す展開後の必要文字数。元Strings原長ではない。
	DWORD		required{} ;
	const BOOL	query = SetupGetStringFieldW( &line, field, nullptr, 0U, &required) ;	// 元query。
	const DWORD queryError = GetLastError() ;											// 追加観測より前に元errorを保持する。
	// 明示outだけへ元観測を渡し、通常readerの戻り値を変えない。
	if( proof != nullptr) {
		*proof = {query, queryError, required} ;
	}

	// 必要長の読取失敗を空値へ変換しない。
	if( query == FALSE && queryError != ERROR_INSUFFICIENT_BUFFER) {
		return nativeErrorFromWin32( queryError) ;
	}

	// 境界超過を個別flags診断へ分離できるよう固有HRESULTを返す。
	if( required > MAXIMUM_INF_FIELD_CHARACTERS) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	// null opt-outでは従来の実readと空field契約をそのまま使う。
	if( proof == nullptr) {
		return readInstallInventoryField( line, field, value) ;
	}

	std::array<wchar_t, MAXIMUM_INF_FIELD_CHARACTERS> buffer{} ;	// 元と同じ有限buffer。
	proof->read		 = SetupGetStringFieldW( &line, field, buffer.data(),
											static_cast<DWORD>( buffer.size()), &proof->readRequired) ;
	proof->readError = GetLastError() ;
	// 元read失敗を私有保留へ弱めず、そのHRESULTで全体拒否する。
	if( proof->read == FALSE) {
		return nativeErrorFromWin32( proof->readError) ;
	}

	const auto end	  = std::ranges::find( buffer, L'\0') ;	// 有限内の最初の終端。
	proof->terminated = end != buffer.end() ;
	// 終端のない成功bufferを所有文字列へ変換しない。
	if( !proof->terminated) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	value.assign( buffer.begin(), end) ;
	return 0 ;
}

// 私有原byte・全recordの共同byte上限。
constexpr std::size_t MAXIMUM_MAINTENANCE_PROOF_BYTES = 1024U * 1024U ;
// 一時全field値・有限caller／binding indexの保守byte予約。raw offsetと共同1MiBへ含める。
constexpr std::size_t MAINTENANCE_PROOF_OVERHEAD_BYTES = 256U * 1024U ;
// 私有行indexの未結合値。公開identityへ渡さない。
constexpr std::size_t NO_MAINTENANCE_RAW_ROW = MAXIMUM_INSTALL_INVENTORY_ITEMS ;

/** @brief 一回の原snapshot上のcode unit範囲を借用する。 */
struct MaintenanceRawSpan {
	/// BOMを除くcode unit開始位置。
	std::size_t begin{} ;
	/// 終端を含まないcode unit数。
	std::size_t size{} ;
} ;

/** @brief case非依存merge後の節envelope。 */
struct MaintenanceRawSection {
	/// 原byte上の元節名。別decoded本文を保持しない。
	MaintenanceRawSpan name ;
	/// merge後の非空entry数。
	std::size_t		   count{} ;
} ;

/** @brief 同section・ordinalの原keyと全fieldの一意結合。 */
struct MaintenanceRawRow {
	/// merge後の節index。
	std::size_t		   section{} ;
	/// 0始まりのmerge後entry ordinal。
	std::size_t		   ordinal{} ;
	/// keyなし行は空範囲。
	MaintenanceRawSpan key ;
	/// field offset vectorの開始位置。
	std::size_t		   firstField{} ;
	/// keyを除く厳密field数。
	std::size_t		   fields{} ;
	/// 全API値が原値と一致した場合true。
	bool			   verified{} ;
	/// built-in13の全target比較を最後へ保留するfield。0は保留なし。
	std::size_t		   deferredField{} ;
	/// 全取得済み値fieldのbitmap。64fieldを切り捨てない。
	std::uint64_t	   observed{} ;
	/// 元keyの有無もAPIへ比較した場合true。
	bool			   keyObserved{} ;
} ;

/** @brief 元用途と原data行をindexだけで結ぶ撤回可能な位置stage。 */
struct MaintenanceRegistryDataProof {
	/// 同元byteの行index。
	std::size_t row{} ;
	/// 元install.fileUsesのdata一件。
	std::size_t use{} ;
	/// 元queueのREGISTRY index。
	std::size_t queue{} ;
	/// 最終append先。親markerの分離後に補正する。
	std::size_t file{NO_MAINTENANCE_RAW_ROW} ;
	/// 一意EventLog callerを全queue終了後に認定した場合true。
	bool		caller{} ;
	/// 全target／sourceが成立した元source用途index。最後まで公開位置へ反映しない。
	std::size_t sourceFile{NO_MAINTENANCE_RAW_ROW} ;
} ;

/**
 * @brief 参照reader一同期scopeだけで元byte・私有component・全値証明を所有する。
 * @note HINFより先に構築して後に破棄する。共有Windows／Tempへlockを掛けない。
 * 私有失敗は予約を撤回し元Uを保持する。元byte不一致だけは既存全体拒否へ返す。
 */
class MaintenanceInfByteProof final {
public:
	/** @brief 空の私有証明を構築する。 */
	MaintenanceInfByteProof() = default ;
	/** @brief HINF解放後に元fileとprivate componentを逆順に閉じる。 */
	~MaintenanceInfByteProof() noexcept
	{
		// 元fileのshare境界をHINF終了まで維持する。
		if( file_ != INVALID_HANDLE_VALUE) {
			CloseHandle( file_) ;
		}

		// 私有rootまでの取得済みdirectoryだけを逆順に解放する。
		while( handleCount_ != 0U) {
			CloseHandle( handles_[--handleCount_]) ;
		}
	}
	/** @brief 同期leaseの複製をコンパイル時に禁止します。
	 * @param[in] other 呼出し不能な元proofです。借用・変更・resource移動を行いません。
	 * @note 削除宣言だけで関数本体はありません。
	 */
	MaintenanceInfByteProof( const MaintenanceInfByteProof &other) = delete ;
	/** @brief 同期leaseの代入をコンパイル時に禁止します。
	 * @param[in] other 呼出し不能な元proofです。借用・変更・resource移動を行いません。
	 * @return 宣言された自己参照型です。削除宣言なので戻り値を生成しません。
	 * @note 削除宣言だけで関数本体はありません。
	 */
	MaintenanceInfByteProof &operator=( const MaintenanceInfByteProof &other) = delete ;
	/** @brief 現在全値証明へ使用できる場合trueを返す。
	 * @return 私有proofが失効していなければtrue。
	 */
	[[nodiscard]] bool		 active() const noexcept
	{
		return active_ ;
	}
	/** @brief 私有予約を全て撤回し、元処理の容量へ返す。 */
	void disable() noexcept
	{
		active_ = false ;
		std::string{}.swap( bytes_) ;
		std::vector<MaintenanceRawSection>{}.swap( sections_) ;
		std::vector<MaintenanceRawRow>{}.swap( rows_) ;
		std::vector<MaintenanceRawSpan>{}.swap( fields_) ;
		std::vector<MaintenanceRegistryDataProof>{}.swap( data) ;
		std::vector<std::pair<std::size_t, std::size_t>>{}.swap( sourceRows) ;
		std::vector<std::pair<std::size_t, std::size_t>>{}.swap( controlUses) ;
	}
	/**
	 * @brief 既存保護workspace内の元fileを一回だけ順序snapshotへ固定する。
	 * @param[in] path workspace.pathで検証済みの元absolute path。
	 * @param[in] relativePath 同じ元相対位置。
	 * @param[in] entry 元固定entryのsizeとhash。
	 * @return 私有成功／保留0。取得済みbyteの固定size／hash不一致はTRUST_E_BAD_DIGEST。
	 */
	[[nodiscard]] NativeError open( const std::wstring &path, std::wstring_view relativePath,
								   const OfficialZipEntry &entry) noexcept
	{
		try {
			std::array<wchar_t, MAX_PATH> windows{} ;	// trusted Windows directoryの観測だけ。
			const UINT					  length = GetWindowsDirectoryW(
				   // 元OS anchor。
				   windows.data(), static_cast<UINT>( windows.size())) ;
			// 生成経路を確認できない入力や私有byte超過は従来readerへ渡す。
			if( length == 0U || length >= windows.size() || path.size() <= relativePath.size() ||
			   entry.uncompressedSize > MAXIMUM_MAINTENANCE_PROOF_BYTES -
											MAINTENANCE_PROOF_OVERHEAD_BYTES - sizeof( *this)) {
				return 0 ;
			}

			const std::wstring root =
				// 私有rootだけ。
				path.substr( 0U, path.size() - relativePath.size() - 1U) ;
			const std::wstring anchor =
				// 共有anchorはlockしない。
				std::wstring( windows.data()) + L"\\Temp\\" ;
			// 既存生成経路の直下でない私有rootを新たなtrust anchorへしない。
			if( root.size() <= anchor.size() ||
			   !stringsEqual( std::wstring_view( root).substr( 0U, anchor.size()), anchor) ||
			   root.find( L'\\', anchor.size()) != root.npos) {
				return 0 ;
			}

			std::wstring component = root ;	// private rootから元INF親までだけを保持する。
			std::size_t	 next{} ;			// 元相対pathの次component。
			DWORD		 volume{} ;			// 全private HANDLEの同volume拘束。
			// 最多64のordinary componentを一度ずつ開き、write／delete shareを許さない。
			for( ;;) {
				// 共同component上限ではprivate proofだけを保留する。
				if( handleCount_ == handles_.size()) {
					return 0 ;
				}

				const HANDLE handle = CreateFileW(
					component.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
					FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
					nullptr) ;	// 私有directory lease。
				// share競合や取得失敗をretryで成立させない。
				if( handle == INVALID_HANDLE_VALUE) {
					return 0 ;
				}

				handles_[handleCount_++] = handle ;
				BY_HANDLE_FILE_INFORMATION info{} ;	// 同HANDLEのordinary／volume／identity。
				// reparseや上位再結合を観測した場合は元Uを保持する。
				if( !ordinary( handle, component, true, info) ||
				   (handleCount_ > 1U && info.dwVolumeSerialNumber != volume)) {
					return 0 ;
				}

				volume				 = info.dwVolumeSerialNumber ;
				const auto separator = relativePath.find( L'\\', next) ;	// 元安全pathの次親要素。
				// 元INFの親まで固定した後だけfileを開く。
				if( separator == relativePath.npos) {
					break ;
				}

				component += L"\\" + std::wstring( relativePath.substr( next, separator - next)) ;
				next = separator + 1U ;
			}

			file_ = CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
								FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr) ;
			BY_HANDLE_FILE_INFORMATION before{} ;	// 元fileの同HANDLE identityとsize。
			// private取得失敗は元hash読取の失敗結果へ混ぜない。
			if( file_ == INVALID_HANDLE_VALUE || !ordinary( file_, path, false, before) ||
			   before.dwVolumeSerialNumber != volume) {
				return 0 ;
			}

			const std::uint64_t size =
				(static_cast<std::uint64_t>( before.nFileSizeHigh) << 32U) |
				before.nFileSizeLow ;	// 元sizeと一致しなければbyte整合全体失敗。
			// 元固定sizeの不一致をprivate未知へ弱めない。
			if( size != entry.uncompressedSize) {
				return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
			}

			bytes_.resize( static_cast<std::size_t>( size)) ;
			std::size_t offset{} ;	// 一回の順序snapshotで完了したbyte数。
			// 同HANDLEからだけ有限chunkを順序どおり読み、短いreadを完全値へ補完しない。
			while( offset < bytes_.size()) {
				const DWORD requested = static_cast<DWORD>(
					(std::min)( bytes_.size() - offset, std::size_t{65536U})) ;	// chunk byte数。
				DWORD read{} ;													// このchunkだけの実byte数。
				// private I/O失敗は元readerへ戻す。
				if( ReadFile( file_, bytes_.data() + offset, requested, &read, nullptr) == FALSE ||
				   read == 0U) {
					disable() ;
					return 0 ;
				}

				offset += read ;
			}

			char					   extra{} ;	// 同HANDLEの確認済みEOF。
			DWORD					   read{} ;		// EOF照会の実byte数。
			BY_HANDLE_FILE_INFORMATION after{} ;	// snapshot終端の同identity。
			// 未確認EOFとidentity照会失敗はprivate保留へ戻す。
			if( ReadFile( file_, &extra, 1U, &read, nullptr) == FALSE ||
			   GetFileInformationByHandle( file_, &after) == FALSE) {
				disable() ;
				return 0 ;
			}

			// EOF／size／file identityの実不一致は既存byte整合失敗を保持する。
			if( read != 0U || before.dwVolumeSerialNumber != after.dwVolumeSerialNumber ||
			   before.nFileIndexHigh != after.nFileIndexHigh ||
			   before.nFileIndexLow != after.nFileIndexLow ||
			   before.nFileSizeHigh != after.nFileSizeHigh ||
			   before.nFileSizeLow != after.nFileSizeLow) {
				return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
			}

			std::wstring hash ;	// 原byteに既存hash入口だけを使う。
			// private hash API失敗を元hash結果へ上書きしない。
			if( computeBytesSha256( bytes_, hash) != 0) {
				disable() ;
				return 0 ;
			}

			// 元entryの明示hashとの全一致を要求する。
			if( !entry.sha256.empty() && !stringsEqual( hash, entry.sha256)) {
				return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
			}

			hash_	= std::move( hash) ;
			active_ = scan() ;
			// 未対応encoding／構文／quotaを正常parserの新拒否へ変えない。
			if( !active_) {
				disable() ;
			}

			return 0 ;
		} catch( const std::bad_alloc &) {
			// 私有allocationだけを撤回し、元allocationのHRESULTは元callerが扱う。
			disable() ;
			return 0 ;
		}
	}
	/** @brief 元通常hashへ一回のsnapshotを完全照合する。
	 * @param[in] hash 同じreaderが通常入口で取得した元hash。
	 * @return snapshotを取得していない保留は0。不一致はTRUST_E_BAD_DIGEST。
	 */
	[[nodiscard]] NativeError matchHash( std::wstring_view hash) const noexcept
	{
		return hash_.empty() || stringsEqual( hash_, hash)
				   ? 0
				   : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	}
	/** @brief 元処理に必要な共同項目を優先し、私有予約を撤回する。
	 * @param[in] coreItems 元保持量。private recordを含まない。
	 */
	void capacity( std::size_t coreItems) noexcept
	{
		// coreの必要量をprivate予約で全体失敗へ変えない。
		if( active_ && (coreItems > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
					   items() > MAXIMUM_INSTALL_INVENTORY_ITEMS - coreItems ||
					   storage() > MAXIMUM_MAINTENANCE_PROOF_BYTES)) {
			disable() ;
		}
	}
	/** @brief 同raw節countと元API countからmerged ordinalを一意に結ぶ。
	 * @param[in] section 元APIで取得した節名。
	 * @param[in] ordinal 同節の元0始まりindex。
	 * @param[in] count 元APIの確定全行数。
	 * @param[in] fields 元APIの厳密field数。
	 * @return 原row index。保留では未結合値。
	 */
	[[nodiscard]] std::size_t row( std::wstring_view section, LONG ordinal, LONG count,
								  DWORD fields) noexcept
	{
		try {
			// 失効証明へ新しい原行を補完しない。
			if( !active_) {
				return NO_MAINTENANCE_RAW_ROW ;
			}

			std::size_t index{} ;	// 原節indexの探索位置。
			// 全有限section名をcase非依存で一度の選択へ結ぶ。
			while( index < sections_.size() && !stringsEqual( text( sections_[index].name), section)) {
				++index ;
			}

			// 行数差と原節不在を先頭row検索で救済しない。
			if( index == sections_.size() || count < 0 ||
			   sections_[index].count != static_cast<std::size_t>( count)) {
				disable() ;
				return NO_MAINTENANCE_RAW_ROW ;
			}

			const auto found =
				std::ranges::lower_bound( rows_, std::pair{index, static_cast<std::size_t>( ordinal)},
										 {}, []( const auto &item) {
											 return std::pair{item.section, item.ordinal} ;
										 }) ; // 同rowだけを一意選択。
			// 全field数差をstrict5行へ縮めない。
			if( found == rows_.end() || found->section != index ||
			   found->ordinal != static_cast<std::size_t>( ordinal) || found->fields != fields) {
				disable() ;
				return NO_MAINTENANCE_RAW_ROW ;
			}

			// 同raw行の再readを一回の全値証拠へ合成しない。
			if( found->keyObserved || found->observed != 0U) {
				disable() ;
				return NO_MAINTENANCE_RAW_ROW ;
			}

			found->verified = true ;
			return static_cast<std::size_t>( found - rows_.begin()) ;
		} catch( const std::bad_alloc &) {
			disable() ;
			return NO_MAINTENANCE_RAW_ROW ;
		}
	}
	/** @brief 同じ元query／readから一fieldの全値を比較する。
	 * @param[in] index 同raw行index。
	 * @param[in] field 0はkey、1以降は元field。
	 * @param[in] value 元coreが一度だけ取得した全値。複写して保持しない。
	 * @param[in] read 同じ二API呼出しの直後の結果。
	 */
	void field( std::size_t index, std::size_t field, std::wstring_view value,
			   const MaintenanceFieldRead &read) noexcept
	{
		try {
			// 既に撤回したprivate行を参照しない。
			if( !active_ || index >= rows_.size()) {
				return ;
			}

			auto		&item = rows_[index] ;	// 同元rowの私有状態。
			std::wstring expanded ;				// 一fieldだけの有限な独立展開。
			const auto	 raw =
				// 元全範囲。
				field == 0U ? item.key : fields_[item.firstField + field - 1U] ;
			const bool complete =
				(read.query != FALSE || read.queryError == ERROR_INSUFFICIENT_BUFFER) &&
				read.read != FALSE && read.terminated && read.required == value.size() + 1U &&
				// 部分bufferを成功証拠へ使わない。
				read.readRequired == read.required ;
			// 原literal／一段Stringsと元全取得値を独立照合する。
			if( !complete || !expand( raw, expanded)) {
				item.verified = false ;
				return ;
			}

			// 唯一の先頭DIRID13だけはnamed full targetが揃うまで保留する。
			if( expanded.starts_with( L"%13%\\")) {
				const auto key = text( item.key) ;	// 原keyからfieldの狭い役割を確認する。
				const bool targetField =
					(item.key.size == 0U && item.fields == 5U && field == 5U) ||
					(stringsEqual( key, L"ServiceBinary") && item.fields == 1U &&
					 // 唯一の保留用途。
					 field == 1U) ;
				// 同rowで二つのDIRID用途を部分比較へ変えない。
				if( !targetField || item.deferredField != 0U) {
					item.verified = false ;
				}

				item.deferredField = field ;
			}
			// token-freeな全値の差はcaseやsuffix救済を行わない。
			else if( expanded != value || expanded.size() + 1U != read.required) {
				// 全code unitの差はcaseやsuffix救済を行わない。
				item.verified = false ;
			}

			// keyと全64fieldを別に記録し、未読fieldを成功へ通さない。
			if( field == 0U) {
				item.keyObserved = true ;
			} else {
				item.observed |= std::uint64_t{1U} << (field - 1U) ;
			}
		} catch( const std::bad_alloc &) {
			disable() ;
		}
	}
	/** @brief core未取得fieldだけを同context内で一回補助取得する。
	 * @param[in,out] line 元の同rowcontext。保持しない。
	 * @param[in] index 原row index。
	 * @param[in] first 最初の未取得field。
	 * @param[in] last 最後の未取得field。
	 */
	void extra( INFCONTEXT &line, std::size_t index, DWORD first, DWORD last) noexcept
	{
		const DWORD originalError = GetLastError() ;	// 元API結果へ補助errorを混入させない。
		try {
			// 未取得fieldだけを一回ずつ補い、query／readを全INFで8192以内へ拘束する。
			for( DWORD number = first; active_ && index < rows_.size() && number <= last; ++number) {
				// 私有API予算の枯渇は元field読取を失敗させない。
				if( extraCalls_ > 8192U - 2U) {
					disable() ;
					break ;
				}

				extraCalls_ += 2U ;
				// strict原keyなしの同rowだけは失敗bufferを読まず、不存在queryの数値を捕捉する。
				if( number == 0U && rows_[index].key.size == 0U) {
					DWORD		required{} ;	// keyなしqueryの終端込み必要長。
					const BOOL	query  = SetupGetStringFieldW( &line, 0U, nullptr, 0U,
															  &required) ;	// 同context一回だけ。
					const DWORD native = GetLastError() ;					// 元の補助結果を直後に固定する。
					// 87単体では採用せず、最終verifiedが同row全field成功も要求する。
					if( query == FALSE && native == ERROR_INVALID_PARAMETER && required == 0U) {
						rows_[index].keyObserved = true ;
						continue ;
					}

					// 別結果をkey不存在へ推測変換しない。
					disable() ;
					break ;
				}

				std::wstring		 value ;	// 未取得fieldだけの短命な補助値。
				MaintenanceFieldRead read{} ;	// 同query／readの完全性。
				const NativeError	 error =
					// 私有読取結果。
					readMaintenanceField( line, number, value, &read) ;
				// 補助失敗で元成功をwhole failureへ変更しない。
				if( error != 0) {
					disable() ;
					break ;
				}

				field( index, number, value, read) ;
			}
		} catch( const std::bad_alloc &) {
			disable() ;
		}

		SetLastError( originalError) ;
	}
	/** @brief 元raw行を同期期間だけ参照する。
	 * @param[in] index 私有原row index。
	 * @return 同raw行。callerはactiveとrangeを先に確認する。
	 */
	[[nodiscard]] const MaintenanceRawRow &get( std::size_t index) const noexcept
	{
		return rows_[index] ;
	}
	/** @brief keyと厳密全fieldの取得・比較完了を確認する。
	 * @param[in] index 同raw row index。
	 * @return 全field bitmapとkeyが揃った一行だけtrue。
	 */
	[[nodiscard]] bool verified( std::size_t index) const noexcept
	{
		// 失効／未結合のprivate indexを参照しない。
		if( !active_ || index >= rows_.size()) {
			return false ;
		}

		const auto &row		 = rows_[index] ;	// 同原rowの比較状態。
		const auto	expected = row.fields == 64U ? (std::numeric_limits<std::uint64_t>::max)()
												 : (std::uint64_t{1U} << row.fields) -
													   1U ;	// 全64bitの場合のshift overflowを避ける。
		return row.verified && row.keyObserved && row.observed == expected ;
	}
	/** @brief 元source観測と原rowを私有indexだけでstageする。
	 * @param[in] row 同元raw row。
	 * @param[in] file 元observed.filesへのindex。
	 */
	void source( std::size_t row, std::size_t file) noexcept
	{
		try {
			// 全値の不足するsourceを後のbindingへ再readしない。
			if( !verified( row)) {
				return ;
			}

			sourceRows.emplace_back( row, file) ;
			capacity( 0U) ;
		} catch( const std::bad_alloc &) {
			disable() ;
		}
	}
	/** @brief 一件の元registry data位置だけを最後までstageする。
	 * @param[in] row 同raw row。
	 * @param[in] use 元use ordinal。
	 * @param[in] queue 元registry queue index。
	 */
	void registry( std::size_t row, std::size_t use, std::size_t queue) noexcept
	{
		try {
			// 未読key／auxや全値不一致をcaller成功だけで補完しない。
			if( !verified( row)) {
				return ;
			}

			data.push_back( {row, use, queue}) ;
			capacity( 0U) ;
		} catch( const std::bad_alloc &) {
			disable() ;
		}
	}
	/** @brief 遅延DIRID全値を元制御用途の一件へ結ぶ。
	 * @param[in] row 同raw row。
	 * @param[in] use 同じ行の元fileUse index。
	 */
	void control( std::size_t row, std::size_t use) noexcept
	{
		try {
			// DIRID13の未結合値を別binary名から補完しない。
			if( !verified( row) || rows_[row].deferredField == 0U) {
				return ;
			}

			controlUses.emplace_back( row, use) ;
			capacity( 0U) ;
		} catch( const std::bad_alloc &) {
			disable() ;
		}
	}
	/** @brief 原fieldの一段Strings全展開を取得する。
	 * @param[in] index 原row index。
	 * @param[in] field 0はkey。
	 * @param[out] value 成功時の有限全値。
	 * @return 失効・展開不明ならfalse。
	 */
	[[nodiscard]] bool value( std::size_t index, std::size_t field, std::wstring &value) noexcept
	{
		try {
			// 撤回済みoffsetを借用しない。
			if( !active_ || index >= rows_.size()) {
				return false ;
			}

			const auto &item = rows_[index] ;	// 同元row。
			return expand( field == 0U ? item.key : fields_[item.firstField + field - 1U], value) ;
		} catch( const std::bad_alloc &) {
			disable() ;
			return false ;
		}
	}
	/// 一件の元data用途だけを結ぶ私有stage。失効時に全解放する。
	std::vector<MaintenanceRegistryDataProof>		 data ;
	/// 元source行indexと元観測用途indexだけを保持する。再API取得に使わない。
	std::vector<std::pair<std::size_t, std::size_t>> sourceRows ;
	/// 同原制御行の遅延DIRID fieldと元binary用途の一意index。
	std::vector<std::pair<std::size_t, std::size_t>> controlUses ;

private:
	/** @brief 同HANDLEの通常種別・最終pathをtrusted上位と照合する。
	 * @param[in] handle private所有HANDLE。
	 * @param[in] path 既存workspaceの元path。
	 * @param[in] directory trueはdirectory。
	 * @param[out] info 同HANDLEの元identity。
	 * @return reparseなし・通常種別・全path一致ならtrue。
	 */
	[[nodiscard]] static bool ordinary( HANDLE handle, const std::wstring &path, bool directory,
									   BY_HANDLE_FILE_INFORMATION &info) noexcept
	{
		std::array<wchar_t, MAX_PATH + 8U> final{} ;	// private最終path観測の有限buffer。
		const DWORD						   size =
			GetFinalPathNameByHandleW( handle, final.data(), static_cast<DWORD>( final.size()),
									  FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;	// 最終解決先。
		return GetFileInformationByHandle( handle, &info) != FALSE &&
			   (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0U &&
			   ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) == directory &&
			   size > 4U && size < final.size() &&
			   std::wstring_view( final.data(), 4U) == L"\\\\?\\" &&
			   stringsEqual( std::wstring_view( final.data() + 4U, size - 4U), path) ;
	}
	/** @brief 原snapshotの一code unitを借用する。
	 * @param[in] index 検証済みcode unit位置。
	 * @return ASCIIまたはUTF-16LE code unit。
	 */
	[[nodiscard]] wchar_t character( std::size_t index) const noexcept
	{
		const auto offset = start_ + index * width_ ;						// 元byte位置。
		const auto low	  = static_cast<unsigned char>( bytes_[offset]) ;	// 低位byte。
		return static_cast<wchar_t>(
			width_ == 1U
				? low
				: low | (static_cast<unsigned int>( static_cast<unsigned char>( bytes_[offset + 1U]))
						 << 8U)) ;
	}
	/** @brief 一つの有限raw範囲だけを比較用文字列へ写す。
	 * @param[in] span 原byte上の範囲。
	 * @return 全code unitの比較用値。保持しない。
	 */
	[[nodiscard]] std::wstring text( MaintenanceRawSpan span) const
	{
		std::wstring value ;	// 一範囲だけの比較値。
		value.reserve( span.size) ;
		// 原code unitを順序どおり一回だけ写す。
		for( std::size_t index = 0U; index < span.size; ++index) {
			value.push_back( character( span.begin + index)) ;
		}

		return value ;
	}
	/** @brief 一fieldのouter quoteとunquoted周辺spaceだけを除く。
	 * @param[in,out] span 元field範囲。成功時だけ有効なliteral範囲。
	 * @return quote連結／continuation／不均衡percentなしならtrue。
	 */
	[[nodiscard]] bool literal( MaintenanceRawSpan &span) const noexcept
	{
		// unquoted両端space／tabだけを取り除く。
		while( span.size != 0U &&
			  (character( span.begin) == L' ' || character( span.begin) == L'\t')) {
			++span.begin ;
			--span.size ;
		}

		// 末尾のsyntax外space／tabだけを取り除く。
		while( span.size != 0U && (character( span.begin + span.size - 1U) == L' ' ||
								  character( span.begin + span.size - 1U) == L'\t')) {
			--span.size ;
		}

		// 一組のouter quoteだけを受理し、本文内のquoteを後で拒否する。
		if( span.size >= 2U && character( span.begin) == L'"' &&
		   character( span.begin + span.size - 1U) == L'"') {
			++span.begin ;
			span.size -= 2U ;
		}

		bool percent{} ;	// 一段tokenの対応するpercent。
		// 不明syntaxを飛ばしてordinalを作らず、同一物理行の全literalを検査する。
		for( std::size_t index = 0U; index < span.size; ++index) {
			const auto value = character( span.begin + index) ;	// 原code unit。
			// quote連結／二重quoteは最小形式外として保留する。
			if( value == L'"') {
				return false ;
			}

			// token delimiterの全対応を確認する。
			if( value == L'%') {
				percent = !percent ;
			}
		}

		return !percent && span.size < MAXIMUM_INF_FIELD_CHARACTERS ;
	}
	/** @brief private byteとrecordの総保持byte数を返す。
	 * @return capacityで確保された全private byte。元core値は複写しない。
	 */
	[[nodiscard]] std::size_t storage() const noexcept
	{
		return MAINTENANCE_PROOF_OVERHEAD_BYTES + sizeof( *this) + bytes_.capacity() +
			   hash_.capacity() * sizeof( wchar_t) +
			   sections_.capacity() * sizeof( MaintenanceRawSection) +
			   rows_.capacity() * sizeof( MaintenanceRawRow) +
			   fields_.capacity() * sizeof( MaintenanceRawSpan) +
			   data.capacity() * sizeof( MaintenanceRegistryDataProof) +
			   (sourceRows.capacity() + controlUses.capacity()) *
				   sizeof( std::pair<std::size_t, std::size_t>) ;
	}
	/** @brief 全private record／binding indexの共同項目数を返す。
	 * @return 原offsetを含む全private record数。
	 */
	[[nodiscard]] std::size_t items() const noexcept
	{
		return sections_.size() + rows_.size() + fields_.size() + data.size() + sourceRows.size() +
			   controlUses.size() ;
	}
	/** @brief 原encodingと有限物理行・節・全field envelopeを一回だけ走査する。
	 * @return 最小形式内かつ全共同上限内ならtrue。
	 */
	[[nodiscard]] bool scan()
	{
		width_ = bytes_.size() >= 2U && static_cast<unsigned char>( bytes_[0]) == 0xffU &&
						 static_cast<unsigned char>( bytes_[1]) == 0xfeU
					 ? 2U
					 : 1U ;
		start_ = width_ == 2U ? 2U : 0U ;
		// UTF-16LEの半code unitを推測decodeしない。
		if( (bytes_.size() - start_) % width_ != 0U) {
			return false ;
		}

		const auto length = (bytes_.size() - start_) / width_ ;	// 全raw code unit数。
		bool	   surrogate{} ;								// 直前high surrogateへの対応要求。
		// 原全byteのencoding／controlを検査し、NULや不正surrogateを飛ばさない。
		for( std::size_t index = 0U; index < length; ++index) {
			const auto value = character( index) ;	// 同snapshotの一code unit。
			// 禁止controlと非ASCII ANSI／UTF-8はprivate保留へ戻す。
			if( (value < 0x20 && value != L'\t' && value != L'\r' && value != L'\n') ||
			   value == 0x7f || (width_ == 1U && value > 0x7e)) {
				return false ;
			}

			// high surrogateの直後にlowを要求する。
			if( surrogate && (value < 0xdc00 || value > 0xdfff)) {
				return false ;
			}

			// 単独low surrogateを正常なcode unit列へしない。
			if( !surrogate && value >= 0xdc00 && value <= 0xdfff) {
				return false ;
			}

			surrogate = value >= 0xd800 && value <= 0xdbff ;
		}

		// 未完high surrogateの末尾を切り捨てない。
		if( surrogate) {
			return false ;
		}

		std::size_t next{} ;							// 原physical line開始位置。
		std::size_t lines{} ;							// 全seed共同raw counter。
		std::size_t envelopes{} ;						// 同名節も元envelopeとして数える。
		std::size_t section = NO_MAINTENANCE_RAW_ROW ;	// 現在のmerge先。
		// 原lineを一回ずつ走査し、未知syntaxではINF全private proofを閉じる。
		while( next < length) {
			// 有限raw physical line上限をseedでresetしない。
			if( ++lines > 16384U) {
				return false ;
			}

			const auto beginning = next ;	// 元lineの先頭。
			// CR／LFまでの単一物理行だけを扱う。
			while( next < length && character( next) != L'\r' && character( next) != L'\n') {
				++next ;
			}

			auto ending = next ;	// comment除去前の行末。
			// CRLFは一physical lineとして数える。
			if( next < length && character( next++) == L'\r' && next < length &&
			   character( next) == L'\n') {
				++next ;
			}

			bool quote{} ;	// quote内semicolonをcommentにしない。
			// comment境界を原line内だけで確定する。
			for( auto index = beginning; index < ending; ++index) {
				// quote境界を同physical lineに拘束する。
				if( character( index) == L'"') {
					quote = !quote ;
				}

				// 引用外semicolonだけをcommentへ分離する。
				if( !quote && character( index) == L';') {
					ending = index ;
					break ;
				}
			}

			MaintenanceRawSpan span{beginning, ending - beginning} ;	// 元line内のsyntax範囲。
			// lineの外側spaceだけを除去する。
			while( span.size != 0U &&
				  (character( span.begin) == L' ' || character( span.begin) == L'\t')) {
				++span.begin ;
				--span.size ;
			}

			// line末尾のsyntax外spaceを除去する。
			while( span.size != 0U && (character( span.begin + span.size - 1U) == L' ' ||
									  character( span.begin + span.size - 1U) == L'\t')) {
				--span.size ;
			}

			// 空line／commentだけを除き、非空entry ordinalを保持する。
			if( span.size == 0U) {
				continue ;
			}

			// continuation／不均衡quoteをordinalから消して成功させない。
			if( quote || character( span.begin + span.size - 1U) == L'\\') {
				return false ;
			}

			// 元section envelopeはtoken-freeな一組bracketだけに限る。
			if( character( span.begin) == L'[') {
				// 過大／未閉headerをprivate保留する。
				if( ++envelopes > 1024U || span.size < 3U ||
				   character( span.begin + span.size - 1U) != L']') {
					return false ;
				}

				++span.begin ;
				span.size -= 2U ;
				const auto name = text( span) ;	// section名だけの比較値。
				// header内tokenや構文曖昧を許さない。
				if( !validInstallInventorySectionName( name) ||
				   name.find_first_of( L"%\"=,") != name.npos) {
					return false ;
				}

				// 空の不正locale envelopeも候補から飛ばさず、INF全private proofを保留する。
				if( isStrings( name) && !validStringsName( name)) {
					return false ;
				}

				section = 0U ;
				// case違い同名sectionを原byte順にmergeする。
				while( section < sections_.size() &&
					  !stringsEqual( text( sections_[section].name), name)) {
					++section ;
				}

				// Strings familyの重複headerはlocale推測で救済しない。
				if( section < sections_.size() && isStrings( name)) {
					return false ;
				}

				// 最初の原envelopeだけを名前offsetとして保持する。
				if( section == sections_.size()) {
					sections_.push_back( {span}) ;
				}

				continue ;
			}

			// section外entryを飛ばして次sectionのordinalを作らない。
			if( section == NO_MAINTENANCE_RAW_ROW || rows_.size() >= 4096U) {
				return false ;
			}

			MaintenanceRawRow row{
				section, sections_[section].count++, {}, fields_.size()} ;	// 一entryのoffsetだけ。
			std::size_t first = span.begin ;								// keyまたは最初のfield開始。
			const auto	end	  = span.begin + span.size ;					// 同physical line終端。
			quote			  = false ;
			bool hasKey{} ;	// 最初の引用外等号だけがkey境界。
			// keyと全comma fieldをquoteの内外で区別する。
			for( auto index = span.begin; index <= end; ++index) {
				const auto value =
					// 末尾empty fieldも保持する。
					index == end ? L',' : character( index) ;
				// quote内commaを別fieldへsplitしない。
				if( value == L'"') {
					quote = !quote ;
				}

				// 最初の引用外等号はkey付き行として独立保持する。
				if( !quote && value == L'=' && first == span.begin && !hasKey && row.fields == 0U) {
					row.key = {first, index - first} ;
					// 不正key形式はkeyなしへ縮めない。
					if( !literal( row.key) || row.key.size == 0U) {
						return false ;
					}

					hasKey = true ;
					first  = index + 1U ;
				}
				// 引用外commaだけを全field境界にし、末尾emptyも保持する。
				else if( !quote && value == L',') {
					MaintenanceRawSpan field{first, index - first} ;	// emptyを含む全field。
					// field数とliteral全形式の上限を先に確認する。
					if( ++row.fields > 64U || !literal( field)) {
						return false ;
					}

					fields_.push_back( field) ;
					first = index + 1U ;
				}
			}

			rows_.push_back( row) ;
			// offsetもprivate recordとしてbyte／共同item上限に含める。
			if( storage() > MAXIMUM_MAINTENANCE_PROOF_BYTES || items() > 4096U) {
				return false ;
			}
		}

		std::ranges::sort( rows_, {},
						  []( const auto &row) { return std::pair{row.section, row.ordinal} ; }) ;
		// 全Strings候補のkey構造と13shadowを確認し、不正localeを除外しない。
		for( const auto &row : rows_) {
			const auto name = text( sections_[row.section].name) ;	// 原候補section名。
			// Strings以外の通常sectionへlocale規則を追加しない。
			if( !isStrings( name)) {
				continue ;
			}

			const auto key = text( row.key) ;	// 原Strings識別子。
			// 一valueでない定義とbuilt-in shadowはprivate保留する。
			if( !validStringsName( name) || !identifier( key) || key == L"13" || row.fields != 1U) {
				return false ;
			}
		}

		return storage() <= MAXIMUM_MAINTENANCE_PROOF_BYTES && items() <= 4096U ;
	}
	/** @brief ASCII token識別子の最小形式を検査する。
	 * @param[in] value 全token名。
	 * @return 一文字以上のASCII英数字／underscoreならtrue。
	 */
	[[nodiscard]] static bool identifier( std::wstring_view value) noexcept
	{
		return !value.empty() && std::ranges::all_of( value, []( wchar_t character) {
			return (character >= L'a' && character <= L'z') ||
				   (character >= L'A' && character <= L'Z') ||
				   (character >= L'0' && character <= L'9') || character == L'_' ;
		}) ;
	}
	/** @brief defaultとdecorated Strings familyを区別する。
	 * @param[in] name 元section名。
	 * @return Strings familyならtrue。
	 */
	[[nodiscard]] static bool isStrings( std::wstring_view name) noexcept
	{
		return stringsEqual( name, L"Strings") ||
			   (name.size() >= 8U && stringsEqual( name.substr( 0U, 8U), L"Strings.")) ;
	}
	/** @brief defaultまたは四桁hex LanguageIDだけを採用する。
	 * @param[in] name 原Strings section名。
	 * @return 最小locale形式ならtrue。
	 */
	[[nodiscard]] static bool validStringsName( std::wstring_view name) noexcept
	{
		return stringsEqual( name, L"Strings") ||
			   (name.size() == 12U && std::ranges::all_of( name.substr( 8U), []( wchar_t character) {
					return (character >= L'0' && character <= L'9') ||
						   (character >= L'a' && character <= L'f') ||
						   (character >= L'A' && character <= L'F') ;
				})) ;
	}
	/** @brief 全default／decorated定義が一意同値の一段tokenだけを展開する。
	 * @param[in] span 原field全範囲。
	 * @param[out] output 独立展開した全code unit。終端込み4096以内。
	 * @return 全locale・全literalを確定できればtrue。
	 */
	[[nodiscard]] bool expand( MaintenanceRawSpan span, std::wstring &output) const
	{
		const auto raw = text( span) ;	// 一fieldだけの原全値。
		output.clear() ;
		std::size_t next{} ;	// 原全literalを順序どおり消費する。
		bool		dirid{} ;	// 先頭13を一度だけ許す。
		// tokenとliteralを一段だけ処理し、再帰や環境展開を行わない。
		while( next < raw.size()) {
			// token外literalは一文字ずつ全体へ残す。
			if( raw[next] != L'%') {
				output.push_back( raw[next++]) ;
			} else {
				const auto end = raw.find( L'%', next + 1U) ;	// 同tokenの閉delimiter。
				// 不均衡percentをescapeと推測しない。
				if( end == raw.npos) {
					return false ;
				}

				const auto key =
					// token全名。
					std::wstring_view( raw).substr( next + 1U, end - next - 1U) ;
				// 唯一のbuilt-inはdata先頭の一回だけ保持する。
				if( key == L"13") {
					// 中間・反復DIRID13を部分pathへ補正しない。
					if( next != 0U || dirid) {
						return false ;
					}

					dirid = true ;
					output += L"%13%" ;
				} else {
					// 未対応token形式をStrings名へ補完しない。
					if( !identifier( key)) {
						return false ;
					}

					std::wstring literal ;			// 最初の全定義だけを比較中に所有する。
					bool		 haveDefault{} ;	// default欠損localeを推測しない。
					std::size_t	 definitions{} ;	// 全candidate Strings section数。
					// defaultと全decorated候補を省略せず、各keyの一意な全literalを比較する。
					for( std::size_t section = 0U; section < sections_.size(); ++section) {
						const auto name = text( sections_[section].name) ;	// 一候補名。
						// 通常sectionをStrings定義へ使わない。
						if( !isStrings( name)) {
							continue ;
						}

						std::size_t	 matches{} ;	// このcandidate内の同key全定義数。
						std::wstring value ;		// この候補のtoken-free全literal。
						const auto	 begin = std::ranges::lower_bound(
							  rows_, section, {}, &MaintenanceRawRow::section) ;	// 元candidate範囲。
						// 同candidateだけの定義を一度ずつ確認し、重複を先頭へ絞らない。
						for( auto row = begin; row != rows_.end() && row->section == section;
							++row) {
							// 原key全名が一致する定義だけを数える。
							if( stringsEqual( text( row->key), key)) {
								++matches ;
								value = text( fields_[row->firstField]) ;
							}
						}

						// 全候補の欠損・nested token・過長・不一致を除外して成功させない。
						if( matches != 1U || value.find( L'%') != value.npos ||
						   value.size() >= 4096U || (definitions != 0U && literal != value)) {
							return false ;
						}

						literal = std::move( value) ;
						++definitions ;
						haveDefault = haveDefault || stringsEqual( name, L"Strings") ;
					}

					// 未定義やdefault欠損をOS localeの推測で補わない。
					if( definitions == 0U || !haveDefault ||
					   literal.size() > 4095U - output.size()) {
						return false ;
					}

					output += literal ;
				}

				next = end + 1U ;
			}

			// 原全展開の上限には終端一文字を含める。
			if( output.size() >= 4096U) {
				return false ;
			}
		}

		return true ;
	}
	/// private directoryの所有HANDLE。最多64、共有anchorは含まない。
	std::array<HANDLE, 64U>			   handles_{} ;
	/// 取得済みprivate component数。
	std::size_t						   handleCount_{} ;
	/// 元通常fileの読取専用所有HANDLE。
	HANDLE							   file_{INVALID_HANDLE_VALUE} ;
	/// 一回の原snapshot。再decode本文を保持しない。
	std::string						   bytes_ ;
	/// snapshot取得時の既存SHA-256。
	std::wstring					   hash_ ;
	/// 原section envelopeのmerge index。
	std::vector<MaintenanceRawSection> sections_ ;
	/// 原rowordinalと全field offsetの結合。
	std::vector<MaintenanceRawRow>	   rows_ ;
	/// 元byteに借用する全field offset。
	std::vector<MaintenanceRawSpan>	   fields_ ;
	/// BOMを除く原code unit開始byte。
	std::size_t						   start_{} ;
	/// ASCIIは1、BOM UTF-16LEは2。
	std::size_t						   width_{1U} ;
	/// 全seed共同の追加query／read消費。
	std::size_t						   extraCalls_{} ;
	/// 位置認定へ使用できるprivate proof状態。
	bool							   active_{} ;
} ;

/**
 * @brief 保守読取で明示空・不存在とその他のAPI失敗を分離する。
 * @param[in] inf 正常に開いた単独INF handle。
 * @param[in] name 元明示節名。
 * @param[out] count 成功時は行数、不存在なら-1。
 * @return 観測成功0、不存在以外の元HRESULT。
 */
[[nodiscard]] NativeError maintenanceLineCount( HINF inf, const std::wstring &name, LONG &count)
{
	SetLastError( ERROR_SUCCESS) ;
	count = SetupGetLineCountW( inf, name.c_str()) ;
	// 明示空と実在節は確定した行数で返す。
	if( count >= 0) {
		return 0 ;
	}

	const DWORD error = GetLastError() ;	// 不在とAPI失敗を直後に固定する。
	// 正常handleでの文書化された不在だけを-1として保持する。
	if( count == -1L && (error == ERROR_SECTION_NOT_FOUND || error == ERROR_SUCCESS)) {
		return 0 ;
	}

	return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
}

/**
 * @brief 確定行数内の一行をindexで取得し、途中終了を正常終端へ変換しない。
 * @param[in] inf 単独INF handle。
 * @param[in] name 実在を確認した元節名。
 * @param[in] ordinal 非負の行index。
 * @param[out] line 成功時だけの借用行context。
 * @return 取得成功0、元API診断。診断欠落も不正として返す。
 */
[[nodiscard]] NativeError maintenanceLineAt( HINF inf, const std::wstring &name, LONG ordinal,
											INFCONTEXT &line)
{
	SetLastError( ERROR_SUCCESS) ;
	// 確定行数の全行が取得できなければ部分参照を返さない。
	if( SetupGetLineByIndexW( inf, name.c_str(), static_cast<DWORD>( ordinal), &line) == FALSE) {
		const DWORD error = GetLastError() ;	// 元読取診断。
		return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
	}

	return 0 ;
}

/**
 * @brief 現OS用Modelsの全一意DDInstall名を一回の有限走査へ集める。
 * @param[in] inf 同期借用するINF handle。
 * @param[in,out] budget 全選択共通のModels読取予算。
 * @param[out] names 成功時の元導入名群。署名・device適合ではない。
 * @return 一つ以上の現在OS選択名の取得成功0、容量・読取・不正・対象なしのHRESULT。
 */
[[nodiscard]] NativeError collectMaintenanceInstallNames( HINF						 inf,
														 MaintenanceStructureBudget &budget,
														 std::vector<std::wstring>	&names)
{
	LONG		manufacturerCount{} ;	// 全メーカーの確定行数。
	NativeError countError =
		// 不在区分。
		maintenanceLineCount( inf, L"Manufacturer", manufacturerCount) ;
	// Manufacturer不在・空・過大とAPI失敗から任意DDInstallを選ばない。
	if( countError != 0 || manufacturerCount <= 0 || manufacturerCount > 4096L) {
		return countError != 0 ? countError : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// 全メーカーの現在OS用Modelsだけを有限に調べ、別OSの名を借用しない。
	for( LONG row = 0L; row < manufacturerCount; ++row) {
		INFCONTEXT manufacturer{} ;	// 現OSのModelsをWindowsへ選ばせる一行。
		countError = maintenanceLineAt( inf, L"Manufacturer", row, manufacturer) ;
		// 途中の読取不能をメーカー集合の正常終端にしない。
		if( countError != 0) {
			return countError ;
		}

		// 対象外メーカーも行予算へ含める。
		if( ++budget.lines > MAXIMUM_INSTALL_INVENTORY_LINES) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS> models{} ;	// 選択された節名。
		// Windowsが対象外としたメーカーだけを飛ばし、容量・API失敗は保持する。
		if( SetupDiGetActualModelsSectionW( &manufacturer, nullptr, models.data(),
										  static_cast<DWORD>( models.size()), nullptr,
										  nullptr) == FALSE) {
			const DWORD error = GetLastError() ;	// 対象なしと実失敗を区別する。
			// 未対応OSのModelsをfallbackで戻さない。
			if( error != ERROR_NO_COMPAT_DRIVERS && error != ERROR_SECTION_NOT_FOUND) {
				return nativeErrorFromWin32( error) ;
			}

			continue ;
		}

		const std::wstring modelName( models.data()) ;	// Windowsが選んだ元節名。
		LONG			   modelCount{} ;				// 選択節の確定行数。
		countError = maintenanceLineCount( inf, modelName, modelCount) ;
		// 選択Modelsの不在・空・過大とAPI失敗では部分集合を返さない。
		if( countError != 0 || modelCount <= 0 || modelCount > 4096L) {
			return countError != 0 ? countError : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// 現在OSの全Models行を読み、一意の導入名を有限に保持する。
		for( LONG modelRow = 0L; modelRow < modelCount; ++modelRow) {
			INFCONTEXT model{} ;	// 選択Models内の現在行。
			countError = maintenanceLineAt( inf, modelName, modelRow, model) ;
			// 全Modelsの途中の失敗を先頭選択成功で隠さない。
			if( countError != 0) {
				return countError ;
			}

			// Modelsとメーカーの累積行数を全INF予算へ拘束する。
			if( ++budget.lines > MAXIMUM_INSTALL_INVENTORY_LINES) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			std::wstring	  name ;									// 必須の元DDInstall名。
			const NativeError error = readInfField( model, 1U, name) ;	// Windows展開結果。
			// 不正行と過大fieldを読み飛ばして先頭選択だけを認定しない。
			if( error != 0 || SetupGetFieldCount( &model) < 2U ||
			   SetupGetFieldCount( &model) > MAXIMUM_INSTALL_INVENTORY_FIELDS ||
			   !validInstallInventorySectionName( name)) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// 一意選択が節上限を超える場合は切捨てない。
			if( appendUnique( names, std::move( name)) &&
			   names.size() > MAXIMUM_INSTALL_INVENTORY_SECTIONS) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}
		}
	}

	return names.empty() ? nativeErrorFromWin32( ERROR_NOT_FOUND) : 0 ;
}

/**
 * @brief AddServiceのnamed構造と限定nullを分けて非実行で読む。
 * @param[in,out] install この選択の構造と診断。
 * @param[in] section 元宣言節。
 * @param[in] values 空fieldを含む全展開値。flags過長時だけ第2値は空。
 * @param[in] flagsReadError flagsの個別長さ診断。0の場合は展開値を解析する。
 * @param[in] expectedServices 選択DDInstallと同じ装飾のServices節。
 */
void observeMaintenanceService( MaintenanceInfInstallStructure &install, const std::wstring &section,
							   std::span<const std::wstring> values, NativeError flagsReadError,
							   const std::wstring &expectedServices)
{
	MaintenanceInfServiceStructure service ;	// 空名もそのまま保持する独立した観測。
	service.section	   = section ;
	service.fieldCount = static_cast<std::uint32_t>( values.size()) ;
	service.parser	   = {MaintenanceInspectionState::PASSED, 0} ;
	// 第1fieldが存在する場合は、空と欠落の差を元field数で保持する。
	if( !values.empty()) {
		service.serviceName = values[0] ;
	}

	MaintenanceInfStructureReason reason =
		MaintenanceInfStructureReason::MISSING_SERVICE_FIELD ;	// 数値失敗時だけ意味を持つ理由。
	std::uint32_t				 parsedFlags{} ;				// 成功後だけoptional flagsへ格納する。
	MaintenanceInspectionFinding finding{MaintenanceInspectionState::FAILED,
										 // 欠落fieldを数値0にしない。
										 nativeErrorFromWin32( ERROR_INVALID_DATA)} ;
	// 過長flagsは通常の読取失敗と区別して個別不正結果へ残す。
	if( flagsReadError != 0) {
		reason		  = MaintenanceInfStructureReason::FLAGS_TOO_LONG ;
		finding.error = flagsReadError ;
	}
	// Namedの省略flagsは空fieldと非空の必須参照を持つ形だけを既定0として扱う。
	else if( !service.serviceName.empty() && values.size() >= 3U && values[1].empty() &&
			!values[2].empty()) {
		finding = {MaintenanceInspectionState::PASSED, 0} ;
	}
	// Fieldが揃った場合だけ、展開後の全文字を数値へ解析する。
	else if( values.size() >= 2U) {
		finding = parseMaintenanceFlags( values[1], parsedFlags, reason) ;
	}

	// 有効なflagsだけを保持し、失敗をoptional値の0へ変換しない。
	if( finding.state == MaintenanceInspectionState::PASSED) {
		service.flags = parsedFlags ;
	} else {
		service.parser = finding ;
		addMaintenanceIssue( install, section, L"AddService", reason, finding) ;
	}

	// 明示空第3fieldは無参照、欠落第3fieldも正当な2-field nullとして保持する。
	if( values.size() >= 3U) {
		service.serviceInstallSection = values[2] ;
	}

	// Event-log参照は第4fieldだけを保持し、後続値を節名へ変換しない。
	if( values.size() >= 4U) {
		service.eventLogSection = values[3] ;
	}

	const MaintenanceInspectionFinding unsupported{MaintenanceInspectionState::UNSUPPORTED,
												   // 未評価構成の診断値。
												   nativeErrorFromWin32( ERROR_NOT_SUPPORTED)} ;
	// 未展開named identityを実在serviceの構造として認定しない。
	if( !service.serviceName.empty() &&
	   (service.serviceName.find( L'%') != std::wstring::npos ||
		service.serviceInstallSection.find( L'%') != std::wstring::npos ||
		service.eventLogSection.find( L'%') != std::wstring::npos)) {
		mergeMaintenanceFinding( service.parser, unsupported) ;
		addMaintenanceIssue( install, section, L"AddService",
							MaintenanceInfStructureReason::NAMED_SERVICE_NOT_ASSESSED, unsupported) ;
	}

	// Namedは補助0とassociated2だけを構造対応し、nullには従来の2完全一致を要求する。
	if( service.flags.has_value() && *service.flags != 2U &&
	   (service.serviceName.empty() || *service.flags != 0U)) {
		mergeMaintenanceFinding( service.parser, unsupported) ;
		addMaintenanceIssue( install, section, L"AddService",
							MaintenanceInfStructureReason::FLAGS_NOT_SUPPORTED, unsupported) ;
	}

	// Namedの必須参照欠落をnullの無参照構造へ読み替えない。
	if( !service.serviceName.empty() && service.serviceInstallSection.empty()) {
		const MaintenanceInspectionFinding missing{MaintenanceInspectionState::FAILED,
												   // 欠落診断。
												   nativeErrorFromWin32( ERROR_INVALID_DATA)} ;
		mergeMaintenanceFinding( service.parser, missing) ;
		addMaintenanceIssue( install, section, L"AddService",
							MaintenanceInfStructureReason::MISSING_SERVICE_FIELD, missing) ;
	}

	// Empty名でも非空の参照節がある構成を無参照nullへ昇格しない。
	if( service.serviceName.empty() &&
	   (!service.serviceInstallSection.empty() || !service.eventLogSection.empty())) {
		mergeMaintenanceFinding( service.parser, unsupported) ;
		addMaintenanceIssue( install, section, L"AddService",
							MaintenanceInfStructureReason::NULL_SERVICE_SECTION_REFERENCE,
							unsupported) ;
	}

	// 非対応節と後続event作用fieldは明示診断として保持する。
	if( !stringsEqual( section, expectedServices) || values.size() > 4U) {
		mergeMaintenanceFinding( service.parser, unsupported) ;
		addMaintenanceIssue( install, section, L"AddService",
							MaintenanceInfStructureReason::SERVICE_DECLARATION_NOT_SUPPORTED,
							unsupported) ;
	}

	install.services.push_back( std::move( service)) ;
}

// Named service-installの必須項目。位置と起動意味の完全審査は別の境界。
constexpr std::array<std::wstring_view, 4U> MAINTENANCE_SERVICE_FIELDS{
	L"ServiceType", L"StartType", L"ErrorControl", L"ServiceBinary"} ;

/** @brief 既存有限queueが読んだservice必須行の構造。本文や数値を所有しない。 */
struct MaintenanceServiceFieldObservation {
	/// 読取元節の所有copy。named参照との結合だけに使う。
	std::wstring				 section ;
	/// 四つの必須directiveの所有copy。
	std::wstring				 directive ;
	/// 非空一fieldと限定数値形式の到達状態。byte・署名・実行意味ではない。
	MaintenanceInspectionFinding finding ;
} ;

/**
 * @brief 読取済みの必須service行を限定構造として確認する。
 * @param[in] key 必須四項目の一つ。呼出し中だけ借用する。
 * @param[in] values 同じqueueで読んだ全展開値。保存しない。
 * @return 構造認識PASSED、値欠落・不正FAILED、tokenと未対応値UNSUPPORTED。
 * @note ServiceBinaryの位置・実byteは既存参照readerへ委ね、SCMの完全validatorを作らない。
 */
[[nodiscard]] MaintenanceInspectionFinding observeMaintenanceServiceField(
	std::wstring_view key, std::span<const std::wstring> values) noexcept
{
	// 必須一値の欠落と多fieldを先頭値で成功へ補完しない。
	if( values.size() != 1U || values.front().empty()) {
		return {MaintenanceInspectionState::FAILED, nativeErrorFromWin32( ERROR_INVALID_DATA)} ;
	}

	// Binaryの非空宣言だけをここで確認し、未知位置や未取得byteは後段へ残す。
	if( stringsEqual( key, L"ServiceBinary")) {
		return {MaintenanceInspectionState::PASSED, 0} ;
	}

	std::uint32_t					   value{} ;	// 全field成功まで部分数値を使用しない。
	MaintenanceInfStructureReason	   reason{} ;	// 数値readerの内部理由。外向き理由へ流用しない。
	const MaintenanceInspectionFinding finding =
		// 既存の厳密uint32境界。
		parseMaintenanceFlags( values.front(), value, reason) ;
	// 不正・token・overflowの元状態とHRESULTを保持する。
	if( finding.state != MaintenanceInspectionState::PASSED) {
		return finding ;
	}

	const bool known =
		stringsEqual( key, L"ServiceType")
			? value == 1U || value == 2U || value == 0x10U || value == 0x20U || value == 0x110U ||
				  value == 0x120U
			: value <= (stringsEqual( key, L"StartType") ? 4U : 3U) ;	// 一次仕様の数値集合だけ。
	return known ? finding
				 : MaintenanceInspectionFinding{MaintenanceInspectionState::UNSUPPORTED,
												nativeErrorFromWin32( ERROR_NOT_SUPPORTED)} ;
}

/**
 * @brief Namedの必須参照と読取済み四項目を照合し具体的不足を保持する。
 * @param[in,out] install 同じ有限queueのservice・参照・用途観測。
 * @param[in] fields 読取済み必須行。最大4,096で同期借用する。
 * @return 観測成功0、診断または用途の保持上限超過のHRESULT。
 * @note 不足用途で全integrityを昇格させず、既知署名FAILEDは後段の既存優先規則で保持する。
 */
[[nodiscard]] NativeError assessMaintenanceNamedServices(
	MaintenanceInfInstallStructure					   &install,
	std::span<const MaintenanceServiceFieldObservation> fields)
{
	// 全namedを同じ元参照へ照合し、shared節を追加走査しない。
	for( auto &service : install.services) {
		// Nullの初期認定とnamed必須四項目の責務を分ける。
		if( service.serviceName.empty()) {
			continue ;
		}

		// 明示event-log参照の不在も、optionalという理由で無参照成功にしない。
		if( !service.eventLogSection.empty() &&
		   service.eventLogSection.find( L'%') == std::wstring::npos) {
			const bool present = std::ranges::any_of(
				install.inventory.references, [&service]( const auto &reference) {
					return stringsEqual( reference.section, service.section) &&
						   stringsEqual( reference.directive, L"AddService") &&
						   stringsEqual( reference.target, service.eventLogSection) &&
						   reference.targetPresent ;
				}) ; // 同宣言の非空event-log節だけ。
			// 照会済み節欠落の元診断を全integrity未検査と分離する。
			if( !present) {
				const MaintenanceInspectionFinding missing{
					MaintenanceInspectionState::FAILED,
					// 元参照節の不在。
					nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND)} ;
				mergeMaintenanceFinding( service.parser, missing) ;
				addMaintenanceIssue(
					install, service.section, L"AddService",
					MaintenanceInfStructureReason::SERVICE_DECLARATION_NOT_SUPPORTED, missing) ;
			}
		}

		// 空・未展開参照は先行診断で保持し、tokenを実在節として追加認定しない。
		if( !service.serviceInstallSection.empty() &&
		   service.serviceInstallSection.find( L'%') == std::wstring::npos) {
			const bool present = std::ranges::any_of(
				install.inventory.references, [&service]( const auto &reference) {
					return stringsEqual( reference.section, service.section) &&
						   stringsEqual( reference.directive, L"AddService") &&
						   stringsEqual( reference.target, service.serviceInstallSection) &&
						   reference.targetPresent ;
				}) ; // 同じ元宣言と明示節の存在だけ。
			// 元queueが確認した不在を空service節として成功へ変換しない。
			if( !present) {
				const MaintenanceInspectionFinding missing{
					MaintenanceInspectionState::FAILED,
					// 元節の欠落診断。
					nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND)} ;
				mergeMaintenanceFinding( service.parser, missing) ;
				addMaintenanceIssue(
					install, service.section, L"AddService",
					MaintenanceInfStructureReason::SERVICE_DECLARATION_NOT_SUPPORTED, missing) ;
			} else {
				// 必須四項目を同じ節へ結び、別の節の項目で欠落を補完しない。
				for( const auto key : MAINTENANCE_SERVICE_FIELDS) {
					const auto matches =
						std::ranges::count_if( fields, [&service, key]( const auto &field) {
							return stringsEqual( field.section, service.serviceInstallSection) &&
								   stringsEqual( field.directive, key) ;
						}) ; // 読取済み集合の件数。優先行は推測しない。
					MaintenanceInspectionFinding  finding{MaintenanceInspectionState::PASSED,
														  0} ;	// 個別項目。
					MaintenanceInfStructureReason reason = MaintenanceInfStructureReason::
						SERVICE_DECLARATION_NOT_SUPPORTED ;	// 値不足・未対応。
					// 項目欠落を既定値で埋めず、必須構造の失敗として残す。
					if( matches == 0) {
						reason	= MaintenanceInfStructureReason::MISSING_SERVICE_FIELD ;
						finding = {MaintenanceInspectionState::FAILED,
								   nativeErrorFromWin32( ERROR_INVALID_DATA)} ;
					}
					// 重複行の処理順序を独自に決定しない。
					else if( matches != 1) {
						finding = {MaintenanceInspectionState::UNSUPPORTED,
								   nativeErrorFromWin32( ERROR_NOT_SUPPORTED)} ;
					} else {
						finding =
							std::ranges::find_if( fields, [&service, key]( const auto &field) {
								return stringsEqual( field.section, service.serviceInstallSection) &&
									   stringsEqual( field.directive, key) ;
							})->finding ; // 一意の読取済み結果だけを同期借用する。
					}

					// 数値・空値の既知失敗を後続未対応で上書きしない。
					if( finding.state != MaintenanceInspectionState::PASSED) {
						mergeMaintenanceFinding( service.parser, finding) ;
						addMaintenanceIssue( install, service.serviceInstallSection,
											std::wstring( key), reason, finding) ;
					}
				}
			}
		}

		// 未評価namedの構造不足を全file参照完了へ昇格させない。
		if( service.parser.state != MaintenanceInspectionState::PASSED) {
			install.fileUses.push_back( {service.section, L"NamedServiceStructureNotAssessed", {}}) ;
		}

		// 不足も共同保持上限を消費し、過大集合を切り捨てない。
		if( install.issues.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
		   install.fileUses.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}
	}

	return 0 ;
}

/**
 * @brief 既知の一明示参照を有限queueとworker内観測へ結合する。
 * @param[in] inf 同期借用するINF handle。
 * @param[in] workspace path境界の検証だけに借用する保護領域。
 * @param[in] entries 固定されたpackage一覧。
 * @param[in] parent 元INFのpackage相対親位置。
 * @param[in] section 元宣言節。
 * @param[in] key 元directive。
 * @param[in] value 明示参照field。所有copyへ移す。
 * @param[in] kind 参照種別。存在だけで署名を認定しない。
 * @param[in] targetKind 同INF節を辿る場合の行形式。
 * @param[in,out] pending 有限な到達節queue。
 * @param[in,out] inventory 欠落参照も残す選択観測。
 * @return 安全な参照観測成功0、不正path・節形式・容量のHRESULT。
 */
[[nodiscard]] NativeError addMaintenanceReference(
	HINF inf, const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	std::wstring_view parent, const std::wstring &section, const std::wstring &key,
	std::wstring value, OfficialInfInstallReferenceKind kind,
	InstallInventorySectionKind targetKind, std::vector<InstallInventorySection> &pending,
	OfficialInfInstallInventory &inventory)
{
	bool present = false ;	// 元inventory／同INF節の存在だけを観測する。
	// Local節だけを同じINFで辿り、外部のNeedsを推測して開かない。
	if( kind == OfficialInfInstallReferenceKind::LOCAL_SECTION) {
		// 空・過長・path的な節名を拒否する。
		if( !validInstallInventorySectionName( value)) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		LONG			  count{} ;													// 明示空と不在、API失敗を区別する行数。
		const NativeError countError = maintenanceLineCount( inf, value, count) ;	// 元診断。
		// 不在以外のAPI失敗を参照欠落へ変換しない。
		if( countError != 0) {
			return countError ;
		}

		present = count >= 0 ;
		// 実在節だけを有限queueへ追加し、欠落を観測から削除しない。
		if( present) {
			// 参照先の形式とqueue容量を既存境界で確認した結果。
			const NativeError error = queueInstallInventorySection( pending, value, targetKind) ;
			// 循環・共有の再走査と矛盾した行形式を既存helperで制限する。
			if( error != 0) {
				return error ;
			}
		}
	} else {
		const std::wstring_view child = stripReferenceCurrentDirectory( value) ;	// 原参照名。
		// 明示空を親位置へ補完しない。
		if( child.empty()) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		value = joinRelativePath( parent, child) ;
		// Fileは元packageの安全な位置だけを参照し、外部探索を行わない。
		if( workspace.path( value).empty() || (kind != OfficialInfInstallReferenceKind::DIRECT_FILE &&
											 lowerExtension( value) != L".inf")) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		present = containsEntry( entries, value) ;
	}

	inventory.references.push_back( {section, key, std::move( value), kind, present}) ;
	return inventory.references.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS
			   ? nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW)
			   : 0 ;
}

// 私有indexの未観測値。実queue・用途indexへ補完しない。
constexpr std::size_t NO_MAINTENANCE_EVENTLOG_INDEX = MAXIMUM_INSTALL_INVENTORY_ITEMS ;

/**
 * @brief 同じ有限queueの節文脈と読取完了だけを保持します。
 * @note 本文を複写せず、既存queue indexを借用する一同期呼出しの私有記録です。
 */
struct MaintenanceEventLogSectionProof {
	/// Seedも含む参照元数。二つ以上なら混在を保留する。
	std::size_t incoming{} ;
	/// 一意AddReg／DelReg元のqueue index。混在時は成功根拠にしない。
	std::size_t registryParent{NO_MAINTENANCE_EVENTLOG_INDEX} ;
	/// このREGISTRYの具体的子Uの元fileUses index。
	std::size_t registryUse{NO_MAINTENANCE_EVENTLOG_INDEX} ;
	/// 非空REGISTRYの元coverage gap index。fallback appendとの結合だけに使う。
	std::size_t registryGap{NO_MAINTENANCE_EVENTLOG_INDEX} ;
	/// 同eventlogの独立した具体的子U index。
	std::size_t childUse{NO_MAINTENANCE_EVENTLOG_INDEX} ;
	/// 同eventlogの非空子REGISTRY gap index。
	std::size_t childGap{NO_MAINTENANCE_EVENTLOG_INDEX} ;
	/// このDIRECTIVESから辿ったAddReg／DelRegのfield数。
	std::size_t children{} ;
	/// 元全行読取を完了した場合だけtrue。
	bool		complete{} ;
	/// 全行が非空AddReg／DelRegの形だけならtrue。空節はfalse。
	bool		registryDirectivesOnly{true} ;
	/// 全子の一意文脈と読取完了を証明できる場合だけtrue。
	bool		childrenValid{true} ;
	/// 元EventLog全制御行の全値が同byteへ結合した場合true。
	bool		fullValues{true} ;
	/// 第4fieldからの処理がAddRegのみならtrue。DelRegを新data認定へ使わない。
	bool		addRegOnly{true} ;
	/// 同registry内のEventMessageFile全設定行数。型の違う重複も数える。
	std::size_t eventMessageSettings{} ;
} ;

/**
 * @brief 一AddService行の親markerと同eventlog子Uだけを私有結合します。
 * @note 明示out-paramの所有vectorをcallerが借用し、公開型や永続stateへ保存しません。
 */
struct MaintenanceEventLogMarkerProof {
	/// 当該行が作った親fileUses index。名前だけのfilterには使わない。
	std::size_t marker{} ;
	/// 当該行の元service観測index。最終named評価後だけ認定する。
	std::size_t service{} ;
	/// Services節内の元行ordinal。
	LONG		row{} ;
	/// 同行第4fieldのDIRECTIVES queue index。
	std::size_t eventSection{NO_MAINTENANCE_EVENTLOG_INDEX} ;
	/// 分離後も残す具体的子Uの元fileUses index。
	std::size_t childUse{NO_MAINTENANCE_EVENTLOG_INDEX} ;
	/// sourceなしfallbackの元REGISTRY gap index。
	std::size_t childGap{NO_MAINTENANCE_EVENTLOG_INDEX} ;
	/// 同AddService keyと全4fieldへ結合したraw行。
	std::size_t rawRow{NO_MAINTENANCE_RAW_ROW} ;
} ;

/**
 * @brief 一DDInstallと同じ装飾の付随節を全INF予算内で非実行観測する。
 * @param[in] inf 同期借用するINF handle。
 * @param[in] workspace path境界だけに使用する保護領域。
 * @param[in] entries 固定package一覧。
 * @param[in] parent 元INFの安全な相対親位置。
 * @param[in,out] budget 全選択共通の有限予算。
 * @param[in,out] install Models所属とWindowsの実在選択を確認した観測。
 * @param[in] explicitSeeds 非空なら原明示節だけを使い、付随suffixを追加しない。
 * @param[in,out] copyDestinations 非nullなら同じ読取済みnamed行を最大4,096件保持する私有sidecar。
 * nullでは通常の構造観測だけを行い、所有権を取得しない。
 * @param[out] eventLogProofs 非nullなら同行親markerと子Uの私有証明を返します。
 * 全体失敗時はcallerが破棄し、私有容量・曖昧時は元markerを保持します。
 * @param[in,out] byteProof 非nullなら同元byteの全値・元data indexを私有結合する。
 * @return 全節観測成功0。読取・不正参照・容量失敗は全体拒否のHRESULT。
 */
[[nodiscard]] NativeError inspectMaintenanceInstallStructure(
	HINF inf, const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	std::wstring_view parent, MaintenanceStructureBudget &budget,
	MaintenanceInfInstallStructure &install, std::span<const std::wstring> explicitSeeds = {},
	std::vector<MaintenanceCopyDestination>		*copyDestinations = nullptr,
	std::vector<MaintenanceEventLogMarkerProof> *eventLogProofs	  = nullptr,
	MaintenanceInfByteProof						*byteProof		  = nullptr)
{
	install.parser						   = {MaintenanceInspectionState::PASSED, 0} ;
	OfficialInfInstallInventory &inventory = install.inventory ;	// この選択だけのgraph。
	std::vector<MaintenanceServiceFieldObservation> serviceFields ;	// 同じ有限queueの必須行だけ。
	std::vector<InstallInventorySection>			pending{
				   {inventory.selectedInstallSection, InstallInventorySectionKind::DIRECTIVES}} ;	// 訪問queue。
	// 同queueのindexだけを所有する。
	std::vector<MaintenanceEventLogSectionProof> eventSections ;
	// 通常構造readerの状態を変更しない。
	bool										 eventProofEnabled = eventLogProofs != nullptr ;
	bool byteQueueComplete = byteProof != nullptr ;	// 最終caller認定まで全制御行を共同評価する。
	// 同期callerの前回証明を今回の同行へ流用しない。
	if( eventLogProofs != nullptr) {
		eventLogProofs->clear() ;
	}

	// 依存先の原明示節へsuffix補完せず、同じ一queueで共有節を除去する。
	if( !explicitSeeds.empty()) {
		pending.clear() ;
		// 呼出し側が存在確認した原seedだけを有限queueへ加える。
		for( const auto &seed : explicitSeeds) {
			const NativeError seedError = queueInstallInventorySection(
				pending, seed, InstallInventorySectionKind::DIRECTIVES) ;	// 一意な明示seed。
			// 過大・形式矛盾のseedを部分集合へ切り詰めない。
			if( seedError != 0) {
				return seedError ;
			}
		}
	}

	const std::wstring servicesSection =
		inventory.selectedInstallSection + L".Services" ;	// 同装飾。
	constexpr std::
		array<std::wstring_view, 9>
			SUFFIXES{L".HW",
					 L".Services",
					 L".CoInstallers",
					 L".Interfaces",
					 L".Components",
					 L".Software",
					 L".Wdf",
					 L".Events",
					 L".LogConfigOverride"} ;	// 既存棚卸しと同じ有限付随節集合。
	// 選択DDInstallと完全一致する付随節だけをseedへ加える。
	for( const auto suffix : SUFFIXES) {
		// 依存先Needsへ推測suffixを加えず、構造選択だけで付随節を加える。
		if( !explicitSeeds.empty()) {
			break ;
		}

		const std::wstring name = inventory.selectedInstallSection + std::wstring( suffix) ;	// 元節。
		LONG			   count{} ;															// 不在と明示空の区別。
		const NativeError  countError = maintenanceLineCount( inf, name, count) ;				// 元診断。
		// 不在以外のAPI失敗を無参照の根拠にしない。
		if( countError != 0) {
			return countError ;
		}

		// 他OS装飾や不在付随節を別の選択へfallbackしない。
		if( count < 0) {
			continue ;
		}

		pending.push_back( {name, InstallInventorySectionKind::DIRECTIVES}) ;
		// 非空CoInstaller節の存在を作用なしへ変換しない。
		if( stringsEqual( suffix, L".CoInstallers") && count > 0) {
			inventory.effects.push_back(
				{name, L"CoInstallers", OfficialInfInstallEffectKind::COINSTALLER}) ;
		}
	}

	// Seedの文脈を明示し、後からeventlogとして再利用された節を一意としない。
	if( eventProofEnabled) {
		eventSections.resize( pending.size()) ;
		// 元seedはそれぞれ独立した到達文脈を一件消費する。
		for( auto &section : eventSections) {
			section.incoming = 1U ;
		}
	}

	// 共有・循環を一度に止める有限queueを末尾追加分まで調べる。
	for( std::size_t index = 0U; index < pending.size(); ++index) {
		const InstallInventorySection current = pending[index] ;	// Queue再確保から独立したcopy。
		LONG						  count{} ;						// 確定読取行数。
		const NativeError			  countError =
			// 元読取診断。
			maintenanceLineCount( inf, current.name, count) ;
		// 不在以外の読取失敗を容量診断へ置換しない。
		if( countError != 0) {
			return countError ;
		}

		// 全選択で1,024節・4,096行を共同消費し、一選択ごとに上限をresetしない。
		if( ++budget.sections > MAXIMUM_INSTALL_INVENTORY_SECTIONS || count < 0 ||
		   static_cast<std::size_t>( count) > MAXIMUM_INSTALL_INVENTORY_LINES - budget.lines) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		inventory.visitedSections.push_back( current.name) ;
		// 明示空節を子Uの証明へ使わず、読取完了だけを保持する。
		if( eventProofEnabled && count == 0) {
			eventSections[index].complete				= true ;
			eventSections[index].registryDirectivesOnly = false ;
		}

		// 明示空節を読取失敗へ変換しない。
		if( count == 0) {
			continue ;
		}

		// Registryとdata本文の作用解釈は全file参照検査とは別の不足へ保持する。
		if( current.kind != InstallInventorySectionKind::DIRECTIVES &&
		   current.kind != InstallInventorySectionKind::COPY_FILE_ROWS) {
			inventory.coverageGaps.push_back(
				{current.name,
				 {},
				 current.kind == InstallInventorySectionKind::REGISTRY
					 ? OfficialInfInstallCoverageKind::REGISTRY_SCOPE_NOT_ASSESSED
					 : OfficialInfInstallCoverageKind::DATA_ROWS_NOT_INTERPRETED}) ;
			// 非空registryの元gapだけをfallback用途へ結合し、別節を代用しない。
			if( eventProofEnabled && current.kind == InstallInventorySectionKind::REGISTRY) {
				eventSections[index].registryGap = inventory.coverageGaps.size() - 1U ;
			}
		}

		// 確定した全行を順に読み、途中終了と過大fieldを拒否する。
		for( LONG row = 0; row < count; ++row) {
			// 後続coreの保持量をprivate予約で奪わない。
			if( byteProof != nullptr) {
				byteProof->capacity( budget.effects + budget.references + budget.services +
									budget.issues + budget.fileUses + budget.coverageGaps +
									inventory.effects.size() + inventory.references.size() +
									inventory.coverageGaps.size() + install.services.size() +
									install.issues.size() + install.fileUses.size() +
									serviceFields.size() + pending.size() + eventSections.size() +
									(eventLogProofs == nullptr ? 0U : eventLogProofs->size()) +
									(copyDestinations == nullptr ? 0U : copyDestinations->size())) ;
			}

			INFCONTEXT		  line{} ;	// 確定indexで取得する現在行。
			const NativeError lineError =
				// 元診断。
				maintenanceLineAt( inf, current.name, row, line) ;
			// 途中失敗を正常終端へ変換しない。
			if( lineError != 0) {
				return lineError ;
			}

			++budget.lines ;
			++inventory.scannedLines ;
			const DWORD fields = SetupGetFieldCount( &line) ;	// Keyを除く元field数。
			// 一行を上限64 fieldへ拘束する。
			if( fields > MAXIMUM_INSTALL_INVENTORY_FIELDS) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			const std::size_t rawRow =
				byteProof == nullptr
					? NO_MAINTENANCE_RAW_ROW
					: byteProof->row( current.name, row, count,
									 fields) ;	// 同section count／ordinalの全値結合。

			std::wstring key ;	// Directive節以外の本文をkeyとして保持しない。
			// 処理節では空keyを不正として検出する。
			if( current.kind == InstallInventorySectionKind::DIRECTIVES) {
				MaintenanceFieldRead read{} ;	// 同じ元query／readの結果だけ。
				const NativeError	 error = readMaintenanceField(
					   line, 0U, key,
					   byteProof != nullptr && byteProof->active() ? &read : nullptr) ;	// 一宣言のkey。
				// 読取不能宣言を未知の正常行として読み飛ばさない。
				if( error != 0 || key.empty()) {
					return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				// 元keyを追加APIより前に全比較する。
				if( byteProof != nullptr) {
					byteProof->field( rawRow, 0U, key, read) ;
				}
			} else {
				// 元coreが未取得のkey有無だけを同context内で一回補う。
				if( byteProof != nullptr) {
					byteProof->extra( line, rawRow, 0U, 0U) ;
				}
			}

			std::vector<std::wstring> values ;				// この行だけの全値。command本文は外へ保持しない。
			NativeError				  flagsReadError{} ;	// 個別過長flagsだけを構造へ残す。
			// 空値を含む全fieldを有限に読み、切捨てbufferを使わない。
			for( DWORD field = 1U; field <= fields; ++field) {
				std::wstring		 value ;	// 一つの展開後field。
				MaintenanceFieldRead read{} ;	// 元結果を同時捕捉し、再readしない。
				const NativeError	 error =
					// 長さを先に照会。
					readMaintenanceField( line, field, value,
										 byteProof != nullptr && byteProof->active() ? &read
																					 : nullptr) ;
				// 過長flagsは個別不正、他の読取不能は全体失敗として分離する。
				if( error != 0) {
					// flagsだけの有限長失敗は0や2へ補完せず観測結果に残す。
					if( stringsEqual( key, L"AddService") && field == 2U &&
					   error == nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW)) {
						flagsReadError = error ;
					} else {
						return error ;
					}
				}

				// 元の成功値だけを同raw fieldへ全比較する。
				if( error == 0 && byteProof != nullptr) {
					byteProof->field( rawRow, field, value, read) ;
				}

				values.push_back( std::move( value)) ;
			}

			// 制御行と到達copyの全値不足を後のcaller名一致で補完しない。
			if( byteProof != nullptr &&
			   (current.kind == InstallInventorySectionKind::DIRECTIVES ||
				current.kind == InstallInventorySectionKind::COPY_FILE_ROWS)) {
				byteQueueComplete = byteQueueComplete && byteProof->verified( rawRow) ;
			}

			// EventLogの全行はAddRegのみと全raw値の一致を独立に確認する。
			if( eventProofEnabled && current.kind == InstallInventorySectionKind::DIRECTIVES) {
				eventSections[index].fullValues = eventSections[index].fullValues &&
												  byteProof != nullptr &&
												  byteProof->verified( rawRow) ;
				eventSections[index].addRegOnly = eventSections[index].addRegOnly &&
												  stringsEqual( key, L"AddReg") && !values.empty() ;
			}

			// 必須service行は一度の有限読取結果だけを保持し、後から到達するnamedにも結ぶ。
			// 第4field本文は既存follow可能なregistry宣言だけで全行を構成する必要がある。
			if( eventProofEnabled && current.kind == InstallInventorySectionKind::DIRECTIVES &&
			   (!(stringsEqual( key, L"AddReg") || stringsEqual( key, L"DelReg")) || values.empty() ||
				std::ranges::any_of( values, []( const auto &value) {
					return !validInstallInventorySectionName( value) ||
						   value.find( L'%') != std::wstring::npos ;
				}))) {
				eventSections[index].registryDirectivesOnly = false ;
			}

			// 必須service行は一度の有限読取結果だけを保持し、後から到達するnamedにも結ぶ。
			if( current.kind == InstallInventorySectionKind::DIRECTIVES &&
			   isAllowedValue( key, MAINTENANCE_SERVICE_FIELDS)) {
				serviceFields.push_back(
					{current.name, key, observeMaintenanceServiceField( key, values)}) ;
			}

			// Data file listの観測を無参照証明へ使わず、具体的用途として残す。
			if( current.kind == InstallInventorySectionKind::COPY_FILE_ROWS) {
				// Source名省略時はdestination名を使い、別名copyを先頭名へ潰さない。
				if( values.empty() || values.front().empty() || values.size() > 4U) {
					return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				install.fileUses.push_back(
					{current.name, L"CopyFileSource",
					 values.size() >= 2U && !values[1].empty() ? values[1] : values.front()}) ;
				// 展開済みbinary照合用の別名を同じ行から保持し、listを再走査しない。
				if( copyDestinations != nullptr) {
					// 全seedで共有する保持上限を行ごとにresetしない。
					if( copyDestinations->size() >= MAXIMUM_INSTALL_INVENTORY_ITEMS) {
						return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
					}

					copyDestinations->push_back(
						{current.name, values.front(),
						 values.size() >= 2U && !values[1].empty() ? values[1] : values.front(),
						 rawRow}) ;
				}
			}
			// 不透明なdata用途は既知CopyFiles listとは区別する。
			else if( current.kind == InstallInventorySectionKind::DATA_ROWS) {
				install.fileUses.push_back( {current.name, L"DataRowsNotInterpreted", {}}) ;
			}
			// Registry行の具体的範囲を保持し、全file用途を解釈したと称さない。
			else if( current.kind == InstallInventorySectionKind::REGISTRY) {
				// Registryのroot／subkeyが欠落した不正入力を拒否する。
				if( values.size() < 2U) {
					return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				// 同値名への別型・別flags・重複行も一意設定の分母へ残す。
				if( eventProofEnabled && values.size() >= 3U &&
				   stringsEqual( values[2], L"EventMessageFile")) {
					++eventSections[index].eventMessageSettings ;
				}

				// 値名で明示されたCoInstallerだけを具体的作用として保持する。
				if( values.size() >= 3U && stringsEqual( values[2], L"CoInstallers32")) {
					inventory.effects.push_back( {current.name, L"CoInstallers32",
												 OfficialInfInstallEffectKind::COINSTALLER}) ;
				}

				// Registry作用とfile用途を分離し、具体的file表記があるdataだけを残す。
				for( std::size_t field = 4U; field < values.size(); ++field) {
					const std::wstring &value = values[field] ;	// この原dataだけの同期借用。
					// File位置／token／binary名の具体的な未追跡用途を無参照へ変換しない。
					if( value.find_first_of( L"\\/%") != std::wstring::npos ||
					   lowerExtension( value) == L".dll" || lowerExtension( value) == L".sys" ||
					   lowerExtension( value) == L".exe") {
						install.fileUses.push_back(
							{current.name, L"RegistryFileUseNotAssessed", value}) ;
						std::uint32_t				  flags{} ;		// この元rowだけのexact type。
						MaintenanceInfStructureReason reason{} ;	// 新private判定にだけ使う。
						// keyなしstrict5fieldの単一EventMessageFileだけを元use ordinalへstageする。
						if( byteProof != nullptr && byteProof->verified( rawRow) &&
						   byteProof->get( rawRow).key.size == 0U && values.size() == 5U &&
						   field == 4U && stringsEqual( values[0], L"HKR") && values[1].empty() &&
						   stringsEqual( values[2], L"EventMessageFile") && !value.empty() &&
						   parseMaintenanceFlags( values[3], flags, reason).state ==
							   MaintenanceInspectionState::PASSED &&
						   flags == 0x00020000U) {
							byteProof->registry( rawRow, install.fileUses.size() - 1U, index) ;
						}

						// 元読取が保持した最初の独立子Uだけをindexで結ぶ。
						if( eventProofEnabled &&
						   eventSections[index].registryUse == NO_MAINTENANCE_EVENTLOG_INDEX) {
							eventSections[index].registryUse = install.fileUses.size() - 1U ;
						}
					}
				}
			} else {
				std::size_t rowProof = NO_MAINTENANCE_EVENTLOG_INDEX ;	// 同行だけのout-param index。
				const OfficialInfInstallEffectKind effect =
					// 宣言種類。
					installInventoryEffectKind( key) ;
				inventory.effects.push_back( {current.name, key, effect}) ;
				const auto gap = installInventoryCoverageKind( key, values) ;	// 既存作用不足。
				// 未追跡directive・未解決依存を新しいcaller証明の外へ捨てない。
				if( effect == OfficialInfInstallEffectKind::UNKNOWN_DIRECTIVE ||
				   (gap.has_value() &&
					*gap != OfficialInfInstallCoverageKind::UNFOLLOWED_SERVICE_EVENTLOG) ||
				   stringsEqual( key, L"Include") || stringsEqual( key, L"Needs")) {
					byteQueueComplete = false ;
				}

				// 具体的な未解釈作用を元宣言へ結合する。
				if( gap.has_value()) {
					inventory.coverageGaps.push_back( {current.name, key, *gap}) ;
				}

				// 未知directiveを限定nullの完全対応へ通さない。
				if( effect == OfficialInfInstallEffectKind::UNKNOWN_DIRECTIVE) {
					addMaintenanceIssue( install, current.name, key,
										MaintenanceInfStructureReason::UNKNOWN_DIRECTIVE,
										{MaintenanceInspectionState::UNSUPPORTED,
										 nativeErrorFromWin32( ERROR_NOT_SUPPORTED)}) ;
				}

				// Serviceはempty第一fieldと2-field形式を保守readerだけで扱う。
				if( stringsEqual( key, L"AddService")) {
					observeMaintenanceService( install, current.name, values, flagsReadError,
											  servicesSection) ;
				}

				// 未追跡だった具体的file用途を保持し、位置・byte・署名の未検査を隠さない。
				if( stringsEqual( key, L"CopyINF") || stringsEqual( key, L"AddComponent") ||
				   stringsEqual( key, L"ServiceBinary") || stringsEqual( key, L"UmdfServiceBinary") ||
				   stringsEqual( key, L"EventMessageFile") ||
				   effect == OfficialInfInstallEffectKind::UNKNOWN_DIRECTIVE || gap.has_value()) {
					install.fileUses.push_back(
						{current.name, key, values.empty() ? std::wstring{} : values.front()}) ;
					// 同元ServiceBinaryのDIRID13全値だけを最後のnamed target比較へstageする。
					if( byteProof != nullptr && stringsEqual( key, L"ServiceBinary")) {
						byteProof->control( rawRow, install.fileUses.size() - 1U) ;
					}

					// 厳密4fieldのnamed行だけを候補にし、最終service成功は後段で確認する。
					if( eventProofEnabled && stringsEqual( key, L"AddService") &&
					   values.size() == 4U && !values[0].empty() && !values[2].empty() &&
					   !values[3].empty()) {
						rowProof = eventLogProofs->size() ;
						eventLogProofs->push_back(
							{install.fileUses.size() - 1U, install.services.size() - 1U, row}) ;
						eventLogProofs->back().rawRow = rawRow ;
					}
				}

				// 同INF参照・package相対file・外部依存を既知directiveだけで区別する。
				for( std::size_t field = 0U; field < values.size(); ++field) {
					std::wstring target = values[field] ;	// 参照だけを結果へ残す所有copy。
					OfficialInfInstallReferenceKind kind =
						OfficialInfInstallReferenceKind::LOCAL_SECTION ;	// 既定境界。
					InstallInventorySectionKind targetKind =
						InstallInventorySectionKind::DATA_ROWS ;	// 不透明dataが既定。
					bool follow = false ;							// 未知fieldを任意節参照へ変換しない。
					// Registry処理の明示節は別行形式で辿る。
					if( stringsEqual( key, L"AddReg") || stringsEqual( key, L"DelReg")) {
						follow	   = true ;
						targetKind = InstallInventorySectionKind::REGISTRY ;
					}
					// 外部INF参照は元packageだけの存在観測に限定する。
					else if( stringsEqual( key, L"Include") || stringsEqual( key, L"CopyINF")) {
						follow = true ;
						kind   = stringsEqual( key, L"Include")
									 ? OfficialInfInstallReferenceKind::INCLUDE_INF
									 : OfficialInfInstallReferenceKind::COPY_INF ;
					}
					// Needsの明示名をそのまま使い、suffixや別節Includeを借用しない。
					else if( stringsEqual( key, L"Needs")) {
						follow	   = true ;
						targetKind = InstallInventorySectionKind::DIRECTIVES ;
					}
					// Nullでは空第3／第4fieldを参照欠落にせず、非空参照だけを辿る。
					else if( stringsEqual( key, L"AddService")) {
						follow	   = (field == 2U || field == 3U) && !target.empty() ;
						targetKind = InstallInventorySectionKind::DIRECTIVES ;
					}
					// 指定第3fieldだけが処理節であり、後続flagsを節にしない。
					else if( stringsEqual( key, L"AddInterface") ||
							stringsEqual( key, L"AddComponent") ||
							stringsEqual( key, L"AddSoftware")) {
						follow	   = field == 2U ;
						targetKind = InstallInventorySectionKind::DIRECTIVES ;
					}
					// WDFは指定第2fieldだけを処理節として辿る。
					else if( stringsEqual( key, L"KmdfService") ||
							stringsEqual( key, L"UmdfService")) {
						follow	   = field == 1U ;
						targetKind = InstallInventorySectionKind::DIRECTIVES ;
					}
					// 直接CopyFilesとfile list節を区別して有限に観測する。
					else if( stringsEqual( key, L"CopyFiles")) {
						follow	   = true ;
						targetKind = InstallInventorySectionKind::COPY_FILE_ROWS ;
						install.fileUses.push_back( {current.name, key, target}) ;
						// @fileを節名に読み替えずpackage相対参照へ渡す。
						if( target.starts_with( L"@")) {
							target.erase( 0U, 1U) ;
							kind = OfficialInfInstallReferenceKind::DIRECT_FILE ;
						}
					}

					// 明示参照を持つfieldだけを有限な既存queueへ追加する。
					if( follow) {
						const NativeError error = addMaintenanceReference(
							inf, workspace, entries, parent, current.name, key, std::move( target),
							kind, targetKind, pending, inventory) ;	// 元境界。
						// 不正参照や容量失敗ではINF全体の部分観測を破棄する。
						if( error != 0) {
							return error ;
						}

						// 欠落したregistry子節は他の子Uで補完せず、元親markerを保留する。
						if( eventProofEnabled &&
						   kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
						   targetKind == InstallInventorySectionKind::REGISTRY &&
						   !inventory.references.back().targetPresent) {
							eventSections[index].childrenValid = false ;
						}

						// 既存queueへ入った同INF参照だけを私有文脈へ結ぶ。再readはしない。
						if( eventProofEnabled &&
						   kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
						   inventory.references.back().targetPresent) {
							eventSections.resize( pending.size()) ;
							const auto targetEntry =
								std::ranges::find_if( pending, [&inventory]( const auto &entry) {
									return stringsEqual( entry.name,
														inventory.references.back().target) ;
								}) ; // 元queueの一意indexだけを同期借用する。
							const std::size_t targetIndex = static_cast<std::size_t>(
								targetEntry - pending.begin()) ;	// 実在queue内。
							auto &targetProof =
								eventSections[targetIndex] ;	// 再確保後の一要素だけ。
							++targetProof.incoming ;
							// 一意registry caller以外の共有文脈は双方を保留する。
							if( targetKind == InstallInventorySectionKind::REGISTRY) {
								++eventSections[index].children ;
								// 最初のcallerだけを保持し、二番目を先頭callerへ統合しない。
								if( targetProof.incoming == 1U) {
									targetProof.registryParent = index ;
								} else {
									eventSections[index].childrenValid = false ;
									// 元callerも共有の影響を受けるため証明を保留する。
									if( targetProof.registryParent !=
									   NO_MAINTENANCE_EVENTLOG_INDEX) {
										eventSections[targetProof.registryParent].childrenValid =
											false ;
									}
								}
							}

							// 第3fieldや別callerでは当該行のeventlog結合を作らない。
							if( rowProof != NO_MAINTENANCE_EVENTLOG_INDEX && field == 3U) {
								eventLogProofs->at( rowProof).eventSection = targetIndex ;
							}
						}
					}
				}
			}

			// 一選択の中間保持量も固定上限を超えさせない。
			if( inventory.effects.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
			   inventory.coverageGaps.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
			   serviceFields.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
			   install.services.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
			   install.issues.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
			   install.fileUses.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			// 私有保持も共同項目枠へ含める。証明限界は元readerの成功を拒否へ変えない。
			if( eventProofEnabled &&
			   (eventSections.size() + eventLogProofs->size() + budget.references +
					inventory.references.size() + budget.fileUses + install.fileUses.size() +
					inventory.effects.size() + inventory.coverageGaps.size() +
					serviceFields.size() + install.services.size() + install.issues.size() >
				MAXIMUM_INSTALL_INVENTORY_ITEMS)) {
				eventProofEnabled = false ;
				eventSections.clear() ;
				eventLogProofs->clear() ;
			}

			// 増加直後にも共同core必要量を優先してprivate予約を撤回する。
			if( byteProof != nullptr) {
				byteProof->capacity(
					budget.effects + budget.references + budget.services + budget.issues +
					budget.fileUses + budget.coverageGaps + inventory.effects.size() +
					inventory.references.size() + inventory.coverageGaps.size() +
					serviceFields.size() + install.services.size() + install.issues.size() +
					install.fileUses.size() + pending.size() + eventSections.size() +
					(eventLogProofs == nullptr ? 0U : eventLogProofs->size()) +
					(copyDestinations == nullptr ? 0U : copyDestinations->size())) ;
			}
		}

		// 確定した全行の成功後だけ読取完了を認定する。
		if( eventProofEnabled) {
			eventSections[index].complete = true ;
		}
	}

	const NativeError namedError =
		// 再読取しない照合。
		assessMaintenanceNamedServices( install, serviceFields) ;
	// 必須構造の不足保持で上限を超えた場合は部分観測を公開しない。
	if( namedError != 0) {
		return namedError ;
	}

	// 全queueを一回だけ照合し、子Uとread完了を一意な元callerへ集約する。
	if( eventProofEnabled) {
		// 各元registryの私有indexだけを順に処理し、親ごとの全節再探索をしない。
		for( const auto &child : eventSections) {
			// registryへ至る元callerがない節を別eventlogの証明へ使わない。
			if( child.registryParent == NO_MAINTENANCE_EVENTLOG_INDEX) {
				continue ;
			}

			auto &event = eventSections[child.registryParent] ;	// 読取済みの元DIRECTIVESだけ。
			event.childrenValid = event.childrenValid && child.complete && child.incoming == 1U ;
			// 同eventlogから到達した具体的Uだけを保持する。
			if( event.childUse == NO_MAINTENANCE_EVENTLOG_INDEX) {
				event.childUse = child.registryUse ;
			}

			// 非空子節の元gapをsourceなしfallbackへ結ぶ。
			if( event.childGap == NO_MAINTENANCE_EVENTLOG_INDEX) {
				event.childGap = child.registryGap ;
			}
		}

		// 同行serviceの最終PASSEDと一意な第4field文脈だけをcallerへ残す。
		for( auto &proof : *eventLogProofs) {
			// 未結合の第4fieldには子のindexを補完しない。
			if( proof.eventSection != NO_MAINTENANCE_EVENTLOG_INDEX) {
				proof.childUse = eventSections[proof.eventSection].childUse ;
				proof.childGap = eventSections[proof.eventSection].childGap ;
			}
		}

		// 元proof順で成功条件だけを残し、サービス名の一致で結び直さない。
		std::erase_if( *eventLogProofs, [&install, &eventSections]( const auto &proof) {
			// 未実在・未結合の第4fieldから親markerを外さない。
			if( proof.eventSection == NO_MAINTENANCE_EVENTLOG_INDEX) {
				return true ;
			}

			const auto &service = install.services[proof.service] ;		// 同行だけの最終観測。
			const auto &event	= eventSections[proof.eventSection] ;	// 同行第4fieldの元queue。
			return service.parser.state != MaintenanceInspectionState::PASSED ||
				   !service.flags.has_value() || (*service.flags != 0U && *service.flags != 2U) ||
				   !event.complete || event.incoming != 1U || !event.registryDirectivesOnly ||
				   !event.childrenValid || event.children == 0U ||
				   (proof.childUse == NO_MAINTENANCE_EVENTLOG_INDEX &&
					proof.childGap == NO_MAINTENANCE_EVENTLOG_INDEX) ;
		}) ;
		// 最終named PASSEDと同第4fieldのAddReg-only一意callerだけをdataへ結ぶ。
		if( byteProof != nullptr && byteProof->active() && byteQueueComplete) {
			// 同元data indexだけを一度ずつ確認し、後からの共有callerを反映する。
			for( auto &candidate : byteProof->data) {
				const auto &registry = eventSections[candidate.queue] ;	// 元REGISTRYの全caller。
				// 別caller／同値名複数rowを一意設定へ絞らない。
				if( registry.incoming != 1U ||
				   registry.registryParent == NO_MAINTENANCE_EVENTLOG_INDEX ||
				   registry.eventMessageSettings != 1U) {
					continue ;
				}

				const auto &event = eventSections[registry.registryParent] ;	// 同第4fieldの元節。
				candidate.caller  = event.complete && event.incoming == 1U && event.fullValues &&
								   event.addRegOnly && event.childrenValid &&
								   std::ranges::any_of( *eventLogProofs, [&]( const auto &proof) {
									   return proof.eventSection == registry.registryParent &&
											  byteProof->verified( proof.rawRow) ;
								   }) ; // 名称からAddServiceを結び直さない。
			}
		}
	}

	const auto associated = std::ranges::count_if( install.services, []( const auto &service) {
		return service.flags.has_value() && (*service.flags & 2U) != 0U ;
	}) ; // SPSVCINST_ASSOCSERVICEのbit観測数。literal比較だけで数えない。
	// 複数associated serviceを先頭nullの成功で隠さない。
	if( associated > 1U) {
		addMaintenanceIssue(
			install, servicesSection, L"AddService",
			MaintenanceInfStructureReason::MULTIPLE_ASSOCIATED_SERVICES,
			{MaintenanceInspectionState::UNSUPPORTED, nativeErrorFromWin32( ERROR_NOT_SUPPORTED)}) ;
		// Namedの矛盾したassociated構成を全参照完了へ昇格させない。
		if( std::ranges::any_of( install.services,
							   []( const auto &service) { return !service.serviceName.empty() ; })) {
			install.fileUses.push_back(
				{servicesSection, L"NamedServiceAssociationNotAssessed", {}}) ;
		}
	}

	const bool nullObserved = std::ranges::any_of( install.services, []( const auto &service) {
		return service.serviceName.empty() && service.flags.has_value() && *service.flags == 2U ;
	}) ; // 構造観測であり、全file不在の認証ではない。
	const bool dependencies = std::ranges::any_of( inventory.effects, []( const auto &effect) {
		return effect.kind == OfficialInfInstallEffectKind::EXPLICIT_DEPENDENCY ;
	}) ; // 同節の依存存在だけを観測する。
	install.contentKind =
		nullObserved && (!install.fileUses.empty() || dependencies)
			? MaintenanceInfContentKind::MIXED
		: nullObserved && install.parser.state == MaintenanceInspectionState::PASSED
			? MaintenanceInfContentKind::NULL_DRIVER
		: !install.fileUses.empty() ? MaintenanceInfContentKind::PACKAGE_FILES
									: MaintenanceInfContentKind::UNKNOWN ;
	budget.effects += inventory.effects.size() ;
	budget.references += inventory.references.size() ;
	budget.services += install.services.size() ;
	budget.issues += install.issues.size() ;
	budget.fileUses += install.fileUses.size() ;
	budget.coverageGaps += inventory.coverageGaps.size() ;
	return budget.effects > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
				   budget.references > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
				   budget.services > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
				   budget.issues > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
				   budget.fileUses > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
				   budget.coverageGaps > MAXIMUM_INSTALL_INVENTORY_ITEMS
			   ? nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW)
			   : 0 ;
}

} // namespace

/** @see src/platform/official_driver_package.h 宣言側の契約を正本とする。 */
NativeError inspectMaintenanceInfStructure( const OfficialDownloadWorkspace		  &workspace,
										   const std::span<const OfficialZipEntry> entries,
										   const std::wstring_view				   infRelativePath,
										   const OfficialInfInspectionPolicy	  &policy,
										   MaintenanceInfStructure				  &structure)
{
	structure = {} ;
	try {
		const std::wstring path = workspace.path( infRelativePath) ;	// 元INFの保護された読取位置。
		const auto entry = std::ranges::find_if( entries, [infRelativePath]( const auto &item) {
			return stringsEqual( item.relativePath, infRelativePath) ;
		}) ; // 固定entryとの一意結合。
		const bool invalidProvider = policy.acceptAnyProvider
										 ? !policy.acceptedProviders.empty()
										 : policy.acceptedProviders.empty() ;	// 矛盾policyを拒否。
		// 一意の最大4 MiB INFと既存内容policyの有限範囲だけを受理する。
		if( path.empty() || entries.empty() || entries.size() > 32'768U || entry == entries.end() ||
		   lowerExtension( infRelativePath) != L".inf" || entry->uncompressedSize == 0U ||
		   entry->uncompressedSize > 4U * 1024U * 1024U || policy.maximumHardwareIds == 0U ||
		   policy.maximumHardwareIds > 4096U || policy.maximumSourceFiles == 0U ||
		   policy.maximumSourceFiles > 8192U || policy.acceptedClasses.empty() ||
		   policy.acceptedSignatures.empty() || invalidProvider ||
		   std::ranges::count_if( entries, [infRelativePath]( const auto &item) {
			   return stringsEqual( item.relativePath, infRelativePath) ;
		   }) != 1) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		NativeError error = verifyOfficialFileMetadata(
			path, {entry->uncompressedSize, entry->sha256}) ;	// 元byte拘束。
		// 不一致入力から部分構造を返さない。
		if( error != 0) {
			return error ;
		}

		MaintenanceInfStructure inspected ;	// 全体成功時だけ出力へ移す保守専用型。
		inspected.infRelativePath = infRelativePath ;
		error					  = computeFileSha256( path, inspected.infSha256) ;
		// 元hashを固定できない場合は構造観測へ進まない。
		if( error != 0) {
			return error ;
		}

		const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  nullptr)) ;	// 読取handleはscopeが単独所有。
		// 全体構文を開けない入力は空結果で診断値だけを返す。
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		std::wstring signature ;	// INF構文識別子。CAT暗号署名とは別。
		error = readInfDirective( inf.get(), L"Version", L"Signature", 1U, signature) ;
		// 未取得または内容policy外の構文識別子を補正しない。
		if( error != 0 || !isAllowedValue( signature, policy.acceptedSignatures)) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		error = readInfDirective( inf.get(), L"Version", L"Class", 1U, inspected.className) ;
		// 必須Classの読取不能は全体失敗、未知Classの意味は後で個別未対応へ分離する。
		if( error != 0) {
			return error ;
		}

		error = readInfDirective( inf.get(), L"Version", L"Provider", 1U, inspected.providerName) ;
		// Provider表示名を署名者や公式由来の証拠へ変換しない。
		if( error != 0 || (!policy.acceptAnyProvider &&
						  !isAllowedValue( inspected.providerName, policy.acceptedProviders))) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		error = readInfDirective( inf.get(), L"Version", L"DriverVer", 1U, inspected.driverDate) ;
		// 必須日付の読取不能を欠損の正常値へ変換しない。
		if( error != 0) {
			return error ;
		}

		error = readInfDirective( inf.get(), L"Version", L"DriverVer", 2U, inspected.driverVersion) ;
		// Versionを推測した候補identityへ使用しない。
		if( error != 0) {
			return error ;
		}

		std::wstring catalog ;	// 既存CAT helperが返した現在architecture用file名。
		error = readCatalogFile( inf.get(), catalog) ;
		// Root CATの必須宣言をnull構造でも省略しない。
		if( error != 0) {
			return error ;
		}

		const std::size_t separator =
			// 元INFの安全な親区切り。
			infRelativePath.find_last_of( L'\\') ;
		const std::wstring_view parent =
			separator == std::wstring_view::npos
				? std::wstring_view{}
				: infRelativePath.substr( 0U, separator) ;	// Package内親位置。
		inspected.catalogRelativePath = joinRelativePath( parent, catalog) ;
		// CAT位置は固定entryとの存在だけを確認し、署名成功としない。
		if( workspace.path( inspected.catalogRelativePath).empty() ||
		   !containsEntry( entries, inspected.catalogRelativePath)) {
			return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
		}

		MaintenanceStructureBudget budget ;	// 全現在OS選択に共通の有限予算。
		std::vector<std::wstring>  names ;	// Modelsから一度だけ集める全一意導入名。
		error = collectMaintenanceInstallNames( inf.get(), budget, names) ;
		// 全選択の取得失敗を先頭選択だけの成功へ変換しない。
		if( error != 0) {
			return error ;
		}

		error = collectHardwareIds( inf.get(), policy.maximumHardwareIds, inspected.hardwareIds) ;
		// IDは既存の現在OS／x64 helperで取得し、実device適合を推測しない。
		if( error != 0) {
			return error ;
		}

		LONG versionCount{} ;	// Version節の確定行数。
		error = maintenanceLineCount( inf.get(), L"Version", versionCount) ;
		// 必須Versionの不在・容量・API失敗を正常な終端へ変換しない。
		if( error != 0 || versionCount <= 0 || versionCount > 4096L) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// 選択queue外のVersionも全行予算へ含め、LayoutFileを見落とさない。
		for( LONG row = 0L; row < versionCount; ++row) {
			INFCONTEXT version{} ;	// Versionの現在行。
			error = maintenanceLineAt( inf.get(), L"Version", row, version) ;
			// 全Version行が読めなければ部分観測を返さない。
			if( error != 0) {
				return error ;
			}

			// Versionの過大入力を部分走査に切り詰めない。
			if( ++budget.lines > MAXIMUM_INSTALL_INVENTORY_LINES) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			std::wstring key ;	// この行のVersion directive。
			error = readMaintenanceField( version, 0U, key) ;
			// Version行の読取不能を見逃さない。
			if( error != 0 || SetupGetFieldCount( &version) > MAXIMUM_INSTALL_INVENTORY_FIELDS) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			// LayoutFileの参照を名前だけでinbox署名済みへ認定しない。
			if( stringsEqual( key, L"LayoutFile")) {
				// 明示された各参照を未検査用途として保持する。
				for( DWORD field = 1U; field <= SetupGetFieldCount( &version); ++field) {
					std::wstring target ;	// LayoutFileの原明示参照。
					error = readMaintenanceField( version, field, target) ;
					// 読取不能参照を空用途へ変換しない。
					if( error != 0) {
						return error ;
					}

					inspected.fileUses.push_back( {L"Version", key, std::move( target)}) ;
					// Versionの多値参照も保持量上限を回避させない。
					if( inspected.fileUses.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS) {
						return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
					}
				}
			}
		}

		const wchar_t *sourceSection = L"SourceDisksFiles.amd64" ;	// 現architectureを先に観測する。
		LONG		   sourceCount{} ;								// 不在と空節を区別。
		error = maintenanceLineCount( inf.get(), sourceSection, sourceCount) ;
		// source API失敗をsource不在へ変換しない。
		if( error != 0) {
			return error ;
		}

		// Architecture固有節がない場合だけ共通節を観測する。
		if( sourceCount < 0) {
			sourceSection = L"SourceDisksFiles" ;
			error		  = maintenanceLineCount( inf.get(), sourceSection, sourceCount) ;
			// 共通sourceのAPI失敗も不在へ弱めない。
			if( error != 0) {
				return error ;
			}
		}

		inspected.sourceSectionPresent = sourceCount >= 0 ;
		// 非空source宣言は構造として読み、位置解決は後続の閉包検査へ残す。
		if( sourceCount > 0) {
			// 過大source節を部分空集合へ変換しない。
			if( static_cast<std::size_t>( sourceCount) >
			   MAXIMUM_INSTALL_INVENTORY_LINES - budget.lines) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			// 全source宣言を有限に観測する。SYS不在だけでnullやinboxを認定しない。
			for( LONG row = 0L; row < sourceCount; ++row) {
				INFCONTEXT source{} ;	// Source宣言の現在行。
				error = maintenanceLineAt( inf.get(), sourceSection, row, source) ;
				// source行の途中失敗で空閉包を作らない。
				if( error != 0) {
					return error ;
				}

				++budget.lines ;
				std::wstring name ;	// 参照宣言のfile名。
				error = readInfField( source, 0U, name) ;
				// File名を安全なpackage相対位置に限定し、実byte不在はまだ評価しない。
				if( error != 0 || name.find_first_of( L"/\\") != std::wstring::npos ||
				   workspace.path( joinRelativePath( parent, name)).empty()) {
					return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				// Source集合がpolicy上限を超える場合は元宣言を切り捨てない。
				if( appendUnique( inspected.sourceFileNames, std::move( name)) &&
				   inspected.sourceFileNames.size() > policy.maximumSourceFiles) {
					return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
				}
			}
		}

		budget.fileUses	 = inspected.fileUses.size() ;
		inspected.parser = {MaintenanceInspectionState::PASSED, 0} ;
		// 現在OSの全一意導入名を分母へ残し、先頭モデルだけでINF全体を分類しない。
		for( const std::wstring &name : names) {
			MaintenanceInfInstallStructure install ;	// 一選択の所有観測。
			install.inventory.infRelativePath	 = inspected.infRelativePath ;
			install.inventory.infSha256			 = inspected.infSha256 ;
			install.inventory.baseInstallSection = name ;
			error = resolveActualInstallInventorySection( inf.get(), name,
														 install.inventory.selectedInstallSection) ;
			// 実在選択の欠落は不正構造の個別行として残し、他の選択を削除しない。
			if( error != 0) {
				install.parser = {MaintenanceInspectionState::FAILED, error} ;
			} else {
				error = inspectMaintenanceInstallStructure( inf.get(), workspace, entries, parent,
														   budget, install) ;
				// 容量・全体読取・不正参照の失敗では部分構造を破棄する。
				if( error != 0) {
					return error ;
				}
			}

			// 未知Classは具体的理由を各選択へ保持し、導入Class表を広げない。
			if( !isAllowedValue( inspected.className, policy.acceptedClasses)) {
				addMaintenanceIssue( install, L"Version", L"Class",
									MaintenanceInfStructureReason::CLASS_NOT_SUPPORTED,
									{MaintenanceInspectionState::UNSUPPORTED,
									 nativeErrorFromWin32( ERROR_NOT_SUPPORTED)}) ;
				// Class診断も全INFの独立保持予算へ加える。
				if( ++budget.issues > MAXIMUM_INSTALL_INVENTORY_ITEMS) {
					return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
				}
			}

			// Source宣言を持つnullはfile構造との併存へ残し、無参照としない。
			if( !inspected.sourceFileNames.empty() || !inspected.fileUses.empty()) {
				install.contentKind =
					install.contentKind == MaintenanceInfContentKind::NULL_DRIVER ||
							install.contentKind == MaintenanceInfContentKind::MIXED
						? MaintenanceInfContentKind::MIXED
						: MaintenanceInfContentKind::PACKAGE_FILES ;
			}

			mergeMaintenanceFinding( inspected.parser, install.parser) ;
			// 異なる選択構造をMIXEDとし、UNKNOWNを先頭成功で隠さない。
			if( inspected.installs.empty()) {
				inspected.contentKind = install.contentKind ;
			}
			// 後続の異なる構造も分母へ残し、先頭構造で全INFを確定しない。
			else if( inspected.contentKind != install.contentKind) {
				inspected.contentKind = MaintenanceInfContentKind::MIXED ;
			}

			// 明示依存の各宣言を数え、由来・byte・署名・全到達節は未照会に残す。
			for( const auto &reference : install.inventory.references) {
				// 同節Include／Needs／AddComponentの明示辺だけを依存summaryへ射影する。
				if( reference.kind == OfficialInfInstallReferenceKind::INCLUDE_INF ||
				   stringsEqual( reference.directive, L"Needs") ||
				   stringsEqual( reference.directive, L"AddComponent")) {
					++inspected.dependency.observedReferenceCount ;
					inspected.dependency.state = MaintenanceInfDependencyState::OBSERVED ;
				}
			}

			inspected.installs.push_back( std::move( install)) ;
		}

		error = verifyOfficialFileMetadata( path, {entry->uncompressedSize, inspected.infSha256}) ;
		// 元byte改変と全体失敗では独立署名未検査の部分構造を公開しない。
		if( error != 0) {
			return error ;
		}

		structure = std::move( inspected) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

/** @see src/platform/official_driver_package.h 宣言側の契約を正本とする。 */
NativeError inspectOfficialInfInstallInventory( const OfficialDownloadWorkspace		  &workspace,
											   const std::span<const OfficialZipEntry> entries,
											   const std::wstring_view		infRelativePath,
											   const std::wstring_view		baseInstallSection,
											   OfficialInfInstallInventory &inventory)
{
	inventory = {} ;
	try {
		const std::wstring path = workspace.path( infRelativePath) ;	// 保護領域内だけのINF読取位置。
		const auto		   entry =
			std::ranges::find_if( entries, [infRelativePath]( const OfficialZipEntry &item) {
				return stringsEqual( item.relativePath, infRelativePath) ;
			}) ; // 呼出し元の有限inventoryと対象INFを結合する。
		// 一意の有限INFとModels用の導入名だけを受け取る。
		if( path.empty() || entries.size() > 32'768U || entry == entries.end() ||
		   entry->uncompressedSize == 0U || entry->uncompressedSize > 4U * 1024U * 1024U ||
		   lowerExtension( infRelativePath) != L".inf" ||
		   !validInstallInventorySectionName( baseInstallSection) ||
		   std::ranges::count_if( entries, [infRelativePath]( const OfficialZipEntry &item) {
			   return stringsEqual( item.relativePath, infRelativePath) ;
		   }) != 1) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		NativeError error = verifyOfficialFileMetadata(
			path, {entry->uncompressedSize, entry->sha256}) ;	// 実size一致を先に要求する。
		// 入力metadata不一致のbyteを解析しない。
		if( error != 0) {
			return error ;
		}

		OfficialInfInstallInventory inspected ;	// 全成功時だけ出力へ移す独立した観測型。
		error = computeFileSha256( path, inspected.infSha256) ;
		// CAT署名ではない元byte結合にも失敗した場合は停止する。
		if( error != 0) {
			return error ;
		}

		const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  nullptr)) ;	// 無cacheの読取専用handle。
		// INF構文読取失敗を元の診断値で返す。
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		std::wstring signature ;	// 構文識別子だけ。暗号署名ではない。
		error = readInfDirective( inf.get(), L"Version", L"Signature", 1U, signature) ;
		// 標準二構文以外の値を正規化して受理しない。
		if( error != 0 ||
		   (!stringsEqual( signature, L"$Windows NT$") && !stringsEqual( signature, L"$Chicago$"))) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		inspected.infRelativePath	 = infRelativePath ;
		inspected.baseInstallSection = baseInstallSection ;
		error = selectInstallInventorySection( inf.get(), inspected.baseInstallSection,
											  inspected.selectedInstallSection) ;
		// 未登録・未実在・対象外を空の正常結果へ変換しない。
		if( error != 0) {
			return error ;
		}

		std::vector<InstallInventorySection> pending{
			{inspected.selectedInstallSection,
			 InstallInventorySectionKind::DIRECTIVES}} ;	// 一度だけ処理する到達graph。
		constexpr std::array<std::wstring_view, 9>
			suffixes{L".HW",
					 L".Services",
					 L".CoInstallers",
					 L".Interfaces",
					 L".Components",
					 L".Software",
					 L".Wdf",
					 L".Events",
					 L".LogConfigOverride"} ;	// 今回解釈する既知の付随節。
		// 選択DDInstallと完全一致する付随節だけを走査する。
		for( const auto suffix : suffixes) {
			const std::wstring name =
				inspected.selectedInstallSection + std::wstring( suffix) ;	// 実sectionの付随名。
			const LONG lineCount =
				// 不在と空節を区別する。
				SetupGetLineCountW( inf.get(), name.c_str()) ;
			// 不在の任意付随節は参照欠落ではなく対象なし。
			if( lineCount < 0) {
				continue ;
			}

			pending.push_back( {name, InstallInventorySectionKind::DIRECTIVES}) ;
			// 非空CoInstaller節の宣言は作用なしとしない。
			if( stringsEqual( suffix, L".CoInstallers") && lineCount > 0) {
				inspected.effects.push_back(
					{name, L"CoInstallers", OfficialInfInstallEffectKind::COINSTALLER}) ;
			}
		}

		const std::size_t separator = infRelativePath.find_last_of( L'\\') ;	// 安全なINF親の区切り。
		const std::wstring_view parent =
			separator == std::wstring_view::npos
				? std::wstring_view{}
				: infRelativePath.substr( 0, separator) ;	// 元INFと同じ親以下だけのfile参照。
		// 動的に増える有限queueを順に処理し、循環でも既存節を再走査しない。
		for( std::size_t index = 0; index < pending.size(); ++index) {
			const InstallInventorySection current =
				pending[index] ;	// Queue再確保の影響を受けない所有copy。
			inspected.visitedSections.push_back( current.name) ;
			const LONG lineCount =
				// 現在節の全行数。
				SetupGetLineCountW( inf.get(), current.name.c_str()) ;
			// 累積上限を先に確認し、過大節を部分列挙しない。
			if( lineCount < 0 || static_cast<std::size_t>( lineCount) >
									MAXIMUM_INSTALL_INVENTORY_LINES - inspected.scannedLines) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			INFCONTEXT line{} ;	// 現在節の行context。
			// 明示空節には行読取が不要だが、非空節の取得失敗は拒否する。
			if( lineCount == 0) {
				continue ;
			}

			// 非空data・registry本文を完全解釈したという誤認を防ぐ。
			if( current.kind != InstallInventorySectionKind::DIRECTIVES) {
				inspected.coverageGaps.push_back(
					{current.name,
					 {},
					 current.kind == InstallInventorySectionKind::REGISTRY
						 ? OfficialInfInstallCoverageKind::REGISTRY_SCOPE_NOT_ASSESSED
						 : OfficialInfInstallCoverageKind::DATA_ROWS_NOT_INTERPRETED}) ;
			}

			// 不正な先頭行を読み飛ばさない。
			if( SetupFindFirstLineW( inf.get(), current.name.c_str(), nullptr, &line) == FALSE) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			// 観測した全行を有限fieldへ読み、途中終了で成功にしない。
			for( LONG row = 0; row < lineCount; ++row) {
				++inspected.scannedLines ;
				const DWORD fields = SetupGetFieldCount( &line) ;	// Keyを除く値数。
				// 過大field集合を走査しない。
				if( fields > MAXIMUM_INSTALL_INVENTORY_FIELDS) {
					return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
				}

				std::vector<std::wstring> values ;	// この行だけの値。結果へ本文を保持しない。
				// 空値を含め、全fieldの上限を確認する。
				for( DWORD field = 1U; field <= fields; ++field) {
					std::wstring value ;	// 個別の有限受信値。
					error = readInstallInventoryField( line, field, value) ;
					// 過長・展開失敗を未知の正常値として隠さない。
					if( error != 0) {
						return error ;
					}

					values.push_back( std::move( value)) ;
				}

				// Registry行の宣言種類だけを観測し、値やcommand本文は保持しない。
				if( current.kind == InstallInventorySectionKind::REGISTRY) {
					// Registry行のroot・subkeyが欠ける不正入力を拒否する。
					if( values.size() < 2U) {
						return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
					}

					// CoInstaller値名を普通のregistry宣言へ読み替えない。
					if( values.size() >= 3U && stringsEqual( values[2], L"CoInstallers32")) {
						inspected.effects.push_back( {current.name, L"CoInstallers32",
													 OfficialInfInstallEffectKind::COINSTALLER}) ;
					}

					std::wstring subkey = values[1] ;	// 比較中だけ保持するregistry位置。
					std::transform( subkey.begin(), subkey.end(), subkey.begin(),
								   []( wchar_t character) {
									   return character >= L'A' && character <= L'Z'
												  ? static_cast<wchar_t>( character - L'A' + L'a')
												  : character ;
								   }) ; // ASCIIの既知registry位置だけを比較する。
					// 自動起動位置の宣言は実行の観測ではなく独立の要確認種類とする。
					if( subkey.find( L"\\currentversion\\run") != std::wstring::npos) {
						inspected.effects.push_back(
							{current.name, L"RegistryAutorun",
							 OfficialInfInstallEffectKind::REGISTRY_AUTORUN}) ;
					}
				}
				// 処理節だけをdirectiveとして解釈し、不透明data行へ同じ規則を適用しない。
				else if( current.kind == InstallInventorySectionKind::DIRECTIVES) {
					std::wstring key ;	// この行のdirective名だけを保持する。
					error = readInstallInventoryField( line, 0U, key) ;
					// Keyを持たない不正行を既知directiveへ読み替えない。
					if( error != 0 || key.empty()) {
						return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
					}

					inspected.effects.push_back(
						{current.name, key, installInventoryEffectKind( key)}) ;
					const auto gap =
						// 一宣言の解析不足。
						installInventoryCoverageKind( key, values) ;
					// 本文を保存せず、不足を元節とdirectiveへ結合する。
					if( gap.has_value()) {
						inspected.coverageGaps.push_back( {current.name, key, *gap}) ;
					}

					InstallInventorySectionKind targetKind =
						InstallInventorySectionKind::DATA_ROWS ;	// Data節は再解釈しない。
					OfficialInfInstallReferenceKind referenceKind =
						OfficialInfInstallReferenceKind::LOCAL_SECTION ;	// 同INF参照が既定。
					std::size_t start{} ;									// 参照値の先頭index。後で処理するdirectiveだけが有効。
					bool		references = false ;						// このdirectiveに既知の参照形式がある場合true。
					// Registry節はdirective節と区別して辿る。
					if( stringsEqual( key, L"AddReg") || stringsEqual( key, L"DelReg")) {
						targetKind = InstallInventorySectionKind::REGISTRY ;
						references = true ;
					}
					// 別INFの存在だけを記録し、同じINF内の処理節として開かない。
					else if( stringsEqual( key, L"Include") || stringsEqual( key, L"CopyINF")) {
						referenceKind = stringsEqual( key, L"Include")
											? OfficialInfInstallReferenceKind::INCLUDE_INF
											: OfficialInfInstallReferenceKind::COPY_INF ;
						references	  = true ;
					}
					// Needsのローカル存在と外部依存の未確認を分離する。
					else if( stringsEqual( key, L"Needs")) {
						targetKind = InstallInventorySectionKind::DIRECTIVES ;
						references = true ;
					}
					// Service等の指定第3 fieldだけを処理節参照にする。
					else if( stringsEqual( key, L"AddService") ||
							stringsEqual( key, L"AddInterface") ||
							stringsEqual( key, L"AddComponent") ||
							stringsEqual( key, L"AddSoftware")) {
						targetKind = InstallInventorySectionKind::DIRECTIVES ;
						start	   = 2U ;
						references = true ;
					}
					// WDF宣言では指定第2 fieldだけを処理節参照にする。
					else if( stringsEqual( key, L"KmdfService") ||
							stringsEqual( key, L"UmdfService")) {
						targetKind = InstallInventorySectionKind::DIRECTIVES ;
						start	   = 1U ;
						references = true ;
					}
					// File・登録・commandのdata節は有限に読むが本文を解釈・保持しない。
					else if( stringsEqual( key, L"CopyFiles") || stringsEqual( key, L"DelFiles") ||
							stringsEqual( key, L"RenFiles") || stringsEqual( key, L"BitReg") ||
							stringsEqual( key, L"RegisterDlls") ||
							stringsEqual( key, L"UnregisterDlls") ||
							stringsEqual( key, L"RunPreSetupCommands") ||
							stringsEqual( key, L"RunPostSetupCommands")) {
						references = true ;
					}

					// 必須参照fieldがない場合は不正宣言として拒否する。
					if( references && values.size() <= start) {
						return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
					}

					// 参照形式が既知のdirectiveだけを有限に辿る。
					for( std::size_t field = start; references && field < values.size(); ++field) {
						std::wstring target = values[field] ;	// 個別の参照名だけを結果へ保持する。
						OfficialInfInstallReferenceKind kind =
							referenceKind ;	// 直接fileである場合のみ変更する。
						// CopyFilesの直接file記法はsectionではない。
						if( stringsEqual( key, L"CopyFiles") && target.starts_with( L"@")) {
							target.erase( 0U, 1U) ;
							kind = OfficialInfInstallReferenceKind::DIRECT_FILE ;
						}

						bool present = false ;	// ローカル存在だけで、実byte・依存充足ではない。
						// File参照はpackage境界へ結合し、別INFを開かない。
						if( kind != OfficialInfInstallReferenceKind::LOCAL_SECTION) {
							const std::wstring_view child =
								// 元の参照名を借用する。
								stripReferenceCurrentDirectory( target) ;
							// 空参照をINF親directoryの参照として保持しない。
							if( child.empty()) {
								return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
							}

							target = joinRelativePath( parent, child) ;
							// 不正pathとINFではないInclude／CopyINFを拒否する。
							if( workspace.path( target).empty() ||
							   (kind != OfficialInfInstallReferenceKind::DIRECT_FILE &&
								lowerExtension( target) != L".inf")) {
								return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
							}

							present = containsEntry( entries, target) ;
						} else {
							// 過長・path的参照をsection名として採用しない。
							if( !validInstallInventorySectionName( target)) {
								return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
							}

							present = SetupGetLineCountW( inf.get(), target.c_str()) >= 0 ;
							// 欠落参照は保持するが、他のsectionから推測補完しない。
							if( present) {
								error = queueInstallInventorySection( pending, target, targetKind) ;
								// Queue容量と矛盾した節解釈は部分結果を破棄する。
								if( error != 0) {
									return error ;
								}
							}
						}

						inspected.references.push_back( {current.name, key, target, kind, present}) ;
						// 確保量を固定上限へ拘束する。
						if( inspected.references.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS) {
							return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
						}

						// Service等は指定field一つだけがsection参照で、後続flagは辿らない。
						if( start > 0U) {
							break ;
						}
					}
				}

				// Registry検出を含む全宣言数を固定上限へ拘束する。
				if( inspected.effects.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
				   inspected.coverageGaps.size() > MAXIMUM_INSTALL_INVENTORY_LINES) {
					return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
				}

				// 確定行数の途中で走査が終わった場合は成功にしない。
				if( row + 1 < lineCount && SetupFindNextLine( &line, &line) == FALSE) {
					return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}
			}
		}

		error = verifyOfficialFileMetadata( path, {entry->uncompressedSize, inspected.infSha256}) ;
		// 解析後の元byte不一致では部分観測を公開しない。
		if( error != 0) {
			return error ;
		}

		inventory = std::move( inspected) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/** @see src/platform/official_driver_package.h 宣言側の契約を正本とする。 */
//------------------------------------------------------------------------------
NativeError inspectOfficialInfReferences( const OfficialDownloadWorkspace		&workspace,
										 const std::span<const OfficialZipEntry> entries,
										 const std::wstring_view				 infRelativePath,
										 OfficialInfReferenceInventory			&inventory)
{
	inventory = {} ;
	OfficialInfReferenceInventory inspected ;	// 非合格の保守参照集合。
	// 失敗時は参照集合を公開せず、到達段階だけを残す同期callback。
	const auto					  fail = [&inventory, &inspected]( const NativeError error) {
		   inventory	   = {} ;
		   inventory.stage = inspected.stage ;
		   return error ;
	} ;
	try {
		const std::wstring absolutePath = workspace.path( infRelativePath) ;	// 保護領域内の読取位置。
		const auto		   original =
			std::ranges::find_if( entries, [infRelativePath]( const OfficialZipEntry &entry) {
				return stringsEqual( entry.relativePath, infRelativePath) ;
			}) ; // 元inventoryの同一INFだけを対象にする。
		// 入力境界とINF上限を検証する。
		if( absolutePath.empty() || entries.size() > 32'768U || original == entries.end() ||
		   original->uncompressedSize > 4U * 1024U * 1024U ||
		   lowerExtension( infRelativePath) != L".inf") {
			return fail( static_cast<NativeError>( E_INVALIDARG)) ;
		}

		const UniqueInf inf( SetupOpenInfFileW( absolutePath.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  nullptr)) ;	// 実行せずに構文だけを読む。
		// 構文読取失敗をそのまま残す。
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return fail( nativeErrorFromWin32( GetLastError())) ;
		}

		inspected.stage = OfficialInfReferenceStage::VERSION ;
		std::wstring signature ;	// Version節の宣言値。CAT署名ではない。
		NativeError	 error =
			// 読取結果。
			readInfDirective( inf.get(), L"Version", L"Signature", 1, signature) ;
		// 未知signatureを推測しない。
		if( error != 0 ||
		   (!stringsEqual( signature, L"$Windows NT$") && !stringsEqual( signature, L"$Chicago$"))) {
			return fail( error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA)) ;
		}

		error = readInfDirective( inf.get(), L"Version", L"Class", 1, inspected.className) ;
		// Class欠落を正常な未知classへ変換しない。
		if( error != 0) {
			return fail( error) ;
		}

		std::wstring catalog ;	// Directoryを含まないCAT名。
		error = readCatalogFile( inf.get(), catalog) ;
		// 対応CATを推測しない。
		if( error != 0) {
			return fail( error) ;
		}

		const std::size_t		slash = infRelativePath.find_last_of( L"/\\") ;	// 元INFの親区切り。
		const std::wstring_view parent =
			slash == std::wstring_view::npos
				? std::wstring_view{}
				: infRelativePath.substr( 0, slash) ;	// 安全な親相対位置。
		inspected.infRelativePath	  = infRelativePath ;
		inspected.catalogRelativePath = joinRelativePath( parent, catalog) ;
		// 元CAT metadataを必須にする。
		if( workspace.path( inspected.catalogRelativePath).empty() ||
		   !containsEntry( entries, inspected.catalogRelativePath)) {
			return fail( nativeErrorFromWin32( ERROR_FILE_NOT_FOUND)) ;
		}

		inspected.stage = OfficialInfReferenceStage::SOURCES ;
		constexpr std::array SOURCE_SECTIONS{L"SourceDisksFiles.amd64",
											 L"SourceDisksFiles"} ;	// 保守用和集合。
		// 共通節の追加fileも省略しない。
		for( const wchar_t *const section : SOURCE_SECTIONS) {
			const LONG lineCount = SetupGetLineCountW( inf.get(), section) ;	// 節の存在と行数。
			// 重複行を含むsource節そのものにも有限上限を設ける。
			if( lineCount > 8'192L) {
				return fail( nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW)) ;
			}

			// 不在以外のAPI失敗を拒否する。
			if( lineCount == -1 && GetLastError() != ERROR_SECTION_NOT_FOUND) {
				return fail( nativeErrorFromWin32( GetLastError())) ;
			}

			// 存在しない節と空節はsource参照を持たない。
			if( lineCount <= 0) {
				continue ;
			}

			std::vector<std::wstring> sectionFiles ;	// 現在節だけの有限参照集合。
			error = collectSourceFiles( inf.get(), workspace, entries, parent, 8'192U, false,
									   sectionFiles, section) ;
			// 欠落sourceを部分棚卸し合格へ変換しない。
			if( error != 0) {
				return fail( error) ;
			}

			// architecture優先解決した重複参照を一意にする。
			for( std::wstring &path : sectionFiles) {
				// 和集合の上限も維持する。
				if( appendUnique( inspected.sourceFiles, std::move( path)) &&
				   inspected.sourceFiles.size() > 8'192U) {
					return fail( nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW)) ;
				}
			}
		}

		inspected.stage = OfficialInfReferenceStage::DEPENDENCIES ;
		std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U>
			 sectionBuffer{} ;	// 全section名受信領域。
		bool ended{} ;			// SetupAPIの正常終端を確認した場合だけtrue。
		// 全sectionを有限走査する。
		for( std::size_t index = 0; index < MAXIMUM_INF_SECTIONS; ++index) {
			// 正常終端と失敗を区別する。
			if( SetupEnumInfSectionsW( inf.get(), static_cast<UINT>( index), sectionBuffer.data(),
									 static_cast<UINT>( sectionBuffer.size()), nullptr) == FALSE) {
				// 部分列挙を合格にしない。
				if( GetLastError() != ERROR_NO_MORE_ITEMS) {
					return fail( nativeErrorFromWin32( GetLastError())) ;
				}

				ended = true ;
				break ;
			}

			INFCONTEXT line{} ;	// 現在sectionのline。
			// 空節を飛ばす。
			if( SetupFindFirstLineW( inf.get(), sectionBuffer.data(), nullptr, &line) == FALSE) {
				continue ;
			}

			// 生line本文やPnP IDを出力せず、依存keyだけを読む。
			do {
				std::wstring key ;				// 現在lineのkey。Keyなし行は対象外。
				DWORD		 keyCharacters{} ;	// Keyなし行と過長keyを分ける必要文字数。
				SetLastError( ERROR_SUCCESS) ;
				// Keyなしの一覧行を依存directiveとして解析しない。
				if( SetupGetStringFieldW( &line, 0, nullptr, 0, &keyCharacters) == FALSE &&
				   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
					continue ;
				}

				// 空の先頭fieldはkeyなし行であり、CopyINFの空valueとは区別する。
				if( keyCharacters <= 1U) {
					continue ;
				}

				// 過長keyをkeyなし行へ変換しない。
				if( keyCharacters > MAXIMUM_INF_FIELD_CHARACTERS) {
					return fail( nativeErrorFromWin32( ERROR_INVALID_DATA)) ;
				}

				const NativeError keyError = readInfField( line, 0, key) ;	// 有限keyの取得結果。
				// 確保失敗や有限keyの受信失敗を省略しない。
				if( keyError != 0) {
					return fail( keyError) ;
				}

				// 存在だけを保持し、依存充足としない。
				if( stringsEqual( key, L"Include") || stringsEqual( key, L"Needs") ||
				   stringsEqual( key, L"AddComponent")) {
					inspected.hasExternalDependencies = true ;
				}

				// CopyINF以外の文字列をpathへ変換しない。
				if( !stringsEqual( key, L"CopyINF")) {
					continue ;
				}

				const DWORD fields = SetupGetFieldCount( &line) ;	// CopyINFの一行参照数。
				// 無限fieldや空依存を拒否する。
				if( fields == 0 || fields > 1'024U) {
					return fail( nativeErrorFromWin32( ERROR_INVALID_DATA)) ;
				}

				// Strings展開済みの各参照を検査する。
				for( DWORD field = 1; field <= fields; ++field) {
					std::wstring child ;	// 子INFへの相対参照。
					error = readInfField( line, field, child) ;
					// 保守参照だけの先頭現在directoryを解決し、他の危険要素は残す。
					if( error == 0) {
						child = std::wstring( stripReferenceCurrentDirectory( child)) ;
					}

					// 未展開・絶対・非INFを拒否する。
					if( error != 0 || child.find( L'%') != std::wstring::npos || child.empty() ||
					   child.front() == L'\\' || child.front() == L'/' ||
					   lowerExtension( child) != L".inf") {
						return fail( error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA)) ;
					}

					std::wstring relative = joinRelativePath( parent, child) ;	// 同じ親以下の参照。
					// traversal等を既存workspace境界で拒否する。
					if( workspace.path( relative).empty()) {
						return fail( nativeErrorFromWin32( ERROR_INVALID_DATA)) ;
					}

					// 全section合計の参照数を制限する。
					if( appendUnique( inspected.copyInfPaths, std::move( relative)) &&
					   inspected.copyInfPaths.size() > 1'024U) {
						return fail( nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW)) ;
					}
				}
			} while( SetupFindNextLine( &line, &line) != FALSE) ;
		}

		// Section上限到達を正常終端へ変換しない。
		if( !ended) {
			return fail( nativeErrorFromWin32( ERROR_TOO_MANY_NAMES)) ;
		}

		bool actionDependencies{} ;	// 既存導入検査の中途観測は棚卸しの全走査結果に代用しない。
		inspected.installActionsError =
			validateInfInstallActions( inf.get(), true, actionDependencies) ;
		inspected.stage = OfficialInfReferenceStage::INVENTORIED ;
		inventory		= std::move( inspected) ;
		return 0 ;
	} catch( const std::bad_alloc &) { // 確保失敗時も部分参照を公開しない。
		return fail( static_cast<NativeError>( E_OUTOFMEMORY)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_driver_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
namespace {
/**
 * @brief 同service-install節の一意な必須一値を既存INF readerで読みます。
 * @param[in] inf 同期中だけ借用する元INF handleです。
 * @param[in] section named service-install節の実名です。
 * @param[in] key 同節の必須directiveです。
 * @param[out] value 成功時だけ元一値を保持し、失敗時は空です。
 * @return 読取成功0、欠損・多値・重複の元HRESULTです。
 */
NativeError readRequiredServiceField( HINF inf, const std::wstring &section, const wchar_t *key,
									 std::wstring &value)
{
	value.clear() ;
	INFCONTEXT line{} ;	// 同HINFの必須行を一度だけ借用します。
	// 一意一値を持たない必須項目を先頭値で補完しません。
	if( !SetupFindFirstLineW( inf, section.c_str(), key, &line) || SetupGetFieldCount( &line) != 1U) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const auto error = readInfField( line, 1U, value) ;	// 既存の有限・展開済みfield読取です。
	INFCONTEXT duplicate{} ;							// 同keyの二行目を採用しません。
	// 相反する重複必須行から都合のよい一値を選びません。
	if( error != 0 || SetupFindNextMatchLineW( &line, key, &duplicate)) {
		value.clear() ;
		return error != 0 ? error : nativeErrorFromWin32( ERROR_DUP_NAME) ;
	}

	return 0 ;
}

/**
 * @brief 元serviceの整数一値を既存の厳密数値readerで解釈します。
 * @param[in] inf 同期中だけ借用する元INF handleです。
 * @param[in] section 元service-install節です。
 * @param[in] key 必須数値directiveです。
 * @param[out] value 成功時だけスカラー数値を確定します。
 * @return 成功0、未知文字列・複合文字列・欠損を補正しない元HRESULTです。
 */
NativeError readRequiredServiceScalar( HINF inf, const std::wstring &section, const wchar_t *key,
									  std::uint32_t &value)
{
	std::wstring text ;															// 原数値文字列の全値です。
	const auto	 error = readRequiredServiceField( inf, section, key, text) ;	// 同元一値の診断です。
	// 欠損・重複を数値0へ変換しません。
	if( error != 0) {
		return error ;
	}

	MaintenanceInfStructureReason reason{} ;							// 既存readerの診断だけを同期借用します。
	const auto parsed = parseMaintenanceFlags( text, value, reason) ;	// 全値の厳密uint32解析です。
	return parsed.state == MaintenanceInspectionState::PASSED ? 0
		   : parsed.error != 0								  ? parsed.error
							   : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
}

/**
 * @brief 必要serviceのsubdirを相対directoryの有限形式へ限定します。
 * @param[in] directory 同期比較中だけ借用する元subdirです。空はrootです。
 * @return 絶対・空要素・traversal・不正文字・末尾dot/spaceを持たない場合trueです。
 * @note 元値を正規化しません。sourceの実位置は別途workspace/memberへ照合します。
 */
[[nodiscard]] bool validRequiredServiceSubdirectory( std::wstring_view directory) noexcept
{
	// 空directoryは明示rootの正常形です。
	if( directory.empty()) {
		return true ;
	}

	std::size_t beginning{} ;	// 元要素の開始位置です。
	// 各元要素を一度ずつ検査し、不正要素または全文終端で終了します。
	while( beginning < directory.size()) {
		const auto separator = directory.find( L'\\', beginning) ;	// 元相対要素の区切りです。
		const auto ending =
			// 同要素の終端です。
			separator == directory.npos ? directory.size() : separator ;
		const auto component =
			// 補正しない原要素です。
			directory.substr( beginning, ending - beginning) ;
		// 危険な要素をWindowsのpath補正で安全な別位置へ読み替えません。
		if( component.empty() || component.size() > 255U || component == L"." ||
		   component == L".." || component.back() == L'.' || component.back() == L' ' ||
		   component.find_first_of( L"<>/%:\"|?*\t\r\n") != component.npos ||
		   std::ranges::any_of( component,
							   []( wchar_t value) { return value < L' ' || value > L'~' ; })) {
			return false ;
		}

		const auto stem =
			// 同期中だけ借用する予約名判定です。
			component.substr( 0U, component.find( L'.')) ;
		// DOS device名を通常directoryへ補正しません。
		if( stringsEqual( stem, L"CON") || stringsEqual( stem, L"PRN") || stringsEqual( stem, L"AUX") ||
		   stringsEqual( stem, L"NUL") ||
		   (stem.size() == 4U && stem[3U] >= L'1' && stem[3U] <= L'9' &&
			(stringsEqual( stem.substr( 0U, 3U), L"COM") ||
			 stringsEqual( stem.substr( 0U, 3U), L"LPT")))) {
			return false ;
		}

		// 全文終端だけを正常形として確定します。
		if( separator == directory.npos) {
			return true ;
		}

		beginning = separator + 1U ;
	}

	return false ;
}

/**
 * @brief 同INFのservice source subdirと媒体pathを共通SetupAPI readerから取得します。
 * @param[in] inf 同期中だけ借用する元INFです。
 * @param[in] executable 検査済みの同名source fileです。
 * @param[out] directory 成功時だけ元SourceDisksFiles相対directoryです。失敗時は空です。
 * @param[out] mediaDirectory 成功時だけ同元source IDの安全な媒体相対pathです。失敗時は空です。
 * @return 完全取得成功0、欠損・過長・重複・安全相対path逸脱のHRESULTです。
 * @pre 出力二つは別の格納先であり、executableともaliasしないこと。
 * @note DIRID13一致用subdirに媒体pathを混ぜません。実byteは既存内容検査が照合します。
 */
NativeError readRequiredServiceSourceDirectory( HINF inf, const std::wstring &executable,
											   std::wstring &directory,
											   std::wstring &mediaDirectory)
{
	directory.clear() ;
	mediaDirectory.clear() ;
	// 共通reader成功まで出力へ公開しないfile subdirです。
	std::wstring source ;
	std::wstring media ;															// 同source IDの完全な元媒体位置です。
	const auto error = readInfSourceDirectories( inf, executable, source, media) ;	// 原位置診断です。
	// 共通位置取得失敗の部分値をservice許可集合へ追加しません。
	if( error != 0) {
		return error ;
	}

	// 既存serviceのASCII相対segment境界を媒体とfile subdirの両方へ適用します。
	if( !validRequiredServiceSubdirectory( source) || !validRequiredServiceSubdirectory( media)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	directory	   = std::move( source) ;
	mediaDirectory = std::move( media) ;
	return 0 ;
}

/**
 * @brief 同DDInstallの明示標準DIRID同名コピーを位置付きservice sourceへ一意に結びます。
 * @param[in] inf 同期中だけ借用する元INFです。
 * @param[in] install 元Services suffixを外した実在DDInstallです。
 * @param[in] executable 同じ元ServiceBinaryの単一file名です。
 * @param[in] binary 同じ元ServiceBinaryの展開済み全値です。basenameへ切り詰めません。
 * @param[out] sourceRelative 成功時だけ元媒体path・source subdirと同名EXEを結んだ位置です。失敗時は空です。
 * @return 一意な同名コピー成功0、欠損・rename・未対応DIRID・位置不一致・曖昧・容量のHRESULTです。
 * @note コピーは実行しません。元file byte/位置/CATの確認は既存source readerとintegrity検査です。
 */
NativeError inspectRequiredServiceCopy( HINF inf, const std::wstring &install,
									   const std::wstring &executable, const std::wstring &binary,
									   std::wstring &sourceRelative)
{
	sourceRelative.clear() ;
	INFCONTEXT copy{} ;	// 同実在DDInstallの原CopyFilesです。
	// 別節や別INFのコピーからserviceの導入位置を推測しません。
	if( !SetupFindFirstLineW( inf, install.c_str(), L"CopyFiles", &copy)) {
		return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
	}

	std::size_t	 matches{} ;		// 同sourceと同DIRIDの一意コピー数です。
	std::size_t	 declarations{} ;	// 全CopyFiles宣言の共同上限です。
	std::size_t	 rows{} ;			// 到達list全体の行予算です。
	std::wstring validatedSource ;	// 全CopyFiles検査の成功まで出力へ公開しない位置です。
	// 同DDInstallの全CopyFilesを有限に読み、任意の先頭listを採用しません。
	do {
		const auto fields = SetupGetFieldCount( &copy) ;	// 全原list指定数です。
		// 過大または欠損宣言を空コピー成功にしません。
		if( ++declarations > 32U || fields == 0U || fields > 32U) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		// 各元参照の同名sourceと明示導入先を照合します。
		for( DWORD field = 1U; field <= fields; ++field) {
			std::wstring list ;										// 既存readerで展開した元参照です。
			const auto	 error = readInfField( copy, field, list) ;	// 参照の全値診断です。
			// 欠損または不正なlist名を推測参照へ変換しません。
			if( error != 0 || (!list.starts_with( L"@") && !validInstallInventorySectionName( list))) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			const bool	direct = list.starts_with( L"@") ;	// Windowsの直接source記法です。
			std::size_t copies{} ;							// この一参照内の同名コピー数です。
			// 直接コピーの元file名だけをServiceBinaryへ照合します。
			if( direct) {
				copies = stringsEqual( std::wstring_view( list).substr( 1U), executable) ? 1U : 0U ;
			} else {
				INFCONTEXT file{} ;	// 同HINFの実在CopyFiles list行です。
				// 不在の参照listを別のcopyへ補完しません。
				if( !SetupFindFirstLineW( inf, list.c_str(), nullptr, &file)) {
					return nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND) ;
				}

				// 到達listの全fileを読み、renameを同名sourceの許可へ変換しません。
				do {
					std::wstring target ;	// 原コピー先file名です。
					// 容量超過や部分fieldの失敗を許可根拠にしません。
					if( ++rows > 4096U || readInfField( file, 1U, target) != 0) {
						return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
					}

					// このserviceの実binary名に一致する行だけを一意に結びます。
					if( stringsEqual( target, executable)) {
						std::wstring source ;	// 空はWindowsの同名source記法です。
						// 異なるsourceのrenameを同じbyteの許可へ読み替えません。
						if( SetupGetFieldCount( &file) > 1U &&
						   (readInstallInventoryField( file, 2U, source) != 0 ||
							(!source.empty() && !stringsEqual( source, executable)))) {
							return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
						}

						++copies ;
					}
				} while( SetupFindNextLine( &file, &file)) ;
			}

			// 無関係なfile listの導入先をこのserviceの根拠へ借用しません。
			if( copies == 0U) {
				continue ;
			}

			const auto destinationKey =
				direct ? L"DefaultDestDir" : list.c_str() ;	// 明示元keyです。
			INFCONTEXT	 destination{} ;					// 同INFの明示DIRIDです。
			int			 dirid{} ;							// 有限なWindows標準DIRIDです。
			std::wstring subdirectory ;						// 元copy先の相対全subdirです。
			// DIRID・subdir不一致をbasenameだけのsource許可へ変換しません。
			if( !SetupFindFirstLineW( inf, L"DestinationDirs", destinationKey, &destination) ||
			   !SetupGetIntField( &destination, 1U, &dirid) ||
			   (dirid != 11 && dirid != 12 && dirid != 13) ||
			   SetupGetFieldCount( &destination) > 2U ||
			   (SetupGetFieldCount( &destination) == 2U &&
				(readInstallInventoryField( destination, 2U, subdirectory) != 0 ||
				 !validRequiredServiceSubdirectory( subdirectory)))) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			std::wstring sourceDirectory ;	// 同INFの完全な元file subdirです。
			std::wstring mediaDirectory ;	// 同source IDの完全な元媒体pathです。
			const auto	 sourceError = readRequiredServiceSourceDirectory(
				  inf, executable, sourceDirectory, mediaDirectory) ;	// 原診断です。
			// DIRID13は元source/destination subdir一致を必須とし、他DIRIDは同元sourceを保持します。
			if( sourceError != 0 || (dirid == 13 && !stringsEqual( sourceDirectory, subdirectory))) {
				return sourceError != 0 ? sourceError : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			INFCONTEXT duplicate{} ;	// 同導入先の重複指定です。
			// 一意のコピーと導入先だけから参照許可を作ります。
			if( SetupFindNextMatchLineW( &destination, destinationKey, &duplicate) ||
			   (matches += copies) > 1U) {
				return nativeErrorFromWin32( ERROR_DUP_NAME) ;
			}

			const auto targetSection = direct ? nullptr : list.c_str() ;	// 同元copyのAPI指定です。
			DWORD	   required{} ;											// Windowsが解決する同宛先の終端込み長です。
			SetLastError( ERROR_SUCCESS) ;
			// 生DIRID tokenと展開値を比較せず、同HINFの同copy先を有限に取得します。
			if( !SetupGetTargetPathW( inf, nullptr, targetSection, nullptr, 0U, &required) &&
			   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
				const auto native = GetLastError() ;	// 原宛先APIの診断です。
				return nativeErrorFromWin32( native == ERROR_SUCCESS ? ERROR_INVALID_DATA : native) ;
			}

			// 部分値や過大宛先を同leafの許可へ切り詰めません。
			if( required <= 1U || required > MAXIMUM_INF_FIELD_CHARACTERS) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			std::vector<wchar_t> target( required) ;	// 同期中だけ所有する有限宛先です。
			DWORD				 readRequired{} ;		// 同APIの実取得長です。
			// 同元の二段目に失敗した部分宛先を使いません。
			if( !SetupGetTargetPathW( inf, nullptr, targetSection, target.data(),
									static_cast<DWORD>( target.size()), &readRequired)) {
				const auto native = GetLastError() ;	// 補助比較前の原診断です。
				return nativeErrorFromWin32( native == ERROR_SUCCESS ? ERROR_INVALID_DATA : native) ;
			}

			const auto end = std::ranges::find( target, L'\0') ;	// 有限bufferの原終端です。
			// 完全な同宛先全値だけを比較し、basenameや任意絶対pathを許可しません。
			if( end == target.end() || readRequired != required ||
			   static_cast<std::size_t>( end - target.begin()) + 1U != required ||
			   !stringsEqual(
				   binary,
				   joinRelativePath( std::wstring_view( target.data(), required - 1U), executable))) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			validatedSource =
				joinRelativePath( joinRelativePath( mediaDirectory, sourceDirectory), executable) ;
		}
	} while( SetupFindNextMatchLineW( &copy, L"CopyFiles", &copy)) ;

	// 全宣言が終わった一意成功だけで位置付きsourceを公開します。
	if( matches == 1U) {
		sourceRelative = std::move( validatedSource) ;
		return 0 ;
	}

	return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
}

/**
 * @brief 同INFの元AddServiceを役割と必須作用へ限定して検査します。
 * @param[in] inf 同期中だけ借用する元INFです。
 * @param[in] services 元AddServiceを読み取った節名です。
 * @param[in,out] line 同節の原行contextです。参照を保存しません。
 * @param[in] role 正式Class/GUIDに対応する内容役割です。
 * @param[out] executable Win32必要serviceの場合だけ位置付き相対sourceを返します。それ以外・失敗時は空です。
 * @return 成功0、未対応種別・欠損・誤role・位置/copy不一致のHRESULTです。
 * @note kernel/file-systemの既存境界を維持し、Win32は0x10/0x20の有限形式だけを扱います。
 */
NativeError inspectRequiredServiceDeclaration( HINF inf, const std::wstring &services,
											  INFCONTEXT &line, DriverPlanRole role,
											  std::wstring &executable)
{
	executable.clear() ;
	std::wstring  section ;	// 元named service-install節です。
	std::uint32_t type{} ;	// 未知文字列を補正しない原スカラーです。
	// 実在named節と厳密ServiceTypeを必要とします。
	if( readInfField( line, 3U, section) != 0 || !validInstallInventorySectionName( section) ||
	   readRequiredServiceScalar( inf, section, L"ServiceType", type) != 0) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// kernel/file-systemにWin32のEXE許可を付与しません。
	if( type == SERVICE_KERNEL_DRIVER || type == SERVICE_FILE_SYSTEM_DRIVER) {
		return 0 ;
	}

	constexpr std::wstring_view SERVICES_SUFFIX = L".Services" ;	// 同DDInstallへの原結合です。
	// 必要SWCだけに明示Win32二種を認め、複合/誤roleを推測補正しません。
	if( role != DriverPlanRole::DRIVER_COMPONENT ||
	   (type != SERVICE_WIN32_OWN_PROCESS && type != SERVICE_WIN32_SHARE_PROCESS) ||
	   services.size() <= SERVICES_SUFFIX.size() ||
	   !stringsEqual( std::wstring_view( services).substr( services.size() - SERVICES_SUFFIX.size()),
					 SERVICES_SUFFIX) ||
	   SetupGetFieldCount( &line) != 3U) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	const auto install =
		// 同元基本節です。
		services.substr( 0U, services.size() - SERVICES_SUFFIX.size()) ;
	std::wstring  name ;		// 非空named serviceだけを扱います。
	std::wstring  flags ;		// 空または厳密uint32の原AddService flagsです。
	std::uint32_t start{} ;		// Win32のAUTO/DEMANDだけです。
	std::uint32_t control{} ;	// 正式ErrorControlのスカラーです。
	std::wstring  binary ;		// 元ServiceBinaryの全値です。
	// 全必須値と同DDInstall実在を確認し、別節のserviceを許可へ転用しません。
	if( SetupGetLineCountW( inf, install.c_str()) < 0 || readInfField( line, 1U, name) != 0 ||
	   readInstallInventoryField( line, 2U, flags) != 0 ||
	   readRequiredServiceScalar( inf, section, L"StartType", start) != 0 ||
	   (start != SERVICE_AUTO_START && start != SERVICE_DEMAND_START) ||
	   readRequiredServiceScalar( inf, section, L"ErrorControl", control) != 0 || control > 3U ||
	   readRequiredServiceField( inf, section, L"ServiceBinary", binary) != 0) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// Win32必要SWCに作用が定義された既存OS共通の正式flagsだけです。
	constexpr std::uint32_t ALLOWED_SERVICE_FLAGS =
		SPSVCINST_NOCLOBBER_DISPLAYNAME | SPSVCINST_NOCLOBBER_STARTTYPE |
		SPSVCINST_NOCLOBBER_ERRORCONTROL | SPSVCINST_NOCLOBBER_LOADORDERGROUP |
		SPSVCINST_NOCLOBBER_DEPENDENCIES | SPSVCINST_NOCLOBBER_DESCRIPTION |
		SPSVCINST_NOCLOBBER_REQUIREDPRIVILEGES | SPSVCINST_STARTSERVICE ;
	std::uint32_t				  parsedFlags{} ;	// 空fieldだけを正式な省略0として扱います。
	MaintenanceInfStructureReason flagReason{} ;	// 原厳密readerの同期診断です。
	// ASSOCSERVICE/unknown/security上書き等をWin32の一般許可へ含めません。
	if( (!flags.empty() && parseMaintenanceFlags( flags, parsedFlags, flagReason).state !=
							  MaintenanceInspectionState::PASSED) ||
	   (parsedFlags & ~ALLOWED_SERVICE_FLAGS) != 0U) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	const auto separator = binary.find_last_of( L'\\') ;	// 展開済み全targetの元leaf境界です。
	const auto file		 = binary.substr(
		 // copy候補だけのleafです。
		 separator == std::wstring::npos ? 0U : separator + 1U) ;
	// leafに引数や未知tokenを認めず、完全なbinaryの位置比較は後段でも必須にします。
	if( file.empty() || file.find_first_of( L"%\\/:\"\t\r\n ") != std::wstring::npos ||
	   lowerExtension( file) != L".exe") {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	std::wstring sourceRelative ;	// 同元copyへ結んだ位置付きsourceです。
	// 同節の元全宛先との比較診断です。
	const auto	 error = inspectRequiredServiceCopy( inf, install, file, binary, sourceRelative) ;
	// 別sourceや別DDInstallのコピーを実行許可へ補完しません。
	if( error != 0) {
		return error ;
	}

	executable = std::move( sourceRelative) ;
	return 0 ;
}

/**
 * @brief 正式SWCの全潜在serviceから同INFの有限EXE source集合を取得します。
 * @param[in] inf 同期中だけ借用する元INFです。
 * @param[in] className 既にVersionから検査した原Classです。
 * @param[out] executables 正常終端時は同INFの全検査済み一意相対source位置です。失敗時は空です。
 * @return 全宣言の検査成功0、列挙異常/誤GUID/未知service/容量/参照不一致のHRESULTです。
 * @note 内容集合だけであり導入authorityではありません。全CAT/member/hashを後段で要求します。
 */
NativeError collectRequiredServiceExecutables( HINF inf, std::wstring_view className,
											  std::vector<std::wstring> &executables)
{
	executables.clear() ;
	// 既存base/Extensionや任意ClassへEXEの内容許可を渡しません。
	if( !stringsEqual( className, L"SoftwareComponent")) {
		return 0 ;
	}

	std::wstring guid ;	// 同原Versionの正式役割GUIDです。
	// Class名だけではサービス型componentを認定しません。
	if( readInfDirective( inf, L"Version", L"ClassGUID", 1U, guid) != 0 ||
	   !stringsEqual( guid, L"{5c4c3332-344d-483c-8739-259e934c9cc8}")) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::size_t services{} ;	// 全節で共同消費する有限service宣言数です。
	// 非選択/別OSの潜在serviceも同元INFの内容検査から除きません。
	for( UINT index = 0U; index < MAXIMUM_INF_SECTIONS; ++index) {
		std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U> section{} ;	// 有限元節名です。
		// 完全な全節終端だけを成功にします。
		if( !SetupEnumInfSectionsW( inf, index, section.data(), static_cast<UINT>( section.size()),
								  nullptr)) {
			const auto error = GetLastError() ;	// 原列挙の終端/失敗です。
			// 正常終端だけが全検査済み集合を保持し、途中の診断では部分許可を破棄します。
			if( error != ERROR_NO_MORE_ITEMS) {
				executables.clear() ;
				return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
			}

			return 0 ;
		}

		INFCONTEXT service{} ;	// 同節の元AddServiceです。
		// serviceなしの構成INFを任意appに読み替えません。
		if( !SetupFindFirstLineW( inf, section.data(), L"AddService", &service)) {
			continue ;
		}

		// 全named serviceを同役割/同節へ結び、一宣言の成功で残りを省きません。
		do {
			std::wstring executable ;	// 検査済み同INFのsource名だけです。
			// 同元serviceの宣言・全宛先比較の診断です。
			const auto	 error = inspectRequiredServiceDeclaration(
				  inf, section.data(), service, DriverPlanRole::DRIVER_COMPONENT, executable) ;
			// 未対応や容量超過では部分EXE集合を公開しません。
			if( ++services > 32U || error != 0) {
				executables.clear() ;
				return error != 0 ? error : nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			// kernel等の空出力はWin32のsource許可へ含めません。
			if( !executable.empty()) {
				static_cast<void>( appendUnique( executables, std::move( executable))) ;
			}
		} while( SetupFindNextMatchLineW( &service, L"AddService", &service)) ;
	}

	executables.clear() ;
	return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
}

/**
 * @brief 元現在OS選択からCopyINFと必要SWC関係を有限に解析します。
 * @param[in] inf 呼出し終了まで生存する読取専用Windows INFです。
 * @param[in] workspace 安全な相対pathだけを解決する保護所有者です。
 * @param[in] entries 元archiveの有限inventoryです。
 * @param[in,out] package 既にClass/ID/参照fileを検査した元metadataです。
 * @param[in] selectedBasicSection 私有nodeで確認した基本名です。空なら全importの内容関係だけを解析します。
 * @return 全関係解析0、欠損・曖昧・role不一致・容量・未対応は元HRESULTです。
 * @note byte/CATの検査や導入は呼出し側です。Include/Needsの充足を推測しません。
 */
NativeError inspectRequiredDriverRelations( HINF inf, const OfficialDownloadWorkspace &workspace,
										   std::span<const OfficialZipEntry> entries,
										   OfficialInfPackage				&package,
										   std::wstring_view selectedBasicSection = {})
{
	// 役割は元Classの正式値だけから決め、名称や公開索引の申告を使いません。
	if( stringsEqual( package.className, L"Extension")) {
		package.role = DriverPlanRole::EXTENSION ;
	}

	// SoftwareComponentも正式Classだけで分類し、Extensionの規則を借用しません。
	if( stringsEqual( package.className, L"SoftwareComponent")) {
		package.role = DriverPlanRole::DRIVER_COMPONENT ;
	}

	// 追加役割の正式GUIDを省略・補完しません。
	if( package.role != DriverPlanRole::BASE_DRIVER) {
		// 元Versionの役割GUID読取診断です。
		NativeError error = readInfDirective( inf, L"Version", L"ClassGUID", 1U, package.classGuid) ;
		const auto	expected =
			 package.role == DriverPlanRole::EXTENSION
				 ? L"{e2f84ce7-8efa-411c-aa69-97454ca4cb57}"
				 : L"{5c4c3332-344d-483c-8739-259e934c9cc8}" ;	// Microsoftの役割GUIDです。
		// 別役割をbase Classの一致規則へ押し込みません。
		if( error != 0 || !stringsEqual( package.classGuid, expected)) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}
	}

	// ExtensionIdの実GUIDを検査し、同じ名称からidentityを作りません。
	if( package.role == DriverPlanRole::EXTENSION) {
		// 元ExtensionIdの読取診断を構文失敗と別に保持します。
		NativeError error =
			readInfDirective( inf, L"Version", L"ExtensionId", 1U, package.extensionId) ;
		GUID identity{} ;	// 構文と同一identityを確定する元GUIDです。
		// 空・不正・zeroの拡張identityを競合判定に使用しません。
		if( error != 0 || FAILED( CLSIDFromString( package.extensionId.c_str(), &identity)) ||
		   IsEqualGUID( identity, GUID_NULL)) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		std::array<wchar_t, 39U> canonical{} ;	// brace付きGUIDと終端の固定上限です。
		// GUIDの表記差から同identityの競合を回避させません。
		if( StringFromGUID2( identity, canonical.data(), static_cast<int>( canonical.size())) == 0) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		package.extensionId.assign( canonical.data()) ;
	}

	NativeError error{} ;	// 全import解析と私有選択解析の独立診断です。
	// 同deviceの私有node名がある場合だけ、現OS Models所属と実在節を確認します。
	if( !selectedBasicSection.empty()) {
		// 不正な基本名を任意実在節の指定へ変換しません。
		if( !validInstallInventorySectionName( selectedBasicSection)) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		error = selectInstallInventorySection( inf, std::wstring( selectedBasicSection),
											  package.selectedInstallSection) ;
		// Windowsの基本名fallbackも同元INFの実在を必要とします。
		if( error != 0) {
			return error ;
		}
	}

	const auto separator = package.infRelativePath.find_last_of( L'\\') ;	// 元INF親の境界です。
	// 元INFと同じ保護package内でだけ相対参照を解決します。
	const std::wstring parent =
		separator == std::wstring::npos ? L"" : package.infRelativePath.substr( 0U, separator) ;
	// SetupCopyOEMInfの全節CopyINF再帰importに備え、全宣言を切り捨てず照合します。
	for( UINT sectionIndex = 0U; sectionIndex < MAXIMUM_INF_SECTIONS; ++sectionIndex) {
		std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U> section{} ;	// 一節の有限名です。
		// 正常な全節終端だけを受理します。
		if( !SetupEnumInfSectionsW( inf, sectionIndex, section.data(),
								  static_cast<UINT>( section.size()), nullptr)) {
			const DWORD last = GetLastError() ;	// 終端とAPI失敗を分けます。
			// 正常終端以外を部分検査成功にしません。
			if( last != ERROR_NO_MORE_ITEMS) {
				return nativeErrorFromWin32( last) ;
			}

			break ;
		}

		// 上限の最後でも追加節がある入力を打ち切り成功にしません。
		if( sectionIndex + 1U == MAXIMUM_INF_SECTIONS) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		INFCONTEXT line{} ;	// 全明示directiveの読取contextです。
		// 明示空節には必要関係を補完しません。
		if( !SetupFindFirstLineW( inf, section.data(), nullptr, &line)) {
			continue ;
		}

		std::size_t lines{} ;	// 一節の有限行数です。
		// 全行のInclude/NeedsとCopyINFを原節へ結合します。
		do {
			// 過大な節を一部の正常構成へ切り詰めません。
			if( ++lines > 4096U) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			std::wstring key ;	// keyなしdata行は既存作用検査へ委ねます。
			// data行にdirectiveを推測しません。
			if( readInfField( line, 0U, key) != 0) {
				continue ;
			}

			// SYSTEM/PACKAGE参照の未確認をfalseへ書き換えません。
			if( stringsEqual( key, L"Include") || stringsEqual( key, L"Needs")) {
				package.unresolvedIncludeNeeds = true ;
			}

			// SourceDisksFiles不在の役割はfile参照を持てません。
			if( package.sourceFiles.empty() &&
			   (stringsEqual( key, L"CopyFiles") || stringsEqual( key, L"ServiceBinary"))) {
				return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
			}

			// import全内容の役割作用を検査し、非選択serviceもWin32 appへ読み替えません。
			if( package.role != DriverPlanRole::BASE_DRIVER && stringsEqual( key, L"AddService")) {
				std::wstring executable ;	// 同INFの必要Win32 serviceだけが返す元EXE名です。
				int			 flags{} ;		// Extensionのfunction-driver関連付けを拒否する原flagsです。
				// Extensionに基本driver serviceの権限を混ぜません。
				if( package.role == DriverPlanRole::EXTENSION &&
				   (!SetupGetIntField( &line, 2U, &flags) || (flags & 2) != 0)) {
					return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}

				// 全潜在importの実作用もdriver-only検査から除きません。
				if( const auto serviceError = inspectRequiredServiceDeclaration(
					   inf, section.data(), line, package.role, executable) ;
				   serviceError != 0) {
					return serviceError ;
				}
			}

			// 元CopyINFだけを再帰閉包の参照へ渡します。
			if( stringsEqual( key, L"CopyINF")) {
				const auto fields = SetupGetFieldCount( &line) ;	// 全原fieldです。
				// 欠損・過大な参照を正常な空集合にしません。
				if( fields == 0U || fields > 32U) {
					return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				// 各相対参照の位置と元archive実在を確認します。
				for( DWORD field = 1U; field <= fields; ++field) {
					std::wstring child ;	// 元INF相対参照です。
					error = readInfField( line, field, child) ;
					const auto path =
						// 安全性はworkspaceでも検査します。
						joinRelativePath( parent, child) ;
					// CopyINFの未知外部位置や欠損をstageの検索へ委ねません。
					if( error != 0 || lowerExtension( path) != L".inf" ||
					   workspace.path( path).empty() || !containsEntry( entries, path)) {
						return error != 0 ? error : nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
					}

					static_cast<void>( appendUnique( package.requiredInfPaths, path)) ;
					// 選択処理の元参照と全節import参照を別に保持します。
					if( stringsEqual( section.data(), package.selectedInstallSection)) {
						static_cast<void>( appendUnique( package.activeRequiredInfPaths, path)) ;
					}
				}
			}
		} while( SetupFindNextLine( &line, &line)) ;
	}

	// 内容検査だけでは全importを保持して終え、device別必要子を推測しません。
	if( selectedBasicSection.empty()) {
		return 0 ;
	}

	const auto componentsSection =
		package.selectedInstallSection + L".Components" ;	// 選択元の子宣言です。
	INFCONTEXT component{} ;								// AddComponentだけを有限に読みます。
	// 元宣言がある場合だけ必要子を作り、同梱名から必要性を作りません。
	if( SetupFindFirstLineW( inf, componentsSection.c_str(), L"AddComponent", &component)) {
		// 元AddComponentを全件保持し、一意名とSWC IDを結びます。
		do {
			OfficialInfComponentReference reference ;	// 一つの元子宣言です。
			std::wstring				  section ;		// ComponentIDsを持つ元sectionです。
			error = readInfField( component, 1U, reference.name) ;
			// 元name/sectionと予約flags以外を受理しません。
			if( error != 0 || SetupGetFieldCount( &component) != 3U ||
			   readInfField( component, 3U, section) != 0 ||
			   !validInstallInventorySectionName( section)) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			std::array<wchar_t, 32U> flags{} ;	// 空または0だけの予約fieldです。
			// 将来flagsを既知の0へ補正しません。
			if( !SetupGetStringFieldW( &component, 2U, flags.data(), static_cast<DWORD>( flags.size()),
									 nullptr) ||
			   (flags[0] != L'\0' && std::wstring_view( flags.data()) != L"0")) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			INFCONTEXT ids{} ;	// 元必須ComponentIDsです。
			// 必須IDを名称から補完しません。
			if( !SetupFindFirstLineW( inf, section.c_str(), L"ComponentIDs", &ids) ||
			   SetupGetFieldCount( &ids) == 0U || SetupGetFieldCount( &ids) > 32U) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// 原文の各ComponentIDにWindowsのSWC接頭辞を結合します。
			for( DWORD field = 1U; field <= SetupGetFieldCount( &ids); ++field) {
				std::wstring id ;	// 元ComponentIDです。端末IDの外部送信は行いません。
				error = readInfField( ids, field, id) ;
				// 空・過大・既接頭辞・異なるbusのIDを推測変換しません。
				if( error != 0 || id.size() > 192U || id.find( L'\\') != std::wstring::npos) {
					return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				static_cast<void>( appendUnique( reference.hardwareIds, L"SWC\\" + id)) ;
			}

			// 一意名・有限数を守り、曖昧な子の全導入をしません。
			if( package.requiredComponents.size() >= 8U ||
			   std::ranges::any_of( package.requiredComponents, [&]( const auto &value) {
				   return stringsEqual( value.name, reference.name) ;
			   })) {
				return nativeErrorFromWin32( ERROR_DUP_NAME) ;
			}

			package.requiredComponents.push_back( std::move( reference)) ;
		} while( SetupFindNextMatchLineW( &component, L"AddComponent", &component)) ;
	}

	// SWCにfunction serviceは必須でありません。ある場合だけ具体的作用を検査します。
	if( package.role != DriverPlanRole::BASE_DRIVER) {
		const auto services =
			package.selectedInstallSection + L".Services" ;	// 元選択service節です。
		INFCONTEXT service{} ;								// 元AddServiceの全driver-only検査です。
		// Serviceなしのdriver構成INFをClassだけで任意appへ読み替えません。
		if( SetupFindFirstLineW( inf, services.c_str(), L"AddService", &service)) {
			// 全serviceを同INFの役割と元コピーへ再照合し、内容許可を単独authorityにしません。
			do {
				std::wstring executable ;	// 同必要SWCの限定Win32 EXE名です。
				int			 flags{} ;		// 追加serviceの作用flagsです。
				// Extensionにfunction driver serviceを関連付けません。
				if( package.role == DriverPlanRole::EXTENSION &&
				   (!SetupGetIntField( &service, 2U, &flags) || (flags & 2) != 0)) {
					return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}

				// 欠損・未知/複合種別・誤roleを方式未対応へ残し、必要Win32 serviceを任意appと混同しません。
				if( const auto serviceError = inspectRequiredServiceDeclaration(
					   inf, services, service, package.role, executable) ;
				   serviceError != 0) {
					return serviceError ;
				}
			} while( SetupFindNextMatchLineW( &service, L"AddService", &service)) ;
		}
	}

	return 0 ;
}
} // namespace

/** @see src/platform/official_driver_package.h 宣言側の契約を正本とします。 */
NativeError inspectSelectedOfficialInfRelations( const OfficialDownloadWorkspace	 &workspace,
												std::span<const OfficialZipEntry> entries,
												const OfficialInfPackage		 &original,
												std::wstring_view	selectedBasicSection,
												OfficialInfPackage &selected)
{
	selected		= {} ;
	const auto path = workspace.path( original.infRelativePath) ;	// 同保護元INF完全pathです。
	// 公開文字列の空指定を内容検査だけの成功へ変換しません。
	if( path.empty() || !validInstallInventorySectionName( selectedBasicSection) ||
	   !containsEntry( entries, original.infRelativePath)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	UINT			errorLine{} ;	// 元INF構文失敗の行数です。外へ実pathを公開しません。
	const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
										  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
										  &errorLine)) ;	// 同期read-only所有handleです。
	// 不在または不正の元INFを別INFで補完しません。
	if( inf.get() == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	try {
		auto parsed = original ;	// 全importと元検査metadataを維持する私有copyです。
		parsed.selectedInstallSection.clear() ;
		parsed.selectedBasicSection = selectedBasicSection ;
		parsed.selectedNativeRank.reset() ;
		parsed.activeRequiredInfPaths.clear() ;
		parsed.requiredComponents.clear() ;
		const auto error = inspectRequiredDriverRelations(
			inf.get(), workspace, entries, parsed,
			selectedBasicSection) ;	// 同node名を渡した選択関係診断です。
		// 部分解析の成功や全import集合の差を公開しません。
		if( error != 0 || parsed.requiredInfPaths != original.requiredInfPaths) {
			return error ? error : nativeErrorFromWin32( ERROR_RETRY) ;
		}

		selected = std::move( parsed) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

/** @see official_driver_package.h */
NativeError readOfficialInfPublishedIdentity( const OfficialDownloadWorkspace &workspace,
											 const OfficialInfPackage		 &package,
											 OfficialInfPublishedIdentity	 &identity)
{
	identity = {} ;
	const auto path =
		// 元保護workspaceだけの読取り位置です。
		workspace.path( package.infRelativePath) ;
	// DTOだけを公開identityへ昇格せず、通常構造検査の有限ID列を要求します。
	if( path.empty() || package.hardwareIds.empty() || package.hardwareIds.size() > 128U) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		OfficialInfPublishedIdentity parsed ;						// 全成立前は外へ出さない一時値です。
		auto error = computeFileSha256( path, parsed.infSha256) ;	// 元原INFの先行identityです。
		// 読取り前の原byte未確認を成功へ補完しません。
		if( error != 0) {
			return error ;
		}

		UINT			errorLine{} ;	// 元HINFの構文診断位置です。
		const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  &errorLine)) ;	// Read-onlyです。
		// 実HINFを開けない場合は元Windows codeを返します。
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		error = readInfDirective( inf.get(), L"Version", L"ClassGUID", 1U, parsed.classGuid) ;
		GUID classGuid{} ;	// 元ClassGUIDの構文だけを確認します。
		// 不明ClassGUIDをdevice classや名前から生成しません。
		if( error != 0 || parsed.classGuid.size() != 38U ||
		   CLSIDFromString( parsed.classGuid.c_str(), &classGuid) != S_OK) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		std::vector<std::wstring> ids ;	// 既存readerの元順ID列です。
		error = collectHardwareIds( inf.get(), 128U, ids,
								   &parsed.models) ;	// 同readerへだけ新用途を追加します。
		// 元構造検査と異なるID列や節不足を公開identityへ変えません。
		if( error != 0 || ids != package.hardwareIds || parsed.models.empty()) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_REVISION_MISMATCH) ;
		}

		std::wstring finalHash ;	// Metadata読取り後の元INF原byteです。
		error = computeFileSha256( path, finalHash) ;
		// 前後hash不一致を部分metadataの正常化で隠しません。
		if( error != 0 || finalHash != parsed.infSha256) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_CRC) ;
		}

		identity = std::move( parsed) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

/** @see src/platform/official_driver_package.h 宣言側の契約を正本とします。 */
NativeError inspectOfficialInfPackage( const OfficialDownloadWorkspace		 &workspace,
									  const std::span<const OfficialZipEntry> entries,
									  const std::wstring_view				  infRelativePath,
									  const OfficialInfInspectionPolicy		 &policy,
									  OfficialInfPackage					 &package)
{
	package							 = {} ;
	const bool invalidProviderPolicy =	// 固定allowlistと汎用modeの矛盾状態。
		policy.acceptAnyProvider ? !policy.acceptedProviders.empty()
								 : policy.acceptedProviders.empty() ;
	// inventory、各上限、class・Provider・signature policyと選択INFを事前検証する。
	if( entries.empty() || policy.maximumHardwareIds == 0 || policy.maximumSourceFiles == 0 ||
	   policy.acceptedClasses.empty() || invalidProviderPolicy ||
	   policy.acceptedSignatures.empty() ||
	   !stringsEqual( lowerExtension( infRelativePath), L".inf") ||
	   !containsEntry( entries, infRelativePath)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 従来Providerはarchive全体、選択的閉包は後段のINF参照fileだけを拒否する。
	if( policy.rejectUnreferencedPrograms &&
	   std::ranges::any_of( entries, []( const OfficialZipEntry &entry) {
		   const std::wstring extension = lowerExtension( entry.relativePath) ;	// 現在entryの拡張子。
		   return std::ranges::find( REJECTED_UNREFERENCED_PROGRAM_EXTENSIONS, extension) !=
				  REJECTED_UNREFERENCED_PROGRAM_EXTENSIONS.end() ;
	   })) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	const std::wstring infPath = workspace.path( infRelativePath) ;	// 検証対象INF絶対path。
	// INFの保護pathを解決できなければ解析を開始しない。
	if( infPath.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	UINT			errorLine{} ;	// INF構文errorが発生した一origin line。
	const UniqueInf inf( SetupOpenInfFileW( infPath.c_str(), nullptr,
										  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
										  &errorLine)) ;	// 読取り専用INF handle。
	// INFを開けなければWindows診断値を保持して返す。
	if( inf.get() == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	bool			  hasExternalDependencies{} ;	// 動作検査で得た存在観測。依存充足ではない。
	const NativeError actionError =					// Policyが要求する場合の静的動作検証結果。
		policy.rejectInstallActions || policy.rejectExternalDependencies
			? validateInfInstallActions( inf.get(), policy.rejectExternalDependencies,
										hasExternalDependencies,
										policy.allowRequiredDriverComponents)
			: 0 ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( actionError != 0) {
		return actionError ;
	}

	try {
		OfficialInfPackage inspected ;	// 全検証成功時だけ出力へ移す一時構造。
		inspected.hasExternalDependencies = hasExternalDependencies ;
		inspected.infRelativePath		  = infRelativePath ;
		std::wstring signature ;	// `[Version]`のWindows INF signature。
		NativeError	 result = readInfDirective( inf.get(), L"Version", L"Signature", 1,
											   signature) ;	// Signature取得結果。
		// INF Signature値が取得不能または許可外なら拒否する。
		if( result != 0 || !isAllowedValue( signature, policy.acceptedSignatures)) {
			return result != 0 ? result : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		result = readInfDirective( inf.get(), L"Version", L"Class", 1, inspected.className) ;
		// INF classが取得不能または許可外なら拒否する。
		if( result != 0 || !isAllowedValue( inspected.className, policy.acceptedClasses)) {
			return result != 0 ? result : nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		result = readInfDirective( inf.get(), L"Version", L"Provider", 1, inspected.providerName) ;
		// 非空Provider値とProvider policyの対応を要求する。
		if( result != 0 || inspected.providerName.empty() ||
		   (!policy.acceptAnyProvider &&
			!isAllowedValue( inspected.providerName, policy.acceptedProviders))) {
			return result != 0 ? result : nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		result = readInfDirective( inf.get(), L"Version", L"DriverVer", 1, inspected.driverDate) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( result != 0) {
			return result ;
		}

		result = readInfDirective( inf.get(), L"Version", L"DriverVer", 2, inspected.driverVersion) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( result != 0) {
			return result ;
		}

		std::wstring catalogFile ;	// Version sectionが指定するCAT file名。
		result = readCatalogFile( inf.get(), catalogFile) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( result != 0) {
			return result ;
		}

		const std::size_t		separator = infRelativePath.find_last_of( L'\\') ;	// INF親位置。
		// Package内のINF親directory。Root直下では空のview。
		const std::wstring_view infParent = separator == std::wstring_view::npos
												? std::wstring_view{}
												: infRelativePath.substr( 0, separator) ;
		inspected.catalogRelativePath	  = joinRelativePath( infParent, catalogFile) ;
		// 対応CATがworkspaceとinventoryに存在しなければpackageを採用しない。
		if( workspace.path( inspected.catalogRelativePath).empty() ||
		   !containsEntry( entries, inspected.catalogRelativePath)) {
			return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
		}

		result = collectHardwareIds( inf.get(), policy.maximumHardwareIds, inspected.hardwareIds) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( result != 0) {
			return result ;
		}

		std::vector<std::wstring>
			serviceExecutables ;	// 同INFの必要SWC/元service/copyに限定する内容集合です。
		// 既存構成modeだけで正式SWCの元作用を検査し、一般EXE allow flagを作りません。
		if( policy.allowRequiredDriverComponents) {
			result = collectRequiredServiceExecutables( inf.get(), inspected.className,
													   serviceExecutables) ;
			// 同serviceの完全な根拠がなければsource byteを許可しません。
			if( result != 0) {
				return result ;
			}
		}

		// 元Extensionだけはfile参照のない標準形式を内容検査できます。署名検査は後段で必須です。
		const bool noExtensionFiles =
			policy.allowRequiredDriverComponents &&
			(stringsEqual( inspected.className, L"Extension") ||
			 stringsEqual( inspected.className, L"SoftwareComponent")) &&
			SetupGetLineCountW( inf.get(), L"SourceDisksFiles.amd64") < 0L &&
			SetupGetLineCountW( inf.get(), L"SourceDisksFiles") < 0L ;
		result = noExtensionFiles
					 ? 0
					 : collectSourceFiles(
						   inf.get(), workspace, entries, infParent, policy.maximumSourceFiles,
						   policy.requireDriverBinary, inspected.sourceFiles, nullptr,
						   policy.allowReferencedExecutablesForContent, serviceExecutables) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( result != 0) {
			return result ;
		}

		// 元検証済みClass/ID/fileからだけ必要構成を解析します。
		if( policy.allowRequiredDriverComponents) {
			result = inspectRequiredDriverRelations( inf.get(), workspace, entries, inspected) ;
			// 不足・曖昧な関係から部分的な導入metadataを返しません。
			if( result != 0) {
				return result ;
			}
		}

		package = std::move( inspected) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		package = {} ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_driver_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
namespace {

/**
 * @brief 共通または固定signer policyでWindows署名とCATを検査する。
 * @param[in] workspace INF閉包の所有領域。
 * @param[in] package 静的検査済みINF。
 * @param[in] acceptedSigners 固定policyのsigner群。
 * @param[in] windowsPolicy Windows検証済みの非空signerを使用する場合true。
 * @param[out] publisher 非null時だけ全署名/同CAT成功後の実DigitalSignerです。省略可です。
 * @return Windows署名、CATとsigner条件に合格した場合0。
 */
[[nodiscard]] NativeError verifyInfCatalogSignature(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const std::span<const std::wstring_view> acceptedSigners, const bool windowsPolicy,
	std::wstring *publisher = nullptr)
{
	const std::wstring infPath = workspace.path( package.infRelativePath) ;	// INF絶対path。
	const std::wstring expectedCatalogPath =
		// 検証対象workspace内CAT絶対path。
		workspace.path( package.catalogRelativePath) ;
	// 固定signerとWindows検証済みsignerのpolicyを混在させない。
	if( infPath.empty() || expectedCatalogPath.empty() ||
	   (windowsPolicy ? !acceptedSigners.empty() : acceptedSigners.empty())) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	SP_INF_SIGNER_INFO_W signer{} ;	// SetupAPIが返すcatalogと署名者情報。
	signer.cbSize = sizeof( signer) ;
	// WindowsのINF署名検証失敗を元の診断値で返す。
	if( driver_package_signature_detail::setupVerifyInf( infPath.c_str(), nullptr, &signer) ==
	   FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const std::wstring_view actualCatalog( signer.CatalogFile) ;	// SetupAPIが署名に使用したCAT。
	const std::wstring_view actualSigner( signer.DigitalSigner) ;	// 検証済みsigner表示名。
	// File名だけで別directoryのCATを誤認しないよう、workspace内絶対pathへ完全一致させる。
	if( !stringsEqual( actualCatalog, expectedCatalogPath)) {
		return nativeErrorFromWin32( ERROR_INVALID_NAME) ;
	}

	// 非空のWindows検証済みsignerを要求し、固定policyならallowlistも照合する。
	if( actualSigner.empty() || (!windowsPolicy && !isAllowedValue( actualSigner, acceptedSigners))) {
		return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
	}

	// 同原CATへ結合した実署名者だけを任意の非許可metadataへ写します。
	if( publisher != nullptr) {
		publisher->assign( actualSigner) ;
	}

	return 0 ;
}

/**
 * @brief 同一の署名検証とCAT member処理を両policyで共有する。
 * @param[in] workspace INF閉包の所有領域。
 * @param[in] package 静的検査済みINF。
 * @param[in] acceptedSigners 固定policyのsigner群。
 * @param[in] windowsPolicy Windows検証済みの非空signerを使用する場合true。
 * @return 全署名と全memberが一致した場合0。
 */
[[nodiscard]] NativeError verifyInfPackageIntegrity(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const std::span<const std::wstring_view> acceptedSigners, const bool windowsPolicy)
{
	// INFとCATの整合性・署名・許可publisherの検証結果。
	const NativeError signatureError =
		verifyInfCatalogSignature( workspace, package, acceptedSigners, windowsPolicy) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( signatureError != 0) {
		return signatureError ;
	}

	const std::wstring catalogPath =
		// 検証済みCAT絶対path。
		workspace.path( package.catalogRelativePath) ;
	const std::wstring infPath = workspace.path( package.infRelativePath) ;	// INF絶対path。
	// 参照fileがないINFも自身のCAT照合を必須とし、INFやCATの欠落だけは拒否する。
	if( catalogPath.empty() || infPath.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		std::vector<std::wstring> memberPaths ;	// CAT member検証するINFと参照file群。
		memberPaths.reserve( package.sourceFiles.size() + 1U) ;
		memberPaths.push_back( infPath) ;
		// INFが現在architectureで参照した全fileを同じCATへ結び付ける。
		for( const std::wstring &relativePath : package.sourceFiles) {
			const std::wstring memberPath = workspace.path( relativePath) ;	// Member絶対path。
			// 参照memberをworkspace内へ解決できなければCAT照合を中止する。
			if( memberPath.empty()) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			memberPaths.push_back( memberPath) ;
		}

		return verifyOfficialCatalogMembers( catalogPath, memberPaths) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

} // namespace

/**
 * @see src/platform/official_driver_package.h 宣言側の契約を正本とする。
 */
NativeError verifyOfficialInfCatalogSignature(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const std::span<const std::wstring_view> acceptedSigners)
{
	return verifyInfCatalogSignature( workspace, package, acceptedSigners, false) ;
}

/**
 * @see src/platform/official_driver_package.h 宣言側の契約を正本とする。
 */
NativeError verifyOfficialInfPackageIntegrity(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const std::span<const std::wstring_view> acceptedSigners)
{
	return verifyInfPackageIntegrity( workspace, package, acceptedSigners, false) ;
}

/**
 * @see src/platform/official_driver_package.h 宣言側の契約を正本とする。
 */
NativeError verifyWindowsInfPackageIntegrity( const OfficialDownloadWorkspace &workspace,
											 const OfficialInfPackage		 &package)
{
	return verifyInfPackageIntegrity( workspace, package, {}, true) ;
}

/** @see official_driver_package.h */
NativeError readWindowsInfPackagePublisher( const OfficialDownloadWorkspace &workspace,
										   const OfficialInfPackage		   &package,
										   std::wstring					   &publisher)
{
	publisher.clear() ;
	const auto error =
		// 全CAT/memberの既存policyです。
		verifyInfPackageIntegrity( workspace, package, {}, true) ;
	// 全member未確認のsigner名を検証済みpublisherへ昇格させません。
	if( error != 0U) {
		return error ;
	}

	return verifyInfCatalogSignature( workspace, package, {}, true, &publisher) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_driver_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError verifyOfficialInfEmbeddedFileSignatures(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const std::span<const std::wstring_view> requiredRelativePaths,
	const std::span<const std::wstring_view> acceptedSigners)
{
	// INF参照、必須署名対象、署名者allowlistが欠けた検証要求を拒否する。
	if( package.sourceFiles.empty() || requiredRelativePaths.empty() || acceptedSigners.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 固定policyの全fileをINF参照集合と同じpublisherへ拘束する。
	for( std::size_t index = 0; index < requiredRelativePaths.size(); ++index) {
		const std::wstring_view relativePath = requiredRelativePaths[index] ;	// 現在の固定path。
		const bool				duplicate =
			std::ranges::any_of( requiredRelativePaths.first( index),
								[relativePath]( const std::wstring_view previous) noexcept {
									return stringsEqual( relativePath, previous) ;
								}) ; // 先行pathとの重複状態。
		const bool referenced = std::ranges::any_of(
			package.sourceFiles, [relativePath]( const std::wstring &sourceFile) noexcept {
				return stringsEqual( relativePath, sourceFile) ;
			}) ; // INF参照集合との一致状態。
		// 不正、重複、INF未参照のpathを埋込署名検証対象にしない。
		if( relativePath.empty() || relativePath.find( L'\0') != std::wstring_view::npos ||
		   duplicate || !referenced) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		const std::wstring path = workspace.path( relativePath) ;	// 参照fileの絶対path。
		// 署名対象fileを保護workspace内へ解決できなければ拒否する。
		if( path.empty()) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		const NativeError error =
			// 埋込み署名検証結果。
			verifyAuthenticodePublisher( path, acceptedSigners) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_driver_package.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialInfDeviceMatch matchOfficialInfToDevice(
	const OfficialInfPackage &package, const std::span<const std::wstring_view> deviceHardwareIds,
	const std::span<const std::wstring_view> deviceCompatibleIds) noexcept
{
	const auto matchesPackage = [&package]( const std::wstring_view deviceId) {
		// 空のdevice IDをINFとの一致として扱わない。
		if( deviceId.empty()) {
			return false ;
		}

		return std::ranges::any_of( package.hardwareIds, [deviceId]( const std::wstring &packageId) {
			return !packageId.empty() && stringsEqual( packageId, deviceId) ;
		}) ;
	} ; // 一つの現在device IDがINFの有限ID群へ完全一致するかを調べる処理。

	// Hardware IDはCompatible IDより具体的なため、先に一致を確定する。
	if( std::ranges::any_of( deviceHardwareIds, matchesPackage)) {
		return OfficialInfDeviceMatch::HARDWARE_ID ;
	}

	// compatible IDによる一致はHardware ID一致と区別して返す。
	if( std::ranges::any_of( deviceCompatibleIds, matchesPackage)) {
		return OfficialInfDeviceMatch::COMPATIBLE_ID ;
	}

	return OfficialInfDeviceMatch::NONE ;
}

namespace {
/**
 * @brief 一file名の明示source媒体位置を固定memberへ結合する。
 * @param[in] inf 単独INFの同期handle。
 * @param[in] workspace 安全相対位置の確認に借用する。
 * @param[in] entries 閉じた元member一覧。
 * @param[in] parent 元INFのpackage相対親位置。
 * @param[in] binaryTarget trueなら既知DIRID表記のbinary名をsource名へ対応させる。
 * @param[in,out] reference 元用途と展開値を持ち、位置観測を受け取る。
 * @param[in] requiredSubdirectory DIRID13の新照合時だけのSourceDisksFiles subdir期待。媒体pathは含めない。
 * @return 観測成功0、不正path・容量・不在以外の読取失敗HRESULT。
 */
[[nodiscard]] NativeError locateMaintenanceSource(
	HINF inf, const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	std::wstring_view parent, bool binaryTarget, MaintenanceInfFileReference &reference,
	std::optional<std::wstring_view> requiredSubdirectory = std::nullopt)
{
	std::wstring_view name = reference.target ;	// 原値を変更せずsource名だけを借用する。
	// DIRIDはpackage sourceとの対応にだけ使い、system payload位置を認証しない。
	if( binaryTarget && (name.starts_with( L"%11%\\") || name.starts_with( L"%12%\\") ||
						name.starts_with( L"%13%\\"))) {
		name.remove_prefix( 5U) ;
	}

	// 未展開tokenと未対応binary位置をbasename推測で救済しない。
	if( name.empty() || name.find( L'%') != name.npos ||
	   (binaryTarget && name.find_first_of( L"/\\") != name.npos)) {
		reference.location = MaintenanceInfFileLocation::UNSUPPORTED ;
		reference.error	   = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		return 0 ;
	}

	// Source名はfile名だけに限定し、traversalを未対応へ弱めない。
	if( name.find_first_of( L"/\\") != name.npos ||
	   workspace.path( joinRelativePath( parent, name)).empty()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const std::wstring fileName( name) ;	// SetupAPIへ渡す終端付き元source名。
	UINT			   sourceId{} ;			// SourceDisksNamesと対応する媒体ID。
	DWORD			   required{} ;			// 終端込みsource相対directory必要長。
	SetLastError( ERROR_SUCCESS) ;
	// source節不在・位置未定義は具体的な用途未対応として残す。
	if( SetupGetSourceFileLocationW( inf, nullptr, fileName.c_str(), &sourceId, nullptr, 0U,
								   &required) == FALSE &&
	   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		const DWORD error = GetLastError() ;	// 原位置照会の直後の診断。
		// 明示source未発見だけはdriver全体の構文不正と区別する。
		if( error == ERROR_LINE_NOT_FOUND || error == ERROR_SECTION_NOT_FOUND ||
		   error == ERROR_FILE_NOT_FOUND) {
			reference.location = MaintenanceInfFileLocation::UNSUPPORTED ;
			reference.error	   = nativeErrorFromWin32( error) ;
			return 0 ;
		}

		return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
	}

	// 不正・過長の必要長を切り詰めず、有限bufferだけを確保する。
	if( required == 0U || required > MAXIMUM_INF_FIELD_CHARACTERS) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	std::vector<wchar_t> directory( required) ;	// SourceDisksFilesの有限相対位置。
	// 二段目のAPI失敗から部分位置を作らない。
	if( SetupGetSourceFileLocationW( inf, nullptr, fileName.c_str(), &sourceId, directory.data(),
								   static_cast<DWORD>( directory.size()), nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	DWORD mediaRequired{} ;	// 終端込み媒体path必要長。
	// source位置だけで媒体pathを省略しない。
	if( SetupGetSourceInfoW( inf, sourceId, SRCINFO_PATH, nullptr, 0U, &mediaRequired) == FALSE &&
	   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		reference.location = MaintenanceInfFileLocation::UNSUPPORTED ;
		reference.error	   = nativeErrorFromWin32( GetLastError()) ;
		return 0 ;
	}

	// 媒体pathの過長・不正必要長を拒否する。
	if( mediaRequired == 0U || mediaRequired > MAXIMUM_INF_FIELD_CHARACTERS) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	std::vector<wchar_t> media( mediaRequired) ;	// SourceDisksNamesの有限媒体位置。
	// 媒体読取失敗後にroot directoryを補完しない。
	if( SetupGetSourceInfoW( inf, sourceId, SRCINFO_PATH, media.data(),
						   static_cast<DWORD>( media.size()), nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	reference.relativePath = joinRelativePath( parent, stripReferenceCurrentDirectory( media.data())) ;
	reference.relativePath =
		joinRelativePath( reference.relativePath, stripReferenceCurrentDirectory( directory.data())) ;
	reference.relativePath = joinRelativePath( reference.relativePath, fileName) ;
	// 逸脱した媒体位置は空位置へ変換せず全体を拒否する。
	if( workspace.path( reference.relativePath).empty()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// DIRID13のsource subdirだけを照合し、SourceDisksNamesの媒体pathを混ぜない。
	if( requiredSubdirectory.has_value() && !stringsEqual( directory.data(), *requiredSubdirectory)) {
		reference.relativePath.clear() ;
		reference.location = MaintenanceInfFileLocation::UNSUPPORTED ;
		reference.error	   = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		return 0 ;
	}

	const auto count = std::ranges::count_if( entries, [&reference]( const auto &entry) {
		return stringsEqual( entry.relativePath, reference.relativePath) ;
	}) ; // 同位置の衝突も先頭候補へ絞らない。
	// 重複memberは閉じた位置根拠として扱わない。
	if( count > 1) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	reference.location =
		count == 1 ? MaintenanceInfFileLocation::LOCATED : MaintenanceInfFileLocation::MISSING ;
	reference.error = count == 1 ? 0 : nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
	return 0 ;
}

/**
 * @brief 到達named list固有の明示導入先を同INFの有限metadataから一度だけ観測する。
 * @param[in] inf 同期借用する単独HINF。Appendとdirectory再割当てを行わない。
 * @param[in] workspace 相対subdirの安全境界だけへ借用する。
 * @param[in] copies 既存queueの同じ読取済み行。最大4,096項目。
 * @param[in,out] budget Version・source・全seedと共同消費する予算。
 * @param[in,out] inventory metadataの節・行もclosure累積計測へ含める。
 * @param[out] directories named固有の元宣言と展開結果。defaultを根拠にしない。
 * @param[in,out] byteProof 非nullなら同HINF・同rowの全field証明へ元取得値を結ぶ。通常読取はnull。
 * @return 観測成功0、不正数値・path・読取・容量失敗は元HRESULT。
 */
[[nodiscard]] NativeError readMaintenanceDestinationDirectories(
	HINF inf, const OfficialDownloadWorkspace &workspace,
	std::span<const MaintenanceCopyDestination> copies, MaintenanceStructureBudget &budget,
	OfficialInfInstallInventory					 &inventory,
	std::vector<MaintenanceDestinationDirectory> &directories,
	MaintenanceInfByteProof						 *byteProof = nullptr)
{
	// 不要なmetadata走査と、queueが既に読んだ節の再走査を追加しない。
	if( copies.empty() || std::ranges::any_of( inventory.visitedSections, []( const auto &section) {
		   return stringsEqual( section, L"DestinationDirs") ;
	   })) {
		return 0 ;
	}

	const std::wstring section = L"DestinationDirs" ;						// 単独INFの明示metadata名。
	LONG			   count{} ;											// 明示空と不存在を別に保持する行数。
	NativeError		   error = maintenanceLineCount( inf, section, count) ;	// 元読取診断。
	// API失敗をdefaultや空の成功へ変換しない。
	if( error != 0) {
		return error ;
	}

	// 不在の明示導入先からWindows-directoryを推測しない。
	if( count < 0) {
		return 0 ;
	}

	// metadataも同じ節・全行予算へ含め、各listで上限をresetしない。
	if( ++budget.sections > MAXIMUM_INSTALL_INVENTORY_SECTIONS ||
	   static_cast<std::size_t>( count) > MAXIMUM_INSTALL_INVENTORY_LINES - budget.lines) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	inventory.visitedSections.push_back( section) ;
	// 確定した全metadata行を一度ずつ読み、現在到達listと同じkeyだけを保持する。
	for( LONG row = 0L; row < count; ++row) {
		INFCONTEXT line{} ;	// 単独INFの元indexに結ぶ借用context。
		error = maintenanceLineAt( inf, section, row, line) ;
		// 途中失敗を正常な節終端へ変換しない。
		if( error != 0) {
			return error ;
		}

		++budget.lines ;
		++inventory.scannedLines ;
		const DWORD fields = SetupGetFieldCount( &line) ;	// key以外の元field数。
		// 未到達keyの行も共同field上限を迂回させない。
		if( fields > MAXIMUM_INSTALL_INVENTORY_FIELDS) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		std::wstring		 key ;	// defaultとnamed固有keyを混同しない元値。
		const auto			 rawRow = byteProof == nullptr
										  ? NO_MAINTENANCE_RAW_ROW
										  : byteProof->row( section, row, count, fields) ;	// 同元metadata行。
		MaintenanceFieldRead keyRead{} ;													// 元keyの同じ二API結果。
		error = readMaintenanceField(
			line, 0U, key, byteProof != nullptr && byteProof->active() ? &keyRead : nullptr) ;
		// 読取不能keyを未知の正常行として捨てない。
		if( error != 0) {
			return error ;
		}

		// 元keyを再readせずにraw全値へ結ぶ。
		if( byteProof != nullptr) {
			byteProof->field( rawRow, 0U, key, keyRead) ;
		}

		// default・未知key・未到達listは展開済み位置の成功根拠にしない。
		if( stringsEqual( key, L"DefaultDestDir") ||
		   !std::ranges::any_of(
			   copies, [&key]( const auto &copy) { return stringsEqual( copy.section, key) ; })) {
			continue ;
		}

		// 保持量を同じ一INFの最大項目数へ制限する。
		if( directories.size() >= MAXIMUM_INSTALL_INVENTORY_ITEMS) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		MaintenanceDestinationDirectory directory ;	// 全展開成功まで私有の部分観測。
		directory.section = std::move( key) ;
		directory.rawRow  = rawRow ;
		// DIRID欠落は合法な未知値と区別し、不正な元行を拒否する。
		if( fields == 0U) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		std::wstring		 dirid ;		// Windowsが返した全数値field。
		MaintenanceFieldRead diridRead{} ;	// 元DIRIDの全取得。
		error = readMaintenanceField(
			line, 1U, dirid, byteProof != nullptr && byteProof->active() ? &diridRead : nullptr) ;
		// 必要長超過と読取失敗を部分数値へ補完しない。
		if( error != 0) {
			return error ;
		}

		// 元数値の全field比較を意味の数値解釈と分ける。
		if( byteProof != nullptr) {
			byteProof->field( rawRow, 1U, dirid, diridRead) ;
		}

		MaintenanceInfStructureReason reason{} ;										// 同じ厳密数値readerの失敗分類。
		const auto finding = parseMaintenanceFlags( dirid, directory.dirid, reason) ;	// 全数値解析。
		// 具体的な数値不正・overflowは位置未知へ弱めない。
		if( finding.state == MaintenanceInspectionState::FAILED) {
			return finding.error ;
		}

		// 明示subdirは媒体位置と分け、元fieldの全必要長を検査する。
		if( fields >= 2U) {
			MaintenanceFieldRead subdirectoryRead{} ;	// 元subdirの同query／read。
			error = readMaintenanceField(
				line, 2U, directory.subdirectory,
				byteProof != nullptr && byteProof->active() ? &subdirectoryRead : nullptr) ;
			// 読取不能値を空directoryへ補完しない。
			if( error != 0) {
				return error ;
			}

			// 元取得値の全長・全code unitを同byteへ比較する。
			if( byteProof != nullptr) {
				byteProof->field( rawRow, 2U, directory.subdirectory, subdirectoryRead) ;
			}

			// token残留は位置未対応として保持し、不正pathと混同しない。
			if( directory.subdirectory.find( L'%') == std::wstring::npos &&
			   !directory.subdirectory.empty() && workspace.path( directory.subdirectory).empty()) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}
		}

		// 元coreが未取得のauxだけを同contextで一度補う。
		if( byteProof != nullptr && fields >= 3U) {
			byteProof->extra( line, rawRow, 3U, fields) ;
		}

		// 現対応三DIRID・二field以内・安全subdirだけをAPI照会候補にする。
		if( finding.state == MaintenanceInspectionState::PASSED && fields <= 2U &&
		   (directory.dirid == 11U || directory.dirid == 12U || directory.dirid == 13U) &&
		   directory.subdirectory.find( L'%') == std::wstring::npos) {
			directory.error = 0 ;
		}

		directories.push_back( std::move( directory)) ;
		// private metadata増加でも元core必要量を優先して予約撤回する。
		if( byteProof != nullptr) {
			byteProof->capacity( budget.effects + budget.references + budget.services +
								budget.issues + budget.fileUses + budget.coverageGaps +
								copies.size() + directories.size() +
								inventory.visitedSections.size()) ;
		}
	}

	// 一意なnamed entryごとに二段階APIを一度だけ使い、default fallbackと重複を避ける。
	for( auto &directory : directories) {
		// 未対応宣言と同key重複は先頭の展開値を成功根拠にしない。
		if( directory.error != 0 ||
		   std::ranges::count_if( directories, [&directory]( const auto &candidate) {
			   return stringsEqual( candidate.section, directory.section) ;
		   }) != 1) {
			continue ;
		}

		DWORD required{} ;	// 終端込みのWindows展開後文字数。
		SetLastError( ERROR_SUCCESS) ;
		// 明示named keyで照会し、APIが解決できない位置は元診断を保持する。
		if( SetupGetTargetPathW( inf, nullptr, directory.section.c_str(), nullptr, 0U, &required) ==
			   FALSE &&
		   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			const DWORD native = GetLastError() ;	// 直後の原API診断。
			directory.error =
				nativeErrorFromWin32( native == ERROR_SUCCESS ? ERROR_INVALID_DATA : native) ;
			continue ;
		}

		// 一回の必要長も共同readerと同じ4,096文字へ拘束し、切捨てない。
		if( required == 0U || required > MAXIMUM_INF_FIELD_CHARACTERS) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		std::vector<wchar_t> path( required) ;	// 呼出し中だけの有限終端付きbuffer。
		DWORD				 readRequired{} ;	// 同じ二段target取得の必要長をprivateだけへ捕捉する。
		SetLastError( ERROR_SUCCESS) ;
		// 二段目の失敗後に部分pathをdirectoryへ保存しない。
		if( SetupGetTargetPathW( inf, nullptr, directory.section.c_str(), path.data(),
							   static_cast<DWORD>( path.size()),
							   byteProof != nullptr && byteProof->active() ? &readRequired
																		   : nullptr) == FALSE) {
			const DWORD native = GetLastError() ;	// buffer取得の原診断。
			directory.error =
				nativeErrorFromWin32( native == ERROR_SUCCESS ? ERROR_INVALID_DATA : native) ;
			continue ;
		}

		directory.expandedDirectory = path.data() ;
		directory.targetComplete	= byteProof != nullptr && byteProof->active() &&
								   std::ranges::find( path, L'\0') != path.end() &&
								   readRequired == required &&
								   directory.expandedDirectory.size() + 1U == required ;
		// 空のAPI出力をraw DIRID対応の展開成功へ昇格しない。
		if( directory.expandedDirectory.empty()) {
			directory.error = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}
	}

	return 0 ;
}

/**
 * @brief 構築完了したnamed行とdirectoryを一度だけ結び、反復検索とpath再生成を除く。
 * @param[in] workspace destination leafの安全性だけへ同期借用する。
 * @param[in] copies 最大4,096行の構築済みvectorを借用する。使用中の再確保・変更は禁止する。
 * @param[in] directories 同INFの構築済みmetadata。cache使用中に変更しない。
 * @param[out] bindings 同scope内だけで有効な非所有pointerと元状態・全targetを最大4,096件保持する。
 * @return 構築成功0、不正destination・保持量／target長超過は元HRESULT。
 */
[[nodiscard]] NativeError bindMaintenanceCopyDestinations(
	const OfficialDownloadWorkspace &workspace, std::span<const MaintenanceCopyDestination> copies,
	std::span<const MaintenanceDestinationDirectory> directories,
	std::vector<MaintenanceCopyBinding>				&bindings)
{
	// 私有cacheも元readerと同じ保持上限へ拘束し、分割・resetをしない。
	if( copies.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	bindings.reserve( copies.size()) ;
	// 全到達copyを一度ずつ元named entryへ結び、各binaryでdirectoryを再検索しない。
	for( const auto &copy : copies) {
		// 現在使用するnamed destinationは安全leafだけに制限する。
		if( copy.destination.find_first_of( L"/\\") != std::wstring::npos ||
		   workspace.path( copy.destination).empty()) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		MaintenanceCopyBinding binding ;	// 一致後も元vectorの同期借用だけを保持する。
		binding.copy	 = &copy ;
		const auto count = std::ranges::count_if( directories, [&copy]( const auto &directory) {
			return stringsEqual( directory.section, copy.section) ;
		}) ; // 同keyの全候補数。重複を先頭へ絞らない。
		// 固有entry不在と重複も原copyに結ぶ元状態として保持する。
		if( count != 1) {
			binding.error = nativeErrorFromWin32( count > 1 ? ERROR_DUP_NAME : ERROR_NOT_SUPPORTED) ;
		} else {
			const auto directory = std::ranges::find_if( directories, [&copy]( const auto &item) {
				return stringsEqual( item.section, copy.section) ;
			}) ; // 一意と確認済みの元metadata。
			binding.directory	 = &*directory ;
			binding.error		 = directory->error ;
			// 未展開destination tokenを既知leafへ補完しない。
			if( copy.destination.find( L'%') != std::wstring::npos && binding.error == 0) {
				binding.error = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			// 全targetを一度だけ作り、元fieldと同じ必要長上限を維持する。
			if( binding.error == 0) {
				binding.fullTarget =
					joinRelativePath( directory->expandedDirectory, copy.destination) ;
				binding.rawTarget = L"%" + std::to_wstring( directory->dirid) + L"%\\" +
									joinRelativePath( directory->subdirectory, copy.destination) ;
				// 終端込み4,096文字を超える合成pathも切り詰めない。
				if( binding.fullTarget.size() >= MAXIMUM_INF_FIELD_CHARACTERS ||
				   binding.rawTarget.size() >= MAXIMUM_INF_FIELD_CHARACTERS) {
					return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
				}
			}
		}

		bindings.push_back( std::move( binding)) ;
	}

	return 0 ;
}

/**
 * @brief 同HINFの成功した到達named13相対全targetとの一致だけを判定する。
 * @param[in] target 元binaryの展開後全値。先頭dotを取り除かず同期借用する。
 * @param[in] binding 構築完了した元copyと明示directoryのcache。使用中に変更しない。
 * @return 明示13・非空dot-relative出力・全値一致ならtrue。それ以外はfalse。
 * @note 一宣言の対応だけを示し、候補一意性・元source・実Storeの充足は判定しない。
 */
[[nodiscard]] bool matchesMaintenanceRelative13Target(
	std::wstring_view target, const MaintenanceCopyBinding &binding) noexcept
{
	return target.starts_with( L".\\") && binding.error == 0 && binding.directory != nullptr &&
		   binding.directory->dirid == 13U &&
		   (binding.directory->expandedDirectory == L"." ||
			binding.directory->expandedDirectory.starts_with( L".\\")) &&
		   stringsEqual( target, binding.fullTarget) ;
}

/**
 * @brief binaryの展開済み導入先を到達named copyの明示sourceだけへ限定対応させる。
 * @param[in] inf 同じ一INFの同期handle。
 * @param[in] workspace 元sourceの安全相対位置にだけ借用する。
 * @param[in] entries 閉じた元member集合。system targetを探索しない。
 * @param[in] parent 元INFのpackage相対親位置。
 * @param[in] bindings 構築完了した元vectorを同期借用する全到達named行のcache。
 * @param[in] sourceObservations 元readerが既に読んだsource用途を含む観測。呼出し中のappendは禁止する。
 * @param[in,out] reference 元binary用途を維持し、位置と元診断だけを更新する。
 * @return 観測成功0、不正path・source読取・容量等の全体拒否HRESULT。
 */
[[nodiscard]] NativeError locateMaintenanceBinarySource(
	HINF inf, const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	std::wstring_view parent, std::span<const MaintenanceCopyBinding> bindings,
	std::span<const MaintenanceInfFileReference> sourceObservations,
	MaintenanceInfFileReference					&reference)
{
	std::wstring_view legacyName = reference.target ;	// 旧同名source対応の借用だけ。
	// 旧raw三prefixの同名leaf対応を新しいabsolute fallbackと混同しない。
	if( legacyName.starts_with( L"%11%\\") || legacyName.starts_with( L"%12%\\") ||
	   legacyName.starts_with( L"%13%\\")) {
		legacyName.remove_prefix( 5U) ;
	}

	// 旧裸leafだけは元媒体と固定memberの既存境界をそのまま使う。
	if( legacyName.find_first_of( L"/\\") == legacyName.npos) {
		return locateMaintenanceSource( inf, workspace, entries, parent, true, reference) ;
	}

	std::wstring_view target = reference.target ;	// 正規化せず全値を借用する。
	const bool		  drivePath =
		target.size() >= 3U &&
		((target[0] >= L'A' && target[0] <= L'Z') || (target[0] >= L'a' && target[0] <= L'z')) &&
		// 現APIで扱うdrive形式だけ。
		target[1] == L':' && target[2] == L'\\' ;
	const auto relative13Matches =
		!drivePath && target.starts_with( L".\\")
			? std::ranges::count_if( bindings,
									[target]( const auto &binding) {
										return matchesMaintenanceRelative13Target( target, binding) ;
									})
			: 0 ;	// 先頭dotの除外と候補選択で同じ全値条件を使い、位置成功は後段へ分ける。
	std::wstring_view components =
		drivePath
			? target.substr( 3U)
			: (relative13Matches != 0 ? target.substr( 2U) : target) ;	// 元の残り全要素を検査する。
	std::size_t beginning{} ;											// 各原path要素の開始位置。
	// 元全pathのdot移動を一度だけ検査し、正規化で未知位置を救済しない。
	while( beginning < components.size()) {
		const auto separator = components.find_first_of( L"/\\", beginning) ;	// 元区切り。
		const auto ending =
			// 要素終端。
			separator == components.npos ? components.size() : separator ;
		const auto component = components.substr( beginning, ending - beginning) ;	// 原要素。
		// traversalを単なる未対応binary位置へ弱めない。
		if( component == L"." || component == L"..") {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		beginning = ending + 1U ;
	}

	// UNC／device pathは照合対象外。drive以外のcolonとADSだけは不正として拒否する。
	if( !target.starts_with( L"\\\\") && components.find( L':') != components.npos) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const auto separator = target.find_last_of( L"/\\") ;			// 保留候補のleafだけを借用する位置。
	const auto leaf		 = target.substr( separator + 1U) ;			// leaf一致だけで成功は作らない。
	const MaintenanceCopyDestination *selected{} ;					// 全候補一意確認後だけ使用する非所有pointer。
	const MaintenanceDestinationDirectory *selectedDirectory{} ;	// 同scopeの元named entry。
	std::size_t							   matches{} ;				// 全pathが一致した全候補数。
	NativeError uncertain{} ;										// 同leafで位置根拠を確定できない候補の元診断。
	bool		selectedRelative13{} ;								// 新相対対応だけに元source行の一意性を追加する。
	// 到達named copyだけを全件比較し、未到達listや任意absoluteのbasenameへfallbackしない。
	for( const auto &binding : bindings) {
		const auto &copy = *binding.copy ;	// 構築完了した元行の同scope借用。
		// 固有entry不在・重複・未対応の同leaf候補を一意成功から消さない。
		if( binding.error != 0) {
			// 未確定同leafの候補を消して一意成功を作らない。
			if( stringsEqual( copy.destination, leaf)) {
				uncertain = binding.error ;
			}

			continue ;
		}

		// 全値一致だけで候補を数え、Windows-prefixやbasenameでは受理しない。
		if( (drivePath && stringsEqual( target, binding.fullTarget)) ||
		   stringsEqual( target, binding.rawTarget) ||
		   matchesMaintenanceRelative13Target( target, binding)) {
			++matches ;
			selected		   = &copy ;
			selectedDirectory  = binding.directory ;
			selectedRelative13 = matchesMaintenanceRelative13Target( target, binding) ;
		}
	}

	reference.location = MaintenanceInfFileLocation::UNSUPPORTED ;
	reference.error	   = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	// 未確定候補と全pathの曖昧を元診断付きで残す。
	if( matches != 1U || uncertain != 0) {
		reference.error = matches > 1U || relative13Matches > 1
							  ? nativeErrorFromWin32( ERROR_DUP_NAME)
							  : (uncertain != 0 ? uncertain : reference.error) ;
		return 0 ;
	}

	// DIRID13はrenameを新対応へ入れず、実Driver Storeの充足も保証しない。
	if( selectedDirectory->dirid == 13U && !stringsEqual( selected->destination, selected->source)) {
		return 0 ;
	}

	// 新相対13は既に有限読取したsource一行だけへ結び、SetupAPIの先頭選択で重複を消さない。
	if( selectedRelative13) {
		const MaintenanceInfFileReference *observedSource{} ;	// 同期借用中だけ有効な元source観測。
		std::size_t sourceMatches{} ;							// 同名の全元source行数。使用先用途を数えない。
		// 元source宣言だけを全件確認し、一照会の間は借用元へappendしない。
		for( const auto &observation : sourceObservations) {
			// 用途名とsource全名が一致する元観測だけを候補へ残す。
			if( stringsEqual( observation.directive, L"SourceDisksFiles") &&
			   stringsEqual( observation.target, selected->source)) {
				++sourceMatches ;
				observedSource = &observation ;
			}
		}

		// 未観測fallbackと同名複数行を推測補完せず、元不足または重複診断を残す。
		if( sourceMatches != 1U) {
			reference.error =
				nativeErrorFromWin32( sourceMatches > 1U ? ERROR_DUP_NAME : ERROR_NOT_SUPPORTED) ;
			return 0 ;
		}

		// 元source APIの未対応・MISSINGを今回のtarget一致で成功へ取り消さない。
		if( observedSource->location != MaintenanceInfFileLocation::LOCATED) {
			reference.relativePath = observedSource->relativePath ;
			reference.location	   = observedSource->location ;
			reference.error		   = observedSource->error ;
			return 0 ;
		}
	}

	MaintenanceInfFileReference source = reference ;	// binary原値を保持するための一時source照会。
	source.target					   = selected->source ;
	const auto requiredSubdirectory =
		selectedDirectory->dirid == 13U
			? std::optional<std::wstring_view>{selectedDirectory->subdirectory}
			: std::nullopt ;	// SourceDisksFiles subdirだけの追加条件。
	const NativeError error =
		locateMaintenanceSource( inf, workspace, entries, parent, false, source,
								requiredSubdirectory) ;	// 元媒体と固定member。
	// sourceの不正・容量・重大な読取失敗は位置未知へ弱めない。
	if( error != 0) {
		return error ;
	}

	reference.relativePath = std::move( source.relativePath) ;
	reference.location	   = source.location ;
	reference.error		   = source.error ;
	return 0 ;
}

/**
 * @brief 全元値とnamed13／成功済み元sourceだけから位置stageの一意source indexを返す。
 * @param[in,out] proof 同HINF・同元byteの私有証明。allocation失敗では撤回する。
 * @param[in] rawRow 元dataまたは制御行index。
 * @param[in] field 元全target field番号。
 * @param[in] target coreが一度だけ読んだAPI全値。
 * @param[in] bindings 同じqueueの到達named copyと元metadata。
 * @param[in] sources 既に観測済みの元source用途。再API取得しない。
 * @return 全値・一意source成立時の元観測index。未知では未結合値。
 * @note prefix／basename／dot除去を成功根拠にせず、同leafの不確定候補を保持する。
 */
[[nodiscard]] std::size_t locateMaintenanceCompleteValueSource(
	MaintenanceInfByteProof &proof, std::size_t rawRow, std::size_t field, std::wstring_view target,
	std::span<const MaintenanceCopyBinding>		 bindings,
	std::span<const MaintenanceInfFileReference> sources)
{
	// 未読fieldの行をcaller成功で補完しない。
	if( !proof.verified( rawRow)) {
		return NO_MAINTENANCE_RAW_ROW ;
	}

	std::wstring expanded ;	// 原全targetだけの短命な独立一段展開。
	// 私有展開失敗は元Uを保持する。
	if( !proof.value( rawRow, field, expanded)) {
		return NO_MAINTENANCE_RAW_ROW ;
	}

	const auto separator = target.find_last_of( L"/\\") ;	// 未確定同leafの診断にだけ使用する。
	const auto leaf =
		// 成功比較には使わない。
		target.substr( separator == target.npos ? 0U : separator + 1U) ;
	const MaintenanceCopyBinding *selected{} ;	// 全候補の一意確認後だけ借用する。
	std::size_t					  matches{} ;	// 原data全値に一致した全binding数。
	bool						  uncertain{} ;	// 同leafの不確定候補を成功集合から捨てない。
	// 全到達named行の元全targetだけを比較し、任意directoryへ探索しない。
	for( const auto &binding : bindings) {
		const auto &copy	  = *binding.copy ;		// 同queueで取得済みの元copy。
		const auto *directory = binding.directory ;	// 一意named metadataのみ。
		// 元copy／全metadata不足、空subdir、renameを私有成功へ救済しない。
		if( binding.error != 0 || directory == nullptr || directory->dirid != 13U ||
		   directory->subdirectory.empty() || !directory->targetComplete ||
		   !proof.verified( copy.rawRow) || !proof.verified( directory->rawRow) ||
		   proof.get( copy.rawRow).key.size != 0U || copy.destination != copy.source) {
			uncertain = uncertain || stringsEqual( copy.destination, leaf) ;
			continue ;
		}

		// 原data全体と同named raw／full target、API全値を完全一致させる。
		if( (expanded == binding.rawTarget || expanded == binding.fullTarget) &&
		   (target == binding.rawTarget || target == binding.fullTarget)) {
			++matches ;
			selected = &binding ;
		}
	}

	// 部分一致・同leafの不確定候補や全target重複を一意成功へ絞らない。
	if( matches != 1U || uncertain || selected == nullptr) {
		return NO_MAINTENANCE_RAW_ROW ;
	}

	std::size_t sourceFile = NO_MAINTENANCE_RAW_ROW ;	// 再読取しない元source用途index。
	std::size_t sourceMatches{} ;						// 選択x64 source全行の同名数。
	// 元metadata用途だけを数え、copy用途とdedup集合をsource一意性へ転用しない。
	for( std::size_t index = 0U; index < sources.size(); ++index) {
		const auto &source = sources[index] ;	// 同期借用する元位置観測。
		// 全source名が一致する全行を残す。
		if( stringsEqual( source.directive, L"SourceDisksFiles") &&
		   stringsEqual( source.target, selected->copy->source)) {
			++sourceMatches ;
			sourceFile = index ;
		}
	}

	// missing／duplicate／未観測sourceは元Uを保持する。
	if( sourceMatches != 1U || sourceFile >= sources.size() ||
	   sources[sourceFile].location != MaintenanceInfFileLocation::LOCATED ||
	   sources[sourceFile].error != 0) {
		return NO_MAINTENANCE_RAW_ROW ;
	}

	const auto source = std::ranges::find_if( proof.sourceRows, [sourceFile]( const auto &row) {
		return row.second == sourceFile ;
	}) ; // 同原source API観測の私有rowだけへ結ぶ。
	// 元sourceのkeyと厳密全aux fieldが揃っていることを要求する。
	if( source == proof.sourceRows.end() || !proof.verified( source->first) ||
	   proof.get( source->first).fields < 2U) {
		return NO_MAINTENANCE_RAW_ROW ;
	}

	const std::size_t sourceRow = source->first ;	// allocation後のvector借用を残さないindex。
	std::wstring	  subdirectory ;				// 同rowの原source subdir全値。
	// 元SourceDisksFilesとDestinationDirsの非空subdir全値を完全一致させる。
	if( !proof.value( sourceRow, 2U, subdirectory) ||
	   subdirectory != selected->directory->subdirectory) {
		return NO_MAINTENANCE_RAW_ROW ;
	}

	return sourceFile ;
}

/**
 * @brief 有限保持量を確認して原用途と位置を棚卸しへ加える。
 * @param[in,out] references 同じ一INFの累積観測。
 * @param[in] file 全観測値を所有する一file用途。
 * @return 追加成功0、保持量超過のHRESULT。
 */
[[nodiscard]] NativeError appendMaintenanceFile( MaintenanceInfReferences   &references,
												MaintenanceInfFileReference file)
{
	// 不足行も分母に残し、過大な用途集合を切り捨てない。
	if( references.files.size() >= MAXIMUM_INSTALL_INVENTORY_ITEMS) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	// 位置未確定と欠落は全参照coverageの完了へ昇格させない。
	if( file.location != MaintenanceInfFileLocation::LOCATED) {
		references.referenceCoverage = MaintenanceInfReferenceCoverage::INCOMPLETE ;
	}

	// root／CAT以外の実在sourceだけを有限な署名member候補へ加える。
	if( file.location == MaintenanceInfFileLocation::LOCATED &&
	   !stringsEqual( file.relativePath, references.infRelativePath) &&
	   !stringsEqual( file.relativePath, references.catalogRelativePath)) {
		static_cast<void>( appendUnique( references.sourceFiles, std::wstring( file.relativePath))) ;
	}

	references.files.push_back( std::move( file)) ;
	return 0 ;
}
} // namespace

/** @see src/platform/official_driver_package.h 宣言側の契約を正本とする。 */
NativeError inspectMaintenanceInfReferences( const OfficialDownloadWorkspace	  &workspace,
											std::span<const OfficialZipEntry>  entries,
											std::wstring_view				   infRelativePath,
											std::span<const std::wstring>	   seeds,
											const OfficialInfInspectionPolicy &policy,
											MaintenanceInfReferences		  &references)
{
	references = {} ;
	try {
		const std::wstring path = workspace.path( infRelativePath) ;	// 保護領域の単独元位置。
		const auto entry = std::ranges::find_if( entries, [infRelativePath]( const auto &item) {
			return stringsEqual( item.relativePath, infRelativePath) ;
		}) ; // 閉じた元memberだけの同期借用。
		// 未固定・過大・重複入力と不正seedから参照集合を作らない。
		if( path.empty() || entries.empty() || entries.size() > 32'768U || entry == entries.end() ||
		   lowerExtension( infRelativePath) != L".inf" || entry->uncompressedSize == 0U ||
		   entry->uncompressedSize > 4U * 1024U * 1024U || seeds.size() > 1024U ||
		   policy.maximumSourceFiles == 0U || policy.maximumSourceFiles > 8192U ||
		   std::ranges::count_if( entries, [infRelativePath]( const auto &item) {
			   return stringsEqual( item.relativePath, infRelativePath) ;
		   }) != 1) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		MaintenanceInfByteProof byteProof ;	// HINFより前に構築し、HINF先closeを保持する。
		NativeError				error =
			// 元fileの一回のbyte snapshot。
			byteProof.open( path, infRelativePath, *entry) ;
		// snapshotの実size／hash不一致は既存全体拒否へ結ぶ。
		if( error != 0) {
			return error ;
		}

		error = verifyOfficialFileMetadata(
			path, {entry->uncompressedSize, entry->sha256}) ;	// 元byte照合。
		// 改変を部分参照の成功へ変換しない。
		if( error != 0) {
			return error ;
		}

		MaintenanceInfReferences observed ;	// 全体再確認後だけ公開するworker内所有物。
		observed.infRelativePath   = infRelativePath ;
		observed.referenceCoverage = MaintenanceInfReferenceCoverage::COMPLETE ;
		error					   = computeFileSha256( path, observed.infSha256) ;
		// 原hashを取得できない入力を解析しない。
		if( error != 0) {
			return error ;
		}

		error = byteProof.matchHash( observed.infSha256) ;
		// 同一snapshotと通常hashの不一致から部分結果を公開しない。
		if( error != 0) {
			return error ;
		}

		const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  nullptr)) ;	// scopeが単独所有しAppendしない。
		// 構文読取不能を空参照へ変換しない。
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		const auto	 separator = infRelativePath.find_last_of( L'\\') ;	// 安全な元親位置。
		const auto	 parent	   = separator == infRelativePath.npos
									 ? std::wstring_view{}
									 : infRelativePath.substr( 0U, separator) ;	// 呼出し中だけの借用。
		std::wstring catalog ;													// 現x64用CATの明示file名。
		error = readCatalogFile( inf.get(), catalog) ;
		// 依存資料のCAT未宣言を構文不正へ潰さず、その他の読取失敗は保持する。
		if( error != 0 && error != nativeErrorFromWin32( ERROR_LINE_NOT_FOUND) &&
		   error != nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND)) {
			return error ;
		}

		observed.catalogRelativePath =
			catalog.empty() ? std::wstring{} : joinRelativePath( parent, catalog) ;
		const auto cat = std::ranges::find_if( entries, [&observed]( const auto &item) {
			return stringsEqual( item.relativePath, observed.catalogRelativePath) ;
		}) ; // 元CAT位置と有限sizeの確認。
		// 明示CATの不正位置と同位置衝突を未確認へ弱めない。
		if( !catalog.empty() && (workspace.path( observed.catalogRelativePath).empty() ||
								std::ranges::count_if( entries, [&observed]( const auto &item) {
									return stringsEqual( item.relativePath,
														observed.catalogRelativePath) ;
								}) > 1)) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		// 実在CATの一file上限を後段抽出前に維持する。
		if( cat != entries.end() &&
		   (cat->uncompressedSize == 0U || cat->uncompressedSize > 32U * 1024U * 1024U)) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		observed.files.push_back( {L"Version", L"INF", std::wstring( infRelativePath),
								  std::wstring( infRelativePath),
								  MaintenanceInfFileLocation::LOCATED, 0}) ;
		error = appendMaintenanceFile(
			observed,
			{L"Version", L"CatalogFile", catalog, observed.catalogRelativePath,
			 catalog.empty() ? MaintenanceInfFileLocation::UNSUPPORTED
							 : (cat == entries.end() ? MaintenanceInfFileLocation::MISSING
													 : MaintenanceInfFileLocation::LOCATED),
			 catalog.empty()
				 ? nativeErrorFromWin32( ERROR_LINE_NOT_FOUND)
				 : (cat == entries.end() ? nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) : 0)}) ;
		// CAT不足も有限保持量へ含め、空閉包を合格にしない。
		if( error != 0) {
			return error ;
		}

		MaintenanceStructureBudget budget ;			// Version・source・全seedの共通予算。
		LONG					   versionCount{} ;	// Versionの確定行数。
		error = maintenanceLineCount( inf.get(), L"Version", versionCount) ;
		// 必須Versionの不在と読取失敗を部分成功にしない。
		if( error != 0 || versionCount <= 0 || versionCount > 4096L) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// Queue外のLayoutFileも同じ有限行予算で観測する。
		for( LONG row = 0L; row < versionCount; ++row) {
			INFCONTEXT line{} ;	// Versionの原行。
			error = maintenanceLineAt( inf.get(), L"Version", row, line) ;
			// 途中失敗と過多fieldを正常終端へ変換しない。
			if( error != 0 || SetupGetFieldCount( &line) > 64U) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			++budget.lines ;
			std::wstring key ;	// Versionの原directive。
			error = readMaintenanceField( line, 0U, key) ;
			// 読取不能keyを無関係行として飛ばさない。
			if( error != 0) {
				return error ;
			}

			// LayoutFileの全原参照を未解決の用途として保持する。
			if( stringsEqual( key, L"LayoutFile")) {
				const DWORD fields = SetupGetFieldCount( &line) ;	// 原参照数。
				// 明示空も無参照へ変換せず一観測として残す。
				for( DWORD field = 1U; field <= (std::max)( fields, DWORD{1U}); ++field) {
					std::wstring target ;	// 原LayoutFile値。
					error = fields == 0U ? 0 : readMaintenanceField( line, field, target) ;
					// 読取不能の参照を空用途へ変換しない。
					if( error != 0) {
						return error ;
					}

					error = appendMaintenanceFile( observed,
												  {L"Version",
												   key,
												   std::move( target),
												   {},
												   MaintenanceInfFileLocation::UNSUPPORTED,
												   nativeErrorFromWin32( ERROR_NOT_SUPPORTED)}) ;
					// 多値参照も保持上限を回避させない。
					if( error != 0) {
						return error ;
					}
				}
			}
		}

		std::wstring sourceSection = L"SourceDisksFiles.amd64" ;	// x64を先に照会する。
		LONG		 sourceCount{} ;								// 不在と明示空を区別する。
		error = maintenanceLineCount( inf.get(), sourceSection, sourceCount) ;
		// API失敗をsource不在にしない。
		if( error != 0) {
			return error ;
		}

		// x64節不在の場合だけ共通節を照会する。
		if( sourceCount < 0) {
			sourceSection = L"SourceDisksFiles" ;
			error		  = maintenanceLineCount( inf.get(), sourceSection, sourceCount) ;
			// 共通節の読取失敗を不在へ弱めない。
			if( error != 0) {
				return error ;
			}
		}

		observed.sourceSectionPresent = sourceCount >= 0 ;
		// source全行と到達節の共同予算を加算前に確認する。
		if( sourceCount > 0 && static_cast<std::size_t>( sourceCount) > 4096U - budget.lines) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		// 通常source宣言を全部残し、使用先だけで元source集合を縮小しない。
		for( LONG row = 0L; row < sourceCount; ++row) {
			INFCONTEXT line{} ;	// Sourceの原行。
			error = maintenanceLineAt( inf.get(), sourceSection, row, line) ;
			// 確定行数の途中の失敗を空集合へ変換しない。
			if( error != 0) {
				return error ;
			}

			++budget.lines ;
			MaintenanceInfFileReference file{sourceSection, L"SourceDisksFiles"} ;	// 元用途。
			// source行の余剰fieldも有限上限を迂回させない。
			const DWORD fields = SetupGetFieldCount( &line) ;	// 元sourceの厳密全field数。
			// 元field数の上限をprivate追加fieldとは独立に維持する。
			if( fields > MAXIMUM_INSTALL_INVENTORY_FIELDS) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			byteProof.capacity( observed.files.size() + budget.fileUses + budget.references) ;
			const auto			 rawRow = byteProof.row( sourceSection, row, sourceCount,
														fields) ;	// 元x64優先選択と同ordinal。
			MaintenanceFieldRead keyRead{} ;						// 元source keyだけの既存取得。
			error = readMaintenanceField( line, 0U, file.target,
										 byteProof.active() ? &keyRead : nullptr) ;
			// 元keyの成功結果だけをextra観測より前に捕捉する。
			if( error == 0) {
				byteProof.field( rawRow, 0U, file.target, keyRead) ;
			}

			// file名取得に成功した場合だけ安全なsource位置を照会する。
			if( error == 0) {
				error = locateMaintenanceSource( inf.get(), workspace, entries, parent, false, file) ;
			}

			// 不正媒体位置と重大な読取失敗をsourceなしへ変換しない。
			if( error != 0) {
				return error ;
			}

			// 元位置照会が成功してから未取得auxだけを同contextで一度補う。
			byteProof.extra( line, rawRow, 1U, fields) ;
			byteProof.source( rawRow, observed.files.size()) ;

			error = appendMaintenanceFile( observed, std::move( file)) ;
			// 不足行を切り捨てて閉包合格を作らない。
			if( error != 0) {
				return error ;
			}

			byteProof.capacity( observed.files.size() + budget.fileUses + budget.references) ;
		}

		std::vector<std::wstring> presentSeeds ;	// 明示名だけの実在seed。
		// 不在seedも観測へ残し、実在節だけをlocal queueへ渡す。
		for( const auto &seed : seeds) {
			LONG count{} ;	// 原seedの存在と行数。
			// path的なseed名を原節として解釈しない。
			if( !validInstallInventorySectionName( seed)) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			error = maintenanceLineCount( inf.get(), seed, count) ;
			// 不在以外のAPI失敗を欠落へ変換しない。
			if( error != 0) {
				return error ;
			}

			// 実在seedだけを一意に加え、独自suffixを使わない。
			if( count >= 0) {
				static_cast<void>( appendUnique( presentSeeds, std::wstring( seed))) ;
			} else {
				error = appendMaintenanceFile( observed,
											  {seed,
											   L"SeedSection",
											   seed,
											   {},
											   MaintenanceInfFileLocation::MISSING,
											   nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND)}) ;
				// 不在seedの保持数も有限に制限する。
				if( error != 0) {
					return error ;
				}
			}
		}

		MaintenanceInfInstallStructure				install ;			// 明示seedだけの到達local観測。
		std::vector<MaintenanceCopyDestination>		copies ;			// 同じ読取済みnamed行の私有sidecar。
		std::vector<MaintenanceEventLogMarkerProof> eventLogProofs ;	// このreferenceだけの同行証明。
		// Includeのみの資料もsource／CATを観測し、seedを捏造しない。
		if( !presentSeeds.empty()) {
			install.inventory.selectedInstallSection = presentSeeds.front() ;
			error = inspectMaintenanceInstallStructure( inf.get(), workspace, entries, parent,
													   budget, install, presentSeeds, &copies,
													   &eventLogProofs, &byteProof) ;
			// 全体読取・容量失敗後に部分local閉包を返さない。
			if( error != 0) {
				return error ;
			}
		}

		std::vector<MaintenanceDestinationDirectory> directories ;	// defaultを含めない元named根拠。
		error = readMaintenanceDestinationDirectories( inf.get(), workspace, copies, budget,
													  install.inventory, directories, &byteProof) ;
		// metadataの不正・容量・読取失敗後に部分参照を返さない。
		if( error != 0) {
			return error ;
		}

		std::vector<MaintenanceCopyBinding>
			bindings ;	// 構築完了vectorだけを同scopeで借用するcache。
		error = bindMaintenanceCopyDestinations( workspace, copies, directories, bindings) ;
		// 私有cacheの不正・容量失敗後に部分参照を返さない。
		if( error != 0) {
			return error ;
		}

		const std::size_t sourceObservationCount =
			// 元sourceを含む構築済み観測範囲。
			observed.files.size() ;
		byteProof.capacity( observed.files.size() + budget.effects + budget.references +
						   budget.services + budget.issues + budget.fileUses + budget.coverageGaps +
						   copies.size() + directories.size() + bindings.size() +
						   eventLogProofs.size()) ;
		bool fullControlTargets =
			byteProof.active() &&
			install.parser.state ==
				MaintenanceInspectionState::PASSED ;	// 後続associated矛盾も最後に確認する。
		// 同原制御行の元用途だけを順に全比較する。typed一時用途をappendしない。
		for( std::size_t index = 0U; byteProof.active() && index < byteProof.controlUses.size();
			++index) {
			const auto control =
				byteProof.controlUses[index] ;									// private失効に備えてindexを値で保持する。
			const auto field   = byteProof.get( control.first).deferredField ;	// 元deferred field。
			fullControlTargets = fullControlTargets && control.second < install.fileUses.size() &&
								 locateMaintenanceCompleteValueSource(
									 byteProof, control.first, field,
									 install.fileUses[control.second].target, bindings,
									 std::span<const MaintenanceInfFileReference>( observed.files)
										 .first( sourceObservationCount)) < sourceObservationCount ;
		}

		// 原data一件の位置候補だけをstageし、後続core／byte確認前に反映しない。
		for( std::size_t index = 0U;
			byteProof.active() && fullControlTargets && index < byteProof.data.size(); ++index) {
			const auto candidate = byteProof.data[index] ;	// private allocation失敗後に借用しない。
			// 同行最終callerの未成立は元Uを保持する。
			if( !candidate.caller || candidate.use >= install.fileUses.size()) {
				continue ;
			}

			const auto source = locateMaintenanceCompleteValueSource(
				byteProof, candidate.row, 5U, install.fileUses[candidate.use].target, bindings,
				std::span<const MaintenanceInfFileReference>( observed.files)
					.first( sourceObservationCount)) ;	// 同元sourceのみ。
			// 私有失効後のdata vectorへ書かない。
			if( byteProof.active()) {
				byteProof.data[index].sourceFile = source ;
			}
		}

		// 同期indexの保持も共同項目上限へ含め、限界時は分離を保留する。
		if( eventLogProofs.size() * 2U + install.fileUses.size() * 2U +
			   install.inventory.coverageGaps.size() * 2U + observed.files.size() >
		   MAXIMUM_INSTALL_INVENTORY_ITEMS) {
			eventLogProofs.clear() ;
		}

		std::vector<std::size_t> useFiles ;	// 元fileUses indexから最終用途indexへの私有結合。
		std::vector<std::size_t> gapFiles ;	// 元registry gapからfallback用途への私有結合。
		// 証明が残る場合だけ有限indexを確保し、通常用途の保持量を増設しない。
		if( !eventLogProofs.empty()) {
			useFiles.resize( install.fileUses.size(), NO_MAINTENANCE_EVENTLOG_INDEX) ;
			gapFiles.resize( install.inventory.coverageGaps.size(), NO_MAINTENANCE_EVENTLOG_INDEX) ;
		}

		// 原用途ごとにsource位置を対応させ、借用終了後だけ用途をappendする。
		for( std::size_t useOrdinal = 0U; useOrdinal < install.fileUses.size(); ++useOrdinal) {
			const auto &use = install.fileUses[useOrdinal] ;	// 同行proofを名前だけで結び直さない。
			MaintenanceInfFileReference file{use.section, use.directive,
											 use.target} ;	// 元用途copy。
			const bool					directCopy = stringsEqual( use.directive, L"CopyFiles") &&
									// 直接source名の表記。
									file.target.starts_with( L"@") ;
			// File-list名そのものをpayloadとして照会しない。
			if( stringsEqual( use.directive, L"CopyFiles") && !directCopy) {
				continue ;
			}

			// 直接CopyFilesの@だけを除き、source名の安全境界は維持する。
			if( directCopy) {
				file.target.erase( 0U, 1U) ;
			}

			const bool binary = stringsEqual( use.directive, L"ServiceBinary") ||
								stringsEqual( use.directive, L"UmdfServiceBinary") ||
								// 既知のfile用途。
								stringsEqual( use.directive, L"EventMessageFile") ;
			// package sourceに結べる既知用途だけを位置解決する。
			if( directCopy || binary || stringsEqual( use.directive, L"CopyFileSource")) {
				error = binary ? locateMaintenanceBinarySource(
									 inf.get(), workspace, entries, parent, bindings,
									 std::span<const MaintenanceInfFileReference>( observed.files)
										 .first( sourceObservationCount),
									 file)
							   : locateMaintenanceSource( inf.get(), workspace, entries, parent,
														 false, file) ;
				// 不正位置・読取失敗を用途未対応へ弱めない。
				if( error != 0) {
					return error ;
				}
			} else {
				file.location = MaintenanceInfFileLocation::UNSUPPORTED ;
				file.error	  = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			error = appendMaintenanceFile( observed, std::move( file)) ;
			// 原用途を切り捨てて参照完了にしない。
			if( error != 0) {
				return error ;
			}

			// 同元use一件の最終append位置だけを結び、typed用途を増やさない。
			if( byteProof.active()) {
				const auto candidate = std::ranges::lower_bound(
					byteProof.data, useOrdinal, {},
					&MaintenanceRegistryDataProof::use) ;	// 原use順の一意indexだけを検索する。
				// 元use ordinalの完全一致だけを最後の位置反映へ渡す。
				if( candidate != byteProof.data.end() && candidate->use == useOrdinal) {
					candidate->file = observed.files.size() - 1U ;
				}

				byteProof.capacity( observed.files.size() + budget.effects + budget.references +
								   budget.services + budget.issues + budget.fileUses +
								   budget.coverageGaps + copies.size() + directories.size() +
								   bindings.size() + eventLogProofs.size() + useFiles.size() +
								   gapFiles.size()) ;
			}

			// 追加成功した元用途の位置だけを保持し、skip行へ位置を捏造しない。
			if( !useFiles.empty()) {
				useFiles[useOrdinal] = observed.files.size() - 1U ;
			}
		}

		// 欠落local節はNeeds以外の具体的な未解決用途へ残す。
		for( const auto &reference : install.inventory.references) {
			// Needsは依存核が同節Includeと共に解決し、local不在だけで不正としない。
			if( reference.kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
			   !reference.targetPresent && !stringsEqual( reference.directive, L"Needs")) {
				error = appendMaintenanceFile( observed,
											  {reference.section,
											   reference.directive,
											   reference.target,
											   {},
											   MaintenanceInfFileLocation::MISSING,
											   nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND)}) ;
				// 欠落用途も保持上限へ含める。
				if( error != 0) {
					return error ;
				}
			}
		}

		// sourceなしregistryは作用未評価と未知file用途を区別して不足を具体的に残す。
		for( std::size_t gapOrdinal = 0U; gapOrdinal < install.inventory.coverageGaps.size();
			++gapOrdinal) {
			const auto &gap =
				install.inventory.coverageGaps[gapOrdinal] ;	// 元fallbackの一意ordinal。
			// 通常sourceの証拠を単なるregistry作用未評価で取り消さない。
			if( !observed.sourceSectionPresent &&
			   gap.kind == OfficialInfInstallCoverageKind::REGISTRY_SCOPE_NOT_ASSESSED) {
				error =
					appendMaintenanceFile( observed, {gap.section,
													 L"RegistryFileUsesNotAssessed",
													 {},
													 {},
													 MaintenanceInfFileLocation::UNSUPPORTED,
													 nativeErrorFromWin32( ERROR_NOT_SUPPORTED)}) ;
				// 不足行の累積保持量も有限にする。
				if( error != 0) {
					return error ;
				}

				// 同eventlog子節の元gapに対応したappend済みUだけを証明へ使う。
				if( !gapFiles.empty()) {
					gapFiles[gapOrdinal] = observed.files.size() - 1U ;
				}
			}
		}

		// 全fallback append後に同referenceの独立Uを確認し、同行親一件だけを分離する。
		if( !eventLogProofs.empty() &&
		   observed.referenceCoverage == MaintenanceInfReferenceCoverage::INCOMPLETE &&
		   useFiles.size() + gapFiles.size() + eventLogProofs.size() * 2U + observed.files.size() <=
			   MAXIMUM_INSTALL_INVENTORY_ITEMS) {
			std::vector<std::size_t> separated ;	// 証明済み親の最終index。上限は元proof数。
			// 各同行proofを二つの既存indexへ定数回結び、全親×全用途を再探索しない。
			for( const auto &proof : eventLogProofs) {
				const std::size_t marker = useFiles[proof.marker] ;	// 当該AddService行の元用途。
				const std::size_t child =
					proof.childUse != NO_MAINTENANCE_EVENTLOG_INDEX
						? useFiles[proof.childUse]
						: (proof.childGap != NO_MAINTENANCE_EVENTLOG_INDEX
							   ? gapFiles[proof.childGap]
							   : NO_MAINTENANCE_EVENTLOG_INDEX) ;	// 別節やSYSTEM不足を代用しない。
				// Appendされなかった子Uや同一用途を独立不足として認めない。
				if( marker >= observed.files.size() || child >= observed.files.size() ||
				   marker == child) {
					continue ;
				}

				const auto &parentFile = observed.files[marker] ;	// 行結合済みの元親。
				const auto &childFile  = observed.files[child] ;	// 同queueから来たappend済み子。
				// 新dataの位置成立を57の独立子Uとして便乗させず、元親markerを保持する。
				if( byteProof.active() &&
				   std::ranges::any_of( byteProof.data, [child]( const auto &candidate) {
					   return candidate.file == child &&
							  candidate.sourceFile != NO_MAINTENANCE_RAW_ROW ;
				   })) {
					continue ;
				}

				// 元Uのkind・HRESULTを保持できる形だけを分離し、file充足へ昇格させない。
				if( stringsEqual( parentFile.directive, L"AddService") &&
				   parentFile.location == MaintenanceInfFileLocation::UNSUPPORTED &&
				   parentFile.error == nativeErrorFromWin32( ERROR_NOT_SUPPORTED) &&
				   (stringsEqual( childFile.directive, L"RegistryFileUseNotAssessed") ||
					stringsEqual( childFile.directive, L"RegistryFileUsesNotAssessed")) &&
				   childFile.location == MaintenanceInfFileLocation::UNSUPPORTED &&
				   childFile.error == nativeErrorFromWin32( ERROR_NOT_SUPPORTED)) {
					separated.push_back( marker) ;
				}
			}

			// 元順序filter用の有限index。
			std::ranges::sort( separated) ;
			// 親だけの分離によるordinal移動を元data一件のindexへ反映する。
			if( byteProof.active()) {
				// 元順序のprivate data indexだけを一度ずつ補正する。
				for( auto &candidate : byteProof.data) {
					// 未appendの用途へ位置indexを補完しない。
					if( candidate.file < observed.files.size()) {
						candidate.file -= static_cast<std::size_t>(
							std::ranges::lower_bound( separated, candidate.file) -
							separated.begin()) ;
					}
				}
			}

			std::size_t fileOrdinal{} ;			// 元最終用途のordinal。survivorの相対順序を維持する。
			std::size_t separatedOrdinal{} ;	// 同行親の昇順indexだけを一度ずつ消費する。
			// 子Uは分離集合に含めず、元coverage・inventory・contentを変更しない。
			std::erase_if( observed.files,
						  [&separated, &fileOrdinal, &separatedOrdinal]( const auto &) {
							  const bool remove = separatedOrdinal < separated.size() &&
												  separated[separatedOrdinal] ==
													  fileOrdinal ;	// 文字列照合filterはしない。
							  ++fileOrdinal ;
							  // 証明済み親だけを一件消費し、未証明用途は全て保持する。
							  if( remove) {
								  ++separatedOrdinal ;
							  }

							  return remove ;
						  }) ;
		}

		// 従来の参照分類を同じ正本集合で維持し、内容専用EXEだけを限定受理する。
		for( const auto &file : observed.sourceFiles) {
			const std::wstring extension = lowerExtension( file) ;	// 元参照fileの拡張子。
			// 未対応program／archive／firmwareをnull認識で許可しない。
			if( std::ranges::find( REJECTED_REFERENCED_EXTENSIONS, extension) !=
				   REJECTED_REFERENCED_EXTENSIONS.end() &&
			   !(extension == L".exe" && policy.allowReferencedExecutablesForContent)) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}
		}

		// 元policyの一INF参照数を新棚卸しでも維持する。
		if( observed.sourceFiles.size() > policy.maximumSourceFiles) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		observed.inventory				   = std::move( install.inventory) ;
		observed.inventory.infRelativePath = observed.infRelativePath ;
		observed.inventory.infSha256	   = observed.infSha256 ;
		observed.inventory.scannedLines +=
			static_cast<std::uint32_t>( versionCount + (std::max)( sourceCount, 0L)) ;
		error = verifyOfficialFileMetadata( path, {entry->uncompressedSize, observed.infSha256}) ;
		// 終了時の元byte差は部分結果を全て破棄する。
		if( error != 0) {
			return error ;
		}

		byteProof.capacity( observed.files.size() + budget.effects + budget.references +
						   budget.services + budget.issues + budget.fileUses + budget.coverageGaps +
						   copies.size() + directories.size() + bindings.size() +
						   eventLogProofs.size() + useFiles.size() + gapFiles.size()) ;
		// 元読取・容量・全byte確認の成功後だけ元data位置を最後に反映する。
		if( byteProof.active()) {
			try {
				// 一意全targetが成立した元data用途だけを元順序で反映する。
				for( const auto &candidate : byteProof.data) {
					// 私有保留と未appendは元identity／U／HRESULTをそのまま保持する。
					if( candidate.file >= observed.files.size() ||
					   candidate.sourceFile >= sourceObservationCount) {
						continue ;
					}

					auto &file		  = observed.files[candidate.file] ;	// 元registry data用途だけ。
					file.relativePath = observed.files[candidate.sourceFile].relativePath ;
					file.location	  = MaintenanceInfFileLocation::LOCATED ;
					file.error		  = 0 ;
				}
			} catch( const std::bad_alloc &) {
				// 私有位置反映のallocation失敗では全stageを撤回し、正常元結果を全体拒否しない。
				for( const auto &candidate : byteProof.data) {
					// 変更可能だった元dataだけを元Uへ戻す。
					if( candidate.file < observed.files.size()) {
						auto &file = observed.files[candidate.file] ;	// 元用途のidentityは保持する。
						file.relativePath.clear() ;
						file.location = MaintenanceInfFileLocation::UNSUPPORTED ;
						file.error	  = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
					}
				}

				byteProof.disable() ;
			}
		}

		references = std::move( observed) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( const std::length_error &) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}
}

NativeError readOfficialInfSourceDirectories( void *inf, const std::wstring &fileName,
											 std::wstring &sourceDirectory,
											 std::wstring &mediaDirectory)
{
	return readInfSourceDirectories( inf, fileName, sourceDirectory, mediaDirectory) ;
}
} // namespace drivercrate
