//------------------------------------------------------------------------------
/**
 * @file official_file_verifier.cpp
 * @brief 公式配布file共通検証実装。
 * @version 01.12.00
 * @date 2026/09/23
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  XML署名publisher検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  署名XMLのUTF-8 BOM対応。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  CAT member検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/23  公開SHA-512とSHA-256を有限stream・例外回収付き処理で共有。
 * Ver.01.02.00 Shunji Ogawa  2026/09/23  全区間取得接続と公式module根拠付き許諾境界を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/25  収集metadata専用の8 MiB hash上限を分離。
 * Ver.01.04.00 Shunji Ogawa  2026/10/06  原container専用の128 MiB hash入口を分離。
 * Ver.01.05.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.06.00 Shunji Ogawa  2026/10/12  完全file hashと同rootを二recordの内部署名表へ結合。
 * Ver.01.07.00 Shunji Ogawa  2026/10/12  別基本INFの完全CAT/member集合と実rootを個別固定。
 * Ver.01.08.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.08.01 Shunji Ogawa  2026/10/12  default/delete宣言の所有権と非実行契約を補足。
 * Ver.01.09.00 Shunji Ogawa  2026/10/13  内部CAT fixtureの同root別INF-owner照合を厳密化。
 * Ver.01.10.00 Shunji Ogawa  2026/10/13  内部CATの安全相対memberを保護root・全位置・元owner/hashへ結合。
 * Ver.01.11.00 Shunji Ogawa  2026/10/15  内部試験factoryだけをarchive128/129境界の完全入力へ拡張。
 * Ver.01.11.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.12.00 Shunji Ogawa  2026/10/17 同一Authenticode実装に明示cached-only入口を追加。
 * </pre>
 *
 * @note Windows CNGとWinTrustを使用し、Provider固有値をpolicyとして受け取ります。
 */
//------------------------------------------------------------------------------

#include "platform/official_file_verifier.h"
#include "platform/driver_package_signature_internal.h"

// Windows.hはWinCryptおよびWinTrustの基本型より先に必要である。
// clang-format off
#include <Windows.h>
#include <Softpub.h>
#include <bcrypt.h>
#include <cryptxml.h>
#include <mscat.h>
#include <wincrypt.h>
#include <wintrust.h>
// clang-format on

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view XML_CANONICALIZATION_ALGORITHM =
	L"http://www.w3.org/TR/2001/REC-xml-c14n-20010315" ;	// 許可C14N URI。
constexpr std::wstring_view XML_SIGNATURE_ALGORITHM =
	L"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" ;	// 許可署名algorithm URI。
constexpr std::wstring_view XML_DIGEST_ALGORITHM =
	L"http://www.w3.org/2001/04/xmlenc#sha256" ;	// 許可digest algorithm URI。
constexpr std::wstring_view XML_ENVELOPED_TRANSFORM =
	L"http://www.w3.org/2000/09/xmldsig#enveloped-signature" ;	// 許可transform URI。
constexpr DWORD SHA256_HASH_BYTES = 32U ;						// Catalog memberに要求するSHA-256 byte数。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief 遅延解決したCryptCATAdminAcquireContext2を、Windows標準の署名のまま呼び出す関数型。
 */
using AcquireCatalogContext = BOOL( WINAPI *)( HCATADMIN *, const GUID *, PCWSTR,
											 PCCERT_STRONG_SIGN_PARA, DWORD) ;
/**
 * @brief 遅延解決したCryptCATAdminCalcHashFromFileHandle2を、Windows標準の署名のまま呼び出す関数型。
 */
using CalculateCatalogHash = BOOL( WINAPI *)( HCATADMIN, HANDLE, DWORD *, BYTE *, DWORD) ;
/**
 * @brief 取得済みcatalog contextをCryptCATAdminReleaseContextへ返すWindows標準の関数型。
 */
using ReleaseCatalogContext = BOOL( WINAPI *)( HCATADMIN, DWORD) ;

/**
 * @brief WinTrust.dllとSHA-256 catalog administrator contextをscope内で所有する。
 */
class CatalogHashContext final {
public:
	/**
	 * @brief 外部resourceを取得しない空の初期状態を作成します。
	 */
	CatalogHashContext() = default ;

	//------------------------------------------------------------------------------
	/**
     * @brief Catalog hash contextを解放する。
     *
     * Contextを先に解放し、最後にsystem WinTrust moduleを閉じる。
     */
	//------------------------------------------------------------------------------
	~CatalogHashContext()
	{
		// contextと解放関数の両方がある場合だけcatalog管理contextを解放する。
		if( catalogAdmin_ != nullptr && release_ != nullptr) {
			static_cast<void>( release_( catalogAdmin_, 0)) ;
		}

		// 取得したWinTrust moduleだけを解放する。
		if( module_ != nullptr) {
			static_cast<void>( FreeLibrary( module_)) ;
		}
	}

	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	CatalogHashContext( const CatalogHashContext &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	CatalogHashContext &operator=( const CatalogHashContext &) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	CatalogHashContext( CatalogHashContext &&) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	CatalogHashContext		 &operator=( CatalogHashContext &&) = delete ;

	//------------------------------------------------------------------------------
	/**
	 * @brief Catalog hash contextを初期化する。
	 * System32のWinTrust.dllだけを読み込み、現在OSのstrong-sign policyを満たすdriver用contextを一度だけ作成する。
	 * @return SHA-256 context作成成功時は0、失敗時はHRESULT。
	 */
	//------------------------------------------------------------------------------
	[[nodiscard]] NativeError initialize() ;

	//------------------------------------------------------------------------------
	/**
	 * @brief Fileのcatalog SHA-256を計算する。
	 * 初期化済みcontextと動的取得した公式APIだけを使用する。
	 * @param[in] file 読取り可能な非所有file handle。
	 * @param[out] hash 成功時の32-byte catalog hash。
	 * @return 成功時は0、WinTrustまたはallocation失敗時はHRESULT。
	 */
	//------------------------------------------------------------------------------
	[[nodiscard]] NativeError calculateHash( HANDLE file, std::vector<BYTE> &hash) const ;

	//------------------------------------------------------------------------------
	/**
     * @brief Catalog administrator contextを参照する。
     *
     * WinVerifyTrust呼出し中だけ非所有handleとして公開する。
     * @return 本instanceが所有するcontext handle。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] HCATADMIN	  get() const noexcept
	{
		return catalogAdmin_ ;
	}

private:
	/// FreeLibraryで閉じるsystem module。
	HMODULE				  module_{} ;
	/// Release関数で閉じるcatalog context。
	HCATADMIN			  catalogAdmin_{} ;
	/// WinTrust.dllから取得するcontext作成API。
	AcquireCatalogContext acquire_{} ;
	/// WinTrust.dllから取得するhash計算API。
	CalculateCatalogHash  calculate_{} ;
	/// WinTrust.dllから取得するcontext解放API。
	ReleaseCatalogContext release_{} ;
} ;

/**
 * @brief Win32 file handleをscope終了時に閉じる。
 */
class ReadOnlyVerificationFile final {
public:
	//------------------------------------------------------------------------------
	/**
     * @brief 読取り専用検証fileを所有する。
     *
     * Hash計算からtrust検証終了までfileを置換不能にする。
     *
     * @param[in] handle CloseHandleで閉じる所有file handle。
     */
	//------------------------------------------------------------------------------
	explicit ReadOnlyVerificationFile( const HANDLE handle) noexcept : handle_( handle)
	{
	}

	//------------------------------------------------------------------------------
	/**
     * @brief 読取り専用検証fileを閉じる。
     *
     * 有効な所有handleだけを一度閉じる。
     */
	//------------------------------------------------------------------------------
	~ReadOnlyVerificationFile()
	{
		// 有効な所有file handleだけを閉じる。
		if( handle_ != INVALID_HANDLE_VALUE) {
			static_cast<void>( CloseHandle( handle_)) ;
		}
	}

	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	ReadOnlyVerificationFile( const ReadOnlyVerificationFile &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	ReadOnlyVerificationFile &operator=( const ReadOnlyVerificationFile &) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	ReadOnlyVerificationFile( ReadOnlyVerificationFile &&) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	ReadOnlyVerificationFile &operator=( ReadOnlyVerificationFile &&) = delete ;

	//------------------------------------------------------------------------------
	/**
     * @brief 読取り専用検証file handleを参照する。
     *
     * 所有権を移さず、現在のhashとtrust検証だけへ使用する。
     * @return 本instanceが所有するfile handle。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] HANDLE	  get() const noexcept
	{
		return handle_ ;
	}

private:
	/// Destructorで閉じる所有file handle。
	HANDLE handle_{INVALID_HANDLE_VALUE} ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief WinTrust.dllのprocedureを型付きpointerへ取得する。
 *
 * FARPROCと対象function pointerの同一sizeをcompile時に確認し、未定義なobject/function pointer castを使用せず複写する。
 *
 * @param[in] module System32から読み込んだ非所有module handle。
 * @param[in] name Null終端のASCII export名。
 * @param[out] procedure 成功時の型付きprocedure pointer。
 * @return Exportが存在しpointerを取得できた場合は`true`。
 */
//------------------------------------------------------------------------------
template <typename Procedure>
[[nodiscard]] bool loadCatalogProcedure( const HMODULE module, const char *const name,
										Procedure &procedure) noexcept
{
	procedure = nullptr ;
	// moduleやprocedure名が欠ける要求を解決しない。
	if( module == nullptr || name == nullptr) {
		return false ;
	}

	const FARPROC address = GetProcAddress( module, name) ;	// 未型付けのexport address。
	// procedureが存在しない場合は型付きpointerを作らない。
	if( address == nullptr) {
		return false ;
	}

	static_assert( sizeof( procedure) == sizeof( address)) ;
	std::memcpy( &procedure, &address, sizeof( address)) ;
	return procedure != nullptr ;
}

/**
 * @brief CryptXMLへ検証対象文書を有限bufferから供給するcallback状態である。
 */
struct XmlDataProviderState {
	/// 呼出し中だけ有効な非所有XML先頭pointer。
	const BYTE *data{} ;
	/// 供給するXML全byte数。
	std::size_t size{} ;
	/// 次回供給するbyte offset。
	std::size_t position{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief CryptXMLへ参照文書の次のbyte群を供給する。
 *
 * Callback境界から例外を漏らさず、検証済みbuffer範囲だけを順序通り供給する。
 *
 * @param[in,out] statePointer 呼出し中有効なXmlDataProviderState。
 * @param[out] output requested byte以上のCryptXML所有buffer。
 * @param[in] requested CryptXMLが要求する最大byte数。
 * @param[out] read 実際に供給したbyte数。
 * @return 供給成功時S_OK、引数または状態不正時E_INVALIDARG。
 */
//------------------------------------------------------------------------------
HRESULT CALLBACK readXmlProvider( void *const statePointer, BYTE *const output,
								 const ULONG requested, ULONG *const read) noexcept
{
	// state、出力件数、要求量に対応するbufferのpointer契約を確認する。
	if( statePointer == nullptr || read == nullptr || (requested != 0 && output == nullptr)) {
		return E_INVALIDARG ;
	}

	// Win32 callbackが型なし状態pointerを要求する境界に限り、元の型へ戻す。
	auto &state = *reinterpret_cast<XmlDataProviderState *>( statePointer) ;	// Provider状態。
	// 読取り位置と入力bufferの整合性が崩れた参照状態を拒否する。
	if( state.position > state.size || (state.size != 0 && state.data == nullptr)) {
		return E_INVALIDARG ;
	}

	const std::size_t remaining = state.size - state.position ;						// 未供給byte数。
	const std::size_t count		= std::min<std::size_t>( remaining, requested) ;	// 今回供給数。
	// 実際に転送するbyteがある場合だけbufferをcopyする。
	if( count != 0) {
		std::memcpy( output, state.data + state.position, count) ;
	}

	state.position += count ;
	*read = static_cast<ULONG>( count) ;
	return S_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief CryptXML参照文書providerの利用終了を受理する。
 *
 * Bufferを所有しないため解放せず、CryptXMLの終了通知だけを検証する。
 *
 * @param[in] statePointer 呼出し中有効なXmlDataProviderState。
 * @return Stateが存在する場合S_OK、nullの場合E_INVALIDARG。
 */
//------------------------------------------------------------------------------
HRESULT CALLBACK closeXmlProvider( void *const statePointer) noexcept
{
	return statePointer == nullptr ? E_INVALIDARG : S_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをHRESULT bit patternへ変換する。
 *
 * 共通検証APIの失敗形式をProvider契約へ揃える。
 *
 * @param[in] error Win32 error code。
 * @return NativeErrorで保持するHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_file_verifier.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError CatalogHashContext::initialize()
{
	// 初期化済みの所有資源を上書きしないよう、重複初期化を拒否する。
	if( module_ != nullptr || catalogAdmin_ != nullptr) {
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}

	module_ = LoadLibraryExW( L"wintrust.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32) ;
	// 暗号 API の module を取得できなければ、loader の診断値を返す。
	if( module_ == nullptr) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 必要な catalog API が一つでも欠ける環境では検証を開始しない。
	if( !loadCatalogProcedure( module_, "CryptCATAdminAcquireContext2", acquire_) ||
	   !loadCatalogProcedure( module_, "CryptCATAdminCalcHashFromFileHandle2", calculate_) ||
	   !loadCatalogProcedure( module_, "CryptCATAdminReleaseContext", release_)) {
		return nativeErrorFromWin32( ERROR_PROC_NOT_FOUND) ;
	}

	CERT_STRONG_SIGN_PARA signingPolicy{} ;	// 現在OSのdriver署名強度policy。
	signingPolicy.cbSize	   = sizeof( signingPolicy) ;
	signingPolicy.dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE ;
	// Windows SDK構造のLPSTR fieldへ渡す、API呼出し中だけ有効な変更可能OID buffer。
	char strongSignOid[] = szOID_CERT_STRONG_SIGN_OS_CURRENT ;
	signingPolicy.pszOID = strongSignOid ;
	GUID subsystem		 = DRIVER_ACTION_VERIFY ;	// OS componentとthird-party driver用subsystem。
	// SHA-256 用の catalog context を確保できなければ、その失敗を返す。
	if( acquire_( &catalogAdmin_, &subsystem, BCRYPT_SHA256_ALGORITHM, &signingPolicy, 0) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_file_verifier.cpp 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError CatalogHashContext::calculateHash( const HANDLE file, std::vector<BYTE> &hash) const
{
	hash.clear() ;
	// 未初期化 context または無効な file handle では hash 計算を受理しない。
	if( catalogAdmin_ == nullptr || calculate_ == nullptr || file == INVALID_HANDLE_VALUE) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	DWORD required{} ;	// Catalog algorithmが要求するhash byte数。
	// Hash buffer の必要量を取得できなければ、API の診断値を返す。
	if( calculate_( catalogAdmin_, file, &required, nullptr, 0) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// SHA-256 と異なる digest 長は期待した検証方式と一致しないため拒否する。
	if( required != SHA256_HASH_BYTES) {
		return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	}

	try {
		hash.resize( required) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	DWORD actual = required ;	// 二回目のAPIが保存したhash byte数。
	// Hash 計算に失敗した場合は、部分的な出力を消して診断値を返す。
	if( calculate_( catalogAdmin_, file, &actual, hash.data(), 0) == FALSE) {
		hash.clear() ;
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 照会時と計算時の digest 長が一致しなければ、出力を破棄する。
	if( actual != required) {
		hash.clear() ;
		return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一fileを指定catalogのmemberとして検証する。
 *
 * 読取りhandleをtrust終了まで保持し、file置換とhash不一致をfail-closedで拒否する。
 *
 * @param[in] context 初期化済みSHA-256 catalog context。
 * @param[in] catalogPath 検証するCAT file絶対path。
 * @param[in] memberPath CATへ収録されるべきfile絶対path。
 * @return Member hashとcatalog trustが有効なら0、失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyCatalogMember( const CatalogHashContext &context,
											  const std::wstring	   &catalogPath,
											  const std::wstring	   &memberPath)
{
	const ReadOnlyVerificationFile file( CreateFileW(
		memberPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
		nullptr)) ;	// Trust終了まで保持するmember file。
	// Member file を開けなければ catalog との照合へ進まない。
	if( file.get() == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	FILE_ATTRIBUTE_TAG_INFO attributes{} ;	// Handleが指すfileのrace-free属性。
	// 開いた file の属性を確認できなければ、検証対象として受理しない。
	if( GetFileInformationByHandleEx( file.get(), FileAttributeTagInfo, &attributes,
									sizeof( attributes)) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 通常file検証でdirectoryとreparse経路を拒否する属性mask。
	constexpr DWORD REJECTED_ATTRIBUTES = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT ;
	// 許可しない属性を持つ member file は署名照合前に拒否する。
	if( (attributes.FileAttributes & REJECTED_ATTRIBUTES) != 0) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::vector<BYTE> hash ;												// Member fileのSHA-256。
	NativeError		  error = context.calculateHash( file.get(), hash) ;	// Hash計算結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	try {
		constexpr std::wstring_view HEX = L"0123456789ABCDEF" ;	// CAT tag用uppercase hex。
		std::wstring				memberTag ;					// HashをCAT member名へ変換した64桁tag。
		memberTag.reserve( hash.size() * 2U) ;
		// Catalog APIが要求する一byte二桁のuppercase reference tagを構築する。
		for( const BYTE byte : hash) {
			memberTag.push_back( HEX[(byte >> 4U) & 0x0fU]) ;
			memberTag.push_back( HEX[byte & 0x0fU]) ;
		}

		WINTRUST_CATALOG_INFO catalog{} ;	// WinTrustへ渡すCAT member情報。
		catalog.cbStruct			 = sizeof( catalog) ;
		catalog.pcwszCatalogFilePath = catalogPath.c_str() ;
		catalog.pcwszMemberTag		 = memberTag.c_str() ;
		catalog.pcwszMemberFilePath	 = memberPath.c_str() ;
		catalog.hMemberFile			 = file.get() ;
		catalog.pbCalculatedFileHash = hash.data() ;
		catalog.cbCalculatedFileHash = static_cast<DWORD>( hash.size()) ;
		catalog.hCatAdmin			 = context.get() ;
		WINTRUST_DATA trust{} ;	// UIを出さないcatalog member trust設定。
		trust.cbStruct			  = sizeof( trust) ;
		trust.dwUIChoice		  = WTD_UI_NONE ;
		trust.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN ;
		trust.dwUnionChoice		  = WTD_CHOICE_CATALOG ;
		trust.pCatalog			  = &catalog ;
		trust.dwStateAction		  = WTD_STATEACTION_VERIFY ;
		trust.dwProvFlags		  = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT ;
		GUID	   action		  = WINTRUST_ACTION_GENERIC_VERIFY_V2 ;	// Authenticode policy GUID。
		const LONG status		  = driver_package_signature_detail::verifyTrust(
			nullptr, &action, &trust) ;	// 同member検証結果。
		trust.dwStateAction = WTD_STATEACTION_CLOSE ;
		static_cast<void>( driver_package_signature_detail::verifyTrust( nullptr, &action, &trust)) ;
		return status == ERROR_SUCCESS ? 0 : static_cast<NativeError>( status) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Publisher表示名を大文字小文字無視で完全一致する。
 *
 * 大文字小文字以外を正規化せず、punctuation差も許可しない。
 *
 * @param[in] left 比較する一方のpublisher表示名。
 * @param[in] right 比較する他方のpublisher表示名。
 * @return Windows ordinal比較で全code unitが一致した場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool publisherNamesEqual( const std::wstring_view left,
									   const std::wstring_view right) noexcept
{
	// 空の表示名と Windows API の文字数範囲を超える入力は一致と扱わない。
	if( left.empty() || right.empty() ||
	   left.size() > static_cast<std::size_t>( std::numeric_limits<int>::max()) ||
	   right.size() > static_cast<std::size_t>( std::numeric_limits<int>::max())) {
		return false ;
	}

	return CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

//------------------------------------------------------------------------------
/**
 * @brief Publisher allowlistの形式と重複を検証する。
 *
 * AuthenticodeとXML署名で同じ完全一致policyを使用する。
 *
 * @param[in] acceptedPublishers 許可publisher表示名群。
 * @return 一意で空でないpolicyは0、不正policyはE_INVALIDARG。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validatePublisherPolicy(
	const std::span<const std::wstring_view> acceptedPublishers)
{
	// Publisher の許可条件が空の場合は、無制限の受理へ退避せず拒否する。
	if( acceptedPublishers.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 許可する publisher を順に検査し、形式不正と重複を排除する。
	for( std::size_t index = 0; index < acceptedPublishers.size(); ++index) {
		const std::wstring_view publisher = acceptedPublishers[index] ;	// 現在のpolicy表示名。
		// 空文字、埋込み NUL、比較 API の上限超過を含む許可名は拒否する。
		if( publisher.empty() || publisher.find( L'\0') != std::wstring_view::npos ||
		   publisher.size() > static_cast<std::size_t>( std::numeric_limits<int>::max())) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		// 既に検査した許可名だけと比較し、同じ publisher の重複を検出する。
		for( std::size_t previous = 0; previous < index; ++previous) {
			// 大文字小文字を無視して同じ publisher 名があれば policy を拒否する。
			if( publisherNamesEqual( publisher, acceptedPublishers[previous])) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief SHA-256文字列を小文字ASCII hexへ検証・正規化する。
 *
 * Unicode類似文字を拒否し、ASCII 16進文字だけを許可する。
 *
 * @param[in] value 親metadataが宣言したSHA-256。
 * @param[out] normalized 成功時の64桁小文字ASCII hex。
 * @return 形式が正しい場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool normalizeSha256( const std::wstring_view value, std::wstring &normalized)
{
	normalized.clear() ;
	// SHA-256 の hex 表現に必要な 64 文字以外は受理しない。
	if( value.size() != 64) {
		return false ;
	}

	normalized.reserve( value.size()) ;
	// 全ての桁を hex として検査し、許可した文字だけを小文字表現へ移す。
	for( const wchar_t character : value) {
		// 数値の hex 桁は表記を変えずに正規化結果へ残す。
		if( character >= L'0' && character <= L'9') {
			normalized.push_back( character) ;
		}
		// 小文字の hex 桁はそのまま正規化結果へ残す。
		else if( character >= L'a' && character <= L'f') {
			normalized.push_back( character) ;
		}
		// 大文字の hex 桁だけを対応する小文字へ変換する。
		else if( character >= L'A' && character <= L'F') {
			normalized.push_back( static_cast<wchar_t>( character - L'A' + L'a')) ;
		} else {
			normalized.clear() ;
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Fileの実byte数を取得する。
 *
 * Metadata宣言sizeとの完全一致検証に使用する。
 *
 * @param[in] path 読取り対象file絶対path。
 * @param[out] size 成功時のfile byte数。
 * @return 成功時は0、file API失敗時はHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readFileSize( const std::wstring_view path, std::uint64_t &size)
{
	size = 0 ;
	// 対象を指定していない size 照会は入力不正として拒否する。
	if( path.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring filePath( path) ;	// CreateFile用終端null付きpath。
	// 属性照合のために開く所有file handle。後続処理でCloseHandleする。
	const HANDLE	   file = CreateFileW( filePath.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
										  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) ;
	// 対象 file を開けない場合は Windows の診断値を保持する。
	if( file == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	LARGE_INTEGER length{} ;													// Signed 64-bit file size。
	const BOOL	  succeeded = GetFileSizeEx( file, &length) ;					// Size取得成否。
	const DWORD	  error = succeeded != FALSE ? ERROR_SUCCESS : GetLastError() ;	// 保存するerror。
	CloseHandle( file) ;
	// Size 照会の失敗を handle 解放後も保持した診断値で返す。
	if( succeeded == FALSE) {
		return nativeErrorFromWin32( error) ;
	}

	// 負の file size は有効な byte 数へ変換せず拒否する。
	if( length.QuadPart < 0) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	size = static_cast<std::uint64_t>( length.QuadPart) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 上限付きで通常file全体を読み取る。
 *
 * XML署名parserへ渡す前にdirectoryとreparse pointを拒否する。
 *
 * @param[in] path 読取り対象file絶対path。
 * @param[in] maximumBytes 0より大きい許容byte数上限。
 * @param[out] bytes 成功時のfile全byte。
 * @return 成功時は0、属性、size、read失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readFileBytes( const std::wstring_view path,
										const std::uint64_t maximumBytes, std::vector<BYTE> &bytes)
{
	bytes.clear() ;
	// 空の path と API の範囲外の読取り上限は、file を開く前に拒否する。
	if( path.empty() || maximumBytes == 0 ||
	   maximumBytes > static_cast<std::uint64_t>( std::numeric_limits<ULONG>::max())) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring pathString( path) ;										// Win32 API用終端null付きpath。
	const DWORD		   attributes = GetFileAttributesW( pathString.c_str()) ;	// File属性。
	// 属性を照会できない file は通常 file と仮定せず拒否する。
	if( attributes == INVALID_FILE_ATTRIBUTES) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// Hash検証へ渡さないdirectory・reparse属性のmask。
	constexpr DWORD REJECTED_ATTRIBUTES = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT ;
	// 許可しない属性を持つ file は内容を読み取らない。
	if( (attributes & REJECTED_ATTRIBUTES) != 0) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::uint64_t	  length{} ;								// Filesystemが返す実byte数。
	const NativeError sizeError = readFileSize( path, length) ;	// Size取得結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( sizeError != 0) {
		return sizeError ;
	}

	// 空の file、policy 上限超過、ReadFile の長さ範囲超過を拒否する。
	if( length == 0 || length > maximumBytes ||
	   length > static_cast<std::uint64_t>( std::numeric_limits<DWORD>::max())) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	// 検証対象を読取り専用で固定する所有handle。後続処理でCloseHandleする。
	const HANDLE file = CreateFileW( pathString.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
									OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr) ;
	// File を開けなければ buffer への読取りを開始しない。
	if( file == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	bytes.resize( static_cast<std::size_t>( length)) ;
	DWORD	   read{} ;	// ReadFileが返したbyte数。
	const BOOL succeeded =
		// Read結果。
		ReadFile( file, bytes.data(), static_cast<DWORD>( length), &read, nullptr) ;
	const DWORD error = succeeded != FALSE ? ERROR_SUCCESS : GetLastError() ;	// 保存するerror。
	CloseHandle( file) ;
	// 読取り失敗時は部分 buffer を破棄し、保存した診断値を返す。
	if( succeeded == FALSE) {
		bytes.clear() ;
		return nativeErrorFromWin32( error) ;
	}

	// 宣言 size まで読み取れなければ、短い内容を正常結果として返さない。
	if( read != length) {
		bytes.clear() ;
		return nativeErrorFromWin32( ERROR_HANDLE_EOF) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Certificateのsimple display nameを取得する。
 *
 * Publisher policyとの完全一致に使用する表示名だけを返す。
 *
 * @param[in] certificate 呼出し中有効なX.509 certificate。
 * @param[out] name 成功時のsimple display name。
 * @return 取得成功時は0、不正certificateはHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readCertificateName( const CERT_CONTEXT &certificate, std::wstring &name)
{
	name.clear() ;
	const DWORD characters = CertGetNameStringW( &certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
												nullptr, nullptr, 0) ;	// 終端null込み文字数。
	// 終端文字以外の certificate 表示名がない場合は受理しない。
	if( characters <= 1) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::wstring buffer( characters, L'\0') ;	// Certificate表示名受信buffer。
	// 照会した文字数どおりに certificate 名を取得できなければ拒否する。
	if( CertGetNameStringW( &certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, buffer.data(),
						  characters) != characters) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	buffer.resize( characters - 1) ;
	// 空または埋込み NUL を含む表示名は publisher 照合へ渡さない。
	if( buffer.empty() || buffer.find( L'\0') != std::wstring::npos) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	name = std::move( buffer) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定時刻のcode-signing certificate chainを検証する。
 *
 * 署名で保護されたSigningTimeをcertificate有効時刻に使用する。
 *
 * @param[in] certificate 署名検証に使用したX.509 certificate。
 * @param[in] validationFiletime 1601年起点100ns単位の署名時刻。
 * @return Chain、revocation、code-signing用途が有効なら0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyCodeSigningChain( const CERT_CONTEXT &certificate,
												 const std::uint64_t validationFiletime)
{
	// 検証時刻が指定されていない certificate chain 検証は拒否する。
	if( validationFiletime == 0) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	ULARGE_INTEGER ticks{} ;	// FILETIMEのHigh/Lowへ分割する署名時刻。
	ticks.QuadPart = validationFiletime ;
	FILETIME validationTime{} ;	// CertGetCertificateChainへ渡す署名時刻。
	validationTime.dwLowDateTime  = ticks.LowPart ;
	validationTime.dwHighDateTime = ticks.HighPart ;

	LPSTR usageIdentifiers[] = {
		const_cast<LPSTR>( szOID_PKIX_KP_CODE_SIGNING)} ;	// 読取り専用code-signing EKU。
	CERT_CHAIN_PARA parameters{} ;							// Chain build policy。
	parameters.cbSize									 = sizeof( parameters) ;
	parameters.RequestedUsage.dwType					 = USAGE_MATCH_TYPE_AND ;
	parameters.RequestedUsage.Usage.cUsageIdentifier	 = 1 ;
	parameters.RequestedUsage.Usage.rgpszUsageIdentifier = usageIdentifiers ;
	PCCERT_CHAIN_CONTEXT chain{} ;	// CertFreeCertificateChainで解放するchain。
	// 信頼chainでroot以外の失効確認を要求するWindows検証flag。
	constexpr DWORD		 CHAIN_FLAGS = CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT ;
	// 指定時刻の certificate chain を構築できなければ、その失敗を返す。
	if( CertGetCertificateChain( nullptr, &certificate, &validationTime, nullptr, &parameters,
							   CHAIN_FLAGS, nullptr, &chain) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	CERT_CHAIN_POLICY_PARA policy{} ;	// Base Windows chain policy設定。
	policy.cbSize = sizeof( policy) ;
	CERT_CHAIN_POLICY_STATUS status{} ;	// Policy検証結果。
	status.cbSize		 = sizeof( status) ;
	const BOOL	verified = CertVerifyCertificateChainPolicy( CERT_CHAIN_POLICY_BASE, chain, &policy,
															&status) ;				// Chain policy結果。
	const DWORD error	 = verified != FALSE ? status.dwError : GetLastError() ;	// 保存するerror。
	CertFreeCertificateChain( chain) ;
	// Chain policy の検証 API が失敗した場合は、保存した診断値を返す。
	if( verified == FALSE) {
		return nativeErrorFromWin32( error) ;
	}

	return error == ERROR_SUCCESS ? 0 : nativeErrorFromWin32( error) ;
}

//------------------------------------------------------------------------------
/**
 * @brief XML署名KeyInfoから単一certificateを取得する。
 *
 * RetrievalMethodやcustom KeyInfoを拒否し、鍵差替えを防ぐ。
 *
 * @param[in] signature CryptXMLが解析した単一Signature。
 * @param[out] certificate 成功時に呼出し側が解放するcertificate。
 * @return KeyValueと単一X509Certificateを取得できた場合は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError findXmlCertificate( const CRYPT_XML_SIGNATURE &signature,
											 PCCERT_CONTEXT			   &certificate)
{
	certificate = nullptr ;
	// KeyInfo の欠落、件数超過、配列不整合は XML 署名形式の不正として拒否する。
	if( signature.pKeyInfo == nullptr || signature.pKeyInfo->cKeyInfo == 0 ||
	   signature.pKeyInfo->cKeyInfo > 8 || signature.pKeyInfo->rgKeyInfo == nullptr) {
		return static_cast<NativeError>( TRUST_E_SUBJECT_FORM_UNKNOWN) ;
	}

	bool					   keyValueFound{} ;	// KeyValueを一つ確認した場合true。
	const CRYPT_XML_DATA_BLOB *encoded{} ;			// KeyInfo内の単一certificate DER。
	// 上限内の KeyInfo を調べ、鍵情報と単一 certificate を抽出する。
	for( UINT index = 0; index < signature.pKeyInfo->cKeyInfo; ++index) {
		const CRYPT_XML_KEY_INFO_ITEM &item = signature.pKeyInfo->rgKeyInfo[index] ;	// 現在項目。
		// KeyValue は存在を記録し、certificate の抽出とは区別して扱う。
		if( item.dwType == CRYPT_XML_KEYINFO_TYPE_KEYVALUE) {
			// 複数の KeyValue を許可して検証対象の鍵を曖昧にしない。
			if( keyValueFound) {
				return static_cast<NativeError>( TRUST_E_SUBJECT_FORM_UNKNOWN) ;
			}

			keyValueFound = true ;
			continue ;
		}

		// 許可した X509Data 以外の形式と不正な配列件数は拒否する。
		if( item.dwType != CRYPT_XML_KEYINFO_TYPE_X509DATA || item.X509Data.cX509Data == 0 ||
		   item.X509Data.cX509Data > 8 || item.X509Data.rgX509Data == nullptr) {
			return static_cast<NativeError>( TRUST_E_SUBJECT_FORM_UNKNOWN) ;
		}

		// X509Data の各項目を確認し、certificate の重複と未知形式を排除する。
		for( UINT dataIndex = 0; dataIndex < item.X509Data.cX509Data; ++dataIndex) {
			const CRYPT_XML_X509DATA_ITEM &data =	// 現在のX509Data項目。
				item.X509Data.rgX509Data[dataIndex] ;
			// Certificate 項目だけから検証用の encoded certificate を選ぶ。
			if( data.dwType == CRYPT_XML_X509DATA_TYPE_CERTIFICATE) {
				// Certificate の重複、空の内容、無効な data pointer は拒否する。
				if( encoded != nullptr || data.Certificate.cbData == 0 ||
				   data.Certificate.pbData == nullptr) {
					return static_cast<NativeError>( TRUST_E_SUBJECT_FORM_UNKNOWN) ;
				}

				encoded = &data.Certificate ;
			}
			// Certificate 以外では issuer/serial と subject name の項目だけを許可する。
			else if( data.dwType != CRYPT_XML_X509DATA_TYPE_ISSUER_SERIAL &&
					data.dwType != CRYPT_XML_X509DATA_TYPE_SUBJECT_NAME) {
				return static_cast<NativeError>( TRUST_E_SUBJECT_FORM_UNKNOWN) ;
			}
		}
	}

	// 鍵情報と certificate の両方が揃わなければ署名検証を開始しない。
	if( !keyValueFound || encoded == nullptr) {
		return static_cast<NativeError>( TRUST_E_SUBJECT_FORM_UNKNOWN) ;
	}

	certificate = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
											   encoded->pbData, encoded->cbData) ;
	return certificate == nullptr ? nativeErrorFromWin32( GetLastError()) : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief XML署名algorithmとdocument referenceを制限する。
 *
 * External reference、複数reference、弱いalgorithmを拒否する。
 *
 * @param[in] signature CryptXMLが解析した単一Signature。
 * @return 文書全体への許可algorithmだけなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAllowedXmlSignature( const CRYPT_XML_SIGNATURE &signature) noexcept
{
	const CRYPT_XML_SIGNED_INFO &information = signature.SignedInfo ;	// SignedInfo参照。
	// 署名方式、正規化方式、単一 reference の構造が policy と異なる場合は拒否する。
	if( information.Canonicalization.wszAlgorithm == nullptr ||
	   information.SignatureMethod.wszAlgorithm == nullptr || information.cReference != 1 ||
	   information.rgpReference == nullptr || information.rgpReference[0] == nullptr ||
	   XML_CANONICALIZATION_ALGORITHM != information.Canonicalization.wszAlgorithm ||
	   XML_SIGNATURE_ALGORITHM != information.SignatureMethod.wszAlgorithm) {
		return false ;
	}

	const CRYPT_XML_REFERENCE &reference = *information.rgpReference[0] ;	// 文書reference。
	return reference.wszUri != nullptr && reference.wszUri[0] == L'\0' &&
		   reference.DigestMethod.wszAlgorithm != nullptr &&
		   XML_DIGEST_ALGORITHM == reference.DigestMethod.wszAlgorithm &&
		   reference.cTransform == 1 && reference.rgTransform != nullptr &&
		   reference.rgTransform[0].wszAlgorithm != nullptr &&
		   XML_ENVELOPED_TRANSFORM == reference.rgTransform[0].wszAlgorithm ;
}

//------------------------------------------------------------------------------
/**
 * @brief Embedded Authenticode signerの表示名を取得する。
 *
 * Embedded signerをissuerとserial numberでstoreから解決する。
 *
 * @param[in] path Chain検証済みfileの絶対path。
 * @param[out] signerName 成功時のcertificate simple display name。
 * @return 取得成功時は0、PKCS#7またはcertificate失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readSignerName( const std::wstring_view path, std::wstring &signerName)
{
	signerName.clear() ;
	const auto &api =
		// 同trustと同じ低位backendです。
		driver_package_signature_detail::authenticodeApi() ;
	const std::wstring pathString( path) ;	// WinCrypt用終端null付きpath。
	DWORD			   encoding{} ;			// Certificate encoding flags。
	DWORD			   contentType{} ;		// PKCS#7 content種別。
	DWORD			   formatType{} ;		// Binary format種別。
	HCERTSTORE		   store{} ;			// CertCloseStoreで閉じるstore。
	HCRYPTMSG		   message{} ;			// CryptMsgCloseで閉じるmessage。
	// Embedded Authenticode 情報を取得できなければ publisher 名を推測しない。
	if( api.query( CERT_QUERY_OBJECT_FILE, pathString.c_str(),
				 CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0,
				 &encoding, &contentType, &formatType, &store, &message, nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	DWORD		signerBytes{} ;	// CMSG_SIGNER_INFOに必要なbyte数。
	NativeError result{} ;		// Cleanup後に返す処理結果。
	// Signer 情報の buffer 長を照会できなければ、処理結果へ失敗を残す。
	if( api.messageParameter( message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerBytes) == FALSE) {
		result = nativeErrorFromWin32( GetLastError()) ;
	}
	// Signer 構造体より短い情報は不正形式として拒否する。
	else if( signerBytes < sizeof( CMSG_SIGNER_INFO)) {
		result = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	} else {
		std::vector<std::byte> signerBuffer( signerBytes) ;	// Signer情報受信buffer。
		// Signer 情報本体を取得できなければ、API の失敗を記録する。
		if( api.messageParameter( message, CMSG_SIGNER_INFO_PARAM, 0, signerBuffer.data(),
								&signerBytes) == FALSE) {
			result = nativeErrorFromWin32( GetLastError()) ;
		} else {
			const auto *const signer =	// Buffer lifetime中だけ有効なsigner情報。
				reinterpret_cast<const CMSG_SIGNER_INFO *>( signerBuffer.data()) ;
			CERT_INFO match{} ;	// Issuerとserial numberによるcertificate検索key。
			match.Issuer			   = signer->Issuer ;
			match.SerialNumber		   = signer->SerialNumber ;
			PCCERT_CONTEXT certificate = api.findCertificate(
				store, encoding, 0, CERT_FIND_SUBJECT_CERT, &match, nullptr) ;	// Signer証明書。
			// Signer に対応する certificate が見つからなければ名前照会へ進まない。
			if( certificate == nullptr) {
				result = nativeErrorFromWin32( GetLastError()) ;
			} else {
				const DWORD characters = api.certificateName(
					certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0) ;	// 文字数。
				// 空の signer 表示名は publisher 検証に使用しない。
				if( characters <= 1) {
					result = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				} else {
					std::wstring name( characters, L'\0') ;	// 終端null込み表示名buffer。
					// 予定した文字数の signer 名を取得できなければ不正 data とする。
					if( api.certificateName( certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
										   name.data(), characters) != characters) {
						result = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
					} else {
						name.resize( characters - 1) ;
						signerName = std::move( name) ;
					}
				}

				api.freeCertificate( certificate) ;
			}
		}
	}

	api.closeMessage( message) ;
	api.closeStore( store, 0) ;
	return result ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_file_verifier.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
namespace {
/** @brief File hash用CNG資源を全return・例外経路で回収します。 */
struct FileHashHandles {
	/// Algorithm providerの所有handle。
	BCRYPT_ALG_HANDLE  algorithm{} ;
	/// Algorithmより先に解放するhash handle。
	BCRYPT_HASH_HANDLE hash{} ;
	/** @brief 有効なCNG資源を依存順に解放します。 */
	~FileHashHandles()
	{
		// 生成できたhashだけを先に破棄する。
		if( hash != nullptr) {
			BCryptDestroyHash( hash) ;
		}

		// Hashから参照されなくなったalgorithmを閉じる。
		if( algorithm != nullptr) {
			BCryptCloseAlgorithmProvider( algorithm, 0) ;
		}
	}
} ;
/**
 * @brief 固定SHA algorithmを使ってfile全体をstream計算します。
 * @tparam DigestBytes SHA-256の32またはSHA-512の64。
 * @param[in] path 読取り専用file path。
 * @param[in] algorithmId 呼出元が固定したCNG algorithm。
 * @param[out] output 成功時だけ公開する小文字hex。
 * @return 成功0、入力・file・CNG・allocation失敗時はHRESULT。
 */
template <std::size_t DigestBytes>
[[nodiscard]] NativeError computeFileSha( const std::wstring_view path, const wchar_t *algorithmId,
										 std::wstring &output)
{
	static_assert( DigestBytes == 32U || DigestBytes == 64U) ;
	output.clear() ;
	// 空または埋込みNULを異なるpathへ読み替えない。
	if( path.empty() || path.find( L'\0') != path.npos) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		std::vector<UCHAR> object ;		// Hash handleより長く生存するCNG storage。
		FileHashHandles	   handles ;	// Object解放前にhashとalgorithmを回収する。
		// 固定algorithmの開始から各CNG操作の診断を保持する。
		NTSTATUS status = BCryptOpenAlgorithmProvider( &handles.algorithm, algorithmId, nullptr, 0) ;
		// 固定algorithmを開始できなければ失敗を保持する。
		if( status < 0) {
			return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
		}

		DWORD objectBytes{} ;	// CNGが要求するstorage量。
		DWORD resultBytes{} ;	// Property出力byte数。
		status = BCryptGetProperty( handles.algorithm, BCRYPT_OBJECT_LENGTH,
								   reinterpret_cast<PUCHAR>( &objectBytes), sizeof( objectBytes),
								   &resultBytes, 0) ;
		// CNG境界の受信型と有限storageを検証する。
		if( status < 0 || resultBytes != sizeof( objectBytes) || objectBytes == 0U ||
		   objectBytes > 1024U * 1024U) {
			return status < 0 ? static_cast<NativeError>( HRESULT_FROM_NT( status))
							  : static_cast<NativeError>( E_UNEXPECTED) ;
		}

		object.resize( objectBytes) ;
		status = BCryptCreateHash( handles.algorithm, &handles.hash, object.data(), objectBytes,
								  nullptr, 0, 0) ;
		// Hash生成失敗時もalgorithmはscopeで回収する。
		if( status < 0) {
			return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
		}

		const std::wstring		 terminated( path) ;	// Win32向け終端付きpath。
		ReadOnlyVerificationFile file( CreateFileW( terminated.c_str(), GENERIC_READ, FILE_SHARE_READ,
												  nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN,
												  nullptr)) ;	// 書換え・削除共有なし。
		// Fileを開けない場合は元Win32診断を返す。
		if( file.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		std::vector<UCHAR> buffer( 64U * 1024U) ;	// File長に依存しない有限read buffer。
		// EOFまたは最初のfile／hash失敗まで順序どおり全byteを処理する。
		while( true) {
			DWORD read{} ;	// 今回の確定read byte数。
			// 部分read失敗を成功digestへ変更しない。
			if( !ReadFile( file.get(), buffer.data(), static_cast<DWORD>( buffer.size()), &read,
						 nullptr)) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			// 0 byteはEOFとして一度だけ終了する。
			if( read == 0U) {
				break ;
			}

			status = BCryptHashData( handles.hash, buffer.data(), read, 0) ;
			// 更新失敗時に残りのfileを無視してdigestを返さない。
			if( status < 0) {
				return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
			}
		}

		std::array<UCHAR, DigestBytes> digest{} ;	// Algorithmに対応する固定出力。
		status =
			BCryptFinishHash( handles.hash, digest.data(), static_cast<ULONG>( digest.size()), 0) ;
		// CNGが固定出力量を受理しない場合は結果を公開しない。
		if( status < 0) {
			return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
		}

		constexpr wchar_t HEX[] = L"0123456789abcdef" ;	// 小文字hex変換表。
		std::wstring	  completed ;					// Allocation終了後だけ公開する完成hash。
		completed.reserve( DigestBytes * 2U) ;
		// Digestを先頭から二桁ずつ変換する。
		for( const UCHAR byte : digest) {
			completed.push_back( HEX[(byte >> 4U) & 0x0fU]) ;
			completed.push_back( HEX[byte & 0x0fU]) ;
		}

		output = std::move( completed) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}
} // namespace

/** @see official_file_verifier.h */
NativeError computeFileSha256( const std::wstring_view path, std::wstring &sha256)
{
	return computeFileSha<32U>( path, BCRYPT_SHA256_ALGORITHM, sha256) ;
}

/** @brief 用途別の有限上限を適用する共通CNG byte hash処理です。
 * @param[in] bytes Hashする原byte列。
 * @param[in] maximumBytes 呼出用途が固定した有限上限。
 * @param[out] sha256 成功時の小文字hash、失敗時は空です。
 * @return 成功0、上限拒否またはCNG失敗のHRESULT。
 */
static NativeError computeBoundedBytesSha256( const std::string_view bytes,
											 const std::size_t maximumBytes, std::wstring &sha256)
{
	sha256.clear() ;
	// Scriptと有限snapshot以外の無制限memory入力を受理しない。
	if( bytes.empty() || bytes.size() > maximumBytes) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		std::vector<UCHAR> input( bytes.begin(), bytes.end()) ;	// CNG向け原byte copy。
		FileHashHandles	   handles ;							// 早期returnでもalgorithmを回収する。
		NTSTATUS status = BCryptOpenAlgorithmProvider( &handles.algorithm, BCRYPT_SHA256_ALGORITHM,
													  nullptr, 0) ;	// 固定algorithm。
		// Algorithm取得失敗を空hash成功へ変換しない。
		if( status < 0) {
			return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
		}

		std::array<UCHAR, 32U> digest{} ;	// 固定SHA-256出力。
		status = BCryptHash( handles.algorithm, nullptr, 0, input.data(),
							static_cast<ULONG>( input.size()), digest.data(),
							static_cast<ULONG>( digest.size())) ;
		// CNG失敗時は部分digestを公開しない。
		if( status < 0) {
			return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
		}

		constexpr wchar_t HEX[] = L"0123456789abcdef" ;	// 小文字hex表。
		std::wstring	  completed ;					// 割当て成功後だけ公開するdigest。
		completed.reserve( 64U) ;
		// 各byteを欠落なく二桁へ変換する。
		for( const UCHAR byte : digest) {
			completed.push_back( HEX[byte >> 4U]) ;
			completed.push_back( HEX[byte & 15U]) ;
		}

		sha256 = std::move( completed) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

/** @see official_file_verifier.h */
NativeError computeBytesSha256( const std::string_view bytes, std::wstring &sha256)
{
	return computeBoundedBytesSha256( bytes, 1024U * 1024U, sha256) ;
}

/** @see official_file_verifier.h */
NativeError computeCollectorMetadataSha256( const std::string_view bytes, std::wstring &sha256)
{
	return computeBoundedBytesSha256( bytes, 8U * 1024U * 1024U, sha256) ;
}

/** @see official_file_verifier.h */
NativeError computeDriverContainerSha256( const std::string_view bytes, std::wstring &sha256)
{
	return computeBoundedBytesSha256( bytes, 128U * 1024U * 1024U, sha256) ;
}

/** @see official_file_verifier.h */
NativeError computeFileSha512( const std::wstring_view path, std::wstring &sha512)
{
	return computeFileSha<64U>( path, BCRYPT_SHA512_ALGORITHM, sha512) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_file_verifier.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError verifyOfficialFileMetadata( const std::wstring_view			 path,
									   const OfficialFileMetadataPolicy &policy)
{
	// 対象または検証根拠がない要求を拒否し、無検証で成功させない。
	if( path.empty() || (!policy.expectedSize.has_value() && policy.expectedSha256.empty())) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// Metadata が size を宣言している場合は実 file の byte 数を照合する。
	if( policy.expectedSize.has_value()) {
		std::uint64_t	  actualSize{} ;							// Download後fileの実byte数。
		const NativeError error = readFileSize( path, actualSize) ;	// Size取得結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		// Metadata と実 file の size が異なる場合は改変または不整合として拒否する。
		if( actualSize != policy.expectedSize.value()) {
			return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		}
	}

	// Metadata に SHA-256 がある場合は形式を検査して実 digest と比較する。
	if( !policy.expectedSha256.empty()) {
		std::wstring expectedHash ;	// 検証・小文字化したmetadata hash。
		// 期待 hash の形式が不正な policy は file の検証前に拒否する。
		if( !normalizeSha256( policy.expectedSha256, expectedHash)) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		std::wstring	  actualHash ;										// CNGで計算したfile hash。
		const NativeError error = computeFileSha256( path, actualHash) ;	// Hash計算結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		// 計算した digest が期待値と一致しなければ file を受理しない。
		if( actualHash != expectedHash) {
			return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		}
	}

	return 0 ;
}

namespace {
/** @brief 通常入口とcached-only入口の署名処理を同じ検証順で実行します。
 * @param[in] path 対象絶対path。
 * @param[in] acceptedPublishers 完全一致を要求する許可publisher群。
 * @param[in] cachedOnly trueなら全URL取得をcache内へ制限します。
 * @return 成功0、最初の入力／署名／publisher拒否の元error。
 */
NativeError verifyAuthenticodePublisherImpl(
	const std::wstring_view path, const std::span<const std::wstring_view> acceptedPublishers,
	const bool cachedOnly)
{
	// 署名検証の対象が空の場合は入力不正として拒否する。
	if( path.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const NativeError policyError = validatePublisherPolicy( acceptedPublishers) ;	// Policy検証。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( policyError != 0) {
		return policyError ;
	}

	const std::wstring pathString( path) ;	// WinTrust用終端null付きpath。
	WINTRUST_FILE_INFO file{} ;				// 検証対象file metadata。
	file.cbStruct	   = sizeof( file) ;
	file.pcwszFilePath = pathString.c_str() ;
	WINTRUST_DATA trust{} ;	// Generic Authenticode検証設定。
	trust.cbStruct			  = sizeof( trust) ;
	trust.dwUIChoice		  = WTD_UI_NONE ;
	trust.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN ;
	trust.dwUnionChoice		  = WTD_CHOICE_FILE ;
	trust.pFile				  = &file ;
	trust.dwStateAction		  = WTD_STATEACTION_VERIFY ;
	trust.dwProvFlags =
		WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | (cachedOnly ? WTD_CACHE_ONLY_URL_RETRIEVAL : 0U) ;
	GUID		action = WINTRUST_ACTION_GENERIC_VERIFY_V2 ;	// Authenticode policy GUID。
	const auto &api =
		// 同threadの完全backendです。
		driver_package_signature_detail::authenticodeApi() ;
	const LONG status	= api.verify( nullptr, &action, &trust) ;	// Chain検証結果。
	trust.dwStateAction = WTD_STATEACTION_CLOSE ;
	static_cast<void>( api.verify( nullptr, &action, &trust)) ;
	// 失敗の診断値を共通の表現へ保ったまま返し、未完了の結果で後続処理を進めない。
	if( status != ERROR_SUCCESS) {
		return static_cast<NativeError>( status) ;
	}

	std::wstring	  signerName ;										// Embedded signer表示名。
	const NativeError signerError = readSignerName( path, signerName) ;	// 取得結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( signerError != 0) {
		return signerError ;
	}

	const bool accepted = std::any_of( acceptedPublishers.begin(), acceptedPublishers.end(),
									  [&signerName]( const std::wstring_view publisher) {
										  return publisherNamesEqual( signerName, publisher) ;
									  }) ; // 完全一致結果。
	// 信頼 chain が成立していても、許可 publisher と一致しなければ拒否する。
	if( !accepted) {
		return static_cast<NativeError>( TRUST_E_SUBJECT_NOT_TRUSTED) ;
	}

	return 0 ;
}
} // namespace

/** @see src/platform/official_file_verifier.h 宣言側の契約を正本とします。 */
NativeError verifyAuthenticodePublisher( const std::wstring_view					 path,
										const std::span<const std::wstring_view> acceptedPublishers)
{
	return verifyAuthenticodePublisherImpl( path, acceptedPublishers, false) ;
}

/** @see src/platform/official_file_verifier.h 宣言側の契約を正本とします。 */
NativeError verifyAuthenticodePublisherCachedOnly(
	const std::wstring_view path, const std::span<const std::wstring_view> acceptedPublishers)
{
	return verifyAuthenticodePublisherImpl( path, acceptedPublishers, true) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_file_verifier.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError verifyOfficialCatalogMembers( const std::wstring_view			 catalogPath,
										 const std::span<const std::wstring> memberPaths)
{
	// Catalog path の空文字・埋込み NUL と空の member 集合は受理しない。
	if( catalogPath.empty() || catalogPath.find( L'\0') != std::wstring_view::npos ||
	   memberPaths.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		const std::wstring			   catalog( catalogPath) ;	// WinTrustへ渡すnull終端CAT path。
		const ReadOnlyVerificationFile catalogFile(
			CreateFileW( catalog.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
						nullptr)) ;	// 検証完了まで置換を防ぐCAT file。
		// Catalog file を開けなければ member 検証へ進まない。
		if( catalogFile.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		FILE_ATTRIBUTE_TAG_INFO catalogAttributes{} ;	// Handleが指すCATの属性。
		// 開いた catalog の属性を確認できなければ安全な対象と仮定しない。
		if( GetFileInformationByHandleEx( catalogFile.get(), FileAttributeTagInfo, &catalogAttributes,
										sizeof( catalogAttributes)) == FALSE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		// 署名検証対象へdirectoryとreparse経路を混入させない属性mask。
		constexpr DWORD REJECTED_ATTRIBUTES =
			FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT ;
		// 許可しない属性を持つ catalog file は検証対象から除外する。
		if( (catalogAttributes.FileAttributes & REJECTED_ATTRIBUTES) != 0) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		CatalogHashContext context ;								// 全memberで共有するSHA-256 catalog context。
		const NativeError  contextError = context.initialize() ;	// Context初期化結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( contextError != 0) {
			return contextError ;
		}

		// 全memberを同じ署名catalogへ結び付け、部分成功を受理しない。
		for( const std::wstring &memberPath : memberPaths) {
			// Member の空 path と埋込み NUL は file API へ渡す前に拒否する。
			if( memberPath.empty() || memberPath.find( L'\0') != std::wstring::npos) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			const NativeError memberError =
				// 一memberのtrust結果。
				verifyCatalogMember( context, catalog, memberPath) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
			if( memberError != 0) {
				return memberError ;
			}
		}

		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_file_verifier.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError verifyXmlSignaturePublisher( const std::wstring_view					 path,
										const std::uint64_t						 maximumBytes,
										const std::uint64_t						 validationFiletime,
										const std::span<const std::wstring_view> acceptedPublishers)
{
	// 対象 path または検証時刻が未指定の XML 署名検証は拒否する。
	if( path.empty() || validationFiletime == 0) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const NativeError policyError = validatePublisherPolicy( acceptedPublishers) ;	// Policy検証。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( policyError != 0) {
		return policyError ;
	}

	std::vector<BYTE> bytes ;												// CryptXMLへ渡す上限確認済みUTF-8文書。
	NativeError		  error = readFileBytes( path, maximumBytes, bytes) ;	// File読取り結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	std::size_t xmlOffset{} ;	// CryptXML入力から任意UTF-8 BOMを除く先頭位置。
	// UTF-8 BOM がある場合だけ、その直後を XML 本文の先頭とする。
	if( bytes.size() >= 3 && bytes[0] == 0xefU && bytes[1] == 0xbbU && bytes[2] == 0xbfU) {
		xmlOffset = 3 ;
	}

	const std::size_t xmlBytes = bytes.size() - xmlOffset ;	// CryptXMLへ渡す文書byte数。
	// 空の本文、API の長さ上限超過、XML 開始文字の欠落を拒否する。
	if( xmlBytes == 0 || xmlBytes > static_cast<std::size_t>( std::numeric_limits<ULONG>::max()) ||
	   bytes[xmlOffset] != static_cast<BYTE>( '<')) {
		return nativeErrorFromWin32( ERROR_NO_UNICODE_TRANSLATION) ;
	}

	// Lenovo descriptorのlowercase `id`属性をCryptXMLがXML
	// IDと誤認しないよう、署名要素だけを解析する。
	const std::string_view	   xmlText( reinterpret_cast<const char *>( bytes.data() + xmlOffset),
									   xmlBytes) ;	// UTF-8全体view。
	constexpr std::string_view SIGNATURE_START =
		R"(<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">)" ;				// 固定署名開始tag。
	constexpr std::string_view SIGNATURE_END  = R"(</Signature>)" ;					// 固定署名終了tag。
	const std::size_t		   signatureStart = xmlText.find( SIGNATURE_START) ;	// 署名開始位置。
	const std::size_t		   signatureEndTag =
		 signatureStart == std::string_view::npos
					 ? std::string_view::npos
					 : xmlText.find( SIGNATURE_END, signatureStart + SIGNATURE_START.size()) ;	// 終了位置。
	// 署名要素の欠落または重複を拒否し、検証対象を単一に限定する。
	if( signatureStart == std::string_view::npos || signatureEndTag == std::string_view::npos ||
	   xmlText.find( SIGNATURE_START, signatureStart + 1) != std::string_view::npos ||
	   xmlText.find( SIGNATURE_END, signatureEndTag + 1) != std::string_view::npos) {
		return static_cast<NativeError>( TRUST_E_SUBJECT_FORM_UNKNOWN) ;
	}

	const std::size_t signatureBytes =
		signatureEndTag + SIGNATURE_END.size() - signatureStart ;	// 署名要素byte数。

	ULONG maximumHeap		= 16U * 1024U * 1024U ;	// CryptXML内部allocation上限。
	ULONG maximumSignatures = 1 ;					// 一文書で受理するSignature数。
	// CryptXMLへ渡すheap使用量と署名件数の有限上限。参照先は呼出し中だけ有効。
	const std::array<CRYPT_XML_PROPERTY, 2> properties{
		CRYPT_XML_PROPERTY{.dwPropId = CRYPT_XML_PROPERTY_MAX_HEAP_SIZE,
						   .pvValue	 = &maximumHeap,
						   .cbValue	 = sizeof( maximumHeap)},
		CRYPT_XML_PROPERTY{.dwPropId = CRYPT_XML_PROPERTY_MAX_SIGNATURES,
						   .pvValue	 = &maximumSignatures,
						   .cbValue	 = sizeof( maximumSignatures)}} ;
	CRYPT_XML_BLOB blob{} ;	// UTF-8文書を表す非所有CryptXML入力。
	blob.dwCharset = CRYPT_XML_CHARSET_UTF8 ;
	blob.cbData	   = static_cast<ULONG>( signatureBytes) ;
	blob.pbData	   = bytes.data() + xmlOffset + signatureStart ;
	HCRYPTXML document{} ;	// CryptXmlCloseで解放するdocument context。
	// 拡張機能を無効にしたCryptXML decode開始結果。後続署名検証へ引き継ぐ。
	HRESULT	  status =
		CryptXmlOpenToDecode( nullptr, CRYPT_XML_FLAG_DISABLE_EXTENSIONS, properties.data(),
							 static_cast<ULONG>( properties.size()), &blob, &document) ;
	// 失敗の診断値を共通の表現へ保ったまま返し、未完了の結果で後続処理を進めない。
	if( FAILED( status)) {
		return static_cast<NativeError>( status) ;
	}

	const CRYPT_XML_DOC_CTXT *context{} ;	// Document handle lifetime中だけ有効な解析結果。
	status = CryptXmlGetDocContext( document, &context) ;
	// 署名 context の取得失敗や単一署名の構造不成立時は document を解放する。
	if( FAILED( status) || context == nullptr || context->cSignature != 1 ||
	   context->rgpSignature == nullptr || context->rgpSignature[0] == nullptr) {
		CryptXmlClose( document) ;
		return FAILED( status) ? static_cast<NativeError>( status)
							  : static_cast<NativeError>( TRUST_E_SUBJECT_FORM_UNKNOWN) ;
	}

	const CRYPT_XML_SIGNATURE &signature = *context->rgpSignature[0] ;	// 単一署名。
	// 許可しない署名方式または reference 構造なら document を解放して拒否する。
	if( !isAllowedXmlSignature( signature)) {
		CryptXmlClose( document) ;
		return static_cast<NativeError>( TRUST_E_SUBJECT_FORM_UNKNOWN) ;
	}

	PCCERT_CONTEXT certificate{} ;	// CertFreeCertificateContextで解放する署名certificate。
	error = findXmlCertificate( signature, certificate) ;
	// Certificate 抽出に失敗した場合も XML document の所有資源を解放する。
	if( error != 0) {
		CryptXmlClose( document) ;
		return error ;
	}

	BCRYPT_KEY_HANDLE key{} ;	// BCryptDestroyKeyで解放するcertificate公開鍵。
	// Certificate の公開鍵を import できなければ、その失敗を保持する。
	if( CryptImportPublicKeyInfoEx2( X509_ASN_ENCODING, &certificate->pCertInfo->SubjectPublicKeyInfo,
								   0, nullptr, &key) == FALSE) {
		error = nativeErrorFromWin32( GetLastError()) ;
	} else {
		XmlDataProviderState	providerState{.data = bytes.data() + xmlOffset,
											  .size = xmlBytes,
											  .position = 0} ;	// Enveloped transformへ渡す元文書状態。
		CRYPT_XML_DATA_PROVIDER provider{.pvCallbackState = &providerState,
										 .cbBufferSize	  = 64U * 1024U,
										 .pfnRead		  = readXmlProvider,
										 .pfnClose =
											 closeXmlProvider} ;	// 元文書の有限data provider。
		status = CryptXmlDigestReference( signature.SignedInfo.rgpReference[0]->hReference, 0,
										 &provider) ;	// 文書全体referenceの再digest結果。
		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( SUCCEEDED( status)) {
			status = CryptXmlVerifySignature( signature.hSignature, key,
											 CRYPT_XML_FLAG_DISABLE_EXTENSIONS) ;	// 署名検証結果。
		}

		// XML 署名の検証 API が失敗した場合は HRESULT を保持する。
		if( FAILED( status)) {
			error = static_cast<NativeError>( status) ;
		} else {
			CRYPT_XML_STATUS signatureStatus{} ;	// Digestと署名valueの詳細状態。
			signatureStatus.cbSize = sizeof( signatureStatus) ;
			status				   = CryptXmlGetStatus( signature.hSignature, &signatureStatus) ;
			// 署名合格に必要なdigest整合とsignature検証の両status bit。
			constexpr DWORD REQUIRED_STATUS =
				CRYPT_XML_STATUS_DIGEST_VALID | CRYPT_XML_STATUS_SIGNATURE_VALID ;
			// 署名状態の照会失敗、検証 error、必要な検証状態の不足を全て拒否する。
			if( FAILED( status) || signatureStatus.dwErrorStatus != CRYPT_XML_STATUS_NO_ERROR ||
			   (signatureStatus.dwInfoStatus & REQUIRED_STATUS) != REQUIRED_STATUS) {
				error = FAILED( status) ? static_cast<NativeError>( status)
									   : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
			}
		}

		BCryptDestroyKey( key) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
	if( error == 0) {
		// Chain検証結果。
		error = verifyCodeSigningChain( *certificate, validationFiletime) ;
	}

	// 暗号学的検証に成功した場合だけ certificate の publisher 名を確認する。
	if( error == 0) {
		std::wstring signerName ;	// 埋込みcertificateのsimple display name。
		error = readCertificateName( *certificate, signerName) ;
		// 表示名を取得できた場合だけ許可 publisher との完全一致を調べる。
		if( error == 0) {
			const bool accepted = std::any_of( acceptedPublishers.begin(), acceptedPublishers.end(),
											  [&signerName]( const std::wstring_view publisher) {
												  return publisherNamesEqual( signerName, publisher) ;
											  }) ; // 一致結果。
			// XML 署名が有効でも許可 publisher に一致しなければ受理しない。
			if( !accepted) {
				error = static_cast<NativeError>( TRUST_E_SUBJECT_NOT_TRUSTED) ;
			}
		}
	}

	CertFreeCertificateContext( certificate) ;
	CryptXmlClose( document) ;
	return error ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_file_verifier.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError verifyOfficialFile( const std::wstring_view					path,
							   const OfficialFileMetadataPolicy		   &metadataPolicy,
							   const std::span<const std::wstring_view> acceptedPublishers)
{
	const NativeError metadataError =	// 親metadataとの完全一致結果。
		verifyOfficialFileMetadata( path, metadataPolicy) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( metadataError != 0) {
		return metadataError ;
	}

	return verifyAuthenticodePublisher( path, acceptedPublishers) ;
}

namespace driver_package_signature_detail {
namespace {
// 製品とfixtureで部分混在しない固定Windows Authenticode ABIです。
const AuthenticodeApi NATIVE_AUTHENTICODE_API{&WinVerifyTrust,	   &CryptQueryObject,
											  &CryptMsgGetParam,   &CertFindCertificateInStore,
											  &CertGetNameStringW, &CertFreeCertificateContext,
											  &CryptMsgClose,	   &CertCloseStore} ;
// 同MTAにだけ生存する内部scopeです。製品経路は常にnullです。
thread_local ScopedAuthenticodeFixture *activeAuthenticode = nullptr ;
}
/** @see ScopedAuthenticodeFixture 宣言側の契約を正本とします。 */
ScopedAuthenticodeFixture::ScopedAuthenticodeFixture( const AuthenticodeApi api) noexcept : api_( api)
{
	activeAuthenticode = this ;
}
/** @see ScopedAuthenticodeFixture 宣言側の契約を正本とします。 */
ScopedAuthenticodeFixture::~ScopedAuthenticodeFixture() noexcept
{
	// 同threadへ固定した元scopeだけを解除します。
	if( activeAuthenticode == this) {
		activeAuthenticode = nullptr ;
	}
}
/** @see authenticodeApi 宣言側の契約を正本とします。 */
const AuthenticodeApi &authenticodeApi() noexcept
{
	return activeAuthenticode ? activeAuthenticode->api() : NATIVE_AUTHENTICODE_API ;
}
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
/** @see Access 宣言側の契約を正本とします。 */
std::unique_ptr<ScopedAuthenticodeFixture> Access::createAuthenticode( const AuthenticodeApi api)
{
	// 欠損表や別scopeの上書きでnativeを部分利用しません。
	if( activeAuthenticode || !api.verify || !api.query || !api.messageParameter ||
	   !api.findCertificate || !api.certificateName || !api.freeCertificate || !api.closeMessage ||
	   !api.closeStore) {
		return nullptr ;
	}

	return std::unique_ptr<ScopedAuthenticodeFixture>{new ScopedAuthenticodeFixture( api)} ;
}
#endif
// Worker threadの同期scopeだけへ固定する完全fixture。製品は常にnullptrです。
thread_local ScopedFixture *activeFixture = nullptr ;

/** @brief 内部署名fixtureの相対member名を安全な全segmentへ限定します。
 * @param[in] name 補正せず同期検査する元相対名です。
 * @return 全segmentが非空で絶対・traversal・不正文字を持たない場合trueです。
 */
[[nodiscard]] bool			validFixtureRelativeName( std::wstring_view name) noexcept
{
	std::size_t beginning{} ;	// 原segmentの開始位置です。
	// 有限な元名の全segmentを読み、最初の不正または終端で終了します。
	while( beginning < name.size()) {
		const auto separator = name.find( L'\\', beginning) ;					// Windowsの単一相対区切りです。
		const auto ending = separator == name.npos ? name.size() : separator ;	// 元segment終端です。
		const auto segment = name.substr( beginning, ending - beginning) ;		// 同元値の借用です。
		// 補正後の別pathを同じfixture memberへ変換しません。
		if( segment.empty() || segment.size() > 255U || segment == L"." || segment == L".." ||
		   segment.back() == L'.' || segment.back() == L' ' ||
		   segment.find_first_of( L"<>/%:\"|?*") != segment.npos ||
		   std::ranges::any_of( segment,
							   []( wchar_t value) { return value < L' ' || value > L'~' ; })) {
			return false ;
		}

		const auto stem = segment.substr( 0U, segment.find( L'.')) ;	// 原ASCII stemの同期借用です。
		const auto reserved = [stem]( std::wstring_view value) {
			return CompareStringOrdinal( stem.data(), static_cast<int>( stem.size()), value.data(),
										static_cast<int>( value.size()), TRUE) == CSTR_EQUAL ;
		} ; // 有限ASCII stemだけを同呼出し中に比較し、captureを保存しません。
		// Windows予約device名を相対member許可へ含めません。
		if( reserved( L"CON") || reserved( L"PRN") || reserved( L"AUX") || reserved( L"NUL") ||
		   (stem.size() == 4U && stem[3U] >= L'1' && stem[3U] <= L'9' &&
			(CompareStringOrdinal( stem.data(), 3, L"COM", 3, TRUE) == CSTR_EQUAL ||
			 CompareStringOrdinal( stem.data(), 3, L"LPT", 3, TRUE) == CSTR_EQUAL))) {
			return false ;
		}

		// 全文終端だけを正常な相対名として確定します。
		if( separator == name.npos) {
			return true ;
		}

		beginning = separator + 1U ;
	}

	return false ;
}

/** @brief 実fileが同rootの完全相対memberと元hashへ一致するか確認します。
 * @param[in] files 完全な固定期待集合。
 * @param[in] path 保護workspace内の実絶対path。
 * @param[in] root 元INFで確認する保護rootです。末尾区切りを含みます。
 * @return 実byteと元hash一致の場合true。
 */
[[nodiscard]] bool matchesFixtureFile( const std::vector<FixtureFile> &files,
									  const std::wstring_view path, const std::wstring_view root)
{
	// 区切り込みの同root外や未知fileを成功する低位APIへ渡しません。
	if( root.size() < 4U || root.back() != L'\\' || !path.starts_with( root)) {
		return false ;
	}

	const auto	 name  = path.substr( root.size()) ;	// 元fixtureの完全な相対位置です。
	const auto	 found = std::find_if( files.begin(), files.end(), [name]( const FixtureFile &file) {
		  return file.name == name ;
	  }) ;			   // 未登録名をnativeへfallbackしないための固定集合検索。
	std::wstring hash ;	// 取得済み実fileのSHA-256。
	return found != files.end() && computeFileSha256( path, hash) == 0 && hash == found->sha256 ;
}

/** @see ScopedFixture宣言側の契約を正本とします。 */
ScopedFixture::ScopedFixture( std::vector<FixtureFile> files, const std::size_t maximumRoots)
	: files_( std::move( files)), maximumRoots_( maximumRoots)
{
	roots_.reserve( maximumRoots_) ;
	rootOwners_.reserve( maximumRoots_) ;
	activeFixture = this ;
}
/** @see ScopedFixture宣言側の契約を正本とします。 */
ScopedFixture::~ScopedFixture() noexcept
{
	// Scopeを使った同workerだけから解除し、別scopeを上書きしません。
	if( activeFixture == this) {
		activeFixture = nullptr ;
	}
}
/** @see ScopedFixture宣言側の契約を正本とします。 */
Receipt ScopedFixture::receipt() const noexcept
{
	auto result			   = receipt_ ;	// Call数と実閉包root数を別の観測として返します。
	result.inspectionRoots = roots_.size() ;
	return result ;
}
/** @see setupVerifyInf宣言側の契約を正本とします。 */
BOOL setupVerifyInf( const PCWSTR path, const PSP_ALTPLATFORM_INFO platform,
					const PSP_INF_SIGNER_INFO_W signer) noexcept
{
	// 製品wrapperは外部入力を受けない固定Windows APIだけを使用します。
	if( activeFixture == nullptr) {
		return SetupVerifyInfFileW( path, platform, signer) ;
	}

	auto &fixture = *activeFixture ;	// 同worker lifetimeの完全な固定表。
	++fixture.receipt_.setupCalls ;
	try {
		// 不完全な署名API入力や未登録・改変INFを合格へ変換しません。
		if( path == nullptr || platform != nullptr || signer == nullptr ||
		   signer->cbSize != sizeof( *signer)) {
			++fixture.receipt_.rejectedCalls ;
			SetLastError( ERROR_ACCESS_DENIED) ;
			return FALSE ;
		}

		const std::wstring inf( path) ;							// 成功APIへ結合する実INF path。
		const auto		   slash = inf.find_last_of( L"\\/") ;	// 同保護閉包のroot。
		// 絶対INFの親境界がない入力から保護rootを作りません。
		if( slash == std::wstring::npos || slash < 3U) {
			++fixture.receipt_.rejectedCalls ;
			SetLastError( ERROR_ACCESS_DENIED) ;
			return FALSE ;
		}

		const auto root	   = inf.substr( 0U, slash + 1U) ;	// CATを別directoryから選びません。
		const auto infName = inf.substr( slash + 1U) ;		// 基本INFの実basenameです。
		const auto infEntry =
			std::ranges::find_if( fixture.files_, [&infName]( const FixtureFile &file) {
				return file.name == infName && file.name.ends_with( L".inf") ;
			}) ; // 完全表にある基本INFだけをrootへ結びます。
		// SYSやCATを基本INFとして照合させた入力を拒否します。
		if( infEntry == fixture.files_.end() || !matchesFixtureFile( fixture.files_, inf, root)) {
			++fixture.receipt_.rejectedCalls ;
			SetLastError( ERROR_ACCESS_DENIED) ;
			return FALSE ;
		}

		const auto owner   = infEntry->infOwner ;	// 旧単一集合は空、複数集合はexact INF名です。
		const auto catalog = std::find_if(
			fixture.files_.begin(), fixture.files_.end(), [&owner]( const FixtureFile &file) {
				return file.infOwner == owner && file.name.ends_with( L".cat") ;
			}) ;					 // 一意固定CAT。
		std::size_t rootIndex{} ;	// 同rootと元INF ownerの完全な組を検索します。
		// 同directoryの別CATを既存ownerの署名へ転用しません。
		while( rootIndex < fixture.roots_.size() &&
			  (fixture.roots_[rootIndex] != root || fixture.rootOwners_[rootIndex] != owner)) {
			++rootIndex ;
		}

		const bool knownRoot = rootIndex < fixture.roots_.size() ;	// 完全なroot-owner組です。
		// 同閉包の完全file集合と有限root枠を満たさなければ成功値を返しません。
		if( catalog == fixture.files_.end() ||
		   !matchesFixtureFile( fixture.files_, root + catalog->name, root) ||
		   (!knownRoot && fixture.roots_.size() >= fixture.maximumRoots_) ||
		   !std::ranges::all_of( fixture.files_,
								[&]( const FixtureFile &file) {
									return file.infOwner != owner ||
										   matchesFixtureFile( fixture.files_, root + file.name,
															  root) ;
								}) ||
		   root.size() + catalog->name.size() >= MAX_PATH) {
			++fixture.receipt_.rejectedCalls ;
			SetLastError( ERROR_ACCESS_DENIED) ;
			return FALSE ;
		}

		// 全memberの実hashを確認した新rootだけを有限集合へ固定します。
		if( !knownRoot) {
			fixture.roots_.push_back( root) ;
			fixture.rootOwners_.push_back( owner) ;
		}

		wcscpy_s( signer->CatalogFile, root.c_str()) ;
		wcscat_s( signer->CatalogFile, catalog->name.c_str()) ;
		wcscpy_s( signer->DigitalSigner, L"DriverCrate internal signature fixture") ;
		return TRUE ;
	} catch( ...) {
		++fixture.receipt_.rejectedCalls ;
		SetLastError( ERROR_IO_DEVICE) ;
		return FALSE ;
	}
}
/** @see verifyTrust宣言側の契約を正本とします。 */
LONG verifyTrust( const HWND window, GUID *const action, LPVOID const data) noexcept
{
	// 製品は同じ固定native関数でVERIFYとCLOSEを処理します。
	if( activeFixture == nullptr) {
		return WinVerifyTrust( window, action, data) ;
	}

	auto &fixture = *activeFixture ;	// 現workerだけのfixture。
	try {
		// 型なしWindows ABI境界でだけWINTRUST_DATAの実型へ戻します。
		auto *const trust		  = static_cast<WINTRUST_DATA *>( data) ;	// 呼出し中だけ有効な設定。
		const GUID expectedAction = WINTRUST_ACTION_GENERIC_VERIFY_V2 ;		// 製品と同じWindows policy。
		// 不足・別policy・別CAT・別member/tagを成功へ補完しません。
		if( window != nullptr || action == nullptr || *action != expectedAction ||
		   trust == nullptr || trust->cbStruct != sizeof( *trust) ||
		   trust->dwUIChoice != WTD_UI_NONE ||
		   trust->fdwRevocationChecks != WTD_REVOKE_WHOLECHAIN ||
		   trust->dwUnionChoice != WTD_CHOICE_CATALOG || trust->pCatalog == nullptr ||
		   trust->dwProvFlags != WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT) {
			++fixture.receipt_.rejectedCalls ;
			return TRUST_E_SUBJECT_NOT_TRUSTED ;
		}

		const auto	&catalog = *trust->pCatalog ;	// 元共通処理が計算した実member hashとtag。
		std::wstring hash ;							// 実member原byteの独立SHA-256。
		// 必須ABI値を確認し、未確認rootのmember byteを読みません。
		if( catalog.cbStruct != sizeof( catalog) || catalog.pcwszCatalogFilePath == nullptr ||
		   catalog.pcwszMemberFilePath == nullptr || catalog.pcwszMemberTag == nullptr ||
		   catalog.hMemberFile == INVALID_HANDLE_VALUE || catalog.hMemberFile == nullptr ||
		   catalog.hCatAdmin == nullptr || catalog.cbCalculatedFileHash != 32U ||
		   catalog.pbCalculatedFileHash == nullptr) {
			++fixture.receipt_.rejectedCalls ;
			return TRUST_E_SUBJECT_NOT_TRUSTED ;
		}

		const std::wstring_view catalogPath{catalog.pcwszCatalogFilePath} ;	// 同CATの実pathです。
		const std::wstring_view memberPath{catalog.pcwszMemberFilePath} ;	// 同memberの実pathです。
		const auto				catalogRoot =
			// 親rootです。
			catalogPath.substr( 0U, catalogPath.find_last_of( L"\\/") + 1U) ;
		// 同登録root以下の完全相対memberだけをCATへ結び、basename一致を使いません。
		if( std::ranges::find( fixture.roots_, catalogRoot) == fixture.roots_.end() ||
		   !memberPath.starts_with( catalogRoot) ||
		   !matchesFixtureFile( fixture.files_, catalogPath, catalogRoot) ||
		   !matchesFixtureFile( fixture.files_, memberPath, catalogRoot) ||
		   computeFileSha256( catalog.pcwszMemberFilePath, hash) != 0) {
			++fixture.receipt_.rejectedCalls ;
			return TRUST_E_SUBJECT_NOT_TRUSTED ;
		}

		const auto memberName =
			// 同閉包の完全相対member名です。
			memberPath.substr( catalogRoot.size()) ;
		const auto catalogName	= catalogPath.substr( catalogRoot.size()) ;	// 同閉包のCAT名です。
		const auto catalogEntry = std::ranges::find_if( fixture.files_, [&]( const auto &file) {
			return file.name == catalogName && file.name.ends_with( L".cat") ;
		}) ; // 元CAT名と元INF ownerを完全な表へ固定します。
		// 未登録CATの名前からownerを作りません。
		if( catalogEntry == fixture.files_.end()) {
			++fixture.receipt_.rejectedCalls ;
			return TRUST_E_SUBJECT_NOT_TRUSTED ;
		}

		const auto &owner = catalogEntry->infOwner ;	// 同元CATだけの元INFです。
		std::size_t rootIndex{} ;						// setupVerifyInfが確認したroot-owner組です。
		// 同directoryの別ownerの確認を今回のCATへ流用しません。
		while( rootIndex < fixture.roots_.size() && (fixture.roots_[rootIndex] != catalogRoot ||
													fixture.rootOwners_[rootIndex] != owner)) {
			++rootIndex ;
		}

		// 元INFと全memberを確認した組だけを署名低位正例にします。
		if( rootIndex == fixture.roots_.size()) {
			++fixture.receipt_.rejectedCalls ;
			return TRUST_E_SUBJECT_NOT_TRUSTED ;
		}

		// 別INF集合のfileを同rootの署名へ紐付けません。
		if( !std::ranges::any_of( fixture.files_,
								[&]( const FixtureFile &file) {
									return file.infOwner == owner && file.name == memberName ;
								}) ||
		   !std::ranges::any_of( fixture.files_, [&]( const FixtureFile &file) {
			   return file.infOwner == owner && file.name == catalogName &&
					  file.name.ends_with( L".cat") ;
		   })) {
			++fixture.receipt_.rejectedCalls ;
			return TRUST_E_SUBJECT_NOT_TRUSTED ;
		}

		std::wstring				actualHash ;				// Common catalog APIの32byteをhexへ独立射影します。
		constexpr std::wstring_view HEX = L"0123456789abcdef" ;	// 正規小文字表現。
		// 全32byteを照合し、tagだけの一致を実hash一致へ読み替えません。
		for( DWORD index = 0U; index < 32U; ++index) {
			actualHash.push_back( HEX[catalog.pbCalculatedFileHash[index] >> 4U]) ;
			actualHash.push_back( HEX[catalog.pbCalculatedFileHash[index] & 15U]) ;
		}

		std::wstring uppercase = hash ;	// WinTrust tagはuppercase exact hexです。
		std::transform( uppercase.begin(), uppercase.end(), uppercase.begin(), []( wchar_t value) {
			return static_cast<wchar_t>( value >= L'a' && value <= L'f' ? value - L'a' + L'A'
																	   : value) ;
		}) ;
		// 元file hash、API計算hashとtagの三値を一致させます。
		if( hash != actualHash || uppercase != catalog.pcwszMemberTag) {
			++fixture.receipt_.rejectedCalls ;
			return TRUST_E_SUBJECT_NOT_TRUSTED ;
		}

		// VERIFYとCLOSEの一対一を同じ実memberへ固定します。
		if( trust->dwStateAction == WTD_STATEACTION_VERIFY && fixture.pendingMember_.empty()) {
			fixture.pendingMember_ = catalog.pcwszMemberFilePath ;
			++fixture.receipt_.verifyCalls ;
			return ERROR_SUCCESS ;
		}

		// 成功VERIFYの同memberだけをCLOSEし、未知のCLOSEを受理しません。
		if( trust->dwStateAction == WTD_STATEACTION_CLOSE &&
		   fixture.pendingMember_ == catalog.pcwszMemberFilePath) {
			fixture.pendingMember_.clear() ;
			++fixture.receipt_.closeCalls ;
			return ERROR_SUCCESS ;
		}

		++fixture.receipt_.rejectedCalls ;
		return TRUST_E_SUBJECT_NOT_TRUSTED ;
	} catch( ...) {
		++fixture.receipt_.rejectedCalls ;
		return TRUST_E_SUBJECT_NOT_TRUSTED ;
	}
}
// 完全な内部factoryだけをtest構成に含め、製品設定から取得しません。
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
/** @see Access宣言側の契約を正本とします。 */
std::unique_ptr<ScopedFixture> Access::create( std::vector<FixtureFile> files,
											  const std::size_t		   maximumRoots)
{
	// 同workerの既存scopeを上書きしません。
	if( activeFixture != nullptr || files.size() < 2U || files.size() > 387U || maximumRoots == 0U ||
	   maximumRoots > 129U) {
		return nullptr ;
	}

	std::size_t catalogs{} ;	// 完全な一CATの期待数。
	std::size_t infs{} ;		// 初回単一基本INFの期待数。
	// 全期待memberを有限・一意にし、不完全表をnativeへ補完しません。
	for( std::size_t index = 0U; index < files.size(); ++index) {
		const auto &file = files[index] ;	// 元fixture byteの一member。
		// 不正segment・subdir INF/CAT・不正hash・重複memberをfactory生成前に拒否します。
		if( !validFixtureRelativeName( file.name) ||
		   ((file.name.ends_with( L".inf") || file.name.ends_with( L".cat")) &&
			file.name.find( L'\\') != std::wstring::npos) ||
		   file.sha256.size() != 64U ||
		   std::ranges::any_of(
			   files.begin(), files.begin() + static_cast<std::ptrdiff_t>( index),
			   [&file]( const FixtureFile &previous) { return previous.name == file.name ; })) {
			return nullptr ;
		}

		catalogs += file.name.ends_with( L".cat") ? 1U : 0U ;
		infs += file.name.ends_with( L".inf") ? 1U : 0U ;
	}

	// 内部試験だけで128正常と129全体拒否の全閉包を固定し、各基本INFへ一CATを要求します。
	if( infs == 0U || infs > 129U || catalogs != infs) {
		return nullptr ;
	}

	// 全memberのownerは存在する基本INFへ結び、不明依存を空集合へ補完しません。
	for( const auto &file : files) {
		const auto owner	= file.infOwner ;	// 登録前の完全閉包名です。
		const auto ownerInf = std::ranges::find_if( files, [&owner]( const FixtureFile &entry) {
			return entry.name.ends_with( L".inf") && (owner.empty() || entry.name == owner) &&
				   entry.infOwner == owner ;
		}) ; // 存在する基本INFへだけmemberを結ぶ照合結果です。
		// 旧空ownerは単一INFに限り、複数閉包はexact基本INF名を必要とします。
		if( ownerInf == files.end() || (owner.empty() && infs != 1U) ||
		   (file.name.ends_with( L".inf") && !owner.empty() && file.name != owner) ||
		   std::ranges::count_if( files, [&owner]( const FixtureFile &entry) {
			   return entry.infOwner == owner && entry.name.ends_with( L".cat") ;
		   }) != 1) {
			return nullptr ;
		}
	}

	return std::unique_ptr<ScopedFixture>{new ScopedFixture( std::move( files), maximumRoots)} ;
}
#endif
} // namespace driver_package_signature_detail
} // namespace drivercrate
