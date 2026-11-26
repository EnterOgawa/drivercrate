//------------------------------------------------------------------------------
/**
 * @file official_file_verifier.cpp
 * @brief 公式配布file共通検証実装
 * @version 01.26.00
 * @date 2026/09/23
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  XML署名publisher検証追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  署名XMLのUTF-8 BOM対応
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  CAT member検証追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/09/23  公開SHA-512とSHA-256を有限stream・例外回収付き処理で共有
 * Ver.01.02.00 Shunji Ogawa  2026/09/23  全区間取得接続と公式module根拠付き許諾境界を追加
 * Ver.01.03.00 Shunji Ogawa  2026/09/25  収集metadata専用の8 MiB hash上限を分離
 * Ver.01.04.00 Shunji Ogawa  2026/10/06  原container専用の128 MiB hash入口を分離
 * Ver.01.05.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続
 * Ver.01.06.00 Shunji Ogawa  2026/10/12  完全file hashと同rootを二recordの内部署名表へ結合
 * Ver.01.07.00 Shunji Ogawa  2026/10/12  別基本INFの完全CAT/member集合と実rootを個別固定
 * Ver.01.08.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続
 * Ver.01.08.01 Shunji Ogawa  2026/10/12  default/delete宣言の所有権と非実行契約を補足
 * Ver.01.09.00 Shunji Ogawa  2026/10/13  内部CAT fixtureの同root別INF-owner照合を厳密化
 * Ver.01.10.00 Shunji Ogawa  2026/10/13  内部CATの安全相対memberを保護root・全位置・元owner/hashへ結合
 * Ver.01.11.00 Shunji Ogawa  2026/10/15  内部試験factoryだけをarchive128/129境界の完全入力へ拡張
 * Ver.01.11.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける
 * Ver.01.12.00 Shunji Ogawa  2026/10/17 同一Authenticode実装に明示cached-only入口を追加
 * Ver.01.13.00 Shunji Ogawa  2026/10/24  内部原archive試験から元native署名へ委譲
 * Ver.01.14.00 Shunji Ogawa  2026/11/05  CAT宣言のmember算法と外側署名を分けて共通検証
 * Ver.01.14.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.14.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.14.03 Shunji Ogawa  2026/11/13  847kの検証済みSYSTEM媒体作用と限定資格を接続
 * Ver.01.14.04 Shunji Ogawa  2026/11/13  847p9の型付きSYSTEM全作用と全選択資格を接続
 * Ver.01.15.00 Shunji Ogawa  2026/11/16  選択storageの原全作用・私有資格と通常導入経路を接続
 * Ver.01.16.00 Shunji Ogawa  2026/11/22  System32直下の補助EXEの現在状態を読み取る
 * Ver.01.17.00 Shunji Ogawa  2026/11/22  登録済み配布のCATと全メンバーを通信なしで照合
 * Ver.01.18.00 Shunji Ogawa  2026/11/23  System32とDriver Storeの保護付き実行ファイル読取りを共用
 * Ver.01.19.00 Shunji Ogawa  2026/11/23  正規drivers直下のSYSを保護付きで観測する
 * Ver.01.20.00 Shunji Ogawa  2026/11/23  System32直下のストレージ用イベント資源DLLを保護付きで観測する
 * Ver.01.21.00 Shunji Ogawa  2026/11/23  Windows同梱machine.infの空導入委譲を保護付きで検証する
 * Ver.01.22.00 Shunji Ogawa  2026/11/23  固定した元ファイルと信頼結果の署名者を一つの検査で照合
 * Ver.01.23.00 Shunji Ogawa  2026/11/23  信頼済みマニフェストの原SHA-1照合用に全ファイルを読取る
 * Ver.01.24.00 Shunji Ogawa  2026/11/23  公開INFとStoreの同梱署名の共通読取りを追加
 * Ver.01.25.00 Shunji Ogawa  2026/11/23  署名INFの同一バイトを保持する一時解析を共用
 * Ver.01.26.00 Shunji Ogawa  2026/11/23  選択済み登録配布のINF・CAT・SYSを保護付きで読取る
 * </pre>
 *
 * @note Windows CNGとWinTrustを使用し、Provider固有値をpolicyとして受け取ります
 */
//------------------------------------------------------------------------------

#include "platform/official_file_verifier.h"
#include "platform/official_mapped_file.h"
#include "platform/official_download_workspace.h"
#include "platform/driver_package_signature_internal.h"

// Windows.hはWinCryptおよびWinTrustの基本型より先に必要である
// clang-format off
#include <Windows.h>
#include <SetupAPI.h>
#include <Softpub.h>
#include <bcrypt.h>
#include <cryptxml.h>
#include <mscat.h>
#include <mssip.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <Aclapi.h>
#include <Sddl.h>
// clang-format on

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <iterator>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義
//------------------------------------------------------------------------------

constexpr std::wstring_view XML_CANONICALIZATION_ALGORITHM =
	L"http://www.w3.org/TR/2001/REC-xml-c14n-20010315" ;	// 許可C14N URI
constexpr std::wstring_view XML_SIGNATURE_ALGORITHM =
	L"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" ;	// 許可署名algorithm URI
constexpr std::wstring_view XML_DIGEST_ALGORITHM =
	L"http://www.w3.org/2001/04/xmlenc#sha256" ;	// 許可digest algorithm URI
constexpr std::wstring_view XML_ENVELOPED_TRANSFORM =
	L"http://www.w3.org/2000/09/xmldsig#enveloped-signature" ;	// 許可transform URI
constexpr std::size_t MAXIMUM_CATALOG_MEMBERS = 65'536U ;		// CAT宣言を読む有限member数です

//------------------------------------------------------------------------------
// 内部型定義
//------------------------------------------------------------------------------

/**
 * @brief 遅延解決したCryptCATAdminAcquireContext2を、Windows標準の署名のまま呼び出す関数型
 */
using AcquireCatalogContext = BOOL( WINAPI *)( HCATADMIN *, const GUID *, PCWSTR,
											 PCCERT_STRONG_SIGN_PARA, DWORD) ;
/**
 * @brief 遅延解決したCryptCATAdminCalcHashFromFileHandle2を、Windows標準の署名のまま呼び出す関数型
 */
using CalculateCatalogHash = BOOL( WINAPI *)( HCATADMIN, HANDLE, DWORD *, BYTE *, DWORD) ;
/**
 * @brief 取得済みcatalog contextをCryptCATAdminReleaseContextへ返すWindows標準の関数型
 */
using ReleaseCatalogContext = BOOL( WINAPI *)( HCATADMIN, DWORD) ;

/** @brief 一つの原CAT memberに結合した算法・digest・tagです */
struct CatalogMemberDigest {
	/// Windowsが定義する静的CNG算法名です
	PCWSTR			  algorithm{} ;
	/// 同じ原member宣言の完全digestです
	std::vector<BYTE> bytes ;
	/// 同じ原memberの完全reference tagです
	std::wstring	  tag ;
} ;

/**
 * @brief WinTrust.dllとCAT宣言算法のadministrator contextをscope内で所有する
 */
class CatalogHashContext final {
public:
	/**
	 * @brief 外部resourceを取得しない空の初期状態を作成します
	 */
	CatalogHashContext() = default ;

	//------------------------------------------------------------------------------
	/**
     * @brief Catalog hash contextを解放する
     *
     * Contextを先に解放し、最後にsystem WinTrust moduleを閉じる
     */
	//------------------------------------------------------------------------------
	~CatalogHashContext()
	{
		// contextと解放関数の両方がある場合だけcatalog管理contextを解放する
		if( catalogAdmin_ != nullptr && release_ != nullptr) {
			static_cast<void>( release_( catalogAdmin_, 0)) ;
		}

		// 取得したWinTrust moduleだけを解放する
		if( module_ != nullptr) {
			static_cast<void>( FreeLibrary( module_)) ;
		}
	}

	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	CatalogHashContext( const CatalogHashContext &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	CatalogHashContext &operator=( const CatalogHashContext &) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	CatalogHashContext( CatalogHashContext &&) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	CatalogHashContext		 &operator=( CatalogHashContext &&) = delete ;

	//------------------------------------------------------------------------------
	/**
	 * @brief Catalog hash contextを初期化する
	 * System32のWinTrust.dllだけを読み込み、元CATの検査済みmember算法だけでhash contextを作ります
	 * 外側署名のcurrent strong-sign policyは各memberのWinVerifyTrustへ別に要求します
	 * @param[in] algorithm 原CATの完全宣言から選んだ静的CNG名です
	 * @param[in] hashBytes 同じ原宣言で検査済みのdigest byte数です
	 * @return 宣言に一致するcontext作成成功時は0、失敗時はHRESULT
	 */
	//------------------------------------------------------------------------------
	[[nodiscard]] NativeError initialize( PCWSTR algorithm, DWORD hashBytes) ;

	//------------------------------------------------------------------------------
	/**
	 * @brief FileのCAT宣言算法のmember hashを計算する
	 * 初期化済みcontextと動的取得した公式APIだけを使用する
	 * @param[in] file 読取り可能な非所有file handle
	 * @param[out] hash 成功時だけ宣言算法の全digest。失敗時は空です
	 * @return 成功時は0、WinTrustまたはallocation失敗時はHRESULT
	 */
	//------------------------------------------------------------------------------
	[[nodiscard]] NativeError calculateHash( HANDLE file, std::vector<BYTE> &hash) const ;

	//------------------------------------------------------------------------------
	/**
     * @brief Catalog administrator contextを参照する
     *
     * WinVerifyTrust呼出し中だけ非所有handleとして公開する
     * @return 本instanceが所有するcontext handle
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] HCATADMIN	  get() const noexcept
	{
		return catalogAdmin_ ;
	}

private:
	/// FreeLibraryで閉じるsystem module
	HMODULE				  module_{} ;
	/// Release関数で閉じるcatalog context
	HCATADMIN			  catalogAdmin_{} ;
	/// WinTrust.dllから取得するcontext作成API
	AcquireCatalogContext acquire_{} ;
	/// WinTrust.dllから取得するhash計算API
	CalculateCatalogHash  calculate_{} ;
	/// WinTrust.dllから取得するcontext解放API
	ReleaseCatalogContext release_{} ;
	/// 一意のCAT宣言に対応するdigest byte数です。未初期化時は0です
	DWORD				  hashBytes_{} ;
} ;

/**
 * @brief Win32 file handleをscope終了時に閉じる
 */
class ReadOnlyVerificationFile final {
public:
	//------------------------------------------------------------------------------
	/**
     * @brief 読取り専用検証fileを所有する
     *
     * Hash計算からtrust検証終了までfileを置換不能にする
     *
     * @param[in] handle CloseHandleで閉じる所有file handle
     */
	//------------------------------------------------------------------------------
	explicit ReadOnlyVerificationFile( const HANDLE handle) noexcept : handle_( handle)
	{
	}

	//------------------------------------------------------------------------------
	/**
     * @brief 読取り専用検証fileを閉じる
     *
     * 有効な所有handleだけを一度閉じる
     */
	//------------------------------------------------------------------------------
	~ReadOnlyVerificationFile()
	{
		// 有効な所有file handleだけを閉じる
		if( handle_ != INVALID_HANDLE_VALUE) {
			static_cast<void>( CloseHandle( handle_)) ;
		}
	}

	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	ReadOnlyVerificationFile( const ReadOnlyVerificationFile &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	ReadOnlyVerificationFile &operator=( const ReadOnlyVerificationFile &) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	ReadOnlyVerificationFile( ReadOnlyVerificationFile &&) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	ReadOnlyVerificationFile &operator=( ReadOnlyVerificationFile &&) = delete ;

	//------------------------------------------------------------------------------
	/**
     * @brief 読取り専用検証file handleを参照する
     *
     * 所有権を移さず、現在のhashとtrust検証だけへ使用する
     * @return 本instanceが所有するfile handle
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] HANDLE	  get() const noexcept
	{
		return handle_ ;
	}

private:
	/// Destructorで閉じる所有file handle
	HANDLE handle_{INVALID_HANDLE_VALUE} ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief WinTrust.dllのprocedureを型付きpointerへ取得する
 * FARPROCと対象function pointerの同一sizeをcompile時に確認し、未定義なobject/function pointer castを使用せず複写する
 * @tparam Procedure FARPROCと同じsizeの呼出し先function pointer型です
 * @param[in] module System32から読み込んだ非所有module handle
 * @param[in] name Null終端のASCII export名
 * @param[out] procedure 成功時の型付きprocedure pointer
 * @return Exportが存在しpointerを取得できた場合は`true`
 */
//------------------------------------------------------------------------------
template <typename Procedure>
[[nodiscard]] bool loadCatalogProcedure( const HMODULE module, const char *const name,
										Procedure &procedure) noexcept
{
	procedure = nullptr ;
	// moduleやprocedure名が欠ける要求を解決しない
	if( module == nullptr || name == nullptr) {
		return false ;
	}

	const FARPROC address = GetProcAddress( module, name) ;	// 未型付けのexport address
	// procedureが存在しない場合は型付きpointerを作らない
	if( address == nullptr) {
		return false ;
	}

	static_assert( sizeof( procedure) == sizeof( address)) ;
	std::memcpy( &procedure, &address, sizeof( address)) ;
	return procedure != nullptr ;
}

/**
 * @brief CryptXMLへ検証対象文書を有限bufferから供給するcallback状態である
 */
struct XmlDataProviderState {
	/// 呼出し中だけ有効な非所有XML先頭pointer
	const BYTE *data{} ;
	/// 供給するXML全byte数
	std::size_t size{} ;
	/// 次回供給するbyte offset
	std::size_t position{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief CryptXMLへ参照文書の次のbyte群を供給する
 *
 * Callback境界から例外を漏らさず、検証済みbuffer範囲だけを順序通り供給する
 *
 * @param[in,out] statePointer 呼出し中有効なXmlDataProviderState
 * @param[out] output requested byte以上のCryptXML所有buffer
 * @param[in] requested CryptXMLが要求する最大byte数
 * @param[out] read 実際に供給したbyte数
 * @return 供給成功時S_OK、引数または状態不正時E_INVALIDARG
 */
//------------------------------------------------------------------------------
HRESULT CALLBACK readXmlProvider( void *const statePointer, BYTE *const output,
								 const ULONG requested, ULONG *const read) noexcept
{
	// state、出力件数、要求量に対応するbufferのpointer契約を確認する
	if( statePointer == nullptr || read == nullptr || (requested != 0 && output == nullptr)) {
		return E_INVALIDARG ;
	}

	// Win32 callbackが型なし状態pointerを要求する境界に限り、元の型へ戻す
	auto &state = *reinterpret_cast<XmlDataProviderState *>( statePointer) ;	// Provider状態
	// 読取り位置と入力bufferの整合性が崩れた参照状態を拒否する
	if( state.position > state.size || (state.size != 0 && state.data == nullptr)) {
		return E_INVALIDARG ;
	}

	const std::size_t remaining = state.size - state.position ;						// 未供給byte数
	const std::size_t count		= std::min<std::size_t>( remaining, requested) ;	// 今回供給数
	// 実際に転送するbyteがある場合だけbufferをcopyする
	if( count != 0) {
		std::memcpy( output, state.data + state.position, count) ;
	}

	state.position += count ;
	*read = static_cast<ULONG>( count) ;
	return S_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief CryptXML参照文書providerの利用終了を受理する
 *
 * Bufferを所有しないため解放せず、CryptXMLの終了通知だけを検証する
 *
 * @param[in] statePointer 呼出し中有効なXmlDataProviderState
 * @return Stateが存在する場合S_OK、nullの場合E_INVALIDARG
 */
//------------------------------------------------------------------------------
HRESULT CALLBACK closeXmlProvider( void *const statePointer) noexcept
{
	return statePointer == nullptr ? E_INVALIDARG : S_OK ;
}

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをHRESULT bit patternへ変換する
 *
 * 共通検証APIの失敗形式をProvider契約へ揃える
 *
 * @param[in] error Win32 error code
 * @return NativeErrorで保持するHRESULT bit pattern
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows CATのmember宣言を既知算法と正確な長さへ結びます
 * @param[in] indirect 原CATから借用するmemberの間接digest宣言です
 * @param[out] algorithm 成功時だけWindows CNGの静的算法名です。失敗時はnullです
 * @param[out] bytes 成功時だけ宣言に対応するbyte数です。失敗時は0です
 * @return 既知の完全な宣言なら0、未知・欠損・不正長はHRESULTです
 * @note 外側署名の算法や信頼をこの宣言から推測しません
 */
//------------------------------------------------------------------------------
NativeError readCatalogMemberAlgorithm( const SIP_INDIRECT_DATA &indirect, PCWSTR &algorithm,
									   DWORD &bytes) noexcept
{
	algorithm = nullptr ;
	bytes	  = 0U ;
	// 欠損したOIDやdigestを既定算法へ読み替えません
	if( indirect.DigestAlgorithm.pszObjId == nullptr || indirect.Digest.pbData == nullptr) {
		return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	}

	const std::string_view oid( indirect.DigestAlgorithm.pszObjId) ;	// 原APIの終端済みOIDです
	// Windowsで定義されたdigestの正確なOIDだけを選びます
	if( oid == szOID_OIWSEC_sha1) {
		algorithm = BCRYPT_SHA1_ALGORITHM ;
		bytes	  = 20U ;
	}
	// SHA256の完全OIDは別のmember算法として扱います
	else if( oid == szOID_NIST_sha256) {
		algorithm = BCRYPT_SHA256_ALGORITHM ;
		bytes	  = 32U ;
	}
	// SHA384のdigest長をSHA256へ縮約しません
	else if( oid == szOID_NIST_sha384) {
		algorithm = BCRYPT_SHA384_ALGORITHM ;
		bytes	  = 48U ;
	}
	// SHA512の元宣言は同じ64byte算法でのみ扱います
	else if( oid == szOID_NIST_sha512) {
		algorithm = BCRYPT_SHA512_ALGORITHM ;
		bytes	  = 64U ;
	} else {
		return static_cast<NativeError>( NTE_BAD_ALGID) ;
	}

	// 原digest全長が算法と一致しない場合は部分値を渡しません
	if( indirect.Digest.cbData != bytes) {
		algorithm = nullptr ;
		bytes	  = 0U ;
		return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じCATの全memberの宣言算法・digest・tagを有限に取得します
 * @param[in] path 置換防止の読取handleが保持される原CATの終端済みpathです
 * @param[out] declarations 成功時だけ全memberの原宣言です。失敗時は空です
 * @return 全宣言の取得なら0、空・未知・不正・容量超過ならHRESULTです
 * @note CAT構造を読むだけです。全memberの署名と内容は後段で必ず検証します
 */
//------------------------------------------------------------------------------
NativeError readCatalogAlgorithms( const std::wstring			   &path,
								  std::vector<CatalogMemberDigest> &declarations)
{
	declarations.clear() ;
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
	std::vector<std::wstring> syntheticHashes ;	// 明示人工scopeの元固定hashだけです
	// 既存人工CATは同root/owner/全hashのfixture契約で扱い、native入力へ拡張しません
	if( driver_package_signature_detail::readSyntheticCatalogDigests( path, syntheticHashes)) {
		constexpr std::wstring_view HEX = L"0123456789abcdef" ;	// 元固定hashをbyteへ戻す表です
		// 完全な元member hashだけから人工宣言を作ります
		for( const auto &hash : syntheticHashes) {
			CatalogMemberDigest declaration ;	// 原人工hashに一意な算法とtagです
			declaration.algorithm = BCRYPT_SHA256_ALGORITHM ;
			declaration.tag		  = hash ;
			std::transform( declaration.tag.begin(), declaration.tag.end(), declaration.tag.begin(),
						   []( const wchar_t value) {
							   return value >= L'a' && value <= L'f'
										  ? static_cast<wchar_t>( value - L'a' + L'A')
										  : value ;
						   }) ; // 元人工tagも既存のuppercase契約へ結びます
			// 先頭一致や不正hexを人工CATの成功へ補正しません
			if( hash.size() != 64U) {
				declarations.clear() ;
				return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
			}

			// 元32byteを欠落なく復元し、実memberのhash照合を省略しません
			for( std::size_t index = 0U; index < hash.size(); index += 2U) {
				const auto high = HEX.find( hash[index]) ;		// 原上位桁です
				const auto low	= HEX.find( hash[index + 1U]) ;	// 原下位桁です
				// factoryの検査とは別に、宣言化の前提を確認します
				if( high == HEX.npos || low == HEX.npos) {
					declarations.clear() ;
					return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
				}

				declaration.bytes.push_back( static_cast<BYTE>( high * 16U + low)) ;
			}

			declarations.push_back( std::move( declaration)) ;
		}

		return declarations.empty() ? static_cast<NativeError>( TRUST_E_BAD_DIGEST) : 0 ;
	}
#endif
	// Windowsの入力専用PWSTR ABIへ渡すためだけにconstを外し、原pathを変更しません
	const HANDLE catalog = CryptCATOpen( const_cast<PWSTR>( path.c_str()), CRYPTCAT_OPEN_EXISTING, 0U,
										CRYPTCAT_VERSION_1, 0U) ;	// 読取中だけ所有するCATです
	// 不正CATを既定算法へ補正しません
	if( catalog == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const std::unique_ptr<void, decltype( &CryptCATClose)> owner(
		catalog, &CryptCATClose) ;	// 例外でもCATを閉じます

	NativeError error = static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;	// 空CATは不完全です
	std::vector<CatalogMemberDigest> inspected ;						// 正常終端まで公開しない全原宣言です
	CRYPTCATMEMBER					*member{} ;							// API所有。次の列挙とcloseまでだけ借用します
	// 有限数の全宣言を検査し、未知memberを除外して成功にしません
	for( std::size_t index = 0U; index <= MAXIMUM_CATALOG_MEMBERS; ++index) {
		member = CryptCATEnumerateMember( catalog, member) ;
		// 一件以上の完全な宣言の正常終端だけを受理します
		if( member == nullptr) {
			break ;
		}

		// 容量超過や間接宣言欠落を署名済みという理由で無視しません
		if( index == MAXIMUM_CATALOG_MEMBERS || member->pIndirectData == nullptr) {
			error = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			break ;
		}

		PCWSTR current{} ;		// 同期中だけ使用するこの原memberの算法です
		DWORD  currentBytes{} ;	// この原digestの全長です
		error = readCatalogMemberAlgorithm( *member->pIndirectData, current, currentBytes) ;
		// 未知算法や不正なtagは別memberの正常宣言で隠しません
		if( error != 0 || member->pwszReferenceTag == nullptr ||
		   wcsnlen_s( member->pwszReferenceTag, 129U) !=
			   static_cast<std::size_t>( currentBytes) * 2U) {
			error = error != 0 ? error : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
			break ;
		}

		CatalogMemberDigest declaration ;	// 同じ原memberから所有copyを作ります
		declaration.algorithm = current ;
		declaration.bytes.assign( member->pIndirectData->Digest.pbData,
								 member->pIndirectData->Digest.pbData + currentBytes) ;
		declaration.tag = member->pwszReferenceTag ;
		inspected.push_back( std::move( declaration)) ;
	}

	// 全列挙が正常に終わった場合だけcontextの入力へ公開します
	if( error == 0 && member == nullptr && !inspected.empty()) {
		declarations = std::move( inspected) ;
		return 0 ;
	}

	return error != 0 ? error : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Catalog hash contextを初期化する。System32のWinTrust.dllだけを読み込み、元CATの検査済みmember算法だけでhash contextを作
 *        ります。外側署名のcurrent strong-sign policyは各memberのWinVerifyTrustへ別に要求します
 * @param[in] algorithm 原CATの完全宣言から選んだ静的CNG名です
 * @param[in] hashBytes 同じ原宣言で検査済みのdigest byte数です
 * @return 宣言に一致するcontext作成成功時は0、失敗時はHRESULT
 */
//------------------------------------------------------------------------------
NativeError CatalogHashContext::initialize( PCWSTR algorithm, DWORD hashBytes)
{
	// 初期化済みの所有資源を上書きしないよう、重複初期化を拒否する
	if( module_ != nullptr || catalogAdmin_ != nullptr) {
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}

	hashBytes_ = hashBytes ;

	module_ = LoadLibraryExW( L"wintrust.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32) ;
	// 暗号 API の module を取得できなければ、loader の診断値を返す
	if( module_ == nullptr) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 必要な catalog API が一つでも欠ける環境では検証を開始しない
	if( !loadCatalogProcedure( module_, "CryptCATAdminAcquireContext2", acquire_) ||
	   !loadCatalogProcedure( module_, "CryptCATAdminCalcHashFromFileHandle2", calculate_) ||
	   !loadCatalogProcedure( module_, "CryptCATAdminReleaseContext", release_)) {
		return nativeErrorFromWin32( ERROR_PROC_NOT_FOUND) ;
	}

	GUID subsystem = DRIVER_ACTION_VERIFY ;	// OS componentとthird-party driver用subsystem
	// 宣言算法のhashだけを取得します。署名強度は後段のAuthenticode trustへ別に要求します
	if( acquire_( &catalogAdmin_, &subsystem, algorithm, nullptr, 0) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief FileのCAT宣言算法のmember hashを計算する。初期化済みcontextと動的取得した公式APIだけを使用する
 * @param[in] file 読取り可能な非所有file handle
 * @param[out] hash 成功時だけ宣言算法の全digest。失敗時は空です
 * @return 成功時は0、WinTrustまたはallocation失敗時はHRESULT
 */
//------------------------------------------------------------------------------
NativeError CatalogHashContext::calculateHash( const HANDLE file, std::vector<BYTE> &hash) const
{
	hash.clear() ;
	// 未初期化 context または無効な file handle では hash 計算を受理しない
	if( catalogAdmin_ == nullptr || calculate_ == nullptr || file == INVALID_HANDLE_VALUE) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	DWORD required{} ;	// Catalog algorithmが要求するhash byte数
	// Hash buffer の必要量を取得できなければ、API の診断値を返す
	if( calculate_( catalogAdmin_, file, &required, nullptr, 0) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// OS contextが別算法を選んだ場合も、原CATの宣言と異なるdigestを渡しません
	if( required != hashBytes_) {
		return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	}

	try {
		hash.resize( required) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	DWORD actual = required ;	// 二回目のAPIが保存したhash byte数
	// Hash 計算に失敗した場合は、部分的な出力を消して診断値を返す
	if( calculate_( catalogAdmin_, file, &actual, hash.data(), 0) == FALSE) {
		hash.clear() ;
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 照会時と計算時の digest 長が一致しなければ、出力を破棄する
	if( actual != required) {
		hash.clear() ;
		return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一fileを指定catalogのmemberとして検証する
 *
 * 読取りhandleをtrust終了まで保持し、file置換とhash不一致をfail-closedで拒否する
 *
 * @param[in] contexts 原CAT宣言の既知算法で初期化済みのcontext集合です
 * @param[in] declarations 同じ原CATの全member宣言です
 * @param[in] catalogPath 検証するCAT file絶対path
 * @param[in] memberPath CATへ収録されるべきfile絶対path
 * @param[in] cachedOnly trueは既cache情報だけで署名を確認し、通信へfallbackしません
 * @return Member hashとcatalog trustが有効なら0、失敗時はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyCatalogMember(
	const std::span<const std::unique_ptr<CatalogHashContext>> contexts,
	const std::span<const CatalogMemberDigest> declarations, const std::wstring &catalogPath,
	const std::wstring &memberPath, const bool cachedOnly)
{
	const ReadOnlyVerificationFile file( CreateFileW(
		memberPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
		nullptr)) ;	// Trust終了まで保持するmember file
	// Member file を開けなければ catalog との照合へ進まない
	if( file.get() == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	FILE_ATTRIBUTE_TAG_INFO attributes{} ;	// Handleが指すfileのrace-free属性
	// 開いた file の属性を確認できなければ、検証対象として受理しない
	if( GetFileInformationByHandleEx( file.get(), FileAttributeTagInfo, &attributes,
									sizeof( attributes)) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 通常file検証でdirectoryとreparse経路を拒否する属性mask
	constexpr DWORD REJECTED_ATTRIBUTES = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT ;
	// 許可しない属性を持つ member file は署名照合前に拒否する
	if( (attributes.FileAttributes & REJECTED_ATTRIBUTES) != 0) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	try {
		constexpr std::wstring_view HEX = L"0123456789ABCDEF" ;	// CAT tag用uppercase hex
		std::wstring				memberTag ;					// 原CATの選択member tagです
		std::vector<BYTE>			hash ;						// 選択memberと一致した原file digestです
		const CatalogHashContext   *selected{} ;				// trust前の完全照合だけで決めます
		// 宣言済み算法の強い順に原digest/tagを照合し、trust失敗後の再試行はしません
		for( const auto &context : contexts) {
			LARGE_INTEGER beginning{} ;	// 各算法は同じ保持fileの先頭から読みます
			// 位置不明な部分fileをdigestの照合へ渡しません
			if( !SetFilePointerEx( file.get(), beginning, nullptr, FILE_BEGIN)) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			const auto error = context->calculateHash( file.get(), hash) ;	// 原hash API診断です
			// APIの失敗を別算法への切替で隠しません
			if( error != 0) {
				return error ;
			}

			std::wstring tag ;	// 同原digestの完全なhex表現です
			tag.reserve( hash.size() * 2U) ;
			// CAT参照tagを各byte二桁で作り、basenameを使いません
			for( const auto byte : hash) {
				tag.push_back( HEX[(byte >> 4U) & 0x0fU]) ;
				tag.push_back( HEX[byte & 0x0fU]) ;
			}

			const auto found = std::ranges::find_if( declarations, [&]( const auto &declaration) {
				return declaration.bytes == hash &&
					   CompareStringOrdinal( declaration.tag.c_str(), -1, tag.c_str(), -1, TRUE) ==
						   CSTR_EQUAL ;
			}) ; // 同期中だけ全原宣言を借用します
			// 原digestとtagの完全一致だけで一度のtrust対象を確定します
			if( found != declarations.end()) {
				selected  = context.get() ;
				memberTag = found->tag ;
				break ;
			}
		}

		// 改変memberや宣言外digestにはtrustの成功を要求する対象自体がありません
		if( selected == nullptr) {
			return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		}

		WINTRUST_CATALOG_INFO catalog{} ;	// WinTrustへ渡すCAT member情報
		catalog.cbStruct			 = sizeof( catalog) ;
		catalog.pcwszCatalogFilePath = catalogPath.c_str() ;
		catalog.pcwszMemberTag		 = memberTag.c_str() ;
		catalog.pcwszMemberFilePath	 = memberPath.c_str() ;
		catalog.hMemberFile			 = file.get() ;
		catalog.pbCalculatedFileHash = hash.data() ;
		catalog.cbCalculatedFileHash = static_cast<DWORD>( hash.size()) ;
		catalog.hCatAdmin			 = selected->get() ;
		WINTRUST_DATA trust{} ;	// UIを出さないcatalog member trust設定
		trust.cbStruct			  = sizeof( trust) ;
		trust.dwUIChoice		  = WTD_UI_NONE ;
		trust.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN ;
		trust.dwUnionChoice		  = WTD_CHOICE_CATALOG ;
		trust.pCatalog			  = &catalog ;
		trust.dwStateAction		  = WTD_STATEACTION_VERIFY ;
		trust.dwProvFlags		  = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
							(cachedOnly ? WTD_CACHE_ONLY_URL_RETRIEVAL : 0U) ;
		CERT_STRONG_SIGN_PARA signingPolicy{} ;	// 元の現在OS強度を外側署名へ要求します
		signingPolicy.cbSize	   = sizeof( signingPolicy) ;
		signingPolicy.dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE ;
		char strongSignOid[] = szOID_CERT_STRONG_SIGN_OS_CURRENT ;	// API寿命内の変更可能OIDです
		signingPolicy.pszOID = strongSignOid ;
		WINTRUST_SIGNATURE_SETTINGS settings{} ;	// member digest算法と独立した署名強度です
		settings.cbStruct	   = sizeof( settings) ;
		settings.pCryptoPolicy = &signingPolicy ;
		// SYSTEM経路はpublisher照会と同じ先頭署名だけを検証し、別署名へ切り替えません
		if( cachedOnly) {
			settings.dwFlags = WSS_VERIFY_SPECIFIC ;
			settings.dwIndex = 0U ;
		}

		trust.pSignatureSettings = &settings ;
		GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2 ;	// 元の全member Authenticode policyです
		const auto verify =
			cachedOnly
				? driver_package_signature_detail::authenticodeApi().verify
				: &driver_package_signature_detail::verifyTrust ;	// 通常経路の表を変更しません
		const LONG status	= verify( nullptr, &action, &trust) ;	// 同member検証結果
		trust.dwStateAction = WTD_STATEACTION_CLOSE ;
		static_cast<void>( verify( nullptr, &action, &trust)) ;
		return status == ERROR_SUCCESS ? 0 : static_cast<NativeError>( status) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Publisher表示名を大文字小文字無視で完全一致する
 *
 * 大文字小文字以外を正規化せず、punctuation差も許可しない
 *
 * @param[in] left 比較する一方のpublisher表示名
 * @param[in] right 比較する他方のpublisher表示名
 * @return Windows ordinal比較で全code unitが一致した場合は`true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool publisherNamesEqual( const std::wstring_view left,
									   const std::wstring_view right) noexcept
{
	// 空の表示名と Windows API の文字数範囲を超える入力は一致と扱わない
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
 * @brief Publisher allowlistの形式と重複を検証する
 *
 * AuthenticodeとXML署名で同じ完全一致policyを使用する
 *
 * @param[in] acceptedPublishers 許可publisher表示名群
 * @return 一意で空でないpolicyは0、不正policyはE_INVALIDARG
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validatePublisherPolicy(
	const std::span<const std::wstring_view> acceptedPublishers)
{
	// Publisher の許可条件が空の場合は、無制限の受理へ退避せず拒否する
	if( acceptedPublishers.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 許可する publisher を順に検査し、形式不正と重複を排除する
	for( std::size_t index = 0; index < acceptedPublishers.size(); ++index) {
		const std::wstring_view publisher = acceptedPublishers[index] ;	// 現在のpolicy表示名
		// 空文字、埋込み NUL、比較 API の上限超過を含む許可名は拒否する
		if( publisher.empty() || publisher.find( L'\0') != std::wstring_view::npos ||
		   publisher.size() > static_cast<std::size_t>( std::numeric_limits<int>::max())) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		// 既に検査した許可名だけと比較し、同じ publisher の重複を検出する
		for( std::size_t previous = 0; previous < index; ++previous) {
			// 大文字小文字を無視して同じ publisher 名があれば policy を拒否する
			if( publisherNamesEqual( publisher, acceptedPublishers[previous])) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief SHA-256文字列を小文字ASCII hexへ検証・正規化する
 *
 * Unicode類似文字を拒否し、ASCII 16進文字だけを許可する
 *
 * @param[in] value 親metadataが宣言したSHA-256
 * @param[out] normalized 成功時の64桁小文字ASCII hex
 * @return 形式が正しい場合は`true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool normalizeSha256( const std::wstring_view value, std::wstring &normalized)
{
	normalized.clear() ;
	// SHA-256 の hex 表現に必要な 64 文字以外は受理しない
	if( value.size() != 64) {
		return false ;
	}

	normalized.reserve( value.size()) ;
	// 全ての桁を hex として検査し、許可した文字だけを小文字表現へ移す
	for( const wchar_t character : value) {
		// 数値の hex 桁は表記を変えずに正規化結果へ残す
		if( character >= L'0' && character <= L'9') {
			normalized.push_back( character) ;
		}
		// 小文字の hex 桁はそのまま正規化結果へ残す
		else if( character >= L'a' && character <= L'f') {
			normalized.push_back( character) ;
		}
		// 大文字の hex 桁だけを対応する小文字へ変換する
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
 * @brief Fileの実byte数を取得する
 *
 * Metadata宣言sizeとの完全一致検証に使用する
 *
 * @param[in] path 読取り対象file絶対path
 * @param[out] size 成功時のfile byte数
 * @return 成功時は0、file API失敗時はHRESULT bit pattern
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readFileSize( const std::wstring_view path, std::uint64_t &size)
{
	size = 0 ;
	// 対象を指定していない size 照会は入力不正として拒否する
	if( path.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring filePath( path) ;	// CreateFile用終端null付きpath
	// 属性照合のために開く所有file handle。後続処理でCloseHandleする
	const HANDLE	   file = CreateFileW( filePath.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
										  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) ;
	// 対象 file を開けない場合は Windows の診断値を保持する
	if( file == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	LARGE_INTEGER length{} ;														// Signed 64-bit file size
	const BOOL	  succeeded = GetFileSizeEx( file, &length) ;						// Size取得成否
	const DWORD	  error		= succeeded != FALSE ? ERROR_SUCCESS : GetLastError() ;	// 保存するerror
	CloseHandle( file) ;
	// Size 照会の失敗を handle 解放後も保持した診断値で返す
	if( succeeded == FALSE) {
		return nativeErrorFromWin32( error) ;
	}

	// 負の file size は有効な byte 数へ変換せず拒否する
	if( length.QuadPart < 0) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	size = static_cast<std::uint64_t>( length.QuadPart) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 上限付きで通常file全体を読み取る
 *
 * XML署名parserへ渡す前にdirectoryとreparse pointを拒否する
 *
 * @param[in] path 読取り対象file絶対path
 * @param[in] maximumBytes 0より大きい許容byte数上限
 * @param[out] bytes 成功時のfile全byte
 * @return 成功時は0、属性、size、read失敗時はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readFileBytes( const std::wstring_view path,
										const std::uint64_t maximumBytes, std::vector<BYTE> &bytes)
{
	bytes.clear() ;
	// 空の path と API の範囲外の読取り上限は、file を開く前に拒否する
	if( path.empty() || maximumBytes == 0 ||
	   maximumBytes > static_cast<std::uint64_t>( std::numeric_limits<ULONG>::max())) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring pathString( path) ;										// Win32 API用終端null付きpath
	const DWORD		   attributes = GetFileAttributesW( pathString.c_str()) ;	// File属性
	// 属性を照会できない file は通常 file と仮定せず拒否する
	if( attributes == INVALID_FILE_ATTRIBUTES) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// Hash検証へ渡さないdirectory・reparse属性のmask
	constexpr DWORD REJECTED_ATTRIBUTES = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT ;
	// 許可しない属性を持つ file は内容を読み取らない
	if( (attributes & REJECTED_ATTRIBUTES) != 0) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::uint64_t	  length{} ;								// Filesystemが返す実byte数
	const NativeError sizeError = readFileSize( path, length) ;	// Size取得結果
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( sizeError != 0) {
		return sizeError ;
	}

	// 空の file、policy 上限超過、ReadFile の長さ範囲超過を拒否する
	if( length == 0 || length > maximumBytes ||
	   length > static_cast<std::uint64_t>( std::numeric_limits<DWORD>::max())) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	// 検証対象を読取り専用で固定する所有handle。後続処理でCloseHandleする
	const HANDLE file = CreateFileW( pathString.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
									OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr) ;
	// File を開けなければ buffer への読取りを開始しない
	if( file == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	bytes.resize( static_cast<std::size_t>( length)) ;
	DWORD	   read{} ;	// ReadFileが返したbyte数
	const BOOL succeeded =
		// Read結果
		ReadFile( file, bytes.data(), static_cast<DWORD>( length), &read, nullptr) ;
	const DWORD error = succeeded != FALSE ? ERROR_SUCCESS : GetLastError() ;	// 保存するerror
	CloseHandle( file) ;
	// 読取り失敗時は部分 buffer を破棄し、保存した診断値を返す
	if( succeeded == FALSE) {
		bytes.clear() ;
		return nativeErrorFromWin32( error) ;
	}

	// 宣言 size まで読み取れなければ、短い内容を正常結果として返さない
	if( read != length) {
		bytes.clear() ;
		return nativeErrorFromWin32( ERROR_HANDLE_EOF) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Certificateのsimple display nameを取得する
 *
 * Publisher policyとの完全一致に使用する表示名だけを返す
 *
 * @param[in] certificate 呼出し中有効なX.509 certificate
 * @param[out] name 成功時のsimple display name
 * @return 取得成功時は0、不正certificateはHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readCertificateName( const CERT_CONTEXT &certificate, std::wstring &name)
{
	name.clear() ;
	const DWORD characters = CertGetNameStringW( &certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
												nullptr, nullptr, 0) ;	// 終端null込み文字数
	// 終端文字以外の certificate 表示名がない場合は受理しない
	if( characters <= 1) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::wstring buffer( characters, L'\0') ;	// Certificate表示名受信buffer
	// 照会した文字数どおりに certificate 名を取得できなければ拒否する
	if( CertGetNameStringW( &certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, buffer.data(),
						  characters) != characters) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	buffer.resize( characters - 1) ;
	// 空または埋込み NUL を含む表示名は publisher 照合へ渡さない
	if( buffer.empty() || buffer.find( L'\0') != std::wstring::npos) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	name = std::move( buffer) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定時刻のcode-signing certificate chainを検証する
 *
 * 署名で保護されたSigningTimeをcertificate有効時刻に使用する
 *
 * @param[in] certificate 署名検証に使用したX.509 certificate
 * @param[in] validationFiletime 1601年起点100ns単位の署名時刻
 * @return Chain、revocation、code-signing用途が有効なら0
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyCodeSigningChain( const CERT_CONTEXT &certificate,
												 const std::uint64_t validationFiletime)
{
	// 検証時刻が指定されていない certificate chain 検証は拒否する
	if( validationFiletime == 0) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	ULARGE_INTEGER ticks{} ;	// FILETIMEのHigh/Lowへ分割する署名時刻
	ticks.QuadPart = validationFiletime ;
	FILETIME validationTime{} ;	// CertGetCertificateChainへ渡す署名時刻
	validationTime.dwLowDateTime  = ticks.LowPart ;
	validationTime.dwHighDateTime = ticks.HighPart ;

	LPSTR usageIdentifiers[] = {
		const_cast<LPSTR>( szOID_PKIX_KP_CODE_SIGNING)} ;	// 読取り専用code-signing EKU
	CERT_CHAIN_PARA parameters{} ;							// Chain build policy
	parameters.cbSize									 = sizeof( parameters) ;
	parameters.RequestedUsage.dwType					 = USAGE_MATCH_TYPE_AND ;
	parameters.RequestedUsage.Usage.cUsageIdentifier	 = 1 ;
	parameters.RequestedUsage.Usage.rgpszUsageIdentifier = usageIdentifiers ;
	PCCERT_CHAIN_CONTEXT chain{} ;	// CertFreeCertificateChainで解放するchain
	// 信頼chainでroot以外の失効確認を要求するWindows検証flag
	constexpr DWORD		 CHAIN_FLAGS = CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT ;
	// 指定時刻の certificate chain を構築できなければ、その失敗を返す
	if( CertGetCertificateChain( nullptr, &certificate, &validationTime, nullptr, &parameters,
							   CHAIN_FLAGS, nullptr, &chain) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	CERT_CHAIN_POLICY_PARA policy{} ;	// Base Windows chain policy設定
	policy.cbSize = sizeof( policy) ;
	CERT_CHAIN_POLICY_STATUS status{} ;	// Policy検証結果
	status.cbSize		 = sizeof( status) ;
	const BOOL	verified = CertVerifyCertificateChainPolicy( CERT_CHAIN_POLICY_BASE, chain, &policy,
															&status) ;				// Chain policy結果
	const DWORD error	 = verified != FALSE ? status.dwError : GetLastError() ;	// 保存するerror
	CertFreeCertificateChain( chain) ;
	// Chain policy の検証 API が失敗した場合は、保存した診断値を返す
	if( verified == FALSE) {
		return nativeErrorFromWin32( error) ;
	}

	return error == ERROR_SUCCESS ? 0 : nativeErrorFromWin32( error) ;
}

//------------------------------------------------------------------------------
/**
 * @brief XML署名KeyInfoから単一certificateを取得する
 *
 * RetrievalMethodやcustom KeyInfoを拒否し、鍵差替えを防ぐ
 *
 * @param[in] signature CryptXMLが解析した単一Signature
 * @param[out] certificate 成功時に呼出し側が解放するcertificate
 * @return KeyValueと単一X509Certificateを取得できた場合は0
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError findXmlCertificate( const CRYPT_XML_SIGNATURE &signature,
											 PCCERT_CONTEXT			   &certificate)
{
	certificate = nullptr ;
	// KeyInfo の欠落、件数超過、配列不整合は XML 署名形式の不正として拒否する
	if( signature.pKeyInfo == nullptr || signature.pKeyInfo->cKeyInfo == 0 ||
	   signature.pKeyInfo->cKeyInfo > 8 || signature.pKeyInfo->rgKeyInfo == nullptr) {
		return static_cast<NativeError>( TRUST_E_SUBJECT_FORM_UNKNOWN) ;
	}

	bool					   keyValueFound{} ;	// KeyValueを一つ確認した場合true
	const CRYPT_XML_DATA_BLOB *encoded{} ;			// KeyInfo内の単一certificate DER
	// 上限内の KeyInfo を調べ、鍵情報と単一 certificate を抽出する
	for( UINT index = 0; index < signature.pKeyInfo->cKeyInfo; ++index) {
		const CRYPT_XML_KEY_INFO_ITEM &item = signature.pKeyInfo->rgKeyInfo[index] ;	// 現在項目
		// KeyValue は存在を記録し、certificate の抽出とは区別して扱う
		if( item.dwType == CRYPT_XML_KEYINFO_TYPE_KEYVALUE) {
			// 複数の KeyValue を許可して検証対象の鍵を曖昧にしない
			if( keyValueFound) {
				return static_cast<NativeError>( TRUST_E_SUBJECT_FORM_UNKNOWN) ;
			}

			keyValueFound = true ;
			continue ;
		}

		// 許可した X509Data 以外の形式と不正な配列件数は拒否する
		if( item.dwType != CRYPT_XML_KEYINFO_TYPE_X509DATA || item.X509Data.cX509Data == 0 ||
		   item.X509Data.cX509Data > 8 || item.X509Data.rgX509Data == nullptr) {
			return static_cast<NativeError>( TRUST_E_SUBJECT_FORM_UNKNOWN) ;
		}

		// X509Data の各項目を確認し、certificate の重複と未知形式を排除する
		for( UINT dataIndex = 0; dataIndex < item.X509Data.cX509Data; ++dataIndex) {
			const CRYPT_XML_X509DATA_ITEM &data =	// 現在のX509Data項目
				item.X509Data.rgX509Data[dataIndex] ;
			// Certificate 項目だけから検証用の encoded certificate を選ぶ
			if( data.dwType == CRYPT_XML_X509DATA_TYPE_CERTIFICATE) {
				// Certificate の重複、空の内容、無効な data pointer は拒否する
				if( encoded != nullptr || data.Certificate.cbData == 0 ||
				   data.Certificate.pbData == nullptr) {
					return static_cast<NativeError>( TRUST_E_SUBJECT_FORM_UNKNOWN) ;
				}

				encoded = &data.Certificate ;
			}
			// Certificate 以外では issuer/serial と subject name の項目だけを許可する
			else if( data.dwType != CRYPT_XML_X509DATA_TYPE_ISSUER_SERIAL &&
					data.dwType != CRYPT_XML_X509DATA_TYPE_SUBJECT_NAME) {
				return static_cast<NativeError>( TRUST_E_SUBJECT_FORM_UNKNOWN) ;
			}
		}
	}

	// 鍵情報と certificate の両方が揃わなければ署名検証を開始しない
	if( !keyValueFound || encoded == nullptr) {
		return static_cast<NativeError>( TRUST_E_SUBJECT_FORM_UNKNOWN) ;
	}

	certificate = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
											   encoded->pbData, encoded->cbData) ;
	return certificate == nullptr ? nativeErrorFromWin32( GetLastError()) : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief XML署名algorithmとdocument referenceを制限する
 *
 * External reference、複数reference、弱いalgorithmを拒否する
 *
 * @param[in] signature CryptXMLが解析した単一Signature
 * @return 文書全体への許可algorithmだけなら`true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAllowedXmlSignature( const CRYPT_XML_SIGNATURE &signature) noexcept
{
	const CRYPT_XML_SIGNED_INFO &information = signature.SignedInfo ;	// SignedInfo参照
	// 署名方式、正規化方式、単一 reference の構造が policy と異なる場合は拒否する
	if( information.Canonicalization.wszAlgorithm == nullptr ||
	   information.SignatureMethod.wszAlgorithm == nullptr || information.cReference != 1 ||
	   information.rgpReference == nullptr || information.rgpReference[0] == nullptr ||
	   XML_CANONICALIZATION_ALGORITHM != information.Canonicalization.wszAlgorithm ||
	   XML_SIGNATURE_ALGORITHM != information.SignatureMethod.wszAlgorithm) {
		return false ;
	}

	const CRYPT_XML_REFERENCE &reference = *information.rgpReference[0] ;	// 文書reference
	return reference.wszUri != nullptr && reference.wszUri[0] == L'\0' &&
		   reference.DigestMethod.wszAlgorithm != nullptr &&
		   XML_DIGEST_ALGORITHM == reference.DigestMethod.wszAlgorithm &&
		   reference.cTransform == 1 && reference.rgTransform != nullptr &&
		   reference.rgTransform[0].wszAlgorithm != nullptr &&
		   XML_ENVELOPED_TRANSFORM == reference.rgTransform[0].wszAlgorithm ;
}

//------------------------------------------------------------------------------
/**
 * @brief 検証済みembedded又はCATのPKCS#7 signer表示名を取得します
 *
 * 原署名のsignerをissuerとserial numberで同storeから解決します
 *
 * @param[in] path Chain検証済みfileの絶対path
 * @param[out] signerName 成功時のcertificate simple display name
 * @param[in] catalog trueはCAT署名、falseは元embedded署名を読取ります
 * @return 取得成功時は0、PKCS#7またはcertificate失敗時はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readSignerName( const std::wstring_view path, std::wstring &signerName,
										 const bool catalog = false)
{
	signerName.clear() ;
	const auto &api =
		// 同trustと同じ低位backendです
		driver_package_signature_detail::authenticodeApi() ;
	const std::wstring pathString( path) ;	// WinCrypt用終端null付きpath
	DWORD			   encoding{} ;			// Certificate encoding flags
	DWORD			   contentType{} ;		// PKCS#7 content種別
	DWORD			   formatType{} ;		// Binary format種別
	HCERTSTORE		   store{} ;			// CertCloseStoreで閉じるstore
	HCRYPTMSG		   message{} ;			// CryptMsgCloseで閉じるmessage
	// Embedded Authenticode 情報を取得できなければ publisher 名を推測しない
	if( api.query( CERT_QUERY_OBJECT_FILE, pathString.c_str(),
				 catalog ? CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED
						 : CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
				 CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &contentType, &formatType, &store,
				 &message, nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	DWORD		signerBytes{} ;	// CMSG_SIGNER_INFOに必要なbyte数
	NativeError result{} ;		// Cleanup後に返す処理結果
	// Signer 情報の buffer 長を照会できなければ、処理結果へ失敗を残す
	if( api.messageParameter( message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerBytes) == FALSE) {
		result = nativeErrorFromWin32( GetLastError()) ;
	}
	// Signer 構造体より短い情報は不正形式として拒否する
	else if( signerBytes < sizeof( CMSG_SIGNER_INFO)) {
		result = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	} else {
		std::vector<std::byte> signerBuffer( signerBytes) ;	// Signer情報受信buffer
		// Signer 情報本体を取得できなければ、API の失敗を記録する
		if( api.messageParameter( message, CMSG_SIGNER_INFO_PARAM, 0, signerBuffer.data(),
								&signerBytes) == FALSE) {
			result = nativeErrorFromWin32( GetLastError()) ;
		} else {
			const auto *const signer =	// Buffer lifetime中だけ有効なsigner情報
				reinterpret_cast<const CMSG_SIGNER_INFO *>( signerBuffer.data()) ;
			CERT_INFO match{} ;	// Issuerとserial numberによるcertificate検索key
			match.Issuer			   = signer->Issuer ;
			match.SerialNumber		   = signer->SerialNumber ;
			PCCERT_CONTEXT certificate = api.findCertificate(
				store, encoding, 0, CERT_FIND_SUBJECT_CERT, &match, nullptr) ;	// Signer証明書
			// Signer に対応する certificate が見つからなければ名前照会へ進まない
			if( certificate == nullptr) {
				result = nativeErrorFromWin32( GetLastError()) ;
			} else {
				const DWORD characters = api.certificateName(
					certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0) ;	// 文字数
				// 空の signer 表示名は publisher 検証に使用しない
				if( characters <= 1) {
					result = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				} else {
					std::wstring name( characters, L'\0') ;	// 終端null込み表示名buffer
					// 予定した文字数の signer 名を取得できなければ不正 data とする
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

//------------------------------------------------------------------------------
namespace {
/** @brief File hash用CNG資源を全return・例外経路で回収します */
struct FileHashHandles {
	/// Algorithm providerの所有handle
	BCRYPT_ALG_HANDLE  algorithm{} ;
	/// Algorithmより先に解放するhash handle
	BCRYPT_HASH_HANDLE hash{} ;
	/**
	 * @brief 有効なCNG資源を依存順に解放します
	 */
	~FileHashHandles()
	{
		// 生成できたhashだけを先に破棄する
		if( hash != nullptr) {
			BCryptDestroyHash( hash) ;
		}

		// Hashから参照されなくなったalgorithmを閉じる
		if( algorithm != nullptr) {
			BCryptCloseAlgorithmProvider( algorithm, 0) ;
		}
	}
} ;
//------------------------------------------------------------------------------
/**
 * @brief 固定SHA algorithmを使ってfile全体をstream計算します
 * @tparam DigestBytes 元マニフェスト照合用SHA-1の20、SHA-256の32、またはSHA-512の64
 * @param[in] path 読取り専用file path
 * @param[in] algorithmId 呼出元が固定したCNG algorithm
 * @param[out] output 成功時だけ公開する小文字hex
 * @return 成功0、入力・file・CNG・allocation失敗時はHRESULT
 */
//------------------------------------------------------------------------------
template <std::size_t DigestBytes>
[[nodiscard]] NativeError computeFileSha( const std::wstring_view path, const wchar_t *algorithmId,
										 std::wstring &output)
{
	static_assert( DigestBytes == 20U || DigestBytes == 32U || DigestBytes == 64U) ;
	output.clear() ;
	// 空または埋込みNULを異なるpathへ読み替えない
	if( path.empty() || path.find( L'\0') != path.npos) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		std::vector<UCHAR> object ;		// Hash handleより長く生存するCNG storage
		FileHashHandles	   handles ;	// Object解放前にhashとalgorithmを回収する
		// 固定algorithmの開始から各CNG操作の診断を保持する
		NTSTATUS status = BCryptOpenAlgorithmProvider( &handles.algorithm, algorithmId, nullptr, 0) ;
		// 固定algorithmを開始できなければ失敗を保持する
		if( status < 0) {
			return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
		}

		DWORD objectBytes{} ;	// CNGが要求するstorage量
		DWORD resultBytes{} ;	// Property出力byte数
		status = BCryptGetProperty( handles.algorithm, BCRYPT_OBJECT_LENGTH,
								   reinterpret_cast<PUCHAR>( &objectBytes), sizeof( objectBytes),
								   &resultBytes, 0) ;
		// CNG境界の受信型と有限storageを検証する
		if( status < 0 || resultBytes != sizeof( objectBytes) || objectBytes == 0U ||
		   objectBytes > 1024U * 1024U) {
			return status < 0 ? static_cast<NativeError>( HRESULT_FROM_NT( status))
							  : static_cast<NativeError>( E_UNEXPECTED) ;
		}

		object.resize( objectBytes) ;
		status = BCryptCreateHash( handles.algorithm, &handles.hash, object.data(), objectBytes,
								  nullptr, 0, 0) ;
		// Hash生成失敗時もalgorithmはscopeで回収する
		if( status < 0) {
			return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
		}

		const std::wstring		 terminated( path) ;	// Win32向け終端付きpath
		ReadOnlyVerificationFile file( CreateFileW( terminated.c_str(), GENERIC_READ, FILE_SHARE_READ,
												  nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN,
												  nullptr)) ;	// 書換え・削除共有なし
		// Fileを開けない場合は元Win32診断を返す
		if( file.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		std::vector<UCHAR> buffer( 64U * 1024U) ;	// File長に依存しない有限read buffer
		// EOFまたは最初のfile／hash失敗まで順序どおり全byteを処理する
		while( true) {
			DWORD read{} ;	// 今回の確定read byte数
			// 部分read失敗を成功digestへ変更しない
			if( !ReadFile( file.get(), buffer.data(), static_cast<DWORD>( buffer.size()), &read,
						 nullptr)) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			// 0 byteはEOFとして一度だけ終了する
			if( read == 0U) {
				break ;
			}

			status = BCryptHashData( handles.hash, buffer.data(), read, 0) ;
			// 更新失敗時に残りのfileを無視してdigestを返さない
			if( status < 0) {
				return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
			}
		}

		std::array<UCHAR, DigestBytes> digest{} ;	// Algorithmに対応する固定出力
		status =
			BCryptFinishHash( handles.hash, digest.data(), static_cast<ULONG>( digest.size()), 0) ;
		// CNGが固定出力量を受理しない場合は結果を公開しない
		if( status < 0) {
			return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
		}

		constexpr wchar_t HEX[] = L"0123456789abcdef" ;	// 小文字hex変換表
		std::wstring	  completed ;					// Allocation終了後だけ公開する完成hash
		completed.reserve( DigestBytes * 2U) ;
		// Digestを先頭から二桁ずつ変換する
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

//------------------------------------------------------------------------------
/**
 * @brief File全体のSHA-256を小文字ASCII hexへ変換する。EOFまでの全byteをCNG SHA-256へ順序通り入力する
 * @param[in] path 読み取るfileの絶対path
 * @param[out] sha256 成功時の64桁小文字SHA-256。失敗時は空
 * @return 成功時は0、fileまたはCNG処理失敗時はHRESULT bit pattern。 成功時は0、fileまたはCNG失敗時はHRESULT bit pattern
 */
//------------------------------------------------------------------------------
NativeError computeFileSha256( const std::wstring_view path, std::wstring &sha256)
{
	return computeFileSha<32U>( path, BCRYPT_SHA256_ALGORITHM, sha256) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 信頼済み元マニフェストに宣言されたSHA-1との比較用にファイル全体を読取る
 * @param[in] path 呼出し側が読取り中固定した通常ファイルの絶対path
 * @param[out] sha1 成功時の40桁小文字hex。失敗時は空
 * @return 成功0、fileまたはCNG失敗時はHRESULT
 * @note SHA-256による元取得の照合、配布元の署名検証、ドライバーCAT検査の代替には使わない
 */
//------------------------------------------------------------------------------
NativeError computeFileSha1ForSignedManifest( const std::wstring_view path, std::wstring &sha1)
{
	return computeFileSha<20U>( path, BCRYPT_SHA1_ALGORITHM, sha1) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 用途別の有限上限を適用する共通CNG byte hash処理です
 * @param[in] bytes Hashする原byte列
 * @param[in] maximumBytes 呼出用途が固定した有限上限
 * @param[out] sha256 成功時の小文字hash、失敗時は空です
 * @return 成功0、上限拒否またはCNG失敗のHRESULT
 */
//------------------------------------------------------------------------------
static NativeError computeBoundedBytesSha256( const std::string_view bytes,
											 const std::size_t maximumBytes, std::wstring &sha256)
{
	sha256.clear() ;
	// Scriptと有限snapshot以外の無制限memory入力を受理しない
	if( bytes.empty() || bytes.size() > maximumBytes) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		std::vector<UCHAR> input( bytes.begin(), bytes.end()) ;	// CNG向け原byte copy
		FileHashHandles	   handles ;							// 早期returnでもalgorithmを回収する
		NTSTATUS status = BCryptOpenAlgorithmProvider( &handles.algorithm, BCRYPT_SHA256_ALGORITHM,
													  nullptr, 0) ;	// 固定algorithm
		// Algorithm取得失敗を空hash成功へ変換しない
		if( status < 0) {
			return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
		}

		std::array<UCHAR, 32U> digest{} ;	// 固定SHA-256出力
		status = BCryptHash( handles.algorithm, nullptr, 0, input.data(),
							static_cast<ULONG>( input.size()), digest.data(),
							static_cast<ULONG>( digest.size())) ;
		// CNG失敗時は部分digestを公開しない
		if( status < 0) {
			return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
		}

		constexpr wchar_t HEX[] = L"0123456789abcdef" ;	// 小文字hex表
		std::wstring	  completed ;					// 割当て成功後だけ公開するdigest
		completed.reserve( 64U) ;
		// 各byteを欠落なく二桁へ変換する
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

//------------------------------------------------------------------------------
/**
 * @brief 最大1 MiBの原byte列からSHA-256を計算します
 * @param[in] bytes 空でない有限入力。BOM等を正規化しません
 * @param[out] sha256 成功時の小文字64桁hex。失敗時は空
 * @return 成功0、入力不正またはCNG失敗時はHRESULT
 */
//------------------------------------------------------------------------------
NativeError computeBytesSha256( const std::string_view bytes, std::wstring &sha256)
{
	return computeBoundedBytesSha256( bytes, 1024U * 1024U, sha256) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 収集した最大8 MiBの原metadata本文を同じCNG処理でhashします
 * @param[in] bytes 1 byte以上8 MiB以下のsession内本文
 * @param[out] sha256 成功時の小文字SHA-256、失敗時は空です
 * @return 成功0、上限拒否またはCNG失敗のHRESULT
 * @note 既存computeBytesSha256の1 MiB上限は変更しません
 */
//------------------------------------------------------------------------------
NativeError computeCollectorMetadataSha256( const std::string_view bytes, std::wstring &sha256)
{
	return computeBoundedBytesSha256( bytes, 8U * 1024U * 1024U, sha256) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原container memoryの最大128 MiBを既存CNG処理でhashする
 * @param[in] bytes 空でない有限原byte。呼出し中に不変とする
 * @param[out] sha256 成功時の小文字64桁SHA-256、失敗時は空
 * @return 完了0、上限拒否またはCNG／allocation失敗のHRESULT
 * @note 従来の1 MiB／8 MiB入口は変更せず、用途別の抽出上限を代替しない
 */
//------------------------------------------------------------------------------
NativeError computeDriverContainerSha256( const std::string_view bytes, std::wstring &sha256)
{
	return computeBoundedBytesSha256( bytes, 128U * 1024U * 1024U, sha256) ;
}

//------------------------------------------------------------------------------
/**
 * @brief File全体のSHA-512を有限bufferで計算します
 * @param[in] path 読み取るfileの絶対path
 * @param[out] sha512 成功時の128桁小文字hex。失敗時は空
 * @return 成功0、file／CNG／allocation失敗時はHRESULT
 * @note 公開hashの照合用であり、署名や導入許可を表しません
 */
//------------------------------------------------------------------------------
NativeError computeFileSha512( const std::wstring_view path, std::wstring &sha512)
{
	return computeFileSha<64U>( path, BCRYPT_SHA512_ALGORITHM, sha512) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式fileのsizeとSHA-256を親metadataの宣言へ完全一致させる。公式fileのsizeとSHA-256をmetadata宣言へ一致させる。Sizeを先に確認し、不
 *        一致fileのhash計算を行わない
 * @param[in] path 検証するfileの絶対path
 * @param[in] policy 一つ以上のsizeまたはSHA-256条件
 * @return 全指定条件一致時は0、不正条件または不一致時はHRESULT bit pattern
 */
//------------------------------------------------------------------------------
NativeError verifyOfficialFileMetadata( const std::wstring_view			 path,
									   const OfficialFileMetadataPolicy &policy)
{
	// 対象または検証根拠がない要求を拒否し、無検証で成功させない
	if( path.empty() || (!policy.expectedSize.has_value() && policy.expectedSha256.empty())) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// Metadata が size を宣言している場合は実 file の byte 数を照合する
	if( policy.expectedSize.has_value()) {
		std::uint64_t	  actualSize{} ;							// Download後fileの実byte数
		const NativeError error = readFileSize( path, actualSize) ;	// Size取得結果
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
		if( error != 0) {
			return error ;
		}

		// Metadata と実 file の size が異なる場合は改変または不整合として拒否する
		if( actualSize != policy.expectedSize.value()) {
			return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		}
	}

	// Metadata に SHA-256 がある場合は形式を検査して実 digest と比較する
	if( !policy.expectedSha256.empty()) {
		std::wstring expectedHash ;	// 検証・小文字化したmetadata hash
		// 期待 hash の形式が不正な policy は file の検証前に拒否する
		if( !normalizeSha256( policy.expectedSha256, expectedHash)) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		std::wstring	  actualHash ;										// CNGで計算したfile hash
		const NativeError error = computeFileSha256( path, actualHash) ;	// Hash計算結果
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
		if( error != 0) {
			return error ;
		}

		// 計算した digest が期待値と一致しなければ file を受理しない
		if( actualHash != expectedHash) {
			return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		}
	}

	return 0 ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 成功したWinTrustの主署名状態を元PKCS#7と照合し、leaf証明書の表示名を取り出す
 * @param[in] state WinVerifyTrustが返した呼出し中だけ有効な非所有状態
 * @param[in] certificate 固定した元ファイル内のPKCS#7と任意の零整列領域
 * @param[out] signerName 成功時に返す検証済み署名者名。失敗時は空
 * @return 成功0、未知の検証状態や証明書はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readVerifiedPrimarySigner( const HANDLE					 state,
													const std::span<const std::byte> certificate,
													std::wstring					&signerName)
{
	signerName.clear() ;
	auto *const provider = WTHelperProvDataFromStateData( state) ;	// WinTrustが所有する検証状態
	// 単一の検証済み主署名を特定できる場合だけ表示名を照合する
	if( provider == nullptr || provider->csSigners != 1U || provider->hMsg == nullptr) {
		return static_cast<NativeError>( TRUST_E_SUBJECT_NOT_TRUSTED) ;
	}

	DWORD messageSize{} ;	// この信頼状態が実際に検証したPKCS#7のbyte数
	// WinTrustが使ったPKCS#7を取得できなければ、埋込み位置の正しさを推測しない
	if( !CryptMsgGetParam( provider->hMsg, CMSG_ENCODED_MESSAGE, 0, nullptr, &messageSize)) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 同じ元領域に収まるメッセージと最大7 byteの零整列だけを照合対象とする
	if( messageSize == 0U || messageSize > certificate.size() ||
	   certificate.size() - messageSize >= 8U ||
	   !std::ranges::all_of( certificate.subspan( messageSize),
							[]( const std::byte byte) { return byte == std::byte{} ; })) {
		return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	}

	std::vector<std::byte> message( messageSize) ;	// 原領域で上限を固定した検証済みPKCS#7
	// 読み取り失敗と先に得た長さからの変化は元領域との比較に進めない
	if( !CryptMsgGetParam( provider->hMsg, CMSG_ENCODED_MESSAGE, 0, message.data(), &messageSize)) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 起動部や別の埋込み署名をWinTrustが使った場合は元の外側署名と一致しない
	if( messageSize != message.size() ||
	   !std::ranges::equal( message, certificate.first( messageSize))) {
		return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	}

	auto *const signer = WTHelperGetProvSignerFromChain( provider, 0U, FALSE, 0U) ;	// 主署名の鎖
	// 主署名の検証エラーを見落とさず、時刻署名者を発行元に使用しない
	if( signer == nullptr || signer->dwError != ERROR_SUCCESS) {
		return static_cast<NativeError>( TRUST_E_SUBJECT_NOT_TRUSTED) ;
	}

	const auto *const leaf = WTHelperGetProvCertFromChain( signer, 0U) ;	// 検証された署名者のleaf
	// 検証状態が提示した証明書だけを使い、ファイルから別途再選択しない
	if( leaf == nullptr || leaf->pCert == nullptr) {
		return static_cast<NativeError>( TRUST_E_SUBJECT_NOT_TRUSTED) ;
	}

	return readCertificateName( *leaf->pCert, signerName) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常入口とcached-only入口の署名処理を同じ検証順で実行します
 * @param[in] path 対象絶対path
 * @param[in] acceptedPublishers 完全一致を要求する許可publisher群
 * @param[in] cachedOnly trueなら全URL取得をcache内へ制限します
 * @param[in] pinnedFile nullでなければ元fileを固定する非所有handle。主署名の検証状態を使う
 * @param[in] certificate 固定入口で照合するPKCS#7元領域。従来入口では空
 * @return 成功0、最初の入力／署名／publisher拒否の元error
 */
//------------------------------------------------------------------------------
NativeError verifyAuthenticodePublisherImpl(
	const std::wstring_view path, const std::span<const std::wstring_view> acceptedPublishers,
	const bool cachedOnly, const HANDLE pinnedFile = nullptr,
	const std::span<const std::byte> certificate = {})
{
	// 署名検証の対象が空の場合は入力不正として拒否する
	if( path.empty() || pinnedFile == INVALID_HANDLE_VALUE ||
	   (pinnedFile != nullptr && certificate.empty())) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const NativeError policyError = validatePublisherPolicy( acceptedPublishers) ;	// Policy検証
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( policyError != 0) {
		return policyError ;
	}

	const std::wstring pathString( path) ;	// WinTrust用終端null付きpath
	WINTRUST_FILE_INFO file{} ;				// 検証対象file metadata
	file.cbStruct	   = sizeof( file) ;
	file.pcwszFilePath = pathString.c_str() ;
	file.hFile		   = pinnedFile ;
	WINTRUST_DATA trust{} ;	// Generic Authenticode検証設定
	trust.cbStruct			  = sizeof( trust) ;
	trust.dwUIChoice		  = WTD_UI_NONE ;
	trust.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN ;
	trust.dwUnionChoice		  = WTD_CHOICE_FILE ;
	trust.pFile				  = &file ;
	trust.dwStateAction		  = WTD_STATEACTION_VERIFY ;
	trust.dwProvFlags =
		WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | (cachedOnly ? WTD_CACHE_ONLY_URL_RETRIEVAL : 0U) ;
	WINTRUST_SIGNATURE_SETTINGS signature{} ;	// 固定元ファイルの主署名を指定する設定
	// 固定入力では付加署名へ切り替えず、主署名のindexを明示する
	if( pinnedFile != nullptr) {
		signature.cbStruct		 = sizeof( signature) ;
		signature.dwIndex		 = 0U ;
		signature.dwFlags		 = WSS_VERIFY_SPECIFIC ;
		trust.pSignatureSettings = &signature ;
	}

	GUID		action = WINTRUST_ACTION_GENERIC_VERIFY_V2 ;	// Authenticode policy GUID
	const auto &api =
		// 同threadの完全backendです
		driver_package_signature_detail::authenticodeApi() ;
	const LONG	 status = api.verify( nullptr, &action, &trust) ;	// Chain検証結果
	std::wstring signerName ;										// 信頼結果で照合する署名者表示名
	NativeError	 signerError{} ;									// 署名者取得が失敗した場合の診断
	// 有効な固定入力は信頼状態が生きている間に署名者を照合できる形で取り出す
	if( status == ERROR_SUCCESS && pinnedFile != nullptr) {
		try {
			signerError =
				trust.hWVTStateData != nullptr
					? readVerifiedPrimarySigner( trust.hWVTStateData, certificate, signerName)
					: static_cast<NativeError>( TRUST_E_SUBJECT_NOT_TRUSTED) ;
		} catch( const std::bad_alloc &) {
			signerError = static_cast<NativeError>( E_OUTOFMEMORY) ;
		}
	}

	trust.dwStateAction = WTD_STATEACTION_CLOSE ;
	static_cast<void>( api.verify( nullptr, &action, &trust)) ;
	// 失敗の診断値を共通の表現へ保ったまま返し、未完了の結果で後続処理を進めない
	if( status != ERROR_SUCCESS) {
		return static_cast<NativeError>( status) ;
	}

	// 従来入口は既存の元embedded署名者の読取りを維持する
	if( pinnedFile == nullptr) {
		signerError = readSignerName( path, signerName) ;
	}

	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( signerError != 0) {
		return signerError ;
	}

	const bool accepted = std::any_of( acceptedPublishers.begin(), acceptedPublishers.end(),
									  [&signerName]( const std::wstring_view publisher) {
										  return publisherNamesEqual( signerName, publisher) ;
									  }) ; // 完全一致結果
	// 信頼 chain が成立していても、許可 publisher と一致しなければ拒否する
	if( !accepted) {
		return static_cast<NativeError>( TRUST_E_SUBJECT_NOT_TRUSTED) ;
	}

	return 0 ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief FileのAuthenticode chainと許可publisher完全一致を検証する。Windows trust policy成功後にembedded signerを完全一致する
 * @param[in] path 検証するfileの絶対path
 * @param[in] acceptedPublishers 許可するcertificate simple display name群。 許可するpublisher表示名群
 * @return Chain、revocation、publisher一致時は0、失敗時はtrust HRESULT。 Chain、revocation、publisher一致時は0、失敗時は
 *         HRESULT
 */
//------------------------------------------------------------------------------
NativeError verifyAuthenticodePublisher( const std::wstring_view					 path,
										const std::span<const std::wstring_view> acceptedPublishers)
{
	return verifyAuthenticodePublisherImpl( path, acceptedPublishers, false) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通信せずcache内のchainと失効情報だけで共通Authenticodeを検証します
 * @param[in] path 検証中に呼出側が実handleで変更・置換を防いだ絶対path
 * @param[in] acceptedPublishers 許可するembedded certificateの完全publisher名群
 * @return 成功0、cache不足・失効・chain・publisher不一致は元trust HRESULT
 * @note 通常入口のpolicyは変えず、online fallbackやcatalog-only signer推測は行いません
 */
//------------------------------------------------------------------------------
NativeError verifyAuthenticodePublisherCachedOnly(
	const std::wstring_view path, const std::span<const std::wstring_view> acceptedPublishers)
{
	return verifyAuthenticodePublisherImpl( path, acceptedPublishers, true) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定した元ファイルの主Authenticode署名を、元PKCS#7と検証済み署名者の両方で照合する
 * @param[in] path mappedFileを開いた同じ元ファイルの絶対path
 * @param[in] mappedFile 呼出し中ずっと開いている読取り専用mapping所有者
 * @param[in] certificate PKCS#7の元領域。末尾の8-byte境界用の零詰めを含められる
 * @param[in] acceptedPublishers 許可する証明書の表示名
 * @param[in] cachedOnly trueなら証明書取得・失効確認をcache内に制限する
 * @return 成功0、入力、信頼、署名者照合の失敗はHRESULT
 * @note 署名者を別fileや別の埋込み署名から求めず、この検証結果そのものを使う
 */
//------------------------------------------------------------------------------
NativeError verifyPrimaryAuthenticodePublisher(
	const std::wstring_view path, const OfficialMappedFile &mappedFile,
	const std::span<const std::byte>		 certificate,
	const std::span<const std::wstring_view> acceptedPublishers, const bool cachedOnly)
{
	return verifyAuthenticodePublisherImpl( path, acceptedPublishers, cachedOnly,
										   mappedFile.readOnlyHandle(), certificate) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名catalogが全member fileの現在内容を収録していることを検証する。署名catalogと全member fileを検証する。各fileに原CATの
 *        digest/tagが一致する既知算法をtrust前に選び、一件でも不一致なら全体を受理しません
 * @param[in] catalogPath 検証するCAT fileの絶対path
 * @param[in] memberPaths Catalog memberとして検証する通常fileの絶対path群。 Catalogへ収録されるべき通常file群
 * @param[in] cachedOnly trueは現strong-signとcache-only chain/失効を要求します
 * @return 全memberのhashとcatalog trustが有効なら0、最初の失敗はtrust HRESULT。 全memberのhashとcatalog trustが有効なら0、失敗
 *         時はHRESULT
 * @note 外側署名のcurrent strong-sign policyを維持し、未知・不正算法を拒否します。blocking処理はworkerで実行します
 */
//------------------------------------------------------------------------------
NativeError verifyCatalogMembersWithPolicy( const std::wstring_view			   catalogPath,
										   const std::span<const std::wstring> memberPaths,
										   const bool						   cachedOnly)
{
	// Catalog path の空文字・埋込み NUL と空の member 集合は受理しない
	if( catalogPath.empty() || catalogPath.find( L'\0') != std::wstring_view::npos ||
	   memberPaths.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		const std::wstring			   catalog( catalogPath) ;	// WinTrustへ渡すnull終端CAT path
		const ReadOnlyVerificationFile catalogFile(
			CreateFileW( catalog.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
						nullptr)) ;	// 検証完了まで置換を防ぐCAT file
		// Catalog file を開けなければ member 検証へ進まない
		if( catalogFile.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		FILE_ATTRIBUTE_TAG_INFO catalogAttributes{} ;	// Handleが指すCATの属性
		// 開いた catalog の属性を確認できなければ安全な対象と仮定しない
		if( GetFileInformationByHandleEx( catalogFile.get(), FileAttributeTagInfo, &catalogAttributes,
										sizeof( catalogAttributes)) == FALSE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		// 署名検証対象へdirectoryとreparse経路を混入させない属性mask
		constexpr DWORD REJECTED_ATTRIBUTES =
			FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT ;
		// 許可しない属性を持つ catalog file は検証対象から除外する
		if( (catalogAttributes.FileAttributes & REJECTED_ATTRIBUTES) != 0) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		std::vector<CatalogMemberDigest> declarations ;	// 同原CATの完全なmember宣言です
		const auto						 declarationError =
			// 原構造診断です
			readCatalogAlgorithms( catalog, declarations) ;
		// 未知・不正CATから算法を推測しません
		if( declarationError != 0) {
			return declarationError ;
		}

		std::vector<std::unique_ptr<CatalogHashContext>> contexts ;	// 原CATの最大四算法だけです
		// 既知の強い算法から各一contextを作り、原member照合前のAPI失敗を保持します
		for( const std::size_t bytes : {64U, 48U, 32U, 20U}) {
			const auto found = std::ranges::find_if( declarations, [bytes]( const auto &declaration) {
				// 同じ長さは検査済みの一意OIDです
				return declaration.bytes.size() == bytes ;
			}) ;
			// 原CATで宣言されない算法は試しません
			if( found == declarations.end()) {
				continue ;
			}

			auto context = std::make_unique<CatalogHashContext>() ;	// この原算法の単独所有者です
			const auto error =
				// 原API診断です
				context->initialize( found->algorithm, static_cast<DWORD>( bytes)) ;
			// 不成立contextを別算法や部分集合で隠しません
			if( error != 0) {
				return error ;
			}

			contexts.push_back( std::move( context)) ;
		}

		// 全memberを同じ署名catalogへ結び付け、部分成功を受理しない
		for( const std::wstring &memberPath : memberPaths) {
			// Member の空 path と埋込み NUL は file API へ渡す前に拒否する
			if( memberPath.empty() || memberPath.find( L'\0') != std::wstring::npos) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			const NativeError memberError =
				// 一memberのtrust結果
				verifyCatalogMember( contexts, declarations, catalog, memberPath, cachedOnly) ;
			// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
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
 * @brief 原CATの全member/hashと現在の署名強度を通常policyで検証します
 * @param[in] catalogPath 検査対象の原CAT絶対位置です
 * @param[in] memberPaths 全て同CATへ結ぶ原memberの完全位置です
 * @return 全member成立0、元の入力/算法/hash/trust errorです
 * @note 既通常APIの通信/署名policyを変更しません
 */
//------------------------------------------------------------------------------
NativeError verifyOfficialCatalogMembers( const std::wstring_view			 catalogPath,
										 const std::span<const std::wstring> memberPaths)
{
	return verifyCatalogMembersWithPolicy( catalogPath, memberPaths, false) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じCAT署名方針で全メンバーをキャッシュ内の信頼情報に照合する
 * @param[in] catalogPath 照合中に保持する元CATの完全な絶対位置
 * @param[in] memberPaths 同CATへ照合する全ファイルの絶対位置
 * @return CAT署名と全員の一致は0、キャッシュ不足、アルゴリズム又は照合不成立はHRESULT
 * @note 署名の強度を変えない。通信時の成功でキャッシュ不足を補わない
 */
//------------------------------------------------------------------------------
NativeError verifyOfficialCatalogMembersCachedOnly( std::wstring_view			 catalogPath,
												   std::span<const std::wstring> memberPaths)
{
	return verifyCatalogMembersWithPolicy( catalogPath, memberPaths, true) ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 新SYSTEM検証の失敗APIに元errorがない場合だけ内部不整合を返します
 * @param[in] error 失敗直後に捕捉した元Win32値です
 * @return 非zero値の元HRESULT又はerror0のE_UNEXPECTEDです
 */
//------------------------------------------------------------------------------
NativeError systemVerificationError( DWORD error)
{
	return error != 0U ? nativeErrorFromWin32( error) : static_cast<NativeError>( E_UNEXPECTED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 任意診断へ固定stageだけを写します
 * @param[out] output null可の同同期の診断先です
 * @param[in] stage 閉じた検証地点です
 */
//------------------------------------------------------------------------------
void systemVerificationStage( std::uint32_t *output, WindowsSystemFileStage stage)
{
	// 診断なしでも元API/合否は同じです
	if( output) {
		*output = static_cast<std::uint32_t>( stage) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief SYSTEM fileの全allow ACEと権限制限tokenで非特権writeを拒否します
 * @param[in] file READ_CONTROLを持ち置換を防いで保持した通常fileです
 * @param[out] snapshot 成功時の元owner/group/control/DACL byteです。開始時は空にします
 * @param[out] stage null可の固定検証地点です。合否には使用しません
 * @param[in] directory 親ディレクトリの場合に子の削除権限も評価する
 * @return 既知owner/妥当DACL/非特権write拒否0、元API又は権限拒否のHRESULTです
 * @note DACLやtokenの永続設定を変更せず、未知の書込許可を信頼しません
 */
//------------------------------------------------------------------------------
NativeError verifySystemFilePermissions( HANDLE file, std::vector<std::byte> &snapshot,
										std::uint32_t *stage, bool directory = false)
{
	snapshot.clear() ;
	systemVerificationStage( stage, WindowsSystemFileStage::SECURITY_DESCRIPTOR) ;
	PSECURITY_DESCRIPTOR raw{} ;	// LocalFreeで閉じる元SDです
	PSID				 owner{} ;	// 同元SDの借用ownerです
	PSID				 group{} ;	// 同元SDの妥当性と不変性だけを確認するgroupです
	PACL				 dacl{} ;	// 同元SDの借用DACLです
	const DWORD			 result = GetSecurityInfo(
		 file, SE_FILE_OBJECT,
		 OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
		 &group, &dacl, nullptr, &raw) ;	// 元Windows errorを保持します
	const std::unique_ptr<void, decltype( &LocalFree)> descriptor(
		raw, &LocalFree) ;	// 全returnで解放します
	// 未読又はnull DACLを保護済みへ変えません
	if( result != ERROR_SUCCESS || !raw || !IsValidSecurityDescriptor( raw) || !owner ||
	   !IsValidSid( owner) || !group || !IsValidSid( group) || !dacl || !IsValidAcl( dacl)) {
		return systemVerificationError( result != ERROR_SUCCESS ? result : ERROR_ACCESS_DENIED) ;
	}

	std::array<BYTE, SECURITY_MAX_SID_SIZE> admin{} ;			// 標準BA SIDの所有bufferです
	std::array<BYTE, SECURITY_MAX_SID_SIZE> system{} ;			// 標準SYSTEM SIDの所有bufferです
	DWORD adminBytes  = static_cast<DWORD>( admin.size()) ;		// SID bufferの全容量です
	DWORD systemBytes = static_cast<DWORD>( system.size()) ;	// SID bufferの全容量です
	PSID  installerRaw{} ;										// 固定Windows service SIDの所有bufferです
	systemVerificationStage( stage, WindowsSystemFileStage::SECURITY_PRINCIPALS) ;
	// 既知の保守主体だけを作り、不正なSIDを比較へ渡しません
	if( !CreateWellKnownSid( WinBuiltinAdministratorsSid, nullptr, admin.data(), &adminBytes) ||
	   !CreateWellKnownSid( WinLocalSystemSid, nullptr, system.data(), &systemBytes) ||
	   !ConvertStringSidToSidW( L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
							   &installerRaw)) {
		return systemVerificationError( GetLastError()) ;
	}

	const std::unique_ptr<void, decltype( &LocalFree)> installer(
		installerRaw, &LocalFree) ;	// service SIDを解放します
	const auto trusted = [&]( PSID sid) {
		return IsValidSid( sid) && (EqualSid( sid, admin.data()) || EqualSid( sid, system.data()) ||
								   EqualSid( sid, installer.get())) ;
	} ; // 同SD内のSIDを同期借用し、保守主体だけへ限定します
	systemVerificationStage( stage, WindowsSystemFileStage::SECURITY_POLICY) ;
	// 任意userをfile ownerとして採用しません
	if( !trusted( owner)) {
		return systemVerificationError( ERROR_INVALID_OWNER) ;
	}

	GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE,
							FILE_ALL_ACCESS} ;	// file権限の元写像です
	const DWORD		writes = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
						 FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER |
						 (directory ? FILE_DELETE_CHILD : 0U) ;	// 内容と親からの置換を許す権限
	// 全allow ACEを確認し、未知主体への書込を一つも許可しません
	for( DWORD index = 0U; index < dacl->AceCount; ++index) {
		void *entry{} ;	// この元DACLの一ACEだけを借用します
		// 不正なACEを省略しません
		if( !GetAce( dacl, index, &entry)) {
			return systemVerificationError( GetLastError()) ;
		}

		const auto header = static_cast<const ACE_HEADER *>( entry) ;	// 検査済みDACL内の元headerです
		// このfileに適用しない継承用ACEとdenyは権限を付与しません
		if( (header->AceFlags & INHERIT_ONLY_ACE) != 0U ||
		   header->AceType == ACCESS_DENIED_ACE_TYPE) {
			continue ;
		}

		// 未対応のcallback/object ACEを一般allowへ縮約しません
		if( header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
		   header->AceSize < offsetof( ACCESS_ALLOWED_ACE, SidStart) + GetSidLengthRequired( 0U)) {
			return systemVerificationError( ERROR_ACCESS_DENIED) ;
		}

		const auto ace = static_cast<const ACCESS_ALLOWED_ACE *>( entry) ;	// 元種類を確認したACEです
		auto	   sid = const_cast<DWORD *>(
			  &ace->SidStart) ;		// IsValidSid/EqualSidの非const Windows ABIだけで借用します
		DWORD mask = ace->Mask ;	// 元generic maskを通常file権限へ写します
		MapGenericMask( &mask, &mapping) ;
		// DACL内のSID終端を確認し、未知writeを拒否します
		if( !IsValidSid( sid) ||
		   GetLengthSid( sid) > header->AceSize - offsetof( ACCESS_ALLOWED_ACE, SidStart) ||
		   ((mask & writes) != 0U && !trusted( sid))) {
			return systemVerificationError( ERROR_ACCESS_DENIED) ;
		}
	}

	HANDLE processRaw{} ;	// このprocessの元tokenだけです
	systemVerificationStage( stage, WindowsSystemFileStage::PROCESS_TOKEN) ;
	// Token複製の不足権限を成功へ補完しません
	if( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT,
						 &processRaw)) {
		return systemVerificationError( GetLastError()) ;
	}

	const ReadOnlyVerificationFile process( processRaw) ;		// tokenもCloseHandleで閉じます
	SID_AND_ATTRIBUTES			   disabled{admin.data(), 0U} ;	// BAをdeny-onlyにする元SIDです
	HANDLE						   restrictedRaw{} ;			// 特権とBA allowを無効にした一時tokenです
	systemVerificationStage( stage, WindowsSystemFileStage::RESTRICTED_TOKEN) ;
	// 同じuserの非特権能力だけでAccessCheckします
	if( !CreateRestrictedToken( process.get(), DISABLE_MAX_PRIVILEGE, 1U, &disabled, 0U, nullptr, 0U,
							  nullptr, &restrictedRaw)) {
		return systemVerificationError( GetLastError()) ;
	}

	const ReadOnlyVerificationFile restricted( restrictedRaw) ;	// 永続tokenを変更しません
	alignas( TOKEN_USER) std::array<std::byte, 1024U>
		  userBytes{} ;	// このprocess本人SIDだけの有限応答です
	DWORD required{} ;	// 元APIが返したbyte数です
	systemVerificationStage( stage, WindowsSystemFileStage::TOKEN_USER) ;
	// 元BA ownerを一時tokenの暗黙owner権として持ち越しません
	if( !GetTokenInformation( process.get(), TokenUser, userBytes.data(),
							static_cast<DWORD>( userBytes.size()), &required)) {
		return systemVerificationError( GetLastError()) ;
	}

	// TOKEN_USERのWindows ABIを同寿命の整列済みbufferへ借用します
	const auto user =
		reinterpret_cast<const TOKEN_USER *>( userBytes.data()) ;	// 外部へSIDを出しません
	TOKEN_OWNER tokenOwner{user->User.Sid} ;						// 新規restricted tokenだけを本人ownerへ合わせます
	systemVerificationStage( stage, WindowsSystemFileStage::TOKEN_OWNER) ;
	// 元process tokenやfile ownerは変更しません
	if( !SetTokenInformation( restricted.get(), TokenOwner, &tokenOwner, sizeof( tokenOwner))) {
		return systemVerificationError( GetLastError()) ;
	}

	HANDLE checkRaw{} ;	// AccessCheckが要求するimpersonation tokenです
	systemVerificationStage( stage, WindowsSystemFileStage::IMPERSONATION_TOKEN) ;
	// PrimaryをそのままAccessCheckへ渡しません
	if( !DuplicateTokenEx( restricted.get(), TOKEN_QUERY, nullptr, SecurityImpersonation,
						 TokenImpersonation, &checkRaw)) {
		return systemVerificationError( GetLastError()) ;
	}

	const ReadOnlyVerificationFile check( checkRaw) ;	// 同同期の終了で閉じます
	systemVerificationStage( stage, WindowsSystemFileStage::ACCESS_CHECK) ;
	constexpr std::array<DWORD, 8U> rights{
		FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES,
		DELETE,			 WRITE_DAC,		   WRITE_OWNER,	  FILE_DELETE_CHILD} ;	// 照会する変更権限
	// 一つのdenyで別のwrite許可を隠さないよう各権限を独立に照会します
	for( const DWORD requested :
		std::span{rights}.first( directory ? rights.size() : rights.size() - 1U)) {
		// 元APIの有限出力です
		alignas( PRIVILEGE_SET) std::array<std::byte, 1024U> privileges{} ;
		DWORD bytes = static_cast<DWORD>( privileges.size()) ;	// 全buffer容量です
		DWORD granted{} ;										// 元AccessCheckの結果だけです
		BOOL  allowed{} ;										// FALSEを拒否成功として区別します
		// Windows ABIの可変長PRIVILEGE_SETを整列済みbufferへ受けます
		if( !AccessCheck( raw, check.get(), requested, &mapping,
						reinterpret_cast<PRIVILEGE_SET *>( privileges.data()), &bytes, &granted,
						&allowed)) {
			return systemVerificationError( GetLastError()) ;
		}

		// 実非特権tokenがwriteできる元SDを採用しません
		if( allowed) {
			return systemVerificationError( ERROR_ACCESS_DENIED) ;
		}
	}

	SECURITY_DESCRIPTOR_CONTROL control{} ;		// 保護/継承flagも原状態へ結びます
	DWORD						revision{} ;	// 元SDのrevisionです
	// 未読controlをbyte一致へ補完しません
	if( !GetSecurityDescriptorControl( raw, &control, &revision)) {
		return systemVerificationError( GetLastError()) ;
	}

	const auto append = [&snapshot]( const void *data, std::size_t bytes) {
		const auto first = static_cast<const std::byte *>( data) ;	// 同元SDを同期借用します
		snapshot.insert( snapshot.end(), first, first + bytes) ;
	} ; // SID/control/ACLの元byteを順序付きで所有します
	append( &control, sizeof( control)) ;
	append( &revision, sizeof( revision)) ;
	append( owner, GetLengthSid( owner)) ;
	append( group, GetLengthSid( group)) ;
	append( dacl, dacl->AclSize) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保持したPEの署名table有無をtrust前に確定します
 * @param[in] file 実byteを保持する通常fileです
 * @param[out] embedded 妥当な非空security directoryを持つ場合trueです
 * @return PE64/範囲成立0、元読取error又は不正形式です
 */
//------------------------------------------------------------------------------
NativeError systemPeSignatureForm( HANDLE file, bool &embedded)
{
	embedded = false ;
	LARGE_INTEGER	 length{} ;	// 原fileの有限sizeです
	LARGE_INTEGER	 offset{} ;	// DOS headerから読みます
	IMAGE_DOS_HEADER dos{} ;	// 実byteの固定headerです
	DWORD			 read{} ;	// 完全headerの読取量です
	// 不完全なPEを署名なしへ変換しません
	if( !GetFileSizeEx( file, &length) || !SetFilePointerEx( file, offset, nullptr, FILE_BEGIN) ||
	   !ReadFile( file, &dos, sizeof( dos), &read, nullptr)) {
		return systemVerificationError( GetLastError()) ;
	}

	// 任意offsetや過大fileをheaderとして使いません
	if( read != sizeof( dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < sizeof( dos) ||
	   dos.e_lfanew > 1024 * 1024 || length.QuadPart > 128LL * 1024LL * 1024LL) {
		return systemVerificationError( ERROR_BAD_EXE_FORMAT) ;
	}

	offset.QuadPart = dos.e_lfanew ;
	IMAGE_NT_HEADERS64 pe{} ;	// x64だけの原NT headerです
	// 元fileの正確なNT headerだけを読みます
	if( !SetFilePointerEx( file, offset, nullptr, FILE_BEGIN) ||
	   !ReadFile( file, &pe, sizeof( pe), &read, nullptr)) {
		return systemVerificationError( GetLastError()) ;
	}

	// 欠損security directoryをCAT方式へ救済しません
	if( read != sizeof( pe) || pe.Signature != IMAGE_NT_SIGNATURE ||
	   pe.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
	   pe.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
	   pe.FileHeader.SizeOfOptionalHeader < sizeof( IMAGE_OPTIONAL_HEADER64) ||
	   pe.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) {
		return systemVerificationError( ERROR_BAD_EXE_FORMAT) ;
	}

	const auto &entry =
		pe.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] ;	// file offsetの原tableです
	// 両値0だけをembedded無しとして扱います
	if( entry.VirtualAddress == 0U && entry.Size == 0U) {
		return 0U ;
	}

	// 不正tableを別方式の署名で隠しません
	if( entry.VirtualAddress == 0U || entry.Size < 8U || (entry.VirtualAddress & 7U) != 0U ||
	   static_cast<std::uint64_t>( entry.VirtualAddress) + entry.Size >
		   static_cast<std::uint64_t>( length.QuadPart)) {
		return systemVerificationError( ERROR_BAD_EXE_FORMAT) ;
	}

	embedded = true ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原SYSTEM file又はlocal CATの全祖先を非reparse/rename不可で保持します
 * @param[in] path OS local storeが返した通常drive絶対位置です
 * @param[out] parents 成功した祖先handleを同期終了まで所有します
 * @param[in] protectedParentCount 葉に近い方からREAD_CONTROLを追加で要求する親の数
 * @return 全祖先成立0、元open/属性又は不正path errorです
 */
//------------------------------------------------------------------------------
NativeError pinSystemCatalogParents( const std::wstring									   &path,
									std::vector<std::unique_ptr<ReadOnlyVerificationFile>> &parents,
									std::size_t protectedParentCount = 0U)
{
	// 不正なdriveやpath切替をOS rootの前方一致だけで採用しません
	if( path.size() < 4U || path[1] != L':' || path[2] != L'\\' ||
	   path.find_first_of( L"/%<>|\"?*") != path.npos) {
		return systemVerificationError( ERROR_INVALID_NAME) ;
	}

	const auto	last		   = path.rfind( L'\\') ;	// ファイルの直接親の終端
	const auto	firstProtected = protectedParentCount == 0U ? path.size()
								 : protectedParentCount == 1U
									 ? last
									 : path.rfind( L'\\', last - 1U) ;	// 保護を読む既知祖先の開始位置
	std::size_t begin		   = 3U ;									// drive以降の元component起点です
	// 全componentと祖先を順に確認し、途中のreparseを追跡しません
	for( std::size_t end = 3U; end <= path.size(); ++end) {
		// 元pathのcomponent境界だけを扱います
		if( end != 3U && end != path.size() && path[end] != L'\\') {
			continue ;
		}

		// 最初のdriveを除き空/親移動/末尾正規化を拒否します
		if( end != 3U) {
			const auto part = std::wstring_view( path).substr( begin, end - begin) ;	// 元componentです
			// Dot/空/制御を別の有効位置へ補正しません
			if( part.empty() || part == L"." || part == L".." || part.back() == L'.' ||
			   part.back() == L' ' || std::ranges::any_of( part, []( wchar_t c) {
				   return c < L' ' || c == L':' || c == 0x7f ;
			   })) {
				return systemVerificationError( ERROR_INVALID_NAME) ;
			}

			begin = end + 1U ;
		}

		// leaf自体は後段の保持fileが担当します
		if( end == path.size()) {
			break ;
		}

		const auto	parent = path.substr( 0U, end) ;	// 元祖先の完全位置です
		const DWORD access = FILE_READ_ATTRIBUTES |
							 (end >= firstProtected ? READ_CONTROL : 0U) ;	// 選択した親のDACL読取り
		auto owner = std::make_unique<ReadOnlyVerificationFile>(
			CreateFileW( parent.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
						OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
						nullptr)) ;	// renameを拒否します
		// 元open失敗を後続pathで隠しません
		if( owner->get() == INVALID_HANDLE_VALUE) {
			return systemVerificationError( GetLastError()) ;
		}

		FILE_ATTRIBUTE_TAG_INFO attributes{} ;	// 同祖先のrace-free属性です
		// 読取不明を通常directoryと認定しません
		if( !GetFileInformationByHandleEx( owner->get(), FileAttributeTagInfo, &attributes,
										 sizeof( attributes))) {
			return systemVerificationError( GetLastError()) ;
		}

		// 非directory又はreparseの祖先は採用しません
		if( (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U ||
		   (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) {
			return systemVerificationError( ERROR_ACCESS_DENIED) ;
		}

		parents.push_back( std::move( owner)) ;
	}

	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 開いたWindows実ファイルまたは親の正規DOS位置を元位置に照合する
 * @param[in] handle 読取中に保持する実ファイルか親
 * @param[in] path 元の完全位置
 * @return 実位置が同じDOS形式で一致すれば0、不一致と元読取りの失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError checkProtectedExecutableLocation( HANDLE handle, std::wstring_view path)
{
	std::array<wchar_t, MAX_PATH + 4U> resolved{} ;	// 同handleに対応する完全DOS位置
	// Windowsが返した完全パスの文字数
	const auto						   length =
		GetFinalPathNameByHandleW( handle, resolved.data(), static_cast<DWORD>( resolved.size()),
								  FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;
	// Windowsの照会自体が失敗した場合は元診断を保持する
	if( length == 0U) {
		return systemVerificationError( GetLastError()) ;
	}

	return length > 4U && length < resolved.size() &&
				   std::wstring_view{resolved.data(), length}.starts_with( L"\\\\?\\") &&
				   publisherNamesEqual( path, {resolved.data() + 4U, length - 4U})
			   ? 0U
			   : systemVerificationError( ERROR_ACCESS_DENIED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 呼出側が限定した正規配置のバイナリを保護付きで読み取る
 * @param[in] path 同じWindowsから解決した完全位置
 * @param[in] driverStore FileRepositoryの保護と元ファイルの実在を要求する場合true
 * @param[out] snapshot 全条件が成立した元ファイルと親の観測
 * @param[in] maximumBytes ハッシュ読取りより前に確認するファイル全体の上限
 * @param[in] requireAmd64 Storeの実ファイルにAMD64形式を要求する場合true
 * @return 成立時0、Windowsの元エラー又は保護・位置・種別の不成立はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readProtectedExecutableAtPath( std::wstring_view path, bool driverStore,
										  ProtectedExecutableSnapshot &snapshot,
										  std::uint64_t maximumBytes = 2ULL * 1024U * 1024U * 1024U,
										  bool			requireAmd64 = true)
{
	const std::wstring name{path} ;	// 同期のWindows照会に渡す終端付き位置
	std::vector<std::unique_ptr<ReadOnlyVerificationFile>>
		 parents ;	// 再解析点でない同じ全祖先を保持
	auto error =
		// 直近親の保護も取得する
		pinSystemCatalogParents( name, parents, driverStore ? 2U : 1U) ;
	// 別名・再解析点・読取り拒否を正式な不在としない
	if( error != 0U || parents.empty()) {
		return error != 0U ? error : E_UNEXPECTED ;
	}

	ProtectedExecutableSnapshot made ;	// 完全な状態が揃うまで出力を確定しない
	error =
		verifySystemFilePermissions( parents.back()->get(), made.directorySecurity, nullptr, true) ;
	// 他の利用者がファイルを追加・置換できる親では観測を採用しない
	if( error != 0U) {
		return error ;
	}

	// Driver StoreではパッケージとFileRepositoryの両方に別名がなく、元保護が成立する必要があります
	if( driverStore) {
		const auto package	  = path.substr( 0U, path.rfind( L'\\')) ;			// 一つの直接パッケージ
		const auto repository = package.substr( 0U, package.rfind( L'\\')) ;	// その正式FileRepository
		// 正式FileRepositoryとその直接子を両方保持している必要がある
		if( parents.size() < 2U) {
			return systemVerificationError( ERROR_ACCESS_DENIED) ;
		}

		const auto &repositoryHandle =
			parents[parents.size() - 2U] ;	// FileRepository自身の保持ハンドル
		error = checkProtectedExecutableLocation( parents.back()->get(), package) ;
		// 実パッケージの別名をFileRepository読み取りで補わない
		if( error == 0U) {
			error = checkProtectedExecutableLocation( repositoryHandle->get(), repository) ;
		}

		// 最終位置の不一致と元エラーを保護付き親として扱わない
		if( error != 0U) {
			return error ;
		}

		error = verifySystemFilePermissions( repositoryHandle->get(), made.repositorySecurity,
											nullptr, true) ;
		// 保護のないFileRepository配下を署名元候補へ渡しません
		if( error != 0U) {
			return error ;
		}
	}

	// 原ファイルの読み取りと保護確認のため終端まで保持するハンドル
	const ReadOnlyVerificationFile file( CreateFileW( name.c_str(), GENERIC_READ | READ_CONTROL,
													FILE_SHARE_READ, nullptr, OPEN_EXISTING,
													FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;
	// 保持した正規親の直下で、Windowsが葉の不存在を明示した場合だけ不在とする
	if( file.get() == INVALID_HANDLE_VALUE) {
		const auto opened = GetLastError() ;	// 別種類の読取り失敗を区別する元診断
		// 共有違反や権限不足を存在しないファイルに読み替えない
		if( driverStore || opened != ERROR_FILE_NOT_FOUND) {
			return systemVerificationError( opened) ;
		}

		snapshot = std::move( made) ;
		return 0U ;
	}

	BY_HANDLE_FILE_INFORMATION info{} ;	// 同じfile handleから取得した元属性と長さ
	FILE_ID_INFO			   id{} ;	// 現在volumeと128 bitファイル識別子
	// 開いた葉が同じ通常ファイルであることを確認するため、属性と識別子を取得する
	if( !GetFileInformationByHandle( file.get(), &info) ||
	   !GetFileInformationByHandleEx( file.get(), FileIdInfo, &id, sizeof( id))) {
		return systemVerificationError( GetLastError()) ;
	}

	// 保持中のファイルの全バイト数
	const auto bytes = (static_cast<std::uint64_t>( info.nFileSizeHigh) << 32U) | info.nFileSizeLow ;
	// ドライバー配布上限以内で内容があり、保持元を確認できる通常ファイルだけを許す
	if( bytes == 0U || bytes > maximumBytes ||
	   (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0U ||
	   info.nNumberOfLinks == 0U) {
		return systemVerificationError( ERROR_ACCESS_DENIED) ;
	}

	// 保持したバイナリの正規位置
	error = checkProtectedExecutableLocation( file.get(), path) ;
	// Windowsが返す最終位置が元位置と一致する場合だけ先へ進む
	if( error != 0U) {
		return error ;
	}

	// Driver Storeの実バイナリには候補と同じAMD64 PE32+の非実行検査を適用する
	if( driverStore && requireAmd64) {
		bool embedded{} ;	// 署名テーブルを含む元形式。現登録の所有照合は別工程
		error = systemPeSignatureForm( file.get(), embedded) ;
		// 読めないバイナリを正常な元実体として扱わない
		if( error != 0U) {
			return error ;
		}
	}

	auto &existing	= made.existing.emplace() ;	// 同じhandleの属性と完全ハッシュ
	existing.volume = id.VolumeSerialNumber ;
	std::ranges::copy( id.FileId.Identifier, existing.fileId.begin()) ;
	existing.bytes		= bytes ;
	existing.attributes = info.dwFileAttributes ;
	existing.links		= info.nNumberOfLinks ;
	existing.lastWrite	= (static_cast<std::uint64_t>( info.ftLastWriteTime.dwHighDateTime) << 32U) |
						 info.ftLastWriteTime.dwLowDateTime ;
	error = verifySystemFilePermissions( file.get(), existing.security, nullptr) ;
	// ハッシュ読取りの前に、保護が成立した同じ通常ファイルであることを確認する
	if( error == 0U) {
		error = computeFileSha256( path, existing.sha256) ;
	}

	// 完全な読み取りだけを呼出側の再確認へ送る
	if( error == 0U) {
		snapshot = std::move( made) ;
	}

	return error ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 選択した補助EXEの同じSystem32直下位置を読み取る
 * @param[in] path 元INFが指定した正確なSystem32直下のEXE絶対位置
 * @param[out] snapshot 運用中の親とファイルの保護およびハッシュ。失敗時は空
 * @return 読取り成功0、配置先、権限、ファイル種別、読取りの不成立はHRESULT
 * @note 名前解決中は祖先を保持し、実ファイルを開いてから全byteを読む
 */
//------------------------------------------------------------------------------
NativeError readSystem32ExecutableSnapshot( std::wstring_view		   path,
										   System32ExecutableSnapshot &snapshot)
{
	snapshot = {} ;
	std::array<wchar_t, MAX_PATH> directory{} ;	// 現在OSのネイティブSystem32の完全位置
	const auto					  length =
		// 実長
		GetSystemDirectoryW( directory.data(), static_cast<UINT>( directory.size())) ;
	const auto slash = path.rfind( L'\\') ;	// 元INFが解決したコピー先の親と葉の境界
	// 完全な標準親は一つだけで、補助EXEの正確な絶対位置を要求する
	if( length == 0U || length >= directory.size() || slash != length ||
	   !publisherNamesEqual( path.substr( 0U, slash), {directory.data(), length}) ||
	   path.size() <= slash + 5U || !publisherNamesEqual( path.substr( path.size() - 4U), L".exe")) {
		return systemVerificationError( ERROR_INVALID_NAME) ;
	}

	return readProtectedExecutableAtPath( path, false, snapshot) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正規driversの直接の子であるSYSの現在値と保護を読む
 * @param[in] path 元INFの解決結果である絶対コピー先
 * @param[out] snapshot 同じ親と実ファイルの全観測。失敗時は空
 * @return 読取り成功0、位置・保護・ファイルの読取り不成立はHRESULT
 * @note 候補から指された通常SYSだけを読む。書込みやバイナリ実行を行わない
 */
//------------------------------------------------------------------------------
NativeError readSystem32StorageDriverSnapshot( std::wstring_view			   path,
											  ProtectedExecutableSnapshot &snapshot)
{
	snapshot = {} ;
	std::array<wchar_t, MAX_PATH> directory{} ;	// Windowsが返すネイティブSystem32の絶対位置
	const auto					  length = GetSystemDirectoryW( directory.data(),
															   // 終端を除く完全長
															   static_cast<UINT>( directory.size())) ;
	// 元のWindowsのディレクトリを取得できなければ別の位置を調べない
	if( length == 0U || length >= directory.size()) {
		return systemVerificationError( length == 0U ? GetLastError() : ERROR_INSUFFICIENT_BUFFER) ;
	}

	constexpr std::wstring_view drivers{L"\\drivers\\"} ;					// 固定された直接の親
	const auto					parentLength = length + drivers.size() ;	// 元SYSの葉が始まる位置
	// 同じWindowsの標準親を参照していることを確認する
	if( path.size() <= parentLength + 4U ||
	   !publisherNamesEqual( path.substr( 0U, length), {directory.data(), length}) ||
	   !publisherNamesEqual( path.substr( length, drivers.size()), drivers)) {
		return systemVerificationError( ERROR_INVALID_NAME) ;
	}

	const auto leaf = path.substr( parentLength) ;	// 元SYS一つの名前
	// 子ディレクトリ、代替データストリーム、別拡張子を許容しない
	if( leaf.find( L'\\') != leaf.npos || !isSafeOfficialArchiveMember( leaf, L'\\') ||
	   !publisherNamesEqual( leaf.substr( leaf.size() - 4U), L".sys")) {
		return systemVerificationError( ERROR_INVALID_NAME) ;
	}

	return readProtectedExecutableAtPath( path, false, snapshot) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保護されたDriver Storeの一パッケージに属する元SYSと親の現在値を読む
 * @param[in] path 照合済みStore INFと同じ一パッケージ直下の元SYSの絶対パス
 * @param[out] snapshot 元の親、元SYSの保護、同一性と全ハッシュ。失敗時は空
 * @return 正規位置、AMD64形式と保護付き読取りが成立すれば0、失敗はHRESULT
 * @note 署名と現用機器への結合は別に確認する。SYSを実行せず変更しない
 */
//------------------------------------------------------------------------------
NativeError readDriverStoreStorageDriverSnapshot( std::wstring_view			  path,
												 ProtectedExecutableSnapshot &snapshot)
{
	snapshot = {} ;
	std::array<wchar_t, MAX_PATH> system{} ;	// 現OSの正規System32の位置
	// 現Windowsが返す絶対位置の完全長
	const auto length = GetSystemDirectoryW( system.data(), static_cast<UINT>( system.size())) ;
	// 同じWindowsのルートを読み取れない場合は別の基点へ進まない
	if( length == 0U || length >= system.size()) {
		return systemVerificationError( length == 0U ? GetLastError() : ERROR_INSUFFICIENT_BUFFER) ;
	}

	// 展開や探索に使わない同じWindowsの固定親
	const auto repository =
		std::wstring{system.data(), length} + L"\\DriverStore\\FileRepository\\" ;
	// 元WindowsのFileRepositoryだけを通常のパッケージとして扱う
	if( path.size() <= repository.size() ||
	   !publisherNamesEqual( path.substr( 0U, repository.size()), repository)) {
		return systemVerificationError( ERROR_INVALID_NAME) ;
	}

	const auto relative = path.substr( repository.size()) ;	// パッケージ親と元SYSの正規相対名
	const auto slash	= relative.find( L'\\') ;			// 一パッケージから葉への境界
	// パッケージの直下にある一つの安全な通常SYSだけを開く
	if( slash == relative.npos || slash != relative.rfind( L'\\') || relative.size() <= slash + 5U ||
	   !isSafeOfficialArchiveMember( relative, L'\\') ||
	   !publisherNamesEqual( relative.substr( relative.size() - 4U), L".sys")) {
		return systemVerificationError( ERROR_INVALID_NAME) ;
	}

	return readProtectedExecutableAtPath( path, true, snapshot) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正規の登録配布にある元ファイルと親の保護、同一性、完全ハッシュを読む
 * @param[in] path 呼出側でWindowsの公開INF又は同じFileRepository配布直下と確認した絶対位置
 * @param[in] store trueはStore側。falseは公開INFだけ
 * @param[out] snapshot 元ファイルと親の保護付き観測。失敗時は空
 * @return 通常の元ファイルの内容と保護を確認して0、位置、形式や読取りの失敗はHRESULT
 * @note 拡張子ごとの上限を適用する。元位置の登録対応と元CATの署名は呼出側で独立に確認する
 */
//------------------------------------------------------------------------------
NativeError readProtectedRegisteredPackageSnapshot( std::wstring_view path, bool store,
												   ProtectedExecutableSnapshot &snapshot)
{
	snapshot		 = {} ;
	const auto slash = path.rfind( L'\\') ;	// 呼出側が限定した元パッケージ内の最後の区切り
	// 相対指定や非正規の葉は保持中の登録パスとして扱わない
	if( path.size() >= MAX_PATH || slash == path.npos || slash < 3U || path[1U] != L':' ||
	   path[2U] != L'\\' || path.size() - slash <= 5U || path.find_first_of( L"/%") != path.npos ||
	   !isSafeOfficialArchiveMember( path.substr( slash + 1U), L'\\')) {
		return systemVerificationError( ERROR_INVALID_NAME) ;
	}

	const auto suffix = path.substr( path.size() - 4U) ;					// 元ファイルの型を判定する末尾
	const bool inf	  = publisherNamesEqual( suffix, L".inf") ;				// 両位置で許される元INF
	const bool cat	  = store && publisherNamesEqual( suffix, L".cat") ;	// 同じStoreにある元CAT
	const bool sys	  = store && publisherNamesEqual( suffix, L".sys") ;	// 同じStoreにある元SYS
	// 同じパッケージが宣言する元ファイルの三種類だけを扱う
	if( !inf && !cat && !sys) {
		return systemVerificationError( ERROR_INVALID_NAME) ;
	}

	const std::uint64_t maximum = inf	? 4ULL * 1024U * 1024U
								  : cat ? 64ULL * 1024U * 1024U
										: 2ULL * 1024U * 1024U * 1024U ;	// 型別の読取り上限
	// ファイルと親の保護を、元の型別上限で読む
	const auto			error = readProtectedExecutableAtPath( path, store, snapshot, maximum, sys) ;
	// 公開INFでも明示的不在を成功の元証拠にしない
	if( error == 0U && !snapshot.existing) {
		snapshot = {} ;
		return systemVerificationError( ERROR_FILE_NOT_FOUND) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正規System32の直接の子であるストレージ用イベント資源DLLの現在値を読む
 * @param[in] path 元INFが指定したSystem32直下のDLL絶対位置
 * @param[out] snapshot 親の保護と実ファイルの同一性・保護・全ハッシュ、または葉の正式な不在。失敗時は空
 * @return 読取り成功0、位置・保護・ファイル照会の不成立はHRESULT
 * @note DLLの存在と署名済み元媒体との同一性は呼出側で照合する。DLLをロードせず変更しない
 */
//------------------------------------------------------------------------------
NativeError readSystem32StorageEventResourceSnapshot( std::wstring_view			  path,
													 ProtectedExecutableSnapshot &snapshot)
{
	snapshot = {} ;
	std::array<wchar_t, MAX_PATH> directory{} ;	// Windowsが返すネイティブSystem32の絶対位置
	const auto					  length = GetSystemDirectoryW( directory.data(),
															   // 終端を除く完全長
															   static_cast<UINT>( directory.size())) ;
	// 正規のWindowsディレクトリを確定できた場合だけ位置を照合する
	if( length == 0U || length >= directory.size()) {
		return systemVerificationError( length == 0U ? GetLastError() : ERROR_INSUFFICIENT_BUFFER) ;
	}

	const auto separator = path.rfind( L'\\') ;	// コピー先の直接親と資源名の境界
	// 同じWindowsのSystem32を直接親とする絶対位置だけを受理する
	if( separator != length ||
	   !publisherNamesEqual( path.substr( 0U, separator), {directory.data(), length})) {
		return systemVerificationError( ERROR_INVALID_NAME) ;
	}

	const auto leaf = path.substr( separator + 1U) ;	// 元イベント資源DLL一つの通常名
	// 予約名、代替データストリームや別拡張子を含む曖昧な資源名を拒否する
	if( leaf.size() <= 4U || !isSafeOfficialArchiveMember( leaf, L'\\') ||
	   !publisherNamesEqual( leaf.substr( leaf.size() - 4U), L".dll")) {
		return systemVerificationError( ERROR_INVALID_NAME) ;
	}

	return readProtectedExecutableAtPath( path, false, snapshot) ;
}

//------------------------------------------------------------------------------
/**
 * @brief SCMの元コマンドを固定Driver Store内の実ファイルへ解決して保護付きで読み取る
 * @param[in] command SCMの原文字列。全体を囲む引用符だけを許容する
 * @param[in] sourceFile 署名済みの選択が宣言した一つのEXEファイル名
 * @param[out] resolved 同じWindowsのFileRepository内の絶対位置。失敗時は空
 * @param[out] snapshot ファイルと二つの親の同一性・保護とハッシュ。失敗時は空
 * @return 保護された実ファイルの読取り成功0、構文・位置・種別・読取の不成立はHRESULT
 * @note 現在ファイルの署名元や登録済みパッケージの所有は別に確認する。実行しない
 */
//------------------------------------------------------------------------------
NativeError readDriverStoreExecutableSnapshot( std::wstring_view command,
											  std::wstring_view sourceFile, std::wstring &resolved,
											  ProtectedExecutableSnapshot &snapshot)
{
	resolved.clear() ;
	snapshot = {} ;
	// 元のコピーと同じ一つのEXE名だけを許す
	if( command.empty() || command.size() > 4096U || sourceFile.size() <= 4U ||
	   sourceFile.find( L'\\') != sourceFile.npos ||
	   !isSafeOfficialArchiveMember( sourceFile, L'\\') ||
	   !publisherNamesEqual( sourceFile.substr( sourceFile.size() - 4U), L".exe")) {
		return systemVerificationError( ERROR_INVALID_NAME) ;
	}

	// 元の位置指定が全体を一組の引用符で囲む場合true
	const bool quoted = command.size() >= 2U && command.front() == L'"' && command.back() == L'"' ;
	// 元全体を囲む単一組だけが実行ファイル名の引用符となる
	if( quoted) {
		command.remove_prefix( 1U) ;
		command.remove_suffix( 1U) ;
	}

	// 引数の切捨て、NULまでの読み替え、非正規のパス区切りを行わない
	if( command.find_first_of( L"\"/<>|?*") != command.npos ||
	   std::ranges::any_of( command, []( wchar_t c) { return c < L' ' || c == 0x7f ; })) {
		return systemVerificationError( ERROR_INVALID_NAME) ;
	}

	std::array<wchar_t, MAX_PATH> system{} ;	// ネイティブSystem32の正規位置
	// 同じWindowsの固定ルートを返した文字数
	const auto length = GetSystemDirectoryW( system.data(), static_cast<UINT>( system.size())) ;
	// 元Windowsから解決できないときは任意の環境変数へ遡らない
	if( length == 0U || length >= system.size()) {
		return systemVerificationError( length == 0U ? GetLastError() : ERROR_INSUFFICIENT_BUFFER) ;
	}

	const std::wstring_view		system32{system.data(), length} ;		// 同Windowsから得た完全親
	const auto					systemLeaf = system32.rfind( L'\\') ;	// 正規Windowsルートとの境界
	constexpr std::wstring_view root{L"%SystemRoot%\\"} ;				// 許容する元変数名一つ
	std::wstring				path{command} ;							// 既知パスとして照合する作業値
	// 変数展開はSCMの一つのWindows起点を完全一致させた場合だけ行う
	if( systemLeaf != system32.npos && command.size() > root.size() &&
	   publisherNamesEqual( command.substr( 0U, root.size()), root)) {
		path = std::wstring{system32.substr( 0U, systemLeaf + 1U)} +
			   std::wstring{command.substr( root.size())} ;
	}

	const auto repository =
		std::wstring{system32} + L"\\DriverStore\\FileRepository\\" ;	// 正式親と末尾区切り
	// 別のWindows、別の配布ルート、未展開変数や引用なしの曖昧な実行先は使わない
	if( path.size() <= repository.size() || path.find( L'%') != path.npos ||
	   (!quoted && path.find( L' ') != path.npos) ||
	   !publisherNamesEqual( std::wstring_view{path}.substr( 0U, repository.size()), repository)) {
		return systemVerificationError( ERROR_INVALID_NAME) ;
	}

	const auto relative =
		std::wstring_view{path}.substr( repository.size()) ;	// パッケージと元EXEの相対位置
	const auto separator = relative.find( L'\\') ;				// 直下の一つのパッケージの終端
	// パッケージ名は固定せず、一つの親と元EXE名への完全一致を確認する
	if( separator == relative.npos || separator != relative.rfind( L'\\') ||
	   !isSafeOfficialArchiveMember( relative, L'\\') ||
	   !publisherNamesEqual( relative.substr( separator + 1U), sourceFile)) {
		return systemVerificationError( ERROR_INVALID_NAME) ;
	}

	// 変更非共有で保持した実行ファイルと保護の読取り診断
	const auto error = readProtectedExecutableAtPath( path, true, snapshot) ;
	// 読取が成立した実ファイル位置だけを再観測へ渡す
	if( error == 0U) {
		resolved = std::move( path) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同元packageのAMD64 PE32+ headerを既有界readerで非実行確認します
 * @param[in] path 元保護領域内の通常file絶対位置です
 * @return 完全headerと有限security table範囲成立0、元I/O又は形式不正のHRESULTです
 * @note 署名/コピー元/実行意味は検証しません。CATと全byteは呼出し側が別に確認します
 */
//------------------------------------------------------------------------------
NativeError verifyAmd64PeFile( const std::wstring_view path)
{
	const std::wstring			   name{path} ;	// 同同期だけでNUL終端を所有します
	// 元byteを同期中だけ保持する読取専用fileです
	const ReadOnlyVerificationFile file( CreateFileW( name.c_str(), GENERIC_READ, FILE_SHARE_READ,
													nullptr, OPEN_EXISTING,
													FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;
	// 元file以外へ再試行せずI/Oの元errorを保持します
	if( file.get() == INVALID_HANDLE_VALUE) {
		return systemVerificationError( GetLastError()) ;
	}

	FILE_ATTRIBUTE_TAG_INFO attributes{} ;	// 同handleの実種別だけです
	// reparseとdirectoryをPE形式の確認へ渡しません
	if( !GetFileInformationByHandleEx( file.get(), FileAttributeTagInfo, &attributes,
									 sizeof( attributes))) {
		return systemVerificationError( GetLastError()) ;
	}

	// 外部参照へsource fileを置換しません
	if( (attributes.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) !=
	   0U) {
		return systemVerificationError( ERROR_ACCESS_DENIED) ;
	}

	bool embedded{} ;	// 署名方式の存在だけでtrustへ昇格しません
	return systemPeSignatureForm( file.get(), embedded) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 防改変権限を持つWindows fileを実署名形式に従いcache-onlyで検証します
 * @param[in] path 同OSの固定System32名から決めた絶対位置です
 * @param[out] evidence 成功時だけ原file/権限/CAT tupleです
 * @param[out] diagnosticStage null可の固定検証地点です
 * @param[in] peFormat trueはPE形式、falseは非実行参考INFです
 * @return 全trust成立0、最初の元HRESULTです
 * @note 許可のないfallbackや実行/ACL変更を行いません
 */
//------------------------------------------------------------------------------
NativeError verifyWindowsSystemFileImpl( const std::wstring_view path,
										WindowsSystemFileTrust &evidence,
										std::uint32_t *diagnosticStage, const bool peFormat)
{
	evidence = {} ;
	systemVerificationStage( diagnosticStage, WindowsSystemFileStage::FILE_OPEN) ;
	const std::wstring name( path) ;	// この同期だけの終端位置です
	std::vector<std::unique_ptr<ReadOnlyVerificationFile>>
		 fileParents ;	// 元helperの全祖先も保持します
	auto parentError =
		// 実体を開く前の非reparse確認です
		pinSystemCatalogParents( name, fileParents) ;
	// 祖先不明を通常Windows位置と見なしません
	if( parentError != 0U) {
		return parentError ;
	}

	const ReadOnlyVerificationFile file( CreateFileW(
		name.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;	// 元実体を変更不能にします
	// openの元errorを失いません
	if( file.get() == INVALID_HANDLE_VALUE) {
		return systemVerificationError( GetLastError()) ;
	}

	FILE_ATTRIBUTE_TAG_INFO attributes{} ;	// 同handleの原属性です
	// Reparseやdirectoryを署名対象へ認定しません
	if( !GetFileInformationByHandleEx( file.get(), FileAttributeTagInfo, &attributes,
									 sizeof( attributes))) {
		return systemVerificationError( GetLastError()) ;
	}

	// 固定SYSTEM fileの種別を検証します
	if( (attributes.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) !=
	   0U) {
		return systemVerificationError( ERROR_ACCESS_DENIED) ;
	}

	WindowsSystemFileTrust original ;	// 全成功時だけ返す元helperのtupleです
	original.filePath = name ;
	auto error		  = verifySystemFilePermissions( file.get(), original.fileSecurity,
													diagnosticStage) ;	// 元SDと非特権AccessCheckです
	// 不明な権限を署名成功で隠しません
	if( error != 0U) {
		return error ;
	}

	LARGE_INTEGER originalBytes{} ;	// 同保持fileの元sizeです
	// Sizeの元errorを後続hashで隠しません
	if( !GetFileSizeEx( file.get(), &originalBytes)) {
		return systemVerificationError( GetLastError()) ;
	}

	original.fileBytes = static_cast<std::uint64_t>( originalBytes.QuadPart) ;
	error			   = computeFileSha256( name, original.fileSha256) ;
	// 完全hashなしにtrustを継承しません
	if( error != 0U) {
		return error ;
	}

	bool embedded{} ;	// 元PEで決める唯一の方式です
	systemVerificationStage( diagnosticStage, WindowsSystemFileStage::SIGNATURE_FORM) ;
	error = peFormat ? systemPeSignatureForm( file.get(), embedded) : 0U ;
	// 不正PEはCAT検索へ進みません
	if( error != 0U) {
		return error ;
	}

	constexpr std::array<std::wstring_view, 1U> WINDOWS_PUBLISHER{
		L"Microsoft Windows"} ;	// 完全publisherだけです
	// 非空embedded tableがあれば既APIの成功/失敗だけを返します
	if( embedded) {
		systemVerificationStage( diagnosticStage, WindowsSystemFileStage::EMBEDDED_TRUST) ;
		error = verifyAuthenticodePublisherCachedOnly( path, WINDOWS_PUBLISHER) ;
		// 成功した同原helperのtupleだけを返します
		if( error == 0U) {
			evidence = std::move( original) ;
		}

		return error ;
	}

	const auto &api =
		// 同threadの完全backendです
		driver_package_signature_detail::authenticodeApi() ;
	systemVerificationStage( diagnosticStage, WindowsSystemFileStage::CATALOG_LOOKUP) ;
	// 内部表の不足をnative CAT取得で補完しません
	if( !api.catalogFromHash || !api.catalogInformation || !api.releaseCatalog) {
		return E_NOTIMPL ;
	}

	std::array<wchar_t, MAX_PATH> windows{} ;	// OSが返す固定rootです
	const auto					  characters = GetWindowsDirectoryW(
		   // 環境変数は使いません
		   windows.data(), static_cast<UINT>( windows.size())) ;
	// Root不明を任意CAT領域へ切り替えません
	if( characters == 0U || characters >= windows.size()) {
		return systemVerificationError( characters == 0U ? GetLastError() : ERROR_BUFFER_OVERFLOW) ;
	}

	const std::wstring catalogRoot =
		// OS local storeだけです
		std::wstring( windows.data()) + L"\\System32\\CatRoot\\" ;
	// Member検索はtrust前だけ、SHA256/SHA1の最大二方式各一候補へ限定します
	for( const auto bytes : {32U, 20U}) {
		CatalogHashContext context ;	// このdigest方式だけの所有contextです
		error = context.initialize( bytes == 32U ? BCRYPT_SHA256_ALGORITHM : BCRYPT_SHA1_ALGORITHM,
								   bytes) ;
		// API失敗を次方式で隠しません
		if( error != 0U) {
			return error ;
		}

		LARGE_INTEGER start{} ;	// 元保持fileの先頭です
		// Hashは全byteから計算します
		if( !SetFilePointerEx( file.get(), start, nullptr, FILE_BEGIN)) {
			return systemVerificationError( GetLastError()) ;
		}

		std::vector<BYTE> hash ;	// 同contextの原file digestです
		error = context.calculateHash( file.get(), hash) ;
		// 不正hashをCAT候補へ渡しません
		if( error != 0U) {
			return error ;
		}

		SetLastError( ERROR_SUCCESS) ;
		const auto catalog =
			api.catalogFromHash( context.get(), hash.data(), static_cast<DWORD>( hash.size()), 0U,
								nullptr) ;	// 同digestの一件です
		// 未発見だけはtrust前の別digest検索を許可します
		if( !catalog) {
			const DWORD lookupError = GetLastError() ;	// 元lookup errorです
			// 未発見以外を単なる候補なしへ変えません
			if( lookupError != ERROR_SUCCESS && lookupError != ERROR_NOT_FOUND &&
			   lookupError != ERROR_NO_MORE_ITEMS) {
				return systemVerificationError( lookupError) ;
			}

			continue ;
		}

		CATALOG_INFO information{} ;	// 同CAT contextの原位置です
		information.cbStruct = sizeof( information) ;
		const BOOL read =
			// 元APIを一度だけ呼びます
			api.catalogInformation( catalog, &information, 0U) ;
		const DWORD readError = read ? ERROR_SUCCESS : GetLastError() ;	// 解放前の元errorです
		const BOOL	released =
			// この一件を必ず解放します
			api.releaseCatalog( context.get(), catalog, 0U) ;
		// 解放/位置読取の失敗を別CATで隠しません
		if( !read || !released) {
			return systemVerificationError( !read ? readError : GetLastError()) ;
		}

		const std::wstring_view observed( information.wszCatalogFile,
										 MAX_PATH) ;			// 固定buffer内で終端を確認します
		const auto				end = observed.find( L'\0') ;	// 任意の未終端pathは使いません
		// OS CAT root以外や名前境界違いを拒否します
		if( end == observed.npos || end <= catalogRoot.size() ||
		   CompareStringOrdinal( observed.data(), static_cast<int>( catalogRoot.size()),
								catalogRoot.c_str(), static_cast<int>( catalogRoot.size()),
								TRUE) != CSTR_EQUAL) {
			return systemVerificationError( ERROR_ACCESS_DENIED) ;
		}

		const std::wstring catalogPath( observed.substr( 0U, end)) ;	// 選択した唯一の原CATです
		std::vector<std::unique_ptr<ReadOnlyVerificationFile>>
			parents ;	// 同原CATの全祖先を保持します
		error = pinSystemCatalogParents( catalogPath, parents) ;
		// 祖先のreparse/rename競合を信頼しません
		if( error != 0U) {
			return error ;
		}

		const ReadOnlyVerificationFile catFile( CreateFileW(
			catalogPath.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr,
			OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;	// Trust終了まで保持します
		// CATを固定できない場合は元errorです
		if( catFile.get() == INVALID_HANDLE_VALUE) {
			return systemVerificationError( GetLastError()) ;
		}

		WindowsSystemFileTrust selected = original ;	// 同helperにCATを結びます
		error =
			verifySystemFilePermissions( catFile.get(), selected.catalogSecurity, diagnosticStage) ;
		// 元CATの防改変権限も必要です
		if( error != 0U) {
			return error ;
		}

		selected.catalogPath = catalogPath ;
		LARGE_INTEGER length{} ;	// 同保持CATの元sizeです
		// 過大CATを署名検証へ渡しません
		if( !GetFileSizeEx( catFile.get(), &length)) {
			return systemVerificationError( GetLastError()) ;
		}

		// 有限な原CATだけを採用します
		if( length.QuadPart <= 0 || length.QuadPart > 64LL * 1024LL * 1024LL) {
			return systemVerificationError( ERROR_BUFFER_OVERFLOW) ;
		}

		selected.catalogBytes = static_cast<std::uint64_t>( length.QuadPart) ;
		error				  = computeFileSha256( catalogPath, selected.catalogSha256) ;
		// Hash失敗をtrustに置換しません
		if( error != 0U) {
			return error ;
		}

		const std::array<std::wstring, 1U> members{name} ;	// 原file一件だけです
		systemVerificationStage( diagnosticStage, WindowsSystemFileStage::CATALOG_TRUST) ;
		error = verifyCatalogMembersWithPolicy( catalogPath, members, true) ;
		// Trust失敗後にCAT/方式を切り替えません
		if( error != 0U) {
			return error ;
		}

		std::wstring publisher ;	// 同CATの先頭署名に結ぶ名前です
		systemVerificationStage( diagnosticStage, WindowsSystemFileStage::CATALOG_PUBLISHER) ;
		error = readSignerName( catalogPath, publisher, true) ;
		// 同じCATの署名と完全publisherを別々に要求します
		if( error != 0U || !publisherNamesEqual( publisher, WINDOWS_PUBLISHER.front())) {
			return error != 0U ? error : static_cast<NativeError>( TRUST_E_SUBJECT_NOT_TRUSTED) ;
		}

		evidence = std::move( selected) ;
		return 0U ;
	}

	return TRUST_E_NOSIGNATURE ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 同梱INFの全祖先の再解析点と置換を拒否し、直接親とFileRepositoryの保護を確認する
 * @param[in] path 同じWindowsに限定した公開INF又はFileRepositoryのINFの完全位置
 * @param[in] protectedCount 公開INFの親は1、パッケージとFileRepositoryは2
 * @param[out] parents 先に開いた各祖先の所有ハンドル。呼出側が検証終了まで保持する
 * @return 祖先の固定と必要な保護の確認は0、元エラー又は不一致はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError pinInboxInfParents(
	const std::wstring &path, std::size_t protectedCount,
	std::vector<std::unique_ptr<ReadOnlyVerificationFile>> &parents)
{
	const auto error =
		// 全祖先の固定結果
		pinSystemCatalogParents( path, parents, protectedCount) ;
	// 祖先の固定が一部でも成立しなければ葉の検査へ進まない
	if( error != 0 || parents.size() < protectedCount) {
		return error != 0 ? error : E_UNEXPECTED ;
	}

	std::vector<std::byte> security ;	// 各ディレクトリの保護を独立に確認するための一時領域
	// 正規の葉を別名から解決させないため、置換を許さない直近の親を確かめる
	for( const auto &parent : std::span{parents}.last( protectedCount)) {
		const auto protection = verifySystemFilePermissions( parent->get(), security, nullptr,
															true) ;	// 子の置換を含む非特権の変更権限
		// 一つでも非特権による置換が可能なら正規配置と認定しない
		if( protection != 0) {
			return protection ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 書込削除非共有で開いた葉の正規位置・通常属性と保護を確認する
 * @param[in] file 直前に開いた所有者から借用したファイルハンドル
 * @param[in] path 再解析点でない各祖先を保持して開いた元の完全位置
 * @param[out] security 成功時の元ownerとDACL等。失敗時は使用しない
 * @return 通常ファイルの正規位置と保護の一致は0、元エラー又は不一致はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyPinnedInboxFile( HANDLE file, std::wstring_view path,
												std::vector<std::byte> &security)
{
	// 直前のCreateFileW失敗の診断を保持する
	if( file == INVALID_HANDLE_VALUE) {
		return systemVerificationError( GetLastError()) ;
	}

	FILE_ATTRIBUTE_TAG_INFO attributes{} ;	// 同じ保持ハンドルから読む種別
	// 種別を確認できないファイルを読み取らない
	if( !GetFileInformationByHandleEx( file, FileAttributeTagInfo, &attributes, sizeof( attributes))) {
		return systemVerificationError( GetLastError()) ;
	}

	// 葉も再解析点やディレクトリを許容しない
	if( (attributes.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) !=
	   0) {
		return systemVerificationError( ERROR_INVALID_DATA) ;
	}

	const auto location = checkProtectedExecutableLocation( file, path) ;	// 元の完全DOS位置との照合
	return location == 0 ? verifySystemFilePermissions( file, security, nullptr) : location ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同梱machine.infから現OSが選ぶ空のNO_DRVと空名の関連サービスだけを確認する
 * @param[in] copy 書込削除非共有で保持した公開machine.infの全バイトと一致する一時コピー
 * @return 完全な空導入契約の場合0、元SetupAPIエラー又は作用不一致はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyInboxNullDriverSections( const std::wstring &copy)
{
	const auto raw =
		SetupOpenInfFileW( copy.c_str(), nullptr, INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
						  nullptr) ;	// Windowsの登録済みINFキャッシュを開かず一時コピーを解析する
	// 原バイトを解析できない場合は空節と推定しない
	if( raw == INVALID_HANDLE_VALUE) {
		return systemVerificationError( GetLastError()) ;
	}

	const std::unique_ptr<void, decltype( &SetupCloseInfFile)> inf(
		raw,
		&SetupCloseInfFile) ;			// 検査終了までSetupAPIの解析結果を保持する
	std::array<wchar_t, 32U> actual{} ;	// NO_DRVそのものを確認する有限の節名
	// 現Windowsによる選択が成立しない場合は未修飾節へ独自に切り替えない
	if( !SetupDiGetActualSectionToInstallW( inf.get(), L"NO_DRV", actual.data(),
										  static_cast<DWORD>( actual.size()), nullptr, nullptr)) {
		return systemVerificationError( GetLastError()) ;
	}

	constexpr std::wstring_view BASIC_SECTION{L"NO_DRV"} ;	// 空導入の固定節名
	// 修飾節を選択する配布は、基本節が空であっても受理しない
	if( actual[BASIC_SECTION.size()] != L'\0' ||
	   !publisherNamesEqual( {actual.data(), BASIC_SECTION.size()}, BASIC_SECTION)) {
		return systemVerificationError( ERROR_INVALID_DATA) ;
	}

	// 必須二節を確認し、Windowsの構文解析エラーと行数違いを区別する
	for( const auto section : {L"NO_DRV", L"NO_DRV.Services"}) {
		const auto count = SetupGetLineCountW( inf.get(), section) ;	// Windowsが解析した実際の行数
		// 必須節の不存在又は読取り失敗は元の値を返す
		if( count < 0) {
			return systemVerificationError( GetLastError()) ;
		}

		const auto expected = std::wstring_view( section) == L"NO_DRV" ? 0L : 1L ;	// 許容する作用数
		// 余分な指示のある基本節やサービス節を空導入と認定しない
		if( count != expected) {
			return systemVerificationError( ERROR_INVALID_DATA) ;
		}
	}

	// 基本節とServices節に関連するSecurity節はいずれも明示的な不存在だけを受理する
	for( const auto section : {L"NO_DRV.Security", L"NO_DRV.Services.Security"}) {
		SetLastError( ERROR_SUCCESS) ;
		const auto count = SetupGetLineCountW( inf.get(), section) ;	// 空の節も存在として扱う
		const auto error = GetLastError() ;								// 不存在と他の照会失敗を区別する診断
		// 対象のセキュリティ作用を追加する節は許可しない
		if( count >= 0 || error != ERROR_SECTION_NOT_FOUND) {
			return systemVerificationError( count >= 0 ? ERROR_INVALID_DATA : error) ;
		}
	}

	INFCONTEXT row{} ;	// 空の関連サービス指定一行の解析位置
	// 既に数えた行の読取り失敗は元診断を維持する
	if( !SetupGetLineByIndexW( inf.get(), L"NO_DRV.Services", 0, &row)) {
		return systemVerificationError( GetLastError()) ;
	}

	// 実サービスの構成や追加引数を持つ行は受理しない
	if( SetupGetFieldCount( &row) != 2U) {
		return systemVerificationError( ERROR_INVALID_DATA) ;
	}

	std::array<wchar_t, 32U> key{} ;	// 空名の関連サービス指定に使うキー
	std::array<wchar_t, 2U>	 name{} ;	// 非空のサービス名を受理しないための有限バッファ
	INT						 flags{} ;	// 文字列置換後にWindowsが解決した数値
	// 行のキーと二項目はSetupAPIの元の構文と数値解釈を使う
	if( !SetupGetStringFieldW( &row, 0, key.data(), static_cast<DWORD>( key.size()), nullptr) ||
	   !SetupGetStringFieldW( &row, 1, name.data(), static_cast<DWORD>( name.size()), nullptr) ||
	   !SetupGetIntField( &row, 2, &flags)) {
		return systemVerificationError( GetLastError()) ;
	}

	constexpr std::wstring_view ADD_SERVICE{L"AddService"} ;	// 二項目を解釈する元directive
	return key[ADD_SERVICE.size()] == L'\0' &&
				   publisherNamesEqual( {key.data(), ADD_SERVICE.size()}, ADD_SERVICE) &&
				   name.front() == L'\0' && flags == SPSVCINST_ASSOCSERVICE
			   ? 0
			   : systemVerificationError( ERROR_INVALID_DATA) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 検査済みINFと完全一致する保護付き一時コピーを保持して内容検査を呼ぶ
 * @param[in] leaf 同じ元INFの安全な葉名
 * @param[in] bytes 同じ元ファイルから取得した有限な原バイト
 * @param[in] sha256 署名検査時の同じ元ファイルの完全SHA-256
 * @param[in] inspect コピーのパスを同期で借用する解析。元の配置は呼出し側で保持する
 * @return 元バイトとの完全一致と内容検査が成功すれば0、失敗はHRESULT
 * @note 元ファイルの署名は呼出し側で確認する。元のWindows INFを解析用に開かない
 */
//------------------------------------------------------------------------------
NativeError inspectProtectedInfCopy( std::wstring_view leaf, std::span<const std::uint8_t> bytes,
									std::wstring_view										sha256,
									const std::function<NativeError( const std::wstring &)> &inspect)
{
	// 同期検査と4 MiB以内の元INFがそろってから隔離領域を確保する
	if( !inspect || leaf.size() <= 4U || leaf.find_first_of( L"\\/") != leaf.npos ||
	   !isSafeOfficialArchiveMember( leaf, L'\\') ||
	   !publisherNamesEqual( leaf.substr( leaf.size() - 4U), L".inf") || bytes.empty() ||
	   bytes.size() > 4U * 1024U * 1024U || sha256.size() != 64U) {
		return E_INVALIDARG ;
	}

	OfficialDownloadWorkspace workspace ;					// 管理者保護の新規領域と、既知ファイルの回収だけを所有する
	auto error = workspace.initialize( L"inbox-inf", 1U) ;	// 収集等と分離した独立の一時領域
	// 一時領域を確保できなければWindowsの公開INFを解析用に開かない
	if( error != 0) {
		return error ;
	}

	// 書込みハンドルの寿命を限定し、読取専用で再固定してからSetupAPIへ渡す
	{
		HANDLE raw = INVALID_HANDLE_VALUE ;	// この領域が新規作成したファイルの所有ハンドル
		error	   = workspace.createFile( leaf, raw) ;
		// 既存ファイル又は未追跡ファイルへの上書きを行わない
		if( error != 0) {
			return error ;
		}

		const ReadOnlyVerificationFile output( raw) ;	// 全return経路で新規ファイルを閉じる
		DWORD						   written{} ;		// Windowsが成功として受理したバイト数
		// 有限な全バイトを保持中の原INFからそのままコピーする
		if( !WriteFile( output.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &written,
					  nullptr)) {
			return systemVerificationError( GetLastError()) ;
		}

		// 一部書込みは解析せず、領域所有者が回収する
		if( written != bytes.size()) {
			return systemVerificationError( ERROR_WRITE_FAULT) ;
		}
	}

	const auto					   path = workspace.path( leaf) ;	// 同領域の新規INFの絶対位置
	const ReadOnlyVerificationFile copy( CreateFileW(
		path.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;	// 原バイトとの一致から解析終了まで固定する
	std::vector<std::byte>		   security ;		// コピーの現在の保護を独立に確認する
	error = verifyPinnedInboxFile( copy.get(), path, security) ;
	// 正規位置と保護の成立を確かめてから内容を読み直す
	if( error != 0) {
		return error ;
	}

	std::vector<BYTE> copied ;	// 再度開いて保持した一時INFから読む全内容
	error = readFileBytes( path, bytes.size(), copied) ;
	// 解析対象が署名照合した元のWindows INFとバイト単位で一致することを確認する
	if( error != 0 || !std::ranges::equal( bytes, copied)) {
		return error != 0 ? error : TRUST_E_BAD_DIGEST ;
	}

	std::wstring copySha256 ;	// 原CAT照合時の元ハッシュと照合する
	error = computeFileSha256( path, copySha256) ;
	// 原INFと同じハッシュで固定できた一時コピーだけを解析する
	if( error != 0 || copySha256 != sha256) {
		return error != 0 ? error : TRUST_E_BAD_DIGEST ;
	}

	return inspect( path) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保護されたWindows同梱INFの公開ファイル、Store原本と登録CATを照合してから内容検査を呼ぶ
 * @param[in] publishedInfName 同じWindowsのINF直下にある公開INFの葉名
 * @param[in] inspect 成功したStore位置、公開INFとCATの信頼、全原バイトを同期で借用する検査
 * @return 署名元と内容の検査がともに成功して0、最初の失敗はHRESULT
 * @note 借用は呼出し中だけ有効。元INFとCATを保持する。解析用入力が必要なら原バイトを一時コピーする
 * @note 正確な元選択、SYSの所属、端末との対応は呼出し側で検証する
 */
//------------------------------------------------------------------------------
NativeError inspectVerifiedWindowsInboxInf( std::wstring_view					   publishedInfName,
										   const VerifiedWindowsInboxInfInspector &inspect)
{
	// Windowsが示す通常のINF葉だけを公開ディレクトリから開く
	if( !inspect || publishedInfName.size() <= 4U || publishedInfName.size() >= MAX_PATH ||
	   publishedInfName.find_first_of( L"\\/") != publishedInfName.npos ||
	   !isSafeOfficialArchiveMember( publishedInfName, L'\\') ||
	   !publisherNamesEqual( publishedInfName.substr( publishedInfName.size() - 4U), L".inf")) {
		return E_INVALIDARG ;
	}

	try {
		std::array<wchar_t, MAX_PATH> root{} ;	// 現OSが返すシステムWindowsの絶対位置
		// OS APIが返した末尾の終端を除く文字数
		const auto length = GetSystemWindowsDirectoryW( root.data(), static_cast<UINT>( root.size())) ;
		// Windowsの固定配置を確認できなければ他の起点を使わない
		if( length == 0 || length >= root.size()) {
			return systemVerificationError( length == 0 ? GetLastError()
													   : ERROR_INSUFFICIENT_BUFFER) ;
		}

		const std::wstring windows( root.data(), length) ;	// 同じOSのWindowsルート
		// 同じWindowsが公開している元INF
		const auto		   published = windows + L"\\INF\\" + std::wstring( publishedInfName) ;
		std::vector<std::unique_ptr<ReadOnlyVerificationFile>> publishedParents ;	// 元INFの全祖先
		auto error = pinInboxInfParents( published, 1U, publishedParents) ;			// 固定した公開位置と保護
		// 公開位置を保護付きで固定できなければStore解決へ進まない
		if( error != 0) {
			return error ;
		}

		const ReadOnlyVerificationFile publishedFile( CreateFileW(
			published.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
			FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;		// 公開INFの実ファイルを保持する
		std::vector<std::byte>		   publishedSecurity ;	// 署名確認時と結ぶ公開INFの保護
		error = verifyPinnedInboxFile( publishedFile.get(), published, publishedSecurity) ;
		// Windowsの正規公開位置の実ファイルだけをSetupAPIへ渡す
		if( error != 0) {
			return error ;
		}

		std::array<wchar_t, MAX_PATH> location{} ;	// 現在登録された同梱INFのStore完全位置
		// 容量を増やしたり別名で再試行したりせず元の対応だけを解決する
		if( !SetupGetInfDriverStoreLocationW( published.c_str(), nullptr, nullptr, location.data(),
											static_cast<DWORD>( location.size()), nullptr)) {
			return systemVerificationError( GetLastError()) ;
		}

		const auto end = std::ranges::find( location, L'\0') ;	// 有限位置内の終端
		const auto repository =
			windows + L"\\System32\\DriverStore\\FileRepository\\" ;	// 正規のStore境界
		const std::wstring store( location.begin(), end) ;				// Windowsが返した原位置
		// WindowsのFileRepository外や未終端の応答を対象にしない
		if( end == location.end() || store.size() <= repository.size() ||
		   !publisherNamesEqual( std::wstring_view( store).substr( 0U, repository.size()),
								repository)) {
			return systemVerificationError( ERROR_INVALID_NAME) ;
		}

		const auto relative =
			// 一つの配布親と葉
			std::wstring_view( store).substr( repository.size()) ;
		const auto separator = relative.find( L'\\') ;	// 親と葉の境界
		// FileRepositoryの直下1階層の正規配布にある同梱INFだけを開く
		if( separator == relative.npos || separator != relative.rfind( L'\\') ||
		   !isSafeOfficialArchiveMember( relative, L'\\') ||
		   !publisherNamesEqual( relative.substr( separator + 1U), publishedInfName)) {
			return systemVerificationError( ERROR_INVALID_NAME) ;
		}

		std::vector<std::unique_ptr<ReadOnlyVerificationFile>> storeParents ;	// Store内の全祖先
		error = pinInboxInfParents( store, 2U, storeParents) ;
		// FileRepositoryと配布親の両方が保護される場合だけ葉を開く
		if( error != 0) {
			return error ;
		}

		const ReadOnlyVerificationFile storeFile( CreateFileW(
			store.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
			FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;	// Storeの実INFを保持する
		std::vector<std::byte>		   storeSecurity ;	// 別ファイルである場合も独立に保護を確認する
		error = verifyPinnedInboxFile( storeFile.get(), store, storeSecurity) ;
		// 保持できない物理ファイルを元配布のコピーと見なさない
		if( error != 0) {
			return error ;
		}

		std::array<wchar_t, MAX_PATH> reverse{} ;	// Storeの実INFに対応する公開名
		// 正方向だけの一致と区別し、保持中に登録の逆引きを確認する
		if( !SetupGetInfPublishedNameW( store.c_str(), reverse.data(),
									  static_cast<DWORD>( reverse.size()), nullptr)) {
			return systemVerificationError( GetLastError()) ;
		}

		const auto				reverseEnd = std::ranges::find( reverse, L'\0') ;	// 有限位置内の終端
		const std::wstring_view reverseName( reverse.begin(), reverseEnd) ;			// Windowsが返した公開名
		// Windowsが返す葉名又は同じ公開ファイルの完全位置だけを受理する
		if( reverseEnd == reverse.end() || (!publisherNamesEqual( reverseName, publishedInfName) &&
										   !publisherNamesEqual( reverseName, published))) {
			return systemVerificationError( ERROR_INVALID_NAME) ;
		}

		constexpr std::uint64_t MAXIMUM_INBOX_INF_BYTES = 4U * 1024U * 1024U ;	// INF全バイトの各上限
		std::vector<BYTE>		publishedBytes ;								// 共有ロック中に読む公開INFの全バイト
		std::vector<BYTE>		storeBytes ;									// 同じロック条件で読むStoreのINFの全バイト
		error = readFileBytes( published, MAXIMUM_INBOX_INF_BYTES, publishedBytes) ;
		// 公開INFを完全に読めた場合だけStore内容を比較する
		if( error == 0) {
			error = readFileBytes( store, MAXIMUM_INBOX_INF_BYTES, storeBytes) ;
		}

		// Hardlinkであっても完全な原バイト一致を確認する
		if( error != 0 || publishedBytes != storeBytes) {
			return error != 0 ? error : TRUST_E_BAD_DIGEST ;
		}

		WindowsSystemFileTrust evidence ;	// Windows現在の原INFと登録済みCATの完全な証明
		error = verifyWindowsSystemFileImpl( published, evidence, nullptr, false) ;
		// 元の非実行INFを証明したCAT以外に切り替えない
		if( error != 0 || evidence.catalogPath.empty() ||
		   publishedBytes.size() != evidence.fileBytes ||
		   evidence.fileSecurity != publishedSecurity) {
			return error != 0 ? error : TRUST_E_SUBJECT_NOT_TRUSTED ;
		}

		std::vector<std::unique_ptr<ReadOnlyVerificationFile>> catalogParents ;	// 元CatRootの全祖先
		error = pinSystemCatalogParents( evidence.catalogPath, catalogParents) ;
		// 署名確認した同じCATを正規配置に固定する
		if( error != 0) {
			return error ;
		}

		const ReadOnlyVerificationFile catalog(
			CreateFileW( evidence.catalogPath.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ,
						nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT,
						nullptr)) ;					// 共通署名CATを解析終了まで保持する
		std::vector<std::byte> catalogSecurity ;	// 再固定したCATの保護を証明時と照合する
		error = verifyPinnedInboxFile( catalog.get(), evidence.catalogPath, catalogSecurity) ;
		// 途中で置き換わった元CAT又は保護不一致は受理しない
		if( error != 0 || catalogSecurity != evidence.catalogSecurity) {
			return error != 0 ? error : TRUST_E_SUBJECT_NOT_TRUSTED ;
		}

		LARGE_INTEGER catalogBytes{} ;	// 再固定したCATの実バイト数
		// 署名元と同じ有限長だけを再度ハッシュへ渡す
		if( !GetFileSizeEx( catalog.get(), &catalogBytes)) {
			return systemVerificationError( GetLastError()) ;
		}

		// サイズ違いのCATは元証拠を継承できない
		if( catalogBytes.QuadPart <= 0 ||
		   static_cast<std::uint64_t>( catalogBytes.QuadPart) != evidence.catalogBytes) {
			return TRUST_E_BAD_DIGEST ;
		}

		std::wstring catalogSha256 ;	// 元証明時の完全ハッシュと比較する
		error = computeFileSha256( evidence.catalogPath, catalogSha256) ;
		// 固定し直した位置の原ハッシュが一致する場合だけ使用する
		if( error != 0 || catalogSha256 != evidence.catalogSha256) {
			return error != 0 ? error : TRUST_E_BAD_DIGEST ;
		}

		const std::array<std::wstring, 2U> members{published, store} ;	// 両実ファイルを共通CATへ結ぶ
		error = verifyCatalogMembersWithPolicy( evidence.catalogPath, members, true) ;
		// 原CATの両メンバーが成立した場合だけ同じCATの署名者を読み取る
		if( error == 0) {
			std::wstring publisher ;	// 再固定した同じCATの署名者
			error = readSignerName( evidence.catalogPath, publisher, true) ;
			// 完全なWindows署名者のみ同梱の作用確認へ進める
			if( error == 0 && !publisherNamesEqual( publisher, L"Microsoft Windows")) {
				error = TRUST_E_SUBJECT_NOT_TRUSTED ;
			}
		}

		// 元INFとCATの所有を保持している間だけ検査へ借用値を渡す
		return error == 0 ? inspect( store, evidence, publishedBytes) : error ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同じWindowsの公開INFとDriver Storeから同梱machine.infの空導入委譲を検証する
 * @return 正規配置・原バイト・保護・Microsoft Windows署名とNO_DRVの作用が一致すれば0、失敗はHRESULT
 * @note 固定したINFとCATを保持中にローカルの信頼情報とハッシュ一致した一時コピーを読み取る
 */
//------------------------------------------------------------------------------
NativeError verifyWindowsInboxNullDriver()
{
	// 元バイトとハッシュを同期で借用し、保護した一時コピーで既存のNO_DRV契約を検査する
	return inspectVerifiedWindowsInboxInf( L"machine.inf", []( std::wstring_view,
															 const WindowsSystemFileTrust &evidence,
															 std::span<const std::uint8_t> bytes) {
		return inspectProtectedInfCopy( L"machine.inf", bytes, evidence.fileSha256,
									   &verifyInboxNullDriverSections) ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定Windows PEを原署名形式/cache-only/防改変権限へ結合します
 * @param[in] path 同OSの固定System32名から得た通常絶対位置です
 * @param[out] evidence 成功時だけの原byte/CAT/SD tupleです。失敗時は空です
 * @param[out] diagnosticStage null可の固定検証地点です。合否には使用しません
 * @return 全成立0、最初の元API/型/署名/権限errorです
 */
//------------------------------------------------------------------------------
NativeError verifyWindowsSystemFileCachedOnly( const std::wstring_view path,
											  WindowsSystemFileTrust &evidence,
											  std::uint32_t			 *diagnosticStage)
{
	return verifyWindowsSystemFileImpl( path, evidence, diagnosticStage, true) ;
}

//------------------------------------------------------------------------------
/**
 * @brief XML Digital Signatureと埋込みcertificateのpublisherを検証する。XML Digital Signatureとpublisherを検証する
 *        Certificate公開鍵と文書全体の単一referenceを結び付け、CryptXML extensionを使用しない
 * @param[in] path 検証するUTF-8 XML fileの絶対path。 検証するUTF-8 XML file絶対path
 * @param[in] maximumBytes 読取りを許可するXML byte数上限。 XML read上限byte数
 * @param[in] validationFiletime 署名済み時刻を表す1601年起点100ns単位値。 署名済みSigningTime
 * @param[in] acceptedPublishers 許可するcertificate simple display name群。 許可publisher表示名群
 * @return 文書全体の署名、code-signing chain、publisher一致時は0。 XML署名、chain、publisherが全て有効なら0
 * @note 単一enveloped reference、RSA-SHA256、SHA-256、標準C14Nだけを許可する
 */
//------------------------------------------------------------------------------
NativeError verifyXmlSignaturePublisher( const std::wstring_view					 path,
										const std::uint64_t						 maximumBytes,
										const std::uint64_t						 validationFiletime,
										const std::span<const std::wstring_view> acceptedPublishers)
{
	// 対象 path または検証時刻が未指定の XML 署名検証は拒否する
	if( path.empty() || validationFiletime == 0) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const NativeError policyError = validatePublisherPolicy( acceptedPublishers) ;	// Policy検証
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( policyError != 0) {
		return policyError ;
	}

	std::vector<BYTE> bytes ;												// CryptXMLへ渡す上限確認済みUTF-8文書
	NativeError		  error = readFileBytes( path, maximumBytes, bytes) ;	// File読取り結果
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( error != 0) {
		return error ;
	}

	std::size_t xmlOffset{} ;	// CryptXML入力から任意UTF-8 BOMを除く先頭位置
	// UTF-8 BOM がある場合だけ、その直後を XML 本文の先頭とする
	if( bytes.size() >= 3 && bytes[0] == 0xefU && bytes[1] == 0xbbU && bytes[2] == 0xbfU) {
		xmlOffset = 3 ;
	}

	const std::size_t xmlBytes = bytes.size() - xmlOffset ;	// CryptXMLへ渡す文書byte数
	// 空の本文、API の長さ上限超過、XML 開始文字の欠落を拒否する
	if( xmlBytes == 0 || xmlBytes > static_cast<std::size_t>( std::numeric_limits<ULONG>::max()) ||
	   bytes[xmlOffset] != static_cast<BYTE>( '<')) {
		return nativeErrorFromWin32( ERROR_NO_UNICODE_TRANSLATION) ;
	}

	// Lenovo descriptorのlowercase `id`属性をCryptXMLがXML
	// IDと誤認しないよう、署名要素だけを解析する
	const std::string_view	   xmlText( reinterpret_cast<const char *>( bytes.data() + xmlOffset),
									   xmlBytes) ;	// UTF-8全体view
	constexpr std::string_view SIGNATURE_START =
		R"(<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">)" ;				// 固定署名開始tag
	constexpr std::string_view SIGNATURE_END  = R"(</Signature>)" ;					// 固定署名終了tag
	const std::size_t		   signatureStart = xmlText.find( SIGNATURE_START) ;	// 署名開始位置
	const std::size_t		   signatureEndTag =
		 signatureStart == std::string_view::npos
					 ? std::string_view::npos
					 : xmlText.find( SIGNATURE_END, signatureStart + SIGNATURE_START.size()) ;	// 終了位置
	// 署名要素の欠落または重複を拒否し、検証対象を単一に限定する
	if( signatureStart == std::string_view::npos || signatureEndTag == std::string_view::npos ||
	   xmlText.find( SIGNATURE_START, signatureStart + 1) != std::string_view::npos ||
	   xmlText.find( SIGNATURE_END, signatureEndTag + 1) != std::string_view::npos) {
		return static_cast<NativeError>( TRUST_E_SUBJECT_FORM_UNKNOWN) ;
	}

	const std::size_t signatureBytes =
		signatureEndTag + SIGNATURE_END.size() - signatureStart ;	// 署名要素byte数

	ULONG maximumHeap		= 16U * 1024U * 1024U ;	// CryptXML内部allocation上限
	ULONG maximumSignatures = 1 ;					// 一文書で受理するSignature数
	// CryptXMLへ渡すheap使用量と署名件数の有限上限。参照先は呼出し中だけ有効
	const std::array<CRYPT_XML_PROPERTY, 2> properties{
		CRYPT_XML_PROPERTY{.dwPropId = CRYPT_XML_PROPERTY_MAX_HEAP_SIZE,
						   .pvValue	 = &maximumHeap,
						   .cbValue	 = sizeof( maximumHeap)},
		CRYPT_XML_PROPERTY{.dwPropId = CRYPT_XML_PROPERTY_MAX_SIGNATURES,
						   .pvValue	 = &maximumSignatures,
						   .cbValue	 = sizeof( maximumSignatures)}} ;
	CRYPT_XML_BLOB blob{} ;	// UTF-8文書を表す非所有CryptXML入力
	blob.dwCharset = CRYPT_XML_CHARSET_UTF8 ;
	blob.cbData	   = static_cast<ULONG>( signatureBytes) ;
	blob.pbData	   = bytes.data() + xmlOffset + signatureStart ;
	HCRYPTXML document{} ;	// CryptXmlCloseで解放するdocument context
	// 拡張機能を無効にしたCryptXML decode開始結果。後続署名検証へ引き継ぐ
	HRESULT	  status =
		CryptXmlOpenToDecode( nullptr, CRYPT_XML_FLAG_DISABLE_EXTENSIONS, properties.data(),
							 static_cast<ULONG>( properties.size()), &blob, &document) ;
	// 失敗の診断値を共通の表現へ保ったまま返し、未完了の結果で後続処理を進めない
	if( FAILED( status)) {
		return static_cast<NativeError>( status) ;
	}

	const CRYPT_XML_DOC_CTXT *context{} ;	// Document handle lifetime中だけ有効な解析結果
	status = CryptXmlGetDocContext( document, &context) ;
	// 署名 context の取得失敗や単一署名の構造不成立時は document を解放する
	if( FAILED( status) || context == nullptr || context->cSignature != 1 ||
	   context->rgpSignature == nullptr || context->rgpSignature[0] == nullptr) {
		CryptXmlClose( document) ;
		return FAILED( status) ? static_cast<NativeError>( status)
							  : static_cast<NativeError>( TRUST_E_SUBJECT_FORM_UNKNOWN) ;
	}

	const CRYPT_XML_SIGNATURE &signature = *context->rgpSignature[0] ;	// 単一署名
	// 許可しない署名方式または reference 構造なら document を解放して拒否する
	if( !isAllowedXmlSignature( signature)) {
		CryptXmlClose( document) ;
		return static_cast<NativeError>( TRUST_E_SUBJECT_FORM_UNKNOWN) ;
	}

	PCCERT_CONTEXT certificate{} ;	// CertFreeCertificateContextで解放する署名certificate
	error = findXmlCertificate( signature, certificate) ;
	// Certificate 抽出に失敗した場合も XML document の所有資源を解放する
	if( error != 0) {
		CryptXmlClose( document) ;
		return error ;
	}

	BCRYPT_KEY_HANDLE key{} ;	// BCryptDestroyKeyで解放するcertificate公開鍵
	// Certificate の公開鍵を import できなければ、その失敗を保持する
	if( CryptImportPublicKeyInfoEx2( X509_ASN_ENCODING, &certificate->pCertInfo->SubjectPublicKeyInfo,
								   0, nullptr, &key) == FALSE) {
		error = nativeErrorFromWin32( GetLastError()) ;
	} else {
		XmlDataProviderState	providerState{.data		= bytes.data() + xmlOffset,
											  .size		= xmlBytes,
											  .position = 0} ;	// Enveloped transformへ渡す元文書状態
		CRYPT_XML_DATA_PROVIDER provider{.pvCallbackState = &providerState,
										 .cbBufferSize	  = 64U * 1024U,
										 .pfnRead		  = readXmlProvider,
										 .pfnClose = closeXmlProvider} ;	// 元文書の有限data provider
		status = CryptXmlDigestReference( signature.SignedInfo.rgpReference[0]->hReference, 0,
										 &provider) ;	// 文書全体referenceの再digest結果
		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない
		if( SUCCEEDED( status)) {
			status = CryptXmlVerifySignature( signature.hSignature, key,
											 CRYPT_XML_FLAG_DISABLE_EXTENSIONS) ;	// 署名検証結果
		}

		// XML 署名の検証 API が失敗した場合は HRESULT を保持する
		if( FAILED( status)) {
			error = static_cast<NativeError>( status) ;
		} else {
			CRYPT_XML_STATUS signatureStatus{} ;	// Digestと署名valueの詳細状態
			signatureStatus.cbSize = sizeof( signatureStatus) ;
			status				   = CryptXmlGetStatus( signature.hSignature, &signatureStatus) ;
			// 署名合格に必要なdigest整合とsignature検証の両status bit
			constexpr DWORD REQUIRED_STATUS =
				CRYPT_XML_STATUS_DIGEST_VALID | CRYPT_XML_STATUS_SIGNATURE_VALID ;
			// 署名状態の照会失敗、検証 error、必要な検証状態の不足を全て拒否する
			if( FAILED( status) || signatureStatus.dwErrorStatus != CRYPT_XML_STATUS_NO_ERROR ||
			   (signatureStatus.dwInfoStatus & REQUIRED_STATUS) != REQUIRED_STATUS) {
				error = FAILED( status) ? static_cast<NativeError>( status)
									   : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
			}
		}

		BCryptDestroyKey( key) ;
	}

	// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない
	if( error == 0) {
		// Chain検証結果
		error = verifyCodeSigningChain( *certificate, validationFiletime) ;
	}

	// 暗号学的検証に成功した場合だけ certificate の publisher 名を確認する
	if( error == 0) {
		std::wstring signerName ;	// 埋込みcertificateのsimple display name
		error = readCertificateName( *certificate, signerName) ;
		// 表示名を取得できた場合だけ許可 publisher との完全一致を調べる
		if( error == 0) {
			const bool accepted = std::any_of( acceptedPublishers.begin(), acceptedPublishers.end(),
											  [&signerName]( const std::wstring_view publisher) {
												  return publisherNamesEqual( signerName, publisher) ;
											  }) ; // 一致結果
			// XML 署名が有効でも許可 publisher に一致しなければ受理しない
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
 * @brief Metadata条件とAuthenticode publisherを一つの順序で検証する。Metadata条件とAuthenticode publisherを順番に検証する。不一致
 *        payloadへWinTrust処理を行わず、全条件をfail-closedにする
 * @param[in] path 検証するfileの絶対path
 * @param[in] metadataPolicy 親metadataが宣言したsize／SHA-256条件。 親metadataのsize／SHA-256条件
 * @param[in] acceptedPublishers 許可するcertificate simple display name群。 許可するpublisher表示名群
 * @return 全検証成功時は0、最初に失敗した検証のHRESULT bit pattern。 全検証成功時は0、最初の失敗時はHRESULT bit pattern
 */
//------------------------------------------------------------------------------
NativeError verifyOfficialFile( const std::wstring_view					path,
							   const OfficialFileMetadataPolicy		   &metadataPolicy,
							   const std::span<const std::wstring_view> acceptedPublishers)
{
	const NativeError metadataError =	// 親metadataとの完全一致結果
		verifyOfficialFileMetadata( path, metadataPolicy) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( metadataError != 0) {
		return metadataError ;
	}

	return verifyAuthenticodePublisher( path, acceptedPublishers) ;
}

namespace driver_package_signature_detail {
namespace {
// 製品とfixtureで部分混在しない固定Windows Authenticode ABIです
const AuthenticodeApi					NATIVE_AUTHENTICODE_API{&WinVerifyTrust,
												&CryptQueryObject,
												&CryptMsgGetParam,
												&CertFindCertificateInStore,
												&CertGetNameStringW,
												&CertFreeCertificateContext,
												&CryptMsgClose,
												&CertCloseStore,
												&CryptCATAdminEnumCatalogFromHash,
												&CryptCATCatalogInfoFromContext,
												&CryptCATAdminReleaseCatalogContext} ;
// 同MTAにだけ生存する内部scopeです。製品経路は常にnullです
thread_local ScopedAuthenticodeFixture *activeAuthenticode = nullptr ;
}
//------------------------------------------------------------------------------
/**
 * @brief 完全な内部表だけを同threadへ固定します
 * @param[in] api 欠損を持たない内部Windows ABI表です
 */
//------------------------------------------------------------------------------
ScopedAuthenticodeFixture::ScopedAuthenticodeFixture( const AuthenticodeApi api) noexcept : api_( api)
{
	activeAuthenticode = this ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同threadの表を解除し、native backendを汚染しません
 */
//------------------------------------------------------------------------------
ScopedAuthenticodeFixture::~ScopedAuthenticodeFixture() noexcept
{
	// 同threadへ固定した元scopeだけを解除します
	if( activeAuthenticode == this) {
		activeAuthenticode = nullptr ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 製品は固定native、内部scopeは欠損のない元ABIへ戻します
 * @return 同threadの不変低位表です。部分的なnative fallbackはありません
 */
//------------------------------------------------------------------------------
const AuthenticodeApi &authenticodeApi() noexcept
{
	return activeAuthenticode ? activeAuthenticode->api() : NATIVE_AUTHENTICODE_API ;
}
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
//------------------------------------------------------------------------------
/**
 * @brief 参考SYSTEM INFの実local CAT/原hash/cache-only trust/権限を非実行検証します
 * @param[in] path 明示したWindows参考INFの通常絶対位置です
 * @param[out] evidence 実成功時だけの元file/CAT/SD tupleです
 * @param[out] stage 任意の固定検証地点です。合否に使用しません
 * @return 全成立0、元API/署名/権限errorです
 * @note PEの署名方式選択を変更せず、この内部入口はCAT-only参考corpusだけへ使用します
 */
//------------------------------------------------------------------------------
NativeError Access::verifySystemCatalogFile( std::wstring_view		path,
											WindowsSystemFileTrust &evidence, std::uint32_t *stage)
{
	return verifyWindowsSystemFileImpl( path, evidence, stage, false) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原CATの全memberと正確なWindows publisherをcache-onlyで確認します
 * @param[in] catalog 原CATの完全位置です
 * @param[in] members 同CATへ結ぶ全実member位置です
 * @return 全成立0、元member/hash/trust/publisherのHRESULTです
 * @note test/probe専用であり通常CAT APIのpolicyは変更しません
 */
//------------------------------------------------------------------------------
NativeError Access::verifyWindowsCatalogMembers( std::wstring_view			  catalog,
												std::span<const std::wstring> members)
{
	const auto error =
		// 同memberの実trustです
		verifyCatalogMembersWithPolicy( catalog, members, true) ;
	// 元trust失敗後にpublisherや別方式へ進みません
	if( error != 0U) {
		return error ;
	}

	std::wstring publisher ;										// 同CATの先頭署名です
	const auto	 read = readSignerName( catalog, publisher, true) ;	// 同元CATの実certificateです
	return read != 0U ? read
		   : publisherNamesEqual( publisher, L"Microsoft Windows")
			   ? 0U
			   : static_cast<NativeError>( TRUST_E_SUBJECT_NOT_TRUSTED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 完全低位Authenticode表を同workerへ固定します
 * @param[in] api 全八ABIが揃った内部表です。外部設定は受理しません
 * @return 完全表だけの単独scope、不足または別scope存在時nullptrです
 */
//------------------------------------------------------------------------------
std::unique_ptr<ScopedAuthenticodeFixture> Access::createAuthenticode( const AuthenticodeApi api)
{
	// 欠損表や別scopeの上書きでnativeを部分利用しません
	if( activeAuthenticode || !api.verify || !api.query || !api.messageParameter ||
	   !api.findCertificate || !api.certificateName || !api.freeCertificate || !api.closeMessage ||
	   !api.closeStore) {
		return nullptr ;
	}

	return std::unique_ptr<ScopedAuthenticodeFixture>{new ScopedAuthenticodeFixture( api)} ;
}
#endif
// Worker threadの同期scopeだけへ固定する完全fixture。製品は常にnullptrです
thread_local ScopedFixture *activeFixture = nullptr ;

//------------------------------------------------------------------------------
/**
 * @brief 内部署名fixtureの相対member名を安全な全segmentへ限定します
 * @param[in] name 補正せず同期検査する元相対名です
 * @return 全segmentが非空で絶対・traversal・不正文字を持たない場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool			validFixtureRelativeName( std::wstring_view name) noexcept
{
	std::size_t beginning{} ;	// 原segmentの開始位置です
	// 有限な元名の全segmentを読み、最初の不正または終端で終了します
	while( beginning < name.size()) {
		const auto separator = name.find( L'\\', beginning) ;					// Windowsの単一相対区切りです
		const auto ending  = separator == name.npos ? name.size() : separator ;	// 元segment終端です
		const auto segment = name.substr( beginning, ending - beginning) ;		// 同元値の借用です
		// 補正後の別pathを同じfixture memberへ変換しません
		if( segment.empty() || segment.size() > 255U || segment == L"." || segment == L".." ||
		   segment.back() == L'.' || segment.back() == L' ' ||
		   segment.find_first_of( L"<>/%:\"|?*") != segment.npos ||
		   std::ranges::any_of( segment,
							   []( wchar_t value) { return value < L' ' || value > L'~' ; })) {
			return false ;
		}

		const auto stem		= segment.substr( 0U, segment.find( L'.')) ;	// 原ASCII stemの同期借用です
		const auto reserved = [stem]( std::wstring_view value) {
			return CompareStringOrdinal( stem.data(), static_cast<int>( stem.size()), value.data(),
										static_cast<int>( value.size()), TRUE) == CSTR_EQUAL ;
		} ; // 有限ASCII stemだけを同呼出し中に比較し、captureを保存しません
		// Windows予約device名を相対member許可へ含めません
		if( reserved( L"CON") || reserved( L"PRN") || reserved( L"AUX") || reserved( L"NUL") ||
		   (stem.size() == 4U && stem[3U] >= L'1' && stem[3U] <= L'9' &&
			(CompareStringOrdinal( stem.data(), 3, L"COM", 3, TRUE) == CSTR_EQUAL ||
			 CompareStringOrdinal( stem.data(), 3, L"LPT", 3, TRUE) == CSTR_EQUAL))) {
			return false ;
		}

		// 全文終端だけを正常な相対名として確定します
		if( separator == name.npos) {
			return true ;
		}

		beginning = separator + 1U ;
	}

	return false ;
}

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 元人工memberが明示したINF ownerだけを比較します
 * @param[in] file 元raw hashを保持する人工memberです
 * @param[in] owner 同scopeの実INF名です
 * @return 単独owner又はshared CATの明示aliasに完全一致する場合trueです
 * @note aliasを実製品の署名/用途/権限へ変換しません
 */
//------------------------------------------------------------------------------
static bool fixtureOwner( const FixtureFile &file, std::wstring_view owner)
{
	return file.infOwner == owner ||
		   std::ranges::find( file.additionalInfOwners, owner) != file.additionalInfOwners.end() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実fileが同rootの完全member名と原raw SHAへ一致するか確認します
 * @param[in] files 完全な元期待集合です
 * @param[in] path 同保護領域の実絶対pathです
 * @param[in] root 元INFで固定した区切り込みrootです
 * @return 同memberの全raw byte一致時trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchesFixtureFile( const std::vector<FixtureFile> &files,
									  const std::wstring_view path, const std::wstring_view root)
{
	// 区切り込みの同root外や未知fileを成功する低位APIへ渡しません
	if( root.size() < 4U || root.back() != L'\\' || !path.starts_with( root)) {
		return false ;
	}

	const auto	 name  = path.substr( root.size()) ;	// 元fixtureの完全な相対位置です
	const auto	 found = std::find_if( files.begin(), files.end(), [name]( const FixtureFile &file) {
		  return file.name == name ;
	  }) ;			   // 未登録名をnativeへfallbackしないための固定集合検索
	std::wstring hash ;	// 取得済み実fileのSHA-256
	return found != files.end() && computeFileSha256( path, hash) == 0 && hash == found->sha256 ;
}

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
/**
 * @brief 原raw hash確認後の人工fileだけからWindowsのcatalog digestを独立計算します
 * @param[in] path 固定人工scopeが原byteを照合済みのmemberです
 * @param[out] hash SHA256 catalog digestの全小文字hexです。失敗時空です
 * @return 元Windows digest APIの全成功時trueです
 * @note PEのcatalog digestとfile全体SHAを混同せず、署名/由来/導入成功を生成しません
 */
//------------------------------------------------------------------------------
static bool syntheticCatalogDigest( std::wstring_view path, std::wstring &hash)
{
	hash.clear() ;
	// 同同期で使用する所有catalog digest contextです
	CatalogHashContext			   context ;
	// 元byteを同期中だけ保持する読取専用fileです
	const ReadOnlyVerificationFile file( CreateFileW( std::wstring{path}.c_str(), GENERIC_READ,
													FILE_SHARE_READ, nullptr, OPEN_EXISTING,
													FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;
	// Windowsが返した原catalog digestの全byteです
	std::vector<BYTE>			   digest ;
	// 不正PEや元API失敗をraw digestへfallbackしません
	if( file.get() == INVALID_HANDLE_VALUE ||
	   context.initialize( BCRYPT_SHA256_ALGORITHM, 32U) != 0U ||
	   context.calculateHash( file.get(), digest) != 0U || digest.size() != 32U) {
		return false ;
	}

	// 原digestをlosslessに表す小文字hex字句です
	constexpr std::wstring_view HEX = L"0123456789abcdef" ;
	// Windowsが返した全digestをlosslessに保持します
	for( const auto byte : digest) {
		hash.push_back( HEX[byte >> 4U]) ;
		hash.push_back( HEX[byte & 15U]) ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元人工scopeの全raw byteを再照合してcatalog digest集合を作ります
 * @param[in] path 同元CATの完全位置です
 * @param[out] hashes 全raw byte確認後のWindows catalog SHA256だけです
 * @return 同固定scope/元owner/全byteが成立した場合trueです
 * @note native adapter又は製品CATへ適用しません
 */
//------------------------------------------------------------------------------
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
bool readSyntheticCatalogDigests( const std::wstring_view	path,
								 std::vector<std::wstring> &hashes) noexcept
{
	hashes.clear() ;
	// 通常製品と明示native adapterには実CAT readerだけを使用します
	if( activeFixture == nullptr || activeFixture->nativeAdapter_) {
		return false ;
	}

	auto &fixture = *activeFixture ;	// 同threadの既存人工scopeだけです
	try {
		const auto separator = path.find_last_of( L'\\') ;	// 元CATの完全root境界です
		// 相対pathや不完全rootを人工集合へ採用しません
		if( separator == path.npos) {
			return false ;
		}

		const auto root =
			// SetupVerifyInf相当が確認済みのrootです
			path.substr( 0U, separator + 1U) ;
		const auto name	   = path.substr( separator + 1U) ;	// 同元CATの相対名です
		const auto catalog = std::ranges::find_if( fixture.files_, [name]( const auto &file) {
			// 元完全名だけを照合します
			return file.name == name && file.name.ends_with( L".cat") ;
		}) ;
		// 同scopeの元CAT byteを現在も保持する必要があります
		if( catalog == fixture.files_.end() || !matchesFixtureFile( fixture.files_, path, root)) {
			return false ;
		}

		std::size_t index{} ;	// 元SetupVerifyInfが確認したroot-owner組を検索します
		// 同rootの別INF-ownerの署名を今回へ流用しません
		while( index < fixture.roots_.size() &&
			  (fixture.roots_[index] != root ||
			   !fixtureOwner( *catalog, fixture.rootOwners_[index]))) {
			++index ;
		}

		// 確認前のscopeからCAT成功を生成しません
		if( index == fixture.roots_.size()) {
			return false ;
		}

		// 同ownerの全実byteを再確認し、元固定hashだけを人工宣言へ渡します
		for( const auto &file : fixture.files_) {
			// 別ownerの内容を今回のCATへ含めません
			if( !fixtureOwner( *catalog, file.infOwner)) {
				continue ;
			}

			// 改変後のfileを旧成功rootだけで受理しません
			if( !matchesFixtureFile( fixture.files_, std::wstring( root) + file.name, root)) {
				hashes.clear() ;
				return false ;
			}

			// CAT自体はmemberではなく、固定された原署名fixtureの所有者です
			if( !file.name.ends_with( L".cat")) {
				// Windowsが返した原catalog digestの全byteです
				std::wstring digest ;
				// 正当なPEでもraw hashをcatalog tagへ置換しません
				if( !syntheticCatalogDigest( std::wstring{root} + file.name, digest)) {
					hashes.clear() ;
					return false ;
				}

				hashes.push_back( std::move( digest)) ;
			}
		}

		return !hashes.empty() ;
	} catch( ...) {
		++fixture.receipt_.rejectedCalls ;
		hashes.clear() ;
		return false ;
	}
}
#endif

//------------------------------------------------------------------------------
/**
 * @brief 内部factoryだけが既存native署名への委譲scopeを作ります
 */
//------------------------------------------------------------------------------
ScopedFixture::ScopedFixture() noexcept : nativeAdapter_( true)
{
	activeFixture = this ;
}
//------------------------------------------------------------------------------
/**
 * @brief 完全な固定file集合だけを所有します
 * @param[in] files INF/CATと参照fileの固定hash集合
 * @param[in] maximumRoots 固定集合を許す保護root-INF-owner組数。内部factoryだけが1～129を指定します
 */
//------------------------------------------------------------------------------
ScopedFixture::ScopedFixture( std::vector<FixtureFile> files, const std::size_t maximumRoots)
	: files_( std::move( files)), maximumRoots_( maximumRoots)
{
	roots_.reserve( maximumRoots_) ;
	rootOwners_.reserve( maximumRoots_) ;
	activeFixture = this ;
}
//------------------------------------------------------------------------------
/**
 * @brief 本threadのfixtureを解除します
 */
//------------------------------------------------------------------------------
ScopedFixture::~ScopedFixture() noexcept
{
	// Scopeを使った同workerだけから解除し、別scopeを上書きしません
	if( activeFixture == this) {
		activeFixture = nullptr ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 秘密pathを含まない呼出し件数を返します
 * @return Scope中だけ有効な有限receipt
 */
//------------------------------------------------------------------------------
Receipt ScopedFixture::receipt() const noexcept
{
	auto result			   = receipt_ ;	// Call数と実閉包root数を別の観測として返します
	result.inspectionRoots = roots_.size() ;
	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief 製品は固定native、内部scopeは実hash fixtureまたは明示native adapterへdispatchします
 * @param[in] path 実INF絶対path
 * @param[in] platform Windowsのplatform条件
 * @param[out] signer Windows標準のCAT/signature出力
 * @return 署名API成功TRUE、拒否FALSE
 */
//------------------------------------------------------------------------------
BOOL setupVerifyInf( const PCWSTR path, const PSP_ALTPLATFORM_INFO platform,
					const PSP_INF_SIGNER_INFO_W signer) noexcept
{
	// 製品wrapperは外部入力を受けない固定Windows APIだけを使用します
	if( activeFixture == nullptr) {
		return SetupVerifyInfFileW( path, platform, signer) ;
	}

	auto &fixture = *activeFixture ;	// 同worker lifetimeの完全な固定表
	++fixture.receipt_.setupCalls ;
	// 明示内部adapterは元APIの成否/診断/publisherをそのまま返します
	if( fixture.nativeAdapter_ && !fixture.originalAdapter_) {
		return SetupVerifyInfFileW( path, platform, signer) ;
	}

	try {
		// 原archiveの明示bootstrapは実INF hashと宣言CATの実cache-only検証を必要とします
		if( fixture.originalAdapter_) {
			// 任意path/別platform/不完全出力を実nativeへ補完しません
			if( !path || platform || !signer || signer->cbSize != sizeof( *signer)) {
				SetLastError( ERROR_INVALID_PARAMETER) ;
				return FALSE ;
			}

			const std::filesystem::path infPath{path} ;	// 同保護閉包の実位置です
			const auto					found =
				std::ranges::find(	// この同期だけで保持する元値です。許可の代用にしません
					fixture.originalInfs_, infPath.filename().wstring(),
					&OriginalInfMetadata::infName) ;
			std::wstring hash ;	// 署名位置metadataを原byteへ束縛します
			// 元選択INF以外や同名改変を信頼しません
			if( found == fixture.originalInfs_.end() || computeFileSha256( path, hash) != 0U ||
			   hash != found->infSha256) {
				SetLastError( ERROR_INVALID_DATA) ;
				return FALSE ;
			}

			const auto catalog =
				(infPath.parent_path() / found->catalogName).wstring() ;	// 同原CATだけです
			const std::array<std::wstring, 1U> member{
				path} ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
			const auto error =
				// 元算法/強度/chainです
				verifyCatalogMembersWithPolicy( catalog, member, true) ;
			// 実trust失敗をmetadata成功へ変換しません
			if( error != 0U || catalog.size() >= MAX_PATH) {
				SetLastError( error != 0U ? static_cast<DWORD>( error) : ERROR_BUFFER_OVERFLOW) ;
				return FALSE ;
			}

			wcscpy_s( signer->CatalogFile, catalog.c_str()) ;
			wcscpy_s( signer->DigitalSigner, L"Original CAT verified; metadata bootstrap") ;
			signer->SignerScore = 0U ;
			return TRUE ;
		}

		// 不完全な署名API入力や未登録・改変INFを合格へ変換しません
		if( path == nullptr || platform != nullptr || signer == nullptr ||
		   signer->cbSize != sizeof( *signer)) {
			++fixture.receipt_.rejectedCalls ;
			SetLastError( ERROR_ACCESS_DENIED) ;
			return FALSE ;
		}

		const std::wstring inf( path) ;							// 成功APIへ結合する実INF path
		const auto		   slash = inf.find_last_of( L"\\/") ;	// 同保護閉包のroot
		// 絶対INFの親境界がない入力から保護rootを作りません
		if( slash == std::wstring::npos || slash < 3U) {
			++fixture.receipt_.rejectedCalls ;
			SetLastError( ERROR_ACCESS_DENIED) ;
			return FALSE ;
		}

		const auto root	   = inf.substr( 0U, slash + 1U) ;	// CATを別directoryから選びません
		const auto infName = inf.substr( slash + 1U) ;		// 基本INFの実basenameです
		const auto infEntry =
			std::ranges::find_if( fixture.files_, [&infName]( const FixtureFile &file) {
				return file.name == infName && file.name.ends_with( L".inf") ;
			}) ; // 完全表にある基本INFだけをrootへ結びます
		// SYSやCATを基本INFとして照合させた入力を拒否します
		if( infEntry == fixture.files_.end() || !matchesFixtureFile( fixture.files_, inf, root)) {
			++fixture.receipt_.rejectedCalls ;
			SetLastError( ERROR_ACCESS_DENIED) ;
			return FALSE ;
		}

		const auto owner   = infEntry->infOwner ;	// 旧単一集合は空、複数集合はexact INF名です
		const auto catalog = std::find_if(
			fixture.files_.begin(), fixture.files_.end(), [&owner]( const FixtureFile &file) {
				return fixtureOwner( file, owner) && file.name.ends_with( L".cat") ;
			}) ;					 // 一意固定CAT
		std::size_t rootIndex{} ;	// 同rootと元INF ownerの完全な組を検索します
		// 同directoryの別CATを既存ownerの署名へ転用しません
		while( rootIndex < fixture.roots_.size() &&
			  (fixture.roots_[rootIndex] != root || fixture.rootOwners_[rootIndex] != owner)) {
			++rootIndex ;
		}

		const bool knownRoot = rootIndex < fixture.roots_.size() ;	// 完全なroot-owner組です
		// 同閉包の完全file集合と有限root枠を満たさなければ成功値を返しません
		if( catalog == fixture.files_.end() ||
		   !matchesFixtureFile( fixture.files_, root + catalog->name, root) ||
		   (!knownRoot && fixture.roots_.size() >= fixture.maximumRoots_) ||
		   !std::ranges::all_of( fixture.files_,
								[&]( const FixtureFile &file) {
									return !fixtureOwner( file, owner) ||
										   matchesFixtureFile( fixture.files_, root + file.name,
															  root) ;
								}) ||
		   root.size() + catalog->name.size() >= MAX_PATH) {
			++fixture.receipt_.rejectedCalls ;
			SetLastError( ERROR_ACCESS_DENIED) ;
			return FALSE ;
		}

		// 全memberの実hashを確認した新rootだけを有限集合へ固定します
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
//------------------------------------------------------------------------------
/**
 * @brief 同member/tag/policyのVERIFYとCLOSEを同じbackendで処理します
 * @param[in] window 親window。内部fixtureはnullptrだけを受理します
 * @param[in] action Windows標準policy GUID
 * @param[in,out] data 完全なWINTRUST_DATA
 * @return 検証成功0、それ以外は元trust error
 */
//------------------------------------------------------------------------------
LONG verifyTrust( const HWND window, GUID *const action, LPVOID const data) noexcept
{
	// 製品は同じ固定native関数でVERIFYとCLOSEを処理します
	if( activeFixture == nullptr) {
		return WinVerifyTrust( window, action, data) ;
	}

	auto &fixture = *activeFixture ;	// 現workerだけのfixture
	// 元Windows policy/flagsを変更せず、同VERIFY/CLOSEをnativeへ委譲します
	if( fixture.nativeAdapter_) {
		const auto *trust = static_cast<const WINTRUST_DATA *>( data) ;	// 元ABIの同期観測だけです
		// CLOSE以外をVERIFY側へ数え、元APIへ返す入力/出力は変更しません
		if( trust && trust->cbStruct == sizeof( *trust) &&
		   trust->dwStateAction == WTD_STATEACTION_CLOSE) {
			++fixture.receipt_.closeCalls ;
		} else {
			++fixture.receipt_.verifyCalls ;
		}

		// 原archive内部資格だけは通常policyを保ち追加の通信を禁止します
		if( fixture.originalAdapter_ && trust && trust->cbStruct == sizeof( *trust)) {
			auto	  *mutableTrust = static_cast<WINTRUST_DATA *>( data) ;	// 同同期ABIの借用です
			const auto flags		= mutableTrust->dwProvFlags ;			// 元caller値を終了時に戻します
			mutableTrust->dwProvFlags |= WTD_CACHE_ONLY_URL_RETRIEVAL ;
			const auto result =
				// 同原文/操作へ結ぶ検査又は結果の所有値です
				WinVerifyTrust( window, action, data) ;
			mutableTrust->dwProvFlags = flags ;
			return result ;
		}

		return WinVerifyTrust( window, action, data) ;
	}

	try {
		// 型なしWindows ABI境界でだけWINTRUST_DATAの実型へ戻します
		auto *const trust		   = static_cast<WINTRUST_DATA *>( data) ;	// 呼出し中だけ有効な設定
		const GUID	expectedAction = WINTRUST_ACTION_GENERIC_VERIFY_V2 ;	// 製品と同じ元policyです
		// 不足・別policy・別CAT・別member/tagを成功へ補完しません
		if( window != nullptr || action == nullptr || *action != expectedAction ||
		   trust == nullptr || trust->cbStruct != sizeof( *trust) ||
		   trust->dwUIChoice != WTD_UI_NONE ||
		   trust->fdwRevocationChecks != WTD_REVOKE_WHOLECHAIN ||
		   trust->dwUnionChoice != WTD_CHOICE_CATALOG || trust->pCatalog == nullptr ||
		   trust->dwProvFlags != WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT) {
			++fixture.receipt_.rejectedCalls ;
			return TRUST_E_SUBJECT_NOT_TRUSTED ;
		}

		const auto *settings = trust->pSignatureSettings ;	// 外側署名の元強度policyです
		const auto *policy =
			// 同同期の借用値です
			settings == nullptr ? nullptr : settings->pCryptoPolicy ;
		// 人工scopeも原current強度の省略・差替えを成功へ補正しません
		if( settings == nullptr || settings->cbStruct != sizeof( *settings) || policy == nullptr ||
		   policy->cbSize != sizeof( *policy) ||
		   policy->dwInfoChoice != CERT_STRONG_SIGN_OID_INFO_CHOICE || policy->pszOID == nullptr ||
		   std::strcmp( policy->pszOID, szOID_CERT_STRONG_SIGN_OS_CURRENT) != 0) {
			++fixture.receipt_.rejectedCalls ;
			return TRUST_E_SUBJECT_NOT_TRUSTED ;
		}

		const auto	&catalog = *trust->pCatalog ;	// 元共通処理が計算した実member hashとtag
		std::wstring hash ;							// 実member原byteの独立SHA-256
		// 必須ABI値を確認し、未確認rootのmember byteを読みません
		if( catalog.cbStruct != sizeof( catalog) || catalog.pcwszCatalogFilePath == nullptr ||
		   catalog.pcwszMemberFilePath == nullptr || catalog.pcwszMemberTag == nullptr ||
		   catalog.hMemberFile == INVALID_HANDLE_VALUE || catalog.hMemberFile == nullptr ||
		   catalog.hCatAdmin == nullptr || catalog.cbCalculatedFileHash != 32U ||
		   catalog.pbCalculatedFileHash == nullptr) {
			++fixture.receipt_.rejectedCalls ;
			return TRUST_E_SUBJECT_NOT_TRUSTED ;
		}

		const std::wstring_view catalogPath{catalog.pcwszCatalogFilePath} ;	// 同CATの実pathです
		const std::wstring_view memberPath{catalog.pcwszMemberFilePath} ;	// 同memberの実pathです
		const auto				catalogRoot =
			// 親rootです
			catalogPath.substr( 0U, catalogPath.find_last_of( L"\\/") + 1U) ;
		// 同登録root以下の完全相対memberだけをCATへ結び、basename一致を使いません
		if( std::ranges::find( fixture.roots_, catalogRoot) == fixture.roots_.end() ||
		   !memberPath.starts_with( catalogRoot) ||
		   !matchesFixtureFile( fixture.files_, catalogPath, catalogRoot) ||
		   !matchesFixtureFile( fixture.files_, memberPath, catalogRoot) ||
		   computeFileSha256( catalog.pcwszMemberFilePath, hash) != 0) {
			++fixture.receipt_.rejectedCalls ;
			return TRUST_E_SUBJECT_NOT_TRUSTED ;
		}

		const auto memberName =
			// 同閉包の完全相対member名です
			memberPath.substr( catalogRoot.size()) ;
		const auto catalogName	= catalogPath.substr( catalogRoot.size()) ;	// 同閉包のCAT名です
		const auto catalogEntry = std::ranges::find_if( fixture.files_, [&]( const auto &file) {
			return file.name == catalogName && file.name.ends_with( L".cat") ;
		}) ; // 元CAT名と元INF ownerを完全な表へ固定します
		// 未登録CATの名前からownerを作りません
		if( catalogEntry == fixture.files_.end()) {
			++fixture.receipt_.rejectedCalls ;
			return TRUST_E_SUBJECT_NOT_TRUSTED ;
		}

		// 当該CAT検査の元完全member期待値です
		const auto memberEntry = std::ranges::find_if(
			fixture.files_, [&]( const auto &file) { return file.name == memberName ; }) ;
		// shared CATでも実memberの元INF ownerを消しません
		if( memberEntry == fixture.files_.end() ||
		   !fixtureOwner( *catalogEntry, memberEntry->infOwner)) {
			++fixture.receipt_.rejectedCalls ;
			return TRUST_E_SUBJECT_NOT_TRUSTED ;
		}

		const auto &owner = memberEntry->infOwner ;	// 同元memberだけの元INFです
		std::size_t rootIndex{} ;					// setupVerifyInfが確認したroot-owner組です
		// 同directoryの別ownerの確認を今回のCATへ流用しません
		while( rootIndex < fixture.roots_.size() && (fixture.roots_[rootIndex] != catalogRoot ||
													fixture.rootOwners_[rootIndex] != owner)) {
			++rootIndex ;
		}

		// 元INFと全memberを確認した組だけを署名低位正例にします
		if( rootIndex == fixture.roots_.size()) {
			++fixture.receipt_.rejectedCalls ;
			return TRUST_E_SUBJECT_NOT_TRUSTED ;
		}

		// 別INF集合のfileを同rootの署名へ紐付けません
		if( !std::ranges::any_of( fixture.files_,
								[&]( const FixtureFile &file) {
									return fixtureOwner( file, owner) && file.name == memberName ;
								}) ||
		   !std::ranges::any_of( fixture.files_, [&]( const FixtureFile &file) {
			   return fixtureOwner( file, owner) && file.name == catalogName &&
					  file.name.ends_with( L".cat") ;
		   })) {
			++fixture.receipt_.rejectedCalls ;
			return TRUST_E_SUBJECT_NOT_TRUSTED ;
		}

		std::wstring				actualHash ;				// Common catalog APIの32byteをhexへ独立射影します
		constexpr std::wstring_view HEX = L"0123456789abcdef" ;	// 正規小文字表現
		// 全32byteを照合し、tagだけの一致を実hash一致へ読み替えません
		for( DWORD index = 0U; index < 32U; ++index) {
			actualHash.push_back( HEX[catalog.pbCalculatedFileHash[index] >> 4U]) ;
			actualHash.push_back( HEX[catalog.pbCalculatedFileHash[index] & 15U]) ;
		}

		std::wstring expectedCatalogHash ;	// 原rawbyteは上で固定し、CAT digestを別に比較します
		// 原raw byteとは別のcatalog digestが成立しなければ低位trustを拒否します
		if( !syntheticCatalogDigest( memberPath, expectedCatalogHash)) {
			++fixture.receipt_.rejectedCalls ;
			return TRUST_E_BAD_DIGEST ;
		}

		std::wstring uppercase = expectedCatalogHash ;	// WinTrust tagはuppercase exact hexです
		std::transform( uppercase.begin(), uppercase.end(), uppercase.begin(), []( wchar_t value) {
			return static_cast<wchar_t>( value >= L'a' && value <= L'f' ? value - L'a' + L'A'
																	   : value) ;
		}) ;
		// 元file hash、API計算hashとtagの三値を一致させます
		if( expectedCatalogHash != actualHash || uppercase != catalog.pcwszMemberTag) {
			++fixture.receipt_.rejectedCalls ;
			return TRUST_E_SUBJECT_NOT_TRUSTED ;
		}

		// VERIFYとCLOSEの一対一を同じ実memberへ固定します
		if( trust->dwStateAction == WTD_STATEACTION_VERIFY && fixture.pendingMember_.empty()) {
			fixture.pendingMember_ = catalog.pcwszMemberFilePath ;
			++fixture.receipt_.verifyCalls ;
			return ERROR_SUCCESS ;
		}

		// 成功VERIFYの同memberだけをCLOSEし、未知のCLOSEを受理しません
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
// 完全な内部factoryだけをtest構成に含め、製品設定から取得しません
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
//------------------------------------------------------------------------------
/**
 * @brief 元Windows署名APIへそのまま委譲する内部scopeを作ります
 * @return 同threadに既存scopeがなければ単独所有adapter、それ以外はnullptrです
 * @note 成功値/publisher/検証policyを補完せず、証明書通信を含む元APIの動作を保持します。公開JSON/成功bool/鍵を受けず、実inventoryや取得・導入能力を発行
 *       しません
 */
//------------------------------------------------------------------------------
std::unique_ptr<ScopedFixture> Access::createNativeAdapter()
{
	// 生存する元scopeを別backendへ切り替えません
	if( activeFixture != nullptr) {
		return nullptr ;
	}

	return std::unique_ptr<ScopedFixture>{new ScopedFixture{}} ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元INF hash/CAT位置と実cache-only trustだけの内部adapterを作ります
 * @param[in] infs 同原archive由来の一意なINF名/完全hash/CAT名です。最大八件です
 * @return 完全表/非再入時のscope、不正入力時nullptrです
 * @note INF metadataとscoreは人工bootstrapで、CAT/member/chainは実cache-only nativeです。実SetupVerifyInfFileへfallbackしません
 */
//------------------------------------------------------------------------------
std::unique_ptr<ScopedFixture> Access::createOriginalAdapter( std::vector<OriginalInfMetadata> infs)
{
	// 私有原入力の有限件数以外を汎用署名APIへ変換しません
	if( activeFixture || infs.empty() || infs.size() > 8U) {
		return nullptr ;
	}

	std::vector<std::wstring> names ;	// 一意な元INF名だけです
	// 全basename/hashを確認し、先頭正常だけで表を発行しません
	for( const auto &inf : infs) {
		// 親path/stream/不正digest/重複を原metadataへ受理しません
		if( inf.infName.empty() || inf.catalogName.empty() || inf.infSha256.size() != 64U ||
		   inf.infName.find_first_of( L"\\/:") != std::wstring::npos ||
		   inf.catalogName.find_first_of( L"\\/:") != std::wstring::npos ||
		   inf.infName.size() < 5U || inf.catalogName.size() < 5U ||
		   CompareStringOrdinal( inf.infName.data() + inf.infName.size() - 4U, 4, L".inf", 4,
								TRUE) != CSTR_EQUAL ||
		   CompareStringOrdinal( inf.catalogName.data() + inf.catalogName.size() - 4U, 4, L".cat", 4,
								TRUE) != CSTR_EQUAL ||
		   inf.infName.find( L'\0') != inf.infName.npos ||
		   inf.catalogName.find( L'\0') != inf.catalogName.npos ||
		   !std::ranges::all_of(
			   inf.infSha256,
			   []( wchar_t c) { return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') ; }) ||
		   std::ranges::any_of( names, [&]( const auto &name) {
			   return CompareStringOrdinal( name.c_str(), -1, inf.infName.c_str(), -1, TRUE) ==
					  CSTR_EQUAL ;
		   })) {
			return nullptr ;
		}

		names.push_back( inf.infName) ;
	}

	auto scope =
		std::unique_ptr<ScopedFixture>{new ScopedFixture{}} ;	// native trustだけの既scopeです
	scope->originalAdapter_ = true ;
	scope->originalInfs_	= std::move( infs) ;
	return scope ;
}
//------------------------------------------------------------------------------
/**
 * @brief 未登録file・未知hash・重複を拒否して本worker lifetimeへ固定します
 * @param[in] files 直下INF/CATと安全相対参照memberの完全な原byte hash。最大387file／129INFです
 * @param[in] maximumRoots 完全なroot-INF-owner組の数。1～129だけを受理します
 * @return 完全集合の場合だけscope。任意の署名合格boolを受理しません
 */
//------------------------------------------------------------------------------
std::unique_ptr<ScopedFixture> Access::create( std::vector<FixtureFile> files,
											  const std::size_t		   maximumRoots)
{
	// 同workerの既存scopeを上書きしません
	if( activeFixture != nullptr || files.size() < 2U || files.size() > 387U || maximumRoots == 0U ||
	   maximumRoots > 129U) {
		return nullptr ;
	}

	std::size_t catalogs{} ;	// 完全な一CATの期待数
	std::size_t infs{} ;		// 初回単一基本INFの期待数
	// 全期待memberを有限・一意にし、不完全表をnativeへ補完しません
	for( std::size_t index = 0U; index < files.size(); ++index) {
		const auto &file = files[index] ;	// 元fixture byteの一member
		// 不正segment・subdir INF/CAT・不正hash・重複memberをfactory生成前に拒否します
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

	// 内部試験だけで128正常と129全体拒否の全閉包を固定し、各基本INFへ一CATを要求します
	if( infs == 0U || infs > 129U || catalogs == 0U || catalogs > infs) {
		return nullptr ;
	}

	// 全memberのownerは存在する基本INFへ結び、不明依存を空集合へ補完しません
	for( const auto &file : files) {
		const auto owner	= file.infOwner ;	// 登録前の完全閉包名です
		const auto ownerInf = std::ranges::find_if( files, [&owner]( const FixtureFile &entry) {
			return entry.name.ends_with( L".inf") && (owner.empty() || entry.name == owner) &&
				   entry.infOwner == owner ;
		}) ; // 存在する基本INFへだけmemberを結ぶ照合結果です
		// 旧空ownerは単一INFに限り、複数閉包はexact基本INF名を必要とします
		if( ownerInf == files.end() || (owner.empty() && infs != 1U) ||
		   (file.name.ends_with( L".inf") && !owner.empty() && file.name != owner) ||
		   std::ranges::count_if( files, [&owner]( const FixtureFile &entry) {
			   return fixtureOwner( entry, owner) && entry.name.ends_with( L".cat") ;
		   }) != 1) {
			return nullptr ;
		}

		// 追加ownerはshared CATの元実INFへだけ明示できます。未知/重複を補完しません
		if( !file.additionalInfOwners.empty() &&
		   (!file.name.ends_with( L".cat") || file.additionalInfOwners.size() > 7U)) {
			return nullptr ;
		}

		// shared CATが明示する全INF ownerを個別に検査します
		for( std::size_t ordinal = 0U; ordinal < file.additionalInfOwners.size(); ++ordinal) {
			// shared CATが明示する一つの追加INF ownerです
			const auto &alias = file.additionalInfOwners[ordinal] ;
			// 未知/重複/自己aliasをCAT所有証拠へ取り込みません
			if( alias.empty() || alias == owner ||
			   std::ranges::find( file.additionalInfOwners.begin(),
								 file.additionalInfOwners.begin() +
									 static_cast<std::ptrdiff_t>( ordinal),
								 alias) !=
				   file.additionalInfOwners.begin() + static_cast<std::ptrdiff_t>( ordinal) ||
			   std::ranges::none_of( files, [&]( const auto &entry) {
				   return entry.name == alias && entry.name.ends_with( L".inf") &&
						  entry.infOwner == alias ;
			   })) {
				return nullptr ;
			}
		}
	}

	return std::unique_ptr<ScopedFixture>{new ScopedFixture( std::move( files), maximumRoots)} ;
}
#endif
} // namespace driver_package_signature_detail
} // namespace drivercrate
