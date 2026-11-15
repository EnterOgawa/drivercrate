//------------------------------------------------------------------------------
/**
 * @file official_catalog_algorithm_tests.cpp
 * @brief CAT宣言算法の非通信境界と明示された原CATを検査します
 * @version 01.00.03
 * @date 2026/11/05
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/05  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.00.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.00.03 Shunji Ogawa  2026/11/13  847kの検証済みSYSTEM媒体作用と限定資格を接続
 * </pre>
 *
 * @note 共通実装を専用compileし、製品に試験用入口を追加しません。実導入・file変更をしません
 * @see docs/adr/0449-declared-catalog-hash-and-inf-attached-content.md
 */
//------------------------------------------------------------------------------

#include "platform/official_file_verifier.cpp"
#include "platform/official_download_workspace.h"
#include "test_framework.h"

#include <crtdbg.h>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <algorithm>
#include <cstring>
#include <utility>

//------------------------------------------------------------------------------
/**
 * @brief 同原CAT/memberのcache-only/current-strong/publisherと元失敗保持を確認します
 * @param[in,out] context 原assertion集計です
 * @note 既完全署名scopeと低位ABI表を使い、実trust成功とは数えません
 */
//------------------------------------------------------------------------------
void testWindowsCatalogPolicy( drivercrate::test::TestContext &context)
{
	using namespace drivercrate ;
	OfficialDownloadWorkspace workspace ;	// 今回だけの人工file所有者です
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"system-cat-policy", 84701U) == 0U) ;
	std::vector<driver_package_signature_detail::FixtureFile> files ;	// 全原hashへ結びます
	// 二原fileを作り、任意の成功boolを入力へ渡しません
	for( const auto name : {L"sample.inf", L"sample.cat"}) {
		HANDLE raw = INVALID_HANDLE_VALUE ;	// この所有者の一fileです
		DRIVERCRATE_EXPECT( context, workspace.createFile( name, raw) == 0U) ;
		const ReadOnlyVerificationFile file( raw) ;		// 全returnで閉じます
		const std::wstring_view		   bytes( name) ;	// 名前のUTF16だけを異なる人工byteにします
		DWORD						   written{} ;		// 原byteの完全書込量です
		DRIVERCRATE_EXPECT( context, WriteFile( raw, bytes.data(),
											  static_cast<DWORD>( bytes.size() * sizeof( wchar_t)),
											  &written, nullptr) &&
										written == bytes.size() * sizeof( wchar_t)) ;
	}

	// 書込handleを閉じた後に原hashを固定します
	for( const auto name : {L"sample.inf", L"sample.cat"}) {
		std::wstring hash ;	// 元byteを独立計算します
		DRIVERCRATE_EXPECT( context, computeFileSha256( workspace.path( name), hash) == 0U) ;
		files.push_back( {name, hash, L"sample.inf"}) ;
	}

	const auto scope =
		// 既root/hash/owner境界です
		driver_package_signature_detail::Access::create( files) ;
	DRIVERCRATE_EXPECT( context, scope != nullptr) ;
	// 不完全scopeを実CATへfallbackしません
	if( !scope) {
		return ;
	}

	SP_INF_SIGNER_INFO_W signer{} ;	// 原rootの人工署名登録だけです
	signer.cbSize = sizeof( signer) ;
	DRIVERCRATE_EXPECT( context, driver_package_signature_detail::setupVerifyInf(
									workspace.path( L"sample.inf").c_str(), nullptr, &signer)) ;
	/** @brief 元Windows ABIの応答だけを保持するこの関数内の固定状態です */
	struct State {
		/// 同原CATだけを照合する完全位置です
		std::wstring catalog ;
		/// API入力が全て固定policyと一致した場合trueです
		bool		 valid{true} ;
		/// VERIFY/CLOSE/queryの元呼出し件数です
		unsigned	 verifies{} ;
		/// 同backendのCLOSE呼出し件数です
		unsigned	 closes{} ;
		/// 元PKCS7 readerの呼出し件数です
		unsigned	 queries{} ;
		/// 0正常/1元trust失敗/2別publisher/3元reader失敗です
		unsigned	 mode{} ;
		/// 元certificate lookupの安定した人工識別byteです
		BYTE		 identity{1U} ;
		/// certificateName callbackが同一性を確認する人工contextです
		CERT_CONTEXT certificate{} ;
	} ;
	static thread_local State						 state ;	// 同test threadだけの完全ABI状態です
	driver_package_signature_detail::AuthenticodeApi api ;		// 欠損をnativeで補完しない元表です
	api.verify = []( HWND window, GUID *action, LPVOID data) -> LONG {
		const auto trust = static_cast<WINTRUST_DATA *>( data) ;	// WinTrustの同期ABIだけです
		const GUID expectedAction =
			WINTRUST_ACTION_GENERIC_VERIFY_V2 ;	// 元署名policyを独立比較します
		state.valid =
			state.valid && !window && action && *action == expectedAction && trust &&
			trust->dwUnionChoice == WTD_CHOICE_CATALOG && trust->dwUIChoice == WTD_UI_NONE &&
			trust->fdwRevocationChecks == WTD_REVOKE_WHOLECHAIN &&
			trust->dwProvFlags ==
				(WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_CACHE_ONLY_URL_RETRIEVAL) &&
			trust->pSignatureSettings &&
			trust->pSignatureSettings->dwFlags == WSS_VERIFY_SPECIFIC &&
			trust->pSignatureSettings->dwIndex == 0U && trust->pSignatureSettings->pCryptoPolicy &&
			trust->pSignatureSettings->pCryptoPolicy->dwInfoChoice ==
				CERT_STRONG_SIGN_OID_INFO_CHOICE &&
			std::strcmp( trust->pSignatureSettings->pCryptoPolicy->pszOID,
						szOID_CERT_STRONG_SIGN_OS_CURRENT) == 0 &&
			trust->pCatalog && trust->pCatalog->pcwszCatalogFilePath == state.catalog &&
			trust->pCatalog->hMemberFile != INVALID_HANDLE_VALUE &&
			trust->pCatalog->cbCalculatedFileHash == 32U ;
		// 元CLOSEを成功/失敗のどちらでも一回確認します
		if( trust && trust->dwStateAction == WTD_STATEACTION_CLOSE) {
			++state.closes ;
			return ERROR_SUCCESS ;
		}

		++state.verifies ;
		return state.valid ? (state.mode == 1U ? TRUST_E_EXPLICIT_DISTRUST : ERROR_SUCCESS)
						   : E_INVALIDARG ;
	} ; // 同元CAT/hashとcache-only/current-strongを独立期待へ照合します
	api.query = []( DWORD object, const void *path, DWORD content, DWORD format, DWORD flags,
				   DWORD *encoding, DWORD *type, DWORD *output, HCERTSTORE *store,
				   HCRYPTMSG *message, const void **context) -> BOOL {
		++state.queries ;
		state.valid = state.valid && object == CERT_QUERY_OBJECT_FILE && path &&
					  std::wstring_view( static_cast<const wchar_t *>( path)) == state.catalog &&
					  content == CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED &&
					  format == CERT_QUERY_FORMAT_FLAG_BINARY && !flags && encoding && type &&
					  output && store && message && !context ;
		// 原reader失敗を保持し、未知APIを成功へしません
		if( !state.valid || state.mode == 3U) {
			SetLastError( ERROR_ACCESS_DENIED) ;
			return FALSE ;
		}

		*encoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING ;
		*type	  = CERT_QUERY_CONTENT_PKCS7_SIGNED ;
		*output	  = CERT_QUERY_FORMAT_BINARY ;
		*store	  = &state ;
		*message  = &state ;
		return TRUE ;
	} ; // 同原CATだけへ完全なPKCS7 ABI応答を返します
	api.messageParameter = []( HCRYPTMSG message, DWORD parameter, DWORD index, void *data,
							  DWORD *bytes) -> BOOL {
		state.valid = state.valid && message == &state && parameter == CMSG_SIGNER_INFO_PARAM &&
					  index == 0U && bytes ;
		// 不完全な応答先へ署名情報を補完しません
		if( !state.valid) {
			return FALSE ;
		}

		// 二段階照会の一段目は元容量だけを返します
		if( !data) {
			*bytes = sizeof( CMSG_SIGNER_INFO) ;
			return TRUE ;
		}

		// 元容量を確認した二段目だけへ完全構造を返します
		if( *bytes < sizeof( CMSG_SIGNER_INFO)) {
			return FALSE ;
		}

		CMSG_SIGNER_INFO info{} ;	// 同寿命の安定したissuer/serialです
		info.Issuer		  = {1U, &state.identity} ;
		info.SerialNumber = {1U, &state.identity} ;
		std::memcpy( data, &info, sizeof( info)) ;
		*bytes = sizeof( info) ;
		return TRUE ;
	} ; // 先頭署名だけを同原CATへ結びます
	api.findCertificate = []( HCERTSTORE store, DWORD encoding, DWORD flags, DWORD type,
							 const void *parameter, PCCERT_CONTEXT previous) -> PCCERT_CONTEXT {
		state.valid = state.valid && store == &state &&
					  encoding == (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING) && !flags &&
					  type == CERT_FIND_SUBJECT_CERT && parameter && !previous ;
		return state.valid ? &state.certificate : nullptr ;
	} ; // 名前だけの別certificateを受け付けません
	api.certificateName = []( PCCERT_CONTEXT certificate, DWORD type, DWORD flags, void *parameter,
							 LPWSTR output, DWORD capacity) -> DWORD {
		state.valid = state.valid && certificate == &state.certificate &&
					  type == CERT_NAME_SIMPLE_DISPLAY_TYPE && !flags && !parameter ;
		const std::wstring_view name =
			// 独立した完全名です
			state.mode == 2U ? L"Unrelated Publisher" : L"Microsoft Windows" ;
		// 元二段階照会の容量だけを返します
		if( !output) {
			return static_cast<DWORD>( name.size() + 1U) ;
		}

		// 未終端の部分名を成功へしません
		if( capacity <= name.size()) {
			return 0U ;
		}

		std::copy( name.begin(), name.end(), output) ;
		output[name.size()] = L'\0' ;
		return static_cast<DWORD>( name.size() + 1U) ;
	} ; // 同CATの正確なpublisher拒否を確認します
	api.freeCertificate = []( PCCERT_CONTEXT value) -> BOOL {
		return value == &state.certificate ;
	} ; // 同借用だけを解放します
	api.closeMessage = []( HCRYPTMSG value) -> BOOL {
		return value == &state ;
	} ; // 同messageだけを解放します
	api.closeStore = []( HCERTSTORE value, DWORD flags) -> BOOL {
		return value == &state && flags == 0U ;
	} ; // 同storeだけを解放します
	const std::array members{workspace.path( L"sample.inf")} ;	// 原CATの実memberです
	// 各条件を同一の原CAT/member/実hashで確認し、trust後の別候補を許しません
	for( unsigned mode = 0U; mode < 4U; ++mode) {
		state		  = {} ;
		state.catalog = workspace.path( L"sample.cat") ;
		state.mode	  = mode ;
		const auto backend =
			// 全八ABIだけです
			driver_package_signature_detail::Access::createAuthenticode( api) ;
		DRIVERCRATE_EXPECT( context, backend != nullptr) ;
		const auto error = driver_package_signature_detail::Access::verifyWindowsCatalogMembers(
			state.catalog, members) ;	// 実member parser/hash経由です
		const NativeError expected =
			mode == 0U	 ? 0U
			: mode == 1U ? static_cast<NativeError>( TRUST_E_EXPLICIT_DISTRUST)
			: mode == 2U ? static_cast<NativeError>( TRUST_E_SUBJECT_NOT_TRUSTED)
						 : static_cast<NativeError>(
							   // 独立したAPI/方針期待です
							   HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED)) ;
		DRIVERCRATE_EXPECT( context, error == expected && state.valid && state.verifies == 1U &&
										state.closes == 1U &&
										state.queries == (mode == 1U ? 0U : 1U)) ;
	}

	std::vector<CatalogMemberDigest> declarations ;	// 同原CATのproducerが返した元宣言です
	DRIVERCRATE_EXPECT( context,
					   readCatalogAlgorithms( workspace.path( L"sample.cat"), declarations) == 0U) ;
	std::vector<std::unique_ptr<CatalogHashContext>> contexts ;	// 原SHA256だけのhash contextです
	auto hash = std::make_unique<CatalogHashContext>() ;		// 原算法の所有者です
	DRIVERCRATE_EXPECT( context, hash->initialize( BCRYPT_SHA256_ALGORITHM, 32U) == 0U) ;
	contexts.push_back( std::move( hash)) ;
	// 原digestを保ちtagだけ不一致にする独立拒否です
	for( auto &entry : declarations) {
		entry.tag += L"BAD" ;
	}

	state		  = {} ;
	state.catalog = workspace.path( L"sample.cat") ;
	const auto backend =
		// nativeへ落ちない表です
		driver_package_signature_detail::Access::createAuthenticode( api) ;
	DRIVERCRATE_EXPECT( context, backend != nullptr &&
									verifyCatalogMember( contexts, declarations, state.catalog,
														members.front(), true) ==
										static_cast<NativeError>( TRUST_E_BAD_DIGEST)) ;
	DRIVERCRATE_EXPECT( context, state.verifies == 0U && state.queries == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 所有fixtureのSDだけを変更し、未知write/null/owner/object/callbackを拒否します
 * @param[in,out] context 元assertion集計です
 * @note 変更前SDを同保持handleへ必ず戻し、Windows fileや既stateを変更しません
 */
//------------------------------------------------------------------------------
void testSystemFilePermissions( drivercrate::test::TestContext &context)
{
	using namespace drivercrate ;
	OfficialDownloadWorkspace workspace ;	// この試験だけの保護所有者です
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"system-permission-policy", 84702U) == 0U) ;
	HANDLE created = INVALID_HANDLE_VALUE ;	// 実行しない人工fileです
	DRIVERCRATE_EXPECT( context, workspace.createFile( L"fixture.bin", created) == 0U) ;
	CloseHandle( created) ;
	const ReadOnlyVerificationFile file(
		CreateFileW( workspace.path( L"fixture.bin").c_str(), READ_CONTROL | WRITE_DAC | WRITE_OWNER,
					FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT,
					nullptr)) ;	// 元権限で保持します
	DRIVERCRATE_EXPECT( context, file.get() != INVALID_HANDLE_VALUE) ;
	PSECURITY_DESCRIPTOR originalRaw{} ;	// LocalFreeする元SDです
	PACL				 originalDacl{} ;	// 元SDが保持するDACLです
	PSID				 originalOwner{} ;	// 元SDの同ownerを最後に戻します
	DRIVERCRATE_EXPECT( context,
					   GetSecurityInfo( file.get(), SE_FILE_OBJECT,
									   DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
									   &originalOwner, nullptr, &originalDacl, nullptr,
									   &originalRaw) == ERROR_SUCCESS) ;
	const std::unique_ptr<void, decltype( &LocalFree)>		 original( originalRaw,
																	  &LocalFree) ;	// 最後に解放します
	const std::array<std::pair<std::wstring_view, bool>, 6U> cases{
		{{L"D:P(A;;FA;;;SY)(A;;FA;;;BA)", true},
		 {L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;WD)", true},
		 {L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GW;;;WD)", false},
		 {L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;WD;;;AU)", false},
		 {L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(OA;;GR;10000000-0000-4000-8000-000000000007;;WD)", false},
		 {L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(XA;;GR;;;WD;(@User.TestAttribute == 1))",
		  false}}} ;	// 固定標準SIDと架空条件だけです
	// 各SDを実fileから読み、元DACLへ戻した後で結果を評価します
	for( const auto &entry : cases) {
		PSECURITY_DESCRIPTOR raw{} ;	// この条件だけのSDです
		DRIVERCRATE_EXPECT( context,
						   ConvertStringSecurityDescriptorToSecurityDescriptorW(
							   std::wstring( entry.first).c_str(), SDDL_REVISION_1, &raw, nullptr)) ;
		const std::unique_ptr<void, decltype( &LocalFree)> descriptor(
			raw, &LocalFree) ;	// 全returnで解放します
		PACL dacl{} ;			// 同SDの借用です
		BOOL present{} ;		// null DACLと区別します
		BOOL defaulted{} ;		// 元SDの既定flagです
		DRIVERCRATE_EXPECT( context,
						   GetSecurityDescriptorDacl( raw, &present, &dacl, &defaulted) && present) ;
		DRIVERCRATE_EXPECT(
			context,
			SetSecurityInfo( file.get(), SE_FILE_OBJECT,
							DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
							nullptr, nullptr, dacl, nullptr) == ERROR_SUCCESS) ;
		std::vector<std::byte> snapshot ;	// 元readerが検証したSDだけです
		const auto			   error = verifySystemFilePermissions(
			// 実restricted token/全ACEを検査します
			file.get(), snapshot, nullptr) ;
		const auto restore =
			SetSecurityInfo( file.get(), SE_FILE_OBJECT,
							DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
							nullptr, nullptr, originalDacl, nullptr) ;	// 同元DACLを復元します
		DRIVERCRATE_EXPECT( context,
						   restore == ERROR_SUCCESS && (entry.second ? error == 0U : error != 0U)) ;
	}

	DRIVERCRATE_EXPECT( context,
					   SetSecurityInfo( file.get(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
									   nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) ;
	std::vector<std::byte> snapshot ;	// null DACL拒否を独立確認します
	const auto			   nullError =
		// 内容は読みません
		verifySystemFilePermissions( file.get(), snapshot, nullptr) ;
	DRIVERCRATE_EXPECT(
		context, SetSecurityInfo( file.get(), SE_FILE_OBJECT,
								 DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
								 nullptr, nullptr, originalDacl, nullptr) == ERROR_SUCCESS &&
					 nullError != 0U) ;
	HANDLE tokenRaw{} ;	// 本人SIDのread-only照会だけです
	DRIVERCRATE_EXPECT( context, OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &tokenRaw)) ;
	const ReadOnlyVerificationFile token( tokenRaw) ;	// この同期だけの所有handleです
	// 実本人SIDを一般logへ出しません
	alignas( TOKEN_USER) std::array<std::byte, 1024U> userBytes{} ;
	DWORD											 required{} ;	// 元APIの必要byteです
	DRIVERCRATE_EXPECT( context,
					   GetTokenInformation( token.get(), TokenUser, userBytes.data(),
										   static_cast<DWORD>( userBytes.size()), &required)) ;
	// 同整列bufferをWindowsのTOKEN_USER ABIとしてだけ借用します
	const auto user = reinterpret_cast<const TOKEN_USER *>( userBytes.data()) ;	// 同寿命の本人SIDです
	DRIVERCRATE_EXPECT( context,
					   SetSecurityInfo( file.get(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
									   user->User.Sid, nullptr, nullptr, nullptr) == ERROR_SUCCESS) ;
	const auto ownerError =
		// 既知保守owner以外を拒否します
		verifySystemFilePermissions( file.get(), snapshot, nullptr) ;
	const auto restoreOwner =
		SetSecurityInfo( file.get(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, originalOwner,
						nullptr, nullptr, nullptr) ;	// 同保持handleから元ownerを戻します
	DRIVERCRATE_EXPECT( context, restoreOwner == ERROR_SUCCESS &&
									ownerError == static_cast<NativeError>(
													  HRESULT_FROM_WIN32( ERROR_INVALID_OWNER))) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既存人工scopeの元hash/root-ownerと新しいCAT宣言検査を接続します
 * @param[in,out] context 一processの有限集計先です
 * @note 実署名を持たない人工fileだけで、実CATの受入証拠には使用しません
 */
//------------------------------------------------------------------------------
void testSyntheticCatalogScope( drivercrate::test::TestContext &context)
{
	drivercrate::OfficialDownloadWorkspace workspace ;	// この試験だけの保護所有領域です
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"cat-scope-test", 71050U) == 0) ;
	std::vector<drivercrate::driver_package_signature_detail::FixtureFile>
		files ;	// 既存factoryの完全固定hash集合です
	// 異なるbyteのINF/CAT/SYSを全て固定し、任意の成功boolは渡しません
	for( const auto name : {L"sample.inf", L"sample.cat", L"sample.sys"}) {
		HANDLE file{INVALID_HANDLE_VALUE} ;	// 作成後は下のRAIIだけが閉じます
		DRIVERCRATE_EXPECT( context, workspace.createFile( name, file) == 0) ;
		std::unique_ptr<void, decltype( &CloseHandle)> owner(
			file, &CloseHandle) ;				// hash前に明示closeし、全returnでも回収します
		const std::wstring_view bytes( name) ;	// 名前のUTF16 byteを架空内容にします
		DWORD					written{} ;		// 実書込みbyte数です
		DRIVERCRATE_EXPECT( context, WriteFile( file, bytes.data(),
											  static_cast<DWORD>( bytes.size() * sizeof( wchar_t)),
											  &written, nullptr) != FALSE) ;
		DRIVERCRATE_EXPECT( context, written == bytes.size() * sizeof( wchar_t)) ;
		owner.reset() ;
		std::wstring hash ;	// 元全byteから計算した固定SHA256です
		DRIVERCRATE_EXPECT( context,
						   drivercrate::computeFileSha256( workspace.path( name), hash) == 0) ;
		files.push_back( {name, hash, L"sample.inf"}) ;
	}

	const auto scope = drivercrate::driver_package_signature_detail::Access::create(
		// 既存の明示人工scopeだけです
		std::move( files)) ;
	DRIVERCRATE_EXPECT( context, scope != nullptr) ;
	// scope作成失敗をnative署名の成功へ読み替えません
	if( scope == nullptr) {
		return ;
	}

	const std::array members{workspace.path( L"sample.inf"),
							 // 同ownerの全memberです
							 workspace.path( L"sample.sys")} ;
	DRIVERCRATE_EXPECT( context, drivercrate::verifyOfficialCatalogMembers(
									workspace.path( L"sample.cat"), members) != 0) ;
	SP_INF_SIGNER_INFO_W signer{} ;	// 元SetupVerifyInf相当の完全な出力です
	signer.cbSize = sizeof( signer) ;
	DRIVERCRATE_EXPECT( context,
					   drivercrate::driver_package_signature_detail::setupVerifyInf(
						   workspace.path( L"sample.inf").c_str(), nullptr, &signer) != FALSE) ;
	DRIVERCRATE_EXPECT( context, drivercrate::verifyOfficialCatalogMembers(
									workspace.path( L"sample.cat"), members) == 0) ;
	const auto receipt = scope->receipt() ;	// 実際の人工VERIFY/CLOSE呼出し数だけです
	DRIVERCRATE_EXPECT( context, receipt.verifyCalls == 2U && receipt.closeCalls == 2U) ;
	std::unique_ptr<void, decltype( &CloseHandle)> mutated(
		CreateFileW( workspace.path( L"sample.sys").c_str(), GENERIC_WRITE, 0U, nullptr,
					TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr),
		&CloseHandle) ;	// 所有試験fileだけを改変します
	DRIVERCRATE_EXPECT( context, mutated.get() != INVALID_HANDLE_VALUE) ;
	mutated.reset() ;
	DRIVERCRATE_EXPECT( context, drivercrate::verifyOfficialCatalogMembers(
									workspace.path( L"sample.cat"), members) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原CAT診断または架空算法の有限matrixを実行します
 * @param[in] count 実行fileを含む引数数です
 * @param[in] arguments --diagnose-catと原CAT、または--membersとCATとmember集合です
 * @return 全検査成功0、入力不正2、境界試験・例外・原検査失敗1です
 * @note CRT/OSの非対話設定を入力とassertionより前に適用します
 */
//------------------------------------------------------------------------------
int wmain( const int count, wchar_t *arguments[])
{
	SetErrorMode( SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX) ;
	_set_abort_behavior( 0U, _WRITE_ABORT_MSG | _CALL_REPORTFAULT) ;
#if defined( _DEBUG)
	_CrtSetReportMode( _CRT_ASSERT, _CRTDBG_MODE_FILE) ;
	_CrtSetReportFile( _CRT_ASSERT, _CRTDBG_FILE_STDERR) ;
#endif
	try {
		// 明示pathだけを読取り、原宣言の取得とcontext失敗を区別します
		if( count == 3 && std::wstring_view( arguments[1]) == L"--diagnose-cat") {
			std::vector<drivercrate::CatalogMemberDigest> declarations ;	// 原CATの全member宣言です
			const auto									  declaration =
				// 宣言診断です
				drivercrate::readCatalogAlgorithms( arguments[2], declarations) ;
			const auto algorithm =
				// 最初の原算法です
				declarations.empty() ? nullptr : declarations.front().algorithm ;
			const auto bytes =
				declarations.empty()
					? 0U
					: static_cast<DWORD>( declarations.front().bytes.size()) ;	// 同じ原長です
			drivercrate::CatalogHashContext context ;							// 同原CATに結ぶ一contextです
			const auto						initialization =
				// 原段階です
				declaration == 0 ? context.initialize( algorithm, bytes) : declaration ;
			std::wcout << L"declaration=" << declaration << L" algorithm="
					   << (algorithm == nullptr ? L"NONE" : algorithm) << L" bytes=" << bytes
					   << L" initialization=" << initialization << L'\n' ;
			return initialization == 0 ? 0 : 1 ;
		}

		// 保存memberの改変拒否も同じproduction検証へ渡します
		if( count >= 4 && std::wstring_view( arguments[1]) == L"--members") {
			std::vector<std::wstring> members ;	// 元順で検証する有限集合です
			// 明示されたmemberだけを保持し、探索・実行しません
			for( int index = 3; index < count; ++index) {
				members.emplace_back( arguments[index]) ;
			}

			const auto error =
				// 原trust結果です
				drivercrate::verifyOfficialCatalogMembers( arguments[2], members) ;
			std::cout << "memberError=" << error << '\n' ;
			return error == 0 ? 0 : 1 ;
		}

		// 想定しないCLIを架空試験の成功へ読み替えません
		if( count != 1) {
			return 2 ;
		}

		drivercrate::test::TestContext context ;	// 非通信matrixの有限集計です
		std::array<BYTE, 64U>		   digest{} ;	// byte値と無関係な宣言構造だけの試験です
		const std::array<std::pair<const char *, DWORD>, 4U> cases{
			{{szOID_OIWSEC_sha1, 20U},
			 {szOID_NIST_sha256, 32U},
			 {szOID_NIST_sha384, 48U},
			 {szOID_NIST_sha512, 64U}}} ;	// 既知の正確なOID/長さです
		// 各既知算法と一byte不足の独立拒否を確認します
		for( const auto &entry : cases) {
			SIP_INDIRECT_DATA data{} ;	// OS構造の原宣言相当です
			data.DigestAlgorithm.pszObjId = const_cast<PSTR>( entry.first) ;
			data.Digest					  = {entry.second, digest.data()} ;
			PCWSTR algorithm{} ;	// 原成功だけで非nullになる出力です
			DWORD  bytes{} ;		// 元全長だけを期待します
			DRIVERCRATE_EXPECT(
				context, drivercrate::readCatalogMemberAlgorithm( data, algorithm, bytes) == 0) ;
			DRIVERCRATE_EXPECT( context, algorithm != nullptr && bytes == entry.second) ;
			--data.Digest.cbData ;
			DRIVERCRATE_EXPECT(
				context, drivercrate::readCatalogMemberAlgorithm( data, algorithm, bytes) != 0) ;
			DRIVERCRATE_EXPECT( context, algorithm == nullptr && bytes == 0U) ;
		}

		SIP_INDIRECT_DATA unknown{} ;				// 既知へのfallbackを持たない架空OIDです
		char			  oid[] = "1.2.3.4.999" ;	// Windows構造の変更可能fieldに渡す同期bufferです
		unknown.DigestAlgorithm.pszObjId = oid ;
		unknown.Digest					 = {32U, digest.data()} ;
		PCWSTR algorithm{} ;	// 拒否後の出力です
		DWORD  bytes{} ;		// 拒否後は0です
		DRIVERCRATE_EXPECT( context,
						   drivercrate::readCatalogMemberAlgorithm( unknown, algorithm, bytes) != 0) ;
		DRIVERCRATE_EXPECT( context, algorithm == nullptr && bytes == 0U) ;
		unknown.DigestAlgorithm.pszObjId = nullptr ;
		DRIVERCRATE_EXPECT( context,
						   drivercrate::readCatalogMemberAlgorithm( unknown, algorithm, bytes) != 0) ;
		testSyntheticCatalogScope( context) ;
		testWindowsCatalogPolicy( context) ;
		testSystemFilePermissions( context) ;
		std::cout << "Assertions: " << context.assertionCount()
				  << ", failures: " << context.failureCount() << '\n' ;
		return context.failureCount() == 0 ? 0 : 1 ;
	} catch( const std::bad_alloc &) {
		std::cerr << "CAT fixture allocation failed.\n" ;
		return 1 ;
	} catch( const std::exception &) {
		std::cerr << "CAT fixture exception.\n" ;
		return 1 ;
	} catch( ...) {
		std::cerr << "CAT fixture unknown exception.\n" ;
		return 1 ;
	}
}
