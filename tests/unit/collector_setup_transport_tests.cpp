//------------------------------------------------------------------------------
/**
 * @file collector_setup_transport_tests.cpp
 * @brief 固定OS curlの共通publisher段階と従来policyを完全人工backendで確認します。
 * @version 01.00.02
 * @date 2026/10/17
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/17 VERIFY/CLOSE policyと元error伝播を検査。
 * Ver.01.00.01 Shunji Ogawa  2026/10/17 実prepareの専用policyを四case群で共有検査し実件数を表示。
 * Ver.01.00.02 Shunji Ogawa  2026/10/24  必須解析に合わせ試験の所有・型・失敗制御を明示。
 * </pre>
 *
 * @note 通常試験は完全fakeです。明示OS観測もcached-onlyで通信しません。
 * @see docs/adr/0357-collector-explicit-run-and-system-transport.md
 */
//------------------------------------------------------------------------------
#include "platform/collector_setup_transport.h"
#include "platform/official_file_verifier.h"
#include "platform/driver_package_signature_internal.h"
#include <Windows.h>
#include <Softpub.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <exception>
#include <initializer_list>
#include <string_view>

namespace drivercrate {
namespace {
// 同thread内の完全fakeだけが参照する期待policy。
DWORD			  expectedFlags{} ;
// VERIFYから返す人工の元trust error。
LONG			  verifyStatus{} ;
// 元ABIのpolicyとVERIFY/CLOSE数を確認する。
std::size_t		  verifyCount{} ;
// CLOSEの呼出し数。
std::size_t		  closeCount{} ;
// Policy相違を成功に変換しない観測値。
bool			  invalidPolicy{} ;
// 共通実装がembedded signerを問い合わせた回数。
std::size_t		  queryCount{} ;
// 同threadの各人工caseが指定する静的寿命のpublisher名。
std::wstring_view publisherName{L"Microsoft Windows"} ;
// Embedded署名なしの人工入力。
bool			  missingEmbedded{} ;
// OS証明書を使わない人工context。
CERT_CONTEXT	  certificate{} ;

/** @brief 一つの固定case群で実行したcheckと失敗を保持します。 */
struct TransportCheckResult {
	/// 固定case群の診断名。静的文字列を借用する。
	const char *name ;
	/// 実際に署名段階を呼び出して照合したcheck数。
	std::size_t checks{} ;
	/// 期待errorまたはABI観測に一致しなかったcheck数。
	std::size_t failures{} ;
} ;

/** @brief VERIFY/CLOSEの同じpolicyだけを検査する完全fakeです。
 * @param[in,out] data 同期呼出し中だけ借用するWINTRUST_DATA。
 * @return VERIFYは固定元error、CLOSEは成功0。
 */
LONG WINAPI fakeVerify( HWND, GUID *, LPVOID data)
{
	auto *trust = static_cast<WINTRUST_DATA *>( data) ;	// 同じABIの借用構造体。
	// 欠けた構造体はpolicy不一致として保持し、検証回数へ数えない。
	if( trust == nullptr) {
		invalidPolicy = true ;
		return E_INVALIDARG ;
	}

	invalidPolicy |= trust->dwUIChoice != WTD_UI_NONE ||
					 trust->fdwRevocationChecks != WTD_REVOKE_WHOLECHAIN ||
					 trust->dwUnionChoice != WTD_CHOICE_FILE ||
					 trust->dwProvFlags != expectedFlags || trust->pFile == nullptr ;
	// 製品共通入口のpath-only契約を人工backendでも区別する。
	if( trust->pFile != nullptr) {
		invalidPolicy |= trust->pFile->hFile != nullptr || trust->pFile->pcwszFilePath == nullptr ;
	}

	// VERIFYとCLOSEを独立に数え、失敗後もCLOSEした事実を残す。
	if( trust->dwStateAction == WTD_STATEACTION_VERIFY) {
		++verifyCount ;
		return verifyStatus ;
	}

	++closeCount ;
	invalidPolicy |= trust->dwStateAction != WTD_STATEACTION_CLOSE ;
	return ERROR_SUCCESS ;
}

/** @brief Embedded署名の有無をOSへ問い合わせない人工queryです。
 * @param[out] encoding 人工証明書のencoding。
 * @param[out] store 人工store token。
 * @param[out] message 人工message token。
 * @return 人工embedded署名がある場合TRUE。
 */
BOOL WINAPI fakeQuery( DWORD, const void *, DWORD, DWORD, DWORD, DWORD *encoding, DWORD *, DWORD *,
					  HCERTSTORE *store, HCRYPTMSG *message, const void **)
{
	++queryCount ;
	// Catalog-onlyをpublisher推測で成功にせず元errorへ残す。
	if( missingEmbedded) {
		SetLastError( static_cast<DWORD>( CRYPT_E_NO_MATCH)) ;
		return FALSE ;
	}

	*encoding = X509_ASN_ENCODING ;
	*store	  = &certificate ;
	*message  = &certificate ;
	return TRUE ;
}

/** @brief 人工signer構造体を二段階の元ABIで返します。
 * @param[out] output 人工signer受信buffer。NULLなら容量照会。
 * @param[in,out] size 必要な構造体byte数。
 * @return 人工query成功TRUE。
 */
BOOL WINAPI fakeMessage( HCRYPTMSG, DWORD, DWORD, void *output, DWORD *size)
{
	*size = sizeof( CMSG_SIGNER_INFO) ;
	// 容量照会ではbufferを参照しない。
	if( output != nullptr) {
		std::memset( output, 0, sizeof( CMSG_SIGNER_INFO)) ;
	}

	return TRUE ;
}

/** @brief 人工contextだけを返します。
 * @return OSへ登録していない静的人工context。
 */
PCCERT_CONTEXT WINAPI fakeFind( HCERTSTORE, DWORD, DWORD, DWORD, const void *, PCCERT_CONTEXT)
{
	return &certificate ;
}

/** @brief 完全一致判定へ渡す人工publisher名を返します。
 * @param[out] output 文字列受信先。NULLなら必要文字数照会。
 * @param[in] capacity 受信容量。
 * @return 終端を含む必要文字数。
 */
DWORD WINAPI fakeName( PCCERT_CONTEXT, DWORD, DWORD, void *, LPWSTR output, DWORD capacity)
{
	const std::wstring_view name   = publisherName ;							// このcaseの人工名。
	const DWORD				length = static_cast<DWORD>( name.size() + 1U) ;	// 有限literalの文字数。
	// 二段階queryの成功時だけ人工文字列を返す。
	if( output != nullptr && capacity >= length) {
		std::copy( name.begin(), name.end(), output) ;
		output[name.size()] = L'\0' ;
	}

	return length ;
}

/** @brief 人工contextの解放を観測しOSへ渡しません。
 * @return 常にTRUE。
 */
BOOL WINAPI fakeFree( PCCERT_CONTEXT)
{
	return TRUE ;
}

/** @brief 人工messageだけを閉じます。
 * @return 常にTRUE。
 */
BOOL WINAPI fakeCloseMessage( HCRYPTMSG)
{
	return TRUE ;
}

/** @brief 人工storeだけを閉じます。
 * @return 常にTRUE。
 */
BOOL WINAPI fakeCloseStore( HCERTSTORE, DWORD)
{
	return TRUE ;
}

/** @brief 一回の共通署名段階について元errorとVERIFY／CLOSE policyを照合します。
 * @param[in,out] result 実check数と不一致数の加算先。
 * @param[in] narrow 実prepareと同じtransport専用helperを呼ぶ場合true。
 * @param[in] cached 通常共通入口ではfalse、cached-onlyではtrue。
 * @param[in] path 完全fakeへ渡す人工path。空入力はAPI起動前拒否を要求します。
 * @param[in] expectedError 期待する元error。
 * @note 署名backendは呼出側のscopeで完全fakeへ固定されていること。
 */
void checkSignature( TransportCheckResult &result, const bool narrow, const bool cached,
					const std::wstring_view path, const NativeError expectedError)
{
	verifyCount	  = 0U ;
	closeCount	  = 0U ;
	queryCount	  = 0U ;
	invalidPolicy = false ;
	expectedFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
					((narrow || cached) ? WTD_CACHE_ONLY_URL_RETRIEVAL : 0U) ;
	constexpr std::array<std::wstring_view, 1U> PUBLISHERS{
		L"Microsoft Windows"} ;	// 通常APIだけの人工policy。
	const NativeError error =
		narrow ? collector_setup_transport_detail::verifyCachedSystemCurlPublisherStage( path)
			   : (cached ? verifyAuthenticodePublisherCachedOnly( path, PUBLISHERS)
						 : verifyAuthenticodePublisher( path, PUBLISHERS)) ;	// 同じ共通実装の元結果。
	const std::size_t expectedCalls = path.empty() ? 0U : 1U ;					// 空入力ではWinTrustへ進まない。
	const std::size_t expectedQueries =
		!path.empty() && verifyStatus == ERROR_SUCCESS ? 1U : 0U ;	// Trust拒否後の再試行を認めない。
	++result.checks ;
	result.failures += error != expectedError || verifyCount != expectedCalls ||
					   closeCount != expectedCalls || queryCount != expectedQueries ||
					   invalidPolicy ;
}

/** @brief 四つの固定case群を実prepareと同じpolicyおよび従来APIで実行します。
 * @return 各群の実check数と不一致数。
 * @note OS署名・通信・実file操作を行わず、全呼出しを完全fake scope内に閉じます。
 */
std::array<TransportCheckResult, 4U> transportChecks()
{
	std::array<TransportCheckResult, 4U> results{
		{{"A01"}, {"A02"}, {"A03"}, {"A04"}}} ;	// 固定分母。
	const auto scope = driver_package_signature_detail::Access::createAuthenticode(
		{&fakeVerify, &fakeQuery, &fakeMessage, &fakeFind, &fakeName, &fakeFree, &fakeCloseMessage,
		 &fakeCloseStore}) ;	// 完全fakeを同threadへ固定する。
	// 人工backendを固定できなければ全群を失敗とし、実WinTrustへ進まない。
	if( scope == nullptr) {
		// 実行不能だった各群の拒否を一回ずつ数え、成功へ換算しない。
		for( auto &result : results) {
			++result.checks ;
			++result.failures ;
		}

		return results ;
	}

	// Null構造体は検証を開始せず、policy不一致と元引数errorを保持する。
	const auto priorVerify = verifyCount ;								// Backend負例がVERIFYを増やさないことを確認する。
	const auto priorClose  = closeCount ;								// Backend負例がCLOSEを増やさないことを確認する。
	const LONG nullError   = fakeVerify( nullptr, nullptr, nullptr) ;	// 実WinTrustは呼ばない。
	++results[3].checks ;
	results[3].failures += nullError != E_INVALIDARG || !invalidPolicy ||
						   verifyCount != priorVerify || closeCount != priorClose ;

	// 両入口で成功、cache不足、失効、chain失敗を同じerrorのまま検査する。
	for( const bool cached : {false, true}) {
		// 四つの人工戻り値を一回ずつVERIFY/CLOSEへ通す。
		for( const LONG status : {LONG{ERROR_SUCCESS}, LONG{CERT_E_REVOCATION_FAILURE},
								 LONG{CERT_E_REVOKED}, LONG{CERT_E_UNTRUSTEDROOT}}) {
			verifyStatus = status ;
			checkSignature( results[3], false, cached, L"synthetic.exe",
						   static_cast<NativeError>( status)) ;
		}
	}

	verifyStatus = ERROR_SUCCESS ;
	// 新観測名と旧三名を、実prepareと同じ一つの許可policyで受理する。
	for( const std::wstring_view name :
		{L"Microsoft 3rd Party Application Component", L"Microsoft Windows",
		 L"Microsoft Corporation", L"Microsoft Windows Publisher"}) {
		publisherName = name ;
		checkSignature( results[0], true, true, L"synthetic.exe", 0) ;
	}

	publisherName = L"Microsoft 3rd Party Application Component" ;
	// 同じ許可名でも三種の元trust拒否を成功へ変えず、一回のCLOSE後に終了する。
	for( const LONG status :
		{LONG{CERT_E_REVOCATION_FAILURE}, LONG{CERT_E_REVOKED}, LONG{CERT_E_UNTRUSTEDROOT}}) {
		verifyStatus = status ;
		checkSignature( results[1], true, true, L"synthetic.exe", static_cast<NativeError>( status)) ;
	}

	verifyStatus = ERROR_SUCCESS ;
	// 無関係名と許可名の前後追加を拒否し、部分名でOS toolを受理しない。
	for( const std::wstring_view name :
		{L"Unrelated Publisher", L"Microsoft 3rd Party Application Component Extra",
		 L"Extra Microsoft Windows"}) {
		publisherName = name ;
		checkSignature( results[2], true, true, L"synthetic.exe",
					   static_cast<NativeError>( TRUST_E_SUBJECT_NOT_TRUSTED)) ;
	}

	publisherName	= L"Microsoft 3rd Party Application Component" ;
	missingEmbedded = true ;
	checkSignature( results[2], true, true, L"synthetic.exe",
				   static_cast<NativeError>( CRYPT_E_NO_MATCH)) ;
	missingEmbedded = false ;
	checkSignature( results[2], true, true, L"", static_cast<NativeError>( E_INVALIDARG)) ;
	return results ;
}
} // namespace
} // namespace drivercrate

/** @brief 完全fakeを標準とし、明示時だけcached-onlyのOS fileを観測します。
 * @param[in] count 引数数。
 * @param[in] args 試験専用の固定観測flag。
 * @return 完全fake合格0、相違1、実OSのcached-only検証拒否2。
 */
int wmain( const int count, wchar_t *args[])
{
	// この専用test入口は実通信せず、OS curl検証の不足を元診断で保存する。
	if( count == 2 && std::wstring_view( args[1]) == L"--cached-os-observation") {
		try {
			const auto transport =
				// OS実byteと署名の非通信観測。
				drivercrate::prepareCollectorSetupTransport() ;
			std::printf( "SYSTEM_CURL_CACHED_VERIFIED hash_characters=%zu\n",
						transport.sha256.size()) ;
			return 0 ;
		} catch( const std::exception &) {
			return 2 ;
		}
	}

	const auto	results = drivercrate::transportChecks() ;	// 実行済み四群の有限結果。
	std::size_t checks{} ;									// 実行した署名段階checkの総数。
	std::size_t failures{} ;								// 四群で検出した不一致総数。
	// 実行済みの各群を一度ずつ集計し、固定の架空件数を表示しない。
	for( const auto &result : results) {
		checks += result.checks ;
		failures += result.failures ;
		std::printf( "TRANSPORT_CASE id=%s checks=%zu failures=%zu\n", result.name, result.checks,
					result.failures) ;
	}

	std::printf( "TRANSPORT_FAKE cases=%zu checks=%zu failures=%zu network=0\n", results.size(),
				checks, failures) ;
	return failures == 0U ? 0 : 1 ;
}
