//------------------------------------------------------------------------------
/**
 * @file signed_index_refresh_tests.cpp
 * @brief 実HTTP検証/codecと完全fake保存のrefresh回帰です。
 * @version 01.01.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/16  原18caseと16variantの実行到達logを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/17  HTTP経路七境界とDNS・handle解放の実到達を追加。
 * </pre>
 * @note 暗号/HTTP policy/codecは製品実装、低位I/Oとstore観測はRAM fakeです。
 * 実atomic disk保存/準備relation/WM close/製品鍵正常署名を証明しません。
 */
//------------------------------------------------------------------------------
#include "signed_index_refresh_tests.h"
#include "test_framework.h"
#include "platform/signed_index_refresh.h"
#include <array>
#include <algorithm>
#include <cstring>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <bcrypt.h>
#include <miniz.h>

namespace drivercrate::test {
namespace {
// OS時計と無関係な架空wireの現在UTCです。
const auto NOW = std::chrono::sys_days{std::chrono::year{2026} / 10 / 13} + std::chrono::hours{18} ;

/** @brief RAM fixture生成失敗を製品拒否の合格にしません。
 * @param[in] value 必須前提の成立値です。
 */
void	   require( const bool value)
{
	// Fixture生成の不成立を検証対象の拒否成功へ変換しません。
	if( !value) {
		throw std::runtime_error( "P4 RAM fixture failed") ;
	}
}

/** @brief BCryptの非永続RSA/SHA資源を所有します。 */
struct RamKey {
	/// RAM algorithmです。
	BCRYPT_ALG_HANDLE		  rsa{} ;
	/// RAM SHA256です。
	BCRYPT_ALG_HANDLE		  sha{} ;
	/// 名前を持たない秘密handleです。
	BCRYPT_KEY_HANDLE		  key{} ;
	/// Public blobだけです。
	std::vector<std::uint8_t> publicBlob ;
	/** @brief 未生成の資源所有者を初期化します。 */
	RamKey() = default ;
	/** @brief 部分生成の失敗も所有者で回収する一時鍵を作ります。
	 * @throws std::runtime_error RAM暗号資源の生成に失敗した場合です。
	 */
	void generate()
	{
		require( BCryptOpenAlgorithmProvider( &rsa, BCRYPT_RSA_ALGORITHM, nullptr, 0) >= 0) ;
		require( BCryptGenerateKeyPair( rsa, &key, 3072, 0) >= 0 &&
				BCryptFinalizeKeyPair( key, 0) >= 0) ;
		require( BCryptOpenAlgorithmProvider( &sha, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0) ;
		ULONG size{} ;	// 公開blobの有限容量です。
		require( BCryptExportKey( key, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &size, 0) >= 0) ;
		publicBlob.resize( size) ;
		require( BCryptExportKey( key, nullptr, BCRYPT_RSAPUBLIC_BLOB, publicBlob.data(), size, &size,
								0) >= 0) ;
	}
	/** @brief 非永続資源を逆順で回収します。 */
	~RamKey()
	{
		// 各部分生成のhandleだけを解放します。
		if( key) {
			static_cast<void>( BCryptDestroyKey( key)) ;
		}

		// 生成されたSHA providerだけを解放します。
		if( sha) {
			static_cast<void>( BCryptCloseAlgorithmProvider( sha, 0)) ;
		}

		// 永続storeへ触れずRSA providerを閉じます。
		if( rsa) {
			static_cast<void>( BCryptCloseAlgorithmProvider( rsa, 0)) ;
		}
	}
	/** @brief 所有handleのcopyを禁止します。 */
	RamKey( const RamKey &) = delete ;
	/** @brief 所有handleのcopy代入を禁止します。
	 * @return 呼出しは禁止されます。
	 */
	RamKey							 &operator=( const RamKey &) = delete ;
	/** @brief 原byteをRAM内CNG SHA256へ結合します。
	 * @param[in] raw 借用する架空byteです。
	 * @return 固定32byteの独立digestです。
	 */
	[[nodiscard]] IndexManifestSha256 digest( const std::string_view raw) const
	{
		IndexManifestSha256 hash{} ;							// 独立出力です。
		std::vector<UCHAR>	bytes( raw.begin(), raw.end()) ;	// CNG ABIへ渡す所有copyです。
		require( BCryptHash( sha, nullptr, 0, bytes.data(), static_cast<ULONG>( bytes.size()),
						   hash.data(), static_cast<ULONG>( hash.size())) >= 0) ;
		return hash ;
	}
	/** @brief 秘密keyをexportせず原byteへPSS salt32署名します。
	 * @param[in] raw 原manifestです。
	 * @return RAMだけの実署名byteです。
	 */
	[[nodiscard]] std::vector<std::uint8_t> sign( const std::string_view raw) const
	{
		auto					hash = digest( raw) ;					// 原manifestの独立digestです。
		BCRYPT_PSS_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM, 32} ;	// 固定salt32です。
		ULONG					size{} ;								// RSA3072の実署名容量です。
		require( BCryptSignHash( key, &padding, hash.data(), static_cast<ULONG>( hash.size()), nullptr,
							   0, &size, BCRYPT_PAD_PSS) >= 0) ;
		std::vector<std::uint8_t> value( size) ;	// 秘密鍵と異なる署名byteです。
		require( BCryptSignHash( key, &padding, hash.data(), static_cast<ULONG>( hash.size()),
							   value.data(), size, &size, BCRYPT_PAD_PSS) >= 0) ;
		return value ;
	}
} ;
/** @brief 独立digestを小文字hexへ表します。
 * @param[in] bytes 固定32byteのdigestです。
 * @return 全64桁のASCIIです。
 */
[[nodiscard]] std::string hex( const IndexManifestSha256 &bytes)
{
	std::string				   out ;							// 全byteの所有表現です。
	constexpr std::string_view DIGITS = "0123456789abcdef" ;	// 小文字alphabetです。
	// 全32byteを欠損なく変換します。
	for( const auto byte : bytes) {
		out += DIGITS[byte >> 4U] ;
		out += DIGITS[byte & 15U] ;
	}

	return out ;
}
/** @brief 人工byteを正規base64へ表します。
 * @param[in] raw 原byteです。
 * @return Paddingを保持するASCIIです。
 */
[[nodiscard]] std::string base64( const std::string_view raw)
{
	std::string				   out ;	// 人工wireの所有出力です。
	constexpr std::string_view ALPHABET =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ;	// 標準表です。
	// 原byteを三byteずつ完全に変換します。
	for( std::size_t i = 0; i < raw.size(); i += 3U) {
		const auto a = static_cast<unsigned char>( raw[i]) ;	// 第一byteです。
		const auto b =
			i + 1U < raw.size() ? static_cast<unsigned char>( raw[i + 1U]) : 0U ;	// 第二byteです。
		const auto c =
			i + 2U < raw.size() ? static_cast<unsigned char>( raw[i + 2U]) : 0U ;	// 第三byteです。
		out += ALPHABET[a >> 2U] ;
		out += ALPHABET[((a & 3U) << 4U) | (b >> 4U)] ;
		out += i + 1U < raw.size() ? ALPHABET[((b & 15U) << 2U) | (c >> 6U)] : '=' ;
		out += i + 2U < raw.size() ? ALPHABET[c & 63U] : '=' ;
	}

	return out ;
}
/** @brief 原JSONを一つのGZipへ実圧縮します。
 * @param[in] raw 架空indexの原byteです。
 * @return 実CRC/ISIZEを持つ一memberです。
 */
[[nodiscard]] std::string gzip( const std::string_view raw)
{
	std::vector<unsigned char> packed( raw.size() + 128U) ;						// 有限zlib容量です。
	mz_ulong				   size = static_cast<mz_ulong>( packed.size()) ;	// 実圧縮長です。
	const auto				  *input =
		reinterpret_cast<const unsigned char *>( raw.data()) ;	// minizへの読取りbyte借用です。
	require( mz_compress2( packed.data(), &size, input, static_cast<mz_ulong>( raw.size()),
						 MZ_BEST_COMPRESSION) == MZ_OK &&
			size >= 6U) ;
	std::string out{"\x1f\x8b\x08\0\0\0\0\0\0\xff", 10U} ;	// GZip固定headerです。
	out.append( reinterpret_cast<const char *>( packed.data() + 2U),
			   size - 6U) ;	// zlib framing以外の原Deflateだけです。
	const auto crc =
		// 独立CRCです。
		static_cast<std::uint32_t>( mz_crc32( MZ_CRC32_INIT, input, raw.size())) ;
	// CRCと元長をlittle endianで完全に付加します。
	for( const auto value : {crc, static_cast<std::uint32_t>( raw.size())}) {
		// 一値の四byteだけを表現します。
		for( unsigned shift = 0; shift < 32U; shift += 8U) {
			out += static_cast<char>( (value >> shift) & 255U) ;
		}
	}

	return out ;
}
/** @brief 既知取得申告を持つ一件の完全人工v2 recordを返します。
 * @param[in] expired 元attestationだけが期限切れの負例です。
 * @return 実driver検査を証明しない人工wireです。
 */
[[nodiscard]] std::string record( const bool expired)
{
	const std::string a( 64U, 'a') ;	// 架空公式出典digestです。
	const std::string b( 64U, 'b') ;	// 架空packageの申告digestです。
	return R"({"schema":"driver-index-record-v2","sourceId":"artificial-source","recordId":"artificial-acquisition","product":"Artificial acquisition purpose","targetOs":{"state":"KNOWN","value":"WINDOWS_11","reason":""},"architecture":{"state":"KNOWN","value":"X64","reason":""},"driverKind":{"state":"KNOWN","value":"NORMAL_DRIVER","reason":""},"version":{"state":"KNOWN","value":"1.2.3.4","reason":""},"publishedDate":{"state":"UNKNOWN","value":"","reason":"artificial date absent"},"acquisition":{"state":"KNOWN","value":"STANDARD_INF_ARCHIVE","reason":""},"packageEvidence":{"publishedHash":{"state":"UNKNOWN","sha256":"","evidenceUrl":"","evidenceSha256":"","reason":"artificial published hash absent"},"calculatedHash":{"state":"KNOWN","sha256":")" +
		   b + R"(","evidenceUrl":"https://vendor.example/package.zip","evidenceSha256":")" + b +
		   R"(","reason":""},"size":{"state":"KNOWN","valueBytes":22,"reason":""}},"lastSuccessfulObservationUtc":{"state":"KNOWN","value":"2026-10-13T12:00:00Z","reason":""},"inspectionStage":"CONTENT_INSPECTED","publishedIdentityEvidence":{"state":"PUBLISHED","kind":"INF","pnpIds":[{"kind":"HARDWARE","value":"PCI\\VEN_1234&DEV_5678"}],"classGuid":"{4D36E972-E325-11CE-BFC1-08002BE10318}","infIdentity":"driver/sample.inf","modelSection":"Models.NTamd64","evidenceUrl":"https://vendor.example/package.zip","evidenceSha256":")" +
		   b +
		   R"(","reason":""},"acquisitionDescriptor":{"schema":"driver-index-acquisition-v1","state":"KNOWN","reason":"","payloadUrl":"https://vendor.example/package.zip","fileName":"package.zip","format":"ZIP","expectedContentType":"application/zip","maximumBytes":1024,"route":[{"url":"https://vendor.example/package.zip","kind":"OFFICIAL_PAYLOAD_LINK","evidenceUrl":"https://vendor.example/support","evidenceSha256":")" +
		   a +
		   R"("}],"terms":{"state":"CONFIRMED_NO_CONSENT","reason":"","evidenceUrl":"https://vendor.example/support","evidenceSha256":")" +
		   a +
		   R"(","revisionKind":"NONE","revision":"","textDocument":null},"prerequisites":{"state":"KNOWN","reason":"","items":[]},"publisher":{"state":"KNOWN","value":"Artificial Package Publisher","reason":""},"attestation":{"kind":"COLLECTOR_VERIFIED_OFFICIAL_ROUTE","policyRevision":1,"checkedAtUtc":"2026-10-13T12:00:00Z","validUntilUtc":")" +
		   (expired ? "2026-10-13T17:00:00Z" : "2026-10-14T12:00:00Z") +
		   R"(","authorityMethod":"OFFICIAL_SITE_CONTROL_AND_LINK","authorityEvidenceUrl":"https://vendor.example/support","authorityEvidenceSha256":")" +
		   a + R"("}}})" ;
}
/** @brief 人工recordを原hashへ結ぶv2 indexを構成します。
 * @param[in] key RAM hash helperです。
 * @param[in] generation Asset世代です。
 * @param[in] expired 元attestationの負例です。
 * @return 一source/一recordの原indexです。
 */
[[nodiscard]] std::string index( const RamKey &key, const unsigned generation, const bool expired)
{
	const auto		  raw = record( expired) ;	// 原recordを再整形しません。
	const std::string a( 64U, 'a') ;			// 架空source出典digestです。
	return "{\"schema\":\"driver-index-records-v2\",\"assetGeneration\":" +
		   std::to_string( generation) +
		   R"(,"sources":[{"sourceId":"artificial-source","officialOrigin":"https://vendor.example/","distributionPage":"https://vendor.example/support","officialEvidence":{"state":"PUBLISHED","kind":"OFFICIAL_PAGE","evidenceUrl":"https://vendor.example/support","evidenceSha256":")" +
		   a + R"(","reason":""}}],"records":[{"recordBytesBase64":")" + base64( raw) +
		   R"(","recordSha256":")" + hex( key.digest( raw)) + R"("}]})" ;
}
/** @brief 一つの完全fake HTTP応答を所有します。 */
struct Hop {
	/// 原byteです。
	std::string	  body ;
	/// 実fixture応答statusです。
	DWORD		  status{200U} ;
	/// 同名headerの完全値です。
	std::wstring  mime{L"application/json; charset=utf-8"} ;
	/// Redirect専用の未検証値です。
	std::wstring  location ;
	/// 未知encodingの負例です。
	std::wstring  encoding ;
	/// Chunked相当の長さ欠損です。
	bool		  noLength{} ;
	/// 宣言長の誤記だけです。
	std::uint64_t extraLength{} ;
} ;
/** @brief 製品I/Oへfallbackしない一caseのRAM状態です。 */
struct Fixture {
	/// 事前固定した応答列です。
	std::vector<Hop>					  hops ;
	/// 現応答indexです。
	std::size_t							  hop{} ;
	/// 現本文の読取り位置です。
	std::size_t							  offset{} ;
	/// Request生成回数です。
	unsigned							  opens{} ;
	/// 実fake send回数です。
	unsigned							  sends{} ;
	/// URL検査後に到達したfake DNS照会回数です。
	unsigned							  resolves{} ;
	/// Session・connection・requestのfake解放回数です。
	unsigned							  closes{} ;
	/// Fake store呼出し回数です。
	unsigned							  commits{} ;
	/// Fake cache呼出し回数です。
	unsigned							  reloads{} ;
	/// 事前固定barrierの時計呼出し数です。
	unsigned							  utcCalls{} ;
	/// Fake headの現世代です。
	unsigned							  highWater{} ;
	/// Fake headの原digestです。
	IndexManifestSha256					  headHash{} ;
	/// Fakeの旧世代保持観測です。
	std::vector<unsigned>				  retained ;
	/// 同一取消しflagです。
	bool								  cancelled{} ;
	/// 受信中の停止barrierです。
	bool								  cancelRead{} ;
	/// 全codec後UTC照会の停止barrierです。
	bool								  cancelBeforeCommit{} ;
	/// 既commit後の停止barrierです。
	bool								  cancelAfterCommit{} ;
	/// 応答待機を90秒へ進める負例です。
	bool								  timeout{} ;
	/// CDN DNSをprivateへ変える負例です。
	bool								  privateCdn{} ;
	/// 能力を含まないfake cache観測です。
	bool								  cacheValid{} ;
	/// Expired cache観測です。
	bool								  cacheExpired{} ;
	/// UTC不明の負例です。
	bool								  unavailableUtc{} ;
	/// Commit直前の別更新です。
	bool								  concurrentAdvance{} ;
	/// 2は不確定、3は既commit/no snapshotです。
	unsigned							  commitFault{} ;
	/// Fake単調時計です。
	std::chrono::steady_clock::time_point monotonic{} ;
	/// Fake内だけの要求pathです。
	std::vector<std::wstring>			  paths ;
	/// 有限正数の実設定値です。
	std::vector<int>					  timeouts ;
} ;
// 同期単独unitだけの借用先です。native handleを作りません。
thread_local Fixture			   *ACTIVE{} ;

/** @brief 全WinHTTP ABIとresolverを完全fakeへ束ねます。
 * @return 欠損時にnativeへ補完されない全I/O表です。
 */
[[nodiscard]] OfficialHttpTransport transport()
{
	OfficialHttpTransport api ;	// 全fieldを直後に完全置換します。
	api.open		= []( LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) -> HINTERNET { return ACTIVE ; } ;
	api.connect		= []( HINTERNET, LPCWSTR, INTERNET_PORT, DWORD) -> HINTERNET { return ACTIVE ; } ;
	api.openRequest = []( HINTERNET, LPCWSTR, LPCWSTR path, LPCWSTR, LPCWSTR, LPCWSTR *,
						 DWORD) -> HINTERNET {
		ACTIVE->hop	   = ACTIVE->opens++ ;
		ACTIVE->offset = 0 ;
		ACTIVE->paths.emplace_back( path) ;
		return ACTIVE ;
	} ;
	api.setTimeouts = []( HINTERNET, int a, int b, int c, int d) -> BOOL {
		ACTIVE->timeouts.insert( ACTIVE->timeouts.end(), {a, b, c, d}) ;
		return TRUE ;
	} ;
	api.setOption	= []( HINTERNET, DWORD, LPVOID, DWORD) -> BOOL { return TRUE ; } ;
	api.addHeaders	= []( HINTERNET, LPCWSTR, DWORD, DWORD) -> BOOL { return TRUE ; } ;
	api.sendRequest = []( HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR) -> BOOL {
		++ACTIVE->sends ;
		return TRUE ;
	} ;
	api.receiveResponse = []( HINTERNET, LPVOID) -> BOOL {
		// 一度の応答待機だけで期限境界へ進め、retryは要求しません。
		if( ACTIVE->timeout) {
			ACTIVE->monotonic += std::chrono::seconds{90} ;
			SetLastError( ERROR_WINHTTP_TIMEOUT) ;
			return FALSE ;
		}

		return TRUE ;
	} ;
	api.queryHeaders = []( HINTERNET, DWORD query, LPCWSTR, LPVOID buffer, LPDWORD bytes,
						  LPDWORD headerIndex) -> BOOL {
		// WinHTTPの同名header位置は本照会成功時だけ前進し、二件目は欠損です。
		if( headerIndex != nullptr && *headerIndex != 0U) {
			SetLastError( ERROR_WINHTTP_HEADER_NOT_FOUND) ;
			return FALSE ;
		}

		// 予定外のrequestを成功応答で補完しません。
		if( ACTIVE->hop >= ACTIVE->hops.size()) {
			SetLastError( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
			return FALSE ;
		}

		const auto &h = ACTIVE->hops[ACTIVE->hop] ;	// 同一応答の固定headerです。
		// Status照会だけはWinHTTPの数値ABIを使用します。
		if( (query & WINHTTP_QUERY_FLAG_NUMBER) != 0U) {
			*static_cast<DWORD *>( buffer) = h.status ;
			*bytes						  = sizeof( DWORD) ;
			return TRUE ;
		}

		const DWORD	 kind = query & 0xffffU ;	// Header名の共通indexです。
		std::wstring value ;					// 一headerだけの有限値です。
		// MIMEをそのまま返します。
		if( kind == WINHTTP_QUERY_CONTENT_TYPE) {
			value = h.mime ;
		}
		// Locationは3xx fixtureだけにあります。
		else if( kind == WINHTTP_QUERY_LOCATION) {
			value = h.location ;
		}
		// 未知encodingの負例以外は欠損です。
		else if( kind == WINHTTP_QUERY_CONTENT_ENCODING) {
			value = h.encoding ;
		}
		// 宣言長を実byteと独立に生成します。
		else if( kind == WINHTTP_QUERY_CONTENT_LENGTH && !h.noLength) {
			value = std::to_wstring( h.body.size() + h.extraLength) ;
		}

		// 欠損headerを空の成功値へ変換しません。
		if( value.empty()) {
			SetLastError( ERROR_WINHTTP_HEADER_NOT_FOUND) ;
			return FALSE ;
		}

		const auto required = static_cast<DWORD>( (value.size() + 1U) *
												 // 終端込みのWinHTTP容量です。
												 sizeof( wchar_t)) ;
		// 第一照会と不足bufferは必要容量だけを返します。
		if( buffer == nullptr || *bytes < required) {
			*bytes = required ;
			SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			return FALSE ;
		}

		std::memcpy( buffer, value.c_str(), required) ;
		// Probeではなく本照会だけが次の同名headerへ進みます。
		if( headerIndex != nullptr) {
			++*headerIndex ;
		}

		*bytes = static_cast<DWORD>( value.size() * sizeof( wchar_t)) ;
		return TRUE ;
	} ;
	api.queryAvailable = []( HINTERNET, LPDWORD available) -> BOOL {
		*available = static_cast<DWORD>( ACTIVE->hops.at( ACTIVE->hop).body.size() - ACTIVE->offset) ;
		return TRUE ;
	} ;
	api.readData = []( HINTERNET, LPVOID output, DWORD requested, LPDWORD received) -> BOOL {
		const auto &body = ACTIVE->hops.at( ACTIVE->hop).body ;	// 同じ原本文です。
		*received =
			static_cast<DWORD>( std::min<std::size_t>( requested, body.size() - ACTIVE->offset)) ;
		std::memcpy( output, body.data() + ACTIVE->offset, *received) ;
		ACTIVE->offset += *received ;
		// 同期待機中の取消しをAPI復帰直後に観測させます。
		if( ACTIVE->cancelRead) {
			ACTIVE->cancelled = true ;
		}

		return TRUE ;
	} ;
	api.closeHandle = []( HINTERNET) -> BOOL {
		++ACTIVE->closes ;
		return TRUE ;
	} ;
	api.resolveDestination = []( const std::wstring_view						 host,
								std::vector<OfficialResolvedNetworkAddress> &out) {
		++ACTIVE->resolves ;
		OfficialResolvedNetworkAddress address ;	// 実DNSを使わない全一addressです。
		address.bytes[0] = std::byte{8} ;
		address.bytes[1] = std::byte{8} ;
		address.bytes[2] = std::byte{8} ;
		address.bytes[3] = std::byte{8} ;
		// 許可CDNでもprivate addressは共通validatorへ渡して拒否させます。
		if( ACTIVE->privateCdn && host == L"release-assets.githubusercontent.com") {
			address.bytes[0] = std::byte{127} ;
		}

		out = {address} ;
		return static_cast<NativeError>( 0) ;
	} ;
	api.utcNow = []() { return 0ULL ; } ;
	return api ;
}

/** @brief 一caseの原manifestを実RAM署名へ結合します。
 * @param[in] key 非永続署名ownerです。
 * @param[in] packed 原gzipです。
 * @param[in] generation Manifest世代です。
 * @param[in] assetGeneration 参照asset世代です。
 * @param[in] mode 固定caseの番号です。
 * @return 再serializationしない署名envelopeです。
 */
[[nodiscard]] std::string envelope( const RamKey &key, const std::string &packed,
								   const unsigned generation, const unsigned assetGeneration,
								   const unsigned mode)
{
	const std::string keyId =
		// 実製品鍵と分離します。
		mode == 6U ? "local-index-acceptance-fixture" : "fixture-refresh" ;
	const auto		  digest = hex( key.digest( packed)) ;	// 原圧縮hashです。
	const std::string published =
		// 未来負例です。
		mode == 10U ? "2026-10-13T19:00:00Z" : "2026-10-13T12:00:00Z" ;
	const std::string expires =
		// 期限切れ負例です。
		mode == 9U ? "2026-10-13T17:00:00Z" : "2026-10-14T12:00:00Z" ;
	const std::string raw =
		"{\"schema\":\"driver-index-manifest-v1\",\"repository\":\"EnterOgawa/drivercrate\",\"channel\":\"driver-index\",\"keyId\":\"" +
		keyId + "\",\"generation\":" + std::to_string( generation) +
		",\"assetGeneration\":" + std::to_string( assetGeneration) + ",\"publishedAtUtc\":\"" +
		published + "\",\"expiresAtUtc\":\"" + expires +
		"\",\"asset\":{\"tag\":\"index-v1-20261013-" + digest +
		"\",\"name\":\"index.json.gz\",\"compression\":\"gzip\",\"sizeBytes\":" +
		std::to_string( packed.size()) + ",\"sha256\":\"" + digest +
		// 既知一件の人工申告です。
		"\"},\"quality\":{\"sourceCount\":1,\"recordCount\":1,\"metadataOnlyCount\":0,\"contentInspectedCount\":1,\"unconfirmedCount\":0}}" ;
	// PSS salt32の実原署名です。
	auto signature = key.sign( raw) ;
	// 原署名だけを変更し、暗号拒否を実validatorへ到達させます。
	if( mode == 5U) {
		signature[0] ^= 1U ;
	}

	const std::string_view signedBytes{reinterpret_cast<const char *>( signature.data()),
									   // 公開署名byteの非所有viewです。
									   signature.size()} ;
	return "{\"schema\":\"driver-index-envelope-v1\",\"keyId\":\"" + keyId +
		   "\",\"manifestBytesBase64\":\"" + base64( raw) + "\",\"signatureBase64\":\"" +
		   base64( signedBytes) + "\"}" ;
}
}

/** @see runSignedIndexRefreshTests宣言側の契約を正本とします。 */
void runSignedIndexRefreshTests( TestContext &context)
{
	const int groupFirstAssertion = context.assertionCount() ;	// 旧34件の開始時点です。
	const int groupFirstFailure	  = context.failureCount() ;	// 旧34件以前の失敗を区別します。
	int		  boundaryAssertion	  = 0 ;							// 七境界へ進む直前の実件数を後で確定します。
	int		  boundaryFailure	  = 0 ;							// 七境界へ進む直前の実失敗数を後で確定します。
	RamKey	  key ;												// 全caseだけの非永続RSA3072です。
	key.generate() ;
	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{"fixture-refresh", key.publicBlob}}} ;	// RAM正例だけの内部集合です。
	constexpr std::array<std::string_view, 41U> IDS{
		"T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09", "T10", "T11",
		"T12", "T13", "T14", "T15", "T16", "T17", "T18", "V01", "V02", "V03", "V04",
		"V05", "V06", "V07", "V08", "V09", "V10", "V11", "V12", "V13", "V14", "V15",
		"V16", "B01", "B02", "B03", "B04", "B05", "B06", "B07"} ;	// 旧34件と新七件の固定分母です。
	constexpr std::array<IndexRefreshStatus, 41U> EXPECTED{
		IndexRefreshStatus::REFRESHED,			 IndexRefreshStatus::REFRESHED,
		IndexRefreshStatus::REFRESHED,			 IndexRefreshStatus::STORE_FAILED,
		IndexRefreshStatus::MANIFEST_REJECTED,	 IndexRefreshStatus::MANIFEST_REJECTED,
		IndexRefreshStatus::ASSET_REJECTED,		 IndexRefreshStatus::RECORDS_REJECTED,
		IndexRefreshStatus::MANIFEST_REJECTED,	 IndexRefreshStatus::MANIFEST_REJECTED,
		IndexRefreshStatus::TIME_UNAVAILABLE,	 IndexRefreshStatus::HTTP_FAILED,
		IndexRefreshStatus::TIMED_OUT,			 IndexRefreshStatus::HTTP_FAILED,
		IndexRefreshStatus::HTTP_FAILED,		 IndexRefreshStatus::CANCELLED,
		IndexRefreshStatus::AUTHENTICATED_CACHE, IndexRefreshStatus::HTTP_FAILED,
		IndexRefreshStatus::STORE_FAILED,		 IndexRefreshStatus::STORE_FAILED,
		IndexRefreshStatus::STORE_FAILED,		 IndexRefreshStatus::HTTP_FAILED,
		IndexRefreshStatus::HTTP_FAILED,		 IndexRefreshStatus::HTTP_FAILED,
		IndexRefreshStatus::CANCELLED,			 IndexRefreshStatus::CANCELLED,
		IndexRefreshStatus::CANCELLED,			 IndexRefreshStatus::HTTP_FAILED,
		IndexRefreshStatus::REFRESHED,			 IndexRefreshStatus::HTTP_FAILED,
		IndexRefreshStatus::HTTP_FAILED,		 IndexRefreshStatus::ASSET_REJECTED,
		IndexRefreshStatus::RECORDS_REJECTED,	 IndexRefreshStatus::STORE_FAILED,
		IndexRefreshStatus::HTTP_FAILED,		 IndexRefreshStatus::HTTP_FAILED,
		IndexRefreshStatus::HTTP_FAILED,		 IndexRefreshStatus::REFRESHED,
		IndexRefreshStatus::HTTP_FAILED,		 IndexRefreshStatus::HTTP_FAILED,
		IndexRefreshStatus::HTTP_FAILED} ;	// 元34件の期待を保持して七境界だけを追加します。
	// 失敗を分母から除かず全固定caseを一度ずつ実行します。
	for( unsigned mode = 1U; mode <= IDS.size(); ++mode) {
		const auto firstFailure = context.failureCount() ;	// 当caseだけの原失敗差です。
		Fixture	   fixture ;								// native I/Oを持たない一caseの所有状態です。
		ACTIVE					  = &fixture ;
		const unsigned generation = mode == 3U
										? 3U
										: (mode == 2U || mode == 19U || mode == 27U || mode == 34U
											   ? 2U
											   : 1U) ;	// 原manifest世代です。
		const unsigned assetGeneration =
			// 旧immutable参照を保持します。
			mode == 3U ? 1U : generation ;
		std::string expanded =
			mode == 8U
				? R"({"schema":"research-v3"})"
				: (mode == 32U ? std::string( 1024U * 1024U, 'a')
							   : index( key, assetGeneration, mode == 33U)) ;	// 各実codec負例です。
		const std::string packed = gzip( expanded) ;							// 実Deflate/CRC/ISIZEです。
		const std::string current =
			// 原署名入力です。
			envelope( key, packed, generation, assetGeneration, mode) ;
		fixture.hops	  = {{current, 200U, L"application/json; charset=utf-8"},
							 {packed, 200U, L"application/gzip"}} ;
		fixture.highWater = mode == 2U ? 1U : (mode == 3U || mode == 4U || mode == 19U ? 2U : 0U) ;
		// 旧headの原digestを固定し、同世代原byte競合を作ります。
		if( fixture.highWater != 0U) {
			fixture.headHash.fill( 7U) ;
			fixture.retained.push_back( fixture.highWater) ;
		}

		// 原gzip改変だけをbyte validatorへ渡します。
		if( mode == 7U) {
			fixture.hops[1].body[12] ^= 1 ;
		}

		fixture.unavailableUtc	   = mode == 11U ;
		fixture.timeout			   = mode == 13U ;
		fixture.cancelRead		   = mode == 16U ;
		fixture.cacheValid		   = mode == 17U ;
		fixture.cacheExpired	   = mode == 18U ;
		fixture.cancelled		   = mode == 25U ;
		fixture.cancelBeforeCommit = mode == 26U ;
		fixture.cancelAfterCommit  = mode == 27U ;
		fixture.concurrentAdvance  = mode == 34U ;
		fixture.commitFault		   = mode == 20U ? 2U : (mode == 21U ? 3U : 0U) ;
		// Source不在と一時応答を元statusで保持します。
		if( mode == 12U || mode == 17U || mode == 18U) {
			fixture.hops[0].status = mode == 12U ? 404U : 503U ;
		}

		// Current上限を宣言長だけで超える負例です。
		if( mode == 15U) {
			fixture.hops[0].extraLength = INDEX_ENVELOPE_MAX_BYTES + 1U ;
		}

		// Currentの実bodyだけを上限+1へし、chunked probeも検査します。
		if( mode == 23U) {
			fixture.hops[0].body.assign( INDEX_ENVELOPE_MAX_BYTES + 1U, ' ') ;
			fixture.hops[0].noLength = true ;
		}

		// Assetの署名size+1をchunked原byteで検査します。
		if( mode == 24U) {
			fixture.hops[1].body += 'x' ;
			fixture.hops[1].noLength = true ;
		}

		// Current redirectは一切追跡しません。
		if( mode == 28U) {
			fixture.hops[0].status	 = 302U ;
			fixture.hops[0].location = L"https://outside.example/current.json" ;
		}

		// 許可CDNへの導線だけを、public/unsafe DNSの正負へ分けます。
		if( mode == 14U || mode == 29U) {
			fixture.hops[1].status = 302U ;
			fixture.hops[1].location =
				L"https://release-assets.githubusercontent.com/fixed/asset?token=fixture-only" ;
			fixture.hops.push_back( {packed, 200U, L"application/octet-stream"}) ;
			fixture.privateCdn = mode == 14U ;
		}

		// 宣言長と原byteの不一致を成功へしません。
		if( mode == 30U) {
			fixture.hops[0].extraLength = 1U ;
		}

		// HTTP自動圧縮を原署名byteとして解釈しません。
		if( mode == 31U) {
			fixture.hops[0].encoding = L"gzip" ;
		}

		// 新七境界はcurrent成功後のasset redirectだけを変更します。
		if( mode >= 35U) {
			fixture.hops[1].status = 302U ;
			fixture.cacheValid	   = true ;
		}

		// 任意hostを許可CDNとしてDNS照会する前に拒否させます。
		if( mode == 35U) {
			fixture.hops[1].location = L"https://outside.example/boundary/1" ;
		}

		// 許可hostでもuserinfoを含む導線は送信前に拒否させます。
		if( mode == 36U) {
			fixture.hops[1].location =
				L"https://fixture-user@release-assets.githubusercontent.com/boundary/1" ;
		}

		// 一度CDNへ進んだ後のGitHubへの逆戻りを次のDNSより前に拒否させます。
		if( mode == 37U) {
			fixture.hops[1].location = L"https://release-assets.githubusercontent.com/boundary/1" ;
			fixture.hops.push_back(
				{"", 302U, L"application/gzip",
				 L"https://github.com/EnterOgawa/drivercrate/releases/download/return/index.json.gz"}) ;
		}

		// 三redirectの最終成功と四redirectの追加送信拒否を同じ長さの前半導線で分けます。
		if( mode == 38U || mode == 39U) {
			fixture.hops[1].location = L"https://release-assets.githubusercontent.com/boundary/1" ;
			fixture.hops.push_back( {"", 302U, L"application/gzip",
									L"https://release-assets.githubusercontent.com/boundary/2"}) ;
			fixture.hops.push_back( {"", 302U, L"application/gzip",
									L"https://release-assets.githubusercontent.com/boundary/3"}) ;
			fixture.hops.push_back( {packed, 200U, L"application/gzip"}) ;
			// 四redirect目の応答では第五asset用の予定bodyを用意しても送信させません。
			if( mode == 39U) {
				fixture.hops[4].status = 302U ;
				fixture.hops[4].location =
					L"https://release-assets.githubusercontent.com/boundary/4" ;
				fixture.hops.push_back( {packed, 200U, L"application/gzip"}) ;
			}
		}

		// 同じCDN URLの循環を次のDNS・送信より先に検出させます。
		if( mode == 40U) {
			fixture.hops[1].location = L"https://release-assets.githubusercontent.com/boundary/1" ;
			fixture.hops.push_back( {"", 302U, L"application/gzip",
									L"https://release-assets.githubusercontent.com/boundary/1"}) ;
		}

		// HTTPSでも標準443以外のportを送信前に拒否させます。
		if( mode == 41U) {
			fixture.hops[1].location =
				L"https://release-assets.githubusercontent.com:444/boundary/1" ;
		}

		signed_index_refresh_detail::Services services ;	// 完全fakeの全依存です。
		services.transport = transport() ;
		// 欠損transportはnativeへfallbackしません。
		if( mode == 22U) {
			services.transport->readData = nullptr ;
		}

		services.fixtureTrust = mode == 6U ? std::span<const signed_index_detail::TrustKey>{}
										   : std::span<const signed_index_detail::TrustKey>{trust} ;
		services.utcNow		  = [&fixture]() -> std::optional<std::chrono::sys_seconds> {
			  ++fixture.utcCalls ;
			  // 全codecと個別期限照合後、commit直前の固定barrierです。
			  if( fixture.cancelBeforeCommit && fixture.utcCalls == 5U) {
				  fixture.cancelled = true ;
			  }

			  return fixture.unavailableUtc ? std::nullopt
												: std::optional<std::chrono::sys_seconds>{NOW} ;
		} ;
		services.monotonicNow = [&fixture]() { return fixture.monotonic ; } ;
		services.reload		  = [&fixture]( std::optional<std::chrono::sys_seconds>) {
			  ++fixture.reloads ;
			  IndexRefreshStoreObservation result ;	// 能力なしのfake観測だけです。
			  result.status			= fixture.cacheValid
											  ? IndexStoreStatus::SNAPSHOT_READY
											  : (fixture.cacheExpired ? IndexStoreStatus::EXPIRED
																	  : IndexStoreStatus::EMPTY_STORE) ;
			  result.usableSnapshot = fixture.cacheValid ;
			  return result ;
		} ;
		services.commit = [&]( const IndexRecordsSchemaReceipt &receipt, const std::string_view raw,
							  std::span<const std::byte>,
							  const std::optional<std::chrono::sys_seconds> now) {
			++fixture.commits ;
			IndexRefreshStoreObservation result ;	// Atomic diskを持たないfake観測です。
			DRIVERCRATE_EXPECT( context, receipt.records().size() == 1U &&
											receipt.records()[0].inspectionStage ==
												IndexInspectionStage::CONTENT_INSPECTED) ;
			// 通信後の別更新をfake排他境界で初めて反映します。
			if( fixture.concurrentAdvance) {
				fixture.highWater = 3U ;
				fixture.headHash.fill( 8U) ;
			}

			const auto water =
				fixture.highWater == 0U
					? std::optional<IndexManifestHighWater>{}
					: std::optional<IndexManifestHighWater>{
						  {fixture.highWater, fixture.headHash}} ;	// 最新fake headだけです。
			const auto checked = signed_index_detail::authenticateWithTrustKeys(
				raw, now, water, trust) ;	// 高水位判定自体は実暗号/世代validatorです。
			result.persistedGeneration = fixture.highWater ;
			// Rollback/conflictを成功statusだけで上書きしません。
			if( !checked.manifest) {
				result.status		  = IndexStoreStatus::MANIFEST_REJECTED ;
				result.manifestStatus = checked.status ;
				result.error		  = checked.error ;
				return result ;
			}

			// Commit不確定は保存成功を推測しません。
			if( fixture.commitFault == 2U) {
				result.status = IndexStoreStatus::COMMIT_UNCERTAIN ;
				result.commit = IndexStoreCommitDisposition::UNKNOWN ;
				result.error  = HRESULT_FROM_WIN32( ERROR_GEN_FAILURE) ;
				return result ;
			}

			fixture.highWater = static_cast<unsigned>( checked.manifest->data().generation) ;
			fixture.headHash  = checked.manifest->data().manifestSha256 ;
			fixture.retained.push_back( fixture.highWater) ;
			result.persistedGeneration = fixture.highWater ;
			result.commit			   = IndexStoreCommitDisposition::COMMITTED ;
			result.status = fixture.commitFault == 3U ? IndexStoreStatus::COMMITTED_NO_SNAPSHOT
													  : IndexStoreStatus::SNAPSHOT_READY ;
			result.usableSnapshot = fixture.commitFault != 3U ;
			// 既commit後の取消しをNO_CHANGEへ戻しません。
			if( fixture.cancelAfterCommit) {
				fixture.cancelled = true ;
			}

			return result ;
		} ;
		const auto result = signed_index_refresh_detail::Access::forTest( services, [&fixture]() {
			return fixture.cancelled ;
		}) ; // 製品HTTP/codec/glueの実入口です。
		DRIVERCRATE_EXPECT( context, result.status == EXPECTED[mode - 1U]) ;
		DRIVERCRATE_EXPECT( context, result.sends == fixture.sends && fixture.sends <= 5U) ;
		DRIVERCRATE_EXPECT(
			context, std::all_of( fixture.timeouts.begin(), fixture.timeouts.end(),
								 []( const int value) { return value > 0 && value <= 90000 ; })) ;
		// Cache利用時も元refresh失敗を必須にします。
		if( mode == 17U) {
			DRIVERCRATE_EXPECT( context, result.usedAuthenticatedCache &&
											result.httpStatus == 503U && result.httpError != 0U &&
											result.error == result.httpError &&
											fixture.reloads == 1U) ;
		}

		// 期限切れcacheを候補能力へ昇格しません。
		if( mode == 18U) {
			DRIVERCRATE_EXPECT( context, !result.usedAuthenticatedCache && result.cache &&
											result.cache->status == IndexStoreStatus::EXPIRED) ;
		}

		// 過去asset参照でもmanifest高水位は上げたままです。
		if( mode == 3U) {
			DRIVERCRATE_EXPECT( context, result.attemptedGeneration == 3U &&
											result.store.persistedGeneration == 3U &&
											fixture.retained == std::vector<unsigned>( {2U, 3U})) ;
		}

		// 世代拒否と競合はcache呼出し0のまま保持します。
		if( mode == 4U || mode == 19U || mode == 34U) {
			DRIVERCRATE_EXPECT(
				context, result.manifestStatus ==
								 (mode == 19U ? SignedIndexManifestStatus::GENERATION_CONFLICT
											  : SignedIndexManifestStatus::GENERATION_ROLLBACK) &&
							 fixture.reloads == 0U) ;
		}

		// Crypto/key拒否はasset GET/保存/cacheへ進みません。
		if( mode == 5U || mode == 6U) {
			DRIVERCRATE_EXPECT( context, fixture.sends == 1U && fixture.commits == 0U &&
											fixture.reloads == 0U) ;
		}

		// Private DNSのhopは未送信のまま拒否します。
		if( mode == 14U) {
			DRIVERCRATE_EXPECT( context, fixture.sends == 2U && fixture.commits == 0U) ;
		}

		// 完全fixture欠損、UTC不明、送信前取消しはsend0です。
		if( mode == 11U || mode == 22U || mode == 25U) {
			DRIVERCRATE_EXPECT( context, fixture.sends == 0U && fixture.commits == 0U) ;
		}

		// 取消し前後で保存事実を区別します。
		if( mode == 16U || mode == 26U) {
			DRIVERCRATE_EXPECT( context,
							   fixture.commits == 0U &&
								   result.store.commit == IndexStoreCommitDisposition::NO_CHANGE &&
								   fixture.reloads == 0U) ;
		}

		// 不確定/既commit/no snapshotと取消し後の事実を別に保持します。
		if( mode == 20U || mode == 21U || mode == 27U) {
			DRIVERCRATE_EXPECT( context,
							   result.store.commit ==
									   (mode == 20U ? IndexStoreCommitDisposition::UNKNOWN
													: IndexStoreCommitDisposition::COMMITTED) &&
								   !result.usedAuthenticatedCache) ;
		}

		// 許可されたCDN queryは三sendの範囲だけで取得します。
		if( mode == 29U) {
			DRIVERCRATE_EXPECT( context,
							   fixture.sends == 3U &&
								   fixture.paths.back() == L"/fixed/asset?token=fixture-only") ;
		}

		// Current capのprobeは最大+1を超えて受信しません。
		if( mode == 23U) {
			DRIVERCRATE_EXPECT( context, result.receivedBytes == INDEX_ENVELOPE_MAX_BYTES + 1U) ;
		}

		// 七境界の送信・DNS・解放・保存と元診断を個別の固定期待へ結びます。
		if( mode >= 35U) {
			constexpr std::array<unsigned, 7U> SENDS{2U, 2U, 3U, 5U,
													 5U, 3U, 2U} ;	// Currentを含みます。
			const unsigned	  expectedSends = SENDS[mode - 35U] ;	// 新七件だけの固定分母です。
			const bool		  accepted		= mode == 38U ;			// 三redirect後の実本文だけが正例です。
			const NativeError expectedError =
				accepted
					? 0U
					: (mode == 39U || mode == 40U
						   ? static_cast<NativeError>(
								 HRESULT_FROM_WIN32( ERROR_WINHTTP_REDIRECT_FAILED))
						   : static_cast<NativeError>( E_ACCESSDENIED)) ;	// 任意errorへ広げません。
			DRIVERCRATE_EXPECT( context, fixture.sends == expectedSends &&
											fixture.opens == expectedSends &&
											fixture.paths.size() == expectedSends) ;
			DRIVERCRATE_EXPECT( context, fixture.resolves == expectedSends) ;
			DRIVERCRATE_EXPECT( context, fixture.closes == expectedSends * 3U) ;
			DRIVERCRATE_EXPECT( context, result.error == expectedError &&
											result.httpError == expectedError &&
											result.httpStatus == (accepted ? 200U : 302U)) ;
			DRIVERCRATE_EXPECT( context, fixture.commits == (accepted ? 1U : 0U) &&
											fixture.reloads == 0U &&
											!result.usedAuthenticatedCache && !result.cache) ;
			DRIVERCRATE_EXPECT( context, result.attemptedGeneration == 1U && !result.assetStatus &&
											!result.recordsStatus) ;
			DRIVERCRATE_EXPECT( context, result.store.commit ==
											(accepted ? IndexStoreCommitDisposition::COMMITTED
													  : IndexStoreCommitDisposition::NO_CHANGE)) ;
			// 上限正負は第四asset hopまでとし、禁止した第五hopのpathを残しません。
			if( mode == 38U || mode == 39U) {
				DRIVERCRATE_EXPECT( context, fixture.paths.back() == L"/boundary/3") ;
			}
		}

		std::cout << "P4 case " << IDS[mode - 1U]
				  << " reached=1 status=" << static_cast<int>( result.status)
				  << " error=" << result.error << " httpError=" << result.httpError
				  << " httpStatus=" << result.httpStatus << " manifest="
				  << (result.manifestStatus ? static_cast<int>( *result.manifestStatus) : -1)
				  << " asset=" << (result.assetStatus ? static_cast<int>( *result.assetStatus) : -1)
				  << " records="
				  << (result.recordsStatus ? static_cast<int>( *result.recordsStatus) : -1)
				  << " store=" << static_cast<int>( result.store.status)
				  << " commit=" << static_cast<int>( result.store.commit)
				  << " sends=" << fixture.sends << " commits=" << fixture.commits
				  << " reloads=" << fixture.reloads << " resolves=" << fixture.resolves
				  << " closes=" << fixture.closes << " requests=" << fixture.opens
				  << " fakeStore=1 failures=" << context.failureCount() - firstFailure << '\n' ;
		ACTIVE = nullptr ;
		// 元34件の実分母を新七件と混ぜず、実行済み差だけを原summaryへ残します。
		if( mode == 34U) {
			boundaryAssertion = context.assertionCount() ;
			boundaryFailure	  = context.failureCount() ;
			std::cout << "P4 legacy reached cases: 34, assertions: "
					  << boundaryAssertion - groupFirstAssertion
					  << ", failures: " << boundaryFailure - groupFirstFailure << '\n' ;
		}
	}

	std::cout << "P4 boundary reached cases: 7, assertions: "
			  << context.assertionCount() - boundaryAssertion
			  << ", failures: " << context.failureCount() - boundaryFailure << '\n' ;
	std::cout << "P4 reached cases: " << IDS.size() << ", assertions: " << context.assertionCount()
			  << ", failures: " << context.failureCount() << '\n' ;
}
} // namespace drivercrate::test
