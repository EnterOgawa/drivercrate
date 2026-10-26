//------------------------------------------------------------------------------
/**
 * @file local_index_signing_tests.cpp
 * @brief 明示既存local鍵の原byte署名と既存native索引の相互検査です。
 * @version 01.07.00
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/13  実保護鍵・原byte・世代・能力分離の明示testを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/14  実収集v2の固定pin／実保存／更新復帰検証modeを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/14  取得用途の人工正常/UNKNOWN/実asset改変拒否を別検証。
 * Ver.01.03.00 Shunji Ogawa  2026/10/15  非永続の人工配布鍵で用途と全codec拒否を検査。
 * Ver.01.03.01 Shunji Ogawa  2026/10/16  P1原byteと配布取得用途のRAM正負を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/17  公開検証CLI用の実UTC人工RAM署名fixture出力を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/17  取得履歴の固定32条件と公開CLI用失効/未来fixtureを追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/24  現行nested member identityと原record完全tupleへ整合。
 * Ver.01.07.00 Shunji Ogawa  2026/10/24  Record非評価の世代下限専用認証をRAMで有限検査。
 * </pre>
 *
 * @note 既存鍵は明示existing-key modeだけで照会し、配布fakeは人工RAM鍵だけを使います。
 * Persistent鍵作成・実HTTP・実device・導入は0です。UNKNOWNを取得許可へ昇格しません。
 * 公開検証CLI用fixtureは実UTCを元に新規一意directoryだけへ保存します。
 * @see docs/adr/0337-local-index-signing-and-build-pins.md
 */
//------------------------------------------------------------------------------
#include "platform/local_index_signing.h"
#include "platform/signed_index_manifest_internal.h"
#include "platform/signed_index_asset_bytes.h"
#include "platform/signed_index_records.h"
#include "platform/signed_index_store_internal.h"
#include "platform/signed_index_record_lookup.h"
#include "platform/signed_index_acquisition_adapter.h"
#include "platform/official_file_verifier.h"
#include "local_index_acceptance.h"
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <miniz.h>

namespace {

// OS時計を期待結果へ使わない固定UTCです。
const std::chrono::sys_seconds NOW =
	std::chrono::sys_days{std::chrono::year{2026} / 10 / 13} + std::chrono::hours{13} ;
// 非秘密の有限assertion集計です。
unsigned assertions{} ;
// 原失敗を除外しない有限failure集計です。
unsigned failures{} ;

/** @brief 一つの固定期待を実結果から数えます。
 * @param[in] value 期待成立の場合だけtrueです。
 * @param[in] name 非秘密の固定条件名です。
 */
void	 expect( const bool value, const char *name)
{
	++assertions ;
	// 成功も原case名へ結合します。
	std::printf( "CASE name=%s passed=%u\n", name, value ? 1U : 0U) ;
	// 原不成立を集計から除外しません。
	if( !value) {
		++failures ;
		std::printf( "FAIL %s\n", name) ;
	}
}

/** @brief Fixture前段失敗で後続成功を合成しないguardです。
 * @param[in] value 前段が成立した場合だけtrueです。
 */
void require( const bool value)
{
	// 前段失敗時は全体失敗へ残して後続testを中断します。
	if( !value) {
		throw std::runtime_error( "local signing fixture prerequisite failed") ;
	}
}

/** @brief 非秘密の原byteを既存共通SHA-256へ結合します。
 * @param[in] raw 不変の人工原byteです。
 * @return 小文字64桁の実digestです。
 */
[[nodiscard]] std::string hash( const std::string_view raw)
{
	std::wstring value ;	// 共通APIの原digestです。
	require( drivercrate::computeBytesSha256( raw, value) == 0) ;
	std::string result ;	// ASCII digestだけの明示変換結果です。
	// 共通hashの各文字を小文字hexへ限定します。
	for( const auto character : value) {
		require( (character >= L'0' && character <= L'9') ||
				(character >= L'a' && character <= L'f')) ;
		result.push_back( static_cast<char>( character)) ;
	}

	return result ;
}

/** @brief 人工recordを改行なしbase64で原byteへ結合します。
 * @param[in] raw 原UTF-8 recordです。
 * @return 標準base64です。
 */
[[nodiscard]] std::string encode( const std::string_view raw)
{
	DWORD			size{} ;	// 有限encoder容量です。
	// SDKの公開byte入力境界だけで文字viewを借用します。
	const auto	   *input = reinterpret_cast<const BYTE *>( raw.data()) ;
	constexpr DWORD FLAGS = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF ;	// Codecの標準字句です。
	require( CryptBinaryToStringA( input, static_cast<DWORD>( raw.size()), FLAGS, nullptr, &size) !=
			FALSE) ;
	std::string value( size, '\0') ;	// 終端を含む出力bufferです。
	require( CryptBinaryToStringA( input, static_cast<DWORD>( raw.size()), FLAGS, value.data(),
								 &size) != FALSE) ;
	value.resize( std::strlen( value.c_str())) ;
	return value ;
}

/** @brief 人工UNKNOWN v2 recordを一件だけ持つ索引を作ります。
 * @return 通信・適合・取得根拠を持たない人工原indexです。
 */
[[nodiscard]] std::string indexBytes()
{
	const std::string unknown =
		R"({"state":"UNKNOWN","value":"","reason":"artificial not supplied"})" ;	// 未確認を明示します。
	const std::string unknownHash =
		// 実hash申告を合成しません。
		R"({"state":"UNKNOWN","sha256":"","evidenceUrl":"","evidenceSha256":"","reason":"artificial not inspected"})" ;
	const std::string record =
		std::string{
			R"({"schema":"driver-index-record-v2","sourceId":"artificial-source","recordId":"artificial-unknown","product":"Artificial signing bridge",)"} +
		"\"targetOs\":" + unknown + ",\"architecture\":" + unknown + ",\"driverKind\":" + unknown +
		",\"version\":" + unknown + ",\"publishedDate\":" + unknown +
		",\"acquisition\":" + unknown + ",\"packageEvidence\":{\"publishedHash\":" + unknownHash +
		",\"calculatedHash\":" + unknownHash +
		R"(,"size":{"state":"UNKNOWN","valueBytes":0,"reason":"artificial not inspected"}},"lastSuccessfulObservationUtc":)" +
		unknown +
		// UNKNOWNを成功へ昇格しません。
		R"(,"inspectionStage":"METADATA_ONLY","publishedIdentityEvidence":{"state":"UNKNOWN","kind":"UNKNOWN","pnpIds":[],"classGuid":"","nestedArchiveIdentity":"","infIdentity":"","modelSection":"","evidenceUrl":"","evidenceSha256":"","reason":"artificial public identity absent"},"acquisitionDescriptor":{"schema":"driver-index-acquisition-v1","state":"UNKNOWN","reason":"artificial route absent","payloadUrl":"","fileName":"","format":"UNKNOWN","expectedContentType":"","maximumBytes":0,"route":[],"terms":{"state":"UNKNOWN","reason":"artificial terms absent","evidenceUrl":"","evidenceSha256":"","revisionKind":"NONE","revision":"","textDocument":null},"prerequisites":{"state":"UNKNOWN","reason":"artificial prerequisites absent","items":[]},"publisher":{"state":"UNKNOWN","value":"","reason":"artificial publisher absent"},"attestation":null}})" ;
	const std::string source =
		// 架空出典だけです。
		R"({"sourceId":"artificial-source","officialOrigin":"https://vendor.example/","distributionPage":"https://vendor.example/support","officialEvidence":{"state":"UNKNOWN","kind":"UNKNOWN","evidenceUrl":"","evidenceSha256":"","reason":"artificial not verified"}})" ;
	return "{\"schema\":\"driver-index-records-v2\",\"assetGeneration\":1,\"sources\":[" + source +
		   "],\"records\":[{\"recordBytesBase64\":\"" + encode( record) + "\",\"recordSha256\":\"" +
		   hash( record) + "\"}]}" ;
}

/** @brief Minizの実deflateで人工indexを単一GZipへ包みます。
 * @param[in] raw 元indexです。
 * @return CRC/ISIZEを実計算したGZip byteです。
 */
[[nodiscard]] std::vector<std::byte> gzip( const std::string_view raw)
{
	std::vector<unsigned char> packed( raw.size() + 128U) ;						// 有限zlib出力bufferです。
	mz_ulong				   size = static_cast<mz_ulong>( packed.size()) ;	// 実圧縮長です。
	// Minizの公開byte境界へ原文字byteを読取り借用します。
	const auto				  *input = reinterpret_cast<const unsigned char *>( raw.data()) ;
	require( mz_compress2( packed.data(), &size, input, static_cast<mz_ulong>( raw.size()),
						 MZ_BEST_COMPRESSION) == MZ_OK &&
			size >= 6U) ;
	std::vector<std::byte> value{std::byte{0x1f}, std::byte{0x8b}, std::byte{8}, std::byte{},
								 std::byte{},	  std::byte{},	   std::byte{},	 std::byte{},
								 std::byte{},	  std::byte{0xff}} ;	// 固定GZip headerです。
	// Zlib header/Adlerを除いた原deflateだけを有限にcopyします。
	for( std::size_t index = 2U; index < size - 4U; ++index) {
		value.push_back( static_cast<std::byte>( packed[index])) ;
	}

	const auto crc = static_cast<std::uint32_t>(
		// 原indexの実CRCです。
		mz_crc32( MZ_CRC32_INIT, input, raw.size())) ;
	// CRCとISIZEを下位byte順へ欠損なく追加します。
	for( const std::uint32_t number : {crc, static_cast<std::uint32_t>( raw.size())}) {
		// 一値四byteだけをlittle endianへ表現します。
		for( unsigned shift = 0U; shift < 32U; shift += 8U) {
			value.push_back( static_cast<std::byte>( (number >> shift) & 0xffU)) ;
		}
	}

	return value ;
}

/** @brief 署名する原manifestを人工assetの実byteへ結合します。
 * @param[in] keyId 今開いた固定local keyのIDです。
 * @param[in] packed 原GZipです。
 * @param[in] generation Manifest世代です。Asset世代は1を保持します。
 * @return 原UTF-8 byteです。先頭改行も署名対象です。
 */
[[nodiscard]] std::string manifest( const std::string			   &keyId,
								   const std::span<const std::byte> packed,
								   const unsigned					generation)
{
	// 共通hashへ実GZipの公開byteを読取り専用で借用します。
	const std::string digest = hash( {reinterpret_cast<const char *>( packed.data()), packed.size()}) ;
	return "\n{\"schema\":\"driver-index-manifest-v1\",\"repository\":\"EnterOgawa/drivercrate\",\"channel\":\"driver-index\",\"keyId\":\"" +
		   keyId + "\",\"generation\":" + std::to_string( generation) +
		   ",\"assetGeneration\":1,\"publishedAtUtc\":\"2026-10-13T12:00:00Z\",\"expiresAtUtc\":\"2026-10-14T12:00:00Z\",\"asset\":{\"tag\":\"index-v1-20261013-" +
		   digest + "\",\"name\":\"index.json.gz\",\"compression\":\"gzip\",\"sizeBytes\":" +
		   std::to_string( packed.size()) + ",\"sha256\":\"" + digest +
		   "\"},\"quality\":{\"sourceCount\":1,\"recordCount\":1,\"metadataOnlyCount\":1,\"contentInspectedCount\":0,\"unconfirmedCount\":0}}" ;
}

/** @brief 人工fixture内の固定日時だけを指定の公開時刻へ置換します。
 * @param[in] raw 既存fixtureの原byteです。呼出し中だけ借用します。
 * @param[in] publication 人工の発行UTC文字列です。
 * @param[in] expiration 人工の失効UTC文字列です。
 * @return 日時以外のbyteを保持した人工wireです。
 */
[[nodiscard]] std::string fixtureTimes( std::string raw, const std::string_view publication,
									   const std::string_view expiration)
{
	// 固定二日時だけを順に処理し、base64化前の原recordとmanifestへ同じ時刻を渡します。
	for( const auto &replacement :
		{std::pair<std::string_view, std::string_view>{"2026-10-13T12:00:00Z", publication},
		 std::pair<std::string_view, std::string_view>{"2026-10-14T12:00:00Z", expiration}}) {
		std::size_t position = 0U ;	// 置換済み文字列の末尾から再開する有限cursorです。
		// 元日時の各出現だけを置換し、更新済み部分を再処理せず末尾で終了します。
		while( (position = raw.find( replacement.first, position)) != raw.npos) {
			raw.replace( position, replacement.first.size(), replacement.second) ;
			position += replacement.second.size() ;
		}
	}

	return raw ;
}

/** @brief 人工fixtureの唯一の完全markerだけを置換します。
 * @param[in] raw 所有する人工原byteです。
 * @param[in] before 一度だけ存在する元markerです。
 * @param[in] after 明示した人工変異です。
 * @return 指定marker以外の原byteを保持した値です。
 * @throws std::runtime_error Markerが欠けるか重複する場合。
 */
[[nodiscard]] std::string replaceFixtureOnce( std::string raw, const std::string_view before,
											 const std::string_view after)
{
	const auto position = raw.find( before) ;	// 唯一の意図した変異位置だけです。
	require( !before.empty() && position != raw.npos &&
			raw.find( before, position + before.size()) == raw.npos) ;
	raw.replace( position, before.size(), after) ;
	return raw ;
}

/** @brief 人工の既知取得申告だけを持つ原v2 indexを構成します。
 * @param[in] publication 人工の発行UTCです。省略時は従来fixtureの固定値です。
 * @param[in] expiration 人工の失効UTCです。省略時は従来fixtureの固定値です。
 * @param[in] recordBefore 履歴負例だけの一意record markerです。空なら旧byteを保持します。
 * @param[in] recordAfter 履歴負例の明示変異です。
 * @return 実内容/公式性/適用性の証拠ではない固定人工wireです。
 */
[[nodiscard]] std::string acquisitionIndexBytes(
	const std::string_view publication	= "2026-10-13T12:00:00Z",
	const std::string_view expiration	= "2026-10-14T12:00:00Z",
	const std::string_view recordBefore = {}, const std::string_view recordAfter = {})
{
	const std::string evidenceHash( 64U, 'a') ;	// 架空の出典原hashです。
	const std::string payloadHash( 64U, 'b') ;	// 架空の検査済み内容申告hashです。
	const std::string
		record =
			R"({"schema":"driver-index-record-v2","sourceId":"artificial-source","recordId":"artificial-acquisition","product":"Artificial acquisition purpose","targetOs":{"state":"KNOWN","value":"WINDOWS_11","reason":""},"architecture":{"state":"KNOWN","value":"X64","reason":""},"driverKind":{"state":"KNOWN","value":"NORMAL_DRIVER","reason":""},"version":{"state":"KNOWN","value":"1.2.3.4","reason":""},"publishedDate":{"state":"UNKNOWN","value":"","reason":"artificial date absent"},"acquisition":{"state":"KNOWN","value":"STANDARD_INF_ARCHIVE","reason":""},"packageEvidence":{"publishedHash":{"state":"UNKNOWN","sha256":"","evidenceUrl":"","evidenceSha256":"","reason":"artificial published hash absent"},"calculatedHash":{"state":"KNOWN","sha256":")" +
			payloadHash +
			R"(","evidenceUrl":"https://vendor.example/package.zip","evidenceSha256":")" + payloadHash + R"(","reason":""},"size":{"state":"KNOWN","valueBytes":22,"reason":""}},"lastSuccessfulObservationUtc":{"state":"KNOWN","value":"2026-10-13T12:00:00Z","reason":""},"inspectionStage":"CONTENT_INSPECTED","publishedIdentityEvidence":{"state":"PUBLISHED","kind":"INF","pnpIds":[{"kind":"HARDWARE","value":"PCI\\VEN_1234&DEV_5678"}],"classGuid":"{4D36E972-E325-11CE-BFC1-08002BE10318}","nestedArchiveIdentity":"","infIdentity":"driver/sample.inf","modelSection":"Models.NTamd64","evidenceUrl":"https://vendor.example/package.zip","evidenceSha256":")" + payloadHash + R"(","reason":""},"acquisitionDescriptor":{"schema":"driver-index-acquisition-v1","state":"KNOWN","reason":"","payloadUrl":"https://vendor.example/package.zip","fileName":"package.zip","format":"ZIP","expectedContentType":"application/zip","maximumBytes":1024,"route":[{"url":"https://vendor.example/package.zip","kind":"OFFICIAL_PAYLOAD_LINK","evidenceUrl":"https://vendor.example/support","evidenceSha256":")" + evidenceHash + R"("}],"terms":{"state":"CONFIRMED_NO_CONSENT","reason":"","evidenceUrl":"https://vendor.example/support","evidenceSha256":")" + evidenceHash + R"(","revisionKind":"NONE","revision":"","textDocument":null},"prerequisites":{"state":"KNOWN","reason":"","items":[]},"publisher":{"state":"KNOWN","value":"Artificial Package Publisher","reason":""},"attestation":{"kind":"COLLECTOR_VERIFIED_OFFICIAL_ROUTE","policyRevision":1,"checkedAtUtc":"2026-10-13T12:00:00Z","validUntilUtc":"2026-10-14T12:00:00Z","authorityMethod":"OFFICIAL_SITE_CONTROL_AND_LINK","authorityEvidenceUrl":"https://vendor.example/support","authorityEvidenceSha256":")" +
			evidenceHash + R"("}}})" ;	// 自己申告を実Driver検査へ換算しません。
	const std::string source =
		R"({"sourceId":"artificial-source","officialOrigin":"https://vendor.example/","distributionPage":"https://vendor.example/support","officialEvidence":{"state":"PUBLISHED","kind":"OFFICIAL_PAGE","evidenceUrl":"https://vendor.example/support","evidenceSha256":")" +
		evidenceHash + R"(","reason":""}})" ;	// 架空sourceだけです。
	auto timedRecord =
		// 署名前の人工日時です。
		fixtureTimes( record, publication, expiration) ;
	// 旧fixtureを変えず、新しい負例だけを原record hashの計算前に変異させます。
	if( !recordBefore.empty()) {
		timedRecord = replaceFixtureOnce( std::move( timedRecord), recordBefore, recordAfter) ;
	}

	return "{\"schema\":\"driver-index-records-v2\",\"assetGeneration\":1,\"sources\":[" + source +
		   "],\"records\":[{\"recordBytesBase64\":\"" + encode( timedRecord) +
		   "\",\"recordSha256\":\"" + hash( timedRecord) + "\"}]}" ;
}

/** @brief 新用途の人工qualityだけを完全一致markerで設定します。
 * @param[in] keyId 固定既存local鍵の公開IDです。
 * @param[in] packed 同人工indexの実GZipです。
 * @return 内容申告一件だけの原manifestです。
 */
[[nodiscard]] std::string acquisitionManifest( const std::string				  &keyId,
											  const std::span<const std::byte> packed)
{
	auto raw = manifest( keyId, packed, 1U) ;	// 旧manifest生成の元asset bindingです。
	constexpr std::string_view BEFORE =
		"\"metadataOnlyCount\":1,\"contentInspectedCount\":0" ;	// 旧qualityの完全markerです。
	const auto position = raw.find( BEFORE) ;					// 一意のquality位置です。
	require( position != raw.npos && raw.find( BEFORE, position + BEFORE.size()) == raw.npos) ;
	raw.replace( position, BEFORE.size(), "\"metadataOnlyCount\":0,\"contentInspectedCount\":1") ;
	return raw ;
}

/** @brief 旧35/21条件と別に新用途の正負を有限検証します。
 * @param[in] fingerprint 既存保護keyの明示公開pinです。
 */
void runAcquisitionPurpose( const std::string &fingerprint)
{
	using namespace drivercrate ;
	const auto inspected = inspectLocalIndexSigningKey( false) ;	// 作成を許可しない照会です。
	expect( inspected.error == 0 && inspected.publicKey && !inspected.created,
		   "purpose existing protected key") ;
	require( inspected.publicKey.has_value()) ;
	const auto &key	   = *inspected.publicKey ;						// 公開receiptだけを借用します。
	const auto	packed = gzip( acquisitionIndexBytes()) ;			// 人工v2だけの実圧縮です。
	const auto	raw	   = acquisitionManifest( key.keyId, packed) ;	// 原manifestへ結合します。
	const auto	signedValue =
		// 新明示用途です。
		signLocalAcquisitionIndex( raw, packed, fingerprint, NOW) ;
	expect( signedValue.error == 0 && !signedValue.envelope.empty() && !signedValue.created,
		   "purpose fully known native signing") ;
	expect( signedValue.assetStatus == IndexAssetBytesStatus::BYTE_VALIDATED &&
			   signedValue.recordsStatus == IndexRecordsStatus::SCHEMA_VALIDATED,
		   "purpose asset and v2 codec") ;
	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{key.keyId, key.publicBlob}}} ;	// 相互検証だけです。
	// 用途別署名を同公開pinで再認証する実結果です。
	const auto authenticated = signed_index_detail::authenticateWithTrustKeys(
		signedValue.envelope, NOW, std::nullopt, trust) ;
	expect( authenticated.manifest && authenticated.manifest->data().manifestBytes == raw,
		   "purpose signature preserves original manifest") ;
	const auto unknownPacked = gzip( indexBytes()) ;	// 同旧UNKNOWN人工入力です。
	// 正常codecを通ったUNKNOWNでも取得用途へ署名しない結果です。
	const auto unknown = signLocalAcquisitionIndex( manifest( key.keyId, unknownPacked, 1U),
												   unknownPacked, fingerprint, NOW) ;
	expect( unknown.error != 0 && unknown.envelope.empty() &&
			   unknown.recordsStatus == IndexRecordsStatus::SCHEMA_VALIDATED,
		   "purpose unknown cannot be signed for acquisition") ;
	auto changedPacked = packed ;	// 条件を明示変更する一byte改変です。
	changedPacked.back() ^= std::byte{1} ;
	const auto changed = signLocalAcquisitionIndex( raw, changedPacked, fingerprint,
												   NOW) ;	// 改変assetの拒否結果です。
	expect( changed.error != 0 && changed.envelope.empty() &&
			   changed.assetStatus == IndexAssetBytesStatus::HASH_MISMATCH,
		   "purpose changed exact asset rejected") ;
	const auto wrongPin =
		// 別pinの拒否結果です。
		signLocalAcquisitionIndex( raw, packed, std::string( 64U, '0'), NOW) ;
	expect( wrongPin.error != 0 && wrongPin.envelope.empty(), "purpose wrong complete pin rejected") ;
	const auto expired =
		// 元期限を越えた署名要求の拒否結果です。
		signLocalAcquisitionIndex( raw, packed, fingerprint, NOW + std::chrono::days{2}) ;
	expect( expired.error != 0 && expired.envelope.empty(), "purpose expired manifest rejected") ;
	const auto noTime = signLocalAcquisitionIndex( raw, packed, fingerprint,
												  std::nullopt) ;	// 時刻欠測の拒否結果です。
	expect( noTime.error != 0 && noTime.envelope.empty(), "purpose missing trusted time rejected") ;
}

/** @brief 人工assetと既存固定local鍵の相互検証を有限に実行します。
 * @param[in] fingerprint 実public blobと一致を要求する明示指紋です。
 */
void run( const std::string &fingerprint)
{
	using namespace drivercrate ;
	expect( local_index_signing_detail::fullControlMask( GENERIC_ALL), "generic full control") ;
	expect( local_index_signing_detail::fullControlMask( FILE_ALL_ACCESS), "mapped full control") ;
	expect( local_index_signing_detail::fullControlMask( 0xd01f01ffU),
		   "observed redundant full control") ;
	expect( local_index_signing_detail::fullControlMask( GENERIC_ALL | GENERIC_READ),
		   "redundant generic rights") ;
	expect( !local_index_signing_detail::fullControlMask( GENERIC_READ), "read-only rejected") ;
	expect( !local_index_signing_detail::fullControlMask( GENERIC_READ | GENERIC_WRITE),
		   "read-write-only rejected") ;
	expect( !local_index_signing_detail::fullControlMask( 0U), "empty permissions rejected") ;
	expect( !local_index_signing_detail::fullControlMask( 0xd11f01ffU),
		   "unknown privilege bit rejected") ;
	const auto inspected = inspectLocalIndexSigningKey( false) ;	// 既存keyを非変更で確認します。
	expect( inspected.error == 0 && inspected.publicKey && !inspected.created,
		   "existing protected key") ;
	require( inspected.publicKey.has_value()) ;
	const auto &key = *inspected.publicKey ;	// 非秘密public receiptだけを借用します。
	expect( key.fingerprint == fingerprint && key.protectionVerified &&
			   key.publicBlob.size() == 411U,
		   "full fingerprint and protection") ;
	const auto again = inspectLocalIndexSigningKey( false) ;	// 別handleから同固定keyを再openします。
	expect( again.publicKey && !again.created && again.publicKey->publicBlob == key.publicBlob,
		   "reuse no overwrite") ;
	const auto index  = indexBytes() ;						// 人工UNKNOWN v2 recordです。
	const auto packed = gzip( index) ;						// 実GZip/CRC/ISIZEです。
	const auto raw	  = manifest( key.keyId, packed, 1U) ;	// 先頭改行を保持する原UTF-8です。
	const auto signedValue =
		// 実保護鍵のnative PSS署名です。
		signLocalIndexManifest( raw, fingerprint, NOW) ;
	expect( signedValue.error == 0 && !signedValue.envelope.empty() && !signedValue.created,
		   "raw native signing") ;
	require( !signedValue.envelope.empty()) ;
	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{key.keyId, key.publicBlob}}} ;	// 相互検証だけの公開trustです。
	const auto authenticated = signed_index_detail::authenticateWithTrustKeys(
		signedValue.envelope, NOW, std::nullopt, trust) ;	// 既存BCrypt verifierです。
	expect( authenticated.manifest && authenticated.manifest->data().manifestBytes == raw,
		   "exact original bytes") ;
	require( authenticated.manifest.has_value()) ;
	const auto product = authenticateSignedIndexManifest(
		signedValue.envelope, NOW, std::nullopt) ;	// Build固定集合の独立検査です。
	expect( local_index_profile::TRUST_KEYS.empty()
			   ? product.status == SignedIndexManifestStatus::UNKNOWN_KEY
			   : product.manifest.has_value(),
		   "normal versus local fixed pin") ;
	expect( local_index_profile::TRUST_KEYS.empty() ||
			   local_index_profile::PUBLIC_FINGERPRINT == fingerprint,
		   "compiled public fingerprint") ;
	auto	   modified = signedValue.envelope ;	// 原署名を使う改変負例です。
	const auto offset =
		// 原byteのbase64位置を固定語で解決します。
		modified.find( "manifestBytesBase64\":\"") ;
	require( offset != std::string::npos) ;
	modified[offset + 22U] = modified[offset + 22U] == 'A' ? 'B' : 'A' ;
	expect( !signed_index_detail::authenticateWithTrustKeys( modified, NOW, std::nullopt, trust)
				.manifest,
		   "original-byte tamper rejected") ;
	auto otherBlob = key.publicBlob ;	// 別modulusの非秘密public負例です。
	otherBlob[100U] ^= 2U ;
	const std::array<signed_index_detail::TrustKey, 1U> otherTrust{
		{{key.keyId, otherBlob}}} ;	// 外部へ配備しません。
	expect( !signed_index_detail::authenticateWithTrustKeys( signedValue.envelope, NOW, std::nullopt,
														   otherTrust)
				.manifest,
		   "different key rejected") ;
	expect( signLocalIndexManifest( raw, std::string( 64U, '0'), NOW).envelope.empty(),
		   "different fingerprint rejected") ;
	expect( signLocalIndexManifest( raw, fingerprint, std::nullopt).envelope.empty(),
		   "missing clock rejected") ;
	expect( signLocalIndexManifest( "{}", fingerprint, NOW).envelope.empty(),
		   "invalid manifest not emitted") ;
	expect( signLocalIndexManifest( std::string( INDEX_MANIFEST_MAX_BYTES + 1U, 'x'), fingerprint, NOW)
			   .envelope.empty(),
		   "input size boundary") ;
	expect( !signed_index_detail::authenticateWithTrustKeys(
				signedValue.envelope, NOW + std::chrono::days{2}, std::nullopt, trust)
				.manifest,
		   "expired manifest rejected") ;
	const IndexManifestHighWater highWater{
		2U, authenticated.manifest->data().manifestSha256} ;	// より高い保護世代の人工入力です。
	expect(
		signed_index_detail::authenticateWithTrustKeys( signedValue.envelope, NOW, highWater, trust)
				.status == SignedIndexManifestStatus::GENERATION_ROLLBACK,
		"generation rollback rejected") ;
	auto	   changedRaw = raw + "\n" ;	// 同世代・意味同じでも原byteが異なる負例です。
	const auto conflict =
		// 原byte差を実署名します。
		signLocalIndexManifest( changedRaw, fingerprint, NOW) ;
	const IndexManifestHighWater same{
		1U, authenticated.manifest->data().manifestSha256} ;	// 同世代の原hashです。
	expect( signed_index_detail::authenticateWithTrustKeys( conflict.envelope, NOW, same, trust)
				   .status == SignedIndexManifestStatus::GENERATION_CONFLICT,
		   "same generation different bytes") ;
	const auto asset = authenticateIndexAssetBytes( *authenticated.manifest, packed,
												   NOW) ;	// 既存size/hash/GZip境界です。
	expect( asset.receipt.has_value(), "native asset bytes") ;
	require( asset.receipt.has_value()) ;
	const auto records = readSignedIndexRecords( *asset.receipt, NOW) ;	// 既存v2 UNKNOWN codecです。
	expect( records.receipt && records.receipt->records().size() == 1U, "native v2 records") ;
	require( records.receipt.has_value()) ;
	expect( records.receipt->records()[0].publishedIdentityEvidence.state ==
			   IndexEvidenceState::UNKNOWN,
		   "unknown is not success") ;
	const auto opened =
		// 自作隔離storeだけを作ります。
		signed_index_store_detail::Access::createIsolated( trust) ;
	expect( opened.store != nullptr, "isolated protected store") ;
	require( opened.store != nullptr) ;
	const auto committed = opened.store->commit( *records.receipt, signedValue.envelope, packed,
												NOW) ;	// 実DPAPI/commit/readbackです。
	expect( committed.snapshot.has_value(), "signed store commit") ;
	require( committed.snapshot.has_value()) ;
	const auto reopened = signed_index_store_detail::Access::reopenIsolated(
		*opened.store) ;	// 別Stateで実再openします。
	require( reopened.store != nullptr) ;
	expect( reopened.store->reload( NOW).snapshot.has_value(), "store reopen and verify") ;
	const auto restoredSignature = signLocalIndexManifest(
		// 新世代で旧asset1を再署名します。
		manifest( key.keyId, packed, 2U), fingerprint, NOW) ;
	const auto restoredManifest = signed_index_detail::authenticateWithTrustKeys(
		restoredSignature.envelope, NOW, std::nullopt, trust) ;	// 実原署名です。
	require( restoredManifest.manifest.has_value()) ;
	const auto restoredAsset = authenticateIndexAssetBytes( *restoredManifest.manifest, packed,
														   NOW) ;	// 同旧assetを再確認します。
	require( restoredAsset.receipt.has_value()) ;
	const auto restoredRecords =
		// 同旧原recordを再確認します。
		readSignedIndexRecords( *restoredAsset.receipt, NOW) ;
	require( restoredRecords.receipt.has_value()) ;
	const auto restored =
		reopened.store->commit( *restoredRecords.receipt, restoredSignature.envelope, packed,
							   NOW) ;	// 新manifest世代の旧asset復帰です。
	expect( restored.snapshot && restored.persistedGeneration == 2U &&
			   restored.snapshot->schemaReceipt().assetBytes().manifest().data().assetGeneration ==
				   1U,
		   "new manifest old asset restoration") ;
	expect( !reopened.store->commit( *records.receipt, signedValue.envelope, packed, NOW).snapshot,
		   "store rejects old generation") ;
	const auto snapshot = std::make_shared<const AuthenticatedIndexSnapshot>(
		*committed.snapshot) ;						// 人工snapshotの所有を共有します。
	const IndexLookupContext context{1U, 1U, 1U} ;	// 同scanの完全contextです。
	const auto lookup = lookupSignedIndexRecords( snapshot, context, context, {}, {}, NOW,
												 nullptr) ;	// 公開IDなしはUNKNOWNを保持します。
	require( lookup.lookup.has_value()) ;
	const auto ownedLookup = std::make_shared<const SignedIndexRecordLookup>(
		*lookup.lookup) ;					// 非公開構築の元lookupを所有します。
	SignedIndexAcquisitionAdapter adapter ;	// Manifestと別の能力境界です。
	const auto begun = adapter.begin( ownedLookup, context, IndexTargetOs::WINDOWS_11,
									 NOW) ;	// 製品profileの実固定能力です。
	expect( local_index_profile::ACQUISITION_KEYS.empty() ? begun == E_ACCESSDENIED : begun == 0,
		   "independent acquisition authority") ;
	SignedIndexPreparationDescription description ;	// 未取得/UNKNOWN理由を保持します。
	const auto						  described =
		// UNKNOWNから取得計画を作りません。
		adapter.describe( 0U, context, NOW, {}, description) ;
	expect( described != 0 && !description.target, "unknown record cannot acquire") ;
	expect( inspectLocalIndexSigningKey( false).publicKey.has_value(),
		   "key remains protected after signing") ;
}

/** @brief 明示した一つのpublic入力をallocation前の上限付きで読みます。
 * @param[in] path 事前固定したevidence artifactの通常path。
 * @param[in] maximum 最大実byte数。
 * @return 完全な原byte。再serializationしません。
 * @throws std::runtime_error 空、過大、短い読取りまたは追加byteの場合。
 * @note 開発用の有限検証だけに使用し、鍵fileや製品storeへ使いません。
 */
[[nodiscard]] std::string readCollectedInput( const std::filesystem::path &path,
											 const std::size_t			  maximum)
{
	std::ifstream input( path, std::ios::binary | std::ios::ate) ;	// 原byteを保持する読み取り。
	require( static_cast<bool>( input)) ;
	const auto length = input.tellg() ;	// Allocation前の実長。
	require( length > 0 && static_cast<std::uint64_t>( length) <= maximum) ;
	std::string raw( static_cast<std::size_t>( length), '\0') ;	// 上限内の原byte。
	input.seekg( 0) ;
	require( static_cast<bool>( input.read( raw.data(), static_cast<std::streamsize>( raw.size()))) &&
			input.peek() == std::char_traits<char>::eof() && !input.bad()) ;
	return raw ;
}

/** @brief Build固定pinと既存codecだけで実収集索引を認証します。
 * @param[in] envelope 原署名envelope。
 * @param[in] packed 原GZip。
 * @param[in] now OSから観測した現在UTC。
 * @return 全段成功のschema receipt。
 * @throws std::runtime_error 前段拒否時。後続成功を合成しません。
 * @note Runtime公開key、network、端末inventory、private keyを入力しません。
 */
[[nodiscard]] drivercrate::IndexRecordsSchemaReceipt authenticateCollected(
	const std::string &envelope, const std::string &packed, const std::chrono::sys_seconds now)
{
	const auto manifestResult =
		drivercrate::authenticateSignedIndexManifest( envelope, now,
													 std::nullopt) ;	// 同じ生成pinだけの署名認証。
	std::printf( "COLLECTED_CODEC manifest=%u error=%d\n",
				static_cast<unsigned>( manifestResult.status), manifestResult.error) ;
	expect( manifestResult.manifest.has_value(), "collected fixed-pin manifest") ;
	require( manifestResult.manifest.has_value()) ;
	const auto bytes = std::as_bytes(
		std::span<const char>{packed.data(), packed.size()}) ;	// 原byteの非owning view。
	const auto assetResult =
		drivercrate::authenticateIndexAssetBytes( *manifestResult.manifest, bytes,
												 now) ;	// 実size/hash/GZip/CRC/ISIZE。
	std::printf( "COLLECTED_CODEC asset=%u error=%d\n", static_cast<unsigned>( assetResult.status),
				assetResult.error) ;
	expect( assetResult.receipt.has_value(), "collected native gzip") ;
	require( assetResult.receipt.has_value()) ;
	const auto records =
		// v2原recordとquality。
		drivercrate::readSignedIndexRecords( *assetResult.receipt, now) ;
	std::printf( "COLLECTED_CODEC records=%u error=%d\n", static_cast<unsigned>( records.status),
				records.error) ;
	expect( records.receipt.has_value(), "collected native v2") ;
	require( records.receipt.has_value()) ;
	return *records.receipt ;
}

/** @brief 実metadataの二asset世代と新manifestによる旧asset復帰を隔離storeで検査します。
 * @param[in] args g1 envelope/asset、g2 envelope/asset、g3 envelopeの固定五path。
 * @note 実DPAPIを使いますが製品ProgramData storeへ書き込まず、実driver導入／network／鍵操作0です。
 * @throws std::runtime_error 前段の入力／codec／store拒否時。
 */
void runCollected( char *const args[])
{
	using namespace drivercrate ;
	require( local_index_profile::TRUST_KEYS.size() == 1U) ;
	const auto now =
		std::chrono::floor<std::chrono::seconds>( std::chrono::system_clock::now()) ;		// 実OS UTC。
	const auto firstEnvelope  = readCollectedInput( args[2], INDEX_ENVELOPE_MAX_BYTES) ;	// 原g1署名。
	const auto firstPacked	  = readCollectedInput( args[3], INDEX_ASSET_MAX_BYTES) ;		// 原g1GZip。
	const auto secondEnvelope = readCollectedInput( args[4], INDEX_ENVELOPE_MAX_BYTES) ;	// 原g2署名。
	const auto secondPacked	  = readCollectedInput( args[5], INDEX_ASSET_MAX_BYTES) ;		// 原g2GZip。
	const auto restoredEnvelope =
		// 新g3署名。
		readCollectedInput( args[6], INDEX_ENVELOPE_MAX_BYTES) ;
	const auto first = authenticateCollected( firstEnvelope, firstPacked, now) ;	// 実収集の第一投影。
	const auto second =
		// 同確認済み観測の新asset世代。
		authenticateCollected( secondEnvelope, secondPacked, now) ;
	const auto restored =
		// 旧原assetを再認証。
		authenticateCollected( restoredEnvelope, firstPacked, now) ;
	expect( first.records().size() == 1U && first.sources().size() == 1U,
		   "fixed one-target denominator") ;
	require( first.records().size() == 1U && second.records().size() == 1U &&
			restored.records().size() == 1U) ;
	const auto &record = first.records().front() ;	// 生端末IDを持たない実metadata。
	expect( record.inspectionStage == IndexInspectionStage::METADATA_ONLY && record.targetOs.value &&
			   record.architecture.value && record.driverKind.value && record.version.value,
		   "collected known metadata is not all unknown") ;
	expect( record.publishedIdentityEvidence.state == IndexEvidenceState::UNKNOWN &&
			   record.acquisitionDescriptor &&
			   record.acquisitionDescriptor->state == IndexDescriptorState::UNKNOWN,
		   "uninspected identity and acquisition stay unknown") ;
	expect( record.originalBytes == second.records().front().originalBytes &&
			   record.originalBytes == restored.records().front().originalBytes,
		   "republication preserves actual observation and original record") ;
	expect( first.assetBytes().manifest().data().generation == 1U &&
			   second.assetBytes().manifest().data().generation == 2U &&
			   restored.assetBytes().manifest().data().generation == 3U &&
			   restored.assetBytes().manifest().data().assetGeneration == 1U,
		   "new manifest restores old asset without rollback") ;
	const auto store = signed_index_store_detail::Access::createIsolated(
		local_index_profile::TRUST_KEYS) ;	// 自作保護root。
	expect( store.store != nullptr, "collected isolated store") ;
	require( store.store != nullptr) ;
	const auto firstBytes =
		// g1原byte。
		std::as_bytes( std::span<const char>{firstPacked.data(), firstPacked.size()}) ;
	const auto secondBytes = std::as_bytes(
		std::span<const char>{secondPacked.data(), secondPacked.size()}) ;	// g2原byte。
	const auto savedFirst =
		// 実原子保存／readback。
		store.store->commit( first, firstEnvelope, firstBytes, now) ;
	expect( savedFirst.snapshot && savedFirst.persistedGeneration == 1U, "collected first commit") ;
	require( savedFirst.snapshot.has_value()) ;
	const auto openedAgain =
		// 別ownerで再open。
		signed_index_store_detail::Access::reopenIsolated( *store.store) ;
	require( openedAgain.store != nullptr) ;
	expect( openedAgain.store->reload( now).snapshot.has_value(), "collected first reopened") ;
	const auto savedSecond =
		// 更新反映。
		openedAgain.store->commit( second, secondEnvelope, secondBytes, now) ;
	expect( savedSecond.snapshot && savedSecond.persistedGeneration == 2U,
		   "collected generation update") ;
	expect( !openedAgain.store->commit( first, firstEnvelope, firstBytes, now).snapshot,
		   "collected lower generation refused") ;
	const auto savedRestored = openedAgain.store->commit( restored, restoredEnvelope, firstBytes,
														 now) ;	// 高manifestの旧asset復帰。
	expect( savedRestored.snapshot && savedRestored.persistedGeneration == 3U &&
			   savedRestored.snapshot->schemaReceipt()
					   .assetBytes()
					   .manifest()
					   .data()
					   .assetGeneration == 1U,
		   "collected old asset restored at higher manifest") ;
	const auto finalOwner = signed_index_store_detail::Access::reopenIsolated(
		*openedAgain.store) ;	// 最終headを再認証するowner。
	require( finalOwner.store != nullptr) ;
	const auto finalReload = finalOwner.store->reload( now) ;	// DTOを信用せず全原byteを再検査。
	expect( finalReload.snapshot && finalReload.persistedGeneration == 3U,
		   "collected restored head reopened") ;
	std::printf(
		"COLLECTED_INDEX_TESTS assertions=%u failures=%u realMetadataRecords=1 payloadPositive=0 candidates=unknown keyOperations=0 install=0 publication=0\n",
		assertions, failures) ;
}

/** @brief 永続storeを持たない人工RSAだけの単独ownerです。 */
struct EphemeralDistributionKey {
	/// RAM上の人工RSA algorithmだけです。
	BCRYPT_ALG_HANDLE algorithm{} ;
	/// RAM上の人工private key handleだけです。Exportしません。
	BCRYPT_KEY_HANDLE key{} ;
	/** @brief 未取得handleを初期化します。 */
	EphemeralDistributionKey() = default ;
	/** @brief 人工RAM keyとalgorithmだけを回収します。 */
	~EphemeralDistributionKey()
	{
		// 人工鍵のRAM ownerを先に解放します。
		if( key != nullptr) {
			static_cast<void>( BCryptDestroyKey( key)) ;
		}

		// Provider ownerを最後に解放します。
		if( algorithm != nullptr) {
			static_cast<void>( BCryptCloseAlgorithmProvider( algorithm, 0U)) ;
		}
	}
	/** @brief 二重解放を防ぐためcopyを禁止します。 */
	EphemeralDistributionKey( const EphemeralDistributionKey &) = delete ;
	/** @brief 二重ownerを作る代入を禁止します。
	 * @return 呼出しは禁止されます。
	 */
	EphemeralDistributionKey &operator=( const EphemeralDistributionKey &) = delete ;
	/** @brief 原byteを人工RAM鍵のPSSで署名します。
	 * @param[in] raw 署名対象の原manifestです。
	 * @param[in] keyId 人工公開blobへ結合したIDです。
	 * @param[in] salt 拒否試験でだけ32以外を指定します。
	 * @return 原byteを保持する人工envelopeです。
	 */
	[[nodiscard]] std::string envelope( const std::string &raw, const std::string &keyId,
									   const ULONG salt = 32U)
	{
		const auto					  hex = hash( raw) ;			// 同じ原byteの既存共通hashです。
		constexpr std::string_view	  HEX = "0123456789abcdef" ;	// 正規digestのdecode表です。
		std::array<std::uint8_t, 32U> digest{} ;					// SHA-256原byteです。
		// 固定32byteを上位/下位nibbleから構成します。
		for( std::size_t index = 0U; index < digest.size(); ++index) {
			digest[index] = static_cast<std::uint8_t>( HEX.find( hex[index * 2U]) * 16U +
													  HEX.find( hex[index * 2U + 1U])) ;
		}

		BCRYPT_PSS_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM, salt} ;	// 本番と同じPSS条件です。
		std::array<std::uint8_t, 384U> signature{} ;						// 非秘密の人工署名です。
		ULONG						   size{} ;								// 実署名byte数です。
		require( BCryptSignHash( key, &padding, digest.data(), static_cast<ULONG>( digest.size()),
							   signature.data(), static_cast<ULONG>( signature.size()), &size,
							   BCRYPT_PAD_PSS) >= 0 &&
				size == signature.size()) ;
		return "{\"schema\":\"driver-index-envelope-v1\",\"keyId\":\"" + keyId +
			   "\",\"manifestBytesBase64\":\"" + encode( raw) + "\",\"signatureBase64\":\"" +
			   encode( {reinterpret_cast<const char *>( signature.data()), signature.size()}) + "\"}" ;
	}
} ;

/** @brief 人工RAM鍵だけで配布profileと歴史seamと全codecを決定的に検査します。 */
void runDistributionFake()
{
	using namespace drivercrate ;
	EphemeralDistributionKey key ;	// Persistent CNG keyを開きません。
	require( BCryptOpenAlgorithmProvider( &key.algorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0U) >= 0) ;
	require( BCryptGenerateKeyPair( key.algorithm, &key.key, 3072U, 0U) >= 0) ;
	require( BCryptFinalizeKeyPair( key.key, 0U) >= 0) ;
	std::vector<std::uint8_t> publicBlob( 411U) ;	// 公開byteだけをexportします。
	ULONG					  publicSize{} ;		// 実公開blob長です。
	require( BCryptExportKey( key.key, nullptr, BCRYPT_RSAPUBLIC_BLOB, publicBlob.data(),
							static_cast<ULONG>( publicBlob.size()), &publicSize, 0U) >= 0 &&
			publicSize == publicBlob.size()) ;
	const auto fingerprint = hash( {reinterpret_cast<const char *>( publicBlob.data()),
								   // 人工公開pinです。
								   publicBlob.size()}) ;
	const auto keyId = "distribution-index-" + fingerprint.substr( 0U, 32U) ;	// 配布専用IDです。
	const std::string marker   = "\"assetGeneration\":1" ;						// 旧fixtureだけの固定markerです。
	auto			  rawIndex = indexBytes() ;									// 人工UNKNOWN索引です。
	rawIndex.replace( rawIndex.find( marker), marker.size(), "\"assetGeneration\":4") ;
	const auto packed = gzip( rawIndex) ;				// 同一世代4の実GZipです。
	auto	   raw	  = manifest( keyId, packed, 4U) ;	// 原manifest署名対象です。
	raw.replace( raw.find( marker), marker.size(), "\"assetGeneration\":4") ;
	const auto envelope = key.envelope( raw, keyId) ;	// 原byteの人工PSS署名です。
	expect( verifyDistributionIndex( envelope, packed, publicBlob, fingerprint, NOW).error == 0,
		   "distribution fake metadata positive") ;
	expect( verifyDistributionIndex( envelope, packed, publicBlob, fingerprint,
								   NOW - std::chrono::hours{1}, true)
				   .error == 0,
		   "distribution history exact signed publication") ;
	expect( verifyDistributionIndex( envelope, packed, publicBlob, fingerprint, NOW, true).error != 0,
		   "distribution history arbitrary past time refused") ;
	expect( verifyDistributionIndex( envelope, packed, publicBlob, fingerprint,
								   NOW + std::chrono::days{2})
				   .error != 0,
		   "distribution current expiry not relaxed") ;
	expect( verifyDistributionIndex( envelope, packed, publicBlob, fingerprint, std::nullopt).error !=
			   0,
		   "distribution missing clock refused") ;
	expect(
		verifyDistributionIndex( envelope, packed, publicBlob, std::string( 64U, '0'), NOW).error !=
			0,
		"distribution wrong local pin refused") ;
	expect( verifyDistributionIndex( envelope, packed,
								   std::span<const std::uint8_t>{publicBlob}.first( 410U),
								   fingerprint, NOW)
				   .error != 0,
		   "distribution wrong public shape refused") ;
	expect(
		verifyDistributionIndex( key.envelope( raw, keyId, 20U), packed, publicBlob, fingerprint, NOW)
				.error != 0,
		"distribution wrong PSS salt refused") ;
	const auto acceptanceId =
		"local-index-" + fingerprint.substr( 0U, 32U) ;	// 別profileへの偽装です。
	expect( verifyDistributionIndex( key.envelope( raw, acceptanceId), packed, publicBlob, fingerprint,
								   NOW)
				   .error != 0,
		   "distribution acceptance profile refused") ;
	auto changed = packed ;	// 原GZipの単byte改変です。
	changed.front() ^= std::byte{1U} ;
	expect( verifyDistributionIndex( envelope, changed, publicBlob, fingerprint, NOW).error != 0,
		   "distribution payload hash refused") ;
	const std::vector<std::byte> invalidGzip{std::byte{1U},
											 std::byte{2U}} ;	// Hashだけ一致する不正GZipです。
	auto invalidRaw = manifest( keyId, invalidGzip, 4U) ;		// 実不正byteのhashへ結合します。
	invalidRaw.replace( invalidRaw.find( marker), marker.size(), "\"assetGeneration\":4") ;
	expect( verifyDistributionIndex( key.envelope( invalidRaw, keyId), invalidGzip, publicBlob,
								   fingerprint, NOW)
				   .error != 0,
		   "distribution malformed GZip refused") ;
	const auto invalidSchema =
		// GZip正常でもrecord schemaが不正です。
		gzip( "{\"schema\":\"invalid\"}") ;
	auto schemaRaw = manifest( keyId, invalidSchema, 4U) ;	// 不正schemaの実asset hashです。
	schemaRaw.replace( schemaRaw.find( marker), marker.size(), "\"assetGeneration\":4") ;
	expect( verifyDistributionIndex( key.envelope( schemaRaw, keyId), invalidSchema, publicBlob,
								   fingerprint, NOW)
				   .error != 0,
		   "distribution schema refused") ;
	auto			  oldGeneration	   = raw ;					// 有効署名を持つ受入専用世代へ改変します。
	const std::string generationMarker = "\"generation\":4" ;	// 一意のmanifest fieldです。
	oldGeneration.replace( oldGeneration.find( generationMarker), generationMarker.size(),
						  "\"generation\":3") ;
	expect( verifyDistributionIndex( key.envelope( oldGeneration, keyId), packed, publicBlob,
								   fingerprint, NOW)
				   .error != 0,
		   "distribution acceptance generation refused") ;
	expect( verifyDistributionIndex( key.envelope( oldGeneration, keyId), packed, publicBlob,
								   fingerprint, NOW - std::chrono::hours{1}, true)
				   .error != 0,
		   "distribution history cannot relax generation") ;
}

/** @brief 実UTCから構成した人工時刻を既存codecのUTC字句へ変換します。
 * @param[in] time 1970年以降の人工fixture用UTC秒です。
 * @return 秒精度のUTC文字列です。
 * @throws std::runtime_error 有限bufferへ正しく出力できない場合。
 */
[[nodiscard]] std::string fixtureUtc( const std::chrono::sys_seconds time)
{
	const auto day = std::chrono::floor<std::chrono::days>( time) ;	// UTCの暦日境界です。
	const std::chrono::year_month_day date{day} ;					// 同じUTC日の各fieldです。
	const std::chrono::hh_mm_ss		  clock{time - day} ;			// 同日の時分秒です。
	std::array<char, 32U>			  text{} ;						// 終端を含む有限出力です。
	const int						  count = std::snprintf(
		text.data(), text.size(), "%04d-%02u-%02uT%02lld:%02lld:%02lldZ",
		static_cast<int>( date.year()), static_cast<unsigned>( date.month()),
		static_cast<unsigned>( date.day()), static_cast<long long>( clock.hours().count()),
		static_cast<long long>( clock.minutes().count()),
		// 書込み長も確認します。
		static_cast<long long>( clock.seconds().count())) ;
	require( count == 20) ;
	return {text.data(), static_cast<std::size_t>( count)} ;
}

/** @brief 人工fixture出力handleを全終了経路で閉じます。 */
struct FixtureHandleCloser {
	/** @brief 単独所有する有効handleだけを閉じます。
	 * @param[in] handle CREATE_NEWで取得したfile handleです。
	 */
	void operator()( void *handle) const noexcept
	{
		static_cast<void>( CloseHandle( handle)) ;
	}
} ;

/** @brief 人工公開byteだけを新規fileへ保存し、既存fileを上書きしません。
 * @param[in] path 新規一意root直下の保存先です。
 * @param[in] bytes 保存する非秘密byteです。最大1MiBです。
 * @throws std::runtime_error 新規作成・全byte書込み・flushに失敗した場合。
 */
void writePublicFixture( const std::filesystem::path &path, const std::string &bytes)
{
	require( bytes.size() <= 1024U * 1024U) ;
	const auto raw = CreateFileW( path.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_NEW,
								 FILE_ATTRIBUTE_NORMAL, nullptr) ;	// 既存fileは拒否します。
	require( raw != INVALID_HANDLE_VALUE) ;
	const std::unique_ptr<void, FixtureHandleCloser> file{raw} ;	// 有限scopeの単独ownerです。
	DWORD											 written{} ;	// 今回の実書込みbyte数です。
	require( WriteFile( file.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &written,
					  nullptr) != FALSE &&
			written == bytes.size()) ;
	require( FlushFileBuffers( file.get()) != FALSE) ;
}

/** @brief 一つの履歴caseで出力分離と正確なcodec段階を検査します。
 * @param[in] name 固定H番号です。
 * @param[in] result 公開APIの実結果です。
 * @param[in] accepted このcaseの固定成功期待です。
 * @param[in] manifestStatus 要求するmanifest段階です。空は段階を追加指定しません。
 * @param[in] assetStatus 要求するasset段階です。
 * @param[in] recordsStatus 要求するrecords段階です。
 * @param[in] extraCondition 時刻未到達や原byte完全一致の追加固定条件です。
 */
void checkHistoryCase(
	const char *name, const drivercrate::LocalIndexSigningResult &result, const bool accepted,
	const std::optional<drivercrate::SignedIndexManifestStatus> manifestStatus = std::nullopt,
	const std::optional<drivercrate::IndexAssetBytesStatus>		assetStatus	   = std::nullopt,
	const std::optional<drivercrate::IndexRecordsStatus>		recordsStatus  = std::nullopt,
	const bool													extraCondition = true)
{
	const bool publicState =
		accepted ? result.error == 0 && result.publicKey && !result.envelope.empty() &&
					   !result.publicKey->created && !result.publicKey->protectionVerified
				 : result.error != 0 && !result.publicKey &&
					   // 成功と拒否の出力境界です。
					   result.envelope.empty() ;
	expect( publicState && !result.created && extraCondition &&
			   (!manifestStatus || result.manifestStatus == manifestStatus) &&
			   (!assetStatus || result.assetStatus == assetStatus) &&
			   (!recordsStatus || result.recordsStatus == recordsStatus),
		   name) ;
	std::printf( "HISTORY_DETAIL case=%s error=%d manifest=%d asset=%d records=%d\n", name,
				result.error, result.manifestStatus ? static_cast<int>( *result.manifestStatus) : -1,
				result.assetStatus ? static_cast<int>( *result.assetStatus) : -1,
				result.recordsStatus ? static_cast<int>( *result.recordsStatus) : -1) ;
}

/** @brief 架空indexとRAM鍵だけで履歴の固定32条件を検査します。
 * @note OS時計、KSP、保護state、高水位、network、driverを操作しません。
 * 前段の人工暗号前提が欠けた場合は例外を親の失敗境界へ渡します。
 */
void runDistributionAcquisitionHistoryFake()
{
	using namespace drivercrate ;
	EphemeralDistributionKey key ;	// 永続containerを持たない人工RAM ownerです。
	require( BCryptOpenAlgorithmProvider( &key.algorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0U) >= 0) ;
	require( BCryptGenerateKeyPair( key.algorithm, &key.key, 3072U, 0U) >= 0) ;
	require( BCryptFinalizeKeyPair( key.key, 0U) >= 0) ;
	std::vector<std::uint8_t> publicBlob( 411U) ;	// 公開成分だけを保存します。
	ULONG					  publicSize{} ;		// 実公開blob長です。
	require( BCryptExportKey( key.key, nullptr, BCRYPT_RSAPUBLIC_BLOB, publicBlob.data(),
							static_cast<ULONG>( publicBlob.size()), &publicSize, 0U) >= 0 &&
			publicSize == publicBlob.size()) ;
	const auto fingerprint = hash( {reinterpret_cast<const char *>( publicBlob.data()),
								   // 公開blobだけの完全pinです。
								   publicBlob.size()}) ;
	const auto keyId = "distribution-index-" + fingerprint.substr( 0U, 32U) ;	// 固定用途IDです。
	const auto publication = NOW - std::chrono::hours{1} ;						// 元人工manifestの署名発行秒です。
	const auto later	= NOW + std::chrono::days{3} ;							// Manifestとattestationが失効した現在です。
	const auto packed	= gzip( acquisitionIndexBytes()) ;						// 架空取得申告だけのGZipです。
	const auto raw		= acquisitionManifest( keyId, packed) ;					// 原改行も署名します。
	const auto envelope = key.envelope( raw, keyId) ;							// 公開fixtureだけの人工署名です。
	// 同じRAM key/public pinを同期借用し、全通常caseを署名発行時点へ限定します。
	const auto history = [&]( const std::string				 &manifestBytes,
							 const std::span<const std::byte> bytes) {
		return verifyDistributionAcquisitionIndexHistory(
			key.envelope( manifestBytes, keyId), bytes, publicBlob, fingerprint, publication, later) ;
	} ;
	const auto first = verifyDistributionAcquisitionIndexHistory(
		envelope, packed, publicBlob, fingerprint, publication,
		later) ;	// 原byte保持と全公開factsを同時に確認します。
	checkHistoryCase( "H01", first, true, {}, {}, {},
					 first.envelope == envelope && first.publicKey &&
						 first.publicKey->publicBlob == publicBlob &&
						 first.publicKey->fingerprint == fingerprint &&
						 first.publicKey->keyId == keyId) ;
	checkHistoryCase(
		"H02", verifyDistributionAcquisitionIndex( envelope, packed, publicBlob, fingerprint, later),
		false, SignedIndexManifestStatus::INVALID_TIME) ;
	checkHistoryCase( "H03",
					 verifyDistributionAcquisitionIndexHistory( envelope, packed, publicBlob,
															   fingerprint, publication, NOW),
					 true) ;
	checkHistoryCase(
		"H04",
		verifyDistributionAcquisitionIndexHistory( envelope, packed, publicBlob, fingerprint,
												  publication + std::chrono::seconds{1}, later),
		false, SignedIndexManifestStatus::AUTHENTICATED, IndexAssetBytesStatus::BYTE_VALIDATED,
		IndexRecordsStatus::SCHEMA_VALIDATED) ;
	const auto future = verifyDistributionAcquisitionIndexHistory(
		envelope, packed, publicBlob, fingerprint, later + std::chrono::seconds{1},
		later) ;	// 申告未来秒はcodec前に止めます。
	checkHistoryCase( "H05", future, false, {}, {}, {},
					 !future.manifestStatus && future.error == 13) ;
	const auto noNow = verifyDistributionAcquisitionIndexHistory(
		envelope, packed, publicBlob, fingerprint, publication,
		std::nullopt) ;	// 現在UTCを補完しません。
	checkHistoryCase( "H06", noNow, false, {}, {}, {}, !noNow.manifestStatus && noNow.error == 13) ;
	const auto noPublication = verifyDistributionAcquisitionIndexHistory(
		envelope, packed, publicBlob, fingerprint, std::nullopt, later) ;	// 発行UTCを補完しません。
	checkHistoryCase( "H07", noPublication, false, {}, {}, {},
					 !noPublication.manifestStatus && noPublication.error == 13) ;
	checkHistoryCase( "H08",
					 history( replaceFixtureOnce( raw, "\"expiresAtUtc\":\"2026-10-14T12:00:00Z\"",
												"\"expiresAtUtc\":\"2026-10-13T12:00:00Z\""),
							 packed),
					 false, SignedIndexManifestStatus::INVALID_TIME) ;
	checkHistoryCase( "H09",
					 history( replaceFixtureOnce( raw, "\"expiresAtUtc\":\"2026-10-14T12:00:00Z\"",
												"\"expiresAtUtc\":\"2026-10-28T12:00:00Z\""),
							 packed),
					 false, SignedIndexManifestStatus::INVALID_TIME) ;
	const auto checkedLater = gzip( acquisitionIndexBytes(
		"2026-10-13T12:00:00Z", "2026-10-14T12:00:00Z", "\"checkedAtUtc\":\"2026-10-13T12:00:00Z\"",
		"\"checkedAtUtc\":\"2026-10-13T12:00:01Z\"")) ;	// 発行後の未確認を正例へしません。
	checkHistoryCase( "H10", history( acquisitionManifest( keyId, checkedLater), checkedLater), false,
					 {}, {}, IndexRecordsStatus::INVALID_EVIDENCE) ;
	const auto expiredAtPublication = gzip( acquisitionIndexBytes(
		"2026-10-13T12:00:00Z", "2026-10-14T12:00:00Z",
		"\"validUntilUtc\":\"2026-10-14T12:00:00Z\"",
		"\"validUntilUtc\":\"2026-10-13T12:00:00Z\"")) ;	// 期限境界を閉じて受理しません。
	checkHistoryCase(
		"H11", history( acquisitionManifest( keyId, expiredAtPublication), expiredAtPublication),
		false, {}, {}, IndexRecordsStatus::INVALID_EVIDENCE) ;
	const auto metadata = gzip( indexBytes()) ;	// UNKNOWN/metadataだけの別用途です。
	checkHistoryCase( "H12", history( manifest( keyId, metadata, 4U), metadata), false, {}, {},
					 IndexRecordsStatus::SCHEMA_VALIDATED) ;
	const auto wrongPin = verifyDistributionAcquisitionIndexHistory(
		envelope, packed, publicBlob, std::string( 64U, '0'), publication,
		later) ;	// 全公開pin不一致です。
	checkHistoryCase( "H13", wrongPin, false, {}, {}, {},
					 !wrongPin.manifestStatus && wrongPin.error == 13) ;
	// 公開blobの固定長欠損をpinや署名の検査前に拒否します。
	const auto shortBlob = verifyDistributionAcquisitionIndexHistory(
		envelope, packed, std::span<const std::uint8_t>{publicBlob}.first( 410U), fingerprint,
		publication, later) ;
	checkHistoryCase( "H14", shortBlob, false, {}, {}, {},
					 !shortBlob.manifestStatus && shortBlob.error == 13) ;
	auto badBlob	  = publicBlob ;	// 完全pinが一致してもRSA形が不正な公開blobです。
	badBlob[0]		  = 0U ;
	const auto badPin = hash(
		{reinterpret_cast<const char *>( badBlob.data()), badBlob.size()}) ;	// 同不正形の実pinです。
	const auto badId =
		"distribution-index-" + badPin.substr( 0U, 32U) ;	// Trust lookupを先に通すIDです。
	checkHistoryCase( "H15",
					 verifyDistributionAcquisitionIndexHistory(
						 key.envelope( acquisitionManifest( badId, packed), badId), packed, badBlob,
						 badPin, publication, later),
					 false, SignedIndexManifestStatus::INVALID_TRUST_KEY) ;
	checkHistoryCase( "H16",
					 verifyDistributionAcquisitionIndexHistory(
						 key.envelope( raw, "local-index-" + fingerprint.substr( 0U, 32U)), packed,
						 publicBlob, fingerprint, publication, later),
					 false, SignedIndexManifestStatus::UNKNOWN_KEY) ;
	checkHistoryCase( "H17",
					 verifyDistributionAcquisitionIndexHistory( key.envelope( raw, keyId, 20U),
															   packed, publicBlob, fingerprint,
															   publication, later),
					 false, SignedIndexManifestStatus::INVALID_SIGNATURE) ;
	auto changedEnvelope		   = envelope ;						// 再署名せず原manifestのbase64一byteを改変します。
	const std::string base64Marker = "\"manifestBytesBase64\":\"" ;	// 署名対象だけの一意位置です。
	const auto		  base64Position =
		// 最初の有効base64文字です。
		changedEnvelope.find( base64Marker) + base64Marker.size() ;
	changedEnvelope[base64Position] = changedEnvelope[base64Position] == 'A' ? 'B' : 'A' ;
	checkHistoryCase( "H18",
					 verifyDistributionAcquisitionIndexHistory( changedEnvelope, packed, publicBlob,
															   fingerprint, publication, later),
					 false, SignedIndexManifestStatus::INVALID_SIGNATURE) ;
	auto changedPacked = packed ;	// 同sizeの原GZip一byte改変です。
	changedPacked.front() ^= std::byte{1U} ;
	checkHistoryCase( "H19",
					 verifyDistributionAcquisitionIndexHistory( envelope, changedPacked, publicBlob,
															   fingerprint, publication, later),
					 false, {}, IndexAssetBytesStatus::HASH_MISMATCH) ;
	const std::vector<std::byte> invalidGzip{std::byte{1U},
											 std::byte{2U}} ;	// 正しいhashだけでは受理しません。
	checkHistoryCase( "H20", history( acquisitionManifest( keyId, invalidGzip), invalidGzip), false,
					 {}, IndexAssetBytesStatus::GZIP_REJECTED) ;
	checkHistoryCase(
		"H21", history( replaceFixtureOnce( raw, "\"generation\":1", "\"generation\":0"), packed),
		false, SignedIndexManifestStatus::INVALID_MANIFEST) ;
	checkHistoryCase(
		"H22",
		history( replaceFixtureOnce( raw, "\"generation\":1", "\"generation\":9007199254740992"),
				packed),
		false, {}, {}, IndexRecordsStatus::SCHEMA_VALIDATED) ;
	checkHistoryCase(
		"H23",
		history( replaceFixtureOnce( raw, "\"assetGeneration\":1", "\"assetGeneration\":2"), packed),
		false, SignedIndexManifestStatus::INVALID_MANIFEST) ;
	const auto wrongIndexGeneration =
		gzip( replaceFixtureOnce( acquisitionIndexBytes(), "\"assetGeneration\":1",
								"\"assetGeneration\":2")) ;	// Manifestだけは世代1を維持します。
	checkHistoryCase(
		"H24", history( acquisitionManifest( keyId, wrongIndexGeneration), wrongIndexGeneration),
		false, {}, {}, IndexRecordsStatus::ASSET_GENERATION_MISMATCH) ;
	checkHistoryCase( "H25", history( manifest( keyId, packed, 1U), packed), false, {}, {},
					 IndexRecordsStatus::QUALITY_MISMATCH) ;
	checkHistoryCase( "H26",
					 verifyDistributionAcquisitionIndexHistory(
						 std::string( INDEX_ENVELOPE_MAX_BYTES + 1U, ' '), packed, publicBlob,
						 fingerprint, publication, later),
					 false, SignedIndexManifestStatus::ENVELOPE_SIZE_LIMIT) ;
	const std::vector<std::byte> overCap( static_cast<std::size_t>( INDEX_ASSET_MAX_BYTES) +
										 1U) ;	// RAMだけの入力cap負例です。
	checkHistoryCase( "H27",
					 verifyDistributionAcquisitionIndexHistory( envelope, overCap, publicBlob,
															   fingerprint, publication, later),
					 false, {}, IndexAssetBytesStatus::COMPRESSED_SIZE_LIMIT) ;
	const auto epoch = verifyDistributionAcquisitionIndexHistory(
		envelope, packed, publicBlob, fingerprint, std::chrono::sys_seconds{},
		later) ;	// 非正の発行秒を拒否します。
	checkHistoryCase( "H28", epoch, false, {}, {}, {}, !epoch.manifestStatus && epoch.error == 13) ;
	const auto wrongRevision = gzip( acquisitionIndexBytes(
		"2026-10-13T12:00:00Z", "2026-10-14T12:00:00Z", "\"policyRevision\":1",
		"\"policyRevision\":2")) ;	// 未採用policyへ補完しません。
	checkHistoryCase( "H29", history( acquisitionManifest( keyId, wrongRevision), wrongRevision),
					 false, {}, {}, IndexRecordsStatus::INVALID_EVIDENCE) ;
	checkHistoryCase(
		"H30", history( replaceFixtureOnce( raw, "\"generation\":1", "\"generation\":5"), packed),
		true) ;
	const auto expiredBeforePublication = gzip( acquisitionIndexBytes(
		"2026-10-13T12:00:00Z", "2026-10-14T12:00:00Z",
		"\"validUntilUtc\":\"2026-10-14T12:00:00Z\"",
		"\"validUntilUtc\":\"2026-10-12T12:00:00Z\"")) ;	// 過去の不成立を現在時刻で救済しません。
	checkHistoryCase(
		"H31",
		history( acquisitionManifest( keyId, expiredBeforePublication), expiredBeforePublication),
		false, {}, {}, IndexRecordsStatus::INVALID_EVIDENCE) ;
	checkHistoryCase(
		"H32", verifyDistributionAcquisitionIndex( envelope, packed, publicBlob, fingerprint, NOW),
		true) ;
}

/** @brief RAM署名と原assetだけで世代下限専用の固定20条件を検査します。
 * @note 現在recordや取得receiptを発行せず、永続鍵/通信/保護storeを扱いません。
 */
void runDistributionHistoryFloorFake()
{
	using namespace drivercrate ;
	EphemeralDistributionKey key ;	// この関数だけが所有する非永続RSAです。
	require( BCryptOpenAlgorithmProvider( &key.algorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0U) >= 0) ;
	require( BCryptGenerateKeyPair( key.algorithm, &key.key, 3072U, 0U) >= 0) ;
	require( BCryptFinalizeKeyPair( key.key, 0U) >= 0) ;
	std::vector<std::uint8_t> publicBlob( 411U) ;	// 公開成分だけです。
	ULONG					  publicSize{} ;		// CNGが返す実公開長です。
	require( BCryptExportKey( key.key, nullptr, BCRYPT_RSAPUBLIC_BLOB, publicBlob.data(),
							static_cast<ULONG>( publicBlob.size()), &publicSize, 0U) >= 0 &&
			publicSize == publicBlob.size()) ;
	const auto fingerprint = hash( {reinterpret_cast<const char *>( publicBlob.data()),
								   // 公開blobだけの完全pinです。
								   publicBlob.size()}) ;
	const auto keyId	   = "distribution-index-" + fingerprint.substr( 0U, 32U) ;	// 固定用途です。
	const auto publication = NOW - std::chrono::hours{1} ;							// 署名された原発行秒です。
	const auto later	   = NOW + std::chrono::days{3} ;							// 失効した現在です。
	const auto packed	   = gzip( acquisitionIndexBytes(
		 "2026-10-13T12:00:00Z", "2026-10-14T12:00:00Z", "\"nestedArchiveIdentity\":\"\",",
		 "")) ;														// 実旧形式同様に現reader必須fieldを欠きます。
	const auto raw		   = acquisitionManifest( keyId, packed) ;	// 原asset hash/sizeへ署名します。
	const auto envelope	   = key.envelope( raw, keyId) ;			// 原manifest byteのRAM署名です。
	// 数値結果だけの成功/拒否を全caseで同じ条件で比較します。
	const auto check = []( const DistributionIndexHistoryFloorResult &value, const bool accepted,
						  const char *name) {
		expect( accepted ? value.error == 0 && value.generation == 1U && value.assetGeneration == 1U
						: value.error != 0 && value.generation == 0U && value.assetGeneration == 0U,
			   name) ;
	} ;
	// 原manifestと同じ署名発行秒だけで共通署名/assetを認証します。
	const auto floor = [&]( const std::string &body, const std::span<const std::byte> bytes) {
		return verifyDistributionIndexHistoryFloor( key.envelope( body, keyId), bytes, publicBlob,
												   fingerprint, publication, later) ;
	} ;
	check( floor( raw, packed), true, "F01 old record floor only") ;
	expect( verifyDistributionAcquisitionIndexHistory( envelope, packed, publicBlob, fingerprint,
													 publication, later)
				   .error != 0,
		   "F02 old record strict history rejected") ;
	expect( verifyDistributionAcquisitionIndex( envelope, packed, publicBlob, fingerprint, later)
				   .error != 0,
		   "F03 expired current rejected") ;
	check( verifyDistributionIndexHistoryFloor( envelope, packed, publicBlob, std::string( 64U, '0'),
											  publication, later),
		  false, "F04 wrong public pin") ;
	check( verifyDistributionIndexHistoryFloor( envelope, packed,
											  std::span<const std::uint8_t>{publicBlob}.first( 410U),
											  fingerprint, publication, later),
		  false, "F05 short public blob") ;
	check(
		floor( replaceFixtureOnce( raw, "EnterOgawa/drivercrate", "EnterOgawa/anotherrepo"), packed),
		false, "F06 other repository") ;
	check( verifyDistributionIndexHistoryFloor( key.envelope( raw, keyId, 20U), packed, publicBlob,
											  fingerprint, publication, later),
		  false, "F07 wrong signature") ;
	auto changed = packed ;	// 同sizeの実byte改変です。
	changed.front() ^= std::byte{1U} ;
	check( verifyDistributionIndexHistoryFloor( envelope, changed, publicBlob, fingerprint,
											  publication, later),
		  false, "F08 asset hash mismatch") ;
	check( verifyDistributionIndexHistoryFloor(
			  envelope, std::span<const std::byte>{packed}.first( packed.size() - 1U), publicBlob,
			  fingerprint, publication, later),
		  false, "F09 asset size mismatch") ;
	const std::vector<std::byte> invalid{std::byte{1U},
										 std::byte{2U}} ;	// 正しいhashでもGZipでない原byteです。
	check( floor( acquisitionManifest( keyId, invalid), invalid), false, "F10 invalid gzip") ;
	check( verifyDistributionIndexHistoryFloor( envelope, packed, publicBlob, fingerprint,
											  publication, publication - std::chrono::seconds{1}),
		  false, "F11 future publication") ;
	check( verifyDistributionIndexHistoryFloor( envelope, packed, publicBlob, fingerprint,
											  std::nullopt, later),
		  false, "F12 missing publication") ;
	check( verifyDistributionIndexHistoryFloor( envelope, packed, publicBlob, fingerprint,
											  publication, std::nullopt),
		  false, "F13 missing current clock") ;
	check( verifyDistributionIndexHistoryFloor( envelope, packed, publicBlob, fingerprint,
											  publication + std::chrono::seconds{1}, later),
		  false, "F14 wrong signed publication") ;
	check( floor( replaceFixtureOnce( raw, "\"generation\":1", "\"generation\":0"), packed), false,
		  "F15 zero generation") ;
	check( floor( replaceFixtureOnce( raw, "\"generation\":1", "\"generation\":9007199254740992"),
				packed),
		  false, "F16 generation overflow") ;
	check( floor( replaceFixtureOnce( raw, "\"assetGeneration\":1", "\"assetGeneration\":2"), packed),
		  false, "F17 future asset generation") ;
	check( verifyDistributionIndexHistoryFloor( std::string( INDEX_ENVELOPE_MAX_BYTES + 1U, ' '),
											  packed, publicBlob, fingerprint, publication, later),
		  false, "F18 envelope cap") ;
	const std::vector<std::byte> overCap( static_cast<std::size_t>( INDEX_ASSET_MAX_BYTES) +
										 1U) ;	// RAM上限負例です。
	check( verifyDistributionIndexHistoryFloor( envelope, overCap, publicBlob, fingerprint,
											  publication, later),
		  false, "F19 asset cap") ;
	const auto bomb = gzip( std::string( 100000U, ' ')) ;	// 原hashが正しくても倍率上限へ達します。
	check( floor( acquisitionManifest( keyId, bomb), bomb), false, "F20 expansion ratio") ;
}

/** @brief 三公開検証CLI用の人工bundleを実UTCとRAM鍵だけから有限生成します。
 * @param[in] root 未存在の一意directoryです。親は呼出し元が準備します。
 * @param[in] includeHistory 明示history fixture modeだけ追加六fileを生成します。
 * @throws std::runtime_error 人工鍵・fixture準備・新規保存に失敗した場合。
 * @note 秘密byteはexportせず、named KSP/NCrypt/実保護鍵を照会しません。
 */
void exportPublicVerifyFixtures( const std::filesystem::path &root,
								const bool					 includeHistory = false)
{
	using namespace drivercrate ;
	require( std::filesystem::create_directory( root)) ;
	EphemeralDistributionKey key ;	// このscopeだけが所有する人工RAM鍵です。
	require( BCryptOpenAlgorithmProvider( &key.algorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0U) >= 0) ;
	require( BCryptGenerateKeyPair( key.algorithm, &key.key, 3072U, 0U) >= 0) ;
	require( BCryptFinalizeKeyPair( key.key, 0U) >= 0) ;
	std::vector<std::uint8_t> publicBlob( 411U) ;	// 公開blobだけをexportします。
	ULONG					  publicSize{} ;		// BCRYPT_RSAPUBLIC_BLOBの実byte数です。
	require( BCryptExportKey( key.key, nullptr, BCRYPT_RSAPUBLIC_BLOB, publicBlob.data(),
							static_cast<ULONG>( publicBlob.size()), &publicSize, 0U) >= 0 &&
			publicSize == publicBlob.size()) ;
	const std::string publicBytes{reinterpret_cast<const char *>( publicBlob.data()),
								  // 非秘密の公開byteだけを保存用viewから所有します。
								  publicBlob.size()} ;
	const auto		  fingerprint = hash( publicBytes) ;						// 人工blob自身から算出する公開pinです。
	const auto keyId = "distribution-index-" + fingerprint.substr( 0U, 32U) ;	// 同公開pinのIDです。
	const auto now	 = std::chrono::floor<std::chrono::seconds>(
		  // 製品CLIへfake clockを渡さず、fixtureだけを現在へ結合します。
		  std::chrono::system_clock::now()) ;
	const auto publication	  = now - std::chrono::minutes{1} ;	// 実時刻以前の人工発行時刻です。
	const auto expiration	  = now + std::chrono::hours{23} ;	// 有限な正常検証期間です。
	const auto oldPublication = now - std::chrono::days{3} ;	// 期限切れの人工発行時刻です。
	const auto oldExpiration  = now - std::chrono::days{2} ;	// 通常検証が拒否する過去期限です。
	auto	   metadata		  = indexBytes() ;					// UNKNOWNだけの既存人工indexです。
	const std::string marker  = "\"assetGeneration\":1" ;		// 元fixtureの一意fieldです。
	metadata.replace( metadata.find( marker), marker.size(), "\"assetGeneration\":4") ;
	const auto packed = gzip( metadata) ;				// 世代4の実GZipです。
	auto	   raw	  = manifest( keyId, packed, 4U) ;	// 元GZipの実hashへ結合します。
	raw.replace( raw.find( marker), marker.size(), "\"assetGeneration\":4") ;
	const auto current =
		// 現在用です。
		fixtureTimes( raw, fixtureUtc( publication), fixtureUtc( expiration)) ;
	const auto expired			 = fixtureTimes( raw, fixtureUtc( oldPublication),
												// 歴史専用の原byteです。
												fixtureUtc( oldExpiration)) ;
	const auto acquisitionIndex	 = acquisitionIndexBytes( fixtureUtc( publication),
														 // 公開申告だけの人工取得recordです。
														 fixtureUtc( expiration)) ;
	const auto acquisitionPacked = gzip( acquisitionIndex) ;	// 実GZip/CRC/ISIZEです。
	const auto acquisitionRaw =
		fixtureTimes( acquisitionManifest( keyId, acquisitionPacked), fixtureUtc( publication),
					 // 同じ人工時刻です。
					 fixtureUtc( expiration)) ;
	const std::string packedBytes{reinterpret_cast<const char *>( packed.data()),
								  // 圧縮済み公開byteだけを保存します。
								  packed.size()} ;
	const std::string acquisitionBytes{reinterpret_cast<const char *>( acquisitionPacked.data()),
									   // 実driver内容を含まない人工assetだけです。
									   acquisitionPacked.size()} ;
	const std::string info =
		"{\"schema\":\"public-verify-fixture-v1\",\"fingerprint\":\"" + fingerprint +
		"\",\"keyId\":\"" + keyId +
		"\",\"publishedSeconds\":" + std::to_string( publication.time_since_epoch().count()) +
		",\"expiredPublishedSeconds\":" +
		std::to_string( oldPublication.time_since_epoch().count()) +
		",\"generatedSeconds\":" + std::to_string( now.time_since_epoch().count()) +
		(includeHistory
			 ? ",\"futurePublishedSeconds\":" +
				   std::to_string( (now + std::chrono::days{1}).time_since_epoch().count())
			 : "") +
		",\"ephemeralKeys\":1,\"artificialSignatures\":" + (includeHistory ? "6" : "4") +
		",\"protectedKeyOperations\":0}" ;	// 非秘密metadataです。
	const std::array<std::pair<std::string, std::string>, 12U> files{
		{{"public.blob", publicBytes},
		 {"current.manifest.raw.json", current},
		 {"current.index.json.gz", packedBytes},
		 {"current.manifest.json", key.envelope( current, keyId)},
		 {"expired.manifest.raw.json", expired},
		 {"expired.manifest.json", key.envelope( expired, keyId)},
		 {"wrong-pss.manifest.json", key.envelope( current, keyId, 20U)},
		 {"acquisition.manifest.raw.json", acquisitionRaw},
		 {"acquisition.index.json.gz", acquisitionBytes},
		 {"acquisition.manifest.json", key.envelope( acquisitionRaw, keyId)},
		 {"acquisition.index.raw.json", acquisitionIndex},
		 {"fixture-info.json", info}}} ;	// 人工公開集合です。
	std::size_t projectedBytes = 0U ;		// 各新規file生成前に明示加算する保持量です。
	// 固定十二fileを一度ずつ保存し、容量超過または既存fileで中断します。
	for( const auto &file : files) {
		require( file.second.size() <= 1024U * 1024U &&
				projectedBytes <= 1024U * 1024U - file.second.size()) ;
		projectedBytes += file.second.size() ;
		std::printf( "FIXTURE_RESERVE name=%s bytes=%zu projectedBytes=%zu\n", file.first.c_str(),
					file.second.size(), projectedBytes) ;
		writePublicFixture( root / file.first, file.second) ;
	}

	// 新明示modeだけが過去と未来の正しく署名された取得申告を追加します。
	if( includeHistory) {
		// 二つの追加時刻を同じRAM鍵へ結合し、各束のmanifest/gzip/envelope三fileを保存します。
		for( const auto &entry : {std::pair{"history-expired", oldPublication},
								 std::pair{"history-future", now + std::chrono::days{1}}}) {
			const auto end = entry.second + std::chrono::days{1} ;	// 発行時には正当な一日期限です。
			// 各時刻を原recordへ結合してから実GZipを生成します。
			const auto historyPacked =
				gzip( acquisitionIndexBytes( fixtureUtc( entry.second), fixtureUtc( end))) ;
			const auto historyRaw =
				fixtureTimes( acquisitionManifest( keyId, historyPacked), fixtureUtc( entry.second),
							 // 同原GZipへhash結合します。
							 fixtureUtc( end)) ;
			const std::string historyBytes{reinterpret_cast<const char *>( historyPacked.data()),
										   // 取得payloadを含まない公開人工byteです。
										   historyPacked.size()} ;
			// 同じ原byte/公開署名だけからなる固定三fileです。
			const std::array<std::pair<std::string, std::string>, 3U> additions{
				{{std::string{entry.first} + ".manifest.raw.json", historyRaw},
				 {std::string{entry.first} + ".index.json.gz", historyBytes},
				 {std::string{entry.first} + ".manifest.json", key.envelope( historyRaw, keyId)}}} ;
			// 各新規fileの容量を加算してから保存し、既存fileへの上書きを拒否します。
			for( const auto &file : additions) {
				require( file.second.size() <= 1024U * 1024U &&
						projectedBytes <= 1024U * 1024U - file.second.size()) ;
				projectedBytes += file.second.size() ;
				std::printf( "FIXTURE_RESERVE name=%s bytes=%zu projectedBytes=%zu\n",
							file.first.c_str(), file.second.size(), projectedBytes) ;
				writePublicFixture( root / file.first, file.second) ;
			}
		}
	}

	std::printf(
		"PUBLIC_VERIFY_FIXTURES files=%u bytes=%zu ephemeralKeys=1 artificialSignatures=%u protectedKeyOperations=0\n",
		includeHistory ? 18U : 12U, projectedBytes, includeHistory ? 6U : 4U) ;
}

/** @brief 原manifestの唯一のkeyId値だけを人工公開鍵へ置換します。
 * @param[in] raw 変更前の原manifestです。
 * @param[in] keyId 人工RAM公開blobに結合したIDです。
 * @param[out] originalId 元fieldの値です。逆置換の原byte証明へ使います。
 * @return 他のbyteを保持した人工manifestです。
 * @throws std::runtime_error 一意の完全markerや終端がない場合。
 */
[[nodiscard]] std::string withFixtureKeyId( const std::string &raw, const std::string &keyId,
										   std::string &originalId)
{
	const std::string marker   = "\"keyId\":\"" ;		// P1の原fieldの完全markerだけです。
	const auto		  position = raw.find( marker) ;	// 一意性を検査する開始位置です。
	require( position != raw.npos && raw.find( marker, position + marker.size()) == raw.npos) ;
	const auto begin = position + marker.size() ;	// 値の先頭だけを変更します。
	const auto end	 = raw.find( '"', begin) ;		// 元JSON値の閉じ引用符です。
	require( end != raw.npos && end > begin) ;
	originalId	= raw.substr( begin, end - begin) ;
	auto result = raw ;	// 他fieldや空白を再serializationしません。
	result.replace( begin, end - begin, keyId) ;
	return result ;
}

/** @brief 公開byteだけのverifyをP1人工束と固定41条件へ接続します。
 * @param[in] root 実行前manifestへ固定した人工入力directoryです。
 * @throws std::runtime_error 原入力欠損/過大やRAM暗号前提が不成立の場合。
 * @note Persistent鍵、network、製品store、実CAT再検査やgrantを呼びません。
 */
void runDistributionAcquisitionFake( const std::filesystem::path &root)
{
	using namespace drivercrate ;
	EphemeralDistributionKey key ;	// BCryptのRAM ownerだけです。
	require( BCryptOpenAlgorithmProvider( &key.algorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0U) >= 0) ;
	require( BCryptGenerateKeyPair( key.algorithm, &key.key, 3072U, 0U) >= 0) ;
	require( BCryptFinalizeKeyPair( key.key, 0U) >= 0) ;
	std::vector<std::uint8_t> publicBlob( 411U) ;	// 非秘密の人工公開byteだけをexportします。
	ULONG					  publicSize{} ;		// 公開blobの実長です。
	require( BCryptExportKey( key.key, nullptr, BCRYPT_RSAPUBLIC_BLOB, publicBlob.data(),
							static_cast<ULONG>( publicBlob.size()), &publicSize, 0U) >= 0 &&
			publicSize == publicBlob.size()) ;
	const auto fingerprint = hash( {reinterpret_cast<const char *>( publicBlob.data()),
								   // 公開byte viewです。
								   publicBlob.size()}) ;
	const auto keyId = "distribution-index-" + fingerprint.substr( 0U, 32U) ;	// 人工配布IDだけです。
	// P1の未署名manifest原byteを保持します。
	const auto original =
		readCollectedInput( root / "P2-01A.manifest.raw.json", INDEX_MANIFEST_MAX_BYTES) ;
	const auto packedRaw =
		// P1原gzipです。
		readCollectedInput( root / "P2-01A.index.json.gz", INDEX_ASSET_MAX_BYTES) ;
	const auto packed = std::as_bytes(
		std::span<const char>{packedRaw.data(), packedRaw.size()}) ;		// P1原gzipを借用します。
	std::string originalId ;												// P1公開IDだけです。
	const auto	raw		 = withFixtureKeyId( original, keyId, originalId) ;	// 他byteは不変です。
	const auto	envelope = key.envelope( raw, keyId) ;						// 原byteをRAM RSA-PSSで署名します。
	// 全codecと取得用途を通った正例の公開receiptです。
	const auto	good =
		verifyDistributionAcquisitionIndex( envelope, packed, publicBlob, fingerprint, NOW) ;
	std::string fixtureId ;	// 逆置換時の人工元IDです。
	expect( withFixtureKeyId( raw, originalId, fixtureId) == original && fixtureId == keyId,
		   "P2-01B") ;
	expect( good.assetStatus == IndexAssetBytesStatus::BYTE_VALIDATED &&
			   good.recordsStatus == IndexRecordsStatus::SCHEMA_VALIDATED &&
			   hash( packedRaw) ==
				   hash( readCollectedInput( root / "P2-01A.index.json.gz", INDEX_ASSET_MAX_BYTES)),
		   "P2-01C") ;
	std::printf(
		"P1_BINDING originalManifest=%s fixtureManifest=%s gzip=%s keyIdOnlyReplacement=1\n",
		hash( original).c_str(), hash( raw).c_str(), hash( packedRaw).c_str()) ;
	/** @brief 固定artifact一組と用途上の期待結果です。 */
	struct Case {
		/// 全8群manifestの一意subcaseです。
		const char *id ;
		/// 全codec/用途を受理する正例だけtrueです。
		bool		accepted ;
		/// 期限の負例だけ現在時計へ加える時間です。
		unsigned	clockHours ;
	} ;
	const std::array<Case, 27U> cases{{{"P2-01A", true, 0U},  {"P2-02A", false, 0U},
									   {"P2-02D", false, 0U}, {"P2-04A", false, 0U},
									   {"P2-04B", false, 0U}, {"P2-04C", false, 0U},
									   {"P2-04D", false, 0U}, {"P2-04E", false, 0U},
									   {"P2-05A", false, 0U}, {"P2-05B", false, 0U},
									   {"P2-05C", false, 0U}, {"P2-05D", false, 0U},
									   {"P2-05E", false, 0U}, {"P2-05F", false, 0U},
									   {"P2-05G", false, 0U}, {"P2-06A", false, 0U},
									   {"P2-06B", false, 1U}, {"P2-06C", false, 0U},
									   {"P2-07A", false, 0U}, {"P2-07B", false, 0U},
									   {"P2-07C", false, 0U}, {"P2-08A", true, 0U},
									   {"P2-08B", true, 0U},  {"P2-08C", false, 0U},
									   {"P2-08D", false, 0U}, {"P2-08E", true, 0U},
									   {"P2-08F", true, 0U}}} ;	// 切捨てない固定分母です。
	// 各原入力を独立に署名し、一つの拒否で他caseを分母から除きません。
	for( const auto &testCase : cases) {
		// caseごとに固定した未署名manifestの原byteです。
		const auto manifestBytes = readCollectedInput(
			root / (std::string{testCase.id} + ".manifest.raw.json"), INDEX_MANIFEST_MAX_BYTES) ;
		// 同じcaseのmanifestへhash結合されたasset原byteです。
		const auto gzipBytes = readCollectedInput(
			root / (std::string{testCase.id} + ".index.json.gz"), INDEX_ASSET_MAX_BYTES) ;
		std::string beforeId ;	// 元fieldの公開IDです。
		const auto	adapted =
			// 公開IDだけをRAM用へ置換します。
			withFixtureKeyId( manifestBytes, keyId, beforeId) ;
		// 期待値と比較する公開byte検証の非秘密結果です。
		const auto result = verifyDistributionAcquisitionIndex(
			key.envelope( adapted, keyId),
			std::as_bytes( std::span<const char>{gzipBytes.data(), gzipBytes.size()}), publicBlob,
			fingerprint, NOW + std::chrono::hours{testCase.clockHours}) ;
		expect( (result.error == 0 && !result.envelope.empty()) == testCase.accepted, testCase.id) ;
		std::printf( "P2_DETAIL case=%s error=%d manifest=%d asset=%d records=%d\n", testCase.id,
					result.error,
					result.manifestStatus ? static_cast<int>( *result.manifestStatus) : -1,
					result.assetStatus ? static_cast<int>( *result.assetStatus) : -1,
					result.recordsStatus ? static_cast<int>( *result.recordsStatus) : -1) ;
	}

	const auto old = verifyDistributionIndex( envelope, packed, publicBlob, fingerprint,
											 NOW) ;	// 旧metadata用途は取得recordを拒否します。
	expect( old.error != 0 && old.recordsStatus == IndexRecordsStatus::SCHEMA_VALIDATED, "P2-02B") ;
	// 旧history用途でも取得recordを許可しないことを確認します。
	const auto history =
		verifyDistributionIndex( envelope, packed, publicBlob, fingerprint, NOW, true) ;
	expect( history.error != 0 && history.recordsStatus == IndexRecordsStatus::SCHEMA_VALIDATED,
		   "P2-02C") ;
	expect(
		verifyDistributionAcquisitionIndex( envelope, packed, publicBlob, std::string( 64U, '0'), NOW)
				.error != 0,
		"P2-03A") ;
	expect( verifyDistributionAcquisitionIndex( envelope, packed,
											  std::span<const std::uint8_t>{publicBlob}.first( 410U),
											  fingerprint, NOW)
				   .error != 0,
		   "P2-03B") ;
	std::string ignoredId ;	// 他profileの負例だけへ使う公開元値です。
	const auto	localId =
		"local-index-" + fingerprint.substr( 0U, 32U) ;	// Acceptance用途との混同を拒否するIDです。
	expect( verifyDistributionAcquisitionIndex(
			   key.envelope( withFixtureKeyId( raw, localId, ignoredId), localId), packed, publicBlob,
			   fingerprint, NOW)
				   .error != 0,
		   "P2-03C") ;
	const std::string unknownId = "unknown-key" ;	// 固定公開pinへ一致しない原IDです。
	expect( verifyDistributionAcquisitionIndex(
			   key.envelope( withFixtureKeyId( raw, unknownId, ignoredId), unknownId), packed,
			   publicBlob, fingerprint, NOW)
				   .error != 0,
		   "P2-03D") ;
	expect( verifyDistributionAcquisitionIndex( key.envelope( raw, keyId, 20U), packed, publicBlob,
											  fingerprint, NOW)
				   .error != 0,
		   "P2-03E") ;
	auto			  changedEnvelope = envelope ;	// 署名byteの一箇所だけを改変します。
	const std::string signatureMarker =
		"\"signatureBase64\":\"" ;	// 人工envelope内の署名field境界です。
	const auto signatureStart =
		// 一箇所改変する位置です。
		changedEnvelope.find( signatureMarker) + signatureMarker.size() ;
	require( signatureStart < changedEnvelope.size()) ;
	changedEnvelope[signatureStart] = changedEnvelope[signatureStart] == 'A' ? 'B' : 'A' ;
	expect( verifyDistributionAcquisitionIndex( changedEnvelope, packed, publicBlob, fingerprint, NOW)
				   .error != 0,
		   "P2-03F") ;
	expect(
		verifyDistributionAcquisitionIndex( envelope, packed, publicBlob, fingerprint, std::nullopt)
				.error != 0,
		"P2-06D") ;
	expect( verifyDistributionAcquisitionIndex( envelope, packed, publicBlob, fingerprint,
											  NOW + std::chrono::days{2})
				   .error != 0,
		   "P2-06E") ;
	expect( good.error == 0 && good.publicKey && !good.created && !good.publicKey->created &&
			   !good.publicKey->protectionVerified,
		   "P2-08H") ;
}

} // namespace

/** @brief 明示existing-key試験または非永続の人工配布試験だけを起動します。
 * @param[in] count 引数数です。
 * @param[in] args --existing-key fingerprint、または--collected-indexの固定五artifact pathです。
 * @return 期待全成功0、入力拒否2、原不成立1です。
 */
int main( const int count, char *args[])
{
	// 無人CIや未知commandでは既存keyを開きません。
	if( args == nullptr || count < 2) {
		return 2 ;
	}

	// 新履歴試験は固定32caseのRAM-only枝だけへ入り、既存鍵modeを呼びません。
	if( count == 2 && std::string_view{args[1]} == "--distribution-history-floor-fake") {
		try {
			runDistributionHistoryFloorFake() ;
		} catch( ...) {
			expect( false, "floor fixture prerequisite") ;
		}

		std::printf(
			"DISTRIBUTION_HISTORY_FLOOR_FAKE fixedCases=20 assertions=%u failures=%u ephemeralKeys=1 protectedKeyOperations=0 network=0\n",
			assertions, failures) ;
		return failures == 0U && assertions == 20U ? 0 : 1 ;
	}

	// 全record用途検査を行う従来historyの32条件も独立に維持します。
	if( count == 2 && std::string_view{args[1]} == "--distribution-acquisition-history-fake") {
		try {
			runDistributionAcquisitionHistoryFake() ;
		} catch( ...) {
			expect( false, "history fixture prerequisite") ;
		}

		std::printf(
			"DISTRIBUTION_ACQUISITION_HISTORY_FAKE fixedCases=32 assertions=%u failures=%u ephemeralKeys=1 protectedKeyOperations=0 network=0\n",
			assertions, failures) ;
		return failures == 0U && assertions == 32U ? 0 : 1 ;
	}

	// 拡張fixtureは旧十二fileを保持した別の明示modeだけで生成します。
	if( count == 3 && std::string_view{args[1]} == "--public-verify-history-fixtures") {
		try {
			exportPublicVerifyFixtures( args[2], true) ;
		} catch( ...) {
			std::printf( "PUBLIC_VERIFY_FIXTURES failed=1 protectedKeyOperations=0\n") ;
			return 1 ;
		}

		return 0 ;
	}

	// 公開検証CLI用の新規人工束だけをRAM鍵で出力し、既存鍵modeへ進みません。
	if( count == 3 && std::string_view{args[1]} == "--public-verify-fixtures") {
		try {
			exportPublicVerifyFixtures( args[2]) ;
		} catch( ...) {
			std::printf( "PUBLIC_VERIFY_FIXTURES failed=1 protectedKeyOperations=0\n") ;
			return 1 ;
		}

		return 0 ;
	}

	// 新用途はexactな明示RAM-only modeだけで人工artifactを読み、永続鍵を呼びません。
	if( count == 3 && std::string_view{args[1]} == "--distribution-acquisition-fake") {
		expect( std::string_view{args[1]} == "--distribution-acquisition-fake", "P2-08G") ;
		try {
			runDistributionAcquisitionFake( args[2]) ;
		} catch( ...) {
			expect( false, "distribution acquisition fake prerequisite") ;
		}

		std::printf(
			"DISTRIBUTION_ACQUISITION_FAKE groups=8 fixedCases=41 assertions=%u failures=%u ephemeralKeys=1 protectedKeyOperations=0 network=0\n",
			assertions, failures) ;
		return failures == 0U ? 0 : 1 ;
	}

	// 配布fakeはRAM鍵だけを生成し、実保護鍵を照会しません。
	if( count == 2 && std::string_view{args[1]} == "--distribution-fake") {
		try {
			runDistributionFake() ;
		} catch( ...) {
			expect( false, "distribution fake prerequisite") ;
		}

		std::printf(
			"DISTRIBUTION_FAKE assertions=%u failures=%u ephemeralKeys=1 protectedKeyOperations=0 network=0\n",
			assertions, failures) ;
		return failures == 0U ? 0 : 1 ;
	}

	// 実収集入力はkey操作なしの別modeでだけ検証します。
	if( count == 7 && std::string_view{args[1]} == "--collected-index") {
		try {
			runCollected( args) ;
		} catch( ...) {
			expect( false, "collected input prerequisite exception") ;
			std::printf( "COLLECTED_INDEX_TESTS assertions=%u failures=%u terminalRejected=1\n",
						assertions, failures) ;
		}

		return failures == 0U ? 0 : 1 ;
	}

	// 新用途は旧35/21条件から独立した明示modeでだけ実行します。
	if( count == 3 && std::string_view{args[1]} == "--acquisition-purpose") {
		try {
			runAcquisitionPurpose( args[2]) ;
		} catch( ...) {
			expect( false, "acquisition purpose prerequisite exception") ;
		}

		std::printf(
			"ACQUISITION_PURPOSE_TESTS assertions=%u failures=%u artificialRecords=1 realPayloads=0 createdKeys=0\n",
			assertions, failures) ;
		return failures == 0U ? 0 : 1 ;
	}

	// 既存35条件の未知commandは暗黙実行しません。
	if( count != 3 || std::string_view{args[1]} != "--existing-key") {
		return 2 ;
	}

	try {
		run( args[2]) ;
	} catch( ...) {
		expect( false, "fixture prerequisite exception") ;
	}

	std::printf(
		"LOCAL_INDEX_TESTS assertions=%u failures=%u artificialRecords=1 createdKeys=0 localPins=%zu acquisitionKeys=%zu\n",
		assertions, failures, drivercrate::local_index_profile::TRUST_KEYS.size(),
		drivercrate::local_index_profile::ACQUISITION_KEYS.size()) ;
	return failures == 0U ? 0 : 1 ;
}
