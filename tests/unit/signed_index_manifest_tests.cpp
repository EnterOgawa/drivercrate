//------------------------------------------------------------------------------
/**
 * @file signed_index_manifest_tests.cpp
 * @brief 非永続CNG RSA鍵の実署名でmanifest認証の拒否境界を検査します。
 * @version 01.12.00
 * @date 2026/10/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  RAM鍵のnative署名・JSON・期限・世代の回帰を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/11  同RAM鍵から実GZip assetの別group検査を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/11  同helperで配布recordとUNKNOWN・原hash拒否を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/11  隔離diskの実DPAPI・原子head・世代拒否を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/11  実保存snapshotから有限公開ID照合の独立groupを追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/11  実Driver Store秘密属性resolverへ保存snapshotを接続。
 * Ver.01.06.00 Shunji Ogawa  2026/10/11  通常workerの同scan署名索引読取り境界を接続。
 * Ver.01.07.00 Shunji Ogawa  2026/10/12  同RAM署名と隔離storeでv2取得descriptor codecを検査。
 * Ver.01.08.00 Shunji Ogawa  2026/10/12  真署名索引から共通取得・検査と拒否の内部fixtureを追加。
 * Ver.01.09.00 Shunji Ogawa  2026/10/12  私有batch集約と通常workerの非空INF取得fixtureを追加。
 * Ver.01.10.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.10.01 Shunji Ogawa  2026/10/12  二通常classへ真正recordを結ぶfixture宣言を説明。
 * Ver.01.10.02 Shunji Ogawa  2026/10/14  共通HTML追加後の現reader policy3へ既存期待値を追従。
 * Ver.01.11.00 Shunji Ogawa  2026/10/14  同v2署名snapshotへnative部分positive準備の正負を接続。
 * Ver.01.11.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.11.02 Shunji Ogawa  2026/10/16  製品固定公開pinとmanifest-only取得拒否を追加。
 * Ver.01.12.00 Shunji Ogawa  2026/10/19  旧headの認証移動と世代/中断/拒否回帰を追加。
 * </pre>
 *
 * @note 秘密鍵はCNG handleのRAM内だけにあり、public blob以外をexportしません。
 * Test材料を製品libraryのtrustへ配置せず、network・製品store・実device・導入を呼びません。
 * 保存試験は自作の隔離directoryだけへ実DPAPIとfile APIを使います。
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#include "signed_index_manifest_tests.h"
#include "signed_index_candidate_binding_tests.h"
#include "metadata_inventory_tests.h"

#include <array>
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <winioctl.h>
#include <bcrypt.h>
#include <miniz.h>

#include "platform/signed_index_asset_bytes.h"
#include "platform/signed_index_manifest_internal.h"
#include "platform/signed_index_records.h"
#include "platform/signed_index_record_lookup.h"
#include "platform/signed_index_store_internal.h"
#include "platform/signed_index_json_internal.h"
#include "platform/signed_index_acquisition_adapter.h"
#include "platform/signed_index_acquisition_adapter_internal.h"
#include "platform/index_distribution_trust.h"
#include "platform/index_legacy_migration_trust.h"
#include "local_index_acceptance.h"
#include "test_framework.h"

namespace drivercrate::test {
/** @brief 真署名隔離storeを実worker取得fixtureへ渡します。
 * @param[in,out] context 共通assertion所有者。
 * @param[in] store 実原byte再認証する隔離store。
 * @param[in] nowUtc 固定信頼UTC。
 * @param[in] zip 文法上有効なINF・参照fileを含む非空原ZIP。
 * @param[in] recordCount 元署名recordの有限件数。
 * @param[in] skip 完了不一致を先行させる関係数。
 */
void runNormalIndexWorkerAcquisitionTests( TestContext					   &context,
										  std::shared_ptr<SignedIndexStore> store,
										  std::chrono::sys_seconds nowUtc, const std::string &zip,
										  std::size_t recordCount, std::size_t skip) ;
/** @brief 真署名lookupを既存完全fake HTTPの取得・seal・共通検査へ渡します。
 * @param[in,out] context 共通assertion集計先。
 * @param[in] lookup 真署名・隔離reloadから構築した不変lookup。
 * @param[in] nowUtc 固定信頼UTC。
 * @param[in] scenario 0は通常、1は計算hash不一致、2はsize不一致、3は保留、4はCDN、6は未知hash／sizeです。
 */
void runSignedIndexAcquisitionAdapterTests( TestContext									 &context,
										   std::shared_ptr<const SignedIndexRecordLookup> lookup,
										   std::chrono::sys_seconds nowUtc, unsigned scenario) ;
namespace {

// 固定検査UTC。OS時計を使わず期限境界を決定的に検査する。
const std::chrono::sys_seconds NOW =
	std::chrono::sys_days{std::chrono::year{2026} / 10 / 11} + std::chrono::hours{6} ;
// 架空assetの固定digest。実asset検証を実行したことにはしない。
constexpr std::string_view ASSET_HASH =
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ;

/** @brief API失敗をfixture成功へ変換せずunit processへ通知します。
 * @param[in] status 元NTSTATUS。
 */
void checkNative( const NTSTATUS status)
{
	// 秘密materialを含まない固定説明だけでfixture生成失敗を通知する。
	if( status < 0) {
		throw std::runtime_error( "CNG RAM fixture API failed") ;
	}
}

/** @brief 鍵生成・署名に使うCNG resourceをRAM内だけで単独所有します。 */
class RamKey final {
public:
	/** @brief 取得前のownerを作ります。 */
	RamKey() = default ;
	/** @brief 秘密鍵を含むCNG handleとalgorithmを全経路で解放します。 */
	~RamKey() noexcept
	{
		// 鍵をalgorithmより先に回収し、秘密鍵を永続化しない。
		if( key_ != nullptr) {
			static_cast<void>( BCryptDestroyKey( key_)) ;
		}

		// SHA algorithmも途中のfixture失敗で残さない。
		if( sha_ != nullptr) {
			static_cast<void>( BCryptCloseAlgorithmProvider( sha_, 0U)) ;
		}

		// RSA algorithmは最後に回収する。
		if( rsa_ != nullptr) {
			static_cast<void>( BCryptCloseAlgorithmProvider( rsa_, 0U)) ;
		}
	}
	/** @brief 単独所有のためコピー構築を禁止します。 */
	RamKey( const RamKey &) = delete ;
	/** @brief 単独所有のためコピー代入を禁止します。
     * @return 呼出しは禁止されます。
     */
	RamKey &operator=( const RamKey &) = delete ;

	/** @brief 名前を持たない非永続RSA鍵を一回生成します。
     * @param[in] bits FixtureのRSA bit長。
     * @note Public blobだけをexportします。秘密鍵exportやNCrypt永続storeを使いません。
     */
	void	generate( const ULONG bits)
	{
		checkNative( BCryptOpenAlgorithmProvider( &rsa_, BCRYPT_RSA_ALGORITHM, nullptr, 0U)) ;
		checkNative( BCryptGenerateKeyPair( rsa_, &key_, bits, 0U)) ;
		checkNative( BCryptFinalizeKeyPair( key_, 0U)) ;
		checkNative( BCryptOpenAlgorithmProvider( &sha_, BCRYPT_SHA256_ALGORITHM, nullptr, 0U)) ;
		ULONG bytes{} ;	// Public blob容量。Private blobを要求しない。
		checkNative( BCryptExportKey( key_, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0U, &bytes, 0U)) ;
		publicBlob.resize( bytes) ;
		checkNative( BCryptExportKey( key_, nullptr, BCRYPT_RSAPUBLIC_BLOB, publicBlob.data(), bytes,
									&bytes, 0U)) ;
		publicBlob.resize( bytes) ;
	}

	/** @brief Test側の独立CNG hashで原byteをSHA-256へ結合します。
     * @param[in] bytes 原byte。
     * @return 実CNG digest。
     */
	[[nodiscard]] IndexManifestSha256 digest( const std::string_view bytes) const
	{
		std::vector<std::uint8_t> input( bytes.begin(), bytes.end()) ;	// CNG境界だけの所有copy。
		IndexManifestSha256		  hash{} ;								// 固定32byte出力。
		checkNative( BCryptHash( sha_, nullptr, 0U, input.data(), static_cast<ULONG>( input.size()),
							   hash.data(), static_cast<ULONG>( hash.size()))) ;
		return hash ;
	}

	/** @brief 原byteをRAM内private keyで実RSA-PSS署名します。
     * @param[in] bytes 署名対象。再整形しません。
     * @param[in] saltBytes 固定32または拒否fixture用の別salt長。
     * @return 原byteに対する実署名。
     */
	[[nodiscard]] std::vector<std::uint8_t> sign( const std::string_view bytes,
												 const ULONG			saltBytes = 32U) const
	{
		IndexManifestSha256		hash = digest( bytes) ;							// 製品hash APIに依存しない署名対象。
		BCRYPT_PSS_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM, saltBytes} ;	// Native PSS設定。
		ULONG					size{} ;										// Key長に由来する実署名長。
		checkNative( BCryptSignHash( key_, &padding, hash.data(), static_cast<ULONG>( hash.size()),
								   nullptr, 0U, &size, BCRYPT_PAD_PSS)) ;
		std::vector<std::uint8_t> signature( size) ;	// Secret keyとは別の署名byte。
		checkNative( BCryptSignHash( key_, &padding, hash.data(), static_cast<ULONG>( hash.size()),
								   signature.data(), size, &size, BCRYPT_PAD_PSS)) ;
		signature.resize( size) ;
		return signature ;
	}
	/// Test verifierへ渡すpublic blobだけの所有値。
	std::vector<std::uint8_t> publicBlob ;

private:
	/// RAMだけのRSA algorithm。
	BCRYPT_ALG_HANDLE rsa_{} ;
	/// RAMだけの秘密鍵handle。Exportや保存をしません。
	BCRYPT_KEY_HANDLE key_{} ;
	/// RAMだけのSHA-256 algorithm。
	BCRYPT_ALG_HANDLE sha_{} ;
} ;

/** @brief Test側で正規base64を作ります。
 * @param[in] bytes 原byte。
 * @return 標準alphabetと正規paddingのASCII。
 */
[[nodiscard]] std::string encodeBase64( const std::span<const std::uint8_t> bytes)
{
	constexpr std::string_view ALPHABET =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ;	// 標準alphabet。
	std::string encoded ;														// Test専用所有base64。
	// 原byteを三byteずつ走査し、末尾だけをpaddingする。
	for( std::size_t offset = 0U; offset < bytes.size(); offset += 3U) {
		const unsigned first = bytes[offset] ;	// 必須第一byte。
		const unsigned second =
			offset + 1U < bytes.size() ? bytes[offset + 1U] : 0U ;						// 欠けたbyteはpaddingで表す。
		const unsigned third = offset + 2U < bytes.size() ? bytes[offset + 2U] : 0U ;	// 最終byte。
		encoded.push_back( ALPHABET[first >> 2U]) ;
		encoded.push_back( ALPHABET[((first & 3U) << 4U) | (second >> 4U)]) ;
		encoded.push_back(
			offset + 1U < bytes.size() ? ALPHABET[((second & 15U) << 2U) | (third >> 6U)] : '=') ;
		encoded.push_back( offset + 2U < bytes.size() ? ALPHABET[third & 63U] : '=') ;
	}

	return encoded ;
}

/** @brief UTF-8原byteをtest側base64へ変換します。
 * @param[in] bytes 原UTF-8。
 * @return 原byteのbase64。
 */
[[nodiscard]] std::string encodeText( const std::string_view bytes)
{
	const std::vector<std::uint8_t> input( bytes.begin(),
										  // Const pointer castを使わないcopy。
										  bytes.end()) ;
	return encodeBase64( input) ;
}

/** @brief 人工manifest原byteを作ります。Field順は製品契約として固定しません。
 * @return 全必須値を持つ架空manifest。
 */
[[nodiscard]] std::string manifest()
{
	return "{\"schema\":\"driver-index-manifest-v1\",\"repository\":\"EnterOgawa/drivercrate\","
		   "\"channel\":\"driver-index\",\"keyId\":\"fixture-main\",\"generation\":7,\"assetGeneration\":7,"
		   "\"publishedAtUtc\":\"2026-10-11T05:00:00Z\",\"expiresAtUtc\":\"2026-10-25T05:00:00Z\","
		   "\"asset\":{\"tag\":\"index-v1-20261011-" +
		   std::string{ASSET_HASH} +
		   "\",\"name\":\"index.json.gz\",\"compression\":\"gzip\",\"sizeBytes\":123,\"sha256\":\"" +
		   std::string{ASSET_HASH} +
		   "\"},\"quality\":{\"sourceCount\":1,\"recordCount\":3,"
		   "\"metadataOnlyCount\":1,\"contentInspectedCount\":1,\"unconfirmedCount\":1}}" ;
}

/** @brief 一箇所だけを意図した値へ変える拒否fixtureを作ります。
 * @param[in] bytes 元fixture。
 * @param[in] before 必ず存在する元断片。
 * @param[in] after 変更断片。
 * @return 一箇所を変更した所有原byte。
 */
[[nodiscard]] std::string replaced( std::string bytes, const std::string_view before,
								   const std::string_view after)
{
	const std::size_t position = bytes.find( before) ;	// 意図した唯一の変更位置。
	// Test生成不成立をcodec拒否の合格へ読み替えない。
	if( position == std::string::npos) {
		throw std::runtime_error( "fixture replacement not found") ;
	}

	bytes.replace( position, before.size(), after) ;
	return bytes ;
}

/** @brief Testで署名済み原byteを有限envelopeへ包みます。
 * @param[in] raw 元manifest。
 * @param[in] signature 元署名。
 * @param[in] keyId 外側ID。
 * @return 署名対象を再serializationしない外側JSON。
 */
[[nodiscard]] std::string envelope( const std::string_view			   raw,
								   const std::span<const std::uint8_t> signature,
								   const std::string_view			   keyId = "fixture-main")
{
	return "{\"schema\":\"driver-index-envelope-v1\",\"keyId\":\"" + std::string{keyId} +
		   "\",\"manifestBytesBase64\":\"" + encodeText( raw) + "\",\"signatureBase64\":\"" +
		   encodeBase64( signature) + "\"}" ;
}

/** @brief 一拒否ケースで理由と認証receiptの不在を確認します。
 * @param[in,out] context 集計先。
 * @param[in] result 実native検査結果。
 * @param[in] expected 固定拒否理由。
 */
void expectRejected( TestContext &context, const SignedIndexManifestResult &result,
					const SignedIndexManifestStatus expected)
{
	DRIVERCRATE_EXPECT( context, result.status == expected) ;
	DRIVERCRATE_EXPECT( context, !result.manifest.has_value()) ;
}

/** @brief 不正RSA整数の値域とCNGの厳格な拒否区分を独立して照合します。
 * @param[in,out] context 共通集計先。
 * @param[in] result 実CNG認証の結果。
 * @param[in] signature 署名とみなして入力した384byte整数。
 * @param[in] blob Trustへ使った既知の正常3072bit public blob。
 * @note 値域外は元INVALID_PARAMETER、値域内の不一致はINVALID_SIGNATUREを要求します。
 */
void expectSignatureIntegerRejected( TestContext &context, const SignedIndexManifestResult &result,
									const std::span<const std::uint8_t> signature,
									const std::span<const std::uint8_t> blob)
{
	constexpr std::size_t MODULUS_OFFSET =
		// 既知blobの指数65537の直後です。
		sizeof( BCRYPT_RSAKEY_BLOB) + 3U ;
	// Fixture前提が崩れた場合は値域判定を推測しません。
	if( signature.size() != 384U || blob.size() != MODULUS_OFFSET + 384U) {
		throw std::runtime_error( "RSA integer fixture shape failed") ;
	}

	const auto modulus = blob.subspan( MODULUS_OFFSET, 384U) ;	// 独立したtrust public modulusです。
	const bool outside =
		!std::lexicographical_compare( signature.begin(), signature.end(), modulus.begin(),
									  // Big-endian整数s>=nです。
									  modulus.end()) ;
	const auto expected =
		outside
			? SignedIndexManifestStatus::CRYPTO_FAILURE
			: SignedIndexManifestStatus::INVALID_SIGNATURE ;	// 暗号verifierの区分は変更しません。
	constexpr NTSTATUS INVALID_PARAMETER_STATUS =
		// 値域外入力のCNG診断です。
		static_cast<NTSTATUS>( 0xC000000DU) ;
	constexpr NTSTATUS INVALID_SIGNATURE_STATUS =
		// 値域内不一致のCNG診断です。
		static_cast<NTSTATUS>( 0xC000A000U) ;
	const NativeError expectedError = static_cast<NativeError>(
		HRESULT_FROM_NT( outside ? INVALID_PARAMETER_STATUS
								: INVALID_SIGNATURE_STATUS)) ;	// 任意crypto errorへ広げません。
	std::cout << "RSA rejected integer range outside: " << outside
			  << ", status: " << static_cast<unsigned>( result.status)
			  << ", error: " << static_cast<std::uint32_t>( result.error) << '\n' ;
	expectRejected( context, result, expected) ;
	DRIVERCRATE_EXPECT( context, result.error == expectedError) ;
}

/** @brief 一つの署名し直した不正manifestを実CNG経路へ渡します。
 * @param[in,out] context 集計先。
 * @param[in] key RAM内署名鍵。
 * @param[in] trust 内部test専用公開鍵集合。
 * @param[in] raw 不正schemaまたは意味を持つ原byte。
 * @param[in] expected 固定拒否理由。
 */
void rejectManifest( TestContext &context, const RamKey &key,
					const std::span<const signed_index_detail::TrustKey> trust,
					const std::string_view raw, const SignedIndexManifestStatus expected)
{
	const auto signedBytes = key.sign( raw) ;	// 不正内容にも正しい実署名を付けて意味層を検査する。
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( envelope( raw, signedBytes), NOW,
																  std::nullopt, trust),
				   expected) ;
}

} // namespace

void runSignedIndexManifestTests( TestContext &context)
{
	static_assert( !std::is_default_constructible_v<AuthenticatedIndexManifest>) ;
	static_assert( !std::is_constructible_v<AuthenticatedIndexManifest, IndexManifestData>) ;
	const int firstAssertion = context.assertionCount() ;	// このgroupだけの実行件数。
	const int firstFailure	 = context.failureCount() ;		// このgroupだけの失敗件数。
	RamKey	  mainKey ;										// 秘密鍵はCNG handleのRAMだけ。
	RamKey	  otherKey ;									// 別の信頼済み3072bit鍵。
	RamKey	  smallKey ;									// 2048bit拒否用だけのRAM鍵。
	mainKey.generate( 3072U) ;
	otherKey.generate( 3072U) ;
	smallKey.generate( 2048U) ;
	// 公開byteだけの非owning viewをRAM内の独立SHA実装へ渡します。
	const auto				   productDigest = mainKey.digest( std::string_view{
		reinterpret_cast<const char *>( index_distribution_trust::PUBLIC_BLOB.data()),
		index_distribution_trust::PUBLIC_BLOB.size()}) ;
	std::string				   productFingerprint ;			// 所有する小文字hex表現だけです。
	constexpr std::string_view HEX = "0123456789abcdef" ;	// 公開digestの表示用です。
	// 全32byteを省略せずfingerprintへ結合します。
	for( const auto byte : productDigest) {
		productFingerprint += HEX[byte >> 4U] ;
		productFingerprint += HEX[byte & 15U] ;
	}

	DRIVERCRATE_EXPECT( context,
					   index_distribution_trust::PUBLIC_BLOB.size() == 411U &&
						   productFingerprint == index_distribution_trust::PUBLIC_FINGERPRINT) ;
	DRIVERCRATE_EXPECT( context, index_distribution_trust::TRUST_KEYS.size() == 1U &&
									index_distribution_trust::ACQUISITION_KEYS.size() == 1U &&
									index_distribution_trust::ACQUISITION_POLICY_REVISION == 1U &&
									index_distribution_trust::KEY_ID ==
										"distribution-index-" + productFingerprint.substr( 0U, 32U)) ;
	DRIVERCRATE_EXPECT( context, signed_index_detail::productTrustAvailable() &&
									(local_index_profile::ENABLED ||
									 (local_index_profile::TRUST_KEYS.empty() &&
									  local_index_profile::ACQUISITION_KEYS.empty()))) ;
	const std::array<signed_index_detail::TrustKey, 2U> trust{
		{{"fixture-main", mainKey.publicBlob},
		 {"fixture-other", otherKey.publicBlob}}} ;					// Test targetだけの有限公開鍵集合。
	const std::string raw			 = manifest() ;					// 人工原manifest。
	const auto		  signature		 = mainKey.sign( raw) ;			// 実RSA-PSS salt32署名。
	const std::string signedEnvelope = envelope( raw, signature) ;	// 原byteを保つ正例。
	const auto		  accepted		 = signed_index_detail::authenticateWithTrustKeys(
		 signedEnvelope, NOW, std::nullopt, trust) ;	// 実CNG正例。
	DRIVERCRATE_EXPECT( context, accepted.status == SignedIndexManifestStatus::AUTHENTICATED) ;
	DRIVERCRATE_EXPECT( context, accepted.error == 0) ;
	DRIVERCRATE_EXPECT( context, accepted.manifest.has_value()) ;
	// 正例不成立時は認証receiptを参照せず、このgroupを失敗として終了する。
	if( !accepted.manifest.has_value()) {
		return ;
	}

	const auto &data = accepted.manifest->data() ;	// 書換え不可の認証値。
	DRIVERCRATE_EXPECT( context, data.manifestBytes == raw) ;
	DRIVERCRATE_EXPECT( context, data.manifestSha256 == mainKey.digest( raw)) ;
	DRIVERCRATE_EXPECT( context, data.generation == 7U && data.assetGeneration == 7U) ;
	DRIVERCRATE_EXPECT( context, data.asset.sizeBytes == 123U && data.asset.name == "index.json.gz") ;
	DRIVERCRATE_EXPECT( context,
					   data.quality.unconfirmedCount == 1U && data.quality.recordCount == 3U) ;
	DRIVERCRATE_EXPECT( context, data.expiresAtUtc - data.publishedAtUtc == std::chrono::days{14}) ;
	expectRejected( context, authenticateSignedIndexManifest( signedEnvelope, NOW, std::nullopt),
				   SignedIndexManifestStatus::UNKNOWN_KEY) ;
	// 既存RAM署名を製品公開keyIdへ変えても真署名成功にはなりません。
	const auto productRaw =
		// 他fieldは不変です。
		replaced( raw, "fixture-main", index_distribution_trust::KEY_ID) ;
	const auto productEnvelope = envelope( productRaw, mainKey.sign( productRaw),
										  index_distribution_trust::KEY_ID) ;	// RAM署名だけです。
	const auto productRejected =
		// 実選択境界です。
		authenticateSignedIndexManifest( productEnvelope, NOW, std::nullopt) ;
	DRIVERCRATE_EXPECT( context,
					   (productRejected.status == SignedIndexManifestStatus::UNKNOWN_KEY) ==
							   local_index_profile::ENABLED &&
						   productRejected.status != SignedIndexManifestStatus::AUTHENTICATED &&
						   !productRejected.manifest) ;
	std::cout << "P3 native public pin/trust: local=" << local_index_profile::ENABLED
			  << ", localTrust=" << local_index_profile::TRUST_KEYS.size()
			  << ", localAcquisition=" << local_index_profile::ACQUISITION_KEYS.size()
			  << ", production signature UNCONFIRMED\n" ;

	const IndexManifestHighWater highWater{data.generation,
										   data.manifestSha256} ;	// 副作用なく照合する固定state。
	const auto					 same = signed_index_detail::authenticateWithTrustKeys(
		  signedEnvelope, NOW, highWater, trust) ;	// 同世代同原byteの正例。
	DRIVERCRATE_EXPECT( context, same.status == SignedIndexManifestStatus::AUTHENTICATED &&
									same.manifest.has_value()) ;
	DRIVERCRATE_EXPECT( context, highWater.generation == 7U &&
									highWater.manifestSha256 == data.manifestSha256) ;

	const std::string alternate = replaced( raw, "\"schema\":\"driver-index-manifest-v1\",",
										   "") ;	// Field順を変える正例の本体。
	// Schemaを最後のfieldへ移し、標準空白も含めて署名対象の原byteを変える。
	const std::string reordered = "\n " + alternate.substr( 0U, alternate.size() - 1U) +
								  ", \"schema\" : \"driver-index-manifest-v1\" }\r\n" ;
	const auto reorderedResult = signed_index_detail::authenticateWithTrustKeys(
		envelope( reordered, mainKey.sign( reordered)), NOW, std::nullopt,
		trust) ;	// 原byteを再整形しない正例。
	DRIVERCRATE_EXPECT( context, reorderedResult.status == SignedIndexManifestStatus::AUTHENTICATED) ;
	DRIVERCRATE_EXPECT( context, reorderedResult.manifest.has_value() &&
									reorderedResult.manifest->data().manifestBytes == reordered) ;
	const std::string escaped = replaced( raw, "EnterOgawa/drivercrate",
										 "EnterOgawa\\/drivercrate") ;	// 標準slash escape正例。
	// 標準escapeを含む原byteの独立した認証結果。
	const auto		  escapedResult = signed_index_detail::authenticateWithTrustKeys(
		   envelope( escaped, mainKey.sign( escaped)), NOW, std::nullopt, trust) ;
	DRIVERCRATE_EXPECT( context, escapedResult.status == SignedIndexManifestStatus::AUTHENTICATED) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys(
					   envelope( reordered, mainKey.sign( reordered)), NOW, highWater, trust),
				   SignedIndexManifestStatus::GENERATION_CONFLICT) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys(
					   signedEnvelope, NOW, IndexManifestHighWater{8U, data.manifestSha256}, trust),
				   SignedIndexManifestStatus::GENERATION_ROLLBACK) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys(
					   signedEnvelope, NOW, IndexManifestHighWater{0U, data.manifestSha256}, trust),
				   SignedIndexManifestStatus::INVALID_HIGH_WATER) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys(
					   signedEnvelope, NOW, IndexManifestHighWater{7U, {}}, trust),
				   SignedIndexManifestStatus::INVALID_HIGH_WATER) ;
	const std::string restored =
		replaced( replaced( raw, "\"generation\":7", "\"generation\":8"), "\"assetGeneration\":7",
				 "\"assetGeneration\":3") ;	// 新manifestが旧assetを参照する正例。
	// 新しい世代で旧assetを参照した場合のmanifest認証結果。
	const auto restoredResult = signed_index_detail::authenticateWithTrustKeys(
		envelope( restored, mainKey.sign( restored)), NOW, highWater, trust) ;
	DRIVERCRATE_EXPECT( context, restoredResult.status == SignedIndexManifestStatus::AUTHENTICATED) ;
	DRIVERCRATE_EXPECT( context, restoredResult.manifest.has_value() &&
									restoredResult.manifest->data().assetGeneration == 3U) ;
	const std::string otherRaw =
		// 別の既知IDの正例。
		replaced( raw, "fixture-main", "fixture-other") ;
	// 内部固定集合の別鍵で署名した場合の独立結果。
	const auto otherResult = signed_index_detail::authenticateWithTrustKeys(
		envelope( otherRaw, otherKey.sign( otherRaw), "fixture-other"), NOW, std::nullopt, trust) ;
	DRIVERCRATE_EXPECT( context, otherResult.status == SignedIndexManifestStatus::AUTHENTICATED) ;
	const auto wrongKeySignature = otherKey.sign( raw) ;	// 別鍵の原署名を再試行・補正せず保持します。
	expectSignatureIntegerRejected( context,
								   signed_index_detail::authenticateWithTrustKeys(
									   envelope( raw, wrongKeySignature), NOW, std::nullopt, trust),
								   wrongKeySignature, mainKey.publicBlob) ;
	const std::vector<std::uint8_t> outsideSignature(
		384U, 255U) ;	// 任意3072bit modulus以上の決定的整数です。
	expectSignatureIntegerRejected( context,
								   signed_index_detail::authenticateWithTrustKeys(
									   envelope( raw, outsideSignature), NOW, std::nullopt, trust),
								   outsideSignature, mainKey.publicBlob) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys(
					   envelope( raw, signature, "unknown-key"), NOW, std::nullopt, trust),
				   SignedIndexManifestStatus::UNKNOWN_KEY) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys(
					   envelope( raw, mainKey.sign( raw, 20U)), NOW, std::nullopt, trust),
				   SignedIndexManifestStatus::INVALID_SIGNATURE) ;
	auto changedSignature = signature ;	// 一byteだけ改変する署名copy。
	changedSignature[0] ^= 1U ;
	expectSignatureIntegerRejected( context,
								   signed_index_detail::authenticateWithTrustKeys(
									   envelope( raw, changedSignature), NOW, std::nullopt, trust),
								   changedSignature, mainKey.publicBlob) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( envelope( raw + " ", signature),
																  NOW, std::nullopt, trust),
				   SignedIndexManifestStatus::INVALID_SIGNATURE) ;
	changedSignature.pop_back() ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( envelope( raw, changedSignature),
																  NOW, std::nullopt, trust),
				   SignedIndexManifestStatus::INVALID_SIGNATURE) ;

	const std::array<signed_index_detail::TrustKey, 1U> smallTrust{
		{{"fixture-main", smallKey.publicBlob}}} ;	// 不許可2048bit。
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( signedEnvelope, NOW, std::nullopt,
																  smallTrust),
				   SignedIndexManifestStatus::INVALID_TRUST_KEY) ;
	const std::array<signed_index_detail::TrustKey, 2U> duplicateTrust{
		{{"fixture-main", mainKey.publicBlob},
		 {"fixture-main", otherKey.publicBlob}}} ;	// 曖昧な内部集合。
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( signedEnvelope, NOW, std::nullopt,
																  duplicateTrust),
				   SignedIndexManifestStatus::INVALID_TRUST_KEY) ;
	std::vector<std::uint8_t> invalidBlob = mainKey.publicBlob ;	// 内部公開blobの拒否fixture。
	invalidBlob[sizeof( BCRYPT_RSAKEY_BLOB) + 2U] = 3U ;
	std::array<signed_index_detail::TrustKey, 1U> invalidTrust{
		{{"fixture-main", invalidBlob}}} ;	// 65537以外。
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( signedEnvelope, NOW, std::nullopt,
																  invalidTrust),
				   SignedIndexManifestStatus::INVALID_TRUST_KEY) ;
	invalidBlob = mainKey.publicBlob ;
	invalidBlob.push_back( 0U) ;
	invalidTrust[0].rsaPublicBlob = invalidBlob ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( signedEnvelope, NOW, std::nullopt,
																  invalidTrust),
				   SignedIndexManifestStatus::INVALID_TRUST_KEY) ;
	invalidBlob = mainKey.publicBlob ;
	BCRYPT_RSAKEY_BLOB privateHeader{} ;	// Public blobにprivate flagを偽装する拒否fixture。
	std::memcpy( &privateHeader, invalidBlob.data(), sizeof( privateHeader)) ;
	privateHeader.cbPrime1 = 1U ;
	std::memcpy( invalidBlob.data(), &privateHeader, sizeof( privateHeader)) ;
	invalidTrust[0].rsaPublicBlob = invalidBlob ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( signedEnvelope, NOW, std::nullopt,
																  invalidTrust),
				   SignedIndexManifestStatus::INVALID_TRUST_KEY) ;

	// 署名が成立した不正manifestを意味層まで渡し、固定条件を一つずつ拒否する。
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "EnterOgawa/drivercrate", "OtherOwner/drivercrate"),
				   SignedIndexManifestStatus::REPOSITORY_MISMATCH) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"channel\":\"driver-index\"", "\"channel\":\"research\""),
				   SignedIndexManifestStatus::CHANNEL_MISMATCH) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "fixture-main", "fixture-other"),
				   SignedIndexManifestStatus::KEY_MISMATCH) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "driver-index-manifest-v1", "research-index-v3"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "2026-10-11T05:00:00Z", "2026-10-11T07:00:00Z"),
				   SignedIndexManifestStatus::INVALID_TIME) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "2026-10-25T05:00:00Z", "2026-10-25T05:00:01Z"),
				   SignedIndexManifestStatus::INVALID_TIME) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "2026-10-25T05:00:00Z", "2026-10-11T06:00:00Z"),
				   SignedIndexManifestStatus::INVALID_TIME) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "2026-10-25T05:00:00Z", "2026-10-11T05:00:00Z"),
				   SignedIndexManifestStatus::INVALID_TIME) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "2026-10-11T05:00:00Z", "2026-02-30T05:00:00Z"),
				   SignedIndexManifestStatus::INVALID_TIME) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "2026-10-11T05:00:00Z", "2026-10-11T25:00:00Z"),
				   SignedIndexManifestStatus::INVALID_TIME) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "2026-10-11T05:00:00Z", "2026-10-11T05:00:00+00"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( signedEnvelope, std::nullopt,
																  std::nullopt, trust),
				   SignedIndexManifestStatus::TIME_UNAVAILABLE) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"assetGeneration\":7", "\"assetGeneration\":8"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "\"generation\":7", "\"generation\":0"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "\"generation\":7", "\"generation\":7.0"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "\"generation\":7", "\"generation\":7e0"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "\"generation\":7", "\"generation\":-7"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "\"generation\":7", "\"generation\":07"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"generation\":7", "\"generation\":18446744073709551616"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"generation\":7", "\"generation\":true"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "index.json.gz", "other.json.gz"),
				   SignedIndexManifestStatus::INVALID_ASSET) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"compression\":\"gzip\"", "\"compression\":\"zip\""),
				   SignedIndexManifestStatus::INVALID_ASSET) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"sizeBytes\":123", "\"sizeBytes\":33554433"),
				   SignedIndexManifestStatus::INVALID_ASSET) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "\"sizeBytes\":123", "\"sizeBytes\":0"),
				   SignedIndexManifestStatus::INVALID_ASSET) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "index-v1-20261011-", "index-v1-20260230-"),
				   SignedIndexManifestStatus::INVALID_ASSET) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "\"sha256\":\"012", "\"sha256\":\"112"),
				   SignedIndexManifestStatus::INVALID_ASSET) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"sha256\":\"0123456789abcdef", "\"sha256\":\"0123456789abcdeF"),
				   SignedIndexManifestStatus::INVALID_ASSET) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"unconfirmedCount\":1", "\"unconfirmedCount\":2"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "\"recordCount\":3", "\"recordCount\":0"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, "{", SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, raw + "{}",
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"generation\":7", "\"generation\":7,\"generation\":7"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"generation\":7", "\"generation\":7,\"genera\\u0074ion\":7"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"sizeBytes\":123", "\"sizeBytes\":123,\"sizeBytes\":123"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"recordCount\":3", "\"recordCount\":3,\"recordCount\":3"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "\"generation\":7", "\"extra\":1"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "driver-index-manifest-v1", "driver-index-manifest-v1\\q"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "driver-index-manifest-v1", "\\uD800"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "driver-index-manifest-v1", "\\uDC00"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, raw + std::string{"\xc0\xaf", 2U},
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, std::string{"\xef\xbb\xbf", 3U} + raw,
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"generation\":7", "\"generation\":null"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;

	// 外側は署名対象外でもschema・重複・自己提示keyを厳密に拒否する。
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( "{}", NOW, std::nullopt, trust),
				   SignedIndexManifestStatus::INVALID_ENVELOPE) ;
	expectRejected(
		context,
		signed_index_detail::authenticateWithTrustKeys(
			replaced( signedEnvelope, "fixture-main", "fixture-main\",\"keyId\":\"fixture-main"),
			NOW, std::nullopt, trust),
		SignedIndexManifestStatus::INVALID_ENVELOPE) ;
	expectRejected(
		context,
		signed_index_detail::authenticateWithTrustKeys(
			replaced( signedEnvelope, "\"keyId\":", "\"publicKey\":"), NOW, std::nullopt, trust),
		SignedIndexManifestStatus::INVALID_ENVELOPE) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys(
					   replaced( signedEnvelope, "driver-index-envelope-v1", "research-v3"), NOW,
					   std::nullopt, trust),
				   SignedIndexManifestStatus::INVALID_ENVELOPE) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( signedEnvelope + "\xff", NOW,
																  std::nullopt, trust),
				   SignedIndexManifestStatus::INVALID_ENVELOPE) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( "", NOW, std::nullopt, trust),
				   SignedIndexManifestStatus::ENVELOPE_SIZE_LIMIT) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys(
					   std::string( INDEX_ENVELOPE_MAX_BYTES + 1U, ' '), NOW, std::nullopt, trust),
				   SignedIndexManifestStatus::ENVELOPE_SIZE_LIMIT) ;
	const std::string oversizedRaw( INDEX_MANIFEST_MAX_BYTES + 1U,
								   ' ') ;	// 外側枠内でもdecoded上限を超えるfixture。
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( envelope( oversizedRaw, signature),
																  NOW, std::nullopt, trust),
				   SignedIndexManifestStatus::MANIFEST_SIZE_LIMIT) ;

	constexpr std::array<std::string_view, 10U> BAD_BASE64{
		"A",	"AAA",	"A===", "AA=A", "AA-_",
		"AA A", "AB==", "AAB=", "====", "AA==AAAA"} ;	// 文法・padding・padbit拒否。
	// 各不正base64だけを外側へ差し込み、native codecのdecode拒否を確認する。
	for( const auto bad : BAD_BASE64) {
		const std::string invalid =
			// 署名は元のまま保持する。
			replaced( signedEnvelope, encodeText( raw), bad) ;
		expectRejected(
			context,
			signed_index_detail::authenticateWithTrustKeys( invalid, NOW, std::nullopt, trust),
			SignedIndexManifestStatus::INVALID_BASE64) ;
	}

	const std::string maxGeneration = replaced(
		raw, "\"generation\":7", "\"generation\":18446744073709551615") ;	// uint64_t上限の正例。
	// 整数上限を丸めず受理した場合の独立結果。
	const auto maxResult = signed_index_detail::authenticateWithTrustKeys(
		envelope( maxGeneration, mainKey.sign( maxGeneration)), NOW, std::nullopt, trust) ;
	DRIVERCRATE_EXPECT( context, maxResult.status == SignedIndexManifestStatus::AUTHENTICATED) ;
	const std::string maxManifest =
		raw + std::string( INDEX_MANIFEST_MAX_BYTES - raw.size(), ' ') ;	// 原byte上限ちょうどの正例。
	// 原manifestの独立byte上限を満たす場合の結果。
	const auto maxManifestResult = signed_index_detail::authenticateWithTrustKeys(
		envelope( maxManifest, mainKey.sign( maxManifest)), NOW, std::nullopt, trust) ;
	DRIVERCRATE_EXPECT( context,
					   maxManifestResult.status == SignedIndexManifestStatus::AUTHENTICATED) ;
	const std::string maxEnvelope =
		signedEnvelope +
		// 外側上限ちょうど。
		std::string( INDEX_ENVELOPE_MAX_BYTES - signedEnvelope.size(), ' ') ;
	DRIVERCRATE_EXPECT( context, signed_index_detail::authenticateWithTrustKeys( maxEnvelope, NOW,
																			   std::nullopt, trust)
										.status == SignedIndexManifestStatus::AUTHENTICATED) ;
	std::cout << "Signed index manifest assertions: " << context.assertionCount() - firstAssertion
			  << ", failures: " << context.failureCount() - firstFailure << '\n' ;
}

namespace {

/** @brief 架空原byteをminizで実圧縮し、CRC／ISIZEを持つ単一GZipを作ります。
 * @param[in] raw 架空の不変原byte。最大128MiB+1で、巨大fixtureは同一文字の繰返しです。
 * @return 実Deflateを持つ単一member。失敗時はtest processへ例外を通知します。
 */
[[nodiscard]] std::vector<std::byte> assetGzip( const std::string_view raw)
{
	const std::size_t		   capacity = raw.size() > 1024U * 1024U
											  ? raw.size() / 64U + 65536U
											  : raw.size() + 128U ;		// Testだけの有限圧縮buffer。
	std::vector<unsigned char> packed( capacity) ;						// Zlib containerの一時所有値。
	mz_ulong	packedSize = static_cast<mz_ulong>( packed.size()) ;	// 実圧縮長の格納先。
	// 原char byteをminizの読取り型へ借用するtest compressor境界です。
	const auto *input = reinterpret_cast<const unsigned char *>( raw.data()) ;
	const int	compressed =
		mz_compress2( packed.data(), &packedSize, input, static_cast<mz_ulong>( raw.size()),
					 MZ_BEST_COMPRESSION) ;	// 実miniz結果。
	// 生成失敗を検査対象の拒否と混同しない。
	if( compressed != MZ_OK || packedSize < 6U) {
		throw std::runtime_error( "synthetic gzip compression failed") ;
	}

	std::vector<std::byte> gzip{std::byte{0x1f}, std::byte{0x8b}, std::byte{8}, std::byte{0},
								std::byte{0},	 std::byte{0},	  std::byte{0}, std::byte{0},
								std::byte{0},	 std::byte{0xff}} ;	// GZip固定header。
	// Zlibのheader二byteとAdler四byteを除いた実raw Deflateだけを移す。
	for( std::size_t offset = 2U; offset < packedSize - 4U; ++offset) {
		gzip.push_back( static_cast<std::byte>( packed[offset])) ;
	}

	const std::uint32_t crc = static_cast<std::uint32_t>(
		// 原展開byteの独立CRC32。
		mz_crc32( MZ_CRC32_INIT, input, raw.size())) ;
	// CRC32と実原byte数を一値ずつtrailerのlittle endianへ欠落なく追加する。
	for( const std::uint32_t value : {crc, static_cast<std::uint32_t>( raw.size())}) {
		// 固定四byteだけを下位側から順に追加する。
		for( unsigned shift = 0U; shift < 32U; shift += 8U) {
			gzip.push_back( static_cast<std::byte>( (value >> shift) & 0xffU)) ;
		}
	}

	return gzip ;
}

/** @brief 有効なoptional commentで人工containerを正確な有限長へ広げます。
 * @param[in] gzip 実Deflate／CRC／ISIZEを持つ人工member。
 * @param[in] sizeBytes 必須の正確なcontainer長。元より大きく最大32MiBです。
 * @return 単一memberを維持し、comment以外の原byteを変えないcontainer。
 */
[[nodiscard]] std::vector<std::byte> padAssetGzip( std::vector<std::byte> gzip,
												  const std::size_t		 sizeBytes)
{
	// 境界fixtureの生成失敗をnative検査の合格にしない。
	if( sizeBytes <= gzip.size() || sizeBytes > INDEX_ASSET_MAX_BYTES) {
		throw std::runtime_error( "synthetic gzip padding failed") ;
	}

	const std::size_t padding = sizeBytes - gzip.size() ;	// FCOMMENTを含む増加byte数。
	gzip[3] |= std::byte{0x10} ;
	gzip.insert( gzip.begin() + 10, padding, std::byte{0x70}) ;
	gzip[10U + padding - 1U] = std::byte{0} ;
	return gzip ;
}

/** @brief Byte列を原byteのままtest hash／署名helperへ借用します。
 * @param[in] bytes 呼出し中不変の架空byte。
 * @return 元byteに対するchar view。正規化やcopyをしません。
 */
[[nodiscard]] std::string_view assetText( const std::span<const std::byte> bytes)
{
	// Object representationを読取り専用charへ渡すtest hash境界です。
	return {reinterpret_cast<const char *>( bytes.data()), bytes.size()} ;
}

/** @brief 実圧縮byteを署名に結合し、前段実CNG認証からだけmanifestを取得します。
 * @param[in] key RAM内秘密鍵。Public blob以外のexportは行いません。
 * @param[in] compressed 架空の原転送byte。
 * @param[in] olderAsset 新manifestが旧asset世代を参照する正例の指定。
 * @param[in] signedQuality Record試験の署名集計。空は旧byte fixtureの集計を維持します。
 * @return 前段が実RSA-PSSとschema／期限を認証したreceipt。
 */
[[nodiscard]] AuthenticatedIndexManifest assetManifest( const RamKey					   &key,
													   const std::span<const std::byte> compressed,
													   const bool			  olderAsset	= false,
													   const std::string_view signedQuality = {})
{
	const auto hash = key.digest( assetText( compressed)) ;	// Test側の独立実CNG圧縮digest。
	constexpr std::string_view HEX = "0123456789abcdef" ;	// 固定ASCII小文字表。
	std::string				   hex ;						// 署名対象のasset digest文字列。
	// 固定32byteを一byteずつ完全な64桁へ変換する。
	for( const auto byte : hash) {
		hex.push_back( HEX[byte >> 4U]) ;
		hex.push_back( HEX[byte & 15U]) ;
	}

	std::string raw = replaced( manifest(), ASSET_HASH, hex) ;	// 固定tag末尾への実digest結合。
	raw				= replaced( std::move( raw), ASSET_HASH, hex) ;
	raw				= replaced( std::move( raw), "\"sizeBytes\":123",
							   "\"sizeBytes\":" + std::to_string( compressed.size())) ;
	// 新record groupだけの集計を署名し、既存byte groupの件数を変更しない。
	if( !signedQuality.empty()) {
		raw = replaced(
			std::move( raw),
			"{\"sourceCount\":1,\"recordCount\":3,\"metadataOnlyCount\":1,\"contentInspectedCount\":1,\"unconfirmedCount\":1}",
			signedQuality) ;
	}

	// 旧assetの再参照はmanifest世代だけを増やし、asset世代を補正しない。
	if( olderAsset) {
		raw = replaced( std::move( raw), "\"generation\":7", "\"generation\":8") ;
	}

	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{"fixture-main", key.publicBlob}}} ;	// Test targetだけのRAM public trust。
	auto result = signed_index_detail::authenticateWithTrustKeys(
		// 前段実CNG認証。
		envelope( raw, key.sign( raw)), NOW, std::nullopt, trust) ;
	// 前段不成立をasset検査の拒否へ読み替えない。
	if( result.status != SignedIndexManifestStatus::AUTHENTICATED || !result.manifest) {
		throw std::runtime_error( "synthetic asset manifest authentication failed") ;
	}

	return std::move( result.manifest.value()) ;
}

/** @brief 拒否理由・元HRESULT・成功receipt不在を別々に確認します。
 * @param[in,out] context Assertion集計先。
 * @param[in] result 実byte API結果。
 * @param[in] expected 期待する独立拒否区分。
 * @param[in] error 保持されるべきAPI元HRESULT。入力拒否は0です。
 */
void expectAssetRejected( TestContext &context, const IndexAssetBytesResult &result,
						 const IndexAssetBytesStatus expected, const NativeError error = 0)
{
	DRIVERCRATE_EXPECT( context, result.status == expected) ;
	DRIVERCRATE_EXPECT( context, result.error == error) ;
	DRIVERCRATE_EXPECT( context, !result.receipt.has_value()) ;
}

/** @brief 不正GZipにも実hash／署名を付け直し、GZip層そのものの拒否を確認します。
 * @param[in,out] context Assertion集計先。
 * @param[in] key Test専用RAM秘密鍵。
 * @param[in] compressed 不正header／stream／trailerを持つ架空原byte。
 * @param[in] expected 独立拒否区分。
 * @param[in] error 既存gzip APIの元HRESULT。
 */
void rejectSignedGzip( TestContext &context, const RamKey &key,
					  const std::span<const std::byte> compressed,
					  const IndexAssetBytesStatus expected, const NativeError error)
{
	const auto authenticated = assetManifest( key, compressed) ;	// 各改変byteへの実署名と前段認証。
	expectAssetRejected( context, authenticateIndexAssetBytes( authenticated, compressed, NOW),
						expected, error) ;
}

} // namespace

/** @see signed_index_manifest_tests.h */
void runSignedIndexAssetBytesTests( TestContext &context)
{
	static_assert( !std::is_default_constructible_v<AuthenticatedIndexAssetBytes>) ;
	static_assert( !std::is_constructible_v<AuthenticatedIndexAssetBytes, IndexManifestData>) ;
	static_assert(
		!std::is_constructible_v<AuthenticatedIndexAssetBytes, AuthenticatedIndexManifest,
								 std::vector<std::byte>, IndexManifestSha256, std::uint64_t>) ;
	const int firstAssertion = context.assertionCount() ;	// 新groupだけの実assertion数。
	const int firstFailure	 = context.failureCount() ;		// 新groupだけの実失敗数。
	RamKey	  key ;											// Test専用のRAM内3072bit鍵。旧manifest groupを変更しません。
	key.generate( 3072U) ;
	constexpr std::string_view RAW =
		"  {\"fixture\":true,\"schema\":\"not-an-index\"}\n" ;	// 架空の非索引JSON。
	const auto gzip			 = assetGzip( RAW) ;				// 実圧縮された小さい正例。
	const auto authenticated = assetManifest( key, gzip) ;		// 本当の前段認証receipt。
	auto movedFromManifest	 = authenticated ;					// Move後の根拠欠損を実native APIで再現する独立copy。
	const auto movedManifest = std::move( movedFromManifest) ;	// 成功値を持つmove先。
	DRIVERCRATE_EXPECT( context,
					   authenticateIndexAssetBytes( movedManifest, gzip, NOW).receipt.has_value()) ;
	const auto movedFromResult =
		// Move元の実検査結果。
		authenticateIndexAssetBytes( movedFromManifest, gzip, NOW) ;
	expectAssetRejected( context, movedFromResult,
						IndexAssetBytesStatus::INCOMPLETE_MANIFEST_RECEIPT) ;
	std::cout << "Moved-from asset receipt generated: " << movedFromResult.receipt.has_value()
			  << ", manifest bytes retained: " << !movedFromManifest.data().manifestBytes.empty()
			  << '\n' ;
	const auto accepted =
		// Native byte正例。
		authenticateIndexAssetBytes( authenticated, gzip, NOW) ;
	DRIVERCRATE_EXPECT( context, accepted.status == IndexAssetBytesStatus::BYTE_VALIDATED) ;
	DRIVERCRATE_EXPECT( context, accepted.error == 0) ;
	DRIVERCRATE_EXPECT( context, accepted.receipt.has_value()) ;
	// 正例が不成立なら未生成receiptを参照しない。
	if( !accepted.receipt) {
		return ;
	}

	const auto &receipt = accepted.receipt.value() ;	// 書換えできない検査結果。
	DRIVERCRATE_EXPECT( context, assetText( receipt.expandedBytes()) == RAW) ;
	DRIVERCRATE_EXPECT( context, receipt.expandedSha256() == key.digest( RAW)) ;
	DRIVERCRATE_EXPECT( context, receipt.manifest().data().manifestSha256 ==
									authenticated.data().manifestSha256) ;
	DRIVERCRATE_EXPECT( context, receipt.manifest().data().manifestBytes ==
									authenticated.data().manifestBytes) ;
	DRIVERCRATE_EXPECT( context,
					   receipt.manifest().data().asset.sha256 == key.digest( assetText( gzip))) ;
	DRIVERCRATE_EXPECT( context, receipt.manifest().data().asset.sizeBytes == gzip.size()) ;
	DRIVERCRATE_EXPECT( context, receipt.expandedSha256() != receipt.manifest().data().asset.sha256) ;
	DRIVERCRATE_EXPECT( context,
					   receipt.expandedSha256() != receipt.manifest().data().manifestSha256) ;
	DRIVERCRATE_EXPECT( context, receipt.bytePolicyVersion() == 1U) ;
	DRIVERCRATE_EXPECT( context, receipt.maximumExpandedBytes() == gzip.size() * 128ULL) ;
	DRIVERCRATE_EXPECT( context, receipt.manifest().data().keyId == "fixture-main" &&
									receipt.manifest().data().asset.name == "index.json.gz") ;

	expectAssetRejected( context, authenticateIndexAssetBytes( authenticated, gzip, std::nullopt),
						IndexAssetBytesStatus::TIME_UNAVAILABLE) ;
	expectAssetRejected(
		context,
		authenticateIndexAssetBytes( authenticated, gzip,
									authenticated.data().publishedAtUtc - std::chrono::seconds{1}),
		IndexAssetBytesStatus::NOT_YET_VALID) ;
	expectAssetRejected(
		context,
		authenticateIndexAssetBytes( authenticated, gzip, authenticated.data().expiresAtUtc),
		IndexAssetBytesStatus::EXPIRED) ;
	expectAssetRejected(
		context,
		authenticateIndexAssetBytes( authenticated, gzip,
									authenticated.data().expiresAtUtc + std::chrono::seconds{1}),
		IndexAssetBytesStatus::EXPIRED) ;
	DRIVERCRATE_EXPECT( context, authenticateIndexAssetBytes( authenticated, gzip,
															authenticated.data().publishedAtUtc)
									.receipt.has_value()) ;
	DRIVERCRATE_EXPECT( context, authenticateIndexAssetBytes( authenticated, gzip,
															authenticated.data().expiresAtUtc -
																std::chrono::seconds{1})
									.receipt.has_value()) ;
	expectAssetRejected( context, authenticateIndexAssetBytes( authenticated, {}, NOW),
						IndexAssetBytesStatus::COMPRESSED_SIZE_LIMIT) ;
	expectAssetRejected(
		context,
		authenticateIndexAssetBytes( authenticated, std::span{gzip}.first( gzip.size() - 1U), NOW),
		IndexAssetBytesStatus::SIZE_MISMATCH) ;
	auto altered = gzip ;	// 認証後の同長改変をGZip処理前に拒否する。
	altered[10] ^= std::byte{1} ;
	expectAssetRejected( context, authenticateIndexAssetBytes( authenticated, altered, NOW),
						IndexAssetBytesStatus::HASH_MISMATCH) ;
	const auto old = assetManifest( key, gzip, true) ;	// 新manifest8から旧asset7を再参照する。
	const auto oldAccepted =
		// 旧asset参照のnative正例。
		authenticateIndexAssetBytes( old, gzip, NOW) ;
	DRIVERCRATE_EXPECT( context, oldAccepted.receipt.has_value() &&
									oldAccepted.receipt->manifest().data().generation == 8U &&
									oldAccepted.receipt->manifest().data().assetGeneration == 7U) ;

	const NativeError invalid =
		// 元GZip形式診断値。
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
	const NativeError crcError =
		// 元CRC診断値。
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CRC)) ;
	const NativeError limit =
		// 元展開枠診断値。
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
	auto badCrc = gzip ;	// 実署名を付け直すCRC改変。
	badCrc[badCrc.size() - 8U] ^= std::byte{1} ;
	rejectSignedGzip( context, key, badCrc, IndexAssetBytesStatus::GZIP_REJECTED, crcError) ;
	auto badSize = gzip ;	// 宣言ISIZEだけを一byte変更し、実出力量不一致を検査する。
	badSize[badSize.size() - 4U] ^= std::byte{1} ;
	rejectSignedGzip( context, key, badSize, IndexAssetBytesStatus::GZIP_REJECTED, invalid) ;
	auto members = gzip ;	// 単一member限定の拒否fixture。
	members.insert( members.end(), gzip.begin(), gzip.end()) ;
	rejectSignedGzip( context, key, members, IndexAssetBytesStatus::GZIP_REJECTED, invalid) ;
	auto trailing = gzip ;	// Trailer前にDeflate未消費byteを残す。
	trailing.insert( trailing.end() - 8, std::byte{0x42}) ;
	rejectSignedGzip( context, key, trailing, IndexAssetBytesStatus::GZIP_REJECTED, invalid) ;
	auto appended = gzip ;	// Container末尾の余剰byteも成功にしない。
	appended.push_back( std::byte{0x42}) ;
	const auto appendedManifest = assetManifest( key, appended) ;	// 余剰byteまで署名する。
	const auto appendedResult =
		// 実拒否。
		authenticateIndexAssetBytes( appendedManifest, appended, NOW) ;
	DRIVERCRATE_EXPECT( context, appendedResult.status != IndexAssetBytesStatus::BYTE_VALIDATED) ;
	DRIVERCRATE_EXPECT( context, !appendedResult.receipt) ;
	auto badHeader = gzip ;	// 予約flagは既存GZip契約のまま拒否する。
	badHeader[3]   = std::byte{0xe0} ;
	rejectSignedGzip( context, key, badHeader, IndexAssetBytesStatus::GZIP_REJECTED, invalid) ;
	auto badMagic = gzip ;	// GZip以外へ暗黙fallbackしない。
	badMagic[0]	  = std::byte{0} ;
	rejectSignedGzip( context, key, badMagic, IndexAssetBytesStatus::GZIP_REJECTED, invalid) ;
	auto noName = gzip ;	// Optional nameのNULを持たないheader。
	noName[3]	= std::byte{8} ;
	std::fill( noName.begin() + 10, noName.end() - 8, std::byte{0x61}) ;
	rejectSignedGzip( context, key, noName, IndexAssetBytesStatus::GZIP_REJECTED, invalid) ;
	const std::array<std::byte, 1U> shortGzip{
		std::byte{0x1f}} ;	// Size署名が成立してもGZip最小構造未満。
	rejectSignedGzip( context, key, shortGzip, IndexAssetBytesStatus::GZIP_REJECTED,
					 static_cast<NativeError>( E_INVALIDARG)) ;

	const std::string ratioRaw( 4096U * 128U, 'r') ;	// Container4096byteの128倍ちょうど。
	const auto		  ratioGzip =
		// 有効なcommentで正確な転送長を固定する。
		padAssetGzip( assetGzip( ratioRaw), 4096U) ;
	const auto ratioManifest = assetManifest( key, ratioGzip) ;	// 比率境界への実認証。
	const auto ratioAccepted =
		// 正確な倍率正例。
		authenticateIndexAssetBytes( ratioManifest, ratioGzip, NOW) ;
	DRIVERCRATE_EXPECT( context,
					   ratioAccepted.receipt &&
						   ratioAccepted.receipt->expandedBytes().size() == ratioRaw.size()) ;
	const std::string ratioOver( ratioRaw.size() + 1U, 'r') ;					// 比率上限より実原byteが一byte多い。
	const auto ratioOverGzip = padAssetGzip( assetGzip( ratioOver), 4096U) ;	// 実圧縮した超過原byte。
	rejectSignedGzip( context, key, ratioOverGzip, IndexAssetBytesStatus::EXPANSION_LIMIT, limit) ;
	{
		const auto maximumCompressed = padAssetGzip(
			gzip, static_cast<std::size_t>( INDEX_ASSET_MAX_BYTES)) ;	// 実32MiBの正確なcontainer。
		const auto maximumManifest =
			// 32MiB実hashを署名する。
			assetManifest( key, maximumCompressed) ;
		const auto maximumAccepted = authenticateIndexAssetBytes( maximumManifest, maximumCompressed,
																 NOW) ;	// 圧縮量上限正例。
		DRIVERCRATE_EXPECT(
			context,
			maximumAccepted.receipt && assetText( maximumAccepted.receipt->expandedBytes()) == RAW &&
				maximumAccepted.receipt->maximumExpandedBytes() == INDEX_ASSET_EXPANDED_MAX_BYTES) ;
		auto oversized = maximumCompressed ;	// 一byte追加で圧縮絶対枠を超える。
		oversized.push_back( std::byte{}) ;
		expectAssetRejected( context, authenticateIndexAssetBytes( maximumManifest, oversized, NOW),
							IndexAssetBytesStatus::COMPRESSED_SIZE_LIMIT) ;
	}

	{
		const std::string absoluteRaw( static_cast<std::size_t>( INDEX_ASSET_EXPANDED_MAX_BYTES),
									  'a') ;	// 実128MiBの人工原byte。
		const auto		  absoluteGzip = padAssetGzip(
			   // 倍率枠と絶対枠が一致する実圧縮入力。
			   assetGzip( absoluteRaw), 1024U * 1024U) ;
		const auto absoluteManifest = assetManifest( key, absoluteGzip) ;	// 実assetへのCNG署名認証。
		const auto absoluteAccepted = authenticateIndexAssetBytes(
			absoluteManifest, absoluteGzip, NOW) ;	// 縮小policyでない実128MiB展開。
		DRIVERCRATE_EXPECT( context, absoluteAccepted.receipt &&
										absoluteAccepted.receipt->expandedBytes().size() ==
											INDEX_ASSET_EXPANDED_MAX_BYTES) ;
		DRIVERCRATE_EXPECT( context,
						   absoluteAccepted.receipt &&
							   assetText( absoluteAccepted.receipt->expandedBytes()) == absoluteRaw) ;
	}

	{
		const std::string absoluteOver(
			static_cast<std::size_t>( INDEX_ASSET_EXPANDED_MAX_BYTES + 1U),
			'a') ;	// 実128MiB+1原byte。
		const auto absoluteOverGzip = padAssetGzip(
			// 比率は許可し絶対128MiBだけを超える。
			assetGzip( absoluteOver), 1024U * 1024U + 1U) ;
		rejectSignedGzip( context, key, absoluteOverGzip, IndexAssetBytesStatus::EXPANSION_LIMIT,
						 limit) ;
	}

	std::cout << "Signed index asset byte assertions: " << context.assertionCount() - firstAssertion
			  << ", failures: " << context.failureCount() - firstFailure << '\n' ;
}

namespace {

// 人工hash値は出典やpackageの実検証を表さず、元申告の型付き保持だけを検査する。
constexpr std::string_view RECORD_CLAIM_HASH =
	"1111111111111111111111111111111111111111111111111111111111111111" ;
// 原出典byteの元申告。Record原byte hashと混同しない。
constexpr std::string_view RECORD_EVIDENCE_HASH =
	"2222222222222222222222222222222222222222222222222222222222222222" ;

/** @brief Test側の独立CNG原hashを小文字hexへ表現します。
 * @param[in] key 既存RAM鍵helper。秘密materialをexportしません。
 * @param[in] raw 元byte。
 * @return 実原bytehashの小文字64桁。
 */
[[nodiscard]] std::string recordDigest( const RamKey &key, const std::string_view raw)
{
	const auto				   hash = key.digest( raw) ;	// 同じRAM helperの独立実CNG digest。
	constexpr std::string_view HEX	= "0123456789abcdef" ;	// 固定hex表。
	std::string				   result ;						// Test専用の所有表現。
	// 全32byteを原値どおり二桁へ表現する。
	for( const auto byte : hash) {
		result.push_back( HEX[byte >> 4U]) ;
		result.push_back( HEX[byte & 15U]) ;
	}

	return result ;
}

/** @brief 原record byteだけをentryへ結びます。
 * @param[in] key 既存RAM helper。
 * @param[in] raw 原UTF-8。
 * @param[in] hashOverride Hash取り違え用の明示digest。空は実原hashです。
 * @return 原byteを再整形しないbase64 entry。
 */
[[nodiscard]] std::string recordEntry( const RamKey &key, const std::string_view raw,
									  const std::string_view hashOverride = {})
{
	return "{\"recordBytesBase64\":\"" + encodeText( raw) + "\",\"recordSha256\":\"" +
		   (hashOverride.empty() ? recordDigest( key, raw) : std::string{hashOverride}) + "\"}" ;
}

/** @brief 架空sourceの公開申告またはUNKNOWNを作ります。
 * @param[in] id 架空のASCII identity。
 * @param[in] unknown 元公式性未確認を保持する指定。
 * @return 通信しないtestだけのsource JSON。
 */
[[nodiscard]] std::string recordSource( const std::string_view id	  = "fixture-source",
									   const bool			  unknown = false)
{
	const std::string evidence =
		unknown
			? R"json({"state":"UNKNOWN","kind":"UNKNOWN","evidenceUrl":"","evidenceSha256":"","reason":"source not verified"})json"
			: R"json({"state":"PUBLISHED","kind":"OFFICIAL_PAGE","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
				  std::string{RECORD_EVIDENCE_HASH} +
				  R"json(","reason":""})json" ;	// 元申告または明示UNKNOWN。
	return "{\"sourceId\":\"" + std::string{id} +
		   "\",\"officialOrigin\":\"https://vendor.example/\",\"distributionPage\":\"https://vendor.example/support\"," +
		   "\"officialEvidence\":" + evidence + "}" ;
}

/** @brief 明示既知のtext条件を作ります。
 * @param[in] value 固定架空値。Quoteを含みません。
 * @return Test用KNOWN JSON。
 */
[[nodiscard]] std::string recordKnown( const std::string_view value)
{
	return "{\"state\":\"KNOWN\",\"value\":\"" + std::string{value} + "\",\"reason\":\"\"}" ;
}

/** @brief 架空recordの完全な型付き元申告を作ります。
 * @param[in] id Source内の架空identity。
 * @param[in] identityPublished PnP evidenceの元申告を持つ指定。FalseではUNKNOWNを保持します。
 * @param[in] stage 発行側の段階。
 * @param[in] source 存在するか拒否用の架空source ID。
 * @return Test専用の元record byte。
 */
[[nodiscard]] std::string distributionRecord( const std::string_view id				  = "metadata",
											 const bool				identityPublished = true,
											 const std::string_view stage  = "METADATA_ONLY",
											 const std::string_view source = "fixture-source")
{
	constexpr std::string_view UNKNOWN =
		R"json({"state":"UNKNOWN","value":"","reason":"not supplied"})json" ;	// 欠損を補完しない条件。
	constexpr std::string_view UNKNOWN_HASH =
		// 未知hash。
		R"json({"state":"UNKNOWN","sha256":"","evidenceUrl":"","evidenceSha256":"","reason":"not inspected"})json" ;
	const std::string hash =
		R"json({"state":"KNOWN","sha256":")json" + std::string{RECORD_CLAIM_HASH} +
		R"json(","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
		std::string{RECORD_EVIDENCE_HASH} + R"json(","reason":""})json" ;	// 型だけを確認する元申告。
	const std::string identity =
		identityPublished
			? R"json({"state":"PUBLISHED","kind":"INF","pnpIds":[{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}],"classGuid":"{11111111-2222-3333-4444-555555555555}","infIdentity":"drivers/fixture.inf","modelSection":"Fixture.NTamd64","evidenceUrl":"https://vendor.example/fixture.inf","evidenceSha256":")json" +
				  std::string{RECORD_EVIDENCE_HASH} + R"json(","reason":""})json"
			// 元公開identityか不足理由。
			: R"json({"state":"UNKNOWN","kind":"UNKNOWN","pnpIds":[],"classGuid":"","infIdentity":"","modelSection":"","evidenceUrl":"","evidenceSha256":"","reason":"public INF identity missing"})json" ;
	return "{\"schema\":\"driver-index-record-v1\",\"sourceId\":\"" + std::string{source} +
		   "\",\"recordId\":\"" + std::string{id} + "\",\"product\":\"Synthetic fixture\"," +
		   "\"targetOs\":" +
		   (identityPublished ? recordKnown( "WINDOWS_11") : std::string{UNKNOWN}) +
		   ",\"architecture\":" + (identityPublished ? recordKnown( "X64") : std::string{UNKNOWN}) +
		   ",\"driverKind\":" +
		   (identityPublished ? recordKnown( "NORMAL_DRIVER") : std::string{UNKNOWN}) +
		   ",\"version\":" + (identityPublished ? recordKnown( "1.2.3.4") : std::string{UNKNOWN}) +
		   ",\"publishedDate\":" +
		   (identityPublished ? recordKnown( "2026-10-01") : std::string{UNKNOWN}) +
		   ",\"acquisition\":" +
		   (identityPublished ? recordKnown( "STANDARD_INF_ARCHIVE") : std::string{UNKNOWN}) +
		   ",\"packageEvidence\":{\"publishedHash\":" +
		   (identityPublished ? hash : std::string{UNKNOWN_HASH}) +
		   ",\"calculatedHash\":" + (identityPublished ? hash : std::string{UNKNOWN_HASH}) +
		   ",\"size\":" +
		   (identityPublished
				? std::string{R"json({"state":"KNOWN","valueBytes":1234,"reason":""})json"}
				: std::
					  string{R"json({"state":"UNKNOWN","valueBytes":0,"reason":"not inspected"})json"}) +
		   "},\"lastSuccessfulObservationUtc\":" +
		   (identityPublished ? recordKnown( "2026-10-10T03:00:00Z") : std::string{UNKNOWN}) +
		   ",\"inspectionStage\":\"" + std::string{stage} +
		   "\",\"publishedIdentityEvidence\":" + identity + "}" ;
}

/** @brief 元sourceとentryを配布indexへ包みます。
 * @param[in] sources 配列内の架空source JSON。
 * @param[in] entries 配列内の原record entry JSON。
 * @return 元順序を保持する配布index。
 */
[[nodiscard]] std::string distributionIndex( const std::string_view sources,
											const std::string_view entries)
{
	return "{\"schema\":\"driver-index-records-v1\",\"assetGeneration\":7,\"sources\":[" +
		   std::string{sources} + "],\"records\":[" + std::string{entries} + "]}" ;
}

/** @brief 実qualityを前段fixtureの署名fieldへ渡す表現を作ります。
 * @param[in] quality 署名する架空集計。
 * @return 全5fieldを持つ集計JSON。
 */
[[nodiscard]] std::string recordQuality( const IndexManifestQuality &quality)
{
	return "{\"sourceCount\":" + std::to_string( quality.sourceCount) +
		   ",\"recordCount\":" + std::to_string( quality.recordCount) +
		   ",\"metadataOnlyCount\":" + std::to_string( quality.metadataOnlyCount) +
		   ",\"contentInspectedCount\":" + std::to_string( quality.contentInspectedCount) +
		   ",\"unconfirmedCount\":" + std::to_string( quality.unconfirmedCount) + "}" ;
}

/** @brief 実署名と実GZipを通してからだけbyte receiptを作ります。
 * @param[in] key 既存RAM鍵helper。
 * @param[in] index 原index byte。
 * @param[in] quality 前段に署名する集計。
 * @return 前段の実認証byte receipt。生成不成立は例外にします。
 */
[[nodiscard]] AuthenticatedIndexAssetBytes recordBytes( const RamKey				 &key,
													   const std::string_view	  index,
													   const IndexManifestQuality quality = {
														   1U, 3U, 1U, 1U, 1U})
{
	auto			  gzip	  = assetGzip( index) ;				// 既存helperによる実圧縮。
	const std::size_t minimum = (index.size() + 127U) / 128U ;	// 実比率上限を満たすcontainer量。
	// 圧縮率の高い人工byteでも既存の128倍policyを変更しない。
	if( gzip.size() < minimum) {
		gzip = padAssetGzip( std::move( gzip), minimum) ;
	}

	const auto manifestReceipt =
		// 実CNG認証。
		assetManifest( key, gzip, false, recordQuality( quality)) ;
	auto result = authenticateIndexAssetBytes( manifestReceipt, gzip, NOW) ;	// 実GZip／原hash検査。
	// Fixture生成失敗を新codec拒否の合格へ読み替えない。
	if( result.status != IndexAssetBytesStatus::BYTE_VALIDATED || !result.receipt) {
		throw std::runtime_error( "record fixture byte authentication failed") ;
	}

	return std::move( *result.receipt) ;
}

/** @brief 一人工indexを全前段からnative codecへ渡します。
 * @param[in] key 既存RAM helper。
 * @param[in] index 元byte。
 * @param[in] quality 署名集計。
 * @return 実codecの結果。
 */
[[nodiscard]] IndexRecordsResult readRecordFixture( const RamKey &key, const std::string_view index,
												   const IndexManifestQuality quality = {1U, 3U, 1U,
																						 1U, 1U})
{
	const auto bytes = recordBytes( key, index, quality) ;	// 全前段を成功した認証receipt。
	return readSignedIndexRecords( bytes, NOW) ;
}

/** @brief 一拒否の理由・元診断・receipt不在を独立に確認します。
 * @param[in,out] context 集計先。
 * @param[in] result 実codec結果。
 * @param[in] status 期待拒否区分。
 */
void expectRecordsRejected( TestContext &context, const IndexRecordsResult &result,
						   const IndexRecordsStatus status)
{
	DRIVERCRATE_EXPECT( context, result.status == status) ;
	DRIVERCRATE_EXPECT( context, result.error == 0) ;
	DRIVERCRATE_EXPECT( context, !result.receipt) ;
}

/** @brief 不正indexにも実署名を付け、新schema層そのものの拒否を確認します。
 * @param[in,out] context 集計先。
 * @param[in] key 既存RAM helper。
 * @param[in] index 不正な元index byte。
 * @param[in] status 期待拒否区分。
 * @param[in] quality 署名集計。
 */
void rejectRecordIndex( TestContext &context, const RamKey &key, const std::string_view index,
					   const IndexRecordsStatus	  status,
					   const IndexManifestQuality quality = {1U, 3U, 1U, 1U, 1U})
{
	expectRecordsRejected( context, readRecordFixture( key, index, quality), status) ;
}

/** @brief 不正recordにも正しい原hashを結び、record schema層の拒否を確認します。
 * @param[in,out] context 集計先。
 * @param[in] key 既存RAM helper。
 * @param[in] raw 不正record原byte。
 * @param[in] status 期待拒否区分。
 */
void rejectDistributionRecord( TestContext &context, const RamKey &key, const std::string_view raw,
							  const IndexRecordsStatus status)
{
	rejectRecordIndex( context, key, distributionIndex( recordSource(), recordEntry( key, raw)),
					  status, {1U, 1U, 1U, 0U, 0U}) ;
}

/** @brief 共通readerの実container深さを固定test再帰で確認します。
 * @param[in,out] reader 借用test reader。
 * @param[in] containers 残る固定container数。Test callerは最大9だけを渡します。
 */
void readDepthFixture( signed_index_json::Reader<IndexRecordsStatus> &reader,
					  const unsigned								 containers)
{
	// 最深の一文字値だけで再帰を終える。
	if( containers == 0U) {
		static_cast<void>( reader.text( 1U)) ;
		return ;
	}

	constexpr std::array<std::string_view, 1U> FIELDS{"x"} ;	// 固定一field。
	// Readerと残container数を同期借用する有限test handler。
	reader.object( FIELDS, [&]( const std::size_t) { readDepthFixture( reader, containers - 1U) ; }) ;
}

/** @brief 静的取得descriptorの完全な人工元申告を作ります。
 * @param[in] unknown 取得情報だけを明示UNKNOWNへする指定。
 * @param[in] rich 規約全文と具体的条件を含む入れ子の正例を作る指定。
 * @return 通信や同意を行わない全13fieldの人工JSON。
 */
[[nodiscard]] std::string descriptorFixture( const bool unknown = false, const bool rich = false)
{
	const std::string evidence{RECORD_EVIDENCE_HASH} ;	// 元出典byteの架空申告。
	const std::string terms =
		rich
			? R"json({"state":"ACCEPTANCE_REQUIRED","reason":"","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
				  evidence +
				  R"json(","revisionKind":"VENDOR_LITERAL","revision":"Original 1.0","textDocument":{"url":"https://vendor.example/terms.txt","sha256":")json" +
				  evidence +
				  R"json(","sizeBytes":123,"contentType":"text/plain; charset=utf-8"}})json"
			: R"json({"state":"CONFIRMED_NO_CONSENT","reason":"","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
				  evidence +
				  R"json(","revisionKind":"NONE","revision":"","textDocument":null})json" ;	// 元規約の別状態。
	const std::string prerequisites =
		rich
			? R"json({"state":"KNOWN","reason":"","items":[{"kind":"LOCAL_CHECK","description":"Check a specific prerequisite","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
				  evidence + R"json("}]})json"
			: R"json({"state":"KNOWN","reason":"","items":[]})json" ;	// 明示空集合か個別条件。
	// UNKNOWNは取得URLやattestationを補完せず、独立した未知理由も保持する。
	if( unknown) {
		return R"json({"schema":"driver-index-acquisition-v1","state":"UNKNOWN","reason":"static route not supplied","payloadUrl":"","fileName":"","format":"UNKNOWN","expectedContentType":"","maximumBytes":0,"route":[],"terms":{"state":"UNKNOWN","reason":"terms not supplied","evidenceUrl":"","evidenceSha256":"","revisionKind":"NONE","revision":"","textDocument":null},"prerequisites":{"state":"UNKNOWN","reason":"prerequisites not supplied","items":[]},"publisher":{"state":"UNKNOWN","value":"","reason":"publisher not supplied"},"attestation":null})json" ;
	}

	return R"json({"schema":"driver-index-acquisition-v1","state":"KNOWN","reason":"","payloadUrl":"https://vendor.example/fixture.zip","fileName":"Fixture 1.2 (x64).zip","format":"ZIP","expectedContentType":"application/zip","maximumBytes":134217728,"route":[{"url":"https://vendor.example/fixture.zip","kind":"OFFICIAL_PAYLOAD_LINK","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
		   evidence + R"json("}],"terms":)json" + terms + R"json(,"prerequisites":)json" +
		   prerequisites +
		   R"json(,"publisher":{"state":"KNOWN","value":"Synthetic publisher","reason":""},"attestation":{"kind":"COLLECTOR_VERIFIED_OFFICIAL_ROUTE","policyRevision":1,"checkedAtUtc":"2026-10-10T03:00:00Z","validUntilUtc":"2026-10-12T03:00:00Z","authorityMethod":"OFFICIAL_SITE_CONTROL_AND_LINK","authorityEvidenceUrl":"https://vendor.example/support","authorityEvidenceSha256":")json" +
		   evidence + R"json("}})json" ;
}

/** @brief Descriptorをschemaより先に置くv2原recordを作ります。
 * @param[in] descriptor 全13fieldの人工元取得情報。
 * @param[in] raw 旧14fieldの人工record。欠損を補いません。
 * @return 原field順を明示した15fieldの人工record。
 */
[[nodiscard]] std::string descriptorRecord( const std::string_view descriptor,
										   std::string			  raw = distributionRecord())
{
	raw = replaced( std::move( raw), "driver-index-record-v1", "driver-index-record-v2") ;
	return "{\"acquisitionDescriptor\":" + std::string{descriptor} + "," + raw.substr( 1U) ;
}

/** @brief Sourcesとrecordsをouter schemaより先に置くv2原indexを作ります。
 * @param[in] sources 人工source集合。
 * @param[in] entries 原byteと実hashに結合した人工entry集合。
 * @return Outer field順を固定しない全4fieldの人工index。
 */
[[nodiscard]] std::string descriptorIndex( const std::string_view sources,
										  const std::string_view entries)
{
	return "{\"sources\":[" + std::string{sources} + "],\"records\":[" + std::string{entries} +
		   "],\"assetGeneration\":7,\"schema\":\"driver-index-records-v2\"}" ;
}

/** @brief 固定人工JSONの一objectへ欠損・未知・重複fieldを作ります。
 * @param[in] raw 完全に既知の人工JSON。製品parserとして使用しません。
 * @param[in] key 対象objectまたは一要素object配列の固定field名。空はrootです。
 * @param[in] mutation 0は先頭field欠損、1は未知field、2は先頭field重複です。
 * @return 元の残りbyteを維持した不正fixture。
 */
[[nodiscard]] std::string mutateDescriptorObject( std::string raw, const std::string_view key,
												 const unsigned mutation)
{
	const std::size_t anchor =
		// 固定field位置。
		key.empty() ? 0U : raw.find( "\"" + std::string{key} + "\":") ;
	const std::size_t start = raw.find( '{', anchor) ;	// 完全fixture内の対象object開始。
	// 不正なtest材料を空の拒否成功として扱わない。
	if( anchor == std::string::npos || start == std::string::npos) {
		throw std::runtime_error( "descriptor mutation anchor missing") ;
	}

	std::size_t end = start + 1U ;	// 先頭memberの終端だけを有限走査する。
	unsigned	depth{} ;			// 入れ子object・arrayの対応。
	bool		quoted{} ;			// Stringの内部commaをmember境界にしない。
	bool		escaped{} ;			// Quote escapeは一byteだけに作用する。
	// 既知fixtureの先頭memberを最後のbyteまでに一度だけ走査する。
	for( ; end < raw.size(); ++end) {
		const char character = raw[end] ;	// 現在の人工byte。
		// String内部ではescapeされたquoteやcommaを保持する。
		if( quoted) {
			// Escapeの直後一byteだけはdelimiterにしない。
			if( escaped) {
				escaped = false ;
			}
			// 次byteのescapeを保持する。
			else if( character == '\\') {
				escaped = true ;
			}
			// 完全quoteでだけstringを閉じる。
			else if( character == '"') {
				quoted = false ;
			}
		}
		// String開始を区別する。
		else if( character == '"') {
			quoted = true ;
		}
		// 先頭値の入れ子を維持する。
		else if( character == '{' || character == '[') {
			++depth ;
		}
		// 同じmemberの入れ子だけを閉じる。
		else if( (character == '}' || character == ']') && depth > 0U) {
			--depth ;
		}
		// 対象objectの最初のmember境界で有限走査を終える。
		else if( depth == 0U && (character == ',' || character == '}')) {
			break ;
		}
	}

	const std::string member = raw.substr( start + 1U, end - start - 1U) ;	// 完全な先頭member。
	// 欠損だけは元memberとそのcommaを除き、残りbyteを維持する。
	if( mutation == 0U) {
		raw.erase( start + 1U, end - start) ;
	} else {
		raw.insert( start + 1U, mutation == 1U ? "\"codecUnknown\":null," : member + ",") ;
	}

	return raw ;
}

/** @brief 静的人工route hopを一つ作ります。
 * @param[in] url 原の架空URL。
 * @param[in] kind 固定元申告種別。
 * @param[in] evidence 元の架空根拠URL。
 * @return 出典hashへ結合した四fieldの人工JSON。
 */
[[nodiscard]] std::string descriptorHop( const std::string_view url, const std::string_view kind,
										const std::string_view evidence)
{
	return "{\"url\":\"" + std::string{url} + "\",\"kind\":\"" + std::string{kind} +
		   "\",\"evidenceUrl\":\"" + std::string{evidence} + "\",\"evidenceSha256\":\"" +
		   std::string{RECORD_EVIDENCE_HASH} + "\"}" ;
}

/** @brief 完全fixtureのrouteだけを別の有限集合へ置き換えます。
 * @param[in] descriptor 全13fieldの完全人工fixture。
 * @param[in] hops 人工hop配列の本文。
 * @return 残りbyteを維持した人工descriptor。
 */
[[nodiscard]] std::string descriptorRoute( std::string descriptor, const std::string_view hops)
{
	const std::size_t begin = descriptor.find( "\"route\":[") ;			// 固定人工fieldの開始。
	const std::size_t end	= descriptor.find( "],\"terms\":", begin) ;	// 固定人工routeの終端。
	// Mutationの失敗を製品codecの拒否成功にしない。
	if( begin == std::string::npos || end == std::string::npos) {
		throw std::runtime_error( "descriptor route fixture missing") ;
	}

	descriptor.replace( begin, end + 1U - begin, "\"route\":[" + std::string{hops} + "]") ;
	return descriptor ;
}

/** @brief 真RAM署名と原GZipからv2 codecの正例・拒否・旧v1互換を検査します。
 * @param[in,out] context 旧record groupと別の集計先。
 * @note 実HTTP・EULA全文取得・grant・実device・導入は実行しません。
 */
void runDescriptorCodecChecks( TestContext &context)
{
	const int firstAssertion = context.assertionCount() ;	// 新codec groupだけの開始件数。
	const int firstFailure	 = context.failureCount() ;		// 新codec groupだけの開始失敗。
	RamKey	  key ;											// 既存CNG helperの秘密鍵はRAMだけに保持する。
	key.generate( 3072U) ;
	const std::string descriptor = descriptorFixture() ;	// 一payloadの完全元申告。
	const std::string raw = descriptorRecord( descriptor) ;	// Descriptorがschemaより先の原byte。
	const std::string index =
		// Outer schemaも最後に置く。
		descriptorIndex( recordSource(), recordEntry( key, raw)) ;
	const auto read =
		// 真署名・実GZip・原hash検査。
		readRecordFixture( key, index, {1U, 1U, 1U, 0U, 0U}) ;
	DRIVERCRATE_EXPECT( context,
					   read.status == IndexRecordsStatus::SCHEMA_VALIDATED && read.receipt) ;
	// 正例生成失敗時は後のtyped assertionを空の成功へ変換しない。
	if( !read.receipt) {
		throw std::runtime_error( "descriptor positive fixture rejected") ;
	}

	const auto &record = read.receipt->records()[0] ;		// Receipt寿命へ結合した所有record。
	const auto &value  = *record.acquisitionDescriptor ;	// 全13fieldの型付き元申告。
	DRIVERCRATE_EXPECT( context, record.recordSchemaVersion == 2U && record.originalBytes == raw &&
									read.receipt->schemaPolicyVersion() == 3U &&
									record.acquisitionDescriptorUnavailableReason.empty()) ;
	DRIVERCRATE_EXPECT(
		context,
		value.state == IndexDescriptorState::KNOWN && value.reason.empty() &&
			value.payloadUrl == "https://vendor.example/fixture.zip" &&
			value.fileName == "Fixture 1.2 (x64).zip" && value.format == IndexPayloadFormat::ZIP &&
			value.expectedContentType == "application/zip" && value.maximumBytes == 134217728U) ;
	DRIVERCRATE_EXPECT( context, value.route.size() == 1U &&
									value.route[0].kind == IndexRouteKind::OFFICIAL_PAYLOAD_LINK &&
									value.route[0].evidenceUrl ==
										read.receipt->sources()[0].distributionPage) ;
	DRIVERCRATE_EXPECT( context, value.terms.state == IndexTermsState::CONFIRMED_NO_CONSENT &&
									value.terms.revisionKind == IndexTermsRevisionKind::NONE &&
									!value.terms.textDocument &&
									value.prerequisites.state == IndexDescriptorState::KNOWN &&
									value.prerequisites.items.empty()) ;
	DRIVERCRATE_EXPECT( context, value.publisher.value == "Synthetic publisher" &&
									value.attestation && value.attestation->policyRevision == 1U &&
									value.attestation->authorityMethod ==
										IndexAuthorityMethod::OFFICIAL_SITE_CONTROL_AND_LINK) ;
	DRIVERCRATE_EXPECT( context, record.packageEvidence.publishedHash.sha256 ==
										record.packageEvidence.calculatedHash.sha256 &&
									record.packageEvidence.publishedHash.evidenceSha256 !=
										record.packageEvidence.publishedHash.sha256) ;
	// 同じ元textでも異なる空白の原byteとhashを独立に保持する。
	const auto spaced = readRecordFixture(
		key, descriptorIndex( recordSource(), recordEntry( key, " \n" + raw + "\t")),
		{1U, 1U, 1U, 0U, 0U}) ;
	DRIVERCRATE_EXPECT( context,
					   spaced.receipt &&
						   spaced.receipt->records()[0].recordSha256 != record.recordSha256 &&
						   spaced.receipt->records()[0].originalBytes == " \n" + raw + "\t") ;
	const auto unknown = readRecordFixture(
		key,
		descriptorIndex( recordSource(),
						recordEntry( key, descriptorRecord( descriptorFixture( true)))),
		{1U, 1U, 1U, 0U, 0U}) ;	// 明示UNKNOWNを保持する正例。
	DRIVERCRATE_EXPECT(
		context, unknown.receipt &&
					 unknown.receipt->records()[0].acquisitionDescriptor->reason ==
						 "static route not supplied" &&
					 unknown.receipt->records()[0].acquisitionDescriptor->terms.reason ==
						 "terms not supplied" &&
					 unknown.receipt->records()[0].acquisitionDescriptor->prerequisites.reason ==
						 "prerequisites not supplied" &&
					 unknown.receipt->records()[0].acquisitionDescriptor->publisher.reason ==
						 "publisher not supplied" &&
					 !unknown.receipt->records()[0].acquisitionDescriptor->attestation) ;
	const std::string legacy = distributionRecord( "legacy") ;	// 元14fieldの旧record。
	const auto		  mixed	 = readRecordFixture(
		key,
		descriptorIndex( recordSource(), recordEntry( key, raw) + "," + recordEntry( key, legacy)),
		{1U, 2U, 2U, 0U, 0U}) ;	// v2 outer内の旧record。
	DRIVERCRATE_EXPECT(
		context, mixed.receipt && mixed.receipt->records()[1].recordSchemaVersion == 1U &&
					 !mixed.receipt->records()[1].acquisitionDescriptor &&
					 !mixed.receipt->records()[1].acquisitionDescriptorUnavailableReason.empty()) ;
	rejectRecordIndex( context, key, distributionIndex( recordSource(), recordEntry( key, raw)),
					  IndexRecordsStatus::INVALID_RECORD, {1U, 1U, 1U, 0U, 0U}) ;
	// 同じrawでも申告hashを別原byteから取った場合はschemaより前で拒否する。
	rejectRecordIndex(
		context, key,
		descriptorIndex( recordSource(), recordEntry( key, raw, recordDigest( key, raw + " "))),
		IndexRecordsStatus::RECORD_HASH_MISMATCH, {1U, 1U, 1U, 0U, 0U}) ;
	const std::string rich =
		// 全nestedobjectを含む正例。
		descriptorRecord( descriptorFixture( false, true)) ;
	const auto richRead =
		readRecordFixture( key, descriptorIndex( recordSource(), recordEntry( key, rich)),
						  {1U, 1U, 1U, 0U, 0U}) ;	// 本文取得や条件確認は実施しない。
	DRIVERCRATE_EXPECT(
		context,
		richRead.receipt &&
			richRead.receipt->records()[0].acquisitionDescriptor->terms.textDocument &&
			richRead.receipt->records()[0].acquisitionDescriptor->terms.revision ==
				"Original 1.0" &&
			richRead.receipt->records()[0].acquisitionDescriptor->prerequisites.items[0].kind ==
				IndexPrerequisiteKind::LOCAL_CHECK) ;
	constexpr std::array<std::string_view, 22U> OBJECTS{"",
														"acquisitionDescriptor",
														"route",
														"terms",
														"textDocument",
														"prerequisites",
														"items",
														"publisher",
														"attestation",
														"targetOs",
														"architecture",
														"driverKind",
														"version",
														"publishedDate",
														"acquisition",
														"packageEvidence",
														"publishedHash",
														"calculatedHash",
														"size",
														"lastSuccessfulObservationUtc",
														"publishedIdentityEvidence",
														"pnpIds"} ;	// 全record入れ子の固定集合。
	// 全nestedobjectの欠損・未知・重複を三通りずつ真署名と正しい原hashで拒否確認する。
	for( const auto object : OBJECTS) {
		// 同じfixtureを有限三種類だけ改変し、既存strict規則を全objectで確認する。
		for( unsigned mutation = 0U; mutation < 3U; ++mutation) {
			const std::string changed =
				// 原byte改変を正しくhashへ結ぶ。
				mutateDescriptorObject( rich, object, mutation) ;
			rejectRecordIndex( context, key,
							  descriptorIndex( recordSource(), recordEntry( key, changed)),
							  IndexRecordsStatus::INVALID_RECORD, {1U, 1U, 1U, 0U, 0U}) ;
		}
	}

	constexpr std::array<std::string_view, 3U> INDEX_OBJECTS{
		"", "sources", "officialEvidence"} ;	// Outerとsourceの全object。
	// Outerの入れ子も三種類ずつ拒否し、schema順序で不正objectを補完しない。
	for( const auto object : INDEX_OBJECTS) {
		// 固定三改変を実署名indexに通す。
		for( unsigned mutation = 0U; mutation < 3U; ++mutation) {
			rejectRecordIndex( context, key, mutateDescriptorObject( index, object, mutation),
							  IndexRecordsStatus::INVALID_INDEX, {1U, 1U, 1U, 0U, 0U}) ;
		}
	}

	// Sourceとrecordの対応を失った先頭route証拠は型が正しくても拒否する。
	const std::array<std::pair<std::string, std::string>, 24U> invalidEvidence{
		{{"\"maximumBytes\":134217728", "\"maximumBytes\":0"},
		 {"\"maximumBytes\":134217728", "\"maximumBytes\":134217729"},
		 {"\"format\":\"ZIP\"", "\"format\":\"UNKNOWN\""},
		 {"\"format\":\"ZIP\"", "\"format\":\"WINDOWS_EXE\""},
		 {"\"reason\":\"\",\"payloadUrl\"", "\"reason\":\"contradictory\",\"payloadUrl\""},
		 {"\"fileName\":\"Fixture 1.2 (x64).zip\"", "\"fileName\":\"CON .v2.zip\""},
		 {"\"fileName\":\"Fixture 1.2 (x64).zip\"", "\"fileName\":\"../fixture.zip\""},
		 {"\"expectedContentType\":\"application/zip\"",
		  "\"expectedContentType\":\"application/zip;token=x\""},
		 {"\"kind\":\"OFFICIAL_PAYLOAD_LINK\"", "\"kind\":\"HTTP_REDIRECT\""},
		 {"\"evidenceUrl\":\"https://vendor.example/support\"",
		  "\"evidenceUrl\":\"https://vendor.example/other\""},
		 {"\"policyRevision\":1", "\"policyRevision\":2"},
		 {"\"kind\":\"COLLECTOR_VERIFIED_OFFICIAL_ROUTE\"", "\"kind\":\"SELF_APPROVED\""},
		 {"2026-10-10T03:00:00Z", "2026-10-11T05:00:01Z"},
		 {"2026-10-12T03:00:00Z", "2026-10-11T05:00:00Z"},
		 {"2026-10-12T03:00:00Z", "2026-10-25T05:00:01Z"},
		 {"2026-10-12T03:00:00Z", "2026-10-17T03:00:01Z"},
		 {"2026-10-10T03:00:00Z", "2026-02-30T03:00:00Z"},
		 {"\"textDocument\":null", "\"textDocument\":{}"},
		 {"\"revisionKind\":\"NONE\"", "\"revisionKind\":\"VENDOR_LITERAL\""},
		 {"\"state\":\"CONFIRMED_NO_CONSENT\"", "\"state\":\"UNKNOWN\""},
		 {"\"prerequisites\":{\"state\":\"KNOWN\",\"reason\":\"\"",
		  "\"prerequisites\":{\"state\":\"UNKNOWN\",\"reason\":\"\""},
		 {"\"publisher\":{\"state\":\"KNOWN\"", "\"publisher\":{\"state\":\"UNKNOWN\""},
		 {"\"format\":\"ZIP\"", "\"format\":\"RAR\""},
		 {"\"payloadUrl\":\"https://vendor.example/fixture.zip\"",
		  "\"payloadUrl\":\"https://vendor.example/other.zip\""}}} ;	// 構造不正と意味不正を別に期待する固定改変表。
	// 意味不整合の固定24条件を型が正しい署名recordで確認する。
	for( std::size_t indexCase = 0U; indexCase < invalidEvidence.size(); ++indexCase) {
		const auto &change = invalidEvidence[indexCase] ;	// 同期借用する元/改変literal。
		const auto	status = indexCase == 17U
								 ? IndexRecordsStatus::INVALID_RECORD
								 : IndexRecordsStatus::INVALID_EVIDENCE ;	// 空objectだけは文法拒否。
		rejectRecordIndex(
			context, key,
			descriptorIndex( recordSource(),
							recordEntry( key, descriptorRecord( replaced( descriptor, change.first,
																	   change.second)))),
			status, {1U, 1U, 1U, 0U, 0U}) ;
	}

	constexpr std::array<std::string_view, 17U> BAD_URLS{
		"http://vendor.example/fixture.zip",	   "https://user@vendor.example/fixture.zip",
		"https://127.0.0.1/fixture.zip",		   "https://[::1]/fixture.zip",
		"https://vendor.local/fixture.zip",		   "https://vendor.internal/fixture.zip",
		"https://localhost.example/fixture.zip",   "https://vendor.lan/fixture.zip",
		"https://-vendor.example/fixture.zip",	   "https://vendor..example/fixture.zip",
		"https://vendor.example:444/fixture.zip",  "https://vendor.example/fixture.zip#x",
		"https://vendor.example/fixture.zip?id=7", "https://vendor.example/a%0d.zip",
		"https://vendor.example/a%255c.zip",	   "https://vendor.example/a%2.zip",
		"https://vendor.example/a b.zip"} ;	// DNSやHTTPを呼ばない固定拒否集合。
	// Payloadとrouteの両方に同じ不正原URLを置き、queryやprivate構文を拒否する。
	for( const auto url : BAD_URLS) {
		std::string changed = descriptor ;	// この条件だけの人工元byte。
		// 同じ原payload URLの二参照を共に改変する。
		for( unsigned occurrence = 0U; occurrence < 2U; ++occurrence) {
			changed = replaced( std::move( changed), "https://vendor.example/fixture.zip", url) ;
		}

		rejectRecordIndex(
			context, key,
			descriptorIndex( recordSource(), recordEntry( key, descriptorRecord( changed))),
			IndexRecordsStatus::INVALID_URL, {1U, 1U, 1U, 0U, 0U}) ;
	}

	// 初回PAGEの閉じた数値queryは原URLを変えず保持する。
	const std::string sourceQuery = replaced(
		replaced( recordSource(), "\"distributionPage\":\"https://vendor.example/support\"",
				 "\"distributionPage\":\"https://vendor.example/support?id=7\""),
		"\"evidenceUrl\":\"https://vendor.example/support\"",
		"\"evidenceUrl\":\"https://vendor.example/support?id=7\"") ;	// 元pageと公式出典を一致させる。
	const std::string queryDescriptor = replaced(
		descriptor, "\"evidenceUrl\":\"https://vendor.example/support\"",
		"\"evidenceUrl\":\"https://vendor.example/support?id=7\"") ;	// 先頭routeの同source根拠。
	const auto queryRead = readRecordFixture(
		key, descriptorIndex( sourceQuery, recordEntry( key, descriptorRecord( queryDescriptor))),
		{1U, 1U, 1U, 0U, 0U}) ;	// PAGEだけの正例。
	DRIVERCRATE_EXPECT( context,
					   queryRead.receipt && queryRead.receipt->sources()[0].distributionPage ==
												"https://vendor.example/support?id=7") ;
	rejectRecordIndex( context, key, distributionIndex( sourceQuery, recordEntry( key, legacy)),
					  IndexRecordsStatus::INVALID_URL, {1U, 1U, 1U, 0U, 0U}) ;
	// 未登録CDNの元申告は専用Providerを増やさず共通codecで保持する。
	std::string cdn = descriptor ;	// 公式pageに結合する別originの元申告。
	// 二つのpayload参照だけをexact CDN URLへ結ぶ。
	for( unsigned occurrence = 0U; occurrence < 2U; ++occurrence) {
		cdn = replaced( std::move( cdn), "https://vendor.example/fixture.zip",
					   "https://new-cdn.example/fixture.zip") ;
	}

	rejectRecordIndex( context, key,
					  descriptorIndex( recordSource(), recordEntry( key, descriptorRecord( cdn))),
					  IndexRecordsStatus::INVALID_EVIDENCE, {1U, 1U, 1U, 0U, 0U}) ;
	cdn				   = replaced( std::move( cdn), "OFFICIAL_PAYLOAD_LINK", "OFFICIAL_CDN_LINK") ;
	const auto cdnRead = readRecordFixture(
		key, descriptorIndex( recordSource(), recordEntry( key, descriptorRecord( cdn))),
		{1U, 1U, 1U, 0U, 0U}) ;	// 元attestationを実公式性へ昇格しない。
	DRIVERCRATE_EXPECT( context,
					   cdnRead.receipt &&
						   cdnRead.receipt->records()[0].acquisitionDescriptor->route[0].kind ==
							   IndexRouteKind::OFFICIAL_CDN_LINK) ;
	rejectRecordIndex( context, key,
					  descriptorIndex( recordSource( "fixture-source", true), recordEntry( key, raw)),
					  IndexRecordsStatus::INVALID_EVIDENCE, {1U, 1U, 1U, 0U, 0U}) ;
	const auto capacity = readRecordFixture(
		key,
		descriptorIndex( recordSource(), recordEntry( key, replaced( raw, "\"valueBytes\":1234",
																  "\"valueBytes\":134217729"))),
		{1U, 1U, 1U, 0U, 0U}) ;	// 元size超過は後段容量保留でありrecordを消さない。
	DRIVERCRATE_EXPECT( context,
					   capacity.receipt &&
						   capacity.receipt->records()[0].packageEvidence.size.value == 134217729U) ;
	const auto missingSize = readRecordFixture(
		key,
		descriptorIndex(
			recordSource(),
			recordEntry(
				key,
				replaced(
					raw, R"json({"state":"KNOWN","valueBytes":1234,"reason":""})json",
					R"json({"state":"UNKNOWN","valueBytes":0,"reason":"size not supplied"})json"))),
		{1U, 1U, 1U, 0U, 0U}) ;	// 推測sizeで補完しない。
	DRIVERCRATE_EXPECT( context, missingSize.receipt &&
									!missingSize.receipt->records()[0].packageEvidence.size.value &&
									missingSize.receipt->records()[0].packageEvidence.size.reason ==
										"size not supplied") ;
	const auto unknownConditions = readRecordFixture(
		key,
		descriptorIndex(
			recordSource(),
			recordEntry( key,
						descriptorRecord( descriptor, distributionRecord( "unknown-target", false)))),
		{1U, 1U, 1U, 0U, 0U}) ;	// Descriptorの形式から未知条件を補わない。
	DRIVERCRATE_EXPECT( context, unknownConditions.receipt &&
									!unknownConditions.receipt->records()[0].targetOs.value &&
									!unknownConditions.receipt->records()[0].architecture.value &&
									!unknownConditions.receipt->records()[0].driverKind.value &&
									!unknownConditions.receipt->records()[0].acquisition.value) ;
	// 公開revisionと算出予定revisionをwire上で別々に保持する。
	const std::string computed =
		replaced( replaced( rich, "VENDOR_LITERAL", "COMPUTED_UTF8_SHA256"), "Original 1.0",
				 "") ;	// 本文の取得やrevision計算は行わない。
	const auto computedRead =
		readRecordFixture( key, descriptorIndex( recordSource(), recordEntry( key, computed)),
						  {1U, 1U, 1U, 0U, 0U}) ;	// 元revisionの由来を保持する読取り。
	DRIVERCRATE_EXPECT(
		context,
		computedRead.receipt &&
			computedRead.receipt->records()[0].acquisitionDescriptor->terms.revisionKind ==
				IndexTermsRevisionKind::COMPUTED_UTF8_SHA256 &&
			computedRead.receipt->records()[0].acquisitionDescriptor->terms.revision.empty()) ;
	const auto oldObservationBytes =
		// 元確認は更新せず原assetを保持する。
		recordBytes( key, index, {1U, 1U, 1U, 0U, 0U}) ;
	const auto expiredIndividual = readSignedIndexRecords(
		oldObservationBytes,
		NOW + std::chrono::days{3}) ;	// Manifest内で個別attestationだけ期限切れ。
	DRIVERCRATE_EXPECT( context, expiredIndividual.receipt &&
									expiredIndividual.receipt->records()[0]
											.acquisitionDescriptor->attestation->validUntilUtc <
										NOW + std::chrono::days{3}) ;
	const auto exactSevenDays = readRecordFixture(
		key,
		descriptorIndex( recordSource(), recordEntry( key, descriptorRecord( replaced(
															 descriptor, "2026-10-12T03:00:00Z",
															 "2026-10-17T03:00:00Z")))),
		{1U, 1U, 1U, 0U, 0U}) ;	// 7日の構造境界は有効。
	DRIVERCRATE_EXPECT( context, exactSevenDays.receipt.has_value()) ;
	constexpr std::array<std::pair<std::string_view, IndexPayloadFormat>, 3U> FORMATS{
		{{"CABINET", IndexPayloadFormat::CABINET},
		 {"WINDOWS_EXE", IndexPayloadFormat::WINDOWS_EXE},
		 {"WINDOWS_MSI", IndexPayloadFormat::WINDOWS_MSI}}} ;	// 申告形式だけを保持し実行はしない。
	// Archiveとinstallerを別方式に結び、全既知形式のtyped値を確認する。
	for( const auto &format : FORMATS) {
		std::string typed = descriptorRecord(
			replaced( descriptor, "\"format\":\"ZIP\"",
					 "\"format\":\"" + std::string{format.first} + "\"")) ;	// 元申告形式だけの変更。
		// EXEとMSIだけは元方式をinstallerへ結ぶ。
		if( format.second != IndexPayloadFormat::CABINET) {
			typed = replaced( std::move( typed), "STANDARD_INF_ARCHIVE", "OFFICIAL_INSTALLER") ;
		}

		const auto acceptedFormat =
			readRecordFixture( key, descriptorIndex( recordSource(), recordEntry( key, typed)),
							  {1U, 1U, 1U, 0U, 0U}) ;	// 実byteや起動許可とは別の型検査。
		DRIVERCRATE_EXPECT( context,
						   acceptedFormat.receipt &&
							   acceptedFormat.receipt->records()[0].acquisitionDescriptor->format ==
								   format.second) ;
	}

	const std::array<std::string, 6U> hopUrls{
		"https://vendor.example/fixture.zip",
		"https://vendor.example/step.zip",
		"https://new-cdn.example/one.zip",
		"https://new-cdn.example/two.zip",
		"https://new-cdn.example/three.zip",
		"https://new-cdn.example/four.zip"} ;	// 有限6hopの原URL。
	std::string hops ;							// Exact routeの元順序を保持する人工配列。
	// 最大5redirectの正例を明示し、以後の根拠を直前URLへ完全結合する。
	for( std::size_t hop = 0U; hop < hopUrls.size(); ++hop) {
		// 二件目以後だけcommaを加える。
		if( hop != 0U) {
			hops += "," ;
		}

		hops += descriptorHop( hopUrls[hop], hop == 0U ? "OFFICIAL_PAYLOAD_LINK" : "HTTP_REDIRECT",
							  hop == 0U ? "https://vendor.example/support" : hopUrls[hop - 1U]) ;
	}

	const auto sixHops = readRecordFixture(
		key,
		descriptorIndex( recordSource(),
						recordEntry( key, descriptorRecord( descriptorRoute( descriptor, hops)))),
		{1U, 1U, 1U, 0U, 0U}) ;	// OriginからCDNへ一方向だけの正例。
	DRIVERCRATE_EXPECT( context,
					   sixHops.receipt &&
						   sixHops.receipt->records()[0].acquisitionDescriptor->route.size() == 6U) ;
	rejectRecordIndex(
		context, key,
		descriptorIndex(
			recordSource(),
			recordEntry( key, descriptorRecord( descriptorRoute(
								 descriptor, hops + "," +
												 descriptorHop( "https://new-cdn.example/five.zip",
															   "HTTP_REDIRECT", hopUrls.back()))))),
		IndexRecordsStatus::COUNT_LIMIT, {1U, 1U, 1U, 0U, 0U}) ;
	const std::string firstHop = descriptorHop(
		hopUrls[0], "OFFICIAL_PAYLOAD_LINK", "https://vendor.example/support") ;	// 先頭の完全根拠。
	const std::array<std::string, 4U> BAD_ROUTES{
		firstHop + "," + descriptorHop( hopUrls[0], "HTTP_REDIRECT", hopUrls[0]),
		firstHop + "," +
			descriptorHop( hopUrls[1], "HTTP_REDIRECT", "https://vendor.example/wrong.zip"),
		firstHop + "," + descriptorHop( hopUrls[1], "OFFICIAL_CDN_LINK", hopUrls[0]),
		firstHop + "," + descriptorHop( hopUrls[2], "HTTP_REDIRECT", hopUrls[0]) + "," +
			descriptorHop( hopUrls[1], "HTTP_REDIRECT",
						  hopUrls[2])} ;	// 循環・根拠不整合・redirect種別違反・CDN逆戻り。
	// 同じpayloadの元route不整合だけを四条件で拒否する。
	for( const auto &route : BAD_ROUTES) {
		rejectRecordIndex(
			context, key,
			descriptorIndex( recordSource(),
							recordEntry( key, descriptorRecord( descriptorRoute( descriptor, route)))),
			IndexRecordsStatus::INVALID_EVIDENCE, {1U, 1U, 1U, 0U, 0U}) ;
	}

	const std::string item =
		R"json({"kind":"USER_CONFIRMATION","description":"Confirm a specific prerequisite","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
		std::string{RECORD_EVIDENCE_HASH} + R"json("})json" ;	// 独立同意にしない具体的条件。
	std::string items ;											// 最大16件の元条件集合。
	// 明示16件だけを生成し、全件で終了する。
	for( unsigned itemIndex = 0U; itemIndex < 16U; ++itemIndex) {
		// 二件目以後だけcommaを追加する。
		if( itemIndex > 0U) {
			items += "," ;
		}

		items += item ;
	}

	const std::string sixteen =
		// 上限の完全人工申告。
		replaced( descriptor, "\"items\":[]", "\"items\":[" + items + "]") ;
	const auto sixteenRead = readRecordFixture(
		key, descriptorIndex( recordSource(), recordEntry( key, descriptorRecord( sixteen))),
		{1U, 1U, 1U, 0U, 0U}) ;	// 条件確認は未実施。
	DRIVERCRATE_EXPECT(
		context,
		sixteenRead.receipt &&
			sixteenRead.receipt->records()[0].acquisitionDescriptor->prerequisites.items.size() ==
				16U) ;
	rejectRecordIndex(
		context, key,
		descriptorIndex(
			recordSource(),
			recordEntry( key, descriptorRecord( replaced( descriptor, "\"items\":[]",
													   "\"items\":[" + items + "," + item + "]")))),
		IndexRecordsStatus::COUNT_LIMIT, {1U, 1U, 1U, 0U, 0U}) ;
	const std::string emptyAttestation =
		descriptor.substr( 0U, descriptor.find( "\"attestation\":")) +
		"\"attestation\":null}" ;	// 既知descriptorの必須元証拠を欠損させる。
	rejectRecordIndex(
		context, key,
		descriptorIndex( recordSource(), recordEntry( key, descriptorRecord( emptyAttestation))),
		IndexRecordsStatus::INVALID_EVIDENCE, {1U, 1U, 1U, 0U, 0U}) ;
	rejectRecordIndex(
		context, key,
		descriptorIndex(
			recordSource(),
			recordEntry( key, descriptorRecord( replaced(
								 descriptorFixture( true), "\"payloadUrl\":\"\"",
								 "\"payloadUrl\":\"https://vendor.example/fixture.zip\"")))),
		IndexRecordsStatus::INVALID_EVIDENCE, {1U, 1U, 1U, 0U, 0U}) ;
	const std::string schemaFirst =
		"{\"schema\":\"driver-index-record-v2\"," +
		replaced( raw.substr( 1U), "\"schema\":\"driver-index-record-v2\",",
				 "") ;	// Record schemaを先頭へ移した別の元byte。
	const auto schemaFirstRead =
		readRecordFixture( key, descriptorIndex( recordSource(), recordEntry( key, schemaFirst)),
						  {1U, 1U, 1U, 0U, 0U}) ;	// 元順序が別でも全15fieldを要求する。
	DRIVERCRATE_EXPECT(
		context, schemaFirstRead.receipt &&
					 schemaFirstRead.receipt->records()[0].originalBytes == schemaFirst &&
					 schemaFirstRead.receipt->records()[0].recordSha256 != record.recordSha256) ;
	std::cout << "Signed index descriptor codec assertions: "
			  << context.assertionCount() - firstAssertion
			  << ", failures: " << context.failureCount() - firstFailure << '\n' ;
}

} // namespace

/** @see signed_index_manifest_tests.h */
void runSignedIndexRecordsTests( TestContext &context)
{
	static_assert( !std::is_default_constructible_v<IndexRecordsSchemaReceipt>) ;
	static_assert(
		!std::is_constructible_v<IndexRecordsSchemaReceipt, AuthenticatedIndexAssetBytes,
								 std::vector<IndexRecordSource>,
								 std::vector<IndexDistributionRecord>, IndexManifestQuality>) ;
	const int firstAssertion = context.assertionCount() ;	// このgroupだけの実件数。
	const int firstFailure	 = context.failureCount() ;		// このgroupだけの実失敗。
	RamKey	  key ;											// 既存helperのRAM鍵。再実装・秘密鍵永続化をしない。
	key.generate( 3072U) ;
	const std::string metadata = distributionRecord() ;	// 架空の公開identityを持つ元申告。
	const std::string content =
		// 発行側内容検査申告。
		distributionRecord( "content", true, "CONTENT_INSPECTED") ;
	const std::string unknown =
		// 明示UNKNOWNを残すrecord。
		distributionRecord( "unconfirmed", false, "UNCONFIRMED") ;
	const std::string entries = recordEntry( key, metadata) + "," + recordEntry( key, content) + "," +
								// 三段階が一件ずつの人工集合。
								recordEntry( key, unknown) ;
	const std::string index	   = distributionIndex( recordSource(), entries) ;	// 原配布index。
	auto			  bytes	   = recordBytes( key, index) ;						// 全前段を通した必須入力。
	const auto		  accepted = readSignedIndexRecords( bytes, NOW) ;			// 実native正例。
	DRIVERCRATE_EXPECT( context, accepted.status == IndexRecordsStatus::SCHEMA_VALIDATED) ;
	DRIVERCRATE_EXPECT( context, accepted.error == 0) ;
	DRIVERCRATE_EXPECT( context, accepted.receipt.has_value()) ;
	// 正例生成不成立でreceiptを参照しない。
	if( !accepted.receipt) {
		return ;
	}

	const auto &receipt = *accepted.receipt ;	// 原byteと元申告だけを持つ不変receipt。
	DRIVERCRATE_EXPECT( context, receipt.sources().size() == 1U && receipt.records().size() == 3U) ;
	DRIVERCRATE_EXPECT( context, receipt.indexSha256() == key.digest( index)) ;
	DRIVERCRATE_EXPECT( context, assetText( receipt.assetBytes().expandedBytes()) == index) ;
	DRIVERCRATE_EXPECT( context, receipt.records()[0].originalBytes == metadata) ;
	DRIVERCRATE_EXPECT( context, receipt.records()[0].recordSha256 == key.digest( metadata)) ;
	DRIVERCRATE_EXPECT( context, receipt.records()[0].recordSha256 != receipt.indexSha256()) ;
	DRIVERCRATE_EXPECT( context, receipt.assetBytes().manifest().data().asset.sha256 !=
									receipt.indexSha256()) ;
	DRIVERCRATE_EXPECT( context, receipt.assetBytes().manifest().data().manifestSha256 !=
									receipt.indexSha256()) ;
	DRIVERCRATE_EXPECT( context, receipt.records()[0].publishedIdentityEvidence.pnpIds[0].value ==
									"TESTBUS\\SYNTH_0001") ;
	DRIVERCRATE_EXPECT( context, receipt.records()[0].publishedIdentityEvidence.infIdentity ==
									"drivers/fixture.inf") ;
	DRIVERCRATE_EXPECT( context,
					   receipt.records()[0].publishedIdentityEvidence.evidenceSha256 ==
						   signed_index_json::decodeHash( RECORD_EVIDENCE_HASH,
														 IndexRecordsStatus::INVALID_EVIDENCE)) ;
	DRIVERCRATE_EXPECT( context, receipt.records()[0].packageEvidence.publishedHash.sha256 ==
									receipt.records()[0].packageEvidence.calculatedHash.sha256) ;
	DRIVERCRATE_EXPECT( context, receipt.records()[2].publishedIdentityEvidence.state ==
									IndexEvidenceState::UNKNOWN) ;
	DRIVERCRATE_EXPECT( context, receipt.records()[2].publishedIdentityEvidence.reason ==
									"public INF identity missing") ;
	DRIVERCRATE_EXPECT( context, !receipt.records()[2].targetOs.value &&
									receipt.records()[2].targetOs.reason == "not supplied") ;
	DRIVERCRATE_EXPECT( context, !receipt.records()[2].packageEvidence.calculatedHash.sha256 &&
									receipt.records()[2].packageEvidence.calculatedHash.reason ==
										"not inspected") ;
	DRIVERCRATE_EXPECT( context, receipt.actualQuality().sourceCount == 1U &&
									receipt.actualQuality().recordCount == 3U &&
									receipt.actualQuality().metadataOnlyCount == 1U &&
									receipt.actualQuality().contentInspectedCount == 1U &&
									receipt.actualQuality().unconfirmedCount == 1U) ;
	DRIVERCRATE_EXPECT( context, receipt.schemaPolicyVersion() == 3U) ;

	expectRecordsRejected( context, readSignedIndexRecords( bytes, std::nullopt),
						  IndexRecordsStatus::TIME_UNAVAILABLE) ;
	expectRecordsRejected( context,
						  readSignedIndexRecords( bytes, bytes.manifest().data().publishedAtUtc -
															std::chrono::seconds{1}),
						  IndexRecordsStatus::NOT_YET_VALID) ;
	expectRecordsRejected( context,
						  readSignedIndexRecords( bytes, bytes.manifest().data().expiresAtUtc),
						  IndexRecordsStatus::EXPIRED) ;
	DRIVERCRATE_EXPECT(
		context,
		readSignedIndexRecords( bytes, bytes.manifest().data().publishedAtUtc).receipt.has_value()) ;
	DRIVERCRATE_EXPECT( context, readSignedIndexRecords( bytes, bytes.manifest().data().expiresAtUtc -
																  std::chrono::seconds{1})
									.receipt.has_value()) ;
	auto moved = std::move( bytes) ;	// 認証byteを持つmove先。
	expectRecordsRejected( context, readSignedIndexRecords( bytes, NOW),
						  IndexRecordsStatus::INCOMPLETE_BYTE_RECEIPT) ;
	DRIVERCRATE_EXPECT( context, readSignedIndexRecords( moved, NOW).receipt.has_value()) ;

	const std::string shifted = replaced( metadata, "\"schema\":\"driver-index-record-v1\",",
										 "") ;	// Field順を変える元record。
	const std::string reordered =
		"\n " + shifted.substr( 0U, shifted.size() - 1U) +
		", \"schema\" : \"driver-index-record-v1\" }\r\n" ;	// 再serializationしない原byte。
	const std::string singleIndex = "\n " +
									distributionIndex( recordSource(), recordEntry( key, reordered)) +
									"\n" ;	// 原空白を持つindex。
	const auto reorderedResult =
		// 順序・空白正例。
		readRecordFixture( key, singleIndex, {1U, 1U, 1U, 0U, 0U}) ;
	DRIVERCRATE_EXPECT( context,
					   reorderedResult.receipt &&
						   reorderedResult.receipt->records()[0].originalBytes == reordered) ;
	DRIVERCRATE_EXPECT( context, reorderedResult.receipt &&
									reorderedResult.receipt->records()[0].recordSha256 ==
										key.digest( reordered)) ;
	DRIVERCRATE_EXPECT( context, reorderedResult.receipt &&
									reorderedResult.receipt->records()[0].recordSha256 !=
										key.digest( metadata)) ;
	const std::string escaped =
		// 標準escape原byte。
		replaced( metadata, "Synthetic fixture", "Synthetic \\u0066ixture") ;
	const auto escapedResult =
		readRecordFixture( key, distributionIndex( recordSource(), recordEntry( key, escaped)),
						  {1U, 1U, 1U, 0U, 0U}) ;	// 解除だけを行う正例。
	DRIVERCRATE_EXPECT( context,
					   escapedResult.receipt &&
						   escapedResult.receipt->records()[0].originalBytes == escaped &&
						   escapedResult.receipt->records()[0].product == "Synthetic fixture") ;
	const auto unknownSource = readRecordFixture(
		key, distributionIndex( recordSource( "fixture-source", true), recordEntry( key, unknown)),
		{1U, 1U, 0U, 0U, 1U}) ;	// 元公式性もUNKNOWNに残す正例。
	DRIVERCRATE_EXPECT( context, unknownSource.receipt &&
									unknownSource.receipt->sources()[0].officialEvidence.state ==
										IndexEvidenceState::UNKNOWN &&
									unknownSource.receipt->sources()[0].officialEvidence.reason ==
										"source not verified") ;
	const auto metadataUnknown = readRecordFixture(
		key,
		distributionIndex( recordSource( "fixture-source", true),
						  recordEntry( key, replaced( unknown, "\"inspectionStage\":\"UNCONFIRMED\"",
													"\"inspectionStage\":\"METADATA_ONLY\""))),
		{1U, 1U, 1U, 0U, 0U}) ;	// UNKNOWNと検査段階を独立に保持する正例。
	DRIVERCRATE_EXPECT( context, metadataUnknown.status == IndexRecordsStatus::SCHEMA_VALIDATED &&
									metadataUnknown.receipt.has_value()) ;
	DRIVERCRATE_EXPECT( context,
					   metadataUnknown.receipt &&
						   metadataUnknown.receipt->records()[0].inspectionStage ==
							   IndexInspectionStage::METADATA_ONLY &&
						   metadataUnknown.receipt->actualQuality().metadataOnlyCount == 1U &&
						   metadataUnknown.receipt->actualQuality().unconfirmedCount == 0U) ;
	DRIVERCRATE_EXPECT( context,
					   metadataUnknown.receipt &&
						   metadataUnknown.receipt->records()[0].publishedIdentityEvidence.state ==
							   IndexEvidenceState::UNKNOWN &&
						   metadataUnknown.receipt->records()[0].publishedIdentityEvidence.reason ==
							   "public INF identity missing" &&
						   !metadataUnknown.receipt->records()[0].targetOs.value &&
						   metadataUnknown.receipt->records()[0].targetOs.reason == "not supplied") ;

	rejectRecordIndex(
		context, key,
		distributionIndex( recordSource(), recordEntry( key, metadata, recordDigest( key, index))),
		IndexRecordsStatus::RECORD_HASH_MISMATCH, {1U, 1U, 1U, 0U, 0U}) ;
	rejectRecordIndex(
		context, key,
		distributionIndex(
			recordSource(),
			recordEntry( key, metadata, recordDigest( key, assetText( assetGzip( index))))),
		IndexRecordsStatus::RECORD_HASH_MISMATCH, {1U, 1U, 1U, 0U, 0U}) ;
	rejectRecordIndex( context, key, index, IndexRecordsStatus::QUALITY_MISMATCH,
					  {2U, 3U, 1U, 1U, 1U}) ;
	rejectRecordIndex( context, key, index, IndexRecordsStatus::QUALITY_MISMATCH,
					  {1U, 4U, 2U, 1U, 1U}) ;
	rejectRecordIndex( context, key, index, IndexRecordsStatus::QUALITY_MISMATCH,
					  {1U, 3U, 2U, 0U, 1U}) ;
	rejectRecordIndex( context, key, index, IndexRecordsStatus::QUALITY_MISMATCH,
					  {1U, 3U, 0U, 1U, 2U}) ;
	rejectRecordIndex( context, key, index, IndexRecordsStatus::QUALITY_MISMATCH,
					  {1U, 3U, 1U, 2U, 0U}) ;
	rejectRecordIndex( context, key,
					  replaced( index, "\"assetGeneration\":7", "\"assetGeneration\":8"),
					  IndexRecordsStatus::ASSET_GENERATION_MISMATCH) ;
	rejectRecordIndex(
		context, key,
		replaced( index, "\"assetGeneration\":7", "\"assetGeneration\":7,\"assetGeneration\":7"),
		IndexRecordsStatus::INVALID_INDEX) ;
	rejectRecordIndex( context, key,
					  replaced( index, "\"assetGeneration\":7",
							   "\"assetGeneration\":7,\"assetGenera\\u0074ion\":7"),
					  IndexRecordsStatus::INVALID_INDEX) ;
	rejectRecordIndex( context, key,
					  replaced( index, "\"assetGeneration\":7", "\"assetGeneration\":7,\"other\":0"),
					  IndexRecordsStatus::INVALID_INDEX) ;
	rejectRecordIndex( context, key, replaced( index, "driver-index-records-v1", "research-v3"),
					  IndexRecordsStatus::INVALID_INDEX) ;
	rejectRecordIndex( context, key, replaced( index, "\"sources\":[", "\"sources\":{"),
					  IndexRecordsStatus::INVALID_INDEX) ;
	rejectRecordIndex( context, key, index + "{}", IndexRecordsStatus::INVALID_INDEX) ;
	rejectRecordIndex( context, key, index + "\xff", IndexRecordsStatus::INVALID_INDEX) ;
	rejectRecordIndex( context, key, "\xef\xbb\xbf" + index, IndexRecordsStatus::INVALID_INDEX) ;
	constexpr std::array<std::string_view, 6U> BAD_NUMBERS{
		"NaN", "Infinity", "7.0", "7e0", "-7", "18446744073709551616"} ;	// 非整数／非有限拒否。
	// 各不正数値を署名済みindexの同じfieldへ一つずつ渡す。
	for( const auto number : BAD_NUMBERS) {
		rejectRecordIndex(
			context, key,
			replaced( index, "\"assetGeneration\":7", "\"assetGeneration\":" + std::string{number}),
			IndexRecordsStatus::INVALID_INDEX) ;
	}

	rejectRecordIndex( context, key,
					  distributionIndex( recordSource() + "," + recordSource(), entries),
					  IndexRecordsStatus::DUPLICATE_SOURCE) ;
	rejectRecordIndex( context, key,
					  distributionIndex( recordSource(), recordEntry( key, metadata) + "," +
															recordEntry( key, metadata)),
					  IndexRecordsStatus::DUPLICATE_RECORD) ;
	rejectRecordIndex( context, key, distributionIndex( "", entries),
					  IndexRecordsStatus::MISSING_SOURCE) ;
	rejectRecordIndex(
		context, key,
		distributionIndex( recordSource(),
						  recordEntry( key, distributionRecord( "metadata", true, "METADATA_ONLY",
															  "missing-source"))),
		IndexRecordsStatus::MISSING_SOURCE) ;
	rejectRecordIndex(
		context, key,
		distributionIndex( recordSource() + "," + recordSource( "unreferenced"), entries),
		IndexRecordsStatus::UNREFERENCED_SOURCE) ;
	const std::string otherSourceRecord = distributionRecord(
		"metadata", true, "METADATA_ONLY", "other-source") ;	// 別sourceの同record ID。
	// 別sourceの同名recordを独立identityとして受理した実結果。
	const auto separateIdentities = readRecordFixture(
		key,
		distributionIndex( recordSource() + "," + recordSource( "other-source"),
						  recordEntry( key, metadata) + "," + recordEntry( key, otherSourceRecord)),
		{2U, 2U, 2U, 0U, 0U}) ;
	DRIVERCRATE_EXPECT( context, separateIdentities.receipt &&
									separateIdentities.receipt->records().size() == 2U) ;

	constexpr std::array<std::string_view, 10U> BAD_BASE64{
		"",		"A",	"A===", "AA=A", "AA-_",
		"AA A", "AB==", "AAB=", "====", "AA==AAAA"} ;	// 全厳格base64拒否。
	// 正しいhash申告を残し、base64文法だけを個別に拒否する。
	for( const auto encoded : BAD_BASE64) {
		const std::string entry = "{\"recordBytesBase64\":\"" + std::string{encoded} +
								  "\",\"recordSha256\":\"" + recordDigest( key, metadata) +
								  "\"}" ;	// 文法だけ不正なentry。
		rejectRecordIndex( context, key, distributionIndex( recordSource(), entry),
						  IndexRecordsStatus::INVALID_BASE64, {1U, 1U, 1U, 0U, 0U}) ;
	}

	rejectRecordIndex(
		context, key,
		distributionIndex( recordSource(), replaced( recordEntry( key, metadata), "\"recordSha256\":",
												   "\"recordSha256\":\"abc\",\"recordSha256\":")),
		IndexRecordsStatus::INVALID_INDEX, {1U, 1U, 1U, 0U, 0U}) ;
	rejectDistributionRecord( context, key, metadata + "\xff", IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord( context, key, "\xef\xbb\xbf" + metadata,
							 IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "Synthetic fixture", std::string{"\xc0\xaf", 2U}),
							 IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"recordId\":\"metadata\"",
									  "\"recordId\":\"metadata\",\"recordId\":\"metadata\""),
							 IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"recordId\":\"metadata\"",
									  "\"recordId\":\"metadata\",\"record\\u0049d\":\"metadata\""),
							 IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord(
		context, key,
		replaced( metadata, "\"recordId\":\"metadata\"", "\"recordId\":\"metadata\",\"other\":true"),
		IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord( context, key, replaced( metadata, "\"recordId\":\"metadata\",", ""),
							 IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "driver-index-record-v1", "research-v3"),
							 IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"value\":\"X64\"", "\"value\":null"),
							 IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"value\":\"X64\"", "\"value\":\"ARM64\""),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"state\":\"KNOWN\",\"value\":\"X64\"",
									  "\"state\":\"UNKNOWN\",\"value\":\"X64\""),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"value\":\"X64\",\"reason\":\"\"",
									  "\"value\":\"X64\",\"reason\":\"not known\""),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key, replaced( metadata, "2026-10-01", "2026-02-30"),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "2026-10-10T03:00:00Z", "2026-10-11T05:00:01Z"),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "2026-10-10T03:00:00Z", "2026-10-10T25:00:00Z"),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"valueBytes\":1234", "\"valueBytes\":0"),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"valueBytes\":1234", "\"valueBytes\":1234.0"),
							 IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"sha256\":\"111", "\"sha256\":\"311"),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord(
		context, key,
		replaced(
			content,
			"\"calculatedHash\":" + std::string{R"json({"state":"KNOWN","sha256":")json"} +
				std::string{RECORD_CLAIM_HASH} +
				R"json(","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
				std::string{RECORD_EVIDENCE_HASH} + R"json(","reason":""})json",
			R"json("calculatedHash":{"state":"UNKNOWN","sha256":"","evidenceUrl":"","evidenceSha256":"","reason":"not inspected"})json"),
		IndexRecordsStatus::INVALID_EVIDENCE) ;

	rejectDistributionRecord(
		context, key,
		replaced( metadata, R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json", "[]"),
		IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "{11111111-2222-3333-4444-555555555555}", ""),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "{11111111-2222-3333-4444-555555555555}",
									  "{00000000-0000-0000-0000-000000000000}"),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "drivers/fixture.inf", "../fixture.inf"),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "drivers/fixture.inf", "/fixture.inf"),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key, replaced( metadata, "Fixture.NTamd64", ""),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key, replaced( metadata, "TESTBUS", "testbus"),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"kind\":\"HARDWARE\"", "\"kind\":\"INSTANCE\""),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord(
		context, key,
		replaced(
			metadata, R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json",
			R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"},{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json"),
		IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectRecordIndex(
		context, key,
		distributionIndex( recordSource( "fixture-source", true), recordEntry( key, metadata)),
		IndexRecordsStatus::INVALID_EVIDENCE, {1U, 1U, 1U, 0U, 0U}) ;
	rejectRecordIndex( context, key,
					  distributionIndex( replaced( recordSource(), "\"sourceId\":\"fixture-source\"",
												 "\"sourceId\":\"bad/source\""),
										recordEntry( key, metadata)),
					  IndexRecordsStatus::INVALID_EVIDENCE, {1U, 1U, 1U, 0U, 0U}) ;
	rejectRecordIndex(
		context, key,
		distributionIndex( replaced( recordSource(),
								   "\"evidenceUrl\":\"https://vendor.example/support\"",
								   "\"evidenceUrl\":\"https://vendor.example/other\""),
						  recordEntry( key, metadata)),
		IndexRecordsStatus::INVALID_EVIDENCE, {1U, 1U, 1U, 0U, 0U}) ;
	constexpr std::array<std::string_view, 8U> BAD_URLS{
		"http://vendor.example/fixture.inf",
		"https://127.0.0.1/fixture.inf",
		"https://[::1]/fixture.inf",
		"https://localhost/fixture.inf",
		"https://vendor.local/fixture.inf",
		"https://user@vendor.example/fixture.inf",
		"https://vendor.example/fixture.inf?token=synthetic",
		"https://vendor.example/fixture.inf#part"} ;	// 未対応形式と不正URL。
	// 公開証拠URL文法の違反を元署名付きrecordへ一つずつ入れる。
	for( const auto url : BAD_URLS) {
		rejectDistributionRecord( context, key,
								 replaced( metadata, "https://vendor.example/fixture.inf", url),
								 IndexRecordsStatus::INVALID_URL) ;
	}

	rejectDistributionRecord( context, key, replaced( unknown, "public INF identity missing", ""),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( unknown, "\"classGuid\":\"\"",
									  "\"classGuid\":\"{11111111-2222-3333-4444-555555555555}\""),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	const std::string deepRecord =
		replaced( metadata, "\"value\":\"X64\"",
				 "\"value\":[[[[[[[[[\"X64\"]]]]]]]]]") ;	// 固定schemaより深い誤型。
	rejectDistributionRecord( context, key, deepRecord, IndexRecordsStatus::INVALID_RECORD) ;

	const std::string exactRecord =
		metadata + std::string( INDEX_RECORD_MAX_BYTES - metadata.size(), ' ') ;	// 原64KiB境界。
	const auto exactRecordResult =
		readRecordFixture( key, distributionIndex( recordSource(), recordEntry( key, exactRecord)),
						  {1U, 1U, 1U, 0U, 0U}) ;	// 縮小policyでない正例。
	DRIVERCRATE_EXPECT( context, exactRecordResult.receipt &&
									exactRecordResult.receipt->records()[0].originalBytes.size() ==
										INDEX_RECORD_MAX_BYTES) ;
	rejectDistributionRecord( context, key, exactRecord + " ",
							 IndexRecordsStatus::RECORD_SIZE_LIMIT) ;
	rejectRecordIndex( context, key, index, IndexRecordsStatus::COUNT_LIMIT,
					  {INDEX_RECORD_SOURCE_MAX_COUNT + 1U, 3U, 1U, 1U, 1U}) ;
	rejectRecordIndex( context, key, index, IndexRecordsStatus::COUNT_LIMIT,
					  {1U, INDEX_RECORD_MAX_COUNT + 1U, INDEX_RECORD_MAX_COUNT - 1U, 1U, 1U}) ;
	std::string ids ;	// 件数境界を検査する一意な架空公開ID配列。
	// 128個の異なる架空IDを順に作り、端末actual IDを一切読まない。
	for( std::size_t count = 0U; count < INDEX_RECORD_PNP_MAX_COUNT; ++count) {
		// 後続要素だけのcommaを追加する。
		if( count != 0U) {
			ids += "," ;
		}

		ids += R"json({"kind":"HARDWARE","value":"TESTBUS\\SYNTH_)json" + std::to_string( count) +
			   R"json("})json" ;
	}

	const std::string maximumIds =
		replaced( metadata, R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json",
				 "[" + ids + "]") ;	// ID件数上限ちょうど。
	DRIVERCRATE_EXPECT(
		context,
		readRecordFixture( key, distributionIndex( recordSource(), recordEntry( key, maximumIds)),
						  {1U, 1U, 1U, 0U, 0U})
			.receipt.has_value()) ;
	rejectDistributionRecord(
		context, key,
		replaced( metadata, R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json",
				 "[" + ids + R"json(,{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_OVER"}])json"),
		IndexRecordsStatus::COUNT_LIMIT) ;
	std::string sources ;	// 実source配列の件数超過fixture。
	// 件数上限の一つ先まで一意sourceを作り、配列上限そのものの拒否を確認する。
	for( std::size_t count = 0U; count <= INDEX_RECORD_SOURCE_MAX_COUNT; ++count) {
		// 後続sourceだけのdelimiterを追加する。
		if( count != 0U) {
			sources += "," ;
		}

		sources += recordSource( "source-" + std::to_string( count), true) ;
	}

	rejectRecordIndex( context, key, distributionIndex( sources, entries),
					  IndexRecordsStatus::COUNT_LIMIT) ;

	std::string depth = "\"x\"" ;	// 実container深さを測る固定一文字。
	// 深さ8ちょうどまで一field objectを作る。
	for( unsigned count = 0U; count < 8U; ++count) {
		depth = "{\"x\":" + depth + "}" ;
	}

	bool depthAccepted{} ;	// 共通readerの実境界正例。
	try {
		signed_index_json::Reader<IndexRecordsStatus> reader(
			depth, IndexRecordsStatus::INVALID_INDEX) ;	// 共通文法。
		readDepthFixture( reader, 8U) ;
		reader.finish() ;
		depthAccepted = true ;
	} catch( const signed_index_json::Failure<IndexRecordsStatus> &) {
		depthAccepted = false ;
	}

	DRIVERCRATE_EXPECT( context, depthAccepted) ;
	bool depthRejected{} ;	// 実深さ9の拒否。
	try {
		const std::string tooDeep = "{\"x\":" + depth + "}" ;	// 一container超過。
		signed_index_json::Reader<IndexRecordsStatus> reader(
			tooDeep, IndexRecordsStatus::INVALID_INDEX) ;	// 同じ固定policy。
		readDepthFixture( reader, 9U) ;
		reader.finish() ;
	} catch( const signed_index_json::Failure<IndexRecordsStatus> &failure) {
		depthRejected = failure.status == IndexRecordsStatus::INVALID_INDEX ;
	}

	DRIVERCRATE_EXPECT( context, depthRejected) ;

	{
		std::string largeEntries ;	// 原record合計64MiBちょうどを持つ有限index。
		largeEntries.reserve( 90U * 1024U * 1024U) ;
		// 各64KiBの一意record1024件を作り、縮小policyなしで合計境界へ達する。
		for( std::size_t count = 0U; count < INDEX_RECORD_TOTAL_MAX_BYTES / INDEX_RECORD_MAX_BYTES;
			++count) {
			// 後続entryだけのcommaを追加する。
			if( count != 0U) {
				largeEntries += "," ;
			}

			std::string raw =
				// 一意の人工record原byte。
				distributionRecord( "total-" + std::to_string( count)) ;
			raw.append( INDEX_RECORD_MAX_BYTES - raw.size(), ' ') ;
			largeEntries += recordEntry( key, raw) ;
		}

		const std::string largeIndex =
			// 実約85MiBの配布index。
			distributionIndex( recordSource(), largeEntries) ;
		const auto totalAccepted =
			// 実合計境界正例。
			readRecordFixture( key, largeIndex, {1U, 1024U, 1024U, 0U, 0U}) ;
		DRIVERCRATE_EXPECT( context, totalAccepted.receipt &&
										totalAccepted.receipt->records().size() == 1024U) ;
		DRIVERCRATE_EXPECT( context,
						   totalAccepted.receipt &&
							   totalAccepted.receipt->records()[0].originalBytes.size() ==
								   INDEX_RECORD_MAX_BYTES &&
							   totalAccepted.receipt->records()[1023U].originalBytes.size() ==
								   INDEX_RECORD_MAX_BYTES) ;
		rejectRecordIndex(
			context, key,
			distributionIndex( recordSource(), largeEntries + "," + recordEntry( key, " ")),
			IndexRecordsStatus::TOTAL_RECORD_SIZE_LIMIT, {1U, 1025U, 1025U, 0U, 0U}) ;
	}
	std::cout << "Signed index record schema assertions: "
			  << context.assertionCount() - firstAssertion
			  << ", failures: " << context.failureCount() - firstFailure << '\n' ;
	runDescriptorCodecChecks( context) ;
}

namespace {

/** @brief 保存試験の原envelope／gzipと前段manifestを一つに所有します。 */
struct StoreInputs {
	/// 実RSA-PSS認証を通った前段manifest。
	AuthenticatedIndexManifest manifest ;
	/// Original-byte認証で使った原外側byte。
	std::string				   envelope ;
	/// 実hash／GZip検査する原転送byte。
	std::vector<std::byte>	   gzip ;
} ;

/** @brief 原入力と保存前schema receiptを所有する架空fixtureです。 */
struct StoreFixture {
	/// 実署名と実原gzipを持つ前段入力。
	StoreInputs				  inputs ;
	/// 保存前まで全検査した不変receipt。
	IndexRecordsSchemaReceipt receipt ;
} ;

/** @brief 実署名付き保存入力を作り、製品の暗号を迂回しません。
 * @param[in] key 同じRAM内署名鍵。
 * @param[in] index 原配布index byte。
 * @param[in] generation 新manifest世代。
 * @param[in] assetGeneration 原asset世代。
 * @param[in] nowUtc Fixtureの検査時刻。
 * @param[in] publication 署名発行のUTC表記。
 * @param[in] expiry 署名期限のUTC表記。
 * @param[in] padBytes 実gzip containerをこのbyte長へ拡大する指定。0は通常です。
 * @param[in] quality 実record集合へ署名する元集計。既存fixtureの既定件数は維持します。
 * @return 実CNG認証から取得した入力。生成不成立は例外です。
 */
[[nodiscard]] StoreInputs makeStoreInputs(
	const RamKey &key, const std::string_view index, const std::uint64_t generation = 7U,
	const std::uint64_t assetGeneration = 7U, const std::chrono::sys_seconds nowUtc = NOW,
	const std::string_view publication = "2026-10-11T05:00:00Z",
	const std::string_view expiry = "2026-10-25T05:00:00Z", const std::size_t padBytes = 0U,
	const IndexManifestQuality quality = {1U, 1U, 1U, 0U, 0U})
{
	auto gzip = assetGzip( index) ;	// 実GZipを独立helperで生成します。
	// 実圧縮上限の正例だけでcontainer長を拡大します。
	if( padBytes > gzip.size()) {
		gzip = padAssetGzip( std::move( gzip), padBytes) ;
	}

	const auto initial =
		// 共通asset hashの実署名です。
		assetManifest( key, gzip, false, recordQuality( quality)) ;
	std::string raw =
		replaced( initial.data().manifestBytes, "\"generation\":7",
				 "\"generation\":" + std::to_string( generation)) ;	// Manifest世代を独立指定します。
	raw						   = replaced( std::move( raw), "\"assetGeneration\":7",
										  "\"assetGeneration\":" + std::to_string( assetGeneration)) ;
	raw						   = replaced( std::move( raw), "2026-10-11T05:00:00Z", publication) ;
	raw						   = replaced( std::move( raw), "2026-10-25T05:00:00Z", expiry) ;
	std::string signedEnvelope = envelope( raw, key.sign( raw)) ;	// PSSは実RAM秘密鍵で行います。
	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{"fixture-main", key.publicBlob}}} ;	// Unit public materialだけです。
	auto result = signed_index_detail::authenticateWithTrustKeys(
		signedEnvelope, nowUtc, std::nullopt, trust) ;	// 製品と同じ実verifierです。
	// Fixture生成を検証済み入力と誤認しません。
	if( !result.manifest) {
		throw std::runtime_error( "store input manifest authentication failed") ;
	}

	return {std::move( *result.manifest), std::move( signedEnvelope), std::move( gzip)} ;
}

/** @brief 完全保存前receiptを実前段からだけ作ります。
 * @param[in] key RAM内署名鍵。
 * @param[in] generation Manifest世代。
 * @param[in] assetGeneration 原asset世代。
 * @param[in] nowUtc 現在の検査UTC。
 * @param[in] publication 署名発行UTC。
 * @param[in] expiry 署名期限UTC。
 * @param[in] padBytes 実圧縮上限を測るcontainer長。通常は0です。
 * @return 全前段が成功した人工入力とreceipt。
 */
[[nodiscard]] StoreFixture makeStoreFixture(
	const RamKey &key, const std::uint64_t generation = 7U,
	const std::uint64_t assetGeneration = 7U, const std::chrono::sys_seconds nowUtc = NOW,
	const std::string_view publication = "2026-10-11T05:00:00Z",
	const std::string_view expiry = "2026-10-25T05:00:00Z", const std::size_t padBytes = 0U)
{
	const auto index =
		replaced( distributionIndex( recordSource(), recordEntry( key, distributionRecord())),
				 "\"assetGeneration\":7",
				 "\"assetGeneration\":" +
					 // 架空recordの元観測は変えません。
					 std::to_string( assetGeneration)) ;
	auto inputs = makeStoreInputs( key, index, generation, assetGeneration, nowUtc, publication,
								  expiry, padBytes) ;	// 実署名です。
	auto bytes =
		// 実gzipの完全hashです。
		authenticateIndexAssetBytes( inputs.manifest, inputs.gzip, nowUtc) ;
	// 前段生成の障害をstoreの拒否成功へ変換しません。
	if( !bytes.receipt) {
		throw std::runtime_error( "store gzip fixture failed") ;
	}

	auto records = readSignedIndexRecords( *bytes.receipt, nowUtc) ;	// 実原recordとschemaです。
	// Schema生成に失敗した場合は試験自体を失敗させます。
	if( !records.receipt) {
		throw std::runtime_error( "store record fixture failed") ;
	}

	return {std::move( inputs), std::move( *records.receipt)} ;
}

/** @brief 保存結果の拒否とsnapshot不在を独立して確認します。
 * @param[in,out] context 共通集計先。
 * @param[in] result 実store結果。
 * @param[in] expected 期待拒否区分。
 * @param[in] commit 期待する実commit区分。
 */
void expectStoreRejected(
	TestContext &context, const IndexStoreResult &result, const IndexStoreStatus expected,
	const IndexStoreCommitDisposition commit = IndexStoreCommitDisposition::NO_CHANGE)
{
	// 拒否区分の不一致だけを非機密の数値診断で残します。
	if( result.status != expected) {
		std::cout << "Store rejection mismatch expected: " << static_cast<unsigned>( expected)
				  << ", actual: " << static_cast<unsigned>( result.status)
				  << ", error: " << static_cast<std::uint32_t>( result.error) << '\n' ;
	}

	DRIVERCRATE_EXPECT( context, result.status == expected) ;
	DRIVERCRATE_EXPECT( context, result.commit == commit) ;
	DRIVERCRATE_EXPECT( context, !result.snapshot) ;
}

/** @brief 実保存済みheadのreloadから世代を確認します。
 * @param[in,out] context 共通集計先。
 * @param[in,out] store 自作隔離store。
 * @param[in] generation 期待する世代。
 * @param[in] nowUtc 現在の信頼UTC。
 */
void expectStoredGeneration( TestContext &context, SignedIndexStore &store,
							const std::uint64_t			   generation,
							const std::chrono::sys_seconds nowUtc = NOW)
{
	const auto result = store.reload( nowUtc) ;	// 実diskの全原入力を再認証します。
	DRIVERCRATE_EXPECT( context,
					   result.status == IndexStoreStatus::SNAPSHOT_READY && result.snapshot) ;
	DRIVERCRATE_EXPECT( context, result.persistedGeneration == generation) ;
	DRIVERCRATE_EXPECT(
		context, result.snapshot &&
					 result.snapshot->schemaReceipt().assetBytes().manifest().data().generation ==
						 generation) ;
}

/** @brief Testの実file handleを例外時も閉じます。 */
class StoreTestFile final {
public:
	/** @brief APIが返したhandleを単独所有します。
	 * @param[in] handle API結果。
	 */
	explicit StoreTestFile( const HANDLE handle) : handle_( handle)
	{
		// 取得不能を空byteの試験成功へ変換しません。
		if( handle_ == INVALID_HANDLE_VALUE) {
			throw std::runtime_error( "isolated file API failed") ;
		}
	}
	/** @brief 所有handleを解放します。 */
	~StoreTestFile() noexcept
	{
		CloseHandle( handle_) ;
	}
	/** @brief 単独所有のcopyを禁止します。 */
	StoreTestFile( const StoreTestFile &) = delete ;
	/** @brief 単独所有の代入を禁止します。
	 * @return 呼出しは禁止されます。
	 */
	StoreTestFile		&operator=( const StoreTestFile &) = delete ;
	/** @brief I/O中だけ実handleを借用します。
	 * @return このownerの寿命まで有効なhandle。
	 */
	[[nodiscard]] HANDLE get() const noexcept
	{
		return handle_ ;
	}

private:
	/// Scopeへ単独所有した実file handle。
	HANDLE handle_ ;
} ;

/** @brief 改変試験だけで隔離fileの実byteを読みます。
 * @param[in] path Isolated capabilityから得たheadまたはstageのpath。
 * @return 完全な実disk byte。
 */
[[nodiscard]] std::vector<std::byte> readStoreTestFile( const std::filesystem::path &path)
{
	const StoreTestFile file{CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
										 OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT,
										 nullptr)} ;	// Test内の実ownerです。
	LARGE_INTEGER		size{} ;						// 同じfileの実長です。
	// Test helperも有限実長なしに確保しません。
	if( !GetFileSizeEx( file.get(), &size) || size.QuadPart <= 0 ||
	   size.QuadPart > 34LL * 1024LL * 1024LL) {
		throw std::runtime_error( "isolated read size failed") ;
	}

	std::vector<std::byte> bytes( static_cast<std::size_t>( size.QuadPart)) ;	// 有限な実byteです。
	DWORD				   count{} ;											// 実read長です。
	// 部分readをoriginal-byte比較へ使いません。
	if( !ReadFile( file.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &count, nullptr) ||
	   count != bytes.size()) {
		throw std::runtime_error( "isolated read failed") ;
	}

	return bytes ;
}

/** @brief 隔離した既存headだけを試験byteで上書きします。
 * @param[in] path Isolated capabilityから得た既存head path。
 * @param[in] bytes 34MiB以内の人工byte。
 */
void writeStoreTestFile( const std::filesystem::path &path, const std::span<const std::byte> bytes)
{
	const StoreTestFile file{CreateFileW( path.c_str(), GENERIC_WRITE, 0U, nullptr, OPEN_EXISTING,
										 FILE_FLAG_OPEN_REPARSE_POINT,
										 nullptr)} ;	// Testだけの同file書込みです。
	DWORD				count{} ;						// 実write長です。
	// Fixture上書きが不完全なら検査自体を失敗させます。
	if( bytes.size() > 34U * 1024U * 1024U ||
	   !WriteFile( file.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &count, nullptr) ||
	   count != bytes.size() || !SetEndOfFile( file.get()) || !FlushFileBuffers( file.get())) {
		throw std::runtime_error( "isolated write failed") ;
	}
}

/** @brief Testの独立wire整数をpaddingなしで追加します。
 * @param[in,out] bytes 人工wire。
 * @param[in] value 値。
 * @param[in] count 幅4または8byte。
 */
void appendStoreTestInteger( std::vector<std::byte> &bytes, const std::uint64_t value,
							const unsigned count)
{
	// 指定の有限byteだけをlittle-endianで書きます。
	for( unsigned index = 0U; index < count; ++index) {
		bytes.push_back( static_cast<std::byte>( (value >> (index * 8U)) & 255U)) ;
	}
}

/** @brief Test独立hashで改変wireの末尾digestを再計算します。
 * @param[in] key RAM helperの独立CNG hash。
 * @param[in,out] plain 最後の32byteがdigestの有限wire。
 */
void refreshStorePlainDigest( const RamKey &key, std::vector<std::byte> &plain)
{
	const auto hash = key.digest(
		// 製品wire codecを使いません。
		assetText( std::span{plain}.first( plain.size() - 32U))) ;
	std::memcpy( plain.data() + plain.size() - 32U, hash.data(), hash.size()) ;
}

/** @brief 不正schemaも実署名・DPAPIへ通せる有限wireをtest側で構成します。
 * @param[in] key RAM helperの独立hash。
 * @param[in] inputs 実署名された人工入力。
 * @param[in] index 元index byte。
 * @return 正しいplain digestを持つwire。Snapshot成功を注入しません。
 */
[[nodiscard]] std::vector<std::byte> makeStorePlain( const RamKey &key, const StoreInputs &inputs,
													const std::string_view index)
{
	const auto			  &data = inputs.manifest.data() ;	// 実署名に結合した値です。
	std::vector<std::byte> bytes ;							// 人工wireの所有byteです。
	// 固定magicだけを追加します。
	for( const char value : std::string_view{"DCIDXSTR01"}) {
		bytes.push_back( static_cast<std::byte>( value)) ;
	}

	appendStoreTestInteger( bytes, 1U, 4U) ;
	appendStoreTestInteger( bytes, 1U, 4U) ;
	appendStoreTestInteger( bytes, 1U, 4U) ;
	appendStoreTestInteger( bytes, data.generation, 8U) ;
	appendStoreTestInteger(
		bytes, static_cast<std::uint64_t>( data.publishedAtUtc.time_since_epoch().count()), 8U) ;
	appendStoreTestInteger( bytes, inputs.envelope.size(), 8U) ;
	appendStoreTestInteger( bytes, inputs.gzip.size(), 8U) ;
	// 独立原manifest／index hashを別fieldへ追加します。
	for( const auto &hash : {data.manifestSha256, key.digest( index)}) {
		// 固定32byteを原値どおり保存します。
		for( const auto value : hash) {
			bytes.push_back( static_cast<std::byte>( value)) ;
		}
	}

	// 原envelope byteを補正せず追加します。
	for( const char value : inputs.envelope) {
		bytes.push_back( static_cast<std::byte>( value)) ;
	}

	bytes.insert( bytes.end(), inputs.gzip.begin(), inputs.gzip.end()) ;
	bytes.resize( bytes.size() + 32U) ;
	refreshStorePlainDigest( key, bytes) ;
	return bytes ;
}

/** @brief Test側のOS descriptorを例外時も回収します。 */
struct StoreTestLocalCloser {
	/** @brief OSが割り当てたdescriptorを返します。
	 * @param[in] value LocalFree可能な領域。
	 */
	void operator()( void *value) const noexcept
	{
		LocalFree( value) ;
	}
} ;

/** @brief 隔離file／rootだけのDACLを広げ、原DACLへ戻すownerです。 */
class StoreTestDacl final {
public:
	/** @brief 元DACLを保持してEveryoneを許す不正profileを設定します。
	 * @param[in] path 自作isolated capabilityのfileまたはroot。
	 * @param[in] directory Directory handleを開く場合true。
	 */
	StoreTestDacl( const std::filesystem::path &path, const bool directory)
		: file_( CreateFileW( path.c_str(), READ_CONTROL | WRITE_DAC,
							FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
							FILE_FLAG_OPEN_REPARSE_POINT |
								(directory ? FILE_FLAG_BACKUP_SEMANTICS : 0U),
							nullptr))
	{
		PSECURITY_DESCRIPTOR raw{} ;	// OSが返す原descriptorです。
		const DWORD			 code =
			GetSecurityInfo( file_.get(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
							nullptr, nullptr, nullptr, &raw) ;	// 原保護を保存します。
		original_.reset( raw) ;
		// 元の保護を回収できなければDACLを変更しません。
		if( code != ERROR_SUCCESS) {
			throw std::runtime_error( "isolated original DACL failed") ;
		}

		PSECURITY_DESCRIPTOR wide{} ;	// 不正profileのOS descriptorです。
		// Test fixtureもOSの有効なdescriptorだけを使います。
		if( !ConvertStringSecurityDescriptorToSecurityDescriptorW( L"D:P(A;;FA;;;WD)",
																 SDDL_REVISION_1, &wide, nullptr)) {
			throw std::runtime_error( "isolated wide DACL failed") ;
		}

		const std::unique_ptr<void, StoreTestLocalCloser> owner{
			wide} ;			// 不正profileもscopeで返します。
		PACL acl{} ;		// OS descriptorへ借用するDACLです。
		BOOL present{} ;	// API返却の存在flagです。
		BOOL defaulted{} ;	// API返却のdefaulted flagです。
		// 実security変更が成立しなければ拒否試験自体を失敗させます。
		if( !GetSecurityDescriptorDacl( wide, &present, &acl, &defaulted) || !present ||
		   SetSecurityInfo( file_.get(), SE_FILE_OBJECT,
						   DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr,
						   nullptr, acl, nullptr) != ERROR_SUCCESS) {
			throw std::runtime_error( "isolated DACL write failed") ;
		}
	}
	/** @brief 例外時も自作rootの原DACLへの復帰を試みます。 */
	~StoreTestDacl() noexcept
	{
		static_cast<void>( restore()) ;
	}
	/** @brief 保護の二重復帰ownerを作りません。 */
	StoreTestDacl( const StoreTestDacl &) = delete ;
	/** @brief 復帰ownerの代入を禁止します。
	 * @return 呼出しは禁止されます。
	 */
	StoreTestDacl	   &operator=( const StoreTestDacl &) = delete ;
	/** @brief 同じ実handleで原DACLへ戻し、元API結果を報告します。
	 * @return 全復帰成功0、元のWin32 error。
	 */
	[[nodiscard]] DWORD restore() noexcept
	{
		PACL acl{} ;		// 保存descriptor内の原DACLです。
		BOOL present{} ;	// 有効DACLの存在flagです。
		BOOL defaulted{} ;	// API返却のdefaulted flagです。
		// 元descriptor不成立を成功へ変換しません。
		if( !GetSecurityDescriptorDacl( original_.get(), &present, &acl, &defaulted) || !present) {
			return ERROR_INVALID_DATA ;
		}

		return SetSecurityInfo( file_.get(), SE_FILE_OBJECT,
							   DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
							   nullptr, nullptr, acl, nullptr) ;
	}

private:
	/// DACL操作を同じfile／rootへ固定するowner。
	StoreTestFile								file_ ;
	/// 復帰のためにだけ所有する元OS descriptor。
	std::unique_ptr<void, StoreTestLocalCloser> original_ ;
} ;

/** @brief 自作のstage directoryへだけ実junctionを設定します。
 * @param[in] stage 自作isolated root内の空directory。
 * @param[in] target 同じisolated root。外部targetへ誘導しません。
 * @return 実FSCTL設定成功の場合true。権限の変更は行いません。
 */
[[nodiscard]] bool createStoreTestJunction( const std::filesystem::path &stage,
										   const std::filesystem::path &target)
{
	const StoreTestFile file{CreateFileW( stage.c_str(), GENERIC_WRITE, 0U, nullptr, OPEN_EXISTING,
										 FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
										 nullptr)} ;	// Reparse自身を開きます。
	const std::wstring	substitute =
		L"\\??\\" + target.native() ;				// Mount-point namespaceだけの内部targetです。
	const std::wstring print = target.native() ;	// 同じrootの表示nameです。
	const std::size_t  pathBytes =
		(substitute.size() + print.size() + 2U) * sizeof( wchar_t) ;	// 二つの終端を含む実byte数です。
	// USHORT fieldとOS reparse枠を超えるfixtureを作りません。
	if( pathBytes > 4096U) {
		throw std::runtime_error( "isolated junction size failed") ;
	}

	std::vector<std::byte> bytes ;	// PaddingなしのWin32 reparse inputです。
	appendStoreTestInteger( bytes, IO_REPARSE_TAG_MOUNT_POINT, 4U) ;
	appendStoreTestInteger( bytes, 8U + pathBytes, 2U) ;
	appendStoreTestInteger( bytes, 0U, 2U) ;
	appendStoreTestInteger( bytes, 0U, 2U) ;
	appendStoreTestInteger( bytes, substitute.size() * sizeof( wchar_t), 2U) ;
	appendStoreTestInteger( bytes, (substitute.size() + 1U) * sizeof( wchar_t), 2U) ;
	appendStoreTestInteger( bytes, print.size() * sizeof( wchar_t), 2U) ;
	// 有限二文字列をUTF-16 code unitの原値どおり追加します。
	for( const auto &text : {substitute, print}) {
		// Code unitごとにlittle-endianへ結合します。
		for( const wchar_t value : text) {
			appendStoreTestInteger( bytes, static_cast<std::uint16_t>( value), 2U) ;
		}

		appendStoreTestInteger( bytes, 0U, 2U) ;
	}

	DWORD returned{} ;	// 同期FSCTLの実返却byte数です。
	return DeviceIoControl( file.get(), FSCTL_SET_REPARSE_POINT, bytes.data(),
						   static_cast<DWORD>( bytes.size()), nullptr, 0U, &returned,
						   nullptr) != FALSE ;
}

} // namespace

/**
 * @copydoc drivercrate::test::runSignedIndexStoreTests
 */
void runSignedIndexStoreTests( TestContext &context)
{
	using signed_index_store_detail::Access ;
	using signed_index_store_detail::Fault ;
	static_assert( !std::is_default_constructible_v<AuthenticatedIndexSnapshot>) ;
	static_assert( !std::is_constructible_v<AuthenticatedIndexSnapshot, IndexRecordsSchemaReceipt,
										   std::string, std::vector<std::byte>>) ;
	static_assert( std::is_nothrow_move_constructible_v<AuthenticatedIndexSnapshot>) ;
	const int firstAssertion = context.assertionCount() ;	// この保存groupだけの実件数です。
	const int firstFailure	 = context.failureCount() ;		// この保存groupだけの失敗です。
	RamKey	  key ;											// 署名秘密鍵はRAMのCNG handleだけです。
	key.generate( 3072U) ;
	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{"fixture-main", key.publicBlob}}} ;			// 製品には配置しません。
	const auto first = makeStoreFixture( key) ;			// 世代7、原asset7、旧成功観測です。
	const auto newer = makeStoreFixture( key, 8U, 8U) ;	// Manifestと原assetを両方増やす正例です。
	const auto restored =
		// 新manifestだけが旧固定assetを参照します。
		makeStoreFixture( key, 9U, 7U) ;
	auto opened = Access::createIsolated( trust) ;	// 実保護temp rootとgenesisです。
	DRIVERCRATE_EXPECT( context, opened.error == 0 && opened.store) ;
	// 保護fixtureを用意できない場合は残りを空の成功にしません。
	if( !opened.store) {
		throw std::runtime_error( "isolated index store creation failed") ;
	}

	auto &store = *opened.store ;	// Fixture寿命に結合する実storeです。
	// 製品二ACEと隔離三ACEをRAM内で交差検査し、製品rootを作成しません。
	for( const bool directory : {false, true}) {
		const auto product = Access::protectionSddl( store, directory, true) ;	// 実製品生成規則です。
		const auto fixture =
			// 実隔離生成規則です。
			Access::protectionSddl( store, directory, false) ;
		DRIVERCRATE_EXPECT( context, Access::acceptsProtectionSddl( store, product, directory, true)) ;
		DRIVERCRATE_EXPECT( context,
						   Access::acceptsProtectionSddl( store, fixture, directory, false)) ;
		DRIVERCRATE_EXPECT( context,
						   !Access::acceptsProtectionSddl( store, fixture, directory, true)) ;
		DRIVERCRATE_EXPECT( context,
						   !Access::acceptsProtectionSddl( store, product, directory, false)) ;
		DRIVERCRATE_EXPECT( context,
						   !Access::acceptsProtectionSddl( store, product, !directory, true)) ;
		const auto userOwner = fixture.substr( 0U, fixture.find( L"D:")) +
							   // 二ACEでもuser ownerを拒否します。
							   product.substr( 4U) ;
		DRIVERCRATE_EXPECT( context,
						   !Access::acceptsProtectionSddl( store, userOwner, directory, true)) ;
		auto systemOwner = product ;	// SYSTEM ownerだけは製品既存profileとして認めます。
		systemOwner.replace( 0U, 4U, L"O:SY") ;
		DRIVERCRATE_EXPECT( context,
						   Access::acceptsProtectionSddl( store, systemOwner, directory, true)) ;
		auto unprotected = product ;	// 同principalでも継承停止欠損を拒否します。
		unprotected.replace( 4U, 3U, L"D:") ;
		DRIVERCRATE_EXPECT( context,
						   !Access::acceptsProtectionSddl( store, unprotected, directory, true)) ;
	}

	const auto root	 = Access::isolatedRoot( store) ;	// 任意pathを作る能力はありません。
	const auto head	 = root / L"head.bin" ;				// 実ciphertext比較対象です。
	const auto empty = store.reload( NOW) ;				// 実genesis headを再読取りします。
	DRIVERCRATE_EXPECT( context, empty.status == IndexStoreStatus::EMPTY_STORE &&
									empty.persistedGeneration == 0U && !empty.snapshot) ;
	const auto accepted = store.commit( first.receipt, first.inputs.envelope, first.inputs.gzip,
									   NOW) ;	// 実一head commitです。
	DRIVERCRATE_EXPECT( context, accepted.status == IndexStoreStatus::SNAPSHOT_READY &&
									accepted.snapshot &&
									accepted.commit == IndexStoreCommitDisposition::COMMITTED) ;
	DRIVERCRATE_EXPECT(
		context, accepted.snapshot &&
					 accepted.snapshot->originalEnvelope() == first.inputs.envelope &&
					 std::ranges::equal( accepted.snapshot->originalGzip(), first.inputs.gzip)) ;
	DRIVERCRATE_EXPECT( context, accepted.snapshot &&
									accepted.snapshot->storePolicyVersion() == 1U &&
									accepted.snapshot->schemaReceipt().indexSha256() ==
										first.receipt.indexSha256()) ;
	expectStoredGeneration( context, store, 7U) ;
	auto reopened = Access::reopenIsolated( store) ;	// 別に初期化した実handleで既存headを検証します。
	DRIVERCRATE_EXPECT( context, reopened.error == 0 && reopened.store) ;
	// 別ownerの再open不成立を試験成功へ読み替えません。
	if( !reopened.store) {
		throw std::runtime_error( "isolated index reopen failed") ;
	}

	expectStoredGeneration( context, *reopened.store, 7U) ;
	const auto original = readStoreTestFile( head) ;	// 初回成功後の実暗号byteです。
	const auto same		= store.commit( first.receipt, first.inputs.envelope, first.inputs.gzip,
									   NOW) ;	// 同世代同原manifestは再利用です。
	DRIVERCRATE_EXPECT( context, same.status == IndexStoreStatus::SNAPSHOT_READY &&
									same.commit == IndexStoreCommitDisposition::NO_CHANGE) ;
	DRIVERCRATE_EXPECT( context, original == readStoreTestFile( head)) ;
	const auto resigned = makeStoreFixture( key) ;	// 同じ原manifestへ別のPSS署名を生成します。
	const auto sameOriginal =
		store.commit( resigned.receipt, resigned.inputs.envelope, resigned.inputs.gzip,
					 NOW) ;	// 元manifest identityで再利用します。
	DRIVERCRATE_EXPECT( context,
					   sameOriginal.snapshot &&
						   sameOriginal.snapshot->originalEnvelope() == first.inputs.envelope) ;
	DRIVERCRATE_EXPECT( context, original == readStoreTestFile( head)) ;
	std::string conflictRaw =
		// 同意味でも異なる原byteです。
		first.inputs.manifest.data().manifestBytes + " " ;
	const auto conflictEnvelope =
		// 正しい実署名を付けます。
		envelope( conflictRaw, key.sign( conflictRaw)) ;
	auto conflictManifest = signed_index_detail::authenticateWithTrustKeys(
		conflictEnvelope, NOW, std::nullopt, trust) ;	// 保存前の世代scalarなしで作ります。
	auto conflictBytes = authenticateIndexAssetBytes( *conflictManifest.manifest, first.inputs.gzip,
													 NOW) ;	// 全asset byteは正当です。
	auto conflictRecords =
		// 全schemaも正当です。
		readSignedIndexRecords( *conflictBytes.receipt, NOW) ;
	const auto conflict = store.commit( *conflictRecords.receipt, conflictEnvelope,
									   first.inputs.gzip, NOW) ;	// 最新headで原byte差を拒否します。
	expectStoreRejected( context, conflict, IndexStoreStatus::MANIFEST_REJECTED) ;
	DRIVERCRATE_EXPECT( context,
					   conflict.manifestStatus == SignedIndexManifestStatus::GENERATION_CONFLICT &&
						   conflict.persistedGeneration == 7U) ;
	DRIVERCRATE_EXPECT( context, original == readStoreTestFile( head)) ;
	// 全commit前診断で旧headの実ciphertextとhighwaterを保持します。
	for( const Fault fault : {Fault::BEFORE_PROTECT, Fault::BEFORE_STAGE, Fault::PARTIAL_WRITE,
							 Fault::BEFORE_FLUSH, Fault::BEFORE_REPLACE}) {
		const auto failed =
			Access::commitWithFault( store, newer.receipt, newer.inputs.envelope, newer.inputs.gzip,
									NOW, fault) ;	// 同じ実I/O経路の拒否点です。
		expectStoreRejected( context, failed,
							fault == Fault::BEFORE_PROTECT ? IndexStoreStatus::PROTECTION_FAILURE
														   : IndexStoreStatus::IO_FAILURE) ;
		DRIVERCRATE_EXPECT( context, failed.persistedGeneration == 7U && failed.error != 0) ;
		DRIVERCRATE_EXPECT( context, original == readStoreTestFile( head)) ;
		expectStoredGeneration( context, store, 7U) ;
	}

	{
		const auto held = Access::holdLock( store) ;	// 実share0の競合writer能力です。
		DRIVERCRATE_EXPECT( context, static_cast<bool>( held)) ;
		expectStoreRejected(
			context,
			reopened.store->commit( newer.receipt, newer.inputs.envelope, newer.inputs.gzip, NOW),
			IndexStoreStatus::BUSY) ;
		expectStoreRejected( context, store.reload( NOW), IndexStoreStatus::BUSY) ;
	}
	{
		const StoreTestFile denyDelete{
			CreateFileW( head.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
						OPEN_EXISTING, 0U, nullptr)} ;	// 旧headのrenameを実OSで拒否します。
		const auto failedRename =
			store.commit( newer.receipt, newer.inputs.envelope, newer.inputs.gzip,
						 NOW) ;	// Flush後のMoveFileEx失敗です。
		expectStoreRejected( context, failedRename, IndexStoreStatus::COMMIT_UNCERTAIN,
							IndexStoreCommitDisposition::UNKNOWN) ;
		DRIVERCRATE_EXPECT( context, !failedRename.persistedGeneration && failedRename.error != 0) ;
	}
	expectStoredGeneration( context, store, 7U) ;
	DRIVERCRATE_EXPECT( context, original == readStoreTestFile( head)) ;
	const auto advanced =
		reopened.store->commit( newer.receipt, newer.inputs.envelope, newer.inputs.gzip,
							   NOW) ;	// 別ownerから先に世代8を確定します。
	DRIVERCRATE_EXPECT( context, advanced.snapshot &&
									advanced.commit == IndexStoreCommitDisposition::COMMITTED) ;
	const auto lower = store.commit( first.receipt, first.inputs.envelope, first.inputs.gzip,
									NOW) ;	// 古いreceiptは最新head再読取りで拒否します。
	expectStoreRejected( context, lower, IndexStoreStatus::MANIFEST_REJECTED) ;
	DRIVERCRATE_EXPECT( context,
					   lower.manifestStatus == SignedIndexManifestStatus::GENERATION_ROLLBACK &&
						   lower.persistedGeneration == 8U) ;
	const auto movedTarget		= first.receipt ;			// Copy後のmove元／先を独立検査します。
	auto	   movedSource		= movedTarget ;				// Storeへ渡す不完全化対象です。
	auto	   movedDestination = std::move( movedSource) ;	// 正当な原入力を所有します。
	expectStoreRejected( context,
						store.commit( movedSource, first.inputs.envelope, first.inputs.gzip, NOW),
						IndexStoreStatus::INVALID_INPUT) ;
	DRIVERCRATE_EXPECT( context, movedDestination.indexSha256() == first.receipt.indexSha256()) ;
	const auto restoredResult =
		store.commit( restored.receipt, restored.inputs.envelope, restored.inputs.gzip,
					 NOW) ;	// 新世代9が旧固定asset7を参照します。
	DRIVERCRATE_EXPECT( context,
					   restoredResult.snapshot && restoredResult.persistedGeneration == 9U) ;
	DRIVERCRATE_EXPECT( context, restoredResult.snapshot && restoredResult.snapshot->schemaReceipt()
																   .assetBytes()
																   .manifest()
																   .data()
																   .assetGeneration == 7U) ;
	DRIVERCRATE_EXPECT(
		context,
		restoredResult.snapshot &&
			restoredResult.snapshot->schemaReceipt().indexSha256() == first.receipt.indexSha256() &&
			std::ranges::equal( restoredResult.snapshot->originalGzip(), first.inputs.gzip)) ;
	DRIVERCRATE_EXPECT( context,
					   restoredResult.snapshot &&
						   restoredResult.snapshot->schemaReceipt()
								   .records()[0]
								   .lastSuccessfulObservationUtc.value ==
							   first.receipt.records()[0].lastSuccessfulObservationUtc.value) ;
	const auto stable = readStoreTestFile( head) ;	// 世代9の実保存byteです。
	expectStoreRejected( context,
						store.commit( restored.receipt, restored.inputs.envelope,
									 restored.inputs.gzip, std::nullopt),
						IndexStoreStatus::TIME_UNAVAILABLE) ;
	const auto clockMissing =
		// 履歴highwaterは回収するがservableにしません。
		store.reload( std::nullopt) ;
	expectStoreRejected( context, clockMissing, IndexStoreStatus::TIME_UNAVAILABLE) ;
	DRIVERCRATE_EXPECT( context, clockMissing.persistedGeneration == 9U) ;
	const auto future  = NOW + std::chrono::days{15} ;	// 旧headが明確に期限切れになる固定時刻です。
	const auto expired = store.reload( future) ;		// Historical署名は正常でも現在期限が不成立です。
	expectStoreRejected( context, expired, IndexStoreStatus::EXPIRED) ;
	DRIVERCRATE_EXPECT( context,
					   expired.persistedGeneration == 9U && stable == readStoreTestFile( head)) ;
	const auto early = store.reload( NOW - std::chrono::hours{2}) ;	// 発行前は候補へ渡しません。
	expectStoreRejected( context, early, IndexStoreStatus::NOT_YET_VALID) ;
	DRIVERCRATE_EXPECT( context, early.persistedGeneration == 9U) ;
	const auto fresh =
		makeStoreFixture( key, 10U, 10U, future, "2026-10-26T05:00:00Z",
						 "2026-11-01T05:00:00Z") ;	// 期限切れheadを新manifestだけで進めます。
	// 期限切れheadを最新の有効manifestで置換した実結果です。
	const auto freshResult =
		store.commit( fresh.receipt, fresh.inputs.envelope, fresh.inputs.gzip, future) ;
	DRIVERCRATE_EXPECT( context, freshResult.snapshot && freshResult.persistedGeneration == 10U) ;
	const auto freshLower =
		makeStoreFixture( key, 8U, 7U, future, "2026-10-26T05:00:00Z",
						 "2026-11-01T05:00:00Z") ;	// 有効期限だけ新しいrollbackです。
	// 時計が進んでもhighwaterを下げない実拒否結果です。
	const auto expiredRollback = store.commit( freshLower.receipt, freshLower.inputs.envelope,
											  freshLower.inputs.gzip, future) ;
	expectStoreRejected( context, expiredRollback, IndexStoreStatus::MANIFEST_REJECTED) ;
	DRIVERCRATE_EXPECT( context, expiredRollback.manifestStatus ==
										SignedIndexManifestStatus::GENERATION_ROLLBACK &&
									expiredRollback.persistedGeneration == 10U) ;
	// 各commit後診断はheadを実advanceし、snapshotだけを発行しません。
	for( const Fault fault :
		{Fault::AFTER_REPLACE, Fault::READBACK, Fault::AFTER_COMMIT_ALLOCATION}) {
		auto	   local = Access::createIsolated( trust) ;	// 各診断を独立した実diskで検査します。
		const auto saved = local.store->commit( first.receipt, first.inputs.envelope,
											   first.inputs.gzip, NOW) ;	// 旧成功stateです。
		DRIVERCRATE_EXPECT( context, saved.snapshot.has_value()) ;
		// Commit後の障害でもadvanceを維持する実結果です。
		const auto failed = Access::commitWithFault(
			*local.store, newer.receipt, newer.inputs.envelope, newer.inputs.gzip, NOW, fault) ;
		expectStoreRejected( context, failed, IndexStoreStatus::COMMITTED_NO_SNAPSHOT,
							IndexStoreCommitDisposition::COMMITTED) ;
		DRIVERCRATE_EXPECT( context, failed.persistedGeneration == 8U && failed.error != 0) ;
		expectStoredGeneration( context, *local.store, 8U) ;
		expectStoreRejected(
			context,
			local.store->commit( first.receipt, first.inputs.envelope, first.inputs.gzip, NOW),
			IndexStoreStatus::MANIFEST_REJECTED) ;
	}

	{
		auto	   local = Access::createIsolated( trust) ;	// 改変群だけの独立rootです。
		// 改変前に確定した実成功stateです。
		const auto saved =
			local.store->commit( first.receipt, first.inputs.envelope, first.inputs.gzip, NOW) ;
		DRIVERCRATE_EXPECT( context, saved.snapshot.has_value()) ;
		const auto localHead =
			// 改変は自作rootへ限定します。
			Access::isolatedRoot( *local.store) / L"head.bin" ;
		const auto originalCipher = readStoreTestFile( localHead) ;	// 元成功ciphertextです。
		std::vector<std::byte> plain ;								// 実DPAPIが返す所有plainです。
		DRIVERCRATE_EXPECT( context, Access::readPlain( *local.store, plain) == 0) ;
		const auto originalPlain = plain ;	// 元成功wireを保持します。
		// Plainの各独立境界を正しいDPAPI保護の内側で改変します。
		for( const std::size_t offset : {0U, 10U, 14U, 18U, 22U, 30U, 38U, 46U, 54U, 86U, 118U}) {
			plain = originalPlain ;
			plain[offset] ^= std::byte{1U} ;
			refreshStorePlainDigest( key, plain) ;
			DRIVERCRATE_EXPECT( context, Access::replacePlain( *local.store, plain) == 0) ;
			const auto rejected = local.store->reload( NOW) ;	// Wire／署名／世代等の実拒否です。
			expectStoreRejected( context, rejected, IndexStoreStatus::STATE_REJECTED) ;
			DRIVERCRATE_EXPECT( context, !rejected.persistedGeneration) ;
		}

		plain = originalPlain ;
		// 原gzip末尾を改変します。
		plain[plain.size() - 33U] ^= std::byte{1U} ;
		refreshStorePlainDigest( key, plain) ;
		DRIVERCRATE_EXPECT( context, Access::replacePlain( *local.store, plain) == 0) ;
		const auto badGzip = local.store->reload( NOW) ;	// DPAPIが正常でも原gzip hashで拒否します。
		expectStoreRejected( context, badGzip, IndexStoreStatus::STATE_REJECTED) ;
		DRIVERCRATE_EXPECT( context, badGzip.assetStatus == IndexAssetBytesStatus::HASH_MISMATCH) ;
		const auto badIndex = replaced(
			distributionIndex( recordSource(), recordEntry( key, distributionRecord())),
			"driver-index-records-v1", "invalid-records-schema") ;			// 正しい署名でも不正schemaです。
		const auto badInputs = makeStoreInputs( key, badIndex) ;			// 実署名と圧縮hashは成立します。
		const auto badPlain = makeStorePlain( key, badInputs, badIndex) ;	// Plain整合性も成立します。
		DRIVERCRATE_EXPECT( context, Access::replacePlain( *local.store, badPlain) == 0) ;
		const auto badRecords = local.store->reload( NOW) ;	// 最後のschema再認証で拒否します。
		expectStoreRejected( context, badRecords, IndexStoreStatus::STATE_REJECTED) ;
		DRIVERCRATE_EXPECT( context, badRecords.recordsStatus == IndexRecordsStatus::INVALID_INDEX) ;
		DRIVERCRATE_EXPECT( context, Access::replacePlain( *local.store, originalPlain) == 0) ;
		expectStoredGeneration( context, *local.store, 7U) ;
		const auto validCipher = readStoreTestFile( localHead) ;	// 実再保護後の正常byteです。
		auto	   corrupted   = validCipher ;						// DPAPI integrity自体の改変です。
		corrupted[corrupted.size() / 2U] ^= std::byte{1U} ;
		writeStoreTestFile( localHead, corrupted) ;
		const auto dpapiRejected = local.store->reload( NOW) ;	// 実DPAPIまたはplain検査での拒否です。
		DRIVERCRATE_EXPECT( context, (dpapiRejected.status == IndexStoreStatus::PROTECTION_FAILURE ||
									 dpapiRejected.status == IndexStoreStatus::STATE_REJECTED) &&
										!dpapiRejected.snapshot) ;
		DRIVERCRATE_EXPECT( context, !dpapiRejected.persistedGeneration) ;
		writeStoreTestFile( localHead, validCipher) ;
		auto other = Access::createIsolated( trust) ;	// 同じmachineでもroot identityが異なります。
		const auto otherHead =
			// 別の自作rootです。
			Access::isolatedRoot( *other.store) / L"head.bin" ;
		writeStoreTestFile( otherHead, validCipher) ;
		expectStoreRejected( context, other.store->reload( NOW),
							IndexStoreStatus::PROTECTION_FAILURE) ;
		std::vector<std::byte> oversized( 33U * 1024U * 1024U + 1U) ;	// 実disk上限の一byte超過です。
		writeStoreTestFile( localHead, oversized) ;
		expectStoreRejected( context, local.store->reload( NOW), IndexStoreStatus::STATE_REJECTED) ;
		writeStoreTestFile( localHead, originalCipher) ;
		expectStoredGeneration( context, *local.store, 7U) ;
		DRIVERCRATE_EXPECT( context, DeleteFileW( localHead.c_str()) !=
										FALSE) ;	// established headだけを意図的に欠損させます。
		expectStoreRejected( context, local.store->reload( NOW), IndexStoreStatus::STATE_REJECTED) ;
		expectStoreRejected(
			context,
			local.store->commit( newer.receipt, newer.inputs.envelope, newer.inputs.gzip, NOW),
			IndexStoreStatus::STATE_REJECTED) ;
		const auto missingReopen =
			// 初期化し直さないことを確認します。
			Access::reopenIsolated( *local.store) ;
		DRIVERCRATE_EXPECT( context, !missingReopen.store && missingReopen.error != 0) ;
		DRIVERCRATE_EXPECT( context, !std::filesystem::exists( localHead)) ;
	}
	{
		auto local = Access::createIsolated( trust) ;	// 属性・ACL・hard link検査用の実rootです。
		// 属性を変更する前に保存した実成功stateです。
		const auto saved =
			local.store->commit( first.receipt, first.inputs.envelope, first.inputs.gzip, NOW) ;
		DRIVERCRATE_EXPECT( context, saved.snapshot.has_value()) ;
		const auto localRoot = Access::isolatedRoot( *local.store) ;	// 自作rootだけへ限定します。
		const auto localHead = localRoot / L"head.bin" ;				// 単一linkを要求するfileです。
		const auto link		 = localRoot / L"extra-link.bin" ;			// 一時hard linkの明示名です。
		DRIVERCRATE_EXPECT( context,
						   CreateHardLinkW( link.c_str(), localHead.c_str(), nullptr) != FALSE) ;
		expectStoreRejected( context, local.store->reload( NOW),
							IndexStoreStatus::PROTECTION_FAILURE) ;
		DRIVERCRATE_EXPECT( context, DeleteFileW( link.c_str()) != FALSE) ;
		expectStoredGeneration( context, *local.store, 7U) ;
		{
			StoreTestDacl wide{localHead, false} ;	// 実headの不正Everyone allowを拒否します。
			expectStoreRejected( context, local.store->reload( NOW),
								IndexStoreStatus::PROTECTION_FAILURE) ;
			DRIVERCRATE_EXPECT( context, wide.restore() == ERROR_SUCCESS) ;
		}
		expectStoredGeneration( context, *local.store, 7U) ;
		{
			StoreTestDacl wide{localRoot, true} ;	// 実rootの不正ACLも再確認して拒否します。
			expectStoreRejected( context, local.store->reload( NOW),
								IndexStoreStatus::PROTECTION_FAILURE) ;
			DRIVERCRATE_EXPECT( context, wide.restore() == ERROR_SUCCESS) ;
		}
		expectStoredGeneration( context, *local.store, 7U) ;
		const auto stage = localRoot / L"head.stage" ;	// 部分stageはauthorityにしません。
		DRIVERCRATE_EXPECT( context, CreateDirectoryW( stage.c_str(), nullptr) != FALSE) ;
		expectStoreRejected(
			context,
			local.store->commit( newer.receipt, newer.inputs.envelope, newer.inputs.gzip, NOW),
			IndexStoreStatus::PROTECTION_FAILURE) ;
		DRIVERCRATE_EXPECT( context, RemoveDirectoryW( stage.c_str()) != FALSE) ;
		expectStoredGeneration( context, *local.store, 7U) ;
		DRIVERCRATE_EXPECT( context, CreateDirectoryW( stage.c_str(), nullptr) != FALSE) ;
		DRIVERCRATE_EXPECT( context, createStoreTestJunction( stage, localRoot)) ;
		expectStoreRejected(
			context,
			local.store->commit( newer.receipt, newer.inputs.envelope, newer.inputs.gzip, NOW),
			IndexStoreStatus::PROTECTION_FAILURE) ;
		DRIVERCRATE_EXPECT( context, RemoveDirectoryW( stage.c_str()) !=
										FALSE) ;	// Junction自身だけを外し、targetを削除しません。
		expectStoredGeneration( context, *local.store, 7U) ;
		const auto renamedRoot =
			localRoot.parent_path() /
			(localRoot.filename().native() + L"-renamed") ;	// 明示した自作rootのrename試験です。
		DRIVERCRATE_EXPECT( context,
						   MoveFileExW( localRoot.c_str(), renamedRoot.c_str(), 0U) == FALSE) ;
		DRIVERCRATE_EXPECT( context, std::filesystem::exists( localRoot) &&
										!std::filesystem::exists( renamedRoot)) ;
		const auto lockPath = localRoot / L"store.lock" ;	// 永続markerの欠損拒否です。
		DRIVERCRATE_EXPECT( context, DeleteFileW( lockPath.c_str()) != FALSE) ;
		expectStoreRejected( context, local.store->reload( NOW), IndexStoreStatus::STATE_REJECTED) ;
		expectStoreRejected(
			context,
			local.store->commit( newer.receipt, newer.inputs.envelope, newer.inputs.gzip, NOW),
			IndexStoreStatus::STATE_REJECTED) ;
	}
	{
		auto local = Access::createIsolated( {}) ;	// 製品と同じempty trustの別隔離stateです。
		expectStoreRejected(
			context,
			local.store->commit( first.receipt, first.inputs.envelope, first.inputs.gzip, NOW),
			IndexStoreStatus::MANIFEST_REJECTED) ;
		const auto stillEmpty = local.store->reload( NOW) ;	// Test鍵の自己信頼でgenesisを進めません。
		DRIVERCRATE_EXPECT( context, stillEmpty.status == IndexStoreStatus::EMPTY_STORE &&
										stillEmpty.persistedGeneration == 0U) ;
	}
	{
		const auto maximum =
			makeStoreFixture( key, 7U, 7U, NOW, "2026-10-11T05:00:00Z", "2026-10-25T05:00:00Z",
							 // 実32MiB gzip境界です。
							 static_cast<std::size_t>( INDEX_ASSET_MAX_BYTES)) ;
		auto	   local = Access::createIsolated( trust) ;	// 通常と同じ実policyで保存します。
		// 実上限gzipを一headへ保護保存した結果です。
		const auto saved =
			local.store->commit( maximum.receipt, maximum.inputs.envelope, maximum.inputs.gzip, NOW) ;
		DRIVERCRATE_EXPECT( context, saved.snapshot && saved.snapshot->originalGzip().size() ==
														  INDEX_ASSET_MAX_BYTES) ;
		const auto loaded = local.store->reload( NOW) ;	// 実上限原byteをDPAPIから再認証します。
		DRIVERCRATE_EXPECT( context,
						   loaded.snapshot && std::ranges::equal( loaded.snapshot->originalGzip(),
																 maximum.inputs.gzip)) ;
	}
	std::cout << "Signed index protected store assertions: "
			  << context.assertionCount() - firstAssertion
			  << ", failures: " << context.failureCount() - firstFailure << '\n' ;
	const int descriptorStoreStart	 = context.assertionCount() ;	// 旧store groupと別の有限集計。
	const int descriptorStoreFailure = context.failureCount() ;		// 新groupだけの失敗開始値。
	auto	  descriptorStore = Access::createIsolated( trust) ;	// 新たな自作隔離rootだけを使用する。
	// 隔離fixtureの生成失敗を再認証成功にしない。
	if( !descriptorStore.store) {
		throw std::runtime_error( "descriptor store fixture failed") ;
	}

	const std::string legacyIndex = distributionIndex(
		// 全14fieldの旧原asset。
		recordSource(), recordEntry( key, distributionRecord())) ;
	const auto legacyPlain =
		// 既存helperで旧head1を明示構成する。
		makeStorePlain( key, first.inputs, legacyIndex) ;
	DRIVERCRATE_EXPECT( context, legacyPlain.size() > 22U && legacyPlain[18U] == std::byte{1U} &&
									legacyPlain[19U] == std::byte{0U} &&
									legacyPlain[20U] == std::byte{0U} &&
									legacyPlain[21U] == std::byte{0U}) ;
	DRIVERCRATE_EXPECT( context, Access::replacePlain( *descriptorStore.store, legacyPlain) == 0) ;
	const auto legacyReload =
		// 実DPAPIから旧headの全原入力を現codecで再認証する。
		descriptorStore.store->reload( NOW) ;
	DRIVERCRATE_EXPECT(
		context,
		legacyReload.snapshot &&
			legacyReload.snapshot->schemaReceipt().schemaPolicyVersion() == 3U &&
			legacyReload.snapshot->schemaReceipt().records()[0].recordSchemaVersion == 1U &&
			!legacyReload.snapshot->schemaReceipt().records()[0].acquisitionDescriptor &&
			legacyReload.persistedGeneration == 7U) ;
	const std::string descriptorRaw =
		// 原byteを維持するv2 record。
		descriptorRecord( descriptorFixture()) ;
	const std::string descriptorAsset =
		// 別固定世代8のv2原byte。
		replaced( descriptorIndex( recordSource(), recordEntry( key, descriptorRaw)),
				 "\"assetGeneration\":7", "\"assetGeneration\":8") ;
	const auto descriptorInputs =
		// 新manifestと新固定assetへ結ぶ。
		makeStoreInputs( key, descriptorAsset, 8U, 8U) ;
	const auto descriptorBytes = authenticateIndexAssetBytes(
		descriptorInputs.manifest, descriptorInputs.gzip, NOW) ;	// 実GZipとhash検査。
	// 前段生成失敗は取得codecの拒否成功にしない。
	if( !descriptorBytes.receipt) {
		throw std::runtime_error( "descriptor store byte fixture rejected") ;
	}

	const auto descriptorRecords =
		// 型付き元申告の全検査。
		readSignedIndexRecords( *descriptorBytes.receipt, NOW) ;
	// Schema fixtureの不成立では保存を開始しない。
	if( !descriptorRecords.receipt) {
		throw std::runtime_error( "descriptor store record fixture rejected") ;
	}

	const auto descriptorSaved = descriptorStore.store->commit(
		*descriptorRecords.receipt, descriptorInputs.envelope, descriptorInputs.gzip,
		NOW) ;	// 実一head transactionを再利用する。
	DRIVERCRATE_EXPECT( context,
					   descriptorSaved.snapshot && descriptorSaved.persistedGeneration == 8U) ;
	std::vector<std::byte> descriptorPlain ;	// 実headの保存wire互換値だけを検査する有限所有byte。
	DRIVERCRATE_EXPECT( context, Access::readPlain( *descriptorStore.store, descriptorPlain) == 0 &&
									descriptorPlain.size() > 22U &&
									descriptorPlain[18U] == std::byte{1U}) ;
	const auto descriptorReload =
		// 保存した原byteからv2を実再認証する。
		descriptorStore.store->reload( NOW) ;
	DRIVERCRATE_EXPECT(
		context,
		descriptorReload.snapshot &&
			descriptorReload.snapshot->schemaReceipt().schemaPolicyVersion() == 3U &&
			descriptorReload.snapshot->schemaReceipt().records()[0].recordSchemaVersion == 2U &&
			descriptorReload.snapshot->schemaReceipt().records()[0].originalBytes ==
				descriptorRaw &&
			descriptorReload.snapshot->schemaReceipt().records()[0].acquisitionDescriptor &&
			descriptorReload.snapshot->originalEnvelope() == descriptorInputs.envelope) ;
	expectStoreRejected(
		context,
		descriptorStore.store->commit( first.receipt, first.inputs.envelope, first.inputs.gzip, NOW),
		IndexStoreStatus::MANIFEST_REJECTED) ;
	std::cout << "Signed index descriptor store assertions: "
			  << context.assertionCount() - descriptorStoreStart
			  << ", failures: " << context.failureCount() - descriptorStoreFailure << '\n' ;
}

namespace {

/** @brief 固定domain名だけを借りた人工RAM署名の完全fixtureを作ります。
 * @param[in] key 永続化しないRAM署名鍵です。
 * @param[in] local 検証用IDへ署名する場合trueです。
 * @param[in] generation Manifest世代です。
 * @param[in] assetGeneration 原asset世代です。
 * @return 架空の署名/byte/schema receiptです。製品鍵の署名ではありません。
 */
[[nodiscard]] StoreFixture makeDomainStoreFixture( const RamKey &key, const bool local,
												  const std::uint64_t generation	  = 7U,
												  const std::uint64_t assetGeneration = 7U)
{
	auto	   first = makeStoreFixture( key, generation, assetGeneration) ;	// 元の全schema正例です。
	const auto id	 = local ? index_legacy_migration_trust::KEY_ID
							 : index_distribution_trust::KEY_ID ;	// 実署名後の分類を検査します。
	const auto raw	 = replaced( first.inputs.manifest.data().manifestBytes, "fixture-main",
								id) ;						// 原manifestだけを人工再署名します。
	auto	   outer = envelope( raw, key.sign( raw), id) ;	// 署名materialは人工RAM鍵です。
	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{id, key.publicBlob}}} ;	// 実製品の固定鍵を置換しません。
	auto manifest = signed_index_detail::authenticateWithTrustKeys( outer, NOW, std::nullopt,
																   trust) ;	// 実CNG認証です。
	// 人工fixtureの不成立を移行拒否の成功にしません。
	if( !manifest.manifest) {
		throw std::runtime_error( "domain manifest fixture failed") ;
	}

	auto asset = authenticateIndexAssetBytes( *manifest.manifest, first.inputs.gzip,
											 NOW) ;	// 原gzipを検証します。
	// 前段が不成立の場合は残りのtestへ進みません。
	if( !asset.receipt) {
		throw std::runtime_error( "domain asset fixture failed") ;
	}

	auto records = readSignedIndexRecords( *asset.receipt, NOW) ;	// 原全schemaを検証します。
	// Schema拒否を移動成功へ換算しません。
	if( !records.receipt) {
		throw std::runtime_error( "domain records fixture failed") ;
	}

	return {{std::move( *manifest.manifest), std::move( outer), std::move( first.inputs.gzip)},
			std::move( *records.receipt)} ;
}

} // namespace

/** @see signed_index_manifest_tests.h */
void runSignedIndexStoreMigrationTests( TestContext &context)
{
	using signed_index_store_detail::Access ;
	using signed_index_store_detail::Fault ;
	const int initialAssertions = context.assertionCount() ;	// 新しい固定groupの分母だけです。
	const int initialFailures	= context.failureCount() ;		// 元groupの失敗を分離します。
	RamKey	  key ;												// 実署名秘密鍵はRAMだけです。
	key.generate( 3072U) ;
	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{"fixture-main", key.publicBlob}}} ;					// 人工公開鍵だけです。
	const auto first	  = makeStoreFixture( key) ;			// 署名世代7の全schema正例です。
	const auto lower	  = makeStoreFixture( key, 6U, 6U) ;	// 同domain rollbackを確認します。
	const auto conflict	  = makeStoreFixture( key, 7U, 6U) ;	// 同世代異manifestの正しい署名です。
	const auto expiredNow = NOW + std::chrono::days{15} ;		// 現在snapshotを許可しない履歴移動です。
	// 同じ実renameの前後中断を独立rootで確認し、原失敗を成功へ変更しません。
	for( const Fault fault : {Fault::NONE, Fault::BEFORE_REPLACE, Fault::AFTER_REPLACE}) {
		auto opened = Access::createIsolated( trust, true) ;	// DELETE権限付き自作rootだけです。
		DRIVERCRATE_EXPECT( context, opened.store && opened.error == 0) ;
		// Fixture生成不能では残りの検査を空成功にしません。
		if( !opened.store) {
			throw std::runtime_error( "migration store creation failed") ;
		}

		auto &store = *opened.store ;	// このloopだけが所有します。
		DRIVERCRATE_EXPECT(
			context, store.commit( first.receipt, first.inputs.envelope, first.inputs.gzip, NOW)
						 .snapshot.has_value()) ;
		const auto source = Access::isolatedRoot( store) ;					// 明示自作rootだけの旧名です。
		const auto head	  = readStoreTestFile( source / L"head.bin") ;		// 旧暗号byteです。
		const auto lock	  = readStoreTestFile( source / L"store.lock") ;	// 固定lock本文も保全します。
		const auto pin	  = recordDigest( key, assetText( head)) ;			// 原ciphertextの完全pinです。
		const auto result = Access::migrateIsolated( store, pin, expiredNow,
													fault) ;	// 製品と同じhistory/renameです。
		std::cout << "Migration fault=" << static_cast<unsigned>( fault)
				  << " error=" << static_cast<std::uint32_t>( result.error)
				  << " commit=" << static_cast<unsigned>( result.commit) << '\n' ;
		// Commit前中断は旧名を保持し、同条件の通常retryとは区別します。
		if( fault == Fault::BEFORE_REPLACE) {
			DRIVERCRATE_EXPECT( context,
							   result.error != 0 &&
								   result.commit == IndexStoreCommitDisposition::NO_CHANGE) ;
			DRIVERCRATE_EXPECT( context, Access::isolatedRoot( store) == source &&
											std::filesystem::exists( source)) ;
			const auto resumed =
				// 中断点を除いた明示再開です。
				Access::migrateIsolated( store, pin, expiredNow) ;
			DRIVERCRATE_EXPECT( context,
							   resumed.error == 0 &&
								   resumed.commit == IndexStoreCommitDisposition::COMMITTED) ;
		} else {
			DRIVERCRATE_EXPECT( context, result.commit == IndexStoreCommitDisposition::COMMITTED &&
											result.generation == 7U) ;
			DRIVERCRATE_EXPECT( context, (result.error == 0) == (fault == Fault::NONE)) ;
		}

		const auto destination = Access::isolatedRoot( store) ;	// identityを保った新名です。
		DRIVERCRATE_EXPECT( context, destination != source && !std::filesystem::exists( source)) ;
		DRIVERCRATE_EXPECT( context, readStoreTestFile( destination / L"head.bin") == head &&
										readStoreTestFile( destination / L"store.lock") == lock) ;
		const auto replay =
			// 同pin/全認証の再実行だけです。
			Access::migrateIsolated( store, pin, expiredNow) ;
		DRIVERCRATE_EXPECT( context, replay.error == 0 && replay.alreadyMigrated &&
										replay.commit == IndexStoreCommitDisposition::NO_CHANGE &&
										replay.generation == 7U) ;
		const auto expired = store.reload( expiredNow) ;	// 歴史移動で現在期限を延長しません。
		DRIVERCRATE_EXPECT( context, expired.status == IndexStoreStatus::EXPIRED &&
										expired.persistedGeneration == 7U && !expired.snapshot) ;
		const auto rollback = store.commit( lower.receipt, lower.inputs.envelope, lower.inputs.gzip,
										   NOW) ;	// 旧floorを保持します。
		DRIVERCRATE_EXPECT( context, rollback.manifestStatus ==
											SignedIndexManifestStatus::GENERATION_ROLLBACK &&
										rollback.persistedGeneration == 7U) ;
		const auto sameGeneration =
			store.commit( conflict.receipt, conflict.inputs.envelope, conflict.inputs.gzip,
						 NOW) ;	// 異内容の上書きを拒否します。
		DRIVERCRATE_EXPECT( context, sameGeneration.manifestStatus ==
											SignedIndexManifestStatus::GENERATION_CONFLICT &&
										sameGeneration.persistedGeneration == 7U) ;
	}

	auto opened = Access::createIsolated( trust, true) ;	// 拒否群だけの自作rootです。
	// 準備の失敗では移行拒否の検査へ進みません。
	if( !opened.store) {
		throw std::runtime_error( "migration rejection store failed") ;
	}

	auto &store = *opened.store ;	// 元ciphertextを保持して拒否を検査します。
	DRIVERCRATE_EXPECT( context,
					   store.commit( first.receipt, first.inputs.envelope, first.inputs.gzip, NOW)
						   .snapshot.has_value()) ;
	const auto source	= Access::isolatedRoot( store) ;				// 製品rootではありません。
	const auto headPath = source / L"head.bin" ;						// 自作fixtureだけを書換えます。
	const auto original = readStoreTestFile( headPath) ;				// 全拒否で保全を比較します。
	const auto pin		= recordDigest( key, assetText( original)) ;	// 正しい原head pinです。
	DRIVERCRATE_EXPECT( context,
					   Access::migrateIsolated( store, std::string( 64U, '0'), NOW).error != 0) ;
	DRIVERCRATE_EXPECT( context, Access::migrateIsolated( store, pin, std::nullopt).error != 0) ;
	DRIVERCRATE_EXPECT( context,
					   Access::migrateIsolated( store, pin, NOW - std::chrono::hours{2}).error != 0) ;
	{
		const auto held = Access::holdLock( store) ;	// 実share0競合を再現します。
		DRIVERCRATE_EXPECT( context, static_cast<bool>( held)) ;
		const auto busy = Access::migrateIsolated( store, pin, NOW) ;	// 待機/強制奪取しません。
		DRIVERCRATE_EXPECT( context, busy.error == ERROR_SHARING_VIOLATION &&
										busy.commit == IndexStoreCommitDisposition::NO_CHANGE) ;
	}

	const auto destination =
		// 固定suffixだけです。
		source.parent_path() / (source.filename().native() + L"-migrated") ;
	DRIVERCRATE_EXPECT( context, CreateDirectoryW( destination.c_str(), nullptr) != FALSE) ;
	const auto existing = Access::migrateIsolated( store, pin, NOW) ;	// 空の既存先も上書きしません。
	DRIVERCRATE_EXPECT( context, existing.error == ERROR_ALREADY_EXISTS &&
									existing.commit == IndexStoreCommitDisposition::NO_CHANGE) ;
	DRIVERCRATE_EXPECT( context, RemoveDirectoryW( destination.c_str()) != FALSE) ;
	DRIVERCRATE_EXPECT( context, readStoreTestFile( headPath) == original) ;
	std::vector<std::byte> plain ;	// 人工wireだけをRAMへ保持します。
	DRIVERCRATE_EXPECT( context, Access::readPlain( store, plain) == 0) ;
	const auto originalPlain = plain ;	// 復旧用の自作fixture原wireです。
	const auto position =
		// 外側keyIdの未知鍵拒否を再現します。
		assetText( plain).find( "fixture-main") ;
	DRIVERCRATE_EXPECT( context, position != std::string::npos) ;
	// 同長の未知IDへ変更し、DPAPI/digest整合だけでは信頼しないことを確認します。
	if( position != std::string::npos) {
		plain[position] = std::byte{'u'} ;
		refreshStorePlainDigest( key, plain) ;
		DRIVERCRATE_EXPECT( context, Access::replacePlain( store, plain) == 0) ;
		const auto unknownHead = readStoreTestFile( headPath) ;	// 正しいDPAPIに包まれた未知鍵です。
		const auto unknown	   = Access::migrateIsolated(
			store, recordDigest( key, assetText( unknownHead)), NOW) ;	// 申告keyIdを信用しません。
		DRIVERCRATE_EXPECT( context, unknown.error != 0 && !unknown.generation &&
										unknown.commit == IndexStoreCommitDisposition::NO_CHANGE) ;
	}

	plain = originalPlain ;
	plain[0] ^= std::byte{1U} ;
	refreshStorePlainDigest( key, plain) ;
	DRIVERCRATE_EXPECT( context, Access::replacePlain( store, plain) == 0) ;
	const auto malformedHead = readStoreTestFile( headPath) ;	// strict wire破損の独立ケースです。
	DRIVERCRATE_EXPECT(
		context,
		Access::migrateIsolated( store, recordDigest( key, assetText( malformedHead)), NOW).error !=
			0) ;
	writeStoreTestFile( headPath, original) ;
	auto other = Access::createIsolated( trust) ;	// 別root identityへ暗号byteをcopyします。
	// 正常な別domainで同じ番号を独立受理できることも確認します。
	if( !other.store) {
		throw std::runtime_error( "independent domain fixture failed") ;
	}

	DRIVERCRATE_EXPECT(
		context,
		other.store->commit( conflict.receipt, conflict.inputs.envelope, conflict.inputs.gzip, NOW)
			.snapshot.has_value()) ;
	const auto foreignHead = readStoreTestFile( Access::isolatedRoot( *other.store) /
											   L"head.bin") ;	// 他rootの正規暗号です。
	writeStoreTestFile( headPath, foreignHead) ;
	const auto binding = Access::migrateIsolated( store, recordDigest( key, assetText( foreignHead)),
												 NOW) ;	// hash一致でもroot binding不成立です。
	DRIVERCRATE_EXPECT( context, binding.error != 0 && !binding.generation &&
									binding.commit == IndexStoreCommitDisposition::NO_CHANGE) ;
	writeStoreTestFile( headPath, original) ;
	DRIVERCRATE_EXPECT( context, Access::isolatedRoot( store) == source &&
									readStoreTestFile( headPath) == original) ;
	const auto legacyPublic = std::string_view{
		reinterpret_cast<const char *>( index_legacy_migration_trust::PUBLIC_BLOB.data()),
		index_legacy_migration_trust::PUBLIC_BLOB
			.size()} ;	// 固定非秘密blobだけを独立hashへ渡します。
	DRIVERCRATE_EXPECT( context, recordDigest( key, legacyPublic) ==
									index_legacy_migration_trust::PUBLIC_FINGERPRINT) ;
	// 同じ製品namespace実装でlocal/productionの分類とsource absent再実行を確認します。
	for( const bool local : {false, true}) {
		using signed_index_store_detail::NamespaceLeaf ;
		auto parent = Access::createIsolated( {}) ;	// 固定三leafを隔離する自作sandboxです。
		const std::array<signed_index_detail::TrustKey, 2U> domainTrust{
			{{index_distribution_trust::KEY_ID, key.publicBlob},
			 {index_legacy_migration_trust::KEY_ID, key.publicBlob}}} ;	// 人工RAM鍵だけです。
		const std::array<signed_index_detail::TrustKey, 1U> productionTrust{
			{{index_distribution_trust::KEY_ID, key.publicBlob}}} ;	// 通常側はlocal鍵を持ちません。
		// Sandbox作成不能を空成功へ補完しません。
		if( !parent.store) {
			throw std::runtime_error( "migration namespace parent failed") ;
		}

		auto	   legacy  = Access::openNamespaceIsolated( *parent.store, NamespaceLeaf::LEGACY,
														   domainTrust) ;	// 固定旧名だけを作ります。
		const auto fixture = makeDomainStoreFixture( key, local) ;			// 型名でなく真署名IDで分類します。
		// 旧rootを用意できない場合は残りのtestへ進みません。
		if( !legacy.store) {
			throw std::runtime_error( "legacy namespace creation failed") ;
		}

		DRIVERCRATE_EXPECT(
			context,
			legacy.store->commit( fixture.receipt, fixture.inputs.envelope, fixture.inputs.gzip, NOW)
				.snapshot.has_value()) ;
		const auto oldPath =
			// 後で消失と原byte保全を確認します。
			Access::isolatedRoot( *legacy.store) ;
		const auto oldHead = readStoreTestFile( oldPath / L"head.bin") ;	// 復号plainを保存しません。
		const auto oldPin  = recordDigest( key, assetText( oldHead)) ;		// 事前確認した完全pinです。
		DRIVERCRATE_EXPECT( context, Access::openNamespaceIsolated(
										*parent.store, NamespaceLeaf::DISTRIBUTION, productionTrust)
											.error == ERROR_REVISION_MISMATCH) ;
		{
			auto competing =
				// 旧binary同等のroot ownerです。
				Access::reopenIsolated( *legacy.store) ;
			DRIVERCRATE_EXPECT( context, competing.store != nullptr) ;
			const auto busy = Access::migrateNamespaceIsolated(
				*legacy.store, oldPin, expiredNow) ;	// DELETE非共有root競合を拒否します。
			DRIVERCRATE_EXPECT( context, busy.error == ERROR_SHARING_VIOLATION &&
											busy.commit == IndexStoreCommitDisposition::NO_CHANGE) ;
		}

		const auto migrated = Access::migrateNamespaceIsolated(
			*legacy.store, oldPin, expiredNow) ;	// 本番と同じ分類/renameです。
		DRIVERCRATE_EXPECT( context, migrated.error == 0 && migrated.localDomain == local &&
										migrated.generation == 7U &&
										migrated.commit == IndexStoreCommitDisposition::COMMITTED) ;
		const auto newPath = Access::isolatedRoot( *legacy.store) ;	// 実署名IDから選んだ移動先です。
		DRIVERCRATE_EXPECT( context, !std::filesystem::exists( oldPath) &&
										readStoreTestFile( newPath / L"head.bin") == oldHead) ;
		const auto expectedName =
			local
				? L"SignedIndex-local-68ab95e96e45db00c62a241d733d29a2e347ef074949aec01293ed2ab024f18d-v1"
				: L"SignedIndex-distribution-v1" ;	// 完全fingerprintを省略しません。
		DRIVERCRATE_EXPECT( context, newPath.filename() == expectedName) ;
		auto production = Access::openNamespaceIsolated(
			*parent.store, NamespaceLeaf::DISTRIBUTION,
			productionTrust) ;	// 旧productionは同floor、旧localとは独立です。
		// 通常domainを開けなければ後続の結果を成功にしません。
		if( !production.store) {
			throw std::runtime_error( "production namespace failed") ;
		}

		// 別domainの正しいgenesisを移行証拠へ昇格せず、local保全headだけを確認します。
		if( local) {
			const auto withGenesis = Access::migrateNamespaceIsolated(
				*legacy.store, oldPin, expiredNow) ;	// source absentの途中再開です。
			DRIVERCRATE_EXPECT( context, withGenesis.error == 0 && withGenesis.alreadyMigrated &&
											withGenesis.localDomain) ;
		}

		const auto productionFixture =
			// localと同番号でも別署名domainです。
			makeDomainStoreFixture( key, false) ;
		DRIVERCRATE_EXPECT( context, production.store
										->commit( productionFixture.receipt,
												 productionFixture.inputs.envelope,
												 productionFixture.inputs.gzip, NOW)
										.snapshot.has_value()) ;
		const auto localFixture	 = makeDomainStoreFixture( key, true) ;	// 通常trustへ混入しません。
		const auto localRejected = production.store->commit(
			localFixture.receipt, localFixture.inputs.envelope, localFixture.inputs.gzip,
			NOW) ;	// 移行用鍵は通常trustへ登録しません。
		DRIVERCRATE_EXPECT( context,
						   !localRejected.snapshot && localRejected.manifestStatus ==
														  SignedIndexManifestStatus::UNKNOWN_KEY) ;
		// 実通常profileも移行用公開pinをmanifest trustへ加えていません。
		if( !local_index_profile::ENABLED) {
			DRIVERCRATE_EXPECT( context, authenticateSignedIndexManifest(
											localFixture.inputs.envelope, NOW, std::nullopt)
												.status == SignedIndexManifestStatus::UNKNOWN_KEY) ;
		}

		const auto lowerProduction =
			// 移動後の旧production floorを検査します。
			makeDomainStoreFixture( key, false, 6U, 6U) ;
		DRIVERCRATE_EXPECT(
			context, production.store
							 ->commit( lowerProduction.receipt, lowerProduction.inputs.envelope,
									  lowerProduction.inputs.gzip, NOW)
							 .manifestStatus == SignedIndexManifestStatus::GENERATION_ROLLBACK) ;
		const auto conflictingProduction =
			// 同番号異内容を維持します。
			makeDomainStoreFixture( key, false, 7U, 6U) ;
		DRIVERCRATE_EXPECT( context, production.store
											->commit( conflictingProduction.receipt,
													 conflictingProduction.inputs.envelope,
													 conflictingProduction.inputs.gzip, NOW)
											.manifestStatus ==
										SignedIndexManifestStatus::GENERATION_CONFLICT) ;
		const auto replay = Access::migrateNamespaceIsolated(
			*legacy.store, oldPin, expiredNow) ;	// 元root absent経路を実行します。
		DRIVERCRATE_EXPECT( context, replay.error == 0 && replay.alreadyMigrated &&
										replay.localDomain == local && replay.generation == 7U) ;
		DRIVERCRATE_EXPECT( context, Access::migrateNamespaceIsolated(
										*legacy.store, std::string( 64U, '0'), expiredNow)
											.error != 0) ;
		// 別domainが壊れていれば、正しいlocal headがあっても再実行成功にしません。
		if( local) {
			const auto productionHead =
				// 自作通常domainだけです。
				Access::isolatedRoot( *production.store) / L"head.bin" ;
			const auto stableProduction =
				// 原ciphertextをRAMだけへ保持します。
				readStoreTestFile( productionHead) ;
			auto broken = stableProduction ;	// DPAPI拒否を別に再現します。
			broken[0] ^= std::byte{1U} ;
			writeStoreTestFile( productionHead, broken) ;
			const auto corruptReplay = Access::migrateNamespaceIsolated(
				*legacy.store, oldPin, expiredNow) ;	// 不完全な他domainを無視しません。
			DRIVERCRATE_EXPECT( context,
							   corruptReplay.error != 0 && !corruptReplay.alreadyMigrated &&
								   corruptReplay.commit == IndexStoreCommitDisposition::NO_CHANGE) ;
			writeStoreTestFile( productionHead, stableProduction) ;
		}

		{
			auto recreated =
				Access::openNamespaceIsolated( *parent.store, NamespaceLeaf::LEGACY,
											  domainTrust) ;	// 旧binary再出現を人工再現します。
			// 新旧両方の存在を空のfixtureで省略しません。
			if( !recreated.store) {
				throw std::runtime_error( "recreated legacy namespace failed") ;
			}

			DRIVERCRATE_EXPECT( context, recreated.store
											->commit( fixture.receipt, fixture.inputs.envelope,
													 fixture.inputs.gzip, NOW)
											.snapshot.has_value()) ;
			const auto recreatedHead =
				readStoreTestFile( Access::isolatedRoot( *recreated.store) /
								  L"head.bin") ;	// 新しい原ciphertext pinです。
			const auto rejected = Access::migrateNamespaceIsolated(
				*recreated.store, recordDigest( key, assetText( recreatedHead)),
				expiredNow) ;	// 既存先をmergeしません。
			DRIVERCRATE_EXPECT( context,
							   rejected.error == ERROR_ALREADY_EXISTS &&
								   rejected.commit == IndexStoreCommitDisposition::NO_CHANGE) ;
			DRIVERCRATE_EXPECT( context,
							   production.store->reload( NOW).error == ERROR_REVISION_MISMATCH) ;
			DRIVERCRATE_EXPECT( context, readStoreTestFile( newPath / L"head.bin") == oldHead) ;
		}
	}

	std::cout << "Signed index store migration assertions: "
			  << context.assertionCount() - initialAssertions
			  << ", failures: " << context.failureCount() - initialFailures << '\n' ;
}

namespace {

/**
 * @brief 文法上有効なINF・SYS・未署名CATの非空ZIPをRAMだけで作ります。
 * @return Minizが生成した有限原byte。CAT拒否を正常署名へ変更しません。
 * @param[in] network trueではNetwork class、falseでは元fixtureの通常classを使う。
 */
std::string normalWorkerDriverZip( const bool network = false)
{
	std::string inf =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=Ports\r\n"
		"ClassGuid={4d36e978-e325-11ce-bfc1-08002be10318}\r\nProvider=%Vendor%\r\n"
		"DriverVer=10/11/2026,1.0.0.0\r\nCatalogFile=fixture.cat\r\n"
		"[Manufacturer]\r\n%Vendor%=Models,NTamd64\r\n[Models.NTamd64]\r\n"
		"%Device%=Install,TESTBUS\\SYNTH_0001\r\n[Install]\r\nCopyFiles=Files\r\n"
		"[Files]\r\nfixture.sys\r\n[DestinationDirs]\r\nFiles=12\r\n"
		"[SourceDisksNames]\r\n1=\"fixture\"\r\n[SourceDisksFiles]\r\nfixture.sys=1\r\n"
		"[Strings]\r\nVendor=\"Fixture Vendor\"\r\nDevice=\"Fixture Device\"\r\n" ;	// 架空IDだけです。
	mz_zip_archive archive{} ;														// MinizのRAM writer。全経路でendします。
	// Writerの初期化不成立は試験材料の生成失敗です。
	// 一般Netも同じ静的基本INF policyへ渡します。
	if( network) {
		inf = replaced( std::move( inf), "Class=Ports", "Class=Net") ;
		inf = replaced( std::move( inf), "4d36e978", "4d36e972") ;
	}

	// ZIP生成開始失敗を非空正常fixtureへ換算しません。
	if( !mz_zip_writer_init_heap( &archive, 0U, 0U)) {
		throw std::runtime_error( "worker ZIP initialization failed") ;
	}

	const std::string sys =
		"fictional nonexecuting system driver bytes" ;				// 実driver binaryではありません。
	const std::string cat = "fictional unsigned catalog bytes" ;	// Windows署名合格を偽装しません。
	// 三つの原memberを全て追加できた場合だけ非空ZIPを完成させます。
	if( !mz_zip_writer_add_mem( &archive, "fixture.inf", inf.data(), inf.size(), MZ_NO_COMPRESSION) ||
	   !mz_zip_writer_add_mem( &archive, "fixture.sys", sys.data(), sys.size(), MZ_NO_COMPRESSION) ||
	   !mz_zip_writer_add_mem( &archive, "fixture.cat", cat.data(), cat.size(), MZ_NO_COMPRESSION)) {
		mz_zip_writer_end( &archive) ;
		throw std::runtime_error( "worker ZIP members failed") ;
	}

	void	   *memory{} ;	// Finalizeが発行したheap。mz_freeへ返します。
	std::size_t bytes{} ;	// 有限fixtureの実原byte長。
	// 正規container生成不成立を内容拒否fixtureの合格へ補完しません。
	if( !mz_zip_writer_finalize_heap_archive( &archive, &memory, &bytes)) {
		mz_zip_writer_end( &archive) ;
		throw std::runtime_error( "worker ZIP finalization failed") ;
	}

	const std::unique_ptr<void, decltype( &mz_free)> owner{memory, &mz_free} ;	// 原heapのRAII。
	mz_zip_writer_end( &archive) ;
	return {static_cast<const char *>( owner.get()), bytes} ;
}

/** @brief 保存前から実署名・gzip・schema・commit／reloadを通したlookup入力を作ります。
 * @param[in] key 既存RAM内秘密鍵。永続保存しません。
 * @param[in] record 架空の原record byte。
 * @param[in] recordCount 有限batch境界用件数。通常は1です。
 * @param[out] storeOut 指定時だけ実reload済み隔離store所有を返します。nullptr可です。
 * @param[in] generation 真署名manifestの人工世代。asset世代7は変更しません。
 * @return Reloadが発行した真のconst snapshotの共有所有。
 */
[[nodiscard]] std::shared_ptr<const AuthenticatedIndexSnapshot> lookupSnapshot(
	const RamKey &key, const std::string_view record, const std::size_t recordCount = 1U,
	std::shared_ptr<SignedIndexStore> *const storeOut	= nullptr,
	const std::uint64_t						 generation = 9U)
{
	std::string entries ;	// 有限batch試験の原entry群。
	// 指定した架空record件数だけ一意identityを生成し、全件で終了する。
	for( std::size_t recordIndex = 0U; recordIndex < recordCount; ++recordIndex) {
		// 後続entryだけにcommaを追加する。
		if( recordIndex != 0U) {
			entries += "," ;
		}

		const auto raw = recordIndex == 0U
							 ? std::string{record}
							 : replaced( std::string{record}, "\"recordId\":\"metadata\"",
										"\"recordId\":\"batch-" + std::to_string( recordIndex) +
											"\"") ;	// 原recordを一意化。
		entries += recordEntry( key, raw) ;
	}

	const auto index  = record.find( "driver-index-record-v2") == std::string_view::npos
							? distributionIndex( recordSource(), entries)
							: descriptorIndex( recordSource(), entries) ;	// Wire版ごとの原index。
	auto	   inputs = makeStoreInputs( key, index, generation, 7U, NOW, "2026-10-11T05:00:00Z",
										"2026-10-25T05:00:00Z", (index.size() + 127U) / 128U,
										{1U, static_cast<std::uint64_t>( recordCount),
										 static_cast<std::uint64_t>( recordCount), 0U,
										 0U}) ;	// 既存比率枠内の実containerと元quality。
	const auto bytes =
		// 実gzip検査。
		authenticateIndexAssetBytes( inputs.manifest, inputs.gzip, NOW) ;
	// Test入力生成の不成立を拒否試験の成功にしない。
	if( !bytes.receipt) {
		throw std::runtime_error( "lookup gzip fixture failed") ;
	}

	const auto records = readSignedIndexRecords( *bytes.receipt, NOW) ;	// 実schema読取り。
	// 元recordを検査していないsnapshotは作れない。
	if( !records.receipt) {
		throw std::runtime_error( "lookup record fixture failed") ;
	}

	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{"fixture-main", key.publicBlob}}} ;									// Test public trustだけを隔離rootへ渡す。
	auto opened = signed_index_store_detail::Access::createIsolated( trust) ;	// 実保護root。
	// Storeの生成失敗をfixture successへ変換しない。
	if( !opened.store) {
		throw std::runtime_error( "lookup isolated store failed") ;
	}

	const auto committed =
		// 実commit。
		opened.store->commit( *records.receipt, inputs.envelope, inputs.gzip, NOW) ;
	// 原子保存なしのschema receiptをlookup入力に使わない。
	if( !committed.snapshot) {
		throw std::runtime_error( "lookup commit failed") ;
	}

	auto loaded = opened.store->reload( NOW) ;	// 保存原byteから再認証する。
	// Reload成功からだけconst所有snapshotを発行する。
	if( !loaded.snapshot) {
		throw std::runtime_error( "lookup reload failed") ;
	}

	// 内部worker fixtureだけが同じ実storeの再認証を継続します。
	if( storeOut != nullptr) {
		*storeOut = std::shared_ptr<SignedIndexStore>{std::move( opened.store)} ;
	}

	return std::make_shared<const AuthenticatedIndexSnapshot>( std::move( *loaded.snapshot)) ;
}

/** @brief Fake callbackの有限な正例・拒否モードです。 */
enum class LookupMode {
	/// 種別ごとに別のdeviceへ一意に結ぶ。
	UNIQUE,
	/// 完了した空結果。
	EMPTY,
	/// 同じ公開IDに同型deviceが複数ある未確定結果。
	MULTIPLE,
	/// 未知opaque。
	UNKNOWN,
	/// 同じopaqueの重複。
	DUPLICATE,
	/// 部分inventory／未完了。
	INCOMPLETE,
	/// 元HRESULT失敗。
	FAILURE,
	/// 例外失敗。
	THROWING,
	/// 確保例外。
	ALLOCATION,
	/// 古いcontext。
	STALE,
	/// 上限超過結果。
	EXCESSIVE
} ;

/** @brief 実端末ID・networkを使わない同期read-only fixtureです。 */
class LookupResolver final : public IndexPublicIdResolver {
public:
	/// この試行だけの有限モード。
	LookupMode							  mode{LookupMode::UNIQUE} ;
	/// 同workerのfixture呼出し件数。
	mutable std::size_t					  calls{} ;
	/// Callbackへ到達した元種別を保持するfixture観測。
	mutable std::vector<IndexPnpIdKind>	  kinds ;
	/// 公開ID・classの原申告が届いたことの観測。
	mutable bool						  receivedOriginal{true} ;
	/**
	 * @copydoc drivercrate::IndexPublicIdResolver::resolve
	 */
	[[nodiscard]] IndexPublicIdResolution resolve(
		const IndexPnpIdKind kind, const std::string_view publishedId,
		const std::string_view classGuid, const IndexLookupContext context,
		const std::span<const std::wstring> present) const override
	{
		++calls ;
		kinds.push_back( kind) ;
		receivedOriginal = receivedOriginal && publishedId == "TESTBUS\\SYNTH_0001" &&
						   classGuid == "{11111111-2222-3333-4444-555555555555}" ;
		IndexPublicIdResolution result{context, true, 0, {}} ;	// 全inventory完了の架空結果。
		// Fixtureモードごとに原結果だけを返し、共通adapter側の拒否を試す。
		switch( mode) {
			// 元種別を区別し、共通recordを別deviceへ結ぶ。
			case LookupMode::UNIQUE:
				result.devices.push_back( present[kind == IndexPnpIdKind::HARDWARE ? 0U : 1U]) ;
				break ;

			// 同型2台も元opaque集合全件を返す。
			case LookupMode::MULTIPLE:
				result.devices.assign( present.begin(), present.end()) ;
				break ;

			// 未知opaqueを返し、adapterで拒否させる。
			case LookupMode::UNKNOWN:
				result.devices = {L"unknown-opaque"} ;
				break ;

			// 重複を合法な非一意へまとめない。
			case LookupMode::DUPLICATE:
				result.devices = {L"opaque-a", L"opaque-a"} ;
				break ;

			// 部分inventoryでは空結果も完了不一致にしない。
			case LookupMode::INCOMPLETE:
				result.completed = false ;
				break ;

			// 元HRESULTを変更せず返す。
			case LookupMode::FAILURE:
				result.error = static_cast<NativeError>( E_ACCESSDENIED) ;
				break ;

			// 非標準のfixture障害もcallback外へ漏らさない。
			case LookupMode::THROWING:
				throw std::runtime_error( "synthetic resolver failure") ;
			// 確保障害を独立した元診断へ変換させる。
			case LookupMode::ALLOCATION:
				throw std::bad_alloc{} ;
			// 不一致のinventory世代を返す。
			case LookupMode::STALE:
				++result.context.inventoryGeneration ;
				break ;

			// Callback戻り枠を超過させる。
			case LookupMode::EXCESSIVE:
				result.devices.resize( INDEX_LOOKUP_PRESENT_MAX + 1U, L"opaque-a") ;
				break ;

			// 全inventory完了かつmatchなし。
			case LookupMode::EMPTY:
				break ;
		}

		return result ;
	}
} ;

/** @brief Lookup成立と各関係の区分を確認します。
 * @param[in,out] context 共通assertion集計先。
 * @param[in] result 実adapter結果。
 * @param[in] state 期待する各関係区分。
 * @param[in] reason 期待する各関係理由。
 */
void expectLookupRelations( TestContext &context, const IndexRecordLookupResult &result,
						   const IndexRecordMatchState state, const IndexRecordMatchReason reason)
{
	DRIVERCRATE_EXPECT( context,
					   result.status == IndexRecordLookupStatus::LOOKUP_READY && result.lookup) ;
	// 不成立結果を参照して試験の失敗を隠さない。
	if( !result.lookup) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, !result.lookup->relations().empty()) ;
	// 有限関係を全件確認し、最初の結果だけでgroupを合格にしない。
	for( const auto &relation : result.lookup->relations()) {
		DRIVERCRATE_EXPECT( context, relation.state == state && relation.reason == reason) ;
		DRIVERCRATE_EXPECT( context,
						   state == IndexRecordMatchState::MATCHED || !relation.deviceIdentity) ;
	}
}

} // namespace

/**
 * @copydoc drivercrate::test::runSignedIndexRecordLookupTests
 */
void runSignedIndexRecordLookupTests( TestContext &context)
{
	const int firstAssertion = context.assertionCount() ;	// 新groupの実件数だけを測る。
	const int firstFailure	 = context.failureCount() ;		// 新groupの実失敗だけを測る。
	RamKey	  key ;											// 非永続の既存RAM CNG鍵。
	key.generate( 3072U) ;
	const std::string raw = replaced(
		distributionRecord(),
		R"json("pnpIds":[{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json",
		// 同じ公表文字列でも種別は別。
		R"json("pnpIds":[{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"},{"kind":"COMPATIBLE","value":"TESTBUS\\SYNTH_0001"}])json") ;
	// 真のcommit／reload snapshot。
	auto							   snapshot = lookupSnapshot( key, raw) ;
	// 同workerの架空有限context。
	const IndexLookupContext		   active{11U, 12U, 13U} ;
	const std::array<std::wstring, 2U> present{L"opaque-a",
											   L"opaque-b"} ;	// Raw端末IDを含まない集合。
	LookupResolver					   resolver ;				// この呼出し中だけ借用するfake。
	const auto						   accepted =
		// 実入口。
		lookupSignedIndexRecords( snapshot, active, active, present, {}, NOW, &resolver) ;
	expectLookupRelations( context, accepted, IndexRecordMatchState::MATCHED,
						  IndexRecordMatchReason::UNIQUE_RELATION) ;
	DRIVERCRATE_EXPECT( context, resolver.calls == 2U && resolver.receivedOriginal) ;
	DRIVERCRATE_EXPECT( context,
					   resolver.kinds == std::vector<IndexPnpIdKind>( {IndexPnpIdKind::HARDWARE,
																	  IndexPnpIdKind::COMPATIBLE})) ;
	DRIVERCRATE_EXPECT( context, accepted.lookup && accepted.lookup->relations().size() == 2U) ;
	// 正例不成立をdereferenceで隠さず、残り試験を中止する。
	if( !accepted.lookup || accepted.lookup->relations().size() != 2U) {
		throw std::runtime_error( "lookup positive fixture failed") ;
	}

	// 同じ認証snapshotから独立lookupを一度作り、共有const所有へ明示移動します。
	auto manifestOnlyLookup =
		lookupSignedIndexRecords( snapshot, active, active, present, {}, NOW, &resolver) ;
	// 正常lookup前提の不成立を取得拒否の正例へ変換しません。
	if( !manifestOnlyLookup.lookup) {
		throw std::runtime_error( "manifest-only lookup prerequisite failed") ;
	}

	const auto manifestOnlyOwned = std::make_shared<const SignedIndexRecordLookup>(
		// 原lookupだけを共有所有します。
		std::move( *manifestOnlyLookup.lookup)) ;
	SignedIndexAcquisitionAdapter
			   manifestOnlyAdapter ;	// RAM trust成功を取得認可に転用しない実境界です。
	const auto manifestOnlyError =
		manifestOnlyAdapter.begin( manifestOnlyOwned, active, IndexTargetOs::WINDOWS_11,
								  NOW) ;	// 選択した取得集合にはRAM鍵を含みません。
	DRIVERCRATE_EXPECT( context, manifestOnlyError == E_ACCESSDENIED) ;
	std::cout << "P3 native manifest-only RAM snapshot: acquisition refused at product begin\n" ;

	const auto &owned	 = accepted.lookup->snapshot() ;			// 共有const所有からの借用。
	const auto &schema	 = owned.schemaReceipt() ;					// 原source／recordを読み取る。
	const auto &manifest = schema.assetBytes().manifest().data() ;	// 原世代とhashを別々に確認する。
	DRIVERCRATE_EXPECT( context, &owned == snapshot.get()) ;
	DRIVERCRATE_EXPECT( context, schema.sources().size() == 1U && schema.records().size() == 1U) ;
	DRIVERCRATE_EXPECT( context, schema.records()[0].originalBytes == raw) ;
	DRIVERCRATE_EXPECT( context, manifest.generation == 9U && manifest.assetGeneration == 7U) ;
	DRIVERCRATE_EXPECT( context, schema.schemaPolicyVersion() == 3U &&
									schema.assetBytes().bytePolicyVersion() == 1U &&
									owned.storePolicyVersion() == 1U) ;
	DRIVERCRATE_EXPECT( context,
					   manifest.manifestSha256 ==
						   snapshot->schemaReceipt().assetBytes().manifest().data().manifestSha256) ;
	DRIVERCRATE_EXPECT( context,
					   manifest.asset.sha256 ==
						   snapshot->schemaReceipt().assetBytes().manifest().data().asset.sha256) ;
	DRIVERCRATE_EXPECT( context, schema.indexSha256() == snapshot->schemaReceipt().indexSha256()) ;
	DRIVERCRATE_EXPECT( context,
					   schema.records()[0].inspectionStage == IndexInspectionStage::METADATA_ONLY) ;
	DRIVERCRATE_EXPECT( context, accepted.lookup->relations()[0].deviceIdentity == L"opaque-a" &&
									accepted.lookup->relations()[1].deviceIdentity == L"opaque-b") ;
	// 同record複数deviceでも原source／record hashとcontextを全件保持する。
	for( const auto &relation : accepted.lookup->relations()) {
		DRIVERCRATE_EXPECT( context, relation.context == active &&
										relation.recordSha256 == schema.records()[0].recordSha256 &&
										relation.sourceId == "fixture-source" &&
										relation.recordId == "metadata") ;
	}

	const std::array modes{LookupMode::EMPTY,	  LookupMode::MULTIPLE,	  LookupMode::UNKNOWN,
						   LookupMode::DUPLICATE, LookupMode::INCOMPLETE, LookupMode::FAILURE,
						   LookupMode::THROWING,  LookupMode::ALLOCATION, LookupMode::STALE,
						   LookupMode::EXCESSIVE} ;	// 独立の拒否試行。
	const std::array reasons{IndexRecordMatchReason::NO_RELATION,
							 IndexRecordMatchReason::NON_UNIQUE_RELATION,
							 IndexRecordMatchReason::INVALID_OPAQUE_RESULT,
							 IndexRecordMatchReason::INVALID_OPAQUE_RESULT,
							 IndexRecordMatchReason::RESOLVER_INCOMPLETE,
							 IndexRecordMatchReason::RESOLVER_FAILED,
							 IndexRecordMatchReason::RESOLVER_EXCEPTION,
							 IndexRecordMatchReason::RESOLVER_EXCEPTION,
							 IndexRecordMatchReason::RESOLVER_CONTEXT_MISMATCH,
							 IndexRecordMatchReason::INVALID_OPAQUE_RESULT} ;	// 各理由。
	// 有限モードを各一度実行し、各公開IDの元結果を確認する。
	for( std::size_t modeIndex = 0U; modeIndex < modes.size(); ++modeIndex) {
		resolver.mode	  = modes[modeIndex] ;
		const auto result = lookupSignedIndexRecords( snapshot, active, active, present, {}, NOW,
													 &resolver) ;	// 同context試行。
		expectLookupRelations( context, result,
							  modeIndex < 2U ? IndexRecordMatchState::UNMATCHED
											 : IndexRecordMatchState::UNDETERMINED,
							  reasons[modeIndex]) ;
		// 同型複数deviceは非一意のまま全opaqueを残す。
		if( modes[modeIndex] == LookupMode::MULTIPLE) {
			DRIVERCRATE_EXPECT( context,
							   result.lookup &&
								   result.lookup->relations()[0].relatedDevices ==
									   std::vector<std::wstring>( {L"opaque-a", L"opaque-b"})) ;
		}

		// Callbackの元失敗HRESULTを保存する。
		if( modes[modeIndex] == LookupMode::FAILURE) {
			DRIVERCRATE_EXPECT( context,
							   result.lookup && result.lookup->relations()[0].error ==
													static_cast<NativeError>( E_ACCESSDENIED)) ;
		}

		// 例外の型を規定した診断へ変換する。
		if( modes[modeIndex] == LookupMode::THROWING || modes[modeIndex] == LookupMode::ALLOCATION) {
			DRIVERCRATE_EXPECT(
				context, result.lookup &&
							 result.lookup->relations()[0].error ==
								 static_cast<NativeError>( modes[modeIndex] == LookupMode::ALLOCATION
															  ? E_OUTOFMEMORY
															  : E_FAIL)) ;
		}
	}

	resolver.mode = LookupMode::UNIQUE ;
	expectLookupRelations(
		context, lookupSignedIndexRecords( snapshot, active, active, present, {}, NOW, nullptr),
		IndexRecordMatchState::UNDETERMINED, IndexRecordMatchReason::RESOLVER_UNAVAILABLE) ;
	expectLookupRelations(
		context,
		lookupSignedIndexRecords( snapshot, active, active, present, {0U, 256U, 0U}, NOW, &resolver),
		IndexRecordMatchState::UNDETERMINED, IndexRecordMatchReason::BUDGET_EXHAUSTED) ;
	const auto partialBudget =
		lookupSignedIndexRecords( snapshot, active, active, present, {0U, 256U, 1U}, NOW,
								 &resolver) ;	// 一回だけcallbackを許す。
	DRIVERCRATE_EXPECT( context, partialBudget.lookup &&
									partialBudget.lookup->relations()[0].state ==
										IndexRecordMatchState::MATCHED &&
									partialBudget.lookup->relations()[1].reason ==
										IndexRecordMatchReason::BUDGET_EXHAUSTED) ;
	const auto unknown =
		// Class・versionも元UNKNOWN。
		lookupSnapshot( key, distributionRecord( "unknown", false)) ;
	const auto unknownResult = lookupSignedIndexRecords( unknown, active, active, present, {}, NOW,
														&resolver) ;	// 公開identity不明。
	expectLookupRelations( context, unknownResult, IndexRecordMatchState::UNDETERMINED,
						  IndexRecordMatchReason::PUBLIC_IDENTITY_UNKNOWN) ;
	DRIVERCRATE_EXPECT(
		context, unknownResult.lookup &&
					 !unknownResult.lookup->snapshot().schemaReceipt().records()[0].version.value &&
					 unknownResult.lookup->snapshot().schemaReceipt().records()[0].version.reason ==
						 "not supplied" &&
					 unknownResult.lookup->snapshot()
							 .schemaReceipt()
							 .records()[0]
							 .publishedIdentityEvidence.reason == "public INF identity missing") ;
	const std::size_t beforeReject = resolver.calls ;	// 入力拒否でcallbackが走らないことの基準。
	const std::array  staleContexts{IndexLookupContext{0U, 12U, 13U},
									IndexLookupContext{10U, 12U, 13U},
									IndexLookupContext{11U, 10U, 13U},
									IndexLookupContext{11U, 12U, 10U}} ;	// 不明・各stale field。
	// 不明と各世代不一致を全て拒否する。
	for( const auto stale : staleContexts) {
		const auto result = lookupSignedIndexRecords( snapshot, stale, active, present, {}, NOW,
													 &resolver) ;	// 不一致context。
		DRIVERCRATE_EXPECT( context, result.status == IndexRecordLookupStatus::STALE_CONTEXT &&
										!result.lookup) ;
	}

	DRIVERCRATE_EXPECT( context, lookupSignedIndexRecords( snapshot, active, active, present, {},
														 std::nullopt, &resolver)
										.status == IndexRecordLookupStatus::TIME_UNAVAILABLE) ;
	DRIVERCRATE_EXPECT( context, lookupSignedIndexRecords(
									snapshot, active, active, present, {},
									manifest.publishedAtUtc - std::chrono::seconds{1}, &resolver)
										.status == IndexRecordLookupStatus::NOT_YET_VALID) ;
	DRIVERCRATE_EXPECT( context, lookupSignedIndexRecords( snapshot, active, active, present, {},
														 manifest.expiresAtUtc, &resolver)
										.status == IndexRecordLookupStatus::EXPIRED) ;
	DRIVERCRATE_EXPECT(
		context, lookupSignedIndexRecords( {}, active, active, present, {}, NOW, &resolver).status ==
					 IndexRecordLookupStatus::INCOMPLETE_SNAPSHOT) ;
	const std::array<std::wstring, 2U> duplicated{L"opaque-a", L"opaque-a"} ;	// 不正present。
	const std::array<std::wstring, 1U> emptyIdentity{L""} ;						// 空opaqueはIDではない。
	DRIVERCRATE_EXPECT(
		context,
		lookupSignedIndexRecords( snapshot, active, active, duplicated, {}, NOW, &resolver).status ==
			IndexRecordLookupStatus::INVALID_PRESENT_SET) ;
	DRIVERCRATE_EXPECT( context, lookupSignedIndexRecords( snapshot, active, active, emptyIdentity,
														 {}, NOW, &resolver)
										.status == IndexRecordLookupStatus::INVALID_PRESENT_SET) ;
	const std::vector<std::wstring> oversized( INDEX_LOOKUP_PRESENT_MAX + 1U,
											  L"opaque-a") ;	// 件数上限超過。
	DRIVERCRATE_EXPECT(
		context,
		lookupSignedIndexRecords( snapshot, active, active, oversized, {}, NOW, &resolver).status ==
			IndexRecordLookupStatus::BUDGET_LIMIT) ;
	const std::array budgets{IndexLookupBudget{2U, 1U, 1U}, IndexLookupBudget{0U, 0U, 1U},
							 IndexLookupBudget{0U, 257U, 1U},
							 IndexLookupBudget{0U, 1U, 32769U}} ;	// 独立した有限枠拒否。
	// Batch範囲と各上限を全て確認する。
	for( const auto budget : budgets) {
		const auto result = lookupSignedIndexRecords( snapshot, active, active, present, budget, NOW,
													 &resolver) ;	// 枠外入力。
		DRIVERCRATE_EXPECT( context, result.status == IndexRecordLookupStatus::BUDGET_LIMIT &&
										!result.lookup) ;
	}

	DRIVERCRATE_EXPECT( context, resolver.calls == beforeReject) ;
	const auto emptyBatch = lookupSignedIndexRecords(
		snapshot, active, active, present, {1U, 256U, 0U}, NOW, &resolver) ;	// 末尾の空batch。
	DRIVERCRATE_EXPECT( context, emptyBatch.lookup && emptyBatch.lookup->relations().empty()) ;
	auto movedSource = *snapshot ;	// 真snapshotの正規copy。任意DTOではない。
	auto movedTarget = std::make_shared<const AuthenticatedIndexSnapshot>(
		// 一度moveして所有する。
		std::move( movedSource)) ;
	const auto movedInput = std::make_shared<const AuthenticatedIndexSnapshot>(
		// 必須byteのないmove元。
		std::move( movedSource)) ;
	DRIVERCRATE_EXPECT(
		context,
		lookupSignedIndexRecords( movedInput, active, active, present, {}, NOW, &resolver).status ==
			IndexRecordLookupStatus::INCOMPLETE_SNAPSHOT) ;
	DRIVERCRATE_EXPECT(
		context,
		lookupSignedIndexRecords( movedTarget, active, active, present, {}, NOW, &resolver).status ==
			IndexRecordLookupStatus::LOOKUP_READY) ;
	const std::weak_ptr<const AuthenticatedIndexSnapshot> lifetime =
		snapshot ;	// 共有寿命を外から観測する。
	const auto batchSnapshot =
		// Batch上限を超える全索引。
		lookupSnapshot( key, distributionRecord(), 257U) ;
	const auto firstBatch = lookupSignedIndexRecords( batchSnapshot, active, active, present, {},
													 NOW, &resolver) ;	// 先頭256件。
	const auto lastBatch =
		lookupSignedIndexRecords( batchSnapshot, active, active, present, {256U, 256U, 32768U}, NOW,
								 &resolver) ;	// 同索引の残り1件。
	DRIVERCRATE_EXPECT( context,
					   firstBatch.lookup && firstBatch.lookup->relations().size() == 256U &&
						   lastBatch.lookup && lastBatch.lookup->relations().size() == 1U &&
						   lastBatch.lookup->relations()[0].recordIndex == 256U) ;
	DRIVERCRATE_EXPECT( context,
					   firstBatch.lookup && lastBatch.lookup &&
						   &firstBatch.lookup->snapshot() == &lastBatch.lookup->snapshot()) ;
	std::vector<std::wstring> maximumPresent ;	// 4096件の架空opaque集合。
	// 最大件数まで一意opaqueを作り、実device列挙はしない。
	for( std::size_t presentIndex = 0U; presentIndex < INDEX_LOOKUP_PRESENT_MAX; ++presentIndex) {
		maximumPresent.push_back( L"opaque-" + std::to_wstring( presentIndex)) ;
	}

	DRIVERCRATE_EXPECT( context, lookupSignedIndexRecords( snapshot, active, active, maximumPresent,
														 {}, NOW, &resolver)
										.status == IndexRecordLookupStatus::LOOKUP_READY) ;
	resolver.mode = LookupMode::MULTIPLE ;
	const auto retainedBoundary =
		lookupSignedIndexRecords( batchSnapshot, active, active, maximumPresent, {0U, 9U, 9U}, NOW,
								 &resolver) ;	// 4096opaqueを8回保持して32768境界へ到達する。
	DRIVERCRATE_EXPECT(
		context,
		retainedBoundary.lookup && retainedBoundary.lookup->relations().size() == 9U &&
			retainedBoundary.lookup->relations()[7].relatedDevices.size() == 4096U &&
			retainedBoundary.lookup->relations()[7].state == IndexRecordMatchState::UNMATCHED &&
			retainedBoundary.lookup->relations()[8].state == IndexRecordMatchState::UNDETERMINED &&
			retainedBoundary.lookup->relations()[8].reason ==
				IndexRecordMatchReason::BUDGET_EXHAUSTED &&
			retainedBoundary.lookup->relations()[8].relatedDevices.empty()) ;
	resolver.mode = LookupMode::EMPTY ;
	expectLookupRelations(
		context, lookupSignedIndexRecords( snapshot, active, active, {}, {}, NOW, &resolver),
		IndexRecordMatchState::UNMATCHED, IndexRecordMatchReason::NO_RELATION) ;
	resolver.mode = LookupMode::INCOMPLETE ;
	expectLookupRelations(
		context, lookupSignedIndexRecords( snapshot, active, active, {}, {}, NOW, &resolver),
		IndexRecordMatchState::UNDETERMINED, IndexRecordMatchReason::RESOLVER_INCOMPLETE) ;
	snapshot.reset() ;
	DRIVERCRATE_EXPECT( context, !lifetime.expired() &&
									owned.schemaReceipt().records()[0].originalBytes == raw) ;
	std::cout << "Signed index record lookup assertions: "
			  << context.assertionCount() - firstAssertion
			  << ", failures: " << context.failureCount() - firstFailure << '\n' ;
	runDriverStoreIndexResolverTests( context, lookupSnapshot( key, raw), NOW) ;
	std::shared_ptr<SignedIndexStore> workerStore ;	// 真署名・commit済み隔離rootだけです。
	static_cast<void>( lookupSnapshot( key, raw, 513U, &workerStore)) ;
	runWorkerSignedIndexScanTests( context, std::move( workerStore), NOW, 513U) ;

	const std::string zip =
		std::string{"PK\x05\x06", 4U} + std::string( 18U, '\0') ;	// 非実行の空ZIP22byte。
	const std::string zipHash = recordDigest( key, zip) ;			// 同RAM helperで実byteへ結ぶ元申告hash。
	const IndexLookupContext		   acquisitionContext{71U, 72U,
												  73U} ;		// 同worker・scan・inventory固定context。
	LookupResolver					   acquisitionResolver ;	// 同じ既存resolverの一意opaque関係。
	const std::array<std::wstring, 2U> acquisitionPresent{L"opaque-a",
														  L"opaque-b"} ;	// 人工presentだけ。
	// 七つの元record条件を各真署名・隔離保存へ通し、有限件数で終了します。
	for( unsigned scenario = 0U; scenario < 7U; ++scenario) {
		std::string acquisitionRaw =
			// 正常の静的ZIP元record。
			descriptorRecord( descriptorFixture()) ;
		acquisitionRaw = replaced( std::move( acquisitionRaw), RECORD_CLAIM_HASH, zipHash) ;
		acquisitionRaw = replaced( std::move( acquisitionRaw), RECORD_CLAIM_HASH, zipHash) ;
		acquisitionRaw =
			replaced( std::move( acquisitionRaw), "\"valueBytes\":1234", "\"valueBytes\":22") ;
		// 計算hashだけを変更し、メーカー公表hash検査とは独立した拒否を確認します。
		if( scenario == 1U) {
			acquisitionRaw =
				replaced( std::move( acquisitionRaw),
						 "\"calculatedHash\":{\"state\":\"KNOWN\",\"sha256\":\"" + zipHash,
						 "\"calculatedHash\":{\"state\":\"KNOWN\",\"sha256\":\"" +
							 std::string{RECORD_CLAIM_HASH}) ;
			acquisitionRaw = replaced(
				std::move( acquisitionRaw),
				"\"publishedHash\":{\"state\":\"KNOWN\",\"sha256\":\"" + zipHash +
					"\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
					std::string{RECORD_EVIDENCE_HASH} + "\",\"reason\":\"\"}",
				"\"publishedHash\":{\"state\":\"UNKNOWN\",\"sha256\":\"\",\"evidenceUrl\":\"\",\"evidenceSha256\":\"\",\"reason\":\"not published\"}") ;
		}

		// 元size不一致を公表hash成功で隠しません。
		if( scenario == 2U) {
			acquisitionRaw =
				replaced( std::move( acquisitionRaw), "\"valueBytes\":22", "\"valueBytes\":23") ;
		}

		// 同意必須と具体的条件は本sliceの取得正常へ補完しません。
		if( scenario == 3U) {
			acquisitionRaw = descriptorRecord( descriptorFixture( false, true)) ;
		}

		// 未登録のCDNも原署名routeのexact URLだけで共通取得へ進めます。
		if( scenario == 4U) {
			acquisitionRaw =
				replaced( std::move( acquisitionRaw), "https://vendor.example/fixture.zip",
						 "https://cdn.fixture.example/fixture.zip") ;
			acquisitionRaw =
				replaced( std::move( acquisitionRaw), "https://vendor.example/fixture.zip",
						 "https://cdn.fixture.example/fixture.zip") ;
			acquisitionRaw =
				replaced( std::move( acquisitionRaw), "OFFICIAL_PAYLOAD_LINK", "OFFICIAL_CDN_LINK") ;
		}

		// 旧v1の配布pageとhashだけではdescriptorを発行しません。
		if( scenario == 5U) {
			acquisitionRaw = distributionRecord() ;
		}

		// 未知hashとsizeも固定上限内で取得し、公表検証済み値を架空に補完しません。
		if( scenario == 6U) {
			const std::string knownHash =
				"{\"state\":\"KNOWN\",\"sha256\":\"" + zipHash +
				"\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
				std::string{RECORD_EVIDENCE_HASH} + "\",\"reason\":\"\"}" ;	// 元known evidence。
			const std::string unknownHash =
				// 欠損を維持するhash。
				"{\"state\":\"UNKNOWN\",\"sha256\":\"\",\"evidenceUrl\":\"\",\"evidenceSha256\":\"\",\"reason\":\"not published\"}" ;
			acquisitionRaw = replaced( std::move( acquisitionRaw), knownHash, unknownHash) ;
			acquisitionRaw = replaced( std::move( acquisitionRaw), knownHash, unknownHash) ;
			acquisitionRaw =
				replaced( std::move( acquisitionRaw),
						 "{\"state\":\"KNOWN\",\"valueBytes\":22,\"reason\":\"\"}",
						 "{\"state\":\"UNKNOWN\",\"valueBytes\":0,\"reason\":\"not inspected\"}") ;
		}

		// 正常v2の同原byteでnative私有証拠の準備正負を追加し、旧七scenarioを維持します。
		if( scenario == 0U) {
			runNativePartialIndexPreparationTests( context, lookupSnapshot( key, acquisitionRaw),
												  NOW) ;
		}

		auto acquisitionLookup = lookupSignedIndexRecords(
			lookupSnapshot( key, acquisitionRaw), acquisitionContext, acquisitionContext,
			acquisitionPresent, {}, NOW, &acquisitionResolver) ;	// 同じ非公開構築入口。
		// Fixtureのlookup不成立を正常取得試験の成功にしません。
		if( !acquisitionLookup.lookup) {
			throw std::runtime_error( "acquisition lookup fixture failed") ;
		}

		runSignedIndexAcquisitionAdapterTests(
			context,
			std::make_shared<const SignedIndexRecordLookup>( std::move( *acquisitionLookup.lookup)),
			NOW, scenario == 5U ? 3U : scenario) ;
	}

	const auto driverZip  = normalWorkerDriverZip() ;					// 非空INF・SYS・CATを含む実container。
	const auto driverHash = recordDigest( key, driverZip) ;				// 原byteへ結ぶ公開申告の人工hash。
	auto	   driverRaw  = descriptorRecord( descriptorFixture()) ;	// 既知の同意不要静的ZIP条件。
	driverRaw			  = replaced( std::move( driverRaw), RECORD_CLAIM_HASH, driverHash) ;
	driverRaw			  = replaced( std::move( driverRaw), RECORD_CLAIM_HASH, driverHash) ;
	driverRaw			  = replaced( std::move( driverRaw), "\"valueBytes\":1234",
									 "\"valueBytes\":" + std::to_string( driverZip.size())) ;
	std::shared_ptr<SignedIndexStore> normalStore ;	// 同実store再認証をworker内へ借用します。
	auto							  normalSnapshot =
		// Batch境界後の二正常対象。
		lookupSnapshot( key, driverRaw, 258U, &normalStore) ;
	runNormalIndexWorkerAcquisitionTests( context, normalStore, NOW, driverZip, 258U, 256U) ;
	runNormalIndexWorkerAcquisitionTests( context, normalStore, NOW, driverZip, 258U, 0U) ;
	// 正常本体fixtureは原native CAT拒否と分離し、同じ真署名storeを一recordへ限定します。
	std::shared_ptr<SignedIndexStore> bindingStore ;	// 公開ClassGUIDまで実fixtureへ完全一致します。
	// 元真正recordの公開classだけを人工Ports内容へ一致させる再署名用byte。
	const auto bindingRaw = replaced( driverRaw, "{11111111-2222-3333-4444-555555555555}",
									 "{4d36e978-e325-11ce-bfc1-08002be10318}") ;
	static_cast<void>( lookupSnapshot( key, bindingRaw, 1U, &bindingStore)) ;
	runNormalSignedIndexCandidateBindingTests( context, bindingStore, NOW, driverZip) ;
	const auto netZip  = normalWorkerDriverZip( true) ;	// 別classの非空通常INFです。
	const auto netHash = recordDigest( key, netZip) ;	// 真署名recordを実原byteへ固定します。
	auto	   netRaw =
		// Net内容のsize/hash/classを再署名へ結ぶ原record。
		descriptorRecord( descriptorFixture()) ;
	netRaw = replaced( std::move( netRaw), RECORD_CLAIM_HASH, netHash) ;
	netRaw = replaced( std::move( netRaw), RECORD_CLAIM_HASH, netHash) ;
	netRaw = replaced( std::move( netRaw), "\"valueBytes\":1234",
					  "\"valueBytes\":" + std::to_string( netZip.size())) ;
	netRaw = replaced( std::move( netRaw), "{11111111-2222-3333-4444-555555555555}",
					  "{4d36e972-e325-11ce-bfc1-08002be10318}") ;
	std::shared_ptr<SignedIndexStore> netStore ;	// Portsとは別の隔離真正storeです。
	static_cast<void>( lookupSnapshot( key, netRaw, 1U, &netStore)) ;
	runNormalSignedIndexCandidateBindingTests( context, netStore, NOW, netZip, true) ;

	const auto aggregateStart	 = context.assertionCount() ;	// 全batch私有凍結groupの開始値。
	const auto aggregateFailures = context.failureCount() ;		// 元失敗を消しません。
	std::vector<SignedIndexRecordLookup> batches ;				// 正規入口でだけ構築した元batch。
	// 同snapshotの二batchを個別に読み、global位置を保持する私有凍結へ渡します。
	for( std::size_t offset = 0U; offset < 258U; offset += 256U) {
		auto batch = lookupSignedIndexRecords(
			normalSnapshot, acquisitionContext, acquisitionContext, acquisitionPresent,
			{offset, 256U, 32768U}, NOW, &acquisitionResolver) ;	// 元scanの全context。
		// 前段の不成立を集約拒否試験の成功へ変更しません。
		if( !batch.lookup) {
			throw std::runtime_error( "worker aggregate batch rejected") ;
		}

		batches.push_back( std::move( *batch.lookup)) ;
	}

	using AggregateAccess =
		signed_index_acquisition_detail::Access ;	// 固定私有batchだけの試験入口。
	const auto aggregate = AggregateAccess::freezeFixture(
		normalSnapshot, acquisitionContext, batches, NOW) ;	// 同原snapshotだけを集約します。
	DRIVERCRATE_EXPECT( context, aggregate.lookup && aggregate.lookup->relations().size() == 258U &&
									aggregate.lookup->relations()[256U].recordIndex == 256U &&
									&aggregate.lookup->snapshot() == normalSnapshot.get()) ;
	const auto otherSnapshot =
		// 同byteでも別commit/reload ownerです。
		lookupSnapshot( key, driverRaw, 258U) ;
	DRIVERCRATE_EXPECT(
		context,
		!AggregateAccess::freezeFixture( otherSnapshot, acquisitionContext, batches, NOW).lookup) ;
	const auto newGeneration =
		// 署名世代だけが異なります。
		lookupSnapshot( key, driverRaw, 258U, nullptr, 10U) ;
	DRIVERCRATE_EXPECT(
		context,
		newGeneration->schemaReceipt().assetBytes().manifest().data().generation == 10U &&
			!AggregateAccess::freezeFixture( newGeneration, acquisitionContext, batches, NOW)
				 .lookup) ;
	const auto otherRaw = replaced( driverRaw, "Synthetic fixture",
								   "Alternate fixture") ;	// 認証済み原record hashが異なります。
	const auto otherHash =
		// 正規署名・保存・再読取を維持します。
		lookupSnapshot( key, otherRaw, 258U) ;
	DRIVERCRATE_EXPECT(
		context,
		otherHash->schemaReceipt().records().front().recordSha256 !=
				normalSnapshot->schemaReceipt().records().front().recordSha256 &&
			!AggregateAccess::freezeFixture( otherHash, acquisitionContext, batches, NOW).lookup) ;
	auto otherContext = acquisitionContext ;	// 新取得operationへ原scan operationを書き換えません。
	++otherContext.operationId ;
	DRIVERCRATE_EXPECT(
		context,
		!AggregateAccess::freezeFixture( normalSnapshot, otherContext, batches, NOW).lookup) ;
	otherContext = acquisitionContext ;
	++otherContext.scanSessionId ;
	DRIVERCRATE_EXPECT(
		context,
		!AggregateAccess::freezeFixture( normalSnapshot, otherContext, batches, NOW).lookup) ;
	otherContext = acquisitionContext ;
	++otherContext.inventoryGeneration ;
	DRIVERCRATE_EXPECT(
		context,
		!AggregateAccess::freezeFixture( normalSnapshot, otherContext, batches, NOW).lookup) ;
	DRIVERCRATE_EXPECT( context, !AggregateAccess::freezeFixture( normalSnapshot, acquisitionContext,
																batches, std::nullopt)
									 .lookup) ;
	DRIVERCRATE_EXPECT( context,
					   !AggregateAccess::freezeFixture( normalSnapshot, acquisitionContext, batches,
													   NOW + std::chrono::days{15})
							.lookup) ;
	// 私有構築済み同batch再使用も重複拒否します。
	batches.push_back( batches.front()) ;
	DRIVERCRATE_EXPECT(
		context,
		!AggregateAccess::freezeFixture( normalSnapshot, acquisitionContext, batches, NOW).lookup) ;
	std::string manyIds ;	// 各recordで128個までの合法な公開IDを持つ原byte。
	// 合法な有限最大128個を一意に生成し、batch保持枠と全batch枠を分けて検査します。
	for( std::size_t index = 0U; index < 128U; ++index) {
		// JSON配列の先頭だけcommaを付けません。
		if( index != 0U) {
			manyIds += "," ;
		}

		manyIds += R"json({"kind":"HARDWARE","value":"TESTBUS\\SYNTH_)json" +
				   std::to_string( index) + R"json("})json" ;
	}

	const auto wideRaw =
		replaced( driverRaw, R"json({"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"})json",
				 manyIds) ;	// 私有relationを直接編集しません。
	const auto wideSnapshot =
		// 真署名・実schemaの原batchだけです。
		lookupSnapshot( key, wideRaw, 257U) ;
	std::vector<SignedIndexRecordLookup> wideBatches ;	// 32768関係と128関係の二元batch。
	// 正規lookupでだけ構築し、未知callback理由を維持したまま枠超過を確認します。
	for( std::size_t offset = 0U; offset < 257U; offset += 256U) {
		auto batch = lookupSignedIndexRecords( wideSnapshot, acquisitionContext, acquisitionContext,
											  {}, {offset, 256U, 0U}, NOW,
											  nullptr) ;	// 未実行はUNKNOWNのままです。
		// 材料生成の失敗を枠拒否の合格へ変更しません。
		if( !batch.lookup) {
			throw std::runtime_error( "wide aggregate batch rejected") ;
		}

		wideBatches.push_back( std::move( *batch.lookup)) ;
	}

	const auto atLimit = AggregateAccess::freezeFixture(
		wideSnapshot, acquisitionContext,
		std::span<const SignedIndexRecordLookup>{wideBatches}.first( 1U),
		NOW) ;	// 上限同値の正常集約。
	DRIVERCRATE_EXPECT( context, atLimit.lookup && atLimit.lookup->relations().size() == 32768U &&
									atLimit.lookup->relations().front().state ==
										IndexRecordMatchState::UNDETERMINED &&
									atLimit.lookup->relations().front().reason ==
										IndexRecordMatchReason::RESOLVER_UNAVAILABLE) ;
	const auto overLimit = AggregateAccess::freezeFixture(
		wideSnapshot, acquisitionContext, wideBatches, NOW) ;	// 全batchが上限を越える要求。
	DRIVERCRATE_EXPECT( context, !overLimit.lookup &&
									overLimit.status == IndexRecordLookupStatus::BUDGET_LIMIT) ;
	std::cout << "Normal index aggregate assertions: " << context.assertionCount() - aggregateStart
			  << ", failures: " << context.failureCount() - aggregateFailures << '\n' ;
}

} // namespace drivercrate::test
