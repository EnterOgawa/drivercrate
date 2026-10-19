//------------------------------------------------------------------------------
/**
 * @file signed_index_manifest.cpp
 * @brief 原UTF-8 manifestをRSA-PSSで認証し、固定schema・期限・世代を検査します。
 * @version 01.03.02
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  有限JSON・base64・CNG・世代の実認証を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/11  strict文法を意味不変で共用部品へ移動。
 * Ver.01.02.00 Shunji Ogawa  2026/10/11  通常workerの同scan署名索引読取り境界を接続。
 * Ver.01.03.00 Shunji Ogawa  2026/10/13  明示local受入buildの固定public pinを接続。
 * Ver.01.03.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.03.02 Shunji Ogawa  2026/10/16  通常固定配布trustをlocal受入と排他的に接続。
 * </pre>
 *
 * @note 内部固定trustだけを使用します。Asset実byte、保護cache、導入許可へ昇格しません。
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#include "signed_index_manifest_internal.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <utility>
#include <vector>
#include <windows.h>
#include <bcrypt.h>

#include "platform/official_file_verifier.h"
#include "platform/signed_index_json_internal.h"
#include "local_index_acceptance.h"
#include "platform/index_distribution_trust.h"
#include <span>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数と内部型。
//------------------------------------------------------------------------------

// RSA-PSS 3072bitの署名・modulus長（byte）。
constexpr std::size_t									 RSA_BYTES = 384U ;
// SHA-256に一致させる固定PSS salt長（byte）。
constexpr ULONG											 PSS_SALT_BYTES = 32U ;
// 通常配布と明示localの集合を合併せず、固定profile一つだけを選択します。
constexpr std::span<const signed_index_detail::TrustKey> PRODUCT_TRUST_KEYS =
	local_index_profile::ENABLED
		? std::span<const signed_index_detail::TrustKey>{local_index_profile::TRUST_KEYS}
		: std::span<const signed_index_detail::TrustKey>{index_distribution_trust::TRUST_KEYS} ;
// CNGが署名不一致として返す元NTSTATUS。
constexpr NTSTATUS INVALID_SIGNATURE_STATUS = static_cast<NTSTATUS>( 0xc000a000UL) ;

/**
 * @brief 共通JSON readerの失敗を当該索引層のstatusで保持し、元診断を上位へ伝える。
 */
using Failure = signed_index_json::Failure<SignedIndexManifestStatus> ;
/**
 * @brief 原byteを正規化しない共通JSON readerを当該索引層のstatusへ結合する。
 */
using Reader = signed_index_json::Reader<SignedIndexManifestStatus> ;
using signed_index_json::require ;
using signed_index_json::decodeHash ;
using signed_index_json::decimal ;

/** @brief 取得済みCNG RSA resourceを逆順に解放する単独ownerです。 */
class RsaHandles final {
public:
	/** @brief 未取得のhandleを持つownerを作ります。 */
	RsaHandles() = default ;
	/** @brief 取得済みkeyとalgorithmを全終了経路で解放します。 */
	~RsaHandles() noexcept
	{
		// Keyをalgorithmより先に解放するため、取得できたkeyだけを回収する。
		if( key != nullptr) {
			static_cast<void>( BCryptDestroyKey( key)) ;
		}

		// Import失敗でも取得済みalgorithmを残さない。
		if( algorithm != nullptr) {
			static_cast<void>( BCryptCloseAlgorithmProvider( algorithm, 0U)) ;
		}
	}
	/** @brief Handleの二重解放を防ぐためコピー構築を禁止します。 */
	RsaHandles( const RsaHandles &) = delete ;
	/** @brief Handleの二重解放を防ぐためコピー代入を禁止します。
     * @return 呼出しは禁止されます。
     */
	RsaHandles		 &operator=( const RsaHandles &) = delete ;
	/// BCryptCloseAlgorithmProviderで回収するalgorithm。
	BCRYPT_ALG_HANDLE algorithm{} ;
	/// BCryptDestroyKeyで回収するpublic key。
	BCRYPT_KEY_HANDLE key{} ;
} ;

/** @brief CNGの失敗値をHRESULTとして失わず中断します。
 * @param[in] status 元NTSTATUS。
 */
void requireCrypto( const NTSTATUS status)
{
	// API失敗と署名不一致の入力拒否を区別する。
	if( status < 0) {
		throw Failure{SignedIndexManifestStatus::CRYPTO_FAILURE,
					  static_cast<NativeError>( HRESULT_FROM_NT( status))} ;
	}
}

//------------------------------------------------------------------------------
// Base64とhash・暦日の検査。
//------------------------------------------------------------------------------

/** @brief 共通base64文法へmanifest固有の拒否区分を渡します。
 * @param[in] text 原base64。
 * @param[in] limit Decode後の独立上限。
 * @param[in] sizeFailure 上限拒否区分。
 * @return 原byte順序のdecode結果。
 */
[[nodiscard]] std::vector<std::uint8_t> decodeBase64( const std::string_view			 text,
													 const std::size_t				 limit,
													 const SignedIndexManifestStatus sizeFailure)
{
	return signed_index_json::decodeBase64( text, limit, sizeFailure,
										   SignedIndexManifestStatus::INVALID_BASE64) ;
}

/** @brief 既存共通hash APIで原byteをSHA-256へ結合します。
 * @param[in] bytes 署名対象原byte。
 * @return 実CNGの32byte hash。
 */
[[nodiscard]] IndexManifestSha256 hashManifest( const std::string_view bytes)
{
	std::wstring	  hex ;										// 共通APIが返す小文字64桁hash。
	const NativeError error = computeBytesSha256( bytes, hex) ;	// 再serializationしない原byte hash。
	// Hash APIの失敗を署名不一致と混同しない。
	if( error != 0) {
		throw Failure{SignedIndexManifestStatus::CRYPTO_FAILURE, error} ;
	}

	std::string narrow ;	// 共通APIのASCII hexだけを明示的に変換する。
	narrow.reserve( hex.size()) ;
	// 共通hashの各桁をASCII範囲へ限定してからcharへ変換する。
	for( const wchar_t character : hex) {
		require( character >= L'0' && character <= L'f', SignedIndexManifestStatus::CRYPTO_FAILURE) ;
		narrow.push_back( static_cast<char>( character)) ;
	}

	return decodeHash( narrow, SignedIndexManifestStatus::CRYPTO_FAILURE) ;
}

/** @brief 共通UTC文法へ既存manifestの拒否区分を渡します。
 * @param[in] text 原UTC。
 * @return 1970～9999年のUTC秒。
 */
[[nodiscard]] std::chrono::sys_seconds utc( const std::string_view text)
{
	return signed_index_json::utc( text, SignedIndexManifestStatus::INVALID_TIME) ;
}

/** @brief 内部trustとmanifestが使うkey IDの有限文法です。
 * @param[in] keyId 原ID。
 * @return 非空で64byte以内、ASCII英数字または._-だけの場合true。
 */
[[nodiscard]] bool validKeyId( const std::string_view keyId) noexcept
{
	return !keyId.empty() && keyId.size() <= 64U &&
		   std::ranges::all_of( keyId, []( const char character) {
			   // 固定key IDをASCIIだけに限定する値検査。外部captureを持たない。
			   return (character >= 'A' && character <= 'Z') ||
					  (character >= 'a' && character <= 'z') ||
					  (character >= '0' && character <= '9') || character == '.' ||
					  character == '_' || character == '-' ;
		   }) ;
}

//------------------------------------------------------------------------------
// 型付きmanifestとCNG認証。
//------------------------------------------------------------------------------

/** @brief 署名されたasset identityを型付きで検査します。
 * @param[in,out] reader 元manifestの借用reader。
 * @return 実byte検査前の署名された固定asset値。
 */
[[nodiscard]] IndexManifestAsset readAsset( Reader &reader)
{
	constexpr std::array<std::string_view, 5U> FIELDS{"tag", "name", "compression", "sizeBytes",
													  "sha256"} ;	// 固定field集合。
	IndexManifestAsset						   asset ;				// 全field検査後に返す値。
	std::string								   compression ;		// 唯一の方式との照合に使う元値。
	std::string								   hash ;				// Tag末尾とも照合する元hex。
	// Readerとこの関数の所有値だけを同期的に借用する型付きhandler。
	reader.object( FIELDS, [&]( const std::size_t field) {
		// 固定field番号に応じ、型を暗黙に変換せず読み取る。
		switch( field) {
			// 完全tag名。
			case 0U:
				asset.tag = reader.text( 128U) ;
				break ;

			// 固定asset名。
			case 1U:
				asset.name = reader.text( 64U) ;
				break ;

			// 固定GZip方式。
			case 2U:
				compression = reader.text( 16U) ;
				break ;

			// 署名された圧縮済み転送長。
			case 3U:
				asset.sizeBytes = reader.number() ;
				break ;

			// 署名された圧縮済みhash。
			case 4U:
				hash = reader.text( 64U) ;
				break ;

			// Schema外の番号は受理しない。
			default:
				throw Failure{SignedIndexManifestStatus::INVALID_ASSET} ;
		}
	}) ;
	constexpr auto FAILURE = SignedIndexManifestStatus::INVALID_ASSET ;	// 意味層拒否分類。
	require( asset.name == "index.json.gz" && compression == "gzip" && asset.sizeBytes > 0U &&
				asset.sizeBytes <= INDEX_ASSET_MAX_BYTES,
			FAILURE) ;
	asset.sha256 = decodeHash( hash, FAILURE) ;
	require( asset.tag.size() == 82U && asset.tag.starts_with( "index-v1-") && asset.tag[17] == '-' &&
				asset.tag.substr( 18U) == hash,
			FAILURE) ;
	const unsigned year =
		// 固定tagの暦年。
		decimal( std::string_view{asset.tag}.substr( 9U, 4U), FAILURE) ;
	const unsigned month =
		// 固定tagの暦月。
		decimal( std::string_view{asset.tag}.substr( 13U, 2U), FAILURE) ;
	const unsigned day =
		// 固定tagの暦日。
		decimal( std::string_view{asset.tag}.substr( 15U, 2U), FAILURE) ;
	const std::chrono::year_month_day date{
		std::chrono::year{static_cast<int>( year)}, std::chrono::month{month},
		std::chrono::day{day}} ;	// 発行時刻へ置換しないasset暦日。
	require( year >= 1970U && date.ok(), FAILURE) ;
	return asset ;
}

/** @brief 発行側の非負集計とoverflowしない三段階合計を検査します。
 * @param[in,out] reader 元manifest reader。
 * @return 署名された集計。実recordとの照合は別工程です。
 */
[[nodiscard]] IndexManifestQuality readQuality( Reader &reader)
{
	constexpr std::array<std::string_view, 5U> FIELDS{"sourceCount", "recordCount",
													  "metadataOnlyCount", "contentInspectedCount",
													  "unconfirmedCount"} ;	// 固定field集合。
	IndexManifestQuality					   quality ;					// 発行側の型付き集計。
	const std::array<std::uint64_t *, 5U>	   targets{
		 &quality.sourceCount, &quality.recordCount, &quality.metadataOnlyCount,
		 &quality.contentInspectedCount,
		 &quality.unconfirmedCount} ;	// 関数寿命内だけの非owning出力先。
	// Readerと有限出力配列だけを同期的に借用するhandler。
	reader.object( FIELDS, [&]( const std::size_t field) { *targets[field] = reader.number() ; }) ;
	require( quality.metadataOnlyCount <= quality.recordCount &&
				quality.contentInspectedCount <= quality.recordCount - quality.metadataOnlyCount &&
				quality.unconfirmedCount ==
					quality.recordCount - quality.metadataOnlyCount - quality.contentInspectedCount,
			SignedIndexManifestStatus::INVALID_MANIFEST) ;
	return quality ;
}

/** @brief 認証済み原byteの全必須fieldを型付きで読みます。
 * @param[in] bytes Decodeした原UTF-8。
 * @param[in] envelopeKeyId Trustへ解決済みの外側key ID。
 * @param[in] nowUtc 検査時刻。
 * @return 全manifest意味検査を通過した値。
 */
[[nodiscard]] IndexManifestData readManifest( const std::string_view bytes,
											 const std::string_view envelopeKeyId,
											 const std::optional<std::chrono::sys_seconds> nowUtc)
{
	Reader reader( bytes, SignedIndexManifestStatus::INVALID_MANIFEST) ;	// 原byteの有限reader。
	constexpr std::array<std::string_view, 10U> FIELDS{
		"schema",		   "repository",	 "channel",		 "keyId", "generation",
		"assetGeneration", "publishedAtUtc", "expiresAtUtc", "asset", "quality"} ;	// 全必須field。
	IndexManifestData data ;														// 全検査成功前には認証wrapperを生成しない値。
	// Readerと所有出力だけを呼出し期間内で借用する型付きhandler。
	reader.object( FIELDS, [&]( const std::size_t field) {
		// Field番号は固定集合に由来し、各値をその型だけで読む。
		switch( field) {
			// 配布manifest v1だけを認める。研究schemaを昇格しない。
			case 0U:
				require( reader.text( 64U) == "driver-index-manifest-v1",
						SignedIndexManifestStatus::INVALID_MANIFEST) ;
				break ;

			// 固定repository。
			case 1U:
				data.repository = reader.text( 64U) ;
				break ;

			// 固定channel。
			case 2U:
				data.channel = reader.text( 64U) ;
				break ;

			// 外側と同じ固定key ID。
			case 3U:
				data.keyId = reader.text( 64U) ;
				break ;

			// 正のmanifest世代。
			case 4U:
				data.generation = reader.number() ;
				break ;

			// 復帰用に独立したasset世代。
			case 5U:
				data.assetGeneration = reader.number() ;
				break ;

			// 補正しない発行UTC。
			case 6U:
				data.publishedAtUtc = utc( reader.text( 20U)) ;
				break ;

			// 補正しない期限UTC。
			case 7U:
				data.expiresAtUtc = utc( reader.text( 20U)) ;
				break ;

			// 固定assetの型付き値。
			case 8U:
				data.asset = readAsset( reader) ;
				break ;

			// 発行側の検査段階集計。
			case 9U:
				data.quality = readQuality( reader) ;
				break ;

			// Schema外番号を受理しない。
			default:
				throw Failure{SignedIndexManifestStatus::INVALID_MANIFEST} ;
		}
	}) ;
	reader.finish() ;
	require( data.repository == "EnterOgawa/drivercrate",
			SignedIndexManifestStatus::REPOSITORY_MISMATCH) ;
	require( data.channel == "driver-index", SignedIndexManifestStatus::CHANNEL_MISMATCH) ;
	require( data.keyId == envelopeKeyId, SignedIndexManifestStatus::KEY_MISMATCH) ;
	require( data.generation > 0U && data.assetGeneration > 0U &&
				data.assetGeneration <= data.generation,
			SignedIndexManifestStatus::INVALID_MANIFEST) ;
	require( nowUtc.has_value(), SignedIndexManifestStatus::TIME_UNAVAILABLE) ;
	require( data.expiresAtUtc > data.publishedAtUtc &&
				data.expiresAtUtc - data.publishedAtUtc <= std::chrono::days{14} &&
				data.publishedAtUtc <= *nowUtc && *nowUtc < data.expiresAtUtc,
			SignedIndexManifestStatus::INVALID_TIME) ;
	return data ;
}

/** @brief 余剰・private成分・不正指数を含む公開blobをimport前に拒否します。
 * @param[in] blob 内部trustの借用public blob。
 */
void validatePublicBlob( const std::span<const std::uint8_t> blob)
{
	constexpr auto FAILURE = SignedIndexManifestStatus::INVALID_TRUST_KEY ;	// 内部trust拒否分類。
	require( blob.size() == sizeof( BCRYPT_RSAKEY_BLOB) + 3U + RSA_BYTES, FAILURE) ;
	BCRYPT_RSAKEY_BLOB header{} ;	// Alignmentに依存せずcopyして読むSDK header。
	std::memcpy( &header, blob.data(), sizeof( header)) ;
	require( header.Magic == BCRYPT_RSAPUBLIC_MAGIC && header.BitLength == 3072U &&
				header.cbPublicExp == 3U && header.cbModulus == RSA_BYTES &&
				header.cbPrime1 == 0U && header.cbPrime2 == 0U,
			FAILURE) ;
	const std::size_t exponent = sizeof( header) ;	// SDK header直後のbig-endian指数。
	require( blob[exponent] == 1U && blob[exponent + 1U] == 0U && blob[exponent + 2U] == 1U &&
				(blob[exponent + 3U] & 0x80U) != 0U && (blob.back() & 1U) != 0U,
			FAILURE) ;
}

/** @brief 内部固定集合から一意の既知public keyへ解決します。
 * @param[in] keyId 外側key ID。Materialの取得元には使用しません。
 * @param[in] keys Binary固定またはtest専用の最大8件。
 * @return 呼出し中だけ借用する既知public blob。
 */
[[nodiscard]] std::span<const std::uint8_t> resolveKey(
	const std::string_view keyId, const std::span<const signed_index_detail::TrustKey> keys)
{
	require( keys.size() <= 8U, SignedIndexManifestStatus::INVALID_TRUST_KEY) ;
	std::span<const std::uint8_t> selected ;	// 未知鍵は空のまま拒否する。
	// 内部集合全体を検査し、重複IDや不正materialを黙って無視しない。
	for( std::size_t index = 0U; index < keys.size(); ++index) {
		require( validKeyId( keys[index].keyId), SignedIndexManifestStatus::INVALID_TRUST_KEY) ;
		validatePublicBlob( keys[index].rsaPublicBlob) ;
		// 前に見た有限IDと完全一致で重複を拒否する。
		for( std::size_t previous = 0U; previous < index; ++previous) {
			require( keys[index].keyId != keys[previous].keyId,
					SignedIndexManifestStatus::INVALID_TRUST_KEY) ;
		}

		// 一意な既知IDだけへ解決し、外側の自己提示鍵を扱わない。
		if( keys[index].keyId == keyId) {
			selected = keys[index].rsaPublicBlob ;
		}
	}

	require( !selected.empty(), SignedIndexManifestStatus::UNKNOWN_KEY) ;
	return selected ;
}

/** @brief 原manifest SHA-256を実CNG RSA-PSS 3072bit／salt32で検証します。
 * @param[in] blob 検査済み内部public blob。
 * @param[in] digest 原manifestのSHA-256。
 * @param[in,out] signature 呼出し内所有の384byte署名。CNGへ渡します。
 */
void verifySignature( const std::span<const std::uint8_t> blob, const IndexManifestSha256 &digest,
					 std::vector<std::uint8_t> &signature)
{
	require( signature.size() == RSA_BYTES, SignedIndexManifestStatus::INVALID_SIGNATURE) ;
	RsaHandles handles ;	// Import失敗を含む全経路で回収するowner。
	requireCrypto(
		BCryptOpenAlgorithmProvider( &handles.algorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0U)) ;
	std::vector<std::uint8_t> material( blob.begin(),
									   // Const借用をCNGの可変pointerへ直接渡さない。
									   blob.end()) ;
	requireCrypto( BCryptImportKeyPair( handles.algorithm, nullptr, BCRYPT_RSAPUBLIC_BLOB,
									  &handles.key, material.data(),
									  static_cast<ULONG>( material.size()), 0U)) ;
	ULONG keyBits{} ;	// CNGがimportした実key長。
	ULONG returned{} ;	// Property実byte長。
	// SDKのULONG property境界だけでbyte pointerへ変換し、固定容量を渡す。
	requireCrypto( BCryptGetProperty( handles.key, BCRYPT_KEY_LENGTH,
									reinterpret_cast<PUCHAR>( &keyBits), sizeof( keyBits), &returned,
									0U)) ;
	require( returned == sizeof( keyBits) && keyBits == 3072U,
			SignedIndexManifestStatus::INVALID_TRUST_KEY) ;
	IndexManifestSha256		hash = digest ;	// CNG境界の非const pointer用に限定したcopy。
	BCRYPT_PSS_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM,
									PSS_SALT_BYTES} ;	// 方式とsaltを固定する。
	const NTSTATUS			status = BCryptVerifySignature(
		 handles.key, &padding, hash.data(), static_cast<ULONG>( hash.size()), signature.data(),
		 // 実RSA-PSS検証。
		 static_cast<ULONG>( signature.size()), BCRYPT_PAD_PSS) ;
	// 署名不一致には元HRESULTを保持し、API障害と別分類にする。
	if( status == INVALID_SIGNATURE_STATUS) {
		throw Failure{SignedIndexManifestStatus::INVALID_SIGNATURE,
					  static_cast<NativeError>( HRESULT_FROM_NT( status))} ;
	}

	requireCrypto( status) ;
}

} // namespace

namespace signed_index_detail {

/** @brief 共通認証処理だけがprivate constructorを呼ぶ内部境界です。 */
struct AuthenticationAccess {
	/** @brief 全検査後の値を認証wrapperへ移します。
     * @param[in] data 署名・schema・期限・世代を検査済みの所有値。
     * @return 外部DTOからは構築できない認証結果。
     */
	[[nodiscard]] static AuthenticatedIndexManifest make( IndexManifestData data) noexcept
	{
		return AuthenticatedIndexManifest{std::move( data)} ;
	}
} ;

/** @see signed_index_manifest_internal.h */
SignedIndexManifestResult authenticateWithTrustKeys(
	const std::string_view envelope, const std::optional<std::chrono::sys_seconds> nowUtc,
	const std::optional<IndexManifestHighWater> &highWater,
	const std::span<const TrustKey>				 trustedKeys) noexcept
{
	try {
		require( !envelope.empty() && envelope.size() <= INDEX_ENVELOPE_MAX_BYTES,
				SignedIndexManifestStatus::ENVELOPE_SIZE_LIMIT) ;
		Reader reader( envelope, SignedIndexManifestStatus::INVALID_ENVELOPE) ;	// 有限外側JSON。
		constexpr std::array<std::string_view, 4U> FIELDS{"schema", "keyId", "manifestBytesBase64",
														  "signatureBase64"} ;	// 外側必須field。
		std::string								   keyId ;						// Materialへ昇格しない外側ID。
		std::string								   manifestBase64 ;				// 原manifestだけのbase64。
		std::string								   signatureBase64 ;			// 原byteに対する署名。
		// Readerとこの呼出しの所有値だけを同期的に借用するhandler。
		reader.object( FIELDS, [&]( const std::size_t field) {
			// 固定fieldごとに要求型と独立容量を検査する。
			switch( field) {
				// 外側v1だけを許可する。
				case 0U:
					require( reader.text( 64U) == "driver-index-envelope-v1",
							SignedIndexManifestStatus::INVALID_ENVELOPE) ;
					break ;

				// 一意な固定key ID。
				case 1U:
					keyId = reader.text( 64U) ;
					break ;

				// Decode後にmanifestの64KiBを独立検査する。
				case 2U:
					manifestBase64 = reader.text( INDEX_ENVELOPE_MAX_BYTES) ;
					break ;

				// Decode後に署名の384byteを独立検査する。
				case 3U:
					signatureBase64 = reader.text( 1024U) ;
					break ;

				// Schema外番号は認証しない。
				default:
					throw Failure{SignedIndexManifestStatus::INVALID_ENVELOPE} ;
			}
		}) ;
		reader.finish() ;
		require( validKeyId( keyId), SignedIndexManifestStatus::INVALID_ENVELOPE) ;
		const auto publicKey = resolveKey( keyId, trustedKeys) ;	// 外部提示materialは一切使わない。
		const auto bytes =
			decodeBase64( manifestBase64, INDEX_MANIFEST_MAX_BYTES,
						 SignedIndexManifestStatus::MANIFEST_SIZE_LIMIT) ;	// 元順序のmanifest。
		std::string				  raw( bytes.begin(), bytes.end()) ;		// 原UTF-8の所有byte。
		auto					  signature = decodeBase64( signatureBase64, RSA_BYTES,
														   SignedIndexManifestStatus::INVALID_SIGNATURE) ;	// 実署名byte。
		// 署名対象はrawだけ。
		const IndexManifestSha256 hash = hashManifest( raw) ;
		verifySignature( publicKey, hash, signature) ;
		IndexManifestData data = readManifest( raw, keyId, nowUtc) ;	// 実署名検証後の型付き意味層。
		// 保護storeの不正stateを初回扱いへ暗黙に変更しない。
		if( highWater.has_value()) {
			require( highWater->generation > 0U && std::ranges::any_of( highWater->manifestSha256,
																	  []( const std::uint8_t byte) {
																		  // 固定hashが空sentinelでないことだけを検査する。
																		  return byte != 0U ;
																	  }),
					SignedIndexManifestStatus::INVALID_HIGH_WATER) ;
			require( data.generation >= highWater->generation,
					SignedIndexManifestStatus::GENERATION_ROLLBACK) ;
			require( data.generation != highWater->generation || hash == highWater->manifestSha256,
					SignedIndexManifestStatus::GENERATION_CONFLICT) ;
		}

		data.manifestBytes	= std::move( raw) ;
		data.manifestSha256 = hash ;
		SignedIndexManifestResult result ;	// 全成功時に限りreceiptを一度だけ作る。
		result.manifest = AuthenticationAccess::make( std::move( data)) ;
		result.status	= SignedIndexManifestStatus::AUTHENTICATED ;
		return result ;
	} catch( const Failure &failure) {
		return {failure.status, failure.error, std::nullopt} ;
	} catch( const std::bad_alloc &) {
		return {SignedIndexManifestStatus::OUT_OF_MEMORY, static_cast<NativeError>( E_OUTOFMEMORY),
				std::nullopt} ;
	} catch( ...) {
		// Noexceptの境界で型不明障害を成功へ読み替えず、receiptを生成しない。
		return {SignedIndexManifestStatus::CRYPTO_FAILURE, static_cast<NativeError>( E_UNEXPECTED),
				std::nullopt} ;
	}
}

} // namespace signed_index_detail

/** @see signed_index_manifest.h */
AuthenticatedIndexManifest::AuthenticatedIndexManifest( IndexManifestData data) noexcept
	: data_( std::move( data))
{
}

/** @see signed_index_manifest.h */
const IndexManifestData &AuthenticatedIndexManifest::data() const noexcept
{
	return data_ ;
}

/** @see signed_index_manifest.h */
SignedIndexManifestResult authenticateSignedIndexManifest(
	const std::string_view envelope, const std::optional<std::chrono::sys_seconds> nowUtc,
	const std::optional<IndexManifestHighWater> &highWater) noexcept
{
	return signed_index_detail::authenticateWithTrustKeys( envelope, nowUtc, highWater,
														  PRODUCT_TRUST_KEYS) ;
}

/** @see signed_index_manifest_internal.h */
bool signed_index_detail::productTrustAvailable() noexcept
{
	return !PRODUCT_TRUST_KEYS.empty() ;
}

} // namespace drivercrate
