//------------------------------------------------------------------------------
/**
 * @file signed_index_asset_bytes.cpp
 * @brief 共通hashとGZip検査を使って署名済みassetの実byteを結合します。
 * @version 01.00.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  原byte hash・期限再検査と上限付きGZipの認証receiptを追加。
 * </pre>
 *
 * @note 認証済みmanifestだけを受理し、JSON意味・保存・highwater更新は行いません。
 *       API失敗時の診断値を保持し、部分展開byteを成功receiptへ残しません。
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#include "platform/signed_index_asset_bytes.h"

#include <algorithm>
#include <limits>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <windows.h>

#include "platform/official_file_verifier.h"
#include "platform/official_gzip.h"

namespace drivercrate {
namespace {

/** @brief 共通APIの原byte hashを固定32byteへ変換します。
 * @param[in] bytes 用途別上限を事前検査した空でない原byte。正規化しません。
 * @param[out] hash 成功時だけ原byte digest、失敗時は全0です。
 * @return 共通CNG APIの元HRESULT。共通戻り値の形式不成立はE_UNEXPECTEDです。
 */
[[nodiscard]] NativeError hashOriginalBytes( const std::span<const std::byte> bytes,
											IndexManifestSha256				&hash)
{
	hash = {} ;
	std::wstring		   hex ;	// 既存APIが所有して返す小文字64桁digest。
	// Char viewはbyteのobject representationを読取り専用で借用する共通hash API境界です。
	const std::string_view original{reinterpret_cast<const char *>( bytes.data()), bytes.size()} ;
	const NativeError error = computeDriverContainerSha256( original, hex) ;	// 128MiB枠の元診断値。
	// CNGまたは確保の失敗を後続変換で上書きしない。
	if( error != 0) {
		return error ;
	}

	// 共通APIの契約不成立を部分digestへ変換しない。
	if( hex.size() != hash.size() * 2U) {
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}

	constexpr std::wstring_view HEX = L"0123456789abcdef" ;	// 固定小文字表。
	IndexManifestSha256			completed{} ;				// 全桁成功後だけ公開するdigest。
	// 固定32byteの各二桁を照合し、形式不正時は全0出力を維持する。
	for( std::size_t index = 0U; index < completed.size(); ++index) {
		const std::size_t high = HEX.find( hex[index * 2U]) ;		// 上位四bit。
		const std::size_t low  = HEX.find( hex[index * 2U + 1U]) ;	// 下位四bit。
		// 未知文字を暗黙に丸めてdigestへ加えない。
		if( high == std::wstring_view::npos || low == std::wstring_view::npos) {
			return static_cast<NativeError>( E_UNEXPECTED) ;
		}

		completed[index] = static_cast<std::uint8_t>( high * 16U + low) ;
	}

	hash = completed ;
	return 0 ;
}

/** @brief API障害を理由付き拒否へ変換し、成功receiptを持たせません。
 * @param[in] error 元API HRESULT。
 * @param[in] status 確保失敗以外の拒否区分。
 * @return 元診断値を保持した拒否。E_OUTOFMEMORYは独立区分です。
 */
[[nodiscard]] IndexAssetBytesResult apiFailure( const NativeError		   error,
											   const IndexAssetBytesStatus status) noexcept
{
	return {error == static_cast<NativeError>( E_OUTOFMEMORY) ? IndexAssetBytesStatus::OUT_OF_MEMORY
															 : status,
			error, std::nullopt} ;
}

} // namespace

/** @see signed_index_asset_bytes.h */
AuthenticatedIndexAssetBytes::AuthenticatedIndexAssetBytes(
	AuthenticatedIndexManifest manifest, std::vector<std::byte> expanded,
	const IndexManifestSha256 expandedSha256, const std::uint64_t maximumExpandedBytes) noexcept
	: manifest_( std::move( manifest)), expanded_( std::move( expanded)),
	  expandedSha256_( expandedSha256), maximumExpandedBytes_( maximumExpandedBytes)
{
}

/** @see signed_index_asset_bytes.h */
const AuthenticatedIndexManifest &AuthenticatedIndexAssetBytes::manifest() const noexcept
{
	return manifest_ ;
}

/** @see signed_index_asset_bytes.h */
std::span<const std::byte> AuthenticatedIndexAssetBytes::expandedBytes() const noexcept
{
	return expanded_ ;
}

/** @see signed_index_asset_bytes.h */
const IndexManifestSha256 &AuthenticatedIndexAssetBytes::expandedSha256() const noexcept
{
	return expandedSha256_ ;
}

/** @see signed_index_asset_bytes.h */
std::uint32_t AuthenticatedIndexAssetBytes::bytePolicyVersion() const noexcept
{
	return INDEX_ASSET_BYTE_POLICY_VERSION ;
}

/** @see signed_index_asset_bytes.h */
std::uint64_t AuthenticatedIndexAssetBytes::maximumExpandedBytes() const noexcept
{
	return maximumExpandedBytes_ ;
}

/** @see signed_index_asset_bytes.h */
IndexAssetBytesResult authenticateIndexAssetBytes(
	const AuthenticatedIndexManifest &manifest, const std::span<const std::byte> compressed,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	// 前段認証後の時刻確認不能を成功とせず、hashや展開を開始しない。
	if( !nowUtc.has_value()) {
		return {IndexAssetBytesStatus::TIME_UNAVAILABLE, 0, std::nullopt} ;
	}

	const auto &data = manifest.data() ;	// 外部DTOではない認証済み所有値。
	// Move元など必須の根拠を失った認証objectを、残ったscalar／hashだけで受理しない。
	if( data.manifestBytes.empty() || data.repository.empty() || data.channel.empty() ||
	   data.keyId.empty() || data.asset.tag.empty() || data.asset.name.empty()) {
		return {IndexAssetBytesStatus::INCOMPLETE_MANIFEST_RECEIPT, 0, std::nullopt} ;
	}

	// 署名された発行前の時計では、認証時の期限結果を流用しない。
	if( nowUtc.value() < data.publishedAtUtc) {
		return {IndexAssetBytesStatus::NOT_YET_VALID, 0, std::nullopt} ;
	}

	// 期限ちょうどからはassetも使わず、highwaterを進めない。
	if( nowUtc.value() >= data.expiresAtUtc) {
		return {IndexAssetBytesStatus::EXPIRED, 0, std::nullopt} ;
	}

	// 展開前に実圧縮量を制限し、巨大入力のhash確保を開始しない。
	if( compressed.empty() || compressed.size() > INDEX_ASSET_MAX_BYTES) {
		return {IndexAssetBytesStatus::COMPRESSED_SIZE_LIMIT, 0, std::nullopt} ;
	}

	const std::uint64_t compressedSize =
		// x64実byte数。
		static_cast<std::uint64_t>( compressed.size()) ;
	// Size不一致はhashやGZip検査へ進めず、署名された完全長を要求する。
	if( compressedSize != data.asset.sizeBytes) {
		return {IndexAssetBytesStatus::SIZE_MISMATCH, 0, std::nullopt} ;
	}

	try {
		IndexManifestSha256 compressedHash{} ;									// 圧縮原byteの実digest。
		NativeError error = hashOriginalBytes( compressed, compressedHash) ;	// 共通CNG検査結果。
		// Hash APIの元失敗を保持し、gzipへ不確定byteを渡さない。
		if( error != 0) {
			return apiFailure( error, IndexAssetBytesStatus::CRYPTO_FAILURE) ;
		}

		// 署名に結合したhashと実圧縮byteを一致させてから展開する。
		if( compressedHash != data.asset.sha256) {
			return {IndexAssetBytesStatus::HASH_MISMATCH, 0, std::nullopt} ;
		}

		// Policy変更後も乗算前にoverflowを拒否し、事後比較だけにしない。
		if( compressedSize >
		   std::numeric_limits<std::uint64_t>::max() / INDEX_ASSET_MAX_COMPRESSION_RATIO) {
			return {IndexAssetBytesStatus::EXPANSION_LIMIT, 0, std::nullopt} ;
		}

		const std::uint64_t maximumExpandedBytes =
			std::min( INDEX_ASSET_EXPANDED_MAX_BYTES,
					 compressedSize * INDEX_ASSET_MAX_COMPRESSION_RATIO) ;	// 実効展開枠。
		std::vector<std::byte> expanded ;									// 全検査成功まで公開しない原展開byte。
		error = decompressOfficialGzip( compressed, maximumExpandedBytes, expanded) ;
		// 共通gzip APIの元診断値を保ち、部分出力からreceiptを作らない。
		if( error != 0) {
			return apiFailure(
				error, error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE))
						   ? IndexAssetBytesStatus::EXPANSION_LIMIT
						   : IndexAssetBytesStatus::GZIP_REJECTED) ;
		}

		IndexManifestSha256 expandedHash{} ;	// 圧縮hashとは別の展開原byte digest。
		error = hashOriginalBytes( expanded, expandedHash) ;
		// 展開後hashの障害でも展開byteだけを成功として返さない。
		if( error != 0) {
			return apiFailure( error, IndexAssetBytesStatus::CRYPTO_FAILURE) ;
		}

		return {IndexAssetBytesStatus::BYTE_VALIDATED, 0,
				AuthenticatedIndexAssetBytes{manifest, std::move( expanded), expandedHash,
											 maximumExpandedBytes}} ;
	} catch( const std::bad_alloc &) {
		return apiFailure( static_cast<NativeError>( E_OUTOFMEMORY),
						  IndexAssetBytesStatus::OUT_OF_MEMORY) ;
	}
}

} // namespace drivercrate
