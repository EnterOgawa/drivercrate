//------------------------------------------------------------------------------
/**
 * @file signed_index_asset_bytes.h
 * @brief 認証済みmanifestに結合した実GZip byteの検査結果を定義します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  固定assetの原byteと上限付きGZip検査境界を追加。
 * </pre>
 *
 * @note JSON・record・公式性・端末適合・導入許可は検査しません。通信・保存も行いません。
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/signed_index_manifest.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace drivercrate {

// 有限な準備policyの版。全製品対応やJSON parserの版ではありません。
inline constexpr std::uint32_t INDEX_ASSET_BYTE_POLICY_VERSION = 1U ;
// 原展開byteの絶対上限。既存hash APIの128MiB枠内にも収めます。
inline constexpr std::uint64_t INDEX_ASSET_EXPANDED_MAX_BYTES = 128ULL * 1024ULL * 1024ULL ;
// Headerとtrailerを含む実圧縮container全体に対する最大展開倍率。
inline constexpr std::uint64_t INDEX_ASSET_MAX_COMPRESSION_RATIO = 128ULL ;

struct IndexAssetBytesResult ;

/**
 * @brief Manifest認証と実GZip byte検査からだけ構築する不変receiptです。
 * @note JSON／schema／record／公式性／端末適合／導入許可は未評価です。
 * WorkerがRAM内で所有し、成功しても最大受理世代を更新しません。
 */
class AuthenticatedIndexAssetBytes final {
public:
	/** @brief 原byte署名を認証したmanifestを変更できない参照で借用します。
     * @return Receiptの寿命まで有効な認証済みmanifest。
     */
	[[nodiscard]] const AuthenticatedIndexManifest &manifest() const noexcept ;
	/** @brief GZip検査に成功した展開原byteを借用します。
     * @return Receiptの寿命まで有効な不変byte列。JSONとしての合格は意味しません。
     */
	[[nodiscard]] std::span<const std::byte>		expandedBytes() const noexcept ;
	/** @brief 展開原byteだけの実SHA-256を借用します。
     * @return 圧縮asset hashやmanifest hashとは別の原byte digest。
     */
	[[nodiscard]] const IndexManifestSha256		   &expandedSha256() const noexcept ;
	/** @brief この検査に適用したbyte policy版を返します。
     * @return 有限準備policy v1。
     */
	[[nodiscard]] std::uint32_t						bytePolicyVersion() const noexcept ;
	/** @brief 展開前に適用した絶対量と圧縮倍率の小さい方を返します。
     * @return Decompressorへ渡した最大展開byte数。
     */
	[[nodiscard]] std::uint64_t						maximumExpandedBytes() const noexcept ;

private:
	/** @brief 全検査後の所有値だけを受け取ります。
     * @param[in] manifest 認証済みmanifestの所有copy。
     * @param[in] expanded 検査済み展開原byteの所有値。
     * @param[in] expandedSha256 展開原byteに対する実digest。
     * @param[in] maximumExpandedBytes Decompressorへ適用した展開byte上限。
     */
	AuthenticatedIndexAssetBytes( AuthenticatedIndexManifest manifest,
								 std::vector<std::byte>		expanded,
								 IndexManifestSha256		expandedSha256,
								 std::uint64_t				maximumExpandedBytes) noexcept ;

	friend IndexAssetBytesResult authenticateIndexAssetBytes(
		const AuthenticatedIndexManifest &, std::span<const std::byte>,
		std::optional<std::chrono::sys_seconds>) noexcept ;

	/// Manifest原byte／hash、key、世代、期限、固定assetと圧縮hash／sizeの認証結果。
	AuthenticatedIndexManifest manifest_ ;
	/// CRC／ISIZEと上限に成功した展開原byte。JSONの意味は未評価です。
	std::vector<std::byte>	   expanded_ ;
	/// 展開原byteだけの実SHA-256。
	IndexManifestSha256		   expandedSha256_{} ;
	/// 展開前にdecompressorへ渡した有限上限（byte）。
	std::uint64_t			   maximumExpandedBytes_{} ;
} ;

/** @brief Byte検査の成功と期限・改変・形式・API障害を区別します。 */
enum class IndexAssetBytesStatus {
	/// Manifest署名と実byte／GZip検査だけが成功しました。Schemaは未評価です。
	BYTE_VALIDATED,
	/// Move後等でmanifest原byteまたは必須の認証identity文字列が欠けています。
	INCOMPLETE_MANIFEST_RECEIPT,
	/// 信頼する検査UTCがありません。
	TIME_UNAVAILABLE,
	/// 認証後の検査UTCが署名された発行UTCより前です。
	NOT_YET_VALID,
	/// 認証後の検査UTCが署名された期限以上です。
	EXPIRED,
	/// 実圧縮byteが空または32MiB上限を超えています。
	COMPRESSED_SIZE_LIMIT,
	/// 実圧縮sizeと署名された完全sizeが異なります。
	SIZE_MISMATCH,
	/// 原圧縮byteの実SHA-256と署名されたdigestが異なります。
	HASH_MISMATCH,
	/// 共通CNG SHA-256処理が失敗しました。元HRESULTを保持します。
	CRYPTO_FAILURE,
	/// Header・単一Deflate・CRC・ISIZE・末尾のGZip検査が失敗しました。
	GZIP_REJECTED,
	/// 絶対展開量または圧縮倍率の有限上限を超えています。
	EXPANSION_LIMIT,
	/// 確保に失敗しました。成功receiptを生成しません。
	OUT_OF_MEMORY
} ;

/** @brief 一回のbyte検査結果です。拒否時はreceiptがありません。 */
struct IndexAssetBytesResult {
	/// 初期値は未検査を成功にしない拒否区分です。
	IndexAssetBytesStatus						status{IndexAssetBytesStatus::GZIP_REJECTED} ;
	/// 共通APIの元HRESULT bit pattern。純粋な入力拒否は0です。
	NativeError									error{} ;
	/// 全byte検査成功時だけ存在する、外部DTOから構築できない不変receipt。
	std::optional<AuthenticatedIndexAssetBytes> receipt ;
} ;

/**
 * @brief 認証済みmanifestへ実圧縮byteを結合し、上限付き単一GZipとして検査します。
 * @param[in] manifest 前段認証成功から構築された不変receipt。呼出し中だけ借用します。
 * @param[in] compressed 原転送byte。呼出し中に全要素を読取り可能かつ不変に保ちます。
 * @param[in] nowUtc 信頼UTCの再確認値。Nullopt、発行前、期限以上では拒否します。
 * @return 全検査成功時だけbyte receipt、拒否時は理由と元API HRESULTです。
 * @note 圧縮size／hash検査後にmin(128MiB, 実圧縮size×128)をdecompressorへ渡します。
 * JSON／record・最新highwater・公式性・端末適合は検査しません。通信・保存・世代更新・scanを行いません。
 * 独立入力では同時呼出し可能です。時刻やhighwaterの保護store transactionは後段が再確認します。
 */
[[nodiscard]] IndexAssetBytesResult authenticateIndexAssetBytes(
	const AuthenticatedIndexManifest &manifest, std::span<const std::byte> compressed,
	std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

} // namespace drivercrate
