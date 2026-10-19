//------------------------------------------------------------------------------
/**
 * @file signed_index_manifest.h
 * @brief 署名manifestの認証結果と有限な世代・期限契約を定義します。
 * @version 01.01.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  原byte署名の型付き認証境界を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/13  Local受入の固定公開pinと通常profileの空trustを明示。
 * Ver.01.01.01 Shunji Ogawa  2026/10/16  通常配布trustとlocal受入の排他契約を説明。
 * </pre>
 *
 * @note 通信・asset取得・保存・端末照合・導入を行いません。失敗時は認証出力を生成しません。
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "core/update_types.h"
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace drivercrate {

// Base64外側のJSON実byte上限。decoded manifestの上限は別に検査します。
inline constexpr std::size_t   INDEX_ENVELOPE_MAX_BYTES = 96U * 1024U ;
// 署名対象の原UTF-8実byte上限。
inline constexpr std::size_t   INDEX_MANIFEST_MAX_BYTES = 64U * 1024U ;
// 次工程へ渡すGZip assetの署名された転送byte上限。
inline constexpr std::uint64_t INDEX_ASSET_MAX_BYTES = 32ULL * 1024ULL * 1024ULL ;

/** @brief 正規化しない原byteのSHA-256を保持する固定32byte型です。 */
using IndexManifestSha256 = std::array<std::uint8_t, 32U> ;

/** @brief Manifestが指定する唯一の圧縮方式です。実byte検査は別工程です。 */
enum class IndexManifestCompression {
	/// GZipによる固定asset。
	GZIP
} ;

/** @brief 署名に結合した固定asset identityです。URLや取得許可を持ちません。 */
struct IndexManifestAsset {
	/// 完全tag名。暦日と末尾digestも検査済みです。
	std::string				 tag ;
	/// 固定名index.json.gz。
	std::string				 name ;
	/// 唯一の許可圧縮方式。
	IndexManifestCompression compression{IndexManifestCompression::GZIP} ;
	/// 圧縮済み転送長。1～32MiB。
	std::uint64_t			 sizeBytes{} ;
	/// 圧縮済み転送byteに対する発行側のSHA-256。
	IndexManifestSha256		 sha256{} ;
} ;

/** @brief 発行側の集計です。端末の内容検査や適合実績ではありません。 */
struct IndexManifestQuality {
	/// 発行側が記載した取得元件数。
	std::uint64_t sourceCount{} ;
	/// 三つの検査段階の合計record件数。
	std::uint64_t recordCount{} ;
	/// Metadataだけのrecord件数。
	std::uint64_t metadataOnlyCount{} ;
	/// 発行側で内容検査したrecord件数。
	std::uint64_t contentInspectedCount{} ;
	/// 未確認を保持するrecord件数。
	std::uint64_t unconfirmedCount{} ;
} ;

/** @brief Manifestの型付き値です。このDTOだけでは認証結果になりません。 */
struct IndexManifestData {
	/// 固定manifest schemaの版。受理する値は1だけです。
	std::uint32_t			 schemaVersion{1U} ;
	/// 固定repository EnterOgawa/drivercrate。
	std::string				 repository ;
	/// 固定channel driver-index。
	std::string				 channel ;
	/// 内部の信頼公開鍵へ解決した固定key ID。
	std::string				 keyId ;
	/// 正のmanifest世代。
	std::uint64_t			 generation{} ;
	/// 参照asset世代。正かつmanifest世代以下。
	std::uint64_t			 assetGeneration{} ;
	/// 署名された発行UTC。
	std::chrono::sys_seconds publishedAtUtc{} ;
	/// 署名された期限UTC。発行から正の期間、最大14日。
	std::chrono::sys_seconds expiresAtUtc{} ;
	/// 固定assetに対する署名された値。
	IndexManifestAsset		 asset ;
	/// 発行側の集計。実recordとの照合は後続工程です。
	IndexManifestQuality	 quality ;
	/// 再serializationしない、decodeした署名対象の原byte。
	std::string				 manifestBytes ;
	/// manifestBytesだけの実CNG SHA-256。
	IndexManifestSha256		 manifestSha256{} ;
} ;

namespace signed_index_detail {
struct AuthenticationAccess ;
}

/**
 * @brief 成功した署名・schema・期限・世代検査からだけ構築する不変の認証結果です。
 * @note Workerが所有し、後段へ認証receiptとして渡します。Asset合格や保存完了を意味しません。
 */
class AuthenticatedIndexManifest final {
public:
	/** @brief 認証された値を変更できない参照で借用します。
     * @return この認証結果の寿命まで有効な型付き値と原byte。
     */
	[[nodiscard]] const IndexManifestData &data() const noexcept ;

private:
	/** @brief 共通認証処理だけが全検証後の値を移譲します。
     * @param[in] data 全検査に成功した所有値。
     */
	explicit AuthenticatedIndexManifest( IndexManifestData data) noexcept ;
	friend struct signed_index_detail::AuthenticationAccess ;
	/// 外部から書き換えず所有する認証済み値。
	IndexManifestData data_ ;
} ;

/** @brief 保護storeから読み取った最大世代と原byte identityです。ここでは更新しません。 */
struct IndexManifestHighWater {
	/// 過去にasset・保存まで受理した最大manifest世代。0は不正です。
	std::uint64_t		generation{} ;
	/// 同世代再利用に要求するmanifest原byte SHA-256。
	IndexManifestSha256 manifestSha256{} ;
} ;

/** @brief 認証成功、入力拒否、CNG障害を区別する結果です。 */
enum class SignedIndexManifestStatus {
	/// 認証receiptを生成しました。Asset検査・保存・導入許可は別です。
	AUTHENTICATED,
	/// 外側JSONの実byteが空または上限を超えました。
	ENVELOPE_SIZE_LIMIT,
	/// Decodeした署名対象が空または上限を超えました。
	MANIFEST_SIZE_LIMIT,
	/// 外側JSONのUTF-8、構文、型、field集合が不正です。
	INVALID_ENVELOPE,
	/// Base64の字句、paddingまたは未使用bitが不正です。
	INVALID_BASE64,
	/// 内部信頼集合にkey IDがありません。
	UNKNOWN_KEY,
	/// 内部信頼集合またはRSA public blobが不正です。
	INVALID_TRUST_KEY,
	/// RSA-PSS署名または384byte長が一致しません。
	INVALID_SIGNATURE,
	/// 認証した原byteのmanifest schema、fieldまたは整数が不正です。
	INVALID_MANIFEST,
	/// 固定repositoryが一致しません。
	REPOSITORY_MISMATCH,
	/// 固定channelが一致しません。
	CHANNEL_MISMATCH,
	/// Envelopeとmanifestのkey IDが一致しません。
	KEY_MISMATCH,
	/// 検査時刻がありません。
	TIME_UNAVAILABLE,
	/// UTC、発行／期限の順序・未来・最大14日・期限が不成立です。
	INVALID_TIME,
	/// 固定asset名・tag・size・hashまたは圧縮方式が不正です。
	INVALID_ASSET,
	/// 最大受理世代の入力が破損しています。
	INVALID_HIGH_WATER,
	/// 最大受理世代より低いmanifestです。
	GENERATION_ROLLBACK,
	/// 同世代で原manifest byteが異なります。
	GENERATION_CONFLICT,
	/// CNG API障害です。元HRESULTを保持します。
	CRYPTO_FAILURE,
	/// 確保に失敗しました。認証出力はありません。
	OUT_OF_MEMORY
} ;

/** @brief 成功時だけ認証receiptを持つ一回の検査結果です。 */
struct SignedIndexManifestResult {
	/// 成功または拒否理由。初期値は未認証です。
	SignedIndexManifestStatus				  status{SignedIndexManifestStatus::INVALID_ENVELOPE} ;
	/// CNG／確保障害の元HRESULT。それ以外は0です。
	NativeError								  error{} ;
	/// 全manifest検査成功時だけ存在する、外部構築不可の認証receipt。
	std::optional<AuthenticatedIndexManifest> manifest ;
} ;

/**
 * @brief 製品binaryの固定鍵集合で署名manifestを認証します。
 * @param[in] envelope 最大96KiBの原UTF-8 JSON。呼出し中だけ借用します。
 * @param[in] nowUtc 信頼する検査UTC。確認不能の場合はnulloptです。
 * @param[in] highWater 保護storeの最大世代。初回はnulloptです。副作用なく照合します。
 * @return 全検査成功時だけ認証receiptを持つ結果。失敗時はreceiptなしです。
 * @note 通常profileはsource固定の配布公開鍵を使い、明示local受入の固定pinと排他です。
 * 実配布鍵の真署名正常例は別受入で、RAM fixture鍵を製品trustへ登録しません。
 * 通信・保存・最大世代更新は行いません。独立入力で同時に呼び出せます。
 */
[[nodiscard]] SignedIndexManifestResult authenticateSignedIndexManifest(
	std::string_view envelope, std::optional<std::chrono::sys_seconds> nowUtc,
	const std::optional<IndexManifestHighWater> &highWater) noexcept ;

} // namespace drivercrate
