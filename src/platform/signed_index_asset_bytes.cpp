//------------------------------------------------------------------------------
/**
 * @file signed_index_asset_bytes.cpp
 * @brief 共通hashとGZip検査を使って署名済みassetの実byteを結合します
 * @version 01.06.01
 * @date 2026/10/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/10/23  同じGZip/hash検査を未認証の値codecへ共通化
 * Ver.01.01.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.01.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.02.00 Shunji Ogawa  2026/11/19  認証済み追加欄の世代・hash・期限と容量を検査
 * Ver.01.03.00 Shunji Ogawa  2026/11/19  圧縮追加欄の運搬検査を未署名候補と共通化
 * Ver.01.04.00 Shunji Ogawa  2026/11/20  追加欄の展開原byteを独立したSHA-256に結合
 * Ver.01.05.00 Shunji Ogawa  2026/11/22  公式Modelsの専用欄を旧本文と従来の追加欄から分離
 * Ver.01.06.00 Shunji Ogawa  2026/11/22  専用欄の元圧縮検査を局所組み立てへ共有
 * Ver.01.06.01 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * </pre>
 *
 * @note 認証済みmanifestだけを受理し、JSON意味・保存・highwater更新は行いません
 *       API失敗時の診断値を保持し、部分展開byteを成功receiptへ残しません
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
#include "platform/signed_index_codec_internal.h"

namespace drivercrate {
namespace {

constexpr std::size_t SUPPLEMENT_SUBFIELD_HEADER = 4U ;	// RFC subfieldの識別子と長さです
constexpr std::size_t SUPPLEMENT_GENERATION =
	SUPPLEMENT_SUBFIELD_HEADER + 1U ;										// 版に続く世代の位置です
constexpr std::size_t SUPPLEMENT_BASE_HASH = SUPPLEMENT_GENERATION + 8U ;	// 元展開hashの位置です
constexpr std::size_t SUPPLEMENT_EXPIRY	   = SUPPLEMENT_BASE_HASH + 32U ;	// 追加欄の期限の位置です
constexpr std::size_t SUPPLEMENT_GZIP	   = SUPPLEMENT_EXPIRY + 8U ;		// 内側GZipの開始位置です

//------------------------------------------------------------------------------
/**
 * @brief 固定長のlittle endian整数を同じ値で読みます
 * @param[in] bytes 呼出し側が検査した2又は8 byteの入力です
 * @return バイト列で指定された符号なし整数です
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint64_t supplementInteger( const std::span<const std::byte> bytes) noexcept
{
	std::uint64_t value{} ;	// 入力を符号拡張しない整数です
	// 最上位側から8ビットずつ詰め、バイト列をホストのエンディアンに依存せず整数化します
	for( std::size_t index = bytes.size(); index > 0U; --index) {
		value = (value << 8U) | std::to_integer<std::uint64_t>( bytes[index - 1U]) ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief GZip追加欄の先頭識別子が指定の用途か調べます
 * @param[in] extra 同じ元GZipに含まれる追加欄です
 * @param[in] kind 識別子の2 byte目です
 * @return 先頭2 byteが指定の識別子に一致する場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasIndexFrameTag( const std::span<const std::byte> extra,
									const std::byte					 kind) noexcept
{
	return extra.size() >= 2U && extra[0] == std::byte{'D'} && extra[1] == kind ;
}

//------------------------------------------------------------------------------
/**
 * @brief 本文の展開枠を判定する圧縮量からDMとそのXLENを除きます
 * @param[in] compressed 実長とSHA-256を確認した元圧縮byteです
 * @return DMが先頭の追加欄ならその宣言範囲を除いた圧縮量です。それ以外は全圧縮量です
 * @note 追加欄の範囲確認だけを行い、外側の形式とCRCは共通GZip検査へ任せます
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::size_t baseCompressedSize( const std::span<const std::byte> compressed) noexcept
{
	constexpr std::size_t EXTRA_LENGTH_OFFSET = 10U ;						// GZip固定headerの後のXLENです
	constexpr std::size_t EXTRA_OFFSET		  = EXTRA_LENGTH_OFFSET + 2U ;	// XLENの次が追加欄です
	constexpr std::size_t TRAILER_BYTES		  = 8U ;						// 末尾のCRC32とISIZEです
	constexpr std::byte	  EXTRA_FLAG{4U} ;									// HeaderのFEXTRAです
	// 追加欄の位置を安全に読めない形式では圧縮量からの差引きを行いません
	if( compressed.size() < EXTRA_OFFSET + 2U + TRAILER_BYTES ||
	   (compressed[3] & EXTRA_FLAG) == std::byte{}) {
		return compressed.size() ;
	}

	// GZipヘッダーが宣言した、XLEN自体を除く追加欄のバイト数
	const auto extraSize =
		static_cast<std::size_t>( supplementInteger( compressed.subspan( EXTRA_LENGTH_OFFSET, 2U))) ;
	// 全追加欄が元の範囲内でDM形式も一致した場合だけ本文の圧縮量を分離します
	if( extraSize > compressed.size() - EXTRA_OFFSET - TRAILER_BYTES ||
	   !hasIndexFrameTag( compressed.subspan( EXTRA_OFFSET, extraSize), std::byte{'M'})) {
		return compressed.size() ;
	}

	return compressed.size() - extraSize - 2U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 共通APIの原byte hashを固定32byteへ変換します
 * @param[in] bytes 用途別上限を事前検査した空でない原byte。正規化しません
 * @param[out] hash 成功時だけ原byte digest、失敗時は全0です
 * @return 共通CNG APIの元HRESULT。共通戻り値の形式不成立はE_UNEXPECTEDです
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError hashOriginalBytes( const std::span<const std::byte> bytes,
											IndexManifestSha256				&hash)
{
	hash = {} ;
	std::wstring		   hex ;	// 既存APIが所有して返す小文字64桁digest
	// Char viewはbyteのobject representationを読取り専用で借用する共通hash API境界です
	const std::string_view original{reinterpret_cast<const char *>( bytes.data()), bytes.size()} ;
	const NativeError error = computeDriverContainerSha256( original, hex) ;	// 128MiB枠の元診断値
	// CNGまたは確保の失敗を後続変換で上書きしない
	if( error != 0) {
		return error ;
	}

	// 共通APIの契約不成立を部分digestへ変換しない
	if( hex.size() != hash.size() * 2U) {
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}

	constexpr std::wstring_view HEX = L"0123456789abcdef" ;	// 固定小文字表
	IndexManifestSha256			completed{} ;				// 全桁成功後だけ公開するdigest
	// 固定32byteの各二桁を照合し、形式不正時は全0出力を維持する
	for( std::size_t index = 0U; index < completed.size(); ++index) {
		const std::size_t high = HEX.find( hex[index * 2U]) ;		// 上位四bit
		const std::size_t low  = HEX.find( hex[index * 2U + 1U]) ;	// 下位四bit
		// 未知文字を暗黙に丸めてdigestへ加えない
		if( high == std::wstring_view::npos || low == std::wstring_view::npos) {
			return static_cast<NativeError>( E_UNEXPECTED) ;
		}

		completed[index] = static_cast<std::uint8_t>( high * 16U + low) ;
	}

	hash = completed ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief API障害を理由付き拒否へ変換し、成功receiptを持たせません
 * @param[in] error 元API HRESULT
 * @param[in] status 確保失敗以外の拒否区分
 * @return 元診断値を保持した拒否。E_OUTOFMEMORYは独立区分です
 */
//------------------------------------------------------------------------------
[[nodiscard]] signed_index_detail::DecodedIndexAsset apiFailure(
	const NativeError error, const IndexAssetBytesStatus status) noexcept
{
	return {error == static_cast<NativeError>( E_OUTOFMEMORY) ? IndexAssetBytesStatus::OUT_OF_MEMORY
															 : status,
			error, std::nullopt} ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 全検査後の所有値だけを受け取ります
 * @param[in] manifest 認証済みmanifestの所有copy
 * @param[in] expanded 検査済み展開原byteの所有値
 * @param[in] expandedSha256 展開原byteに対する実digest
 * @param[in] maximumExpandedBytes Decompressorへ適用した展開byte上限
 * @param[in] supplementFrame 署名済み原圧縮byteに含まれるDC欄です
 * @param[in] scopedModelsFrame 署名済み原圧縮byteに含まれるDM欄です
 */
//------------------------------------------------------------------------------
AuthenticatedIndexAssetBytes::AuthenticatedIndexAssetBytes(
	AuthenticatedIndexManifest manifest, std::vector<std::byte> expanded,
	const IndexManifestSha256 expandedSha256, const std::uint64_t maximumExpandedBytes,
	std::vector<std::byte> supplementFrame, std::vector<std::byte> scopedModelsFrame) noexcept
	: manifest_( std::move( manifest)), expanded_( std::move( expanded)),
	  expandedSha256_( expandedSha256), maximumExpandedBytes_( maximumExpandedBytes),
	  supplementFrame_( std::move( supplementFrame)), scopedModelsFrame_( std::move( scopedModelsFrame))
{
}

//------------------------------------------------------------------------------
/**
 * @brief 原byte署名を認証したmanifestを変更できない参照で借用します
 * @return Receiptの寿命まで有効な認証済みmanifest
 */
//------------------------------------------------------------------------------
const AuthenticatedIndexManifest &AuthenticatedIndexAssetBytes::manifest() const noexcept
{
	return manifest_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief GZip検査に成功した展開原byteを借用します
 * @return Receiptの寿命まで有効な不変byte列。JSONとしての合格は意味しません
 */
//------------------------------------------------------------------------------
std::span<const std::byte> AuthenticatedIndexAssetBytes::expandedBytes() const noexcept
{
	return expanded_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 展開原byteだけの実SHA-256を借用します
 * @return 圧縮asset hashやmanifest hashとは別の原byte digest
 */
//------------------------------------------------------------------------------
const IndexManifestSha256 &AuthenticatedIndexAssetBytes::expandedSha256() const noexcept
{
	return expandedSha256_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief この検査に適用したbyte policy版を返します
 * @return 有限準備policy v1
 */
//------------------------------------------------------------------------------
std::uint32_t AuthenticatedIndexAssetBytes::bytePolicyVersion() const noexcept
{
	return INDEX_ASSET_BYTE_POLICY_VERSION ;
}

//------------------------------------------------------------------------------
/**
 * @brief 展開前に適用した絶対量と圧縮倍率の小さい方を返します
 * @return Decompressorへ渡した最大展開byte数
 */
//------------------------------------------------------------------------------
std::uint64_t AuthenticatedIndexAssetBytes::maximumExpandedBytes() const noexcept
{
	return maximumExpandedBytes_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名に結合した原圧縮byteが従来のDC欄を持つか調べます
 * @return DC欄の存在だけを示します
 */
//------------------------------------------------------------------------------
bool AuthenticatedIndexAssetBytes::hasSupplementFrame() const noexcept
{
	return !supplementFrame_.empty() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 従来のDC欄を同じassetの既存展開byteと現在時刻へ結び、上限内で展開します
 * @param[in] nowUtc 確認済みの現在UTCです
 * @return 期限内の運搬検査が成立したときだけ追加欄の展開原byteを含みます
 * @note 原manifestの集計及び既存展開byteを更新せず、取得と導入の権限を発行しません
 */
//------------------------------------------------------------------------------
IndexAssetSupplementResult AuthenticatedIndexAssetBytes::readSupplement(
	const std::optional<std::chrono::sys_seconds> nowUtc) const noexcept
{
	return signed_index_detail::decodeIndexSupplementFrame(
		manifest_.data(), supplementFrame_, expanded_.size(), expandedSha256_, nowUtc) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名に結合した元圧縮byteが公式ModelsのDM欄を持つか調べます
 * @return DM欄の存在だけを示します
 */
//------------------------------------------------------------------------------
bool AuthenticatedIndexAssetBytes::hasScopedModelsFrame() const noexcept
{
	return !scopedModelsFrame_.empty() ;
}

namespace {

//------------------------------------------------------------------------------
/**
 * @brief 検査済みGZipの追加欄を元展開hash・世代・期限と容量へ照合します
 * @param[in] data 同じ圧縮全byteに結合したmanifest値です
 * @param[in] frame 同じ圧縮から検出した予約追加欄の原byteです
 * @param[in] kind 予約識別子の2 byte目です
 * @param[in] baseExpandedBytes 同じGZipの旧本文展開サイズです
 * @param[in] baseExpandedSha256 同じGZipの旧本文原展開hashです
 * @param[in] nowUtc 確認済み現在UTCです
 * @return 全運搬検査が成立した場合にだけ展開内容を含みます
 * @note 署名、取得、導入、公開の許可は発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexAssetSupplementResult decodeTaggedIndexFrame(
	const IndexManifestData &data, const std::span<const std::byte> frame, const std::byte kind,
	const std::size_t baseExpandedBytes, const IndexManifestSha256 &baseExpandedSha256,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	using Status = IndexAssetSupplementStatus ;
	IndexAssetSupplementResult result ;	// 証拠が成立するまでbyteを渡しません
	// 追加欄がない索引は初期の検査結果を返します
	if( frame.empty()) {
		return result ;
	}

	result.status = Status::INVALID_FRAME ;
	// 追加欄の識別子、形式バージョン、宣言長がそろう形式だけを読み取ります
	if( frame.size() <= SUPPLEMENT_GZIP ||
	   frame.size() > std::numeric_limits<std::uint16_t>::max() || !hasIndexFrameTag( frame, kind) ||
	   frame[SUPPLEMENT_SUBFIELD_HEADER] != std::byte{1} ||
	   supplementInteger( frame.subspan( 2U, 2U)) != frame.size() - SUPPLEMENT_SUBFIELD_HEADER) {
		return result ;
	}

	const auto encodedExpiry =
		// 署名に結び付くUnix秒です
		supplementInteger( frame.subspan( SUPPLEMENT_EXPIRY, 8U)) ;
	// 有効な符号付き秒へ変換できる期限だけを採用します
	if( encodedExpiry == 0U ||
	   encodedExpiry > static_cast<std::uint64_t>( std::numeric_limits<std::int64_t>::max())) {
		return result ;
	}

	result.expiresAtUtc =
		std::chrono::sys_seconds{std::chrono::seconds{static_cast<std::int64_t>( encodedExpiry)}} ;
	result.status = Status::BINDING_MISMATCH ;
	const auto baseHash =
		// 旧領域を指定するhashです
		frame.subspan( SUPPLEMENT_BASE_HASH, baseExpandedSha256.size()) ;
	// 本文の内容と世代に結び付かない追加欄の内容を渡しません
	if( data.manifestBytes.empty() || baseExpandedBytes == 0U ||
	   supplementInteger( frame.subspan( SUPPLEMENT_GENERATION, 8U)) != data.assetGeneration ||
	   !std::ranges::equal( baseHash, std::as_bytes( std::span{baseExpandedSha256}))) {
		return result ;
	}

	// 現在時刻を確認できない場合は有効期間の判定を保留します
	if( !nowUtc) {
		result.status = Status::TIME_UNAVAILABLE ;
		return result ;
	}

	// 発行時刻の到来まで署名済み追加欄を消費しません
	if( *nowUtc < data.publishedAtUtc) {
		result.status = Status::NOT_YET_VALID ;
		return result ;
	}

	// 本文と追加欄のうち早い期限に達した時点で利用を止めます
	if( *nowUtc >= std::min( data.expiresAtUtc, result.expiresAtUtc)) {
		result.status = Status::EXPIRED ;
		return result ;
	}

	result.status = Status::EXPANSION_LIMIT ;
	// 宣言された配布サイズの範囲内に圧縮本文の残量があることを確認します
	if( data.asset.sizeBytes <= frame.size() + 2U || data.asset.sizeBytes > INDEX_ASSET_MAX_BYTES) {
		return result ;
	}

	const auto baseCompressedBytes =
		data.asset.sizeBytes - frame.size() - 2U ;	// XLENと追加欄を除いた旧圧縮量です
	// 追加欄の分離後も、本文に適用する展開量と圧縮率の両方を確認します
	if( baseExpandedBytes > baseCompressedBytes * INDEX_ASSET_MAX_COMPRESSION_RATIO ||
	   baseExpandedBytes >= INDEX_ASSET_EXPANDED_MAX_BYTES) {
		return result ;
	}

	const auto compressed = frame.subspan( SUPPLEMENT_GZIP) ;	// 内側は同じ署名内の一memberです
	const auto limit	  = std::min( INDEX_ASSET_EXPANDED_MAX_BYTES - baseExpandedBytes,
									 // 合計絶対枠と内側の倍率です
									 compressed.size() * INDEX_ASSET_MAX_COMPRESSION_RATIO) ;
	result.status		  = Status::GZIP_REJECTED ;
	// 追加欄から取り出した内側のGZipは付加フラグのない形式に限定します
	if( compressed.size() < 4U || compressed[3] != std::byte{}) {
		return result ;
	}

	result.error = decompressOfficialGzip( compressed, limit, result.expanded) ;
	// 展開失敗の区分は元診断から求めます
	if( result.error == static_cast<NativeError>( E_OUTOFMEMORY)) {
		result.status = Status::OUT_OF_MEMORY ;
	}
	// 展開枠を超えた失敗を圧縮形式の拒否と区別します
	else if( result.error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE))) {
		result.status = Status::EXPANSION_LIMIT ;
	}

	// 展開失敗では原byteを確認できないため、SHA-256を計算しません
	if( result.error != 0U) {
		return result ;
	}

	result.error = hashOriginalBytes( result.expanded, result.expandedSha256) ;
	// Hash失敗の追加欄は後段の構造検査へ渡しません
	if( result.error != 0U) {
		result.expanded.clear() ;
		result.status = result.error == static_cast<NativeError>( E_OUTOFMEMORY)
							? Status::OUT_OF_MEMORY
							: Status::HASH_FAILURE ;
		return result ;
	}

	result.status = Status::BYTE_VALIDATED ;
	return result ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 従来のDC欄だけを同じ圧縮byteの本文・世代・期限へ結合します
 * @param[in] data 実圧縮byteに結合したmanifest値です
 * @param[in] frame 同じGZipから読み取ったDC欄です。未検出なら空です
 * @param[in] baseExpandedBytes 同じGZipの従来本文の展開サイズです
 * @param[in] baseExpandedSha256 同じGZipの従来本文の展開SHA-256です
 * @param[in] nowUtc 確認済みの現在UTCです
 * @return 期限と有限な運搬検査に合格した場合だけDC欄の展開byteを含みます
 * @note 値の検査だけを行い、認証や公開の権限は発行しません
 */
//------------------------------------------------------------------------------
IndexAssetSupplementResult signed_index_detail::decodeIndexSupplementFrame(
	const IndexManifestData &data, const std::span<const std::byte> frame,
	const std::size_t baseExpandedBytes, const IndexManifestSha256 &baseExpandedSha256,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	return decodeTaggedIndexFrame( data, frame, std::byte{'C'}, baseExpandedBytes,
								  baseExpandedSha256, nowUtc) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式ModelsのDM欄を同じ認証済みassetの本文・世代・時刻へ結合します
 * @param[in] nowUtc 確認済みの現在UTCです
 * @return 期限と有限な運搬検査に合格した場合だけDM欄の展開byteと実SHA-256を含みます
 * @note 従来本文は独立に保持し、レコードの意味や端末適用は別の検査で確認します
 */
//------------------------------------------------------------------------------
IndexAssetSupplementResult AuthenticatedIndexAssetBytes::readScopedModels(
	const std::optional<std::chrono::sys_seconds> nowUtc) const noexcept
{
	return signed_index_detail::decodeIndexScopedModelsFrame(
		manifest_.data(), scopedModelsFrame_, expanded_.size(), expandedSha256_, nowUtc) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ元gzipから分離したDMの世代・本文ハッシュと期限を照合します
 * @param[in] manifest 元圧縮byteに結合したmanifest値です
 * @param[in] frame 検出したDMの原バイトです
 * @param[in] baseExpandedBytes 同じ本文の展開バイト数です
 * @param[in] baseExpandedSha256 同じ本文の展開ハッシュです
 * @param[in] nowUtc 原内外期限の評価時刻です
 * @return 有限運搬検査に成功したDMの展開バイトです
 * @note 取得と公開許可は発行しません
 */
//------------------------------------------------------------------------------
IndexAssetSupplementResult signed_index_detail::decodeIndexScopedModelsFrame(
	const IndexManifestData &manifest, const std::span<const std::byte> frame,
	const std::size_t baseExpandedBytes, const IndexManifestSha256 &baseExpandedSha256,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	return decodeTaggedIndexFrame( manifest, frame, std::byte{'M'}, baseExpandedBytes,
								  baseExpandedSha256, nowUtc) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 認証済みmanifestへ実圧縮byteを結合し、上限付き単一GZipとして検査します
 * @param[in] manifest 前段認証成功から構築された不変receipt。呼出し中だけ借用します
 * @param[in] compressed 原転送byte。呼出し中に全要素を読取り可能かつ不変に保ちます
 * @param[in] nowUtc 信頼UTCの再確認値。Nullopt、発行前、期限以上では拒否します
 * @return 全検査成功時だけbyte receipt、拒否時は理由と元API HRESULTです
 * @note 圧縮size／hash検査後、DM欄とXLENを除いた実圧縮sizeに展開枠を適用します。JSON／record・最新highwater・公式性・端末適合は
 *       検査しません。通信・保存・世代更新・scanを行いません。独立入力では同時呼出し可能です。時刻やhighwaterの保護store transactionは後段が再確認します
 */
//------------------------------------------------------------------------------
IndexAssetBytesResult authenticateIndexAssetBytes(
	const AuthenticatedIndexManifest &manifest, const std::span<const std::byte> compressed,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	// 前段認証後の時刻欠損は従来と同じ区分で拒否し、byte処理を始めません
	if( !nowUtc) {
		return {IndexAssetBytesStatus::TIME_UNAVAILABLE, 0, std::nullopt} ;
	}

	const auto &data = manifest.data() ;	// 外部DTOではない認証済み所有値
	// Move元など必須の根拠を失った認証objectを、残ったscalar／hashだけで受理しない
	if( data.manifestBytes.empty() || data.repository.empty() || data.channel.empty() ||
	   data.keyId.empty() || data.asset.tag.empty() || data.asset.name.empty()) {
		return {IndexAssetBytesStatus::INCOMPLETE_MANIFEST_RECEIPT, 0, std::nullopt} ;
	}

	auto decoded =
		// 同じ値codecです
		signed_index_detail::decodeIndexAssetData( data, compressed, nowUtc) ;
	// このwrapperだけが前段の認証済みmanifestを要求して認証byte型を構築します
	if( !decoded.data) {
		return {decoded.status, decoded.error, std::nullopt} ;
	}

	return {IndexAssetBytesStatus::BYTE_VALIDATED, 0,
			AuthenticatedIndexAssetBytes{
				manifest, std::move( decoded.data->expanded), decoded.data->expandedSha256,
				decoded.data->maximumExpandedBytes, std::move( decoded.data->supplementFrame),
				std::move( decoded.data->scopedModelsFrame)}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実GZip byteを同じhash/容量/圧縮率/CRC規則で検査します
 * @param[in] data 呼出側が意味検査済みの値です。認証の有無を表しません
 * @param[in] compressed 最大32MiBの実byteです
 * @param[in] nowUtc 確認済みUTCです
 * @return 未認証の展開値だけを所有する結果です
 */
//------------------------------------------------------------------------------
signed_index_detail::DecodedIndexAsset signed_index_detail::decodeIndexAssetData(
	const IndexManifestData &data, const std::span<const std::byte> compressed,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	// 時刻確認不能ではhashや展開を開始しません
	if( !nowUtc) {
		return {IndexAssetBytesStatus::TIME_UNAVAILABLE, 0, std::nullopt} ;
	}

	// 署名された発行前の時計では、認証時の期限結果を流用しない
	if( nowUtc.value() < data.publishedAtUtc) {
		return {IndexAssetBytesStatus::NOT_YET_VALID, 0, std::nullopt} ;
	}

	// 期限ちょうどからはassetも使わず、highwaterを進めない
	if( nowUtc.value() >= data.expiresAtUtc) {
		return {IndexAssetBytesStatus::EXPIRED, 0, std::nullopt} ;
	}

	// 展開前に実圧縮量を制限し、巨大入力のhash確保を開始しない
	if( compressed.empty() || compressed.size() > INDEX_ASSET_MAX_BYTES) {
		return {IndexAssetBytesStatus::COMPRESSED_SIZE_LIMIT, 0, std::nullopt} ;
	}

	const std::uint64_t compressedSize =
		// x64実byte数
		static_cast<std::uint64_t>( compressed.size()) ;
	// Size不一致はhashやGZip検査へ進めず、署名された完全長を要求する
	if( compressedSize != data.asset.sizeBytes) {
		return {IndexAssetBytesStatus::SIZE_MISMATCH, 0, std::nullopt} ;
	}

	try {
		IndexManifestSha256 compressedHash{} ;									// 圧縮原byteの実digest
		NativeError error = hashOriginalBytes( compressed, compressedHash) ;	// 共通CNG検査結果
		// Hash APIの元失敗を保持し、gzipへ不確定byteを渡さない
		if( error != 0) {
			return apiFailure( error, IndexAssetBytesStatus::CRYPTO_FAILURE) ;
		}

		// 署名に結合したhashと実圧縮byteを一致させてから展開する
		if( compressedHash != data.asset.sha256) {
			return {IndexAssetBytesStatus::HASH_MISMATCH, 0, std::nullopt} ;
		}

		const std::uint64_t baseSize =
			// DMとは独立した本文の圧縮量です
			baseCompressedSize( compressed) ;
		// Policy変更後も乗算前にoverflowを拒否し、事後比較だけにしない
		if( baseSize >
		   std::numeric_limits<std::uint64_t>::max() / INDEX_ASSET_MAX_COMPRESSION_RATIO) {
			return {IndexAssetBytesStatus::EXPANSION_LIMIT, 0, std::nullopt} ;
		}

		const std::uint64_t maximumExpandedBytes =
			std::min( INDEX_ASSET_EXPANDED_MAX_BYTES,
					 baseSize * INDEX_ASSET_MAX_COMPRESSION_RATIO) ;	// 本文の実効展開枠
		std::vector<std::byte>	   expanded ;							// 全検査成功まで公開しない原展開byte
		std::span<const std::byte> extra ;								// 同じ検証済み圧縮byteからだけ借用します
		error = decompressOfficialGzip( compressed, maximumExpandedBytes, expanded, &extra) ;
		// 共通gzip APIの元診断値を保ち、部分出力からreceiptを作らない
		if( error != 0) {
			return apiFailure(
				error, error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE))
						   ? IndexAssetBytesStatus::EXPANSION_LIMIT
						   : IndexAssetBytesStatus::GZIP_REJECTED) ;
		}

		IndexManifestSha256 expandedHash{} ;	// 圧縮hashとは別の展開原byte digest
		error = hashOriginalBytes( expanded, expandedHash) ;
		// 展開後hashの障害でも展開byteだけを成功として返さない
		if( error != 0) {
			return apiFailure( error, IndexAssetBytesStatus::CRYPTO_FAILURE) ;
		}

		std::vector<std::byte> supplement ;		// 従来のDC欄です
		std::vector<std::byte> scopedModels ;	// 公式ModelsのDM欄です
		// 既存の利用者向け追加候補欄を対応する保管先へ渡します
		if( hasIndexFrameTag( extra, std::byte{'C'})) {
			supplement.assign( extra.begin(), extra.end()) ;
		}
		// 公式Modelsの追加欄を専用の保管先へ渡します
		else if( hasIndexFrameTag( extra, std::byte{'M'})) {
			scopedModels.assign( extra.begin(), extra.end()) ;
		}

		return {IndexAssetBytesStatus::BYTE_VALIDATED, 0,
				DecodedIndexAssetData{std::move( expanded), expandedHash, maximumExpandedBytes,
									  std::move( supplement), std::move( scopedModels)}} ;
	} catch( const std::bad_alloc &) {
		return apiFailure( static_cast<NativeError>( E_OUTOFMEMORY),
						  IndexAssetBytesStatus::OUT_OF_MEMORY) ;
	}
}

} // namespace drivercrate
