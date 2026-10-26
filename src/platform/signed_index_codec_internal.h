//------------------------------------------------------------------------------
/**
 * @file signed_index_codec_internal.h
 * @brief 署名wrapperと未署名候補が共有する値codecを定義します。
 * @version 01.00.00
 * @date 2026/10/23
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/23  認証型を作らない共通値codecを抽出。
 * </pre>
 * @note 値の検査だけです。認証receipt、信頼鍵、通信能力を作りません。
 * @see docs/adr/0396-collector-distribution-pipeline-connection.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/signed_index_records.h"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace drivercrate::signed_index_detail {

/** @brief Manifest値codecの未認証結果です。 */
struct DecodedIndexManifest {
	/// 既存codecの元拒否だけです。値成功時はnulloptで、認証成功区分を作りません。
	std::optional<SignedIndexManifestStatus> failure{SignedIndexManifestStatus::INVALID_MANIFEST} ;
	/// CNGまたは確保の元診断です。
	NativeError								 error{} ;
	/// 全値検査成功時だけ所有する未認証DTOです。
	std::optional<IndexManifestData>		 data ;
} ;

/** @brief 実GZipの検査・展開値です。 */
struct DecodedIndexAssetData {
	/// 全境界検査を終えた原展開byteです。
	std::vector<std::byte> expanded ;
	/// 展開原byteだけの実hashです。
	IndexManifestSha256	   expandedSha256{} ;
	/// 圧縮率と絶対上限の最小値です。
	std::uint64_t		   maximumExpandedBytes{} ;
} ;

/** @brief Asset値codecの未認証結果です。 */
struct DecodedIndexAsset {
	/// 既存codecの元区分です。
	IndexAssetBytesStatus				 status{IndexAssetBytesStatus::GZIP_REJECTED} ;
	/// 共通CNG/GZip APIの元診断です。
	NativeError							 error{} ;
	/// 全検査成功時だけ所有する未認証byteです。
	std::optional<DecodedIndexAssetData> data ;
} ;

/** @brief 全recordとqualityの未認証所有値です。 */
struct DecodedIndexRecordsData {
	/// 全参照検査を終えたsource集合です。
	std::vector<IndexRecordSource>		 sources ;
	/// 全hash/schema検査を終えたrecord集合です。
	std::vector<IndexDistributionRecord> records ;
	/// Manifestと照合した実件数です。
	IndexManifestQuality				 quality ;
} ;

/** @brief Record値codecの未認証結果です。 */
struct DecodedIndexRecords {
	/// 既存codecの元区分です。
	IndexRecordsStatus					   status{IndexRecordsStatus::INVALID_INDEX} ;
	/// 元APIまたは確保診断です。
	NativeError							   error{} ;
	/// 全検査成功時だけ所有する未認証値です。
	std::optional<DecodedIndexRecordsData> data ;
} ;

/** @brief 既存manifest意味codecを認証型の作成なしで実行します。
 * @param[in] bytes 最大64KiBの原UTF-8です。
 * @param[in] expectedKeyId 署名側または候補channelで固定したkey IDです。
 * @param[in] nowUtc 確認済みUTCです。欠損は拒否します。
 * @return 同じschema/期限/asset検査の値結果です。署名検証は行いません。
 */
[[nodiscard]] DecodedIndexManifest decodeIndexManifestData(
	std::string_view bytes, std::string_view expectedKeyId,
	std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

/** @brief 実GZip byteを同じhash/容量/圧縮率/CRC規則で検査します。
 * @param[in] manifest 呼出側が意味検査済みの値です。認証の有無を表しません。
 * @param[in] compressed 最大32MiBの実byteです。
 * @param[in] nowUtc 確認済みUTCです。
 * @return 未認証の展開値だけを所有する結果です。
 */
[[nodiscard]] DecodedIndexAsset decodeIndexAssetData(
	const IndexManifestData &manifest, std::span<const std::byte> compressed,
	std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

/** @brief 展開byteの原record/schema/参照/qualityを共通codecで検査します。
 * @param[in] manifest 同じ原manifestの検査済み値です。
 * @param[in] expanded 同じasset値codecの展開byteです。
 * @param[in] nowUtc 確認済みUTCです。
 * @return 未認証の全値結果です。署名receiptは構築しません。
 */
[[nodiscard]] DecodedIndexRecords decodeIndexRecordsData(
	const IndexManifestData &manifest, std::span<const std::byte> expanded,
	std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;
} // namespace drivercrate::signed_index_detail
