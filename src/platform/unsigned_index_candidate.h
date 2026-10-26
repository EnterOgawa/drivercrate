//------------------------------------------------------------------------------
/**
 * @file unsigned_index_candidate.h
 * @brief 共通codecを使う未署名配布候補の検査receiptを定義します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/23  認証型を発行しない配布候補検査を追加。
 * </pre>
 * @note 鍵照会・署名・通信・high-water変更を行いません。
 * @see docs/adr/0396-collector-distribution-pipeline-connection.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/signed_index_records.h"
#include <chrono>
#include <optional>
#include <span>
#include <string_view>

namespace drivercrate {
/** @brief 未署名検査の到達段階です。認証成功区分を持ちません。 */
enum class UnsignedIndexCandidateStatus {
	/// 全byte/schema/qualityと候補用期限規則が成立しました。
	VALIDATED,
	/// Manifestの元拒否です。
	MANIFEST_REJECTED,
	/// GZip byteの元拒否です。
	ASSET_REJECTED,
	/// Record/schema/qualityの元拒否です。
	RECORDS_REJECTED,
	/// 内容検査済み取得用途の必要値が欠損しています。
	ACQUISITION_PURPOSE_REJECTED,
	/// Manifest期限が全recordの原期限の最小値と一致しません。
	MINIMUM_EXPIRY_MISMATCH
} ;

/** @brief 候補の値検査実績だけです。認証済み型への変換はありません。 */
struct UnsignedIndexCandidateReceipt {
	/// 原manifestの未認証値です。
	IndexManifestData	 manifest ;
	/// 共通codecで照合した実qualityです。
	IndexManifestQuality quality ;
	/// 原GZipを展開したbyteの実hashです。
	IndexManifestSha256	 expandedSha256{} ;
} ;

/** @brief 全検査成功時だけ未署名receiptを持つ結果です。 */
struct UnsignedIndexCandidateResult {
	/// 未署名の到達区分です。
	UnsignedIndexCandidateStatus status{UnsignedIndexCandidateStatus::MANIFEST_REJECTED} ;
	/// 既存manifest codecの元拒否だけです。値検査成功時はnulloptです。
	std::optional<SignedIndexManifestStatus> manifestFailure{
		SignedIndexManifestStatus::INVALID_MANIFEST} ;
	/// 既存asset codecの元区分です。
	IndexAssetBytesStatus						 assetStatus{IndexAssetBytesStatus::GZIP_REJECTED} ;
	/// 既存record codecの元区分です。
	IndexRecordsStatus							 recordsStatus{IndexRecordsStatus::INVALID_INDEX} ;
	/// 元API診断です。
	NativeError									 error{} ;
	/// 成功時の未署名値receiptです。通常アプリの認証入口には渡せません。
	std::optional<UnsignedIndexCandidateReceipt> receipt ;
} ;

/** @brief 配布用の実manifest/GZipを署名型を生成せず共通codecで検査します。
 * @param[in] manifest 原UTF-8 manifestです。最大64KiBです。
 * @param[in] gzip 原GZipです。最大32MiBです。
 * @param[in] nowUtc 確認済みUTCです。欠損時は拒否します。
 * @return 元codec診断と、全成功時だけ未署名receiptを返します。
 * @note 配布channelの固定公開key IDだけを照合します。鍵storeは開きません。
 */
[[nodiscard]] UnsignedIndexCandidateResult validateUnsignedIndexCandidate(
	std::string_view manifest, std::span<const std::byte> gzip,
	std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;
} // namespace drivercrate
