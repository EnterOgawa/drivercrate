//------------------------------------------------------------------------------
/**
 * @file unsigned_index_candidate.cpp
 * @brief 実GZipと全recordを未署名候補の共通検査へ接続します
 * @version 01.06.00
 * @date 2026/10/23
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/23  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.00.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.01.00 Shunji Ogawa  2026/11/19  未検査の追加欄付き索引を旧公開準備で保留
 * Ver.01.02.00 Shunji Ogawa  2026/11/19  内容検査済み取得候補の必須条件を共通化
 * Ver.01.03.00 Shunji Ogawa  2026/11/19  通常収集の追加欄付き候補の配置と全行期限を検査
 * Ver.01.04.00 Shunji Ogawa  2026/11/22  公式Models専用欄を従来の署名前検査で保留
 * Ver.01.05.00 Shunji Ogawa  2026/11/25  私有追加欄の値検査を元本文との照合で共有
 * Ver.01.05.01 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * Ver.01.06.00 Shunji Ogawa  2026/11/28  版2の期限を最長の元期限と発行期間上限へ結合
 * </pre>
 * @note 認証型のconstructorを呼びません。副作用はCNG hashと有限な確保だけです
 * @see docs/adr/0396-collector-distribution-pipeline-connection.md
 */
//------------------------------------------------------------------------------
#include "platform/unsigned_index_candidate.h"
#include "platform/index_distribution_trust.h"
#include "platform/signed_index_codec_internal.h"
#include <algorithm>
#include <utility>

namespace drivercrate {
//------------------------------------------------------------------------------
/**
 * @brief 配布用の実manifest/GZipを署名型を生成せず共通codecで検査します
 * @param[in] manifest 原UTF-8 manifestです。最大64KiBです
 * @param[in] gzip 原GZipです。最大32MiBです
 * @param[in] nowUtc 確認済みUTCです。欠損時は拒否します
 * @param[in] schemaVersion 検査する署名スキーマ。旧版と個別期限版を混在させません
 * @return 元codec診断と、全成功時だけ未署名receiptを返します
 * @note 配布channelの固定公開key IDだけを照合します。鍵storeは開きません
 */
//------------------------------------------------------------------------------
UnsignedIndexCandidateResult validateUnsignedIndexCandidate(
	const std::string_view manifest, const std::span<const std::byte> gzip,
	const std::optional<std::chrono::sys_seconds> nowUtc,
	const std::uint32_t							  schemaVersion) noexcept
{
	UnsignedIndexCandidateResult result ;	// 失敗時に認証型を残しません
	auto						 decodedManifest = signed_index_detail::decodeIndexManifestData(
		manifest, index_distribution_trust::KEY_ID, nowUtc) ;	// 同じ意味codecです
	result.manifestFailure = decodedManifest.failure ;
	result.error		   = decodedManifest.error ;
	// Manifest全値検査の失敗時は展開を開始しません
	if( !decodedManifest.data) {
		return result ;
	}

	// 旧発行入口へ異なる期限方式を流用しません
	if( decodedManifest.data->schemaVersion != schemaVersion) {
		result.manifestFailure = SignedIndexManifestStatus::INVALID_MANIFEST ;
		return result ;
	}

	result.status	   = UnsignedIndexCandidateStatus::ASSET_REJECTED ;
	auto asset		   = signed_index_detail::decodeIndexAssetData( *decodedManifest.data, gzip,
																   nowUtc) ;	// 同じ実byte規則です
	result.assetStatus = asset.status ;
	result.error	   = asset.error ;
	// 実hash/CRC/容量不一致からrecordを救済しません
	if( !asset.data) {
		return result ;
	}

	// 追加欄を旧索引の内容検査だけで署名準備へ通しません
	if( !asset.data->supplementFrame.empty() || !asset.data->scopedModelsFrame.empty()) {
		result.status = UnsignedIndexCandidateStatus::ACQUISITION_PURPOSE_REJECTED ;
		return result ;
	}

	result.status = UnsignedIndexCandidateStatus::RECORDS_REJECTED ;
	auto records  = signed_index_detail::decodeIndexRecordsData(
		 *decodedManifest.data, asset.data->expanded, nowUtc) ;	// 全原recordの共通codecです
	result.recordsStatus = records.status ;
	result.error		 = records.error ;
	// Qualityや一件のschema不成立も部分成功へ変換しません
	if( !records.data) {
		return result ;
	}

	result.status = UnsignedIndexCandidateStatus::ACQUISITION_PURPOSE_REJECTED ;
	// 空の成功候補はhead更新にも署名準備にも使いません
	if( records.data->records.empty()) {
		return result ;
	}

	auto earliest = std::chrono::sys_seconds::max() ;	// 旧配信に適用する最も近い元期限です
	auto latest	  = std::chrono::sys_seconds::min() ;	// 個別期限配信に残る最も遅い元期限です
	// 全収録recordが現在有効な内容検査済み取得用途であることを確認します
	for( const auto &record : records.data->records) {
		// UNKNOWNや他用途は新producerの取得候補へ混入させません
		if( !signed_index_detail::isInspectedIndexAcquisition( record, *nowUtc)) {
			return result ;
		}

		const auto until =
			record.acquisitionDescriptor->attestation->validUntilUtc ;	// 同じ行の元期限
		earliest = std::min( earliest, until) ;
		latest	 = std::max( latest, until) ;
	}

	const auto expiry =
		schemaVersion == 2U
			? std::min( latest, decodedManifest.data->publishedAtUtc + std::chrono::days{14})
			: earliest ;	// 個別期限と索引全体の原期間を延長しません
	// 指定スキーマの期限規則から外れた候補は署名準備へ渡しません
	if( expiry != decodedManifest.data->expiresAtUtc) {
		result.status = schemaVersion == 2U
							? UnsignedIndexCandidateStatus::INDEPENDENT_EXPIRY_MISMATCH
							: UnsignedIndexCandidateStatus::MINIMUM_EXPIRY_MISMATCH ;
		return result ;
	}

	result.status = UnsignedIndexCandidateStatus::VALIDATED ;
	result.receipt =
		UnsignedIndexCandidateReceipt{std::move( *decodedManifest.data), records.data->quality,
									  asset.data->expandedSha256, latest} ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 収集候補の追加欄を旧本文及び全候補の元期限へ結合します
 * @param[in] manifest 実圧縮hashと世代を検査済みのmanifest値です
 * @param[in] asset 同manifestへ結合して展開した実圧縮の値です
 * @param[in] base 同assetの旧本文を検査した元取得元とレコードです
 * @param[in] nowUtc 確認済みの現在UTCです
 * @return 全条件成立時だけ未署名の追加レコードを保持します
 * @note 旧公開準備の候補検査とは別の入口で、署名権限を発行しません
 */
//------------------------------------------------------------------------------
IndexSupplementRecordsResult signed_index_detail::validateNativeSupplementCandidateData(
	const IndexManifestData &manifest, const DecodedIndexAssetData &asset,
	const DecodedIndexRecordsData &base, const std::chrono::sys_seconds nowUtc) noexcept
{
	const auto transport =
		decodeIndexSupplementFrame( manifest, asset.supplementFrame, asset.expanded.size(),
								   asset.expandedSha256, nowUtc) ;	// 同圧縮由来の追加欄です
	return validateNativeSupplementValues( manifest, base, transport, nowUtc) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 収集用追加欄と同じ本文の用途、原期限、共通上限を検査します
 * @param[in] manifest 本文を検査した元manifestです
 * @param[in] base 通常本文の元取得元とレコードです
 * @param[in] transport 圧縮、原ハッシュ、期限を照合した追加欄の検査結果です
 * @param[in] nowUtc 両領域に適用する確認済みUTCです
 * @return 両領域の条件が成立した場合に限り、追加レコードを返します
 */
//------------------------------------------------------------------------------
IndexSupplementRecordsResult signed_index_detail::validateNativeSupplementValues(
	const IndexManifestData &manifest, const DecodedIndexRecordsData &base,
	const IndexAssetSupplementResult &transport, const std::chrono::sys_seconds nowUtc) noexcept
{
	auto result = decodeIndexSupplementRecordsData( manifest, base.sources, base.records, transport,
												   nowUtc) ;	// 全行の原証拠と合計枠を照合します
	// 追加欄のレコード文法が未確定なら原検査の結果を返します
	if( result.status != IndexRecordsStatus::SCHEMA_VALIDATED) {
		return result ;
	}

	// 私有追加欄の用途に該当しないレコードを同じ欄へ混在させません
	if( !std::ranges::all_of( result.records, indexRecordNeedsSupplement)) {
		return {result.transportStatus, IndexRecordsStatus::INVALID_SUPPLEMENT_PURPOSE, 0, {}, {}} ;
	}

	auto expiry = transport.expiresAtUtc ;	// 追加欄だけの元最短期限です
	// 本文の各レコードに有効な取得証拠があることを確認して最短期限を求めます
	for( const auto &record : base.records) {
		// 元配布の証拠が失効したか検査が未成立のレコードを本文に含めません
		if( !isInspectedIndexAcquisition( record, nowUtc)) {
			return {
				result.transportStatus, IndexRecordsStatus::INVALID_SUPPLEMENT_PURPOSE, 0, {}, {}} ;
		}

		expiry = std::min( expiry, record.acquisitionDescriptor->attestation->validUntilUtc) ;
	}

	// 本文と追加欄の原期限を集約した値がマニフェストと一致することを要求します
	if( expiry != manifest.expiresAtUtc) {
		return {result.transportStatus, IndexRecordsStatus::SUPPLEMENT_EXPIRY_MISMATCH, 0, {}, {}} ;
	}

	return result ;
}
} // namespace drivercrate
