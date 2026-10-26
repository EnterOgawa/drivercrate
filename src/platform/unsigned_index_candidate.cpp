//------------------------------------------------------------------------------
/**
 * @file unsigned_index_candidate.cpp
 * @brief 実GZipと全recordを未署名候補の共通検査へ接続します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/23  共通値codecと原期限の最小値検査を追加。
 * </pre>
 * @note 認証型のconstructorを呼びません。副作用はCNG hashと有限な確保だけです。
 * @see docs/adr/0396-collector-distribution-pipeline-connection.md
 */
//------------------------------------------------------------------------------
#include "platform/unsigned_index_candidate.h"
#include "platform/index_distribution_trust.h"
#include "platform/signed_index_codec_internal.h"
#include <algorithm>
#include <utility>

namespace drivercrate {
/** @see unsigned_index_candidate.h */
UnsignedIndexCandidateResult validateUnsignedIndexCandidate(
	const std::string_view manifest, const std::span<const std::byte> gzip,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	UnsignedIndexCandidateResult result ;	// 失敗時に認証型を残しません。
	auto						 decodedManifest = signed_index_detail::decodeIndexManifestData(
		manifest, index_distribution_trust::KEY_ID, nowUtc) ;	// 同じ意味codecです。
	result.manifestFailure = decodedManifest.failure ;
	result.error		   = decodedManifest.error ;
	// Manifest全値検査の失敗時は展開を開始しません。
	if( !decodedManifest.data) {
		return result ;
	}

	result.status	   = UnsignedIndexCandidateStatus::ASSET_REJECTED ;
	auto asset		   = signed_index_detail::decodeIndexAssetData( *decodedManifest.data, gzip,
																   nowUtc) ;	// 同じ実byte規則です。
	result.assetStatus = asset.status ;
	result.error	   = asset.error ;
	// 実hash/CRC/容量不一致からrecordを救済しません。
	if( !asset.data) {
		return result ;
	}

	result.status = UnsignedIndexCandidateStatus::RECORDS_REJECTED ;
	auto records  = signed_index_detail::decodeIndexRecordsData(
		 *decodedManifest.data, asset.data->expanded, nowUtc) ;	// 全原recordの共通codecです。
	result.recordsStatus = records.status ;
	result.error		 = records.error ;
	// Qualityや一件のschema不成立も部分成功へ変換しません。
	if( !records.data) {
		return result ;
	}

	result.status = UnsignedIndexCandidateStatus::ACQUISITION_PURPOSE_REJECTED ;
	// 空の成功候補はhead更新にも署名準備にも使いません。
	if( records.data->records.empty()) {
		return result ;
	}

	auto expiry = std::chrono::sys_seconds::max() ;	// 全原期限を延長せず最小値へ収束させます。
	// 全収録recordが現在有効な内容検査済み取得用途であることを確認します。
	for( const auto &record : records.data->records) {
		// UNKNOWNや他用途は新producerの取得候補へ混入させません。
		if( record.recordSchemaVersion != 2U || !record.acquisitionDescriptor ||
		   record.acquisitionDescriptor->state != IndexDescriptorState::KNOWN ||
		   record.inspectionStage != IndexInspectionStage::CONTENT_INSPECTED ||
		   !record.targetOs.value || record.architecture.value != IndexArchitecture::X64 ||
		   record.driverKind.value != IndexDriverKind::NORMAL_DRIVER ||
		   record.acquisition.value != IndexAcquisitionKind::STANDARD_INF_ARCHIVE ||
		   record.publishedIdentityEvidence.state != IndexEvidenceState::PUBLISHED ||
		   !record.packageEvidence.calculatedHash.sha256 || !record.packageEvidence.size.value) {
			return result ;
		}

		const auto &descriptor = *record.acquisitionDescriptor ;	// 同じ原申告です。
		// 個別期限をmanifest期限から推測せず実UTCへ照合します。
		if( !descriptor.attestation || descriptor.attestation->policyRevision != 1U ||
		   descriptor.attestation->checkedAtUtc > *nowUtc ||
		   *nowUtc >= descriptor.attestation->validUntilUtc || !descriptor.publisher.value ||
		   descriptor.terms.state == IndexTermsState::UNKNOWN ||
		   descriptor.prerequisites.state != IndexDescriptorState::KNOWN) {
			return result ;
		}

		expiry = std::min( expiry, descriptor.attestation->validUntilUtc) ;
	}

	// 候補は最小期限へ厳密一致させ、古いrecordの期限をbuildで延長しません。
	if( expiry != decodedManifest.data->expiresAtUtc) {
		result.status = UnsignedIndexCandidateStatus::MINIMUM_EXPIRY_MISMATCH ;
		return result ;
	}

	result.status  = UnsignedIndexCandidateStatus::VALIDATED ;
	result.receipt = UnsignedIndexCandidateReceipt{
		std::move( *decodedManifest.data), records.data->quality, asset.data->expandedSha256} ;
	return result ;
}
} // namespace drivercrate
