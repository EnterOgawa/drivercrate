//------------------------------------------------------------------------------
/**
 * @file update_provider.cpp
 * @brief 任意取得準備APIの未対応時動作。
 * @version 01.01.00
 * @date 2026/09/06
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の表示境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得計画とworker実行を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索専用の型と拒否境界を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  通常scan取消しの互換委譲を追加。
 * </pre>
 *
 * @note 未対応Providerは取得計画なしと取得拒否を返し、既存導入を変更しません。
 */
//------------------------------------------------------------------------------

#include "core/update_provider.h"

#include <bit>
#include <cstdint>
#include <optional>
#include <vector>

namespace drivercrate {

/** @see update_provider.h */
ScanResult IUpdateProvider::scanMetadataOnly( const ScanSessionId			 scanSessionId,
											 const MetadataSearchRequest	&request,
											 MetadataSearchExecutionContext &execution,
											 const ProviderProgressCallback &progressCallback)
{
	static_cast<void>( request) ;
	static_cast<void>( execution) ;
	static_cast<void>( progressCallback) ;
	ScanResult result ;	// 通常scanや取得へ暗黙移行しない拒否結果。
	result.scanSessionId = scanSessionId ;
	result.purpose		 = ScanPurpose::METADATA_ONLY ;
	result.outcome		 = OutcomeCode::FAILURE ;
	result.state		 = ProviderScanState::FAILURE ;
	result.error		 = std::bit_cast<NativeError>( std::uint32_t{0x80004001U}) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult IUpdateProvider::scanWithCancellation( const ScanSessionId			 scanSessionId,
												 const ScanOptions				&options,
												 const ProviderScanCancellation &cancellation,
												 const ProviderProgressCallback &progressCallback)
{
	static_cast<void>( cancellation) ;
	return scan( scanSessionId, options, progressCallback) ;
}
//------------------------------------------------------------------------------
/**
 * @see src/core/update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::optional<OfficialPreparationPlan> IUpdateProvider::preparationPlan(
	const ScanSessionId scanSessionId, const std::uint64_t planId)
{
	static_cast<void>( scanSessionId) ;
	static_cast<void>( planId) ;
	return std::nullopt ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialPreparationTransferResult IUpdateProvider::acquireForInspection(
	const OfficialPreparationTask &task, const PreparationCancellation &cancellation)
{
	static_cast<void>( task) ;
	static_cast<void>( cancellation) ;
	return {OfficialPreparationItemState::REJECTED,
			std::bit_cast<NativeError>( std::uint32_t{0x80004001U}), 0U} ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void IUpdateProvider::invalidatePreparation() noexcept
{
}

//------------------------------------------------------------------------------
/**
 * @see src/core/update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------

std::vector<OfficialPreparationAuditReport> IUpdateProvider::preparationAuditReports(
	const OfficialPreparationOperationResult &result)
{
	static_cast<void>( result) ;
	return {} ;
}

} // namespace drivercrate
