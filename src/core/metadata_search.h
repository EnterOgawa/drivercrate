//------------------------------------------------------------------------------
/**
 * @file metadata_search.h
 * @brief 情報検索requestと結果の純粋検証。
 * @version 01.00.00
 * @date 2026/09/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  Metadata専用検索の契約を追加。
 * </pre>
 *
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/metadata_search_types.h"
#include "core/update_types.h"

#include <span>

namespace drivercrate {

/**
 * @brief 専用検索能力と公式source policyの整合性を検証する。
 * @param[in] descriptor 検証する一つの登録定義。
 * @return 既知能力だけを持ち、専用検索と固定公式sourceが整合する場合true。
 */
[[nodiscard]] bool isMetadataSearchProvider( const ProviderDescriptor &descriptor) noexcept ;

/**
 * @brief 明示した有限集合を検証し、未知・重複・未対応・未知policyを拒否する。
 * @param[in] request 所有値として受け渡される今回の要求。
 * @param[in] descriptors Registryの正本。Testでは能力追加前の合成snapshotを渡せる。
 * @return 全入力が整合し、一つ以上の専用Providerを明示した場合true。
 * @note I/Oもsession失効も行わない。
 */
[[nodiscard]] bool validateMetadataSearchRequest(
	const MetadataSearchRequest &request, std::span<const ProviderDescriptor> descriptors) noexcept ;

/**
 * @brief 新modeの候補に取得・導入権限が混入していないか検証する。
 * @param[in] result 同一sessionの情報検索結果。
 * @return METADATA_ONLYかつ全候補が非推奨・非導入・NONEの場合true。
 * @note Operationとsummaryの照合は公開境界で別途実行する。
 */
[[nodiscard]] bool hasOnlyMetadataDisplayCandidates( const ScanResult &result) noexcept ;

/**
 * @brief 公開する情報検索のrequest、全登録、件数、消費、非導入性を再照合する。
 * @param[in] operationId WorkerとUIで一致させる非ゼロ操作ID。
 * @param[in] request 開始時に固定した要求。結果側の自己申告から補完しない。
 * @param[in] result Worker公開直前またはUI受領時の所有結果。
 * @return 全snapshotが一致した場合true。矛盾した部分結果は一括で拒否する。
 */
[[nodiscard]] bool isMetadataSearchResultValid( OperationId					operationId,
											   const MetadataSearchRequest &request,
											   const ScanResult			   &result) noexcept ;

} // namespace drivercrate
