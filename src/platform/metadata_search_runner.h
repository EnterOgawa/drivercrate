//------------------------------------------------------------------------------
/**
 * @file metadata_search_runner.h
 * @brief Registry経由の非取得情報検索を実行する内部契約。
 * @version 01.00.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  非取得専用のRegistry実行境界を追加。
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 通常scan・準備・導入callbackを受け取らず、immutable表示値だけを返す。
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "core/metadata_search_budget.h"
#include "core/scan_measurement.h"
#include "core/update_provider.h"
#include "platform/official_catalog_device.h"

#include <functional>
#include <span>

namespace drivercrate {

/**
 * @brief Registryが固定した専用callback。Native ID、matcher、rank、取得serviceは渡さない。
 */
using MetadataProviderScan =
	std::function<ScanResult( ScanSessionId, std::span<const OfficialCatalogDevice>, bool,
							 std::uint32_t, MetadataSearchExecutionContext &,
							 const ProviderProgressCallback &, ProviderMeasurementEvidence &)> ;
/**
 * @brief 現在属性専用のinventory境界。TestではOS APIを呼ばないfakeへ差し替える。
 */
using MetadataInventoryScan =
	std::function<ScanResult( ScanSessionId, MetadataSearchExecutionContext &,
							 const ProviderProgressCallback &, DeviceInventoryMeasurement &)> ;

/** @brief 正本registryから一回の実行中だけ作る、専用callbackの借用snapshot。 */
struct MetadataSearchRegistration {
	/// 正本と完全一致させる登録定義。
	ProviderDescriptor	 descriptor ;
	/// 専用能力を持つ登録だけのcallback。未対応は空。
	MetadataProviderScan scan ;
} ;

/**
 * @brief 全registryのdescriptorと専用能力・callbackの両側を検証する。
 * @param[in] registrations 正本registryから得た有限snapshot。順序には依存しない。
 * @return 正本と同じ一意集合で、能力とcallbackが完全対応する場合true。
 */
[[nodiscard]] bool validateMetadataSearchRegistrations(
	std::span<const MetadataSearchRegistration> registrations) noexcept ;

/**
 * @brief 現在属性と明示した公式情報を有界実行し、非導入の部分結果を保持する。
 * @param[in] session Contextと同じ非ゼロsession。
 * @param[in] request 空でない専用Provider集合と今回の回線許可。
 * @param[in,out] execution Workerが所有し、inventoryを含む実行全体へ借用する予算。
 * @param[in] registrations 既存registryの専用callback。別のProvider一覧を作らない。
 * @param[in] inventory 現在属性だけを取得する必須依存。
 * @param[in] measurementContext 開始時刻、OS、実行版の固定条件。選択集合は要求から設定する。
 * @param[in] progress UIへの確定進捗通知。取消しを含む通常の例外はcallerが処理する。
 * @return 全registryの終端と専用summary。契約不正ではsummaryを発行しない。
 * @note 20／70／10の段階配分。未実行Provider分を架空の進捗で埋めない。
 */
[[nodiscard]] ScanResult runMetadataSearch(
	ScanSessionId session, const MetadataSearchRequest &request,
	MetadataSearchExecutionContext			   &execution,
	std::span<const MetadataSearchRegistration> registrations,
	const MetadataInventoryScan &inventory, ScanMeasurementContext measurementContext,
	const ProviderProgressCallback &progress) ;

} // namespace drivercrate
