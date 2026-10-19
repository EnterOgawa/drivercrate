//------------------------------------------------------------------------------
/**
 * @file local_coverage.h
 * @brief Local候補到達集計定義。
 * @version 01.00.00
 * @date 2026/09/02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Manufacturer intake分類追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Scan時点の段階別計測を保持する更新関数を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 現在scanの表示用candidateからmanufacturer／setup class別の候補到達件数を端末内だけで集計します。候補0件を最新または未対応とは判定しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace drivercrate {

/**
 * @brief Manufacturer表示名をロードマップ審査状態へ分類する。
 * S63+ intakeの端末内表示にだけ使用する。分類結果をProvider routing、適用性判定、候補選択へ使用しない。
 * @param[in] manufacturer 現在device propertyから得た表示名。本呼出し中だけ参照する。 現在device propertyの表示名。
 * @return 明示aliasへ一致した審査状態。一致しない非空表示名は`PENDING_INTAKE`。 明示aliasへ一致した審査状態。未一致の非空keyは`PENDING_INTAKE`
 *         、空keyは`UNIDENTIFIED`。
 * @note 端末内のS63+ intake表示にだけ使用する。Provider routing、driver適用性、候補選択には使用しない。
 */
[[nodiscard]] ManufacturerReviewState classifyManufacturerReviewState(
	std::wstring_view manufacturer) ;

/**
 * @brief 現在deviceを母数として取得元種別ごとの候補到達device数を集計する。
 * 現在deviceを母数として取得元別の候補到達件数を集計する。
 * 現在版行からpresent deviceの母数を作り、非現在版候補をopaque device identityでlocal照合して一device一回数える。Local照合できない候補は推測で
 * groupへ割り当てない。
 * @param[in] candidates Aggregateが検証済みの現在scan表示候補。 Aggregate検証済みの現在scan表示候補。
 * @param[in] providers Candidateのstable Provider IDとtrust boundaryを解決するregistry。 Stable IDとtrust
 *                   boundaryを持つregistry。
 * @return 成功時はmanufacturer／setup class順の集計。契約違反時は`std::nullopt`。 成功時はmanufacturer／setup class順の集計。
 *         Providerまたはinventory契約違反時は`std::nullopt`。
 * @note Hardware ID、instance ID、serial numberは入力または出力に含めない。Local deviceへ照合できない候補は推測でgroupへ割り当てない。
 */
[[nodiscard]] std::optional<std::vector<LocalCoverageEntry>> aggregateLocalCoverage(
	std::span<const UpdateCandidate> candidates, std::span<const ProviderDescriptor> providers) ;

/**
 * @brief 候補準備後の従来集計へscan完了時点の段階別計測を引き継ぐ。
 * @param[in] scanCoverage Scan完了時点に固定したmanufacturer／class別集計。
 * @param[in,out] refreshedCoverage 現在版母数を変えずに候補到達だけを再集計した値。
 * @return Group集合とdevice母数が完全一致し、全measurementを引き継いだ場合はtrue。
 * @note 段階別件数を追加候補から再計算せず、準備後もscan snapshotを維持する。
 */
[[nodiscard]] bool preserveLocalCoverageMeasurements(
	std::span<const LocalCoverageEntry> scanCoverage,
	std::span<LocalCoverageEntry>		refreshedCoverage) noexcept ;

} // namespace drivercrate
