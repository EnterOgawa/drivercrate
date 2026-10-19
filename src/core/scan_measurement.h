//------------------------------------------------------------------------------
/**
 * @file scan_measurement.h
 * @brief Worker内計測根拠と段階別和集合の純粋集計契約。
 * @version 01.00.00
 * @date 2026/09/10
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  有限な根拠集合とfail-closed集計を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  公式HTTP取得根拠の非機密要約を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  UI公開前の計測snapshot検証を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  有界列挙の終端・一回probe分類を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Evidenceはworker内だけに保持し、UI結果へは件数のみを渡します。Native IDを保持しません。
 * @see docs/adr/0139-local-scan-measurement-contract.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/scan_measurement_types.h"
#include "core/update_types.h"

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {

inline constexpr std::size_t MEASUREMENT_DEVICE_LIMIT	 = 4096 ;	// 既存local node保持上限。
inline constexpr std::size_t MEASUREMENT_CANDIDATE_LIMIT = 32768 ;	// 既存候補保持上限。
inline constexpr std::size_t MEASUREMENT_RESOURCE_LIMIT	 = 4096 ;	// 一Providerの取得根拠保持上限。

/** @brief 有界列挙の本体loopが停止した理由を表す。 */
enum class BoundedEnumerationStop {
	/// 上限前に列挙APIの正常終端を確認した。
	NORMAL_END,
	/// 上限件数を保持し、次の一件をprobeする必要がある。
	LIMIT,
	/// 上限前に列挙APIが失敗した。
	API_FAILURE,
} ;

/** @brief 上限ちょうどで実行する最大一回の追加probe結果を表す。 */
enum class BoundedEnumerationProbe {
	/// 上限未到達のため追加probeを実行していない。
	NOT_RUN,
	/// 次のindexで列挙APIの正常終端を確認した。
	NORMAL_END,
	/// 保持しない次の一件が存在した。
	ELEMENT_FOUND,
	/// 次のindexの確認自体が失敗した。
	API_FAILURE,
} ;

/** @brief 有界列挙の保持数と実観測下限を分けた純粋な分類結果。 */
struct BoundedEnumerationMeasurement {
	/// 追加probeで確認した一件を含む観測数。
	CountMeasurement observedItemCount ;
	/// 正常終端を確認した場合だけtrue。
	bool			 enumerationComplete{} ;
	/// 上限外の実要素を確認した場合だけtrue。
	bool			 limitExceeded{} ;
	/// 列挙またはprobe失敗の診断値。成功時は0。
	NativeError		 error{} ;
} ;

/** @brief Workerが実際の観測地点で得たopaque device集合である。 */
struct MeasurementDeviceSet {
	/// 集合全体の観測確定度。
	MeasurementExtent		  extent{MeasurementExtent::NOT_MEASURED} ;
	/// 重複しないD内identity。最大4096件。
	std::vector<std::wstring> identities ;
} ;

/** @brief 検証済みmetadataの一recordと一意matcherが結合したlocal nodeを表す。 */
struct MeasurementRecordEvidence {
	/// Providerがsession内で発行するopaque record ID。
	std::wstring			  identity ;
	/// 一意に結合できたD内node。空なら未照合record。
	std::vector<std::wstring> deviceIdentities ;
} ;

/** @brief 対象・検索完了・情報到達を各Providerの実観測地点から受け取る。 */
struct ProviderMeasurementEvidence {
	/// Registryへ完全一致させる発行元。
	std::wstring						   providerId ;
	/// 全根拠を拘束する非ゼロsession。
	ScanSessionId						   scanSessionId{} ;
	/// Device別検索証拠の有無。
	MeasurementScope					   scope{MeasurementScope::LEGACY_UNKNOWN} ;
	/// Payload処理と独立した検索結果。
	OutcomeCode							   queryOutcome{OutcomeCode::NOT_STARTED} ;
	/// 明示した探索条件へ一致したnode。
	MeasurementDeviceSet				   eligible ;
	/// 当該nodeの検索を正常に完了した根拠。
	MeasurementDeviceSet				   queryCompleted ;
	/// Originとschemaを検証した具体的情報の到達根拠。
	MeasurementDeviceSet				   information ;
	/// 件数を自己申告せず、候補監査から導く集合の完全性だけを指定する。
	MeasurementExtent					   applicabilityExtent{MeasurementExtent::NOT_MEASURED} ;
	/// Routing確定範囲の完全性。
	MeasurementExtent					   readinessExtent{MeasurementExtent::NOT_MEASURED} ;
	/// Record識別・列挙の完全性。
	MeasurementExtent					   recordExtent{MeasurementExtent::NOT_MEASURED} ;
	/// 最大32768record、結合総数も32768以下。
	std::vector<MeasurementRecordEvidence> records ;
	/// URLを含まない固定source・実取得経路。最大4096件。
	std::vector<MeasurementResource>	   resources ;
} ;

/** @brief Registry IDとUI公開可能な集計を対応付ける。 */
struct ProviderMeasurementEntry {
	/// 既存registryのID。別のProvider一覧ではない。
	std::wstring		providerId ;
	/// Identity集合を含まない所有値。
	ProviderMeasurement measurement ;
} ;

/** @brief 一回の純粋集計の出力をまとめる。 */
struct ScanMeasurementAggregation {
	/// Scan完了時点へ固定する集計。
	ScanMeasurement						  snapshot ;
	/// Registry順のProvider別結果。
	std::vector<ProviderMeasurementEntry> providers ;
	/// 既存groupと段階別集計。表示制限前の全group。
	std::vector<LocalCoverageEntry>		  localCoverage ;
} ;

/**
 * @brief 数値の有無と確定度が矛盾しないか確認する。
 * @param[in] measurement 検査する件数。
 * @return 既知enumでEXACT／LOWER_BOUNDだけが値を持つ場合はtrue。
 */
[[nodiscard]] bool isCountMeasurementValid( const CountMeasurement &measurement) noexcept ;

/**
 * @brief 有界列挙の停止点と一回probeから確定度付き観測数を作る。
 * @param[in] retainedItemCount 上限内で実際に保持した要素数。
 * @param[in] itemLimit 列挙本体が保持できる正の上限。
 * @param[in] stop 本体loopが停止した理由。
 * @param[in] probe 上限時だけ実行した次の一件の確認結果。
 * @param[in] error API_FAILUREの診断値。それ以外は0。
 * @return 入力が整合する場合は分類結果、矛盾またはoverflow時は値なし。
 * @note OS APIを呼ばず、上限到達だけを正常終端へ読み替えない。
 */
[[nodiscard]] std::optional<BoundedEnumerationMeasurement> classifyBoundedEnumeration(
	std::uint64_t retainedItemCount, std::uint64_t itemLimit, BoundedEnumerationStop stop,
	BoundedEnumerationProbe probe, NativeError error) noexcept ;

/**
 * @brief 公式HTTP ledgerをURLなしの計測resourceへ変換する。
 * @param[in] evidence 同一Provider・sessionの連続した取得根拠。
 * @param[out] resources 成功時の固定policy／resource ID、実取得経路、時刻。失敗時は空。
 * @return 全根拠がregistry・連番・実取得経路の契約を満たす場合はtrue。
 * @note Network、cache I/O、時刻取得を行わず、既存根拠だけをcopyする。
 */
[[nodiscard]] bool summarizeOfficialSourceEvidence(
	std::span<const OfficialSourceEvidence> evidence,
	std::vector<MeasurementResource>	   &resources) noexcept ;

/**
 * @brief Workerが公開するscan計測をoperation、session、DTO全体へ再照合する。
 * @param[in] operationId UIが発行した現在の非ゼロscan operation ID。
 * @param[in] result Compositeの候補、Provider report、group、任意measurementを持つ結果。
 * @return Measurementなし、または全公開値が同じoperation／sessionと件数契約を満たす場合はtrue。
 * @note 不正measurementを候補scan失敗へ昇格させず、Controllerが計測だけを破棄するために使う。
 */
[[nodiscard]] bool isPublishedScanMeasurementValid( OperationId		 operationId,
												   const ScanResult &result) noexcept ;

/**
 * @brief Local現在版を母数に、検証済み根拠と候補から段階別和集合を作る。
 * @param[in] context Scan開始時に固定した条件。operationIdはworker公開直前の設定まで0を許す。
 * @param[in] candidates 同一sessionの全表示候補。Filterや取得元groupで削除していない集合。
 * @param[in] providers 既存registryの定義。重複IDや信頼境界の重複を拒否する。
 * @param[in] inventory 詳細列挙地点の根拠。未接続なら既定値を渡す。
 * @param[in] evidence Worker内観測地点の根拠。未接続Providerは省略し旧二値を使わない。
 * @param[in] routableCandidateIds 既存install routingが保持する候補ID。権限を新規発行しない。
 * @return 正常時は所有値の集計。上限、identity、集合または候補契約に反する場合は値なし。
 * @note 通信・OS API・永続化を行わず入力を変更しない。A／Iは既存監査validatorからのみ導く。
 * @warning 計測失敗で正常候補の導入権限を増減しない。既存候補契約違反は別途scanを拒否する。
 */
[[nodiscard]] std::optional<ScanMeasurementAggregation> aggregateScanMeasurement(
	const ScanMeasurementContext &context, std::span<const UpdateCandidate> candidates,
	std::span<const ProviderDescriptor> providers, const DeviceInventoryMeasurement &inventory,
	std::span<const ProviderMeasurementEvidence> evidence,
	std::span<const std::wstring>				 routableCandidateIds) ;

} // namespace drivercrate
