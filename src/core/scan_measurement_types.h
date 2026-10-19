//------------------------------------------------------------------------------
/**
 * @file scan_measurement_types.h
 * @brief Scan完了時点の段階別件数と計測条件の所有値。
 * @version 01.00.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  未計測と段階別到達を区別する値型を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * </pre>
 *
 * @note 件数は表示用であり、取得・監査・導入の許可ではありません。端末identity集合は保持しません。
 * @see docs/adr/0139-local-scan-measurement-contract.md
 */
//------------------------------------------------------------------------------

#pragma once
#include "core/metadata_search_types.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace drivercrate {

/** @brief 宣言された探索範囲に対する件数の確定度を表す。 */
enum class MeasurementExtent {
	/// 未実行または計測未接続であり値を持たない。
	NOT_MEASURED,
	/// 当該指標の範囲で確定した件数である。
	EXACT,
	/// 確認済みの下限であり、残りの存在を否定しない。
	LOWER_BOUND,
	/// 計測を信用できず有効な値を示せない。
	UNAVAILABLE,
} ;

/** @brief 未計測をゼロと区別する件数と確定度の組である。 */
struct CountMeasurement {
	/// EXACT／LOWER_BOUNDだけが値を持つ。
	std::optional<std::uint64_t> value ;
	/// 初期状態は未計測。
	MeasurementExtent			 extent{MeasurementExtent::NOT_MEASURED} ;
} ;

/** @brief 対象、検索完了、情報到達、適用可能更新、準備完了更新を別単位で保持する。 */
struct StageDeviceCounts {
	/// 探索条件に該当したlocal node数。
	CountMeasurement eligibleDeviceCount ;
	/// 個別検索の正常完了を確認したnode数。
	CountMeasurement queryCompletedDeviceCount ;
	/// 検証済み具体的情報へ結合できたnode数。
	CountMeasurement informationDeviceCount ;
	/// 適用性を確認した通常更新があるnode数。
	CountMeasurement applicableUpdateDeviceCount ;
	/// 既存routingとREADYを満たす通常更新のnode数。
	CountMeasurement installReadyUpdateDeviceCount ;
} ;

/** @brief Network取得元を信頼境界別と和集合で示す。 */
struct NetworkCoverageMeasurement {
	/// 両境界をdevice単位で重複排除した和集合。
	StageDeviceCounts combined ;
	/// Windows管理serviceだけの和集合。
	StageDeviceCounts managed ;
	/// 公式networkだけの和集合。
	StageDeviceCounts official ;
} ;

/** @brief Providerが発行できる個別検索の証拠範囲を表す。 */
enum class MeasurementScope {
	/// 従来二値しかなく個別集合を推測できない。
	LEGACY_UNKNOWN,
	/// Deviceごとの検索完了を記録できる。
	DEVICE_QUERY,
	/// System全体queryであり成功をdevice別へ配賦しない。
	SYSTEM_QUERY,
} ;

/** @brief 計測・検索が未完了となった理由を本文なしで表す。 */
enum class MeasurementReason {
	/// 設定で検索が無効である。
	DISABLED,
	/// 必要条件の不一致を確認した。
	NOT_APPLICABLE,
	/// 対象処理へ未着手である。
	NOT_STARTED,
	/// 条件判定に必要な属性がない。
	MISSING_ATTRIBUTE,
	/// 新計測の観測地点が未接続である。
	ADAPTER_UNCONNECTED,
	/// 宣言した検索範囲で情報なしを確認した。
	NO_INFORMATION,
	/// 通信または検索APIが失敗した。
	QUERY_FAILED,
	/// 公式取得元の規則に反した。
	SOURCE_REJECTED,
	/// Schema等のmetadata検証に失敗した。
	METADATA_REJECTED,
	/// 検査用取得の明示同意がない。
	INSPECTION_CONSENT_REQUIRED,
	/// 検査用payloadの取得が失敗した。
	DOWNLOAD_FAILED,
	/// 取得物の内容を監査で拒否した。
	CONTENT_REJECTED,
	/// System適用性をまだ確認していない。
	APPLICABILITY_PENDING,
	/// System適用性の監査で拒否した。
	APPLICABILITY_REJECTED,
	/// Local nodeへ一致しなかった。
	UNMATCHED,
	/// 複数一致で一意に結合できなかった。
	AMBIGUOUS_MATCH,
	/// 照合自体を完了できなかった。
	MATCH_UNAVAILABLE,
	/// 実際に処理を取り消した。
	ABORTED,
	/// 有限な保持上限に達した。
	LIMIT_REACHED,
	/// 列挙または詳細処理を完了していない。
	INCOMPLETE,
} ;

/** @brief 理由別件数の単位を区別する。 */
enum class MeasurementUnit {
	/// Opaque local nodeの重複排除件数。
	DEVICE,
	/// Provider内の識別済み情報record件数。
	RECORD,
	/// 定義された検索操作件数。
	QUERY,
	/// 実際のHTTP request件数。
	REQUEST,
} ;

/** @brief 固定理由と単位だけを持つ診断集計である。 */
struct MeasurementReasonCount {
	/// 実際の観測に基づく理由。
	MeasurementReason reason{MeasurementReason::NOT_STARTED} ;
	/// 数えた要素の種類。
	MeasurementUnit	  unit{MeasurementUnit::QUERY} ;
	/// 同理由・同単位の重複排除済み件数。
	std::uint64_t	  count{} ;
} ;

/** @brief OS列挙と一覧に表現できたlocal nodeを区別する。 */
struct DeviceInventoryMeasurement {
	/// 詳細列挙で実際に観測したnode数。
	CountMeasurement					enumeratedDeviceCount ;
	/// 有効なlocal現在版行の件数。
	CountMeasurement					representedDeviceCount ;
	/// 同一列挙から現在版行を発行できなかった数。
	CountMeasurement					unrepresentedDeviceCount ;
	/// 現在版行の製造元表示値の欠損数。
	CountMeasurement					missingManufacturerCount ;
	/// 現在版行のclass表示値の欠損数。
	CountMeasurement					missingClassCount ;
	/// 現在版行のINF版の欠損数。
	CountMeasurement					missingCurrentVersionCount ;
	/// 正常終端と詳細処理の完了を確認した場合だけtrue。
	bool								detailedEnumerationComplete{} ;
	/// 固定理由ごとの有限な診断内訳。
	std::vector<MeasurementReasonCount> reasons ;
	/// 元の列挙診断値。件数の確定度とは独立する。
	std::int32_t						error{} ;
} ;

/** @brief Cache使用方針と区別する実際の取得経路を表す。 */
enum class MeasurementAcquisition {
	/// 実取得経路の計測がない。
	UNKNOWN,
	/// 今回のnetwork本文を検証した。
	NETWORK_BODY,
	/// 有効期間内のcache本文を再検証した。
	FRESH_CACHE,
	/// 304と対応する検証済み本文を使った。
	REVALIDATED_CACHE,
	/// 複数resourceの実経路が混在する。
	MIXED,
	/// 公式HTTP経路ではない。
	NOT_APPLICABLE,
} ;

/** @brief 既存の取得結果から得た非機密な固定識別子と時刻を保持する。 */
struct MeasurementResource {
	/// 組み込みpolicyの固定ID。URLや製品名を含めない。
	std::wstring				 policyId ;
	/// Policy内で登録済みのresource ID。
	std::wstring				 resourceId ;
	/// 登録済み探索枝の固定ID。不明時は空。
	std::wstring				 branchId ;
	/// 使用したparser契約版。不明時は値なし。
	std::optional<std::uint32_t> parserRevision ;
	/// 本文取得UTCのUnix秒。不明時は値なし。
	std::optional<std::uint64_t> bodyAcquiredUtcSeconds ;
	/// Origin再検証UTCのUnix秒。
	std::optional<std::uint64_t> originValidatedUtcSeconds ;
	/// Cache許可方針。実cache hitの意味ではない。
	std::optional<bool>			 cachePermitted ;
	/// 実際の取得根拠。
	MeasurementAcquisition		 acquisition{MeasurementAcquisition::UNKNOWN} ;
} ;

/** @brief Providerの段階別集計をidentity集合なしでUIへ渡す。 */
struct ProviderMeasurement {
	/// 段階ごとの異なるdevice集合の件数。
	StageDeviceCounts					devices ;
	/// 個別検索証拠の範囲。
	MeasurementScope					scope{MeasurementScope::LEGACY_UNKNOWN} ;
	/// Localへ結合できない非現在版行数。
	CountMeasurement					unmatchedCandidateCount ;
	/// 識別根拠がある具体的な情報record数。
	CountMeasurement					informationRecordCount ;
	/// どのlocal nodeにも結合しないrecord数。
	CountMeasurement					unmatchedInformationRecordCount ;
	/// 理由・単位別の有限な集計。
	std::vector<MeasurementReasonCount> reasons ;
	/// 既存取得地点からの有限な取得根拠。
	std::vector<MeasurementResource>	resources ;
	/// 計測自体の診断。Provider元errorの代替にしない。
	std::int32_t						diagnostic{} ;
} ;

/** @brief 実測条件に記録するOS製品区分である。 */
enum class MeasurementOsKind {
	/// OS区分を取得できなかった。
	UNKNOWN,
	/// Windows clientである。
	CLIENT,
	/// Windows Serverである。
	SERVER,
} ;

/** @brief 一回のscan完了時点に固定する非機密な測定条件である。 */
struct ScanMeasurementContext {
	/// ADR 0139の計測契約版。
	std::uint32_t				 contractRevision{1} ;
	/// WorkerがUI公開前に設定する非ゼロoperation ID。
	std::uint64_t				 operationId{} ;
	/// 根拠と候補を拘束する非ゼロscan session ID。
	std::uint64_t				 scanSessionId{} ;
	/// Scan開始UTCのUnix秒。
	std::optional<std::uint64_t> startedUtcSeconds ;
	/// Scan完了UTCのUnix秒。
	std::optional<std::uint64_t> completedUtcSeconds ;
	/// 実行中のアプリ版。未接続時は空。
	std::wstring				 applicationVersion ;
	/// Workerが確認したOS区分。
	MeasurementOsKind			 osKind{MeasurementOsKind::UNKNOWN} ;
	/// Workerが確認したOS build。不明時は値なし。
	std::optional<std::uint32_t> osBuild ;
	/// 対応architectureを固定し他architectureの結果を受理しない。
	bool						 x64{true} ;
	/// Scan開始時の既定／明示選択の別。
	bool						 usedDefaultProviders{true} ;
	/// Registryから解決した固定済み有効ID集合。
	std::vector<std::wstring>	 enabledProviderIds ;
	/// 計測が表す検索用途。旧reportへ専用modeを混入させない。
	ScanPurpose					 purpose{ScanPurpose::STANDARD} ;
} ;

/** @brief 後続のfilter、準備、installで数え直さないscan時点の集計である。 */
struct ScanMeasurement {
	/// 集計対象のoperation、session、条件。
	ScanMeasurementContext	   context ;
	/// OS列挙と一覧母数の区別。
	DeviceInventoryMeasurement inventory ;
	/// 管理service／公式と全体の段階別和集合。
	NetworkCoverageMeasurement network ;
	/// Networkの未照合行数。Device数へ変換しない。
	CountMeasurement		   unmatchedCandidateCount ;
} ;

} // namespace drivercrate
