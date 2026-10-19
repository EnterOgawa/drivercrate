//------------------------------------------------------------------------------
/**
 * @file scan_measurement_diagnostics.h
 * @brief 固定条件scanの明示実行profileと非機密ASCII出力契約。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  固定profileと計測reportの出力境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  ReportのID照合と限定失敗診断を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  有効context集合の照合と固定順出力を契約へ明記。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/10/12  明示9件と通常既定10件を分け31登録の照合契約を更新。
 * </pre>
 *
 * @note Test専用の明示実行入口から利用し、通常アプリの保存・通信経路へ接続しません。
 *       Candidate、device、URL、path、EULAおよび任意branch文字列は出力しません。
 * @see docs/adr/0140-read-only-scan-measurement-run.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate::test {

inline constexpr std::string_view SCAN_MEASUREMENT_PROFILE_ID =
	"reviewed-defaults-20260910-v1" ;									// 初回実測条件を識別する固定ASCII ID。
inline constexpr std::uint32_t SCAN_MEASUREMENT_PROFILE_REVISION = 1U ;	// 固定profile schema版。
inline constexpr std::uint32_t SCAN_MEASUREMENT_REPORT_REVISION	 = 1U ;	// ASCII report schema版。
inline constexpr std::size_t   SCAN_MEASUREMENT_REPORT_MAXIMUM_BYTES =
	1024U * 1024U ;	// 完全構築後に一回出力できるreport上限。
inline constexpr std::size_t SCAN_MEASUREMENT_FAILURE_MAXIMUM_BYTES =
	1024U ;	// 固定失敗recordのbyte上限。

/** @brief Report本文の書込み前に判明した拒否地点を表す。 */
enum class ScanMeasurementFailureReason {
	/// Worker eventまたはmessage受信経路を拒否した。
	WORKER_EVENT_REJECTED,
	/// Worker停止後に完了結果が存在しない。
	SCAN_RESULT_MISSING,
	/// Controllerが完了または候補sessionを受理しなかった。
	CONTROLLER_REJECTED,
	/// 公開計測が欠落している。
	MEASUREMENT_MISSING,
	/// 公開計測validatorが矛盾を検出した。
	PUBLISHED_MEASUREMENT_REJECTED,
	/// Exportの完全構築を拒否した。
	REPORT_CONTRACT_REJECTED,
} ;

/** @brief 計測用command lineを外部処理開始前に分類する。 */
enum class ScanMeasurementCommand {
	/// 条件表示だけを行いworkerを構築しない。
	DESCRIBE_BASELINE,
	/// 固定profileを解決した後で一回だけscanする。
	RUN_BASELINE,
	/// 未知、重複または任意入力を開始前に拒否する。
	REJECTED,
} ;

/** @brief 完全な計測reportの構築・一回出力結果を表す。 */
enum class ScanMeasurementReportStatus {
	/// 有効なreportを出力し全scanが成功した。
	SUCCESS,
	/// 有効なreportを出力したが個別失敗を含む。
	PARTIAL_SUCCESS,
	/// Snapshot、profileまたは容量の契約に反した。
	CONTRACT_REJECTED,
	/// 一回writeまたは明示flushが失敗した。
	OUTPUT_FAILED,
} ;

/**
 * @brief 実行file名を除いた引数を副作用なしで分類する。
 * @param[in] arguments 呼出し中だけ借用する引数。各値は完全一致で比較する。
 * @return 引数なし／describe、単一run、または拒否の分類。
 * @note Provider、COM、device、cache、networkおよびfile I/Oを開始しません。
 */
[[nodiscard]] ScanMeasurementCommand parseScanMeasurementArguments(
	std::span<const std::wstring_view> arguments) noexcept ;

/**
 * @brief 初回実測で明示的に有効にするstable Provider IDを固定順で返す。
 * @return Process lifetime中有効な9 IDの非所有view。
 */
[[nodiscard]] std::span<const std::wstring_view> baselineScanProviderIds() noexcept ;

/**
 * @brief 全31登録と通常既定10件を確認し、測定の明示9件を維持する。
 * @param[in] descriptors 検証するProvider registry snapshot。
 * @return ID、既定集合、capabilityおよび公式policy境界が一致する場合true。
 * @note 索引は固定の通常SCAN／INSTALL能力だけを確認し、測定profileでは無効です。
 *       元9件以外の追加既定Providerや索引能力の変更を暗黙採用しません。
 */
[[nodiscard]] bool								 isBaselineScanRegistryCompatible(
								  std::span<const ProviderDescriptor> descriptors) noexcept ;

/**
 * @brief 組み込みregistryから固定profileの明示ScanOptionsを解決する。
 * @param[out] options 成功時だけ更新する所有設定。失敗時は変更しない。
 * @return 全31登録と明示9／無効22の設定が既存validatorへ一致する場合true。
 * @note Inspection同意は全てfalse、利用者指定fileは空に固定します。
 */
[[nodiscard]] bool resolveBaselineScanOptions( ScanOptions &options) noexcept ;

/**
 * @brief Workerを作らず固定profileと既存scanの副作用条件をASCIIへ構築する。
 * @param[out] description 成功時だけ更新する完全な条件表示。失敗時は変更しない。
 * @return 固定profileを現registryへ照合して構築できた場合true。
 */
[[nodiscard]] bool buildBaselineScanDescription( std::string &description) noexcept ;

/**
 * @brief 完全な条件表示を一回writeし、明示flushする。
 * @param[in,out] output 呼出し中だけ借用するnarrow stream。失敗状態は解除しない。
 * @return 構築、全byte書込みおよびflushが成功した場合true。
 */
[[nodiscard]] bool writeBaselineScanDescription( std::ostream &output) noexcept ;

/**
 * @brief 固定enumだけの1 KiB以下の失敗recordを一回writeしてflushする。
 * @param[in,out] output 呼出し中だけ借用するstream。既存失敗状態を解除しない。
 * @param[in] reason 本文出力前に確定した拒否理由。未知enumは無出力で拒否する。
 * @return 構築、全byte書込みとflushが成功した場合true。
 * @note Reportまたは診断のI/O失敗後の再送に使用しません。任意文字列を受け取りません。
 */
[[nodiscard]] bool writeScanMeasurementFailure( std::ostream				   &output,
											   ScanMeasurementFailureReason reason) noexcept ;

/**
 * @brief 公開済みscan snapshotを検証し、1 MiB以下の固定ASCII reportを構築する。
 * @param[in] operationId Controllerが発行した現在の非ゼロscan operation ID。
 * @param[in] applicationVersion CMake生成値から渡す実行中application version。
 * @param[in] options Workerへ渡した固定profileのScanOptions。
 * @param[in] result ProviderWorkerから受け取りControllerへ適用したscan結果。
 * @param[out] report 成功時だけ更新する完全report。失敗時は変更しない。
 * @return Profile、registry、snapshot、enum、固定IDおよび容量が全て有効な場合true。
 * @note 任意の候補文字列とbranch文字列を読み出力へ複写しません。
 *       Reportをstable IDで一対一に照合し、入力順に依存せずregistry順で出力します。
 *       Contextの有効9 IDも一意集合として照合し、headerは固定profile順で出力します。
 *       実行用optionsの固定順は維持し、元contextとreportの配列を変更しません。
 */
[[nodiscard]] bool buildScanMeasurementReport( OperationId		 operationId,
											  std::wstring_view	 applicationVersion,
											  const ScanOptions &options, const ScanResult &result,
											  std::string &report) noexcept ;

/**
 * @brief 検証・完全構築したreportを一回writeし、明示flushする。
 * @param[in,out] output 呼出し中だけ借用するnarrow stream。失敗状態は解除しない。
 * @param[in] operationId Controllerが発行した現在の非ゼロscan operation ID。
 * @param[in] applicationVersion CMake生成値から渡す実行中application version。
 * @param[in] options Workerへ渡した固定profileのScanOptions。
 * @param[in] result ProviderWorkerから受け取りControllerへ適用したscan結果。
 * @return 全成功、部分成功、契約拒否またはI/O失敗の分類。
 * @note 部分writeを再試行せず、I/O失敗をscan成功へ読み替えません。
 */
[[nodiscard]] ScanMeasurementReportStatus writeScanMeasurementReport(
	std::ostream &output, OperationId operationId, std::wstring_view applicationVersion,
	const ScanOptions &options, const ScanResult &result) noexcept ;

} // namespace drivercrate::test
