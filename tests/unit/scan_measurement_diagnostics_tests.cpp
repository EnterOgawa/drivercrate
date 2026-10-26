//------------------------------------------------------------------------------
/**
 * @file scan_measurement_diagnostics_tests.cpp
 * @brief 固定条件scan profileと非機密ASCII reportの決定的試験。
 * @version 01.00.04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  固定profileと出力拒否境界の試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Report順序、ID照合と限定失敗診断の回帰を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  有効集合と全reportの独立した順序変更を検証。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/15  組み込みProvider件数を更新。
 * Ver.01.00.02 Shunji Ogawa  2026/10/12  31登録と明示9件を分離し解決拒否後の空集合参照を防止。
 * Ver.01.00.03 Shunji Ogawa  2026/10/12  metadata探索判定の必要宣言を直接includeして単独compileを修正。
 * Ver.01.00.04 Shunji Ogawa  2026/10/24  必須解析に合わせ試験の所有・型・失敗制御を明示。
 * </pre>
 *
 * @note 架空candidate、公開registryの固定IDおよびfake streamだけを使います。
 *       実device列挙、network、cache、driver導入、PnP変更、復元APIを呼びません。
 */
//------------------------------------------------------------------------------

#include <memory>
#include "scan_measurement_diagnostics_tests.h"

#include "core/metadata_search.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "core/scan_measurement.h"
#include "core/update_types.h"
#include "support/scan_measurement_diagnostics.h"
#include "test_framework.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <optional>
#include <ostream>
#include <span>
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 合成fixture定数定義。
//------------------------------------------------------------------------------

constexpr OperationId		FIXTURE_OPERATION_ID	= 71U ;			// Controller採番を模した非ゼロID。
constexpr ScanSessionId		FIXTURE_SCAN_SESSION_ID = 109U ;		// 合成scanを拘束する非ゼロsession。
constexpr std::wstring_view FIXTURE_VERSION			= L"0.1.0" ;	// CMake版照合用の架空実行版。
constexpr std::wstring_view SECRET_SENTINEL =
	L"SENSITIVE_CANDIDATE_SENTINEL" ;	// Reportへ現れてはならない候補文字列。
constexpr std::wstring_view BRANCH_SENTINEL =
	L"SENSITIVE_BRANCH_SENTINEL" ;	// NOT_EXPORTEDへ置換される任意branch。
constexpr std::string_view SECRET_SENTINEL_ASCII =
	"SENSITIVE_CANDIDATE_SENTINEL" ;	// Narrow report内の候補sentinel検索値。
constexpr std::string_view BRANCH_SENTINEL_ASCII =
	"SENSITIVE_BRANCH_SENTINEL" ;	// Narrow report内のbranch sentinel検索値。

// Compositeのinventory、managed、公式と索引を含む全31 ID。Descriptor値は複製しない。
constexpr std::array<std::wstring_view, 31> PRODUCTION_REPORT_ORDER{
	DRIVER_STORE_PROVIDER_ID,
	WINDOWS_UPDATE_PROVIDER_ID,
	PROLIFIC_OFFICIAL_PROVIDER_ID,
	SILICON_LABS_OFFICIAL_PROVIDER_ID,
	WCH_OFFICIAL_PROVIDER_ID,
	WCH_MULTI_OFFICIAL_PROVIDER_ID,
	NVIDIA_PROVIDER_ID,
	INTEL_WIRELESS_PACKAGE_PROVIDER_ID,
	PROLIFIC_SERIAL_PACKAGE_PROVIDER_ID,
	SILICON_LABS_SERIAL_PACKAGE_PROVIDER_ID,
	WCH_SERIAL_PACKAGE_PROVIDER_ID,
	WCH_MULTI_SERIAL_PACKAGE_PROVIDER_ID,
	GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID,
	DELL_PROVIDER_ID,
	DELL_POWER_EDGE_PROVIDER_ID,
	LENOVO_PROVIDER_ID,
	HP_PROVIDER_ID,
	VAIO_PROVIDER_ID,
	AMD_PROVIDER_ID,
	ASUS_PROVIDER_ID,
	ASROCK_PROVIDER_ID,
	BROADCOM_NET_XTREME_PROVIDER_ID,
	INTEL_WIFI_OFFICIAL_PROVIDER_ID,
	INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID,
	INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID,
	ASIX_AX88179A_PROVIDER_ID,
	RICOH_UNIVERSAL_PRINT_PROVIDER_ID,
	WACOM_WINDOWS_PROVIDER_ID,
	FOCUSRITE_SCARLETT2I2_PROVIDER_ID,
	NVIDIA_WINOF2_PROVIDER_ID,
	SIGNED_INDEX_PROVIDER_ID,
} ;

//------------------------------------------------------------------------------
// Fake出力型定義。
//------------------------------------------------------------------------------

/** @brief 一回write／flushの故障位置を選ぶ。 */
enum class SinkFailure {
	/// 全byteとflushを受理する。
	NONE,
	/// 要求byteの一部だけを受理する。
	SHORT_WRITE,
	/// 全byte受理後にflush失敗を返す。
	FLUSH_FAILURE,
	/// Write時に例外を投げる。
	WRITE_EXCEPTION,
	/// Flush時に例外を投げる。
	FLUSH_EXCEPTION,
} ;

/** @brief Reportの一回write、部分出力、flushおよび再試行有無を観測する。 */
class DiagnosticBuffer final : public std::streambuf {
public:
	/**
	 * @brief 構築後に変えない故障modeを指定する。
	 * @param[in] failure Writeまたはflushへ注入する故障。
	 */
	explicit DiagnosticBuffer( const SinkFailure failure) : failure_( failure)
	{
	}

	/// 故障位置までに受理したASCII byte列。
	std::string bytes ;
	/// xsputn呼出し回数。
	std::size_t writeCount{} ;
	/// sync呼出し回数。
	std::size_t flushCount{} ;

protected:
	/**
	 * @brief 設定modeに従い要求byteを全部、一部、または例外として処理する。
	 * @param[in] data count byteを指す呼出し中だけの借用領域。
	 * @param[in] count 要求byte数。正数だけを保存する。
	 * @return 実際に受理したbyte数。
	 */
	std::streamsize xsputn( const char *data, const std::streamsize count) override
	{
		++writeCount ;
		// Write例外の呼出し境界と再試行禁止を検証する。
		if( failure_ == SinkFailure::WRITE_EXCEPTION) {
			throw std::runtime_error( "Synthetic report write failure.") ;
		}

		// 0以下の要求をsize_tへ変換せず、そのまま拒否する。
		if( count <= 0) {
			return 0 ;
		}

		const std::streamsize accepted =
			// 今回受理する長さ。
			failure_ == SinkFailure::SHORT_WRITE ? count / 2 : count ;
		bytes.append( data, static_cast<std::size_t>( accepted)) ;
		return accepted ;
	}

	/**
	 * @brief 設定modeに従いflush結果または例外を返す。
	 * @return 正常時0、明示故障時-1。
	 */
	int sync() override
	{
		++flushCount ;
		// Flush例外も公開helper内で失敗へ変換されることを確認する。
		if( failure_ == SinkFailure::FLUSH_EXCEPTION) {
			throw std::runtime_error( "Synthetic report flush failure.") ;
		}

		return failure_ == SinkFailure::FLUSH_FAILURE ? -1 : 0 ;
	}

private:
	/// 構築後に変更しない故障mode。
	const SinkFailure failure_ ;
} ;

//------------------------------------------------------------------------------
// 合成fixture関数定義。
//------------------------------------------------------------------------------

/**
 * @brief 値を持つEXACT件数を作る。
 * @param[in] value 合成する確定件数。
 * @return `EXACT:value`のCountMeasurement。
 */
[[nodiscard]] CountMeasurement exactCount( const std::uint64_t value)
{
	return {value, MeasurementExtent::EXACT} ;
}

/**
 * @brief 値を持つLOWER_BOUND件数を作る。
 * @param[in] value 合成する確認済み下限。
 * @return `LOWER_BOUND:value`のCountMeasurement。
 */
[[nodiscard]] CountMeasurement lowerBoundCount( const std::uint64_t value)
{
	return {value, MeasurementExtent::LOWER_BOUND} ;
}

/**
 * @brief 固定profileを解決し、test継続用の所有設定を返す。
 * @param[in,out] context 解決失敗を記録するAssertion集計先。
 * @return 実registryに一致した明示9 Provider設定。失敗時は既定値。
 */
[[nodiscard]] ScanOptions fixtureOptions( TestContext &context)
{
	ScanOptions options ;	// Helperから受け取る固定profile。
	DRIVERCRATE_EXPECT( context, resolveBaselineScanOptions( options)) ;
	return options ;
}

/**
 * @brief Device 0件で全31 reportを持つ有効な公開snapshotを作る。
 * @param[in] options Contextとreportの有効状態に使用する固定profile。
 * @param[in] outcome 全体scanのSUCCESSまたはSUCCEEDED_WITH_ERRORS。
 * @return Networkや実deviceへ接続しない合成ScanResult。
 */
[[nodiscard]] ScanResult fixtureResult( const ScanOptions &options,
									   const OutcomeCode  outcome = OutcomeCode::SUCCESS)
{
	ScanResult result ;	// 全31 Providerと新計測を保持する合成結果。
	result.succeeded	 = true ;
	result.scanSessionId = FIXTURE_SCAN_SESSION_ID ;
	result.outcome		 = outcome ;
	result.state		 = ProviderScanState::NO_CANDIDATES ;

	ScanMeasurement measurement ;	// Candidate identityを出力しない段階別snapshot。
	measurement.context.contractRevision			  = 1U ;
	measurement.context.operationId					  = FIXTURE_OPERATION_ID ;
	measurement.context.scanSessionId				  = FIXTURE_SCAN_SESSION_ID ;
	measurement.context.startedUtcSeconds			  = 1'788'912'000U ;
	measurement.context.completedUtcSeconds			  = 1'788'912'060U ;
	measurement.context.applicationVersion			  = FIXTURE_VERSION ;
	measurement.context.osKind						  = MeasurementOsKind::CLIENT ;
	measurement.context.osBuild						  = 26'100U ;
	measurement.context.x64							  = true ;
	measurement.context.usedDefaultProviders		  = false ;
	measurement.context.enabledProviderIds			  = options.enabledProviderIds ;
	measurement.inventory.enumeratedDeviceCount		  = exactCount( 0U) ;
	measurement.inventory.representedDeviceCount	  = exactCount( 0U) ;
	measurement.inventory.unrepresentedDeviceCount	  = exactCount( 0U) ;
	measurement.inventory.missingManufacturerCount	  = exactCount( 0U) ;
	measurement.inventory.missingClassCount			  = exactCount( 0U) ;
	measurement.inventory.missingCurrentVersionCount  = exactCount( 0U) ;
	measurement.inventory.detailedEnumerationComplete = true ;
	result.measurement								  = std::move( measurement) ;

	const std::span descriptors = builtInProviderDescriptors() ;	// Reportへcopyするregistry正本。
	result.providerReports.reserve( descriptors.size()) ;
	// 全31登録へ新計測を一対一で付け、無効22もreportとして保持する。
	for( const ProviderDescriptor &descriptor : descriptors) {
		const bool enabled = isProviderEnabled( options, descriptor) ;	// 固定profile内の状態。
		ProviderScanReport report ;										// 現在descriptorに対応する合成完了report。
		report.descriptor = descriptor ;
		report.state   = enabled ? ProviderScanState::NO_CANDIDATES : ProviderScanState::DISABLED ;
		report.outcome = enabled ? OutcomeCode::SUCCESS : OutcomeCode::NOT_STARTED ;
		report.coverage.measurement = ProviderMeasurement{} ;
		result.providerReports.push_back( std::move( report)) ;
	}

	return result ;
}

/**
 * @brief 指定Providerのreportをstable IDで検索する。
 * @param[in,out] result 検索対象の所有ScanResult。
 * @param[in] providerId 完全一致させる組み込みProvider ID。
 * @return 一致reportへの非所有pointer。欠落時はnullptr。
 */
[[nodiscard]] ProviderScanReport *findReport( ScanResult &result, const std::wstring_view providerId)
{
	const auto found = std::find_if( result.providerReports.begin(), result.providerReports.end(),
									[providerId]( const ProviderScanReport &report) {
										return report.descriptor.id == providerId ;
									}) ; // Stable IDへ完全一致したreport位置。
	return found == result.providerReports.end() ? nullptr : &*found ;
}

/**
 * @brief 登録済みresource一件をProvider measurementへ追加する。
 * @param[in,out] context 前提欠落を記録するAssertion集計先。
 * @param[in,out] result Resourceを追加する合成snapshot。
 * @param[in] providerId 公式policyを持つProvider ID。
 * @param[in] branch 任意branchの合成値。出力時は複写されない。
 * @return Resourceを追加できた場合true。
 */
[[nodiscard]] bool appendFixtureResource( TestContext &context, ScanResult &result,
										 const std::wstring_view providerId,
										 const std::wstring_view branch)
{
	ProviderScanReport *const		  report = findReport( result, providerId) ;	// 対象report。
	const OfficialSourcePolicy *const policy = officialSourcePolicyForProvider( providerId) ;
	DRIVERCRATE_EXPECT( context,
					   report != nullptr && policy != nullptr && !policy->resources.empty()) ;
	// Fixture前提が欠けた場合はnullを参照せず、呼出し側へ失敗を返す。
	if( report == nullptr || !report->coverage.measurement.has_value() || policy == nullptr ||
	   policy->resources.empty()) {
		return false ;
	}

	MeasurementResource resource ;	// URLを持たない登録済みresource要約。
	resource.policyId	 = policy->id ;
	resource.resourceId	 = policy->resources.front().id ;
	resource.branchId	 = branch ;
	resource.acquisition = MeasurementAcquisition::UNKNOWN ;
	report->coverage.measurement->resources.push_back( std::move( resource)) ;
	return true ;
}

/**
 * @brief 文字列内にある非重複開始位置の出現数を数える。
 * @param[in] text 検索対象ASCII文字列。
 * @param[in] token 空でない固定token。
 * @return 見つかった開始位置の件数。
 */
[[nodiscard]] std::size_t countOccurrences( const std::string_view text,
										   const std::string_view token)
{
	std::size_t count{} ;		// 検出済みtoken数。
	std::size_t position{} ;	// 次に検索を開始するbyte位置。
	// Token開始位置を順に進め、空tokenをfixtureから渡さない。
	while( !token.empty()) {
		const std::size_t found = text.find( token, position) ;	// 次の一致位置。
		// 残りに一致がなければ有限loopを終了する。
		if( found == std::string_view::npos) {
			break ;
		}

		++count ;
		position = found + token.size() ;
	}

	return count ;
}

//------------------------------------------------------------------------------
// 内部試験関数定義。
//------------------------------------------------------------------------------

/**
 * @brief 引数分類、固定9／無効22、同意falseとregistry drift拒否を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testArgumentsAndProfile( TestContext &context)
{
	const std::span<const std::wstring_view> noArguments ;							// 暗黙scanを禁止する空引数。
	const std::array describe{std::wstring_view( L"--describe-baseline")} ;			// 条件表示。
	const std::array run{std::wstring_view( L"--run-baseline")} ;					// 唯一の実行指定。
	const std::array unknown{std::wstring_view( L"--provider=nvidia-official")} ;	// 任意Provider。
	const std::array url{std::wstring_view( L"https://invalid.example/")} ;			// 任意URL。
	const std::array path{std::wstring_view( LR"(C:\fictional\input.zip)")} ;		// 任意path。
	const std::array duplicate{std::wstring_view( L"--run-baseline"),
							   // 重複実行option。
							   std::wstring_view( L"--run-baseline")} ;
	DRIVERCRATE_EXPECT( context, parseScanMeasurementArguments( noArguments) ==
									ScanMeasurementCommand::DESCRIBE_BASELINE) ;
	DRIVERCRATE_EXPECT( context, parseScanMeasurementArguments( describe) ==
									ScanMeasurementCommand::DESCRIBE_BASELINE) ;
	DRIVERCRATE_EXPECT( context,
					   parseScanMeasurementArguments( run) == ScanMeasurementCommand::RUN_BASELINE) ;
	DRIVERCRATE_EXPECT( context,
					   parseScanMeasurementArguments( unknown) == ScanMeasurementCommand::REJECTED) ;
	DRIVERCRATE_EXPECT( context,
					   parseScanMeasurementArguments( url) == ScanMeasurementCommand::REJECTED) ;
	DRIVERCRATE_EXPECT( context,
					   parseScanMeasurementArguments( path) == ScanMeasurementCommand::REJECTED) ;
	DRIVERCRATE_EXPECT( context, parseScanMeasurementArguments( duplicate) ==
									ScanMeasurementCommand::REJECTED) ;

	ScanOptions options = fixtureOptions( context) ;	// 実registryから解決した固定設定。
	DRIVERCRATE_EXPECT( context, !options.useDefaultProviders) ;
	DRIVERCRATE_EXPECT( context, options.enabledProviderIds.size() == 9U) ;
	DRIVERCRATE_EXPECT( context, options.userSelectedFiles.empty()) ;
	DRIVERCRATE_EXPECT(
		context, !options.prolificInspectionApproved && !options.siliconLabsInspectionApproved &&
					 !options.wchInspectionApproved && !options.wchMultiInspectionApproved) ;
	DRIVERCRATE_EXPECT( context, baselineScanProviderIds().size() == 9U) ;
	DRIVERCRATE_EXPECT( context, isBaselineScanRegistryCompatible( builtInProviderDescriptors())) ;
	DRIVERCRATE_EXPECT( context, std::count_if( builtInProviderDescriptors().begin(),
											  builtInProviderDescriptors().end(),
											  []( const ProviderDescriptor &descriptor) {
												  return descriptor.enabledByDefault ;
											  }) == 10) ;
	const ProviderDescriptor *const index =
		// 新しい通常既定登録。
		findProviderDescriptor( SIGNED_INDEX_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, index != nullptr && index->enabledByDefault &&
									!isProviderEnabled( options, *index) &&
									!isMetadataSearchProvider( *index)) ;

	std::vector<ProviderDescriptor> drift( builtInProviderDescriptors().begin(),
										  // 実registryを壊す合成copy。
										  builtInProviderDescriptors().end()) ;
	// Default有効状態の変更を同じprofile revisionとして受理しない。
	if( !drift.empty()) {
		drift.front().enabledByDefault = false ;
	}

	DRIVERCRATE_EXPECT( context, !isBaselineScanRegistryCompatible( drift)) ;
	drift.assign( builtInProviderDescriptors().begin(), builtInProviderDescriptors().end()) ;
	// 元明示集合外の追加既定Providerを固定profileへ暗黙採用しない。
	for( auto &descriptor : drift) {
		// 通常は無効のASUSだけを追加既定へ改ざんする。
		if( descriptor.id == ASUS_PROVIDER_ID) {
			descriptor.enabledByDefault = true ;
		}
	}

	DRIVERCRATE_EXPECT( context, !isBaselineScanRegistryCompatible( drift)) ;
	drift.assign( builtInProviderDescriptors().begin(), builtInProviderDescriptors().end()) ;
	// 索引の既定状態だけを変更しても元測定契約のdriftとして拒否する。
	for( auto &descriptor : drift) {
		// 唯一の索引登録の能力を省略せず既定無効へ改ざんする。
		if( descriptor.id == SIGNED_INDEX_PROVIDER_ID) {
			descriptor.enabledByDefault = false ;
		}
	}

	DRIVERCRATE_EXPECT( context, !isBaselineScanRegistryCompatible( drift)) ;
	drift.assign( builtInProviderDescriptors().begin(), builtInProviderDescriptors().end()) ;
	// 索引を情報検索の専用能力へ偽装する変更を受理しない。
	for( auto &descriptor : drift) {
		// 固定索引に未実装のmetadata能力だけを注入する。
		if( descriptor.id == SIGNED_INDEX_PROVIDER_ID) {
			descriptor.capabilities |= capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) ;
		}
	}

	DRIVERCRATE_EXPECT( context, !isBaselineScanRegistryCompatible( drift)) ;
	drift.assign( builtInProviderDescriptors().begin(), builtInProviderDescriptors().end()) ;
	// Scan capabilityの削除も開始前のprofile driftとして拒否する。
	if( !drift.empty()) {
		drift.front().capabilities &= ~capabilityMask( ProviderCapability::SCAN) ;
	}

	DRIVERCRATE_EXPECT( context, !isBaselineScanRegistryCompatible( drift)) ;
	drift.assign( builtInProviderDescriptors().begin(), builtInProviderDescriptors().end()) ;
	drift.push_back( drift.front()) ;
	DRIVERCRATE_EXPECT( context, !isBaselineScanRegistryCompatible( drift)) ;

	std::string description = "unchanged" ;	// 成功時だけ置換される条件表示。
	DRIVERCRATE_EXPECT( context, buildBaselineScanDescription( description)) ;
	DRIVERCRATE_EXPECT( context, description.find( "mode=describe_only\n") != std::string::npos) ;
	DRIVERCRATE_EXPECT( context,
					   description.find( "run_option=--run-baseline\n") != std::string::npos) ;
	DRIVERCRATE_EXPECT( context, countOccurrences( description, "explicit_provider_id=") == 9U) ;
	DRIVERCRATE_EXPECT( context,
					   description.find( "driver_install=not_requested\n") != std::string::npos) ;
	DRIVERCRATE_EXPECT(
		context,
		description.find( "release_observation_store=existing_protected_store_may_update\n") !=
			std::string::npos) ;
}

/**
 * @brief 四確定度、全31 report、任意branch非出力と候補文字列非出力を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testCompleteReportAndRedaction( TestContext &context)
{
	const ScanOptions options = fixtureOptions( context) ;	// 明示9 Provider設定。
	ScanResult		  result  = fixtureResult( options) ;	// Device 0件の有効snapshot。
	result.measurement->network.combined.eligibleDeviceCount		 = exactCount( 0U) ;
	result.measurement->network.combined.queryCompletedDeviceCount	 = lowerBoundCount( 0U) ;
	result.measurement->network.combined.informationDeviceCount		 = {std::nullopt,
																		MeasurementExtent::NOT_MEASURED} ;
	result.measurement->network.combined.applicableUpdateDeviceCount = {
		std::nullopt, MeasurementExtent::UNAVAILABLE} ;
	result.measurement->network.combined.installReadyUpdateDeviceCount = exactCount( 0U) ;
	result.measurement->unmatchedCandidateCount						   = exactCount( 1U) ;

	UpdateCandidate candidate ;	// Reportへ内容を複写してはならない非現在版の架空候補。
	candidate.identity		  = SECRET_SENTINEL ;
	candidate.deviceIdentity  = SECRET_SENTINEL ;
	candidate.providerId	  = NVIDIA_PROVIDER_ID ;
	candidate.packageIdentity = SECRET_SENTINEL ;
	candidate.title			  = SECRET_SENTINEL ;
	candidate.manufacturer	  = SECRET_SENTINEL ;
	candidate.model			  = SECRET_SENTINEL ;
	candidate.driverClass	  = SECRET_SENTINEL ;
	candidate.provider		  = SECRET_SENTINEL ;
	candidate.version		  = SECRET_SENTINEL ;
	candidate.driverDate	  = SECRET_SENTINEL ;
	candidate.sourceName	  = SECRET_SENTINEL ;
	candidate.sourceLocation  = SECRET_SENTINEL ;
	result.candidates.push_back( std::move( candidate)) ;
	result.state					 = ProviderScanState::CANDIDATES_AVAILABLE ;
	ProviderScanReport *const nvidia = findReport( result, NVIDIA_PROVIDER_ID) ;	// 候補元report。
	DRIVERCRATE_EXPECT( context, nvidia != nullptr) ;
	// Provider reportがある場合だけ候補行数と未照合行数を反映する。
	if( nvidia != nullptr && nvidia->coverage.measurement.has_value()) {
		nvidia->candidateCount								  = 1U ;
		nvidia->coverage.measurement->unmatchedCandidateCount = exactCount( 1U) ;
	}

	DRIVERCRATE_EXPECT( context,
					   appendFixtureResource( context, result, NVIDIA_PROVIDER_ID, BRANCH_SENTINEL)) ;
	DRIVERCRATE_EXPECT( context, isPublishedScanMeasurementValid( FIXTURE_OPERATION_ID, result)) ;
	std::string report = "unchanged" ;	// 成功時だけ完全ASCIIへ置換される出力。
	DRIVERCRATE_EXPECT( context, buildScanMeasurementReport( FIXTURE_OPERATION_ID, FIXTURE_VERSION,
														   options, result, report)) ;
	DRIVERCRATE_EXPECT( context, report.size() <= SCAN_MEASUREMENT_REPORT_MAXIMUM_BYTES) ;
	DRIVERCRATE_EXPECT( context, report.find( "network.combined.T=EXACT:0\n") != std::string::npos) ;
	DRIVERCRATE_EXPECT( context,
					   report.find( "network.combined.Q=LOWER_BOUND:0\n") != std::string::npos) ;
	DRIVERCRATE_EXPECT( context,
					   report.find( "network.combined.R=NOT_MEASURED:null\n") != std::string::npos) ;
	DRIVERCRATE_EXPECT( context,
					   report.find( "network.combined.A=UNAVAILABLE:null\n") != std::string::npos) ;
	DRIVERCRATE_EXPECT( context, report.find( "inventory.represented_device_count=EXACT:0\n") !=
									std::string::npos) ;
	DRIVERCRATE_EXPECT( context, countOccurrences( report, "provider.begin=") == 31U) ;
	DRIVERCRATE_EXPECT( context, countOccurrences( report, "provider.enabled=1\n") == 9U) ;
	DRIVERCRATE_EXPECT( context, countOccurrences( report, "provider.enabled=0\n") == 22U) ;
	DRIVERCRATE_EXPECT( context,
					   report.find( "provider.resource.branch=NOT_EXPORTED\n") != std::string::npos) ;
	DRIVERCRATE_EXPECT( context,
					   report.find( "provider.resource.acquisition=UNKNOWN\n") != std::string::npos) ;
	DRIVERCRATE_EXPECT( context, report.find( "report_end=1\n") != std::string::npos) ;

	DRIVERCRATE_EXPECT( context, report.find( SECRET_SENTINEL_ASCII) == std::string::npos) ;
	DRIVERCRATE_EXPECT( context, report.find( BRANCH_SENTINEL_ASCII) == std::string::npos) ;
	DRIVERCRATE_EXPECT( context,
					   std::all_of( report.begin(), report.end(), []( const unsigned char byte) {
						   return byte == '\n' || (byte >= 0x20U && byte <= 0x7EU) ;
					   })) ;
}

/**
 * @brief 部分成功の終了区分と不正snapshotの無出力拒否を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testPartialAndRejectedReports( TestContext &context)
{
	// 各戻り値とtemporaryを短命なfactory内で生成し、元の検証期間はheapで所有する。
	const auto ownResult = []( auto make) { return std::make_unique<decltype( make())>( make()) ; } ;

	const ScanOptions options = fixtureOptions( context) ;	// 明示9 Provider設定。
	DRIVERCRATE_EXPECT( context,
					   options.enabledProviderIds.size() == baselineScanProviderIds().size() &&
						   !options.useDefaultProviders && options.enabledProviderIds.size() >= 2U) ;
	// 解決拒否後の空集合を改ざんfixtureへ使用せず、失敗assertionを保持して終了する。
	if( options.useDefaultProviders ||
	   options.enabledProviderIds.size() != baselineScanProviderIds().size() ||
	   options.enabledProviderIds.size() < 2U) {
		return ;
	}

	const auto				  partialOwner = ownResult( [&] {
		   return	// 個別失敗を含む結果。
			   fixtureResult( options, OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
	   }) ;								   // 同じ元結果を単独所有する。
	auto					 &partial = *partialOwner ;										// 元所有者と同じscopeだけで結果を借用する。
	ProviderScanReport *const wua	  = findReport( partial, WINDOWS_UPDATE_PROVIDER_ID) ;	// 失敗元。
	DRIVERCRATE_EXPECT( context, wua != nullptr) ;
	// WUA reportが存在する場合だけ、検索失敗とnative診断を設定する。
	if( wua != nullptr && wua->coverage.measurement.has_value()) {
		wua->state	 = ProviderScanState::FAILURE ;
		wua->outcome = OutcomeCode::FAILURE ;
		wua->error	 = static_cast<NativeError>( 0x80004005U) ;
		wua->coverage.measurement->reasons.push_back(
			{MeasurementReason::QUERY_FAILED, MeasurementUnit::QUERY, 1U}) ;
	}

	partial.error = static_cast<NativeError>( 0x80004005U) ;
	std::ostringstream partialOutput ;	// 完全な部分成功reportの出力先。
	DRIVERCRATE_EXPECT( context, writeScanMeasurementReport( partialOutput, FIXTURE_OPERATION_ID,
														   FIXTURE_VERSION, options, partial) ==
									ScanMeasurementReportStatus::PARTIAL_SUCCESS) ;
	DRIVERCRATE_EXPECT( context, partialOutput.str().find( "scan_outcome=SUCCEEDED_WITH_ERRORS\n") !=
									std::string::npos) ;
	DRIVERCRATE_EXPECT( context, partialOutput.str().find(
									"provider.reason=QUERY_FAILED|QUERY|1\n") != std::string::npos) ;
	DRIVERCRATE_EXPECT( context, partialOutput.str().find( "provider.error=0x80004005\n") !=
									std::string::npos) ;

	// 各caseは既存出力文字列を変更せずcontract拒否になることを確認する。
	const auto expectRejected = [&context, &options]( ScanResult invalid) {
		std::string report = "unchanged" ;	// 失敗時に維持すべき呼出し側の既存値。
		DRIVERCRATE_EXPECT( context,
						   !buildScanMeasurementReport( FIXTURE_OPERATION_ID, FIXTURE_VERSION,
													   options, invalid, report)) ;
		DRIVERCRATE_EXPECT( context, report == "unchanged") ;
		std::ostringstream output ;	// Contract拒否時に空のままのstream。
		DRIVERCRATE_EXPECT( context, writeScanMeasurementReport( output, FIXTURE_OPERATION_ID,
															   FIXTURE_VERSION, options, invalid) ==
										ScanMeasurementReportStatus::CONTRACT_REJECTED) ;
		DRIVERCRATE_EXPECT( context, output.str().empty()) ;
	} ; // 各不正snapshotを同じ出力不変条件で検証する。

	const auto unknownContextIdOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &unknownContextId = *unknownContextIdOwner ;	// Contextだけに未知IDを含む結果。
	unknownContextId.measurement->context.enabledProviderIds.front() = L"unregistered-provider" ;
	expectRejected( std::move( unknownContextId)) ;

	const auto emptyContextIdOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &emptyContextId = *emptyContextIdOwner ;	// 空IDを含む同数の有効集合。
	emptyContextId.measurement->context.enabledProviderIds.front().clear() ;
	expectRejected( std::move( emptyContextId)) ;

	const auto duplicateContextIdOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &duplicateContextId = *duplicateContextIdOwner ;	// 9件のまま一IDが重複した集合。
	duplicateContextId.measurement->context.enabledProviderIds[1] =
		duplicateContextId.measurement->context.enabledProviderIds.front() ;
	expectRejected( std::move( duplicateContextId)) ;

	const auto missingContextIdOwner = ownResult( [&] {
		return	// 公開契約は有効だが固定profileより一件少ない結果。
			fixtureResult( options) ;
	}) ;												 // 同じ元結果を単独所有する。
	auto &missingContextId = *missingContextIdOwner ;	// 元所有者と同じscopeだけで結果を借用する。
	missingContextId.measurement->context.enabledProviderIds.pop_back() ;
	ProviderScanReport *const missingContextReport =
		// 除いたIDのreport。
		findReport( missingContextId, AMD_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, missingContextReport != nullptr) ;
	// Fixture前提が崩れた場合は欠落reportを参照せず試験を失敗として終了する。
	if( missingContextReport == nullptr) {
		return ;
	}

	missingContextReport->state	  = ProviderScanState::DISABLED ;
	missingContextReport->outcome = OutcomeCode::NOT_STARTED ;
	DRIVERCRATE_EXPECT( context,
					   isPublishedScanMeasurementValid( FIXTURE_OPERATION_ID, missingContextId)) ;
	expectRejected( std::move( missingContextId)) ;

	const auto extraContextIdOwner = ownResult( [&] {
		return	// 公開契約は有効だが固定profileより一件多い結果。
			fixtureResult( options) ;
	}) ;												  // 同じ元結果を単独所有する。
	auto	  &extraContextId = *extraContextIdOwner ;	// 元所有者と同じscopeだけで結果を借用する。
	extraContextId.measurement->context.enabledProviderIds.emplace_back( ASUS_PROVIDER_ID) ;
	ProviderScanReport *const extraContextReport =
		// 余剰IDの既存report。
		findReport( extraContextId, ASUS_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, extraContextReport != nullptr) ;
	// 既存descriptorを使えない場合は架空のProvider定義でfixtureを補わない。
	if( extraContextReport == nullptr) {
		return ;
	}

	extraContextReport->state	= ProviderScanState::NO_CANDIDATES ;
	extraContextReport->outcome = OutcomeCode::SUCCESS ;
	DRIVERCRATE_EXPECT( context,
					   isPublishedScanMeasurementValid( FIXTURE_OPERATION_ID, extraContextId)) ;
	const auto otherKnownContextIdOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return extraContextId ; }) ;
	auto &otherKnownContextId =
		*otherKnownContextIdOwner ;	// 9件だがWUAを別の登録済みProviderへ置換した集合。
	expectRejected( std::move( extraContextId)) ;
	otherKnownContextId.measurement->context.enabledProviderIds.erase(
		otherKnownContextId.measurement->context.enabledProviderIds.begin()) ;
	otherKnownContextId.providerReports.front().state	= ProviderScanState::DISABLED ;
	otherKnownContextId.providerReports.front().outcome = OutcomeCode::NOT_STARTED ;
	DRIVERCRATE_EXPECT( context,
					   isPublishedScanMeasurementValid( FIXTURE_OPERATION_ID, otherKnownContextId)) ;
	expectRejected( std::move( otherKnownContextId)) ;

	const auto defaultContextOwner = ownResult( [&] {
		return	// 明示profileを既定選択と誤申告したcontext。
			fixtureResult( options) ;
	}) ;												  // 同じ元結果を単独所有する。
	auto	  &defaultContext = *defaultContextOwner ;	// 元所有者と同じscopeだけで結果を借用する。
	defaultContext.measurement->context.usedDefaultProviders = true ;
	expectRejected( std::move( defaultContext)) ;

	const auto invalidExtentOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &invalidExtent = *invalidExtentOwner ;	// 未知確定度を含むsnapshot。
	invalidExtent.measurement->network.combined.eligibleDeviceCount.extent =
		static_cast<MeasurementExtent>( 99) ;
	expectRejected( std::move( invalidExtent)) ;

	const auto wrongSessionOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &wrongSession = *wrongSessionOwner ;	// Contextだけ別sessionのsnapshot。
	wrongSession.measurement->context.scanSessionId += 1U ;
	expectRejected( std::move( wrongSession)) ;

	const auto missingReportOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &missingReport = *missingReportOwner ;	// 無効Provider report一件を欠くsnapshot。
	missingReport.providerReports.pop_back() ;
	expectRejected( std::move( missingReport)) ;

	const auto unknownIdOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &unknownId = *unknownIdOwner ;	// 未登録IDへ置換した同数report。
	unknownId.providerReports.front().descriptor.id = L"unregistered-provider" ;
	expectRejected( std::move( unknownId)) ;

	const auto emptyIdOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &emptyId = *emptyIdOwner ;	// 空IDで元のreportを隠す不正結果。
	emptyId.providerReports.front().descriptor.id.clear() ;
	expectRejected( std::move( emptyId)) ;

	const auto duplicateIdOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &duplicateId			   = *duplicateIdOwner ;	// 件数は31のまま一件が重複・一件が欠落。
	duplicateId.providerReports[1] = duplicateId.providerReports.front() ;
	std::reverse( duplicateId.providerReports.begin(), duplicateId.providerReports.end()) ;
	expectRejected( std::move( duplicateId)) ;

	const auto displayDriftOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &displayDrift = *displayDriftOwner ;	// ID以外の表示名変更も拒否する。
	displayDrift.providerReports.front().descriptor.displayName = SECRET_SENTINEL ;
	expectRejected( std::move( displayDrift)) ;

	const auto capabilityDriftOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &capabilityDrift = *capabilityDriftOwner ;	// 同じIDのcapability差分。
	capabilityDrift.providerReports.front().descriptor.capabilities = 0U ;
	expectRejected( std::move( capabilityDrift)) ;

	const auto tierDriftOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &tierDrift = *tierDriftOwner ;	// 取得元選択tierだけが不一致。
	tierDrift.providerReports.front().descriptor.selectionTier =
		static_cast<ProviderSelectionTier>( 99) ;
	expectRejected( std::move( tierDrift)) ;

	const auto basisDriftOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &basisDrift = *basisDriftOwner ;	// 探索根拠だけが不一致。
	basisDrift.providerReports.front().descriptor.discoveryBasis =
		static_cast<CandidateDiscoveryBasis>( 99) ;
	expectRejected( std::move( basisDrift)) ;

	const auto noticeDriftOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &noticeDrift = *noticeDriftOwner ;	// 導入注意区分だけが不一致。
	noticeDrift.providerReports.front().descriptor.installNotice =
		static_cast<InstallNoticeKind>( 99) ;
	expectRejected( std::move( noticeDrift)) ;

	const auto defaultDriftOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &defaultDrift = *defaultDriftOwner ;	// 既定有効状態だけが不一致。
	defaultDrift.providerReports.front().descriptor.enabledByDefault = false ;
	expectRejected( std::move( defaultDrift)) ;

	const auto policyDriftOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &policyDrift = *policyDriftOwner ;	// 同じIDへ任意policyを付けた不正結果。
	policyDrift.providerReports.front().descriptor.officialSourcePolicyId = L"unregistered-policy" ;
	expectRejected( std::move( policyDrift)) ;

	const auto disabledEnabledProviderOwner = ownResult( [&] {
		return	// 明示有効Providerを未実行へ変えた結果。
			fixtureResult( options) ;
	}) ; // 同じ元結果を単独所有する。
	auto	  &disabledEnabledProvider =
		*disabledEnabledProviderOwner ;	// 元所有者と同じscopeだけで結果を借用する。
	disabledEnabledProvider.providerReports.front().state	= ProviderScanState::DISABLED ;
	disabledEnabledProvider.providerReports.front().outcome = OutcomeCode::NOT_STARTED ;
	expectRejected( std::move( disabledEnabledProvider)) ;

	const auto invalidResourceOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &invalidResource = *invalidResourceOwner ;	// 未登録policyを持つresource。
	DRIVERCRATE_EXPECT( context,
					   appendFixtureResource( context, invalidResource, NVIDIA_PROVIDER_ID, {})) ;
	ProviderScanReport *const resourceReport = findReport( invalidResource, NVIDIA_PROVIDER_ID) ;
	// 追加済みresourceがある場合だけpolicy IDを未登録値へ変更する。
	if( resourceReport != nullptr && resourceReport->coverage.measurement.has_value() &&
	   !resourceReport->coverage.measurement->resources.empty()) {
		resourceReport->coverage.measurement->resources.front().policyId = L"unregistered-policy" ;
	}

	expectRejected( std::move( invalidResource)) ;

	const auto missingMeasurementOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &missingMeasurement = *missingMeasurementOwner ;	// 旧契約の計測なしsnapshot。
	missingMeasurement.measurement.reset() ;
	expectRejected( std::move( missingMeasurement)) ;

	const auto unknownStateOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &unknownState = *unknownStateOwner ;	// 定義外Provider stateを持つsnapshot。
	unknownState.providerReports.front().state = static_cast<ProviderScanState>( 99) ;
	expectRejected( std::move( unknownState)) ;

	const auto versionMismatchOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	auto &versionMismatch = *versionMismatchOwner ;	// 実行版と異なるcontext version。
	versionMismatch.measurement->context.applicationVersion = L"9.9.9" ;
	expectRejected( std::move( versionMismatch)) ;

	const auto validOwner =
		// 同じ元結果を単独所有する。
		ownResult( [&] { return fixtureResult( options) ; }) ;
	const auto &valid = *validOwner ;	// Profile検証中に変更しない有効snapshot。
	// 入力profileの拒否でも既存文字列とstreamの無出力を同時に確認する。
	const auto	expectRejectedOptions = [&context, &valid]( const ScanOptions &invalid) {
		 std::string unchanged = "unchanged" ;	// 構築失敗時に保持する呼出し側の値。
		 DRIVERCRATE_EXPECT( context,
							!buildScanMeasurementReport( FIXTURE_OPERATION_ID, FIXTURE_VERSION,
														invalid, valid, unchanged)) ;
		 DRIVERCRATE_EXPECT( context, unchanged == "unchanged") ;
		 std::ostringstream output ;	// Profile拒否では書込みを許さないstream。
		 DRIVERCRATE_EXPECT( context, writeScanMeasurementReport( output, FIXTURE_OPERATION_ID,
																FIXTURE_VERSION, invalid, valid) ==
										 ScanMeasurementReportStatus::CONTRACT_REJECTED) ;
		 DRIVERCRATE_EXPECT( context, output.str().empty()) ;
	} ;

	ScanOptions defaultOptions		   = options ;	// 既定自動解決を混在させた不正profile。
	defaultOptions.useDefaultProviders = true ;
	expectRejectedOptions( defaultOptions) ;
	ScanOptions reorderedOptions = options ;	// Contextと異なり実行profile自体の順序は固定する。
	std::reverse( reorderedOptions.enabledProviderIds.begin(),
				 reorderedOptions.enabledProviderIds.end()) ;
	expectRejectedOptions( reorderedOptions) ;

	// 四つのinspection承認のどれか一つでも固定条件から逸脱したら拒否する。
	for( const auto approval :
		{&ScanOptions::prolificInspectionApproved, &ScanOptions::siliconLabsInspectionApproved,
		 &ScanOptions::wchInspectionApproved, &ScanOptions::wchMultiInspectionApproved}) {
		ScanOptions approvedOptions = options ;	// 今回の承認fieldだけを変更するcopy。
		approvedOptions.*approval	= true ;
		expectRejectedOptions( approvedOptions) ;
	}

	ScanOptions fileOptions = options ;	// Fileの実在確認より前に拒否すべき非空入力。
	fileOptions.userSelectedFiles.push_back(
		{.providerId = std::wstring( INTEL_WIRELESS_PACKAGE_PROVIDER_ID),
		 .path		 = LR"(C:\Fictional\wireless.zip)"}) ;
	expectRejectedOptions( fileOptions) ;
}

/**
 * @brief 1 MiB上限、完全構築前の無出力、部分writeとflush失敗を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testCapacityAndIoFailures( TestContext &context)
{
	const ScanOptions options = fixtureOptions( context) ;	// 明示9 Provider設定。
	const ScanResult  valid	  = fixtureResult( options) ;	// 正常な小規模report。
	DiagnosticBuffer  successBuffer( SinkFailure::NONE) ;	// 一回writeとflushを観測する正常sink。
	std::ostream	  successOutput( &successBuffer) ;		// Bufferを所有しないstream。
	DRIVERCRATE_EXPECT( context, writeScanMeasurementReport( successOutput, FIXTURE_OPERATION_ID,
														   FIXTURE_VERSION, options, valid) ==
									ScanMeasurementReportStatus::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, successBuffer.writeCount == 1U && successBuffer.flushCount == 1U) ;
	DRIVERCRATE_EXPECT( context, successBuffer.bytes.find( "report_end=1\n") != std::string::npos) ;

	// Write、flushの各故障で再試行せずOUTPUT_FAILEDになることを確認する。
	for( const SinkFailure failure : {SinkFailure::SHORT_WRITE, SinkFailure::FLUSH_FAILURE,
									 SinkFailure::WRITE_EXCEPTION, SinkFailure::FLUSH_EXCEPTION}) {
		DiagnosticBuffer buffer( failure) ;	// 今回の一箇所だけを故障させるsink。
		std::ostream	 output( &buffer) ;	// Fake bufferを借用するstream。
		output.exceptions( std::ios::badbit | std::ios::failbit) ;
		DRIVERCRATE_EXPECT( context, writeScanMeasurementReport( output, FIXTURE_OPERATION_ID,
															   FIXTURE_VERSION, options, valid) ==
										ScanMeasurementReportStatus::OUTPUT_FAILED) ;
		DRIVERCRATE_EXPECT( context, buffer.writeCount == 1U) ;
		const bool writeFailure = failure == SinkFailure::SHORT_WRITE ||
								  // Flushへ到達しない二故障。
								  failure == SinkFailure::WRITE_EXCEPTION ;
		DRIVERCRATE_EXPECT( context, buffer.flushCount == (writeFailure ? 0U : 1U)) ;
		DRIVERCRATE_EXPECT( context, !output.good()) ;
	}

	DiagnosticBuffer existingFailureBuffer( SinkFailure::NONE) ;		// 初期失敗時に未使用のsink。
	std::ostream	 existingFailureOutput( &existingFailureBuffer) ;	// 既存failbitを持たせるstream。
	existingFailureOutput.setstate( std::ios::failbit) ;
	DRIVERCRATE_EXPECT( context, writeScanMeasurementReport(
									existingFailureOutput, FIXTURE_OPERATION_ID, FIXTURE_VERSION,
									options, valid) == ScanMeasurementReportStatus::OUTPUT_FAILED) ;
	DRIVERCRATE_EXPECT( context, existingFailureBuffer.writeCount == 0U &&
									existingFailureBuffer.flushCount == 0U) ;

	DiagnosticBuffer descriptionBuffer( SinkFailure::NONE) ;	// Describe-only一回出力の正常sink。
	std::ostream	 descriptionOutput( &descriptionBuffer) ;	// Bufferを借用するstream。
	DRIVERCRATE_EXPECT( context, writeBaselineScanDescription( descriptionOutput)) ;
	DRIVERCRATE_EXPECT( context,
					   descriptionBuffer.writeCount == 1U && descriptionBuffer.flushCount == 1U) ;

	ScanResult oversized = fixtureResult( options) ;	// 有効だが出力上限を超えるresource集合。
	// 固定profile内の公式7 Providerへ最大件数の登録済みresourceを追加する。
	for( ProviderScanReport &report : oversized.providerReports) {
		const bool enabled	= isProviderEnabled( options, report.descriptor) ;	// 今回の実行状態。
		const bool official = (report.descriptor.capabilities &
							   capabilityMask( ProviderCapability::OFFICIAL_NETWORK)) !=
							  0U ;	// Resourceを保持できる公式network境界。
		// 無効Provider、WUA、Driver Storeにはresourceを捏造しない。
		if( !enabled || !official || !report.coverage.measurement.has_value()) {
			continue ;
		}

		const OfficialSourcePolicy *const policy =
			// 対応する固定policy。
			officialSourcePolicyForProvider( report.descriptor.id) ;
		DRIVERCRATE_EXPECT( context, policy != nullptr && !policy->resources.empty()) ;
		// Registry前提が崩れた場合はnullを参照せず、このProviderを飛ばす。
		if( policy == nullptr || policy->resources.empty()) {
			continue ;
		}

		MeasurementResource resource ;	// 出力可能な最小の登録済みresource。
		resource.policyId	 = policy->id ;
		resource.resourceId	 = policy->resources.front().id ;
		resource.acquisition = MeasurementAcquisition::UNKNOWN ;
		report.coverage.measurement->resources.assign( MEASUREMENT_RESOURCE_LIMIT, resource) ;
	}

	DRIVERCRATE_EXPECT( context, isPublishedScanMeasurementValid( FIXTURE_OPERATION_ID, oversized)) ;
	std::string report = "unchanged" ;	// 容量拒否時に変更されない呼出し側buffer。
	DRIVERCRATE_EXPECT( context, !buildScanMeasurementReport( FIXTURE_OPERATION_ID, FIXTURE_VERSION,
															options, oversized, report)) ;
	DRIVERCRATE_EXPECT( context, report == "unchanged") ;
	DiagnosticBuffer oversizedBuffer( SinkFailure::NONE) ;	// 構築拒否時に未使用であるべきsink。
	std::ostream	 oversizedOutput( &oversizedBuffer) ;	// Bufferを借用するstream。
	DRIVERCRATE_EXPECT( context, writeScanMeasurementReport( oversizedOutput, FIXTURE_OPERATION_ID,
														   FIXTURE_VERSION, options, oversized) ==
									ScanMeasurementReportStatus::CONTRACT_REJECTED) ;
	DRIVERCRATE_EXPECT( context, oversizedBuffer.writeCount == 0U &&
									oversizedBuffer.flushCount == 0U &&
									oversizedBuffer.bytes.empty()) ;
}

/**
 * @brief Report先頭二件の入替えと逆順を同じ登録順出力へ変換できることを検証する。
 * @param[in,out] context Assertion集計先。
 */
void testReportOrdering( TestContext &context)
{
	const ScanOptions options  = fixtureOptions( context) ;	// 同じprofileを全順序へ適用する。
	const ScanResult  baseline = fixtureResult( options) ;	// 比較元のregistry順snapshot。
	std::string		  expected ;							// 同じ値を登録順で出力した正本。
	DRIVERCRATE_EXPECT( context, buildScanMeasurementReport( FIXTURE_OPERATION_ID, FIXTURE_VERSION,
														   options, baseline, expected)) ;
	// 本番の先頭二件入替えと全件逆順を独立したsnapshotで検証する。
	for( const bool reverse : {false, true}) {
		ScanResult reordered = baseline ;	// 呼出し前後の入力順を保持すべきsnapshot。
		// 全件逆順でもIDの集合と各report値が同じなら同じexportを得る。
		if( reverse) {
			std::reverse( reordered.providerReports.begin(), reordered.providerReports.end()) ;
		} else {
			// Compositeは必須inventoryをmanaged serviceより先に発行する。
			std::swap( reordered.providerReports[0], reordered.providerReports[1]) ;
		}

		const std::wstring firstId =
			// 入力順の証拠。
			reordered.providerReports.front().descriptor.id ;
		DRIVERCRATE_EXPECT( context,
						   isPublishedScanMeasurementValid( FIXTURE_OPERATION_ID, reordered)) ;
		std::string actual ;	// 入力順へ依存してはならないASCII出力。
		DRIVERCRATE_EXPECT( context,
						   buildScanMeasurementReport( FIXTURE_OPERATION_ID, FIXTURE_VERSION,
													  options, reordered, actual)) ;
		DRIVERCRATE_EXPECT( context, actual == expected) ;
		DRIVERCRATE_EXPECT( context, reordered.providerReports.front().descriptor.id == firstId) ;
	}
}

/**
 * @brief 全31 reportと有効9 IDを独立に並べ替え、同じ出力と入力不変を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testContextAndReportOrdering( TestContext &context)
{
	const ScanOptions options = fixtureOptions( context) ;	// 全組合せで変更しない固定profile。
	// 正常完了とWUA個別失敗の双方へ同じ3×3の順序組合せを適用する。
	for( const OutcomeCode outcome : {OutcomeCode::SUCCESS, OutcomeCode::SUCCEEDED_WITH_ERRORS}) {
		ScanResult baseline = fixtureResult( options, outcome) ;	// 比較元のregistry順snapshot。
		// 部分成功ではWUA失敗と元errorを保持し、全体成功へ昇格させない。
		if( outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS) {
			baseline.providerReports.front().state	 = ProviderScanState::FAILURE ;
			baseline.providerReports.front().outcome = OutcomeCode::FAILURE ;
			baseline.providerReports.front().error	 = static_cast<NativeError>( 0x80004005U) ;
			baseline.error							 = static_cast<NativeError>( 0x80004005U) ;
		}

		std::string expected ;	// 登録順の完全ASCII正本。
		DRIVERCRATE_EXPECT( context,
						   buildScanMeasurementReport( FIXTURE_OPERATION_ID, FIXTURE_VERSION,
													  options, baseline, expected)) ;
		std::array<std::vector<ProviderScanReport>, 3> reportOrders{
			baseline.providerReports, std::vector<ProviderScanReport>{},
			baseline.providerReports} ;	// 登録・本番・逆順のreport群。
		std::array<std::vector<std::wstring>, 3> contextOrders{
			options.enabledProviderIds, std::vector<std::wstring>{},
			options.enabledProviderIds} ;	// 同じ三順序の有効ID集合。
		// 本番の全31 ID順で既存reportを解決し、無効Serial群と索引も省略せずにcopyする。
		for( const std::wstring_view providerId : PRODUCTION_REPORT_ORDER) {
			const ProviderScanReport *const report =
				// Registry由来の合成report。
				findReport( baseline, providerId) ;
			DRIVERCRATE_EXPECT( context, report != nullptr) ;
			// FixtureのIDがregistryから消えた場合は不完全な本番順を試験しない。
			if( report == nullptr) {
				return ;
			}

			reportOrders[1].push_back( *report) ;
			// Contextには固定profileで有効なIDだけを本番順で含める。
			if( isProviderEnabled( options, report->descriptor)) {
				contextOrders[1].emplace_back( providerId) ;
			}
		}

		std::reverse( reportOrders[2].begin(), reportOrders[2].end()) ;
		std::reverse( contextOrders[2].begin(), contextOrders[2].end()) ;
		DRIVERCRATE_EXPECT( context, reportOrders[1].size() == 31U && contextOrders[1].size() == 9U) ;
		// 三つのreport順ごとに、context順を独立に三通り変更する。
		for( const std::vector<ProviderScanReport> &reportOrder : reportOrders) {
			// Contextだけ、本番reportだけ、両方が異なる場合を同じ契約で検証する。
			for( const std::vector<std::wstring> &contextOrder : contextOrders) {
				ScanResult reordered	  = baseline ;	// 呼出しで変更されてはならない入力copy。
				reordered.providerReports = reportOrder ;
				reordered.measurement->context.enabledProviderIds = contextOrder ;
				DRIVERCRATE_EXPECT(
					context, isPublishedScanMeasurementValid( FIXTURE_OPERATION_ID, reordered)) ;
				std::string actual ;	// 順序差によらず正本へ一致すべき完全出力。
				DRIVERCRATE_EXPECT( context,
								   buildScanMeasurementReport( FIXTURE_OPERATION_ID, FIXTURE_VERSION,
															  options, reordered, actual)) ;
				DRIVERCRATE_EXPECT( context, actual == expected) ;
				std::ostringstream				  output ;	// 完全reportと終了区分を検証するstream。
				const ScanMeasurementReportStatus expectedStatus =
					outcome == OutcomeCode::SUCCESS
						? ScanMeasurementReportStatus::SUCCESS
						: ScanMeasurementReportStatus::
							  PARTIAL_SUCCESS ;	// Outcomeを保持する期待終了値。
				DRIVERCRATE_EXPECT( context, writeScanMeasurementReport(
												output, FIXTURE_OPERATION_ID, FIXTURE_VERSION,
												options, reordered) == expectedStatus) ;
				DRIVERCRATE_EXPECT( context, output.str() == expected) ;
				DRIVERCRATE_EXPECT( context, reordered.measurement->context.enabledProviderIds ==
												contextOrder) ;
				DRIVERCRATE_EXPECT( context,
								   std::equal( reordered.providerReports.begin(),
											  reordered.providerReports.end(), reportOrder.begin(),
											  reportOrder.end(),
											  []( const ProviderScanReport &actualReport,
												 const ProviderScanReport &expectedReport) {
												  return actualReport.descriptor.id ==
														 expectedReport.descriptor.id ;
											  })) ;
			}
		}
	}
}

/**
 * @brief 六つの固定診断、未知enumの無出力、1 KiB上限とI/O再試行禁止を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testFailureDiagnostics( TestContext &context)
{
	// 固定enumと期待ASCII名を独立した定数で一対一に照合する。
	const std::array<std::pair<ScanMeasurementFailureReason, std::string_view>, 6> reasons{{
		{ScanMeasurementFailureReason::WORKER_EVENT_REJECTED, "WORKER_EVENT_REJECTED"},
		{ScanMeasurementFailureReason::SCAN_RESULT_MISSING, "SCAN_RESULT_MISSING"},
		{ScanMeasurementFailureReason::CONTROLLER_REJECTED, "CONTROLLER_REJECTED"},
		{ScanMeasurementFailureReason::MEASUREMENT_MISSING, "MEASUREMENT_MISSING"},
		{ScanMeasurementFailureReason::PUBLISHED_MEASUREMENT_REJECTED,
		 "PUBLISHED_MEASUREMENT_REJECTED"},
		{ScanMeasurementFailureReason::REPORT_CONTRACT_REJECTED, "REPORT_CONTRACT_REJECTED"},
	}} ;
	// 全六理由が任意のsnapshotや例外本文を受け取らず三行だけを出すことを確認する。
	for( const auto &[reason, name] : reasons) {
		DiagnosticBuffer buffer( SinkFailure::NONE) ;	// 一回write／flushを観測する正常sink。
		std::ostream	 output( &buffer) ;				// 呼出し中にfake bufferを借用するstream。
		std::string		 expected =
			"record=drivercrate_scan_measurement_failure\nfailure_revision=1\nfailure_reason=" ;	// 許可する三行だけの正本。
		expected.append( name) ;
		expected.push_back( '\n') ;
		DRIVERCRATE_EXPECT( context, writeScanMeasurementFailure( output, reason)) ;
		DRIVERCRATE_EXPECT( context, buffer.bytes == expected) ;
		DRIVERCRATE_EXPECT( context, buffer.bytes.size() <= SCAN_MEASUREMENT_FAILURE_MAXIMUM_BYTES) ;
		DRIVERCRATE_EXPECT( context, buffer.writeCount == 1U && buffer.flushCount == 1U) ;
		DRIVERCRATE_EXPECT( context, std::all_of( buffer.bytes.begin(), buffer.bytes.end(),
												[]( const unsigned char byte) {
													return byte == '\n' ||
														   (byte >= 0x20U && byte <= 0x7EU) ;
												})) ;
	}

	DiagnosticBuffer unknownBuffer( SinkFailure::NONE) ;	// 未知enumでは未使用に保つsink。
	std::ostream	 unknownOutput( &unknownBuffer) ;		// 正常なstreamでも未知値を許可しない。
	DRIVERCRATE_EXPECT( context, !writeScanMeasurementFailure(
									unknownOutput, static_cast<ScanMeasurementFailureReason>( 99))) ;
	DRIVERCRATE_EXPECT( context, unknownBuffer.bytes.empty() && unknownBuffer.writeCount == 0U &&
									unknownBuffer.flushCount == 0U) ;

	// 一箇所ずつ故障させ、exception maskがあっても再送せずfalseへ変換する。
	for( const SinkFailure failure : {SinkFailure::SHORT_WRITE, SinkFailure::FLUSH_FAILURE,
									 SinkFailure::WRITE_EXCEPTION, SinkFailure::FLUSH_EXCEPTION}) {
		DiagnosticBuffer buffer( failure) ;	// 今回の故障位置と受理byteを保持するsink。
		std::ostream	 output( &buffer) ;	// Exception maskを有効にした借用stream。
		output.exceptions( std::ios::badbit | std::ios::failbit) ;
		DRIVERCRATE_EXPECT( context,
						   !writeScanMeasurementFailure(
							   output, ScanMeasurementFailureReason::REPORT_CONTRACT_REJECTED)) ;
		DRIVERCRATE_EXPECT( context, buffer.writeCount == 1U) ;
		const bool writeFailure = failure == SinkFailure::SHORT_WRITE ||
								  // Flushへ到達しない故障区分。
								  failure == SinkFailure::WRITE_EXCEPTION ;
		DRIVERCRATE_EXPECT( context, buffer.flushCount == (writeFailure ? 0U : 1U)) ;
		DRIVERCRATE_EXPECT( context, !output.good()) ;
	}

	DiagnosticBuffer failedBuffer( SinkFailure::NONE) ;	// 初期failbitで未使用に保つsink。
	std::ostream	 failedOutput( &failedBuffer) ;		// 既存失敗状態を解除してはならないstream。
	failedOutput.setstate( std::ios::failbit) ;
	DRIVERCRATE_EXPECT(
		context, !writeScanMeasurementFailure( failedOutput,
											  ScanMeasurementFailureReason::MEASUREMENT_MISSING)) ;
	DRIVERCRATE_EXPECT( context, failedBuffer.bytes.empty() && failedBuffer.writeCount == 0U &&
									failedBuffer.flushCount == 0U) ;
}

} // namespace

//------------------------------------------------------------------------------
/** @see tests/unit/scan_measurement_diagnostics_tests.h 宣言側の契約を正本とする。 */
//------------------------------------------------------------------------------
void runScanMeasurementDiagnosticsTests( TestContext &context)
{
	testArgumentsAndProfile( context) ;
	testCompleteReportAndRedaction( context) ;
	testReportOrdering( context) ;
	testContextAndReportOrdering( context) ;
	testPartialAndRejectedReports( context) ;
	testCapacityAndIoFailures( context) ;
	testFailureDiagnostics( context) ;
}

} // namespace drivercrate::test
