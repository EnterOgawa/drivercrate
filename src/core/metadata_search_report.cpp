//------------------------------------------------------------------------------
/**
 * @file metadata_search_report.cpp
 * @brief 情報検索の入力拒否と非機密ASCII report構築。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  情報検索専用の非機密出力契約を追加。
 * </pre>
 *
 * @note 任意の端末表示値・URL・path・EULA本文を出力しない。
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#include "core/metadata_search_report.h"

#include "core/metadata_search.h"
#include "core/metadata_search_budget.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <utility>

namespace drivercrate {
namespace {

/**
 * @brief 固定ASCII tokenだけをwide値から変換する。
 * @param[in] value 正本IDまたはCMake版。端末表示値は渡さない。
 * @return 最大128字の安全なtoken。拒否は空文字列。
 */
std::string asciiToken( const std::wstring_view value)
{
	// 空、過大、改行やURL構成記号を持つtokenをreportへ出さない。
	if( value.empty() || value.size() > 128U) {
		return {} ;
	}

	std::string result ;	// ASCIIだけの所有copy。
	// 固定IDで使う文字集合だけを一字ずつ変換する。
	for( const wchar_t character : value) {
		// 非ASCII、区切り、制御文字を混ぜたfieldを全体拒否する。
		if( !((character >= L'a' && character <= L'z') || (character >= L'A' && character <= L'Z') ||
			 (character >= L'0' && character <= L'9') || character == L'-' || character == L'_' ||
			 character == L'.')) {
			return {} ;
		}

		result.push_back( static_cast<char>( character)) ;
	}

	return result ;
}

/** @brief 上限内の完全reportを組み立て、最初の失敗を保持する。 */
class ReportBuilder final {
public:
	/**
     * @brief 固定keyとASCII値を一行だけ追加する。
     * @param[in] key 固定の非機密field名。
     * @param[in] value 検証済みtokenまたは数字。
     */
	void field( const std::string_view key, const std::string_view value)
	{
		// 一行の不正や上限超過の後で部分reportを再び有効にしない。
		if( !valid_ || key.empty() || value.empty() || key.size() > 128U || value.size() > 256U ||
		   key.size() + value.size() + 2U > METADATA_SEARCH_REPORT_MAXIMUM_BYTES - output_.size()) {
			valid_ = false ;
			return ;
		}

		output_.append( key) ;
		output_.push_back( '=') ;
		output_.append( value) ;
		output_.push_back( '\n') ;
	}

	/**
     * @brief 符号を維持した整数をASCIIへ変換する。
     * @tparam Integer 呼出元の有界な整数型。
     * @param[in] key 固定field名。
     * @param[in] value 実際の件数または診断値。
     */
	template <typename Integer> void number( const std::string_view key, const Integer value)
	{
		field( key, std::to_string( value)) ;
	}

	/**
     * @brief 未取得の時刻や版を0と区別する。
     * @tparam Integer 公開された符号なし整数型。
     * @param[in] key 固定field名。
     * @param[in] value 同一snapshotの任意値。
     */
	template <typename Integer>
	void optionalNumber( const std::string_view key, const std::optional<Integer> &value)
	{
		field( key, value ? std::to_string( *value) : "unknown") ;
	}

	/**
     * @brief 完全構築に成功した場合だけ出力を置き換える。
     * @param[out] result 呼出元の所有文字列。不正時は変更しない。
     * @return 全fieldが上限内で有効ならtrue。
     */
	bool finish( std::string &result)
	{
		// 不完全reportを無出力の成功に変換しない。
		if( !valid_ || output_.empty()) {
			return false ;
		}

		result = std::move( output_) ;
		return true ;
	}

private:
	/// 完全構築まで外部へ公開しない所有buffer。
	std::string output_ ;
	/// falseの後は構築を再開しない。
	bool		valid_{true} ;
} ;

/**
 * @brief 定義済みenumを固定文字列へ一対一で変換する。
 * @tparam Enum 0から連続した公開enum。
 * @tparam Size 固定表の要素数。
 * @param[in] value 検証するenum値。
 * @param[in] names 型の宣言順に対応する固定表。
 * @return 定義済みの固定名。未知は空文字列。
 */
template <typename Enum, std::size_t Size>
std::string_view enumName( const Enum								value,
						  const std::array<std::string_view, Size> &names) noexcept
{
	const auto index = static_cast<std::size_t>( value) ;	// 負の未知enumも上限で拒否される。
	return index < names.size() ? names[index] : std::string_view{} ;
}

/**
 * @brief 停止理由をschema固定の文字列へ変換する。
 * @param[in] reason 全体またはProviderの確定理由。
 * @return 固定名。未知enumは空。
 */
std::string_view reasonName( const MetadataSearchReason reason) noexcept
{
	// 公開enum宣言順に固定した非機密の終了理由。
	constexpr std::array<std::string_view, 9> names{
		"completed",	"cancelled",	  "budget_exceeded",	  "deadline_exceeded", "failed",
		"not_selected", "not_applicable", "network_not_approved", "not_run_after_stop"} ;
	return enumName( reason, names) ;
}

/**
 * @brief 全体・個別の元outcomeを固定名へ変換する。
 * @param[in] outcome Provider元の終端区分。
 * @return 固定名。未知enumは空。
 */
std::string_view outcomeName( const OutcomeCode outcome) noexcept
{
	// 元outcomeを独自の全成功表現へ変えない固定名。
	constexpr std::array<std::string_view, 6> names{
		"not_started", "in_progress", "success", "succeeded_with_errors", "failure", "aborted"} ;
	return enumName( outcome, names) ;
}

/**
 * @brief 件数と確定度を別fieldで出力する。
 * @param[in,out] builder 完全構築中の所有buffer。
 * @param[in] key 固定の指標名。
 * @param[in] count 同一snapshotの件数。
 */
void appendCount( ReportBuilder &builder, const std::string_view key, const CountMeasurement &count)
{
	constexpr std::array<std::string_view, 4> names{"not_measured", "exact", "lower_bound",
													"unavailable"} ;	// 数値と別に記録する確定度。
	builder.field( std::string( key) + ".extent", enumName( count.extent, names)) ;
	builder.field( std::string( key) + ".value",
				  count.value ? std::to_string( *count.value) : "unknown") ;
}

/**
 * @brief 異なる五指標を合算せず出力する。
 * @param[in,out] builder 出力buffer。
 * @param[in] prefix 固定のglobal／provider区分。
 * @param[in] counts 同一snapshotのT/Q/R/A/I。
 */
void appendStages( ReportBuilder &builder, const std::string_view prefix,
				  const StageDeviceCounts &counts)
{
	appendCount( builder, std::string( prefix) + ".T", counts.eligibleDeviceCount) ;
	appendCount( builder, std::string( prefix) + ".Q", counts.queryCompletedDeviceCount) ;
	appendCount( builder, std::string( prefix) + ".R", counts.informationDeviceCount) ;
	appendCount( builder, std::string( prefix) + ".A", counts.applicableUpdateDeviceCount) ;
	appendCount( builder, std::string( prefix) + ".I", counts.installReadyUpdateDeviceCount) ;
}

/**
 * @brief 成功resource数とは独立した消費量を出力する。
 * @param[in,out] builder 出力buffer。
 * @param[in] prefix 固定のglobal／provider区分。
 * @param[in] usage 上限内と検証済みの実消費。
 */
void appendUsage( ReportBuilder &builder, const std::string_view prefix,
				 const MetadataSearchUsage &usage)
{
	builder.number( std::string( prefix) + ".body_bytes", usage.bodyBytes) ;
	builder.number( std::string( prefix) + ".probe_bytes", usage.probeBytes) ;
	builder.number( std::string( prefix) + ".logical_resources", usage.logicalResources) ;
	builder.number( std::string( prefix) + ".http_attempts", usage.httpAttempts) ;
}

/**
 * @brief 製品上限を条件表示と実測reportで共用する。
 * @param[in,out] builder 出力buffer。
 */
void appendLimits( ReportBuilder &builder)
{
	const MetadataSearchLimits limits ;	// 実行contextと同じ製品既定値。
	builder.field( "policy_id", asciiToken( METADATA_SEARCH_POLICY_ID)) ;
	builder.number( "policy_revision", METADATA_SEARCH_POLICY_REVISION) ;
	builder.number( "limit.resource_body_bytes", limits.resourceBytes) ;
	builder.number( "limit.provider_body_bytes", limits.providerBytes) ;
	builder.number( "limit.session_body_bytes", limits.sessionBytes) ;
	builder.number( "limit.provider_logical_resources", limits.providerResources) ;
	builder.number( "limit.session_logical_resources", limits.sessionResources) ;
	builder.number( "limit.provider_http_attempts", limits.providerAttempts) ;
	builder.number( "limit.session_http_attempts", limits.sessionAttempts) ;
	builder.number( "limit.provider_milliseconds", limits.providerMilliseconds) ;
	builder.number( "limit.session_milliseconds", limits.sessionMilliseconds) ;
	builder.field( "budget_scope", "application_body_and_explicit_sends_not_total_billed_traffic") ;
	builder.field( "cache_policy", "bounded_catalog_read_write") ;
	builder.field( "release_observation_write", "forbidden") ;
	builder.field( "payload_acquisition", "forbidden") ;
	builder.field( "preparation_and_install", "forbidden") ;
}
} // namespace

/** @see src/core/metadata_search_report.h */
MetadataSearchCommand parseMetadataSearchArguments(
	const std::span<const std::wstring_view> arguments) noexcept
{
	try {
		// 引数なしと単一describeは列挙も通信も行わない。
		if( arguments.empty() ||
		   (arguments.size() == 1U && arguments.front() == L"--describe-metadata")) {
			return {.kind = MetadataSearchCommandKind::DESCRIBE} ;
		}

		// 最初の明示runがなければworkerを生成しない。
		if( arguments.size() > 2U * METADATA_SEARCH_PROVIDER_LIMIT + 2U ||
		   arguments.front() != L"--run-metadata") {
			return {} ;
		}

		MetadataSearchRequest request ;	// 承認は毎回falseから始める。
		// 固定flagと、その直後の一つの登録IDだけを有限に解析する。
		for( std::size_t index = 1U; index < arguments.size(); ++index) {
			// 回線許可の重複を曖昧な引数として拒否する。
			if( arguments[index] == L"--allow-restricted-network" &&
			   !request.restrictedNetworkApproved) {
				request.restrictedNetworkApproved = true ;
			}
			// Provider指定には直後の一つのIDを必須とする。
			else if( arguments[index] == L"--provider" && index + 1U < arguments.size()) {
				// Copy前に固定IDの長さを制限し、過大な任意引数を所有しない。
				if( arguments[index + 1U].empty() || arguments[index + 1U].size() > 128U) {
					return {} ;
				}

				request.enabledProviderIds.emplace_back( arguments[++index]) ;
			} else {
				return {} ;
			}
		}

		// 空集合や通常能力だけのProvider、重複・未知IDを通信前に拒否する。
		if( !validateMetadataSearchRequest( request, builtInProviderDescriptors())) {
			return {} ;
		}

		return {.kind = MetadataSearchCommandKind::RUN, .request = std::move( request)} ;
	} catch( ...) {
		// 引数copy失敗でも部分集合を実行しない。
		return {} ;
	}
}

/** @see src/core/metadata_search_report.h */
bool buildMetadataSearchDescription( std::string &description) noexcept
{
	try {
		ReportBuilder builder ;	// 条件だけの完全出力。
		builder.field( "record", "metadata_search_conditions") ;
		builder.number( "schema_revision", 1U) ;
		builder.field( "purpose", "metadata_only") ;
		builder.field( "run_option", "--run-metadata") ;
		builder.field( "provider_option", "--provider") ;
		builder.field( "initial_selection", "empty") ;
		builder.field( "restricted_network_default", "not_approved") ;
		builder.field( "inventory_dependency", asciiToken( DRIVER_STORE_PROVIDER_ID)) ;
		appendLimits( builder) ;
		// 能力正本の専用集合だけを表示し、通常既定集合を代用しない。
		for( const auto &descriptor : builtInProviderDescriptors()) {
			// 未対応は実行可能ID一覧へ含めない。
			if( isMetadataSearchProvider( descriptor)) {
				builder.field( "available_provider", asciiToken( descriptor.id)) ;
			}
		}

		return builder.finish( description) ;
	} catch( ...) {
		// 構築に失敗しても呼出元の既存文字列は変更しない。
		return false ;
	}
}

/** @see src/core/metadata_search_report.h */
bool buildMetadataSearchReport( const OperationId			operationId,
							   const std::wstring_view		applicationVersion,
							   const MetadataSearchRequest &request, const ScanResult &result,
							   std::string &report) noexcept
{
	try {
		// 候補、request、消費、用途のいずれかが不正なら何も出力しない。
		if( !isMetadataSearchResultValid( operationId, request, result) ||
		   result.measurement->context.applicationVersion != applicationVersion) {
			return false ;
		}

		const auto	 &summary	  = *result.metadataSearch ;	// 同一操作の確定理由と消費。
		const auto	 &measurement = *result.measurement ;		// Localとnetworkの異なる母数。
		const auto	 &conditions  = measurement.context ;		// Workerが固定した実行条件。
		ReportBuilder builder ;									// 完全構築まで外部へ渡さない。
		builder.field( "record", "metadata_search_report") ;
		builder.number( "schema_revision", 1U) ;
		builder.field( "purpose", "metadata_only") ;
		builder.field( "application_version", asciiToken( applicationVersion)) ;
		builder.number( "operation_id", operationId) ;
		builder.number( "scan_session_id", result.scanSessionId) ;
		builder.optionalNumber( "started_utc_seconds", conditions.startedUtcSeconds) ;
		builder.optionalNumber( "completed_utc_seconds", conditions.completedUtcSeconds) ;
		constexpr std::array<std::string_view, 3> osNames{"unknown", "client",
														  "server"} ;	// 実OSの既知区分。
		builder.field( "os_kind", enumName( conditions.osKind, osNames)) ;
		builder.optionalNumber( "os_build", conditions.osBuild) ;
		builder.field( "architecture", "x64") ;
		builder.field( "restricted_network_approved",
					  request.restrictedNetworkApproved ? "true" : "false") ;
		builder.number( "selected_provider_count", request.enabledProviderIds.size()) ;
		builder.field( "inventory_dependency", asciiToken( DRIVER_STORE_PROVIDER_ID)) ;
		appendLimits( builder) ;
		// 選択の出力もregistry順に固定し、入力順だけの差を作らない。
		for( const auto &descriptor : builtInProviderDescriptors()) {
			// 今回明示したIDだけを条件として記録する。
			if( std::find( request.enabledProviderIds.begin(), request.enabledProviderIds.end(),
						 descriptor.id) != request.enabledProviderIds.end()) {
				builder.field( "selected_provider", asciiToken( descriptor.id)) ;
			}
		}

		builder.field( "outcome", outcomeName( result.outcome)) ;
		builder.field( "reason", reasonName( summary.reason)) ;
		builder.number( "native_error", result.error) ;
		builder.number( "elapsed_milliseconds", summary.elapsedMilliseconds) ;
		builder.field( "inventory_complete", summary.inventoryComplete ? "true" : "false") ;
		appendUsage( builder, "usage", summary.usage) ;
		appendCount( builder, "inventory.enumerated", measurement.inventory.enumeratedDeviceCount) ;
		appendCount( builder, "inventory.D", measurement.inventory.representedDeviceCount) ;
		appendCount( builder, "inventory.unrepresented",
					measurement.inventory.unrepresentedDeviceCount) ;
		appendCount( builder, "inventory.missing_manufacturer",
					measurement.inventory.missingManufacturerCount) ;
		appendCount( builder, "inventory.missing_class", measurement.inventory.missingClassCount) ;
		appendCount( builder, "inventory.missing_current_version",
					measurement.inventory.missingCurrentVersionCount) ;
		appendStages( builder, "combined", measurement.network.combined) ;
		appendStages( builder, "official", measurement.network.official) ;
		appendStages( builder, "managed", measurement.network.managed) ;
		// Registryの全登録を出力し、未選択と未実施を省略しない。
		for( const auto &descriptor : builtInProviderDescriptors()) {
			// 一意な登録へ検証済みの元結果を対応付ける借用索引。
			const auto source = std::find_if(
				result.providerReports.begin(), result.providerReports.end(),
				[&descriptor]( const auto &value) { return value.descriptor.id == descriptor.id ; }) ;
			// 同じ登録の確定した消費と停止理由への借用索引。
			const auto detail = std::find_if(
				summary.providers.begin(), summary.providers.end(),
				[&descriptor]( const auto &value) { return value.providerId == descriptor.id ; }) ;
			const auto &counts = *source->coverage.measurement ;	// 全validatorで存在確認済み。
			builder.field( "provider.begin", asciiToken( descriptor.id)) ;
			builder.number( "provider.capabilities", descriptor.capabilities) ;
			builder.field( "provider.reason", reasonName( detail->reason)) ;
			builder.field( "provider.outcome", outcomeName( source->outcome)) ;
			builder.number( "provider.state", static_cast<unsigned int>( source->state)) ;
			builder.number( "provider.native_error", source->error) ;
			builder.number( "provider.candidate_rows", source->candidateCount) ;
			appendUsage( builder, "provider.usage", detail->usage) ;
			appendStages( builder, "provider", counts.devices) ;
			appendCount( builder, "provider.information_records", counts.informationRecordCount) ;
			appendCount( builder, "provider.unmatched_records",
						counts.unmatchedInformationRecordCount) ;
			builder.number( "provider.resource_count", counts.resources.size()) ;
			// 検証済み取得根拠だけを成功ledgerとして出力し、失敗消費と分離する。
			for( const auto &resource : counts.resources) {
				const auto *policy =
					// 正本の固定起点。
					officialSourcePolicyForProvider( descriptor.id) ;
				// 登録済みresourceだけを出力するための借用policy。
				const auto *fixed =
					policy ? findOfficialSourceResource( *policy, resource.resourceId) : nullptr ;
				// Payloadや署名fileをmetadata取得成功へ混ぜない。
				if( !fixed || resource.policyId != policy->id ||
				   (fixed->kind != OfficialSourceResourceKind::LANDING_PAGE &&
					fixed->kind != OfficialSourceResourceKind::METADATA)) {
					return false ;
				}

				builder.field( "resource.policy_id", asciiToken( policy->id)) ;
				builder.field( "resource.id", asciiToken( fixed->id)) ;
				builder.optionalNumber( "resource.parser_revision", resource.parserRevision) ;
				builder.optionalNumber( "resource.body_acquired_utc_seconds",
									   resource.bodyAcquiredUtcSeconds) ;
				builder.optionalNumber( "resource.origin_validated_utc_seconds",
									   resource.originValidatedUtcSeconds) ;
				builder.field( "resource.cache_permitted",
							  !resource.cachePermitted
								  ? "unknown"
								  : (*resource.cachePermitted ? "true" : "false")) ;
				// Cache方針とは分けて記録する実際の本文取得経路。
				constexpr std::array<std::string_view, 6> acquisitionNames{
					"unknown",			 "network_body", "fresh_cache",
					"revalidated_cache", "mixed",		 "not_applicable"} ;
				builder.field( "resource.acquisition",
							  enumName( resource.acquisition, acquisitionNames)) ;
			}

			builder.field( "provider.end", asciiToken( descriptor.id)) ;
		}

		return builder.finish( report) ;
	} catch( ...) {
		// Allocation等の失敗で不完全なreportを公開しない。
		return false ;
	}
}

} // namespace drivercrate
