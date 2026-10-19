//------------------------------------------------------------------------------
/**
 * @file metadata_search_budget_tests.cpp
 * @brief 検索予算・cost・停止・HTTP用途拒否の非通信試験。
 * @version 01.01.00
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
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  十Provider用の件数予算を検証。
 * </pre>
 *
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#include "metadata_search_budget_tests.h"

#include "core/metadata_search_budget.h"
#include "core/metadata_search.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/official_http_client.h"
#include "platform/driver_store_provider.h"
#include "test_framework.h"

#include <cstdint>
#include <climits>
#include <algorithm>
#include <limits>
#include <string>
#include <stdexcept>

namespace drivercrate::test {
namespace {

/**
 * @brief 二つの既存公式IDを明示した有限requestを作る。
 * @return PayloadやEULA許可を含まない要求。
 */
MetadataSearchRequest requestFixture()
{
	MetadataSearchRequest request ;	// 複数Providerの独立予算を確認する。
	request.enabledProviderIds = {std::wstring( PROLIFIC_OFFICIAL_PROVIDER_ID),
								  std::wstring( SILICON_LABS_OFFICIAL_PROVIDER_ID)} ;
	return request ;
}

/**
 * @brief Byteの境界、probe、宣言長、cache相当計数を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testBodyBudgets( TestContext &context)
{
	// 一resourceの直前・ちょうど・一byte超過を実固定上限で確認する。
	for( const std::uint64_t count : {2097151ULL, 2097152ULL, 2097153ULL}) {
		MetadataSearchExecutionContext execution( 7U, requestFixture()) ;	// 独立した一session。
		DRIVERCRATE_EXPECT( context, execution.beginProvider( PROLIFIC_OFFICIAL_PROVIDER_ID) == 0) ;
		DRIVERCRATE_EXPECT( context, execution.beginResource( 2097152U) == 0) ;
		DRIVERCRATE_EXPECT( context, execution.readAllowance(
										std::numeric_limits<std::uint32_t>::max()) == 2097153U) ;
		DRIVERCRATE_EXPECT( context, (execution.consumeBytes( count) == 0) == (count <= 2097152U)) ;
		DRIVERCRATE_EXPECT( context,
						   execution.usage().bodyBytes == std::min<std::uint64_t>( count, 2097152U)) ;
		DRIVERCRATE_EXPECT( context, execution.usage().probeBytes == (count > 2097152U ? 1U : 0U)) ;
		DRIVERCRATE_EXPECT( context, execution.usage().httpAttempts == 0U) ;
		execution.finishResource() ;
		execution.finishProvider( MetadataSearchReason::FAILED, -1) ;
		DRIVERCRATE_EXPECT( context, execution.providers().front().usage.bodyBytes != 0U) ;
	}

	MetadataSearchLimits limits ;	// 容量だけ縮小した全体予算。
	limits.resourceBytes = 4U ;
	limits.providerBytes = 8U ;
	limits.sessionBytes	 = 12U ;
	MetadataSearchExecutionContext execution( 8U, requestFixture(), {}, {}, {},
											 limits) ;	// 縮小予算を共有するrun。
	DRIVERCRATE_EXPECT( context, execution.beginProvider( PROLIFIC_OFFICIAL_PROVIDER_ID) == 0) ;
	DRIVERCRATE_EXPECT( context, execution.beginResource( 4U) == 0) ;
	DRIVERCRATE_EXPECT( context, execution.consumeBytes( 3U) == 0) ;
	// 失敗resourceも消費を返さない。
	execution.finishResource() ;
	DRIVERCRATE_EXPECT( context, execution.beginResource( 4U) == 0) ;
	DRIVERCRATE_EXPECT( context, execution.consumeBytes( 4U) == 0) ;
	execution.finishResource() ;
	DRIVERCRATE_EXPECT( context, execution.beginResource( 4U) != 0) ;
	DRIVERCRATE_EXPECT( context, execution.usage().bodyBytes == 7U) ;
	DRIVERCRATE_EXPECT( context, !execution.sessionStopped()) ;
	execution.finishProvider( MetadataSearchReason::FAILED) ;
	DRIVERCRATE_EXPECT( context, execution.beginProvider( SILICON_LABS_OFFICIAL_PROVIDER_ID) == 0) ;
	DRIVERCRATE_EXPECT( context, execution.beginResource( 4U) == 0) ;
	DRIVERCRATE_EXPECT( context, execution.consumeBytes( 4U) == 0) ;
	execution.finishResource() ;
	DRIVERCRATE_EXPECT( context, execution.beginResource( 4U) == 0) ;
	DRIVERCRATE_EXPECT( context, execution.readAllowance( 4U) == 2U) ;
	DRIVERCRATE_EXPECT( context, execution.consumeBytes( 2U) != 0) ;
	DRIVERCRATE_EXPECT( context, execution.sessionStopped()) ;
	DRIVERCRATE_EXPECT( context, execution.usage().bodyBytes == 12U) ;
	DRIVERCRATE_EXPECT( context, execution.usage().probeBytes == 1U) ;

	MetadataSearchExecutionContext declared( 9U,
											// 宣言長だけで実受信量を創作しない。
											requestFixture()) ;
	DRIVERCRATE_EXPECT( context, declared.beginProvider( PROLIFIC_OFFICIAL_PROVIDER_ID) == 0) ;
	DRIVERCRATE_EXPECT( context, declared.beginResource( 20U) == 0) ;
	DRIVERCRATE_EXPECT( context, declared.validateDeclaredBodyLength( 21U) != 0) ;
	DRIVERCRATE_EXPECT( context, declared.usage().bodyBytes == 0U) ;
	DRIVERCRATE_EXPECT( context,
					   declared.providerStopReason() == MetadataSearchReason::BUDGET_EXCEEDED) ;
}

/**
 * @brief 送信予算、回線変更、取消し、期限、clock失敗を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testNetworkAndStopping( TestContext &context)
{
	std::uint64_t		 ticks		  = 100U ;	// Fake単調時計。
	bool				 cancelled	  = false ;	// 実atomicの代わりに単一threadで切替える取消し。
	bool				 unrestricted = true ;	// 送信ごとに変化する回線cost。
	MetadataSearchLimits limits ;				// 時間・試行だけを縮小。
	limits.providerMilliseconds = 90U ;
	limits.sessionMilliseconds	= 300U ;
	limits.providerAttempts		= 2U ;
	limits.sessionAttempts		= 3U ;
	// Fake時計・cost・取消しを借用し、一run中の変化を注入するcontext。
	MetadataSearchExecutionContext execution(
		10U, requestFixture(), [&] { return cancelled ; }, [&] { return ticks ; },
		[&] { return MetadataNetworkCost{unrestricted, 0} ; }, limits) ;
	DRIVERCRATE_EXPECT( context, execution.beginProvider( PROLIFIC_OFFICIAL_PROVIDER_ID) == 0) ;
	DRIVERCRATE_EXPECT( context, execution.beginResource( 100U) == 0) ;
	DRIVERCRATE_EXPECT( context, execution.beforeHttpAttempt() == 0) ;
	unrestricted = false ;
	DRIVERCRATE_EXPECT( context, execution.beforeHttpAttempt() != 0) ;
	DRIVERCRATE_EXPECT( context, execution.usage().httpAttempts == 1U) ;
	DRIVERCRATE_EXPECT( context, execution.providerStopReason() ==
									MetadataSearchReason::NETWORK_NOT_APPROVED) ;
	execution.finishProvider( MetadataSearchReason::COMPLETED) ;
	unrestricted = true ;
	DRIVERCRATE_EXPECT( context, execution.beginProvider( SILICON_LABS_OFFICIAL_PROVIDER_ID) == 0) ;
	DRIVERCRATE_EXPECT( context, execution.beginResource( 100U) == 0) ;
	ticks = 189U ;
	DRIVERCRATE_EXPECT( context, execution.timeoutMilliseconds( 60000) == 1) ;
	ticks = 190U ;
	DRIVERCRATE_EXPECT( context, execution.checkpoint() != 0) ;
	DRIVERCRATE_EXPECT( context,
					   execution.providerStopReason() == MetadataSearchReason::DEADLINE_EXCEEDED) ;
	cancelled = true ;
	DRIVERCRATE_EXPECT( context, execution.checkpoint() != 0) ;
	DRIVERCRATE_EXPECT( context, execution.sessionStopReason() == MetadataSearchReason::CANCELLED) ;

	MetadataSearchRequest approved	   = requestFixture() ;	// 今回だけ未知・制限回線を許可する要求。
	approved.restrictedNetworkApproved = true ;
	MetadataSearchExecutionContext attempts( 11U, approved, {}, {}, {},
											limits) ;	// 試行上限に達する別run。
	DRIVERCRATE_EXPECT( context, attempts.beginProvider( PROLIFIC_OFFICIAL_PROVIDER_ID) == 0) ;
	DRIVERCRATE_EXPECT( context, attempts.beginResource( 100U) == 0) ;
	DRIVERCRATE_EXPECT( context, attempts.beforeHttpAttempt() == 0) ;
	DRIVERCRATE_EXPECT( context, attempts.beforeHttpAttempt() == 0) ;
	DRIVERCRATE_EXPECT( context, attempts.beforeHttpAttempt() != 0) ;
	DRIVERCRATE_EXPECT( context, !attempts.sessionStopped()) ;
	attempts.finishProvider( MetadataSearchReason::FAILED) ;
	DRIVERCRATE_EXPECT( context, attempts.beginProvider( SILICON_LABS_OFFICIAL_PROVIDER_ID) == 0) ;
	DRIVERCRATE_EXPECT( context, attempts.beginResource( 100U) == 0) ;
	DRIVERCRATE_EXPECT( context, attempts.beforeHttpAttempt() == 0) ;
	DRIVERCRATE_EXPECT( context, attempts.beforeHttpAttempt() != 0) ;
	DRIVERCRATE_EXPECT( context, attempts.sessionStopped()) ;
	DRIVERCRATE_EXPECT( context, attempts.usage().httpAttempts == 3U) ;

	ticks	  = 0U ;
	cancelled = false ;
	MetadataSearchExecutionContext inventory(
		12U, requestFixture(), [&] { return cancelled ; }, [&] { return ticks ; }, {},
		limits) ;	// Provider開始前もsession期限を適用。
	ticks = 300U ;
	DRIVERCRATE_EXPECT( context, inventory.checkpoint() != 0) ;
	DRIVERCRATE_EXPECT( context,
					   inventory.sessionStopReason() == MetadataSearchReason::DEADLINE_EXCEEDED) ;
	DRIVERCRATE_EXPECT( context, inventory.beginProvider( PROLIFIC_OFFICIAL_PROVIDER_ID) != 0) ;
	limits.resourceBytes = 0U ;
	MetadataSearchExecutionContext invalid( 13U, requestFixture(), {}, {}, {},
										   limits) ;	// 不正予算を拒否するrun。
	DRIVERCRATE_EXPECT( context, invalid.checkpoint() != 0) ;
}

/**
 * @brief 専用HTTPからpayload・別API・別sessionへ到達できないことを検証する。
 * @param[in,out] context Assertion集計先。
 */
void testHttpPurpose( TestContext &context)
{
	MetadataSearchExecutionContext execution( 21U, requestFixture()) ;	// Networkを一度も許可しない。
	OfficialHttpClient			   client( execution, false) ;			// Cache I/Oも行わないfixture。
	DRIVERCRATE_EXPECT( context, client.beginSourceSession( 21U, PROLIFIC_OFFICIAL_PROVIDER_ID) != 0) ;
	DRIVERCRATE_EXPECT( context, execution.beginProvider( PROLIFIC_OFFICIAL_PROVIDER_ID) == 0) ;
	DRIVERCRATE_EXPECT( context, client.beginSourceSession( 20U, PROLIFIC_OFFICIAL_PROVIDER_ID) != 0) ;
	DRIVERCRATE_EXPECT( context,
					   client.beginSourceSession( 21U, SILICON_LABS_OFFICIAL_PROVIDER_ID) != 0) ;
	DRIVERCRATE_EXPECT( context, client.beginSourceSession( 21U, PROLIFIC_OFFICIAL_PROVIDER_ID) == 0) ;
	std::wstring text = L"must clear" ;	// 拒否時に残してはならない本文。
	DRIVERCRATE_EXPECT( context, client.getUtf8TextForSource( L"https://invalid.example/payload.zip",
															L"unknown-payload", 100U, text) != 0) ;
	DRIVERCRATE_EXPECT( context, text.empty()) ;
	DRIVERCRATE_EXPECT( context, client.postFormUtf8TextForSource( L"", L"", "", 100U, text) != 0) ;
	DRIVERCRATE_EXPECT( context, client.downloadForSource( L"", L"", 100U, nullptr, {}, {}) != 0) ;
	DRIVERCRATE_EXPECT( context, client.downloadCatalogForSource( L"", L"", 100U, nullptr, {}) != 0) ;
	DRIVERCRATE_EXPECT( context, execution.usage().httpAttempts == 0U) ;
	DRIVERCRATE_EXPECT( context, execution.usage().logicalResources == 0U) ;

	MetadataSearchExecutionContext cancelled( 31U, requestFixture(),
											 [] { return true ; }) ;	// API前の取消し。
	DriverStoreProvider			   inventory ;							// 実列挙を開始してはならないProvider。
	// API開始前の取消し結果。実列挙と実device情報を含んではならない。
	const auto					   result =
		inventory.scanCurrentInventory( 31U, cancelled, []( const ProviderProgress &) {}) ;
	DRIVERCRATE_EXPECT( context, result.purpose == ScanPurpose::METADATA_ONLY) ;
	DRIVERCRATE_EXPECT( context, !result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.outcome == OutcomeCode::ABORTED) ;
	DRIVERCRATE_EXPECT( context, result.candidates.empty()) ;
	DRIVERCRATE_EXPECT( context, inventory.inventoryMeasurement().enumeratedDeviceCount.extent ==
									MeasurementExtent::UNAVAILABLE) ;
}

/**
 * @brief 正本の九登録を明示し、固定session上限に届く非通信要求を作る。
 * @return 制限回線許可なし・専用九登録の要求。
 */
MetadataSearchRequest allMetadataRequest()
{
	MetadataSearchRequest request ;	// 通常の既定九件とは独立した集合。
	// Registryの専用能力からだけ有限集合を生成する。
	for( const auto &descriptor : builtInProviderDescriptors()) {
		// 未対応の通常scanを予算消費へ混ぜない。
		if( isMetadataSearchProvider( descriptor)) {
			request.enabledProviderIds.push_back( descriptor.id) ;
		}
	}

	return request ;
}

/**
 * @brief 固定4／32 MiBの直前・一致・probe超過をchunk跨ぎで検証する。
 * @param[in,out] context Assertion集計先。
 */
void testProductionBodyBoundaries( TestContext &context)
{
	const auto				request		   = allMetadataRequest() ;	// 十分なProviderを持つ正本集合。
	constexpr std::uint64_t RESOURCE_BYTES = 2U * 1024U * 1024U ;	// 固定resource本文上限。
	// 二resourceで到達するProvider上限と、八Providerで到達するsession上限を別々に確認する。
	for( const std::size_t providerCount : {1U, 8U}) {
		// 最終chunkの直前、一致、一byte超過をそれぞれ別sessionで実施する。
		for( const std::int64_t offset : {-1LL, 0LL, 1LL}) {
			MetadataSearchExecutionContext execution(
				50U, request) ;	// Payloadを確保せず実計数を検証する。
			// 固定一Provider二resourceまでを順に確定させる。
			for( std::size_t providerIndex = 0U; providerIndex < providerCount; ++providerIndex) {
				DRIVERCRATE_EXPECT( context, execution.beginProvider(
												request.enabledProviderIds[providerIndex]) == 0) ;
				// 各resourceを二chunkに分け、端数をまたぐ加算でも同じ上限を強制する。
				for( std::size_t resource = 0U; resource < 2U; ++resource) {
					DRIVERCRATE_EXPECT( context, execution.beginResource( RESOURCE_BYTES) == 0) ;
					DRIVERCRATE_EXPECT( context, execution.consumeBytes( RESOURCE_BYTES - 3U) == 0) ;
					const bool last = providerIndex + 1U == providerCount &&
									  // 主境界の最終chunk。
									  resource == 1U ;
					const auto tail = static_cast<std::uint64_t>(
						3 + (last ? offset : 0)) ;	// 許可量以下の最終read。
					DRIVERCRATE_EXPECT( context, (execution.consumeBytes( tail) == 0) ==
													(!last || offset <= 0)) ;
					execution.finishResource() ;
				}

				execution.finishProvider( MetadataSearchReason::COMPLETED) ;
			}

			const auto expected =
				providerCount * 2U * RESOURCE_BYTES - (offset < 0 ? 1U : 0U) ;	// 本文とprobeを分離。
			DRIVERCRATE_EXPECT( context, execution.usage().bodyBytes == expected) ;
			DRIVERCRATE_EXPECT( context, execution.usage().probeBytes == (offset > 0 ? 1U : 0U)) ;
			DRIVERCRATE_EXPECT( context,
							   execution.sessionStopped() == (providerCount == 8U && offset > 0)) ;
			DRIVERCRATE_EXPECT( context, execution.providers().back().reason ==
											(offset > 0 ? MetadataSearchReason::BUDGET_EXCEEDED
														: MetadataSearchReason::COMPLETED)) ;
			// 上限一致後の新resourceは許さず、直前なら一byteの残予算を使える。
			if( providerCount == 8U && offset <= 0) {
				DRIVERCRATE_EXPECT( context,
								   execution.beginProvider( request.enabledProviderIds.back()) == 0) ;
				DRIVERCRATE_EXPECT( context,
								   (execution.beginResource( RESOURCE_BYTES) == 0) == (offset < 0)) ;
				// 残量がある場合でも巨大な宣言長や不正chunkでoverflowさせない。
				if( offset < 0) {
					DRIVERCRATE_EXPECT( context, execution.readAllowance( UINT32_MAX) == 2U) ;
					DRIVERCRATE_EXPECT( context, execution.consumeBytes( UINT64_MAX) != 0) ;
					DRIVERCRATE_EXPECT( context, execution.usage().bodyBytes == expected) ;
					DRIVERCRATE_EXPECT( context,
									   execution.validateDeclaredBodyLength( UINT64_MAX) != 0) ;
				}

				DRIVERCRATE_EXPECT( context, execution.sessionStopReason() ==
												MetadataSearchReason::BUDGET_EXCEEDED) ;
			}
		}
	}
}

/**
 * @brief 固定2／20 logical resourceと12／120明示送信の境界を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testProductionRequestBoundaries( TestContext &context)
{
	const auto					   request = allMetadataRequest() ;	// 順序に依存しない正本十登録。
	MetadataSearchExecutionContext execution( 60U, request, {}, {}, [] {
		return MetadataNetworkCost{true, 0} ;
	}) ; // Costだけを非通信fakeへ置換する。
	// 十Provider・各二resource・各六送信で固定上限へ一致させる。
	for( std::size_t provider = 0U; provider < request.enabledProviderIds.size(); ++provider) {
		DRIVERCRATE_EXPECT( context,
						   execution.beginProvider( request.enabledProviderIds[provider]) == 0) ;
		// 二つのlogical resourceで送信上限を共有し、cache相当では送信を追加しない。
		for( std::uint32_t resource = 0U; resource < 2U; ++resource) {
			DRIVERCRATE_EXPECT( context, execution.beginResource( 8U) == 0) ;
			// 初回と最大五redirectに相当する送信単位を確認する。
			for( std::uint32_t attempt = 0U; attempt < 6U; ++attempt) {
				DRIVERCRATE_EXPECT( context, execution.beforeHttpAttempt() == 0) ;
				DRIVERCRATE_EXPECT( context, execution.usage().httpAttempts ==
												provider * 12U + resource * 6U + attempt + 1U) ;
			}

			// 一致した個別送信上限を超える要求は13回目を加算しない。
			if( resource == 1U) {
				DRIVERCRATE_EXPECT( context, execution.beforeHttpAttempt() != 0) ;
				DRIVERCRATE_EXPECT( context, execution.sessionStopped() == (provider == 9U)) ;
			}

			execution.finishResource() ;
		}

		execution.finishProvider( MetadataSearchReason::COMPLETED) ;
	}

	DRIVERCRATE_EXPECT( context, execution.usage().httpAttempts == 120U) ;
	DRIVERCRATE_EXPECT( context, execution.usage().logicalResources == 20U) ;

	MetadataSearchExecutionContext logical(
		61U, request) ;	// Cache hit相当の送信なしresourceだけを消費する。
	// 個別と全体のresource上限を送信上限の副作用なしで独立に確認する。
	for( std::size_t provider = 0U; provider < request.enabledProviderIds.size(); ++provider) {
		DRIVERCRATE_EXPECT( context,
						   logical.beginProvider( request.enabledProviderIds[provider]) == 0) ;
		// 一Providerの二つの成功resourceを確定し、三つ目だけを拒否する。
		for( std::size_t resource = 0U; resource < 2U; ++resource) {
			DRIVERCRATE_EXPECT( context, logical.beginResource( 8U) == 0) ;
			DRIVERCRATE_EXPECT( context, logical.consumeBytes( 1U) == 0) ;
			logical.finishResource() ;
		}

		DRIVERCRATE_EXPECT( context, logical.beginResource( 8U) != 0) ;
		DRIVERCRATE_EXPECT( context, logical.sessionStopped() == (provider == 9U)) ;
		logical.finishProvider( MetadataSearchReason::COMPLETED) ;
	}

	DRIVERCRATE_EXPECT( context, logical.usage().logicalResources == 20U &&
									logical.usage().httpAttempts == 0U) ;
}

/**
 * @brief 固定期限と同時停止・主因固定・cost例外を実時間待機なしで検証する。
 * @param[in,out] context Assertion集計先。
 */
void testProductionDeadlineAndCauses( TestContext &context)
{
	const auto	  request = requestFixture() ;	// 二Provider間の期限resetも確認する。
	std::uint64_t ticks{} ;						// Millisecond単位の注入単調時計。
	bool		  cancelled{} ;					// 同時成立を明示的に作る取消し状態。
	// 個別と全体の期限を同じ注入時計で検証する。
	MetadataSearchExecutionContext execution(
		70U, request, [&] { return cancelled ; }, [&] { return ticks ; }) ;
	DRIVERCRATE_EXPECT( context, execution.beginProvider( request.enabledProviderIds.front()) == 0) ;
	ticks = 89999U ;
	DRIVERCRATE_EXPECT( context, execution.timeoutMilliseconds( INT_MAX) == 1) ;
	ticks = 90000U ;
	DRIVERCRATE_EXPECT( context, execution.checkpoint() != 0 && !execution.sessionStopped()) ;
	execution.finishProvider( MetadataSearchReason::COMPLETED) ;
	DRIVERCRATE_EXPECT( context, execution.providers().front().reason ==
									MetadataSearchReason::DEADLINE_EXCEEDED) ;
	ticks = 299999U ;
	DRIVERCRATE_EXPECT( context, execution.beginProvider( request.enabledProviderIds.back()) == 0) ;
	DRIVERCRATE_EXPECT( context, execution.timeoutMilliseconds( 60000) == 1) ;
	ticks	  = 300000U ;
	cancelled = true ;
	DRIVERCRATE_EXPECT( context, execution.checkpoint() != 0 && execution.sessionStopReason() ==
																   MetadataSearchReason::CANCELLED) ;
	cancelled = false ;
	DRIVERCRATE_EXPECT( context, execution.checkpoint() != 0 && execution.sessionStopReason() ==
																   MetadataSearchReason::CANCELLED) ;
	DRIVERCRATE_EXPECT( context, execution.timeoutMilliseconds( 0) == 0 &&
									execution.timeoutMilliseconds( -1) == 0) ;

	ticks = 0U ;
	// 先に観測した本文上限を後の期限で上書きしないことを確認する。
	MetadataSearchExecutionContext budgetFirst(
		71U, request, [&] { return cancelled ; }, [&] { return ticks ; }) ;
	DRIVERCRATE_EXPECT( context, budgetFirst.beginProvider( request.enabledProviderIds.front()) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   budgetFirst.beginResource( 1U) == 0 && budgetFirst.consumeBytes( 2U) != 0) ;
	ticks = 90000U ;
	DRIVERCRATE_EXPECT( context,
					   budgetFirst.checkpoint() != 0 && budgetFirst.providerStopReason() ==
															MetadataSearchReason::BUDGET_EXCEEDED) ;
	ticks = 300000U ;
	DRIVERCRATE_EXPECT( context, budgetFirst.checkpoint() != 0 &&
									budgetFirst.sessionStopReason() ==
										MetadataSearchReason::DEADLINE_EXCEEDED) ;
	cancelled = true ;
	DRIVERCRATE_EXPECT( context, budgetFirst.checkpoint() != 0 &&
									budgetFirst.sessionStopReason() ==
										MetadataSearchReason::DEADLINE_EXCEEDED) ;

	// Server未知相当・cost失敗・例外は、今回の許可がない限り送信へ進めない。
	for( const bool approved : {false, true}) {
		auto changed					  = request ;	// 後runへ前runの許可をコピーしない新しい要求。
		changed.restrictedNetworkApproved = approved ;
		MetadataSearchExecutionContext unknown( 72U, changed, {}, {}, []() -> MetadataNetworkCost {
			throw std::runtime_error( "fake cost unavailable") ;
		}) ; // API取得失敗を限定して注入する。
		DRIVERCRATE_EXPECT( context, unknown.beginProvider( request.enabledProviderIds.front()) == 0) ;
		DRIVERCRATE_EXPECT( context, unknown.beginResource( 1U) == 0) ;
		DRIVERCRATE_EXPECT( context, (unknown.beforeHttpAttempt() == 0) == approved) ;
		DRIVERCRATE_EXPECT( context, unknown.usage().httpAttempts == (approved ? 1U : 0U)) ;
	}

	ticks = 10U ;
	MetadataSearchExecutionContext backwards( 73U, request, {},
											 [&] { return ticks ; }) ;	// 時計異常の独立run。
	ticks = 9U ;
	DRIVERCRATE_EXPECT( context, backwards.checkpoint() != 0 &&
									backwards.sessionStopReason() == MetadataSearchReason::FAILED) ;
	MetadataSearchExecutionContext brokenClock( 74U, request, {}, []() -> std::uint64_t {
		throw std::runtime_error( "fake clock unavailable") ;
	}) ; // 時計例外を無期限の継続へ変換しない。
	DRIVERCRATE_EXPECT( context, brokenClock.checkpoint() != 0 && brokenClock.sessionStopReason() ==
																	 MetadataSearchReason::FAILED) ;
}

} // namespace

/** @see metadata_search_budget_tests.h */
void runMetadataSearchBudgetTests( TestContext &context)
{
	testBodyBudgets( context) ;
	testNetworkAndStopping( context) ;
	testHttpPurpose( context) ;
	testProductionBodyBoundaries( context) ;
	testProductionRequestBoundaries( context) ;
	testProductionDeadlineAndCauses( context) ;
}

} // namespace drivercrate::test
