//------------------------------------------------------------------------------
/**
 * @file index_capacity_inventory_tests.cpp
 * @brief 大規模索引を既低位fakeの本native matcherと同scan凍結へ結びます。
 * @version 01.00.00
 * @date 2026/11/07
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/07  同native大規模進行・実測・coverage失効を追加。
 * </pre>
 * @note metadata_inventory_tests.cpp末尾へincludeし、同TUの既低位fixtureを共有します。
 * 実inventory/通信/導入を行わず、RAM署名の隔離storeだけを使用します。
 * @see docs/adr/0458-bounded-index-capacity-and-owned-state-maps.md
 */
//------------------------------------------------------------------------------
#include "metadata_inventory_tests.h"
#include "platform/signed_index_scan.h"
#include "platform/provider_worker_index_internal.h"
#include "platform/signed_index_acquisition_adapter_internal.h"
#include "test_framework.h"
#include <chrono>
#include <memory>
#include <string_view>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <windows.h>
#include <psapi.h>

namespace drivercrate::test {
namespace {
/** @brief 本processの累計CPU時間を同じWindows計数から読みます。
 * @return kernel/userの合計millisecondです。
 */
std::uint64_t capacityCpuMilliseconds()
{
	FILETIME creation{} ;	// 本processの生成値です。
	FILETIME exit{} ;		// 本processはまだ動作中です。
	FILETIME kernel{} ;		// kernel CPUです。
	FILETIME user{} ;		// user CPUです。
	// 計測不能を0秒の性能成功へ変換しません。
	if( !GetProcessTimes( GetCurrentProcess(), &creation, &exit, &kernel, &user)) {
		throw std::runtime_error( "capacity CPU measurement unavailable") ;
	}

	const auto kernelTicks = (static_cast<std::uint64_t>( kernel.dwHighDateTime) << 32U) |
							 kernel.dwLowDateTime ;	// 100ns単位です。
	const auto userTicks = (static_cast<std::uint64_t>( user.dwHighDateTime) << 32U) |
						   user.dwLowDateTime ;	// 100ns単位です。
	return (kernelTicks + userTicks) / 10000U ;
}
} // namespace

/** @see metadata_inventory_tests.h 宣言側の契約を正本とします。 */
IndexScanSummary runIndexCapacityNativeScan( TestContext						 &context,
											std::shared_ptr<SignedIndexStore> store,
											std::chrono::sys_seconds		  nowUtc,
											std::size_t expectedRecords, std::size_t expectedInputs,
											std::string_view tailId, bool large, bool realClock,
											bool cancelOnFinalProgress)
{
	const auto state = std::make_shared<WorkerIndexState>() ;	// 同threadの低位fakeだけを所有します。
	state->capacityNodes	   = large ? 4096U : 1U ;
	state->capacityPublishedId = std::wstring( tailId.begin(), tailId.end()) ;
	WorkerIndexProvider provider( state) ;							// 本DriverStoreProviderを完全低位表でcaptureします。
	const auto			began = std::chrono::steady_clock::now() ;	// fake時計と分ける実時間です。
	const auto			cpuBefore = capacityCpuMilliseconds() ;		// 同process CPUの開始値です。
	const auto			captured =
		// 実端末を列挙しません。
		provider.scan( 83U, {}, []( const ProviderProgress &) {}) ;
	DRIVERCRATE_EXPECT( context, captured.succeeded && captured.error == 0U) ;
	IndexLookupContext		  measuredContext ;	// 実factoryが返したcontextだけです。
	std::vector<std::wstring> measuredPresent ;	// 匿名件数以外を出力しません。
	const auto				  measuredResolver = provider.indexScanInventory(
		   11U, measuredContext, measuredPresent) ;		// 追加I/Oなしの同snapshotです。
	const auto capturedNodes = measuredPresent.size() ;	// 設定値と区別した実present分母です。
	DRIVERCRATE_EXPECT( context, measuredResolver && capturedNodes == state->capacityNodes &&
									measuredContext.scanSessionId == 83U) ;
	provider_worker_index_detail::Services services ;	// 実保護reload以外の製品依存を呼びません。
	services.load = [store]( std::optional<std::chrono::sys_seconds> at) {
		return store->reload( at) ;
	} ;
	services.utc	   = [nowUtc] { return std::optional{nowUtc} ; } ;
	services.monotonic = [realClock] {
		return realClock ? std::chrono::steady_clock::now()
						 : std::chrono::steady_clock::time_point{} ;
	} ; // 機能時計を実性能へ読み替えません。
	services.targetOs = [] {
		return std::optional{IndexTargetOs::WINDOWS_11} ;
	} ; // 架空target OSです。
	services.beginAcquisition = []( SignedIndexAcquisitionAdapter				 &adapter,
								   std::shared_ptr<const SignedIndexRecordLookup> lookup,
								   IndexLookupContext current, IndexTargetOs os,
								   std::optional<std::chrono::sys_seconds> at) {
		return signed_index_acquisition_detail::Access::beginFixture( adapter, std::move( lookup),
																	 current, os, at) ;
	} ; // 固定RAM fixture-mainだけで、本番配布keyではありません。
	services.httpTransport = []() -> OfficialHttpTransport {
		throw std::runtime_error( "unexpected terms HTTP in capacity fixture") ;
	} ; // 前提が崩れてもnative HTTPへ補完しません。
	bool cancelled{} ;	// 同同期operation限定の取消しです。
	std::optional<std::chrono::steady_clock::time_point>
						   cancelledAt ;	// 最終progress後の実応答測定です。
	SignedIndexScanSession session ;		// 本製品と同じ全batch/plan所有者です。
	const auto			   summary = session.scan(
		provider, 11U, 83U, services, [&] { return cancelled ; },
		[&]( const IndexScanSummary &progress) {
			// 最後のrecord確定通知からでも取消しを取りこぼしません。
			if( cancelOnFinalProgress && progress.processedRecords == expectedRecords) {
				cancelled	= true ;
				cancelledAt = std::chrono::steady_clock::now() ;
			}
		}) ;
	const auto ended   = std::chrono::steady_clock::now() ;	// 本scanの終端です。
	const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>( ended - began)
							 .count() ;											// capture/reload/照合全体です。
	const auto				   cpu = capacityCpuMilliseconds() - cpuBefore ;	// 実CPU差分です。
	PROCESS_MEMORY_COUNTERS_EX memory{} ;										// 全fixture生成も含むprocessのpeakです。
	memory.cb = sizeof( memory) ;
	// peak取得不能をメモリ0の合格にしません。
	if( !GetProcessMemoryInfo( GetCurrentProcess(),
							 reinterpret_cast<PROCESS_MEMORY_COUNTERS *>( &memory),
							 sizeof( memory))) {
		throw std::runtime_error( "capacity memory measurement unavailable") ;
	}

	const auto cancelMilliseconds =
		cancelledAt
			? std::chrono::duration_cast<std::chrono::milliseconds>( ended - *cancelledAt).count()
			: 0 ;	// 実解除応答です。
	std::cout << "CAPACITY_RESOURCE {\"nativeMatcher\":true,\"realClock\":"
			  << (realClock ? "true" : "false") << ",\"nodes\":" << capturedNodes
			  << ",\"requestedNodes\":" << state->capacityNodes
			  << ",\"nativeIdCaptureBound\":" << index_capacity::NATIVE_INVENTORY_IDS
			  << ",\"expectedInputs\":" << expectedInputs
			  << ",\"records\":" << summary.processedRecords
			  << ",\"totalRecords\":" << expectedRecords
			  << ",\"processedInputs\":" << summary.processedPublicIds
			  << ",\"resolverCalls\":" << summary.resolverCalls
			  << ",\"matched\":" << summary.matchedRelations
			  << ",\"definitiveNoRelation\":" << summary.definitiveNoRelationIds
			  << ",\"status\":" << static_cast<unsigned>( summary.status)
			  << ",\"elapsedMilliseconds\":" << elapsed << ",\"cpuMilliseconds\":" << cpu
			  << ",\"peakPrivateBytes\":" << memory.PeakPagefileUsage
			  << ",\"peakWorkingSetBytes\":" << memory.PeakWorkingSetSize
			  << ",\"maximumBatchCalls\":" << summary.maximumBatchResolverCalls
			  << ",\"maximumBatchMilliseconds\":" << summary.maximumBatchMilliseconds
			  << ",\"cancelMilliseconds\":" << cancelMilliseconds
			  << ",\"realHttp\":0,\"realInventory\":0,\"installs\":0}\n" ;
	DRIVERCRATE_EXPECT( context,
					   summary.maximumBatchResolverCalls <= index_capacity::BATCH_PUBLIC_IDS) ;
	// 最終progress後の取消しもCOMPLETEDや取得権限へ昇格しません。
	if( cancelOnFinalProgress) {
		DRIVERCRATE_EXPECT( context, summary.status == IndexScanStatus::CANCELLED && cancelledAt &&
										cancelMilliseconds < 1000) ;
	} else {
		DRIVERCRATE_EXPECT( context, summary.processedRecords == expectedRecords &&
										summary.remainingRecords == 0U) ;
		DRIVERCRATE_EXPECT( context, summary.processedPublicIds == expectedInputs &&
										summary.resolverCalls == expectedInputs) ;
		DRIVERCRATE_EXPECT( context, summary.matchedRelations == 1U &&
										summary.definitiveNoRelationIds == expectedInputs - 1U) ;
	}

	OfficialPreparationPlan plan ;	// 既256取得枠を増やさない空の正規計画です。
	plan.scanSessionId = 83U ;
	plan.planId		   = 1U ;
	plan.limits		   = {128U * 1024U * 1024U, 128U * 1024U * 1024U, 128U * 1024U * 1024U, 1U, 1U} ;
	IndexPreparationSummary preparation ;	// 件数だけの既存準備結果です。
	DRIVERCRATE_EXPECT( context, session.augmentPreparationPlan( plan, services, preparation) == 0U) ;
	std::cout << "CAPACITY_PLAN {\"authorityError\":" << preparation.authorityError
			  << ",\"targets\":" << plan.targets.size()
			  << ",\"unavailable\":" << preparation.unavailableRelations
			  << ",\"capacityRejected\":" << preparation.capacityRejectedRelations << "}\n" ;
	// 全batch凍結の成功からだけ末尾候補が一件つながります。
	if( summary.status == IndexScanStatus::COMPLETED) {
		DRIVERCRATE_EXPECT( context, preparation.authorityError == 0U && plan.targets.size() == 1U) ;
	}

	// 取消し後のsnapshot/lease/planを再利用しません。
	if( cancelOnFinalProgress) {
		DRIVERCRATE_EXPECT( context, plan.targets.empty()) ;
	}

	// fake時計の機能成功をRelease実時間/メモリの合格に数えません。
	if( realClock) {
		DRIVERCRATE_EXPECT( context,
						   summary.status == IndexScanStatus::COMPLETED && elapsed <= 30000) ;
		DRIVERCRATE_EXPECT( context, memory.PeakPagefileUsage <= 1024ULL * 1024ULL * 1024ULL) ;
	}

	DRIVERCRATE_EXPECT( context, state->installs == 0U && state->restores == 0U) ;
	return summary ;
}

/** @see metadata_inventory_tests.h 宣言側の契約を正本とします。 */
void runIndexCapacityNativeLeaseChecks( TestContext										&context,
									   std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot,
									   std::chrono::sys_seconds							 nowUtc)
{
	InventoryCase run ;	// 元epochを明示失効できる既完全低位fixtureです。
	run.fixture.nodes	= 1U ;
	run.fixture.indexId = L"CAPACITYBUS\\NO_MATCH" ;
	DRIVERCRATE_EXPECT( context, run.scanForIndex().succeeded) ;
	IndexLookupContext		  issued ;	// factoryが発行する正のcontextです。
	std::vector<std::wstring> present ;	// 同contextの全opaque集合です。
	// 本factoryが同capture/leaseに固定して発行した同期callbackです。
	const auto resolver = run.provider.makeIndexPublicIdResolver( 11U, issued, present) ;
	DRIVERCRATE_EXPECT( context, resolver && resolver->leaseProof()) ;
	// 前提不成立を空関係での成功にしません。
	if( !resolver) {
		throw std::runtime_error( "capacity lease fixture unavailable") ;
	}

	std::vector<SignedIndexRecordLookup> batches ;	// private coverageだけで全prefixを所有します。
	std::size_t							 offset{} ;	// 未commitの原record位置です。
	// 全batchを同一resolver/leaseだけで生成します。
	while( offset < snapshot->schemaReceipt().records().size()) {
		IndexLookupBudget budget ;	// 一batch枠を全体枠へ広げません。
		budget.recordOffset		  = offset ;
		budget.compactNoRelations = true ;
		// 同batchの所有結果と停止理由です。
		auto result = lookupSignedIndexRecords( snapshot, issued, issued, present, budget, nowUtc,
											   resolver.get()) ;
		DRIVERCRATE_EXPECT( context,
						   result.lookup && result.lookup->progress().completedRecords > 0U) ;
		// 偽の空prefixを無限に繰り返しません。
		if( !result.lookup || result.lookup->progress().completedRecords == 0U) {
			throw std::runtime_error( "capacity lease prefix incomplete") ;
		}

		DRIVERCRATE_EXPECT( context, result.lookup->relations().empty()) ;
		offset = result.lookup->progress().nextRecordOffset ;
		batches.push_back( std::move( *result.lookup)) ;
	}

	// 全原prefixと元leaseを再照合した凍結結果です。
	const auto frozen =
		signed_index_acquisition_detail::Access::freezeFixture( snapshot, issued, batches, nowUtc) ;
	DRIVERCRATE_EXPECT( context, frozen.lookup && frozen.lookup->relations().empty() &&
									frozen.lookup->progress().nextRecordOffset == offset) ;
	// 先頭の抜けや同じbatch重複を、空tupleだからと受理しません。
	if( batches.size() > 1U) {
		DRIVERCRATE_EXPECT( context, !signed_index_acquisition_detail::Access::freezeFixture(
										 snapshot, issued, std::span{batches}.subspan( 1U), nowUtc)
										 .lookup) ;
		std::array<SignedIndexRecordLookup, 2U> duplicate{
			batches[0], batches[0]} ;	// 同じ私有証拠でも二度commitできません。
		DRIVERCRATE_EXPECT( context, !signed_index_acquisition_detail::Access::freezeFixture(
										 snapshot, issued, duplicate, nowUtc)
										 .lookup) ;
	}

	DriverStoreBindingProbe::invalidate( run.provider) ;
	DRIVERCRATE_EXPECT( context, !resolver->leaseProof()->matches( issued, GetCurrentThreadId())) ;
	DRIVERCRATE_EXPECT( context, !signed_index_acquisition_detail::Access::freezeFixture(
									 snapshot, issued, batches, nowUtc)
									 .lookup) ;
}

/** @see metadata_inventory_tests.h 宣言側のnative projection保持契約です。 */
void runIndexCapacityProjectionBoundary( TestContext										 &context,
										std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot,
										std::chrono::sys_seconds nowUtc, bool overflowing)
{
	InventoryCase run ;	// 同じ二nodeの本capture/proofだけを用います。
	DRIVERCRATE_EXPECT( context, run.scanForIndex().succeeded) ;
	IndexLookupContext		  issued ;	// 同factoryの全contextです。
	std::vector<std::wstring> present ;	// 全二nodeを毎query再照合します。
	const auto				  resolver =
		// 元callbackです。
		run.provider.makeIndexPublicIdResolver( 11U, issued, present) ;
	DRIVERCRATE_EXPECT( context, resolver && present.size() == 2U) ;
	// 正例のcapture失敗を空prefixの成功へ変換しません。
	if( !resolver) {
		throw std::runtime_error( "projection capacity resolver unavailable") ;
	}

	std::vector<SignedIndexRecordLookup> batches ;		// 全recordと同一leaseを維持します。
	std::size_t							 offset{} ;		// 完全commit済みrecord数です。
	std::size_t							 relations{} ;	// 全保持tupleの実件数です。
	std::size_t							 identities{} ;	// 全cohort copyを含む実opaque保持数です。
	IndexLookupStopReason				 stop{} ;		// 最後の完全prefixの停止理由です。
	// 原全recordの終了又は有限保持停止まで、batch256/32768を維持します。
	while( offset < snapshot->schemaReceipt().records().size()) {
		IndexLookupBudget budget ;	// 残保持枠を毎回渡し直します。
		budget.recordOffset				= offset ;
		budget.maximumRelations			= index_capacity::RETAINED_RELATIONS - relations ;
		budget.maximumRelatedIdentities = index_capacity::RETAINED_OPAQUE_IDENTITIES - identities ;
		auto result = lookupSignedIndexRecords( snapshot, issued, issued, present, budget, nowUtc,
											   // 同sourceの本lookupです。
											   resolver.get()) ;
		DRIVERCRATE_EXPECT( context, result.lookup.has_value()) ;
		// 不成立結果の参照で正例の失敗を隠しません。
		if( !result.lookup) {
			throw std::runtime_error( "projection capacity lookup unavailable") ;
		}

		const auto progress = result.lookup->progress() ;	// 同record単位の確定範囲です。
		// 全projectionの元cohort copyを保持opaque分母へ含めます。
		for( const auto &relation : result.lookup->relations()) {
			identities += relation.relatedDevices.size() ;
		}

		relations += result.lookup->relations().size() ;
		offset = progress.nextRecordOffset ;
		stop   = progress.stopReason ;
		// 全recordがcommitしたbatchだけを凍結材料へ残します。
		if( progress.completedRecords > 0U) {
			batches.push_back( std::move( *result.lookup)) ;
		}

		// 保持不足又は進行不能のrecordを飛び越えません。
		if( stop == IndexLookupStopReason::RETAINED_CAPACITY || progress.completedRecords == 0U) {
			break ;
		}
	}

	DRIVERCRATE_EXPECT( context, offset == 5463U && relations == 16385U && identities == 32768U) ;
	DRIVERCRATE_EXPECT( context, overflowing
									? stop == IndexLookupStopReason::RETAINED_CAPACITY &&
										  offset + 1U == snapshot->schemaReceipt().records().size()
									: stop == IndexLookupStopReason::NONE &&
										  offset == snapshot->schemaReceipt().records().size()) ;
	const auto frozen = signed_index_acquisition_detail::Access::freezeFixture(
		snapshot, issued, batches, nowUtc) ;	// 全prefixと元proofを再照合します。
	DRIVERCRATE_EXPECT( context,
					   frozen.lookup && frozen.lookup->relations().size() == relations &&
						   frozen.lookup->progress().nextRecordOffset == offset &&
						   frozen.lookup->snapshot().schemaReceipt().records().size() - offset ==
							   (overflowing ? 1U : 0U)) ;
	DriverStoreBindingProbe::invalidate( run.provider) ;
	DRIVERCRATE_EXPECT( context, !signed_index_acquisition_detail::Access::freezeFixture(
									 snapshot, issued, batches, nowUtc)
									 .lookup) ;
	std::cout << "CAPACITY_PROJECTION {\"overflowing\":" << (overflowing ? "true" : "false")
			  << ",\"committedRecords\":" << offset << ",\"relations\":" << relations
			  << ",\"cohortCopyOpaque\":" << identities
			  << ",\"nextOpaque32769Rejected\":" << (overflowing ? "true" : "false")
			  << ",\"realInventory\":false}\n" ;
}
} // namespace drivercrate::test
