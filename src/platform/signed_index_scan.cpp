//------------------------------------------------------------------------------
/**
 * @file signed_index_scan.cpp
 * @brief 通常worker scanの全batchと協調期限を管理します。
 * @version 01.14.01
 * @date 2026/10/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  秘密所有と全operation予算を通常scanへ接続。
 * Ver.01.00.01 Shunji Ogawa  2026/10/11  停止と保持枠拒否で最初の元照合診断を保持。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  全batch凍結から同active taskの共通取得・内容検査へ接続。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  同認証payloadと取得policyの同一targetを一枠へ予約。
 * Ver.01.04.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.05.00 Shunji Ogawa  2026/10/14  私有証拠付き部分positiveを元未判定件数へ分離保持。
 * Ver.01.06.00 Shunji Ogawa  2026/10/15  UI専用objectで実claim済みtaskを同期観測。
 * Ver.01.07.00 Shunji Ogawa  2026/10/16  通常索引refreshと非通信worker/UI境界を接続。
 * Ver.01.08.00 Shunji Ogawa  2026/11/03  有界large archiveと共有内容保持・標準serviceを接続。
 * Ver.01.09.00 Shunji Ogawa  2026/11/03  署名原範囲の非実行resource内容を接続。
 * Ver.01.10.00 Shunji Ogawa  2026/11/03  匿名CDNの同record二要求と有限予約を接続。
 * Ver.01.11.00 Shunji Ogawa  2026/11/03  拡大recordと有限保持quotaを通常経路へ整合。
 * Ver.01.12.00 Shunji Ogawa  2026/11/07  全体容量・所有stateと有限進行の契約へ整合。
 * Ver.01.13.00 Shunji Ogawa  2026/11/08  同一署名索引の本体再利用から通常loadと照合を継続。
 * Ver.01.14.00 Shunji Ogawa  2026/11/10  対象限定の完了更新と未処理所有・本体再検証を接続。
 * Ver.01.14.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 *
 * @note Crypto・schema・端末照合は既存の共通実装へ委譲します。
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#include "platform/signed_index_scan.h"
#include "platform/provider_worker_index_internal.h"
#include "platform/signed_index_acquisition_adapter_internal.h"
#include "core/provider_registry.h"
#include "platform/official_download_grant.h"
#include "platform/official_download_workspace.h"
#include "platform/common_driver_package.h"
#include "platform/official_file_verifier.h"
#include "platform/signed_index_task_observer_internal.h"
#include <array>
#include <utility>
#include <algorithm>
#include <windows.h>

namespace drivercrate {

//------------------------------------------------------------------------------
/**
 * @brief 同scanの保持量を有限枠内だけで加算する。
 * @param[in] additional 今回検査が実保持したbyte数。
 * @param[in,out] total 元累計。失敗時は変更しない。
 * @return overflowせず3GiB以内へ加算できた場合true。
 */
//------------------------------------------------------------------------------
bool tryRetainIndexedInspectionBytes( const std::uint64_t additional, std::uint64_t &total) noexcept
{
	// 既に不正な累計も、加算overflowも小さい正常値へ戻さない。
	if( total > INDEX_SCAN_RETAINED_MAX_BYTES ||
	   additional > INDEX_SCAN_RETAINED_MAX_BYTES - total) {
		return false ;
	}

	total += additional ;
	return true ;
}
// 通常platformと製品EXEへ観測登録・呼出の定義を生成しません。
#if defined( DRIVERCRATE_INTERNAL_INDEX_TASK_OBSERVER) && defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
namespace {
/** @brief 同workerの同期観測関数です。 */
// 同worker threadだけで使用する非所有noexcept関数pointerです。
thread_local signed_index_task_observer_detail::ApprovedTaskObserver approvedIndexTaskObserver =
	nullptr ;
/** @brief 同workerの同期観測stateです。 */
// 試験がworkerのstop/joinまで共有所有する非所有stateです。
thread_local void *approvedIndexTaskObserverState = nullptr ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同worker threadへ一組の観測pointerを登録し、null対で解除します。
 * @param[in] observer 非nullはstateと対で登録します。nullはstateもnullの場合だけ解除します。
 * @param[in] state Workerのstop/joinまで有効な非所有pointerです。関数と対でnullを受理します。
 * @return 空slotへの登録またはnull対の解除はtrue、不整合または重複登録はfalseです。
 * @note 同workerだけから呼びます。例外・blocking・製品への登録fallbackはありません。
 */
//------------------------------------------------------------------------------
bool signed_index_task_observer_detail::registerApprovedIndexTaskObserver(
	ApprovedTaskObserver observer, void *state) noexcept
{
	// 片方だけのnullと重複登録から未所有stateを呼び出しません。
	if( (observer == nullptr) != (state == nullptr) ||
	   (observer != nullptr && approvedIndexTaskObserver != nullptr)) {
		return false ;
	}

	approvedIndexTaskObserver	   = observer ;
	approvedIndexTaskObserverState = state ;
	return true ;
}
#endif
namespace {
/** @brief Callback回数と時計・取消しを全batch共通で制限します。 */
class LimitedResolver final : public IndexPublicIdResolver {
public:
	/**
	 * @brief 同期scan期間だけ全参照を借用します。
	 * @param[in] inner 元の同scan callback。
	 * @param[in] services 固定service。
	 * @param[in] cancellation 操作限定取消し。
	 * @param[in] deadline 全operation期限。
	 * @param[in,out] summary 全operation件数。
	 */
	LimitedResolver( const IndexPublicIdResolver					 &inner,
					const provider_worker_index_detail::Services &services,
					const ProviderScanCancellation				 &cancellation,
					std::chrono::steady_clock::time_point deadline, IndexScanSummary &summary)
		: inner_( inner), services_( services), cancellation_( cancellation), deadline_( deadline),
		  summary_( summary), batchDeadline_( deadline)
	{
	}
	/**
	 * @brief 種別・contextを保ったまま予算内のcallbackだけを呼びます。
	 * @param[in] kind 元公開ID種別。
	 * @param[in] publishedId 元公開ID。
	 * @param[in] classGuid 元class。
	 * @param[in] context 同scan context。
	 * @param[in] present 全present opaque。
	 * @return 停止・超過では未完了。実callback診断を保持します。
	 */
	[[nodiscard]] IndexPublicIdResolution resolve(
		IndexPnpIdKind kind, std::string_view publishedId, std::string_view classGuid,
		IndexLookupContext context, std::span<const std::wstring> present) const override
	{
		// 取消し・期限・全operation callback上限後に秘密照合を開始しません。
		if( stopped() || summary_.resolverCalls >= services_.maximumCalls) {
			return {.context = context,
					.error	 = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT))} ;
		}

		++summary_.resolverCalls ;
		auto result =
			// 元結果です。
			inner_.resolve( kind, publishedId, classGuid, context, present) ;
		// 同期callback中の取消しや期限到達を正の関係へ昇格しません。
		if( stopped()) {
			result.completed = false ;
			result.devices.clear() ;
			result.positiveProof.reset() ;
			result.deviceProofs.clear() ;
			// 元callback診断がない場合だけ協調停止の診断を補います。
			if( result.error == 0U) {
				result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT)) ;
			}
		}

		return result ;
	}
	/**
	 * @brief Nativeだけが元inventoryの私有leaseを共有します。
	 * @return 元factory発行の不変証拠の共有所有です。generic callbackでは空です。証拠objectは共有しても元inventory/contextの有効性や権限を
	 *         延長しません。
	 * @note 内側resolverのleaseProofを一回呼び、そのshared_ptrを返します。このwrapper自身はleaseを新発行しません。
	 */
	[[nodiscard]] std::shared_ptr<const NativeIndexLookupLease> leaseProof() const noexcept override
	{
		return inner_.leaseProof() ;
	}
	/**
	 * @brief 元全体期限以内の一batch協調期限を開始します。
	 */
	void startBatch()
	{
		batchDeadline_ =
			std::min( deadline_, services_.monotonic() +
									std::chrono::milliseconds{index_capacity::BATCH_MILLISECONDS}) ;
	}
	/**
	 * @brief 現在の協調停止条件を確認します。
	 * @return 取消しまたは期限以上ならtrue。
	 */
	[[nodiscard]] bool stopped() const
	{
		return (cancellation_ && cancellation_()) ||
			   services_.monotonic() >= std::min( deadline_, batchDeadline_) ;
	}

private:
	/// 同scan秘密callbackの借用。
	const IndexPublicIdResolver					 &inner_ ;
	/// Worker固定serviceの借用。
	const provider_worker_index_detail::Services &services_ ;
	/// 同operation取消しの借用。
	const ProviderScanCancellation				 &cancellation_ ;
	/// 全operationの単調期限。
	std::chrono::steady_clock::time_point		  deadline_ ;
	/// 同workerだけが更新する非機密件数。
	IndexScanSummary							 &summary_ ;
	/// 同全体期限以内に固定した一batchの協調期限です。
	std::chrono::steady_clock::time_point		  batchDeadline_ ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief Store／lookupの期限拒否を索引専用区分へ保ちます。
 * @param[in] status Storeの元区分。
 * @return 読取り成立以外の明示区分。
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexScanStatus loadStatus( const IndexStoreStatus status) noexcept
{
	// 元拒否分類だけを映し、空・未配備を成功へまとめません。
	if( status == IndexStoreStatus::TRUST_UNAVAILABLE) {
		return IndexScanStatus::TRUST_UNAVAILABLE ;
	}

	// Genesisは有効な索引世代がない状態です。
	if( status == IndexStoreStatus::EMPTY_STORE) {
		return IndexScanStatus::EMPTY_STORE ;
	}

	// 現在時刻不明は期限内と推測しません。
	if( status == IndexStoreStatus::TIME_UNAVAILABLE) {
		return IndexScanStatus::TIME_UNAVAILABLE ;
	}

	// 発行前の索引を使用しません。
	if( status == IndexStoreStatus::NOT_YET_VALID) {
		return IndexScanStatus::NOT_YET_VALID ;
	}

	// 期限以上の索引を使用しません。
	if( status == IndexStoreStatus::EXPIRED) {
		return IndexScanStatus::EXPIRED ;
	}

	return IndexScanStatus::LOAD_REJECTED ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 秘密snapshot・callback・関係を全て解放します。
 */
//------------------------------------------------------------------------------
void SignedIndexScanSession::invalidate() noexcept
{
	nextOwnedPayloadOrdinal_ = 1U ;
	adapter_.invalidate() ;
	binding_.invalidate( bindingStore_) ;
	acquisition_.reset() ;
	workspace_.reset() ;
	acquisitionLookup_.reset() ;
	context_			= {} ;
	limits_				= {} ;
	preparationSummary_ = {} ;
	batches_.clear() ;
	resolver_.reset() ;
	snapshot_.reset() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常workerの同scan完了後に全operation予算内で読取ります。
 * @param[in,out] provider 実scanを終えた同worker Provider。
 * @param[in] operationId 正のworker operation。
 * @param[in] sessionId 実scan結果と一致する正のsession。
 * @param[in] services 固定製品入口または内部fixture能力。
 * @param[in] cancellation 同operation限定の協調取消し。
 * @param[in] progress 確定record数だけの同期通知。空では通知しません。
 * @return 非機密件数と独立status。元scanの成否を変更しません。
 * @note 例外は秘密所有を破棄して診断へ変換します。
 */
//------------------------------------------------------------------------------
IndexScanSummary SignedIndexScanSession::scan(
	IUpdateProvider &provider, const OperationId operationId, const ScanSessionId sessionId,
	const provider_worker_index_detail::Services		&services,
	const ProviderScanCancellation						&cancellation,
	const std::function<void( const IndexScanSummary &)> &progress) noexcept
{
	invalidate() ;
	IndexScanSummary summary ;	// 終端でも秘密文字列を持たない件数です。
	try {
		// 内部fixtureでも固定製品上限を広げることを認めません。
		if( !services.load || !services.utc || !services.monotonic ||
		   services.maximumRecords > index_capacity::RECORDS ||
		   services.maximumCalls > index_capacity::WHOLE_PUBLIC_IDS ||
		   services.maximumRelations > index_capacity::RETAINED_RELATIONS ||
		   services.duration.count() < 0 ||
		   services.duration > std::chrono::milliseconds{index_capacity::SCAN_MILLISECONDS}) {
			summary.status = IndexScanStatus::INTERNAL_FAILURE ;
			return summary ;
		}

		auto *const inventory =
			dynamic_cast<IIndexScanInventory *>( &provider) ;	// 同scanの秘密seamだけです。
		// SeamのないProviderから製品network/storeや別inventoryを起動しません。
		if( inventory == nullptr) {
			summary.status = IndexScanStatus::INVENTORY_UNAVAILABLE ;
			return summary ;
		}

		// 取消済みcommandはstoreを読みません。
		if( cancellation && cancellation()) {
			summary.status = IndexScanStatus::CANCELLED ;
			return summary ;
		}

		// 明示されたrefreshだけを一回実行し、空のlocal fixtureを製品依存へ補完しません。
		if( services.refresh) {
			summary.refresh = services.refresh( cancellation) ;
			// Commit後でも取消しからlocal候補や未使用grantを発行しません。
			if( (cancellation && cancellation()) ||
			   summary.refresh->status == IndexRefreshStatus::CANCELLED) {
				summary.status = IndexScanStatus::CANCELLED ;
				return summary ;
			}

			// 暗号・rollback・不確定commit等の元失敗を旧cacheの再読取りで隠しません。
			if( summary.refresh->status != IndexRefreshStatus::REFRESHED &&
			   summary.refresh->status != IndexRefreshStatus::AUTHENTICATED_CACHE &&
			   summary.refresh->status != IndexRefreshStatus::UNCHANGED) {
				summary.status = summary.refresh->status == IndexRefreshStatus::TIME_UNAVAILABLE
									 ? IndexScanStatus::TIME_UNAVAILABLE
									 : IndexScanStatus::LOAD_REJECTED ;
				summary.error  = summary.refresh->error ;
				return summary ;
			}
		}

		const auto deadline =
			// Refresh後の独立した全scan期限です。
			services.monotonic() + services.duration ;
		const auto now = services.utc() ;	// 信頼UTCを一度確認します。
		// 時刻不明ではloadを開始しません。
		if( !now) {
			summary.status = IndexScanStatus::TIME_UNAVAILABLE ;
			return summary ;
		}

		// 期限到達後は追加I/Oを開始しません。
		if( services.monotonic() >= deadline) {
			summary.status = IndexScanStatus::BUDGET_EXHAUSTED ;
			return summary ;
		}

		auto loaded			= services.load( now) ;	// 同じ実保存原byteの全再認証です。
		summary.storeStatus = loaded.status ;
		summary.error		= loaded.error ;
		// Load中の取消しはsnapshotを所有しません。
		if( cancellation && cancellation()) {
			summary.status = IndexScanStatus::CANCELLED ;
			return summary ;
		}

		// 未配備・破損・期限切れを候補なし成功へ変換しません。
		if( loaded.status != IndexStoreStatus::SNAPSHOT_READY || !loaded.snapshot) {
			summary.status = loadStatus( loaded.status) ;
			return summary ;
		}

		snapshot_ = std::make_shared<const AuthenticatedIndexSnapshot>( std::move( *loaded.snapshot)) ;
		summary.totalRecords	 = snapshot_->schemaReceipt().records().size() ;
		summary.remainingRecords = summary.totalRecords ;
		// 全codec検査済みrecordの公開入力数を別分母として保持します。
		for( const auto &record : snapshot_->schemaReceipt().records()) {
			summary.totalPublicIds += record.publishedIdentityEvidence.pnpIds.size() ;
		}

		IndexLookupContext		  context ;	// 実Driver Store発行contextです。
		std::vector<std::wstring> present ;	// 同scanの全opaqueです。
		resolver_ = inventory->indexScanInventory( operationId, context, present) ;
		// 別scan／0／不正inventory contextではbatchを開始しません。
		if( !resolver_ || operationId == 0U || sessionId == 0U ||
		   context.operationId != operationId || context.scanSessionId != sessionId ||
		   context.inventoryGeneration == 0U) {
			summary.status = IndexScanStatus::STALE_CONTEXT ;
			invalidate() ;
			return summary ;
		}

		context_ = context ;

		LimitedResolver limited{*resolver_, services, cancellation, deadline,
								summary} ;	// 全batchで同じ予算です。
		// 全recordを処理するか有限operation予算／協調停止まで進めます。
		while( summary.processedRecords < summary.totalRecords) {
			// 中断後の関係は秘密所有も含めて失効します。
			if( cancellation && cancellation()) {
				summary.status = IndexScanStatus::CANCELLED ;
				invalidate() ;
				return summary ;
			}

			// 全operation上限を超える残recordを成功へ数えません。
			if( limited.stopped() || summary.processedRecords >= services.maximumRecords) {
				summary.status = IndexScanStatus::BUDGET_EXHAUSTED ;
				return summary ;
			}

			const auto count =
				std::min( {INDEX_LOOKUP_RECORD_BATCH_MAX, summary.remainingRecords,
						  services.maximumRecords -
							  summary.processedRecords}) ;	// 全operation残枠内のbatchです。
			limited.startBatch() ;
			const auto batchStart  = services.monotonic() ;		// 同じ単調時計のbatch開始値です。
			const auto callsBefore = summary.resolverCalls ;	// 元inner resolverの実呼出数です。
			// 同batchの所有結果と停止理由です。
			auto	   result = lookupSignedIndexRecords(
				  snapshot_, context, context, present,
				  {summary.processedRecords, count,
					   std::min( INDEX_LOOKUP_RESOLVER_CALL_MAX,
								services.maximumCalls - summary.resolverCalls),
					   services.maximumRelations - summary.relationCount,
					   index_capacity::RETAINED_OPAQUE_IDENTITIES - summary.relatedDeviceCount, true,
					   [&limited] { return limited.stopped() ; }},
				  services.utc(), &limited) ;
			summary.maximumBatchResolverCalls =
				std::max( summary.maximumBatchResolverCalls, summary.resolverCalls - callsBefore) ;
			const auto batchElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
										  services.monotonic() - batchStart)
										  .count() ;	// 観測時間です。
			summary.maximumBatchMilliseconds = std::max(
				summary.maximumBatchMilliseconds,
				static_cast<std::size_t>( std::max<decltype( batchElapsed)>( 0, batchElapsed))) ;
			summary.lookupStatus = result.status ;
			// Lookup入力拒否では保存物を後続に保持しません。
			if( !result.lookup) {
				// 後続batchの入力拒否で先行した元callback診断を上書きしません。
				if( summary.error == 0U) {
					summary.error = result.error ;
				}

				summary.status = result.status == IndexRecordLookupStatus::EXPIRED
									 ? IndexScanStatus::EXPIRED
								 : result.status == IndexRecordLookupStatus::TIME_UNAVAILABLE
									 ? IndexScanStatus::TIME_UNAVAILABLE
								 : result.status == IndexRecordLookupStatus::NOT_YET_VALID
									 ? IndexScanStatus::NOT_YET_VALID
									 : IndexScanStatus::STALE_CONTEXT ;
				invalidate() ;
				return summary ;
			}

			// 未commit recordの元診断も先行する失敗を上書きせず保持します。
			if( summary.error == 0U) {
				summary.error = result.error ;
			}

			// 取消し後のpartial positivesから権限を発行しません。
			if( cancellation && cancellation()) {
				summary.status = IndexScanStatus::CANCELLED ;
				invalidate() ;
				return summary ;
			}

			const auto coverage =
				// 同lookupだけがcommitした全record prefixです。
				result.lookup->progress() ;
			// 完全recordに属する保持tupleと元不足だけを計数します。
			for( const auto &relation : result.lookup->relations()) {
				summary.relatedDeviceCount += relation.relatedDevices.size() ;
				++summary.relationCount ;
				summary.matchedRelations +=
					relation.state == IndexRecordMatchState::MATCHED ? 1U : 0U ;
				summary.nonUniqueRelations +=
					relation.reason == IndexRecordMatchReason::NON_UNIQUE_RELATION ? 1U : 0U ;
				summary.undeterminedRelations +=
					relation.state == IndexRecordMatchState::UNDETERMINED ||
							relation.state == IndexRecordMatchState::VERIFIED_PARTIAL ||
							relation.error != 0U
						? 1U
						: 0U ;
				summary.verifiedPartialRelations +=
					relation.state == IndexRecordMatchState::VERIFIED_PARTIAL ? 1U : 0U ;
				// 原callback診断は後続成功で消しません。
				if( summary.error == 0U) {
					summary.error = relation.error ;
				}
			}

			summary.processedRecords += coverage.completedRecords ;
			summary.remainingRecords = summary.totalRecords - summary.processedRecords ;
			summary.processedPublicIds += coverage.processedPublicIds ;
			summary.definitiveNoRelationIds += coverage.definitiveNoRelationIds ;
			// 空の途中recordを完了batchとして保存しません。
			if( coverage.completedRecords != 0U) {
				batches_.push_back( std::move( *result.lookup)) ;
			}

			// 表示の進行は要求countでなく完全record prefixだけです。
			if( progress) {
				progress( summary) ;
			}

			// 最終progress callbackからの取消しも残件なし成功へ通しません。
			if( cancellation && cancellation()) {
				summary.status = IndexScanStatus::CANCELLED ;
				invalidate() ;
				return summary ;
			}

			// 取消し/時刻/保持不足や進行不能を残件ありのまま返します。
			if( coverage.stopReason == IndexLookupStopReason::STOP_REQUESTED ||
			   coverage.stopReason == IndexLookupStopReason::RETAINED_CAPACITY ||
			   coverage.completedRecords == 0U || limited.stopped()) {
				summary.status = IndexScanStatus::BUDGET_EXHAUSTED ;
				return summary ;
			}
			// CALL_BUDGETは完全record境界で次の有限batchへ進み、元IDを飛ばしません。
		}

		// 最終progress callbackからの取消しも残件なし成功へ通しません。
		if( cancellation && cancellation()) {
			summary.status = IndexScanStatus::CANCELLED ;
			invalidate() ;
			return summary ;
		}

		summary.status = summary.undeterminedRelations == 0U && summary.error == 0U &&
								 summary.processedPublicIds == summary.totalPublicIds
							 ? IndexScanStatus::COMPLETED
							 : IndexScanStatus::PARTIAL ;
		return summary ;
	} catch( const std::bad_alloc &) {
		invalidate() ;
		summary.status = IndexScanStatus::INTERNAL_FAILURE ;
		summary.error  = static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		invalidate() ;
		summary.status = IndexScanStatus::INTERNAL_FAILURE ;
		summary.error  = static_cast<NativeError>( E_UNEXPECTED) ;
	}

	return summary ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同scanの全私有batchから既存計画へ取得対象だけを結合します。
 * @param[in,out] plan Providerの元計画または同じ有限上限の空計画。
 * @param[in] services Worker開始前に固定した依存。任意公開鍵を受けません。
 * @param[out] summary 非機密の件数と未接続診断。原UNKNOWNは元snapshotへ保持します。
 * @return 計画の結合成立0。取得能力不足はsummaryへ独立保持して元Provider計画を維持します。
 */
//------------------------------------------------------------------------------
NativeError SignedIndexScanSession::augmentPreparationPlan(
	OfficialPreparationPlan &plan, const provider_worker_index_detail::Services &services,
	IndexPreparationSummary &summary)
{
	preparationSummary_ = {.scanSessionId = plan.scanSessionId, .planId = plan.planId} ;
	// 索引読取り不成立では元Provider計画だけを維持します。
	if( !snapshot_ || !resolver_ || context_.scanSessionId != plan.scanSessionId) {
		summary = preparationSummary_ ;
		return 0U ;
	}

	// 同scanの元計画上限と一意IDを、索引追加で回避しません。
	if( plan.targets.size() > 256U || plan.scanSessionId == 0U || plan.planId == 0U ||
	   acquisitionLookup_) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	auto frozen = SignedIndexRecordLookup::freezeOwnedBatches( snapshot_, context_, batches_,
															  // 原byte／世代／全contextの再照合。
															  services.utc()) ;
	// 全batchが凍結できなければ一部lookupから権限を作りません。
	if( !frozen.lookup) {
		preparationSummary_.authorityError =
			frozen.error != 0U ? frozen.error : static_cast<NativeError>( E_ACCESSDENIED) ;
		summary = preparationSummary_ ;
		return 0U ;
	}

	acquisitionLookup_ = std::make_shared<const SignedIndexRecordLookup>( std::move( *frozen.lookup)) ;
	limits_			   = plan.limits ;
	const auto os =
		services.targetOs ? services.targetOs() : std::nullopt ;	// WorkerのOS観測だけです。
	// OS不明をrecordの公開条件から補完しません。
	if( !os) {
		preparationSummary_.authorityError = static_cast<NativeError>( E_NOTIMPL) ;
	} else {
		preparationSummary_.authorityError =
			services.beginAcquisition
				? services.beginAcquisition( adapter_, acquisitionLookup_, context_, *os,
											services.utc())
				: adapter_.begin( acquisitionLookup_, context_, *os, services.utc()) ;
	}

	// 製品取得policy未配備では元Provider計画を残し、索引不足件数だけを返します。
	if( preparationSummary_.authorityError != 0U) {
		preparationSummary_.unavailableRelations = acquisitionLookup_->relations().size() ;
		summary									 = preparationSummary_ ;
		return 0U ;
	}

	std::unique_ptr<OfficialHttpClient> termsClient ;	// 本文が必要な元recordでだけ生成します。
	// 全batchのglobal関係位置だけを使用し、計画全体256対象を越えません。
	for( std::size_t relationIndex = 0U; relationIndex < acquisitionLookup_->relations().size();
		++relationIndex) {
		// 枠超過分を候補なし成功へ数えず元recordは不変に保持します。
		if( plan.targets.size() >= 256U) {
			++preparationSummary_.capacityRejectedRelations ;
			continue ;
		}

		SignedIndexPreparationDescription description ;							// 同原関係だけの非機密対象と私有理由。
		NativeError						  error{} ;								// 同意不要からnetwork clientを生成しません。
		const auto &relation = acquisitionLookup_->relations()[relationIndex] ;	// 同原関係です。
		const auto &original = acquisitionLookup_->snapshot()
								   .schemaReceipt()
								   .records()[relation.recordIndex] ;	// 原recordです。
		// 同意必須の元recordだけが全文取得を必要とします。
		if( original.acquisitionDescriptor &&
		   original.acquisitionDescriptor->terms.state == IndexTermsState::ACCEPTANCE_REQUIRED) {
			// 完全HTTP表を一度だけ同workerへ固定します。
			if( !termsClient) {
				termsClient = services.httpTransport
								  ? std::make_unique<OfficialHttpClient>( services.httpTransport())
								  : std::make_unique<OfficialHttpClient>( false) ;
			}

			error =
				adapter_.readTermsText( relationIndex, context_, services.utc(), *termsClient, {}) ;
		}

		// 全文不成立の対象はpayloadの取得同意計画へ入れません。
		if( error == 0U) {
			error = adapter_.describe( relationIndex, context_, services.utc(), limits_,
									  description) ;	// 同scan予約上限を維持します。
		}

		// UNKNOWN・未対応・非一意は取得対象を発行せず元理由をsnapshotへ残します。
		if( error != 0U || !description.target) {
			++preparationSummary_.unavailableRelations ;
			continue ;
		}

		const auto existingTarget = std::ranges::find_if( plan.targets, [&]( const auto &target) {
			return target.identity == description.target->identity ;
		}) ; // 同issuerが全元関係へ結合した共有targetだけを一回予約します。
		// 同じ共有targetの完全一致は別payload予約や取得件数へ重複追加しません。
		if( existingTarget != plan.targets.end() && *existingTarget == *description.target &&
		   existingTarget->providerId == SIGNED_INDEX_PROVIDER_ID) {
			continue ;
		}

		// 同じIDでも値やProviderが異なる対象は黙って削除しません。
		if( existingTarget != plan.targets.end()) {
			adapter_.invalidate() ;
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		plan.targets.push_back( std::move( *description.target)) ;
		++preparationSummary_.plannedTargets ;
	}

	summary = preparationSummary_ ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同active taskだけを共通grant・取得seal・通常内容検査へ接続します。
 * @param[in,out] preparation 実approve／claimNextしたworker session。
 * @param[in] task 同計画の未変更active task。元scan操作とは別です。
 * @param[in] services Worker固定のHTTP・時計・回線依存。
 * @param[in] cancellation 同取得操作の協調停止。
 * @return 取得の確定結果。内容失敗は独立summaryへ残します。
 * @throws std::bad_alloc 内部allocationに失敗した場合。
 * @throws ... 内部serviceが送出した元例外。
 * @note Workerの取得callbackは例外を再throwする前にinvalidateAcquisitionを呼びます。
 */
//------------------------------------------------------------------------------
OfficialPreparationTransferResult SignedIndexScanSession::acquireForInspection(
	OfficialPreparationSession &preparation, const OfficialPreparationTask &task,
	const provider_worker_index_detail::Services &services,
	const PreparationCancellation				 &cancellation)
{
	IndexPreparationItemSummary item{.targetIdentity =
										 task.target.identity} ;	// URL・hash・pathを含みません。
	// 実active taskと元planが一致しない要求は共通取得より前に拒否します。
	if( !acquisitionLookup_ || task.scanSessionId != context_.scanSessionId ||
	   task.planId != preparationSummary_.planId || !preparation.ownsActiveTask( task) ||
	   preparationSummary_.items.size() >= 256U) {
		return {OfficialPreparationItemState::REJECTED, static_cast<NativeError>( E_ACCESSDENIED),
				0U} ;
	}

	// 原TRANSFERのowned fileだけを直接参照します。local→localの連鎖を作りません。
	for( std::size_t sourceIndex = 0U; sourceIndex < binding_.records_.size(); ++sourceIndex) {
		const auto &source = binding_.records_[sourceIndex] ;	// 原owned recordです。
		// 同配布tupleの原所有があれば通信へfallbackせず、新承認の独立検査へ進みます。
		if( !source.ownedBodyRecordIndex && adapter_.matchesRetainedBody( task, source.task)) {
			return inspectRetainedBody( preparation, task, sourceIndex, services, cancellation) ;
		}
	}

	const auto utcClock = [&services]() -> std::uint64_t {
		const auto now = services.utc() ;	// 信頼時計の再照会。失敗では0です。
		return now && now->time_since_epoch().count() > 0
				   ? static_cast<std::uint64_t>( now->time_since_epoch().count())
				   : 0U ;
	} ; // 同期呼出し中だけworker固定serviceを借用します。
	SignedIndexCandidateBindingSession::PreparedRecord record ;	// 元権限と閉包をmove所有します。
	record.lookup		 = acquisitionLookup_ ;
	record.context		 = context_ ;
	record.task			 = task ;
	const auto reference = std::find_if( binding_.references_.begin(), binding_.references_.end(),
										[&task]( const auto &value) {
											return value.target == task.target ;
										}) ; // 元同targetへの私有対応。
	// 取得検査専用の既存fixtureから参照なしの候補を発行しません。
	record.referenceIndex =
		reference == binding_.references_.end()
			? binding_.references_.size()
			: static_cast<std::size_t>( reference - binding_.references_.begin()) ;
	auto &grant = record.grant ;	// 同active taskから一回だけ発行する既存grant。
								// UI専用objectだけで元claim後・grant発行前の同期観測を行います。
#if defined( DRIVERCRATE_INTERNAL_INDEX_TASK_OBSERVER) && defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
	// 同workerが登録したnoexcept観測だけへ同期中の実所有者を貸します。
	if( approvedIndexTaskObserver != nullptr) {
		approvedIndexTaskObserver( approvedIndexTaskObserverState, preparation, task, adapter_,
								  context_, utcClock(), *this) ;
	}
#endif
	const auto grantError =
		// 一回grant。
		adapter_.claimApprovedRecord( preparation, task, context_, utcClock(), grant) ;
	// 改変・再使用・期限切れ・別issuerでは取得を開始しません。
	if( grantError != 0U) {
		// 拒否した当該taskの結果だけを残し、未処理owner/issuerを失効させません。
		item.acquisition	  = OfficialAcquisitionState::REJECTED ;
		item.acquisitionError = grantError ;
		preparationSummary_.items.push_back( item) ;
		return {OfficialPreparationItemState::REJECTED, grantError, 0U} ;
	}

	// 同scanだけの保護領域と成功byte累積ledgerを最初の選択時に一度作ります。
	if( !workspace_ || !acquisition_) {
		auto workspace = std::make_unique<OfficialDownloadWorkspace>() ;	// 初期化失敗時の自動回収。
		auto acquisition = std::make_unique<OfficialAcquisitionSession>() ;	// 同scanの累積ledger。
		NativeError error =
			// 保護領域のみ。
			workspace->initialize( L"signed-index", task.scanSessionId) ;
		// 元計画と同じ上限で取得ledgerを開始し、Provider別と全scan枠を維持します。
		if( error == 0U) {
			error = acquisition->initialize(
				task.scanSessionId, {limits_.maximumFileBytes, limits_.maximumProviderBytes,
									 limits_.maximumSessionBytes, 256ULL * 1024ULL * 1024ULL,
									 limits_.maximumProviderFiles, limits_.maximumSessionFiles}) ;
		}

		// 保護領域不成立を一般Tempや未保護fileへfallbackしません。
		if( error != 0U) {
			item.acquisition	  = OfficialAcquisitionState::FAILURE ;
			item.acquisitionError = error ;
			preparationSummary_.items.push_back( item) ;
			return {OfficialPreparationItemState::FAILURE, error, 0U} ;
		}

		workspace_	 = std::move( workspace) ;
		acquisition_ = std::move( acquisition) ;
	}

	auto							 client = services.httpTransport
												  ? std::make_unique<OfficialHttpClient>( services.httpTransport())
												  : std::make_unique<OfficialHttpClient>(
							false) ;						// 製品は既存共通HTTPS、fixtureは完全低位fake。
	OfficialHttpAcquisitionTransport transport{*client} ;	// 同grantの共通HTTP validatorを通ります。
	auto							 cost = services.costReader
												? services.costReader()
												: std::make_unique<
													  WindowsOfficialNetworkCostReader>() ;	// 内部fixture以外は標準cost照会。
	// 不完全な内部依存から製品回線境界へ縮退しません。
	if( !cost) {
		item.acquisition	  = OfficialAcquisitionState::FAILURE ;
		item.acquisitionError = static_cast<NativeError>( E_UNEXPECTED) ;
		preparationSummary_.items.push_back( item) ;
		return {OfficialPreparationItemState::FAILURE, static_cast<NativeError>( E_UNEXPECTED), 0U} ;
	}

	const auto relationIndex =
		// 私有grantが封印した元関係です。
		grant.metadata().recordEvidenceId - 1U ;
	// 表示IDや外部tupleから形式や保存pathを組み立てません。
	if( relationIndex >= acquisitionLookup_->relations().size()) {
		return {OfficialPreparationItemState::REJECTED, static_cast<NativeError>( E_ACCESSDENIED),
				0U} ;
	}

	const auto &distribution =
		acquisitionLookup_->snapshot().schemaReceipt().records()
			[acquisitionLookup_->relations()[relationIndex].recordIndex] ;	// 同元認証recordです。
	const auto payloadFormat =
		distribution.acquisitionDescriptor->format ;	// 元方式へcodec結合済みです。
	const auto extension = payloadFormat == IndexPayloadFormat::CABINET ? L".cab"
						   : (payloadFormat == IndexPayloadFormat::WINDOWS_EXE ||
							  payloadFormat == IndexPayloadFormat::SEVEN_ZIP_SFX ||
							  payloadFormat == IndexPayloadFormat::PE_RESOURCE_CONTAINER)
							   ? L".exe"
						   : payloadFormat == IndexPayloadFormat::WINDOWS_MSI
							   ? L".msi"
							   : L".zip" ;	// 固定四形式だけです。
	const auto fileName	 = L"index-payload-" + std::to_wstring( nextOwnedPayloadOrdinal_++) +
						  extension ;	// 元wireのfilenameではなく保護所有者の不透明名です。
	// 同一保護領域の各対象でCREATE_NEW用相対名を一意にします。
	const OfficialAcquisitionRequest request{.workspaceFileName = fileName,
											 .restrictedNetworkApproved =
												 task.restrictedNetworkApproved,
											 .delegatedGrant   = &grant,
											 .delegatedGrantId = grant.metadata().grantId,
											 .delegatedUtcNow  = utcClock} ;
	auto	  &acquired		= record.acquisition ;	// 実path/hashを元私有recordへ保持します。
	const auto acquireError = acquisition_->acquire(
		request, *workspace_, transport, *cost, []( std::uint64_t, std::uint64_t) {}, cancellation,
		acquired) ;	// 同期転送中は確定件数を増やしません。
	item.acquisition	  = acquired.state ;
	item.acquisitionError = acquireError ;
	item.auxiliaryHttp	  = acquired.auxiliaryHttp ;
	// 成功取得だけを元sealと実byte内容検査へ進めます。
	if( acquireError == 0U) {
		auto &evidence = record.seal ;	// 公開取得DTOから作れない実seal。
		item.contentError =
			acquisition_->bindAcquiredFile( *workspace_, acquired.acquisitionId, evidence) ;
		auto &hint	= record.hint ;		// 原record/descriptorへ結合する実byte期待値。
		auto &input = record.input ;	// 元保護archiveを所有者の寿命に結合します。
		// 取得seal成立時だけ同task／同issuerの元recordへ再照合します。
		if( item.contentError == 0U) {
			item.contentError = adapter_.bindInspectionInput(
				task, context_, utcClock(), *acquisition_, *workspace_, evidence, hint, input) ;
		}

		auto &inspected = record.inspection ;	// 内容・CATの個別拒否と保護閉包を所有します。
		// 同消費済みgrantと実ledgerを結合し、DTOから権限を生成しません。
		if( item.contentError == 0U &&
		   *distribution.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE) {
			item.contentError =
				(payloadFormat == IndexPayloadFormat::PE_RESOURCE_CONTAINER ||
				 payloadFormat == IndexPayloadFormat::SEVEN_ZIP_SFX)
					? makeDelegatedOfficialPackageInput(
						  acquired, grant, hint,
						  payloadFormat == IndexPayloadFormat::PE_RESOURCE_CONTAINER
							  ? OfficialDriverArchiveFormat::PE_RESOURCE_CONTAINER
							  : OfficialDriverArchiveFormat::SEVEN_ZIP_SFX,
						  record.delegated)
					: makeDelegatedOfficialPackageInput( acquired, grant, record.delegated) ;
		}

		// 実byteと元record結合が成立した対象だけ通常policyで内容検査します。
		if( item.contentError == 0U &&
		   *distribution.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE) {
			item.contentError = inspectIndexedDriverPackage(
				task.scanSessionId, hint, input,
				payloadFormat == IndexPayloadFormat::CABINET ? OfficialDriverArchiveFormat::CABINET
				: payloadFormat == IndexPayloadFormat::PE_RESOURCE_CONTAINER
					? OfficialDriverArchiveFormat::PE_RESOURCE_CONTAINER
				: payloadFormat == IndexPayloadFormat::SEVEN_ZIP_SFX
					? OfficialDriverArchiveFormat::SEVEN_ZIP_SFX
					: OfficialDriverArchiveFormat::ZIP,
				inspected, cancellation) ;
		} else {
			inspected.state = IndexedDriverInspectionState::INPUT_REJECTED ;
		}

		// EXE/MSIは展開せず、同seal/原hash/publisherを専用署名境界へ結びます。
		if( *distribution.acquisition.value == IndexAcquisitionKind::OFFICIAL_INSTALLER) {
			record.installerHandoff = true ;
			record.msi				= payloadFormat == IndexPayloadFormat::WINDOWS_MSI ;
			record.publisher =
				// 元grantの厳密UTF-8変換済み期待値です。
				grant.payloadView().publisher ;
			// 原byteと同recordの結合前に署名処理を実行しません。
			if( item.contentError == 0U) {
				const std::array<std::wstring_view, 1U> publishers{
					record.publisher} ;	// 元exact publisherだけです。
				item.contentError = verifyAuthenticodePublisher( input.inspectionPath, publishers) ;
			}

			record.installerError = item.contentError ;
			inspected.state		  = item.contentError == 0U
										? IndexedDriverInspectionState::INSTALLER_INSPECTION_COMPLETED
										: IndexedDriverInspectionState::INSPECTION_FAILED ;
			inspected.error		  = item.contentError ;
			inspected.inputBound  = item.contentError == 0U ;
		}

		item.content			= inspected.state ;
		item.inputBound			= inspected.inputBound ;
		item.inventoryFileCount = inspected.inspection.inventoryFileCount ;
		item.infCount			= inspected.inspection.infs.size() ;
		// 最大128 INFの内容合格数と元の最初の拒否診断を別々に保持します。
		for( const auto &inf : inspected.inspection.infs) {
			item.acceptedInfCount += inf.state == CommonInfInspectionState::VERIFIED ? 1U : 0U ;
			item.signatureRejectedInfCount +=
				inf.state == CommonInfInspectionState::SIGNATURE_REJECTED ? 1U : 0U ;
			item.parsedInfCount += inf.state == CommonInfInspectionState::SIGNATURE_REJECTED ||
										   inf.state == CommonInfInspectionState::VERIFIED
									   ? 1U
									   : 0U ;
			// 全体完了でも最初の個別拒否を成功値で上書きしません。
			if( item.firstInfRejection == 0U && inf.error != 0U) {
				item.firstInfRejection = inf.error ;
			}
		}

		const auto retained = inspected.inspection.retainedBytes ;	// 実閉包の保持byte。
		// 過大閉包を切捨て成功にせず、容量不足へ保持します。
		if( !tryRetainIndexedInspectionBytes( retained, binding_.retainedBytes_)) {
			item.contentError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
			item.acceptedInfCount = 0U ;
			record.inspection	  = {} ;
		}

		binding_.records_.push_back( std::move( record)) ;
	}

	preparationSummary_.items.push_back( std::move( item)) ;
	// 内容失敗後も取得成功は取得成功のまま保持し、UIで独立した失敗を表示します。
	return {acquireError == 0U ? OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION
			: acquired.state == OfficialAcquisitionState::CANCELLED
				? OfficialPreparationItemState::CANCELLED
			: acquired.state == OfficialAcquisitionState::REJECTED
				? OfficialPreparationItemState::REJECTED
				: OfficialPreparationItemState::FAILURE,
			acquireError, acquired.byteCount} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元owned bodyを新active taskで非通信再検査します。
 * @param[in,out] preparation 当該active taskの所有者です。
 * @param[in] task 新しい明示承認taskです。
 * @param[in] sourceIndex 元TRANSFER recordの安定indexです。
 * @param[in] services 元時計です。通信は呼びません。
 * @param[in] cancellation 同検査の取消しです。
 * @return 実検査の終端と当該local照合票です。取得成功は再発行しません。
 */
//------------------------------------------------------------------------------
OfficialPreparationTransferResult SignedIndexScanSession::inspectRetainedBody(
	OfficialPreparationSession &preparation, const OfficialPreparationTask &task,
	const std::size_t sourceIndex, const provider_worker_index_detail::Services &services,
	const PreparationCancellation &cancellation)
{
	IndexPreparationItemSummary item{.targetIdentity =
										 task.target.identity} ;		// 取得を再発行しません。
	NativeError error	= static_cast<NativeError>( E_ACCESSDENIED) ;	// 原拒否を保持します。
	const auto	binding = std::ranges::find(
		 adapter_.bindings_, task.target,
		 &SignedIndexAcquisitionAdapter::PreparedBinding::target) ;	// 新Bの元targetです。
	// 現在承認と原ownerがなければhash/pathだけで許可しません。
	if( preparation.ownsActiveTask( task) && sourceIndex < binding_.records_.size() &&
	   binding != adapter_.bindings_.end() && !binding->claimedTask &&
	   !binding_.records_[sourceIndex].ownedBodyRecordIndex) {
		error = binding_.reverifyRecord( *this, binding_.records_[sourceIndex], services) ;
	}

	SignedIndexCandidateBindingSession::PreparedRecord
		record ;	// Bの新しい実検査結果だけを所有します。
	// 原TRANSFERの期限/所有/実byte成立後だけ、新しいLOCAL taskを一回claimします。
	if( error == 0U) {
		record.localInspection = preparation.claimIndexLocalInspection( task) ;
		// 他用途の既claimや別active taskを拒否します。
		if( !record.localInspection) {
			error = static_cast<NativeError>( E_ACCESSDENIED) ;
		}
	}

	// 元grant/report/token/sealをBへ複写しません。
	if( error == 0U) {
		record.lookup					= acquisitionLookup_ ;
		record.context					= context_ ;
		record.task						= task ;
		record.ownedBodyRecordIndex		= sourceIndex ;
		binding->claimedTask			= task ;
		binding->localInspectionClaimed = true ;
		const auto reference			= std::ranges::find(
			   binding_.references_, task.target,
			   &SignedIndexCandidateBindingSession::Reference::target) ;	// Bの原参照です。
		record.referenceIndex = static_cast<std::size_t>( reference - binding_.references_.begin()) ;
		const auto	now		  = services.utc ? services.utc() : std::nullopt ;	// 原時計です。
		const auto	seconds	  = now && now->time_since_epoch().count() > 0
									? static_cast<std::uint64_t>( now->time_since_epoch().count())
									: 0U ;							// 正のUTCだけです。
		const auto &source	  = binding_.records_[sourceIndex] ;	// 原ownerを借用し移動しません。
		error				  = adapter_.bindRetainedInspectionInput(
			task, source.task, context_, seconds, *acquisition_, *workspace_, source.seal,
			*record.localInspection, record.hint, record.input) ;
		// 新対象の原selectorへ実INF/CATを独立検査します。Aの合格を流用しません。
		if( error == 0U) {
			error = inspectIndexedDriverPackage( task.scanSessionId, record.hint, record.input,
												source.delegated.format, record.inspection,
												cancellation) ;
		}

		item.reusedOwnedBody	= true ;
		item.content			= record.inspection.state ;
		item.inputBound			= record.inspection.inputBound ;
		item.inventoryFileCount = record.inspection.inspection.inventoryFileCount ;
		item.infCount			= record.inspection.inspection.infs.size() ;
		// 新しい検査事実だけを数え、過去取得日時を変更しません。
		for( const auto &inf : record.inspection.inspection.infs) {
			item.acceptedInfCount += inf.state == CommonInfInspectionState::VERIFIED ? 1U : 0U ;
			item.signatureRejectedInfCount +=
				inf.state == CommonInfInspectionState::SIGNATURE_REJECTED ? 1U : 0U ;
			item.parsedInfCount += inf.state == CommonInfInspectionState::VERIFIED ||
										   inf.state == CommonInfInspectionState::SIGNATURE_REJECTED
									   ? 1U
									   : 0U ;
			// 最初の個別拒否を合格件数で消しません。
			if( item.firstInfRejection == 0U && inf.error != 0U) {
				item.firstInfRejection = inf.error ;
			}
		}

		// 同scanの既保持上限を独立検査でも維持します。
		if( !tryRetainIndexedInspectionBytes( record.inspection.inspection.retainedBytes,
											binding_.retainedBytes_)) {
			error			  = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
			record.inspection = {} ;
			item.content	  = IndexedDriverInspectionState::INSPECTION_FAILED ;
			item.inventoryFileCount		   = 0U ;
			item.infCount				   = 0U ;
			item.parsedInfCount			   = 0U ;
			item.acceptedInfCount		   = 0U ;
			item.signatureRejectedInfCount = 0U ;
			item.firstInfRejection		   = 0U ;
		}
	}

	item.contentError = error ;
	// 入力未成立を未開始成功や再取得成功へ変えません。
	if( !item.reusedOwnedBody) {
		item.acquisition	  = OfficialAcquisitionState::REJECTED ;
		item.acquisitionError = error ;
		item.contentError	  = 0U ;
	}

	const auto local = record.localInspection ;	// 同active claimの照合票だけを結果へ結びます。
	// 原recordは安定indexで保持し、原Aのownerを消費routeと一緒に消しません。
	if( record.localInspection) {
		binding_.records_.push_back( std::move( record)) ;
	}

	preparationSummary_.items.push_back( std::move( item)) ;
	return error == 0U ? OfficialPreparationTransferResult{OfficialPreparationItemState::
															   LOCAL_INSPECTION_COMPLETED,
														   0U, 0U, local}
					   : OfficialPreparationTransferResult{OfficialPreparationItemState::REJECTED,
														   error, 0U} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元計画と今回の操作へ非機密結果だけを複写します。
 * @param[in] operationId 実取得operation。0では計画summaryです。
 * @return 同scan／planと有限個別結果。秘密所有を含みません。
 */
//------------------------------------------------------------------------------
IndexPreparationSummary SignedIndexScanSession::preparationSummary(
	const OperationId operationId) const
{
	auto summary		= preparationSummary_ ;	// 非機密の確定snapshotだけを複写します。
	summary.operationId = operationId ;
	return summary ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原metadataだけで残planを検証し当該summaryを開始します。
 * @param[in,out] plan 原tuple/予算のsubsetです。失効対象だけを除きます。
 * @param[in] services 元信頼時計です。HTTPは呼びません。
 * @return 原context/新ID/予算が整合した場合trueです。
 */
//------------------------------------------------------------------------------
bool SignedIndexScanSession::retainPreparationPlan(
	OfficialPreparationPlan &plan, const provider_worker_index_detail::Services &services)
{
	// 原索引ownerなしで索引targetを新たに追加しません。
	if( !acquisitionLookup_) {
		return std::ranges::none_of( plan.targets, []( const auto &target) {
			return target.providerId == SIGNED_INDEX_PROVIDER_ID ;
		}) ;
	}

	// 原予算/scanと新しいplan IDだけを使います。
	if( plan.scanSessionId != context_.scanSessionId || plan.planId <= preparationSummary_.planId ||
	   plan.limits != limits_) {
		return false ;
	}

	const auto now = services.utc ? services.utc() : std::nullopt ;	// 原時計です。
	std::erase_if( plan.targets, [&]( const auto &target) {
		// 他Providerの原記述はこのadapterで変更しません。
		if( target.providerId != SIGNED_INDEX_PROVIDER_ID) {
			return false ;
		}

		const auto	binding = std::ranges::find_if( adapter_.bindings_, [&]( const auto &entry) {
			 return entry.target == target ;
		 }) ;				// 元targetです。
		std::string reason ;	// 非公開診断です。
		return binding == adapter_.bindings_.end() || binding->claimedTask ||
			   adapter_.validateBinding( *binding, context_, now, reason) != 0U ;
	}) ;
	preparationSummary_.planId = plan.planId ;
	preparationSummary_.items.clear() ;
	preparationSummary_.plannedTargets = static_cast<std::uint64_t>(
		std::ranges::count( plan.targets, std::wstring{SIGNED_INDEX_PROVIDER_ID},
						   &OfficialPreparationTarget::providerId)) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Adapterの取得能力とissuer leaseを失効し、確定結果と内容所有を保持します。
 * @note 新しいgrantと未使用grantの使用を拒否し、snapshot、lookup、取得ledger、workspace、summary、検査閉包は解放しません。同期callbackの
 *       借用を破壊しません。
 */
//------------------------------------------------------------------------------
void SignedIndexScanSession::invalidateAcquisition() noexcept
{
	adapter_.invalidate() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 新取得だけを閉鎖し、同期限内の消費済み元根拠を導入終端まで保持します。
 */
//------------------------------------------------------------------------------
void SignedIndexScanSession::closeAcquisitionForInstall() noexcept
{
	adapter_.closeAcquisitionForInstall() ;
}
} // namespace drivercrate
