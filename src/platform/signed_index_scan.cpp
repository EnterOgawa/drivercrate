//------------------------------------------------------------------------------
/**
 * @file signed_index_scan.cpp
 * @brief 通常worker scanの全batchと協調期限を管理します。
 * @version 01.07.00
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

/** @see signed_index_task_observer_internal.h 宣言側の契約を正本とします。 */
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
	/** @brief 同期scan期間だけ全参照を借用します。
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
		  summary_( summary)
	{
	}
	/** @brief 種別・contextを保ったまま予算内のcallbackだけを呼びます。
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
			// 元callback診断がない場合だけ協調停止の診断を補います。
			if( result.error == 0U) {
				result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT)) ;
			}
		}

		return result ;
	}
	/** @brief 現在の協調停止条件を確認します。
	 * @return 取消しまたは期限以上ならtrue。
	 */
	[[nodiscard]] bool stopped() const
	{
		return (cancellation_ && cancellation_()) || services_.monotonic() >= deadline_ ;
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
} ;

/** @brief Store／lookupの期限拒否を索引専用区分へ保ちます。
 * @param[in] status Storeの元区分。
 * @return 読取り成立以外の明示区分。
 */
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

/** @see signed_index_scan.h */
void SignedIndexScanSession::invalidate() noexcept
{
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

/** @see signed_index_scan.h */
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
		   services.maximumRecords > 16384U || services.maximumCalls > 32768U ||
		   services.maximumRelations > 32768U || services.duration.count() < 0 ||
		   services.duration > std::chrono::milliseconds{5000}) {
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
			   summary.refresh->status != IndexRefreshStatus::AUTHENTICATED_CACHE) {
				summary.status = summary.refresh->status == IndexRefreshStatus::TIME_UNAVAILABLE
									 ? IndexScanStatus::TIME_UNAVAILABLE
									 : IndexScanStatus::LOAD_REJECTED ;
				summary.error  = summary.refresh->error ;
				return summary ;
			}
		}

		const auto deadline = services.monotonic() + services.duration ;	// Refresh後の独立5秒です。
		const auto now		= services.utc() ;								// 信頼UTCを一度確認します。
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
			if( limited.stopped() || summary.processedRecords >= services.maximumRecords ||
			   summary.resolverCalls >= services.maximumCalls ||
			   summary.relationCount >= services.maximumRelations) {
				summary.status = IndexScanStatus::BUDGET_EXHAUSTED ;
				return summary ;
			}

			const auto count =
				std::min( {INDEX_LOOKUP_RECORD_BATCH_MAX, summary.remainingRecords,
						  services.maximumRecords -
							  summary.processedRecords}) ;	// 全operation残枠内のbatchです。
			auto result = lookupSignedIndexRecords(
				snapshot_, context, context, present,
				{summary.processedRecords, count, services.maximumCalls - summary.resolverCalls},
				// UTCは各batchで再確認します。
				services.utc(), &limited) ;
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

			// 有限batchの診断だけを先に読み、取消し・保持枠拒否でも元エラーを失いません。
			// ここでは正の関係を保持せず、recordや関係の処理済み件数も更新しません。
			for( const auto &relation : result.lookup->relations()) {
				// 最初の非0診断を保持し、後続の合成timeoutで置換しません。
				if( summary.error == 0U && relation.error != 0U) {
					summary.error = relation.error ;
				}
			}

			// 取消し後のpartial positivesを通常完了にしません。
			if( cancellation && cancellation()) {
				summary.status = IndexScanStatus::CANCELLED ;
				invalidate() ;
				return summary ;
			}

			// Tuple確保枠を超えるbatchは全recordを未処理のまま残します。
			if( result.lookup->relations().size() >
			   services.maximumRelations - summary.relationCount) {
				summary.status = IndexScanStatus::BUDGET_EXHAUSTED ;
				return summary ;
			}

			std::size_t batchDevices{} ;	// 全batch共通のopaque保持枠を先に確認します。
			bool		batchExhausted{} ;	// Batch内の未実行callbackも全体停止へ保持します。
			// 有限batchのopaque保持数を積算し、余剰を秘密sessionへ移しません。
			for( const auto &relation : result.lookup->relations()) {
				batchDevices += relation.relatedDevices.size() ;
				batchExhausted |= relation.reason == IndexRecordMatchReason::BUDGET_EXHAUSTED ;
			}

			// 同じrecordで複数deviceへ結ぶ場合も累積保持を制限します。
			if( batchDevices > 32768U - summary.relatedDeviceCount) {
				summary.status = IndexScanStatus::BUDGET_EXHAUSTED ;
				return summary ;
			}

			summary.relatedDeviceCount += batchDevices ;
			// 停止・保持枠確認後にだけ元関係区分を全batchへ累積します。
			for( const auto &relation : result.lookup->relations()) {
				++summary.relationCount ;
				summary.matchedRelations +=
					relation.state == IndexRecordMatchState::MATCHED ? 1U : 0U ;
				summary.nonUniqueRelations +=
					relation.reason == IndexRecordMatchReason::NON_UNIQUE_RELATION ? 1U : 0U ;
				summary.undeterminedRelations +=
					relation.state == IndexRecordMatchState::UNDETERMINED ||
							relation.state == IndexRecordMatchState::VERIFIED_PARTIAL
						? 1U
						: 0U ;
				summary.verifiedPartialRelations +=
					relation.state == IndexRecordMatchState::VERIFIED_PARTIAL ? 1U : 0U ;
			}

			batches_.push_back( std::move( *result.lookup)) ;
			summary.processedRecords += count ;
			summary.remainingRecords = summary.totalRecords - summary.processedRecords ;
			// 実際に保持できたrecord数だけを通知し、同期callback待ちでは増やしません。
			if( progress) {
				progress( summary) ;
			}

			// 最後のbatchの未実行を全読取り完了へ昇格しません。
			if( batchExhausted) {
				summary.status = IndexScanStatus::BUDGET_EXHAUSTED ;
				return summary ;
			}

			// Callback中の期限到達を全完了へ昇格しません。
			if( limited.stopped()) {
				summary.status = IndexScanStatus::BUDGET_EXHAUSTED ;
				return summary ;
			}
		}

		summary.status = summary.undeterminedRelations == 0U ? IndexScanStatus::COMPLETED
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

/** @see SignedIndexScanSession 宣言側の契約を正本とする。 */
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

/** @see SignedIndexScanSession 宣言側の契約を正本とする。 */
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
		adapter_.invalidate() ;
		preparationSummary_.authorityError = grantError ;
		item.acquisition				   = OfficialAcquisitionState::REJECTED ;
		item.acquisitionError			   = grantError ;
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
	const auto extension = payloadFormat == IndexPayloadFormat::CABINET		  ? L".cab"
						   : payloadFormat == IndexPayloadFormat::WINDOWS_EXE ? L".exe"
						   : payloadFormat == IndexPayloadFormat::WINDOWS_MSI
							   ? L".msi"
							   : L".zip" ;	// 固定四形式だけです。
	const auto fileName	 = L"index-payload-" + std::to_wstring( preparationSummary_.items.size()) +
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
				makeDelegatedOfficialPackageInput( acquired, grant, record.delegated) ;
		}

		// 実byteと元record結合が成立した対象だけ通常policyで内容検査します。
		if( item.contentError == 0U &&
		   *distribution.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE) {
			item.contentError = inspectIndexedDriverPackage(
				task.scanSessionId, hint, input,
				payloadFormat == IndexPayloadFormat::CABINET ? OfficialDriverArchiveFormat::CABINET
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
		const auto maximum =
			std::min<std::uint64_t>( 512ULL * 1024ULL * 1024ULL,
									limits_.maximumSessionBytes) ;	// 元session予算を拡大しません。
		// 過大閉包を切捨て成功にせず、容量不足へ保持します。
		if( retained > maximum - std::min( maximum, binding_.retainedBytes_)) {
			item.contentError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
			item.acceptedInfCount = 0U ;
			record.inspection	  = {} ;
		} else {
			binding_.retainedBytes_ += retained ;
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

/** @see SignedIndexScanSession 宣言側の契約を正本とする。 */
IndexPreparationSummary SignedIndexScanSession::preparationSummary(
	const OperationId operationId) const
{
	auto summary		= preparationSummary_ ;	// 非機密の確定snapshotだけを複写します。
	summary.operationId = operationId ;
	return summary ;
}

/** @see SignedIndexScanSession 宣言側の契約を正本とする。 */
void SignedIndexScanSession::invalidateAcquisition() noexcept
{
	adapter_.invalidate() ;
}

/** @see SignedIndexScanSession宣言側の契約を正本とします。 */
void SignedIndexScanSession::closeAcquisitionForInstall() noexcept
{
	adapter_.closeAcquisitionForInstall() ;
}
} // namespace drivercrate
