//------------------------------------------------------------------------------
/**
 * @file signed_index_scan.h
 * @brief 通常worker scanに結合する署名索引の秘密sessionを定義します。
 * @version 01.04.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  通常scanの有限索引読取りと非機密summaryを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  私有batch凍結と同active taskの取得・内容結果を追加。
 * Ver.01.01.01 Shunji Ogawa  2026/10/12  取得callback例外時の能力失効と確定所有保持を明示。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.03.00 Shunji Ogawa  2026/10/14  元未判定の中から私有証拠付き部分positive件数を分離。
 * Ver.01.04.00 Shunji Ogawa  2026/10/16  通常索引refreshと非通信worker/UI境界を接続。
 * </pre>
 *
 * @note 全秘密所有はworker限定です。索引一致は導入権限を作りません。
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "core/update_provider.h"
#include "platform/signed_index_record_lookup.h"
#include "platform/signed_index_refresh.h"
#include "platform/signed_index_acquisition_adapter.h"
#include "platform/signed_index_candidate_binding.h"
#include "core/official_preparation_operation.h"
#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace drivercrate {
namespace provider_worker_index_detail {
struct Services ;
}

/** @brief 同じ通常scanのDriver Store秘密stateを借りる独立seamです。 */
class IIndexScanInventory {
public:
	/** @brief 所有Providerの派生資源を解放します。 */
	virtual ~IIndexScanInventory() = default ;
	/** @brief 同scanの全presentとweak resolverを発行します。
	 * @param[in] operationId 正のworker operation。
	 * @param[out] context 同scanの正のcontext。拒否時空です。
	 * @param[out] present 全present opaque。拒否時空です。
	 * @return 同threadの秘密snapshotだけを借りるcallback。拒否時nullptrです。
	 */
	[[nodiscard]] virtual std::unique_ptr<IndexPublicIdResolver> indexScanInventory(
		OperationId operationId, IndexLookupContext &context,
		std::vector<std::wstring> &present) = 0 ;
} ;

/** @brief 索引の未実行・不足・失敗と全読取り完了を区別します。 */
enum class IndexScanStatus {
	/// 索引段階を実行していません。
	NOT_RUN,
	/// 元の通常scanが失敗しました。
	SCAN_FAILED,
	/// Binary固定trustが未配備です。
	TRUST_UNAVAILABLE,
	/// 有効な保存世代がありません。
	EMPTY_STORE,
	/// 保護・認証・schemaまたはI/Oが拒否されました。
	LOAD_REJECTED,
	/// 現在のUTCを確認できません。
	TIME_UNAVAILABLE,
	/// 署名発行前です。
	NOT_YET_VALID,
	/// 署名期限以上です。
	EXPIRED,
	/// 同scan inventory seamがありません。
	INVENTORY_UNAVAILABLE,
	/// Operation・session・inventoryの結合が成立しません。
	STALE_CONTEXT,
	/// 同operationの取消しで秘密sessionを失効しました。
	CANCELLED,
	/// 全operationの有限予算で残件を未判定へ残しました。
	BUDGET_EXHAUSTED,
	/// 全recordを読んだが未判定の関係があります。
	PARTIAL,
	/// 全recordを読取り、各関係の照合が完了しました。適合ではありません。
	COMPLETED,
	/// 例外等で秘密sessionを破棄しました。
	INTERNAL_FAILURE
} ;

/** @brief 通常eventへ渡せる文字列・byte・identityを持たない値です。 */
struct IndexScanSummary {
	/// 独立した索引段階の区分。
	IndexScanStatus						   status{IndexScanStatus::NOT_RUN} ;
	/// Storeの元拒否区分。Load前はnulloptです。
	std::optional<IndexStoreStatus>		   storeStatus ;
	/// Lookupの元拒否区分。Lookup前はnulloptです。
	std::optional<IndexRecordLookupStatus> lookupStatus ;
	/// 元HRESULTまたはWin32診断。未発生時0です。
	NativeError							   error{} ;
	/// 保存snapshotのrecord総数。未取得時0です。
	std::size_t							   totalRecords{} ;
	/// 関係を保持できたrecord数。
	std::size_t							   processedRecords{} ;
	/// 未実行record数。適合なしへ換算しません。
	std::size_t							   remainingRecords{} ;
	/// 保持した関係tuple数。
	std::size_t							   relationCount{} ;
	/// 全batchで保持したopaque関係数。最大32,768です。
	std::size_t							   relatedDeviceCount{} ;
	/// 一意な公開ID関係数。driver適合数ではありません。
	std::size_t							   matchedRelations{} ;
	/// 完了した非一意関係数。
	std::size_t							   nonUniqueRelations{} ;
	/// 未判定関係数。残record数とは別です。
	std::size_t							   undeterminedRelations{} ;
	/// 未判定総数に含む私有証拠付き部分positive関係数。完全MATCHEDとは別です。
	std::size_t							   verifiedPartialRelations{} ;
	/// 全operationの実resolver呼出し数。
	std::size_t							   resolverCalls{} ;
	/// 通信を試みた場合だけ元失敗・明示cache・commit事実を保持します。秘密能力を含みません。
	std::optional<IndexRefreshSummary>	   refresh ;
} ;

/** @brief 原ID・URL・hash・pathを持たない一取得対象の確定内容結果です。 */
struct IndexPreparationItemSummary {
	/// 同計画内だけで意味を持つopaque取得対象ID。
	std::wstring				 targetIdentity ;
	/// 実byte取得の確定状態。内容合格とは独立です。
	OfficialAcquisitionState	 acquisition{OfficialAcquisitionState::NOT_STARTED} ;
	/// 実byte取得の元HRESULT。未実行は0です。
	NativeError					 acquisitionError{} ;
	/// 共通内容検査の到達段階。Windows適合を示しません。
	IndexedDriverInspectionState content{IndexedDriverInspectionState::NOT_STARTED} ;
	/// 入力結合または全体内容検査の元HRESULT。
	NativeError					 contentError{} ;
	/// 個別INFの最初の拒否診断。全体成功でも保持します。
	NativeError					 firstInfRejection{} ;
	/// 実file hash/sizeを元hintへ結合した場合だけtrueです。
	bool						 inputBound{} ;
	/// 共通検査で確定した通常file数。
	std::size_t					 inventoryFileCount{} ;
	/// 共通検査で発見したINF数。候補数ではありません。
	std::size_t					 infCount{} ;
	/// 共通閉包の構造・INF解析を通過した数。署名合格ではありません。
	std::size_t					 parsedInfCount{} ;
	/// 構造解析後に通常Windows署名policyで拒否したINF数。
	std::size_t					 signatureRejectedInfCount{} ;
	/// 通常署名・内容policyを通過したINF数。Windows適合ではありません。
	std::size_t					 acceptedInfCount{} ;
} ;

/** @brief 同operation・scan・planへ結合する有限な索引取得結果です。 */
struct IndexPreparationSummary {
	/// 取得操作ID。scan時の計画summaryでは0です。
	OperationId								 operationId{} ;
	/// 元通常scanのsession。
	ScanSessionId							 scanSessionId{} ;
	/// 元取得計画のID。
	std::uint64_t							 planId{} ;
	/// 私有lookup／取得能力の開始拒否診断。未試行または成立は0です。
	NativeError								 authorityError{} ;
	/// 計画へ結合した索引対象数。最大256です。
	std::size_t								 plannedTargets{} ;
	/// 元UNKNOWN・未対応・非一意など取得対象を作れなかった関係数。
	std::size_t								 unavailableRelations{} ;
	/// 共通計画の保持枠を越えた関係数。
	std::size_t								 capacityRejectedRelations{} ;
	/// 最大256件。個別結果だけを表示しcandidate／install能力へ昇格しません。
	std::vector<IndexPreparationItemSummary> items ;
} ;

/** @brief 全record関係とconst原snapshotをworker内だけへ保持します。 */
class SignedIndexScanSession final {
public:
	/** @brief 秘密snapshot・callback・関係を全て解放します。 */
	void						   invalidate() noexcept ;
	/** @brief 通常workerの同scan完了後に全operation予算内で読取ります。
	 * @param[in,out] provider 実scanを終えた同worker Provider。
	 * @param[in] operationId 正のworker operation。
	 * @param[in] sessionId 実scan結果と一致する正のsession。
	 * @param[in] services 固定製品入口または内部fixture能力。
	 * @param[in] cancellation 同operation限定の協調取消し。
	 * @param[in] progress 確定record数だけの同期通知。空では通知しません。
	 * @return 非機密件数と独立status。元scanの成否を変更しません。
	 * @note 例外は秘密所有を破棄して診断へ変換します。
	 */
	[[nodiscard]] IndexScanSummary scan(
		IUpdateProvider &provider, OperationId operationId, ScanSessionId sessionId,
		const provider_worker_index_detail::Services		&services,
		const ProviderScanCancellation						&cancellation,
		const std::function<void( const IndexScanSummary &)> &progress = {}) noexcept ;
	/** @brief 同scanの全私有batchから既存計画へ取得対象だけを結合します。
	 * @param[in,out] plan Providerの元計画または同じ有限上限の空計画。
	 * @param[in] services Worker開始前に固定した依存。任意公開鍵を受けません。
	 * @param[out] summary 非機密の件数と未接続診断。原UNKNOWNは元snapshotへ保持します。
	 * @return 計画の結合成立0。取得能力不足はsummaryへ独立保持して元Provider計画を維持します。
	 */
	[[nodiscard]] NativeError augmentPreparationPlan(
		OfficialPreparationPlan &plan, const provider_worker_index_detail::Services &services,
		IndexPreparationSummary &summary) ;
	/** @brief 同active taskだけを共通grant・取得seal・通常内容検査へ接続します。
	 * @param[in,out] preparation 実approve／claimNextしたworker session。
	 * @param[in] task 同計画の未変更active task。元scan操作とは別です。
	 * @param[in] services Worker固定のHTTP・時計・回線依存。
	 * @param[in] cancellation 同取得操作の協調停止。
	 * @return 取得の確定結果。内容失敗は独立summaryへ残します。
	 * @throws std::bad_alloc 内部allocationに失敗した場合。
	 * @throws ... 内部serviceが送出した元例外。
	 * @note Workerの取得callbackは例外を再throwする前にinvalidateAcquisitionを呼びます。
	 */
	[[nodiscard]] OfficialPreparationTransferResult acquireForInspection(
		OfficialPreparationSession &preparation, const OfficialPreparationTask &task,
		const provider_worker_index_detail::Services &services,
		const PreparationCancellation				 &cancellation) ;
	/** @brief 元計画と今回の操作へ非機密結果だけを複写します。
	 * @param[in] operationId 実取得operation。0では計画summaryです。
	 * @return 同scan／planと有限個別結果。秘密所有を含みません。
	 */
	[[nodiscard]] IndexPreparationSummary preparationSummary( OperationId operationId) const ;
	/** @brief Adapterの取得能力とissuer leaseを失効し、確定結果と内容所有を保持します。
	 * @note 新しいgrantと未使用grantの使用を拒否し、snapshot、lookup、取得ledger、
	 *       workspace、summary、検査閉包は解放しません。同期callbackの借用を破壊しません。
	 */
	void								  invalidateAcquisition() noexcept ;
	/** @brief 新取得だけを閉鎖し、同期限内の消費済み元根拠を導入終端まで保持します。 */
	void								  closeAcquisitionForInstall() noexcept ;

private:
	friend class CompositeUpdateProvider ;
	friend class SignedIndexCandidateBindingSession ;
	friend struct signed_index_candidate_binding_detail::Access ;
	/// 原byteを複製せず共有するconst保存snapshot。
	std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot_ ;
	/// 同scan秘密inventoryをweak所有するcallback。
	std::unique_ptr<IndexPublicIdResolver>			  resolver_ ;
	/// 有限な全batch関係。通常eventへ移しません。
	std::vector<SignedIndexRecordLookup>			  batches_ ;
	/// 元scanの全context。取得operationへ変更しません。
	IndexLookupContext								  context_ ;
	/// 全batchを一度だけ凍結した元lookup。global relation位置を使用します。
	std::shared_ptr<const SignedIndexRecordLookup>	  acquisitionLookup_ ;
	/// 同scanだけの共通adapter。失効issuerをsnapshot寿命とは独立に保持します。
	SignedIndexAcquisitionAdapter					  adapter_ ;
	/// 同scanの実成功取得byteを累積する共通ledger。
	std::unique_ptr<OfficialAcquisitionSession>		  acquisition_ ;
	/// 同scanの取得fileを保護所有する領域。
	std::unique_ptr<OfficialDownloadWorkspace>		  workspace_ ;
	/// 同scanへ固定した準備予算。計画再初期化で増やしません。
	OfficialPreparationLimits						  limits_ ;
	/// UIへ渡せる有限な確定結果。秘密文字列は保持しません。
	IndexPreparationSummary							  preparationSummary_ ;
	/// 元task/grant/sealと内容・pair/token/routeを同workerで私有所有します。
	SignedIndexCandidateBindingSession				  binding_ ;
	/// Binding issuer。Compositeより長くsessionを保持し、detach時にnullptrへ戻します。
	DriverStoreProvider								 *bindingStore_{} ;
} ;
} // namespace drivercrate
