//------------------------------------------------------------------------------
/**
 * @file official_preparation_operation_tests.cpp
 * @brief 承認済み取得実行の内部試験。
 * @version 01.00.00
 * @date 2026/09/06
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得計画とworker実行を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 同期fakeだけを使用し、network・復元ポイント・実導入を呼びません。
 */
//------------------------------------------------------------------------------

#include "official_preparation_operation_tests.h"
#include "core/official_preparation_operation.h"
#include "core/provider_registry.h"
#include "test_framework.h"

#include <bit>
#include <cstdint>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {
constexpr NativeError FAILURE =
	std::bit_cast<NativeError>( std::uint32_t{0x80004005U}) ;	// 合成したE_FAIL。

//------------------------------------------------------------------------------
/**
 * @brief 実inventoryを使わず、一Provider内の選択差を確認する。
 * @return 三配布物の有限な合成計画。
 */
//------------------------------------------------------------------------------
OfficialPreparationPlan operationPlan()
{
	OfficialPreparationPlan plan{12U, 1U, {100U, 300U, 300U, 3U, 3U}, {}} ;	// 試験用計画。
	// 全三件の配布物を、相互に異なるopaque IDで固定する。
	for( std::uint32_t index = 0U; index < 3U; ++index) {
		OfficialPreparationTarget target ;	// 合成配布物のsnapshot。
		target.identity		   = L"target:" + std::to_wstring( index) ;
		target.providerId	   = PROLIFIC_OFFICIAL_PROVIDER_ID ;
		target.resourceId	   = L"payload" ;
		target.releaseIdentity = L"release:" + std::to_wstring( index) ;
		target.parserRevision  = 1U ;
		target.maximumBytes	   = 100U ;
		target.deviceCount	   = 1U ;
		target.terms		   = OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
		plan.targets.push_back( std::move( target)) ;
	}

	return plan ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択していない対象が取得境界へ渡らないことを確認できる形にする。
 *
 * @param[in] plan 元となる固定計画。
 * @return 中央一件を取得しない合成判断。
 */
//------------------------------------------------------------------------------
OfficialPreparationApproval operationApproval( const OfficialPreparationPlan &plan)
{
	// 合成した全対象の判断snapshot。取得可否を一件ずつ設定する。
	OfficialPreparationApproval approval{2U, plan.scanSessionId, plan.planId, plan.limits, {}} ;
	// 順序どおり全対象の可否を明示し、省略を拒否と見なす挙動に依存しない。
	for( const OfficialPreparationTarget &target : plan.targets) {
		approval.decisions.push_back( {target, target.identity != L"target:1", false, false}) ;
	}

	return approval ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択対象だけを呼び、部分失敗と確定進捗を保持する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testExecutorPartialSelection( TestContext &context)
{
	OfficialPreparationSession session ;								// 取得許可の状態。
	const auto				   plan		= operationPlan() ;				// 三配布物の合成計画。
	const auto				   approval = operationApproval( plan) ;	// 二対象だけを選択する判断。
	std::vector<std::wstring>  calls ;									// 実際にfakeへ渡った非機密対象ID。
	std::vector<OfficialPreparationProgress> progress ;					// 通知順の確定件数。
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
	// 対象別結果と制御エラーを照合する実行結果。
	const auto result = executeOfficialPreparation(
		session, approval,
		[&calls]( const OfficialPreparationTask &task, const PreparationCancellation &) {
			calls.push_back( task.target.identity) ;
			return task.target.identity == L"target:0"
					   ? OfficialPreparationTransferResult{OfficialPreparationItemState::
															   ACQUIRED_FOR_INSPECTION,
														   0, 50U}
					   : OfficialPreparationTransferResult{OfficialPreparationItemState::FAILURE,
														   FAILURE, 0U} ;
		},
		{}, [&progress]( const OfficialPreparationProgress &value) { progress.push_back( value) ; }) ;
	DRIVERCRATE_EXPECT( context, result.approvalError == OfficialPreparationError::NONE) ;
	DRIVERCRATE_EXPECT( context, result.controlError == 0) ;
	DRIVERCRATE_EXPECT( context, calls.size() == 2U) ;
	DRIVERCRATE_EXPECT( context, result.items.size() == 3U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( calls.size() == 2U && result.items.size() == 3U) {
		DRIVERCRATE_EXPECT( context, calls[0] == L"target:0" && calls[1] == L"target:2") ;
		DRIVERCRATE_EXPECT( context, result.items[1].result.state ==
										OfficialPreparationItemState::NOT_SELECTED) ;
		DRIVERCRATE_EXPECT( context, result.items[0].result.byteCount == 50U) ;
		DRIVERCRATE_EXPECT( context, result.items[2].result.error == FAILURE) ;
	}

	DRIVERCRATE_EXPECT( context, !progress.empty()) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( !progress.empty()) {
		DRIVERCRATE_EXPECT( context, progress.front().completed == 0U) ;
		DRIVERCRATE_EXPECT( context, progress.back().completed == 2U) ;
		DRIVERCRATE_EXPECT( context, progress.back().total == 2U) ;
	}

	DRIVERCRATE_EXPECT( context, result.operationId == approval.operationId) ;
	DRIVERCRATE_EXPECT( context, result.scanSessionId == approval.scanSessionId) ;
	DRIVERCRATE_EXPECT( context, result.planId == approval.planId) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 差替え・未接続callback・使用済み承認から取得を開始しない。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testExecutorRejectionAndReplay( TestContext &context)
{
	OfficialPreparationSession		 session ;								// 拒否後の再試行と使用済み状態。
	const auto						 plan	  = operationPlan() ;			// 検証元の計画。
	auto							 approval = operationApproval( plan) ;	// 差替え試験用の判断。
	std::uint32_t					 calls{} ;								// Fake取得を呼んだ回数。
	const PreparationAcquireFunction acquire = [&calls]( const OfficialPreparationTask &,
														const PreparationCancellation &) {
		++calls ;
		return OfficialPreparationTransferResult{
			OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0, 20U} ;
	} ; // Networkへは接続しないfake。
	// 進捗受信を必要としない試験で使用する、captureなしの空callback。
	const PreparationProgressCallback progress = []( const OfficialPreparationProgress &) {} ;
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
	++approval.decisions[0].target.parserRevision ;
	DRIVERCRATE_EXPECT(
		context,
		executeOfficialPreparation( session, approval, acquire, {}, progress).approvalError ==
			OfficialPreparationError::INVALID_APPROVAL) ;
	DRIVERCRATE_EXPECT( context, calls == 0U) ;
	approval = operationApproval( plan) ;
	DRIVERCRATE_EXPECT(
		context, executeOfficialPreparation( session, approval, {}, {}, progress).approvalError ==
					 OfficialPreparationError::INVALID_APPROVAL) ;
	DRIVERCRATE_EXPECT(
		context, executeOfficialPreparation( session, approval, acquire, {}, {}).approvalError ==
					 OfficialPreparationError::INVALID_APPROVAL) ;
	DRIVERCRATE_EXPECT(
		context,
		executeOfficialPreparation( session, approval, acquire, {}, progress).approvalError ==
			OfficialPreparationError::NONE) ;
	DRIVERCRATE_EXPECT( context, calls == 2U) ;
	DRIVERCRATE_EXPECT(
		context,
		executeOfficialPreparation( session, approval, acquire, {}, progress).approvalError ==
			OfficialPreparationError::NO_PLAN) ;
	DRIVERCRATE_EXPECT( context, calls == 2U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 開始前・取得中の協調取消しで未開始対象を呼ばず、取得済み事実は保持する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testExecutorCancellation( TestContext &context)
{
	// 取消しの開始時点だけを変えた二条件を独立に実行する。
	for( const bool beforeStart : {true, false}) {
		OfficialPreparationSession session ;						// 今回の操作状態。
		const auto				   plan		 = operationPlan() ;	// 三配布物の固定計画。
		bool					   cancelled = beforeStart ;		// 利用者からの合成取消し信号。
		std::uint32_t			   calls{} ;						// 開始したfake取得数。
		DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
		// 対象別結果と制御エラーを照合する実行結果。
		const auto result = executeOfficialPreparation(
			session, operationApproval( plan),
			[&calls, &cancelled]( const OfficialPreparationTask &, const PreparationCancellation &) {
				++calls ;
				cancelled = true ;
				return OfficialPreparationTransferResult{
					OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0, 20U} ;
			},
			[&cancelled]() { return cancelled ; }, []( const OfficialPreparationProgress &) {}) ;
		DRIVERCRATE_EXPECT( context, calls == (beforeStart ? 0U : 1U)) ;
		DRIVERCRATE_EXPECT( context, result.items.size() == 3U) ;
		DRIVERCRATE_EXPECT( context, session.state() == OfficialPreparationState::COMPLETED) ;
		// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
		if( result.items.size() == 3U) {
			DRIVERCRATE_EXPECT(
				context, result.items[0].result.state ==
							 (beforeStart ? OfficialPreparationItemState::CANCELLED
										  : OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION)) ;
			DRIVERCRATE_EXPECT( context, result.items[2].result.state ==
											OfficialPreparationItemState::CANCELLED) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 取得例外は部分失敗、不正な成功通知は拒否として確定する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testExecutorExceptionAndBadResult( TestContext &context)
{
	// 取得例外だけなら継続し、整合しない結果では以後の取得を止める。
	for( const bool malformed : {false, true}) {
		OfficialPreparationSession session ;				// 失敗後の継続可否の状態。
		const auto				   plan = operationPlan() ;	// 三対象中の二対象を取得する計画。
		std::uint32_t			   calls{} ;				// 例外後の呼出数も数える。
		DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
		// 対象別結果と制御エラーを照合する実行結果。
		const auto result = executeOfficialPreparation(
			session, operationApproval( plan),
			[&calls, malformed]( const OfficialPreparationTask &, const PreparationCancellation &)
				-> OfficialPreparationTransferResult {
				++calls ;
				// 許可容量を超える成功通知を注入して不正な完了結果の拒否を検証する。
				if( malformed) {
					return {OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0, 101U} ;
				}

				// 初回取得だけに例外を注入し、部分失敗として保持されることを確認する。
				if( calls == 1U) {
					throw std::runtime_error( "synthetic acquisition failure") ;
				}

				return {OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0, 20U} ;
			},
			{}, []( const OfficialPreparationProgress &) {}) ;
		DRIVERCRATE_EXPECT( context, calls == (malformed ? 1U : 2U)) ;
		DRIVERCRATE_EXPECT( context, result.items.size() == 3U) ;
		// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
		if( result.items.size() == 3U) {
			DRIVERCRATE_EXPECT( context, result.items[0].result.state ==
											(malformed ? OfficialPreparationItemState::REJECTED
													   : OfficialPreparationItemState::FAILURE)) ;
			DRIVERCRATE_EXPECT(
				context, result.items[2].result.state ==
							 (malformed ? OfficialPreparationItemState::CANCELLED
										: OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION)) ;
		}

		DRIVERCRATE_EXPECT( context, (result.controlError != 0) == malformed) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 取消し照会・進捗通知の例外では取得を止め、診断値を残す。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testExecutorControlCallbackFailure( TestContext &context)
{
	// 初回取消し照会失敗と初回通知失敗をそれぞれ検証する。
	for( const bool cancellationFailure : {false, true}) {
		OfficialPreparationSession session ;				// 制御系異常時の状態。
		const auto				   plan = operationPlan() ;	// 取消しで閉じる固定計画。
		std::uint32_t			   calls{} ;				// 制御系異常後の取得開始検出用。
		DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
		// 対象別結果と制御エラーを照合する実行結果。
		const auto result = executeOfficialPreparation(
			session, operationApproval( plan),
			[&calls]( const OfficialPreparationTask &, const PreparationCancellation &) {
				++calls ;
				return OfficialPreparationTransferResult{OfficialPreparationItemState::FAILURE,
														 FAILURE, 0U} ;
			},
			[cancellationFailure]() {
				// 取消し照会の例外を注入して取得停止と診断保持を検証する。
				if( cancellationFailure) {
					throw std::runtime_error( "synthetic cancellation failure") ;
				}

				return false ;
			},
			[cancellationFailure]( const OfficialPreparationProgress &) {
				// 進捗通知の例外を注入して取得停止と診断保持を検証する。
				if( !cancellationFailure) {
					throw std::runtime_error( "synthetic progress failure") ;
				}
			}) ;
		DRIVERCRATE_EXPECT( context, calls == 0U) ;
		DRIVERCRATE_EXPECT( context, result.controlError != 0) ;
		DRIVERCRATE_EXPECT( context, session.state() == OfficialPreparationState::COMPLETED) ;
		DRIVERCRATE_EXPECT( context, result.items.size() == 3U) ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_preparation_operation_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOfficialPreparationOperationTests( TestContext &context)
{
	testExecutorPartialSelection( context) ;
	testExecutorRejectionAndReplay( context) ;
	testExecutorCancellation( context) ;
	testExecutorExceptionAndBadResult( context) ;
	testExecutorControlCallbackFailure( context) ;
}

} // namespace drivercrate::test
