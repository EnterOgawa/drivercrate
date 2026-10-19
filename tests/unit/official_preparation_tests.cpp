//------------------------------------------------------------------------------
/**
 * @file official_preparation_tests.cpp
 * @brief 取得承認と一度限りのtaskの内部試験。
 * @version 01.01.00
 * @date 2026/09/05
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernetの取得前提確認と選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  EULA本文と取得再確認の境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  配布物単位の取得承認を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  EULA group tokenのsnapshot検証を追加。
 * </pre>
 *
 * @note 合成対象の状態だけを検証し、network・復元ポイント・導入を使用しません。
 */
//------------------------------------------------------------------------------

#include "official_preparation_tests.h"
#include "test_framework.h"

#include "core/official_preparation.h"
#include "core/provider_registry.h"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>

namespace drivercrate::test {
namespace {
constexpr NativeError FAILURE =
	std::bit_cast<NativeError>( std::uint32_t{0x80004005U}) ;	// 合成したE_FAIL結果。
constexpr NativeError CANCELLED =
	std::bit_cast<NativeError>( std::uint32_t{0x800704C7U}) ;	// 合成した取消しHRESULT。

//------------------------------------------------------------------------------
/**
 * @brief 実deviceやURLを持たず、容量境界と対象別判断を検証する。
 * @return 二Provider・三配布物の合成計画。
 */
//------------------------------------------------------------------------------
OfficialPreparationPlan makePlan()
{
	OfficialPreparationPlan plan ;	// 各試験で変更する所有計画。
	plan.scanSessionId = 10U ;
	plan.planId		   = 1U ;
	plan.limits		   = {100U, 200U, 300U, 2U, 3U} ;
	// 三配布物のうち二つは同一Providerに属し、一つは未解決EULAを持つ。
	for( std::uint32_t index = 0U; index < 3U; ++index) {
		OfficialPreparationTarget target ;	// 架空の配布物snapshot。
		target.identity = L"target:" + std::to_wstring( index) ;
		target.providerId =
			index == 2U ? SILICON_LABS_OFFICIAL_PROVIDER_ID : PROLIFIC_OFFICIAL_PROVIDER_ID ;
		target.resourceId	   = L"payload-fixture" ;
		target.releaseIdentity = L"release:" + std::to_wstring( index) ;
		target.parserRevision  = 1U ;
		target.maximumBytes	   = 100U ;
		target.deviceCount	   = index + 1U ;
		target.terms		   = index == 1U ? OfficialPreparationTerms::UNRESOLVED
											 : OfficialPreparationTerms::ACCEPTANCE_REQUIRED ;
		// 同意必須の架空対象には実契約でない本文とrevisionを対応付ける。
		if( target.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED) {
			target.eulaRevision = L"terms:1" ;
			target.eulaText =
				L"Synthetic test terms. No real license." ;	// 実契約を転載しない合成本文。
		}

		plan.targets.push_back( std::move( target)) ;
	}

	return plan ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実UIの同意を代行せず、testだけで明示判断を構成する。
 *
 * @param[in] plan 承認snapshotの元にする合成計画。
 * @param[in] operationId 各試験の単調操作ID。
 * @return 未解決条件以外の対象を選択した合成承認。
 */
//------------------------------------------------------------------------------
OfficialPreparationApproval makeApproval( const OfficialPreparationPlan &plan,
										 const OperationId				operationId)
{
	OfficialPreparationApproval approval ;	// 状態管理へ渡す合成判断。
	approval.operationId   = operationId ;
	approval.scanSessionId = plan.scanSessionId ;
	approval.planId		   = plan.planId ;
	approval.limits		   = plan.limits ;
	// 全表示対象の判断を作り、未解決EULAを未選択として保持する。
	for( const OfficialPreparationTarget &target : plan.targets) {
		const bool selected = target.terms != OfficialPreparationTerms::UNRESOLVED ;	// 合成選択。
		approval.decisions.push_back(
			{target, selected,
			 selected && target.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED, false}) ;
	}

	return approval ;
}

//------------------------------------------------------------------------------
/**
 * @brief Networkを使わず、最大256taskへ取得失敗を返して予約を維持する。
 *
 * @param[in,out] session 有限対象を承認済みの合成session。
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void finishAll( OfficialPreparationSession &session, TestContext &context)
{
	// 不具合時にもtestが無限loopにならないよう、計画上限回までで打ち切る。
	for( std::size_t count = 0U; count < 256U; ++count) {
		const auto task = session.claimNext() ;	// 今回だけ許可された合成task。
		// 取得可能taskが尽きた時点で予約消費の模擬を終了する。
		if( !task.has_value()) {
			break ;
		}

		DRIVERCRATE_EXPECT(
			context, session.complete( *task, {OfficialPreparationItemState::FAILURE, FAILURE, 0U})) ;
	}

	DRIVERCRATE_EXPECT( context, session.state() == OfficialPreparationState::COMPLETED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未選択取得0、一度限りのtask、確定件数、部分失敗を確認する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testPartialApproval( TestContext &context)
{
	OfficialPreparationSession	  session ;								// 一scanの取得計画管理。
	const OfficialPreparationPlan plan	   = makePlan() ;				// 三配布物の合成表示。
	auto						  approval = makeApproval( plan, 20U) ;	// 二対象だけを取得する判断。
	std::reverse( approval.decisions.begin(), approval.decisions.end()) ;
	DRIVERCRATE_EXPECT( context, !session.claimNext().has_value()) ;
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
	DRIVERCRATE_EXPECT( context, !session.claimNext().has_value()) ;
	DRIVERCRATE_EXPECT( context, session.approve( approval) == OfficialPreparationError::NONE) ;
	DRIVERCRATE_EXPECT( context, session.progress().total == 2U) ;
	DRIVERCRATE_EXPECT( context, session.progress().completed == 0U) ;
	const auto first = session.claimNext() ;	// 計画順の先頭対象。
	DRIVERCRATE_EXPECT( context, first.has_value()) ;
	// 前提不成立時にもoptionalを参照しない。
	if( !first) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, first->target == plan.targets[0]) ;
	DRIVERCRATE_EXPECT( context, !session.claimNext()) ;
	DRIVERCRATE_EXPECT( context, !session.invalidate()) ;
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::BUSY) ;
	DRIVERCRATE_EXPECT( context, session.approve( approval) == OfficialPreparationError::NO_PLAN) ;
	DRIVERCRATE_EXPECT(
		context,
		session.complete( *first, {OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0, 60U})) ;
	DRIVERCRATE_EXPECT(
		context,
		!session.complete( *first, {OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0, 60U})) ;
	DRIVERCRATE_EXPECT( context, session.progress().completed == 1U) ;
	const auto second = session.claimNext() ;	// 未選択を飛ばした別Providerの対象。
	DRIVERCRATE_EXPECT( context, second.has_value()) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( !second) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, second->target == plan.targets[2]) ;
	DRIVERCRATE_EXPECT(
		context, session.complete( *second, {OfficialPreparationItemState::FAILURE, FAILURE, 0U})) ;
	DRIVERCRATE_EXPECT( context, session.state() == OfficialPreparationState::COMPLETED) ;
	DRIVERCRATE_EXPECT( context, session.progress().completed == 2U) ;
	DRIVERCRATE_EXPECT( context, session.items()[1].result.state ==
									OfficialPreparationItemState::NOT_SELECTED) ;
	DRIVERCRATE_EXPECT( context, session.items()[0].result.byteCount == 60U) ;
	DRIVERCRATE_EXPECT( context, session.items()[2].result.error == FAILURE) ;
	DRIVERCRATE_EXPECT( context, !session.claimNext()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全拒否を取得成功と混同せず、taskと進捗を0件にする。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testAllDeclined( TestContext &context)
{
	OfficialPreparationSession	  session ;				// 全拒否時の管理状態。
	const OfficialPreparationPlan plan = makePlan() ;	// 未解決条件も含む計画。
	auto approval = makeApproval( plan, 20U) ;			// この試験で全拒否へ変更する判断。
	// 表示対象を省略せず、三件すべて取得しないと明示する。
	for( OfficialPreparationDecision &decision : approval.decisions) {
		decision.acquire	  = false ;
		decision.eulaAccepted = false ;
	}

	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
	DRIVERCRATE_EXPECT( context, session.approve( approval) == OfficialPreparationError::NONE) ;
	DRIVERCRATE_EXPECT( context, session.state() == OfficialPreparationState::COMPLETED) ;
	DRIVERCRATE_EXPECT( context, session.progress().total == 0U) ;
	DRIVERCRATE_EXPECT( context, session.progress().completed == 0U) ;
	DRIVERCRATE_EXPECT( context, session.items().size() == 3U) ;
	DRIVERCRATE_EXPECT( context, !session.claimNext()) ;
	DRIVERCRATE_EXPECT( context, session.approve( approval) == OfficialPreparationError::NO_PLAN) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 承認snapshotの各差替え、省略、未知対象、重複を開始前に拒否する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testApprovalBinding( TestContext &context)
{
	// 一つの差替えごとに新しい管理objectを使い、拒否後も正規承認できることを確認する。
	for( std::uint32_t mutation = 0U; mutation < 19U; ++mutation) {
		OfficialPreparationSession	  session ;								// 差替えの影響を隔離する管理状態。
		const OfficialPreparationPlan plan	  = makePlan() ;				// 正規snapshot。
		const auto					  valid	  = makeApproval( plan, 20U) ;	// 比較用の正しい判断。
		auto						  invalid = valid ;						// 一fieldだけ壊す判断。
		// 承認snapshotのfieldを一つずつ変形し、差替えと省略の拒否を切り分ける。
		switch( mutation) {
			// 別scan sessionへの承認流用を検出する入力を作る。
			case 0U:
				++invalid.scanSessionId ;
				break ;

			// 別計画への承認流用を検出する入力を作る。
			case 1U:
				++invalid.planId ;
				break ;

			// 承認後の単一file容量上限の変更を検出する。
			case 2U:
				++invalid.limits.maximumFileBytes ;
				break ;

			// 承認後のProvider別容量上限の変更を検出する。
			case 3U:
				++invalid.limits.maximumProviderBytes ;
				break ;

			// 承認後のsession全体容量上限の変更を検出する。
			case 4U:
				++invalid.limits.maximumSessionBytes ;
				break ;

			// 承認後のProvider別file件数上限の変更を検出する。
			case 5U:
				++invalid.limits.maximumProviderFiles ;
				break ;

			// 承認後のsession全体file件数上限の変更を検出する。
			case 6U:
				++invalid.limits.maximumSessionFiles ;
				break ;

			// 未表示の対象identityへ承認を差し替えた場合を検証する。
			case 7U:
				invalid.decisions[0].target.identity = L"unknown" ;
				break ;

			// 対象のProviderだけを差し替えた場合の拒否を検証する。
			case 8U:
				invalid.decisions[0].target.providerId = SILICON_LABS_OFFICIAL_PROVIDER_ID ;
				break ;

			// 承認済みの配布resourceとの結合が失われた場合を検証する。
			case 9U:
				invalid.decisions[0].target.resourceId = L"other-resource" ;
				break ;

			// 承認対象のrelease identityの変更を検出する。
			case 10U:
				invalid.decisions[0].target.releaseIdentity = L"other-release" ;
				break ;

			// 承認後のparser revisionの変更を検出する。
			case 11U:
				++invalid.decisions[0].target.parserRevision ;
				break ;

			// 承認対象に固有の容量上限の変更を検出する。
			case 12U:
				++invalid.decisions[0].target.maximumBytes ;
				break ;

			// 承認した影響device件数の変更を検出する。
			case 13U:
				++invalid.decisions[0].target.deviceCount ;
				break ;

			// 別EULA revisionへの同意流用を拒否する入力を作る。
			case 14U:
				invalid.decisions[0].target.eulaRevision = L"terms:2" ;
				break ;

			// 承認後に利用条件の区分を変更した場合を検証する。
			case 15U:
				invalid.decisions[0].target.terms = OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
				break ;

			// 必要な対象判断が省略された承認を検証する。
			case 16U:
				invalid.decisions.pop_back() ;
				break ;

			// 承認内の対象判断の重複を検出する。
			case 17U:
				invalid.decisions[1] = invalid.decisions[0] ;
				break ;

			// 余分な対象判断を追加した承認を検出する。
			case 18U:
				invalid.decisions.push_back( invalid.decisions[0]) ;
				break ;

			// 定義した改変case以外ではfixtureを追加変更しない。
			default:
				break ;
		}

		DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
		DRIVERCRATE_EXPECT( context, session.approve( invalid) != OfficialPreparationError::NONE) ;
		DRIVERCRATE_EXPECT( context, !session.claimNext()) ;
		DRIVERCRATE_EXPECT( context, session.progress().total == 0U) ;
		DRIVERCRATE_EXPECT( context, session.approve( valid) == OfficialPreparationError::NONE) ;
		session.cancel() ;
		DRIVERCRATE_EXPECT( context, session.progress().completed == 2U) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 不明EULA、必要同意不足、未選択への同意付与とtaskの変更を拒否する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testTermsAndNetworkBinding( TestContext &context)
{
	// 条件を満たさない判断をそれぞれ独立に作り、取得前拒否を検証する。
	for( std::uint32_t mutation = 0U; mutation < 4U; ++mutation) {
		OfficialPreparationSession	  session ;								// 条件検証を行う管理状態。
		const OfficialPreparationPlan plan	   = makePlan() ;				// 未解決条件を含む計画。
		auto						  approval = makeApproval( plan, 20U) ;	// 変更対象の判断。
		// 必要同意の欠落と未選択対象への同意を個別に注入する。
		switch( mutation) {
			// 必須EULA同意を欠く取得指示の拒否を検証する。
			case 0U:
				approval.decisions[0].eulaAccepted = false ;
				break ;

			// 利用条件が解決していない対象の取得選択を検証する。
			case 1U:
				approval.decisions[1].acquire = true ;
				break ;

			// 未選択対象へのEULA同意の付与を拒否する入力を作る。
			case 2U:
				approval.decisions[1].eulaAccepted = true ;
				break ;

			// 未選択対象への制限付き通信承認の付与を検証する。
			case 3U:
				approval.decisions[1].restrictedNetworkApproved = true ;
				break ;

			// 定義した同意改変以外ではfixtureを変更しない。
			default:
				break ;
		}

		DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
		DRIVERCRATE_EXPECT( context,
						   session.approve( approval) == OfficialPreparationError::INVALID_APPROVAL) ;
		DRIVERCRATE_EXPECT( context, !session.claimNext()) ;
	}

	OfficialPreparationSession session ;			// 確認済み同意不要とnetwork同意の照合。
	auto					   plan = makePlan() ;	// この試験で条件を明確化する合成計画。
	plan.targets[0].terms			= OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
	plan.targets[0].eulaRevision.clear() ;
	plan.targets[0].eulaText.clear() ;
	auto approval = makeApproval( plan, 20U) ;	// 対象0だけnetwork制限を承認する。
	approval.decisions[0].restrictedNetworkApproved = true ;
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
	DRIVERCRATE_EXPECT( context, session.approve( approval) == OfficialPreparationError::NONE) ;
	const auto task = session.claimNext() ;	// 対象別network同意を含むtoken。
	DRIVERCRATE_EXPECT( context, task.has_value()) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( !task) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, task->restrictedNetworkApproved) ;
	auto modified					   = *task ;	// 同意状態を書き換えた偽token。
	modified.restrictedNetworkApproved = false ;
	DRIVERCRATE_EXPECT(
		context, !session.complete( modified, {OfficialPreparationItemState::FAILURE, FAILURE, 0U})) ;
	DRIVERCRATE_EXPECT(
		context, session.complete(
					 *task, {OfficialPreparationItemState::AWAITING_NETWORK_CONSENT, FAILURE, 0U})) ;
	const auto next = session.claimNext() ;	// 別Providerのnetwork未承認対象。
	DRIVERCRATE_EXPECT( context, next.has_value()) ;
	// 次taskを取得できた場合にだけnetwork同意と失敗完了を検証する。
	if( next) {
		DRIVERCRATE_EXPECT( context, !next->restrictedNetworkApproved) ;
		DRIVERCRATE_EXPECT(
			context, session.complete( *next, {OfficialPreparationItemState::FAILURE, FAILURE, 0U})) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 不完全計画、未知Provider、重複配布物、定義外条件を拒否する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testInvalidPlans( TestContext &context)
{
	// 有限な不正入力表を一件ずつ検証し、旧未使用計画の失効も確認する。
	for( std::uint32_t mutation = 0U; mutation < 20U; ++mutation) {
		OfficialPreparationSession session ;				// 入力検証用の管理状態。
		const auto				   original = makePlan() ;	// 失効させる有効計画。
		auto					   plan		= original ;	// 一点だけ不正にする新計画。
		plan.planId							= 2U ;
		// 計画の識別子・対象・上限を個別に不正化し、公開前の拒否を確認する。
		switch( mutation) {
			// scan session identityが欠けた計画を検証する。
			case 0U:
				plan.scanSessionId = 0U ;
				break ;

			// 計画identityが欠けた入力を検証する。
			case 1U:
				plan.planId = 0U ;
				break ;

			// 取得対象が存在しない計画の拒否を検証する。
			case 2U:
				plan.targets.clear() ;
				break ;

			// 対象件数の上限を超える計画を検証する。
			case 3U:
				plan.targets.resize( 257U) ;
				break ;

			// 単一fileの許可容量がない計画を検証する。
			case 4U:
				plan.limits.maximumFileBytes = 0U ;
				break ;

			// 単一fileを収容できないProvider容量上限を検証する。
			case 5U:
				plan.limits.maximumProviderBytes = 99U ;
				break ;

			// Provider容量と整合しないsession容量上限を検証する。
			case 6U:
				plan.limits.maximumSessionBytes = 199U ;
				break ;

			// Providerが一fileも扱えない件数上限を検証する。
			case 7U:
				plan.limits.maximumProviderFiles = 0U ;
				break ;

			// sessionのfile件数上限が許容範囲を超える場合を検証する。
			case 8U:
				plan.limits.maximumSessionFiles = 257U ;
				break ;

			// 許可されない文字を含む対象identityの拒否を検証する。
			case 9U:
				plan.targets[0].identity = L"bad/identity" ;
				break ;

			// 未知Providerを持つ計画の拒否を検証する。
			case 10U:
				plan.targets[0].providerId = L"unknown-provider" ;
				break ;

			// 公式取得対象をDriver Storeへ誤routingする入力を検証する。
			case 11U:
				plan.targets[0].providerId = DRIVER_STORE_PROVIDER_ID ;
				break ;

			// 配布resourceのidentityが欠けた対象を検証する。
			case 12U:
				plan.targets[0].resourceId.clear() ;
				break ;

			// release identityが欠けた対象から取得taskを作らないことを検証する。
			case 13U:
				plan.targets[0].releaseIdentity.clear() ;
				break ;

			// parser revisionが確定していない対象の拒否を検証する。
			case 14U:
				plan.targets[0].parserRevision = 0U ;
				break ;

			// 計画の単一file容量を超える対象の拒否を検証する。
			case 15U:
				plan.targets[0].maximumBytes = 101U ;
				break ;

			// 影響device件数の上限を超える対象を検証する。
			case 16U:
				plan.targets[0].deviceCount = 4097U ;
				break ;

			// 必要なEULA revisionが欠けた対象を検証する。
			case 17U:
				plan.targets[0].eulaRevision.clear() ;
				break ;

			// 同一releaseを重複して計画に含めた場合を検証する。
			case 18U:
				plan.targets[1].releaseIdentity = plan.targets[0].releaseIdentity ;
				break ;

			// 未定義の利用条件を既知の同意区分として扱わないことを検証する。
			case 19U:
				plan.targets[0].terms = static_cast<OfficialPreparationTerms>( 255) ;
				break ;

			// 定義した不正計画case以外ではfixtureを変更しない。
			default:
				break ;
		}

		DRIVERCRATE_EXPECT( context, session.initialize( original) == OfficialPreparationError::NONE) ;
		DRIVERCRATE_EXPECT( context,
						   session.initialize( plan) == OfficialPreparationError::INVALID_PLAN) ;
		DRIVERCRATE_EXPECT( context, session.state() == OfficialPreparationState::EMPTY) ;
		DRIVERCRATE_EXPECT( context, !session.claimNext()) ;
		DRIVERCRATE_EXPECT( context, session.approve( makeApproval( original, 20U)) ==
										OfficialPreparationError::NO_PLAN) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 取消しが未選択・既存結果を保持し、開始済み転送の結果を待つことを確認する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testCancellationAndLateCompletion( TestContext &context)
{
	OfficialPreparationSession session ;			// 取消し競合の管理状態。
	const auto				   plan = makePlan() ;	// 二対象だけを取得する計画。
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
	DRIVERCRATE_EXPECT( context,
					   session.approve( makeApproval( plan, 20U)) == OfficialPreparationError::NONE) ;
	const auto task = session.claimNext() ;	// 取消しより先に開始した対象。
	DRIVERCRATE_EXPECT( context, task.has_value()) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( !task) {
		return ;
	}

	session.cancel() ;
	session.cancel() ;
	DRIVERCRATE_EXPECT( context, session.state() == OfficialPreparationState::CANCELLING) ;
	DRIVERCRATE_EXPECT( context, !session.claimNext()) ;
	DRIVERCRATE_EXPECT( context, !session.invalidate()) ;
	DRIVERCRATE_EXPECT( context, session.progress().completed == 1U) ;
	DRIVERCRATE_EXPECT( context, session.items()[1].result.state ==
									OfficialPreparationItemState::NOT_SELECTED) ;
	DRIVERCRATE_EXPECT( context, session.items()[2].result.error == CANCELLED) ;
	DRIVERCRATE_EXPECT(
		context,
		session.complete( *task, {OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0, 40U})) ;
	DRIVERCRATE_EXPECT( context, session.state() == OfficialPreparationState::COMPLETED) ;
	DRIVERCRATE_EXPECT( context, session.progress().completed == 2U) ;
	session.cancel() ;
	DRIVERCRATE_EXPECT( context, session.items()[0].result.byteCount == 40U) ;
	DRIVERCRATE_EXPECT( context, !session.complete( *task, {OfficialPreparationItemState::CANCELLED,
														  CANCELLED, 0U})) ;
	DRIVERCRATE_EXPECT( context, session.invalidate()) ;
	DRIVERCRATE_EXPECT(
		context,
		!session.complete( *task, {OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0, 40U})) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 別task・再送・非終端通知・上限超過を拒否し、正しい完了だけを反映する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testResultBinding( TestContext &context)
{
	// 各差替えを隔離し、拒否後も現在taskが保持されていることを確認する。
	for( std::uint32_t mutation = 0U; mutation < 11U; ++mutation) {
		OfficialPreparationSession session ;			// 結果照合用の管理状態。
		const auto				   plan = makePlan() ;	// 結果tokenの元となる計画。
		DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
		DRIVERCRATE_EXPECT( context, session.approve( makeApproval( plan, 20U)) ==
										OfficialPreparationError::NONE) ;
		const auto task = session.claimNext() ;	// 一度だけ受け取る正しいtoken。
		DRIVERCRATE_EXPECT( context, task.has_value()) ;
		// 前提が崩れても未初期化tokenを使わない。
		if( !task) {
			continue ;
		}

		auto							  invalid = *task ;	// 書き換える完了token。
		OfficialPreparationTransferResult result{
			OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0, 40U} ;	// 正常結果の元値。
		// task identityと完了結果を個別に変形し、正しい終端通知だけの受理を検証する。
		switch( mutation) {
			// 別operationの完了通知を現在のtaskへ反映しないことを検証する。
			case 0U:
				++invalid.operationId ;
				break ;

			// 別scan sessionの完了通知の拒否を検証する。
			case 1U:
				++invalid.scanSessionId ;
				break ;

			// 別計画の完了通知の拒否を検証する。
			case 2U:
				++invalid.planId ;
				break ;

			// 実行中でない対象への完了通知を検証する。
			case 3U:
				invalid.target = plan.targets[2] ;
				break ;

			// 予約容量を超えた取得結果を成功として受理しないことを検証する。
			case 4U:
				result.byteCount = 101U ;
				break ;

			// 空の取得結果を有効な完了として受理しないことを検証する。
			case 5U:
				result.byteCount = 0U ;
				break ;

			// 成功状態に失敗診断が混在する結果を検証する。
			case 6U:
				result.error = FAILURE ;
				break ;

			// 未実行状態を終端通知として受理しないことを検証する。
			case 7U:
				result = {OfficialPreparationItemState::PENDING, 0, 0U} ;
				break ;

			// 失敗状態なのに診断値がない矛盾を検証する。
			case 8U:
				result = {OfficialPreparationItemState::FAILURE, 0, 0U} ;
				break ;

			// 失敗状態へ取得済みbyteを混在させた結果を検証する。
			case 9U:
				result = {OfficialPreparationItemState::FAILURE, FAILURE, 1U} ;
				break ;

			// 未定義の項目状態を成功として受理しないことを検証する。
			case 10U:
				result.state = static_cast<OfficialPreparationItemState>( 255) ;
				break ;

			// 定義した不正完了case以外ではfixtureを変更しない。
			default:
				break ;
		}

		DRIVERCRATE_EXPECT( context, !session.complete( invalid, result)) ;
		DRIVERCRATE_EXPECT( context, session.progress().completed == 0U) ;
		DRIVERCRATE_EXPECT( context, !session.claimNext()) ;
		DRIVERCRATE_EXPECT( context, session.complete( *task, {OfficialPreparationItemState::REJECTED,
															 FAILURE, 0U})) ;
		session.cancel() ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief byteとfileのProvider別／全体予算を開始前に確認し、予約を原子的に行う。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testBudgetBoundaries( TestContext &context)
{
	// 三つの対象を選択し、一箇所の予算を超過する四条件を検証する。
	for( std::uint32_t boundary = 0U; boundary < 4U; ++boundary) {
		OfficialPreparationSession session ;			// 予算境界用の管理状態。
		auto					   plan = makePlan() ;	// 未解決条件を確認済みへ変える計画。
		plan.targets[1].terms			= OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
		// Provider別とsession全体のbyte・file上限を別々に試験する。
		switch( boundary) {
			// Provider別の容量予算不足を、取得開始前に検出する。
			case 0U:
				plan.limits.maximumProviderBytes = 199U ;
				break ;

			// session全体の容量予算不足を、取得開始前に検出する。
			case 1U:
				plan.limits.maximumSessionBytes = 299U ;
				break ;

			// Provider別のfile件数不足を、予約時に検出する。
			case 2U:
				plan.limits.maximumProviderFiles = 1U ;
				break ;

			// session全体のfile件数不足を、予約時に検出する。
			case 3U:
				plan.limits.maximumSessionFiles = 2U ;
				break ;

			// 定義した予算境界case以外ではfixtureを変更しない。
			default:
				break ;
		}

		auto approval = makeApproval( plan, 20U) ;	// 最初は三件を選択する判断。
		DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
		DRIVERCRATE_EXPECT( context,
						   session.approve( approval) == OfficialPreparationError::BUDGET_EXCEEDED) ;
		DRIVERCRATE_EXPECT( context, !session.claimNext()) ;
		approval.decisions[1].acquire = false ;
		DRIVERCRATE_EXPECT( context, session.approve( approval) == OfficialPreparationError::NONE) ;
		finishAll( session, context) ;
	}

	OfficialPreparationSession exact ;				// 全予算へちょうど達する管理状態。
	auto					   plan = makePlan() ;	// 三件すべての条件を明示した計画。
	plan.targets[1].terms			= OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
	DRIVERCRATE_EXPECT( context, exact.initialize( plan) == OfficialPreparationError::NONE) ;
	DRIVERCRATE_EXPECT( context,
					   exact.approve( makeApproval( plan, 20U)) == OfficialPreparationError::NONE) ;
	finishAll( exact, context) ;
}

//------------------------------------------------------------------------------
/**
 * @brief UINT64境界と、同一scanの再計画による予算リセットを拒否する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testOverflowAndPersistentBudget( TestContext &context)
{
	OfficialPreparationSession huge ;				// 最大uint64値付近での加算前検証。
	auto					   plan	 = makePlan() ;	// 二配布物へ巨大上限を指定する合成計画。
	plan.limits.maximumFileBytes	 = std::numeric_limits<std::uint64_t>::max() ;
	plan.limits.maximumProviderBytes = plan.limits.maximumFileBytes ;
	plan.limits.maximumSessionBytes	 = plan.limits.maximumFileBytes ;
	plan.targets[0].maximumBytes	 = plan.limits.maximumFileBytes ;
	DRIVERCRATE_EXPECT( context, huge.initialize( plan) == OfficialPreparationError::NONE) ;
	auto approval = makeApproval( plan, 20U) ;	// 合計が表現上限を超える判断。
	DRIVERCRATE_EXPECT( context,
					   huge.approve( approval) == OfficialPreparationError::BUDGET_EXCEEDED) ;
	approval.decisions[2].acquire	   = false ;
	approval.decisions[2].eulaAccepted = false ;
	DRIVERCRATE_EXPECT( context, huge.approve( approval) == OfficialPreparationError::NONE) ;
	huge.cancel() ;

	OfficialPreparationSession session ;	// 再計画でも予算を残す管理状態。
	plan = makePlan() ;
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
	DRIVERCRATE_EXPECT( context,
					   session.approve( makeApproval( plan, 20U)) == OfficialPreparationError::NONE) ;
	session.cancel() ;
	DRIVERCRATE_EXPECT( context, session.invalidate()) ;
	plan.planId = 2U ;
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
	DRIVERCRATE_EXPECT( context, session.approve( makeApproval( plan, 21U)) ==
									OfficialPreparationError::BUDGET_EXCEEDED) ;
	plan.planId = 3U ;
	++plan.limits.maximumSessionBytes ;
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::INVALID_PLAN) ;
	plan.planId = 4U ;
	++plan.scanSessionId ;
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
	DRIVERCRATE_EXPECT( context,
					   session.approve( makeApproval( plan, 21U)) == OfficialPreparationError::NONE) ;
	finishAll( session, context) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 失効後も古い計画・操作IDを拒否し、同意前取消しで取得を開始しない。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testIdHighWaterAndPreapprovalCancel( TestContext &context)
{
	OfficialPreparationSession session ;			// ID高水位を保持する管理object。
	auto					   plan = makePlan() ;	// 最初に表示する計画。
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
	session.cancel() ;
	DRIVERCRATE_EXPECT( context, session.state() == OfficialPreparationState::EMPTY) ;
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::STALE_PLAN) ;
	++plan.planId ;
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
	DRIVERCRATE_EXPECT( context, session.approve( makeApproval( plan, 0U)) ==
									OfficialPreparationError::STALE_OPERATION) ;
	DRIVERCRATE_EXPECT( context,
					   session.approve( makeApproval( plan, 20U)) == OfficialPreparationError::NONE) ;
	finishAll( session, context) ;
	++plan.planId ;
	--plan.scanSessionId ;
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::STALE_PLAN) ;
	plan.scanSessionId = 11U ;
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
	DRIVERCRATE_EXPECT( context, session.approve( makeApproval( plan, 20U)) ==
									OfficialPreparationError::STALE_OPERATION) ;
	DRIVERCRATE_EXPECT( context, session.approve( makeApproval( plan, 19U)) ==
									OfficialPreparationError::STALE_OPERATION) ;
	DRIVERCRATE_EXPECT( context,
					   session.approve( makeApproval( plan, 21U)) == OfficialPreparationError::NONE) ;
	session.cancel() ;
	DRIVERCRATE_EXPECT( context, session.state() == OfficialPreparationState::COMPLETED) ;
	DRIVERCRATE_EXPECT( context, session.progress().completed == session.progress().total) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 失敗で予約を返さず、同じscanのProvider別容量・件数も計画をまたいで守る。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testProviderBudgetAcrossPlans( TestContext &context)
{
	// Provider容量とfile件数を別々に制限し、scan全体の残枠だけでは取得できないと確認する。
	for( std::uint32_t boundary = 0U; boundary < 2U; ++boundary) {
		OfficialPreparationSession session ;			// 一Providerの累計を保持する管理状態。
		auto					   plan = makePlan() ;	// 一件だけ残す再試行用の合成計画。
		plan.targets.resize( 1U) ;
		// 容量境界のscenarioではProviderのbyte予算を一件分へ制限する。
		if( boundary == 0U) {
			plan.limits.maximumProviderBytes = 100U ;
		} else {
			plan.limits.maximumProviderFiles = 1U ;
		}

		DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
		DRIVERCRATE_EXPECT( context, session.approve( makeApproval( plan, 20U)) ==
										OfficialPreparationError::NONE) ;
		finishAll( session, context) ;
		++plan.planId ;
		DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
		DRIVERCRATE_EXPECT( context, session.approve( makeApproval( plan, 21U)) ==
										OfficialPreparationError::BUDGET_EXCEEDED) ;
		++plan.planId ;
		plan.targets[0].providerId = SILICON_LABS_OFFICIAL_PROVIDER_ID ;
		DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
		DRIVERCRATE_EXPECT( context, session.approve( makeApproval( plan, 21U)) ==
										OfficialPreparationError::NONE) ;
		finishAll( session, context) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 実契約を転載せず、UTF-16・制御文字・本文上限だけを合成dataで検証する。
 *
 * @param[in,out] context 本文表示条件のassertion集計先。
 */
//------------------------------------------------------------------------------
void testEulaTextValidation( TestContext &context)
{
	DRIVERCRATE_EXPECT( context,
					   validPreparationEulaText( L"Synthetic terms.\r\nSecond line.\tEnd.")) ;
	DRIVERCRATE_EXPECT( context, !validPreparationEulaText( L"")) ;
	DRIVERCRATE_EXPECT( context, !validPreparationEulaText( L" \t\r\n")) ;
	DRIVERCRATE_EXPECT( context, !validPreparationEulaText( L"\x2000\x200A\x202F\x205F\x3000")) ;
	DRIVERCRATE_EXPECT( context, !validPreparationEulaText( std::wstring( 3, L'\0'))) ;
	DRIVERCRATE_EXPECT( context, !validPreparationEulaText( L"Terms\x202E"
														  L"hidden")) ;
	DRIVERCRATE_EXPECT( context,
					   !validPreparationEulaText( std::wstring( 1, static_cast<wchar_t>( 0xD800)))) ;
	DRIVERCRATE_EXPECT( context,
					   !validPreparationEulaText( std::wstring( 1, static_cast<wchar_t>( 0xDC00)))) ;
	const std::wstring paired{static_cast<wchar_t>( 0xD83D),
							  // 正当なpair。
							  static_cast<wchar_t>( 0xDE00)} ;
	DRIVERCRATE_EXPECT( context, validPreparationEulaText( paired)) ;
	DRIVERCRATE_EXPECT(
		context, validPreparationEulaText( std::wstring( MAXIMUM_PREPARATION_EULA_CHARACTERS, L'A'))) ;
	DRIVERCRATE_EXPECT( context, !validPreparationEulaText(
									std::wstring( MAXIMUM_PREPARATION_EULA_CHARACTERS + 1U, L'A'))) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じrevisionの本文差替えも拒否し、EULAなし取得へ分類し直して通過させない。
 *
 * @param[in,out] context 本文変更と同意のassertion集計先。
 */
//------------------------------------------------------------------------------
void testEulaBodyBoundApproval( TestContext &context)
{
	OfficialPreparationSession	  session ;				// 固定本文を持つ対象別承認。
	const OfficialPreparationPlan plan = makePlan() ;	// 合成本文を含む既存fixture。
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
	OfficialPreparationApproval approval = makeApproval( plan, 30) ;	// 表示本文に対応した同意。
	approval.decisions[0].target.eulaText += L" Changed." ;
	DRIVERCRATE_EXPECT( context,
					   session.approve( approval) == OfficialPreparationError::INVALID_APPROVAL) ;
	approval						   = makeApproval( plan, 31) ;
	approval.decisions[0].eulaAccepted = false ;
	DRIVERCRATE_EXPECT( context,
					   session.approve( approval) == OfficialPreparationError::INVALID_APPROVAL) ;
	approval.decisions[0].eulaAccepted = true ;
	DRIVERCRATE_EXPECT( context, session.approve( approval) == OfficialPreparationError::NONE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同一EULAの短命group tokenを同意必須対象だけへ結合する。
 * @param[in,out] context Group tokenの計画・承認binding assertion集計先。
 */
//------------------------------------------------------------------------------
void testSharedEulaTokenBinding( TestContext &context)
{
	OfficialPreparationPlan plan	= makePlan() ;	// Group tokenを設定する合成計画。
	plan.targets[0].sharedEulaToken = 7U ;			// 同意必須対象の現在scan限定token。
	OfficialPreparationSession session ;			// Token込みsnapshotを固定する管理状態。
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
	OfficialPreparationApproval approval = makeApproval( plan, 30U) ;	// Token込みの正規判断。
	approval.decisions[0].target.sharedEulaToken++ ;
	DRIVERCRATE_EXPECT( context,
					   session.approve( approval) == OfficialPreparationError::INVALID_APPROVAL) ;
	approval = makeApproval( plan, 31U) ;
	DRIVERCRATE_EXPECT( context, session.approve( approval) == OfficialPreparationError::NONE) ;

	OfficialPreparationPlan invalid	   = makePlan() ;	// 同意不要分類へtokenを混入する不正計画。
	invalid.targets[1].terms		   = OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
	invalid.targets[1].sharedEulaToken = 1U ;
	OfficialPreparationSession rejected ;	// 不正計画の拒否を隔離する管理状態。
	DRIVERCRATE_EXPECT( context,
					   rejected.initialize( invalid) == OfficialPreparationError::INVALID_PLAN) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 本文欠落・矛盾分類・最大量超過を計画の公開前に拒否する。
 *
 * @param[in,out] context 個別／全体本文上限のassertion集計先。
 */
//------------------------------------------------------------------------------
void testEulaPlanLimits( TestContext &context)
{
	// 本文の欠落、同意不要との矛盾、個別上限超過を別objectで試験する。
	for( int scenario = 0; scenario < 3; ++scenario) {
		OfficialPreparationSession session ;			// 一つの不正条件だけを試験する状態。
		OfficialPreparationPlan	   plan = makePlan() ;	// 当該caseで変更する計画。
		// 同意本文の欠落を注入し、不完全な計画の公開拒否を確認する。
		if( scenario == 0) {
			plan.targets[0].eulaText.clear() ;
		}
		// 同意不要区分と残存本文を矛盾させ、計画の整合性拒否を確認する。
		else if( scenario == 1) {
			plan.targets[0].terms = OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
			plan.targets[0].eulaRevision.clear() ;
		} else {
			plan.targets[0].eulaText.assign( MAXIMUM_PREPARATION_EULA_CHARACTERS + 1U, L'A') ;
		}

		DRIVERCRATE_EXPECT( context,
						   session.initialize( plan) == OfficialPreparationError::INVALID_PLAN) ;
	}

	OfficialPreparationPlan plan = makePlan() ;	// 全体保持上限の境界を作る計画。
	plan.targets.clear() ;
	plan.limits = {100, 1000, 1000, 10, 10} ;
	// 一対象の上限を守りつつ、四対象で全体上限にちょうど一致させる。
	for( std::size_t index = 0; index < 4; ++index) {
		OfficialPreparationTarget target = makePlan().targets[0] ;	// 独立した配布物にするcopy。
		target.identity					 = L"body-target:" + std::to_wstring( index) ;
		target.releaseIdentity			 = L"body-release:" + std::to_wstring( index) ;
		target.eulaText.assign( MAXIMUM_PREPARATION_EULA_CHARACTERS, L'A') ;
		plan.targets.push_back( std::move( target)) ;
	}

	OfficialPreparationSession accepted ;	// 上限ちょうどの計画を受け取る状態。
	DRIVERCRATE_EXPECT( context, accepted.initialize( plan) == OfficialPreparationError::NONE) ;
	OfficialPreparationTarget extra = makePlan().targets[0] ;	// 一文字でも超えると拒否する対象。
	extra.identity					= L"body-extra" ;
	extra.releaseIdentity			= L"body-release-extra" ;
	extra.eulaText					= L"A" ;
	plan.targets.push_back( std::move( extra)) ;
	OfficialPreparationSession rejected ;	// 別objectで全体上限超過を試験する。
	DRIVERCRATE_EXPECT( context,
					   rejected.initialize( plan) == OfficialPreparationError::INVALID_PLAN) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 許諾同意だけでは取得前提確認を代用できず、不整合な確認値も拒否する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testPrerequisiteConfirmation( TestContext &context)
{
	OfficialPreparationPlan plan = makePlan() ;	// 前提確認が必要な一対象の計画。
	plan.targets.resize( 1U) ;
	plan.targets[0].requiresPrerequisiteConfirmation = true ;
	OfficialPreparationSession session ;	// 本番と同じ承認境界。実通信を行わない。
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
	OfficialPreparationApproval approval = makeApproval( plan, 1U) ;	// 全文同意だけの不十分な判断。
	DRIVERCRATE_EXPECT( context,
					   session.approve( approval) == OfficialPreparationError::INVALID_APPROVAL) ;
	DRIVERCRATE_EXPECT( context, !session.claimNext()) ;
	approval.decisions[0].prerequisitesConfirmed = true ;
	approval.decisions[0].eulaAccepted			 = false ;
	DRIVERCRATE_EXPECT( context,
					   session.approve( approval) == OfficialPreparationError::INVALID_APPROVAL) ;
	approval.decisions[0].eulaAccepted							  = true ;
	approval.decisions[0].target.requiresPrerequisiteConfirmation = false ;
	DRIVERCRATE_EXPECT( context,
					   session.approve( approval) == OfficialPreparationError::INVALID_APPROVAL) ;
	approval.decisions[0].target = plan.targets[0] ;
	DRIVERCRATE_EXPECT( context, session.approve( approval) == OfficialPreparationError::NONE) ;
	const auto task = session.claimNext() ;	// 二種類の判断を照合した後だけ発行するtoken。
	DRIVERCRATE_EXPECT( context, task.has_value()) ;
	// 取得できたtaskに前提条件の確認要求が保持されることを検証する。
	if( task) {
		DRIVERCRATE_EXPECT( context, task->target.requiresPrerequisiteConfirmation) ;
	}

	// 同じ取得を再claimしない。
	DRIVERCRATE_EXPECT( context, !session.claimNext()) ;

	// 未選択なのに確認済み、または確認不要なのに確認済みの二つの矛盾を拒否する。
	for( unsigned scenario = 0U; scenario < 2U; ++scenario) {
		OfficialPreparationSession rejected ;	// 各矛盾を独立した状態で確認する。
		plan.targets[0].requiresPrerequisiteConfirmation = scenario == 0U ;
		DRIVERCRATE_EXPECT( context, rejected.initialize( plan) == OfficialPreparationError::NONE) ;
		approval									 = makeApproval( plan, 1U) ;
		approval.decisions[0].acquire				 = scenario != 0U ;
		approval.decisions[0].eulaAccepted			 = scenario != 0U ;
		approval.decisions[0].prerequisitesConfirmed = true ;
		DRIVERCRATE_EXPECT( context, rejected.approve( approval) ==
										OfficialPreparationError::INVALID_APPROVAL) ;
		DRIVERCRATE_EXPECT( context, !rejected.claimNext()) ;
	}

	// 本文への同意を持たない分類へ取得前提確認だけを追加する不正計画を拒否する。
	for( unsigned scenario = 0U; scenario < 2U; ++scenario) {
		OfficialPreparationSession rejected ;	// 初期化段階での拒否境界。
		plan.targets[0].requiresPrerequisiteConfirmation = true ;
		plan.targets[0].terms = scenario == 0U ? OfficialPreparationTerms::UNRESOLVED
											   : OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
		plan.targets[0].eulaText.clear() ;
		plan.targets[0].eulaRevision.clear() ;
		DRIVERCRATE_EXPECT( context,
						   rejected.initialize( plan) == OfficialPreparationError::INVALID_PLAN) ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_preparation_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOfficialPreparationTests( TestContext &context)
{
	testPrerequisiteConfirmation( context) ;
	testEulaTextValidation( context) ;
	testEulaBodyBoundApproval( context) ;
	testSharedEulaTokenBinding( context) ;
	testEulaPlanLimits( context) ;
	testPartialApproval( context) ;
	testAllDeclined( context) ;
	testApprovalBinding( context) ;
	testTermsAndNetworkBinding( context) ;
	testInvalidPlans( context) ;
	testCancellationAndLateCompletion( context) ;
	testResultBinding( context) ;
	testBudgetBoundaries( context) ;
	testOverflowAndPersistentBudget( context) ;
	testIdHighWaterAndPreapprovalCancel( context) ;
	testProviderBudgetAcrossPlans( context) ;
}

} // namespace drivercrate::test
