//------------------------------------------------------------------------------
/**
 * @file local_collector_segment_preparation.cpp
 * @brief 同親readerから導出した元hashと全66像を非保存draftへ結合します。
 * @version 01.01.00
 * @date 2026/10/02
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  初回区間の実根拠から全draftを導出。
 * Ver.01.01.00 Shunji Ogawa  2026/10/02  実所有freezeを保持してfresh draftを導出。
 * </pre>
 *
 * @note 元保存byteは変更しません。準備contextから実保存を実行しません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#include "local_collector_segment_preparation.h"
#include "local_collector_projected_json.h"
#include "official_file_verifier.h"
#include <cstddef>
#include <cstdint>
#include <new>
#include <string>
#include <utility>

namespace drivercrate {
/** @see local_collector_segment_preparation.h */
const CollectorSegmentSwitchDraft &CollectorSegmentQuiescentSwitch::draft() const noexcept
{
	return prepared_->draft() ;
}
/** @see local_collector_segment_preparation.h */
const CollectorSegmentRootInventory &CollectorSegmentQuiescentSwitch::root() const noexcept
{
	return prepared_->root() ;
}
/** @see local_collector_segment_preparation.h */
DWORD LocalCollectorSegmentPreparation::prepareQuiescent(
	LocalCollectorCollectionStore &collection, LocalCollectorSegmentLease &segment,
	const std::span<const CollectorCampaignSource> sources, const std::wstring_view newSegment,
	const std::uint64_t										acceptedUtcMillis,
	std::shared_ptr<const CollectorSegmentQuiescentSwitch> &prepared,
	const std::function<DWORD()>						   &beforeFinalRecheck) noexcept
{
	auto previous = std::move( prepared) ;	// Alias参照と旧freezeを呼出し終了まで保持します。
	(void)previous ;
	try {
		// 異なる能力と不正keyは実閉鎖を取得する前に拒否します。
		if( !segment.history()) {
			return ERROR_INVALID_PARAMETER ;
		}

		// 不正keyを閉鎖やreaderへ持ち込みません。
		if( !collector_projected_json::isHash( newSegment)) {
			return ERROR_INVALID_DATA ;
		}

		const std::wstring nextKey( newSegment) ;							// Caller keyを診断前に所有します。
		std::shared_ptr<const CollectorStoreHttpFreeze> freeze ;			// 同じ実historyだけの閉鎖です。
		const auto code = segment.history()->freezeHttpActivity( freeze) ;	// 実所有と借用の第一判定。
		// 未回収所有・監督や旧freezeをtrue観測で補完しません。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		std::shared_ptr<const CollectorSegmentPreparedSwitch> fresh ;	// 旧contextを入力にしません。
		const auto											  inspected =
			prepare( collection, segment, sources, nextKey, acceptedUtcMillis, true, fresh,
					beforeFinalRecheck) ;	// 私有閉鎖が成立した後のfresh非保存検査です。
		// 元reader／hashの失敗で閉鎖を返し、出力を空に保ちます。
		if( inspected != ERROR_SUCCESS) {
			return inspected ;
		}

		prepared = std::make_shared<const CollectorSegmentQuiescentSwitch>(
			CollectorSegmentQuiescentSwitch::ConstructionKey{}, std::move( freeze),
			std::move( fresh)) ;
		return ERROR_SUCCESS ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}
/** @see local_collector_segment_preparation.h */
DWORD LocalCollectorSegmentPreparation::prepare(
	LocalCollectorCollectionStore &collection, LocalCollectorSegmentLease &segment,
	const std::span<const CollectorCampaignSource> sources, const std::wstring_view newSegment,
	const std::uint64_t acceptedUtcMillis, const bool workersJoinedObservation,
	std::shared_ptr<const CollectorSegmentPreparedSwitch> &prepared,
	const std::function<DWORD()>						  &beforeFinalRecheck) noexcept
{
	auto previous = std::move( prepared) ;	// 出力内keyの借用も同期呼出し中だけ生存させます。
	(void)previous ;
	try {
		// 不正keyと停止未観測を実readerや診断へ渡さず、元領域を保持します。
		if( !workersJoinedObservation || !collector_projected_json::isHash( newSegment)) {
			return ERROR_INVALID_DATA ;
		}

		const std::wstring nextKey( newSegment) ;					// 診断中にcaller参照を書き換えられても固定します。
		std::shared_ptr<const CollectorSegmentRootInventory> root ;	// 古いcontextを再利用しません。
		const auto											 inspected =
			LocalCollectorSegmentInventory::inspect( collection, segment, sources, acceptedUtcMillis,
													root, beforeFinalRecheck) ;	// 第一数値です。
		// 元readerの不成立を新hashやcaller観測で補完しません。
		if( inspected != ERROR_SUCCESS) {
			return inspected ;
		}

		const auto &evidence = root->evidence() ;				// 同じ全raw最終検査の所有値です。
		const auto &history	 = evidence.history->evidence() ;	// 実完了ROOTとCACHE由来です。
		const auto &shared	 = evidence.shared->evidence() ;	// 唯一containerと初回／更新headです。
		CollectorSegmentSwitchRequest request ;					// 成功hashは全て実readerから導出します。
		request.oldSegment = shared.segment ;
		request.newSegment = nextKey ;
		request.oldHead	   = shared.headSha256 ;
		request.oldRoot	   = history.rootSha256 ;
		request.seal	   = evidence.sealSha256 ;
		request.accepted   = acceptedUtcMillis ;
		// 初回readerが検査した唯一の現区間はordinal0、過去seal参照なしです。
		request.oldOrdinal							 = 0U ;
		request.observation.workersJoined			 = workersJoinedObservation ;
		request.observation.lastGenerationComplete	 = true ;
		request.observation.summaryPointerConsistent = true ;
		// 未受領・未精算0／active commitなしは実readerとcarryの閉鎖条件へ結合します。
		for( const auto &shard : evidence.shards) {
			request.inventory.push_back( shard.sha256) ;
		}

		CollectorSegmentSwitchDraft draft ;	// 全成立後だけimmutable出力へ移譲します。
		const auto					drafted = prepareCollectorSegmentSwitchDraft(
			 shared.snapshot, shared.snapshot, request, draft) ;	// 元台帳を変更しません。
		// Draftの不正と元CNG errorを第一結果のまま返します。
		if( drafted != ERROR_SUCCESS) {
			return drafted ;
		}

		// 66元本文由来のdigestを同じ実共有根拠に完全結合します。
		if( draft.intent.ledger != shared.ledger) {
			return ERROR_INVALID_DATA ;
		}

		const auto checked = checkCollectorSegmentSwitchDraft(
			shared.snapshot, shared.snapshot, request, draft) ;	// 全body／hashを独立再導出します。
		// 全出力一致前に保存可能と誤認するcontextを公開しません。
		if( checked != ERROR_SUCCESS) {
			return checked ;
		}

		prepared = std::make_shared<const CollectorSegmentPreparedSwitch>(
			CollectorSegmentPreparedSwitch::ConstructionKey{}, std::move( root), std::move( draft)) ;
		return ERROR_SUCCESS ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}
} // namespace drivercrate
