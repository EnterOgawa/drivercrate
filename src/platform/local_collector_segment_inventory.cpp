//------------------------------------------------------------------------------
/**
 * @file local_collector_segment_inventory.cpp
 * @brief 同親共有根拠と完了履歴の全値／CACHE由来を結合します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  二readerの同時借用と最終再照合を結合。
 * Ver.01.01.00 Shunji Ogawa  2026/10/03  保護実handleの初回切替回復と検査を追加。
 * </pre>
 *
 * @note 保存形式と各readerの容量を変更しません。実切替／取得許可ではありません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#include "local_collector_segment_inventory.h"
#include "local_collector_segment_recovery.h"
#include "local_collector_projected_json.h"
#include "local_collector_recovery.h"
#include "local_collector_shared_store.h"
#include "official_file_verifier.h"
#include <algorithm>
#include <new>
#include <string_view>

namespace drivercrate {
namespace {
/** @brief 不成立を第一数値で伝播します。
 * @param[in] ok 成立が必須の条件。
 * @param[in] code 拒否時の第一数値。
 * @throws DWORD 条件不成立時。
 */
void require( const bool ok, const DWORD code = ERROR_INVALID_DATA)
{
	// 元I/O／容量を内容拒否へ読み替えません。
	if( !ok) {
		throw code ;
	}
}
/** @brief 同じ実根拠の共有全値と現区間CACHEを比較します。
 * @param[in] history 同じ借用中の全完了候補。
 * @param[in] shared 同じ親／子借用中の共有候補。
 * @throws DWORD 元codecまたは値一致が不成立の場合。
 */
void compare( const CollectorCompletedRootEvidence &history,
			 const CollectorSharedRootEvidence	  &shared)
{
	require( history.rootUtcMillis == shared.snapshot.lastUtcMillis &&
			history.inspectedUtcMillis == shared.inspectedUtcMillis) ;
	std::string budget ;	// 共有値の全予約を元順序で比較する本文です。
	require( encodeCollectorBudgetSnapshot( shared.snapshot.budget, budget) &&
			budget == history.budgetBody) ;
	CollectorWaitSnapshot original ;	// 元control自身の最高時計を保持します。
	require( parseCollectorWaitSnapshot( history.controlBody, original)) ;
	CollectorWaitSnapshot reconstructed ;	// 推測で最高時計や待機を更新しません。
	reconstructed.lastUtc = original.lastUtc ;
	// 元group集合を省略せず結合します。
	for( const auto &[group, control] : shared.snapshot.groups) {
		require( reconstructed.controls.emplace( L"g-" + group, control).second) ;
	}

	// 元request集合を省略せず結合し、参照の有無も別に照合します。
	for( const auto &[request, state] : shared.snapshot.requests) {
		require( reconstructed.controls.emplace( L"r-" + request, state.control).second) ;
	}

	std::string control ;	// 全field／集合の完全一致対象です。
	require( encodeCollectorWaitSnapshot( reconstructed, control) && control == history.controlBody) ;
	std::size_t caches = 0U ;	// 実在する共有参照だけの分母です。
	// 余分な参照・旧区間参照を現区間の成功根拠として採用しません。
	for( const auto &[request, state] : shared.snapshot.requests) {
		(void)request ;
		// 参照なしのrequestを成功CACHEとして数えません。
		if( state.cache) {
			require( state.cache->segment == shared.segment) ;
			++caches ;
		}
	}

	require( caches == history.caches.size()) ;
	// 登録と元200閉包を検査した全参照を同じrequestへ完全結合します。
	for( const auto &cache : history.caches) {
		const auto request = shared.snapshot.requests.find( cache.request) ;	// 同じ完全identityです。
		require( request != shared.snapshot.requests.end() && request->second.cache &&
				request->second.cache->cacheSha256 == cache.cacheSha256 &&
				request->second.cache->binding == cache.binding) ;
	}
}
/** @brief 元byte全体の指紋を第一CNG errorを保持して求めます。
 * @param[in] body 同じ検査の有限canonical本文。
 * @return 元全byteのSHA-256。
 * @throws DWORD 元CNG error。
 */
std::wstring digest( const std::string_view body)
{
	std::wstring result ;	// 元全byteだけの指紋です。
	const auto	 code =
		// 第一結果です。
		static_cast<DWORD>( computeCollectorMetadataSha256( body, result)) ;
	require( code == ERROR_SUCCESS, code) ;
	return result ;
}
/** @brief 元二inventoryの全rawをscope付き区間shardへ結合します。
 * @param[in,out] evidence 全再検査済みの二根拠。初回だけ呼び出します。
 * @throws DWORD 全8192名または元byteの有限上限不成立。
 * @throws collector_projected_json::Failure 本文byte上限不成立。
 */
void segmentInventory( CollectorSegmentRootEvidence &evidence)
{
	const auto &history = evidence.history->evidence() ;	// 元history scopeです。
	const auto &shared	= evidence.shared->evidence() ;		// 元親／子scopeです。
	require( evidence.files.empty() && evidence.shards.empty() && evidence.fileBytes == 0U) ;
	require( shared.files.size() <= 256U && history.files.size() <= 8192U - shared.files.size(),
			ERROR_TOO_MANY_NAMES) ;
	// 共有readerの元親current／runs、子current／runsの順序を保持します。
	for( const auto &file : shared.files) {
		evidence.files.push_back(
			{file.parent ? L"parent" : L"segment", file.name, file.sha256, file.bytes}) ;
	}

	// 別scopeのhistory current／runsを元順序で追加します。
	for( const auto &file : history.files) {
		evidence.files.push_back( {L"history", file.name, file.sha256, file.bytes}) ;
	}

	// 元各readerの枠を合算しても整数とcanonical numberの範囲を超えません。
	for( const auto &file : evidence.files) {
		require( file.bytes <= 144U * 1024U * 1024U - evidence.fileBytes, ERROR_TOO_MANY_NAMES) ;
		evidence.fileBytes += file.bytes ;
	}

	require( !evidence.files.empty() && evidence.fileBytes == history.fileBytes + shared.fileBytes) ;
	// 最大512行ずつ、元scope／順序を保持して有限shardへ閉じます。
	for( std::size_t first = 0U; first < evidence.files.size(); first += 512U) {
		collector_projected_json::Writer writer( 256U * 1024U) ;	// 一shardだけの独立上限です。
		writer.append( "{\"schema\":\"collector-segment-root-inventory-v1\",\"collection\":") ;
		writer.wideText( shared.snapshot.collection) ;
		writer.append( ",\"segment\":") ;
		writer.wideText( shared.segment) ;
		writer.append( ",\"ordinal\":") ;
		writer.number( evidence.shards.size()) ;
		writer.append( ",\"fileCount\":") ;
		writer.number( evidence.files.size()) ;
		writer.append( ",\"files\":[") ;
		// 最後の残行も一回だけ載せ、空shardを作りません。
		for( std::size_t index = first; index < std::min( first + 512U, evidence.files.size());
			++index) {
			const auto &file = evidence.files[index] ;	// 同じ全再検査済みの一rawです。
			// Shard先頭以外だけseparatorを追加します。
			if( index != first) {
				writer.append( ",") ;
			}

			writer.append( "{\"scope\":") ;
			writer.wideText( file.scope) ;
			writer.append( ",\"name\":") ;
			writer.wideText( file.name) ;
			writer.append( ",\"bytes\":") ;
			writer.number( file.bytes) ;
			writer.append( ",\"sha256\":") ;
			writer.wideText( file.sha256) ;
			writer.append( "}") ;
		}

		writer.append( "]}") ;
		auto	   body = writer.take() ;	// 完成byteだけからhashを求めます。
		const auto hash = digest( body) ;	// 各shardの全byteです。
		evidence.shards.push_back( {std::move( body), hash}) ;
	}

	require( !evidence.shards.empty() && evidence.shards.size() <= 16U, ERROR_TOO_MANY_NAMES) ;
}
/** @brief 元二inventoryを区間整合性記録へ結合します。
 * @param[in] history 同じ呼出しで最終再検査済みの履歴根拠。
 * @param[in] shared 同じ呼出しで最終再検査済みの共有根拠。
 * @param[in] evidence 両根拠から導出済みの全scope付き区間inventory。
 * @return 16 KiB以内の固定順本文。配布署名ではありません。
 * @throws collector_projected_json::Failure 有限byte上限違反。
 */
std::string segmentSeal( const CollectorCompletedRootEvidence &history,
						const CollectorSharedRootEvidence	 &shared,
						const CollectorSegmentRootEvidence	 &evidence)
{
	collector_projected_json::Writer writer( 16U * 1024U) ;	// 新本文だけの独立上限です。
	writer.append( "{\"schema\":\"collector-segment-root-seal-v1\",\"collection\":") ;
	writer.wideText( shared.snapshot.collection) ;
	writer.append( ",\"segment\":") ;
	writer.wideText( shared.segment) ;
	writer.append( ",\"rootKey\":") ;
	writer.wideText( history.rootKey) ;
	writer.append( ",\"root\":") ;
	writer.wideText( history.rootSha256) ;
	writer.append( ",\"rootUtc\":") ;
	writer.number( history.rootUtcMillis) ;
	writer.append( ",\"inspectedUtc\":") ;
	writer.number( history.inspectedUtcMillis) ;
	writer.append( ",\"head\":") ;
	writer.wideText( shared.headSha256) ;
	writer.append( ",\"ledger\":") ;
	writer.wideText( shared.ledger) ;
	writer.append( ",\"historySeal\":") ;
	writer.wideText( history.sealSha256) ;
	writer.append( ",\"sharedSeal\":") ;
	writer.wideText( shared.sealSha256) ;
	writer.append( ",\"generations\":") ;
	writer.number( history.generations) ;
	writer.append( ",\"historyOperations\":") ;
	writer.number( history.operations) ;
	writer.append( ",\"sharedOperations\":") ;
	writer.number( shared.operations) ;
	writer.append( ",\"cacheCount\":") ;
	writer.number( history.caches.size()) ;
	writer.append( ",\"historyFiles\":") ;
	writer.number( history.files.size()) ;
	writer.append( ",\"sharedFiles\":") ;
	writer.number( shared.files.size()) ;
	writer.append( ",\"historyBytes\":") ;
	writer.number( history.fileBytes) ;
	writer.append( ",\"sharedBytes\":") ;
	writer.number( shared.fileBytes) ;
	writer.append( ",\"fileCount\":") ;
	writer.number( evidence.files.size()) ;
	writer.append( ",\"fileBytes\":") ;
	writer.number( evidence.fileBytes) ;
	writer.append( ",\"inventory\":[") ;
	// 全ordinalの区間shardを同じsealへ結合します。
	for( std::size_t ordinal = 0U; ordinal < evidence.shards.size(); ++ordinal) {
		// 先頭以外だけseparatorを追加します。
		if( ordinal != 0U) {
			writer.append( ",") ;
		}

		writer.wideText( evidence.shards[ordinal].sha256) ;
	}

	writer.append( "]") ;
	writer.append( "}") ;
	return writer.take() ;
}
} // namespace

/** @see local_collector_segment_inventory.h */
DWORD LocalCollectorSegmentInventory::inspect(
	LocalCollectorCollectionStore &collection, LocalCollectorSegmentLease &segment,
	const std::span<const CollectorCampaignSource> sources, const std::uint64_t utcMillis,
	std::shared_ptr<const CollectorSegmentRootInventory> &inventory,
	const std::function<DWORD()>						 &beforeFinalRecheck) noexcept
{
	inventory.reset() ;
	try {
		require( segment.history() != nullptr, ERROR_INVALID_PARAMETER) ;
		CollectorSegmentRootEvidence evidence ;	// 同じ二readerだけが埋める未公開値です。
		const std::function<DWORD( const CollectorCompletedRootEvidence &,
								  const std::function<DWORD()> &)>
			couple = [&collection, &segment, utcMillis, &evidence,
					  &beforeFinalRecheck]( const CollectorCompletedRootEvidence &history,
										   const std::function<DWORD()>			&recheck) {
				// 共有監督だけが元候補を渡し、双方の借用中に値比較と診断を行います。
				const std::function<DWORD( const CollectorSharedRootEvidence &)> before =
					[&history, &beforeFinalRecheck]( const CollectorSharedRootEvidence &shared) {
						compare( history, shared) ;
						return beforeFinalRecheck ? beforeFinalRecheck() : ERROR_SUCCESS ;
					} ; // 元候補はこの同期共有検査より長く存続します。
				return LocalCollectorSharedStore::inspectSharedRootInventoryBound(
					collection, segment, utcMillis, evidence.shared, before, recheck) ;
			} ; // Leaseと全参照はこの同期検査中だけ有効です。
		const auto code = LocalCollectorRecovery::inspectCompletedRootInventoryBound(
			*segment.history(), sources, utcMillis, evidence.history, {}, nullptr,
			couple) ;	// 第一errorです。
		require( code == ERROR_SUCCESS, code) ;
		require( evidence.history && evidence.shared) ;
		segmentInventory( evidence) ;
		evidence.seal =
			segmentSeal( evidence.history->evidence(), evidence.shared->evidence(), evidence) ;
		const auto hashed = static_cast<DWORD>( computeCollectorMetadataSha256(
			evidence.seal, evidence.sealSha256)) ;	// 元本文全byteのCNG結果です。
		require( hashed == ERROR_SUCCESS, hashed) ;
		inventory = std::make_shared<const CollectorSegmentRootInventory>(
			CollectorSegmentRootInventory::ConstructionKey{}, std::move( evidence)) ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		return code ;
	} catch( const collector_projected_json::Failure failure) {
		return failure.status == collector_projected_json::Status::SIZE_LIMIT ? ERROR_TOO_MANY_NAMES
																			  : ERROR_INVALID_DATA ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}
/** @see local_collector_segment_inventory.h */
DWORD LocalCollectorSegmentInventory::inspectRecovery(
	const std::array<LocalCollectorStateStore *, 3U>	 &stores,
	const CollectorSegmentRecoveryState					 &state,
	const std::span<const CollectorCampaignSource>		  sources,
	std::shared_ptr<const CollectorSegmentRootInventory> &inventory,
	const std::function<DWORD()>						 &beforeFinalRecheck) noexcept
{
	inventory.reset() ;
	try {
		require( stores[0] && stores[1] && stores[2], ERROR_INVALID_PARAMETER) ;
		CollectorSegmentRootEvidence evidence ;					// 同じ保護二readerだけの未公開値です。
		const auto utcMillis = state.draft.intent.accepted ;	// 元seal検査時刻です。
		const std::function<DWORD( const CollectorCompletedRootEvidence &,
								  const std::function<DWORD()> &)>
			couple = [&]( const CollectorCompletedRootEvidence &history,
						 const std::function<DWORD()>		  &recheck) {
				const std::function<DWORD( const CollectorSharedRootEvidence &)> before =
					[&]( const CollectorSharedRootEvidence &shared) {
						compare( history, shared) ;
						return beforeFinalRecheck ? beforeFinalRecheck() : ERROR_SUCCESS ;
					} ; // 両借用中だけの比較と診断です。
				return LocalCollectorSharedStore::inspectRecoveryRootInventoryBound(
					*stores[0], *stores[1], state.draft, state.oldHeadRaw, evidence.shared, before,
					recheck) ;
			} ; // 実handleとstateは同期検査より長く生存します。
		const auto code = LocalCollectorRecovery::inspectCompletedRootInventoryBound(
			*stores[2], sources, utcMillis, evidence.history, {}, nullptr,
			couple) ;	// 元履歴の全意味検査です。
		require( code == ERROR_SUCCESS, code) ;
		require( evidence.history && evidence.shared) ;
		segmentInventory( evidence) ;
		evidence.seal =
			segmentSeal( evidence.history->evidence(), evidence.shared->evidence(), evidence) ;
		evidence.sealSha256 = digest( evidence.seal) ;
		require( evidence.sealSha256 == state.draft.intent.seal &&
				evidence.history->evidence().rootSha256 == state.draft.intent.oldRoot &&
				evidence.shared->evidence().headSha256 == state.draft.intent.oldHead &&
				evidence.shards.size() == state.draft.intent.inventory.size()) ;
		// 元全shardをordinalごとの本文hashへ完全結合します。
		for( std::size_t n = 0U; n < evidence.shards.size(); ++n) {
			require( evidence.shards[n].sha256 == state.draft.intent.inventory[n]) ;
		}

		inventory = std::make_shared<const CollectorSegmentRootInventory>(
			CollectorSegmentRootInventory::ConstructionKey{}, std::move( evidence)) ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		return code ;
	} catch( const collector_projected_json::Failure &failure) {
		return failure.status == collector_projected_json::Status::SIZE_LIMIT ? ERROR_TOO_MANY_NAMES
			   : failure.status == collector_projected_json::Status::OUT_OF_MEMORY
				   ? ERROR_NOT_ENOUGH_MEMORY
				   : ERROR_INVALID_DATA ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}
} // namespace drivercrate
