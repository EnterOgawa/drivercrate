//------------------------------------------------------------------------------
/**
 * @file signed_index_record_lookup.cpp
 * @brief 保存snapshotの期限とcontextを確認して公開ID照合関係を保持します。
 * @version 01.02.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  有限callbackとopaque結果の拒否を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  同snapshotと全context限定の私有batch集約を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/14  同native私有証拠の部分positiveを元不足と分離。
 * </pre>
 *
 * @note 原公開metadataを保持し、Windows適合・rank・導入許可へ昇格しません。
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#include "platform/signed_index_record_lookup.h"

#include <algorithm>
#include <new>
#include <set>
#include <utility>
#include <windows.h>

namespace drivercrate {

/** @see signed_index_record_lookup.h 宣言側の契約を正本とします。 */
NativeIndexPositiveProof::NativeIndexPositiveProof(
	MintKey key, IndexLookupContext context, IndexPnpIdKind kind, std::string_view publishedId,
	std::string_view classGuid, std::uint32_t ownerThread, std::weak_ptr<const void> lease,
	std::vector<std::wstring> devices, NativeError error)
	: context_( context), kind_( kind), publishedId_( publishedId), classGuid_( classGuid),
	  ownerThread_( ownerThread), lease_( std::move( lease)), devices_( std::move( devices)),
	  error_( error)
{
	static_cast<void>( key) ;
}

/** @see signed_index_record_lookup.h 宣言側の契約を正本とします。 */
bool NativeIndexPositiveProof::matches( const IndexLookupContext context, const IndexPnpIdKind kind,
									   const std::string_view			   publishedId,
									   const std::string_view			   classGuid,
									   const std::uint32_t				   ownerThread,
									   const std::span<const std::wstring> devices,
									   const NativeError				   error) const noexcept
{
	return context == context_ && kind == kind_ && publishedId == publishedId_ &&
		   classGuid == classGuid_ && ownerThread == ownerThread_ && error == error_ &&
		   !lease_.expired() && !devices_.empty() && devices.size() == devices_.size() &&
		   std::equal( devices.begin(), devices.end(), devices_.begin()) ;
}

namespace {

/** @brief 一公開IDのcallback結果を有限に検査し、関係へ反映します。
 * @param[in,out] relation 元recordとcontextを持つ格納先。
 * @param[in] resolution Callbackの元結果。
 * @param[in] present 同contextの有限present検索集合。本呼出し中だけ借用します。
 * @param[in,out] retainedIdentities Batch内で保持したopaqueの総数。最大32768件です。
 * @param[in] kind 元recordの公開identifier役割です。
 * @param[in] publishedId 元recordの公開identifierです。保持しません。
 * @param[in] classGuid 元recordの公開Classです。保持しません。
 */
void applyResolution( IndexRecordRelation &relation, const IndexPublicIdResolution &resolution,
					 const std::set<std::wstring_view> &present, std::size_t &retainedIdentities,
					 IndexPnpIdKind kind, std::string_view publishedId, std::string_view classGuid)
{
	relation.error = resolution.error ;
	// 古いcallbackを現在のrelationへ適用しない。
	if( resolution.context != relation.context) {
		relation.reason = IndexRecordMatchReason::RESOLVER_CONTEXT_MISMATCH ;
		return ;
	}

	const bool verifiedPartial =
		!resolution.completed && resolution.positiveProof &&
		resolution.positiveProof->matches(
			relation.context, kind, publishedId, classGuid, GetCurrentThreadId(),
			resolution.devices, resolution.error) ;	// 公開DTOだけでは成立しない同native根拠です。
	// 発行済みpartial証拠のcompletedを変更して完全成功へ読み替えません。
	if( resolution.positiveProof && resolution.completed) {
		relation.reason = IndexRecordMatchReason::INVALID_OPAQUE_RESULT ;
		return ;
	}

	// 私有positive根拠のない元失敗を独立した障害として保持します。
	if( FAILED( static_cast<HRESULT>( resolution.error)) && !verifiedPartial) {
		relation.reason = IndexRecordMatchReason::RESOLVER_FAILED ;
		return ;
	}

	// 部分的な戻りidentityを照合完了とみなさない。
	if( !resolution.completed && !verifiedPartial) {
		relation.reason = IndexRecordMatchReason::RESOLVER_INCOMPLETE ;
		return ;
	}

	// 不正な大量結果を解析せず、有限戻り枠を拒否する。
	if( resolution.devices.size() > INDEX_LOOKUP_PRESENT_MAX) {
		relation.reason = IndexRecordMatchReason::INVALID_OPAQUE_RESULT ;
		return ;
	}

	std::set<std::wstring_view> seen ;	// Callback内の重複identityを検出する借用集合。
	// 有限な戻りopaqueを一度ずつ確認し、最初の未知または重複で停止する。
	for( const auto &device : resolution.devices) {
		// 未知opaque・空値・重複を合法な非一意結果へ読み替えない。
		if( device.empty() || !present.contains( device) || !seen.insert( device).second) {
			relation.reason = IndexRecordMatchReason::INVALID_OPAQUE_RESULT ;
			return ;
		}
	}

	// Batch全体の保持枠を超える戻り値を部分的な成功へ削らない。
	if( resolution.devices.size() > INDEX_LOOKUP_RESOLVER_CALL_MAX - retainedIdentities) {
		relation.reason = IndexRecordMatchReason::BUDGET_EXHAUSTED ;
		return ;
	}

	relation.relatedDevices = resolution.devices ;
	retainedIdentities += resolution.devices.size() ;
	// 他node不足を正常完了へ変えず、元errorと既知positiveを独立した区分で保持します。
	if( verifiedPartial) {
		relation.state		   = IndexRecordMatchState::VERIFIED_PARTIAL ;
		relation.reason		   = IndexRecordMatchReason::VERIFIED_POSITIVE_PARTIAL ;
		relation.positiveProof = resolution.positiveProof ;
		// 検証済み部分集合が一deviceのときだけ独立した準備対象へ結べます。
		if( resolution.devices.size() == 1U) {
			relation.deviceIdentity = resolution.devices.front() ;
		}

		return ;
	}

	relation.state	= IndexRecordMatchState::UNMATCHED ;
	relation.reason = resolution.devices.empty() ? IndexRecordMatchReason::NO_RELATION
												 : IndexRecordMatchReason::NON_UNIQUE_RELATION ;
	// 完了した一つのpresent opaqueだけをread-only関係へ結ぶ。
	if( resolution.devices.size() == 1U) {
		relation.deviceIdentity = resolution.devices.front() ;
		relation.state			= IndexRecordMatchState::MATCHED ;
		relation.reason			= IndexRecordMatchReason::UNIQUE_RELATION ;
	}
}

} // namespace

SignedIndexRecordLookup::SignedIndexRecordLookup(
	std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot,
	std::vector<IndexRecordRelation> relations, const IndexLookupContext context)
	: snapshot_( std::move( snapshot)), relations_( std::move( relations)), context_( context)
{
}

const AuthenticatedIndexSnapshot &SignedIndexRecordLookup::snapshot() const noexcept
{
	return *snapshot_ ;
}

std::span<const IndexRecordRelation> SignedIndexRecordLookup::relations() const noexcept
{
	return relations_ ;
}

IndexRecordLookupResult lookupSignedIndexRecords(
	std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot, const IndexLookupContext request,
	const IndexLookupContext current, const std::span<const std::wstring> present,
	const IndexLookupBudget budget, const std::optional<std::chrono::sys_seconds> nowUtc,
	const IndexPublicIdResolver *resolver) noexcept
{
	IndexRecordLookupResult result ;	// 拒否時には所有lookupを発行しない。
	try {
		// 所有根拠のないnull入力ではmetadataやcallbackへ進まない。
		if( !snapshot) {
			return result ;
		}

		const auto &schema	 = snapshot->schemaReceipt() ;	// 原schema receiptの呼出し中だけの借用。
		const auto &asset	 = schema.assetBytes() ;		// 原byte根拠を借用する。
		const auto &manifest = asset.manifest().data() ;	// Scalarだけ残ったmove元も検査する。
		// 必須の原byteと認証identityが欠けたmove元をcallbackへ渡さない。
		if( snapshot->originalEnvelope().empty() || snapshot->originalGzip().empty() ||
		   asset.expandedBytes().empty() || manifest.manifestBytes.empty() ||
		   manifest.repository.empty() || manifest.channel.empty() || manifest.keyId.empty() ||
		   manifest.asset.tag.empty() || manifest.asset.name.empty()) {
			return result ;
		}

		// 信頼UTC不明を期限内と推測しない。
		if( !nowUtc) {
			result.status = IndexRecordLookupStatus::TIME_UNAVAILABLE ;
			return result ;
		}

		// 署名発行前のsnapshotを利用しない。
		if( *nowUtc < manifest.publishedAtUtc) {
			result.status = IndexRecordLookupStatus::NOT_YET_VALID ;
			return result ;
		}

		// 署名期限と同値を含め、期限切れsnapshotを利用しない。
		if( *nowUtc >= manifest.expiresAtUtc) {
			result.status = IndexRecordLookupStatus::EXPIRED ;
			return result ;
		}

		// 不明またはstaleなworker contextをopaque集合へ結ばない。
		if( request.operationId == 0U || request.scanSessionId == 0U ||
		   request.inventoryGeneration == 0U || request != current) {
			result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
			return result ;
		}

		// Batch位置と件数・callback枠を有限にし、加算前に残量へ制限する。
		if( present.size() > INDEX_LOOKUP_PRESENT_MAX ||
		   budget.recordOffset > schema.records().size() || budget.recordCount == 0U ||
		   budget.recordCount > INDEX_LOOKUP_RECORD_BATCH_MAX ||
		   budget.resolverCalls > INDEX_LOOKUP_RESOLVER_CALL_MAX) {
			result.status = IndexRecordLookupStatus::BUDGET_LIMIT ;
			return result ;
		}

		std::set<std::wstring_view> identities ;	// Workerの有限opaqueを呼出し中だけ借用する。
		// Presentの全opaqueを確認し、空・重複ではcallback前に停止する。
		for( const auto &identity : present) {
			// 不正present集合から照合成功を作らない。
			if( identity.empty() || !identities.insert( identity).second) {
				result.status = IndexRecordLookupStatus::INVALID_PRESENT_SET ;
				return result ;
			}
		}

		const std::size_t				 count = std::min( budget.recordCount,
														  // 選択batchの有限実件数。
														  schema.records().size() - budget.recordOffset) ;
		std::size_t						 calls = 0U ;				// この呼出しで実行したcallback数。
		std::size_t						 retainedIdentities = 0U ;	// Batch全体の有限opaque保持数。
		std::vector<IndexRecordRelation> relations ;				// 公開文字列を持たない所有結果。
		// 選択batchの各recordだけを原順序で読み、全件で終了する。
		for( std::size_t offset = 0U; offset < count; ++offset) {
			const std::size_t index	 = budget.recordOffset + offset ;	// 所有snapshotのrecord位置。
			const auto		 &record = schema.records()[index] ;		// 元申告を変更しない借用。
			const auto		 &evidence =
				record.publishedIdentityEvidence ;	// 公開側のIDとclassだけを使う。
			IndexRecordRelation base ;				// 同recordの原hashとidentityのread-only tuple。
			base.recordIndex  = index ;
			base.context	  = request ;
			base.recordSha256 = record.recordSha256 ;
			base.sourceId	  = record.sourceId ;
			base.recordId	  = record.recordId ;
			// 公開identity不足をdevice不存在やdriverなしへ読み替えない。
			if( evidence.state != IndexEvidenceState::PUBLISHED || evidence.pnpIds.empty() ||
			   evidence.classGuid.empty()) {
				relations.push_back( std::move( base)) ;
				continue ;
			}

			// 有限な元公開IDを原順序で一つずつ照合し、複数device関係を維持する。
			for( std::size_t idIndex = 0U; idIndex < evidence.pnpIds.size(); ++idIndex) {
				auto relation		   = base ;	// 同recordへ結ぶ独立した公開ID結果。
				relation.publicIdIndex = idIndex ;
				// 未設定callbackを未実行のまま残す。
				if( resolver == nullptr) {
					relation.reason = IndexRecordMatchReason::RESOLVER_UNAVAILABLE ;
				}
				// 有限予算を使い切ったIDを黙って削除しない。
				else if( calls == budget.resolverCalls) {
					relation.reason = IndexRecordMatchReason::BUDGET_EXHAUSTED ;
				} else {
					++calls ;
					const auto &id = evidence.pnpIds[idIndex] ;	// 公表種別と原文字列の借用。
					try {
						const auto resolution =
							resolver->resolve( id.kind, id.value, evidence.classGuid, request,
											  present) ;	// 同worker同期の元結果。
						applyResolution( relation, resolution, identities, retainedIdentities,
										id.kind, id.value, evidence.classGuid) ;
					} catch( const std::bad_alloc &) {
						relation.state = IndexRecordMatchState::UNDETERMINED ;
						relation.deviceIdentity.reset() ;
						relation.relatedDevices.clear() ;
						relation.reason = IndexRecordMatchReason::RESOLVER_EXCEPTION ;
						relation.error	= static_cast<NativeError>( E_OUTOFMEMORY) ;
					} catch( ...) {
						relation.state = IndexRecordMatchState::UNDETERMINED ;
						relation.deviceIdentity.reset() ;
						relation.relatedDevices.clear() ;
						relation.reason = IndexRecordMatchReason::RESOLVER_EXCEPTION ;
						relation.error	= static_cast<NativeError>( E_FAIL) ;
					}
				}

				relations.push_back( std::move( relation)) ;
			}
		}

		result.lookup = SignedIndexRecordLookup{snapshot, std::move( relations), request} ;
		result.status = IndexRecordLookupStatus::LOOKUP_READY ;
		return result ;
	} catch( const std::bad_alloc &) {
		result.status = IndexRecordLookupStatus::OUT_OF_MEMORY ;
		result.error  = static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		result.status = IndexRecordLookupStatus::INTERNAL_FAILURE ;
		result.error  = static_cast<NativeError>( E_FAIL) ;
	}

	result.lookup.reset() ;
	return result ;
}

/** @see SignedIndexRecordLookup 宣言側の契約を正本とする。 */
IndexRecordLookupResult SignedIndexRecordLookup::freezeOwnedBatches(
	std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot, const IndexLookupContext context,
	const std::span<const SignedIndexRecordLookup> batches,
	const std::optional<std::chrono::sys_seconds>  nowUtc) noexcept
{
	const auto recordEnd =
		snapshot ? snapshot->schemaReceipt().records().size() : 0U ;	// 空終端batch位置。
	auto result = lookupSignedIndexRecords( snapshot, context, context, {}, {recordEnd, 1U, 0U},
										   nowUtc, nullptr) ;	// 原byte・期限・contextの共通再検査。
	// 入力拒否では集約用の空lookupも発行しません。
	if( !result.lookup) {
		return result ;
	}

	result.lookup.reset() ;
	try {
		std::vector<IndexRecordRelation> relations ;	// 全batchのglobal位置を保つ私有所有。
		std::set<std::pair<std::size_t, std::optional<std::size_t>>>
					seen ;											// 原record／公開IDの一意集合。
		std::size_t relatedCount{} ;								// 全batch共通のopaque保持枠。
		const auto	records = snapshot->schemaReceipt().records() ;	// 同原snapshotの借用。
		// 私有構築済みbatchを順に読み、別snapshotやcontext混入で全集約を拒否します。
		for( const auto &batch : batches) {
			// 共有元object完全一致は原byte/hashと全generationの取り替えも拒否します。
			if( batch.snapshot_ != snapshot || batch.context_ != context) {
				result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
				return result ;
			}

			// 最大32768関係を越えるbatchを部分的な権限へ削りません。
			if( batch.relations_.size() > 32768U - relations.size()) {
				result.status = IndexRecordLookupStatus::BUDGET_LIMIT ;
				return result ;
			}

			// 全関係の原record hash・identity・contextを再照合してから所有します。
			for( const auto &relation : batch.relations_) {
				// 原recordや公開IDを取り替えた関係と重複batchを受理しません。
				if( relation.context != context || relation.recordIndex >= records.size() ||
				   !seen.emplace( relation.recordIndex, relation.publicIdIndex).second) {
					result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
					return result ;
				}

				const auto &record = records[relation.recordIndex] ;	// 一意な原record。
				// Hash・source・recordは同認証原byteの値との完全一致だけを受理します。
				if( relation.recordSha256 != record.recordSha256 ||
				   relation.sourceId != record.sourceId || relation.recordId != record.recordId ||
				   relation.relatedDevices.size() > 32768U - relatedCount) {
					result.status = IndexRecordLookupStatus::BUDGET_LIMIT ;
					return result ;
				}

				relatedCount += relation.relatedDevices.size() ;
				relations.push_back( relation) ;
			}
		}

		result.lookup = SignedIndexRecordLookup{std::move( snapshot), std::move( relations), context} ;
		result.status = IndexRecordLookupStatus::LOOKUP_READY ;
	} catch( const std::bad_alloc &) {
		result.status = IndexRecordLookupStatus::OUT_OF_MEMORY ;
		result.error  = static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		result.status = IndexRecordLookupStatus::INTERNAL_FAILURE ;
		result.error  = static_cast<NativeError>( E_UNEXPECTED) ;
	}

	return result ;
}

} // namespace drivercrate
