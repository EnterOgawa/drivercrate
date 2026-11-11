//------------------------------------------------------------------------------
/**
 * @file signed_index_record_lookup.cpp
 * @brief 保存snapshotの期限とcontextを確認して公開ID照合関係を保持します。
 * @version 01.04.01
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
 * Ver.01.03.00 Shunji Ogawa  2026/10/27  元cohort/診断と対象一件をprivate証拠へ完全結合。
 * Ver.01.04.00 Shunji Ogawa  2026/11/07  全体容量・所有stateと有限進行の契約へ整合。
 * Ver.01.04.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 *
 * @note 原公開metadataを保持し、Windows適合・rank・導入許可へ昇格しません。
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 * @see docs/adr/0413-authenticated-per-device-index-projection.md
 */
//------------------------------------------------------------------------------
#include "platform/signed_index_record_lookup.h"

#include <algorithm>
#include <new>
#include <set>
#include <tuple>
#include <utility>
#include <windows.h>

namespace drivercrate {

//------------------------------------------------------------------------------
/**
 * @brief 元context/ownerとweak寿命にread-open fieldの借用を結びます。
 * @param[in] key 元DriverStoreのmint keyです。
 * @param[in] context 元operation/scan/inventoryです。
 * @param[in] ownerThread 元inventoryのthreadです。
 * @param[in] owner 元stateのweak寿命です。強所有しません。
 * @param[in] readOpen owner内の元read-open fieldです。lock成功時だけ参照します。
 */
//------------------------------------------------------------------------------
NativeIndexLookupLease::NativeIndexLookupLease( MintKey key, IndexLookupContext context,
											   std::uint32_t			 ownerThread,
											   std::weak_ptr<const void> owner,
											   const bool				*readOpen)
	: context_( context), ownerThread_( ownerThread), owner_( std::move( owner)), readOpen_( readOpen)
{
	static_cast<void>( key) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同context/owner thread・元state寿命/read-openを確認します。
 * @param[in] context 元完全contextです。
 * @param[in] ownerThread 現在実行中のthreadです。
 * @return 元stateが同threadでread-openのときだけtrueです。I/Oを行いません。
 */
//------------------------------------------------------------------------------
bool NativeIndexLookupLease::matches( IndexLookupContext context,
									 std::uint32_t		ownerThread) const noexcept
{
	// 別threadから元mutable stateを参照せず、別context/空fieldも拒否します。
	if( context != context_ || ownerThread != ownerThread_ || readOpen_ == nullptr) {
		return false ;
	}

	const auto owner = owner_.lock() ;	// fieldを参照する期間だけ元stateの寿命を確保します。
	return owner && *readOpen_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同scanから確認した元公開tupleと既知device集合を不変保存します。
 * @param[in] key DriverStoreだけが構築した発行keyです。
 * @param[in] context 元worker／scan／inventoryの全contextです。
 * @param[in] kind 元公開INF側のidentifier役割です。
 * @param[in] publishedId 元公開ASCII identifierを本呼出し中だけ借用してcopyします。
 * @param[in] classGuid 元公開Class文字列を本呼出し中だけ借用してcopyします。
 * @param[in] ownerThread 同inventoryを所有するWindows thread IDです。
 * @param[in] lease Providerが強所有する元scan stateへのweak leaseです。
 * @param[in] devices 両native属性と既知Classが検証されたopaque集合を所有moveします。
 * @param[in] error 同callbackが保持した元不足診断です。
 * @note 元列挙完了と必要属性の検証は発行側の前提です。秘密IDやURLを保持しません。
 */
//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
/**
 * @brief 元tupleとdevice集合の完全一致および同ownerの生存を確認します。
 * @param[in] context 現callbackの全contextです。
 * @param[in] kind lookupが元recordから読んだ公開役割です。
 * @param[in] publishedId lookupが元recordから読んだ公開identifierです。
 * @param[in] classGuid lookupが元recordから読んだ公開Classです。
 * @param[in] ownerThread lookupを実行中のWindows thread IDです。
 * @param[in] devices callbackが返した全opaque集合を本呼出し中だけ借用します。
 * @param[in] error callbackまたは私有relationが保持した元不足診断です。
 * @return 全一致と生存確認が成立した場合だけtrueです。
 * @note I/Oや参照の保持は行いません。失効したscanを再有効化しません。
 */
//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
/**
 * @brief 元公開tupleと全cohort、一deviceの完全観測を不変保存します。
 * @param[in] key DriverStoreだけが構築した発行keyです。
 * @param[in] context 元operation/scan/inventoryです。
 * @param[in] kind 元公開IDの役割です。
 * @param[in] publishedId 元公開IDをcopyします。端末raw IDではありません。
 * @param[in] classGuid 元公開Classをcopyします。
 * @param[in] ownerThread 元scanのWindows owner threadです。
 * @param[in] lease Providerだけが強所有する元stateです。
 * @param[in] devices 同callbackが返す全opaque cohortをcopyします。
 * @param[in] error 他node不足も保持する元診断です。
 * @param[in] completed 元callbackの全体完了区分です。
 * @param[in] deviceIdentity 完全個別観測が成立したopaque一件をcopyします。
 */
//------------------------------------------------------------------------------
NativeIndexDeviceProof::NativeIndexDeviceProof( MintKey key, IndexLookupContext context,
											   IndexPnpIdKind kind, std::string_view publishedId,
											   std::string_view			 classGuid,
											   std::uint32_t			 ownerThread,
											   std::weak_ptr<const void> lease,
											   std::vector<std::wstring> devices, NativeError error,
											   bool completed, std::wstring deviceIdentity)
	: context_( context), kind_( kind), publishedId_( publishedId), classGuid_( classGuid),
	  ownerThread_( ownerThread), lease_( std::move( lease)), devices_( std::move( devices)),
	  error_( error), completed_( completed), deviceIdentity_( std::move( deviceIdentity))
{
	static_cast<void>( key) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元tuple/診断/全cohortと対象一件、同ownerの生存を完全照合します。
 * @param[in] context 使用時の全contextです。
 * @param[in] kind 原recordの公開ID役割です。
 * @param[in] publishedId 原recordの公開IDです。
 * @param[in] classGuid 原recordの公開Classです。
 * @param[in] ownerThread 使用中のWindows threadです。
 * @param[in] devices 元callbackの全opaque cohortです。
 * @param[in] error 消去しない元診断です。
 * @param[in] completed 元callbackの完了区分です。
 * @param[in] deviceIdentity 使用対象のopaque一件です。同cohortの他deviceも拒否します。
 * @return 全一致と元leaseの生存が成立した場合だけtrueです。
 */
//------------------------------------------------------------------------------
bool NativeIndexDeviceProof::matches( const IndexLookupContext context, const IndexPnpIdKind kind,
									 const std::string_view				 publishedId,
									 const std::string_view				 classGuid,
									 const std::uint32_t				 ownerThread,
									 const std::span<const std::wstring> devices,
									 const NativeError error, const bool completed,
									 const std::wstring_view deviceIdentity) const noexcept
{
	return context == context_ && kind == kind_ && publishedId == publishedId_ &&
		   classGuid == classGuid_ && ownerThread == ownerThread_ && !lease_.expired() &&
		   error == error_ && completed == completed_ && deviceIdentity == deviceIdentity_ &&
		   !deviceIdentity_.empty() && !devices_.empty() && devices_.size() <= 32U &&
		   devices.size() == devices_.size() &&
		   std::equal( devices.begin(), devices.end(), devices_.begin()) &&
		   std::ranges::find( devices_, deviceIdentity_) != devices_.end() ;
}

namespace {

//------------------------------------------------------------------------------
/**
 * @brief 元callbackの各個別証拠を全tuple/全cohortへ照合します。
 * @param[in] resolution 元callbackの不変結果です。
 * @param[in] kind 原recordの公開役割です。
 * @param[in] publishedId 原recordの公開IDです。
 * @param[in] classGuid 原recordの公開Classです。
 * @return 一件以上の認証済みslotがあり、存在する証拠が全て完全一致した場合trueです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool verifiedDeviceProofs( const IndexPublicIdResolution &resolution,
										IndexPnpIdKind kind, std::string_view publishedId,
										std::string_view classGuid)
{
	// 欠損や大量cohortを一部の成功証拠で補完しません。
	if( resolution.devices.empty() || resolution.devices.size() > 32U ||
	   resolution.deviceProofs.size() != resolution.devices.size()) {
		return false ;
	}

	bool found{} ;	// 一件以上の完全証拠が必要です。
	// 同順の全slotを確認し、証拠の対象や元errorの改変で全投影を拒否します。
	for( std::size_t index = 0U; index < resolution.deviceProofs.size(); ++index) {
		const auto &proof = resolution.deviceProofs[index] ;	// 元node専用の不変証拠です。
		// 未認証nodeは成功へ数えず、他の合法nodeの全cohortには残します。
		if( !proof) {
			continue ;
		}

		// 同cohortの他deviceや別公開tupleへの転用を認めません。
		if( !proof->matches( resolution.context, kind, publishedId, classGuid, GetCurrentThreadId(),
						   resolution.devices, resolution.error, resolution.completed,
						   resolution.devices[index])) {
			return false ;
		}

		found = true ;
	}

	return found ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一公開IDのcallback結果を有限に検査し、関係へ反映します。
 * @param[in,out] relation 元recordとcontextを持つ格納先。
 * @param[in] resolution Callbackの元結果。
 * @param[in] present 同contextの有限present検索集合。本呼出し中だけ借用します。
 * @param[in,out] retainedIdentities 同batchの保持opaque総数です。
 * @param[in] maximumRelatedIdentities 同scanに残る有限opaque枠です。
 * @param[in] kind 元recordの公開identifier役割です。
 * @param[in] publishedId 元recordの公開identifierです。保持しません。
 * @param[in] classGuid 元recordの公開Classです。保持しません。
 */
//------------------------------------------------------------------------------
void applyResolution( IndexRecordRelation &relation, const IndexPublicIdResolution &resolution,
					 const std::set<std::wstring_view> &present, std::size_t &retainedIdentities,
					 std::size_t maximumRelatedIdentities, IndexPnpIdKind kind,
					 std::string_view publishedId, std::string_view classGuid)
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
	const bool verifiedDevices = verifiedDeviceProofs( resolution, kind, publishedId,
													  classGuid) ;	// 個別観測だけの別証拠です。
	// 存在する個別証拠が不正な結果を完全DTOへ読み替えません。
	if( !resolution.deviceProofs.empty() && !verifiedDevices) {
		relation.reason = IndexRecordMatchReason::INVALID_OPAQUE_RESULT ;
		return ;
	}

	// 発行済みpartial証拠のcompletedを変更して完全成功へ読み替えません。
	if( resolution.positiveProof && resolution.completed) {
		relation.reason = IndexRecordMatchReason::INVALID_OPAQUE_RESULT ;
		return ;
	}

	// 私有positive根拠のない元失敗を独立した障害として保持します。
	if( FAILED( static_cast<HRESULT>( resolution.error)) && !verifiedPartial && !verifiedDevices) {
		relation.reason = IndexRecordMatchReason::RESOLVER_FAILED ;
		return ;
	}

	// 部分的な戻りidentityを照合完了とみなさない。
	if( !resolution.completed && !verifiedPartial && !verifiedDevices) {
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
	if( resolution.devices.size() > maximumRelatedIdentities - retainedIdentities) {
		relation.reason = IndexRecordMatchReason::BUDGET_EXHAUSTED ;
		return ;
	}

	relation.relatedDevices = resolution.devices ;
	retainedIdentities += resolution.devices.size() ;
	// 個別観測だけでは全体不足を成功へ変更せず、全cohortと元診断を保持します。
	if( !resolution.completed && !verifiedPartial) {
		relation.reason = FAILED( static_cast<HRESULT>( resolution.error))
							  ? IndexRecordMatchReason::RESOLVER_FAILED
							  : IndexRecordMatchReason::RESOLVER_INCOMPLETE ;
		return ;
	}

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

//------------------------------------------------------------------------------
/**
 * @brief 保存済みconst snapshotの所有を共有し、関係を所有します。
 * @param[in] snapshot 完全な原保存snapshot。
 * @param[in] relations 同contextの有限関係。
 * @param[in] context 元scanの完全context。取得operationへ書き換えません。
 * @param[in] progress 同じlookup内だけで検査・commitした原record範囲です。
 * @param[in] nativeLease Native元inventoryだけの共有weak寿命証拠です。genericでは空です。
 */
//------------------------------------------------------------------------------
SignedIndexRecordLookup::SignedIndexRecordLookup(
	std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot,
	std::vector<IndexRecordRelation> relations, const IndexLookupContext context,
	IndexLookupProgress progress, std::shared_ptr<const NativeIndexLookupLease> nativeLease)
	: snapshot_( std::move( snapshot)), relations_( std::move( relations)), context_( context),
	  progress_( progress), nativeLease_( std::move( nativeLease))
{
}

//------------------------------------------------------------------------------
/**
 * @brief 原hash・世代・policy・source／record／UNKNOWNを保持するsnapshotを借用します。
 * @return 本lookupが所有する不変snapshot。
 */
//------------------------------------------------------------------------------
const AuthenticatedIndexSnapshot &SignedIndexRecordLookup::snapshot() const noexcept
{
	return *snapshot_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公開ID文字列を含まない有限関係を借用します。
 * @return 本lookupの寿命まで有効な不変span。
 */
//------------------------------------------------------------------------------
std::span<const IndexRecordRelation> SignedIndexRecordLookup::relations() const noexcept
{
	return relations_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 完全record prefixと実callback数だけを借用します。
 * @return 同object寿命まで有効な私有構築済み進行です。
 */
//------------------------------------------------------------------------------
const IndexLookupProgress &SignedIndexRecordLookup::progress() const noexcept
{
	return progress_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原保存snapshotの有限record batchを同worker resolverへ結びます。
 * @param[in] snapshot Commit／reloadだけが発行した完全const snapshotの共有所有。Null・move元を拒否します。正規結果を一度moveしてconst
 *                   所有とし、可変aliasを使いません。
 * @param[in] request 呼出しが要求する正のcontext。
 * @param[in] current 現workerが確認した正のcontext。
 * @param[in] present 同contextのopaque present集合。本呼出し中不変です。
 * @param[in] budget 有限batchとcallback枠。
 * @param[in] nowUtc 現在信頼UTC。発行前・期限以上・確認不能は拒否します。
 * @param[in] resolver 同workerの借用callback。nullptrは未実行として保持します。
 * @return 入力拒否、または元snapshotと各関係を所有する読取り結果。
 * @note 参照を外へ保持せず、例外を境界で診断へ変換します。独立入力は独立workerで呼出し可能です。
 */
//------------------------------------------------------------------------------
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
		   budget.resolverCalls > INDEX_LOOKUP_RESOLVER_CALL_MAX ||
		   budget.maximumRelations > index_capacity::RETAINED_RELATIONS ||
		   budget.maximumRelatedIdentities > index_capacity::RETAINED_OPAQUE_IDENTITIES) {
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

		const auto nativeLease = resolver != nullptr ? resolver->leaseProof()
													 : nullptr ;	// 元native factoryの証拠だけです。
		// staleな元stateを同contextへ読み替えません。
		if( nativeLease && !nativeLease->matches( request, GetCurrentThreadId())) {
			result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
			return result ;
		}

		const auto count = std::min(
			budget.recordCount, schema.records().size() - budget.recordOffset) ;	// 要求prefixです。
		IndexLookupProgress progress ;												// 本呼出しだけが確定する原record coverageです。
		progress.recordOffset	  = budget.recordOffset ;
		progress.nextRecordOffset = budget.recordOffset ;
		std::size_t						 retainedIdentities{} ;	// commit済みbatchのopaque総数です。
		std::vector<IndexRecordRelation> relations ;			// 完全recordだけを単独所有します。
		// 全IDが入るrecordを原順序で処理し、未commit recordは元位置に残します。
		for( std::size_t offset = 0U; offset < count; ++offset) {
			const auto	index	  = budget.recordOffset + offset ;		// 原recordの位置です。
			const auto &record	  = schema.records()[index] ;			// 不変の認証済み原recordです。
			const auto &evidence  = record.publishedIdentityEvidence ;	// 原公開申告です。
			const bool	published = evidence.state == IndexEvidenceState::PUBLISHED &&
								   !evidence.pnpIds.empty() &&
								   !evidence.classGuid.empty() ;	// 全IDを処理する条件です。
			const auto publicIds =
				published ? evidence.pnpIds.size() : 0U ;	// 不明証拠をIDへ推測しません。
			// 取消し・期限後に次recordを開始しません。
			if( budget.stopRequested && budget.stopRequested()) {
				progress.stopReason = IndexLookupStopReason::STOP_REQUESTED ;
				break ;
			}

			// 次record全体が残callback枠へ収まるprefixだけを選びます。
			if( resolver != nullptr && publicIds > budget.resolverCalls - progress.resolverCalls) {
				progress.stopReason = IndexLookupStopReason::CALL_BUDGET ;
				break ;
			}

			IndexRecordRelation base ;	// 同recordの原hash・identity・contextです。
			base.recordIndex  = index ;
			base.context	  = request ;
			base.recordSha256 = record.recordSha256 ;
			base.sourceId	  = record.sourceId ;
			base.recordId	  = record.recordId ;
			std::vector<IndexRecordRelation>
						staged ;								// 原aggregateと全投影をrecord単位で保留します。
			auto		stagedIdentities = retainedIdentities ;	// 未commit時は元累計へ戻ります。
			std::size_t definitive{} ;							// このrecordの完了した確定不一致ID数です。
			const auto	isDefinitive = []( const IndexRecordRelation &relation) {
				 return relation.state == IndexRecordMatchState::UNMATCHED &&
						relation.reason == IndexRecordMatchReason::NO_RELATION &&
						relation.error == 0U && !relation.deviceIdentity &&
						relation.relatedDevices.empty() && !relation.positiveProof &&
						!relation.deviceProof ;
			} ; // 唯一の不一致集約条件です。
			bool stopped{} ;	// 一件でも途中停止ならrecord全体を未commitにします。
			// 公開証拠不足を不存在成功へ変えず、一件の未判定として保持します。
			if( !published) {
				staged.push_back( std::move( base)) ;
			} else {
				// 全公開IDを原順序で照合し、途中停止で次recordへ飛びません。
				for( std::size_t idIndex = 0U; idIndex < publicIds; ++idIndex) {
					// 各同期IDの前にも協調停止を確認します。
					if( budget.stopRequested && budget.stopRequested()) {
						progress.stopReason = IndexLookupStopReason::STOP_REQUESTED ;
						stopped				= true ;
						break ;
					}

					auto relation		   = base ;	// 元recordへ結ぶ独立したID結果です。
					relation.publicIdIndex = idIndex ;
					const auto &id		   = evidence.pnpIds[idIndex] ;	// 原公開IDの借用です。
					// Callbackなしは未判定の元理由を保持します。
					if( resolver == nullptr) {
						relation.reason = IndexRecordMatchReason::RESOLVER_UNAVAILABLE ;
					} else {
						++progress.resolverCalls ;
						const auto stagedBefore =
							// 例外時にこのIDの全投影だけを戻します。
							staged.size() ;
						const auto identitiesBefore =
							stagedIdentities ;	// このID前のopaque累計です。
						try {
							const auto resolution =
								resolver->resolve( id.kind, id.value, evidence.classGuid, request,
												  present) ;	// 同workerの同期結果です。
							// 同期処理中の停止は部分recordの発行を禁止します。
							if( budget.stopRequested && budget.stopRequested()) {
								result.error = result.error != 0U ? result.error : resolution.error ;
								progress.stopReason = IndexLookupStopReason::STOP_REQUESTED ;
								stopped				= true ;
								break ;
							}

							applyResolution( relation, resolution, identities, stagedIdentities,
											budget.maximumRelatedIdentities, id.kind, id.value,
											evidence.classGuid) ;
							// 最初の元診断は保持容量拒否時にも失いません。
							if( result.error == 0U) {
								result.error = relation.error ;
							}

							// Opaque不足を一部のpositiveへ切り詰めません。
							if( relation.reason == IndexRecordMatchReason::BUDGET_EXHAUSTED) {
								progress.stopReason = IndexLookupStopReason::RETAINED_CAPACITY ;
								stopped				= true ;
								break ;
							}

							// 認証済み個別投影は原aggregateと全slotを原子的に保留します。
							if( !relation.deviceIdentity && !relation.relatedDevices.empty() &&
							   verifiedDeviceProofs( resolution, id.kind, id.value,
													evidence.classGuid)) {
								const auto proofCount =
									static_cast<std::size_t>( std::ranges::count_if(
										resolution.deviceProofs, []( const auto &proof) {
											return static_cast<bool>( proof) ;
										})) ; // 認証済みslot数です。
								// 全投影・全opaqueの残枠がなければrecord全体を残します。
								if( proofCount == 0U ||
								   staged.size() + proofCount + 1U >
									   budget.maximumRelations - relations.size() ||
								   resolution.devices.size() >
									   (budget.maximumRelatedIdentities - stagedIdentities) /
										   proofCount) {
									progress.stopReason = IndexLookupStopReason::RETAINED_CAPACITY ;
									stopped				= true ;
									break ;
								}

								staged.push_back( relation) ;
								// 最大32slotを同順で保持し、未認証slotを成功へ投影しません。
								for( std::size_t deviceIndex = 0U;
									deviceIndex < resolution.devices.size(); ++deviceIndex) {
									// 不足slotは元aggregateにだけ残します。
									if( !resolution.deviceProofs[deviceIndex]) {
										continue ;
									}

									auto projected = relation ;	// 元tupleと全cohortをcopyします。
									projected.deviceIdentity = resolution.devices[deviceIndex] ;
									projected.deviceProof	 = resolution.deviceProofs[deviceIndex] ;
									projected.resolutionCompleted = resolution.completed ;
									projected.positiveProof.reset() ;
									projected.state = IndexRecordMatchState::VERIFIED_DEVICE ;
									projected.reason =
										IndexRecordMatchReason::VERIFIED_DEVICE_PROJECTION ;
									staged.push_back( std::move( projected)) ;
								}

								stagedIdentities += resolution.devices.size() * proofCount ;
								continue ;
							}
						} catch( const std::bad_alloc &) {
							staged.resize( stagedBefore) ;
							stagedIdentities	   = identitiesBefore ;
							relation			   = base ;
							relation.publicIdIndex = idIndex ;
							relation.reason		   = IndexRecordMatchReason::RESOLVER_EXCEPTION ;
							relation.error		   = static_cast<NativeError>( E_OUTOFMEMORY) ;
						} catch( ...) {
							staged.resize( stagedBefore) ;
							stagedIdentities	   = identitiesBefore ;
							relation			   = base ;
							relation.publicIdIndex = idIndex ;
							relation.reason		   = IndexRecordMatchReason::RESOLVER_EXCEPTION ;
							relation.error		   = static_cast<NativeError>( E_FAIL) ;
						}
					}

					// 最初の元callback診断を停止時も保持します。
					if( result.error == 0U) {
						result.error = relation.error ;
					}

					const bool noRelation =
						// 私有coverageへ集約できる元結果です。
						isDefinitive( relation) ;
					definitive += noRelation ? 1U : 0U ;
					// 集約可能な確定不一致以外は、一時結果も残保持枠内だけで保持します。
					if( !budget.compactNoRelations || !noRelation) {
						// 次tupleの確保前にrecord全体を残件へ戻します。
						if( staged.size() >= budget.maximumRelations - relations.size()) {
							progress.stopReason = IndexLookupStopReason::RETAINED_CAPACITY ;
							stopped				= true ;
							break ;
						}

						staged.push_back( std::move( relation)) ;
					}

					// 一件のrecordでも一時保持枠を超えたら一部だけを発行しません。
					if( staged.size() > index_capacity::RETAINED_RELATIONS) {
						progress.stopReason = IndexLookupStopReason::RETAINED_CAPACITY ;
						stopped				= true ;
						break ;
					}
				}
			}

			// callback中に失効した元inventoryから完全recordを発行しません。
			if( nativeLease && !nativeLease->matches( request, GetCurrentThreadId())) {
				result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
				return result ;
			}

			// 不足又はcommit直前の停止では原record全体を残件にします。
			if( stopped || (budget.stopRequested && budget.stopRequested())) {
				progress.stopReason =
					stopped ? progress.stopReason : IndexLookupStopReason::STOP_REQUESTED ;
				break ;
			}

			// 全recordの確定結果が残保持枠へ入る場合だけcommitします。
			if( staged.size() > budget.maximumRelations - relations.size()) {
				progress.stopReason = IndexLookupStopReason::RETAINED_CAPACITY ;
				break ;
			}

			relations.reserve( relations.size() + staged.size()) ;
			// 完全recordの全関係を一括moveした後だけ進行を確定します。
			for( auto &relation : staged) {
				relations.push_back( std::move( relation)) ;
			}

			retainedIdentities = stagedIdentities ;
			++progress.completedRecords ;
			progress.nextRecordOffset = index + 1U ;
			progress.processedPublicIds += publicIds ;
			progress.definitiveNoRelationIds += definitive ;
			progress.compactedNoRelationIds += budget.compactNoRelations ? definitive : 0U ;
		}

		result.lookup =
			SignedIndexRecordLookup{snapshot, std::move( relations), request, progress, nativeLease} ;
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

//------------------------------------------------------------------------------
/**
 * @brief 同ownerが発行した全batchだけを一つの不変lookupへ凍結します。
 * @param[in] snapshot 同scanの原保存snapshotの共有所有。
 * @param[in] context 元scanの完全context。
 * @param[in] batches 私有構築済みbatch。公開relationから再構築しません。
 * @param[in] nowUtc 現信頼UTC。期限は凍結時も再照合します。
 * @return 同snapshot・全context・原record結合成立時だけ集約lookup。
 */
//------------------------------------------------------------------------------
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
		std::vector<IndexRecordRelation> relations ;	// 保持する元tupleだけの私有集合です。
		std::set<std::tuple<std::size_t, std::optional<std::size_t>, std::optional<std::wstring>>>
					seen ;											// 全元tupleの一意性です。
		std::size_t relatedCount{} ;								// 同scanの全opaque保持数です。
		std::shared_ptr<const NativeIndexLookupLease> nativeLease ;	// 全batchで同一の元証拠です。
		bool				firstBatch{true} ;						// generic空証拠とnative証拠の混在も拒否します。
		IndexLookupProgress progress ;								// 連続した完全record prefixだけを集約します。
		const auto records = snapshot->schemaReceipt().records() ;	// 同一原snapshotの借用です。
		// 私有batchの所有・進行範囲・原tupleを全件再検査します。
		for( const auto &batch : batches) {
			// 同scanの元private leaseだけを共有し、新しい証拠へ結び直しません。
			if( firstBatch) {
				nativeLease = batch.nativeLease_ ;
				firstBatch	= false ;
			}

			// 失効又は別factoryの証拠を部分的に採用しません。
			if( batch.nativeLease_ != nativeLease ||
			   (nativeLease && !nativeLease->matches( context, GetCurrentThreadId()))) {
				result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
				return result ;
			}

			const auto &coverage = batch.progress_ ;	// DTOから構築できない元commit範囲です。
			// 別snapshot/context、抜け・重複したprefixを受理しません。
			if( batch.snapshot_ != snapshot || batch.context_ != context ||
			   coverage.recordOffset != progress.nextRecordOffset ||
			   coverage.completedRecords == 0U || coverage.recordOffset > records.size() ||
			   coverage.completedRecords > records.size() - coverage.recordOffset ||
			   coverage.nextRecordOffset != coverage.recordOffset + coverage.completedRecords) {
				result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
				return result ;
			}

			// 全scanの入力・関係・opaque枠を加算前に検査します。
			if( batch.relations_.size() > index_capacity::RETAINED_RELATIONS - relations.size() ||
			   coverage.processedPublicIds >
				   index_capacity::WHOLE_PUBLIC_IDS - progress.processedPublicIds) {
				result.status = IndexRecordLookupStatus::BUDGET_LIMIT ;
				return result ;
			}

			std::size_t expectedIds{} ;	// 同認証範囲に実在する公開ID総数です。
			// 完全record範囲の全IDを間引かず数えます。
			for( auto index = coverage.recordOffset; index < coverage.nextRecordOffset; ++index) {
				const auto &evidence =
					records[index].publishedIdentityEvidence ;	// lookupと同じ公開入力分母です。
				// UNKNOWNを公開IDへ補完しません。
				if( evidence.state == IndexEvidenceState::PUBLISHED && !evidence.pnpIds.empty() &&
				   !evidence.classGuid.empty()) {
					expectedIds += evidence.pnpIds.size() ;
				}
			}

			std::size_t aggregateIds{} ;	// 投影を重複加算しない元公開IDtuple数です。
			// 全保持tupleを元record/hash/source/公開IDとleaseへ結び直します。
			for( const auto &relation : batch.relations_) {
				// 他recordへの転用や重複tupleを拒否します。
				if( relation.context != context || relation.recordIndex < coverage.recordOffset ||
				   relation.recordIndex >= coverage.nextRecordOffset ||
				   !seen.emplace( relation.recordIndex, relation.publicIdIndex,
								 relation.deviceIdentity)
						.second) {
					result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
					return result ;
				}

				const auto &record	 = records[relation.recordIndex] ;		// 不変の原recordです。
				const auto &evidence = record.publishedIdentityEvidence ;	// 元ID/classの借用です。
				// 原hash/identity又は個別ID位置が変わったtupleを拒否します。
				if( relation.recordSha256 != record.recordSha256 ||
				   relation.sourceId != record.sourceId || relation.recordId != record.recordId ||
				   (relation.publicIdIndex && *relation.publicIdIndex >= evidence.pnpIds.size()) ||
				   relation.relatedDevices.size() >
					   index_capacity::RETAINED_OPAQUE_IDENTITIES - relatedCount) {
					result.status = IndexRecordLookupStatus::BUDGET_LIMIT ;
					return result ;
				}

				// 発行済みpartial/device証拠は凍結時にも元leaseと全tupleへ完全一致させます。
				if( relation.positiveProof || relation.deviceProof) {
					// 公開ID又は対象opaqueがない証拠を補完しません。
					if( !relation.publicIdIndex ||
					   (relation.deviceProof && !relation.deviceIdentity)) {
						result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
						return result ;
					}

					const auto &id = evidence.pnpIds[*relation.publicIdIndex] ;	// 同原公開IDです。
					// 期限後・別cohort・別workerの私有証拠を拒否します。
					if( (relation.positiveProof &&
						!relation.positiveProof->matches(
							context, id.kind, id.value, evidence.classGuid, GetCurrentThreadId(),
							relation.relatedDevices, relation.error)) ||
					   (relation.deviceProof &&
						!relation.deviceProof->matches(
							context, id.kind, id.value, evidence.classGuid, GetCurrentThreadId(),
							relation.relatedDevices, relation.error, relation.resolutionCompleted,
							*relation.deviceIdentity))) {
						result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
						return result ;
					}
				}

				aggregateIds += relation.publicIdIndex &&
										relation.state != IndexRecordMatchState::VERIFIED_DEVICE
									? 1U
									: 0U ;
				relatedCount += relation.relatedDevices.size() ;
				relations.push_back( relation) ;
			}

			// 省略できるのは元私有lookupが確定した不一致だけです。
			if( expectedIds != coverage.processedPublicIds ||
			   coverage.compactedNoRelationIds > expectedIds ||
			   aggregateIds != expectedIds - coverage.compactedNoRelationIds ||
			   coverage.definitiveNoRelationIds > expectedIds ||
			   coverage.compactedNoRelationIds > coverage.definitiveNoRelationIds) {
				result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
				return result ;
			}

			progress.completedRecords += coverage.completedRecords ;
			progress.nextRecordOffset = coverage.nextRecordOffset ;
			progress.processedPublicIds += coverage.processedPublicIds ;
			progress.definitiveNoRelationIds += coverage.definitiveNoRelationIds ;
			progress.compactedNoRelationIds += coverage.compactedNoRelationIds ;
			progress.resolverCalls += coverage.resolverCalls ;
			progress.stopReason = coverage.stopReason ;
		}

		result.lookup = SignedIndexRecordLookup{std::move( snapshot), std::move( relations), context,
												progress, nativeLease} ;
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
