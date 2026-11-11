//------------------------------------------------------------------------------
/**
 * @file local_scan_diagnostics.cpp
 * @brief 索引通信/照合/候補分類の匿名終端診断を組み立てます。
 * @version 01.05.00
 * @date 2026/11/03
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/03  元summaryだけから固定列を投影。
 * Ver.01.01.00 Shunji Ogawa  2026/11/03  元現在観測との取得前版比較件数を投影。
 * Ver.01.02.00 Shunji Ogawa  2026/11/08  匿名導入診断と保存状態・元数値の有限確認を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/11/08  準備不成立後の元表示保持と段階別匿名診断を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/11/08  元checkbox意図の表示保持とbinding拒否の固定診断を接続。
 * Ver.01.05.00 Shunji Ogawa  2026/11/10  最新実確認の選択表示と日内復元保護の実在再利用を接続。
 * </pre>
 * @note 文字列本文・端末identity・版文字列は記録しません。未判定を不適合へ換算しません。
 * @see docs/adr/0427-local-anonymous-scan-diagnostics.md
 */
//------------------------------------------------------------------------------
#include "platform/local_scan_diagnostics.h"
#include "platform/provider_worker.h"
#include "core/provider_registry.h"
#include "core/pending_reference_version.h"
#include "core/device_observation.h"
#include <array>
#include <algorithm>

namespace drivercrate {
namespace {
/** @brief 固定recordだけを既sinkへ非待機投入します。
 * @param[in] record 匿名数値だけの所有値。
 * @param[in,out] sink 内部試験の保存先。
 */
void emitDiagnostic( const DiagnosticRecord &record, LocalDiagnosticLog *sink) noexcept
{
	// Test sinkも同じwriterを使います。
	if( sink) {
		sink->append( record) ;
	} else {
		recordLocalDiagnostic( record) ;
	}
}
}

/** @see local_scan_diagnostics.h 宣言側の契約を正本とします。 */
void recordInstallSelectionDiagnostics( const OperationId					  operation,
									   const std::span<const UpdateCandidate> candidates,
									   const std::span<const std::size_t>	  indexes,
									   const bool accepted, LocalDiagnosticLog *const sink) noexcept
{
	DiagnosticRecord record ;	// 候補のidentityや版を持ちません。
	record.event = accepted ? DiagnosticEvent::INSTALL_STARTED : DiagnosticEvent::INSTALL_REQUESTED ;
	record.operation = operation ;
	std::uint64_t updates{}, reinstalls{}, downgrades{}, initial{} ;	// 元actionの件数だけです。
	// 元indexから分類件数だけを読みます。
	for( const auto index : indexes) {
		// 範囲外を先頭候補へ補完しません。
		if( index >= candidates.size()) {
			continue ;
		}

		const auto action = candidates[index].action ;	// 閉enumです。
		updates += action == DriverAction::UPDATE ? 1U : 0U ;
		reinstalls += action == DriverAction::REINSTALL ? 1U : 0U ;
		downgrades += action == DriverAction::DOWNGRADE ? 1U : 0U ;
		initial += action == DriverAction::INITIAL_INSTALL ? 1U : 0U ;
	}

	record.add( DiagnosticField::TOTAL, indexes.size())
		.add( DiagnosticField::UPDATES, updates)
		.add( DiagnosticField::REINSTALLS, reinstalls)
		.add( DiagnosticField::DOWNGRADES, downgrades)
		.add( DiagnosticField::INITIAL_INSTALLS, initial) ;
	emitDiagnostic( record, sink) ;
}

/** @see local_scan_diagnostics.h 宣言側の契約を正本とします。 */
void recordPreparationDiagnostics( const OfficialPreparationApproval				 &approval,
								  const OfficialPreparationOperationResult *const result,
								  const std::int32_t							  applicationState,
								  LocalDiagnosticLog *const						  sink) noexcept
{
	DiagnosticRecord record ;	// 元承認の本文は出しません。
	record.event	 = DiagnosticEvent::PREPARATION_OPERATION ;
	record.operation = approval.operationId ;
	record.status	 = applicationState ;
	record.add( DiagnosticField::STAGE, result ? 1U : 0U)
		.add( DiagnosticField::TOTAL, approval.decisions.size())
		.add( DiagnosticField::INTENT_COUNT, approval.installIntentIdentities.size()) ;
	// 元終端がある場合だけ結果を加えます。
	if( result) {
		record.error = result->controlError ;
		record.add( DiagnosticField::OUTCOME, static_cast<std::uint64_t>( result->approvalError))
			.add( DiagnosticField::PROCESSED, result->items.size())
			.add( DiagnosticField::READY_COUNT,
				 std::ranges::count( result->installResolutions,
									PreparedInstallResolutionState::READY,
									&PreparedInstallResolution::state)) ;
	}

	emitDiagnostic( record, sink) ;
}

/** @see local_scan_diagnostics.h 宣言側の契約を正本とします。 */
void recordPreparationResultDiagnostics( const OfficialPreparationApproval		 &approval,
										const OfficialPreparationOperationResult &result,
										const IndexPreparationSummary			 *verifiedIndex,
										LocalDiagnosticLog *const				  sink) noexcept
{
	constexpr std::size_t limit	   = 16U ;	// 実処理を制限せず、匿名投影だけを有限化します。
	const auto			  selected = static_cast<std::size_t>( std::ranges::count(
		   approval.decisions, true, &OfficialPreparationDecision::acquire)) ;	// 元の取得判断数です。
	const auto			  make = [&]( const std::size_t ordinal, const std::wstring_view provider,
							 const PreparationDiagnosticStage stage, const std::int32_t status,
							 const NativeError error, const bool bound = true) {
		   DiagnosticRecord record ;	// 元の文字列はcanonical Provider照合以外へ渡しません。
		   record.event		= DiagnosticEvent::PREPARATION_TARGET ;
		   record.operation = approval.operationId ;
		   // Applicationは既定tokenのまま保持し、他はcanonical registryだけを照合します。
		   if( provider != L"application") {
			   record.provider = DiagnosticProvider::fromId( provider) ;
		   }

		   record.status = status ;
		   record.error	 = error ;
		   record.add( DiagnosticField::ORDINAL, ordinal)
			   .add( DiagnosticField::STAGE, static_cast<std::uint64_t>( stage))
			   .add( DiagnosticField::BOUND, bound)
			   .add( DiagnosticField::CODE_KNOWN, error != 0) ;
		   return record ;
	} ; // 各固定段階の元codeを別recordへ保持します。
	// 元総数と投影省略数を一行へ保持します。
	auto summary = make( 0U, L"application", PreparationDiagnosticStage::SUMMARY, 0, 0) ;
	summary.add( DiagnosticField::TOTAL, approval.decisions.size())
		.add( DiagnosticField::SELECTED_COUNT, selected)
		.add( DiagnosticField::PROCESSED, std::min( selected, limit))
		.add( DiagnosticField::OMITTED, selected - std::min( selected, limit))
		.add( DiagnosticField::KNOWN, verifiedIndex != nullptr) ;
	emitDiagnostic( summary, sink) ;
	std::size_t emitted{} ;	// 元plan順の選択targetだけを数えます。
	// 非選択targetを取得失敗として記録せず、先頭16対象だけを投影します。
	for( std::size_t index{}; index < approval.decisions.size() && emitted < limit; ++index) {
		const auto &decision = approval.decisions[index] ;	// 元承認の同targetです。
		// 未選択の結果は操作summaryの全件数だけへ残します。
		if( !decision.acquire) {
			continue ;
		}

		++emitted ;
		const auto transfer =
			std::ranges::find( result.items, decision.target.identity,
							  &OfficialPreparationItem::identity) ;	// 文字列は内部結合だけです。
		const bool transferBound = transfer != result.items.end() &&
								   std::ranges::count( result.items, decision.target.identity,
													  &OfficialPreparationItem::identity) ==
									   1 ;	// 欠落や重複から原結果を補いません。
		// 取得の元状態と元codeを独立して記録します。
		auto acquired =
			make( index + 1U, decision.target.providerId, PreparationDiagnosticStage::TRANSFER,
				 transferBound ? static_cast<std::int32_t>( transfer->result.state) : -1,
				 transferBound ? transfer->result.error : 0, transferBound) ;
		acquired.add( DiagnosticField::RECEIVED_BYTES,
					 transferBound ? transfer->result.byteCount : 0U) ;
		emitDiagnostic( acquired, sink) ;
		const auto report = std::ranges::find(
			result.auditReports, decision.target.identity,
			&OfficialPreparationAuditReport::targetIdentity) ;	// 受理済みreportの同targetだけです。
		// 内容・適用性・候補発行を取得codeと独立した段階へ投影します。
		if( report != result.auditReports.end()) {
			// 内容段階の元状態と件数だけです。
			auto content =
				make( index + 1U, decision.target.providerId, PreparationDiagnosticStage::CONTENT,
					 static_cast<std::int32_t>( report->content), report->contentError) ;
			content.add( DiagnosticField::TOTAL, report->infCount)
				.add( DiagnosticField::PROCESSED, report->acceptedInfCount) ;
			emitDiagnostic( content, sink) ;
			emitDiagnostic( make( index + 1U, decision.target.providerId,
								PreparationDiagnosticStage::CONTENT_REJECTION,
								static_cast<std::int32_t>( report->content),
								report->firstContentRejection),
						   sink) ;
			// 元の全組合せ数と適用/未確認数です。
			auto applicability = make(
				index + 1U, decision.target.providerId, PreparationDiagnosticStage::APPLICABILITY,
				static_cast<std::int32_t>( report->applicability), report->applicabilityError) ;
			applicability.add( DiagnosticField::TOTAL, report->examinedPairCount)
				.add( DiagnosticField::PROCESSED, report->applicablePairCount)
				.add( DiagnosticField::UNAVAILABLE, report->failedPairCount) ;
			emitDiagnostic( applicability, sink) ;
			emitDiagnostic( make( index + 1U, decision.target.providerId,
								PreparationDiagnosticStage::PAIR_REJECTION,
								static_cast<std::int32_t>( report->applicability),
								report->firstPairError),
						   sink) ;
			// 候補発行と除外の元件数を保持します。
			auto publication = make( index + 1U, decision.target.providerId,
									PreparationDiagnosticStage::PUBLICATION,
									static_cast<std::int32_t>( report->publication.state),
									report->publication.firstError) ;
			publication.add( DiagnosticField::TOTAL, report->publication.examinedPairCount)
				.add( DiagnosticField::PROCESSED, report->publication.publishedCount)
				.add( DiagnosticField::REMAINING, report->publication.excludedPairCount)
				.add( DiagnosticField::BINDING_PATH, report->publication.bindingPath)
				.add( DiagnosticField::BINDING_REJECTION, report->publication.bindingRejection)
				.add( DiagnosticField::BINDING_OBSERVED, report->publication.bindingObserved)
				.add( DiagnosticField::BINDING_STAGE, report->publication.bindingStage)
				.add( DiagnosticField::BINDING_FLAGS, report->publication.bindingFlags)
				.add( DiagnosticField::DEPENDENCY_REASON, report->publication.dependencyReason)
				.add( DiagnosticField::ROOT_SIGNATURE_ERROR,
					 static_cast<std::uint32_t>( report->publication.rootSignatureError))
				.add( DiagnosticField::DEPENDENCY_SIGNATURE_ERROR,
					 static_cast<std::uint32_t>( report->publication.dependencySignatureError))
				.add( DiagnosticField::DEPENDENCY_PROVENANCE_ERROR,
					 static_cast<std::uint32_t>( report->publication.dependencyProvenanceError)) ;
			emitDiagnostic( publication, sink) ;
		}

		// 未検証summaryの内容はUI結合拒否の固定理由以外に出力しません。
		if( verifiedIndex == nullptr || verifiedIndex->operationId != approval.operationId ||
		   verifiedIndex->scanSessionId != approval.scanSessionId ||
		   verifiedIndex->planId != approval.planId) {
			continue ;
		}

		const auto item = std::ranges::find(
			verifiedIndex->items, decision.target.identity,
			&IndexPreparationItemSummary::targetIdentity) ;	// 全件照合済みsummaryだけです。
		// 当該targetの内容結果が無い場合も取得成功へ補いません。
		if( item == verifiedIndex->items.end()) {
			continue ;
		}

		// 内容段階の元状態と件数だけです。
		auto content =
			make( index + 1U, decision.target.providerId, PreparationDiagnosticStage::INDEX_CONTENT,
				 static_cast<std::int32_t>( item->content), item->contentError) ;
		content.add( DiagnosticField::TOTAL, item->infCount)
			.add( DiagnosticField::PROCESSED, item->acceptedInfCount)
			.add( DiagnosticField::PARSED_COUNT, item->parsedInfCount)
			.add( DiagnosticField::SIGNATURE_REJECTED_COUNT, item->signatureRejectedInfCount)
			.add( DiagnosticField::SUCCEEDED, item->inputBound) ;
		emitDiagnostic( content, sink) ;
		emitDiagnostic( make( index + 1U, decision.target.providerId,
							PreparationDiagnosticStage::INDEX_INF_REJECTION,
							static_cast<std::int32_t>( item->content), item->firstInfRejection),
					   sink) ;
		emitDiagnostic( make( index + 1U, decision.target.providerId,
							PreparationDiagnosticStage::INDEX_ACQUISITION,
							static_cast<std::int32_t>( item->acquisition), item->acquisitionError),
					   sink) ;
		// 補助要求の実観測だけでURLや本文を持ちません。
		auto http = make( index + 1U, decision.target.providerId,
						 PreparationDiagnosticStage::INDEX_HTTP, 0, 0) ;
		http.add( DiagnosticField::SENDS, item->auxiliaryHttp.requests)
			.add( DiagnosticField::RECEIVED_BYTES, item->auxiliaryHttp.bodyBytes)
			.add( DiagnosticField::HTTP_STATUS, item->auxiliaryHttp.httpStatus) ;
		emitDiagnostic( http, sink) ;
	}

	// 元意図のordinalと元区分だけを投影し、候補identityをserializeしません。
	for( std::size_t index{}; index < approval.installIntentIdentities.size() && index < limit;
		++index) {
		const bool present = index < result.installResolutions.size() ;	// 欠落をREADYにしません。
		DiagnosticRecord record ;										// UI拒否に存在しないHRESULTは作りません。
		record.event	 = DiagnosticEvent::PREPARATION_RESOLUTION ;
		record.operation = approval.operationId ;
		record.status =
			present ? static_cast<std::int32_t>( result.installResolutions[index].state) : -1 ;
		record.add( DiagnosticField::ORDINAL, index + 1U)
			.add( DiagnosticField::TOTAL, approval.installIntentIdentities.size())
			.add( DiagnosticField::OMITTED,
				 approval.installIntentIdentities.size() -
					 std::min( approval.installIntentIdentities.size(), limit))
			.add( DiagnosticField::BOUND,
				 present && result.installResolutions[index].originalIdentity ==
								approval.installIntentIdentities[index])
			.add( DiagnosticField::CODE_KNOWN, false) ;
		emitDiagnostic( record, sink) ;
	}
}

/** @see local_scan_diagnostics.h 宣言側の契約を正本とします。 */
void recordPreparationContinuationDiagnostics( const OperationId					  operation,
											  const PreparationContinuationReason reason,
											  const std::size_t					  intentCount,
											  const std::size_t					  readyCount,
											  LocalDiagnosticLog *const			  sink) noexcept
{
	DiagnosticRecord record ;	// UIの固定拒否理由であってWindowsのHRESULTではありません。
	record.event	 = DiagnosticEvent::PREPARATION_CONTINUATION ;
	record.operation = operation ;
	record.status	 = static_cast<std::int32_t>( reason) ;
	record.add( DiagnosticField::INTENT_COUNT, intentCount)
		.add( DiagnosticField::READY_COUNT, readyCount)
		.add( DiagnosticField::CODE_KNOWN, false) ;
	emitDiagnostic( record, sink) ;
}

/** @see local_scan_diagnostics.h 宣言側の契約を正本とします。 */
void recordInstallDiagnostics( const WorkerEvent &event, const ScanSessionId scanSession,
							  const std::span<const UpdateCandidate> candidates,
							  const std::int32_t					 applicationState,
							  LocalDiagnosticLog *const				 sink) noexcept
{
	const auto &result = event.installResult ;	// 受理済み原結果を変更しません。
	const auto	make   = [&event]( const DiagnosticEvent kind) {
		   DiagnosticRecord record ;	// operationだけを共有する固定recordです。
		   record.event		= kind ;
		   record.operation = event.operationId ;
		   return record ;
	} ;
	auto completed	 = make( DiagnosticEvent::OPERATION_COMPLETED) ;	// 元全体終端です。
	completed.status = applicationState ;
	completed.error	 = result.installError ;
	completed.add( DiagnosticField::SUCCEEDED, result.succeeded)
		.add( DiagnosticField::OUTCOME, static_cast<std::uint64_t>( result.installOutcome))
		.add( DiagnosticField::TOTAL, result.updates.size())
		.add( DiagnosticField::REBOOT_REQUIRED, result.rebootRequired) ;
	emitDiagnostic( completed, sink) ;
	const std::array protection{result.restorePointCreation,
								result.restorePointCompletion} ;	// 原保護事実です。
	// 開始と終了を導入結果とは別に記録します。
	for( std::size_t index{}; index < protection.size(); ++index) {
		auto record	  = make( DiagnosticEvent::INSTALL_PROTECTION) ;	// 元保護段階です。
		record.status = static_cast<std::int32_t>( protection[index].outcome) ;
		record.error  = protection[index].error ;
		record.add( DiagnosticField::STAGE, index)
			.add( DiagnosticField::ACTION, static_cast<std::uint64_t>( result.protectionMode)) ;
		emitDiagnostic( record, sink) ;
	}

	const auto &restoreObservation =
		result.restorePointProtection ;	// 原日付/番号を一般logへ出しません。
	// 実在保護の区分を固定enumと数値だけで記録します。
	if( restoreObservation.disposition != RestorePointDisposition::NATIVE_TRANSACTION) {
		auto record =
			make( DiagnosticEvent::
					 INSTALL_PROTECTION) ;	// 固定stageで作成/既存/日内reuse/未成立を区別します。
		record.status = static_cast<std::int32_t>( restoreObservation.verification) ;
		record.error  = restoreObservation.error ;
		record
			.add( DiagnosticField::STAGE,
				 2U + static_cast<std::uint64_t>( restoreObservation.disposition))
			.add( DiagnosticField::ACTION, static_cast<std::uint64_t>( result.protectionMode)) ;
		emitDiagnostic( record, sink) ;
	}

	// メモ診断をnative実行結果と別stageへ記録します。
	if( restoreObservation.memoError != 0) {
		auto warning =
			// 非致命的memo I/Oを別codeへ残します。
			make( DiagnosticEvent::INSTALL_PROTECTION) ;
		warning.status = static_cast<std::int32_t>( OutcomeCode::FAILURE) ;
		warning.error  = restoreObservation.memoError ;
		warning.add( DiagnosticField::STAGE, 7U)
			.add( DiagnosticField::ACTION, static_cast<std::uint64_t>( result.protectionMode)) ;
		emitDiagnostic( warning, sink) ;
	}

	// 個別ordinalは当該操作だけの連番です。
	for( std::size_t ordinal{}; ordinal < result.updates.size(); ++ordinal) {
		const auto &update	  = result.updates[ordinal] ;	// 元identityは結合にだけ使います。
		const auto	candidate = std::ranges::find( candidates, update.identity,
												  &UpdateCandidate::identity) ;	// 元候補です。
		const bool	bound =
			candidate != candidates.end() &&
			std::ranges::count( candidates, update.identity, &UpdateCandidate::identity) == 1 &&
			std::ranges::count( result.updates, update.identity, &UpdateExecutionResult::identity) ==
				1 ;											// 重複は未知です。
		auto item = make( DiagnosticEvent::INSTALL_ITEM) ;	// 数値だけの個別結果です。
		item.add( DiagnosticField::ORDINAL, ordinal + 1U)
			.add( DiagnosticField::BOUND, bound)
			.add( DiagnosticField::DOWNLOAD_OUTCOME,
				 static_cast<std::uint64_t>( update.downloadOutcome))
			.add( DiagnosticField::DOWNLOAD_ERROR, static_cast<std::uint32_t>( update.downloadError))
			.add( DiagnosticField::INSTALL_OUTCOME,
				 static_cast<std::uint64_t>( update.installOutcome))
			.add( DiagnosticField::INSTALL_ERROR, static_cast<std::uint32_t>( update.installError))
			.add( DiagnosticField::HANDOFF, update.installerHandoff)
			.add( DiagnosticField::HANDOFF_OUTCOME,
				 static_cast<std::uint64_t>( update.handoffOutcome))
			.add( DiagnosticField::HANDOFF_ERROR, static_cast<std::uint32_t>( update.handoffError))
			.add( DiagnosticField::REBOOT_REQUIRED, update.rebootRequired) ;
		// 元候補が一意な場合だけcanonical Provider/actionを使います。
		if( bound) {
			item.provider = DiagnosticProvider::fromId( candidate->providerId) ;
			item.add( DiagnosticField::ACTION, static_cast<std::uint64_t>( candidate->action)) ;
		}

		emitDiagnostic( item, sink) ;
		// 役割結果をbase成功や未開始から補完しません。
		for( const auto &role : update.requiredRoles) {
			auto record		= make( DiagnosticEvent::INSTALL_ROLE) ;	// 元roleの閉じた値です。
			record.provider = item.provider ;
			record.add( DiagnosticField::ORDINAL, ordinal + 1U)
				.add( DiagnosticField::PROCESSED, role.ordinal)
				.add( DiagnosticField::ACTION, static_cast<std::uint64_t>( role.role))
				.add( DiagnosticField::DOWNLOAD_OUTCOME,
					 static_cast<std::uint64_t>( role.stageOutcome))
				.add( DiagnosticField::DOWNLOAD_ERROR, static_cast<std::uint32_t>( role.stageError))
				.add( DiagnosticField::INSTALL_OUTCOME,
					 static_cast<std::uint64_t>( role.installOutcome))
				.add( DiagnosticField::INSTALL_ERROR, static_cast<std::uint32_t>( role.installError))
				.add( DiagnosticField::REFLECTION, static_cast<std::uint64_t>( role.reflection))
				.add( DiagnosticField::DIAGNOSTIC_MISSING, role.installDiagnosticMissing) ;
			emitDiagnostic( record, sink) ;
		}

		auto post	  = make( DiagnosticEvent::POST_INSTALL) ;	// 観測不能も明示する一記録です。
		post.provider = item.provider ;
		post.add( DiagnosticField::ORDINAL, ordinal + 1U) ;
		const PostInstallDeviceObservation *observed{} ;	// 同device一件だけを採用します。
		const UpdateCandidate			   *before{} ;		// 版比較用の一意な元現在行です。
		std::size_t observationCount{}, beforeCount{} ;		// 欠測と重複を分けます。
		// 未結合の結果から任意deviceを照会しません。
		if( bound) {
			// 返却DTOだけを読み、native再照会を追加しません。
			for( const auto &value : result.currentDevices) {
				// 生device値は一致照合だけです。
				if( value.observation.deviceIdentity == candidate->deviceIdentity) {
					observed = &value ;
					++observationCount ;
				}
			}

			// 元現在行の一意性も確認します。
			for( const auto &value : candidates) {
				// 異なるdeviceの版を使いません。
				if( value.current && value.deviceIdentity == candidate->deviceIdentity) {
					before = &value ;
					++beforeCount ;
				}
			}
		}

		const bool validPost =
			observationCount == 1U && observed && observed->error == 0 &&
			isDeviceObservationBound( observed->observation, scanSession,
									 candidate->deviceIdentity) ;	// 元scan結合です。
		post.add( DiagnosticField::TOTAL, observationCount).add( DiagnosticField::BOUND, validPost) ;
		// 一意な元観測のerrorだけを保持します。
		if( observationCount == 1U && observed) {
			post.error = observed->error ;
		}

		std::uint64_t requestedRelation{}, beforeRelation{} ;	// 0は未確認です。
		// 属性読取の実状態だけを出力します。
		if( validPost) {
			const auto &value = observed->observation ;	// 原文字列を出さない読取enumです。
			post.add( DiagnosticField::PRESENCE, static_cast<std::uint64_t>( value.driverPresence))
				.add( DiagnosticField::NODE_READ, static_cast<std::uint64_t>( value.node.read.state))
				.add( DiagnosticField::DRIVER_KEY_READ,
					 static_cast<std::uint64_t>( value.driverKey.state))
				.add( DiagnosticField::VERSION_READ, static_cast<std::uint64_t>( value.version.state))
				.add( DiagnosticField::PROBLEM_KNOWN, value.node.problemCode.has_value())
				.add( DiagnosticField::PROBLEM_CODE, value.node.problemCode.value_or( 0U)) ;
			const auto afterVersion = value.driverPresence == DeviceDriverPresence::REGISTERED &&
											  value.version.state == DevicePropertyReadState::VALUE
										  ? parseFourPartDriverVersion( observed->version)
										  : std::nullopt ;	// 比較可能な元Windows版だけです。
			const auto requestedVersion =
				candidate->installable ? parseFourPartDriverVersion( candidate->version)
									   : std::nullopt ;	// 取得前申告やreadonlyを補完しません。
			// 版のpacked値そのものは記録しません。
			if( afterVersion && requestedVersion) {
				requestedRelation = *afterVersion == *requestedVersion ? 1U : 2U ;
			}

			// 同scanの有効現在観測が一つの場合だけ前後比較します。
			if( afterVersion && beforeCount == 1U && before && before->deviceObservation &&
			   isDeviceObservationBound( *before->deviceObservation, scanSession,
										candidate->deviceIdentity) &&
			   before->deviceObservation->driverPresence == DeviceDriverPresence::REGISTERED &&
			   before->deviceObservation->version.state == DevicePropertyReadState::VALUE) {
				const auto beforeVersion =
					// 診断だけの局所比較です。
					parseFourPartDriverVersion( before->version) ;
				// 不明版を変化なしへ換算しません。
				if( beforeVersion) {
					beforeRelation = *afterVersion == *beforeVersion ? 1U : 2U ;
				}
			}
		}

		post.add( DiagnosticField::REQUEST_VERSION_RELATION, requestedRelation)
			.add( DiagnosticField::BEFORE_VERSION_RELATION, beforeRelation) ;
		emitDiagnostic( post, sink) ;
	}
}

/** @see local_scan_diagnostics.h 宣言側の契約を正本とします。 */
void recordScanDiagnostics( const WorkerEvent &event, const std::int32_t applicationState,
						   const bool measurementAccepted, LocalDiagnosticLog *const sink) noexcept
{
	const auto emit = [sink]( const DiagnosticRecord &record) noexcept {
		// 内部file試験のsinkも製品と同じ保存処理を使います。
		if( sink) {
			sink->append( record) ;
		} else {
			recordLocalDiagnostic( record) ;
		}
	} ; // 数値recordだけの同期投影です。
	const auto make = [&event]( const DiagnosticEvent kind) {
		DiagnosticRecord record ;	// 型付き固定容量だけです。
		record.event	 = kind ;
		record.operation = event.operationId ;
		return record ;
	} ; // 元operationの連番を全行へ結合します。
	DiagnosticRecord completed = make( DiagnosticEvent::SCAN_COMPLETED) ;	// Scanの元終端です。
	completed.status		   = applicationState ;
	completed.error			   = event.scanResult.error ;
	completed.add( DiagnosticField::SUCCEEDED, event.scanResult.succeeded)
		.add( DiagnosticField::OUTCOME, static_cast<std::uint64_t>( event.scanResult.outcome))
		.add( DiagnosticField::TOTAL, event.scanResult.candidates.size())
		.add( DiagnosticField::MEASUREMENT_ACCEPTED, measurementAccepted) ;
	emit( completed) ;
	// Provider報告の表示名・本文を使わずcanonical stable IDへ限定します。
	for( const auto &report : event.scanResult.providerReports) {
		auto record		= make( DiagnosticEvent::PROVIDER_SCAN) ;	// 元Providerの確定数だけです。
		record.provider = DiagnosticProvider::fromId( report.descriptor.id) ;
		record.status	= static_cast<std::int32_t>( report.state) ;
		record.error	= report.error ;
		record.add( DiagnosticField::OUTCOME, static_cast<std::uint64_t>( report.outcome))
			.add( DiagnosticField::TOTAL, report.candidateCount)
			.add( DiagnosticField::ELIGIBLE, report.coverage.eligibleDeviceCount)
			.add( DiagnosticField::ASSESSED, report.coverage.assessedDeviceCount) ;
		emit( record) ;
	}

	const auto provider =
		// 固定の共通索引Providerです。
		DiagnosticProvider::fromId( SIGNED_INDEX_PROVIDER_ID) ;
	const auto &summary = event.indexSummary ;						// 文字列を持たない元summaryです。
	auto		refresh = make( DiagnosticEvent::INDEX_REFRESH) ;	// 未実行とHTTP拒否を分けます。
	refresh.provider	= provider ;
	refresh.add( DiagnosticField::KNOWN, summary.refresh.has_value()) ;
	// 未実行をHTTP成功や世代0へ補いません。
	if( summary.refresh) {
		const auto &source = *summary.refresh ;	// 元codec/HTTP数値だけです。
		refresh.status	   = static_cast<std::int32_t>( source.status) ;
		refresh.error	   = source.error ;
		refresh.add( DiagnosticField::HTTP_STATUS, source.httpStatus)
			.add( DiagnosticField::HTTP_ERROR, static_cast<std::uint32_t>( source.httpError))
			.add( DiagnosticField::SENDS, source.sends)
			.add( DiagnosticField::RECEIVED_BYTES, source.receivedBytes)
			.add( DiagnosticField::GENERATION_KNOWN, source.attemptedGeneration.has_value())
			.add( DiagnosticField::USED_CACHE, source.usedAuthenticatedCache) ;
		// Optional診断の不在をcodec成功値へ補いません。
		if( source.attemptedGeneration) {
			refresh.add( DiagnosticField::ATTEMPTED_GENERATION, *source.attemptedGeneration) ;
		}

		// 元manifest診断を観測したときだけ記録します。
		if( source.manifestStatus) {
			refresh.add( DiagnosticField::MANIFEST_STATUS,
						static_cast<std::uint64_t>( *source.manifestStatus)) ;
		}

		// 元gzip診断を観測したときだけ記録します。
		if( source.assetStatus) {
			refresh.add( DiagnosticField::ASSET_STATUS,
						static_cast<std::uint64_t>( *source.assetStatus)) ;
		}

		// 元record診断を観測したときだけ記録します。
		if( source.recordsStatus) {
			refresh.add( DiagnosticField::RECORDS_STATUS,
						static_cast<std::uint64_t>( *source.recordsStatus)) ;
		}

		auto stored		= make( DiagnosticEvent::INDEX_STORE) ;	// 認証取得と保存を分けます。
		stored.provider = provider ;
		stored.status	= static_cast<std::int32_t>( source.store.status) ;
		stored.error	= source.store.error ;
		stored.add( DiagnosticField::GENERATION_KNOWN, source.store.persistedGeneration.has_value())
			.add( DiagnosticField::COMMIT, static_cast<std::uint64_t>( source.store.commit))
			.add( DiagnosticField::USABLE_SNAPSHOT, source.store.usableSnapshot)
			.add( DiagnosticField::USED_CACHE, source.usedAuthenticatedCache) ;
		// 元高水位を観測したときだけ値を添えます。
		if( source.store.persistedGeneration) {
			stored.add( DiagnosticField::PERSISTED_GENERATION, *source.store.persistedGeneration) ;
		}

		// 再認証cache観測は元refreshの成否と分けます。
		if( source.cache) {
			stored.add( DiagnosticField::CACHE_GENERATION_KNOWN,
					   source.cache->persistedGeneration.has_value()) ;
			// Cacheの世代不明を0へ補いません。
			if( source.cache->persistedGeneration) {
				stored.add( DiagnosticField::CACHE_GENERATION, *source.cache->persistedGeneration) ;
			}
		}

		emit( stored) ;
	}

	emit( refresh) ;
	auto scan	  = make( DiagnosticEvent::INDEX_SCAN) ;	// ID関係は適用候補数ではありません。
	scan.provider = provider ;
	scan.status	  = static_cast<std::int32_t>( summary.status) ;
	scan.error	  = summary.error ;
	scan.add( DiagnosticField::TOTAL, summary.totalRecords)
		.add( DiagnosticField::PROCESSED, summary.processedRecords)
		.add( DiagnosticField::REMAINING, summary.remainingRecords)
		.add( DiagnosticField::RELATIONS, summary.relationCount)
		.add( DiagnosticField::RELATED_DEVICES, summary.relatedDeviceCount)
		.add( DiagnosticField::MATCHED, summary.matchedRelations)
		.add( DiagnosticField::NON_UNIQUE, summary.nonUniqueRelations)
		.add( DiagnosticField::UNDETERMINED, summary.undeterminedRelations)
		.add( DiagnosticField::PARTIAL_POSITIVE, summary.verifiedPartialRelations)
		.add( DiagnosticField::RESOLVER_CALLS, summary.resolverCalls) ;
	// 未観測のoptional区分を既定成功へ変換しません。
	if( summary.storeStatus) {
		scan.add( DiagnosticField::STORE_STATUS, static_cast<std::uint64_t>( *summary.storeStatus)) ;
	}

	// 未着手lookupを成功区分へ補いません。
	if( summary.lookupStatus) {
		scan.add( DiagnosticField::LOOKUP_STATUS, static_cast<std::uint64_t>( *summary.lookupStatus)) ;
	}

	emit( scan) ;
	auto plan  = make( DiagnosticEvent::PREPARATION_PLAN) ;	// Object有無と実targetは独立です。
	plan.error = event.preparationError ;
	plan.add( DiagnosticField::PLAN_PRESENT, event.preparationPlan.has_value())
		.add( DiagnosticField::TARGETS,
			 event.preparationPlan ? event.preparationPlan->targets.size() : 0U)
		.add( DiagnosticField::INDEX_TARGETS, event.indexPreparation.plannedTargets)
		.add( DiagnosticField::UNAVAILABLE, event.indexPreparation.unavailableRelations)
		.add( DiagnosticField::CAPACITY_REJECTED, event.indexPreparation.capacityRejectedRelations) ;
	emit( plan) ;
	auto authority	   = make( DiagnosticEvent::INDEX_LOOKUP) ;	// OS不明等の元取得準備拒否です。
	authority.provider = provider ;
	authority.error	   = event.indexPreparation.authorityError ;
	authority.add( DiagnosticField::INDEX_TARGETS, event.indexPreparation.plannedTargets) ;
	emit( authority) ;

	std::uint64_t current{} ;					// 現在観測行の件数です。
	std::uint64_t installable{} ;				// 元flagだけの件数です。
	std::uint64_t references{} ;				// 非installableの実target付き参照数です。
	std::uint64_t updates{} ;					// 元分類だけの件数です。
	std::uint64_t reinstalls{} ;				// 同版または再導入分類です。
	std::uint64_t downgrades{} ;				// 旧版分類です。
	std::uint64_t initials{} ;					// 検証済み初回分類です。
	std::uint64_t pending{} ;					// 適用性未確認です。
	std::uint64_t rejected{} ;					// 適用性拒否です。
	std::uint64_t osRejected{} ;				// 明示OS不一致理由だけです。
	std::uint64_t registeredReferences{} ;		// 登録driver観測と結合する取得前参照です。
	std::uint64_t unknownReferences{} ;			// 現在の登録状態を確認できない取得前参照です。
	std::array<std::uint64_t, 4U> versions{} ;	// 閉じたUNKNOWN/NEWER/SAME/OLDER件数だけです。
	// 文字列の版比較やID出力をせず、既存enumだけを数えます。
	for( const auto &candidate : event.scanResult.candidates) {
		current += candidate.current ;
		installable += candidate.installable ;
		references += !candidate.current && !candidate.installable &&
					  !candidate.preparationTargetIdentity.empty() ;
		updates += !candidate.current && candidate.action == DriverAction::UPDATE ;
		reinstalls += !candidate.current && candidate.action == DriverAction::REINSTALL ;
		downgrades += !candidate.current && candidate.action == DriverAction::DOWNGRADE ;
		initials += !candidate.current && candidate.action == DriverAction::INITIAL_INSTALL ;
		pending += !candidate.current &&
				   candidate.audit.systemApplicability == CandidateAuditGateState::PENDING ;
		rejected += !candidate.current &&
					candidate.audit.systemApplicability == CandidateAuditGateState::REJECTED ;
		osRejected += candidate.assessment && candidate.assessment->applicability.reason ==
												  CandidateAssessmentReason::OS_MISMATCH ;
		// 取得前参照についてだけ現在観測を匿名集計し、版や名前から未導入を推定しません。
		if( !candidate.current && !candidate.installable &&
		   !candidate.preparationTargetIdentity.empty()) {
			++versions[static_cast<std::size_t>( classifyPendingReferenceVersion(
				candidate, event.scanResult.candidates, event.scanResult.scanSessionId))] ;
			const UpdateCandidate *observed{} ;		// 一意な現在観測だけを借用します。
			bool				   ambiguous{} ;	// 矛盾する複数現在行から選びません。
			// 元opaque deviceの現在行を同期中だけ比較します。外部へ保存しません。
			for( const auto &currentCandidate : event.scanResult.candidates) {
				// 他deviceや非現在行を登録状態の根拠にしません。
				if( currentCandidate.current &&
				   currentCandidate.deviceIdentity == candidate.deviceIdentity) {
					ambiguous = observed != nullptr ;
					observed  = &currentCandidate ;
					// 複数現在行の一つだけを都合よく選びません。
					if( ambiguous) {
						break ;
					}
				}
			}

			const bool known = !ambiguous && observed && observed->deviceObservation &&
							   isDeviceObservationBound(
								   *observed->deviceObservation, event.scanResult.scanSessionId,
								   candidate.deviceIdentity) ;	// 元観測の結合だけです。
			registeredReferences += known && observed->deviceObservation->driverPresence ==
												 DeviceDriverPresence::REGISTERED ;
			unknownReferences += !known || observed->deviceObservation->driverPresence ==
											   DeviceDriverPresence::UNKNOWN ;
		}
	}

	auto reasons = make( DiagnosticEvent::CANDIDATE_REASONS) ;	// 固定分類の重なりは独立件数です。
	reasons.add( DiagnosticField::CURRENT, current)
		.add( DiagnosticField::INSTALLABLE, installable)
		.add( DiagnosticField::PENDING_REFERENCES, references)
		.add( DiagnosticField::UPDATES, updates)
		.add( DiagnosticField::REINSTALLS, reinstalls)
		.add( DiagnosticField::DOWNGRADES, downgrades)
		.add( DiagnosticField::INITIAL_INSTALLS, initials)
		.add( DiagnosticField::APPLICABILITY_PENDING, pending)
		.add( DiagnosticField::APPLICABILITY_REJECTED, rejected)
		.add( DiagnosticField::OS_REJECTED, osRejected)
		.add( DiagnosticField::REGISTERED_REFERENCES, registeredReferences)
		.add( DiagnosticField::UNKNOWN_PRESENCE_REFERENCES, unknownReferences) ;
	reasons
		.add( DiagnosticField::NEWER_REFERENCES,
			 versions[static_cast<std::size_t>( PendingReferenceVersion::NEWER)])
		.add( DiagnosticField::SAME_REFERENCES,
			 versions[static_cast<std::size_t>( PendingReferenceVersion::SAME)])
		.add( DiagnosticField::OLDER_REFERENCES,
			 versions[static_cast<std::size_t>( PendingReferenceVersion::OLDER)])
		.add( DiagnosticField::UNKNOWN_VERSION_REFERENCES,
			 versions[static_cast<std::size_t>( PendingReferenceVersion::UNKNOWN)]) ;
	emit( reasons) ;
}
}
