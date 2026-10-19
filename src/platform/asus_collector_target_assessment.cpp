//------------------------------------------------------------------------------
/**
 * @file asus_collector_target_assessment.cpp
 * @brief 同一ASUS本文の一時候補と公開対象を三状態で照合します。
 * @version 01.02.00
 * @date 2026/09/28
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  公開target三状態と複数候補番号の純粋照合を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/28  同一controlの対象／候補照合と型付き終了を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/28  元表記record keyと正規化model keyの帰属を修正。
 * </pre>
 *
 * @note 本文所有worker内でだけ候補を参照します。GET出典・配布許可は発行しません。
 * @see docs/adr/0221-collector-official-product-identity.md
 */
//------------------------------------------------------------------------------

#include "platform/asus_collector_target_assessment.h"
#include "platform/official_collector_public_text.h"

#include <algorithm>
#include <cstddef>
#include <new>
#include <utility>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

/**
 * @brief 一つの公開target fieldの上限と秘密形状を確認します。
 * @param[in] value 公開対象のfield。
 * @param[in] maximumCharacters UTF-16単位の上限。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] allowEmpty chipだけ空を許す場合true。
 * @return 対象条件として有効ならtrue。
 */
[[nodiscard]] bool validQueryText( CollectorParserContext *control, const std::wstring_view value,
								  const std::size_t maximumCharacters,
								  const bool		allowEmpty = false)
{
	collectorParserCheckpoint( control) ;
	return value.size() <= maximumCharacters && (allowEmpty || !value.empty()) &&
		   (control != nullptr ? isOfficialCollectorPublicTextForCollector(
									 value, 1'024U, OfficialCollectorPublicTextKind::TEXT, *control)
							   : isOfficialCollectorPublicText( value, 1'024U)) ;
}

/**
 * @brief 公開対象の全fieldを個別に確認します。
 * @param[in] query 一つの借用対象。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] modelKey 成立時の製品比較key。
 * @return 有限公開値だけならtrue。
 */
[[nodiscard]] bool validQuery( CollectorParserContext		 *control,
							  const AsusCollectorTargetQuery &query, std::wstring &modelKey)
{
	collectorParserCheckpoint( control) ;
	modelKey = asusCollectorModelComparisonKey( query.model) ;
	return validQueryText( control, query.targetKey, 128U) &&
		   validQueryText( control, query.maker, 128U) && !modelKey.empty() &&
		   validQueryText( control, query.kind, 64U) &&
		   validQueryText( control, query.purpose, 64U) &&
		   validQueryText( control, query.operatingSystem, 64U) &&
		   validQueryText( control, query.architecture, 32U) &&
		   validQueryText( control, query.chip, 128U, true) ;
}

/**
 * @brief 公開pageの製品identityだけを独立に確認します。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] page 解析済みの一本文。
 * @return 比較可能なLAN製品identityがある場合true。
 */
[[nodiscard]] bool validPageIdentity( CollectorParserContext		   *control,
									 const AsusCollectorPageResult &page)
{
	collectorParserCheckpoint( control) ;
	// 元parserが拒否した構造や製品fieldを再解釈しません。
	if( !page.structurallyValid || page.category != L"LAN" || page.pageModel.empty() ||
	   page.productId.empty() || page.productId.size() > 16U || page.modelComparisonKey.empty() ||
	   page.modelComparisonKey != asusCollectorModelComparisonKey( page.pageModel)) {
		return false ;
	}

	// 架空のIDを公開製品識別として使用しません。
	for( const wchar_t ch : page.productId) {
		collectorParserStep( control) ;
		// Parserと同じ十進文字集合だけを要求します。
		if( ch < L'0' || ch > L'9') {
			return false ;
		}
	}

	const std::wstring_view maximumId = L"9007199254740991" ;	// JSON Numberの整数精度上限。
	return page.productId != L"0" &&
		   (page.productId.size() == 1U || page.productId.front() != L'0') &&
		   (page.productId.size() < maximumId.size() ||
			(page.productId.size() == maximumId.size() && page.productId <= maximumId)) ;
}

/**
 * @brief 候補集合と採用行の順序・所有値が同じであることを確認します。
 * @param[in] page 同一storeで採用した行。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] candidates その行から構築した一時record。
 * @return 候補が空、または全行一対一で結合した場合true。
 */
[[nodiscard]] bool boundCandidates(
	CollectorParserContext *control, const AsusCollectorPageResult &page,
	const std::span<const OfficialCollectorRecordCandidate> candidates)
{
	collectorParserCheckpoint( control) ;
	// 解析のみの段階は候補欠測として扱います。
	if( candidates.empty()) {
		return true ;
	}

	// 候補の部分集合を黙って受理しません。
	if( !validPageIdentity( control, page) || !page.targetModelMatches || page.osId.empty() ||
	   (page.sliceStatus != AsusCollectorSliceStatus::ACCEPTED &&
		page.sliceStatus != AsusCollectorSliceStatus::PARTIAL_REJECTED) ||
	   candidates.size() > 16U || candidates.size() != page.entries.size()) {
		return false ;
	}

	// 各ordinalが元pageの同じ行へ戻ることを確かめます。
	for( std::size_t index = 0U; index < candidates.size(); ++index) {
		collectorParserStep( control) ;
		const auto		  &candidate = candidates[index] ;		// 今回の一時record。
		const auto		  &entry	 = page.entries[index] ;	// 元parserの採用行。
		const std::wstring suffix	 = L"|" + entry.opaqueId ;	// 元record keyの固定末尾。
		// Keyの元model表記は保持し、比較時だけpageと同じ規則へ揃えます。
		if( !candidate.recordKey.ends_with( suffix) || candidate.recordKey.size() <= suffix.size() ||
		   asusCollectorModelComparisonKey(
			   std::wstring_view( candidate.recordKey)
				   .substr( 0U, candidate.recordKey.size() - suffix.size())) !=
			   page.modelComparisonKey) {
			return false ;
		}

		collectorParserCheckpoint( control) ;
		// 秘密URLを出力へ複写せず、worker内でだけ一意の帰属を照合します。
		if( candidate.recordEvidenceId != index + 1U ||
		   candidate.parserId != L"asus-catalog-record-v1" ||
		   candidate.recordRoute != L"asus-support-catalog-zip" ||
		   candidate.productFamily != entry.title || candidate.driverCategory != L"LAN" ||
		   candidate.operatingSystem != page.osName || candidate.packageVersion != entry.version ||
		   candidate.publishedDate != entry.releaseDate || candidate.payloads.size() != 1U ||
		   candidate.payloads[0].publishedSha256 != entry.sha256 ||
		   candidate.payloads[0].targetUrl.view() != entry.downloadUrl) {
			return false ;
		}
	}

	return true ;
}

/**
 * @brief 最初に判明した同状態の理由を上書きしません。
 * @param[in,out] first 先着の理由。初期MATCHEDは未設定を表します。
 * @param[in] next 現在の軸の理由。
 */
void rememberFirst( AsusCollectorTargetReason &first, const AsusCollectorTargetReason next) noexcept
{
	// 診断を後の軸で上書きしません。
	if( first == AsusCollectorTargetReason::MATCHED) {
		first = next ;
	}
}

/**
 * @brief 一対象の軸をすべて評価し、明示矛盾を未知より優先します。
 * @param[in] query 公開対象。
 * @param[in] modelKey ASUS比較規則の製品名。
 * @param[in] page 同一storeの公開identity。
 * @param[in] hasCandidates 一件以上の結合済み候補がある場合true。
 * @param[in,out] result 出力状態と第一理由。
 */
void assessTarget( const AsusCollectorTargetQuery &query, const std::wstring_view modelKey,
				  const AsusCollectorPageResult &page, const bool hasCandidates,
				  AsusCollectorTargetAssessment &result) noexcept
{
	AsusCollectorTargetReason conflict = AsusCollectorTargetReason::MATCHED ;	// 第一明示矛盾。
	AsusCollectorTargetReason unknown  = AsusCollectorTargetReason::MATCHED ;	// 第一未知軸。
	// 公開boardと対象maker／種別／modelを同じ製品軸で比較します。
	if( query.maker != L"ASUS" || query.kind != L"MAINBOARD" ||
	   modelKey != page.modelComparisonKey) {
		rememberFirst( conflict, AsusCollectorTargetReason::PRODUCT_CONFLICT) ;
	}

	// 配布title中のcomponentメーカー名は製品makerの照合へ使用しません。
	if( query.purpose != L"LAN") {
		// 明示別driver分類だけを矛盾にします。
		if( query.purpose == L"Wi-Fi" || query.purpose == L"Bluetooth" ||
		   query.purpose == L"Audio") {
			rememberFirst( conflict, AsusCollectorTargetReason::PURPOSE_CONFLICT) ;
		} else {
			rememberFirst( unknown, AsusCollectorTargetReason::PURPOSE_UNKNOWN) ;
		}
	}

	// OS IDが未解決なら元要求文字列だけで矛盾を発行しません。
	if( page.osId.empty()) {
		rememberFirst( unknown, AsusCollectorTargetReason::OS_UNKNOWN) ;
	}
	// 解決済みのOS IDだけで対象の別名を比較します。
	else if( query.operatingSystem != page.osName) {
		// 公開された別Windows名だけを明示矛盾にします。
		if( query.operatingSystem == L"Windows 10 64-bit" ||
		   query.operatingSystem == L"Windows Server 2025") {
			rememberFirst( conflict, AsusCollectorTargetReason::OS_CONFLICT) ;
		} else {
			rememberFirst( unknown, AsusCollectorTargetReason::OS_UNKNOWN) ;
		}
	}

	// x64以外の既知architectureを同一LAN配布へ結びません。
	if( query.architecture != L"x64") {
		// 未知architectureから不適合を推測しません。
		if( query.architecture == L"x86" || query.architecture == L"arm64") {
			rememberFirst( conflict, AsusCollectorTargetReason::ARCHITECTURE_CONFLICT) ;
		} else {
			rememberFirst( unknown, AsusCollectorTargetReason::ARCHITECTURE_UNKNOWN) ;
		}
	}

	// 明示chipに対応する構造化根拠は本pageにありません。
	if( !query.chip.empty()) {
		rememberFirst( unknown, AsusCollectorTargetReason::CHIP_UNKNOWN) ;
	}

	// Sourceの明示矛盾を未知または候補欠測より優先します。
	if( conflict != AsusCollectorTargetReason::MATCHED) {
		result.state  = AsusCollectorTargetState::NO_MATCH ;
		result.reason = conflict ;
	}
	// 矛盾がない場合だけ最初の未知を残します。
	else if( unknown != AsusCollectorTargetReason::MATCHED) {
		result.state  = AsusCollectorTargetState::UNKNOWN ;
		result.reason = unknown ;
	}
	// 対象一致だけで配布候補の存在を補いません。
	else if( !hasCandidates) {
		result.state  = AsusCollectorTargetState::UNKNOWN ;
		result.reason = AsusCollectorTargetReason::RECORD_UNKNOWN ;
	} else {
		result.state  = AsusCollectorTargetState::MATCH ;
		result.reason = AsusCollectorTargetReason::MATCHED ;
	}
}

} // namespace

//------------------------------------------------------------------------------
// 公開関数定義。
//------------------------------------------------------------------------------

/**
 * @brief 旧入口と制御付き入口の共通coreです。
 * @param[in,out] control 新経路の制御。旧入口だけnull。
 * @param[in] page 同一本文のpage。
 * @param[in] candidates 同じpageの全候補。
 * @param[in] targets 全対象。
 * @param[out] assessments 全成立後だけ公開する値。
 * @return 集合契約が成立すればtrue。
 */
static bool inspectAsusCollectorTargetsCore(
	CollectorParserContext *control, const AsusCollectorPageResult &page,
	const std::span<const OfficialCollectorRecordCandidate> candidates,
	const std::span<const AsusCollectorTargetQuery>			targets,
	std::vector<AsusCollectorTargetAssessment>			   &assessments)
{
	collectorParserCheckpoint( control) ;
	assessments.clear() ;
	// 予算外や重複keyを部分結果へ変換しません。
	// 入力分母の上限を構造拒否と区別します。
	if( targets.size() > 300U || candidates.size() > 16U) {
		collectorParserLimit( control) ;
	}

	// 空集合や旧経路の過大集合も部分結果へ変換しません。
	if( targets.empty() || targets.size() > 300U || candidates.size() > 16U) {
		return false ;
	}

	// 全体入力である公開keyだけは一対象のUNKNOWNとして保持しません。
	for( std::size_t index = 0U; index < targets.size(); ++index) {
		collectorParserStep( control) ;
		// Keyは一意かつ有限である必要があります。
		if( !validQueryText( control, targets[index].targetKey, 128U)) {
			return false ;
		}

		// 最大300件を元順序で有限照合します。
		for( std::size_t prior = 0U; prior < index; ++prior) {
			collectorParserStep( control) ;
			// 同じ公開keyのedgeを二重生成しません。
			if( targets[index].targetKey == targets[prior].targetKey) {
				return false ;
			}
		}
	}

	try {
		const bool sourceValid = validPageIdentity( control, page) ;	// 検証済みの製品軸。
		// 候補があるのに元行へ帰属しない場合は全体拒否します。
		if( !boundCandidates( control, page, candidates)) {
			return false ;
		}

		std::vector<AsusCollectorTargetAssessment> pending ;	// 全件後の一括出力。
		pending.reserve( targets.size()) ;
		// 一本文内の対象分母と元順序をそのまま保持します。
		for( const auto &query : targets) {
			collectorParserCheckpoint( control) ;
			AsusCollectorTargetAssessment target ;	// 一対象の所有結果。
			target.targetKey = query.targetKey ;
			std::wstring modelKey ;	// Target公開名の比較key。
			// 破損query／sourceから不適合を発行しません。
			if( !validQuery( control, query, modelKey)) {
				target.reason = AsusCollectorTargetReason::INVALID_QUERY ;
			}
			// 破損pageから明示矛盾を作りません。
			else if( !sourceValid) {
				target.reason = AsusCollectorTargetReason::SOURCE_UNKNOWN ;
			} else {
				target.productId	   = page.productId ;
				target.displayModel	   = page.pageModel ;
				target.comparisonModel = page.modelComparisonKey ;
				// 複数候補を一件へ縮退させず、各indexを保持します。
				for( std::size_t index = 0U; index < candidates.size(); ++index) {
					collectorParserStep( control) ;
					target.candidateOrdinals.push_back( static_cast<std::uint32_t>( index)) ;
				}

				assessTarget( query, modelKey, page, !candidates.empty(), target) ;
			}

			pending.push_back( std::move( target)) ;
			collectorParserCheckpoint( control) ;
		}

		assessments = std::move( pending) ;
		return true ;
	} catch( const std::bad_alloc &) {
		// 新経路ではOOMを入力拒否へ変換しません。
		if( control != nullptr) {
			throw ;
		}

		assessments.clear() ;
		return false ;
	}
}

/** @see asus_collector_target_assessment.h */
bool inspectAsusCollectorTargets( const AsusCollectorPageResult					  &page,
								 std::span<const OfficialCollectorRecordCandidate> candidates,
								 std::span<const AsusCollectorTargetQuery>		   targets,
								 std::vector<AsusCollectorTargetAssessment>		  &assessments)
{
	return inspectAsusCollectorTargetsCore( nullptr, page, candidates, targets, assessments) ;
}

/** @see asus_collector_target_assessment.h */
CollectorParserResult inspectAsusCollectorTargetsControlled(
	const AsusCollectorPageResult					 &page,
	std::span<const OfficialCollectorRecordCandidate> candidates,
	std::span<const AsusCollectorTargetQuery> targets, OfficialCollectorHttpControl &control,
	std::vector<AsusCollectorTargetAssessment> &assessments)
{
	assessments.clear() ;
	std::vector<AsusCollectorTargetAssessment> parsed ;	// 途中結果の持出しを防ぐ所有値。
	const auto								   outcome = runCollectorParser(
		control,
		[&]( CollectorParserContext &context) {
			return inspectAsusCollectorTargetsCore( &context, page, candidates, targets, parsed) ;
		},
		CollectorIoStage::PROJECT) ;	// 元GETの制御で射影段階を確認します。
	// 終端確認後だけ一括移動します。
	if( outcome.status == CollectorParserStatus::COMPLETED) {
		assessments = std::move( parsed) ;
	}

	return outcome ;
}
} // namespace drivercrate
