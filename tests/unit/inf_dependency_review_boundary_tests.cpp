//------------------------------------------------------------------------------
/**
 * @file inf_dependency_review_boundary_tests.cpp
 * @brief 架空INFの全証拠組合せと確認計画の非実行境界を検証する。
 * @version 01.00.00
 * @date 2026/10/06
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  全証拠組合せ・差替え・計画非昇格の独立試験を追加。
 * </pre>
 *
 * @note 架空tableだけを同期借用する。実file・network・署名・device・導入APIを呼ばない。
 * @see docs/adr/0281-inf-dependency-review-boundary-verification.md
 */
//------------------------------------------------------------------------------

#include "platform/inf_dependency_plan.h"
#include "core/official_preparation.h"
#include "core/update_types.h"
#include "test_framework.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace drivercrate::test {
namespace {

// 確認用計画を製品候補・取得準備・導入結果として暗黙または直接構築させない。
static_assert( !std::is_convertible_v<InfDependencyReviewPlan, UpdateCandidate>) ;
static_assert( !std::is_constructible_v<UpdateCandidate, InfDependencyReviewPlan>) ;
static_assert( !std::is_convertible_v<InfDependencyReviewPlan, OfficialPreparationPlan>) ;
static_assert( !std::is_constructible_v<OfficialPreparationPlan, InfDependencyReviewPlan>) ;
static_assert( !std::is_convertible_v<InfDependencyResult, InstallResult>) ;
static_assert( !std::is_constructible_v<InstallResult, InfDependencyResult>) ;

constexpr std::array  EVIDENCE_STATES{InfDependencyEvidence::NOT_CHECKED,
									  InfDependencyEvidence::VERIFIED,
									  InfDependencyEvidence::FAILED} ;	// 独立三状態の全列挙。

/** @brief 架空の一documentを生成する。
 * @param[in] identity この試験内の非零identity。
 * @param[in] origin 架空の配布境界。
 * @return 三証拠を確認済みにした架空snapshot。実証拠ではない。
 */
InfDependencyDocument makeDocument( std::uint64_t identity, InfDependencyOrigin origin)
{
	return {identity,
			std::wstring( 64U, L'a'),
			123U,
			origin,
			InfDependencyEvidence::VERIFIED,
			InfDependencyEvidence::VERIFIED,
			InfDependencyEvidence::VERIFIED,
			{10U, 0U, 26100U, 0x8664U, false, 17U}} ;
}

/** @brief 架空の一明示節の応答。 */
struct ReviewSection {
	/// 元documentのidentity。
	std::uint64_t		 identity{} ;
	/// 明示された架空節名。
	std::wstring		 name ;
	/// 当該節の有限な応答。
	InfDependencySection value ;
} ;

/** @brief 架空の一Include照会の応答。 */
struct ReviewLookup {
	/// 元documentのidentity。
	std::uint64_t		identity{} ;
	/// 架空の相対INF名。
	std::wstring		name ;
	/// 照会完了と有限候補を独立して保持する応答。
	InfDependencyLookup value ;
} ;

/** @brief 有限の架空名をWindows ordinal規則で比較する。
 * @param[in] left 架空の一明示名。
 * @param[in] right 架空の一明示名。
 * @return 大小文字を除いて一致すればtrue。
 */
bool sameFixtureName( std::wstring_view left, std::wstring_view right)
{
	return CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

/** @brief 同期runだけの架空tableとcallback観測を所有する。 */
struct ReviewFixture {
	/// 架空の基本driver。
	InfDependencyDocument	   root{makeDocument( 1U, InfDependencyOrigin::PACKAGE)} ;
	/// 元節と一参照節の架空table。
	std::vector<ReviewSection> sections{{1U,
										 L"Install",
										 {InfDependencyReadState::PRESENT,
										  {{InfDependencyDirective::INCLUDE, L"child.inf"},
										   {InfDependencyDirective::NEEDS, L"Shared"}}}},
										{2U, L"Shared", {InfDependencyReadState::PRESENT, {}}}} ;
	/// 一参照先の架空table。
	std::vector<ReviewLookup>  lookups{
		 {1U, L"child.inf", {true, {makeDocument( 2U, InfDependencyOrigin::SYSTEM)}}}} ;
	/// lookupの呼出し数。
	std::size_t				   lookupCalls{} ;
	/// 明示節の読取回数。
	std::size_t				   readCalls{} ;
	/// 終了再確認の順序付きidentity。
	std::vector<std::uint64_t> rechecked ;
	/// 非零なら当該1-based再確認でERROR_RETRYを返す。
	std::size_t				   failRecheckAt{} ;
	/// trueなら失敗指定の再確認で一般例外を送出する。
	bool					   throwRecheck{} ;

	/** @brief このfixtureを呼出し中だけ借用する偽操作を作る。
	 * @return 同期runの寿命内だけ使える三callback。
	 */
	InfDependencyOperations	   operations()
	{
		return {
			[this]( const auto &source, std::wstring_view name, InfDependencyLookup &output) {
				// 架空元identityと原名を結合し、実pathを検索しない。
				++lookupCalls ;
				const auto found = std::ranges::find_if( lookups, [&source, name]( const auto &item) {
					// 別元節の照会結果を名前だけで持ち込まない。
					return item.identity == source.identity && sameFixtureName( item.name, name) ;
				}) ; // iteratorはこの同期callback内だけで使用する。
				output = found == lookups.end() ? InfDependencyLookup{true, {}} : found->value ;
				return NativeError{} ;
			},
			[this]( const auto &source, std::wstring_view name, InfDependencySection &output) {
				// 架空tableに明示された節だけを読む。
				++readCalls ;
				const auto found =
					std::ranges::find_if( sections, [&source, name]( const auto &item) {
						// 大小文字以外の装飾や別identityを推測しない。
						return item.identity == source.identity && sameFixtureName( item.name, name) ;
					}) ; // 借用はcallback終了まで。
				output = found == sections.end()
							 ? InfDependencySection{InfDependencyReadState::MISSING, {}}
							 : found->value ;
				return NativeError{} ;
			},
			[this]( const auto &snapshot) -> NativeError {
				// 全発見documentの最終再確認と順序を観測する。
				rechecked.push_back( snapshot.identity) ;
				// 最後のdocumentまで成功していない状態を全成功にしない。
				if( failRecheckAt == rechecked.size()) {
					// 例外でも部分結果が残らないことを同じ位置で検査する。
					if( throwRecheck) {
						throw std::runtime_error( "fictional recheck") ;
					}

					return HRESULT_FROM_WIN32( ERROR_RETRY) ;
				}

				return 0 ;
			}} ;
	}
} ;

/** @brief 成功の確認用計画に実行能力や検査済みの別軸が混入しないことを確認する。
 * @param[in,out] context assertionの集計先。
 * @param[in] result 今回の非実行観測。
 */
void expectReviewOnly( TestContext &context, const InfDependencyResult &result)
{
	DRIVERCRATE_EXPECT( context, result.plan.actionCoverage == InfDependencyEvidence::NOT_CHECKED) ;
	DRIVERCRATE_EXPECT( context,
					   result.plan.deviceApplicability == InfDependencyEvidence::NOT_CHECKED) ;
	DRIVERCRATE_EXPECT( context, result.plan.installRoute == InfDependencyEvidence::NOT_CHECKED) ;
	DRIVERCRATE_EXPECT( context, result.plan.entries.size() == result.documents.size()) ;
	DRIVERCRATE_EXPECT( context, std::ranges::count_if( result.plan.entries, []( const auto &entry) {
									// rootだけが基本driverで、参照資料を追加導入対象にしない。
									return entry.baseDriver ;
								}) == 1) ;
	// 各確認項目を同じgraphの一意documentと基本driverの役割へ結合する。
	for( const auto &entry : result.plan.entries) {
		DRIVERCRATE_EXPECT( context,
						   std::ranges::count_if( result.documents, [&entry]( const auto &item) {
							   // 名前や同hashから別identityを同一化しない。
							   return item.identity == entry.identity ;
						   }) == 1) ;
		DRIVERCRATE_EXPECT( context, entry.baseDriver == (entry.identity == 1U)) ;
	}
}

/** @brief 古い成功値を詰めた出力を使い、全失敗時の空化まで確認する。
 * @param[in,out] context assertionの集計先。
 * @param[in,out] fixture 同期runだけの架空loader。
 * @param[in,out] cases 実行した有限caseの集計先。
 * @param[in] expected 期待する観測error。0は観測成功で導入成功ではない。
 * @return 今回の結果。拒否なら全出力が空。
 */
InfDependencyResult exercise( TestContext &context, ReviewFixture &fixture, std::size_t &cases,
							 NativeError expected = 0)
{
	++cases ;
	const std::array	seeds{std::wstring( L"Install")} ;	// 明示元節だけを観測する。
	const auto			operations = fixture.operations() ;	// fixtureをこの同期runだけ借用する。
	InfDependencyResult result ;							// 古い成功snapshotを消すことも確認する。
	result.context = fixture.root.context ;
	result.documents.push_back( fixture.root) ;
	result.sections.push_back( {1U, L"Old", InfDependencyReadState::PRESENT}) ;
	result.edges.emplace_back() ;
	result.plan.entries.push_back( {1U, true}) ;
	result.plan.referencesResolved	 = true ;
	result.plan.rootEvidenceVerified = true ;
	result.plan.actionCoverage = result.plan.deviceApplicability = result.plan.installRoute =
		InfDependencyEvidence::VERIFIED ;
	const NativeError error =
		// 核のみを呼ぶ。
		resolveInfDependencies( fixture.root, seeds, operations, result) ;
	DRIVERCRATE_EXPECT( context, error == expected) ;
	// 拒否時は古い全成功flag・graph・文脈を残さない。
	if( expected != 0) {
		DRIVERCRATE_EXPECT( context, result.documents.empty() && result.sections.empty() &&
										result.edges.empty()) ;
		DRIVERCRATE_EXPECT( context, result.plan.entries.empty() &&
										!result.plan.referencesResolved &&
										!result.plan.rootEvidenceVerified) ;
		DRIVERCRATE_EXPECT( context, result.context.major == 0U && result.context.minor == 0U &&
										result.context.build == 0U &&
										result.context.observationId == 0U &&
										!result.context.windowsServer) ;
		DRIVERCRATE_EXPECT(
			context, result.plan.actionCoverage == InfDependencyEvidence::NOT_CHECKED &&
						 result.plan.deviceApplicability == InfDependencyEvidence::NOT_CHECKED &&
						 result.plan.installRoute == InfDependencyEvidence::NOT_CHECKED) ;
	} else {
		expectReviewOnly( context, result) ;
		DRIVERCRATE_EXPECT( context, fixture.rechecked.size() == result.documents.size()) ;
	}

	return result ;
}

/** @brief 候補とrootの独立三証拠を全組合せで検証する。
 * @param[in,out] context assertionの集計先。
 * @param[in,out] cases 実行したcase数。
 */
void testEvidenceMatrix( TestContext &context, std::size_t &cases)
{
	// 配布境界を変えても同じ三証拠を全27組合せで要求する。
	for( const auto origin : {InfDependencyOrigin::PACKAGE, InfDependencyOrigin::SYSTEM}) {
		// byte未結合を節の実在確認へ進ませない。
		for( const auto bytes : EVIDENCE_STATES) {
			// 由来を署名から推測しない。
			for( const auto provenance : EVIDENCE_STATES) {
				// 署名の未検査と不合格を独立して保持する。
				for( const auto signature : EVIDENCE_STATES) {
					ReviewFixture fixture ;										// 各組合せでcallback履歴を分離する。
					auto &candidate	 = fixture.lookups[0].value.documents[0] ;	// 架空候補の三軸。
					candidate.origin = origin ;
					candidate.byteBinding = bytes ;
					candidate.provenance  = provenance ;
					candidate.signature	  = signature ;
					const auto result = exercise( context, fixture, cases) ;	// 実証拠を発行しない。
					// 三軸が全て確認済みの組合せだけを参照解決の正例とする。
					const bool verified = bytes == InfDependencyEvidence::VERIFIED &&
										  provenance == InfDependencyEvidence::VERIFIED &&
										  signature == InfDependencyEvidence::VERIFIED ;
					const auto resolvedState =
						origin == InfDependencyOrigin::PACKAGE
							? InfDependencyState::RESOLVED_PACKAGE
							: InfDependencyState::RESOLVED_SYSTEM ;	// 正しい配布境界。
					DRIVERCRATE_EXPECT( context,
									   result.documents.size() == 2U && result.edges.size() == 2U) ;
					DRIVERCRATE_EXPECT( context,
									   result.documents.back().byteBinding == bytes &&
										   result.documents.back().provenance == provenance &&
										   result.documents.back().signature == signature) ;
					DRIVERCRATE_EXPECT( context, result.plan.referencesResolved == verified &&
													result.plan.rootEvidenceVerified) ;
					DRIVERCRATE_EXPECT(
						context, result.edges.front().state ==
									 (verified ? resolvedState : InfDependencyState::OBSERVED)) ;
					DRIVERCRATE_EXPECT(
						context,
						result.edges.back().state ==
							(bytes != InfDependencyEvidence::VERIFIED
								 ? InfDependencyState::NOT_CHECKED
								 : (verified ? resolvedState : InfDependencyState::OBSERVED))) ;
					DRIVERCRATE_EXPECT( context,
									   fixture.readCalls ==
										   (bytes == InfDependencyEvidence::VERIFIED ? 3U : 2U)) ;
				}
			}
		}
	}

	// root証拠不足を外部参照成功で補完せず、byte未確認は入口で拒否する。
	for( const auto bytes : EVIDENCE_STATES) {
		// root由来の全状態を独立して測る。
		for( const auto provenance : EVIDENCE_STATES) {
			// root署名の全状態を独立して測る。
			for( const auto signature : EVIDENCE_STATES) {
				ReviewFixture fixture ;	// root以外は検証済みの架空値。
				fixture.root.byteBinding = bytes ;
				fixture.root.provenance	 = provenance ;
				fixture.root.signature	 = signature ;
				const auto result		 = exercise( context, fixture, cases,
												bytes == InfDependencyEvidence::VERIFIED
														? 0
														: E_INVALIDARG) ;	// byteだけが入口必須。
				// 入口拒否ではcallbackを一つも呼ばない。
				if( bytes != InfDependencyEvidence::VERIFIED) {
					DRIVERCRATE_EXPECT( context, fixture.readCalls == 0U &&
													fixture.lookupCalls == 0U &&
													fixture.rechecked.empty()) ;
				} else {
					DRIVERCRATE_EXPECT( context, result.plan.referencesResolved) ;
					DRIVERCRATE_EXPECT( context,
									   result.plan.rootEvidenceVerified ==
										   (provenance == InfDependencyEvidence::VERIFIED &&
											signature == InfDependencyEvidence::VERIFIED)) ;
					DRIVERCRATE_EXPECT( context,
									   result.documents.front().provenance == provenance &&
										   result.documents.front().signature == signature) ;
				}
			}
		}
	}
}

/** @brief 文脈転用・同identity差替え・最後の再確認失敗を拒否する。
 * @param[in,out] context assertionの集計先。
 * @param[in,out] cases 実行したcase数。
 */
void testSnapshotBoundaries( TestContext &context, std::size_t &cases)
{
	// 全六OS文脈fieldを一つずつ変え、同hashでも転用を拒否する。
	for( unsigned int field = 0U; field < 6U; ++field) {
		ReviewFixture fixture ;													// 文脈だけが異なる架空候補。
		auto		 &value = fixture.lookups[0].value.documents[0].context ;	// 今回の一候補文脈。
		// 文脈差を再現する対象fieldを限定する。
		switch( field) {
			// OS major差。
			case 0U:
				++value.major ;
				break ;

			// OS minor差。
			case 1U:
				++value.minor ;
				break ;

			// OS build差。
			case 2U:
				++value.build ;
				break ;

			// architecture差。
			case 3U:
				value.machine = 0xaa64U ;
				break ;

			// Serverとclientの境界差。
			case 4U:
				value.windowsServer = true ;
				break ;

			// 同OSでも別の観測世代。
			default:
				++value.observationId ;
				break ;
		}

		(void)exercise( context, fixture, cases, HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH)) ;
		DRIVERCRATE_EXPECT( context, fixture.rechecked.empty()) ;
	}

	// 同identityの全六byte／証拠field差替えを未検査へ弱めない。
	for( unsigned int field = 0U; field < 6U; ++field) {
		ReviewFixture fixture ;											// rootを別候補として再提示する架空不正応答。
		auto		 &value = fixture.lookups[0].value.documents[0] ;	// 同identityへ変更する候補。
		value				= fixture.root ;
		// 差替えを一fieldずつ再現し、最初の不一致を全体拒否する。
		switch( field) {
			// 原hash差。
			case 0U:
				value.sha256.assign( 64U, L'b') ;
				break ;

			// 原size差。
			case 1U:
				++value.byteCount ;
				break ;

			// 配布境界差。
			case 2U:
				value.origin = InfDependencyOrigin::SYSTEM ;
				break ;

			// byte証拠差。
			case 3U:
				value.byteBinding = InfDependencyEvidence::FAILED ;
				break ;

			// 由来証拠差。
			case 4U:
				value.provenance = InfDependencyEvidence::FAILED ;
				break ;

			// 署名証拠差。
			default:
				value.signature = InfDependencyEvidence::FAILED ;
				break ;
		}

		(void)exercise( context, fixture, cases, HRESULT_FROM_WIN32( ERROR_FILE_INVALID)) ;
		DRIVERCRATE_EXPECT( context, fixture.rechecked.empty()) ;
	}

	// 最初・最後の再確認と例外を分け、古い成功flagも全て消す。
	for( std::size_t ordinal = 1U; ordinal <= 2U; ++ordinal) {
		// 原code拒否と一般例外のどちらも部分成功へ変えない。
		for( const bool exception : {false, true}) {
			ReviewFixture fixture ;	// 全観測後の再確認だけで失敗する。
			fixture.failRecheckAt = ordinal ;
			fixture.throwRecheck  = exception ;
			(void)exercise( context, fixture, cases,
						   exception ? E_FAIL : HRESULT_FROM_WIN32( ERROR_RETRY)) ;
			DRIVERCRATE_EXPECT( context, fixture.rechecked.size() == ordinal) ;
			DRIVERCRATE_EXPECT( context, fixture.rechecked.front() == 1U) ;
		}
	}
}

/** @brief 部分照会・複数候補・循環・空参照と資料役割を検証する。
 * @param[in,out] context assertionの集計先。
 * @param[in,out] cases 実行したcase数。
 */
void testGraphBoundaries( TestContext &context, std::size_t &cases)
{
	// 未照会・未発見・曖昧・循環と正当な空集合を独立したcaseへ残す。
	for( unsigned int scenario = 0U; scenario < 12U; ++scenario) {
		ReviewFixture fixture ;	// 各caseで候補と節の既定正例を分離する。
		// 一意な実在候補があっても別Include未照会ならNeedsを確定しない。
		if( scenario <= 2U) {
			fixture.sections[0].value.references.push_back(
				{InfDependencyDirective::INCLUDE, L"other.inf"}) ;
			fixture.lookups.push_back( {1U, L"other.inf", {scenario != 0U, {}}}) ;
			// 別候補が見つかっても節未照会なら一意性は未確認。
			if( scenario == 2U) {
				fixture.lookups.back().value.documents.push_back(
					makeDocument( 3U, InfDependencyOrigin::PACKAGE)) ;
				fixture.sections.push_back(
					{3U, L"Shared", {InfDependencyReadState::NOT_CHECKED, {}}}) ;
			}
		}

		// 署名不合格の同名実在節を隠して検証済み一件へ絞らない。
		if( scenario == 3U) {
			fixture.sections.push_back( {1U, L"Shared", {InfDependencyReadState::PRESENT, {}}}) ;
			fixture.root.signature = InfDependencyEvidence::FAILED ;
		}

		// 別二identityの同hashは曖昧候補として残す。
		if( scenario == 4U) {
			fixture.lookups[0].value.documents.push_back(
				makeDocument( 3U, InfDependencyOrigin::SYSTEM)) ;
			fixture.sections.push_back( {3U, L"Shared", {InfDependencyReadState::PRESENT, {}}}) ;
		}

		// 大小文字違いのactive節へ戻る場合も循環にする。
		if( scenario == 5U) {
			fixture.sections[1].value.references.push_back(
				{InfDependencyDirective::NEEDS, L"sHaReD"}) ;
		}

		// 重複Include辺は残し、共有実在節の照会だけをcacheする。
		if( scenario == 6U) {
			fixture.sections[0].value.references.push_back(
				{InfDependencyDirective::INCLUDE, L"CHILD.INF"}) ;
		}

		// 同節参照の前後順で解決先を変えない。
		if( scenario == 7U) {
			std::ranges::reverse( fixture.sections[0].value.references) ;
		}

		// root参照なしでも別軸を検査済みにしない。
		if( scenario >= 8U) {
			fixture.sections[0].value.references.clear() ;
			// 未発見と未照会の開始節を空の完全graphへ昇格しない。
			if( scenario == 9U || scenario == 10U) {
				fixture.sections[0].value.state = scenario == 9U
													  ? InfDependencyReadState::MISSING
													  : InfDependencyReadState::NOT_CHECKED ;
			}

			// 正当な空参照のroot証拠不足も独立に残す。
			if( scenario == 11U) {
				fixture.root.provenance = InfDependencyEvidence::NOT_CHECKED ;
			}
		}

		const auto result =
			// 欠落や曖昧は観測成功として理由を残す。
			exercise( context, fixture, cases) ;
		const bool resolved = scenario == 6U || scenario == 7U || scenario == 8U ||
							  // 全辺だけの評価。
							  scenario == 11U ;
		DRIVERCRATE_EXPECT( context, result.plan.referencesResolved == resolved) ;
		DRIVERCRATE_EXPECT( context,
						   result.plan.rootEvidenceVerified == (scenario != 3U && scenario != 11U)) ;
		// 未確認候補が一つでも残れば一意のNeeds節を認定しない。
		if( scenario == 0U || scenario == 2U) {
			DRIVERCRATE_EXPECT( context,
							   result.edges[1].state == InfDependencyState::NOT_CHECKED &&
								   result.edges[1].reason == InfDependencyReason::NOT_CHECKED &&
								   result.edges[1].candidateCount == 1U) ;
		}

		// 照会済み未発見のIncludeと実在Needsを別状態へ保持する。
		if( scenario == 1U) {
			DRIVERCRATE_EXPECT( context,
							   result.edges[1].state == InfDependencyState::RESOLVED_SYSTEM &&
								   result.edges[2].reason == InfDependencyReason::MISSING) ;
		}

		// 実在二候補を一つのhashで併合しない。
		if( scenario == 3U || scenario == 4U) {
			DRIVERCRATE_EXPECT( context, result.edges[1].reason == InfDependencyReason::AMBIGUOUS &&
											result.edges[1].candidateCount == 2U &&
											result.edges[1].targetIdentity == 0U) ;
		}

		// active節への辺だけを循環として数える。
		if( scenario == 5U) {
			DRIVERCRATE_EXPECT( context, std::ranges::count_if( result.edges, []( const auto &edge) {
											// 共有の再発見を循環数へ混ぜない。
											return edge.reason == InfDependencyReason::CYCLE ;
										}) == 1) ;
		}

		// 重複辺の分母とcacheの呼出し数を独立に確認する。
		if( scenario == 6U) {
			DRIVERCRATE_EXPECT( context, result.edges.size() == 3U && fixture.lookupCalls == 2U &&
											fixture.readCalls == 3U &&
											result.documents.size() == 2U) ;
		}
	}
}

} // namespace
} // namespace drivercrate::test

/** @brief 架空境界試験の件数だけを表示する。
 * @return 全assertion成功0、失敗または予期しない例外1。
 */
int main()
{
	drivercrate::test::TestContext context ;	// このprocessだけのassertion集計。
	std::size_t					   cases{} ;	// 実行した有限架空case数。
	try {
		drivercrate::test::testEvidenceMatrix( context, cases) ;
		drivercrate::test::testSnapshotBoundaries( context, cases) ;
		drivercrate::test::testGraphBoundaries( context, cases) ;
	} catch( ...) {
		std::cerr << "Unexpected fixture exception.\n" ;
		return 1 ;
	}

	std::cout << "Boundary cases: " << cases << ", Assertions: " << context.assertionCount()
			  << ", failures: " << context.failureCount() << '\n' ;
	return context.failureCount() == 0 ? 0 : 1 ;
}
