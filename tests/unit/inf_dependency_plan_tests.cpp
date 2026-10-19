//------------------------------------------------------------------------------
/**
 * @file inf_dependency_plan_tests.cpp
 * @brief 偽loaderによる有限INF依存核と非実行計画の単体試験。
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  偽loader・証拠分離・有限graphの試験を追加。
 * </pre>
 *
 * @note 架空snapshotだけを使用し、INF・署名・実device・network・導入APIを呼ばない。
 * @see docs/adr/0269-bounded-inf-dependency-core-and-review-plan.md
 */
//------------------------------------------------------------------------------

#include "platform/inf_dependency_plan.h"
#include "test_framework.h"

#include <Windows.h>

#include <algorithm>
#include <iostream>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {

/** @brief 架空のrun内documentを作る。
 * @param[in] identity 一意の非零identity。
 * @param[in] origin packageまたはsystem。
 * @return 三証拠を独立にVERIFIEDとした架空snapshot。実署名ではない。
 */
InfDependencyDocument document( std::uint64_t identity, InfDependencyOrigin origin)
{
	return {identity,
			std::wstring( 64U, L'a'),
			100U,
			origin,
			InfDependencyEvidence::VERIFIED,
			InfDependencyEvidence::VERIFIED,
			InfDependencyEvidence::VERIFIED,
			{10U, 0U, 26100U, 0x8664U, false, 7U}} ;
}

/** @brief 偽section tableの一要素。 */
struct SectionFixture {
	/// 偽document identity。
	std::uint64_t		 identity{} ;
	/// 架空明示節名。
	std::wstring		 name ;
	/// 有限応答snapshot。
	InfDependencySection value ;
} ;

/** @brief 偽Include tableの一要素。 */
struct LookupFixture {
	/// 元の架空document identity。
	std::uint64_t		identity{} ;
	/// 架空相対INF名。
	std::wstring		name ;
	/// 未検査または有限候補応答。
	InfDependencyLookup value ;
} ;

/** @brief Windows ordinalで架空の節だけを比較する。
 * @param[in] left 有限な架空名。
 * @param[in] right 有限な架空名。
 * @return 大小文字だけを除いて一致ならtrue。
 */
bool equalName( std::wstring_view left, std::wstring_view right)
{
	return CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

/** @brief 実filesystemを使わない同期loader。失敗注入もrun内だけに限定する。 */
struct FakeLoader {
	/// 架空節の有限table。
	std::vector<SectionFixture> sections ;
	/// 架空Includeの有限table。
	std::vector<LookupFixture>	lookups ;
	/// lookup呼出し数。
	std::size_t					lookupCalls{} ;
	/// 明示節照会数。
	std::size_t					readCalls{} ;
	/// snapshot再確認数。
	std::size_t					recheckCalls{} ;
	/// 0なら通常応答、非零ならlookup失敗を注入する。
	NativeError					lookupError{} ;
	/// 0なら通常応答、非零ならread失敗を注入する。
	NativeError					readError{} ;
	/// 0なら通常応答、非零ならrecheck失敗を注入する。
	NativeError					recheckError{} ;
	/// trueならlookupでbad_allocを注入する。
	bool						allocationFailure{} ;
	/// trueならreadで型付き例外を注入する。
	bool						readException{} ;
	/// trueならrecheckで型付き例外を注入する。
	bool						recheckException{} ;

	/** @brief 同期借用の三callbackを生成する。
	 * @return このFakeLoaderの寿命内だけで使う操作集合。
	 */
	InfDependencyOperations		operations()
	{
		return {[this]( const auto &source, std::wstring_view name,
					   InfDependencyLookup &output) -> NativeError {
					// このtestのloaderだけを同期借用し、呼出しを集計する。
					++lookupCalls ;
					// allocation失敗を観測成功へ変換させない。
					if( allocationFailure) {
						throw std::bad_alloc() ;
					}

					// 明示callback失敗をそのまま核へ渡す。
					if( lookupError != 0) {
						return lookupError ;
					}

					const auto found =
						std::ranges::find_if( lookups, [&source, name]( const auto &item) {
							// 名前一致だけで別sourceの候補を補完しない。
							return item.identity == source.identity && equalName( item.name, name) ;
						}) ; // この同期借用内でだけtableを読む。
					output = found == lookups.end() ? InfDependencyLookup{true, {}} : found->value ;
					return 0 ;
				},
				[this]( const auto &source, std::wstring_view name,
					   InfDependencySection &output) -> NativeError {
					// 架空tableだけを読む。実Windows INFを開かない。
					++readCalls ;
					// callback例外の全体拒否を確認する。
					if( readException) {
						throw std::runtime_error( "fictional") ;
					}

					// 明示読取失敗を欠落節へ弱めない。
					if( readError != 0) {
						return readError ;
					}

					const auto found =
						std::ranges::find_if( sections, [&source, name]( const auto &item) {
							// 同documentの明示節だけを照会する。
							return item.identity == source.identity && equalName( item.name, name) ;
						}) ; // 借用はこのlookup終了まで。
					output = found == sections.end()
								 ? InfDependencySection{InfDependencyReadState::MISSING, {}}
								 : found->value ;
					return 0 ;
				},
				[this]( const auto &snapshot) -> NativeError {
					// 全発見snapshotで最後の再確認を要求した事実を測る。
					++recheckCalls ;
					// 最後のcallback例外にも部分成功を残さない。
					if( recheckException) {
						throw std::runtime_error( "fictional") ;
					}

					return snapshot.identity == 0U ? NativeError{E_INVALIDARG} : recheckError ;
				}} ;
	}
} ;

/** @brief 二documentを結ぶ架空正例から拒否・上限・分離を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testScenarios( TestContext &context)
{
	// 58の有限な架空シナリオを独立loaderで実行し、旧観測を変えない。
	for( unsigned int scenario = 0U; scenario < 58U; ++scenario) {
		InfDependencyDocument root = document( 1U, InfDependencyOrigin::PACKAGE) ;	// 架空基本driver。
		FakeLoader			  loader ;												// 当該caseだけの架空状態。
		loader.sections = {{1U,
							L"Install",
							{InfDependencyReadState::PRESENT,
							 {{InfDependencyDirective::INCLUDE, L"base.inf"},
							  {InfDependencyDirective::NEEDS, L"Shared"}}}},
						   {2U, L"Shared", {InfDependencyReadState::PRESENT, {}}}} ;
		loader.lookups	= {{1U, L"base.inf", {true, {document( 2U, InfDependencyOrigin::SYSTEM)}}}} ;
		std::vector<std::wstring> seeds{L"Install"} ;	// root内の明示開始節。
		NativeError				  expected{} ;			// 0は全体観測成功で、導入成功ではない。
		// 配布境界だけを変え、system認定を名前だけに依存させない。
		if( scenario == 1U) {
			loader.lookups[0].value.documents[0].origin = InfDependencyOrigin::PACKAGE ;
		}

		// 独立署名・由来・byte軸の未検査と不合格をそれぞれ残す。
		if( scenario >= 2U && scenario <= 7U) {
			const InfDependencyEvidence state =
				scenario % 2U == 0U ? InfDependencyEvidence::NOT_CHECKED
									: InfDependencyEvidence::FAILED ;	// 対応軸の状態。
			auto &candidate = loader.lookups[0].value.documents[0] ;	// 架空候補の一証拠軸。
			// 署名がない場合もbyte観測を消さない。
			if( scenario <= 3U) {
				candidate.signature = state ;
			}
			// 由来不明を不正署名へ読み替えない。
			else if( scenario <= 5U) {
				candidate.provenance = state ;
			} else {
				candidate.byteBinding = state ;
			}
		}

		// 未照会と照会済み未発見を分ける。
		if( scenario == 8U || scenario == 9U) {
			loader.lookups[0].value = {scenario == 9U, {}} ;
		}

		// 別節にしかないIncludeでInstallのNeedsを補完させない。
		if( scenario == 10U) {
			loader.sections[0].value.references.erase( loader.sections[0].value.references.begin()) ;
			loader.sections.push_back( {1U,
									   L"Install.Services",
									   {InfDependencyReadState::PRESENT,
										{{InfDependencyDirective::INCLUDE, L"base.inf"}}}}) ;
			seeds.push_back( L"Install.Services") ;
		}

		// 重複辺を保持し、共有節の再照会を止める。
		if( scenario == 11U) {
			loader.sections[0].value.references.push_back(
				{InfDependencyDirective::NEEDS, L"Shared"}) ;
		}

		// 正当な存在・署名でも自己循環を全充足としない。
		if( scenario == 12U) {
			loader.sections[1].value.references = {{InfDependencyDirective::NEEDS, L"Shared"}} ;
		}

		// 別document経由でrootのactive節へ戻る循環も捕捉する。
		if( scenario == 13U) {
			loader.sections[1].value.references = {{InfDependencyDirective::INCLUDE, L"root.inf"},
												   {InfDependencyDirective::NEEDS, L"Install"}} ;
			loader.lookups.push_back( {2U, L"root.inf", {true, {root}}}) ;
		}

		// 同INFとInclude先の同名実在節から勝手に一つを選ばない。
		if( scenario == 14U) {
			loader.sections.push_back( {1U, L"Shared", {InfDependencyReadState::PRESENT, {}}}) ;
		}

		// 二Include候補の同名実在節を曖昧として残す。
		if( scenario == 15U) {
			loader.lookups[0].value.documents.push_back( document( 3U, InfDependencyOrigin::PACKAGE)) ;
			loader.sections.push_back( {3U, L"Shared", {InfDependencyReadState::PRESENT, {}}}) ;
		}

		// 未検査節を未発見としない。
		if( scenario == 16U) {
			loader.sections[1].value.state = InfDependencyReadState::NOT_CHECKED ;
		}

		// 不正pathからloaderを呼ばせない。
		if( scenario == 17U) {
			loader.sections[0].value.references[0].target = L"..\\base.inf" ;
		}

		// 不正節名も原辺の分母へ残す。
		if( scenario == 18U) {
			loader.sections[0].value.references[1].target = L"[bad]" ;
		}

		// 未知directiveをNeedsへ弱めない。
		if( scenario == 19U) {
			loader.sections[0].value.references[0].directive =
				static_cast<InfDependencyDirective>( 99) ;
			expected = E_INVALIDARG ;
		}

		// loaderの同候補重複は不正として拒否する。
		if( scenario == 20U) {
			loader.lookups[0].value.documents.push_back( loader.lookups[0].value.documents[0]) ;
			expected = E_INVALIDARG ;
		}

		// 未結合の原hashを最初に拒否する。
		if( scenario == 21U) {
			root.sha256 = L"invalid" ;
			expected	= E_INVALIDARG ;
		}

		// 他OSの充足は転用しない。
		if( scenario == 22U) {
			++loader.lookups[0].value.documents[0].context.build ;
			expected = HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) ;
		}

		// 同identityのbyte差替えは全体拒否する。
		if( scenario == 23U) {
			loader.lookups[0].value.documents[0] = root ;
			loader.lookups[0].value.documents[0].sha256.assign( 64U, L'b') ;
			expected = HRESULT_FROM_WIN32( ERROR_FILE_INVALID) ;
		}

		// 最後の再確認失敗も原codeを保持する。
		if( scenario == 24U) {
			loader.recheckError = HRESULT_FROM_WIN32( ERROR_RETRY) ;
			expected			= loader.recheckError ;
		}

		// lookup・readの失敗をそのまま返す。
		if( scenario == 25U) {
			loader.lookupError = E_ACCESSDENIED ;
			expected		   = E_ACCESSDENIED ;
		}

		// read拒否を未発見へ変換しない。
		if( scenario == 26U) {
			loader.readError = E_ACCESSDENIED ;
			expected		 = E_ACCESSDENIED ;
		}

		// bad_allocを境界で捕捉する。
		if( scenario == 27U) {
			loader.allocationFailure = true ;
			expected				 = E_OUTOFMEMORY ;
		}

		// 一般例外も部分成功へ変換しない。
		if( scenario == 28U) {
			loader.readException = true ;
			expected			 = E_FAIL ;
		}

		// rootのbyteは必須とする。
		if( scenario == 29U) {
			root.byteBinding = InfDependencyEvidence::NOT_CHECKED ;
			expected		 = E_INVALIDARG ;
		}

		// 空seed・他architecture・世代差を拒否する。
		if( scenario == 31U) {
			seeds.clear() ;
			expected = E_INVALIDARG ;
		}

		// x64以外へ黙って適用しない。
		if( scenario == 32U) {
			root.context.machine = 0xaa64U ;
			expected			 = E_INVALIDARG ;
		}

		// 同OS buildでも別観測世代なら転用しない。
		if( scenario == 33U) {
			++loader.lookups[0].value.documents[0].context.observationId ;
			expected = HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) ;
		}

		// OS未観測から解決済みを発行しない。
		if( scenario == 34U) {
			root.context.major = 0U ;
			expected		   = E_INVALIDARG ;
		}

		// 未知署名enumを確認済みへ変換しない。
		if( scenario == 35U) {
			loader.lookups[0].value.documents[0].signature = static_cast<InfDependencyEvidence>( 99) ;
			expected									   = E_INVALIDARG ;
		}

		// 一照会の過大候補を拒否する。
		if( scenario == 36U) {
			loader.lookups[0].value.documents.assign( 65U,
													 document( 2U, InfDependencyOrigin::SYSTEM)) ;
			expected = E_INVALIDARG ;
		}

		// 参照数の最大量と一件超過を分ける。
		if( scenario == 37U || scenario == 38U) {
			loader.sections[0].value.references.assign( scenario == 37U ? 4096U : 4097U,
													   {InfDependencyDirective::NEEDS, L"Shared"}) ;
			loader.sections.push_back( {1U, L"Shared", {InfDependencyReadState::PRESENT, {}}}) ;
			// 一件超過の部分graphを残さない。
			if( scenario == 38U) {
				expected = HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
			}
		}

		// seed／節数の最大量と入力超過を分ける。
		if( scenario == 39U || scenario == 40U) {
			seeds.clear() ;
			loader.sections.clear() ;
			// 既知の有限節だけを生成する。
			for( unsigned int ordinal = 0U; ordinal < (scenario == 39U ? 1024U : 1025U); ++ordinal) {
				const std::wstring name = L"Seed" + std::to_wstring( ordinal) ;	// 架空節名。
				seeds.push_back( name) ;
				loader.sections.push_back( {1U, name, {InfDependencyReadState::PRESENT, {}}}) ;
			}

			// seed入力超過はcallback前に拒否する。
			if( scenario == 40U) {
				expected = E_INVALIDARG ;
			}
		}

		// 再帰32段ちょうどと一段超過を確認する。
		if( scenario == 41U || scenario == 42U) {
			loader.sections.clear() ;
			seeds					 = {L"Node1"} ;
			const unsigned int count = scenario == 41U ? 32U : 33U ;	// 有限再帰長。
			// 最後の節だけを空にして真の再帰境界を測る。
			for( unsigned int ordinal = 1U; ordinal <= count; ++ordinal) {
				InfDependencySection value{InfDependencyReadState::PRESENT, {}} ;	// 架空節。
				// 最後の節は再帰を追加しない。
				if( ordinal != count) {
					value.references.push_back(
						{InfDependencyDirective::NEEDS, L"Node" + std::to_wstring( ordinal + 1U)}) ;
				}

				loader.sections.push_back( {1U, L"Node" + std::to_wstring( ordinal), value}) ;
			}

			// 一段超過も全体拒否する。
			if( scenario == 42U) {
				expected = HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
			}
		}

		// diamond共有は循環とせず、Leafを一度だけ読む。
		if( scenario == 43U) {
			loader.sections = {
				{1U,
				 L"Install",
				 {InfDependencyReadState::PRESENT,
				  {{InfDependencyDirective::NEEDS, L"Left"},
				   {InfDependencyDirective::NEEDS, L"Right"}}}},
				{1U,
				 L"Left",
				 {InfDependencyReadState::PRESENT, {{InfDependencyDirective::NEEDS, L"Leaf"}}}},
				{1U,
				 L"Right",
				 {InfDependencyReadState::PRESENT, {{InfDependencyDirective::NEEDS, L"Leaf"}}}},
				{1U, L"Leaf", {InfDependencyReadState::PRESENT, {}}}} ;
		}

		// 明示節の大小文字一致はWindows ordinalで扱う。
		if( scenario == 44U) {
			loader.sections[0].value.references[1].target = L"sHaReD" ;
		}

		// root証拠と外部の明示辺解決を独立に残す。
		if( scenario == 45U) {
			root.signature = InfDependencyEvidence::NOT_CHECKED ;
		}

		// 観測世代なしを拒否する。
		if( scenario == 46U) {
			root.context.observationId = 0U ;
			expected				   = E_INVALIDARG ;
		}

		// 空seed観測を全充足にしない。
		if( scenario == 47U) {
			loader.sections[0].value = {InfDependencyReadState::MISSING, {}} ;
		}

		// Serverとclientのsnapshot転用を拒否する。
		if( scenario == 48U) {
			loader.lookups[0].value.documents[0].context.windowsServer = true ;
			expected = HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) ;
		}

		// sizeなしdocumentを拒否する。
		if( scenario == 49U) {
			loader.lookups[0].value.documents[0].byteCount = 0U ;
			expected									   = E_INVALIDARG ;
		}

		// 再確認の例外も全体を破棄する。
		if( scenario == 50U) {
			loader.recheckException = true ;
			expected				= E_FAIL ;
		}

		// 最大64 documentと一件超過を別々に測る。
		if( scenario == 51U || scenario == 52U) {
			loader.sections[0].value.references.clear() ;
			loader.lookups.clear() ;
			// 各相対INFを一つの異なるdocumentへ結合する。
			for( unsigned int identity = 2U; identity <= (scenario == 51U ? 64U : 65U); ++identity) {
				const std::wstring name =
					L"dependency" + std::to_wstring( identity) + L".inf" ;	// 架空Include名。
				loader.sections[0].value.references.push_back(
					{InfDependencyDirective::INCLUDE, name}) ;
				loader.lookups.push_back(
					{1U, name, {true, {document( identity, InfDependencyOrigin::SYSTEM)}}}) ;
			}

			// 超過は全体失敗にして63件だけの成功を出さない。
			if( scenario == 52U) {
				expected = HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
			}
		}

		// 個別節が上限内でも累積参照超過を拒否する。
		if( scenario == 53U) {
			loader.sections[0].value.references = {{InfDependencyDirective::NEEDS, L"Shared"}} ;
			loader.sections.push_back( {1U,
									   L"Shared",
									   {InfDependencyReadState::PRESENT,
										std::vector<InfDependencyReference>(
											4096U, {InfDependencyDirective::NEEDS, L"Leaf"})}}) ;
			expected = HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		// 未検査lookupの部分候補を拒否する。
		if( scenario == 54U) {
			loader.lookups[0].value.checked = false ;
			expected						= E_INVALIDARG ;
		}

		// 参照なしでも計画の作用・device・導入方式は未評価のままとする。
		if( scenario == 55U) {
			loader.sections[0].value.references.clear() ;
		}

		// 過長名は不正辺へ残し、本文を複製しない。
		if( scenario == 56U) {
			loader.sections[0].value.references = {
				{InfDependencyDirective::NEEDS, std::wstring( 255U, L'x')}} ;
		}

		// 同一seedの大小文字差と共有を一度だけ読む。
		if( scenario == 57U) {
			seeds.push_back( L"iNsTaLl") ;
		}

		InfDependencyOperations operations = loader.operations() ;	// loader寿命内だけの同期借用。
		// 必須再確認なしでは観測を開始させない。
		if( scenario == 30U) {
			operations.recheck = {} ;
			expected		   = E_INVALIDARG ;
		}

		InfDependencyResult result ;	// 失敗で古い結果が残らないことを確認する。
		result.documents.push_back( root) ;
		const NativeError error =
			// 実loaderを呼ばない。
			resolveInfDependencies( root, seeds, operations, result) ;
		DRIVERCRATE_EXPECT( context, error == expected) ;
		// 全体拒否ではgraph・計画の部分値を全て破棄する。
		if( expected != 0) {
			DRIVERCRATE_EXPECT( context, result.documents.empty() && result.sections.empty() &&
											result.edges.empty() && result.plan.entries.empty()) ;
			continue ;
		}

		DRIVERCRATE_EXPECT( context, result.plan.entries.size() == result.documents.size()) ;
		DRIVERCRATE_EXPECT( context, loader.recheckCalls == result.documents.size()) ;
		DRIVERCRATE_EXPECT(
			context, result.plan.actionCoverage == InfDependencyEvidence::NOT_CHECKED &&
						 result.plan.deviceApplicability == InfDependencyEvidence::NOT_CHECKED &&
						 result.plan.installRoute == InfDependencyEvidence::NOT_CHECKED) ;
		DRIVERCRATE_EXPECT( context, result.documents.size() <= 64U &&
										result.sections.size() <= 1024U &&
										result.edges.size() <= 4096U) ;
		const auto cycles	 = std::ranges::count_if( result.edges, []( const auto &edge) {
			   // 循環を共有とは別に数える。
			   return edge.reason == InfDependencyReason::CYCLE ;
		   }) ; // 検査後の局所結果だけを借用する。
		const auto ambiguous = std::ranges::count_if( result.edges, []( const auto &edge) {
			// 曖昧な候補を解決済みから除く。
			return edge.reason == InfDependencyReason::AMBIGUOUS ;
		}) ; // 対象candidateの原値を変更しない。
		const bool resolved	 = scenario == 0U || scenario == 1U || scenario == 11U ||
							  scenario == 37U || scenario == 39U || scenario == 41U ||
							  scenario == 43U || scenario == 44U || scenario == 45U ||
							  scenario == 51U || scenario == 55U ||
							  // 明示辺だけの正例。
							  scenario == 57U ;
		DRIVERCRATE_EXPECT( context, result.plan.referencesResolved == resolved) ;
		DRIVERCRATE_EXPECT( context, result.plan.rootEvidenceVerified == (scenario != 45U)) ;
		DRIVERCRATE_EXPECT( context, cycles == (scenario == 12U || scenario == 13U ? 1 : 0)) ;
		DRIVERCRATE_EXPECT( context, ambiguous == (scenario == 14U ? 1 : (scenario == 15U ? 2 : 0))) ;
		// 同節正例は異なるpackage／system状態を区別する。
		if( scenario == 0U || scenario == 1U) {
			DRIVERCRATE_EXPECT( context,
							   result.edges.back().state ==
								   (scenario == 0U ? InfDependencyState::RESOLVED_SYSTEM
												   : InfDependencyState::RESOLVED_PACKAGE)) ;
		}

		// byte未確認候補は節を開かず証拠の不合格もそのまま残す。
		if( scenario >= 2U && scenario <= 7U) {
			DRIVERCRATE_EXPECT( context, result.edges[0].state == InfDependencyState::OBSERVED) ;
			// 未結合byteの節照会を実施しない。
			if( scenario >= 6U) {
				DRIVERCRATE_EXPECT( context, loader.readCalls == 2U) ;
			}
		}

		// 別節Includeからの誤補完を具体的に確認する。
		if( scenario == 10U) {
			DRIVERCRATE_EXPECT( context,
							   result.edges.front().reason == InfDependencyReason::MISSING) ;
		}

		// 重複辺と共有cacheの双方を確認する。
		if( scenario == 11U || scenario == 57U) {
			DRIVERCRATE_EXPECT( context, loader.readCalls == 3U &&
											result.edges.size() == (scenario == 11U ? 3U : 2U)) ;
		}

		// 不正Includeをloaderへ渡さない。
		if( scenario == 17U) {
			DRIVERCRATE_EXPECT( context, loader.lookupCalls == 0U) ;
		}

		// 最大参照を過剰拒否しない。
		if( scenario == 37U) {
			DRIVERCRATE_EXPECT( context, result.edges.size() == 4096U) ;
		}

		// 最大節を過剰拒否しない。
		if( scenario == 39U) {
			DRIVERCRATE_EXPECT( context, result.sections.size() == 1024U) ;
		}

		// 最大再帰段数を過剰拒否しない。
		if( scenario == 41U) {
			DRIVERCRATE_EXPECT( context, result.sections.size() == 32U) ;
		}

		// diamondの共有Leafは一度だけ照会する。
		if( scenario == 43U) {
			DRIVERCRATE_EXPECT( context, loader.readCalls == 4U && result.edges.size() == 4U) ;
		}

		// INF数の最大量を過剰拒否しない。
		if( scenario == 51U) {
			DRIVERCRATE_EXPECT( context, result.documents.size() == 64U) ;
		}

		// 過長本文を結果へ残さない。
		if( scenario == 56U) {
			DRIVERCRATE_EXPECT( context,
							   result.edges.size() == 1U && result.edges[0].target.empty() &&
								   result.edges[0].state == InfDependencyState::INVALID_REFERENCE) ;
		}
	}
}

} // namespace
} // namespace drivercrate::test

/** @brief 非通信の核試験を実行し件数だけを表示する。
 * @return 全成功0、assertionまたは予期しない例外の失敗1。
 */
int main()
{
	drivercrate::test::TestContext context ;	// このprocessだけの集計。
	try {
		drivercrate::test::testScenarios( context) ;
	} catch( ...) {
		std::cerr << "Unexpected fixture exception.\n" ;
		return 1 ;
	}

	std::cout << "Scenarios: 58, Assertions: " << context.assertionCount()
			  << ", failures: " << context.failureCount() << '\n' ;
	return context.failureCount() == 0 ? 0 : 1 ;
}
