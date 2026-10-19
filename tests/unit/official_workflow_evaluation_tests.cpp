//------------------------------------------------------------------------------
/**
 * @file official_workflow_evaluation_tests.cpp
 * @brief 固定評価case・入口・方式・未測定の決定的試験。
 * @version 01.00.00
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  固定case・入口・方式の集計契約を検証。
 * </pre>
 *
 * @note 架空の固定集合を扱う試験専用実装。実機対応率を計測・公開せず、OSへ作用しない。
 * @see docs/adr/0150-device-observation-and-candidate-assessment-contract.md
 */
//------------------------------------------------------------------------------

#include "official_workflow_evaluation_tests.h"
#include "core/candidate_assessment.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <set>
#include <span>
#include <tuple>

namespace drivercrate::test {
namespace {

/** @brief 他入口の成功を自動探索へ算入しない試験入口。 */
enum class EvaluationEntry {
	/// 自動探索だけの試行。
	AUTOMATIC,
	/// 利用者のURL入力後の試行。
	URL_INPUT,
	/// 利用者のlocal指定後の試行。
	LOCAL_INPUT,
} ;

/** @brief 未実行と定義不能を別にする比率状態。 */
enum class RatioState {
	/// 試行未実行のため率は存在しない。
	NOT_MEASURED,
	/// 実行済みだが分母0で率を定義できない。
	UNDEFINED,
	/// 元の件数に対する比率を計算できる。
	VALUE,
} ;

/** @brief 固定したdevice／OS一組の架空正解。 */
struct EvaluationCase {
	/// 実IDでない試験内のcase連番。
	unsigned								 identity{} ;
	/// 内容hashの一致へ相当する試験専用の内容token。
	unsigned								 contentToken{} ;
	/// 当該package内で適合するdriverの試験token。
	unsigned								 driverToken{} ;
	/// 明示した方針上の対象外理由。値なしは分母に残す。
	std::optional<CandidateAssessmentReason> excludedReason ;
} ;

/** @brief 一回の架空評価で提示された候補。Provider重複も元の行へ残す。 */
struct EvaluationCandidate {
	/// 提示先の架空case連番。
	unsigned			   caseIdentity{} ;
	/// 検証済み内容hashに相当する試験token。
	unsigned			   contentToken{} ;
	/// 同じpackage内のdriver識別token。
	unsigned			   driverToken{} ;
	/// 成功を別集計する入口。
	EvaluationEntry		   entry{EvaluationEntry::AUTOMATIC} ;
	/// Windows管理・標準INF・installerを分離する方式。
	CandidateInstallMethod method{CandidateInstallMethod::UNDETERMINED} ;
	/// 評価対象が適合確認済みと主張した場合true。
	bool				   claimedApplicable{} ;
	/// 通常アプリ内導入の内部fixtureが成立した場合true。実機適用ではない。
	bool				   internalReady{} ;
} ;

/** @brief 実測値ではなく、固定fixture内の元件数を保持する。 */
struct EvaluationCounts {
	/// 方針上対象の固定case数。失敗や未実装でも減らさない。
	std::size_t denominator{} ;
	/// 根拠を持つ方針上対象外のcase数。
	std::size_t excluded{} ;
	/// 対象入口の元の候補行数。Provider重複を残す。
	std::size_t rows{} ;
	/// 内容・driver・case・方式の重複を除いた候補数。
	std::size_t candidates{} ;
	/// 内容tokenが異なる取得単位の数。
	std::size_t packages{} ;
	/// 入口ごとに正解と一致した適合確認済みcase数。
	std::size_t discovered{} ;
	/// 適合済みと主張した評価候補数。
	std::size_t precisionDenominator{} ;
	/// 正解と一致する適合確認済み評価候補数。
	std::size_t precisionNumerator{} ;
	/// 標準INF方式のアプリ内導入が内部確認されたcase数。
	std::size_t standardReady{} ;
	/// Windows管理方式で内部確認されたcase数。
	std::size_t windowsReady{} ;
	/// 適合未確認を含むinstaller提案候補数。起動数ではない。
	std::size_t installerProposed{} ;
} ;

/**
 * @brief 固定集合に対して一入口の元件数を数える試験専用helper。
 * @param[in] cases 評価前に固定した架空device／OSと正解。
 * @param[in] candidates Provider重複を残した架空候補行。
 * @param[in] entry 集計する一入口。
 * @return 元件数。結果は実機再現率や全メーカー対応率を表さない。
 */
EvaluationCounts evaluateFixture( const std::span<const EvaluationCase>		cases,
								 const std::span<const EvaluationCandidate> candidates,
								 const EvaluationEntry						entry)
{
	EvaluationCounts result ;	// 本呼出し専用の合成件数。
	// 固定した全caseを数え、解析未対応や通信失敗を分母から引かない。
	for( const auto &known : cases) {
		// 方針上対象外は検出失敗とは別に数える。
		if( known.excludedReason) {
			++result.excluded ;
		} else {
			++result.denominator ;
		}
	}

	std::set<std::tuple<unsigned, unsigned, unsigned, CandidateInstallMethod>>
					   unique ;			// 候補評価単位。
	std::set<unsigned> packages ;		// 内容の同一性による取得単位。
	std::set<unsigned> discovered ;		// 同じcaseの複数候補を一つにする。
	std::set<unsigned> standardReady ;	// 標準方式のcase単位。
	std::set<unsigned> windowsReady ;	// Windows管理方式のcase単位。
	// 固定した一入口だけを評価し、元候補行は変更しない。
	for( const auto &candidate : candidates) {
		// 他入口の成功を今回入口の成功に流用しない。
		if( candidate.entry != entry) {
			continue ;
		}

		++result.rows ;
		// 同じcase・内容・driver・方式のProvider重複を精度の分母へ二重加算しない。
		if( !unique
				.emplace( candidate.caseIdentity, candidate.contentToken, candidate.driverToken,
						 candidate.method)
				.second) {
			continue ;
		}

		++result.candidates ;
		packages.insert( candidate.contentToken) ;
		const auto known   = std::find_if( cases.begin(), cases.end(), [&]( const auto &value) {
			  return value.identity == candidate.caseIdentity ;
		  }) ; // 同期探索中だけcandidateを借用する。
		const bool matches = known != cases.end() && !known->excludedReason &&
							 known->contentToken == candidate.contentToken &&
							 // 正解との一致。
							 known->driverToken == candidate.driverToken ;
		// Installerの提案を適合確認や起動成功に置き換えない。
		if( candidate.method == CandidateInstallMethod::OFFICIAL_INSTALLER) {
			++result.installerProposed ;
		}

		// 未確認候補を精度の正解と分母に加えない。
		if( !candidate.claimedApplicable) {
			continue ;
		}

		++result.precisionDenominator ;
		// 誤判定は精度の分母に残し、再現率の成功から除く。
		if( !matches) {
			continue ;
		}

		++result.precisionNumerator ;
		discovered.insert( candidate.caseIdentity) ;
		// 内部確認していない導入方式を成功に加算しない。
		if( !candidate.internalReady) {
			continue ;
		}

		// 標準INFとWindows管理を別に数え、installerを標準導入へ含めない。
		if( candidate.method == CandidateInstallMethod::STANDARD_INF) {
			standardReady.insert( candidate.caseIdentity) ;
		}
		// Windows管理の内部確認を標準INF方式とは別のcase集合へ残す。
		else if( candidate.method == CandidateInstallMethod::WINDOWS_MANAGED) {
			windowsReady.insert( candidate.caseIdentity) ;
		}
	}

	result.packages		 = packages.size() ;
	result.discovered	 = discovered.size() ;
	result.standardReady = standardReady.size() ;
	result.windowsReady	 = windowsReady.size() ;
	return result ;
}

/**
 * @brief 分母0・未実行を数値0や100パーセントへ補完しない。
 * @param[in] executed 試験の当該指標を実行した場合true。
 * @param[in] denominator 固定した当該指標の分母。
 * @return 数値計算を許可するか、未実行か、分母0かの状態。
 */
RatioState ratioState( const bool executed, const std::size_t denominator) noexcept
{
	// 実行前は分母が既知でも達成率を作らない。
	if( !executed) {
		return RatioState::NOT_MEASURED ;
	}

	return denominator == 0U ? RatioState::UNDEFINED : RatioState::VALUE ;
}

} // namespace

/** @see tests/unit/official_workflow_evaluation_tests.h */
void runOfficialWorkflowEvaluationTests( TestContext &context)
{
	const std::array<EvaluationCase, 8> cases{
		{{1U, 101U, 1U, {}},
		 {2U, 101U, 1U, {}},
		 {3U, 103U, 1U, {}},
		 {4U, 104U, 1U, {}},
		 {5U, 105U, 1U, {}},
		 {6U, 106U, 1U, {}},
		 {7U, 107U, 1U, {}},
		 {8U, 108U, 1U,
		  CandidateAssessmentReason::
			  FIRMWARE_PAYLOAD}}} ;	// 二port共通内容、通信失敗、解析未対応、未実装、別入口と方針対象外。
	const std::array<EvaluationCandidate, 7> candidates{
		{{1U, 101U, 1U, EvaluationEntry::AUTOMATIC, CandidateInstallMethod::STANDARD_INF, true,
		  true},
		 {1U, 101U, 1U, EvaluationEntry::AUTOMATIC, CandidateInstallMethod::STANDARD_INF, true,
		  true},
		 {2U, 101U, 1U, EvaluationEntry::AUTOMATIC, CandidateInstallMethod::WINDOWS_MANAGED, true,
		  true},
		 {3U, 999U, 1U, EvaluationEntry::AUTOMATIC, CandidateInstallMethod::STANDARD_INF, true,
		  false},
		 {4U, 104U, 1U, EvaluationEntry::AUTOMATIC, CandidateInstallMethod::OFFICIAL_INSTALLER,
		  false, false},
		 {6U, 106U, 1U, EvaluationEntry::URL_INPUT, CandidateInstallMethod::STANDARD_INF, true,
		  false},
		 {7U, 107U, 1U, EvaluationEntry::LOCAL_INPUT, CandidateInstallMethod::STANDARD_INF, true,
		  true}}} ;	// 一重複、一誤判定、未確認installer、別入口を含む固定出力。実packageではない。
	const auto automatic =
		// 自動のみ。
		evaluateFixture( cases, candidates, EvaluationEntry::AUTOMATIC) ;
	DRIVERCRATE_EXPECT( context, automatic.denominator == 7U && automatic.excluded == 1U) ;
	DRIVERCRATE_EXPECT( context, automatic.rows == 5U && automatic.candidates == 4U) ;
	DRIVERCRATE_EXPECT( context, automatic.packages == 3U && automatic.discovered == 2U) ;
	DRIVERCRATE_EXPECT( context,
					   automatic.precisionDenominator == 3U && automatic.precisionNumerator == 2U) ;
	DRIVERCRATE_EXPECT( context, automatic.standardReady == 1U && automatic.windowsReady == 1U) ;
	DRIVERCRATE_EXPECT( context, automatic.installerProposed == 1U) ;
	const auto url = evaluateFixture( cases, candidates, EvaluationEntry::URL_INPUT) ;	// 入力後のみ。
	const auto local =
		// 持込み後のみ。
		evaluateFixture( cases, candidates, EvaluationEntry::LOCAL_INPUT) ;
	DRIVERCRATE_EXPECT( context,
					   url.denominator == 7U && url.discovered == 1U && url.standardReady == 0U) ;
	DRIVERCRATE_EXPECT( context, local.denominator == 7U && local.discovered == 1U &&
									local.standardReady == 1U) ;
	const auto failed = evaluateFixture(
		cases, {}, EvaluationEntry::AUTOMATIC) ;	// 全通信・解析が失敗しても分母は同じ。
	DRIVERCRATE_EXPECT( context, failed.denominator == 7U && failed.discovered == 0U) ;
	DRIVERCRATE_EXPECT( context,
					   ratioState( true, failed.precisionDenominator) == RatioState::UNDEFINED) ;
	DRIVERCRATE_EXPECT( context, ratioState( false, failed.denominator) == RatioState::NOT_MEASURED) ;
	DRIVERCRATE_EXPECT( context, ratioState( false, 0U) == RatioState::NOT_MEASURED) ;
	DRIVERCRATE_EXPECT( context, ratioState( true, automatic.denominator) == RatioState::VALUE) ;
	DRIVERCRATE_EXPECT( context,
					   cases[7].excludedReason == CandidateAssessmentReason::FIRMWARE_PAYLOAD) ;
	// 未確認installerを誤って適合済みと主張した場合、その主張は精度評価の対象になる。
	auto claimed				 = candidates ;	// 元集合は不変のまま別試行を作る。
	claimed[4].claimedApplicable = true ;
	const auto claimedResult =
		// 実検証済みとの意味はない。
		evaluateFixture( cases, claimed, EvaluationEntry::AUTOMATIC) ;
	DRIVERCRATE_EXPECT( context, claimedResult.precisionDenominator == 4U &&
									claimedResult.precisionNumerator == 3U) ;
	DRIVERCRATE_EXPECT( context, claimedResult.standardReady == automatic.standardReady) ;
	// 正解と異なるdriverを同じpackageから選んでも適合精度の正解にしない。
	claimed[4].driverToken = 2U ;
	const auto wrongDriver = evaluateFixture(
		cases, claimed, EvaluationEntry::AUTOMATIC) ;	// 内容だけの一致を拒否する試行。
	DRIVERCRATE_EXPECT( context, wrongDriver.precisionDenominator == 4U &&
									wrongDriver.precisionNumerator == 2U) ;
	DRIVERCRATE_EXPECT( context, candidates.size() == 7U && !candidates[4].claimedApplicable) ;
}
} // namespace drivercrate::test
