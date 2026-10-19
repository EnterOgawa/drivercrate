//------------------------------------------------------------------------------
/**
 * @file official_driver_rank_tests.cpp
 * @brief 公式driver rank監査単体試験実装。
 * @version 01.01.00
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/10/13  Class未確定初回と独立INF/native GUIDの固定受入を追加。
 * </pre>
 *
 * @note 架空PnP IDとrankを使用し、実deviceまたはSetupAPIへ依存しません。
 */
//------------------------------------------------------------------------------

#include "official_driver_rank_tests.h"

#include "core/official_driver_rank.h"
#include "test_framework.h"

#include <cstdint>
#include <array>
#include <string_view>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 試験data定義。
//------------------------------------------------------------------------------

/**
 * @brief 一つのrank判定条件を変更可能な架空evidenceとして保持する。
 */
struct RankFixture {
	/// 現在deviceのsetup class。
	std::wstring				 deviceClass{L"Net"} ;
	/// Candidate INFのsetup class。
	std::wstring				 candidateClass{L"Net"} ;
	/// Device Hardware ID群。
	std::vector<std::wstring>	 hardwareIds{L"PCI\\VEN_1234&DEV_5678"} ;
	/// Device Compatible ID群。
	std::vector<std::wstring>	 compatibleIds{L"PCI\\VEN_1234"} ;
	/// INFのPnP ID群。
	std::vector<std::wstring>	 candidateIds{L"PCI\\VEN_1234&DEV_5678"} ;
	/// 現在driverの一致ID。
	std::wstring				 currentMatchingId{L"PCI\\VEN_1234&DEV_5678"} ;
	/// 現在driverのrank。
	std::optional<std::uint32_t> currentRank{0x00ff1000U} ;
	/// 候補rank。
	std::optional<std::uint32_t> candidateRank{0x00ff1000U} ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 試験fixtureをlifetime付きrank evidenceへ変換する。
 *
 * Pure evaluatorへ同じ既定値を渡し、各拒否条件だけを変更する。
 *
 * @param[in] fixture 本試験scope中有効なPnP IDとrank。
 * @return Fixtureの記憶領域を非所有参照するrank evidence。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialDriverRankEvidence makeEvidence( const RankFixture &fixture) noexcept
{
	return {
		.deviceClass			 = fixture.deviceClass,
		.candidateClass			 = fixture.candidateClass,
		.deviceHardwareIds		 = std::span<const std::wstring>( fixture.hardwareIds),
		.deviceCompatibleIds	 = std::span<const std::wstring>( fixture.compatibleIds),
		.candidateIds			 = std::span<const std::wstring>( fixture.candidateIds),
		.currentMatchingDeviceId = fixture.currentMatchingId,
		.currentRank			 = fixture.currentRank,
		.candidateRank			 = fixture.candidateRank,
	} ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_driver_rank_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOfficialDriverRankTests( TestContext &context)
{
	{
		RankFixture				fixture ;	// 同じID位置とrankを持つ受理fixture。
		OfficialDriverRankAudit audit ;		// 同等rankの監査結果。
		DRIVERCRATE_EXPECT( context, evaluateOfficialDriverRank( makeEvidence( fixture), audit)) ;
		DRIVERCRATE_EXPECT( context, audit.decision == OfficialDriverRankDecision::APPLICABLE) ;
		DRIVERCRATE_EXPECT( context, audit.currentRank == fixture.currentRank.value()) ;
		DRIVERCRATE_EXPECT( context, audit.candidateRank == fixture.candidateRank.value()) ;
	}
	{
		RankFixture fixture ;	// Compatible IDからHardware IDへ改善するfixture。
		fixture.currentMatchingId = fixture.compatibleIds.front() ;
		fixture.candidateRank	  = 0x00ff0000U ;
		OfficialDriverRankAudit audit ;	// 具体性とrank改善の監査結果。
		DRIVERCRATE_EXPECT( context, evaluateOfficialDriverRank( makeEvidence( fixture), audit)) ;
		DRIVERCRATE_EXPECT( context, audit.decision == OfficialDriverRankDecision::APPLICABLE) ;
		DRIVERCRATE_EXPECT( context, audit.currentPosition.kind == PnpIdentifierKind::COMPATIBLE_ID) ;
		DRIVERCRATE_EXPECT( context, audit.candidatePosition.kind == PnpIdentifierKind::HARDWARE_ID) ;
	}
	{
		RankFixture fixture ;	// Candidate classだけが異なる拒否fixture。
		fixture.candidateClass = L"Display" ;
		OfficialDriverRankAudit audit ;	// Class不一致の監査結果。
		DRIVERCRATE_EXPECT( context, evaluateOfficialDriverRank( makeEvidence( fixture), audit)) ;
		DRIVERCRATE_EXPECT( context, audit.decision == OfficialDriverRankDecision::CLASS_MISMATCH) ;
	}
	{
		RankFixture fixture ;	// Deviceへ一致しないcandidate IDの拒否fixture。
		fixture.candidateIds = {L"PCI\\VEN_ABCD&DEV_EF01"} ;
		OfficialDriverRankAudit audit ;	// Candidate不一致の監査結果。
		DRIVERCRATE_EXPECT( context, evaluateOfficialDriverRank( makeEvidence( fixture), audit)) ;
		DRIVERCRATE_EXPECT( context,
						   audit.decision == OfficialDriverRankDecision::CANDIDATE_NOT_MATCHED) ;
	}
	{
		RankFixture fixture ;	// Device一覧にない現在MatchingDeviceIdの拒否fixture。
		fixture.currentMatchingId = L"PCI\\VEN_ABCD&DEV_EF01" ;
		OfficialDriverRankAudit audit ;	// 現在一致根拠欠落の監査結果。
		DRIVERCRATE_EXPECT( context, evaluateOfficialDriverRank( makeEvidence( fixture), audit)) ;
		DRIVERCRATE_EXPECT( context,
						   audit.decision == OfficialDriverRankDecision::CURRENT_MATCH_UNAVAILABLE) ;
	}
	{
		RankFixture fixture ;	// 現在rankが欠落した拒否fixture。
		fixture.currentRank.reset() ;
		OfficialDriverRankAudit audit ;	// 現在rank欠落の監査結果。
		DRIVERCRATE_EXPECT( context, evaluateOfficialDriverRank( makeEvidence( fixture), audit)) ;
		DRIVERCRATE_EXPECT( context,
						   audit.decision == OfficialDriverRankDecision::CURRENT_RANK_UNAVAILABLE) ;
	}
	{
		RankFixture fixture ;	// Candidate rankが欠落した拒否fixture。
		fixture.candidateRank.reset() ;
		OfficialDriverRankAudit audit ;	// Candidate rank欠落の監査結果。
		DRIVERCRATE_EXPECT( context, evaluateOfficialDriverRank( makeEvidence( fixture), audit)) ;
		DRIVERCRATE_EXPECT( context, audit.decision ==
										OfficialDriverRankDecision::CANDIDATE_RANK_UNAVAILABLE) ;
	}
	{
		RankFixture fixture ;	// Hardware IDからCompatible IDへ弱くなる拒否fixture。
		fixture.candidateIds  = {fixture.compatibleIds.front()} ;
		fixture.candidateRank = 0x00ff0000U ;
		OfficialDriverRankAudit audit ;	// ID位置退行の監査結果。
		DRIVERCRATE_EXPECT( context, evaluateOfficialDriverRank( makeEvidence( fixture), audit)) ;
		DRIVERCRATE_EXPECT( context, audit.decision ==
										OfficialDriverRankDecision::IDENTIFIER_POSITION_REGRESSION) ;
	}
	{
		RankFixture fixture ;	// 同じID位置でidentifier scoreだけが悪化する拒否fixture。
		fixture.currentRank	  = 0x00ff0100U ;
		fixture.candidateRank = 0x00ff0200U ;
		OfficialDriverRankAudit audit ;	// Identifier score退行の監査結果。
		DRIVERCRATE_EXPECT( context, evaluateOfficialDriverRank( makeEvidence( fixture), audit)) ;
		DRIVERCRATE_EXPECT( context, audit.decision ==
										OfficialDriverRankDecision::IDENTIFIER_SCORE_REGRESSION) ;
	}
	{
		RankFixture fixture ;	// ID具体性は改善するがfull rankが悪化する拒否fixture。
		fixture.currentMatchingId = fixture.compatibleIds.front() ;
		fixture.currentRank		  = 0x00ff1000U ;
		fixture.candidateRank	  = 0x01ff0000U ;
		OfficialDriverRankAudit audit ;	// Full rank退行の監査結果。
		DRIVERCRATE_EXPECT( context, evaluateOfficialDriverRank( makeEvidence( fixture), audit)) ;
		DRIVERCRATE_EXPECT( context,
						   audit.decision == OfficialDriverRankDecision::OVERALL_RANK_REGRESSION) ;
	}
	{
		RankFixture fixture ;	// Hardware IDをcase違いで重複させた不正evidence fixture。
		fixture.hardwareIds.push_back( L"pci\\ven_1234&dev_5678") ;
		OfficialDriverRankAudit audit ;	// 入力構造拒否の監査結果。
		DRIVERCRATE_EXPECT( context, !evaluateOfficialDriverRank( makeEvidence( fixture), audit)) ;
		DRIVERCRATE_EXPECT( context, audit.decision == OfficialDriverRankDecision::INVALID_EVIDENCE) ;
	}
	{
		/** @brief Class観測と候補GUIDの有限入力と期待だけを保持します。 */
		struct ClassCase {
			/// 元Class観測の方式です。
			OfficialDriverRankDeviceClassState state ;
			/// 元Class名でありINFのClassで補完しません。
			std::wstring_view				   observed ;
			/// 検査したINFが返す候補GUIDです。
			std::wstring_view				   infGuid ;
			/// Windows互換一覧が返す候補GUIDです。
			std::wstring_view				   nativeGuid ;
			/// 完全なNO_DRIVER入力を持つ場合trueです。
			bool							   initial ;
			/// 候補PnP IDを一致させる場合trueです。
			bool							   matched ;
			/// Windows candidate rankを持つ場合trueです。
			bool							   ranked ;
			/// 入力構造の妥当性についての期待です。
			bool							   valid ;
			/// 純粋判定の期待区分です。
			OfficialDriverRankDecision		   decision ;
		} ;
		using State	   = OfficialDriverRankDeviceClassState ;	// 観測方式の簡潔な名前です。
		using Decision = OfficialDriverRankDecision ;			// 期待判断の簡潔な名前です。
		constexpr std::wstring_view NET =
			L"{4D36E972-E325-11CE-BFC1-08002BE10318}" ;	// 架空観測の通常Classです。
		constexpr std::wstring_view PORTS =
			L"{4D36E978-E325-11CE-BFC1-08002BE10318}" ;	// 不一致用の通常Classです。
		const std::array cases{
			ClassCase{State::NOT_PRESENT, L"", NET, NET, true, true, true, true,
					  Decision::APPLICABLE},
			ClassCase{State::UNKNOWN_CLASS, L"Unknown", NET, NET, true, true, true, true,
					  Decision::APPLICABLE},
			ClassCase{State::NOT_PRESENT, L"", NET, NET, false, true, true, false,
					  Decision::INVALID_EVIDENCE},
			ClassCase{State::NOT_PRESENT, L"", NET, L"", true, true, true, false,
					  Decision::INVALID_EVIDENCE},
			ClassCase{State::NOT_PRESENT, L"", NET, PORTS, true, true, true, false,
					  Decision::INVALID_EVIDENCE},
			ClassCase{State::NOT_PRESENT, L"", L"not-guid", L"not-guid", true, true, true, false,
					  Decision::INVALID_EVIDENCE},
			ClassCase{State::NOT_PRESENT, L"", L"{00000000-0000-0000-0000-000000000000}",
					  L"{00000000-0000-0000-0000-000000000000}", true, true, true, false,
					  Decision::INVALID_EVIDENCE},
			ClassCase{State::UNKNOWN_CLASS, L"Unknown", L"{4D36E97E-E325-11CE-BFC1-08002BE10318}",
					  L"{4D36E97E-E325-11CE-BFC1-08002BE10318}", true, true, true, false,
					  Decision::INVALID_EVIDENCE},
			ClassCase{State::NOT_PRESENT, L"", NET, NET, true, true, false, true,
					  Decision::CANDIDATE_RANK_UNAVAILABLE},
			ClassCase{State::NOT_PRESENT, L"", NET, NET, true, false, true, true,
					  Decision::CANDIDATE_NOT_MATCHED},
			ClassCase{State::KNOWN_CLASS, L"Ports", NET, NET, true, true, true, true,
					  Decision::CLASS_MISMATCH},
		} ; // Code前の固定九分類を不正/zero/Unknownの三GUIDへ分離した11入力です。
		// 正常二件と拒否九件を全て実行し、不正状態を分母から除きません。
		for( const auto &testCase : cases) {
			RankFixture fixture ;	// 元のIDとcandidate rankを独立に所有します。
			// 具体的なPnP不一致だけを元ID集合へ与えます。
			if( !testCase.matched) {
				fixture.candidateIds = {L"PCI\\VEN_ABCD&DEV_EF01"} ;
			}

			auto evidence =
				// 同scopeの純粋入力で実Windowsの成功を生成しません。
				makeEvidence( fixture) ;
			evidence.deviceClass			  = testCase.observed ;
			evidence.deviceClassState		  = testCase.state ;
			evidence.candidateInfClassGuid	  = testCase.infGuid ;
			evidence.candidateNativeClassGuid = testCase.nativeGuid ;
			// NO_DRIVERは架空current rank/Matching IDを持たない独立した入力です。
			if( testCase.initial) {
				evidence.currentState			 = OfficialDriverRankCurrentState::NO_DRIVER ;
				evidence.currentMatchingDeviceId = {} ;
				evidence.currentRank.reset() ;
			}

			// 候補rank欠損をClassの正常性から補完しません。
			if( !testCase.ranked) {
				evidence.candidateRank.reset() ;
			}

			OfficialDriverRankAudit audit ;	// 原判定の非機密値だけです。
			DRIVERCRATE_EXPECT( context,
							   evaluateOfficialDriverRank( evidence, audit) == testCase.valid) ;
			DRIVERCRATE_EXPECT( context, audit.decision == testCase.decision) ;
		}
	}
}

} // namespace drivercrate::test
