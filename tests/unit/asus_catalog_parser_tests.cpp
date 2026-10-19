//------------------------------------------------------------------------------
/**
 * @file asus_catalog_parser_tests.cpp
 * @brief ASUS公式Web parser単体試験実装。
 * @version 01.06.01
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
 * Ver.01.01.00 Shunji Ogawa  2026/09/20  対象外0 KBとcategory限定解析の回帰を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/20  個別不正の隔離と全体構造拒否の区別を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/28  収集専用の同一store所属・公開ID・行理由のfixtureを追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/28  再ラベル拒否・参照と日付・件数境界・旧指紋を検証。
 * Ver.01.05.00 Shunji Ogawa  2026/09/28  複数候補・chip欠測・300対象の三状態fixtureを追加。
 * Ver.01.06.00 Shunji Ogawa  2026/09/28  制御付きcore全checkpointの停止・例外fixtureを追加。
 * Ver.01.06.01 Shunji Ogawa  2026/10/02  AI依存を撤去し非AI共通処理と試験を維持。
 * </pre>
 *
 * @note 架空Nuxt flattened JSONだけを使用し、model、OS、origin、hashの拒否を確認します。Payloadを取得または実行しません。
 */
//------------------------------------------------------------------------------

#include "asus_catalog_parser_tests.h"
#include "collector_parser_test_control.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/asus_catalog_parser.h"
#include "platform/asus_collector_target_assessment.h"
#include "platform/asus_network_record_adapter.h"
#include "platform/official_record_utilities.h"
#include "test_framework.h"

#include <string>
#include <array>
#include <utility>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 試験data定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view SHA256 =
	L"DEF73029462651E78B30791C9E6EDB2E99F86755B2334F942612A50467761CB5" ;
// ASUS URL境界の解析試験に使用する架空配布path。
constexpr std::wstring_view PAYLOAD_PATH =
	L"/pub/ASUS/mb/04LAN/DRV_LAN_Fictional_W11_64_V11252750919.zip" ;

//------------------------------------------------------------------------------
// 内部試験関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 外部JSON libraryを使わず固定安全文字列だけでfixtureを作る。
 *
 * @param[in] model 架空ASUS製品名。
 * @param[in] opaqueId 架空driver record ID。
 * @param[in] path 架空Global download相対path。
 * @param[in] sha256 架空公開SHA-256。
 * @param[in] duplicate trueの場合は同じrecord参照を二回含める。
 * @return ASUS pageと同型のNuxt flattened JSON付きHTML。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring makePage( const std::wstring_view model, const std::wstring_view opaqueId,
									const std::wstring_view path, const std::wstring_view sha256,
									const bool duplicate)
{
	std::wstring html =	// Parserの一意なNuxt script markerを持つ架空HTML。
		LR"(<html><script type="application/json" data-ssr="true" id="__NUXT_DATA__">)" ;
	html += LR"([{"model":1,"productId":2,"downloadUrl":3},")" ;
	html += model ;
	html += LR"(",123,"",{"Id":5,"Name":6},"52","Windows 11 64-bit",)" ;
	html += LR"({"Name":8,"Count":9,"Files":10,"IsDescShow":11},)" ;
	html += LR"("LAN",1,[12)" ;
	// 重複検出の試験では同じ配布recordの参照をfixtureへ追加する。
	if( duplicate) {
		html += L",12" ;
	}

	html += LR"(],false,{"Id":13,"Version":14,"Title":15,"FileSize":16,)" ;
	html += LR"("ReleaseDate":17,"DownloadUrl":18,"sha256":20},")" ;
	html += opaqueId ;
	html += LR"(","1125.27.50.919","Fictional ASUS LAN Driver","14.67 MB",)" ;
	html += LR"("2025/12/31",{"Global":19,"China":3},")" ;
	html += path ;
	html += LR"(",")" ;
	html += sha256 ;
	html += LR"("]</script></html>)" ;
	return html ;
}

/**
 * @brief 同一pdSupportStoreから製品、OS、LANを参照する収集専用fixtureを作ります。
 * @param[in] opaqueId 固定7 fieldの架空ASUS entry ID。
 * @param[in] path 架空のASUS CDN相対path。
 * @param[in] hash 架空の公開SHA-256。
 * @return 参照indexを固定した有限Nuxt HTML。
 */
[[nodiscard]] std::wstring makeCollectorPage( const std::wstring_view opaqueId,
											 const std::wstring_view path,
											 const std::wstring_view hash)
{
	std::wstring html =
		LR"(<html><script type="application/json" id="__NUXT_DATA__">)" ;	// 同一store fixture。
	html +=
		LR"([["ShallowReactive",1],{"pinia":2},["Reactive",3],{"pdSupportStore":4},{"productSupportCheckModelExist":5,"productSupportOS":9,"productSupportDriver":13},{"model":6,"productId":7,"downloadUrl":8},"PRIME TEST",123,"",[10],{"Id":11,"Name":12},"52","Windows 11 64-bit",{"Model":6,"Count":14,"Obj":15},1,[16],{"Name":17,"Count":14,"Files":18,"IsDescShow":19},"LAN",[20],false,{"Id":21,"Version":22,"Title":23,"FileSize":24,"ReleaseDate":25,"DownloadUrl":26,"sha256":28},")" ;
	html += opaqueId ;
	html +=
		LR"(","1125.27.50.919","Fictional ASUS LAN Driver","14.67 MB","2025/12/31",{"Global":27},")" ;
	html += path ;
	html += LR"(",")" ;
	html += hash ;
	html += LR"("]</script></html>)" ;
	return html ;
}

/**
 * @brief 行数だけを変えた一意なLAN一覧を組み立てます。
 * @param[in] count 配布行数。試験内では最大17。
 * @return 同じ公開modelとOSを持つ有限Nuxt HTML。
 */
[[nodiscard]] std::wstring makeCollectorRows( const std::size_t count)
{
	std::wstring html =
		LR"(<html><script type="application/json" id="__NUXT_DATA__">)" ;	// 架空一覧。
	html +=
		LR"([["ShallowReactive",1],{"pinia":2},["Reactive",3],{"pdSupportStore":4},{"productSupportCheckModelExist":5,"productSupportOS":9,"productSupportDriver":13},{"model":6,"productId":7,"downloadUrl":8},"PRIME TEST",123,"",[10],{"Id":11,"Name":12},"52","Windows 11 64-bit",{"Model":6,"Count":14,"Obj":15},)" ;
	html += std::to_wstring( count) +
			LR"(,[16],{"Name":17,"Count":14,"Files":18,"IsDescShow":19},"LAN",[)" ;
	// 各recordを9要素の独立したslotへ参照します。
	for( std::size_t index = 0U; index < count; ++index) {
		// 二行目以降にだけseparatorを挿入します。
		if( index != 0U) {
			html += L"," ;
		}

		html += std::to_wstring( 20U + index * 9U) ;
	}

	html += L"],false" ;
	// 配布URLとopaque IDは同じ一意file名を持ちます。
	for( std::size_t index = 0U; index < count; ++index) {
		const auto slot = 20U + index * 9U ;	// この行の最初の参照位置。
		const auto file =
			L"DRV_LAN_Fictional_" + std::to_wstring( index) + L".zip" ;	// 架空basename。
		html += L",{\"Id\":" + std::to_wstring( slot + 1U) + L",\"Version\":" +
				std::to_wstring( slot + 2U) + L",\"Title\":" + std::to_wstring( slot + 3U) +
				L",\"FileSize\":" + std::to_wstring( slot + 4U) + L",\"ReleaseDate\":" +
				std::to_wstring( slot + 5U) + L",\"DownloadUrl\":" + std::to_wstring( slot + 6U) +
				L",\"sha256\":" + std::to_wstring( slot + 8U) + L"},\"1@66@7@8@52@5@" + file +
				L"\",\"1.0\",\"Realtek LAN Driver\",\"1 MB\",\"2025/12/31\",{\"Global\":" +
				std::to_wstring( slot + 7U) + L"},\"/pub/ASUS/mb/04LAN/" + file + L"\",\"" +
				std::wstring( SHA256) + L"\"" ;
	}

	return html + L"]</script></html>" ;
}

/**
 * @brief 収集専用route、公開identity、第一理由と旧経路からの分離を検査します。
 * @param[in,out] context Assertion集計先。
 */
void testCollectorIdentity( TestContext &context)
{
	const std::wstring opaqueId =
		L"1@66@7@8@52@5@DRV_LAN_Fictional_W11_64_V11252750919.zip" ;				// 架空entry ID。
	const std::wstring html = makeCollectorPage( opaqueId, PAYLOAD_PATH, SHA256) ;	// 同一store本文。
	AsusCollectorPageResult result ;												// 製品identityと対象LANの行理由。
	constexpr std::uint64_t LIMIT = 128ULL * 1024ULL * 1024ULL ;					// 既存の有限profile。
	// 同一store内の完全な行から公開IDと一件のZIPを得る。
	DRIVERCRATE_EXPECT( context,
					   parseAsusCollectorDriverPageHtml( html, L"prime test", L"Windows 11 64-bit",
														L"LAN", LIMIT, result)) ;
	DRIVERCRATE_EXPECT(
		context,
		result.structurallyValid && result.targetModelMatches && result.productId == L"123" &&
			result.modelComparisonKey == L"PRIME TEST" && result.osId == L"52" &&
			result.sliceStatus == AsusCollectorSliceStatus::ACCEPTED && result.seen == 1U &&
			result.entries.size() == 1U &&
			result.reasonCounts[static_cast<std::size_t>( AsusCollectorRowReason::ACCEPTED)] == 1U) ;

	AsusSupportPageRequest request ;	// 同じ公開modelから再構築した公式起点。
	DRIVERCRATE_EXPECT( context, makeAsusPublicModelSupportPageRequest(
									L"PRIME TEST", L"Windows 11 64-bit", request)) ;
	std::vector<OfficialCollectorRecordCandidate> candidates ;	// Worker内だけの秘密URL付き候補。
	DRIVERCRATE_EXPECT( context, adaptAsusCollectorNetworkRecordCandidates(
									result, request, 1'780'000'000ULL, candidates)) ;
	DRIVERCRATE_EXPECT( context, candidates.size() == 1U &&
									candidates.front().parserId == L"asus-catalog-record-v1" &&
									candidates.front().recordKey == L"PRIME TEST|" + opaqueId) ;

	const OfficialSourceEvidence			root{	// 旧callerの架空root証拠。
												 .scanSessionId = 711U,
												 .acquisitionId = 1U,
												 .providerId	= std::wstring{ASUS_PROVIDER_ID},
												 .policyId = std::wstring{ASUS_OFFICIAL_SOURCE_POLICY_ID},
												 .resourceId =
											 std::wstring{OFFICIAL_PRIMARY_METADATA_RESOURCE_ID},
												 .redirectCount		  = 0U,
												 .originPolicyIndices = {0U},
												 .acquisition = MeasurementAcquisition::NETWORK_BODY,
												 .bodyAcquiredUtcSeconds	= 100U,
												 .originValidatedUtcSeconds = 101U,
												 .cachePermitted			= false} ;
	std::vector<OfficialDistributionRecord> normalRecords ;	// 通常recordのgolden対照。
	DRIVERCRATE_EXPECT( context, adaptAsusNetworkDistributionRecords(
									result.entries, request, AsusNetworkRecordTarget::CATALOG, root,
									1'780'000'000ULL, normalRecords, L"LAN", LIMIT)) ;
	OfficialDistributionRecordEvidence normalEvidence ;	// 旧指紋を固定する検証出力。
	DRIVERCRATE_EXPECT( context, normalRecords.size() == 1U &&
									validateOfficialDistributionRecord( normalRecords.front(),
																	   normalEvidence) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   officialRecordFingerprint( normalEvidence) ==
						   "419b8683e5914a720129ca717aa9ce2f5c55d8f0cc3f1ddff69faae45afe82b0") ;
	AsusSupportPageRequest wrongRequest ;	// 解析後に別製品を渡しても再ラベルしません。
	DRIVERCRATE_EXPECT( context, makeAsusPublicModelSupportPageRequest(
									L"PRIME OTHER", L"Windows 11 64-bit", wrongRequest)) ;
	DRIVERCRATE_EXPECT( context, !adaptAsusCollectorNetworkRecordCandidates(
									result, wrongRequest, 1'780'000'000ULL, candidates)) ;

	// 別modelは同一storeの公開矛盾として残し、recordを返さない。
	DRIVERCRATE_EXPECT( context,
					   parseAsusCollectorDriverPageHtml( html, L"PRIME OTHER", L"Windows 11 64-bit",
														L"LAN", LIMIT, result)) ;
	DRIVERCRATE_EXPECT( context, result.structurallyValid && !result.targetModelMatches &&
									result.entries.empty()) ;
	DRIVERCRATE_EXPECT( context, !adaptAsusCollectorNetworkRecordCandidates(
									result, request, 1'780'000'000ULL, candidates)) ;

	// Root外の同形categoryは公式sliceに含めない。
	std::wstring unrelated = html ;
	const auto	 closing   = unrelated.find( L"]</script>") ;	// JSON終端位置。
	DRIVERCRATE_EXPECT( context, closing != std::wstring::npos) ;
	// 完全なroot末尾だけを書き換えて無所属categoryを追加する。
	if( closing != std::wstring::npos) {
		unrelated.insert( closing, LR"(,{"Name":17,"Count":14,"Files":18,"IsDescShow":19})") ;
		DRIVERCRATE_EXPECT( context, parseAsusCollectorDriverPageHtml( unrelated, L"PRIME TEST",
																	 L"Windows 11 64-bit", L"LAN",
																	 LIMIT, result)) ;
		DRIVERCRATE_EXPECT( context, result.entries.size() == 1U && result.seen == 1U) ;
	}

	// 型違いproductIdと復号後に重複するpropertyを拒否する。
	std::wstring badId = html ;
	badId.replace( badId.find( L",123,"), 5U, L",\"123\",") ;
	DRIVERCRATE_EXPECT( context,
					   !parseAsusCollectorDriverPageHtml( badId, L"PRIME TEST", L"Windows 11 64-bit",
														 L"LAN", LIMIT, result)) ;
	std::wstring duplicate = html ;	// Escape表記の重複key。
	duplicate.replace( duplicate.find( L"\"productId\":7"), 13U,
					  L"\"productId\":7,\"product\\u0049d\":7") ;
	DRIVERCRATE_EXPECT( context, !parseAsusCollectorDriverPageHtml( duplicate, L"PRIME TEST",
																  L"Windows 11 64-bit", L"LAN",
																  LIMIT, result)) ;
	std::wstring embeddedNul = html ;	// 制御文字を含む製品名。
	embeddedNul.replace( embeddedNul.find( L"\"PRIME TEST\""), 12U, L"\"PRIME\\u0000TEST\"") ;
	DRIVERCRATE_EXPECT( context, !parseAsusCollectorDriverPageHtml( embeddedNul, L"PRIME TEST",
																  L"Windows 11 64-bit", L"LAN",
																  LIMIT, result)) ;

	// OS未掲載と同一storeのCount不一致は別の結果を返す。
	std::wstring noOs = html ;
	noOs.replace( noOs.find( L"[10]"), 4U, L"[]") ;
	DRIVERCRATE_EXPECT( context,
					   parseAsusCollectorDriverPageHtml( noOs, L"PRIME TEST", L"Windows 11 64-bit",
														L"LAN", LIMIT, result)) ;
	DRIVERCRATE_EXPECT( context, result.sliceStatus == AsusCollectorSliceStatus::OS_NOT_LISTED &&
									result.entries.empty()) ;
	std::wstring badCount = html ;	// 合計数だけの不正。
	badCount.replace( badCount.find( L"},1,[16]"), 8U, L"},2,[16]") ;
	DRIVERCRATE_EXPECT( context, !parseAsusCollectorDriverPageHtml( badCount, L"PRIME TEST",
																  L"Windows 11 64-bit", L"LAN",
																  LIMIT, result)) ;

	// 別OS、hash未掲載、形式外、予算超過を第一理由で分ける。
	std::wstring otherOs = makeCollectorPage(
		L"1@66@7@8@45@5@DRV_LAN_Fictional_W11_64_V11252750919.zip", PAYLOAD_PATH, SHA256) ;
	DRIVERCRATE_EXPECT( context, parseAsusCollectorDriverPageHtml( otherOs, L"PRIME TEST",
																 L"Windows 11 64-bit", L"LAN",
																 LIMIT, result)) ;
	DRIVERCRATE_EXPECT(
		context,
		result.reasonCounts[static_cast<std::size_t>( AsusCollectorRowReason::OTHER_OS)] == 1U &&
			result.entries.empty()) ;
	const std::wstring noHash = makeCollectorPage( opaqueId, PAYLOAD_PATH, L"") ;	// Hash欠測。
	DRIVERCRATE_EXPECT( context,
					   parseAsusCollectorDriverPageHtml( noHash, L"PRIME TEST", L"Windows 11 64-bit",
														L"LAN", LIMIT, result)) ;
	DRIVERCRATE_EXPECT(
		context,
		result.reasonCounts[static_cast<std::size_t>( AsusCollectorRowReason::HASH_NOT_PUBLISHED)] ==
			1U) ;
	std::wstring cabId = opaqueId ;			// 対象外CABを指すID。
	std::wstring cabPath( PAYLOAD_PATH) ;	// IDと一致する拡張子のpath。
	cabId.replace( cabId.size() - 4U, 4U, L".cab") ;
	cabPath.replace( cabPath.size() - 4U, 4U, L".cab") ;
	DRIVERCRATE_EXPECT( context, parseAsusCollectorDriverPageHtml(
									makeCollectorPage( cabId, cabPath, SHA256), L"PRIME TEST",
									L"Windows 11 64-bit", L"LAN", LIMIT, result)) ;
	DRIVERCRATE_EXPECT(
		context,
		result.reasonCounts[static_cast<std::size_t>( AsusCollectorRowReason::UNSUPPORTED_FORMAT)] ==
			1U) ;
	DRIVERCRATE_EXPECT( context, parseAsusCollectorDriverPageHtml(
									html, L"PRIME TEST", L"Windows 11 64-bit", L"LAN", 1U, result)) ;
	DRIVERCRATE_EXPECT(
		context,
		result.reasonCounts[static_cast<std::size_t>( AsusCollectorRowReason::BUDGET_EXCEEDED)] ==
			1U) ;
}

/**
 * @brief 収集の参照・表示・件数境界を決定的に検査します。
 * @param[in,out] context Assertion集計先。
 */
void testCollectorCrosscut( TestContext &context)
{
	constexpr std::uint64_t LIMIT	 = 128ULL * 1024ULL * 1024ULL ;	// 既存取得検査profile。
	const auto				baseline = makeCollectorRows( 1U) ;		// 一行だけの正常store。
	AsusCollectorPageResult parsed ;								// 各変異で初期化される結果。
	// 有効recordの有限上限では全件採用、直後では切捨てず専用状態にします。
	for( const std::size_t count : {0U, 16U, 17U}) {
		DRIVERCRATE_EXPECT(
			context, parseAsusCollectorDriverPageHtml( makeCollectorRows( count), L"PRIME TEST",
													  L"Windows 11 64-bit", L"LAN", LIMIT, parsed)) ;
		DRIVERCRATE_EXPECT(
			context, parsed.sliceStatus ==
						 (count == 0U ? AsusCollectorSliceStatus::EMPTY
									  : (count == 16U ? AsusCollectorSliceStatus::ACCEPTED
													  : AsusCollectorSliceStatus::RECORD_LIMIT))) ;
		DRIVERCRATE_EXPECT( context, parsed.entries.size() == (count == 16U ? 16U : 0U)) ;
	}

	// Number型・有限整数条件を独立に逸脱させます。
	for( const std::wstring_view id :
		{L"0", L"-1", L"1.5", L"9007199254740992", L"true", L"\"123\""}) {
		auto bad = baseline ;	// 製品ID以外は同一の本文。
		bad.replace( bad.find( L",123,"), 5U, L"," + std::wstring( id) + L",") ;
		DRIVERCRATE_EXPECT( context, !parseAsusCollectorDriverPageHtml( bad, L"PRIME TEST",
																	  L"Windows 11 64-bit", L"LAN",
																	  LIMIT, parsed)) ;
		DRIVERCRATE_EXPECT( context, parsed.entries.empty() && !parsed.structurallyValid) ;
	}

	// 参照cycle、別driver model、名前への秘密形状は全体拒否にします。
	for( const auto &[before, after] :
		std::array<std::pair<std::wstring_view, std::wstring_view>, 5U>{
			{{L"\"pinia\":2", L"\"pinia\":1"},
			 {L"\"Model\":6", L"\"Model\":12"},
			 {L"PRIME TEST", L"VEN_1234"},
			 {L"PRIME TEST", L"folder/file"},
			 {L"PRIME TEST", L"PRIME\\u0085TEST"}}}) {
		auto bad = baseline ;	// 一箇所だけの変異。
		bad.replace( bad.find( before), before.size(), after) ;
		DRIVERCRATE_EXPECT( context, !parseAsusCollectorDriverPageHtml( bad, L"PRIME TEST",
																	  L"Windows 11 64-bit", L"LAN",
																	  LIMIT, parsed)) ;
	}

	// 公開行値・日付・ID・path・hash異常は個別REJECTED_ROWに残します。
	for( const auto &[before, after] :
		std::array<std::pair<std::wstring_view, std::wstring_view>, 6U>{
			{{L"Realtek LAN Driver", L"vid_1234"},
			 {L"Realtek LAN Driver", L"folder/file"},
			 {L"2025/12/31", L"2025/02/30"},
			 {L"1@66@7@8@52@5@", L"1@66@7@8@52@"},
			 {L"/pub/ASUS/mb/04LAN/", L"/pub/ASUS/../"},
			 {SHA256, L"xyz"}}}) {
		auto bad = baseline ;	// 行内だけの異常。
		bad.replace( bad.find( before), before.size(), after) ;
		DRIVERCRATE_EXPECT( context, parseAsusCollectorDriverPageHtml( bad, L"PRIME TEST",
																	 L"Windows 11 64-bit", L"LAN",
																	 LIMIT, parsed)) ;
		DRIVERCRATE_EXPECT( context, parsed.entries.empty() && parsed.seen == 1U &&
										parsed.reasonCounts[static_cast<std::size_t>(
											AsusCollectorRowReason::REJECTED_ROW)] == 1U) ;
	}

	// Boardとcomponentのメーカー名を混同せず、LANの公開行を残します。
	DRIVERCRATE_EXPECT( context, parseAsusCollectorDriverPageHtml( baseline, L"prime test",
																 L"Windows 11 64-bit", L"LAN",
																 LIMIT, parsed)) ;
	DRIVERCRATE_EXPECT( context, parsed.targetModelMatches && parsed.entries.size() == 1U &&
									parsed.entries[0].title == L"Realtek LAN Driver") ;
	// Revision語は削らず別製品とします。
	DRIVERCRATE_EXPECT( context, parseAsusCollectorDriverPageHtml( baseline, L"PRIME TEST D4",
																 L"Windows 11 64-bit", L"LAN",
																 LIMIT, parsed)) ;
	DRIVERCRATE_EXPECT( context, !parsed.targetModelMatches && parsed.entries.empty()) ;
}

/**
 * @brief 同一storeの複数候補と公開対象を三状態へ照合します。
 * @param[in,out] context Assertion集計先。
 */
void testCollectorTargetAssessment( TestContext &context)
{
	constexpr std::uint64_t LIMIT	   = 128ULL * 1'024ULL * 1'024ULL ;				// 既存ZIP予算。
	std::wstring			html	   = makeCollectorRows( 2U) ;					// 同一boardの二LAN配布行。
	const auto				firstTitle = html.find( L"Realtek LAN Driver") ;		// 一行目の表示名。
	const auto secondTitle = html.find( L"Realtek LAN Driver", firstTitle + 1U) ;	// 二行目。
	DRIVERCRATE_EXPECT( context, firstTitle != html.npos && secondTitle != html.npos) ;
	// 異なるcomponent名を持つ二行でもboardのmakerはASUSです。
	if( secondTitle != html.npos) {
		html.replace( secondTitle, std::wstring_view{L"Realtek LAN Driver"}.size(),
					 L"Marvell LAN Driver") ;
	}

	AsusCollectorPageResult page ;	// 同一Nuxt storeの解析結果。
	DRIVERCRATE_EXPECT( context,
					   parseAsusCollectorDriverPageHtml( html, L"PRIME TEST", L"Windows 11 64-bit",
														L"LAN", LIMIT, page)) ;
	AsusSupportPageRequest request ;	// 本文に対応するcanonical要求。
	DRIVERCRATE_EXPECT( context, makeAsusPublicModelSupportPageRequest(
									L"PRIME TEST", L"Windows 11 64-bit", request)) ;
	std::vector<OfficialCollectorRecordCandidate> candidates ;	// 証拠未発行の二record。
	DRIVERCRATE_EXPECT( context, adaptAsusCollectorNetworkRecordCandidates(
									page, request, 1'780'000'000ULL, candidates)) ;
	DRIVERCRATE_EXPECT( context, candidates.size() == 2U &&
									page.entries[0].title == L"Realtek LAN Driver" &&
									page.entries[1].title == L"Marvell LAN Driver") ;
	const std::array<AsusCollectorTargetQuery, 13U> targets{{
		{L"matched", L"ASUS", L"prime  test", L"MAINBOARD", L"LAN", L"Windows 11 64-bit", L"x64",
		 L""},
		{L"chip", L"ASUS", L"PRIME TEST", L"MAINBOARD", L"LAN", L"Windows 11 64-bit", L"x64",
		 L"Realtek"},
		{L"revision", L"ASUS", L"PRIME TEST D4", L"MAINBOARD", L"Wi-Fi", L"Windows 11 64-bit",
		 L"x64", L""},
		{L"component", L"Realtek", L"PRIME TEST", L"MAINBOARD", L"LAN", L"Windows 11 64-bit",
		 L"x64", L""},
		{L"kind", L"ASUS", L"PRIME TEST", L"NETWORK_ADAPTER", L"LAN", L"Windows 11 64-bit", L"x64",
		 L""},
		{L"purpose", L"ASUS", L"PRIME TEST", L"MAINBOARD", L"Wi-Fi", L"Windows 11 64-bit", L"x64",
		 L""},
		{L"os", L"ASUS", L"PRIME TEST", L"MAINBOARD", L"Other", L"Windows 10 64-bit", L"x64", L""},
		{L"arch", L"ASUS", L"PRIME TEST", L"MAINBOARD", L"LAN", L"Other", L"arm64", L""},
		{L"invalid", L"ASUS", L"https://bad.example", L"MAINBOARD", L"Wi-Fi", L"Windows 11 64-bit",
		 L"x64", L""},
		{L"purpose-unknown", L"ASUS", L"PRIME TEST", L"MAINBOARD", L"Other", L"Windows 11 64-bit",
		 L"x64", L""},
		{L"os-unknown", L"ASUS", L"PRIME TEST", L"MAINBOARD", L"LAN", L"Windows X", L"x64", L""},
		{L"arch-unknown", L"ASUS", L"PRIME TEST", L"MAINBOARD", L"LAN", L"Windows 11 64-bit",
		 L"Other", L""},
		{L"product-priority", L"Intel", L"PRIME TEST", L"MAINBOARD", L"LAN", L"Windows 10 64-bit",
		 L"arm64", L""},
	}} ; // 各状態の固定oracle。
	const std::array								expectedReasons{
		   AsusCollectorTargetReason::MATCHED,
		   AsusCollectorTargetReason::CHIP_UNKNOWN,
		   AsusCollectorTargetReason::PRODUCT_CONFLICT,
		   AsusCollectorTargetReason::PRODUCT_CONFLICT,
		   AsusCollectorTargetReason::PRODUCT_CONFLICT,
		   AsusCollectorTargetReason::PURPOSE_CONFLICT,
		   AsusCollectorTargetReason::OS_CONFLICT,
		   AsusCollectorTargetReason::ARCHITECTURE_CONFLICT,
		   AsusCollectorTargetReason::INVALID_QUERY,
		   AsusCollectorTargetReason::PURPOSE_UNKNOWN,
		   AsusCollectorTargetReason::OS_UNKNOWN,
		   AsusCollectorTargetReason::ARCHITECTURE_UNKNOWN,
		   AsusCollectorTargetReason::PRODUCT_CONFLICT} ;	// 順序対応する第一理由。
	std::vector<AsusCollectorTargetAssessment> assessed ;	// URLを持たない所有結果。
	DRIVERCRATE_EXPECT( context, inspectAsusCollectorTargets( page, candidates, targets, assessed)) ;
	DRIVERCRATE_EXPECT( context, assessed.size() == targets.size()) ;
	// 二候補を一件へ縮退させず、同じpageの各ordinalを保持します。
	for( std::size_t index = 0U; index < assessed.size() && index < targets.size(); ++index) {
		const auto expectedState = index == 0U
									   ? AsusCollectorTargetState::MATCH
									   : (index == 1U || (index >= 8U && index <= 11U)
											  ? AsusCollectorTargetState::UNKNOWN
											  : AsusCollectorTargetState::NO_MATCH) ;	// 固定状態。
		DRIVERCRATE_EXPECT( context, assessed[index].reason == expectedReasons[index] &&
										assessed[index].state == expectedState) ;
		// 破損queryだけは公式product identity・候補番号を公開結果へ付けません。
		if( index != 8U) {
			DRIVERCRATE_EXPECT( context, assessed[index].productId == L"123" &&
											assessed[index].candidateOrdinals ==
												std::vector<std::uint32_t>( {0U, 1U})) ;
		} else {
			DRIVERCRATE_EXPECT( context, assessed[index].productId.empty() &&
											assessed[index].candidateOrdinals.empty()) ;
		}
	}

	// 候補欠測でも公開製品と対象の明示矛盾は残します。
	const std::array sparse{targets[0], targets[2]} ;	// 一致／別revisionの対照。
	DRIVERCRATE_EXPECT( context, inspectAsusCollectorTargets( page, {}, sparse, assessed)) ;
	DRIVERCRATE_EXPECT(
		context, assessed.size() == 2U && assessed[0].state == AsusCollectorTargetState::UNKNOWN &&
					 assessed[0].reason == AsusCollectorTargetReason::RECORD_UNKNOWN &&
					 assessed[0].candidateOrdinals.empty() &&
					 assessed[1].state == AsusCollectorTargetState::NO_MATCH &&
					 assessed[1].reason == AsusCollectorTargetReason::PRODUCT_CONFLICT) ;
	// OS選択肢がない場合は要求OS名をsource証拠として扱いません。
	std::wstring noOs = html ;	// 同じpageからOS参照だけを除いた入力。
	noOs.replace( noOs.find( L"[10]"), 4U, L"[]") ;
	DRIVERCRATE_EXPECT( context,
					   parseAsusCollectorDriverPageHtml( noOs, L"PRIME TEST", L"Windows 11 64-bit",
														L"LAN", LIMIT, page)) ;
	auto missingOsQuery	   = targets[6] ;	// 用途は既知LANに戻し、OSの欠測だけを評価します。
	missingOsQuery.purpose = L"LAN" ;
	const std::array noOsTargets{missingOsQuery} ;	// Windows 10を要求しても根拠不足。
	DRIVERCRATE_EXPECT( context, inspectAsusCollectorTargets( page, {}, noOsTargets, assessed)) ;
	DRIVERCRATE_EXPECT( context, assessed.size() == 1U &&
									assessed[0].state == AsusCollectorTargetState::UNKNOWN &&
									assessed[0].reason == AsusCollectorTargetReason::OS_UNKNOWN) ;
	// 構造不成立のpageからは別modelでも明示矛盾を発行しません。
	DRIVERCRATE_EXPECT(
		context, inspectAsusCollectorTargets( AsusCollectorPageResult{}, {}, sparse, assessed)) ;
	DRIVERCRATE_EXPECT(
		context, assessed.size() == 2U && assessed[1].state == AsusCollectorTargetState::UNKNOWN &&
					 assessed[1].reason == AsusCollectorTargetReason::SOURCE_UNKNOWN) ;
	// 一候補のkey付替え、件数欠落、順序変更を全体拒否します。
	DRIVERCRATE_EXPECT( context,
					   parseAsusCollectorDriverPageHtml( html, L"PRIME TEST", L"Windows 11 64-bit",
														L"LAN", LIMIT, page)) ;
	std::vector<OfficialCollectorRecordCandidate> changed ;	// 秘密URLは複写せず別途構築します。
	DRIVERCRATE_EXPECT( context, adaptAsusCollectorNetworkRecordCandidates(
									page, request, 1'780'000'000ULL, changed)) ;
	changed[0].recordKey = L"PRIME OTHER|wrong" ;
	DRIVERCRATE_EXPECT( context, !inspectAsusCollectorTargets( page, changed, sparse, assessed) &&
									assessed.empty()) ;
	DRIVERCRATE_EXPECT(
		context, !inspectAsusCollectorTargets(
					 page, std::span<const OfficialCollectorRecordCandidate>{candidates}.first( 1U),
					 sparse, assessed)) ;
	DRIVERCRATE_EXPECT( context, adaptAsusCollectorNetworkRecordCandidates(
									page, request, 1'780'000'000ULL, changed)) ;
	std::swap( changed[0], changed[1]) ;
	DRIVERCRATE_EXPECT( context, !inspectAsusCollectorTargets( page, changed, sparse, assessed)) ;
	// 重複keyと最大件数超過は最初から集合全体を拒否します。
	const std::array duplicate{targets[0], targets[0]} ;	// 同じ公開key。
	DRIVERCRATE_EXPECT( context,
					   !inspectAsusCollectorTargets( page, candidates, duplicate, assessed)) ;
	std::vector<std::wstring> keys ;	// 大集合でviewの寿命を保持するkey。
	keys.reserve( 301U) ;
	std::vector<AsusCollectorTargetQuery> many ;	// 上限300／301を確認する対象。
	many.reserve( 301U) ;
	// 同一boardでも元対象分母を維持します。
	for( std::size_t index = 0U; index < 301U; ++index) {
		keys.push_back( L"public-" + std::to_wstring( index)) ;
		auto query		= targets[0] ;	// 各対象は同じ公式製品を参照します。
		query.targetKey = keys.back() ;
		many.push_back( query) ;
	}

	DRIVERCRATE_EXPECT( context,
					   inspectAsusCollectorTargets(
						   page, candidates,
						   std::span<const AsusCollectorTargetQuery>{many}.first( 300U), assessed)) ;
	DRIVERCRATE_EXPECT( context, assessed.size() == 300U) ;
	// 一本文内のcandidate countは対象件数で増えません。
	for( const auto &target : assessed) {
		DRIVERCRATE_EXPECT( context, target.state == AsusCollectorTargetState::MATCH &&
										target.candidateOrdinals.size() == 2U) ;
	}

	DRIVERCRATE_EXPECT( context, !inspectAsusCollectorTargets( page, candidates, many, assessed)) ;
	DRIVERCRATE_EXPECT( context, assessed.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Model／OS一致時に公式CDN、hash、有限sizeを取得する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testValidPage( TestContext &context)
{
	const std::wstring opaqueId =	// 製品別ID 66、OS ID 52、payload file名を含む架空ID。
		L"1@66@7@8@52@5@DRV_LAN_Fictional_W11_64_V11252750919.zip" ;
	// Modelの大小文字差を含む正常なASUS page fixture。
	const std::wstring html = makePage( L"prime test", opaqueId, PAYLOAD_PATH, SHA256, false) ;
	std::vector<AsusDriverPageEntry> entries ;	// Parserが返す検査前metadata。
	DRIVERCRATE_EXPECT( context,
					   parseAsusDriverPageHtml( html, L"PRIME TEST", L"Windows 11 64-bit", entries)) ;
	DRIVERCRATE_EXPECT( context, entries.size() == 1U) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( entries.size() != 1U) {
		return ;
	}

	const AsusDriverPageEntry &entry = entries.front() ;	// 採用entryの検証対象。
	DRIVERCRATE_EXPECT( context, entry.category == L"LAN") ;
	DRIVERCRATE_EXPECT( context, entry.version == L"1125.27.50.919") ;
	DRIVERCRATE_EXPECT( context, entry.releaseDate == L"2025/12/31") ;
	const std::wstring expectedUrl =
		// 期待URL。
		std::wstring( L"https://dlcdnets.asus.com") + std::wstring( PAYLOAD_PATH) ;
	DRIVERCRATE_EXPECT( context, entry.downloadUrl == expectedUrl) ;
	DRIVERCRATE_EXPECT( context,
					   entry.sha256 ==
						   L"def73029462651e78b30791c9e6edb2e99f86755b2334f942612a50467761cb5") ;
	DRIVERCRATE_EXPECT( context, entry.maximumDownloadBytes == 16'431'186ULL) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Model不一致を拒否し、別OSとEXEを候補にしない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testScopeFiltering( TestContext &context)
{
	const std::wstring validId =	// 対象OSとZIP file名を持つ架空record ID。
		L"1@66@7@8@52@5@DRV_LAN_Fictional_W11_64_V11252750919.zip" ;
	// 不正入力比較の基準となる正常なASUS page fixture。
	const std::wstring valid = makePage( L"PRIME TEST", validId, PAYLOAD_PATH, SHA256, false) ;
	std::vector<AsusDriverPageEntry> entries ;	// 各拒否後の空結果確認先。
	DRIVERCRATE_EXPECT(
		context, !parseAsusDriverPageHtml( valid, L"PRIME OTHER", L"Windows 11 64-bit", entries)) ;
	DRIVERCRATE_EXPECT( context, entries.empty()) ;

	const std::wstring otherOsId =	// Windows 10相当の別OS IDを持つrecord。
		L"1@66@7@8@45@5@DRV_LAN_Fictional_W11_64_V11252750919.zip" ;
	// 対象OSが一致しないrecordを再現するpage fixture。
	const std::wstring otherOs = makePage( L"PRIME TEST", otherOsId, PAYLOAD_PATH, SHA256, false) ;
	DRIVERCRATE_EXPECT(
		context, parseAsusDriverPageHtml( otherOs, L"PRIME TEST", L"Windows 11 64-bit", entries)) ;
	DRIVERCRATE_EXPECT( context, entries.empty()) ;

	// Archive以外のEXE配布を拒否するための架空path。
	constexpr std::wstring_view EXECUTABLE_PATH = L"/pub/ASUS/mb/04LAN/driver.exe" ;
	// EXE配布名へ対応する架空opaque ID。
	const std::wstring			executableId = L"1@66@7@8@52@5@driver.exe" ;
	// EXE配布を候補化しないことを検証するpage fixture。
	const std::wstring			executable =
		makePage( L"PRIME TEST", executableId, EXECUTABLE_PATH, SHA256, false) ;
	DRIVERCRATE_EXPECT(
		context, parseAsusDriverPageHtml( executable, L"PRIME TEST", L"Windows 11 64-bit", entries)) ;
	DRIVERCRATE_EXPECT( context, entries.empty()) ;

	std::wstring utility =	// Driver archive形でも取得対象外にするutility分類fixture。
		makePage( L"PRIME TEST", validId, PAYLOAD_PATH, SHA256, false) ;
	// Driver categoryをutilityへ改変するためのfixture内位置。
	const std::size_t category = utility.find( LR"("LAN",1,[12)") ;
	DRIVERCRATE_EXPECT( context, category != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( category != std::wstring::npos) {
		utility.replace( category, 11U, LR"("Software and Utility",1,[12)") ;
		DRIVERCRATE_EXPECT( context, parseAsusDriverPageHtml( utility, L"PRIME TEST",
															L"Windows 11 64-bit", entries)) ;
		DRIVERCRATE_EXPECT( context, entries.empty()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Hash、path、file identity、重複、script schemaを拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testSecurityRejections( TestContext &context)
{
	const std::wstring validId =	// 正常系を一項目だけ変える基準record ID。
		L"1@66@7@8@52@5@DRV_LAN_Fictional_W11_64_V11252750919.zip" ;
	std::vector<AsusDriverPageEntry> entries ;	// 拒否時に空へ戻す結果一覧。

	// 公開SHA-256の形式不正を再現するpage fixture。
	const std::wstring				 badHash =
		makePage( L"PRIME TEST", validId, PAYLOAD_PATH, L"not-a-sha256", false) ;
	DRIVERCRATE_EXPECT(
		context, !parseAsusDriverPageHtml( badHash, L"PRIME TEST", L"Windows 11 64-bit", entries)) ;
	DRIVERCRATE_EXPECT( context, entries.empty()) ;

	std::wstring brokenHashReference =	// Hash fieldだけをroot範囲外参照へ変えたfixture。
		makePage( L"PRIME TEST", validId, PAYLOAD_PATH, SHA256, false) ;
	// Nuxt hash参照を不正化するためのfixture内位置。
	const std::size_t hashReference = brokenHashReference.find( LR"("sha256":20)") ;
	DRIVERCRATE_EXPECT( context, hashReference != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( hashReference != std::wstring::npos) {
		brokenHashReference.replace( hashReference, 11U, LR"("sha256":99)") ;
		DRIVERCRATE_EXPECT( context, !parseAsusDriverPageHtml( brokenHashReference, L"PRIME TEST",
															 L"Windows 11 64-bit", entries)) ;
		DRIVERCRATE_EXPECT( context, entries.empty()) ;
	}

	// 公開hashがないmetadataの分類を検証するpage fixture。
	const std::wstring noPublishedHash = makePage( L"PRIME TEST", validId, PAYLOAD_PATH, L"", false) ;
	DRIVERCRATE_EXPECT( context, parseAsusDriverPageHtml( noPublishedHash, L"PRIME TEST",
														L"Windows 11 64-bit", entries)) ;
	DRIVERCRATE_EXPECT( context, entries.empty()) ;

	// 親directory参照を含むpayload pathの拒否用入力。
	constexpr std::wstring_view TRAVERSAL_PATH = L"/pub/ASUS/../driver.zip" ;
	// Traversal試験用file名へ対応させた架空opaque ID。
	const std::wstring			traversalId = L"1@66@7@8@52@5@driver.zip" ;
	// Payload pathのtraversalを拒否するためのpage fixture。
	const std::wstring			traversal =
		makePage( L"PRIME TEST", traversalId, TRAVERSAL_PATH, SHA256, false) ;
	DRIVERCRATE_EXPECT(
		context, !parseAsusDriverPageHtml( traversal, L"PRIME TEST", L"Windows 11 64-bit", entries)) ;

	// Opaque IDと配布file名が一致しないpage fixture。
	const std::wstring wrongFile =
		makePage( L"PRIME TEST", validId, L"/pub/ASUS/mb/04LAN/other.zip", SHA256, false) ;
	DRIVERCRATE_EXPECT(
		context, !parseAsusDriverPageHtml( wrongFile, L"PRIME TEST", L"Windows 11 64-bit", entries)) ;

	// 同じ配布recordが重複するpage fixture。
	const std::wstring duplicate = makePage( L"PRIME TEST", validId, PAYLOAD_PATH, SHA256, true) ;
	DRIVERCRATE_EXPECT(
		context, !parseAsusDriverPageHtml( duplicate, L"PRIME TEST", L"Windows 11 64-bit", entries)) ;

	std::wstring mismatchedCount =	// Files一件に対して別numberを参照するCount違反fixture。
		makePage( L"PRIME TEST", validId, PAYLOAD_PATH, SHA256, false) ;
	// 宣言件数と実record数の不一致を注入するfixture内位置。
	const std::size_t countReference = mismatchedCount.find( LR"("LAN",1,[12)") ;
	DRIVERCRATE_EXPECT( context, countReference != std::wstring::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( countReference != std::wstring::npos) {
		mismatchedCount.replace( countReference, 11U, LR"("LAN",2,[12)") ;
		DRIVERCRATE_EXPECT( context, !parseAsusDriverPageHtml( mismatchedCount, L"PRIME TEST",
															 L"Windows 11 64-bit", entries)) ;
	}

	// Nuxt data要素のcontent typeがJSONでない拒否用HTML。
	constexpr std::wstring_view WRONG_SCRIPT =
		LR"(<script type="text/javascript" id="__NUXT_DATA__">[]</script>)" ;
	DRIVERCRATE_EXPECT( context, !parseAsusDriverPageHtml( WRONG_SCRIPT, L"PRIME TEST",
														 L"Windows 11 64-bit", entries)) ;
}

/**
 * @brief 対象外0 KBを取得せず、対象内の不正と全体構造違反を拒否する。
 * @param[in,out] context Assertion集計先。
 */
void testExplicitNetworkCategory( TestContext &context)
{
	const std::wstring validId =
		L"1@66@7@8@52@5@DRV_LAN_Fictional_W11_64_V11252750919.zip" ;	// 架空ID。
	std::wstring page = makePage( L"PRIME TEST", validId, PAYLOAD_PATH, SHA256,
								 false) ;			// LANと対象外Audioを併記する。
	const auto	 end  = page.find( L"]</script>") ;	// Flattened root末尾。
	DRIVERCRATE_EXPECT( context, end != std::wstring::npos) ;
	// Fixture自体が成立しない場合は範囲外編集をしない。
	if( end == std::wstring::npos) {
		return ;
	}

	page.insert(
		end,
		LR"(,{"Name":22,"Count":9,"Files":23,"IsDescShow":11},"Audio",[24],{"Id":25,"Version":14,"Title":15,"FileSize":26,"ReleaseDate":17,"DownloadUrl":18,"sha256":20},"1@66@7@8@52@6@DRV_LAN_Fictional_W11_64_V11252750919.zip","0 KB")") ;
	std::vector<AsusDriverPageEntry> entries ;	// 取得判断へ渡す範囲内record。
	DRIVERCRATE_EXPECT(
		context, !parseAsusDriverPageHtml( page, L"PRIME TEST", L"Windows 11 64-bit", entries)) ;
	DRIVERCRATE_EXPECT( context, entries.empty()) ;
	DRIVERCRATE_EXPECT( context, parseAsusDriverPageHtml( page, L"PRIME TEST", L"Windows 11 64-bit",
														entries, L"LAN")) ;
	DRIVERCRATE_EXPECT( context, entries.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, parseAsusDriverPageHtml( page, L"PRIME TEST", L"Windows 11 64-bit",
														entries, L"Wireless")) ;
	DRIVERCRATE_EXPECT( context, entries.empty()) ;
	DRIVERCRATE_EXPECT( context, !parseAsusDriverPageHtml( page, L"PRIME TEST", L"Windows 11 64-bit",
														 entries, L"Audio")) ;
	DRIVERCRATE_EXPECT(
		context, !parseAsusDriverPageHtml( page, L"OTHER", L"Windows 11 64-bit", entries, L"LAN")) ;
	DRIVERCRATE_EXPECT( context, !parseAsusDriverPageHtml( page, L"PRIME TEST", L"Windows 10 64-bit",
														 entries, L"LAN")) ;
	const auto size = page.find( L"14.67 MB") ;	// 対象内0 KBの注入位置。
	DRIVERCRATE_EXPECT( context, size != std::wstring::npos) ;
	// 対象内の容量不正はscope指定でも拒否されることを確認する。
	if( size != std::wstring::npos) {
		std::wstring invalid = page ;	// 対象LAN本文だけを変えたfixture。
		invalid.replace( size, 8U, L"0 KB") ;
		DRIVERCRATE_EXPECT( context,
						   !parseAsusDriverPageHtml( invalid, L"PRIME TEST", L"Windows 11 64-bit",
													entries, L"LAN")) ;
		DRIVERCRATE_EXPECT( context, entries.empty()) ;
	}

	const auto category = page.find( LR"("LAN",1,[12)") ;	// Wirelessへのscope切替位置。
	DRIVERCRATE_EXPECT( context, category != std::wstring::npos) ;
	// Wirelessも同じ根拠検証を経由し、対象外Audioは取得しない。
	if( category != std::wstring::npos) {
		std::wstring wireless = page ;	// Wireless正常fixture。
		wireless.replace( category, 5U, L"\"Wireless\"") ;
		DRIVERCRATE_EXPECT( context,
						   parseAsusDriverPageHtml( wireless, L"PRIME TEST", L"Windows 11 64-bit",
												   entries, L"Wireless")) ;
		DRIVERCRATE_EXPECT( context, entries.size() == 1U) ;
	}

	AsusDriverCatalogObservation observation ;	// 個別不正と全体構造拒否を区別する観測。
	DRIVERCRATE_EXPECT( context, parseAsusDriverPageHtml( page, L"PRIME TEST", L"Windows 11 64-bit",
														entries, L"Audio", &observation)) ;
	DRIVERCRATE_EXPECT( context, entries.empty() && observation.structurallyValid &&
									observation.seen == 1U && observation.rejected == 1U) ;
	DRIVERCRATE_EXPECT( context, parseAsusDriverPageHtml( page, L"PRIME TEST", L"Windows 11 64-bit",
														entries, L"LAN", &observation)) ;
	DRIVERCRATE_EXPECT( context, entries.size() == 1U && observation.accepted == 1U &&
									observation.rejected == 0U) ;
	auto mixed = page ;	// 同じ分類に正常行と0 KB行が混在するfixture。
	mixed.replace( mixed.find( L"\"Audio\""), 7U, L"\"LAN\"") ;
	DRIVERCRATE_EXPECT( context, !parseAsusDriverPageHtml( mixed, L"PRIME TEST", L"Windows 11 64-bit",
														 entries, L"LAN")) ;
	DRIVERCRATE_EXPECT( context, parseAsusDriverPageHtml( mixed, L"PRIME TEST", L"Windows 11 64-bit",
														entries, L"LAN", &observation)) ;
	DRIVERCRATE_EXPECT( context, entries.size() == 1U && observation.seen == 2U &&
									observation.accepted == 1U && observation.rejected == 1U) ;
	DRIVERCRATE_EXPECT( context, !parseAsusDriverPageHtml( page, L"PRIME TEST", L"Windows 11 64-bit",
														 entries, L"BIOS", &observation)) ;
	DRIVERCRATE_EXPECT( context, !observation.structurallyValid && entries.empty()) ;
	DRIVERCRATE_EXPECT( context, !parseAsusDriverPageHtml( page, L"PRIME TEST", L"Windows 11 64-bit",
														 entries, {}, &observation)) ;
	const auto reference = page.find( L"[24]") ;	// 対象外でも維持する参照検証の注入位置。
	DRIVERCRATE_EXPECT( context, reference != std::wstring::npos) ;
	// 対象外categoryでも不正参照を無視して本文へ進まない。
	if( reference != std::wstring::npos) {
		page.replace( reference, 4U, L"[999999]") ;
		DRIVERCRATE_EXPECT( context,
						   !parseAsusDriverPageHtml( page, L"PRIME TEST", L"Windows 11 64-bit",
													entries, L"LAN", &observation)) ;
		DRIVERCRATE_EXPECT( context, !observation.structurallyValid && entries.empty()) ;
		DRIVERCRATE_EXPECT(
			context,
			!parseAsusDriverPageHtml( page, L"PRIME TEST", L"Windows 11 64-bit", entries, L"LAN")) ;
		DRIVERCRATE_EXPECT( context, entries.empty()) ;
	}
}

/** @brief Nuxtから候補・全targetまで同じ制御を伝播する内部試験です。
 * @param[in,out] context Assertion集計。
 */
void testControlledAsus( TestContext &context)
{
	const auto				html   = makeCollectorRows( 2U) ;	// 同じ公開boardの二配布。
	constexpr std::uint64_t budget = 128ULL * 1024U * 1024U ;	// 既存予算を維持。
	AsusCollectorPageResult parsed ;							// 本番parser所有結果。
	testParserCheckpoints(
		context,
		[&]( OfficialCollectorHttpControl &control) {
			return parseAsusCollectorDriverPageHtmlControlled(
				html, L"PRIME TEST", L"Windows 11 64-bit", L"LAN", budget, control, parsed) ;
		},
		[&] { return parsed.entries.empty() && !parsed.structurallyValid ; }) ;
	ParserTestControl normal ;	// 候補変換用の正常解析。
	DRIVERCRATE_EXPECT(
		context, parseAsusCollectorDriverPageHtmlControlled(
					 html, L"PRIME TEST", L"Windows 11 64-bit", L"LAN", budget, normal, parsed)
						 .status == CollectorParserStatus::COMPLETED) ;
	AsusSupportPageRequest request ;	// 同じ製品の公式要求。
	DRIVERCRATE_EXPECT( context, makeAsusPublicModelSupportPageRequest(
									L"PRIME TEST", L"Windows 11 64-bit", request)) ;
	std::vector<OfficialCollectorRecordCandidate> candidates ;	// URLはworker内のまま。
	testParserCheckpoints(
		context,
		[&]( OfficialCollectorHttpControl &control) {
			return adaptAsusCollectorNetworkRecordCandidatesControlled(
				parsed, request, 1'780'000'000ULL, control, candidates) ;
		},
		[&] { return candidates.empty() ; }, CollectorIoStage::PROJECT) ;
	DRIVERCRATE_EXPECT( context, adaptAsusCollectorNetworkRecordCandidates(
									parsed, request, 1'780'000'000ULL, candidates)) ;
	const std::array<AsusCollectorTargetQuery, 2U> targets{
		{{L"one", L"ASUS", L"PRIME TEST", L"MAINBOARD", L"LAN", L"Windows 11 64-bit", L"x64", L""},
		 {L"two", L"ASUS", L"PRIME TEST", L"MAINBOARD", L"LAN", L"Windows 11 64-bit", L"x64",
		  L"chip"}}} ;											// 全対象を省略せず評価します。
	std::vector<AsusCollectorTargetAssessment> assessments ;	// 全対象の所有結果。
	testParserCheckpoints(
		context,
		[&]( OfficialCollectorHttpControl &control) {
			return inspectAsusCollectorTargetsControlled( parsed, candidates, targets, control,
														 assessments) ;
		},
		[&] { return assessments.empty() ; }, CollectorIoStage::PROJECT) ;
	ParserTestControl limit ;	// 17件目は切捨て採用しません。
	DRIVERCRATE_EXPECT( context, parseAsusCollectorDriverPageHtmlControlled(
									makeCollectorRows( 17U), L"PRIME TEST", L"Windows 11 64-bit",
									L"LAN", budget, limit, parsed)
										.status == CollectorParserStatus::LIMIT_EXCEEDED) ;
	ParserTestControl empty ;	// 空分類は正常解析です。
	DRIVERCRATE_EXPECT( context, parseAsusCollectorDriverPageHtmlControlled(
									makeCollectorRows( 0U), L"PRIME TEST", L"Windows 11 64-bit",
									L"LAN", budget, empty, parsed)
											.status == CollectorParserStatus::COMPLETED &&
									parsed.sliceStatus == AsusCollectorSliceStatus::EMPTY) ;
	ParserTestControl malformed ;															// WinRT JSON文法拒否をOOMと分けます。
	const auto broken = html.substr( 0U, html.find( L">") + 1U) + L"[invalid]</script>" ;	// 不正JSON。
	DRIVERCRATE_EXPECT(
		context, parseAsusCollectorDriverPageHtmlControlled(
					 broken, L"PRIME TEST", L"Windows 11 64-bit", L"LAN", budget, malformed, parsed)
						 .status == CollectorParserStatus::REJECTED) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/asus_catalog_parser_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runAsusCatalogParserTests( TestContext &context)
{
	testControlledAsus( context) ;
	testCollectorIdentity( context) ;
	testCollectorCrosscut( context) ;
	testCollectorTargetAssessment( context) ;
	testValidPage( context) ;
	testScopeFiltering( context) ;
	testSecurityRejections( context) ;
	testExplicitNetworkCategory( context) ;
}

} // namespace drivercrate::test
