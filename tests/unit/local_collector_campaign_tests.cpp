//------------------------------------------------------------------------------
/**
 * @file local_collector_campaign_tests.cpp
 * @brief 共有job・予算・保存窓の回収を非通信で検証します。
 * @version 01.42.04
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/27  共有job・予算予約・中断回収を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/27  store借用と独立待機の回帰fixtureを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/27  非変更予算・固定精算・mode拒否を検証。
 * Ver.01.03.00 Shunji Ogawa  2026/09/27  応答・日次commitの保存窓と型拒否を検証。
 * Ver.01.04.00 Shunji Ogawa  2026/09/27  全prefix・欠損・変更入力・容量の追加受入。
 * Ver.01.05.00 Shunji Ogawa  2026/09/27  v2共通予算・batch・型付き失敗の統合受入。
 * Ver.01.06.00 Shunji Ogawa  2026/09/27  非変更readinessと予約期限の結合を検証。
 * Ver.01.07.00 Shunji Ogawa  2026/09/27  有限DNS・共通HTTPの非通信fixtureを接続。
 * Ver.01.08.00 Shunji Ogawa  2026/09/27  v3応答・監督の非通信受入を接続。
 * Ver.01.09.00 Shunji Ogawa  2026/09/27  横断受入と専用subsuiteを接続。
 * Ver.01.10.00 Shunji Ogawa  2026/09/28  全共有対象scopeと新本文の未発行拒否を検証。
 * Ver.01.11.00 Shunji Ogawa  2026/09/28  全jobのv3入力と旧G分離を非保存で検証。
 * Ver.01.12.00 Shunji Ogawa  2026/09/28  v3保存・再開・旧root回収fixtureを接続。
 * Ver.01.13.00 Shunji Ogawa  2026/09/28  二sourceの射影偽HTTP受入を接続。
 * Ver.01.14.00 Shunji Ogawa  2026/09/29  canonical field改変と再計算hash／世代の拒否を検査。
 * Ver.01.15.00 Shunji Ogawa  2026/09/29  v3保存入力の300／301対象境界を検査。
 * Ver.01.16.00 Shunji Ogawa  2026/09/29  新応答の有限byte・envelope・版別判定試験を接続。
 * Ver.01.17.00 Shunji Ogawa  2026/09/30  全fixtureを省略せず有限CTest二件へ分割。
 * Ver.01.18.00 Shunji Ogawa  2026/10/01  未応答中断fixtureを独立CTestへ追加し旧二枠を保持。
 * Ver.01.19.00 Shunji Ogawa  2026/10/01  部分開始の非重複CTestと既定全件実行を接続。
 * Ver.01.20.00 Shunji Ogawa  2026/10/01  日次切替復旧の非重複CTestを追加し旧四枠を保持。
 * Ver.01.21.00 Shunji Ogawa  2026/10/01  末尾完了復旧の専用CTestと既定全件実行を接続。
 * Ver.01.22.00 Shunji Ogawa  2026/10/01  正常300世代の独立境界CTestと既定全件を接続。
 * Ver.01.23.00 Shunji Ogawa  2026/10/01  操作300枠の独立非通信CTestを接続。
 * Ver.01.23.01 Shunji Ogawa  2026/10/01  300枠の未測定を保持し基礎履歴CTestへ分離。
 * Ver.01.24.00 Shunji Ogawa  2026/10/01  合成操作上限の独立CTestを追加。
 * Ver.01.25.00 Shunji Ogawa  2026/10/01  新requestのCACHE増加を独立有限枠へ分離。
 * Ver.01.26.00 Shunji Ogawa  2026/10/01  大量新requestの先着容量測定を独立枠へ接続。
 * Ver.01.27.00 Shunji Ogawa  2026/10/01  完了世代境界と通常起動の専用枠を追加。
 * Ver.01.28.00 Shunji Ogawa  2026/10/02  元raw封印の独立有限CTestを追加。
 * Ver.01.29.00 Shunji Ogawa  2026/10/02  同親historyのv3接続を独立した専用枠へ分離。
 * Ver.01.30.00 Shunji Ogawa  2026/10/02  現区間の結合検査を独立CTestへ追加。
 * Ver.01.31.00 Shunji Ogawa  2026/10/02  実根拠の非保存切替準備を独立CTestへ追加。
 * Ver.01.32.00 Shunji Ogawa  2026/10/02  実HTTP所有閉鎖を独立CTestへ追加。
 * Ver.01.33.00 Shunji Ogawa  2026/10/02  同親保持・保存role先払いを独立CTestへ追加。
 * Ver.01.34.00 Shunji Ogawa  2026/10/02  切替準備の実保存専用CTestを接続。
 * Ver.01.35.00 Shunji Ogawa  2026/10/02  新子準備保存の独立CTestを接続。
 * Ver.01.36.00 Shunji Ogawa  2026/10/02  専用初期ROOT実保存の独立CTestを接続。
 * Ver.01.37.00 Shunji Ogawa  2026/10/02  元head保持と親head実保存の独立CTestを接続。
 * Ver.01.38.00 Shunji Ogawa  2026/10/02  回復byte decoderの独立選択を追加。
 * Ver.01.39.00 Shunji Ogawa  2026/10/03  保護実handleの初回切替回復と検査を追加。
 * Ver.01.40.00 Shunji Ogawa  2026/10/03  ROOT未保存の連続準備prefix回復と検査を追加。
 * Ver.01.41.00 Shunji Ogawa  2026/10/03  初回読取りcodecの独立CTest選択を追加。
 * Ver.01.42.00 Shunji Ogawa  2026/10/03  実handle初回readerの独立native選択を追加。
 * Ver.01.42.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.42.02   Shunji Ogawa  2026/10/16 共有jobと準備済みcampaign試験のassertion引数を明記。
 * Ver.01.42.03   Shunji Ogawa  2026/10/18 自作fixtureの属性・削除をextended DOS表記へ統一。
 * Ver.01.42.04   Shunji Ogawa  2026/10/18 日次欠損fixtureの削除にも同じ長path表記を適用。
 * </pre>
 *
 * @note 単一監督threadから使用します。通信・取得grant・導入を実行しません。
 * @see docs/adr/0214-multi-source-collector-campaign.md
 */
//------------------------------------------------------------------------------

#include "platform/local_collector_campaign.h"
#include "platform/local_collector_http_control.h"
#include "platform/local_collector_recovery.h"
#include "platform/local_collector_projected_job.h"
#include "platform/local_collector_projected_input.h"
#include "local_collector_projected_recovery_tests.h"
#include "local_collector_projected_json_tests.h"
#include "platform/local_collector_http_client.h"
#include "core/official_source_policy.h"
#include "platform/local_collector_state_store.h"
#include "platform/official_file_verifier.h"
#include "test_framework.h"
#include "local_collector_http_tests.h"
#include "local_collector_executor_tests.h"

#include <objbase.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#include <wrl/wrappers/corewrappers.h>
#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <latch>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {

/**
 * @brief JSON objectをWinRT参照で保持する。Copyは同じobjectを共有し、schema検証は利用側で行う。
 */
using JsonObject = winrt::Windows::Data::Json::JsonObject ;
/**
 * @brief JSON配列をWinRT参照で保持する。要素数と各要素のschema検証は利用側で行う。
 */
using JsonArray = winrt::Windows::Data::Json::JsonArray ;
/**
 * @brief JSON値をWinRT参照で保持する。所有byteの検証と型判定はreader側で行う。
 */
using JsonValue = winrt::Windows::Data::Json::JsonValue ;

// Fixtureのartifact／planは端末情報を含まない架空hash。
const std::wstring					HASH( 64U, L'a') ;
// Fixtureの固定UTC秒。実時計とは切り離す。
constexpr std::uint64_t				UTC = 1790456400ULL ;

/**
 * @brief GUID付きの未存在専用rootだけをfixtureへ渡します。
 * @param[in,out] roots 自作rootだけを追加する回収集合。
 * @return Workspace内の未存在GUID root。
 */
[[nodiscard]] std::filesystem::path rootFor( std::vector<std::filesystem::path> &roots)
{
	// 衝突を防ぐ公開GUID。
	GUID	guid{} ;
	// GUIDの有限UTF-16表現。
	wchar_t text[40]{} ;
	// GUID API失敗をroot欠損として処理しない。
	if( FAILED( CoCreateGuid( &guid)) || StringFromGUID2( guid, text, 40) == 0) {
		throw std::runtime_error( "fixture GUID") ;
	}

	// 自作fixtureだけが持つworkspace内のpath。
	const auto root = std::filesystem::current_path() / L"work/state" /
					  (std::wstring( L"campaign-fixture-") + text) ;
	roots.push_back( root) ;
	return root ;
}

/** @brief 自作fixtureの実I/Oだけをextended DOS表記へ揃えます。
 * @param[in] path rootFor由来の検証済み絶対DOS path。
 * @return 同じ対象のbackslash付きextended path。
 * @pre 回収範囲と非reparseの検査は呼出し元で維持します。
 */
[[nodiscard]] std::filesystem::path campaignFixtureIoPath( const std::filesystem::path &path)
{
	return L"\\\\?\\" + std::filesystem::path( path).make_preferred().native() ;
}

/**
 * @brief 架空sourceの固定契約を作ります。
 * @param[in] maximum 一応答のfixture byte上限。
 * @return 五つの架空source契約。
 */
[[nodiscard]] std::vector<CollectorCampaignSource> sources( const std::uint64_t maximum = 8U *
																						 1024U *
																						 1024U)
{
	// 相互に独立した四sourceと同groupの追加resource。
	std::vector<CollectorCampaignSource> values ;
	// 四つの実行枠を確認するため固定五sourceを登録する。
	for( std::size_t index = 0U; index < 5U; ++index) {
		values.push_back( {L"source" + std::to_wstring( index), L"metadata",
						  L"group" + std::to_wstring( index), L"parser-v1", maximum}) ;
	}

	return values ;
}

/**
 * @brief 製品数とjob数を有限の架空JSONへ生成します。
 * @param[in] count 架空製品数。
 * @param[in] jobs 入力job数。
 * @param[in] id 架空campaign名。
 * @param[in] differentSources 五sourceへ循環配分する場合true。
 * @param[in] duplicateJob 同じ公開locatorへ束ねる場合true。
 * @return 評価planとは別の実行manifest本文。
 */
[[nodiscard]] std::string manifestBytes( const std::size_t count, const std::size_t jobs,
										const std::wstring_view id				 = L"fixture",
										const bool				differentSources = false,
										const bool				duplicateJob	 = false)
{
	// 評価planとは別の実行schema。
	JsonObject root ;
	root.Insert( L"schema", JsonValue::CreateStringValue( L"collector-campaign-manifest-v1")) ;
	root.Insert( L"campaignId", JsonValue::CreateStringValue( winrt::hstring( id))) ;
	root.Insert( L"planSha256", JsonValue::CreateStringValue( HASH)) ;
	root.Insert( L"os", JsonValue::CreateStringValue( L"WINDOWS_11_X64")) ;
	// 最大300の架空製品集合。
	JsonArray targets ;
	// 実製品名・端末IDを使わず対象数と共有関係を確認する。
	for( std::size_t index = 0U; index < count; ++index) {
		// 同じメーカーへ最大64公開製品を割当てる。
		JsonObject target ;
		target.Insert( L"id", JsonValue::CreateStringValue( L"target" + std::to_wstring( index))) ;
		target.Insert( L"maker",
					  JsonValue::CreateStringValue( L"Maker" + std::to_wstring( index / 64U))) ;
		target.Insert( L"model",
					  JsonValue::CreateStringValue( L"Public Product " + std::to_wstring( index))) ;
		target.Insert( L"kind", JsonValue::CreateStringValue( L"MAINBOARD")) ;
		target.Insert( L"purpose", JsonValue::CreateStringValue( L"network")) ;
		targets.Append( target) ;
	}

	root.Insert( L"targets", targets) ;
	// 共有requestだけを持つjob入力。
	JsonArray rows ;
	// 各jobは架空の公開locatorを持ち、全対象へ参照する。
	for( std::size_t index = 0U; index < jobs; ++index) {
		// 一つのmetadata request。
		JsonObject job ;
		job.Insert( L"source",
				   JsonValue::CreateStringValue(
					   differentSources ? L"source" + std::to_wstring( index % 5U) : L"source0")) ;
		job.Insert( L"resource", JsonValue::CreateStringValue( L"metadata")) ;
		job.Insert( L"locator", JsonValue::CreateStringValue(
								   L"public-page-" + std::to_wstring( duplicateJob ? 0U : index))) ;
		job.Insert( L"locale", JsonValue::CreateStringValue( L"en-US")) ;
		job.Insert( L"page", JsonValue::CreateNumberValue( 1.0)) ;
		// 全対象へのrequest参照を有限にする。
		JsonArray references ;
		// Jobごとの製品参照を固定順で生成する。
		for( std::size_t product = 0U; product < count; ++product) {
			references.Append( JsonValue::CreateStringValue( L"target" + std::to_wstring( product))) ;
		}

		job.Insert( L"targets", references) ;
		rows.Append( job) ;
	}

	root.Insert( L"jobs", rows) ;
	return winrt::to_string( root.Stringify()) ;
}

/**
 * @brief 架空manifestをproduction parserへ渡して型付き値を得ます。
 * @param[in] count 架空製品数。
 * @param[in] jobs 架空request数。
 * @param[in] id 架空campaign名。
 * @param[in] maximum 架空応答上限byte。
 * @param[in] differentSources 独立sourceへ配分する場合true。
 * @return Production parserが検査した固定manifest。
 */
[[nodiscard]] CollectorCampaignManifest manifest( const std::size_t		 count = 2U,
												 const std::size_t		 jobs  = 1U,
												 const std::wstring_view id	   = L"fixture",
												 const std::uint64_t maximum   = 8U * 1024U * 1024U,
												 const bool			 differentSources = false)
{
	// Production parserの成功出力だけを使う。
	CollectorCampaignManifest result ;
	// 架空descriptorもcaller固定の同じ境界で検証する。
	if( !parseCollectorCampaignManifest( manifestBytes( count, jobs, id, differentSources),
									   sources( maximum), result)) {
		throw std::runtime_error( "fixture manifest") ;
	}

	return result ;
}

/**
 * @brief 成功した架空metadataの有限観測を作ります。
 * @param[in] bytes 架空の実受信byte数。
 * @return 適合や取得grantを含まない正常観測。
 */
[[nodiscard]] CollectorCampaignObservation success( const std::uint64_t bytes = 3U)
{
	// Driver適合や取得grantを含まないmetadata観測。
	CollectorCampaignObservation result ;
	result.state			= CollectorCampaignJobState::OBSERVED ;
	result.receivedBytes	= bytes ;
	result.httpStatus		= 200U ;
	result.bodySha256		= HASH ;
	result.projectionSha256 = HASH ;
	return result ;
}

/**
 * @brief Manifestの未知schema・秘密・重複・境界を検証します。
 * @param[in,out] context 非通信assertion集計。
 */
void inputChecks( TestContext &context)
{
	// 各拒否で出力が空になることも確認する。
	CollectorCampaignManifest output ;
	DRIVERCRATE_EXPECT( context,
					   parseCollectorCampaignManifest( manifestBytes( 300U, 1U), sources(), output)) ;
	DRIVERCRATE_EXPECT( context, output.targets.size() == 300U && output.jobs.size() == 1U &&
									output.jobs.front().targetIndices.size() == 300U) ;
	DRIVERCRATE_EXPECT(
		context, parseCollectorCampaignManifest( manifestBytes( 2U, 2U, L"duplicate", false, true),
												sources(), output) &&
					 output.jobs.size() == 1U) ;
	DRIVERCRATE_EXPECT(
		context, !parseCollectorCampaignManifest( manifestBytes( 301U, 1U), sources(), output) &&
					 output.targets.empty()) ;
	// 型とkey改変に対する拒否fixture。
	const std::vector<std::pair<std::string, std::string>> changes{
		{"collector-campaign-manifest-v1", "drivercrate-collector-evaluation-plan-v1"},
		{"WINDOWS_11_X64", "WINDOWS_11_ARM64"},
		{"public-page-0", "https://example.invalid/x"},
		{"public-page-0", "PCI#PRIVATE"},
		{"source0", "unknown-source"},
		{"Public Product 1", "Public Product 0"},
		{"target1", "target0"},
		{"\"page\":1", "\"page\":0"},
		{"\"page\":1", "\"page\":11"},
		{"\"page\":1", "\"page\":1.5"},
		{"\"os\":", "\"os\":\"WINDOWS_11_X64\",\"os\":"},
		{"\"schema\":", "\"\\u0073chema\":\"ignored\",\"schema\":"}} ;
	// 不正入力を一つずつ独立に拒否させる。
	for( const auto &change : changes) {
		// 正常入力から一箇所だけを変更する。
		auto	   bytes = manifestBytes( 2U, 1U) ;
		// Fixtureの変更対象位置。
		const auto at = bytes.find( change.first) ;
		DRIVERCRATE_EXPECT( context, at != bytes.npos) ;
		// 対象が存在する変更だけを試験し、元文字列の偶然一致を隠さない。
		if( at != bytes.npos) {
			bytes.replace( at, change.first.size(), change.second) ;
			DRIVERCRATE_EXPECT( context, !parseCollectorCampaignManifest( bytes, sources(), output) &&
											output.targets.empty() && output.jobs.empty()) ;
		}
	}

	// 固定descriptorの最大byte上限を超える契約。
	auto oversized						   = sources() ;
	oversized.front().maximumResponseBytes = 8U * 1024U * 1024U + 1U ;
	DRIVERCRATE_EXPECT( context,
					   !parseCollectorCampaignManifest( manifestBytes( 2U, 1U), oversized, output)) ;
	// 現評価planを実行manifestとして通さない。
	std::ifstream	  file( "docs/evaluation/local-collector-campaign-v1.json", std::ios::binary) ;
	// 実評価planのbyte列。公開製品名は検査後に保持しない。
	const std::string bytes( std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}) ;
	DRIVERCRATE_EXPECT( context,
					   !bytes.empty() && !parseCollectorCampaignManifest( bytes, sources(), output)) ;
}

/**
 * @brief 共有一jobと300製品への32件ずつ反映・再開を確認します。
 * @param[in,out] context 非通信assertion集計。
 * @param[in] root 自作GUID付き専用root。
 */
void sharedAndResume( TestContext &context, const std::filesystem::path &root)
{
	// 300製品に共有する一つの架空metadata job。
	const auto input = manifest( 300U) ;
	{
		// Writer lockを保持する一回目の監督。
		LocalCollectorCampaign campaign ;
		DRIVERCRATE_EXPECT( context, campaign.initialize( root, input, HASH, UTC) == 0U) ;
		// 同rootへの別writerは拒否される。
		LocalCollectorCampaign competing ;
		DRIVERCRATE_EXPECT( context, competing.initialize( root, input, HASH, UTC) != 0U) ;
		// 予約済みrequestを一件だけ受け取る。
		CollectorCampaignDispatch dispatch ;
		DRIVERCRATE_EXPECT( context, campaign.reserve( UTC, dispatch) ==
										CollectorCampaignDispatchResult::READY) ;
		DRIVERCRATE_EXPECT( context, dispatch.deadlineUtc == UTC + 14400U) ;
		DRIVERCRATE_EXPECT( context, campaign.reserve( UTC, dispatch) ==
										CollectorCampaignDispatchResult::WAIT) ;
		DRIVERCRATE_EXPECT( context, campaign.finish( input.jobs[0].key, success(), UTC + 1U) == 0U) ;
		// 結果の最大32製品だけを先に反映する。
		std::size_t applied{} ;
		DRIVERCRATE_EXPECT( context, campaign.applyResults( applied) == 0U && applied == 32U) ;
	}
	{
		// Terminal requestを再通信せず反映途中から再開する。
		LocalCollectorCampaign resumed ;
		DRIVERCRATE_EXPECT( context, resumed.initialize( root, input, HASH, UTC + 2U) == 0U) ;
		// HTTPは完了済みなので新予約は作らない。
		CollectorCampaignDispatch dispatch ;
		DRIVERCRATE_EXPECT( context, resumed.reserve( UTC + 2U, dispatch) ==
										CollectorCampaignDispatchResult::COMPLETE) ;
		// 残り268製品を有限batchで反映する。
		std::size_t total{} ;
		// 最大九batchで残り268製品を処理する。
		for( std::size_t batch = 0U; batch < 9U; ++batch) {
			// 今回反映した公開製品数。
			std::size_t applied{} ;
			DRIVERCRATE_EXPECT( context, resumed.applyResults( applied) == 0U && applied <= 32U) ;
			total += applied ;
		}

		DRIVERCRATE_EXPECT(
			context,
			total == 268U && std::all_of( resumed.targetStates().begin(),
										 resumed.targetStates().end(), []( const auto state) {
											 return state == CollectorCampaignTargetState::OBSERVED ;
										 })) ;
		// 同じ結果を再反映しても件数を増やさない。
		std::size_t applied{} ;
		DRIVERCRATE_EXPECT( context, resumed.applyResults( applied) == 0U && applied == 0U) ;
	}
}

/**
 * @brief 予約／観測保存の中断窓で回収・再送禁止を確認します。
 * @param[in,out] context 非通信assertion集計。
 * @param[in] root 自作GUID付き専用root。
 * @param[in] afterObservation 結果保存窓を試験する場合true。
 */
void interrupted( TestContext &context, const std::filesystem::path &root,
				 const bool afterObservation)
{
	// 二target・一共有jobの固定入力。
	const auto input = manifest() ;
	{
		// 指定された保存窓でだけ停止するfixture callback。
		LocalCollectorCampaign campaign ;
		DRIVERCRATE_EXPECT(
			context, campaign.initialize(
						 root, input, HASH, UTC, [=]( const CollectorCampaignCheckpoint checkpoint) {
							 return checkpoint ==
									(afterObservation
										 ? CollectorCampaignCheckpoint::OBSERVATION_SAVED
										 : CollectorCampaignCheckpoint::BUDGET_RESERVED) ;
						 }) == 0U) ;
		// 予算予約の結果を受け取る。
		CollectorCampaignDispatch dispatch ;
		// 結果保存窓の試験では予約から結果保存まで進める。
		if( afterObservation) {
			DRIVERCRATE_EXPECT( context, campaign.reserve( UTC, dispatch) ==
											CollectorCampaignDispatchResult::READY) ;
			DRIVERCRATE_EXPECT( context, campaign.finish( dispatch.jobKey, success(), UTC + 1U) ==
											ERROR_OPERATION_ABORTED) ;
		} else {
			DRIVERCRATE_EXPECT( context, campaign.reserve( UTC, dispatch) ==
												CollectorCampaignDispatchResult::REJECTED &&
											campaign.lastError() == ERROR_OPERATION_ABORTED) ;
		}
	}
	{
		// 翌日に回収しても元のjobを再送しない。
		LocalCollectorCampaign recovered ;
		DRIVERCRATE_EXPECT( context, recovered.initialize( root, input, HASH, UTC + 86400U) == 0U) ;
		DRIVERCRATE_EXPECT( context,
						   recovered.observations()[0].state ==
							   (afterObservation ? CollectorCampaignJobState::OBSERVED
												 : CollectorCampaignJobState::INTERRUPTED)) ;
		// 新日になっても同じcampaignの完了requestは再送しない。
		CollectorCampaignDispatch dispatch ;
		DRIVERCRATE_EXPECT( context, recovered.reserve( UTC + 86400U, dispatch) ==
										CollectorCampaignDispatchResult::COMPLETE) ;
	}
	{
		// Archive照合を含む二回目の再開でも結果を保持する。
		LocalCollectorCampaign reopened ;
		DRIVERCRATE_EXPECT( context, reopened.initialize( root, input, HASH, UTC + 86401U) == 0U) ;
	}
}

/**
 * @brief 四in-flight枠、同source一件、開始間隔を確認します。
 * @param[in,out] context 非通信assertion集計。
 * @param[in] root 自作GUID付き専用root。
 */
void concurrency( TestContext &context, const std::filesystem::path &root)
{
	// 五つの独立sourceへそれぞれ一jobを割当てる。
	const auto			   input = manifest( 1U, 5U, L"parallel", 8U * 1024U * 1024U, true) ;
	// 一監督の有限dispatch枠。
	LocalCollectorCampaign campaign ;
	DRIVERCRATE_EXPECT( context, campaign.initialize( root, input, HASH, UTC) == 0U) ;
	// 同時数だけを確認する四回の予約。
	for( std::size_t index = 0U; index < 4U; ++index) {
		// 異なるsourceの一予約。
		CollectorCampaignDispatch dispatch ;
		DRIVERCRATE_EXPECT( context, campaign.reserve( UTC, dispatch) ==
										CollectorCampaignDispatchResult::READY) ;
	}

	// 五つ目のsourceは全体四枠の制限を受ける。
	CollectorCampaignDispatch dispatch ;
	DRIVERCRATE_EXPECT( context,
					   campaign.reserve( UTC, dispatch) == CollectorCampaignDispatchResult::WAIT) ;
	DRIVERCRATE_EXPECT( context, campaign.finish( input.jobs[0].key, success(), UTC + 1U) == 0U) ;
	DRIVERCRATE_EXPECT( context, campaign.reserve( UTC + 1U, dispatch) ==
									CollectorCampaignDispatchResult::READY) ;
	DRIVERCRATE_EXPECT( context, campaign.reserve( UTC + 14400U, dispatch) ==
									CollectorCampaignDispatchResult::BUDGET_EXHAUSTED) ;
}

/**
 * @brief 別campaignへ引き継ぐ日次byte／時計／中断予約を確認します。
 * @param[in,out] context 非通信assertion集計。
 * @param[in] root 自作GUID付き専用root。
 */
void byteBudget( TestContext &context, const std::filesystem::path &root)
{
	// 129×8 MiBを要求するmetadata job集合。
	const auto input = manifest( 1U, 129U, L"bytes") ;
	{
		// 実networkなしで予約課金を日次上限まで確定する。
		LocalCollectorCampaign campaign ;
		DRIVERCRATE_EXPECT( context, campaign.initialize( root, input, HASH, UTC) == 0U) ;
		// 最大128応答を処理し、129件目は開始しない。
		for( std::size_t index = 0U; index < 128U; ++index) {
			// 同じsourceで二秒の開始間隔を守る。
			CollectorCampaignDispatch dispatch ;
			DRIVERCRATE_EXPECT( context, campaign.reserve( UTC + index * 2U, dispatch) ==
											CollectorCampaignDispatchResult::READY) ;
			DRIVERCRATE_EXPECT( context, campaign.finish( dispatch.jobKey,
														success( dispatch.maximumResponseBytes),
														UTC + index * 2U) == 0U) ;
		}

		// byte課金を共有root全体で制限する。
		CollectorCampaignDispatch dispatch ;
		DRIVERCRATE_EXPECT( context, campaign.reserve( UTC + 256U, dispatch) ==
										CollectorCampaignDispatchResult::BUDGET_EXHAUSTED) ;
	}
	{
		// 別manifest・別artifact契約でも予算を復活させない。
		LocalCollectorCampaign other ;
		DRIVERCRATE_EXPECT( context, other.initialize( root, manifest( 1U, 1U, L"other"),
													 std::wstring( 64U, L'b'), UTC + 258U) == 0U) ;
		// 共通予算からの追加予約は拒否される。
		CollectorCampaignDispatch dispatch ;
		DRIVERCRATE_EXPECT( context, other.reserve( UTC + 258U, dispatch) ==
										CollectorCampaignDispatchResult::BUDGET_EXHAUSTED) ;
	}
	{
		// 先行観測より前の時計を拒否する。
		LocalCollectorCampaign rollback ;
		DRIVERCRATE_EXPECT( context,
						   rollback.initialize( root, input, HASH, UTC) == ERROR_INVALID_DATA) ;
	}
	{
		// 新日には旧日を保存し、未開始の一jobだけを処理できる。
		LocalCollectorCampaign nextDay ;
		DRIVERCRATE_EXPECT( context, nextDay.initialize( root, input, HASH, UTC + 86400U) == 0U) ;
		// 前日完了の128jobを再送しない。
		CollectorCampaignDispatch dispatch ;
		DRIVERCRATE_EXPECT( context, nextDay.reserve( UTC + 86400U, dispatch) ==
											CollectorCampaignDispatchResult::READY &&
										dispatch.jobIndex == 128U) ;
	}
}

/**
 * @brief 要求数1200回を複数campaignで共有することを確認します。
 * @param[in,out] context 非通信assertion集計。
 * @param[in] root 自作GUID付き専用root。
 */
void requestBudget( TestContext &context, const std::filesystem::path &root)
{
	// 四campaignが合計1200の一byte metadata要求を処理する。
	for( std::size_t batch = 0U; batch < 4U; ++batch) {
		// 各campaignのmanifestは別identityを持つ。
		const auto input = manifest( 1U, 300U, L"requests-" + std::to_wstring( batch), 1U) ;
		// 同rootの先行budgetを使用する監督。
		LocalCollectorCampaign campaign ;
		DRIVERCRATE_EXPECT( context,
						   campaign.initialize( root, input, HASH, UTC + batch * 600U) == 0U) ;
		// 同sourceの二秒間隔で日次1200要求まで進める。
		for( std::size_t index = 0U; index < 300U; ++index) {
			// 予算に予約する一request。
			CollectorCampaignDispatch dispatch ;
			// Fixture内の単調UTC秒。
			const auto				  now = UTC + batch * 600U + index * 2U ;
			DRIVERCRATE_EXPECT( context, campaign.reserve( now, dispatch) ==
											CollectorCampaignDispatchResult::READY) ;
			DRIVERCRATE_EXPECT( context, campaign.finish( dispatch.jobKey, success( 1U), now) == 0U) ;
		}
	}

	// 五campaign目でも1201件目は開始しない。
	LocalCollectorCampaign excess ;
	DRIVERCRATE_EXPECT(
		context, excess.initialize( root, manifest( 1U, 1U, L"excess", 1U), HASH, UTC + 2400U) == 0U) ;
	// 完了した四campaignで共通request枠を使い切っている。
	CollectorCampaignDispatch dispatch ;
	DRIVERCRATE_EXPECT( context, excess.reserve( UTC + 2400U, dispatch) ==
									CollectorCampaignDispatchResult::BUDGET_EXHAUSTED) ;
}

/**
 * @brief 初回から4時間のwall予算と同source待機を確認します。
 * @param[in,out] context 非通信assertion集計。
 * @param[in] root 自作GUID付き専用root。
 */
void timeBudget( TestContext &context, const std::filesystem::path &root)
{
	// 同source二jobの有限入力。
	const auto			   input = manifest( 1U, 2U) ;
	// Windowの開始は最初の実予約で確定する。
	LocalCollectorCampaign campaign ;
	DRIVERCRATE_EXPECT( context, campaign.initialize( root, input, HASH, UTC) == 0U) ;
	// 先行一jobの予約。
	CollectorCampaignDispatch dispatch ;
	DRIVERCRATE_EXPECT( context,
					   campaign.reserve( UTC, dispatch) == CollectorCampaignDispatchResult::READY) ;
	DRIVERCRATE_EXPECT( context, campaign.reserve( UTC + 1U, dispatch) ==
									CollectorCampaignDispatchResult::WAIT) ;
	DRIVERCRATE_EXPECT( context, campaign.finish( input.jobs[0].key, success(), UTC + 1U) == 0U) ;
	DRIVERCRATE_EXPECT( context, campaign.reserve( UTC + 1U, dispatch) ==
									CollectorCampaignDispatchResult::WAIT) ;
	DRIVERCRATE_EXPECT( context, campaign.reserve( UTC + 14400U, dispatch) ==
									CollectorCampaignDispatchResult::BUDGET_EXHAUSTED) ;
}

/**
 * @brief 未対応・部分失敗・重複完了・台帳破損を確認します。
 * @param[in,out] context 非通信assertion集計。
 * @param[in] root 自作GUID付き専用root。
 */
void failureChecks( TestContext &context, const std::filesystem::path &root)
{
	// 未対応二製品は固定分母に残る。
	const auto unsupported = manifest( 2U, 0U) ;
	{
		// Jobなしでも製品結果を保持する。
		LocalCollectorCampaign campaign ;
		DRIVERCRATE_EXPECT( context, campaign.initialize( root, unsupported, HASH, UTC) == 0U) ;
		// 未対応を二件へ反映する。
		std::size_t applied{} ;
		DRIVERCRATE_EXPECT( context, campaign.applyResults( applied) == 0U && applied == 2U &&
										campaign.targetStates()[0] ==
											CollectorCampaignTargetState::UNSUPPORTED) ;
	}
	{
		// 同rootの別campaignに二jobを追加する。
		LocalCollectorCampaign campaign ;
		const auto			   input = manifest( 2U, 2U, L"failure") ;	// 成功と失敗の混在。
		DRIVERCRATE_EXPECT( context, campaign.initialize( root, input, HASH, UTC) == 0U) ;
		// 一つ目だけが成功する。
		CollectorCampaignDispatch dispatch ;
		DRIVERCRATE_EXPECT( context, campaign.reserve( UTC, dispatch) ==
										CollectorCampaignDispatchResult::READY) ;
		DRIVERCRATE_EXPECT( context, campaign.finish( dispatch.jobKey, success(), UTC) == 0U) ;
		// 二つ目の解析失敗を元code付きで保持する。
		CollectorCampaignObservation failed ;
		failed.state	  = CollectorCampaignJobState::FAILED ;
		failed.error	  = ERROR_INVALID_DATA ;
		failed.httpStatus = 200U ;
		DRIVERCRATE_EXPECT( context, campaign.reserve( UTC + 2U, dispatch) ==
										CollectorCampaignDispatchResult::READY) ;
		DRIVERCRATE_EXPECT( context, campaign.finish( dispatch.jobKey, failed, UTC + 2U) == 0U) ;
		// 共有製品への部分失敗を成功にしない。
		std::size_t applied{} ;
		DRIVERCRATE_EXPECT( context,
						   campaign.applyResults( applied) == 0U &&
							   campaign.targetStates()[0] == CollectorCampaignTargetState::FAILED) ;
		DRIVERCRATE_EXPECT( context, campaign.finish( dispatch.jobKey, failed, UTC + 2U) ==
										ERROR_INVALID_DATA) ;
	}
	{
		// ACLは維持したまま本文を破損させる。
		LocalCollectorStateStore store ;
		DRIVERCRATE_EXPECT( context, store.initialize( root, true) == 0U) ;
		DRIVERCRATE_EXPECT( context, store.write( L"current/campaign-budget-v1.json", "{}") == 0U) ;
	}
	{
		// 別manifestでも共通台帳破損は初回として受理しない。
		LocalCollectorCampaign corrupt ;
		DRIVERCRATE_EXPECT( context, corrupt.initialize( root, manifest( 1U, 1U, L"corrupt"), HASH,
													   UTC + 3U) == ERROR_INVALID_DATA) ;
	}
}

/**
 * @brief 台帳欠損・別campaign中断予約・過大応答の拒否を確認します。
 * @param[in,out] context 非通信assertion集計。
 * @param[in,out] roots 自作rootを追加する回収集合。
 */
void stateBoundaries( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 自作rootからbudgetだけを失わせるscenario。
	const auto missingRoot = rootFor( roots) ;
	{
		// 初回budgetとimmutable markerをproduction APIで作成する。
		LocalCollectorCampaign original ;
		DRIVERCRATE_EXPECT( context, original.initialize( missingRoot, manifest(), HASH, UTC) == 0U) ;
	}
	// 確認済み自作rootの特定一fileだけを削除し、欠損を再現する。
	DRIVERCRATE_EXPECT(
		context, DeleteFileW( (missingRoot / L"current/campaign-budget-v1.json").c_str()) != FALSE) ;
	{
		// 別manifestもmarkerのあるrootを初回扱いしない。
		LocalCollectorCampaign missing ;
		DRIVERCRATE_EXPECT( context, missing.initialize( missingRoot, manifest( 1U, 1U, L"different"),
													   HASH, UTC) == ERROR_INVALID_DATA) ;
	}
	// 別campaignが中断したsource枠を回収するscenario。
	const auto abandonedRoot = rootFor( roots) ;
	// 再開対象の固定入力。
	const auto first = manifest( 1U, 1U, L"abandoned") ;
	{
		// 予約したまま監督を終了させる。
		LocalCollectorCampaign abandoned ;
		DRIVERCRATE_EXPECT( context, abandoned.initialize( abandonedRoot, first, HASH, UTC) == 0U) ;
		// Sourceを一枠使用した予約。
		CollectorCampaignDispatch dispatch ;
		DRIVERCRATE_EXPECT( context, abandoned.reserve( UTC, dispatch) ==
										CollectorCampaignDispatchResult::READY) ;
	}
	{
		// 同groupの別campaignが古いin-flight枠を引き継がない。
		LocalCollectorCampaign other ;
		DRIVERCRATE_EXPECT( context, other.initialize( abandonedRoot, manifest( 1U, 1U, L"following"),
													 HASH, UTC + 2U) == 0U) ;
		// 元の最大byte課金を維持して新予約を一つ作る。
		CollectorCampaignDispatch dispatch ;
		DRIVERCRATE_EXPECT( context, other.reserve( UTC + 2U, dispatch) ==
										CollectorCampaignDispatchResult::READY) ;
		DRIVERCRATE_EXPECT( context, other.finish( dispatch.jobKey, success(), UTC + 2U) == 0U) ;
	}
	{
		// 元campaignは同じjobを再送せず中断へ確定する。
		LocalCollectorCampaign recovered ;
		DRIVERCRATE_EXPECT( context,
						   recovered.initialize( abandonedRoot, first, HASH, UTC + 3U) == 0U &&
							   recovered.observations()[0].state ==
								   CollectorCampaignJobState::INTERRUPTED) ;
	}
	// 過大な観測を拒否して予算を返金しないscenario。
	const auto overflowRoot = rootFor( roots) ;
	{
		// 固定一byteの応答予算。
		LocalCollectorCampaign limited ;
		DRIVERCRATE_EXPECT(
			context,
			limited.initialize( overflowRoot, manifest( 1U, 1U, L"limited", 1U), HASH, UTC) == 0U) ;
		// 一byteだけを先払いした予約。
		CollectorCampaignDispatch dispatch ;
		DRIVERCRATE_EXPECT( context, limited.reserve( UTC, dispatch) ==
										CollectorCampaignDispatchResult::READY) ;
		DRIVERCRATE_EXPECT( context,
						   limited.finish( dispatch.jobKey, success( 2U), UTC) == ERROR_INVALID_DATA) ;
	}
	{
		// 過大応答は成功保存されず、未確定予約を回収する。
		LocalCollectorCampaign recovered ;
		DRIVERCRATE_EXPECT(
			context,
			recovered.initialize( overflowRoot, manifest( 1U, 1U, L"limited", 1U), HASH, UTC + 1U) ==
					0U &&
				recovered.observations()[0].state == CollectorCampaignJobState::INTERRUPTED) ;
	}
}

/**
 * @brief 日次履歴が移った後のcampaign本文／marker欠損を拒否します。
 * @param[in,out] context 非通信assertion集計。
 * @param[in,out] roots 自作rootを追加する回収集合。
 */
void campaignLoss( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 本文だけ欠損する場合と、immutable markerだけ欠損する場合を確認する。
	for( const bool loseBody : {true, false}) {
		// 自作root内の固定campaignだけを削除scenarioへ使う。
		const auto root = rootFor( roots) ;
		// 完了結果を持つ最初のcampaign。
		const auto input = manifest( 1U, 1U, L"completed") ;
		{
			// 一要求の成功を保存し、翌日以降に再送できない状態を作る。
			LocalCollectorCampaign completed ;
			DRIVERCRATE_EXPECT( context, completed.initialize( root, input, HASH, UTC) == 0U) ;
			// 一件の架空metadata予約。
			CollectorCampaignDispatch dispatch ;
			DRIVERCRATE_EXPECT( context, completed.reserve( UTC, dispatch) ==
											CollectorCampaignDispatchResult::READY) ;
			DRIVERCRATE_EXPECT( context, completed.finish( dispatch.jobKey, success(), UTC) == 0U) ;
		}
		{
			// 他campaignによる日跨ぎで元予約を旧日のarchiveへ移す。
			LocalCollectorCampaign later ;
			DRIVERCRATE_EXPECT( context, later.initialize( root, manifest( 1U, 1U, L"later"), HASH,
														 UTC + 86400U) == 0U) ;
		}
		// 本番identity規則から、既知の自作一fileだけを特定する。
		std::wstring key ;
		// 実SDKのSHA-256表記を本番の小文字へ正規化する。
		DRIVERCRATE_EXPECT(
			context, computeBytesSha256( winrt::to_string( winrt::hstring( input.manifestSha256)) +
											"\n" + winrt::to_string( winrt::hstring( HASH)) + "\n",
										key) == 0) ;
		// HashのASCII大文字だけを変換し、pathへ任意入力を渡さない。
		for( auto &digit : key) {
			// SDKが大文字で返したhexだけを下げる。
			if( digit >= L'A' && digit <= L'F') {
				digit = digit - L'A' + L'a' ;
			}
		}

		// GUID専用rootに生成された、hash付き一fileの絶対path。
		const auto missing =
			root / L"current" /
			((loseBody ? L"campaign-v1-" : L"campaign-marker-v1-") + key + L".json") ;
		DRIVERCRATE_EXPECT( context, DeleteFileW( campaignFixtureIoPath( missing).c_str()) != FALSE) ;
		{
			// 欠損を元の固定manifestのPENDINGへ戻して再送しない。
			LocalCollectorCampaign rejected ;
			DRIVERCRATE_EXPECT( context, rejected.initialize( root, input, HASH, UTC + 86401U) ==
											ERROR_INVALID_DATA) ;
			// 拒否後にも欠損fileを自動再作成しない。
			DRIVERCRATE_EXPECT( context, !std::filesystem::exists( missing)) ;
		}
	}
}

/**
 * @brief 監督storeの借用・排他・解放と既存予算の共有を確認します。
 * @param[in,out] context 非通信assertion集計。
 * @param[in] root 自作GUID付き専用root。
 */
void borrowedStore( TestContext &context, const std::filesystem::path &root)
{
	// 一度だけwriterを所有する監督。
	LocalCollectorStateStore store ;
	DRIVERCRATE_EXPECT( context, !store.isWritable()) ;
	DRIVERCRATE_EXPECT( context, store.initialize( root, false) == 0U && !store.isWritable()) ;
	DRIVERCRATE_EXPECT( context, !std::filesystem::exists( root)) ;
	{
		// read-only検証を借用writerとして扱わない。
		LocalCollectorCampaign rejected ;
		DRIVERCRATE_EXPECT( context, rejected.initializeBorrowed( store, manifest(), HASH, UTC) ==
										ERROR_INVALID_PARAMETER) ;
	}

	DRIVERCRATE_EXPECT( context, store.initialize( root, true) == 0U && store.isWritable()) ;
	DRIVERCRATE_EXPECT( context, store.root() == root) ;
	{
		// 初回coreは既存writerを二重取得しない。
		LocalCollectorCampaign first ;
		DRIVERCRATE_EXPECT( context, first.initializeBorrowed( store, manifest(), HASH, UTC) == 0U) ;
		// 監督は借用中でも待機射影等を同じstoreへ保存できる。
		DRIVERCRATE_EXPECT( context, store.write( L"current/supervisor-fixture.json", "{}") == 0U) ;
		{
			// 二つのcoreが同じbudgetを別々に保持することを拒否する。
			LocalCollectorCampaign second ;
			DRIVERCRATE_EXPECT( context, second.initializeBorrowed( store, manifest(), HASH, UTC) ==
											ERROR_BUSY) ;
			// 失敗した借用者の破棄でfirstのleaseを解除しない。
			LocalCollectorCampaign third ;
			DRIVERCRATE_EXPECT( context, third.initializeBorrowed( store, manifest(), HASH, UTC) ==
											ERROR_BUSY) ;
		}

		DRIVERCRATE_EXPECT( context,
						   store.initialize( root, false) == ERROR_BUSY && store.isWritable()) ;
		// 別root所有coreはOS writer lockでも拒否する。
		LocalCollectorCampaign separate ;
		DRIVERCRATE_EXPECT( context, separate.initialize( root, manifest(), HASH, UTC) ==
										ERROR_SHARING_VIOLATION) ;
		// 拒否後も元の借用coreを正常に完了できる。
		CollectorCampaignDispatch dispatch ;
		DRIVERCRATE_EXPECT( context,
						   first.reserve( UTC, dispatch) == CollectorCampaignDispatchResult::READY) ;
		DRIVERCRATE_EXPECT( context, first.finish( dispatch.jobKey, success( 7U), UTC + 1U) == 0U) ;
	}

	DRIVERCRATE_EXPECT( context, store.isWritable()) ;
	{
		// 借用者破棄後も監督writerのまま保存結果を再利用する。
		LocalCollectorCampaign resume ;
		DRIVERCRATE_EXPECT( context,
						   resume.initializeBorrowed( store, manifest(), HASH, UTC + 2U) == 0U) ;
		// 同じjobに追加予約を生成しない。
		CollectorCampaignDispatch dispatch ;
		DRIVERCRATE_EXPECT( context, resume.reserve( UTC + 2U, dispatch) ==
										CollectorCampaignDispatchResult::COMPLETE) ;
		DRIVERCRATE_EXPECT( context, resume.observations()[0].receivedBytes == 7U) ;
	}

	{
		// 別manifestでも同じ日次budgetへ一件だけ追加する。
		LocalCollectorCampaign other ;
		DRIVERCRATE_EXPECT( context, other.initializeBorrowed( store, manifest( 1U, 1U, L"other"),
															 HASH, UTC + 2U) == 0U) ;
		// 元台帳の課金が保存されたまま次のjobを追加する。
		CollectorCampaignDispatch dispatch ;
		DRIVERCRATE_EXPECT( context, other.reserve( UTC + 2U, dispatch) ==
										CollectorCampaignDispatchResult::READY) ;
		DRIVERCRATE_EXPECT( context, other.finish( dispatch.jobKey, success( 9U), UTC + 3U) == 0U) ;
	}

	// 既存v1予算schemaと二予約の実byteを原fileから確認する。
	std::string bytes ;
	// 存在確認と読取り成功を分離する。
	bool		found{} ;
	DRIVERCRATE_EXPECT( context,
					   store.read( L"current/campaign-budget-v1.json", bytes, found) == 0U && found) ;
	// Hash envelope内の保存本文を読む。
	const auto envelope = JsonObject::Parse( winrt::to_hstring( bytes)) ;
	// 元予算schemaは変更していない。
	const auto budget = JsonObject::Parse( envelope.GetNamedString( L"body")) ;
	DRIVERCRATE_EXPECT( context,
					   budget.GetNamedString( L"schema") == L"collector-campaign-budget-v1") ;
	// 全campaignへ共通の二件分の予約。
	const auto reservations = budget.GetNamedArray( L"reservations") ;
	DRIVERCRATE_EXPECT( context, reservations.Size() == 2U) ;
	DRIVERCRATE_EXPECT( context,
					   reservations.GetAt( 0U).GetObject().GetNamedNumber( L"charged") == 7.0) ;
	DRIVERCRATE_EXPECT( context,
					   reservations.GetAt( 1U).GetObject().GetNamedNumber( L"charged") == 9.0) ;
}

/**
 * @brief 架空要求の完全hashを生成します。
 * @param[in] group 架空の公開group。
 * @param[in] request Request hashへ使う小文字16進のfixture文字。
 * @param[in] generation Generation hashへ使う小文字16進のfixture文字。
 * @return URL・端末IDなしの要求identity。
 */
[[nodiscard]] CollectorWaitRequest waitRequest( const std::wstring_view group	  = L"group0",
											   const wchar_t		   request	  = L'b',
											   const wchar_t		   generation = L'a')
{
	return {std::wstring( group), std::wstring( 64U, request), std::wstring( 64U, generation), HASH} ;
}

/**
 * @brief 旧collectorの実schemaとhashを使う待機fileを生成します。
 * @param[in,out] store 自作GUID rootのwriter。
 * @param[in] group 初期二sourceのgroup。
 * @param[in] next 旧schemaのUTC秒で表す待機期限。
 * @param[in] review 自動解除しない待機。
 * @return 保護storeへの保存成功時true。
 */
[[nodiscard]] bool legacyWait( LocalCollectorStateStore &store, const std::wstring_view group,
							  const std::uint64_t next, const bool review)
{
	// 旧collectorが保存する固定source名。
	const std::wstring source = group == L"asus" ? L"ASUS_CATALOG" : L"INTEL_ETHERNET_WINDOWS11" ;
	// 原headerを含めない旧待機本文。
	JsonObject		   body ;
	body.Insert( L"schema", JsonValue::CreateStringValue( L"dc-collector-cooldown-v1")) ;
	body.Insert( L"source", JsonValue::CreateStringValue( source)) ;
	body.Insert( L"observedAt", JsonValue::CreateNumberValue( static_cast<double>( UTC))) ;
	body.Insert( L"nextAttemptAt", JsonValue::CreateNumberValue( static_cast<double>( next))) ;
	body.Insert( L"status", JsonValue::CreateNumberValue( 429.0)) ;
	body.Insert( L"needsReview", JsonValue::CreateBooleanValue( review)) ;
	// 完全hashに結合するUTF-8原本文。
	const auto	 bytes = winrt::to_string( body.Stringify()) ;
	// 原sourceの固定file名。
	std::wstring sourceHash ;
	// 原本文の破損検出hash。
	std::wstring bodyHash ;
	// productionと同じhash APIを使う。
	if( computeBytesSha256( winrt::to_string( winrt::hstring( source)), sourceHash) != 0U ||
	   computeBytesSha256( bytes, bodyHash) != 0U) {
		return false ;
	}

	// 旧schemaと同じenvelopeを保護storeへ保存する。
	JsonObject envelope ;
	envelope.Insert( L"schema", JsonValue::CreateStringValue( L"dc-collector-envelope-v1")) ;
	envelope.Insert( L"body", JsonValue::CreateStringValue( winrt::to_hstring( bytes))) ;
	envelope.Insert( L"sha256", JsonValue::CreateStringValue( bodyHash)) ;
	return store.write( std::filesystem::path( L"current") / (L"cooldown-" + sourceHash + L".json"),
					   winrt::to_string( envelope.Stringify())) == 0U ;
}

/**
 * @brief 二時計の間隔・同group排他・再起動待機と旧source引継ぎを確認します。
 * @param[in,out] context 非通信assertion集計。
 * @param[in,out] roots 自作GUID rootの回収集合。
 */
void waitBoundaries( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 第一応答前にもmillisecond境界を検査する固定時刻。
	constexpr std::uint64_t	 utc = UTC * 1000U + 999U ;
	// 一つのwriterへcoreと待機台帳を共存させる。
	LocalCollectorStateStore store ;
	DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
	{
		// 同じwriter内の予算core。
		LocalCollectorCampaign core ;
		DRIVERCRATE_EXPECT( context, core.initializeBorrowed( store, manifest(), HASH, UTC) == 0U) ;
		// 同じwriterを借用する待機監督。
		LocalCollectorWaitLedger ledger ;
		DRIVERCRATE_EXPECT( context, ledger.initialize( store, utc, 100U) == 0U) ;
		// 同じ単調時計基準を別監督が置き換えない。
		LocalCollectorWaitLedger duplicate ;
		DRIVERCRATE_EXPECT( context, duplicate.initialize( store, utc, 100U) == ERROR_BUSY) ;
		DRIVERCRATE_EXPECT( context, store.initialize( store.root(), false) == ERROR_BUSY) ;
		// 待機の初回には追加期限を生成しない。
		CollectorWaitDecision decision{} ;
		// 一要求に固定した非機密identity。
		const auto			  request = waitRequest() ;
		DRIVERCRATE_EXPECT( context, ledger.check( request, utc, 100U, decision) == 0U &&
										decision == CollectorWaitDecision::READY) ;
		DRIVERCRATE_EXPECT( context, ledger.begin( request, utc, 100U) == 0U) ;
		DRIVERCRATE_EXPECT( context,
						   ledger.check( waitRequest( L"group0", L'c'), utc, 100U, decision) == 0U &&
							   decision == CollectorWaitDecision::RECOVERY_REQUIRED) ;
		// 独立groupは同時に進められる。
		DRIVERCRATE_EXPECT( context,
						   ledger.check( waitRequest( L"group1", L'd'), utc, 100U, decision) == 0U &&
							   decision == CollectorWaitDecision::READY) ;
		DRIVERCRATE_EXPECT( context, ledger.finish( request, {true, 200U}, utc + 1U, 101U) == 0U) ;
		// 秒切捨てやUTCの急進だけでは二秒間隔を通過しない。
		DRIVERCRATE_EXPECT( context, ledger.check( waitRequest( L"group0", L'c'), utc + 2000U, 2100U,
												 decision) == 0U &&
										decision == CollectorWaitDecision::WAIT) ;
		DRIVERCRATE_EXPECT( context, ledger.check( waitRequest( L"group0", L'c'), utc + 9000U, 2100U,
												 decision) == 0U &&
										decision == CollectorWaitDecision::WAIT) ;
		DRIVERCRATE_EXPECT( context, ledger.check( waitRequest( L"group0", L'c'), utc + 9001U, 2101U,
												 decision) == 0U &&
										decision == CollectorWaitDecision::READY) ;
		// Requestは別generationでも24時間freshness待機を保持する。
		DRIVERCRATE_EXPECT( context, ledger.check( waitRequest( L"group0", L'b', L'e'), utc + 9001U,
												 2101U, decision) == 0U &&
										decision == CollectorWaitDecision::WAIT) ;
	}

	DRIVERCRATE_EXPECT( context, store.isWritable()) ;
	{
		// 別process相当の単調時計でも保存UTCと保守的二秒を確認する。
		LocalCollectorWaitLedger reopened ;
		DRIVERCRATE_EXPECT( context, reopened.initialize( store, utc + 10000U, 0U) == 0U) ;
		// 旧group完了は起動直後に即再開しない。
		CollectorWaitDecision decision{} ;
		DRIVERCRATE_EXPECT( context, reopened.check( waitRequest( L"group0", L'c'), utc + 10000U, 0U,
												   decision) == 0U &&
										decision == CollectorWaitDecision::WAIT) ;
		DRIVERCRATE_EXPECT( context, reopened.check( waitRequest( L"group0", L'c'), utc + 12000U,
												   2000U, decision) == 0U &&
										decision == CollectorWaitDecision::READY) ;
		DRIVERCRATE_EXPECT( context,
						   reopened.check( waitRequest(), utc + 86400000U, 3000U, decision) == 0U &&
							   decision == CollectorWaitDecision::WAIT) ;
		DRIVERCRATE_EXPECT( context,
						   reopened.check( waitRequest(), utc + 86400001U, 3001U, decision) == 0U &&
							   decision == CollectorWaitDecision::READY) ;
	}

	// 二sourceの旧fileは変更せず、最大期限と要確認を読む。
	LocalCollectorStateStore legacy ;
	DRIVERCRATE_EXPECT( context, legacy.initialize( rootFor( roots), true) == 0U) ;
	DRIVERCRATE_EXPECT( context, legacyWait( legacy, L"asus", UTC + 172800U, false)) ;
	DRIVERCRATE_EXPECT( context, legacyWait( legacy, L"intel", UTC + 1U, true)) ;
	{
		// 新wait台帳が旧source待機を読み取る。
		LocalCollectorWaitLedger ledger ;
		DRIVERCRATE_EXPECT( context, ledger.initialize( legacy, utc, 0U) == 0U) ;
		// ASUSは将来の期限待ち、Intelは期限経過後もreview。
		CollectorWaitDecision decision{} ;
		DRIVERCRATE_EXPECT( context, ledger.check( waitRequest( L"asus"), utc, 0U, decision) == 0U &&
										decision == CollectorWaitDecision::WAIT) ;
		DRIVERCRATE_EXPECT(
			context, ledger.check( waitRequest( L"intel"), utc + 10000U, 10000U, decision) == 0U &&
						 decision == CollectorWaitDecision::NEEDS_REVIEW) ;
		// 待機確認では旧fileを更新しない。
		DRIVERCRATE_EXPECT( context,
						   ledger.begin( waitRequest( L"asus"), utc + 10000U, 10000U) == ERROR_RETRY) ;
		DRIVERCRATE_EXPECT( context, ledger.lastError() == 0U) ;
	}

	// 年2100以降の有効な旧期限を短い期限へ丸めない。
	LocalCollectorStateStore farFuture ;
	DRIVERCRATE_EXPECT( context, farFuture.initialize( rootFor( roots), true) == 0U) ;
	DRIVERCRATE_EXPECT( context, legacyWait( farFuture, L"asus", 253402300799ULL, false)) ;
	// 原期限の上限を保ち要確認にする。
	LocalCollectorWaitLedger futureLedger ;
	DRIVERCRATE_EXPECT( context, futureLedger.initialize( farFuture, utc, 0U) == 0U) ;
	// 独立groupへ期限外の値を伝播しない。
	CollectorWaitDecision decision{} ;
	DRIVERCRATE_EXPECT( context, futureLedger.check( waitRequest( L"asus"), utc, 0U, decision) == 0U &&
									decision == CollectorWaitDecision::NEEDS_REVIEW) ;
	// 旧fileが失われても取り込み済みの遠い期限・reviewを維持する。
	std::wstring sourceHash ;
	DRIVERCRATE_EXPECT( context, computeBytesSha256( "ASUS_CATALOG", sourceHash) == 0U) ;
	DRIVERCRATE_EXPECT(
		context,
		DeleteFileW(
			(farFuture.root() / L"current" / (L"cooldown-" + sourceHash + L".json")).c_str()) !=
			FALSE) ;
	DRIVERCRATE_EXPECT( context,
					   futureLedger.check( waitRequest( L"asus"), utc + 1U, 1U, decision) == 0U &&
						   decision == CollectorWaitDecision::NEEDS_REVIEW) ;
	// 原期限を保存値から再確認し、2100年へ切り詰めていないことを確かめる。
	std::string saved ;
	// 保存済みcontrolの存在確認。
	bool		found{} ;
	DRIVERCRATE_EXPECT(
		context, farFuture.read( L"current/campaign-controls-v1.json", saved, found) == 0U && found) ;
	// 非機密control台帳の原envelope。
	const auto envelope = JsonObject::Parse( winrt::to_hstring( saved)) ;
	// 取り込み済み原値を読む保存本文。
	const auto body = JsonObject::Parse( envelope.GetNamedString( L"body")) ;
	DRIVERCRATE_EXPECT(
		context,
		body.GetNamedArray( L"controls").GetAt( 0U).GetObject().GetNamedNumber( L"notBefore") ==
			253402300799000.0) ;
}

/**
 * @brief 429／403・開始中断・304の待機を再起動と別generationで確認します。
 * @param[in,out] context 非通信assertion集計。
 * @param[in,out] roots 自作GUID rootの回収集合。
 */
void waitRecovery( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 応答の種類ごとに別の自作storeを使用する。
	for( const std::uint32_t status : {0U, 200U, 304U, 403U, 429U, 503U}) {
		// 外部clockへ依存しない固定millisecond。
		constexpr std::uint64_t	 utc = UTC * 1000U ;
		// 元予約の架空identity。
		const auto				 request = waitRequest() ;
		// 一度だけwriterを所有する監督。
		LocalCollectorStateStore store ;
		DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
		{
			// 開始intentの後でprocess相当の監督を終了する。
			LocalCollectorWaitLedger ledger ;
			DRIVERCRATE_EXPECT( context, ledger.initialize( store, utc, 0U) == 0U) ;
			DRIVERCRATE_EXPECT( context, ledger.begin( request, utc, 0U) == 0U) ;
		}

		{
			// 同じrequestの開始intentは日付やgenerationの変更だけで解除しない。
			LocalCollectorWaitLedger ledger ;
			DRIVERCRATE_EXPECT( context, ledger.initialize( store, utc + 1000U, 0U) == 0U) ;
			// 元開始のまま回収を要求する。
			CollectorWaitDecision decision{} ;
			DRIVERCRATE_EXPECT( context, ledger.check( waitRequest( L"group0", L'b', L'c'),
													 utc + 1000U, 0U, decision) == 0U &&
											decision == CollectorWaitDecision::RECOVERY_REQUIRED) ;
			// 応答intentがなければ回収時刻から24時間を保持する。
			if( status == 0U) {
				DRIVERCRATE_EXPECT( context,
								   ledger.recoverInterrupted( request, utc + 1000U, 0U) == 0U) ;
			} else {
				// 429と503は長いRetry-Afterをgroupへ反映する。
				const CollectorWaitObservation observed{
					status == 200U || status == 304U, status,
					status == 429U || status == 503U ? utc + 172800000U : 0U} ;
				DRIVERCRATE_EXPECT( context,
								   ledger.finish( request, observed, utc + 1000U, 0U) == 0U) ;
			}
		}

		{
			// 再起動した別generationから旧待機を再検査する。
			LocalCollectorWaitLedger ledger ;
			DRIVERCRATE_EXPECT( context, ledger.initialize( store, utc + 10000U, 0U) == 0U) ;
			// 同groupの別requestへ及ぶ待機を確認する。
			CollectorWaitDecision decision{} ;
			DRIVERCRATE_EXPECT( context, ledger.check( waitRequest( L"group0", L'd', L'e'),
													 utc + 12000U, 2000U, decision) == 0U) ;
			DRIVERCRATE_EXPECT( context,
							   decision == (status == 403U ? CollectorWaitDecision::NEEDS_REVIEW
											: status == 429U || status == 503U
												? CollectorWaitDecision::WAIT
												: CollectorWaitDecision::READY)) ;
			DRIVERCRATE_EXPECT( context, ledger.check( waitRequest( L"group0", L'b', L'e'),
													 utc + 12000U, 2000U, decision) == 0U) ;
			DRIVERCRATE_EXPECT( context,
							   decision == (status == 403U ? CollectorWaitDecision::NEEDS_REVIEW
														   : CollectorWaitDecision::WAIT)) ;
			// 同じ根にある他groupのdue判定は独立している。
			DRIVERCRATE_EXPECT( context, ledger.check( waitRequest( L"other", L'f'), utc + 12000U,
													 2000U, decision) == 0U &&
											decision == CollectorWaitDecision::READY) ;
		}
	}
}

/**
 * @brief 台帳欠損・未知schema・時計・完了identityの拒否を確認します。
 * @param[in,out] context 非通信assertion集計。
 * @param[in,out] roots 自作GUID rootの回収集合。
 */
void waitFailures( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 各拒否は新規storeで試し、失敗後の無言継続も拒否する。
	for( std::size_t index = 0U; index < 9U; ++index) {
		// 固定UTC millisecond。
		constexpr std::uint64_t	 utc = UTC * 1000U ;
		// 自作rootだけを回収対象へ入れる。
		const auto				 root = rootFor( roots) ;
		// 監督writer。
		LocalCollectorStateStore store ;
		DRIVERCRATE_EXPECT( context, store.initialize( root, true) == 0U) ;
		// テスト対象の待機台帳。
		LocalCollectorWaitLedger ledger ;
		DRIVERCRATE_EXPECT( context, ledger.initialize( store, utc, 10U) == 0U) ;
		DRIVERCRATE_EXPECT( context, ledger.begin( waitRequest(), utc, 10U) == 0U) ;
		// 拒否操作後に元開始intentを成功へ変えない。
		DWORD error{} ;
		// Fixtureの明示条件ごとに保存境界の違反を作る。
		switch( index) {
			case 0U:
				// 本文欠損を新規control集合として再作成しない。
				DRIVERCRATE_EXPECT(
					context,
					DeleteFileW( (root / L"current/campaign-controls-v1.json").c_str()) != FALSE) ;
				break ;

			case 1U:
				// Marker欠損も新規扱いにしない。
				DRIVERCRATE_EXPECT(
					context,
					DeleteFileW( (root / L"current/campaign-controls-marker-v1.json").c_str()) !=
						FALSE) ;
				break ;

			case 2U:
				// 未知schemaのenvelopeを正常な空台帳とみなさない。
				DRIVERCRATE_EXPECT( context,
								   store.write( L"current/campaign-controls-v1.json", "{}") == 0U) ;
				break ;

			case 3U:
				// 完了の別generationは保存開始intentを解除できない。
				error =
					ledger.finish( waitRequest( L"group0", L'b', L'c'), {true, 200U}, utc + 1U, 11U) ;
				break ;

			case 4U:
				// 304へ原本文取得成功のstatusを偽装しない。
				error = ledger.finish( waitRequest(), {true, 503U}, utc + 1U, 11U) ;
				break ;

			case 5U:
				// UTC巻戻しを待機期限の解除へ使用しない。
				error = ledger.finish( waitRequest(), {true, 200U}, utc - 1U, 11U) ;
				break ;

			case 6U:
				// 単調時計の巻戻しも拒否する。
				error = ledger.finish( waitRequest(), {true, 200U}, utc + 1U, 9U) ;
				break ;

			case 7U:
				// 原requestの所属groupを別名に変えて待機を抜けない。
				error = ledger.finish( waitRequest( L"other"), {true, 200U}, utc + 1U, 11U) ;
				break ;

			case 8U:
				// 別threadからwriterの監督stateを操作しない。
				{
					// 子threadが戻るまで唯一の呼出し元を待つ。
					std::thread worker( [&]() {
						CollectorWaitDecision decision{} ;	// 非通信のthread拒否結果。
						error = ledger.check( waitRequest(), utc, 10U, decision) ;
					}) ;
					worker.join() ;
				}
				break ;
		}

		// file破損の三条件はcheck時に拒否を観測する。
		if( index < 3U) {
			// 拒否時には開始可能なdecisionを返さない。
			CollectorWaitDecision decision{} ;
			error = ledger.check( waitRequest(), utc, 10U, decision) ;
			DRIVERCRATE_EXPECT( context, decision == CollectorWaitDecision::NEEDS_REVIEW) ;
		}

		DRIVERCRATE_EXPECT( context, error == ERROR_INVALID_DATA) ;
		DRIVERCRATE_EXPECT( context, ledger.lastError() == ERROR_INVALID_DATA) ;
		DRIVERCRATE_EXPECT( context, ledger.recoverInterrupted( waitRequest(), utc + 100U, 110U) ==
										ERROR_INVALID_DATA) ;
	}
}

/**
 * @brief 控えめな制御上限と初回保存窓・更新失敗の状態を確認します。
 * @param[in,out] context 非通信assertion集計。
 * @param[in,out] roots 自作GUID rootの回収集合。
 */
void waitCapacityAndSave( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// Group／request上限をnative保存parserの入口で検証する。
	for( std::size_t condition = 0U; condition < 4U; ++condition) {
		// Source数と要求数を別々に上限へ固定する。
		const std::size_t		 count = condition < 2U ? 20U + condition : 300U + condition - 2U ;
		// 自作rootにだけ試験台帳を作成する。
		LocalCollectorStateStore store ;
		DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
		{
			// Markerと初回空台帳を通常APIで生成する。
			LocalCollectorWaitLedger empty ;
			DRIVERCRATE_EXPECT( context, empty.initialize( store, UTC * 1000U, 0U) == 0U) ;
		}

		// 保存schemaを固定した境界fixture本文。
		JsonObject body ;
		body.Insert( L"schema", JsonValue::CreateStringValue( L"collector-campaign-controls-v1")) ;
		body.Insert( L"lastUtcMillis",
					JsonValue::CreateNumberValue( static_cast<double>( UTC * 1000U))) ;
		// Productionが受理する順序で保存する有限entry集合。
		JsonArray  controls ;
		// 個別controlを型・文字列・数値の正規形で追加するcapture。
		const auto append = [&]( const std::wstring &group, const std::wstring &request) {
			JsonObject row ;	// 一つのcontrolの許可field。
			row.Insert( L"key", JsonValue::CreateStringValue( request.empty() ? L"g-" + group
																			: L"r-" + request)) ;
			row.Insert( L"group", JsonValue::CreateStringValue( group)) ;
			row.Insert( L"request", JsonValue::CreateStringValue( request)) ;
			row.Insert( L"observed", JsonValue::CreateNumberValue( static_cast<double>( UTC * 1000U))) ;
			row.Insert( L"notBefore", JsonValue::CreateNumberValue( 0.0)) ;
			row.Insert( L"completed", JsonValue::CreateNumberValue( 0.0)) ;
			row.Insert( L"needsReview", JsonValue::CreateBooleanValue( false)) ;
			row.Insert( L"generation", JsonValue::CreateStringValue( L"")) ;
			row.Insert( L"job", JsonValue::CreateStringValue( L"")) ;
			row.Insert( L"started", JsonValue::CreateNumberValue( 0.0)) ;
			controls.Append( row) ;
		} ;
		// Request上限fixtureには所属groupを先に登録する。
		if( condition >= 2U) {
			append( L"group0", L"") ;
		}

		// Keyをmapと同じ順に固定して非canonical拒否と個数拒否を混同しない。
		std::map<std::wstring, std::wstring> values ;
		// 架空の公開labelだけから有限request hashを生成する。
		for( std::size_t index = 0U; index < count; ++index) {
			// 個数の境界だけを変えるfixture label。
			const auto	 label = L"group" + std::to_wstring( index) ;
			// Request identityへ使用する完全hash。
			std::wstring hash ;
			DRIVERCRATE_EXPECT(
				context, computeBytesSha256( winrt::to_string( winrt::hstring( label)), hash) == 0U) ;
			values.emplace( condition < 2U ? label : hash, condition < 2U ? label : L"group0") ;
		}

		// 先に生成した全keyを辞書順で追加する。
		for( const auto &value : values) {
			append( value.second, condition < 2U ? L"" : value.first) ;
		}

		body.Insert( L"controls", controls) ;
		// Production形式と同じhash envelopeを保護writerで保存する。
		const auto	 bytes = winrt::to_string( body.Stringify()) ;
		// 改変本文へ結合するfixture hash。
		std::wstring hash ;
		DRIVERCRATE_EXPECT( context, computeBytesSha256( bytes, hash) == 0U) ;
		// 正常envelopeにした上で件数を検査する。
		JsonObject envelope ;
		envelope.Insert( L"schema", JsonValue::CreateStringValue( L"collector-campaign-envelope-v1")) ;
		envelope.Insert( L"body", JsonValue::CreateStringValue( winrt::to_hstring( bytes))) ;
		envelope.Insert( L"sha256", JsonValue::CreateStringValue( hash)) ;
		DRIVERCRATE_EXPECT( context, store.write( L"current/campaign-controls-v1.json",
												winrt::to_string( envelope.Stringify())) == 0U) ;
		// 境界値は受理し、一つ超過した値は空台帳へ戻さず拒否する。
		LocalCollectorWaitLedger bounded ;
		DRIVERCRATE_EXPECT(
			context, bounded.initialize( store, UTC * 1000U, 0U) ==
						 (condition % 2U == 0U ? 0U : static_cast<DWORD>( ERROR_INVALID_DATA))) ;
	}

	{
		// 通常のfile置換だけを阻むread handleで保存失敗を再現する。
		LocalCollectorStateStore store ;
		// 自作GUID rootだけを対象にする。
		const auto				 root = rootFor( roots) ;
		DRIVERCRATE_EXPECT( context, store.initialize( root, true) == 0U) ;
		// 旧台帳を保持したまま更新失敗を観測する監督。
		LocalCollectorWaitLedger ledger ;
		DRIVERCRATE_EXPECT( context, ledger.initialize( store, UTC * 1000U, 0U) == 0U) ;
		// 原台帳のbyteを変更前に保存する。
		std::string before ;
		// 原台帳の存在確認。
		bool		found{} ;
		DRIVERCRATE_EXPECT( context,
						   store.read( L"current/campaign-controls-v1.json", before, found) == 0U &&
							   found) ;
		// 置換の削除共有を許さず、保護ACLやOS設定は変更しない。
		Microsoft::WRL::Wrappers::FileHandle held(
			CreateFileW( (root / L"current/campaign-controls-v1.json").c_str(), GENERIC_READ,
						FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)) ;
		DRIVERCRATE_EXPECT( context, held.Get() != INVALID_HANDLE_VALUE) ;
		// 開始intentの保存が成立しなければ新規操作を停止する。
		const DWORD error = ledger.begin( waitRequest(), UTC * 1000U, 0U) ;
		// Fixture handleだけを終了し、失敗後の旧本文を確認する。
		if( held.Get() != INVALID_HANDLE_VALUE) {
			held.Close() ;
		}

		// OSは共有拒否または置換拒否の元Win32 codeを返す。
		DRIVERCRATE_EXPECT( context,
						   error == ERROR_SHARING_VIOLATION || error == ERROR_ACCESS_DENIED) ;
		std::cout << "Collector wait blocked-replace Win32 code: " << error << '\n' ;
		DRIVERCRATE_EXPECT( context, ledger.lastError() == error) ;
		// 未確定stagingを完了controlとして読み込まない。
		std::string after ;
		DRIVERCRATE_EXPECT( context,
						   store.read( L"current/campaign-controls-v1.json", after, found) == 0U &&
							   found && before == after) ;
		DRIVERCRATE_EXPECT( context, ledger.begin( waitRequest(), UTC * 1000U, 0U) == error) ;
	}

	// 初回markerと台帳の片側欠損を再起動時にも拒否する。
	for( const bool markerMissing : {false, true}) {
		// 自作GUID rootで初期作成済みのwriter。
		LocalCollectorStateStore store ;
		// 自作rootだけへ欠損を差し込む。
		const auto				 root = rootFor( roots) ;
		DRIVERCRATE_EXPECT( context, store.initialize( root, true) == 0U) ;
		{
			// 初回markerと台帳を通常APIで作成する。
			LocalCollectorWaitLedger original ;
			DRIVERCRATE_EXPECT( context, original.initialize( store, UTC * 1000U, 0U) == 0U) ;
		}

		// 片側だけが残る初回保存窓相当のpath。
		const auto missing = root / (markerMissing ? L"current/campaign-controls-marker-v1.json"
												   : L"current/campaign-controls-v1.json") ;
		DRIVERCRATE_EXPECT( context, DeleteFileW( missing.c_str()) != FALSE) ;
		// 新instanceでも初回へ戻さない。
		LocalCollectorWaitLedger rejected ;
		DRIVERCRATE_EXPECT( context,
						   rejected.initialize( store, UTC * 1000U, 0U) == ERROR_INVALID_DATA) ;
		DRIVERCRATE_EXPECT( context, !std::filesystem::exists( missing)) ;
	}
}

/**
 * @brief 保護storeの確定JSONを本文ごと比較するため読み取ります。
 * @param[in,out] store fixture専用のwriter。
 * @return currentとrunsの相対名・原byte集合。
 */
[[nodiscard]] std::map<std::wstring, std::string> savedFiles( LocalCollectorStateStore &store)
{
	std::map<std::wstring, std::string> files ;	// 変更・追加・削除を同時に検知する集合。
	// 固定二directoryだけを保護handle経由で列挙する。
	for( const bool current : {true, false}) {
		std::vector<std::wstring> names ;	// 決定的な保存名一覧。
		const DWORD				  error =
			  current ? store.listCurrentNames( names) : store.listRunNames( names) ;	// 元I/O code。
		// 不完全な集合を非変更の証明に使わない。
		if( error != 0U) {
			throw std::runtime_error( "saved fixture listing") ;
		}

		// 確定fileだけを比較対象にする。
		for( const auto &name : names) {
			const auto path =
				// 相対名。
				std::filesystem::path( current ? L"current" : L"runs") / name ;
			std::string bytes ;		// 原保存byte。
			bool		found{} ;	// 列挙後の欠損も拒否する。
			// 保護fileの全byteを確認する。
			if( store.read( path, bytes, found) != 0U || !found) {
				throw std::runtime_error( "saved fixture read") ;
			}

			files.emplace( path.native(), std::move( bytes)) ;
		}
	}

	return files ;
}

/**
 * @brief 共通budgetを包む通常hash envelopeだけをfixtureへ書きます。
 * @param[in,out] store fixture専用writer。
 * @param[in] body 検証済みcanonical本文。
 */
void saveBudgetBody( LocalCollectorStateStore &store, const std::string_view body)
{
	std::wstring hash ;	// 通常verifierで計算する本文hash。
	// Hash失敗を改ざんfixtureとして黙って保存しない。
	if( computeBytesSha256( body, hash) != 0) {
		throw std::runtime_error( "budget fixture hash") ;
	}

	std::transform( hash.begin(), hash.end(), hash.begin(), []( const wchar_t ch) {
		return ch >= L'A' && ch <= L'F' ? static_cast<wchar_t>( ch - L'A' + L'a') : ch ;
	}) ;
	JsonObject envelope ;	// 通常保存と同じ外側schema。
	envelope.Insert( L"schema", JsonValue::CreateStringValue( L"collector-campaign-envelope-v1")) ;
	envelope.Insert( L"sha256", JsonValue::CreateStringValue( hash)) ;
	envelope.Insert( L"body", JsonValue::CreateStringValue( winrt::to_hstring( body))) ;
	// 自作root以外へ書込みを広げない。
	if( store.write( L"current/campaign-budget-v1.json", winrt::to_string( envelope.Stringify())) !=
	   0U) {
		throw std::runtime_error( "budget fixture save") ;
	}
}

/**
 * @brief 実v1予約を残し、非変更読込みと固定精算を比較します。
 * @param[in,out] context assertion集計。
 * @param[in,out] roots 自作rootの回収集合。
 */
void passiveBudget( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	LocalCollectorStateStore store ;	// 監督が所有するwriter。
	DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
	{
		LocalCollectorCampaign original ;	// 本番v1から未閉鎖予約を作る。
		DRIVERCRATE_EXPECT( context,
						   original.initializeBorrowed( store, manifest(), HASH, UTC) == 0U) ;
		CollectorCampaignDispatch dispatch ;	// 完了させない一要求。
		DRIVERCRATE_EXPECT( context, original.reserve( UTC, dispatch) ==
										CollectorCampaignDispatchResult::READY) ;
		LocalCollectorBudgetLedger competing ;	// v1の借用中は読込みも排他する。
		DRIVERCRATE_EXPECT( context, competing.initializeBorrowed( store, UTC) == ERROR_BUSY) ;
	}
	const auto	 before = savedFiles( store) ;	// v1が確定した全JSON。
	std::string	 fixedAfter ;					// 後日回収との同一byte比較用。
	std::wstring fixedHash ;					// 後日回収との同一hash比較用。
	// 読込み時計だけを一日ずつ進めても元予約と精算本文は固定する。
	for( const std::uint64_t readUtc : {UTC + 86400U, UTC + 172800U}) {
		LocalCollectorBudgetLedger ledger ;	// 読むだけで中断や日次切替をしない。
		DRIVERCRATE_EXPECT( context,
						   ledger.initializeBorrowed( store, readUtc) == 0U && ledger.hasSnapshot()) ;
		const auto snapshot = ledger.snapshot() ;	// 準備前の一予約。
		DRIVERCRATE_EXPECT( context, snapshot.reservations.size() == 1U && snapshot.lastUtc == UTC &&
										snapshot.reservations[0].phase == 0U) ;
		std::string				canonical ;	// 同じcodecへ往復する。
		CollectorBudgetSnapshot decoded ;	// 往復後の検証済み型。
		DRIVERCRATE_EXPECT( context, encodeCollectorBudgetSnapshot( snapshot, canonical) &&
										parseCollectorBudgetSnapshot( canonical, decoded)) ;
		DRIVERCRATE_EXPECT( context,
						   decoded.day == snapshot.day &&
							   decoded.reservations[0].charged == snapshot.reservations[0].maximum) ;
		// 実byte 0も未知も含め、相互に異なる精算条件を同じ未変更snapshotから準備する。
		for( const unsigned mode : {0U, 1U, 2U, 3U, 4U}) {
			CollectorBudgetSettlement	  settlement{UTC + 1U, UTC + 2U, mode < 3U,
												 mode == 0U	  ? 7U
													 : mode == 2U ? snapshot.reservations[0].maximum
																  : 0U,
												 // 元応答の固定観測。
												 mode == 4U} ;
			CollectorBudgetPreparedUpdate prepared ;	// 保存しない更新前後。
			DRIVERCRATE_EXPECT( context, ledger.prepareSettlement( snapshot.reservations[0].campaign,
																 snapshot.reservations[0].job,
																 settlement, prepared) == 0U) ;
			CollectorBudgetSnapshot after ;	// 更新後も通常codecで読めることを確認する。
			DRIVERCRATE_EXPECT( context,
							   prepared.beforeBody == canonical &&
								   parseCollectorBudgetSnapshot( prepared.afterBody, after)) ;
			DRIVERCRATE_EXPECT( context,
							   after.day == snapshot.day && after.lastUtc == UTC + 2U &&
								   after.reservations[0].phase == (mode == 4U ? 2U : 1U) &&
								   after.reservations[0].charged ==
									   (settlement.bytesKnown ? settlement.receivedBytes
															  : snapshot.reservations[0].maximum)) ;
			// 固定intentの再準備は、read時計が違っても同じ本文とhashへ収束する。
			if( mode == 0U) {
				DRIVERCRATE_EXPECT( context,
								   fixedAfter.empty() || (fixedAfter == prepared.afterBody &&
														  fixedHash == prepared.afterSha256)) ;
				fixedAfter = prepared.afterBody ;
				fixedHash  = prepared.afterSha256 ;
			}

			DRIVERCRATE_EXPECT( context, ledger.snapshot().reservations[0].phase == 0U &&
											savedFiles( store) == before) ;
		}
	}

	// 後から受け取った別応答が保存済み最高時計より古くても最高値を下げない。
	CollectorBudgetSnapshot later ;	// 実v1本文を通常codecで取得する。
	const auto				envelope = JsonObject::Parse(
		 // v1原envelope。
		 winrt::to_hstring( before.at( L"current\\campaign-budget-v1.json"))) ;
	DRIVERCRATE_EXPECT( context, parseCollectorBudgetSnapshot(
									winrt::to_string( envelope.GetNamedString( L"body")), later)) ;
	later.lastUtc = UTC + 20U ;
	std::string laterBody ;	// 元予約は変更せず最高時計だけを進めたfixture。
	DRIVERCRATE_EXPECT( context, encodeCollectorBudgetSnapshot( later, laterBody)) ;
	saveBudgetBody( store, laterBody) ;
	LocalCollectorBudgetLedger ledger ;	// 保存済み最高時計で再初期化する。
	DRIVERCRATE_EXPECT( context, ledger.initializeBorrowed( store, UTC + 30U) == 0U) ;
	CollectorBudgetPreparedUpdate prepared ;	// 時刻逆順の精算準備。
	DRIVERCRATE_EXPECT(
		context, ledger.prepareSettlement( later.reservations[0].campaign, later.reservations[0].job,
										  {UTC + 1U, UTC + 2U, true, 7U, false}, prepared) == 0U) ;
	DRIVERCRATE_EXPECT( context, parseCollectorBudgetSnapshot( prepared.afterBody, later) &&
									later.lastUtc == UTC + 20U) ;
}

/**
 * @brief 不正codec・不正精算・古いsnapshotを拒否し保存を変えません。
 * @param[in,out] context assertion集計。
 * @param[in,out] roots 自作rootの回収集合。
 */
void passiveBudgetFailures( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	LocalCollectorStateStore store ;	// 失敗入力だけを与える専用root。
	DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
	{
		LocalCollectorCampaign original ;	// 不正入力と分離した本番予約。
		DRIVERCRATE_EXPECT( context,
						   original.initializeBorrowed( store, manifest(), HASH, UTC) == 0U) ;
		CollectorCampaignDispatch dispatch ;	// 元の未閉鎖予約。
		DRIVERCRATE_EXPECT( context, original.reserve( UTC, dispatch) ==
										CollectorCampaignDispatchResult::READY) ;
	}
	CollectorBudgetSnapshot snapshot ;	// 全失敗で固定する元予算。
	{
		LocalCollectorBudgetLedger original ;	// 非変更の基準読込み。
		DRIVERCRATE_EXPECT( context, original.initializeBorrowed( store, UTC + 10U) == 0U) ;
		snapshot = original.snapshot() ;
	}
	const auto before = savedFiles( store) ;	// 拒否後も同じ集合を要求する。
	// 時刻・byte・中断・identityの九種類を独立instanceで検査する。
	for( unsigned mode = 0U; mode < 9U; ++mode) {
		LocalCollectorBudgetLedger ledger ;	// 初回拒否を以後維持する。
		DRIVERCRATE_EXPECT( context, ledger.initializeBorrowed( store, UTC + 10U) == 0U) ;
		CollectorBudgetSettlement settlement{UTC + 1U, UTC + 2U, true, 7U,
											 false} ;								// 正常基準から一条件だけ改変する。
		std::wstring			  campaign = snapshot.reservations[0].campaign ;	// 元予約identity。
		// 開始前の応答は拒否する。
		if( mode == 0U) {
			settlement.finishedUtcSeconds = UTC - 1U ;
		}

		// 受領が完了より前なら拒否する。
		if( mode == 1U) {
			settlement.acceptedUtcSeconds = UTC ;
		}

		// 回収時計より未来なら拒否する。
		if( mode == 2U) {
			settlement.acceptedUtcSeconds = UTC + 11U ;
		}

		// 不正UTCを拒否する。
		if( mode == 3U) {
			settlement.finishedUtcSeconds = 0U ;
		}

		// 先払い上限を越える実byteを拒否する。
		if( mode == 4U) {
			settlement.receivedBytes = snapshot.reservations[0].maximum + 1U ;
		}

		// 未知byteに数値観測を混ぜない。
		if( mode == 5U) {
			settlement.bytesKnown = false ;
		}

		// 応答なし中断を既知byteの成功へ変えない。
		if( mode == 6U) {
			settlement.interrupted = true ;
		}

		// 不正identityを拒否する。
		if( mode == 7U) {
			campaign = L"not-a-hash" ;
		}

		// 型が正しくても別campaignの予約を閉じない。
		if( mode == 8U) {
			campaign.assign( 64U, L'f') ;
		}

		CollectorBudgetPreparedUpdate prepared{"old", "old", HASH,
											   HASH} ;	// 拒否時の出力消去も確認する。
		DRIVERCRATE_EXPECT( context,
						   ledger.prepareSettlement( campaign, snapshot.reservations[0].job,
													settlement, prepared) == ERROR_INVALID_DATA) ;
		DRIVERCRATE_EXPECT( context, prepared.beforeBody.empty() && prepared.afterBody.empty() &&
										prepared.afterSha256.empty() &&
										ledger.lastError() == ERROR_INVALID_DATA) ;
		DRIVERCRATE_EXPECT( context, ledger.prepareSettlement( snapshot.reservations[0].campaign,
															 snapshot.reservations[0].job,
															 {UTC + 1U, UTC + 2U, true, 7U, false},
															 prepared) == ERROR_INVALID_DATA &&
										savedFiles( store) == before) ;
	}

	// Codecのtyped入力も通常decoderと同じ境界で拒否する。
	for( unsigned mode = 0U; mode < 8U; ++mode) {
		auto invalid = snapshot ;	// 正常値から一つの矛盾だけを作る。
		// 予約stateを定義域外にする。
		if( mode == 0U) {
			invalid.reservations[0].phase = 3U ;
		}

		// 未閉鎖予約の先払い不足を拒否する。
		if( mode == 1U) {
			invalid.reservations[0].charged = 1U ;
		}

		// 同identityの二重予約を拒否する。
		if( mode == 2U) {
			invalid.reservations.push_back( invalid.reservations[0]) ;
		}

		// 不正groupを拒否する。
		if( mode == 3U) {
			invalid.reservations[0].group = L"https://example.invalid" ;
		}

		// 予約開始前の最高時計を拒否する。
		if( mode == 4U) {
			invalid.lastUtc = UTC - 1U ;
		}

		// 異なる予約日を拒否する。
		if( mode == 5U) {
			invalid.day = L"20200101" ;
		}

		// 8 MiBを超える予約を拒否する。
		if( mode == 6U) {
			invalid.reservations[0].maximum = 8U * 1024U * 1024U + 1U ;
		}

		// 配列上限をJSON化する前に拒否する。
		if( mode == 7U) {
			invalid.reservations.resize( 1201U, invalid.reservations[0]) ;
		}

		std::string bytes = "old" ;	// 拒否時には旧出力を残さない。
		DRIVERCRATE_EXPECT( context,
						   !encodeCollectorBudgetSnapshot( invalid, bytes) && bytes.empty()) ;
	}

	CollectorBudgetSnapshot decoded = snapshot ;	// 不正文字入力後の型付き出力を確認する。
	DRIVERCRATE_EXPECT( context, !parseCollectorBudgetSnapshot( "{}", decoded) &&
									decoded.reservations.empty()) ;
	{
		LocalCollectorBudgetLedger stale ;	// 読込み後に別保存が起きた場合。
		DRIVERCRATE_EXPECT( context, stale.initializeBorrowed( store, UTC + 10U) == 0U) ;
		auto changed	= snapshot ;	// 同じschemaの別本文を通常envelopeで保存する。
		changed.lastUtc = UTC + 3U ;
		std::string bytes ;	// 検証済み更新本文。
		DRIVERCRATE_EXPECT( context, encodeCollectorBudgetSnapshot( changed, bytes)) ;
		saveBudgetBody( store, bytes) ;
		const auto changedFiles = savedFiles( store) ;	// 故障注入後を非変更比較の基準にする。
		CollectorBudgetPreparedUpdate prepared ;		// 古いsnapshotから精算を作らせない。
		DRIVERCRATE_EXPECT( context, stale.prepareSettlement( snapshot.reservations[0].campaign,
															snapshot.reservations[0].job,
															{UTC + 1U, UTC + 2U, true, 7U, false},
															prepared) == ERROR_INVALID_DATA &&
										savedFiles( store) == changedFiles) ;
	}
	// 閉鎖済み予約を再準備して課金を下げない。
	snapshot.reservations[0].phase	 = 1U ;
	snapshot.reservations[0].charged = 7U ;
	std::string closed ;	// 通常codecで確認した閉鎖状態。
	DRIVERCRATE_EXPECT( context, encodeCollectorBudgetSnapshot( snapshot, closed)) ;
	saveBudgetBody( store, closed) ;
	LocalCollectorBudgetLedger ledger ;	// 別起動相当の新しい読込み。
	DRIVERCRATE_EXPECT( context, ledger.initializeBorrowed( store, UTC + 10U) == 0U) ;
	CollectorBudgetPreparedUpdate prepared ;	// 再精算はcommit証拠なしに認めない。
	DRIVERCRATE_EXPECT( context, ledger.prepareSettlement( snapshot.reservations[0].campaign,
														 snapshot.reservations[0].job,
														 {UTC + 1U, UTC + 2U, true, 0U, false},
														 prepared) == ERROR_INVALID_DATA) ;
}

/**
 * @brief 初回・欠損・mode拒否・確定名列挙を非通信で検査します。
 * @param[in,out] context assertion集計。
 * @param[in,out] roots 自作rootの回収集合。
 */
void passiveBudgetRoots( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 初回とlegacy v4だけのrootでは、予算を新設せず欠損を観測する。
	for( const bool legacy : {false, true}) {
		LocalCollectorStateStore store ;	// 初回専用writer。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
		// Legacy名の存在をv1 campaign予算の消失と混同しない。
		if( legacy) {
			DRIVERCRATE_EXPECT( context, store.write( L"current/legacy-v4-fixture.json", "{}") == 0U) ;
		}

		const auto before = savedFiles( store) ;	// 初回一覧も空集合として固定する。
		{
			LocalCollectorBudgetLedger ledger ;	// 初回にmarkerも予算も作らない。
			DRIVERCRATE_EXPECT( context, ledger.initializeBorrowed( store, UTC) == 0U &&
											!ledger.hasSnapshot()) ;
			DRIVERCRATE_EXPECT( context, savedFiles( store) == before) ;
			LocalCollectorCampaign competing ;	// 非変更読込み中も暗黙回収を排他する。
			DRIVERCRATE_EXPECT(
				context, competing.initializeBorrowed( store, manifest(), HASH, UTC) == ERROR_BUSY) ;
		}
		LocalCollectorCampaign original ;	// 借用を解放して元writerを残す。
		DRIVERCRATE_EXPECT( context, store.isWritable() && original.initializeBorrowed(
															  store, manifest(), HASH, UTC) == 0U) ;
	}

	// 予算依存の別campaign履歴・modeがあれば、両側欠損も初回へ戻さない。
	for( const auto *path :
		{L"current/campaign-input-other.json", L"runs/campaign-budget-20260926.json",
		 L"current/collector-campaign-mode-v1.json"}) {
		LocalCollectorStateStore store ;	// 他履歴だけを持つroot。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U &&
										store.write( path, "{}") == 0U) ;
		const auto				   before = savedFiles( store) ;	// 拒否後の保存比較。
		LocalCollectorBudgetLedger ledger ;							// 空予算を生成しない。
		DRIVERCRATE_EXPECT( context, ledger.initializeBorrowed( store, UTC) == ERROR_INVALID_DATA &&
										savedFiles( store) == before) ;
	}

	// 片側欠損・破損本文とclock後退を独立rootで試す。
	for( unsigned mode = 0U; mode < 4U; ++mode) {
		LocalCollectorStateStore store ;					// 故障注入専用root。
		const auto				 root = rootFor( roots) ;	// 削除対象は自作GUID内の明示一fileだけ。
		DRIVERCRATE_EXPECT( context, store.initialize( root, true) == 0U) ;
		{
			LocalCollectorCampaign original ;	// Markerと本文を通常APIで作る。
			DRIVERCRATE_EXPECT( context,
							   original.initializeBorrowed( store, manifest(), HASH, UTC) == 0U) ;
		}
		// 本文側欠損を注入する。
		if( mode == 0U) {
			DRIVERCRATE_EXPECT(
				context, DeleteFileW( (root / L"current/campaign-budget-v1.json").c_str()) != FALSE) ;
		}

		// Marker側欠損を注入する。
		if( mode == 1U) {
			DRIVERCRATE_EXPECT(
				context,
				DeleteFileW( (root / L"current/campaign-budget-marker-v1.json").c_str()) != FALSE) ;
		}

		// 存在する破損予算を未存在に変えない。
		if( mode == 2U) {
			DRIVERCRATE_EXPECT( context,
							   store.write( L"current/campaign-budget-v1.json", "{}") == 0U) ;
		}

		const auto				   before = savedFiles( store) ;	// 元の故障状態を維持する。
		LocalCollectorBudgetLedger ledger ;							// 時計後退だけは正常保存へ与える。
		DRIVERCRATE_EXPECT( context, ledger.initializeBorrowed( store, mode == 3U ? UTC - 1U : UTC) ==
											ERROR_INVALID_DATA &&
										savedFiles( store) == before) ;
	}

	// Mode markerは本文が未知でも旧callerに書込みを許可しない。
	for( const std::string_view marker : {"{}", "corrupt-mode"}) {
		LocalCollectorStateStore store ;					// v2用modeだけがあるroot。
		const auto				 root = rootFor( roots) ;	// Owned再開の対象も同じ自作root。
		DRIVERCRATE_EXPECT(
			context, store.initialize( root, true) == 0U &&
						 store.write( L"current/collector-campaign-mode-v1.json", marker) == 0U) ;
		const auto			   before = savedFiles( store) ;	// 旧callerの変更禁止を確認する。
		LocalCollectorCampaign legacy ;							// 借用入口の旧core。
		DRIVERCRATE_EXPECT( context, rejectLocalCollectorCampaignMode( store) == ERROR_INVALID_DATA &&
										legacy.initializeBorrowed( store, manifest(), HASH, UTC) ==
											ERROR_INVALID_DATA &&
										savedFiles( store) == before) ;
	}

	const auto ownedRoot = rootFor( roots) ;			// 自己所有入口でもmodeを拒否する。
	std::map<std::wstring, std::string> ownedBefore ;	// writer解放前の全JSON。
	{
		LocalCollectorStateStore store ;	// modeを作った後にOS lockを解放する。
		DRIVERCRATE_EXPECT( context,
						   store.initialize( ownedRoot, true) == 0U &&
							   store.write( L"current/collector-campaign-mode-v1.json", "{}") == 0U) ;
		ownedBefore = savedFiles( store) ;
	}
	{
		LocalCollectorCampaign legacy ;	// OS lock競合ではなくmodeにより拒否する。
		DRIVERCRATE_EXPECT( context, legacy.initialize( ownedRoot, manifest(), HASH, UTC) ==
										ERROR_INVALID_DATA) ;
	}
	{
		LocalCollectorStateStore store ;	// 拒否後の保存が同一か確認する。
		DRIVERCRATE_EXPECT( context, store.initialize( ownedRoot, true) == 0U &&
										savedFiles( store) == ownedBefore) ;
	}
	{
		LocalCollectorStateStore store ;					// 決定的な確定名一覧の専用root。
		const auto				 root = rootFor( roots) ;	// stagingも自作rootへ限定する。
		DRIVERCRATE_EXPECT( context, store.initialize( root, true) == 0U &&
										store.write( L"current/z.json", "{}") == 0U &&
										store.write( L"current/a.json", "{}") == 0U &&
										store.write( L"current/b.json", "{}") == 0U) ;
		// 保護storeが作成した同じfileを移し、通常stagingと同じowner・DACLを維持する。
		DRIVERCRATE_EXPECT( context, MoveFileExW( (root / L"current/b.json").c_str(),
												(root / L"current/b.json.tmp").c_str(),
												MOVEFILE_WRITE_THROUGH) != FALSE) ;
		std::vector<std::wstring> names ;	// stagingを除外した固定順の一覧。
		DRIVERCRATE_EXPECT( context, store.listCurrentNames( names) == 0U &&
										names == std::vector<std::wstring>( {L"a.json", L"z.json"})) ;
		DRIVERCRATE_EXPECT( context, store.listRunNames( names) == 0U && names.empty()) ;
		// 初期監査後に通常名をdirectoryへ差し替えても部分一覧を返さない。
		DRIVERCRATE_EXPECT( context,
						   CreateDirectoryW( (root / L"current/c.json").c_str(), nullptr) != FALSE) ;
		DRIVERCRATE_EXPECT( context,
						   store.listCurrentNames( names) == ERROR_ACCESS_DENIED && names.empty()) ;
		DRIVERCRATE_EXPECT( context, RemoveDirectoryW( (root / L"current/c.json").c_str()) != FALSE) ;
	}
	LocalCollectorStateStore   uninitialized ;	// 未初期化storeも拒否する。
	LocalCollectorBudgetLedger ledger ;			// 失敗後の再初期化を認めない。
	DRIVERCRATE_EXPECT( context,
					   ledger.initializeBorrowed( uninitialized, UTC) == ERROR_INVALID_PARAMETER) ;
}

/**
 * @brief 自作GUID rootの直下fileだけを非再帰で回収します。
 * @param[in] root rootForで作成した回収対象。
 * @return 自作fileとdirectoryの回収成功時true。
 */
[[nodiscard]] bool cleanup( const std::filesystem::path &root)
{
	// 生成したprefixとworkspace内位置を削除前に確認する。
	if( root.parent_path() != std::filesystem::current_path() / L"work/state" ||
	   !root.filename().native().starts_with( L"campaign-fixture-")) {
		return false ;
	}

	// 実際に作成した固定二階層だけを回収する。
	for( const auto *name : {L"current", L"runs"}) {
		// 自作の子directory。
		const auto directory = root / name ;
		// 未作成folderは後始末不要。
		if( !std::filesystem::exists( directory)) {
			continue ;
		}

		// Reparse先や第三階層へは進まない。
		for( const auto &entry : std::filesystem::directory_iterator( directory)) {
			// 自作fileだけを削除する属性検査。
			const DWORD attributes =
				GetFileAttributesW( campaignFixtureIoPath( entry.path()).c_str()) ;
			// Folderやreparseの混入は再帰削除せず失敗させる。
			if( attributes == INVALID_FILE_ATTRIBUTES ||
			   (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0U ||
			   DeleteFileW( campaignFixtureIoPath( entry.path()).c_str()) == FALSE) {
				return false ;
			}
		}

		// 子にfileを残したままrootを消さない。
		if( RemoveDirectoryW( directory.c_str()) == FALSE) {
			return false ;
		}
	}

	// Storeが作ったlock一件を回収する。
	DeleteFileW( (root / L"collector.lock").c_str()) ;
	return !std::filesystem::exists( root) || RemoveDirectoryW( root.c_str()) != FALSE ;
}

/** @brief 復旧専用の有限架空入力を作ります。
 * @param[in] count Job数。
 * @return 実URL・実deviceを含まない固定入力。
 */
CollectorRecoveryInput recoveryInput( const std::size_t count = 1U)
{
	CollectorRecoveryInput result ;	// 通常manifest parserも通すfixture。
	result.manifestBytes  = manifestBytes( count, count, L"recovery", true) ;
	result.sources		  = sources() ;
	result.artifactSha256 = HASH ;
	// 異なる公開requestの架空hashを与える。
	for( std::size_t index = 0; index < count; ++index) {
		result.requestKeys.push_back( std::wstring( 64U, static_cast<wchar_t>( L'a' + index))) ;
		result.cacheBindings.push_back( HASH) ;
	}

	return result ;
}

/** @brief 保存envelopeからfixture用の元本文を読みます。
 * @param[in,out] store 自作rootのwriter。
 * @param[in] name 固定相対名。
 * @return 元本文。
 */
std::string recoveryBody( LocalCollectorStateStore &store, const std::wstring &name)
{
	// Fixture envelopeの元byte。
	std::string raw ;
	bool		found{} ;	// 保存済みbyteの確認。
	// Fixtureの欠損やI/O失敗を空本文として採点しない。
	if( store.read( name, raw, found) != 0U || !found) {
		throw std::runtime_error( "recovery read") ;
	}

	return winrt::to_string( JsonObject::Parse( winrt::to_hstring( raw)).GetNamedString( L"body")) ;
}

/** @brief 元hash envelopeを維持して故障入力だけを保存します。
 * @param[in,out] store 自作rootのwriter。
 * @param[in] name 固定相対名。
 * @param[in] body 故障または初期化用本文。
 */
void recoverySave( LocalCollectorStateStore &store, const std::wstring &name,
				  const std::string &body)
{
	std::wstring hash ;	// 元本文hash。
	// Hash準備の失敗は故障注入成功へ変換しない。
	if( computeBytesSha256( body, hash) != 0U) {
		throw std::runtime_error( "recovery hash") ;
	}

	std::transform( hash.begin(), hash.end(), hash.begin(), []( wchar_t c) {
		return c >= L'A' && c <= L'F' ? static_cast<wchar_t>( c + 32) : c ;
	}) ;
	JsonObject envelope ;	// 通常schemaと同じ外側。
	envelope.Insert( L"schema", JsonValue::CreateStringValue( L"collector-campaign-envelope-v1")) ;
	envelope.Insert( L"body", JsonValue::CreateStringValue( winrt::to_hstring( body))) ;
	envelope.Insert( L"sha256", JsonValue::CreateStringValue( hash)) ;
	// 保存失敗を後続の期待する形式拒否と混同しない。
	if( store.write( name, winrt::to_string( envelope.Stringify())) != 0U) {
		throw std::runtime_error( "recovery write") ;
	}
}

/** @brief 実byte既知のmetadata応答fixtureを作ります。
 * @param[in] finished 元完了UTC millisecond。
 * @return 成功と型付けされた有限観測。製品適合ではありません。
 */
CollectorRecoveryResponse recoverySuccess( const std::uint64_t finished)
{
	CollectorRecoveryResponse result ;	// 非通信の三byte観測。
	result.state			 = CollectorCampaignJobState::OBSERVED ;
	result.finishedUtcMillis = finished ;
	result.acceptedUtcMillis = finished ;
	result.bytesKnown		 = true ;
	result.sentRequests		 = 1U ;
	result.receivedBytes	 = 3U ;
	result.status			 = 200U ;
	result.bodySha256		 = HASH ;
	result.projectionSha256	 = HASH ;
	return result ;
}

/** @brief 非変更照会と永続予約の同一選択・期限を確認します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryReadiness( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 三つの段階を別rootで検査して予約やclockを混在させない。
	for( unsigned mode = 0U; mode < 3U; ++mode) {
		LocalCollectorStateStore store ;	// 非通信の保護台帳。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
		auto input = recoveryInput( mode == 0U ? 5U : (mode == 1U ? 2U : 1U)) ;	// 固定候補。
		// 同groupの短時間待機だけを作る。
		if( mode == 1U) {
			input.sources[1].rateLimitGroup = input.sources[0].rateLimitGroup ;
		}

		LocalCollectorRecovery core ;	// HTTPを持たない単一writer。
		DRIVERCRATE_EXPECT( context, core.initialize( store, input, UTC * 1000U, 0U) == 0U) ;
		const auto				   before = savedFiles( store) ;	// 照会の非変更根拠。
		CollectorRecoveryReadiness ready ;							// 送信tokenではない結果。
		DRIVERCRATE_EXPECT( context, core.readiness( UTC * 1000U + 599U, 75U, ready) == 0U &&
										ready.kind == CollectorRecoveryReadinessKind::READY &&
										ready.jobIndex == 0U &&
										ready.deadlineUtcMillis == UTC * 1000U + 120000U &&
										ready.waitMillis == 0U) ;
		DRIVERCRATE_EXPECT(
			context, core.readiness( UTC * 1000U - 1U, 75U, ready) == ERROR_INVALID_DATA &&
						 !ready.jobIndex && core.lastError() == 0U && savedFiles( store) == before) ;
		CollectorRecoveryDispatch dispatch ;	// 永続化後の元予約。
		DRIVERCRATE_EXPECT(
			context,
			core.reserve( UTC * 1000U + 599U, 75U, dispatch) == 0U &&
				dispatch.startedUtcMillis == UTC * 1000U &&
				dispatch.anchorUtcMillis == UTC * 1000U + 599U &&
				dispatch.anchorSteadyMillis == 75U &&
				dispatch.deadlineUtcMillis == UTC * 1000U + 120000U &&
				dispatch.deadlineSteadyMillis == 119476U && dispatch.jobKey.size() == 64U &&
				dispatch.requestKey == input.requestKeys[0] && dispatch.cacheBinding == HASH &&
				dispatch.source.sourceId == input.sources[0].sourceId &&
				dispatch.source.maximumResponseBytes == input.sources[0].maximumResponseBytes) ;
		// 四slot満杯と、回収後の次候補選択を区別する。
		if( mode == 0U) {
			// 独立groupを四つまで予約する。
			for( unsigned index = 1U; index < 4U; ++index) {
				DRIVERCRATE_EXPECT( context, core.reserve( UTC * 1000U + 599U, 75U, dispatch) == 0U &&
												dispatch.jobIndex == index) ;
			}

			const auto reserved = savedFiles( store) ;	// 待機照会も一切保存しない。
			DRIVERCRATE_EXPECT( context,
							   core.readiness( UTC * 1000U + 600U, 76U, ready) == 0U &&
								   ready.kind == CollectorRecoveryReadinessKind::ACTIVE_WAIT &&
								   !ready.jobIndex && savedFiles( store) == reserved) ;
			DRIVERCRATE_EXPECT( context, core.accept( 0U, recoverySuccess( UTC * 1000U + 1000U),
													UTC * 1000U + 1000U, 1000U) == 0U) ;
			DRIVERCRATE_EXPECT( context, core.readiness( UTC * 1000U + 1000U, 1000U, ready) == 0U &&
											ready.kind == CollectorRecoveryReadinessKind::READY &&
											ready.jobIndex == 4U) ;
		} else {
			DRIVERCRATE_EXPECT( context,
							   core.readiness( UTC * 1000U + 600U, 76U, ready) == 0U &&
								   ready.kind == CollectorRecoveryReadinessKind::ACTIVE_WAIT) ;
			DRIVERCRATE_EXPECT( context, core.accept( 0U, recoverySuccess( UTC * 1000U + 1000U),
													UTC * 1000U + 1000U, 1000U) == 0U) ;
			const auto completed = savedFiles( store) ;	// 受理後の確定file集合。
			// 同groupの二clock待ちと、全job終端を別々に確認する。
			if( mode == 1U) {
				DRIVERCRATE_EXPECT(
					context, core.readiness( UTC * 1000U + 2999U, 2999U, ready) == 0U &&
								 ready.kind == CollectorRecoveryReadinessKind::INTERVAL_WAIT &&
								 ready.waitMillis == 1U) ;
				DRIVERCRATE_EXPECT(
					context, core.readiness( UTC * 1000U + 4000U, 2999U, ready) == 0U &&
								 ready.kind == CollectorRecoveryReadinessKind::INTERVAL_WAIT &&
								 ready.waitMillis == 1U) ;
				DRIVERCRATE_EXPECT( context,
								   core.readiness( UTC * 1000U + 3000U, 3000U, ready) == 0U &&
									   ready.kind == CollectorRecoveryReadinessKind::READY &&
									   ready.jobIndex == 1U) ;
			} else {
				DRIVERCRATE_EXPECT( context,
								   core.readiness( UTC * 1000U + 1000U, 1000U, ready) == 0U &&
									   ready.kind == CollectorRecoveryReadinessKind::TERMINAL) ;
			}

			DRIVERCRATE_EXPECT( context, savedFiles( store) == completed) ;
		}
	}
}

/** @brief Batchの元期限と単調期限overflowを保存前に確認します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryDispatchDeadline( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// Batch短縮と単調overflowを独立rootで確認する。
	for( const bool overflow : {false, true}) {
		LocalCollectorStateStore store ;	// 初期fixtureだけを書き込む。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
		LocalCollectorRecovery core ;	// 二group・同batchの非通信監督。
		DRIVERCRATE_EXPECT( context,
						   core.initialize( store, recoveryInput( 2U), UTC * 1000U, 0U) == 0U) ;
		CollectorRecoveryDispatch dispatch ;	// 元予約をHTTPへ偽装しない。
		// 整数overflowは一件の先払いも保存しない。
		if( overflow) {
			CollectorRecoveryReadiness ready ;	// 非変更照会でも同じoverflowを拒否する。
			DRIVERCRATE_EXPECT( context, core.readiness( UTC * 1000U,
													   std::numeric_limits<std::uint64_t>::max(),
													   ready) == ERROR_INVALID_DATA &&
											!ready.jobIndex && core.lastError() == 0U) ;
			const auto before = savedFiles( store) ;	// 拒否前の台帳。
			DRIVERCRATE_EXPECT( context,
							   core.reserve( UTC * 1000U, std::numeric_limits<std::uint64_t>::max(),
											dispatch) == ERROR_INVALID_DATA &&
								   dispatch.generationKey.empty() && savedFiles( store) == before) ;
		} else {
			DRIVERCRATE_EXPECT( context, core.reserve( UTC * 1000U, 0U, dispatch) == 0U) ;
			DRIVERCRATE_EXPECT(
				context, core.accept( 0U, recoverySuccess( UTC * 1000U), UTC * 1000U, 0U) == 0U) ;
			DRIVERCRATE_EXPECT( context,
							   core.reserve( UTC * 1000U + 3599500U, 9000U, dispatch) == 0U &&
								   dispatch.deadlineUtcMillis == UTC * 1000U + 3600000U &&
								   dispatch.deadlineSteadyMillis == 9500U) ;
		}
	}
}

/** @brief Slotとpermitの全結合、二重消費、保存前失敗を検査します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void collectorPermitBinding( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 一fieldずつ独立に改変する。各条件に固有の保護rootを使う。
	for( unsigned fault = 0U; fault < 17U; ++fault) {
		LocalCollectorStateStore store ;	// 非通信の固定台帳。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
		LocalCollectorRecovery recovery ;	// 予約保存だけの監督。
		DRIVERCRATE_EXPECT( context,
						   recovery.initialize( store, recoveryInput(), UTC * 1000U, 1000U) == 0U) ;
		CollectorHttpClockSample clock{UTC * 1000U, 1000U} ;		// 試験が所有する時刻。
		CollectorHttpPermitPool	 pool( [&] { return clock ; }) ;	// Native clockへfallbackしない。
		CollectorHttpPermit		 permit ;							// 値から自作できない許可。
		DRIVERCRATE_EXPECT( context, pool.reserve( recovery, permit) == 0U && permit.present() &&
										pool.occupied() == 1U) ;
		auto binding = *permit.binding() ;	// 全結合を一つずつ改変するコピー。
		int	 client{} ;						// Fake clientのidentity。Native通信なし。
		// 変更fieldを固定caseで列挙する。
		switch( fault) {
			case 0U:	// 固定indexの改変。
				++binding.jobIndex ;
				break ;

			case 1U:	// 別generation。
				binding.generationKey[0] = L'z' ;
				break ;

			case 2U:	// 別job。
				binding.jobKey[0] = L'z' ;
				break ;

			case 3U:	// 別request。
				binding.requestKey[0] = L'z' ;
				break ;

			case 4U:	// 別cache。
				binding.cacheBinding[0] = L'z' ;
				break ;

			case 5U:	// 別source。
				binding.source.sourceId += L'x' ;
				break ;

			case 6U:	// 別用途。
				binding.source.resourceId += L'x' ;
				break ;

			case 7U:	// 別group。
				binding.source.rateLimitGroup += L'x' ;
				break ;

			case 8U:	// 別parser。
				binding.source.parserRevision += L'x' ;
				break ;

			case 9U:	// 上限の拡大。
				++binding.source.maximumResponseBytes ;
				break ;

			case 10U:	// 起点UTC変更。
				++binding.anchorUtcMillis ;
				break ;

			case 11U:	// 起点単調時計変更。
				++binding.anchorSteadyMillis ;
				break ;

			case 12U:	// UTC期限延長。
				++binding.deadlineUtcMillis ;
				break ;

			case 13U:	// 単調期限延長。
				++binding.deadlineSteadyMillis ;
				break ;

			case 14U:	// 元保存開始変更。
				++binding.startedUtcMillis ;
				break ;

			default:	// 15と16は正規結合の移動と二重消費。
				break ;
		}

		// 改変はclaim段階で止まり、正しい結合での再claimも認めない。
		if( fault < 15U) {
			DRIVERCRATE_EXPECT( context, !permit.claim( &client, binding) &&
											!permit.claim( &client, *permit.binding())) ;
		} else {
			CollectorHttpPermit moved = std::move( permit) ;	// 元許可を空にする。
			DRIVERCRATE_EXPECT( context, !permit.present() && !permit.claim( &client, binding)) ;
			const auto control = moved.claim( &client, binding) ;	// 一つのclientだけが成功する。
			DRIVERCRATE_EXPECT( context, control != nullptr) ;
			// claim前期限切れと二重消費を独立に検査する。
			if( fault == 15U) {
				DRIVERCRATE_EXPECT( context,
								   !moved.claim( &client, binding) &&
									   control->snapshot().cause == CollectorIoCause::SETUP &&
									   control->snapshot().sends == 0U) ;
			} else {
				clock.utcMillis += 120000U ;
				DRIVERCRATE_EXPECT( context,
								   control->begin( CollectorIoStage::DNS, 15000U) == 0U &&
									   control->snapshot().cause == CollectorIoCause::DEADLINE &&
									   control->snapshot().sends == 0U) ;
			}
		}
	}

	LocalCollectorStateStore store ;	// Save失敗前に許可を出さない試験。
	DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
	LocalCollectorRecovery recovery ;	// 先払い保存後に止める。
	DRIVERCRATE_EXPECT(
		context, recovery.initialize( store, recoveryInput(), UTC * 1000U, 0U, []( const auto point) {
			return point == CollectorRecoveryCheckpoint::RESERVED ;
		}) == 0U) ;
	CollectorHttpPermitPool pool(
		[] { return CollectorHttpClockSample{UTC * 1000U, 0U} ; }) ;	// 固定時計。
	CollectorHttpPermit permit ;										// 失敗時は空を維持する。
	DRIVERCRATE_EXPECT( context, pool.reserve( recovery, permit) == ERROR_OPERATION_ABORTED &&
									!permit.present() && pool.occupied() == 0U) ;
}

/** @brief 二clock・取消し先着・既知量と下限・解放観測を確認します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void collectorControlObservations( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 独立した固定失敗段階を一度ずつ検査する。
	for( unsigned mode = 0U; mode < 14U; ++mode) {
		LocalCollectorStateStore store ;	// 架空製品だけの台帳。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
		LocalCollectorRecovery recovery ;	// HTTPなしの予約元。
		DRIVERCRATE_EXPECT( context,
						   recovery.initialize( store, recoveryInput(), UTC * 1000U, 1000U) == 0U) ;
		CollectorHttpClockSample clock{UTC * 1000U, 1000U} ;	// 二clockの各境界。
		bool					 throwClock{} ;					// Callback欠測を後から注入する。
		CollectorHttpPermitPool	 pool( [&] {
			 // Native clockで試験欠測を補わない。
			 if( throwClock) {
				 throw std::runtime_error( "fixture clock") ;
			 }

			 return clock ;
		 }) ;
		CollectorHttpPermit		 permit ;	// 永続予約でだけ発行する。
		DRIVERCRATE_EXPECT( context, pool.reserve( recovery, permit) == 0U) ;
		int		   client{} ;												// Native I/Oを行わないidentity。
		const auto control = permit.claim( &client, *permit.binding()) ;	// 共有controlの所有値。
		DRIVERCRATE_EXPECT( context, control != nullptr &&
										control->begin( CollectorIoStage::DNS, 15000U) == 15000U) ;
		// 送信前取消しは明示SendRequest回数0。
		if( mode == 0U) {
			pool.requestStop() ;
			DRIVERCRATE_EXPECT( context, control->begin( CollectorIoStage::SEND, 30000U) == 0U &&
											!control->noteSendCall() &&
											control->snapshot().sends == 0U) ;
		} else {
			DRIVERCRATE_EXPECT( context, control->begin( CollectorIoStage::SEND, 30000U) == 30000U &&
											control->noteSendCall() && control->noteHeaders()) ;
			DRIVERCRATE_EXPECT( context, !control->noteHeaders() &&
											control->snapshot().headerUtcMillis == UTC * 1000U) ;
			DRIVERCRATE_EXPECT( context, control->begin( CollectorIoStage::READ, 60000U) == 60000U &&
											control->noteRead( 3U, 3U)) ;
			// 原errorと停止の発生順を固定する。
			switch( mode) {
				case 1U:	// Parser失敗でも既知3 byteを戻さない。
					control->fail( CollectorIoCause::PARSER,
								  {CollectorIoErrorDomain::PARSER, 13U, CollectorIoStage::PARSE},
								  false) ;
					break ;

				case 2U:	// Read失敗は下限3 byteと原HRESULTを残す。
					control->fail( CollectorIoCause::HTTP,
								  {CollectorIoErrorDomain::HRESULT_ERROR, 0x80004005U,
								   CollectorIoStage::READ},
								  true) ;
					break ;

				case 3U:	// 取消しがAPI失敗より先。
					control->requestStop() ;
					control->fail(
						CollectorIoCause::HTTP,
						{CollectorIoErrorDomain::WIN32_ERROR, 12002U, CollectorIoStage::READ},
						true) ;
					break ;

				case 4U:	// API失敗が取消しより先。
					control->fail(
						CollectorIoCause::HTTP,
						{CollectorIoErrorDomain::WINSOCK_ERROR, 11001U, CollectorIoStage::DNS},
						true) ;
					control->requestStop() ;
					break ;

				case 5U:	// 同checkpointの期限と取消しでは取消しを先に確定。
					clock.utcMillis += 120000U ;
					control->requestStop() ;
					break ;

				case 6U:	// UTC後退。
					--clock.utcMillis ;
					break ;

				case 7U:	// 単調時計後退。
					--clock.steadyMillis ;
					break ;

				case 8U:	// Callback欠測。
					throwClock = true ;
					break ;

				case 9U:	// Native資源未解放。
					control->setNativeReleased( false) ;
					break ;

				case 10U:	// 正常完了を後で取消さない。
					break ;

				case 11U:	// 明示APIの二回目は拒否。
					DRIVERCRATE_EXPECT( context, !control->noteSendCall()) ;
					break ;

				case 12U:	// 不正な成功read返却量。
					DRIVERCRATE_EXPECT( context, !control->noteRead( 1U, 2U)) ;
					break ;

				default:	// 単調期限を短い方として使用する。
					clock.steadyMillis += 119999U ;
					DRIVERCRATE_EXPECT( context,
									   control->begin( CollectorIoStage::QUERY, 60000U) == 1U) ;
					++clock.steadyMillis ;
					break ;
			}
		}

		DRIVERCRATE_EXPECT( context, control->finish() && !control->finish()) ;
		const auto observation = control->snapshot() ;	// 結果確定後は値が変わらない。
		DRIVERCRATE_EXPECT( context, observation.sealed &&
										observation.sends == (mode == 0U ? 0U : 1U) &&
										observation.lowerBytes == (mode == 0U ? 0U : 3U)) ;
		// 欠測と実測0を区別する。
		if( mode >= 6U && mode <= 8U) {
			DRIVERCRATE_EXPECT( context, observation.cause == CollectorIoCause::CLOCK &&
											!observation.finishedUtcMillis &&
											!observation.elapsedMillis) ;
		} else {
			const auto expected = mode == 0U || mode == 3U || mode == 5U
									  ? CollectorIoCause::CANCELLED
								  : mode == 1U				 ? CollectorIoCause::PARSER
								  : mode == 2U || mode == 4U ? CollectorIoCause::HTTP
								  : mode == 10U				 ? CollectorIoCause::COMPLETE
								  : mode == 13U				 ? CollectorIoCause::DEADLINE
												: CollectorIoCause::SETUP ;	// 固定oracle。
			DRIVERCRATE_EXPECT( context, observation.cause == expected &&
											observation.finishedUtcMillis.has_value()) ;
		}

		DRIVERCRATE_EXPECT( context, observation.bytesKnown ==
										!(mode == 2U || mode == 3U || mode == 4U || mode == 12U)) ;
		// 原値はbit patternのまま保持する。
		if( mode == 2U || mode == 3U || mode == 4U) {
			DRIVERCRATE_EXPECT( context, observation.native &&
											observation.native->code == (mode == 2U	  ? 0x80004005U
																		 : mode == 3U ? 12002U
																					  : 11001U)) ;
		}

		control->requestStop() ;
		control->setNativeReleased( !observation.nativeReleased) ;
		DRIVERCRATE_EXPECT(
			context, !control->noteRead( 1U, 1U) && control->snapshot().cause == observation.cause &&
						 control->snapshot().nativeReleased == observation.nativeReleased &&
						 control->snapshot().lowerBytes == observation.lowerBytes) ;
	}
}

/** @brief 本文成功readと親取消しの競合、保存後も未回収のslotを確認します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void collectorControlOwnership( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	static_assert( !std::is_copy_constructible_v<CollectorHttpPermitPool>) ;
	static_assert( !std::is_move_constructible_v<CollectorHttpPermitPool>) ;
	static_assert( !std::is_copy_constructible_v<CollectorHttpPermit>) ;
	LocalCollectorStateStore store ;	// 五つの独立groupを作る。
	DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
	LocalCollectorRecovery recovery ;	// 保存は親threadだけ。
	DRIVERCRATE_EXPECT( context,
					   recovery.initialize( store, recoveryInput( 5U), UTC * 1000U, 0U) == 0U) ;
	CollectorHttpPermitPool pool(
		[] { return CollectorHttpClockSample{UTC * 1000U, 0U} ; }) ;	// Thread-safeな定数時計。
	std::array<CollectorHttpPermit, 4> permits ;						// コピー不可の四許可。
	// 固定四slotまでだけ発行する。
	for( auto &permit : permits) {
		DRIVERCRATE_EXPECT( context, pool.reserve( recovery, permit) == 0U) ;
	}

	int		   firstClient{} ;													// 保存済みslotを再発行しない試験の所有者identity。
	const auto first = permits[0].claim( &firstClient, *permits[0].binding()) ;	// 一回だけclaimする。
	DRIVERCRATE_EXPECT( context, first && first->begin( CollectorIoStage::SEND, 30000U) != 0U &&
									first->noteSendCall() && first->noteHeaders() &&
									first->noteRead( 3U, 3U) && first->finish()) ;
	DRIVERCRATE_EXPECT(
		context, recovery.acceptControlled( *permits[0].binding(), recoverySuccess( UTC * 1000U),
										   first->snapshot(), UTC * 1000U, 0U) == 0U) ;
	const auto			   before = savedFiles( store) ;	// 保存済みでもslot未回収の状態。
	CollectorHttpPermit	   extra ;							// 五番目は予約しない。
	LocalCollectorRecovery other ;							// 別writerへの混用は初期化前でも拒否する。
	DRIVERCRATE_EXPECT( context, pool.reserve( other, extra) == ERROR_INVALID_PARAMETER &&
									!extra.present() && savedFiles( store) == before) ;
	DRIVERCRATE_EXPECT( context, pool.reserve( recovery, extra) == ERROR_RETRY && !extra.present() &&
									pool.occupied() == 4U && savedFiles( store) == before) ;
	int		   client{} ;	// 一つのworkerだけに渡すidentity。
	const auto control =
		permits[1].claim( &client, *permits[1].binding()) ;	// 親も停止通知用の所有参照を持つ。
	DRIVERCRATE_EXPECT( context, control && control->begin( CollectorIoStage::SEND, 30000U) != 0U &&
									control->noteSendCall()) ;
	std::latch	 entered( 1) ;		// WorkerがI/O中相当へ到達した通知。
	std::latch	 released( 1) ;		// 親取消し後にだけ偽readを復帰させる。
	bool		 workerResult{} ;	// Join後にだけ親が読む。
	std::jthread worker( [&] {
		bool notified{} ;	// 例外時も親の待機を一度だけ解除する。
		try {
			control->setNativeReleased( false) ;
			entered.count_down() ;
			notified = true ;
			released.wait() ;
			workerResult = control->noteRead( 3U, 3U) ;
			control->setNativeReleased( true) ;
			workerResult = control->finish() && workerResult ;
		} catch( ...) {
			workerResult = false ;
			// Entry前失敗でも親を閉じ込めず、join後のassertionへ失敗を渡す。
			if( !notified) {
				entered.count_down() ;
			}
		}
	}) ; // 全captureはjoinまで存続する。
	entered.wait() ;
	pool.requestStop() ;
	released.count_down() ;
	worker.join() ;
	const auto observation = control->snapshot() ;	// Native通信ではなくcontrol競合の観測。
	DRIVERCRATE_EXPECT( context, workerResult && observation.cause == CollectorIoCause::CANCELLED &&
									observation.bytesKnown && observation.lowerBytes == 3U &&
									observation.nativeReleased && observation.sealed) ;
	DRIVERCRATE_EXPECT( context, pool.reserve( recovery, extra) == ERROR_OPERATION_ABORTED &&
									savedFiles( store) == before) ;
}

/** @brief 予約と応答の全保存窓を中断して、同じ精算へ収束させます。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryWindows( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	const std::array points{CollectorRecoveryCheckpoint::RESERVED,
							CollectorRecoveryCheckpoint::STARTED,
							CollectorRecoveryCheckpoint::RUNNING,
							CollectorRecoveryCheckpoint::RESPONSE,
							CollectorRecoveryCheckpoint::EFFECTS,
							CollectorRecoveryCheckpoint::REGISTERED,
							CollectorRecoveryCheckpoint::APPLIED,
							CollectorRecoveryCheckpoint::COMPLETED} ;	// 各永続化境界。
	// 同じ応答は元時刻のまま反映し、中断の初回時刻も次回に延長しない。
	for( const auto point : points) {
		// APPLIEDは三roleの各直後を独立して試す。
		for( unsigned window = 1U;
			window <= (point == CollectorRecoveryCheckpoint::APPLIED ? 3U : 1U); ++window) {
			LocalCollectorStateStore store ;	// 独立した自作root。
			DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
			const auto input = recoveryInput() ;	// すべて同じ元契約。
			{
				// 同じcheckpointの何回目で中断するかを数える。
				unsigned			   visits{} ;
				LocalCollectorRecovery core ;	// 各保存窓でのみ止める。
				// 停止hook付き監督の初回接続結果。
				const auto			   initialized =
					core.initialize( store, input, UTC * 1000U, 0U, [&]( auto value) {
						return value == point && ++visits == window ;
					}) ;
				// 失敗した保存窓と元errorをfixtureの診断へ残す。
				if( initialized != 0U) {
					std::cerr << "initial recovery code=" << initialized
							  << " files=" << savedFiles( store).size()
							  << " reason=" << winrt::to_string( core.reason()) << "\n" ;
				}

				DRIVERCRATE_EXPECT( context, initialized == 0U) ;
				CollectorRecoveryDispatch dispatch ;	// HTTPは実行しない。
				// 通信なしの永続予約結果。
				const auto				  reserved = core.reserve( UTC * 1000U, 0U, dispatch) ;
				// 応答前の三窓では予約呼出し自体が中断する。
				if( point == CollectorRecoveryCheckpoint::RESERVED ||
				   point == CollectorRecoveryCheckpoint::STARTED ||
				   point == CollectorRecoveryCheckpoint::RUNNING) {
					DRIVERCRATE_EXPECT( context, reserved == ERROR_OPERATION_ABORTED) ;
				} else {
					DRIVERCRATE_EXPECT( context, reserved == 0U) ;
					DRIVERCRATE_EXPECT( context,
									   core.accept( 0U, recoverySuccess( UTC * 1000U + 1000U),
												   UTC * 1000U + 2000U,
												   2000U) == ERROR_OPERATION_ABORTED) ;
				}
			}
			{
				LocalCollectorRecovery core ;	// 時計を進めた独立監督で回収する。
				// 独立した監督による回収の数値結果。
				const auto code = core.initialize( store, input, UTC * 1000U + 10000U, 0U) ;
				// 回収失敗では対象窓と元codeを表示する。
				if( code != 0U) {
					std::cerr << "recovery window " << static_cast<int>( point) << "/" << window
							  << " code=" << code << "\n" ;
				}

				DRIVERCRATE_EXPECT( context, code == 0U && core.terminalJobs() == 1U) ;
			}
			// 回収後の共通予算snapshot。
			CollectorBudgetSnapshot budget ;
			CollectorWaitSnapshot	waits ;	// 二重計上と固定期限。
			DRIVERCRATE_EXPECT(
				context, parseCollectorBudgetSnapshot(
							 recoveryBody( store, L"current/campaign-budget-v1.json"), budget)) ;
			DRIVERCRATE_EXPECT(
				context, parseCollectorWaitSnapshot(
							 recoveryBody( store, L"current/campaign-controls-v1.json"), waits)) ;
			// 応答保存前の停止だけを未知結果として扱う。
			const bool interrupted = point == CollectorRecoveryCheckpoint::RESERVED ||
									 point == CollectorRecoveryCheckpoint::STARTED ||
									 point == CollectorRecoveryCheckpoint::RUNNING ;
			DRIVERCRATE_EXPECT( context,
							   budget.reservations.size() == 1U &&
								   budget.reservations[0].phase == (interrupted ? 2U : 1U) &&
								   budget.reservations[0].charged ==
									   (interrupted ? 8U * 1024U * 1024U : 3U)) ;
			DRIVERCRATE_EXPECT( context,
							   waits.controls.at( L"r-" + input.requestKeys[0]).notBefore ==
								   UTC * 1000U + (interrupted ? 10000U : 1000U) + 86400000U) ;
			const auto beforeBudget =
				// 後日再開でも変わらない。
				recoveryBody( store, L"current/campaign-budget-v1.json") ;
			// 二回目の回収前に固定した待機表。
			const auto beforeControl = recoveryBody( store, L"current/campaign-controls-v1.json") ;
			{
				// 翌日の再開でも再課金しないことを確かめる監督。
				LocalCollectorRecovery core ;
				DRIVERCRATE_EXPECT(
					context, core.initialize( store, input, (UTC + 86400U) * 1000U, 0U) == 0U &&
								 core.terminalJobs() == 1U) ;
				// 完了jobを再予約できないことの出力先。
				CollectorRecoveryDispatch dispatch ;
				DRIVERCRATE_EXPECT(
					context, core.reserve( (UTC + 86400U) * 1000U, 10000U, dispatch) == ERROR_RETRY) ;
			}
			DRIVERCRATE_EXPECT(
				context,
				recoveryBody( store, L"current/campaign-budget-v1.json") == beforeBudget &&
					recoveryBody( store, L"current/campaign-controls-v1.json") == beforeControl) ;
		}
	}
}

/** @brief 終了順逆転、未知byte、翌日未予約閉鎖を検査します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryOrdering( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	LocalCollectorStateStore store ;	// 一rootに三つの固定job。
	DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
	// 三つの独立groupを含む元入力。
	const auto input = recoveryInput( 3U) ;
	{
		// 二つの同時予約を持つ非通信監督。
		LocalCollectorRecovery core ;
		DRIVERCRATE_EXPECT( context, core.initialize( store, input, UTC * 1000U, 0U) == 0U) ;
		// 先に開始して後で結果を保存する要求。
		CollectorRecoveryDispatch first ;
		CollectorRecoveryDispatch second ;	// 独立二groupの予約。
		DRIVERCRATE_EXPECT( context,
						   core.reserve( UTC * 1000U, 0U, first) == 0U && first.jobIndex == 0U) ;
		DRIVERCRATE_EXPECT( context, core.reserve( UTC * 1000U + 1000U, 1000U, second) == 0U &&
										second.jobIndex == 1U) ;
		DRIVERCRATE_EXPECT( context, core.accept( 1U, recoverySuccess( UTC * 1000U + 6000U),
												UTC * 1000U + 7000U, 7000U) == 0U) ;
		CollectorRecoveryResponse unknown ;	// 失敗byte未知は最大課金する。
		unknown.finishedUtcMillis = UTC * 1000U + 3000U ;
		unknown.acceptedUtcMillis = UTC * 1000U + 4000U ;
		unknown.error			  = 12002U ;
		unknown.errorDomain		  = L"WIN32" ;
		DRIVERCRATE_EXPECT( context, core.accept( 0U, unknown, UTC * 1000U + 8000U, 8000U) == 0U) ;
	}
	{
		LocalCollectorRecovery core ;	// 翌日は三件目を取得せずDEFERREDへ閉じる。
		DRIVERCRATE_EXPECT( context,
						   core.initialize( store, input, (UTC + 86400U) * 1000U, 0U) == 0U &&
							   core.terminalJobs() == 3U) ;
		DRIVERCRATE_EXPECT( context, core.reason() == L"DAY_CLOSED") ;
	}
	// 二要求の課金を照合する予算snapshot。
	CollectorBudgetSnapshot budget ;
	CollectorWaitSnapshot	controls ;	// 保存最高時計を後退させない。
	DRIVERCRATE_EXPECT( context,
					   parseCollectorBudgetSnapshot(
						   recoveryBody( store, L"current/campaign-budget-v1.json"), budget) &&
						   budget.reservations.size() == 2U &&
						   budget.reservations[0].charged == 8U * 1024U * 1024U &&
						   budget.reservations[1].charged == 3U) ;
	DRIVERCRATE_EXPECT( context,
					   parseCollectorWaitSnapshot(
						   recoveryBody( store, L"current/campaign-controls-v1.json"), controls) &&
						   controls.lastUtc == UTC * 1000U + 6000U) ;
}

/** @brief 登録後の順序矛盾とeffect破損を非変更拒否します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryCorruption( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 更新順逆転・after偽造・未登録fileを独立rootで拒否する。
	for( unsigned fault = 0U; fault < 3U; ++fault) {
		// 故障を独立させる保護store。
		LocalCollectorStateStore store ;
		DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
		// 破損前後で固定した元入力。
		const auto input = recoveryInput() ;
		{
			// Commit登録の直後で停止する監督。
			LocalCollectorRecovery core ;
			DRIVERCRATE_EXPECT( context,
							   core.initialize( store, input, UTC * 1000U, 0U, []( auto point) {
								   return point == CollectorRecoveryCheckpoint::REGISTERED ;
							   }) == 0U) ;
			// 元の一要求だけの永続予約。
			CollectorRecoveryDispatch dispatch ;
			DRIVERCRATE_EXPECT( context, core.reserve( UTC * 1000U, 0U, dispatch) == 0U) ;
			DRIVERCRATE_EXPECT( context,
							   core.accept( 0U, recoverySuccess( UTC * 1000U + 1000U),
										   UTC * 1000U + 2000U, 2000U) == ERROR_OPERATION_ABORTED) ;
		}
		// 停止後に残ったrootとactive commit。
		const auto root = JsonObject::Parse(
			winrt::to_hstring( recoveryBody( store, L"current/campaign-root-v2.json"))) ;
		const auto op = std::wstring(
			// 元の固定操作。
			root.GetNamedObject( L"commit").GetNamedString( L"operation")) ;
		// Controlより先に予算だけを更新後へ差し替える。
		if( fault == 0U) {
			recoverySave( store, L"current/campaign-budget-v1.json",
						 recoveryBody( store, L"runs/campaign-effect-v1-" + op + L"-budget.json")) ;
		}

		// 登録済みeffectを別の型へ破損させる。
		if( fault == 1U) {
			recoverySave( store, L"runs/campaign-effect-v1-" + op + L"-control.json", "{}") ;
		}

		// 未知schemaのcampaign fileを追加する。
		if( fault == 2U) {
			recoverySave( store, L"runs/campaign-unknown-v9.json", "{}") ;
		}

		const auto			   before = savedFiles( store) ;	// 故障注入後は書込みなしで止める。
		// 故障注入後の独立した再開監督。
		LocalCollectorRecovery core ;
		DRIVERCRATE_EXPECT( context, core.initialize( store, input, UTC * 1000U + 10000U, 0U) ==
										ERROR_INVALID_DATA) ;
		DRIVERCRATE_EXPECT( context, savedFiles( store) == before) ;
	}
}

/** @brief 固定日次intentとarchive保存窓の再開を検査します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryDayRoll( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	const std::array points{CollectorRecoveryCheckpoint::EFFECTS,
							CollectorRecoveryCheckpoint::REGISTERED,
							CollectorRecoveryCheckpoint::APPLIED,
							CollectorRecoveryCheckpoint::COMPLETED} ;	// 日次の全保存窓。
	// 日次切替の全保存段階を独立rootで確認する。
	for( const auto point : points) {
		// Archive後と新予算後の両方を停止する。
		for( unsigned window = 1U;
			window <= (point == CollectorRecoveryCheckpoint::APPLIED ? 2U : 1U); ++window) {
			// 日次保存窓一件の専用store。
			LocalCollectorStateStore store ;
			DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
			const CollectorBudgetSnapshot oldBudget{
				L"20260927", UTC, {}} ;	// 閉鎖済み空予算を旧v1から共有する。
			// 切替前の共通予算の元本文。
			std::string oldBody ;
			DRIVERCRATE_EXPECT( context, encodeCollectorBudgetSnapshot( oldBudget, oldBody)) ;
			recoverySave( store, L"current/campaign-budget-marker-v1.json",
						 "collector-campaign-budget-root-v1") ;
			saveBudgetBody( store, oldBody) ;
			{
				// 指定roleの適用直後だけで止める回数。
				unsigned			   visits{} ;
				// 旧日budgetから切替を始める監督。
				LocalCollectorRecovery core ;
				DRIVERCRATE_EXPECT( context,
								   core.initialize( store, recoveryInput(), (UTC + 86400U) * 1000U,
												   0U, [&]( auto value) {
													   return value == point && ++visits == window ;
												   }) == ERROR_OPERATION_ABORTED) ;
			}
			{
				LocalCollectorRecovery core ;	// 同じ日に後の時刻で再開する。
				// 後の時計で同じ日次intentを回収した結果。
				const auto			   code =
					core.initialize( store, recoveryInput(), (UTC + 86400U) * 1000U + 10000U, 0U) ;
				// 日次回収失敗の対象窓を数値で残す。
				if( code != 0U) {
					std::cerr << "day roll point=" << static_cast<int>( point)
							  << " window=" << window << " code=" << code << "\n" ;
				}

				DRIVERCRATE_EXPECT( context, code == 0U) ;
			}
			CollectorBudgetSnapshot current ;	// 最初の切替時刻を維持する。
			DRIVERCRATE_EXPECT(
				context, parseCollectorBudgetSnapshot(
							 recoveryBody( store, L"current/campaign-budget-v1.json"), current) &&
							 current.lastUtc == UTC + 86400U && current.reservations.empty()) ;
			DRIVERCRATE_EXPECT(
				context, recoveryBody( store, L"runs/campaign-budget-20260927.json") == oldBody) ;
		}
	}
}

/** @brief 旧v1の閉鎖予算共有と未閉鎖登録拒否を確認します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryV1Enrollment( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 同じ元契約について閉鎖・未閉鎖を分けて移行する。
	for( const bool closed : {false, true}) {
		LocalCollectorStateStore store ;	// 同じ保護storeを順に借用する。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
		{
			LocalCollectorCampaign old ;	// 旧coreの実codecで履歴を生成する。
			DRIVERCRATE_EXPECT( context, old.initializeBorrowed( store, manifest(), HASH, UTC) == 0U) ;
			CollectorCampaignDispatch dispatch ;	// 元の一予約。
			DRIVERCRATE_EXPECT( context, old.reserve( UTC, dispatch) ==
											CollectorCampaignDispatchResult::READY) ;
			// 閉鎖fixtureだけ結果と製品反映まで確定する。
			if( closed) {
				DRIVERCRATE_EXPECT( context, old.finish( dispatch.jobKey, success(), UTC + 1U) == 0U) ;
				std::size_t applied{} ;	// 旧製品集約を完了する。
				DRIVERCRATE_EXPECT( context, old.applyResults( applied) == 0U) ;
			}
		}
		const auto			   before = savedFiles( store) ;	// 未閉鎖なら一byteも変えない。
		LocalCollectorRecovery core ;							// mode登録は全検査後だけ。
		const auto			   code =
			// 登録結果。
			core.initialize( store, recoveryInput(), (UTC + 2U) * 1000U, 0U) ;
		// 閉鎖旧予算を維持したまま新入力を登録できる。
		if( closed) {
			DRIVERCRATE_EXPECT( context, code == 0U) ;
			CollectorBudgetSnapshot value ;	// 旧課金を再加算も破棄もしない。
			DRIVERCRATE_EXPECT(
				context, parseCollectorBudgetSnapshot(
							 recoveryBody( store, L"current/campaign-budget-v1.json"), value) &&
							 value.reservations.size() == 1U &&
							 value.reservations[0].charged == 3U) ;
		} else {
			DRIVERCRATE_EXPECT( context, code == ERROR_RETRY &&
											core.reason() == L"CORE_V1_RECOVERY_REQUIRED" &&
											savedFiles( store) == before) ;
		}
	}
}

/** @brief 指定保存窓に固定応答を残します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] store 自作fixture writer。
 * @param[in] input 元入力。
 * @param[in] point 停止窓。
 * @param[in] response 固定観測。
 * @return 登録されたgeneration。
 */
std::wstring recoveryStopped( TestContext &context, LocalCollectorStateStore &store,
							 const CollectorRecoveryInput	  &input,
							 const CollectorRecoveryCheckpoint point,
							 const CollectorRecoveryResponse  &response)
{
	// 保存窓以外には停止を挿入しない。
	LocalCollectorRecovery core ;
	DRIVERCRATE_EXPECT( context, core.initialize( store, input, UTC * 1000U, 0U, [point]( auto value) {
		return value == point ;
	}) == 0U) ;
	// 非通信の先払い予約。
	CollectorRecoveryDispatch dispatch ;
	DRIVERCRATE_EXPECT( context, core.reserve( UTC * 1000U, 0U, dispatch) == 0U) ;
	DRIVERCRATE_EXPECT( context, core.accept( 0U, response, response.acceptedUtcMillis + 1000U,
											response.acceptedUtcMillis + 1000U - UTC * 1000U) ==
									ERROR_OPERATION_ABORTED) ;
	return core.generationKey() ;
}

/** @brief 自作GUID領域の単一保存物だけを欠損させます。
 * @param[in,out] store 自作fixture writer。
 * @param[in] name 確認済みの相対file名。
 */
void recoveryRemove( LocalCollectorStateStore &store, const std::wstring &name)
{
	// 削除対象をworkspace内の自作fixtureに限定する。
	const auto base = (std::filesystem::current_path() / L"work/state").lexically_normal() ;
	// 二階層の既知保存物以外を拒否する。
	const auto relative = std::filesystem::path( name) ;
	// 誤ったrootやpathを単一削除にも使用しない。
	if( store.root().parent_path() != base ||
	   !store.root().filename().wstring().starts_with( L"campaign-fixture-") ||
	   (relative.parent_path() != L"runs" && relative.parent_path() != L"current") ||
	   relative.extension() != L".json" ||
	   !DeleteFileW( campaignFixtureIoPath( store.root() / relative).c_str())) {
		throw std::runtime_error( "recovery fixture remove") ;
	}
}

/** @brief 応答三roleと日次二roleの全前後組合せを検査します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryPrefixes( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 応答と日次はそれぞれ固有の固定順を持つ。
	for( const bool daily : {false, true}) {
		// 更新後の集合をbitで列挙し、先頭prefix以外は変更なし拒否する。
		for( unsigned mask = 0U; mask < (daily ? 4U : 8U); ++mask) {
			// 一組合せだけを持つ自作root。
			LocalCollectorStateStore store ;
			DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
			// 同一の非通信入力。
			const auto	input = recoveryInput() ;
			// 日次だけは次日の時計を使う。
			const auto	now = (UTC + (daily ? 86400U : 0U)) * 1000U ;
			// 日次切替の原像。
			std::string oldBudget ;
			// 日次fixtureには既存の正常な空予算を配置する。
			if( daily) {
				DRIVERCRATE_EXPECT(
					context, encodeCollectorBudgetSnapshot( {L"20260927", UTC, {}}, oldBudget)) ;
				recoverySave( store, L"current/campaign-budget-marker-v1.json",
							 "collector-campaign-budget-root-v1") ;
				saveBudgetBody( store, oldBudget) ;
				// 登録直後、共有file反映前で止める。
				LocalCollectorRecovery core ;
				DRIVERCRATE_EXPECT( context, core.initialize( store, input, now, 0U, []( auto point) {
					return point == CollectorRecoveryCheckpoint::REGISTERED ;
				}) == ERROR_OPERATION_ABORTED) ;
			} else {
				(void)recoveryStopped( context, store, input,
									  CollectorRecoveryCheckpoint::REGISTERED,
									  recoverySuccess( now + 1000U)) ;
			}

			// 登録された型付き操作から固定保存名を得る。
			const auto root = JsonObject::Parse(
				winrt::to_hstring( recoveryBody( store, L"current/campaign-root-v2.json"))) ;
			// 固定操作と世代。日次では世代は空。
			const auto commit = root.GetNamedObject( L"commit") ;
			// Fixtureだけで前後の組合せを構成する。
			const auto op = std::wstring( commit.GetNamedString( L"operation")) ;
			// roleと更新先は任意pathではなく固定する。
			const std::vector<std::pair<std::wstring, std::wstring>> roles =
				daily
					? std::vector<std::pair<std::wstring,
											std::wstring>>{{L"archive",
															L"runs/campaign-budget-20260927.json"},
														   {L"budget",
															L"current/campaign-budget-v1.json"}}
					: std::vector<std::pair<std::wstring, std::wstring>>{
						  {L"control", L"current/campaign-controls-v1.json"},
						  {L"job", L"current/campaign-state-v2-" +
									   std::wstring( commit.GetNamedString( L"generation")) +
									   L".json"},
						  {L"budget", L"current/campaign-budget-v1.json"}} ;
			// 指定bitの共有fileだけを正しい更新後像へ差し替える。
			for( std::size_t index = 0U; index < roles.size(); ++index) {
				// 未指定roleは更新前のままにする。
				if( (mask & (1U << index)) != 0U) {
					recoverySave( store, roles[index].second,
								 recoveryBody( store, L"runs/campaign-effect-v1-" + op + L"-" +
														 roles[index].first + L".json")) ;
				}
			}

			// 0、1、3、7だけが先頭からの連続集合。
			const bool valid = (mask & (mask + 1U)) == 0U ;
			// 拒否時の原byte不変を確認する。
			const auto before = savedFiles( store) ;
			{
				// 独立監督で元操作を回収する。
				LocalCollectorRecovery core ;
				DRIVERCRATE_EXPECT(
					context, core.initialize( store, input, now + 10000U, 0U) ==
								 static_cast<DWORD>( valid ? ERROR_SUCCESS : ERROR_INVALID_DATA)) ;
			}
			// 逆順ではいずれの共有台帳も変更しない。
			if( !valid) {
				DRIVERCRATE_EXPECT( context, savedFiles( store) == before) ;
				continue ;
			}

			// 正常回収後の固定台帳。
			const auto fixedBudget = recoveryBody( store, L"current/campaign-budget-v1.json") ;
			// 元期限を二回目の起動時計へ延長しない。
			const auto fixedControl = recoveryBody( store, L"current/campaign-controls-v1.json") ;
			{
				// 二回目の回収で再課金しない。
				LocalCollectorRecovery core ;
				DRIVERCRATE_EXPECT( context, core.initialize( store, input, now + 20000U, 0U) == 0U) ;
				DRIVERCRATE_EXPECT( context, core.terminalJobs() == (daily ? 0U : 1U)) ;
			}
			DRIVERCRATE_EXPECT(
				context,
				recoveryBody( store, L"current/campaign-budget-v1.json") == fixedBudget &&
					recoveryBody( store, L"current/campaign-controls-v1.json") == fixedControl) ;
			// Archiveは切替前byteをそのまま保持する。
			if( daily) {
				DRIVERCRATE_EXPECT( context,
								   recoveryBody( store, L"runs/campaign-budget-20260927.json") ==
									   oldBudget) ;
			}
		}
	}
}

/** @brief 保存応答を入力差分より先に確定し、元待機を保持します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryChangedInput( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 同条件、manifest変更、artifact変更、日跨ぎの四条件。
	for( unsigned variant = 0U; variant < 4U; ++variant) {
		// 元応答と未予約jobを同じrootへ保持する。
		LocalCollectorStateStore store ;
		DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
		// 二つの独立group。
		const auto				  input = recoveryInput( 2U) ;
		// 実応答由来の429を未知中断へ変換させない。
		CollectorRecoveryResponse response ;
		response.finishedUtcMillis	 = UTC * 1000U + (variant == 3U ? 86401000U : 1000U) ;
		response.acceptedUtcMillis	 = response.finishedUtcMillis ;
		response.sentRequests		 = 1U ;
		response.bytesKnown			 = true ;
		response.receivedBytes		 = 17U ;
		response.status				 = 429U ;
		response.error				 = 429U ;
		response.errorDomain		 = L"HTTP" ;
		response.retryAfterUtcMillis = (UTC + 172800U) * 1000U ;
		// 保存時と同じ世代を維持する。
		const auto generation =
			recoveryStopped( context, store, input, CollectorRecoveryCheckpoint::RESPONSE, response) ;
		// 起動時の新入力は旧結果を採点する入力にしない。
		auto incoming = input ;
		// Manifest本文だけの変更を明示する。
		if( variant == 1U) {
			incoming.manifestBytes = manifestBytes( 2U, 2U, L"changed", true) ;
		}

		// Artifact変更も世代の新規開始とは区別する。
		if( variant == 2U) {
			incoming.artifactSha256 = std::wstring( 64U, L'f') ;
		}

		// 応答受領後の再開時計。
		const auto now = response.acceptedUtcMillis + 10000U ;
		{
			// 旧結果の固定回収を優先する。
			LocalCollectorRecovery core ;
			DRIVERCRATE_EXPECT( context, core.initialize( store, incoming, now, 0U) == 0U) ;
			DRIVERCRATE_EXPECT( context, core.generationKey() == generation &&
											core.terminalJobs() == (variant == 0U ? 1U : 2U)) ;
			// 同日同条件だけ未予約の二件目を続行できる。
			CollectorRecoveryDispatch dispatch ;
			DRIVERCRATE_EXPECT( context, core.reserve( now, 2000U, dispatch) ==
											(variant == 0U ? 0U : ERROR_RETRY)) ;
			// 継続しても旧要求を再送しない。
			if( variant == 0U) {
				DRIVERCRATE_EXPECT( context, dispatch.jobIndex == 1U) ;
			}
		}
		// 元予約日の課金と元HTTP応答を維持する。
		CollectorBudgetSnapshot budget ;
		DRIVERCRATE_EXPECT( context,
						   parseCollectorBudgetSnapshot(
							   recoveryBody( store, L"current/campaign-budget-v1.json"), budget)) ;
		DRIVERCRATE_EXPECT( context, budget.day == L"20260927" &&
										budget.reservations[0].phase == 1U &&
										budget.reservations[0].charged == 17U &&
										budget.reservations.size() == (variant == 0U ? 2U : 1U)) ;
		// Group待機を元Retry-Afterへ固定する。
		CollectorWaitSnapshot control ;
		DRIVERCRATE_EXPECT( context,
						   parseCollectorWaitSnapshot(
							   recoveryBody( store, L"current/campaign-controls-v1.json"), control)) ;
		DRIVERCRATE_EXPECT( context, control.controls.at( L"g-group0").notBefore ==
										std::max( response.retryAfterUtcMillis,
												 response.finishedUtcMillis + 86400000U)) ;
	}
}

/** @brief 欠損とhash更新付き偽造を、登録前後の区別付きで検査します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryMissingAndForgery( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 登録済み欠損七種、型付き偽造、登録前欠損／不一致を独立させる。
	for( unsigned fault = 0U; fault < 10U; ++fault) {
		// 故障一件専用の保護store。
		LocalCollectorStateStore store ;
		DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
		// 全故障で同じ入力を使う。
		const auto input = recoveryInput() ;
		// 登録前では欠損だけ再構成を許す。
		const auto generation =
			recoveryStopped( context, store, input,
							fault >= 8U ? CollectorRecoveryCheckpoint::EFFECTS
										: CollectorRecoveryCheckpoint::REGISTERED,
							recoverySuccess( UTC * 1000U + 1000U)) ;
		// 登録前でもjobから操作を一意に導出する。
		const auto	 jobState = JsonObject::Parse( winrt::to_hstring(
			  recoveryBody( store, L"current/campaign-state-v2-" + generation + L".json"))) ;
		// 操作hashを実装と同じ固定識別式で作る。
		std::wstring op ;
		DRIVERCRATE_EXPECT(
			context,
			computeBytesSha256(
				"response-v2\n" + winrt::to_string( generation) + "\n" +
					winrt::to_string(
						jobState.GetNamedArray( L"jobs").GetObjectAt( 0U).GetNamedString( L"job")) +
					"\n",
				op) == 0U) ;
		std::transform( op.begin(), op.end(), op.begin(), []( wchar_t c) {
			return c >= L'A' && c <= L'F' ? static_cast<wchar_t>( c + 32) : c ;
		}) ;
		// 欠損対象は固定した登録物だけ。
		const std::array names{L"runs/campaign-effect-v1-" + op + L"-before-control.json",
							   L"runs/campaign-effect-v1-" + op + L"-control.json",
							   L"runs/campaign-response-v2-" + op + L".json",
							   L"runs/campaign-input-v2-" + generation + L".json",
							   L"runs/campaign-marker-v2-" + generation + L".json",
							   std::wstring( L"current/campaign-budget-marker-v1.json"),
							   std::wstring( L"current/campaign-controls-v1.json")} ;
		// 登録済み必須fileの欠損。
		if( fault < 7U) {
			recoveryRemove( store, names[fault]) ;
		}

		// Envelopeとdescriptor両方のhashを改めても元応答と異なるafterを拒否する。
		if( fault == 7U) {
			// 型として正常な待機表へ値だけ偽造する。
			CollectorWaitSnapshot waits ;
			DRIVERCRATE_EXPECT( context,
							   parseCollectorWaitSnapshot( recoveryBody( store, names[1]), waits)) ;
			waits.controls.at( L"r-" + input.requestKeys[0]).notBefore += 1000U ;
			// 新hashを含む正しいenvelopeで保存する。
			std::string altered ;
			DRIVERCRATE_EXPECT( context, encodeCollectorWaitSnapshot( waits, altered)) ;
			recoverySave( store, names[1], altered) ;
			// 登録descriptorまで一致させてhash検査だけでは通る故障にする。
			auto root = JsonObject::Parse(
				winrt::to_hstring( recoveryBody( store, L"current/campaign-root-v2.json"))) ;
			// 新しい元byte hash。
			std::wstring alteredHash ;
			DRIVERCRATE_EXPECT( context, computeBytesSha256( altered, alteredHash) == 0U) ;
			std::transform( alteredHash.begin(), alteredHash.end(), alteredHash.begin(),
						   []( wchar_t c) {
							   return c >= L'A' && c <= L'F' ? static_cast<wchar_t>( c + 32) : c ;
						   }) ;
			root.GetNamedObject( L"commit")
				.GetNamedArray( L"effects")
				.GetObjectAt( 0U)
				.Insert( L"after", JsonValue::CreateStringValue( alteredHash)) ;
			recoverySave( store, L"current/campaign-root-v2.json",
						 winrt::to_string( root.Stringify())) ;
		}

		// 未登録の欠けたeffectだけは再構成できる。
		if( fault == 8U) {
			recoveryRemove( store, names[1]) ;
		}

		// 未登録でも不一致を上書きしてはいけない。
		if( fault == 9U) {
			recoverySave( store, names[1], "{}") ;
		}

		// 故障後の原byte集合。
		const auto			   before = savedFiles( store) ;
		// 再開は本番の検査経路だけを使う。
		LocalCollectorRecovery core ;
		DRIVERCRATE_EXPECT(
			context, core.initialize( store, input, UTC * 1000U + 10000U, 0U) ==
						 static_cast<DWORD>( fault == 8U ? ERROR_SUCCESS : ERROR_INVALID_DATA)) ;
		// 正常再構成以外は全fileが不変である。
		if( fault != 8U) {
			DRIVERCRATE_EXPECT( context, savedFiles( store) == before) ;
		}
	}
}

/** @brief 中断intentの再中断と複数日後の日次回収を検査します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryRepeatedInterruption( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 応答なしの先払いだけを残す。
	LocalCollectorStateStore store ;
	DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
	// 固定一要求の入力。
	const auto input = recoveryInput() ;
	{
		// 先払いの直後で停止する。
		LocalCollectorRecovery core ;
		DRIVERCRATE_EXPECT( context, core.initialize( store, input, UTC * 1000U, 0U, []( auto point) {
			return point == CollectorRecoveryCheckpoint::RESERVED ;
		}) == 0U) ;
		// 永続予約だけを生成する。
		CollectorRecoveryDispatch dispatch ;
		DRIVERCRATE_EXPECT( context,
						   core.reserve( UTC * 1000U, 0U, dispatch) == ERROR_OPERATION_ABORTED) ;
	}
	{
		// 最初の中断intentを書いた直後で再度停止する。
		LocalCollectorRecovery core ;
		DRIVERCRATE_EXPECT( context,
						   core.initialize( store, input, UTC * 1000U + 10000U, 0U, []( auto point) {
							   return point == CollectorRecoveryCheckpoint::RESPONSE ;
						   }) == ERROR_OPERATION_ABORTED) ;
	}
	{
		// 後の回収でも最初の中断確定時刻を維持する。
		LocalCollectorRecovery core ;
		DRIVERCRATE_EXPECT( context, core.initialize( store, input, UTC * 1000U + 20000U, 0U) == 0U) ;
	}
	// 一回だけの最大課金。
	CollectorBudgetSnapshot budget ;
	// 24時間の起点は10000であり20000ではない。
	CollectorWaitSnapshot	control ;
	DRIVERCRATE_EXPECT( context,
					   parseCollectorBudgetSnapshot(
						   recoveryBody( store, L"current/campaign-budget-v1.json"), budget)) ;
	DRIVERCRATE_EXPECT( context,
					   parseCollectorWaitSnapshot(
						   recoveryBody( store, L"current/campaign-controls-v1.json"), control)) ;
	DRIVERCRATE_EXPECT( context, budget.reservations.size() == 1U &&
									budget.reservations[0].phase == 2U &&
									budget.reservations[0].charged == 8U * 1024U * 1024U) ;
	DRIVERCRATE_EXPECT( context, control.controls.at( L"r-" + input.requestKeys[0]).notBefore ==
									UTC * 1000U + 10000U + 86400000U) ;
	// 登録前後のどちらで止まっても一入口では固定した一日だけ回収する。
	for( const auto point :
		{CollectorRecoveryCheckpoint::EFFECTS, CollectorRecoveryCheckpoint::REGISTERED}) {
		// 日次切替専用の別root。
		LocalCollectorStateStore daily ;
		DRIVERCRATE_EXPECT( context, daily.initialize( rootFor( roots), true) == 0U) ;
		// 元日次予算の正常byte。
		std::string oldBody ;
		DRIVERCRATE_EXPECT( context, encodeCollectorBudgetSnapshot( {L"20260927", UTC, {}}, oldBody)) ;
		recoverySave( daily, L"current/campaign-budget-marker-v1.json",
					 "collector-campaign-budget-root-v1") ;
		saveBudgetBody( daily, oldBody) ;
		{
			// 翌日への切替を途中で止める。
			LocalCollectorRecovery core ;
			DRIVERCRATE_EXPECT( context, core.initialize( daily, input, (UTC + 86400U) * 1000U, 0U,
														[point]( auto value) {
															return value == point ;
														}) == ERROR_OPERATION_ABORTED) ;
		}
		{
			// さらに翌日に回収しても二日分を同じ入口で進めない。
			LocalCollectorRecovery core ;
			DRIVERCRATE_EXPECT(
				context, core.initialize( daily, input, (UTC + 172800U) * 1000U, 0U) == ERROR_RETRY) ;
			DRIVERCRATE_EXPECT( context, core.reason() == L"DAY_ROLL_CONTINUE" &&
											core.generationKey().empty()) ;
		}
		DRIVERCRATE_EXPECT( context,
						   parseCollectorBudgetSnapshot(
							   recoveryBody( daily, L"current/campaign-budget-v1.json"), budget)) ;
		DRIVERCRATE_EXPECT( context, budget.day == L"20260928" && budget.lastUtc == UTC + 86400U) ;
	}
}

/** @brief 容量境界の正常待機表を配置します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] store 初期化済みの自作writer。
 * @param[in] groups 既存group数。
 * @param[in] requests 既存request数。
 */
void recoverySeedControls( TestContext &context, LocalCollectorStateStore &store,
						  const std::size_t groups, const std::size_t requests)
{
	// 開始intentのない正常表だけを生成する。
	CollectorWaitSnapshot snapshot ;
	snapshot.lastUtc = UTC * 1000U ;
	// Source0のgroupを含み、超過時は新groupを必要とする。
	for( std::size_t index = 0U; index < groups; ++index) {
		// 有限groupの正常な空待機。
		CollectorWaitControl row ;
		row.group	 = L"group" + std::to_wstring( index) ;
		row.observed = snapshot.lastUtc ;
		snapshot.controls.emplace( L"g-" + row.group, row) ;
	}

	// 任意の実URLを保存せず架空hashだけで境界を作る。
	for( std::size_t index = 0U; index < requests; ++index) {
		// 固有hashを持つ既存request。
		CollectorWaitControl row ;
		row.group	 = L"group0" ;
		row.observed = snapshot.lastUtc ;
		DRIVERCRATE_EXPECT(
			context, computeBytesSha256( "capacity-" + std::to_string( index), row.request) == 0U) ;
		std::transform( row.request.begin(), row.request.end(), row.request.begin(), []( wchar_t c) {
			return c >= L'A' && c <= L'F' ? static_cast<wchar_t>( c + 32) : c ;
		}) ;
		snapshot.controls.emplace( L"r-" + row.request, row) ;
	}

	// 本番codecで検査してから配置する。
	std::string body ;
	DRIVERCRATE_EXPECT( context, encodeCollectorWaitSnapshot( snapshot, body)) ;
	recoverySave( store, L"current/campaign-controls-v1.json", body) ;
	recoverySave( store, L"current/campaign-controls-marker-v1.json",
				 "collector-campaign-controls-root-v1") ;
}

/** @brief 容量拒否、同時枠、時計と重複完了の非変更性を検査します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryLimits( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 300 requestまたは20 groupの満杯と一枠手前を区別する。
	for( unsigned variant = 0U; variant < 4U; ++variant) {
		// 一境界専用のroot。
		LocalCollectorStateStore store ;
		DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
		recoverySeedControls( context, store, variant < 2U ? 1U : 19U + variant % 2U,
							 variant < 2U ? 299U + variant : 0U) ;
		// 新しい公開要求一件だけを加える。
		auto input = recoveryInput() ;
		// Group境界では既存集合外のgroupへ接続する。
		if( variant >= 2U) {
			input.sources[0].rateLimitGroup = L"group20" ;
		}

		// 既存台帳読込みは満杯でも正常である。
		LocalCollectorRecovery core ;
		DRIVERCRATE_EXPECT( context, core.initialize( store, input, UTC * 1000U, 0U) == 0U) ;
		// 新規予約前の原byte集合。
		const auto				  before = savedFiles( store) ;
		// 拒否ではpermitを発行しない。
		CollectorRecoveryDispatch dispatch ;
		// 満杯時のcodeは破損13ではなく容量68である。
		const auto				  code = core.reserve( UTC * 1000U, 0U, dispatch) ;
		DRIVERCRATE_EXPECT( context, code == (variant % 2U == 0U ? 0U : ERROR_TOO_MANY_NAMES)) ;
		// 容量拒否でbudgetの先払いも保存しない。
		if( variant % 2U != 0U) {
			DRIVERCRATE_EXPECT( context,
							   core.reason() == L"STATE_CAPACITY" && savedFiles( store) == before) ;
			DRIVERCRATE_EXPECT( context,
							   core.accept( 99U, {}, UTC * 1000U, 0U) == ERROR_TOO_MANY_NAMES) ;
		}
	}

	// 異なるgroupでも同時実行は四枠までである。
	LocalCollectorStateStore store ;
	DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
	// 五つの独立要求。
	const auto			   input = recoveryInput( 5U) ;
	// 実HTTPなしで枠管理を検査する。
	LocalCollectorRecovery core ;
	DRIVERCRATE_EXPECT( context, core.initialize( store, input, UTC * 1000U, 0U) == 0U) ;
	// 予約の戻り値だけを観測する。
	CollectorRecoveryDispatch dispatch ;
	// 最初の四件だけにpermitを出す。
	for( std::size_t index = 0U; index < 4U; ++index) {
		DRIVERCRATE_EXPECT( context, core.reserve( UTC * 1000U, 0U, dispatch) == 0U &&
										dispatch.jobIndex == index) ;
	}

	DRIVERCRATE_EXPECT( context, core.reserve( UTC * 1000U, 0U, dispatch) == ERROR_RETRY) ;
	DRIVERCRATE_EXPECT( context, core.accept( 0U, recoverySuccess( UTC * 1000U + 1000U),
											UTC * 1000U + 2000U, 2000U) == 0U) ;
	DRIVERCRATE_EXPECT( context, core.reserve( UTC * 1000U + 2000U, 2000U, dispatch) == 0U &&
									dispatch.jobIndex == 4U) ;
	// 重複結果は第一errorとなり、後続予約でも消えない。
	const auto before = savedFiles( store) ;
	DRIVERCRATE_EXPECT( context, core.accept( 0U, recoverySuccess( UTC * 1000U + 1000U),
											UTC * 1000U + 2000U, 2000U) == ERROR_INVALID_DATA) ;
	DRIVERCRATE_EXPECT( context,
					   core.reserve( UTC * 1000U + 3000U, 3000U, dispatch) == ERROR_INVALID_DATA) ;
	DRIVERCRATE_EXPECT( context, savedFiles( store) == before) ;
}

/** @brief 再開後のgroup間隔と時計巻戻しを非通信で検査します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryClocks( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 二つの別requestを同groupへ所属させる。
	auto input						= recoveryInput( 2U) ;
	input.sources[1].rateLimitGroup = input.sources[0].rateLimitGroup ;
	// 完了時刻を保存するroot。
	LocalCollectorStateStore store ;
	DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
	{
		// 同group二要求を同時に予約しない。
		LocalCollectorRecovery core ;
		DRIVERCRATE_EXPECT( context, core.initialize( store, input, UTC * 1000U, 0U) == 0U) ;
		// 未予約の二件目を誤って送信しない。
		CollectorRecoveryDispatch dispatch ;
		DRIVERCRATE_EXPECT( context, core.reserve( UTC * 1000U, 0U, dispatch) == 0U &&
										dispatch.jobIndex == 0U) ;
		DRIVERCRATE_EXPECT( context, core.reserve( UTC * 1000U, 0U, dispatch) == ERROR_RETRY) ;
		DRIVERCRATE_EXPECT( context, core.accept( 0U, recoverySuccess( UTC * 1000U + 1000U),
												UTC * 1000U + 1000U, 1000U) == 0U) ;
		DRIVERCRATE_EXPECT( context,
						   core.reserve( UTC * 1000U + 2999U, 2999U, dispatch) == ERROR_RETRY) ;
	}
	{
		// 絶対時計が進んでもprocess再開後の2秒も必要。
		LocalCollectorRecovery core ;
		DRIVERCRATE_EXPECT( context,
						   core.initialize( store, input, UTC * 1000U + 10000U, 500U) == 0U) ;
		// 再起動後の未予約jobだけを継続する。
		CollectorRecoveryDispatch dispatch ;
		DRIVERCRATE_EXPECT( context,
						   core.reserve( UTC * 1000U + 12000U, 2499U, dispatch) == ERROR_RETRY) ;
		DRIVERCRATE_EXPECT( context, core.reserve( UTC * 1000U + 12000U, 2500U, dispatch) == 0U &&
										dispatch.jobIndex == 1U) ;
	}
	// UTCと単調時計の巻戻しを独立rootで検査する。
	for( const bool steady : {false, true}) {
		// 時計誤り以外の故障を混ぜない専用root。
		LocalCollectorStateStore clockStore ;
		DRIVERCRATE_EXPECT( context, clockStore.initialize( rootFor( roots), true) == 0U) ;
		// 元開始時計を保持する監督。
		LocalCollectorRecovery core ;
		DRIVERCRATE_EXPECT( context,
						   core.initialize( clockStore, recoveryInput(), UTC * 1000U, 1000U) == 0U) ;
		// 時計拒否前の全保存byte。
		const auto				  before = savedFiles( clockStore) ;
		// 拒否時はpermitを返さない。
		CollectorRecoveryDispatch dispatch ;
		DRIVERCRATE_EXPECT( context,
						   core.reserve( UTC * 1000U - (steady ? 0U : 1U), steady ? 999U : 1000U,
										dispatch) == ERROR_INVALID_DATA) ;
		DRIVERCRATE_EXPECT( context, core.reserve( UTC * 1000U + 1000U, 2000U, dispatch) ==
										ERROR_INVALID_DATA) ;
		DRIVERCRATE_EXPECT( context,
						   savedFiles( clockStore) == before && dispatch.generationKey.empty()) ;
	}
}

/** @brief 保存済み閉鎖予算をv2へ共有し、日次境界を検査します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryDailyBudgets( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// Request、byte、wall時間の各境界で直前と到達を独立確認する。
	for( unsigned boundary = 0U; boundary < 3U; ++boundary) {
		// 同じ初期予算から一枠差だけを作る。
		for( const bool full : {false, true}) {
			// 閉鎖旧契約の有限予算を持つroot。
			LocalCollectorStateStore store ;
			DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
			// 現在日と共通clockを保持する。
			CollectorBudgetSnapshot budget{L"20260927", UTC, {}} ;
			// 各境界に必要な既存予約数。
			const auto				count =
				 boundary == 0U ? (full ? 1200U : 1199U) : (boundary == 1U ? 128U : 1U) ;
			// 実HTTPの量を推定せず合成された閉鎖台帳を構成する。
			for( unsigned index = 0U; index < count; ++index) {
				// 重複のない予約identity。
				std::wstring job ;
				// Hash失敗を正常な予算fixtureへ混ぜない。
				if( computeBytesSha256( "prior-budget-" + std::to_string( index), job) != 0U) {
					throw std::runtime_error( "prior budget hash") ;
				}

				// Byte境界では最後の一予約だけ8 MiBの余白を残す。
				const auto charged =
					boundary == 1U && (full || index + 1U < count) ? 8U * 1024U * 1024U : 0U ;
				// 四時間起点の一秒差を保持する。
				const auto started = boundary == 2U ? UTC - (full ? 14400U : 14399U) : UTC ;
				budget.reservations.push_back(
					{HASH, job, L"prior-group", started, 8U * 1024U * 1024U, charged, 1U}) ;
			}

			// 旧codecの正常形として配置する。
			std::string body ;
			DRIVERCRATE_EXPECT( context, encodeCollectorBudgetSnapshot( budget, body)) ;
			recoverySave( store, L"current/campaign-budget-marker-v1.json",
						 "collector-campaign-budget-root-v1") ;
			saveBudgetBody( store, body) ;
			// 新入力で旧使用量をリセットしない。
			LocalCollectorRecovery core ;
			DRIVERCRATE_EXPECT( context,
							   core.initialize( store, recoveryInput(), UTC * 1000U, 0U) == 0U) ;
			// 拒否では先払いの追加保存をしない。
			const auto				  before = savedFiles( store) ;
			// 新規予約の結果だけを確認する。
			CollectorRecoveryDispatch dispatch ;
			DRIVERCRATE_EXPECT( context, core.reserve( UTC * 1000U, 0U, dispatch) ==
											(full ? ERROR_RETRY : 0U)) ;
			// 上限の旧課金と原file集合を保持する。
			if( full) {
				DRIVERCRATE_EXPECT( context,
								   savedFiles( store) == before && dispatch.generationKey.empty()) ;
			}
			// 日次四時間の直前ではjob二分より短い残一秒を返す。
			else if( boundary == 2U) {
				DRIVERCRATE_EXPECT( context, dispatch.deadlineUtcMillis == (UTC + 1U) * 1000U &&
												dispatch.deadlineSteadyMillis == 1000U) ;
			}
		}
	}
}

/** @brief 元v2応答によるbatch課金と再開後の時間枠を確認します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryBatchBudgets( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 共通日次より先に一batchの上限が働くことを確認する。
	for( const bool bytes : {false, true}) {
		// 一targetだけに全requestを所属させる。
		auto input			= recoveryInput() ;
		input.manifestBytes = manifestBytes( 1U, bytes ? 33U : 2U, L"batch-v2") ;
		input.requestKeys.clear() ;
		input.cacheBindings.clear() ;
		// 各jobに同じgroupの別requestを割り当てる。
		for( std::size_t index = 0U; index < (bytes ? 33U : 2U); ++index) {
			// 架空公開requestの固有hash。
			std::wstring request ;
			// 固定入力の準備に失敗した場合は採点しない。
			if( computeBytesSha256( "batch-request-" + std::to_string( index), request) != 0U) {
				throw std::runtime_error( "batch hash") ;
			}

			input.requestKeys.push_back( request) ;
			input.cacheBindings.push_back( HASH) ;
		}

		// Batch上限を別rootへ固定する。
		LocalCollectorStateStore store ;
		DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
		{
			// 実応答保存と固定精算で課金を作る。
			LocalCollectorRecovery core ;
			DRIVERCRATE_EXPECT( context, core.initialize( store, input, UTC * 1000U, 0U) == 0U) ;
			// Byte試験は32×8 MiB、時間試験は一件を処理する。
			for( std::size_t index = 0U; index < (bytes ? 32U : 1U); ++index) {
				// 同groupの2秒間隔を保つ元時計。
				const auto				  now = UTC * 1000U + index * 2000U ;
				// 一度だけ予約し、最大まで観測した応答を閉じる。
				CollectorRecoveryDispatch dispatch ;
				DRIVERCRATE_EXPECT( context, core.reserve( now, index * 2000U, dispatch) == 0U &&
												dispatch.jobIndex == index) ;
				// 元応答のbyteだけでbatchへ課金する。
				auto response		   = recoverySuccess( now) ;
				response.receivedBytes = bytes ? 8U * 1024U * 1024U : 3U ;
				DRIVERCRATE_EXPECT( context, core.accept( index, response, now, index * 2000U) == 0U) ;
			}
		}
		// 再起動で固定batchの課金と最初の開始時刻を戻さない。
		LocalCollectorRecovery resumed ;
		// Byte上限では二秒後、時間上限では一時間ちょうどに再開する。
		const auto			   now = UTC * 1000U + (bytes ? 64000U : 3600000U) ;
		DRIVERCRATE_EXPECT( context, resumed.initialize( store, input, now, 0U) == 0U) ;
		// Reopenが更新したroot以外をここから変更しない。
		const auto				  before = savedFiles( store) ;
		// 上限越えの未予約jobへpermitを出さない。
		CollectorRecoveryDispatch dispatch ;
		DRIVERCRATE_EXPECT( context, resumed.reserve( now, 2000U, dispatch) == ERROR_RETRY) ;
		DRIVERCRATE_EXPECT( context, savedFiles( store) == before) ;
	}
}

/** @brief 0既知byteの観測と閉鎖結果の矛盾を検査します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryZeroAndContradictions( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 304、送信前失敗、課金差、未予約terminalを独立させる。
	for( unsigned variant = 0U; variant < 4U; ++variant) {
		// 一要求だけを持つ自作root。
		LocalCollectorStateStore store ;
		DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
		// 不変の公開入力。
		const auto	 input = recoveryInput() ;
		// 後続の元state名に使うgeneration。
		std::wstring generation ;
		{
			// 元固定観測を受理する監督。
			LocalCollectorRecovery core ;
			DRIVERCRATE_EXPECT( context, core.initialize( store, input, UTC * 1000U, 0U) == 0U) ;
			generation = core.generationKey() ;
			// 未予約terminal fixture以外は正常に先払いする。
			if( variant < 3U) {
				// 元一要求の永続予約。
				CollectorRecoveryDispatch dispatch ;
				DRIVERCRATE_EXPECT( context, core.reserve( UTC * 1000U, 0U, dispatch) == 0U) ;
				// 元観測の0は未知nullと区別する。
				auto response		   = recoverySuccess( UTC * 1000U + 1000U) ;
				response.receivedBytes = 0U ;
				response.status		   = 304U ;
				// 送信前に失敗した場合だけ実送信0を明示する。
				if( variant == 1U) {
					response.state		  = CollectorCampaignJobState::FAILED ;
					response.sentRequests = 0U ;
					response.status		  = 0U ;
					response.error		  = ERROR_CANCELLED ;
					response.errorDomain  = L"WIN32" ;
					response.bodySha256.clear() ;
					response.projectionSha256.clear() ;
				}

				DRIVERCRATE_EXPECT( context,
								   core.accept( 0U, response, UTC * 1000U + 2000U, 2000U) == 0U) ;
			}
		}
		// 登録済み閉鎖予算の課金だけを矛盾させる。
		if( variant == 2U) {
			// 本番codecで正常形式の課金差を作る。
			CollectorBudgetSnapshot budget ;
			DRIVERCRATE_EXPECT(
				context, parseCollectorBudgetSnapshot(
							 recoveryBody( store, L"current/campaign-budget-v1.json"), budget)) ;
			budget.reservations[0].charged = 1U ;
			// Hashを一致させても元応答の0と矛盾する。
			std::string body ;
			DRIVERCRATE_EXPECT( context, encodeCollectorBudgetSnapshot( budget, body)) ;
			saveBudgetBody( store, body) ;
		}

		// 応答を持たないterminalへ変更する。
		if( variant == 3U) {
			// 元保存stateのfield順を保持する。
			auto state = JsonObject::Parse( winrt::to_hstring(
				recoveryBody( store, L"current/campaign-state-v2-" + generation + L".json"))) ;
			state.GetNamedArray( L"jobs").GetObjectAt( 0U).Insert(
				L"state", JsonValue::CreateStringValue( L"OBSERVED")) ;
			recoverySave( store, L"current/campaign-state-v2-" + generation + L".json",
						 winrt::to_string( state.Stringify())) ;
		}

		// 破損拒否でfileを補完しない。
		const auto			   before = savedFiles( store) ;
		// 元観測または矛盾を独立監督で再検査する。
		LocalCollectorRecovery resumed ;
		DRIVERCRATE_EXPECT(
			context, resumed.initialize( store, input, UTC * 1000U + 10000U, 0U) ==
						 static_cast<DWORD>( variant < 2U ? ERROR_SUCCESS : ERROR_INVALID_DATA)) ;
		// 0観測は一度だけ精算する。
		if( variant < 2U) {
			// 最大課金へ変更されていないことの確認。
			CollectorBudgetSnapshot budget ;
			DRIVERCRATE_EXPECT(
				context, parseCollectorBudgetSnapshot(
							 recoveryBody( store, L"current/campaign-budget-v1.json"), budget)) ;
			DRIVERCRATE_EXPECT( context, budget.reservations.size() == 1U &&
											budget.reservations[0].phase == 1U &&
											budget.reservations[0].charged == 0U) ;
		} else {
			DRIVERCRATE_EXPECT( context, savedFiles( store) == before) ;
		}
	}
}

/** @brief 世代保存の固定容量境界と実stagingの集計を確認します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryStorageCapacity( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// ADRのjob数、許可される既存run件数、既存MiBの四profile。
	const std::array<std::array<std::uint64_t, 3U>, 4U> profiles{
		{{0U, 4088U, 5104U}, {1U, 4081U, 5090U}, {32U, 3864U, 4656U}, {300U, 1988U, 904U}}} ;
	// 一entry／一byteの超過を独立に判定する。
	for( const auto &profile : profiles) {
		// 全dimensionを上限ちょうどへ配置する合成usage。
		const CollectorStoreUsage limit{4088U, static_cast<std::size_t>( profile[1]),
										profile[2] * 1024U * 1024U} ;
		// Fixed profileのjob数は0～300。
		const auto				  jobs = static_cast<std::size_t>( profile[0]) ;
		DRIVERCRATE_EXPECT( context, checkCollectorRecoveryCapacity( limit, jobs) == 0U) ;
		DRIVERCRATE_EXPECT( context,
						   checkCollectorRecoveryCapacity( {4089U, limit.runEntries, limit.bytes},
														  jobs) == ERROR_TOO_MANY_NAMES) ;
		DRIVERCRATE_EXPECT( context, checkCollectorRecoveryCapacity(
										{limit.currentEntries, limit.runEntries + 1U, limit.bytes},
										jobs) == ERROR_TOO_MANY_NAMES) ;
		DRIVERCRATE_EXPECT( context, checkCollectorRecoveryCapacity(
										{limit.currentEntries, limit.runEntries, limit.bytes + 1U},
										jobs) == ERROR_TOO_MANY_NAMES) ;
	}

	DRIVERCRATE_EXPECT( context,
					   checkCollectorRecoveryCapacity( {}, 301U) == ERROR_INVALID_PARAMETER) ;
	DRIVERCRATE_EXPECT( context, checkCollectorRecoveryCapacity( {SIZE_MAX, 0U, 0U}, 1U) ==
									ERROR_TOO_MANY_NAMES) ;
	DRIVERCRATE_EXPECT( context, checkCollectorRecoveryCapacity( {0U, SIZE_MAX, 0U}, 1U) ==
									ERROR_TOO_MANY_NAMES) ;
	DRIVERCRATE_EXPECT( context, checkCollectorRecoveryCapacity( {0U, 0U, UINT64_MAX}, 1U) ==
									ERROR_TOO_MANY_NAMES) ;
	// 合成usageだけでなく、実tmpが保護列挙へ含まれることを確認する。
	LocalCollectorStateStore store ;
	DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
	// 固定入力の初回接続に使う監督。
	LocalCollectorRecovery core ;
	DRIVERCRATE_EXPECT( context, core.initialize( store, recoveryInput(), UTC * 1000U, 0U) == 0U) ;
	// Tmp作成前の実集計。
	CollectorStoreUsage before ;
	DRIVERCRATE_EXPECT( context, store.inspectUsage( before) == 0U) ;
	// 通常storeが明示保護DACL付きで作成したfileだけをstagingへ移す。
	const auto confirmed = store.root() / L"runs/unused-capacity.json" ;
	// 本fixtureが作成したroot直下の既知stagingだけを作る。
	const auto temporary = store.root() / L"runs/unused-capacity.json.tmp" ;
	// 同じ自作rootの既知二pathであり、別領域へ移さない。
	DRIVERCRATE_EXPECT( context,
					   temporary.parent_path().parent_path() == store.root() &&
						   confirmed.parent_path() == temporary.parent_path() &&
						   store.root().filename().wstring().starts_with( L"campaign-fixture-")) ;
	DRIVERCRATE_EXPECT( context, store.write( L"runs/unused-capacity.json", "test") == 0U) ;
	// Protected DACLを保持した改名とし、既存stagingを上書きしない。
	DRIVERCRATE_EXPECT( context,
					   MoveFileExW( confirmed.c_str(), temporary.c_str(), MOVEFILE_WRITE_THROUGH)) ;
	// 確定名一覧には含まれず、容量へは含まれる。
	CollectorStoreUsage after ;
	DRIVERCRATE_EXPECT( context, store.inspectUsage( after) == 0U &&
									after.runEntries == before.runEntries + 1U &&
									after.bytes == before.bytes + 4U &&
									after.currentEntries == before.currentEntries) ;
	// 登録inventoryも同じ実集計を読み、tmpを成功recordへ昇格しない。
	std::vector<std::wstring> names ;
	DRIVERCRATE_EXPECT( context, store.listRunNames( names) == 0U &&
									std::find( names.begin(), names.end(),
											  L"unused-capacity.json.tmp") == names.end()) ;
}

/** @brief 登録済みrootの台帳両側欠損も初回扱いへ戻しません。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryPairedLoss( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// Budgetとcontrolsの各marker／bodyを同時に欠損させる。
	for( const auto table : {L"budget", L"controls"}) {
		// 一欠損だけを試す専用root。
		LocalCollectorStateStore store ;
		DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
		// 正常な初回登録を行う固定入力。
		const auto input = recoveryInput() ;
		{
			// Root登録を確定してから欠損を作る。
			LocalCollectorRecovery core ;
			DRIVERCRATE_EXPECT( context, core.initialize( store, input, UTC * 1000U, 0U) == 0U) ;
		}
		recoveryRemove( store, std::wstring( L"current/campaign-") + table + L"-v1.json") ;
		recoveryRemove( store, std::wstring( L"current/campaign-") + table + L"-marker-v1.json") ;
		// 両側欠損後の原byte集合。
		const auto			   before = savedFiles( store) ;
		// 空の初回予算や待機を作らない。
		LocalCollectorRecovery core ;
		DRIVERCRATE_EXPECT( context, core.initialize( store, input, UTC * 1000U + 1000U, 0U) ==
										ERROR_INVALID_DATA) ;
		DRIVERCRATE_EXPECT( context, savedFiles( store) == before) ;
	}
}

/** @brief hash一致だけでは別identityや任意更新先を反映しません。
 * @param[in,out] context Assertion集計。
 * @param[in,out] roots 自作root回収集合。
 */
void recoveryBindingMutations( TestContext &context, std::vector<std::filesystem::path> &roots)
{
	// 応答identity四field、未知role／path、二重登録の七種を独立検査する。
	for( unsigned fault = 0U; fault < 7U; ++fault) {
		// 一故障専用の保護store。
		LocalCollectorStateStore store ;
		DRIVERCRATE_EXPECT( context, store.initialize( rootFor( roots), true) == 0U) ;
		// 元の一要求入力。
		const auto input = recoveryInput() ;
		(void)recoveryStopped( context, store, input, CollectorRecoveryCheckpoint::REGISTERED,
							  recoverySuccess( UTC * 1000U + 1000U)) ;
		// 元の登録済みcommitを故障注入対象とする。
		auto root = JsonObject::Parse(
			winrt::to_hstring( recoveryBody( store, L"current/campaign-root-v2.json"))) ;
		// 元応答への固定操作。
		auto	   commit = root.GetNamedObject( L"commit") ;
		// 応答保存先は元操作のままにする。
		const auto responseName = L"runs/campaign-response-v2-" +
								  std::wstring( commit.GetNamedString( L"operation")) + L".json" ;
		// 応答の別identityはhashも更新して検査する。
		if( fault < 4U) {
			// 型として正常な元応答object。
			auto response = JsonObject::Parse( winrt::to_hstring( recoveryBody( store, responseName))) ;
			// 元inputと結合すべき有限field。
			const std::array fields{L"generation", L"job", L"request", L"source"} ;
			response.Insert( fields[fault], JsonValue::CreateStringValue(
											   fault == 3U ? L"source1" : std::wstring( 64U, L'f'))) ;
			// 原byteと登録hashを同じ値へ変える。
			const auto	 body = winrt::to_string( response.Stringify()) ;
			// 外側hashとは別のroot登録hash。
			std::wstring hash ;
			DRIVERCRATE_EXPECT( context, computeBytesSha256( body, hash) == 0U) ;
			recoverySave( store, responseName, body) ;
			commit.Insert( L"response", JsonValue::CreateStringValue( hash)) ;
		}

		// 未実装roleへeffectを転用することは許可しない。
		if( fault == 4U) {
			commit.GetNamedArray( L"effects")
				.GetObjectAt( 0U)
				.Insert( L"role", JsonValue::CreateStringValue( L"CACHE")) ;
		}

		// 任意pathを持つ更新器へ拡張されていないことを確認する。
		if( fault == 5U) {
			commit.GetNamedArray( L"effects")
				.GetObjectAt( 0U)
				.Insert( L"path", JsonValue::CreateStringValue( L"current/arbitrary.json")) ;
		}

		// 一active generationしか扱わない現段階で二つの登録を選び直さない。
		if( fault == 6U) {
			// 正常な元登録を重複させてもhash envelopeだけでは許可しない。
			const auto generations = root.GetNamedArray( L"generations") ;
			generations.Append( generations.GetAt( 0U)) ;
		}

		recoverySave( store, L"current/campaign-root-v2.json", winrt::to_string( root.Stringify())) ;
		// 改変後の原集合を一byteも修復しない。
		const auto			   before = savedFiles( store) ;
		// 復旧の本番検査を通す。
		LocalCollectorRecovery core ;
		DRIVERCRATE_EXPECT( context, core.initialize( store, input, UTC * 1000U + 10000U, 0U) ==
										ERROR_INVALID_DATA) ;
		DRIVERCRATE_EXPECT( context, savedFiles( store) == before) ;
	}
}

/**
 * @brief 一回GETの共有対象を全件cache identityへ結合する境界を検査します。
 * @param[in,out] context 同期中だけ借用し、実行済みassertionと失敗件数を追加する集計先です。
 */
void projectedJobScope( TestContext &context)
{
	static_assert( !std::is_copy_constructible_v<CollectorMetadataBody>) ;
	static_assert( std::is_nothrow_move_constructible_v<CollectorMetadataBody>) ;
	CollectorCampaignManifest manifest ;	// 固定fixtureの共有manifest。
	manifest.manifestSha256 = HASH ;
	CollectorCampaignJob job ;	// 26製品を一つのIntel公式pageへ集約する。
	job.source = {L"INTEL_ETHERNET_WINDOWS11", std::wstring( OFFICIAL_LANDING_RESOURCE_ID), L"intel",
				  L"intel-collector-v1", 2U * 1024U * 1024U} ;
	job.publicLocator = L"727998" ;
	job.locale		  = L"en-US" ;
	job.page		  = 1U ;
	// 26対象を一件のjobへ保持し、後半対象の脱落を検出する。
	for( std::size_t index = 0U; index < 26U; ++index) {
		// 公開製品名をすべて所有し、先頭だけを使う退行を検出する。
		manifest.targets.push_back( {L"t" + std::to_wstring( index), L"Intel",
									L"Ethernet Product " + std::to_wstring( index),
									L"NETWORK_ADAPTER", L"Ethernet"}) ;
		job.targetIndices.push_back( index) ;
	}

	DRIVERCRATE_EXPECT( context, makeCollectorCampaignJobKey( job, job.key)) ;
	manifest.jobs.push_back( job) ;
	CollectorProjectedJobInput input ;	// 全scopeを取得する。
	DRIVERCRATE_EXPECT( context, makeCollectorProjectedJobInput( manifest, 0U, HASH, input)) ;
	DRIVERCRATE_EXPECT( context, input.targets.size() == 26U) ;
	DRIVERCRATE_EXPECT( context, input.slices.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, input.requestTarget.publicModel.empty()) ;
	DRIVERCRATE_EXPECT( context, input.jobKey == job.key) ;
	DRIVERCRATE_EXPECT( context, input.providerId != input.policyId) ;
	const auto originalScope		= input.scopeSha256 ;	// 元scope hash。
	const auto originalCache		= input.cacheBinding ;	// 元cache binding。
	manifest.targets.back().purpose = L"Other" ;
	DRIVERCRATE_EXPECT( context, makeCollectorProjectedJobInput( manifest, 0U, HASH, input)) ;
	DRIVERCRATE_EXPECT( context, input.scopeSha256 != originalScope) ;
	DRIVERCRATE_EXPECT( context, input.cacheBinding != originalCache) ;
	// Scopeの重複や範囲外、source改変を全体拒否する。
	manifest.jobs.front().targetIndices.push_back( 0U) ;
	DRIVERCRATE_EXPECT( context, !makeCollectorProjectedJobInput( manifest, 0U, HASH, input)) ;
	manifest.jobs.front().targetIndices.pop_back() ;
	manifest.jobs.front().targetIndices.back() = 300U ;
	DRIVERCRATE_EXPECT( context, !makeCollectorProjectedJobInput( manifest, 0U, HASH, input)) ;
	manifest.jobs.front()					= job ;
	manifest.jobs.front().source.resourceId = L"metadata-primary" ;
	DRIVERCRATE_EXPECT( context, !makeCollectorProjectedJobInput( manifest, 0U, HASH, input)) ;
	manifest.jobs.front() = job ;
	DRIVERCRATE_EXPECT(
		context, !makeCollectorProjectedJobInput( manifest, 0U, std::wstring( 64U, L'A'), input)) ;
	// ASUSは同じ組み込みpolicyでもsourceラベルとは別のIDへ解決する。
	CollectorCampaignManifest asusManifest ;	// 一製品一jobの公開fixture。
	asusManifest.manifestSha256 = HASH ;
	asusManifest.targets.push_back(
		{L"board", L"ASUS", L"ProArt X870E-CREATOR WIFI", L"MAINBOARD", L"LAN"}) ;
	CollectorCampaignJob asusJob ;	// 公式model locatorとLAN一slice。
	asusJob.source = {L"ASUS_CATALOG", std::wstring( OFFICIAL_PRIMARY_METADATA_RESOURCE_ID), L"asus",
					  L"asus-collector-v1", 8U * 1024U * 1024U} ;
	asusJob.publicLocator = L"ProArt X870E-CREATOR WIFI" ;
	asusJob.locale		  = L"en-US" ;
	asusJob.page		  = 1U ;
	asusJob.targetIndices = {0U} ;
	DRIVERCRATE_EXPECT( context, makeCollectorCampaignJobKey( asusJob, asusJob.key)) ;
	asusManifest.jobs.push_back( asusJob) ;
	DRIVERCRATE_EXPECT( context, makeCollectorProjectedJobInput( asusManifest, 0U, HASH, input)) ;
	DRIVERCRATE_EXPECT( context, input.requestTarget.category == L"LAN") ;
	DRIVERCRATE_EXPECT( context, input.policyId == ASUS_OFFICIAL_SOURCE_POLICY_ID) ;
	CollectorRecoveryDispatch oldBinding ;	// 既存制御予約の既定mode。
	CollectorRecoveryDispatch newBinding ;	// 内容が同じでもmodeだけ別の予約。
	newBinding.mode = CollectorRecoveryDispatch::Mode::PROJECTED ;
	DRIVERCRATE_EXPECT( context, !sameCollectorRecoveryDispatch( oldBinding, newBinding)) ;
}

/** @brief 二つの公式jobと26共有対象の非通信定義を作ります。
 * @return 公開値だけを含む検証用定義。
 */
CollectorProjectedCampaignDefinition projectedDefinition()
{
	JsonObject manifest ;	// 元公開manifestの実byteを作る。
	manifest.Insert( L"schema", JsonValue::CreateStringValue( L"collector-campaign-manifest-v1")) ;
	manifest.Insert( L"campaignId", JsonValue::CreateStringValue( L"projected")) ;
	manifest.Insert( L"planSha256", JsonValue::CreateStringValue( HASH)) ;
	manifest.Insert( L"os", JsonValue::CreateStringValue( L"WINDOWS_11_X64")) ;
	JsonArray targets ;			// 固定Intel 26製品とASUS一製品。
	JsonArray intelReferences ;	// 一GETで共有する26 ID。
	// 後半の製品変更も同一GETのscopeへ結合する。
	for( std::size_t index = 0U; index < 26U; ++index) {
		JsonObject target ;										// 一公開製品。
		const auto id = L"intel" + std::to_wstring( index) ;	// Manifest内の公開ID。
		target.Insert( L"id", JsonValue::CreateStringValue( id)) ;
		target.Insert( L"maker", JsonValue::CreateStringValue( L"Intel")) ;
		target.Insert( L"model",
					  JsonValue::CreateStringValue( L"Ethernet Product " + std::to_wstring( index))) ;
		target.Insert( L"kind", JsonValue::CreateStringValue( L"NETWORK_ADAPTER")) ;
		target.Insert( L"purpose", JsonValue::CreateStringValue( L"Ethernet")) ;
		targets.Append( target) ;
		intelReferences.Append( JsonValue::CreateStringValue( id)) ;
	}

	JsonObject board ;	// 別sourceの一公開製品。
	board.Insert( L"id", JsonValue::CreateStringValue( L"board")) ;
	board.Insert( L"maker", JsonValue::CreateStringValue( L"ASUS")) ;
	board.Insert( L"model", JsonValue::CreateStringValue( L"ProArt X870E-CREATOR WIFI")) ;
	board.Insert( L"kind", JsonValue::CreateStringValue( L"MAINBOARD")) ;
	board.Insert( L"purpose", JsonValue::CreateStringValue( L"LAN")) ;
	targets.Append( board) ;
	manifest.Insert( L"targets", targets) ;
	JsonArray  jobs ;		// 元job順のIntel一回とASUS一回。
	JsonObject intelJob ;	// Intel固定727998の同一GET。
	intelJob.Insert( L"source", JsonValue::CreateStringValue( L"INTEL_ETHERNET_WINDOWS11")) ;
	intelJob.Insert( L"resource", JsonValue::CreateStringValue( L"landing")) ;
	intelJob.Insert( L"locator", JsonValue::CreateStringValue( L"727998")) ;
	intelJob.Insert( L"locale", JsonValue::CreateStringValue( L"en-US")) ;
	intelJob.Insert( L"page", JsonValue::CreateNumberValue( 1.0)) ;
	intelJob.Insert( L"targets", intelReferences) ;
	jobs.Append( intelJob) ;
	JsonObject asusJob ;	// ASUSの公開model起点。
	asusJob.Insert( L"source", JsonValue::CreateStringValue( L"ASUS_CATALOG")) ;
	asusJob.Insert( L"resource", JsonValue::CreateStringValue( L"metadata-primary")) ;
	asusJob.Insert( L"locator", JsonValue::CreateStringValue( L"ProArt X870E-CREATOR WIFI")) ;
	asusJob.Insert( L"locale", JsonValue::CreateStringValue( L"en-US")) ;
	asusJob.Insert( L"page", JsonValue::CreateNumberValue( 1.0)) ;
	JsonArray asusReferences ;	// 一公開対象。
	asusReferences.Append( JsonValue::CreateStringValue( L"board")) ;
	asusJob.Insert( L"targets", asusReferences) ;
	jobs.Append( asusJob) ;
	manifest.Insert( L"jobs", jobs) ;
	CollectorProjectedCampaignDefinition definition ;	// 固定source registry。
	definition.manifestBytes  = winrt::to_string( manifest.Stringify()) ;
	definition.artifactSha256 = HASH ;
	definition.sources		  = {
		   {L"INTEL_ETHERNET_WINDOWS11", L"landing", L"intel", L"intel-collector-v1",
				2U * 1024U * 1024U},
		   {L"ASUS_CATALOG", L"metadata-primary", L"asus", L"asus-collector-v1", 8U * 1024U * 1024U}} ;
	return definition ;
}

/**
 * @brief 一共有jobの300対象準備と301対象の全体拒否を検証します。
 * @param[in,out] context 同期中だけ借用し、実行済みassertionと失敗件数を追加する集計先です。
 */
void projectedCampaignTargetBoundary( TestContext &context)
{
	auto	  definition = projectedDefinition() ;	// 元の二source登録を保持する。
	// 元の公開manifestから、同じschemaの上限用入力を構成する。
	auto	  manifest = JsonObject::Parse( winrt::to_hstring( definition.manifestBytes)) ;
	JsonArray targets ;		// 5 maker×60製品でmaker別64件制限と全体300件を分離する。
	JsonArray references ;	// 一GETから全対象へ向く元順序の参照。
	// Maker別上限に触れず全体上限だけへ到達させる。
	for( std::size_t index = 0U; index < 300U; ++index) {
		const auto id = L"product" + std::to_wstring( index) ;	// 公開token。
		JsonObject target ;										// 端末IDを含まない架空製品。
		target.Insert( L"id", JsonValue::CreateStringValue( id)) ;
		target.Insert( L"maker",
					  JsonValue::CreateStringValue( L"Maker " + std::to_wstring( index / 60U))) ;
		target.Insert( L"model",
					  JsonValue::CreateStringValue( L"Ethernet Product " + std::to_wstring( index))) ;
		target.Insert( L"kind", JsonValue::CreateStringValue( L"NETWORK_ADAPTER")) ;
		target.Insert( L"purpose", JsonValue::CreateStringValue( L"Ethernet")) ;
		targets.Append( target) ;
		references.Append( JsonValue::CreateStringValue( id)) ;
	}

	JsonArray jobs ;	// Intelの一共有GETだけに全製品を参照させる。
	// 元の固定resource／locatorを維持して対象参照だけを差し替える。
	auto	  intelJob = manifest.GetNamedArray( L"jobs").GetObjectAt( 0U) ;
	intelJob.Insert( L"targets", references) ;
	jobs.Append( intelJob) ;
	manifest.Insert( L"targets", targets) ;
	manifest.Insert( L"jobs", jobs) ;
	definition.manifestBytes = winrt::to_string( manifest.Stringify()) ;
	CollectorProjectedCampaignIdentity identity ;	// 保存対象の正規v3入力。
	DRIVERCRATE_EXPECT( context,
					   makeCollectorProjectedCampaignIdentity( definition, L"20260929", identity) &&
						   identity.jobs.size() == 1U && identity.jobs[0].targets.size() == 300U &&
						   identity.jobs[0].targets[0].target.id == L"product0" &&
						   identity.jobs[0].targets[299].target.id == L"product299") ;
	std::shared_ptr<const CollectorPreparedProjectedCampaign> prepared ;	// 全入力を再照合。
	DRIVERCRATE_EXPECT( context,
					   prepareCollectorProjectedCampaign(
						   identity.canonicalInput, identity.inputSha256, identity.generationKey,
						   definition.artifactSha256, definition.sources, prepared) &&
						   prepared && prepared->jobCount() == 1U &&
						   prepared->job( 0U)->value().targets.size() == 300U &&
						   prepared->job( 0U)->value().targets[299].target.id == L"product299") ;

	// 同じmaker別上限内で全体だけを301へ越え、部分準備を許さない。
	JsonObject excess ;	// 既存Maker 0の61件目。
	excess.Insert( L"id", JsonValue::CreateStringValue( L"product300")) ;
	excess.Insert( L"maker", JsonValue::CreateStringValue( L"Maker 0")) ;
	excess.Insert( L"model", JsonValue::CreateStringValue( L"Ethernet Product 300")) ;
	excess.Insert( L"kind", JsonValue::CreateStringValue( L"NETWORK_ADAPTER")) ;
	excess.Insert( L"purpose", JsonValue::CreateStringValue( L"Ethernet")) ;
	targets.Append( excess) ;
	references.Append( JsonValue::CreateStringValue( L"product300")) ;
	definition.manifestBytes = winrt::to_string( manifest.Stringify()) ;
	CollectorCampaignManifest rejectedManifest ;	// 下位manifestも同じ全体上限を拒否する。
	DRIVERCRATE_EXPECT( context,
					   !parseCollectorCampaignManifest( definition.manifestBytes, definition.sources,
													   rejectedManifest) &&
						   rejectedManifest.targets.empty()) ;
	DRIVERCRATE_EXPECT( context,
					   !makeCollectorProjectedCampaignIdentity( definition, L"20260929", identity) &&
						   identity.canonicalInput.empty() && identity.jobs.empty()) ;
}

/**
 * @brief 新v3入力を二つの公式job・26共有対象から再構築し、旧Gと分離します。
 * @param[in,out] context 同期中だけ借用し、実行済みassertionと失敗件数を追加する集計先です。
 */
void projectedCampaignIdentity( TestContext &context)
{
	auto							   definition = projectedDefinition() ;	// 固定source registry。
	CollectorProjectedCampaignIdentity identity ;							// 非保存v3入力。
	DRIVERCRATE_EXPECT( context,
					   makeCollectorProjectedCampaignIdentity( definition, L"20260928", identity)) ;
	DRIVERCRATE_EXPECT( context, identity.jobs.size() == 2U) ;
	DRIVERCRATE_EXPECT( context, identity.jobs.front().targets.size() == 26U) ;
	DRIVERCRATE_EXPECT( context, identity.jobs.back().targets.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, !identity.canonicalInput.empty()) ;
	std::shared_ptr<const CollectorPreparedProjectedCampaign> prepared ;	// 全jobを一回で準備。
	DRIVERCRATE_EXPECT( context,
					   prepareCollectorProjectedCampaign(
						   identity.canonicalInput, identity.inputSha256, identity.generationKey,
						   definition.artifactSha256, definition.sources, prepared) &&
						   prepared && prepared->jobCount() == 2U && prepared->job( 2U) == nullptr) ;
	// 準備失敗を有効jobの試験へ進めない。
	if( !prepared || prepared->jobCount() != 2U) {
		return ;
	}

	// 元canonicalの一fieldだけを改変し、表面上のhashと世代も再計算します。
	for( unsigned mode = 0U; mode < 6U; ++mode) {
		JsonObject root =
			// 元保存像。
			JsonObject::Parse( winrt::to_hstring( identity.canonicalInput)) ;
		auto row = root.GetNamedArray( L"jobs").GetObjectAt( 0U) ;	// 第一jobの一行。
		// 変更前は元canonical実byteへ無損失で戻ることを保証します。
		DRIVERCRATE_EXPECT( context, winrt::to_string( root.Stringify()) == identity.canonicalInput) ;
		// 対象・slice・parser・policy・artifact・scopeをそれぞれ独立に壊します。
		switch( mode) {
			// Manifest内の後半対象だけ変更し、公開job行を元のままにします。
			case 0: {
				auto manifest = JsonObject::Parse( root.GetNamedString( L"manifest")) ;	// 元manifest。
				manifest.GetNamedArray( L"targets")
					.GetObjectAt( 25U)
					.Insert( L"purpose", JsonValue::CreateStringValue( L"Other")) ;
				root.Insert( L"manifest", JsonValue::CreateStringValue( manifest.Stringify())) ;
				break ;
			}

			// 第一sliceだけを別keyへ置換します。
			case 1:
				row.GetNamedArray( L"slices").SetAt( 0U,
												   JsonValue::CreateStringValue( L"tampered-slice")) ;
				break ;

			// 元parser revisionを変更しても保存元sourceへは遡及させません。
			case 2:
				row.Insert( L"recordParser", JsonValue::CreateStringValue( L"tampered-parser")) ;
				break ;

			// 元公式policy IDを別値へ置換します。
			case 3:
				row.Insert( L"policy", JsonValue::CreateStringValue( L"tampered-policy")) ;
				break ;

			// 一見有効な64桁でも現物artifactとは一致させません。
			case 4:
				root.Insert( L"artifact", JsonValue::CreateStringValue( std::wstring( 64U, L'b'))) ;
				break ;

			// 全対象scope hash文字列だけを差し替えます。
			default:
				row.Insert( L"scope", JsonValue::CreateStringValue( std::wstring( 64U, L'c'))) ;
				break ;
		}

		const auto	 tampered = winrt::to_string( root.Stringify()) ;	// 変更済みの実保存byte。
		std::wstring tamperedHash ;										// 改変本文の新SHA-256。
		std::wstring tamperedGeneration ;								// 新hashから導出した専用G。
		DRIVERCRATE_EXPECT(
			context, computeBytesSha256( tampered, tamperedHash) == 0U &&
						 computeBytesSha256(
							 "schema-v3\n" + winrt::to_string( winrt::hstring( tamperedHash)) + "\n",
							 tamperedGeneration) == 0U &&
						 tampered != identity.canonicalInput) ;
		std::shared_ptr<const CollectorPreparedProjectedCampaign> refused = prepared ;	// 失敗時空。
		const auto artifact = mode == 4U ? std::wstring( 64U, L'b')
										 : definition.artifactSha256 ;	// 改変元と現物の両条件。
		DRIVERCRATE_EXPECT(
			context, !prepareCollectorProjectedCampaign( tampered, tamperedHash, tamperedGeneration,
														artifact, definition.sources, refused) &&
						 !refused) ;
	}

	const auto lockedPurpose =
		// 元の末尾対象目的。
		prepared->job( 0U)->value().targets.back().target.purpose ;
	// 準備後に旧可変identityを書き換えてもworkerの所有値は変わらない。
	identity.jobs[0].targets.back().target.purpose = L"Mutated" ;
	DRIVERCRATE_EXPECT( context, prepared->job( 0U)->value().targets.size() == 26U &&
									prepared->job( 0U)->value().targets.back().target.purpose ==
										lockedPurpose &&
									prepared->job( 1U)->value().targets.size() == 1U) ;
	std::shared_ptr<const CollectorPreparedProjectedCampaign> refused =
		prepared ;	// 失敗時は空へ戻す。
	// 入力実byte・G・artifact・組み込みregistryの差し替えを一件ずつ拒否する。
	DRIVERCRATE_EXPECT( context,
					   !prepareCollectorProjectedCampaign(
						   identity.canonicalInput, std::wstring( 64U, L'a'), identity.generationKey,
						   definition.artifactSha256, definition.sources, refused) &&
						   !refused) ;
	DRIVERCRATE_EXPECT( context,
					   !prepareCollectorProjectedCampaign(
						   identity.canonicalInput, identity.inputSha256, std::wstring( 64U, L'b'),
						   definition.artifactSha256, definition.sources, refused) &&
						   !refused) ;
	DRIVERCRATE_EXPECT(
		context, !prepareCollectorProjectedCampaign( identity.canonicalInput, identity.inputSha256,
													identity.generationKey, std::wstring( 64U, L'c'),
													definition.sources, refused) &&
					 !refused) ;
	auto otherSources = definition.sources ;	// 検証済み保存sourceとは別の組み込み条件。
	otherSources.front().parserRevision += L"-different" ;
	DRIVERCRATE_EXPECT( context,
					   !prepareCollectorProjectedCampaign(
						   identity.canonicalInput, identity.inputSha256, identity.generationKey,
						   definition.artifactSha256, otherSources, refused) &&
						   !refused) ;
	// 正当な列挙順差は許す。
	std::reverse( otherSources.begin(), otherSources.end()) ;
	otherSources.back().parserRevision = definition.sources.front().parserRevision ;
	DRIVERCRATE_EXPECT(
		context,
		prepareCollectorProjectedCampaign( identity.canonicalInput, identity.inputSha256,
										  identity.generationKey, definition.artifactSha256,
										  otherSources, refused) &&
			refused &&
			refused->job( 0U)->value().scopeSha256 == prepared->job( 0U)->value().scopeSha256) ;
	std::wstring inputHash ;	// 実canonical byteの独立再hash。
	DRIVERCRATE_EXPECT( context, computeBytesSha256( identity.canonicalInput, inputHash) == 0U) ;
	DRIVERCRATE_EXPECT( context, inputHash == identity.inputSha256) ;
	std::wstring expectedGeneration ;	// ADR 0220の新G公式。
	DRIVERCRATE_EXPECT(
		context,
		computeBytesSha256( "schema-v3\n" + winrt::to_string( winrt::hstring( inputHash)) + "\n",
						   expectedGeneration) == 0U) ;
	DRIVERCRATE_EXPECT( context, expectedGeneration == identity.generationKey) ;
	CollectorCampaignManifest checked ;	// 旧Gとの分離を元manifest hashで確認する。
	DRIVERCRATE_EXPECT( context, parseCollectorCampaignManifest( definition.manifestBytes,
															   definition.sources, checked)) ;
	std::wstring oldGeneration ;	// v2の元domainと入力順。
	DRIVERCRATE_EXPECT(
		context, computeBytesSha256( "schema-v2\n20260928\n" +
										winrt::to_string( winrt::hstring( checked.manifestSha256)) +
										"\n" + winrt::to_string( winrt::hstring( HASH)) + "\n",
									oldGeneration) == 0U) ;
	DRIVERCRATE_EXPECT( context, oldGeneration != identity.generationKey) ;
	const auto originalInput	  = identity.canonicalInput ;	// 再構築時の実byte照合。
	const auto originalGeneration = identity.generationKey ;	// 元G。
	std::reverse( definition.sources.begin(), definition.sources.end()) ;
	DRIVERCRATE_EXPECT( context,
					   makeCollectorProjectedCampaignIdentity( definition, L"20260928", identity)) ;
	DRIVERCRATE_EXPECT( context, identity.canonicalInput == originalInput) ;
	DRIVERCRATE_EXPECT( context, identity.generationKey == originalGeneration) ;
	// 同じmanifest・artifactでも日付が違えば新Gを区別する。
	DRIVERCRATE_EXPECT( context,
					   makeCollectorProjectedCampaignIdentity( definition, L"20260929", identity)) ;
	DRIVERCRATE_EXPECT( context, identity.generationKey != originalGeneration) ;
	// 後半targetだけのpurpose変更も全scopeを再計算する。
	auto manifest =
		// 後半対象の変更。
		JsonObject::Parse( winrt::to_hstring( definition.manifestBytes)) ;
	manifest.GetNamedArray( L"targets")
		.GetObjectAt( 25U)
		.Insert( L"purpose", JsonValue::CreateStringValue( L"Other")) ;
	definition.manifestBytes = winrt::to_string( manifest.Stringify()) ;
	DRIVERCRATE_EXPECT( context,
					   makeCollectorProjectedCampaignIdentity( definition, L"20260928", identity)) ;
	DRIVERCRATE_EXPECT( context, identity.generationKey != originalGeneration) ;
	// 失敗後に元成功identityを残さない。
	DRIVERCRATE_EXPECT( context,
					   !makeCollectorProjectedCampaignIdentity( definition, L"20260229", identity)) ;
	DRIVERCRATE_EXPECT( context, identity.canonicalInput.empty() && identity.jobs.empty()) ;
	definition.artifactSha256 = std::wstring( 64U, L'A') ;
	DRIVERCRATE_EXPECT( context,
					   !makeCollectorProjectedCampaignIdentity( definition, L"20260928", identity)) ;
}

} // namespace
} // namespace drivercrate::test

/** @brief 非通信fixtureだけを実行してassertion集計を返します。
 * @param[in] argc 起動引数の個数。
 * @param[in] argv 開発用subsuite指定または既定の全件実行。
 * @return 全assertion成功0、失敗1。
 */
int main( const int argc, char **argv)
{
	// 非通信assertion集計。
	drivercrate::test::TestContext	   context ;
	// 自作GUID領域だけを後始末する。
	std::vector<std::filesystem::path> roots ;
	try {
		winrt::init_apartment( winrt::apartment_type::multi_threaded) ;
		// 実handleの読取り証明をbyte codecや監督再開の分母から分離します。
		if( argc == 2 && std::string_view( argv[1]) == "--segment-read-context-only") {
			drivercrate::test::runCollectorSegmentReadContextTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
			std::cout << "Collector segment read context tests: " << context.assertionCount()
					  << " assertions, " << context.failureCount() << " failures\n" ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// 初回readyのbyte結合だけを実handle readerの分母から分離します。
		if( argc == 2 && std::string_view( argv[1]) == "--segment-initial-read-codec-only") {
			drivercrate::test::runCollectorSegmentInitialReadCodecTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
			std::cout << "Collector segment initial read codec tests: " << context.assertionCount()
					  << " assertions, " << context.failureCount() << " failures\n" ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// ROOT未保存の全準備prefix回復を独立分母で検査します。
		if( argc == 2 && std::string_view( argv[1]) == "--segment-preparation-recovery-only") {
			drivercrate::test::runCollectorSegmentPreparationRecoveryTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
			std::cout << "Collector segment preparation recovery tests: "
					  << context.assertionCount() << " assertions, " << context.failureCount()
					  << " failures\n" ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// 保護実fileからのROOT保存済み回復を独立分母で検査します。
		if( argc == 2 && std::string_view( argv[1]) == "--segment-recovery-storage-only") {
			drivercrate::test::runCollectorSegmentRecoveryStorageTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
			std::cout << "Collector segment recovery storage tests: " << context.assertionCount()
					  << " assertions, " << context.failureCount() << " failures\n" ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// 回復候補byteだけを独立分母で測り、実再起動回復へ昇格させません。
		if( argc == 2 && std::string_view( argv[1]) == "--segment-recovery-codec-only") {
			drivercrate::test::runCollectorSegmentRecoveryCodecTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
			std::cout << "Collector segment recovery codec tests: " << context.assertionCount()
					  << " assertions, " << context.failureCount() << " failures\n" ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// 親head実保存を同一生存予約だけの独立分母として測ります。
		if( argc == 2 && std::string_view( argv[1]) == "--parent-head-storage-only") {
			drivercrate::test::runCollectorParentHeadStorageTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
			std::cout << "Collector parent head storage tests: " << context.assertionCount()
					  << " assertions, " << context.failureCount() << " failures\n" ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// 専用初期ROOTの実保存を親head／再起動回復の分母へ混入させません。
		if( argc == 2 && std::string_view( argv[1]) == "--initial-root-storage-only") {
			drivercrate::test::runCollectorInitialRootStorageTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
			std::cout << "Collector initial root storage tests: " << context.assertionCount()
					  << " assertions, " << context.failureCount() << " failures\n" ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// 私有新子の実保存を旧準備保存・非保存容量の分母から分離します。
		if( argc == 2 && std::string_view( argv[1]) == "--new-segment-storage-only") {
			drivercrate::test::runCollectorNewSegmentStorageTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
			std::cout << "Collector new segment storage tests: " << context.assertionCount()
					  << " assertions, " << context.failureCount() << " failures\n" ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// 実保存の新分母を非保存容量／HTTP所有の分母へ混ぜません。
		if( argc == 2 && std::string_view( argv[1]) == "--segment-preparation-storage-only") {
			drivercrate::test::runCollectorSegmentPreparationStorageTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
			std::cout << "Collector segment preparation storage tests: " << context.assertionCount()
					  << " assertions, " << context.failureCount() << " failures\n" ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// 非保存holdと容量の新分母だけを独立測定します。
		if( argc == 2 && std::string_view( argv[1]) == "--segment-storage-only") {
			drivercrate::test::runCollectorSegmentStorageTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
			std::cout << "Collector segment storage tests: " << context.assertionCount()
					  << " assertions, " << context.failureCount() << " failures\n" ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// HTTP実所有閉鎖の分母を旧reader／準備fixtureへ重複させません。
		if( argc == 2 && std::string_view( argv[1]) == "--http-quiescence-only") {
			drivercrate::test::runCollectorHttpQuiescenceTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
			std::cout << "Collector HTTP quiescence tests: " << context.assertionCount()
					  << " assertions, " << context.failureCount() << " failures\n" ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// 非保存準備の追加枠を旧reader・draft coreの分母へ重複させません。
		if( argc == 2 && std::string_view( argv[1]) == "--segment-preparation-only") {
			drivercrate::test::runCollectorSegmentPreparationTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
			// 新階層fixtureは保持し、旧回収の削除範囲を広げません。
			std::cout << "Collector segment preparation tests: " << context.assertionCount()
					  << " assertions, " << context.failureCount() << " failures\n" ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// 結合検査の分母を旧個別readerの分母へ重複させません。
		if( argc == 2 && std::string_view( argv[1]) == "--segment-inventory-only") {
			drivercrate::test::runCollectorSegmentInventoryTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
			// 新階層のfixtureは保持します。旧非再帰回収を再帰削除へ拡張しません。
			std::cout << "Collector segment inventory tests: " << context.assertionCount()
					  << " assertions, " << context.failureCount() << " failures\n" ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// 同親配置の新枠だけを測り、旧v3 fixtureの分母へ重複させません。
		if( argc == 2 && std::string_view( argv[1]) == "--history-layout-v3-only") {
			drivercrate::test::runCollectorHistoryLayoutV3Tests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
			// 新階層は旧二directoryの非再帰回収対象外です。専用fixtureを残し、削除範囲を広げません。

			std::cout << "Collector history layout v3 tests: " << context.assertionCount()
					  << " assertions, " << context.failureCount() << " failures\n" ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// 新封印の分母を既存全枠へ混ぜず、専用指定だけを実行します。
		if( argc == 2 && std::string_view( argv[1]) == "--completed-inventory-only") {
			drivercrate::test::runCollectorCompletedInventoryTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
			// この専用枠が作成したGUID rootだけを回収します。
			for( const auto &root : roots) {
				DRIVERCRATE_EXPECT( context, drivercrate::test::cleanup( root)) ;
			}

			std::cout << "Collector completed inventory tests: " << context.assertionCount()
					  << " assertions, " << context.failureCount() << " failures\n" ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		const bool projectedOnly =
			argc == 2 && std::string_view( argv[1]) ==
							 "--projected-http-only" ;	// 射影HTTP専用CTestだけを選択します。
		const bool withoutProjected =
			argc == 2 && std::string_view( argv[1]) ==
							 "--without-projected-http" ;	// 既存CTestから専用分を重複なく除きます。
		const bool nextRecoveryOnly = argc == 2 &&
									  // 新規分だけの有限枠。
									  std::string_view( argv[1]) == "--next-recovery-only" ;
		const bool partialStartOnly = argc == 2 &&
									  // 新規保存窓だけの独立枠。
									  std::string_view( argv[1]) == "--partial-start-only" ;
		const bool dayRollOnly = argc == 2 &&
								 // 日次保存窓だけの有限非重複枠。
								 std::string_view( argv[1]) == "--day-roll-only" ;
		const bool finishOnly = argc == 2 && std::string_view( argv[1]) ==
												 "--finish-recovery-only" ;	// 新末尾完了専用枠です。
		const bool boundaryOnly = argc == 2 &&
								  // 世代上限の専用枠。
								  std::string_view( argv[1]) == "--generation-boundary-only" ;
		const bool operationOnly =
			argc == 2 && std::string_view( argv[1]) ==
							 "--operation-history-only" ;	// 本番二世代・未受領予約の基礎枠。
		const bool capacityOnly = argc == 2 &&
								  // 合成操作閉包の有限独立枠。
								  std::string_view( argv[1]) == "--operation-capacity-only" ;
		const bool cacheGrowthOnly = argc == 2 &&
									 // 新requestの専用枠です。
									 std::string_view( argv[1]) == "--cache-growth-only" ;
		const bool cacheCapacityOnly = argc == 2 &&
									   // 大量新要求だけの有限枠です。
									   std::string_view( argv[1]) == "--cache-capacity-only" ;
		const bool cacheStartupOnly = argc == 2 &&
									  // 四件単位の厳密境界・通常起動だけを独立測定します。
									  std::string_view( argv[1]) == "--cache-startup-only" ;
		// 無引数は従来の全件実行を維持します。
		if( !projectedOnly && !nextRecoveryOnly && !partialStartOnly && !dayRollOnly &&
		   !finishOnly && !boundaryOnly && !operationOnly && !capacityOnly && !cacheGrowthOnly &&
		   !cacheCapacityOnly && !cacheStartupOnly) {
			drivercrate::test::runCollectorProjectedJsonTests( context) ;
			drivercrate::test::projectedJobScope( context) ;
			drivercrate::test::projectedCampaignIdentity( context) ;
			drivercrate::test::projectedCampaignTargetBoundary( context) ;
			drivercrate::test::runCollectorProjectedRecoveryTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
		}

		// 専用CTest以外では従来と同じ引数無しの射影HTTP全件です。
		if( !withoutProjected && !nextRecoveryOnly && !partialStartOnly && !dayRollOnly &&
		   !finishOnly && !boundaryOnly && !operationOnly && !capacityOnly && !cacheGrowthOnly &&
		   !cacheCapacityOnly && !cacheStartupOnly) {
			drivercrate::test::runCollectorProjectedHttpTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
		}

		// 既定の全件または専用枠だけで新規分を実行し、旧二CTestへ重複させません。
		if( argc == 1 || nextRecoveryOnly) {
			drivercrate::test::runCollectorNextRecoveryTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
		}

		// 旧三収集枠へ新規分を重複させず、無引数の全件実行だけは維持します。
		if( argc == 1 || partialStartOnly) {
			drivercrate::test::runCollectorPartialStartRecoveryTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
		}

		// 旧四収集枠へ新規日次fixtureを重複させず、無引数の全件実行も保持します。
		if( argc == 1 || dayRollOnly) {
			drivercrate::test::runCollectorDayRollRecoveryTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
		}

		// 旧五収集CTestへ重複せず、無引数は新規分も含む全件実行です。
		if( argc == 1 || finishOnly) {
			drivercrate::test::runCollectorFinishRecoveryTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
		}

		// 無引数の全件実行にだけ新境界を含め、旧六CTestへ混入させません。
		if( argc == 1 || boundaryOnly) {
			drivercrate::test::runCollectorGenerationBoundaryTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
		}

		// 専用境界枠では既存fixtureを重複実行しません。
		if( argc == 1 || operationOnly) {
			drivercrate::test::runCollectorOperationHistoryTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
		}

		// 元基礎fixtureと重複させず、合成境界を専用枠で実行します。
		if( argc == 1 || capacityOnly) {
			drivercrate::test::runCollectorOperationHistoryTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }, true) ;
		}

		// 新request増加は旧十二CTestへ重複させません。
		if( argc == 1 || cacheGrowthOnly) {
			drivercrate::test::runCollectorCacheGrowthTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }) ;
		}

		// 専用の保存操作境界は旧七suiteへ混入させません。
		// 大量新requestは旧十三CTestと同じ分母へ入れません。
		if( argc == 1 || cacheCapacityOnly) {
			drivercrate::test::runCollectorCacheGrowthTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }, true) ;
		}

		// 元段階系列を変更せず、通常起動境界は独立の分母で測ります。
		if( argc == 1 || cacheStartupOnly) {
			drivercrate::test::runCollectorCacheGrowthTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[] { return drivercrate::test::projectedDefinition() ; }, true, true) ;
		}

		// 独立の新容量枠には旧executor受入を重複実行しません。
		if( !projectedOnly && !nextRecoveryOnly && !partialStartOnly && !dayRollOnly &&
		   !finishOnly && !boundaryOnly && !operationOnly && !capacityOnly && !cacheGrowthOnly &&
		   !cacheCapacityOnly && !cacheStartupOnly) {
			drivercrate::test::runCollectorExecutorAcceptanceTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[]( std::size_t count) { return drivercrate::test::recoveryInput( count) ; }) ;
		}

		// 新しい受入subsuiteだけを指定した場合は旧suiteを重複実行しない。
		if( !projectedOnly && !nextRecoveryOnly && !partialStartOnly && !dayRollOnly &&
		   !finishOnly && !boundaryOnly && !operationOnly && !capacityOnly && !cacheGrowthOnly &&
		   !cacheCapacityOnly && !cacheStartupOnly &&
		   (argc != 2 || std::string_view( argv[1]) != "--executor-acceptance-only")) {
			drivercrate::test::runCollectorV3RecoveryTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[]( std::size_t count) { return drivercrate::test::recoveryInput( count) ; }) ;
			drivercrate::test::runCollectorExecutorTests(
				context, [&roots] { return drivercrate::test::rootFor( roots) ; },
				[]( std::size_t count) { return drivercrate::test::recoveryInput( count) ; }) ;
			drivercrate::test::recoveryPrefixes( context, roots) ;
			drivercrate::test::recoveryChangedInput( context, roots) ;
			drivercrate::test::recoveryMissingAndForgery( context, roots) ;
			drivercrate::test::recoveryRepeatedInterruption( context, roots) ;
			drivercrate::test::recoveryLimits( context, roots) ;
			drivercrate::test::recoveryClocks( context, roots) ;
			drivercrate::test::recoveryDailyBudgets( context, roots) ;
			drivercrate::test::recoveryBatchBudgets( context, roots) ;
			drivercrate::test::recoveryZeroAndContradictions( context, roots) ;
			drivercrate::test::recoveryStorageCapacity( context, roots) ;
			drivercrate::test::recoveryPairedLoss( context, roots) ;
			drivercrate::test::recoveryBindingMutations( context, roots) ;
			drivercrate::test::recoveryReadiness( context, roots) ;
			drivercrate::test::recoveryDispatchDeadline( context, roots) ;
			drivercrate::test::collectorPermitBinding( context, roots) ;
			drivercrate::test::collectorControlObservations( context, roots) ;
			drivercrate::test::collectorControlOwnership( context, roots) ;
			drivercrate::test::runCollectorControlledHttpTests( context, [&roots] {
				return drivercrate::test::rootFor( roots) ;
			}) ; // 自作rootの回収を既存suiteへ結合する。
			drivercrate::test::runCollectorControlledExecutorHttpTests( context, [&roots] {
				return drivercrate::test::rootFor( roots) ;
			}) ; // Raw HTTPからv3保存まで同じ監督経路を通す。
			// 開発中の復旧subsuite指定。CTestはこの全件と射影HTTPを分割します。
			if( argc == 2 && std::string_view( argv[1]) == "--recovery-only") {
				drivercrate::test::recoveryWindows( context, roots) ;
				drivercrate::test::recoveryOrdering( context, roots) ;
				drivercrate::test::recoveryCorruption( context, roots) ;
				drivercrate::test::recoveryDayRoll( context, roots) ;
				drivercrate::test::recoveryV1Enrollment( context, roots) ;
			} else {
				drivercrate::test::inputChecks( context) ;
				drivercrate::test::sharedAndResume( context, drivercrate::test::rootFor( roots)) ;
				drivercrate::test::interrupted( context, drivercrate::test::rootFor( roots), false) ;
				drivercrate::test::interrupted( context, drivercrate::test::rootFor( roots), true) ;
				drivercrate::test::concurrency( context, drivercrate::test::rootFor( roots)) ;
				drivercrate::test::byteBudget( context, drivercrate::test::rootFor( roots)) ;
				drivercrate::test::requestBudget( context, drivercrate::test::rootFor( roots)) ;
				drivercrate::test::timeBudget( context, drivercrate::test::rootFor( roots)) ;
				drivercrate::test::failureChecks( context, drivercrate::test::rootFor( roots)) ;
				drivercrate::test::stateBoundaries( context, roots) ;
				drivercrate::test::campaignLoss( context, roots) ;
				drivercrate::test::borrowedStore( context, drivercrate::test::rootFor( roots)) ;
				drivercrate::test::waitBoundaries( context, roots) ;
				drivercrate::test::waitRecovery( context, roots) ;
				drivercrate::test::waitFailures( context, roots) ;
				drivercrate::test::waitCapacityAndSave( context, roots) ;
				drivercrate::test::passiveBudget( context, roots) ;
				drivercrate::test::passiveBudgetFailures( context, roots) ;
				drivercrate::test::passiveBudgetRoots( context, roots) ;
				drivercrate::test::recoveryWindows( context, roots) ;
				drivercrate::test::recoveryOrdering( context, roots) ;
				drivercrate::test::recoveryCorruption( context, roots) ;
				drivercrate::test::recoveryDayRoll( context, roots) ;
				drivercrate::test::recoveryV1Enrollment( context, roots) ;
			}
		}
	} catch( const std::exception &error) {
		std::cerr << "Campaign fixture exception: " << error.what() << '\n' ;
		context.expect( false, "campaign fixture exception", __FILE__, __LINE__) ;
	} catch( const winrt::hresult_error &) {
		context.expect( false, "campaign JSON fixture exception", __FILE__, __LINE__) ;
	}

	// 初回reader codecのfixture例外でも独立分母と原故障を保持します。
	if( argc == 2 && std::string_view( argv[1]) == "--segment-read-context-only") {
		std::cout << "Collector segment read context tests: " << context.assertionCount()
				  << " assertions, " << context.failureCount() << " failures\n" ;
		return context.failureCount() == 0 ? 0 : 1 ;
	}

	// 初回reader codecのfixture例外でも独立分母と原故障を保持します。
	if( argc == 2 && std::string_view( argv[1]) == "--segment-initial-read-codec-only") {
		std::cout << "Collector segment initial read codec tests: " << context.assertionCount()
				  << " assertions, " << context.failureCount() << " failures\n" ;
		return context.failureCount() == 0 ? 0 : 1 ;
	}

	// ROOT未保存回復fixtureの例外でも原故障と独立分母を維持します。
	if( argc == 2 && std::string_view( argv[1]) == "--segment-preparation-recovery-only") {
		std::cout << "Collector segment preparation recovery tests: " << context.assertionCount()
				  << " assertions, " << context.failureCount() << " failures\n" ;
		return context.failureCount() == 0 ? 0 : 1 ;
	}

	// 保護実回復fixtureの例外でも独立分母を維持します。
	if( argc == 2 && std::string_view( argv[1]) == "--segment-recovery-storage-only") {
		std::cout << "Collector segment recovery storage tests: " << context.assertionCount()
				  << " assertions, " << context.failureCount() << " failures\n" ;
		return context.failureCount() == 0 ? 0 : 1 ;
	}

	// 回復byte fixtureの例外でも原故障と独立分母を保持します。
	if( argc == 2 && std::string_view( argv[1]) == "--segment-recovery-codec-only") {
		std::cout << "Collector segment recovery codec tests: " << context.assertionCount()
				  << " assertions, " << context.failureCount() << " failures\n" ;
		return context.failureCount() == 0 ? 0 : 1 ;
	}

	// 親head fixtureの例外でも原故障と全階層を保持します。
	if( argc == 2 && std::string_view( argv[1]) == "--parent-head-storage-only") {
		std::cout << "Collector parent head storage tests: " << context.assertionCount()
				  << " assertions, " << context.failureCount() << " failures\n" ;
		return context.failureCount() == 0 ? 0 : 1 ;
	}

	// 専用ROOT fixtureの例外でも元故障と全byteを保持します。
	if( argc == 2 && std::string_view( argv[1]) == "--initial-root-storage-only") {
		std::cout << "Collector initial root storage tests: " << context.assertionCount()
				  << " assertions, " << context.failureCount() << " failures\n" ;
		return context.failureCount() == 0 ? 0 : 1 ;
	}

	// 新子準備fixtureの例外も原故障と全階層を保持します。
	if( argc == 2 && std::string_view( argv[1]) == "--new-segment-storage-only") {
		std::cout << "Collector new segment storage tests: " << context.assertionCount()
				  << " assertions, " << context.failureCount() << " failures\n" ;
		return context.failureCount() == 0 ? 0 : 1 ;
	}

	// 実保存fixtureの例外時も原故障と新階層を保持します。
	if( argc == 2 && std::string_view( argv[1]) == "--segment-preparation-storage-only") {
		std::cout << "Collector segment preparation storage tests: " << context.assertionCount()
				  << " assertions, " << context.failureCount() << " failures\n" ;
		return context.failureCount() == 0 ? 0 : 1 ;
	}

	// 保存予定の非保存試験も例外時の元階層と失敗を保持します。
	if( argc == 2 && std::string_view( argv[1]) == "--segment-storage-only") {
		std::cout << "Collector segment storage tests: " << context.assertionCount()
				  << " assertions, " << context.failureCount() << " failures\n" ;
		return context.failureCount() == 0 ? 0 : 1 ;
	}

	// 実所有閉鎖の例外時にも元階層fixtureを保持します。
	if( argc == 2 && std::string_view( argv[1]) == "--http-quiescence-only") {
		std::cout << "Collector HTTP quiescence tests: " << context.assertionCount()
				  << " assertions, " << context.failureCount() << " failures\n" ;
		return context.failureCount() == 0 ? 0 : 1 ;
	}

	// 新階層fixtureは例外時も旧非再帰回収へ渡さず、原故障と保存物を保持します。
	if( argc == 2 && std::string_view( argv[1]) == "--segment-preparation-only") {
		std::cout << "Collector segment preparation tests: " << context.assertionCount()
				  << " assertions, " << context.failureCount() << " failures\n" ;
		return context.failureCount() == 0 ? 0 : 1 ;
	}

	// 区間inventoryの元例外分母とfixture保持も変更しません。
	if( argc == 2 && std::string_view( argv[1]) == "--segment-inventory-only") {
		std::cout << "Collector segment inventory tests: " << context.assertionCount()
				  << " assertions, " << context.failureCount() << " failures\n" ;
		return context.failureCount() == 0 ? 0 : 1 ;
	}

	// 自分が作成した領域だけを回収する。
	for( const auto &root : roots) {
		DRIVERCRATE_EXPECT( context, drivercrate::test::cleanup( root)) ;
	}

	std::cout << "Collector campaign tests: " << context.assertionCount() << " assertions, "
			  << context.failureCount() << " failures\n" ;
	return context.failureCount() == 0 ? 0 : 1 ;
}
