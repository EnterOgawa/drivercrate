//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_recovery_tests.cpp
 * @brief 新世代保存窓と旧応答回収を実保護storeで検証します。
 * @version 01.01.04
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  新世代登録と旧回収の非通信fixtureを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/28  永続予約・四role全保存窓と改変拒否を追加。
 * Ver.01.01.01 Shunji Ogawa  2026/09/28  専用開始intentの元scope照合を更新。
 * Ver.01.01.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.01.03 Shunji Ogawa  2026/10/18  旧世代回収の元戻り値とreasonを診断表示。
 * Ver.01.01.04 Shunji Ogawa  2026/10/18 一時path診断を除去し元の回収期待を保持。
 * </pre>
 *
 * @note 自作fixture rootだけを使用し、通信・実driver処理を行いません。
 */
//------------------------------------------------------------------------------
#include "local_collector_projected_recovery_tests.h"
#include "platform/local_collector_projected_start.h"
#include "platform/local_collector_http_control.h"
#include "platform/local_collector_recovery.h"
#include "platform/local_collector_state_store.h"
#include "platform/official_file_verifier.h"
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#include <array>
#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

namespace drivercrate::test {
namespace {
/**
 * @brief JSON objectをWinRT参照で保持する。Copyは同じobjectを共有し、schema検証は利用側で行う。
 */
using Object = winrt::Windows::Data::Json::JsonObject ;
/**
 * @brief JSON値をWinRT参照で保持する。所有byteの検証と型判定はreader側で行う。
 */
using Value = winrt::Windows::Data::Json::JsonValue ;
// JST 2026-09-28の開始。実時計に依存しない。
constexpr std::uint64_t NOW = 1790521200000ULL ;
// 元schemaごとに同じ入口を使う。
constexpr auto			ROOT = L"current/campaign-root-v2.json" ;

/** @brief 元保護fileの本文を読みます。
 * @param[in,out] store Fixture writer。
 * @param[in] name 固定相対名。
 * @return 元本文。読込み失敗はtestを停止します。
 */
std::string				body( LocalCollectorStateStore &store, const std::wstring &name)
{
	std::string raw ;		// 元envelope。
	bool		found{} ;	// 欠損を空成功にしない。
	// Test準備失敗を検証成功へ変換しない。
	if( store.read( name, raw, found) != 0U || !found) {
		throw std::runtime_error( "projected fixture read") ;
	}

	return winrt::to_string( Object::Parse( winrt::to_hstring( raw)).GetNamedString( L"body")) ;
}

/** @brief 正しいenvelopeを付けて内容改変だけを注入します。
 * @param[in,out] store 自作root writer。
 * @param[in] name 自作固定名。
 * @param[in] content 型・bindingを改変した元本文。
 */
void save( LocalCollectorStateStore &store, const std::wstring &name, const std::string &content)
{
	std::wstring hash ;	// 実byte指紋。
	// Hash失敗を意図した改変拒否として採点しない。
	if( computeBytesSha256( content, hash) != 0U) {
		throw std::runtime_error( "projected fixture hash") ;
	}

	Object envelope ;	// Productionと同じ外側schema。
	envelope.Insert( L"schema", Value::CreateStringValue( L"collector-campaign-envelope-v1")) ;
	envelope.Insert( L"body", Value::CreateStringValue( winrt::to_hstring( content))) ;
	envelope.Insert( L"sha256", Value::CreateStringValue( hash)) ;
	// 正しいenvelopeでのみ内側の拒否を検査する。
	if( store.write( name, winrt::to_string( envelope.Stringify())) != 0U) {
		throw std::runtime_error( "projected fixture save") ;
	}
}

/** @brief 新定義と同じ公開jobを旧予約fixtureへ渡します。
 * @param[in] definition 有効な新入力。
 * @return 旧v2専用入力。
 */
CollectorRecoveryInput oldInput( const CollectorProjectedCampaignDefinition &definition)
{
	CollectorProjectedCampaignIdentity identity ;	// 元builderでjob集合を固定する。
	// Fixture準備でだけ失敗する条件を検査結果へ混ぜない。
	if( !makeCollectorProjectedCampaignIdentity( definition, L"20260928", identity)) {
		throw std::runtime_error( "projected fixture input") ;
	}

	CollectorRecoveryInput result ;	// 旧入力codecへ渡す形。
	result.manifestBytes  = definition.manifestBytes ;
	result.sources		  = definition.sources ;
	result.artifactSha256 = definition.artifactSha256 ;
	// 保存形式の違いだけを切り分ける。
	for( const auto &job : identity.jobs) {
		result.requestKeys.push_back( job.requestKey) ;
		result.cacheBindings.push_back( job.cacheBinding) ;
	}

	return result ;
}

/** @brief Input全再構築と専用開始intentの改変拒否を確認します。
 * @param[in,out] context Assertion集計。
 * @param[in] definition 有効な二source入力。
 */
void codecs( TestContext &context, const CollectorProjectedCampaignDefinition &definition)
{
	CollectorProjectedCampaignIdentity identity ;	// 元canonical入力。
	DRIVERCRATE_EXPECT( context,
					   makeCollectorProjectedCampaignIdentity( definition, L"20260928", identity)) ;
	CollectorProjectedCampaignDefinition decoded ;	// 全照合後の定義。
	CollectorProjectedCampaignIdentity	 readback ;	// 全照合後の所有値。
	DRIVERCRATE_EXPECT( context, parseCollectorProjectedCampaignIdentity( identity.canonicalInput,
																		decoded, readback)) ;
	DRIVERCRATE_EXPECT( context, readback.generationKey == identity.generationKey &&
									decoded.manifestBytes == definition.manifestBytes) ;
	// 正しいJSONとenvelopeでもinputの一部改変を許さない。
	for( unsigned mutation = 0U; mutation < 8U; ++mutation) {
		auto object =
			// 元入力から毎回独立変更。
			Object::Parse( winrt::to_hstring( identity.canonicalInput)) ;
		// 各軸の不正を一つだけ注入する。
		switch( mutation) {
			// 未知fieldを無視しない。
			case 0:
				object.Insert( L"extra", Value::CreateNullValue()) ;
				break ;

			// 別profileへ読み替えない。
			case 1:
				object.Insert( L"profile", Value::CreateStringValue( L"OTHER")) ;
				break ;

			// 全対象scopeの改変を検出する。
			case 2:
				object.GetNamedArray( L"jobs").GetObjectAt( 0U).Insert(
					L"scope", Value::CreateStringValue( std::wstring( 64U, L'0'))) ;
				break ;

			// 小数上限を整数へ丸めない。
			case 3:
				object.GetNamedArray( L"sources")
					.GetObjectAt( 0U)
					.Insert( L"maximum", Value::CreateNumberValue( 0.5)) ;
				break ;

			// 共有jobの欠落を検出する。
			case 4:
				object.GetNamedArray( L"jobs").RemoveAtEnd() ;
				break ;

			// Parser版の改変を検出する。
			case 5:
				object.GetNamedArray( L"jobs").GetObjectAt( 0U).Insert(
					L"recordParser", Value::CreateStringValue( L"new")) ;
				break ;

			// Source内の未知fieldも拒否する。
			case 6:
				object.GetNamedArray( L"sources")
					.GetObjectAt( 0U)
					.Insert( L"unknown", Value::CreateNullValue()) ;
				break ;

			// 実在しない日付を拒否する。
			case 7:
				object.Insert( L"day", Value::CreateStringValue( L"20260229")) ;
				break ;
		}

		DRIVERCRATE_EXPECT( context, !parseCollectorProjectedCampaignIdentity(
										winrt::to_string( object.Stringify()), decoded, readback)) ;
		DRIVERCRATE_EXPECT( context, decoded.manifestBytes.empty() &&
										readback.canonicalInput.empty() &&
										readback.generationKey.empty()) ;
	}

	auto duplicate = identity.canonicalInput ;	// 重複propertyがparse時に消えても実byteで拒否する。
	duplicate.insert( 1U, "\"profile\":\"METADATA_PROJECTION_V1\",") ;
	DRIVERCRATE_EXPECT( context,
					   !parseCollectorProjectedCampaignIdentity( duplicate, decoded, readback)) ;
	DRIVERCRATE_EXPECT( context, !parseCollectorProjectedCampaignIdentity(
									" " + identity.canonicalInput, decoded, readback)) ;

	CollectorRecoveryDispatch dispatch ;	// 未発行のcodec専用候補。
	dispatch.mode				  = CollectorRecoveryDispatch::Mode::PROJECTED ;
	dispatch.jobIndex			  = 0U ;
	dispatch.generationKey		  = identity.generationKey ;
	dispatch.jobKey				  = identity.jobs[0].jobKey ;
	dispatch.requestKey			  = identity.jobs[0].requestKey ;
	dispatch.cacheBinding		  = identity.jobs[0].cacheBinding ;
	dispatch.scopeSha256		  = identity.jobs[0].scopeSha256 ;
	dispatch.source				  = identity.jobs[0].source ;
	dispatch.startedUtcMillis	  = NOW ;
	dispatch.anchorUtcMillis	  = NOW + 123U ;
	dispatch.anchorSteadyMillis	  = 900U ;
	dispatch.deadlineUtcMillis	  = NOW + 120000U ;
	dispatch.deadlineSteadyMillis = 900U + 120000U - 123U ;
	std::string encoded ;	// 専用開始intent。
	DRIVERCRATE_EXPECT( context, encodeCollectorProjectedStart( identity, dispatch, encoded)) ;
	CollectorRecoveryDispatch restored ;	// 元二時計はそのまま保持する。
	DRIVERCRATE_EXPECT( context, parseCollectorProjectedStart( identity, encoded, restored)) ;
	DRIVERCRATE_EXPECT( context, sameCollectorRecoveryDispatch( dispatch, restored)) ;
	// 保存intentの異常を元入力・二時計の再計算で拒否する。
	for( const auto field : {L"schema", L"profile", L"responseVersion", L"generation", L"inputHash",
							L"scope", L"index", L"job", L"request", L"cache", L"started",
							L"anchorUtc", L"anchorSteady", L"deadlineUtc", L"deadlineSteady"}) {
		auto object = Object::Parse( winrt::to_hstring( encoded)) ;	// 成功本文から一fieldだけ変更。
		object.Insert( field, Value::CreateNullValue()) ;
		restored = dispatch ;
		DRIVERCRATE_EXPECT( context, !parseCollectorProjectedStart(
										identity, winrt::to_string( object.Stringify()), restored)) ;
		DRIVERCRATE_EXPECT( context, restored.generationKey.empty()) ;
	}

	auto wrong = dispatch ;	// 旧modeを新intentへ昇格させない。
	wrong.mode = CollectorRecoveryDispatch::Mode::CONTROLLED ;
	DRIVERCRATE_EXPECT( context,
					   !encodeCollectorProjectedStart( identity, wrong, encoded) && encoded.empty()) ;
	wrong = dispatch ;
	wrong.source.maximumResponseBytes += 1U ;
	DRIVERCRATE_EXPECT( context, !encodeCollectorProjectedStart( identity, wrong, encoded)) ;
	wrong = dispatch ;
	wrong.deadlineSteadyMillis += 1U ;
	DRIVERCRATE_EXPECT( context, !encodeCollectorProjectedStart( identity, wrong, encoded)) ;
	wrong = dispatch ;
	wrong.startedUtcMillis += 86400000U ;
	wrong.anchorUtcMillis += 86400000U ;
	wrong.deadlineUtcMillis += 86400000U ;
	DRIVERCRATE_EXPECT( context, !encodeCollectorProjectedStart( identity, wrong, encoded)) ;
}

/** @brief 新登録の各保存窓から再開し、部分登録だけを拒否します。
 * @param[in,out] context Assertion集計。
 * @param[in] roots 自作root生成。
 * @param[in] definition 新定義。
 */
void registration( TestContext &context, const std::function<std::filesystem::path()> &roots,
				  const CollectorProjectedCampaignDefinition &definition)
{
	// Rootだけの保存と、三fileの未登録保存、root登録後を区別する。
	for( const auto point :
		{CollectorRecoveryCheckpoint::ROOT_ENROLLED, CollectorRecoveryCheckpoint::PROJECTED_INPUT,
		 CollectorRecoveryCheckpoint::PROJECTED_MARKER,
		 CollectorRecoveryCheckpoint::PROJECTED_STATE,
		 CollectorRecoveryCheckpoint::PROJECTED_REGISTERED}) {
		LocalCollectorStateStore store ;	// このcaseだけの保護store。
		DRIVERCRATE_EXPECT( context, store.initialize( roots(), true) == 0U) ;
		{
			LocalCollectorRecovery recovery ;	// 保存後停止によりprocess中断を模擬する。
			DRIVERCRATE_EXPECT( context, recovery.initializeProjected( store, definition, NOW, 100U,
																	 [point]( const auto observed) {
																		 return observed == point ;
																	 }) == ERROR_OPERATION_ABORTED) ;
		}
		const bool complete = point == CollectorRecoveryCheckpoint::ROOT_ENROLLED ||
							  // 再読込可能な二窓。
							  point == CollectorRecoveryCheckpoint::PROJECTED_REGISTERED ;
		{
			LocalCollectorRecovery resumed ;	// 前objectのwriter借用は解放済み。
			DRIVERCRATE_EXPECT( context,
							   resumed.initializeProjected( store, definition, NOW + 1000U, 200U) ==
								   (complete ? 0U : ERROR_INVALID_DATA)) ;
			// 部分保存から新しい入力を作って再送しない。
			if( complete) {
				DRIVERCRATE_EXPECT( context, resumed.terminalJobs() == 0U) ;
				const auto root =
					// 登録済みschema。
					Object::Parse( winrt::to_hstring( body( store, ROOT))) ;
				DRIVERCRATE_EXPECT( context,
								   root.GetNamedString( L"schema") == L"collector-campaign-root-v3") ;
				DRIVERCRATE_EXPECT( context, root.GetNamedValue( L"upgradeFrom").ValueType() ==
												winrt::Windows::Data::Json::JsonValueType::Null) ;
				DRIVERCRATE_EXPECT( context, root.GetNamedArray( L"generations")
													.GetObjectAt( 0U)
													.GetNamedNumber( L"storageVersion") == 3.0) ;
			}
		}
	}
}

/** @brief Active世代がないrootの孤立予約を登録前に拒否します。
 * @param[in,out] context Assertion集計。
 * @param[in] roots 自作root生成。
 * @param[in] definition 新定義。
 */
void orphanReservation( TestContext &context, const std::function<std::filesystem::path()> &roots,
					   const CollectorProjectedCampaignDefinition &definition)
{
	// 旧rootの移行と初回新rootの再開に同じ拒否を要求する。
	for( const bool projected : {false, true}) {
		LocalCollectorStateStore store ;	// Activeが空の登録窓だけを作る。
		DRIVERCRATE_EXPECT( context, store.initialize( roots(), true) == 0U) ;
		{
			LocalCollectorRecovery initial ;	// 空active rootを保存して停止する。
			const auto			   stop = []( const auto point) {
				return point == CollectorRecoveryCheckpoint::ROOT_ENROLLED ;
			} ; // 元停止点。
			DRIVERCRATE_EXPECT(
				context, (projected ? initial.initializeProjected( store, definition, NOW, 0U, stop)
									: initial.initialize( store, oldInput( definition), NOW, 0U,
														 stop)) == ERROR_OPERATION_ABORTED) ;
		}
		const auto				rootBefore = body( store, ROOT) ;	// 不正予約でschemaを変えない。
		CollectorBudgetSnapshot budget ;							// 有効envelopeへ孤立した未精算予約を追加する。
		DRIVERCRATE_EXPECT( context, parseCollectorBudgetSnapshot(
										body( store, L"current/campaign-budget-v1.json"), budget)) ;
		budget.reservations.push_back( {std::wstring( 64U, L'a'), std::wstring( 64U, L'b'), L"intel",
									   NOW / 1000U, 2097152U, 2097152U, 0U}) ;
		std::string encoded ;	// 共通予算codecで形式は有効に保つ。
		DRIVERCRATE_EXPECT( context, encodeCollectorBudgetSnapshot( budget, encoded)) ;
		save( store, L"current/campaign-budget-v1.json", encoded) ;
		LocalCollectorRecovery rejected ;	// 許可もroot移行も行わない。
		DRIVERCRATE_EXPECT( context, rejected.initializeProjected( store, definition, NOW + 1000U,
																 1U) == ERROR_INVALID_DATA) ;
		DRIVERCRATE_EXPECT( context, body( store, ROOT) == rootBefore) ;
		DRIVERCRATE_EXPECT( context, body( store, L"current/campaign-budget-v1.json") == encoded) ;
	}
}

/** @brief 空activeの旧rootだけが同じ入口で一回移行することを確認します。
 * @param[in,out] context Assertion集計。
 * @param[in] roots 自作root生成。
 * @param[in] definition 新定義。
 */
void migration( TestContext &context, const std::function<std::filesystem::path()> &roots,
			   const CollectorProjectedCampaignDefinition &definition)
{
	// 移行直前とatomic保存後の双方から再開する。
	for( const auto point : {CollectorRecoveryCheckpoint::BEFORE_ROOT_UPGRADE,
							CollectorRecoveryCheckpoint::ROOT_UPGRADED}) {
		LocalCollectorStateStore store ;	// 旧rootと同じ保護writer。
		DRIVERCRATE_EXPECT( context, store.initialize( roots(), true) == 0U) ;
		{
			LocalCollectorRecovery old ;	// 自然なroot登録窓を使い、fileの削除で空履歴を捏造しない。
			DRIVERCRATE_EXPECT(
				context, old.initialize( store, oldInput( definition), NOW, 1U, []( const auto value) {
					return value == CollectorRecoveryCheckpoint::ROOT_ENROLLED ;
				}) == ERROR_OPERATION_ABORTED) ;
		}
		const auto before	= body( store, ROOT) ;									// 原rootの実byte。
		const auto budget	= body( store, L"current/campaign-budget-v1.json") ;	// 課金不変。
		const auto controls = body( store, L"current/campaign-controls-v1.json") ;	// 待機不変。
		const auto mode =
			// Immutable不変。
			body( store, L"current/collector-campaign-mode-v1.json") ;
		{
			LocalCollectorRecovery upgrade ;	// 指定した一窓で停止。
			DRIVERCRATE_EXPECT( context, upgrade.initializeProjected( store, definition, NOW + 1000U,
																	2U, [point]( const auto value) {
																		return value == point ;
																	}) == ERROR_OPERATION_ABORTED) ;
		}
		{
			LocalCollectorRecovery resumed ;	// 同じrootで移行を完了または再読込する。
			DRIVERCRATE_EXPECT(
				context, resumed.initializeProjected( store, definition, NOW + 2000U, 3U) == 0U) ;
		}
		std::wstring priorHash ;	// 移行前の実byte hash。
		DRIVERCRATE_EXPECT( context, computeBytesSha256( before, priorHash) == 0U) ;
		const auto after = Object::Parse( winrt::to_hstring( body( store, ROOT))) ;	// 新登録後のroot。
		DRIVERCRATE_EXPECT( context, after.GetNamedString( L"upgradeFrom") == priorHash) ;
		DRIVERCRATE_EXPECT( context, body( store, L"current/campaign-budget-v1.json") == budget) ;
		DRIVERCRATE_EXPECT( context, body( store, L"current/campaign-controls-v1.json") == controls) ;
		DRIVERCRATE_EXPECT( context,
						   body( store, L"current/collector-campaign-mode-v1.json") == mode) ;
	}
}

/** @brief 入力差・日跨ぎで元分母を維持し、旧状態へ戻さないことを確認します。
 * @param[in,out] context Assertion集計。
 * @param[in] roots 自作root生成。
 * @param[in] definition 新定義。
 */
void changedInput( TestContext &context, const std::function<std::filesystem::path()> &roots,
				  const CollectorProjectedCampaignDefinition &definition)
{
	// 同値registry、artifact差、公開対象差、日跨ぎを独立に確認する。
	for( unsigned change = 0U; change < 4U; ++change) {
		LocalCollectorStateStore store ;	// 元世代の保存像。
		DRIVERCRATE_EXPECT( context, store.initialize( roots(), true) == 0U) ;
		std::wstring key ;	// 新世代を作らず元世代を保持する。
		{
			LocalCollectorRecovery initial ;	// 元入力の新世代登録。
			DRIVERCRATE_EXPECT( context,
							   initial.initializeProjected( store, definition, NOW, 0U) == 0U) ;
			key = initial.generationKey() ;
		}
		auto		  incoming = definition ;	// 変更する現在の公開入力。
		std::uint64_t later	   = NOW + 1000U ;	// 同日を既定とする。
		// 各差分を新しいscopeとして再構築する。
		switch( change) {
			// Registry順序だけの変更は同値にする。
			case 0:
				std::reverse( incoming.sources.begin(), incoming.sources.end()) ;
				break ;

			// 同じmanifestのartifact差を区別する。
			case 1:
				incoming.artifactSha256 = std::wstring( 64U, L'b') ;
				break ;

			// 後半対象だけの変更も旧分母へ反映する。
			case 2: {
				auto manifest = Object::Parse(
					// 最後の共有対象だけを変更する。
					winrt::to_hstring( incoming.manifestBytes)) ;
				manifest.GetNamedArray( L"targets")
					.GetObjectAt( 25U)
					.Insert( L"purpose", Value::CreateStringValue( L"changed")) ;
				incoming.manifestBytes = winrt::to_string( manifest.Stringify()) ;
				break ;
			}
			// 日跨ぎで旧世代へ予約を追加しない。
			case 3:
				later += 86400000U ;
				break ;
		}

		{
			LocalCollectorRecovery resumed ;	// 未予約を対象差で再送せず終端へ閉じる。
			DRIVERCRATE_EXPECT( context,
							   resumed.initializeProjected( store, incoming, later, 1000U) == 0U) ;
			DRIVERCRATE_EXPECT( context, resumed.generationKey() == key &&
											resumed.terminalJobs() == (change == 0U ? 0U : 2U)) ;
			const std::wstring expected = change == 1U	 ? L"ARTIFACT_CHANGED"
										  : change == 2U ? L"INPUT_CHANGED"
										  : change == 3U ? L"DAY_CLOSED"
														 : L"" ;	// 元理由を区別する。
			DRIVERCRATE_EXPECT( context, resumed.reason() == expected) ;
		}
		{
			LocalCollectorRecovery again ;	// 旧定義へ戻してもDEFERREDをPENDINGへ戻さない。
			DRIVERCRATE_EXPECT(
				context, again.initializeProjected( store, definition, later + 1000U, 2000U) == 0U) ;
			DRIVERCRATE_EXPECT( context, again.generationKey() == key &&
											again.terminalJobs() == (change == 0U ? 0U : 2U)) ;
		}
	}
}

/** @brief 旧予約・応答commitを回収してから移行待機することを確認します。
 * @param[in,out] context Assertion集計。
 * @param[in] roots 自作root生成。
 * @param[in] definition 新定義。
 * @param[in] controlled 旧v3応答の回収を確認する場合true。
 */
void legacyRecovery( TestContext &context, const std::function<std::filesystem::path()> &roots,
					const CollectorProjectedCampaignDefinition &definition, const bool controlled)
{
	// 応答前と保存応答の全commit窓を元codecで回収する。
	for( const auto point :
		{CollectorRecoveryCheckpoint::RESERVED, CollectorRecoveryCheckpoint::STARTED,
		 CollectorRecoveryCheckpoint::RUNNING, CollectorRecoveryCheckpoint::RESPONSE,
		 CollectorRecoveryCheckpoint::EFFECTS, CollectorRecoveryCheckpoint::REGISTERED,
		 CollectorRecoveryCheckpoint::APPLIED, CollectorRecoveryCheckpoint::COMPLETED}) {
		LocalCollectorStateStore store ;	// 実通信のない旧保存物。
		DRIVERCRATE_EXPECT( context, store.initialize( roots(), true) == 0U) ;
		std::wstring oldKey ;	// 移行を許さない旧active。
		{
			LocalCollectorRecovery old ;	// 旧v2入口と予約。
			DRIVERCRATE_EXPECT( context, old.initialize( store, oldInput( definition), NOW, 100U,
													   [point]( const auto value) {
														   return value == point ;
													   }) == 0U) ;
			oldKey = old.generationKey() ;
			CollectorRecoveryDispatch dispatch ;	// 実HTTPへ渡さない旧予約。
			const auto				  reserved = controlled
													 ? old.reserveControlled( NOW, 101U, dispatch)
													 : old.reserve( NOW, 101U, dispatch) ;	// 指定保存窓の結果。
			const bool beforeResponse		   = point == CollectorRecoveryCheckpoint::RESERVED ||
										point == CollectorRecoveryCheckpoint::STARTED ||
										// 応答なし。
										point == CollectorRecoveryCheckpoint::RUNNING ;
			DRIVERCRATE_EXPECT( context,
							   reserved == (beforeResponse ? ERROR_OPERATION_ABORTED : 0U)) ;
			// 応答後窓では有限失敗観測を保存する。
			if( !beforeResponse) {
				CollectorRecoveryResponse response ;	// 公式取得を伴わない型付き失敗。
				response.finishedUtcMillis = NOW + 1000U ;
				response.acceptedUtcMillis = NOW + 1000U ;
				response.bytesKnown		   = true ;
				response.receivedBytes	   = 3U ;
				response.sentRequests	   = 1U ;
				response.status			   = 500U ;
				response.error			   = 500U ;
				response.errorDomain	   = L"HTTP" ;
				// 旧v3のI/O付き応答も新入口から元codecへ回収する。
				if( controlled) {
					CollectorIoSnapshot observation ;	// 完了した有限fake I/O。
					observation.cause			  = CollectorIoCause::COMPLETE ;
					observation.stage			  = CollectorIoStage::COMPLETE ;
					observation.error.stage		  = CollectorIoStage::COMPLETE ;
					observation.sends			  = 1U ;
					observation.lowerBytes		  = 3U ;
					observation.deadlineUtcMillis = dispatch.deadlineUtcMillis ;
					observation.elapsedMillis	  = 1000U ;
					observation.headerUtcMillis	  = NOW ;
					observation.finishedUtcMillis = NOW + 1000U ;
					observation.sealed			  = true ;
					response.state				  = CollectorCampaignJobState::HELD ;
					response.status				  = 200U ;
					response.error				  = 0U ;
					response.errorDomain		  = L"NONE" ;
					DRIVERCRATE_EXPECT(
						context, old.acceptControlled( dispatch, response, observation, NOW + 1000U,
													  1101U) == ERROR_OPERATION_ABORTED) ;
				} else {
					DRIVERCRATE_EXPECT( context, old.accept( dispatch.jobIndex, response, NOW + 1000U,
														   1101U) == ERROR_OPERATION_ABORTED) ;
				}
			}
		}
		const auto oldBytes =
			// 不変入力。
			body( store, L"runs/campaign-input-v2-" + oldKey + L".json") ;
		{
			LocalCollectorRecovery next ;	// 新入口でも旧回収が先行する。
			DRIVERCRATE_EXPECT( context, next.initializeProjected( store, definition, NOW + 2000U,
																 2000U) == ERROR_RETRY) ;
			DRIVERCRATE_EXPECT( context, next.reason() == L"LEGACY_GENERATION_PENDING" &&
											next.generationKey() == oldKey) ;
		}
		CollectorBudgetSnapshot budget ;	// 回収後の元一予約。
		DRIVERCRATE_EXPECT( context, parseCollectorBudgetSnapshot(
										body( store, L"current/campaign-budget-v1.json"), budget)) ;
		DRIVERCRATE_EXPECT( context,
						   budget.reservations.size() == 1U && budget.reservations[0].phase != 0U) ;
		const auto root = Object::Parse( winrt::to_hstring( body( store, ROOT))) ;	// 旧schemaのまま。
		DRIVERCRATE_EXPECT( context,
						   root.GetNamedString( L"schema") == L"collector-campaign-root-v2" &&
							   root.GetNamedString( L"activeGeneration") == oldKey &&
							   !root.HasKey( L"upgradeFrom")) ;
		DRIVERCRATE_EXPECT( context,
						   body( store, L"runs/campaign-input-v2-" + oldKey + L".json") == oldBytes) ;
		const auto charged =
			// 再読込で二重精算しない。
			body( store, L"current/campaign-budget-v1.json") ;
		{
			LocalCollectorRecovery again ;	// 待機の再開を同じrootで確認する。
			DRIVERCRATE_EXPECT( context, again.initializeProjected( store, definition, NOW + 3000U,
																  3000U) == ERROR_RETRY) ;
		}
		DRIVERCRATE_EXPECT( context, body( store, L"current/campaign-budget-v1.json") == charged) ;
	}
}

/** @brief v3 stateや旧応答の混在を登録時点で拒否します。
 * @param[in,out] context Assertion集計。
 * @param[in] roots 自作root生成。
 * @param[in] definition 新定義。
 */
void corruption( TestContext &context, const std::function<std::filesystem::path()> &roots,
				const CollectorProjectedCampaignDefinition &definition)
{
	// 各改変は独立rootへ一度だけ注入する。
	for( unsigned mutation = 0U; mutation < 11U; ++mutation) {
		LocalCollectorStateStore store ;	// 元成功登録。
		DRIVERCRATE_EXPECT( context, store.initialize( roots(), true) == 0U) ;
		std::wstring key ;	// 元新世代の固定保存名。
		{
			LocalCollectorRecovery initial ;	// 元入力の新世代登録。
			DRIVERCRATE_EXPECT( context,
							   initial.initializeProjected( store, definition, NOW, 0U) == 0U) ;
			key = initial.generationKey() ;
		}
		const auto stateName  = L"current/campaign-state-v3-" + key + L".json" ;	// 元state。
		const auto markerName = L"runs/campaign-marker-v3-" + key + L".json" ;		// 元marker。
		const auto name		  = mutation < 4U	? std::wstring( ROOT)
								: mutation < 7U ? stateName
												: markerName ;								// 改変先。
		auto	   object	  = Object::Parse( winrt::to_hstring( body( store, name))) ;	// 元本文。
		// 世代の取り違え、未来応答、未登録fileをそれぞれ検査する。
		switch( mutation) {
			// 新世代を旧保存版として解釈しない。
			case 0:
				object.GetNamedArray( L"generations")
					.GetObjectAt( 0U)
					.Insert( L"storageVersion", Value::CreateNumberValue( 2.0)) ;
				break ;

			// 未定義の保存版を拒否する。
			case 1:
				object.GetNamedArray( L"generations")
					.GetObjectAt( 0U)
					.Insert( L"storageVersion", Value::CreateNumberValue( 4.0)) ;
				break ;

			// 移行元hashの形式を検査する。
			case 2:
				object.Insert( L"upgradeFrom", Value::CreateStringValue( L"bad")) ;
				break ;

			// Root schemaとfieldの不一致を拒否する。
			case 3:
				object.Insert( L"schema", Value::CreateStringValue( L"collector-campaign-root-v2")) ;
				break ;

			// 未発行RUNNINGを受理しない。
			case 4:
				object.GetNamedArray( L"jobs").GetObjectAt( 0U).Insert(
					L"state", Value::CreateStringValue( L"RUNNING")) ;
				break ;

			// 旧OBSERVEDを新成功へ転用しない。
			case 5:
				object.GetNamedArray( L"jobs").GetObjectAt( 0U).Insert(
					L"state", Value::CreateStringValue( L"OBSERVED")) ;
				break ;

			// State保存名とschemaの不一致を拒否する。
			case 6:
				object.Insert( L"schema", Value::CreateStringValue( L"collector-campaign-state-v2")) ;
				break ;

			// 必須応答versionを下げさせない。
			case 7:
				object.Insert( L"responseVersion", Value::CreateNumberValue( 3.0)) ;
				break ;

			// Markerの別profileを拒否する。
			case 8:
				object.Insert( L"profile", Value::CreateStringValue( L"OTHER")) ;
				break ;

			// 新世代へ旧応答fileを混入させない。
			case 9:
				save( store, L"runs/campaign-response-v3-" + key + L".json", "{}") ;
				break ;

			// 同じGの旧state file併存を拒否する。
			case 10:
				save( store, L"current/campaign-state-v2-" + key + L".json", body( store, stateName)) ;
				break ;
		}

		save( store, name, winrt::to_string( object.Stringify())) ;
		LocalCollectorRecovery rejected ;	// 全検査より後に書込みへ進まない。
		DRIVERCRATE_EXPECT( context, rejected.initializeProjected( store, definition, NOW + 1000U,
																 1U) == ERROR_INVALID_DATA) ;
	}
}

/** @brief 新登録に旧caller・旧予約・旧acceptを通せないことを確認します。
 * @param[in,out] context Assertion集計。
 * @param[in] roots 自作root生成。
 * @param[in] definition 新定義。
 */
void oldEntrypoints( TestContext &context, const std::function<std::filesystem::path()> &roots,
					const CollectorProjectedCampaignDefinition &definition)
{
	// 失敗をstickyにするobjectごとに入口を一つだけ試す。
	for( unsigned mode = 0U; mode < 6U; ++mode) {
		LocalCollectorStateStore store ;	// 同caseの保存before像。
		DRIVERCRATE_EXPECT( context, store.initialize( roots(), true) == 0U) ;
		{
			LocalCollectorRecovery initial ;	// 元入力の新世代登録。
			DRIVERCRATE_EXPECT( context,
							   initial.initializeProjected( store, definition, NOW, 100U) == 0U) ;
		}
		const auto budget =
			// 予約発行0を確認する。
			body( store, L"current/campaign-budget-v1.json") ;
		LocalCollectorRecovery next ;	// 旧操作の拒否を検査する。
		// 旧initialize自体もv3 activeを実行可能にしない。
		if( mode == 0U) {
			DRIVERCRATE_EXPECT( context, next.initialize( store, oldInput( definition), NOW, 100U) ==
											ERROR_INVALID_DATA) ;
		} else {
			DRIVERCRATE_EXPECT( context,
							   next.initializeProjected( store, definition, NOW, 100U) == 0U) ;
			CollectorRecoveryDispatch  dispatch ;	// 空の未発行予約。
			CollectorRecoveryReadiness ready ;		// READYは生成されない。
			// 旧入口ごとの拒否を独立に確認する。
			switch( mode) {
				// 旧基本予約を拒否する。
				case 1:
					DRIVERCRATE_EXPECT( context, next.reserve( NOW, 100U, dispatch) ==
													ERROR_INVALID_PARAMETER) ;
					break ;

				// 旧制御予約も拒否する。
				case 2:
					DRIVERCRATE_EXPECT( context, next.reserveControlled( NOW, 100U, dispatch) ==
													ERROR_INVALID_PARAMETER) ;
					break ;

				// 旧応答の保存を拒否する。
				case 3:
					DRIVERCRATE_EXPECT( context,
									   next.accept( 0U, {}, NOW, 100U) == ERROR_INVALID_PARAMETER) ;
					break ;

				// READY候補を返さない。
				case 4:
					DRIVERCRATE_EXPECT( context,
									   next.readiness( NOW, 100U, ready) == ERROR_INVALID_PARAMETER) ;
					break ;

				// 旧I/O付き応答も拒否する。
				case 5:
					DRIVERCRATE_EXPECT( context,
									   next.acceptControlled( dispatch, {}, {}, NOW, 100U) ==
										   ERROR_INVALID_PARAMETER) ;
					break ;
			}
		}

		DRIVERCRATE_EXPECT( context, body( store, L"current/campaign-budget-v1.json") == budget) ;
	}
}
/** @brief 専用保存枠の三上限をちょうど境界と一件超過で確認します。
 * @param[in,out] context Assertion集計。
 */
void projectedCapacity( TestContext &context)
{
	// 空・小規模・最大job集合を独立に検査する。
	for( const auto count : {0U, 1U, 300U}) {
		const auto extra = 7ULL * count * 2U * 1024U * 1024U + 3ULL * count * 64U * 1024U +
						   50ULL * 1024U * 1024U ;	// ADRの式。
		CollectorStoreUsage usage{4096U - count - 13U, 4096U - 9U * count - 13U,
								  5ULL * 1024U * 1024U * 1024U - extra} ;	// 全上限ちょうど。
		DRIVERCRATE_EXPECT( context,
						   checkCollectorProjectedRecoveryCapacity( usage, count, count) == 0U) ;
		++usage.currentEntries ;
		DRIVERCRATE_EXPECT( context, checkCollectorProjectedRecoveryCapacity( usage, count, count) ==
										ERROR_TOO_MANY_NAMES) ;
		--usage.currentEntries ;
		++usage.runEntries ;
		DRIVERCRATE_EXPECT( context, checkCollectorProjectedRecoveryCapacity( usage, count, count) ==
										ERROR_TOO_MANY_NAMES) ;
		--usage.runEntries ;
		++usage.bytes ;
		DRIVERCRATE_EXPECT( context, checkCollectorProjectedRecoveryCapacity( usage, count, count) ==
										ERROR_TOO_MANY_NAMES) ;
	}

	DRIVERCRATE_EXPECT( context, checkCollectorProjectedRecoveryCapacity( {}, 301U, 300U) ==
									ERROR_INVALID_PARAMETER) ;
	DRIVERCRATE_EXPECT( context, checkCollectorProjectedRecoveryCapacity( {}, 1U, 2U) ==
									ERROR_INVALID_PARAMETER) ;
}

/** @brief 全保存窓で中断した元予約を一度だけ回収します。
 * @param[in,out] context Assertion集計。
 * @param[in] roots 自作root生成。
 * @param[in] definition 元入力。
 */
void projectedWindows( TestContext &context, const std::function<std::filesystem::path()> &roots,
					  const CollectorProjectedCampaignDefinition &definition)
{
	// 二source同時予約、全roleの前像だけの窓も含める。
	for( unsigned window = 0U; window < 20U; ++window) {
		LocalCollectorStateStore store ;	// 実保護fileによるfixture。
		DRIVERCRATE_EXPECT( context, store.initialize( roots(), true) == 0U) ;
		std::wstring generation ;	// 再起動しても元Gを保持。
		{
			LocalCollectorRecovery initial ;	// HTTP未実行の予約だけ。
			DRIVERCRATE_EXPECT(
				context,
				initial.initializeProjected(
					store, definition, NOW, 100U, [window]( const auto point) {
						return (window == 1U && point == CollectorRecoveryCheckpoint::RESERVED) ||
							   (window == 2U && point == CollectorRecoveryCheckpoint::STARTED) ||
							   (window == 3U && point == CollectorRecoveryCheckpoint::RUNNING) ;
					}) == 0U) ;
			generation = initial.generationKey() ;
			CollectorHttpPermitPool pool(
				[] { return CollectorHttpClockSample{NOW, 100U} ; }) ;				// 固定元時計。
			CollectorHttpPermit permit ;											// 永続保存後だけ発行される。
			const auto			error = pool.reserveProjected( initial, permit) ;	// 一回予約。
			const bool aborted = window >= 1U && window <= 3U ;						// 保存途中にpermitを返さない。
			DRIVERCRATE_EXPECT( context, error == (aborted ? ERROR_OPERATION_ABORTED : 0U)) ;
			DRIVERCRATE_EXPECT( context, permit.present() != aborted &&
											pool.occupied() == (aborted ? 0U : 1U)) ;
			// 成功発行は全scopeと元二時計へ結合する。
			if( !aborted && permit.binding()) {
				const auto dispatch = *permit.binding() ;	// 元許可の所有copy。
				DRIVERCRATE_EXPECT( context,
								   dispatch.mode == CollectorRecoveryDispatch::Mode::PROJECTED &&
									   dispatch.anchorUtcMillis == NOW &&
									   dispatch.deadlineUtcMillis == NOW + 120000U) ;
				const auto						   state = Object::Parse( winrt::to_hstring( body(
					store,
					L"current/campaign-state-v3-" + generation + L".json"))) ;	// 永続intent確認。
				CollectorProjectedCampaignIdentity identity ;					// 元入力。
				DRIVERCRATE_EXPECT( context, makeCollectorProjectedCampaignIdentity(
												definition, L"20260928", identity)) ;
				CollectorRecoveryDispatch decoded ;	// 復号は許可再発行しない。
				DRIVERCRATE_EXPECT(
					context, parseCollectorProjectedStart(
								 identity,
								 winrt::to_string(
									 state.GetNamedArray( L"jobs")
										 .GetObjectAt( static_cast<std::uint32_t>( dispatch.jobIndex))
										 .GetNamedObject( L"intent")
										 .Stringify()),
								 decoded)) ;
				DRIVERCRATE_EXPECT( context, sameCollectorRecoveryDispatch( dispatch, decoded)) ;
				// 一つのpermitは同じbindingでも二度claimできない。
				if( window == 0U) {
					DRIVERCRATE_EXPECT( context, permit.claim( &pool, dispatch) != nullptr) ;
					DRIVERCRATE_EXPECT( context, permit.claim( &pool, dispatch) == nullptr) ;
				}

				// 別group二件も最大枠と永続台帳の下で同時予約できる。
				if( window == 16U) {
					CollectorHttpPermit second ;	// 元jobとは異なるsource。
					DRIVERCRATE_EXPECT( context, pool.reserveProjected( initial, second) == 0U &&
													pool.occupied() == 2U) ;
				}
			}
		}
		// 回復自身を応答・各準備effect・commit・四role各反映後で止める。
		if( window >= 4U && window != 16U) {
			unsigned			   beforeEffects{} ;	// 前像だけの保存順1～3。
			unsigned			   effects{} ;			// 準備順1～4。
			unsigned			   applied{} ;			// 反映順1～4。
			LocalCollectorRecovery partial ;			// 初回の中断観測時刻を固定する。
			DRIVERCRATE_EXPECT(
				context,
				partial.initializeProjected(
					store, definition, NOW + 1000U, 0U, [&]( const auto point) {
						// 前像だけが存在する準備途中も停止窓にする。
						if( point == CollectorRecoveryCheckpoint::PROJECTED_BEFORE_EFFECT) {
							++beforeEffects ;
						}

						// 四つの準備file群のそれぞれを停止窓にする。
						if( point == CollectorRecoveryCheckpoint::PROJECTED_EFFECT) {
							++effects ;
						}

						// 各共有role反映後に停止してprefixを確認する。
						if( point == CollectorRecoveryCheckpoint::APPLIED) {
							++applied ;
						}

						return (window == 4U && point == CollectorRecoveryCheckpoint::RESPONSE) ||
							   (window >= 5U && window <= 8U &&
								point == CollectorRecoveryCheckpoint::PROJECTED_EFFECT &&
								effects == window - 4U) ||
							   (window == 9U && point == CollectorRecoveryCheckpoint::EFFECTS) ||
							   (window == 10U &&
								point == CollectorRecoveryCheckpoint::REGISTERED) ||
							   (window >= 11U && window <= 14U &&
								point == CollectorRecoveryCheckpoint::APPLIED &&
								applied == window - 10U) ||
							   (window == 15U && point == CollectorRecoveryCheckpoint::COMPLETED) ||
							   (window >= 17U &&
								point == CollectorRecoveryCheckpoint::PROJECTED_BEFORE_EFFECT &&
								beforeEffects == window - 16U) ;
					}) == ERROR_OPERATION_ABORTED) ;
		}

		{
			LocalCollectorRecovery recovered ;	// 新process時計は元intentの代わりにしない。
			DRIVERCRATE_EXPECT(
				context, recovered.initializeProjected( store, definition, NOW + 2000U, 0U) == 0U) ;
			DRIVERCRATE_EXPECT( context, recovered.generationKey() == generation &&
											recovered.terminalJobs() == (window == 16U ? 2U : 1U)) ;
		}
		const auto budgetBody  = body( store, L"current/campaign-budget-v1.json") ;		// 二重精算監視。
		const auto controlBody = body( store, L"current/campaign-controls-v1.json") ;	// 元待機保持。
		CollectorBudgetSnapshot budget ;												// 最大課金と閉鎖phase。
		DRIVERCRATE_EXPECT( context, parseCollectorBudgetSnapshot( budgetBody, budget)) ;
		DRIVERCRATE_EXPECT( context, budget.reservations.size() == (window == 16U ? 2U : 1U)) ;
		// 未知bytesを0として予算へ返金しない。
		for( const auto &reservation : budget.reservations) {
			DRIVERCRATE_EXPECT( context, reservation.phase == 2U &&
											reservation.charged == reservation.maximum) ;
		}

		const auto root =
			// 全role反映後にだけ登録。
			Object::Parse( winrt::to_hstring( body( store, ROOT))) ;
		DRIVERCRATE_EXPECT( context, root.GetNamedValue( L"commit").ValueType() ==
											winrt::Windows::Data::Json::JsonValueType::Null &&
										root.GetNamedArray( L"cacheInventory").Size() ==
											budget.reservations.size()) ;
		const auto state = Object::Parse( winrt::to_hstring(
			body( store,
				 L"current/campaign-state-v3-" + generation + L".json"))) ;	// 保存結果。
		// 全中断応答の欠測と初回回復時刻を検査する。
		for( const auto &entry : state.GetNamedArray( L"jobs")) {
			const auto row = entry.GetObject() ;	// 全共有job。
			// 未予約行は成功・失敗いずれにも数えない。
			if( row.GetNamedString( L"state") != L"INTERRUPTED") {
				continue ;
			}

			const auto response = Object::Parse( winrt::to_hstring( body(
				store,
				L"runs/campaign-response-v2-" + std::wstring( row.GetNamedString( L"operation")) +
					L".json"))) ;	// 元欠測観測。
			DRIVERCRATE_EXPECT( context, !response.HasKey( L"io") &&
											response.GetNamedValue( L"bytes").ValueType() ==
												winrt::Windows::Data::Json::JsonValueType::Null &&
											response.GetNamedValue( L"sends").ValueType() ==
												winrt::Windows::Data::Json::JsonValueType::Null) ;
			DRIVERCRATE_EXPECT(
				context,
				response.GetNamedNumber( L"finished") ==
					static_cast<double>( NOW + (window >= 4U && window != 16U ? 1000U : 2000U))) ;
		}

		{
			LocalCollectorRecovery again ;	// 同じ中断の再回復は保存値を更新しない。
			DRIVERCRATE_EXPECT( context,
							   again.initializeProjected( store, definition, NOW + 3000U, 0U) == 0U) ;
			// 全job中断済みなら同世代から再送予約を発行しない。
			if( window == 16U) {
				CollectorHttpPermitPool pool(
					[] { return CollectorHttpClockSample{NOW + 3000U, 0U} ; }) ;	// 再開時計。
				CollectorHttpPermit permit ;										// 新規送信権は出ない。
				DRIVERCRATE_EXPECT( context, pool.reserveProjected( again, permit) == ERROR_RETRY &&
												!permit.present() && pool.occupied() == 0U) ;
			}
		}
		DRIVERCRATE_EXPECT( context,
						   body( store, L"current/campaign-budget-v1.json") == budgetBody &&
							   body( store, L"current/campaign-controls-v1.json") == controlBody) ;
	}
}

/** @brief 起動済み新世代の改変を書込み前に拒否します。
 * @param[in,out] context Assertion集計。
 * @param[in] roots 自作root生成。
 * @param[in] definition 元入力。
 */
void projectedTampering( TestContext &context, const std::function<std::filesystem::path()> &roots,
						const CollectorProjectedCampaignDefinition &definition)
{
	// RUNNINGのintent改変とactive commitの改変を別rootで評価する。
	for( unsigned mutation = 0U; mutation < 14U; ++mutation) {
		LocalCollectorStateStore store ;	// 改変専用自作root。
		DRIVERCRATE_EXPECT( context, store.initialize( roots(), true) == 0U) ;
		std::wstring key ;	// 新generation。
		{
			LocalCollectorRecovery initial ;	// 有効な元予約。
			DRIVERCRATE_EXPECT( context,
							   initial.initializeProjected( store, definition, NOW, 100U) == 0U) ;
			key = initial.generationKey() ;
			CollectorHttpPermitPool pool(
				[] { return CollectorHttpClockSample{NOW, 100U} ; }) ;	// 固定時計。
			CollectorHttpPermit permit ;								// 元許可。
			DRIVERCRATE_EXPECT( context, pool.reserveProjected( initial, permit) == 0U) ;
		}
		const auto stateName = L"current/campaign-state-v3-" + key + L".json" ;	// 固定state名。
		// 後半はactive四role commitができた時点で止める。
		if( mutation >= 4U) {
			LocalCollectorRecovery partial ;	// 全effect準備後、共有file反映前。
			DRIVERCRATE_EXPECT( context,
							   partial.initializeProjected(
								   store, definition, NOW + 1000U, 0U, []( const auto point) {
									   return point == CollectorRecoveryCheckpoint::REGISTERED ;
								   }) == ERROR_OPERATION_ABORTED) ;
		}

		auto root = Object::Parse( winrt::to_hstring( body( store, ROOT))) ;	// 改変対象の元root。
		// 前半は元開始intentの欠損・入力不一致・期限改変を注入する。
		if( mutation < 4U) {
			const auto state =
				// 元RUNNING。
				Object::Parse( winrt::to_hstring( body( store, stateName))) ;
			const auto row = state.GetNamedArray( L"jobs").GetObjectAt( 0U) ;	// 予約済みの先頭。
			// RUNNINGでnullのintentを許さない。
			if( mutation == 0U) {
				row.Insert( L"intent", Value::CreateNullValue()) ;
			}

			// 元scopeのhashを他の正当hashにしても拒否する。
			if( mutation == 1U) {
				row.GetNamedObject( L"intent").Insert( L"scope", Value::CreateStringValue( key)) ;
			}

			// 二時計残量が一致しても元予算期限とは一致しない。
			if( mutation == 2U) {
				const auto intent = row.GetNamedObject( L"intent") ;	// 単独codecを通る期限差。
				intent.Insert( L"deadlineUtc",
							  Value::CreateNumberValue( static_cast<double>( NOW + 119000U))) ;
				intent.Insert( L"deadlineSteady", Value::CreateNumberValue( 119100.0)) ;
			}

			// 旧初期root互換を稼働済みrootへ適用しない。
			if( mutation == 3U) {
				root.Remove( L"cacheInventory") ;
			}

			save( store, stateName, winrt::to_string( state.Stringify())) ;
		} else {
			const auto commit = root.GetNamedObject( L"commit") ;							// 登録された四role。
			const auto op	  = std::wstring( commit.GetNamedString( L"operation")) ;		// 元操作key。
			const auto cacheEffect = L"runs/campaign-effect-v2-" + op + L"-cache.json" ;	// 元後像。
			const auto cache =
				// 固定無効像。
				Object::Parse( winrt::to_hstring( body( store, cacheEffect))) ;
			const auto cacheName = L"current/campaign-cache-v1-" +
								   std::wstring( cache.GetNamedString( L"request")) +
								   L".json" ;	// 自作fixture名。
			// 個々の反例を一度だけ注入する。
			switch( mutation) {
				// CONTROLより先にCACHEを反映した不連続prefix。
				case 4:
					save( store, cacheName, body( store, cacheEffect)) ;
					break ;

				// JOBより先にBUDGETを精算した不連続prefix。
				case 5:
					save( store, L"current/campaign-budget-v1.json",
						 body( store, L"runs/campaign-effect-v2-" + op + L"-budget.json")) ;
					break ;

				// 正しいhashでも任意のCACHE patchは元応答から導出できない。
				case 6: {
					cache.Insert( L"reusable", Value::CreateBooleanValue( true)) ;
					const auto	 changed = winrt::to_string( cache.Stringify()) ;	// 改変本文。
					std::wstring hash ;												// 改変後hashも整合させる。
					DRIVERCRATE_EXPECT( context, computeBytesSha256( changed, hash) == 0U) ;
					save( store, cacheEffect, changed) ;
					commit.GetNamedArray( L"effects")
						.GetObjectAt( 1U)
						.Insert( L"after", Value::CreateStringValue( hash)) ;
					break ;
				}
				// 初回CACHEのbefore fileは存在してはならない。
				case 7:
					save( store, L"runs/campaign-effect-v2-" + op + L"-before-cache.json",
						 body( store, cacheEffect)) ;
					break ;

				// 旧三role kindへの格下げを拒否する。
				case 8:
					commit.Insert( L"kind", Value::CreateStringValue( L"RESPONSE")) ;
					break ;

				// 旧effect名を新世代へ混入させない。
				case 9:
					save( store, L"runs/campaign-effect-v1-" + op + L"-cache.json",
						 body( store, cacheEffect)) ;
					break ;

				// 同operationの応答v3を並存させない。
				case 10:
					save( store, L"runs/campaign-response-v3-" + op + L".json",
						 body( store, L"runs/campaign-response-v2-" + op + L".json")) ;
					break ;

				// 稼働後のcacheInventory欠損を補完しない。
				case 11:
					root.Remove( L"cacheInventory") ;
					break ;

				// 登録effectの本文を破損させる。
				case 12:
					save( store, cacheEffect, "{}") ;
					break ;

				// 固定roleの順序を変更しない。
				case 13:
					commit.GetNamedArray( L"effects")
						.GetObjectAt( 0U)
						.Insert( L"role", Value::CreateStringValue( L"JOB")) ;
					break ;
			}
		}

		save( store, ROOT, winrt::to_string( root.Stringify())) ;
		const auto budget = body( store, L"current/campaign-budget-v1.json") ;		// 拒否時の非変更確認。
		const auto controls = body( store, L"current/campaign-controls-v1.json") ;	// 同上。
		LocalCollectorRecovery next ;												// 改変後の再開は拒否。
		DRIVERCRATE_EXPECT( context, next.initializeProjected( store, definition, NOW + 2000U, 0U) ==
										ERROR_INVALID_DATA) ;
		DRIVERCRATE_EXPECT( context,
						   body( store, L"current/campaign-budget-v1.json") == budget &&
							   body( store, L"current/campaign-controls-v1.json") == controls) ;
	}
}

/** @brief 初期v3互換・専用permitの旧mode拒否を検査します。
 * @param[in,out] context Assertion集計。
 * @param[in] roots 自作root生成。
 * @param[in] definition 元入力。
 */
void projectedPermitBoundary( TestContext								  &context,
							 const std::function<std::filesystem::path()> &roots,
							 const CollectorProjectedCampaignDefinition	  &definition)
{
	// 初期root移行、旧rootへの新予約、予約済み新rootの旧acceptを分ける。
	for( unsigned mode = 0U; mode < 5U; ++mode) {
		LocalCollectorStateStore store ;	// 専用fixture。
		DRIVERCRATE_EXPECT( context, store.initialize( roots(), true) == 0U) ;
		// b2bの初期root v3を正確に再現する。
		if( mode == 0U) {
			{
				LocalCollectorRecovery initial ;	// 未予約の登録のみ。
				DRIVERCRATE_EXPECT( context,
								   initial.initializeProjected( store, definition, NOW, 100U) == 0U) ;
			}
			const auto root = Object::Parse( winrt::to_hstring( body( store, ROOT))) ;	// 旧初期形。
			root.Remove( L"cacheInventory") ;
			save( store, ROOT, winrt::to_string( root.Stringify())) ;
		}

		LocalCollectorRecovery recovery ;	// 単一writer。
		DRIVERCRATE_EXPECT(
			context,
			(mode == 1U ? recovery.initialize( store, oldInput( definition), NOW, 100U)
						: recovery.initializeProjected( store, definition, NOW, 100U)) == 0U) ;
		CollectorHttpPermitPool pool(
			[] { return CollectorHttpClockSample{NOW, 100U} ; }) ;				// 元clock。
		CollectorHttpPermit permit ;											// 新入口だけから発行。
		const auto before = body( store, L"current/campaign-budget-v1.json") ;	// 旧mode拒否前の予算。
		const auto error  = pool.reserveProjected( recovery, permit) ;			// 型境界を確認。
		DRIVERCRATE_EXPECT( context, error == (mode == 1U ? ERROR_INVALID_PARAMETER : 0U)) ;
		// 旧rootでは保存・発行とも行わない。
		if( mode == 1U) {
			DRIVERCRATE_EXPECT( context,
							   !permit.present() &&
								   body( store, L"current/campaign-budget-v1.json") == before) ;
			continue ;
		}

		const auto budget = body( store, L"current/campaign-budget-v1.json") ;	// 元予約は閉じない。
		// 元新dispatchを渡しても旧acceptには昇格しない。
		if( mode == 2U) {
			DRIVERCRATE_EXPECT( context, recovery.accept( permit.binding()->jobIndex, {}, NOW,
														100U) == ERROR_INVALID_PARAMETER) ;
		}

		// I/O付き旧入口も同様に拒否する。
		if( mode == 3U) {
			DRIVERCRATE_EXPECT( context, recovery.acceptControlled( *permit.binding(), {}, {}, NOW,
																  100U) == ERROR_INVALID_PARAMETER) ;
		}

		// 既存permit上書きと停止後の発行を拒否する。
		if( mode == 4U) {
			DRIVERCRATE_EXPECT( context,
							   pool.reserveProjected( recovery, permit) == ERROR_INVALID_PARAMETER) ;
			pool.requestStop() ;
			CollectorHttpPermit empty ;	// 停止後の新発行先。
			DRIVERCRATE_EXPECT( context,
							   pool.reserveProjected( recovery, empty) == ERROR_OPERATION_ABORTED &&
								   !empty.present()) ;
		}

		DRIVERCRATE_EXPECT( context, body( store, L"current/campaign-budget-v1.json") == budget) ;
	}
}
} // namespace

/** @see local_collector_projected_recovery_tests.h */
void runCollectorProjectedRecoveryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &inputFactory)
{
	const auto definition = inputFactory() ;	// 全fixtureで同じ元入力。
	codecs( context, definition) ;
	registration( context, rootFactory, definition) ;
	orphanReservation( context, rootFactory, definition) ;
	migration( context, rootFactory, definition) ;
	changedInput( context, rootFactory, definition) ;
	legacyRecovery( context, rootFactory, definition, false) ;
	legacyRecovery( context, rootFactory, definition, true) ;
	corruption( context, rootFactory, definition) ;
	oldEntrypoints( context, rootFactory, definition) ;
	projectedCapacity( context) ;
	projectedWindows( context, rootFactory, definition) ;
	projectedTampering( context, rootFactory, definition) ;
	projectedPermitBoundary( context, rootFactory, definition) ;
}
} // namespace drivercrate::test
