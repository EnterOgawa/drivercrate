//------------------------------------------------------------------------------
/**
 * @file local_collector_executor_tests.cpp
 * @brief v3の原観測・固定hash・全保存窓を非通信検証します。
 * @version 01.01.01
 * @date 2026/09/27
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/27  応答v3・所有worker回収を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/27  保存中取消し・監督診断の受入を追加。
 * Ver.01.01.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 開発用の有限収集に限定し、製品の取得・導入を許可しません。
 * @see docs/adr/0218-collector-controlled-http-lifetime.md
 */
//------------------------------------------------------------------------------
#include "local_collector_executor_tests.h"
#include "platform/local_collector_executor.h"
#include "platform/local_collector_http_control.h"
#include "platform/local_collector_http_observation.h"
#include "platform/local_collector_state_store.h"
#include "platform/official_file_verifier.h"
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#include <wrl/wrappers/corewrappers.h>
#include <objbase.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>

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
// 実時計に依存しない固定UTC。
constexpr std::uint64_t TEST_UTC = 1790456400000ULL ;
/** @brief 一時保護storeから元envelope本文を読みます。
 * @param[in,out] store 試験専用writer。
 * @param[in] name 固定相対名。
 * @return 元本文。
 */
std::string				body( LocalCollectorStateStore &store, const std::wstring &name)
{
	std::string raw ;		// Hash envelopeの保存byte。
	bool		found{} ;	// 欠損を空本文へ変換しない。
	// 取得不能は試験失敗として停止する。
	if( store.read( name, raw, found) != 0U || !found) {
		throw std::runtime_error( "collector v3 fixture read") ;
	}

	return winrt::to_string( Object::Parse( winrt::to_hstring( raw)).GetNamedString( L"body")) ;
}
/** @brief Hash envelopeを維持して故障本文を注入します。
 * @param[in,out] store 試験専用writer。
 * @param[in] name 固定相対名。
 * @param[in] content 故障／元本文。
 */
void writeBody( LocalCollectorStateStore &store, const std::wstring &name, std::string_view content)
{
	std::wstring hash ;	// 内容一致だけを再現し、元許可を増やさない。
	// 計算失敗を故障注入成功にしない。
	if( computeBytesSha256( content, hash) != 0) {
		throw std::runtime_error( "collector v3 fixture hash") ;
	}

	std::transform( hash.begin(), hash.end(), hash.begin(), []( wchar_t c) {
		return c >= L'A' && c <= L'F' ? static_cast<wchar_t>( c + 32) : c ;
	}) ;
	Object envelope ;	// 元schemaの外側。
	envelope.Insert( L"schema", Value::CreateStringValue( L"collector-campaign-envelope-v1")) ;
	envelope.Insert( L"sha256", Value::CreateStringValue( hash)) ;
	envelope.Insert( L"body", Value::CreateStringValue( winrt::to_hstring( content))) ;
	// Test rootの元fileだけを書き換える。
	if( store.write( name, winrt::to_string( envelope.Stringify())) != 0U) {
		throw std::runtime_error( "collector v3 fixture write") ;
	}
}
/** @brief 一回許可に実観測相当の固定値を入れて確定します。
 * @param[in,out] context Assertion集計。
 * @param[in,out] permit 元の制御予約。
 * @param[in] unknown 途中read失敗を注入する場合true。
 * @return 元control。Native通信は実行しません。
 */
std::shared_ptr<CollectorHttpControl> completed( TestContext &context, CollectorHttpPermit &permit,
												bool unknown = false)
{
	const auto result = permit.claim( &permit, *permit.binding()) ;	// 試験scopeの一意identity。
	DRIVERCRATE_EXPECT( context, result && result->begin( CollectorIoStage::SEND, 30000U) > 0U &&
									result->noteSendCall() && result->noteHeaders()) ;
	// 未知終了にも成功readの下限を残す。
	if( result) {
		DRIVERCRATE_EXPECT( context, result->noteRead( 3U, 3U)) ;
		// API失敗の原HRESULT bit patternと未知全量を別に残す。
		if( unknown) {
			result->fail(
				CollectorIoCause::HTTP,
				{CollectorIoErrorDomain::HRESULT_ERROR, 0x80070005U, CollectorIoStage::READ}, true) ;
		}

		DRIVERCRATE_EXPECT( context, result->finish()) ;
	}

	return result ;
}
/** @brief 確定観測と整合した、公式解析未接続の応答を作ります。
 * @param[in] io 元観測。
 * @param[in] accepted 監督の受領時刻。
 * @return HELDまたはFAILED。OBSERVEDは作りません。
 */
CollectorRecoveryResponse response( const CollectorIoSnapshot &io, std::uint64_t accepted)
{
	CollectorRecoveryResponse result ;	// 元worker終了を保持する。
	result.state = io.cause == CollectorIoCause::COMPLETE ? CollectorCampaignJobState::HELD
														  : CollectorCampaignJobState::FAILED ;
	result.finishedUtcMillis = io.finishedUtcMillis.value() ;
	result.acceptedUtcMillis = accepted ;
	result.sentRequests		 = io.sends ;
	result.bytesKnown		 = io.bytesKnown ;
	result.receivedBytes	 = io.bytesKnown ? io.lowerBytes : 0U ;
	result.status			 = io.sends == 1U ? 200U : 0U ;
	result.error			 = io.error.code ;
	result.errorDomain		 = io.error.domain == CollectorIoErrorDomain::HRESULT_ERROR ? L"HRESULT"
							   : io.error.domain == CollectorIoErrorDomain::PARSER		? L"PARSER"
							   : io.error.domain == CollectorIoErrorDomain::NONE		? L"NONE"
																						: L"WIN32" ;
	return result ;
}
/** @brief 固定観測の未知field・enum・型・上限を検査します。
 * @param[in,out] context Assertion集計。
 */
void codecChecks( TestContext &context)
{
	CollectorIoSnapshot io ;	// 外側結果に依存しない固定codecの値。
	io.cause			 = CollectorIoCause::HTTP ;
	io.stage			 = CollectorIoStage::READ ;
	io.sealed			 = true ;
	io.deadlineUtcMillis = TEST_UTC + 120000U ;
	io.elapsedMillis	 = 1000U ;
	io.lowerBytes		 = 3U ;
	io.headerUtcMillis	 = TEST_UTC ;
	io.native			 = CollectorIoError{CollectorIoErrorDomain::HRESULT_ERROR, 0x80070005U,
									CollectorIoStage::READ} ;
	const std::wstring permit( 64U, L'a') ;	// 架空の元操作hash。
	std::string		   encoded ;			// 正常canonical。
	DRIVERCRATE_EXPECT( context, encodeCollectorHttpObservation( io, permit, encoded)) ;
	CollectorIoSnapshot decoded ;	// Decode結果を別領域へ出す。
	DRIVERCRATE_EXPECT( context, decodeCollectorHttpObservation( encoded, permit, decoded) &&
									decoded.native && decoded.native->code == 0x80070005U &&
									decoded.lowerBytes == 3U) ;
	// 各故障を元正常本文から独立注入する。
	for( unsigned mode = 0U; mode < 9U; ++mode) {
		auto object = Object::Parse( winrt::to_hstring( encoded)) ;	// 同じ元本文。
		// 未知・欠損・範囲・原domainの異常を切り分ける。
		switch( mode) {
			// 未知fieldを無視しない。
			case 0:
				object.Insert( L"extra", Value::CreateNullValue()) ;
				break ;

			// Null elapsedと既知stopの矛盾。
			case 1:
				object.Insert( L"elapsed", Value::CreateNullValue()) ;
				object.Insert( L"stopElapsed", Value::CreateNumberValue( 0)) ;
				break ;

			// 未知causeを成功へ丸めない。
			case 2:
				object.Insert( L"cause", Value::CreateStringValue( L"OTHER")) ;
				break ;

			// 欠損stageを旧defaultへ戻さない。
			case 3:
				object.Remove( L"stage") ;
				break ;

			// 正確でない数値を受理しない。
			case 4:
				object.Insert( L"lowerBytes", Value::CreateNumberValue( 0.5)) ;
				break ;

			// 別permitを同じ保存slotへ受理しない。
			case 5:
				object.Insert( L"permit", Value::CreateStringValue( std::wstring( 64U, L'b'))) ;
				break ;

			// Native domainを分類名へ混同しない。
			case 6:
				object.GetNamedObject( L"native").Insert( L"domain",
														Value::CreateStringValue( L"HTTP")) ;
				break ;

			// 32 bitを超えた原値。
			case 7:
				object.GetNamedObject( L"native").Insert( L"code",
														Value::CreateNumberValue( 4294967296.0)) ;
				break ;

			// 未知enum ordinalを空名として受理しない。
			case 8:
				object.Insert( L"stage", Value::CreateStringValue( L"")) ;
				break ;
		}

		DRIVERCRATE_EXPECT( context, !decodeCollectorHttpObservation(
										winrt::to_string( object.Stringify()), permit, decoded)) ;
	}

	DRIVERCRATE_EXPECT( context, !decodeCollectorHttpObservation( encoded + " ", permit, decoded)) ;
	DRIVERCRATE_EXPECT( context,
					   !decodeCollectorHttpObservation( std::string( 4097U, 'x'), permit, decoded)) ;
}
} // namespace
/** @see local_collector_executor_tests.h */
void runCollectorV3RecoveryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorRecoveryInput( std::size_t)> &inputFactory)
{
	codecChecks( context) ;
	// 各応答保存／反映窓で停止し、元時刻・観測byteを保持したまま回収する。
	for( unsigned window = 0U; window < 7U; ++window) {
		const auto				 point = window == 0U	? CollectorRecoveryCheckpoint::RESPONSE
										 : window == 1U ? CollectorRecoveryCheckpoint::EFFECTS
										 : window == 2U ? CollectorRecoveryCheckpoint::REGISTERED
										 : window == 6U ? CollectorRecoveryCheckpoint::COMPLETED
														: CollectorRecoveryCheckpoint::APPLIED ;	// 元保存窓。
		// CONTROL／JOB／BUDGETの反映数。
		unsigned				 applied{} ;
		LocalCollectorStateStore store ;	// 一時GUIDの単一writer。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		const auto	 input = inputFactory( 1U) ;	// 架空一job。
		std::wstring responseName ;					// 元操作の唯一v3名。
		std::string	 original ;						// 保存済み応答の完全byte。
		{
			LocalCollectorRecovery recovery ;	// 中断注入の元監督。
			DRIVERCRATE_EXPECT(
				context, recovery.initialize( store, input, TEST_UTC, 0U, [&, point]( auto at) {
					// 三roleの各prefixを別の停止条件として試す。
					if( at == CollectorRecoveryCheckpoint::APPLIED) {
						++applied ;
					}

					return at == point && (point != CollectorRecoveryCheckpoint::APPLIED ||
										   applied == window - 2U) ;
				}) == 0U) ;
			CollectorHttpPermitPool pool(
				[] { return CollectorHttpClockSample{TEST_UTC, 0U} ; }) ;	// 同じ元clock。
			CollectorHttpPermit permit ;									// 予約後だけの一回許可。
			DRIVERCRATE_EXPECT( context, pool.reserve( recovery, permit) == 0U) ;
			const auto control = completed( context, permit) ;	// 固定三byte。
			DRIVERCRATE_EXPECT( context,
							   recovery.acceptControlled(
								   *permit.binding(), response( control->snapshot(), TEST_UTC),
								   control->snapshot(), TEST_UTC, 0U) == ERROR_OPERATION_ABORTED) ;
			std::vector<std::wstring> names ;	// 実保存名から元応答を確認する。
			DRIVERCRATE_EXPECT( context, store.listRunNames( names) == 0U) ;
			// 同じrunの一件だけを元byte比較対象とする。
			for( const auto &name : names) {
				// 新応答名以外を読み替えない。
				if( name.starts_with( L"campaign-response-v3-")) {
					responseName = L"runs/" + name ;
					original	 = body( store, responseName) ;
				}
			}

			DRIVERCRATE_EXPECT( context, !original.empty()) ;
		}
		LocalCollectorRecovery resumed ;	// 応答先行回収。
		DRIVERCRATE_EXPECT( context,
						   resumed.initialize( store, input, TEST_UTC + 2000U, 100U) == 0U &&
							   resumed.terminalJobs() == 1U) ;
		DRIVERCRATE_EXPECT( context, body( store, responseName) == original) ;
		CollectorBudgetSnapshot budget ;	// 三byteだけを一回課金する。
		DRIVERCRATE_EXPECT(
			context,
			parseCollectorBudgetSnapshot( body( store, L"current/campaign-budget-v1.json"), budget) &&
				budget.reservations.size() == 1U && budget.reservations[0].charged == 3U &&
				budget.reservations[0].phase == 1U) ;
	}

	// 改変はenvelope hashを再計算しても元結合・整合性が拒否する。
	for( unsigned fault = 0U; fault < 13U; ++fault) {
		LocalCollectorStateStore store ;	// 独立した故障root。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		const auto	 input = inputFactory( 1U) ;	// 元入力。
		std::wstring name ;							// 固定v3応答名。
		{
			LocalCollectorRecovery recovery ;	// 応答だけ保存して停止する。
			DRIVERCRATE_EXPECT(
				context, recovery.initialize( store, input, TEST_UTC, 0U, [fault]( auto at) {
					return at == (fault == 12U ? CollectorRecoveryCheckpoint::REGISTERED
											   : CollectorRecoveryCheckpoint::RESPONSE) ;
				}) == 0U) ;
			CollectorHttpPermitPool pool(
				[] { return CollectorHttpClockSample{TEST_UTC, 0U} ; }) ;	// 元予約clock。
			CollectorHttpPermit permit ;									// 実予約。
			DRIVERCRATE_EXPECT( context, pool.reserve( recovery, permit) == 0U) ;
			const auto control = completed( context, permit, true) ;	// 未知全量・下限三byte。
			DRIVERCRATE_EXPECT( context,
							   recovery.acceptControlled(
								   *permit.binding(), response( control->snapshot(), TEST_UTC),
								   control->snapshot(), TEST_UTC, 0U) == ERROR_OPERATION_ABORTED) ;
			std::vector<std::wstring> names ;	// 故障対象を一件に限定する。
			DRIVERCRATE_EXPECT( context, store.listRunNames( names) == 0U) ;
			// 応答名を既存有限一覧から取り出す。
			for( const auto &entry : names) {
				// 試験用v3だけを選ぶ。
				if( entry.starts_with( L"campaign-response-v3-")) {
					name = L"runs/" + entry ;
				}
			}
		}
		auto	   object = Object::Parse( winrt::to_hstring( body( store, name))) ;	// 原応答。
		const auto io	  = object.GetNamedObject( L"io") ;								// 固定I/O object。
		// 原enum・数値・deadline・hash／schema結合の改変を試す。
		switch( fault) {
			// 元期限改変。
			case 0:
				io.Insert( L"deadline",
						  Value::CreateNumberValue( static_cast<double>( TEST_UTC + 119999U))) ;
				break ;

			// 下限が最大量を超える。
			case 1:
				io.Insert( L"lowerBytes", Value::CreateNumberValue( 9000000.0)) ;
				break ;

			// 元headerより早い終了。
			case 2:
				io.Insert( L"headerUtc",
						  Value::CreateNumberValue( static_cast<double>( TEST_UTC + 1U))) ;
				break ;

			// 取消し受理の欠測。
			case 3:
				io.Insert( L"cause", Value::CreateStringValue( L"CANCELLED")) ;
				break ;

			// 別原domain。
			case 4:
				object.Insert( L"errorDomain", Value::CreateStringValue( L"OTHER")) ;
				break ;

			// 確定済み成功へ偽装してnative副診断を残す。
			case 5:
				io.Insert( L"cause", Value::CreateStringValue( L"COMPLETE")) ;
				break ;

			// 全量既知と下限の不一致。
			case 6:
				object.Insert( L"bytes", Value::CreateNumberValue( 2)) ;
				break ;

			// 別permit。
			case 7:
				io.Insert( L"permit", Value::CreateStringValue( std::wstring( 64U, L'b'))) ;
				break ;

			// 送信欠測を予約数へ補完しない。
			case 8:
				object.Insert( L"sends", Value::CreateNullValue()) ;
				break ;

			// 旧schemaへ新field／domainを混入する。
			case 9:
				object.Insert( L"schema",
							  Value::CreateStringValue( L"collector-campaign-response-v2")) ;
				break ;

			// 二version同時保存。
			case 10:
				break ;

			// 未知prefixが正規応答と共存する。
			case 11:
				break ;

			// 構造上有効なelapsed改変も登録response hashが拒否する。
			case 12:
				io.Insert( L"elapsed", Value::CreateNumberValue( 1)) ;
				break ;
		}

		writeBody( store, name, winrt::to_string( object.Stringify())) ;
		// 同内容でも両versionを許可しない。
		if( fault == 10U) {
			std::wstring other = name ;	// 元操作の旧名。
			other.replace( other.find( L"v3-"), 3U, L"v2-") ;
			writeBody( store, other, body( store, name)) ;
		}

		// 未知名を無視して回収しない。
		if( fault == 11U) {
			writeBody( store, L"runs/campaign-response-v4-forged.json", "{}") ;
		}

		const auto beforeBudget =
			// 拒否時の未精算像。
			body( store, L"current/campaign-budget-v1.json") ;
		LocalCollectorRecovery resumed ;	// 改変拒否。
		DRIVERCRATE_EXPECT( context, resumed.initialize( store, input, TEST_UTC + 2000U, 100U) ==
										ERROR_INVALID_DATA) ;
		DRIVERCRATE_EXPECT( context,
						   body( store, L"current/campaign-budget-v1.json") == beforeBudget) ;
	}

	// 制御予約を旧acceptへ渡した場合、新応答を作らず停止する。
	{
		LocalCollectorStateStore store ;	// 迂回拒否専用root。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		LocalCollectorRecovery recovery ;	// 元制御監督。
		DRIVERCRATE_EXPECT( context,
						   recovery.initialize( store, inputFactory( 1U), TEST_UTC, 0U) == 0U) ;
		CollectorHttpPermitPool pool(
			[] { return CollectorHttpClockSample{TEST_UTC, 0U} ; }) ;	// 一回予約。
		CollectorHttpPermit permit ;									// 保存後に発行する許可。
		DRIVERCRATE_EXPECT( context, pool.reserve( recovery, permit) == 0U) ;
		const auto control = completed( context, permit) ;	// 完了した観測を捨てる攻撃相当。
		DRIVERCRATE_EXPECT( context, recovery.accept( 0U, response( control->snapshot(), TEST_UTC),
													TEST_UTC, 0U) == ERROR_INVALID_DATA) ;
		std::vector<std::wstring> names ;	// 予約と入力だけが残る。
		DRIVERCRATE_EXPECT( context,
						   store.listRunNames( names) == 0U &&
							   std::none_of( names.begin(), names.end(), []( const auto &entry) {
								   return entry.starts_with( L"campaign-response-") ;
							   })) ;
	}
}
namespace {
/** @brief Thread間でfake時刻・終了順・通知だけを共有します。 */
struct ExecutorFixture {
	/// 時刻と通知を保護します。Storeは共有しません。
	std::mutex				 mutex ;
	/// 上限10秒のfixture待機を通知します。
	std::condition_variable	 changed ;
	/// 元UTC／単調clockの同じ増分です。
	std::uint64_t			 elapsed{} ;
	/// 元UTCを故障注入で後退させる場合trueです。
	bool					 rollback{} ;
	/// GET開始数。Mutex内でだけ更新します。
	std::size_t				 entered{} ;
	/// 保存完了checkpoint数。Mutex内でだけ更新します。
	std::size_t				 committed{} ;
	/// 当jobのGETを復帰させる固定bitです。
	std::array<bool, 5>		 released{} ;
	/// Worker COM apartment等の試験違反です。
	std::atomic_bool		 valid{true} ;
	/** @brief 同じlockで二clockを採取します。
	 * @return 元fixture時刻。
	 */
	CollectorHttpClockSample sample()
	{
		const std::lock_guard lock( mutex) ;	// 二clockの同時読取り。
		return {rollback ? TEST_UTC - 1U : TEST_UTC + elapsed, elapsed} ;
	}
	/** @brief GET開始を通知し、当jobの有限解放を待ちます。
	 * @param[in] index job index。
	 * @param[in] wave 全四件の開始だけを待つ場合true。
	 */
	void enter( std::size_t index, bool wave = false)
	{
		APTTYPE			 apartment{} ;	// 当workerの実COM区分。
		APTTYPEQUALIFIER qualifier{} ;	// COM qualifier。
		// WorkerがCOMを初期化していない場合も測定違反として残す。
		if( CoGetApartmentType( &apartment, &qualifier) != S_OK || apartment != APTTYPE_MTA) {
			valid.store( false) ;
		}

		std::unique_lock lock( mutex) ;	// 待機中はmutexを解放する。
		++entered ;
		changed.notify_all() ;
		// Waveは先頭四件を揃え、第五件は待たせない。
		if( !changed.wait_for( lock, std::chrono::seconds( 10),
							 [&] { return wave ? entered >= 4U : released[index] ; })) {
			valid.store( false) ;
			throw std::runtime_error( "executor fixture deadline") ;
		}
	}
	/** @brief 監督の保存完了を通知します。
	 * @param[in] point 元checkpoint。
	 * @return 中断を注入しないfalse。
	 */
	bool checkpoint( CollectorRecoveryCheckpoint point)
	{
		// 保存完了以外で終了順を進めない。
		if( point == CollectorRecoveryCheckpoint::COMPLETED) {
			const std::lock_guard lock( mutex) ;	// 通知countだけを更新する。
			++committed ;
			changed.notify_all() ;
		}

		return false ;
	}
} ;
/** @brief 正常なGETの固定観測を作ります。実HTTP試験とは分けます。
 * @param[in,out] permit 元の一回許可。
 * @param[out] http 固定200とraw三byteのhash。
 * @return Claim済み元制御。
 */
std::shared_ptr<CollectorHttpControl> executorGet( CollectorHttpPermit				 &permit,
												  CollectorControlledHttpObservation &http)
{
	auto control = permit.claim( &permit, *permit.binding()) ;	// 当slotにだけclaimする。
	// 不正fixtureを成功へ補完しない。
	if( !control || control->begin( CollectorIoStage::SEND, 30000U) == 0U ||
	   !control->noteSendCall() || !control->noteHeaders() || !control->noteRead( 3U, 3U)) {
		throw std::runtime_error( "executor fixture GET") ;
	}

	http.status = 200U ;
	// 保存されるhashも同じraw三byteへ結合する。
	if( computeBytesSha256( "abc", http.bodySha256) != 0) {
		throw std::runtime_error( "executor fixture hash") ;
	}

	return control ;
}
/** @brief 保存済みv3の一覧を同期writerで読みます。
 * @param[in,out] store 試験専用writer。
 * @return v3の本文object。Workerへ渡しません。
 */
std::vector<Object> executorResponses( LocalCollectorStateStore &store)
{
	std::vector<std::wstring> names ;	// 有限保存一覧。
	// 取得失敗を空一覧へ変換しない。
	if( store.listRunNames( names) != 0U) {
		throw std::runtime_error( "executor fixture inventory") ;
	}

	std::vector<Object> results ;	// 同じMTA内だけの解析object。
	// v3応答だけを検査する。
	for( const auto &name : names) {
		// 他fileを応答として数えない。
		if( name.starts_with( L"campaign-response-v3-")) {
			results.push_back( Object::Parse( winrt::to_hstring( body( store, L"runs/" + name)))) ;
		}
	}

	return results ;
}
} // namespace
/** @see local_collector_executor_tests.h */
void runCollectorExecutorTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorRecoveryInput( std::size_t)> &inputFactory)
{
	// 全四枠を揃えた後、保存後だけ第五件を開始する。
	{
		ExecutorFixture			 fixture ;	// 開始waveの明示状態。
		LocalCollectorStateStore store ;	// 一時writer。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		LocalCollectorRecovery recovery ;	// 五つの独立group。
		DRIVERCRATE_EXPECT( context,
						   recovery.initialize( store, inputFactory( 5U), TEST_UTC, 0U) == 0U) ;
		LocalCollectorExecutor executor(
			{[&] { return fixture.sample() ; },
			 [&]( std::size_t index, const auto &, auto &permit, auto &http) -> NativeError {
				 fixture.enter( index, true) ;
				 (void)executorGet( permit, http) ;
				 return 0 ;
			 },
			 // Callbackはrun内でのみ借用する。
			 collectorNativeThreadStarter()}) ;
		const auto report = executor.run( recovery) ;	// Join・保存まで待つ。
		DRIVERCRATE_EXPECT(
			context, report.error == 0U && report.outcome == CollectorExecutorOutcome::TERMINAL &&
						 report.reserved == 5U && report.started == 5U && report.joined == 5U &&
						 report.saved == 5U && report.peakSlots == 4U && report.failedJobs == 0U &&
						 fixture.valid.load()) ;
		const auto records = executorResponses( store) ;	// Metadata成功と混同しない。
		DRIVERCRATE_EXPECT( context, records.size() == 5U && recovery.terminalJobs() == 5U) ;
		// 全件の元観測とHELD分類を確認する。
		for( const auto &record : records) {
			DRIVERCRATE_EXPECT( context, record.GetNamedString( L"state") == L"HELD" &&
											record.GetNamedNumber( L"bytes") == 3.0 &&
											record.GetNamedObject( L"io").GetNamedString( L"cause") ==
												L"COMPLETE") ;
		}

		DRIVERCRATE_EXPECT( context, executor.run( recovery).error == ERROR_INVALID_STATE &&
										executorResponses( store).size() == 5U) ;
	}
	// 取消し前受付停止、thread作成／entry例外、個別HTTP拒否と保存失敗を分離する。
	for( unsigned mode = 0U; mode < 14U; ++mode) {
		ExecutorFixture			 fixture ;	// 当故障だけに限定した共有時計。
		LocalCollectorStateStore store ;	// 独立GUID root。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		const auto input = inputFactory( mode == 3U ? 2U : mode >= 7U ? 5U : 1U) ;	// 元条件。
		unsigned   applied{} ;														// 各role保存後の注入位置。
		LocalCollectorRecovery recovery ;											// 保存失敗は応答先行窓へ注入する。
		DRIVERCRATE_EXPECT(
			context, recovery.initialize( store, input, TEST_UTC, 0U, [&, mode]( auto point) {
				// 元四workerを開始した後、応答から三role各prefixまで別窓へ停止を注入する。
				if( point == CollectorRecoveryCheckpoint::APPLIED) {
					++applied ;
				}

				const auto expected = mode == 7U   ? CollectorRecoveryCheckpoint::RESPONSE
									  : mode == 8U ? CollectorRecoveryCheckpoint::EFFECTS
									  : mode == 9U ? CollectorRecoveryCheckpoint::REGISTERED
									  : mode == 13U
										  ? CollectorRecoveryCheckpoint::COMPLETED
										  : CollectorRecoveryCheckpoint::APPLIED ;	// 元保存窓。
				return mode >= 7U && point == expected &&
					   (expected != CollectorRecoveryCheckpoint::APPLIED || applied == mode - 9U) ;
			}) == 0U) ;
		auto starter = collectorNativeThreadStarter() ;	// 明示開始。
		// 作成不能の原Win32 errorを保持する。
		if( mode == 1U) {
			starter = []( std::function<void()>) -> std::thread {
				throw std::system_error( ERROR_NOT_ENOUGH_MEMORY, std::system_category()) ;
			} ;
		}

		LocalCollectorExecutor executor(
			{[&] { return fixture.sample() ; },
			 [&, mode]( std::size_t index, const auto &, auto &permit, auto &http) -> NativeError {
				 // 全四workerを開始した後だけ保存失敗を起こす。
				 if( mode >= 7U) {
					 fixture.enter( index, true) ;
				 }

				 // Thread entryの未知例外も外へ漏らさない。
				 if( mode == 2U) {
					 throw std::runtime_error( "executor entry exception") ;
				 }

				 const auto control = executorGet( permit, http) ;	// 固定三byte。
				 // 個別HTTP失敗だけでは別groupを停止しない。
				 if( mode == 3U && index == 0U) {
					 http.status = 403U ;
					 control->fail( CollectorIoCause::HTTP,
								   {CollectorIoErrorDomain::HTTP, 403U, CollectorIoStage::HEADERS},
								   false) ;
				 }

				 // 解放未確認を正常thread終了で補わない。
				 if( mode == 4U) {
					 control->fail( CollectorIoCause::HTTP,
								   {CollectorIoErrorDomain::WIN32_ERROR, ERROR_ACCESS_DENIED,
									CollectorIoStage::CLEANUP},
								   false) ;
					 control->setNativeReleased( false) ;
				 }

				 // 時計巻戻しは原終了時刻を架空補完させない。
				 if( mode == 5U) {
					 const std::lock_guard lock( fixture.mutex) ;	// Clock対を同じlockで変更する。
					 fixture.rollback = true ;
				 }

				 return 0 ;
			 },
			 // Fixtureはrunの全joinより長く存続する。
			 std::move( starter)}) ;
		// 予約前取消しはstore予約もGETも増やさない。
		if( mode == 0U) {
			executor.requestStop() ;
		}

		// 外部予約を所有workerなしで永久待機しない。
		if( mode == 6U) {
			CollectorRecoveryDispatch foreign ;	// 旧予約を復旧せず混在させた故障。
			DRIVERCRATE_EXPECT( context, recovery.reserve( TEST_UTC, 0U, foreign) == 0U) ;
		}

		const auto report  = executor.run( recovery) ;		// 全通知を回収する。
		const auto records = executorResponses( store) ;	// 保存失敗後の更新も確認する。
		// 予約・保存・回収の差を故障別に固定採点する。
		switch( mode) {
			// 予約前取消し。
			case 0:
				DRIVERCRATE_EXPECT( context, report.outcome == CollectorExecutorOutcome::CANCELLED &&
												report.error == 0U && report.reserved == 0U &&
												report.started == 0U && records.empty()) ;
				break ;

			// Thread作成失敗も一回保存する。
			case 1:
				DRIVERCRATE_EXPECT(
					context,
					report.error == ERROR_NOT_ENOUGH_MEMORY && report.reserved == 1U &&
						report.started == 0U && report.joined == 0U && report.saved == 1U &&
						records.size() == 1U && records[0].GetNamedNumber( L"sends") == 0.0 &&
						records[0].GetNamedObject( L"io").GetNamedString( L"cause") == L"SETUP") ;
				break ;

			// 元HRESULTを保持する。
			case 2:
				DRIVERCRATE_EXPECT(
					context, report.error == static_cast<DWORD>( E_FAIL) && report.joined == 1U &&
								 report.saved == 1U && records.size() == 1U &&
								 records[0].GetNamedString( L"errorDomain") == L"HRESULT") ;
				break ;

			// HTTP個別拒否と別group完了を両方保存する。
			case 3:
				DRIVERCRATE_EXPECT( context, report.error == 0U && report.saved == 2U &&
												report.joined == 2U && report.failedJobs == 1U &&
												records.size() == 2U) ;
				break ;

			// Native解放未確認は元5で受付停止する。
			case 4:
				DRIVERCRATE_EXPECT(
					context,
					report.error == ERROR_ACCESS_DENIED && report.saved == 1U &&
						report.joined == 1U && records.size() == 1U &&
						!records[0].GetNamedObject( L"io").GetNamedBoolean( L"nativeReleased")) ;
				break ;

			// 欠測終了は次回未知intentへ残す。
			case 5:
				DRIVERCRATE_EXPECT( context, report.error == ERROR_INVALID_DATA &&
												report.joined == 1U && report.saved == 0U &&
												records.empty()) ;
				break ;

			// 他のexecutor所有予約は混在させない。
			case 6:
				DRIVERCRATE_EXPECT( context, report.error == ERROR_INVALID_STATE &&
												report.reserved == 0U && report.started == 0U &&
												records.empty()) ;
				break ;

			// 第一保存失敗後は残り三件をjoinだけし、第五件を予約しない。
			case 7:
			// 前後像保存後の停止。
			case 8:
			// 登録済みcommitの停止。
			case 9:
			// CONTROL prefixの停止。
			case 10:
			// JOB prefixの停止。
			case 11:
			// BUDGET prefixの停止。
			case 12:
			// 完了登録後の停止。
			case 13:
				DRIVERCRATE_EXPECT( context, report.error == ERROR_OPERATION_ABORTED &&
												report.reserved == 4U && report.started == 4U &&
												report.joined == 4U && report.saved == 0U &&
												report.peakSlots == 4U && records.size() == 1U &&
												fixture.valid.load()) ;
				break ;
		}
	}

	// Workerの終了順と監督の保存時刻を同じUTCへ付け替えない。
	{
		ExecutorFixture			 fixture ;	// 明示逆順の固定通知。
		LocalCollectorStateStore store ;	// 同期writer。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		LocalCollectorRecovery recovery ;					// Checkpointで保存終了だけを通知する。
		const auto			   input = inputFactory( 4U) ;	// 四group。
		DRIVERCRATE_EXPECT( context,
						   recovery.initialize( store, input, TEST_UTC, 0U, [&]( auto point) {
							   return fixture.checkpoint( point) ;
						   }) == 0U) ;
		LocalCollectorExecutor executor(
			{[&] { return fixture.sample() ; },
			 [&]( std::size_t index, const auto &, auto &permit, auto &http) -> NativeError {
				 (void)executorGet( permit, http) ;
				 fixture.enter( index) ;
				 return 0 ;
			 },
			 // 元worker clockを共有する。
			 collectorNativeThreadStarter()}) ;
		std::thread order( [&] {
			std::unique_lock lock( fixture.mutex) ;	// 待機中だけ解放する。
			// 四worker開始を有限待機し、未開始を見逃さない。
			if( !fixture.changed.wait_for( lock, std::chrono::seconds( 10),
										 [&] { return fixture.entered == 4U ; })) {
				fixture.valid.store( false) ;
			}

			// 一件の保存完了後にだけ次の逆順jobを解放する。
			for( std::size_t count = 0U; count < 4U; ++count) {
				fixture.elapsed				 = (count + 1U) * 1000U ;
				fixture.released[3U - count] = true ;
				fixture.changed.notify_all() ;
				// 保存失敗では全解放してjoinを妨げない。
				if( !fixture.changed.wait_for( lock, std::chrono::seconds( 10),
											 [&] { return fixture.committed > count ; })) {
					fixture.valid.store( false) ;
					fixture.released.fill( true) ;
					fixture.changed.notify_all() ;
					break ;
				}
			}
		}) ; // 台帳やWinRT objectはdriver threadへ渡さない。
		const auto	report = executor.run( recovery) ;	// 元MTA／単一writerで実行する。
		order.join() ;
		DRIVERCRATE_EXPECT( context, fixture.valid.load() && report.error == 0U &&
										report.joined == 4U && report.saved == 4U &&
										report.peakSlots == 4U) ;
		const auto records = executorResponses( store) ;	// 元jobと時刻を照合する。
		DRIVERCRATE_EXPECT( context, records.size() == 4U) ;
		// Input job keyを元ordinalに結合する。
		for( const auto &record : records) {
			const auto key = record.GetNamedString( L"request") ;	// 固定job識別子。
			const auto at =
				std::find_if( input.requestKeys.begin(), input.requestKeys.end(),
							 [&]( const auto &job) { return job == key ; }) ;	// 原jobだけを解決する。
			DRIVERCRATE_EXPECT( context, at != input.requestKeys.end()) ;
			// 未知jobへ期待時刻を作らない。
			if( at != input.requestKeys.end()) {
				const auto index =
					// 元index。
					static_cast<std::size_t>( std::distance( input.requestKeys.begin(), at)) ;
				DRIVERCRATE_EXPECT( context,
								   record.GetNamedNumber( L"finished") ==
										   static_cast<double>( TEST_UTC + (4U - index) * 1000U) &&
									   record.GetNamedObject( L"io").GetNamedNumber( L"elapsed") ==
										   (4U - index) * 1000.0) ;
			}
		}
	}
	// 実行中の取消しは先着原因と全join・保存を保持する。
	{
		ExecutorFixture			 fixture ;	// 停止通知だけのdriver共有状態。
		LocalCollectorStateStore store ;	// 二jobの単一writer。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		LocalCollectorRecovery recovery ;	// 元予約。
		DRIVERCRATE_EXPECT( context,
						   recovery.initialize( store, inputFactory( 2U), TEST_UTC, 0U) == 0U) ;
		LocalCollectorExecutor executor(
			{[&] { return fixture.sample() ; },
			 [&]( std::size_t index, const auto &, auto &permit, auto &http) -> NativeError {
				 const auto control = executorGet( permit, http) ;	// 受信中相当の三byte。
				 fixture.enter( index) ;
				 const auto deadline =
					 // Fixture上限。
					 std::chrono::steady_clock::now() + std::chrono::seconds( 10) ;
				 // 親が元controlへ取消しを配信するまでだけ待つ。
				 while( control->snapshot().cause == CollectorIoCause::NONE &&
					   std::chrono::steady_clock::now() < deadline) {
					 std::this_thread::sleep_for( std::chrono::milliseconds( 1)) ;
				 }

				 return static_cast<NativeError>( E_ABORT) ;
			 },
			 // Driverは公開停止入口だけを呼ぶ。
			 collectorNativeThreadStarter()}) ;
		std::thread cancel( [&] {
			std::unique_lock lock( fixture.mutex) ;	// 開始通知を有限待機する。
			// 両workerの開始後だけ取消す。
			if( !fixture.changed.wait_for( lock, std::chrono::seconds( 10),
										 [&] { return fixture.entered == 2U ; })) {
				fixture.valid.store( false) ;
			}

			executor.requestStop() ;
			fixture.released.fill( true) ;
			fixture.changed.notify_all() ;
		}) ;											 // Storeを共有しない。
		const auto	report = executor.run( recovery) ;	// 取消し後も結果を全回収する。
		cancel.join() ;
		DRIVERCRATE_EXPECT( context, fixture.valid.load() && report.error == 0U &&
										report.outcome == CollectorExecutorOutcome::CANCELLED &&
										report.reserved == 2U && report.joined == 2U &&
										report.saved == 2U && report.failedJobs == 2U) ;
		const auto records = executorResponses( store) ;	// Stop受理の欠測を0で補わない。
		DRIVERCRATE_EXPECT( context, records.size() == 2U) ;
		// 全取消し観測に元stopElapsedがある。
		for( const auto &record : records) {
			DRIVERCRATE_EXPECT(
				context, record.GetNamedObject( L"io").GetNamedString( L"cause") == L"CANCELLED" &&
							 record.GetNamedObject( L"io").GetNamedNumber( L"stopElapsed") == 0.0) ;
		}
	}
	// 旧clientがcontrolを保持したまま別jobへarmしない。
	{
		ExecutorFixture						  fixture ;		// 先頭四件を揃える明示通知。
		std::shared_ptr<CollectorHttpControl> retained ;	// 第0jobの旧client保持を再現する。
		LocalCollectorStateStore			  store ;		// 第五件を未予約へ残す保護writer。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		LocalCollectorRecovery recovery ;	// 元の五job。
		DRIVERCRATE_EXPECT(
			context, recovery.initialize( store, inputFactory( 5U), TEST_UTC, 0U, [&]( auto point) {
				// 第0jobを保存してから他workerを復帰させる。
				if( point == CollectorRecoveryCheckpoint::COMPLETED) {
					const std::lock_guard lock( fixture.mutex) ;	// 通知bitだけを共有する。
					fixture.released.fill( true) ;
					fixture.changed.notify_all() ;
				}

				return false ;
			}) == 0U) ;
		LocalCollectorExecutor executor(
			{[&] { return fixture.sample() ; },
			 [&]( std::size_t index, const auto &, auto &permit, auto &http) -> NativeError {
				 fixture.enter( index, true) ;
				 const auto control = executorGet( permit, http) ;	// 元client借用。
				 // 保持するのは第0jobだけであり、親はjoin後だけ読む。
				 if( index == 0U) {
					 retained = control ;
				 }

				 return 0 ;
			 },
			 // 枠再利用前に残参照を検査する。
			 collectorNativeThreadStarter()}) ;
		const auto report = executor.run( recovery) ;	// 第五件は予約前に拒否する。
		DRIVERCRATE_EXPECT(
			context, fixture.valid.load() && retained && report.error == ERROR_INVALID_STATE &&
						 report.reserved == 4U && report.joined == 4U && report.saved == 4U &&
						 executorResponses( store).size() == 4U) ;
	}
	// 空依存は予約前構築で拒否し、nativeへ補完しない。
	{
		bool refused{} ;	// 明示欠損拒否の観測。
		try {
			// 欠損依存を渡す構築だけを試す。
			LocalCollectorExecutor missing(
				{[] { return CollectorHttpClockSample{TEST_UTC, 0U} ; }, {}, {}}) ;
		} catch( const std::invalid_argument &) {
			refused = true ;
		}

		DRIVERCRATE_EXPECT( context, refused) ;
	}
}
namespace {
/** @brief 保存窓とworkerの順序を固定する有限な試験通知です。 */
struct AcceptanceGate {
	/// Worker開始と停止後checkpointの観測だけを保護します。
	std::mutex				mutex ;
	/// Storeを共有せず固定bitを通知します。
	std::condition_variable changed ;
	/// 開始済みGETの数です。
	unsigned				entered{} ;
	/// 保存中取消し後だけ第二workerを進めます。
	bool					release{} ;
	/// 第二workerが停止後のSEND判定を行った場合trueです。
	bool					checked{} ;
	/// 同期starterの終了待ちを通知します。
	unsigned				ended{} ;
	/// 取消し後に許可された送信数です。
	unsigned				lateSends{} ;
	/// 有限待機が成立した場合trueです。
	std::atomic_bool		valid{true} ;
	/** @brief 同じlockで必要条件を最大10秒待ちます。
     * @param[in,out] lock 通知mutexの所有lock。
     * @param[in] predicate 完了条件。共有値をこのlock内だけで読みます。
     * @return 期限内成立の場合trueです。
     */
	bool wait( std::unique_lock<std::mutex> &lock, const std::function<bool()> &predicate)
	{
		// 待機不能でもworkerを残さず試験失敗として記録する。
		if( !changed.wait_for( lock, std::chrono::seconds( 10), predicate)) {
			valid.store( false) ;
			return false ;
		}

		return true ;
	}
} ;
/** @brief 予約・応答・完了保存中の取消しを固定した順序で検査します。
 * @param[in,out] context 親threadの集計。
 * @param[in] rootFactory 自作root生成。
 * @param[in] inputFactory 固定入力生成。
 */
void cancellationSaveWindows( TestContext											  &context,
							 const std::function<std::filesystem::path()>			  &rootFactory,
							 const std::function<CollectorRecoveryInput( std::size_t)> &inputFactory)
{
	// 予約中・別job保存中・完了保存直後の各通知を独立したrootで試験する。
	for( unsigned mode = 0U; mode < 3U; ++mode) {
		AcceptanceGate			 gate ;		// COM／storeを共有しない順序通知。
		LocalCollectorStateStore store ;	// 単一writer。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		LocalCollectorExecutor *running{} ;		// Runより長く存続する停止先。
		bool					triggered{} ;	// 保存checkpointの一回だけの取消し。
		LocalCollectorRecovery	recovery ;		// 同じwriterの元予約。
		const auto				checkpoint = mode == 0U	  ? CollectorRecoveryCheckpoint::RESERVED
											 : mode == 1U ? CollectorRecoveryCheckpoint::RESPONSE
														  : CollectorRecoveryCheckpoint::COMPLETED ;	// 元窓。
		DRIVERCRATE_EXPECT(
			context, recovery.initialize(
						 store, inputFactory( mode == 0U ? 1U : 2U), TEST_UTC, 0U, [&]( auto point) {
							 // 取消しがcoordinatorの次loopより前に確実に公開される。
							 if( point == checkpoint && !triggered) {
								 triggered = true ;
								 running->requestStop() ;
								 // 別workerは保存callbackが帰る前に次checkpointへ進める。
								 if( mode == 1U) {
									 std::unique_lock lock( gate.mutex) ;	// Bitの通知だけを共有する。
									 gate.release = true ;
									 gate.changed.notify_all() ;
									 (void)gate.wait( lock, [&] { return gate.checked ; }) ;
								 }
							 }

							 return false ;
						 }) == 0U) ;
		LocalCollectorExecutor executor(
			{[] { return CollectorHttpClockSample{TEST_UTC, 0U} ; },
			 [&]( std::size_t index, const auto &, auto &permit, auto &http) -> NativeError {
				 // 保存中の第二workerは取消し前にclaimだけを済ませる。
				 if( mode == 1U && index == 1U) {
					 const auto control = permit.claim( &permit, *permit.binding()) ;	// 元許可。
					 // 開始条件の不成立は親で採点し、threadから例外を漏らさない。
					 if( !control) {
						 gate.valid.store( false) ;
						 return static_cast<NativeError>( E_FAIL) ;
					 }

					 {
						 std::unique_lock lock( gate.mutex) ;	// 第一workerとの開始barrier。
						 ++gate.entered ;
						 gate.changed.notify_all() ;
						 (void)gate.wait( lock, [&] { return gate.release ; }) ;
					 }

					 const bool sent = control->begin( CollectorIoStage::SEND, 30000U) != 0U &&
									   // 通知後の本番判定。
									   control->noteSendCall() ;
					 {
						 const std::lock_guard lock( gate.mutex) ;	// 結果を親へ公開する。
						 gate.lateSends += sent ? 1U : 0U ;
						 gate.checked = true ;
						 gate.changed.notify_all() ;
					 }
					 // 旧実装での誤送信も型付き結果として保存できるようにする。
					 if( sent) {
						 http.status = 200U ;
					 }

					 return sent ? 0 : static_cast<NativeError>( E_ABORT) ;
				 }

				 // 第一workerは両予約を開始した後だけ完了する。
				 if( mode == 1U) {
					 std::unique_lock lock( gate.mutex) ;	// 第二workerのclaimを待つ。
					 ++gate.entered ;
					 gate.changed.notify_all() ;
					 (void)gate.wait( lock, [&] { return gate.entered == 2U ; }) ;
				 }

				 (void)executorGet( permit, http) ;
				 // 予約中通知・完了保存後通知では、ここへの追加GETが拒否対象。
				 if( mode != 1U) {
					 const std::lock_guard lock( gate.mutex) ;	// Join後まで共有する計数。
					 ++gate.entered ;
					 gate.lateSends += (mode == 0U || index != 0U) ? 1U : 0U ;
				 }

				 return 0 ;
			 },
			 [&]( std::function<void()> entry) {
				 // 第二workerのbarrierが必要な条件だけ通常startを使う。
				 if( mode == 1U) {
					 return std::thread( std::move( entry)) ;
				 }

				 unsigned previous{} ;	// 元終了通知数。
				 {
					 const std::lock_guard lock( gate.mutex) ;	// 終了順を同期する。
					 previous = gate.ended ;
				 }
				 std::thread	  worker( [&, entry = std::move( entry)] {
					  // 本番entry全体が終了してから親を進める。
					  entry() ;
					  {
						  const std::lock_guard lock( gate.mutex) ;	// 終了通知だけを公開する。
						  ++gate.ended ;
					  }
					  gate.changed.notify_all() ;
				  }) ;							// Entry captureはrunのjoinより長く存続する。
				 std::unique_lock lock( gate.mutex) ;	// Ready公開済みの実行順序に固定する。
				 (void)gate.wait( lock, [&] { return gate.ended > previous ; }) ;
				 return worker ;
			 }}) ;
		running				= &executor ;
		const auto report	= executor.run( recovery) ;		// 全回収後だけ共有値を読む。
		const auto records	= executorResponses( store) ;	// 元v3を読む。
		const auto expected = mode == 1U ? 2U : 1U ;		// 完了済み＋取消し済みの件数。
		DRIVERCRATE_EXPECT( context, triggered && gate.valid.load() && gate.lateSends == 0U &&
										report.error == 0U &&
										report.outcome == CollectorExecutorOutcome::CANCELLED &&
										report.reserved == expected && report.saved == expected &&
										records.size() == expected &&
										report.started == (mode == 0U ? 0U : expected) &&
										report.joined == report.started) ;
		// 取消し前にCOMPLETEを確定した第一結果はそのまま保持する。
		for( const auto &record : records) {
			const auto complete = mode != 0U && record.GetNamedString( L"request") ==
													// 元job。
													inputFactory( 2U).requestKeys[0] ;
			DRIVERCRATE_EXPECT( context,
							   record.GetNamedObject( L"io").GetNamedString( L"cause") ==
									   (complete ? L"COMPLETE" : L"CANCELLED") &&
								   record.GetNamedNumber( L"sends") == (complete ? 1.0 : 0.0) &&
								   record.GetNamedNumber( L"bytes") == (complete ? 3.0 : 0.0)) ;
		}
	}
}
/** @brief 個別原因・最初のnative副診断・全体errorを区別します。
 * @param[in,out] context 親threadの集計。
 * @param[in] rootFactory 自作root生成。
 * @param[in] inputFactory 固定入力生成。
 */
void cleanupDiagnostics( TestContext												 &context,
						const std::function<std::filesystem::path()>			 &rootFactory,
						const std::function<CollectorRecoveryInput( std::size_t)> &inputFactory)
{
	// HTTP先着・native先着・保存error先着・四slot混在を独立して確認する。
	for( unsigned mode = 0U; mode < 4U; ++mode) {
		ExecutorFixture			 fixture ;	// 四件開始だけを固定する共有通知。
		LocalCollectorStateStore store ;	// 自作の単一writer。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		LocalCollectorRecovery recovery ;	// 元予約と保存窓。
		DRIVERCRATE_EXPECT(
			context, recovery.initialize( store, inputFactory( mode == 3U ? 5U : 1U), TEST_UTC, 0U,
										 [&, mode]( auto point) {
											 // 混在条件では第一応答の保存後だけ残り三workerを進める。
											 if( mode == 3U) {
												 (void)fixture.checkpoint( point) ;
											 }

											 return mode == 2U &&
													point == CollectorRecoveryCheckpoint::RESPONSE ;
										 }) == 0U) ;
		LocalCollectorExecutor executor(
			{[&] { return fixture.sample() ; },
			 [&]( std::size_t index, const auto &, auto &permit, auto &http) -> NativeError {
				 // 全四slotを先に開始して、第五予約が抑止されるか確認する。
				 if( mode == 3U) {
					 fixture.enter( index, true) ;
					 // 故障jobが保存されるまで三件は占有したまま待機する。
					 if( index != 0U) {
						 std::unique_lock lock( fixture.mutex) ;	// 保存通知を有限待機する。
						 // 待機不成立は全回収後に親で失敗へ集計する。
						 if( !fixture.changed.wait_for( lock, std::chrono::seconds( 10),
													  [&] { return fixture.committed != 0U ; })) {
							 fixture.valid.store( false) ;
						 }
					 }
				 }

				 const auto control = executorGet( permit, http) ;	// 元三byte。
				 // 個別causeと解放原値を意図的に異ならせる。
				 if( index == 0U) {
					 http.status = 403U ;
					 control->fail( CollectorIoCause::HTTP,
								   {mode == 1U ? CollectorIoErrorDomain::WIN32_ERROR
											   : CollectorIoErrorDomain::HTTP,
									mode == 1U ? 12030U : 403U, CollectorIoStage::RECEIVE},
								   false) ;
					 control->fail(
						 CollectorIoCause::SETUP,
						 {CollectorIoErrorDomain::WIN32_ERROR, 12002U, CollectorIoStage::CLEANUP},
						 false) ;
					 control->setNativeReleased( false) ;
				 }

				 return 0 ;
			 },
			 collectorNativeThreadStarter()}) ;
		const auto report		 = executor.run( recovery) ;	// 全workerを回収する。
		const auto records		 = executorResponses( store) ;	// 保存失敗の窓でも元応答を確認する。
		const auto expectedError = mode == 1U	? ERROR_INVALID_STATE
								   : mode == 2U ? ERROR_OPERATION_ABORTED
												: 12002U ;	// 全体原因。
		const auto count		 = mode == 3U ? 4U : 1U ;	// 第五件は予約しない。
		DRIVERCRATE_EXPECT( context, fixture.valid.load() && report.error == expectedError &&
										report.outcome == CollectorExecutorOutcome::FAILED &&
										report.reserved == count && report.joined == count &&
										report.saved == (mode == 2U ? 0U : count)) ;
		// 第一結果をrequestで照合し、後続結果の保存順に依存しない。
		for( const auto &record : records) {
			// 解放故障を注入したjobだけを採点する。
			if( record.GetNamedString( L"request") == inputFactory( 1U).requestKeys[0]) {
				const auto io = record.GetNamedObject( L"io") ;	// 元個別診断。
				DRIVERCRATE_EXPECT(
					context, record.GetNamedNumber( L"error") == (mode == 1U ? 12030.0 : 403.0) &&
								 io.GetNamedString( L"cause") == L"HTTP" &&
								 io.GetNamedObject( L"native").GetNamedNumber( L"code") ==
									 (mode == 1U ? 12030.0 : 12002.0) &&
								 !io.GetNamedBoolean( L"nativeReleased")) ;
			}
		}
	}
}
/** @brief Run共有signalのSEND境界・先着規則を本番controlで検査します。
 * @param[in,out] context 同じ監督threadの集計。
 * @param[in] rootFactory 自作保護root生成。
 * @param[in] inputFactory 固定架空入力生成。
 */
void sharedCancellationCheckpoints(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorRecoveryInput( std::size_t)> &inputFactory)
{
	// SEND確定前後・COMPLETE先着・期限同時・clock異常同時を独立に試験する。
	for( unsigned mode = 0U; mode < 5U; ++mode) {
		CollectorHttpClockSample clock{TEST_UTC, 0U} ;						// 親だけが操作するclock。
		const auto signal = std::make_shared<std::atomic_bool>( false) ;	// 四controlより長いsignal。
		LocalCollectorStateStore store ;									// このscopeだけのwriter。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		LocalCollectorRecovery recovery ;	// 元の永続予約。
		DRIVERCRATE_EXPECT( context,
						   recovery.initialize( store, inputFactory( 1U), TEST_UTC, 0U) == 0U) ;
		CollectorHttpPermitPool pool( [&] { return clock ; }, signal) ;	// 本番と同じsignal接続。
		CollectorHttpPermit		permit ;								// 一回の元許可。
		DRIVERCRATE_EXPECT( context, pool.reserve( recovery, permit) == 0U) ;
		const auto control = permit.claim( &permit, *permit.binding()) ;	// 正規claim。
		DRIVERCRATE_EXPECT( context, control && control->begin( CollectorIoStage::SEND, 30000U) > 0U) ;
		// 必須前提が不成立なら未知pointerを使わず当条件を失敗へ残す。
		if( !control) {
			continue ;
		}

		// API呼出し確定が先行した二条件だけ一回の送信を観測する。
		if( mode == 1U || mode == 2U) {
			DRIVERCRATE_EXPECT( context, control->noteSendCall()) ;
		}

		// COMPLETEを先に確定すると後日の取消しでは変更しない。
		if( mode == 2U) {
			DRIVERCRATE_EXPECT( context, control->finish()) ;
		}

		// 同時の期限到達では取消し、時計巻戻しではCLOCKが優先する。
		if( mode == 3U) {
			clock = {TEST_UTC + 120000U, 120000U} ;
		}
		// Clock異常と取消しが同時なら欠測を補完しない。
		else if( mode == 4U) {
			clock = {TEST_UTC - 1U, 0U} ;
		}

		signal->store( true, std::memory_order_release) ;
		// In-flight成功read量は次停止checkpointより先に反映する。
		if( mode == 1U) {
			DRIVERCRATE_EXPECT( context, control->noteRead( 3U, 3U)) ;
			DRIVERCRATE_EXPECT( context, control->begin( CollectorIoStage::READ, 60000U) == 0U) ;
			control->fail( CollectorIoCause::HTTP,
						  {CollectorIoErrorDomain::WIN32_ERROR, 12030U, CollectorIoStage::READ},
						  true) ;
		}
		// 未呼出しSENDは通知後に実API計数へ進めない。
		else if( mode != 2U) {
			DRIVERCRATE_EXPECT( context, !control->noteSendCall()) ;
		}

		(void)control->finish() ;
		const auto io	 = control->snapshot() ;	// 元観測を親が検査する。
		const auto cause = mode == 2U	? CollectorIoCause::COMPLETE
						   : mode == 4U ? CollectorIoCause::CLOCK
										: CollectorIoCause::CANCELLED ;	// 先着。
		DRIVERCRATE_EXPECT( context, io.cause == cause && io.sealed &&
										io.sends == (mode == 1U || mode == 2U ? 1U : 0U) &&
										io.lowerBytes == (mode == 1U ? 3U : 0U)) ;
		// 停止中の原API失敗は先着取消しを上書きせず副診断へ残す。
		if( mode == 1U) {
			DRIVERCRATE_EXPECT( context, io.native && io.native->code == 12030U && !io.bytesKnown &&
											io.stopElapsedMillis == 0U) ;
		}
		// COMPLETE後は停止経過も新しく作らない。
		else if( mode == 2U) {
			DRIVERCRATE_EXPECT( context, !io.stopElapsedMillis && io.error.code == 0U) ;
		}
		// 時計欠測を架空の終了UTCへ補完しない。
		else if( mode == 4U) {
			DRIVERCRATE_EXPECT( context, !io.elapsedMillis && !io.finishedUtcMillis) ;
		}
	}
}
/** @brief 元終了時刻・遅延保存・欠測・元日精算を再開まで検査します。
 * @param[in,out] context 単一writerの集計。
 * @param[in] rootFactory 架空保護root生成。
 * @param[in] inputFactory 固定入力生成。
 */
void settlementTimeline( TestContext												 &context,
						const std::function<std::filesystem::path()>			 &rootFactory,
						const std::function<CollectorRecoveryInput( std::size_t)> &inputFactory)
{
	// 遅延正常・未知、期限三境界、UTC前進、欠測、日跨ぎ、HASH拒否を一度ずつ確認する。
	for( unsigned mode = 0U; mode < 9U; ++mode) {
		const auto start =
			mode == 7U ? ((TEST_UTC + 32400000U) / 86400000U + 1U) * 86400000U - 32400000U - 500U
					   : TEST_UTC ;									// 固定JST日境界の直前を使う。
		CollectorHttpClockSample clock{start, 0U} ;					// 親threadだけで操作する二clock。
		const auto input = inputFactory( mode == 7U ? 2U : 1U) ;	// 日跨ぎでは未予約も残す。
		LocalCollectorStateStore store ;							// 元writer。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		std::vector<std::pair<std::wstring, std::string>> originals ;	// 保存済み実byte。
		{
			LocalCollectorRecovery recovery ;	// 元日と開始の拘束。
			DRIVERCRATE_EXPECT( context, recovery.initialize( store, input, start, 0U) == 0U) ;
			CollectorHttpPermitPool pool( [&] { return clock ; }) ;	// Native時計へ補完しない。
			CollectorHttpPermit		permit ;						// 一回だけの元予約。
			DRIVERCRATE_EXPECT( context, pool.reserve( recovery, permit) == 0U) ;
			CollectorControlledHttpObservation http ;			// 未確定の同じ三byte観測。
			const auto control = executorGet( permit, http) ;	// Finish前に原時計を操作する。
			const auto elapsed = mode == 2U					? 119999U
								 : mode == 3U || mode == 5U ? 120000U
								 : mode == 4U				? 120001U
															: 1000U ;	// 期限直前・一致・以後。
			clock = {mode == 6U ? start - 1U : start + elapsed, mode == 5U ? 1000U : elapsed} ;
			// 途中READの原失敗は下限を保持して未知全量とする。
			if( mode == 1U) {
				control->fail( CollectorIoCause::HTTP,
							  {CollectorIoErrorDomain::WIN32_ERROR, 12030U, CollectorIoStage::READ},
							  true) ;
			}

			// CNG故障を実行したとはせず、HASH段階の拒否と既知量の保存を検査する。
			if( mode == 8U) {
				control->fail(
					CollectorIoCause::PARSER,
					{CollectorIoErrorDomain::PARSER, ERROR_INVALID_DATA, CollectorIoStage::HASH},
					false) ;
			}

			DRIVERCRATE_EXPECT( context, control->finish()) ;
			const auto initial	= control->snapshot() ;	// 元終了時計と先着原因。
			const auto expected = mode == 8U   ? CollectorIoCause::PARSER
								  : mode == 1U ? CollectorIoCause::HTTP
								  : mode == 6U ? CollectorIoCause::CLOCK
								  : mode >= 3U && mode <= 5U
									  ? CollectorIoCause::DEADLINE
									  : CollectorIoCause::COMPLETE ;	// Oracle。
			DRIVERCRATE_EXPECT( context,
							   initial.lowerBytes == 3U && initial.cause == expected &&
								   (mode == 6U
										? !initial.elapsedMillis && !initial.finishedUtcMillis
										: initial.elapsedMillis == (mode == 5U ? 1000U : elapsed) &&
											  initial.finishedUtcMillis == start + elapsed)) ;
			clock = {start + 125000U, 125000U} ;
			// 成否は元終了時刻で確定し、受領125秒へ期限を付け替えない。
			if( mode != 6U) {
				DRIVERCRATE_EXPECT(
					context,
					recovery.acceptControlled( *permit.binding(), response( initial, clock.utcMillis),
											  initial, clock.utcMillis, clock.steadyMillis) == 0U) ;
			}

			// 日跨ぎの開始済み精算後も同runの新予約は許可しない。
			if( mode == 7U) {
				CollectorRecoveryDispatch next ;	// 未予約の第二job。
				DRIVERCRATE_EXPECT( context, recovery.reserve( clock.utcMillis, clock.steadyMillis,
															 next) == ERROR_RETRY) ;
			}
		}
		std::vector<std::wstring> names ;	// 元応答だけを不変比較する。
		DRIVERCRATE_EXPECT( context, store.listRunNames( names) == 0U) ;
		// v3を元schemaで読む。欠測にv3が存在しないことも検査する。
		for( const auto &name : names) {
			// 補助fileを応答へ数えない。
			if( name.starts_with( L"campaign-response-v3-")) {
				originals.emplace_back( L"runs/" + name, body( store, L"runs/" + name)) ;
			}
		}

		DRIVERCRATE_EXPECT( context, originals.size() == (mode == 6U ? 0U : 1U)) ;
		LocalCollectorRecovery resumed ;	// 保存後／欠測後の独立した監督。
		DRIVERCRATE_EXPECT( context, resumed.initialize( store, input, start + 126000U, 0U) == 0U) ;
		// 保存された元応答を後日の時計で書き換えない。
		for( const auto &[name, bytes] : originals) {
			DRIVERCRATE_EXPECT( context, body( store, name) == bytes) ;
		}

		CollectorBudgetSnapshot budget ;	// 再開後も一回だけの精算。
		DRIVERCRATE_EXPECT(
			context,
			parseCollectorBudgetSnapshot( body( store, L"current/campaign-budget-v1.json"), budget) &&
				budget.day == L"20260927" && budget.reservations.size() == 1U &&
				budget.reservations[0].charged == (mode == 1U || mode == 6U ? 8388608U : 3U) &&
				budget.reservations[0].phase == (mode == 6U ? 2U : 1U)) ;
		// CLOCK欠測の再開はnull sends／bytesの旧INTERRUPTED一件であり、架空v3を作らない。
		if( mode == 6U) {
			DRIVERCRATE_EXPECT( context, store.listRunNames( names) == 0U) ;
			unsigned interrupted{} ;	// 元未回収予約の数。
			// Responseだけを元schemaで検査し、補助fileは数えない。
			for( const auto &name : names) {
				// 制御欠測をv3へ変換しない。
				if( name.starts_with( L"campaign-response-v3-")) {
					DRIVERCRATE_EXPECT( context, false) ;
				}

				// 保存済み旧中断は未知量を0へ丸めない。
				if( name.starts_with( L"campaign-response-v2-")) {
					const auto object =
						// 元本文。
						Object::Parse( winrt::to_hstring( body( store, L"runs/" + name))) ;
					++interrupted ;
					DRIVERCRATE_EXPECT( context,
									   object.GetNamedString( L"state") == L"INTERRUPTED" &&
										   object.GetNamedValue( L"sends").ValueType() ==
											   winrt::Windows::Data::Json::JsonValueType::Null &&
										   object.GetNamedValue( L"bytes").ValueType() ==
											   winrt::Windows::Data::Json::JsonValueType::Null) ;
				}
			}

			DRIVERCRATE_EXPECT( context, interrupted == 1U) ;
		}
	}
}
/** @brief 予約四窓の未開始とthread／entry例外の型付き回収を確認します。
 * @param[in,out] context 親threadの集計。
 * @param[in] rootFactory 自作root生成。
 * @param[in] inputFactory 元入力生成。
 */
void dispatchFailureBoundaries(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorRecoveryInput( std::size_t)> &inputFactory)
{
	// 三保存checkpoint・最終root実拒否・三原例外を独立rootで一度ずつ試す。
	for( unsigned mode = 0U; mode < 7U; ++mode) {
		LocalCollectorStateStore store ;	// 予約から回収までの単一writer。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		Microsoft::WRL::Wrappers::FileHandle blocked ;	// テスト自身のfileだけの一時拒否。
		LocalCollectorRecovery				 recovery ;	// Native DACLや通常fileを変更しない。
		DRIVERCRATE_EXPECT(
			context, recovery.initialize( store, inputFactory( 1U), TEST_UTC, 0U, [mode]( auto point) {
				return mode < 3U && point == (mode == 0U   ? CollectorRecoveryCheckpoint::RESERVED
											  : mode == 1U ? CollectorRecoveryCheckpoint::STARTED
														   : CollectorRecoveryCheckpoint::RUNNING) ;
			}) == 0U) ;
		// Root最終保存も元fileへのshare-delete拒否で通信許可前に失敗させる。
		if( mode == 3U) {
			blocked = Microsoft::WRL::Wrappers::FileHandle( CreateFileW(
				(store.root() / L"current/campaign-root-v2.json").c_str(), GENERIC_READ,
				FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)) ;
			DRIVERCRATE_EXPECT( context, blocked.IsValid()) ;
		}

		std::atomic_uint gets{} ;									// 元entryの実呼出し数だけを共有する。
		auto			 starter = collectorNativeThreadStarter() ;	// 通常の所有thread。
		// Allocation原失敗は予約後に送信0のSETUPへ精算する。
		if( mode == 4U) {
			starter = []( std::function<void()>) -> std::thread { throw std::bad_alloc() ; } ;
		}

		LocalCollectorExecutor executor(
			{[] { return CollectorHttpClockSample{TEST_UTC, 0U} ; },
			 [&]( std::size_t, const auto &, auto &, auto &) -> NativeError {
				 ++gets ;
				 // Worker例外も所有threadから外へ漏らさない。
				 if( mode == 5U) {
					 throw winrt::hresult_error( E_ACCESSDENIED) ;
				 }

				 throw std::bad_alloc() ;
			 },
			 std::move( starter)}) ;
		const auto report  = executor.run( recovery) ;		// 開始失敗でも元予約を一回閉じる。
		const auto records = executorResponses( store) ;	// 完了前にworker領域を読まない。
		const auto error =
			mode < 3U ? ERROR_OPERATION_ABORTED
			: mode == 3U
				? ERROR_ACCESS_DENIED
				: static_cast<DWORD>( mode == 5U ? E_ACCESSDENIED : E_OUTOFMEMORY) ;	// 原失敗。
		context.expect(
			report.outcome == CollectorExecutorOutcome::FAILED && report.error == error &&
				report.reserved == (mode < 4U ? 0U : 1U) &&
				report.started == (mode < 5U ? 0U : 1U) && report.joined == report.started &&
				report.saved == (mode < 4U ? 0U : 1U) && gets.load() == (mode < 5U ? 0U : 1U) &&
				records.size() == report.saved,
			"reservation fault " + std::to_string( mode) + " code=" + std::to_string( report.error),
			__FILE__, __LINE__) ;
		// 元例外のdomainと送信0はHRESULTを別codeへ丸めない。
		if( !records.empty()) {
			DRIVERCRATE_EXPECT(
				context, records[0].GetNamedString( L"errorDomain") == L"HRESULT" &&
							 records[0].GetNamedNumber( L"error") == error &&
							 records[0].GetNamedNumber( L"sends") == 0.0 &&
							 records[0].GetNamedObject( L"io").GetNamedString( L"cause") == L"SETUP") ;
		}
	}
}
/** @brief 四worker混在で本物のatomic保存拒否と第一error・全joinを確認します。
 * @param[in,out] context 親threadの集計。
 * @param[in] rootFactory 架空の専用root生成。
 * @param[in] inputFactory 固定入力生成。
 */
void nativeStoreFailure( TestContext												 &context,
						const std::function<std::filesystem::path()>			 &rootFactory,
						const std::function<CollectorRecoveryInput( std::size_t)> &inputFactory)
{
	ExecutorFixture			 fixture ;	// 同時四件の開始だけを共有する。
	LocalCollectorStateStore store ;	// Test専用の保護writer。
	DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
	Microsoft::WRL::Wrappers::FileHandle blocked ;		// 元budgetのatomic置換だけを拒否する。
	unsigned							 effects{} ;	// 保存失敗後の追加操作を検出する。
	unsigned							 applied{} ;	// CONTROL／JOB後のBUDGET拒否を確認する。
	LocalCollectorRecovery				 recovery ;		// Source／cacheは接続しない。
	DRIVERCRATE_EXPECT(
		context, recovery.initialize( store, inputFactory( 5U), TEST_UTC, 0U, [&]( auto point) {
			// 全予約の後、応答の前後像保存が成立した一度だけ実fileを保持する。
			if( point == CollectorRecoveryCheckpoint::EFFECTS) {
				++effects ;
				blocked = Microsoft::WRL::Wrappers::FileHandle( CreateFileW(
					(store.root() / L"current/campaign-budget-v1.json").c_str(), GENERIC_READ,
					FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)) ;
			}

			// 第一失敗以後に次commitへ進めば計数差として拒否する。
			if( point == CollectorRecoveryCheckpoint::APPLIED) {
				++applied ;
			}

			return false ;
		}) == 0U) ;
	// 未開始の第五jobへ進む前に第一store故障で受付を止める本番監督。
	LocalCollectorExecutor executor(
		{[&] { return fixture.sample() ; },
		 [&]( std::size_t index, const auto &, auto &permit, auto &http) -> NativeError {
			 fixture.enter( index, true) ;
			 (void)executorGet( permit, http) ;
			 return 0 ;
		 },
		 collectorNativeThreadStarter()}) ;
	const auto report = executor.run( recovery) ;	// 第五jobを開始せず四件を回収する。
	context.expect(
		fixture.valid.load() && blocked.IsValid() &&
			report.outcome == CollectorExecutorOutcome::FAILED &&
			report.error == ERROR_ACCESS_DENIED && report.reserved == 4U && report.started == 4U &&
			report.joined == 4U && report.saved == 0U && report.peakSlots == 4U && effects == 1U &&
			applied == 2U && executorResponses( store).size() == 1U,
		"native store code=" + std::to_string( report.error) + " applied=" + std::to_string( applied),
		__FILE__, __LINE__) ;
}
/** @brief 旧v2 domainと保存三層・登録前後のhash境界を分離します。
 * @param[in,out] context 単一writerの集計。
 * @param[in] rootFactory 自作root生成。
 * @param[in] inputFactory 固定元入力生成。
 */
void storageVersionBoundaries(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorRecoveryInput( std::size_t)> &inputFactory)
{
	// 未登録v2への二新domain、内側容量、登録前の型付き観測変更を独立rootへ注入する。
	for( unsigned mode = 0U; mode < 4U; ++mode) {
		LocalCollectorStateStore store ;	// 同じwriterの一件保存だけを変更する。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		const auto	 input = inputFactory( 1U) ;	// 全identityの元入力。
		std::wstring name ;							// 元応答一件の固定相対名。
		{
			LocalCollectorRecovery recovery ;	// 登録前の応答窓で止める。
			DRIVERCRATE_EXPECT( context,
							   recovery.initialize( store, input, TEST_UTC, 0U, []( auto point) {
								   return point == CollectorRecoveryCheckpoint::RESPONSE ;
							   }) == 0U) ;
			// 新domainの旧v2受入を本番acceptControlledの緩和と混同しない。
			if( mode < 2U) {
				CollectorRecoveryDispatch dispatch ;	// 旧accept用の非制御予約。
				DRIVERCRATE_EXPECT( context, recovery.reserve( TEST_UTC, 0U, dispatch) == 0U) ;
				CollectorRecoveryResponse saved ;	// 元v2では許されるWIN32原値。
				saved.state				= CollectorCampaignJobState::FAILED ;
				saved.finishedUtcMillis = TEST_UTC ;
				saved.acceptedUtcMillis = TEST_UTC ;
				saved.sentRequests		= 1U ;
				saved.bytesKnown		= true ;
				saved.receivedBytes		= 3U ;
				saved.status			= 200U ;
				saved.error				= ERROR_INVALID_DATA ;
				saved.errorDomain		= L"WIN32" ;
				DRIVERCRATE_EXPECT( context, recovery.accept( 0U, saved, TEST_UTC, 0U) ==
												ERROR_OPERATION_ABORTED) ;
			} else {
				CollectorHttpPermitPool pool(
					[] { return CollectorHttpClockSample{TEST_UTC, 0U} ; }) ;	// 同じ時計。
				CollectorHttpPermit permit ;									// 元の制御許可。
				DRIVERCRATE_EXPECT( context, pool.reserve( recovery, permit) == 0U) ;
				const auto control = completed( context, permit) ;	// 登録前の型付き原観測。
				DRIVERCRATE_EXPECT(
					context, recovery.acceptControlled(
								 *permit.binding(), response( control->snapshot(), TEST_UTC),
								 control->snapshot(), TEST_UTC, 0U) == ERROR_OPERATION_ABORTED) ;
			}

			std::vector<std::wstring> names ;	// 過去の任意応答を使わない。
			DRIVERCRATE_EXPECT( context, store.listRunNames( names) == 0U) ;
			// 元operationに一意の応答名を探す。
			for( const auto &entry : names) {
				// schemaに対応した元応答だけを故障対象にする。
				if( entry.starts_with( mode < 2U ? L"campaign-response-v2-"
											   : L"campaign-response-v3-")) {
					name = L"runs/" + entry ;
				}
			}
		}
		const auto beforeBudget =
			// 拒否前の未精算像。
			body( store, L"current/campaign-budget-v1.json") ;
		auto object = Object::Parse( winrt::to_hstring( body( store, name))) ;	// 構造を保持した故障。
		// 新domainだけを旧形式へ注入しても旧decoderが拒否する。
		if( mode < 2U) {
			object.Insert( L"errorDomain",
						  Value::CreateStringValue( mode == 0U ? L"HRESULT" : L"WINSOCK")) ;
		}

		// 同じuserの型付き未登録変更を署名付き改ざん検知とは表現しない。
		if( mode == 3U) {
			object.GetNamedObject( L"io").Insert( L"elapsed", Value::CreateNumberValue( 1.0)) ;
		}

		const auto changed =
			mode == 2U ? std::string( 768U * 1024U + 1U, 'x')
					   : winrt::to_string( object.Stringify()) ;	// 外側上限とは別の内側本文。
		writeBody( store, name, changed) ;
		LocalCollectorRecovery resumed ;	// 元inputとの結合は常に維持する。
		DRIVERCRATE_EXPECT( context,
						   resumed.initialize( store, input, TEST_UTC + 2000U, 100U) ==
							   static_cast<DWORD>( mode == 3U ? ERROR_SUCCESS : ERROR_INVALID_DATA)) ;
		DRIVERCRATE_EXPECT(
			context,
			body( store, name) == changed &&
				(mode == 3U || body( store, L"current/campaign-budget-v1.json") == beforeBudget)) ;
	}

	LocalCollectorStateStore outer ;	// 単純file上限の独立root。
	DRIVERCRATE_EXPECT( context, outer.initialize( rootFactory(), true) == 0U) ;
	const std::string limit( 2U * 1024U * 1024U, 'x') ;	// 外側fileのbyte上限ちょうど。
	DRIVERCRATE_EXPECT( context, outer.write( L"runs/size-layer.json", limit) == 0U &&
									outer.write( L"runs/size-layer.json", limit + "x") ==
										ERROR_INVALID_PARAMETER) ;
	std::string raw ;		// 拒否後に元fileの完全byteを読む。
	bool		found{} ;	// 欠測を一致へ変換しない。
	DRIVERCRATE_EXPECT( context, outer.read( L"runs/size-layer.json", raw, found) == 0U && found &&
									raw == limit) ;
}
/** @brief 同group待ち・別group進行・通知取消しとclock照会上限を検査します。
 * @param[in,out] context 親threadの集計。
 * @param[in] rootFactory 自作root生成。
 * @param[in] inputFactory 固定入力生成。
 */
void executorWaitBoundaries( TestContext												 &context,
							const std::function<std::filesystem::path()>			 &rootFactory,
							const std::function<CollectorRecoveryInput( std::size_t)> &inputFactory)
{
	// 通常間隔と独立group、長期DEFERRED、短期待機の取消しを一度ずつ測る。
	for( unsigned mode = 0U; mode < 3U; ++mode) {
		auto input = inputFactory( mode == 0U ? 3U : 2U) ;	// 第二jobだけ同groupにする。
		input.sources[1].rateLimitGroup = input.sources[0].rateLimitGroup ;
		LocalCollectorStateStore store ;	// 親threadだけの台帳。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		std::atomic_uint64_t   elapsed{} ;		// 共有値だけをdriverから変える。
		std::atomic_uint	   clockCalls{} ;	// Controlも含む全clock callback呼出し数。
		AcceptanceGate		   gate ;			// 回収後の順序と有限通知。
		LocalCollectorRecovery recovery ;		// 第一jobの精算を先に固定する。
		DRIVERCRATE_EXPECT( context,
						   recovery.initialize( store, input, TEST_UTC, 0U, [&]( auto point) {
							   // 第一seedも含め完了保存済みの件数だけを通知する。
							   if( point == CollectorRecoveryCheckpoint::COMPLETED) {
								   const std::lock_guard lock( gate.mutex) ;
								   ++gate.ended ;
								   gate.changed.notify_all() ;
							   }

							   return false ;
						   }) == 0U) ;
		{
			CollectorHttpPermitPool pool( [&] {
				return CollectorHttpClockSample{TEST_UTC + elapsed.load(), elapsed.load()} ;
			}) ;								// 元clock。
			CollectorHttpPermit		permit ;	// 第一jobだけを予約する。
			DRIVERCRATE_EXPECT( context, pool.reserve( recovery, permit) == 0U) ;
			CollectorControlledHttpObservation http ;									// 通信しないseed観測。
			const auto						   control = executorGet( permit, http) ;	// 固定三byte。
			elapsed.store( 1000U) ;
			// 429は24時間のgroup待機を元終了へ固定する。
			if( mode == 1U) {
				control->fail( CollectorIoCause::HTTP,
							  {CollectorIoErrorDomain::HTTP, 429U, CollectorIoStage::HEADERS},
							  false) ;
			}

			DRIVERCRATE_EXPECT( context, control->finish()) ;
			auto seed = response( control->snapshot(), TEST_UTC + 1000U) ;	// 元受領。
			// Helperの通常200だけを元HTTP429に結合する。
			if( mode == 1U) {
				seed.status		 = 429U ;
				seed.errorDomain = L"HTTP" ;
			}

			DRIVERCRATE_EXPECT( context, recovery.acceptControlled( *permit.binding(), seed,
																  control->snapshot(),
																  TEST_UTC + 1000U, 1000U) == 0U) ;
		}
		elapsed.store( 1999U) ;
		std::vector<std::size_t> order ;	// Gate mutexでworker間のGET開始順を公開する。
		LocalCollectorExecutor	 executor(
			  {[&] {
				   ++clockCalls ;
				   gate.changed.notify_all() ;
				   const auto value = elapsed.load() ;	// Clock対を一回の読取りへ固定する。
				   return CollectorHttpClockSample{TEST_UTC + value, value} ;
			   },
			   [&]( std::size_t index, const auto &, auto &permit, auto &http) -> NativeError {
				   {
					   const std::lock_guard lock( gate.mutex) ;
					   order.push_back( index) ;
				   }
				   (void)executorGet( permit, http) ;
				   return 0 ;
			   },
			   collectorNativeThreadStarter()}) ;
		std::thread driver ;	// 長期延期条件だけは別threadを作らない。
		// 第一照会または別groupの保存後にだけ待機解除を通知する。
		if( mode != 1U) {
			driver = std::thread( [&] {
				{
					std::unique_lock lock( gate.mutex) ;
					(void)gate.wait( lock, [&] {
						return mode == 0U ? gate.ended >= 2U : clockCalls.load() != 0U ;
					}) ;
				}
				std::this_thread::sleep_for(
					// 実wait中のbusy-loop検出窓。
					std::chrono::milliseconds( 100)) ;
				// 短期待機取消しは公開signalとnotifyだけを使う。
				if( mode == 2U) {
					executor.requestStop() ;
				} else {
					elapsed.store( 3000U) ;
				}
			}) ;
		}

		const auto began  = std::chrono::steady_clock::now() ;	// 取消し通知の有限回収対照。
		const auto report = executor.run( recovery) ;			// 待機時も同じwriterを維持する。
		// 通知元を回収してから共有値を読む。
		if( driver.joinable()) {
			driver.join() ;
		}

		DRIVERCRATE_EXPECT(
			context, gate.valid.load() && report.error == 0U && clockCalls.load() < 100U &&
						 report.reserved == (mode == 0U ? 2U : 0U) &&
						 report.started == report.reserved && report.saved == report.reserved &&
						 report.joined == report.started &&
						 report.outcome == (mode == 0U	 ? CollectorExecutorOutcome::TERMINAL
											: mode == 1U ? CollectorExecutorOutcome::DEFERRED
														 : CollectorExecutorOutcome::CANCELLED)) ;
		// 同groupの未予約第二jobを待たせても独立groupは先に処理する。
		if( mode == 0U) {
			DRIVERCRATE_EXPECT( context, order == std::vector<std::size_t>( {2U, 1U})) ;
		}

		// 500ms pollingだけに依存せず、signal通知から二秒内に終了する。
		if( mode == 2U) {
			DRIVERCRATE_EXPECT( context,
							   std::chrono::steady_clock::now() - began < std::chrono::seconds( 2)) ;
		}
	}
}
} // namespace
/** @see local_collector_executor_tests.h */
void runCollectorExecutorAcceptanceTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorRecoveryInput( std::size_t)> &inputFactory)
{
	cancellationSaveWindows( context, rootFactory, inputFactory) ;
	cleanupDiagnostics( context, rootFactory, inputFactory) ;
	sharedCancellationCheckpoints( context, rootFactory, inputFactory) ;
	settlementTimeline( context, rootFactory, inputFactory) ;
	dispatchFailureBoundaries( context, rootFactory, inputFactory) ;
	nativeStoreFailure( context, rootFactory, inputFactory) ;
	storageVersionBoundaries( context, rootFactory, inputFactory) ;
	executorWaitBoundaries( context, rootFactory, inputFactory) ;
}
} // namespace drivercrate::test
