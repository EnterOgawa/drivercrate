//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_start.cpp
 * @brief 専用開始intentをinput再構築と固定schemaで検査します。
 * @version 01.00.02
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  専用開始intentの厳密codecを追加。
 * Ver.01.00.01 Shunji Ogawa  2026/09/28  元inputのscopeをdispatchへ復元。
 * Ver.01.00.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 本codecは保存・HTTP・予約を行いません。
 */
//------------------------------------------------------------------------------
#include "platform/local_collector_projected_start.h"
#include "platform/local_collector_projected_input.h"
#include "platform/local_collector_recovery.h"

#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#include <cmath>
#include <chrono>
#include <cwchar>
#include <cstdint>
#include <stdexcept>
#include <utility>

namespace drivercrate {
namespace {
/**
 * @brief JSON objectをWinRT参照で保持する。Copyは同じobjectを共有し、schema検証は利用側で行う。
 */
using Object = winrt::Windows::Data::Json::JsonObject ;
/**
 * @brief JSON値をWinRT参照で保持する。所有byteの検証と型判定はreader側で行う。
 */
using Value = winrt::Windows::Data::Json::JsonValue ;
// JSONの整数表現と既存UTC境界を共用する。
constexpr std::uint64_t MAXIMUM_INTEGER = 9007199254740991ULL ;
// 2100年未満のUTC millisecond。
constexpr std::uint64_t LAST_UTC = 4102444799999ULL ;

/** @brief JSONから精度を失わない非負整数だけを読みます。
 * @param[in] object 元object。
 * @param[in] name 固定field名。
 * @return 53bit以内の整数。範囲外は例外でcodec全体を拒否します。
 */
std::uint64_t			number( const Object &object, const wchar_t *name)
{
	const auto value = object.GetNamedNumber( name) ;	// 狭小化前の元値。
	// NaN・小数・巨大整数を別の時刻へ丸めない。
	if( !std::isfinite( value) || value < 0.0 || value > static_cast<double>( MAXIMUM_INTEGER) ||
	   std::floor( value) != value) {
		throw std::invalid_argument( "projected start integer") ;
	}

	return static_cast<std::uint64_t>( value) ;
}

/** @brief 入力実byteからjob結合を作り、時刻だけ元値を保持します。
 * @param[in] identity 登録input。
 * @param[in] candidate 時刻とjob indexを含む照合対象。
 * @param[out] bound 全再構築したjob結合。
 * @param[out] scope 元jobの全対象hash。
 * @return 全inputと時計が整合する場合true。
 */
bool bindStart( const CollectorProjectedCampaignIdentity &identity,
			   const CollectorRecoveryDispatch &candidate, CollectorRecoveryDispatch &bound,
			   std::wstring &scope)
{
	CollectorProjectedCampaignDefinition definition ;	// 保存sourceはbuilderで再照合する。
	CollectorProjectedCampaignIdentity	 checked ;		// 可変DTOのjobを直接信用しない。
	// 元入力とGを再構築し、範囲外job・旧modeを拒否する。
	if( !parseCollectorProjectedCampaignIdentity( identity.canonicalInput, definition, checked) ||
	   checked.inputSha256 != identity.inputSha256 ||
	   checked.generationKey != identity.generationKey ||
	   candidate.mode != CollectorRecoveryDispatch::Mode::PROJECTED ||
	   candidate.jobIndex >= checked.jobs.size()) {
		return false ;
	}

	const auto &job = checked.jobs[candidate.jobIndex] ;	// 固定順の全対象job。
	// 秒境界・UTC上限・有限deadline・単調残時間を検査する。
	if( candidate.startedUtcMillis < 1000U || candidate.anchorUtcMillis > LAST_UTC ||
	   candidate.startedUtcMillis != candidate.anchorUtcMillis / 1000U * 1000U ||
	   candidate.deadlineUtcMillis <= candidate.anchorUtcMillis ||
	   candidate.deadlineUtcMillis > LAST_UTC ||
	   candidate.deadlineUtcMillis - candidate.startedUtcMillis > 120000U ||
	   candidate.deadlineSteadyMillis > MAXIMUM_INTEGER ||
	   candidate.deadlineSteadyMillis < candidate.anchorSteadyMillis ||
	   candidate.deadlineSteadyMillis - candidate.anchorSteadyMillis !=
		   candidate.deadlineUtcMillis - candidate.anchorUtcMillis) {
		return false ;
	}

	const auto date = std::chrono::year_month_day( std::chrono::floor<std::chrono::days>(
		std::chrono::sys_time<std::chrono::milliseconds>(
			std::chrono::milliseconds( candidate.anchorUtcMillis)) +
		// 元予約がinputのJST日に属するかを検査する。
		std::chrono::hours( 9))) ;
	wchar_t	   dateText[9]{} ;	// 固定8桁の年月日。
	swprintf_s( dateText, L"%04d%02u%02u", static_cast<int>( date.year()),
			   static_cast<unsigned>( date.month()), static_cast<unsigned>( date.day())) ;
	// 保存inputの開始日を越えた予約は同じ世代へ追加しない。
	if( Object::Parse( winrt::to_hstring( checked.canonicalInput)).GetNamedString( L"day") !=
	   dateText) {
		return false ;
	}

	bound				= candidate ;
	bound.generationKey = checked.generationKey ;
	bound.jobKey		= job.jobKey ;
	bound.requestKey	= job.requestKey ;
	bound.cacheBinding	= job.cacheBinding ;
	bound.scopeSha256	= job.scopeSha256 ;
	bound.source		= job.source ;
	scope				= job.scopeSha256 ;
	return true ;
}
} // namespace

/** @see local_collector_projected_start.h */
bool encodeCollectorProjectedStart( const CollectorProjectedCampaignIdentity &identity,
								   const CollectorRecoveryDispatch &dispatch, std::string &body)
{
	body.clear() ;
	try {
		CollectorRecoveryDispatch bound ;	// 元inputからの全field照合。
		std::wstring			  scope ;	// 同じ共有jobの全対象hash。
		// 呼出し側の任意sourceやscopeを保存しない。
		if( !bindStart( identity, dispatch, bound, scope) ||
		   !sameCollectorRecoveryDispatch( bound, dispatch)) {
			return false ;
		}

		Object	   root ;	// 固定field順でのみ作る専用intent。
		const auto text = [&]( const wchar_t *name, const std::wstring_view value) {
			root.Insert( name, Value::CreateStringValue( winrt::hstring( value))) ;
		} ; // 同期scope内だけでJSONへ書く。
		const auto integer = [&]( const wchar_t *name, const std::uint64_t value) {
			root.Insert( name, Value::CreateNumberValue( static_cast<double>( value))) ;
		} ; // 値は上で有限検査済み。
		text( L"schema", L"collector-campaign-start-v3") ;
		text( L"profile", L"METADATA_PROJECTION_V1") ;
		integer( L"responseVersion", 4U) ;
		text( L"generation", bound.generationKey) ;
		text( L"inputHash", identity.inputSha256) ;
		text( L"scope", scope) ;
		integer( L"index", bound.jobIndex) ;
		text( L"job", bound.jobKey) ;
		text( L"request", bound.requestKey) ;
		text( L"cache", bound.cacheBinding) ;
		integer( L"started", bound.startedUtcMillis) ;
		integer( L"anchorUtc", bound.anchorUtcMillis) ;
		integer( L"anchorSteady", bound.anchorSteadyMillis) ;
		integer( L"deadlineUtc", bound.deadlineUtcMillis) ;
		integer( L"deadlineSteady", bound.deadlineSteadyMillis) ;
		body = winrt::to_string( root.Stringify()) ;
		return true ;
	} catch( ...) {
		body.clear() ;
		return false ;
	}
}

/** @see local_collector_projected_start.h */
bool parseCollectorProjectedStart( const CollectorProjectedCampaignIdentity &identity,
								  const std::string_view body, CollectorRecoveryDispatch &dispatch)
{
	dispatch = {} ;
	try {
		// 不正UTF-8を含む保存byteは再符号化比較で拒否する。
		if( body.empty() || body.size() > 4096U || body.find( '\0') != std::string_view::npos) {
			return false ;
		}

		const auto				  root = Object::Parse( winrt::to_hstring( body)) ;	// 元intent。
		CollectorRecoveryDispatch candidate ;										// 復号は送信許可ではない。
		candidate.mode				   = CollectorRecoveryDispatch::Mode::PROJECTED ;
		candidate.jobIndex			   = number( root, L"index") ;
		candidate.startedUtcMillis	   = number( root, L"started") ;
		candidate.anchorUtcMillis	   = number( root, L"anchorUtc") ;
		candidate.anchorSteadyMillis   = number( root, L"anchorSteady") ;
		candidate.deadlineUtcMillis	   = number( root, L"deadlineUtc") ;
		candidate.deadlineSteadyMillis = number( root, L"deadlineSteady") ;
		CollectorRecoveryDispatch bound ;		// 入力から復元するsource／job結合。
		std::wstring			  scope ;		// 全対象scope。
		std::string				  canonical ;	// 全fieldの再符号化byte。
		// schema・profile・必須response version・scope・未知fieldも完全比較する。
		if( !bindStart( identity, candidate, bound, scope) ||
		   !encodeCollectorProjectedStart( identity, bound, canonical) || canonical != body) {
			return false ;
		}

		dispatch = std::move( bound) ;
		return true ;
	} catch( ...) {
		dispatch = {} ;
		return false ;
	}
}
} // namespace drivercrate
