//------------------------------------------------------------------------------
/**
 * @file local_collector_http_observation.cpp
 * @brief 観測の固定field・原値・欠測を厳密に保存します。
 * @version 01.00.02
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
 * Ver.01.00.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.00.02 Shunji Ogawa  2026/10/24  必須解析の型・有限所有buffer・失敗制御を明示。
 * </pre>
 *
 * @note 開発用の有限収集に限定し、製品の取得・導入を許可しません。
 * @see docs/adr/0218-collector-controlled-http-lifetime.md
 */
//------------------------------------------------------------------------------
#include "local_collector_http_observation.h"
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#include <algorithm>
#include <array>
#include <cmath>
#include <limits>
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
/**
 * @brief JSON値の実種別を表し、schemaで要求する型との一致を検査する。
 */
using Kind = winrt::Windows::Data::Json::JsonValueType ;
// 固定enumの保存表現。内部enum ordinalと照合します。
constexpr std::array<std::wstring_view, 12> CAUSES{
	L"NONE",	   L"COMPLETE",		   L"CANCELLED", L"DEADLINE", L"DNS",		  L"HTTP",
	L"BODY_LIMIT", L"BODY_INCOMPLETE", L"PARSER",	 L"SETUP",	  L"SHARED_STOP", L"CLOCK"} ;
// 保存するstageはAPIの有限段階だけです。
constexpr std::array<std::wstring_view, 15> STAGES{
	L"RESERVATION", L"SETUP",  L"DNS",	L"OPEN",  L"SEND",	  L"RECEIVE", L"HEADERS", L"QUERY",
	L"READ",		L"DECODE", L"HASH", L"PARSE", L"PROJECT", L"CLEANUP", L"COMPLETE"} ;
// 原native値を持つdomainだけを保存します。
constexpr std::array<std::wstring_view, 3> DOMAINS{L"WIN32", L"WINSOCK", L"HRESULT"} ;
/** @brief 固定形式の不成立をcodec内で拒否します。
 * @param[in] valid 許可条件。
 */
void									   require( bool valid)
{
	// 同じcodec出口で空結果へ収束させる。
	if( !valid) {
		throw std::invalid_argument( "collector io observation") ;
	}
}
/** @brief 正確な非負整数を読みます。
 * @param[in] object 型付きobject。
 * @param[in] name 固定field名。
 * @return 2の53乗未満の整数。
 */
std::uint64_t number( const Object &object, const wchar_t *name)
{
	const double value = object.GetNamedNumber( name) ;	// JSON numberの元値。
	require( std::isfinite( value) && value >= 0.0 && value < 9007199254740992.0 &&
			std::floor( value) == value) ;
	return static_cast<std::uint64_t>( value) ;
}
/** @brief 欠測と実測0を区別して読みます。
 * @param[in] object 型付きobject。
 * @param[in] name 固定field名。
 * @return Nullの場合だけnullopt。
 */
std::optional<std::uint64_t> optionalNumber( const Object &object, const wchar_t *name)
{
	// 欠損fieldはGetNamedValueが拒否する。
	if( object.GetNamedValue( name).ValueType() == Kind::Null) {
		return std::nullopt ;
	}

	return number( object, name) ;
}
/** @brief 正確な整数または明示nullを保存します。
 * @param[in,out] object 保存先。
 * @param[in] name 固定field名。
 * @param[in] value 有限値または欠測。
 */
void putNumber( const Object &object, const wchar_t *name, std::optional<std::uint64_t> value)
{
	require( !value || *value < 9007199254740992ULL) ;
	object.Insert( name, value ? Value::CreateNumberValue( static_cast<double>( *value))
							  : Value::CreateNullValue()) ;
}
/** @brief 固定列挙値を保存名へ変換します。
 * @tparam N 固定表の件数。
 * @param[in] values 保存名の表。
 * @param[in] value 有限ordinal。
 * @return 元表の借用名。
 */
template <std::size_t N>
std::wstring_view named( const std::array<std::wstring_view, N> &values, std::size_t value)
{
	// 未定義ordinalは元codecと同じ例外で止め、表の範囲外を参照しない。
	if( value >= N) {
		throw std::invalid_argument( "collector io observation") ;
	}

	return values[value] ;
}
/** @brief 未知名を拒否してordinalを読みます。
 * @tparam N 固定表の件数。
 * @param[in] values 保存名の表。
 * @param[in] object 型付きobject。
 * @param[in] field 固定field。
 * @return 元表内のordinal。
 */
template <std::size_t N>
std::size_t ordinal( const std::array<std::wstring_view, N> &values, const Object &object,
					const wchar_t *field)
{
	const std::wstring value( object.GetNamedString( field)) ;						// 任意文字列を後段へ渡さない。
	const auto		   found = std::find( values.begin(), values.end(), value) ;	// 完全一致。
	require( found != values.end()) ;
	return static_cast<std::size_t>( std::distance( values.begin(), found)) ;
}
/** @brief Native専用domainのordinalを求めます。
 * @param[in] domain 元domain。
 * @return 有限表のindex。
 */
std::size_t nativeOrdinal( CollectorIoErrorDomain domain)
{
	require( domain == CollectorIoErrorDomain::WIN32_ERROR ||
			domain == CollectorIoErrorDomain::WINSOCK_ERROR ||
			domain == CollectorIoErrorDomain::HRESULT_ERROR) ;
	return static_cast<std::size_t>( domain) - 1U ;
}
} // namespace
/** @see local_collector_http_observation.h */
bool encodeCollectorHttpObservation( const CollectorIoSnapshot &observation,
									std::wstring_view permit, std::string &bytes)
{
	bytes.clear() ;
	try {
		require( permit.size() == 64U && std::all_of( permit.begin(), permit.end(), []( wchar_t c) {
					return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') ;
				})) ;
		require( observation.sealed && observation.cause != CollectorIoCause::NONE) ;
		require( observation.deadlineUtcMillis >= 1000U &&
				observation.deadlineUtcMillis <= 4102444799999ULL) ;
		require( !observation.headerUtcMillis || *observation.headerUtcMillis <= 4102444799999ULL) ;
		require( !observation.stopElapsedMillis ||
				(observation.elapsedMillis &&
				 *observation.stopElapsedMillis <= *observation.elapsedMillis)) ;
		Object object ;	// 有限fieldの新object。
		object.Insert( L"schema", Value::CreateStringValue( L"collector-http-observation-v1")) ;
		object.Insert( L"permit", Value::CreateStringValue( winrt::hstring( permit))) ;
		putNumber( object, L"deadline", observation.deadlineUtcMillis) ;
		putNumber( object, L"elapsed", observation.elapsedMillis) ;
		putNumber( object, L"headerUtc", observation.headerUtcMillis) ;
		object.Insert( L"cause", Value::CreateStringValue( winrt::hstring(
									named( CAUSES, static_cast<std::size_t>( observation.cause))))) ;
		object.Insert( L"stage", Value::CreateStringValue( winrt::hstring(
									named( STAGES, static_cast<std::size_t>( observation.stage))))) ;
		object.Insert( L"native", Value::CreateNullValue()) ;
		// 原API失敗は最初の一件だけを保存する。
		if( observation.native) {
			Object native ;	// 元bit patternと段階だけ。
			native.Insert( L"domain", Value::CreateStringValue( winrt::hstring( named(
										 DOMAINS, nativeOrdinal( observation.native->domain))))) ;
			putNumber( native, L"code", observation.native->code) ;
			native.Insert( L"stage",
						  Value::CreateStringValue( winrt::hstring(
							  named( STAGES, static_cast<std::size_t>( observation.native->stage))))) ;
			object.Insert( L"native", native) ;
		}

		putNumber( object, L"lowerBytes", observation.lowerBytes) ;
		putNumber( object, L"stopElapsed", observation.stopElapsedMillis) ;
		object.Insert( L"nativeReleased", Value::CreateBooleanValue( observation.nativeReleased)) ;
		std::string encoded = winrt::to_string( object.Stringify()) ;	// Canonical UTF-8。
		require( encoded.size() <= 4096U) ;
		bytes = std::move( encoded) ;
		return true ;
	} catch( ...) {
		return false ;
	}
}
/** @see local_collector_http_observation.h */
bool decodeCollectorHttpObservation( std::string_view bytes, std::wstring_view permit,
									CollectorIoSnapshot &observation)
{
	observation = {} ;
	try {
		require( bytes.size() <= 4096U && bytes.find( '\0') == std::string_view::npos) ;
		const auto object = Object::Parse( winrt::to_hstring( bytes)) ;	// 最大objectの型付き復号。
		CollectorIoSnapshot decoded ;									// 成功確定まで呼出し側へ出さない。
		require( std::wstring_view( object.GetNamedString( L"schema")) ==
				L"collector-http-observation-v1") ;
		require( std::wstring_view( object.GetNamedString( L"permit")) == permit) ;
		decoded.deadlineUtcMillis = number( object, L"deadline") ;
		decoded.elapsedMillis	  = optionalNumber( object, L"elapsed") ;
		decoded.headerUtcMillis	  = optionalNumber( object, L"headerUtc") ;
		decoded.cause = static_cast<CollectorIoCause>( ordinal( CAUSES, object, L"cause")) ;
		decoded.stage = static_cast<CollectorIoStage>( ordinal( STAGES, object, L"stage")) ;
		// API副診断の欠測を数値0へ補完しない。
		if( object.GetNamedValue( L"native").ValueType() != Kind::Null) {
			const auto native = object.GetNamedObject( L"native") ;	// 三field以外を拒否する。
			require( native.Size() == 3U &&
					number( native, L"code") <= std::numeric_limits<std::uint32_t>::max()) ;
			decoded.native = CollectorIoError{
				static_cast<CollectorIoErrorDomain>( ordinal( DOMAINS, native, L"domain") + 1U),
				static_cast<std::uint32_t>( number( native, L"code")),
				static_cast<CollectorIoStage>( ordinal( STAGES, native, L"stage"))} ;
		}

		decoded.lowerBytes		  = number( object, L"lowerBytes") ;
		decoded.stopElapsedMillis = optionalNumber( object, L"stopElapsed") ;
		decoded.nativeReleased	  = object.GetNamedBoolean( L"nativeReleased") ;
		decoded.sealed			  = true ;
		std::string canonical ;	// Field・型・順序・重複を再出力と比較する。
		require( encodeCollectorHttpObservation( decoded, permit, canonical) && canonical == bytes) ;
		observation = decoded ;
		return true ;
	} catch( ...) {
		return false ;
	}
}
} // namespace drivercrate
