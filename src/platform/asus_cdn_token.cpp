//------------------------------------------------------------------------------
/**
 * @file asus_cdn_token.cpp
 * @brief 保存一次仕様の匿名CDN文脈とresponseを非永続で解決する。
 * @version 01.00.01
 * @date 2026/11/03
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/03  二段encodingと有限epoch/string文法を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 * @note HTTPを開始せず、公開文脈の構築とsession限定responseの解釈だけを行う。
 */
//------------------------------------------------------------------------------
#include "platform/official_cdn_token.h"
#include <Windows.h>
#include <algorithm>
#include <cmath>
#include <new>
#include <utility>
#include <winrt/Windows.Data.Json.h>

namespace drivercrate {
namespace {
constexpr std::uint64_t		MAXIMUM_EPOCH = 253402300799ULL ;	// 製品UTC年9999の最終秒。
constexpr std::wstring_view PAYLOAD_ORIGIN =
	L"https://dlcdnta.asus.com" ;	// 保存一次JSのGlobal起点。
constexpr std::wstring_view ENDPOINT =
	L"https://cdnta.asus.com/api/v1/TokenHQ?filePath=" ;	// metadata起点。
//------------------------------------------------------------------------------
/**
 * @brief 公開ASCII英数字だけを検査する。
 * @param[in] c 原一文字。
 * @return ASCII英数字ならtrue。
 */
//------------------------------------------------------------------------------
bool alphaNumeric( const wchar_t c) noexcept
{
	return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9') ;
}
//------------------------------------------------------------------------------
/**
 * @brief ECMAScript両encodingの共通safe文字を検査する。
 * @param[in] c 原ASCII文字。
 * @return encodeURIComponentが維持する場合true。
 */
//------------------------------------------------------------------------------
bool componentSafe( const wchar_t c) noexcept
{
	return alphaNumeric( c) || std::wstring_view( L"-_.!~*'()").find( c) != std::wstring_view::npos ;
}
//------------------------------------------------------------------------------
/**
 * @brief ASCII原URLを保存一次JSのsafe集合でencodeする。
 * @param[in] text 固定grammar内のASCII原値。
 * @param[in] component trueは第二段でcolonだけを戻す。
 * @return 原caseを維持したpercent表現。
 */
//------------------------------------------------------------------------------
std::wstring encode( const std::wstring_view text, const bool component)
{
	constexpr std::wstring_view HEX = L"0123456789ABCDEF" ;	// JSと同じupper hex。
	std::wstring				value ;						// 公開metadata request用の非秘密値。
	// 原byteの表現を追加し、decode/re-encodeで意味を変えない。
	for( const auto c : text) {
		const bool safe =
			componentSafe( c) || (component ? c == L':'
										   : std::wstring_view( L";/?:@&=+$,#").find( c) !=
												 std::wstring_view::npos) ;	// 各段のsafe集合。
		// safe文字は原caseで保つ。
		if( safe) {
			value.push_back( c) ;
		} else {
			value.push_back( L'%') ;
			value.push_back( HEX[(static_cast<unsigned>( c) >> 4U) & 15U]) ;
			value.push_back( HEX[static_cast<unsigned>( c) & 15U]) ;
		}
	}

	return value ;
}
//------------------------------------------------------------------------------
/**
 * @brief 変換済みsignatureの有限envelopeを検査する。
 * @param[in] value response原文字列。
 * @return queryを構造変更しない現protocol文字だけならtrue。
 */
//------------------------------------------------------------------------------
bool signatureGrammar( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= 1024U &&
		   std::ranges::all_of( value, []( const wchar_t c) {
			   return alphaNumeric( c) || c == L'-' || c == L'_' || c == L'~' ;
		   }) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 現公開key identifierの有限文法を検査する。
 * @param[in] value response原key。
 * @return 非空ASCII英数字ならtrue。
 */
//------------------------------------------------------------------------------
bool keyGrammar( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= 128U && std::ranges::all_of( value, alphaNumeric) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原十進stringを単位推測せずUTC Unix秒へchecked変換する。
 * @param[in] text JSON stringの元内容。
 * @param[out] value 成功時の元整数。
 * @return canonical grammarと製品UTC範囲内ならtrue。
 */
//------------------------------------------------------------------------------
bool epochString( const std::wstring_view text, std::uint64_t &value) noexcept
{
	value = 0U ;
	// 空・過大・leading zeroをcoerceしない。
	if( text.empty() || text.size() > 12U || (text.size() > 1U && text.front() == L'0')) {
		return false ;
	}

	// 桁ごとの上限を加算前に検査する。
	for( const auto c : text) {
		// ASCII十進だけを単位変換なしで読む。
		if( c < L'0' || c > L'9' ||
		   value > (MAXIMUM_EPOCH - static_cast<unsigned>( c - L'0')) / 10U) {
			return false ;
		}

		value = value * 10U + static_cast<unsigned>( c - L'0') ;
	}

	return true ;
}
/** @brief 自身が複写したtoken文字列だけをscope終了時に消去する。 */
struct SecretFields {
	/// raw変換済みsignature。
	std::wstring signature ;
	/// raw key identifier。
	std::wstring key ;
	/**
	 * @brief 自身の二つの所有値だけを消去する。
	 */
	~SecretFields()
	{
		SecureZeroMemory( signature.data(), signature.size() * sizeof( wchar_t)) ;
		SecureZeroMemory( key.data(), key.size() * sizeof( wchar_t)) ;
	}
} ;
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 現固定protocolの公開値を有限文法へ検査する。
 * @param[in] plan 元recordの公開文脈。
 * @return 現protocolで表現可能ならtrue。
 */
//------------------------------------------------------------------------------
bool validAsusAnonymousCdnPlan( const OfficialAnonymousCdnPlan &plan) noexcept
{
	return !plan.model.empty() && plan.model.size() <= 64U &&
		   std::ranges::all_of(
			   plan.model,
			   []( const wchar_t c) { return alphaNumeric( c) || c == L'_' || c == L'-' ; }) &&
		   plan.systemCode == L"asus" && plan.path.starts_with( L"/pub/ASUS/") &&
		   plan.path.size() <= 512U && !plan.path.ends_with( L'/') &&
		   plan.path.find( L"//") == std::wstring::npos &&
		   plan.path.find( L"/./") == std::wstring::npos &&
		   plan.path.find( L"/../") == std::wstring::npos && !plan.path.ends_with( L"/.") &&
		   !plan.path.ends_with( L"/..") && std::ranges::all_of( plan.path, []( const wchar_t c) {
			   return c == L'/' || componentSafe( c) ;
		   }) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元path/modelから唯一のpublic canonical URLを作る。
 * @param[in] plan 検査済み公開文脈。
 * @return 正常時の元URL。不成立なら空。
 */
//------------------------------------------------------------------------------
std::wstring asusAnonymousCdnCanonicalUrl( const OfficialAnonymousCdnPlan &plan)
{
	return validAsusAnonymousCdnPlan( plan)
			   ? std::wstring( PAYLOAD_ORIGIN) + plan.path + L"?model=" + plan.model
			   : std::wstring{} ;
}
//------------------------------------------------------------------------------
/**
 * @brief 保存一次JSの二段encodingで固定POSTを作る。
 * @param[in] plan 元recordの公開文脈。
 * @param[out] request 全成功時だけ有効な閉request。
 * @return 成功0、不正文脈またはallocationはHRESULT。
 */
//------------------------------------------------------------------------------
NativeError makeAsusAnonymousCdnPost( const OfficialAnonymousCdnPlan &plan,
									 OfficialEmptyJsonQueryPost		&request)
{
	request = {} ;
	// 不正な公開文脈から任意endpointを作らない。
	if( !validAsusAnonymousCdnPlan( plan)) {
		return E_INVALIDARG ;
	}

	try {
		OfficialEmptyJsonQueryPost next ;	// 全検証後だけ公開するrequest。
		next.url_ = std::wstring( ENDPOINT) +
					encode( encode( asusAnonymousCdnCanonicalUrl( plan), false), true) +
					L"&systemCode=asus" ;
		// 共通HTTP parserの有限URL枠に収める。
		if( next.url_.size() > 2048U) {
			return E_INVALIDARG ;
		}

		next.origin_  = L"https://www.asus.com" ;
		next.referer_ = L"https://www.asus.com/" ;
		next.valid_	  = true ;
		request		  = std::move( next) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 有限responseを元public URLとprotocol epochへ結ぶ。
 * @param[in] response session内だけのUTF-16 JSON。保存しない。
 * @param[in] plan 元recordの公開文脈。
 * @param[out] result 全型/文法/量を成功した秘密URL。権限ではない。
 * @return 全解釈成功0、不正応答は元HRESULT。
 */
//------------------------------------------------------------------------------
NativeError parseAsusAnonymousCdnResponse( const std::wstring_view		  response,
										  const OfficialAnonymousCdnPlan &plan,
										  OfficialAnonymousCdnResolution &result)
{
	result = {} ;
	// 未検証のendpointや過大本文をprotocolへ持ち込まない。
	if( !validAsusAnonymousCdnPlan( plan) || response.empty() || response.size() > 16384U) {
		return E_INVALIDARG ;
	}

	try {
		using namespace winrt::Windows::Data::Json ;
		const auto root =
			// Windows標準の有限本文解釈。
			JsonObject::Parse( winrt::hstring( response)) ;
		const auto status = root.GetNamedValue( L"status") ;	// 原JSON型を保持するstatus。
		// 文字列/boolの200を成功にしない。
		if( status.ValueType() != JsonValueType::Number || status.GetNumber() != 200.0) {
			return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		}

		const auto data		 = root.GetNamedObject( L"result") ;	// 元result object。
		const auto signature = data.GetNamedValue( L"signature") ;	// 元scalar型。
		const auto key		 = data.GetNamedValue( L"keyPairId") ;	// caseを補正しない元field。
		// 任意scalarをstringへcoerceしない。
		if( signature.ValueType() != JsonValueType::String ||
		   key.ValueType() != JsonValueType::String) {
			return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		}

		SecretFields fields ;									// このscopeで消去する文字列copy。
		const auto	 signatureText = signature.GetString() ;	// NULも含む原長を保持。
		const auto	 keyText	   = key.GetString() ;			// 元keyの全長。
		fields.signature.assign( signatureText.c_str(), signatureText.size()) ;
		fields.key.assign( keyText.c_str(), keyText.size()) ;
		// query区切りや未知のescapeを修正せず拒否する。
		if( !signatureGrammar( fields.signature) || !keyGrammar( fields.key)) {
			return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		}

		const auto	  expiry = data.GetNamedValue( L"expires") ;	// 原number/string型。
		std::uint64_t seconds{} ;									// 元protocolのUTC Unix秒。
		// 数値は製品UTC範囲内の有限整数値だけを認める。
		if( expiry.ValueType() == JsonValueType::Number) {
			const auto number = expiry.GetNumber() ;	// Windows/JavaScriptと同じJSON数値値。
			// この範囲はdoubleで全整数を正確に保持する。
			if( !std::isfinite( number) || number < 0.0 ||
			   number > static_cast<double>( MAXIMUM_EPOCH) || std::floor( number) != number) {
				return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
			}

			seconds = static_cast<std::uint64_t>( number) ;
		}
		// Stringだけは元十進grammarをcheckedに読む。
		else if( expiry.ValueType() == JsonValueType::String) {
			const auto text = expiry.GetString() ;	// 原十進文字列の同期所有値。
			// 符号/小数/単位推測を導入しない。
			if( !epochString( {text.c_str(), text.size()}, seconds)) {
				return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
			}
		} else {
			return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		}

		SecretOfficialUrl base{asusAnonymousCdnCanonicalUrl( plan) + L"&Signature=" +
							   fields.signature + L"&Expires=" + std::to_wstring( seconds) +
							   L"&Key-Pair-Id=" + fields.key} ;	// 元queryを変更しない。
		// 既存HTTPの完全URL枠を超える値を封印しない。
		if( base.view().size() > 2048U) {
			return HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER) ;
		}

		result.target			 = std::move( base) ;
		result.expiresUtcSeconds = seconds ;
		return 0 ;
	} catch( const winrt::hresult_error &error) {
		return static_cast<NativeError>( error.code().value) ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_UNEXPECTED ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 解決結果が元公開queryと同じepochを保持するか再照合する。
 * @param[in] plan 同recordの公開文脈。
 * @param[in] target session限定の完全解決URL。
 * @param[in] expires 同responseのUTC Unix秒。
 * @return 元URLと各認証fieldが一度だけ一致する場合true。
 */
//------------------------------------------------------------------------------
bool matchesAsusAnonymousCdnTarget( const OfficialAnonymousCdnPlan &plan,
								   const std::wstring_view target, const std::uint64_t expires)
{
	const auto prefix =
		// 元公開URLの完全表現。
		asusAnonymousCdnCanonicalUrl( plan) + L"&Signature=" ;
	// 元public queryをhostだけへ縮約しない。
	if( !validAsusAnonymousCdnPlan( plan) || !target.starts_with( prefix) || target.size() > 2048U ||
	   expires > MAXIMUM_EPOCH) {
		return false ;
	}

	const auto tail = target.substr( prefix.size()) ;	// 認証三fieldだけの借用。
	const auto end	= tail.find( L"&Expires=") ;		// signature終端。
	// 認証fieldを欠損または別名へ読み替えない。
	if( end == std::wstring_view::npos || !signatureGrammar( tail.substr( 0U, end))) {
		return false ;
	}

	const auto after = tail.substr( end + 9U) ;			// 元Expires値とkey。
	const auto key	 = after.find( L"&Key-Pair-Id=") ;	// expiry終端。
	return key != std::wstring_view::npos && after.substr( 0U, key) == std::to_wstring( expires) &&
		   keyGrammar( after.substr( key + 13U)) ;
}
} // namespace drivercrate
