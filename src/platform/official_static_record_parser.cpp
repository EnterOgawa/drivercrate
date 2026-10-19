//------------------------------------------------------------------------------
/**
 * @file official_static_record_parser.cpp
 * @brief 公式配布record用の静的HTML／JSON抽出境界実装。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  有限HTML属性とJSON object path抽出境界を追加。
 * </pre>
 *
 * @note 入力はworker内の公式応答だけを想定し、抽出値を表示、永続化、通信または取得許可へ
 *       自動変換しません。失敗時は部分値を返しません。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#include "platform/official_static_record_parser.h"

// Windows SDK 10.0.26100のWindowsNumerics.inlにあるSAL差だけをSDK include区間へ隔離する。
#pragma warning( push)
#pragma warning( disable : 28252 28253 6101)
#include <winrt/Windows.Data.Json.h>
#include <winrt/base.h>
#pragma warning( pop)

#include <algorithm>
#include <cstddef>
#include <exception>
#include <new>
#include <string>
#include <string_view>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t MAXIMUM_DOCUMENT_CHARACTERS =
	4U * 1'024U * 1'024U ;										// 一回解析するUTF-16文書上限。
constexpr std::size_t MAXIMUM_HTML_TAG_CHARACTERS	 = 4'096U ;	// 一開始tagの有限上限。
constexpr std::size_t MAXIMUM_MARKER_CHARACTERS		 = 512U ;	// Provider markerの有限上限。
constexpr std::size_t MAXIMUM_NAME_CHARACTERS		 = 128U ;	// 属性／JSON property名上限。
constexpr std::size_t MAXIMUM_OBJECT_PATH_COMPONENTS = 8U ;		// JSON object pathの深さ上限。
constexpr std::size_t MAXIMUM_OUTPUT_CHARACTERS		 = 8'192U ;	// 抽出値の絶対上限。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

/**
 * @brief HTML属性またはJSON field名に使う有限ASCII識別子か判定します。
 * @param[in] name 検証対象の名前。
 * @return ASCII英数字、hyphen、underscore、colonだけで構成される場合は`true`。
 */
[[nodiscard]] bool	  isStaticName( const std::wstring_view name) noexcept
{
	return !name.empty() && name.size() <= MAXIMUM_NAME_CHARACTERS &&
		   std::ranges::all_of( name, []( const wchar_t character) {
			   return (character >= L'a' && character <= L'z') ||
					  (character >= L'A' && character <= L'Z') ||
					  (character >= L'0' && character <= L'9') || character == L'-' ||
					  character == L'_' || character == L':' ;
		   }) ;
}

/**
 * @brief 抽出後の文字列が非空、上限内、制御文字なしであるか判定します。
 * @param[in] text 検証するdecoded文字列。
 * @param[in] maximumCharacters 呼出し側が指定した有限上限。
 * @return 安全なplain文字列として保持できる場合は`true`。
 */
[[nodiscard]] bool isStaticValue( const std::wstring_view text,
								 const std::size_t		 maximumCharacters) noexcept
{
	return !text.empty() && maximumCharacters != 0U &&
		   maximumCharacters <= MAXIMUM_OUTPUT_CHARACTERS && text.size() <= maximumCharacters &&
		   std::ranges::none_of( text, []( const wchar_t character) {
			   return character == L'\0' || character < L' ' || character == L'\x7f' ;
		   }) ;
}

/**
 * @brief ASCII大小を区別せずHTML tag名のprefixを比較します。
 * @param[in] value 比較元の開始tag断片。
 * @param[in] expected 小文字ASCIIの期待prefix。
 * @return ASCII大小以外が完全一致する場合は`true`。
 */
[[nodiscard]] bool startsWithAsciiInsensitive( const std::wstring_view value,
											  const std::wstring_view expected) noexcept
{
	// 期待prefixより短いtagを一致としない。
	if( value.size() < expected.size()) {
		return false ;
	}

	// Prefix全code unitをASCII小文字へ揃えて比較する。
	for( std::size_t index = 0U; index < expected.size(); ++index) {
		wchar_t character = value[index] ;	// 現在比較するtag文字。
		// ASCII大文字だけを小文字へ変換する。
		if( character >= L'A' && character <= L'Z') {
			character = static_cast<wchar_t>( character - L'A' + L'a') ;
		}

		// 一文字でも異なれば対象tag名ではない。
		if( character != expected[index]) {
			return false ;
		}
	}

	return true ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_static_record_parser.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
bool extractUniqueOfficialHtmlAttribute( const std::wstring_view html,
										const std::wstring_view uniqueMarker,
										const std::wstring_view attributeName,
										const std::size_t		maximumValueCharacters,
										std::wstring		   &value)
{
	value.clear() ;
	// 文書、marker、属性名、出力上限を走査前に有限化する。
	if( html.empty() || html.size() > MAXIMUM_DOCUMENT_CHARACTERS ||
	   html.find( L'\0') != std::wstring_view::npos || uniqueMarker.empty() ||
	   uniqueMarker.size() > MAXIMUM_MARKER_CHARACTERS ||
	   uniqueMarker.find( L'\0') != std::wstring_view::npos || !isStaticName( attributeName) ||
	   maximumValueCharacters == 0U || maximumValueCharacters > MAXIMUM_OUTPUT_CHARACTERS) {
		return false ;
	}

	const std::size_t marker = html.find( uniqueMarker) ;	// 一意性を確認するmarker位置。
	// 欠落または二件以上のProvider markerから任意のtagを選ばない。
	if( marker == std::wstring_view::npos ||
	   html.find( uniqueMarker, marker + uniqueMarker.size()) != std::wstring_view::npos) {
		return false ;
	}

	const std::size_t tagBegin = html.rfind( L'<', marker) ;	// Markerを含む開始tag候補。
	const std::size_t tagEnd   = html.find( L'>', marker) ;		// 開始tagの有限終端候補。
	// Markerが同じ開始tag内にない場合や過大tagを拒否する。
	if( tagBegin == std::wstring_view::npos || tagEnd == std::wstring_view::npos ||
	   tagEnd <= tagBegin || tagEnd - tagBegin > MAXIMUM_HTML_TAG_CHARACTERS ||
	   html.find( L'>', tagBegin) != tagEnd) {
		return false ;
	}

	const std::wstring_view tag =
		// 同一tagに限定した検索範囲。
		html.substr( tagBegin, tagEnd - tagBegin + 1U) ;
	// 終了tag、declaration、processing instruction、script、styleを値の出所にしない。
	if( tag.starts_with( L"</") || tag.starts_with( L"<!") || tag.starts_with( L"<?") ||
	   startsWithAsciiInsensitive( tag, L"<script") || startsWithAsciiInsensitive( tag, L"<style")) {
		return false ;
	}

	const std::wstring token = L" " + std::wstring( attributeName) + L"=\"" ;	// 厳密な属性開始token。
	const std::size_t  attribute = tag.find( token) ;							// 同じtag内の属性開始位置。
	// 属性欠落または同じ属性の重複を拒否する。
	if( attribute == std::wstring_view::npos ||
	   tag.find( token, attribute + token.size()) != std::wstring_view::npos) {
		return false ;
	}

	const std::size_t valueBegin = attribute + token.size() ;		// 属性値の先頭位置。
	const std::size_t valueEnd	 = tag.find( L'"', valueBegin) ;	// 属性値の終端位置。
	// 未終端、空、上限外、別markupまたはentityを含む値を解釈しない。
	if( valueEnd == std::wstring_view::npos || valueEnd <= valueBegin ||
	   valueEnd - valueBegin > maximumValueCharacters) {
		return false ;
	}

	const std::wstring_view parsed =
		// 検証完了まで借用する属性値。
		tag.substr( valueBegin, valueEnd - valueBegin) ;
	// HTML entityやmarkup断片をURLまたはplain値へ推測復号しない。
	if( !isStaticValue( parsed, maximumValueCharacters) ||
	   parsed.find_first_of( L"<>&") != std::wstring_view::npos) {
		return false ;
	}

	value.assign( parsed) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_static_record_parser.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
bool extractOfficialJsonStringAtObjectPath( const std::wstring_view					json,
										   const std::span<const std::wstring_view> objectPath,
										   const std::wstring_view					propertyName,
										   const std::size_t maximumValueCharacters,
										   std::wstring		&value)
{
	value.clear() ;
	// 文書、path深さ、property名と出力上限をJSON parser前に有限化する。
	if( json.empty() || json.size() > MAXIMUM_DOCUMENT_CHARACTERS ||
	   json.find( L'\0') != std::wstring_view::npos ||
	   objectPath.size() > MAXIMUM_OBJECT_PATH_COMPONENTS || !isStaticName( propertyName) ||
	   maximumValueCharacters == 0U || maximumValueCharacters > MAXIMUM_OUTPUT_CHARACTERS) {
		return false ;
	}

	// 全path要素を有限ASCII property名として事前検証する。
	for( const std::wstring_view component : objectPath) {
		// 不正名をWinRT property lookupへ渡さない。
		if( !isStaticName( component)) {
			return false ;
		}
	}

	try {
		auto current = winrt::Windows::Data::Json::JsonObject::Parse(
			// 型付きroot object。
			winrt::hstring( json)) ;
		// Providerが指定したobject propertyだけを順に辿る。
		for( const std::wstring_view component : objectPath) {
			const auto nested =
				// 現在path要素の型付き値。
				current.GetNamedValue( winrt::hstring( component)) ;
			// Array、文字列、数値、nullをobject pathとして解釈しない。
			if( nested.ValueType() != winrt::Windows::Data::Json::JsonValueType::Object) {
				return false ;
			}

			current = nested.GetObject() ;
		}

		const auto property =
			// 最終propertyの型付き値。
			current.GetNamedValue( winrt::hstring( propertyName)) ;
		// 数値、bool、object、array、nullを文字列へ変換しない。
		if( property.ValueType() != winrt::Windows::Data::Json::JsonValueType::String) {
			return false ;
		}

		const std::wstring parsed = property.GetString().c_str() ;	// JSON escapeを復号した値。
		// 復号後の空、制御文字または上限超過を返さない。
		if( !isStaticValue( parsed, maximumValueCharacters)) {
			return false ;
		}

		value = parsed ;
		return true ;
	} catch( const std::bad_alloc &) {
		return false ;
	} catch( const winrt::hresult_error &) {
		return false ;
	} catch( const std::exception &) {
		return false ;
	} catch( ...) {
		// JSON境界の型不明例外をworkerへ漏らさず、部分値なしで拒否する。
		return false ;
	}
}

} // namespace drivercrate
