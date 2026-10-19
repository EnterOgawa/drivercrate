//------------------------------------------------------------------------------
/**
 * @file amd_catalog_parser.cpp
 * @brief AMD公式support page parser実装。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  現行公式製品page経路追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note AMD公式HTML以外のscriptを実行せず、埋込みJSONと限定したdriver articleだけを解析します。Schema逸脱時は部分結果を公開しません。
 */
//------------------------------------------------------------------------------

#include "platform/amd_catalog_parser.h"

#include <Windows.h>

// Windows SDK 10.0.26100のWindowsNumerics.inlは宣言と定義のSAL差を/analyzeが報告する。
// DriverCrate sourceの警告は維持し、該当SDK headerを展開する区間だけ抑止する。
#pragma warning( push)
#pragma warning( disable : 28252 28253 6101)
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#pragma warning( pop)

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t MAXIMUM_INDEX_CHARACTERS =
	16U * 1024U * 1024U ;	// 復号後の製品一覧JSONを含むHTML文字数上限。
constexpr std::size_t MAXIMUM_DRIVER_PAGE_CHARACTERS =
	4U * 1024U * 1024U ;										// 一製品のdriver page文字数上限。
constexpr std::size_t MAXIMUM_PRODUCT_COUNT	   = 16'384U ;		// 一つの公式一覧で保持する末端製品上限。
constexpr std::size_t MAXIMUM_PRODUCT_DEPTH	   = 12U ;			// 埋込み製品treeの最大深さ。
constexpr std::size_t MAXIMUM_TITLE_CHARACTERS = 256U ;			// 製品名とdriver名の文字数上限。
constexpr std::size_t MAXIMUM_REVISION_CHARACTERS = 128U ;		// Revision表示の文字数上限。
constexpr std::size_t MAXIMUM_URL_CHARACTERS	  = 2'048U ;	// 公式page／payload URL上限。
constexpr std::size_t MAXIMUM_DRIVER_ENTRIES	  = 16U ;		// 一OS区分のdriver article上限。
constexpr std::wstring_view PRODUCT_COMPONENT_MARKER =
	L"data-component=\"coveo-browse-documentation\"" ;					// 製品tree component識別子。
constexpr std::wstring_view PRODUCT_JSON_ATTRIBUTE = L"data-json=\"" ;	// JSON属性開始。
// 製品treeで確認したAMD公式製品pageの固定prefix。
constexpr std::array<std::wstring_view, 3U> PRODUCT_PAGE_PREFIXES{
	L"https://www.amd.com/en/support/downloads/drivers.html/",
	L"https://www.amd.com/en/support/downloads/alveo-downloads.html/",
	L"https://www.amd.com/en/support/downloads/solarflare-downloads.html/"} ;
constexpr std::wstring_view PAYLOAD_PREFIX =
	L"https://drivers.amd.com/" ;	// 表示だけを許可するAMD payload prefix。
constexpr std::wstring_view ACCORDION_ITEM_MARKER =
	L"<div class=\"accordion-item\"" ;	// OS accordion開始識別子。
constexpr std::wstring_view ARTICLE_MARKER =
	L"<article class=\"container-fluid driver-download-details\"" ;	// Driver article開始。
constexpr std::wstring_view ARTICLE_END_MARKER = L"</article>" ;	// Driver article終了。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief HTML数値entityをlocale非依存で解析する。
 *
 * @param[in] character 数値entity内の一文字。
 * @return Hexadecimal digit値。該当しない場合は-1。
 */
//------------------------------------------------------------------------------
[[nodiscard]] int			hexDigitValue( const wchar_t character) noexcept
{
	// ASCII数字を十進・十六進に共通する下位10個の値へ変換する。
	if( character >= L'0' && character <= L'9') {
		return character - L'0' ;
	}

	// 小文字の十六進英字を10から15の値へ変換する。
	if( character >= L'a' && character <= L'f') {
		return character - L'a' + 10 ;
	}

	// 大文字の十六進英字も同じ10から15の値へ変換する。
	if( character >= L'A' && character <= L'F') {
		return character - L'A' + 10 ;
	}

	return -1 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Surrogate範囲とUnicode上限外を拒否し、必要時はpairへ変換する。
 *
 * @param[in] scalar HTML数値entityから得たUnicode scalar値。
 * @param[in,out] output 検証済みUTF-16の追加先。
 * @return 有効な非NUL scalarを追加できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool appendUnicodeScalar( const std::uint32_t scalar, std::wstring &output)
{
	// NUL、Unicode上限外、単独surrogateを有効なscalarとして受理しない。
	if( scalar == 0U || scalar > 0x10ffffU || (scalar >= 0xd800U && scalar <= 0xdfffU)) {
		return false ;
	}

	// BMP内のscalarはsurrogate pairを作らず一code unitで出力する。
	if( scalar <= 0xffffU) {
		output.push_back( static_cast<wchar_t>( scalar)) ;
		return true ;
	}

	const std::uint32_t adjusted = scalar - 0x10000U ;	// Surrogate pairへ変換する21-bit値。
	output.push_back( static_cast<wchar_t>( 0xd800U + (adjusted >> 10U))) ;
	output.push_back( static_cast<wchar_t>( 0xdc00U + (adjusted & 0x3ffU))) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 定義済みentityと有限桁の10進／16進数値entityだけを許可する。
 *
 * @param[in] input HTML属性または要素内のescaped text。
 * @param[in] maximumCharacters 復号後UTF-16文字数上限。
 * @return 復号済み文字列。未知entityまたは上限超過時はnullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> decodeHtmlEntities( const std::wstring_view input,
															 const std::size_t maximumCharacters)
{
	// entity展開前の入力にも上限を設け、過大なHTML属性を解析しない。
	if( input.size() > maximumCharacters * 6U) {
		return std::nullopt ;
	}

	std::wstring output ;	// Entityを復号するUTF-16出力。
	output.reserve( std::min( input.size(), maximumCharacters)) ;
	// 有限の入力を前方へ消費し、定義済みentityか可視文字として復号する。
	for( std::size_t index = 0U; index < input.size();) {
		// 復号結果が表示文字数上限へ達した後は追加出力しない。
		if( output.size() >= maximumCharacters) {
			return std::nullopt ;
		}

		const wchar_t character = input[index] ;	// 現在処理するHTML code unit。
		// entity開始記号以外はNULを検証して元のcode unitを保持する。
		if( character != L'&') {
			// 文字列の途中終了と解釈されるNULを表示metadataへ取り込まない。
			if( character == L'\0') {
				return std::nullopt ;
			}

			output.push_back( character) ;
			++index ;
			continue ;
		}

		struct NamedEntity {
			std::wstring_view encoded ;		// HTMLでのentity表現。
			wchar_t			  decoded{} ;	// 対応する一文字。
		} ;
		// 公式HTML本文で復号を許可する名前付きentityと文字の固定対応。
		constexpr std::array ENTITIES{NamedEntity{L"&amp;", L'&'}, NamedEntity{L"&quot;", L'\"'},
									  NamedEntity{L"&apos;", L'\''}, NamedEntity{L"&lt;", L'<'},
									  NamedEntity{L"&gt;", L'>'}} ;
		bool				 namedMatched{} ;	// trueの場合は定義済みentityを復号済み。
		// 現在位置に一致する最小の定義済みentityを探す。
		for( const NamedEntity &entity : ENTITIES) {
			// 既知の名前付きentityに一致した場合は対応文字を一つだけ出力する。
			if( input.substr( index).starts_with( entity.encoded)) {
				output.push_back( entity.decoded) ;
				index += entity.encoded.size() ;
				namedMatched = true ;
				break ;
			}
		}

		// 名前付きentityを消費済みの場合は数値entityとして二重解釈しない。
		if( namedMatched) {
			continue ;
		}

		// 未登録の名前付きentityを推測で復号せず拒否する。
		if( !input.substr( index).starts_with( L"&#")) {
			return std::nullopt ;
		}

		std::size_t digitIndex = index + 2U ;	// 数値entityの先頭digit位置。
		bool		hexadecimal{} ;				// trueの場合は16進数値entity。
		// 数値entityの明示的なx指定がある場合だけ十六進として読む。
		if( digitIndex < input.size() && (input[digitIndex] == L'x' || input[digitIndex] == L'X')) {
			hexadecimal = true ;
			++digitIndex ;
		}

		const std::size_t digitsBegin = digitIndex ;	// 一桁以上を要求する開始位置。
		std::uint32_t	  scalar{} ;					// 復号中のUnicode scalar値。
		// 入力終端またはentity終端までを有限桁で読み、Unicode値を組み立てる。
		while( digitIndex < input.size() && input[digitIndex] != L';') {
			const int			digit = hexadecimal ? hexDigitValue( input[digitIndex])
													: (input[digitIndex] >= L'0' && input[digitIndex] <= L'9'
														   ? input[digitIndex] - L'0'
														   : -1) ;	// 現在digit値。
			const std::uint32_t radix = hexadecimal ? 16U : 10U ;	// Entityの基数。
			// 不正な桁、桁数超過、Unicode上限を超える演算を復号前に拒否する。
			if( digit < 0 || digitIndex - digitsBegin >= 8U ||
			   scalar > (0x10ffffU - static_cast<std::uint32_t>( digit)) / radix) {
				return std::nullopt ;
			}

			scalar = scalar * radix + static_cast<std::uint32_t>( digit) ;
			++digitIndex ;
		}

		// 空の数値、終端欠落、無効scalar、出力上限超過を部分成功にしない。
		if( digitIndex == digitsBegin || digitIndex >= input.size() || input[digitIndex] != L';' ||
		   !appendUnicodeScalar( scalar, output) || output.size() > maximumCharacters) {
			return std::nullopt ;
		}

		index = digitIndex + 1U ;
	}

	return output ;
}

//------------------------------------------------------------------------------
/**
 * @brief HTML表示用改行を除き、内部空白の意味は変更しない。
 *
 * @param[in] value HTML要素から切り出したtext。
 * @return 前後のASCII空白を除いた同一入力内view。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring_view trimAsciiWhitespace( std::wstring_view value) noexcept
{
	// HTML外側の整形で除去するASCII空白を判定する、captureを持たない関数。
	const auto whitespace = []( const wchar_t character) {
		return character == L' ' || character == L'\t' || character == L'\r' || character == L'\n' ;
	} ;
	// 表示整形由来の先頭空白だけを取り除き、本文内の空白を保つ。
	while( !value.empty() && whitespace( value.front())) {
		value.remove_prefix( 1U) ;
	}

	// 表示整形由来の末尾空白だけを取り除き、本文内の空白を保つ。
	while( !value.empty() && whitespace( value.back())) {
		value.remove_suffix( 1U) ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 製品語や数字を削らず、曖昧な部分一致へ縮退させない。
 *
 * @param[in] value AMD公式またはSetupAPI由来の製品表示名。
 * @return 商標表記を除きASCII大文字と単一空白へ正規化した名前。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizeProductName( const std::wstring_view value)
{
	std::wstring normalized ;	// 完全一致比較に使用する製品名。
	normalized.reserve( value.size()) ;
	bool previousSpace{true} ;	// trueの場合は連続空白を追加しない。
	// 製品名を一文字ずつ確認し、商標とASCII表記ゆれだけを正規化する。
	for( std::size_t index = 0U; index < value.size(); ++index) {
		wchar_t character = value[index] ;	// 現在正規化するUTF-16 code unit。
		// 製品識別語に含めない登録商標・商標記号だけを除く。
		if( character == L'\u00ae' || character == L'\u2122') {
			continue ;
		}

		// 括弧付き商標を読み取れる残り長がある場合にだけsuffixを照合する。
		if( character == L'(' && index + 2U < value.size()) {
			const std::wstring_view remainder = value.substr( index) ;	// 商標suffix判定範囲。
			// 括弧付きTM商標だけを消費し、後続の製品名を保持する。
			if( remainder.starts_with( L"(TM)") || remainder.starts_with( L"(tm)")) {
				index += 3U ;
				continue ;
			}

			// 括弧付きR商標だけを消費し、後続の製品名を保持する。
			if( remainder.starts_with( L"(R)") || remainder.starts_with( L"(r)")) {
				index += 2U ;
				continue ;
			}
		}

		// 表示本文の空白連続を一つへまとめる対象文字かを示す。
		const bool whitespace =
			character == L' ' || character == L'\t' || character == L'\r' || character == L'\n' ;
		// 整形用空白を一つに畳み、製品語の区切り自体は残す。
		if( whitespace) {
			// 空白が連続する場合でも比較keyへ追加する区切りは一つにする。
			if( !previousSpace) {
				normalized.push_back( L' ') ;
				previousSpace = true ;
			}

			continue ;
		}

		// ASCII英字の大小だけを揃え、非ASCII文字と数字は変更しない。
		if( character >= L'a' && character <= L'z') {
			character = static_cast<wchar_t>( character - L'a' + L'A') ;
		}

		normalized.push_back( character) ;
		previousSpace = false ;
	}

	// 正規化で残った末尾の区切り空白を除く。
	if( !normalized.empty() && normalized.back() == L' ') {
		normalized.pop_back() ;
	}

	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief Query、fragment、userinfo相当表現を許可せず起点を固定する。
 *
 * @param[in] url 埋込み製品treeが返したURL。
 * @return 固定AMD HTTPS prefix配下のHTML URLの場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAllowedProductUrl( const std::wstring_view url) noexcept
{
	// 過長URLとquery・fragment・userinfo等を拒否し、製品pageの形式を限定する。
	if( url.size() > MAXIMUM_URL_CHARACTERS || !url.ends_with( L".html") ||
	   url.find_first_of( L"?#\\@") != std::wstring_view::npos) {
		return false ;
	}

	// 同じ公式host上でも登録していないsupport経路へ範囲を広げない。
	return std::ranges::any_of( PRODUCT_PAGE_PREFIXES, [url]( const std::wstring_view prefix) {
		return url.starts_with( prefix) ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief URLは表示metadataに限定し、直接install可能とは判定しない。
 *
 * @param[in] url Driver articleが提示したdownload URL。
 * @return AMD payload host上のEXEまたはZIP URLの場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAllowedPayloadUrl( const std::wstring_view url) noexcept
{
	// payloadの固定起点と長さを検証し、別解釈を生むURL成分を拒否する。
	if( url.size() > MAXIMUM_URL_CHARACTERS || !url.starts_with( PAYLOAD_PREFIX) ||
	   url.find_first_of( L"?#\\@") != std::wstring_view::npos) {
		return false ;
	}

	std::wstring	  extension ;						// 大文字小文字を正規化した末尾拡張子。
	const std::size_t dot = url.find_last_of( L'.') ;	// 拡張子開始位置。
	// 拡張子を識別できないpayload URLを受理しない。
	if( dot == std::wstring_view::npos) {
		return false ;
	}

	extension.assign( url.substr( dot)) ;
	std::transform( extension.begin(), extension.end(), extension.begin(),
				   []( const wchar_t character) {
					   return character >= L'A' && character <= L'Z'
								  ? static_cast<wchar_t>( character - L'A' + L'a')
								  : character ;
				   }) ;
	return extension == L".exe" || extension == L".zip" ;
}

//------------------------------------------------------------------------------
/**
 * @brief Family nodeを候補化せず、itemsを持たない末端だけを採用する。
 *
 * @param[in] nodes 現在階層の公式製品JSON array。
 * @param[in] depth Rootからの有限階層数。
 * @param[in,out] products 末端製品の追加先。
 * @return 全nodeがschemaと上限を満たす場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool collectProductNodes( const winrt::Windows::Data::Json::JsonArray &nodes,
									   const std::size_t							depth,
									   std::vector<AmdProductPage>				   &products)
{
	using winrt::Windows::Data::Json::JsonValueType ;
	// 製品treeの深さと一段のnode数を制限し、過大な再帰解析を防ぐ。
	if( depth > MAXIMUM_PRODUCT_DEPTH || nodes.Size() > MAXIMUM_PRODUCT_COUNT) {
		return false ;
	}

	// JSON順を維持し、上限到達後に部分一覧へ縮退させない。
	for( std::uint32_t index = 0U; index < nodes.Size(); ++index) {
		const auto value = nodes.GetAt( index) ;	// 現在検証する製品node値。
		// object以外の製品nodeをschema違反として拒否する。
		if( value.ValueType() != JsonValueType::Object) {
			return false ;
		}

		const auto object	= value.GetObject() ;			// 現在の製品node object。
		const bool hasItems = object.HasKey( L"items") ;	// Familyまたは末端内itemsの有無。
		// 子node欄がある場合は型と子階層を先に検証する。
		if( hasItems) {
			const auto itemsValue = object.GetNamedValue( L"items") ;	// 子node値。
			// 子node欄の型不一致または子階層の検証失敗を親の成功で隠さない。
			if( itemsValue.ValueType() != JsonValueType::Array ||
			   !collectProductNodes( itemsValue.GetArray(), depth + 1U, products)) {
				return false ;
			}

			// 子を持つfamily node自体を末端製品として採用しない。
			if( itemsValue.GetArray().Size() != 0U) {
				continue ;
			}
		}

		// 末端製品のtitleとURLが文字列で揃わないschemaを拒否する。
		if( !object.HasKey( L"title") || !object.HasKey( L"url") ||
		   object.GetNamedValue( L"title").ValueType() != JsonValueType::String ||
		   object.GetNamedValue( L"url").ValueType() != JsonValueType::String) {
			return false ;
		}

		const std::wstring title = object.GetNamedString( L"title").c_str() ;	// 公式製品名。
		const std::wstring url	 = object.GetNamedString( L"url").c_str() ;		// 公式製品page。
		// 製品名・URL・件数の境界を満たさない末端情報を候補へ取り込まない。
		if( title.empty() || title.size() > MAXIMUM_TITLE_CHARACTERS ||
		   title.find( L'\0') != std::wstring::npos || !isAllowedProductUrl( url) ||
		   products.size() >= MAXIMUM_PRODUCT_COUNT) {
			return false ;
		}

		products.push_back( {.title = title, .url = url}) ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示HTMLを任意DOMとして解釈せず、必要な単純要素だけを読む。
 *
 * @param[in] fragment 一つのdriver article。
 * @param[in] element `h4`等の属性なしelement名。
 * @param[in] maximumCharacters 復号後文字数上限。
 * @return 一意な単純text要素。欠損、markup、entity違反時はnullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> readElementText( const std::wstring_view fragment,
														  const std::wstring_view element,
														  const std::size_t		  maximumCharacters)
{
	const std::wstring opening = L"<" + std::wstring( element) + L">" ;		// 開始tag。
	const std::wstring closing = L"</" + std::wstring( element) + L">" ;	// 終了tag。
	const std::size_t  begin   = fragment.find( opening) ;					// 開始位置。
	// 対象要素の開始tagが欠落または重複したHTMLを曖昧なまま読まない。
	if( begin == std::wstring_view::npos ||
	   fragment.find( opening, begin + opening.size()) != std::wstring_view::npos) {
		return std::nullopt ;
	}

	const std::size_t valueBegin = begin + opening.size() ;					// Text開始位置。
	const std::size_t end		 = fragment.find( closing, valueBegin) ;	// Text終了位置。
	// 対象要素の終了tagが欠落または重複したHTMLを受理しない。
	if( end == std::wstring_view::npos ||
	   fragment.find( closing, end + closing.size()) != std::wstring_view::npos) {
		return std::nullopt ;
	}

	const std::wstring_view encoded =
		// Entity text。
		trimAsciiWhitespace( fragment.substr( valueBegin, end - valueBegin)) ;
	// 単純な表示文字列の内部に追加markupを許可しない。
	if( encoded.find_first_of( L"<>") != std::wstring_view::npos) {
		return std::nullopt ;
	}

	return decodeHtmlEntities( encoded, maximumCharacters) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同名labelの重複とlabelより前のparagraphを受理しない。
 *
 * @param[in] article 一つのdriver article。
 * @param[in] label `Revision Number`等の固定label。
 * @param[in] maximumCharacters 復号後文字数上限。
 * @return Label直後の単純paragraph。欠損または不正時はnullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> readLabeledParagraph( const std::wstring_view article,
															   const std::wstring_view label,
															   const std::size_t maximumCharacters)
{
	const std::wstring marker = L"<strong>" + std::wstring( label) + L"</strong>" ;	// 固定label表現。
	const std::size_t  labelPosition = article.find( marker) ;						// Label開始位置。
	// 必須labelの欠落や重複を推測で補わず拒否する。
	if( labelPosition == std::wstring_view::npos ||
	   article.find( marker, labelPosition + marker.size()) != std::wstring_view::npos) {
		return std::nullopt ;
	}

	// 項目labelの後にある値paragraphの開始位置。未検出はnpos。
	const std::size_t paragraphBegin = article.find( L"<p>", labelPosition + marker.size()) ;
	const std::size_t nextLabel =
		// 次label開始位置。
		article.find( L"<strong>", labelPosition + marker.size()) ;
	// 対応paragraphがない場合や次のlabelへ越境する場合は値を取得しない。
	if( paragraphBegin == std::wstring_view::npos ||
	   (nextLabel != std::wstring_view::npos && paragraphBegin > nextLabel)) {
		return std::nullopt ;
	}

	const std::size_t valueBegin   = paragraphBegin + 3U ;					// Paragraph text開始位置。
	const std::size_t paragraphEnd = article.find( L"</p>", valueBegin) ;	// 終了位置。
	// paragraph終端がない内容を表示値として切り出さない。
	if( paragraphEnd == std::wstring_view::npos) {
		return std::nullopt ;
	}

	const std::wstring_view encoded = trimAsciiWhitespace(
		// Paragraph text。
		article.substr( valueBegin, paragraphEnd - valueBegin)) ;
	// 空またはmarkupを含むparagraphを単純metadataとして受理しない。
	if( encoded.empty() || encoded.find_first_of( L"<>") != std::wstring_view::npos) {
		return std::nullopt ;
	}

	return decodeHtmlEntities( encoded, maximumCharacters) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Details linkを誤採用せず、Download aria-labelを必須にする。
 *
 * @param[in] article 採用対象のdriver article。
 * @return 一意なDownload anchorのAMD payload URL。不正時はnullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> readDownloadUrl( const std::wstring_view article)
{
	constexpr std::wstring_view ANCHOR_MARKER = L"<a href=\"" ;	// Anchor URL開始。
	std::optional<std::wstring> result ;						// 一意に検証したdownload URL。
	std::size_t					searchPosition{} ;				// 次に調べるanchor開始位置。
	// article内のanchorを前方へ走査し、Download用途の一意なlinkだけを探す。
	while( (searchPosition = article.find( ANCHOR_MARKER, searchPosition)) !=
		  std::wstring_view::npos) {
		const std::size_t urlBegin = searchPosition + ANCHOR_MARKER.size() ;	// URL開始位置。
		const std::size_t urlEnd   = article.find( L'\"', urlBegin) ;			// URL終了位置。
		const std::size_t tagEnd   = article.find( L'>', urlEnd) ;				// Anchor開始tag終端。
		// URLの引用終端やtag終端がないanchorを受理しない。
		if( urlEnd == std::wstring_view::npos || tagEnd == std::wstring_view::npos) {
			return std::nullopt ;
		}

		// 現在探索中のHTML tag範囲。元articleの存続中だけ借用する。
		const std::wstring_view tag = article.substr( searchPosition, tagEnd - searchPosition) ;
		// Downloadのaria-labelがあるanchorだけをpayload linkとして検証する。
		if( tag.find( L"aria-label=\"Download ") != std::wstring_view::npos) {
			const std::wstring_view url = article.substr( urlBegin, urlEnd - urlBegin) ;	// URL。
			// Download linkの重複と許可範囲外のURLを拒否する。
			if( result.has_value() || !isAllowedPayloadUrl( url)) {
				return std::nullopt ;
			}

			result = std::wstring( url) ;
		}

		searchPosition = tagEnd + 1U ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 浮動小数とlocaleへ依存せず、最大三桁の小数だけを扱う。
 *
 * @param[in] value AMDが表示する`849 MB`等のfile size。
 * @return Binary単位で切り上げたbyte数。不正またはoverflow時はnullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::uint64_t> parseDisplaySizeBytes( const std::wstring_view value)
{
	const std::wstring_view trimmed = trimAsciiWhitespace( value) ;	// 前後空白除去値。
	const std::size_t		space	= trimmed.find( L' ') ;			// 数値と単位の境界。
	// 容量値と単位を分離できない表記を数値容量へ変換しない。
	if( space == std::wstring_view::npos || space == 0U) {
		return std::nullopt ;
	}

	const std::wstring_view number	= trimmed.substr( 0U, space) ;							// ASCII decimal文字列。
	const std::wstring_view unit	= trimAsciiWhitespace( trimmed.substr( space + 1U)) ;	// 単位。
	const std::size_t		decimal = number.find( L'.') ;									// 小数点位置。
	// 小数点が重複した容量表記を拒否する。
	if( decimal != std::wstring_view::npos &&
	   number.find( L'.', decimal + 1U) != std::wstring_view::npos) {
		return std::nullopt ;
	}

	const std::wstring_view integral =
		// 整数部。
		decimal == std::wstring_view::npos ? number : number.substr( 0U, decimal) ;
	// 概算容量の小数部分。小数点がない場合は空のview。
	const std::wstring_view fractional =
		decimal == std::wstring_view::npos ? std::wstring_view{} : number.substr( decimal + 1U) ;
	// 整数部欠落や小数部の桁数不正を容量値として受理しない。
	if( integral.empty() || (!fractional.empty() && fractional.size() > 3U) ||
	   (decimal != std::wstring_view::npos && fractional.empty())) {
		return std::nullopt ;
	}

	std::uint64_t numerator{} ;	// 小数を整数化したsize値。
	// 整数部をoverflow検証付きで読み取る。
	for( const wchar_t character : integral) {
		// 数字以外と桁追加時の整数overflowを検出して容量解析を中止する。
		if( character < L'0' || character > L'9' ||
		   numerator > (std::numeric_limits<std::uint64_t>::max() - 9U) / 10U) {
			return std::nullopt ;
		}

		numerator = numerator * 10U + static_cast<std::uint64_t>( character - L'0') ;
	}

	std::uint64_t scale{1U} ;	// Fractional digit数に対応する10の累乗。
	// 最大三桁の小数部を順に取り込み、整数の分子とscaleで精度を保持する。
	for( const wchar_t character : fractional) {
		// 小数部にも数字検証とoverflow制限を適用する。
		if( character < L'0' || character > L'9' ||
		   numerator > (std::numeric_limits<std::uint64_t>::max() - 9U) / 10U) {
			return std::nullopt ;
		}

		numerator = numerator * 10U + static_cast<std::uint64_t>( character - L'0') ;
		scale *= 10U ;
	}

	const std::uint64_t multiplier = unit == L"KB"	 ? 1024ULL
									 : unit == L"MB" ? 1024ULL * 1024ULL
									 : unit == L"GB"
										 ? 1024ULL * 1024ULL * 1024ULL
										 : 0U ;	// AMD表示単位に対応するbinary multiplier。
	// ゼロ容量、未知単位、単位倍率によるoverflowを拒否する。
	if( numerator == 0U || multiplier == 0U ||
	   numerator > std::numeric_limits<std::uint64_t>::max() / multiplier) {
		return std::nullopt ;
	}

	const std::uint64_t product = numerator * multiplier ;	// Scale適用前のbyte分子。
	return product / scale + (product % scale == 0U ? 0U : 1U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示文字列をSYSTEMTIMEへ通し、存在しない日付を拒否する。
 *
 * @param[in] value AMDが表示する公開日。
 * @return 2000～2100年の有効な`YYYY-MM-DD`日付の場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidDate( const std::wstring_view value) noexcept
{
	// 日付の固定長と区切り位置が一致しない表記を受理しない。
	if( value.size() != 10U || value[4] != L'-' || value[7] != L'-') {
		return false ;
	}

	const auto decimal = [value]( const std::size_t begin,
								 const std::size_t count) -> std::optional<unsigned short> {
		unsigned int parsed{} ;	// 指定範囲から得る10進値。
		// 年・月・日の固定桁範囲を順に読み、数値fieldへ変換する。
		for( std::size_t index = begin; index < begin + count; ++index) {
			// 日付fieldにASCII数字以外を許可しない。
			if( value[index] < L'0' || value[index] > L'9') {
				return std::nullopt ;
			}

			parsed = parsed * 10U + static_cast<unsigned int>( value[index] - L'0') ;
		}

		// SYSTEMTIMEのfield型に収まらない値を切り詰めず拒否する。
		if( parsed > std::numeric_limits<unsigned short>::max()) {
			return std::nullopt ;
		}

		return static_cast<unsigned short>( parsed) ;
	} ;
	const std::optional<unsigned short> year  = decimal( 0U, 4U) ;	// 公開年。
	const std::optional<unsigned short> month = decimal( 5U, 2U) ;	// 公開月。
	const std::optional<unsigned short> day	  = decimal( 8U, 2U) ;	// 公開日。
	// 各fieldの欠落と審査範囲外の年を日付検証前に拒否する。
	if( !year.has_value() || !month.has_value() || !day.has_value() || *year < 2000U ||
	   *year > 2100U) {
		return false ;
	}

	SYSTEMTIME date{} ;	// Windows calendar検証へ渡す日付。
	date.wYear	= *year ;
	date.wMonth = *month ;
	date.wDay	= *day ;
	FILETIME converted{} ;	// 有効日付の場合に設定される未使用FILETIME。
	return SystemTimeToFileTime( &date, &converted) != FALSE ;
}

//------------------------------------------------------------------------------
/**
 * @brief Auto-Detect、RGB tool、chipset、NPU単体等を候補から除く。
 *
 * @param[in] title AMD articleのh4表示名。
 * @return Radeon Display driver系列だけの場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSupportedDriverTitle( const std::wstring_view title) noexcept
{
	return title == L"AMD Software: Adrenalin Edition" || title == L"AMD Software: PRO Edition" ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/amd_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseAmdProductIndexHtml( const std::wstring_view html, std::vector<AmdProductPage> &products)
{
	products.clear() ;
	// 空・過大・NUL混入のHTMLを製品indexとして解析しない。
	if( html.empty() || html.size() > MAXIMUM_INDEX_CHARACTERS ||
	   html.find( L'\0') != std::wstring_view::npos) {
		return false ;
	}

	const std::size_t component = html.find( PRODUCT_COMPONENT_MARKER) ;	// Component開始位置。
	// 製品componentの欠落や重複をschema変更として拒否する。
	if( component == std::wstring_view::npos ||
	   html.find( PRODUCT_COMPONENT_MARKER, component + PRODUCT_COMPONENT_MARKER.size()) !=
		   std::wstring_view::npos) {
		return false ;
	}

	const std::size_t attribute = html.find( PRODUCT_JSON_ATTRIBUTE, component) ;	// JSON属性位置。
	// component近傍に必要なdata属性がない場合は別の属性へ探索を広げない。
	if( attribute == std::wstring_view::npos || attribute - component > 1'024U) {
		return false ;
	}

	const std::size_t valueBegin = attribute + PRODUCT_JSON_ATTRIBUTE.size() ;	// 属性値先頭。
	const std::size_t valueEnd	 = html.find( L'\"', valueBegin) ;				// 属性値終端。
	// 属性値の終端欠落と入力上限超過を拒否する。
	if( valueEnd == std::wstring_view::npos || valueEnd - valueBegin > MAXIMUM_INDEX_CHARACTERS) {
		return false ;
	}

	const std::optional<std::wstring> json =
		decodeHtmlEntities( html.substr( valueBegin, valueEnd - valueBegin),
						   MAXIMUM_INDEX_CHARACTERS) ;	// 復号済み製品JSON。
	// HTML entityを正しく復号できないJSON属性を解析しない。
	if( !json.has_value()) {
		return false ;
	}

	try {
		using winrt::Windows::Data::Json::JsonObject ;
		using winrt::Windows::Data::Json::JsonValueType ;
		const JsonObject root =
			// 構文検証済みroot object。
			JsonObject::Parse( winrt::hstring( *json)) ;
		// 製品type一覧が配列で存在しないJSONを拒否する。
		if( !root.HasKey( L"productTypes") ||
		   root.GetNamedValue( L"productTypes").ValueType() != JsonValueType::Array) {
			return false ;
		}

		std::vector<AmdProductPage> parsed ;	// 全成功時だけ公開する末端製品一覧。
		parsed.reserve( 1'024U) ;
		// tree解析に失敗した場合や末端製品がない場合はindexを有効としない。
		if( !collectProductNodes( root.GetNamedArray( L"productTypes"), 0U, parsed) ||
		   parsed.empty()) {
			return false ;
		}

		products = std::move( parsed) ;
		return true ;
	} catch( const winrt::hresult_error &) {
		products.clear() ;
		return false ;
	} catch( const std::bad_alloc &) {
		products.clear() ;
		return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/amd_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool findAmdProductPage( const std::span<const AmdProductPage> products,
						const std::wstring_view deviceModel, AmdProductPage &product)
{
	product						= {} ;
	const std::wstring modelKey = normalizeProductName( deviceModel) ;	// Local完全一致key。
	// 比較keyが空になるmodelを製品照合へ使用しない。
	if( modelKey.empty()) {
		return false ;
	}

	const AmdProductPage *match{} ;	// 一意に一致した一覧内の非所有pointer。
	// 末端製品だけを走査し、二件目の一致でfail-closedにする。
	for( const AmdProductPage &candidate : products) {
		// 商標だけを正規化した製品名が完全一致しない候補を除外する。
		if( normalizeProductName( candidate.title) != modelKey) {
			continue ;
		}

		// 同じ比較keyの製品が複数ある場合は一意に選ばず拒否する。
		if( match != nullptr) {
			return false ;
		}

		match = &candidate ;
	}

	// 一致する製品がない場合は推測したpageを返さない。
	if( match == nullptr) {
		return false ;
	}

	product = *match ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/amd_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseAmdDriverPageHtml( const std::wstring_view html, const std::wstring_view windowsSection,
							std::vector<AmdDriverPageEntry> &entries)
{
	entries.clear() ;
	// 対応するWindows x64 section名が明示された場合だけtrue。
	const bool knownSection = windowsSection == L"Windows 10 - 64-Bit Edition" ||
							  windowsSection == L"Windows 11 - 64-Bit Edition" ;
	// 未知OS区分と空・過大・NUL混入のdriver pageを拒否する。
	if( !knownSection || html.empty() || html.size() > MAXIMUM_DRIVER_PAGE_CHARACTERS ||
	   html.find( L'\0') != std::wstring_view::npos) {
		return false ;
	}

	const std::size_t driverList   = html.find( L"id=\"amd_support_driver_list\"") ;	// 基点。
	const std::size_t sectionLabel = html.find( windowsSection, driverList) ;			// OS label位置。
	// driver一覧または指定OS見出しがないpageを受理しない。
	if( driverList == std::wstring_view::npos || sectionLabel == std::wstring_view::npos) {
		return false ;
	}

	const std::size_t sectionBegin = html.rfind( ACCORDION_ITEM_MARKER, sectionLabel) ;	// 区分先頭。
	// 対象OS区分の開始位置を取得できない場合は解析を中止する。
	if( sectionBegin == std::wstring_view::npos) {
		return false ;
	}

	std::size_t sectionEnd =
		// 次区分。
		html.find( ACCORDION_ITEM_MARKER, sectionLabel + windowsSection.size()) ;
	// 次の区分がない場合は既知のsection終端を解析範囲の境界にする。
	if( sectionEnd == std::wstring_view::npos) {
		// Accordion終端。
		sectionEnd = html.find( L"</section>", sectionLabel) ;
	}

	// 終端欠落や逆転したsection範囲をdriver一覧として読まない。
	if( sectionEnd == std::wstring_view::npos || sectionEnd <= sectionBegin) {
		return false ;
	}

	const std::wstring_view section =
		// 対象OS区分だけのHTML。
		html.substr( sectionBegin, sectionEnd - sectionBegin) ;
	std::vector<AmdDriverPageEntry>	 parsed ;				// 全article成功時だけ公開する結果。
	std::unordered_set<std::wstring> downloadUrls ;			// 同一区分内のpayload URL重複検出集合。
	std::size_t						 articlePosition{} ;	// 次に検索するarticle位置。
	// 指定OS section内のarticleだけを前方へ走査して表示metadataを取得する。
	while( (articlePosition = section.find( ARTICLE_MARKER, articlePosition)) !=
		  std::wstring_view::npos) {
		// 現在のdriver articleを閉じる位置。別候補への読み越しを防ぐ境界。
		const std::size_t articleEnd = section.find( ARTICLE_END_MARKER, articlePosition) ;
		// article終端のない不完全なdriver情報を受理しない。
		if( articleEnd == std::wstring_view::npos) {
			return false ;
		}

		// 現在解析する一つのdriver詳細article。
		const std::wstring_view article = section.substr(
			articlePosition, articleEnd + ARTICLE_END_MARKER.size() - articlePosition) ;
		const std::optional<std::wstring> title =
			// Driver系列名。
			readElementText( article, L"h4", MAXIMUM_TITLE_CHARACTERS) ;
		// driver系列のtitleを取得できないarticleは受理しない。
		if( !title.has_value()) {
			return false ;
		}

		// 対応するDisplay driver系列だけからrevision・日付・容量・URLを取得する。
		if( isSupportedDriverTitle( *title)) {
			const std::optional<std::wstring> revision = readLabeledParagraph(
				article, L"Revision Number", MAXIMUM_REVISION_CHARACTERS) ;	// Revision。
			const std::optional<std::wstring> size =
				// File size表示。
				readLabeledParagraph( article, L"File Size", 32U) ;
			const std::optional<std::wstring> date =
				// 公開日表示。
				readLabeledParagraph( article, L"Release Date", 32U) ;
			const std::optional<std::wstring>  url = readDownloadUrl( article) ;	// Payload URL。
			const std::optional<std::uint64_t> bytes =
				// Size上限。
				size.has_value() ? parseDisplaySizeBytes( *size) : std::nullopt ;
			// 必須metadataの欠落・日付不正・payload重複・候補数超過を全体拒否する。
			if( !revision.has_value() || revision->empty() || !date.has_value() ||
			   !isValidDate( *date) || !url.has_value() || !bytes.has_value() ||
			   !downloadUrls.insert( *url).second || parsed.size() >= MAXIMUM_DRIVER_ENTRIES) {
				return false ;
			}

			parsed.push_back(
				{.title				   = *title,
				 .revision			   = *revision,
				 .releaseDate		   = *date,
				 .downloadUrl		   = *url,
				 .maximumDownloadBytes = *bytes,
				 .whqlRecommended = revision->find( L"(WHQL Recommended)") != std::wstring::npos,
				 .whqlOptional	  = revision->find( L"(WHQL Optional)") != std::wstring::npos}) ;
		}

		articlePosition = articleEnd + ARTICLE_END_MARKER.size() ;
	}

	entries = std::move( parsed) ;
	return true ;
}

} // namespace drivercrate
