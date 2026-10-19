//------------------------------------------------------------------------------
/**
 * @file official_html_terms.cpp
 * @brief 静的HTML許諾の原要素・原文書・全文をメーカー非依存で検査します。
 * @version 01.00.00
 * @date 2026/10/14
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/14  有限selectorとraw textarea文書の全文検査を追加。
 * </pre>
 *
 * @note Script/CSSを取得・評価せず、同意や取得能力を生成しません。
 * @see docs/adr/0339-common-static-html-terms-binding.md
 */
//------------------------------------------------------------------------------
#include "platform/official_html_terms.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <windows.h>

#include "core/official_preparation.h"
#include "platform/official_file_verifier.h"

namespace drivercrate {
namespace {

// 原pageと選択文書の独立した有限文字上限です。
constexpr std::size_t						 MAX_PAGE_CHARACTERS = 256U * 1024U ;
// 属性を含む一tagの走査上限です。
constexpr std::size_t						 MAX_TAG_CHARACTERS = 4096U ;
// 入れ子と一tagの属性数の上限です。
constexpr std::size_t						 MAX_DEPTH = 64U ;
// 認識した本文tagだけを全文へ写します。
constexpr std::array<std::wstring_view, 11U> BODY_TAGS{
	L"b", L"br", L"div", L"p", L"table", L"tbody", L"td", L"tr", L"ul", L"li", L"a"} ;

/** @brief 原pageを借用する一tagと一意な属性集合です。 */
struct HtmlTag {
	/// ASCII小文字へ照合用に写したtag名です。
	std::wstring											name ;
	/// 原pageを借用する属性名/値です。名前だけを小文字へ写します。
	std::vector<std::pair<std::wstring, std::wstring_view>> attributes ;
	/// tagを閉じるgreater-thanの原位置です。
	std::size_t												end{} ;
	/// 閉じtagの場合trueです。
	bool													closing{} ;
	/// 明示self-closingの場合trueです。
	bool													selfClosing{} ;
} ;

/** @brief HTML外枠で許可するASCII空白です。
 * @param[in] value 原一文字です。
 * @return 許可する外枠空白の場合trueです。
 */
[[nodiscard]] bool space( const wchar_t value)
{
	return value == L' ' || value == L'\t' || value == L'\r' || value == L'\n' ;
}

/** @brief 解析名のASCII一文字を照合用に小文字へ写します。
 * @param[in] value 原一文字です。
 * @return 名前の照合値です。原本文は変更しません。
 */
[[nodiscard]] wchar_t lower( const wchar_t value)
{
	return value >= L'A' && value <= L'Z' ? value - L'A' + L'a' : value ;
}

/** @brief 公開tag/属性名の閉じた文字集合です。
 * @param[in] value 原一文字です。
 * @return ASCII名に使用できる場合trueです。
 */
[[nodiscard]] bool nameCharacter( const wchar_t value)
{
	return (lower( value) >= L'a' && lower( value) <= L'z') || (value >= L'0' && value <= L'9') ||
		   value == L'-' || value == L'_' || value == L':' ;
}

/** @brief 文書外枠の空白だけを取り除いた借用範囲です。
 * @param[in] value 原外枠です。本文内部には使用しません。
 * @return 前後空白を除いた借用範囲です。
 */
[[nodiscard]] std::wstring_view frame( std::wstring_view value)
{
	// 有限外枠の先頭空白だけを除きます。
	while( !value.empty() && space( value.front())) {
		value.remove_prefix( 1U) ;
	}

	// 有限外枠の末尾空白だけを除きます。
	while( !value.empty() && space( value.back())) {
		value.remove_suffix( 1U) ;
	}

	return value ;
}

/** @brief 引用符と重複属性を確認して一tagだけを読みます。
 * @param[in] page 呼出し中だけ借用する原文字列です。
 * @param[in] begin less-thanの原位置です。
 * @param[out] tag 全成功時だけ有効なtagです。失敗出力は使用しません。
 * @return 最大4096文字以内で全属性を読めた場合trueです。
 */
[[nodiscard]] bool readTag( const std::wstring_view page, const std::size_t begin, HtmlTag &tag)
{
	tag = {} ;
	// 不正境界を部分要素へ変換しません。
	if( begin >= page.size() || page[begin] != L'<') {
		return false ;
	}

	std::size_t cursor = begin + 1U ;	// 元tagの有限走査位置です。
	// 閉じtagは名前の前だけで認識します。
	if( cursor < page.size() && page[cursor] == L'/') {
		tag.closing = true ;
		++cursor ;
	}

	// ASCII tag名を一度だけ照合値へ写します。
	while( cursor < page.size() && nameCharacter( page[cursor])) {
		tag.name.push_back( lower( page[cursor++])) ;
	}

	// 空名と過大名をselectorへ採用しません。
	if( tag.name.empty() || tag.name.size() > 64U) {
		return false ;
	}

	// 元tagが閉じるまで、最大64属性を欠損なく読みます。
	while( cursor < page.size() && cursor - begin < MAX_TAG_CHARACTERS) {
		// 属性間の外枠空白だけを消費します。
		while( cursor < page.size() && space( page[cursor])) {
			++cursor ;
		}

		// 終端欠損は部分属性を採用しません。
		if( cursor >= page.size()) {
			return false ;
		}

		// Self-closingのslashを属性として扱いません。
		if( page[cursor] == L'/') {
			tag.selfClosing = true ;
			++cursor ;
		}

		// Tag全体の成功位置だけを公開します。
		if( cursor < page.size() && page[cursor] == L'>') {
			tag.end = cursor ;
			return !tag.closing || (!tag.selfClosing && tag.attributes.empty()) ;
		}

		// 閉じtagの余分な属性と過大集合を拒否します。
		if( tag.closing || tag.selfClosing || tag.attributes.size() == MAX_DEPTH) {
			return false ;
		}

		std::wstring name ;	// この実属性だけの照合名です。
		// 一つの属性名を元tagから完全に読みます。
		while( cursor < page.size() && nameCharacter( page[cursor])) {
			name.push_back( lower( page[cursor++])) ;
		}

		// 重複属性をブラウザー依存の選択へ委ねません。
		if( name.empty() || std::ranges::any_of( tag.attributes, [&name]( const auto &value) {
			   return value.first == name ;
		   })) {
			return false ;
		}

		// 属性のequals前にある外枠空白だけを消費します。
		while( cursor < page.size() && space( page[cursor])) {
			++cursor ;
		}

		std::wstring_view value ;	// Boolean属性では空、他は原値を借用します。
		// 値を持つ属性だけを引用符または有限tokenとして読みます。
		if( cursor < page.size() && page[cursor] == L'=') {
			++cursor ;
			// Equals後の外枠空白だけを消費します。
			while( cursor < page.size() && space( page[cursor])) {
				++cursor ;
			}

			// 値のない属性をBoolean属性へ変換しません。
			if( cursor >= page.size()) {
				return false ;
			}

			const wchar_t quote = page[cursor] ;	// 引用符の元種別です。
			// 引用付き値は引用符内の偽属性を別属性へ数えません。
			if( quote == L'"' || quote == L'\'') {
				const std::size_t start = ++cursor ;					// 原属性値の開始です。
				const std::size_t end	= page.find( quote, start) ;	// 同じ引用符の終端です。
				// 閉じない引用符と過大tagを拒否します。
				if( end == page.npos || end - begin >= MAX_TAG_CHARACTERS) {
					return false ;
				}

				value  = page.substr( start, end - start) ;
				cursor = end + 1U ;
			} else {
				const std::size_t start = cursor ;	// 元unquoted tokenの開始です。
				// 未引用の値はHTMLの区切りまでに限定します。
				while( cursor < page.size() && !space( page[cursor]) && page[cursor] != L'>') {
					// 特殊文字を別属性や文書へ読み替えません。
					if( page[cursor] == L'<' || page[cursor] == L'"' || page[cursor] == L'\'' ||
					   page[cursor] == L'=' || page[cursor] == L'`') {
						return false ;
					}

					++cursor ;
				}

				value = page.substr( start, cursor - start) ;
			}
		}

		tag.attributes.emplace_back( std::move( name), value) ;
	}

	return false ;
}

/** @brief 一意に解析済みの実属性だけを返します。
 * @param[in] tag 原tagです。
 * @param[in] name ASCII小文字の照合名です。
 * @return 実属性値。欠損は空です。
 */
[[nodiscard]] std::wstring_view attribute( const HtmlTag &tag, const std::wstring_view name)
{
	const auto found = std::ranges::find_if( tag.attributes, [&name]( const auto &value) {
		return value.first == name ;
	}) ; // 元実属性の位置です。
	return found == tag.attributes.end() ? std::wstring_view{} : found->second ;
}

/** @brief 公開selectorを実tag属性へ完全一致させます。
 * @param[in] tag 原要素です。
 * @param[in] selector 認証済みまたはproducerの有限ASCII selectorです。
 * @return 元tag/属性/値が全て一致する場合trueです。
 */
[[nodiscard]] bool matches( const HtmlTag &tag, const IndexHtmlTermsSelector &selector)
{
	return !tag.closing && tag.name == std::wstring( selector.tag.begin(), selector.tag.end()) &&
		   attribute( tag, std::wstring( selector.attribute.begin(), selector.attribute.end())) ==
			   std::wstring( selector.value.begin(), selector.value.end()) ;
}

/** @brief 外pageの実tagだけを順に訪問します。
 * @tparam Visitor 呼出し中だけpageを借用する同期visitorです。
 * @param[in] page 原pageです。
 * @param[in] visitor 各実tagと原開始位置を確認する同期関数です。
 * @param[out] rejectedOffset 非null時だけ直近の原tag位置です。省略可です。
 * @return 文法とvisitorが全て成立する場合trueです。
 * @note Script/style/textareaの原内側は外page要素へ数えません。
 */
template <class Visitor>
[[nodiscard]] bool visitOuterTags( const std::wstring_view page, Visitor visitor,
								  std::size_t *rejectedOffset = nullptr)
{
	std::size_t cursor{} ;	// 全反復で前進する元page位置です。
	// 最大page長以内で全外要素を訪問し、失敗時は部分成功を返しません。
	while( cursor < page.size()) {
		const std::size_t begin = page.find( L'<', cursor) ;	// 次の実tag候補です。
		// 要素の残りがない場合だけ走査を完了します。
		if( begin == page.npos) {
			return true ;
		}

		// 任意数値診断だけを更新し、原内容は公開しません。
		if( rejectedOffset != nullptr) {
			*rejectedOffset = begin ;
		}

		// 外pageの可視less-thanはHTML要素ではなく、次の実tagまで本文として保持します。
		if( begin + 1U >= page.size() ||
		   (!(lower( page[begin + 1U]) >= L'a' && lower( page[begin + 1U]) <= L'z') &&
			page[begin + 1U] != L'/' && page[begin + 1U] != L'!')) {
			cursor = begin + 1U ;
			continue ;
		}

		// コメント中のselectorらしい文字列を実要素へ数えません。
		if( page.substr( begin).starts_with( L"<!--")) {
			const std::size_t end = page.find( L"-->", begin + 4U) ;	// コメント終端です。
			// 不完全なコメントを黙って削除しません。
			if( end == page.npos) {
				return false ;
			}

			cursor = end + 3U ;
			continue ;
		}

		// 外pageのDOCTYPEは要素や許諾本文ではありません。
		if( page.substr( begin).starts_with( L"<!DOCTYPE ") ||
		   page.substr( begin).starts_with( L"<!doctype ")) {
			const std::size_t end = page.find( L'>', begin) ;	// 有限宣言の終端です。
			// 過大/未終端の宣言を成功へ変換しません。
			if( end == page.npos || end - begin > MAX_TAG_CHARACTERS) {
				return false ;
			}

			cursor = end + 1U ;
			continue ;
		}

		HtmlTag tag ;	// 原pageを呼出し中だけ借用する実要素です。
		// 未終端tagや偽属性を選択結果へ混入させません。
		if( !readTag( page, begin, tag)) {
			return false ;
		}

		std::size_t contentEnd = tag.end + 1U ;	// 通常tagでは空の内側です。
		std::size_t next	   = contentEnd ;	// 次に走査する原位置です。
		// Raw-text要素内部を外pageの実要素として再解釈しません。
		if( !tag.closing &&
		   (tag.name == L"script" || tag.name == L"style" || tag.name == L"textarea")) {
			const std::wstring close = L"</" + tag.name + L">" ;	// Profileの明示終端です。
			contentEnd				 = page.find( close, next) ;
			// 未終端raw要素を選択可能にしません。
			if( contentEnd == page.npos) {
				return false ;
			}

			next = contentEnd + close.size() ;
		}

		// Visitorの拒否を部分正常へ変換しません。
		if( !visitor( tag, begin, contentEnd)) {
			return false ;
		}

		cursor = next ;
	}

	return true ;
}

/** @brief 一つの既知文字参照をUnicode scalarへ復元します。
 * @param[in] entity Ampersandとsemicolonの内側です。
 * @param[in,out] text 成功した文字だけを追加する一時全文です。
 * @return Unicodeと閉じたentity集合が成立する場合trueです。
 */
[[nodiscard]] bool appendEntity( const std::wstring_view entity, std::wstring &text)
{
	constexpr std::array<std::pair<std::wstring_view, std::uint32_t>, 6U> ENTITIES{
		{{L"quot", L'"'},
		 {L"amp", L'&'},
		 {L"lt", L'<'},
		 {L"gt", L'>'},
		 {L"apos", L'\''},
		 {L"nbsp", 0xA0U}}} ;	// 既存許諾rendererと同じ文字参照です。
	const auto	  found = std::ranges::find_if( ENTITIES, [&entity]( const auto &value) {
		   return value.first == entity ;
	   }) ;				  // 完全一致の位置です。
	std::uint32_t code{} ;	// 検査するUnicode scalarです。
	// 既知名だけを一文字へ戻します。
	if( found != ENTITIES.end()) {
		code = found->second ;
	} else {
		// 未知名を削除した本文を返しません。
		if( !entity.starts_with( L"#")) {
			return false ;
		}

		const bool hex =
			// 基数です。
			entity.size() > 1U && (entity[1] == L'x' || entity[1] == L'X') ;
		const std::uint32_t base  = hex ? 16U : 10U ;	// 元数値参照の基数です。
		const std::size_t	first = hex ? 2U : 1U ;		// 原数字列開始です。
		// 数字のない参照を空文字へ置換しません。
		if( first == entity.size()) {
			return false ;
		}

		// 全数字をUnicode上限の加算前検査で読みます。
		for( std::size_t index = first; index < entity.size(); ++index) {
			const wchar_t		value = lower( entity[index]) ;	// 原一桁の照合値です。
			const std::uint32_t digit =
				value >= L'0' && value <= L'9'	 ? static_cast<std::uint32_t>( value - L'0')
				: value >= L'a' && value <= L'f' ? static_cast<std::uint32_t>( value - L'a' + 10)
												 : base ;	// 不正桁です。
			// 桁あふれと基数外の文字を拒否します。
			if( digit >= base || code > (0x10ffffU - digit) / base) {
				return false ;
			}

			code = code * base + digit ;
		}
	}

	// NULと単独surrogateを全文へ残しません。
	if( code == 0U || (code >= 0xd800U && code <= 0xdfffU)) {
		return false ;
	}

	// 補助文字もUTF-16 pairへ欠損なく写します。
	if( code > 0xffffU) {
		code -= 0x10000U ;
		text.push_back( static_cast<wchar_t>( 0xd800U + (code >> 10U))) ;
		text.push_back( static_cast<wchar_t>( 0xdc00U + (code & 0x3ffU))) ;
	} else {
		text.push_back( static_cast<wchar_t>( code)) ;
	}

	return true ;
}

/** @brief 許可本文の全tagと文字を既存の表示規則へ写します。
 * @param[in] body 原body内部です。
 * @param[in,out] text Title付きの一時全文です。失敗時は呼出し側が破棄します。
 * @return 本文を切り詰めず全て写せた場合trueです。
 */
[[nodiscard]] bool renderBody( const std::wstring_view body, std::wstring &text)
{
	std::vector<std::wstring> stack ;		// 64段以内の対応tag名です。
	bool					  tail{} ;		// 空外部script参照以降は表示本文を許可しません。
	bool					  hasText{} ;	// Title以外に非空本文を確認した場合trueです。
	// 各反復で原位置を前進させ、本文を途中で切り詰めません。
	for( std::size_t cursor{}; cursor < body.size();) {
		// 実tagを本文文字から分けます。
		if( body[cursor] == L'<') {
			HtmlTag tag ;	// この本文要素だけを借用します。
			// 不完全な要素を黙って削除しません。
			if( !readTag( body, cursor, tag)) {
				return false ;
			}

			// 末尾の空外部scriptだけを非実行で認識します。
			if( tag.name == L"script" && !tag.closing) {
				const auto src	= attribute( tag, L"src") ;		// 実行しない原参照です。
				const auto type = attribute( tag, L"type") ;	// 明示されれば既知MIMEだけです。
				// Inline script/任意属性/本文中scriptを成功へ変換しません。
				if( !stack.empty() || !src.starts_with( L"/") || src.starts_with( L"//") ||
				   src.size() > 2048U || src.find_first_of( L" \t\r\n<>?&#\"") != src.npos ||
				   src.find( L"..") != src.npos || (type != L"" && type != L"text/javascript") ||
				   tag.attributes.size() != (type.empty() ? 1U : 2U) ||
				   !body.substr( tag.end + 1U).starts_with( L"</script>")) {
					return false ;
				}

				tail   = true ;
				cursor = tag.end + 10U ;
				continue ;
			}

			// Tail後の表示要素や未知tagを全文から除外しません。
			if( tail || std::ranges::find( BODY_TAGS, tag.name) == BODY_TAGS.end()) {
				return false ;
			}

			// 閉じtagは対応stackを一段だけ戻します。
			if( tag.closing) {
				// 間違った入れ子や余剰終端を許諾全文として採用しません。
				if( stack.empty() || stack.back() != tag.name) {
					return false ;
				}

				stack.pop_back() ;
			} else {
				// 明示リンクもURLを表示へ残し、外部参照は実行しません。
				if( tag.name == L"a") {
					const auto href	  = attribute( tag, L"href") ;		// 元許諾の公開参照です。
					const auto target = attribute( tag, L"target") ;	// 既知の非実行補足です。
					// Script URLや曖昧な追加属性を本文へ混入させません。
					if( (!href.starts_with( L"http://") && !href.starts_with( L"https://")) ||
					   href.size() > 2048U || href.find_first_of( L" \t\r\n<>&\"") != href.npos ||
					   (target != L"" && target != L"_blank") ||
					   tag.attributes.size() != (target.empty() ? 1U : 2U)) {
						return false ;
					}

					text += L" [" + std::wstring( href) + L"] " ;
				} else {
					// CSSを評価せず全textを保持し、style以外の本文属性は未対応です。
					if( tag.attributes.size() > 1U ||
					   (!tag.attributes.empty() && tag.attributes.front().first != L"style") ||
					   (tag.name == L"br" && !tag.attributes.empty())) {
						return false ;
					}
				}

				// 改行以外の要素を有限stackへ結合します。
				if( tag.name != L"br") {
					// 未対応self-closeと64段超過を拒否します。
					if( tag.selfClosing || stack.size() == MAX_DEPTH) {
						return false ;
					}

					stack.push_back( tag.name) ;
				}
			}

			// 既存rendererと同じ段落/表境界を保持します。
			if( tag.name != L"b") {
				text += L"\r\n" ;
			}

			cursor = tag.end + 1U ;
		} else {
			// 外部script以降の表示textを捨てて成功にしません。
			if( tail && !space( body[cursor])) {
				return false ;
			}

			// 末尾の外枠空白はscriptの一部として表示しません。
			if( tail) {
				++cursor ;
				continue ;
			}

			// Entityだけを復元し、通常ampersandは保持します。
			if( body[cursor] == L'&') {
				const std::size_t end = body.find( L';', cursor + 1U) ;	// 原entityの有限終端です。
				// Entityらしい未終端を通常文字へ読み替えません。
				if( end == body.npos || end - cursor > 12U) {
					const wchar_t next =
						cursor + 1U < body.size() ? lower( body[cursor + 1U]) : L' ' ;	// 開始です。
					// 未知entityの文字を削除しません。
					if( (next >= L'a' && next <= L'z') || next == L'#') {
						return false ;
					}

					text.push_back( body[cursor++]) ;
				} else {
					// 既知の完全文字参照だけを全文へ追加します。
					if( !appendEntity( body.substr( cursor + 1U, end - cursor - 1U), text)) {
						return false ;
					}

					cursor = end + 1U ;
				}

				hasText = true ;
			} else {
				const wchar_t value = body[cursor++] ;	// 全文へ保持する原一文字です。
				text.push_back( value) ;
				hasText = hasText || !space( value) ;
			}
		}

		// 表示上限を越えた全文を部分成功として返しません。
		if( text.size() > MAXIMUM_PREPARATION_EULA_CHARACTERS) {
			return false ;
		}
	}

	return stack.empty() && hasText && validPreparationEulaText( text) ;
}

/** @brief Raw文書のhead/bodyを一意に確認してtitle付き全文へ写します。
 * @param[in] document 選択した完全原文書です。
 * @param[in] revision 公開titleです。空は比較しません。
 * @param[out] text 全成功時だけtitle付き全文です。
 * @return 文書全体を欠損なく認識した場合trueです。
 */
[[nodiscard]] bool renderDocument( const std::wstring_view document,
								  const std::wstring_view revision, std::wstring &text)
{
	const auto raw = frame( document) ;	// 外枠だけを借用照合します。
	HtmlTag	   root ;					// 一意なhtml外枠です。
	// 不完全な外枠を部分bodyへ補完しません。
	if( !readTag( raw, 0U, root) || root.name != L"html" || root.closing || root.selfClosing ||
	   root.attributes.size() > 1U ||
	   (!root.attributes.empty() && root.attributes.front().first != L"lang") ||
	   !raw.ends_with( L"</html>")) {
		return false ;
	}

	std::size_t cursor = root.end + 1U ;	// 外枠内の有限読み取り位置です。
	// Head前の外枠空白だけを消費します。
	while( cursor < raw.size() && space( raw[cursor])) {
		++cursor ;
	}

	// 原head境界の欠損や複数文書を拒否します。
	if( !raw.substr( cursor).starts_with( L"<head>")) {
		return false ;
	}

	cursor += 6U ;
	std::wstring title ;		// 一意に取得した元公開titleです。
	bool		 headEnded{} ;	// 一つのhead終端を確認した場合trueです。
	// Headの既知要素だけを最大128回で確認します。
	for( std::size_t count{}; count < 128U && cursor < raw.size(); ++count) {
		// Head要素間の外枠空白だけを消費します。
		while( cursor < raw.size() && space( raw[cursor])) {
			++cursor ;
		}

		// 一意なhead終端でbodyへ進みます。
		if( raw.substr( cursor).starts_with( L"</head>")) {
			cursor += 7U ;
			headEnded = true ;
			break ;
		}

		HtmlTag tag ;	// このhead要素だけです。
		// 未知構造や実行要素をheadから黙って除きません。
		if( !readTag( raw, cursor, tag) || tag.closing) {
			return false ;
		}

		// 公開titleは一つだけを採用します。
		if( tag.name == L"title" && title.empty() && tag.attributes.empty()) {
			const std::size_t end = raw.find( L"</title>", tag.end + 1U) ;	// 元title終端です。
			// 空/HTML付き/過大titleを元revisionにしません。
			if( end == raw.npos || end - tag.end > 513U) {
				return false ;
			}

			const auto value = frame( raw.substr( tag.end + 1U, end - tag.end - 1U)) ;	// 原titleです。
			// Revisionは表示文字を推測せず原literalへ照合します。
			if( value.empty() || value.find_first_of( L"<>&\r\n") != value.npos) {
				return false ;
			}

			title.assign( value) ;
			cursor = end + 8U ;
		}
		// Inert styleは評価せず、raw文書hashへ含めます。
		else if( tag.name == L"style" && tag.attributes.empty()) {
			const std::size_t end = raw.find( L"</style>", tag.end + 1U) ;	// 非実行style終端です。
			// 不完全なstyleをbodyへ読み替えません。
			if( end == raw.npos) {
				return false ;
			}

			cursor = end + 8U ;
		}
		// Root-relative stylesheet参照だけを非実行で認識します。
		else if( tag.name == L"link") {
			const auto href = attribute( tag, L"href") ;	// 取得しない原stylesheet参照です。
			// Headの別用途/任意属性/動的参照を許容しません。
			if( attribute( tag, L"rel") != L"stylesheet" || attribute( tag, L"type") != L"text/css" ||
			   tag.attributes.size() != 3U || !href.starts_with( L"/") || href.starts_with( L"//") ||
			   href.find_first_of( L" \t\r\n<>?&#\"") != href.npos || href.size() > 2048U) {
				return false ;
			}

			cursor = tag.end + 1U ;
		} else {
			return false ;
		}
	}

	// 一意titleとheadの完了を要求します。
	if( !headEnded || title.empty() || (!revision.empty() && revision != title)) {
		return false ;
	}

	// Head/body間の外枠空白だけを消費します。
	while( cursor < raw.size() && space( raw[cursor])) {
		++cursor ;
	}

	HtmlTag body ;	// 原bodyの開始境界です。
	// Body外の表示本文を黙って捨てません。
	if( !readTag( raw, cursor, body) || body.name != L"body" || body.closing || body.selfClosing ||
	   body.attributes.size() > 1U ||
	   (!body.attributes.empty() && body.attributes.front().first != L"style")) {
		return false ;
	}

	const std::size_t end = raw.find( L"</body>", body.end + 1U) ;	// 原bodyの一意な終端です。
	// Body後の別文書や表示本文を許容しません。
	if( end == raw.npos || frame( raw.substr( end + 7U)) != L"</html>") {
		return false ;
	}

	text = title + L"\r\n" ;
	return renderBody( raw.substr( body.end + 1U, end - body.end - 1U), text) ;
}

/** @brief 一つのUTF-16原値を厳密UTF-8へ写します。
 * @param[in] value 元Unicode値です。
 * @param[out] bytes 成功時だけ完全UTF-8です。
 * @return 全文字を表現できた場合trueです。
 */
[[nodiscard]] bool utf8( const std::wstring_view value, std::string &bytes)
{
	// API整数境界はpage上限から確認します。
	if( value.empty() || value.size() > MAX_PAGE_CHARACTERS) {
		return false ;
	}

	const int count = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
										  static_cast<int>( value.size()), nullptr, 0, nullptr,
										  nullptr) ;	// 必要なUTF-8 byte数です。
	// 不正Unicodeを代替文字へ置換しません。
	if( count <= 0) {
		return false ;
	}

	bytes.resize( static_cast<std::size_t>( count)) ;
	return WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
							   static_cast<int>( value.size()), bytes.data(), count, nullptr,
							   nullptr) == count ;
}

/** @brief 共通SHA-256の結果を元固定digestへ完全一致させます。
 * @param[in] bytes 同じ原文書または全文の完全UTF-8です。
 * @param[in] expected 署名recordの元digestです。
 * @return 共通SHA-256が成功し全byteが一致した場合trueです。
 */
[[nodiscard]] bool hashMatches( const std::string_view bytes, const IndexManifestSha256 &expected)
{
	constexpr std::wstring_view HEX = L"0123456789abcdef" ;	// 共通digest表示の字句です。
	std::wstring				actual ;					// 同原byteからの共通SHA-256結果です。
	// Hash API失敗を一致へ変換しません。
	if( computeBytesSha256( bytes, actual) != 0U || actual.size() != 64U) {
		return false ;
	}

	// 全32byteを小文字digestと完全比較します。
	for( std::size_t index{}; index < expected.size(); ++index) {
		// 不一致時は部分正常を返しません。
		if( actual[index * 2U] != HEX[expected[index] >> 4U] ||
		   actual[index * 2U + 1U] != HEX[expected[index] & 0x0fU]) {
			return false ;
		}
	}

	return true ;
}

} // namespace

/** @see official_html_terms.h */
NativeError extractStaticHtmlTerms( const std::wstring_view		   page,
								   const IndexHtmlTermsExtraction &extraction,
								   const std::string_view		   payloadUrl,
								   const std::wstring_view		   revision,
								   HtmlTermsTextObservation		  &observation)
{
	observation			   = {} ;
	observation.checkStage = 1U ;
	// Profileや未検証の過大入力を曖昧な抽出へ進めません。
	if( extraction.profile != "TEXTAREA_HTML_DOCUMENT_V1" || extraction.selector.tag != "textarea" ||
	   page.empty() || page.size() > MAX_PAGE_CHARACTERS || page.find( L'\0') != page.npos ||
	   payloadUrl.empty()) {
		return E_INVALIDARG ;
	}

	try {
		std::size_t				 containers{} ;	// 一意containerの実一致数です。
		std::size_t				 links{} ;		// 一意payload操作の実一致数です。
		std::size_t				 selectors{} ;	// 一意textareaの実一致数です。
		std::size_t				 depth{} ;		// 対象containerと同じtagの有限入れ子数です。
		bool					 closed{} ;		// 対象containerの終端を確認した場合trueです。
		bool					 contained{} ;	// 選択textareaが対象container内にあった場合trueです。
		HtmlTermsTextObservation value ;		// 全成功前には公開しない所有値です。
		const std::wstring		 containerTag( extraction.containerSelector.tag.begin(),
											  // 元container tagです。
											  extraction.containerSelector.tag.end()) ;
		const std::wstring		 payload( payloadUrl.begin(), payloadUrl.end()) ;	// 原ASCII URLです。
		const std::wstring		 payloadAttribute( extraction.payloadAttribute.begin(),
												  // 元payload属性名です。
												  extraction.payloadAttribute.end()) ;
		const bool				 parsed = visitOuterTags(
			  page,
			  [&]( const HtmlTag &tag, const std::size_t, const std::size_t contentEnd) {
				  // Container selector自体の重複を拒否します。
				  if( matches( tag, extraction.containerSelector)) {
					  ++containers ;
					  // 複数containerの最初だけを採用しません。
					  if( containers != 1U || depth != 0U || tag.selfClosing) {
						  return false ;
					  }

					  depth = 1U ;
				  } else {
					  // 一意containerの同tag入れ子だけを終了境界へ結合します。
					  if( depth > 0U && tag.name == containerTag) {
						  // 閉じtagでは原container終端まで一段戻します。
						  if( tag.closing) {
							  --depth ;
							  closed = depth == 0U ;
						  } else {
							  ++depth ;
							  // 過大入れ子を無制限走査へ変えません。
							  if( depth > MAX_DEPTH) {
								  return false ;
							  }
						  }
					  }
				  }

				  // 元link selectorと実payload属性を一緒に照合します。
				  if( matches( tag, extraction.linkSelector)) {
					  ++links ;
					  // 別recordのpayloadや重複操作を同じ許諾へ結合しません。
					  if( links != 1U || attribute( tag, payloadAttribute) != payload) {
						  return false ;
					  }
				  }

				  // 実textareaの全原文書だけを保持します。
				  if( matches( tag, extraction.selector)) {
					  ++selectors ;
					  // Container外や複数textareaの最初だけを採用しません。
					  if( selectors != 1U || depth == 0U || tag.selfClosing ||
						 contentEnd <= tag.end + 1U) {
						  return false ;
					  }

					  contained = true ;
					  value.document.assign( page.substr( tag.end + 1U, contentEnd - tag.end - 1U)) ;
				  }

				  return true ;
			  },
			  &observation.checkOffset) ;	// 同期中だけpage/所有valueと数値診断を借用します。
		// 全pageの一意性・包含・完全終端が成立した場合だけ全文を抽出します。
		if( !parsed) {
			observation.checkStage = 2U ;
			return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		}

		// 一意性や包含失敗を全文解析の成功へ補完しません。
		if( containers != 1U || links != 1U || selectors != 1U || !contained || !closed ||
		   depth != 0U) {
			observation.checkStage = 3U ;
			return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		}

		// 原文書の未知構造を部分全文へ変換しません。
		if( !renderDocument( value.document, revision, value.text)) {
			observation.checkStage = 4U ;
			return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		}

		observation = std::move( value) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

/** @see official_html_terms.h */
NativeError verifyStaticHtmlTerms( const std::wstring_view		  page,
								  const IndexHtmlTermsExtraction &extraction,
								  const std::string_view		  payloadUrl,
								  const std::wstring_view revision, std::wstring &text)
{
	text.clear() ;
	HtmlTermsTextObservation observation ;	// 同一抽出からの原文書と全文です。
	const auto				 error = extractStaticHtmlTerms( page, extraction, payloadUrl, revision,
															observation) ;	// 同期の共通構造検査です。
	// 構造失敗の部分文書をhash成功へ変換しません。
	if( error != 0U) {
		return error ;
	}

	try {
		std::string document ;	// 原選択文書の完全UTF-8です。
		std::string fullText ;	// 同抽出全文の完全UTF-8です。
		// 原文書/全文を個別のexact size/hashへ一致させます。
		if( !utf8( observation.document, document) || !utf8( observation.text, fullText) ||
		   document.size() != extraction.documentSizeBytes ||
		   fullText.size() != extraction.textSizeBytes ||
		   !hashMatches( document, extraction.documentSha256) ||
		   !hashMatches( fullText, extraction.textSha256)) {
			return HRESULT_FROM_WIN32( ERROR_CRC) ;
		}

		text = std::move( observation.text) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

/** @see official_html_terms.h */
bool hasSingleStaticHtmlScriptReference( const std::wstring_view page,
										const std::wstring_view absoluteUrl,
										const std::wstring_view relativePath)
{
	std::size_t matchesCount{} ;	// 外pageの実参照数です。
	// 元pageの上限と一意な参照だけを必要とします。
	if( page.empty() || page.size() > MAX_PAGE_CHARACTERS || absoluteUrl.empty() ||
	   relativePath.empty()) {
		return false ;
	}

	const bool parsed =
		visitOuterTags( page, [&]( const HtmlTag &tag, const std::size_t, const std::size_t) {
			// Script内部の文字列をscript参照へ数えません。
			if( tag.name == L"script" && !tag.closing) {
				const auto src = attribute( tag, L"src") ;	// 外pageの実参照です。
				// Root-relativeとabsoluteの原同URLだけを一つとして数えます。
				if( src == absoluteUrl || src == relativePath) {
					++matchesCount ;
				}
			}

			return matchesCount <= 1U ;
		}) ; // 呼出し中だけ元pageと参照値を借用します。
	return parsed && matchesCount == 1U ;
}

} // namespace drivercrate
