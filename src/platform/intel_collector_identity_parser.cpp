//------------------------------------------------------------------------------
/**
 * @file intel_collector_identity_parser.cpp
 * @brief Intel対応製品一覧の有限token・所属・全行衝突検証。
 * @version 01.04.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  有限Intel製品identity解析を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/28  同じheroに属する配布buttonとの一意結合を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/28  保存HTMLの非採用navigationと空span構文へ限定対応。
 * Ver.01.03.00 Shunji Ogawa  2026/09/28  収集公開名の端末ID形状拒否を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/28  明示制御付きcoreと型付き終了を追加。
 * </pre>
 *
 * @note 関連階層は閉鎖を検証し、公式GETとのbindingは呼出し側の別責務です。
 * @see docs/adr/0221-collector-official-product-identity.md
 */
//------------------------------------------------------------------------------

#include "intel_collector_identity_parser.h"
#include "platform/official_collector_public_text.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <windows.h>

namespace drivercrate {
namespace {

// 本文、tag、階層、属性、行は独立に有限化する。
constexpr std::size_t		MAXIMUM_BODY = 4U * 1024U * 1024U ;
// 開始・終了・commentを含む全token上限。
constexpr std::size_t		MAXIMUM_TAGS = 65536U ;
// 採用・非採用領域とも有限stackを用いる。
constexpr std::size_t		MAXIMUM_DEPTH = 64U ;
// 一開始tagの属性上限。
constexpr std::size_t		MAXIMUM_ATTRIBUTES = 64U ;
// 山括弧を含む一tagのUTF-16上限。
constexpr std::size_t		MAXIMUM_TAG_LENGTH = 16384U ;
// 重複除去前の全製品行上限。
constexpr std::size_t		MAXIMUM_ROWS = 1024U ;
// 親または一意一致が存在しないindex。
constexpr std::size_t		NONE = static_cast<std::size_t>( -1) ;
// 比較対象は既存727998 profileに限定し、製品名表は持たない。
constexpr std::wstring_view CANONICAL =
	L"https://www.intel.com/content/www/us/en/download/727998/"
	L"intel-network-adapter-driver-for-microsoft-windows-11.html" ;
// 専用対応一覧のbundle識別子。
constexpr std::wstring_view LIST_BUNDLE =
	L"downloadcenter.components.content.dcPageOtherValidProducts" ;
constexpr std::wstring_view LIST_CLASS =
	L"dc-page-detailed-other-valid-products" ;	// 一覧divのclass。
constexpr std::wstring_view PANEL_CLASS =
	L"dc-page-detailed-other-valid-products-panel" ;	// 直下ulのclass。
constexpr std::wstring_view ROW_CLASS =
	L"dc-page-detailed-other-valid-products-panel__product" ;	// 原行のclass。
// 製品pageへ向かう直接anchorのclass。
constexpr std::wstring_view ANCHOR_CLASS =
	L"dc-page-detailed-other-valid-products-panel__product--fixed" ;

/**
 * @brief 内部の有限解析中止理由です。公開関数で所有結果へ変換します。
 */
struct ParseFailure {
	/// 構造または有限上限の第一理由。
	IntelCollectorIdentityStatus status ;
} ;

/**
 * @brief 内部解析の前提を満たさない場合に処理を中止します。
 * @param[in] condition 継続可能な条件。
 * @param[in] status 中止時の第一理由。
 * @throws ParseFailure 条件が成立しない場合。
 */
void require( bool						  condition,
			 IntelCollectorIdentityStatus status = IntelCollectorIdentityStatus::SCHEMA_REJECTED)
{
	// 不正入力から部分的な所属証拠を返さない。
	if( !condition) {
		throw ParseFailure{status} ;
	}
}

/**
 * @brief HTML構文用のASCII空白を識別します。
 * @param[in] ch 判定する一文字。
 * @return HTMLの整形空白ならtrue。
 */
[[nodiscard]] bool htmlSpace( wchar_t ch)
{
	return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n' || ch == L'\f' ;
}

/**
 * @brief 名前比較だけに使うASCII小文字化です。
 * @param[in] ch 元の一文字。
 * @return ASCII大文字だけを小文字へ変換した値。
 */
[[nodiscard]] wchar_t lowerAscii( wchar_t ch)
{
	return ch >= L'A' && ch <= L'Z' ? static_cast<wchar_t>( ch - L'A' + L'a') : ch ;
}

/**
 * @brief HTML tagと属性名に許す有限文字集合です。
 * @param[in] ch 判定文字。
 * @return ASCII英数字または名前区切りならtrue。
 */
[[nodiscard]] bool nameCharacter( wchar_t ch)
{
	return (ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z') || (ch >= L'0' && ch <= L'9') ||
		   ch == L'-' || ch == L'_' || ch == L':' ;
}

/**
 * @brief 属性名と値です。値は呼出し中の本文だけを借用します。
 */
struct Attribute {
	/// ASCII小文字の属性名。
	std::wstring	  name ;
	/// 元本文の値。URLも内部だけに留める。
	std::wstring_view value ;
} ;

/**
 * @brief 走査中だけ存在するHTML tokenです。
 */
struct Token {
	/// 小文字tag名。textまたはcommentなら空。
	std::wstring		   name ;
	/// 元本文から借用する直接text。
	std::wstring_view	   text ;
	/// 一tag最大64件、重複名は拒否した属性。
	std::vector<Attribute> attributes ;
	/// 終了tagである。
	bool				   closing{} ;
	/// 明示的なslash終端である。
	bool				   selfClosing{} ;
} ;

/**
 * @brief 一つの有限tokenを読みます。Commentからtagを生成しません。
 * @param[in] html 借用本文。
 * @param[in,out] position 次の読取位置。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in,out] tags 本文全体のtag数。
 * @return 検査済みtoken。Commentは空token。
 * @throws ParseFailure 構文または有限上限の違反時。
 */
[[nodiscard]] Token nextToken( CollectorParserContext *control, std::wstring_view html,
							  std::size_t &position, std::size_t &tags)
{
	collectorParserCheckpoint( control) ;
	Token	   token ;				// 一回の借用token。
	const auto begin = position ;	// 上限測定の開始位置。
	// Markupでない区間は直接textとしてだけ返す。
	if( html[position] != L'<') {
		const auto end = collectorParserFind( control, html, L'<', position) ;	// 次のmarkup境界。
		position	   = end == html.npos ? html.size() : end ;
		token.text	   = html.substr( begin, position - begin) ;
		return token ;
	}

	require( ++tags <= MAXIMUM_TAGS, IntelCollectorIdentityStatus::LIMIT_EXCEEDED) ;
	// Commentの見かけ上の一覧を候補へ変換しない。
	if( html.substr( position, 4U) == L"<!--") {
		const auto end =
			// Commentの必須終端。
			collectorParserFind( control, html, L"-->", position + 4U) ;
		require( end != html.npos) ;
		position = end + 3U ;
		return token ;
	}

	// Quote内の山括弧をtag終端として扱わず、有限長で走査する。
	wchar_t		quote = 0 ;				// 現在のquote。0は属性値の外。
	std::size_t end	  = position + 1U ;	// Tag終端候補。
	// Quote状態を保ちながら有限長のtag終端を探す。
	for( ; end < html.size() && end - begin < MAXIMUM_TAG_LENGTH; ++end) {
		collectorParserStep( control) ;
		const auto ch = html[end] ;	// Quote状態を更新する文字。
		// 属性のquoteは同じquoteだけが閉じる。
		if( quote != 0) {
			// 別quoteで属性境界を補修しない。
			if( ch == quote) {
				quote = 0 ;
			}
		}
		// 属性値の開始を記録する。
		else if( ch == L'\'' || ch == L'"') {
			quote = ch ;
		}
		// Quote外だけがtag終端となる。
		else if( ch == L'>') {
			break ;
		}
	}

	require( end - begin < MAXIMUM_TAG_LENGTH, IntelCollectorIdentityStatus::LIMIT_EXCEEDED) ;
	require( end < html.size() && quote == 0) ;
	position		   = end + 1U ;
	std::size_t cursor = begin + 1U ;	// Tag内の有限cursor。
	// DOCTYPEだけを非要素として認め、任意宣言を解釈しない。
	if( html[cursor] == L'!') {
		std::wstring declaration( html.substr( cursor + 1U, end - cursor - 1U)) ;	// 有限宣言。
		std::transform( declaration.begin(), declaration.end(), declaration.begin(),
					   [&]( wchar_t ch) {
						   collectorParserStep( control) ;
						   return lowerAscii( ch) ;
					   }) ;
		require( declaration == L"doctype html") ;
		return token ;
	}

	// 終了tagは属性を持たない。
	if( html[cursor] == L'/') {
		token.closing = true ;
		++cursor ;
	}

	const auto nameBegin = cursor ;	// Tag名の開始。
	// ASCIIのtag名をquoteや空白と分離する。
	while( cursor < end && nameCharacter( html[cursor])) {
		collectorParserStep( control) ;
		++cursor ;
	}

	require( cursor > nameBegin) ;
	token.name.assign( html.substr( nameBegin, cursor - nameBegin)) ;
	std::transform( token.name.begin(), token.name.end(), token.name.begin(), [&]( wchar_t ch) {
		collectorParserStep( control) ;
		return lowerAscii( ch) ;
	}) ;
	// Plaintextは残りの本文を全てtextに変えるため、推測した終了tagを採用しない。
	require( token.name != L"plaintext") ;
	// 属性を重複復元せず最大64件まで順に解析する。
	while( cursor < end) {
		collectorParserStep( control) ;
		const auto beforeSpace = cursor ;	// 属性間の空白有無。
		// HTMLの整形空白だけを読み飛ばす。
		while( cursor < end && htmlSpace( html[cursor])) {
			collectorParserStep( control) ;
			++cursor ;
		}

		// Tag末尾の空白は値に含めない。
		if( cursor == end) {
			break ;
		}

		// Slash終端を属性値から推測しない。
		if( html[cursor] == L'/') {
			require( !token.closing && cursor + 1U == end) ;
			token.selfClosing = true ;
			break ;
		}

		require( !token.closing && cursor > beforeSpace) ;
		const auto attributeBegin = cursor ;	// 属性名の開始。
		// 属性名はASCII名として読み、大小文字違いの重複も後で拒否する。
		while( cursor < end && nameCharacter( html[cursor])) {
			collectorParserStep( control) ;
			++cursor ;
		}

		require( cursor > attributeBegin) ;
		Attribute attribute ;	// 一つの属性名と借用値。
		attribute.name.assign( html.substr( attributeBegin, cursor - attributeBegin)) ;
		std::transform( attribute.name.begin(), attribute.name.end(), attribute.name.begin(),
					   [&]( wchar_t ch) {
						   collectorParserStep( control) ;
						   return lowerAscii( ch) ;
					   }) ;
		require( std::none_of(
			token.attributes.begin(), token.attributes.end(),
			[&attribute]( const Attribute &old) { return old.name == attribute.name ; })) ;
		const auto afterName = cursor ;	// Boolean属性の後続空白を残す位置。
		// 等号の前の空白を許す。
		while( cursor < end && htmlSpace( html[cursor])) {
			collectorParserStep( control) ;
			++cursor ;
		}

		// 値がある属性はquoteまたは有限unquoted値を読む。
		if( cursor < end && html[cursor] == L'=') {
			++cursor ;
			// 等号後の整形空白は値に含めない。
			while( cursor < end && htmlSpace( html[cursor])) {
				collectorParserStep( control) ;
				++cursor ;
			}

			require( cursor < end) ;
			const auto delimiter = html[cursor] ;	// Quote有無の判定。
			// Quote値は空文字も正当に保持する。
			if( delimiter == L'\'' || delimiter == L'"') {
				const auto valueBegin = ++cursor ;	// 値だけの開始。
				// 同じquoteの終端まで読む。
				while( cursor < end && html[cursor] != delimiter) {
					collectorParserStep( control) ;
					++cursor ;
				}

				require( cursor < end) ;
				attribute.value = html.substr( valueBegin, cursor - valueBegin) ;
				++cursor ;
			} else {
				const auto valueBegin = cursor ;	// Unquoted値の開始。
				// Unquoted値へquote・山括弧・等号を混ぜない。
				while( cursor < end && !htmlSpace( html[cursor])) {
					collectorParserStep( control) ;
					require( html[cursor] != L'\'' && html[cursor] != L'"' && html[cursor] != L'<' &&
							html[cursor] != L'=' && html[cursor] != L'\x60') ;
					++cursor ;
				}

				require( cursor > valueBegin) ;
				attribute.value = html.substr( valueBegin, cursor - valueBegin) ;
			}
		} else {
			cursor = afterName ;
		}

		require( token.attributes.size() < MAXIMUM_ATTRIBUTES,
				IntelCollectorIdentityStatus::LIMIT_EXCEEDED) ;
		token.attributes.push_back( std::move( attribute)) ;
	}

	return token ;
}

/**
 * @brief 終了tagを要求しない標準HTML要素を識別します。
 * @param[in] name 小文字tag名。
 * @return Void要素ならtrue。
 */
[[nodiscard]] bool voidElement( std::wstring_view name)
{
	constexpr std::array names{L"area",	 L"base",	L"br",	  L"col",  L"embed",
							   L"hr",	 L"img",	L"input", L"link", L"meta",
							   L"param", L"source", L"track", L"wbr"} ;	// 標準void集合。
	return std::find( names.begin(), names.end(), name) != names.end() ;
}

/**
 * @brief 内容の見かけ上のtagを解析しない要素を識別します。
 * @param[in] name 小文字tag名。
 * @return Raw-textまたはRCDATA等の不透明要素ならtrue。
 */
[[nodiscard]] bool rawElement( std::wstring_view name)
{
	constexpr std::array names{
		L"script", L"style",   L"textarea", L"title",	L"xmp",
		L"iframe", L"noembed", L"noframes", L"noscript"} ;	// Script無実行profileの保守的集合。
	return std::find( names.begin(), names.end(), name) != names.end() ;
}

/**
 * @brief Raw-textの対応する終了tagまでを有限に読み飛ばします。
 * @param[in] html 借用本文。
 * @param[in] name 小文字開始tag名。
 * @param[in,out] position 内容開始から終了tag後へ更新する位置。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in,out] tags 全文tag数。
 * @throws ParseFailure 終端欠落または構文不正時。
 */
void skipRaw( CollectorParserContext *control, std::wstring_view html, std::wstring_view name,
			 std::size_t &position, std::size_t &tags)
{
	collectorParserCheckpoint( control) ;
	bool scriptComment = false ;	// 二重escapeを保守的に拒否するためのcomment開始観測。
	// 本文の山括弧候補を各一回調べ、対応する実終了tagだけを認める。
	while( position < html.size()) {
		collectorParserStep( control) ;
		position = collectorParserFind( control, html, L'<', position) ;
		require( position != html.npos) ;
		const auto remaining = html.substr( position) ;	// 終端候補の借用。
		// Script escaped状態へ入る可能性がある本文を記録する。
		if( name == L"script" && remaining.starts_with( L"<!--")) {
			scriptComment = true ;
		}

		// 二重escapeの終了を通常の最初の閉鎖tagと誤認しない。
		if( name == L"script" && scriptComment && remaining.size() > 7U &&
		   std::equal( name.begin(), name.end(), remaining.begin() + 1,
					  []( wchar_t left, wchar_t right) { return left == lowerAscii( right) ; }) &&
		   (htmlSpace( remaining[7U]) || remaining[7U] == L'/' || remaining[7U] == L'>')) {
			require( false) ;
		}

		// ASCII大小文字を無視するが、名前のprefix一致は認めない。
		if( remaining.size() > name.size() + 2U && remaining[1] == L'/' &&
		   std::equal( name.begin(), name.end(), remaining.begin() + 2,
					  []( wchar_t left, wchar_t right) { return left == lowerAscii( right) ; }) &&
		   (htmlSpace( remaining[name.size() + 2U]) || remaining[name.size() + 2U] == L'>')) {
			const auto close = nextToken( control, html, position, tags) ;	// 終了構文の独立検査。
			require( close.closing && close.name == name) ;
			return ;
		}

		++position ;
	}

	require( false) ;
}

/**
 * @brief Template内部を有限入れ子として読み飛ばします。
 * @param[in] html 借用本文。
 * @param[in,out] position Template内容開始から終端後へ更新する位置。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in,out] tags 全文tag数。
 * @throws ParseFailure 閉鎖不成立または上限超過時。
 */
void skipTemplate( CollectorParserContext *control, std::wstring_view html, std::size_t &position,
				  std::size_t &tags)
{
	collectorParserCheckpoint( control) ;
	std::size_t depth = 1U ;	// 無視するtemplateの入れ子数。
	// Script内のtemplate文字列は数えず、実templateだけを閉鎖する。
	while( position < html.size() && depth != 0U) {
		collectorParserStep( control) ;
		const auto token = nextToken( control, html, position, tags) ;	// 無所属の一token。
		// Raw要素の中にある閉鎖文字列をtemplate終端にしない。
		if( !token.closing && rawElement( token.name)) {
			skipRaw( control, html, token.name, position, tags) ;
		}
		// 実templateの入れ子だけを追跡する。
		else if( token.name == L"template") {
			require( !token.selfClosing) ;
			depth = token.closing ? depth - 1U : depth + 1U ;
			require( depth <= MAXIMUM_DEPTH, IntelCollectorIdentityStatus::LIMIT_EXCEEDED) ;
		}
	}

	require( depth == 0U) ;
}

/**
 * @brief 本文内だけで存続する要素です。親へ渡しません。
 */
struct Node {
	/// 小文字tag名。
	std::wstring			 name ;
	/// 借用属性。
	std::vector<Attribute>	 attributes ;
	/// 直接textだけの所有値。
	std::wstring			 text ;
	/// 親index。根はNONE。
	std::size_t				 parent{NONE} ;
	/// 元順序の直接子index。
	std::vector<std::size_t> children ;
	/// Headまたはmainの厳格閉鎖範囲に属する。
	bool					 strict{} ;
	/// Template／raw-textのため内容を解釈しない。
	bool					 opaque{} ;
} ;

/**
 * @brief 有限treeを作り、関連するhead／mainの閉鎖を厳格確認します。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] html 借用本文。
 * @return 本文内解析用tree。Viewはhtmlの寿命内だけ有効。
 * @throws ParseFailure 構造違反・上限超過時。
 */
[[nodiscard]] std::vector<Node> readTree( CollectorParserContext *control, std::wstring_view html)
{
	collectorParserCheckpoint( control) ;
	std::vector<Node>		 nodes ;			// 最大tag数以内の所有要素。
	std::vector<std::size_t> stack ;			// 最大64の開始要素index。
	std::size_t				 position = 0U ;	// 本文読取位置。
	std::size_t				 tags	  = 0U ;	// Commentと閉鎖も含むmarkup数。
	// 有限本文を一方向に走査する。
	while( position < html.size()) {
		collectorParserStep( control) ;
		// 実pageの非採用navigationにある未escapeの表示用「<」だけをtextとして通します。
		if( html.substr( position, 2U) == L"<<" && (stack.empty() || !nodes[stack.back()].strict)) {
			// 厳格なhead／main内では同じ壊れたtagを補修しません。
			if( !stack.empty()) {
				nodes[stack.back()].text.push_back( L'<') ;
			}

			++position ;
			continue ;
		}

		auto token = nextToken( control, html, position, tags) ;	// 一tokenの一時所有値。
		// 直接textだけを親に保持し、子のtextを平坦化しない。
		if( token.name.empty()) {
			// Document外のtextは採用根拠へ使わない。
			if( !stack.empty()) {
				nodes[stack.back()].text.append( token.text) ;
			}

			continue ;
		}

		// 終了tagは関連階層内では最上位と完全一致を要求する。
		if( token.closing) {
			// 関連階層での省略閉鎖・crossingを修復しない。
			if( !stack.empty() && nodes[stack.back()].strict) {
				require( nodes[stack.back()].name == token.name) ;
				stack.pop_back() ;
			} else {
				const auto found =
					std::find_if( stack.rbegin(), stack.rend(), [&]( std::size_t index) {
						return nodes[index].name == token.name ;
					}) ; // 非採用navigationの終端。
				// 非採用領域の省略終了は関連treeへ流用しない。
				if( found != stack.rend()) {
					stack.resize( static_cast<std::size_t>( std::distance( found, stack.rend())) - 1U) ;
				}
			}

			continue ;
		}

		Node node ;	// この開始tagの内部要素。
		node.name		= std::move( token.name) ;
		node.attributes = std::move( token.attributes) ;
		node.parent		= stack.empty() ? NONE : stack.back() ;
		node.strict		= node.name == L"head" || node.name == L"main" ||
					  (node.parent != NONE && nodes[node.parent].strict) ;
		node.opaque		 = rawElement( node.name) || node.name == L"template" ;
		const auto index = nodes.size() ;	// 新要素の安定index。
		// 関連する非voidをslashだけで閉じたことにしない。
		require( !token.selfClosing || voidElement( node.name) || node.name == L"span" ||
				!node.strict) ;
		// 直接親へ一回だけ結ぶ。
		if( node.parent != NONE) {
			nodes[node.parent].children.push_back( index) ;
		}

		nodes.push_back( std::move( node)) ;
		// 不透明要素は内側のtagをtreeへ生成しない。
		if( nodes[index].opaque) {
			// Templateだけは同名の実入れ子を数える。
			if( nodes[index].name == L"template") {
				skipTemplate( control, html, position, tags) ;
			} else {
				skipRaw( control, html, nodes[index].name, position, tags) ;
			}
		}
		// 非voidの閉鎖を後段で追う。
		else if( !voidElement( nodes[index].name) && !token.selfClosing) {
			require( stack.size() < MAXIMUM_DEPTH, IntelCollectorIdentityStatus::LIMIT_EXCEEDED) ;
			stack.push_back( index) ;
		}
	}

	require( std::none_of( stack.begin(), stack.end(),
						 [&]( std::size_t index) { return nodes[index].strict ; })) ;
	return nodes ;
}

/**
 * @brief 重複検査済みの属性を借用します。
 * @param[in] node 読取要素。
 * @param[in] name 小文字属性名。
 * @return 値。未掲載と空値はどちらも空。
 */
[[nodiscard]] std::wstring_view attribute( const Node &node, std::wstring_view name)
{
	const auto found =
		std::find_if( node.attributes.begin(), node.attributes.end(),
					 [&]( const Attribute &item) { return item.name == name ; }) ;	// 一意属性位置。
	return found == node.attributes.end() ? std::wstring_view{} : found->value ;
}

/**
 * @brief 空白区切り属性をtoken単位で照合します。
 * @param[in] value 元属性値。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] expected 期待token。
 * @return 完全tokenが存在すればtrue。
 */
[[nodiscard]] bool hasToken( CollectorParserContext *control, std::wstring_view value,
							std::wstring_view expected)
{
	collectorParserCheckpoint( control) ;
	std::size_t position = 0U ;	// 有限属性内のcursor。
	// 空白区切りを維持し、class名のprefix一致を許さない。
	while( position < value.size()) {
		collectorParserStep( control) ;
		// 整形空白を一方向へ読む。
		while( position < value.size() && htmlSpace( value[position])) {
			collectorParserStep( control) ;
			++position ;
		}

		const auto begin = position ;	// Token開始。
		// 非空白部分だけが一token。
		while( position < value.size() && !htmlSpace( value[position])) {
			collectorParserStep( control) ;
			++position ;
		}

		// 同名tokenだけを受理する。
		if( value.substr( begin, position - begin) == expected) {
			return true ;
		}
	}

	return false ;
}

/**
 * @brief UTF-16列に公開不可の文字と形状がないことを確認します。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] value 整形済み表示名。
 * @return 有効な公開名ならtrue。
 */
[[nodiscard]] bool publicName( CollectorParserContext *control, std::wstring_view value)
{
	collectorParserCheckpoint( control) ;
	// URL・path・query・markupの持出しを拒否する。
	if( value.empty() || value.size() > 256U ||
	   !(control != nullptr ? isOfficialCollectorPublicTextForCollector(
								  value, 1'024U, OfficialCollectorPublicTextKind::TEXT, *control)
							: isOfficialCollectorPublicText( value, 1'024U))) {
		return false ;
	}

	// Surrogateは必ず対で消費し、C0／DEL／C1を除く。
	for( std::size_t index = 0U; index < value.size(); ++index) {
		collectorParserStep( control) ;
		const auto ch = static_cast<std::uint32_t>( value[index]) ;	// UTF-16単位。
		// 公開fieldの不可視制御を通さない。
		if( ch < 32U || (ch >= 127U && ch <= 159U) || (ch >= 0xDC00U && ch <= 0xDFFFU)) {
			return false ;
		}

		// High surrogateの直後にはlow surrogateを必須とする。
		if( ch >= 0xD800U && ch <= 0xDBFFU) {
			++index ;
			// 終端欠落または異なる文字は無効UTF-16。
			if( index == value.size() || value[index] < 0xDC00 || value[index] > 0xDFFF) {
				return false ;
			}
		}
	}

	return true ;
}

/**
 * @brief 有限entity集合を復号して整形空白をまとめます。
 * @param[in] raw 元の直接text。
 * @param[out] display 空白整形済み表示名。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] comparison NFC比較名。
 * @return 有限公開名として成立すればtrue。
 */
[[nodiscard]] bool decodeName( CollectorParserContext *control, std::wstring_view raw,
							  std::wstring &display, std::wstring &comparison)
{
	collectorParserCheckpoint( control) ;
	display.clear() ;
	comparison.clear() ;
	// 256文字の数値entity表現を越える入力を先に拒否する。
	if( raw.size() > 4096U) {
		return false ;
	}

	std::wstring decoded ;	// 最大4096文字以内の中間値。
	// 元textを一方向に読み、再帰entity復号はしない。
	for( std::size_t index = 0U; index < raw.size(); ++index) {
		collectorParserStep( control) ;
		std::uint32_t scalar = static_cast<std::uint32_t>( raw[index]) ;	// 復号する一文字。
		// Entityは必ずsemicolonを持つ有限表現に限定する。
		if( raw[index] == L'&') {
			const auto end = collectorParserFind( control, raw, L';', index + 1U) ;	// Entity終端。
			// 不完全entityを文字列のまま通さない。
			if( end == raw.npos || end - index > 12U) {
				return false ;
			}

			auto entity = raw.substr( index + 1U, end - index - 1U) ;	// 有限entity名。
			constexpr std::array<std::pair<std::wstring_view, std::uint32_t>, 8U> named{
				{{L"amp", 38U},
				 {L"lt", 60U},
				 {L"gt", 62U},
				 {L"quot", 34U},
				 {L"apos", 39U},
				 {L"nbsp", 160U},
				 {L"reg", 174U},
				 {L"trade", 8482U}}} ;	// 採用済みnamed集合。
			const auto found = std::find_if( named.begin(), named.end(), [&]( const auto &item) {
				return item.first == entity ;
			}) ; // Named候補。
			// 既知namedだけを対応scalarへ変換する。
			if( found != named.end()) {
				scalar = found->second ;
			}
			// 数値はUnicode scalarまで有限に解析する。
			else if( entity.starts_with( L'#')) {
				entity.remove_prefix( 1U) ;
				unsigned base = 10U ;	// 既定は十進。
				// HTML数値entityのhex表記を明示的に扱う。
				if( entity.starts_with( L'x') || entity.starts_with( L'X')) {
					base = 16U ;
					entity.remove_prefix( 1U) ;
				}

				// 空数値を0へ変換しない。
				if( entity.empty()) {
					return false ;
				}

				scalar = 0U ;
				// Overflow前にUnicode上限で止める。
				for( const auto digit : entity) {
					collectorParserStep( control) ;
					const auto	   folded = lowerAscii( digit) ;	// Hexの大小文字を揃える。
					// 基数内の一桁、または不正を表す16。
					const unsigned number = digit >= L'0' && digit <= L'9'
												? static_cast<unsigned>( digit - L'0')
												: (folded >= L'a' && folded <= L'f'
													   ? static_cast<unsigned>( folded - L'a') + 10U
													   : 16U) ;
					// 不正桁・上限超過を拒否する。
					if( number >= base || scalar > (0x10FFFFU - number) / base) {
						return false ;
					}

					scalar = scalar * base + number ;
				}

				// 数値entityによるsurrogate生成は認めない。
				if( scalar == 0U || (scalar >= 0xD800U && scalar <= 0xDFFFU)) {
					return false ;
				}
			} else {
				return false ;
			}

			index = end ;
		}

		// 補助面のscalarは明示的にUTF-16対へ変換する。
		if( scalar > 0xFFFFU) {
			decoded.push_back( static_cast<wchar_t>( 0xD800U + ((scalar - 0x10000U) >> 10U))) ;
			decoded.push_back( static_cast<wchar_t>( 0xDC00U + ((scalar - 0x10000U) & 0x3FFU))) ;
		} else {
			decoded.push_back( static_cast<wchar_t>( scalar)) ;
		}
	}

	bool space = false ;	// 次の文字前に空白一つを挿入するか。
	// 許可された整形空白だけをcollapseする。FFは公開制御拒否へ残す。
	for( const auto ch : decoded) {
		collectorParserStep( control) ;
		// TAB／CR／LF／NBSPを単語境界として保存する。
		if( ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n' || ch == 160) {
			space = !display.empty() ;
			continue ;
		}

		// 両端空白は出力せず、内部だけ一つ残す。
		if( space) {
			display.push_back( L' ') ;
			space = false ;
		}

		display.push_back( ch) ;
	}

	// NFC前にも公開文字を検証する。
	if( !publicName( control, display)) {
		return false ;
	}

	std::array<wchar_t, 512U> normalized{} ;	// 最大256文字のNFC用有限buffer。
	const int				  length = NormalizeString( NormalizationC, display.data(),
													   static_cast<int>( display.size()), normalized.data(),
													   // WindowsのUnicode正規化結果。
													   static_cast<int>( normalized.size())) ;
	// 新経路ではAPI失敗を公開名不採用と区別します。
	if( length <= 0 && control != nullptr) {
		control->failed( CollectorIoErrorDomain::WIN32_ERROR, GetLastError()) ;
	}

	collectorParserCheckpoint( control) ;
	// API失敗や出力上限超過を推測補完しない。
	if( length <= 0 || length > 256) {
		return false ;
	}

	comparison.assign( normalized.data(), static_cast<std::size_t>( length)) ;
	return publicName( control, comparison) ;
}

/**
 * @brief 指定pathだけから公開SKUを取り出します。URLを返しません。
 * @param[in] href 元のhref属性。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] sku 成功時の十進SKU。
 * @return 固定host・path・桁・slug契約が成立すればtrue。
 */
[[nodiscard]] bool parseSku( CollectorParserContext *control, std::wstring_view href,
							std::wstring &sku)
{
	collectorParserCheckpoint( control) ;
	sku.clear() ;
	// URL全体の上限をprefix除去前に判定する。
	if( href.size() > 2048U) {
		return false ;
	}

	constexpr std::wstring_view host = L"https://www.intel.com" ;	// 唯一の絶対起点。
	// 完全hostの後にpathが続くことを後続prefixで確認する。
	if( href.starts_with( host)) {
		href.remove_prefix( host.size()) ;
	}

	constexpr std::wstring_view prefix = L"/content/www/us/en/products/sku/" ;	// 公開製品route。
	constexpr std::wstring_view suffix = L"/downloads.html" ;					// 取得先ではなく製品page。
	// Query、fragment、別host、別pathを許可しない。
	if( !href.starts_with( prefix) || !href.ends_with( suffix)) {
		return false ;
	}

	href.remove_prefix( prefix.size()) ;
	href.remove_suffix( suffix.size()) ;
	const auto slash = collectorParserFind( control, href, L'/') ;	// SKUとslugの一意境界。
	// SKUは先頭0なしの1～10桁でなければならない。
	if( slash == href.npos || slash == 0U || slash > 10U || href.front() == L'0') {
		return false ;
	}

	const auto key	= href.substr( 0U, slash) ;		// 一時SKU借用。
	const auto slug = href.substr( slash + 1U) ;	// 一時slug借用。
	// Dot segment・percent escape・追加slashを推測修復しない。
	if( !std::all_of( key.begin(), key.end(), []( wchar_t ch) { return ch >= L'0' && ch <= L'9' ; }) ||
	   slug.empty() || !std::all_of( slug.begin(), slug.end(), [&]( wchar_t ch) {
		   collectorParserStep( control) ;
		   return (ch >= L'a' && ch <= L'z') || (ch >= L'0' && ch <= L'9') || ch == L'-' ;
	   })) {
		return false ;
	}

	sku.assign( key) ;
	return true ;
}

/**
 * @brief 一意なselectorを全treeから解決します。
 * @tparam Predicate 要素条件の関数型。
 * @param[in] nodes 有限tree。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] predicate 対象要素条件。
 * @return 一致index。未掲載はNONE。
 * @throws ParseFailure 二つ以上が一致する場合。
 */
template <class Predicate>
[[nodiscard]] std::size_t uniqueNode( CollectorParserContext	 *control,
									 const std::vector<Node> &nodes, Predicate predicate)
{
	collectorParserCheckpoint( control) ;
	std::size_t result = NONE ;	// 一意一致の位置。
	// 先頭採用で二つ目を隠さず全要素を検査する。
	for( std::size_t index = 0U; index < nodes.size(); ++index) {
		collectorParserStep( control) ;
		// 選択条件を満たす要素は最大一つだけ採用する。
		if( predicate( nodes[index])) {
			require( result == NONE) ;
			result = index ;
		}
	}

	return result ;
}

/**
 * @brief 要素が指定祖先の子孫であり、異なる意味の領域を跨がないことを検査します。
 * @param[in] nodes 有限tree。
 * @param[in] child 子要素index。
 * @param[in] ancestor 期待祖先index。
 * @return 所属が成立すればtrue。
 */
[[nodiscard]] bool belongs( const std::vector<Node> &nodes, std::size_t child, std::size_t ancestor)
{
	// Parserが作った有限親chainだけを辿る。
	for( auto parent = nodes[child].parent; parent != NONE; parent = nodes[parent].parent) {
		// 期待祖先へ到達した場合だけ所属を認める。
		if( parent == ancestor) {
			return true ;
		}

		const auto &name = nodes[parent].name ;	// 意味を変える中間要素。
		// Footer・navigation・foreign namespace等からの所属偽装を排除する。
		if( name == L"footer" || name == L"nav" || name == L"aside" || name == L"svg" ||
		   name == L"math" || name == L"template" || name == L"select" || name == L"table") {
			return false ;
		}
	}

	return false ;
}

/**
 * @brief Text-only要素を有限復号して期待値と比較します。
 * @param[in] node 検査対象要素。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] expected 完全一致の期待表示。
 * @return 直接textだけで一致すればtrue。
 */
[[nodiscard]] bool exactText( CollectorParserContext *control, const Node &node,
							 std::wstring_view expected)
{
	collectorParserCheckpoint( control) ;
	std::wstring display ;		// 整形後の表示。
	std::wstring comparison ;	// NFC比較値。
	return node.children.empty() && !node.opaque &&
		   decodeName( control, node.text, display, comparison) && comparison == expected ;
}

/**
 * @brief 対応一覧の所属・閉鎖・全行を検証します。
 * @param[in] nodes 閉鎖検査済みの有限tree。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] expectedDownloadUrl 配布parserが選んだURL。空ならidentityだけを検証。
 * @return 出典未発行の所有identityと診断。
 * @throws ParseFailure 全体構造の拒否時。
 */
[[nodiscard]] IntelCollectorIdentityResult inspectTree( CollectorParserContext  *control,
													   const std::vector<Node> &nodes,
													   const std::wstring_view	expectedDownloadUrl)
{
	collectorParserCheckpoint( control) ;
	IntelCollectorIdentityResult result ;	// 未掲載を既定にする。
	const auto					 root =
		// 文書根。
		uniqueNode( control, nodes, [&]( const Node &node) { return node.name == L"html" ; }) ;
	const auto body =
		// 唯一の本文。
		uniqueNode( control, nodes, [&]( const Node &node) { return node.name == L"body" ; }) ;
	const auto head =
		// Head根。
		uniqueNode( control, nodes, [&]( const Node &node) { return node.name == L"head" ; }) ;
	const auto main		 = uniqueNode( control, nodes, [&]( const Node &node) {
		 return node.name == L"main" && attribute( node, L"id") == L"primary-content" ;
	 }) ; // 対象main根。
	const auto canonical = uniqueNode( control, nodes, [&]( const Node &node) {
		return node.name == L"link" && hasToken( control, attribute( node, L"rel"), L"canonical") ;
	}) ; // 全文で唯一のcanonical。
	const auto banner	 = uniqueNode( control, nodes, [&]( const Node &node) {
		   return attribute( node, L"data-bundle-id") ==
				  L"downloadcenter.components.content.dcPageBanner" ;
	   }) ; // 配布IDの所属元。
	const auto container = uniqueNode( control, nodes, [&]( const Node &node) {
		return attribute( node, L"data-bundle-id") ==
			   L"downloadcenter.components.content.dcPageContainer" ;
	}) ; // 配布本文container。
	const auto left		 = uniqueNode( control, nodes, [&]( const Node &node) {
		 return hasToken( control, attribute( node, L"class"), L"dc-page-container__body--left-panel") ;
	 }) ; // 同一左本文panel。
	const auto hero		 = uniqueNode( control, nodes, [&]( const Node &node) {
		 return hasToken( control, attribute( node, L"class"), L"dc-page-available-downloads-hero") ;
	 }) ; // 同一panelの配布hero。
	const auto list		 = uniqueNode( control, nodes, [&]( const Node &node) {
		 return attribute( node, L"data-bundle-id") == LIST_BUNDLE ;
	 }) ; // 専用対応一覧。
	// 未掲載を構造矛盾や製品不適合へ変換しない。
	if( root == NONE || body == NONE || head == NONE || main == NONE || canonical == NONE ||
	   banner == NONE || container == NONE || left == NONE || hero == NONE || list == NONE) {
		return result ;
	}

	require( nodes[root].parent == NONE && nodes[head].parent == root &&
			nodes[body].parent == root && nodes[main].parent == body) ;
	// Relative hrefの意味を変えるbaseは、この固定配布schemaでは採用しない。
	require( std::none_of( nodes.begin(), nodes.end(), [&]( const Node &node) {
		collectorParserStep( control) ;
		return node.name == L"base" ;
	})) ;
	require( nodes[canonical].parent == head && attribute( nodes[canonical], L"href") == CANONICAL) ;
	require( nodes[banner].name == L"div" &&
			hasToken( control, attribute( nodes[banner], L"class"), L"dc-page-banner") &&
			belongs( nodes, banner, main)) ;
	require( nodes[container].name == L"div" &&
			hasToken( control, attribute( nodes[container], L"class"), L"dc-page-container") &&
			belongs( nodes, container, main)) ;
	require( nodes[left].name == L"div" && belongs( nodes, left, container)) ;
	require( nodes[hero].name == L"div" && belongs( nodes, hero, left)) ;
	// 配布recordへ結ぶ場合は同じ左panelのheroに一つの配布buttonが必要です。
	if( !expectedDownloadUrl.empty()) {
		std::size_t matchedButtons{} ;	// URLもクラスも一致した直接配布button数。
		// Hero以下のbutton全体を調べ、無関係な欄の配布URLを流用しません。
		for( const auto &node : nodes) {
			collectorParserStep( control) ;
			// 配布CTAは唯一の期待URLだけを示さなければなりません。
			if( node.name == L"button" &&
			   hasToken( control, attribute( node, L"class"),
						L"dc-page-available-downloads-hero-button__cta") &&
			   belongs( nodes, static_cast<std::size_t>( &node - nodes.data()), hero)) {
				require( attribute( node, L"data-href") == expectedDownloadUrl) ;
				++matchedButtons ;
			}
		}

		require( matchedButtons == 1U) ;
	}

	require( nodes[list].name == L"div" &&
			hasToken( control, attribute( nodes[list], L"class"), LIST_CLASS) &&
			belongs( nodes, list, left)) ;
	// 未知のpagination／hidden等の属性がある一覧を完全と断定しない。
	if( nodes[list].attributes.size() != 2U) {
		return {IntelCollectorIdentityStatus::PAGINATION_INCOMPLETE} ;
	}

	const auto id = uniqueNode( control, nodes, [&]( const Node &node) {
		return hasToken( control, attribute( node, L"class"), L"dc-page-banner-actions-action-id") ;
	}) ; // Banner専用ID表示group。
	require( id != NONE && nodes[id].name == L"div" && belongs( nodes, id, banner)) ;
	std::size_t values = 0U ;	// ID group直下の値表示数。
	std::size_t labels = 0U ;	// ID group直下のlabel数。
	// 日付・versionの同名spanを配布IDと取り違えない。
	for( const auto child : nodes[id].children) {
		collectorParserStep( control) ;
		const auto &node = nodes[child] ;	// 直接子だけが根拠。
		// ID labelの完全一致を確認する。
		if( node.name == L"label" &&
		   hasToken( control, attribute( node, L"class"), L"dc-page-banner-actions-action__label")) {
			require( exactText( control, node, L"ID")) ;
			++labels ;
		}
		// ID値は同じgroupの727998だけを認める。
		else if( node.name == L"span" &&
				hasToken( control, attribute( node, L"class"),
						 L"dc-page-banner-actions-action__value")) {	// ID値は727998だけ。
			require( exactText( control, node, L"727998")) ;
			++values ;
		} else {
			require( false) ;
		}
	}

	require( labels == 1U && values == 1U &&
			std::all_of( nodes[id].text.begin(), nodes[id].text.end(), [&]( wchar_t ch) {
				collectorParserStep( control) ;
				return htmlSpace( ch) ;
			})) ;
	std::size_t heading = NONE ;	// 一覧直下の一意見出し。
	std::size_t panel	= NONE ;	// 一覧直下の一意ul。
	// 未評価の追加button／外部linkは完全一覧としない。
	for( const auto child : nodes[list].children) {
		collectorParserStep( control) ;
		const auto &node = nodes[child] ;	// 専用divの直接子。
		// 見出しを別階層から補完しない。
		if( node.name == L"h2" && hasToken( control, attribute( node, L"class"),
										  L"dc-page-detailed-other-valid-products__title")) {
			require( heading == NONE) ;
			heading = child ;
		}
		// 見出しと同じ親に属するulだけを採用する。
		else if( node.name == L"ul" &&
				hasToken( control, attribute( node, L"class"), PANEL_CLASS)) {	// 採用一覧。
			require( panel == NONE) ;
			panel = child ;
		} else {
			result.status = IntelCollectorIdentityStatus::PAGINATION_INCOMPLETE ;
			return result ;
		}
	}

	require( std::all_of( nodes[list].text.begin(), nodes[list].text.end(), [&]( wchar_t ch) {
		collectorParserStep( control) ;
		return htmlSpace( ch) ;
	})) ;
	// 外部一覧だけやtitleだけではidentityを確定しない。
	if( heading == NONE || panel == NONE) {
		return result ;
	}

	// Ulの未知属性による続き読込み条件を黙って無視しない。
	if( nodes[panel].attributes.size() != 1U) {
		return {IntelCollectorIdentityStatus::PAGINATION_INCOMPLETE} ;
	}

	require( exactText( control, nodes[heading],
					  L"This download is valid for the product(s) listed below.")) ;
	require( std::all_of( nodes[panel].text.begin(), nodes[panel].text.end(), [&]( wchar_t ch) {
		collectorParserStep( control) ;
		return htmlSpace( ch) ;
	})) ;
	require( nodes[panel].children.size() <= MAXIMUM_ROWS,
			IntelCollectorIdentityStatus::LIMIT_EXCEEDED) ;
	std::vector<IntelCollectorProductIdentity> rows ;	// 全有効原行。重複もまだ保持する。
	// 全行の閉鎖後に一意性を確定するため、先頭採用しない。
	for( const auto child : nodes[panel].children) {
		collectorParserCheckpoint( control) ;
		const auto &row = nodes[child] ;	// 元順序の一行。
		// 続きlink等の未知子要素を欠落した製品行へ変換しない。
		if( row.name != L"li" || !hasToken( control, attribute( row, L"class"), ROW_CLASS)) {
			return {IntelCollectorIdentityStatus::PAGINATION_INCOMPLETE} ;
		}

		++result.seen ;
		IntelCollectorProductIdentity product ;	// この行の公開所有値。
		// 入れ子anchor・余分な行内容・非text表示を個別不正として隔離する。
		bool						  valid = row.children.size() == 1U &&
					 // 行の単純構造。
					 std::all_of( row.text.begin(), row.text.end(), [&]( wchar_t ch) {
						 collectorParserStep( control) ;
						 return htmlSpace( ch) ;
					 }) ;
		// Anchorが一つのときだけ有限の属性と表示を検証する。
		if( valid) {
			const auto &anchor = nodes[row.children.front()] ;	// 唯一の直接子。
			valid			   = anchor.name == L"a" && !anchor.opaque && anchor.children.empty() &&
					hasToken( control, attribute( anchor, L"class"), ANCHOR_CLASS) &&
					parseSku( control, attribute( anchor, L"href"), product.sku) &&
					decodeName( control, anchor.text, product.displayName, product.comparisonName) ;
		}

		// 不正行を黙って成功件数から消さない。
		if( !valid) {
			++result.rejected ;
		} else {
			rows.push_back( std::move( product)) ;
		}
	}

	std::vector<bool> collision( rows.size(), false) ;	// 原行単位の衝突隔離mask。
	// 最大1024行の全pairで、後続が先行行と重複行へ与える衝突を確定する。
	for( std::size_t first = 0U; first < rows.size(); ++first) {
		collectorParserStep( control) ;
		// keyと名の一対一性を両方向で調べる。
		for( std::size_t second = first + 1U; second < rows.size(); ++second) {
			collectorParserStep( control) ;
			const bool sameKey = rows[first].sku == rows[second].sku ;	// Keyの同一性。
			const bool sameName =
				rows[first].comparisonName == rows[second].comparisonName ;	// 名の同一性。
			// 片側だけ一致する全行を撤回する。
			if( sameKey != sameName) {
				collision[first]  = true ;
				collision[second] = true ;
			}
		}
	}

	// 衝突判定完了後だけ、独立した一意identityを元順序で出力する。
	for( std::size_t index = 0U; index < rows.size(); ++index) {
		collectorParserStep( control) ;
		// 衝突原行は重複件数でなく衝突件数へ計上する。
		if( collision[index]) {
			++result.collisions ;
			continue ;
		}

		const auto duplicate =
			std::find_if( result.products.begin(), result.products.end(),
						 [&]( const IntelCollectorProductIdentity &old) {
							 collectorParserStep( control) ;
							 return old.sku == rows[index].sku &&
									old.comparisonName == rows[index].comparisonName ;
						 }) ; // 既出の同値identity。
		// 同key同名だけを折り畳む。
		if( duplicate != result.products.end()) {
			++result.duplicates ;
		} else {
			result.products.push_back( std::move( rows[index])) ;
		}
	}

	result.status = result.rejected != 0U || result.collisions != 0U
						? IntelCollectorIdentityStatus::PARTIAL_REJECTED
						: IntelCollectorIdentityStatus::ACCEPTED ;
	return result ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/intel_collector_identity_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
IntelCollectorIdentityResult parseIntelCollectorProductIdentity( std::wstring_view html)
{
	try {
		require( html.size() <= MAXIMUM_BODY, IntelCollectorIdentityStatus::LIMIT_EXCEEDED) ;
		require( !html.empty() && html.find( L'\0') == html.npos) ;
		return inspectTree( nullptr, readTree( nullptr, html), {}) ;
	} catch( const ParseFailure &failure) {
		return {failure.status} ;
	} catch( const std::bad_alloc &) {
		return {IntelCollectorIdentityStatus::LIMIT_EXCEEDED} ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/intel_collector_identity_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
IntelCollectorIdentityResult parseIntelCollectorProductIdentityForPayload(
	const std::wstring_view html, const std::wstring_view expectedDownloadUrl)
{
	try {
		// 空URLや過大本文から配布所属の証拠を作りません。
		require( !expectedDownloadUrl.empty() && expectedDownloadUrl.size() <= 8'192U) ;
		require( !html.empty() && html.size() <= MAXIMUM_BODY && html.find( L'\0') == html.npos,
				IntelCollectorIdentityStatus::LIMIT_EXCEEDED) ;
		return inspectTree( nullptr, readTree( nullptr, html), expectedDownloadUrl) ;
	} catch( const ParseFailure &failure) {
		return {failure.status} ;
	} catch( const std::bad_alloc &) {
		return {IntelCollectorIdentityStatus::LIMIT_EXCEEDED} ;
	}
}

/** @see intel_collector_identity_parser.h */
CollectorParserResult parseIntelCollectorProductIdentityControlled(
	std::wstring_view html, std::wstring_view expectedDownloadUrl,
	OfficialCollectorHttpControl &control, IntelCollectorIdentityResult &result)
{
	result = {} ;
	IntelCollectorIdentityResult parsed ;	// 成功後だけ公開する同一coreの所有結果。
	const auto outcome = runCollectorParser( control, [&]( CollectorParserContext &context) {
		// 本文の実上限と入力構造を区別します。
		if( html.size() > MAXIMUM_BODY) {
			collectorParserLimit( &context) ;
		}

		// 空本文・過大URL・埋込NULを入力拒否します。
		if( html.empty() || expectedDownloadUrl.size() > 8'192U ||
		   collectorParserFind( &context, html, L'\0') != html.npos) {
			return false ;
		}

		try {
			parsed = inspectTree( &context, readTree( &context, html), expectedDownloadUrl) ;
			context.checkpoint() ;
			return true ;
		} catch( const ParseFailure &failure) {
			// 有限上限だけをLIMITとし、OOMは共通境界へ伝播します。
			if( failure.status == IntelCollectorIdentityStatus::LIMIT_EXCEEDED) {
				collectorParserLimit( &context) ;
			}

			return false ;
		}
	}) ; // 元controlで停止と原errorを固定します。
	// 完了後だけ一時結果を公開し、失敗時に部分identityを残しません。
	if( outcome.status == CollectorParserStatus::COMPLETED) {
		result = std::move( parsed) ;
	}

	return outcome ;
}

} // namespace drivercrate
