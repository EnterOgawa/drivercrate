//------------------------------------------------------------------------------
/**
 * @file asix_catalog_parser.cpp
 * @brief ASIX AX88179A公式製品page・Terms parser実装。
 * @version 01.00.00
 * @date 2026/09/06
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Terms本文と取得前配布recordの結合を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  数値配布IDの観測境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 固定ASIX製品pageとTermsを実行せず、Windows client x64の取得前recordへ結合します。欠落、重複、未知構造、別OS、別hostを推測で補完せず拒否しま
 *       す。
 */
//------------------------------------------------------------------------------

#include "platform/asix_catalog_parser.h"

#include "core/official_preparation.h"
#include "platform/official_http_client.h"
#include "platform/official_prepared_acquisition.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t	MAXIMUM_HTML_CHARACTERS		  = 512U * 1024U ;	// 製品pageの文字数上限。
constexpr std::size_t	MAXIMUM_TERMS_HTML_CHARACTERS = 256U * 1024U ;	// Terms pageの文字数上限。
constexpr std::size_t	MAXIMUM_TERMS_TAG_CHARACTERS  = 128U ;			// 一つの許可tag表現の文字数上限。
constexpr std::size_t	MAXIMUM_TERMS_DEPTH			  = 32U ;			// Termsの入れ子stack上限。
constexpr std::size_t	MAXIMUM_VALUE_CHARACTERS	  = 64U ;			// 一つの表示値の文字数上限。
constexpr std::size_t	MAXIMUM_URL_CHARACTERS		  = 512U ;			// 固定endpoint URLの文字数上限。
constexpr std::uint32_t PREPARED_PARSER_REVISION	  = 2U ;			// Terms結合済みASIX parser契約の版。
constexpr std::uint32_t WINDOWS10_MINIMUM_BUILD		  = 10'240U ;		// Windows 10初期build。
constexpr std::uint32_t WINDOWS11_MINIMUM_BUILD		  = 22'000U ;		// Windows 11系列の下限。
constexpr std::wstring_view PRODUCT_MARKER =
	L"<h1 class=\"txt_cover_title\">AX88179A</h1>" ;						// 固定製品識別marker。
constexpr std::wstring_view ROW_MARKER = L"<div class=\"table_item\">" ;	// 配布行の開始。
constexpr std::wstring_view X64_CERTIFICATION =
	L"For x64 CPU platform, HLK/WHCK certified" ;	// x64 driver行の必須説明。
constexpr std::wstring_view DOWNLOAD_PREFIX =
	L"https://www.asix.com.tw/en/support/download/file/" ;	// 固定endpoint prefix。
constexpr std::wstring_view TERMS_LINK =
	L"<a href=\"https://www.asix.com.tw/en/useterm\">Terms Of Use</a>" ;	// 固定Terms参照。
constexpr std::array DOWNLOAD_HOSTS{										// 表示URLとして認識する完全一致host。
									std::wstring_view( L"www.asix.com.tw")} ;
constexpr std::array TERMS_HEADING_MARKERS{
	std::wstring_view( L"<h3 class=\"txt_title\">Terms</h3>"),
	std::wstring_view( L"<h3 class=\"txt_title\">Account/Password Policy</h3>"),
	std::wstring_view( L"<h3 class=\"txt_title\">Trademark</h3>"),
	// 必須見出しの固定順序。
	std::wstring_view( L"<h3 class=\"txt_title\">Disclaimer</h3>")} ;

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/** @brief Terms本文で許可する意味付きtag分類。 */
enum class AsixTermsTagKind {
	/// Main直下の既知背景container。
	INSIDE_BACKGROUND,
	/// Terms全体を囲む既知section。
	CONTAINER,
	/// Titleと注意文を囲む既知container。
	TITLE_WRAP,
	/// TERMS OF USEの固定title。
	TITLE,
	/// 注意文または各sectionの本文段落。
	PARAGRAPH,
	/// 四つのTerms sectionを囲むarticle。
	ARTICLE,
	/// Article内の既知本文container。
	TEXT_CONTENT,
	/// 一見出しと本文を持つsection。
	SECTION,
	/// 固定順序で現れる四つの見出し。
	HEADING,
	/// Terms内の箇条書き。
	LIST,
	/// 箇条書きの一項目。
	ITEM,
	/// Paragraph内の明示改行。
	BREAK,
} ;

/** @brief 一つの許可tag表現と閉じtag、改行属性を結合する内部定義。 */
struct AsixTermsTagDefinition {
	/// 属性を含む完全一致の開きtag。
	std::wstring_view opening ;
	/// 対応する閉じtag。空はvoid tag。
	std::wstring_view closing ;
	/// Parent規則と必須件数を選ぶ分類。
	AsixTermsTagKind  kind{} ;
	/// trueの場合は前後を正規化改行で分離する。
	bool			  separatesText{} ;
} ;

// 現行公式Terms mainで確認した属性を含むtag表現と閉じtagの有限許可表。
constexpr std::array TERMS_TAG_DEFINITIONS{
	AsixTermsTagDefinition{L"<div class=\"inside_bg\">", L"</div>",
						   AsixTermsTagKind::INSIDE_BACKGROUND, true},
	AsixTermsTagDefinition{L"<section class=\"container\">", L"</section>",
						   AsixTermsTagKind::CONTAINER, true},
	AsixTermsTagDefinition{L"<div class=\"tit_wrap\">", L"</div>", AsixTermsTagKind::TITLE_WRAP,
						   true},
	AsixTermsTagDefinition{L"<p class=\"title\">", L"</p>", AsixTermsTagKind::TITLE, true},
	AsixTermsTagDefinition{L"<p>", L"</p>", AsixTermsTagKind::PARAGRAPH, true},
	AsixTermsTagDefinition{L"<article class=\"text_wrap\">", L"</article>",
						   AsixTermsTagKind::ARTICLE, true},
	AsixTermsTagDefinition{L"<div class=\"txt_contant\">", L"</div>",
						   AsixTermsTagKind::TEXT_CONTENT, true},
	AsixTermsTagDefinition{L"<section>", L"</section>", AsixTermsTagKind::SECTION, true},
	AsixTermsTagDefinition{L"<h3 class=\"txt_title\">", L"</h3>", AsixTermsTagKind::HEADING, true},
	AsixTermsTagDefinition{L"<ul class=\"list\">", L"</ul>", AsixTermsTagKind::LIST, true},
	AsixTermsTagDefinition{L"<li>", L"</li>", AsixTermsTagKind::ITEM, true},
	AsixTermsTagDefinition{L"<br>", L"", AsixTermsTagKind::BREAK, true}} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 欠落または重複を曖昧なschemaとして拒否する。
 *
 * @param[in] text 有限長の検索対象。
 * @param[in] marker 一度だけ存在すべき固定文字列。
 * @param[out] position 成功時のmarker開始位置。
 * @return Markerが一度だけ存在する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool findUniqueMarker( const std::wstring_view text, const std::wstring_view marker,
									std::size_t &position) noexcept
{
	position = text.find( marker) ;
	return !marker.empty() && position != std::wstring_view::npos &&
		   text.find( marker, position + marker.size()) == std::wstring_view::npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief Tag境界の連続改行と行末空白を一つのCRLFへ正規化する。
 *
 * @param[in,out] text 正規化中のTerms全文。
 */
//------------------------------------------------------------------------------
void appendTermsBreak( std::wstring &text)
{
	// 改行直前のASCII空白を除去し、表示上の意味がない差を識別子へ含めない。
	while( !text.empty() && text.back() == L' ') {
		text.pop_back() ;
	}

	// 先頭または既存改行の直後へ空行を追加しない。
	if( text.empty() || text.ends_with( L"\r\n")) {
		return ;
	}

	text.append( L"\r\n") ;
}

//------------------------------------------------------------------------------
/**
 * @brief Markup整形用のASCII空白を畳み、可視文字の順序とUnicode値は変更しない。
 *
 * @param[in] character HTML text nodeまたは既知entityの一文字。
 * @param[in,out] pendingSpace 次の可視文字前に空白を一つ挿入する場合true。
 * @param[in,out] text 正規化中のTerms全文。
 * @return 本文上限内へ文字を追加または空白として保留できた場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool appendTermsCharacter( const wchar_t character, bool &pendingSpace,
										std::wstring &text)
{
	// markup整形用の空白は直ちに出力せず、次の可視文字まで区切りを保留する。
	if( character == L' ' || character == L'\t' || character == L'\r' || character == L'\n' ||
	   character == static_cast<wchar_t>( 0x00A0)) {
		pendingSpace = !text.empty() && !text.ends_with( L"\r\n") ;
		// 連続空白は次の可視文字がある場合だけ一つ残す。
		return true ;
	}

	// 可視文字間で必要な場合にだけ保留中の空白を一つ出力する。
	if( pendingSpace && !text.empty() && !text.ends_with( L"\r\n")) {
		text.push_back( L' ') ;
	}

	pendingSpace = false ;
	text.push_back( character) ;
	return text.size() <= MAXIMUM_PREPARATION_EULA_CHARACTERS ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未知名や数値参照を推測変換せず、Terms schema変更として拒否する。
 *
 * @param[in] entity Ampersandとsemicolonを含まないentity名。
 * @param[out] character 成功時の単一Unicode文字。
 * @return HTMLの既知named entityだけに一致した場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool decodeTermsEntity( const std::wstring_view entity, wchar_t &character) noexcept
{
	character = 0 ;
	// 既知のamp entityを表示用のアンパサンドへ復号する。
	if( entity == L"amp") {
		character = L'&' ;
	}
	// 既知のquot entityを二重引用符へ復号する。
	else if( entity == L"quot") {
		character = L'"' ;
	}
	// 既知のapos entityを単一引用符へ復号する。
	else if( entity == L"apos") {
		character = L'\'' ;
	}
	// 既知のlt entityを表示文字として復号し、tag開始とは解釈しない。
	else if( entity == L"lt") {
		character = L'<' ;
	}
	// 既知のgt entityを表示文字として復号し、tag終端とは解釈しない。
	else if( entity == L"gt") {
		character = L'>' ;
	}
	// 既知のnbsp entityを空白正規化の対象文字へ復号する。
	else if( entity == L"nbsp") {
		character = static_cast<wchar_t>( 0x00A0) ;
	}

	return character != 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 許可tag名だけを別containerへ移したschema変更もfail-closedで拒否する。
 *
 * @param[in] kind 開こうとしているtag分類。
 * @param[in] parent 現在の親tag定義。Main直下の場合nullptr。
 * @return ADR 0136で確認した親子関係に一致する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validTermsParent( const AsixTermsTagKind				kind,
									const AsixTermsTagDefinition *const parent) noexcept
{
	const auto parentIs = [parent]( const AsixTermsTagKind expected) noexcept {
		return parent != nullptr && parent->kind == expected ;
	} ; // Nullableな親の一致判定。
	// tag種別ごとに許可する親を固定し、別containerへの移動を拒否する。
	switch( kind) {
		// 背景 container は親を持たない最上位の配置だけを許可する。
		case AsixTermsTagKind::INSIDE_BACKGROUND:
			return parent == nullptr ;
		// 本文 container は固定背景要素の直下だけを許可する。
		case AsixTermsTagKind::CONTAINER:
			return parentIs( AsixTermsTagKind::INSIDE_BACKGROUND) ;
		// Title wrapper は本文 container の直下だけを許可する。
		case AsixTermsTagKind::TITLE_WRAP:
			return parentIs( AsixTermsTagKind::CONTAINER) ;
		// Title は専用 wrapper の直下だけを許可する。
		case AsixTermsTagKind::TITLE:
			return parentIs( AsixTermsTagKind::TITLE_WRAP) ;
		// 段落は title wrapper または本文 section の直下だけを許可する。
		case AsixTermsTagKind::PARAGRAPH:
			return parentIs( AsixTermsTagKind::TITLE_WRAP) || parentIs( AsixTermsTagKind::SECTION) ;
		// Article は本文 container の直下だけを許可する。
		case AsixTermsTagKind::ARTICLE:
			return parentIs( AsixTermsTagKind::CONTAINER) ;
		// Text content は article の直下だけを許可する。
		case AsixTermsTagKind::TEXT_CONTENT:
			return parentIs( AsixTermsTagKind::ARTICLE) ;
		// Section は text content の直下だけを許可する。
		case AsixTermsTagKind::SECTION:
			return parentIs( AsixTermsTagKind::TEXT_CONTENT) ;
		// 見出しは section の直下だけを許可する。
		case AsixTermsTagKind::HEADING:
			return parentIs( AsixTermsTagKind::SECTION) ;
		// List は section の直下だけを許可する。
		case AsixTermsTagKind::LIST:
			return parentIs( AsixTermsTagKind::SECTION) ;
		// List 項目は list の直下だけを許可する。
		case AsixTermsTagKind::ITEM:
			return parentIs( AsixTermsTagKind::LIST) ;
		// 改行は段落・list 項目・section の本文内だけを許可する。
		case AsixTermsTagKind::BREAK:
			return parentIs( AsixTermsTagKind::PARAGRAPH) || parentIs( AsixTermsTagKind::ITEM) ||
				   parentIs( AsixTermsTagKind::SECTION) ;
		// 未知 tag 種別を root 直下の許可要素へ読み替えない。
		default:
			// 定義外の列挙値をMain直下として受理しない。
			return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Tag stackと親子関係を検証し、未知tagや境界外本文を黙って除去しない。
 *
 * @param[in] body 単一main tagの内側にある有限HTML。
 * @param[out] text 成功時の正規化済み全文。失敗時の内容は使用しない。
 * @return 既知の構造、見出し、tag、entityを省略なく変換できた場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool termsPlainText( const std::wstring_view body, std::wstring &text)
{
	text.clear() ;
	constexpr std::wstring_view TITLE_MARKER =
		L"<p class=\"title\">TERMS OF USE</p>" ;	// 一意であるべき本文title。
	std::size_t titlePosition{} ;					// 固定titleの一意な開始位置。
	// Title欠落または重複を不完全な同意対象として拒否する。
	if( !findUniqueMarker( body, TITLE_MARKER, titlePosition)) {
		return false ;
	}

	std::array<std::size_t, TERMS_HEADING_MARKERS.size()>
		headingPositions{} ;	// 必須見出しごとの開始位置。
	// 四つの見出しを一意に取得し、公式pageの意味順序が変わっていないことを確認する。
	for( std::size_t index = 0U; index < TERMS_HEADING_MARKERS.size(); ++index) {
		// 見出し欠落、重複または並べ替えを拒否する。
		if( !findUniqueMarker( body, TERMS_HEADING_MARKERS[index], headingPositions[index]) ||
		   (index != 0U && headingPositions[index] <= headingPositions[index - 1U])) {
			return false ;
		}
	}

	std::vector<const AsixTermsTagDefinition *> stack ;	// Bodyと同じ寿命の定義pointer stack。
	bool		pendingSpace{} ;						// 次の可視文字前へ空白を残す場合true。
	std::size_t insideBackgroundCount{} ;				// Main直下containerの出現数。
	std::size_t containerCount{} ;						// Terms全体sectionの出現数。
	std::size_t titleWrapCount{} ;						// 注意文containerの出現数。
	std::size_t titleCount{} ;							// 固定title tagの出現数。
	std::size_t paragraphCount{} ;						// 注意文とsection本文の段落数。
	std::size_t articleCount{} ;						// 本文articleの出現数。
	std::size_t textContentCount{} ;					// 本文containerの出現数。
	std::size_t sectionCount{} ;						// 四つの見出しsection数。
	std::size_t headingCount{} ;						// 固定見出しtag数。
	std::size_t listCount{} ;							// 現行Termsの箇条書き数。
	std::size_t itemCount{} ;							// 箇条書き内の項目数。
	std::size_t breakCount{} ;							// 本文中の明示改行数。
	// Offsetを必ず前進させ、有限bodyを一度だけ走査する。
	for( std::size_t offset = 0U; offset < body.size();) {
		// tag開始を検出した場合は本文として除去する前に完全な構造を検証する。
		if( body[offset] == L'<') {
			const std::size_t end = body.find( L'>', offset + 1U) ;	// 現在tagの終端位置。
			// 未終端または過大なtagを切り詰めて解釈しない。
			if( end == body.npos || end - offset + 1U > MAXIMUM_TERMS_TAG_CHARACTERS) {
				return false ;
			}

			const std::wstring_view tag = body.substr( offset, end - offset + 1U) ;	// 完全tag。
			// 閉じtagはstackの直前要素との対応を確認してから閉じる。
			if( tag.starts_with( L"</")) {
				// 対応しない閉じtagまたはstack不足を拒否する。
				if( stack.empty() || stack.back()->closing != tag) {
					return false ;
				}

				const AsixTermsTagDefinition *const definition =
					// 改行判断後に破棄する閉じtag定義。
					stack.back() ;
				stack.pop_back() ;
				// 本文を区切る要素の終端では改行を入れ、保留空白を解除する。
				if( definition->separatesText) {
					appendTermsBreak( text) ;
					pendingSpace = false ;
				}
			} else {
				const AsixTermsTagDefinition *definition{} ;	// 完全一致した組み込みtag定義。
				// 許可表を有限回走査し、属性違いを同じtag名として受理しない。
				for( const AsixTermsTagDefinition &candidate : TERMS_TAG_DEFINITIONS) {
					// 既知の完全な開始tagに一致する定義だけを採用する。
					if( candidate.opening == tag) {
						definition = &candidate ;
						break ;
					}
				}

				const AsixTermsTagDefinition *const parent =
					// 開く直前の親tag。
					stack.empty() ? nullptr : stack.back() ;
				// 未知tag、属性または確認済み親子関係の変更を拒否する。
				if( definition == nullptr || !validTermsParent( definition->kind, parent)) {
					return false ;
				}

				// 要素種別ごとの出現数を集計し、必須構造と重複の検証へ渡す。
				switch( definition->kind) {
					// 背景要素を数え、後続の固定 schema 件数検証へ渡す。
					case AsixTermsTagKind::INSIDE_BACKGROUND:
						++insideBackgroundCount ;
						break ;

					// 本文 container の件数を schema 照合用に保持する。
					case AsixTermsTagKind::CONTAINER:
						++containerCount ;
						break ;

					// Title wrapper の件数を schema 照合用に保持する。
					case AsixTermsTagKind::TITLE_WRAP:
						++titleWrapCount ;
						break ;

					// Title 要素の件数を schema 照合用に保持する。
					case AsixTermsTagKind::TITLE:
						++titleCount ;
						break ;

					// 段落の件数を本文構造の検証用に保持する。
					case AsixTermsTagKind::PARAGRAPH:
						++paragraphCount ;
						break ;

					// Article の件数を schema 照合用に保持する。
					case AsixTermsTagKind::ARTICLE:
						++articleCount ;
						break ;

					// Text content の件数を schema 照合用に保持する。
					case AsixTermsTagKind::TEXT_CONTENT:
						++textContentCount ;
						break ;

					// Section の件数を本文構造の検証用に保持する。
					case AsixTermsTagKind::SECTION:
						++sectionCount ;
						break ;

					// 見出しの件数を本文構造の検証用に保持する。
					case AsixTermsTagKind::HEADING:
						++headingCount ;
						break ;

					// List の件数を本文構造の検証用に保持する。
					case AsixTermsTagKind::LIST:
						++listCount ;
						break ;

					// List 項目の件数を本文構造の検証用に保持する。
					case AsixTermsTagKind::ITEM:
						++itemCount ;
						break ;

					// 改行要素の件数も固定 schema の確認対象に含める。
					case AsixTermsTagKind::BREAK:
						++breakCount ;
						break ;

					// 未知 tag を件数未確認のまま通過させない。
					default:
						// 定義外値を件数未確認のtagとして通さない。
						return false ;
				}

				// 本文を区切る要素の開始では文字列の連結を防ぐ改行を入れる。
				if( definition->separatesText) {
					appendTermsBreak( text) ;
					pendingSpace = false ;
				}

				// 閉じtagを持つ要素だけをstackへ積み、有限の深さで追跡する。
				if( !definition->closing.empty()) {
					// 異常な深さへ記憶域を増やさない。
					if( stack.size() >= MAXIMUM_TERMS_DEPTH) {
						return false ;
					}

					stack.push_back( definition) ;
				}
			}

			offset = end + 1U ;
			continue ;
		}

		// entity開始を検出した場合は既知名と本文の配置を検証してから復号する。
		if( body[offset] == L'&') {
			const std::size_t end = body.find( L';', offset + 1U) ;	// Entityのsemicolon位置。
			// 未終端、過大またはcontainer外entityを拒否する。
			if( end == body.npos || end - offset > 12U || stack.empty()) {
				return false ;
			}

			wchar_t decoded{} ;	// 既知entityから得る単一文字。
			// 未知entityを黙って削除または文字列として残さない。
			if( !decodeTermsEntity( body.substr( offset + 1U, end - offset - 1U), decoded)) {
				return false ;
			}

			const AsixTermsTagKind parentKind = stack.back()->kind ;		// Entityの直属親分類。
			const bool visible = decoded != static_cast<wchar_t>( 0x00A0) ;	// NBSP以外なら可視文字。
			// Container直下のentityまたは本文上限超過を拒否する。
			if( (visible && parentKind != AsixTermsTagKind::TITLE &&
				parentKind != AsixTermsTagKind::PARAGRAPH &&
				parentKind != AsixTermsTagKind::HEADING && parentKind != AsixTermsTagKind::ITEM) ||
			   !appendTermsCharacter( decoded, pendingSpace, text)) {
				return false ;
			}

			offset = end + 1U ;
			continue ;
		}

		const wchar_t character = body[offset++] ;	// 現在のraw text node文字。
		const bool	  visible	= character != L' ' && character != L'\t' && character != L'\r' &&
							 character != L'\n' ;	// Markup整形空白以外の場合true。
		const AsixTermsTagKind parentKind =
			// Textの直属親分類。
			stack.empty() ? AsixTermsTagKind::BREAK : stack.back()->kind ;
		// Container直下の未知本文または本文上限超過を拒否する。
		if( (visible && parentKind != AsixTermsTagKind::TITLE &&
			parentKind != AsixTermsTagKind::PARAGRAPH && parentKind != AsixTermsTagKind::HEADING &&
			parentKind != AsixTermsTagKind::ITEM) ||
		   !appendTermsCharacter( character, pendingSpace, text)) {
			return false ;
		}
	}

	// 終端に残る整形空白と改行を削除し、同じ表示本文の識別子を安定させる。
	while( !text.empty() && (text.back() == L' ' || text.back() == L'\r' || text.back() == L'\n')) {
		text.pop_back() ;
	}

	return stack.empty() && insideBackgroundCount == 1U && containerCount == 1U &&
		   titleWrapCount == 1U && titleCount == 1U && paragraphCount >= 5U && articleCount == 1U &&
		   textContentCount == 1U && sectionCount == 4U && headingCount == 4U && listCount == 1U &&
		   itemCount != 0U && breakCount != 0U && validPreparationEulaText( text) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 空component、path、suffixまたはUnicode類似数字を受理しない。
 *
 * @param[in] value PageのVersion表示。
 * @return 四つの1～3桁ASCII数値componentならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isVersion( const std::wstring_view value) noexcept
{
	// 空または有限上限外の版を拒否する。
	if( value.empty() || value.size() > 15U) {
		return false ;
	}

	std::size_t componentCount{1U} ;	// 現在までに開始した数値component数。
	std::size_t digitCount{} ;			// 現在componentのASCII数字数。
	// 全文字を有限回で確認し、四つの数値component以外を拒否する。
	for( const wchar_t character : value) {
		// ASCII数字だけをversion componentへ数え、各componentの桁数を制限する。
		if( character >= L'0' && character <= L'9') {
			++digitCount ;
			// 過大なcomponent表現を受理しない。
			if( digitCount > 3U) {
				return false ;
			}

			continue ;
		}

		// 空component、dot以外または五つ目のcomponentを拒否する。
		if( character != L'.' || digitCount == 0U || componentCount >= 4U) {
			return false ;
		}

		++componentCount ;
		digitCount = 0U ;
	}

	return componentCount == 4U && digitCount != 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief Calendar上の有効日は推測せず、表示schemaだけを検証する。
 *
 * @param[in] value PageのRelease Date表示。
 * @return YYYY-MM-DD形式のASCII文字列ならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isReleaseDate( const std::wstring_view value) noexcept
{
	// 固定長またはseparatorが異なる表示を拒否する。
	if( value.size() != 10U || value[4] != L'-' || value[7] != L'-') {
		return false ;
	}

	// Separator以外がASCII数字であることを全桁確認する。
	for( std::size_t index = 0U; index < value.size(); ++index) {
		// 固定位置の区切り文字は数字検証から除く。
		if( index == 4U || index == 7U) {
			continue ;
		}

		// 日付の数字位置にASCII数字以外を許可しない。
		if( value[index] < L'0' || value[index] > L'9') {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 丸められた表示をbyte数やdownload上限へ変換しない。
 *
 * @param[in] value PageのFile Size表示。
 * @return 数値、dot、空白、KB／MBだけで構成された有限値ならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isDisplaySize( const std::wstring_view value) noexcept
{
	// 単位欠落、未対応単位または上限外を拒否する。
	if( value.size() < 4U || value.size() > MAXIMUM_VALUE_CHARACTERS ||
	   (!value.ends_with( L" KB") && !value.ends_with( L" MB"))) {
		return false ;
	}

	const std::wstring_view number = value.substr( 0U, value.size() - 3U) ;	// 単位前の数値部。
	bool					foundDot{} ;									// 小数点を既に一つ確認した場合true。
	bool					foundDigit{} ;									// 一桁以上のASCII数字を確認した場合true。
	// 数値部を有限回で確認し、数字と一つの内部dot以外を拒否する。
	for( std::size_t index = 0U; index < number.size(); ++index) {
		const wchar_t character = number[index] ;	// 現在確認する数値部の一文字。
		// 容量表示の数字部分を識別し、後続の書式検証へ進める。
		if( character >= L'0' && character <= L'9') {
			foundDigit = true ;
			continue ;
		}

		// 空小数、複数dotまたは数値外文字を拒否する。
		if( character != L'.' || foundDot || index == 0U || index + 1U == number.size()) {
			return false ;
		}

		foundDot = true ;
	}

	return foundDigit ;
}

//------------------------------------------------------------------------------
/**
 * @brief HTMLを実行せず、現在pageの単純なtext nodeだけを読み取る。
 *
 * @param[in] row 一つのASIX table item。
 * @param[in] label 一度だけ存在すべきlabelとBR marker。
 * @param[out] value 成功時の直後text node。
 * @return Label直後に有限な単一値がある場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readBrValue( const std::wstring_view row, const std::wstring_view label,
							   std::wstring &value)
{
	value.clear() ;
	std::size_t position{} ;	// 一意なlabelの開始位置。
	// 必須値の欠落または重複を拒否する。
	if( !findUniqueMarker( row, label, position)) {
		return false ;
	}

	const std::size_t begin = position + label.size() ;	// 値の開始位置。
	const std::size_t end	= row.find( L'<', begin) ;	// Text nodeの終了位置。
	// Tag終端がない値、空値または上限外を拒否する。
	if( end == std::wstring_view::npos || begin >= end || end - begin > MAXIMUM_VALUE_CHARACTERS) {
		return false ;
	}

	value.assign( row.substr( begin, end - begin)) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示URLを保持するだけで、payload取得capabilityを発行しない。
 *
 * @param[in] row 一つのASIX driver行。
 * @param[out] url 成功時のASIX公式file endpoint。
 * @param[out] releaseKey 成功時の数値download ID。
 * @return 固定host／pathと有限な数値IDが一件だけある場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readDownloadUrl( const std::wstring_view row, std::wstring &url,
								   std::wstring &releaseKey)
{
	url.clear() ;
	releaseKey.clear() ;
	constexpr std::wstring_view ATTRIBUTE = L"data-href=\"" ;	// URL attribute開始marker。
	std::size_t					position{} ;					// 一意なURL attributeの開始位置。
	// URL欠落または複数URLを拒否する。
	if( !findUniqueMarker( row, ATTRIBUTE, position)) {
		return false ;
	}

	const std::size_t begin = position + ATTRIBUTE.size() ;	// URL開始位置。
	const std::size_t end	= row.find( L'\"', begin) ;		// URL終了位置。
	// 閉じquoteがないURLまたは上限外を拒否する。
	if( end == std::wstring_view::npos || begin >= end || end - begin > MAXIMUM_URL_CHARACTERS) {
		return false ;
	}

	const std::wstring_view candidate = row.substr( begin, end - begin) ;	// 検証対象URL。
	// Query、fragment、非HTTPSまたは別hostを拒否する。
	if( candidate.find( L'?') != std::wstring_view::npos ||
	   candidate.find( L'#') != std::wstring_view::npos ||
	   validateOfficialHttpsUrl( candidate, DOWNLOAD_HOSTS) != 0) {
		return false ;
	}

	// 固定scheme、host、path外または空IDを拒否する。
	if( !candidate.starts_with( DOWNLOAD_PREFIX) || candidate.size() <= DOWNLOAD_PREFIX.size()) {
		return false ;
	}

	const std::wstring_view fileId = candidate.substr( DOWNLOAD_PREFIX.size()) ;	// 数値file ID。
	// 任意path文字をfile IDとして受理しない。
	if( !std::ranges::all_of( fileId, []( const wchar_t character) {
		   return character >= L'0' && character <= L'9' ;
	   })) {
		return false ;
	}

	url.assign( candidate) ;
	releaseKey.assign( fileId) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 前後のtable itemを混ぜず、対象一行の値だけを解析する。
 *
 * @param[in] html 検証中の固定製品page。
 * @param[in] title Setup programと区別した対象driver行名。
 * @param[in] family 行へ割り当てるWindows client系列。
 * @param[out] entry 成功時の表示専用metadata。
 * @return 一意な行の必須値と公式endpointが整合する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool parseDriverRow( const std::wstring_view html, const std::wstring_view title,
								  const AsixWindowsClientFamily family, AsixDriverPageEntry &entry)
{
	entry						   = {} ;
	const std::wstring titleMarker = L"<p>" + std::wstring( title) + L"</p>" ;	// 完全一致行名。
	std::size_t		   titlePosition{} ;										// 一意な行名の開始位置。
	// 対象行の欠落または重複を拒否する。
	if( !findUniqueMarker( html, titleMarker, titlePosition)) {
		return false ;
	}

	const std::size_t rowBegin = html.rfind( ROW_MARKER, titlePosition) ;	// 対象行の開始位置。
	// 対象titleの次に始まる行の位置。現在のdriver行を解析する終端境界。
	const std::size_t rowEnd = html.find( ROW_MARKER, titlePosition + titleMarker.size()) ;
	// 一つのtable itemへ閉じないschemaを拒否する。
	if( rowBegin == std::wstring_view::npos || rowEnd == std::wstring_view::npos ||
	   rowBegin >= titlePosition || rowEnd <= titlePosition) {
		return false ;
	}

	const std::wstring_view row = html.substr( rowBegin, rowEnd - rowBegin) ;	// 対象行だけのview。
	std::size_t				certificationPosition{} ;							// 一意なx64認証説明の開始位置。
	// x64 driver-only説明がない行または別形式を拒否する。
	if( !findUniqueMarker( row, X64_CERTIFICATION, certificationPosition) ||
	   row.find( L"setup program") != std::wstring_view::npos ||
	   row.find( L"ARM") != std::wstring_view::npos) {
		return false ;
	}

	AsixDriverPageEntry parsed ;	// 全条件成立時だけ出力する一時結果。
	parsed.family = family ;
	parsed.title  = title ;
	// 一つでも欠ける表示情報を推測で補完しない。
	if( !readBrValue( row, L"Version<br/>", parsed.version) || !isVersion( parsed.version) ||
	   !readBrValue( row, L"Release Date<br/>", parsed.releaseDate) ||
	   !isReleaseDate( parsed.releaseDate) ||
	   !readBrValue( row, L"File Size<br/>", parsed.displaySize) ||
	   !isDisplaySize( parsed.displaySize) ||
	   !readDownloadUrl( row, parsed.downloadUrl, parsed.releaseKey)) {
		return false ;
	}

	entry = std::move( parsed) ;
	return true ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseAsixAx88179aProductPage( const std::wstring_view html, AsixAx88179aCatalog &catalog)
{
	catalog = {} ;
	std::size_t productPosition{} ;	// 一意な固定製品markerの位置。
	std::size_t termsPosition{} ;	// 一意な固定Terms linkの位置。
	// 空、過大、NUL、別製品または必須section欠落を拒否する。
	if( html.empty() || html.size() > MAXIMUM_HTML_CHARACTERS ||
	   html.find( L'\0') != std::wstring_view::npos ||
	   !findUniqueMarker( html, PRODUCT_MARKER, productPosition) ||
	   !findUniqueMarker( html, TERMS_LINK, termsPosition) ||
	   html.find( L"USB 3.2 Gen1 to Gigabit Ethernet Controller") == std::wstring_view::npos ||
	   html.find( L"Software &amp; Tools") == std::wstring_view::npos) {
		return false ;
	}

	try {
		AsixAx88179aCatalog parsed ;	// 二行とも成立した場合だけ公開する一時結果。
		// 行欠落または同じendpointへの曖昧な対応を拒否する。
		if( !parseDriverRow( html, L"Windows 10 64-bit Driver",
						   AsixWindowsClientFamily::WINDOWS10_X64, parsed.windows10) ||
		   !parseDriverRow( html, L"Windows 11 64-bit Driver",
						   AsixWindowsClientFamily::WINDOWS11_X64, parsed.windows11) ||
		   parsed.windows10.downloadUrl == parsed.windows11.downloadUrl) {
			return false ;
		}

		catalog = std::move( parsed) ;
		return true ;
	} catch( const std::bad_alloc &) {
		catalog = {} ;
		// 記憶域不足を部分的なmetadata成功として返さない。
		return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseAsixTermsPage( const std::wstring_view html, AsixTermsSnapshot &snapshot)
{
	snapshot								 = {} ;
	constexpr std::wstring_view MAIN_OPENING = L"<main>" ;	// 属性なしmainの固定開始tag。
	constexpr std::wstring_view MAIN_CLOSING = L"</main>" ;	// Mainの固定終了tag。
	std::size_t					mainBegin{} ;				// 一意なmain開始tagの位置。
	std::size_t					mainEnd{} ;					// 一意なmain終了tagの位置。
	// 欠落、重複、過大または空の同意対象を拒否する。
	if( html.empty() || html.size() > MAXIMUM_TERMS_HTML_CHARACTERS ||
	   html.find( L'\0') != std::wstring_view::npos ||
	   !findUniqueMarker( html, MAIN_OPENING, mainBegin) ||
	   !findUniqueMarker( html, MAIN_CLOSING, mainEnd) ||
	   mainEnd <= mainBegin + MAIN_OPENING.size()) {
		return false ;
	}

	try {
		const std::wstring_view body =
			html.substr( mainBegin + MAIN_OPENING.size(),
						mainEnd - mainBegin - MAIN_OPENING.size()) ;	// Main内だけの非所有view。
		AsixTermsSnapshot parsed ;										// 全変換とhash成功後だけ出力する一時snapshot。
		// 不完全本文や識別子算出失敗を同意可能として返さない。
		if( !termsPlainText( body, parsed.text) ||
		   makeComputedEulaRevision( parsed.text, parsed.revision) != 0) {
			return false ;
		}

		snapshot = std::move( parsed) ;
		return true ;
	} catch( const std::bad_alloc &) {
		snapshot = {} ;
		// 記憶域不足を部分的なTerms解析成功として返さない。
		return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool selectAsixAx88179aWindowsEntry( const AsixAx88179aCatalog &catalog, const bool windowsServer,
									const std::uint32_t windowsBuild, AsixDriverPageEntry &entry)
{
	entry = {} ;
	// ServerまたはWindows 10未満／判定不能では選択しない。
	if( windowsServer || windowsBuild < WINDOWS10_MINIMUM_BUILD) {
		return false ;
	}

	entry = windowsBuild >= WINDOWS11_MINIMUM_BUILD ? catalog.windows11 : catalog.windows10 ;
	return !entry.title.empty() && !entry.downloadUrl.empty() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asix_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool makeAsixAx88179aPreparedRelease( const std::wstring_view productHtml,
									 const std::wstring_view termsHtml, const bool windowsServer,
									 const std::uint32_t	windowsBuild,
									 OfficialReleaseRecord &record)
{
	record = {} ;
	try {
		AsixAx88179aCatalog catalog ;	// 検証済みの二OS分製品metadata。
		AsixDriverPageEntry entry ;		// 実client OSに対応する一配布行。
		AsixTermsSnapshot	terms ;		// 固定Terms pageの全文snapshot。
		// 一方のpageやOS対応が不成立なら部分recordを公開しない。
		if( !parseAsixAx88179aProductPage( productHtml, catalog) ||
		   !selectAsixAx88179aWindowsEntry( catalog, windowsServer, windowsBuild, entry) ||
		   !parseAsixTermsPage( termsHtml, terms)) {
			return false ;
		}

		OfficialReleaseRecord parsed ;	// 全field検証後だけ出力へ移す一時record。
		parsed.family		  = OfficialReleaseFamily::ASIX_AX88179A ;
		parsed.releaseKey	  = entry.releaseKey ;
		parsed.packageVersion = entry.version ;
		parsed.displaySize	  = entry.displaySize ;
		parsed.publishedDate  = entry.releaseDate ;
		parsed.downloadUrl	  = entry.downloadUrl ;
		parsed.license		  = OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD ;
		parsed.eulaRevision	  = terms.revision ;
		parsed.parserRevision = PREPARED_PARSER_REVISION ;
		parsed.eulaText		  = terms.text ;
		// ASIX限定の空file名・数値ID・固定URL契約を最後に再確認する。
		if( !validPreparedReleaseIdentity( parsed)) {
			return false ;
		}

		record = std::move( parsed) ;
		return true ;
	} catch( const std::bad_alloc &) {
		record = {} ;
		// 記憶域不足時に不完全な配布recordを残さない。
		return false ;
	}
}

} // namespace drivercrate
