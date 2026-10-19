//------------------------------------------------------------------------------
/**
 * @file intel_download_license_parser.cpp
 * @brief Intel配布pageの非実行許諾snapshot実装。
 * @version 01.04.01
 * @date 2026/09/23
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  現行pageのtextarea・外部asset名構造へ追従。
 * Ver.01.02.00 Shunji Ogawa  2026/09/23  外枠空白、明示改訂title、listと非実行linkを保持。
 * Ver.01.03.00 Shunji Ogawa  2026/09/23  全区間取得接続と公式module根拠付き許諾境界を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/28  許諾内部走査へ同一controlを伝播しOOMを保持。
 * Ver.01.04.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 単一page内の配布URLと許諾をworkerの一時recordへ結合します。本文を実行せず、未知構造や不完全な変換は拒否します。
 */
//------------------------------------------------------------------------------

#include "platform/intel_download_license_parser.h"

#include "core/official_preparation.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
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
constexpr std::size_t		MAXIMUM_PAGE_CHARACTERS			= 2U * 1024U * 1024U ;	// Page入力上限。
constexpr std::size_t		MAXIMUM_LICENSE_HTML_CHARACTERS = 128U * 1024U ;		// 許諾HTML上限。
constexpr std::size_t		MAXIMUM_TAG_CHARACTERS			= 4096U ;				// 引用符を含む一tagの上限。
constexpr std::size_t		MAXIMUM_DEPTH					= 64U ;					// 許諾本文の有限stack要素上限。
constexpr std::wstring_view TEXTAREA =
	L"<textarea id=\"content-raw\" class=\"license-modal-content_body_license-text-raw\""
	L" tabindex=\"0\">" ;	// 確認済みの埋込み許諾欄。
constexpr std::wstring_view SCRIPT_PREFIX =
	L"<script type=\"text/javascript\" src=\"/etc.clientlibs/intel/clientlibs/bundles/"
	L"resources/js/" ;													// 本文末尾でのみ許可するpage用外部script参照。
constexpr std::wstring_view SCRIPT_SUFFIX = L".bundle.js\"></script>" ;	// 空scriptの終端。
constexpr std::array		BODY_TAGS{
	   std::wstring_view( L"b"), std::wstring_view( L"br"), std::wstring_view( L"div"),
	   std::wstring_view( L"p"), std::wstring_view( L"table"), std::wstring_view( L"tbody"),
	   // 現行本文で確認したtag名。
	   std::wstring_view( L"td"), std::wstring_view( L"tr"), std::wstring_view( L"ul"),
	   std::wstring_view( L"li"), std::wstring_view( L"a")} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

/**
 * @brief 文書外枠に限ってASCII空白を除いた借用範囲を返します。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] value 外枠tag間の文字列。本文内部には使用しません。
 * @return 前後空白のないview。空白だけなら空。
 */
[[nodiscard]] std::wstring_view trimFrameSpace( CollectorParserContext *control,
											   std::wstring_view	   value)
{
	collectorParserCheckpoint( control) ;
	std::size_t first = 0U ;	// 先頭空白の有限走査。
	// 外枠の空白を一文字ずつ読みます。
	while( first < value.size() && std::wstring_view( L" \t\r\n").find( value[first]) != value.npos) {
		collectorParserStep( control) ;
		++first ;
	}

	// 空白だけの外枠は空範囲として扱う。
	if( first == value.size()) {
		return {} ;
	}

	std::size_t last = value.size() - 1U ;	// 末尾空白の有限走査。
	// 空白だけの値は先に返しているため先頭へ戻り過ぎません。
	while( last > first && std::wstring_view( L" \t\r\n").find( value[last]) != value.npos) {
		collectorParserStep( control) ;
		--last ;
	}

	return value.substr( first, last - first + 1U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 複数欄の最初の一件を同意対象へ推測採用しません。
 *
 * @param[in] input 有限入力。
 * @param[in] marker 空でない完全一致marker。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] position 成功時の開始位置。
 * @return Markerが一つだけ存在する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool uniquePosition( CollectorParserContext *control, const std::wstring_view input,
								  const std::wstring_view marker, std::size_t &position)
{
	collectorParserCheckpoint( control) ;
	position = collectorParserFind( control, input, marker) ;
	return !marker.empty() && position != input.npos &&
		   collectorParserFind( control, input, marker, position + marker.size()) == input.npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief 属性値の大なり記号をtag終端として解釈しません。
 *
 * @param[in] input 有限入力。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] begin 開き山括弧の位置。
 * @return 引用符の外側の終端位置。不正時はnpos。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::size_t tagEnd( CollectorParserContext *control, const std::wstring_view input,
								 const std::size_t begin)
{
	collectorParserCheckpoint( control) ;
	wchar_t quote{} ;	// 0の場合は属性引用符の外側。
	// 入力長とtag上限の範囲だけを前進する。
	for( std::size_t index = begin + 1U;
		index < input.size() && index - begin <= MAXIMUM_TAG_CHARACTERS; ++index) {
		collectorParserStep( control) ;
		const wchar_t character = input[index] ;	// 今回調べるtag内文字。
		// 引用符内の大なり記号をtag終端として扱わない。
		if( quote != 0) {
			// 対応する引用符で属性値が閉じたことを記録する。
			if( character == quote) {
				quote = 0 ;
			}
		}
		// 属性値の引用開始を記録して内部の区切りを保護する。
		else if( character == L'\'' || character == L'"') {
			quote = character ;
		}
		// 引用符の外側にある大なり記号だけをtag終端として返す。
		else if( character == L'>') {
			return index ;
		}
	}

	// 未終端属性や過大tagを省略しない。
	if( input.size() - begin > MAXIMUM_TAG_CHARACTERS + 1U) {
		collectorParserLimit( control) ;
	}

	return input.npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief class等の引用符内に書かれた偽属性を結合根拠に使いません。
 *
 * @param[in] tag 終端検証済みbutton tag。
 * @param[in] downloadUrl 系列parserが検証した同一pageの配布URL。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] requirePublicClass 公開download classも要求する場合true。
 * @return 属性としてmodal 1と対象URLが一意に指定される場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool buttonMatches( CollectorParserContext *control, const std::wstring_view tag,
								 const std::wstring_view downloadUrl,
								 const bool				 requirePublicClass = false)
{
	collectorParserCheckpoint( control) ;
	// 想定したbutton tagでない断片をdownload結合の根拠にしない。
	if( !tag.starts_with( L"<button ") || !tag.ends_with( L">")) {
		return false ;
	}

	bool						   modal{} ;		// 対象modal属性の一致状態。
	bool						   publicClass{} ;	// 公開download操作のclass token。
	bool						   href{} ;			// 対象URL属性の一致状態。
	std::vector<std::wstring_view> names ;			// 最大16属性の重複検査用非所有名。
	// Tag終端まで属性を前進し、値の内部を属性名として再走査しない。
	for( std::size_t offset = 7U; offset < tag.size() - 1U;) {
		collectorParserStep( control) ;
		// 属性間の空白だけを読み飛ばして次の属性名へ進む。
		if( tag[offset] == L' ' || tag[offset] == L'\t' || tag[offset] == L'\r' ||
		   tag[offset] == L'\n') {
			++offset ;
			continue ;
		}

		const std::size_t begin = offset ;	// 今回属性名の先頭。
		// ASCII英小文字・hyphen・underscoreからなる既知形式の属性名だけを読む。
		while( offset < tag.size() - 1U && ((tag[offset] >= L'a' && tag[offset] <= L'z') ||
										   tag[offset] == L'-' || tag[offset] == L'_')) {
			collectorParserStep( control) ;
			++offset ;
		}

		const std::wstring_view name = tag.substr( begin, offset - begin) ;	// 今回属性名。
		// 空、過剰、重複の属性を拒否し、曖昧な結合根拠を採用しない。
		if( names.size() == 16U) {
			collectorParserLimit( control) ;
		}

		// 空属性や重複属性を構造不正として扱います。
		if( name.empty() || names.size() == 16U || std::ranges::find( names, name) != names.end()) {
			return false ;
		}

		names.push_back( name) ;
		// 値付き属性は引用範囲を確定してから名前ごとに検証する。
		if( offset < tag.size() - 1U && tag[offset] == L'=') {
			++offset ;
			// 値が欠ける属性や引用符なしの値を拒否する。
			if( offset >= tag.size() - 1U || (tag[offset] != L'"' && tag[offset] != L'\'')) {
				return false ;
			}

			const wchar_t	  quote = tag[offset++] ;									// 値を囲む引用符。
			const std::size_t end = collectorParserFind( control, tag, quote, offset) ;	// 値の終端。
			// tag内で閉じない属性値を採用しない。
			if( end == tag.npos || end >= tag.size() - 1U) {
				return false ;
			}

			const std::wstring_view value = tag.substr( offset, end - offset) ;	// 属性値。
			// license modalの明示IDが期待値と一致することを記録する。
			if( name == L"data-modal-id") {
				modal = value == L"1" ;
			}
			// download URLとの完全一致をbutton結合条件へ反映する。
			else if( name == L"data-href") {
				href = value == downloadUrl ;
			}
			// 結合対象以外の値付き属性は既知の補助属性だけに制限する。
			else if( name == L"class") {
				const std::wstring tokens =
					L" " + std::wstring( value) + L" " ;	// 完全tokenの照合用。
				publicClass =
					collectorParserFind( control, tokens, L" available-download-button__cta ") !=
					tokens.npos ;
			}
			// Class以外の補助属性は既知名だけを認める。
			else if( name != L"data-wap_ref") {
				return false ;
			}

			offset = end + 1U ;
		}
		// 値なし属性は確認済みのdata-wap以外を拒否する。
		else if( name != L"data-wap") {
			return false ;
		} // 既知boolean属性だけを受理する。

		// 属性末尾に区切り空白がない曖昧なtag構造を拒否する。
		if( offset < tag.size() - 1U && tag[offset] != L' ' && tag[offset] != L'\t' &&
		   tag[offset] != L'\r' && tag[offset] != L'\n') {
			return false ;
		}
	}

	return modal && href && (!requirePublicClass || publicClass) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未知entity、NUL、surrogate、数値overflowを拒否します。
 *
 * @param[in] entity 最大12文字のentity本体。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in,out] text 成功時だけ復号文字を追加する一時本文。
 * @return 既知名または有効なUnicode数値参照ならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool decodeEntity( CollectorParserContext *control, const std::wstring_view entity,
								std::wstring &text)
{
	collectorParserCheckpoint( control) ;
	std::uint32_t code{} ;	// 復号するUnicode scalar value。
	// 既知の引用符entityを表示文字へ復元する。
	if( entity == L"quot") {
		code = L'"' ;
	}
	// 既知のampersand entityを表示文字へ復元する。
	else if( entity == L"amp") {
		code = L'&' ;
	}
	// 既知の小なりentityを表示文字へ復元する。
	else if( entity == L"lt") {
		code = L'<' ;
	}
	// 既知の大なりentityを表示文字へ復元する。
	else if( entity == L"gt") {
		code = L'>' ;
	}
	// 既知のapostrophe entityを表示文字へ復元する。
	else if( entity == L"apos") {
		code = L'\'' ;
	}
	// 改行しない空白のentityを対応するUnicode文字へ復元する。
	else if( entity == L"nbsp") {
		code = 0xA0U ;
	}
	// 数値文字参照は基数とUnicode範囲を検証してから復元する。
	else if( entity.starts_with( L"#")) {
		const bool hex =
			// 数値の基数選択。
			entity.size() > 1U && (entity[1] == L'x' || entity[1] == L'X') ;
		const std::uint32_t base  = hex ? 16U : 10U ;	// 検証する進数。
		const std::size_t	first = hex ? 2U : 1U ;		// 数値部分の先頭。
		// 数字のない数値文字参照を拒否する。
		// 空の数値参照を拒否する。
		if( first == entity.size()) {
			return false ;
		}

		// 加算前にUnicode上限を確認する有限数値変換。
		for( std::size_t index = first; index < entity.size(); ++index) {
			collectorParserStep( control) ;
			const wchar_t		character = entity[index] ;	// 変換する一桁。
			const std::uint32_t digit	  = character >= L'0' && character <= L'9'
												? static_cast<std::uint32_t>( character - L'0')
											: character >= L'a' && character <= L'f'
												? static_cast<std::uint32_t>( character - L'a' + 10)
											: character >= L'A' && character <= L'F'
												? static_cast<std::uint32_t>( character - L'A' + 10)
												: base ;	// 基数と同じ値は不正桁を示す。
			// 基数外の桁とUnicode上限を超える数値参照を拒否する。
			if( digit >= base || code > (0x10FFFFU - digit) / base) {
				return false ;
			}

			code = code * base + digit ;
		}
	} else {
		return false ;
	} // 未知文字参照を削除した本文を返さない。

	// NULと単独surrogateを表示本文へ混入させない。
	if( code == 0U || (code >= 0xD800U && code <= 0xDFFFU)) {
		return false ;
	}

	// 基本多言語面の外の文字をUTF-16 surrogate pairとして保持する。
	if( code > 0xFFFFU) {
		code -= 0x10000U ;
		text += static_cast<wchar_t>( 0xD800U + (code >> 10U)) ;
		text += static_cast<wchar_t>( 0xDC00U + (code & 0x3FFU)) ;
	} else {
		text += static_cast<wchar_t>( code) ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 外部script参照は末尾だけで認識し、実行や取得を行いません。
 *
 * @param[in] body body tagの内側の有限許諾HTML。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in,out] text Titleを含む一時本文。失敗時は呼出側が破棄する。
 * @return 既知の入れ子を保ち本文を全て変換できた場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool bodyPlainText( CollectorParserContext *control, const std::wstring_view body,
								 std::wstring &text)
{
	collectorParserCheckpoint( control) ;
	std::vector<std::wstring_view> stack ;	// 有効期間がbodyと同じ非所有tag名のstack。
	bool scriptTail{} ;						// true以降は空白と固定形式の外部script参照だけを許す。
	bool hasText{} ;						// Title以外の実本文が一文字以上存在したか。
	// 各反復でoffsetを前進し、本文／tag／entityを途中で切り詰めない。
	for( std::size_t offset = 0U; offset < body.size();) {
		collectorParserStep( control) ;
		// 既知の外部script参照は本文末尾の構造としてだけ解析する。
		if( body.substr( offset).starts_with( SCRIPT_PREFIX)) {
			// 本文tag内のscriptを黙って除去して成功扱いしない。
			// 本文途中に埋め込まれたscriptを除去しない。
			if( !stack.empty()) {
				return false ;
			}

			const std::size_t begin = offset + SCRIPT_PREFIX.size() ;	// Script basename開始。
			const std::size_t end =
				// 既知suffixの位置。
				collectorParserFind( control, body, SCRIPT_SUFFIX, begin) ;
			// script basenameの欠落、未終端、長さ超過を拒否する。
			if( end == body.npos || end == begin || end - begin > 256U) {
				return false ;
			}

			const std::wstring_view name = body.substr( begin, end - begin) ;	// 非所有basename。
			// script basenameを確認済みASCII文字集合に制限する。
			// 任意URLやinline codeを受理しない。
			if( !std::ranges::all_of( name, []( const wchar_t character) {
				   return (character >= L'a' && character <= L'z') ||
						  (character >= L'A' && character <= L'Z') ||
						  (character >= L'0' && character <= L'9') || character == L'.' ||
						  character == L'-' || character == L'_' ;
			   })) {
				return false ;
			}

			scriptTail = true ;
			offset	   = end + SCRIPT_SUFFIX.size() ;
			continue ;
		}

		// script参照後は空白以外の本文が残らないことを確認する。
		if( scriptTail) {
			// script後の表示本文を捨てて解析成功にしない。
			if( body[offset] != L' ' && body[offset] != L'\t' && body[offset] != L'\r' &&
			   body[offset] != L'\n') {
				return false ;
			}

			++offset ;
			// Script後の表示本文を落として成功にしない。
			continue ;
		}

		// tag開始を認識し、許可tagと入れ子の整合性を検証する。
		if( body[offset] == L'<') {
			const std::size_t end = tagEnd( control, body, offset) ;	// 引用符を考慮したtag終端。
			// 閉じないtagを本文へ取り込まず拒否する。
			if( end == body.npos) {
				return false ;
			}

			std::wstring_view tag	  = body.substr( offset + 1U, end - offset - 1U) ;	// 非所有tag。
			const bool		  closing = tag.starts_with( L"/") ;						// 閉じtagかどうか。
			// 閉じtagの記号を除いて開始tagとの名前照合を行う。
			if( closing) {
				tag.remove_prefix( 1U) ;
			}

			// 属性を除いたtag名。stackに保存してもbodyの寿命内だけで使用する。
			const std::wstring_view name =
				tag.substr( 0U, collectorParserFindSet( control, tag, L" /\t\r\n", false, false)) ;
			// 名前が既知でも属性による本文の参照を許可しない。
			const std::wstring_view attributes = tag.substr( name.size()) ;	// 属性または末尾空白。
			// 既知の本文tag以外を解釈または黙認しない。
			if( std::ranges::find( BODY_TAGS, name) == BODY_TAGS.end()) {
				return false ;
			}

			// 閉じtagは属性とstackの対応を確認してから入れ子を戻す。
			if( closing) {
				// 閉じtagの余分な属性、余剰終端、名前不一致を拒否する。
				if( collectorParserFindSet( control, attributes, L" \t\r\n", true, false) !=
					   attributes.npos ||
				   stack.empty() || stack.back() != name) {
					return false ;
				}

				stack.pop_back() ;
			}
			// 改行tagを通常の入れ子tagと分けて扱う。
			else if( name == L"br") {
				// 改行tagに未確認の属性を許容しない。
				if( attributes != L"" && attributes != L" /" && attributes != L"/") {
					return false ;
				}
			}
			// 公開許諾の外部参照を実行せず、リンク先も本文へ残す。
			else if( name == L"a") {
				// Anchorも同じstackの明示上限へ含めます。
				if( stack.size() == MAXIMUM_DEPTH) {
					collectorParserLimit( control) ;
				}

				constexpr std::wstring_view PREFIX = L" href=\"" ;	// 非実行参照の開始。
				const auto					endQuote =
					// href終端。
					collectorParserFind( control, attributes, L'"', PREFIX.size()) ;
				// 有限の引用付き参照以外を本文へ埋め込まない。
				if( !attributes.starts_with( PREFIX) || endQuote == attributes.npos ||
				   endQuote - PREFIX.size() > 2048U || stack.size() == MAXIMUM_DEPTH) {
					return false ;
				}

				const auto url =
					// 公開許諾内参照。
					attributes.substr( PREFIX.size(), endQuote - PREFIX.size()) ;
				const auto tail = attributes.substr( endQuote + 1U) ;	// 任意追加属性は拒否。
				// Script URL、制御文字、未確認属性と曖昧なentityは受理しない。
				if( (!url.starts_with( L"http://") && !url.starts_with( L"https://")) ||
				   collectorParserFindSet( control, url, L" \t\r\n<>&\"", false, false) !=
					   url.npos ||
				   (!tail.empty() && tail != L" target=\"_blank\"")) {
					return false ;
				}

				text += L" [" + std::wstring( url) + L"] " ;
				stack.push_back( name) ;
			} else {
				// 通常tagの属性は確認済みの引用付きstyle形式に制限する。
				// CSSを評価せず、他属性を混入させない。
				if( !attributes.empty() &&
				   (attributes.size() < 9U || !attributes.starts_with( L" style=\"") ||
					!attributes.ends_with( L"\"") ||
					collectorParserFind( control, attributes.substr( 8U, attributes.size() - 9U),
										L'"') != attributes.npos)) {
					return false ;
				}

				// tagの入れ子上限を超える本文を拒否する。
				if( stack.size() == MAXIMUM_DEPTH) {
					collectorParserLimit( control) ;
					return false ;
				}

				stack.push_back( name) ;
			}

			// 強調tag以外の構造境界を表示本文の改行へ反映する。
			// 段落・表・セルを連結して意味を変えない。
			if( name != L"b") {
				text += L"\r\n" ;
			}

			offset = end + 1U ;
		}
		// ampersandは文字参照と通常文字を区別して本文へ復元する。
		else if( body[offset] == L'&') {
			const std::size_t end =
				// Entityの終端。
				collectorParserFind( control, body, L';', offset + 1U) ;
			// 未終端や長過ぎるentityらしい表現を通常文字として通さない。
			if( end == body.npos || end - offset > 12U) {
				// 長過ぎるentityや未終端の数値参照を通常のampersandとして通過させない。
				const wchar_t next = offset + 1U < body.size() ? body[offset + 1U] : L' ' ;
				// 文字参照の開始らしい未終端表現を通常のampersandとして通さない。
				if( (next >= L'a' && next <= L'z') || (next >= L'A' && next <= L'Z') ||
				   next == L'#') {
					return false ;
				}

				// 通常のampersandはそのまま表示する。
				text += body[offset++] ;
			} else {
				// 未知または不正な文字参照を含むlicense本文を拒否する。
				if( !decodeEntity( control, body.substr( offset + 1U, end - offset - 1U), text)) {
					return false ;
				}

				offset = end + 1U ;
			}

			hasText = true ;
		} else {
			const wchar_t character = body[offset++] ;	// 全文へ保存する一文字。
			text += character ;
			hasText = hasText || (character != L' ' && character != L'\t' && character != L'\r' &&
								  character != L'\n') ;
		}

		// 復元後のEULA本文も保持文字数の上限を守る。
		if( text.size() > MAXIMUM_PREPARATION_EULA_CHARACTERS) {
			collectorParserLimit( control) ;
			return false ;
		}
	}

	return stack.empty() && hasText &&
		   (control != nullptr
				? validPreparationEulaTextControlled(
					  text,
					  []( void *borrowed) {
						  static_cast<CollectorParserContext *>( borrowed)->checkpoint() ;
					  },
					  control)
				: validPreparationEulaText( text)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief URLや配布版を許諾改訂識別子として代用しません。
 *
 * @param[in] document 埋込み許諾HTML。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] title 成功時の明示title。
 * @return Intelの許諾名とYYYY.MM.DD形式の版を一意に得た場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool licenseTitle( CollectorParserContext *control, const std::wstring_view document,
								std::wstring &title)
{
	collectorParserCheckpoint( control) ;
	std::size_t begin{} ;	// 一意なtitle開始位置。
	std::size_t end{} ;		// 一意なtitle終端位置。
	// titleの欠落、重複、境界不正から改訂識別子を推測しない。
	if( !uniquePosition( control, document, L"<title>", begin) ||
	   !uniquePosition( control, document, L"</title>", end) || end < begin + 7U) {
		return false ;
	}

	const std::wstring_view value = document.substr( begin + 7U, end - begin - 7U) ;	// 明示title。
	// Intel titleの長さと印字可能文字を限定し、HTML混入を拒否する。
	if( value.size() > 200U ||
	   (!value.starts_with( L"Intel ") && !value.starts_with( L"Deprecated: Intel ")) ||
	   !std::ranges::all_of( value, []( const wchar_t character) {
		   return character >= L' ' && character <= L'~' && character != L'<' &&
				  character != L'>' && character != L'&' ;
	   })) {
		return false ;
	}

	const std::wstring_view VERSION_PREFIX =
		collectorParserFind( control, value, L" License Agreement [v") != value.npos
			? L" License Agreement [v"
			: L" License [v" ;		// いずれも明示改訂だけを読む。
	std::size_t versionBegin{} ;	// Title内の明示版開始位置。
	// 改訂markerが一意に得られなければlicense版を決めない。
	if( !uniquePosition( control, value, VERSION_PREFIX, versionBegin)) {
		return false ;
	}

	// 明示版と閉じ括弧だけを参照する非所有文字列。
	const std::wstring_view version = value.substr( versionBegin + VERSION_PREFIX.size()) ;
	// license改訂の固定形式と区切り位置を検証する。
	if( version.size() != 11U || version[4] != L'.' || version[7] != L'.' || version[10] != L']') {
		return false ;
	}

	// 版識別子の数字位置だけを検証する。日時の有効性や新旧を推測しない。
	for( std::size_t index = 0U; index < 10U; ++index) {
		collectorParserStep( control) ;
		// 改訂識別子の数値位置に数字以外を許容しない。
		if( index != 4U && index != 7U && (version[index] < L'0' || version[index] > L'9')) {
			return false ;
		}
	}

	title.assign( value) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Head内の本文やinline codeを読み捨てて全文としません。
 *
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] head html開始からhead終端までの有限文書構造。
 * @return Title・空のli style・公式CSS参照だけで構成される場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool knownDocumentHead( CollectorParserContext *control, std::wstring_view head)
{
	collectorParserCheckpoint( control) ;
	constexpr std::wstring_view PREFIX = L"<head>" ;	// 固定head開始。
	constexpr std::wstring_view LINK_PREFIX =
		L"<link rel=\"stylesheet\" type=\"text/css\" href=\"/etc.clientlibs/intel/clientlibs/"
		L"bundles/resources/css/" ;											// 読み込まず形式だけ確認する外部CSS参照。
	constexpr std::wstring_view LINK_SUFFIX		= L".bundle.css\"/>" ;		// 既知CSS参照の終端。
	constexpr std::wstring_view DOCUMENT_PREFIX = L"<html lang=\"en\">" ;	// 固定言語。
	// 文書開始の改変を空白処理で修復しない。
	if( !head.starts_with( DOCUMENT_PREFIX)) {
		return false ;
	}

	head = trimFrameSpace( control, head.substr( DOCUMENT_PREFIX.size())) ;
	// 確認済みのhead外枠に一致しない文書を拒否する。
	if( !head.starts_with( PREFIX) || !head.ends_with( L"</head>")) {
		return false ;
	}

	// 文書外枠を除いた未解析head。前方からのみ消費する。
	std::wstring_view rest = head.substr( PREFIX.size(), head.size() - PREFIX.size() - 7U) ;
	// 各反復で既知の一要素を消費し、未知要素を本文から除外しない。
	while( !rest.empty()) {
		collectorParserStep( control) ;
		// head要素間の空白だけを読み飛ばす。
		if( rest.front() == L' ' || rest.front() == L'\t' || rest.front() == L'\r' ||
		   rest.front() == L'\n') {
			rest.remove_prefix( 1U) ;
			continue ;
		}

		// titleは終端を確認し、内容の別検証と分離してheadを走査する。
		if( rest.starts_with( L"<title>")) {
			const std::size_t end =
				// 別途内容と一意性を検証する終端。
				collectorParserFind( control, rest, L"</title>") ;
			// titleが閉じない文書を採用しない。
			if( end == rest.npos) {
				return false ;
			}

			rest.remove_prefix( end + 8U) ;
		}
		// 既知の空styleだけを許容し、表示本文を隠すCSSを受理しない。
		else if( rest.starts_with( L"<style>li {")) {
			const std::size_t end =
				// 空のstyle内容の終端。
				collectorParserFind( control, rest, L"</style>") ;
			// style終端の欠落や不正範囲を拒否する。
			if( end == rest.npos || end < 11U) {
				return false ;
			}

			const std::wstring_view content = rest.substr( 11U, end - 11U) ;	// 開き波括弧の後。
			const std::size_t close = collectorParserFindSet( control, content, L" \t\r\n", true,
															 false) ;	// 閉じ括弧の位置。
			// 空の規則以外のstyle内容を黙って読み捨てない。
			// CSSによる追加表示などを見落とした全文としない。
			if( close == content.npos || content[close] != L'}' ||
			   collectorParserFindSet( control, content.substr( close + 1U), L" \t\r\n", true,
									  false) != content.npos) {
				return false ;
			}

			rest.remove_prefix( end + 8U) ;
		}
		// 既知形式のCSS参照をbasename検証付きで認識する。
		else if( rest.starts_with( LINK_PREFIX)) {
			const std::size_t end = collectorParserFind( control, rest, LINK_SUFFIX,
														// CSS名の終端。
														LINK_PREFIX.size()) ;
			// CSS名の欠落、未終端、上限超過を拒否する。
			if( end == rest.npos || end == LINK_PREFIX.size() || end - LINK_PREFIX.size() > 256U) {
				return false ;
			}

			// Query、追加属性、外部hostを含められない非所有basename。
			const std::wstring_view name =
				rest.substr( LINK_PREFIX.size(), end - LINK_PREFIX.size()) ;
			// CSS参照名を既知のASCII文字集合へ制限する。
			if( !std::ranges::all_of( name, []( const wchar_t character) {
				   return (character >= L'a' && character <= L'z') ||
						  (character >= L'A' && character <= L'Z') ||
						  (character >= L'0' && character <= L'9') || character == L'.' ||
						  character == L'-' || character == L'_' ;
			   })) {
				return false ;
			}

			rest.remove_prefix( end + LINK_SUFFIX.size()) ;
		} else {
			return false ;
		} // 本文、未知tag、scriptをheadとして省略しない。
	}

	return true ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 元HTMLと配布pageを照合し、制御付きで規約revisionと表示本文を抽出する。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] html 同期中だけ借用する有限の公式HTML本文。
 * @param[in] downloadUrl 同じ配布pageへの固定起点URL。同期中だけ借用する。
 * @param[out] revision 取得した規約revision。失敗時の途中状態は使用しない。
 * @param[out] text 正規化した規約表示本文。失敗時の途中状態は使用しない。
 * @return 規約本文とrevisionをともに確認できた場合true。構造不一致や制御停止ではfalse。
 * @see src/platform/intel_download_license_parser.h 公開wrapperの宣言側契約を参照する。
 */
//------------------------------------------------------------------------------
static bool parseIntelDownloadLicenseCore( CollectorParserContext *control,
										  const std::wstring_view html,
										  const std::wstring_view downloadUrl,
										  std::wstring &revision, std::wstring &text)
{
	collectorParserCheckpoint( control) ;
	revision.clear() ;
	text.clear() ;
	// 空、過大、埋込NUL付きのHTMLや取得先なしの要求を拒否する。
	// 制御付き経路の実本文上限だけをLIMITへ分離します。
	if( html.size() > MAXIMUM_PAGE_CHARACTERS) {
		collectorParserLimit( control) ;
	}

	// 本文と配布URLの最低限の入力契約を確認します。
	if( html.empty() || html.size() > MAXIMUM_PAGE_CHARACTERS || downloadUrl.empty() ||
	   collectorParserFind( control, html, L'\0') != html.npos) {
		return false ;
	}

	try {
		std::size_t modal{} ;		// 一意なdownload buttonのmodal属性位置。
		std::size_t textarea{} ;	// 一意なraw許諾欄開始位置。
		std::size_t textareaEnd{} ;	// 一意なraw許諾欄終端位置。
		std::size_t identifier{} ;	// 重複id検査の一時位置。
		// modalと本文領域を一意に特定し、重複や境界不正を拒否する。
		if( !uniquePosition( control, html, L"data-modal-id=", modal) ||
		   !html.substr( modal).starts_with( L"data-modal-id=\"1\"") ||
		   !uniquePosition( control, html, TEXTAREA, textarea) ||
		   !uniquePosition( control, html, L"id=\"content-raw\"", identifier)) {
			return false ;
		}

		textareaEnd =
			collectorParserFind( control, html, L"</textarea>", textarea + TEXTAREA.size()) ;
		// 一意なraw欄より後の最初の終端だけを結合し、他のtextareaとは混同しない。
		if( textareaEnd == html.npos || textareaEnd < textarea + TEXTAREA.size()) {
			return false ;
		}

		const std::size_t button =
			// 対象button開始位置。
			collectorParserRfind( control, html, L"<button ", modal) ;
		// modalに対応するbuttonがなければdownloadとの結合を成立させない。
		if( button == html.npos) {
			return false ;
		}

		const std::size_t buttonEnd = tagEnd( control, html, button) ;	// 対象button属性の終端。
		// buttonの終端がmodal属性を含む正しい位置にあることを確認する。
		if( buttonEnd == html.npos || buttonEnd <= modal) {
			return false ;
		}

		// 引用符内部の偽属性を無視し、実際のbutton属性だけで結合する。
		if( !buttonMatches( control, html.substr( button, buttonEnd - button + 1U), downloadUrl)) {
			return false ;
		}

		// 同じpageのtextarea内部だけを参照する埋込み文書。
		const std::wstring_view document =
			html.substr( textarea + TEXTAREA.size(), textareaEnd - textarea - TEXTAREA.size()) ;
		// 空または上限超過のlicense文書を復元しない。
		if( document.size() > MAXIMUM_LICENSE_HTML_CHARACTERS) {
			collectorParserLimit( control) ;
		}

		// 空の許諾文書は採用しません。
		if( document.empty() || document.size() > MAXIMUM_LICENSE_HTML_CHARACTERS) {
			return false ;
		}

		std::size_t body{} ;	// 埋込み文書のbody開始。
		std::size_t bodyEnd{} ;	// 埋込み文書のbody終端。
		// 本文の開始と終了が一意に得られない文書を拒否する。
		if( !uniquePosition( control, document, L"<body", body) ||
		   !uniquePosition( control, document, L"</body>", bodyEnd)) {
			return false ;
		}

		const std::size_t bodyTagEnd = tagEnd( control, document, body) ;	// body属性終端。
		// body tagの境界と名前が整合しなければ本文を採用しない。
		if( bodyTagEnd == document.npos || bodyEnd <= bodyTagEnd ||
		   (document[body + 5U] != L'>' && document[body + 5U] != L' ')) {
			return false ;
		}

		// 言語を含む既知の文書外枠と末尾に一致することを確認する。
		if( !document.starts_with( L"<html lang=\"en\">") ||
		   trimFrameSpace( control, document.substr( bodyEnd + 7U)) != L"</html>") {
			return false ;
		}

		// body外の別本文や追加文書を許諾全文から除外しない。
		std::size_t headEnd{} ;	// 一意なhead終端。
		// headからbodyへの境界とhead内要素を検証し、本文の読み落としを防ぐ。
		if( !uniquePosition( control, document, L"</head>", headEnd) || headEnd + 7U > body ||
		   !trimFrameSpace( control, document.substr( headEnd + 7U, body - headEnd - 7U)).empty() ||
		   !knownDocumentHead( control, document.substr( 0U, body))) {
			return false ;
		}

		std::wstring parsedRevision ;	// 全条件成立後に公開する許諾識別子。
		// license titleから改訂を確定できない場合は部分結果を公開しない。
		if( !licenseTitle( control, document.substr( 0U, body), parsedRevision)) {
			return false ;
		}

		std::wstring parsedText = parsedRevision + L"\r\n" ;	// Title付き本文。
		// 本文全体を安全に復元できない場合は部分EULAを公開しない。
		if( !bodyPlainText( control, document.substr( bodyTagEnd + 1U, bodyEnd - bodyTagEnd - 1U),
						  parsedText)) {
			return false ;
		}

		revision = std::move( parsedRevision) ;
		text	 = std::move( parsedText) ;
		return true ;
	} catch( const std::bad_alloc &) {
		// 新経路のOOMを許諾不採用へ変換しません。
		if( control != nullptr) {
			throw ;
		}

		revision.clear() ;
		text.clear() ;
		// 割当て失敗を部分的な全文として公開しない。
		return false ;
	}
}
/** @see intel_download_license_parser.h */
bool matchesIntelPublicEmptyDownloadLicense( const std::wstring_view html,
											const std::wstring_view downloadUrl,
											const std::wstring_view modulePath)
{
	// 非空の任意文書や過大入力を空欄の根拠へ変換しない。
	if( html.empty() || html.size() > MAXIMUM_PAGE_CHARACTERS || html.find( L'\0') != html.npos ||
	   downloadUrl.empty() || modulePath.empty()) {
		return false ;
	}

	try {
		std::size_t modal{} ;		// 一意な公開操作位置。
		std::size_t raw{} ;			// 一意な空textarea位置。
		std::size_t identifier{} ;	// 重複IDの検査位置。
		std::size_t scriptPath{} ;	// 一意なmodule参照位置。
		// Commentやscript中の同名断片を含め、複数候補を先頭優先で採用しない。
		if( !uniquePosition( nullptr, html, L"data-modal-id=", modal) ||
		   !uniquePosition( nullptr, html, TEXTAREA, raw) ||
		   !uniquePosition( nullptr, html, L"id=\"content-raw\"", identifier) ||
		   !uniquePosition( nullptr, html, modulePath, scriptPath)) {
			return false ;
		}

		const std::wstring expectedScript = L"<script type=\"text/javascript\" src=\"" +
											std::wstring( modulePath) +
											L"\">" ;	// 確認した参照tagだけを許可する。
		bool buttonSeen{} ;								// 実buttonを確認した状態。
		bool rawSeen{} ;								// 実空textareaを確認した状態。
		bool scriptSeen{} ;								// 実module参照を確認した状態。
		// 引用符・comment・raw text内部の偽tagを要素として認識しない。
		for( std::size_t offset = 0U; offset < html.size();) {
			const auto begin = html.find( L'<', offset) ;	// 次の構造開始。
			// 本文末尾まで構造候補を調べたら終了する。
			if( begin == html.npos) {
				break ;
			}

			// Comment内部のbutton／textarea／scriptを根拠にしない。
			if( html.substr( begin).starts_with( L"<!--")) {
				const auto end = html.find( L"-->", begin + 4U) ;	// Comment終端。
				// 未終端commentの後を実要素へ読み替えない。
				if( end == html.npos) {
					return false ;
				}

				offset = end + 3U ;
				continue ;
			}

			const auto end = tagEnd( nullptr, html, begin) ;	// 引用符を尊重したtag終端。
			// 壊れたtagから後続の根拠を推測しない。
			if( end == html.npos) {
				return false ;
			}

			const auto	 tag	 = html.substr( begin, end - begin + 1U) ;	// 非所有の実tag。
			const auto	 nameEnd = tag.find_first_of( L" \t\r\n/>", 1U) ;	// Tag名の境界。
			std::wstring name( tag.substr( 1U, nameEnd - 1U)) ;				// ASCII大小文字を正規化する名前。
			std::transform( name.begin(), name.end(), name.begin(), []( const wchar_t ch) {
				return ch >= L'A' && ch <= L'Z' ? static_cast<wchar_t>( ch + 32) : ch ;
			}) ;
			// 対象modal位置を実button属性が包含している場合だけ照合する。
			if( begin < modal && modal < end) {
				// 未知属性・非公開属性・別URLを補完しない。
				if( !buttonMatches( nullptr, tag, downloadUrl, true)) {
					return false ;
				}

				buttonSeen = true ;
			}

			// Raw text／非表示templateの内部を再走査しない。
			if( name == L"script" || name == L"style" || name == L"textarea" || name == L"title" ||
			   name == L"template" || name == L"noscript" || name == L"xmp" || name == L"iframe" ||
			   name == L"noembed") {
				const std::wstring closing = L"</" + name + L">" ;				// 既知の厳密終端。
				const auto		   close   = html.find( closing, end + 1U) ;	// 対応するraw終端。
				// 大文字終端等の未対応構造は推測せず保留する。
				if( close == html.npos) {
					return false ;
				}

				const auto inner = html.substr( end + 1U, close - end - 1U) ;	// 非実行内容。
				// 一意なraw候補が実textareaとして存在する場合だけ空白を確認する。
				if( begin == raw) {
					rawSeen = tag == TEXTAREA && trimFrameSpace( nullptr, inner).empty() ;
				}

				// 一意なmodule pathが実script参照として存在する場合だけ確認する。
				if( begin < scriptPath && scriptPath < end) {
					scriptSeen = tag == expectedScript && trimFrameSpace( nullptr, inner).empty() ;
				}

				offset = close + closing.size() ;
			} else {
				offset = end + 1U ;
			}
		}

		return buttonSeen && rawSeen && scriptSeen ;
	} catch( const std::bad_alloc &) {
		return false ;
	}
}

/** @see intel_download_license_parser.h */
bool parseIntelDownloadLicense( std::wstring_view html, std::wstring_view downloadUrl,
							   std::wstring &revision, std::wstring &text)
{
	return parseIntelDownloadLicenseCore( nullptr, html, downloadUrl, revision, text) ;
}

/** @see intel_download_license_parser.h */
bool parseIntelDownloadLicenseForCollector( std::wstring_view html, std::wstring_view downloadUrl,
										   std::wstring &revision, std::wstring &text,
										   CollectorParserContext &context)
{
	return parseIntelDownloadLicenseCore( &context, html, downloadUrl, revision, text) ;
}

} // namespace drivercrate
