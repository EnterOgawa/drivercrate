//------------------------------------------------------------------------------
/**
 * @file official_rtf_terms.cpp
 * @brief 文字、段落、改行を保持する有限RTF変換を実装します
 * @version 01.00.00
 * @date 2026/11/23
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/23  新規作成
 * </pre>
 *
 * @note 原文書は同期的に借用し、全文の検証後にだけ出力を渡します
 * @see docs/adr/0572-signed-wix-burn-driver-content.md
 */
//------------------------------------------------------------------------------
#include "platform/official_rtf_terms.h"

#include <array>
#include <charconv>
#include <cstdint>
#include <map>
#include <optional>
#include <string_view>
#include <system_error>
#include <utility>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 原文書の上限と対応する制御語
//------------------------------------------------------------------------------

constexpr std::size_t	   MAXIMUM_RTF_BYTES	= 1024U * 1024U ;	// 一文書の原バイト上限です
constexpr std::size_t	   MAXIMUM_GROUP_DEPTH	= 32U ;				// 本文とメタデータに共通の階層上限です
constexpr std::size_t	   MAXIMUM_FONT_COUNT	= 256U ;			// 一文書で扱う明示フォント数です
constexpr std::size_t	   MAXIMUM_CONTROL_WORD = 32U ;				// RTFの制御語のASCII文字数上限です

// 既知の文書宣言とレイアウトだけを、本文より前の最外層で認めます
constexpr std::string_view DOCUMENT_FLAGS =
	" aenddoc afelev allowfieldendsel alntblind asianbrkrule cachedcolbal dgmargin "
	"dntblnsbdb endnhere expshrtn felnbrelev formshade ftnbj ftnlytwnine horzdoc htmautsp "
	"hwelev indrlsweleven jexpand krnprsnet lnbrkrule ltrsect lytcalctblwd lyttblrtgr "
	"newtblstyruls noafcnsttbl nobrkwrptbl nocxsptable nogrowautofit noindnmbrts "
	"nojkernpunct nolnhtadjtbl noqfpromote nospaceforul notbrkcnstfrctbl notcvasp notvatxbx "
	"nouicompat noultrlspc noxlattoyen pgbrdrfoot pgbrdrhead revisions sectd sectdefaultcl "
	"sftnbj snaptogridincell spltpgpar splytwnine useltbaln usenormstyforlist utinl "
	"widowctrl wrppunct " ;

// 数値付きの文書レイアウト・編集設定です。本文の語や段落を生成しません
constexpr std::string_view DOCUMENT_VALUES =
	" adeflang colsx deflang deflangfe deftab dghorigin dghshow dghspace dgvorigin dgvshow "
	"dgvspace donotembedlingdata donotembedsysfont fet footery grfdocevents gutter headery "
	"ignoremixedcontent ilfomacatclnup linex margb margl margr margt nofeaturethrottle "
	"paperh paperw relyonvml rsidroot saveinvalidxml sectlinegrid showplaceholdtext "
	"showxmlerrors stshfbi stshfdbch stshfhich stshfloch themelang themelangcs themelangfe "
	"trackformatting trackmoves validatexml viewkind viewscale " ;

// 本文中で認める文字の選択面・段落の配置・折返しです。方向とフォントは個別に扱います
constexpr std::string_view LAYOUT_FLAGS =
	" adjustright aspalpha aspnum cgrid faauto ltrpar nowidctlpar nowwrap pard qj ql "
	"widctlpar wrapdefault " ;

// 本文中の書式の数値です。リストの適用・変更記録の表示切替は含めません
constexpr std::string_view LAYOUT_VALUES =
	" alang insrsid kerning lang langfe langfenp langnp li lin pararsid ri rin sa sl slmult " ;

// 本文外の宣言にだけ現れるタグです。文書・文字の作用を持つ未知制御語は拒否します
constexpr std::string_view METADATA_FLAGS =
	" additive author company creatim dbch faauto fbidi fbimajor fbiminor fdbmajor fdbminor "
	"fhimajor fhiminor flomajor flominor froman fswiss hich loch lsdlockedexcept ltrch "
	"operator pndec pnhang pnlcltr pnlcrm pntxta pntxtb pnucltr pnucrm revtim rtlch "
	"slocked sqformat ssemihidden sunhideused tsbrdrb tsbrdrdgl tsbrdrdgr tsbrdrh tsbrdrl "
	"tsbrdrr tsbrdrt tsbrdrv tsrowd tsvertalt ud upr " ;

// 色・フォント・書式見本・編集履歴のメタデータにだけ認める数値付き制御語です
constexpr std::string_view METADATA_VALUES =
	" af afs blue cs dy edmins f fcs fprq fs green hr itap lsdlocked lsdlockeddef "
	"lsdpriority lsdprioritydef lsdqformat lsdqformatdef lsdsemihidden lsdsemihiddendef "
	"lsdstimax lsdunhideused lsdunhideuseddef mbrkBin mbrkBinSub mdefJc mdispDef min "
	"mintLim mlMargin mmathFont mnaryLim mo mrMargin msmallFrac mwrapIndent nofchars "
	"nofcharsws nofpages nofwords pnindent pnstart red rsid s sbasedon slink snext "
	"spriority styrsid tblind tblindtype trcbpat trcfpat trftsWidthB trpaddfb trpaddfl "
	"trpaddfr trpaddft trpaddl trpaddr ts vern version xmlns yr " ;

// \*付きのメタデータ内でさらに用いる補助宣言です
constexpr std::string_view NESTED_METADATA = " company ud " ;

// 最外層にだけ置ける標準のメタデータdestinationです
constexpr std::string_view HEADER_METADATA = " colortbl info mmathPr stylesheet " ;
// 最外層にだけ置ける明示の補助メタデータdestinationです
constexpr std::string_view OPTIONAL_HEADER_METADATA =
	" defchp defpap rsidtbl wgrffmtfilter xmlnstbl " ;

// Wordの本文後メタデータです。埋込み16進データは文字構文の検査だけを行います
constexpr std::string_view OPAQUE_TRAILER_METADATA = " colorschememapping datastore themedata " ;

// Windows-1252のASCII・Latin-1と異なる範囲です。0は未割当てを示します
constexpr std::array<wchar_t, 32U> ANSI_EXTENSIONS{
	0x20AC, 0,		0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160,
	0x2039, 0x0152, 0,		0x017D, 0,		0,		0x2018, 0x2019, 0x201C, 0x201D, 0x2022,
	0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0,		0x017E, 0x0178} ;

//------------------------------------------------------------------------------
// 字句とgroupの状態
//------------------------------------------------------------------------------

/**
 * @brief 借用字句が持つ構造と文字の種類です
 */
enum class RtfTokenKind {
	/// 原文書の終端です
	END,
	/// 欠落または不正構文です
	INVALID,
	/// groupの開始です
	OPEN,
	/// groupの終端です
	CLOSE,
	/// ASCIIの原文字または非表示の代替表記に使える文字制御記号です
	TEXT,
	/// バックスラッシュに続く二桁の16進byteです
	HEX_BYTE,
	/// \*による補助destination指定です
	STAR,
	/// ASCII名と任意の符号付き整数を持ちます
	WORD
} ;

/**
 * @brief 有限長のRTF字句を保持します
 */
struct RtfToken {
	/// 構造または値の種類です
	RtfTokenKind	   kind{RtfTokenKind::INVALID} ;
	/// WORDの場合だけ原制御語名を借用します
	std::string_view   name{} ;
	/// 制御語の値が指定された場合の整数です
	std::optional<int> number{} ;
	/// TEXTのUnicode一文字またはHEX_BYTEの符号なしbyteです
	wchar_t			   character{} ;
} ;

/**
 * @brief メタデータgroupの解釈方法です
 */
enum class MetadataKind {
	/// 本文を含まない許可済み文書情報を字句検査します
	DOCUMENT,
	/// フォントIDと文字集合を収集する外枠です
	FONT_TABLE,
	/// 一フォントの定義を収集します
	FONT_ENTRY,
	/// 元の閉じた16進列だけを字句検査します
	OPAQUE
} ;

/**
 * @brief 各groupが親から引き継ぐ本文書式です
 */
struct RtfFormat {
	/// Unicode一単位の直後で読飛ばす代替文字の個数です
	int				   fallbackCount{1} ;
	/// 指定した本文フォントです。値なしは文書既定です
	std::optional<int> font{} ;
	/// 指定した代替フォントです。値なしは文書既定です
	std::optional<int> alternateFont{} ;
	/// 右から左へ表示する文字列の指定が有効な間だけtrueです
	bool			   rightToLeft{} ;
	/// 東アジア文字面を指定した場合trueです
	bool			   doubleByte{} ;
} ;

/**
 * @brief 文書から得た固定宣言と、検証まで外へ渡さない本文です
 */
struct RtfDocument {
	/// ANSI文字集合の宣言が現れた場合trueです
	bool			   ansi{} ;
	/// 明示されたWindows-1252の文書既定文字集合です
	bool			   ansi1252{} ;
	/// 本文後のメタデータに到達した場合trueです
	bool			   trailer{} ;
	/// 既定フォントのIDです
	std::optional<int> defaultFont{} ;
	/// 既定の代替フォントのIDです
	std::optional<int> defaultAlternateFont{} ;
	/// 登録したフォントIDからRTF文字集合への対応です
	std::map<int, int> fonts ;
	/// 変換した本文です。失敗した場合は破棄します
	std::wstring	   body ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 既知の制御語だけをリスト内の完全一致で判定します
 * @param[in] list 各語の先頭と末尾をASCII空白で区切った固定リストです
 * @param[in] name 空でないASCII制御語です
 * @return 独立した一語が一致した場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool containsRtfWord( const std::string_view list, const std::string_view name)
{
	// 接頭辞と接尾辞を除外して、区切りに囲まれた完全一致を探します
	for( auto match = list.find( name); match != std::string_view::npos;
		match	   = list.find( name, match + 1U)) {
		const auto end = match + name.size() ;	// 一語の直後となる位置です
		// 一致する字面の前後がどちらも区切りの場合だけ許可します
		if( match != 0U && end < list.size() && list[match - 1U] == ' ' && list[end] == ' ') {
			return true ;
		}
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASCIIの英字を判定します
 * @param[in] value 原一文字です
 * @return ASCII英字の場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAsciiLetter( const char value)
{
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASCIIの16進数字を数値へ変換します
 * @param[in] value 原一文字です
 * @return 0～15、該当しない場合は-1です
 */
//------------------------------------------------------------------------------
[[nodiscard]] int hexadecimalValue( const char value)
{
	// 数字の範囲を英字より先に扱います
	if( value >= '0' && value <= '9') {
		return value - '0' ;
	}

	// 大文字と小文字を原文字に応じて読みます
	if( value >= 'A' && value <= 'F') {
		return value - 'A' + 10 ;
	}

	return value >= 'a' && value <= 'f' ? value - 'a' + 10 : -1 ;
}

//------------------------------------------------------------------------------
/**
 * @brief バックスラッシュの後ろの制御記号を一つ読みます
 * @param[in,out] remaining 先頭のバックスラッシュを除いた原バイトです。絵文字等はUTF-16の制御語を使います
 * @return 構造、文字または不正字句です
 */
//------------------------------------------------------------------------------
[[nodiscard]] RtfToken readControlSymbol( std::string_view &remaining)
{
	const auto symbol = remaining.front() ;	// 呼出し側が存在を確認した制御記号です
	remaining.remove_prefix( 1U) ;
	// 一byteのエスケープには16進二桁を必須とします
	if( symbol == '\'') {
		// 二桁未満の末尾から部分文字を生成しません
		if( remaining.size() < 2U) {
			return {} ;
		}

		const auto high = hexadecimalValue( remaining[0]) ;	// 上位16進数です
		const auto low	= hexadecimalValue( remaining[1]) ;	// 下位16進数です
		// 両桁が成立する場合だけ一byteとして扱います
		if( high < 0 || low < 0) {
			return {} ;
		}

		remaining.remove_prefix( 2U) ;
		return {RtfTokenKind::HEX_BYTE, {}, {}, static_cast<wchar_t>( high * 16 + low)} ;
	}

	// 既知の表示文字と補助destinationの開始を区別します
	switch( symbol) {
		case '*':	// 補助destinationの印です
			return {RtfTokenKind::STAR} ;
		case '\\':	// 本文のバックスラッシュです
		case '{':	// 本文の開き波括弧です
		case '}':	// 本文の閉じ波括弧です
			return {RtfTokenKind::TEXT, {}, {}, static_cast<wchar_t>( symbol)} ;
		case '~':	// 改行しない空白です
			return {RtfTokenKind::TEXT, {}, {}, L'\u00A0'} ;
		case '_':	// 改行しないハイフンです
			return {RtfTokenKind::TEXT, {}, {}, L'\u2011'} ;
		case '-':	// 単語内の任意改行位置です
			return {RtfTokenKind::TEXT, {}, {}, L'\u00AD'} ;
		default:	// 未対応の表示や処理を要求する記号です
			return {} ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 原バイトから次のRTF字句を取り出します
 * @param[in,out] remaining 借用する未読原バイトです。読んだ構文と物理CR/LFを消費します
 * @return 一字句または終端です。未知の制御記号と不正な数値はINVALIDです
 */
//------------------------------------------------------------------------------
[[nodiscard]] RtfToken readRtfToken( std::string_view &remaining)
{
	// 物理CR/LFだけを読み飛ばし、表示上の改行は制御語から生成します
	while( !remaining.empty() && (remaining.front() == '\r' || remaining.front() == '\n')) {
		remaining.remove_prefix( 1U) ;
	}

	// 文書終端に到達した場合は未読入力を参照しません
	if( remaining.empty()) {
		return {RtfTokenKind::END} ;
	}

	const auto first = remaining.front() ;	// 原字句を区分する最初のASCII byteです
	remaining.remove_prefix( 1U) ;
	// group境界は表示文字から分離します
	if( first == '{') {
		return {RtfTokenKind::OPEN} ;
	}

	// group終端は後続の別groupや外枠と区別します
	if( first == '}') {
		return {RtfTokenKind::CLOSE} ;
	}

	// 原本文の文字は印字可能ASCIIのみに限定し、上位byteを暗黙変換しません
	if( first != '\\') {
		return first >= ' ' && first <= '~'
				   ? RtfToken{RtfTokenKind::TEXT, {}, {}, static_cast<wchar_t>( first)}
				   : RtfToken{} ;
	}

	// 途中で切れたエスケープから本文を生成しません
	if( remaining.empty()) {
		return {} ;
	}

	// 非英字は名前が一文字で終わる制御記号です
	if( !isAsciiLetter( remaining.front())) {
		return readControlSymbol( remaining) ;
	}

	std::size_t nameLength{} ;	// 制御語名を構成するASCII文字数です
	// 同じ名前の境界を確定し、過長語は接頭辞として扱いません
	while( nameLength < remaining.size() && isAsciiLetter( remaining[nameLength])) {
		++nameLength ;
	}

	// 有限長を超える未対応の制御語は拒否します
	if( nameLength > MAXIMUM_CONTROL_WORD) {
		return {} ;
	}

	RtfToken token{RtfTokenKind::WORD,
				   // 同じ原文書を借用する字句です
				   remaining.substr( 0U, nameLength)} ;
	remaining.remove_prefix( nameLength) ;
	// 付随する負号または数字を、完全な十進整数として読みます
	if( !remaining.empty() &&
	   (remaining.front() == '-' || (remaining.front() >= '0' && remaining.front() <= '9'))) {
		int		   number{} ;	// 制御語の有限な符号付き数値です
		// 数値の成功状態と直後の未読位置を受け取ります
		const auto parsed =
			std::from_chars( remaining.data(), remaining.data() + remaining.size(), number) ;
		// 負号だけの場合と数値の範囲超過を拒否します
		if( parsed.ec != std::errc{}) {
			return {} ;
		}

		token.number = number ;
		remaining.remove_prefix( static_cast<std::size_t>( parsed.ptr - remaining.data())) ;
	}

	// 語終端のASCII空白一個だけを構文として消費します
	if( !remaining.empty() && remaining.front() == ' ') {
		remaining.remove_prefix( 1U) ;
	}

	return token ;
}

//------------------------------------------------------------------------------
/**
 * @brief Unicode制御語に続く旧文字集合の代替表記を消費します
 * @param[in,out] remaining 次の未読原バイトです
 * @param[in] fallbackCount このgroupで指定された代替字句数です
 * @return 指定数の文字だけが揃った場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool consumeFallback( std::string_view &remaining, const int fallbackCount)
{
	// 表示文字と対応しない代替列をその原単位数だけ読み、groupや制御語へ越境しません
	for( int index = 0; index < fallbackCount; ++index) {
		const auto next = readRtfToken( remaining) ;	// 一文字または代替byte一個です
		// 不正なエスケープ・制御文字・構造を代替表記として捨てません
		if( next.kind != RtfTokenKind::TEXT && (next.kind != RtfTokenKind::HEX_BYTE ||
											   next.character < 0x20 || next.character == 0x7F)) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原Unicode制御語から符号なしUTF-16単位を得ます
 * @param[in] token Unicode制御語です
 * @param[in,out] remaining Unicode制御語の後ろの未読原バイトです
 * @param[in] fallbackCount このgroupで指定された代替字句数です
 * @return 対応するUTF-16単位です。原値や代替列が不正なら値なしです
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<wchar_t> unicodeUnit( const RtfToken &token, std::string_view &remaining,
												 const int fallbackCount)
{
	// RTFの符号付き16-bit値と同じ字句の完全な代替表記を要求します
	if( !token.number || *token.number < -32768 || *token.number > 32767 ||
	   !consumeFallback( remaining, fallbackCount)) {
		return std::nullopt ;
	}

	const auto unit = static_cast<std::uint16_t>( *token.number) ;	// 同じ初期16-bit値です
	// 埋込み制御文字による切断や表示と同意の食い違いを拒否します
	if( unit < 0x20U || (unit >= 0x7FU && unit <= 0x9FU)) {
		return std::nullopt ;
	}

	return static_cast<wchar_t>( unit) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 確認済みメタデータを有界で検査し、本文に混ぜないようにします
 * @param[in,out] remaining group開始後の未読原バイトです
 * @param[in] depth 開いているgroup数です
 * @param[in] kind groupの役割です
 * @param[in] first 読取り済みの先頭字句です
 * @param[in] fallbackCount 親から引き継いだ代替文字数です
 * @param[in,out] document フォント定義を収集する文書状態です
 * @return group終端まで確認できた場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readMetadata( std::string_view &remaining, const std::size_t depth,
								const MetadataKind kind, RtfToken first, int fallbackCount,
								RtfDocument &document)
{
	std::optional<int> fontId ;		// 一フォントの一意なIDです
	std::optional<int> charset ;	// 一フォントに明示された文字集合です
	std::size_t		   digits{} ;	// 不透明な16進列の数字数です
	// groupの終端まで明示的に消費し、閉じるまで内容を本文へ渡しません
	for( auto token = first; token.kind != RtfTokenKind::CLOSE; token = readRtfToken( remaining)) {
		// 不透明データを入れ子、制御語または埋込み文書として解釈しません
		if( kind == MetadataKind::OPAQUE) {
			// 元データに現れるASCIIの16進数字以外を拒否します
			if( token.kind != RtfTokenKind::TEXT || token.character > L'~' ||
			   hexadecimalValue( static_cast<char>( token.character)) < 0) {
				return false ;
			}

			++digits ;
			continue ;
		}

		// 入れ子のメタデータにも同じ階層限界と閉じ方を要求します
		if( token.kind == RtfTokenKind::OPEN) {
			auto	   child   = readRtfToken( remaining) ;			// 内側groupの最初の字句です
			const bool starred = child.kind == RtfTokenKind::STAR ;	// 明示の補助destinationです
			// フォント表の直下だけが一件のフォントです
			auto	   role = kind == MetadataKind::FONT_TABLE ? MetadataKind::FONT_ENTRY
															   : MetadataKind::DOCUMENT ;
			// 星付きの新しい意味を持つdestinationは、既知の補助宣言だけを扱います
			if( starred) {
				child = readRtfToken( remaining) ;
			}

			// 一フォントの内部は文字集合を上書きしないPANOSE値だけ入れ子にできます
			if( kind == MetadataKind::FONT_ENTRY) {
				// 既知の補助宣言以外を暗黙に破棄しません
				if( !starred || child.kind != RtfTokenKind::WORD || child.name != "panose" ||
				   child.number) {
					return false ;
				}

				role  = MetadataKind::OPAQUE ;
				child = readRtfToken( remaining) ;
			}

			// その他の星付きgroupは明示の補助宣言だけを認めます
			if( starred && role != MetadataKind::OPAQUE &&
			   (role != MetadataKind::DOCUMENT || child.kind != RtfTokenKind::WORD ||
				(child.number ? child.name != "cs" && child.name != "ts"
							  : !containsRtfWord( NESTED_METADATA, child.name)))) {
				return false ;
			}

			// GROUPの深さを制限し、途中で失敗した情報を公開しません
			if( depth >= MAXIMUM_GROUP_DEPTH ||
			   !readMetadata( remaining, depth + 1U, role, child, fallbackCount, document)) {
				return false ;
			}

			continue ;
		}

		// フォント表の直下をgroup構成に限定します
		if( kind == MetadataKind::FONT_TABLE) {
			return false ;
		}

		// 安全なメタデータ文字は表示用の文字列へ写しません
		if( token.kind == RtfTokenKind::TEXT) {
			continue ;
		}

		// 知らない記号、切断、バイナリや別の文書は読み飛ばさず拒否します
		if( token.kind != RtfTokenKind::WORD) {
			return false ;
		}

		// フォント表直下にある一件からIDと文字集合を得ます
		if( kind == MetadataKind::FONT_ENTRY && (token.name == "f" || token.name == "fcharset")) {
			auto &field = token.name == "f" ? fontId : charset ;	// 二項目を別々に検査します
			// 同じ項目を上書きせず、範囲外の指定を拒否します
			if( field || !token.number || *token.number < 0 ||
			   (token.name == "fcharset" && *token.number > 255)) {
				return false ;
			}

			field = token.number ;
			continue ;
		}

		// メタデータのUnicode代替表記にも同じ厳密な字句境界を適用します
		if( token.name == "uc") {
			// この限定形式では一文字に最大二byteの代替を認めます
			if( !token.number || *token.number < 0 || *token.number > 2) {
				return false ;
			}

			fallbackCount = *token.number ;
			continue ;
		}

		// 著者名等にあるBMP内のUnicode字句を構造として検査します
		if( token.name == "u") {
			const auto unit =
				// この領域で許可するUTF-16単位です
				unicodeUnit( token, remaining, fallbackCount) ;
			// 不完全なUnicodeと、この領域で未対応のサロゲート対を拒否します
			if( !unit || (*unit >= 0xD800 && *unit <= 0xDFFF)) {
				return false ;
			}

			continue ;
		}

		// メタデータ内にも既知の文字・段落配置と編集情報しか認めません
		if( token.number ? !containsRtfWord( METADATA_VALUES, token.name) &&
							  !containsRtfWord( LAYOUT_VALUES, token.name)
						: !containsRtfWord( METADATA_FLAGS, token.name) &&
							  !containsRtfWord( LAYOUT_FLAGS, token.name)) {
			return false ;
		}
	}

	// フォント参照を重複なく固定し、本文の使用時に照合します
	if( kind == MetadataKind::FONT_ENTRY) {
		return fontId && document.fonts.size() < MAXIMUM_FONT_COUNT &&
			   document.fonts.emplace( *fontId, charset.value_or( 0)).second ;
	}

	// 空のフォント表を暗黙の既定書式に置き換えません
	if( kind == MetadataKind::FONT_TABLE) {
		return !document.fonts.empty() ;
	}

	// 十六進データは一byte単位で完結していることを要求します
	return kind != MetadataKind::OPAQUE || (digits != 0U && digits % 2U == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択したフォントが文字の解釈を変えない範囲かを確認します
 * @param[in] document 文書で定義されたフォント表です
 * @param[in] font 有効なフォントIDです
 * @param[in] ansiByte 上位のANSI一byteを解釈する場合trueです
 * @return 対応する文字集合の場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool compatibleFont( const RtfDocument &document, const int font, const bool ansiByte)
{
	// フォント表を省略した場合も未知のfont IDは許しません
	if( document.fonts.empty()) {
		return font == 0 ;
	}

	const auto entry = document.fonts.find( font) ;	// 同じ文書のfont IDの宣言です
	// 生の上位byteは明示的なANSIフォントでだけ読みます
	return entry != document.fonts.end() &&
		   (entry->second == 0 || (!ansiByte && (entry->second == 1 || entry->second == 129))) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一文字を有効な文書状態と文字集合へ照合して追加します
 * @param[in,out] document 出力前の文書状態です
 * @param[in] format 有効なgroup内の書式です
 * @param[in] value 原文字またはUTF-16一単位です
 * @param[in] legacyByte 一byteエスケープから得た場合trueです
 * @return 意味を保持して表示できる場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool appendCharacter( RtfDocument &document, const RtfFormat &format, wchar_t value,
								   const bool legacyByte)
{
	const bool ansiByte =
		legacyByte && value >= 0x80 ;	// 上位の旧文字集合byteは明示的なANSIだけに限定します
	// 未確認の文字面、右から左の本文、または別の文字集合を暗黙に解釈しません
	if( !document.ansi || document.trailer || format.rightToLeft ||
	   (ansiByte && (!document.ansi1252 || format.doubleByte)) ||
	   !compatibleFont( document, format.font.value_or( document.defaultFont.value_or( 0)),
					   ansiByte) ||
	   !compatibleFont( document,
					   format.alternateFont.value_or( document.defaultAlternateFont.value_or( 0)),
					   ansiByte)) {
		return false ;
	}

	// 定義済みのWindows-1252拡張だけをUnicodeに写します
	if( ansiByte && value < 0xA0) {
		value = ANSI_EXTENSIONS[static_cast<std::size_t>( value - 0x80)] ;
	}

	// 未割当てや見えない制御文字をプレーンテキストへ渡しません
	if( value < 0x20 || value == 0x7F) {
		return false ;
	}

	document.body.push_back( value) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 本文の文字、段落または確認済み書式を処理します
 * @param[in] token 本文の制御語です
 * @param[in,out] remaining Unicodeの代替表記読取りに使う未読原バイトです
 * @param[in,out] format 現在のgroup内の有効な書式です
 * @param[in,out] document 原文書と表示用本文です
 * @return 本文の意味を保って処理できる場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool applyBodyWord( const RtfToken &token, std::string_view &remaining,
								 RtfFormat &format, RtfDocument &document)
{
	// 本文後のメタデータを見た時点で本文は終わっています
	if( document.trailer) {
		return false ;
	}

	// Unicodeは先行する文字集合に依存せず、一単位と代替列の対応を確認します
	if( token.name == "u") {
		const auto unit = unicodeUnit( token, remaining, format.fallbackCount) ;	// UTF-16の一単位です
		return unit && appendCharacter( document, format, *unit, false) ;
	}

	// Unicode代替個数は入れ子を抜けると親の値に戻します
	if( token.name == "uc") {
		// 保存文書の単一・二byte代替および代替なしだけを扱います
		if( !token.number || *token.number < 0 || *token.number > 2) {
			return false ;
		}

		format.fallbackCount = *token.number ;
		return true ;
	}

	// 段落と明示改行を通常のWindowsプレーンテキストと同じ区切りへ写します
	if( token.name == "par" || token.name == "line" || token.name == "tab") {
		// 見えている段落境界を欠落させず、余分な数値指定は拒否します
		if( token.number || !document.ansi || format.rightToLeft) {
			return false ;
		}

		document.body.append( token.name == "tab" ? L"\t" : L"\r\n") ;
		return true ;
	}

	// テキスト記号は最終本文に残して引用と句読点を保存します
	if( token.name == "rquote" || token.name == "lquote" || token.name == "ldblquote" ||
	   token.name == "rdblquote" || token.name == "emdash" || token.name == "endash" ||
	   token.name == "bullet") {
		const auto punctuation = token.name == "rquote"		 ? L'\u2019'
								 : token.name == "lquote"	 ? L'\u2018'
								 : token.name == "ldblquote" ? L'\u201C'
								 : token.name == "rdblquote" ? L'\u201D'
								 : token.name == "emdash"	 ? L'\u2014'
								 : token.name == "endash"	 ? L'\u2013'
															 : L'\u2022' ;	// 制御語が表す原文字です
		return !token.number && appendCharacter( document, format, punctuation, false) ;
	}

	// 明示フォント指定を追跡し、他の文字集合を誤ってANSIとして表示しないようにします
	if( token.name == "f" || token.name == "af") {
		// フォントIDは負値や省略を許しません
		if( !token.number || *token.number < 0) {
			return false ;
		}

		(token.name == "f" ? format.font : format.alternateFont) = token.number ;
		return true ;
	}

	// 右から左の文字データは未対応です。文字が続かない書式指定は左から右へ切替え可能です
	if( token.name == "ltrch" || token.name == "rtlch") {
		format.rightToLeft = token.name == "rtlch" ;
		return !token.number ;
	}

	// 東アジア面の原byteは解釈せず、同じrunに明示されたUnicodeを使います
	if( token.name == "loch" || token.name == "hich" || token.name == "dbch") {
		format.doubleByte = token.name == "dbch" ;
		return !token.number ;
	}

	// 文字設定のresetを処理し、Unicode代替数のgroup境界を保ちます
	if( token.name == "plain") {
		format = {format.fallbackCount} ;
		return !token.number ;
	}

	// 表の内側を扱いません。平坦な段落で観測した階層0だけを扱います
	if( token.name == "itap") {
		return token.number == 0 ;
	}

	// 実際の文字サイズが成立する明示値を認めます
	if( token.name == "fs" || token.name == "afs") {
		return token.number && *token.number > 0 ;
	}

	// 既知の文字面を選択する書式だけを落とし、同じフォント照合を維持します
	if( token.name == "fcs") {
		return token.number == 0 || token.number == 1 ;
	}

	return token.number ? containsRtfWord( LAYOUT_VALUES, token.name)
						: containsRtfWord( LAYOUT_FLAGS, token.name) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 最外層の本文前宣言を確認します
 * @param[in] token 文書の制御語です
 * @param[in,out] document 認識した宣言を保持する文書です
 * @return 対応する文書前宣言を受理した場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool applyDocumentWord( const RtfToken &token, RtfDocument &document)
{
	// 異なる文字集合へ途中で切替えないよう、一意なANSI宣言を扱います
	if( token.name == "ansi") {
		// 数値指定や重複宣言を拒否します
		if( token.number || document.ansi) {
			return false ;
		}

		document.ansi = true ;
		return true ;
	}

	// 明示ページでだけ上位byteのWindows-1252解釈を有効にします
	if( token.name == "ansicpg") {
		// ANSI宣言を伴うWindows-1252の一意な明示だけを扱います
		if( !document.ansi || document.ansi1252 || token.number != 1252) {
			return false ;
		}

		document.ansi1252 = true ;
		return true ;
	}

	// 文書既定のフォント宣言を上書きせず保持します
	if( token.name == "deff" || token.name == "adeff") {
		// 主フォントと代替フォントの元宣言を分けて保持します
		auto &field = token.name == "deff" ? document.defaultFont : document.defaultAlternateFont ;
		// 不正な既定値や重複宣言を拒否します
		if( field || !token.number || *token.number < 0) {
			return false ;
		}

		field = token.number ;
		return true ;
	}

	return token.number ? containsRtfWord( DOCUMENT_VALUES, token.name)
						: containsRtfWord( DOCUMENT_FLAGS, token.name) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 最外層の子groupだけで許可されるメタデータを区分します
 * @param[in] token group先頭の制御語です
 * @param[in] starred \*が先行する場合trueです
 * @param[in,out] document 本文とメタデータの位置を管理する文書です
 * @return 既知の役割、または本文groupもしくは未対応を表す値なしです
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<MetadataKind> metadataRole( const RtfToken &token, const bool starred,
													   RtfDocument &document)
{
	// 最外層の本文より後に置かれた編集用データを認識します
	if( starred && !token.number && !document.body.empty()) {
		// テーマと編集用バイトを文字として扱わず、以降は本文を閉じます
		if( containsRtfWord( OPAQUE_TRAILER_METADATA, token.name)) {
			document.trailer = true ;
			return MetadataKind::OPAQUE ;
		}

		// 潜在スタイルの一覧にも本文要素を混ぜません
		if( token.name == "latentstyles") {
			document.trailer = true ;
			return MetadataKind::DOCUMENT ;
		}
	}

	// 段落前の宣言だけが文書の前置メタデータになれます
	if( !document.body.empty()) {
		return std::nullopt ;
	}

	// フォント表は本文の文字解釈用に独立して取り出します
	if( !starred && token.name == "fonttbl" && !token.number && document.fonts.empty()) {
		return MetadataKind::FONT_TABLE ;
	}

	// 古い段落番号の書式テンプレートだけを許可し、本文でその適用は許可しません
	if( starred && token.name == "pnseclvl" && token.number && *token.number >= 1 &&
	   *token.number <= 9) {
		return MetadataKind::DOCUMENT ;
	}

	const auto header = starred ? OPTIONAL_HEADER_METADATA
								: HEADER_METADATA ;	// destinationの正しい先頭表記を照合します
	return !token.number && containsRtfWord( header, token.name)
			   ? std::optional{MetadataKind::DOCUMENT}
			   : std::nullopt ;
}

//------------------------------------------------------------------------------
/**
 * @brief groupごとの書式を引き継ぎながら本文と既知のメタデータを読みます
 * @param[in,out] remaining 未読の元RTFです
 * @param[in] depth 開いているgroup数です
 * @param[in] first group開始後の最初の字句です
 * @param[in] format groupが所有する書式です
 * @param[in,out] document 文書の宣言と全文を保持します
 * @return 同じgroupの終端まで完全に読めた場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readBody( std::string_view &remaining, const std::size_t depth,
							const RtfToken first, RtfFormat format, RtfDocument &document)
{
	// groupを閉じるまで、原字句の順序で処理します
	for( auto token = first; token.kind != RtfTokenKind::CLOSE; token = readRtfToken( remaining)) {
		// 入れ子は有限にし、独立した書式状態を渡します
		if( token.kind == RtfTokenKind::OPEN) {
			// それ以上のgroupを処理する前に深さを検査します
			if( depth >= MAXIMUM_GROUP_DEPTH) {
				return false ;
			}

			auto	   child   = readRtfToken( remaining) ;			// 子groupの最初の制御語または文字です
			const bool starred = child.kind == RtfTokenKind::STAR ;	// 明示された補助destinationです
			// 補助destinationが現れた場合も、名前と既知の役割を要求します
			if( starred) {
				child = readRtfToken( remaining) ;
			}

			const auto metadata = depth == 1U && child.kind == RtfTokenKind::WORD
									  ? metadataRole( child, starred, document)
									  : std::nullopt ;	// 安全に内容を分けられる場合だけ値ありです
			// 既知のメタデータを対応する構文に限定します
			if( metadata) {
				// 先頭のdestination宣言は役割の認識に使用済みです
				if( !readMetadata( remaining, depth + 1U, *metadata, readRtfToken( remaining),
								 format.fallbackCount, document)) {
					return false ;
				}

				continue ;
			}

			// 本文groupへの未知の補助destinationや本文後の入れ子を拒否します
			if( starred || document.trailer ||
			   !readBody( remaining, depth + 1U, child, format, document)) {
				return false ;
			}

			continue ;
		}

		// 書式と文字を同じ原字句順に適用します
		if( token.kind == RtfTokenKind::WORD) {
			// 文書宣言は最外層の本文前だけで有効です
			if( depth == 1U && document.body.empty() && applyDocumentWord( token, document)) {
				continue ;
			}

			// 既知の本文制御語だけを許可します
			if( !applyBodyWord( token, remaining, format, document)) {
				return false ;
			}

			continue ;
		}

		// 文字かbyteに限って本文へ渡し、終端不足や孤立した記号を拒否します
		if( (token.kind != RtfTokenKind::TEXT && token.kind != RtfTokenKind::HEX_BYTE) ||
		   !appendCharacter( document, format, token.character,
							token.kind == RtfTokenKind::HEX_BYTE)) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示本文のUTF-16と構造文字を検証します
 * @param[in] text 原文字と明示された区切りから生成された表示本文です
 * @return Unicodeの組と表示用文字がすべて成立する場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validBody( const std::wstring_view text)
{
	// 全文のUTF-16を順に読み、対の途中で切れた文字を拒否します
	for( std::size_t index = 0U; index < text.size(); ++index) {
		auto scalar =
			// Unicode単一値へまとめる先頭単位です
			static_cast<std::uint32_t>( text[index]) ;
		// 上位サロゲートには直後の下位サロゲートを要求します
		if( scalar >= 0xD800U && scalar <= 0xDBFFU) {
			// 文書の末尾で不完全な文字を生成しません
			if( index + 1U == text.size()) {
				return false ;
			}

			const auto low =
				// 同じUnicode値の下位単位です
				static_cast<std::uint32_t>( text[++index]) ;
			// 他の文字または改行を対として取り込みません
			if( low < 0xDC00U || low > 0xDFFFU) {
				return false ;
			}

			scalar = 0x10000U + (scalar - 0xD800U) * 0x400U + low - 0xDC00U ;
		}

		// 前に上位単位がない場合は不正です
		if( scalar >= 0xDC00U && scalar <= 0xDFFFU) {
			return false ;
		}

		// 明示の方向変更、不可視制御、非文字、埋込み物の代替記号を表示へ混ぜません
		if( scalar == 0x061CU || (scalar >= 0x200BU && scalar <= 0x200FU) ||
		   (scalar >= 0x2028U && scalar <= 0x202EU) || (scalar >= 0x2060U && scalar <= 0x206FU) ||
		   (scalar >= 0xFDD0U && scalar <= 0xFDEFU) || scalar == 0xFEFFU || scalar == 0xFFFCU ||
		   scalar == 0xFFFDU || (scalar & 0xFFFFU) >= 0xFFFEU) {
			return false ;
		}
	}

	return text.find_first_not_of( L" \t\r\n\u00A0") != std::wstring_view::npos ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 有限なRTFの本文をUnicodeのプレーンテキストへ変換します
 *
 * 本文の文字と順序を保持し、段落と明示改行をCRLFへ変換します
 *
 * @param[in] source 呼出し中だけ借用する原RTF全体です
 * @param[out] body 成功した場合は全文、失敗した場合は空文字列です。sourceと記憶領域を共有できません
 * @return 対応形式で全文を表示できる場合true、形式・文字・上限の拒否時はfalseです
 * @throws std::bad_alloc 本文または解析状態に必要な記憶を確保できない場合です
 * @note 埋込みコードや外部参照を処理する機能は持ちません
 */
//------------------------------------------------------------------------------
bool decodeOfficialRtfTerms( const std::span<const std::byte> source, std::wstring &body)
{
	body.clear() ;
	// 文字表現への借用変換前に原バイトの有限上限と空入力を検査します
	if( source.empty() || source.size() > MAXIMUM_RTF_BYTES) {
		return false ;
	}

	// 元データをcharのオブジェクト表現として同じ呼出し中だけ借用し、ASCII構文を検査します
	std::string_view remaining{reinterpret_cast<const char *>( source.data()), source.size()} ;
	// 唯一のroot groupとRTF版1を文書の先頭から要求します
	if( !remaining.starts_with( "{\\rtf")) {
		return false ;
	}

	remaining.remove_prefix( 1U) ;
	const auto header = readRtfToken( remaining) ;	// 文書版を明示する最初の字句です
	// 接頭辞が一致するだけの別形式や未知版を拒否します
	if( header.kind != RtfTokenKind::WORD || header.name != "rtf" || header.number != 1) {
		return false ;
	}

	RtfDocument document ;	// 成功時だけ本文を外へ移す文書状態です
	// rootを閉じた後は物理空白だけを許可し、連結文書や未検査本文も拒否します
	if( !readBody( remaining, 1U, readRtfToken( remaining), {}, document) ||
	   remaining.find_first_not_of( " \t\r\n") != std::string_view::npos ||
	   !validBody( document.body)) {
		return false ;
	}

	body = std::move( document.body) ;
	return true ;
}

} // namespace drivercrate
