//------------------------------------------------------------------------------
/**
 * @file asrock_catalog_parser.cpp
 * @brief ASRock公式最新driver一覧parser実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note ASRock公式の固定一覧だけを解析し、local SMBIOS modelとWindows x64区分へ端末内で照合します。個別製品pageやpayloadへは接続しません。
 */
//------------------------------------------------------------------------------

#include "platform/asrock_catalog_parser.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t		MAXIMUM_HTML_CHARACTERS = 2U * 1024U * 1024U ;	// HTML文字数上限。
constexpr std::size_t		MAXIMUM_ROWS			= 4'096U ;				// Table行数上限。
constexpr std::size_t		MAXIMUM_TEXT_CHARACTERS = 256U ;				// 一cellの文字数上限。
constexpr std::size_t		EXPECTED_CELL_COUNT		= 6U ;					// 公式table列数。
// Driver一覧のDownload tableを特定する、許可HTML開始表現。
constexpr std::wstring_view TABLE_MARKER = L"<table class=\"Download\"" ;
// Driver一覧tableの探索範囲を閉じるHTML終端。
constexpr std::wstring_view TABLE_END_MARKER = L"</table>" ;
// 一候補に対応するHTML行の開始を探索するmarker。
constexpr std::wstring_view ROW_MARKER = L"<tr" ;
// 別候補へ読み越さないためのHTML行終端。
constexpr std::wstring_view ROW_END_MARKER = L"</tr>" ;
// 候補metadataを構成するHTML cellの開始marker。
constexpr std::wstring_view CELL_MARKER = L"<td" ;
// 一つのmetadata fieldを区切るHTML cell終端。
constexpr std::wstring_view CELL_END_MARKER = L"</td>" ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief ASCII英字の大小を無視してsubstring位置を検索する。
 *
 * Localeに依存せずHTML keywordとdriver名を比較する。
 *
 * @param[in] input 検索対象文字列。
 * @param[in] needle ASCIIで指定する検索文字列。
 * @param[in] offset 検索開始位置。
 * @return 一致開始位置。見つからない場合は`std::wstring_view::npos`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::size_t	findAsciiCaseInsensitive( const std::wstring_view input,
													 const std::wstring_view needle,
													 const std::size_t		 offset = 0U) noexcept
{
	// 空の検索語や入力範囲外の照合を開始しない。
	if( needle.empty() || offset > input.size() || needle.size() > input.size() - offset) {
		return std::wstring_view::npos ;
	}

	// 有限な各開始位置でASCII大小文字を一文字ずつ比較する。
	for( std::size_t index = offset; index + needle.size() <= input.size(); ++index) {
		bool matched = true ;	// 現在位置からneedle全体が一致した場合はtrue。
		// 検索語の有限な文字数だけを比較し、ASCII英字の大小だけを揃える。
		for( std::size_t needleIndex = 0U; needleIndex < needle.size(); ++needleIndex) {
			wchar_t left  = input[index + needleIndex] ;	// Input側の現在文字。
			wchar_t right = needle[needleIndex] ;			// Needle側の現在文字。
			// 入力側のASCII小文字を比較用の大文字へ揃える。
			if( left >= L'a' && left <= L'z') {
				left = static_cast<wchar_t>( left - L'a' + L'A') ;
			}

			// 検索語側のASCII小文字も同じ比較用の大文字へ揃える。
			if( right >= L'a' && right <= L'z') {
				right = static_cast<wchar_t>( right - L'a' + L'A') ;
			}

			// 一文字でも不一致なら現在位置での照合を終了する。
			if( left != right) {
				matched = false ;
				break ;
			}
		}

		// 検索語全体が一致した最初の位置だけを返す。
		if( matched) {
			return index ;
		}
	}

	return std::wstring_view::npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief HTML cellを有限な表示textへ変換する。
 *
 * Scriptを実行せず、未知entity、NUL、未終端tagを拒否する。
 *
 * @param[in] html 一つのcell内部HTML。
 * @return Tagと既知entityを処理した表示text。不正時はnullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> stripHtmlText( const std::wstring_view html)
{
	std::wstring output ;	// 空白を正規化した表示text。
	output.reserve( std::min( html.size(), MAXIMUM_TEXT_CHARACTERS)) ;
	bool pendingSpace{} ;	// 次の表示文字前へ一つの空白を挿入する場合true。
	// Cell内部を先頭から有限に走査してtagとentityを処理する。
	for( std::size_t index = 0U; index < html.size();) {
		const wchar_t character = html[index] ;	// 現在処理するUTF-16 code unit。
		// 文字列の途中終了と解釈されるNULを表示textへ含めない。
		if( character == L'\0') {
			return std::nullopt ;
		}

		// markup開始を検出した場合は完全なtagを消費して表示上の区切りを保留する。
		if( character == L'<') {
			const std::size_t end = html.find( L'>', index + 1U) ;	// Tag終端位置。
			// 終端のないtagを黙って捨てず、HTMLの解析失敗にする。
			if( end == std::wstring_view::npos) {
				return std::nullopt ;
			}

			pendingSpace = !output.empty() ;
			index		 = end + 1U ;
			continue ;
		}

		// entity開始では既知の有限な変換表だけを照合する。
		if( character == L'&') {
			struct Entity {
				std::wstring_view encoded ;		// HTML entity表現。
				wchar_t			  decoded{} ;	// 対応する表示文字。
			} ;
			// 公式一覧の表示本文で許可するHTML entityとUnicode文字の固定対応。
			constexpr std::array ENTITIES{Entity{L"&amp;", L'&'},	   Entity{L"&quot;", L'\"'},
										  Entity{L"&apos;", L'\''},	   Entity{L"&#39;", L'\''},
										  Entity{L"&nbsp;", L' '},	   Entity{L"&reg;", L'\x00ae'},
										  Entity{L"&#174;", L'\x00ae'}} ;
			bool				 decoded{} ;	// 一つの既知entityを処理した場合true。
			// 定義済みentityのいずれかへ完全一致させる。
			for( const Entity &entity : ENTITIES) {
				// 既知entityの完全一致だけを復号し、消費した範囲を進める。
				if( html.substr( index).starts_with( entity.encoded)) {
					// 空白entityは連続空白の正規化へ合流させる。
					if( entity.decoded == L' ') {
						pendingSpace = !output.empty() ;
					} else {
						// entityの可視文字前に必要な区切り空白だけを一つ出力する。
						if( pendingSpace && !output.empty()) {
							output.push_back( L' ') ;
						}

						output.push_back( entity.decoded) ;
						pendingSpace = false ;
					}

					index += entity.encoded.size() ;
					decoded = true ;
					break ;
				}
			}

			// 未知のentityを推測で残したり除去したりせず拒否する。
			if( !decoded) {
				return std::nullopt ;
			}

			continue ;
		}

		// HTML整形用の連続空白を保留し、表示語間の区切りへ畳む。
		if( character == L' ' || character == L'\t' || character == L'\r' || character == L'\n') {
			pendingSpace = !output.empty() ;
			++index ;
			continue ;
		}

		// 許可した整形空白以外の制御文字を表示metadataへ取り込まない。
		if( character < L' ') {
			return std::nullopt ;
		}

		// 通常文字の前に必要な区切り空白だけを一つ出力する。
		if( pendingSpace && !output.empty()) {
			output.push_back( L' ') ;
		}

		output.push_back( character) ;
		pendingSpace = false ;
		++index ;
		// 復号後の表示textが上限を超えた場合は切り詰めず拒否する。
		if( output.size() > MAXIMUM_TEXT_CHARACTERS) {
			return std::nullopt ;
		}
	}

	return output ;
}

//------------------------------------------------------------------------------
/**
 * @brief HTML table rowから六つのcell textを取得する。
 *
 * Column追加、欠損、未終端cellをschema変更として拒否する。
 *
 * @param[in] row `<tr>`内部HTML。
 * @param[out] cells 成功時の六列。失敗時は空にする。
 * @return 六つの`td`を有限に取得できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool extractRowCells( const std::wstring_view row, std::vector<std::wstring> &cells)
{
	cells.clear() ;
	std::size_t offset{} ;	// 次のcellを検索するrow内位置。
	// 公式schemaの六列を順番どおり取得する。
	while( offset < row.size()) {
		// 現在の行内で次に読むcellの開始位置。未検出はnpos。
		const std::size_t cell = findAsciiCaseInsensitive( row, CELL_MARKER, offset) ;
		// 後続cellがなくなった時点でrowの走査を終了する。
		if( cell == std::wstring_view::npos) {
			break ;
		}

		const std::size_t openEnd = row.find( L'>', cell + CELL_MARKER.size()) ;	// 開始tag末尾。
		const std::size_t close =
			// Cell終了tag位置。
			findAsciiCaseInsensitive( row, CELL_END_MARKER, openEnd) ;
		// cellのtag境界が欠落または逆転している場合は部分結果を破棄する。
		if( openEnd == std::wstring_view::npos || close == std::wstring_view::npos ||
		   close < openEnd) {
			cells.clear() ;
			return false ;
		}

		const std::optional<std::wstring> text =
			// 表示text。
			stripHtmlText( row.substr( openEnd + 1U, close - openEnd - 1U)) ;
		// cell本文が不正または列数上限に達した場合はrow全体を拒否する。
		if( !text.has_value() || cells.size() >= EXPECTED_CELL_COUNT) {
			cells.clear() ;
			return false ;
		}

		cells.push_back( *text) ;
		offset = close + CELL_END_MARKER.size() ;
	}

	// data cellのないrowは候補を持たない行として許可する。
	if( cells.empty()) {
		return true ;
	}

	// dataを持つrowは固定六列が揃わなければ部分結果を破棄する。
	if( cells.size() != EXPECTED_CELL_COUNT) {
		cells.clear() ;
		return false ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示名を大小文字だけ無視する完全一致keyへ変換する。
 *
 * Slash、plus、dot等のmodel識別文字を除去せず完全一致を保つ。
 *
 * @param[in] value ModelまたはOS表示値。
 * @return ASCII英字を大文字化し、空白を一つへ畳んだ比較key。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring exactDisplayKey( const std::wstring_view value)
{
	std::wstring key ;				// 完全一致に使用する表示key。
	bool		 pendingSpace{} ;	// 次の文字前へ空白を一つ入れる場合true。
	// 前後空白と連続空白だけを正規化する。
	for( wchar_t character : value) {
		// 表示名の整形用空白を畳み、語間の区切り自体は維持する。
		if( character == L' ' || character == L'\t' || character == L'\r' || character == L'\n') {
			pendingSpace = !key.empty() ;
			continue ;
		}

		// 非空の比較keyに必要な区切り空白だけを一つ追加する。
		if( pendingSpace && !key.empty()) {
			key.push_back( L' ') ;
		}

		// 比較keyではASCII英字の大小だけを正規化する。
		if( character >= L'a' && character <= L'z') {
			character = static_cast<wchar_t>( character - L'a' + L'A') ;
		}

		key.push_back( character) ;
		pendingSpace = false ;
	}

	return key ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示textの前後ASCII空白を除去する。
 *
 * ASRockが表示する大小文字と記号を変更せず保持する。
 *
 * @param[in] value HTML cellから得た表示text。
 * @return 元文字列を所有しない前後空白除去後のview。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring_view trimAsciiWhitespace( std::wstring_view value) noexcept
{
	// 本文内部を変えず、先頭のASCII整形空白だけを除く。
	while( !value.empty() && (value.front() == L' ' || value.front() == L'\t' ||
							 value.front() == L'\r' || value.front() == L'\n')) {
		value.remove_prefix( 1U) ;
	}

	// 本文内部を変えず、末尾のASCII整形空白だけを除く。
	while( !value.empty() && (value.back() == L' ' || value.back() == L'\t' ||
							 value.back() == L'\r' || value.back() == L'\n')) {
		value.remove_suffix( 1U) ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示textをASCII英数字比較keyへ変換する。
 *
 * 分類とmaker alias照合だけに使用し、製品適用性へ使用しない。
 *
 * @param[in] value Driver、OS、makerまたはclass表示値。
 * @return ASCII英数字だけを大文字化した比較key。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring looseAsciiKey( const std::wstring_view value)
{
	std::wstring key ;	// ASCII分類用比較key。
	key.reserve( value.size()) ;
	// ASCII英数字だけを順序どおり保持する。
	for( const wchar_t character : value) {
		// 英数字keyに採用するASCII小文字を大文字へ揃える。
		if( character >= L'a' && character <= L'z') {
			key.push_back( static_cast<wchar_t>( character - L'a' + L'A')) ;
		}
		// 既に大文字のASCII英字と数字は比較keyへ保持する。
		else if( (character >= L'A' && character <= L'Z') ||
				(character >= L'0' && character <= L'9')) {
			key.push_back( character) ;
		}
	}

	return key ;
}

//------------------------------------------------------------------------------
/**
 * @brief Driver titleから安全に表示関連付けできる種別を判定する。
 *
 * BIOS、utility、chipset等を個別device候補へ関連付けない。
 *
 * @param[in] title `ver:`を除いたASRock公式driver名称。
 * @return 対応PnP driver種別。複合package等は`UNSUPPORTED`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] AsrockDriverKind classifyDriverKind( const std::wstring_view title)
{
	const std::wstring key = looseAsciiKey( title) ;	// Driver分類key。
	// driver表記のない情報とutility・firmware・BIOS・chipsetを対象分類から除く。
	if( key.find( L"DRIVER") == std::wstring::npos || key.find( L"UTILITY") != std::wstring::npos ||
	   key.find( L"FIRMWARE") != std::wstring::npos || key.find( L"BIOS") != std::wstring::npos ||
	   key.find( L"CHIPSET") != std::wstring::npos) {
		return AsrockDriverKind::UNSUPPORTED ;
	}

	// Bluetoothの明示表記があるtitleをBluetooth種別へ分類する。
	if( key.find( L"BLUETOOTH") != std::wstring::npos) {
		return AsrockDriverKind::BLUETOOTH ;
	}

	// 既知の無線LAN表記があるtitleをwireless種別へ分類する。
	if( key.find( L"WIRELESSLAN") != std::wstring::npos ||
	   key.find( L"WLANDRIVER") != std::wstring::npos ||
	   key.find( L"WIFIDRIVER") != std::wstring::npos) {
		return AsrockDriverKind::WIRELESS ;
	}

	// Audio driverの明示表記があるtitleをaudio種別へ分類する。
	if( key.find( L"AUDIODRIVER") != std::wstring::npos) {
		return AsrockDriverKind::AUDIO ;
	}

	// LAN driverの明示表記があるtitleをnetwork種別へ分類する。
	if( key.find( L"LANDRIVER") != std::wstring::npos) {
		return AsrockDriverKind::NETWORK ;
	}

	// 既知の画像driver表記があるtitleをdisplay種別へ分類する。
	if( key.find( L"GRAPHICSDRIVER") != std::wstring::npos ||
	   key.find( L"VGADRIVER") != std::wstring::npos ||
	   key.find( L"DISPLAYDRIVER") != std::wstring::npos) {
		return AsrockDriverKind::DISPLAY ;
	}

	return AsrockDriverKind::UNSUPPORTED ;
}

//------------------------------------------------------------------------------
/**
 * @brief Driver titleから明示されたmaker keyを取得する。
 *
 * Generic Bluetooth等を任意のlocal deviceへ結び付けない。
 *
 * @param[in] title ASRock公式driver名称。
 * @return 審査済みmaker key。Makerが明示されない場合は空。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring driverVendorKey( const std::wstring_view title)
{
	const std::wstring						   key = looseAsciiKey( title) ;	// Maker探索用title key。
	constexpr std::array<std::wstring_view, 9> VENDORS{
		L"REALTEK",	 L"MEDIATEK", L"INTEL",	   L"NVIDIA", L"QUALCOMM",
		L"BROADCOM", L"MARVELL",  L"AQUANTIA", L"AMD"} ;	// 許可maker key群。
	// Titleへ明示された一つ目の審査済みmakerを採用する。
	for( const std::wstring_view vendor : VENDORS) {
		// 審査済みvendor語がtitle内に明示されている場合にだけmaker keyを返す。
		if( key.find( vendor) != std::wstring::npos) {
			return std::wstring( vendor) ;
		}
	}

	// AMDの正式名表記を同じmaker keyへ対応付ける。
	if( key.find( L"ADVANCEDMICRODEVICES") != std::wstring::npos) {
		return L"AMD" ;
	}

	return {} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 掲載日を有限なM/D/YYYY形式として検証する。
 *
 * 並び替えや新旧判定には使用せず、破損metadataだけを拒否する。
 *
 * @param[in] value ASRock公式pageの日付表示。
 * @return 暦範囲内の`M/D/YYYY`の場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidReleaseDate( const std::wstring_view value) noexcept
{
	const std::size_t first = value.find( L'/') ;	// Monthとdayの区切り。
	const std::size_t second =
		// Dayとyearの区切り。
		value.find( L'/', first == std::wstring_view::npos ? 0U : first + 1U) ;
	// 月日と四桁年を区切れない日付表記を受理しない。
	if( first == std::wstring_view::npos || second == std::wstring_view::npos || first == 0U ||
	   second <= first + 1U || second + 5U != value.size()) {
		return false ;
	}

	const auto parseNumber = []( const std::wstring_view text, unsigned &number) {
		number = 0U ;
		// 空または四桁を超える日付fieldは数値化しない。
		if( text.empty() || text.size() > 4U) {
			return false ;
		}

		// Decimal各桁を有限に変換する。
		for( const wchar_t character : text) {
			// 日付fieldにASCII数字以外を許可しない。
			if( character < L'0' || character > L'9') {
				return false ;
			}

			number = number * 10U + static_cast<unsigned>( character - L'0') ;
		}

		return true ;
	} ; // Locale非依存decimal parser。
	unsigned month{} ;	// 掲載月。
	unsigned day{} ;	// 掲載日。
	unsigned year{} ;	// 掲載年。
	// 日付fieldの変換失敗と月・年の範囲外をcalendar判定前に拒否する。
	if( !parseNumber( value.substr( 0U, first), month) ||
	   !parseNumber( value.substr( first + 1U, second - first - 1U), day) ||
	   !parseNumber( value.substr( second + 1U), year) || month < 1U || month > 12U || year < 2000U ||
	   year > 9999U) {
		return false ;
	}

	// 平年の各月で許可する最終日。閏年の二月補正は別途評価する。
	constexpr std::array<unsigned, 12> MAXIMUM_DAYS{31U, 28U, 31U, 30U, 31U, 30U,
													31U, 31U, 30U, 31U, 30U, 31U} ;
	unsigned   maximumDay = MAXIMUM_DAYS[month - 1U] ;	// 対象月の通常年最大日。
	const bool leapYear =
		year % 400U == 0U || (year % 4U == 0U && year % 100U != 0U) ;	// 閏年の場合true。
	// 閏年の二月だけ日数上限を29日へ変更する。
	if( month == 2U && leapYear) {
		maximumDay = 29U ;
	}

	return day >= 1U && day <= maximumDay ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示download sizeの形式を検証する。
 *
 * 表示値をbyte数へ推測変換せず、破損metadataだけを拒否する。
 *
 * @param[in] value ASRock公式pageのsize表示。
 * @return 正のdecimal値とKB／MB／GB単位だけの場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidSizeText( const std::wstring_view value) noexcept
{
	const std::wstring_view trimmed = trimAsciiWhitespace( value) ;	// 前後空白除去後の表示値。
	// 単位を含めた容量表示の長さが範囲外なら受理しない。
	if( trimmed.size() < 3U || trimmed.size() > 20U) {
		return false ;
	}

	const std::wstring unit = looseAsciiKey( trimmed.substr( trimmed.size() - 2U)) ;	// 単位key。
	// 審査済みのKB・MB・GB以外を容量単位として推測しない。
	if( unit != L"KB" && unit != L"MB" && unit != L"GB") {
		return false ;
	}

	const std::wstring_view number =
		// Decimal表示部。
		trimAsciiWhitespace( trimmed.substr( 0U, trimmed.size() - 2U)) ;
	bool digitFound{} ;			// 数字を確認した場合true。
	bool nonzeroDigitFound{} ;	// 1以上の数字を確認した場合true。
	bool decimalFound{} ;		// 小数点を確認した場合true。
	// Decimal表示を有限に走査し、符号、桁区切り、指数表記を拒否する。
	for( const wchar_t character : number) {
		// ASCII数字の存在と非ゼロ桁を保持し、ゼロ容量の検証へ使う。
		if( character >= L'0' && character <= L'9') {
			digitFound		  = true ;
			nonzeroDigitFound = nonzeroDigitFound || character != L'0' ;
			continue ;
		}

		// 数字以外では一度だけの小数点を許可し、他の文字と重複を拒否する。
		if( character != L'.' || decimalFound) {
			return false ;
		}

		decimalFound = true ;
	}

	return digitFound && nonzeroDigitFound && number.front() != L'.' && number.back() != L'.' ;
}

//------------------------------------------------------------------------------
/**
 * @brief Driver種別へ対応するWindows setup classか判定する。
 *
 * Local表示用の関連付けをclass境界外へ広げない。
 *
 * @param[in] kind ASRock表示情報のdriver種別。
 * @param[in] classGuid Local deviceのsetup class GUID。
 * @return 審査済みclass対応表へ一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool classMatches( const AsrockDriverKind kind, const std::wstring_view classGuid)
{
	const std::wstring key = looseAsciiKey( classGuid) ;	// Braceとhyphenを除くGUID key。
	// 表示上のdriver種別を対応するWindows setup classへ限定して照合する。
	switch( kind) {
		// 有線 network driver は Net class の共通照合へ進む。
		case AsrockDriverKind::NETWORK:
		// 無線を含む network driver は Net setup class と照合する。
		case AsrockDriverKind::WIRELESS:
			return key == L"4D36E972E32511CEBFC108002BE10318" ;
		// Bluetooth driver は専用 setup class と照合する。
		case AsrockDriverKind::BLUETOOTH:
			return key == L"E0CBF06CCD8B4647BB8A263B43F0F974" ;
		// Audio driver は Media または Audio Processing Object class と照合する。
		case AsrockDriverKind::AUDIO:
			return key == L"4D36E96CE32511CEBFC108002BE10318" ||
				   key == L"C166523CFE0C4A94A586F1A80CFBBF3E" ;
		// Display driver は Display setup class と照合する。
		case AsrockDriverKind::DISPLAY:
			return key == L"4D36E968E32511CEBFC108002BE10318" ;
		// 未対応種別には類似の setup class を割り当てない。
		case AsrockDriverKind::UNSUPPORTED:
			return false ;
	}

	return false ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/asrock_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseAsrockLatestDriverHtml( const std::wstring_view html, const std::wstring_view boardModel,
								 const std::wstring_view			 osName,
								 std::vector<AsrockDriverPageEntry> &entries)
{
	entries.clear() ;
	// 空・過大・NUL混入のHTMLと照合先model・OSの欠落を拒否する。
	if( html.empty() || html.size() > MAXIMUM_HTML_CHARACTERS || boardModel.empty() ||
	   osName.empty() || html.find( L'\0') != std::wstring_view::npos) {
		return false ;
	}

	const std::size_t table = findAsciiCaseInsensitive( html, TABLE_MARKER) ;	// Table開始。
	const std::size_t tableEnd =
		// Table終了。
		findAsciiCaseInsensitive( html, TABLE_END_MARKER, table) ;
	// 公式一覧tableの境界が欠落または逆転したHTMLを解析しない。
	if( table == std::wstring_view::npos || tableEnd == std::wstring_view::npos ||
	   tableEnd <= table) {
		return false ;
	}

	const std::wstring_view tableHtml =
		// 解析対象table。
		html.substr( table, tableEnd + TABLE_END_MARKER.size() - table) ;
	const std::wstring modelKey = exactDisplayKey( boardModel) ;	// Local model完全一致key。
	const std::wstring osKey	= looseAsciiKey( osName) ;			// Local OS区分key。
	// 空のmodel比較keyと未対応のWindows x64表記を検索条件へ使用しない。
	if( modelKey.empty() || (osKey != L"WINDOWS1064BIT" && osKey != L"WINDOWS1164BIT")) {
		return false ;
	}

	std::size_t						   offset{} ;	// 次のrowを検索するtable内位置。
	std::size_t						   rowCount{} ;	// 処理済みdata row数。
	std::vector<AsrockDriverPageEntry> parsed ;		// 全体成功時だけ公開する一時結果。
	// Table内のdata rowを公式掲載順で処理する。
	while( offset < tableHtml.size()) {
		// 限定したtable内で次に解析するdriver行の開始位置。
		const std::size_t row = findAsciiCaseInsensitive( tableHtml, ROW_MARKER, offset) ;
		// table内の後続rowがなくなった時点で走査を終了する。
		if( row == std::wstring_view::npos) {
			break ;
		}

		const std::size_t openEnd = tableHtml.find( L'>', row + ROW_MARKER.size()) ;	// Tag末尾。
		const std::size_t close =
			// Row終了。
			findAsciiCaseInsensitive( tableHtml, ROW_END_MARKER, openEnd) ;
		// rowの境界不正と件数上限超過を検出して一覧全体を拒否する。
		if( openEnd == std::wstring_view::npos || close == std::wstring_view::npos ||
		   close < openEnd || ++rowCount > MAXIMUM_ROWS) {
			return false ;
		}

		std::vector<std::wstring> cells ;	// 現在rowの六列表示text。
		// 六列構造を検証できないrowを部分的に採用しない。
		if( !extractRowCells( tableHtml.substr( openEnd + 1U, close - openEnd - 1U), cells)) {
			return false ;
		}

		offset = close + ROW_END_MARKER.size() ;
		// dataのない行とmodel・OS条件に一致しない行を候補化しない。
		if( cells.empty() || exactDisplayKey( cells[0]) != modelKey ||
		   looseAsciiKey( cells[2]).find( osKey) == std::wstring::npos) {
			continue ;
		}

		const std::size_t versionMarker =
			// Revision区切り位置。
			findAsciiCaseInsensitive( cells[1], L"ver:") ;
		// 明示的なversion区切りがないdriver titleから版を推測しない。
		if( versionMarker == std::wstring::npos) {
			return false ;
		}

		const std::wstring	   title	 = std::wstring( trimAsciiWhitespace(
			// 表示用driver title。
			std::wstring_view( cells[1]).substr( 0U, versionMarker))) ;
		const std::wstring	   version	 = std::wstring( trimAsciiWhitespace(
			  // 表示用package revision。
			  std::wstring_view( cells[1]).substr( versionMarker + 4U))) ;
		const AsrockDriverKind kind		 = classifyDriverKind( title) ;	// 審査済みdriver種別。
		const std::wstring	   vendorKey = driverVendorKey( title) ;	// 明示maker key。
		// 未対応driver種別とメーカー未確定の行を表示関連付けから除外する。
		if( kind == AsrockDriverKind::UNSUPPORTED || vendorKey.empty()) {
			continue ;
		}

		// title・version・公開日・容量が揃わない対象行を受理しない。
		if( title.empty() || version.empty() || !isValidReleaseDate( cells[3]) ||
		   !isValidSizeText( cells[4])) {
			return false ;
		}

		AsrockDriverPageEntry entry ;	// 検証済みの一行。
		entry.title		  = title ;
		entry.version	  = version ;
		entry.releaseDate = cells[3] ;
		entry.sizeText	  = cells[4] ;
		entry.vendorKey	  = vendorKey ;
		entry.kind		  = kind ;
		parsed.push_back( std::move( entry)) ;
	}

	entries = std::move( parsed) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asrock_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool asrockEntryMatchesDevice( const AsrockDriverPageEntry &entry,
							  const OfficialCatalogDevice &device)
{
	// 未対応種別、メーカー欠落、setup class不一致のdeviceへ関連付けない。
	if( entry.kind == AsrockDriverKind::UNSUPPORTED || entry.vendorKey.empty() ||
	   !classMatches( entry.kind, device.deviceClassGuid)) {
		return false ;
	}

	// 端末内の表示名照合にだけ使用するmaker・model・現在providerの複合key。
	const std::wstring deviceKey =
		looseAsciiKey( device.manufacturer + L" " + device.model + L" " + device.currentProvider) ;
	// AMDの短縮名と正式名を同じメーカーの表示照合として扱う。
	if( entry.vendorKey == L"AMD") {
		return deviceKey.find( L"AMD") != std::wstring::npos ||
			   deviceKey.find( L"ADVANCEDMICRODEVICES") != std::wstring::npos ;
	}

	return deviceKey.find( entry.vendorKey) != std::wstring::npos ;
}

} // namespace drivercrate
