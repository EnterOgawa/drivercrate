//------------------------------------------------------------------------------
/**
 * @file signed_index_acquisition_descriptor_internal.cpp
 * @brief 全メーカー共通の取得descriptor元申告を有限な文法とbindingで検査します
 * @version 01.11.00
 * @date 2026/10/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/10/14  共通HTML許諾の原page・原文書・全文と配布recordを結合
 * Ver.01.01.01 Shunji Ogawa  2026/10/14  規約文書の共通必須field欠損をURL値検査前に構造拒否
 * Ver.01.01.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける
 * Ver.01.01.03 Shunji Ogawa  2026/10/23  個別期限を維持しmanifestとの順序制約だけを除去
 * Ver.01.01.04 Shunji Ogawa  2026/10/24  新規配布recordの有限8日上限へ統一
 * Ver.01.02.00 Shunji Ogawa  2026/11/03  共通公式packageの手動索引と選択内容検査を接続
 * Ver.01.03.00 Shunji Ogawa  2026/11/03  有界large archiveと共有内容保持・標準serviceを接続
 * Ver.01.04.00 Shunji Ogawa  2026/11/03  署名原範囲の非実行resource内容を接続
 * Ver.01.05.00 Shunji Ogawa  2026/11/03  匿名CDNの同record二要求と有限予約を接続
 * Ver.01.06.00 Shunji Ogawa  2026/11/05  独立静的規約の原文書・公式リンクと既存同意を共通接続
 * Ver.01.06.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.06.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.07.00 Shunji Ogawa  2026/11/22  専用欄の出典だけに正規のCatalog配布票を許可
 * Ver.01.08.00 Shunji Ogawa  2026/11/22  私有規約を元ZIPと公式規約文書へ結合
 * Ver.01.09.00 Shunji Ogawa  2026/11/22  私有収集に必須のZIP規約だけを読み取る入口を追加
 * Ver.01.10.00 Shunji Ogawa  2026/11/23  私有WiXの非実行取得形式と埋込み規約の元申告を検査
 * Ver.01.11.00 Shunji Ogawa  2026/11/27  二段の公式規約と算出版に限った署名記述子を検査
 * </pre>
 *
 * @note 索引発行者の申告を読むだけで、公式性・vendor署名・実byte・端末適合を実証しません
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#include "platform/signed_index_acquisition_descriptor_internal.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <windows.h>

#include "platform/official_html_terms.h"
#include "platform/official_http_client.h"

namespace drivercrate::signed_index_acquisition {
namespace {

// Descriptorの元textと不足理由の独立上限
constexpr std::size_t	TEXT_LIMIT = 512U ;
// 原URLを再構成せず読む固定byte上限
constexpr std::size_t	URL_LIMIT = 2048U ;
// 初回の一payload取得profile。全製品の対応上限ではありません
constexpr std::uint64_t PAYLOAD_LIMIT = 2ULL * 1024ULL * 1024ULL * 1024ULL ;
// UTF-8規約本文の正のexact byte上限
constexpr std::uint64_t TERMS_LIMIT		   = 256U * 1024U ;
constexpr std::uint64_t STATIC_TERMS_LIMIT = 2U * 1024U * 1024U ;	// 独立静的文書だけの応答上限です
/**
 * @brief この層とrecord層で元診断を共有します
 */
using Failure = signed_index_json::Failure<IndexRecordsStatus> ;
using signed_index_json::require ;
using signed_index_json::decodeHash ;

//------------------------------------------------------------------------------
/**
 * @brief 非空の公開textを制御byteなしで確認します
 * @param[in] value UTF-8検査済みの所有値からの借用
 * @return 512byte以内の非空公開textの場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validText( const std::string_view value)
{
	return !value.empty() && value.size() <= TEXT_LIMIT &&
		   std::ranges::all_of( value, []( const unsigned char character) {
			   // 表示を変えるASCII制御byteだけを拒否し、元UTF-8を維持する
			   return character >= 0x20U && character != 0x7fU ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASCII英数字の一byteを確認します
 * @param[in] value 一byteの原ASCII
 * @return 英数字の場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool alphaNumeric( const char value)
{
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
		   (value >= '0' && value <= '9') ;
}

//------------------------------------------------------------------------------
/**
 * @brief Percent tripletの一桁だけを整数へ戻します
 * @param[in] value 一byteの原hex
 * @return 0～15。不正は-1です
 */
//------------------------------------------------------------------------------
[[nodiscard]] int hexDigit( const char value)
{
	// Decimal域は同じ整数へ戻す
	if( value >= '0' && value <= '9') {
		return value - '0' ;
	}

	// 小文字hexを標準URI値へ戻す
	if( value >= 'a' && value <= 'f') {
		return value - 'a' + 10 ;
	}

	// 大文字hexも原byteを書き換えず許可する
	if( value >= 'A' && value <= 'F') {
		return value - 'A' + 10 ;
	}

	return -1 ;
}

//------------------------------------------------------------------------------
/**
 * @brief CollectorのPAGE数値selector文法だけを確認します
 * @param[in] query Question markを含まない原query
 * @return 一つの固定keyと1～20桁の数値だけの場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validPageQuery( const std::string_view query)
{
	const std::size_t	   equal = query.find( '=') ;			// 固定keyと公開数値の境界
	const std::string_view key	 = query.substr( 0U, equal) ;	// 値を書き換えない原key
	constexpr std::array<std::string_view, 5U> KEYS{"id", "drid", "download_id", "file_id",
													"product_id"} ;	// PAGEの閉じた許可集合
	// Tokenや複合queryを数値selectorの許可へ混入させない
	if( equal == std::string_view::npos || std::ranges::find( KEYS, key) == KEYS.end()) {
		return false ;
	}

	const std::string_view number = query.substr( equal + 1U) ;	// 元公開数値
	return !number.empty() && number.size() <= 20U &&
		   std::ranges::all_of( number,
							   []( const char value) { return value >= '0' && value <= '9' ; }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 検査済みURLからDNS hostを値を変えず借用します
 * @param[in] value requireUrlを成功した原HTTPS URL
 * @return Port443を除いた元DNS host
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string_view hostOf( const std::string_view value)
{
	const std::size_t	   end		 = value.find_first_of( "/?", 8U) ;	// Authority終端
	const std::string_view authority = value.substr(
		8U, end == std::string_view::npos ? value.size() - 8U : end - 8U) ;	// 原authority
	return authority.substr( 0U, authority.find( ':')) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じHTTPS scheme・DNS host・443 portを比較します
 * @param[in] left 構文検査済みURL
 * @param[in] right 構文検査済みURL
 * @return Originが同じ場合true。URL prefixは使用しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool sameOrigin( const std::string_view left, const std::string_view right)
{
	return hostOf( left) == hostOf( right) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windowsの予約名やpathを含まない有限basenameを確認します
 * @param[in] value 原basename。保存pathへ変換しません
 * @return ASCIIの安全な一componentの場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validBasename( const std::string_view value)
{
	// 有限ASCIIと先頭英数字を要求し、relative traversalを除く
	if( value.empty() || value.size() > 180U || !alphaNumeric( value.front()) ||
	   value.back() == '.' || value.back() == ' ' || value.find( "..") != std::string_view::npos) {
		return false ;
	}

	unsigned depth{} ;	// 対応する一段の括弧だけを許可する
	// 原basenameの全byteを確認し、path delimiterや予約文字を拒否する
	for( const char character : value) {
		// 開括弧は一段だけ許可する
		if( character == '(') {
			// 入れ子の括弧は初回profileで未対応として拒否する
			if( depth != 0U) {
				return false ;
			}

			depth = 1U ;
		}
		// 閉括弧は対応する開括弧だけを閉じる
		else if( character == ')') {
			// 対応しない閉括弧は安全basenameにしない
			if( depth != 1U) {
				return false ;
			}

			depth = 0U ;
		}
		// 英数字と内部space・._-以外をpathや特殊名として拒否する
		else if( !alphaNumeric( character) && character != '.' && character != '_' &&
				character != '-' && character != ' ') {
			return false ;
		}
	}

	std::string stem{value.substr( 0U, value.find( '.'))} ;	// 最初のdot以前の予約名照合値
	// Windowsが予約名照合で無視する末尾spaceだけを比較用に除く
	while( !stem.empty() && stem.back() == ' ') {
		stem.pop_back() ;
	}

	// 予約名照合だけをASCII uppercaseへ変換し、公開basenameは変更しない
	for( char &character : stem) {
		// ASCII小文字だけを同じ予約名へ照合する
		if( character >= 'a' && character <= 'z') {
			character = static_cast<char>( character - 'a' + 'A') ;
		}
	}

	const bool numbered = stem.size() == 4U &&
						  (stem.starts_with( "COM") || stem.starts_with( "LPT")) &&
						  // Windows予約device名の有限集合
						  stem.back() >= '1' && stem.back() <= '9' ;
	return depth == 0U && stem != "CON" && stem != "PRN" && stem != "AUX" && stem != "NUL" &&
		   !numbered ;
}

//------------------------------------------------------------------------------
/**
 * @brief Payload Content-Typeの単一ASCII media type申告を確認します
 * @param[in] value 原media type。実応答の検査ではありません
 * @return 有限なtype/subtypeで制御byteやparameterがない場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validContentType( const std::string_view value)
{
	const std::size_t slash = value.find( '/') ;	// Typeとsubtypeの唯一の区切り
	return !value.empty() && value.size() <= 128U && slash != std::string_view::npos &&
		   slash > 0U && slash + 1U < value.size() &&
		   value.find( '/', slash + 1U) == std::string_view::npos &&
		   std::ranges::all_of( value, []( const char character) {
			   // 元media typeをlowercase tokenとslashに限定する
			   return (character >= 'a' && character <= 'z') ||
					  (character >= '0' && character <= '9') || character == '/' ||
					  character == '.' || character == '-' || character == '+' || character == '_' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定文字列集合を元申告enumへ完全一致で解決します
 * @tparam Value 申告enum
 * @tparam Count 固定集合の件数
 * @param[in] text 原申告
 * @param[in] choices 閉じた許可集合
 * @return 一致したenum。不明literalは拒否します
 */
//------------------------------------------------------------------------------
template <class Value, std::size_t Count>
[[nodiscard]] Value choice( const std::string_view										text,
						   const std::array<std::pair<std::string_view, Value>, Count> &choices)
{
	const auto found = std::ranges::find_if( choices, [&]( const auto &item) {
		// 借用textと固定集合だけを同期参照する
		return item.first == text ;
	}) ; // 元申告の完全一致位置
	require( found != choices.end(), IndexRecordsStatus::INVALID_EVIDENCE) ;
	return found->second ;
}

//------------------------------------------------------------------------------
/**
 * @brief KNOWN／UNKNOWNの閉じた元申告を読みます
 * @param[in] value 原state
 * @return 型付きstate。不明literalは拒否します
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexDescriptorState descriptorState( const std::string_view value)
{
	constexpr std::array<std::pair<std::string_view, IndexDescriptorState>, 2U> CHOICES{
		{{"KNOWN", IndexDescriptorState::KNOWN},
		 {"UNKNOWN", IndexDescriptorState::UNKNOWN}}} ;	// 元state
	return choice( value, CHOICES) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Route hopの四必須fieldを読みます
 * @param[in,out] reader 有限record reader
 * @param[in] scopedModels 専用欄の配布票を証拠として許す場合trueです
 * @return 型付き原URLと出典の元申告
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexAcquisitionRouteHop readHop( DescriptorReader &reader, const bool scopedModels)
{
	constexpr std::array<std::string_view, 4U> FIELDS{"url", "kind", "evidenceUrl",
													  "evidenceSha256"} ;	// 全必須field
	std::array<std::string, 4U>				   fields ;						// 順序によらない原値
	// Readerと所有配列を同期借用して全fieldを要求型で読む
	reader.object( FIELDS, [&]( const std::size_t index) { fields[index] = reader.text( URL_LIMIT) ; }) ;
	constexpr std::array<std::pair<std::string_view, IndexRouteKind>, 3U> KINDS{
		{{"OFFICIAL_PAYLOAD_LINK", IndexRouteKind::OFFICIAL_PAYLOAD_LINK},
		 {"OFFICIAL_CDN_LINK", IndexRouteKind::OFFICIAL_CDN_LINK},
		 {"HTTP_REDIRECT", IndexRouteKind::HTTP_REDIRECT}}} ;	// 閉じた導線種別
	// 新protocolのpublic canonicalだけを一時的に読み、後でdescriptorへ結ぶ
	const std::string_view	 canonicalPrefix = "https://dlcdnta.asus.com" ;
	const auto				 modelAt		 = fields[0].find( "?model=") ;	// 唯一の公開selector位置
	OfficialAnonymousCdnPlan publicPlan ;									// source確認前の非authority値
	// 推定hostを登録済みCDNへ置換しない
	if( fields[0].starts_with( canonicalPrefix) && modelAt != std::string::npos) {
		publicPlan.path =
			std::wstring( fields[0].begin() + static_cast<std::ptrdiff_t>( canonicalPrefix.size()),
						 fields[0].begin() + static_cast<std::ptrdiff_t>( modelAt)) ;
		publicPlan.model = std::wstring(
			fields[0].begin() + static_cast<std::ptrdiff_t>( modelAt + 7U), fields[0].end()) ;
		publicPlan.systemCode = L"asus" ;
	}

	// 別queryや不完全contextは旧URL規則の拒否へ戻す
	if( !validAsusAnonymousCdnPlan( publicPlan)) {
		requirePayloadUrl( fields[0]) ;
	}

	// 専用欄でも配布票の例外は導線の出典にだけ適用します
	if( !scopedModels || catalogDownloadDialogUpdateId( fields[2]).empty()) {
		requireEvidenceUrl( fields[2]) ;
	}

	return {std::move( fields[0]), choice( fields[1], KINDS), std::move( fields[2]),
			decodeHash( fields[3], IndexRecordsStatus::INVALID_EVIDENCE)} ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASCII小文字の公開tag/属性名を確認します
 * @param[in] value 原名です
 * @return 1～64byteの閉じた名前の場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validHtmlName( const std::string_view value)
{
	return !value.empty() && value.size() <= 64U && value.front() >= 'a' && value.front() <= 'z' &&
		   std::ranges::all_of( value, []( const char character) {
			   // ScriptやCSS selector式を名前へ混入させません
			   return (character >= 'a' && character <= 'z') ||
					  (character >= '0' && character <= '9') || character == '-' ||
					  character == '_' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つの実tagと実属性へ完全一致する元selectorを読みます
 * @param[in,out] reader 有限readerです
 * @return 三つの必須fieldを検査した元selectorです
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexHtmlTermsSelector readHtmlSelector( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 3U> FIELDS{"tag", "attribute",
													  "value"} ;	// 全必須fieldです
	std::array<std::string, 3U>				   fields ;				// 要求型で読み終えた元値です
	// 元集合を順序非依存で同期消費します
	reader.object( FIELDS, [&]( const std::size_t field) { fields[field] = reader.text( 128U) ; }) ;
	require(
		validHtmlName( fields[0]) && validHtmlName( fields[1]) && validText( fields[2]) &&
			std::ranges::all_of( fields[2], []( const unsigned char value) { return value < 0x7fU ; }),
		IndexRecordsStatus::INVALID_EVIDENCE) ;
	return {std::move( fields[0]), std::move( fields[1]), std::move( fields[2])} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原選択文書と抽出全文の独立digestを持つHTML申告を読みます
 * @param[in,out] reader 有限readerです
 * @return profileごとの閉じた原項目です。元文書や同意は生成しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexHtmlTermsExtraction readHtmlExtraction( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 15U> FIELDS{
		"profile",
		"selector",
		"containerSelector",
		"linkSelector",
		"payloadAttribute",
		"documentSha256",
		"documentSizeBytes",
		"textSha256",
		"textSizeBytes",
		"bindingEvidenceUrl",
		"bindingEvidenceSha256",
		"bindingEvidenceSizeBytes",
		"bindingDirectoryUrl",
		"bindingDirectorySha256",
		"bindingDirectorySizeBytes"} ;	// profile別の閉集合です
	IndexHtmlTermsExtraction value ;	// 全成功前には公開しない元値です
	// 全入れ子を要求型だけで読み、未知fieldや重複を拒否します
	const auto presence = reader.objectWithPresence( FIELDS, [&]( const std::size_t field) {
		// 原selectorはCSS式ではなく固定三fieldだけです
		if( field >= 1U && field <= 3U) {
			const std::array<IndexHtmlTermsSelector *, 3U> selectors{
				&value.selector, &value.containerSelector, &value.linkSelector} ;	// 元出力先です
			*selectors[field - 1U] = readHtmlSelector( reader) ;
		} else {
			// 元項目ごとの上限と型で同期して読み取ります
			switch( field) {
				// 閉じた共通profileです
				case 0U:
					value.profile = reader.text( TEXT_LIMIT) ;
					break ;

				// 配布linkの実payload属性名です
				case 4U:
					value.payloadAttribute = reader.text( TEXT_LIMIT) ;
					break ;

				// 選択原文書の完全hashです
				case 5U:
					value.documentSha256 =
						decodeHash( reader.text( TEXT_LIMIT), IndexRecordsStatus::INVALID_EVIDENCE) ;
					break ;

				// 選択原文書のbyte数です
				case 6U:
					value.documentSizeBytes = reader.number() ;
					break ;

				// 抽出全文の完全hashです
				case 7U:
					value.textSha256 =
						decodeHash( reader.text( TEXT_LIMIT), IndexRecordsStatus::INVALID_EVIDENCE) ;
					break ;

				// 抽出全文のbyte数です
				case 8U:
					value.textSizeBytes = reader.number() ;
					break ;

				// 監視側許諾導線の原根拠URLです
				case 9U:
					value.bindingEvidenceUrl = reader.text( URL_LIMIT) ;
					break ;

				// 同原根拠byteのhashです
				case 10U:
					value.bindingEvidenceSha256 =
						decodeHash( reader.text( TEXT_LIMIT), IndexRecordsStatus::INVALID_EVIDENCE) ;
					break ;

				// 同原根拠のbyte数です
				case 11U:
					value.bindingEvidenceSizeBytes = reader.number() ;
					break ;

				// 二段リンクの中間一覧の元URLです
				case 12U:
					value.bindingDirectoryUrl = reader.text( URL_LIMIT) ;
					break ;

				// 中間一覧の原応答全体のhashです
				case 13U:
					value.bindingDirectorySha256 =
						decodeHash( reader.text( TEXT_LIMIT), IndexRecordsStatus::INVALID_EVIDENCE) ;
					break ;

				// 中間一覧の原応答のbyte数です
				case 14U:
					value.bindingDirectorySizeBytes = reader.number() ;
					break ;

				// 不明番号は補完しません
				default:
					throw Failure{IndexRecordsStatus::INVALID_EVIDENCE} ;
			}
		}
	}) ;
	constexpr std::uint32_t DIRECTORY_FIELDS =
		(1U << 12U) | (1U << 13U) | (1U << 14U) ;						// 規約一覧の元応答を指定する必須集合です
	const bool linked = value.profile == LINKED_STATIC_TERMS_PROFILE ;	// 二段リンク専用形式です
	// 中間一覧の項目は従来形式では未知の項目として拒否します
	require( linked || (presence & DIRECTORY_FIELDS) == 0U, IndexRecordsStatus::INVALID_RECORD) ;
	// 独立sectionで使う原項目は閉集合に限定し、二段の場合だけ中間一覧を要求します
	if( linked || value.profile == "STATIC_HTML_SECTION_V1") {
		constexpr std::uint64_t STATIC_FIELDS = (1U << 0U) | (1U << 1U) | (1U << 5U) | (1U << 6U) |
												(1U << 7U) | (1U << 8U) | (1U << 9U) | (1U << 10U) |
												(1U << 11U) ;	// 独立sectionの必須集合です
		require( presence == (STATIC_FIELDS | (linked ? DIRECTORY_FIELDS : 0U)) &&
					value.documentSizeBytes > 0U && value.documentSizeBytes <= STATIC_TERMS_LIMIT &&
					value.textSizeBytes > 0U &&
					value.textSizeBytes <= (linked ? STATIC_TERMS_LIMIT : TERMS_LIMIT) &&
					value.bindingEvidenceSizeBytes > 0U &&
					value.bindingEvidenceSizeBytes <= STATIC_TERMS_LIMIT &&
					(!linked || (value.bindingDirectorySizeBytes > 0U &&
								 value.bindingDirectorySizeBytes <= STATIC_TERMS_LIMIT)),
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	} else {
		require( presence == 2047U && value.profile == "TEXTAREA_HTML_DOCUMENT_V1" &&
					value.selector.tag == "textarea" && validHtmlName( value.payloadAttribute) &&
					value.documentSizeBytes > 0U && value.documentSizeBytes <= TERMS_LIMIT &&
					value.textSizeBytes > 0U && value.textSizeBytes <= TERMS_LIMIT &&
					value.selector.tag != value.containerSelector.tag &&
					value.linkSelector.tag != value.selector.tag,
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	}

	requireUrl( value.bindingEvidenceUrl, false) ;
	// 二段形式だけ中間一覧を静的な元URLとして検査します
	if( linked) {
		requireUrl( value.bindingDirectoryUrl, false) ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原plain全文または明示HTMLの取得申告を読みます
 * @param[in,out] reader 有限reader
 * @return profile別の原wire size/hashです。本文は取得しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexTermsTextDocument readDocument( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 5U> FIELDS{
		"url", "sha256", "sizeBytes", "contentType",
		"htmlExtraction"} ;			// Plain4fieldとHTML5fieldの閉じた集合です
	IndexTermsTextDocument value ;	// 全成功前には公開しない原申告
	std::string			   hash ;	// 原digestの文字列
	// 所有出力だけを同期借用し、sizeだけを整数型で読む
	const auto presence = reader.objectWithPresence( FIELDS, [&]( const std::size_t field) {
		// HTMLだけに存在する必須objectをnullへ補完しません
		if( field == 4U) {
			value.htmlExtraction = readHtmlExtraction( reader) ;
			return ;
		}

		// Exact sizeは文字列や推測値として受理しない
		if( field == 2U) {
			value.sizeBytes = reader.number() ;
		} else {
			// それぞれの元textを固定出力へ写す
			const std::array<std::string *, 4U> targets{&value.url, &hash, nullptr,
														&value.contentType} ;	// 非owning出力先
			*targets[field] = reader.text( field == 0U ? URL_LIMIT : TEXT_LIMIT) ;
		}
	}) ;
	// 共通4fieldの欠損を空のURL値へ読み替えず、従来の構造拒否を維持します
	require( (presence & 15U) == 15U, IndexRecordsStatus::INVALID_RECORD) ;
	requireUrl( value.url, false) ;
	const bool html	  = value.contentType == "text/html; charset=utf-8" ;	// 明示別契約です
	const bool linked = value.htmlExtraction && value.htmlExtraction->profile ==
													LINKED_STATIC_TERMS_PROFILE ;	// 二段リンク用です
	const bool staticSection =
		linked || (value.htmlExtraction &&
				   // 独立文書です
				   value.htmlExtraction->profile == "STATIC_HTML_SECTION_V1") ;
	require( presence == (html ? 31U : 15U) && value.sizeBytes > 0U &&
				value.sizeBytes <= (staticSection ? STATIC_TERMS_LIMIT : TERMS_LIMIT) &&
				(html || value.contentType == "text/plain; charset=utf-8") &&
				(value.htmlExtraction.has_value() == html),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 二段の各元ページを、共通アンカー検査が扱う互いに異なる正規URLへ限定します
	if( linked) {
		const auto &extraction = *value.htmlExtraction ;	// 既に構造を検査した二段の元URLです
		require( hasSameOriginStaticHtmlDocumentUrls( extraction.bindingEvidenceUrl,
													extraction.bindingDirectoryUrl, value.url),
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	}

	value.sha256 = decodeHash( hash, IndexRecordsStatus::INVALID_EVIDENCE) ;
	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 審査済みの規約メンバーを元ZIPへ結ぶ閉じた申告を読みます
 * @param[in,out] reader 同じ元記述子の有限readerです
 * @return 原サイズ、ハッシュ、相対名と規約指定文です。取得を発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexArchiveTermsNotice readArchiveNotice( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 8U> NAMES{
		"memberPath",		   "memberSha256",	  "statement",
		"originalDocumentUrl", "archiveSha256",	  "memberSizeBytes",
		"statementOffset",	   "archiveSizeBytes"} ;	// 全必須の原項目です
	constexpr std::array<std::size_t, 5U> TEXT_LIMITS{160U, 64U, TEXT_LIMIT, URL_LIMIT,
													  64U} ;	// 原文字列ごとの読み取り上限です
	std::array<std::string, 5U>			  texts ;				// 元の文字列を変更せず所有します
	std::array<std::uint64_t, 3U>		  numbers{} ;			// メンバーサイズ、指定位置、ZIPサイズです
	// 元申告の順番から独立して閉じた型に読み込みます
	reader.object( NAMES, [&]( const std::size_t field) {
		// サイズと位置を文字列へ補完しません
		if( field < texts.size()) {
			texts[field] = reader.text( TEXT_LIMITS[field]) ;
		} else {
			numbers[field - texts.size()] = reader.number() ;
		}
	}) ;
	// 正規相対名の全成分を、先頭から末尾まで一度ずつ確認します
	for( auto remaining = std::string_view{texts[0]};;) {
		const auto separator = remaining.find( '\\') ;				// 正規Windows相対名の成分境界です
		const auto component = remaining.substr( 0U, separator) ;	// 同じ原名の一成分です
		require( component.size() <= 96U && validBasename( component),
				IndexRecordsStatus::INVALID_EVIDENCE) ;
		// 最後の成分まで、空や親展開を含まない同じ名を確認します
		if( separator == remaining.npos) {
			break ;
		}

		remaining.remove_prefix( separator + 1U) ;
	}

	// 指定位置の範囲と、印字可能な原ASCII文を整数演算の上限内で照合します
	require( numbers[0] > 0U && numbers[0] <= 64U * 1024U && numbers[1] <= numbers[0] &&
				numbers[2] > 0U && numbers[2] <= PAYLOAD_LIMIT && !texts[2].empty() &&
				texts[2].size() <= numbers[0] - numbers[1] &&
				std::ranges::all_of( texts[2],
									[]( const unsigned char character) {
										// メンバー全体は原byteで検査し、指定文だけをASCIIへ限定します
										return character >= 0x20U && character <= 0x7eU ;
									}),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	return {numbers[2],
			decodeHash( texts[4], IndexRecordsStatus::INVALID_EVIDENCE),
			std::move( texts[0]),
			numbers[0],
			decodeHash( texts[1], IndexRecordsStatus::INVALID_EVIDENCE),
			numbers[1],
			std::move( texts[2]),
			std::move( texts[3])} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 規約状態を本文取得や同意へ昇格せず読みます
 * @param[in,out] reader 有限reader
 * @param[in] allowWix 取得descriptorでWiX固有の埋込み規約を構造検査する場合trueです
 * @return 元規約申告と不足理由
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexAcquisitionTerms readTerms( DescriptorReader &reader, const bool allowWix = false)
{
	constexpr std::array<std::string_view, 8U> FIELDS{
		"state",		"reason",	"evidenceUrl",	"evidenceSha256",
		"revisionKind", "revision", "textDocument", "archiveNotice"} ;	// 必須七項目と私有の証拠です
	std::array<std::string, 6U> fields ;								// Document以外の元text
	IndexAcquisitionTerms		value ;									// 全成功前には公開しない値
	// 原field集合を順序非依存で同期消費する
	const auto present = reader.objectWithPresence( FIELDS, [&]( const std::size_t field) {
		// 明示nullと固定documentだけを区別する
		if( field == 6U) {
			// 本文情報の欠損を空objectで補わない
			if( !reader.nullValue()) {
				value.textDocument = readDocument( reader) ;
			}
		}
		// 私有の規約証拠は省略とnullを区別します
		else if( field == 7U) {
			value.archiveNotice = readArchiveNotice( reader) ;
		} else {
			fields[field] = reader.text( field == 2U ? URL_LIMIT : TEXT_LIMIT) ;
		}
	}) ;
	require( (present & 0x7fU) == 0x7fU, IndexRecordsStatus::INVALID_RECORD) ;
	constexpr std::array<std::pair<std::string_view, IndexTermsState>, 3U> STATES{
		{{"UNKNOWN", IndexTermsState::UNKNOWN},
		 {"CONFIRMED_NO_CONSENT", IndexTermsState::CONFIRMED_NO_CONSENT},
		 {"ACCEPTANCE_REQUIRED", IndexTermsState::ACCEPTANCE_REQUIRED}}} ;	// 同意結果ではない元state
	constexpr std::array<std::pair<std::string_view, IndexTermsRevisionKind>, 4U> REVISIONS{
		{{"NONE", IndexTermsRevisionKind::NONE},
		 {"VENDOR_LITERAL", IndexTermsRevisionKind::VENDOR_LITERAL},
		 {"COMPUTED_UTF8_SHA256", IndexTermsRevisionKind::COMPUTED_UTF8_SHA256},
		 {"WIX_RTF_SHA256", IndexTermsRevisionKind::WIX_RTF_SHA256}}} ;	// Revisionの由来
	value.state		   = choice( fields[0], STATES) ;
	value.reason	   = std::move( fields[1]) ;
	value.evidenceUrl  = std::move( fields[2]) ;
	value.revisionKind = choice( fields[4], REVISIONS) ;
	value.revision	   = std::move( fields[5]) ;
	// WiXの規約は同じEXEから検査するため、別取得の本文や旧ZIP規約を認めません
	if( value.revisionKind == IndexTermsRevisionKind::WIX_RTF_SHA256) {
		require( allowWix && value.state == IndexTermsState::ACCEPTANCE_REQUIRED &&
					value.reason.empty() && value.revision.empty() && !value.textDocument &&
					!value.archiveNotice,
				IndexRecordsStatus::INVALID_EVIDENCE) ;
		requireUrl( value.evidenceUrl, true) ;
		value.evidenceSha256 = decodeHash( fields[3], IndexRecordsStatus::INVALID_EVIDENCE) ;
		return value ;
	}

	// 規約メンバーがあるときは、独立文書と同意必須の原改訂に結びます
	if( value.archiveNotice) {
		require( value.state == IndexTermsState::ACCEPTANCE_REQUIRED &&
					value.revisionKind == IndexTermsRevisionKind::VENDOR_LITERAL &&
					value.textDocument && value.textDocument->htmlExtraction &&
					value.textDocument->htmlExtraction->profile == "STATIC_HTML_SECTION_V1",
				IndexRecordsStatus::INVALID_EVIDENCE) ;
		const auto &notice = *value.archiveNotice ;	// 審査済みの原文と原URLです
		const auto	https =
			std::string_view{value.textDocument->url} ;							// 別に検査したHTTPS文書URLです
		const auto original = std::string_view{notice.originalDocumentUrl} ;	// ZIP内の原表記です
		const auto position = notice.statement.find( original) ;				// 原指定文でのURL開始位置です
		const auto scheme =
			// ほかのURLを含まない指定文か照合する位置です
			notice.statement.find( "://") ;
		require( (original == https ||
				 (original.starts_with( "http://") && original.substr( 7U) == https.substr( 8U))) &&
					position != std::string::npos && position > 0U &&
					notice.statement[position - 1U] == ' ' &&
					scheme == position + (original.starts_with( "http://") ? 4U : 5U) &&
					notice.statement.find( "://", scheme + 3U) == std::string::npos,
				IndexRecordsStatus::INVALID_EVIDENCE) ;
		const auto suffix = std::string_view{notice.statement}.substr(
			position + original.size()) ;	// 完全な原URLに続く末尾句読点です
		require( suffix.empty() || suffix == ".", IndexRecordsStatus::INVALID_EVIDENCE) ;
	}

	// 未確認の根拠とrevisionを架空補完せず非空理由だけを保持する
	if( value.state == IndexTermsState::UNKNOWN) {
		require( validText( value.reason) && value.evidenceUrl.empty() && fields[3].empty() &&
					value.revisionKind == IndexTermsRevisionKind::NONE && value.revision.empty() &&
					!value.textDocument,
				IndexRecordsStatus::INVALID_EVIDENCE) ;
		return value ;
	}

	require( value.reason.empty(), IndexRecordsStatus::INVALID_EVIDENCE) ;
	requireUrl( value.evidenceUrl, true) ;
	value.evidenceSha256 = decodeHash( fields[3], IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 同意不要に本文やrevisionを付けて同意状態を混同しない
	if( value.state == IndexTermsState::CONFIRMED_NO_CONSENT) {
		require( value.revisionKind == IndexTermsRevisionKind::NONE && value.revision.empty() &&
					!value.textDocument,
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	} else {
		require( value.textDocument.has_value() &&
					((value.revisionKind == IndexTermsRevisionKind::VENDOR_LITERAL &&
					  validText( value.revision) && value.revision.size() <= 128U) ||
					 (value.revisionKind == IndexTermsRevisionKind::COMPUTED_UTF8_SHA256 &&
					  value.revision.empty())),
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	}

	// 二段規約の版は、同じ規約文書から表示する完全UTF-8本文だけで算出します
	if( value.textDocument && value.textDocument->htmlExtraction &&
	   value.textDocument->htmlExtraction->profile == LINKED_STATIC_TERMS_PROFILE) {
		require( value.revisionKind == IndexTermsRevisionKind::COMPUTED_UTF8_SHA256 &&
					value.evidenceUrl == value.textDocument->url &&
					value.evidenceSha256 == value.textDocument->sha256,
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つの具体的条件をcommandやscriptなしで読みます
 * @param[in,out] reader 有限reader
 * @return 元条件と一出典へのbinding
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexAcquisitionPrerequisite readPrerequisite( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 4U> FIELDS{"kind", "description", "evidenceUrl",
													  "evidenceSha256"} ;	// 全必須field
	std::array<std::string, 4U>				   fields ;						// 元公開条件の所有text
	// 全fieldだけを要求型で同期消費する
	reader.object( FIELDS, [&]( const std::size_t field) {
		fields[field] = reader.text( field == 2U ? URL_LIMIT : TEXT_LIMIT) ;
	}) ;
	constexpr std::array<std::pair<std::string_view, IndexPrerequisiteKind>, 3U> KINDS{
		{{"USER_CONFIRMATION", IndexPrerequisiteKind::USER_CONFIRMATION},
		 {"LOCAL_CHECK", IndexPrerequisiteKind::LOCAL_CHECK},
		 {"INSEPARABLE_FIRMWARE",
		  IndexPrerequisiteKind::INSEPARABLE_FIRMWARE}}} ;	// 未確認を同意で補わない条件
	require( validText( fields[1]), IndexRecordsStatus::INVALID_EVIDENCE) ;
	requireUrl( fields[2], true) ;
	return {choice( fields[0], KINDS), std::move( fields[1]), std::move( fields[2]),
			decodeHash( fields[3], IndexRecordsStatus::INVALID_EVIDENCE)} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 条件の有限集合か明示UNKNOWN理由を読みます
 * @param[in,out] reader 有限reader
 * @return 最大16件の申告集合または不足理由
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexAcquisitionPrerequisites readPrerequisites( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 3U> FIELDS{"state", "reason", "items"} ;	// 全必須field
	IndexAcquisitionPrerequisites			   value ;								// 成功前には公開しない元集合
	std::string								   state ;								// 原stateの閉じたliteral
	// Stateと理由・有限配列をそれぞれの型で同期消費する
	reader.object( FIELDS, [&]( const std::size_t field) {
		// 条件配列は空集合も明示として読取り、上限を維持する
		if( field == 2U) {
			reader.array(
				16U, [&] { value.items.push_back( readPrerequisite( reader)) ; },
				IndexRecordsStatus::COUNT_LIMIT) ;
		} else {
			(field == 0U ? state : value.reason) = reader.text( TEXT_LIMIT) ;
		}
	}) ;
	value.state = descriptorState( state) ;
	require( value.state == IndexDescriptorState::KNOWN
				? value.reason.empty()
				: validText( value.reason) && value.items.empty(),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 監視PCによる導線確認の元申告を読みます
 * @param[in,out] reader 有限reader
 * @param[in] scopedModels 専用欄の配布票を証拠として許す場合trueです
 * @return 固定kind・revisionと元UTC・証拠。製品trustやvendor検証実績ではありません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexAcquisitionAttestation readAttestation( DescriptorReader &reader,
														  const bool		scopedModels)
{
	constexpr std::array<std::string_view, 7U> FIELDS{"kind",
													  "policyRevision",
													  "checkedAtUtc",
													  "validUntilUtc",
													  "authorityMethod",
													  "authorityEvidenceUrl",
													  "authorityEvidenceSha256"} ;	// 全必須field
	std::array<std::string, 7U>				   fields ;								// Revision以外の元text
	IndexAcquisitionAttestation				   value ;								// 全検査前には公開しない元申告
	// 原UTCと整数revisionを別型で同期消費する
	reader.object( FIELDS, [&]( const std::size_t field) {
		// 監視PC policyの版は正確な整数で固定する
		if( field == 1U) {
			value.policyRevision = reader.number() ;
		} else {
			fields[field] = reader.text( field == 5U ? URL_LIMIT : TEXT_LIMIT) ;
		}
	}) ;
	constexpr std::array<std::pair<std::string_view, IndexAuthorityMethod>, 2U> METHODS{
		{{"OFFICIAL_SITE_CONTROL_AND_LINK", IndexAuthorityMethod::OFFICIAL_SITE_CONTROL_AND_LINK},
		 {"VENDOR_CATALOG_SIGNATURE_VERIFIED",
		  IndexAuthorityMethod::VENDOR_CATALOG_SIGNATURE_VERIFIED}}} ;	// 端末実績ではない元method
	value.manualReview = fields[0] == "MANUAL_VERIFIED_OFFICIAL_ROUTE" ;
	require( (fields[0] == "COLLECTOR_VERIFIED_OFFICIAL_ROUTE" || value.manualReview) &&
				value.policyRevision == 1U,
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	value.checkedAtUtc	  = signed_index_json::utc( fields[2], IndexRecordsStatus::INVALID_EVIDENCE) ;
	value.validUntilUtc	  = signed_index_json::utc( fields[3], IndexRecordsStatus::INVALID_EVIDENCE) ;
	value.authorityMethod = choice( fields[4], METHODS) ;
	// 専用欄であっても正規配布票以外のquery規則は維持します
	if( !scopedModels || catalogDownloadDialogUpdateId( fields[5]).empty()) {
		requireUrl( fields[5], true) ;
	}

	value.authorityEvidenceUrl	  = std::move( fields[5]) ;
	value.authorityEvidenceSha256 = decodeHash( fields[6], IndexRecordsStatus::INVALID_EVIDENCE) ;
	return value ;
}

} // namespace

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 共通の静的URL規則と用途別の閉じたquery許可を検査します
 * @param[in] value 原ASCII URLです
 * @param[in] pageQuery PAGEの公開数値selectorを許す場合trueです
 * @param[in] payloadCacheQuery payloadの単一公開cache版を許す場合trueです
 * @note 公式性・到達性・通信許可を発行しません
 */
//------------------------------------------------------------------------------
void requireUrlWithPolicy( const std::string_view value, const bool pageQuery,
						  const bool payloadCacheQuery)
{
	require( !value.empty() && value.size() <= URL_LIMIT && value.starts_with( "https://") &&
				value.find_first_of( "#@\\") == std::string_view::npos &&
				std::ranges::all_of( value,
									[]( const unsigned char character) {
										// 静的URLのASCII原byteを維持し、空白や制御byteを除く
										return character > 0x20U && character < 0x7fU ;
									}),
			IndexRecordsStatus::INVALID_URL) ;
	const std::size_t query = value.find( '?') ;	// 原queryの存在位置
	// 既存PAGE数値selectorと、認証情報を持たない単一公開cache版だけを認めます
	if( query != std::string_view::npos) {
		const auto selector =
			// 単一の公開cache版か既存PAGE selectorです
			value.substr( query + 1U) ;
		// 認証情報や複合queryを含まない有限な公開cache版だけです
		const bool cacheVersion =
			selector.starts_with( "v=") && selector.size() > 2U && selector.size() <= 130U &&
			std::ranges::all_of( selector.substr( 2U),
								[]( const char digit) { return hexDigit( digit) >= 0 ; }) ;
		require( (payloadCacheQuery && cacheVersion) || (pageQuery && validPageQuery( selector)),
				IndexRecordsStatus::INVALID_URL) ;
	}

	const std::size_t	   end		 = value.find_first_of( "/?", 8U) ;	// 原authorityの終端
	const std::string_view authority = value.substr(
		8U, end == std::string_view::npos ? value.size() - 8U : end - 8U) ;	// 原authority
	const std::size_t	   colon = authority.find( ':') ;					// 明示portの位置
	const std::string_view host	 = hostOf( value) ;							// 元DNS名
	require( colon == std::string_view::npos || authority.substr( colon) == ":443",
			IndexRecordsStatus::INVALID_URL) ;
	require( !host.empty() && host.size() <= 253U && host.find( '.') != std::string_view::npos &&
				host.back() >= 'a' && host.back() <= 'z' && !host.starts_with( "localhost.") &&
				!host.ends_with( ".local") && !host.ends_with( ".internal") &&
				!host.ends_with( ".localhost") && !host.ends_with( ".lan"),
			IndexRecordsStatus::INVALID_URL) ;
	std::size_t start{} ;	// DNS labelごとの原開始位置
	// 原DNS名の全labelを確認し、空label・先末尾hyphen・IP literalを拒否する
	while( start < host.size()) {
		const std::size_t	   dot	 = host.find( '.', start) ;	// 次labelへの境界
		const std::string_view label = host.substr(
			start, dot == std::string_view::npos ? host.size() - start : dot - start) ;	// 原label
		require( !label.empty() && label.size() <= 63U && alphaNumeric( label.front()) &&
					alphaNumeric( label.back()) &&
					std::ranges::all_of( label,
										[]( const char character) {
											// 収集側と同じ小文字DNS文法を保持する
											return (character >= 'a' && character <= 'z') ||
												   (character >= '0' && character <= '9') ||
												   character == '-' ;
										}),
				IndexRecordsStatus::INVALID_URL) ;
		// 最後のlabelを確認したら有限走査を終える
		if( dot == std::string_view::npos) {
			break ;
		}

		start = dot + 1U ;
	}

	std::string decoded{value} ;	// Encoded control検査だけの一時copy。URLは書き換えない
	// Collectorと同じ三層上限でpercent controlを検査し、反復decodeを通信値にしない
	for( unsigned pass = 0U; pass < 3U; ++pass) {
		std::string next ;	// この一層だけの比較値
		// 元copyの全byteを一度ずつ確認し、malformed escape・制御・backslashを拒否する
		for( std::size_t index = 0U; index < decoded.size(); ++index) {
			unsigned char character = static_cast<unsigned char>( decoded[index]) ;	// 次の検査byte
			// 正しいtripletだけを一層解除する
			if( character == '%') {
				require( index + 2U < decoded.size() && hexDigit( decoded[index + 1U]) >= 0 &&
							hexDigit( decoded[index + 2U]) >= 0,
						IndexRecordsStatus::INVALID_URL) ;
				character = static_cast<unsigned char>( hexDigit( decoded[index + 1U]) * 16 +
													   hexDigit( decoded[index + 2U])) ;
				index += 2U ;
			}

			require( character >= 0x20U && character != 0x7fU && character != '\\',
					IndexRecordsStatus::INVALID_URL) ;
			next.push_back( static_cast<char>( character)) ;
		}

		decoded = std::move( next) ;
	}

	const std::wstring wide{value.begin(), value.end()} ;				// 共通URL parserへ渡す原ASCIIのcopy
	const std::wstring wideHost{host.begin(), host.end()} ;				// 同じ原hostだけの構文照合値
	const std::array<std::wstring_view, 1U> hosts{wideHost} ;			// Trust登録やnetwork policyではない
	const NativeError error = validateOfficialHttpsUrl( wide, hosts) ;	// 共通parserの元診断
	// 確保失敗をURLの不正へ読み替えない
	if( error == static_cast<NativeError>( E_OUTOFMEMORY)) {
		throw Failure{IndexRecordsStatus::OUT_OF_MEMORY, error} ;
	}

	require( error == 0, IndexRecordsStatus::INVALID_URL) ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 原HTTPS URLを共通URL parserと用途限定PAGE文法へ照合します
 * @param[in] value 2048byte以内の原ASCII URL。値を書き換えません
 * @param[in] pageQuery PAGEの閉じた公開数値selectorだけを認める指定
 * @note DNS・実宛先・公式性・到達性を確認しません。不成立はcodecの固定拒否へ中断します
 */
//------------------------------------------------------------------------------
void requireUrl( const std::string_view value, const bool pageQuery)
{
	requireUrlWithPolicy( value, pageQuery, false) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原payload URLだけに単一公開cache版queryを認めます
 * @param[in] value 原ASCII URLです。認証queryや複合値は拒否します
 * @note PAGEの数値selectorをpayload用途へ追加しません
 */
//------------------------------------------------------------------------------
void requirePayloadUrl( const std::string_view value)
{
	requireUrlWithPolicy( value, false, true) ;
}

//------------------------------------------------------------------------------
/**
 * @brief PAGEまたはpayloadを出典にできる証拠URLの既存数値/公開cache版を検査します
 * @param[in] value 根拠の原ASCII URLです。通信値を書き換えません
 * @note sourceのdistributionPageと公式性attestationはrequireUrlでPAGEとして別検査します
 */
//------------------------------------------------------------------------------
void requireEvidenceUrl( const std::string_view value)
{
	requireUrlWithPolicy( value, true, true) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式Catalogの単一更新用の固定配布票URLで繰り返される元GUIDを検査します
 * @param[in] value 同じ更新の原配布票URLの候補です
 * @return 借用する同一GUIDです。別起点、別query、別表記と不一致は空です
 * @note 公開出典の比較専用です。通信や取得許可を発行しません
 */
//------------------------------------------------------------------------------
std::string_view catalogDownloadDialogUpdateId( const std::string_view value) noexcept
{
	// 公式Catalogの固定起点と、一件の元GUIDより前の正規表記です
	constexpr std::string_view prefix =
		"https://www.catalog.update.microsoft.com/DownloadDialog.aspx"
		"?updateIDs=%5B%7B%22size%22%3A0%2C%22languages%22%3A%22%22%2C%22uidInfo%22%3A%22" ;
	// 最初のGUIDと同じ値を指定する第二項目の正規表記です
	constexpr std::string_view separator = "%22%2C%22updateID%22%3A%22" ;
	// 固定した一件の配布票の終端です
	constexpr std::string_view suffix = "%22%7D%5D" ;
	// 元GUIDのハイフンを含む固定長です
	constexpr std::size_t	   guidBytes = 36U ;
	// 追加パラメーターや別順のエンコードは同じ配布票へ読み替えません
	if( value.size() != prefix.size() + guidBytes * 2U + separator.size() + suffix.size() ||
	   !value.starts_with( prefix) || !value.ends_with( suffix) ||
	   value.substr( prefix.size() + guidBytes, separator.size()) != separator) {
		return {} ;
	}

	const auto id = value.substr( prefix.size(), guidBytes) ;	// 元の単一更新です
	// 同じ更新ID二箇所の原バイトを照合します
	if( id != value.substr( prefix.size() + guidBytes + separator.size(), guidBytes)) {
		return {} ;
	}

	// 固定位置のハイフンと小文字hexだけを許します
	for( std::size_t index = 0U; index < id.size(); ++index) {
		const auto character = id[index] ;	// 公開GUIDの一桁です
		// GUIDの固定区切り位置を判定します
		const bool hyphen = index == 8U || index == 13U || index == 18U || index == 23U ;
		// 空白・エスケープや別の識別子への補正は行いません
		if( hyphen ? character != '-'
				  : !((character >= '0' && character <= '9') ||
					  (character >= 'a' && character <= 'f'))) {
			return {} ;
		}
	}

	return id ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既存strict readerで一つの規約宣言を閉検証します
 * @param[in] raw 最大512KiBの原JSONです。本文ではなく固定文書情報だけです
 * @return 観測や同意を発行しない型付き規約です
 */
//------------------------------------------------------------------------------
IndexAcquisitionTerms readTermsValue( const std::string_view raw)
{
	DescriptorReader reader( raw, IndexRecordsStatus::INVALID_RECORD, 512U * 1024U,
							8U) ;					// 既存最大8段と重複key検査を維持します
	const auto		 terms = readTerms( reader) ;	// 従来と新profileの同じ閉schemaです
	reader.finish() ;
	require( !terms.archiveNotice, IndexRecordsStatus::INVALID_EVIDENCE) ;
	return terms ;
}

//------------------------------------------------------------------------------
/**
 * @brief 私有収集の保存済み規約を厳密な共通文法で読み取り、ZIP規約の証拠を要求します
 * @param[in] raw 元取得の規約JSONです。呼出し中だけ借用します
 * @return ZIP、メンバー、固定の規約文書への照合条件です
 * @throws signed_index_json::Failure<IndexRecordsStatus> 構造または証拠が不正です
 * @note 公式配布と実バイトは収集処理で別に検査します
 */
//------------------------------------------------------------------------------
IndexAcquisitionTerms readCollectorArchiveTermsValue( const std::string_view raw)
{
	DescriptorReader reader( raw, IndexRecordsStatus::INVALID_RECORD, 512U * 1024U,
							8U) ;					// 従来と同じ入力制限と重複キーの検査です
	const auto		 terms = readTerms( reader) ;	// 取得記述子と同じ全条件です
	reader.finish() ;
	require( terms.archiveNotice.has_value(), IndexRecordsStatus::INVALID_EVIDENCE) ;
	return terms ;
}

//------------------------------------------------------------------------------
/**
 * @brief Descriptorのv1全13fieldまたはv2全14fieldと全入れ子をstrict readerで読みます
 * @param[in,out] reader 原recordの有限reader。呼出し中だけ借用します
 * @param[in] readText 既存Known textの同期parser。Null不可、参照を保持しません
 * @param[in] scopedModels 専用欄の配布票を証拠として読む場合trueです
 * @return 全構造検査を成功した元申告。取得能力はありません
 * @note Source・manifest・record方式への結合はvalidateBindingで別に検査します
 */
//------------------------------------------------------------------------------
IndexAcquisitionDescriptor readDescriptor( DescriptorReader &reader, const TextValueReader readText,
										  const bool scopedModels)
{
	constexpr std::array<std::string_view, 14U> FIELDS{
		"schema",
		"state",
		"reason",
		"payloadUrl",
		"fileName",
		"format",
		"expectedContentType",
		"maximumBytes",
		"route",
		"terms",
		"prerequisites",
		"publisher",
		"attestation",
		"payloadPlan"} ;					// v1共通13必須fieldとv2追加一field
	std::array<std::string, 7U> fields ;	// 先頭の原text申告
	IndexAcquisitionDescriptor	value ;		// 全成功前には公開しない値
	require( readText != nullptr, IndexRecordsStatus::INTERNAL_FAILURE) ;
	// Field順によらず要求型だけを同期消費する
	const auto present = reader.objectWithPresence( FIELDS, [&]( const std::size_t field) {
		// 先頭七つは元textの上限を別々に保つ
		if( field < 7U) {
			fields[field] = reader.text( field == 3U ? URL_LIMIT : TEXT_LIMIT) ;
		} else {
			// 残りの固定fieldを型付きの有限読取りへ接続する
			switch( field) {
				// 一payloadの有限byte上限
				case 7U:
					value.maximumBytes = reader.number() ;
					break ;

				// 最大6hop、redirectは後のbindingで結合する
				case 8U:
					reader.array(
						6U, [&] { value.route.push_back( readHop( reader, scopedModels)) ; },
						IndexRecordsStatus::COUNT_LIMIT) ;
					break ;

				// 規約の申告であり本文や同意ではない
				case 9U:
					value.terms = readTerms( reader, !scopedModels) ;
					break ;

				// 明示空集合とUNKNOWN理由を分ける
				case 10U:
					value.prerequisites = readPrerequisites( reader) ;
					break ;

				// Known textの既存文法だけへ委譲する
				case 11U:
					value.publisher = readText( reader) ;
					break ;

				// NullはUNKNOWNだけで許可し、欠損fieldと区別する
				case 12U:
					// 元attestationが存在する場合だけ全fieldを読む
					if( !reader.nullValue()) {
						value.attestation = readAttestation( reader, scopedModels) ;
					}

					break ;

				// v2だけの閉じたcontent/retrieval計画
				case 13U:
					value.resourceContent = readResourcePayloadPlan( reader, value.anonymousCdn) ;
					break ;

				// 未登録番号を成功へ補完しない
				default:
					throw Failure{IndexRecordsStatus::INVALID_RECORD} ;
			}
		}
	}) ;
	constexpr std::array<std::pair<std::string_view, IndexPayloadFormat>, 8U> FORMATS{
		{{"UNKNOWN", IndexPayloadFormat::UNKNOWN},
		 {"ZIP", IndexPayloadFormat::ZIP},
		 {"CABINET", IndexPayloadFormat::CABINET},
		 {"WINDOWS_EXE", IndexPayloadFormat::WINDOWS_EXE},
		 {"WINDOWS_MSI", IndexPayloadFormat::WINDOWS_MSI},
		 {"SEVEN_ZIP_SFX", IndexPayloadFormat::SEVEN_ZIP_SFX},
		 {"PE_RESOURCE_CONTAINER", IndexPayloadFormat::PE_RESOURCE_CONTAINER},
		 {"WIX_BURN_V3", IndexPayloadFormat::WIX_BURN_V3}}} ;	// 未知は自動補完しない形式
	// 旧必須field欠損は旧object readerと同じ構造拒否へ保つ
	require( (present & 0x1fffU) == 0x1fffU, IndexRecordsStatus::INVALID_RECORD) ;
	require( fields[0] == "driver-index-acquisition-v1" ||
				fields[0] == "driver-index-acquisition-v2",
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	require( (fields[0] == "driver-index-acquisition-v1" && present == 0x1fffU) ||
				(fields[0] == "driver-index-acquisition-v2" && present == 0x3fffU),
			IndexRecordsStatus::INVALID_RECORD) ;
	value.schemaVersion		  = fields[0] == "driver-index-acquisition-v2" ? 2U : 1U ;
	value.state				  = descriptorState( fields[1]) ;
	value.reason			  = std::move( fields[2]) ;
	value.payloadUrl		  = std::move( fields[3]) ;
	value.fileName			  = std::move( fields[4]) ;
	value.format			  = choice( fields[5], FORMATS) ;
	value.expectedContentType = std::move( fields[6]) ;
	const bool wix = value.format == IndexPayloadFormat::WIX_BURN_V3 ;	// 元EXE内規約の形式です
	require( wix == (value.terms.revisionKind == IndexTermsRevisionKind::WIX_RTF_SHA256) &&
				(!wix || (value.schemaVersion == 1U && value.state == IndexDescriptorState::KNOWN &&
						  value.expectedContentType == "application/octet-stream" &&
						  value.route.size() == 1U && !scopedModels)),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 私有規約証拠を、使用できない方式や未確認の配布へ添付できません
	require( !value.terms.archiveNotice || (value.state == IndexDescriptorState::KNOWN &&
										   value.format == IndexPayloadFormat::ZIP &&
										   value.schemaVersion == 1U && !scopedModels),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	// v1に新fieldや新形式を黙って混ぜず、v2の原計画を必須にする
	require( (value.schemaVersion == 1U && !value.resourceContent && !value.anonymousCdn &&
			 value.format != IndexPayloadFormat::PE_RESOURCE_CONTAINER) ||
				(value.schemaVersion == 2U && value.resourceContent &&
				 value.format == IndexPayloadFormat::PE_RESOURCE_CONTAINER &&
				 value.state == IndexDescriptorState::KNOWN),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 未知の取得情報をURLやattestationの存在で暗黙に既知へ補完しない
	if( value.state == IndexDescriptorState::UNKNOWN) {
		const auto &document = value.terms.textDocument ;	// 同じ配布物へ結ぶ規約の原申告です
		require( validText( value.reason) && value.payloadUrl.empty() && value.fileName.empty() &&
					value.format == IndexPayloadFormat::UNKNOWN &&
					value.expectedContentType.empty() && value.maximumBytes == 0U &&
					value.route.empty() && !value.attestation &&
					(!document || !document->htmlExtraction ||
					 document->htmlExtraction->profile != LINKED_STATIC_TERMS_PROFILE),
				IndexRecordsStatus::INVALID_EVIDENCE) ;
		return value ;
	}

	require( value.reason.empty() && validBasename( value.fileName) &&
				value.format != IndexPayloadFormat::UNKNOWN &&
				validContentType( value.expectedContentType) && value.maximumBytes > 0U &&
				value.maximumBytes <= PAYLOAD_LIMIT && !value.route.empty() &&
				value.attestation.has_value(),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 新kindだけにpublic model selectorを認め、元path/modelを完全一致させる
	if( value.anonymousCdn) {
		const auto canonical =
			// 元contextの唯一URL
			asusAnonymousCdnCanonicalUrl( *value.anonymousCdn) ;
		require( std::wstring( value.payloadUrl.begin(), value.payloadUrl.end()) == canonical &&
					value.route.size() == 1U && value.route.front().url == value.payloadUrl,
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	} else {
		requirePayloadUrl( value.payloadUrl) ;
		// 旧static routeに新query許可を漏らさない
		for( const auto &hop : value.route) {
			requirePayloadUrl( hop.url) ;
		}
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元recordとsource・manifestへの取得情報の結合だけを検査します
 * @param[in] record 原byteへ結合した読取り済みrecord。値を補完しません
 * @param[in] source 一意に解決した同indexのsource
 * @param[in] manifest 原byte認証済みmanifest。確認時刻を更新しません
 * @note Size上限超過の元申告recordは保持します。後段の容量保留とgrant判断は別です
 */
//------------------------------------------------------------------------------
void validateBinding( const IndexDistributionRecord &record, const IndexRecordSource &source,
					 const IndexManifestData &manifest)
{
	// v1の不在やUNKNOWNの元理由だけを保持し、取得能力へ昇格しない
	if( !record.acquisitionDescriptor ||
	   record.acquisitionDescriptor->state == IndexDescriptorState::UNKNOWN) {
		return ;
	}

	const auto &value		= *record.acquisitionDescriptor ;	// 固定原recordに結合した申告
	const auto &attestation = *value.attestation ;				// 構造検査が要求した元確認
	// 新resolverは同公式originと既知の元payload identityに限定する
	if( value.anonymousCdn) {
		require( sameOrigin( source.officialOrigin, "https://www.asus.com") &&
					record.packageEvidence.size.value.has_value() &&
					record.packageEvidence.calculatedHash.sha256.has_value() &&
					value.resourceContent.has_value(),
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	}

	// 新content計画を元recordの実outer identityと一INFへ完全結合する
	if( value.resourceContent) {
		const auto &plan = *value.resourceContent ;	// 元recordの閉じた選択
		std::string rootHash ;						// 既に小文字ASCII hexと検査した原hash
		// 暗黙narrowingせず検査済みhexだけをbyteへ写す
		for( const auto character : plan.rootSha256) {
			rootHash.push_back( static_cast<char>( character)) ;
		}

		require( record.packageEvidence.size.value == plan.rootBytes &&
					record.packageEvidence.calculatedHash.sha256.has_value() &&
					*record.packageEvidence.calculatedHash.sha256 ==
						decodeHash( rootHash, IndexRecordsStatus::INVALID_EVIDENCE) &&
					record.publishedIdentityEvidence.nestedArchiveIdentity.empty() &&
					std::wstring( record.publishedIdentityEvidence.infIdentity.begin(),
								 record.publishedIdentityEvidence.infIdentity.end()) ==
						plan.selectedInf,
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	}

	// 手動review原byteと自動HTTP本文を同じ観測種別へ混ぜません
	require( attestation.manualReview ==
				(source.officialEvidence.kind == IndexOfficialEvidenceKind::OFFICIAL_LINK_REVIEW),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 手動確認は元記録へ結合し、別reviewのhashをpage本文hashとして借用しません
	if( attestation.manualReview) {
		require( source.officialEvidence.evidenceSha256 == attestation.authorityEvidenceSha256 &&
					attestation.authorityEvidenceUrl == source.distributionPage &&
					!value.route.empty() &&
					value.route.front().evidenceSha256 == source.officialEvidence.evidenceSha256,
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	}

	require( attestation.checkedAtUtc <= manifest.publishedAtUtc &&
				manifest.publishedAtUtc < attestation.validUntilUtc &&
				attestation.validUntilUtc - attestation.checkedAtUtc <=
					INDEX_ACQUISITION_MAX_VALIDITY,
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 既知の取得方式と形式が矛盾する申告だけを拒否し、UNKNOWN方式を補わない
	if( record.acquisition.value) {
		const bool archive = value.format == IndexPayloadFormat::ZIP ||
							 // 元形式の分類
							 value.format == IndexPayloadFormat::CABINET ||
							 value.format == IndexPayloadFormat::SEVEN_ZIP_SFX ||
							 value.format == IndexPayloadFormat::PE_RESOURCE_CONTAINER ||
							 value.format == IndexPayloadFormat::WIX_BURN_V3 ;
		require( (*record.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE) ==
					archive,
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	}

	require( source.officialEvidence.state == IndexEvidenceState::PUBLISHED &&
				!source.officialOrigin.empty() && value.route.front().url == value.payloadUrl &&
				value.route.front().evidenceUrl == source.distributionPage &&
				(value.route.front().kind == IndexRouteKind::OFFICIAL_PAYLOAD_LINK ||
				 value.route.front().kind == IndexRouteKind::OFFICIAL_CDN_LINK),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	// HTMLの原page provenanceと監視側関連根拠を同じ配布recordへ完全結合します
	if( value.terms.textDocument && value.terms.textDocument->htmlExtraction) {
		const auto &document = *value.terms.textDocument ;						// 原page観測です
		const auto &html	 = *document.htmlExtraction ;						// 選択文書と公開関連根拠です
		const bool	linked	 = html.profile == LINKED_STATIC_TERMS_PROFILE ;	// 算出版の二段形式です
		require( value.terms.state == IndexTermsState::ACCEPTANCE_REQUIRED &&
					value.terms.revisionKind == (linked
													 ? IndexTermsRevisionKind::COMPUTED_UTF8_SHA256
													 : IndexTermsRevisionKind::VENDOR_LITERAL) &&
					value.terms.evidenceUrl == document.url &&
					value.terms.evidenceSha256 == document.sha256 &&
					sameOrigin( html.bindingEvidenceUrl, source.officialOrigin),
				IndexRecordsStatus::INVALID_EVIDENCE) ;
		// 独立文書だけは公式配布pageの実リンク根拠へ別に結び、規約hashを配布pageへ偽装しません
		if( linked || html.profile == "STATIC_HTML_SECTION_V1") {
			require( html.bindingEvidenceUrl == source.distributionPage &&
						source.officialEvidence.evidenceSha256 == html.bindingEvidenceSha256 &&
						value.route.front().evidenceSha256 == html.bindingEvidenceSha256,
					IndexRecordsStatus::INVALID_EVIDENCE) ;
		} else {
			require( document.url == source.distributionPage &&
						source.officialEvidence.evidenceSha256 == document.sha256 &&
						value.route.front().evidenceSha256 == document.sha256,
					IndexRecordsStatus::INVALID_EVIDENCE) ;
		}
	}

	require( sameOrigin( value.payloadUrl, source.officialOrigin) ||
				value.route.front().kind == IndexRouteKind::OFFICIAL_CDN_LINK,
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 規約メンバーの根拠は内容検査済みの同じ原ZIPと公式配布ページだけに結びます
	if( value.terms.archiveNotice) {
		const auto &notice	   = *value.terms.archiveNotice ;					// 私有欄に置ける同じ規約証拠です
		const auto &calculated = record.packageEvidence.calculatedHash ;		// 元ZIPの実測根拠です
		const auto &html	   = *value.terms.textDocument->htmlExtraction ;	// 同じ原配布ページです
		require( record.inspectionStage == IndexInspectionStage::CONTENT_INSPECTED &&
					record.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE &&
					source.officialEvidence.kind == IndexOfficialEvidenceKind::OFFICIAL_PAGE &&
					source.officialEvidence.evidenceUrl == source.distributionPage &&
					record.packageEvidence.size.value == notice.archiveSizeBytes &&
					notice.archiveSizeBytes <= value.maximumBytes &&
					calculated.sha256 == notice.archiveSha256 &&
					calculated.evidenceSha256 == notice.archiveSha256 &&
					calculated.evidenceUrl == value.payloadUrl &&
					attestation.authorityMethod ==
						IndexAuthorityMethod::OFFICIAL_SITE_CONTROL_AND_LINK &&
					attestation.authorityEvidenceUrl == html.bindingEvidenceUrl &&
					attestation.authorityEvidenceSha256 == html.bindingEvidenceSha256,
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	}

	std::set<std::string> urls ;				// 完全原URLの重複・循環拒否集合
	bool				  cdnEntered{} ;		// 公式originへ戻る逆向きrouteを許可しない
	std::size_t			  originRedirects{} ;	// CDN移行前の同origin redirectは最大2回
	// 全6hop以内で元順序・出典と一方向CDN移行を確認する
	for( std::size_t index = 0U; index < value.route.size(); ++index) {
		const auto &hop = value.route[index] ;	// 同recordの原hop
		require( urls.insert( hop.url).second, IndexRecordsStatus::INVALID_EVIDENCE) ;
		const bool official =
			// Prefixを使わないorigin判定
			sameOrigin( hop.url, source.officialOrigin) ;
		require( !cdnEntered || !official, IndexRecordsStatus::INVALID_EVIDENCE) ;
		cdnEntered = cdnEntered || !official ;
		// 二番目以降は直前の原URLを根拠としたHTTP redirectだけを許可する
		if( index > 0U) {
			require( hop.kind == IndexRouteKind::HTTP_REDIRECT &&
						hop.evidenceUrl == value.route[index - 1U].url,
					IndexRecordsStatus::INVALID_EVIDENCE) ;
			// 移行前の同originだけを有限なredirect数として数える
			if( !cdnEntered) {
				++originRedirects ;
				require( originRedirects <= 2U, IndexRecordsStatus::INVALID_EVIDENCE) ;
			}
		}
	}
}

} // namespace drivercrate::signed_index_acquisition
