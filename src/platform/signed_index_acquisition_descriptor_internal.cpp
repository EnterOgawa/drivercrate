//------------------------------------------------------------------------------
/**
 * @file signed_index_acquisition_descriptor_internal.cpp
 * @brief 全メーカー共通の取得descriptor元申告を有限な文法とbindingで検査します。
 * @version 01.01.04
 * @date 2026/10/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  strict descriptorと用途URL・出典・時間の検査を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/14  共通HTML許諾の原page・原文書・全文と配布recordを結合。
 * Ver.01.01.01 Shunji Ogawa  2026/10/14  規約文書の共通必須field欠損をURL値検査前に構造拒否。
 * Ver.01.01.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.01.03 Shunji Ogawa  2026/10/23  個別期限を維持しmanifestとの順序制約だけを除去。
 * Ver.01.01.04 Shunji Ogawa  2026/10/24  新規配布recordの有限8日上限へ統一。
 * </pre>
 *
 * @note 索引発行者の申告を読むだけで、公式性・vendor署名・実byte・端末適合を実証しません。
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

#include "platform/official_http_client.h"

namespace drivercrate::signed_index_acquisition {
namespace {

// Descriptorの元textと不足理由の独立上限。
constexpr std::size_t	TEXT_LIMIT = 512U ;
// 原URLを再構成せず読む固定byte上限。
constexpr std::size_t	URL_LIMIT = 2048U ;
// 初回の一payload取得profile。全製品の対応上限ではありません。
constexpr std::uint64_t PAYLOAD_LIMIT = 128U * 1024U * 1024U ;
// UTF-8規約本文の正のexact byte上限。
constexpr std::uint64_t TERMS_LIMIT = 256U * 1024U ;
/**
 * @brief この層とrecord層で元診断を共有します。
 */
using Failure = signed_index_json::Failure<IndexRecordsStatus> ;
using signed_index_json::require ;
using signed_index_json::decodeHash ;

/** @brief 非空の公開textを制御byteなしで確認します。
 * @param[in] value UTF-8検査済みの所有値からの借用。
 * @return 512byte以内の非空公開textの場合true。
 */
[[nodiscard]] bool validText( const std::string_view value)
{
	return !value.empty() && value.size() <= TEXT_LIMIT &&
		   std::ranges::all_of( value, []( const unsigned char character) {
			   // 表示を変えるASCII制御byteだけを拒否し、元UTF-8を維持する。
			   return character >= 0x20U && character != 0x7fU ;
		   }) ;
}

/** @brief ASCII英数字の一byteを確認します。
 * @param[in] value 一byteの原ASCII。
 * @return 英数字の場合true。
 */
[[nodiscard]] bool alphaNumeric( const char value)
{
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
		   (value >= '0' && value <= '9') ;
}

/** @brief Percent tripletの一桁だけを整数へ戻します。
 * @param[in] value 一byteの原hex。
 * @return 0～15。不正は-1です。
 */
[[nodiscard]] int hexDigit( const char value)
{
	// Decimal域は同じ整数へ戻す。
	if( value >= '0' && value <= '9') {
		return value - '0' ;
	}

	// 小文字hexを標準URI値へ戻す。
	if( value >= 'a' && value <= 'f') {
		return value - 'a' + 10 ;
	}

	// 大文字hexも原byteを書き換えず許可する。
	if( value >= 'A' && value <= 'F') {
		return value - 'A' + 10 ;
	}

	return -1 ;
}

/** @brief CollectorのPAGE数値selector文法だけを確認します。
 * @param[in] query Question markを含まない原query。
 * @return 一つの固定keyと1～20桁の数値だけの場合true。
 */
[[nodiscard]] bool validPageQuery( const std::string_view query)
{
	const std::size_t	   equal = query.find( '=') ;			// 固定keyと公開数値の境界。
	const std::string_view key	 = query.substr( 0U, equal) ;	// 値を書き換えない原key。
	constexpr std::array<std::string_view, 5U> KEYS{"id", "drid", "download_id", "file_id",
													"product_id"} ;	// PAGEの閉じた許可集合。
	// Tokenや複合queryを数値selectorの許可へ混入させない。
	if( equal == std::string_view::npos || std::ranges::find( KEYS, key) == KEYS.end()) {
		return false ;
	}

	const std::string_view number = query.substr( equal + 1U) ;	// 元公開数値。
	return !number.empty() && number.size() <= 20U &&
		   std::ranges::all_of( number,
							   []( const char value) { return value >= '0' && value <= '9' ; }) ;
}

/** @brief 検査済みURLからDNS hostを値を変えず借用します。
 * @param[in] value requireUrlを成功した原HTTPS URL。
 * @return Port443を除いた元DNS host。
 */
[[nodiscard]] std::string_view hostOf( const std::string_view value)
{
	const std::size_t	   end		 = value.find_first_of( "/?", 8U) ;	// Authority終端。
	const std::string_view authority = value.substr(
		8U, end == std::string_view::npos ? value.size() - 8U : end - 8U) ;	// 原authority。
	return authority.substr( 0U, authority.find( ':')) ;
}

/** @brief 同じHTTPS scheme・DNS host・443 portを比較します。
 * @param[in] left 構文検査済みURL。
 * @param[in] right 構文検査済みURL。
 * @return Originが同じ場合true。URL prefixは使用しません。
 */
[[nodiscard]] bool sameOrigin( const std::string_view left, const std::string_view right)
{
	return hostOf( left) == hostOf( right) ;
}

/** @brief Windowsの予約名やpathを含まない有限basenameを確認します。
 * @param[in] value 原basename。保存pathへ変換しません。
 * @return ASCIIの安全な一componentの場合true。
 */
[[nodiscard]] bool validBasename( const std::string_view value)
{
	// 有限ASCIIと先頭英数字を要求し、relative traversalを除く。
	if( value.empty() || value.size() > 180U || !alphaNumeric( value.front()) ||
	   value.back() == '.' || value.back() == ' ' || value.find( "..") != std::string_view::npos) {
		return false ;
	}

	unsigned depth{} ;	// 対応する一段の括弧だけを許可する。
	// 原basenameの全byteを確認し、path delimiterや予約文字を拒否する。
	for( const char character : value) {
		// 開括弧は一段だけ許可する。
		if( character == '(') {
			// 入れ子の括弧は初回profileで未対応として拒否する。
			if( depth != 0U) {
				return false ;
			}

			depth = 1U ;
		}
		// 閉括弧は対応する開括弧だけを閉じる。
		else if( character == ')') {
			// 対応しない閉括弧は安全basenameにしない。
			if( depth != 1U) {
				return false ;
			}

			depth = 0U ;
		}
		// 英数字と内部space・._-以外をpathや特殊名として拒否する。
		else if( !alphaNumeric( character) && character != '.' && character != '_' &&
				character != '-' && character != ' ') {
			return false ;
		}
	}

	std::string stem{value.substr( 0U, value.find( '.'))} ;	// 最初のdot以前の予約名照合値。
	// Windowsが予約名照合で無視する末尾spaceだけを比較用に除く。
	while( !stem.empty() && stem.back() == ' ') {
		stem.pop_back() ;
	}

	// 予約名照合だけをASCII uppercaseへ変換し、公開basenameは変更しない。
	for( char &character : stem) {
		// ASCII小文字だけを同じ予約名へ照合する。
		if( character >= 'a' && character <= 'z') {
			character = static_cast<char>( character - 'a' + 'A') ;
		}
	}

	const bool numbered = stem.size() == 4U &&
						  (stem.starts_with( "COM") || stem.starts_with( "LPT")) &&
						  // Windows予約device名の有限集合。
						  stem.back() >= '1' && stem.back() <= '9' ;
	return depth == 0U && stem != "CON" && stem != "PRN" && stem != "AUX" && stem != "NUL" &&
		   !numbered ;
}

/** @brief Payload Content-Typeの単一ASCII media type申告を確認します。
 * @param[in] value 原media type。実応答の検査ではありません。
 * @return 有限なtype/subtypeで制御byteやparameterがない場合true。
 */
[[nodiscard]] bool validContentType( const std::string_view value)
{
	const std::size_t slash = value.find( '/') ;	// Typeとsubtypeの唯一の区切り。
	return !value.empty() && value.size() <= 128U && slash != std::string_view::npos &&
		   slash > 0U && slash + 1U < value.size() &&
		   value.find( '/', slash + 1U) == std::string_view::npos &&
		   std::ranges::all_of( value, []( const char character) {
			   // 元media typeをlowercase tokenとslashに限定する。
			   return (character >= 'a' && character <= 'z') ||
					  (character >= '0' && character <= '9') || character == '/' ||
					  character == '.' || character == '-' || character == '+' || character == '_' ;
		   }) ;
}

/** @brief 固定文字列集合を元申告enumへ完全一致で解決します。
 * @tparam Value 申告enum。
 * @tparam Count 固定集合の件数。
 * @param[in] text 原申告。
 * @param[in] choices 閉じた許可集合。
 * @return 一致したenum。不明literalは拒否します。
 */
template <class Value, std::size_t Count>
[[nodiscard]] Value choice( const std::string_view										text,
						   const std::array<std::pair<std::string_view, Value>, Count> &choices)
{
	const auto found = std::ranges::find_if( choices, [&]( const auto &item) {
		// 借用textと固定集合だけを同期参照する。
		return item.first == text ;
	}) ; // 元申告の完全一致位置。
	require( found != choices.end(), IndexRecordsStatus::INVALID_EVIDENCE) ;
	return found->second ;
}

/** @brief KNOWN／UNKNOWNの閉じた元申告を読みます。
 * @param[in] value 原state。
 * @return 型付きstate。不明literalは拒否します。
 */
[[nodiscard]] IndexDescriptorState descriptorState( const std::string_view value)
{
	constexpr std::array<std::pair<std::string_view, IndexDescriptorState>, 2U> CHOICES{
		{{"KNOWN", IndexDescriptorState::KNOWN},
		 {"UNKNOWN", IndexDescriptorState::UNKNOWN}}} ;	// 元state。
	return choice( value, CHOICES) ;
}

/** @brief Route hopの四必須fieldを読みます。
 * @param[in,out] reader 有限record reader。
 * @return 型付き原URLと出典の元申告。
 */
[[nodiscard]] IndexAcquisitionRouteHop readHop( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 4U> FIELDS{"url", "kind", "evidenceUrl",
													  "evidenceSha256"} ;	// 全必須field。
	std::array<std::string, 4U>				   fields ;						// 順序によらない原値。
	// Readerと所有配列を同期借用して全fieldを要求型で読む。
	reader.object( FIELDS, [&]( const std::size_t index) { fields[index] = reader.text( URL_LIMIT) ; }) ;
	constexpr std::array<std::pair<std::string_view, IndexRouteKind>, 3U> KINDS{
		{{"OFFICIAL_PAYLOAD_LINK", IndexRouteKind::OFFICIAL_PAYLOAD_LINK},
		 {"OFFICIAL_CDN_LINK", IndexRouteKind::OFFICIAL_CDN_LINK},
		 {"HTTP_REDIRECT", IndexRouteKind::HTTP_REDIRECT}}} ;	// 閉じた導線種別。
	requireUrl( fields[0], false) ;
	requireUrl( fields[2], true) ;
	return {std::move( fields[0]), choice( fields[1], KINDS), std::move( fields[2]),
			decodeHash( fields[3], IndexRecordsStatus::INVALID_EVIDENCE)} ;
}

/** @brief ASCII小文字の公開tag/属性名を確認します。
 * @param[in] value 原名です。
 * @return 1～64byteの閉じた名前の場合trueです。
 */
[[nodiscard]] bool validHtmlName( const std::string_view value)
{
	return !value.empty() && value.size() <= 64U && value.front() >= 'a' && value.front() <= 'z' &&
		   std::ranges::all_of( value, []( const char character) {
			   // ScriptやCSS selector式を名前へ混入させません。
			   return (character >= 'a' && character <= 'z') ||
					  (character >= '0' && character <= '9') || character == '-' ||
					  character == '_' ;
		   }) ;
}

/** @brief 一つの実tagと実属性へ完全一致する元selectorを読みます。
 * @param[in,out] reader 有限readerです。
 * @return 三つの必須fieldを検査した元selectorです。
 */
[[nodiscard]] IndexHtmlTermsSelector readHtmlSelector( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 3U> FIELDS{"tag", "attribute",
													  "value"} ;	// 全必須fieldです。
	std::array<std::string, 3U>				   fields ;				// 要求型で読み終えた元値です。
	// 元集合を順序非依存で同期消費します。
	reader.object( FIELDS, [&]( const std::size_t field) { fields[field] = reader.text( 128U) ; }) ;
	require(
		validHtmlName( fields[0]) && validHtmlName( fields[1]) && validText( fields[2]) &&
			std::ranges::all_of( fields[2], []( const unsigned char value) { return value < 0x7fU ; }),
		IndexRecordsStatus::INVALID_EVIDENCE) ;
	return {std::move( fields[0]), std::move( fields[1]), std::move( fields[2])} ;
}

/** @brief 原選択文書と抽出全文の独立digestを持つHTML申告を読みます。
 * @param[in,out] reader 有限readerです。
 * @return 共通profileの全11fieldです。本文や同意は生成しません。
 */
[[nodiscard]] IndexHtmlTermsExtraction readHtmlExtraction( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 11U> FIELDS{
		"profile",			"selector",			  "containerSelector",	  "linkSelector",
		"payloadAttribute", "documentSha256",	  "documentSizeBytes",	  "textSha256",
		"textSizeBytes",	"bindingEvidenceUrl", "bindingEvidenceSha256"} ;	// 全必須fieldです。
	IndexHtmlTermsExtraction value ;											// 全成功前には公開しない元値です。
	// 全入れ子を要求型だけで読み、未知fieldや重複を拒否します。
	reader.object( FIELDS, [&]( const std::size_t field) {
		// 原selectorはCSS式ではなく固定三fieldだけです。
		if( field >= 1U && field <= 3U) {
			const std::array<IndexHtmlTermsSelector *, 3U> selectors{
				&value.selector, &value.containerSelector, &value.linkSelector} ;	// 元出力先です。
			*selectors[field - 1U] = readHtmlSelector( reader) ;
		} else {
			// Exact sizeだけを整数型で読みます。
			if( field == 6U || field == 8U) {
				(field == 6U ? value.documentSizeBytes : value.textSizeBytes) = reader.number() ;
			} else {
				const auto text = reader.text( field == 9U ? URL_LIMIT : TEXT_LIMIT) ;	// 原textです。
				// 元field番号へ要求型だけを結合します。
				switch( field) {
					case 0U:
						// 閉じた共通profileを保持します。
						value.profile = text ;
						// 閉じたprofileです。
						break ;

					case 4U:
						// 配布linkの実payload属性名を保持します。
						value.payloadAttribute = text ;
						// 実payload属性名です。
						break ;

					case 5U:
						// 選択原文書の完全hashを読みます。
						value.documentSha256 =
							decodeHash( text, IndexRecordsStatus::INVALID_EVIDENCE) ;
						// 原文書です。
						break ;

					case 7U:
						// 抽出全文の完全hashを読みます。
						value.textSha256 = decodeHash( text, IndexRecordsStatus::INVALID_EVIDENCE) ;
						// 全文です。
						break ;

					case 9U:
						// 監視側許諾導線の原根拠URLを保持します。
						value.bindingEvidenceUrl = text ;
						// 監視側関連根拠です。
						break ;

					case 10U:
						// 同原根拠byteのhashを読みます。
						value.bindingEvidenceSha256 =
							decodeHash( text, IndexRecordsStatus::INVALID_EVIDENCE) ;
						// 原根拠です。
						break ;

					default:
						// 不明番号です。
						throw Failure{IndexRecordsStatus::INVALID_EVIDENCE} ;
				}
			}
		}
	}) ;
	require( value.profile == "TEXTAREA_HTML_DOCUMENT_V1" && value.selector.tag == "textarea" &&
				validHtmlName( value.payloadAttribute) && value.documentSizeBytes > 0U &&
				value.documentSizeBytes <= TERMS_LIMIT && value.textSizeBytes > 0U &&
				value.textSizeBytes <= TERMS_LIMIT &&
				value.selector.tag != value.containerSelector.tag &&
				value.linkSelector.tag != value.selector.tag,
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	requireUrl( value.bindingEvidenceUrl, false) ;
	return value ;
}

/** @brief 原plain全文または明示HTMLの取得申告を読みます。
 * @param[in,out] reader 有限reader。
 * @return 最大256KiBのexact sizeと原hash。本文は取得しません。
 */
[[nodiscard]] IndexTermsTextDocument readDocument( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 5U> FIELDS{
		"url", "sha256", "sizeBytes", "contentType",
		"htmlExtraction"} ;			// Plain4fieldとHTML5fieldの閉じた集合です。
	IndexTermsTextDocument value ;	// 全成功前には公開しない原申告。
	std::string			   hash ;	// 原digestの文字列。
	// 所有出力だけを同期借用し、sizeだけを整数型で読む。
	const auto presence = reader.objectWithPresence( FIELDS, [&]( const std::size_t field) {
		// HTMLだけに存在する必須objectをnullへ補完しません。
		if( field == 4U) {
			value.htmlExtraction = readHtmlExtraction( reader) ;
			return ;
		}

		// Exact sizeは文字列や推測値として受理しない。
		if( field == 2U) {
			value.sizeBytes = reader.number() ;
		} else {
			// それぞれの元textを固定出力へ写す。
			const std::array<std::string *, 4U> targets{&value.url, &hash, nullptr,
														&value.contentType} ;	// 非owning出力先。
			*targets[field] = reader.text( field == 0U ? URL_LIMIT : TEXT_LIMIT) ;
		}
	}) ;
	// 共通4fieldの欠損を空のURL値へ読み替えず、従来の構造拒否を維持します。
	require( (presence & 15U) == 15U, IndexRecordsStatus::INVALID_RECORD) ;
	requireUrl( value.url, false) ;
	const bool html = value.contentType == "text/html; charset=utf-8" ;	// 明示別契約です。
	require( presence == (html ? 31U : 15U) && value.sizeBytes > 0U &&
				value.sizeBytes <= TERMS_LIMIT &&
				(html || value.contentType == "text/plain; charset=utf-8") &&
				(value.htmlExtraction.has_value() == html),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	value.sha256 = decodeHash( hash, IndexRecordsStatus::INVALID_EVIDENCE) ;
	return value ;
}

/** @brief 規約状態を本文取得や同意へ昇格せず読みます。
 * @param[in,out] reader 有限reader。
 * @return 元規約申告と不足理由。
 */
[[nodiscard]] IndexAcquisitionTerms readTerms( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 7U> FIELDS{
		"state",		"reason",	"evidenceUrl", "evidenceSha256",
		"revisionKind", "revision", "textDocument"} ;	// 全必須field。
	std::array<std::string, 6U> fields ;				// Document以外の元text。
	IndexAcquisitionTerms		value ;					// 全成功前には公開しない値。
	// 原field集合を順序非依存で同期消費する。
	reader.object( FIELDS, [&]( const std::size_t field) {
		// 明示nullと固定documentだけを区別する。
		if( field == 6U) {
			// 本文情報の欠損を空objectで補わない。
			if( !reader.nullValue()) {
				value.textDocument = readDocument( reader) ;
			}
		} else {
			fields[field] = reader.text( field == 2U ? URL_LIMIT : TEXT_LIMIT) ;
		}
	}) ;
	constexpr std::array<std::pair<std::string_view, IndexTermsState>, 3U> STATES{
		{{"UNKNOWN", IndexTermsState::UNKNOWN},
		 {"CONFIRMED_NO_CONSENT", IndexTermsState::CONFIRMED_NO_CONSENT},
		 {"ACCEPTANCE_REQUIRED",
		  IndexTermsState::ACCEPTANCE_REQUIRED}}} ;	// 同意結果ではない元state。
	constexpr std::array<std::pair<std::string_view, IndexTermsRevisionKind>, 3U> REVISIONS{
		{{"NONE", IndexTermsRevisionKind::NONE},
		 {"VENDOR_LITERAL", IndexTermsRevisionKind::VENDOR_LITERAL},
		 {"COMPUTED_UTF8_SHA256",
		  IndexTermsRevisionKind::COMPUTED_UTF8_SHA256}}} ;	// Revisionの由来。
	value.state		   = choice( fields[0], STATES) ;
	value.reason	   = std::move( fields[1]) ;
	value.evidenceUrl  = std::move( fields[2]) ;
	value.revisionKind = choice( fields[4], REVISIONS) ;
	value.revision	   = std::move( fields[5]) ;
	// 未確認の根拠とrevisionを架空補完せず非空理由だけを保持する。
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
	// 同意不要に本文やrevisionを付けて同意状態を混同しない。
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

	return value ;
}

/** @brief 一つの具体的条件をcommandやscriptなしで読みます。
 * @param[in,out] reader 有限reader。
 * @return 元条件と一出典へのbinding。
 */
[[nodiscard]] IndexAcquisitionPrerequisite readPrerequisite( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 4U> FIELDS{"kind", "description", "evidenceUrl",
													  "evidenceSha256"} ;	// 全必須field。
	std::array<std::string, 4U>				   fields ;						// 元公開条件の所有text。
	// 全fieldだけを要求型で同期消費する。
	reader.object( FIELDS, [&]( const std::size_t field) {
		fields[field] = reader.text( field == 2U ? URL_LIMIT : TEXT_LIMIT) ;
	}) ;
	constexpr std::array<std::pair<std::string_view, IndexPrerequisiteKind>, 3U> KINDS{
		{{"USER_CONFIRMATION", IndexPrerequisiteKind::USER_CONFIRMATION},
		 {"LOCAL_CHECK", IndexPrerequisiteKind::LOCAL_CHECK},
		 {"INSEPARABLE_FIRMWARE",
		  IndexPrerequisiteKind::INSEPARABLE_FIRMWARE}}} ;	// 未確認を同意で補わない条件。
	require( validText( fields[1]), IndexRecordsStatus::INVALID_EVIDENCE) ;
	requireUrl( fields[2], true) ;
	return {choice( fields[0], KINDS), std::move( fields[1]), std::move( fields[2]),
			decodeHash( fields[3], IndexRecordsStatus::INVALID_EVIDENCE)} ;
}

/** @brief 条件の有限集合か明示UNKNOWN理由を読みます。
 * @param[in,out] reader 有限reader。
 * @return 最大16件の申告集合または不足理由。
 */
[[nodiscard]] IndexAcquisitionPrerequisites readPrerequisites( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 3U> FIELDS{"state", "reason", "items"} ;	// 全必須field。
	IndexAcquisitionPrerequisites			   value ;								// 成功前には公開しない元集合。
	std::string								   state ;								// 原stateの閉じたliteral。
	// Stateと理由・有限配列をそれぞれの型で同期消費する。
	reader.object( FIELDS, [&]( const std::size_t field) {
		// 条件配列は空集合も明示として読取り、上限を維持する。
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

/** @brief 監視PCによる導線確認の元申告を読みます。
 * @param[in,out] reader 有限reader。
 * @return 固定kind・revisionと元UTC・証拠。製品trustやvendor検証実績ではありません。
 */
[[nodiscard]] IndexAcquisitionAttestation readAttestation( DescriptorReader &reader)
{
	constexpr std::array<std::string_view, 7U> FIELDS{"kind",
													  "policyRevision",
													  "checkedAtUtc",
													  "validUntilUtc",
													  "authorityMethod",
													  "authorityEvidenceUrl",
													  "authorityEvidenceSha256"} ;	// 全必須field。
	std::array<std::string, 7U>				   fields ;								// Revision以外の元text。
	IndexAcquisitionAttestation				   value ;								// 全検査前には公開しない元申告。
	// 原UTCと整数revisionを別型で同期消費する。
	reader.object( FIELDS, [&]( const std::size_t field) {
		// 監視PC policyの版は正確な整数で固定する。
		if( field == 1U) {
			value.policyRevision = reader.number() ;
		} else {
			fields[field] = reader.text( field == 5U ? URL_LIMIT : TEXT_LIMIT) ;
		}
	}) ;
	constexpr std::array<std::pair<std::string_view, IndexAuthorityMethod>, 2U> METHODS{
		{{"OFFICIAL_SITE_CONTROL_AND_LINK", IndexAuthorityMethod::OFFICIAL_SITE_CONTROL_AND_LINK},
		 {"VENDOR_CATALOG_SIGNATURE_VERIFIED",
		  IndexAuthorityMethod::VENDOR_CATALOG_SIGNATURE_VERIFIED}}} ;	// 端末実績ではない元method。
	require( fields[0] == "COLLECTOR_VERIFIED_OFFICIAL_ROUTE" && value.policyRevision == 1U,
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	value.checkedAtUtc	  = signed_index_json::utc( fields[2], IndexRecordsStatus::INVALID_EVIDENCE) ;
	value.validUntilUtc	  = signed_index_json::utc( fields[3], IndexRecordsStatus::INVALID_EVIDENCE) ;
	value.authorityMethod = choice( fields[4], METHODS) ;
	requireUrl( fields[5], true) ;
	value.authorityEvidenceUrl	  = std::move( fields[5]) ;
	value.authorityEvidenceSha256 = decodeHash( fields[6], IndexRecordsStatus::INVALID_EVIDENCE) ;
	return value ;
}

} // namespace

/** @see signed_index_acquisition_descriptor_internal.h */
void requireUrl( const std::string_view value, const bool pageQuery)
{
	require( !value.empty() && value.size() <= URL_LIMIT && value.starts_with( "https://") &&
				value.find_first_of( "#@\\") == std::string_view::npos &&
				std::ranges::all_of( value,
									[]( const unsigned char character) {
										// 静的URLのASCII原byteを維持し、空白や制御byteを除く。
										return character > 0x20U && character < 0x7fU ;
									}),
			IndexRecordsStatus::INVALID_URL) ;
	const std::size_t query = value.find( '?') ;	// 原queryの存在位置。
	// PAGEの閉じた数値selectorだけを認め、payloadやrouteへ許可を拡張しない。
	if( query != std::string_view::npos) {
		require( pageQuery && validPageQuery( value.substr( query + 1U)),
				IndexRecordsStatus::INVALID_URL) ;
	}

	const std::size_t	   end		 = value.find_first_of( "/?", 8U) ;	// 原authorityの終端。
	const std::string_view authority = value.substr(
		8U, end == std::string_view::npos ? value.size() - 8U : end - 8U) ;	// 原authority。
	const std::size_t	   colon = authority.find( ':') ;					// 明示portの位置。
	const std::string_view host	 = hostOf( value) ;							// 元DNS名。
	require( colon == std::string_view::npos || authority.substr( colon) == ":443",
			IndexRecordsStatus::INVALID_URL) ;
	require( !host.empty() && host.size() <= 253U && host.find( '.') != std::string_view::npos &&
				host.back() >= 'a' && host.back() <= 'z' && !host.starts_with( "localhost.") &&
				!host.ends_with( ".local") && !host.ends_with( ".internal") &&
				!host.ends_with( ".localhost") && !host.ends_with( ".lan"),
			IndexRecordsStatus::INVALID_URL) ;
	std::size_t start{} ;	// DNS labelごとの原開始位置。
	// 原DNS名の全labelを確認し、空label・先末尾hyphen・IP literalを拒否する。
	while( start < host.size()) {
		const std::size_t	   dot	 = host.find( '.', start) ;	// 次labelへの境界。
		const std::string_view label = host.substr(
			start, dot == std::string_view::npos ? host.size() - start : dot - start) ;	// 原label。
		require( !label.empty() && label.size() <= 63U && alphaNumeric( label.front()) &&
					alphaNumeric( label.back()) &&
					std::ranges::all_of( label,
										[]( const char character) {
											// 収集側と同じ小文字DNS文法を保持する。
											return (character >= 'a' && character <= 'z') ||
												   (character >= '0' && character <= '9') ||
												   character == '-' ;
										}),
				IndexRecordsStatus::INVALID_URL) ;
		// 最後のlabelを確認したら有限走査を終える。
		if( dot == std::string_view::npos) {
			break ;
		}

		start = dot + 1U ;
	}

	std::string decoded{value} ;	// Encoded control検査だけの一時copy。URLは書き換えない。
	// Collectorと同じ三層上限でpercent controlを検査し、反復decodeを通信値にしない。
	for( unsigned pass = 0U; pass < 3U; ++pass) {
		std::string next ;	// この一層だけの比較値。
		// 元copyの全byteを一度ずつ確認し、malformed escape・制御・backslashを拒否する。
		for( std::size_t index = 0U; index < decoded.size(); ++index) {
			unsigned char character = static_cast<unsigned char>( decoded[index]) ;	// 次の検査byte。
			// 正しいtripletだけを一層解除する。
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

	const std::wstring wide{value.begin(), value.end()} ;				// 共通URL parserへ渡す原ASCIIのcopy。
	const std::wstring wideHost{host.begin(), host.end()} ;				// 同じ原hostだけの構文照合値。
	const std::array<std::wstring_view, 1U> hosts{wideHost} ;			// Trust登録やnetwork policyではない。
	const NativeError error = validateOfficialHttpsUrl( wide, hosts) ;	// 共通parserの元診断。
	// 確保失敗をURLの不正へ読み替えない。
	if( error == static_cast<NativeError>( E_OUTOFMEMORY)) {
		throw Failure{IndexRecordsStatus::OUT_OF_MEMORY, error} ;
	}

	require( error == 0, IndexRecordsStatus::INVALID_URL) ;
}

/** @see signed_index_acquisition_descriptor_internal.h */
IndexAcquisitionDescriptor readDescriptor( DescriptorReader &reader, const TextValueReader readText)
{
	constexpr std::array<std::string_view, 13U> FIELDS{"schema",
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
													   "attestation"} ;	// 全13必須field。
	std::array<std::string, 7U>					fields ;				// 先頭の原text申告。
	IndexAcquisitionDescriptor					value ;					// 全成功前には公開しない値。
	require( readText != nullptr, IndexRecordsStatus::INTERNAL_FAILURE) ;
	// Field順によらず要求型だけを同期消費する。
	reader.object( FIELDS, [&]( const std::size_t field) {
		// 先頭七つは元textの上限を別々に保つ。
		if( field < 7U) {
			fields[field] = reader.text( field == 3U ? URL_LIMIT : TEXT_LIMIT) ;
		} else {
			// 残りの固定fieldを型付きの有限読取りへ接続する。
			switch( field) {
				// 一payloadの有限byte上限。
				case 7U:
					value.maximumBytes = reader.number() ;
					break ;

				// 最大6hop、redirectは後のbindingで結合する。
				case 8U:
					reader.array(
						6U, [&] { value.route.push_back( readHop( reader)) ; },
						IndexRecordsStatus::COUNT_LIMIT) ;
					break ;

				// 規約の申告であり本文や同意ではない。
				case 9U:
					value.terms = readTerms( reader) ;
					break ;

				// 明示空集合とUNKNOWN理由を分ける。
				case 10U:
					value.prerequisites = readPrerequisites( reader) ;
					break ;

				// Known textの既存文法だけへ委譲する。
				case 11U:
					value.publisher = readText( reader) ;
					break ;

				// NullはUNKNOWNだけで許可し、欠損fieldと区別する。
				case 12U:
					// 元attestationが存在する場合だけ全fieldを読む。
					if( !reader.nullValue()) {
						value.attestation = readAttestation( reader) ;
					}

					break ;

				// 未登録番号を成功へ補完しない。
				default:
					throw Failure{IndexRecordsStatus::INVALID_RECORD} ;
			}
		}
	}) ;
	constexpr std::array<std::pair<std::string_view, IndexPayloadFormat>, 5U> FORMATS{
		{{"UNKNOWN", IndexPayloadFormat::UNKNOWN},
		 {"ZIP", IndexPayloadFormat::ZIP},
		 {"CABINET", IndexPayloadFormat::CABINET},
		 {"WINDOWS_EXE", IndexPayloadFormat::WINDOWS_EXE},
		 {"WINDOWS_MSI", IndexPayloadFormat::WINDOWS_MSI}}} ;	// 未知は自動補完しない形式。
	require( fields[0] == "driver-index-acquisition-v1", IndexRecordsStatus::INVALID_EVIDENCE) ;
	value.state				  = descriptorState( fields[1]) ;
	value.reason			  = std::move( fields[2]) ;
	value.payloadUrl		  = std::move( fields[3]) ;
	value.fileName			  = std::move( fields[4]) ;
	value.format			  = choice( fields[5], FORMATS) ;
	value.expectedContentType = std::move( fields[6]) ;
	// 未知の取得情報をURLやattestationの存在で暗黙に既知へ補完しない。
	if( value.state == IndexDescriptorState::UNKNOWN) {
		require( validText( value.reason) && value.payloadUrl.empty() && value.fileName.empty() &&
					value.format == IndexPayloadFormat::UNKNOWN &&
					value.expectedContentType.empty() && value.maximumBytes == 0U &&
					value.route.empty() && !value.attestation,
				IndexRecordsStatus::INVALID_EVIDENCE) ;
		return value ;
	}

	require( value.reason.empty() && validBasename( value.fileName) &&
				value.format != IndexPayloadFormat::UNKNOWN &&
				validContentType( value.expectedContentType) && value.maximumBytes > 0U &&
				value.maximumBytes <= PAYLOAD_LIMIT && !value.route.empty() &&
				value.attestation.has_value(),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	requireUrl( value.payloadUrl, false) ;
	return value ;
}

/** @see signed_index_acquisition_descriptor_internal.h */
void validateBinding( const IndexDistributionRecord &record, const IndexRecordSource &source,
					 const IndexManifestData &manifest)
{
	// v1の不在やUNKNOWNの元理由だけを保持し、取得能力へ昇格しない。
	if( !record.acquisitionDescriptor ||
	   record.acquisitionDescriptor->state == IndexDescriptorState::UNKNOWN) {
		return ;
	}

	const auto &value		= *record.acquisitionDescriptor ;	// 固定原recordに結合した申告。
	const auto &attestation = *value.attestation ;				// 構造検査が要求した元確認。
	require( attestation.checkedAtUtc <= manifest.publishedAtUtc &&
				manifest.publishedAtUtc < attestation.validUntilUtc &&
				attestation.validUntilUtc - attestation.checkedAtUtc <=
					INDEX_ACQUISITION_MAX_VALIDITY,
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 既知の取得方式と形式が矛盾する申告だけを拒否し、UNKNOWN方式を補わない。
	if( record.acquisition.value) {
		const bool archive = value.format == IndexPayloadFormat::ZIP ||
							 // 元形式の分類。
							 value.format == IndexPayloadFormat::CABINET ;
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
	// HTMLの原page provenanceと監視側関連根拠を同じ配布recordへ完全結合します。
	if( value.terms.textDocument && value.terms.textDocument->htmlExtraction) {
		const auto &document = *value.terms.textDocument ;	// 原page観測です。
		const auto &html	 = *document.htmlExtraction ;	// 選択文書と公開関連根拠です。
		require( value.terms.state == IndexTermsState::ACCEPTANCE_REQUIRED &&
					value.terms.revisionKind == IndexTermsRevisionKind::VENDOR_LITERAL &&
					document.url == source.distributionPage &&
					value.terms.evidenceUrl == document.url &&
					value.terms.evidenceSha256 == document.sha256 &&
					source.officialEvidence.evidenceSha256 == document.sha256 &&
					value.route.front().evidenceSha256 == document.sha256 &&
					sameOrigin( html.bindingEvidenceUrl, source.officialOrigin),
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	}

	require( sameOrigin( value.payloadUrl, source.officialOrigin) ||
				value.route.front().kind == IndexRouteKind::OFFICIAL_CDN_LINK,
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	std::set<std::string> urls ;				// 完全原URLの重複・循環拒否集合。
	bool				  cdnEntered{} ;		// 公式originへ戻る逆向きrouteを許可しない。
	std::size_t			  originRedirects{} ;	// CDN移行前の同origin redirectは最大2回。
	// 全6hop以内で元順序・出典と一方向CDN移行を確認する。
	for( std::size_t index = 0U; index < value.route.size(); ++index) {
		const auto &hop = value.route[index] ;	// 同recordの原hop。
		require( urls.insert( hop.url).second, IndexRecordsStatus::INVALID_EVIDENCE) ;
		const bool official =
			// Prefixを使わないorigin判定。
			sameOrigin( hop.url, source.officialOrigin) ;
		require( !cdnEntered || !official, IndexRecordsStatus::INVALID_EVIDENCE) ;
		cdnEntered = cdnEntered || !official ;
		// 二番目以降は直前の原URLを根拠としたHTTP redirectだけを許可する。
		if( index > 0U) {
			require( hop.kind == IndexRouteKind::HTTP_REDIRECT &&
						hop.evidenceUrl == value.route[index - 1U].url,
					IndexRecordsStatus::INVALID_EVIDENCE) ;
			// 移行前の同originだけを有限なredirect数として数える。
			if( !cdnEntered) {
				++originRedirects ;
				require( originRedirects <= 2U, IndexRecordsStatus::INVALID_EVIDENCE) ;
			}
		}
	}
}

} // namespace drivercrate::signed_index_acquisition
