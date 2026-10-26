//------------------------------------------------------------------------------
/**
 * @file signed_index_records.cpp
 * @brief 共通strict文法で署名済み配布recordの原byteと元申告を検査します。
 * @version 01.03.00
 * @date 2026/10/24
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  原byte・厳格schema・公開証拠とquality照合を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  v1互換を維持してv2 descriptorと現policy読取りを接続。
 * Ver.01.01.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.02.00 Shunji Ogawa  2026/10/23  全record/qualityの値codecを署名wrapperと共用。
 * Ver.01.03.00 Shunji Ogawa  2026/10/24  現行nested member identityと原record完全tupleへ整合。
 * </pre>
 *
 * @note 元申告を型付きで保持するだけで、公式性・適合・取得・導入を実証しません。
 *       全成功前の中間値は公開せず、network・保存・世代更新を行いません。
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#include "platform/signed_index_records.h"
#include "platform/signed_index_codec_internal.h"
#include "platform/official_download_workspace.h"

#include <algorithm>
#include <array>
#include <map>
#include <new>
#include <set>
#include <string_view>
#include <utility>
#include <windows.h>

#include "platform/official_file_verifier.h"
#include "platform/official_http_client.h"
#include "platform/signed_index_json_internal.h"
#include "platform/signed_index_acquisition_descriptor_internal.h"

namespace drivercrate {
namespace {

// 元申告の文字列と理由を有限に保持する実byte上限。
constexpr std::size_t TEXT_MAX_BYTES = 512U ;
// 静的な公開根拠URLのv1準備枠。
constexpr std::size_t URL_MAX_BYTES = 2048U ;
// Record原byteをbase64化した時の完全上限。
constexpr std::size_t RECORD_BASE64_MAX_BYTES = ((INDEX_RECORD_MAX_BYTES + 2U) / 3U) * 4U ;
/**
 * @brief 共通parserがこの層へ返す失敗値。
 */
using Failure = signed_index_json::Failure<IndexRecordsStatus> ;
/**
 * @brief 原byteを正規化しない共通parser。
 */
using Reader = signed_index_json::Reader<IndexRecordsStatus> ;
using signed_index_json::require ;
using signed_index_json::decodeHash ;

/** @brief 公開textとして制御byteを除外し、UTF-8は共通readerへ委ねます。
 * @param[in] value 解除後のUTF-8。
 * @return 非空で512byte以内、ASCII制御byteがない場合true。
 */
[[nodiscard]] bool validText( const std::string_view value) noexcept
{
	return !value.empty() && value.size() <= TEXT_MAX_BYTES &&
		   std::ranges::all_of( value, []( const unsigned char character) {
			   // UTF-8の非ASCII byteを保持し、表示を変える制御byteを除外する。
			   return character >= 0x20U && character != 0x7fU ;
		   }) ;
}

/** @brief 申告identityのASCII文法を検査します。
 * @param[in] value 原identity。
 * @param[in] limit 固定実byte上限。
 * @return 非空で英数字または._-だけの場合true。
 */
[[nodiscard]] bool validIdentity( const std::string_view value, const std::size_t limit) noexcept
{
	return !value.empty() && value.size() <= limit &&
		   std::ranges::all_of( value, []( const char character) {
			   // 公開identityを曖昧なUnicodeやpath delimiterへ拡張しない。
			   return (character >= 'A' && character <= 'Z') ||
					  (character >= 'a' && character <= 'z') ||
					  (character >= '0' && character <= '9') || character == '.' ||
					  character == '_' || character == '-' ;
		   }) ;
}

/** @brief 静的証拠URLの有限準備形式を共通URL parserで検査します。
 * @param[in] value 原ASCII URL。正規化しません。
 * @note DNS・通信・公開宛先実測は行いません。Queryを持つPAGEはv1未対応です。
 */
void requireEvidenceUrl( const std::string_view value)
{
	require( !value.empty() && value.size() <= URL_MAX_BYTES && value.starts_with( "https://") &&
				value.find_first_of( "?#@") == std::string_view::npos,
			IndexRecordsStatus::INVALID_URL) ;
	require( std::ranges::all_of( value,
								[]( const unsigned char character) {
									// URLの制御byte・Unicode表記をv1準備枠から除外する。
									return character > 0x20U && character < 0x7fU ;
								}),
			IndexRecordsStatus::INVALID_URL) ;
	const std::size_t	   end		 = value.find( '/', 8U) ;	// Authorityの完全範囲。
	const std::string_view authority = value.substr(
		8U, end == std::string_view::npos ? value.size() - 8U
										  : end - 8U) ;				// 共通parserへ渡すhostの抽出元。
	const std::size_t	   colon = authority.find( ':') ;			// 明示portがある場合の位置。
	const std::string_view host	 = authority.substr( 0U, colon) ;	// 元DNS名。
	require( colon == std::string_view::npos || authority.substr( colon) == ":443",
			IndexRecordsStatus::INVALID_URL) ;
	require( !host.empty() && host.find( '.') != std::string_view::npos && host.back() >= 'a' &&
				host.back() <= 'z' && !host.ends_with( ".localhost") && !host.ends_with( ".local") &&
				!host.ends_with( ".internal") &&
				std::ranges::all_of( host,
									[]( const char character) {
										// IP literalや括弧を認めず、原DNS名をそのまま保持する。
										return (character >= 'a' && character <= 'z') ||
											   (character >= '0' && character <= '9') ||
											   character == '.' || character == '-' ;
									}),
			IndexRecordsStatus::INVALID_URL) ;
	std::wstring wide ;	// 共通WinHTTP URL parserだけへ渡すASCII所有copy。
	wide.reserve( value.size()) ;
	// 元ASCII URLの全byteを値を変えずUTF-16へ写す。
	for( const unsigned char character : value) {
		wide.push_back( static_cast<wchar_t>( character)) ;
	}

	const std::wstring wideHost( host.begin(), host.end()) ;			// 同じ原DNS名だけのpolicy。
	const std::array<std::wstring_view, 1U> hosts{wideHost} ;			// 構文照合用。公式trust登録ではない。
	const NativeError error = validateOfficialHttpsUrl( wide, hosts) ;	// 共通parserの元診断。
	// 共通parserの確保失敗をURL形式の不正へ読み替えない。
	if( error == static_cast<NativeError>( E_OUTOFMEMORY)) {
		throw Failure{IndexRecordsStatus::OUT_OF_MEMORY, error} ;
	}

	require( error == 0, IndexRecordsStatus::INVALID_URL) ;
}

/** @brief 固定enum表から一つの元申告へ解決します。
 * @tparam Value 型付きenum。
 * @tparam Count 固定enum値数。
 * @param[in] text 原文字列。
 * @param[in] choices 唯一の許可表。
 * @return 完全一致の元申告enum。
 */
template <class Value, std::size_t Count>
[[nodiscard]] Value choice( const std::string_view										text,
						   const std::array<std::pair<std::string_view, Value>, Count> &choices)
{
	const auto found = std::ranges::find_if( choices, [&]( const auto &item) {
		// 借用textを固定enum表へ完全一致で照合する。
		return item.first == text ;
	}) ; // 固定集合の一致位置。
	require( found != choices.end(), IndexRecordsStatus::INVALID_EVIDENCE) ;
	return found->second ;
}

/** @brief 既知textとUNKNOWN理由の排他的表現を読みます。
 * @param[in,out] reader Record原byteの共通reader。
 * @return KNOWNの値かUNKNOWNの理由を所有する値。
 */
[[nodiscard]] IndexObservedValue<std::string> readTextValue( Reader &reader)
{
	constexpr std::array<std::string_view, 3U> FIELDS{"state", "value", "reason"} ;	// 全必須field。
	std::array<std::string, 3U>				   values ;								// Field順によらない所有元値。
	// Readerとこの呼出しの所有配列だけを同期借用するhandler。
	reader.object( FIELDS,
				  [&]( const std::size_t field) { values[field] = reader.text( TEXT_MAX_BYTES) ; }) ;
	require( values[0] == "KNOWN" || values[0] == "UNKNOWN", IndexRecordsStatus::INVALID_EVIDENCE) ;
	// UNKNOWNは欠損値を補完せず、非空理由をそのまま保持する。
	if( values[0] == "UNKNOWN") {
		require( values[1].empty() && validText( values[2]), IndexRecordsStatus::INVALID_EVIDENCE) ;
		return {std::nullopt, std::move( values[2])} ;
	}

	require( validText( values[1]) && values[2].empty(), IndexRecordsStatus::INVALID_EVIDENCE) ;
	return {std::move( values[1]), {}} ;
}

/** @brief 既知条件を固定enumへ、UNKNOWNをnulloptと理由へ読みます。
 * @tparam Value 型付きenum。
 * @tparam Count 固定enum値数。
 * @param[in,out] reader 共通reader。
 * @param[in] choices 固定enum表。
 * @return 元申告の条件またはUNKNOWN理由。
 */
template <class Value, std::size_t Count>
[[nodiscard]] IndexObservedValue<Value> readEnumValue(
	Reader &reader, const std::array<std::pair<std::string_view, Value>, Count> &choices)
{
	auto text = readTextValue( reader) ;	// UNKNOWN理由を保持した元text。
	// 未確認をenumの架空既知値へ変換しない。
	if( !text.value) {
		return {std::nullopt, std::move( text.reason)} ;
	}

	return {choice( *text.value, choices), {}} ;
}

/** @brief 元申告hashと出典原bytehashを別々に読みます。
 * @param[in,out] reader 共通reader。
 * @return 出典に結合した既知hashまたはUNKNOWN理由。
 */
[[nodiscard]] IndexHashEvidence readHashEvidence( Reader &reader)
{
	constexpr std::array<std::string_view, 5U> FIELDS{"state", "sha256", "evidenceUrl",
													  "evidenceSha256", "reason"} ;	// 全必須field。
	std::array<std::string, 5U>				   values ;								// 元申告の所有値。
	// 固定5fieldを要求長以内で順序非依存に読むhandler。
	reader.object( FIELDS, [&]( const std::size_t field) {
		values[field] = reader.text( field == 2U ? URL_MAX_BYTES : TEXT_MAX_BYTES) ;
	}) ;
	require( values[0] == "KNOWN" || values[0] == "UNKNOWN", IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 不足時は全証拠値を空にしてUNKNOWN理由だけを保持する。
	if( values[0] == "UNKNOWN") {
		require( values[1].empty() && values[2].empty() && values[3].empty() && validText( values[4]),
				IndexRecordsStatus::INVALID_EVIDENCE) ;
		return {std::nullopt, {}, std::nullopt, std::move( values[4])} ;
	}

	require( values[4].empty(), IndexRecordsStatus::INVALID_EVIDENCE) ;
	signed_index_acquisition::requireUrl( values[2], true) ;
	return {decodeHash( values[1], IndexRecordsStatus::INVALID_EVIDENCE),
			std::move( values[2]),
			decodeHash( values[3], IndexRecordsStatus::INVALID_EVIDENCE),
			{}} ;
}

/** @brief 正の元byte長またはUNKNOWN理由を読みます。
 * @param[in,out] reader 共通reader。
 * @return 元申告sizeまたはUNKNOWN理由。
 */
[[nodiscard]] IndexObservedValue<std::uint64_t> readSize( Reader &reader)
{
	constexpr std::array<std::string_view, 3U> FIELDS{"state", "valueBytes",
													  "reason"} ;	// 必須field。
	std::string								   state ;				// 元申告状態。
	std::string								   reason ;				// UNKNOWN理由。
	std::uint64_t							   bytes{} ;			// 元申告byte長。
	// Readerと有限出力だけを同期借用するhandler。
	reader.object( FIELDS, [&]( const std::size_t field) {
		// 数値fieldだけを整数型で読む。
		if( field == 1U) {
			bytes = reader.number() ;
		} else {
			// その他の状態と理由はtextのまま保持する。
			(field == 0U ? state : reason) = reader.text( TEXT_MAX_BYTES) ;
		}
	}) ;
	require( state == "KNOWN" || state == "UNKNOWN", IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 未知sizeに0を既知値として流用しない。
	if( state == "UNKNOWN") {
		require( bytes == 0U && validText( reason), IndexRecordsStatus::INVALID_EVIDENCE) ;
		return {std::nullopt, std::move( reason)} ;
	}

	require( bytes > 0U && reason.empty(), IndexRecordsStatus::INVALID_EVIDENCE) ;
	return {bytes, {}} ;
}

/** @brief 公開／計算hashとsizeの元申告を別々に読みます。
 * @param[in,out] reader 共通reader。
 * @return 両hashが既知なら完全一致を要求した元申告。
 */
[[nodiscard]] IndexPackageEvidence readPackage( Reader &reader)
{
	constexpr std::array<std::string_view, 3U> FIELDS{"publishedHash", "calculatedHash",
													  "size"} ;	// 必須field。
	IndexPackageEvidence					   value ;			// 全成功前には公開しない元申告。
	// 型付きfieldを固定番号へ接続する同期handler。
	reader.object( FIELDS, [&]( const std::size_t field) {
		// sizeは正の整数またはUNKNOWNを別に読む。
		if( field == 2U) {
			value.size = readSize( reader) ;
		} else {
			// 二つのhashは別々の出典を保持する。
			(field == 0U ? value.publishedHash : value.calculatedHash) = readHashEvidence( reader) ;
		}
	}) ;
	require( !value.publishedHash.sha256 || !value.calculatedHash.sha256 ||
				value.publishedHash.sha256 == value.calculatedHash.sha256,
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	return value ;
}

/** @brief Source公式性の元申告を読み、公式性の実証へ昇格しません。
 * @param[in,out] reader 共通reader。
 * @return 元申告の出典またはUNKNOWN理由。
 */
[[nodiscard]] IndexOfficialEvidence readOfficialEvidence( Reader &reader)
{
	constexpr std::array<std::string_view, 5U> FIELDS{"state", "kind", "evidenceUrl",
													  "evidenceSha256", "reason"} ;	// 必須field。
	std::array<std::string, 5U>				   values ;								// 順序に依存しない所有元値。
	// URLだけの独立上限を保って固定fieldを読むhandler。
	reader.object( FIELDS, [&]( const std::size_t field) {
		values[field] = reader.text( field == 2U ? URL_MAX_BYTES : TEXT_MAX_BYTES) ;
	}) ;
	require( values[0] == "PUBLISHED" || values[0] == "UNKNOWN",
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	// UNKNOWNは出典の公式性を架空の既知値にしない。
	if( values[0] == "UNKNOWN") {
		require( values[1] == "UNKNOWN" && values[2].empty() && values[3].empty() &&
					validText( values[4]),
				IndexRecordsStatus::INVALID_EVIDENCE) ;
		return {IndexEvidenceState::UNKNOWN,
				IndexOfficialEvidenceKind::UNKNOWN,
				{},
				std::nullopt,
				std::move( values[4])} ;
	}

	constexpr std::array<std::pair<std::string_view, IndexOfficialEvidenceKind>, 2U> KINDS{
		{{"OFFICIAL_PAGE", IndexOfficialEvidenceKind::OFFICIAL_PAGE},
		 {"OFFICIAL_CATALOG", IndexOfficialEvidenceKind::OFFICIAL_CATALOG}}} ;	// 固定元申告種別。
	require( values[4].empty(), IndexRecordsStatus::INVALID_EVIDENCE) ;
	signed_index_acquisition::requireUrl( values[2], true) ;
	return {IndexEvidenceState::PUBLISHED,
			choice( values[1], KINDS),
			std::move( values[2]),
			decodeHash( values[3], IndexRecordsStatus::INVALID_EVIDENCE),
			{}} ;
}

/** @brief Source identityと元申告の配布pageを読みます。
 * @param[in,out] reader Index原byteの共通reader。
 * @return 全fieldを検査した元申告source。
 */
[[nodiscard]] IndexRecordSource readSource( Reader &reader)
{
	constexpr std::array<std::string_view, 4U> FIELDS{
		"sourceId", "officialOrigin", "distributionPage", "officialEvidence"} ;	// 必須field。
	IndexRecordSource value ;													// 全成功前には公開しないsource。
	// Readerと所有sourceだけを借用するhandler。
	reader.object( FIELDS, [&]( const std::size_t field) {
		// 証拠objectは全fieldを独立に検査する。
		if( field == 3U) {
			value.officialEvidence = readOfficialEvidence( reader) ;
		} else {
			const std::array<std::string *, 3U> targets{
				&value.sourceId, &value.officialOrigin,
				&value.distributionPage} ;	// 非owning出力先。
			*targets[field] = reader.text( field == 0U ? 64U : URL_MAX_BYTES) ;
		}
	}) ;
	require( validIdentity( value.sourceId, 64U), IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 起点を持つUNKNOWN sourceでも静的URL文法は維持する。
	if( !value.officialOrigin.empty()) {
		signed_index_acquisition::requireUrl( value.officialOrigin, false) ;
	}

	// 元pageがある場合は未知の公式性とURL構文を分ける。
	if( !value.distributionPage.empty()) {
		signed_index_acquisition::requireUrl( value.distributionPage, true) ;
	}

	// 公開申告は一つのsource pageへ結合するが、真正性を実証しない。
	if( value.officialEvidence.state == IndexEvidenceState::PUBLISHED) {
		require( !value.officialOrigin.empty() && !value.distributionPage.empty() &&
					value.officialEvidence.evidenceUrl == value.distributionPage,
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	}

	return value ;
}

/** @brief メーカー公表側PnP IDの有限文法を確認します。
 * @param[in] value 原ID。
 * @return 一つのbus delimiterと非空残部、許可ASCIIだけの場合true。
 */
[[nodiscard]] bool validPnpId( const std::string_view value) noexcept
{
	const std::size_t slash = value.find( '\\') ;	// Busと原公開ID残部の境界。
	return value.size() <= TEXT_MAX_BYTES && slash != std::string_view::npos && slash > 0U &&
		   slash + 1U < value.size() && value.find( '\\', slash + 1U) == std::string_view::npos &&
		   std::ranges::all_of( value, []( const char character) {
			   // 原caseを保持し、比較keyだけを別途case非依存へ対応させます。
			   return (character >= 'A' && character <= 'Z') ||
					  (character >= 'a' && character <= 'z') ||
					  (character >= '0' && character <= '9') || character == '\\' ||
					  character == '&' || character == '_' || character == '-' ||
					  character == '.' || character == '*' ;
		   }) ;
}

/** @brief 非0のbrace付きClassGUIDの原表記を検査します。
 * @param[in] value 元ClassGUID。
 * @return 8-4-4-4-12桁のhexで非0の場合true。
 */
[[nodiscard]] bool validClassGuid( const std::string_view value) noexcept
{
	// 全固定位置を安全に参照できない値は拒否する。
	if( value.size() != 38U || value.front() != '{' || value.back() != '}') {
		return false ;
	}

	bool nonzero{} ;	// 全0 sentinelを既知classへ変換しない。
	// 固定36byteのGUID本文だけを調べ、区切りと全hex桁を検査する。
	for( std::size_t index = 1U; index < 37U; ++index) {
		const char character = value[index] ;	// 元hexまたは区切り。
		// 四つの固定区切りだけを許可する。
		if( index == 9U || index == 14U || index == 19U || index == 24U) {
			// 区切りが欠損している場合は型付きclassを作らない。
			if( character != '-') {
				return false ;
			}

			continue ;
		}

		// 元caseを保ったままhex以外を拒否する。
		if( !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') ||
			 (character >= 'A' && character <= 'F'))) {
			return false ;
		}

		nonzero = nonzero || character != '0' ;
	}

	return nonzero ;
}

/** @brief 静的相対INF identityを検査し、実local pathを構築しません。
 * @param[in] value Slash区切りの元identity。
 * @return 有限componentと.inf suffixを持つ場合true。
 */
[[nodiscard]] bool validInfIdentity( const std::string_view value)
{
	// Suffixの安全な参照と全identityの独立上限を要求する。
	if( value.size() < 5U || value.size() > TEXT_MAX_BYTES) {
		return false ;
	}

	const std::string_view suffix = value.substr( value.size() - 4U) ;	// 元suffix。
	// INF以外やabsolute identityへ正規化fallbackしない。
	if( suffix[0] != '.' || (suffix[1] != 'i' && suffix[1] != 'I') ||
	   (suffix[2] != 'n' && suffix[2] != 'N') || (suffix[3] != 'f' && suffix[3] != 'F')) {
		return false ;
	}

	return isSafeOfficialArchiveMember( std::wstring{value.begin(), value.end()}, L'/') ;
}

/** @brief 一段nested selectorをnativeと共通のmember文法で検査します。
 * @param[in] value 空はflat、非空は原slash相対archive memberです。
 * @return 空または安全なZIP/CAB memberの場合だけtrueです。
 * @note 公開memberからfilesystem pathを構築しません。
 */
[[nodiscard]] bool validNestedIdentity( const std::string_view value)
{
	// 空だけがflatの明示値です。
	if( value.empty()) {
		return true ;
	}

	// ASCII通常名を既存nativeの全上限/予約名へ照合します。
	if( !isSafeOfficialArchiveMember( std::wstring{value.begin(), value.end()}, L'/') ||
	   value.size() < 5U) {
		return false ;
	}

	std::string suffix{value.substr( value.size() - 4U)} ;	// 原末尾だけの比較値です。
	std::ranges::transform( suffix, suffix.begin(), []( const char character) {
		return character >= 'A' && character <= 'Z' ? static_cast<char>( character + ('a' - 'A'))
													: character ;
	}) ;
	return suffix == ".zip" || suffix == ".cab" ;
}

/** @brief 原公開IDの種別と値を一つずつ読みます。
 * @param[in,out] reader 共通reader。
 * @return 検査した原公開ID。端末actual IDではありません。
 */
[[nodiscard]] IndexPublishedPnpId readPnpId( Reader &reader)
{
	constexpr std::array<std::string_view, 2U> FIELDS{"kind", "value"} ;	// 必須field。
	std::array<std::string, 2U>				   values ;						// 元ID種別と原value。
	// 二fieldを独立上限内で読む同期handler。
	reader.object( FIELDS,
				  [&]( const std::size_t field) { values[field] = reader.text( TEXT_MAX_BYTES) ; }) ;
	constexpr std::array<std::pair<std::string_view, IndexPnpIdKind>, 2U> KINDS{
		{{"HARDWARE", IndexPnpIdKind::HARDWARE},
		 {"COMPATIBLE", IndexPnpIdKind::COMPATIBLE}}} ;	// 固定ID種別。
	require( validPnpId( values[1]), IndexRecordsStatus::INVALID_EVIDENCE) ;
	return {choice( values[0], KINDS), std::move( values[1])} ;
}

/** @brief 現行10fieldの公開identityを一出典へ結合し、明示UNKNOWNを保持します。
 * @param[in,out] reader 共通reader。
 * @return 元申告の公開identityまたはUNKNOWN理由。
 */
[[nodiscard]] IndexPublishedIdentityEvidence readIdentityEvidence( Reader &reader)
{
	constexpr std::array<std::string_view, 10U> FIELDS{
		"state",	   "kind",
		"pnpIds",	   "classGuid",
		"infIdentity", "modelSection",
		"evidenceUrl", "evidenceSha256",
		"reason",	   "nestedArchiveIdentity"} ;				// 必須field。
	std::array<std::string, 10U>					 values ;	// ID配列以外の元値。
	IndexPublishedIdentityEvidence					 value ;	// 全検査前には公開しない元申告。
	std::set<std::pair<IndexPnpIdKind, std::string>> seen ;		// 種別と原IDによる重複拒否集合。
	// 有限ID配列と固定text fieldを読む同期handler。
	reader.object( FIELDS, [&]( const std::size_t field) {
		// メーカー公表側IDだけを一件ずつ型付きで読む。
		if( field == 2U) {
			reader.array(
				INDEX_RECORD_PNP_MAX_COUNT,
				[&] {
					auto id	 = readPnpId( reader) ;	// 一公開IDの所有値。
					auto key = id.value ;			// 原公開byteを変更しない重複判定専用keyです。
					std::ranges::transform( key, key.begin(), []( const char character) {
						return character >= 'a' && character <= 'z'
								   ? static_cast<char>( character - ('a' - 'A'))
								   : character ;
					}) ;
					require( seen.emplace( id.kind, std::move( key)).second,
							IndexRecordsStatus::INVALID_EVIDENCE) ;
					value.pnpIds.push_back( std::move( id)) ;
				},
				IndexRecordsStatus::COUNT_LIMIT) ;
		} else {
			values[field] = reader.text( field == 6U ? URL_MAX_BYTES : TEXT_MAX_BYTES) ;
		}
	}) ;
	require( values[0] == "PUBLISHED" || values[0] == "UNKNOWN",
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 不足を既知identityへ補完せず、recordと非空理由を保持する。
	if( values[0] == "UNKNOWN") {
		require( values[1] == "UNKNOWN" && value.pnpIds.empty() && values[3].empty() &&
					values[4].empty() && values[5].empty() && values[6].empty() &&
					values[7].empty() && values[9].empty() && validText( values[8]),
				IndexRecordsStatus::INVALID_EVIDENCE) ;
		value.reason = std::move( values[8]) ;
		return value ;
	}

	constexpr std::array<std::pair<std::string_view, IndexIdentityEvidenceKind>, 2U> KINDS{
		{{"INF", IndexIdentityEvidenceKind::INF},
		 {"CATALOG", IndexIdentityEvidenceKind::CATALOG}}} ;	// 固定出典種別。
	require( !value.pnpIds.empty() && validClassGuid( values[3]) && validInfIdentity( values[4]) &&
				validIdentity( values[5], 128U) && values[8].empty() &&
				validNestedIdentity( values[9]) && (values[9].empty() || values[1] == "INF"),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	signed_index_acquisition::requireUrl( values[6], true) ;
	value.state					= IndexEvidenceState::PUBLISHED ;
	value.kind					= choice( values[1], KINDS) ;
	value.classGuid				= std::move( values[3]) ;
	value.infIdentity			= std::move( values[4]) ;
	value.nestedArchiveIdentity = std::move( values[9]) ;
	value.modelSection			= std::move( values[5]) ;
	value.evidenceUrl			= std::move( values[6]) ;
	value.evidenceSha256		= decodeHash( values[7], IndexRecordsStatus::INVALID_EVIDENCE) ;
	return value ;
}

/** @brief 原record byteを固定schemaに従って読むだけの内部関数です。
 * @param[in] raw Hashを照合済みの原UTF-8。
 * @param[in] digest rawだけの実SHA-256。
 * @param[in] manifest 原認証manifest。観測時刻を昇格しません。
 * @return 原byteと型付き元申告を所有するrecord。
 */
[[nodiscard]] IndexDistributionRecord readRecord( std::string raw, const IndexManifestSha256 digest,
												 const IndexManifestData &manifest)
{
	Reader										reader( raw, IndexRecordsStatus::INVALID_RECORD,
													   INDEX_RECORD_MAX_BYTES) ;	// 原byteの有限reader。
	constexpr std::array<std::string_view, 15U> FIELDS{
		"schema",
		"sourceId",
		"recordId",
		"product",
		"targetOs",
		"architecture",
		"driverKind",
		"version",
		"publishedDate",
		"acquisition",
		"packageEvidence",
		"lastSuccessfulObservationUtc",
		"inspectionStage",
		"publishedIdentityEvidence",
		"acquisitionDescriptor"} ;	// Schema別の閉じたfield集合。
	constexpr std::array<std::pair<std::string_view, IndexTargetOs>, 3U> OS{
		{{"WINDOWS_10", IndexTargetOs::WINDOWS_10},
		 {"WINDOWS_11", IndexTargetOs::WINDOWS_11},
		 {"WINDOWS_SERVER", IndexTargetOs::WINDOWS_SERVER}}} ;	// 固定OS条件。
	constexpr std::array<std::pair<std::string_view, IndexArchitecture>, 1U> ARCH{
		{{"X64", IndexArchitecture::X64}}} ;	// x64だけの既知条件。
	constexpr std::array<std::pair<std::string_view, IndexDriverKind>, 3U> KINDS{
		{{"NORMAL_DRIVER", IndexDriverKind::NORMAL_DRIVER},
		 {"FIRMWARE", IndexDriverKind::FIRMWARE},
		 {"APPLICATION", IndexDriverKind::APPLICATION}}} ;	// 除外種別も保持する元申告。
	constexpr std::array<std::pair<std::string_view, IndexAcquisitionKind>, 2U> ACQUISITION{
		{{"STANDARD_INF_ARCHIVE", IndexAcquisitionKind::STANDARD_INF_ARCHIVE},
		 {"OFFICIAL_INSTALLER",
		  IndexAcquisitionKind::OFFICIAL_INSTALLER}}} ;	// 実行許可ではない方式。
	constexpr std::array<std::pair<std::string_view, IndexInspectionStage>, 3U> STAGES{
		{{"UNCONFIRMED", IndexInspectionStage::UNCONFIRMED},
		 {"METADATA_ONLY", IndexInspectionStage::METADATA_ONLY},
		 {"CONTENT_INSPECTED", IndexInspectionStage::CONTENT_INSPECTED}}} ;	// 発行側の段階。
	IndexDistributionRecord value ;											// Schema全成功前にはreceiptにしない所有record。
	std::string				schema ;										// 全fieldの読取り後に確定する原wire版。
	// Readerとこのrecordだけを同期借用する型付きhandler。
	const std::uint32_t		seen = reader.objectWithPresence( FIELDS, [&]( const std::size_t field) {
		// 固定schema番号ごとに要求型を保って読む。
		switch( field) {
			// 新配布schemaだけを受理し研究v3を昇格しない。
			case 0U:
				schema = reader.text( 64U) ;
				break ;

			// Source参照は後段で一意なsourceへ結合する。
			case 1U:
				value.sourceId = reader.text( 64U) ;
				break ;

			// Source内の原identityを保持する。
			case 2U:
				value.recordId = reader.text( 64U) ;
				break ;

			// 製品表示名を適合条件に使わない。
			case 3U:
				value.product = reader.text( TEXT_MAX_BYTES) ;
				break ;

			// 公開OS条件またはUNKNOWN理由。
			case 4U:
				value.targetOs = readEnumValue( reader, OS) ;
				break ;

			// 公開x64条件またはUNKNOWN理由。
			case 5U:
				value.architecture = readEnumValue( reader, ARCH) ;
				break ;

			// 元内容種別またはUNKNOWN理由。
			case 6U:
				value.driverKind = readEnumValue( reader, KINDS) ;
				break ;

			// Version原値を比較・正規化しない。
			case 7U:
				value.version = readTextValue( reader) ;
				break ;

			// 公開暦日を補正せず検査する。
			case 8U:
				value.publishedDate = readTextValue( reader) ;
				// 既知公開日だけを実在する日付へ照合する。
				if( value.publishedDate.value) {
					require( value.publishedDate.value->size() == 10U,
								IndexRecordsStatus::INVALID_EVIDENCE) ;
					static_cast<void>(
						signed_index_json::utc( *value.publishedDate.value + "T00:00:00Z",
												   IndexRecordsStatus::INVALID_EVIDENCE)) ;
				}

				break ;

			// 方式は元申告であり導入許可ではない。
			case 9U:
				value.acquisition = readEnumValue( reader, ACQUISITION) ;
				break ;

			// 公開hashと計算hashとsizeを独立に保持する。
			case 10U:
				value.packageEvidence = readPackage( reader) ;
				break ;

			// 成功観測はmanifest発行時刻へ繰り上げない。
			case 11U: {
				auto observed = readTextValue( reader) ;	// 原UTCまたはUNKNOWN理由。
				value.lastSuccessfulObservationUtc.reason = std::move( observed.reason) ;
				// 既知観測UTCだけを暦日・秒単位で読む。
				if( observed.value) {
					value.lastSuccessfulObservationUtc.value = signed_index_json::utc(
						*observed.value, IndexRecordsStatus::INVALID_EVIDENCE) ;
				}

				break ;
			}
			// Qualityに照合する発行側の三段階。
			case 12U:
				value.inspectionStage = choice( reader.text( 32U), STAGES) ;
				break ;

			// 公開identity全体を一出典へ結ぶ。
			case 13U:
				value.publishedIdentityEvidence = readIdentityEvidence( reader) ;
				break ;

			// 取得申告を型付きで読むだけで、grantや候補を発行しない。
			case 14U:
				value.acquisitionDescriptor =
					signed_index_acquisition::readDescriptor( reader, readTextValue) ;
				break ;

			// 未登録field番号を成功にしない。
			default:
				throw Failure{IndexRecordsStatus::INVALID_RECORD} ;
		}
	}) ;
	reader.finish() ;
	require( (schema == "driver-index-record-v1" && seen == (1U << 14U) - 1U) ||
				(schema == "driver-index-record-v2" && seen == (1U << 15U) - 1U),
			IndexRecordsStatus::INVALID_RECORD) ;
	value.recordSchemaVersion = schema == "driver-index-record-v2" ? 2U : 1U ;
	// v1の取得情報不在を理由付きで保持し、既存pageからpayloadを補完しない。
	if( value.recordSchemaVersion == 1U) {
		value.acquisitionDescriptorUnavailableReason = "record v1 has no acquisition descriptor" ;
		// v1の既知出典URLは引き続きquery未対応の元文法で検査する。
		for( const auto *evidence :
			{&value.packageEvidence.publishedHash, &value.packageEvidence.calculatedHash}) {
			// UNKNOWNの空URLを出典へ補完しない。
			if( !evidence->evidenceUrl.empty()) {
				requireEvidenceUrl( evidence->evidenceUrl) ;
			}
		}

		// 公開identityのv1根拠にも同じquery未対応を保持する。
		if( !value.publishedIdentityEvidence.evidenceUrl.empty()) {
			requireEvidenceUrl( value.publishedIdentityEvidence.evidenceUrl) ;
		}
	}

	require( validIdentity( value.sourceId, 64U) && validIdentity( value.recordId, 64U) &&
				validText( value.product),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	require( !value.lastSuccessfulObservationUtc.value ||
				*value.lastSuccessfulObservationUtc.value <= manifest.publishedAtUtc,
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 内容検査の元申告には実byte由来の計算hash・size・成功観測を要求する。
	if( value.inspectionStage == IndexInspectionStage::CONTENT_INSPECTED) {
		require( value.packageEvidence.calculatedHash.sha256.has_value() &&
					value.packageEvidence.size.value.has_value() &&
					value.lastSuccessfulObservationUtc.value.has_value(),
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	}

	value.recordSha256	= digest ;
	value.originalBytes = std::move( raw) ;
	return value ;
}

/** @brief 原record byteを既存1MiB共通hash APIで実SHA-256へ結合します。
 * @param[in] raw 64KiB以下のdecode原byte。
 * @return 原byteの実digest。再serializationしません。
 */
[[nodiscard]] IndexManifestSha256 hashRecord( const std::string_view raw)
{
	std::wstring	  hex ;										// 共通APIが返す実digest。
	const NativeError error = computeBytesSha256( raw, hex) ;	// 元診断値。
	// API障害を入力hash不一致へ読み替えない。
	if( error != 0) {
		throw Failure{error == static_cast<NativeError>( E_OUTOFMEMORY)
						  ? IndexRecordsStatus::OUT_OF_MEMORY
						  : IndexRecordsStatus::CRYPTO_FAILURE,
					  error} ;
	}

	std::string narrow ;	// 共通hexをASCIIのまま固定型へ渡す値。
	narrow.reserve( hex.size()) ;
	// 全小文字hex桁を値を変えずcopyし、共通戻り値の形式も検査する。
	for( const wchar_t character : hex) {
		require( (character >= L'0' && character <= L'9') ||
					(character >= L'a' && character <= L'f'),
				IndexRecordsStatus::CRYPTO_FAILURE) ;
		narrow.push_back( static_cast<char>( character)) ;
	}

	return decodeHash( narrow, IndexRecordsStatus::CRYPTO_FAILURE) ;
}

/** @brief 一entryを厳格base64／原hashへ結合してからrecord schemaを読みます。
 * @param[in,out] reader Index原byteの共通reader。
 * @param[in,out] totalBytes Decode原record合計byte数。上限内でだけ加算します。
 * @param[in] manifest 原認証manifest。
 * @return 原byteに結合した型付きrecord。
 */
[[nodiscard]] IndexDistributionRecord readEntry( Reader &reader, std::size_t &totalBytes,
												const IndexManifestData &manifest)
{
	constexpr std::array<std::string_view, 2U> FIELDS{"recordBytesBase64",
													  "recordSha256"} ;	// 必須field。
	std::array<std::string, 2U>				   values ;					// 原base64と申告hash。
	// Decoderへ進む前にもencoded実byte枠を守る同期handler。
	reader.object( FIELDS, [&]( const std::size_t field) {
		values[field] = reader.text( field == 0U ? RECORD_BASE64_MAX_BYTES : 64U) ;
	}) ;
	const auto bytes = signed_index_json::decodeBase64(
		values[0], INDEX_RECORD_MAX_BYTES, IndexRecordsStatus::RECORD_SIZE_LIMIT,
		IndexRecordsStatus::INVALID_BASE64) ;	// 元順序のdecode結果。
	require( bytes.size() <= INDEX_RECORD_TOTAL_MAX_BYTES - totalBytes,
			IndexRecordsStatus::TOTAL_RECORD_SIZE_LIMIT) ;
	totalBytes += bytes.size() ;
	std::string raw( bytes.begin(), bytes.end()) ;	// 原UTF-8。正規化しない。
	const auto	digest = hashRecord( raw) ;			// 原byteだけの実digest。
	require( digest == decodeHash( values[1], IndexRecordsStatus::INVALID_RECORD),
			IndexRecordsStatus::RECORD_HASH_MISMATCH) ;
	return readRecord( std::move( raw), digest, manifest) ;
}

/** @brief 実件数の全5fieldを署名qualityへ厳格に照合します。
 * @param[in] actual 読み取ったsource／record／stage件数。
 * @param[in] signedQuality 認証manifestの発行側集計。
 * @return 全5fieldが完全一致する場合true。
 */
[[nodiscard]] bool sameQuality( const IndexManifestQuality &actual,
							   const IndexManifestQuality &signedQuality) noexcept
{
	return actual.sourceCount == signedQuality.sourceCount &&
		   actual.recordCount == signedQuality.recordCount &&
		   actual.metadataOnlyCount == signedQuality.metadataOnlyCount &&
		   actual.contentInspectedCount == signedQuality.contentInspectedCount &&
		   actual.unconfirmedCount == signedQuality.unconfirmedCount ;
}

} // namespace

/** @see signed_index_records.h */
IndexRecordsSchemaReceipt::IndexRecordsSchemaReceipt( AuthenticatedIndexAssetBytes		  asset,
													 std::vector<IndexRecordSource>		  sources,
													 std::vector<IndexDistributionRecord> records,
													 const IndexManifestQuality quality) noexcept
	: asset_( std::move( asset)), sources_( std::move( sources)), records_( std::move( records)),
	  quality_( quality)
{
}

/** @see signed_index_records.h */
const AuthenticatedIndexAssetBytes &IndexRecordsSchemaReceipt::assetBytes() const noexcept
{
	return asset_ ;
}

/** @see signed_index_records.h */
const IndexManifestSha256 &IndexRecordsSchemaReceipt::indexSha256() const noexcept
{
	return asset_.expandedSha256() ;
}

/** @see signed_index_records.h */
std::span<const IndexRecordSource> IndexRecordsSchemaReceipt::sources() const noexcept
{
	return sources_ ;
}

/** @see signed_index_records.h */
std::span<const IndexDistributionRecord> IndexRecordsSchemaReceipt::records() const noexcept
{
	return records_ ;
}

/** @see signed_index_records.h */
const IndexManifestQuality &IndexRecordsSchemaReceipt::actualQuality() const noexcept
{
	return quality_ ;
}

/** @see signed_index_records.h */
std::uint32_t IndexRecordsSchemaReceipt::schemaPolicyVersion() const noexcept
{
	return INDEX_RECORD_READER_POLICY_VERSION ;
}

/** @see signed_index_records.h */
IndexRecordsResult readSignedIndexRecords(
	const AuthenticatedIndexAssetBytes			 &asset,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	const auto &manifest = asset.manifest().data() ;	// 前段が所有する認証済み値。
	const auto	expanded = asset.expandedBytes() ;		// 前段の検査済み原UTF-8候補。
	// Move元の不完全receiptや必須根拠欠損をscalarと残hashだけで受理しない。
	if( manifest.manifestBytes.empty() || manifest.repository.empty() || manifest.channel.empty() ||
	   manifest.keyId.empty() || manifest.asset.tag.empty() || manifest.asset.name.empty() ||
	   expanded.empty() || asset.bytePolicyVersion() != INDEX_ASSET_BYTE_POLICY_VERSION ||
	   asset.maximumExpandedBytes() == 0U || expanded.size() > asset.maximumExpandedBytes()) {
		return {IndexRecordsStatus::INCOMPLETE_BYTE_RECEIPT, 0, std::nullopt} ;
	}

	auto decoded = signed_index_detail::decodeIndexRecordsData( manifest, expanded,
															   nowUtc) ;	// 同じ全値検査です。
	// 前段認証済みassetを所有するwrapperだけがschema receiptを構築します。
	if( !decoded.data) {
		return {decoded.status, decoded.error, std::nullopt} ;
	}

	return {IndexRecordsStatus::SCHEMA_VALIDATED, 0,
			IndexRecordsSchemaReceipt{asset, std::move( decoded.data->sources),
									  std::move( decoded.data->records), decoded.data->quality}} ;
}

/** @see signed_index_codec_internal.h */
signed_index_detail::DecodedIndexRecords signed_index_detail::decodeIndexRecordsData(
	const IndexManifestData &manifest, const std::span<const std::byte> expanded,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{

	// 時刻確認不能ではschema成功を生成しない。
	if( !nowUtc) {
		return {IndexRecordsStatus::TIME_UNAVAILABLE, 0, std::nullopt} ;
	}

	// 認証後も発行前の時刻を補正して成功にしない。
	if( *nowUtc < manifest.publishedAtUtc) {
		return {IndexRecordsStatus::NOT_YET_VALID, 0, std::nullopt} ;
	}

	// 期限ちょうどからはschema読取りも成功にしない。
	if( *nowUtc >= manifest.expiresAtUtc) {
		return {IndexRecordsStatus::EXPIRED, 0, std::nullopt} ;
	}

	// 実原index byteは前段枠を独立に確認する。
	if( expanded.size() > INDEX_ASSET_EXPANDED_MAX_BYTES) {
		return {IndexRecordsStatus::INDEX_SIZE_LIMIT, 0, std::nullopt} ;
	}

	try {
		require( manifest.quality.sourceCount <= INDEX_RECORD_SOURCE_MAX_COUNT &&
					manifest.quality.recordCount <= INDEX_RECORD_MAX_COUNT,
				IndexRecordsStatus::COUNT_LIMIT) ;
		// 原byteのobject representationだけを共通parserへ借用する境界です。
		const std::string_view original{reinterpret_cast<const char *>( expanded.data()),
										expanded.size()} ;
		Reader				   reader( original, IndexRecordsStatus::INVALID_INDEX,
									  // 正規化しないindex reader。
									  static_cast<std::size_t>( INDEX_ASSET_EXPANDED_MAX_BYTES)) ;
		constexpr std::array<std::string_view, 4U> FIELDS{"schema", "assetGeneration", "sources",
														  "records"} ;	// 全必須field。
		std::uint64_t							   generation{} ;		// 原indexが申告したasset世代。
		std::size_t								   totalBytes{} ;		// Decode原record合計実byte。
		std::vector<IndexRecordSource>			   sources ;			// 全参照検査まで公開しないsource集合。
		std::vector<IndexDistributionRecord>	   records ;			// 原byteを所有した有限record集合。
		std::string								   schema ;				// Outer field順に依存しないwire版。
		// Field順を固定せず型付きschemaと独立件数枠を検査する同期handler。
		reader.object( FIELDS, [&]( const std::size_t field) {
			// Schemaごとの型を維持し、未登録fieldは共通readerが拒否する。
			switch( field) {
				// 新配布schemaだけを受理する。
				case 0U:
					schema = reader.text( 64U) ;
					break ;

				// 署名manifestと照合する原asset世代。
				case 1U:
					generation = reader.number() ;
					break ;

				// 有限sourceを元順序どおり読む。
				case 2U:
					reader.array(
						INDEX_RECORD_SOURCE_MAX_COUNT,
						[&] {
							sources.push_back(
								// 原申告sourceを所有する同期handler。
								readSource( reader)) ;
						},
						IndexRecordsStatus::COUNT_LIMIT) ;
					break ;

				// 各原record byteと実hashを別々に検査する。
				case 3U:
					reader.array(
						INDEX_RECORD_MAX_COUNT,
						[&] {
							records.push_back( readEntry( reader, totalBytes,
														manifest)) ;	// 同期的な原byte読取り。
						},
						IndexRecordsStatus::COUNT_LIMIT) ;
					break ;

				// 未登録番号を成功へ変換しない。
				default:
					throw Failure{IndexRecordsStatus::INVALID_INDEX} ;
			}
		}) ;
		reader.finish() ;
		require( schema == "driver-index-records-v1" || schema == "driver-index-records-v2",
				IndexRecordsStatus::INVALID_INDEX) ;
		require( generation == manifest.assetGeneration,
				IndexRecordsStatus::ASSET_GENERATION_MISMATCH) ;
		std::map<std::string, std::pair<std::size_t, bool>>
			sourceMap ;	// 一意source位置と参照済み状態。
		// 全source identityを完全一致で登録し、重複を黙ってまとめない。
		for( std::size_t index = 0U; index < sources.size(); ++index) {
			// 旧outerでは旧PAGE query未対応を維持し、順序に依存してv2へ昇格しない。
			if( schema == "driver-index-records-v1") {
				// v1 sourceの全非空URLだけを旧文法へ照合する。
				for( const auto *url :
					{&sources[index].officialOrigin, &sources[index].distributionPage,
					 &sources[index].officialEvidence.evidenceUrl}) {
					// UNKNOWNの空値を既知URLにしない。
					if( !url->empty()) {
						requireEvidenceUrl( *url) ;
					}
				}
			}

			require( sourceMap.emplace( sources[index].sourceId, std::pair{index, false}).second,
					IndexRecordsStatus::DUPLICATE_SOURCE) ;
		}

		std::set<std::pair<std::string, std::string>>
							 recordIdentities ;	// Source内の原record identity集合。
		IndexManifestQuality quality ;			// 署名qualityへ照合する実件数。
		quality.sourceCount = sources.size() ;
		quality.recordCount = records.size() ;
		// 全recordを同じsourceへ結合し、実三段階件数を欠落なく数える。
		for( const auto &record : records) {
			require( schema == "driver-index-records-v2" || record.recordSchemaVersion == 1U,
					IndexRecordsStatus::INVALID_RECORD) ;
			require( recordIdentities.emplace( record.sourceId, record.recordId).second,
					IndexRecordsStatus::DUPLICATE_RECORD) ;
			const auto source = sourceMap.find( record.sourceId) ;	// 原source参照の一意位置。
			require( source != sourceMap.end(), IndexRecordsStatus::MISSING_SOURCE) ;
			source->second.second = true ;
			signed_index_acquisition::validateBinding( record, sources[source->second.first],
													  manifest) ;
			// 公開identityは同sourceの公開申告へ結合するが、公式性を実証しない。
			if( record.publishedIdentityEvidence.state == IndexEvidenceState::PUBLISHED) {
				require( sources[source->second.first].officialEvidence.state ==
							IndexEvidenceState::PUBLISHED,
						IndexRecordsStatus::INVALID_EVIDENCE) ;
			}

			// 元申告stageごとに実件数を一つだけ数え、UNKNOWNを成功へ変換しない。
			switch( record.inspectionStage) {
				// 未確認は不足のまま集計する。
				case IndexInspectionStage::UNCONFIRMED:
					++quality.unconfirmedCount ;
					break ;

				// Metadata段階だけを別集計する。
				case IndexInspectionStage::METADATA_ONLY:
					++quality.metadataOnlyCount ;
					break ;

				// 発行側の内容検査申告を端末実績へ変換しない。
				case IndexInspectionStage::CONTENT_INSPECTED:
					++quality.contentInspectedCount ;
					break ;
			}
		}

		// 全sourceが一record以上へ結合していることを確認する。
		for( const auto &source : sourceMap) {
			require( source.second.second, IndexRecordsStatus::UNREFERENCED_SOURCE) ;
		}

		require( sameQuality( quality, manifest.quality), IndexRecordsStatus::QUALITY_MISMATCH) ;
		return {IndexRecordsStatus::SCHEMA_VALIDATED, 0,
				DecodedIndexRecordsData{std::move( sources), std::move( records), quality}} ;
	} catch( const Failure &failure) {
		return {failure.status, failure.error, std::nullopt} ;
	} catch( const std::bad_alloc &) {
		return {IndexRecordsStatus::OUT_OF_MEMORY, static_cast<NativeError>( E_OUTOFMEMORY),
				std::nullopt} ;
	} catch( ...) {
		// Noexcept境界で未知障害を成功にせず、原診断に相当する固定失敗を保持する。
		return {IndexRecordsStatus::INTERNAL_FAILURE, static_cast<NativeError>( E_UNEXPECTED),
				std::nullopt} ;
	}
}

} // namespace drivercrate
