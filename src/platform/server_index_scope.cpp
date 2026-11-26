//------------------------------------------------------------------------------
/**
 * @file server_index_scope.cpp
 * @brief Server版/product別の三条件と同INF根拠を有限照合します
 * @version 01.02.00
 * @date 2026/11/17
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/17  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/11/17  未終端hiddenを拒否し有効な数値空白参照を比較へ接続
 * Ver.01.01.00 Shunji Ogawa  2026/11/17  宣言Server scopeとpolicy・Models・identityを分離接続
 * Ver.01.01.01 Shunji Ogawa  2026/11/17  GetObject macroを当該翻訳単位のJSON検査から隔離
 * Ver.01.02.00 Shunji Ogawa  2026/11/18  P3同scan fullhost観測と取得直前拒否を接続
 * </pre>
 * @note 同期DTO/WinRT JSON検査だけで、host観測/通信/導入を行いません。未知/不正は空で保持します
 * @see docs/adr/0508-exact-server-release-collection-and-acquisition.md
 */
//------------------------------------------------------------------------------
#include "platform/server_index_scope.h"
#include "platform/signed_index_acquisition_descriptor_internal.h"
#include <algorithm>
#include <array>
#include <regex>
#include <string>
#include <initializer_list>
#include <stdexcept>
#include <winrt/base.h>
#include <winrt/Windows.Foundation.Collections.h>

// Windows SDKのGetObject aliasを保存し、以下のWinRT JSON member名へ展開させません
#pragma push_macro( "GetObject")
#undef GetObject

namespace drivercrate {
namespace {

/** @brief 一つの採用版と原literal/base buildです。最低build範囲ではありません */
struct ReleaseInfo {
	/// 採用した閉じた版です
	ServerIndexRelease release ;
	/// static寿命のcanonical定義literalです
	std::string_view   name ;
	/// major10/minor0のexact base buildです
	std::uint32_t	   build ;
} ;

constexpr std::array<ReleaseInfo, 4U> RELEASES{
	{{ServerIndexRelease::WINDOWS_SERVER_2016, "WINDOWS_SERVER_2016", 14393U},
	 {ServerIndexRelease::WINDOWS_SERVER_2019, "WINDOWS_SERVER_2019", 17763U},
	 {ServerIndexRelease::WINDOWS_SERVER_2022, "WINDOWS_SERVER_2022", 20348U},
	 {ServerIndexRelease::WINDOWS_SERVER_2025, "WINDOWS_SERVER_2025",
	  26100U}}} ;													// 採用済み四版だけです
constexpr std::string_view OS_PREFIX = "DriverCrate:target-os=" ;	// 一record一版の条件です
constexpr std::string_view PRODUCT_PREFIX =
	"DriverCrate:target-product-type=" ;	// DC/Serverを分離します
constexpr std::string_view SUITE_CONDITION =
	"DriverCrate:models-observed-suite=0" ;	// hostの条件ではありません

//------------------------------------------------------------------------------
/**
 * @brief 元INF根拠の既知種別/URL/hashを検査します
 * @param[in] identity 呼出し中だけ借用する元record根拠です
 * @return PUBLISHED/INFと有効な有限URL/hashだけtrueです
 * @throws std::bad_alloc URL parserの割当て失敗です
 */
//------------------------------------------------------------------------------
bool validInfEvidence( const IndexPublishedIdentityEvidence &identity)
{
	// 未知根拠や他形式を存在するhashだけでINF成功へ変換しません
	if( identity.state != IndexEvidenceState::PUBLISHED ||
	   identity.kind != IndexIdentityEvidenceKind::INF || !identity.reason.empty() ||
	   !identity.evidenceSha256 || identity.evidenceUrl.empty() ||
	   identity.evidenceUrl.size() > 2048U) {
		return false ;
	}

	try {
		signed_index_acquisition::requireUrl( identity.evidenceUrl, true) ;
		return true ;
	} catch( const signed_index_json::Failure<IndexRecordsStatus> &) {
		return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 一条件の既codecと同じ有限text/URL/kindを検査します
 * @param[in] condition 借用する一つの原条件です。書き換えません
 * @return 有限の既知kind/非空text/正しいPAGE URLだけtrueです
 * @throws std::bad_alloc URL parserの割当て失敗です
 */
//------------------------------------------------------------------------------
bool validCondition( const IndexAcquisitionPrerequisite &condition)
{
	// 型付きDTOを直接作る呼出しでも、上限/未知kindを省略しません
	if( condition.description.empty() || condition.description.size() > 512U ||
	   condition.evidenceUrl.empty() || condition.evidenceUrl.size() > 2048U ||
	   (condition.kind != IndexPrerequisiteKind::LOCAL_CHECK &&
		condition.kind != IndexPrerequisiteKind::USER_CONFIRMATION &&
		condition.kind != IndexPrerequisiteKind::INSEPARABLE_FIRMWARE) ||
	   std::ranges::any_of( condition.description, []( const unsigned char character) {
		   return character < 0x20U || character == 0x7fU ;
	   })) {
		return false ;
	}

	try {
		signed_index_acquisition::requireUrl( condition.evidenceUrl, true) ;
		return true ;
	} catch( const signed_index_json::Failure<IndexRecordsStatus> &) {
		return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief HTMLの有効な数値空白参照だけを比較用ASCII spaceへ移します
 * @param[in] text 最大2MiB文字の借用比較本文です。原metadataは変更しません
 * @return NBSP名とdecimal/hex空白参照だけを変換した所有本文です
 * @throws std::bad_alloc 比較本文の割当て失敗です
 * @pre 呼出し側がtextをmetadata上限内へ検査済みです
 * @note Unicode空白scalarを扱い、HTML5で削除/別文字へ対応するC0/C1値は空白へ補完しません
 */
//------------------------------------------------------------------------------
std::wstring numericCatalogSpaces( const std::wstring_view text)
{
	std::wstring result ;	// 原byte/hashを置換しない比較専用の所有本文です
	result.reserve( text.size()) ;
	// 有限本文を前から走査し、未知参照は原表記のまま保持します
	for( std::size_t index = 0U; index < text.size();) {
		// Pythonのunescapeと同じcaseのNBSP名だけを既空白へ移します
		if( text.substr( index).starts_with( L"&nbsp;")) {
			result.push_back( L' ') ;
			index += 6U ;
			continue ;
		}

		// 有効なsemicolon終端の数値空白参照だけを解釈します
		if( text.substr( index).starts_with( L"&#")) {
			std::size_t	  cursor = index + 2U ;	// 同本文内の数値先頭です
			std::uint32_t base	 = 10U ;		// decimalを既定とし、明示x/Xだけhexです
			// HTMLの明示hex prefixを認め、数値や本文を推測しません
			if( cursor < text.size() && (text[cursor] == L'x' || text[cursor] == L'X')) {
				base = 16U ;
				++cursor ;
			}

			const auto	  first = cursor ;	// 空の参照を有効な0へしません
			std::uint32_t scalar{} ;		// Unicode上限を越える計算は実行しません
			bool		  valid = true ;	// 過大値は空白へ補完しません
			// 最大元本文長までの数字だけを消費し、integer overflowを防ぎます
			while( cursor < text.size()) {
				const auto character = text[cursor] ;	// 元ASCII桁です
				const auto digit	 = character >= L'0' && character <= L'9' ? character - L'0'
									   : character >= L'a' && character <= L'f' ? character - L'a' + 10
									   : character >= L'A' && character <= L'F' ? character - L'A' + 10
																				: -1 ;	// 非桁は-1です
				// 指定baseの数字以外でこの参照の走査を終えます
				if( digit < 0 || static_cast<std::uint32_t>( digit) >= base) {
					break ;
				}

				// Unicode scalar上限を越えた値をwrapしてspaceへ一致させません
				if( valid && scalar > (0x10ffffU - static_cast<std::uint32_t>( digit)) / base) {
					valid = false ;
				}

				// 不正になった数値は消費だけ続け、値は計算しません
				if( valid) {
					scalar = scalar * base + static_cast<std::uint32_t>( digit) ;
				}

				++cursor ;
			}

			const bool space = scalar == 9U || scalar == 10U || scalar == 12U || scalar == 13U ||
							   scalar == 32U || scalar == 160U || scalar == 0x1680U ||
							   (scalar >= 0x2000U && scalar <= 0x200aU) || scalar == 0x2028U ||
							   scalar == 0x2029U || scalar == 0x202fU || scalar == 0x205fU ||
							   // 有効なUnicode空白だけです
							   scalar == 0x3000U ;
			// 未終端/空/無効値/非空白参照を成功条件へ置換しません
			if( valid && space && cursor > first && cursor < text.size() && text[cursor] == L';') {
				result.push_back( L' ') ;
				index = cursor + 1U ;
				continue ;
			}
		}

		result.push_back( text[index]) ;
		++index ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief bridge不成立を固定例外へ移します
 * @param[in] valid 元成立条件です
 * @param[in] code 固定診断です
 * @throws std::runtime_error 不成立です
 */
//------------------------------------------------------------------------------
void scopeRequire( const bool valid, const char *code)
{
	// 不正条件をdefault成功へ補完しません
	if( !valid) {
		throw std::runtime_error( code) ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 同条件objectの閉field集合を要求します
 * @param[in] value 借用objectです
 * @param[in] names 必須field集合です
 * @throws std::runtime_error 欠落又は追加fieldです
 */
//------------------------------------------------------------------------------
void scopeFields( const winrt::Windows::Data::Json::JsonObject &value,
				 const std::initializer_list<const wchar_t *>  names)
{
	scopeRequire( value.Size() == names.size(), "COLLECTION_SERVER_FIELDS") ;
	// 最大四つの必須fieldを全て検査します
	for( const auto *name : names) {
		scopeRequire( value.HasKey( name), "COLLECTION_SERVER_FIELDS") ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief canonical literalだけを採用Server版へ解決します
 * @param[in] name 呼出し中だけ借用する原literalです
 * @return 四版だけ値あり。client/generic/未知は空です
 */
//------------------------------------------------------------------------------
std::optional<ServerIndexRelease> serverIndexRelease( const std::string_view name) noexcept
{
	// 四つのexact literalだけを比較し、and laterや別表記を補完しません
	for( const auto &entry : RELEASES) {
		// 一致した採用版だけを返します
		if( name == entry.name) {
			return entry.release ;
		}
	}

	return std::nullopt ;
}

//------------------------------------------------------------------------------
/**
 * @brief 採用版の原literalをstatic寿命で借用します
 * @param[in] release 解決済み版または未知値です
 * @return UNKNOWN/不正enumでは空、それ以外はcanonical literalです
 */
//------------------------------------------------------------------------------
std::string_view serverIndexReleaseName( const ServerIndexRelease release) noexcept
{
	// 固定四版以外へ表示名や世代を推測しません
	for( const auto &entry : RELEASES) {
		// 対応する一版の元literalだけを借用します
		if( entry.release == release) {
			return entry.name ;
		}
	}

	return {} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 明示したServer scopeから非権限Models観測tupleを作ります
 * @param[in] scope 一版/product2or3/観測suite0の元値です
 * @return 正しいscopeだけ10.0/AMD64/exact buildのtuple、それ以外は空です
 * @note hostを読まず、suite0をhost等値条件にも適用性成功にも変換しません
 */
//------------------------------------------------------------------------------
std::optional<OfficialInfModelsPlatform> serverIndexModelsPlatform(
	const ServerIndexScope &scope) noexcept
{
	// 観測していないproduct/suiteを成功したdefaultへ変えません
	if( (scope.productType != 2U && scope.productType != 3U) || scope.modelsObservedSuite != 0U) {
		return std::nullopt ;
	}

	// 採用表のexact base buildだけを選びます
	for( const auto &entry : RELEASES) {
		// 一致した版の全fieldを明示し、既DTOのclient既定値を借りません
		if( entry.release == scope.release) {
			return OfficialInfModelsPlatform{10U, 0U, entry.build, 9U, scope.productType, 0U} ;
		}
	}

	return std::nullopt ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同INFの最大16条件から必須三条件を一意に読みます
 * @param[in] identity PUBLISHED/INF型の同record根拠です。変更しません
 * @param[in] prerequisites 同recordの型付き元条件です。同期中だけ借用します
 * @return 全必須条件/根拠一致だけscopeあり。不正/未知/欠落は空です
 * @throws std::bad_alloc URL検証の割当て失敗です
 * @note 非LOCAL_CHECK条件の同意/適用性を確認せず、元recordも書き換えません
 */
//------------------------------------------------------------------------------
std::optional<ServerIndexScope> readServerIndexScope(
	const IndexPublishedIdentityEvidence &identity,
	const IndexAcquisitionPrerequisites	 &prerequisites)
{
	// 不明/過大集合と別種の根拠を先に拒否し、無制限走査をしません
	if( !validInfEvidence( identity) || prerequisites.state != IndexDescriptorState::KNOWN ||
	   !prerequisites.reason.empty() || prerequisites.items.size() > 16U) {
		return std::nullopt ;
	}

	ServerIndexScope scope ;		// 未確認fieldをdefault成功へしない出力候補です
	bool			 hasRelease{} ;	// exact版条件の一意性です
	bool			 hasProduct{} ;	// product条件の一意性です
	bool			 hasSuite{} ;	// suite由来条件の一意性です
	// 最大16条件を全て検査し、未知LOCAL_CHECKや重複を切り捨てません
	for( const auto &condition : prerequisites.items) {
		// 他種の元条件も切り捨てず、既codecの有限構文を要求します
		if( !validCondition( condition)) {
			return std::nullopt ;
		}

		// 無効なenumを既知条件に読み替えません
		if( condition.kind != IndexPrerequisiteKind::LOCAL_CHECK) {
			// 他種の正規条件はこのscopeだけでは確認済みにしません
			if( condition.kind != IndexPrerequisiteKind::USER_CONFIRMATION &&
			   condition.kind != IndexPrerequisiteKind::INSEPARABLE_FIRMWARE) {
				return std::nullopt ;
			}

			continue ;
		}

		// 三条件はいずれも同INF URL/hashへ完全結合します
		if( condition.evidenceUrl != identity.evidenceUrl ||
		   condition.evidenceSha256 != *identity.evidenceSha256) {
			return std::nullopt ;
		}

		const std::string_view text = condition.description ;	// 元literalを正規化しません
		// 版条件はgenericや複数版へ拡張しません
		if( text.starts_with( OS_PREFIX)) {
			const auto release =
				// 採用四版だけです
				serverIndexRelease( text.substr( OS_PREFIX.size())) ;
			// 同じ版の重複も一個へ丸めず拒否します
			if( hasRelease || !release) {
				return std::nullopt ;
			}

			scope.release = *release ;
			hasRelease	  = true ;
		}
		// productは版とは独立して一つだけ要求します
		else if( text.starts_with( PRODUCT_PREFIX)) {
			const auto product = text.substr( PRODUCT_PREFIX.size()) ;	// 文字列2/3だけを採用します
			// 非1や数値prefix一致で未知productを受け入れません
			if( hasProduct || (product != "2" && product != "3")) {
				return std::nullopt ;
			}

			scope.productType = static_cast<std::uint8_t>( product == "2" ? 2U : 3U) ;
			hasProduct		  = true ;
		}
		// suite0はhost条件ではなく観測由来の必須markerです
		else if( text == SUITE_CONDITION) {
			// 観測suite条件もexact一個を必須とします
			if( hasSuite) {
				return std::nullopt ;
			}

			hasSuite = true ;
		} else {
			return std::nullopt ;
		}
	}

	// 欠落条件を宣言名や現在OSから補完しません
	if( !hasRelease || !hasProduct || !hasSuite) {
		return std::nullopt ;
	}

	return scope ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同PUBLISHED/INF根拠へ三条件を生成し既条件を全件保持します
 * @param[in] scope 一版/product2or3/観測suite0です
 * @param[in] identity 同INF原URL/hashです。書き換えません
 * @param[in] additional 最大13の非LOCAL_CHECK既条件です。同期中だけ借用します
 * @return 全条件を保持したKNOWN集合です。不正scope/根拠/過大集合は空です
 * @throws std::bad_alloc 所有出力の割当て失敗です
 */
//------------------------------------------------------------------------------
std::optional<IndexAcquisitionPrerequisites> makeServerIndexPrerequisites(
	const ServerIndexScope &scope, const IndexPublishedIdentityEvidence &identity,
	const std::span<const IndexAcquisitionPrerequisite> additional)
{
	// 最大16件を維持するため、追加条件を省略して成功にはしません
	if( !serverIndexModelsPlatform( scope) || !validInfEvidence( identity) ||
	   additional.size() > 13U) {
		return std::nullopt ;
	}

	IndexAcquisitionPrerequisites result ;	// 原条件を保持する所有出力です
	result.state = IndexDescriptorState::KNOWN ;
	// 元の非LOCAL_CHECK条件を順序を変えず保持します
	for( const auto &condition : additional) {
		// 未検査LOCAL_CHECKを新三条件に混ぜたり同意へ変えません
		if( !validCondition( condition) || condition.kind == IndexPrerequisiteKind::LOCAL_CHECK ||
		   (condition.kind != IndexPrerequisiteKind::USER_CONFIRMATION &&
			condition.kind != IndexPrerequisiteKind::INSEPARABLE_FIRMWARE)) {
			return std::nullopt ;
		}

		result.items.push_back( condition) ;
	}

	const std::array descriptions{
		std::string{OS_PREFIX} + std::string{serverIndexReleaseName( scope.release)},
		std::string{PRODUCT_PREFIX} + (scope.productType == 2U ? "2" : "3"),
		std::string{SUITE_CONDITION}} ;	// 固定三literalです
	// 三条件を同INF根拠へ個別に結び、一generic条件へ丸めません
	for( const auto &description : descriptions) {
		result.items.push_back( {IndexPrerequisiteKind::LOCAL_CHECK, description,
								identity.evidenceUrl, *identity.evidenceSha256}) ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 有限Catalog本文の明記されたServer版だけを照合します
 * @param[in] text 最大2MiB文字の原metadataです。呼出し中だけ借用します
 * @param[in] release 採用した一Server版です
 * @return 当該exact版名が本文に存在する場合だけtrueです
 * @throws std::bad_alloc 比較用所有本文の割当て失敗です
 * @throws std::regex_error 正規表現の解析/実行失敗です
 * @note 完全なhidden/comment/tagを除き、未終端は拒否します。数値空白参照は比較本文だけで変換します
 * @note 全HTML文法のparserではなく、将来版/適用性/productの証明でもありません
 */
//------------------------------------------------------------------------------
bool catalogHasServerIndexRelease( const std::wstring_view text, const ServerIndexRelease release)
{
	const auto name = serverIndexReleaseName( release) ;	// 採用literalから四桁版だけを取ります
	// 未知版や有限metadata外は文字列比較を開始しません
	if( name.empty() || text.empty() || text.size() > 2U * 1024U * 1024U) {
		return false ;
	}

	const std::wregex hidden{
		LR"(<(script|style|template|noscript)\b[^>]*>[\s\S]*?</\1\s*>|<!--[\s\S]*?-->)",
		std::regex::icase} ;											// 非本文を除外します
	auto body = std::regex_replace( std::wstring{text}, hidden, L" ") ;	// 元本文は変更しません
	// 完全閉鎖していないhidden/commentから版名を拾わず、Server判定をHOLDへ返します
	if( std::regex_search(
		   body, std::wregex{LR"(<(script|style|template|noscript)\b|<!--)", std::regex::icase})) {
		return false ;
	}

	body					= std::regex_replace( body, std::wregex{L"<[^>]*>"}, L" ") ;
	body					= numericCatalogSpaces( body) ;
	const auto		   year = name.substr( name.size() - 4U) ;	// 定義literalの採用済み四桁だけです
	const std::wstring wideYear{year.begin(), year.end()} ;		// ASCII版文字列の等値表現です
	return std::regex_search(
		body, std::wregex{L"\\bwindows\\s+server\\s+" + wideYear + L"\\b", std::regex::icase}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 新条件が混じらない旧generic Server recordだけを区別します
 * @param[in] record strict入力の借用recordです。原byteを変更しません
 * @return 条件なし又は旧generic LOCAL_CHECK一個のみtrueです。不正/部分/未知はfalseです
 * @note 取得/公開成功ではなく、旧raw/key保持だけの分類です。MTA専用です
 */
//------------------------------------------------------------------------------
bool isLegacyServerIndexRecord( const winrt::Windows::Data::Json::JsonObject &record)
{
	try {
		// clientや不明OSをlegacy Serverへ読み替えません
		if( record.GetNamedObject( L"targetOs").GetNamedString( L"value") != L"WINDOWS_SERVER") {
			return false ;
		}

		const auto descriptor = record.GetNamedObject( L"acquisitionDescriptor") ;	// 元wireだけです
		// 新条件が存在しない旧recordのraw/keyを保持します
		if( !descriptor.HasKey( L"prerequisites")) {
			return true ;
		}

		const auto prerequisites = descriptor.GetNamedObject( L"prerequisites") ;	// 原条件です
		const auto items		 = prerequisites.GetNamedArray( L"items") ;			// 既codecの有限集合です
		// 不明集合内の値や上限超過を旧成功へfallbackしません
		if( items.Size() > 16U ||
		   (prerequisites.GetNamedString( L"state") != L"KNOWN" && items.Size() != 0U)) {
			return false ;
		}

		bool generic{} ;	// 旧generic条件も重複を許しません
		// 全元条件を検査し、new markerや未知LOCAL_CHECKを残したままfallbackしません
		for( const auto &item : items) {
			const auto		   condition = item.GetObject() ;						// 一原条件です
			const std::wstring text{condition.GetNamedString( L"description")} ;	// 値を正規化しません
			// 旧generic一個だけを例外にして新markerと分離します
			if( condition.GetNamedString( L"kind") == L"LOCAL_CHECK") {
				// 重複/未知/partialをlegacyとして受理しません
				if( generic || text != L"DriverCrate:target-os=WINDOWS_SERVER") {
					return false ;
				}

				generic = true ;
			}
			// 別kindへ移したnew markerもfallbackを許しません
			else if( text.starts_with( L"DriverCrate:target-os=") ||
					text.starts_with( L"DriverCrate:target-product-type=") ||
					text.starts_with( L"DriverCrate:models-observed-suite=")) {
				return false ;
			}
		}

		return true ;
	} catch( const winrt::hresult_error &) {
		return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief strict元templateを同INF根拠のServer scopeへ変換します
 * @param[in] record MTA内で同期借用する元objectです。変更しません
 * @return 正しい一版/product/観測suiteです
 * @throws std::runtime_error 不正条件/根拠/上限です
 * @throws winrt::hresult_error 必須field/型違いです
 * @note record全codecの代替ではありません
 */
//------------------------------------------------------------------------------
ServerIndexScope readServerIndexTemplateScope( const winrt::Windows::Data::Json::JsonObject &record)
{
	const auto target		= record.GetNamedObject( L"targetOs") ;		// 元wire enumを維持します
	const auto acquisition	= record.GetNamedObject( L"acquisition") ;	// 今回は標準INFだけです
	const auto architecture = record.GetNamedObject( L"architecture") ;	// 同templateの明示値です
	scopeRequire( target.GetNamedString( L"state") == L"KNOWN" &&
					 target.GetNamedString( L"value") == L"WINDOWS_SERVER" &&
					 architecture.GetNamedString( L"state") == L"KNOWN" &&
					 architecture.GetNamedString( L"value") == L"X64" &&
					 acquisition.GetNamedString( L"state") == L"KNOWN" &&
					 acquisition.GetNamedString( L"value") == L"STANDARD_INF_ARCHIVE" &&
					 target.GetNamedString( L"reason").empty() &&
					 architecture.GetNamedString( L"reason").empty() &&
					 acquisition.GetNamedString( L"reason").empty(),
				 "COLLECTION_SERVER_TEMPLATE_KIND") ;
	const auto published = record.GetNamedObject( L"publishedIdentityEvidence") ;	// 同INF原根拠です
	scopeRequire( published.GetNamedString( L"state") == L"PUBLISHED" &&
					 published.GetNamedString( L"kind") == L"INF",
				 "COLLECTION_SERVER_INF_EVIDENCE") ;
	IndexPublishedIdentityEvidence identity ;	// full recordを合成せず必要な根拠だけを移します
	identity.state		  = IndexEvidenceState::PUBLISHED ;
	identity.kind		  = IndexIdentityEvidenceKind::INF ;
	identity.reason		  = winrt::to_string( published.GetNamedString( L"reason")) ;
	identity.evidenceUrl  = winrt::to_string( published.GetNamedString( L"evidenceUrl")) ;
	const auto descriptor = record.GetNamedObject( L"acquisitionDescriptor") ;	// 元取得申告です
	scopeRequire( descriptor.GetNamedString( L"state") == L"KNOWN" &&
					 descriptor.GetNamedString( L"reason").empty(),
				 "COLLECTION_SERVER_DESCRIPTOR") ;
	const auto raw = descriptor.GetNamedObject( L"prerequisites") ;	// 原条件です
	scopeFields( raw, {L"state", L"reason", L"items"}) ;
	scopeRequire( raw.GetNamedString( L"state") == L"KNOWN", "COLLECTION_SERVER_PREREQUISITES") ;
	const auto items = raw.GetNamedArray( L"items") ;	// 走査前に既codecと同じ上限を課します
	scopeRequire( items.Size() <= 16U, "COLLECTION_SERVER_PREREQUISITES") ;
	IndexAcquisitionPrerequisites prerequisites ;	// 原順序と他条件を保持する一時DTOです
	prerequisites.state	 = IndexDescriptorState::KNOWN ;
	prerequisites.reason = winrt::to_string( raw.GetNamedString( L"reason")) ;
	try {
		identity.evidenceSha256 = signed_index_json::decodeHash(
			winrt::to_string( published.GetNamedString( L"evidenceSha256")),
			IndexRecordsStatus::INVALID_RECORD) ;
		// 最大16の元条件を全て移し、未知kindを別条件へ読み替えません
		for( const auto &item : items) {
			const auto value = item.GetObject() ;	// 一つの原条件です
			scopeFields( value, {L"kind", L"description", L"evidenceUrl", L"evidenceSha256"}) ;
			const auto kind = value.GetNamedString( L"kind") ;	// 閉じた三kindです
			scopeRequire( kind == L"LOCAL_CHECK" || kind == L"USER_CONFIRMATION" ||
							 kind == L"INSEPARABLE_FIRMWARE",
						 "COLLECTION_SERVER_PREREQUISITE_KIND") ;
			IndexAcquisitionPrerequisite
				condition ;	// 未知値をdefault USER_CONFIRMATIONへ補完しません
			condition.kind		  = kind == L"LOCAL_CHECK" ? IndexPrerequisiteKind::LOCAL_CHECK
									: kind == L"USER_CONFIRMATION"
										? IndexPrerequisiteKind::USER_CONFIRMATION
										: IndexPrerequisiteKind::INSEPARABLE_FIRMWARE ;
			condition.description = winrt::to_string( value.GetNamedString( L"description")) ;
			condition.evidenceUrl = winrt::to_string( value.GetNamedString( L"evidenceUrl")) ;
			scopeRequire( !condition.description.empty() && condition.description.size() <= 512U,
						 "COLLECTION_SERVER_PREREQUISITE_TEXT") ;
			signed_index_acquisition::requireUrl( condition.evidenceUrl, true) ;
			condition.evidenceSha256 = signed_index_json::decodeHash(
				winrt::to_string( value.GetNamedString( L"evidenceSha256")),
				IndexRecordsStatus::INVALID_RECORD) ;
			prerequisites.items.push_back( std::move( condition)) ;
		}
	} catch( const signed_index_json::Failure<IndexRecordsStatus> &) {
		throw std::runtime_error( "COLLECTION_SERVER_EVIDENCE_FORMAT") ;
	}

	const auto scope = readServerIndexScope( identity, prerequisites) ;	// 共通三条件の意味検査です
	scopeRequire( scope.has_value(), "COLLECTION_SERVER_SCOPE") ;
	return *scope ;
}

//------------------------------------------------------------------------------
/**
 * @brief 観測成功と初回hostの対応範囲を分けて検査します
 * @param[in] observed 同期借用する原観測です
 * @return UNKNOWN/UNSUPPORTED又は未検査取得までの判定です。導入能力は発行しません
 */
//------------------------------------------------------------------------------
IndexHostGateResult classifyIndexHost( const WindowsHostPlatformObservation &observed) noexcept
{
	IndexHostGateResult result{IndexHostGateState::UNKNOWN, E_NOTIMPL,
							   observed} ;	// 原API値は保持します
	// 必要fieldの不明を未対応OSの既知値へ変換しません
	if( observed.state != WindowsHostObservationState::OBSERVED || !observed.value ||
	   observed.value->majorVersion == 0U || observed.value->buildNumber == 0U ||
	   observed.value->productType == 0U || observed.value->nativeArchitecture == 0xffffU) {
		return result ;
	}

	const auto &value = *observed.value ;	// 実suite0も既知の観測値です
	// 初回の完全観測が未採用ならUNSUPPORTEDです
	if( value.majorVersion != 10U || value.minorVersion != 0U || value.nativeArchitecture != 9U ||
	   (value.productType != 1U && value.productType != 2U && value.productType != 3U) ||
	   (value.productType != 1U && value.buildNumber != 14393U && value.buildNumber != 17763U &&
		value.buildNumber != 20348U && value.buildNumber != 26100U)) {
		result.state = IndexHostGateState::UNSUPPORTED ;
		return result ;
	}

	result.state = IndexHostGateState::ALLOW_UNVERIFIED ;
	result.error = 0 ;
	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief 初回の原hostとfresh観測を比較します
 * @param[in] original 同scanの元観測です
 * @param[in] fresh 今回の原観測です
 * @return 必要field不明はUNKNOWN、完全tuple変化は未採用値でもSTALEです
 */
//------------------------------------------------------------------------------
IndexHostGateResult compareIndexHost( const WindowsHostPlatformObservation &original,
									 const WindowsHostPlatformObservation &fresh) noexcept
{
	auto result = classifyIndexHost( fresh) ;	// 原error/domain/bitsを保持します
	// API失敗と必要field欠損は比較できないUNKNOWNです
	if( result.state == IndexHostGateState::UNKNOWN) {
		return result ;
	}

	// freshの対応範囲より先に全tupleの変化を評価します
	if( !original.value || original.state != WindowsHostObservationState::OBSERVED) {
		result.state = IndexHostGateState::UNKNOWN ;
		result.error = E_NOTIMPL ;
		return result ;
	}

	// 新tupleが既知未対応でも同scanの変化はSTALEです
	if( *fresh.value != *original.value) {
		result.state = IndexHostGateState::STALE ;
		result.error = HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) ;
	}

	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief Server一scopeと実hostを取得前に照合します
 * @param[in] scope 元三条件から得た一版/productです
 * @param[in] observed 同scanの原hostです
 * @return suite0 markerを実suite等値とせず、版/product/architectureを検査した判定です
 */
//------------------------------------------------------------------------------
IndexHostGateResult matchServerIndexHost( const ServerIndexScope				  &scope,
										 const WindowsHostPlatformObservation &observed) noexcept
{
	auto result = classifyIndexHost( observed) ;	// API観測失敗と未対応を保持します
	// UNKNOWN/UNSUPPORTEDからrecordの条件でhostを補完しません
	if( result.state != IndexHostGateState::ALLOW_UNVERIFIED) {
		return result ;
	}

	const auto expected = serverIndexModelsPlatform( scope) ;	// 元scopeの既知版だけです
	// 不正scopeを汎用Serverへ戻しません
	if( !expected) {
		result.state = IndexHostGateState::UNKNOWN ;
		result.error = E_NOTIMPL ;
		return result ;
	}

	// producer suite0は実hostの等値条件に含めません
	if( observed.value->productType != expected->productType ||
	   observed.value->buildNumber != expected->buildNumber) {
		result.state = IndexHostGateState::INCOMPATIBLE ;
		result.error = E_ACCESSDENIED ;
	}

	return result ;
}
} // namespace drivercrate

// include後に保存したWindows SDKのmacro状態を復元します
#pragma pop_macro( "GetObject")
