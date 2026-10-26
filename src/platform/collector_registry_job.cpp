//------------------------------------------------------------------------------
/**
 * @file collector_registry_job.cpp
 * @brief 原jobと同HTTP・通常全INF検査の公開結果を結合します。
 * @version 01.04.00
 * @date 2026/10/23
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/23  厳密外部jobと保護一回取得・全拒否保持を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/23  台帳の未記載URLとlocator由来取得経路を分離。
 * Ver.01.01.00 Shunji Ogawa  2026/10/23  私有cap/期限・PAGE借用・同I/O転送観測を接続。
 * Ver.01.02.00 Shunji Ogawa  2026/10/23  同run私有結果へ全体失敗/部分失敗区分を保持。
 * Ver.01.03.00 Shunji Ogawa  2026/10/23  同I/O・全INF公開値を結果objectの私有観測へ所有。
 * Ver.01.03.01 Shunji Ogawa  2026/10/25  実手動確認時刻を原PAGE観測以降・実現在以下へ検証。
 * Ver.01.04.00 Shunji Ogawa  2026/10/25  現行v2の四scope比較digestを原PAGEとは独立に結合。
 * </pre>
 *
 * @note setup親の保護callerだけが接続します。成功JSONのimport、導入、署名、端末列挙は行いません。
 * @see docs/adr/0395-data-driven-collector-expansion.md
 */
//------------------------------------------------------------------------------
#include "platform/collector_registry_job.h"
#include "platform/official_collector_public_text.h"
#include "platform/official_file_verifier.h"
#include "platform/signed_index_json_internal.h"
#include "platform/windows_product_type.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <new>
#include <set>
#include <span>
#include <utility>
#include <vector>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>

namespace drivercrate {
namespace {
using JsonObject	= winrt::Windows::Data::Json::JsonObject ;		// 意味検証と明示結果だけのDOMです。
using JsonArray		= winrt::Windows::Data::Json::JsonArray ;		// 有限元順の配列です。
using JsonValue		= winrt::Windows::Data::Json::JsonValue ;		// 出力値です。
using JsonValueType = winrt::Windows::Data::Json::JsonValueType ;	// 明示nullの区別です。
using Reader = signed_index_json::Reader<NativeError> ;				// UTF-8・重複・全fieldの既存readerです。

/** @brief 解析拒否を数値だけで上位へ返します。
 * @param[in] valid 成立条件です。
 */
void require( const bool valid)
{
	signed_index_json::require( valid, static_cast<NativeError>( E_INVALIDARG)) ;
}

/** @brief Jobの固定型付きfield群です。 */
enum class Shape {
	/// 有限文字列です。
	TEXT,
	/// 明示nullまたは文字列です。
	NULLABLE_TEXT,
	/// 非負の整数です。
	NUMBER,
	/// 有限文字列配列です。
	TEXTS,
	/// 製品配列です。上限超過時は全体を拒否します。
	PRODUCTS,
	/// 一製品の全fieldです。
	PRODUCT,
	/// 元file bindingです。
	BINDING,
	/// Exact公式経路です。
	SOURCE,
	/// 元配布recordです。
	RECORD,
	/// 原page観測です。
	PAGE,
	/// 明示INF選択です。
	SELECTION,
	/// 四独立確認です。
	REVIEW,
	/// 一確認scopeです。
	SCOPE,
	/// 必須条件scopeです。
	PREREQUISITES,
	/// 原pageへ結合する根拠です。
	EVIDENCE,
	/// 外側jobです。
	JOB,
} ;

/** @brief 固定schemaの一値を再帰的に全消費します。
 * @param[in,out] reader 原byteを借用する有限readerです。
 * @param[in] shape この位置だけが受け付けるschemaです。
 */
void readShape( Reader &reader, Shape shape) ;

/** @brief 閉じたfield表で未知・解除後重複・欠損を拒否します。
 * @tparam Count 固定field件数です。Jobだけ17です。
 * @param[in,out] reader 同じ原byteのreaderです。
 * @param[in] names 全必須fieldです。
 * @param[in] shapes 各fieldの型です。
 */
template <std::size_t Count>
void readObject( Reader &reader, const char *const ( &names)[Count], const Shape ( &shapes)[Count])
{
	std::array<std::string_view, Count> fields{} ;	// 既存readerへ渡す固定field viewです。
	// 小さな固定表を同順で借用し、入力からfieldを生成しません。
	for( std::size_t index = 0U; index < Count; ++index) {
		fields[index] = names[index] ;
	}

	// Lambdaは同readerと固定表を同期借用し、一つの型だけを消費します。
	reader.object( fields, [&]( const std::size_t index) { readShape( reader, shapes[index]) ; }) ;
}

/** @see readShape 宣言。 */
void readShape( Reader &reader, const Shape shape)
{
	// 各位置が許可する固定型だけを消費し、任意JSON値を読み飛ばしません。
	switch( shape) {
		case Shape::TEXT:	// 原文字列を上限内で解除します。
			static_cast<void>( reader.text( 8192U)) ;
			break ;

		case Shape::NULLABLE_TEXT:	// 未知値は明示nullでだけ表現します。
			// Null以外のboolや数値を欠損へ変換しません。
			if( !reader.nullValue()) {
				static_cast<void>( reader.text( 8192U)) ;
			}

			break ;

		case Shape::NUMBER:	// 小数や指数を丸めて受理しません。
			static_cast<void>( reader.number()) ;
			break ;

		case Shape::TEXTS:	// 原集合を最大4096要素まで全消費します。
			reader.array( 4096U, [&]() { readShape( reader, Shape::TEXT) ; }, E_INVALIDARG) ;
			break ;

		case Shape::PRODUCTS:	// 共有製品を途中で切り捨てません。
			reader.array( 4096U, [&]() { readShape( reader, Shape::PRODUCT) ; }, E_INVALIDARG) ;
			break ;

		case Shape::PRODUCT:	// 元製品全fieldを要求します。
			readObject( reader,
					   {"id", "manufacturer", "model", "driverCategory", "sourceIds", "recordIds",
						"researchState", "reason"},
					   {Shape::TEXT, Shape::TEXT, Shape::TEXT, Shape::TEXT, Shape::TEXTS,
						Shape::TEXTS, Shape::TEXT, Shape::TEXT}) ;
			break ;

		case Shape::BINDING:	// 原fileの世代と実bytehashを保持します。
			readObject( reader, {"schema", "revision", "asOf", "sha256"},
					   {Shape::TEXT, Shape::TEXT, Shape::TEXT, Shape::TEXT}) ;
			break ;

		case Shape::SOURCE:	// 実行commandや任意pathを許可しません。
			readObject( reader, {"rootUrl", "rootHost", "payloadUrl", "payloadHost", "href"},
					   {Shape::TEXT, Shape::TEXT, Shape::TEXT, Shape::TEXT, Shape::TEXT}) ;
			break ;

		case Shape::RECORD:	// 研究成功boolなどを入力へ追加できません。
			readObject( reader,
					   {"id", "sourceId", "title", "driverCategory", "operatingSystems",
						"packageVersion", "driverVersion", "publishedDate", "downloadUrl",
						"linkState", "publishedSha256", "contentState"},
					   {Shape::TEXT, Shape::TEXT, Shape::TEXT, Shape::TEXT, Shape::TEXTS,
						Shape::NULLABLE_TEXT, Shape::NULLABLE_TEXT, Shape::NULLABLE_TEXT,
						Shape::NULLABLE_TEXT, Shape::TEXT, Shape::NULLABLE_TEXT, Shape::TEXT}) ;
			break ;

		case Shape::PAGE:	// 原本文観測の型を固定します。
			readObject( reader, {"method", "httpStatus", "bodyBytes", "bodySha256", "checkedAt"},
					   {Shape::TEXT, Shape::NUMBER, Shape::NUMBER, Shape::TEXT, Shape::TEXT}) ;
			break ;

		case Shape::SELECTION:	// 全INFまたは明示相対INFだけです。
			readObject( reader, {"mode", "paths"}, {Shape::TEXT, Shape::TEXTS}) ;
			break ;

		case Shape::REVIEW:	// 四確認を相互に代用しません。
			readObject( reader, {"official", "preDownload", "terms", "prerequisites"},
					   {Shape::SCOPE, Shape::SCOPE, Shape::SCOPE, Shape::PREREQUISITES}) ;
			break ;

		case Shape::SCOPE:	// 一確認の成功入力も実取得証拠にはしません。
			readObject( reader, {"state", "evidence"}, {Shape::TEXT, Shape::EVIDENCE}) ;
			break ;

		case Shape::PREREQUISITES:	// 条件の不明・有条件を空集合へ補完しません。
			readObject( reader, {"state", "evidence", "items"},
					   {Shape::TEXT, Shape::EVIDENCE, Shape::TEXTS}) ;
			break ;

		case Shape::EVIDENCE:	// 元pageの確認範囲を完全に保持します。
			readObject( reader, {"locatorId", "bodySha256", "contentSha256", "checkedAt", "scope"},
					   {Shape::TEXT, Shape::TEXT, Shape::TEXT, Shape::TEXT, Shape::TEXT}) ;
			break ;

		case Shape::JOB:	// 17field指定をこの新jobだけへ適用します。
			readObject( reader,
					   {"schema", "jobId", "profileRevision", "referenceSha256", "registry",
						"locators", "sourceFormat", "sourceId", "recordId", "source", "record",
						"products", "pageObservation", "container", "maximumBytes", "infSelection",
						"review"},
					   {Shape::TEXT, Shape::TEXT, Shape::TEXT, Shape::TEXT, Shape::BINDING,
						Shape::BINDING, Shape::TEXT, Shape::TEXT, Shape::TEXT, Shape::SOURCE,
						Shape::RECORD, Shape::PRODUCTS, Shape::PAGE, Shape::TEXT, Shape::NUMBER,
						Shape::SELECTION, Shape::REVIEW}) ;
			break ;
	}
}

/** @brief 非空の元文字列を上限内で取得します。
 * @param[in] object 型を字句検証済みのobjectです。
 * @param[in] name 必須fieldです。
 * @param[in] maximum UTF-16 code unit上限です。
 * @return 制御文字を含まない所有元文字列です。
 */
std::wstring text( const JsonObject &object, const wchar_t *name, const std::size_t maximum = 1024U)
{
	std::wstring value{object.GetNamedString( name)} ;	// 解除後の元値です。
	require( !value.empty() && value.size() <= maximum &&
			std::ranges::none_of( value, []( const wchar_t c) { return c < L' ' || c == L'\x7f' ; })) ;
	return value ;
}

/** @brief 公開不透明IDだけを検証します。
 * @param[in] value 元文字列です。
 */
void identity( const std::wstring_view value)
{
	require( !value.empty() && value.size() <= 80U && value.front() != L'-' &&
			value.find_first_not_of( L"abcdefghijklmnopqrstuvwxyz0123456789-") ==
				std::wstring_view::npos) ;
}

/** @brief 元表示fieldへ端末pathやcredential形状を混入させません。
 * @param[in] value 公開表示値です。
 */
void label( const std::wstring_view value)
{
	require( !value.empty() && isOfficialCollectorPublicText( value, 1024U)) ;
}

/** @brief Canonical SHA-256を検証します。
 * @param[in] value 元小文字hexです。
 */
void hash( const std::wstring_view value)
{
	require( value.size() == 64U &&
			value.find_first_not_of( L"0123456789abcdef") == std::wstring_view::npos) ;
}

/** @brief 原観測の小数秒を保持したまま暦日と秒を検証します。
 * @param[in] value UTC秒または小数1～6桁です。
 * @return 時刻比較用の元microsecondです。
 */
std::chrono::sys_time<std::chrono::microseconds> timestamp( const std::wstring_view value)
{
	const auto raw = winrt::to_string( value) ;	// 形式を変えないASCII時刻です。
	require( raw.back() == 'Z' &&
			(raw.size() == 20U || (raw.size() >= 22U && raw.size() <= 27U && raw[19] == '.'))) ;
	const auto seconds =
		// 実在する暦日です。
		signed_index_json::utc( raw.substr( 0U, 19U) + "Z", E_INVALIDARG) ;
	std::uint32_t fraction{} ;	// 元小数部を6桁microsecondへ対応させます。
	// 小数桁だけを検査し、欠損または7桁以上は受理しません。
	for( std::size_t index = 20U; index + 1U < raw.size(); ++index) {
		require( raw[index] >= '0' && raw[index] <= '9') ;
		fraction = fraction * 10U + static_cast<std::uint32_t>( raw[index] - '0') ;
	}

	// 明示小数の不足桁だけをmicrosecond単位へ換算します。
	for( std::size_t digits = raw.size() > 20U ? raw.size() - 21U : 6U; digits < 6U; ++digits) {
		fraction *= 10U ;
	}

	return seconds + std::chrono::microseconds{fraction} ;
}

/** @brief 重複しない元不透明ID配列を返します。
 * @param[in] values 字句検証済みの配列です。
 * @return 原順の全IDです。
 */
std::vector<std::wstring> identities( const JsonArray &values)
{
	std::vector<std::wstring> result ;	// 切捨てない有限原集合です。
	std::set<std::wstring>	  seen ;	// 完全一致だけの重複確認です。
	// 元配列を全て検証し、途中拒否時は一部集合を返しません。
	for( const auto &value : values) {
		std::wstring item{value.GetString()} ;	// 一つの元IDです。
		identity( item) ;
		require( seen.insert( item).second) ;
		result.push_back( std::move( item)) ;
	}

	return result ;
}

/** @brief 一般driverだけの採用済み台帳categoryを検証します。
 * @param[in] category 元分類です。
 */
void category( const std::wstring_view category)
{
	constexpr std::
		wstring_view
			CATEGORIES[]{L"LAN",   L"WIFI",	  L"BLUETOOTH",	  L"DISPLAY",
						 L"AUDIO", L"SERIAL", L"STORAGE",	  L"CHIPSET",
						 L"USB",   L"PRINT",  L"OTHER_DRIVER"} ;	// Firmware/appを含みません。
	require( std::ranges::find( CATEGORIES, category) != std::end( CATEGORIES)) ;
}

/** @brief Exact sourceを元jobから取得します。
 * @param[in] root 検証済みの元jobです。
 * @return 外部成功flagを持たないsource定義です。
 */
CollectorInspectionSource source( const JsonObject &root)
{
	const auto value = root.GetNamedObject( L"source") ;	// 同jobの一sourceです。
	return {text( value, L"rootUrl", 8192U), text( value, L"rootHost", 253U),
			text( value, L"payloadUrl", 8192U), text( value, L"payloadHost", 253U),
			text( value, L"href", 480U)} ;
}

/** @brief Archive相対INFの有限表記を検証します。
 * @param[in] value 原相対名です。
 */
void infPath( const std::wstring_view value)
{
	require( !value.empty() && value.size() <= 240U && !value.starts_with( L"\\") &&
			value.find_first_not_of(
				L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_. -\\") ==
				std::wstring_view::npos) ;
	std::wstring lower( value) ;	// 拡張子と重複判定だけのASCII小文字です。
	// 元相対名の大文字を比較用にだけ変換します。
	for( auto &c : lower) {
		// Archive名自体は変更しません。
		if( c >= L'A' && c <= L'Z') {
			c = static_cast<wchar_t>( c - L'A' + L'a') ;
		}
	}

	require( lower.ends_with( L".inf")) ;
	std::size_t start{} ;	// 各相対componentの始点です。
	// 全componentを検証し、絶対・dot・末尾曖昧形を拒否します。
	while( start < value.size()) {
		const auto end = value.find( L'\\', start) ;	// 次の区切りまたは終端です。
		const auto part =
			value.substr( start, end == std::wstring_view::npos ? value.size() - start
															   : end - start) ;	// 元componentです。
		require( !part.empty() && part != L"." && part != L".." && part.back() != L'.' &&
				part.back() != L' ') ;
		// 最後のcomponent検証後は必ず終了します。
		if( end == std::wstring_view::npos) {
			return ;
		}

		start = end + 1U ;
	}

	require( false) ;
}

/** @brief 全型を字句確認したjobの意味と内部参照を検証します。
 * @param[in] root 元DOMです。余分なfieldは事前に拒否済みです。
 * @return 共有recordに属する全製品参照数です。
 */
std::size_t validate( const JsonObject &root)
{
	require( text( root, L"schema") == L"dc-collector-registry-job-v2" &&
			text( root, L"sourceFormat") == L"STATIC_HTML_ANCHOR_V1") ;
	identity( text( root, L"jobId")) ;
	identity( text( root, L"profileRevision")) ;
	identity( text( root, L"sourceId")) ;
	identity( text( root, L"recordId")) ;
	hash( text( root, L"referenceSha256")) ;
	const auto registry = root.GetNamedObject( L"registry") ;	// 原台帳bindingです。
	const auto locators = root.GetNamedObject( L"locators") ;	// 原locator bindingです。
	require( text( registry, L"schema") == L"dc-public-driver-registry-v1" ||
			text( registry, L"schema") == L"dc-public-driver-registry-v2") ;
	require( text( locators, L"schema") == L"dc-public-driver-locators-v1" ||
			text( locators, L"schema") == L"dc-public-driver-locators-v2") ;
	// 両原世代の有限ID・暦日・hashを独立に検証します。
	for( const auto &binding : {registry, locators}) {
		identity( text( binding, L"revision")) ;
		require( text( binding, L"asOf").size() == 20U) ;
		static_cast<void>( timestamp( text( binding, L"asOf"))) ;
		hash( text( binding, L"sha256")) ;
	}

	const auto route = source( root) ;	// exact導線の未認証定義です。
	require( validateCollectorInspectionSource( route)) ;
	const auto maximum = root.GetNamedNumber( L"maximumBytes") ;	// Strict整数readerを通過済みです。
	require( maximum >= 1.0 && maximum <= static_cast<double>( COLLECTOR_INSPECTION_MAXIMUM_BYTES)) ;
	const auto container = text( root, L"container") ;	// 推測しない明示形式です。
	require( container == L"ZIP" || container == L"CAB") ;
	const auto record = root.GetNamedObject( L"record") ;	// 元一配布recordです。
	require( text( record, L"id") == text( root, L"recordId") &&
			text( record, L"sourceId") == text( root, L"sourceId")) ;
	const auto linkState = text( record, L"linkState") ;	// 元台帳の過去の観測状態です。
	// 未記載URLはMISSINGだけを受理し、locatorの後日の観測で元台帳を上書きしません。
	if( record.GetNamedValue( L"downloadUrl").ValueType() == JsonValueType::Null) {
		require( linkState == L"MISSING") ;
	} else {
		// 既知URLは従来どおり状態とexact取得経路の両方へ一致させます。
		require( (linkState == L"OFFICIAL_LINK" || linkState == L"HEAD_OK") &&
				text( record, L"downloadUrl", 8192U) == route.payloadUrl) ;
	}

	category( text( record, L"driverCategory")) ;
	label( text( record, L"title")) ;
	require( text( record, L"contentState") == L"NOT_DOWNLOADED") ;
	// Nullableな版は未知を保持し、入力成功へ補完しません。
	for( const auto name : {L"packageVersion", L"driverVersion"}) {
		// Null以外には公開表示文字列の規則を適用します。
		if( record.GetNamedValue( name).ValueType() != JsonValueType::Null) {
			label( text( record, name)) ;
		}
	}

	// 公開hashは存在時だけ実byte比較対象になります。
	if( record.GetNamedValue( L"publishedSha256").ValueType() != JsonValueType::Null) {
		hash( text( record, L"publishedSha256")) ;
	}

	// 日付は元暦日を検証し、現在日時へ補完しません。
	if( record.GetNamedValue( L"publishedDate").ValueType() != JsonValueType::Null) {
		const auto date = text( record, L"publishedDate") ;	// 元公開日です。
		require( date.size() == 10U) ;
		static_cast<void>( timestamp( date + L"T00:00:00Z")) ;
	}

	const auto os = record.GetNamedArray( L"operatingSystems") ;	// 台帳IDとは別の大文字OS列挙です。
	require( os.Size() > 0U && os.Size() <= 3U) ;
	std::set<std::wstring> osValues ;	// OS重複を完全一致で拒否します。
	// OSを未知やx86へ推測拡張しません。
	for( const auto &item : os) {
		const std::wstring value{item.GetString()} ;	// 元OS列挙値です。
		require( osValues.insert( value).second &&
				(value == L"WINDOWS_10_X64" || value == L"WINDOWS_11_X64" ||
				 value == L"WINDOWS_SERVER_X64")) ;
	}

	const auto products = root.GetNamedArray( L"products") ;	// 全共有製品です。
	require( products.Size() > 0U) ;
	std::set<std::wstring>							productIds ;	// 元IDの重複を拒否します。
	std::set<std::pair<std::wstring, std::wstring>> productNames ;	// 重複表示製品を拒否します。
	// 元全製品を一recordへ結合し、部分だけを実行しません。
	for( const auto &value : products) {
		const auto product = value.GetObject() ;		// 元一製品です。
		const auto id	   = text( product, L"id") ;	// 製品IDです。
		identity( id) ;
		require( productIds.insert( id).second) ;
		const auto manufacturer = text( product, L"manufacturer") ;	// 公開製造元です。
		const auto model		= text( product, L"model") ;		// 公開製品名です。
		label( manufacturer) ;
		label( model) ;
		require( productNames.emplace( manufacturer, model).second &&
				text( product, L"driverCategory") == text( record, L"driverCategory")) ;
		const auto sources =
			// 全元source参照です。
			identities( product.GetNamedArray( L"sourceIds")) ;
		const auto records =
			// 全元record参照です。
			identities( product.GetNamedArray( L"recordIds")) ;
		require( std::ranges::find( sources, text( root, L"sourceId")) != sources.end() &&
				std::ranges::find( records, text( root, L"recordId")) != records.end() &&
				text( product, L"researchState") == L"METADATA_SAVED" &&
				text( product, L"reason") == L"NONE") ;
	}

	const auto page = root.GetNamedObject( L"pageObservation") ;	// 手動確認に使った原観測です。
	require( text( page, L"method") == L"LOCAL_HTTP" && page.GetNamedNumber( L"httpStatus") == 200.0 &&
			page.GetNamedNumber( L"bodyBytes") >= 1.0 &&
			page.GetNamedNumber( L"bodyBytes") <= 2.0 * 1024.0 * 1024.0) ;
	hash( text( page, L"bodySha256")) ;
	const auto pageAt = timestamp( text( page, L"checkedAt")) ;	// 元観測時刻です。
	require( pageAt <= timestamp( text( locators, L"asOf"))) ;
	const auto review = root.GetNamedObject( L"review") ;	// 公式性認証と区別した手動確認です。
	const auto now	  = std::chrono::floor<std::chrono::microseconds>(
		   // 同じ検証の実現在です。
		   std::chrono::system_clock::now()) ;
	std::wstring contentHash ;	// 四scopeへ同じ比較値を結合します。
	std::wstring locatorId ;	// 同じ起点pageへの確認だけを今回の形式で受理します。
	const std::pair<const wchar_t *, const wchar_t *> scopes[]{
		{L"official", L"CONFIRMED"},
		{L"preDownload", L"NO_EXTRA_PROMPT"},
		{L"terms", L"NO_ADDITIONAL_TERMS"},
		{L"prerequisites", L"NONE_REQUIRED"}} ;	// 有条件や未知は実行不可です。
	// 全確認を同じ原PAGE hashへ結合し、手動確認時刻を観測以降・実現在以下へ限定します。
	for( const auto &[scope, expected] : scopes) {
		const auto item = review.GetNamedObject( scope) ;	// 一つの独立確認です。
		require( text( item, L"state") == expected) ;
		const auto evidence =
			// 成功boolの代わりではない元根拠です。
			item.GetNamedObject( L"evidence") ;
		const auto id = text( evidence, L"locatorId") ;	// 起点の公開locator IDです。
		identity( id) ;
		// 初回だけ根拠pageを固定し、別pageの確認借用を拒否します。
		if( locatorId.empty()) {
			locatorId	= id ;
			contentHash = text( evidence, L"contentSha256") ;
			hash( contentHash) ;
		}

		const auto reviewedAt =
			// このscopeを実際に確認した原時刻です。
			timestamp( text( evidence, L"checkedAt")) ;
		require( id == locatorId && text( evidence, L"scope") == scope &&
				text( evidence, L"bodySha256") == text( page, L"bodySha256") &&
				text( evidence, L"contentSha256") == contentHash && pageAt <= reviewedAt &&
				reviewedAt <= now) ;
	}

	require( review.GetNamedObject( L"prerequisites").GetNamedArray( L"items").Size() == 0U) ;
	const auto selection = root.GetNamedObject( L"infSelection") ;	// 元明示選択です。
	const auto paths	 = selection.GetNamedArray( L"paths") ;		// 全相対名です。
	const auto mode		 = text( selection, L"mode") ;				// ALLまたはSELECTEDです。
	require( (mode == L"ALL" && paths.Size() == 0U) ||
			(mode == L"SELECTED" && paths.Size() > 0U && paths.Size() <= 128U)) ;
	std::set<std::wstring> selected ;	// 大小文字だけ異なる重複を拒否します。
	// 明示相対INF名の全てを検証します。
	for( const auto &path : paths) {
		std::wstring value{path.GetString()} ;	// 元INF相対名です。
		infPath( value) ;
		// 重複比較だけの小文字化で実選択名は変えません。
		for( auto &c : value) {
			// ASCII大文字だけを元小文字へ対応させます。
			if( c >= L'A' && c <= L'Z') {
				c = static_cast<wchar_t>( c - L'A' + L'a') ;
			}
		}

		require( selected.insert( value).second) ;
	}

	return products.Size() ;
}

/** @brief 明示結果に原文字列を保存します。
 * @param[in,out] value 結果objectです。
 * @param[in] key 固定fieldです。
 * @param[in] text 元非秘密metadataです。
 */
void put( JsonObject &value, const wchar_t *key, const std::wstring_view text)
{
	value.Insert( key, JsonValue::CreateStringValue( text)) ;
}

/** @brief 明示結果に診断数値を保存します。
 * @param[in,out] value 結果objectです。
 * @param[in] key 固定fieldです。
 * @param[in] number 丸めのない32bit診断または有限byte数です。
 */
void putNumber( JsonObject &value, const wchar_t *key, const std::int64_t number)
{
	value.Insert( key, JsonValue::CreateNumberValue( static_cast<double>( number))) ;
}

/** @brief 私有HTTP観測の読取り値だけを明示結果へ投影します。
 * @param[in] transfer 同じ低位I/Oが生成した観測です。
 * @return 導入/取得権限やdecoderを持たない保存用objectです。
 */
JsonObject projectTransfer( const CollectorHttpTransferObservation &transfer)
{
	JsonObject output ;	// 実本文量と完了区分だけを保存します。
	put( output, L"stage",
		transfer.stage() == CollectorHttpTransferStage::PAGE	  ? L"PAGE"
		: transfer.stage() == CollectorHttpTransferStage::PAYLOAD ? L"PAYLOAD"
																  : L"UNSTARTED") ;
	putNumber( output, L"attemptedRequests", transfer.attemptedRequests()) ;
	putNumber( output, L"bodyBytesRead", static_cast<std::int64_t>( transfer.bodyBytesRead())) ;
	putNumber( output, L"terminalStatus", transfer.terminalStatus()) ;
	put( output, L"completion",
		transfer.completion() == CollectorHttpTransferCompletion::COMPLETE ? L"COMPLETE"
																		   : L"UNKNOWN") ;
	return output ;
}

/** @brief 同じ実保護INFの公開metadataとCAT signerだけを読みます。
 * @param[in] inf 通常署名検査が成功した元閉包です。
 * @param[out] identity 成功時の公開ID/ClassGUID/節です。失敗時空です。
 * @param[out] publisher 実Windows signerです。失敗時空です。
 * @return 全元内容の再確認0、未確認/署名失敗は元HRESULTです。
 */
NativeError readIdentity( const CommonInfInspection &inf, OfficialInfPublishedIdentity &identity,
						 std::wstring &publisher)
{
	identity = {} ;
	publisher.clear() ;
	// 公開ID成功を構造拒否や失敗閉包へ付けません。
	if( inf.state != CommonInfInspectionState::VERIFIED || inf.error != 0 || !inf.workspace ||
	   inf.closure.packages.size() != 1U) {
		return E_INVALIDARG ;
	}

	const auto &package = inf.closure.packages.front() ;	// 同検査が所有する元packageです。
	auto		error =
		// 元HINFの観測です。
		readOfficialInfPublishedIdentity( *inf.workspace, package, identity) ;
	// ID読取後に元全署名/memberを再確認します。
	if( error == 0) {
		error = verifyWindowsInfPackageIntegrity( *inf.workspace, package) ;
	}

	// PublisherをProvider文字列から合成しません。
	if( error == 0) {
		error = readWindowsInfPackagePublisher( *inf.workspace, package, publisher) ;
	}

	// 失敗時の一部公開identityを結果へ流しません。
	if( error != 0 || publisher.empty()) {
		identity = {} ;
		publisher.clear() ;
		return error != 0 ? error : E_INVALIDARG ;
	}

	return 0 ;
}

/** @brief 一公開INFの原節/IDを切捨てず明示結果へ射影します。
 * @param[in,out] row 個別結果objectです。
 * @param[in] inf 同通常検査の成功行です。
 * @param[in] identity 同元INFの公開観測です。
 * @param[in] publisher 同Windows CAT検査のsignerです。
 */
void projectIdentity( JsonObject &row, const CommonInfInspection &inf,
					 const OfficialInfPublishedIdentity &identity,
					 const std::wstring_view			 publisher)
{
	const auto &package = inf.closure.packages.front() ;	// 元packageの公開metadataです。
	put( row, L"infSha256", identity.infSha256) ;
	put( row, L"classGuid", identity.classGuid) ;
	put( row, L"className", package.className) ;
	put( row, L"driverVersion", package.driverVersion) ;
	put( row, L"driverDate", package.driverDate) ;
	put( row, L"provider", package.providerName) ;
	put( row, L"catalogIdentity", package.catalogRelativePath) ;
	put( row, L"verifiedPublisher", publisher) ;
	JsonArray models ;	// 原節ごとの全公開IDです。
	// 現OSでWindowsが選んだ元節を全て保持します。他OSの適合へ補完しません。
	for( const auto &section : identity.models) {
		JsonObject model ;	// 元一節です。
		put( model, L"modelSection", section.modelSection) ;
		JsonArray ids ;	// 元Hardware/Compatible種別付き全集合です。
		// ID種別ごとに元順を保持します。
		for( const bool compatible : {false, true}) {
			const auto &values =
				compatible ? section.compatibleIds : section.hardwareIds ;	// 同元節だけです。
			// IDを正規化・切捨て・コード列挙で補完しません。
			for( const auto &id : values) {
				JsonObject item ;	// 原公開IDです。
				put( item, L"kind", compatible ? L"COMPATIBLE" : L"HARDWARE") ;
				put( item, L"value", id) ;
				ids.Append( item) ;
			}
		}

		model.Insert( L"pnpIds", ids) ;
		models.Append( model) ;
	}

	row.Insert( L"models", models) ;
}
} // namespace

/** @see collector_registry_job.h */
NativeError parseCollectorRegistryJob( const std::string_view bytes,
									  CollectorRegistryJob	&job) noexcept
{
	job = {} ;
	try {
		Reader reader( bytes, E_INVALIDARG, COLLECTOR_REGISTRY_JOB_MAX_BYTES, 8U,
					  17U) ;	// 新jobだけ17fieldです。
		readShape( reader, Shape::JOB) ;
		reader.finish() ;
		const auto value =
			// 重複を拒否済みの元byteだけです。
			JsonObject::Parse( winrt::to_hstring( bytes)) ;
		const auto	 products = validate( value) ;					// 全意味/内部参照が成立した件数です。
		std::wstring digest ;										// 同原bytehashです。
		const auto	 error = computeBytesSha256( bytes, digest) ;	// 原fileの意味hashとは独立です。
		// CNG失敗を入力合格へ変換しません。
		if( error != 0) {
			return error ;
		}

		job.bytes_	  = bytes ;
		job.sha256_	  = std::move( digest) ;
		job.products_ = products ;
		return 0 ;
	} catch( const signed_index_json::Failure<NativeError> &failure) {
		return failure.status ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( const winrt::hresult_error &) {
		return E_INVALIDARG ;
	} catch( ...) {
		return E_UNEXPECTED ;
	}
}

/** @see collector_registry_job.h */
std::size_t CollectorRegistryJob::productCount() const noexcept
{
	return products_ ;
}
/** @see collector_registry_job.h */
std::string_view CollectorRegistryJobResult::json() const noexcept
{
	return bytes_ ;
}
/** @see collector_registry_job.h */
const CollectorHttpTransferObservation &CollectorRegistryJobResult::pageTransfer() const noexcept
{
	return pageTransfer_ ;
}
/** @see collector_registry_job.h */
const CollectorHttpTransferObservation &CollectorRegistryJobResult::payloadTransfer() const noexcept
{
	return payloadTransfer_ ;
}
/** @see collector_registry_job.h */
bool CollectorRegistryJobResult::pageReusedInRun() const noexcept
{
	return pageReusedInRun_ ;
}
/** @see collector_registry_job.h */
CollectorRegistryExecutionLimits::CollectorRegistryExecutionLimits(
	std::uint64_t payloadCapBytes, std::chrono::steady_clock::time_point deadline,
	std::function<std::chrono::steady_clock::time_point()> now)
	: payloadCapBytes_( payloadCapBytes), deadline_( deadline), now_( std::move( now))
{
}
/** @see collector_registry_job.h */
bool CollectorRegistryExecutionLimits::expired() const noexcept
{
	try {
		return (now_ ? now_() : std::chrono::steady_clock::now()) >= deadline_ ;
	} catch( ...) {
		return true ;
	}
}
/** @see collector_registry_job.h */
CollectorRegistryJobRunner::CollectorRegistryJobRunner( OfficialHttpTransport transport)
	: acquisition_( std::move( transport))
{
}

/** @see collector_registry_job.h */
NativeError CollectorRegistryJobRunner::run(
	const CollectorRegistryJob &job, const ScanSessionId sessionId,
	IOfficialNetworkCostReader &costReader, const HttpCancellationCallback &cancellation,
	const CollectorRegistryExecutionLimits &limits, CollectorRegistryJobResult &result,
	CollectorRunPageScope *pageScope, const CollectorRunPageProof *pageProof)
try {
	result = {} ;
	// 失敗runもscopeを消費し、別jobや保存成功JSONによる再取得を拒否します。
	if( std::exchange( used_, true) || sessionId == 0U || job.bytes_.empty()) {
		return E_INVALIDARG ;
	}

	const auto root		= JsonObject::Parse( winrt::to_hstring( job.bytes_)) ;	// 私有検証済みjobです。
	result.observation_ = CollectorRegistryVerifiedObservation{} ;
	auto &typed			= *result.observation_ ;	// 同じ実結果objectだけが全公開観測を所有します。
	typed.jobBytes_		= job.bytes_ ;
	typed.jobSha256_	= job.sha256_ ;
	const auto record	= root.GetNamedObject( L"record") ;	// 元公開hash等です。
	const auto maximum =
		// 検証済み1～32MiBです。
		static_cast<std::uint64_t>( root.GetNamedNumber( L"maximumBytes")) ;
	// 私有上限を拡大・ゼロ・期限切れ・不完全な借用contextから作りません。
	if( limits.payloadCapBytes_ == 0U || limits.payloadCapBytes_ > maximum ||
	   limits.payloadCapBytes_ > COLLECTOR_INSPECTION_MAXIMUM_BYTES || limits.expired() ||
	   (pageScope == nullptr && pageProof != nullptr)) {
		return E_INVALIDARG ;
	}

	const auto effective = std::min( maximum, limits.payloadCapBytes_) ;	// 原jobは変更しません。
	// 同じ期限とcaller取消しを各hop/read/通常検査へ渡します。
	const auto stop = [&limits, &cancellation]() {
		return limits.expired() || (cancellation && cancellation()) ;
	} ;
	const auto route = source( root) ;	// 同jobのexact導線です。
	const auto publishedHash =
		record.GetNamedValue( L"publishedSha256").ValueType() == JsonValueType::Null
			? std::wstring{}
			: text( record, L"publishedSha256") ;	// 未公開は空です。
	JsonObject output ;								// 明示結果file専用です。通常logには渡しません。
	put( output, L"schema", L"dc-collector-registry-native-result-v1") ;
	put( output, L"jobSha256", job.sha256_) ;
	output.Insert( L"job", root) ;
	putNumber( output, L"originalMaximumBytes", static_cast<std::int64_t>( maximum)) ;
	putNumber( output, L"effectiveMaximumBytes", static_cast<std::int64_t>( effective)) ;
	output.Insert( L"actualApplicabilityChecked", JsonValue::CreateBooleanValue( false)) ;
	output.Insert( L"installAuthorized", JsonValue::CreateBooleanValue( false)) ;
	put( output, L"modelsScope", L"CURRENT_WINDOWS_X64_SELECTION_ONLY") ;
	typed.windowsBuild_		 = currentWindowsBuildNumber() ;
	typed.windowsServer_	 = isWindowsServer() ;
	typed.windowsProductSku_ = currentWindowsProductSku() ;
	putNumber( output, L"inspectionWindowsBuild", typed.windowsBuild_) ;
	output.Insert( L"inspectionWindowsServer", JsonValue::CreateBooleanValue( typed.windowsServer_)) ;
	putNumber( output, L"inspectionWindowsProductSku", typed.windowsProductSku_) ;
	OfficialAcquisitionSession	 session ;		// 元取得と封印issuerを同runで保持します。
	OfficialDownloadWorkspace	 workspace ;	// 原archiveをrun終了まで保持します。
	OfficialAcquisitionResult	 acquired ;		// 生存sessionの実結果です。
	OfficialAcquiredFileEvidence evidence ;		// JSONから構築できない元取得証拠です。
	NativeError					 error =
		session.initialize( sessionId, {effective, effective, effective, 256ULL * 1024ULL * 1024ULL,
									   1U, 1U}) ;	// 空き容量境界を維持します。
	std::wstring reason = L"WORKSPACE_REJECTED" ;	// 全体失敗の独立理由です。
	// 無効workspaceでHTTPへ進みません。
	if( error == 0) {
		error = workspace.initialize( COLLECTOR_INSPECTION_PROVIDER_ID, sessionId) ;
	}

	const auto contentHash =
		text( root.GetNamedObject( L"review").GetNamedObject( L"official").GetNamedObject( L"evidence"),
			 L"contentSha256") ;	// 四scopeで一致済みです。
	// 同jobの容量・原公開hash・手動確認比較値へ実取得を固定します。
	if( error == 0) {
		reason = L"ACQUISITION_REJECTED" ;
		error  = pageScope != nullptr
					 ? acquisition_.acquireWithRunPage(
						   sessionId, route, session, workspace, costReader, stop, acquired,
						   effective, publishedHash, contentHash, *pageScope, pageProof)
					 : acquisition_.acquire( sessionId, route, session, workspace, costReader, stop,
											acquired, effective, publishedHash, contentHash) ;
	}

	result.pageTransfer_	= acquisition_.pageTransfer() ;
	result.payloadTransfer_ = acquisition_.payloadTransfer() ;
	result.pageReusedInRun_ = acquisition_.pageReusedInRun() ;
	output.Insert( L"pageTransfer", projectTransfer( result.pageTransfer_)) ;
	output.Insert( L"payloadTransfer", projectTransfer( result.payloadTransfer_)) ;
	output.Insert( L"pageReusedInRun", JsonValue::CreateBooleanValue( result.pageReusedInRun_)) ;
	putNumber( output, L"incrementalPageRequests",
			  result.pageReusedInRun_ ? 0U : result.pageTransfer_.attemptedRequests()) ;
	putNumber( output, L"incrementalPageBodyBytes",
			  static_cast<std::int64_t>(
				  result.pageReusedInRun_ ? 0U : result.pageTransfer_.bodyBytesRead())) ;

	const auto &observed = acquisition_.pageObservation() ;	// 同じ原HTTPの観測だけです。
	typed.page_			 = observed ;
	JsonObject observedPage ;	// 未取得時も0/空として保持します。
	putNumber( observedPage, L"httpStatus", observed.httpStatus) ;
	putNumber( observedPage, L"bodyBytes", static_cast<std::int64_t>( observed.bodyBytes)) ;
	put( observedPage, L"bodySha256", observed.bodySha256) ;
	put( observedPage, L"finalUrl", observed.finalUrl) ;
	putNumber( observedPage, L"requestCount", observed.requestCount) ;
	putNumber( observedPage, L"observedUtcSeconds",
			  observed.observedAtUtc.time_since_epoch().count()) ;
	output.Insert( L"pageObservation", observedPage) ;
	// 公開結果のboolで代用せず、私有issuerと原byteを確認します。
	if( error == 0) {
		reason = L"ACQUIRED_EVIDENCE_REJECTED" ;
		error  = session.bindAcquiredFile( workspace, acquired.acquisitionId, evidence) ;
	}

	// 入力hashと元生存取得の一致を再確認します。
	if( error == 0) {
		error = session.verifyAcquiredFile( evidence, workspace) ;
	}

	put( output, L"archiveSha256", acquired.sha256) ;
	typed.archiveSha256_ = acquired.sha256 ;
	typed.archiveBytes_	 = acquired.byteCount ;
	typed.routeVerified_ = error == 0 && acquisition_.sourceVerified() ;
	putNumber( output, L"archiveBytes", static_cast<std::int64_t>( acquired.byteCount)) ;
	output.Insert( L"sourceVerified",
				  JsonValue::CreateBooleanValue( error == 0 && acquisition_.sourceVerified())) ;
	JsonArray	rows ;			// 個別成功・拒否を全て保持します。
	std::size_t verified{} ;	// 公開metadataまで確認したINF数です。
	std::size_t rejected{} ;	// 個別拒否件数です。
	// 全体取得失敗時は検査を呼ばず、成功行を作りません。
	if( error == 0) {
		const DriverArchiveInput input{sessionId, acquired.inspectionPath, acquired.byteCount,
									   acquired.sha256} ;	// 封印検証済み元archiveです。
		const auto				 format = text( root, L"container") == L"ZIP"
											  ? OfficialDriverArchiveFormat::ZIP
											  : OfficialDriverArchiveFormat::CABINET ;	// 元明示形式です。
		const auto				 selection =
			// 全INFまたは明示有限集合です。
			root.GetNamedObject( L"infSelection") ;
		const auto paths  = selection.GetNamedArray( L"paths") ;		// 空なら全INFです。
		const auto passes = paths.Size() == 0U ? 1U : paths.Size() ;	// 明示集合を切り捨てません。
		reason			  = L"PACKAGE_INSPECTION_REJECTED" ;
		// 各明示INFを同じ原archiveへ通常検査し、全体拒否では全成功を無効にします。
		for( std::uint32_t pass = 0U; pass < passes; ++pass) {
			CommonDriverPackageInspection inspection ;	// 個別拒否を含む通常結果です。
			bool inspectedByProbe = false ;				// 専用unit以外では必ず本物検査を呼びます。
#ifdef DRIVERCRATE_REGISTRY_JOB_TESTING
			// Test専用TUのI/O seamだけです。製品buildには存在しません。
			if( inspectionProbe_) {
				error			 = inspectionProbe_( input, format, inspection) ;
				inspectedByProbe = true ;
			}
#endif
			// 成功JSONや通常設定から本物検査を省略する入口はありません。
			if( !inspectedByProbe) {
				error = paths.Size() == 0U
							? inspectCommonDriverPackage( input, format, inspection, stop)
							: inspectSelectedCommonDriverPackage(
								  input, format, std::wstring_view{paths.GetAt( pass).GetString()},
								  inspection, stop) ;
			}

			// 全体失敗・別archiveの結果は一部合格へ変換しません。
			if( error != 0 || inspection.error != 0 || inspection.scanSessionId != sessionId ||
			   inspection.archiveSha256 != acquired.sha256 ||
			   inspection.archiveBytes != acquired.byteCount || inspection.infs.empty() ||
			   inspection.infs.size() > 128U) {
				error = error != 0				? error
						: inspection.error != 0 ? inspection.error
												: static_cast<NativeError>( E_INVALIDARG) ;
				break ;
			}

			// 通常検査の全個別行を保持し、失敗を成功分母から消しません。
			for( const auto &inf : inspection.infs) {
				CollectorRegistryInfObservation observedInf ;	// 同じ個別検査の全元値です。
				observedInf.infIdentity			  = inf.infRelativePath ;
				observedInf.nestedArchiveIdentity = inf.nestedArchivePath ;
				observedInf.contentState		  = static_cast<std::uint32_t>( inf.state) ;
				observedInf.contentError		  = inf.error ;
				JsonObject row ;	// 公開相対名と元診断だけです。
				put( row, L"infIdentity", inf.infRelativePath) ;
				put( row, L"nestedArchiveIdentity", inf.nestedArchivePath) ;
				putNumber( row, L"contentState", static_cast<std::int64_t>( inf.state)) ;
				putNumber( row, L"contentError", inf.error) ;
				OfficialInfPublishedIdentity identity ;		// 同実INFだけの公開観測です。
				std::wstring				 publisher ;	// Windows signerです。
				NativeError					 identityError =
					 inf.error != 0 ? inf.error : E_INVALIDARG ;	// 未検査を成功0へしません。
				// 成功閉包だけを元metadata読取へ渡します。
				if( inf.state == CommonInfInspectionState::VERIFIED && inf.error == 0) {
					bool identityByProbe = false ;	// 専用unitだけのI/O置換状態です。
#ifdef DRIVERCRATE_REGISTRY_JOB_TESTING
					// Test専用の同検査I/Oだけを置換します。成功JSONを読みません。
					if( identityProbe_) {
						identityError	= identityProbe_( inf, identity, publisher) ;
						identityByProbe = true ;
					}
#endif
					// 通常buildでは必ず同Windows検査から公開metadataを取得します。
					if( !identityByProbe) {
						identityError = readIdentity( inf, identity, publisher) ;
					}
				}

				// 必須公開metadata不足も明示拒否へ残します。
				const bool accepted = identityError == 0 && !publisher.empty() &&
									  !identity.models.empty() && !identity.classGuid.empty() &&
									  // 導入適用性は含みません。
									  inf.closure.packages.size() == 1U ;
				// 元APIが成功してもpublisher等が欠損した結果は未知として診断します。
				if( !accepted && identityError == 0) {
					identityError = E_INVALIDARG ;
				}

				putNumber( row, L"identityError", identityError) ;
				put( row, L"status", accepted ? L"CONTENT_INSPECTED" : L"INF_REJECTED_OR_UNKNOWN") ;
				// 元成功INFだけへ公開情報を付けます。
				if( accepted) {
					projectIdentity( row, inf, identity, publisher) ;
					const auto &package = inf.closure.packages.front() ;	// 同じ検査が返したINFです。
					observedInf.identity		  = identity ;
					observedInf.className		  = package.className ;
					observedInf.driverVersion	  = package.driverVersion ;
					observedInf.driverDate		  = package.driverDate ;
					observedInf.provider		  = package.providerName ;
					observedInf.catalogIdentity	  = package.catalogRelativePath ;
					observedInf.verifiedPublisher = publisher ;
					++verified ;
				} else {
					++rejected ;
				}

				rows.Append( row) ;
				observedInf.identityError = identityError ;
				typed.infs_.push_back( std::move( observedInf)) ;
			}
		}

		// 検査中の元byte変更を全体拒否にし、公開成功を残しません。
		if( error == 0) {
			error = session.verifyAcquiredFile( evidence, workspace) ;
		}
	}

	// 全体失敗時は旧成功rowを配布へ利用できない状態に固定します。
	if( error != 0) {
		verified = 0U ;
		// 先行した成功行も全体失敗後は配布へ投影できません。失敗行自体は保持します。
		for( const auto &value : rows) {
			auto row = value.GetObject() ;	// 元個別診断を保持する行です。
			// 全体拒否前の内容成功を利用可能な行として残しません。
			if( row.GetNamedString( L"status") == L"CONTENT_INSPECTED") {
				put( row, L"status", L"DISCARDED_JOB_FAILURE") ;
			}
		}
	}

	putNumber( output, L"error", error) ;
	putNumber( output, L"verifiedInfs", static_cast<std::int64_t>( verified)) ;
	putNumber( output, L"rejectedInfs", static_cast<std::int64_t>( rejected)) ;
	result.outcome_ = error != 0	   ? L"FAILED"
					  : verified == 0U ? L"NO_VERIFIED_INF"
					  : rejected != 0U ? L"PARTIAL_FAILURE"
									   : L"CONTENT_INSPECTED" ;
	result.reason_	= error != 0	   ? reason
					  : rejected != 0U ? L"INDIVIDUAL_INF_REJECTED"
					  : verified == 0U ? L"NO_VERIFIED_INF"
									   : L"NONE" ;
	result.error_	= error ;
	put( output, L"status",
		error != 0		 ? L"FAILED"
		: verified == 0U ? L"NO_VERIFIED_INF"
		: rejected != 0U ? L"PARTIAL_FAILURE"
						 : L"CONTENT_INSPECTED") ;
	put( output, L"reason",
		error != 0		 ? reason
		: rejected != 0U ? L"INDIVIDUAL_INF_REJECTED"
		: verified == 0U ? L"NO_VERIFIED_INF"
						 : L"NONE") ;
	output.Insert( L"infs", rows) ;
	typed.jobError_	 = error ;
	typed.checkedAt_ = std::chrono::floor<std::chrono::seconds>( std::chrono::system_clock::now()) ;
	putNumber( output, L"contentCheckedUtcSeconds", typed.checkedAt_.time_since_epoch().count()) ;
	result.bytes_ = winrt::to_string( output.Stringify()) ;
	return error != 0						  ? error
		   : rejected != 0U || verified == 0U ? static_cast<NativeError>( S_FALSE)
											  : 0 ;
} catch( const std::bad_alloc &) {
	// 確保失敗後の部分JSONは公開せず、保護callerで予約をUNKNOWN_OUTCOMEへ残します。
	result					= {} ;
	result.pageTransfer_	= acquisition_.pageTransfer() ;
	result.payloadTransfer_ = acquisition_.payloadTransfer() ;
	result.pageReusedInRun_ = acquisition_.pageReusedInRun() ;
	return E_OUTOFMEMORY ;
} catch( const winrt::hresult_error &failure) {
	// 例外の任意textを出力せず、元HRESULTと結果欠損を保護callerへ返します。
	result					= {} ;
	result.pageTransfer_	= acquisition_.pageTransfer() ;
	result.payloadTransfer_ = acquisition_.payloadTransfer() ;
	result.pageReusedInRun_ = acquisition_.pageReusedInRun() ;
	return failure.code().value ;
} catch( ...) {
	// 途中取得・検査の例外も成功や再試行許可へ変換しません。
	result					= {} ;
	result.pageTransfer_	= acquisition_.pageTransfer() ;
	result.payloadTransfer_ = acquisition_.payloadTransfer() ;
	result.pageReusedInRun_ = acquisition_.pageReusedInRun() ;
	return E_UNEXPECTED ;
}
} // namespace drivercrate
