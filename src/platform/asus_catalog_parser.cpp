//------------------------------------------------------------------------------
/**
 * @file asus_catalog_parser.cpp
 * @brief ASUS公式support page parser実装。
 * @version 01.06.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WinRT collectionの直接依存を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/20  LAN／Wireless限定解析を明示引数として追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/20  汎用categoryと個別拒否の観測modeを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/28  収集専用の同一store解析・公開値拒否を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/28  収集専用公開値と暦日の検査を共通境界へ接続。
 * Ver.01.05.00 Shunji Ogawa  2026/09/28  収集target照合へ製品比較key規則を共有。
 * Ver.01.06.00 Shunji Ogawa  2026/09/28  共通controlをNuxt内部まで伝播し終了を型分離。
 * Ver.01.06.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note ASUS公式HTML内のNuxt JSONをscriptとして実行せず解析します。Schema、model、OS、originのいずれかが不明な場合は部分結果を公開しません。
 */
//------------------------------------------------------------------------------

#include "platform/asus_catalog_parser.h"
#include "platform/official_collector_public_text.h"

#include <Windows.h>

// Windows SDK 10.0.26100のWindowsNumerics.inlは宣言と定義のSAL差を/analyzeが報告する。
// DriverCrate sourceの警告は維持し、該当SDK headerを展開する区間だけ抑止する。
#pragma warning( push)
#pragma warning( disable : 28252 28253 6101)
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#pragma warning( pop)

#include <algorithm>
#include <array>
#include <cmath>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <new>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

/**
 * @brief JSON配列をWinRT参照で保持する。要素数と各要素のschema検証は利用側で行う。
 */
using JsonArray = winrt::Windows::Data::Json::JsonArray ;
/**
 * @brief JSON objectをWinRT参照で保持する。Copyは同じobjectを共有し、schema検証は利用側で行う。
 */
using JsonObject = winrt::Windows::Data::Json::JsonObject ;
/**
 * @brief JSON値をWinRT参照で保持する。所有byteの検証と型判定はreader側で行う。
 */
using JsonValue = winrt::Windows::Data::Json::IJsonValue ;
/**
 * @brief JSON値の実種別を表し、schemaで要求する型との一致を検査する。
 */
using JsonValueType = winrt::Windows::Data::Json::JsonValueType ;

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t		MAXIMUM_PAGE_CHARACTERS	 = 4U * 1024U * 1024U ;	// HTML文字数上限。
constexpr std::uint32_t		MAXIMUM_ROOT_VALUES		 = 65'536U ;			// Flattened JSON root要素数上限。
constexpr std::size_t		MAXIMUM_CATEGORIES		 = 64U ;				// Driver分類数上限。
constexpr std::size_t		MAXIMUM_RECORDS			 = 1'024U ;				// 全driver record数上限。
constexpr std::size_t		MAXIMUM_ENTRIES			 = 256U ;				// 公開するarchive数上限。
constexpr std::size_t		MAXIMUM_MODEL_CHARACTERS = 128U ;				// SMBIOS／page model名上限。
constexpr std::size_t		MAXIMUM_TEXT_CHARACTERS	 = 512U ;				// Category／title等の文字数上限。
constexpr std::size_t		MAXIMUM_URL_CHARACTERS	 = 2'048U ;				// Payload URL文字数上限。
// 一配布物の取得計画へ許可する最大byte数。
constexpr std::uint64_t		MAXIMUM_PAYLOAD_BYTES = 4ULL * 1024ULL * 1024ULL * 1024ULL ;
// 表示用概算sizeから取得上限を作る際の最小余裕byte数。
constexpr std::uint64_t		MINIMUM_SIZE_MARGIN_BYTES = 1ULL * 1024ULL * 1024ULL ;
// 公式page内のNuxt data要素を識別する固定attribute。
constexpr std::wstring_view NUXT_MARKER = L"id=\"__NUXT_DATA__\"" ;
// Nuxt dataをJSONとして扱うために要求するcontent type表現。
constexpr std::wstring_view JSON_TYPE_MARKER = L"type=\"application/json\"" ;
// JSON dataの探索をscript要素の内側へ限定する終端。
constexpr std::wstring_view SCRIPT_END = L"</script>" ;
// ASUS payload URLで許可する固定HTTPS origin。
constexpr std::wstring_view PAYLOAD_PREFIX = L"https://dlcdnets.asus.com" ;
// ASUS公式配布物として許可するpathの起点。
constexpr std::wstring_view PAYLOAD_PATH_PREFIX = L"/pub/ASUS/" ;
constexpr std::array<std::wstring_view, 14> SUPPORTED_DRIVER_CATEGORIES{
	L"Audio",	 L"Bluetooth", L"Card Reader", L"Camera",		   L"Chipset",
	L"Graphics", L"LAN",	   L"Networking",  L"Pointing Device", L"TouchPad",
	L"USB",		 L"VGA",	   L"VGA Drivers", L"Wireless",
} ; // G11で非boot-critical PnP INFを検査できるASUS page分類。

/**
 * @brief ASUS配布recordの解析結果を、拒否・対象外・取得前metadataとしての採用に分ける。
 */
enum class EntryParseResult {
	/// Record schemaまたは安全境界が不正。
	REJECTED,
	/// 正常recordだが対象OS、形式または公開hash条件の対象外。
	IGNORED,
	/// G11取得前metadataとして採用可能。
	ACCEPTED,
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief JSON文字列をUIやURL検証へ渡す前に有限な表示値へ制限する。
 *
 * @param[in] value 検証対象文字列。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] maximumCharacters 許可する最大UTF-16 code unit数。
 * @return 非空で制御文字を含まず上限内の場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidText( CollectorParserContext *control, const std::wstring_view value,
							   const std::size_t maximumCharacters)
{
	collectorParserCheckpoint( control) ;
	return !value.empty() && value.size() <= maximumCharacters &&
		   std::ranges::none_of( value, [&]( const wchar_t character) {
			   collectorParserStep( control) ;
			   return character == L'\0' || character < L' ' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 製品語と記号を削らず、部分一致へ縮退しない比較keyを作る。
 *
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] value ASUS pageまたはSMBIOS由来のmodel名。
 * @return ASCII英字を大文字化し空白を一つへ畳んだmodel名。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizeModel( CollectorParserContext *control,
										  const std::wstring_view value)
{
	collectorParserCheckpoint( control) ;
	std::wstring normalized ;	// Model完全一致に使用する比較key。
	normalized.reserve( value.size()) ;
	bool previousSpace{true} ;	// trueの場合は連続空白を追加しない。
	// Modelの全code unitを順番に正規化する。
	for( wchar_t character : value) {
		collectorParserStep( control) ;
		// 表示本文で連続空白として正規化するASCII文字かを示す。
		const bool whitespace =
			character == L' ' || character == L'\t' || character == L'\r' || character == L'\n' ;
		// 連続した整形空白を一つへ畳み、製品語間の区切りは維持する。
		if( whitespace) {
			// 同じ連続空白から比較keyへ複数の区切りを追加しない。
			if( !previousSpace) {
				normalized.push_back( L' ') ;
				previousSpace = true ;
			}

			continue ;
		}

		// NULと制御文字を含む製品名から比較keyを作らない。
		if( character == L'\0' || character < L' ') {
			return {} ;
		}

		// ASCII英字の大小だけを揃え、製品記号や非ASCII文字を保持する。
		if( character >= L'a' && character <= L'z') {
			character = static_cast<wchar_t>( character - L'a' + L'A') ;
		}

		normalized.push_back( character) ;
		previousSpace = false ;
	}

	// 正規化で残った末尾の区切り空白を除く。
	if( !normalized.empty() && normalized.back() == L' ') {
		normalized.pop_back() ;
	}

	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief Double表現のfraction、負値、範囲外を参照として拒否する。
 *
 * @param[in] root Nuxt flattened root array。
 * @param[in] reference Root要素を指すJSON number。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] index 成功時のroot内index。
 * @return 非負整数でroot範囲内の場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool resolveIndex( CollectorParserContext *control, const JsonArray &root,
								const JsonValue &reference, std::uint32_t &index)
{
	collectorParserCheckpoint( control) ;
	index = 0U ;
	// 数値型でないflattened参照を配列indexとして解釈しない。
	if( reference.ValueType() != JsonValueType::Number) {
		return false ;
	}

	const double number = reference.GetNumber() ;	// Nuxtが出力した参照index値。
	// 非有限値・負値・配列範囲外の参照を整数化前に拒否する。
	if( !std::isfinite( number) || number < 0.0 || number >= static_cast<double>( root.Size())) {
		return false ;
	}

	const auto converted = static_cast<std::uint32_t>( number) ;	// 範囲検証済み整数候補。
	// 小数を切り捨てて別の参照先へ解決しない。
	if( number != static_cast<double>( converted)) {
		return false ;
	}

	index = converted ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Field値そのものを信用せずflattened rootへ一段だけ解決する。
 *
 * @param[in] root Nuxt flattened root array。
 * @param[in] object 参照fieldを持つobject。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] name 取得するfield名。
 * @return 有効な参照先JSON value。欠損または不正参照時はnullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<JsonValue> resolveValue( CollectorParserContext *control,
													const JsonArray &root, const JsonObject &object,
													const std::wstring_view name)
{
	collectorParserCheckpoint( control) ;
	// 必須fieldがないobjectから参照値を取得しない。
	if( !object.HasKey( name)) {
		return std::nullopt ;
	}

	std::uint32_t index{} ;	// 解決したroot内index。
	// fieldの参照indexを検証できない場合は未解決として返す。
	if( !resolveIndex( control, root, object.GetNamedValue( name), index)) {
		return std::nullopt ;
	}

	return root.GetAt( index) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 必須文字列fieldの型、参照、内容を一箇所で検証する。
 *
 * @param[in] root Nuxt flattened root array。
 * @param[in] object 参照fieldを持つobject。
 * @param[in] name 取得するfield名。
 * @param[in] maximumCharacters 許可する文字数上限。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] output 成功時の文字列。失敗時は空。
 * @return 参照先が有限な非空文字列の場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool resolveString( CollectorParserContext *control, const JsonArray &root,
								 const JsonObject &object, const std::wstring_view name,
								 const std::size_t maximumCharacters, std::wstring &output)
{
	collectorParserCheckpoint( control) ;
	output.clear() ;
	const std::optional<JsonValue> value = resolveValue( control, root, object, name) ;	// 解決値。
	// 解決先が文字列でない必須fieldを受理しない。
	if( !value.has_value() || value->ValueType() != JsonValueType::String) {
		return false ;
	}

	const auto text = value->GetString() ;	// 埋込みNULを切り捨てず保持するWinRT文字列。
	output.assign( text.c_str(), text.size()) ;
	return isValidText( control, output, maximumCharacters) ;
}

//------------------------------------------------------------------------------
/**
 * @brief OS IDをlocaleに依存しない有限な識別子へ制限する。
 *
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] value 検証対象文字列。
 * @return 一文字以上のASCII decimalだけの場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAsciiDecimal( CollectorParserContext *control, const std::wstring_view value)
{
	collectorParserCheckpoint( control) ;
	return !value.empty() && value.size() <= 8U &&
		   std::ranges::all_of( value, [&]( const wchar_t character) {
			   collectorParserStep( control) ;
			   return character >= L'0' && character <= L'9' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 任意の表示文字列ではなくpage data objectだけからmodelを得る。
 *
 * @param[in] root Nuxt flattened root array。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] model 一意に確認したASUS page model名。
 * @return `model`／`productId`／`downloadUrl` objectが一件の場合`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool findPageModel( CollectorParserContext *control, const JsonArray &root,
								 std::wstring &model)
{
	collectorParserCheckpoint( control) ;
	model.clear() ;
	std::size_t matches{} ;	// Page model objectの一致件数。
	// Rootの全objectからpage data schemaだけを探す。
	for( std::uint32_t index = 0U; index < root.Size(); ++index) {
		collectorParserStep( control) ;
		const JsonValue value = root.GetAt( index) ;	// 現在検証するroot値。
		// object以外の値を製品page data候補として調べない。
		if( value.ValueType() != JsonValueType::Object) {
			continue ;
		}

		const JsonObject object = value.GetObject() ;	// 現在のroot object。
		// 製品dataを識別する三fieldが揃わないobjectを対象外にする。
		if( !object.HasKey( L"model") || !object.HasKey( L"productId") ||
		   !object.HasKey( L"downloadUrl")) {
			continue ;
		}

		std::wstring current ;	// 現在objectから解決するmodel名。
		// 製品modelの文字列参照が不正なら一覧全体を拒否する。
		if( !resolveString( control, root, object, L"model", MAXIMUM_MODEL_CHARACTERS, current)) {
			return false ;
		}

		++matches ;
		// 製品dataが複数一致する場合は一意に選ばず拒否する。
		if( matches != 1U) {
			return false ;
		}

		model = std::move( current) ;
	}

	return matches == 1U ;
}

//------------------------------------------------------------------------------
/**
 * @brief Driver recordのopaque IDを対象OSへfail-closedで拘束する。
 *
 * @param[in] root Nuxt flattened root array。
 * @param[in] osName 利用者端末に対応するASUS page OS名。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] osId 一意に解決したASCII decimal OS ID。
 * @return 同じ名前が一つの有効IDだけを指す場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool findOsId( CollectorParserContext *control, const JsonArray &root,
							const std::wstring_view osName, std::wstring &osId)
{
	collectorParserCheckpoint( control) ;
	osId.clear() ;
	// OS表示名の文字列境界が不正ならOS参照を解決しない。
	if( !isValidText( control, osName, MAXIMUM_TEXT_CHARACTERS)) {
		return false ;
	}

	// RootのId／Name objectを調べ、指定OS名と完全一致するIDを探す。
	for( std::uint32_t index = 0U; index < root.Size(); ++index) {
		collectorParserStep( control) ;
		const JsonValue value = root.GetAt( index) ;	// 現在検証するroot値。
		// object以外の値をOS選択肢として扱わない。
		if( value.ValueType() != JsonValueType::Object) {
			continue ;
		}

		const JsonObject object = value.GetObject() ;	// OS選択肢候補object。
		// IDとNameが揃わないobjectをOS選択肢から除く。
		if( !object.HasKey( L"Id") || !object.HasKey( L"Name")) {
			continue ;
		}

		std::wstring name ;	// 現在objectの表示名。
		std::wstring id ;	// 現在objectのID。
		// OS名を解決できない場合と指定名に一致しない場合は採用しない。
		if( !resolveString( control, root, object, L"Name", MAXIMUM_TEXT_CHARACTERS, name) ||
		   name != osName) {
			continue ;
		}

		// OS IDの不正表記と同名OSに異なるIDがある曖昧な対応を拒否する。
		if( !resolveString( control, root, object, L"Id", 8U, id) || !isAsciiDecimal( control, id) ||
		   (!osId.empty() && osId != id)) {
			return false ;
		}

		osId = std::move( id) ;
	}

	return !osId.empty() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公開表示をexact sizeとして扱わず、取得拒否用上限だけ作る。
 *
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] value ASUS pageの丸め済みKB／MB／GB表示。
 * @return 表示sizeへ5%または1 MiBの余裕を加えた上限。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::uint64_t> parseDisplaySize( CollectorParserContext *control,
															const std::wstring_view value)
{
	collectorParserCheckpoint( control) ;
	const std::size_t space = collectorParserFind( control, value, L' ') ;	// 数値と単位の境界。
	// 数値と単位の両方を分離できない容量表記は解析しない。
	if( space == std::wstring_view::npos || space == 0U || space + 1U >= value.size()) {
		return std::nullopt ;
	}

	const std::wstring_view number	= value.substr( 0U, space) ;					// ASCII decimal size。
	const std::wstring_view unit	= value.substr( space + 1U) ;					// Binary換算する単位。
	const std::size_t		decimal = collectorParserFind( control, number, L'.') ;	// 小数点位置。
	// 小数点が重複した容量表記を拒否する。
	if( decimal != std::wstring_view::npos &&
	   collectorParserFind( control, number, L'.', decimal + 1U) != std::wstring_view::npos) {
		return std::nullopt ;
	}

	const std::wstring_view integral =
		// 整数部。
		decimal == std::wstring_view::npos ? number : number.substr( 0U, decimal) ;
	// 表示容量の小数部分。整数表記では空のviewを使用する。
	const std::wstring_view fractional =
		decimal == std::wstring_view::npos ? std::wstring_view{} : number.substr( decimal + 1U) ;
	// 整数部欠落と小数部の桁数不正を取得上限へ変換しない。
	if( integral.empty() || fractional.size() > 3U ||
	   (decimal != std::wstring_view::npos && fractional.empty())) {
		return std::nullopt ;
	}

	std::uint64_t numerator{} ;	// 小数点を除去したsize分子。
	// 整数部をoverflow検証しながら読む。
	for( const wchar_t character : integral) {
		collectorParserStep( control) ;
		// 整数部の非数字と桁追加時のoverflowを拒否する。
		if( character < L'0' || character > L'9' ||
		   numerator > (std::numeric_limits<std::uint64_t>::max() - 9U) / 10U) {
			return std::nullopt ;
		}

		numerator = numerator * 10U + static_cast<std::uint64_t>( character - L'0') ;
	}

	std::uint64_t scale{1U} ;	// 小数桁数に対応する10の累乗。
	// 小数部を分子へ追加する。
	for( const wchar_t character : fractional) {
		collectorParserStep( control) ;
		// 小数部にも数字検証と整数overflow制限を適用する。
		if( character < L'0' || character > L'9' ||
		   numerator > (std::numeric_limits<std::uint64_t>::max() - 9U) / 10U) {
			return std::nullopt ;
		}

		numerator = numerator * 10U + static_cast<std::uint64_t>( character - L'0') ;
		scale *= 10U ;
	}

	const std::uint64_t multiplier = unit == L"KB"	 ? 1024ULL
									 : unit == L"MB" ? 1024ULL * 1024ULL
									 : unit == L"GB" ? 1024ULL * 1024ULL * 1024ULL
													 : 0U ;	// ASUS表示単位のbinary multiplier。
	// ゼロ容量、未知単位、倍率によるoverflowを拒否する。
	if( numerator == 0U || multiplier == 0U ||
	   numerator > std::numeric_limits<std::uint64_t>::max() / multiplier) {
		return std::nullopt ;
	}

	const std::uint64_t product = numerator * multiplier ;	// Scale適用前のbyte分子。
	const std::uint64_t rounded =
		product / scale + (product % scale == 0U ? 0U : 1U) ;	// 切り上げ表示byte数。
	const std::uint64_t margin =
		// 丸め差を吸収する5%以上の余裕。
		std::max( MINIMUM_SIZE_MARGIN_BYTES, rounded / 20U) ;
	// 丸め値に余裕量を加えた取得上限がpayloadの固定上限を超えないよう拒否する。
	if( rounded > MAXIMUM_PAYLOAD_BYTES || margin > MAXIMUM_PAYLOAD_BYTES - rounded) {
		return std::nullopt ;
	}

	return rounded + margin ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公開hashをG11取得時のexact identityとして使用可能にする。
 *
 * @param[in] value ASUS pageが公開するSHA-256。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] normalized 成功時の小文字64桁hex。
 * @return 64桁ASCII hexadecimalの場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool normalizeSha256( CollectorParserContext *control, const std::wstring_view value,
								   std::wstring &normalized)
{
	collectorParserCheckpoint( control) ;
	normalized.clear() ;
	// SHA-256の64桁を満たさない公開hashを受理しない。
	if( value.size() != 64U) {
		return false ;
	}

	normalized.reserve( value.size()) ;
	// 全hex digitを検証し小文字へ統一する。
	for( wchar_t character : value) {
		collectorParserStep( control) ;
		// hash内のASCII数字は値を変えず保持する。
		if( character >= L'0' && character <= L'9') {
			normalized.push_back( character) ;
		}
		// hash内の小文字十六進英字は正規形として保持する。
		else if( character >= L'a' && character <= L'f') {
			normalized.push_back( character) ;
		}
		// hash内の大文字十六進英字だけを小文字表記へ揃える。
		else if( character >= L'A' && character <= L'F') {
			normalized.push_back( static_cast<wchar_t>( character - L'A' + L'a')) ;
		} else {
			normalized.clear() ;
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Calendar変換を行わず、表示metadataの不正構文だけを拒否する。
 *
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] value ASUS pageの公開日。
 * @return `YYYY/MM/DD`の構文と基本範囲を満たす場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidReleaseDate( CollectorParserContext *control,
									  const std::wstring_view value)
{
	collectorParserCheckpoint( control) ;
	// 公開日の固定長と区切り位置が一致しない表記を拒否する。
	if( value.size() != 10U || value[4] != L'/' || value[7] != L'/') {
		return false ;
	}

	// Separator以外が全てASCII digitであることを確認する。
	for( std::size_t index = 0U; index < value.size(); ++index) {
		collectorParserStep( control) ;
		// 固定位置のslashは日付の数字検証から除く。
		if( index == 4U || index == 7U) {
			continue ;
		}

		// 日付fieldにASCII数字以外を許可しない。
		if( value[index] < L'0' || value[index] > L'9') {
			return false ;
		}
	}

	// 固定日付形式の月fieldを十進数へ復号した値。
	const unsigned month = static_cast<unsigned>( (value[5] - L'0') * 10 + value[6] - L'0') ;
	// 固定日付形式の日fieldを十進数へ復号した値。
	const unsigned day = static_cast<unsigned>( (value[8] - L'0') * 10 + value[9] - L'0') ;
	return month >= 1U && month <= 12U && day >= 1U && day <= 31U ;
}

//------------------------------------------------------------------------------
/**
 * @brief URL拡張子とfile名をlocale非依存で比較する。
 *
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] value ASCII比較する文字列。
 * @return ASCII英字だけを小文字化した複製。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring lowerAscii( CollectorParserContext *control,
									  const std::wstring_view value)
{
	collectorParserCheckpoint( control) ;
	std::wstring lowered( value) ;	// 小文字化する複製。
	std::ranges::transform( lowered, lowered.begin(), [&]( const wchar_t character) {
		collectorParserStep( control) ;
		return character >= L'A' && character <= L'Z'
				   ? static_cast<wchar_t>( character - L'A' + L'a')
				   : character ;
	}) ;
	return lowered ;
}

//------------------------------------------------------------------------------
/**
 * @brief Origin、path traversal、record IDとのfile差替えを拒否する。
 *
 * @param[in] path Nuxt JSONのGlobal download相対path。
 * @param[in] opaqueId OSとfile名を含むASUS record ID。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] url 成功時の固定ASUS CDN絶対URL。
 * @return ZIP／CABはAccepted、他形式はIgnored、不正pathはRejected。
 */
//------------------------------------------------------------------------------
[[nodiscard]] EntryParseResult validatePayloadPath( CollectorParserContext *control,
												   const std::wstring_view path,
												   const std::wstring_view opaqueId,
												   std::wstring			  &url)
{
	collectorParserCheckpoint( control) ;
	url.clear() ;
	// 固定path起点・長さ・区切り・traversal条件に違反するpayloadを拒否する。
	if( !path.starts_with( PAYLOAD_PATH_PREFIX) || path.size() > MAXIMUM_URL_CHARACTERS ||
	   collectorParserFindSet( control, path, L"?#\\\0", false, false) != std::wstring_view::npos ||
	   collectorParserFind( control, path, L"//") != std::wstring_view::npos ||
	   collectorParserFind( control, path, L"/../") != std::wstring_view::npos ||
	   collectorParserFind( control, path, L"/./") != std::wstring_view::npos) {
		return EntryParseResult::REJECTED ;
	}

	const std::size_t slash =
		// Payload file名の開始境界。
		collectorParserFindSet( control, path, L"/", false, true) ;
	// basenameを切り出せないpayload pathを受理しない。
	if( slash == std::wstring_view::npos || slash + 1U >= path.size()) {
		return EntryParseResult::REJECTED ;
	}

	const std::wstring_view fileName = path.substr( slash + 1U) ;	// CDN上のpayload file名。
	const std::size_t		idSeparator =
		// ID内file名境界。
		collectorParserFindSet( control, opaqueId, L"@", false, true) ;
	// opaque record IDと実際のfile名が対応しなければ差替えとして拒否する。
	if( idSeparator == std::wstring_view::npos ||
	   lowerAscii( control, opaqueId.substr( idSeparator + 1U)) != lowerAscii( control, fileName)) {
		return EntryParseResult::REJECTED ;
	}

	const std::wstring lowered = lowerAscii( control, fileName) ;	// 拡張子判定用file名。
	// 監査対象のZIP・CAB以外は取得候補から除外する。
	if( !lowered.ends_with( L".zip") && !lowered.ends_with( L".cab")) {
		return EntryParseResult::IGNORED ;
	}

	url = std::wstring( PAYLOAD_PREFIX) + std::wstring( path) ;
	return EntryParseResult::ACCEPTED ;
}

//------------------------------------------------------------------------------
/**
 * @brief Architectureはx64のOS選択肢で拘束し、製品別に変わる第2 fieldをarchitectureと推測しない。
 *
 * @param[in] opaqueId ASUS flattened record ID。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] osId Page OS選択肢から解決したID。
 * @return 先頭6 fieldがdecimalの7 field schemaでOS ID一致時は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool recordMatchesOs( CollectorParserContext *control,
								   const std::wstring_view opaqueId, const std::wstring_view osId)
{
	collectorParserCheckpoint( control) ;
	std::vector<std::wstring_view> fields ;	// `@`で分割したrecord field群。
	fields.reserve( 7U) ;
	std::size_t begin{} ;	// 現在fieldの開始位置。
	// 全separatorを順番に処理し、空fieldを許可しない。
	while( begin <= opaqueId.size()) {
		collectorParserStep( control) ;
		const std::size_t end =
			// 現在fieldの終端。
			collectorParserFind( control, opaqueId, L'@', begin) ;
		const std::wstring_view field = end == std::wstring_view::npos
											? opaqueId.substr( begin)
											: opaqueId.substr( begin, end - begin) ;	// Field値。
		// 空fieldまたは七fieldを超えるopaque IDを受理しない。
		if( field.empty() || fields.size() >= 7U) {
			return false ;
		}

		fields.push_back( field) ;
		// 区切りが尽きた時点でopaque IDの分解を終了する。
		if( end == std::wstring_view::npos) {
			break ;
		}

		begin = end + 1U ;
	}

	// field数と選択済みOS IDが一致しなければrecordを対象にしない。
	if( fields.size() != 7U || fields[4] != osId) {
		return false ;
	}

	// File名を除くASUS内部ID fieldが有限なdecimalであることを確認する。
	for( std::size_t index = 0U; index + 1U < fields.size(); ++index) {
		collectorParserStep( control) ;
		// 数値と定義されたopaque fieldにASCII数字以外を許可しない。
		if( !isAsciiDecimal( control, fields[index])) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASUS page分類をPnP driver検査対象へ限定する。
 *
 * Software／UtilityとSATA／RAIDを取得前に除外する。Unknown分類を推測でdriver扱いせず、G11監査量を有限に保つ。
 *
 * @param[in] category ASUS pageが表示する分類名。
 * @return 非boot-critical PnP driverを含み得る既知分類なら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSupportedDriverCategory( const std::wstring_view category) noexcept
{
	return std::ranges::find( SUPPORTED_DRIVER_CATEGORIES, category) !=
		   SUPPORTED_DRIVER_CATEGORIES.end() ;
}

//------------------------------------------------------------------------------
/**
 * @brief URL、hash、sizeは取得用入力に限定し、INF適用性を推測しない。
 *
 * @param[in] root Nuxt flattened root array。
 * @param[in] record ASUS driver record object。
 * @param[in] category 親driver分類。
 * @param[in] osId 対象OSのASUS ID。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] entry Accepted時の取得前metadata。
 * @return Schema不正、対象外または採用可能の三状態。
 */
//------------------------------------------------------------------------------
[[nodiscard]] EntryParseResult parseDriverRecord( CollectorParserContext *control,
												 const JsonArray &root, const JsonObject &record,
												 const std::wstring_view category,
												 const std::wstring_view osId,
												 AsusDriverPageEntry	&entry)
{
	collectorParserCheckpoint( control) ;
	entry = {} ;
	std::wstring opaqueId ;		// ASUS record ID。
	std::wstring version ;		// Page表示version。
	std::wstring title ;		// Page表示title。
	std::wstring fileSize ;		// 丸め済みpage表示size。
	std::wstring releaseDate ;	// Page表示公開日。
	// recordの必須表示fieldと公開日を解決できなければ拒否する。
	if( !resolveString( control, root, record, L"Id", MAXIMUM_TEXT_CHARACTERS, opaqueId) ||
	   !resolveString( control, root, record, L"Version", MAXIMUM_TEXT_CHARACTERS, version) ||
	   !resolveString( control, root, record, L"Title", MAXIMUM_TEXT_CHARACTERS, title) ||
	   !resolveString( control, root, record, L"FileSize", 64U, fileSize) ||
	   !resolveString( control, root, record, L"ReleaseDate", 32U, releaseDate) ||
	   !isValidReleaseDate( control, releaseDate)) {
		return EntryParseResult::REJECTED ;
	}

	const std::optional<std::uint64_t> maximumDownloadBytes =
		// 丸め差を含む取得上限。
		parseDisplaySize( control, fileSize) ;
	// 有限な取得上限を確定できないrecordを取得候補にしない。
	if( !maximumDownloadBytes.has_value()) {
		return EntryParseResult::REJECTED ;
	}

	const std::optional<JsonValue> downloadValue =
		// Download origin object。
		resolveValue( control, root, record, L"DownloadUrl") ;
	// download fieldの参照先がobjectでなければ拒否する。
	if( !downloadValue.has_value() || downloadValue->ValueType() != JsonValueType::Object) {
		return EntryParseResult::REJECTED ;
	}

	const JsonObject download = downloadValue->GetObject() ;	// Global／China path保持object。
	std::wstring	 path ;										// 固定ASUS CDNへ接続するGlobal相対path。
	// Global配布pathを文字列として解決できなければ拒否する。
	if( !resolveString( control, root, download, L"Global", MAXIMUM_URL_CHARACTERS, path)) {
		return EntryParseResult::REJECTED ;
	}

	std::wstring		   downloadUrl ;	// Originとpathを検証済みの絶対URL。
	// 配布pathを検証し、opaque IDとURLへ分離した結果区分。
	const EntryParseResult pathResult = validatePayloadPath( control, path, opaqueId, downloadUrl) ;
	// path検証の拒否または対象外判定を後続処理で成功へ変えない。
	if( pathResult != EntryParseResult::ACCEPTED) {
		return pathResult ;
	}

	const std::optional<JsonValue> sha256Json =
		// 公開SHA-256の参照解決結果。
		resolveValue( control, root, record, L"sha256") ;
	// 公開SHA-256 fieldの欠落や型不一致を拒否する。
	if( !sha256Json.has_value() || sha256Json->ValueType() != JsonValueType::String) {
		return EntryParseResult::REJECTED ;
	}

	std::wstring sha256Value = sha256Json->GetString().c_str() ;	// Pageが公開するhash文字列。
	// 公開hashが空のrecordは検証可能な取得候補から除外する。
	if( sha256Value.empty()) {
		return EntryParseResult::IGNORED ;
	}

	// 公開hashに長さ・文字列境界の不正がある場合は拒否する。
	if( !isValidText( control, sha256Value, 64U)) {
		return EntryParseResult::REJECTED ;
	}

	std::wstring sha256 ;	// 小文字へ正規化した公開SHA-256。
	// 公開hashを64桁の十六進値として正規化できなければ拒否する。
	if( !normalizeSha256( control, sha256Value, sha256)) {
		return EntryParseResult::REJECTED ;
	}

	// OS不一致、未対応category、markup混入titleのrecordは候補化しない。
	if( !recordMatchesOs( control, opaqueId, osId) || !isSupportedDriverCategory( category) ||
	   collectorParserFindSet( control, title, L"<>", false, false) != std::wstring::npos) {
		return EntryParseResult::IGNORED ;
	}

	entry = {.category			   = std::wstring( category),
			 .opaqueId			   = std::move( opaqueId),
			 .title				   = std::move( title),
			 .version			   = std::move( version),
			 .releaseDate		   = std::move( releaseDate),
			 .downloadUrl		   = std::move( downloadUrl),
			 .sha256			   = std::move( sha256),
			 .maximumDownloadBytes = *maximumDownloadBytes} ;
	return EntryParseResult::ACCEPTED ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一recordの不正を無視せず、部分的な公式一覧へ縮退しない。
 *
 * @param[in] root Nuxt flattened root array。
 * @param[in] osId 対象OSのASUS ID。
 * @param[out] entries 全成功時のSHA-256付きarchive一覧。
 * @param[in] expectedCategory 空なら全record、明示時は指定category本文だけを検証する。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] observation 非nullなら全体構造を維持した行単位拒否を集計する。
 * @return 全category構造と指定範囲のrecord本文が有限schemaを満たす場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool collectDriverEntries( CollectorParserContext *control, const JsonArray &root,
										const std::wstring_view			  osId,
										std::vector<AsusDriverPageEntry> &entries,
										const std::wstring_view			  expectedCategory,
										AsusDriverCatalogObservation	 *observation)
{
	collectorParserCheckpoint( control) ;
	entries.clear() ;
	std::size_t						 categoryCount{} ;	// 検証したdriver category object数。
	std::size_t						 recordCount{} ;	// 検証した全driver record数。
	std::unordered_set<std::wstring> urls ;				// 重複差替えを拒否する絶対URL集合。
	// Rootの全objectからName／Files category schemaだけを処理する。
	for( std::uint32_t index = 0U; index < root.Size(); ++index) {
		collectorParserStep( control) ;
		const JsonValue value = root.GetAt( index) ;	// 現在検証するroot値。
		// object以外のflattened値をcategoryとして解析しない。
		if( value.ValueType() != JsonValueType::Object) {
			continue ;
		}

		const JsonObject object = value.GetObject() ;	// Category候補object。
		// categoryを識別する必須field群がないobjectは対象外にする。
		if( !object.HasKey( L"Name") || !object.HasKey( L"Files") || !object.HasKey( L"Count") ||
		   !object.HasKey( L"IsDescShow")) {
			continue ;
		}

		++categoryCount ;
		// category数が固定上限を超える一覧を拒否する。
		if( categoryCount > MAXIMUM_CATEGORIES) {
			return false ;
		}

		std::wstring				   category ;	// Page表示driver分類。
		// Nuxt参照を解決したFiles値。欠損または不正参照では値なし。
		const std::optional<JsonValue> filesValue = resolveValue( control, root, object, L"Files") ;
		// category名とfile配列を解決できなければ一覧全体を拒否する。
		if( !resolveString( control, root, object, L"Name", MAXIMUM_TEXT_CHARACTERS, category) ||
		   !filesValue.has_value() || filesValue->ValueType() != JsonValueType::Array) {
			return false ;
		}

		const JsonArray				   files = filesValue->GetArray() ;	// Category内record参照群。
		const std::optional<JsonValue> countValue =
			// Pageが宣言するcategory件数。
			resolveValue( control, root, object, L"Count") ;
		const std::optional<JsonValue> descriptionValue =
			// Category説明表示flag。
			resolveValue( control, root, object, L"IsDescShow") ;
		// 宣言件数と説明表示flagの型がschemaと一致しなければ拒否する。
		if( !countValue.has_value() || countValue->ValueType() != JsonValueType::Number ||
		   !descriptionValue.has_value() ||
		   descriptionValue->ValueType() != JsonValueType::Boolean) {
			return false ;
		}

		const double declaredCount = countValue->GetNumber() ;	// JSON numberの宣言件数。
		// 宣言件数の非有限値・上限超過・実配列数との不一致を拒否する。
		if( !std::isfinite( declaredCount) || declaredCount < 0.0 ||
		   declaredCount > static_cast<double>( MAXIMUM_RECORDS) ||
		   declaredCount != static_cast<double>( files.Size())) {
			return false ;
		}

		// Category内の全recordをASUS表示順に検証する。
		for( std::uint32_t fileIndex = 0U; fileIndex < files.Size(); ++fileIndex) {
			collectorParserStep( control) ;
			++recordCount ;
			// 全categoryを通じたrecord数が固定上限を超えた場合は拒否する。
			if( recordCount > MAXIMUM_RECORDS) {
				return false ;
			}

			std::uint32_t recordIndex{} ;	// Flattened root内のrecord index。
			// 配列内のfile参照indexが不正なら部分一覧へ縮退させない。
			if( !resolveIndex( control, root, files.GetAt( fileIndex), recordIndex)) {
				return false ;
			}

			const JsonValue recordValue = root.GetAt( recordIndex) ;	// 解決済みrecord値。
			// file参照先がobjectでなければschema違反として拒否する。
			if( recordValue.ValueType() != JsonValueType::Object) {
				return false ;
			}

			// 明示した探索範囲外の本文を取得根拠へ使用しない。参照構造の検証は維持する。
			if( !expectedCategory.empty() && category != expectedCategory) {
				continue ;
			}

			AsusDriverPageEntry entry ;	// 現在recordの採用可能metadata。
			// Catalog modeでは不採用を分母から除外しない。
			if( observation != nullptr) {
				++observation->seen ;
			}

			// 一つのdriver recordの解析結果。対象外と拒否を区別して集約する。
			const EntryParseResult result =
				parseDriverRecord( control, root, recordValue.GetObject(), category, osId, entry) ;
			// 個別不正は明示catalog modeでだけ隔離し、従来modeは全体を拒否する。
			if( result == EntryParseResult::REJECTED) {
				// 明示catalog modeだけ個別不正を隔離し、同じ行を取得根拠にしない。
				if( observation != nullptr) {
					++observation->rejected ;
					continue ;
				}

				return false ;
			}

			// 検証上の対象外recordは候補へ追加せず後続を確認する。
			if( result == EntryParseResult::IGNORED) {
				// 対象外とschema拒否を別の件数で保持する。
				if( observation != nullptr) {
					++observation->ignored ;
				}

				continue ;
			}

			// 候補数上限とpayload URLの重複を検出して全体拒否する。
			if( entries.size() >= MAXIMUM_ENTRIES || !urls.insert( entry.downloadUrl).second) {
				return false ;
			}

			entries.push_back( std::move( entry)) ;
			// 全体成功が確定するまでは参考集計としてのみ保持する。
			if( observation != nullptr) {
				++observation->accepted ;
			}
		}
	}

	return categoryCount != 0U ;
}

/**
 * @brief WinRT JSON解析が上書きする復号後の重複propertyを拒否します。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] json 文法検証済みの有限Nuxt JSON。
 * @return 全objectの復号済みkeyが各scope内で一意の場合true。
 */
[[nodiscard]] bool collectorUniqueKeys( CollectorParserContext *control,
									   const std::wstring_view json)
{
	collectorParserCheckpoint( control) ;
	std::vector<std::set<std::wstring>> scopes ;	// Object／arrayごとの復号済みkey集合。
	// JSON全体を一回走査し、string外でだけ階層を変更する。
	for( std::size_t offset = 0U; offset < json.size(); ++offset) {
		collectorParserStep( control) ;
		// 有限な階層を保持して巨大な入れ子入力を拒否する。
		if( json[offset] == L'{' || json[offset] == L'[') {
			scopes.emplace_back() ;
			// Nuxtの通常構造より深い本文を推測解決しない。
			if( scopes.size() > 64U) {
				collectorParserLimit( control) ;
				return false ;
			}

			continue ;
		}

		// 閉じた階層のkey集合を解放する。
		if( json[offset] == L'}' || json[offset] == L']') {
			// 対応する開始境界がない文字列を採用しない。
			if( scopes.empty()) {
				return false ;
			}

			scopes.pop_back() ;
			continue ;
		}

		// String中の構造記号を飛ばし、直後がcolonならkeyとして比較する。
		if( json[offset] == L'"') {
			const std::size_t begin = offset++ ;	// JSON string tokenの開始位置。
			// Escapeの次の引用符はtoken終端としない。
			while( offset < json.size() && json[offset] != L'"') {
				collectorParserStep( control, 2U) ;
				// JSON escape一組を飛ばす。
				if( json[offset] == L'\\') {
					++offset ;
				}

				++offset ;
			}

			// 閉じ引用符がないtokenを拒否する。
			if( offset >= json.size()) {
				return false ;
			}

			std::size_t after = offset + 1U ;	// Token後のcolonまたは値境界。
			// JSON空白だけを飛ばしてkeyを識別する。
			while( after < json.size() && (json[after] == L' ' || json[after] == L'\t' ||
										  json[after] == L'\r' || json[after] == L'\n')) {
				collectorParserStep( control) ;
				++after ;
			}

			// 復号後の同じkeyを別表記で重複させない。
			if( after < json.size() && json[after] == L':') {
				collectorParserCheckpoint( control) ;
				// Escapeを復号したproperty名を比較します。
				const auto key = winrt::Windows::Data::Json::JsonValue::Parse(
									 winrt::hstring( json.substr( begin, offset - begin + 1U)))
									 .GetString() ;
				collectorParserCheckpoint( control) ;
				// 親scope不在または重複propertyなら上書きを拒否する。
				if( scopes.empty() ||
				   !scopes.back().insert( std::wstring( key.c_str(), key.size())).second) {
					return false ;
				}

				collectorParserCheckpoint( control) ;
			}
		}
	}

	return scopes.empty() ;
}

/**
 * @brief Nuxt参照を指定されたJSON objectへ一段だけ解決します。
 * @param[in] root Flattened root。
 * @param[in] parent 参照元object。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] key 参照field名。
 * @return Objectへ解決した場合だけ所有viewを返します。
 */
[[nodiscard]] std::optional<JsonObject> collectorObject( CollectorParserContext *control,
														const JsonArray		   &root,
														const JsonObject	   &parent,
														const std::wstring_view key)
{
	collectorParserCheckpoint( control) ;
	const auto value = resolveValue( control, root, parent, key) ;	// 型未確認の参照先。
	// Object以外を次のrouteへ進めない。
	if( !value || value->ValueType() != JsonValueType::Object) {
		return std::nullopt ;
	}

	return value->GetObject() ;
}

/**
 * @brief Nuxt参照を指定されたJSON arrayへ一段だけ解決します。
 * @param[in] root Flattened root。
 * @param[in] parent 参照元object。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] key 参照field名。
 * @return Arrayへ解決した場合だけ所有viewを返します。
 */
[[nodiscard]] std::optional<JsonArray> collectorArray( CollectorParserContext *control,
													  const JsonArray		 &root,
													  const JsonObject		 &parent,
													  const std::wstring_view key)
{
	collectorParserCheckpoint( control) ;
	const auto value = resolveValue( control, root, parent, key) ;	// 型未確認の参照先。
	// Array以外を次のrouteへ進めない。
	if( !value || value->ValueType() != JsonValueType::Array) {
		return std::nullopt ;
	}

	return value->GetArray() ;
}

/**
 * @brief 収集結果へ保持する文字列の制御文字とUTF-16境界を確認します。
 * @param[in] value 元の公式公開field。
 * @param[in] maximumCharacters 公開field上限。
 * @param[in] allowEmpty 非公開page markerだけを認める場合true。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] kind 公開fieldのslash文法。
 * @return 有限かつ有効Unicodeの場合true。
 */
[[nodiscard]] bool collectorPublicText(
	CollectorParserContext *control, const std::wstring_view value,
	const std::size_t maximumCharacters, const bool allowEmpty = false,
	const OfficialCollectorPublicTextKind kind = OfficialCollectorPublicTextKind::TEXT)
{
	collectorParserCheckpoint( control) ;
	// 空marker以外の欠損や過大な値を公開identityにしない。
	if( value.size() > maximumCharacters || (!allowEmpty && value.empty())) {
		return false ;
	}

	// 公開表示へURL、query、絶対path形状を紛れ込ませない。Page markerは親へ渡さない。
	if( !allowEmpty && !(control != nullptr ? isOfficialCollectorPublicTextForCollector(
												 value, 1'024U, kind, *control)
										   : isOfficialCollectorPublicText( value, 1'024U, kind))) {
		return false ;
	}

	// UTF-16 surrogateは正しいhigh／lowの組でだけ通過させる。
	for( std::size_t index = 0U; index < value.size(); ++index) {
		collectorParserStep( control) ;
		const wchar_t current = value[index] ;	// 現在のUTF-16 code unit。
		// C0／DEL／C1を表示可能な公開値へ昇格させない。
		if( current < L' ' || (current >= 0x7f && current <= 0x9f)) {
			return false ;
		}

		// 高位surrogateは直後の低位surrogateを必須にする。
		if( current >= 0xd800 && current <= 0xdbff) {
			// 不完全な対を公式製品名へ変換しない。
			if( index + 1U >= value.size() || value[index + 1U] < 0xdc00 ||
			   value[index + 1U] > 0xdfff) {
				return false ;
			}

			++index ;
		}
		// 単独の低位surrogateは拒否する。
		else if( current >= 0xdc00 && current <= 0xdfff) {
			return false ;
		}
	}

	return true ;
}

/**
 * @brief ASUS opaque IDの型とOS位置を別の第一理由に分けます。
 * @param[in] opaqueId 公式entry ID。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] osId 同一support storeの要求OS ID。
 * @return 不正schemaは拒否、別OSはOTHER_OS、一致ならACCEPTED。
 */
[[nodiscard]] AsusCollectorRowReason collectorRecordOs( CollectorParserContext *control,
													   const std::wstring_view opaqueId,
													   const std::wstring_view osId)
{
	collectorParserCheckpoint( control) ;
	std::array<std::wstring_view, 7U> fields{} ;	// IDの固定7 field。
	std::size_t						  count{} ;		// 検証済みfield数。
	std::size_t						  begin{} ;		// 次のfield開始位置。
	// 全fieldを有限配列へ分解し、余分なfieldを拒否する。
	while( begin <= opaqueId.size()) {
		collectorParserStep( control) ;
		const std::size_t end = collectorParserFind( control, opaqueId, L'@', begin) ;	// 次の区切り。
		// 空fieldや八つ目のfieldを持つIDを拒否する。
		if( count >= fields.size() || end == begin) {
			return AsusCollectorRowReason::REJECTED_ROW ;
		}

		fields[count++] = end == std::wstring_view::npos ? opaqueId.substr( begin)
														 : opaqueId.substr( begin, end - begin) ;
		// 最後のfieldまで到達したら走査を終了する。
		if( end == std::wstring_view::npos) {
			break ;
		}

		begin = end + 1U ;
	}

	// OSを比較する前に全数値fieldと個数を検証する。
	if( count != fields.size() ||
	   !std::ranges::all_of( fields.begin(), fields.end() - 1U, [&]( const std::wstring_view field) {
		   return isAsciiDecimal( control, field) ;
	   })) {
		return AsusCollectorRowReason::REJECTED_ROW ;
	}

	return fields[4] == osId ? AsusCollectorRowReason::ACCEPTED : AsusCollectorRowReason::OTHER_OS ;
}

/**
 * @brief 収集専用で公開日を実在する暦日へ限定します。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] value 公式表示のYYYY/MM/DD。
 * @return 年1以上、実在する日ならtrue。
 */
[[nodiscard]] bool validCollectorDate( CollectorParserContext *control,
									  const std::wstring_view value)
{
	collectorParserCheckpoint( control) ;
	// 旧通常parserの構文検証後だけ固定位置を読みます。
	if( !isValidReleaseDate( control, value)) {
		return false ;
	}

	const int year = (value[0] - L'0') * 1000 + (value[1] - L'0') * 100 + (value[2] - L'0') * 10 +
					 value[3] - L'0' ;	// 四桁の公開年。
	const unsigned month =
		// 公開月。
		static_cast<unsigned>( (value[5] - L'0') * 10 + value[6] - L'0') ;
	const unsigned day =
		// 公開日。
		static_cast<unsigned>( (value[8] - L'0') * 10 + value[9] - L'0') ;
	return year >= 1 &&
		   std::chrono::year_month_day{std::chrono::year{year}, std::chrono::month{month},
									   std::chrono::day{day}}
			   .ok() ;
}

/**
 * @brief 収集専用の行順序でOS・path・形式・hash・sizeを判定します。
 * @param[in] root 同一Nuxt root。
 * @param[in] record 同一categoryに所属する行。
 * @param[in] osId 同一storeの要求OS ID。
 * @param[in] maximumBytes 一配布物の明示予算。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[out] entry ACCEPTED時だけURL付きのworker内行を設定します。
 * @return 最初に確定した行理由。
 */
[[nodiscard]] AsusCollectorRowReason parseCollectorRow(
	CollectorParserContext *control, const JsonArray &root, const JsonObject &record,
	const std::wstring_view osId, const std::uint64_t maximumBytes, AsusDriverPageEntry &entry)
{
	collectorParserCheckpoint( control) ;
	entry = {} ;
	std::wstring opaqueId ;		// ASUSの固定7 field key。
	std::wstring version ;		// 公開版。
	std::wstring title ;		// 公開title。
	std::wstring fileSize ;		// 数値解釈前の表示size。
	std::wstring releaseDate ;	// 表示公開日。
	// 必須fieldと公開表示値を第一段で検査する。
	if( !resolveString( control, root, record, L"Id", MAXIMUM_TEXT_CHARACTERS, opaqueId) ||
	   !resolveString( control, root, record, L"Version", MAXIMUM_TEXT_CHARACTERS, version) ||
	   !resolveString( control, root, record, L"Title", MAXIMUM_TEXT_CHARACTERS, title) ||
	   !resolveString( control, root, record, L"FileSize", 64U, fileSize) ||
	   !resolveString( control, root, record, L"ReleaseDate", 32U, releaseDate) ||
	   !collectorPublicText( control, opaqueId, MAXIMUM_TEXT_CHARACTERS) ||
	   !collectorPublicText( control, version, MAXIMUM_TEXT_CHARACTERS) ||
	   !collectorPublicText( control, title, MAXIMUM_TEXT_CHARACTERS) ||
	   !collectorPublicText( control, releaseDate, 32U, false,
							OfficialCollectorPublicTextKind::DATE) ||
	   collectorParserFindSet( control, title, L"<>", false, false) != std::wstring::npos ||
	   !validCollectorDate( control, releaseDate)) {
		return AsusCollectorRowReason::REJECTED_ROW ;
	}

	const auto osReason = collectorRecordOs( control, opaqueId, osId) ;	// 型とOSの第一理由。
	// 別OSまたは不正IDは配布pathを調べる前に確定する。
	if( osReason != AsusCollectorRowReason::ACCEPTED) {
		return osReason ;
	}

	const auto download =
		// 配布path保持object。
		collectorObject( control, root, record, L"DownloadUrl") ;
	std::wstring path ;	// 公式CDNの相対path。
	// 配布pathの参照・型を検証しない行は対象にしない。
	if( !download ||
	   !resolveString( control, root, *download, L"Global", MAXIMUM_URL_CHARACTERS, path)) {
		return AsusCollectorRowReason::REJECTED_ROW ;
	}

	std::wstring downloadUrl ;	// workerだけが所有する完全URL。
	const auto	 pathReason =
		// 既存のpath契約。
		validatePayloadPath( control, path, opaqueId, downloadUrl) ;
	// 無効pathとID不一致は形式対象外に読み替えない。
	if( pathReason == EntryParseResult::REJECTED) {
		return AsusCollectorRowReason::REJECTED_ROW ;
	}

	// ZIP以外の有効形式は初期収集scopeに採用しない。
	if( pathReason == EntryParseResult::IGNORED ||
	   !lowerAscii( control, downloadUrl).ends_with( L".zip")) {
		return AsusCollectorRowReason::UNSUPPORTED_FORMAT ;
	}

	const auto hashValue = resolveValue( control, root, record, L"sha256") ;	// 公開SHA-256参照先。
	// Hash fieldの未掲載と、掲載されたが不正な参照を区別する。
	if( !record.HasKey( L"sha256")) {
		return AsusCollectorRowReason::HASH_NOT_PUBLISHED ;
	}

	// 参照先の型違いをhash欠測へ変換しない。
	if( !hashValue || hashValue->ValueType() != JsonValueType::String) {
		return AsusCollectorRowReason::REJECTED_ROW ;
	}

	const auto		   hashText = hashValue->GetString() ;					// 元のhash文字列を終端まで保持。
	const std::wstring publishedHash( hashText.c_str(), hashText.size()) ;	// 元のhash表記。
	// 空の公開hashは不正hashと分けて数える。
	if( publishedHash.empty()) {
		return AsusCollectorRowReason::HASH_NOT_PUBLISHED ;
	}

	std::wstring sha256 ;	// 正規化した公開SHA-256。
	// Hashの不正hexと制御文字を取得可能な行へ昇格させない。
	if( !collectorPublicText( control, publishedHash, 64U) ||
	   !normalizeSha256( control, publishedHash, sha256)) {
		return AsusCollectorRowReason::REJECTED_ROW ;
	}

	const auto size = parseDisplaySize( control, fileSize) ;	// 表示値を有限な取得上限へ変換。
	// 不正sizeと明示予算超過を別に数える。
	if( !size) {
		return AsusCollectorRowReason::REJECTED_ROW ;
	}

	// 有効な公開行でも予算外なら取得候補にしない。
	if( *size > maximumBytes) {
		return AsusCollectorRowReason::BUDGET_EXCEEDED ;
	}

	entry = {.category			   = L"LAN",
			 .opaqueId			   = std::move( opaqueId),
			 .title				   = std::move( title),
			 .version			   = std::move( version),
			 .releaseDate		   = std::move( releaseDate),
			 .downloadUrl		   = std::move( downloadUrl),
			 .sha256			   = std::move( sha256),
			 .maximumDownloadBytes = *size} ;
	return AsusCollectorRowReason::ACCEPTED ;
}

//------------------------------------------------------------------------------
/**
 * @brief 任意scriptを実行せず、Nuxt data scriptのtextだけを分離する。
 *
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] html ASUS公式製品page HTML。
 * @return 一意なapplication/json script本文。違反時はnullopt。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring_view> extractNuxtJson( CollectorParserContext *control,
															   const std::wstring_view html)
{
	collectorParserCheckpoint( control) ;
	const std::size_t marker =
		// Nuxt script ID位置。
		collectorParserFind( control, html, NUXT_MARKER) ;
	// Nuxt data markerの欠落や重複を曖昧なまま解析しない。
	if( marker == std::wstring_view::npos ||
	   collectorParserFind( control, html, NUXT_MARKER, marker + NUXT_MARKER.size()) !=
		   std::wstring_view::npos) {
		return std::nullopt ;
	}

	const std::size_t scriptBegin =
		// Script開始tag位置。
		collectorParserRfind( control, html, L"<script", marker) ;
	const std::size_t tagEnd =
		// Script開始tag終端。
		collectorParserFind( control, html, L'>', marker) ;
	// marker近傍に完全なscript開始tagがない場合はdata領域を取得しない。
	if( scriptBegin == std::wstring_view::npos || tagEnd == std::wstring_view::npos ||
	   marker - scriptBegin > 1'024U) {
		return std::nullopt ;
	}

	// JSON dataを保持するscript開始tag全体。元HTML内の借用範囲。
	const std::wstring_view tag = html.substr( scriptBegin, tagEnd - scriptBegin + 1U) ;
	// JSON形式と明示されたdata scriptだけを対象にする。
	if( collectorParserFind( control, tag, JSON_TYPE_MARKER) == std::wstring_view::npos) {
		return std::nullopt ;
	}

	const std::size_t jsonBegin = tagEnd + 1U ;	// JSON本文開始位置。
	const std::size_t jsonEnd =
		// Script終了tag位置。
		collectorParserFind( control, html, SCRIPT_END, jsonBegin) ;
	// data scriptの終端欠落と文字数上限超過を拒否する。
	if( jsonEnd == std::wstring_view::npos || jsonEnd - jsonBegin > MAXIMUM_PAGE_CHARACTERS) {
		return std::nullopt ;
	}

	const std::wstring_view json = html.substr( jsonBegin, jsonEnd - jsonBegin) ;	// JSON本文。
	// 空・NUL・追加markupを含むdata領域をJSONとして採用しない。
	if( json.empty() || collectorParserFind( control, json, L'\0') != std::wstring_view::npos ||
	   collectorParserFind( control, json, L'<') != std::wstring_view::npos) {
		return std::nullopt ;
	}

	return json ;
}

} // namespace

/** @see asus_catalog_parser.h */
bool isAsusDriverCatalogCategory( const std::wstring_view category) noexcept
{
	return isSupportedDriverCategory( category) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asus_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseAsusDriverPageHtml( const std::wstring_view html, const std::wstring_view expectedModel,
							 const std::wstring_view		   expectedOsName,
							 std::vector<AsusDriverPageEntry> &entries,
							 const std::wstring_view		   expectedCategory,
							 AsusDriverCatalogObservation	  *catalogObservation)
{
	CollectorParserContext *control = nullptr ;	// 旧入口は無制御coreを維持します。
	entries.clear() ;
	// 前回の観測を再使用せず、全体失敗時は成立flagを返さない。
	if( catalogObservation != nullptr) {
		*catalogObservation = {} ;
	}

	// HTMLの入力境界と照合用modelの文字列境界を先に検証する。
	// 入力の空値・scope・埋込NULを解析前に拒否します。
	if( html.empty() || html.size() > MAXIMUM_PAGE_CHARACTERS ||
	   html.find( L'\0') != std::wstring_view::npos ||
	   !isValidText( control, expectedModel, MAXIMUM_MODEL_CHARACTERS) ||
	   (catalogObservation != nullptr ? !isSupportedDriverCategory( expectedCategory)
									  : (!expectedCategory.empty() && expectedCategory != L"LAN" &&
										 expectedCategory != L"Wireless"))) {
		return false ;
	}

	const std::optional<std::wstring_view> json = extractNuxtJson( control, html) ;	// Nuxt JSON本文。
	// Nuxt JSON領域を一意に取得できないpageを解析しない。
	if( !json.has_value()) {
		return false ;
	}

	try {
		const JsonArray root = JsonArray::Parse( winrt::hstring( *json)) ;	// Flattened root array。
		// 空または過大なflattened配列を受理しない。
		if( root.Size() == 0U || root.Size() > MAXIMUM_ROOT_VALUES) {
			return false ;
		}

		std::wstring pageModel ;	// Nuxt page dataのASUS model名。
		// pageの製品modelが照合先と一致しなければ候補を返さない。
		if( !findPageModel( control, root, pageModel) ||
		   normalizeModel( control, pageModel) != normalizeModel( control, expectedModel)) {
			return false ;
		}

		std::wstring osId ;	// 指定OS名へ対応するASUS ID。
		// 指定OSに対応するopaque IDを確定できなければ候補を返さない。
		if( !findOsId( control, root, expectedOsName, osId)) {
			return false ;
		}

		std::vector<AsusDriverPageEntry> parsed ;	// 全成功時だけ公開するentry群。
		parsed.reserve( 32U) ;
		// 全体構造違反とmodeごとの拒否条件を満たす場合だけ検証済み行を返す。
		if( !collectDriverEntries( control, root, osId, parsed, expectedCategory,
								 catalogObservation)) {
			return false ;
		}

		entries = std::move( parsed) ;
		// 全体schema確認後にだけcatalog集計の成立を公表する。
		if( catalogObservation != nullptr) {
			catalogObservation->structurallyValid = true ;
		}

		return true ;
	} catch( const winrt::hresult_error &) {
		entries.clear() ;
		return false ;
	} catch( const std::bad_alloc &) {
		entries.clear() ;
		return false ;
	}
}

/** @see asus_catalog_parser.h */
std::wstring asusCollectorModelComparisonKey( const std::wstring_view publicModel)
{
	CollectorParserContext *control = nullptr ;	// 旧入口は無制御coreを維持します。
	// 公式表示でも公開targetでも同じ制御文字・UTF-8境界を先に確認します。
	if( !collectorPublicText( control, publicModel, MAXIMUM_MODEL_CHARACTERS)) {
		return {} ;
	}

	return normalizeModel( control, publicModel) ;
}

/** @brief 旧入口と制御付き入口が共有するNuxt解析coreです。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] html 同じ有限本文。
 * @param[in] expectedModel 公開model。
 * @param[in] expectedOsName 公開OS。
 * @param[in] expectedCategory LAN分類。
 * @param[in] maximumBytes 配布予算。
 * @param[out] result 所有結果。
 * @return 同一storeの構造が成立した場合true。
 */
static bool parseAsusCollectorDriverPageHtmlCore( CollectorParserContext	 *control,
												 const std::wstring_view  html,
												 const std::wstring_view  expectedModel,
												 const std::wstring_view  expectedOsName,
												 const std::wstring_view  expectedCategory,
												 const std::uint64_t	  maximumBytes,
												 AsusCollectorPageResult &result)
{
	collectorParserCheckpoint( control) ;
	result = {} ;
	// 初期scope以外を未知分類から類推して解析しない。
	// 本文の明示上限を構造拒否と分離します。
	if( html.size() > MAXIMUM_PAGE_CHARACTERS) {
		collectorParserLimit( control) ;
	}

	// 入力の空値・scope・埋込NULを解析前に拒否します。
	if( html.empty() || html.size() > MAXIMUM_PAGE_CHARACTERS ||
	   collectorParserFind( control, html, L'\0') != std::wstring_view::npos ||
	   !collectorPublicText( control, expectedModel, MAXIMUM_MODEL_CHARACTERS) ||
	   expectedOsName != L"Windows 11 64-bit" || expectedCategory != L"LAN" || maximumBytes == 0U ||
	   maximumBytes > MAXIMUM_PAYLOAD_BYTES) {
		return false ;
	}

	const auto json = extractNuxtJson( control, html) ;	// 一意なNuxt script本文。
	// Nuxt本文を取得できないHTMLからproductIdを推測しない。
	if( !json) {
		return false ;
	}

	try {
		collectorParserCheckpoint( control) ;
		const JsonArray root = JsonArray::Parse( winrt::hstring( *json)) ;	// 同一本文の有限parse。
		collectorParserCheckpoint( control) ;
		// Rootの実件数超過は明示上限として終了します。
		// 同一本文の一回のparse。
		if( root.Size() > MAXIMUM_ROOT_VALUES) {
			collectorParserLimit( control) ;
		}

		// WinRTの上書き済みpropertyや過大rootを製品情報へ使用しない。
		if( root.Size() == 0U || root.Size() > MAXIMUM_ROOT_VALUES ||
		   !collectorUniqueKeys( control, *json)) {
			return false ;
		}

		const JsonValue first = root.GetAt( 0U) ;	// Nuxtのapplication wrapper。
		// 保存本文に確認されたShallowReactiveだけを根として認める。
		if( first.ValueType() != JsonValueType::Array || first.GetArray().Size() != 2U) {
			return false ;
		}

		const JsonArray appWrapper = first.GetArray() ;	// Wrapper名と参照index。
		std::uint32_t	appIndex{} ;					// Application objectのroot index。
		// Wrapper名と参照先のobject型を固定する。
		if( appWrapper.GetAt( 0U).ValueType() != JsonValueType::String ||
		   appWrapper.GetAt( 0U).GetString() != L"ShallowReactive" ||
		   !resolveIndex( control, root, appWrapper.GetAt( 1U), appIndex) ||
		   root.GetAt( appIndex).ValueType() != JsonValueType::Object) {
			return false ;
		}

		const JsonObject app  = root.GetAt( appIndex).GetObject() ;				// Nuxt application state。
		const auto piniaValue = resolveValue( control, root, app, L"pinia") ;	// Pinia wrapper参照先。
		// Applicationから明示されたReactive wrapperを必須にする。
		if( !piniaValue || piniaValue->ValueType() != JsonValueType::Array ||
		   piniaValue->GetArray().Size() != 2U) {
			return false ;
		}

		const JsonArray piniaWrapper = piniaValue->GetArray() ;	// Pinia参照とwrapper名。
		std::uint32_t	piniaIndex{} ;							// Pinia storesのroot index。
		// 別storeへの推測fallbackを許さない。
		if( piniaWrapper.GetAt( 0U).ValueType() != JsonValueType::String ||
		   piniaWrapper.GetAt( 0U).GetString() != L"Reactive" ||
		   !resolveIndex( control, root, piniaWrapper.GetAt( 1U), piniaIndex) ||
		   root.GetAt( piniaIndex).ValueType() != JsonValueType::Object) {
			return false ;
		}

		const auto store = collectorObject( control, root, root.GetAt( piniaIndex).GetObject(),
										   L"pdSupportStore") ;	// 唯一のactive support store。
		// 製品・OS・driver分類を同一storeからだけ解決する。
		if( !store) {
			return false ;
		}

		const auto page =
			// 公開製品。
			collectorObject( control, root, *store, L"productSupportCheckModelExist") ;
		const auto osChoices =
			// OS一覧。
			collectorArray( control, root, *store, L"productSupportOS") ;
		const auto driver =
			// 配布分類。
			collectorObject( control, root, *store, L"productSupportDriver") ;
		// 所属する三objectの欠落を部分成功にしない。
		if( !page || !osChoices || !driver) {
			return false ;
		}

		AsusCollectorPageResult parsed ;		// 全schema成立後だけ公開する所有値。
		std::wstring			driverModel ;	// 同じstoreのdriver側Model。
		// Page identityとdriver modelを独立の公開fieldとして検証する。
		if( !resolveString( control, root, *page, L"model", MAXIMUM_MODEL_CHARACTERS,
						  parsed.pageModel) ||
		   !resolveString( control, root, *driver, L"Model", MAXIMUM_MODEL_CHARACTERS,
						  driverModel) ||
		   !collectorPublicText( control, parsed.pageModel, MAXIMUM_MODEL_CHARACTERS) ||
		   !collectorPublicText( control, driverModel, MAXIMUM_MODEL_CHARACTERS)) {
			return false ;
		}

		parsed.modelComparisonKey = normalizeModel( control, parsed.pageModel) ;
		// 同じstoreに別製品のdriver集合が紛れ込んだ場合は構造拒否する。
		if( parsed.modelComparisonKey.empty() ||
		   normalizeModel( control, driverModel) != parsed.modelComparisonKey) {
			return false ;
		}

		const auto productIdValue =
			// 型検証前のID。
			resolveValue( control, root, *page, L"productId") ;
		const auto pageUrlMarker =
			// 非公開marker。
			resolveValue( control, root, *page, L"downloadUrl") ;
		// 型違い、未解決、非有限、非整数の公開IDを拒否する。
		if( !productIdValue || productIdValue->ValueType() != JsonValueType::Number ||
		   !pageUrlMarker || pageUrlMarker->ValueType() != JsonValueType::String) {
			return false ;
		}

		const double	   number	  = productIdValue->GetNumber() ;		// JSON Numberの公開ID。
		const auto		   markerText = pageUrlMarker->GetString() ;		// 空も有効なpage marker。
		const std::wstring marker( markerText.c_str(), markerText.size()) ;	// NULを保持する所有値。
		// JSON Numberの整数精度と空markerを含む文字列境界を検証する。
		if( !std::isfinite( number) || number < 1.0 || number > 9007199254740991.0 ||
		   std::floor( number) != number ||
		   !collectorPublicText( control, marker, MAXIMUM_URL_CHARACTERS, true)) {
			return false ;
		}

		parsed.productId = std::to_wstring( static_cast<std::uint64_t>( number)) ;
		parsed.osName	 = std::wstring( expectedOsName) ;
		parsed.category	 = std::wstring( expectedCategory) ;
		parsed.targetModelMatches =
			normalizeModel( control, expectedModel) == parsed.modelComparisonKey ;

		// 対象OSを同じstoreの選択肢だけから解決する。
		for( std::uint32_t index = 0U; index < osChoices->Size(); ++index) {
			collectorParserStep( control) ;
			std::uint32_t osIndex{} ;	// 現在のOS object参照。
			// 無効参照やobject以外の選択肢を見逃さない。
			if( !resolveIndex( control, root, osChoices->GetAt( index), osIndex) ||
			   root.GetAt( osIndex).ValueType() != JsonValueType::Object) {
				return false ;
			}

			const JsonObject choice = root.GetAt( osIndex).GetObject() ;	// 公式OS選択肢。
			std::wstring	 name ;											// OS表示名。
			std::wstring	 id ;											// OS ID。
			// 同じstoreの無効なOS選択肢は適合情報に使用しない。
			if( !resolveString( control, root, choice, L"Name", MAXIMUM_TEXT_CHARACTERS, name) ||
			   !resolveString( control, root, choice, L"Id", 8U, id) ||
			   !collectorPublicText( control, name, MAXIMUM_TEXT_CHARACTERS) ||
			   !isAsciiDecimal( control, id)) {
				return false ;
			}

			// 別OSの選択肢を要求OSへ読み替えない。
			if( name != expectedOsName) {
				continue ;
			}

			// 同名OSの異なるIDは曖昧なため拒否する。
			if( !parsed.osId.empty() && parsed.osId != id) {
				return false ;
			}

			parsed.osId = std::move( id) ;
		}

		const auto categories =
			// 同一storeの分類参照列。
			collectorArray( control, root, *driver, L"Obj") ;
		const auto driverCountValue =
			// 全Filesの宣言数。
			resolveValue( control, root, *driver, L"Count") ;
		// 分類列と総数のschemaを欠いた一覧を採用しない。
		// 分類の実件数上限を独立に報告します。
		if( categories && categories->Size() > MAXIMUM_CATEGORIES) {
			collectorParserLimit( control) ;
		}

		// 分類とCountの型が揃った場合だけ一覧を読みます。
		if( !categories || categories->Size() > MAXIMUM_CATEGORIES || !driverCountValue ||
		   driverCountValue->ValueType() != JsonValueType::Number) {
			return false ;
		}

		std::size_t				 totalRows{} ;		// 全分類のFiles合計。
		std::optional<JsonArray> selectedFiles ;	// 対象LAN分類の行参照列。
		// 同じstoreの全category参照とCountを検証し、無所属objectを採用しない。
		for( std::uint32_t index = 0U; index < categories->Size(); ++index) {
			collectorParserStep( control) ;
			std::uint32_t categoryIndex{} ;	// 現在のcategory参照。
			// Category参照先がobjectでなければ一覧全体を拒否する。
			if( !resolveIndex( control, root, categories->GetAt( index), categoryIndex) ||
			   root.GetAt( categoryIndex).ValueType() != JsonValueType::Object) {
				return false ;
			}

			const JsonObject category = root.GetAt( categoryIndex).GetObject() ;	// 所属確認済み分類。
			std::wstring	 categoryName ;											// 公式分類名。
			const auto files = collectorArray( control, root, category, L"Files") ;	// 行参照列。
			const auto count = resolveValue( control, root, category, L"Count") ;	// 分類の宣言数。
			const auto description =
				// 表示flag。
				resolveValue( control, root, category, L"IsDescShow") ;
			// 分類fieldの型と公開名を確認する。
			if( !resolveString( control, root, category, L"Name", MAXIMUM_TEXT_CHARACTERS,
							  categoryName) ||
			   !collectorPublicText( control, categoryName, MAXIMUM_TEXT_CHARACTERS) || !files ||
			   !count || count->ValueType() != JsonValueType::Number || !description ||
			   description->ValueType() != JsonValueType::Boolean) {
				return false ;
			}

			const double declaredCount = count->GetNumber() ;	// 分類の公開件数。
			// 実配列数との違いと全件上限を検出する。
			// Filesの実件数超過を公開Count不整合と区別します。
			if( totalRows + files->Size() > MAXIMUM_RECORDS) {
				collectorParserLimit( control) ;
			}

			// 公開Countと実配列数の不一致を構造拒否します。
			if( !std::isfinite( declaredCount) || declaredCount != files->Size() ||
			   totalRows + files->Size() > MAXIMUM_RECORDS) {
				return false ;
			}

			totalRows += files->Size() ;
			// 各行の参照型を対象外分類でも確認する。
			for( std::uint32_t fileIndex = 0U; fileIndex < files->Size(); ++fileIndex) {
				collectorParserStep( control) ;
				std::uint32_t recordIndex{} ;	// Flattened entry参照。
				// 不正な行参照を分類の空結果へ変換しない。
				if( !resolveIndex( control, root, files->GetAt( fileIndex), recordIndex) ||
				   root.GetAt( recordIndex).ValueType() != JsonValueType::Object) {
					return false ;
				}
			}

			// 同じ公開分類を二つのsliceへ分割して採用しない。
			if( categoryName == expectedCategory) {
				// 重複分類は曖昧なためschemaを拒否する。
				if( selectedFiles) {
					return false ;
				}

				selectedFiles = *files ;
			}
		}

		// Driver全体Countは分類数でなくFiles合計と照合する。
		if( !std::isfinite( driverCountValue->GetNumber()) ||
		   driverCountValue->GetNumber() != static_cast<double>( totalRows)) {
			return false ;
		}

		parsed.structurallyValid = true ;
		// 対象modelが違う場合は公開identityの矛盾を保持し、配布行を採用しない。
		if( !parsed.targetModelMatches) {
			parsed.sliceStatus = AsusCollectorSliceStatus::NO_ELIGIBLE_RECORD ;
			result			   = std::move( parsed) ;
			return true ;
		}

		// 同一storeの要求OSがない場合は別OSの行を推測採用しない。
		if( parsed.osId.empty()) {
			parsed.sliceStatus = AsusCollectorSliceStatus::OS_NOT_LISTED ;
			result			   = std::move( parsed) ;
			return true ;
		}

		// Category未掲載と掲載済みの空sliceを分ける。
		if( !selectedFiles || selectedFiles->Size() == 0U) {
			parsed.sliceStatus = selectedFiles ? AsusCollectorSliceStatus::EMPTY
											   : AsusCollectorSliceStatus::NOT_LISTED ;
			result			   = std::move( parsed) ;
			return true ;
		}

		std::unordered_set<std::wstring> recordKeys ;	// 採用行のopaque ID集合。
		std::unordered_set<std::wstring> urls ;			// 採用行の秘密URL集合。
		// 対象分類の全行を元順序に検査して第一理由だけを数える。
		for( std::uint32_t index = 0U; index < selectedFiles->Size(); ++index) {
			collectorParserStep( control) ;
			std::uint32_t recordIndex{} ;	// 事前検証済み行の参照先。
			// 先行の全分類検証後にも参照型を再照合する。
			if( !resolveIndex( control, root, selectedFiles->GetAt( index), recordIndex)) {
				return false ;
			}

			AsusDriverPageEntry entry ;	// ACCEPTED時だけ設定する一行。
			// 一行の最初の採否理由を保持します。
			const auto			reason =
				parseCollectorRow( control, root, root.GetAt( recordIndex).GetObject(), parsed.osId,
								  maximumBytes, entry) ;
			++parsed.seen ;
			++parsed.reasonCounts[static_cast<std::size_t>( reason)] ;
			// 不採用の行を公式record集合へ混ぜない。
			if( reason != AsusCollectorRowReason::ACCEPTED) {
				continue ;
			}

			// 行keyとpayload URLの衝突を先着採用で回避しない。
			if( !recordKeys.insert( entry.opaqueId).second ||
			   !urls.insert( entry.downloadUrl).second) {
				return false ;
			}

			// 17件目を切捨て成功として報告しない。
			if( parsed.entries.size() >= 16U) {
				collectorParserLimit( control) ;
				parsed.entries.clear() ;
				parsed.sliceStatus = AsusCollectorSliceStatus::RECORD_LIMIT ;
				result			   = std::move( parsed) ;
				return true ;
			}

			entry.category = std::wstring( expectedCategory) ;
			parsed.entries.push_back( std::move( entry)) ;
		}

		// 有効行、部分結果、全行不採用を別statusへ固定する。
		if( parsed.entries.empty()) {
			parsed.sliceStatus = AsusCollectorSliceStatus::NO_ELIGIBLE_RECORD ;
		}
		// 有効行と不採用行の共存を完全成功へ変換しません。
		else if( parsed.entries.size() != parsed.seen) {
			parsed.sliceStatus = AsusCollectorSliceStatus::PARTIAL_REJECTED ;
		} else {
			parsed.sliceStatus = AsusCollectorSliceStatus::ACCEPTED ;
		}

		result = std::move( parsed) ;
		return true ;
	} catch( const winrt::hresult_error &failure) {
		// 既知のJSON文法不正だけを構造拒否へ分類します。
		if( control != nullptr && failure.code() != WEB_E_INVALID_JSON_STRING &&
		   failure.code() != WEB_E_INVALID_JSON_NUMBER) {
			throw ;
		}

		result = {} ;
		return false ;
	} catch( const std::bad_alloc &) {
		// OOMを候補なしへ落とさず上位の型付き境界へ渡します。
		if( control != nullptr) {
			throw ;
		}

		result = {} ;
		return false ;
	}
}

/** @see asus_catalog_parser.h */
bool parseAsusCollectorDriverPageHtml( std::wstring_view html, std::wstring_view expectedModel,
									  std::wstring_view expectedOsName,
									  std::wstring_view expectedCategory,
									  std::uint64_t maximumBytes, AsusCollectorPageResult &result)
{
	return parseAsusCollectorDriverPageHtmlCore( nullptr, html, expectedModel, expectedOsName,
												expectedCategory, maximumBytes, result) ;
}

/** @see asus_catalog_parser.h */
CollectorParserResult parseAsusCollectorDriverPageHtmlControlled(
	std::wstring_view html, std::wstring_view expectedModel, std::wstring_view expectedOsName,
	std::wstring_view expectedCategory, std::uint64_t maximumBytes,
	OfficialCollectorHttpControl &control, AsusCollectorPageResult &result)
{
	result = {} ;
	AsusCollectorPageResult parsed ;	// 停止確認前に部分結果を公開しません。
	const auto outcome = runCollectorParser( control, [&]( CollectorParserContext &context) {
		return parseAsusCollectorDriverPageHtmlCore( &context, html, expectedModel, expectedOsName,
													expectedCategory, maximumBytes, parsed) ;
	}) ; // 同じcontrolの第一原因を保持します。
	// 正常終了後だけ所有結果を呼出し側へ移動します。
	if( outcome.status == CollectorParserStatus::COMPLETED) {
		result = std::move( parsed) ;
	}

	return outcome ;
}

} // namespace drivercrate
