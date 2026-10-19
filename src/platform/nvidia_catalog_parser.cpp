//------------------------------------------------------------------------------
/**
 * @file nvidia_catalog_parser.cpp
 * @brief NVIDIA公式catalog応答parser実装。
 * @version 01.00.00
 * @date 2026/09/01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  公式URLとdownload ID照合を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  共通XML検証を適用。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note XMLは共通MSXML security境界の後にLookupValue schemaを検証し、JSONはWindows標準のWindows.Data.Json parserを使用し
 *       ます。
 */
//------------------------------------------------------------------------------

#include "platform/nvidia_catalog_parser.h"

#include "platform/com_raii.h"
#include "platform/official_catalog_validation.h"
#include "platform/official_http_client.h"

#include <Windows.h>

// Windows SDK 10.0.26100のWindowsNumerics.inlは宣言と定義のSAL差を/analyzeが報告する。
// DriverCrate sourceの警告は維持し、該当SDK headerを展開する区間だけ既知のSDK診断を抑止する。
#pragma warning( push)
#pragma warning( disable : 28252 28253 6101)
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#pragma warning( pop)

#include <algorithm>
#include <array>
#include <cstddef>
#include <exception>
#include <limits>
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

constexpr std::size_t MAXIMUM_LOOKUP_VALUES		 = 512 ;	// 一応答で受理するlookup要素数上限。
constexpr std::size_t MAXIMUM_DRIVER_ENTRIES	 = 64 ;		// 一応答で受理するrelease数上限。
constexpr std::size_t MAXIMUM_DISPLAY_CHARACTERS = 2048 ;	// 一つの表示文字列上限。
constexpr std::size_t MAXIMUM_URL_CHARACTERS	 = 8192 ;	// 一つの公式URL文字数上限。
constexpr std::size_t MAXIMUM_LOOKUP_XML_CHARACTERS =
	16U * 1024U * 1024U ;	// Lookup XMLのUTF-16文字数上限。
constexpr std::array<std::wstring_view, 1> NVIDIA_DETAILS_HOSTS{
	L"www.nvidia.com"} ;	// Driver details pageの完全一致host。
constexpr std::array<std::wstring_view, 1> NVIDIA_DOWNLOAD_HOSTS{
	L".download.nvidia.com"} ;	// NVIDIA直属payload domain suffix。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief XML text要素に使用される限定entityを復号する。
 *
 * Lookup APIで必要な五つのXML predefined entityだけを許可する。
 *
 * @param[in] text XML要素内部のescaped text。
 * @return 復号済みtext。未知entityまたは上限超過時は`std::nullopt`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> decodeXmlText( const std::wstring_view text)
{
	// 表示文字列の上限を超えるXML本文を復号しない。
	if( text.size() > MAXIMUM_DISPLAY_CHARACTERS) {
		return std::nullopt ;
	}

	std::wstring decoded ;	// Entityを展開する出力文字列。
	decoded.reserve( text.size()) ;
	// XML textを先頭から走査し、既知entityだけを復号する。
	for( std::size_t index = 0; index < text.size();) {
		const wchar_t character = text[index] ;	// 現在処理中のUTF-16 code unit。
		// entity開始以外の文字はそのまま本文へ保持する。
		if( character != L'&') {
			decoded.push_back( character) ;
			++index ;
			continue ;
		}

		struct Entity {
			std::wstring_view encoded ;		// XML内のentity表現。
			wchar_t			  decoded{} ;	// 対応する一文字。
		} ;
		// 公式metadata内で復号を許可する名前付きentityの固定対応。
		constexpr std::array ENTITIES{Entity{L"&amp;", L'&'}, Entity{L"&lt;", L'<'},
									  Entity{L"&gt;", L'>'}, Entity{L"&quot;", L'"'},
									  Entity{L"&apos;", L'\''}} ;
		bool				 matched{} ;	// trueの場合は既知entityを一つ復号済み。
		// 現在位置から一致するpredefined entityを探す。
		for( const Entity &entity : ENTITIES) {
			// 一致した既知entityを一文字へ復元してその表現全体を消費する。
			if( text.substr( index).starts_with( entity.encoded)) {
				decoded.push_back( entity.decoded) ;
				index += entity.encoded.size() ;
				matched = true ;
				break ;
			}
		}

		// 未知entityを推測変換せず拒否する。
		if( !matched) {
			return std::nullopt ;
		}
	}

	return decoded ;
}

//------------------------------------------------------------------------------
/**
 * @brief XML fragmentから指定要素のtextを取得する。
 *
 * 属性やnested markupを許可せず、schema逸脱をfail-closedにする。
 *
 * @param[in] fragment 一つのLookupValue fragment。
 * @param[in] element `Name`または`Value`のelement名。
 * @return 復号済み要素text。欠損、重複、不正時は`std::nullopt`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> readXmlElement( const std::wstring_view fragment,
														 const std::wstring_view element)
{
	const std::wstring opening = L"<" + std::wstring( element) + L">" ;		// 開始tag。
	const std::wstring closing = L"</" + std::wstring( element) + L">" ;	// 終了tag。
	const std::size_t  begin   = fragment.find( opening) ;					// 要素開始位置。
	// 開始要素の欠落や重複があるfragmentを採用しない。
	if( begin == std::wstring_view::npos ||
	   fragment.find( opening, begin + opening.size()) != std::wstring_view::npos) {
		return std::nullopt ;
	}

	const std::size_t valueBegin = begin + opening.size() ;					// Text先頭位置。
	const std::size_t end		 = fragment.find( closing, valueBegin) ;	// 要素終了位置。
	// 閉じ要素の欠落や重複があるfragmentを採用しない。
	if( end == std::wstring_view::npos ||
	   fragment.find( closing, end + closing.size()) != std::wstring_view::npos) {
		return std::nullopt ;
	}

	const std::wstring_view encoded = fragment.substr( valueBegin, end - valueBegin) ;	// Text範囲。
	// text要素へ入れ子markupを許容しない。
	if( encoded.find( L'<') != std::wstring_view::npos) {
		return std::nullopt ;
	}

	return decodeXmlText( encoded) ;
}

//------------------------------------------------------------------------------
/**
 * @brief lookup IDが数字だけで構成されるか検証する。
 *
 * 後続URLへ組み込む値を数字へ限定してquery injectionを防ぐ。
 *
 * @param[in] value APIが返したopaque ID。
 * @return 1～10桁のASCII数字だけなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isDecimalId( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= 10 &&
		   std::all_of( value.begin(), value.end(), []( const wchar_t character) {
			   return character >= L'0' && character <= L'9' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief NVIDIA driver details URLとdownload IDを照合する。
 *
 * Query、fragment、別IDへの差替えを拒否する。
 *
 * @param[in] url NVIDIA search metadataの詳細page URL。
 * @param[in] downloadId 同じentryの数値download ID。
 * @return 公式host、既知path、ID完全一致時は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isNvidiaDetailsUrl( const std::wstring_view url,
									  const std::wstring_view downloadId) noexcept
{
	// download IDと公式詳細URLの形式を確認し、queryやfragmentを拒否する。
	if( !isDecimalId( downloadId) || validateOfficialHttpsUrl( url, NVIDIA_DETAILS_HOSTS) != 0 ||
	   url.find_first_of( L"?#") != std::wstring_view::npos) {
		return false ;
	}

	std::wstring normalized( url) ;	// Path比較に限定したASCII小文字URL。
	std::transform( normalized.begin(), normalized.end(), normalized.begin(),
				   []( const wchar_t character) {
					   return character >= L'A' && character <= L'Z'
								  ? static_cast<wchar_t>( character - L'A' + L'a')
								  : character ;
				   }) ;
	const std::wstring modern =	// 現行の地域付きdetails page完全path。
		L"https://www.nvidia.com/en-us/drivers/details/" + std::wstring( downloadId) + L"/" ;
	const std::wstring legacy =	// 公式searchが継続して返す旧details path。
		L"https://www.nvidia.com/download/driverresults.aspx/" + std::wstring( downloadId) +
		L"/en-us/" ;
	return normalized == modern || normalized == legacy ;
}

//------------------------------------------------------------------------------
/**
 * @brief NVIDIA payload URLが有限な公式EXE経路か検証する。
 *
 * Policy登録は導入許可ではない。検索metadataのoriginとfile種類だけをここで固定する。
 *
 * @param[in] url NVIDIA search metadataのpayload URL。
 * @return 公式domain配下のqueryなしEXEの場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isNvidiaPayloadUrl( const std::wstring_view url) noexcept
{
	// payload URLを公式HTTPS hostへ制限し、曖昧なencoded経路を拒否する。
	if( validateOfficialHttpsUrl( url, NVIDIA_DOWNLOAD_HOSTS) != 0 ||
	   url.find_first_of( L"?#%") != std::wstring_view::npos || url.size() < 5U) {
		return false ;
	}

	std::wstring extension( url.substr( url.size() - 4U)) ;	// Payload拡張子。
	std::transform( extension.begin(), extension.end(), extension.begin(),
				   []( const wchar_t character) {
					   return character >= L'A' && character <= L'Z'
								  ? static_cast<wchar_t>( character - L'A' + L'a')
								  : character ;
				   }) ;
	return extension == L".exe" ;
}

//------------------------------------------------------------------------------
/**
 * @brief Percent-encoded UTF-8 fieldをUTF-16へ復号する。
 *
 * `%HH`をbyte列へ戻し、厳密なUTF-8として変換する。
 *
 * @param[in] value NVIDIA JSON field。
 * @param[in] maximumCharacters 復号後のUTF-16文字数上限。
 * @return 復号済みtext。不正encodingまたは上限超過時は`std::nullopt`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> percentDecode( const std::wstring_view value,
														const std::size_t		maximumCharacters)
{
	// encoded入力が出力上限由来の長さやWindows変換APIの範囲を超えたら拒否する。
	if( value.size() > maximumCharacters * 3 ||
	   value.size() > static_cast<std::size_t>( std::numeric_limits<int>::max())) {
		return std::nullopt ;
	}

	const auto hexValue = []( const wchar_t character) -> int {
		// hexの数字を対応する桁値へ変換する。
		if( character >= L'0' && character <= L'9') {
			return character - L'0' ;
		}

		// 小文字hexを対応する桁値へ変換する。
		if( character >= L'a' && character <= L'f') {
			return character - L'a' + 10 ;
		}

		// 大文字hexを対応する桁値へ変換する。
		if( character >= L'A' && character <= L'F') {
			return character - L'A' + 10 ;
		}

		return -1 ;
	} ;

	std::vector<char> bytes ;	// Percent encodingを戻したUTF-8 byte列。
	bytes.reserve( value.size()) ;
	// percent表現とASCII文字を検証してUTF-8 byte列へ復元する。
	for( std::size_t index = 0; index < value.size(); ++index) {
		const wchar_t character = value[index] ;	// 現在のencoded code unit。
		// percent開始時は後続の2桁を一byteとして検証する。
		if( character == L'%') {
			// 2桁が揃わないpercent表現を拒否する。
			if( index + 2 >= value.size()) {
				return std::nullopt ;
			}

			const int high = hexValue( value[index + 1]) ;	// 上位hex digit。
			const int low  = hexValue( value[index + 2]) ;	// 下位hex digit。
			// hexでないpercent表現を拒否する。
			if( high < 0 || low < 0) {
				return std::nullopt ;
			}

			bytes.push_back( static_cast<char>( (high << 4) | low)) ;
			index += 2 ;
		}
		// percent化されていない文字はASCII範囲だけを直接保持する。
		else if( character <= 0x7f) {
			bytes.push_back( static_cast<char>( character)) ;
		} else {
			return std::nullopt ;
		}
	}

	// 空の入力は変換APIを呼ばず空文字列として返す。
	if( bytes.empty()) {
		return std::wstring{} ;
	}

	const int required =	// 厳密なUTF-8からUTF-16への変換文字数。
		MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(),
							static_cast<int>( bytes.size()), nullptr, 0) ;
	// 不正UTF-8または復号後の文字数超過を拒否する。
	if( required <= 0 || static_cast<std::size_t>( required) > maximumCharacters) {
		return std::nullopt ;
	}

	std::wstring decoded( static_cast<std::size_t>( required), L'\0') ;	// UTF-16出力領域。
	// 変換長の不一致や埋込NULを検出して復号結果を採用しない。
	if( MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(),
						   static_cast<int>( bytes.size()), decoded.data(), required) != required ||
	   decoded.find( L'\0') != std::wstring::npos) {
		return std::nullopt ;
	}

	return decoded ;
}

//------------------------------------------------------------------------------
/**
 * @brief JsonObjectから上限付き文字列propertyを取得する。
 *
 * JSON型、文字数、encodingを一か所で検証する。
 *
 * @param[in] object 読取り対象JSON object。
 * @param[in] name 必須property名。
 * @param[in] maximumCharacters 復号後文字数上限。
 * @param[in] percentEncoded trueの場合はpercent decodeする。
 * @return 検証済み文字列。欠損または不正時は`std::nullopt`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> readJsonString(
	const winrt::Windows::Data::Json::JsonObject &object, const std::wstring_view name,
	const std::size_t maximumCharacters, const bool percentEncoded)
{
	const winrt::hstring key( name) ;	// Windows.Data.Jsonへ渡すproperty名。
	// 指定propertyの欠落を空文字列で代用しない。
	if( !object.HasKey( key)) {
		return std::nullopt ;
	}

	const winrt::hstring raw = object.GetNamedString( key) ;	// JSON string property値。
	const std::wstring	 value( raw.c_str(), raw.size()) ;		// 所有するUTF-16 property値。
	// percent化が指定されたpropertyだけを復号する。
	if( percentEncoded) {
		return percentDecode( value, maximumCharacters) ;
	}

	// 通常propertyにも長さ上限と埋込NUL拒否を適用する。
	if( value.size() > maximumCharacters || value.find( L'\0') != std::wstring::npos) {
		return std::nullopt ;
	}

	return value ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseNvidiaLookupXml( const std::wstring_view xml, std::vector<NvidiaLookupValue> &values)
{
	values.clear() ;
	Microsoft::WRL::ComPtr<IXMLDOMDocument2> document ;	// 共通security設定済みlookup DOM。
	// 安全設定と文字数上限付きのXML読込みに失敗したら解析しない。
	if( loadOfficialXmlDocument( xml, {.maximumCharacters = MAXIMUM_LOOKUP_XML_CHARACTERS},
							   document) != 0) {
		return false ;
	}

	Microsoft::WRL::ComPtr<IXMLDOMElement> root ;	// NVIDIA schemaのroot element。
	// XML rootを取得できなければlookup結果を作らない。
	if( FAILED( document->get_documentElement( &root)) || root == nullptr) {
		return false ;
	}

	UniqueBstr rootName ;	// MSXMLが割り当てるroot tag名。
	// 期待するlookup root名に一致しないXMLを拒否する。
	if( FAILED( root->get_tagName( rootName.put())) || rootName.get() == nullptr ||
	   std::wstring_view( rootName.get(), SysStringLen( rootName.get())) != L"LookupValueSearch") {
		return false ;
	}

	std::size_t searchPosition{} ;	// 次のLookupValue開始tagを探す位置。
	// 有限なXML内でLookupValue要素を順に抽出する。
	while( searchPosition < xml.size()) {
		const std::size_t begin = xml.find( L"<LookupValue", searchPosition) ;	// 開始tag候補。
		// 後続のLookupValueがなければ探索を終える。
		if( begin == std::wstring_view::npos) {
			break ;
		}

		// LookupValue要素名の直後。似た名前の別要素との境界確認に使用する。
		const std::size_t nameEnd = begin + std::wstring_view( L"<LookupValue").size() ;
		// 名前prefixだけ一致する別tagをlookup値として採用しない。
		if( nameEnd >= xml.size() || (xml[nameEnd] != L'>' && xml[nameEnd] != L' ')) {
			searchPosition = nameEnd ;
			continue ;
		}

		const std::size_t openingEnd = xml.find( L'>', nameEnd) ;					// 開始tag終了位置。
		const std::size_t end		 = xml.find( L"</LookupValue>", openingEnd) ;	// 要素終了位置。
		// 要素の未終端や長さ超過を検出したら部分結果を破棄する。
		if( openingEnd == std::wstring_view::npos || end == std::wstring_view::npos ||
		   end - openingEnd > MAXIMUM_DISPLAY_CHARACTERS * 4) {
			values.clear() ;
			return false ;
		}

		const std::wstring_view fragment =	// NameとValueを含む要素内部。
			xml.substr( openingEnd + 1, end - openingEnd - 1) ;
		std::optional<std::wstring> name  = readXmlElement( fragment, L"Name") ;	// 表示名。
		std::optional<std::wstring> value = readXmlElement( fragment, L"Value") ;	// 数値ID。
		// 非空の表示名と10進IDが揃わないlookup値を拒否する。
		if( !name.has_value() || name->empty() || !value.has_value() || !isDecimalId( *value)) {
			values.clear() ;
			return false ;
		}

		// lookup保持数が上限を超える応答は全体を拒否する。
		if( values.size() >= MAXIMUM_LOOKUP_VALUES) {
			values.clear() ;
			return false ;
		}

		values.push_back( {.name = std::move( *name), .value = std::move( *value)}) ;
		searchPosition = end + std::wstring_view( L"</LookupValue>").size() ;
	}

	return !values.empty() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/nvidia_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool parseNvidiaDriverJson( const std::wstring_view json, std::vector<NvidiaDriverEntry> &entries)
{
	entries.clear() ;
	try {
		const winrt::Windows::Data::Json::JsonObject root =	// 公式応答root object。
			winrt::Windows::Data::Json::JsonObject::Parse( winrt::hstring( json)) ;
		// IDS propertyがないJSONをdriver一覧とみなさない。
		if( !root.HasKey( L"IDS")) {
			return false ;
		}

		const winrt::Windows::Data::Json::JsonArray ids = root.GetNamedArray( L"IDS") ;	// Release群。
		// driver entry数の上限を超えるJSONを拒否する。
		if( ids.Size() > MAXIMUM_DRIVER_ENTRIES) {
			return false ;
		}

		// 各downloadInfoを検証し、Success=1の完全なreleaseだけを受理する。
		for( const winrt::Windows::Data::Json::IJsonValue &value : ids) {
			const winrt::Windows::Data::Json::JsonObject wrapper = value.GetObject() ;	// IDS要素。
			// downloadInfoを持たないentryを不正schemaとして拒否する。
			if( !wrapper.HasKey( L"downloadInfo")) {
				return false ;
			}

			const winrt::Windows::Data::Json::JsonObject info =
				// Driver metadata object。
				wrapper.GetNamedObject( L"downloadInfo") ;
			const std::optional<std::wstring> success =
				// Entry成否flag。
				readJsonString( info, L"Success", 8, false) ;
			// 成功状態が欠けたentryを候補なしとして読み飛ばさない。
			if( !success.has_value()) {
				return false ;
			}

			// 公式応答が成功としていないentryを候補へ戻さない。
			if( *success != L"1") {
				continue ;
			}

			std::optional<std::wstring> id = readJsonString( info, L"ID", 10, false) ;	// ID。
			std::optional<std::wstring> name =
				// 名称。
				readJsonString( info, L"Name", MAXIMUM_DISPLAY_CHARACTERS, true) ;
			std::optional<std::wstring> version =
				// Driver版。
				readJsonString( info, L"Version", 64, false) ;
			std::optional<std::wstring> date =
				// Release日。
				readJsonString( info, L"ReleaseDateTime", 64, true) ;
			std::optional<std::wstring> details =
				// 詳細URL。
				readJsonString( info, L"DetailsURL", MAXIMUM_URL_CHARACTERS, false) ;
			std::optional<std::wstring> download = readJsonString(
				info, L"DownloadURL", MAXIMUM_URL_CHARACTERS, false) ;	// Payload URL。
			std::optional<std::wstring> size =
				// 表示size。
				readJsonString( info, L"DownloadURLFileSize", 64, false) ;
			std::optional<std::wstring> whql =
				// WHQL flag。
				readJsonString( info, L"IsWHQL", 8, false) ;
			std::optional<std::wstring> studio =
				// Studio flag。
				readJsonString( info, L"IsCRD", 8, false) ;
			std::optional<std::wstring> active =
				// Active flag。
				readJsonString( info, L"IsActive", 8, false) ;
			std::optional<std::wstring> x64 =
				// Architecture flag。
				readJsonString( info, L"Is64Bit", 8, false) ;
			// 必須driver情報とIDに対応する公式詳細・payload URLを検証する。
			if( !id.has_value() || !isDecimalId( *id) || !name.has_value() || name->empty() ||
			   !version.has_value() || version->empty() || !date.has_value() ||
			   !details.has_value() || !download.has_value() || !size.has_value() ||
			   !whql.has_value() || !studio.has_value() || !active.has_value() ||
			   !x64.has_value() || !isNvidiaDetailsUrl( *details, *id) ||
			   !isNvidiaPayloadUrl( *download)) {
				return false ;
			}

			entries.push_back( {.id			 = std::move( *id),
							   .name		 = std::move( *name),
							   .version		 = std::move( *version),
							   .releaseDate	 = std::move( *date),
							   .detailsUrl	 = std::move( *details),
							   .downloadUrl	 = std::move( *download),
							   .downloadSize = std::move( *size),
							   .whql		 = *whql == L"1",
							   .studio		 = *studio == L"1",
							   .active		 = *active == L"1",
							   .x64			 = *x64 == L"1"}) ;
		}

		return true ;
	} catch( const winrt::hresult_error &) {
		entries.clear() ;
		return false ;
	} catch( const std::exception &) {
		entries.clear() ;
		return false ;
	}
}

} // namespace drivercrate
