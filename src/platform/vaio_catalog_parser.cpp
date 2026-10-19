//------------------------------------------------------------------------------
/**
 * @file vaio_catalog_parser.cpp
 * @brief VAIO Global公式catalog parser実装。
 * @version 01.00.00
 * @date 2026/09/02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  公式取得元policy registryへ統合。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Windows.Data.Jsonで公式JSONの型と上限を検証します。非driver分類とpayload欠損項目は候補へ変換せず、必須schema不正はfail-closedにしま
 *       す。
 */
//------------------------------------------------------------------------------

#include "platform/vaio_catalog_parser.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
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
#include <cstdint>
#include <exception>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t	MAXIMUM_JSON_CHARACTERS		 = 2U * 1024U * 1024U ;	// 各JSON文字数上限。
constexpr std::size_t	MAXIMUM_MODELS				 = 256 ;				// Model record数上限。
constexpr std::size_t	MAXIMUM_PREINSTALLED_DRIVERS = 1024 ;				// Driver表項目数上限。
constexpr std::size_t	MAXIMUM_UPDATES				 = 512 ;				// Update record数上限。
constexpr std::size_t	MAXIMUM_LIST_ITEMS			 = 128 ;				// 一field内のtoken数上限。
constexpr std::size_t	MAXIMUM_DISPLAY_CHARACTERS	 = 1024 ;				// 表示field文字数上限。
constexpr std::size_t	MAXIMUM_URL_CHARACTERS		 = 2048 ;				// URL文字数上限。
constexpr std::uint64_t MAXIMUM_INSTALLER_BYTES =
	4ULL * 1024ULL * 1024ULL * 1024ULL ;	// 一payloadの許可上限。
// Application等を除外し、driver候補として解析するcategoryの許可集合。
constexpr std::array<std::wstring_view, 17> DRIVER_CATEGORIES{
	L"audio", L"audio_old", L"bt",	 L"camera",	   L"dt",	   L"ethernet",
	L"fp",	  L"graphics",	L"ipf",	 L"me_driver", L"noican",  L"npu",
	L"sst",	  L"vfep",		L"wlan", L"chipset",   L"touchpad"} ;
// Applicationとfirmwareを含まない審査済みcategory。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをNativeErrorへ変換する。
 *
 * Parserの診断値をProvider共通表現へ統一する。
 *
 * @param[in] error Win32 error code。
 * @return HRESULT_FROM_WIN32で変換したbit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief JSON objectから上限付きstring propertyを取得する。
 *
 * Null文字を拒否し、fieldごとの上限を一か所で適用する。
 *
 * @param[in] object 読取り対象object。
 * @param[in] name 必須property名。
 * @param[in] maximum UTF-16 code unit数上限。
 * @return 検証済みstring。欠損、型違い、上限超過時は`std::nullopt`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> readString(
	const winrt::Windows::Data::Json::JsonObject &object, const std::wstring_view name,
	const std::size_t maximum)
{
	const winrt::hstring key( name) ;	// Windows.Data.Jsonへ渡すproperty名。
	// 指定 property がない場合は値を補完せず未取得として返す。
	if( !object.HasKey( key)) {
		return std::nullopt ;
	}

	const winrt::hstring raw = object.GetNamedString( key) ;	// JSON string property値。
	std::wstring		 value( raw.c_str(), raw.size()) ;		// 所有するUTF-16値。
	// 長さ上限超過または埋込み NUL を持つ property を拒否する。
	if( value.size() > maximum || value.find( L'\0') != std::wstring::npos) {
		return std::nullopt ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASCII空白を文字列の両端から除去する。
 *
 * Version等の意味を変更せず、公式dataの余分な端空白だけ除く。
 *
 * @param[in] value Catalogが返した文字列。
 * @return Space、tab、CR、LFを両端から除いた所有文字列。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring trimAscii( const std::wstring_view value)
{
	constexpr std::wstring_view WHITESPACE = L" \t\r\n" ;						// 除去を許可するASCII空白。
	const std::size_t			first = value.find_first_not_of( WHITESPACE) ;	// 最初の非空白位置。
	// 全て空白の値は空文字列として返す。
	if( first == std::wstring_view::npos) {
		return {} ;
	}

	const std::size_t last = value.find_last_not_of( WHITESPACE) ;	// 最後の非空白位置。
	return std::wstring( value.substr( first, last - first + 1)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式表示名から許可済みHTML表記だけを除去する。
 *
 * 公式JSONで使用されるregistered trademark tagだけを許可し、UIへの任意markup混入を拒否する。
 *
 * @param[in] value ProgramName field。
 * @return 表示用plain text。未知markupまたは空なら`std::nullopt`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::wstring> sanitizeTitle( const std::wstring_view value)
{
	std::wstring							   title( value) ;	// 許可tagを除去するmutable表示名。
	// 製品名の照合前に除去を許可する登録商標の固定HTML表現。
	constexpr std::array<std::wstring_view, 2> TAGS{L"<sup>&reg;</sup>", L"<SUP>&REG;</SUP>"} ;
	// 大小文字が既知の二形式だけを繰り返し除去する。
	for( const std::wstring_view tag : TAGS) {
		std::size_t position{} ;	// 次の許可tagを探す位置。
		// 有限長 title から許可した tag 表記だけを順に除去する。
		while( (position = title.find( tag, position)) != std::wstring::npos) {
			title.replace( position, tag.size(), L"") ;
		}
	}

	// 許可 tag の除去後も markup または entity が残る title を拒否する。
	if( title.find( L'<') != std::wstring::npos || title.find( L'>') != std::wstring::npos ||
	   title.find( L'&') != std::wstring::npos) {
		return std::nullopt ;
	}

	title = trimAscii( title) ;
	return title.empty() ? std::nullopt : std::optional<std::wstring>( std::move( title)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 大文字ASCII model codeか検証する。
 *
 * SMBIOS照合に使う値をpathやqueryへ解釈できない文字へ限定する。
 *
 * @param[in] value Models.jsonのModelName token。
 * @return 5～8文字の英大文字・数字で先頭がVの場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isModelCode( const std::wstring_view value) noexcept
{
	return value.size() >= 5 && value.size() <= 8 && value.front() == L'V' &&
		   std::all_of( value.begin(), value.end(), []( const wchar_t character) {
			   return (character >= L'A' && character <= L'Z') ||
					  (character >= L'0' && character <= L'9') ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 小文字ASCII category IDか検証する。
 *
 * 分類allowlistを曖昧な大小文字比較にしない。
 *
 * @param[in] value CategoryID field。
 * @return 1～32文字の小文字、数字、underscoreなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isCategoryId( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= 32 &&
		   std::all_of( value.begin(), value.end(), []( const wchar_t character) {
			   return (character >= L'a' && character <= L'z') ||
					  (character >= L'0' && character <= L'9') || character == L'_' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 区切り文字付きASCII token集合を検証して分割する。
 *
 * VAIO JSONに存在する二種類のOS区切りを許可し、空tokenとduplicateを拒否する。
 *
 * @param[in] value Commaまたはperiod区切りfield。
 * @param[in] models trueの場合はmodel code規則も検証する。
 * @param[out] tokens 成功時の重複しないtrim済みtoken群。
 * @return 一件以上の有限なtoken集合なら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool splitTokens( const std::wstring_view value, const bool models,
							   std::vector<std::wstring> &tokens)
{
	tokens.clear() ;
	std::unordered_set<std::wstring> unique ;	// 重複token検出集合。
	std::size_t						 start{} ;	// 現在token開始位置。
	// 区切りごとに token を検証し、最終要素まで有限に分割する。
	while( start <= value.size()) {
		const std::size_t  end = value.find_first_of( L",.", start) ;	// 次の区切り位置。
		// 区切り間の値からASCII空白を除いた一つの検索token。
		const std::wstring token = trimAscii( value.substr(
			start, end == std::wstring_view::npos ? value.size() - start : end - start)) ;
		// 空・長さ超過・model 形式不正・重複・件数超過の token 集合を破棄する。
		if( token.empty() || token.size() > 64 || (models && !isModelCode( token)) ||
		   !unique.insert( token).second || tokens.size() >= MAXIMUM_LIST_ITEMS) {
			tokens.clear() ;
			return false ;
		}

		tokens.push_back( token) ;
		// 最後の token を追加したら区切り探索を終了する。
		if( end == std::wstring_view::npos) {
			break ;
		}

		start = end + 1 ;
	}

	return !tokens.empty() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 十進byte数を上限付きで変換する。
 *
 * Overflowを各桁で検出し、0 byte payloadを許可しない。
 *
 * @param[in] value FileSize field。
 * @return 1～4GiBのbyte数。不正時は`std::nullopt`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::uint64_t> parseSize( const std::wstring_view value) noexcept
{
	// 空または 64-bit 十進表記の最大桁数を超える size を拒否する。
	if( value.empty() || value.size() > 20) {
		return std::nullopt ;
	}

	std::uint64_t size{} ;	// 変換中のbyte数。
	// Size の全桁を検証し、overflow しない範囲で十進値へ変換する。
	for( const wchar_t character : value) {
		// Size 表記に十進数字以外があれば拒否する。
		if( character < L'0' || character > L'9') {
			return std::nullopt ;
		}

		const std::uint64_t digit = static_cast<std::uint64_t>( character - L'0') ;	// 現在桁。
		// 次の桁を加える前に 64-bit overflow を検出する。
		if( size > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
			return std::nullopt ;
		}

		size = size * 10 + digit ;
	}

	return size == 0 || size > MAXIMUM_INSTALLER_BYTES ? std::nullopt
													   : std::optional<std::uint64_t>( size) ;
}

//------------------------------------------------------------------------------
/**
 * @brief VAIO Software IDを検証する。
 *
 * Package identityへ使用するopaque IDの文字集合を限定する。
 *
 * @param[in] value SoftwareID field。
 * @return `SP`または`VP`と10桁以内の数字なら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSoftwareId( const std::wstring_view value) noexcept
{
	// Software ID の長さと固定 prefix に一致しない値を拒否する。
	if( value.size() < 3 || value.size() > 12 ||
	   (value.substr( 0, 2) != L"SP" && value.substr( 0, 2) != L"VP")) {
		return false ;
	}

	return std::all_of( value.begin() + 2, value.end(), []( const wchar_t character) {
		return character >= L'0' && character <= L'9' ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief SHA-256文字列表現を検証する。
 *
 * Payload検証に使用できない長さまたは文字を拒否する。
 *
 * @param[in] value SHA256 field。
 * @return 64桁ASCII hexadecimalなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSha256( const std::wstring_view value) noexcept
{
	return value.size() == 64 &&
		   std::all_of( value.begin(), value.end(), []( const wchar_t character) {
			   return (character >= L'0' && character <= L'9') ||
					  (character >= L'a' && character <= L'f') ||
					  (character >= L'A' && character <= L'F') ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief VAIO payload URLとSoftware IDの対応を検証する。
 *
 * URLのbasenameとopaque IDを一致させ、別payload参照を拒否する。
 *
 * @param[in] url DownloadReferenceUrl field。
 * @param[in] softwareId 検証済みSoftware ID。
 * @return 公式host内の`/{SoftwareID}.exe`なら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isPayloadUrl( const std::wstring_view url,
								const std::wstring_view softwareId) noexcept
{
	const std::span<const std::wstring_view> hosts =
		// 公式payload host群。
		officialSourceHosts( VAIO_PROVIDER_ID, OFFICIAL_PAYLOAD_RESOURCE_ID) ;
	// 共通の公式 HTTPS 検証が成立しない payload URL を拒否する。
	if( validateOfficialHttpsUrl( url, hosts) != 0) {
		return false ;
	}

	const std::wstring suffix = L"/" + std::wstring( softwareId) + L".exe" ;	// 期待basename。
	return url.size() > suffix.size() && url.ends_with( suffix) ;
}

//------------------------------------------------------------------------------
/**
 * @brief YYYY/MM/DD形式の日付を検証する。
 *
 * Calendar補正を推測せず、表示と並替えに必要な形式だけ確認する。
 *
 * @param[in] value Date field。
 * @return 固定長ASCII日付形式なら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isReleaseDate( const std::wstring_view value) noexcept
{
	// 日付の固定桁数と YYYY/MM/DD の区切り位置を確認する。
	if( value.size() != 10 || value[4] != L'/' || value[7] != L'/') {
		return false ;
	}

	// Separator以外がすべてASCII数字であることを確認する。
	for( std::size_t index = 0; index < value.size(); ++index) {
		// 検証済みの slash 位置は数値文字の確認から除く。
		if( (index == 4 || index == 7)) {
			continue ;
		}

		// 日付の数値部分に十進数字以外を許可しない。
		if( value[index] < L'0' || value[index] > L'9') {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示文字列を大文字英数字だけの比較keyへ変換する。
 *
 * 区切り差だけを吸収し、versionや日付の比較には使用しない。
 *
 * @param[in] value 公式titleまたはlocal表示値。
 * @return ASCII英数字を大文字化し、他の文字を除いた比較key。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizeMatchText( const std::wstring_view value)
{
	std::wstring normalized ;	// 比較に使用するASCII英数字列。
	normalized.reserve( value.size()) ;
	// ASCII英数字だけを順序どおり保持する。
	for( const wchar_t character : value) {
		// ASCII 小文字は比較 key 内で大文字へ正規化する。
		if( character >= L'a' && character <= L'z') {
			normalized.push_back( static_cast<wchar_t>( character - L'a' + L'A')) ;
		}
		// 既に大文字の英字と数字だけを比較 key に残す。
		else if( (character >= L'A' && character <= L'Z') ||
				(character >= L'0' && character <= L'9')) {
			normalized.push_back( character) ;
		}
	}

	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式titleのmaker tokenがlocal deviceと一致するか判定する。
 *
 * Intel、AMD、NVIDIA、Realtek、ELANのOEM component取り違えを防ぎ、未知makerを推測しない。
 *
 * @param[in] title 正規化済み公式title。
 * @param[in] device 判定対象local device。
 * @return 既知makerが一致するか、titleにmaker指定がなければ`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchesMaker( const std::wstring_view title, const OfficialCatalogDevice &device)
{
	// Device表示名のmaker整合を確認するcomponent maker名の固定集合。
	constexpr std::array<std::wstring_view, 5> MAKERS{L"INTEL", L"AMD", L"NVIDIA", L"REALTEK",
													  L"ELAN"} ;
	// 外部へ送信せず、端末内だけで製品名照合に使う正規化表示文字列。
	const std::wstring local = normalizeMatchText( device.manufacturer + L" " +
												  device.currentProvider + L" " + device.model) ;
	// Titleが明示する既知makerはlocal表示値にも存在することを必須にする。
	for( const std::wstring_view maker : MAKERS) {
		// Title が明示した maker token は local device にも存在することを要求する。
		if( title.find( maker) != std::wstring_view::npos) {
			return local.find( maker) != std::wstring::npos ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief VAIO categoryに対応するSetup classとmodel tokenを判定する。
 *
 * Localized class名ではなくclass GUIDを使い、曖昧なcategoryはmodel tokenも必須にする。
 *
 * @param[in] categoryId 検証済みcategory ID。
 * @param[in] device 判定対象local device。
 * @return Category固有のclassとmodel条件を全て満たす場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchesCategory( const std::wstring_view		categoryId,
								   const OfficialCatalogDevice &device)
{
	const std::wstring guid	 = normalizeMatchText( device.deviceClassGuid) ;	// Class GUID key。
	const std::wstring model = normalizeMatchText( device.model) ;				// Device model key。
	// 表示class照合用に区切りを除いたDisplay class GUID。
	constexpr std::wstring_view DISPLAY = L"4D36E968E32511CEBFC108002BE10318" ;
	// Network adapter class照合用に区切りを除いたGUID。
	constexpr std::wstring_view NET = L"4D36E972E32511CEBFC108002BE10318" ;
	// Bluetooth class照合用に区切りを除いたGUID。
	constexpr std::wstring_view BLUETOOTH = L"E0CBF06CCD8B4647BB8A263B43F0F974" ;
	// 生体認証class照合用に区切りを除いたGUID。
	constexpr std::wstring_view BIOMETRIC = L"53D29EF7377C4D14864BEB3A85769359" ;
	// Camera class照合用に区切りを除いたGUID。
	constexpr std::wstring_view CAMERA = L"CA3E7AB9B4C34AE68251579EF933890F" ;
	// Image class照合用に区切りを除いたGUID。
	constexpr std::wstring_view IMAGE = L"6BDD1FC6810F11D0BEC708002BE2092F" ;
	// Media class照合用に区切りを除いたGUID。
	constexpr std::wstring_view MEDIA = L"4D36E96CE32511CEBFC108002BE10318" ;
	// System class照合用に区切りを除いたGUID。
	constexpr std::wstring_view SYSTEM = L"4D36E97DE32511CEBFC108002BE10318" ;
	// Software component class照合用に区切りを除いたGUID。
	constexpr std::wstring_view SOFTWARE = L"5C4C3332344D483C8739259E934C9CC8" ;
	// Compute class照合用に区切りを除いたGUID。
	constexpr std::wstring_view COMPUTE = L"F01A9D533FF648D29F97C8A7004BE10C" ;
	// Mouse class照合用に区切りを除いたGUID。
	constexpr std::wstring_view MOUSE = L"4D36E96FE32511CEBFC108002BE10318" ;
	// HID class照合用に区切りを除いたGUID。
	constexpr std::wstring_view HID = L"745A17A074D311D0B6FE00A0C90F57DA" ;
	// Modelに許可tokenが含まれるかの同期判定関数。Model参照を呼出し中だけ借用する。
	const auto containsAny = [&model]( const std::initializer_list<std::wstring_view> tokens) {
		return std::any_of( tokens.begin(), tokens.end(), [&model]( const std::wstring_view token) {
			return model.find( token) != std::wstring::npos ;
		}) ;
	} ;

	// Graphics 分類は Display class と照合する。
	if( categoryId == L"graphics") {
		return guid == DISPLAY ;
	}

	// 無線 LAN 分類は Net class と無線製品 token の両方を要求する。
	if( categoryId == L"wlan") {
		return guid == NET && containsAny( {L"WIRELESS", L"WIFI", L"WLAN"}) ;
	}

	// Ethernet 分類は Net class と有線 LAN 製品 token を照合する。
	if( categoryId == L"ethernet") {
		return guid == NET && containsAny( {L"ETHERNET", L"GIGABIT", L"I225", L"I226"}) ;
	}

	// Bluetooth 分類は class と製品 token の一致を要求する。
	if( categoryId == L"bt") {
		return guid == BLUETOOTH && model.find( L"BLUETOOTH") != std::wstring::npos ;
	}

	// 指紋認証分類は Biometric class と照合する。
	if( categoryId == L"fp") {
		return guid == BIOMETRIC ;
	}

	// Camera 分類は許可 class と Camera 製品 token を照合する。
	if( categoryId == L"camera") {
		return (guid == CAMERA || guid == IMAGE) && model.find( L"CAMERA") != std::wstring::npos ;
	}

	// Management Engine 分類は System class と専用製品 token を確認する。
	if( categoryId == L"me_driver") {
		return guid == SYSTEM && containsAny( {L"MANAGEMENTENGINE", L"MEINTERFACE"}) ;
	}

	// NPU 分類は許可する三 class と NPU 系の製品 token を照合する。
	if( categoryId == L"npu") {
		return (guid == COMPUTE || guid == SYSTEM || guid == SOFTWARE) &&
			   containsAny( {L"NPU", L"NEURAL", L"AIBOOST"}) ;
	}

	// VFEP 分類は System／Software class と専用製品 token を確認する。
	if( categoryId == L"vfep") {
		return (guid == SYSTEM || guid == SOFTWARE) &&
			   containsAny( {L"VAIO", L"FIRMWAREEXTENSIONPARSER"}) ;
	}

	// Audio 系分類は許可 class と Smart Sound 系の製品 token を照合する。
	if( categoryId == L"audio" || categoryId == L"audio_old" || categoryId == L"sst") {
		return (guid == MEDIA || guid == SYSTEM || guid == SOFTWARE) &&
			   containsAny( {L"SMARTSOUND", L"ISST"}) ;
	}

	// Noise Cancellation 分類は Media／Software class と製品 token を確認する。
	if( categoryId == L"noican") {
		return (guid == MEDIA || guid == SOFTWARE) && containsAny( {L"NOISE", L"CANCEL"}) ;
	}

	// Dynamic Tuning 分類は System／Software class と専用 token を要求する。
	if( categoryId == L"dt") {
		return (guid == SYSTEM || guid == SOFTWARE) &&
			   model.find( L"DYNAMICTUNING") != std::wstring::npos ;
	}

	// Innovation Platform 分類は許可 class と専用製品 token を照合する。
	if( categoryId == L"ipf") {
		return (guid == SYSTEM || guid == SOFTWARE) &&
			   model.find( L"INNOVATIONPLATFORM") != std::wstring::npos ;
	}

	// Touchpad 分類は Mouse／HID class と製品 token を要求する。
	if( categoryId == L"touchpad") {
		return (guid == MOUSE || guid == HID) && model.find( L"TOUCHPAD") != std::wstring::npos ;
	}

	// Chipsetは複数system deviceへ適用されるため、Hardware IDなしでは一意に解決しない。
	return false ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/vaio_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool isVaioDriverCategory( const std::wstring_view categoryId) noexcept
{
	return std::find( DRIVER_CATEGORIES.begin(), DRIVER_CATEGORIES.end(), categoryId) !=
		   DRIVER_CATEGORIES.end() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/vaio_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::optional<std::wstring> matchVaioDriverDevice(
	const std::wstring_view categoryId, const std::wstring_view officialTitle,
	const std::span<const OfficialCatalogDevice> devices)
{
	// Driver として許可しない category は local device へ対応付けない。
	if( !isVaioDriverCategory( categoryId)) {
		return std::nullopt ;
	}

	const std::wstring title = normalizeMatchText( officialTitle) ;	// Maker照合用title key。
	const OfficialCatalogDevice *matched{} ;						// 現在までに一致した唯一のdevice。
	// 全present deviceからcategoryとmakerが一致する対象を探す。
	for( const OfficialCatalogDevice &device : devices) {
		// Category と maker の条件に一致しない local device は候補から除く。
		if( !matchesCategory( categoryId, device) || !matchesMaker( title, device)) {
			continue ;
		}

		// 複数 device が一致した場合は一台を推測で選ばず対応付けを拒否する。
		if( matched != nullptr) {
			return std::nullopt ;
		}

		matched = &device ;
	}

	return matched == nullptr ? std::nullopt : std::optional<std::wstring>( matched->deviceIdentity) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/vaio_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError parseVaioModelCatalog( const std::wstring_view jsonUtf16, std::vector<VaioModel> &models)
{
	models.clear() ;
	// 空または取得上限を超える model JSON は解析しない。
	if( jsonUtf16.empty() || jsonUtf16.size() > MAXIMUM_JSON_CHARACTERS) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		const auto array = winrt::Windows::Data::Json::JsonArray::Parse(
			// Model record root array。
			winrt::hstring( jsonUtf16)) ;
		// Model 件数が保持上限を超える catalog を拒否する。
		if( array.Size() > MAXIMUM_MODELS) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		std::unordered_set<std::wstring> unique ;	// Global model code重複検出集合。
		// 全model recordの既知fieldを検証し、Global対象だけを保持する。
		for( const winrt::Windows::Data::Json::IJsonValue &value : array) {
			const auto					object = value.GetObject() ;						// 現在のmodel record。
			std::optional<std::wstring> code   = readString( object, L"ModelName", 64) ;	// Code。
			std::optional<std::wstring> global = readString( object, L"Global", 8) ;		// Flag。
			// 必須 model property が欠ける場合は部分一覧を破棄する。
			if( !code.has_value() || !global.has_value()) {
				models.clear() ;
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			code   = trimAscii( *code) ;
			global = trimAscii( *global) ;
			// Global 対象でない明示値の model は一覧に含めない。
			if( global->empty() || *global == L"N") {
				continue ;
			}

			// Global flag・model code の不正と重複を含む一覧は拒否する。
			if( *global != L"Y" || !isModelCode( *code) || !unique.insert( *code).second) {
				models.clear() ;
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			models.push_back( {.code = std::move( *code)}) ;
		}

		return models.empty() ? nativeErrorFromWin32( ERROR_NOT_FOUND) : 0 ;
	} catch( const winrt::hresult_error &error) {
		models.clear() ;
		return static_cast<NativeError>( error.code().value) ;
	} catch( const std::exception &) {
		models.clear() ;
		return static_cast<NativeError>( E_FAIL) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/vaio_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::optional<std::wstring> matchVaioModelCode( const std::span<const VaioModel>	   models,
											   const std::span<const std::wstring> localValues)
{
	std::optional<std::wstring> matched ;	// 現在までに一致した一意なmodel code。
	// 各公式codeがいずれかのlocal値で英数字境界から始まるか確認する。
	for( const VaioModel &model : models) {
		bool found{} ;	// 現在model codeがlocal表示値へ一致した場合true。
		// 各 local SMBIOS 表示値で同じ公式 model code の一致を調べる。
		for( const std::wstring &localValue : localValues) {
			std::wstring upper = localValue ;	// ASCII大文字化するSMBIOS表示値。
			std::transform( upper.begin(), upper.end(), upper.begin(), []( const wchar_t character) {
				return character >= L'a' && character <= L'z'
						   ? static_cast<wchar_t>( character - L'a' + L'A')
						   : character ;
			}) ;
			std::size_t position{} ;	// Model codeの検索開始位置。
			// 有限の表示値内で model code を探し、前方の文字境界を確認する。
			while( (position = upper.find( model.code, position)) != std::wstring::npos) {
				// Maker名の部分一致を別の英数字語へ誤適用しないための先頭境界。
				const bool boundary =
					position == 0 ||
					!((upper[position - 1] >= L'A' && upper[position - 1] <= L'Z') ||
					  (upper[position - 1] >= L'0' && upper[position - 1] <= L'9')) ;
				// 英数字の途中でない位置に model code が見つかった場合だけ一致とする。
				if( boundary) {
					found = true ;
					break ;
				}

				position += model.code.size() ;
			}

			// 一つの local 表示値で一致した model は残り表示値の探索を省く。
			if( found) {
				break ;
			}
		}

		// Local 表示値に一致しなかった公式 model は選択しない。
		if( !found) {
			continue ;
		}

		// 異なる公式 model が複数一致した場合は一意に解決できないため拒否する。
		if( matched.has_value() && *matched != model.code) {
			return std::nullopt ;
		}

		matched = model.code ;
	}

	return matched ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/vaio_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError parseVaioPreinstalledCatalog( const std::wstring_view			  jsonUtf16,
										 std::vector<VaioPreinstalledDriver> &drivers)
{
	drivers.clear() ;
	// 空または取得上限を超える pre-installed JSON を拒否する。
	if( jsonUtf16.empty() || jsonUtf16.size() > MAXIMUM_JSON_CHARACTERS) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		const auto array = winrt::Windows::Data::Json::JsonArray::Parse(
			// Pre-installed record root array。
			winrt::hstring( jsonUtf16)) ;
		// Pre-installed driver 件数が保持上限を超える場合は解析を中止する。
		if( array.Size() > MAXIMUM_PREINSTALLED_DRIVERS) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		// 全recordのschemaを検証し、modelとcategoryの対応を保持する。
		for( const winrt::Windows::Data::Json::IJsonValue &value : array) {
			const auto object = value.GetObject() ;	// 現在のpre-installed record。
			const std::optional<std::wstring> modelText =
				// Model集合。
				readString( object, L"ModelName", MAXIMUM_DISPLAY_CHARACTERS) ;
			std::optional<std::wstring> table = readString( object, L"Table-No", 8) ;	// Table。
			std::optional<std::wstring> category =
				// Category ID。
				readString( object, L"CategoryID", 32) ;
			const std::optional<std::wstring> titleRaw =
				// 名称。
				readString( object, L"ProgramName", MAXIMUM_DISPLAY_CHARACTERS) ;
			// Model・table・category・title の必須値がない場合は一覧を破棄する。
			if( !modelText.has_value() || !table.has_value() || !category.has_value() ||
			   !titleRaw.has_value()) {
				drivers.clear() ;
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			std::vector<std::wstring> models ;	// 検証済みmodel code集合。
			table	 = trimAscii( *table) ;
			category = trimAscii( *category) ;
			// Model 集合、category 形式、許可 table 番号の条件を全て確認する。
			if( !splitTokens( *modelText, true, models) ||
			   (!category->empty() && !isCategoryId( *category)) ||
			   (*table != L"1" && *table != L"2")) {
				drivers.clear() ;
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// Table 2、空category、非driver categoryはUI用項目であり候補照合から除外する。
			if( *table != L"1" || category->empty() || !isVaioDriverCategory( *category)) {
				continue ;
			}

			const std::optional<std::wstring> title = sanitizeTitle( *titleRaw) ;	// Plain名称。
			// Title の許可表記への変換に失敗した場合は部分一覧を残さない。
			if( !title.has_value()) {
				drivers.clear() ;
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			drivers.push_back( {.models	   = std::move( models),
							   .categoryId = std::move( *category),
							   .title	   = std::move( *title),
							   .tableOne   = true}) ;
		}

		return 0 ;
	} catch( const winrt::hresult_error &error) {
		drivers.clear() ;
		return static_cast<NativeError>( error.code().value) ;
	} catch( const std::exception &) {
		drivers.clear() ;
		return static_cast<NativeError>( E_FAIL) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/vaio_catalog_parser.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError parseVaioUpdateCatalog( const std::wstring_view		   jsonUtf16,
								   std::vector<VaioDriverRelease> &releases)
{
	releases.clear() ;
	// 空または取得上限を超える update JSON を拒否する。
	if( jsonUtf16.empty() || jsonUtf16.size() > MAXIMUM_JSON_CHARACTERS) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		const auto array = winrt::Windows::Data::Json::JsonArray::Parse(
			// Update record root array。
			winrt::hstring( jsonUtf16)) ;
		// Update 件数が保持上限を超える catalog を拒否する。
		if( array.Size() > MAXIMUM_UPDATES) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		std::unordered_set<std::wstring> identities ;	// Software ID/hash矛盾検出集合。
		// 全recordのschemaを検証し、有効なdriver categoryだけを保持する。
		for( const winrt::Windows::Data::Json::IJsonValue &value : array) {
			const auto					object = value.GetObject() ;	// 現在のupdate record。
			std::optional<std::wstring> category =
				// Category ID。
				readString( object, L"CategoryID", 32) ;
			const std::optional<std::wstring> titleRaw =
				// 名称。
				readString( object, L"ProgramName", MAXIMUM_DISPLAY_CHARACTERS) ;
			std::optional<std::wstring> version = readString( object, L"Version", 128) ;	// 版。
			std::optional<std::wstring> date	= readString( object, L"Date", 16) ;		// 公開日。
			std::optional<std::wstring> softwareId =
				// Software ID。
				readString( object, L"SoftwareID", 32) ;
			std::optional<std::wstring> sizeText = readString( object, L"FileSize", 32) ;	// Size。
			std::optional<std::wstring> sha256	 = readString( object, L"SHA256", 128) ;	// Hash。
			const std::optional<std::wstring> modelText =
				// Models。
				readString( object, L"ApplicableModel", MAXIMUM_DISPLAY_CHARACTERS) ;
			const std::optional<std::wstring> osText =
				// OS集合。
				readString( object, L"ApplicableOS", 128) ;
			std::optional<std::wstring> na = readString( object, L"NA", 8) ;	// 無効flag。
			std::optional<std::wstring> url =
				// URL。
				readString( object, L"DownloadReferenceUrl", MAXIMUM_URL_CHARACTERS) ;
			// 配布情報の必須 property が一つでも欠ける場合は release 集合を破棄する。
			if( !category.has_value() || !titleRaw.has_value() || !version.has_value() ||
			   !date.has_value() || !softwareId.has_value() || !sizeText.has_value() ||
			   !sha256.has_value() || !modelText.has_value() || !osText.has_value() ||
			   !na.has_value() || !url.has_value()) {
				releases.clear() ;
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			category								= trimAscii( *category) ;
			version									= trimAscii( *version) ;
			date									= trimAscii( *date) ;
			softwareId								= trimAscii( *softwareId) ;
			sizeText								= trimAscii( *sizeText) ;
			sha256									= trimAscii( *sha256) ;
			na										= trimAscii( *na) ;
			url										= trimAscii( *url) ;
			const std::optional<std::wstring> title = sanitizeTitle( *titleRaw) ;	// Plain名称。
			// Category または title 表記が不正な配布情報を拒否する。
			if( !isCategoryId( *category) || !title.has_value()) {
				releases.clear() ;
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// 対象外の明示値がある項目と driver 以外の category は候補にしない。
			if( !na->empty() || !isVaioDriverCategory( *category)) {
				continue ;
			}

			std::vector<std::wstring>		   models ;							// 適用model code集合。
			std::vector<std::wstring>		   osNames ;						// 適用OS token集合。
			const std::optional<std::uint64_t> size = parseSize( *sizeText) ;	// Payload size。
			// 版・日付・ID・hash・size・model・OS・URL の必須形式を全て確認する。
			if( version->empty() || !isReleaseDate( *date) || !isSoftwareId( *softwareId) ||
			   !isSha256( *sha256) || !size.has_value() || !splitTokens( *modelText, true, models) ||
			   !splitTokens( *osText, false, osNames) || !isPayloadUrl( *url, *softwareId)) {
				releases.clear() ;
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			std::transform( sha256->begin(), sha256->end(), sha256->begin(),
						   []( const wchar_t character) {
							   return character >= L'A' && character <= L'F'
										  ? static_cast<wchar_t>( character - L'A' + L'a')
										  : character ;
						   }) ;
			const std::wstring identity = *softwareId + L":" + *sha256 ;	// Metadata一意key。
			// 同じ release identity の重複を検出した場合は曖昧な一覧を破棄する。
			if( !identities.insert( identity).second) {
				releases.clear() ;
				return nativeErrorFromWin32( ERROR_DUPLICATE_TAG) ;
			}

			releases.push_back( {.models		  = std::move( models),
								.osNames	  = std::move( osNames),
								.categoryId	  = std::move( *category),
								.title		  = std::move( *title),
								.version	  = std::move( *version),
								.releaseDate  = std::move( *date),
								.softwareId	  = std::move( *softwareId),
								.installerUrl = std::move( *url),
								.sha256		  = std::move( *sha256),
								.size		  = *size}) ;
		}

		return 0 ;
	} catch( const winrt::hresult_error &error) {
		releases.clear() ;
		return static_cast<NativeError>( error.code().value) ;
	} catch( const std::exception &) {
		releases.clear() ;
		return static_cast<NativeError>( E_FAIL) ;
	}
}

} // namespace drivercrate
