//------------------------------------------------------------------------------
/**
 * @file asus_system_identity.cpp
 * @brief ASUS公式support page用local system識別実装。
 * @version 01.02.00
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
 * Ver.01.01.00 Shunji Ogawa  2026/09/20  Registry実取得sizeに基づく有限decodeを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/24  公開modelからの非registry公式page要求を追加。
 * </pre>
 *
 * @note Local SMBIOS表示値をASUS modelへfail-closedで照合します。外部送信値は製品表示名一つに限定し、serial numberやPnP IDを読み取りません
 *       。
 */
//------------------------------------------------------------------------------

#include "platform/asus_system_identity.h"

#include "platform/windows_product_type.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <limits>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view BIOS_KEY = L"HARDWARE\\DESCRIPTION\\System\\BIOS" ;
// 対象OSのbuildを照合するために読み取るWindows registry key。
constexpr std::wstring_view WINDOWS_KEY = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ;
// 照合済みASUS modelのsupport pageを構成する固定公式起点。
constexpr std::wstring_view SUPPORT_PAGE_PREFIX = L"https://www.asus.com/supportonly/" ;
// 製品pageのうちdriver一覧だけを参照する固定suffix。
constexpr std::wstring_view SUPPORT_PAGE_SUFFIX		 = L"/helpdesk_download/" ;
constexpr std::size_t		MAXIMUM_REGISTRY_BYTES	 = 32U * 1024U ;	// 一表示値の取得上限。
constexpr std::size_t		MAXIMUM_MODEL_CHARACTERS = 128U ;			// 外部送信modelの上限。
constexpr std::uint32_t		WINDOWS10_MINIMUM_BUILD	 = 10'240U ;		// Windows 10初期build。
constexpr std::uint32_t		WINDOWS11_MINIMUM_BUILD	 = 22'000U ;		// Windows 11初期build。

constexpr std::array<std::wstring_view, 5> GENERIC_MODELS{
	L"DEFAULTSTRING", L"NOTAPPLICABLE", L"SYSTEMPRODUCTNAME", L"TOBEFILLEDBYOEM",
	L"UNKNOWN"} ;	// Firmware既定値として拒否するmodel名群。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをNativeErrorへ変換する。
 *
 * 元のWin32診断値をProvider共通型へ保持する。
 *
 * @param[in] error Win32 APIが返したerror code。
 * @return HRESULT_FROM_WIN32で変換したbit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Registry文字列を任意値として有限に取得する。
 *
 * Systemとbaseboardの片方だけを持つfirmwareも判定できる。
 *
 * @param[in] root 所有しないroot registry handle。
 * @param[in] subkey 読取り対象subkey。
 * @param[in] valueName 読取り対象REG_SZ名。
 * @param[out] value 成功時の終端nullを除く値。欠損時は空。
 * @return 成功または値欠損時は0、型、上限またはWin32失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readOptionalRegistryString( const HKEY				 root,
													 const std::wstring_view subkey,
													 const std::wstring_view valueName,
													 std::wstring			&value)
{
	value.clear() ;
	std::wstring key( subkey) ;		// RegGetValueW用の終端null付きsubkey。
	std::wstring name( valueName) ;	// RegGetValueW用の終端null付きvalue名。
	DWORD		 type{} ;			// Registryが返したvalue型。
	DWORD		 bytes{} ;			// 終端nullを含む必要byte数。
	LSTATUS status = RegGetValueW( root, key.c_str(), name.c_str(), RRF_RT_REG_SZ, &type, nullptr,
								  &bytes) ;	// 必要sizeの照会結果。
	// 任意registry値の未登録は空のまま成功として扱う。
	if( status == ERROR_FILE_NOT_FOUND) {
		return 0 ;
	}

	// registry照会自体の失敗は未登録と区別して診断値を返す。
	if( status != ERROR_SUCCESS) {
		return nativeErrorFromWin32( static_cast<DWORD>( status)) ;
	}

	// REG_SZ型、UTF-16境界、有限byte上限が揃わないregistry値を拒否する。
	if( type != REG_SZ || bytes < sizeof( wchar_t) || bytes > MAXIMUM_REGISTRY_BYTES ||
	   bytes % sizeof( wchar_t) != 0U) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::wstring buffer( bytes / sizeof( wchar_t), L'\0') ;	// 終端nullを含む取得buffer。
	status = RegGetValueW( root, key.c_str(), name.c_str(), RRF_RT_REG_SZ, &type, buffer.data(),
						  &bytes) ;	// 実際の値取得結果。
	// registry本文の読込み失敗をそのまま診断として返す。
	if( status != ERROR_SUCCESS) {
		return nativeErrorFromWin32( static_cast<DWORD>( status)) ;
	}

	// 型変更や返却size異常を拒否し、未使用の確保末尾を本文として扱わない。
	if( type != REG_SZ || !decodeAsusRegistryString( buffer, bytes, value)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示名を大文字ASCII英数字keyへ正規化する。
 *
 * 空白と句読点差だけを吸収し、語の部分一致は行わない。
 *
 * @param[in] value SMBIOSのmakerまたはmodel表示値。
 * @return ASCII英数字だけを大文字化した比較key。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring normalizeAsciiName( const std::wstring_view value)
{
	std::wstring normalized ;	// 完全一致に使用する比較key。
	normalized.reserve( value.size()) ;
	// 表示値を先頭から処理し、ASCII英数字だけを保持する。
	for( const wchar_t character : value) {
		// メーカー比較用のASCII小文字を大文字へ揃える。
		if( character >= L'a' && character <= L'z') {
			normalized.push_back( static_cast<wchar_t>( character - L'a' + L'A')) ;
		}
		// ASCII大文字と数字はメーカー比較keyへ保持する。
		else if( (character >= L'A' && character <= L'Z') ||
				(character >= L'0' && character <= L'9')) {
			normalized.push_back( character) ;
		}
	}

	return normalized ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASUS manufacturer表示値か判定する。
 *
 * ASUSを含むだけの第三者名を対象端末へ誤分類しない。
 *
 * @param[in] value SMBIOS manufacturer表示値。
 * @return ASUSまたはASUSTeK COMPUTER INC.の完全一致時は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAsusManufacturer( const std::wstring_view value)
{
	// ASCII表示範囲外のメーカー名を類似表記として受理しない。
	if( std::ranges::any_of(
		   value, []( const wchar_t character) { return character < L' ' || character > L'~' ; })) {
		return false ;
	}

	const std::wstring key = normalizeAsciiName( value) ;	// Maker比較key。
	return key == L"ASUS" || key == L"ASUSTEK" || key == L"ASUSTEKCOMPUTERINC" ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASUS support pageへ送信可能なmodelか判定する。
 *
 * Unicode変換差、制御文字、firmware既定名をfail-closedにする。
 *
 * @param[in] value SMBIOS由来model表示値。
 * @return 非genericの印字可能ASCII文字列で上限内なら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidModel( const std::wstring_view value)
{
	// 空・過長・前後空白・非ASCIIのmodelを公式lookupへ送信しない。
	if( value.empty() || value.size() > MAXIMUM_MODEL_CHARACTERS || value.front() == L' ' ||
	   value.back() == L' ' || std::ranges::any_of( value, []( const wchar_t character) {
		   return character < L' ' || character > L'~' ;
	   })) {
		return false ;
	}

	const std::wstring key = normalizeAsciiName( value) ;	// Generic判定用key。
	return !key.empty() && std::ranges::find( GENERIC_MODELS, key) == GENERIC_MODELS.end() ;
}

//------------------------------------------------------------------------------
/**
 * @brief ModelをURL path segmentへpercent encodeする。
 *
 * ASUS canonical pathへ直接接続し、redirectを発生させない。Slash、query、fragmentはpath構造ではなくdata化する。
 *
 * @param[in] model 検証済みASCII model表示値。
 * @return ASCII英字を小文字化し、unreserved以外をencodeしたsegment。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring encodeModelPath( const std::wstring_view model)
{
	constexpr std::wstring_view HEX = L"0123456789ABCDEF" ;	// Percent encode用hex表。
	std::wstring				encoded ;					// 固定pathへ連結するmodel segment。
	encoded.reserve( model.size() * 3U) ;
	// 検証済みASCII一文字ごとにURL segmentを構築する。
	for( const wchar_t character : model) {
		const wchar_t canonical = character >= L'A' && character <= L'Z'
									  ? static_cast<wchar_t>( character - L'A' + L'a')
									  : character ;	// ASUS canonical path用の小文字ASCII。
		// Modelをpathへ符号化する際、そのまま使用可能なASCII unreserved文字かを示す。
		const bool	  unreserved = (canonical >= L'a' && canonical <= L'z') ||
								(canonical >= L'0' && canonical <= L'9') || canonical == L'-' ||
								canonical == L'.' || canonical == L'_' || canonical == L'~' ;
		// URLの非予約文字だけはpercent encodeせず正規化済み文字として保持する。
		if( unreserved) {
			encoded.push_back( canonical) ;
			continue ;
		}

		const auto byte = static_cast<unsigned>( canonical) ;	// ASCII検証済みbyte値。
		encoded.push_back( L'%') ;
		encoded.push_back( HEX[(byte >> 4U) & 0x0FU]) ;
		encoded.push_back( HEX[byte & 0x0FU]) ;
	}

	return encoded ;
}

//------------------------------------------------------------------------------
/**
 * @brief CurrentBuildNumberを有限な数値へ変換する。
 *
 * Locale、符号、末尾文字を許さずOS世代判定を固定する。
 *
 * @param[in] value Registry由来のASCII decimal文字列。
 * @param[out] build 成功時のWindows build番号。
 * @return 非零の32-bit整数へ完全変換できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool parseWindowsBuild( const std::wstring_view value, std::uint32_t &build) noexcept
{
	build = 0U ;
	// 空または十桁を超えるWindows buildを解析しない。
	if( value.empty() || value.size() > 10U) {
		return false ;
	}

	std::uint32_t parsed{} ;	// Overflow検証中のbuild値。
	// 全桁を処理し、32-bit上限を超える入力を拒否する。
	for( const wchar_t character : value) {
		// Windows buildにASCII数字以外を許可しない。
		if( character < L'0' || character > L'9') {
			return false ;
		}

		const std::uint32_t digit = static_cast<std::uint32_t>( character - L'0') ;	// 現在桁。
		// 桁追加前にuint32範囲を検証し、build番号のoverflowを拒否する。
		if( parsed > (std::numeric_limits<std::uint32_t>::max() - digit) / 10U) {
			return false ;
		}

		parsed = parsed * 10U + digit ;
	}

	build = parsed ;
	return build != 0U ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/asus_system_identity.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool decodeAsusRegistryString( const std::span<const wchar_t> buffer,
							  const std::uint32_t returnedBytes, std::wstring &value)
{
	value.clear() ;
	// 実取得範囲を容量内のUTF-16単位へ限定し、未初期化領域や端数を参照しない。
	if( returnedBytes < sizeof( wchar_t) || returnedBytes > MAXIMUM_REGISTRY_BYTES ||
	   returnedBytes % sizeof( wchar_t) != 0U || returnedBytes / sizeof( wchar_t) > buffer.size()) {
		return false ;
	}

	const std::wstring_view text( buffer.data(), returnedBytes / sizeof( wchar_t)) ;	// 実取得範囲。
	// 有効範囲内の終端を一つだけ認め、途中NULで別表示値へ切り詰めない。
	if( text.back() != L'\0' ||
	   text.substr( 0U, text.size() - 1U).find( L'\0') != std::wstring_view::npos) {
		return false ;
	}

	value.assign( text.substr( 0U, text.size() - 1U)) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asus_system_identity.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool makeAsusSupportPageRequest( const std::wstring_view systemManufacturer,
								const std::wstring_view systemProduct,
								const std::wstring_view baseboardManufacturer,
								const std::wstring_view baseboardProduct,
								const std::uint32_t windowsBuild, const bool windowsServer,
								AsusSupportPageRequest &request, bool &applicable)
{
	request	   = {} ;
	applicable = false ;
	// ServerではClient専用のASUS page要求を作らない。
	if( windowsServer) {
		return true ;
	}

	const bool asusSystem = isAsusManufacturer( systemManufacturer) ;		// ASUS system判定。
	const bool asusBoard  = isAsusManufacturer( baseboardManufacturer) ;	// ASUS board判定。
	// systemとboardのどちらもASUSでない場合は対象外として終了する。
	if( !asusSystem && !asusBoard) {
		return true ;
	}

	std::wstring_view model ;	// Makerと対になる、外部送信可能な製品表示名。
	// ASUS systemと有効なsystem modelが揃う場合は完成機のmodelを優先する。
	if( asusSystem && isValidModel( systemProduct)) {
		model = systemProduct ;
	}
	// system側で確定しない場合はASUS boardの有効なmodelを採用する。
	else if( asusBoard && isValidModel( baseboardProduct)) {
		model = baseboardProduct ;
	}

	// model未確定または未対応buildでは公式page要求を発行しない。
	if( model.empty() || windowsBuild < WINDOWS10_MINIMUM_BUILD) {
		return false ;
	}

	request.model = model ;
	request.osName =
		windowsBuild >= WINDOWS11_MINIMUM_BUILD ? L"Windows 11 64-bit" : L"Windows 10 64-bit" ;
	request.pageUrl = std::wstring( SUPPORT_PAGE_PREFIX) + encodeModelPath( model) +
					  std::wstring( SUPPORT_PAGE_SUFFIX) ;
	applicable = true ;
	return true ;
}

/** @see asus_system_identity.h */
bool makeAsusPublicModelSupportPageRequest( const std::wstring_view publicModel,
										   const std::wstring_view osName,
										   AsusSupportPageRequest &request)
{
	request = {} ;
	// 外部入力ではSMBIOSより狭い公開model文字集合を使いURL・ID断片を拒否する。
	if( publicModel.empty() || !std::ranges::all_of( publicModel, []( const wchar_t character) {
		   return (character >= L'A' && character <= L'Z') ||
				  (character >= L'a' && character <= L'z') ||
				  (character >= L'0' && character <= L'9') ||
				  std::wstring_view( L" ._()+-").find( character) != std::wstring_view::npos ;
	   })) {
		return false ;
	}

	std::wstring markerText( publicModel) ;	// ID markerをASCII大小文字に依存せず照合する。
	std::ranges::transform( markerText, markerText.begin(), []( const wchar_t character) {
		return character >= L'a' && character <= L'z'
				   ? static_cast<wchar_t>( character - L'a' + L'A')
				   : character ;
	}) ;
	// 生PnP ID由来の識別片を公開modelとして外部送信しない。
	if( markerText.find( L"VEN_") != std::wstring::npos ||
	   markerText.find( L"DEV_") != std::wstring::npos ||
	   markerText.find( L"VID_") != std::wstring::npos ||
	   markerText.find( L"PID_") != std::wstring::npos || markerText.starts_with( L"PCI_") ||
	   markerText.starts_with( L"USB_")) {
		return false ;
	}

	// 公開対象OSを二つの明示的なWindows x64表記へ限定する。
	if( osName != L"Windows 11 64-bit" && osName != L"Windows 10 64-bit") {
		return false ;
	}

	bool applicable{} ;	// 既存のcanonical builderによるASUS判定結果。
	// SMBIOSを読まず、公開modelだけで固定ASUS起点を構築する。
	if( !makeAsusSupportPageRequest( L"ASUSTeK COMPUTER INC.", publicModel, L"", L"",
								   osName == L"Windows 11 64-bit" ? WINDOWS11_MINIMUM_BUILD
																  : WINDOWS10_MINIMUM_BUILD,
								   false, request, applicable) ||
	   !applicable || request.model != publicModel || request.osName != osName) {
		request = {} ;
		return false ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asus_system_identity.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError readLocalAsusSupportPageRequest( AsusSupportPageRequest &request, bool &applicable)
{
	request	   = {} ;
	applicable = false ;
	// ServerではClient用のlocal識別処理を開始しない。
	if( isWindowsServer()) {
		return 0 ;
	}

	try {
		std::wstring systemManufacturer ;	// SMBIOS System Manufacturer表示値。
		std::wstring systemProduct ;		// SMBIOS System Product Name表示値。
		std::wstring boardManufacturer ;	// SMBIOS BaseBoard Manufacturer表示値。
		std::wstring boardProduct ;			// SMBIOS BaseBoard Product表示値。
		std::wstring buildText ;			// Windows CurrentBuildNumber原文。
		// SystemManufacturerの読取りから後続の端末照合へ引き継ぐ診断値。
		NativeError	 error = readOptionalRegistryString( HKEY_LOCAL_MACHINE, BIOS_KEY,
														L"SystemManufacturer", systemManufacturer) ;
		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = readOptionalRegistryString( HKEY_LOCAL_MACHINE, BIOS_KEY, L"SystemProductName",
											   systemProduct) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = readOptionalRegistryString( HKEY_LOCAL_MACHINE, BIOS_KEY,
											   L"BaseBoardManufacturer", boardManufacturer) ;
		}

		// 先行段階が成功した場合だけ次の処理へ進み、最初の失敗原因を後続の結果で上書きしない。
		if( error == 0) {
			error = readOptionalRegistryString( HKEY_LOCAL_MACHINE, BIOS_KEY, L"BaseBoardProduct",
											   boardProduct) ;
		}

		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}

		// 両メーカー情報がASUSを示さない場合は追加の要求を構築しない。
		if( !isAsusManufacturer( systemManufacturer) && !isAsusManufacturer( boardManufacturer)) {
			return 0 ;
		}

		error = readOptionalRegistryString( HKEY_LOCAL_MACHINE, WINDOWS_KEY, L"CurrentBuildNumber",
										   buildText) ;
		std::uint32_t windowsBuild{} ;	// 数値化したCurrentBuildNumber。
		// build照会失敗または数値変換失敗では実OSを推測しない。
		if( error != 0 || !parseWindowsBuild( buildText, windowsBuild)) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// local表示値から安全なpage要求を構築できなければ不正dataとして返す。
		if( !makeAsusSupportPageRequest( systemManufacturer, systemProduct, boardManufacturer,
									   boardProduct, windowsBuild, false, request, applicable)) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		return 0 ;
	} catch( const std::bad_alloc &) {
		request	   = {} ;
		applicable = false ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

} // namespace drivercrate
