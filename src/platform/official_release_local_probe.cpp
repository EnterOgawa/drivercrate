//------------------------------------------------------------------------------
/**
 * @file official_release_local_probe.cpp
 * @brief 公式release端末内fingerprint生成実装。
 * @version 01.00.00
 * @date 2026/09/07
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 長さ付きUTF-16 canonical形式をCNGで処理します。Native識別値は呼出し中だけ参照し、返却値や永続化対象へ含めません。
 */
//------------------------------------------------------------------------------

#include "platform/official_release_local_probe.h"

#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t	   DIGEST_BYTES			   = 32U ;		// SHA-256 digest byte数。
constexpr std::size_t	   SHA256_CHARACTERS	   = 64U ;		// 小文字hex文字数。
constexpr std::size_t	   MAXIMUM_NATIVE_IDENTITY = 4'096U ;	// Native識別値の文字数上限。
constexpr std::size_t	   MAXIMUM_DEVICE_BINDINGS = 4'096U ;	// Device集合の件数上限。
constexpr std::string_view DEVICE_DOMAIN =
	"drivercrate.device-binding.v1" ;	// Device HMACの用途分離label。
constexpr std::string_view OPERATING_SYSTEM_DOMAIN =
	"drivercrate.operating-system.v1" ;	// OS hashの用途分離label。
constexpr std::string_view CONFIGURATION_DOMAIN =
	"drivercrate.device-configuration.v1" ;	// Device集合hashの用途分離label。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief NTSTATUSをHRESULT bit patternへ変換する。
 *
 * CNGの元診断値を失わずplatform共通結果型へ変換する。
 *
 * @param[in] status BCrypt APIが返したNTSTATUS。
 * @return NativeErrorで保持できるHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromNt( const NTSTATUS status) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 32-bit整数をlittle-endianで追加する。
 *
 * CPU endianとcompiler表現に依存しないcanonical形式を作る。
 *
 * @param[in] value 追加する値。
 * @param[in,out] output 末尾へ固定4 byteを追加するbuffer。
 */
//------------------------------------------------------------------------------
void appendUint32( const std::uint32_t value, std::vector<std::byte> &output)
{
	// 下位byteから固定4回だけ追加する。
	for( std::uint32_t shift = 0U; shift < 32U; shift += 8U) {
		output.push_back( static_cast<std::byte>( (value >> shift) & 0xffU)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief ASCII用途分離labelを追加する。
 *
 * 同じ入力値を異なるfingerprint用途間で再利用しない。
 *
 * @param[in] label 組み込みASCII label。
 * @param[in,out] output 長さとlabelを追加するbuffer。
 */
//------------------------------------------------------------------------------
void appendLabel( const std::string_view label, std::vector<std::byte> &output)
{
	appendUint32( static_cast<std::uint32_t>( label.size()), output) ;
	// 組み込みlabelをbyte単位で追加する。
	for( const char character : label) {
		output.push_back( static_cast<std::byte>( static_cast<unsigned char>( character))) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief UTF-16値を長さ付きlittle-endianで追加する。
 *
 * 文字数と各code unitを明示し、field境界の曖昧さを防ぐ。
 *
 * @param[in] value NULを含まない有限UTF-16値。
 * @param[in,out] output Canonical byte列。
 * @return 入力を追加できた場合はtrue。不正または上限時はfalse。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool appendUtf16( const std::wstring_view value, std::vector<std::byte> &output)
{
	// 空・長さ超過・埋込み NUL を持つ native identity を正準化へ受理しない。
	if( value.empty() || value.size() > MAXIMUM_NATIVE_IDENTITY ||
	   value.find( L'\0') != std::wstring_view::npos ||
	   value.size() > std::numeric_limits<std::uint32_t>::max()) {
		return false ;
	}

	appendUint32( static_cast<std::uint32_t>( value.size()), output) ;
	// Windowsの各UTF-16 code unitを固定byte順で追加する。
	for( const wchar_t character : value) {
		const std::uint16_t codeUnit = static_cast<std::uint16_t>( character) ;	// UTF-16値。
		output.push_back( static_cast<std::byte>( codeUnit & 0xffU)) ;
		output.push_back( static_cast<std::byte>( (codeUnit >> 8U) & 0xffU)) ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief SHA-256表記を検証する。
 *
 * Device集合のcanonical順序と重複判定を一意にする。
 *
 * @param[in] value 検証するfingerprint表記。
 * @return 64桁小文字hexの場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isLowerSha256( const std::wstring_view value) noexcept
{
	// SHA-256 の固定桁数と異なる binding を拒否する。
	if( value.size() != SHA256_CHARACTERS) {
		return false ;
	}

	// 全文字が小文字hexであることを確認する。
	for( const wchar_t character : value) {
		const bool decimal	 = character >= L'0' && character <= L'9' ;	// 数字範囲。
		const bool lowercase = character >= L'a' && character <= L'f' ;	// 小文字hex範囲。
		// 十進数字と小文字 hex 以外を含む binding は受理しない。
		if( !decimal && !lowercase) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Byte列のSHA-256またはHMAC-SHA-256を取得する。
 *
 * Device bindingだけHMACを使用し、端末間の照合を防ぐ。
 *
 * @param[in] input Canonical入力byte列。
 * @param[in] secret 空ならSHA-256、32 byteならHMAC key。
 * @param[out] digest 成功時の32 byte digest。
 * @return 成功時は0、不正sizeまたはCNG失敗時はHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError hashBytes( const std::span<const std::byte>	 input,
									const std::span<const std::byte>	 secret,
									std::array<std::byte, DIGEST_BYTES> &digest)
{
	digest.fill( std::byte{}) ;
	// 空入力または暗号 API の byte 数範囲を超える入力・鍵を拒否する。
	if( input.empty() || input.size() > std::numeric_limits<ULONG>::max() ||
	   secret.size() > std::numeric_limits<ULONG>::max()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const ULONG		  flags = secret.empty() ? 0U : BCRYPT_ALG_HANDLE_HMAC_FLAG ;	// Algorithm mode。
	// BCryptCloseAlgorithmProvider対象handle。
	BCRYPT_ALG_HANDLE rawAlgorithm{} ;
	const NTSTATUS openStatus = BCryptOpenAlgorithmProvider( &rawAlgorithm, BCRYPT_SHA256_ALGORITHM,
															nullptr, flags) ;	// Algorithm開始結果。
	// Hash algorithm の初期化失敗を native 診断値で返す。
	if( !BCRYPT_SUCCESS( openStatus)) {
		return nativeErrorFromNt( openStatus) ;
	}

	// BCrypt algorithm handleを第二引数0で閉じるdeleter。
	const auto closeAlgorithm = []( void *const value) noexcept {
		static_cast<void>( BCryptCloseAlgorithmProvider( static_cast<BCRYPT_ALG_HANDLE>( value), 0)) ;
	} ;
	// Local probe内のCNG algorithm handleをscope終了時に閉じる所有wrapper。
	const std::unique_ptr<void, decltype( closeAlgorithm)> algorithm( rawAlgorithm, closeAlgorithm) ;

	// BCryptHashは入力を変更しないがWindows宣言がmutable pointerを要求する。
	auto *const											  inputBytes = reinterpret_cast<PUCHAR>(
		  const_cast<std::byte *>( input.data())) ;	// 呼出し中だけ有効な入力view。
	auto *const secretBytes = reinterpret_cast<PUCHAR>(
		const_cast<std::byte *>( secret.data())) ;							// 呼出し中だけ有効なHMAC key view。
	auto *const	   digestBytes = reinterpret_cast<PUCHAR>( digest.data()) ;	// Digest出力先。
	const NTSTATUS hashStatus =
		BCryptHash( static_cast<BCRYPT_ALG_HANDLE>( algorithm.get()), secretBytes,
				   static_cast<ULONG>( secret.size()), inputBytes, static_cast<ULONG>( input.size()),
				   digestBytes, static_cast<ULONG>( digest.size())) ;	// 一回のhashまたはHMAC結果。
	return BCRYPT_SUCCESS( hashStatus) ? 0 : nativeErrorFromNt( hashStatus) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Digestを小文字hexへ変換する。
 *
 * 永続化形式の表記を一意にする。
 *
 * @param[in] digest SHA-256またはHMAC-SHA-256結果。
 * @return 64桁の小文字hex文字列。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring digestToHex( const std::array<std::byte, DIGEST_BYTES> &digest)
{
	constexpr std::wstring_view HEX = L"0123456789abcdef" ;	// 小文字hex変換表。
	std::wstring				result ;					// 64桁へ変換する結果。
	result.reserve( SHA256_CHARACTERS) ;
	// Digestを上位nibbleから固定二文字へ変換する。
	for( const std::byte value : digest) {
		const unsigned int byteValue = std::to_integer<unsigned int>( value) ;	// 0～255。
		result.push_back( HEX[(byteValue >> 4U) & 0x0fU]) ;
		result.push_back( HEX[byteValue & 0x0fU]) ;
	}

	return result ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_local_probe.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError makeLocalOfficialDeviceBindingFingerprint( const LocalOfficialBindingSecret &secret,
													  const std::wstring_view nativeDeviceIdentity,
													  std::wstring			 &fingerprint)
{
	fingerprint.clear() ;
	const bool secretIsZero =	// 初期化されていないkeyならtrue。
		std::all_of( secret.begin(), secret.end(),
					[]( const std::byte value) { return value == std::byte{} ; }) ;
	// ゼロの秘密値と不正な native identity から端末内 binding を生成しない。
	if( secretIsZero || nativeDeviceIdentity.empty() ||
	   nativeDeviceIdentity.size() > MAXIMUM_NATIVE_IDENTITY ||
	   nativeDeviceIdentity.find( L'\0') != std::wstring_view::npos) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::vector<std::byte> canonical ;	// HMAC終了後に破棄するnative値の一時表現。
	canonical.reserve( DEVICE_DOMAIN.size() + nativeDeviceIdentity.size() * 2U + 8U) ;
	appendLabel( DEVICE_DOMAIN, canonical) ;
	// Native identity を正準 byte 列へ追加できなければ binding 生成を中止する。
	if( !appendUtf16( nativeDeviceIdentity, canonical)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::array<std::byte, DIGEST_BYTES> digest{} ;						// HMAC-SHA-256出力。
	const NativeError error = hashBytes( canonical, secret, digest) ;	// CNG処理結果。
	SecureZeroMemory( canonical.data(), canonical.size()) ;
	// Hash 計算失敗時は中間 digest を消去して元の診断値を返す。
	if( error != 0) {
		SecureZeroMemory( digest.data(), digest.size()) ;
		return error ;
	}

	fingerprint = digestToHex( digest) ;
	SecureZeroMemory( digest.data(), digest.size()) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_local_probe.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError makeLocalOfficialEnvironmentFingerprints(
	const bool windowsServer, const std::uint32_t windowsBuild,
	const std::uint32_t windowsProductSku, const std::span<const std::wstring> deviceBindings,
	OfficialReleaseEnvironmentFingerprints &fingerprints)
{
	fingerprints = {} ;
// 非 x64 build では端末構成の fingerprint を生成せず未対応として返す。
#if !defined( _WIN64)
	static_cast<void>( windowsServer) ;
	static_cast<void>( windowsBuild) ;
	static_cast<void>( windowsProductSku) ;
	static_cast<void>( deviceBindings) ;
	return static_cast<NativeError>( E_NOTIMPL) ;
#else
	// OS 識別値の欠落と空・件数超過の device 構成を拒否する。
	if( windowsBuild == 0U || windowsProductSku == 0U || deviceBindings.empty() ||
	   deviceBindings.size() > MAXIMUM_DEVICE_BINDINGS) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::vector<std::wstring> ordered( deviceBindings.begin(),
									  // Sort対象の所有copy。
									  deviceBindings.end()) ;
	// 全fingerprintを検証してから順序非依存のcanonical集合を作る。
	for( const std::wstring &binding : ordered) {
		// Device binding が正規の小文字 SHA-256 表記でなければ構成に含めない。
		if( !isLowerSha256( binding)) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}
	}

	std::sort( ordered.begin(), ordered.end()) ;
	// 整列済み binding に重複がある構成は一意な inventory と扱わない。
	if( std::adjacent_find( ordered.begin(), ordered.end()) != ordered.end()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::vector<std::byte> operatingSystem ;	// OS fingerprintのcanonical入力。
	appendLabel( OPERATING_SYSTEM_DOMAIN, operatingSystem) ;
	operatingSystem.push_back( windowsServer ? std::byte{1U} : std::byte{}) ;
	appendUint32( windowsBuild, operatingSystem) ;
	appendUint32( windowsProductSku, operatingSystem) ;
	appendLabel( "x64", operatingSystem) ;
	std::array<std::byte, DIGEST_BYTES> operatingSystemDigest{} ;	// OS SHA-256。
	NativeError error = hashBytes( operatingSystem, std::span<const std::byte>{},
								  operatingSystemDigest) ;	// OS計算結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	std::vector<std::byte> configuration ;	// Device集合fingerprintのcanonical入力。
	configuration.reserve( CONFIGURATION_DOMAIN.size() + ordered.size() * 68U + 8U) ;
	appendLabel( CONFIGURATION_DOMAIN, configuration) ;
	appendUint32( static_cast<std::uint32_t>( ordered.size()), configuration) ;
	// Sort済みfingerprintを長さ付きUTF-16として一件ずつ追加する。
	for( const std::wstring &binding : ordered) {
		// Binding を正準構成へ追加できなければ fingerprint 生成を中止する。
		if( !appendUtf16( binding, configuration)) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}
	}

	std::array<std::byte, DIGEST_BYTES> configurationDigest{} ;	// Device集合SHA-256。
	error = hashBytes( configuration, std::span<const std::byte>{},
					  configurationDigest) ;	// 集合計算結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	fingerprints.operatingSystem	 = digestToHex( operatingSystemDigest) ;
	fingerprints.deviceConfiguration = digestToHex( configurationDigest) ;
	return 0 ;
#endif
}

} // namespace drivercrate
