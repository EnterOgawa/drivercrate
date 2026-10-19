//------------------------------------------------------------------------------
/**
 * @file official_release_observation_store.cpp
 * @brief 公式release観測と自動探索cacheの端末内永続化実装。
 * @version 01.01.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  端末固有binding key管理追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  URL非保持の公式自動探索cache永続化を追加。
 * Ver.01.01.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note Version付きsnapshotと端末固有keyを有限bufferで扱い、reparse pointを拒否します。Production rootは
 *       SYSTEM／Administratorsだけが利用でき、保存は一時fileのflush後にatomic置換します。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#include "platform/official_release_observation_store.h"

#include <Windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shlobj.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
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

constexpr std::wstring_view PRODUCT_DIRECTORY_NAME = L"DriverCrate" ;				// 製品directory名。
constexpr std::wstring_view STATE_DIRECTORY_NAME   = L"ReleaseObservations" ;		// State directory名。
constexpr std::wstring_view STATE_FILE_NAME		   = L"release-observations.bin" ;	// Snapshot名。
constexpr std::wstring_view DISCOVERY_CACHE_FILE_NAME =
	L"official-discovery-cache.bin" ;	// URL非保持cacheの固定snapshot名。
constexpr std::wstring_view BINDING_SECRET_FILE_NAME =
	L"binding-secret.bin" ;	// 端末固有HMAC keyの固定file名。
constexpr std::array<std::byte, 8> FILE_MAGIC{
	static_cast<std::byte>( 'D'), static_cast<std::byte>( 'C'), static_cast<std::byte>( 'R'),
	static_cast<std::byte>( 'O'), static_cast<std::byte>( 'S'), static_cast<std::byte>( '0'),
	// Format識別子。
	static_cast<std::byte>( '0'), static_cast<std::byte>( '1')} ;
constexpr std::array<std::byte, 8> DISCOVERY_CACHE_FILE_MAGIC{
	static_cast<std::byte>( 'D'), static_cast<std::byte>( 'C'), static_cast<std::byte>( 'D'),
	static_cast<std::byte>( 'C'), static_cast<std::byte>( 'S'), static_cast<std::byte>( '0'),
	// 公式自動探索cache形式の識別子。
	static_cast<std::byte>( '0'), static_cast<std::byte>( '1')} ;
constexpr std::uint32_t FORMAT_VERSION				   = 1U ;			// Binary format revision。
constexpr std::uint32_t DISCOVERY_CACHE_FORMAT_VERSION = 1U ;			// Cache binary format revision。
constexpr std::size_t	DIGEST_BYTES				   = 32U ;			// SHA-256 digest byte数。
constexpr std::size_t	FIXED_HEADER_BYTES			   = 52U ;			// Magic、整数、digestの合計byte数。
constexpr std::size_t	MAXIMUM_OBSERVATION_COUNT	   = 4'096U ;		// 一snapshotのrecord上限。
constexpr std::size_t	MAXIMUM_DISCOVERY_CACHE_ENTRY_COUNT = 256U ;	// 一snapshotのroot entry上限。
constexpr std::size_t	MAXIMUM_STATE_BYTES = 4U * 1'024U * 1'024U ;	// File全体上限。

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief CloseHandleで解放する所有handle。
 */
using UniqueWin32Handle = std::unique_ptr<void, decltype( &CloseHandle)> ;
/**
 * @brief LocalFreeで解放する所有memory。
 */
using UniqueLocalMemory = std::unique_ptr<void, decltype( &LocalFree)> ;
/**
 * @brief CoTaskMemFreeで解放する所有memory。
 */
using UniqueCoTaskMemory = std::unique_ptr<void, decltype( &CoTaskMemFree)> ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをHRESULT bit patternへ変換する。
 *
 * 元のWin32診断値を失わずplatform共通結果型へ変換する。
 *
 * @param[in] error GetLastErrorまたはWin32 APIのerror。
 * @return NativeErrorで保持できるHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief NTSTATUSをHRESULT bit patternへ変換する。
 *
 * CNG失敗codeを診断可能な形式で保持する。
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
 * @brief Byte列のSHA-256を取得する。
 *
 * Snapshot payloadの破損をload時に検出する。
 *
 * @param[in] input 最大4 MiBの入力byte列。
 * @param[out] digest 成功時の32 byte SHA-256。
 * @return 成功時は0、上限またはCNG失敗時はHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError sha256Bytes( const std::span<const std::byte>	   input,
									  std::array<std::byte, DIGEST_BYTES> &digest)
{
	digest.fill( std::byte{}) ;
	// 暗号 API の入力長範囲を超える byte 列は hash 計算へ渡さない。
	if( input.size() > std::numeric_limits<ULONG>::max()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	BCRYPT_ALG_HANDLE rawAlgorithm{} ;	// BCryptCloseAlgorithmProvider対象handle。
	const NTSTATUS openStatus = BCryptOpenAlgorithmProvider( &rawAlgorithm, BCRYPT_SHA256_ALGORITHM,
															nullptr, 0) ;	// Algorithm開始結果。
	// SHA-256 algorithm を初期化できなければ診断値を返す。
	if( !BCRYPT_SUCCESS( openStatus)) {
		return nativeErrorFromNt( openStatus) ;
	}

	// BCrypt algorithm handleへ第二引数0を渡して確実に閉じるdeleter。
	const auto closeAlgorithm = []( void *const value) noexcept {
		static_cast<void>( BCryptCloseAlgorithmProvider( static_cast<BCRYPT_ALG_HANDLE>( value), 0)) ;
	} ;
	// 観測情報のhash計算用CNG algorithm handleを所有するwrapper。
	const std::unique_ptr<void, decltype( closeAlgorithm)> algorithm( rawAlgorithm, closeAlgorithm) ;

	// BCryptHashは入力を変更しないがWin32宣言がmutable pointerを要求する。
	auto *const											  inputBytes = reinterpret_cast<PUCHAR>(
		  const_cast<std::byte *>( input.data())) ;							// 呼出し中だけ有効な非所有byte view。
	auto *const	   outputBytes = reinterpret_cast<PUCHAR>( digest.data()) ;	// Digest出力先byte view。
	const NTSTATUS hashStatus =
		BCryptHash( static_cast<BCRYPT_ALG_HANDLE>( algorithm.get()), nullptr, 0, inputBytes,
				   static_cast<ULONG>( input.size()), outputBytes,
				   // 一回のSHA-256結果。
				   static_cast<ULONG>( digest.size())) ;
	return BCRYPT_SUCCESS( hashStatus) ? 0 : nativeErrorFromNt( hashStatus) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 32-bit整数をlittle-endianで追加する。
 *
 * Compilerのpaddingとhost endianに依存しない形式を作る。
 *
 * @param[in] value 追加する符号なし値。
 * @param[in,out] output 末尾へ4 byteを追加するbuffer。
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
 * @brief 64-bit整数をlittle-endianで追加する。
 *
 * FILETIME値を明示したbyte順で保存する。
 *
 * @param[in] value 追加する符号なし値。
 * @param[in,out] output 末尾へ8 byteを追加するbuffer。
 */
//------------------------------------------------------------------------------
void appendUint64( const std::uint64_t value, std::vector<std::byte> &output)
{
	// 下位byteから固定8回だけ追加する。
	for( std::uint32_t shift = 0U; shift < 64U; shift += 8U) {
		output.push_back( static_cast<std::byte>( (value >> shift) & 0xffU)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief UTF-16文字列を長さ付きUTF-8へ追加する。
 *
 * 空文字列は長さ0として保存し、不正surrogateを拒否する。
 *
 * @param[in] value 保存する有限UTF-16文字列。
 * @param[in,out] output 長さとUTF-8を追加するpayload。
 * @return 成功時は0、不正Unicodeまたは上限時はHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError appendUtf8( const std::wstring_view value, std::vector<std::byte> &output)
{
	// 変換 API の文字数範囲を超える文字列は保存形式へ受理しない。
	if( value.size() > static_cast<std::size_t>( std::numeric_limits<int>::max())) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 空文字列は本文を追加せず、長さゼロの field として記録する。
	if( value.empty()) {
		// 空文字列でも長さ field の追加が保存上限を超えないことを確認する。
		if( output.size() > MAXIMUM_STATE_BYTES - sizeof( std::uint32_t)) {
			return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
		}

		appendUint32( 0U, output) ;
		return 0 ;
	}

	const int		  required = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
													 static_cast<int>( value.size()), nullptr, 0, nullptr,
													 nullptr) ;	// UTF-8必要byte数。
	const std::size_t requiredSize =
		required > 0 ? static_cast<std::size_t>( required) : 0U ;	// 符号検証後のUTF-8長。
	// UTF-8 変換量の不正と長さ field を含む保存上限超過を加算前に拒否する。
	if( required <= 0 || requiredSize > MAXIMUM_STATE_BYTES - sizeof( std::uint32_t) ||
	   output.size() > MAXIMUM_STATE_BYTES - sizeof( std::uint32_t) - requiredSize) {
		return nativeErrorFromWin32( required <= 0 ? GetLastError() : ERROR_FILE_TOO_LARGE) ;
	}

	appendUint32( static_cast<std::uint32_t>( required), output) ;
	const std::size_t originalSize = output.size() ;	// UTF-8追記開始位置。
	output.resize( originalSize + static_cast<std::size_t>( required)) ;
	auto *const destination =
		reinterpret_cast<char *>( output.data() + originalSize) ;	// UTF-8出力先。
	const int converted = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
											  static_cast<int>( value.size()), destination, required,
											  nullptr, nullptr) ;	// UTF-8変換結果byte数。
	return converted == required ? 0 : nativeErrorFromWin32( GetLastError()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのrelease観測をpayloadへ追加する。
 *
 * 固定field順で追加し、URL、PnP ID、payloadを保存しない。
 *
 * @param[in] observation Core検証済み観測。
 * @param[in,out] payload 末尾へrecordを追加する有限buffer。
 * @return 成功時は0、文字変換または容量上限時はHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError appendObservation( const LocalOfficialReleaseObservation &observation,
											std::vector<std::byte>				  &payload)
{
	const std::array<std::wstring_view, 11> fields{
		observation.binding.deviceBindingFingerprint,
		observation.binding.providerId,
		observation.binding.sourceId,
		observation.binding.familyId,
		observation.binding.productKey,
		observation.binding.branch,
		observation.environment.operatingSystemFingerprint,
		observation.environment.deviceConfigurationFingerprint,
		observation.releaseKey,
		observation.packageVersion,
		observation.publishedSha256} ;	// Binary format順の文字列field。
	// 全fieldを同じUTF-8規則で追加し、最初の変換失敗で停止する。
	for( const std::wstring_view field : fields) {
		const NativeError error = appendUtf8( field, payload) ;	// 現在fieldの変換結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}
	}

	// 固定数値 field の追加が snapshot 上限を超えないことを確認する。
	if( payload.size() > MAXIMUM_STATE_BYTES - 20U) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	appendUint32( observation.environment.policyRevision, payload) ;
	appendUint32( observation.environment.parserRevision, payload) ;
	appendUint64( observation.observedFileTime, payload) ;
	appendUint32( static_cast<std::uint32_t>( observation.pendingReason), payload) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 32-bit整数を保存上限内で追加します。
 *
 * @param[in] value 追加する符号なし値です。
 * @param[in,out] output 末尾へ4 byteを追加するbufferです。
 * @return 追加成功時は0、保存上限超過時はHRESULT bit patternです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError appendLimitedUint32( const std::uint32_t	  value,
											  std::vector<std::byte> &output)
{
	// 固定長fieldを追加できない場合は部分fieldを作りません。
	if( output.size() > MAXIMUM_STATE_BYTES - sizeof( value)) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	appendUint32( value, output) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 64-bit整数を保存上限内で追加します。
 *
 * @param[in] value 追加する符号なし値です。
 * @param[in,out] output 末尾へ8 byteを追加するbufferです。
 * @return 追加成功時は0、保存上限超過時はHRESULT bit patternです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError appendLimitedUint64( const std::uint64_t	  value,
											  std::vector<std::byte> &output)
{
	// 固定長fieldを追加できない場合は部分fieldを作りません。
	if( output.size() > MAXIMUM_STATE_BYTES - sizeof( value)) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	appendUint64( value, output) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定byte列を保存上限内で追加します。
 *
 * @param[in] value 追加する固定byte列です。
 * @param[in,out] output 末尾へbyte列を追加するbufferです。
 * @return 追加成功時は0、保存上限超過時はHRESULT bit patternです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError appendLimitedBytes( const std::span<const std::byte> value,
											 std::vector<std::byte>			 &output)
{
	// 残容量より大きいbyte列を追加しません。
	if( value.size() > MAXIMUM_STATE_BYTES || output.size() > MAXIMUM_STATE_BYTES - value.size()) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	output.insert( output.end(), value.begin(), value.end()) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つの公式自動探索payload公開metadataを追加します。
 *
 * URL、hash値、EULA本文、grantまたはlocal pathを受け取らない固定fieldだけを保存します。
 *
 * @param[in] value 保存する公開payload metadataです。
 * @param[in,out] output 末尾へpayloadを追加する有限bufferです。
 * @return 成功時は0、文字変換または容量上限時はHRESULT bit patternです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError appendDiscoveryCachePayload( const OfficialDiscoveryCachedPayload &value,
													  std::vector<std::byte>			   &output)
{
	NativeError error = appendLimitedUint32( value.payloadOrdinal, output) ;	// Ordinal保存結果。
	// Ordinalを保存できなければ後続fieldを追加しません。
	if( error != 0) {
		return error ;
	}

	const std::array<std::wstring_view, 6> publicFields{
		value.payloadResourceId, value.fileDisplayName, value.productFamily, value.operatingSystem,
		value.packageVersion,	 value.publishedDate} ;	// Binary format前半の文字列。
	// 公開文字列を固定順で追加し、最初の変換失敗で停止します。
	for( const std::wstring_view field : publicFields) {
		error = appendUtf8( field, output) ;
		// 不正Unicodeまたは上限超過後に部分recordを継続しません。
		if( error != 0) {
			return error ;
		}
	}

	const std::uint32_t hasPublishedSize =
		// Size有無。
		value.publishedSizeBytes.has_value() ? 1U : 0U ;
	const std::uint64_t publishedSize = value.publishedSizeBytes.value_or( 0U) ;	// 保存size値。
	const std::array<std::uint32_t, 2> publicFlags{static_cast<std::uint32_t>( value.payloadKind),
												   hasPublishedSize} ;	// Kindとsize有無。
	// Enumとoptional有無を固定順で追加します。
	for( const std::uint32_t flag : publicFlags) {
		error = appendLimitedUint32( flag, output) ;
		// 固定値の保存上限超過後は残りを追加しません。
		if( error != 0) {
			return error ;
		}
	}

	error = appendLimitedUint64( publishedSize, output) ;
	// Size値を保存できなければ後続fieldを追加しません。
	if( error != 0) {
		return error ;
	}

	const std::array<std::uint32_t, 2> trailingFlags{value.publishedSha256Available ? 1U : 0U,
													 // Hash有無とdownload前条件。
													 static_cast<std::uint32_t>( value.terms)} ;
	// 残るflagを固定順で追加します。
	for( const std::uint32_t flag : trailingFlags) {
		error = appendLimitedUint32( flag, output) ;
		// 固定値の保存上限超過後は残りを追加しません。
		if( error != 0) {
			return error ;
		}
	}

	const std::array<std::wstring_view, 2> trailingFields{
		value.declaredPublisher, value.eulaRevision} ;	// Binary format後半の文字列。
	// PublisherとEULA revisionだけを保存し、本文を受け取りません。
	for( const std::wstring_view field : trailingFields) {
		error = appendUtf8( field, output) ;
		// 不正Unicodeまたは上限超過後に部分recordを継続しません。
		if( error != 0) {
			return error ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのURL非保持公式自動探索cache entryを追加します。
 *
 * @param[in] entry 公開validatorに合格したentryです。
 * @param[in,out] output 末尾へentryを追加する有限bufferです。
 * @return 成功時は0、文字変換または容量上限時はHRESULT bit patternです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError appendDiscoveryCacheEntry( const OfficialDiscoveryCacheEntry &entry,
													std::vector<std::byte>			  &output)
{
	const std::array<std::uint32_t, 2> leadingNumbers{
		entry.schemaRevision, static_cast<std::uint32_t>( entry.kind)} ;	// Schemaと結果種別。
	NativeError error{} ;													// 現在fieldの保存結果。
	// Schemaと結果種別を先頭へ追加します。
	for( const std::uint32_t number : leadingNumbers) {
		error = appendLimitedUint32( number, output) ;
		// 固定値の保存上限超過後は残りを追加しません。
		if( error != 0) {
			return error ;
		}
	}

	const std::array<std::wstring_view, 3> bindingFields{
		entry.providerId, entry.policyId, entry.rootResourceId} ;	// 組み込み固定root binding。
	// Provider、policyとrootを固定順で追加します。
	for( const std::wstring_view field : bindingFields) {
		error = appendUtf8( field, output) ;
		// 不正Unicodeまたは上限超過後に部分entryを継続しません。
		if( error != 0) {
			return error ;
		}
	}

	error = appendLimitedUint32( entry.policyRevision, output) ;
	// Policy revisionを保存できなければparser情報へ進みません。
	if( error != 0) {
		return error ;
	}

	error = appendUtf8( entry.parserId, output) ;
	// Parser IDの変換に失敗したentryを継続しません。
	if( error != 0) {
		return error ;
	}

	error = appendLimitedUint32( entry.parserRevision, output) ;
	// Parser revisionを保存できなければrecord情報へ進みません。
	if( error != 0) {
		return error ;
	}

	error = appendLimitedBytes( entry.recordFingerprint.bytes, output) ;
	// URL非保持record fingerprintを完全に保存できないentryを継続しません。
	if( error != 0) {
		return error ;
	}

	error = appendLimitedUint32( static_cast<std::uint32_t>( entry.payloads.size()), output) ;
	// Payload件数を保存できなければ個別metadataへ進みません。
	if( error != 0) {
		return error ;
	}

	// Validator済みの全payloadをordinal順に追加します。
	for( const OfficialDiscoveryCachedPayload &payload : entry.payloads) {
		error = appendDiscoveryCachePayload( payload, output) ;
		// 一件でも保存できなければ部分entryを成功にしません。
		if( error != 0) {
			return error ;
		}
	}

	const std::array<std::uint64_t, 2> timestamps{entry.observedUtcSeconds,
												  entry.expiresUtcSeconds} ;	// 観測と期限のUTC秒。
	// 観測と期限を固定順で追加します。
	for( const std::uint64_t timestamp : timestamps) {
		error = appendLimitedUint64( timestamp, output) ;
		// 時刻fieldの保存上限超過後は残りを追加しません。
		if( error != 0) {
			return error ;
		}
	}

	const std::array<std::wstring_view, 2> environmentFields{
		entry.operatingSystemFingerprint,
		entry.deviceConfigurationFingerprint} ;	// URL非保持の環境fingerprint。
	// 二つの環境fingerprintを固定順で追加します。
	for( const std::wstring_view field : environmentFields) {
		error = appendUtf8( field, output) ;
		// 不正Unicodeまたは上限超過後に部分entryを継続しません。
		if( error != 0) {
			return error ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式自動探索cacheの固定root重複検出keyを作ります。
 *
 * @param[in] entry 公開validatorに合格したentryです。
 * @return Field境界をNULで分離したprocess内専用keyです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring discoveryCacheKey( const OfficialDiscoveryCacheEntry &entry)
{
	std::wstring						   key ;	// Unordered setへ渡す衝突しないfield列。
	const std::array<std::wstring_view, 3> fields{entry.providerId, entry.policyId,
												  entry.rootResourceId} ;	// 一意な固定root binding。
	// Stable IDが含まないNULをfield境界として追加します。
	for( const std::wstring_view field : fields) {
		key.append( field) ;
		key.push_back( L'\0') ;
	}

	return key ;
}

//------------------------------------------------------------------------------
/**
 * @brief Binding重複検出keyを作成する。
 *
 * 一snapshot内の同じdevice／source対応を一件に限定する。
 *
 * @param[in] binding Core検証済み端末内binding。
 * @return Field境界をNULで分離したprocess内専用key。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring bindingKey( const LocalOfficialSourceBinding &binding)
{
	std::wstring						   key ;	// Unordered setへ渡す衝突しないfield列。
	const std::array<std::wstring_view, 6> fields{binding.deviceBindingFingerprint,
												  binding.providerId,
												  binding.sourceId,
												  binding.familyId,
												  binding.productKey,
												  binding.branch} ;	// Binding field順。
	// Stable IDが含まないNULをfield境界として追加する。
	for( const std::wstring_view field : fields) {
		key.append( field) ;
		key.push_back( L'\0') ;
	}

	return key ;
}

//------------------------------------------------------------------------------
/**
 * @brief 観測集合を一つのbinary snapshotへ変換する。
 *
 * 既存snapshotを変更する前に全recordを検証して直列化する。
 *
 * @param[in] observations 保存する全観測。
 * @param[out] encoded 成功時のheader、digest、payload。
 * @return 成功時は0、不正、重複、上限、CNG失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError encodeSnapshot(
	const std::span<const LocalOfficialReleaseObservation> observations,
	std::vector<std::byte>								  &encoded)
{
	encoded.clear() ;
	// 保存可能件数を超える観測集合を受理しない。
	if( observations.size() > MAXIMUM_OBSERVATION_COUNT) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::vector<std::byte>			 payload ;	// 全recordを保持するdigest対象buffer。
	std::unordered_set<std::wstring> bindings ;	// Snapshot内binding重複検出集合。
	bindings.reserve( observations.size()) ;
	// 全観測を検証して一つずつ有限payloadへ追加する。
	for( const LocalOfficialReleaseObservation &observation : observations) {
		// 不正な観測と binding の重複を snapshot へ記録しない。
		if( !isLocalOfficialReleaseObservationValid( observation) ||
		   !bindings.insert( bindingKey( observation.binding)).second) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		const NativeError error = appendObservation( observation, payload) ;	// Record変換結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( error != 0) {
			return error ;
		}
	}

	// Header を含む保存上限と payload 長 field の表現範囲を確認する。
	if( payload.size() > MAXIMUM_STATE_BYTES - FIXED_HEADER_BYTES ||
	   payload.size() > std::numeric_limits<std::uint32_t>::max()) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	std::array<std::byte, DIGEST_BYTES> digest{} ;									// PayloadのSHA-256。
	const NativeError					hashError = sha256Bytes( payload, digest) ;	// CNG計算結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( hashError != 0) {
		return hashError ;
	}

	encoded.reserve( FIXED_HEADER_BYTES + payload.size()) ;
	encoded.insert( encoded.end(), FILE_MAGIC.begin(), FILE_MAGIC.end()) ;
	appendUint32( FORMAT_VERSION, encoded) ;
	appendUint32( static_cast<std::uint32_t>( observations.size()), encoded) ;
	appendUint32( static_cast<std::uint32_t>( payload.size()), encoded) ;
	encoded.insert( encoded.end(), digest.begin(), digest.end()) ;
	encoded.insert( encoded.end(), payload.begin(), payload.end()) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式自動探索cache集合を独立したbinary snapshotへ変換します。
 *
 * 既存snapshotを変更する前にURL非保持schemaと固定root一意性を検証します。
 *
 * @param[in] entries 保存する全cache entryです。
 * @param[out] encoded 成功時のheader、digestとpayloadです。
 * @return 成功時は0、不正、重複、上限またはCNG失敗時はHRESULT bit patternです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError encodeDiscoveryCacheSnapshot(
	const std::span<const OfficialDiscoveryCacheEntry> entries, std::vector<std::byte> &encoded)
{
	encoded.clear() ;
	// 保存可能件数を超える固定root集合を受理しません。
	if( entries.size() > MAXIMUM_DISCOVERY_CACHE_ENTRY_COUNT) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	std::vector<std::byte>			 payload ;	// 全entryを保持するdigest対象buffer。
	std::unordered_set<std::wstring> bindings ;	// Snapshot内固定root重複検出集合。
	bindings.reserve( entries.size()) ;
	// 全entryを検証して一つずつ有限payloadへ追加します。
	for( const OfficialDiscoveryCacheEntry &entry : entries) {
		// 不正entryまたは同じProvider固定rootの重複をsnapshotへ記録しません。
		if( !isOfficialDiscoveryCacheEntryValid( entry) ||
		   !bindings.insert( discoveryCacheKey( entry)).second) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		const NativeError error = appendDiscoveryCacheEntry( entry, payload) ;	// Entry変換結果。
		// 最初の変換失敗を後続処理で上書きしません。
		if( error != 0) {
			return error ;
		}
	}

	// Headerを含む保存上限とpayload長fieldの表現範囲を確認します。
	if( payload.size() > MAXIMUM_STATE_BYTES - FIXED_HEADER_BYTES ||
	   payload.size() > std::numeric_limits<std::uint32_t>::max()) {
		return nativeErrorFromWin32( ERROR_FILE_TOO_LARGE) ;
	}

	std::array<std::byte, DIGEST_BYTES> digest{} ;									// Cache payloadのSHA-256。
	const NativeError					hashError = sha256Bytes( payload, digest) ;	// CNG計算結果。
	// Hash計算失敗を後続処理で上書きしません。
	if( hashError != 0) {
		return hashError ;
	}

	encoded.reserve( FIXED_HEADER_BYTES + payload.size()) ;
	encoded.insert( encoded.end(), DISCOVERY_CACHE_FILE_MAGIC.begin(),
				   DISCOVERY_CACHE_FILE_MAGIC.end()) ;
	appendUint32( DISCOVERY_CACHE_FORMAT_VERSION, encoded) ;
	appendUint32( static_cast<std::uint32_t>( entries.size()), encoded) ;
	appendUint32( static_cast<std::uint32_t>( payload.size()), encoded) ;
	encoded.insert( encoded.end(), digest.begin(), digest.end()) ;
	encoded.insert( encoded.end(), payload.begin(), payload.end()) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 32-bit little-endian整数を読み取る。
 *
 * 範囲外入力でoffsetを進めず、host endianへ依存しない。
 *
 * @param[in] input 検証対象buffer。
 * @param[in,out] offset 読取り開始位置と成功時の次位置。
 * @param[out] value 成功時の値。
 * @return 4 byteを範囲内で読めた場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readUint32( const std::span<const std::byte> input, std::size_t &offset,
							  std::uint32_t &value) noexcept
{
	// 32-bit 整数の全 byte が残っていない場合は読取りを拒否する。
	if( offset > input.size() || input.size() - offset < sizeof( std::uint32_t)) {
		return false ;
	}

	std::uint32_t decoded{} ;	// Little-endianから組み立てる値。
	// 固定4 byteを下位側から結合する。
	for( std::uint32_t index = 0U; index < 4U; ++index) {
		decoded |= std::to_integer<std::uint32_t>( input[offset + index]) << (index * 8U) ;
	}

	offset += sizeof( std::uint32_t) ;
	value = decoded ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 64-bit little-endian整数を読み取る。
 *
 * 範囲外入力でoffsetを進めず、FILETIME値を復元する。
 *
 * @param[in] input 検証対象buffer。
 * @param[in,out] offset 読取り開始位置と成功時の次位置。
 * @param[out] value 成功時の値。
 * @return 8 byteを範囲内で読めた場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readUint64( const std::span<const std::byte> input, std::size_t &offset,
							  std::uint64_t &value) noexcept
{
	// 64-bit 整数の全 byte が残っていない場合は読取りを拒否する。
	if( offset > input.size() || input.size() - offset < sizeof( std::uint64_t)) {
		return false ;
	}

	std::uint64_t decoded{} ;	// Little-endianから組み立てる値。
	// 固定8 byteを下位側から結合する。
	for( std::uint32_t index = 0U; index < 8U; ++index) {
		decoded |= static_cast<std::uint64_t>( std::to_integer<std::uint32_t>( input[offset + index]))
				   << (index * 8U) ;
	}

	offset += sizeof( std::uint64_t) ;
	value = decoded ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 長さ付きUTF-8をUTF-16へ読み取る。
 *
 * 不正UTF-8、NUL、範囲外長を受理しない。
 *
 * @param[in] input Record payload。
 * @param[in,out] offset 長さfield位置と成功時の次位置。
 * @param[out] value 成功時のUTF-16文字列。
 * @return 長さ、UTF-8、変換結果が正しい場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readUtf8( const std::span<const std::byte> input, std::size_t &offset,
							std::wstring &value)
{
	value.clear() ;
	std::uint32_t byteCount{} ;	// 保存されたUTF-8 byte数。
	// 文字列の宣言長が残り data と変換 API の上限内に収まることを確認する。
	if( !readUint32( input, offset, byteCount) || offset > input.size() ||
	   static_cast<std::size_t>( byteCount) > input.size() - offset ||
	   byteCount > static_cast<std::uint32_t>( std::numeric_limits<int>::max())) {
		return false ;
	}

	// 長さゼロの field は空文字列として正常に読み終える。
	if( byteCount == 0U) {
		return true ;
	}

	const auto *const source =
		reinterpret_cast<const char *>( input.data() + offset) ;	// UTF-8入力先頭。
	// 埋込み NUL を持つ保存文字列は後続照合へ渡さない。
	if( std::find( source, source + byteCount, '\0') != source + byteCount) {
		return false ;
	}

	const int required = MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, source,
											 static_cast<int>( byteCount), nullptr,
											 0) ;	// UTF-16必要文字数。
	// UTF-8 検証または必要文字数の計算に失敗した field を拒否する。
	if( required <= 0) {
		return false ;
	}

	std::wstring decoded( static_cast<std::size_t>( required), L'\0') ;	// UTF-16変換先。
	const int	 converted = MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, source,
												 static_cast<int>( byteCount), decoded.data(),
												 required) ;	// UTF-16変換結果文字数。
	// 予定文字数どおりに変換できなければ部分文字列を受理しない。
	if( converted != required) {
		return false ;
	}

	offset += byteCount ;
	value = std::move( decoded) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのbinary recordをrelease観測へ変換する。
 *
 * 未知enum、欠落、上限、不正identityを復元後に再拒否する。
 *
 * @param[in] payload SHA-256検証済みpayload。
 * @param[in,out] offset Record開始位置と成功時の次位置。
 * @param[out] observation 成功時のcore検証済み観測。
 * @return 全fieldとcore保存契約が正しい場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readObservation( const std::span<const std::byte> payload, std::size_t &offset,
								   LocalOfficialReleaseObservation &observation)
{
	LocalOfficialReleaseObservation decoded ;	// 全field成功後に返す一時観測。
	std::array<std::wstring *, 11>	fields{&decoded.binding.deviceBindingFingerprint,
										   &decoded.binding.providerId,
										   &decoded.binding.sourceId,
										   &decoded.binding.familyId,
										   &decoded.binding.productKey,
										   &decoded.binding.branch,
										   &decoded.environment.operatingSystemFingerprint,
										   &decoded.environment.deviceConfigurationFingerprint,
										   &decoded.releaseKey,
										   &decoded.packageVersion,
										   &decoded.publishedSha256} ;	// Binary format順の出力field。
	// 全文字列fieldを固定順で復元する。
	for( std::wstring *const field : fields) {
		// 必須文字列 field を一つでも復元できなければ record 全体を拒否する。
		if( !readUtf8( payload, offset, *field)) {
			return false ;
		}
	}

	std::uint32_t pendingReason{} ;	// 保存された未確認理由enum値。
	// Revision、観測時刻、保留理由の数値 field が欠ける record を拒否する。
	if( !readUint32( payload, offset, decoded.environment.policyRevision) ||
	   !readUint32( payload, offset, decoded.environment.parserRevision) ||
	   !readUint64( payload, offset, decoded.observedFileTime) ||
	   !readUint32( payload, offset, pendingReason)) {
		return false ;
	}

	decoded.pendingReason = static_cast<ReleaseObservationPendingReason>( pendingReason) ;
	// 復元した観測が公開契約を満たさなければ呼出し元へ渡さない。
	if( !isLocalOfficialReleaseObservationValid( decoded)) {
		return false ;
	}

	observation = std::move( decoded) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定長byte列を範囲内で読み取ります。
 *
 * @param[in] input 検証対象bufferです。
 * @param[in,out] offset 読取り開始位置と成功時の次位置です。
 * @param[out] value 成功時に固定長byte列を受け取るspanです。
 * @return 全byteを範囲内で読めた場合trueです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readFixedBytes( const std::span<const std::byte> input, std::size_t &offset,
								  std::span<std::byte> value) noexcept
{
	// 固定長全体が残っていない場合はoffsetと出力を変更しません。
	if( value.size() > input.size() || offset > input.size() - value.size()) {
		return false ;
	}

	std::copy_n( input.begin() + static_cast<std::ptrdiff_t>( offset), value.size(), value.begin()) ;
	offset += value.size() ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのbinary recordを公式自動探索payload公開metadataへ変換します。
 *
 * @param[in] payload SHA-256検証済みpayloadです。
 * @param[in,out] offset Record開始位置と成功時の次位置です。
 * @param[out] value 成功時のURL非保持payload metadataです。
 * @return 全fieldが正しい範囲とcanonical表現の場合trueです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readDiscoveryCachePayload( const std::span<const std::byte> payload,
											 std::size_t					 &offset,
											 OfficialDiscoveryCachedPayload	 &value)
{
	OfficialDiscoveryCachedPayload decoded ;	// 全field成功後に返す一時payload。
	// Ordinalが欠落したrecordを拒否します。
	if( !readUint32( payload, offset, decoded.payloadOrdinal)) {
		return false ;
	}

	std::array<std::wstring *, 6> publicFields{
		&decoded.payloadResourceId, &decoded.fileDisplayName,
		&decoded.productFamily,		&decoded.operatingSystem,
		&decoded.packageVersion,	&decoded.publishedDate} ;	// 前半文字列出力先。
	// 公開文字列を固定順で復元します。
	for( std::wstring *const field : publicFields) {
		// 一つでもUTF-8を復元できなければpayload全体を拒否します。
		if( !readUtf8( payload, offset, *field)) {
			return false ;
		}
	}

	std::uint32_t payloadKind{} ;		// 保存されたpayload kind enum値。
	std::uint32_t hasPublishedSize{} ;	// Optional size有無のcanonical flag。
	std::uint64_t publishedSize{} ;		// Optional有無にかかわらず保存されたsize値。
	std::uint32_t hashAvailable{} ;		// 公開SHA-256有無のcanonical flag。
	std::uint32_t terms{} ;				// 保存されたdownload前条件enum値。
	// Kind、size、hash有無と利用条件の数値fieldが欠けるrecordを拒否します。
	if( !readUint32( payload, offset, payloadKind) ||
	   !readUint32( payload, offset, hasPublishedSize) ||
	   !readUint64( payload, offset, publishedSize) || !readUint32( payload, offset, hashAvailable) ||
	   !readUint32( payload, offset, terms)) {
		return false ;
	}

	// Boolを0または1へ限定し、sizeなしに非zero値を隠す表現を拒否します。
	if( hasPublishedSize > 1U || hashAvailable > 1U ||
	   (hasPublishedSize == 0U && publishedSize != 0U)) {
		return false ;
	}

	std::array<std::wstring *, 2> trailingFields{&decoded.declaredPublisher,
												 &decoded.eulaRevision} ;	// 後半文字列出力先。
	// PublisherとEULA revisionを固定順で復元します。
	for( std::wstring *const field : trailingFields) {
		// 一つでもUTF-8を復元できなければpayload全体を拒否します。
		if( !readUtf8( payload, offset, *field)) {
			return false ;
		}
	}

	decoded.payloadKind = static_cast<OfficialDistributionPayloadKind>( payloadKind) ;
	// Size有りのcanonical表現だけをoptionalへ復元します。
	if( hasPublishedSize == 1U) {
		decoded.publishedSizeBytes = publishedSize ;
	}

	decoded.publishedSha256Available = hashAvailable == 1U ;
	decoded.terms					 = static_cast<OfficialDistributionTerms>( terms) ;
	value							 = std::move( decoded) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのbinary recordをURL非保持公式自動探索cache entryへ変換します。
 *
 * @param[in] payload SHA-256検証済みpayloadです。
 * @param[in,out] offset Record開始位置と成功時の次位置です。
 * @param[out] entry 成功時の公開validator検証済みentryです。
 * @return 全field、件数と固定root bindingが正しい場合trueです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readDiscoveryCacheEntry( const std::span<const std::byte> payload,
										   std::size_t &offset, OfficialDiscoveryCacheEntry &entry)
{
	OfficialDiscoveryCacheEntry decoded ;	// 全field成功後に返す一時entry。
	std::uint32_t				kind{} ;	// 保存されたentry kind enum値。
	// Schemaとentry種別が欠落したrecordを拒否します。
	if( !readUint32( payload, offset, decoded.schemaRevision) || !readUint32( payload, offset, kind)) {
		return false ;
	}

	std::array<std::wstring *, 3> bindingFields{
		&decoded.providerId, &decoded.policyId,
		&decoded.rootResourceId} ;	// 固定root binding出力先。
	// Provider、policyとrootを固定順で復元します。
	for( std::wstring *const field : bindingFields) {
		// 一つでもUTF-8を復元できなければentry全体を拒否します。
		if( !readUtf8( payload, offset, *field)) {
			return false ;
		}
	}

	// Policy revisionとparser IDを順番どおりに復元します。
	if( !readUint32( payload, offset, decoded.policyRevision) ||
	   !readUtf8( payload, offset, decoded.parserId) ||
	   !readUint32( payload, offset, decoded.parserRevision) ||
	   !readFixedBytes( payload, offset, decoded.recordFingerprint.bytes)) {
		return false ;
	}

	std::uint32_t payloadCount{} ;	// 保存された公開payload件数。
	// 件数field欠落または一entryの有限上限超過を拒否します。
	if( !readUint32( payload, offset, payloadCount) || payloadCount > 32U) {
		return false ;
	}

	decoded.payloads.reserve( payloadCount) ;
	// Headerが宣言した有限件数だけをordinal順に復元します。
	for( std::uint32_t index = 0U; index < payloadCount; ++index) {
		OfficialDiscoveryCachedPayload cachedPayload ;	// 現在復元する一payload。
		// 一件でもfieldを復元できなければentry全体を拒否します。
		if( !readDiscoveryCachePayload( payload, offset, cachedPayload)) {
			return false ;
		}

		decoded.payloads.push_back( std::move( cachedPayload)) ;
	}

	// 観測、期限と二つの環境fingerprintが欠けるentryを拒否します。
	if( !readUint64( payload, offset, decoded.observedUtcSeconds) ||
	   !readUint64( payload, offset, decoded.expiresUtcSeconds) ||
	   !readUtf8( payload, offset, decoded.operatingSystemFingerprint) ||
	   !readUtf8( payload, offset, decoded.deviceConfigurationFingerprint)) {
		return false ;
	}

	decoded.kind = static_cast<OfficialDiscoveryCacheEntryKind>( kind) ;
	// 復元したentryがschema、期限と固定root契約を満たさなければ公開しません。
	if( !isOfficialDiscoveryCacheEntryValid( decoded)) {
		return false ;
	}

	entry = std::move( decoded) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Binary snapshotを検証済み観測集合へ変換する。
 *
 * 余剰byte、重複binding、将来versionをfail-closedで拒否する。
 *
 * @param[in] encoded 上限付きで読み取ったfile全体。
 * @param[out] observations 成功時の観測集合。
 * @return 正常時は0、不正形式またはCNG失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError decodeSnapshot( const std::span<const std::byte>			   encoded,
										 std::vector<LocalOfficialReleaseObservation> &observations)
{
	observations.clear() ;
	// Snapshot の size 範囲と magic が正しくない入力を拒否する。
	if( encoded.size() < FIXED_HEADER_BYTES || encoded.size() > MAXIMUM_STATE_BYTES ||
	   !std::equal( FILE_MAGIC.begin(), FILE_MAGIC.end(), encoded.begin())) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::size_t	  offset = FILE_MAGIC.size() ;	// Header内の現在読取り位置。
	std::uint32_t version{} ;					// 保存format revision。
	std::uint32_t recordCount{} ;				// 保存record件数。
	std::uint32_t payloadSize{} ;				// 保存payload byte数。
	// Header 欠落、未対応 version、件数上限超過、digest 領域不足を拒否する。
	if( !readUint32( encoded, offset, version) || !readUint32( encoded, offset, recordCount) ||
	   !readUint32( encoded, offset, payloadSize) || version != FORMAT_VERSION ||
	   recordCount > static_cast<std::uint32_t>( MAXIMUM_OBSERVATION_COUNT) ||
	   offset + DIGEST_BYTES > encoded.size()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::array<std::byte, DIGEST_BYTES> storedDigest{} ;	// File header内のSHA-256。
	const std::span<const std::byte>	digestView =
		// Header内digest範囲。
		encoded.subspan( offset, DIGEST_BYTES) ;
	std::copy( digestView.begin(), digestView.end(), storedDigest.begin()) ;
	offset += DIGEST_BYTES ;
	// Payload の宣言長と残り byte 数が異なる snapshot を拒否する。
	if( static_cast<std::size_t>( payloadSize) != encoded.size() - offset) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const std::span<const std::byte>	payload = encoded.subspan( offset) ;	// Record payload全体。
	std::array<std::byte, DIGEST_BYTES> actualDigest{} ;						// 再計算したSHA-256。
	const NativeError hashError = sha256Bytes( payload, actualDigest) ;			// CNG計算結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( hashError != 0) {
		return hashError ;
	}

	// 保存 digest と計算値が異なる snapshot は破損として受理しない。
	if( actualDigest != storedDigest) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::size_t									 payloadOffset{} ;	// Payload内の次record位置。
	std::vector<LocalOfficialReleaseObservation> decoded ;			// 全成功後に返す観測集合。
	decoded.reserve( recordCount) ;
	std::unordered_set<std::wstring> bindings ;	// 復元recordのbinding重複検出集合。
	bindings.reserve( recordCount) ;
	// Headerが宣言した有限件数だけを復元する。
	for( std::uint32_t index = 0U; index < recordCount; ++index) {
		LocalOfficialReleaseObservation observation ;	// 現在復元する一record。
		// 観測の復元失敗と binding 重複を検出したら集合全体を拒否する。
		if( !readObservation( payload, payloadOffset, observation) ||
		   !bindings.insert( bindingKey( observation.binding)).second) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		decoded.push_back( std::move( observation)) ;
	}

	// 宣言件数を復元した後の余分な payload を許可しない。
	if( payloadOffset != payload.size()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	observations = std::move( decoded) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Binary snapshotを検証済み公式自動探索cache集合へ変換します。
 *
 * 余剰byte、重複固定root、未知versionまたは不正schemaをfail-closedで拒否します。
 *
 * @param[in] encoded 上限付きで読み取ったfile全体です。
 * @param[out] entries 成功時のURL非保持cache entry集合です。
 * @return 正常時は0、不正形式またはCNG失敗時はHRESULT bit patternです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError decodeDiscoveryCacheSnapshot(
	const std::span<const std::byte> encoded, std::vector<OfficialDiscoveryCacheEntry> &entries)
{
	entries.clear() ;
	// Snapshotのsize範囲と専用magicが正しくない入力を拒否します。
	if( encoded.size() < FIXED_HEADER_BYTES || encoded.size() > MAXIMUM_STATE_BYTES ||
	   !std::equal( DISCOVERY_CACHE_FILE_MAGIC.begin(), DISCOVERY_CACHE_FILE_MAGIC.end(),
				   encoded.begin())) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::size_t	  offset = DISCOVERY_CACHE_FILE_MAGIC.size() ;	// Header内の現在読取り位置。
	std::uint32_t version{} ;									// 保存format revision。
	std::uint32_t entryCount{} ;								// 保存entry件数。
	std::uint32_t payloadSize{} ;								// 保存payload byte数。
	// Header欠落、未対応version、件数上限超過またはdigest領域不足を拒否します。
	if( !readUint32( encoded, offset, version) || !readUint32( encoded, offset, entryCount) ||
	   !readUint32( encoded, offset, payloadSize) || version != DISCOVERY_CACHE_FORMAT_VERSION ||
	   entryCount > static_cast<std::uint32_t>( MAXIMUM_DISCOVERY_CACHE_ENTRY_COUNT) ||
	   offset + DIGEST_BYTES > encoded.size()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::array<std::byte, DIGEST_BYTES> storedDigest{} ;	// File header内のSHA-256。
	const std::span<const std::byte>	digestView =
		// Header内digest範囲。
		encoded.subspan( offset, DIGEST_BYTES) ;
	std::copy( digestView.begin(), digestView.end(), storedDigest.begin()) ;
	offset += DIGEST_BYTES ;
	// Payloadの宣言長と残りbyte数が異なるsnapshotを拒否します。
	if( static_cast<std::size_t>( payloadSize) != encoded.size() - offset) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const std::span<const std::byte>	payload = encoded.subspan( offset) ;	// Entry payload全体。
	std::array<std::byte, DIGEST_BYTES> actualDigest{} ;						// 再計算したSHA-256。
	const NativeError hashError = sha256Bytes( payload, actualDigest) ;			// CNG計算結果。
	// Hash計算失敗を後続処理で上書きしません。
	if( hashError != 0) {
		return hashError ;
	}

	// 保存digestと計算値が異なるsnapshotは破損として受理しません。
	if( actualDigest != storedDigest) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::size_t								 payloadOffset{} ;	// Payload内の次entry位置。
	std::vector<OfficialDiscoveryCacheEntry> decoded ;			// 全成功後に返すentry集合。
	decoded.reserve( entryCount) ;
	std::unordered_set<std::wstring> bindings ;	// 復元entryの固定root重複検出集合。
	bindings.reserve( entryCount) ;
	// Headerが宣言した有限件数だけを復元します。
	for( std::uint32_t index = 0U; index < entryCount; ++index) {
		OfficialDiscoveryCacheEntry entry ;	// 現在復元する一entry。
		// Entry復元失敗または同じProvider固定rootの重複で集合全体を拒否します。
		if( !readDiscoveryCacheEntry( payload, payloadOffset, entry) ||
		   !bindings.insert( discoveryCacheKey( entry)).second) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		decoded.push_back( std::move( entry)) ;
	}

	// 宣言件数を復元した後の余分なpayloadを許可しません。
	if( payloadOffset != payload.size()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	entries = std::move( decoded) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Directoryが通常directoryか確認する。
 *
 * Elevated processのstate書込み先をreparse pointへ移さない。
 *
 * @param[in] path 検証する絶対directory path。
 * @return 通常directoryなら0、欠落またはreparse時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateDirectory( const std::wstring_view path)
{
	const std::wstring owned( path) ;										// Win32 API用終端null付きpath。
	const DWORD		   attributes = GetFileAttributesW( owned.c_str()) ;	// Directory属性。
	// Directory 属性を照会できなければ安全な保存先と仮定しない。
	if( attributes == INVALID_FILE_ATTRIBUTES) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 通常 directory でない対象と reparse point を保存先に使用しない。
	if( (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
	   (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
		return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Production pathへ保護DACLを設定する。
 *
 * SYSTEMとbuilt-in Administratorsだけへfull accessを許可する。
 *
 * @param[in] path 所有者変更を行わない既存fileまたはdirectory。
 * @return DACL設定成功時は0、security API失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError protectPath( const std::wstring_view path)
{
	constexpr std::wstring_view SECURITY_DESCRIPTOR =
		L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" ;	// 対象とdirectoryの子へ適用する保護DACL。
	PSECURITY_DESCRIPTOR rawDescriptor{} ;			// SDDL変換が割り当てる所有memory。
	// 固定 security descriptor を構築できなければ保護設定を中止する。
	if( ConvertStringSecurityDescriptorToSecurityDescriptorW(
		   SECURITY_DESCRIPTOR.data(), SDDL_REVISION_1, &rawDescriptor, nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const UniqueLocalMemory descriptor( rawDescriptor, &LocalFree) ;	// LocalFree対象descriptor。
	BOOL					present{} ;									// DescriptorにDACLが存在すればTRUE。
	BOOL					defaulted{} ;								// Default DACL由来ならTRUE。
	PACL					dacl{} ;									// Descriptor lifetime中有効な非所有ACL。
	const BOOL				gotDacl =
		// DACL取得結果。
		GetSecurityDescriptorDacl( descriptor.get(), &present, &dacl, &defaulted) ;
	static_cast<void>( defaulted) ;
	// 有効な DACL が取得できなければ無制限の権限へ退避しない。
	if( gotDacl == FALSE || present == FALSE || dacl == nullptr) {
		return nativeErrorFromWin32( ERROR_INVALID_SECURITY_DESCR) ;
	}

	std::wstring owned( path) ;	// SetNamedSecurityInfo用mutable終端null付きpath。
	const DWORD	 error =
		SetNamedSecurityInfoW( owned.data(), SE_FILE_OBJECT,
							  DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
							  nullptr, nullptr, dacl, nullptr) ;	// DACL設定結果。
	return error == ERROR_SUCCESS ? 0 : nativeErrorFromWin32( error) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常directoryを作成して必要なDACLを設定する。
 *
 * 既存pathもreparse検証し、pre-createによる置換を拒否する。
 *
 * @param[in] path 作成または再利用する絶対path。
 * @param[in] protect trueの場合はproduction保護DACLを設定する。
 * @return 作成、検証、DACL設定成功時は0、それ以外はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError ensureDirectory( const std::wstring_view path, const bool protect)
{
	const std::wstring owned( path) ;	// CreateDirectory用終端null付きpath。
	// Directory 作成が失敗した場合は既存 directory とその他の失敗を区別する。
	if( CreateDirectoryW( owned.c_str(), nullptr) == FALSE) {
		const DWORD error = GetLastError() ;	// 既存directoryか判定する作成error。
		// 既存対象以外の作成失敗は診断値を保持して返す。
		if( error != ERROR_ALREADY_EXISTS) {
			return nativeErrorFromWin32( error) ;
		}
	}

	const NativeError validationError = validateDirectory( path) ;	// Reparse等の検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( validationError != 0) {
		return validationError ;
	}

	return protect ? protectPath( path) : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Release observation rootを初期化する。
 *
 * ProductionではProgramData直下から二段を検証して保護する。
 *
 * @param[in] overridePath 空または試験用絶対path。
 * @param[out] root 成功時の通常directory絶対path。
 * @return Root利用可能時は0、known folderまたはACL失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError initializeRoot( const std::wstring_view overridePath, std::wstring &root)
{
	root.clear() ;
	// 試験用 root の明示指定がある場合だけ通常の保存先解決を置き換える。
	if( !overridePath.empty()) {
		const std::filesystem::path testRoot( overridePath) ;	// 試験指定rootの構文。
		// 試験用 root でも相対 path を許可して CWD に依存させない。
		if( !testRoot.is_absolute()) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		root = overridePath ;
		return ensureDirectory( root, false) ;
	}

	PWSTR		  rawProgramData{} ;	// SHGetKnownFolderPathが割り当てる所有path。
	const HRESULT folderResult =
		SHGetKnownFolderPath( FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr,
							 &rawProgramData) ;	// ProgramData取得結果。
	// 失敗の診断値を共通の表現へ保ったまま返し、未完了の結果で後続処理を進めない。
	if( FAILED( folderResult)) {
		return static_cast<NativeError>( folderResult) ;
	}

	const UniqueCoTaskMemory programData( rawProgramData,
										 &CoTaskMemFree) ;							// CoTaskMemFree対象path。
	std::wstring productRoot( static_cast<const wchar_t *>( programData.get())) ;	// 製品root。
	productRoot.append( L"\\").append( PRODUCT_DIRECTORY_NAME) ;
	NativeError error = ensureDirectory( productRoot, true) ;	// 製品root初期化結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	root = productRoot ;
	root.append( L"\\").append( STATE_DIRECTORY_NAME) ;
	error = ensureDirectory( root, true) ;
	// 初期化失敗時は未検証の root を呼出し元へ残さない。
	if( error != 0) {
		root.clear() ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief State file pathを構築する。
 *
 * 外部入力をfile名へ使用せずpath traversalを作らない。
 *
 * @param[in] root 検証済みstate root。
 * @return 固定basenameを持つ完全path。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring stateFilePath( const std::wstring_view root)
{
	std::wstring path( root) ;	// 固定basenameを追加する結果。
	path.append( L"\\").append( STATE_FILE_NAME) ;
	return path ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式自動探索cache file pathを構築します。
 *
 * 外部入力をfile名へ使用せずpath traversalを作りません。
 *
 * @param[in] root 検証済みstate rootです。
 * @return 固定basenameを持つ完全pathです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring discoveryCacheFilePath( const std::wstring_view root)
{
	std::wstring path( root) ;	// 固定basenameを追加する結果。
	path.append( L"\\").append( DISCOVERY_CACHE_FILE_NAME) ;
	return path ;
}

//------------------------------------------------------------------------------
/**
 * @brief Binding secret file pathを構築する。
 *
 * 外部入力をfile名へ使用せずpath traversalを作らない。
 *
 * @param[in] root 検証済みstate root。
 * @return 固定basenameを持つ完全path。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring bindingSecretFilePath( const std::wstring_view root)
{
	std::wstring path( root) ;	// 固定basenameを追加する結果。
	path.append( L"\\").append( BINDING_SECRET_FILE_NAME) ;
	return path ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常fileを上限付きで読み取る。
 *
 * Reparse pointと範囲外sizeを拒否し、一回で読み取る。
 *
 * @param[in] path State root配下の固定file path。
 * @param[in] minimumBytes 許可する最小file byte数。
 * @param[in] maximumBytes 許可する最大file byte数。
 * @param[out] content 成功時のfile全体。
 * @return 読取り成功時は0、size、reparse、I/O失敗時はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readFile( const std::wstring_view path, const std::size_t minimumBytes,
								   const std::size_t maximumBytes, std::vector<std::byte> &content)
{
	content.clear() ;
	// 矛盾する最小・最大長と ReadFile 上限超過を読取り前に拒否する。
	if( minimumBytes == 0U || minimumBytes > maximumBytes ||
	   maximumBytes > std::numeric_limits<DWORD>::max()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring owned( path) ;	// CreateFile用終端null付きpath。
	const HANDLE	   rawFile = CreateFileW(
		  owned.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
		  nullptr) ;	// CloseHandle対象file handle。
	// 対象 file を開けなければ byte 列を読み取らない。
	if( rawFile == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const UniqueWin32Handle file( rawFile, &CloseHandle) ;	// 所有file handle。
	FILE_ATTRIBUTE_TAG_INFO tagInfo{} ;						// Reparse属性とtagの取得先。
	LARGE_INTEGER			size{} ;						// File全体のsigned byte数。
	const BOOL				gotAttributes = GetFileInformationByHandleEx(
		 // 属性取得結果。
		 file.get(), FileAttributeTagInfo, &tagInfo, sizeof( tagInfo)) ;
	const BOOL gotSize = GetFileSizeEx( file.get(), &size) ;	// Size取得結果。
	// 属性または size を取得できなければ未確認のまま読取りへ進まない。
	if( gotAttributes == FALSE || gotSize == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// Reparse point と directory は通常の保存 file と扱わない。
	if( (tagInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
	   (tagInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
		return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
	}

	// File size が許可する最小・最大範囲外なら読み取らない。
	if( size.QuadPart < static_cast<LONGLONG>( minimumBytes) ||
	   static_cast<std::uint64_t>( size.QuadPart) > maximumBytes) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::vector<std::byte> loaded( static_cast<std::size_t>( size.QuadPart)) ;	// File buffer。
	DWORD				   bytesRead{} ;										// ReadFileが返したbyte数。
	const BOOL			   readResult =
		ReadFile( file.get(), loaded.data(), static_cast<DWORD>( loaded.size()), &bytesRead,
				 nullptr) ;	// Snapshot全体読取り結果。
	// 読取り失敗と予定長未満の終端を区別して診断値を返す。
	if( readResult == FALSE || bytesRead != static_cast<DWORD>( loaded.size())) {
		return nativeErrorFromWin32( readResult == FALSE ? GetLastError() : ERROR_HANDLE_EOF) ;
	}

	content = std::move( loaded) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Byte列を新規fileへ保存してflushする。
 *
 * CREATE_NEWで既存fileを上書きせず、partial writeを拒否する。
 *
 * @param[in] path 未作成である一時file path。
 * @param[in] content 保存する有限snapshot。
 * @return 保存とflush成功時は0、それ以外はHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError writeNewFile( const std::wstring_view			path,
									   const std::span<const std::byte> content)
{
	// 空内容、保存上限超過、書込み API の長さ超過を保存前に拒否する。
	if( content.empty() || content.size() > MAXIMUM_STATE_BYTES ||
	   content.size() > std::numeric_limits<DWORD>::max()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	const std::wstring owned( path) ;	// CreateFile用終端null付きpath。
	const HANDLE	   rawFile = CreateFileW( owned.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
											 FILE_ATTRIBUTE_NORMAL, nullptr) ;	// 所有file handle。
	// 新規 file を作成できなければ既存 file を暗黙に上書きしない。
	if( rawFile == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const UniqueWin32Handle file( rawFile, &CloseHandle) ;	// CloseHandle対象file。
	DWORD					written{} ;						// WriteFileが保存したbyte数。
	const BOOL				writeResult =
		WriteFile( file.get(), content.data(), static_cast<DWORD>( content.size()), &written,
				  nullptr) ;	// Snapshot全体書込み結果。
	// 全 byte を書き込めなかった場合は保存成功を返さない。
	if( writeResult == FALSE || written != static_cast<DWORD>( content.size())) {
		return nativeErrorFromWin32( writeResult == FALSE ? GetLastError() : ERROR_WRITE_FAULT) ;
	}

	return FlushFileBuffers( file.get()) != FALSE ? 0 : nativeErrorFromWin32( GetLastError()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief State fileをbest-effortで削除する。
 *
 * 破損snapshotの再利用防止を優先し、削除errorを伝播しない。
 *
 * @param[in] path 固定state file path。
 */
//------------------------------------------------------------------------------
void discardFile( const std::wstring_view path) noexcept
{
	const std::wstring owned( path) ;	// DeleteFile用終端null付きpath。
	static_cast<void>( DeleteFileW( owned.c_str())) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既存binding secretを検証して読み取る。
 *
 * Reparseを拒否し、全0 keyを破損として扱う。
 *
 * @param[in] path 固定secret file path。
 * @param[in] protect Production DACLを再設定する場合はtrue。
 * @param[out] secret 成功時の端末固有key。
 * @return 正常な32 byte fileなら0、それ以外はHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError loadBindingSecretFile( const std::wstring_view path, const bool protect,
												LocalOfficialBindingSecret &secret)
{
	secret.fill( std::byte{}) ;
	// 保護指定がある key file では読取り前に固定 DACL を適用する。
	if( protect) {
		const NativeError protectionError = protectPath( path) ;	// DACL再固定結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( protectionError != 0) {
			return protectionError ;
		}
	}

	std::vector<std::byte> encoded ;	// 固定32 byteだけを保持する読取りbuffer。
	const NativeError	   readError =
		// 有限読取り結果。
		readFile( path, secret.size(), secret.size(), encoded) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( readError != 0) {
		return readError ;
	}

	const bool allZero =	// 破損または未初期化keyならtrue。
		std::all_of( encoded.begin(), encoded.end(),
					[]( const std::byte value) { return value == std::byte{} ; }) ;
	// 全ゼロの秘密値は無効とし、読み取った中間 buffer を消去する。
	if( allZero) {
		SecureZeroMemory( encoded.data(), encoded.size()) ;
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::copy( encoded.begin(), encoded.end(), secret.begin()) ;
	SecureZeroMemory( encoded.data(), encoded.size()) ;
	return 0 ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_observation_store.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialReleaseObservationStore::OfficialReleaseObservationStore( std::wstring rootOverride)
	: rootOverride_( std::move( rootOverride))
{
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_observation_store.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialReleaseObservationStore::load( ReleaseObservationStoreResult &result) const
{
	result = {} ;
	std::wstring	  root ;												// 初期化済みstate root。
	const NativeError rootError = initializeRoot( rootOverride_, root) ;	// Root初期化結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( rootError != 0) {
		return rootError ;
	}

	const std::wstring path		  = stateFilePath( root) ;				// 固定snapshot path。
	const DWORD		   attributes = GetFileAttributesW( path.c_str()) ;	// 不在判定用file属性。
	// 属性照会に失敗した場合は保存物の未作成と I/O 失敗を区別する。
	if( attributes == INVALID_FILE_ATTRIBUTES) {
		const DWORD error = GetLastError() ;	// MissingとI/O失敗を区別する値。
		// File または保存 path がない場合は正常な未保存状態として返す。
		if( error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
			result.state = ReleaseObservationStoreState::MISSING ;
			return 0 ;
		}

		return nativeErrorFromWin32( error) ;
	}

	// Directory と reparse point を観測 snapshot として読み取らない。
	if( (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
	   (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
		return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
	}

	// 本番保存先では既存 snapshot の DACL も固定してから読み取る。
	if( rootOverride_.empty()) {
		const NativeError protectionError = protectPath( path) ;	// 既存fileのDACL固定結果。
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
		if( protectionError != 0) {
			return protectionError ;
		}
	}

	std::vector<std::byte> encoded ;	// 上限内で読み取るsnapshot候補。
	const NativeError	   readError =
		// 有限読取り結果。
		readFile( path, FIXED_HEADER_BYTES, MAXIMUM_STATE_BYTES, encoded) ;
	// 読取り失敗時は破損による失効とその他の I/O 失敗を分ける。
	if( readError != 0) {
		// 不正 size 等の破損 file は破棄し、観測の失効を通知する。
		if( readError == nativeErrorFromWin32( ERROR_INVALID_DATA)) {
			discardFile( path) ;
			result.state = ReleaseObservationStoreState::INVALIDATED ;
			return 0 ;
		}

		return readError ;
	}

	std::vector<LocalOfficialReleaseObservation> observations ;					// Decode成功時の観測集合。
	const NativeError decodeError = decodeSnapshot( encoded, observations) ;	// 形式検証結果。
	// Decode 失敗では不正 data の失効と実行 error を区別する。
	if( decodeError != 0) {
		// Data 破損以外の decode 失敗は保存物を破棄せず診断値を返す。
		if( decodeError != nativeErrorFromWin32( ERROR_INVALID_DATA)) {
			return decodeError ;
		}

		discardFile( path) ;
		result.state = ReleaseObservationStoreState::INVALIDATED ;
		return 0 ;
	}

	result.state		= ReleaseObservationStoreState::LOADED ;
	result.observations = std::move( observations) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_observation_store.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialReleaseObservationStore::store(
	const std::span<const LocalOfficialReleaseObservation> observations) const
{
	std::vector<std::byte> encoded ;										// 検証済みの完全snapshot。
	NativeError			   error = encodeSnapshot( observations, encoded) ;	// 全入力の直列化結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	std::wstring root ;	// 初期化済みstate root。
	error = initializeRoot( rootOverride_, root) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	const std::wstring finalPath = stateFilePath( root) ;	// Commit後のsnapshot path。
	const std::wstring suffix	 = L"." + std::to_wstring( GetCurrentProcessId()) + L"." +
								std::to_wstring( GetCurrentThreadId()) +
								L".tmp" ;					// 一時file固有suffix。
	const std::wstring temporaryPath = finalPath + suffix ;	// CREATE_NEW対象path。
	discardFile( temporaryPath) ;
	error = writeNewFile( temporaryPath, encoded) ;
	// 本番の仮 file が正常に作成できた場合だけ置換前に DACL を固定する。
	if( error == 0 && rootOverride_.empty()) {
		// 置換前に固定DACLを明示する結果。
		error = protectPath( temporaryPath) ;
	}

	// 準備済み snapshot の置換に失敗した場合はその診断値を保持する。
	if( error == 0 && MoveFileExW( temporaryPath.c_str(), finalPath.c_str(),
								 MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
		error = nativeErrorFromWin32( GetLastError()) ;
	}

	discardFile( temporaryPath) ;
	return error ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_observation_store.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError OfficialReleaseObservationStore::loadDiscoveryCache(
	DiscoveryCacheStoreResult &result) const
{
	result = {} ;
	std::wstring	  root ;												// 初期化済みstate root。
	const NativeError rootError = initializeRoot( rootOverride_, root) ;	// Root初期化結果。
	// Rootを初期化できなければfile操作へ進みません。
	if( rootError != 0) {
		return rootError ;
	}

	const std::wstring path		  = discoveryCacheFilePath( root) ;		// 固定cache snapshot path。
	const DWORD		   attributes = GetFileAttributesW( path.c_str()) ;	// 不在判定用file属性。
	// 属性照会に失敗した場合は保存物の未作成とI/O失敗を区別します。
	if( attributes == INVALID_FILE_ATTRIBUTES) {
		const DWORD error = GetLastError() ;	// MissingとI/O失敗を区別する値。
		// Fileまたは保存pathがない場合は正常な未保存状態として返します。
		if( error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
			result.state = DiscoveryCacheStoreState::MISSING ;
			return 0 ;
		}

		return nativeErrorFromWin32( error) ;
	}

	// Directoryとreparse pointをcache snapshotとして読み取りません。
	if( (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
	   (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
		return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
	}

	// 本番保存先では既存snapshotのDACLも固定してから読み取ります。
	if( rootOverride_.empty()) {
		const NativeError protectionError = protectPath( path) ;	// 既存fileのDACL固定結果。
		// DACLを固定できなければ未確認内容を読み取りません。
		if( protectionError != 0) {
			return protectionError ;
		}
	}

	std::vector<std::byte> encoded ;	// 上限内で読み取るcache snapshot候補。
	const NativeError	   readError =
		// 有限読取り結果。
		readFile( path, FIXED_HEADER_BYTES, MAXIMUM_STATE_BYTES, encoded) ;
	// 読取り失敗時は破損による失効とその他のI/O失敗を分けます。
	if( readError != 0) {
		// 不正size等の破損fileは破棄し、cache失効を通知します。
		if( readError == nativeErrorFromWin32( ERROR_INVALID_DATA)) {
			discardFile( path) ;
			result.state = DiscoveryCacheStoreState::INVALIDATED ;
			return 0 ;
		}

		return readError ;
	}

	std::vector<OfficialDiscoveryCacheEntry> entries ;	// Decode成功時のURL非保持entry集合。
	const NativeError						 decodeError =
		// 形式検証結果。
		decodeDiscoveryCacheSnapshot( encoded, entries) ;
	// Decode失敗では不正dataの失効と実行errorを区別します。
	if( decodeError != 0) {
		// Data破損以外のdecode失敗は保存物を破棄せず診断値を返します。
		if( decodeError != nativeErrorFromWin32( ERROR_INVALID_DATA)) {
			return decodeError ;
		}

		discardFile( path) ;
		result.state = DiscoveryCacheStoreState::INVALIDATED ;
		return 0 ;
	}

	result.state   = DiscoveryCacheStoreState::LOADED ;
	result.entries = std::move( entries) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_observation_store.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError OfficialReleaseObservationStore::storeDiscoveryCache(
	const std::span<const OfficialDiscoveryCacheEntry> entries) const
{
	std::vector<std::byte> encoded ;										// 検証済みの完全cache snapshot。
	NativeError error = encodeDiscoveryCacheSnapshot( entries, encoded) ;	// 全入力の直列化結果。
	// Encodeに失敗した場合は既存snapshotを変更しません。
	if( error != 0) {
		return error ;
	}

	std::wstring root ;	// 初期化済みstate root。
	error = initializeRoot( rootOverride_, root) ;
	// Rootを初期化できなければfile操作へ進みません。
	if( error != 0) {
		return error ;
	}

	const std::wstring finalPath = discoveryCacheFilePath( root) ;	// Commit後のcache path。
	const std::wstring suffix	 = L"." + std::to_wstring( GetCurrentProcessId()) + L"." +
								std::to_wstring( GetCurrentThreadId()) +
								L".tmp" ;					// 一時file固有suffix。
	const std::wstring temporaryPath = finalPath + suffix ;	// CREATE_NEW対象path。
	discardFile( temporaryPath) ;
	error = writeNewFile( temporaryPath, encoded) ;
	// 本番の仮fileが正常に作成できた場合だけ置換前にDACLを固定します。
	if( error == 0 && rootOverride_.empty()) {
		// 置換前の固定DACL設定結果。
		error = protectPath( temporaryPath) ;
	}

	// 準備済みsnapshotの置換に失敗した場合はその診断値を保持します。
	if( error == 0 && MoveFileExW( temporaryPath.c_str(), finalPath.c_str(),
								 MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
		error = nativeErrorFromWin32( GetLastError()) ;
	}

	discardFile( temporaryPath) ;
	return error ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_observation_store.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialReleaseObservationStore::loadOrCreateBindingSecret(
	LocalOfficialBindingSecret &secret, bool &regenerated) const
{
	secret.fill( std::byte{}) ;
	regenerated = false ;
	std::wstring root ;											// 初期化済みstate root。
	NativeError	 error = initializeRoot( rootOverride_, root) ;	// Root初期化結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	const std::wstring path		  = bindingSecretFilePath( root) ;		// 固定secret path。
	DWORD			   attributes = GetFileAttributesW( path.c_str()) ;	// 既存file属性または不在。
	// Key file が既にある場合は形式を検証し、正常な秘密値を再利用する。
	if( attributes != INVALID_FILE_ATTRIBUTES) {
		// Directory と reparse point を秘密値の保存 file として許可しない。
		if( (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
		   (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
			return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		error = loadBindingSecretFile( path, rootOverride_.empty(), secret) ;
		// 既存 key を正常に取得できた場合は新しい key を生成しない。
		if( error == 0) {
			return 0 ;
		}

		// 破損以外の既存 key 読取り失敗では key を置き換えない。
		if( error != nativeErrorFromWin32( ERROR_INVALID_DATA)) {
			return error ;
		}

		// 通常fileの破損keyだけを破棄し、過去fingerprintを再利用不能にする。
		if( DeleteFileW( path.c_str()) == FALSE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		regenerated = true ;
	} else {
		const DWORD attributeError = GetLastError() ;	// 不在とI/O失敗を区別する値。
		// 未作成以外の属性照会失敗を key 不在とみなして再生成しない。
		if( attributeError != ERROR_FILE_NOT_FOUND && attributeError != ERROR_PATH_NOT_FOUND) {
			return nativeErrorFromWin32( attributeError) ;
		}

		regenerated = true ;
	}

	LocalOfficialBindingSecret generated{} ;	// CNGで作る一時key。
	const NTSTATUS			   randomStatus = BCryptGenRandom(
		nullptr, reinterpret_cast<PUCHAR>( generated.data()), static_cast<ULONG>( generated.size()),
		BCRYPT_USE_SYSTEM_PREFERRED_RNG) ;	// 乱数生成結果。
	// 乱数生成に失敗した場合は固定値等へ退避せず中止する。
	if( !BCRYPT_SUCCESS( randomStatus)) {
		return nativeErrorFromNt( randomStatus) ;
	}

	const bool generatedAllZero =	// 極端な異常を永続化しない検証結果。
		std::all_of( generated.begin(), generated.end(),
					[]( const std::byte value) { return value == std::byte{} ; }) ;
	// 生成値が全ゼロなら buffer を消去し、無効な key を保存しない。
	if( generatedAllZero) {
		SecureZeroMemory( generated.data(), generated.size()) ;
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	error = writeNewFile( path, generated) ;
	// 同時 process が先に作成した場合は、その既存 key を検証して採用する。
	if( error == nativeErrorFromWin32( ERROR_FILE_EXISTS)) {
		// 同時processが先に生成した場合は、その完全なkeyだけを採用する。
		error = loadBindingSecretFile( path, rootOverride_.empty(), secret) ;
	}
	// 新規保存に成功した場合だけ key の保護と呼出し元への反映を行う。
	else if( error == 0) {
		// 本番保存先の新規 key には固定 DACL を設定する。
		if( rootOverride_.empty()) {
			// Production fileのDACL固定結果。
			error = protectPath( path) ;
		}

		// 保存と必要な保護が成功した場合だけ生成した秘密値を返す。
		if( error == 0) {
			secret = generated ;
		}
	}

	SecureZeroMemory( generated.data(), generated.size()) ;
	// Key の確定に失敗した場合は呼出し元の秘密値もゼロに戻す。
	if( error != 0) {
		secret.fill( std::byte{}) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_observation_store.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void OfficialReleaseObservationStore::discard() const noexcept
{
	try {
		std::wstring root ;	// 利用可能なstate root。
		// 保存 root を安全に解決できなければ file の破棄を試みない。
		if( initializeRoot( rootOverride_, root) != 0) {
			return ;
		}

		discardFile( stateFilePath( root)) ;
	} catch( ...) {
		// noexcept cleanup境界では破棄失敗を成功状態へ変換せず、呼出し側を終了可能にする。
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_observation_store.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
void OfficialReleaseObservationStore::discardDiscoveryCache() const noexcept
{
	try {
		std::wstring root ;	// 利用可能なstate root。
		// 保存rootを安全に解決できなければfileの破棄を試みません。
		if( initializeRoot( rootOverride_, root) != 0) {
			return ;
		}

		discardFile( discoveryCacheFilePath( root)) ;
	} catch( ...) {
		// noexcept cleanup境界では破棄失敗を外へ伝播せず、呼出し側を終了可能にします。
	}
}

} // namespace drivercrate
