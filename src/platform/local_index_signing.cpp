//------------------------------------------------------------------------------
/**
 * @file local_index_signing.cpp
 * @brief CNG保護領域の固定鍵でローカル索引の原byteを署名します。
 * @version 01.03.00
 * @date 2026/10/13
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/13  非exportのcurrent-user鍵とnative PSS署名を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/14  実GZip/v2/取得revision1の全検査後だけ署名を出力。
 * Ver.01.02.00 Shunji Ogawa  2026/10/15  配布専用固定profileと公開pin検証を追加。
 * Ver.01.02.01 Shunji Ogawa  2026/10/16  全取得recordの共通用途検査と配布署名を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/17  現在UTCと発行秒を分けた公開取得履歴検証を追加。
 * </pre>
 *
 * @note 同期開発tool専用です。秘密byteをexportせず、鍵の上書き・削除を行いません。
 * @see docs/adr/0337-local-index-signing-and-build-pins.md
 */
//------------------------------------------------------------------------------
#include "platform/local_index_signing.h"
#include "platform/official_file_verifier.h"
#include "platform/signed_index_manifest_internal.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <memory>
#include <new>
#include <span>
#include <utility>
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <sddl.h>
#include <wincrypt.h>

namespace drivercrate {
namespace {

// 公開用の鍵と共用しない、current-userの固定local受入container名です。
constexpr wchar_t KEY_NAME[] = L"DriverCrate.LocalIndex.Acceptance.20261013.v1" ;
// 明示distribution操作だけへ結合する別の固定current-user containerです。
constexpr wchar_t DISTRIBUTION_KEY_NAME[] = L"DriverCrate.IndexDistribution.20261015.v1" ;
// Public blobとdescriptorだけを対象にした独立容量上限です。
constexpr DWORD	  PUBLIC_BYTES = 411U ;
// Owner/DACL照会の最大byte数。秘密materialには使いません。
constexpr DWORD	  DESCRIPTOR_MAX_BYTES = 16U * 1024U ;

/** @brief 元OS拒否codeを例外境界へ渡す非秘密の内部値です。 */
struct Failure {
	/// 成功へ変換しない元CNG/Win32/HRESULTです。
	NativeError	  error{} ;
	/// 不成立の固定検査段階です。非秘密数値だけを保持します。
	std::uint32_t stage{} ;
	/// 不成立属性の元数値です。秘密byteやSIDを含みません。
	std::uint32_t observed{} ;
} ;

/** @brief CNG handleと作成事実だけを単独所有し、秘密byteを所有しません。 */
class KeyHandles final {
public:
	/** @brief 未取得のprovider/keyを初期化します。 */
	KeyHandles() = default ;
	/** @brief Keyを先に閉じ、providerを回収します。永続鍵は削除しません。 */
	~KeyHandles() noexcept
	{
		// 全終了経路でhandleだけを回収し、永続containerを保持します。
		if( key != 0U) {
			static_cast<void>( NCryptFreeObject( key)) ;
		}

		// Provider取得途中の失敗でもresourceを残しません。
		if( provider != 0U) {
			static_cast<void>( NCryptFreeObject( provider)) ;
		}
	}
	/** @brief Handleのcopyを禁止します。 */
	KeyHandles( const KeyHandles &) = delete ;
	/** @brief 二重解放を防ぐためcopy代入を禁止します。
	 * @return 呼出しは禁止されます。
	 */
	KeyHandles		  &operator=( const KeyHandles &) = delete ;
	/// Windows固定Software KSPのhandleです。
	NCRYPT_PROV_HANDLE provider{} ;
	/// 固定current-user containerのhandleです。秘密byteを取り出しません。
	NCRYPT_KEY_HANDLE  key{} ;
	/// このoperationでfinalizeした事実を後段失敗時も保持します。
	bool			   created{} ;
} ;

/** @brief LocalAllocによる非秘密descriptor/textだけを回収します。 */
struct LocalCloser {
	/** @brief Windowsから取得した非秘密blockを解放します。
	 * @param[in] value LocalAlloc互換の単独owner blockです。
	 */
	void operator()( void *value) const noexcept
	{
		static_cast<void>( LocalFree( value)) ;
	}
} ;

/** @brief OS token handleだけを回収するdeleterです。 */
struct HandleCloser {
	/** @brief 単独ownerの有効handleを閉じます。
	 * @param[in] value CloseHandle互換のOS handleです。
	 */
	void operator()( void *value) const noexcept
	{
		static_cast<void>( CloseHandle( value)) ;
	}
} ;

/** @brief 元CNG失敗を欠損や成功へ読み替えず中断します。
 * @param[in] code 元SECURITY_STATUSです。
 */
void check( const SECURITY_STATUS code)
{
	// CNG失敗の元32bit codeを保持します。
	if( code != ERROR_SUCCESS) {
		throw Failure{static_cast<NativeError>( code)} ;
	}
}

/** @brief OS前提が不成立の場合にfail-closedへ進みます。
 * @param[in] condition 全検査成功の場合だけtrueです。
 * @param[in] stage 非秘密の固定検査段階番号です。
 * @param[in] observed 不成立時だけ保持する元属性数値です。
 */
void require( const bool condition, const std::uint32_t stage = 0U,
			 const std::uint32_t observed = 0U)
{
	// 不適合な既存鍵やdescriptorを変更して受理しません。
	if( !condition) {
		throw Failure{static_cast<NativeError>( ERROR_INVALID_DATA), stage, observed} ;
	}
}

/** @brief CNGのDWORD propertyを固定容量で実照会します。
 * @param[in] handle Providerまたはkeyの借用handleです。
 * @param[in] name SDKの固定property名です。
 * @return 実byte長がDWORDと一致した元property値です。
 */
[[nodiscard]] DWORD property( const NCRYPT_HANDLE handle, const wchar_t *name)
{
	DWORD value{} ;	// SDKが定義するDWORD propertyの受信値です。
	DWORD size{} ;	// 実APIが返す受信byte数です。
	// SDKのDWORD byte境界だけでpointerを変換し、正確な固定容量を渡します。
	check(
		NCryptGetProperty( handle, name, reinterpret_cast<PBYTE>( &value), sizeof( value), &size, 0U)) ;
	require( size == sizeof( value)) ;
	return value ;
}

/** @brief 新規鍵だけへ固定DWORD propertyを設定します。
 * @param[in] key 未finalizeの新規key handleです。
 * @param[in] name SDKの固定property名です。
 * @param[in] value 本契約の固定値です。
 */
void setProperty( const NCRYPT_KEY_HANDLE key, const wchar_t *name, DWORD value)
{
	// SDKのDWORD入力境界でだけbyte pointerへ変換し、既存keyを変更しません。
	check( NCryptSetProperty( key, name, reinterpret_cast<PBYTE>( &value), sizeof( value), 0U)) ;
}

/** @brief 実process userのSIDを非秘密の照合用RAMへcopyします。
 * @return 有効なuser SIDの所有byteです。SIDを出力や永続化しません。
 */
[[nodiscard]] std::vector<std::uint8_t> currentUserSid()
{
	HANDLE raw{} ;	// 実process tokenを借用照会するhandleです。
	// User SIDの照会に必要なread-only権限だけを要求します。
	if( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &raw)) {
		throw Failure{static_cast<NativeError>( GetLastError())} ;
	}

	const std::unique_ptr<void, HandleCloser> token( raw) ;	// 途中失敗でもhandleを回収します。
	DWORD									  size{} ;		// TokenUserの有限な必要byte数です。
	static_cast<void>( GetTokenInformation( token.get(), TokenUser, nullptr, 0U, &size)) ;
	require( size >= sizeof( TOKEN_USER) && size <= DESCRIPTOR_MAX_BYTES) ;
	std::vector<std::uint8_t> bytes( size) ;	// TokenUserの非秘密RAM入力です。
	// 実user照会失敗を既定userへ補完しません。
	if( !GetTokenInformation( token.get(), TokenUser, bytes.data(), size, &size)) {
		throw Failure{static_cast<NativeError>( GetLastError())} ;
	}

	// Windows TokenUser構造境界です。容量を確認した同じblockを同期的に借用します。
	const auto *user = reinterpret_cast<const TOKEN_USER *>( bytes.data()) ;
	require( IsValidSid( user->User.Sid) != FALSE) ;
	const DWORD length = GetLengthSid( user->User.Sid) ;	// Copyする有効SIDの有限byte数です。
	std::vector<std::uint8_t> sid( length) ;				// 外部へ出さない照合用の所有SIDです。
	// TokenUser寿命へ依存しない有効SIDを保持します。
	if( !CopySid( length, sid.data(), user->User.Sid)) {
		throw Failure{static_cast<NativeError>( GetLastError())} ;
	}

	return sid ;
}

/** @brief 新規finalize鍵だけのowner/DACLをcurrent userとSYSTEMへ限定します。
 * @param[in] key このoperationが作成した永続keyです。
 * @param[in] user 有効な現在userの所有SIDです。
 */
void protectNewKey( const NCRYPT_KEY_HANDLE key, std::vector<std::uint8_t> &user)
{
	LPWSTR rawSid{} ;	// 非秘密SIDのSDDL表現です。出力しません。
	// 有効SIDだけをdescriptor生成の内部入力へ変換します。
	if( !ConvertSidToStringSidW( user.data(), &rawSid)) {
		throw Failure{static_cast<NativeError>( GetLastError())} ;
	}

	const std::unique_ptr<void, LocalCloser> sidText( rawSid) ;	// SDK割当てを回収するownerです。
	const std::wstring text = std::wstring{L"O:"} + rawSid + L"D:P(A;;GA;;;SY)(A;;GA;;;" + rawSid +
							  L")" ;		// Ownerと継承しない二ACEだけを生成します。
	PSECURITY_DESCRIPTOR rawDescriptor{} ;	// Windowsが検査した非秘密descriptorです。
	DWORD				 descriptorSize{} ;	// 自己相対descriptorの実byte数です。
	// 元SDDLから実descriptorを作れない場合は鍵を使用しません。
	if( !ConvertStringSecurityDescriptorToSecurityDescriptorW( text.c_str(), SDDL_REVISION_1,
															 &rawDescriptor, &descriptorSize)) {
		throw Failure{static_cast<NativeError>( GetLastError())} ;
	}

	const std::unique_ptr<void, LocalCloser> descriptor( rawDescriptor) ;	// 途中失敗でも回収します。
	// SDKのdescriptor byte境界だけで変換し、新規keyの保護metadataへ限定します。
	check( NCryptSetProperty( key, NCRYPT_SECURITY_DESCR_PROPERTY,
							reinterpret_cast<PBYTE>( descriptor.get()), descriptorSize,
							OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
								NCRYPT_PERSIST_FLAG)) ;
}

/** @brief 同key handleの実owner/DACLを限定profileと完全照合します。
 * @param[in] key 固定永続keyの借用handleです。
 * @param[in] user 現在process userの有効SIDです。
 */
void verifyProtection( const NCRYPT_KEY_HANDLE key, std::vector<std::uint8_t> &user)
{
	DWORD			size{} ;	// 実descriptorの有限必要byte数です。
	constexpr DWORD FLAGS =
		OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION ;	// SACLは照会しません。
	check( NCryptGetProperty( key, NCRYPT_SECURITY_DESCR_PROPERTY, nullptr, 0U, &size, FLAGS)) ;
	require( size > 0U && size <= DESCRIPTOR_MAX_BYTES, 301U) ;
	std::vector<std::uint8_t> bytes( size) ;	// Owner/DACLだけの非秘密RAMです。
	check( NCryptGetProperty( key, NCRYPT_SECURITY_DESCR_PROPERTY, bytes.data(), size, &size, FLAGS)) ;
	require( size <= bytes.size() && IsValidSecurityDescriptor( bytes.data()) != FALSE, 302U) ;
	PSID owner{} ;		// 同descriptorから借用するowner SIDです。
	BOOL defaulted{} ;	// Ownerが明示されていることを確認します。
	require( GetSecurityDescriptorOwner( bytes.data(), &owner, &defaulted) != FALSE &&
				owner != nullptr && EqualSid( owner, user.data()) != FALSE && !defaulted,
			303U) ;
	PACL acl{} ;		// 同descriptorのDACLを同期的に借用します。
	BOOL present{} ;	// NULL DACLを受理しません。
	require( GetSecurityDescriptorDacl( bytes.data(), &present, &acl, &defaulted) != FALSE &&
				present && acl != nullptr && !defaulted && IsValidAcl( acl) != FALSE &&
				acl->AceCount == 2U,
			304U) ;
	SECURITY_DESCRIPTOR_CONTROL control{} ;		// 継承保護を確認する実controlです。
	DWORD						revision{} ;	// DescriptorのSDK revisionです。
	require( GetSecurityDescriptorControl( bytes.data(), &control, &revision) != FALSE &&
				(control & SE_DACL_PROTECTED) != 0U,
			305U) ;
	std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> system{} ;	// Windows固定SYSTEM SID用RAMです。
	DWORD systemSize = static_cast<DWORD>( system.size()) ;		// 実必要容量をSDKへ渡します。
	require( CreateWellKnownSid( WinLocalSystemSid, nullptr, system.data(), &systemSize) != FALSE,
			306U) ;
	unsigned userCount{} ;		// 同じuser ACEの重複を拒否します。
	unsigned systemCount{} ;	// 同じSYSTEM ACEの重複を拒否します。
	// 二つのACEだけを照合し、未知principal/継承/権限追加を拒否します。
	for( DWORD index = 0U; index < 2U; ++index) {
		void *rawAce{} ;	// 同ACL内の有限ACEを借用します。
		require( GetAce( acl, index, &rawAce) != FALSE && rawAce != nullptr) ;
		// Windows ACE構造境界です。SDK検査済みACLから得たpointerだけを扱います。
		const auto *ace = reinterpret_cast<const ACCESS_ALLOWED_ACE *>( rawAce) ;
		require( ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE, 3071U, ace->Header.AceType) ;
		require( ace->Header.AceFlags == 0U, 3072U, ace->Header.AceFlags) ;
		require( ace->Header.AceSize >= sizeof( ACCESS_ALLOWED_ACE), 3073U, ace->Header.AceSize) ;
		require( local_index_signing_detail::fullControlMask( ace->Mask), 3074U, ace->Mask) ;
		// SDKはSidStartを可変SIDの先頭として定義します。同ACE内の実長を確認します。
		auto *sid = const_cast<DWORD *>( &ace->SidStart) ;	// EqualSidの非const境界だけで借用します。
		require( IsValidSid( sid) != FALSE &&
					offsetof( ACCESS_ALLOWED_ACE, SidStart) + GetLengthSid( sid) ==
						ace->Header.AceSize,
				308U) ;
		userCount += EqualSid( sid, user.data()) ? 1U : 0U ;
		systemCount += EqualSid( sid, system.data()) ? 1U : 0U ;
	}

	require( userCount == 1U && systemCount == 1U, 309U) ;
}

/** @brief 固定鍵を開き、明示createだけ欠損時の作成へ進めます。
 * @param[in,out] handles この呼出しで取得する単独ownerです。
 * @param[in] createIfMissing 明示createの場合だけtrueです。
 * @param[in] distribution 明示配布profileだけtrueです。欠損時のprofile切替はありません。
 */
void openKey( KeyHandles &handles, const bool createIfMissing, const bool distribution)
{
	const auto name = distribution ? DISTRIBUTION_KEY_NAME : KEY_NAME ;	// 固定二profileの選択です。
	check( NCryptOpenStorageProvider( &handles.provider, MS_KEY_STORAGE_PROVIDER, 0U)) ;
	require( property( handles.provider, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY) == 1U) ;
	const SECURITY_STATUS opened =
		// 固定user鍵です。
		NCryptOpenKey( handles.provider, &handles.key, name, 0U, NCRYPT_SILENT_FLAG) ;
	// 明確な欠損以外は既存keyを変更せず元codeで中断します。
	if( opened != ERROR_SUCCESS) {
		// Create許可と固定key欠損が同時に成立する場合だけ作成します。
		if( !createIfMissing || opened != NTE_BAD_KEYSET) {
			check( opened) ;
		}

		check( NCryptCreatePersistedKey( handles.provider, &handles.key, NCRYPT_RSA_ALGORITHM, name,
									   0U, 0U)) ;
		setProperty( handles.key, NCRYPT_LENGTH_PROPERTY, 3072U) ;
		setProperty( handles.key, NCRYPT_EXPORT_POLICY_PROPERTY, 0U) ;
		setProperty( handles.key, NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_ALLOW_SIGNING_FLAG) ;
		check( NCryptFinalizeKey( handles.key, 0U)) ;
		handles.created = true ;
		auto user		= currentUserSid() ;	// 新規鍵の限定ACLを生成するRAM値です。
		protectNewKey( handles.key, user) ;
	}

	require( property( handles.key, NCRYPT_LENGTH_PROPERTY) == 3072U &&
				property( handles.key, NCRYPT_EXPORT_POLICY_PROPERTY) == 0U &&
				property( handles.key, NCRYPT_KEY_USAGE_PROPERTY) == NCRYPT_ALLOW_SIGNING_FLAG &&
				property( handles.key, NCRYPT_KEY_TYPE_PROPERTY) == 0U,
			201U) ;
	auto user = currentUserSid() ;	// 既存鍵でもowner/DACLを再照会します。
	verifyProtection( handles.key, user) ;
}

/** @brief 非秘密byteを既存共通SHA-256で完全fingerprintへ結合します。
 * @param[in] bytes 原公開blobまたは原manifestです。
 * @return 小文字64桁の完全SHA-256です。
 */
[[nodiscard]] std::string hashHex( const std::string_view bytes)
{
	std::wstring	  hex ;										// 既存共通暗号APIが返す非秘密digestです。
	const NativeError error = computeBytesSha256( bytes, hex) ;	// Byte順序を変更しません。
	// 元hash障害を有効fingerprintへ補完しません。
	if( error != 0) {
		throw Failure{error} ;
	}

	require( hex.size() == 64U) ;
	std::string value ;	// 共通digestのASCIIだけを明示変換します。
	value.reserve( hex.size()) ;
	// 小文字hex64桁をASCII範囲確認後に欠損なくcopyします。
	for( const auto character : hex) {
		require( (character >= L'0' && character <= L'9') ||
				(character >= L'a' && character <= L'f')) ;
		value.push_back( static_cast<char>( character)) ;
	}

	return value ;
}

/** @brief Public blobだけをexportし、完全shapeとfingerprintを検査します。
 * @param[in] handles 保護検査成功後の固定key ownerです。
 * @param[in] distribution 配布専用keyIdへ結合する場合だけtrueです。
 * @return 非秘密公開receiptです。
 */
[[nodiscard]] LocalIndexPublicKey publicReceipt( const KeyHandles &handles, const bool distribution)
{
	DWORD size{} ;	// 秘密blobは要求せず、公開byte容量だけを確認します。
	check( NCryptExportKey( handles.key, 0U, BCRYPT_RSAPUBLIC_BLOB, nullptr, nullptr, 0U, &size, 0U)) ;
	require( size == PUBLIC_BYTES) ;
	LocalIndexPublicKey result ;	// 全公開検査成功後だけ返す値です。
	result.publicBlob.resize( size) ;
	check( NCryptExportKey( handles.key, 0U, BCRYPT_RSAPUBLIC_BLOB, nullptr, result.publicBlob.data(),
						  size, &size, 0U)) ;
	BCRYPT_RSAKEY_BLOB header{} ;	// SDK構造をcopyし、未整列pointerをdereferenceしません。
	std::memcpy( &header, result.publicBlob.data(), sizeof( header)) ;
	require( size == PUBLIC_BYTES && header.Magic == BCRYPT_RSAPUBLIC_MAGIC &&
			header.BitLength == 3072U && header.cbPublicExp == 3U && header.cbModulus == 384U &&
			header.cbPrime1 == 0U && header.cbPrime2 == 0U && result.publicBlob[24U] == 1U &&
			result.publicBlob[25U] == 0U && result.publicBlob[26U] == 1U &&
			(result.publicBlob[27U] & 0x80U) != 0U && (result.publicBlob.back() & 1U) != 0U) ;
	// 共通hashのbyte境界だけでpublic vectorを文字viewとして借用します。
	result.fingerprint = hashHex(
		{reinterpret_cast<const char *>( result.publicBlob.data()), result.publicBlob.size()}) ;
	result.keyId = (distribution ? "distribution-index-" : "local-index-") +
				   result.fingerprint.substr( 0U, 32U) ;
	result.created			  = handles.created ;
	result.protectionVerified = true ;
	return result ;
}

/** @brief 非秘密byteを改行なしの標準base64へ表現します。
 * @param[in] bytes 原manifestまたは384byte署名です。
 * @return 原byte順序を保持するbase64です。
 */
[[nodiscard]] std::string base64( const std::span<const std::uint8_t> bytes)
{
	DWORD			size{} ;											// 終端を含む有限出力容量です。
	constexpr DWORD FLAGS = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF ;	// 文法を固定します。
	require( bytes.size() <= INDEX_MANIFEST_MAX_BYTES) ;
	// 標準encoderの容量取得失敗を出力成功へ読み替えません。
	if( !CryptBinaryToStringA( bytes.data(), static_cast<DWORD>( bytes.size()), FLAGS, nullptr,
							 &size)) {
		throw Failure{static_cast<NativeError>( GetLastError())} ;
	}

	std::string result( size, '\0') ;	// 終端も含めたSDK出力bufferです。
	// 同原byteの実変換が終わるまでenvelopeを生成しません。
	if( !CryptBinaryToStringA( bytes.data(), static_cast<DWORD>( bytes.size()), FLAGS, result.data(),
							 &size)) {
		throw Failure{static_cast<NativeError>( GetLastError())} ;
	}

	result.resize( std::strlen( result.c_str())) ;
	return result ;
}

} // namespace

/** @see local_index_signing.h */
bool local_index_signing_detail::fullControlMask( const std::uint32_t mask) noexcept
{
	constexpr std::uint32_t KNOWN = GENERIC_ALL | GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE |
									FILE_ALL_ACCESS ;	// 全権限へ追加しない既知bitだけです。
	return mask == FILE_ALL_ACCESS || ((mask & GENERIC_ALL) != 0U && (mask & ~KNOWN) == 0U) ;
}

/** @brief 二つの固定profileへ同じ保護検査を適用します。
 * @param[in] createIfMissing 明示作成の場合だけtrueです。
 * @param[in] distribution 配布用固定containerだけを扱う場合trueです。
 * @return 同profileの公開receiptと元拒否codeです。
 */
static LocalIndexSigningResult inspectProfile( const bool createIfMissing,
											  const bool distribution) noexcept
{
	LocalIndexSigningResult result ;	// 途中作成と失敗codeを独立して保持します。
	KeyHandles				handles ;	// 秘密byteではなくOS handleだけを所有します。
	try {
		openKey( handles, createIfMissing, distribution) ;
		result.publicKey = publicReceipt( handles, distribution) ;
	} catch( const Failure &failure) {
		result.error		 = failure.error ;
		result.checkStage	 = failure.stage ;
		result.observedValue = failure.observed ;
	} catch( const std::bad_alloc &) {
		result.error = static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		result.error = static_cast<NativeError>( E_UNEXPECTED) ;
	}

	result.created = handles.created ;
	return result ;
}

/** @brief 固定profileで原manifestを署名し既存codecへ戻します。
 * @param[in] manifestBytes 原manifestです。
 * @param[in] expectedFingerprint 明示した公開pinです。
 * @param[in] nowUtc 現在UTCです。
 * @param[in] distribution 配布専用containerだけの場合trueです。
 * @return 全原byte検査成功時だけenvelopeです。
 */
static LocalIndexSigningResult signProfile( const std::string_view manifestBytes,
										   const std::string_view expectedFingerprint,
										   const std::optional<std::chrono::sys_seconds> nowUtc,
										   const bool distribution) noexcept
{
	LocalIndexSigningResult result ;	// 全検査成功時だけenvelopeを移します。
	KeyHandles				handles ;	// Inspect/sign操作は永続鍵を作りません。
	try {
		require( !manifestBytes.empty() && manifestBytes.size() <= INDEX_MANIFEST_MAX_BYTES &&
				expectedFingerprint.size() == 64U && nowUtc.has_value()) ;
		openKey( handles, false, distribution) ;
		auto key =
			// 今開いた同じkeyのpublic fingerprintです。
			publicReceipt( handles, distribution) ;
		require( key.fingerprint == expectedFingerprint) ;
		const auto			hex = hashHex( manifestBytes) ;	// 正規化しない原byteの共通SHA-256です。
		IndexManifestSha256 digest{} ;						// CNG signing境界へ渡す固定32byteです。
		constexpr std::string_view HEX =
			"0123456789abcdef" ;	// 共通hashの小文字字句だけを解釈します。
		// 全32byteを二桁ずつdecodeし、原hashを別値へ補完しません。
		for( std::size_t index = 0U; index < digest.size(); ++index) {
			const auto high = HEX.find( hex[index * 2U]) ;		// 高位nibbleの位置です。
			const auto low	= HEX.find( hex[index * 2U + 1U]) ;	// 低位nibbleの位置です。
			require( high < 16U && low < 16U) ;
			digest[index] = static_cast<std::uint8_t>( high * 16U + low) ;
		}

		BCRYPT_PSS_PADDING_INFO		   padding{BCRYPT_SHA256_ALGORITHM,
										   32U} ;		// RSA-PSS/SHA256/salt32を固定します。
		std::array<std::uint8_t, 384U> signature{} ;	// 非秘密の固定RSA3072署名byteです。
		DWORD						   size{} ;			// 実署名のbyte数です。
		check( NCryptSignHash( handles.key, &padding, digest.data(),
							 static_cast<DWORD>( digest.size()), signature.data(),
							 static_cast<DWORD>( signature.size()), &size,
							 NCRYPT_PAD_PSS_FLAG | NCRYPT_SILENT_FLAG)) ;
		require( size == signature.size()) ;
		// 原文字byteをencoderの公開byte境界へ借用し、UTF-8の再整形を行いません。
		const auto raw = std::span<const std::uint8_t>{
			reinterpret_cast<const std::uint8_t *>( manifestBytes.data()), manifestBytes.size()} ;
		std::string envelope = "{\"schema\":\"driver-index-envelope-v1\",\"keyId\":\"" + key.keyId +
							   "\",\"manifestBytesBase64\":\"" + base64( raw) +
							   "\",\"signatureBase64\":\"" + base64( signature) +
							   "\"}" ;	// 原byteと署名だけを外側schemaへ結合します。
		const std::array<signed_index_detail::TrustKey, 1U> trust{
			{{key.keyId, key.publicBlob}}} ;	// 出力検査専用です。製品へ登録しません。
		const auto verified = signed_index_detail::authenticateWithTrustKeys(
			envelope, nowUtc, std::nullopt, trust) ;	// 既存codecの実検査です。
		result.manifestStatus = verified.status ;
		// 署名API成功だけで意味不正なmanifestを出力しません。
		if( !verified.manifest) {
			throw Failure{verified.error != 0 ? verified.error
											  : static_cast<NativeError>( ERROR_INVALID_DATA)} ;
		}

		result.publicKey = std::move( key) ;
		result.envelope	 = std::move( envelope) ;
	} catch( const Failure &failure) {
		result.error		 = failure.error ;
		result.checkStage	 = failure.stage ;
		result.observedValue = failure.observed ;
	} catch( const std::bad_alloc &) {
		result.error = static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		result.error = static_cast<NativeError>( E_UNEXPECTED) ;
	}

	return result ;
}

/** @see local_index_signing.h */
LocalIndexSigningResult inspectLocalIndexSigningKey( const bool createIfMissing) noexcept
{
	return inspectProfile( createIfMissing, false) ;
}

/** @see local_index_signing.h */
LocalIndexSigningResult inspectDistributionIndexSigningKey( const bool createIfMissing) noexcept
{
	return inspectProfile( createIfMissing, true) ;
}

/** @see local_index_signing.h */
LocalIndexSigningResult signLocalIndexManifest(
	const std::string_view manifestBytes, const std::string_view expectedFingerprint,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	return signProfile( manifestBytes, expectedFingerprint, nowUtc, false) ;
}

/** @brief 全取得recordへ既存の内容/公開INF/revision1申告条件を適用します。
 * @param[in] records 原byteとqualityを検査したschema receiptです。
 * @param[in] nowUtc 確認済み現在UTCです。
 * @throws Failure 一つでも取得用途条件が不成立の場合。
 * @note 実CAT/公式性/端末適用性を再検査せず、既存申告の用途だけを検査します。
 */
static void requireAcquisitionPurpose( const IndexRecordsSchemaReceipt &records,
									  const std::chrono::sys_seconds   nowUtc)
{
	require( !records.records().empty()) ;
	// 一つのUNKNOWNや異用途も取得索引へ混在させません。
	for( const auto &record : records.records()) {
		require( record.recordSchemaVersion == 2U && record.acquisitionDescriptor &&
				record.acquisitionDescriptor->state == IndexDescriptorState::KNOWN &&
				record.inspectionStage == IndexInspectionStage::CONTENT_INSPECTED &&
				record.targetOs.value && record.architecture.value == IndexArchitecture::X64 &&
				record.driverKind.value == IndexDriverKind::NORMAL_DRIVER &&
				record.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE &&
				record.publishedIdentityEvidence.state == IndexEvidenceState::PUBLISHED &&
				record.publishedIdentityEvidence.kind == IndexIdentityEvidenceKind::INF &&
				record.packageEvidence.size.value &&
				(record.packageEvidence.publishedHash.sha256 ||
				 record.packageEvidence.calculatedHash.sha256)) ;
		const auto &descriptor = *record.acquisitionDescriptor ;	// 同原recordの申告だけです。
		require( descriptor.attestation && descriptor.attestation->policyRevision == 1U &&
				descriptor.attestation->checkedAtUtc <= nowUtc &&
				nowUtc < descriptor.attestation->validUntilUtc && !descriptor.route.empty() &&
				descriptor.publisher.value && descriptor.terms.state != IndexTermsState::UNKNOWN &&
				descriptor.prerequisites.state == IndexDescriptorState::KNOWN &&
				(descriptor.format == IndexPayloadFormat::ZIP ||
				 descriptor.format == IndexPayloadFormat::CABINET)) ;
		const auto source = std::ranges::find_if( records.sources(), [&record]( const auto &value) {
			// 同期借用中だけ原sourceを照合します。
			return value.sourceId == record.sourceId ;
		}) ; // 他sourceの公式申告へ付替えません。
		require( source != records.sources().end() &&
				source->officialEvidence.state == IndexEvidenceState::PUBLISHED) ;
	}
}

/** @brief 公開byteの共通codec後、明示した配布用途だけを検査します。
 * @param[in] envelopeBytes 原envelopeです。
 * @param[in] gzipBytes 原GZipです。
 * @param[in] publicBlob 明示公開blobです。
 * @param[in] expectedFingerprint 完全な公開pinです。
 * @param[in] nowUtc 確認済みUTCです。
 * @param[in] requirePublicationTime 明示historyだけの署名発行秒一致条件です。
 * @param[in] acquisition trueは取得用途、falseは従来metadata-only用途です。
 * @param[in] publicationCeilingUtc 新取得historyの確認済み現在UTCです。旧metadataは実OS時計を維持します。
 * @return 全成功時だけ原envelope、拒否時は空と元診断です。
 */
static LocalIndexSigningResult verifyDistributionProfile(
	const std::string_view envelopeBytes, const std::span<const std::byte> gzipBytes,
	const std::span<const std::uint8_t> publicBlob, const std::string_view expectedFingerprint,
	const std::optional<std::chrono::sys_seconds> nowUtc, const bool requirePublicationTime,
	const bool									  acquisition,
	const std::optional<std::chrono::sys_seconds> publicationCeilingUtc = std::nullopt) noexcept
{
	LocalIndexSigningResult result ;	// 全検査が終わるまで出力を空に保ちます。
	try {
		require( publicBlob.size() == PUBLIC_BYTES && expectedFingerprint.size() == 64U &&
				nowUtc.has_value()) ;
		const auto fingerprint = hashHex( {reinterpret_cast<const char *>( publicBlob.data()),
										  // 公開byteだけのviewです。
										  publicBlob.size()}) ;
		require( fingerprint == expectedFingerprint) ;
		const auto keyId =
			"distribution-index-" + fingerprint.substr( 0U, 32U) ;	// Remote IDを採用しません。
		const std::array<signed_index_detail::TrustKey, 1U> trust{
			{{keyId, publicBlob}}} ;	// Local pinだけです。
		const auto manifest = signed_index_detail::authenticateWithTrustKeys(
			envelopeBytes, nowUtc, std::nullopt, trust) ;	// 既存署名/期限検査です。
		result.manifestStatus = manifest.status ;
		// 署名の不成立後はGZipを展開しません。
		if( !manifest.manifest) {
			throw Failure{manifest.error != 0 ? manifest.error
											  : static_cast<NativeError>( ERROR_INVALID_DATA)} ;
		}

		const auto asset   = authenticateIndexAssetBytes( *manifest.manifest, gzipBytes,
														 nowUtc) ;	// 既存hash/size/GZip検査です。
		result.assetStatus = asset.status ;
		// Asset拒否を署名だけで補いません。
		if( !asset.receipt) {
			throw Failure{asset.error != 0 ? asset.error
										   : static_cast<NativeError>( ERROR_INVALID_DATA)} ;
		}

		const auto records =
			// 既存厳密v2 schemaです。
			readSignedIndexRecords( *asset.receipt, nowUtc) ;
		result.recordsStatus = records.status ;
		// Metadata schemaの失敗も出力を空のまま残します。
		if( !records.receipt) {
			throw Failure{records.error != 0 ? records.error
											 : static_cast<NativeError>( ERROR_INVALID_DATA)} ;
		}

		// 履歴は署名発行秒だけを検査時点とし、未来や任意の古い時刻を受理しません。
		if( requirePublicationTime) {
			// 新APIの現在UTC、または従来metadata用の実OS時計を上限にします。
			const auto ceiling = publicationCeilingUtc.value_or(
				std::chrono::floor<std::chrono::seconds>( std::chrono::system_clock::now())) ;
			require( manifest.manifest->data().publishedAtUtc == *nowUtc && *nowUtc <= ceiling) ;
		}

		// 新用途だけ正の有限世代と全取得recordを要求し、旧metadata条件を緩めません。
		if( acquisition) {
			require( manifest.manifest->data().generation <= 9007199254740991ULL &&
					manifest.manifest->data().assetGeneration <= 9007199254740991ULL) ;
			requireAcquisitionPurpose( *records.receipt, *nowUtc) ;
		} else {
			require( records.receipt->records().size() == 1U &&
					records.receipt->sources().size() == 1U &&
					manifest.manifest->data().generation >= 4U &&
					manifest.manifest->data().assetGeneration ==
						manifest.manifest->data().generation) ;
			const auto &record = records.receipt->records().front() ;	// 有限一対象だけです。
			require( record.recordSchemaVersion == 2U &&
					record.inspectionStage == IndexInspectionStage::METADATA_ONLY &&
					record.acquisitionDescriptor &&
					record.acquisitionDescriptor->state == IndexDescriptorState::UNKNOWN &&
					record.publishedIdentityEvidence.state == IndexEvidenceState::UNKNOWN) ;
		}

		LocalIndexPublicKey key ;	// 公開検証では保護鍵の存在を主張しません。
		key.publicBlob.assign( publicBlob.begin(), publicBlob.end()) ;
		key.fingerprint	 = fingerprint ;
		key.keyId		 = keyId ;
		result.publicKey = std::move( key) ;
		result.envelope	 = envelopeBytes ;
	} catch( const Failure &failure) {
		result.error = failure.error ;
	} catch( const std::bad_alloc &) {
		result.error = static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		result.error = static_cast<NativeError>( E_UNEXPECTED) ;
	}

	return result ;
}

/** @see local_index_signing.h */
LocalIndexSigningResult verifyDistributionIndex(
	const std::string_view envelopeBytes, const std::span<const std::byte> gzipBytes,
	const std::span<const std::uint8_t> publicBlob, const std::string_view expectedFingerprint,
	const std::optional<std::chrono::sys_seconds> nowUtc,
	const bool									  requirePublicationTime) noexcept
{
	return verifyDistributionProfile( envelopeBytes, gzipBytes, publicBlob, expectedFingerprint,
									 nowUtc, requirePublicationTime, false) ;
}

/** @see local_index_signing.h */
LocalIndexSigningResult verifyDistributionAcquisitionIndex(
	const std::string_view envelopeBytes, const std::span<const std::byte> gzipBytes,
	const std::span<const std::uint8_t> publicBlob, const std::string_view expectedFingerprint,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	return verifyDistributionProfile( envelopeBytes, gzipBytes, publicBlob, expectedFingerprint,
									 nowUtc, false, true) ;
}

/** @see local_index_signing.h */
LocalIndexSigningResult verifyDistributionAcquisitionIndexHistory(
	const std::string_view envelopeBytes, const std::span<const std::byte> gzipBytes,
	const std::span<const std::uint8_t> publicBlob, const std::string_view expectedFingerprint,
	const std::optional<std::chrono::sys_seconds> publishedAtUtc,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	// 時刻欠損や未来の発行申告では公開codecにも進めず、別modeへ補完しません。
	if( !publishedAtUtc || !nowUtc || publishedAtUtc->time_since_epoch().count() <= 0 ||
	   *publishedAtUtc > *nowUtc) {
		LocalIndexSigningResult result ;	// 成功receiptと原envelopeを返さない入力拒否です。
		result.error = static_cast<NativeError>( ERROR_INVALID_DATA) ;
		return result ;
	}

	return verifyDistributionProfile( envelopeBytes, gzipBytes, publicBlob, expectedFingerprint,
									 publishedAtUtc, true, true, nowUtc) ;
}

/** @see local_index_signing.h */
LocalIndexSigningResult signDistributionAcquisitionIndex(
	const std::string_view manifestBytes, const std::span<const std::byte> gzipBytes,
	const std::string_view						  expectedFingerprint,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	auto signedResult =
		// 固定配布鍵だけです。
		signProfile( manifestBytes, expectedFingerprint, nowUtc, true) ;
	// 既存鍵/保護/署名の拒否後に別profileを試しません。
	if( signedResult.error != 0 || !signedResult.publicKey) {
		return signedResult ;
	}

	auto verified = verifyDistributionAcquisitionIndex(
		signedResult.envelope, gzipBytes, signedResult.publicKey->publicBlob, expectedFingerprint,
		nowUtc) ;	// 署名申告の用途検査です。
	// 実保護検査の事実は署名と全用途検査が両方成功した場合だけ返します。
	if( verified.error == 0) {
		verified.publicKey = std::move( signedResult.publicKey) ;
	}

	return verified ;
}

/** @see local_index_signing.h */
LocalIndexSigningResult signDistributionIndex(
	const std::string_view manifestBytes, const std::span<const std::byte> gzipBytes,
	const std::string_view						  expectedFingerprint,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	auto signedResult =
		// Acceptanceを開きません。
		signProfile( manifestBytes, expectedFingerprint, nowUtc, true) ;
	// 元署名の失敗は再検証で上書きしません。
	if( signedResult.error != 0 || !signedResult.publicKey) {
		return signedResult ;
	}

	auto verified = verifyDistributionIndex( signedResult.envelope, gzipBytes,
											signedResult.publicKey->publicBlob, expectedFingerprint,
											nowUtc) ;	// 同鍵の公開pinで全byteを検査します。
	// 実保護確認は同署名operationが成功した時だけ保持します。
	if( verified.error == 0) {
		verified.publicKey = std::move( signedResult.publicKey) ;
	}

	return verified ;
}

/** @see local_index_signing.h */
LocalIndexSigningResult signLocalAcquisitionIndex(
	const std::string_view manifestBytes, const std::span<const std::byte> gzipBytes,
	const std::string_view						  expectedFingerprint,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	auto result = signLocalIndexManifest( manifestBytes, expectedFingerprint,
										 nowUtc) ;	// 元署名はRAMだけに保持します。
	// 原署名または同公開pin確認の拒否を、用途別成功へ補完しません。
	if( result.error != 0 || !result.publicKey || result.envelope.empty()) {
		return result ;
	}

	std::string envelope = std::move( result.envelope) ;	// 全用途検査まで外側出力を空に保ちます。
	result.envelope.clear() ;
	try {
		const std::array<signed_index_detail::TrustKey, 1U> trust{
			{{result.publicKey->keyId,
			  result.publicKey->publicBlob}}} ;	// 今開いた同固定鍵だけです。
		const auto manifest = signed_index_detail::authenticateWithTrustKeys(
			envelope, nowUtc, std::nullopt, trust) ;	// 既存原byte検証を再使用します。
		require( manifest.manifest.has_value()) ;
		const auto asset =
			// 同原GZipです。
			authenticateIndexAssetBytes( *manifest.manifest, gzipBytes, nowUtc) ;
		result.assetStatus = asset.status ;
		// Hash/size/単一GZip拒否の原HRESULTを保持します。
		if( !asset.receipt) {
			throw Failure{asset.error != 0 ? asset.error
										   : static_cast<NativeError>( ERROR_INVALID_DATA)} ;
		}

		const auto records =
			// strict field/原record/qualityです。
			readSignedIndexRecords( *asset.receipt, nowUtc) ;
		result.recordsStatus = records.status ;
		// Schemaの不成立を署名API成功で補いません。
		if( !records.receipt) {
			throw Failure{records.error != 0 ? records.error
											 : static_cast<NativeError>( ERROR_INVALID_DATA)} ;
		}

		requireAcquisitionPurpose( *records.receipt, *nowUtc) ;

		result.envelope = std::move( envelope) ;
	} catch( const Failure &failure) {
		result.error		 = failure.error ;
		result.checkStage	 = failure.stage ;
		result.observedValue = failure.observed ;
	} catch( const std::bad_alloc &) {
		result.error = static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		result.error = static_cast<NativeError>( E_UNEXPECTED) ;
	}

	return result ;
}

} // namespace drivercrate
