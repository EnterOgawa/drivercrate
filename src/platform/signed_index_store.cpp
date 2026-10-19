//------------------------------------------------------------------------------
/**
 * @file signed_index_store.cpp
 * @brief 署名索引の原入力と最大世代を一つのDPAPI headへ原子保存します。
 * @version 01.02.00
 * @date 2026/10/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  排他再読取りと実保護head切替・再認証を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/11  通常workerの同scan署名索引読取り境界を接続。
 * Ver.01.01.01 Shunji Ogawa  2026/10/16  固定製品trust選択の現行説明を訂正。
 * Ver.01.02.00 Shunji Ogawa  2026/10/19  用途別rootと旧head不変の認証renameを追加。
 * </pre>
 *
 * @note 製品rootは固定です。実lockと保持directory handleを用い、mutexを保持しません。
 *       履歴検証はhighwater回収だけに使い、現在期限を独立確認します。
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#include "platform/signed_index_store.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <limits>
#include <new>
#include <type_traits>
#include <utility>
#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <dpapi.h>
#include <sddl.h>
#include <shlobj.h>

#include "platform/official_file_verifier.h"
#include "platform/signed_index_store_internal.h"
#include "platform/index_distribution_trust.h"
#include "platform/index_legacy_migration_trust.h"
#include "local_index_acceptance.h"

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 有限wireと所有資源。
//------------------------------------------------------------------------------

// Plain wireの厳格識別子。Native structのpaddingを保存しません。
constexpr std::string_view MAGIC = "DCIDXSTR01" ;
// Lockの固定本文。空の作成途中fileを既存正常stateへ昇格させません。
constexpr std::string_view LOCK_BYTES = "driver-index-lock-v1" ;
// 原入力と固定field・plain digestを含む有限上限。
constexpr std::size_t	   MAX_PLAIN =
	static_cast<std::size_t>( INDEX_ASSET_MAX_BYTES) + INDEX_ENVELOPE_MAX_BYTES + 256U ;
// DPAPI overheadを含む実disk byte上限。
constexpr std::size_t		MAX_PROTECTED = 33U * 1024U * 1024U ;
// 旧共用名は明示移行以外から開かず、新storeの迂回初期化を拒否します。
constexpr std::wstring_view LEGACY_NAME = L"SignedIndex-v1" ;

/** @brief 用途と完全公開pinから固定保存名を構成します。
 * @param[in] local 検証用domainの場合trueです。
 * @param[in] fingerprint 検証用だけで使用する固定ASCII完全SHA-256です。
 * @return 同じ親の単一leaf名です。
 */
[[nodiscard]] std::wstring	domainName( const bool local, const std::string_view fingerprint)
{
	return local ? L"SignedIndex-local-" + std::wstring{fingerprint.begin(), fingerprint.end()} +
					   L"-v1"
				 : L"SignedIndex-distribution-v1" ;
}

/** @brief Win32 file／token handleを単独解放します。 */
struct HandleCloser {
	/** @brief 有効なhandleを閉じます。
	 * @param[in] value Unique ownerが持つ非null handle。
	 */
	void operator()( void *value) const noexcept
	{
		CloseHandle( value) ;
	}
} ;
/** @brief OSがLocalAllocしたdescriptor／DPAPI byteを解放します。 */
struct LocalCloser {
	/** @brief OS allocationを返します。
	 * @param[in] value LocalFree可能な非null値。
	 */
	void operator()( void *value) const noexcept
	{
		LocalFree( value) ;
	}
} ;
/** @brief KnownFolder APIが割り当てたpathを解放します。 */
struct TaskMemoryCloser {
	/** @brief COM task allocatorへ返します。
	 * @param[in] value CoTaskMemFree可能な非null値。
	 */
	void operator()( wchar_t *value) const noexcept
	{
		CoTaskMemFree( value) ;
	}
} ;
/** @brief 無効handleをnullへ正規化して所有する型です。 */
using Handle = std::unique_ptr<void, HandleCloser> ;
/** @brief LocalAlloc領域の単独所有型です。 */
using LocalMemory = std::unique_ptr<void, LocalCloser> ;

/** @brief 成功を注入せず元診断と拒否段階を伝える内部例外です。 */
struct Failure {
	/// 公開の拒否区分。
	IndexStoreStatus						 status ;
	/// 元Win32／HRESULT。
	NativeError								 error{} ;
	/// 前段manifest拒否を保持します。
	std::optional<SignedIndexManifestStatus> manifestStatus ;
	/// 前段asset拒否を保持します。
	std::optional<IndexAssetBytesStatus>	 assetStatus ;
	/// 前段record拒否を保持します。
	std::optional<IndexRecordsStatus>		 recordsStatus ;
} ;

/** @brief Plain wireの原入力と保護最大世代を所有します。DTOはauthorityではありません。 */
struct Wire {
	/// Genesisだけ0、通常は署名manifestと完全一致する最大世代。
	std::uint64_t		   generation{} ;
	/// 履歴検証だけへ使う署名発行Unix秒。
	std::uint64_t		   publishedSeconds{} ;
	/// 署名manifest原byte hash。
	IndexManifestSha256	   manifestHash{} ;
	/// 展開原index hash。圧縮hashと区別します。
	IndexManifestSha256	   indexHash{} ;
	/// 認証する原外側byte。
	std::string			   envelope ;
	/// 認証する原gzip byte。
	std::vector<std::byte> gzip ;
} ;

/** @brief 実headからの原入力と完全なschema再認証結果を保持します。 */
struct Verified {
	/// DPAPI・wire検査を通った原入力。
	Wire									 wire ;
	/// Genesis以外は全前段を通ったreceipt。履歴検証だけでservableとは扱いません。
	std::optional<IndexRecordsSchemaReceipt> receipt ;
} ;

/** @brief Storeがcopyして所有する内部固定public trustです。 */
struct OwnedTrust {
	/// Binary固定またはunit RAM由来ID。
	std::string				  keyId ;
	/// Private成分を持たないpublic blob。
	std::vector<std::uint8_t> blob ;
} ;

/** @brief 不成立条件を元診断付きの拒否へ変換します。
 * @param[in] condition 必須条件。
 * @param[in] status 拒否区分。
 * @param[in] error 元数値診断。純粋な入力拒否は0です。
 */
void require( const bool condition, const IndexStoreStatus status, const NativeError error = 0)
{
	// 一つでも境界が欠けた場合は後続のI/Oとsnapshot発行を行いません。
	if( !condition) {
		throw Failure{status, error} ;
	}
}

/** @brief API失敗を最初のGetLastErrorへ結合します。
 * @param[in] succeeded Win32 APIの結果。
 * @param[in] status 拒否区分。
 */
void requireApi( const BOOL succeeded, const IndexStoreStatus status)
{
	// Errorを後続APIで失う前に拒否へ変換します。
	if( !succeeded) {
		throw Failure{status, static_cast<NativeError>( GetLastError())} ;
	}
}

/** @brief INVALID_HANDLE_VALUEを空ownerへ変換します。
 * @param[in] raw 所有権を引き取るAPI結果。
 * @return Scope終了時に閉じるowner。
 */
[[nodiscard]] Handle own( const HANDLE raw)
{
	return Handle{raw == INVALID_HANDLE_VALUE ? nullptr : raw} ;
}

/** @brief 旧rootの存在や照会不能を新domainの初回へ補完しません。
 * @param[in] path 固定旧rootです。空は隔離test/明示移行です。
 */
void requireLegacyAbsent( const std::filesystem::path &path)
{
	// 隔離fixtureと移行専用stateは通常入口の旧root guardを使いません。
	if( path.empty()) {
		return ;
	}

	const DWORD attributes =
		// 存在だけを照会しreparseを辿りません。
		GetFileAttributesW( path.c_str()) ;
	// 旧stateがある間はdomainを勝手に初回へ戻しません。
	if( attributes != INVALID_FILE_ATTRIBUTES) {
		throw Failure{IndexStoreStatus::STATE_REJECTED, ERROR_REVISION_MISMATCH} ;
	}

	const DWORD code = GetLastError() ;	// 最初の存在照会errorです。
	require( code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND,
			IndexStoreStatus::PROTECTION_FAILURE, static_cast<NativeError>( code)) ;
}

/** @brief 固定pathをextended DOS形式でAPIへ渡します。
 * @param[in] path 正規化済みのlocal絶対path。
 * @return 有限のAPI用表現。
 */
[[nodiscard]] std::wstring apiPath( const std::filesystem::path &path)
{
	return L"\\\\?\\" + path.native() ;
}

/** @brief 同じhandleのpath・属性・link数を検査します。
 * @param[in] handle I/Oにも使う実handle。
 * @param[in] expected 固定された期待path。
 * @param[in] directory Directoryの場合true。
 */
void checkObject( HANDLE handle, const std::filesystem::path &expected, const bool directory)
{
	BY_HANDLE_FILE_INFORMATION info{} ;	// 同じ実fileの属性とlink数です。
	requireApi( GetFileInformationByHandle( handle, &info), IndexStoreStatus::PROTECTION_FAILURE) ;
	require( GetFileType( handle) == FILE_TYPE_DISK &&
				(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0U &&
				((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) == directory &&
				(directory || info.nNumberOfLinks == 1U),
			IndexStoreStatus::PROTECTION_FAILURE, ERROR_ACCESS_DENIED) ;
	std::wstring actual( 32768U, L'\0') ;	// 切詰めを一致と扱わない有限bufferです。
	const DWORD	 count = GetFinalPathNameByHandleW(
		 handle, actual.data(), static_cast<DWORD>( actual.size()),
		 FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;	// 同じhandleの最終DOS pathです。
	require( count != 0U && count < actual.size(), IndexStoreStatus::PROTECTION_FAILURE,
			count == 0U ? static_cast<NativeError>( GetLastError()) : ERROR_FILENAME_EXCED_RANGE) ;
	actual.resize( count) ;
	std::wstring wanted = apiPath( expected) ;	// Drive rootの末尾だけ表現差を除きます。
	// APIが返すroot末尾の区切りを有限文字列から除きます。
	while( !actual.empty() && actual.back() == L'\\') {
		actual.pop_back() ;
	}

	// 比較側も同じroot末尾規則へ揃えます。
	while( !wanted.empty() && wanted.back() == L'\\') {
		wanted.pop_back() ;
	}

	require( CompareStringOrdinal( actual.c_str(), -1, wanted.c_str(), -1, TRUE) == CSTR_EQUAL,
			IndexStoreStatus::PROTECTION_FAILURE, ERROR_ACCESS_DENIED) ;
}

/** @brief 製品二principalと隔離三principalを分けて保護DACLを検査します。
 * @param[in] descriptor OSが返した有効descriptor。
 * @param[in] userSid Process userの有効SID。
 * @param[in] directory 継承用OICIを要求する場合true。
 * @param[in] isolated 隔離profileだけでuser owner／許可を認める区分。
 * @return Profileのownerと明示full-control ACEが完全一致する場合true。
 */
[[nodiscard]] bool allowedDescriptor( PSECURITY_DESCRIPTOR descriptor, PSID userSid,
									 const bool directory, const bool isolated)
{
	PSID						owner{} ;		// Descriptorに属する借用ownerです。
	BOOL						defaulted{} ;	// OSが返すdefaulted区分です。
	SECURITY_DESCRIPTOR_CONTROL control{} ;		// 継承停止を含む実制御bitです。
	DWORD						revision{} ;	// 実descriptor版です。
	// 欠損と不正ownerを保護済みへ昇格させません。
	if( descriptor == nullptr || !IsValidSecurityDescriptor( descriptor) ||
	   !GetSecurityDescriptorOwner( descriptor, &owner, &defaulted) || owner == nullptr ||
	   !IsValidSid( owner) ||
	   !((isolated && EqualSid( owner, userSid)) || IsWellKnownSid( owner, WinLocalSystemSid) ||
		 IsWellKnownSid( owner, WinBuiltinAdministratorsSid)) ||
	   !GetSecurityDescriptorControl( descriptor, &control, &revision) ||
	   (control & SE_DACL_PROTECTED) == 0U) {
		return false ;
	}

	PACL acl{} ;		// Descriptorに属する借用ACLです。
	BOOL present{} ;	// Null DACLを拒否する存在区分です。
	// 許可principal数を増やすACL表現を認めません。
	if( !GetSecurityDescriptorDacl( descriptor, &present, &acl, &defaulted) || !present ||
	   acl == nullptr || !IsValidAcl( acl) || acl->AceCount != (isolated ? 3U : 2U)) {
		return false ;
	}

	bool user{} ;	// Userへの明示許可を確認した区分です。
	bool system{} ;	// SYSTEMへの明示許可を確認した区分です。
	bool admins{} ;	// Administratorsへの明示許可を確認した区分です。
	// 有限二／三ACEを一つずつ確認し、未知principal・mask・flagを拒否します。
	for( DWORD index = 0U; index < acl->AceCount; ++index) {
		void *raw{} ;	// GetAceの借用結果です。
		// 壊れたACLから許可を推測しません。
		if( !GetAce( acl, index, &raw)) {
			return false ;
		}

		const auto *ace =
			// 検査済みACLのWin32境界です。
			static_cast<const ACCESS_ALLOWED_ACE *>( raw) ;
		// 条件付き権限や余分なflagを許可しません。
		if( ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
		   ace->Header.AceSize < sizeof( ACCESS_ALLOWED_ACE) || ace->Mask != FILE_ALL_ACCESS ||
		   ace->Header.AceFlags != (directory ? OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE : 0U)) {
			return false ;
		}

		PSID sid = const_cast<DWORD *>( &ace->SidStart) ;	// 可変長ACEのSIDをOS APIへ借用します。
		// SIDの検査不能を一致と扱いません。
		if( !IsValidSid( sid)) {
			return false ;
		}

		// 可変SIDがACEの実byte範囲へ完全に収まることも要求します。
		if( GetLengthSid( sid) > ace->Header.AceSize - offsetof( ACCESS_ALLOWED_ACE, SidStart)) {
			return false ;
		}

		const bool isUser = isolated && EqualSid( sid, userSid) != FALSE ;	// 製品はuserを許しません。
		const bool isSystem =
			// 固定SYSTEM SIDです。
			IsWellKnownSid( sid, WinLocalSystemSid) != FALSE ;
		const bool isAdmins =
			// 固定管理者groupです。
			IsWellKnownSid( sid, WinBuiltinAdministratorsSid) != FALSE ;
		// 信頼集合以外のallowを拒否します。
		if( !isUser && !isSystem && !isAdmins) {
			return false ;
		}

		user |= isUser ;
		system |= isSystem ;
		admins |= isAdmins ;
	}

	return (!isolated || user) && system && admins ;
}

/** @brief 同じ生成規則から製品二ACEまたは隔離三ACEのSDDLを作ります。
 * @param[in] sid 隔離profileだけで使うprocess userの文字列。
 * @param[in] directory 継承用OICIを付ける場合true。
 * @param[in] isolated User owner／明示許可を加える場合true。
 * @return 作成時の保護profile。製品ownerはAdministratorsです。
 */
[[nodiscard]] std::wstring protectionSddl( const std::wstring_view sid, const bool directory,
										  const bool isolated)
{
	const std::wstring flags = directory ? L"OICI" : L"" ;	// Directoryだけの継承flagです。
	const std::wstring fixed =
		L"(A;" + flags + L";FA;;;SY)(A;" + flags + L";FA;;;BA)" ;	// 製品二ACEです。
	return isolated ? L"O:" + std::wstring{sid} + L"D:P(A;" + flags + L";FA;;;" +
						  std::wstring{sid} + L")" + fixed
					: L"O:BAD:P" + fixed ;
}

/** @brief Current threadのimpersonationを拒否します。
 * @note Process userで作成したDACLとDPAPIを別identityで使用しません。
 */
void rejectImpersonation()
{
	HANDLE raw{} ;	// 照会で取得したthread tokenを直ちに所有します。
	// 成り代わったthreadではstore操作を続けません。
	if( OpenThreadToken( GetCurrentThread(), TOKEN_QUERY, TRUE, &raw)) {
		const auto token = own( raw) ;	// 拒否経路でもtokenを解放します。
		throw Failure{IndexStoreStatus::PROTECTION_FAILURE, ERROR_BAD_IMPERSONATION_LEVEL} ;
	}

	const DWORD error = GetLastError() ;	// 最初のtoken照会errorです。
	require( error == ERROR_NO_TOKEN, IndexStoreStatus::PROTECTION_FAILURE,
			static_cast<NativeError>( error)) ;
}

/** @brief 既存の用途別CNG hash入口を使って原byte digestを求めます。
 * @param[in] bytes 事前に有限量を確認した非空原byte。
 * @return 原byteの32byte SHA-256。API失敗は元HRESULTで拒否します。
 */
[[nodiscard]] IndexManifestSha256 digest( std::span<const std::byte> bytes)
{
	std::wstring		   hex ;	// 共通APIの所有digest表現です。
	// Char viewはbyte object representationを借用する既存hash境界です。
	const std::string_view text{reinterpret_cast<const char *>( bytes.data()), bytes.size()} ;
	const NativeError	   error =
		// 既存128MiB上限を維持します。
		computeDriverContainerSha256( text, hex) ;
	require( error == 0, IndexStoreStatus::PROTECTION_FAILURE, error) ;
	require( hex.size() == 64U, IndexStoreStatus::PROTECTION_FAILURE,
			static_cast<NativeError>( E_UNEXPECTED)) ;
	constexpr std::wstring_view HEX = L"0123456789abcdef" ;	// 共通APIの固定小文字文法です。
	IndexManifestSha256			result{} ;					// 全桁を成功した値だけ返します。
	// 固定32byteの各二桁を完全に変換します。
	for( std::size_t index = 0U; index < result.size(); ++index) {
		const auto high = HEX.find( hex[index * 2U]) ;		// 上位四bitです。
		const auto low	= HEX.find( hex[index * 2U + 1U]) ;	// 下位四bitです。
		require( high != std::wstring_view::npos && low != std::wstring_view::npos,
				IndexStoreStatus::PROTECTION_FAILURE, static_cast<NativeError>( E_UNEXPECTED)) ;
		result[index] = static_cast<std::uint8_t>( high * 16U + low) ;
	}

	return result ;
}

/** @brief 固定幅整数をpaddingなしでlittle-endianへ追加します。
 * @param[in,out] bytes 所有wire。
 * @param[in] value 幅内の値。
 * @param[in] width 4または8byte。
 */
void appendInteger( std::vector<std::byte> &bytes, const std::uint64_t value, const unsigned width)
{
	// 指定の有限幅だけ下位byteから追加します。
	for( unsigned index = 0U; index < width; ++index) {
		bytes.push_back( static_cast<std::byte>( (value >> (index * 8U)) & 255U)) ;
	}
}

/** @brief 事前確認された完全hashを原ciphertextへ照合します。
 * @param[in] bytes 同handleで読んだ原headです。
 * @param[in] expected 小文字ASCII64桁の承認済みSHA-256です。
 */
void requireExpectedHead( const std::span<const std::byte> bytes, const std::string_view expected)
{
	constexpr std::string_view HEX = "0123456789abcdef" ;	// 自動正規化しない固定文法です。
	require( expected.size() == 64U, IndexStoreStatus::INVALID_INPUT, ERROR_INVALID_PARAMETER) ;
	const auto actual = digest( bytes) ;	// DPAPI復号前の原ciphertextへ結合します。
	// 全64桁を検査し、部分pinや大文字を許可しません。
	for( std::size_t index = 0U; index < actual.size(); ++index) {
		require( expected[index * 2U] == HEX[actual[index] >> 4U] &&
					expected[index * 2U + 1U] == HEX[actual[index] & 15U],
				IndexStoreStatus::STATE_REJECTED, ERROR_INVALID_DATA) ;
	}
}

/** @brief Wireの有限範囲を先に確認して切り出します。
 * @param[in] bytes 全plain byte。
 * @param[in,out] offset 消費位置。成功時だけ進めます。
 * @param[in] count 必要なbyte数。
 * @return 全長が存在する借用範囲。
 */
[[nodiscard]] std::span<const std::byte> take( std::span<const std::byte> bytes, std::size_t &offset,
											  const std::size_t count)
{
	require( offset <= bytes.size() && count <= bytes.size() - offset,
			IndexStoreStatus::STATE_REJECTED) ;
	const auto result = bytes.subspan( offset, count) ;	// 検査した部分だけ借用します。
	offset += count ;
	return result ;
}

/** @brief 固定幅little-endianをoverflowなしで読みます。
 * @param[in] bytes 全plain byte。
 * @param[in,out] offset 消費位置。
 * @param[in] width 4または8byte。
 * @return その幅内のuint64値。
 */
[[nodiscard]] std::uint64_t readInteger( std::span<const std::byte> bytes, std::size_t &offset,
										const unsigned width)
{
	const auto	  part = take( bytes, offset, width) ;	// 完全な固定幅入力です。
	std::uint64_t value{} ;								// 全byteをlittle-endianで構成します。
	// 有限の4／8byteを対応bitへ格納します。
	for( unsigned index = 0U; index < width; ++index) {
		value |= std::to_integer<std::uint64_t>( part[index]) << (index * 8U) ;
	}

	return value ;
}

/** @brief 全0 digestか確認し、genesisの厳格例外へ使います。
 * @param[in] hash 固定digest。
 * @return 全byte0の場合true。
 */
[[nodiscard]] bool zeroHash( const IndexManifestSha256 &hash)
{
	return std::ranges::all_of( hash, []( const auto value) { return value == 0U ; }) ;
}

/** @brief 原入力とhighwaterを一つのstrict plainへ結びます。
 * @param[in] wire 検証済みまたはtestの有限所有値。
 * @return 元byteを維持したplainと末尾digest。
 */
[[nodiscard]] std::vector<std::byte> encodeWire( const Wire &wire)
{
	std::vector<std::byte> bytes ;	// 原入力を一つの保存単位で所有します。
	bytes.reserve( wire.envelope.size() + wire.gzip.size() + 150U) ;
	// 固定magicの全ASCII byteを追加します。
	for( const char value : MAGIC) {
		bytes.push_back( static_cast<std::byte>( value)) ;
	}

	appendInteger( bytes, INDEX_STORE_POLICY_VERSION, 4U) ;
	appendInteger( bytes, INDEX_ASSET_BYTE_POLICY_VERSION, 4U) ;
	appendInteger( bytes, INDEX_RECORD_SCHEMA_POLICY_VERSION, 4U) ;
	appendInteger( bytes, wire.generation, 8U) ;
	appendInteger( bytes, wire.publishedSeconds, 8U) ;
	appendInteger( bytes, wire.envelope.size(), 8U) ;
	appendInteger( bytes, wire.gzip.size(), 8U) ;
	// 二つの独立原hashを順番に保存します。
	for( const auto &hash : {wire.manifestHash, wire.indexHash}) {
		// 固定32byteを変換せずwireへ追加します。
		for( const auto value : hash) {
			bytes.push_back( static_cast<std::byte>( value)) ;
		}
	}

	// 原envelope byteは再serializationせず追加します。
	for( const char value : wire.envelope) {
		bytes.push_back( static_cast<std::byte>( value)) ;
	}

	bytes.insert( bytes.end(), wire.gzip.begin(), wire.gzip.end()) ;
	const auto hash = digest( bytes) ;	// 全先行plain byteの別digestです。
	// Plainの長さ・fieldと原入力も同じdigestへ結合します。
	for( const auto value : hash) {
		bytes.push_back( static_cast<std::byte>( value)) ;
	}

	return bytes ;
}

/** @brief DPAPIが返したplainにも厳格長・版・digestを要求します。
 * @param[in] bytes 有限plain byte。
 * @return 厳格wire。余剰や破損・不正genesisは拒否します。
 */
[[nodiscard]] Wire decodeWire( std::span<const std::byte> bytes)
{
	require( bytes.size() >= 150U && bytes.size() <= MAX_PLAIN, IndexStoreStatus::STATE_REJECTED) ;
	const auto	actual = digest( bytes.first( bytes.size() - 32U)) ;	// DPAPIに加えるplain整合性です。
	std::size_t offset{} ;												// 検査したfieldだけ消費します。
	const auto	magic = take( bytes, offset, MAGIC.size()) ;			// 固定識別子です。
	require( std::memcmp( magic.data(), MAGIC.data(), MAGIC.size()) == 0 &&
				readInteger( bytes, offset, 4U) == INDEX_STORE_POLICY_VERSION &&
				readInteger( bytes, offset, 4U) == INDEX_ASSET_BYTE_POLICY_VERSION &&
				readInteger( bytes, offset, 4U) == INDEX_RECORD_SCHEMA_POLICY_VERSION,
			IndexStoreStatus::STATE_REJECTED) ;
	Wire wire ;	// 完全読取り後だけ返す所有値です。
	wire.generation			 = readInteger( bytes, offset, 8U) ;
	wire.publishedSeconds	 = readInteger( bytes, offset, 8U) ;
	const auto envelopeBytes = readInteger( bytes, offset, 8U) ;	// 独立96KiB枠です。
	const auto gzipBytes	 = readInteger( bytes, offset, 8U) ;	// 独立32MiB枠です。
	require( envelopeBytes <= INDEX_ENVELOPE_MAX_BYTES && gzipBytes <= INDEX_ASSET_MAX_BYTES &&
				wire.publishedSeconds <= 253402300799ULL,
			IndexStoreStatus::STATE_REJECTED) ;
	std::memcpy( wire.manifestHash.data(), take( bytes, offset, 32U).data(), 32U) ;
	std::memcpy( wire.indexHash.data(), take( bytes, offset, 32U).data(), 32U) ;
	const auto envelope =
		// 長さ検査済みです。
		take( bytes, offset, static_cast<std::size_t>( envelopeBytes)) ;
	// Char representationへの借用はplain byteから原UTF-8を所有する境界です。
	wire.envelope.assign( reinterpret_cast<const char *>( envelope.data()), envelope.size()) ;
	const auto gzip =
		// 実原転送byteです。
		take( bytes, offset, static_cast<std::size_t>( gzipBytes)) ;
	wire.gzip.assign( gzip.begin(), gzip.end()) ;
	const auto expected = take( bytes, offset, 32U) ;	// 末尾plain digestです。
	require( offset == bytes.size() && std::memcmp( expected.data(), actual.data(), 32U) == 0,
			IndexStoreStatus::STATE_REJECTED) ;
	// 世代0は新規genesisの全field0だけで、manifestへ渡しません。
	if( wire.generation == 0U) {
		require( wire.publishedSeconds == 0U && wire.envelope.empty() && wire.gzip.empty() &&
					zeroHash( wire.manifestHash) && zeroHash( wire.indexHash),
				IndexStoreStatus::STATE_REJECTED) ;
	} else {
		require( !wire.envelope.empty() && !wire.gzip.empty() && !zeroHash( wire.manifestHash) &&
					!zeroHash( wire.indexHash),
				IndexStoreStatus::STATE_REJECTED) ;
	}

	return wire ;
}

/** @brief 現在期限を履歴検証から独立して確認します。
 * @param[in] data 署名・schema再認証済みmanifest。
 * @param[in] nowUtc 現在の信頼UTC。
 */
void requireCurrentTime( const IndexManifestData						 &data,
						const std::optional<std::chrono::sys_seconds> nowUtc)
{
	require( nowUtc.has_value(), IndexStoreStatus::TIME_UNAVAILABLE) ;
	require( *nowUtc >= data.publishedAtUtc, IndexStoreStatus::NOT_YET_VALID) ;
	require( *nowUtc < data.expiresAtUtc, IndexStoreStatus::EXPIRED) ;
}

/** @brief 内部例外の元診断を公開結果へ維持します。
 * @param[in] failure 拒否段階と元error。
 * @param[in] commit 実commit点の到達区分。
 * @param[in] generation 最新headで確認した最大世代。
 * @return Snapshotなしの失敗結果。
 */
[[nodiscard]] IndexStoreResult failureResult( const Failure					   &failure,
											 const IndexStoreCommitDisposition	commit,
											 const std::optional<std::uint64_t> generation)
{
	IndexStoreResult result ;	// 元診断とcommit事実を別に保持します。
	result.status =
		commit == IndexStoreCommitDisposition::COMMITTED
			? IndexStoreStatus::COMMITTED_NO_SNAPSHOT
			: (commit == IndexStoreCommitDisposition::UNKNOWN ? IndexStoreStatus::COMMIT_UNCERTAIN
															  : failure.status) ;
	result.commit = commit ;
	result.error  = failure.error ;
	result.persistedGeneration =
		commit == IndexStoreCommitDisposition::UNKNOWN ? std::nullopt : generation ;
	result.manifestStatus = failure.manifestStatus ;
	result.assetStatus	  = failure.assetStatus ;
	result.recordsStatus  = failure.recordsStatus ;
	return result ;
}

} // namespace

/** @brief Rootの保護・entropy・原入力再認証と有限I/Oを所有します。 */
struct SignedIndexStore::State {
	/// 自作isolated fixtureだけの診断能力区分。
	bool					isolated{} ;
	/// 成功作成したisolated rootだけを終了時に後始末する区分。
	bool					ownsIsolatedRoot{} ;
	/// 明示移行だけが固定履歴公開集合を使います。通常trustを変更しません。
	bool					migrationTrust{} ;
	/// 明示移行だけがroot handleへDELETE権限を要求します。
	bool					renameable{} ;
	/// APIへ渡す正規local絶対path。
	std::filesystem::path	root ;
	/// 通常domainだけが旧共用rootの再出現を拒否します。
	std::filesystem::path	legacyGuard ;
	/// 削除共有を許さずpinした祖先とrootの実handle。
	std::vector<Handle>		directories ;
	/// TokenUser領域。SIDの借用寿命を所有します。
	std::vector<std::byte>	tokenUser ;
	/// Fileの作成時保護descriptor。
	LocalMemory				fileDescriptor ;
	/// Directoryの作成時保護descriptor。
	LocalMemory				directoryDescriptor ;
	/// 用途とroot identityを結合する非秘密DPAPI entropy。
	std::vector<std::byte>	entropy ;
	/// 通常製品は空、明示移行の固定公開集合またはfixtureのRAM公開集合の所有copy。
	std::vector<OwnedTrust> keys ;
	/// 再openしたfixtureが元の隔離rootの後始末能力だけを延長します。
	std::shared_ptr<State>	rootOwner ;

	/** @brief Isolatedで自作した固定fileだけを回収します。
	 * @note 失敗時も任意再帰削除を行いません。製品rootは触りません。
	 */
	~State() noexcept
	{
		directories.clear() ;
		// 作成能力を持つ隔離rootだけで、既知三fileの後始末を行います。
		if( ownsIsolatedRoot) {
			// 固定三名だけを消し、未知entryがあればdirectoryを残します。
			for( const auto *name : {L"head.bin", L"head.stage", L"store.lock"}) {
				static_cast<void>( DeleteFileW( (root / name).c_str())) ;
			}

			static_cast<void>( RemoveDirectoryW( root.c_str())) ;
		}
	}

	/** @brief Process userのborrowed SIDを返します。
	 * @return TokenUser所有期間に有効なSID。
	 */
	[[nodiscard]] PSID userSid() const noexcept
	{
		// TokenUserのOS境界で、APIが埋めた可変bufferの型を読む借用castです。
		return reinterpret_cast<const TOKEN_USER *>( tokenUser.data())->User.Sid ;
	}

	/** @brief 製品管理者profileと隔離user profileの作成時descriptorを分離します。 */
	void makeSecurity()
	{
		rejectImpersonation() ;
		HANDLE raw{} ;	// Process userを照会するtokenです。
		requireApi( OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &raw),
				   IndexStoreStatus::PROTECTION_FAILURE) ;
		const auto token = own( raw) ;	// 全経路でtokenを閉じます。
		DWORD	   required{} ;			// TokenUserの実必要byte数です。
		static_cast<void>( GetTokenInformation( token.get(), TokenUser, nullptr, 0U, &required)) ;
		require( required >= sizeof( TOKEN_USER) && required <= 65536U,
				IndexStoreStatus::PROTECTION_FAILURE, ERROR_INVALID_DATA) ;
		tokenUser.resize( required) ;
		requireApi(
			GetTokenInformation( token.get(), TokenUser, tokenUser.data(), required, &required),
			IndexStoreStatus::PROTECTION_FAILURE) ;
		require( IsValidSid( userSid()) != FALSE, IndexStoreStatus::PROTECTION_FAILURE,
				ERROR_INVALID_SID) ;
		LPWSTR rawSid{} ;	// OSが返すSDDL用SID文字列です。
		requireApi( ConvertSidToStringSidW( userSid(), &rawSid),
				   IndexStoreStatus::PROTECTION_FAILURE) ;
		const LocalMemory  sidOwner{rawSid} ;	// SID表現をscopeへ所有します。
		const std::wstring sid{rawSid} ;		// ログへ渡さないprocess identityです。
		// Fileとdirectoryの二つの厳格作成profileだけを構築します。
		for( const bool directory : {false, true}) {
			const std::wstring sddl =
				// Profileを交差させません。
				protectionSddl( sid, directory, isolated) ;
			PSECURITY_DESCRIPTOR rawDescriptor{} ;	// OSが構築するdescriptorです。
			requireApi( ConvertStringSecurityDescriptorToSecurityDescriptorW(
						   sddl.c_str(), SDDL_REVISION_1, &rawDescriptor, nullptr),
					   IndexStoreStatus::PROTECTION_FAILURE) ;
			// 対応種類の作成時descriptorへ所有権を移します。
			if( directory) {
				directoryDescriptor.reset( rawDescriptor) ;
			} else {
				fileDescriptor.reset( rawDescriptor) ;
			}
		}
	}

	/** @brief 同じhandleの実owner／DACLを検査します。
	 * @param[in] handle READ_CONTROL付き実handle。
	 * @param[in] directory Directoryの場合true。
	 */
	void checkSecurity( HANDLE handle, const bool directory) const
	{
		PSECURITY_DESCRIPTOR raw{} ;	// OS descriptorを直後に所有します。
		const DWORD			 code = GetSecurityInfo(
			 handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr,
			 nullptr, nullptr, nullptr, &raw) ;	// 同じ実objectのsecurityです。
		const LocalMemory owner{raw} ;			// API失敗で返った領域も回収します。
		require( code == ERROR_SUCCESS, IndexStoreStatus::PROTECTION_FAILURE,
				static_cast<NativeError>( code)) ;
		require( allowedDescriptor( raw, userSid(), directory, isolated),
				IndexStoreStatus::PROTECTION_FAILURE, ERROR_ACCESS_DENIED) ;
	}

	/** @brief Directoryを削除共有せず開き、path・reparseとprivate ACLを検査します。
	 * @param[in] path Pinする絶対path。
	 * @param[in] privateDirectory 専用階層だけで保護ACLを要求する区分。
	 */
	void pin( const std::filesystem::path &path, const bool privateDirectory)
	{
		auto handle = own( CreateFileW( apiPath( path).c_str(),
									  FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES |
										  (privateDirectory ? READ_CONTROL : 0U) |
										  (renameable && path == root ? DELETE : 0U),
									  FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
									  FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
									  nullptr)) ;	// 祖先差替えを防ぐ実ownerです。
		require( static_cast<bool>( handle), IndexStoreStatus::PROTECTION_FAILURE,
				static_cast<NativeError>( GetLastError())) ;
		checkObject( handle.get(), path, true) ;
		// 専用rootと製品の親だけで選択した厳格profileを要求します。
		if( privateDirectory) {
			checkSecurity( handle.get(), true) ;
		}

		directories.push_back( std::move( handle)) ;
	}

	/** @brief 作成時にだけ保護descriptorを付け、既存fileを修復せず開きます。
	 * @param[in] name 固定した一file名。
	 * @param[in] access 要求するI/O権限。
	 * @param[in] share 有限の共有flag。
	 * @param[in] disposition OPEN_EXISTING、CREATE_NEWまたはOPEN_ALWAYS。
	 * @return 属性／ACLを同じhandleで検査したowner。
	 */
	[[nodiscard]] Handle openFile( const wchar_t *name, const DWORD access, const DWORD share,
								  const DWORD disposition) const
	{
		SECURITY_ATTRIBUTES attributes{sizeof( SECURITY_ATTRIBUTES), fileDescriptor.get(),
									   FALSE} ;		// 作成時から継承停止します。
		const auto			path   = root / name ;	// Caller指定pathは受理しません。
		auto				handle = own( CreateFileW(
			   apiPath( path).c_str(), access | READ_CONTROL, share,
			   disposition == OPEN_EXISTING ? nullptr : &attributes, disposition,
			   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
			   nullptr)) ;	// I/Oと検査を同じfileへ固定します。
		// Sharing競合は待機せず、欠損は既存stateの拒否として返します。
		if( !handle) {
			const DWORD code = GetLastError() ;	// 最初のopen errorです。
			throw Failure{code == ERROR_SHARING_VIOLATION
							  ? IndexStoreStatus::BUSY
							  : (code == ERROR_FILE_NOT_FOUND ? IndexStoreStatus::STATE_REJECTED
															  : IndexStoreStatus::IO_FAILURE),
						  static_cast<NativeError>( code)} ;
		}

		checkObject( handle.get(), path, false) ;
		checkSecurity( handle.get(), false) ;
		return handle ;
	}

	/** @brief 同じfile handleの実長を確認して有限byteを読みます。
	 * @param[in] file 検査済みread handle。
	 * @param[in] maximum 実byte上限。
	 * @return 完全に読み取った所有byte。部分readは拒否します。
	 */
	[[nodiscard]] std::vector<std::byte> readFile( HANDLE file, const std::size_t maximum) const
	{
		LARGE_INTEGER size{} ;	// 同じhandleの実長です。
		requireApi( GetFileSizeEx( file, &size), IndexStoreStatus::IO_FAILURE) ;
		require( size.QuadPart > 0 && static_cast<std::uint64_t>( size.QuadPart) <= maximum,
				IndexStoreStatus::STATE_REJECTED, ERROR_INVALID_DATA) ;
		std::vector<std::byte> bytes(
			// 実上限内だけ確保します。
			static_cast<std::size_t>( size.QuadPart)) ;
		DWORD read{} ;	// 完了した実byte数です。
		requireApi( ReadFile( file, bytes.data(), static_cast<DWORD>( bytes.size()), &read, nullptr),
				   IndexStoreStatus::IO_FAILURE) ;
		require( read == bytes.size(), IndexStoreStatus::IO_FAILURE, ERROR_READ_FAULT) ;
		return bytes ;
	}

	/** @brief 実rootを再確認してshare0のlockを取得します。
	 * @return 固定本文・属性・ACLも成立した排他的owner。
	 */
	[[nodiscard]] Handle lock() const
	{
		rejectImpersonation() ;
		requireLegacyAbsent( legacyGuard) ;
		checkObject( directories.back().get(), root, true) ;
		checkSecurity( directories.back().get(), true) ;
		auto	   file = openFile( L"store.lock", GENERIC_READ, 0U,
								   OPEN_EXISTING) ;	// 他operationをOSのsharingで排除します。
		const auto bytes =
			// 初期化中の空lockも拒否します。
			readFile( file.get(), LOCK_BYTES.size()) ;
		require( bytes.size() == LOCK_BYTES.size() &&
					std::memcmp( bytes.data(), LOCK_BYTES.data(), bytes.size()) == 0,
				IndexStoreStatus::STATE_REJECTED, ERROR_INVALID_DATA) ;
		return file ;
	}

	/** @brief 用途とroot identityのentropyで実DPAPIを実行します。
	 * @param[in] bytes Protect時plain、unprotect時実disk byte。
	 * @param[in] protect Protectの場合true。
	 * @return 完全なOS出力。上限外／障害では拒否します。
	 */
	[[nodiscard]] std::vector<std::byte> dpapi( const std::span<const std::byte> bytes,
											   const bool						protect) const
	{
		require( !bytes.empty() && bytes.size() <= (protect ? MAX_PLAIN : MAX_PROTECTED),
				IndexStoreStatus::STATE_REJECTED) ;
		// DPAPIはnonconst pointerを要求しますが、入力byteを変更しない契約へ限定したWin32境界です。
		DATA_BLOB  input{static_cast<DWORD>( bytes.size()),
						 reinterpret_cast<BYTE *>( const_cast<std::byte *>( bytes.data()))} ;
		DATA_BLOB  additional{static_cast<DWORD>( entropy.size()),
							  reinterpret_cast<BYTE *>( const_cast<std::byte *>(
								  // Rootに結合する非秘密用途entropyです。
								  entropy.data()))} ;
		DATA_BLOB  output{} ;	// LocalFreeで回収するOS allocationです。
		const BOOL success =
			protect
				? CryptProtectData( &input, nullptr, &additional, nullptr, nullptr,
								   CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &output)
				: CryptUnprotectData( &input, nullptr, &additional, nullptr, nullptr,
									 CRYPTPROTECT_UI_FORBIDDEN,
									 &output) ;	// 署名の代用には使いません。
		const DWORD code =
			success ? ERROR_SUCCESS : GetLastError() ;	// 他APIより前に診断を保持します。
		const LocalMemory owner{output.pbData} ;		// API失敗時の非null出力も回収します。
		require( success != FALSE, IndexStoreStatus::PROTECTION_FAILURE,
				static_cast<NativeError>( code)) ;
		require( output.pbData != nullptr && output.cbData > 0U &&
					output.cbData <= (protect ? MAX_PROTECTED : MAX_PLAIN),
				IndexStoreStatus::STATE_REJECTED) ;
		std::vector<std::byte> result( output.cbData) ;	// 有限実出力だけを所有します。
		std::memcpy( result.data(), output.pbData, result.size()) ;
		return result ;
	}

	/** @brief 実署名・gzip・recordを同じ既存verifierへ再投入します。
	 * @param[in] wire 原入力とplain claims。
	 * @param[in] nowUtc 現在の信頼UTCまたは履歴検証専用発行秒。
	 * @param[in] highWater 排他的に再読取りした最新headのauthority。
	 * @return 全再認証済み所有値。Claimsと署名の矛盾は拒否します。
	 */
	[[nodiscard]] Verified verify( Wire wire, const std::optional<std::chrono::sys_seconds> nowUtc,
								  const std::optional<IndexManifestHighWater> &highWater) const
	{
		std::vector<signed_index_detail::TrustKey> trust ;	// 所有固定鍵の呼出し中だけのviewです。
		// 最大8の固定public keyを借用し、外部envelopeからtrustを作りません。
		for( const auto &key : keys) {
			trust.push_back( {key.keyId, key.blob}) ;
		}

		auto manifest =
			(isolated || migrationTrust)
				? signed_index_detail::authenticateWithTrustKeys( wire.envelope, nowUtc, highWater,
																 trust)
				: authenticateSignedIndexManifest( wire.envelope, nowUtc,
												  highWater) ;	// 製品の唯一のbinary trust入口です。
		// Crypto／世代拒否の元区分を維持します。
		if( !manifest.manifest) {
			throw Failure{IndexStoreStatus::MANIFEST_REJECTED, manifest.error, manifest.status} ;
		}

		const auto &data = manifest.manifest->data() ;	// 署名に結合した実値です。
		require( wire.generation == data.generation && wire.manifestHash == data.manifestSha256 &&
					wire.publishedSeconds ==
						static_cast<std::uint64_t>( data.publishedAtUtc.time_since_epoch().count()),
				IndexStoreStatus::STATE_REJECTED) ;
		auto bytes = authenticateIndexAssetBytes( *manifest.manifest, wire.gzip,
												 nowUtc) ;	// 原圧縮hash・sizeとGZipを再検査します。
		// Partial展開を成功receiptへ変換しません。
		if( !bytes.receipt) {
			throw Failure{IndexStoreStatus::ASSET_REJECTED, bytes.error, {}, bytes.status} ;
		}

		auto records = readSignedIndexRecords( *bytes.receipt,
											  nowUtc) ;	// 原record hashと全schemaを再検査します。
		// 署名だけの合格でschema出力を作りません。
		if( !records.receipt) {
			throw Failure{
				IndexStoreStatus::RECORDS_REJECTED, records.error, {}, {}, records.status} ;
		}

		require( wire.indexHash == records.receipt->indexSha256(), IndexStoreStatus::STATE_REJECTED) ;
		return {std::move( wire), std::move( records.receipt)} ;
	}

	/** @brief Lock保持中の実headを履歴再認証して最大世代を回収します。
	 * @return Genesisまたは完全履歴verified。期限切れでも世代を0へ戻しません。
	 */
	[[nodiscard]] Verified readHead() const
	{
		const auto file			  = openFile( L"head.bin", GENERIC_READ, FILE_SHARE_READ,
											 OPEN_EXISTING) ;				// 同じhandleで保護を確認します。
		const auto protectedBytes = readFile( file.get(), MAX_PROTECTED) ;	// 実disk全byteです。
		const auto plain =
			// 端末／rootとplain integrityを先に確認します。
			dpapi( protectedBytes, false) ;
		auto wire = decodeWire( plain) ;	// Strict wireを認証元にせず原入力を再確認します。
		// Genesisは正常初回の私有例外だけで、manifest verifierへ渡しません。
		if( wire.generation == 0U) {
			return {std::move( wire), std::nullopt} ;
		}

		const auto publication = std::chrono::sys_seconds{
			std::chrono::seconds{	// 履歴authority回収だけの時刻です。
								 static_cast<std::int64_t>( wire.publishedSeconds)}} ;
		try {
			return verify( std::move( wire), publication, std::nullopt) ;
		} catch( Failure &failure) {
			failure.status =
				IndexStoreStatus::STATE_REJECTED ;	// Historical拒否をfirst-useへ変換しません。
			throw ;
		}
	}

	/** @brief 完全write／flushから一headだけを置換します。
	 * @param[in] protectedBytes 実DPAPI出力。
	 * @param[in] fault Isolatedだけの拒否点。
	 * @param[in,out] disposition Rename呼出し前後の確定区分。
	 */
	void replaceHead( const std::span<const std::byte>		protectedBytes,
					 const signed_index_store_detail::Fault fault,
					 IndexStoreCommitDisposition		   &disposition) const
	{
		using signed_index_store_detail::Fault ;
		require( fault != Fault::BEFORE_STAGE, IndexStoreStatus::IO_FAILURE, ERROR_WRITE_FAULT) ;
		auto		  file = openFile( L"head.stage", GENERIC_READ | GENERIC_WRITE, 0U,
									  OPEN_ALWAYS) ;	// 保護検査後だけtruncateします。
		LARGE_INTEGER beginning{} ;						// Stagingを先頭へ限定するoffsetです。
		requireApi( SetFilePointerEx( file.get(), beginning, nullptr, FILE_BEGIN),
				   IndexStoreStatus::IO_FAILURE) ;
		requireApi( SetEndOfFile( file.get()), IndexStoreStatus::IO_FAILURE) ;
		const auto count = fault == Fault::PARTIAL_WRITE
							   ? protectedBytes.size() / 2U
							   : protectedBytes.size() ;	// 部分writeを実diskで再現します。
		DWORD	   written{} ;								// 実write byte数です。
		requireApi( WriteFile( file.get(), protectedBytes.data(), static_cast<DWORD>( count), &written,
							 nullptr),
				   IndexStoreStatus::IO_FAILURE) ;
		require( written == protectedBytes.size() && fault != Fault::PARTIAL_WRITE,
				IndexStoreStatus::IO_FAILURE, ERROR_WRITE_FAULT) ;
		require( fault != Fault::BEFORE_FLUSH, IndexStoreStatus::IO_FAILURE, ERROR_WRITE_FAULT) ;
		requireApi( FlushFileBuffers( file.get()), IndexStoreStatus::IO_FAILURE) ;
		require( fault != Fault::BEFORE_REPLACE, IndexStoreStatus::IO_FAILURE, ERROR_WRITE_FAULT) ;
		file.reset() ;
		requireLegacyAbsent( legacyGuard) ;
		// API失敗を旧head保持と推測しません。
		disposition = IndexStoreCommitDisposition::UNKNOWN ;
		requireApi( MoveFileExW( apiPath( root / L"head.stage").c_str(),
							   apiPath( root / L"head.bin").c_str(),
							   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH),
				   IndexStoreStatus::IO_FAILURE) ;
		// ここが一つだけのcommit点です。
		disposition = IndexStoreCommitDisposition::COMMITTED ;
	}

	/** @brief 保護directoryとgenesisを新規rootだけへ初期化します。
	 * @param[in] path 内部で選定した固定製品または一意fixture絶対path。
	 * @param[in] production 製品の専用親も保護する場合true。
	 * @param[in] allowExisting 再openまたは製品入口だけで既存rootを認める区分。
	 * @param[in] createMissing 新規root・genesis作成を認める場合true。
	 */
	void initialize( const std::filesystem::path &path, const bool production,
					const bool allowExisting = true, const bool createMissing = true)
	{
		root = path.lexically_normal() ;
		require( path.is_absolute() && root == path && root.root_name().native().size() == 2U &&
					root.native().size() < 32700U &&
					root.native().find( L':', 2U) == std::wstring::npos,
				IndexStoreStatus::PROTECTION_FAILURE, ERROR_INVALID_NAME) ;
		DWORD					 flags{} ;		// 実volumeの永続ACL能力です。
		std::array<wchar_t, 32U> filesystem{} ;	// 対象filesystemの有限名です。
		require( GetDriveTypeW( root.root_path().c_str()) == DRIVE_FIXED,
				IndexStoreStatus::PROTECTION_FAILURE, ERROR_NOT_SUPPORTED) ;
		requireApi( GetVolumeInformationW( root.root_path().c_str(), nullptr, 0U, nullptr, nullptr,
										 &flags, filesystem.data(),
										 static_cast<DWORD>( filesystem.size())),
				   IndexStoreStatus::PROTECTION_FAILURE) ;
		require( (flags & FILE_PERSISTENT_ACLS) != 0U &&
					std::wstring_view{filesystem.data()} == L"NTFS",
				IndexStoreStatus::PROTECTION_FAILURE, ERROR_NOT_SUPPORTED) ;
		makeSecurity() ;
		auto current = root.root_path() ;	// Driveから順番にpinするpathです。
		pin( current, false) ;
		std::size_t depth{} ;	// 祖先数も有限に制限します。
		// 専用root前までの祖先を順に保持し、reparse経路を拒否します。
		for( const auto &component : root.relative_path()) {
			current /= component ;
			require( ++depth <= 64U, IndexStoreStatus::PROTECTION_FAILURE,
					ERROR_FILENAME_EXCED_RANGE) ;
			// Rootの作成状態は最後に一回だけ区別します。
			if( current == root) {
				break ;
			}

			// 製品専用親は新規時だけ保護して作成します。
			if( production && createMissing && current == root.parent_path()) {
				SECURITY_ATTRIBUTES attrs{sizeof( SECURITY_ATTRIBUTES), directoryDescriptor.get(),
										  FALSE} ;	// 作成時の保護です。
				// 既存親は修復せず、後続handleで厳格検査します。
				if( !CreateDirectoryW( apiPath( current).c_str(), &attrs)) {
					const DWORD code = GetLastError() ;	// 親作成の最初のerrorです。
					require( code == ERROR_ALREADY_EXISTS, IndexStoreStatus::PROTECTION_FAILURE,
							static_cast<NativeError>( code)) ;
				}
			}

			pin( current, production && current == root.parent_path()) ;
		}

		SECURITY_ATTRIBUTES attrs{sizeof( SECURITY_ATTRIBUTES), directoryDescriptor.get(),
								  FALSE} ;	// Rootの作成時保護です。
		const BOOL			created = createMissing ? CreateDirectoryW( apiPath( root).c_str(),
																	   &attrs)
													: FALSE ;	// 読取りmodeでは作成APIを呼びません。
		const DWORD			createCode =
			created			? ERROR_SUCCESS
					: createMissing ? GetLastError()
									: ERROR_ALREADY_EXISTS ;	// 読取りmodeは後続pinで存在を確認します。
		require( created || createCode == ERROR_ALREADY_EXISTS, IndexStoreStatus::PROTECTION_FAILURE,
				static_cast<NativeError>( createCode)) ;
		require( created || allowExisting, IndexStoreStatus::PROTECTION_FAILURE,
				ERROR_ALREADY_EXISTS) ;
		ownsIsolatedRoot = created && isolated ;
		pin( root, true) ;
		BY_HANDLE_FILE_INFORMATION identity{} ;	// 実保持rootのvolume／file identityです。
		requireApi( GetFileInformationByHandle( directories.back().get(), &identity),
				   IndexStoreStatus::PROTECTION_FAILURE) ;
		// 用途識別の全byteをroot identityと同じentropyへ結合します。
		for( const char value : MAGIC) {
			entropy.push_back( static_cast<std::byte>( value)) ;
		}

		appendInteger( entropy, identity.dwVolumeSerialNumber, 4U) ;
		appendInteger( entropy, identity.nFileIndexHigh, 4U) ;
		appendInteger( entropy, identity.nFileIndexLow, 4U) ;
		// 既存rootの欠損を初回として救済しません。
		if( !created) {
			const auto lease = lock() ;	// 実lockとheadが必須です。
			static_cast<void>( readHead()) ;
			return ;
		}

		auto  lease = openFile( L"store.lock", GENERIC_READ | GENERIC_WRITE, 0U,
							   CREATE_NEW) ;	// 初期prefixにも排他を維持します。
		DWORD written{} ;						// 固定lock本文の実write長です。
		requireApi( WriteFile( lease.get(), LOCK_BYTES.data(), static_cast<DWORD>( LOCK_BYTES.size()),
							 &written, nullptr),
				   IndexStoreStatus::IO_FAILURE) ;
		require( written == LOCK_BYTES.size(), IndexStoreStatus::IO_FAILURE, ERROR_WRITE_FAULT) ;
		requireApi( FlushFileBuffers( lease.get()), IndexStoreStatus::IO_FAILURE) ;
		const auto genesis = encodeWire( Wire{}) ;			// Manifestの正世代を緩めない私有genesisです。
		const auto protectedBytes = dpapi( genesis, true) ;	// 実端末／rootへ保護します。
		IndexStoreCommitDisposition disposition{} ;			// 初期headも一namespace切替です。
		replaceHead( protectedBytes, signed_index_store_detail::Fault::NONE, disposition) ;
		static_cast<void>( readHead()) ;
	}

	/** @brief 固定domainの分類/移動/再実行を同じ実装で検証します。
	 * @param[in] parent 製品の固定親または自作隔離rootです。
	 * @param[in] expectedHeadSha256 事前確認された原ciphertextの完全pinです。
	 * @param[in] nowUtc 現在UTC。未来履歴を拒否します。
	 * @param[in] migrationKeys 固定二公開鍵または隔離RAM鍵だけです。
	 * @param[in] isolated 自作fixtureだけでuser ACLを認める場合trueです。
	 * @return 旧世代と原headを保持した移動または明示拒否です。
	 */
	[[nodiscard]] static IndexStoreMigrationResult migrateNamespace(
		const std::filesystem::path &parent, std::string_view expectedHeadSha256,
		std::optional<std::chrono::sys_seconds>		   nowUtc,
		std::span<const signed_index_detail::TrustKey> migrationKeys, bool isolated) noexcept ;

	/** @brief 原headとidentityを保持した同親renameだけを実行します。
	 * @param[in] destination 固定domainまたは自作fixtureの単一leafです。
	 * @param[in] expectedHeadSha256 事前確認された原ciphertextの完全pinです。
	 * @param[in] nowUtc 現在UTC。歴史認証の未来発行を拒否します。
	 * @param[in] fault 隔離testだけが使うcommit前後の拒否点です。
	 * @return 現在snapshotを含まない歴史世代と移動事実です。
	 */
	[[nodiscard]] IndexStoreMigrationResult relocate(
		std::filesystem::path destination, const std::string_view expectedHeadSha256,
		const std::optional<std::chrono::sys_seconds> nowUtc,
		const signed_index_store_detail::Fault		  fault)
	{
		using signed_index_store_detail::Fault ;
		IndexStoreMigrationResult result ;	// Rename成功と認証した世代を別々に保持します。
		try {
			require( renameable && destination.parent_path() == root.parent_path() &&
						destination != root && destination == destination.lexically_normal(),
					IndexStoreStatus::INVALID_INPUT, ERROR_INVALID_PARAMETER) ;
			auto	   lease	 = lock() ;	// 最終検査まで旧writerをshare0で排除します。
			auto	   headLease = openFile( L"head.bin", GENERIC_READ, FILE_SHARE_READ,
											OPEN_EXISTING) ;	// 最終照合まで書換えと削除を排除します。
			const auto original	 = protectedHead() ;			// 旧暗号byteを比較用RAMだけへ所有します。
			requireExpectedHead( original, expectedHeadSha256) ;
			auto verified = readHead() ;	// 期限切れでも実署名・全schemaを独立認証します。
			require( verified.receipt.has_value(), IndexStoreStatus::STATE_REJECTED,
					ERROR_INVALID_DATA) ;
			require( nowUtc.has_value(), IndexStoreStatus::TIME_UNAVAILABLE, ERROR_INVALID_TIME) ;
			require( verified.receipt->assetBytes().manifest().data().publishedAtUtc <= *nowUtc,
					IndexStoreStatus::NOT_YET_VALID, ERROR_INVALID_TIME) ;
			result.generation = verified.wire.generation ;
			const DWORD targetAttributes =
				// 既存先を修復/mergeしません。
				GetFileAttributesW( destination.c_str()) ;
			require( targetAttributes == INVALID_FILE_ATTRIBUTES, IndexStoreStatus::STATE_REJECTED,
					ERROR_ALREADY_EXISTS) ;
			const DWORD targetError = GetLastError() ;	// 不存在以外の照会失敗を拒否します。
			require( targetError == ERROR_FILE_NOT_FOUND, IndexStoreStatus::PROTECTION_FAILURE,
					static_cast<NativeError>( targetError)) ;
			BY_HANDLE_FILE_INFORMATION before{} ;	// rename前後のroot identity比較です。
			requireApi( GetFileInformationByHandle( directories.back().get(), &before),
					   IndexStoreStatus::PROTECTION_FAILURE) ;
			const auto target = apiPath( destination) ;	// 変更前に必要な所有bufferを確保します。
			const auto size =
				// 終端分も確保します。
				sizeof( FILE_RENAME_INFO) + target.size() * sizeof( wchar_t) ;
			std::vector<std::byte> storage( size) ;	// OS構造体と可変長pathだけの有限bufferです。
			// Win32可変長FILE_RENAME_INFOのAPI境界で、構造体の全固定fieldを初期化します。
			auto				  *rename = reinterpret_cast<FILE_RENAME_INFO *>( storage.data()) ;
			rename->ReplaceIfExists		  = FALSE ;
			rename->RootDirectory		  = nullptr ;
			rename->FileNameLength		  = static_cast<DWORD>( target.size() * sizeof( wchar_t)) ;
			std::memcpy( rename->FileName, target.data(), rename->FileNameLength) ;
			checkObject( directories.back().get(), root, true) ;
			checkSecurity( directories.back().get(), true) ;
			const auto final = readHead() ;	// 最終namespace変更前に全署名認証を繰り返します。
			require( final.wire.manifestHash == verified.wire.manifestHash &&
						protectedHead() == original,
					IndexStoreStatus::STATE_REJECTED, ERROR_INVALID_DATA) ;
			require( fault != Fault::BEFORE_REPLACE, IndexStoreStatus::IO_FAILURE,
					ERROR_WRITE_FAULT) ;
			// NTFSは開いた子fileを含むdirectory renameを拒否するため直前だけ閉じます。
			// DELETE権限を持ちDELETE共有しないroot handleが既存/新規store ownerを排除し続けます。
			headLease.reset() ;
			lease.reset() ;
			result.commit = IndexStoreCommitDisposition::UNKNOWN ;
			requireApi( SetFileInformationByHandle( directories.back().get(), FileRenameInfo, rename,
												  static_cast<DWORD>( storage.size())),
					   IndexStoreStatus::IO_FAILURE) ;
			result.commit = IndexStoreCommitDisposition::COMMITTED ;
			root.swap( destination) ;
			require( fault != Fault::AFTER_REPLACE, IndexStoreStatus::IO_FAILURE, ERROR_READ_FAULT) ;
			checkObject( directories.back().get(), root, true) ;
			checkSecurity( directories.back().get(), true) ;
			BY_HANDLE_FILE_INFORMATION
			after{} ;	// 同directoryであることを数値identityでも確認します。
			requireApi( GetFileInformationByHandle( directories.back().get(), &after),
					   IndexStoreStatus::PROTECTION_FAILURE) ;
			require( before.dwVolumeSerialNumber == after.dwVolumeSerialNumber &&
						before.nFileIndexHigh == after.nFileIndexHigh &&
						before.nFileIndexLow == after.nFileIndexLow && protectedHead() == original,
					IndexStoreStatus::STATE_REJECTED, ERROR_INVALID_DATA) ;
			const auto persisted = readHead() ;	// 新pathでも同DPAPI entropyとfloorが成立します。
			require( persisted.wire.generation == result.generation &&
						persisted.wire.manifestHash == verified.wire.manifestHash,
					IndexStoreStatus::STATE_REJECTED, ERROR_INVALID_DATA) ;
		} catch( const Failure &failure) {
			result.error = failure.error == 0 ? ERROR_INVALID_DATA : failure.error ;
		} catch( const std::bad_alloc &) {
			result.error = static_cast<NativeError>( E_OUTOFMEMORY) ;
		} catch( ...) {
			result.error = static_cast<NativeError>( E_UNEXPECTED) ;
		}

		return result ;
	}

	/** @brief 同handle保護検査を通した原ciphertextだけを読みます。
	 * @return 上限内の原head byteです。復号plainを保存しません。
	 */
	[[nodiscard]] std::vector<std::byte> protectedHead() const
	{
		const auto file = openFile( L"head.bin", GENERIC_READ, FILE_SHARE_READ,
								   OPEN_EXISTING) ;	// 検査とreadを結合します。
		return readFile( file.get(), MAX_PROTECTED) ;
	}
} ;

/** @see signed_index_store.h */
AuthenticatedIndexSnapshot::AuthenticatedIndexSnapshot( IndexRecordsSchemaReceipt receipt,
													   std::string				 envelope,
													   std::vector<std::byte>	 gzip) noexcept
	: receipt_( std::move( receipt)), envelope_( std::move( envelope)), gzip_( std::move( gzip))
{
}
/** @see signed_index_store.h */
const IndexRecordsSchemaReceipt &AuthenticatedIndexSnapshot::schemaReceipt() const noexcept
{
	return receipt_ ;
}
/** @see signed_index_store.h */
std::string_view AuthenticatedIndexSnapshot::originalEnvelope() const noexcept
{
	return envelope_ ;
}
/** @see signed_index_store.h */
std::span<const std::byte> AuthenticatedIndexSnapshot::originalGzip() const noexcept
{
	return gzip_ ;
}
/** @see signed_index_store.h */
std::uint32_t AuthenticatedIndexSnapshot::storePolicyVersion() const noexcept
{
	return INDEX_STORE_POLICY_VERSION ;
}
/** @see signed_index_store.h */
SignedIndexStore::SignedIndexStore( std::shared_ptr<State> state) noexcept : state_( std::move( state))
{
}
/** @see signed_index_store.h */
SignedIndexStore::~SignedIndexStore() = default ;

/** @see signed_index_store.h */
IndexStoreResult SignedIndexStore::reloadFixedExisting(
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	// 本番trust未配備では固定rootを照会・作成しません。
	if( !signed_index_detail::productTrustAvailable()) {
		return {.status = IndexStoreStatus::TRUST_UNAVAILABLE} ;
	}

	try {
		PWSTR		  raw{} ;	// KnownFolder API所有pathです。
		const HRESULT error = SHGetKnownFolderPath( FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr,
												   &raw) ;				// 固定起点だけです。
		const std::unique_ptr<wchar_t, TaskMemoryCloser> owner{raw} ;	// 全経路で解放します。
		require( SUCCEEDED( error) && raw != nullptr, IndexStoreStatus::PROTECTION_FAILURE,
				static_cast<NativeError>( error)) ;
		auto	   state   = std::make_shared<State>() ;					// 任意trustを追加しない製品stateです。
		const auto parent  = std::filesystem::path{raw} / L"DriverCrate" ;	// 固定された製品親です。
		state->legacyGuard = parent / LEGACY_NAME ;
		requireLegacyAbsent( state->legacyGuard) ;
		state->initialize( parent / domainName( local_index_profile::ENABLED,
											  local_index_profile::PUBLIC_FINGERPRINT),
						  true, true, false) ;
		SignedIndexStore store{std::move( state)} ;	// 同じ再認証実装へ戻します。
		return store.reload( nowUtc) ;
	} catch( const Failure &failure) {
		return failureResult( failure, IndexStoreCommitDisposition::NO_CHANGE, std::nullopt) ;
	} catch( const std::bad_alloc &) {
		return {.status = IndexStoreStatus::OUT_OF_MEMORY,
				.error	= static_cast<NativeError>( E_OUTOFMEMORY)} ;
	} catch( ...) {
		return {.status = IndexStoreStatus::IO_FAILURE,
				.error	= static_cast<NativeError>( E_UNEXPECTED)} ;
	}
}

/** @see signed_index_store.h */
IndexStoreOpenResult SignedIndexStore::openFixedProtectedStore() noexcept
{
	try {
		PWSTR		  raw{} ;	// KnownFolder APIのowned pathです。
		const HRESULT error = SHGetKnownFolderPath( FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr,
												   &raw) ;					// 任意入力を受理しません。
		const std::unique_ptr<wchar_t, TaskMemoryCloser> pathOwner{raw} ;	// 全経路で返します。
		require( SUCCEEDED( error) && raw != nullptr, IndexStoreStatus::PROTECTION_FAILURE,
				static_cast<NativeError>( error)) ;
		auto state =
			std::make_shared<State>() ;	// 任意trustを追加せず、通常/localの固定選択に従います。
		const auto parent =
			std::filesystem::path{raw} / L"DriverCrate" ;	// 通常/検証domainで同じ保護親です。
		state->legacyGuard = parent / LEGACY_NAME ;
		requireLegacyAbsent( state->legacyGuard) ;
		state->initialize( parent / domainName( local_index_profile::ENABLED,
											  local_index_profile::PUBLIC_FINGERPRINT),
						  true) ;
		return {0, std::unique_ptr<SignedIndexStore>{new SignedIndexStore{std::move( state)}}} ;
	} catch( const Failure &failure) {
		return {failure.error == 0 ? ERROR_INVALID_DATA : failure.error, {}} ;
	} catch( const std::bad_alloc &) {
		return {static_cast<NativeError>( E_OUTOFMEMORY), {}} ;
	} catch( ...) {
		return {static_cast<NativeError>( E_UNEXPECTED), {}} ;
	}
}

/** @see SignedIndexStore::State */
IndexStoreMigrationResult SignedIndexStore::State::migrateNamespace(
	const std::filesystem::path &parent, const std::string_view expectedHeadSha256,
	const std::optional<std::chrono::sys_seconds>		 nowUtc,
	const std::span<const signed_index_detail::TrustKey> migrationKeys,
	const bool											 isolated) noexcept
{
	try {
		require( nowUtc.has_value(), IndexStoreStatus::TIME_UNAVAILABLE, ERROR_INVALID_TIME) ;
		const auto legacy = parent / LEGACY_NAME ;	// 移行元は旧共用rootだけです。
		// 固定二公開集合だけを移行stateへ所有し、通常trustを変更しません。
		const auto makeState = [migrationKeys, isolated] {
			auto state			  = std::make_shared<State>() ;	// 呼出し中だけの固定/隔離trustです。
			state->migrationTrust = !isolated ;
			state->isolated		  = isolated ;
			// 移行専用の既知公開集合だけを所有copyします。
			for( const auto &key : migrationKeys) {
				state->keys.push_back(
					{std::string{key.keyId}, {key.rsaPublicBlob.begin(), key.rsaPublicBlob.end()}}) ;
			}

			return state ;
		} ;
		const DWORD attributes =
			// 旧reparseも存在扱いで後段拒否します。
			GetFileAttributesW( legacy.c_str()) ;
		// 旧rootがある間だけ実移動を行い、既存先を上書きしません。
		if( attributes != INVALID_FILE_ATTRIBUTES) {
			auto state		  = makeState() ;	// 通常stateへ移行鍵を渡しません。
			state->renameable = true ;
			state->initialize( legacy, !isolated, true, false) ;
			bool local{} ;	// 実署名認証後の用途だけで選択します。
			{
				const auto lease = state->lock() ;	// 分類中も旧writerを排除します。
				requireExpectedHead( state->protectedHead(), expectedHeadSha256) ;
				const auto verified = state->readHead() ;	// Unknown署名を分類へ通しません。
				require( verified.receipt.has_value(), IndexStoreStatus::STATE_REJECTED,
						ERROR_INVALID_DATA) ;
				local = verified.receipt->assetBytes().manifest().data().keyId ==
						index_legacy_migration_trust::KEY_ID ;
			}

			auto result = state->relocate(
				parent / domainName( local, index_legacy_migration_trust::PUBLIC_FINGERPRINT),
				expectedHeadSha256, nowUtc,
				signed_index_store_detail::Fault::NONE) ;	// 唯一のnamespace変更です。
			result.localDomain = local ;
			return result ;
		}

		const DWORD absentError = GetLastError() ;	// 欠損以外の照会不能を再実行成功にしません。
		require( absentError == ERROR_FILE_NOT_FOUND, IndexStoreStatus::PROTECTION_FAILURE,
				static_cast<NativeError>( absentError)) ;
		IndexStoreMigrationResult replay{
			.error = ERROR_FILE_NOT_FOUND} ;	// 正しい移動先が確認されるまで成功しません。
		// 有限二domainを検査し、既存の壊れた先やdomain違いも拒否します。
		for( const bool local : {false, true}) {
			const auto destination =
				parent /
				domainName( local,
						   index_legacy_migration_trust::PUBLIC_FINGERPRINT) ;	// 固定先だけです。
			const DWORD targetAttributes =
				// 任意root探索を行いません。
				GetFileAttributesW( destination.c_str()) ;
			// 存在しない先だけは次の固定domainへ進みます。
			if( targetAttributes == INVALID_FILE_ATTRIBUTES) {
				const DWORD targetError = GetLastError() ;	// 不存在以外は拒否します。
				require( targetError == ERROR_FILE_NOT_FOUND, IndexStoreStatus::PROTECTION_FAILURE,
						static_cast<NativeError>( targetError)) ;
				continue ;
			}

			auto state = makeState() ;	// 再実行はread-onlyでroot/lock/headを作成しません。
			state->initialize( destination, !isolated, true, false) ;
			const auto lease	= state->lock() ;		// 正規writerとの競合では待機せず拒否します。
			const auto verified = state->readHead() ;	// 現在期限と区別した履歴認証です。
			// 正常genesisは移動の証拠にせず、別domainの原head確認を続けます。
			if( !verified.receipt) {
				continue ;
			}

			require( (verified.receipt->assetBytes().manifest().data().keyId ==
					 index_legacy_migration_trust::KEY_ID) == local &&
						verified.receipt->assetBytes().manifest().data().publishedAtUtc <= *nowUtc,
					IndexStoreStatus::STATE_REJECTED, ERROR_INVALID_DATA) ;
			try {
				requireExpectedHead( state->protectedHead(), expectedHeadSha256) ;
			} catch( const Failure &failure) {
				// 別domainの正常なheadはpin一致の移動先と数えません。
				if( failure.status == IndexStoreStatus::STATE_REJECTED &&
				   failure.error == ERROR_INVALID_DATA) {
					continue ;
				}

				throw ;
			}

			require( !replay.alreadyMigrated, IndexStoreStatus::STATE_REJECTED,
					ERROR_ALREADY_EXISTS) ;
			replay = {.error		   = 0,
					  .generation	   = verified.wire.generation,
					  .localDomain	   = local,
					  .alreadyMigrated = true} ;
		}

		return replay ;
	} catch( const Failure &failure) {
		return {.error = failure.error == 0 ? ERROR_INVALID_DATA : failure.error} ;
	} catch( const std::bad_alloc &) {
		return {.error = static_cast<NativeError>( E_OUTOFMEMORY)} ;
	} catch( ...) {
		return {.error = static_cast<NativeError>( E_UNEXPECTED)} ;
	}
}

/** @see signed_index_store.h */
IndexStoreMigrationResult SignedIndexStore::migrateFixedLegacyStore(
	const std::string_view						  expectedHeadSha256,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	try {
		require( expectedHeadSha256.size() == 64U &&
					std::ranges::all_of( expectedHeadSha256,
										[]( const char value) {
											return (value >= '0' && value <= '9') ||
												   (value >= 'a' && value <= 'f') ;
										}),
				IndexStoreStatus::INVALID_INPUT, ERROR_INVALID_PARAMETER) ;
		require( nowUtc.has_value(), IndexStoreStatus::TIME_UNAVAILABLE, ERROR_INVALID_TIME) ;
		PWSTR		  raw{} ;	// KnownFolder所有の固定起点です。
		const HRESULT code = SHGetKnownFolderPath( FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr,
												  &raw) ;				// 任意path入力を受理しません。
		const std::unique_ptr<wchar_t, TaskMemoryCloser> owner{raw} ;	// 全経路で返します。
		require( SUCCEEDED( code) && raw != nullptr, IndexStoreStatus::PROTECTION_FAILURE,
				static_cast<NativeError>( code)) ;
		const auto parent = std::filesystem::path{raw} / L"DriverCrate" ;	// 同volumeの固定親です。
		const std::array<signed_index_detail::TrustKey, 2U> migrationKeys{
			{{index_distribution_trust::KEY_ID, index_distribution_trust::PUBLIC_BLOB},
			 {index_legacy_migration_trust::KEY_ID,
			  index_legacy_migration_trust::PUBLIC_BLOB}}} ;	// 通常trustへ登録しません。
		return State::migrateNamespace( parent, expectedHeadSha256, nowUtc, migrationKeys, false) ;
	} catch( const Failure &failure) {
		return {.error = failure.error == 0 ? ERROR_INVALID_DATA : failure.error} ;
	} catch( const std::bad_alloc &) {
		return {.error = static_cast<NativeError>( E_OUTOFMEMORY)} ;
	} catch( ...) {
		return {.error = static_cast<NativeError>( E_UNEXPECTED)} ;
	}
}

/** @see signed_index_store.h */
IndexStoreResult SignedIndexStore::reload(
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	std::optional<std::uint64_t> generation ;	// 実head再認証後だけ報告します。
	try {
		const auto lease	= state_->lock() ;		// Mutexなしで実I/Oのexclusive能力を保持します。
		auto	   verified = state_->readHead() ;	// 期限切れでも原入力を再認証します。
		generation			= verified.wire.generation ;
		IndexStoreResult result ;	// 現在期限と保存事実を独立して返します。
		result.persistedGeneration = generation ;
		// 正常genesisに索引候補はありません。
		if( !verified.receipt) {
			result.status = IndexStoreStatus::EMPTY_STORE ;
			return result ;
		}

		requireCurrentTime( verified.receipt->assetBytes().manifest().data(), nowUtc) ;
		result.snapshot = AuthenticatedIndexSnapshot{std::move( *verified.receipt),
													 std::move( verified.wire.envelope),
													 std::move( verified.wire.gzip)} ;
		result.status	= IndexStoreStatus::SNAPSHOT_READY ;
		return result ;
	} catch( const Failure &failure) {
		return failureResult( failure, IndexStoreCommitDisposition::NO_CHANGE, generation) ;
	} catch( const std::bad_alloc &) {
		return failureResult(
			{IndexStoreStatus::OUT_OF_MEMORY, static_cast<NativeError>( E_OUTOFMEMORY)},
			IndexStoreCommitDisposition::NO_CHANGE, generation) ;
	} catch( ...) {
		return failureResult(
			{IndexStoreStatus::STATE_REJECTED, static_cast<NativeError>( E_UNEXPECTED)},
			IndexStoreCommitDisposition::NO_CHANGE, generation) ;
	}
}

/** @see signed_index_store.h */
IndexStoreResult SignedIndexStore::commit(
	const IndexRecordsSchemaReceipt &receipt, const std::string_view envelope,
	const std::span<const std::byte>			  gzip,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	return commitImpl( receipt, envelope, gzip, nowUtc, signed_index_store_detail::Fault::NONE) ;
}

/** @see signed_index_store.h */
IndexStoreResult SignedIndexStore::commitImpl( const IndexRecordsSchemaReceipt &receipt,
											  const std::string_view		   envelope,
											  const std::span<const std::byte> gzip,
											  const std::optional<std::chrono::sys_seconds> nowUtc,
											  const signed_index_store_detail::Fault fault) noexcept
{
	using signed_index_store_detail::Fault ;
	IndexStoreCommitDisposition disposition =
		IndexStoreCommitDisposition::NO_CHANGE ;	// Commit点前の初期区分です。
	std::optional<std::uint64_t> generation ;		// 最新headからだけ取得します。
	try {
		require( fault >= Fault::NONE && fault <= Fault::AFTER_COMMIT_ALLOCATION &&
					(state_->isolated || fault == Fault::NONE),
				IndexStoreStatus::INVALID_INPUT) ;
		const auto lease	= state_->lock() ;		// 全比較と一head切替を実exclusive能力へ結合します。
		auto	   previous = state_->readHead() ;	// Callerの古いscalarを最大世代へ使いません。
		generation			= previous.wire.generation ;
		const auto &data	= receipt.assetBytes().manifest().data() ;	// 保存前の原receiptです。
		require( !data.manifestBytes.empty() && !data.repository.empty() && !data.channel.empty() &&
					!data.keyId.empty() && !data.asset.tag.empty() && !data.asset.name.empty() &&
					!receipt.assetBytes().expandedBytes().empty() && !envelope.empty() &&
					envelope.size() <= INDEX_ENVELOPE_MAX_BYTES && !gzip.empty() &&
					gzip.size() <= INDEX_ASSET_MAX_BYTES,
				IndexStoreStatus::INVALID_INPUT) ;
		requireCurrentTime( data, nowUtc) ;
		std::optional<IndexManifestHighWater> highWater ;	// 最新保護state以外から構成しません。
		// Genesisの0を既存manifest highwater APIへ流し込みません。
		if( previous.wire.generation != 0U) {
			highWater =
				IndexManifestHighWater{previous.wire.generation, previous.wire.manifestHash} ;
		}

		Wire candidate ;	// 原入力は一headへ所有copyし、commit後に未確保としません。
		candidate.generation = data.generation ;
		candidate.publishedSeconds =
			static_cast<std::uint64_t>( data.publishedAtUtc.time_since_epoch().count()) ;
		candidate.manifestHash = data.manifestSha256 ;
		candidate.indexHash	   = receipt.indexSha256() ;
		candidate.envelope.assign( envelope) ;
		candidate.gzip.assign( gzip.begin(), gzip.end()) ;
		auto verified = state_->verify( std::move( candidate), nowUtc,
									   highWater) ;	// 全原byteを実verifierへ通します。
		// 同世代の同原manifest／固定assetはheadを変えず保存済み値だけ再利用します。
		if( verified.wire.generation == previous.wire.generation) {
			require( verified.wire.manifestHash == previous.wire.manifestHash &&
						verified.wire.indexHash == previous.wire.indexHash &&
						verified.wire.gzip == previous.wire.gzip,
					IndexStoreStatus::STATE_REJECTED) ;
			requireCurrentTime( previous.receipt->assetBytes().manifest().data(), nowUtc) ;
			IndexStoreResult result ;	// 再利用を新commitと数えません。
			result.status			   = IndexStoreStatus::SNAPSHOT_READY ;
			result.persistedGeneration = generation ;
			result.snapshot			   = AuthenticatedIndexSnapshot{std::move( *previous.receipt),
															std::move( previous.wire.envelope),
															std::move( previous.wire.gzip)} ;
			return result ;
		}

		require( fault != Fault::BEFORE_PROTECT, IndexStoreStatus::PROTECTION_FAILURE,
				ERROR_INVALID_DATA) ;
		const auto plain = encodeWire( verified.wire) ;	// 原cacheと最大世代を同じplainへ結合します。
		const auto protectedBytes =
			// 実DPAPI成功後だけstagingへ書きます。
			state_->dpapi( plain, true) ;
		state_->replaceHead( protectedBytes, fault, disposition) ;
		// Commit成功後の最大世代はすでにadvanceしています。
		generation = verified.wire.generation ;
		require( fault != Fault::AFTER_REPLACE && fault != Fault::READBACK,
				IndexStoreStatus::IO_FAILURE, ERROR_READ_FAULT) ;
		// Commit後の確保失敗を旧head保持と誤報しない診断です。
		if( fault == Fault::AFTER_COMMIT_ALLOCATION) {
			throw std::bad_alloc{} ;
		}

		auto persisted = state_->readHead() ;	// 実diskのenvelope／gzip／全schemaを再認証します。
		require( persisted.wire.generation == verified.wire.generation &&
					persisted.wire.manifestHash == verified.wire.manifestHash &&
					persisted.wire.envelope == verified.wire.envelope &&
					persisted.wire.gzip == verified.wire.gzip,
				IndexStoreStatus::STATE_REJECTED) ;
		requireCurrentTime( persisted.receipt->assetBytes().manifest().data(), nowUtc) ;
		IndexStoreResult result ;	// Save成功とsnapshot発行は全readback後だけです。
		result.status			   = IndexStoreStatus::SNAPSHOT_READY ;
		result.commit			   = disposition ;
		result.persistedGeneration = generation ;
		result.snapshot			   = AuthenticatedIndexSnapshot{std::move( *persisted.receipt),
														std::move( persisted.wire.envelope),
														std::move( persisted.wire.gzip)} ;
		return result ;
	} catch( const Failure &failure) {
		return failureResult( failure, disposition, generation) ;
	} catch( const std::bad_alloc &) {
		return failureResult(
			{IndexStoreStatus::OUT_OF_MEMORY, static_cast<NativeError>( E_OUTOFMEMORY)}, disposition,
			generation) ;
	} catch( ...) {
		return failureResult(
			{IndexStoreStatus::STATE_REJECTED, static_cast<NativeError>( E_UNEXPECTED)}, disposition,
			generation) ;
	}
}

namespace signed_index_store_detail {

/** @see signed_index_store_internal.h */
TestLock::TestLock( const HANDLE handle) noexcept : handle_( handle)
{
}
/** @see signed_index_store_internal.h */
TestLock::~TestLock() noexcept
{
	CloseHandle( handle_) ;
}

/** @see signed_index_store_internal.h */
IndexStoreOpenResult Access::openNamespaceIsolated(
	const SignedIndexStore &parent, const NamespaceLeaf leaf,
	const std::span<const signed_index_detail::TrustKey> trust, const bool createMissing) noexcept
{
	try {
		require( parent.state_->isolated && trust.size() <= 8U && leaf >= NamespaceLeaf::LEGACY &&
					leaf <= NamespaceLeaf::DISTRIBUTION,
				IndexStoreStatus::INVALID_INPUT, ERROR_ACCESS_DENIED) ;
		auto state = std::make_shared<SignedIndexStore::State>() ;	// 自作parentに寿命を結合します。
		state->isolated	 = true ;
		state->rootOwner = parent.state_ ;
		// 有限RAM公開集合だけをcopyします。
		for( const auto &key : trust) {
			state->keys.push_back(
				{std::string{key.keyId}, {key.rsaPublicBlob.begin(), key.rsaPublicBlob.end()}}) ;
		}

		const auto name =
			leaf == NamespaceLeaf::LEGACY
				? std::wstring{LEGACY_NAME}
				: domainName(
					  leaf == NamespaceLeaf::LOCAL,
					  index_legacy_migration_trust::PUBLIC_FINGERPRINT) ;	// 固定三leafだけです。
		// 通常の二domainは旧rootの存在中に初回へ進めません。
		if( leaf != NamespaceLeaf::LEGACY) {
			state->legacyGuard = parent.state_->root / LEGACY_NAME ;
			requireLegacyAbsent( state->legacyGuard) ;
		}

		state->initialize( parent.state_->root / name, false, true, createMissing) ;
		return {0, std::unique_ptr<SignedIndexStore>{new SignedIndexStore{std::move( state)}}} ;
	} catch( const Failure &failure) {
		return {failure.error == 0 ? ERROR_INVALID_DATA : failure.error, {}} ;
	} catch( const std::bad_alloc &) {
		return {static_cast<NativeError>( E_OUTOFMEMORY), {}} ;
	} catch( ...) {
		return {static_cast<NativeError>( E_UNEXPECTED), {}} ;
	}
}

/** @see signed_index_store_internal.h */
IndexStoreMigrationResult Access::migrateNamespaceIsolated(
	SignedIndexStore &store, const std::string_view expectedHeadSha256,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	try {
		auto old = store.state_ ;	// 所有cleanupとsandboxの寿命を保持します。
		require( old->isolated && old->rootOwner && old->rootOwner->isolated &&
					old->root.parent_path() == old->rootOwner->root,
				IndexStoreStatus::INVALID_INPUT, ERROR_ACCESS_DENIED) ;
		std::vector<signed_index_detail::TrustKey> keys ;	// 呼出し中だけ所有公開集合を借用します。
		// 通常と同じ分類実装へ人工RAM materialだけを渡します。
		for( const auto &key : old->keys) {
			keys.push_back( {key.keyId, key.blob}) ;
		}

		old->directories.clear() ;
		auto result = SignedIndexStore::State::migrateNamespace(
			old->rootOwner->root, expectedHeadSha256, nowUtc, keys,
			true) ;	// 固定製品と同じnamespace実装です。
		const auto path =
			result.commit == IndexStoreCommitDisposition::COMMITTED || result.alreadyMigrated
				? old->rootOwner->root /
					  domainName( result.localDomain,
								 index_legacy_migration_trust::PUBLIC_FINGERPRINT)
				: old->root ;	// 原子結果の確定値だけを使います。
		auto reopened =
			std::make_shared<SignedIndexStore::State>() ;	// Cleanup能力を新しいhandleへ結合します。
		reopened->isolated	= true ;
		reopened->keys		= old->keys ;
		reopened->rootOwner = old->rootOwner ;
		reopened->initialize( path, false, true, false) ;
		reopened->ownsIsolatedRoot = old->ownsIsolatedRoot ;
		old->ownsIsolatedRoot	   = false ;
		store.state_			   = std::move( reopened) ;
		return result ;
	} catch( const Failure &failure) {
		return {.error = failure.error == 0 ? ERROR_INVALID_DATA : failure.error} ;
	} catch( const std::bad_alloc &) {
		return {.error = static_cast<NativeError>( E_OUTOFMEMORY)} ;
	} catch( ...) {
		return {.error = static_cast<NativeError>( E_UNEXPECTED)} ;
	}
}

/** @see signed_index_store_internal.h */
IndexStoreOpenResult Access::createIsolated(
	const std::span<const signed_index_detail::TrustKey> trust, const bool migration) noexcept
{
	try {
		require( trust.size() <= 8U, IndexStoreStatus::INVALID_INPUT, ERROR_INVALID_PARAMETER) ;
		auto state =
			std::make_shared<SignedIndexStore::State>() ;	// 本番stateを渡すAPIはありません。
		state->isolated	  = true ;
		state->renameable = migration ;
		// Unit RAM public blobの有限copyだけを所有します。
		for( const auto &key : trust) {
			require( key.keyId.size() <= 64U && key.rsaPublicBlob.size() <= 1024U,
					IndexStoreStatus::INVALID_INPUT, ERROR_INVALID_PARAMETER) ;
			state->keys.push_back(
				{std::string{key.keyId}, {key.rsaPublicBlob.begin(), key.rsaPublicBlob.end()}}) ;
		}

		std::array<wchar_t, 32768U> temporary{} ;	// Caller指定pathを受理しないOS temp基点です。
		const DWORD					length = GetTempPathW( static_cast<DWORD>( temporary.size()),
														  // 有限API pathです。
														  temporary.data()) ;
		require( length > 0U && length < temporary.size(), IndexStoreStatus::IO_FAILURE,
				static_cast<NativeError>( GetLastError())) ;
		std::array<std::uint8_t, 16U> random{} ;	// 一意なfixture名だけに使う非秘密乱数です。
		const NTSTATUS				  status =
			BCryptGenRandom( nullptr, random.data(), static_cast<ULONG>( random.size()),
							BCRYPT_USE_SYSTEM_PREFERRED_RNG) ;	// 別processとの名衝突を避けます。
		require( status >= 0, IndexStoreStatus::PROTECTION_FAILURE,
				static_cast<NativeError>( HRESULT_FROM_NT( status))) ;
		constexpr std::wstring_view HEX = L"0123456789abcdef" ;	// 固定名へ限定するhex表です。
		std::wstring name = L"drivercrate-index-fixture-" ;		// 自作fixtureだけの専用prefixです。
		// 有限16byteを一意なASCII名へ変換します。
		for( const auto value : random) {
			name.push_back( HEX[value >> 4U]) ;
			name.push_back( HEX[value & 15U]) ;
		}

		state->initialize( std::filesystem::path{temporary.data()} / name, false, false) ;
		return {0, std::unique_ptr<SignedIndexStore>{new SignedIndexStore{std::move( state)}}} ;
	} catch( const Failure &failure) {
		return {failure.error == 0 ? ERROR_INVALID_DATA : failure.error, {}} ;
	} catch( const std::bad_alloc &) {
		return {static_cast<NativeError>( E_OUTOFMEMORY), {}} ;
	} catch( ...) {
		return {static_cast<NativeError>( E_UNEXPECTED), {}} ;
	}
}

/** @see signed_index_store_internal.h */
IndexStoreMigrationResult Access::migrateIsolated(
	SignedIndexStore &store, const std::string_view expectedHeadSha256,
	const std::optional<std::chrono::sys_seconds> nowUtc, const Fault fault) noexcept
{
	try {
		require( store.state_->isolated && store.state_->renameable &&
					(fault == Fault::NONE || fault == Fault::BEFORE_REPLACE ||
					 fault == Fault::AFTER_REPLACE),
				IndexStoreStatus::INVALID_INPUT, ERROR_ACCESS_DENIED) ;
		// 移動後の同じ自作rootだけで、原pinと全履歴を再認証します。
		if( store.state_->root.filename().native().ends_with( L"-migrated")) {
			const auto lease = store.state_->lock() ;	// 再実行も実lockへ結合します。
			requireExpectedHead( store.state_->protectedHead(), expectedHeadSha256) ;
			const auto verified = store.state_->readHead() ;	// 現在期限へ昇格しない実署名認証です。
			require( verified.receipt && nowUtc &&
						verified.receipt->assetBytes().manifest().data().publishedAtUtc <= *nowUtc,
					IndexStoreStatus::STATE_REJECTED, ERROR_INVALID_DATA) ;
			return {.generation = verified.wire.generation, .alreadyMigrated = true} ;
		}

		return store.state_->relocate( store.state_->root.parent_path() /
										  (store.state_->root.filename().native() + L"-migrated"),
									  expectedHeadSha256, nowUtc, fault) ;
	} catch( const Failure &failure) {
		return {.error = failure.error == 0 ? ERROR_INVALID_DATA : failure.error} ;
	} catch( const std::bad_alloc &) {
		return {.error = static_cast<NativeError>( E_OUTOFMEMORY)} ;
	} catch( ...) {
		return {.error = static_cast<NativeError>( E_UNEXPECTED)} ;
	}
}

/** @see signed_index_store_internal.h */
IndexStoreOpenResult Access::reopenIsolated( const SignedIndexStore &store) noexcept
{
	// 任意path・製品storeの診断能力を発行しません。
	if( !store.state_->isolated) {
		return {ERROR_ACCESS_DENIED, {}} ;
	}

	try {
		auto state =
			std::make_shared<SignedIndexStore::State>() ;	// 別の実handleとentropyを初期化します。
		state->isolated	 = true ;
		state->keys		 = store.state_->keys ;
		state->rootOwner = store.state_ ;
		// 既存rootのlock／headを作り直しません。
		state->initialize( store.state_->root, false) ;
		return {0, std::unique_ptr<SignedIndexStore>{new SignedIndexStore{std::move( state)}}} ;
	} catch( const Failure &failure) {
		return {failure.error == 0 ? ERROR_INVALID_DATA : failure.error, {}} ;
	} catch( const std::bad_alloc &) {
		return {static_cast<NativeError>( E_OUTOFMEMORY), {}} ;
	} catch( ...) {
		return {static_cast<NativeError>( E_UNEXPECTED), {}} ;
	}
}

/** @see signed_index_store_internal.h */
std::filesystem::path Access::isolatedRoot( const SignedIndexStore &store)
{
	return store.state_->isolated ? store.state_->root : std::filesystem::path{} ;
}

/** @see signed_index_store_internal.h */
std::wstring Access::protectionSddl( const SignedIndexStore &store, const bool directory,
									const bool product)
{
	// 実製品storeのidentityをtestへ開示しません。
	if( !store.state_->isolated) {
		return {} ;
	}

	LPWSTR raw{} ;	// OSが返すprocess SIDのRAM表現です。
	requireApi( ConvertSidToStringSidW( store.state_->userSid(), &raw),
			   IndexStoreStatus::PROTECTION_FAILURE) ;
	const LocalMemory owner{raw} ;	// RAM表現をscopeで返します。
	return drivercrate::protectionSddl( raw, directory, !product) ;
}

/** @see signed_index_store_internal.h */
bool Access::acceptsProtectionSddl( const SignedIndexStore &store, const std::wstring_view sddl,
								   const bool directory, const bool product) noexcept
{
	// TestはRAMだけを検査し、製品rootやfileを変更しません。
	if( !store.state_->isolated) {
		return false ;
	}

	try {
		const std::wstring	 terminated{sddl} ;	// OS APIへ有限の終端文字列を渡します。
		PSECURITY_DESCRIPTOR raw{} ;			// OSが生成するRAM descriptorです。
		// 不正SDDLからprofileを推測しません。
		if( !ConvertStringSecurityDescriptorToSecurityDescriptorW( terminated.c_str(),
																 SDDL_REVISION_1, &raw, nullptr)) {
			return false ;
		}

		const LocalMemory owner{raw} ;	// 生成descriptorをscopeで返します。
		return allowedDescriptor( raw, store.state_->userSid(), directory, !product) ;
	} catch( ...) {
		// RAM検査の確保不能を許可へ変えません。
		return false ;
	}
}

/** @see signed_index_store_internal.h */
IndexStoreResult Access::commitWithFault( SignedIndexStore							  &store,
										 const IndexRecordsSchemaReceipt			  &receipt,
										 const std::string_view						   envelope,
										 const std::span<const std::byte>			   gzip,
										 const std::optional<std::chrono::sys_seconds> nowUtc,
										 const Fault fault) noexcept
{
	// 本番storeへtest faultを持ち込みません。
	if( !store.state_->isolated) {
		return failureResult( {IndexStoreStatus::INVALID_INPUT, ERROR_ACCESS_DENIED},
							 IndexStoreCommitDisposition::NO_CHANGE, {}) ;
	}

	return store.commitImpl( receipt, envelope, gzip, nowUtc, fault) ;
}

/** @see signed_index_store_internal.h */
std::unique_ptr<TestLock> Access::holdLock( const SignedIndexStore &store)
{
	// 隔離能力がない場合は実lock pathへ触りません。
	if( !store.state_->isolated) {
		return {} ;
	}

	try {
		auto lease	= store.state_->lock() ;	// 競合も実share0のOS境界を使います。
		auto result = std::unique_ptr<TestLock>{
			new TestLock{lease.get()}} ;	// 確保成功まで元ownerを維持します。
		static_cast<void>( lease.release()) ;
		return result ;
	} catch( const Failure &) {
		return {} ;
	}
}

/** @see signed_index_store_internal.h */
NativeError Access::readPlain( const SignedIndexStore &store, std::vector<std::byte> &plain)
{
	plain.clear() ;
	// 本番rootのplainをtestへ開示しません。
	if( !store.state_->isolated) {
		return ERROR_ACCESS_DENIED ;
	}

	try {
		const auto lease = store.state_->lock() ;	// Testの診断も実lockへ結合します。
		const auto file	 = store.state_->openFile( L"head.bin", GENERIC_READ, FILE_SHARE_READ,
												  OPEN_EXISTING) ;				// 同じhandleを検査します。
		const auto bytes = store.state_->readFile( file.get(), MAX_PROTECTED) ;	// 実disk byteです。
		plain			 = store.state_->dpapi( bytes, false) ;
		return 0 ;
	} catch( const Failure &failure) {
		return failure.error == 0 ? ERROR_INVALID_DATA : failure.error ;
	}
}

/** @see signed_index_store_internal.h */
NativeError Access::replacePlain( const SignedIndexStore			 &store,
								 const std::span<const std::byte> plain)
{
	// Testが作った破損wireも製品rootへは書きません。
	if( !store.state_->isolated) {
		return ERROR_ACCESS_DENIED ;
	}

	try {
		const auto lease = store.state_->lock() ;				// 通常と同じ実排他です。
		const auto bytes = store.state_->dpapi( plain, true) ;	// DPAPIをfakeに置換しません。
		IndexStoreCommitDisposition disposition{} ;				// 一head切替の実結果です。
		store.state_->replaceHead( bytes, Fault::NONE, disposition) ;
		return 0 ;
	} catch( const Failure &failure) {
		return failure.error == 0 ? ERROR_INVALID_DATA : failure.error ;
	}
}

} // namespace signed_index_store_detail
} // namespace drivercrate
