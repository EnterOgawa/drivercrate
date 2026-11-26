//------------------------------------------------------------------------------
/**
 * @file mtd_shared_file_internal.cpp
 * @brief MTD共有DLLの保護対象を固定し非置換で配置します
 * @version 01.01.00
 * @date 2026/11/16
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/16  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/17  既存祖先と配置親の権限を役割別に照合
 * </pre>
 *
 * @note 原INFとSYSを変更せず、queueとDIFは呼出し側で実行します
 */
//------------------------------------------------------------------------------
#include "platform/mtd_shared_file_internal.h"
#include "platform/driver_store_inf_transport_internal.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"

#include <Windows.h>
#include <bcrypt.h>
#include <sddl.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>
#include <string>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {
using driver_store_inf_detail::MtdTransport ;

//------------------------------------------------------------------------------
/**
 * @brief 元Windows errorをHRESULTとして保持します
 * @param[in] value 直前のWindows errorです
 * @return 非零診断を持つHRESULTです
 */
//------------------------------------------------------------------------------
NativeError mtdError( DWORD value) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( value ? value : ERROR_INVALID_DATA)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同長の完全pathをWindows ordinal規則で比較します
 * @param[in] left 一方の完全値です
 * @param[in] right 他方の完全値です
 * @return 全文字が大小文字以外一致する場合trueです
 */
//------------------------------------------------------------------------------
bool mtdSame( std::wstring_view left, std::wstring_view right) noexcept
{
	return left.size() == right.size() && left.size() <= 32767U &&
		   CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

/** @brief 同API表から開いた一handleだけを単独所有します */
class MtdHandle final {
public:
	/**
	 * @brief 空のhandleを作ります
	 * @param[in] api 同operation中有効な低位表です
	 */
	explicit MtdHandle( const MtdTransport &api) noexcept : api_( &api)
	{
	}
	/**
	 * @brief 同表で開いたhandleだけを閉じます
	 */
	~MtdHandle() noexcept
	{
		reset() ;
	}
	/**
	 * @brief 一handleの所有を移します
	 * @param[in,out] other 同表の移動元です
	 */
	MtdHandle( MtdHandle &&other) noexcept
		: api_( other.api_), value_( std::exchange( other.value_, INVALID_HANDLE_VALUE))
	{
	}
	/**
	 * @brief 同表の一handleだけを移動代入します
	 * @param[in,out] other 同表の移動元です
	 * @return 更新後の自身です
	 */
	MtdHandle &operator=( MtdHandle &&other) noexcept
	{
		// 自己移動で保持中のhandleを閉じないよう区別します
		if( this != &other) {
			reset() ;
			api_   = other.api_ ;
			value_ = std::exchange( other.value_, INVALID_HANDLE_VALUE) ;
		}

		return *this ;
	}
	/**
	 * @brief handleの複製を禁止します
	 * @param[in] other 複製できない所有元です
	 */
	MtdHandle( const MtdHandle &other) = delete ;
	/**
	 * @brief handleの複製代入を禁止します
	 * @param[in] other 複製できない所有元です
	 */
	MtdHandle &operator=( const MtdHandle &other) = delete ;
	/**
	 * @brief 古い所有を閉じて新しいhandleを保持します
	 * @param[in] next 同表が返したhandleです
	 */
	void	   reset( HANDLE next = INVALID_HANDLE_VALUE) noexcept
	{
		// 有効な同表handleだけを閉じます
		if( valid()) {
			api_->closeHandle( value_) ;
		}

		value_ = next ;
	}
	/**
	 * @brief 保持中の借用handleを返します
	 * @return 同所有期間だけ有効なhandleです
	 */
	[[nodiscard]] HANDLE get() const noexcept
	{
		return value_ ;
	}
	/**
	 * @brief 有効なhandleかを確認します
	 * @return nullとINVALID_HANDLE_VALUE以外ならtrueです
	 */
	[[nodiscard]] bool valid() const noexcept
	{
		return value_ && value_ != INVALID_HANDLE_VALUE ;
	}

private:
	/// 同handleの解放に使う低位API表です
	const MtdTransport *api_{} ;
	/// このownerが保持するWindows handleです
	HANDLE				value_{INVALID_HANDLE_VALUE} ;
} ;

/** @brief 元volumeと128bit file IDを含む固定観測です */
struct MtdIdentity {
	/// 原属性・link数とsizeです
	BY_HANDLE_FILE_INFORMATION standard{} ;
	/// 同handleから読んだvolumeと128bit file IDです
	FILE_ID_INFO			   identifier{} ;
	/// 同handleのownerとDACLを含む原security descriptorです
	std::vector<std::byte>	   security ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同handleの通常属性と安定file IDを確認します
 * @param[in] api 同workerの完全低位表です
 * @param[in] file 変更非共有で開いた元handleです
 * @param[in] directory directoryの型を要求する場合trueです
 * @param[out] info 成功時だけの元情報です
 * @return 型とfile ID成立0、失敗は元HRESULTです
 */
//------------------------------------------------------------------------------
NativeError mtdInfo( const MtdTransport &api, HANDLE file, bool directory, MtdIdentity &info)
{
	info = {} ;
	// 属性かfile IDを取得できない場合は元Windows errorを返します
	if( !api.fileInfo( file, &info.standard) ||
	   !api.fileInfoEx( file, FileIdInfo, &info.identifier, sizeof( info.identifier))) {
		return mtdError( GetLastError()) ;
	}

	// reparse、種別不一致、複数linkを保持対象から除外します
	if( (info.standard.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U ||
	   ((info.standard.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) != directory ||
	   (!directory && info.standard.nNumberOfLinks != 1U) ||
	   std::ranges::all_of( info.identifier.FileId.Identifier,
						   []( BYTE value) { return value == 0U ; })) {
		return mtdError( ERROR_ACCESS_DENIED) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 独立取得した二つのfile IDを比較します
 * @param[in] left 最初に固定した元情報です
 * @param[in] right 再読取した元情報です
 * @return volumeとfile IDが一致する場合trueです
 */
//------------------------------------------------------------------------------
bool mtdSameFile( const MtdIdentity &left, const MtdIdentity &right) noexcept
{
	return left.identifier.VolumeSerialNumber == right.identifier.VolumeSerialNumber &&
		   std::ranges::equal( left.identifier.FileId.Identifier,
							  right.identifier.FileId.Identifier) &&
		   left.standard.nFileIndexHigh == right.standard.nFileIndexHigh &&
		   left.standard.nFileIndexLow == right.standard.nFileIndexLow ;
}

//------------------------------------------------------------------------------
/**
 * @brief handleの最終DOS pathを原完全pathへ比較します
 * @param[in] api 同workerの完全低位表です
 * @param[in] file 同期借用するhandleです
 * @param[in] expected 原正規DOS pathです
 * @return 同じpathなら0、不一致や元API失敗はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError mtdPath( const MtdTransport &api, HANDLE file, std::wstring_view expected)
{
	// 最終DOS pathを受け取る有限bufferです
	std::vector<wchar_t> buffer( 32768U) ;
	// 同handleから返ったpath長です
	const auto length = api.finalPath( file, buffer.data(), static_cast<DWORD>( buffer.size()),
									  FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;
	// 最終pathが取得できないか容量外なら一致判定を行いません
	if( !length || length >= buffer.size()) {
		return mtdError( length ? ERROR_FILENAME_EXCED_RANGE : GetLastError()) ;
	}

	// 取得したDOS pathの借用viewです
	std::wstring_view path{buffer.data(), length} ;
	// WindowsのDOS path接頭辞を比較前に除きます
	if( path.starts_with( L"\\\\?\\")) {
		path.remove_prefix( 4U) ;
	}

	// root以外の末尾separatorを観測pathから除きます
	while( path.size() > 3U && path.back() == L'\\') {
		path.remove_suffix( 1U) ;
	}

	// 比較対象の末尾separatorも同じ規則で除きます
	while( expected.size() > 3U && expected.back() == L'\\') {
		expected.remove_suffix( 1U) ;
	}

	return mtdSame( path, expected) ? 0U : mtdError( ERROR_RETRY) ;
}

//------------------------------------------------------------------------------
/**
 * @brief fileのownerと全DACLから非保守主体の変更権限を拒否します
 * @param[in] api 同workerの完全低位表です
 * @param[in] file 同期借用するfile又はdirectory handleです
 * @param[in] directory 子への継承も検査する場合trueです
 * @param[out] original 全成立時の完全なsecurity descriptorです
 * @param[in] ancestor 固定済み既存childへ進むdirectoryの場合だけtrueです
 * @param[in] requireProtected 前祖先の限定許可からDACL保護が必要な場合trueです
 * @param[out] protectNext 非nullの場合、次の既存childにDACL保護が必要かを返します
 * @return 保護成立0、未知ACE/owner又は元API errorはHRESULTです
 */
//------------------------------------------------------------------------------
NativeError mtdSecurity( const MtdTransport &api, HANDLE file, bool directory,
						std::vector<std::byte> &original, bool ancestor = false,
						bool requireProtected = false, bool *protectNext = nullptr)
{
	original.clear() ;
	// 次child条件の出力がある場合は未確認から始めます
	if( protectNext) {
		*protectNext = false ;
	}

	// fileを祖先扱いにせず、次のchild保護を検査できない限定許可を拒否します
	if( (ancestor && (!directory || !protectNext)) || (requireProtected && !directory)) {
		return mtdError( ERROR_INVALID_PARAMETER) ;
	}

	// 同fileの元owner SIDです
	PSID				 owner{} ;
	// 同fileの元DACLです
	PACL				 acl{} ;
	// 元ownerとDACLを含む所有descriptorです
	PSECURITY_DESCRIPTOR descriptor{} ;
	// security情報の原Windows応答です
	const DWORD			 error = api.securityInfo( file, SE_FILE_OBJECT,
												  OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
												  &owner, nullptr, &acl, nullptr, &descriptor) ;
	// ownerとDACLの取得失敗を不在に変換しません
	if( error != ERROR_SUCCESS) {
		return mtdError( error) ;
	}

	/** @brief 元APIが返したdescriptorの所有です */
	struct Descriptor final {
		/// 同workerの低位API表です
		const MtdTransport	&api ;
		/// 所有するsecurity descriptorです
		PSECURITY_DESCRIPTOR value ;
		/**
		 * @brief 所有descriptorだけを解放します
		 */
		~Descriptor()
		{
			// 返されたdescriptorだけを同API表で解放します
			if( value) {
				api.localFree( value) ;
			}
		}
	} holder{api, descriptor} ;
	// descriptorの制御flagsです
	SECURITY_DESCRIPTOR_CONTROL control{} ;
	// descriptor制御flagsのrevisionです
	DWORD						revision{} ;
	// 不正なdescriptor、owner、ACLを保護済みとみなしません
	if( !descriptor || !IsValidSecurityDescriptor( descriptor) ||
	   !GetSecurityDescriptorControl( descriptor, &control, &revision) ||
	   (control & SE_SELF_RELATIVE) == 0U || !owner || !IsValidSid( owner) || !acl ||
	   !IsValidAcl( acl) || acl->AceCount > 256U) {
		return mtdError( ERROR_INVALID_SECURITY_DESCR) ;
	}

	// 祖先に限定許可がある場合、実在する次のchildのDACL保護を必須にします
	if( requireProtected && (control & SE_DACL_PROTECTED) == 0U) {
		return mtdError( ERROR_ACCESS_DENIED) ;
	}

	// AdministratorsのSID bufferです
	std::array<BYTE, SECURITY_MAX_SID_SIZE> admin{} ;
	// SYSTEMのSID bufferです
	std::array<BYTE, SECURITY_MAX_SID_SIZE> system{} ;
	// CREATOR_OWNERのSID bufferです
	std::array<BYTE, SECURITY_MAX_SID_SIZE> creatorOwner{} ;
	// Administrators SID bufferの容量です
	DWORD									adminSize = static_cast<DWORD>( admin.size()) ;
	// SYSTEM SID bufferの容量です
	DWORD									systemSize = static_cast<DWORD>( system.size()) ;
	// CREATOR_OWNER SID bufferの容量です
	DWORD									creatorSize = static_cast<DWORD>( creatorOwner.size()) ;
	// TrustedInstaller SIDの元allocationです
	PSID									installer{} ;
	// 許可信頼主体を構成できなければ保護判定を中止します
	if( !CreateWellKnownSid( WinBuiltinAdministratorsSid, nullptr, admin.data(), &adminSize) ||
	   !CreateWellKnownSid( WinLocalSystemSid, nullptr, system.data(), &systemSize) ||
	   !CreateWellKnownSid( WinCreatorOwnerSid, nullptr, creatorOwner.data(), &creatorSize) ||
	   !ConvertStringSidToSidW( L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
							   &installer)) {
		return mtdError( GetLastError()) ;
	}

	// TrustedInstaller SID allocationの所有です
	const std::unique_ptr<void, decltype( &::LocalFree)> ownedInstaller{installer, &::LocalFree} ;
	// 書込みを許容するownerとACE主体の判定です
	const auto											trusted = [&]( PSID sid) {
		 return sid && IsValidSid( sid) &&
				(EqualSid( sid, admin.data()) || EqualSid( sid, system.data()) ||
				 EqualSid( sid, ownedInstaller.get())) ;
	} ;
	// ownerが許可信頼主体以外の場合は変更前に拒否します
	if( !trusted( owner)) {
		return mtdError( ERROR_INVALID_OWNER) ;
	}

	// generic権限をfile権限へ写す対応です
	GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE,
							FILE_ALL_ACCESS} ;
	// 非信頼主体に許さない書込み系maskです
	constexpr DWORD writes = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
							 FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD | DELETE | WRITE_DAC |
							 WRITE_OWNER ;
	// 全ACEを検査し一部だけで保護を認定しません
	for( DWORD index = 0U; index < acl->AceCount; ++index) {
		void *raw{} ;
		// ACE取得に失敗した場合は元診断を返します
		if( !GetAce( acl, index, &raw)) {
			return mtdError( GetLastError()) ;
		}

		// 現在ACEの共通headerです
		const auto header = static_cast<const ACE_HEADER *>( raw) ;
		// 未知ACE型や不正な長さ・継承flagsを拒否します
		if( !header ||
		   (header->AceType != ACCESS_ALLOWED_ACE_TYPE &&
			header->AceType != ACCESS_DENIED_ACE_TYPE) ||
		   header->AceSize < offsetof( ACCESS_ALLOWED_ACE, SidStart) + 8U ||
		   (header->AceFlags & ~(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE |
								 NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE | INHERITED_ACE)) !=
			   0U) {
			return mtdError( ERROR_ACCESS_DENIED) ;
		}

		// 検査対象ACEのmaskとSID領域です
		const auto ace = static_cast<const ACCESS_ALLOWED_ACE *>( raw) ;
		// 同ACE内のSID先頭です
		auto	   sid = const_cast<DWORD *>( &ace->SidStart) ;
		// ACE内でSIDに使える残りbyteです
		const auto available = header->AceSize - offsetof( ACCESS_ALLOWED_ACE, SidStart) ;
		// SID領域の長さと実体が一致しないACEを拒否します
		if( available < 8U ||
		   reinterpret_cast<const SID *>( sid)->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES ||
		   8U + 4U * reinterpret_cast<const SID *>( sid)->SubAuthorityCount != available ||
		   !IsValidSid( sid) || GetLengthSid( sid) != available) {
			return mtdError( ERROR_ACCESS_DENIED) ;
		}

		// generic権限を展開するACE maskです
		DWORD mask = ace->Mask ;
		MapGenericMask( &mask, &mapping) ;
		// 同ACEが現在objectに適用され得るかです
		const bool applies =
			(header->AceFlags & INHERIT_ONLY_ACE) == 0U ||
			(directory && (header->AceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)) != 0U) ;
		// CREATOR_OWNERは同新規fileのownerを別途検査する場合だけ継承上のplaceholderです
		const bool creator = directory && (header->AceFlags & INHERIT_ONLY_ACE) != 0U &&
							 EqualSid( sid, creatorOwner.data()) ;
		// 未知maskは継承専用でも受理しません
		if( (mask & ~FILE_ALL_ACCESS) != 0U) {
			return mtdError( ERROR_ACCESS_DENIED) ;
		}

		// 祖先のCREATOR_OWNER継承も次child自体の保護で確認します
		if( ancestor && creator && applies && header->AceType == ACCESS_ALLOWED_ACE_TYPE &&
		   (mask & writes) != 0U) {
			*protectNext = true ;
			continue ;
		}

		// 信頼主体・拒否ACE・書込みを含まないACEは現行どおりです
		if( header->AceType != ACCESS_ALLOWED_ACE_TYPE || (mask & writes) == 0U || trusted( sid) ||
		   creator || !applies) {
			continue ;
		}

		// 既存childへの祖先だけで、継承専用または新規directory作成だけを区別します
		if( ancestor && ((header->AceFlags & INHERIT_ONLY_ACE) != 0U ||
						(mask & writes) == FILE_ADD_SUBDIRECTORY)) {
			*protectNext = true ;
			continue ;
		}

		return mtdError( ERROR_ACCESS_DENIED) ;
	}

	// 保護比較へ保持するdescriptorのbyte数です
	const auto descriptorBytes = GetSecurityDescriptorLength( descriptor) ;
	// 固定範囲外のdescriptorを保存しません
	if( !descriptorBytes || descriptorBytes > 65536U) {
		return mtdError( ERROR_INVALID_SECURITY_DESCR) ;
	}

	// descriptor全byteの読取開始位置です
	const auto data = static_cast<const std::byte *>( descriptor) ;
	original.assign( data, data + descriptorBytes) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同reader handleの全byteを一度読み元sizeとSHA-256へ照合します
 * @param[in] api 同workerの完全低位表です
 * @param[in] file 読取位置0から借用するhandleです
 * @param[in] expectedBytes 元CAT memberのbyte数です
 * @param[in] expectedHash 元CAT memberの小文字SHA-256です
 * @return EOFと全byte一致0、元read/CNG/不一致はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError mtdHash( const MtdTransport &api, HANDLE file, std::uint64_t expectedBytes,
					std::wstring_view expectedHash)
{
	// 同hash処理が所有するCNG algorithm handleです
	BCRYPT_ALG_HANDLE  algorithm{} ;
	// 同hash処理が所有するCNG hash handleです
	BCRYPT_HASH_HANDLE hash{} ;
	/** @brief 同hash処理が所有するCNG handleの解放です */
	struct Close	   final {
		  /// 所有するCNG algorithm handleです
		  BCRYPT_ALG_HANDLE	 &algorithm ;
		  /// 所有するCNG hash handleです
		  BCRYPT_HASH_HANDLE &hash ;
		  /**
		   * @brief 開いたhashとalgorithmだけを閉じます
		   */
		  ~Close()
		  {
			  // 作成済みhash handleだけを閉じます
			  if( hash) {
				  BCryptDestroyHash( hash) ;
			  }

			  // 作成済みalgorithm handleだけを閉じます
			  if( algorithm) {
				  BCryptCloseAlgorithmProvider( algorithm, 0U) ;
			  }
		  }
	  } close{algorithm, hash} ;
	// CNG呼出しの元NTSTATUSです
	NTSTATUS status = BCryptOpenAlgorithmProvider( &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0U) ;
	// SHA-256 providerの元NTSTATUSを保持します
	if( status < 0) {
		return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
	}

	// hash objectの必要byte数と返却byte数です
	DWORD length{}, returned{} ;
	status = BCryptGetProperty( algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>( &length),
							   sizeof( length), &returned, 0U) ;
	// hash object長の失敗・欠損・過大値を拒否します
	if( status < 0 || returned != sizeof( length) || !length || length > 1024U * 1024U) {
		return status < 0 ? static_cast<NativeError>( HRESULT_FROM_NT( status))
						  : mtdError( ERROR_INVALID_DATA) ;
	}

	// CNG hash objectが使う所有bufferです
	std::vector<UCHAR> object( length) ;
	status = BCryptCreateHash( algorithm, &hash, object.data(), length, nullptr, 0U, 0U) ;
	// hash作成失敗を元NTSTATUSで返します
	if( status < 0) {
		return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
	}

	// 原fileをEOFまで読む有限bufferです
	std::array<BYTE, 65536U> bytes{} ;
	// 累積でhashした原byte数です
	std::uint64_t			 total{} ;
	// 固定したfile handleをEOFまで順にhashします
	for( ;;) {
		// 今回readが返したbyte数です
		DWORD got{} ;
		// 原fileの読取失敗をWindows errorで保持します
		if( !api.readFile( file, bytes.data(), static_cast<DWORD>( bytes.size()), &got, nullptr)) {
			return mtdError( GetLastError()) ;
		}

		// EOFでhash入力を終えます
		if( !got) {
			break ;
		}

		// 原byte数を超える読取を許可しません
		if( got > bytes.size() || got > expectedBytes - std::min( total, expectedBytes)) {
			return mtdError( ERROR_FILE_INVALID) ;
		}

		total += got ;
		status = BCryptHashData( hash, bytes.data(), got, 0U) ;
		// hash更新失敗を元NTSTATUSで返します
		if( status < 0) {
			return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
		}
	}

	// EOFまでのbyte数とSHA-256表記長を照合します
	if( total != expectedBytes || expectedHash.size() != 64U) {
		return mtdError( ERROR_FILE_INVALID) ;
	}

	// 確定したSHA-256 digestです
	std::array<BYTE, 32U> digest{} ;
	status = BCryptFinishHash( hash, digest.data(), static_cast<ULONG>( digest.size()), 0U) ;
	// hash確定失敗を元NTSTATUSで返します
	if( status < 0) {
		return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
	}

	// 元小文字SHA-256との照合表です
	constexpr wchar_t hex[] = L"0123456789abcdef" ;
	// 32 byteの各桁を元SHA-256へ照合します
	for( std::size_t i = 0U; i < digest.size(); ++i) {
		// 一桁でも異なるmemberを拒否します
		if( expectedHash[i * 2U] != hex[digest[i] >> 4U] ||
		   expectedHash[i * 2U + 1U] != hex[digest[i] & 0x0fU]) {
			return mtdError( ERROR_CRC) ;
		}
	}

	return 0U ;
}
} // namespace

/** @brief 一原DLLのsourceとtargetを同operation中だけ固定します */
struct MtdSharedEntry {
	/**
	 * @brief 同低位表を借用する空entryを作ります
	 * @param[in] calls 同worker中だけ有効な完全表です
	 */
	explicit MtdSharedEntry( const MtdTransport &calls) : source( calls), target( calls)
	{
	}
	/// 同原INF/CATから固定したコピーです
	SelectedStorageCopyFact fact ;
	/// 元ADMIN領域の完全source pathです
	std::wstring			sourcePath ;
	/// 同原byteを固定する変更非共有handleです
	MtdHandle				source ;
	/// 同targetを固定する変更非共有handleです
	MtdHandle				target ;
	/// sourceの原file IDです
	MtdIdentity				sourceId ;
	/// targetの原file IDです
	MtdIdentity				targetId ;
	/// 開始時に対象が存在した場合trueです
	bool					existed{} ;
} ;

/** @brief renameを防ぐため保持する一つの親directoryです */
struct MtdSharedParent {
	/**
	 * @brief 同低位表の空parentを作ります
	 * @param[in] calls 同worker中だけ有効な完全表です
	 */
	explicit MtdSharedParent( const MtdTransport &calls) : handle( calls)
	{
	}
	/// 元正規完全pathです
	std::wstring path ;
	/// 変更非共有で保持する同parentです
	MtdHandle	 handle ;
	/// 元file IDと全security descriptorです
	MtdIdentity	 identity ;
	/// 既存childへ進む祖先だけに限定権限を認めます
	bool		 ancestor{} ;
	/// 前の祖先により当該childのDACL保護が必要です
	bool		 requireProtected{} ;
	/// 次の既存childにもDACL保護が必要です
	bool		 protectNext{} ;
} ;

/** @brief 同原CAT memberとして保持したqueue sourceです */
struct MtdQueueSource {
	/**
	 * @brief 同workerのAPI表でsource保持を作ります
	 * @param[in] calls 終端まで有効な低位API表です
	 */
	explicit MtdQueueSource( const MtdTransport &calls) : handle( calls)
	{
	}
	/// 固定した同原memberの正規pathです
	std::wstring  path ;
	/// 変更を防いで保持するhandleです
	MtdHandle	  handle ;
	/// file IDと保護descriptorです
	MtdIdentity	  identity ;
	/// 元CAT memberのbyte数です
	std::uint64_t bytes{} ;
	/// 元CAT memberのSHA-256です
	std::wstring  sha256 ;
} ;

/** @brief parent、source、targetと一時fileの単独所有です */
struct MtdSharedFileOperation::State {
	/**
	 * @brief 同workerのAPI表と元workspaceを借用します
	 * @param[in,out] original 同原ADMIN所有領域です
	 */
	explicit State( OfficialDownloadWorkspace &original)
		: api( driver_store_inf_detail::transport().mtd), workspace( original), systemSource( api),
		  pending( api)
	{
	}

	/**
	 * @brief 残った同operationの未配置tempだけを回収します
	 */
	~State()
	{
		// 未配置かつ所有確認済みtempだけをcleanup候補にします
		if( pending.valid() && pendingKnown && !pendingPlaced) {
			// 未配置tempの現在属性とfile IDです
			MtdIdentity actual ;
			// 同file IDを再確認できたtempだけに削除を指定します
			if( mtdInfo( api, pending.get(), false, actual) == 0U && mtdSameFile( actual, pendingId)) {
				// 所有tempだけに送る削除指定です
				FILE_DISPOSITION_INFO disposition{TRUE} ;
				static_cast<void>( api.setFileInfo( pending.get(), FileDispositionInfo, &disposition,
												  sizeof( disposition))) ;
			}
		}
	}

	/**
	 * @brief 全親のpath、file IDと保護descriptorを直前再照合します
	 * @return 全親一致0、変化又は元API失敗はHRESULTです
	 */
	[[nodiscard]] NativeError verifyParents() const
	{
		// 保持した親集合を同じ規則で再照合する関数です
		const auto verify = [&]( const auto &list) -> NativeError {
			// 保持中の全親directoryの同一性と保護を再確認します
			for( const auto &parent : list) {
				// 親handleの現在属性と保護です
				MtdIdentity actual ;
				// 親属性取得からの最初の診断です
				auto		error = mtdInfo( api, parent.handle.get(), true, actual) ;
				// 属性取得が成功した親だけの正規pathを検証します
				if( error == 0U) {
					error = mtdPath( api, parent.handle.get(), parent.path) ;
				}

				// 当初の祖先権限から次childの保護を要するか再確認します
				bool protectNext{} ;
				// path一致後に同じ役割でownerとDACLを再確認します
				if( error == 0U) {
					error = mtdSecurity( api, parent.handle.get(), true, actual.security,
										parent.ancestor, parent.requireProtected, &protectNext) ;
				}

				// 親の検査失敗は元診断のまま返します
				if( error != 0U) {
					return error ;
				}

				// 親のfile IDまたは保護が変われば以降の変更を止めます
				if( !mtdSameFile( parent.identity, actual) ||
				   parent.identity.security != actual.security ||
				   protectNext != parent.protectNext) {
					return mtdError( ERROR_RETRY) ;
				}
			}

			return 0U ;
		} ;
		// System32親集合の再検証結果です
		const auto error = verify( parents) ;
		return error != 0U ? error : verify( storeParents) ;
	}

	/// 同workerの完全なMTD低位表です
	const MtdTransport					&api ;
	/// 元ADMIN領域と原sourceを借用します
	OfficialDownloadWorkspace			&workspace ;
	/// Windowsの元System32完全pathです
	std::wstring						 directory ;
	/// volume rootからSystem32までの変更非共有handleです
	std::vector<MtdSharedParent>		 parents ;
	/// 同登録INFのDriver Store sourceが使う全親です
	std::vector<MtdSharedParent>		 storeParents ;
	/// 同原COPY順序とqueue sourceの保持です
	std::vector<SelectedStorageCopyFact> copies ;
	/// 同原queueから固定した全sourceです
	std::vector<MtdQueueSource>			 queueSources ;
	/// 同登録INFの元相対pathです
	std::wstring						 infRelativePath ;
	/// 全source固定後だけtrueです
	bool								 sourcesBound{} ;
	/// 同System32 directoryのvolumeとfile IDです
	MtdIdentity							 parentId ;
	/// 原SYS sourceもqueue commit終端まで変更非共有で保持します
	MtdHandle							 systemSource ;
	/// 同CAT memberのsource位置と固定IDです
	std::wstring						 systemSourcePath ;
	/// 同SYS sourceのfile IDと保護です
	MtdIdentity							 systemSourceId ;
	/// 同SYSの元byte数です
	std::uint64_t						 systemBytes{} ;
	/// 同SYSの元SHA-256です
	std::wstring						 systemSha256 ;
	/// 全原DLLです
	std::vector<MtdSharedEntry>			 entries ;
	/// 所有中の未配置tempだけです
	MtdHandle							 pending ;
	/// 同tempを作成直後に確認したfile IDです
	MtdIdentity							 pendingId ;
	/// 同tempのIDを確認できた場合trueです
	bool								 pendingKnown{} ;
	/// tempが既に正規targetになった場合trueです
	bool								 pendingPlaced{} ;
	/// このoperationのsatisfyを開始した場合trueです
	bool								 attempted{} ;
} ;

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 借用pathを既存fileとして開き同file IDと保護を固定します
 * @param[in] api 同workerの完全低位表です
 * @param[in] path 元完全pathです
 * @param[in] share 元保持handleと共存するWindows share flagsです
 * @param[in] directory directory型を要求する場合trueです
 * @param[out] handle 成功時だけの単独所有です
 * @param[out] identity 同handleの安定file IDです
 * @param[in] ancestor 固定した既存childを持つ祖先の場合trueです
 * @param[in] requireProtected 前祖先によりDACL保護が必要な場合trueです
 * @param[out] protectNext 次childのDACL保護が必要な場合trueです
 * @return 全保護成立0、元API/不一致はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError mtdOpen( const MtdTransport &api, const std::wstring &path, DWORD share, bool directory,
					MtdHandle &handle, MtdIdentity &identity, bool ancestor = false,
					bool requireProtected = false, bool *protectNext = nullptr)
{
	handle.reset(
		api.createFile( path.c_str(), GENERIC_READ | READ_CONTROL, share, nullptr, OPEN_EXISTING,
					   FILE_FLAG_OPEN_REPARSE_POINT |
						   (directory ? FILE_FLAG_BACKUP_SEMANTICS : FILE_FLAG_SEQUENTIAL_SCAN),
					   nullptr)) ;
	// 対象を開けない場合は元Windows errorを返します
	if( !handle.valid()) {
		return mtdError( GetLastError()) ;
	}

	// 開いた対象の属性検証からの最初の診断です
	auto error = mtdInfo( api, handle.get(), directory, identity) ;
	// 属性確認後に同handleの正規pathを検証します
	if( error == 0U) {
		error = mtdPath( api, handle.get(), path) ;
	}

	// 正規path確認後にownerとDACLを検証します
	if( error == 0U) {
		error = mtdSecurity( api, handle.get(), directory, identity.security, ancestor,
							requireProtected, protectNext) ;
	}

	// 不適格なhandleを保持対象から外します
	if( error != 0U) {
		handle.reset() ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元固定handleを維持し別readerの同IDと全byteを照合します
 * @param[in] api 同workerの完全低位表です
 * @param[in] path 元正規完全pathです
 * @param[in] pinned 変更非共有で保持する元file IDです
 * @param[in] size 同CAT memberの元sizeです
 * @param[in] hash 同CAT memberの元SHA-256です
 * @return 同ID/保護/全byte一致0、それ以外は元HRESULTです
 */
//------------------------------------------------------------------------------
NativeError mtdVerifyFile( const MtdTransport &api, const std::wstring &path,
						  const MtdIdentity &pinned, std::uint64_t size, std::wstring_view hash)
{
	// 同fileを再照合する一時readerです
	MtdHandle	reader( api) ;
	// 再openした対象の現在属性と保護です
	MtdIdentity actual ;
	// 再openから保持する最初の診断です
	auto error = mtdOpen( api, path, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, false,
						 reader, actual) ;
	// 対象を再openできない場合は元失敗を返します
	if( error != 0U) {
		return error ;
	}

	// 保持中からfile IDまたは保護が変わった場合は拒否します
	if( !mtdSameFile( pinned, actual) || pinned.security != actual.security) {
		return mtdError( ERROR_RETRY) ;
	}

	// 現在file属性から再構成したbyte数です
	const auto bytes = (static_cast<std::uint64_t>( actual.standard.nFileSizeHigh) << 32U) |
					   actual.standard.nFileSizeLow ;
	// 現在sizeと元CAT memberのsizeが異なれば拒否します
	if( bytes != size) {
		return mtdError( ERROR_FILE_INVALID) ;
	}

	return mtdHash( api, reader.get(), size, hash) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同操作の未配置tempだけを同file IDで片付けます
 * @param[in] api 同workerの完全低位表です
 * @param[in,out] pending 同操作が作成した未配置handleです
 * @param[in] known 作成時のfile ID確認済みならtrueです
 * @param[in] original 作成直後のfile IDです
 * @return 削除指示成立0、不明IDや元API失敗はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError mtdDiscardTemp( const MtdTransport &api, MtdHandle &pending, bool known,
						   const MtdIdentity &original)
{
	// 未配置tempを所有していなければ削除不要です
	if( !pending.valid()) {
		return 0U ;
	}

	// cleanup対象tempの現在file IDです
	MtdIdentity actual ;
	// 所有ID再照合からの最初の診断です
	auto error = known ? mtdInfo( api, pending.get(), false, actual) : mtdError( ERROR_INVALID_DATA) ;
	// 現在file IDが元tempと違う場合は削除しません
	if( error == 0U && !mtdSameFile( actual, original)) {
		error = mtdError( ERROR_RETRY) ;
	}

	// 所有IDが一致する場合だけtempへ削除を指定します
	if( error == 0U) {
		// 同ID tempに限って送る削除指定です
		FILE_DISPOSITION_INFO disposition{TRUE} ;
		// 削除指定の元Windows失敗を保持します
		if( !api.setFileInfo( pending.get(), FileDispositionInfo, &disposition,
							sizeof( disposition))) {
			error = mtdError( GetLastError()) ;
		}
	}

	pending.reset() ;
	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同operation用の衝突しないtemp文字列を作ります
 * @param[out] nonce 成功時の小文字16進文字列です
 * @return 乱数生成成功0、失敗は元HRESULTです
 */
//------------------------------------------------------------------------------
NativeError mtdNonce( std::wstring &nonce)
{
	// temp名の暗号乱数です
	std::array<UCHAR, 16U> random{} ;
	// 乱数生成の元NTSTATUSです
	const auto status = BCryptGenRandom( nullptr, random.data(), static_cast<ULONG>( random.size()),
										BCRYPT_USE_SYSTEM_PREFERRED_RNG) ;
	// nonce生成に失敗した場合は一時名を発行しません
	if( status < 0) {
		return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
	}

	// nonce名へのhex変換表です
	constexpr wchar_t hex[] = L"0123456789abcdef" ;
	nonce.clear() ;
	nonce.reserve( random.size() * 2U) ;
	// nonceの各byteを一意名の小文字hexへ変換します
	for( const auto value : random) {
		nonce.push_back( hex[value >> 4U]) ;
		nonce.push_back( hex[value & 0x0fU]) ;
	}

	return 0U ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 完全preflight前の所有状態を作ります
 * @param[in] workspace 同原ADMIN保護領域です
 */
//------------------------------------------------------------------------------
MtdSharedFileOperation::MtdSharedFileOperation( OfficialDownloadWorkspace &workspace)
	: state_( std::make_unique<State>( workspace))
{
}

//------------------------------------------------------------------------------
/**
 * @brief 同操作が所有するhandleと未配置tempだけを解放します
 */
//------------------------------------------------------------------------------
MtdSharedFileOperation::~MtdSharedFileOperation() noexcept = default ;

//------------------------------------------------------------------------------
/**
 * @brief 同意と復旧の後に元COPY/CATと既存targetを変更せず固定します
 * @param[in,out] workspace 同原ADMIN保護sourceとoperation記録を所有します
 * @param[in] facts 同原選択から固定した全COPY行とassociated SYSです
 * @param[out] operation 全preflight成立時だけの単独所有です
 * @return 全sourceと既存target成立0、不正/未知/異byteは元HRESULTです
 * @note INF登録、共有fileの新規配置、queue commitを行いません
 */
//------------------------------------------------------------------------------
NativeError MtdSharedFileOperation::prepare( OfficialDownloadWorkspace				&workspace,
											const SelectedStorageServiceFacts		&facts,
											std::unique_ptr<MtdSharedFileOperation> &operation)
{
	operation.reset() ;
	// 完全低位表と保護workspaceがなければ共有先へ触れません
	if( !driver_store_inf_detail::mtdTransportReady() ||
	   workspace.protectionMode() != OfficialWorkspaceMode::ADMINISTRATOR ||
	   !mtdSame( facts.className, L"MTD") ||
	   !mtdSame( facts.classGuid, L"{4d36e970-e325-11ce-bfc1-08002be10318}") ||
	   facts.mtdCopies.empty() || facts.mtdCopies.size() > 4096U || facts.binaryTarget.empty()) {
		return mtdError( ERROR_NOT_SUPPORTED) ;
	}

	try {
		// 全preflight成功時だけ引き渡すoperation所有です
		auto  made = std::unique_ptr<MtdSharedFileOperation>{new MtdSharedFileOperation( workspace)} ;
		// 構築中の共有file保持状態です
		auto &state			  = *made->state_ ;
		state.copies		  = facts.mtdCopies ;
		state.infRelativePath = facts.infRelativePath ;
		// Windows directoryを受け取る有限bufferです
		std::vector<wchar_t> windows( 32768U) ;
		// Windows directoryの返却長です
		const auto			 length =
			state.api.windowsDirectory( windows.data(), static_cast<UINT>( windows.size())) ;
		// Windows directoryの取得失敗や過長を拒否します
		if( length < 3U || length >= windows.size()) {
			return mtdError( length ? ERROR_FILENAME_EXCED_RANGE : GetLastError()) ;
		}

		// 検証するWindows root pathです
		std::wstring root( windows.data(), length) ;
		// Windows root以外の末尾separatorを取り除きます
		while( root.size() > 3U && root.back() == L'\\') {
			root.pop_back() ;
		}

		// drive絶対path以外やADSを含むWindows rootを拒否します
		if( root.size() < 3U || root[1] != L':' || root[2] != L'\\' ||
		   root.find( L':', 2U) != root.npos || root.find( L'\0') != root.npos ||
		   root.find( L"\\..") != root.npos || root.find( L"\\.\\") != root.npos) {
			return mtdError( ERROR_INVALID_NAME) ;
		}

		state.directory = root + L"\\System32" ;
		// volume rootから親を保持し、途中のrename/reparseを許しません
		std::size_t end = 3U ;
		// 直前の祖先が次childの保護を要求したかです
		bool		requireProtected{} ;
		// volume rootからSystem32まで全親を順に保持します
		for( ;;) {
			// 現在開く親directoryのpathです
			auto			path = state.directory.substr( 0U, end) ;
			// 親directoryのhandleと保護観測です
			MtdSharedParent parent( state.api) ;
			parent.path				= path ;
			parent.ancestor			= end != state.directory.size() ;
			parent.requireProtected = requireProtected ;
			// 親openからの最初の診断です
			auto error = mtdOpen( state.api, path, FILE_SHARE_READ | FILE_SHARE_WRITE, true,
								 parent.handle, parent.identity, parent.ancestor,
								 parent.requireProtected, &parent.protectNext) ;
			// 親を安全に開けない場合は元診断を返します
			if( error != 0U) {
				return error ;
			}

			// 最終System32親のvolumeとfile IDを保存します
			if( end == state.directory.size()) {
				state.parentId = parent.identity ;
			}

			requireProtected = parent.protectNext ;
			state.parents.push_back( std::move( parent)) ;
			// 最終親を保持した時点で探索を終えます
			if( end == state.directory.size()) {
				break ;
			}

			// 次の親を特定するseparator位置です
			const auto slash = state.directory.find( L'\\', end == 3U ? end : end + 1U) ;
			end				 = slash == state.directory.npos ? state.directory.size() : slash ;
		}

		// 原COPY内のassociated SYS件数です
		std::size_t	  systemCopies{} ;
		// 不在DLLの新規配置に必要な累積byte数です
		std::uint64_t requiredBytes{} ;
		// 全原COPYをSYS一件と共有DLLへ分けます
		for( const auto &copy : facts.mtdCopies) {
			// associated SYSは元binary factと照合します
			if( mtdSame( copy.target, facts.binaryTarget)) {
				++systemCopies ;
				// SYSの重複や元source・size・hash差を拒否します
				if( systemCopies != 1U || !mtdSame( copy.source, facts.binarySource) ||
				   copy.bytes != facts.binaryBytes || !mtdSame( copy.sha256, facts.binarySha256)) {
					return mtdError( ERROR_INVALID_DATA) ;
				}

				state.systemSourcePath = workspace.path( copy.source) ;
				state.systemBytes	   = copy.bytes ;
				state.systemSha256	   = copy.sha256 ;
				// SYS sourceを原workspaceへ結べなければ止めます
				if( state.systemSourcePath.empty()) {
					return mtdError( ERROR_INVALID_DATA) ;
				}

				// SYS source openからの最初の診断です
				auto error = mtdOpen( state.api, state.systemSourcePath, FILE_SHARE_READ, false,
									 state.systemSource, state.systemSourceId) ;
				// 保持できたSYS sourceを元sizeとhashへ照合します
				if( error == 0U) {
					error = mtdVerifyFile( state.api, state.systemSourcePath, state.systemSourceId,
										  state.systemBytes, state.systemSha256) ;
				}

				// SYS sourceの保護またはbyte不一致を元診断で返します
				if( error != 0U) {
					return error ;
				}

				continue ;
			}

			// System32直下のDLL targetに要求するprefixです
			const auto prefix = state.directory + L"\\" ;
			// DLL targetがDIRID11直下の安全な一意名であることを要求します
			if( copy.dirid != 11 || copy.target.size() <= prefix.size() ||
			   !mtdSame( std::wstring_view{copy.target}.substr( 0U, prefix.size()), prefix) ||
			   copy.target.find( L'\\', prefix.size()) != copy.target.npos ||
			   !isSafeOfficialArchiveMember( std::wstring_view{copy.target}.substr( prefix.size()),
											L'\\') ||
			   std::ranges::any_of( state.entries, [&]( const auto &old) {
				   return mtdSame( old.fact.target, copy.target) ;
			   })) {
				return mtdError( ERROR_INVALID_DATA) ;
			}

			// 一DLLの元COPYとsource・target保持です
			MtdSharedEntry entry( state.api) ;
			entry.fact		 = copy ;
			entry.sourcePath = workspace.path( copy.source) ;
			// 共有DLL sourceを原workspaceへ結べなければ止めます
			if( entry.sourcePath.empty()) {
				return mtdError( ERROR_INVALID_DATA) ;
			}

			// DLL source openからの最初の診断です
			auto error = mtdOpen( state.api, entry.sourcePath, FILE_SHARE_READ, false, entry.source,
								 entry.sourceId) ;
			// 保持できたDLL sourceを元sizeとhashへ照合します
			if( error == 0U) {
				error = mtdVerifyFile( state.api, entry.sourcePath, entry.sourceId, copy.bytes,
									  copy.sha256) ;
			}

			// DLL sourceの保護またはbyte不一致を元診断で返します
			if( error != 0U) {
				return error ;
			}

			error = mtdOpen( state.api, copy.target, FILE_SHARE_READ, false, entry.target,
							entry.targetId) ;
			// target不在だけを新規配置候補として扱います
			if( error == mtdError( ERROR_FILE_NOT_FOUND)) {
				entry.existed = false ;
				// 必要容量の加算overflowを拒否します
				if( copy.bytes > (std::numeric_limits<std::uint64_t>::max)() - requiredBytes) {
					return mtdError( ERROR_ARITHMETIC_OVERFLOW) ;
				}

				requiredBytes += copy.bytes ;
			}
			// 不在以外のopen失敗を新規配置へ変換しません
			else if( error != 0U) {
				return error ;
			} else {
				entry.existed = true ;
				error =
					mtdVerifyFile( state.api, copy.target, entry.targetId, copy.bytes, copy.sha256) ;
				// 既存targetが同byteでなければ上書き前に拒否します
				if( error != 0U) {
					return error ;
				}
			}

			state.entries.push_back( std::move( entry)) ;
		}

		// associated SYSを正確に一件要求します
		if( systemCopies != 1U) {
			return mtdError( ERROR_INVALID_DATA) ;
		}

		// 新規配置がある場合だけ必要容量を確認します
		if( requiredBytes != 0U) {
			// 要求者が使える容量とvolume容量の観測です
			ULARGE_INTEGER available{}, total{}, freeBytes{} ;
			// 空き容量の照会失敗を元Windows errorで返します
			if( !state.api.freeSpace( state.directory.c_str(), &available, &total, &freeBytes)) {
				return mtdError( GetLastError()) ;
			}

			// 新規DLL全件に必要な容量がなければ配置しません
			if( available.QuadPart < requiredBytes) {
				return mtdError( ERROR_DISK_FULL) ;
			}
		}

		operation = std::move( made) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_FAIL ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元queueの各sourceを同原workspace又は同登録INFの保護Store memberへ結びます
 * @param[in] registeredInf 同原byteとして保持中の登録INFです
 * @param[in] sources 原COPY行と同じ順序のqueue source完全pathです
 * @return 全sourceの位置、親、所有、file IDとCAT hash成立0、それ以外はHRESULTです
 * @note 他packageや任意の同hash pathを採用せず、全handleを操作終端まで保持します
 */
//------------------------------------------------------------------------------
NativeError MtdSharedFileOperation::bindQueueSources( std::wstring_view			   registeredInf,
													 std::span<const std::wstring> sources)
{
	try {
		// 同operationの保持状態です
		auto &state = *state_ ;
		// 再bindingや不完全な原source集合を拒否します
		if( state.sourcesBound || state.attempted || !driver_store_inf_detail::mtdTransportReady() ||
		   registeredInf.empty() || registeredInf.find( L'\0') != registeredInf.npos ||
		   sources.size() != state.copies.size() || state.infRelativePath.empty()) {
			return mtdError( ERROR_INVALID_PARAMETER) ;
		}

		// 登録INFに対応するStore INF pathです
		std::wstring storeInf ;
		// 同登録packageのStore directoryです
		std::wstring storeDirectory ;
		// Store sourceの全親を固定する関数です
		auto		 pinParents = [&]( const std::wstring &file) -> NativeError {
			// 対象file直親を示すseparator位置です
			const auto last = file.find_last_of( L'\\') ;
			// 親を特定できないStore pathを拒否します
			if( last == file.npos || last < 3U) {
				return mtdError( ERROR_INVALID_NAME) ;
			}

			// 直前の祖先が次childの保護を要求したかです
			bool requireProtected{} ;
			// 登録Store sourceの全親を順に検査します
			for( std::size_t end = 3U;;) {
				// 今回固定するStore親pathです
				const auto path = file.substr( 0U, end) ;
				// 最終のsource直親は限定許可を使わず厳格に検査します
				const bool ancestor = end != last ;
				// 同じ親が別memberの検査で保持済みかです
				const auto old = std::ranges::find_if( state.storeParents, [&]( const auto &entry) {
					return mtdSame( entry.path, path) ;
				}) ;
				// 未保持の親は同役割と保護条件で固定します
				if( old == state.storeParents.end()) {
					// 一Store親のhandleと保護観測です
					MtdSharedParent parent( state.api) ;
					parent.path				= path ;
					parent.ancestor			= ancestor ;
					parent.requireProtected = requireProtected ;
					// 同Store親openの元診断です
					const auto error =
						mtdOpen( state.api, path, FILE_SHARE_READ | FILE_SHARE_WRITE, true,
										parent.handle, parent.identity, parent.ancestor,
										parent.requireProtected, &parent.protectNext) ;
					// Store親の保護を確認できない場合は元診断を返します
					if( error != 0U) {
						return error ;
					}

					requireProtected = parent.protectNext ;
					state.storeParents.push_back( std::move( parent)) ;
				} else {
					// source直親を兼ねる場合は常に厳しい役割を優先します
					const bool	combinedAncestor = old->ancestor && ancestor ;
					// どちらかの親経路に必要なDACL保護を維持します
					const bool	combinedProtected = old->requireProtected || requireProtected ;
					// 保持済みhandleの現在のfile IDとdescriptorです
					MtdIdentity actual ;
					// 同じ役割における次child保護条件です
					bool		protectNext{} ;
					// 保持した親の属性と正規pathを再確認します
					auto		error = mtdInfo( state.api, old->handle.get(), true, actual) ;
					// 属性確認後に同handleの正規pathを照合します
					if( error == 0U) {
						error = mtdPath( state.api, old->handle.get(), old->path) ;
					}

					// 共通経路で必要な厳しい方の保護を検査します
					if( error == 0U) {
						error = mtdSecurity( state.api, old->handle.get(), true, actual.security,
													combinedAncestor, combinedProtected, &protectNext) ;
					}

					// 取得や保護の失敗を元診断で返します
					if( error != 0U) {
						return error ;
					}

					// 異なるfileまたはdescriptorを同じStore親にしません
					if( !mtdSameFile( old->identity, actual) ||
					   old->identity.security != actual.security) {
						return mtdError( ERROR_RETRY) ;
					}

					old->ancestor		  = combinedAncestor ;
					old->requireProtected = combinedProtected ;
					old->protectNext	  = protectNext ;
					requireProtected	  = protectNext ;
				}

				// 対象fileの直親まで保持したら終了します
				if( end == last) {
					break ;
				}

				// 次のStore親を示すseparator位置です
				const auto next = file.find( L'\\', end == 3U ? end : end + 1U) ;
				// 区切りの欠損や親範囲外pathを拒否します
				if( next == file.npos || next > last) {
					return mtdError( ERROR_INVALID_NAME) ;
				}

				end = next ;
			}

			return 0U ;
		} ;
		// 同登録INFだけのStore解決関数です
		auto resolveStore = [&]() -> NativeError {
			// 同登録INFのStore解決は一operationで再利用します
			if( !storeDirectory.empty()) {
				return 0U ;
			}

			// WindowsからStore INF位置を受け取る有限bufferです
			std::vector<wchar_t> buffer( 32768U, L'\0') ;
			// Store位置の必要文字数です
			DWORD				 required{} ;
			// 同選択registered INFの所有文字列です
			const std::wstring	 registered{registeredInf} ;
			// 登録INFに対応するStore位置照会の元失敗を保持します
			if( !state.api.storeLocation( registered.c_str(), nullptr, nullptr, buffer.data(),
										static_cast<DWORD>( buffer.size()), &required)) {
				return mtdError( GetLastError()) ;
			}

			// Store位置の長さとNUL終端を検証します
			if( required < 2U || required > buffer.size() || buffer[required - 1U] != L'\0') {
				return mtdError( ERROR_INVALID_DATA) ;
			}

			storeInf.assign( buffer.data(), required - 1U) ;
			// 正規FileRepositoryを限定するprefixです
			const auto prefix = state.directory + L"\\DriverStore\\FileRepository\\" ;
			// System32のFileRepository外を登録Storeとして採用しません
			if( storeInf.size() <= prefix.size() ||
			   !mtdSame( std::wstring_view{storeInf}.substr( 0U, prefix.size()), prefix)) {
				return mtdError( ERROR_ACCESS_DENIED) ;
			}

			// Store package directoryを区切る位置です
			const auto slash = storeInf.find( L'\\', prefix.size()) ;
			// 元INF basenameの開始を求める位置です
			const auto leaf = state.infRelativePath.find_last_of( L'\\') ;
			// 原INFのbasenameです
			const auto originalLeaf =
				state.infRelativePath.substr( leaf == state.infRelativePath.npos ? 0U : leaf + 1U) ;
			// 別packageや不正なINF名を同登録INFとみなしません
			if( slash == storeInf.npos || storeInf.find( L'\\', slash + 1U) != storeInf.npos ||
			   !isSafeOfficialArchiveMember(
				   std::wstring_view{storeInf}.substr( prefix.size(), slash - prefix.size()),
				   L'\\') ||
			   !mtdSame( std::wstring_view{storeInf}.substr( slash + 1U), originalLeaf)) {
				return mtdError( ERROR_INVALID_NAME) ;
			}

			storeDirectory = storeInf.substr( 0U, slash) ;
			// 登録Store INFの親保持からの最初の診断です
			auto error = pinParents( storeInf) ;
			// 登録INFの親を保持できなければ同Storeを使いません
			if( error != 0U) {
				return error ;
			}

			// 元workspaceに保持したINF pathです
			const auto	originalInf = state.workspace.path( state.infRelativePath) ;
			// 元INFの変更非共有handleです
			MtdHandle	original( state.api) ;
			// 元INFのfile IDと保護観測です
			MtdIdentity originalId ;
			error = mtdOpen( state.api, originalInf, FILE_SHARE_READ, false, original, originalId) ;
			// 元INFの全byte SHA-256です
			std::wstring hash ;
			// 元workspace INFを開けた場合だけ全hashを求めます
			if( error == 0U) {
				error = computeFileSha256( originalInf, hash) ;
			}

			// 同原INFとして固定するStore sourceです
			MtdQueueSource pin( state.api) ;
			pin.path  = storeInf ;
			pin.bytes = (static_cast<std::uint64_t>( originalId.standard.nFileSizeHigh) << 32U) |
						originalId.standard.nFileSizeLow ;
			pin.sha256 = std::move( hash) ;
			// 同登録Store INFを変更非共有で開きます
			if( error == 0U) {
				error =
					mtdOpen( state.api, pin.path, FILE_SHARE_READ, false, pin.handle, pin.identity) ;
			}

			// Store INFのsizeとhashを原INFへ照合します
			if( error == 0U) {
				error = mtdVerifyFile( state.api, pin.path, pin.identity, pin.bytes, pin.sha256) ;
			}

			// 同原INFと確認できたStore handleを保持します
			if( error == 0U) {
				state.queueSources.push_back( std::move( pin)) ;
			}

			return error ;
		} ;
		// 元INFの相対親を求めるseparator位置です
		const auto originalSlash = state.infRelativePath.find_last_of( L'\\') ;
		// 同原package内のmemberに要求する相対prefixです
		const auto relativePrefix = originalSlash == state.infRelativePath.npos
										? std::wstring{}
										: state.infRelativePath.substr( 0U, originalSlash + 1U) ;
		// 原COPY順に全queue sourceを固定します
		for( std::size_t index = 0U; index < sources.size(); ++index) {
			// 現在の原COPY行です
			const auto &copy = state.copies[index] ;
			// 原COPYに対応するworkspace sourceです
			const auto	original = state.workspace.path( copy.source) ;
			// 元sourceまたは通知sourceの欠損を拒否します
			if( original.empty() || sources[index].empty()) {
				return mtdError( ERROR_INVALID_DATA) ;
			}

			// workspaceと異なるsourceは同登録Storeに限定します
			if( !mtdSame( sources[index], original)) {
				// 同登録Store解決の元診断です
				auto error = resolveStore() ;
				// Store解決失敗を元診断のまま返します
				if( error != 0U) {
					return error ;
				}

				// 原INF相対prefix外のmemberを拒否します
				if( copy.source.size() <= relativePrefix.size() ||
				   (!relativePrefix.empty() &&
					!mtdSame( std::wstring_view{copy.source}.substr( 0U, relativePrefix.size()),
							 relativePrefix))) {
					return mtdError( ERROR_INVALID_NAME) ;
				}

				// 原INFの親から見た安全member相対pathです
				const auto relative = std::wstring_view{copy.source}.substr( relativePrefix.size()) ;
				// 通知sourceが安全な同Store memberに完全一致しなければ拒否します
				if( !isSafeOfficialArchiveMember( relative, L'\\') ||
				   !mtdSame( sources[index], storeDirectory + L"\\" + std::wstring{relative})) {
					return mtdError( ERROR_ACCESS_DENIED) ;
				}

				error = pinParents( sources[index]) ;
				// Store memberの全親を保持できない場合は止めます
				if( error != 0U) {
					return error ;
				}
			}

			// 同原COPYへ結ぶqueue sourceの保持です
			MtdQueueSource pin( state.api) ;
			pin.path   = sources[index] ;
			pin.bytes  = copy.bytes ;
			pin.sha256 = copy.sha256 ;
			// queue source openからの最初の診断です
			auto error =
				mtdOpen( state.api, pin.path, FILE_SHARE_READ, false, pin.handle, pin.identity) ;
			// 開いたmemberを原CATのsizeとhashへ照合します
			if( error == 0U) {
				error = mtdVerifyFile( state.api, pin.path, pin.identity, pin.bytes, pin.sha256) ;
			}

			// sourceの保護または原byte不一致を返します
			if( error != 0U) {
				return error ;
			}

			state.queueSources.push_back( std::move( pin)) ;
		}

		state.sourcesBound = true ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_FAIL ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 原queue照合後に共有DLLを同byte再利用又は非置換配置します
 * @param[in] cancelled 操作中の取消し照会です。空は取消しなしです
 * @param[in] authorization 同原record/UTCを作用直前に再確認します
 * @param[out] result 部分配置とcleanup不確定も含む原結果です
 * @return 全共有DLL充足0、取消し又は最初の原HRESULTです
 * @pre 呼出し側は同意/復旧と同選択の原queue全照合を確認済みです
 * @note SYSのcopy、queue commit、DIFを行いません
 */
//------------------------------------------------------------------------------
NativeError MtdSharedFileOperation::satisfy( const std::function<bool()>		   &cancelled,
											const std::function<NativeError()> &authorization,
											MtdSharedFileResult				   &result)
{
	result = {} ;
	// 同operationの保持状態です
	auto &state = *state_ ;
	// source未固定、認可欠損、再実行を作用前に拒否します
	if( state.attempted || !state.sourcesBound || !authorization || state.parents.empty() ||
	   !driver_store_inf_detail::mtdTransportReady()) {
		return mtdError( ERROR_INVALID_STATE) ;
	}

	state.attempted = true ;
	// 部分結果を保って所有tempだけcleanupする失敗処理です
	const auto fail = [&]( NativeError error) {
		// 未配置で所有するtempだけを失敗時に片付けます
		if( state.pending.valid() && !state.pendingPlaced) {
			// temp cleanupの元診断です
			const auto cleanup =
				mtdDiscardTemp( state.api, state.pending, state.pendingKnown, state.pendingId) ;
			result.cleanupUncertain = cleanup != 0U ;
			state.pendingKnown		= false ;
		}

		return error ;
	} ;
	try {
		// 共有先の全親を再検証した結果です
		auto parentError = state.verifyParents() ;
		// System32親の変化を検出したら共有先を変更しません
		if( parentError != 0U) {
			return fail( parentError) ;
		}

		// 全queue sourceの保持状態と原byteを再確認します
		for( const auto &source : state.queueSources) {
			// 保持handleが欠けたsourceを使用しません
			if( !source.handle.valid()) {
				return fail( mtdError( ERROR_INVALID_DATA)) ;
			}

			// 保持sourceの原byte再照合結果です
			const auto error =
				mtdVerifyFile( state.api, source.path, source.identity, source.bytes, source.sha256) ;
			// source再検証の元失敗を返します
			if( error != 0U) {
				return fail( error) ;
			}
		}

		// 各共有DLLを原順に充足し部分結果を保持します
		for( auto &entry : state.entries) {
			result.failureStage = 1U ;
			// 内部取消し後は次の共有作用を始めません
			if( cancelled && cancelled()) {
				return fail( mtdError( ERROR_CANCELLED)) ;
			}

			// 共有作用直前の元record再検証結果です
			const auto authorizationError = authorization() ;
			// 元recordの失効を取消しへ変換せず保持します
			if( authorizationError != 0U) {
				return fail( authorizationError) ;
			}

			// 既存targetは保護と同byteを再確認して再利用します
			if( entry.existed) {
				// 既存targetの保護と原byte確認結果です
				const auto error = mtdVerifyFile( state.api, entry.fact.target, entry.targetId,
												 entry.fact.bytes, entry.fact.sha256) ;
				// 既存targetが変化した場合は置換せず止めます
				if( error != 0U) {
					return fail( error) ;
				}

				++result.reused ;
				continue ;
			}

			// 正規targetを作る前に新規temp名と対象を元保護領域へ記録します
			std::wstring nonce ;
			result.failureStage = 2U ;
			// 一意temp名生成からの最初の診断です
			auto error = mtdNonce( nonce) ;
			// 一時名の生成失敗を保持します
			if( error != 0U) {
				return fail( error) ;
			}

			// 正規先と同volumeの一時pathです
			const auto tempPath = state.directory + L"\\drivercrate-" + nonce + L".tmp" ;
			// 同operationの所有tempを記録するjournal名です
			const auto journalName = L"mtd-" + nonce + L".pending" ;
			// 所有journalのhandleです
			HANDLE	   journal	= INVALID_HANDLE_VALUE ;
			result.failureStage = 3U ;
			error				= state.workspace.createFile( journalName, journal) ;
			// 所有journalを作れない場合はtemp作成へ進みません
			if( error != 0U) {
				return fail( error) ;
			}

			// 同operationが開いたjournal handleの所有です
			const std::unique_ptr<void, decltype( &::CloseHandle)> journalOwner{journal,
																			   &::CloseHandle} ;
			// tempと最終targetを結ぶjournal本文です
			const std::wstring journalBody = tempPath + L"\n" + entry.fact.target + L"\n" ;
			// journal writeが返したbyte数です
			DWORD			   journalWritten{} ;
			// journal本文のUTF-16 byte数です
			const auto journalBytes = static_cast<DWORD>( journalBody.size() * sizeof( wchar_t)) ;
			// journal本文の全writeとflushの成否です
			const bool journalOk = ::WriteFile( journal, journalBody.data(), journalBytes,
											   &journalWritten, nullptr) != FALSE &&
								   journalWritten == journalBytes &&
								   ::FlushFileBuffers( journal) != FALSE ;
			// journal失敗直後の元Windows診断です
			const auto journalError = journalOk ? ERROR_SUCCESS : GetLastError() ;
			// journalの書込またはflush失敗後に共有先を変更しません
			if( !journalOk) {
				return fail( mtdError( journalError)) ;
			}

			// CREATE_NEWで他者の既存tempを変更せず、同volumeへ完成させます
			state.pending.reset( state.api.createFile(
				tempPath.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL,
				FILE_SHARE_READ, nullptr, CREATE_NEW,
				FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) ;
			state.pendingKnown	= false ;
			state.pendingPlaced = false ;
			result.failureStage = 4U ;
			// CREATE_NEW tempの失敗を元Windows診断で返します
			if( !state.pending.valid()) {
				return fail( mtdError( GetLastError())) ;
			}

			error = mtdInfo( state.api, state.pending.get(), false, state.pendingId) ;
			// tempのfile IDを取得できた場合だけ所有済みと記録します
			if( error == 0U) {
				state.pendingKnown = true ;
			}

			// temp handleの正規pathを確認します
			if( error == 0U) {
				error = mtdPath( state.api, state.pending.get(), tempPath) ;
			}

			// tempのownerとDACLを確認します
			if( error == 0U) {
				error =
					mtdSecurity( state.api, state.pending.get(), false, state.pendingId.security) ;
			}

			// 異なるvolumeのtempから非置換配置しません
			if( error == 0U && state.pendingId.identifier.VolumeSerialNumber !=
								  state.parentId.identifier.VolumeSerialNumber) {
				error = mtdError( ERROR_NOT_SAME_DEVICE) ;
			}

			// tempの同一性や保護を確認できなければ配置しません
			if( error != 0U) {
				return fail( error) ;
			}

			// journalへのfile ID記録byte数です
			DWORD idWritten{} ;
			// journalへのtemp file ID記録を確認します
			if( !::WriteFile( journal, &state.pendingId.identifier,
							static_cast<DWORD>( sizeof( state.pendingId.identifier)), &idWritten,
							nullptr) ||
			   idWritten != sizeof( state.pendingId.identifier) || !::FlushFileBuffers( journal)) {
				return fail( mtdError( GetLastError())) ;
			}

			// 原DLLをcopyする変更非共有readerです
			MtdHandle	sourceReader( state.api) ;
			// 再openしたDLL sourceのfile IDです
			MtdIdentity sourceId ;
			result.failureStage = 5U ;
			error = mtdOpen( state.api, entry.sourcePath, FILE_SHARE_READ, false, sourceReader,
							sourceId) ;
			// 再openしたsourceのfile IDが変化した場合は拒否します
			if( error == 0U && !mtdSameFile( sourceId, entry.sourceId)) {
				error = mtdError( ERROR_RETRY) ;
			}

			// source再openまたはID確認の失敗を返します
			if( error != 0U) {
				return fail( error) ;
			}

			// 原DLLの有限copy bufferです
			std::array<BYTE, 65536U> bytes{} ;
			// tempへ書いた累積byte数です
			std::uint64_t			 total{} ;
			result.failureStage = 6U ;
			// 元DLLの全byteを完成前tempへ順に書きます
			for( ;;) {
				// 内部取消し時は未配置tempだけをcleanupします
				if( cancelled && cancelled()) {
					return fail( mtdError( ERROR_CANCELLED)) ;
				}

				// 今回source readが返したbyte数です
				DWORD got{} ;
				// source読取の元Windows失敗を保持します
				if( !state.api.readFile( sourceReader.get(), bytes.data(),
									   static_cast<DWORD>( bytes.size()), &got, nullptr)) {
					return fail( mtdError( GetLastError())) ;
				}

				// source EOFでcopyを終えます
				if( !got) {
					break ;
				}

				// 元sizeを超える読取を拒否します
				if( got > bytes.size() ||
				   got > entry.fact.bytes - std::min( total, entry.fact.bytes)) {
					return fail( mtdError( ERROR_FILE_INVALID)) ;
				}

				// 同bufferで書込済みの位置です
				DWORD at{} ;
				// 部分writeを含め読み取った全byteを書きます
				while( at < got) {
					// 今回writeが返したbyte数です
					DWORD written{} ;
					// temp書込の元Windows失敗を保持します
					if( !state.api.writeFile( state.pending.get(), bytes.data() + at, got - at,
											&written, nullptr)) {
						return fail( mtdError( GetLastError())) ;
					}

					// 進捗0や過大なwrite応答を失敗にします
					if( !written || written > got - at) {
						return fail( mtdError( ERROR_WRITE_FAULT)) ;
					}

					at += written ;
				}

				total += got ;
			}

			// 実copy byte数が原CATと異なれば配置しません
			if( total != entry.fact.bytes) {
				return fail( mtdError( ERROR_FILE_INVALID)) ;
			}

			result.failureStage = 7U ;
			// 完成済みtempのflush失敗を保持します
			if( !state.api.flushFile( state.pending.get())) {
				return fail( mtdError( GetLastError())) ;
			}

			result.failureStage = 8U ;
			error = mtdVerifyFile( state.api, tempPath, state.pendingId, entry.fact.bytes,
								  entry.fact.sha256) ;
			// tempの原byteと保護の検証失敗を返します
			if( error != 0U) {
				return fail( error) ;
			}

			// rename前の内部取消しでは正規先を作りません
			if( cancelled && cancelled()) {
				return fail( mtdError( ERROR_CANCELLED)) ;
			}

			// FileRenameInfoの非置換契約で正規先へ一度だけ配置します
			error = state.verifyParents() ;
			// rename直前の親directory変化を拒否します
			if( error != 0U) {
				return fail( error) ;
			}

			// 終端を除く正規target名のUTF-16 byte数です
			const auto			   targetBytes = entry.fact.target.size() * sizeof( wchar_t) ;
			// NUL終端を含むFileRenameInfo bufferです
			std::vector<std::byte> renameBytes( offsetof( FILE_RENAME_INFO, FileName) + targetBytes +
											   sizeof( wchar_t)) ;
			// 非置換renameへ渡す構造の借用viewです
			auto rename				= reinterpret_cast<FILE_RENAME_INFO *>( renameBytes.data()) ;
			rename->ReplaceIfExists = FALSE ;
			rename->RootDirectory	= nullptr ;
			rename->FileNameLength	= static_cast<DWORD>( targetBytes) ;
			std::memcpy( rename->FileName, entry.fact.target.data(), targetBytes) ;
			rename->FileName[entry.fact.target.size()] = L'\0' ;
			result.failureStage						   = 12U ;
			error									   = authorization() ;
			// 各非置換rename直前の元record失効を保持します
			if( error != 0U) {
				return fail( error) ;
			}

			result.failureStage = 9U ;
			// 非置換rename失敗時は競合とその他の元errorを区別します
			if( !state.api.setFileInfo( state.pending.get(), FileRenameInfo, rename,
									  static_cast<DWORD>( renameBytes.size()))) {
				// rename失敗直後の元Windows診断です
				const auto native = GetLastError() ;
				// 未配置tempの所有IDに限定したcleanup結果です
				const auto cleanup =
					mtdDiscardTemp( state.api, state.pending, state.pendingKnown, state.pendingId) ;
				state.pendingKnown = false ;
				// temp cleanupが不確定なら元rename失敗と共に記録します
				if( cleanup != 0U) {
					result.cleanupUncertain = true ;
					return mtdError( native) ;
				}

				// 既存先競合以外のrename失敗をそのまま返します
				if( native != ERROR_ALREADY_EXISTS && native != ERROR_FILE_EXISTS) {
					return mtdError( native) ;
				}

				// 競合で出現したtargetも保護と同byteが成立する場合だけ再利用します
				error = mtdOpen( state.api, entry.fact.target, FILE_SHARE_READ, false, entry.target,
								entry.targetId) ;
				// 競合先の保護と原byteを確認できた場合だけ再利用します
				if( error == 0U) {
					error = mtdVerifyFile( state.api, entry.fact.target, entry.targetId,
										  entry.fact.bytes, entry.fact.sha256) ;
				}

				// 競合先の不一致は置換せず拒否します
				if( error != 0U) {
					return error ;
				}

				++result.reused ;
				continue ;
			}

			state.pendingPlaced = true ;
			entry.targetId		= state.pendingId ;
			entry.target		= std::move( state.pending) ;
			state.pendingKnown	= false ;
			++result.renameSucceeded ;
			result.failureStage = 100U ;
			error				= mtdPath( state.api, entry.target.get(), entry.fact.target) ;
			// rename後の正規path確認に続き同IDとhashを検証します
			if( error == 0U) {
				result.failureStage = 101U ;
				error				= mtdVerifyFile( state.api, entry.fact.target, entry.targetId,
													entry.fact.bytes, entry.fact.sha256) ;
			}

			// 配置済みという部分作用を消さず事後確認の失敗を返します
			if( error != 0U) {
				return error ;
			}

			++result.created ;
		}

		result.failureStage = 11U ;
		// 全共有fileの終端再確認結果です
		const auto error = verify() ;
		// 全保持の再確認が成功した場合だけ失敗stageを解除します
		if( error == 0U) {
			result.failureStage = 0U ;
		}

		return error ;
	} catch( const std::bad_alloc &) {
		return fail( E_OUTOFMEMORY) ;
	} catch( ...) {
		return fail( E_FAIL) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同一handle/file IDと全byteを共有DLLごとに再照合します
 * @return 全target固定0、不在/差替え/byte変更はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError MtdSharedFileOperation::verify() const
{
	try {
		// 同operationの保持状態です
		const auto &state = *state_ ;
		// 共有充足未開始や不完全低位表では再検証を行いません
		if( !state.attempted || !driver_store_inf_detail::mtdTransportReady()) {
			return mtdError( ERROR_INVALID_STATE) ;
		}

		// 保持親の再確認結果です
		auto parentError = state.verifyParents() ;
		// 保持した親の変化を元診断で返します
		if( parentError != 0U) {
			return parentError ;
		}

		// SYS sourceの保持欠損を拒否します
		if( !state.systemSource.valid()) {
			return mtdError( ERROR_INVALID_DATA) ;
		}

		// 保持SYS sourceの再確認結果です
		const auto sourceError =
			mtdVerifyFile( state.api, state.systemSourcePath, state.systemSourceId,
						  state.systemBytes, state.systemSha256) ;
		// SYS sourceの変化を元診断で返します
		if( sourceError != 0U) {
			return sourceError ;
		}

		// 保持した全queue sourceを再照合します
		for( const auto &source : state.queueSources) {
			// source handleが失われた場合は拒否します
			if( !source.handle.valid()) {
				return mtdError( ERROR_INVALID_DATA) ;
			}

			// 保持queue sourceの再確認結果です
			const auto error =
				mtdVerifyFile( state.api, source.path, source.identity, source.bytes, source.sha256) ;
			// queue sourceの保護または原byteの変化を返します
			if( error != 0U) {
				return error ;
			}
		}

		// 全共有DLLのsourceとtargetを再照合します
		for( const auto &entry : state.entries) {
			// いずれかの保持handle欠損を拒否します
			if( !entry.source.valid() || !entry.target.valid()) {
				return mtdError( ERROR_INVALID_DATA) ;
			}

			// 共有DLL sourceからの最初の再確認診断です
			auto error = mtdVerifyFile( state.api, entry.sourcePath, entry.sourceId,
									   entry.fact.bytes, entry.fact.sha256) ;
			// source確認後に正規targetも原byteへ照合します
			if( error == 0U) {
				error = mtdVerifyFile( state.api, entry.fact.target, entry.targetId,
									  entry.fact.bytes, entry.fact.sha256) ;
			}

			// 共有sourceまたはtargetの変化を元診断で返します
			if( error != 0U) {
				return error ;
			}
		}

		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_FAIL ;
	}
}
} // namespace drivercrate
