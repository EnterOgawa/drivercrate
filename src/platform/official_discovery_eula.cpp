//------------------------------------------------------------------------------
/**
 * @file official_discovery_eula.cpp
 * @brief 公式自動探索payloadのEULA完全一致groupと短命同意tokenを実装する。
 * @version 01.00.00
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  EULA完全一致groupと短命同意tokenを実装。
 * </pre>
 *
 * @note SHA-256はWindows CNGで計算し、EULA本文、hash、tokenをdiskまたはlogへ出力しません。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#include "platform/official_discovery_eula.h"

#include "core/official_preparation.h"

#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

// 一payloadへ許可するADR 0157の検査用取得上限。
constexpr std::uint64_t	  MAXIMUM_PACKAGE_BYTES = 128ULL * 1'024ULL * 1'024ULL ;
// EULA revisionに許可する有限UTF-16 code unit数。
constexpr std::size_t	  MAXIMUM_EULA_REVISION_CHARACTERS = 1'024U ;
// Stable Providerまたはpackage IDに許可する文字数。
constexpr std::size_t	  MAXIMUM_STABLE_ID_CHARACTERS = 256U ;

// 入力またはsession結合違反を表すHRESULT bit pattern。
constexpr NativeError	  INVALID_ARGUMENT = static_cast<NativeError>( E_INVALIDARG) ;
// 一時領域または所有snapshotの確保失敗を表すHRESULT bit pattern。
constexpr NativeError	  OUT_OF_MEMORY = static_cast<NativeError>( E_OUTOFMEMORY) ;
// C++境界の未知例外を表すHRESULT bit pattern。
constexpr NativeError	  UNEXPECTED_FAILURE = static_cast<NativeError>( E_UNEXPECTED) ;

/**
 * @brief Win32 errorをHRESULT bit patternへ変換する。
 * @param[in] error 変換するWin32 error code。
 * @return NativeErrorで保持するHRESULT bit pattern。
 */
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

/**
 * @brief CNGのNTSTATUSをHRESULT bit patternへ変換する。
 * @param[in] status BCrypt APIが返したNTSTATUS。
 * @return NativeErrorで保持するHRESULT bit pattern。
 */
[[nodiscard]] NativeError nativeErrorFromNt( const NTSTATUS status) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
}

/**
 * @brief Stable IDとして使用できる有限ASCII文字列か検証する。
 * @param[in] value Providerまたはopaque package ID。
 * @return 空、過大、制御文字、非ASCIIを含まない場合true。
 */
[[nodiscard]] bool isStableId( const std::wstring_view value) noexcept
{
	// 空または上限外の文字列をidentityとして受理しない。
	if( value.empty() || value.size() > MAXIMUM_STABLE_ID_CHARACTERS) {
		return false ;
	}

	// ASCIIの表示可能文字だけを確認し、本文やURLをIDへ混入させない。
	for( const wchar_t character : value) {
		// 制御文字または非ASCII値をopaque IDとして扱わない。
		if( character < 0x21 || character > 0x7e) {
			return false ;
		}
	}

	return true ;
}

/**
 * @brief EULA revisionを有限plain textとして検証する。
 * @param[in] value Providerが明示したrevision。
 * @return 空、過大、制御文字、壊れたsurrogateを含まない場合true。
 */
[[nodiscard]] bool isEulaRevision( const std::wstring_view value) noexcept
{
	// Revisionは共有keyなので欠損や大きすぎる値を許可しない。
	if( value.empty() || value.size() > MAXIMUM_EULA_REVISION_CHARACTERS) {
		return false ;
	}

	// 改行を含まない表示可能値と正しいsurrogate pairだけを受理する。
	for( std::size_t index = 0U; index < value.size(); ++index) {
		const wchar_t character = value[index] ;	// 現在検証するUTF-16 code unit。
		// 制御文字、単独low surrogate、範囲外値をrevisionへ含めない。
		if( character < 0x20 || (character >= 0xdc00 && character <= 0xdfff)) {
			return false ;
		}

		// High surrogateは直後のlow surrogateと一組の場合だけ読み進める。
		if( character >= 0xd800 && character <= 0xdbff) {
			// 終端または非low surrogateなら壊れたUTF-16として拒否する。
			if( index + 1U >= value.size() || value[index + 1U] < 0xdc00 ||
			   value[index + 1U] > 0xdfff) {
				return false ;
			}

			++index ;
		}
	}

	return true ;
}

/**
 * @brief UTF-16全文を厳格なUTF-8 byte列へ変換する。
 * @param[in] text 有限検証済みのEULA全文。
 * @param[out] utf8 成功時だけ全文のUTF-8 byte列。
 * @return 成功時0、変換不能または領域不足時はHRESULT bit pattern。
 */
[[nodiscard]] NativeError toUtf8( const std::wstring_view text,
								 std::vector<std::byte> &utf8) noexcept
{
	utf8.clear() ;
	// Win32 APIのsigned文字数へ変換できない入力を渡さない。
	if( text.empty() || text.size() > static_cast<std::size_t>( std::numeric_limits<int>::max())) {
		return INVALID_ARGUMENT ;
	}

	const int inputCharacters = static_cast<int>( text.size()) ;	// 検証済みのUTF-16文字数。
	const int requiredBytes =
		WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), inputCharacters, nullptr, 0,
							nullptr, nullptr) ;	// 必要byte数。
	// 壊れたUTF-16または変換失敗では空hashを作らない。
	if( requiredBytes <= 0) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	try {
		utf8.resize( static_cast<std::size_t>( requiredBytes)) ;
	} catch( const std::bad_alloc &) {
		return OUT_OF_MEMORY ;
	} catch( ...) {
		return UNEXPECTED_FAILURE ;
	}

	// Win32宣言がchar出力を要求するため、byte storageを境界でだけ変換する。
	const int converted =
		WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), inputCharacters,
							reinterpret_cast<char *>( utf8.data()), requiredBytes, nullptr, nullptr) ;
	// 事前計測と変換結果が一致しない場合は部分byte列を破棄する。
	if( converted != requiredBytes) {
		utf8.clear() ;
		return nativeErrorFromWin32( GetLastError()) ;
	}

	return 0 ;
}

/**
 * @brief UTF-8 byte列のSHA-256をWindows CNGで計算する。
 * @param[in] bytes UTF-8化したEULA全文。
 * @param[out] hash 成功時だけ32 byte SHA-256。
 * @return 成功時0、CNG失敗時はHRESULT bit pattern。
 */
[[nodiscard]] NativeError hashSha256( const std::span<const std::byte> bytes,
									 std::array<std::byte, 32U>		 &hash) noexcept
{
	hash.fill( std::byte{}) ;
	// BCryptHashのULONG入力上限へ変換できないbyte列を渡さない。
	if( bytes.empty() ||
	   bytes.size() > static_cast<std::size_t>( std::numeric_limits<ULONG>::max())) {
		return INVALID_ARGUMENT ;
	}

	BCRYPT_ALG_HANDLE rawAlgorithm{} ;	// 成功時にRAIIへ移すalgorithm handle。
	// SHA-256 Algorithm Providerを開いた結果。
	const NTSTATUS	  openStatus =
		BCryptOpenAlgorithmProvider( &rawAlgorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) ;
	// Algorithm Providerを開けない場合はhashを公開しない。
	if( openStatus < 0) {
		return nativeErrorFromNt( openStatus) ;
	}

	const auto closeAlgorithm = []( void *value) noexcept {
		// 非null handleだけをCNGへ返す。
		if( value != nullptr) {
			static_cast<void>(
				BCryptCloseAlgorithmProvider( static_cast<BCRYPT_ALG_HANDLE>( value), 0)) ;
		}
	} ; // Scope終了時にalgorithm handleを必ず閉じる。
	const std::unique_ptr<void, decltype( closeAlgorithm)> algorithm(
		rawAlgorithm, closeAlgorithm) ;	// CNG algorithm handleの所有者。
	// BCryptHashは入力を変更しないがWindows宣言がmutable pointerを要求する。
	const NTSTATUS hashStatus =
		BCryptHash( static_cast<BCRYPT_ALG_HANDLE>( algorithm.get()), nullptr, 0U,
				   reinterpret_cast<PUCHAR>( const_cast<std::byte *>( bytes.data())),
				   static_cast<ULONG>( bytes.size()), reinterpret_cast<PUCHAR>( hash.data()),
				   static_cast<ULONG>( hash.size())) ;
	// Hash失敗時は部分digestを残さない。
	if( hashStatus < 0) {
		hash.fill( std::byte{}) ;
		return nativeErrorFromNt( hashStatus) ;
	}

	return 0 ;
}

/**
 * @brief EULA全文をUTF-8化してSHA-256を計算する。
 * @param[in] text 検証済みplain text全文。
 * @param[out] hash 成功時だけ32 byte SHA-256。
 * @return 成功時0、変換またはCNG失敗時はHRESULT bit pattern。
 */
[[nodiscard]] NativeError eulaTextHash( const std::wstring_view	   text,
									   std::array<std::byte, 32U> &hash) noexcept
{
	std::vector<std::byte> utf8 ;									// Hash計算中だけ所有する全文UTF-8 byte列。
	const NativeError	   conversionError = toUtf8( text, utf8) ;	// 厳格変換結果。
	// 変換失敗ではCNGへ空または部分入力を渡さない。
	if( conversionError != 0) {
		return conversionError ;
	}

	return hashSha256( utf8, hash) ;
}

/**
 * @brief 一つのEULA package snapshotをgroup化可能か検証する。
 * @param[in] package 検証する一payload。
 * @return ID、revision、本文、予約byte数が全て有限な場合true。
 */
[[nodiscard]] bool isValidPackage( const OfficialDiscoveryEulaPackage &package) noexcept
{
	return isStableId( package.packageIdentity) && isStableId( package.providerId) &&
		   isEulaRevision( package.eulaRevision) && validPreparationEulaText( package.eulaText) &&
		   package.maximumBytes != 0U && package.maximumBytes <= MAXIMUM_PACKAGE_BYTES ;
}

/**
 * @brief Tokenが現在bindingとgroup indexへ一致するか検証する。
 * @param[in] binding 現在有効なsession binding。
 * @param[in] token 照合する短命token。
 * @param[in] groupCount 現在sessionのgroup件数。
 * @return Bindingと1始まりtoken値が有効な場合true。
 */
[[nodiscard]] bool isCurrentToken( const OfficialDiscoveryBinding		&binding,
								  const OfficialDiscoveryEulaGroupToken &token,
								  const std::size_t						 groupCount) noexcept
{
	return token.binding == binding && token.value != 0U && token.value <= groupCount ;
}

} // namespace

/** @see official_discovery_eula.h */
NativeError OfficialDiscoveryEulaSession::beginSession(
	const OfficialDiscoveryBinding					   &binding,
	const std::span<const OfficialDiscoveryEulaPackage> packages) noexcept
{
	invalidate() ;
	// Stale、空、予算外件数を受理せず旧sessionの本文と判断も残さない。
	if( !isOfficialDiscoveryBindingValid( binding) || binding.operationId <= latestOperationId_ ||
	   binding.scanSessionId <= latestScanSessionId_ ||
	   packages.size() > OFFICIAL_DISCOVERY_EULA_PACKAGE_LIMIT) {
		return INVALID_ARGUMENT ;
	}

	try {
		std::vector<OfficialDiscoveryEulaPackage> newPackages ;	// 全検証後にcommitする所有copy。
		std::vector<OfficialDiscoveryEulaGroup>	  newGroups ;	// 全検証後にcommitするgroup集合。
		newPackages.reserve( packages.size()) ;
		newGroups.reserve( packages.size()) ;
		// 入力順を維持し、同じpackage IDの二重同意対象化を拒否する。
		for( const OfficialDiscoveryEulaPackage &package : packages) {
			// 不正snapshotまたは重複packageを部分groupへ変換しない。
			if( !isValidPackage( package) ||
			   std::any_of( newPackages.begin(), newPackages.end(),
						   [&package]( const OfficialDiscoveryEulaPackage &existing) {
							   return existing.packageIdentity == package.packageIdentity ;
						   })) {
				return INVALID_ARGUMENT ;
			}

			std::array<std::byte, 32U> hash{} ;	// UTF-8本文の完全一致group key。
			// 現在packageのUTF-8全文を固定するhash計算結果。
			const NativeError		   hashError = eulaTextHash( package.eulaText, hash) ;
			// Hash不能な本文をrevisionだけで共有しない。
			if( hashError != 0) {
				return hashError ;
			}

			const auto existingGroup =
				std::find_if( newGroups.begin(), newGroups.end(),
							 [&package, &hash]( const OfficialDiscoveryEulaGroup &group) {
								 return group.providerId == package.providerId &&
										group.eulaRevision == package.eulaRevision &&
										group.eulaTextSha256 == hash ;
							 }) ; // Provider、revision、UTF-8全文SHA-256が完全一致するgroup。
			// 初出keyは新しいtokenと本文を所有するgroupとして追加する。
			if( existingGroup == newGroups.end()) {
				const std::uint64_t tokenValue =
					// 1始まりtoken値。
					static_cast<std::uint64_t>( newGroups.size()) + 1U ;
				newGroups.push_back( {.token				= {.binding = binding, .value = tokenValue},
									 .providerId		= package.providerId,
									 .eulaRevision		= package.eulaRevision,
									 .eulaText			= package.eulaText,
									 .eulaTextSha256	= hash,
									 .packageIdentities = {package.packageIdentity},
									 .maximumTotalBytes = package.maximumBytes}) ;
			} else {
				// 合計上限をoverflowさせるgroupへ対象を追加しない。
				if( existingGroup->maximumTotalBytes >
				   std::numeric_limits<std::uint64_t>::max() - package.maximumBytes) {
					return INVALID_ARGUMENT ;
				}

				existingGroup->packageIdentities.push_back( package.packageIdentity) ;
				existingGroup->maximumTotalBytes += package.maximumBytes ;
			}

			newPackages.push_back( package) ;
		}

		packages_ = std::move( newPackages) ;
		groups_	  = std::move( newGroups) ;
		decisions_.assign( groups_.size(), Decision::PENDING) ;
		binding_			 = binding ;
		latestOperationId_	 = binding.operationId ;
		latestScanSessionId_ = binding.scanSessionId ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		invalidate() ;
		return OUT_OF_MEMORY ;
	} catch( ...) {
		invalidate() ;
		return UNEXPECTED_FAILURE ;
	}
}

/** @see official_discovery_eula.h */
NativeError OfficialDiscoveryEulaSession::recordDecision(
	const OfficialDiscoveryBinding &binding, const OfficialDiscoveryEulaGroupToken &token,
	const bool accepted) noexcept
{
	// Staleまたは未知tokenを現在groupへ位置だけで対応付けない。
	if( binding != binding_ || !isCurrentToken( binding_, token, groups_.size()) ||
	   decisions_.size() != groups_.size()) {
		return INVALID_ARGUMENT ;
	}

	const std::size_t index = static_cast<std::size_t>( token.value - 1U) ;	// 検証済みgroup index。
	// 一度記録した許可または拒否を後の呼出しで反転させない。
	if( decisions_[index] != Decision::PENDING) {
		return nativeErrorFromWin32( ERROR_ALREADY_EXISTS) ;
	}

	decisions_[index] = accepted ? Decision::ACCEPTED : Decision::REJECTED ;
	return 0 ;
}

/** @see official_discovery_eula.h */
bool OfficialDiscoveryEulaSession::isPackageAccepted(
	const OfficialDiscoveryBinding &binding, const OfficialDiscoveryEulaGroupToken &token,
	const OfficialDiscoveryEulaPackage &package) const noexcept
{
	// Stale、未知、未判断、拒否済みgroupへ取得許可を返さない。
	if( binding != binding_ || !isCurrentToken( binding_, token, groups_.size()) ||
	   decisions_.size() != groups_.size()) {
		return false ;
	}

	const std::size_t index = static_cast<std::size_t>( token.value - 1U) ;	// 検証済みgroup index。
	// 明示許可されていないgroupを同意済みにしない。
	if( decisions_[index] != Decision::ACCEPTED || !isValidPackage( package)) {
		return false ;
	}

	const auto original = std::find_if( packages_.begin(), packages_.end(),
									   [&package]( const OfficialDiscoveryEulaPackage &value) {
										   return value.packageIdentity == package.packageIdentity ;
									   }) ; // 開始時の同じopaque package snapshot。
	// Package ID、Provider、revision、本文、予算のどれかが変化した取得を拒否する。
	if( original == packages_.end() || *original != package) {
		return false ;
	}

	const OfficialDiscoveryEulaGroup &group = groups_[index] ;	// 利用者が許可した完全一致group。
	// Packageが別group tokenへ差し替えられていないことを確認する。
	if( std::find( group.packageIdentities.begin(), group.packageIdentities.end(),
				 package.packageIdentity) == group.packageIdentities.end() ||
	   group.providerId != package.providerId || group.eulaRevision != package.eulaRevision) {
		return false ;
	}

	std::array<std::byte, 32U> currentHash{} ;	// 取得直前本文の再計算SHA-256。
	// Hash計算不能または開始時groupと不一致なら同意を失効扱いにする。
	return eulaTextHash( package.eulaText, currentHash) == 0 && currentHash == group.eulaTextSha256 ;
}

/** @see official_discovery_eula.h */
std::span<const OfficialDiscoveryEulaGroup> OfficialDiscoveryEulaSession::groups() const noexcept
{
	return groups_ ;
}

/** @see official_discovery_eula.h */
void OfficialDiscoveryEulaSession::invalidate() noexcept
{
	binding_ = {} ;
	packages_.clear() ;
	groups_.clear() ;
	decisions_.clear() ;
}

/** @see official_discovery_eula.h */
OfficialDiscoveryBinding OfficialDiscoveryEulaSession::activeBinding() const noexcept
{
	return binding_ ;
}

} // namespace drivercrate
