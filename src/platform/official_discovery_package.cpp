//------------------------------------------------------------------------------
/**
 * @file official_discovery_package.cpp
 * @brief 公式自動探索record payloadのopaque identity生成と重複排除。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Record／payload単位の重複排除を追加。
 * </pre>
 *
 * @note 検証済みrecord fingerprintをopaque package IDへ符号化し、表示metadataから推測しません。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#include "platform/official_discovery_package.h"

#include "core/official_source_policy.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

// Fingerprintをlowercase hexadecimalへ変換する固定alphabet。
constexpr std::wstring_view HEX_DIGITS = L"0123456789abcdef" ;

/**
 * @brief URLやpathを表せない有限ASCII opaque identityか確認する。
 * @param[in] value 検証する文字列。
 * @param[in] maximumCharacters 許可する最大文字数。
 * @return 非空、上限内、限定文字だけの場合true。
 */
[[nodiscard]] bool			isBoundedIdentity( const std::wstring_view value,
											  const std::size_t		  maximumCharacters) noexcept
{
	// 空、過大、埋込みNULをidentityとして受理しない。
	if( value.empty() || value.size() > maximumCharacters ||
	   value.find( L'\0') != std::wstring_view::npos) {
		return false ;
	}

	// 生ID、URL、pathを表しにくい限定ASCIIだけを一文字ずつ確認する。
	for( const wchar_t character : value) {
		const bool alphaNumeric =
			// ASCII英数字の判定。
			(character >= L'a' && character <= L'z') || (character >= L'A' && character <= L'Z') ||
			(character >= L'0' && character <= L'9') ;
		// Opaque IDの区切り以外を含む値を拒否する。
		if( !alphaNumeric && character != L'-' && character != L'_' && character != L'.' &&
		   character != L':') {
			return false ;
		}
	}

	return true ;
}

/**
 * @brief Fingerprintが全zeroの未設定値でないか確認する。
 * @param[in] fingerprint 検証する32 byte値。
 * @return 一byte以上が非zeroの場合true。
 */
[[nodiscard]] bool hasFingerprint( const OfficialStableRecordFingerprint &fingerprint) noexcept
{
	return std::any_of( fingerprint.bytes.begin(), fingerprint.bytes.end(),
					   []( const std::byte value) { return value != std::byte{} ; }) ;
}

/**
 * @brief Provider、record fingerprint、payload ordinalからopaque package IDを作る。
 * @param[in] providerId 検証済みProvider stable ID。
 * @param[in] fingerprint URLを除く検証済みrecord SHA-256。
 * @param[in] payloadOrdinal Record内の0起点payload順序。
 * @return 表示値を含まない決定的なpackage ID。
 * @throws std::bad_alloc 文字列領域を確保できない場合。
 */
[[nodiscard]] std::wstring makePackageIdentity( const std::wstring_view				  providerId,
											   const OfficialStableRecordFingerprint &fingerprint,
											   const std::uint32_t payloadOrdinal)
{
	std::wstring identity = L"official-package:" ;	// 固定namespaceから始めるopaque ID。
	identity.append( providerId) ;
	identity.push_back( L':') ;
	identity.reserve( identity.size() + fingerprint.bytes.size() * 2U + 12U) ;
	// 32 byteを固定64文字へ変換し、元record表示値を含めない。
	for( const std::byte value : fingerprint.bytes) {
		const auto byte = std::to_integer<unsigned int>( value) ;	// 0～255の変換値。
		identity.push_back( HEX_DIGITS[byte >> 4U]) ;
		identity.push_back( HEX_DIGITS[byte & 0x0FU]) ;
	}

	identity.push_back( L':') ;
	identity.append( std::to_wstring( payloadOrdinal)) ;
	return identity ;
}

/**
 * @brief Package groupと一route分参照のstable fieldが完全一致するか確認する。
 * @param[in] group 既存の初出package group。
 * @param[in] package 追加する一route分参照。
 * @return 表示値以外の全package由来が一致する場合true。
 */
[[nodiscard]] bool samePackage( const OfficialDiscoveryPackageGroup	  &group,
							   const OfficialDiscoveryResolvedPackage &package) noexcept
{
	return group.packageIdentity == package.packageIdentity &&
		   group.providerId == package.providerId && group.policyId == package.policyId &&
		   group.rootResourceId == package.rootResourceId &&
		   group.recordFingerprint.bytes == package.recordFingerprint.bytes &&
		   group.payloadCount == package.payloadCount &&
		   group.payloadOrdinal == package.payloadOrdinal ;
}

} // namespace

/** @see official_discovery_package.h */
std::optional<OfficialDiscoveryResolvedPackage> makeOfficialDiscoveryResolvedPackage(
	const OfficialDiscoveryRoute &route, const OfficialRecordPayloadDescriptor &payload,
	const std::span<const OfficialDiscoveryDeviceHint> devices,
	const std::span<const ProviderDescriptor>		   descriptors)
{
	// Routeとrecord descriptorをそれぞれの公開validatorへ通してから相互結合する。
	if( !validateOfficialDiscoveryRoute( route, devices, descriptors) ||
	   !isOfficialRecordPayloadDescriptorValid( payload) || route.providerId != payload.providerId ||
	   route.rootResourceId != payload.rootResourceId) {
		return std::nullopt ;
	}

	const OfficialSourcePolicy *const policy =
		// Providerへ結合した組み込みpolicy。
		officialSourcePolicyForProvider( route.providerId) ;
	// DescriptorのpolicyをProvider正本以外へ差し替えた入力を拒否する。
	if( policy == nullptr || payload.policyId != policy->id) {
		return std::nullopt ;
	}

	OfficialDiscoveryResolvedPackage package ;	// 全照合後に返す一route分参照。
	package.packageIdentity =
		makePackageIdentity( payload.providerId, payload.recordFingerprint, payload.payloadOrdinal) ;
	package.recordEvidenceId  = payload.recordEvidenceId ;
	package.providerId		  = payload.providerId ;
	package.policyId		  = payload.policyId ;
	package.rootResourceId	  = payload.rootResourceId ;
	package.recordFingerprint = payload.recordFingerprint ;
	package.payloadCount	  = payload.payloadCount ;
	package.payloadOrdinal	  = payload.payloadOrdinal ;
	package.routeId			  = route.routeId ;
	package.deviceIdentities  = route.deviceIdentities ;
	// 内部生成値も公開前validatorへ通し、部分的な参照を返さない。
	if( !isOfficialDiscoveryResolvedPackageValid( package)) {
		return std::nullopt ;
	}

	return package ;
}

/** @see official_discovery_package.h */
bool isOfficialDiscoveryResolvedPackageValid(
	const OfficialDiscoveryResolvedPackage &package) noexcept
{
	// Stable field、件数、証拠IDとdevice集合を有限範囲へ限定する。
	if( !isBoundedIdentity( package.providerId, OFFICIAL_DISCOVERY_STABLE_ID_LIMIT) ||
	   !isBoundedIdentity( package.policyId, OFFICIAL_DISCOVERY_STABLE_ID_LIMIT) ||
	   !isBoundedIdentity( package.rootResourceId, OFFICIAL_DISCOVERY_STABLE_ID_LIMIT) ||
	   package.recordEvidenceId == 0U || !hasFingerprint( package.recordFingerprint) ||
	   package.payloadCount == 0U || package.payloadCount > 32U ||
	   package.payloadOrdinal >= package.payloadCount || package.routeId == 0U ||
	   package.deviceIdentities.empty() ||
	   package.deviceIdentities.size() > OFFICIAL_DISCOVERY_DEVICE_LIMIT) {
		return false ;
	}

	const OfficialSourcePolicy *const policy =
		// Providerへ結合した組み込みpolicy。
		officialSourcePolicyForProvider( package.providerId) ;
	const OfficialSourceResourcePolicy *const resource =
		policy == nullptr
			? nullptr
			: findOfficialSourceResource( *policy, package.rootResourceId) ;	// 固定root。
	// Provider、policy、landing／metadata rootの一意な関係を維持する。
	if( policy == nullptr || package.policyId != policy->id || resource == nullptr ||
	   (resource->kind != OfficialSourceResourceKind::LANDING_PAGE &&
		resource->kind != OfficialSourceResourceKind::METADATA)) {
		return false ;
	}

	// 全device identityを限定ASCIIかつ重複なしで検証する。
	for( const std::wstring &deviceIdentity : package.deviceIdentities) {
		// 一件でも不正または重複ならpackage参照全体を拒否する。
		if( !isBoundedIdentity( deviceIdentity, OFFICIAL_DISCOVERY_OPAQUE_ID_LIMIT) ||
		   std::count( package.deviceIdentities.begin(), package.deviceIdentities.end(),
					  deviceIdentity) != 1) {
			return false ;
		}
	}

	try {
		const std::wstring expected =
			makePackageIdentity( package.providerId, package.recordFingerprint,
								package.payloadOrdinal) ;	// Stable fieldからの再生成値。
		return package.packageIdentity == expected &&
			   isBoundedIdentity( package.packageIdentity, OFFICIAL_DISCOVERY_OPAQUE_ID_LIMIT) ;
	} catch( const std::bad_alloc &) {
		// Validatorの領域不足を有効なidentityへ縮退させない。
		return false ;
	}
}

/** @see official_discovery_package.h */
std::optional<std::vector<OfficialDiscoveryPackageGroup>> groupOfficialDiscoveryPackages(
	const std::span<const OfficialDiscoveryResolvedPackage> packages)
{
	// 空入力またはroute×payload上限超過から実行groupを作らない。
	if( packages.empty() || packages.size() > OFFICIAL_DISCOVERY_PACKAGE_REFERENCE_LIMIT) {
		return std::nullopt ;
	}

	std::vector<OfficialDiscoveryPackageGroup> groups ;	// Package初出順の所有結果。
	groups.reserve( packages.size()) ;
	std::unordered_map<std::wstring, std::size_t>  packageIndexes ;		// Opaque ID別group位置。
	std::vector<std::unordered_set<std::uint64_t>> routeIds ;			// Group別route一意性。
	std::vector<std::unordered_set<std::uint64_t>> evidenceIds ;		// Group別record証拠一意性。
	std::vector<std::unordered_set<std::wstring>>  deviceIdentities ;	// Group別device一意性。
	routeIds.reserve( packages.size()) ;
	evidenceIds.reserve( packages.size()) ;
	deviceIdentities.reserve( packages.size()) ;
	// Route順の全参照を検証し、同じpackageだけを初出groupへ集約する。
	for( const OfficialDiscoveryResolvedPackage &package : packages) {
		// 一件でも不正なら部分groupを公開しない。
		if( !isOfficialDiscoveryResolvedPackageValid( package)) {
			return std::nullopt ;
		}

		const auto [position, inserted] =
			// Group位置。
			packageIndexes.try_emplace( package.packageIdentity, groups.size()) ;
		// 初出packageはstable fieldと一意性集合を同時に作る。
		if( inserted) {
			OfficialDiscoveryPackageGroup group ;	// 一つの取得・検査実行単位。
			group.packageIdentity	= package.packageIdentity ;
			group.providerId		= package.providerId ;
			group.policyId			= package.policyId ;
			group.rootResourceId	= package.rootResourceId ;
			group.recordFingerprint = package.recordFingerprint ;
			group.payloadCount		= package.payloadCount ;
			group.payloadOrdinal	= package.payloadOrdinal ;
			group.recordEvidenceIds.push_back( package.recordEvidenceId) ;
			group.routeIds.push_back( package.routeId) ;
			group.deviceIdentities = package.deviceIdentities ;
			groups.push_back( std::move( group)) ;
			routeIds.emplace_back( std::initializer_list<std::uint64_t>{package.routeId}) ;
			evidenceIds.emplace_back(
				std::initializer_list<std::uint64_t>{package.recordEvidenceId}) ;
			deviceIdentities.emplace_back( package.deviceIdentities.begin(),
										  package.deviceIdentities.end()) ;
			continue ;
		}

		OfficialDiscoveryPackageGroup &group = groups[position->second] ;	// 既存の同一ID group。
		// 同じopaque IDへ異なるrecord由来を衝突させず全体拒否する。
		if( !samePackage( group, package) ||
		   !routeIds[position->second].insert( package.routeId).second) {
			return std::nullopt ;
		}

		// 別routeが別record証拠IDで同じstable recordへ到達した場合だけ追加する。
		if( evidenceIds[position->second].insert( package.recordEvidenceId).second) {
			group.recordEvidenceIds.push_back( package.recordEvidenceId) ;
		}

		group.routeIds.push_back( package.routeId) ;
		// 同じpayloadを共有するdeviceを初出順で一度だけ保持する。
		for( const std::wstring &deviceIdentity : package.deviceIdentities) {
			// 別routeで既出のdeviceは重複せず、未出だけを実行結果の対象へ追加する。
			if( deviceIdentities[position->second].insert( deviceIdentity).second) {
				group.deviceIdentities.push_back( deviceIdentity) ;
			}
		}
	}

	// 集約後の全groupを再検証し、一件の不整合でも結果全体を破棄する。
	for( const OfficialDiscoveryPackageGroup &group : groups) {
		// 内部生成値を信用せず公開validatorへ通す。
		if( !isOfficialDiscoveryPackageGroupValid( group)) {
			return std::nullopt ;
		}
	}

	return groups ;
}

/** @see official_discovery_package.h */
bool isOfficialDiscoveryPackageGroupValid( const OfficialDiscoveryPackageGroup &group) noexcept
{
	OfficialDiscoveryResolvedPackage base ;	// 共通fieldを単体validatorへ再利用する合成参照。
	base.packageIdentity   = group.packageIdentity ;
	base.providerId		   = group.providerId ;
	base.policyId		   = group.policyId ;
	base.rootResourceId	   = group.rootResourceId ;
	base.recordFingerprint = group.recordFingerprint ;
	base.payloadCount	   = group.payloadCount ;
	base.payloadOrdinal	   = group.payloadOrdinal ;
	base.deviceIdentities  = group.deviceIdentities ;
	// Group固有集合の空値を単体validatorへ補完しない。
	if( group.recordEvidenceIds.empty() || group.routeIds.empty()) {
		return false ;
	}

	base.recordEvidenceId = group.recordEvidenceIds.front() ;
	base.routeId		  = group.routeIds.front() ;
	// Stable fieldまたはdevice集合の不正を先に拒否する。
	if( !isOfficialDiscoveryResolvedPackageValid( base)) {
		return false ;
	}

	// 全record証拠IDを非zeroかつ重複なしに限定する。
	for( const std::uint64_t evidenceId : group.recordEvidenceIds) {
		// 0または重複IDを一つのclaim候補として受理しない。
		if( evidenceId == 0U || std::count( group.recordEvidenceIds.begin(),
										  group.recordEvidenceIds.end(), evidenceId) != 1) {
			return false ;
		}
	}

	// 全route IDを非zeroかつ重複なしに限定する。
	for( const std::uint64_t routeId : group.routeIds) {
		// 一routeが同じpayloadを二重報告したgroupを拒否する。
		if( routeId == 0U ||
		   std::count( group.routeIds.begin(), group.routeIds.end(), routeId) != 1) {
			return false ;
		}
	}

	return true ;
}

} // namespace drivercrate
