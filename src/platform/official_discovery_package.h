//------------------------------------------------------------------------------
/**
 * @file official_discovery_package.h
 * @brief 公式自動探索recordからopaque package実行groupを作る境界。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Record／payload単位の重複排除契約を追加。
 * </pre>
 *
 * @note 本値型はURL、title、版、Hardware ID、instance ID、serial、local pathを保持しません。
 * Package identityは検証済みrecord fingerprint、Provider ID、payload ordinalだけから作ります。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_discovery.h"
#include "platform/official_record_payload_routing.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {

// 一scanの64 routeが各32 payloadを返す場合の固定上限。
inline constexpr std::size_t OFFICIAL_DISCOVERY_PACKAGE_REFERENCE_LIMIT =
	OFFICIAL_DISCOVERY_ROUTE_LIMIT * 32U ;

/**
 * @brief 一つのrouteが解決した検証済みrecord payload参照を表す。
 */
struct OfficialDiscoveryResolvedPackage {
	/// 検証済みrecord fingerprintとpayload ordinalから作ったopaque package ID。
	std::wstring					packageIdentity ;
	/// 秘密recordを後段で一回claimするscan session内の証拠ID。
	std::uint64_t					recordEvidenceId{} ;
	/// Packageを解決したProvider registryのstable ID。
	std::wstring					providerId ;
	/// Providerへ一意に結合した公式source policy ID。
	std::wstring					policyId ;
	/// Recordを解決したlandingまたはmetadata固定root ID。
	std::wstring					rootResourceId ;
	/// URLを除く検証済みrecordのSHA-256。
	OfficialStableRecordFingerprint recordFingerprint ;
	/// Recordが宣言した1以上32以下のpayload総数。
	std::uint32_t					payloadCount{} ;
	/// Record内の0起点payload順序。
	std::uint32_t					payloadOrdinal{} ;
	/// Packageを返した元route ID。
	std::uint64_t					routeId{} ;
	/// 元routeへ結合した重複なしopaque device identity。
	std::vector<std::wstring>		deviceIdentities ;
} ;

/**
 * @brief 同じ検証済みrecord payloadへ到達したrouteとdeviceを一実行単位へまとめる。
 */
struct OfficialDiscoveryPackageGroup {
	/// Groupを識別するopaque package ID。
	std::wstring					packageIdentity ;
	/// Packageを解決したProvider registryのstable ID。
	std::wstring					providerId ;
	/// Providerへ一意に結合した公式source policy ID。
	std::wstring					policyId ;
	/// Recordを解決したlandingまたはmetadata固定root ID。
	std::wstring					rootResourceId ;
	/// URLを除く検証済みrecordのSHA-256。
	OfficialStableRecordFingerprint recordFingerprint ;
	/// Recordが宣言した1以上32以下のpayload総数。
	std::uint32_t					payloadCount{} ;
	/// Record内の0起点payload順序。
	std::uint32_t					payloadOrdinal{} ;
	/// 同一packageへ到達した重複なしrecord証拠ID。
	std::vector<std::uint64_t>		recordEvidenceIds ;
	/// 同一packageへ到達した初出順の重複なしroute ID。
	std::vector<std::uint64_t>		routeIds ;
	/// 同じpayloadを使用する初出順の重複なしopaque device identity。
	std::vector<std::wstring>		deviceIdentities ;
} ;

/**
 * @brief 検証済みrouteとURL非保持payload descriptorをpackage参照へ結合する。
 * @param[in] route 自動探索plannerが作成した元route。
 * @param[in] payload 検証済み公式recordから作ったURL非保持payload descriptor。
 * @param[in] devices 同じinventory snapshotのraw ID非保持device hint集合。
 * @param[in] descriptors Provider registryの正本または同じ合成copy。
 * @return 全bindingが一致する場合のpackage参照。不正または不一致は値なし。
 * @throws std::bad_alloc Opaque identityまたは所有値の領域を確保できない場合。
 */
[[nodiscard]] std::optional<OfficialDiscoveryResolvedPackage> makeOfficialDiscoveryResolvedPackage(
	const OfficialDiscoveryRoute &route, const OfficialRecordPayloadDescriptor &payload,
	std::span<const OfficialDiscoveryDeviceHint> devices,
	std::span<const ProviderDescriptor>			 descriptors) ;

/**
 * @brief 一つのpackage参照がrecord／payload由来だけへ結合しているか検証する。
 * @param[in] package 検証する一route分のpackage参照。
 * @return 全field、opaque ID、device集合が整合する場合true。
 */
[[nodiscard]] bool isOfficialDiscoveryResolvedPackageValid(
	const OfficialDiscoveryResolvedPackage &package) noexcept ;

/**
 * @brief 同じopaque packageを一回の取得・検査単位へまとめる。
 * @param[in] packages Route resolverが返した初出順のpackage参照集合。
 * @return Package初出順の重複排除group。不正、空、上限超過は値なし。
 * @throws std::bad_alloc Groupまたは一意性検査領域を確保できない場合。
 * @note Provider、fingerprint、ordinalが完全一致する場合だけまとめます。Title、版、URLは使用しません。
 */
[[nodiscard]] std::optional<std::vector<OfficialDiscoveryPackageGroup>>
groupOfficialDiscoveryPackages( std::span<const OfficialDiscoveryResolvedPackage> packages) ;

/**
 * @brief 重複排除済みpackage groupの全fieldと一意性を検証する。
 * @param[in] group 検証する一つのpackage実行group。
 * @return Opaque identity、record、route、device集合が整合する場合true。
 */
[[nodiscard]] bool isOfficialDiscoveryPackageGroupValid(
	const OfficialDiscoveryPackageGroup &group) noexcept ;

} // namespace drivercrate
