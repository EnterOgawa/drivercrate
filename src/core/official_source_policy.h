//------------------------------------------------------------------------------
/**
 * @file official_source_policy.h
 * @brief 公式取得元policy registry定義。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  ASIXの二page・配布物policyをrevision 2へ更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernetの取得前提確認と選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Focusrite公式取得元を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Wacom Windows公式取得元を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Ricoh PCL6公式取得元を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  NVIDIA WinOF-2取得元を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  ASIX AX88179A表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Intel Ethernet Server検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Broadcomの選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  共通配布情報とIntel公式検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  NetXtreme-E表示専用検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公式2経路とfamily別予算を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  CP210x公式取得とserial共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  公式serial取得と新版受入境界を更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Opaque origin経路契約追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  AMD公式Web取得元追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASUS公式取得元追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASRock公式取得元追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の固定起点を共通policyへ登録。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Intel Ethernet Windows 11取得元を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/23  製品registryと独立した取得専用開発sourceを追加。
 * </pre>
 *
 * @note 公式取得元の用途別policyを宣言します。登録だけを取得同意・導入許可とはしません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstdint>
#include <span>
#include <string_view>

namespace drivercrate {

// 製品scanに登録しないIntel EXE取得評価専用のidentity。
inline constexpr std::wstring_view INTEL_DOWNLOAD_DEVELOPMENT_PROVIDER_ID =
	L"intel-download-development" ;
// 既存Intel製品policyを流用しない独立した取得専用policy。
inline constexpr std::wstring_view INTEL_DOWNLOAD_DEVELOPMENT_POLICY_ID =
	L"intel-download-development-v1" ;

inline constexpr std::wstring_view PROLIFIC_OFFICIAL_SOURCE_POLICY_ID =
	L"prolific-origin-v1" ;	// Prolific製品pageとDCHU ZIPの公式origin policy。
inline constexpr std::wstring_view SILICON_LABS_OFFICIAL_SOURCE_POLICY_ID =
	L"silicon-labs-origin-v1" ;	// CP210x製品page、JSON、公開ZIPの公式origin policy。
inline constexpr std::wstring_view WCH_OFFICIAL_SOURCE_POLICY_ID =
	L"wch-origin-v1" ;	// CH341SER page、公開JSON、file hostの公式origin policy。
inline constexpr std::wstring_view WCH_MULTI_OFFICIAL_SOURCE_POLICY_ID =
	L"wch-multi-origin-v1" ;	// CH343SER page、公開JSON、file hostの公式origin policy。

//------------------------------------------------------------------------------
// 公式取得元policy ID定義。
//------------------------------------------------------------------------------

inline constexpr std::wstring_view NVIDIA_OFFICIAL_SOURCE_POLICY_ID =
	L"nvidia-official-sources" ;	// NVIDIA公式network Providerのpolicy ID。
inline constexpr std::wstring_view DELL_OFFICIAL_SOURCE_POLICY_ID =
	L"dell-official-sources" ;	// Dell PC公式network Providerのpolicy ID。
inline constexpr std::wstring_view DELL_POWER_EDGE_OFFICIAL_SOURCE_POLICY_ID =
	L"dell-poweredge-official-sources" ;	// Dell PowerEdge Providerのpolicy ID。
inline constexpr std::wstring_view LENOVO_OFFICIAL_SOURCE_POLICY_ID =
	L"lenovo-official-sources" ;	// Lenovo公式network Providerのpolicy ID。
inline constexpr std::wstring_view HP_OFFICIAL_SOURCE_POLICY_ID =
	L"hp-official-sources" ;	// HP公式network Providerのpolicy ID。
inline constexpr std::wstring_view VAIO_OFFICIAL_SOURCE_POLICY_ID =
	L"vaio-official-sources" ;	// VAIO公式network Providerのpolicy ID。
inline constexpr std::wstring_view AMD_OFFICIAL_SOURCE_POLICY_ID =
	L"amd-official-sources" ;	// AMD表示専用network Providerのpolicy ID。
inline constexpr std::wstring_view ASUS_OFFICIAL_SOURCE_POLICY_ID =
	L"asus-official-sources" ;	// ASUS公式support page Providerのpolicy ID。
inline constexpr std::wstring_view ASROCK_OFFICIAL_SOURCE_POLICY_ID =
	L"asrock-official-sources" ;	// ASRock表示専用network Providerのpolicy ID。
inline constexpr std::wstring_view BROADCOM_OFFICIAL_SOURCE_POLICY_ID =
	L"broadcom-netxtreme-e-origin-v1" ;	// 公開製品・EULA情報と承認済みZIP取得のpolicy ID。
inline constexpr std::wstring_view INTEL_WIFI_OFFICIAL_SOURCE_POLICY_ID =
	L"intel-wifi-origin-v1" ;	// Intel Wi-Fiの公開pageのみを扱うpolicy ID。
inline constexpr std::wstring_view INTEL_ETHERNET_SERVER2025_OFFICIAL_SOURCE_POLICY_ID =
	L"intel-ethernet-server-2025-origin-v2" ;	// Server 2025配布pageと承認済みZIPのpolicy ID。
inline constexpr std::wstring_view INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID =
	L"intel-ethernet-windows11-origin-v1" ;	// Windows 11配布pageと検査用ZIPのpolicy ID。
inline constexpr std::wstring_view ASIX_OFFICIAL_SOURCE_POLICY_ID =
	L"asix-ax88179a-origin-v2" ;	// AX88179A製品・Terms・承認済みZIP取得のpolicy ID。
inline constexpr std::wstring_view RICOH_UNIVERSAL_PRINT_OFFICIAL_SOURCE_POLICY_ID =
	L"ricoh-universal-print-origin-v1" ;	// Ricoh PCL6配布pageだけを扱う表示専用policy ID。
inline constexpr std::wstring_view WACOM_WINDOWS_OFFICIAL_SOURCE_POLICY_ID =
	L"wacom-windows-origin-v1" ;	// Wacom Windows配布pageだけを扱う表示専用policy ID。
inline constexpr std::wstring_view FOCUSRITE_SCARLETT2I2_OFFICIAL_SOURCE_POLICY_ID =
	L"focusrite-scarlett-2i2-origin-v1" ;	// 固定製品pageだけを扱う表示専用policy ID。
inline constexpr std::wstring_view NVIDIA_WINOF2_OFFICIAL_SOURCE_POLICY_ID =
	L"nvidia-winof2-origin-v1" ;	// WinOF-2製品pageとmetadata POSTの公式origin policy ID。

//------------------------------------------------------------------------------
// 公式resource ID定義。
//------------------------------------------------------------------------------

inline constexpr std::wstring_view OFFICIAL_LANDING_RESOURCE_ID =
	L"landing" ;	// 公式取得起点pageのresource ID。
inline constexpr std::wstring_view OFFICIAL_PRIMARY_METADATA_RESOURCE_ID =
	L"metadata-primary" ;	// 主metadataのresource ID。
inline constexpr std::wstring_view OFFICIAL_SECONDARY_METADATA_RESOURCE_ID =
	L"metadata-secondary" ;	// 補助metadataのresource ID。
inline constexpr std::wstring_view OFFICIAL_DETACHED_SIGNATURE_RESOURCE_ID =
	L"detached-signature" ;	// 分離署名のresource ID。
inline constexpr std::wstring_view OFFICIAL_PAYLOAD_RESOURCE_ID =
	L"payload" ;	// 配布fileのresource ID。

/**
 * @brief 公式originを利用するresourceの用途を表す。
 */
enum class OfficialSourceResourceKind {
	/// 人またはProviderがtrust chainを開始する公式page。
	LANDING_PAGE,
	/// Candidate探索または適用性判定に使用するmetadata。
	METADATA,
	/// Metadataと別に取得する署名resource。
	DETACHED_SIGNATURE,
	/// 検査またはinstall対象となる配布file。
	PAYLOAD,
} ;

/**
 * @brief 一つの公式resourceへ許可するhostとredirect上限を表す。
 */
struct OfficialSourceResourcePolicy {
	/// Policy内で重複しないASCII resource ID。
	std::wstring_view				   id ;
	/// Resourceの監査用途。
	OfficialSourceResourceKind		   kind{} ;
	/// 完全一致hostまたは先頭dot付きdomain suffixの組み込みallowlist。
	std::span<const std::wstring_view> allowedHosts ;
	/// 起点を含まない許可redirect回数。0の場合はredirectを拒否する。
	std::uint32_t					   maximumRedirects{} ;
} ;

/** @brief 情報検索専用の固定起点。任意の同host pathへ展開しない。 */
struct OfficialMetadataEndpoint {
	/// 同じpolicy内のlandingまたはmetadata resource ID。
	std::wstring_view resourceId ;
	/// 固定GETの完全なHTTPS URL。UI・log・reportへは渡さない。
	std::wstring_view url ;
} ;

/**
 * @brief 一つの公式network Providerへ対応する組み込みorigin policyを表す。
 */
struct OfficialSourcePolicy {
	/// Application内で安定したpolicy ID。
	std::wstring_view							  id ;
	/// Provider registryのstable ID。
	std::wstring_view							  providerId ;
	/// Landing、metadata、署名、payload等の用途別resource policy。
	std::span<const OfficialSourceResourcePolicy> resources ;
	/// 専用metadata検索の固定起点。通常の任意resource APIへ許可を広げない。
	std::span<const OfficialMetadataEndpoint>	  metadataEndpoints ;
} ;

/**
 * @brief Applicationへ組み込んだ公式取得元policyを登録順で返す。
 * 組み込み公式取得元policyを返す。
 * NetworkまたはAIから変更できないcompile-time registryを返す。
 * @return Process lifetime中有効なpolicy群。
 */
[[nodiscard]] std::span<const OfficialSourcePolicy> builtInOfficialSourcePolicies() noexcept ;

/**
 * @brief Stable policy IDに対応する組み込み公式取得元policyを検索する。
 * Stable IDから公式取得元policyを検索する。
 * 表示名、URLまたは部分一致からpolicyを推測しない。
 * @param[in] policyId 検索する空でないpolicy ID。 検索するpolicy ID。
 * @return 一致したprocess lifetime中有効なpolicy。未登録時はnullptr。 一致policy。未登録の場合はnullptr。
 */
[[nodiscard]] const OfficialSourcePolicy		   *findOfficialSourcePolicy(
			  std::wstring_view policyId) noexcept ;

/**
 * @brief Provider IDに対応する組み込み公式取得元policyを検索する。
 * Provider IDから公式取得元policyを検索する。
 * 一つのProviderに一つだけ存在する検証済みpolicyを返す。
 * @param[in] providerId Provider registryのstable ID。
 * @return 一致したprocess lifetime中有効なpolicy。未登録時はnullptr。 一致policy。未登録の場合はnullptr。
 */
[[nodiscard]] const OfficialSourcePolicy *officialSourcePolicyForProvider(
	std::wstring_view providerId) noexcept ;

/**
 * @brief 正本policyから専用metadataの固定起点を取得する。
 * @param[in] providerId 正本のstable Provider ID。
 * @param[in] resourceId 当該policyの用途別resource ID。
 * @return Process寿命の固定URL。未登録は空であり、通常URLへfallbackしない。
 */
[[nodiscard]] std::wstring_view officialMetadataEndpoint( std::wstring_view providerId,
														 std::wstring_view resourceId) noexcept ;

/**
 * @brief Policy内のstable resource IDに対応するresource policyを検索する。
 * Policy内resourceをstable IDで検索する。
 * Resource表示用途またはhostから別resourceを推測しない。
 * @param[in] policy 検索対象の組み込みまたはtest用policy。 検索対象policy。
 * @param[in] resourceId 検索する空でないresource ID。 検索するresource ID。
 * @return 一致したpolicy内resource。未登録時はnullptr。 一致resource。未登録の場合はnullptr。
 */
[[nodiscard]] const OfficialSourceResourcePolicy *findOfficialSourceResource(
	const OfficialSourcePolicy &policy, std::wstring_view resourceId) noexcept ;

/**
 * @brief Providerと公式取得元policy registryの一対一関係を検証する。
 * Providerと公式取得元policy registryを検証する。
 * 未登録、重複、network capability不一致をfail-closedにする。
 * @param[in] policies 検証する公式取得元policy群。 検証するpolicy群。
 * @param[in] providers 検証するProvider定義群。 対応Provider定義群。
 * @return ID、host、resource、Provider対応が全て有効な場合は`true`。 全構造と一対一対応が有効な場合は`true`。
 */
[[nodiscard]] bool validateOfficialSourcePolicies(
	std::span<const OfficialSourcePolicy> policies,
	std::span<const ProviderDescriptor>	  providers) noexcept ;

/**
 * @brief 組み込み公式取得元policy registryの整合性を検証する。
 * 組み込み公式取得元policy registryを検証する。
 * Runtime入力を受けずcompile-time registry全体を検証する。
 * @return 組み込みProviderとの一対一関係を含めて有効な場合は`true`。 組み込みProviderとの整合性を満たす場合は`true`。
 */
[[nodiscard]] bool								 validateBuiltInOfficialSourcePolicies() noexcept ;

/**
 * @brief Providerとresource IDに対応する公式host allowlistを返す。
 * Provider resourceの公式host allowlistを返す。
 * Provider内にhost定数を複製せず、用途別最小allowlistを返す。
 * @param[in] providerId Provider registryのstable ID。
 * @param[in] resourceId Provider policy内のstable resource ID。 Policy内のstable resource ID。
 * @return Process lifetime中有効なhost群。未登録または不整合時は空span。 登録済みhost群。不正または未登録の場合は空span。
 */
[[nodiscard]] std::span<const std::wstring_view> officialSourceHosts(
	std::wstring_view providerId, std::wstring_view resourceId) noexcept ;

/**
 * @brief Scan session内の取得根拠が組み込みpolicyと一致するか検証する。
 * Opaqueな公式取得根拠を組み込みpolicyへ照合する。
 * 未登録IDとredirect上限超過を候補またはUIへ渡さない。
 * @param[in] evidence URLまたはhostを含まない取得根拠。 URLとhostを含まない取得根拠。
 * @return Session、Provider、policy、resource、redirect回数とorigin列が有効なら`true`。 Sessionとpolicy境界が全て有効な場合は
 *         `true`。
 */
[[nodiscard]] bool isValidOfficialSourceEvidence( const OfficialSourceEvidence &evidence) noexcept ;

} // namespace drivercrate
