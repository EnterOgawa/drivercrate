//------------------------------------------------------------------------------
/**
 * @file official_release_metadata.cpp
 * @brief 公式配布情報の取得と系列照合。
 * @version 01.04.01
 * @date 2026/09/05
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  ASIXのTerms結合recordへ観測revisionを同期。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  観測SHA-256をlowercase正規形へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernetの取得前提確認と選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernetの許諾snapshotを結合。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Focusrite Scarlett 2i2検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Wacom Windows配布情報検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Ricoh Universal Print検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  ASIX配布IDのRelease観測を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Release観測生成を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Intel Ethernet Server検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Broadcomの選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  共通配布情報と検索接続を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Intel Ethernet Windows 11 record解析を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  Windows 11 recordを正式検索定義へ接続。
 * Ver.01.03.00 Shunji Ogawa  2026/09/23  Wi-Fi ZIPの同一buttonへEULA本文を結合。
 * Ver.01.04.00 Shunji Ogawa  2026/09/28  収集専用Intel解析へ制御を伝播し旧field変換を共用。
 * Ver.01.04.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 系列ごとの有限な公式metadataを扱います。Broadcomの二文書解析は専用Providerへ委譲します。
 */
//------------------------------------------------------------------------------

#include "platform/official_release_metadata.h"

#include "core/official_source_policy.h"
#include "core/metadata_search_budget.h"
#include "core/provider_registry.h"
#include "platform/broadcom_catalog_parser.h"
#include "platform/focusrite_download_page_parser.h"
#include "platform/intel_ethernet_server_page_parser.h"
#include "platform/intel_download_license_parser.h"
#include "platform/intel_wireless_page_parser.h"
#include "platform/official_serial_provider.h"
#include "platform/ricoh_universal_print_page_parser.h"
#include "platform/silicon_labs_catalog_parser.h"
#include "platform/wacom_driver_page_parser.h"
#include "platform/wch_catalog_parser.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {
constexpr std::size_t	MAXIMUM_DISPLAY_CHARACTERS = 512U ;						// Local probeへ渡す表示値の上限。
constexpr std::uint64_t MAXIMUM_METADATA_BYTES	   = 2ULL * 1024ULL * 1024ULL ;	// 各pageの受信上限。
constexpr std::uint32_t WINDOWS_SERVER2025_BUILD =
	26100U ;	// Microsoft公開のServer 2025 major build。
constexpr std::array RICOH_SUPPORTED_SERVER_BUILDS{
	14393U, 17763U, 20348U, 26100U} ;	// 公式pageが明示するServer 2016～2025のmajor build。
constexpr std::array INTEL_ETHERNET_SERIES{
	std::wstring_view( L"I210"), std::wstring_view( L"I219"), std::wstring_view( L"I225"),
	std::wstring_view( L"I226"), std::wstring_view( L"I350"), std::wstring_view( L"X550"),
	std::wstring_view( L"X710"), std::wstring_view( L"XL710"), std::wstring_view( L"XXV710"),
	std::wstring_view( L"E610"), std::wstring_view( L"E810"), std::wstring_view( L"E830"),
	// 公式page掲載の製品系列token。
	std::wstring_view( L"E835"), std::wstring_view( L"V710")} ;

//------------------------------------------------------------------------------
/**
 * @brief Win32引数へのnarrowing前に上限を検証する。
 *
 * @param[in] left 有限長の比較元。
 * @param[in] right 期待するclassまたは系列表示。
 * @return 大文字小文字以外が同じならtrue。
 */
//------------------------------------------------------------------------------
bool sameText( const std::wstring_view left, const std::wstring_view right) noexcept
{
	return left.size() <= MAXIMUM_DISPLAY_CHARACTERS && !left.empty() &&
		   left.size() == right.size() &&
		   CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

//------------------------------------------------------------------------------
/**
 * @brief IDやnetwork queryを作らず、表示名のlocal probeだけに使う。
 *
 * @param[in] text 最大512文字の表示名。
 * @param[in] prefix 系列名の期待prefix。
 * @return 表示prefixが一致すればtrue。
 */
//------------------------------------------------------------------------------
bool startsWithText( const std::wstring_view text, const std::wstring_view prefix) noexcept
{
	return text.size() <= MAXIMUM_DISPLAY_CHARACTERS && text.size() >= prefix.size() &&
		   sameText( text.substr( 0U, prefix.size()), prefix) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 最大512文字を検査する。メーカーprefixは呼出し側で別途要求する。
 *
 * @param[in] text 有限のdevice表示名。
 * @param[in] token 期待する系列語。
 * @return 系列語が含まれればtrue。
 */
//------------------------------------------------------------------------------
bool containsText( const std::wstring_view text, const std::wstring_view token) noexcept
{
	// 上限外と長さ差のunderflowを拒否する。
	if( text.size() > MAXIMUM_DISPLAY_CHARACTERS || token.empty() || token.size() > text.size()) {
		return false ;
	}

	// 系列語の開始位置を最大512箇所で照合する。
	for( std::size_t offset = 0U; offset <= text.size() - token.size(); ++offset) {
		// 現在位置で検索 token と一致した場合は包含条件の成立を返す。
		if( sameText( text.substr( offset, token.size()), token)) {
			return true ;
		}
	}

	return false ;
}

/**
 * @brief ASCII英数字が隣接しない型番tokenだけを端末内で照合する。
 * @param[in] text 最大512文字の表示名。
 * @param[in] token 審査済みASCII型番。
 * @return 完全tokenの大文字小文字を無視した一致時true。
 */
bool containsProductToken( const std::wstring_view text, const std::wstring_view token) noexcept
{
	// 空token、過大な入力、減算underflowを拒否する。
	if( text.size() > MAXIMUM_DISPLAY_CHARACTERS || token.empty() || token.size() > text.size()) {
		return false ;
	}

	// ASCII英数字だけをtoken内文字とし、部分型番への拡大を防ぐ。
	const auto alphanumeric = []( const wchar_t value) noexcept {
		return (value >= L'0' && value <= L'9') || (value >= L'A' && value <= L'Z') ||
			   (value >= L'a' && value <= L'z') ;
	} ;
	// 最大512開始位置を確認し、前後の境界を含む一意な語を探す。
	for( std::size_t offset = 0U; offset <= text.size() - token.size(); ++offset) {
		const std::size_t end = offset + token.size() ;	// token直後の境界位置。
		// 前後のASCII英数字に連結した別型番を一致扱いにしない。
		if( (offset == 0U || !alphanumeric( text[offset - 1U])) &&
		   (end == text.size() || !alphanumeric( text[end])) &&
		   sameText( text.substr( offset, token.size()), token)) {
			return true ;
		}
	}

	return false ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_metadata.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
const OfficialSourceDefinition *officialSourceDefinition(
	const OfficialReleaseFamily family) noexcept
{
	static const OfficialSourceDefinition PROLIFIC{
		.family		= OfficialReleaseFamily::PROLIFIC_DCHU,
		.providerId = PROLIFIC_OFFICIAL_PROVIDER_ID,
		.sourceId	= PROLIFIC_OFFICIAL_SOURCE_POLICY_ID,
		.familyId	= L"prolific-dchu",
		.productKey = L"pl2303gt",
		.branch		= L"pl2303g-dchu",
		.profileId	= L"prolific-dchu-inf",
		.landingUrl =
			officialMetadataEndpoint( PROLIFIC_OFFICIAL_PROVIDER_ID, OFFICIAL_LANDING_RESOURCE_ID),
		.displayOrigin			   = L"www.prolific.com.tw",
		.maximumMetadataBytes	   = MAXIMUM_METADATA_BYTES,
		.observationPolicyRevision = 1U} ;	// 既存のDCHU INF配布行だけを参照。
	static const OfficialSourceDefinition INTEL{
		.family		= OfficialReleaseFamily::INTEL_WIFI,
		.providerId = INTEL_WIFI_OFFICIAL_PROVIDER_ID,
		.sourceId	= INTEL_WIFI_OFFICIAL_SOURCE_POLICY_ID,
		.familyId	= L"intel-wifi",
		.productKey = L"18231",
		.branch		= L"wifi-it-admin",
		.profileId	= L"intel-wifi-inf",
		.landingUrl =
			officialMetadataEndpoint( INTEL_WIFI_OFFICIAL_PROVIDER_ID, OFFICIAL_LANDING_RESOURCE_ID),
		.displayOrigin			   = L"www.intel.com",
		.maximumMetadataBytes	   = MAXIMUM_METADATA_BYTES,
		.observationPolicyRevision = 1U} ;	// Payload取得の許可を含めない。
	static const OfficialSourceDefinition INTEL_ETHERNET_SERVER2025{
		.family		   = OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025,
		.providerId	   = INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID,
		.sourceId	   = INTEL_ETHERNET_SERVER2025_OFFICIAL_SOURCE_POLICY_ID,
		.familyId	   = L"intel-ethernet-server-2025",
		.productKey	   = L"838943",
		.branch		   = L"ethernet-windows-server-2025",
		.profileId	   = L"intel-ethernet-server-2025-inf",
		.landingUrl	   = officialMetadataEndpoint( INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID,
												  OFFICIAL_LANDING_RESOURCE_ID),
		.displayOrigin = L"www.intel.com",
		.maximumMetadataBytes	   = MAXIMUM_METADATA_BYTES,
		.observationPolicyRevision = 2U} ;	// 明示同意付き検査用取得を別操作で許可する。
	static const OfficialSourceDefinition INTEL_ETHERNET_WINDOWS11{
		.family		   = OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11,
		.providerId	   = INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID,
		.sourceId	   = INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID,
		.familyId	   = L"intel-ethernet-windows11",
		.productKey	   = L"727998",
		.branch		   = L"ethernet-windows11",
		.profileId	   = L"intel-ethernet-windows11-inf",
		.landingUrl	   = officialMetadataEndpoint( INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID,
												  OFFICIAL_LANDING_RESOURCE_ID),
		.displayOrigin = L"www.intel.com",
		.maximumMetadataBytes	   = MAXIMUM_METADATA_BYTES,
		.observationPolicyRevision = 1U} ;	// 取得・内容検査能力をProvider表示へ拡大しない。
	static constexpr OfficialSourceDefinition BROADCOM{
		.family					   = OfficialReleaseFamily::BROADCOM_NET_XTREME_E,
		.providerId				   = BROADCOM_NET_XTREME_PROVIDER_ID,
		.sourceId				   = BROADCOM_OFFICIAL_SOURCE_POLICY_ID,
		.familyId				   = L"broadcom-netxtreme-e",
		.productKey				   = L"n210tp",
		.branch					   = L"netxtreme-e-windows",
		.profileId				   = L"",
		.landingUrl				   = BROADCOM_CATALOG_URL,
		.displayOrigin			   = L"www.broadcom.com",
		.maximumMetadataBytes	   = MAXIMUM_METADATA_BYTES,
		.observationPolicyRevision = 1U} ;	// 内容監査profileの接続はX3で行う。
	static constexpr OfficialSourceDefinition ASIX{
		.family		= OfficialReleaseFamily::ASIX_AX88179A,
		.providerId = ASIX_AX88179A_PROVIDER_ID,
		.sourceId	= ASIX_OFFICIAL_SOURCE_POLICY_ID,
		.familyId	= L"asix-ax88179a",
		.productKey = L"AX88179A",
		.branch		= L"windows-client-x64",
		.profileId	= L"",
		.landingUrl =
			L"https://www.asix.com.tw/en/product/USBEthernet/Super-Speed_USB_Ethernet/AX88179A",
		.displayOrigin			   = L"www.asix.com.tw",
		.maximumMetadataBytes	   = MAXIMUM_METADATA_BYTES,
		.observationPolicyRevision = 2U} ;	// 製品・Terms結合済み数値download IDを観測する。
	static const OfficialSourceDefinition RICOH_UNIVERSAL_PCL6{
		.family					   = OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6,
		.providerId				   = RICOH_UNIVERSAL_PRINT_PROVIDER_ID,
		.sourceId				   = RICOH_UNIVERSAL_PRINT_OFFICIAL_SOURCE_POLICY_ID,
		.familyId				   = L"ricoh-universal-pcl6",
		.productKey				   = L"pcl6-universal-print",
		.branch					   = L"windows-x64",
		.profileId				   = L"",
		.landingUrl				   = officialMetadataEndpoint( RICOH_UNIVERSAL_PRINT_PROVIDER_ID,
															  OFFICIAL_LANDING_RESOURCE_ID),
		.displayOrigin			   = L"support.ricoh.com",
		.maximumMetadataBytes	   = MAXIMUM_METADATA_BYTES,
		.observationPolicyRevision = 1U} ;	// 六つのx64 OS欄が一致する従来型PCL6だけを参照。
	static const OfficialSourceDefinition WACOM_WINDOWS_TABLET{
		.family		= OfficialReleaseFamily::WACOM_WINDOWS_TABLET,
		.providerId = WACOM_WINDOWS_PROVIDER_ID,
		.sourceId	= WACOM_WINDOWS_OFFICIAL_SOURCE_POLICY_ID,
		.familyId	= L"wacom-windows-tablet",
		.productKey = L"latest-windows-tablet-driver",
		.branch		= L"windows-10-11-x64",
		.profileId	= L"",
		.landingUrl =
			officialMetadataEndpoint( WACOM_WINDOWS_PROVIDER_ID, OFFICIAL_LANDING_RESOURCE_ID),
		.displayOrigin			   = L"www.wacom.com",
		.maximumMetadataBytes	   = MAXIMUM_METADATA_BYTES,
		.observationPolicyRevision = 1U} ;	// 統合EXEの取得と導入を許可しない表示系列。
	static const OfficialSourceDefinition FOCUSRITE_SCARLETT2I2{
		.family					   = OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN,
		.providerId				   = FOCUSRITE_SCARLETT2I2_PROVIDER_ID,
		.sourceId				   = FOCUSRITE_SCARLETT2I2_OFFICIAL_SOURCE_POLICY_ID,
		.familyId				   = L"focusrite-scarlett-2i2-second-gen",
		.productKey				   = L"scarlett-2i2-2nd-gen",
		.branch					   = L"windows-10-11-x64",
		.profileId				   = L"",
		.landingUrl				   = officialMetadataEndpoint( FOCUSRITE_SCARLETT2I2_PROVIDER_ID,
															  OFFICIAL_LANDING_RESOURCE_ID),
		.displayOrigin			   = L"downloads.focusrite.com",
		.maximumMetadataBytes	   = MAXIMUM_METADATA_BYTES,
		.observationPolicyRevision = 1U} ;	// EXEを取得しない製品限定表示系列。
	// 既存Serialの公開起点を共有する。情報検索はZIPへ進まない。
	static const OfficialSourceDefinition SILICON_LABS{
		.family					   = OfficialReleaseFamily::SILICON_LABS_CP210X,
		.providerId				   = SILICON_LABS_OFFICIAL_PROVIDER_ID,
		.sourceId				   = SILICON_LABS_OFFICIAL_SOURCE_POLICY_ID,
		.familyId				   = L"silicon-labs-cp210x",
		.productKey				   = L"cp210x-universal-windows",
		.branch					   = L"cp210x-universal-windows",
		.profileId				   = L"silicon-labs-cp210x-inf",
		.landingUrl				   = officialMetadataEndpoint( SILICON_LABS_OFFICIAL_PROVIDER_ID,
															  OFFICIAL_LANDING_RESOURCE_ID),
		.displayOrigin			   = L"www.silabs.com",
		.maximumMetadataBytes	   = MAXIMUM_METADATA_BYTES,
		.observationPolicyRevision = 1U,
		.metadataUrl			   = officialMetadataEndpoint( SILICON_LABS_OFFICIAL_PROVIDER_ID,
															  OFFICIAL_PRIMARY_METADATA_RESOURCE_ID)} ;
	// CH341配布とCH343配布は異なる固定source policyを維持する。
	static const OfficialSourceDefinition WCH_CH341{
		.family		= OfficialReleaseFamily::WCH_CH341,
		.providerId = WCH_OFFICIAL_PROVIDER_ID,
		.sourceId	= WCH_OFFICIAL_SOURCE_POLICY_ID,
		.familyId	= L"wch-ch341",
		.productKey = L"CH341SER.ZIP",
		.branch		= L"ch341ser",
		.profileId	= L"wch-ch341-inf",
		.landingUrl =
			officialMetadataEndpoint( WCH_OFFICIAL_PROVIDER_ID, OFFICIAL_LANDING_RESOURCE_ID),
		.displayOrigin			   = L"www.wch.cn",
		.maximumMetadataBytes	   = MAXIMUM_METADATA_BYTES,
		.observationPolicyRevision = 1U,
		.metadataUrl			   = officialMetadataEndpoint( WCH_OFFICIAL_PROVIDER_ID,
															  OFFICIAL_PRIMARY_METADATA_RESOURCE_ID)} ;
	// CH343情報検索の表示probeはCH342へ拡大しない。
	static const OfficialSourceDefinition WCH_CH343{
		.family		= OfficialReleaseFamily::WCH_CH343,
		.providerId = WCH_MULTI_OFFICIAL_PROVIDER_ID,
		.sourceId	= WCH_MULTI_OFFICIAL_SOURCE_POLICY_ID,
		.familyId	= L"wch-ch343",
		.productKey = L"CH343SER.ZIP",
		.branch		= L"ch343ser",
		.profileId	= L"wch-ch343-inf",
		.landingUrl =
			officialMetadataEndpoint( WCH_MULTI_OFFICIAL_PROVIDER_ID, OFFICIAL_LANDING_RESOURCE_ID),
		.displayOrigin			   = L"www.wch.cn",
		.maximumMetadataBytes	   = MAXIMUM_METADATA_BYTES,
		.observationPolicyRevision = 1U,
		.metadataUrl			   = officialMetadataEndpoint( WCH_MULTI_OFFICIAL_PROVIDER_ID,
															  OFFICIAL_PRIMARY_METADATA_RESOURCE_ID)} ;
	// 系列ごとに固定定義を選び、host と capability は登録済み policy へ委ねる。
	switch( family) {
		// CP210x公開一覧の固定した二文書だけを参照する。
		case OfficialReleaseFamily::SILICON_LABS_CP210X:
			return &SILICON_LABS ;
		// CH340／CH341用の固定起点を返す。
		case OfficialReleaseFamily::WCH_CH341:
			return &WCH_CH341 ;
		// CH343用の固定起点を別policyに保持する。
		case OfficialReleaseFamily::WCH_CH343:
			return &WCH_CH343 ;
		// Prolific DCHU系列には、その系列専用の組み込み取得定義を返す。
		case OfficialReleaseFamily::PROLIFIC_DCHU:
			return &PROLIFIC ;
		// Intel Wi-Fi系列には、無線driver用の組み込み取得定義を返す。
		case OfficialReleaseFamily::INTEL_WIFI:
			return &INTEL ;
		// Intel Server 2025 Ethernet系列を、client無線系列と分離する。
		case OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025:
			return &INTEL_ETHERNET_SERVER2025 ;
		// Intel Windows 11 Ethernet系列をServer系列と分離する。
		case OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11:
			return &INTEL_ETHERNET_WINDOWS11 ;
		// Broadcom NetXtreme-E系列には、対応する組み込み取得定義を返す。
		case OfficialReleaseFamily::BROADCOM_NET_XTREME_E:
			return &BROADCOM ;
		// ASIX AX88179A系列には、対応する組み込み取得定義を返す。
		case OfficialReleaseFamily::ASIX_AX88179A:
			return &ASIX ;
		// Ricoh Universal PCL6系列には、印刷driver用の取得定義を返す。
		case OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6:
			return &RICOH_UNIVERSAL_PCL6 ;
		// Wacom Windows tablet系列には、その系列の取得定義を返す。
		case OfficialReleaseFamily::WACOM_WINDOWS_TABLET:
			return &WACOM_WINDOWS_TABLET ;
		// Focusrite Scarlett 2i2第2世代を、別製品系列へ流用しない。
		case OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN:
			return &FOCUSRITE_SCARLETT2I2 ;
		// 未知の系列を別メーカーの取得定義へfallbackしない。
		default:
			// 定義外enumを別メーカーへ流用しない。
			return nullptr ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_metadata.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool evaluateOfficialReleaseObservation(
	const OfficialReleaseFamily family, const OfficialReleaseRecord &release,
	const OfficialCatalogDevice &device, const std::wstring_view operatingSystemFingerprint,
	const std::wstring_view deviceConfigurationFingerprint, const std::uint64_t observedFileTime,
	const std::span<const LocalOfficialReleaseObservation> previous,
	OfficialReleaseObservationEvaluation				  &evaluation)
{
	evaluation = {} ;
	const OfficialSourceDefinition *const definition =
		// 組み込みstable IDの唯一の取得元。
		officialSourceDefinition( family) ;
	// 不完全なlive情報やlocal probeを部分的に永続化しない。
	if( definition == nullptr || release.family != family || release.parserRevision == 0U ||
	   (release.releaseKey.empty() && release.fileName.empty()) ||
	   device.localBindingFingerprint.empty() || operatingSystemFingerprint.empty() ||
	   deviceConfigurationFingerprint.empty() || observedFileTime == 0U ||
	   previous.size() > 4'096U) {
		return false ;
	}

	ReleaseObservationPendingReason pendingReason{} ;	// 今回metadataで残る未確認段階。
	// 許諾状態と公表 hash の有無から、追加操作や再検証が必要な理由を決める。
	switch( release.license) {
		// 取得前の利用条件同意が必要な場合は、sourceとの対話待ちへ合流する。
		case OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD:
		// 利用条件が未解決の場合も、対話なしで取得可能とは扱わない。
		case OfficialReleaseLicense::UNRESOLVED:
			pendingReason = ReleaseObservationPendingReason::SOURCE_INTERACTION_REQUIRED ;
			break ;

		// 追加同意不要が確認済みの場合も、公開hashがなければ内容の再検証を残す。
		case OfficialReleaseLicense::CONFIRMED_NO_CONSENT:
			pendingReason = release.publishedSha256.empty()
								? ReleaseObservationPendingReason::CONTENT_REVALIDATION_NEEDED
								: ReleaseObservationPendingReason::NONE ;
			break ;

		// 未知の利用条件を、既知の観測状態として保存しない。
		default:
			// 定義外の利用条件を既知の観測として保存しない。
			return false ;
	}

	LocalOfficialReleaseObservation current ;	// 全field設定後にcore検証する今回観測。
	current.binding.deviceBindingFingerprint		   = device.localBindingFingerprint ;
	current.binding.providerId						   = definition->providerId ;
	current.binding.sourceId						   = definition->sourceId ;
	current.binding.familyId						   = definition->familyId ;
	current.binding.productKey						   = definition->productKey ;
	current.binding.branch							   = definition->branch ;
	current.environment.operatingSystemFingerprint	   = operatingSystemFingerprint ;
	current.environment.deviceConfigurationFingerprint = deviceConfigurationFingerprint ;
	current.environment.policyRevision				   = definition->observationPolicyRevision ;
	current.environment.parserRevision				   = release.parserRevision ;
	current.releaseKey =
		// 公式の明示key。
		release.releaseKey.empty() ? release.fileName : release.releaseKey ;
	current.packageVersion	= release.packageVersion ;
	current.publishedSha256 = release.publishedSha256 ;
	// characterは公式hashの各文字。Hex文字case差だけを吸収し、非hex文字は後続で拒否する。
	for( wchar_t &character : current.publishedSha256) {
		// SHA-256 の大文字 hex 桁だけを小文字へ正規化する。
		if( character >= L'A' && character <= L'F') {
			character = static_cast<wchar_t>( character - L'A' + L'a') ;
		}
	}

	current.observedFileTime = observedFileTime ;
	current.pendingReason	 = pendingReason ;
	// 現在の観測値が保存契約を満たさなければ差分評価へ進まない。
	if( !isLocalOfficialReleaseObservationValid( current)) {
		return false ;
	}

	const LocalOfficialReleaseObservation *matchedPrevious{} ;	// 同Provider・deviceの前回一件。
	// 全前回recordを検証し、同じProvider・deviceの曖昧な重複を拒否する。
	for( const LocalOfficialReleaseObservation &observation : previous) {
		// 不正な過去観測を比較の正本として使用しない。
		if( !isLocalOfficialReleaseObservationValid( observation)) {
			return false ;
		}

		// 同じ Provider と device binding の過去観測だけを比較対象とする。
		if( observation.binding.providerId == current.binding.providerId &&
		   observation.binding.deviceBindingFingerprint ==
			   current.binding.deviceBindingFingerprint) {
			// 同じ binding の過去観測が複数ある場合は比較対象を推測しない。
			if( matchedPrevious != nullptr) {
				return false ;
			}

			matchedPrevious = &observation ;
		}
	}

	const ReleaseObservationDifference difference =
		// 非許可の差分。
		compareLocalOfficialReleaseObservation( matchedPrevious, current) ;
	// 差分の判定が不正となった場合は有効な評価結果を返さない。
	if( difference == ReleaseObservationDifference::INVALID) {
		return false ;
	}

	evaluation.observation = std::move( current) ;
	evaluation.difference  = difference ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_metadata.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool officialReleaseDeviceMatches( const OfficialReleaseFamily  family,
								  const OfficialCatalogDevice &device) noexcept
{
	// 不正identityと過大表示をnetwork対象へしない。
	if( device.deviceIdentity.empty() || device.deviceIdentity.size() > 256U ||
	   device.model.size() > MAXIMUM_DISPLAY_CHARACTERS ||
	   device.manufacturer.size() > MAXIMUM_DISPLAY_CHARACTERS) {
		return false ;
	}

	// 新Serial probeはPorts GUIDを必須とし、異系列tokenの混在を全て拒否する。
	if( family == OfficialReleaseFamily::SILICON_LABS_CP210X ||
	   family == OfficialReleaseFamily::WCH_CH341 || family == OfficialReleaseFamily::WCH_CH343) {
		const bool cp210x = containsProductToken( device.model, L"CP210x") ;	// 審査済みCP210x表示。
		const bool ch341  = containsProductToken( device.model, L"CH340") ||
						   // 同じ公開配布系列の二token。
						   containsProductToken( device.model, L"CH341") ;
		const bool	   ch343	= containsProductToken( device.model, L"CH343") ;	// 初期限定の型番。
		const unsigned families = static_cast<unsigned>( cp210x) + static_cast<unsigned>( ch341) +
								  // 一系列だけを許可する。
								  static_cast<unsigned>( ch343) ;
		return families == 1U &&
			   (device.driverClass.empty() || sameText( device.driverClass, L"Ports")) &&
			   sameText( device.deviceClassGuid, L"{4d36e978-e325-11ce-bfc1-08002be10318}") &&
			   ((family == OfficialReleaseFamily::SILICON_LABS_CP210X && cp210x) ||
				(family == OfficialReleaseFamily::WCH_CH341 && ch341) ||
				(family == OfficialReleaseFamily::WCH_CH343 && ch343)) ;
	}

	// Intel Wi-Fi は Net class と Intel の無線製品表示条件で local 対象を絞る。
	if( family == OfficialReleaseFamily::INTEL_WIFI) {
		return (device.driverClass.empty() || sameText( device.driverClass, L"Net")) &&
			   (device.deviceClassGuid.empty() ||
				sameText( device.deviceClassGuid, L"{4d36e972-e325-11ce-bfc1-08002be10318}")) &&
			   (startsWithText( device.model, L"Intel(R) ") ||
				startsWithText( device.model, L"Intel® ") ||
				startsWithText( device.model, L"Intel ")) &&
			   (containsText( device.model, L"Wi-Fi") || containsText( device.model, L"Wireless")) ;
	}

	// Intel Ethernet は公式掲載系列の local 製品表示条件を適用する。
	if( family == OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025 ||
	   family == OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11) {
		const bool intelName = startsWithText( device.model, L"Intel(R) ") ||
							   startsWithText( device.model, L"Intel\x00ae ") ||
							   // Local表示名のメーカー境界。
							   startsWithText( device.model, L"Intel ") ;
		const bool listedSeries =
			std::ranges::any_of( INTEL_ETHERNET_SERIES, [&device]( const std::wstring_view token) {
				return containsText( device.model, token) ;
			}) ; // 公式page掲載系列のいずれか。
		return (device.driverClass.empty() || sameText( device.driverClass, L"Net")) &&
			   (device.deviceClassGuid.empty() ||
				sameText( device.deviceClassGuid, L"{4d36e972-e325-11ce-bfc1-08002be10318}")) &&
			   intelName && listedSeries ;
	}

	// Prolific DCHU は Ports class と PL2303 の製品表示条件を適用する。
	if( family == OfficialReleaseFamily::PROLIFIC_DCHU) {
		return (device.driverClass.empty() || sameText( device.driverClass, L"Ports")) &&
			   (device.deviceClassGuid.empty() ||
				sameText( device.deviceClassGuid, L"{4d36e978-e325-11ce-bfc1-08002be10318}")) &&
			   (startsWithText( device.model, L"Prolific PL2303") ||
				startsWithText( device.model, L"PL2303")) ;
	}

	// Ricoh は printer・queue class と製造元・製品表示の境界を確認する。
	if( family == OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6) {
		const bool printer = sameText( device.driverClass, L"Printer") ;	// Printer class判定。
		const bool printQueue =
			// Software-enumerated queue判定。
			sameText( device.driverClass, L"PrintQueue") ;
		// Class情報が未取得か、明示されたprinter／print queue classと一致するかを示す。
		const bool classGuidMatches =
			device.deviceClassGuid.empty() ||
			(printer &&
			 sameText( device.deviceClassGuid, L"{4d36e979-e325-11ce-bfc1-08002be10318}")) ||
			(printQueue &&
			 sameText( device.deviceClassGuid, L"{1ed2bbf9-11f0-4084-b21f-ad83a8e6dcdc}")) ;
		const bool ricohName = containsText( device.manufacturer, L"RICOH") ||
							   // Local表示のメーカー境界。
							   containsText( device.model, L"RICOH") ;
		return (printer || printQueue) && classGuidMatches && ricohName ;
	}

	// Wacom は HID class と製造元・製品表示の境界を確認する。
	if( family == OfficialReleaseFamily::WACOM_WINDOWS_TABLET) {
		const bool hidClass = sameText( device.driverClass, L"HIDClass") ;	// 入力device class。
		const bool classGuidMatches =
			device.deviceClassGuid.empty() ||
			sameText( device.deviceClassGuid,
					 L"{745a17a0-74d3-11d0-b6fe-00a0c90f57da}") ;	// HIDClass GUID。
		const bool wacomManufacturer =
			// Local製造元のWacom境界。
			containsText( device.manufacturer, L"Wacom") ;
		const bool wacomModel = containsText( device.model, L"Wacom") ;	// Local modelのWacom境界。
		return hidClass && classGuidMatches && wacomManufacturer && wacomModel ;
	}

	// Focusrite は MEDIA class と対象 Scarlett の製品表示条件を確認する。
	if( family == OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN) {
		const bool mediaClass = sameText( device.driverClass, L"MEDIA") ;	// 物理audio class。
		const bool classGuidMatches =
			device.deviceClassGuid.empty() ||
			sameText( device.deviceClassGuid,
					 L"{4d36e96c-e325-11ce-bfc1-08002be10318}") ;	// MEDIA class GUID。
		const bool focusriteManufacturer =
			// Local製造元のFocusrite境界。
			containsText( device.manufacturer, L"Focusrite") ;
		const bool scarlett2i2Model =
			// 固定製品系列の表示名境界。
			containsText( device.model, L"Scarlett 2i2") ;
		return mediaClass && classGuidMatches && focusriteManufacturer && scarlett2i2Model ;
	}

	// 未審査系列を汎用INF対応として探索しない。
	return false ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_metadata.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool officialReleaseOperatingSystemMatches( const OfficialReleaseFamily family,
										   const bool				   windowsServer,
										   const std::uint32_t		   windowsBuild) noexcept
{
	// 系列別に Client／Server と明示された build 範囲を照合する。
	switch( family) {
		// Server専用Ethernet系列は、指定したServer buildだけを許可する。
		case OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025:
			return windowsServer && windowsBuild == WINDOWS_SERVER2025_BUILD ;
		// Windows 11 recordはWindows 11以降のclient buildだけを許可する。
		case OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11:
			return !windowsServer && windowsBuild >= 22000U ;
		// Intel Wi-Fi系列は、client限定の共通判定へ合流する。
		case OfficialReleaseFamily::INTEL_WIFI:
		// Prolific DCHU系列も、Serverでは許可しない。
		case OfficialReleaseFamily::PROLIFIC_DCHU:
			return !windowsServer ;
		// 初期Serial情報検索の三系列は既存Serialと同じclient境界を使う。
		case OfficialReleaseFamily::SILICON_LABS_CP210X:
		// CH341SERも既存のclient限定を維持する。
		case OfficialReleaseFamily::WCH_CH341:
		// CH343SERもServerへ適用範囲を拡張しない。
		case OfficialReleaseFamily::WCH_CH343:
			return !windowsServer ;
		// Ricoh系列のServer利用は、明示された対応build集合に限定する。
		case OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6:
			return !windowsServer ||
				   std::ranges::find( RICOH_SUPPORTED_SERVER_BUILDS, windowsBuild) !=
					   RICOH_SUPPORTED_SERVER_BUILDS.end() ;
		// Wacom系列は、Windows 10以降のclientだけを許可する。
		case OfficialReleaseFamily::WACOM_WINDOWS_TABLET:
			// Windows 10／11 clientだけを許可。
			return !windowsServer && windowsBuild >= 10240U ;
		// Focusrite系列は、release notesに対応するclient build境界を適用する。
		case OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN:
			// 公式release notesのx64 client境界。
			return !windowsServer && windowsBuild >= 10240U ;
		// 未知または未使用の系列を、client向け既定条件へ流さない。
		default:
			// 未使用・未知系列をclient既定へ流さない。
			return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 配布familyごとの公式metadataを制御付きで解析し、完成recordだけを返す。
 * @param[in,out] control 呼出し中だけ借用するparser制御。旧wrapperからの呼出しだけnullを許可する。
 * @param[in] family 必要な公式metadataと専用parserを選ぶ配布family。
 * @param[in] html 同じ取得元の有限HTML。UTF-16 viewを同期中だけ借用する。
 * @param[out] record 開始時に空へ戻し、解析を全て終えた場合だけ完成値を設定する。
 * @return 対象familyの必要metadataを抽出できた場合true。必要構造・値を確認できない場合false。
 * @see src/platform/official_release_metadata.h 公開wrapperの宣言側契約を参照する。
 */
//------------------------------------------------------------------------------
static bool parseOfficialReleaseRecordCore( CollectorParserContext	  *control,
										   const OfficialReleaseFamily family,
										   const std::wstring_view	   html,
										   OfficialReleaseRecord	  &record)
{
	record = {} ;
	OfficialReleaseRecord parsed ;	// 全検証後にのみ出力へ移動する情報。
	parsed.family		  = family ;
	parsed.parserRevision = 1U ;
	// Prolific の公式配布行は専用 parser で取得し、未公表情報を補完しない。
	if( family == OfficialReleaseFamily::PROLIFIC_DCHU) {
		// 審査済み配布行以外を受理しない。
		if( !parseProlificOfficialZipUrl( html, parsed.downloadUrl)) {
			return false ;
		}

		parsed.fileName = parsed.downloadUrl.substr( parsed.downloadUrl.rfind( L'/') + 1U) ;
		// File名から配布版、EULA、hash、正確なbyte数を推測しない。
	}
	// Intel Wi-Fi の page は既存専用 parser の metadata だけを取り込む。
	else if( family == OfficialReleaseFamily::INTEL_WIFI) {
		// 非表示領域・許諾構造の変更で旧cacheと分離する。
		parsed.parserRevision = 2U ;
		IntelWirelessPageMetadata intel ;	// 既存parserの有限な必須metadata。
		// Intel Wi-Fi page の解析に失敗した場合は配布 record を作らない。
		if( !parseIntelWirelessDownloadPage( html, intel)) {
			return false ;
		}

		parsed.fileName		   = std::move( intel.fileName) ;
		parsed.packageVersion  = std::move( intel.version) ;
		parsed.displaySize	   = std::move( intel.displaySize) ;
		parsed.publishedSha256 = std::move( intel.sha256) ;
		parsed.downloadUrl	   = std::move( intel.downloadUrl) ;
		parsed.license		   = OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD ;
		// 本文が掲載されたpageでは同じdownload buttonへ完全な許諾snapshotを結合する。
		if( html.find( L"content-raw") != html.npos &&
		   !parseIntelDownloadLicense( html, parsed.downloadUrl, parsed.eulaRevision,
									  parsed.eulaText)) {
			return false ;
		}
		// 本文未掲載時は表示検索だけを維持し、共通取得adapterは同意欠落で拒否する。
	}
	// Intel Ethernet Server 2025 の専用 page から明示 metadata を取り込む。
	else if( family == OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025) {
		IntelEthernetServerPageMetadata intel ;	// Server 2025専用pageの有限metadata。
		// Intel Ethernet page の解析に失敗した場合は配布 record を返さない。
		if( !parseIntelEthernetServerDownloadPage( html, intel)) {
			return false ;
		}

		parsed.fileName		   = std::move( intel.fileName) ;
		parsed.packageVersion  = std::move( intel.version) ;
		parsed.displaySize	   = std::move( intel.displaySize) ;
		parsed.publishedSha256 = std::move( intel.sha256) ;
		parsed.downloadUrl	   = std::move( intel.downloadUrl) ;
		parsed.license		   = OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD ;
		parsed.eulaRevision	   = std::move( intel.eulaRevision) ;
		parsed.eulaText		   = std::move( intel.eulaText) ;
		parsed.parserRevision  = 2U ;
		// 本文保持は同意や利用条件の成立ではない。取得targetとpayload能力は別工程。
	}
	// Intel Ethernet Windows 11 record 727998の専用profileから明示metadataを取り込む。
	else if( family == OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11) {
		IntelEthernetDownloadPageMetadata intel ;	// Windows 11専用pageの有限metadata。
		// Windows 11、E610-XT2掲載、配布行とEULAを一意に確認できなければ拒否する。
		if( !(control != nullptr
				 ? parseIntelEthernetWindows11DownloadPageForCollector( html, intel, *control)
				 : parseIntelEthernetWindows11DownloadPage( html, intel))) {
			return false ;
		}

		parsed.fileName		   = std::move( intel.fileName) ;
		parsed.packageVersion  = std::move( intel.version) ;
		parsed.displaySize	   = std::move( intel.displaySize) ;
		parsed.publishedSha256 = std::move( intel.sha256) ;
		parsed.downloadUrl	   = std::move( intel.downloadUrl) ;
		parsed.license		   = OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD ;
		parsed.eulaRevision	   = std::move( intel.eulaRevision) ;
		parsed.eulaText		   = std::move( intel.eulaText) ;
		parsed.parserRevision  = 3U ;
		// 概算38.6 MBをexact byte数へ変換せず、publishedSizeBytesは未指定のままにする。
	}
	// Ricoh の共通印刷 driver page は専用 parser の一致結果を使用する。
	else if( family == OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6) {
		RicohUniversalPrintPageMetadata ricoh ;	// 六つのx64 OS欄で一致した表示情報。
		// Ricoh page の必須条件が成立しなければ配布 record を作らない。
		if( !parseRicohUniversalPrintPage( html, ricoh)) {
			return false ;
		}

		parsed.fileName		  = std::move( ricoh.fileName) ;
		parsed.packageVersion = std::move( ricoh.version) ;
		parsed.displaySize	  = std::move( ricoh.displaySize) ;
		parsed.publishedDate  = std::move( ricoh.releaseDate) ;
		parsed.downloadUrl	  = std::move( ricoh.downloadUrl) ;
		// 公開hashと利用許諾識別子がないためUnresolvedのまま保持する。
	}
	// Wacom の Windows driver page から専用 parser の表示情報を取り込む。
	else if( family == OfficialReleaseFamily::WACOM_WINDOWS_TABLET) {
		WacomDriverPageMetadata wacom ;	// Windows x64を含む一意な統合driver表示情報。
		// Wacom page を一意に解析できなければ metadata を受理しない。
		if( !parseWacomWindowsDriverPage( html, wacom)) {
			return false ;
		}

		parsed.fileName		  = std::move( wacom.fileName) ;
		parsed.packageVersion = std::move( wacom.version) ;
		parsed.displaySize	  = std::move( wacom.displaySize) ;
		parsed.publishedDate  = std::move( wacom.releaseDate) ;
		parsed.downloadUrl	  = std::move( wacom.downloadUrl) ;
		// 公開hash、EULA改訂結合、内容監査がないためUnresolvedのまま保持する。
	}
	// Focusrite の固定製品 page から対象系列の表示情報だけを取り込む。
	else if( family == OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN) {
		FocusriteDownloadPageMetadata focusrite ;	// 固定製品pageの現行Windows表示情報。
		// 対象 Focusrite page の解析失敗時は配布情報を返さない。
		if( !parseFocusriteScarlett2i2SecondGenPage( html, focusrite)) {
			return false ;
		}

		parsed.fileName		  = std::move( focusrite.fileName) ;
		parsed.packageVersion = std::move( focusrite.version) ;
		parsed.displaySize	  = std::move( focusrite.displaySize) ;
		parsed.downloadUrl	  = std::move( focusrite.downloadUrl) ;
		// 公開hash、日付、EULA改訂、内容監査がないためUnresolvedのまま保持する。
	} else {
		// 未知値を初期系列で解析しない。
		return false ;
	}

	record = std::move( parsed) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_release_metadata.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------

/** @see official_release_metadata.h */
bool parseOfficialReleaseRecord( OfficialReleaseFamily family, std::wstring_view html,
								OfficialReleaseRecord &record)
{
	return parseOfficialReleaseRecordCore( nullptr, family, html, record) ;
}

/** @see official_release_metadata.h */
bool parseIntelCollectorReleaseRecord( std::wstring_view html, OfficialReleaseRecord &record,
									  CollectorParserContext &context)
{
	context.checkpoint() ;
	const bool parsed =
		parseOfficialReleaseRecordCore( &context, OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11,
									   html, record) ;	// 同じfield変換を維持します。
	context.checkpoint() ;
	return parsed ;
}

NativeError readOfficialReleaseMetadata( const OfficialReleaseFamily family,
										const ScanSessionId session, OfficialHttpClient &http,
										OfficialReleaseRecord &record, bool &metadataRejected,
										MetadataSearchExecutionContext *const execution)
{
	http.invalidateSourceSession() ;
	record			 = {} ;
	metadataRejected = false ;
	const OfficialSourceDefinition *const definition =
		// Process寿命中有効な検索定義。
		officialSourceDefinition( family) ;
	// 不正契約では通信しない。
	if( definition == nullptr || session == 0U ||
	   family == OfficialReleaseFamily::BROADCOM_NET_XTREME_E ||
	   (execution != nullptr && (execution->scanSessionId() != session ||
								 execution->activeProviderId() != definition->providerId))) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	NativeError error = http.beginSourceSession( session, definition->providerId) ;	// 元の診断値。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	std::wstring html ;	// 2 MiBまでの公式landing本文。端末情報を含まない要求だけを使う。
	error = http.getUtf8TextForSource( definition->landingUrl, OFFICIAL_LANDING_RESOURCE_ID,
									  definition->maximumMetadataBytes, html) ;
	// 通信失敗を最新／候補なしに変換しない。
	if( error != 0) {
		return error ;
	}

	std::wstring json ;	// 二文書系列だけが読む、上限付き補助metadata。
	// 固定定義に補助JSONがある系列だけで第二resourceを消費する。
	if( !definition->metadataUrl.empty()) {
		error = http.getUtf8TextForSource( definition->metadataUrl,
										  OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
										  definition->maximumMetadataBytes, json) ;
		// 第一文書の成功を第二文書の失敗で候補へ昇格させない。
		if( error != 0) {
			return error ;
		}
	}

	// 取消しまたは期限を観測した後はparserへ新しい処理を渡さない。
	if( execution != nullptr && (error = execution->checkpoint()) != 0) {
		return error ;
	}

	bool parsed{} ;	// 同じsource sessionの文書を全て取得した後だけ解析する。
	// 既存一文書parserを共用し、二文書を一文書として受理しない。
	if( definition->metadataUrl.empty()) {
		parsed = parseOfficialReleaseRecord( family, html, record) ;
	}
	// CP210xは二文書を一組として既存の詳細parserへ渡す。
	else if( family == OfficialReleaseFamily::SILICON_LABS_CP210X) {
		parsed = parseSiliconLabsOfficialRelease( html, json, record) ;
	} else {
		parsed = parseWchOfficialRelease( family == OfficialReleaseFamily::WCH_CH341
											 ? WchOfficialPackageKind::CH341
											 : WchOfficialPackageKind::CH343,
										 html, json, record) ;
	}

	// 同期parserから戻った後も確認し、停止後のrecordをcommitしない。
	if( execution != nullptr && (error = execution->checkpoint()) != 0) {
		record = {} ;
		return error ;
	}

	// 同 session の取得根拠または metadata 解析が成立しなければ形式拒否とする。
	if( !http.hasSourceEvidence( session, definition->providerId, OFFICIAL_LANDING_RESOURCE_ID) ||
	   (!definition->metadataUrl.empty() &&
		!http.hasSourceEvidence( session, definition->providerId,
								OFFICIAL_PRIMARY_METADATA_RESOURCE_ID)) ||
	   !parsed) {
		record			 = {} ;
		metadataRejected = true ;
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
	}

	return 0 ;
}
} // namespace drivercrate
