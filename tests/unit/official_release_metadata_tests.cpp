//------------------------------------------------------------------------------
/**
 * @file official_release_metadata_tests.cpp
 * @brief 共通配布情報と表示専用検索の内部試験。
 * @version 01.02.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  Focusriteのcache mode構築回帰を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  ASIXのTerms結合観測revisionを照合。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Wacom架空HTMLのraw string境界を修正。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernetの取得前提確認と選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Focusrite Scarlett 2i2検索試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Wacom Windows公式検索試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Ricoh PCL6公式検索試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  ASIX配布IDのRelease観測試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Release観測差分試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Intel Ethernet Server検索試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得計画とworker実行を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  共通配布情報と検索接続を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  共通metadata計測根拠の回帰試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  計測出力有無の取得回数比較を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Windows 11 Ethernet検索定義を検証。
 * Ver.01.02.00 Shunji Ogawa  2026/09/23  Wi-Fiの新parser版と可視表示・取得元境界を検証。
 * Ver.01.02.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 合成metadataとfake取得だけを使い、外部通信・復元・導入を行いません。
 */
//------------------------------------------------------------------------------

#include "official_release_metadata_tests.h"
#include "test_framework.h"

#include "core/candidate_audit.h"
#include "core/official_preparation_operation.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/focusrite_download_page_parser.h"
#include "platform/official_release_discovery_provider.h"
#include "platform/official_release_metadata.h"
#include "platform/ricoh_universal_print_page_parser.h"
#include "platform/wacom_driver_page_parser.h"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {
constexpr std::wstring_view INTEL_PAGE =
	LR"(<html><p>Intel requires an accepted license agreement</p>)"
	LR"(<p>drivers-only distribution packages for Wi-Fi version 24.60.0</p>)"
	LR"(<h2>Available Downloads</h2>)"
	LR"(<a href="https://downloadmirror.intel.com/123456/WiFi-24.60.0-Driver64-Win10-Win11.zip">)"
	LR"(Download WiFi-24.60.0-Driver64-Win10-Win11.zip</a>)"
	LR"(<span>Windows 11*, Windows 10, 64-bit*</span>)"
	LR"(<span>Size: 42.7 MB</span><span>SHA256: )"
	LR"(0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF</span>)"
	LR"(<h2>Detailed Description</h2><p>Drivers only:</p></html>)" ;	// 合成公開page。実hashではない。
constexpr std::wstring_view PROLIFIC_PAGE =
	LR"(<table><tr><td>Windows DCHU+DFx+Modem Standy Driver INF Setup</td>)"
	LR"(<td>Win10 / Win11</td>)"
	LR"(<td><a href="/wp-content/uploads/2026/01/PL2303G_DCHU_fixture.zip">ZIP</a></td>)"
	LR"(</tr></table>)" ;	// 架空の配布file名だけを使う。
// Server 2025向けIntel Ethernet公式pageの必須表示だけを再現する合成fixture。
constexpr std::wstring_view INTEL_ETHERNET_SERVER_PAGE =
	LR"(<html><h1>Intel® Network Adapter Driver for Windows Server 2025*</h1>)"
	LR"(<p>Intel requires an accepted license agreement in order to download this file.</p>)"
	LR"(<h2>Available Downloads</h2>)"
	LR"(<button data-href="https://downloadmirror.intel.com/900001/)"
	LR"(Wired_driver_31.2.2_x64.zip">Wired_driver_31.2.2_x64.zip</button>)"
	LR"(<li>Windows Server 2025 family*</li><li>Size: 38.6 MB</li>)"
	LR"(<li>SHA256: 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF</li>)"
	LR"(<h2>Detailed Description</h2>)"
	LR"(<p><strong>Driver Package:</strong> Wired_driver_31.2.2_x64.zip</p></html>)" ;
constexpr ScanSessionId		SESSION = 31U ;	// 合成inventoryの検索session。
constexpr std::wstring_view WACOM_DOWNLOAD_URL =
	L"https://cdn.wacom.com/u/productsupport/drivers/win/professional/"
	L"WacomTablet_6.4.14-1.exe" ;	// 実fileではない現行命名形式のfixture URL。
// 未展開templateと確定したWindows配布情報を区別する合成HTML。
constexpr std::wstring_view WACOM_PAGE =
	LR"(<html><script><a data-driver-os="windows")"
	LR"( data-Download-link="{{WindowsLatestDownloadLink}}"></a>)"
	LR"(<a data-driver-os="windows" data-download-link="{{DownloadLink}}")"
	LR"( data-title="{{Title}}" data-size="{{Size}}"></a></script>)"
	LR"(<a href="#" class="drivers__btn" data-driver-os="windows")"
	LR"( data-download-link="https://cdn.wacom.com/u/productsupport/drivers/win/professional/)"
	LR"(WacomTablet_6.4.14-1.exe" data-title="Driver 6.4.14-1 Windows 10 &amp; 11 (x64))"
	LR"WACOM( &amp; Windows 11 (ARM64)" data-version="Driver 6.4.14-1")WACOM"
	LR"WACOM( data-description="Windows 10 &amp; 11 (x64) &amp; Windows 11 (ARM64)")WACOM"
	LR"( data-size="304 MB" data-release-date="8/26/2026 4:56:00 PM"></a></html>)" ;
// Wacom公式pageの二つのtemplateと一つの具体的Windows配布欄を再現する合成fixture。
constexpr std::wstring_view FOCUSRITE_DOWNLOAD_URL =
	L"https://fael-downloads-prod.focusrite.com/customer/prod/downloads/"
	L"focusritedriver_4.150.0_432.exe" ;	// 実fileを取得しない公式命名形式のfixture URL。
// Focusrite製品起点とWindows配布情報の結合を検証する合成HTML。
constexpr std::wstring_view FOCUSRITE_PAGE =
	LR"(<html><head><link rel="canonical" href="https://downloads.focusrite.com/focusrite/)"
	LR"(scarlett-2nd-gen/scarlett-2i2-2nd-gen" />)"
	LR"(<title>Scarlett 2i2 2nd Gen | Focusrite Downloads</title></head>)"
	LR"(<div class="windows"><h3>Focusrite Driver 4.150.0 - Windows</h3>)"
	LR"(<p>Windows 10 + 11</p><a href="https://fael-downloads-prod.focusrite.com/)"
	LR"(customer/prod/downloads/focusritedriver_4.150.0_432.exe">Download</a>)"
	LR"(<span class="file-size">53.64 MB</span><span class="file-type">.exe</span></div>)"
	LR"(<div class="mac"><h3>Focusrite Control 3.26.0 - Mac</h3></div>)"
	LR"(<div class="windows"><h3>Focusrite USB Driver 4.65.5 - Windows</h3>)"
	LR"(<p>Windows 7 + 8</p></div></html>)" ;
// 現行driver、Mac境界、名称が異なる旧USB driverを再現する合成fixture。

//------------------------------------------------------------------------------
/**
 * @brief 実model、hardware ID、instance pathを含めない。
 *
 * @param[in] identity 架空のopaque device ID。
 * @return 合成したIntel系列snapshotの所有値。
 */
//------------------------------------------------------------------------------
OfficialCatalogDevice intelDevice( std::wstring identity)
{
	OfficialCatalogDevice device ;	// 各試験で変更する非機密snapshot。
	device.deviceIdentity = std::move( identity) ;
	device.model		  = L"Intel(R) Wi-Fi Fixture" ;
	device.driverClass	  = L"Net" ;
	return device ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実Hardware IDを含めず、公式page掲載系列の表示名だけを使用する。
 *
 * @param[in] identity 架空のopaque device ID。
 * @return 合成したIntel Ethernet系列snapshotの所有値。
 */
//------------------------------------------------------------------------------
OfficialCatalogDevice intelEthernetServerDevice( std::wstring identity)
{
	OfficialCatalogDevice device ;	// Server向けlocal probeへ渡す非機密snapshot。
	device.deviceIdentity = std::move( identity) ;
	device.model		  = L"Intel(R) Ethernet Controller X710 Fixture" ;
	device.driverClass	  = L"Net" ;
	return device ;
}

//------------------------------------------------------------------------------
/**
 * @brief 従来型PCL6と除外対象V4を同じ欄へ置き、行境界の誤選択を検出できる形にする。
 *
 * @param[in] operatingSystem 架空の対象OS見出し。
 * @param[in] version 架空のPCL6配布版。
 * @param[in] url 架空のRicoh形式download URL。
 * @return 一つのOS欄を再現する所有HTML。
 */
//------------------------------------------------------------------------------
std::wstring makeRicohSection( const std::wstring_view operatingSystem,
							  const std::wstring_view version, const std::wstring_view url)
{
	std::wstring section =
		L"<div class=\"accordion_sct accordionSingleLinkSub\"><a>" ;	// OS欄の開始。
	section.append( operatingSystem) ;
	section.append( L"</a><div class=\"dl_list_box\">"
				   L"<strong>PCL6 Driver for Universal Print</strong><a href=\"") ;
	section.append( url) ;
	section.append( L"\">Download</a><p>(File Size : 34,552 KB)</p>"
				   L"<span class=\"pr32\">Ver.") ;
	section.append( version) ;
	section.append( L"</span> Released Date: 06/23/2026<br /></div>"
				   L"<div class=\"dl_list_box\">"
				   L"<strong>PCL6 Driver for Universal Print V4</strong>"
				   L"<a href=\"https://support.ricoh.com/bb/html/dr_ut_e/rc3/license.htm\">"
				   L"Download</a></div></div>") ;
	return section ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実端末情報、実payloadまたはnetworkを使用せず、六つのx64欄を構築する。
 *
 * @param[in] version 六つのOS欄へ設定する架空配布版。
 * @param[in] url 六つのOS欄へ設定する架空download URL。
 * @return Ricoh固定page schemaを再現する所有HTML。
 */
//------------------------------------------------------------------------------
std::wstring makeRicohPage( const std::wstring_view version, const std::wstring_view url)
{
	constexpr std::array OPERATING_SYSTEMS{
		std::wstring_view( L"Microsoft Windows 11 (64-bit)"),
		std::wstring_view( L"Microsoft Windows 10 (64-bit)"),
		std::wstring_view( L"Microsoft Windows Server 2025 (64-bit)"),
		std::wstring_view( L"Microsoft Windows Server 2022 (64-bit)"),
		std::wstring_view( L"Microsoft Windows Server 2019 (64-bit)"),
		// 必須OS欄。
		std::wstring_view( L"Microsoft Windows Server 2016 (64-bit)")} ;
	std::wstring page = L"<html><h1 class=\"hd01\">Universal Print Driver</h1>" ;	// 合成page本体。
	// 六つの対象OS欄を同じ配布情報で構築する。
	for( const std::wstring_view operatingSystem : OPERATING_SYSTEMS) {
		page.append( makeRicohSection( operatingSystem, version, url)) ;
	}

	page.append( makeRicohSection( L"Microsoft Windows 10 (32-bit)", version,
								 L"https://support.ricoh.com/bb/pub_e/dr_ut_e/0000000/"
								 L"0000000000/V00000/x86fixture.exe")) ;
	page.append( L"</html>") ;
	return page ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実Hardware ID、serial numberまたはinstance pathを含めない。
 *
 * @param[in] identity 架空のopaque device ID。
 * @return Ricoh Printer classの合成snapshot。
 */
//------------------------------------------------------------------------------
OfficialCatalogDevice ricohPrinterDevice( std::wstring identity)
{
	OfficialCatalogDevice device ;	// Ricoh local probeへ渡す非機密snapshot。
	device.deviceIdentity  = std::move( identity) ;
	device.model		   = L"RICOH Universal Printer Fixture" ;
	device.manufacturer	   = L"RICOH" ;
	device.driverClass	   = L"Printer" ;
	device.deviceClassGuid = L"{4d36e979-e325-11ce-bfc1-08002be10318}" ;
	return device ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実Hardware ID、serial numberまたはinstance pathを含めない。
 *
 * @param[in] identity 架空のopaque device ID。
 * @return Wacom HIDClassの合成snapshot。
 */
//------------------------------------------------------------------------------
OfficialCatalogDevice wacomHidDevice( std::wstring identity)
{
	OfficialCatalogDevice device ;	// Wacom local probeへ渡す非機密snapshot。
	device.deviceIdentity  = std::move( identity) ;
	device.model		   = L"Wacom Tablet Fixture" ;
	device.manufacturer	   = L"Wacom Co., Ltd." ;
	device.driverClass	   = L"HIDClass" ;
	device.deviceClassGuid = L"{745a17a0-74d3-11d0-b6fe-00a0c90f57da}" ;
	return device ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実Hardware ID、serial numberまたはinstance pathを含めない。
 *
 * @param[in] identity 架空のopaque device ID。
 * @return Focusrite Scarlett 2i2 MEDIA classの合成snapshot。
 */
//------------------------------------------------------------------------------
OfficialCatalogDevice focusriteScarlett2i2Device( std::wstring identity)
{
	OfficialCatalogDevice device ;	// Focusrite local probeへ渡す非機密snapshot。
	device.deviceIdentity  = std::move( identity) ;
	device.model		   = L"Focusrite Scarlett 2i2 2nd Gen Fixture" ;
	device.manufacturer	   = L"Focusrite Audio Engineering" ;
	device.driverClass	   = L"MEDIA" ;
	device.deviceClassGuid = L"{4d36e96c-e325-11ce-bfc1-08002be10318}" ;
	return device ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二系列の共通情報と、明示値以外を補完しないことを確認する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testReleaseRecords( TestContext &context)
{
	OfficialReleaseRecord release ;	// 成功情報と失敗時初期化の確認先。
	DRIVERCRATE_EXPECT( context, parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_WIFI,
														   INTEL_PAGE, release)) ;
	DRIVERCRATE_EXPECT( context, release.family == OfficialReleaseFamily::INTEL_WIFI) ;
	DRIVERCRATE_EXPECT( context, release.packageVersion == L"24.60.0") ;
	DRIVERCRATE_EXPECT( context, release.displaySize == L"42.7 MB") ;
	DRIVERCRATE_EXPECT( context, !release.publishedSizeBytes.has_value()) ;
	DRIVERCRATE_EXPECT( context, release.publishedSha256.size() == 64U) ;
	DRIVERCRATE_EXPECT( context, release.parserRevision == 2U) ;
	DRIVERCRATE_EXPECT( context, release.eulaRevision.empty()) ;
	// Raw text内の偽labelと未終端entityを可視欄へ持ち込まない。
	const std::wstring decorated =
		L"<!-- Available Downloads --><script>bad & unfinished</script><style>x & y</style><textarea>Available Downloads & unfinished</textarea><p>Drivers & Software</p>" +
		// 実pageの形だけを再現。
		std::wstring( INTEL_PAGE) ;
	OfficialReleaseRecord decoratedRelease ;	// 元fixtureの結果を保持する別出力。
	DRIVERCRATE_EXPECT( context, parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_WIFI,
														   decorated, decoratedRelease) &&
									decoratedRelease.fileName == release.fileName) ;
	DRIVERCRATE_EXPECT(
		context, !parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_WIFI,
											 L"<p>&unfinished </p>" + std::wstring( INTEL_PAGE),
											 decoratedRelease)) ;
	DRIVERCRATE_EXPECT( context,
					   release.license == OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD) ;

	DRIVERCRATE_EXPECT( context, parseOfficialReleaseRecord( OfficialReleaseFamily::PROLIFIC_DCHU,
														   PROLIFIC_PAGE, release)) ;
	DRIVERCRATE_EXPECT( context, release.fileName == L"PL2303G_DCHU_fixture.zip") ;
	DRIVERCRATE_EXPECT( context, release.packageVersion.empty()) ;
	DRIVERCRATE_EXPECT( context, release.publishedSha256.empty()) ;
	DRIVERCRATE_EXPECT( context, release.displaySize.empty()) ;
	DRIVERCRATE_EXPECT( context, !release.publishedSizeBytes.has_value()) ;
	DRIVERCRATE_EXPECT( context, release.license == OfficialReleaseLicense::UNRESOLVED) ;
	DRIVERCRATE_EXPECT( context, !parseOfficialReleaseRecord( static_cast<OfficialReleaseFamily>( 999),
															INTEL_PAGE, release)) ;
	DRIVERCRATE_EXPECT( context, release.family == OfficialReleaseFamily::UNKNOWN) ;
	DRIVERCRATE_EXPECT( context, release.downloadUrl.empty()) ;
	DRIVERCRATE_EXPECT( context, !parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_WIFI,
															PROLIFIC_PAGE, release)) ;

	std::wstring next( INTEL_PAGE) ;	// 全ての明示版を同じ仮の新版へ変更する。
	std::size_t	 position = 0U ;		// 置換済み位置より後だけを走査する。
	// 同じ長さの版へ有限回で置換し、版固定に依存しないことを確認する。
	while( (position = next.find( L"24.60.0", position)) != std::wstring::npos) {
		next.replace( position, 7U, L"25.10.0") ;
		position += 7U ;
	}

	DRIVERCRATE_EXPECT(
		context, parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_WIFI, next, release)) ;
	DRIVERCRATE_EXPECT( context, release.packageVersion == L"25.10.0") ;

	std::wstring badUrl( INTEL_PAGE) ;	// 許可hostの類似名へ改変したpage。
	badUrl.replace( badUrl.find( L"downloadmirror.intel.com"),
				   std::wstring_view( L"downloadmirror.intel.com").size(),
				   L"mirror.invalid.example") ;
	DRIVERCRATE_EXPECT(
		context, !parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_WIFI, badUrl, release)) ;
	DRIVERCRATE_EXPECT( context, release.downloadUrl.empty()) ;
	DRIVERCRATE_EXPECT( context, !parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_WIFI,
															L"<html>unavailable</html>", release)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不明な現在版・classと、明示的な別classを区別する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testLocalProbe( TestContext &context)
{
	OfficialCatalogDevice device = intelDevice( L"fixture-device") ;	// Probeの入力だけを変更する。
	DRIVERCRATE_EXPECT( context,
					   officialReleaseDeviceMatches( OfficialReleaseFamily::INTEL_WIFI, device)) ;
	device.driverClass.clear() ;
	device.currentVersion.clear() ;
	DRIVERCRATE_EXPECT( context,
					   officialReleaseDeviceMatches( OfficialReleaseFamily::INTEL_WIFI, device)) ;
	device.driverClass = L"Bluetooth" ;
	DRIVERCRATE_EXPECT( context,
					   !officialReleaseDeviceMatches( OfficialReleaseFamily::INTEL_WIFI, device)) ;
	device.driverClass.clear() ;
	device.deviceClassGuid = L"{4d36e978-e325-11ce-bfc1-08002be10318}" ;
	DRIVERCRATE_EXPECT( context,
					   !officialReleaseDeviceMatches( OfficialReleaseFamily::INTEL_WIFI, device)) ;
	device.deviceClassGuid.clear() ;
	device.model = L"Other Wi-Fi Fixture" ;
	DRIVERCRATE_EXPECT( context,
					   !officialReleaseDeviceMatches( OfficialReleaseFamily::INTEL_WIFI, device)) ;
	device.model = L"Intel Ethernet Fixture" ;
	DRIVERCRATE_EXPECT( context,
					   !officialReleaseDeviceMatches( OfficialReleaseFamily::INTEL_WIFI, device)) ;
	device.model = L"Intel(R) Wireless Fixture" ;
	DRIVERCRATE_EXPECT( context,
					   officialReleaseDeviceMatches( OfficialReleaseFamily::INTEL_WIFI, device)) ;
	device.model = L"Prolific PL2303 Fixture" ;
	DRIVERCRATE_EXPECT( context,
					   officialReleaseDeviceMatches( OfficialReleaseFamily::PROLIFIC_DCHU, device)) ;
	DRIVERCRATE_EXPECT( context,
					   !officialReleaseDeviceMatches( OfficialReleaseFamily::UNKNOWN, device)) ;
	device.deviceIdentity.clear() ;
	DRIVERCRATE_EXPECT( context,
					   !officialReleaseDeviceMatches( OfficialReleaseFamily::PROLIFIC_DCHU, device)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一回のmetadataを同型二台へ表示し、適用性や導入許可へ昇格しない。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testDiscoveryResults( TestContext &context)
{
	const std::array					devices{intelDevice( L"fixture-one"),
								// 同型二台。
								intelDevice( L"fixture-two")} ;
	std::size_t							reads{} ;	// Metadataだけの取得回数。
	std::vector<ProviderProgress>		updates ;	// 完了した段階の通知列。
	const OfficialReleaseMetadataReader reader =
		[&context, &reads]( const OfficialReleaseFamily family, const ScanSessionId session,
						   OfficialReleaseRecord &release, bool &rejected) {
			++reads ;
			rejected = false ;
			DRIVERCRATE_EXPECT( context, session == SESSION) ;
			DRIVERCRATE_EXPECT( context, parseOfficialReleaseRecord( family, INTEL_PAGE, release)) ;
			return NativeError{0} ;
		} ; // 合成pageを解析するだけで通信しない。
	const ProviderProgressCallback progress = [&updates]( const ProviderProgress &value) {
		updates.push_back( value) ;
	} ; // 値だけを保存。
	ProviderMeasurementEvidence evidence ;	// 同型二台へ結合する一recordのworker内根拠。
	const ScanResult			result = scanOfficialReleaseMetadata(
		   OfficialReleaseFamily::INTEL_WIFI, SESSION, devices, false, reader, progress, 0U, {},
		   &evidence) ;	// 対象検索。
	DRIVERCRATE_EXPECT( context, reads == 1U) ;
	const ScanResult withoutMeasurement = scanOfficialReleaseMetadata(
		OfficialReleaseFamily::INTEL_WIFI, SESSION, devices, false, reader,
		progress) ;	// 計測出力先を渡さない同一入力の比較scan。
	DRIVERCRATE_EXPECT( context, reads == 2U) ;
	DRIVERCRATE_EXPECT( context, withoutMeasurement.succeeded) ;
	DRIVERCRATE_EXPECT( context, withoutMeasurement.candidates.size() == result.candidates.size()) ;
	DRIVERCRATE_EXPECT( context, result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.state == ProviderScanState::CANDIDATES_AVAILABLE) ;
	DRIVERCRATE_EXPECT( context, result.candidates.size() == 2U) ;
	DRIVERCRATE_EXPECT( context, result.coverage.eligibleDeviceCount == 2U) ;
	DRIVERCRATE_EXPECT( context, result.coverage.assessedDeviceCount == 2U) ;
	DRIVERCRATE_EXPECT( context, isProviderScanResultConsistent( result, true)) ;
	DRIVERCRATE_EXPECT( context, evidence.providerId == INTEL_WIFI_OFFICIAL_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, evidence.scanSessionId == SESSION) ;
	DRIVERCRATE_EXPECT( context, evidence.scope == MeasurementScope::DEVICE_QUERY) ;
	DRIVERCRATE_EXPECT( context, evidence.queryOutcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, evidence.eligible.extent == MeasurementExtent::EXACT) ;
	DRIVERCRATE_EXPECT( context, evidence.eligible.identities.size() == 2U) ;
	DRIVERCRATE_EXPECT( context, evidence.queryCompleted.identities == evidence.eligible.identities) ;
	DRIVERCRATE_EXPECT( context, evidence.information.identities == evidence.eligible.identities) ;
	DRIVERCRATE_EXPECT( context, evidence.recordExtent == MeasurementExtent::EXACT) ;
	DRIVERCRATE_EXPECT( context, evidence.records.size() == 1U) ;
	// 一recordが同型二deviceへ結合した場合だけrecord内容を参照する。
	if( evidence.records.size() == 1U) {
		DRIVERCRATE_EXPECT( context, evidence.records.front().deviceIdentities ==
										evidence.eligible.identities) ;
	}

	DRIVERCRATE_EXPECT( context, evidence.applicabilityExtent == MeasurementExtent::LOWER_BOUND) ;
	DRIVERCRATE_EXPECT( context, evidence.readinessExtent == MeasurementExtent::LOWER_BOUND) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( result.candidates.size() == 2U) {
		DRIVERCRATE_EXPECT( context, result.candidates[0].identity != result.candidates[1].identity) ;
		DRIVERCRATE_EXPECT( context, result.candidates[0].deviceIdentity == L"fixture-one") ;
		DRIVERCRATE_EXPECT( context, result.candidates[1].deviceIdentity == L"fixture-two") ;
		DRIVERCRATE_EXPECT( context, result.candidates[0].packageIdentity ==
										result.candidates[1].packageIdentity) ;
	}

	// 全表示行が監査未完了であり、URL・INF版・download sizeを補完していないことを確認する。
	for( const UpdateCandidate &candidate : result.candidates) {
		DRIVERCRATE_EXPECT( context,
						   !candidate.installable && !candidate.recommended && !candidate.current) ;
		DRIVERCRATE_EXPECT( context, !candidate.eulaAccepted && !candidate.allContentCached) ;
		DRIVERCRATE_EXPECT( context, candidate.action == DriverAction::NONE) ;
		DRIVERCRATE_EXPECT( context, candidate.version.empty() && candidate.driverDate.empty()) ;
		DRIVERCRATE_EXPECT( context, candidate.provider.empty()) ;
		DRIVERCRATE_EXPECT( context, candidate.maximumDownloadBytes == 0U) ;
		DRIVERCRATE_EXPECT( context, candidate.sourceLocation == L"www.intel.com") ;
		DRIVERCRATE_EXPECT( context, candidate.title.find( L"https:") == std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context,
						   candidate.sourceName.find( L"downloadmirror") == std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context,
						   candidate.audit.systemApplicability == CandidateAuditGateState::PENDING) ;
		// Registryのcapabilityと表示専用候補の監査契約を照合する。
		for( const ProviderDescriptor &descriptor : builtInProviderDescriptors()) {
			// 候補と同じProvider定義を使って監査状態の整合性を検証する。
			if( descriptor.id == candidate.providerId) {
				DRIVERCRATE_EXPECT( context, isCandidateAuditValid( candidate, descriptor)) ;
			}
		}
	}

	DRIVERCRATE_EXPECT( context, !updates.empty() && updates.front().percentComplete == 0U) ;
	DRIVERCRATE_EXPECT( context, !updates.empty() && updates.back().percentComplete == 100U) ;
	DRIVERCRATE_EXPECT( context, !updates.empty() && updates.back().completedItems == 2U) ;
	const ScanResult repeated = scanOfficialReleaseMetadata(
		OfficialReleaseFamily::INTEL_WIFI, SESSION + 1U, devices, false,
		[]( const OfficialReleaseFamily family, const ScanSessionId, OfficialReleaseRecord &release,
		   bool &rejected) {
			rejected = !parseOfficialReleaseRecord( family, INTEL_PAGE, release) ;
			return NativeError{0} ;
		},
		progress) ;	// 別sessionでは表示identityを再発行する。
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( !result.candidates.empty() && !repeated.candidates.empty()) {
		DRIVERCRATE_EXPECT( context, result.candidates.front().identity !=
										repeated.candidates.front().identity) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 対象外・入力不正・Serverでは取得を呼ばず、失敗の診断値を保持する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testRejectionsWithoutNetwork( TestContext &context)
{
	std::size_t							reads{} ;	// 不要なmetadata取得が発生しないことを確認する。
	const OfficialReleaseMetadataReader reader = [&reads]( const OfficialReleaseFamily,
														  const ScanSessionId,
														  OfficialReleaseRecord &, bool &) {
		++reads ;
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	} ; // 実通信せず取得拒否を返す。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {
	} ; // 通知値は使用しない。
	std::array devices{intelDevice( L"fixture-one")} ;	// 個別の入力拒否試験用。
	DRIVERCRATE_EXPECT( context, scanOfficialReleaseMetadata( OfficialReleaseFamily::INTEL_WIFI,
															SESSION, {}, false, reader, progress)
										.state == ProviderScanState::NOT_APPLICABLE) ;
	DRIVERCRATE_EXPECT( context,
					   scanOfficialReleaseMetadata( OfficialReleaseFamily::INTEL_WIFI, SESSION,
												   devices, true, reader, progress)
							   .state == ProviderScanState::NOT_APPLICABLE) ;
	devices[0].model = L"Other Device" ;
	DRIVERCRATE_EXPECT( context,
					   scanOfficialReleaseMetadata( OfficialReleaseFamily::INTEL_WIFI, SESSION,
												   devices, false, reader, progress)
							   .state == ProviderScanState::NOT_APPLICABLE) ;
	devices[0] = intelDevice( L"fixture-one") ;
	DRIVERCRATE_EXPECT( context, !scanOfficialReleaseMetadata( OfficialReleaseFamily::INTEL_WIFI, 0U,
															 devices, false, reader, progress)
									 .succeeded) ;
	DRIVERCRATE_EXPECT( context,
					   !scanOfficialReleaseMetadata( OfficialReleaseFamily::UNKNOWN, SESSION,
													devices, false, reader, progress)
							.succeeded) ;
	const std::array duplicate{devices[0], devices[0]} ;	// 重複opaque identityの禁止。
	DRIVERCRATE_EXPECT( context,
					   !scanOfficialReleaseMetadata( OfficialReleaseFamily::INTEL_WIFI, SESSION,
													duplicate, false, reader, progress)
							.succeeded) ;
	const std::vector<OfficialCatalogDevice> oversized( 4097U) ;	// 入力上限を一件超過。
	DRIVERCRATE_EXPECT( context,
					   !scanOfficialReleaseMetadata( OfficialReleaseFamily::INTEL_WIFI, SESSION,
													oversized, false, reader, progress)
							.succeeded) ;
	DRIVERCRATE_EXPECT( context, !scanOfficialReleaseMetadata( OfficialReleaseFamily::INTEL_WIFI,
															 SESSION, devices, false, {}, progress)
									 .succeeded) ;
	DRIVERCRATE_EXPECT( context, !scanOfficialReleaseMetadata( OfficialReleaseFamily::INTEL_WIFI,
															 SESSION, devices, false, reader, {})
									 .succeeded) ;
	DRIVERCRATE_EXPECT( context, reads == 0U) ;

	ProviderMeasurementEvidence failedEvidence ;	// Metadata取得失敗時の確定済み対象と下限。
	const ScanResult			failed = scanOfficialReleaseMetadata(
		   OfficialReleaseFamily::INTEL_WIFI, SESSION, devices, false, reader, progress, 0U, {},
		   &failedEvidence) ;	// 取得拒否。
	DRIVERCRATE_EXPECT( context, reads == 1U) ;
	DRIVERCRATE_EXPECT( context, !failed.succeeded && failed.state == ProviderScanState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, failed.error == static_cast<NativeError>( E_ACCESSDENIED)) ;
	DRIVERCRATE_EXPECT( context, failed.candidates.empty()) ;
	DRIVERCRATE_EXPECT( context, failedEvidence.queryOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, failedEvidence.eligible.extent == MeasurementExtent::EXACT) ;
	DRIVERCRATE_EXPECT( context, failedEvidence.eligible.identities.size() == 1U) ;
	DRIVERCRATE_EXPECT( context,
					   failedEvidence.queryCompleted.extent == MeasurementExtent::LOWER_BOUND) ;
	DRIVERCRATE_EXPECT( context,
					   failedEvidence.information.extent == MeasurementExtent::LOWER_BOUND) ;
	DRIVERCRATE_EXPECT( context, failedEvidence.records.empty()) ;
	const ScanResult rejected = scanOfficialReleaseMetadata(
		OfficialReleaseFamily::INTEL_WIFI, SESSION, devices, false,
		[]( const OfficialReleaseFamily, const ScanSessionId, OfficialReleaseRecord &,
		   bool &rejected) {
			rejected = true ;
			return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
		},
		progress) ;	// 取得成功後のschema拒否。
	DRIVERCRATE_EXPECT( context, rejected.state == ProviderScanState::METADATA_REJECTED) ;
	DRIVERCRATE_EXPECT( context, rejected.error == static_cast<NativeError>(
													  HRESULT_FROM_WIN32( ERROR_INVALID_DATA))) ;
	const ScanResult wrongFamily = scanOfficialReleaseMetadata(
		OfficialReleaseFamily::INTEL_WIFI, SESSION, devices, false,
		[]( const OfficialReleaseFamily, const ScanSessionId, OfficialReleaseRecord &release,
		   bool &) {
			static_cast<void>( parseOfficialReleaseRecord( OfficialReleaseFamily::PROLIFIC_DCHU,
														 PROLIFIC_PAGE, release)) ;
			return NativeError{0} ;
		},
		progress) ;	// 別系列のrecordを成功として渡しても拒否する。
	DRIVERCRATE_EXPECT( context, !wrongFamily.succeeded) ;
	DRIVERCRATE_EXPECT( context, wrongFamily.state == ProviderScanState::METADATA_REJECTED) ;

	OfficialHttpClient	  http ;				// 不正sessionなら実HTTPへ進まないclient。
	OfficialReleaseRecord release ;				// 不正要求で初期化されるmetadata。
	bool				  invalidMetadata{} ;	// 入力拒否と解析拒否を分ける出力。
	DRIVERCRATE_EXPECT( context, readOfficialReleaseMetadata( OfficialReleaseFamily::INTEL_WIFI, 0U,
															http, release, invalidMetadata) ==
									static_cast<NativeError>( E_INVALIDARG)) ;
	DRIVERCRATE_EXPECT( context, !invalidMetadata && release.downloadUrl.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定host、redirect禁止、payload未登録、直接install拒否を確認する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testSourceAndInstallBoundaries( TestContext &context)
{
	const OfficialSourceDefinition *const definition =
		// 共通の検索契約。
		officialSourceDefinition( OfficialReleaseFamily::INTEL_WIFI) ;
	DRIVERCRATE_EXPECT( context, definition != nullptr) ;
	// Intel Wi-Fiの固定定義を取得できた場合にだけ各識別fieldを検証する。
	if( definition != nullptr) {
		DRIVERCRATE_EXPECT( context, definition->providerId == INTEL_WIFI_OFFICIAL_PROVIDER_ID) ;
		DRIVERCRATE_EXPECT( context, definition->sourceId == INTEL_WIFI_OFFICIAL_SOURCE_POLICY_ID) ;
		DRIVERCRATE_EXPECT( context, definition->familyId == L"intel-wifi") ;
		DRIVERCRATE_EXPECT( context, definition->productKey == L"18231") ;
		DRIVERCRATE_EXPECT( context, definition->profileId == L"intel-wifi-inf") ;
		DRIVERCRATE_EXPECT( context, definition->observationPolicyRevision == 1U) ;
		DRIVERCRATE_EXPECT( context, definition->maximumMetadataBytes == 2ULL * 1024ULL * 1024ULL) ;
	}

	DRIVERCRATE_EXPECT( context,
					   officialSourceDefinition( OfficialReleaseFamily::UNKNOWN) == nullptr) ;
	const OfficialSourceDefinition *const asixDefinition =
		// ASIX観測検索契約。
		officialSourceDefinition( OfficialReleaseFamily::ASIX_AX88179A) ;
	DRIVERCRATE_EXPECT( context, asixDefinition != nullptr) ;
	// ASIXの固定定義を取得できた場合にだけ各識別fieldを検証する。
	if( asixDefinition != nullptr) {
		DRIVERCRATE_EXPECT( context, asixDefinition->providerId == ASIX_AX88179A_PROVIDER_ID) ;
		DRIVERCRATE_EXPECT( context, asixDefinition->sourceId == ASIX_OFFICIAL_SOURCE_POLICY_ID) ;
		DRIVERCRATE_EXPECT( context, asixDefinition->familyId == L"asix-ax88179a") ;
		DRIVERCRATE_EXPECT( context, asixDefinition->productKey == L"AX88179A") ;
		DRIVERCRATE_EXPECT( context, asixDefinition->branch == L"windows-client-x64") ;
		DRIVERCRATE_EXPECT( context, asixDefinition->profileId.empty()) ;
		DRIVERCRATE_EXPECT( context, asixDefinition->observationPolicyRevision == 2U) ;
	}

	const OfficialSourcePolicy *const policy =
		// 実host policy。
		officialSourcePolicyForProvider( INTEL_WIFI_OFFICIAL_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, policy != nullptr) ;
	// 取得元policyを取得できた場合にだけ用途別resource境界を検証する。
	if( policy != nullptr) {
		const auto *payload = findOfficialSourceResource(
			*policy, OFFICIAL_PAYLOAD_RESOURCE_ID) ;	// ADR 0197のZIP用途。
		DRIVERCRATE_EXPECT( context, payload != nullptr) ;
		// 登録済みの場合だけ取得先とredirect禁止を照合する。
		if( payload != nullptr) {
			DRIVERCRATE_EXPECT( context, payload->kind == OfficialSourceResourceKind::PAYLOAD) ;
			DRIVERCRATE_EXPECT( context, payload->maximumRedirects == 0U) ;
			DRIVERCRATE_EXPECT( context,
							   payload->allowedHosts.size() == 1U &&
								   payload->allowedHosts.front() == L"downloadmirror.intel.com") ;
		}

		const OfficialSourceResourcePolicy *const landing =
			// 固定page用途。
			findOfficialSourceResource( *policy, OFFICIAL_LANDING_RESOURCE_ID) ;
		DRIVERCRATE_EXPECT( context, landing != nullptr) ;
		// landing resourceを取得できた場合にだけhostとredirect制限を検証する。
		if( landing != nullptr) {
			DRIVERCRATE_EXPECT( context, landing->maximumRedirects == 0U) ;
			DRIVERCRATE_EXPECT( context, landing->allowedHosts.size() == 1U) ;
			DRIVERCRATE_EXPECT( context, landing->allowedHosts.front() == L"www.intel.com") ;
		}
	}

	// 取得元設定は自動生成menuへ反映するが、導入capabilityは付与しない。
	for( const ProviderDescriptor &descriptor : builtInProviderDescriptors()) {
		// Intel Wi-Fiのregistry定義に対して既定状態とcapabilityを検証する。
		if( descriptor.id == INTEL_WIFI_OFFICIAL_PROVIDER_ID) {
			DRIVERCRATE_EXPECT( context, !descriptor.enabledByDefault) ;
			DRIVERCRATE_EXPECT( context,
							   descriptor.capabilities ==
								   (capabilityMask( ProviderCapability::METADATA_ONLY_SCAN) |
									capabilityMask( ProviderCapability::SCAN) |
									capabilityMask( ProviderCapability::OFFICIAL_NETWORK))) ;
		}
	}

	OfficialReleaseDiscoveryProvider provider( OfficialReleaseFamily::INTEL_WIFI) ;	// 表示専用。
	const InstallResult result = provider.install( SESSION, {}, 0U, {}) ;			// OS導入を呼ばない。
	DRIVERCRATE_EXPECT( context, result.downloadOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, result.downloadError == static_cast<NativeError>( E_NOTIMPL)) ;
	DRIVERCRATE_EXPECT( context, result.installOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, result.installError == static_cast<NativeError>( E_NOTIMPL)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Server 2025と掲載Intel NICだけが表示専用検索へ進み、別OSと取得を拒否する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetServerDiscovery( TestContext &context)
{
	OfficialReleaseRecord release ;	// Server専用pageから解析する共通record。
	DRIVERCRATE_EXPECT( context,
					   parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025,
												  INTEL_ETHERNET_SERVER_PAGE, release)) ;
	DRIVERCRATE_EXPECT( context, release.family == OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025) ;
	DRIVERCRATE_EXPECT( context, release.fileName == L"Wired_driver_31.2.2_x64.zip") ;
	DRIVERCRATE_EXPECT( context, release.packageVersion == L"31.2.2") ;
	DRIVERCRATE_EXPECT( context, release.displaySize == L"38.6 MB") ;
	DRIVERCRATE_EXPECT( context, release.publishedSha256.size() == 64U) ;
	DRIVERCRATE_EXPECT( context,
					   release.license == OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD) ;
	DRIVERCRATE_EXPECT( context, makeReleasePreparationTargets( release, SESSION, 7U, 1U).empty()) ;

	OfficialCatalogDevice device =
		// Local系列probeの正常入力。
		intelEthernetServerDevice( L"server-nic") ;
	DRIVERCRATE_EXPECT( context, officialReleaseDeviceMatches(
									OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025, device)) ;
	device.model = L"Intel(R) Wi-Fi Fixture" ;
	DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches(
									OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025, device)) ;
	device			   = intelEthernetServerDevice( L"server-nic") ;
	device.driverClass = L"Display" ;
	DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches(
									OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025, device)) ;

	DRIVERCRATE_EXPECT( context,
					   officialReleaseOperatingSystemMatches(
						   OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025, true, 26100U)) ;
	DRIVERCRATE_EXPECT( context,
					   !officialReleaseOperatingSystemMatches(
						   OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025, false, 26100U)) ;
	DRIVERCRATE_EXPECT( context,
					   !officialReleaseOperatingSystemMatches(
						   OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025, true, 20348U)) ;
	DRIVERCRATE_EXPECT( context, !officialReleaseOperatingSystemMatches(
									OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025, true, 0U)) ;

	const std::array					devices{	// 一台のServer NIC inventory。
								intelEthernetServerDevice( L"server-nic")} ;
	std::size_t							reads{} ;	// 公式metadata readerの呼出し回数。
	const OfficialReleaseMetadataReader reader =
		[&reads]( const OfficialReleaseFamily family, const ScanSessionId,
				 OfficialReleaseRecord &result, bool &rejected) {
			++reads ;
			rejected = !parseOfficialReleaseRecord( family, INTEL_ETHERNET_SERVER_PAGE, result) ;
			return NativeError{0} ;
		} ; // 合成pageだけを読むnetwork不要境界。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {} ;	// 通知は破棄する。
	const ScanResult			   result	= scanOfficialReleaseMetadata(
		OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025, SESSION, devices, true, reader, progress,
		26100U) ;	// Server 2025だけを許可する検索。
	DRIVERCRATE_EXPECT( context, reads == 1U) ;
	DRIVERCRATE_EXPECT( context, result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.state == ProviderScanState::CANDIDATES_AVAILABLE) ;
	DRIVERCRATE_EXPECT( context, result.candidates.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( result.candidates.size() == 1U) {
		DRIVERCRATE_EXPECT( context, !result.candidates[0].installable) ;
		DRIVERCRATE_EXPECT( context, !result.candidates[0].recommended) ;
		DRIVERCRATE_EXPECT( context, result.candidates[0].sourceLocation == L"www.intel.com") ;
		DRIVERCRATE_EXPECT( context, result.candidates[0].providerId ==
										INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID) ;
	}

	DRIVERCRATE_EXPECT(
		context, scanOfficialReleaseMetadata( OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025,
											 SESSION + 1U, devices, true, reader, progress, 20348U)
						 .state == ProviderScanState::NOT_APPLICABLE) ;
	DRIVERCRATE_EXPECT(
		context, scanOfficialReleaseMetadata( OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025,
											 SESSION + 2U, devices, false, reader, progress, 26100U)
						 .state == ProviderScanState::NOT_APPLICABLE) ;
	DRIVERCRATE_EXPECT( context, reads == 1U) ;

	const OfficialSourceDefinition *const definition =
		officialSourceDefinition( OfficialReleaseFamily::INTEL_ETHERNET_SERVER2025) ;
	DRIVERCRATE_EXPECT( context, definition != nullptr) ;
	// Intel Serverの固定定義を取得できた場合にだけ各識別fieldを検証する。
	if( definition != nullptr) {
		DRIVERCRATE_EXPECT( context, definition->providerId ==
										INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID) ;
		DRIVERCRATE_EXPECT( context, definition->sourceId ==
										INTEL_ETHERNET_SERVER2025_OFFICIAL_SOURCE_POLICY_ID) ;
		DRIVERCRATE_EXPECT( context, definition->familyId == L"intel-ethernet-server-2025") ;
		DRIVERCRATE_EXPECT( context, definition->productKey == L"838943") ;
		DRIVERCRATE_EXPECT( context, definition->profileId == L"intel-ethernet-server-2025-inf") ;
		DRIVERCRATE_EXPECT( context, definition->observationPolicyRevision == 2U) ;
	}

	const OfficialSourcePolicy *const policy =
		officialSourcePolicyForProvider( INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, policy != nullptr) ;
	// Intel Serverのpolicyがある場合にだけlandingとpayload用途を検証する。
	if( policy != nullptr) {
		DRIVERCRATE_EXPECT(
			context, findOfficialSourceResource( *policy, OFFICIAL_LANDING_RESOURCE_ID) != nullptr) ;
		DRIVERCRATE_EXPECT(
			context, findOfficialSourceResource( *policy, OFFICIAL_PAYLOAD_RESOURCE_ID) != nullptr) ;
	}

	const OfficialSourceDefinition *const windows11Definition =
		// Client定義。
		officialSourceDefinition( OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11) ;
	DRIVERCRATE_EXPECT( context, windows11Definition != nullptr) ;
	// Windows 11固定定義を取得できた場合だけServer系列との分離を検証する。
	if( windows11Definition != nullptr) {
		DRIVERCRATE_EXPECT( context, windows11Definition->providerId ==
										INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID) ;
		DRIVERCRATE_EXPECT( context, windows11Definition->sourceId ==
										INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID) ;
		DRIVERCRATE_EXPECT( context, windows11Definition->familyId == L"intel-ethernet-windows11") ;
		DRIVERCRATE_EXPECT( context, windows11Definition->productKey == L"727998") ;
		DRIVERCRATE_EXPECT( context,
						   windows11Definition->profileId == L"intel-ethernet-windows11-inf") ;
	}

	device = intelEthernetServerDevice( L"windows11-nic") ;
	DRIVERCRATE_EXPECT( context, officialReleaseDeviceMatches(
									OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11, device)) ;
	DRIVERCRATE_EXPECT( context,
					   officialReleaseOperatingSystemMatches(
						   OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11, false, 22621U)) ;
	DRIVERCRATE_EXPECT( context, !officialReleaseOperatingSystemMatches(
									OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11, true, 26100U)) ;
	DRIVERCRATE_EXPECT( context,
					   !officialReleaseOperatingSystemMatches(
						   OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11, false, 19045U)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 六つのx64 OS欄、公式host、Ricoh Printer／PrintQueue照合、表示専用候補、release観測および拒否境界を合成pageだけで確認する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testRicohUniversalPrintDiscovery( TestContext &context)
{
	constexpr std::wstring_view URL =
		L"https://support.ricoh.com/bb/pub_e/dr_ut_e/0001346/0001346104/V44500/"
		L"z07106L24.exe" ;														// 形式だけが現行公式pathと一致するfixture URL。
	const std::wstring				page = makeRicohPage( L"4.45.0.0", URL) ;	// 六OS一致の正常page。
	RicohUniversalPrintPageMetadata metadata ;									// 専用parserの正常・拒否結果。
	DRIVERCRATE_EXPECT( context, parseRicohUniversalPrintPage( page, metadata)) ;
	DRIVERCRATE_EXPECT( context, metadata.fileName == L"z07106L24.exe") ;
	DRIVERCRATE_EXPECT( context, metadata.version == L"4.45.0.0") ;
	DRIVERCRATE_EXPECT( context, metadata.releaseDate == L"06/23/2026") ;
	DRIVERCRATE_EXPECT( context, metadata.displaySize == L"34,552 KB") ;
	DRIVERCRATE_EXPECT( context, metadata.downloadUrl == URL) ;

	const std::wstring nextPage = makeRicohPage( L"4.46.0.0", URL) ;	// 仮の次版page。
	DRIVERCRATE_EXPECT( context, parseRicohUniversalPrintPage( nextPage, metadata)) ;
	DRIVERCRATE_EXPECT( context, metadata.version == L"4.46.0.0") ;

	std::wstring	  divergent( page) ;							// 最初のOS欄だけ版が異なるpage。
	const std::size_t firstVersion = divergent.find( L"4.45.0.0") ;	// 最初の版位置。
	DRIVERCRATE_EXPECT( context, firstVersion != std::wstring::npos) ;
	// 掲載版の位置を取得できた場合にだけ差異を注入して版一致条件を検証する。
	if( firstVersion != std::wstring::npos) {
		divergent.replace( firstVersion, 8U, L"4.44.0.0") ;
	}

	DRIVERCRATE_EXPECT( context, !parseRicohUniversalPrintPage( divergent, metadata)) ;

	std::wstring	  badHost( page) ;									// 最初の対象行だけ類似hostへ変更したpage。
	const std::size_t firstHost = badHost.find( L"support.ricoh.com") ;	// 最初のhost位置。
	DRIVERCRATE_EXPECT( context, firstHost != std::wstring::npos) ;
	// host位置を取得できた場合にだけ非公式hostへ置換して拒否を検証する。
	if( firstHost != std::wstring::npos) {
		badHost.replace( firstHost, 17U, L"support.ricoh.example") ;
	}

	DRIVERCRATE_EXPECT( context, !parseRicohUniversalPrintPage( badHost, metadata)) ;

	std::wstring				missingOs( page) ;	// Server 2016欄を欠落扱いにするpage。
	constexpr std::wstring_view SERVER2016 =
		L"Microsoft Windows Server 2016 (64-bit)" ;					// 置換する必須見出し。
	const std::size_t server2016 = missingOs.find( SERVER2016) ;	// 必須見出し位置。
	DRIVERCRATE_EXPECT( context, server2016 != std::wstring::npos) ;
	// Server欄を取得できた場合にだけ未対応OS表記へ置換して拒否を検証する。
	if( server2016 != std::wstring::npos) {
		missingOs.replace( server2016, SERVER2016.size(),
						  L"Microsoft Windows Server Legacy (64-bit)") ;
	}

	DRIVERCRATE_EXPECT( context, !parseRicohUniversalPrintPage( missingOs, metadata)) ;

	std::wstring				v4Only( page) ;	// 従来型PCL6 titleをV4へ置換したpage。
	constexpr std::wstring_view CLASSIC_TITLE =
		L"<strong>PCL6 Driver for Universal Print</strong>" ;	// 必須行title。
	constexpr std::wstring_view V4_TITLE =
		L"<strong>PCL6 Driver for Universal Print V4</strong>" ;	// 除外対象title。
	std::size_t titlePosition{} ;									// 次に置換する必須title位置。
	// 六つの対象欄と32-bit欄の従来型titleを全てV4表記へ置換する。
	while( (titlePosition = v4Only.find( CLASSIC_TITLE, titlePosition)) != std::wstring::npos) {
		v4Only.replace( titlePosition, CLASSIC_TITLE.size(), V4_TITLE) ;
		titlePosition += V4_TITLE.size() ;
	}

	DRIVERCRATE_EXPECT( context, !parseRicohUniversalPrintPage( v4Only, metadata)) ;

	std::wstring	  duplicateTitle( page) ;								// 最初のOS欄でtitleを重複させるpage。
	const std::size_t firstTitle = duplicateTitle.find( CLASSIC_TITLE) ;	// 最初のtitle位置。
	DRIVERCRATE_EXPECT( context, firstTitle != std::wstring::npos) ;
	// 見出し位置を取得できた場合にだけ複製し、曖昧な製品欄の拒否を検証する。
	if( firstTitle != std::wstring::npos) {
		duplicateTitle.insert( firstTitle, CLASSIC_TITLE) ;
	}

	DRIVERCRATE_EXPECT( context, !parseRicohUniversalPrintPage( duplicateTitle, metadata)) ;

	OfficialReleaseRecord release ;	// 共通recordへの変換結果。
	DRIVERCRATE_EXPECT( context, parseOfficialReleaseRecord(
									OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6, page, release)) ;
	DRIVERCRATE_EXPECT( context, release.family == OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6) ;
	DRIVERCRATE_EXPECT( context, release.fileName == L"z07106L24.exe") ;
	DRIVERCRATE_EXPECT( context, release.packageVersion == L"4.45.0.0") ;
	DRIVERCRATE_EXPECT( context, release.displaySize == L"34,552 KB") ;
	DRIVERCRATE_EXPECT( context, release.publishedDate == L"06/23/2026") ;
	DRIVERCRATE_EXPECT( context, release.publishedSha256.empty()) ;
	DRIVERCRATE_EXPECT( context, release.license == OfficialReleaseLicense::UNRESOLVED) ;
	DRIVERCRATE_EXPECT( context, makeReleasePreparationTargets( release, SESSION, 7U, 1U).empty()) ;

	OfficialCatalogDevice device = ricohPrinterDevice( L"ricoh-printer") ;	// Printer正常入力。
	DRIVERCRATE_EXPECT(
		context, officialReleaseDeviceMatches( OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6, device)) ;
	device.driverClass	   = L"PrintQueue" ;
	device.deviceClassGuid = L"{1ed2bbf9-11f0-4084-b21f-ad83a8e6dcdc}" ;
	DRIVERCRATE_EXPECT(
		context, officialReleaseDeviceMatches( OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6, device)) ;
	device.manufacturer.clear() ;
	DRIVERCRATE_EXPECT(
		context, officialReleaseDeviceMatches( OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6, device)) ;
	device.model = L"Other Printer Fixture" ;
	DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches(
									OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6, device)) ;
	device			   = ricohPrinterDevice( L"ricoh-printer") ;
	device.driverClass = L"Image" ;
	DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches(
									OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6, device)) ;
	device				   = ricohPrinterDevice( L"ricoh-printer") ;
	device.deviceClassGuid = L"{4d36e972-e325-11ce-bfc1-08002be10318}" ;
	DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches(
									OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6, device)) ;

	DRIVERCRATE_EXPECT( context, officialReleaseOperatingSystemMatches(
									OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6, false, 26100U)) ;
	DRIVERCRATE_EXPECT( context, officialReleaseOperatingSystemMatches(
									OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6, true, 14393U)) ;
	DRIVERCRATE_EXPECT( context, officialReleaseOperatingSystemMatches(
									OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6, true, 17763U)) ;
	DRIVERCRATE_EXPECT( context, officialReleaseOperatingSystemMatches(
									OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6, true, 20348U)) ;
	DRIVERCRATE_EXPECT( context, officialReleaseOperatingSystemMatches(
									OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6, true, 26100U)) ;
	DRIVERCRATE_EXPECT( context, !officialReleaseOperatingSystemMatches(
									OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6, true, 0U)) ;

	const OfficialSourceDefinition *const definition =
		// 固定検索定義。
		officialSourceDefinition( OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6) ;
	DRIVERCRATE_EXPECT( context, definition != nullptr) ;
	// Ricohの固定定義を取得できた場合にだけ各識別fieldを検証する。
	if( definition != nullptr) {
		DRIVERCRATE_EXPECT( context, definition->providerId == RICOH_UNIVERSAL_PRINT_PROVIDER_ID) ;
		DRIVERCRATE_EXPECT( context,
						   definition->sourceId == RICOH_UNIVERSAL_PRINT_OFFICIAL_SOURCE_POLICY_ID) ;
		DRIVERCRATE_EXPECT( context, definition->familyId == L"ricoh-universal-pcl6") ;
		DRIVERCRATE_EXPECT( context, definition->productKey == L"pcl6-universal-print") ;
		DRIVERCRATE_EXPECT( context, definition->branch == L"windows-x64") ;
		DRIVERCRATE_EXPECT( context, definition->profileId.empty()) ;
		DRIVERCRATE_EXPECT( context, definition->displayOrigin == L"support.ricoh.com") ;
		DRIVERCRATE_EXPECT( context, definition->observationPolicyRevision == 1U) ;
	}

	const OfficialSourcePolicy *const policy =
		// Ricoh origin policy。
		officialSourcePolicyForProvider( RICOH_UNIVERSAL_PRINT_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, policy != nullptr) ;
	// Ricohのpolicyがある場合にだけ表示用pageとpayload未登録を検証する。
	if( policy != nullptr) {
		DRIVERCRATE_EXPECT(
			context, findOfficialSourceResource( *policy, OFFICIAL_LANDING_RESOURCE_ID) != nullptr) ;
		DRIVERCRATE_EXPECT(
			context, findOfficialSourceResource( *policy, OFFICIAL_PAYLOAD_RESOURCE_ID) == nullptr) ;
	}

	const std::array devices{ricohPrinterDevice( L"ricoh-printer")} ;	// 一台のRicoh inventory。
	std::size_t		 reads{} ;											// Fake reader呼出し回数。
	const OfficialReleaseMetadataReader reader =
		[&reads, &page]( const OfficialReleaseFamily family, const ScanSessionId,
						OfficialReleaseRecord &result, bool &rejected) {
			++reads ;
			rejected = !parseOfficialReleaseRecord( family, page, result) ;
			return NativeError{0} ;
		} ; // 合成page以外を読まない取得境界。
	std::size_t								  evaluations{} ;	// 候補へ反映した観測差分数。
	const OfficialReleaseObservationEvaluator evaluator =
		[&evaluations](
			const OfficialCatalogDevice &,
			const OfficialReleaseRecord &) -> std::optional<ReleaseObservationDifference> {
		++evaluations ;
		return ReleaseObservationDifference::FIRST_OBSERVATION ;
	} ; // 非機密な差分だけを返すfake。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {} ;	// 通知破棄先。
	const ScanResult			   result	= scanOfficialReleaseMetadata(
		OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6, SESSION, devices, false, reader, progress, 0U,
		evaluator) ;	// Windows client上の表示専用検索。
	DRIVERCRATE_EXPECT( context, reads == 1U) ;
	DRIVERCRATE_EXPECT( context, evaluations == 1U) ;
	DRIVERCRATE_EXPECT( context, result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.state == ProviderScanState::CANDIDATES_AVAILABLE) ;
	DRIVERCRATE_EXPECT( context, result.candidates.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( result.candidates.size() == 1U) {
		const UpdateCandidate &candidate = result.candidates[0] ;	// Ricoh表示専用候補。
		DRIVERCRATE_EXPECT( context, candidate.providerId == RICOH_UNIVERSAL_PRINT_PROVIDER_ID) ;
		DRIVERCRATE_EXPECT( context, candidate.sourceLocation == L"support.ricoh.com") ;
		DRIVERCRATE_EXPECT( context, candidate.driverDate == L"06/23/2026") ;
		DRIVERCRATE_EXPECT( context, !candidate.installable) ;
		DRIVERCRATE_EXPECT( context, !candidate.recommended) ;
		DRIVERCRATE_EXPECT( context, !candidate.allContentCached) ;
		DRIVERCRATE_EXPECT( context,
						   candidate.audit.installReadiness == CandidateInstallReadiness::BLOCKED) ;
		DRIVERCRATE_EXPECT( context, candidate.releaseObservationDifference ==
										ReleaseObservationDifference::FIRST_OBSERVATION) ;
	}

	OfficialCatalogDevice observedDevice =
		// Release観測用device。
		ricohPrinterDevice( L"ricoh-observation") ;
	// 端末内HMACの架空値。
	observedDevice.localBindingFingerprint = std::wstring( 64U, L'd') ;
	OfficialReleaseObservationEvaluation observation ;	// Ricoh初回観測結果。
	DRIVERCRATE_EXPECT( context, evaluateOfficialReleaseObservation(
									OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6, release,
									observedDevice, std::wstring( 64U, L'a'),
									std::wstring( 64U, L'b'), 100U, {}, observation)) ;
	DRIVERCRATE_EXPECT( context,
					   observation.difference == ReleaseObservationDifference::FIRST_OBSERVATION) ;
	DRIVERCRATE_EXPECT( context, observation.observation.binding.providerId ==
									RICOH_UNIVERSAL_PRINT_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, observation.observation.releaseKey == L"z07106L24.exe") ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既知Mustache templateの除外、Windows x64併記、公式CDN、版、日付、size、HIDClass、表示専用候補、release観測と拒否境界を合成page
 *        だけで確認する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testWacomWindowsDiscovery( TestContext &context)
{
	WacomDriverPageMetadata metadata ;	// 専用parserの正常・拒否結果。
	DRIVERCRATE_EXPECT( context, parseWacomWindowsDriverPage( WACOM_PAGE, metadata)) ;
	DRIVERCRATE_EXPECT( context, metadata.fileName == L"WacomTablet_6.4.14-1.exe") ;
	DRIVERCRATE_EXPECT( context, metadata.version == L"6.4.14-1") ;
	DRIVERCRATE_EXPECT( context, metadata.releaseDate == L"8/26/2026") ;
	DRIVERCRATE_EXPECT( context, metadata.displaySize == L"304 MB") ;
	DRIVERCRATE_EXPECT( context, metadata.downloadUrl == WACOM_DOWNLOAD_URL) ;

	std::wstring	  badHost( WACOM_PAGE) ;							// 公式CDNに似た別hostを持つpage。
	const std::size_t hostPosition = badHost.find( L"cdn.wacom.com") ;	// 置換対象host位置。
	DRIVERCRATE_EXPECT( context, hostPosition != std::wstring::npos) ;
	// Wacom CDNの位置を取得できた場合にだけ非公式hostへ置換する。
	if( hostPosition != std::wstring::npos) {
		badHost.replace( hostPosition, 13U, L"cdn.wacom.example") ;
	}

	DRIVERCRATE_EXPECT( context, !parseWacomWindowsDriverPage( badHost, metadata)) ;

	std::wstring				armOnly( WACOM_PAGE) ;	// x64を欠落させるOS属性のpage。
	constexpr std::wstring_view X64_DESCRIPTION =
		L"Windows 10 &amp; 11 (x64) &amp; Windows 11 (ARM64)" ;	// 必須OS属性値。
	constexpr std::wstring_view ARM_DESCRIPTION =
		L"Windows 11 (ARM64)" ;			// x64を含まない拒否対象属性値。
	std::size_t descriptionPosition{} ;	// 次に置換する必須OS属性位置。
	// Titleとdescriptionの両方からx64表示を除去する。
	while( (descriptionPosition = armOnly.find( X64_DESCRIPTION, descriptionPosition)) !=
		  std::wstring::npos) {
		armOnly.replace( descriptionPosition, X64_DESCRIPTION.size(), ARM_DESCRIPTION) ;
		descriptionPosition += ARM_DESCRIPTION.size() ;
	}

	DRIVERCRATE_EXPECT( context, !parseWacomWindowsDriverPage( armOnly, metadata)) ;

	std::wstring	  versionMismatch( WACOM_PAGE) ;	// 属性版だけがfile名と異なるpage。
	const std::size_t versionPosition =
		// 版属性位置。
		versionMismatch.find( L"data-version=\"Driver 6.4.14-1\"") ;
	DRIVERCRATE_EXPECT( context, versionPosition != std::wstring::npos) ;
	// 版属性を取得できた場合にだけ数値部分を変更し、掲載版不一致を検証する。
	if( versionPosition != std::wstring::npos) {
		const std::size_t versionValue =
			versionPosition + std::wstring_view( L"data-version=\"Driver ").size() ;	// 数値版位置。
		versionMismatch.replace( versionValue, 10U, L"6.4.13-3") ;
	}

	DRIVERCRATE_EXPECT( context, !parseWacomWindowsDriverPage( versionMismatch, metadata)) ;

	std::wstring	  duplicateWindows( WACOM_PAGE) ;	// OS属性を二重化した曖昧なpage。
	const std::size_t markerPosition =
		// 対象属性位置。
		duplicateWindows.find( L"data-driver-os=\"windows\"") ;
	DRIVERCRATE_EXPECT( context, markerPosition != std::wstring::npos) ;
	// OS markerの位置を取得できた場合にだけ重複属性を注入する。
	if( markerPosition != std::wstring::npos) {
		duplicateWindows.insert( markerPosition, L"data-driver-os=\"windows\" ") ;
	}

	DRIVERCRATE_EXPECT( context, !parseWacomWindowsDriverPage( duplicateWindows, metadata)) ;

	std::wstring multipleConcrete( WACOM_PAGE) ;	// 具体的な現行配布欄を二重化した曖昧なpage。
	constexpr std::wstring_view CONCRETE_PREFIX =
		L"<a href=\"#\" class=\"drivers__btn\" data-driver-os=\"windows\"" ;			// 具体欄prefix。
	const std::size_t concreteBegin = multipleConcrete.rfind( CONCRETE_PREFIX) ;		// 具体欄開始位置。
	const std::size_t concreteEnd	= multipleConcrete.find( L"</a>", concreteBegin) ;	// 終了位置。
	DRIVERCRATE_EXPECT( context, concreteBegin != std::wstring::npos) ;
	DRIVERCRATE_EXPECT( context, concreteEnd != std::wstring::npos) ;
	// 具体的tagの両端を確認してから複製し、実候補の重複を検証する。
	if( concreteBegin != std::wstring::npos && concreteEnd != std::wstring::npos) {
		// 二つ目として挿入する具体的な開始tagと終了tag。
		const std::wstring concreteTag =
			multipleConcrete.substr( concreteBegin, concreteEnd - concreteBegin + 4U) ;
		multipleConcrete.insert( concreteEnd + 4U, concreteTag) ;
	}

	DRIVERCRATE_EXPECT( context, !parseWacomWindowsDriverPage( multipleConcrete, metadata)) ;

	std::wstring	  badDate( WACOM_PAGE) ;						// 範囲外monthを持つ公開日属性。
	const std::size_t datePosition = badDate.find( L"8/26/2026") ;	// 公開日値位置。
	DRIVERCRATE_EXPECT( context, datePosition != std::wstring::npos) ;
	// 日付位置を取得できた場合にだけ不正な月を注入する。
	if( datePosition != std::wstring::npos) {
		badDate.replace( datePosition, 9U, L"13/26/2026") ;
	}

	DRIVERCRATE_EXPECT( context, !parseWacomWindowsDriverPage( badDate, metadata)) ;

	OfficialReleaseRecord release ;	// 共通recordへの変換結果。
	DRIVERCRATE_EXPECT( context,
					   parseOfficialReleaseRecord( OfficialReleaseFamily::WACOM_WINDOWS_TABLET,
												  WACOM_PAGE, release)) ;
	DRIVERCRATE_EXPECT( context, release.family == OfficialReleaseFamily::WACOM_WINDOWS_TABLET) ;
	DRIVERCRATE_EXPECT( context, release.fileName == L"WacomTablet_6.4.14-1.exe") ;
	DRIVERCRATE_EXPECT( context, release.packageVersion == L"6.4.14-1") ;
	DRIVERCRATE_EXPECT( context, release.displaySize == L"304 MB") ;
	DRIVERCRATE_EXPECT( context, release.publishedDate == L"8/26/2026") ;
	DRIVERCRATE_EXPECT( context, release.publishedSha256.empty()) ;
	DRIVERCRATE_EXPECT( context, release.license == OfficialReleaseLicense::UNRESOLVED) ;
	DRIVERCRATE_EXPECT( context, makeReleasePreparationTargets( release, SESSION, 8U, 1U).empty()) ;

	OfficialCatalogDevice device = wacomHidDevice( L"wacom-hid") ;	// HIDClass正常入力。
	DRIVERCRATE_EXPECT(
		context, officialReleaseDeviceMatches( OfficialReleaseFamily::WACOM_WINDOWS_TABLET, device)) ;
	device.driverClass = L"Mouse" ;
	DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches(
									OfficialReleaseFamily::WACOM_WINDOWS_TABLET, device)) ;
	device				= wacomHidDevice( L"wacom-hid") ;
	device.manufacturer = L"OEM Fixture" ;
	DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches(
									OfficialReleaseFamily::WACOM_WINDOWS_TABLET, device)) ;
	device		 = wacomHidDevice( L"wacom-hid") ;
	device.model = L"OEM Pen Fixture" ;
	DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches(
									OfficialReleaseFamily::WACOM_WINDOWS_TABLET, device)) ;
	device				   = wacomHidDevice( L"wacom-hid") ;
	device.deviceClassGuid = L"{4d36e96f-e325-11ce-bfc1-08002be10318}" ;
	DRIVERCRATE_EXPECT( context, !officialReleaseDeviceMatches(
									OfficialReleaseFamily::WACOM_WINDOWS_TABLET, device)) ;

	DRIVERCRATE_EXPECT( context, officialReleaseOperatingSystemMatches(
									OfficialReleaseFamily::WACOM_WINDOWS_TABLET, false, 19045U)) ;
	DRIVERCRATE_EXPECT( context, officialReleaseOperatingSystemMatches(
									OfficialReleaseFamily::WACOM_WINDOWS_TABLET, false, 26100U)) ;
	DRIVERCRATE_EXPECT( context, !officialReleaseOperatingSystemMatches(
									OfficialReleaseFamily::WACOM_WINDOWS_TABLET, false, 0U)) ;
	DRIVERCRATE_EXPECT( context, !officialReleaseOperatingSystemMatches(
									OfficialReleaseFamily::WACOM_WINDOWS_TABLET, true, 26100U)) ;

	const OfficialSourceDefinition *const definition =
		// 固定検索定義。
		officialSourceDefinition( OfficialReleaseFamily::WACOM_WINDOWS_TABLET) ;
	DRIVERCRATE_EXPECT( context, definition != nullptr) ;
	// Wacomの固定定義を取得できた場合にだけ各識別fieldを検証する。
	if( definition != nullptr) {
		DRIVERCRATE_EXPECT( context, definition->providerId == WACOM_WINDOWS_PROVIDER_ID) ;
		DRIVERCRATE_EXPECT( context,
						   definition->sourceId == WACOM_WINDOWS_OFFICIAL_SOURCE_POLICY_ID) ;
		DRIVERCRATE_EXPECT( context, definition->familyId == L"wacom-windows-tablet") ;
		DRIVERCRATE_EXPECT( context, definition->productKey == L"latest-windows-tablet-driver") ;
		DRIVERCRATE_EXPECT( context, definition->branch == L"windows-10-11-x64") ;
		DRIVERCRATE_EXPECT( context, definition->profileId.empty()) ;
		DRIVERCRATE_EXPECT( context, definition->displayOrigin == L"www.wacom.com") ;
		DRIVERCRATE_EXPECT( context, definition->observationPolicyRevision == 1U) ;
	}

	const OfficialSourcePolicy *const policy =
		// Wacom origin policy。
		officialSourcePolicyForProvider( WACOM_WINDOWS_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, policy != nullptr) ;
	// Wacomのpolicyがある場合にだけ表示用pageとpayload未登録を検証する。
	if( policy != nullptr) {
		DRIVERCRATE_EXPECT(
			context, findOfficialSourceResource( *policy, OFFICIAL_LANDING_RESOURCE_ID) != nullptr) ;
		DRIVERCRATE_EXPECT(
			context, findOfficialSourceResource( *policy, OFFICIAL_PAYLOAD_RESOURCE_ID) == nullptr) ;
	}

	const std::array devices{wacomHidDevice( L"wacom-hid")} ;	// 一台のWacom inventory。
	std::size_t		 reads{} ;									// Fake reader呼出し回数。
	const OfficialReleaseMetadataReader reader =
		[&reads]( const OfficialReleaseFamily family, const ScanSessionId,
				 OfficialReleaseRecord &result, bool &rejected) {
			++reads ;
			rejected = !parseOfficialReleaseRecord( family, WACOM_PAGE, result) ;
			return NativeError{0} ;
		} ; // 合成page以外を読まない取得境界。
	std::size_t								  evaluations{} ;	// 候補へ反映した観測差分数。
	const OfficialReleaseObservationEvaluator evaluator =
		[&evaluations](
			const OfficialCatalogDevice &,
			const OfficialReleaseRecord &) -> std::optional<ReleaseObservationDifference> {
		++evaluations ;
		return ReleaseObservationDifference::FIRST_OBSERVATION ;
	} ; // 非機密な差分だけを返すfake。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {} ;	// 通知破棄先。
	const ScanResult			   result	= scanOfficialReleaseMetadata(
		OfficialReleaseFamily::WACOM_WINDOWS_TABLET, SESSION, devices, false, reader, progress,
		19045U, evaluator) ;	// Windows 10 x64上の表示専用検索。
	DRIVERCRATE_EXPECT( context, reads == 1U) ;
	DRIVERCRATE_EXPECT( context, evaluations == 1U) ;
	DRIVERCRATE_EXPECT( context, result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.state == ProviderScanState::CANDIDATES_AVAILABLE) ;
	DRIVERCRATE_EXPECT( context, result.candidates.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( result.candidates.size() == 1U) {
		const UpdateCandidate &candidate = result.candidates[0] ;	// Wacom表示専用候補。
		DRIVERCRATE_EXPECT( context, candidate.providerId == WACOM_WINDOWS_PROVIDER_ID) ;
		DRIVERCRATE_EXPECT( context, candidate.sourceLocation == L"www.wacom.com") ;
		DRIVERCRATE_EXPECT( context, candidate.driverDate == L"8/26/2026") ;
		DRIVERCRATE_EXPECT( context, !candidate.installable) ;
		DRIVERCRATE_EXPECT( context, !candidate.recommended) ;
		DRIVERCRATE_EXPECT( context, !candidate.allContentCached) ;
		DRIVERCRATE_EXPECT( context,
						   candidate.audit.installReadiness == CandidateInstallReadiness::BLOCKED) ;
		DRIVERCRATE_EXPECT( context, candidate.releaseObservationDifference ==
										ReleaseObservationDifference::FIRST_OBSERVATION) ;
	}

	OfficialCatalogDevice observedDevice =
		// Release観測用device。
		wacomHidDevice( L"wacom-observation") ;
	// 端末内HMAC架空値。
	observedDevice.localBindingFingerprint = std::wstring( 64U, L'e') ;
	OfficialReleaseObservationEvaluation observation ;	// Wacom初回観測結果。
	DRIVERCRATE_EXPECT( context, evaluateOfficialReleaseObservation(
									OfficialReleaseFamily::WACOM_WINDOWS_TABLET, release,
									observedDevice, std::wstring( 64U, L'a'),
									std::wstring( 64U, L'b'), 100U, {}, observation)) ;
	DRIVERCRATE_EXPECT( context,
					   observation.difference == ReleaseObservationDifference::FIRST_OBSERVATION) ;
	DRIVERCRATE_EXPECT( context,
					   observation.observation.binding.providerId == WACOM_WINDOWS_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, observation.observation.releaseKey == L"WacomTablet_6.4.14-1.exe") ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定製品、現行Windows欄、公式配布host、版、size、MEDIA class、表示専用候補とrelease観測の拒否境界を合成pageだけで確認する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testFocusriteScarlett2i2Discovery( TestContext &context)
{
	FocusriteDownloadPageMetadata metadata ;	// 専用parserの正常・拒否結果。
	DRIVERCRATE_EXPECT( context, parseFocusriteScarlett2i2SecondGenPage( FOCUSRITE_PAGE, metadata)) ;
	DRIVERCRATE_EXPECT( context, metadata.fileName == L"focusritedriver_4.150.0_432.exe") ;
	DRIVERCRATE_EXPECT( context, metadata.version == L"4.150.0") ;
	DRIVERCRATE_EXPECT( context, metadata.displaySize == L"53.64 MB") ;
	DRIVERCRATE_EXPECT( context, metadata.downloadUrl == FOCUSRITE_DOWNLOAD_URL) ;

	std::wstring				wrongProduct( FOCUSRITE_PAGE) ;						// Canonical製品識別を変更したpage。
	constexpr std::wstring_view PRODUCT_KEY		= L"scarlett-2i2-2nd-gen" ;			// 固定製品key。
	const std::size_t			productPosition = wrongProduct.find( PRODUCT_KEY) ;	// 置換対象位置。
	DRIVERCRATE_EXPECT( context, productPosition != std::wstring::npos) ;
	// 製品keyの位置を取得できた場合にだけ別製品へ置換して照合拒否を検証する。
	if( productPosition != std::wstring::npos) {
		wrongProduct.replace( productPosition, PRODUCT_KEY.size(), L"scarlett-4i4-2nd-gen") ;
	}

	DRIVERCRATE_EXPECT( context, !parseFocusriteScarlett2i2SecondGenPage( wrongProduct, metadata)) ;

	std::wstring				badHost( FOCUSRITE_PAGE) ;	// 公式配布hostに似た別hostを持つpage。
	constexpr std::wstring_view PAYLOAD_HOST =
		L"fael-downloads-prod.focusrite.com" ;						// 許可するpayload host。
	const std::size_t hostPosition = badHost.find( PAYLOAD_HOST) ;	// 置換対象host位置。
	DRIVERCRATE_EXPECT( context, hostPosition != std::wstring::npos) ;
	// 配布hostの位置を取得できた場合にだけ非公式hostへ置換する。
	if( hostPosition != std::wstring::npos) {
		badHost.replace( hostPosition, PAYLOAD_HOST.size(), L"focusrite.example") ;
	}

	DRIVERCRATE_EXPECT( context, !parseFocusriteScarlett2i2SecondGenPage( badHost, metadata)) ;

	std::wstring	  unsupportedOs( FOCUSRITE_PAGE) ;							// 必須Windows 10／11表示を欠くpage。
	const std::size_t osPosition = unsupportedOs.find( L"Windows 10 + 11") ;	// OS表示位置。
	DRIVERCRATE_EXPECT( context, osPosition != std::wstring::npos) ;
	// OS欄の位置を取得できた場合にだけ未対応OSへ置換する。
	if( osPosition != std::wstring::npos) {
		unsupportedOs.replace( osPosition, 15U, L"Windows 8.1") ;
	}

	DRIVERCRATE_EXPECT( context, !parseFocusriteScarlett2i2SecondGenPage( unsupportedOs, metadata)) ;

	std::wstring				versionMismatch( FOCUSRITE_PAGE) ;	// URL版だけが名称版と異なるpage。
	constexpr std::wstring_view CURRENT_FILE_NAME =
		L"focusritedriver_4.150.0_432.exe" ;	// 名称版と一致する現行file名。
	const std::size_t urlVersionPosition =
		// URL内のfile名位置。
		versionMismatch.find( CURRENT_FILE_NAME) ;
	DRIVERCRATE_EXPECT( context, urlVersionPosition != std::wstring::npos) ;
	// file名位置を取得できた場合にだけ別版へ変更し、掲載版との不一致を検証する。
	if( urlVersionPosition != std::wstring::npos) {
		versionMismatch.replace( urlVersionPosition, CURRENT_FILE_NAME.size(),
								L"focusritedriver_4.149.0_432.exe") ;
	}

	DRIVERCRATE_EXPECT( context, !parseFocusriteScarlett2i2SecondGenPage( versionMismatch, metadata)) ;

	std::wstring	  duplicateCurrent( FOCUSRITE_PAGE) ;	// 現行driver名を二重化した曖昧なpage。
	const std::size_t currentPosition =
		// 現行名称位置。
		duplicateCurrent.find( L"Focusrite Driver 4.150.0 - Windows") ;
	DRIVERCRATE_EXPECT( context, currentPosition != std::wstring::npos) ;
	// 現行欄の位置を取得できた場合にだけ重複表示を注入する。
	if( currentPosition != std::wstring::npos) {
		duplicateCurrent.insert( currentPosition, L"Focusrite Driver 4.150.0 - Windows ") ;
	}

	DRIVERCRATE_EXPECT( context,
					   !parseFocusriteScarlett2i2SecondGenPage( duplicateCurrent, metadata)) ;

	std::wstring	  badSize( FOCUSRITE_PAGE) ;					// 小数桁が不正な概算sizeを持つpage。
	const std::size_t sizePosition = badSize.find( L"53.64 MB") ;	// 概算size位置。
	DRIVERCRATE_EXPECT( context, sizePosition != std::wstring::npos) ;
	// 容量位置を取得できた場合にだけ単位表記を変更してschema拒否を検証する。
	if( sizePosition != std::wstring::npos) {
		badSize.replace( sizePosition, 8U, L"53.6 MB") ;
	}

	DRIVERCRATE_EXPECT( context, !parseFocusriteScarlett2i2SecondGenPage( badSize, metadata)) ;

	std::wstring	  badBuild( FOCUSRITE_PAGE) ;					// 数字以外のpayload buildを持つpage。
	const std::size_t buildPosition = badBuild.find( L"_432.exe") ;	// Build suffix位置。
	DRIVERCRATE_EXPECT( context, buildPosition != std::wstring::npos) ;
	// build番号の位置を取得できた場合にだけ非数値へ置換する。
	if( buildPosition != std::wstring::npos) {
		badBuild.replace( buildPosition, 8U, L"_abc.exe") ;
	}

	DRIVERCRATE_EXPECT( context, !parseFocusriteScarlett2i2SecondGenPage( badBuild, metadata)) ;

	OfficialReleaseRecord release ;	// 共通recordへの変換結果。
	DRIVERCRATE_EXPECT(
		context, parseOfficialReleaseRecord( OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN,
											FOCUSRITE_PAGE, release)) ;
	DRIVERCRATE_EXPECT( context,
					   release.family == OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN) ;
	DRIVERCRATE_EXPECT( context, release.fileName == L"focusritedriver_4.150.0_432.exe") ;
	DRIVERCRATE_EXPECT( context, release.packageVersion == L"4.150.0") ;
	DRIVERCRATE_EXPECT( context, release.displaySize == L"53.64 MB") ;
	DRIVERCRATE_EXPECT( context, release.publishedDate.empty()) ;
	DRIVERCRATE_EXPECT( context, release.publishedSha256.empty()) ;
	DRIVERCRATE_EXPECT( context, release.license == OfficialReleaseLicense::UNRESOLVED) ;
	DRIVERCRATE_EXPECT( context, makeReleasePreparationTargets( release, SESSION, 9U, 1U).empty()) ;

	OfficialCatalogDevice device =
		// MEDIA class正常入力。
		focusriteScarlett2i2Device( L"focusrite-media") ;
	DRIVERCRATE_EXPECT( context,
					   officialReleaseDeviceMatches(
						   OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN, device)) ;
	device.driverClass = L"AudioEndpoint" ;
	DRIVERCRATE_EXPECT( context,
					   !officialReleaseDeviceMatches(
						   OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN, device)) ;
	device				= focusriteScarlett2i2Device( L"focusrite-media") ;
	device.manufacturer = L"OEM Fixture" ;
	DRIVERCRATE_EXPECT( context,
					   !officialReleaseDeviceMatches(
						   OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN, device)) ;
	device		 = focusriteScarlett2i2Device( L"focusrite-media") ;
	device.model = L"Focusrite Scarlett 4i4 Fixture" ;
	DRIVERCRATE_EXPECT( context,
					   !officialReleaseDeviceMatches(
						   OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN, device)) ;
	device				   = focusriteScarlett2i2Device( L"focusrite-media") ;
	device.deviceClassGuid = L"{4d36e96f-e325-11ce-bfc1-08002be10318}" ;
	DRIVERCRATE_EXPECT( context,
					   !officialReleaseDeviceMatches(
						   OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN, device)) ;

	DRIVERCRATE_EXPECT( context,
					   officialReleaseOperatingSystemMatches(
						   OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN, false, 19045U)) ;
	DRIVERCRATE_EXPECT( context,
					   officialReleaseOperatingSystemMatches(
						   OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN, false, 26100U)) ;
	DRIVERCRATE_EXPECT( context,
					   !officialReleaseOperatingSystemMatches(
						   OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN, false, 0U)) ;
	DRIVERCRATE_EXPECT( context,
					   !officialReleaseOperatingSystemMatches(
						   OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN, true, 26100U)) ;

	const OfficialSourceDefinition *const definition = officialSourceDefinition(
		OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN) ;	// 固定検索定義。
	DRIVERCRATE_EXPECT( context, definition != nullptr) ;
	// Focusriteの固定定義を取得できた場合にだけ各識別fieldを検証する。
	if( definition != nullptr) {
		DRIVERCRATE_EXPECT( context, definition->providerId == FOCUSRITE_SCARLETT2I2_PROVIDER_ID) ;
		DRIVERCRATE_EXPECT( context,
						   definition->sourceId == FOCUSRITE_SCARLETT2I2_OFFICIAL_SOURCE_POLICY_ID) ;
		DRIVERCRATE_EXPECT( context, definition->familyId == L"focusrite-scarlett-2i2-second-gen") ;
		DRIVERCRATE_EXPECT( context, definition->productKey == L"scarlett-2i2-2nd-gen") ;
		DRIVERCRATE_EXPECT( context, definition->branch == L"windows-10-11-x64") ;
		DRIVERCRATE_EXPECT( context, definition->profileId.empty()) ;
		DRIVERCRATE_EXPECT( context, definition->displayOrigin == L"downloads.focusrite.com") ;
		DRIVERCRATE_EXPECT( context, definition->observationPolicyRevision == 1U) ;
	}

	const OfficialSourcePolicy *const policy = officialSourcePolicyForProvider(
		FOCUSRITE_SCARLETT2I2_PROVIDER_ID) ;	// Focusrite origin policy。
	DRIVERCRATE_EXPECT( context, policy != nullptr) ;
	// Focusriteのpolicyがある場合にだけ表示用pageとpayload未登録を検証する。
	if( policy != nullptr) {
		DRIVERCRATE_EXPECT(
			context, findOfficialSourceResource( *policy, OFFICIAL_LANDING_RESOURCE_ID) != nullptr) ;
		DRIVERCRATE_EXPECT(
			context, findOfficialSourceResource( *policy, OFFICIAL_PAYLOAD_RESOURCE_ID) == nullptr) ;
	}

	const std::array					devices{	// 一台のFocusrite inventory。
								focusriteScarlett2i2Device( L"focusrite-media")} ;
	std::size_t							reads{} ;	// Fake reader呼出し回数。
	const OfficialReleaseMetadataReader reader =
		[&reads]( const OfficialReleaseFamily family, const ScanSessionId,
				 OfficialReleaseRecord &result, bool &rejected) {
			++reads ;
			rejected = !parseOfficialReleaseRecord( family, FOCUSRITE_PAGE, result) ;
			return NativeError{0} ;
		} ; // 合成page以外を読まない取得境界。
	std::size_t								  evaluations{} ;	// 候補へ反映した観測差分数。
	const OfficialReleaseObservationEvaluator evaluator =
		[&evaluations](
			const OfficialCatalogDevice &,
			const OfficialReleaseRecord &) -> std::optional<ReleaseObservationDifference> {
		++evaluations ;
		return ReleaseObservationDifference::FIRST_OBSERVATION ;
	} ; // 非機密な差分だけを返すfake。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {} ;	// 通知破棄先。
	const ScanResult			   result	= scanOfficialReleaseMetadata(
		OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN, SESSION, devices, false, reader,
		progress, 19045U, evaluator) ;	// Windows 10 x64上の表示専用検索。
	DRIVERCRATE_EXPECT( context, reads == 1U) ;
	DRIVERCRATE_EXPECT( context, evaluations == 1U) ;
	DRIVERCRATE_EXPECT( context, result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.state == ProviderScanState::CANDIDATES_AVAILABLE) ;
	DRIVERCRATE_EXPECT( context, result.candidates.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( result.candidates.size() == 1U) {
		const UpdateCandidate &candidate = result.candidates[0] ;	// Focusrite表示専用候補。
		DRIVERCRATE_EXPECT( context, candidate.providerId == FOCUSRITE_SCARLETT2I2_PROVIDER_ID) ;
		DRIVERCRATE_EXPECT( context, candidate.sourceLocation == L"downloads.focusrite.com") ;
		DRIVERCRATE_EXPECT( context, candidate.driverDate.empty()) ;
		DRIVERCRATE_EXPECT( context, candidate.displayDownloadSize == L"53.64 MB") ;
		DRIVERCRATE_EXPECT( context, candidate.maximumDownloadBytes == 0U) ;
		DRIVERCRATE_EXPECT( context, candidate.title.find( L"4.150.0") != std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, !candidate.installable) ;
		DRIVERCRATE_EXPECT( context, !candidate.recommended) ;
		DRIVERCRATE_EXPECT( context, !candidate.allContentCached) ;
		DRIVERCRATE_EXPECT( context,
						   candidate.audit.installReadiness == CandidateInstallReadiness::BLOCKED) ;
		DRIVERCRATE_EXPECT( context, candidate.releaseObservationDifference ==
										ReleaseObservationDifference::FIRST_OBSERVATION) ;
	}

	OfficialCatalogDevice observedDevice =
		// Release観測用device。
		focusriteScarlett2i2Device( L"focusrite-observation") ;
	// 端末内HMAC架空値。
	observedDevice.localBindingFingerprint = std::wstring( 64U, L'e') ;
	OfficialReleaseObservationEvaluation observation ;	// Focusrite初回観測結果。
	DRIVERCRATE_EXPECT( context, evaluateOfficialReleaseObservation(
									OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN,
									release, observedDevice, std::wstring( 64U, L'a'),
									std::wstring( 64U, L'b'), 100U, {}, observation)) ;
	DRIVERCRATE_EXPECT( context,
					   observation.difference == ReleaseObservationDifference::FIRST_OBSERVATION) ;
	DRIVERCRATE_EXPECT( context, observation.observation.binding.providerId ==
									FOCUSRITE_SCARLETT2I2_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context,
					   observation.observation.releaseKey == L"focusritedriver_4.150.0_432.exe") ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常Providerとlive検証用非cache Providerを構築し、通信前の同じ拒否境界を維持することを確認する。公式HTTPまたはcache I/Oは実行しない。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testFocusriteProviderCacheConstruction( TestContext &context)
{
	OfficialReleaseDiscoveryProvider cachedProvider(
		OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN) ;	// 通常scanのcache有効Provider。
	OfficialReleaseDiscoveryProvider uncachedProvider(
		OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN, OfficialInfRankAuditor{},
		OfficialInfInstallBinder{}, OfficialInfInstallBindingReleaser{},
		OfficialBoundInfInstaller{}, false) ;		// 明示live検証だけが使うcache無効Provider。
	const std::array			   matchingDevices{	// 通信前拒否用の合成device。
									   focusriteScarlett2i2Device( L"focusrite-cache-mode")} ;
	const ProviderProgressCallback ignoredProgress = []( const ProviderProgress &) {
	} ; // 不正sessionでは呼ばれない通知先。
	const ScanResult cachedRejection = cachedProvider.scan(
		0U, matchingDevices, {}, ignoredProgress) ;	// Cache modeに関係なく拒否する不正session。
	const ScanResult uncachedRejection = uncachedProvider.scan(
		0U, matchingDevices, {}, ignoredProgress) ;	// 非cacheでも同じ境界を通す不正session。
	DRIVERCRATE_EXPECT( context, !cachedRejection.succeeded) ;
	DRIVERCRATE_EXPECT( context, cachedRejection.error == static_cast<NativeError>( E_INVALIDARG)) ;
	DRIVERCRATE_EXPECT( context, !uncachedRejection.succeeded) ;
	DRIVERCRATE_EXPECT( context, uncachedRejection.error == static_cast<NativeError>( E_INVALIDARG)) ;

	// Focusrite対象製品とは一致しない架空audio deviceの集合。
	const std::array nonmatchingDevices{
		OfficialCatalogDevice{.deviceIdentity  = L"focusrite-nonmatching",
							  .model		   = L"Unrelated Audio Fixture",
							  .manufacturer	   = L"Fixture Manufacturer",
							  .driverClass	   = L"MEDIA",
							  .deviceClassGuid = L"{4d36e96c-e325-11ce-bfc1-08002be10318}"}} ;
	// 対象外入力が通信せずNotApplicableへ到達する確定進捗。
	std::vector<ProviderProgress>  progressEvents ;
	const ProviderProgressCallback progress = [&progressEvents]( const ProviderProgress &event) {
		progressEvents.push_back( event) ;
	} ; // 対象外終了の通知だけを保持する。
	// 対象外deviceを渡した未cache Providerのscan結果。
	const ScanResult nonmatching = uncachedProvider.scan( 1U, nonmatchingDevices, {}, progress) ;
	DRIVERCRATE_EXPECT( context, nonmatching.succeeded) ;
	DRIVERCRATE_EXPECT( context, nonmatching.error == 0) ;
	DRIVERCRATE_EXPECT( context, nonmatching.state == ProviderScanState::NOT_APPLICABLE) ;
	DRIVERCRATE_EXPECT( context, nonmatching.candidates.empty()) ;
	DRIVERCRATE_EXPECT( context, progressEvents.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( progressEvents.size() == 1U) {
		DRIVERCRATE_EXPECT( context, progressEvents[0].percentComplete == 100U) ;
		DRIVERCRATE_EXPECT( context, progressEvents[0].completedItems == 0U) ;
		DRIVERCRATE_EXPECT( context, progressEvents[0].totalItems == 0U) ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 同型deviceを一配布物へまとめ、EULA未接続と古いsessionからの取得不可を確認する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testReleasePreparationTargets( TestContext &context)
{
	OfficialReleaseRecord release ;	// 合成pageから解析したworker用情報。
	DRIVERCRATE_EXPECT( context, parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_WIFI,
														   INTEL_PAGE, release)) ;
	// 同じ配布物に関係する二台分をまとめた未承認対象。
	const auto targets = makeReleasePreparationTargets( release, SESSION, 3U, 2U) ;
	// 二台へ関係するmetadataでも承認対象は一配布物とする。
	DRIVERCRATE_EXPECT( context, targets.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( targets.size() == 1U) {
		DRIVERCRATE_EXPECT( context, targets[0].deviceCount == 2U) ;
		DRIVERCRATE_EXPECT( context, targets[0].providerId == INTEL_WIFI_OFFICIAL_PROVIDER_ID) ;
		DRIVERCRATE_EXPECT( context, targets[0].terms == OfficialPreparationTerms::UNRESOLVED) ;
		DRIVERCRATE_EXPECT( context, targets[0].eulaRevision.empty()) ;
		DRIVERCRATE_EXPECT( context, targets[0].maximumBytes == 128ULL * 1024ULL * 1024ULL) ;
		OfficialPreparationSession session ;	// 未解決EULAを通さない承認状態。
		// 未解決EULAの拒否を確認する、固定上限付きの計画。
		OfficialPreparationPlan	   plan{SESSION, 3U, DEFAULT_OFFICIAL_PREPARATION_LIMITS, targets} ;
		DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
		OfficialPreparationApproval approval{
			4U, SESSION, 3U, plan.limits, {{targets[0], true, true, false}}} ;	// 不正な合成同意。
		DRIVERCRATE_EXPECT( context,
						   session.approve( approval) == OfficialPreparationError::INVALID_APPROVAL) ;
		DRIVERCRATE_EXPECT( context, !session.claimNext()) ;
	}

	DRIVERCRATE_EXPECT( context, makeReleasePreparationTargets( release, 0U, 3U, 2U).empty()) ;
	DRIVERCRATE_EXPECT( context, makeReleasePreparationTargets( release, SESSION, 0U, 2U).empty()) ;
	DRIVERCRATE_EXPECT( context, makeReleasePreparationTargets( release, SESSION, 3U, 0U).empty()) ;
	DRIVERCRATE_EXPECT( context, makeReleasePreparationTargets( release, SESSION, 3U, 4097U).empty()) ;
	release.family = OfficialReleaseFamily::PROLIFIC_DCHU ;
	DRIVERCRATE_EXPECT( context, makeReleasePreparationTargets( release, SESSION, 3U, 2U).empty()) ;
	OfficialReleaseDiscoveryProvider provider( OfficialReleaseFamily::INTEL_WIFI) ;	// HTTP未実行。
	DRIVERCRATE_EXPECT( context, provider.preparationTargets( SESSION, 3U).empty()) ;
	provider.invalidatePreparation() ;
	DRIVERCRATE_EXPECT( context, provider.preparationTargets( SESSION, 4U).empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Live metadata、数値配布ID、local binding、前回観測を結合し、初回、一致、release／hash変更と曖昧な前回recordを決定的に確認する。
 *
 * @param[in,out] context Assertionの集計先。
 */
//------------------------------------------------------------------------------
void testReleaseObservationEvaluation( TestContext &context)
{
	OfficialReleaseRecord release ;	// Intel合成pageから解析する強いrelease identity。
	DRIVERCRATE_EXPECT( context, parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_WIFI,
														   INTEL_PAGE, release)) ;
	OfficialCatalogDevice device = intelDevice( L"observation-device") ;	// 架空の現在device。
	// 端末内HMACの合成値。
	device.localBindingFingerprint = std::wstring( 64U, L'c') ;
	const std::wstring operatingSystem( 64U, L'a') ;	// 現在OS条件の合成fingerprint。
	const std::wstring configuration( 64U, L'b') ;		// 現在device集合の合成fingerprint。
	OfficialReleaseObservationEvaluation first ;		// 初回観測の生成結果。
	DRIVERCRATE_EXPECT( context, evaluateOfficialReleaseObservation(
									OfficialReleaseFamily::INTEL_WIFI, release, device,
									operatingSystem, configuration, 100U, {}, first)) ;
	DRIVERCRATE_EXPECT( context,
					   first.difference == ReleaseObservationDifference::FIRST_OBSERVATION) ;
	DRIVERCRATE_EXPECT( context,
					   first.observation.binding.sourceId == INTEL_WIFI_OFFICIAL_SOURCE_POLICY_ID) ;
	DRIVERCRATE_EXPECT( context, first.observation.binding.familyId == L"intel-wifi") ;
	DRIVERCRATE_EXPECT( context, first.observation.binding.productKey == L"18231") ;
	DRIVERCRATE_EXPECT( context, first.observation.releaseKey == release.fileName) ;

	OfficialReleaseRecord asixRelease ;	// File名ではなく数値配布IDを持つASIX metadata。
	asixRelease.family		   = OfficialReleaseFamily::ASIX_AX88179A ;
	asixRelease.releaseKey	   = L"9001" ;
	asixRelease.packageVersion = L"4.22.1.0" ;
	asixRelease.displaySize	   = L"129.5 KB" ;
	asixRelease.downloadUrl	   = L"https://www.asix.com.tw/en/support/download/file/9001" ;
	asixRelease.license		   = OfficialReleaseLicense::UNRESOLVED ;
	asixRelease.parserRevision = 1U ;
	OfficialCatalogDevice asixObservationDevice ;	// ASIX観測用の最小非機密device。
	asixObservationDevice.deviceIdentity = L"asix-observation-device" ;
	asixObservationDevice.localBindingFingerprint =
		// ASIX deviceに対応する端末内HMAC合成値。
		std::wstring( 64U, L'd') ;
	OfficialReleaseObservationEvaluation asixFirst ;	// 数値keyによる初回観測結果。
	DRIVERCRATE_EXPECT( context,
					   evaluateOfficialReleaseObservation(
						   OfficialReleaseFamily::ASIX_AX88179A, asixRelease, asixObservationDevice,
						   operatingSystem, configuration, 100U, {}, asixFirst)) ;
	DRIVERCRATE_EXPECT( context,
					   asixFirst.difference == ReleaseObservationDifference::FIRST_OBSERVATION) ;
	DRIVERCRATE_EXPECT( context,
					   asixFirst.observation.binding.sourceId == ASIX_OFFICIAL_SOURCE_POLICY_ID) ;
	DRIVERCRATE_EXPECT( context, asixFirst.observation.binding.familyId == L"asix-ax88179a") ;
	DRIVERCRATE_EXPECT( context, asixFirst.observation.releaseKey == L"9001") ;

	const std::array					 previous{first.observation} ;	// 一件だけの有効な前回観測。
	OfficialReleaseObservationEvaluation unchanged ;					// 同じ公開hashを持つ今回観測。
	DRIVERCRATE_EXPECT( context, evaluateOfficialReleaseObservation(
									OfficialReleaseFamily::INTEL_WIFI, release, device,
									operatingSystem, configuration, 101U, previous, unchanged)) ;
	DRIVERCRATE_EXPECT( context, unchanged.difference ==
									ReleaseObservationDifference::STRONG_IDENTITY_UNCHANGED) ;

	OfficialReleaseRecord changedRelease = release ;	// File名と表示版を変えた新版metadata。
	changedRelease.fileName				 = L"WiFi-25.10.0-Driver64-Win10-Win11.zip" ;
	changedRelease.packageVersion		 = L"25.10.0" ;
	OfficialReleaseObservationEvaluation releaseDifference ;	// 新版の比較結果。
	DRIVERCRATE_EXPECT( context,
					   evaluateOfficialReleaseObservation(
						   OfficialReleaseFamily::INTEL_WIFI, changedRelease, device,
						   operatingSystem, configuration, 102U, previous, releaseDifference)) ;
	DRIVERCRATE_EXPECT( context, releaseDifference.difference ==
									ReleaseObservationDifference::RELEASE_CHANGED) ;

	OfficialReleaseRecord changedHash = release ;	// 同じ版で公開hashだけが変わったmetadata。
	changedHash.publishedSha256		  = std::wstring( 64U, L'd') ;
	OfficialReleaseObservationEvaluation hashDifference ;	// 内容identity変更の比較結果。
	DRIVERCRATE_EXPECT(
		context, evaluateOfficialReleaseObservation( OfficialReleaseFamily::INTEL_WIFI, changedHash,
													device, operatingSystem, configuration, 103U,
													previous, hashDifference)) ;
	DRIVERCRATE_EXPECT( context, hashDifference.difference ==
									ReleaseObservationDifference::CONTENT_IDENTITY_CHANGED) ;

	const std::array					 duplicatePrevious{first.observation,
									   first.observation} ;	// 曖昧な同device前回観測。
	OfficialReleaseObservationEvaluation rejected ;			// 失敗時に初期値を維持する出力。
	DRIVERCRATE_EXPECT(
		context, !evaluateOfficialReleaseObservation( OfficialReleaseFamily::INTEL_WIFI, release,
													 device, operatingSystem, configuration, 104U,
													 duplicatePrevious, rejected)) ;
	DRIVERCRATE_EXPECT( context, rejected.difference == ReleaseObservationDifference::INVALID) ;

	std::size_t								  evaluations{} ;	// 表示候補へ反映した観測差分数。
	const OfficialReleaseObservationEvaluator evaluator =
		[&evaluations](
			const OfficialCatalogDevice &,
			const OfficialReleaseRecord &) -> std::optional<ReleaseObservationDifference> {
		++evaluations ;
		return ReleaseObservationDifference::STRONG_IDENTITY_UNCHANGED ;
	} ; // HashやbindingをUIへ渡さない差分だけのfake。
	const OfficialReleaseMetadataReader reader =
		[]( const OfficialReleaseFamily family, const ScanSessionId, OfficialReleaseRecord &result,
		   bool &rejectedMetadata) {
			rejectedMetadata = !parseOfficialReleaseRecord( family, INTEL_PAGE, result) ;
			return NativeError{0} ;
		} ; // 合成pageだけを読むnetwork不要境界。
	const std::array			   devices{intelDevice( L"display-observation")} ;	// 一台の表示対象。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {} ;	// 通知破棄先。
	const ScanResult			   scanned	= scanOfficialReleaseMetadata(
		   OfficialReleaseFamily::INTEL_WIFI, SESSION, devices, false, reader, progress, 0U,
		   evaluator) ;	// 差分callback付きの表示検索。
	DRIVERCRATE_EXPECT( context, scanned.succeeded && evaluations == 1U) ;
	DRIVERCRATE_EXPECT( context, scanned.candidates.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( scanned.candidates.size() == 1U) {
		DRIVERCRATE_EXPECT( context, scanned.candidates[0].releaseObservationDifference.has_value()) ;
		DRIVERCRATE_EXPECT( context, *scanned.candidates[0].releaseObservationDifference ==
										ReleaseObservationDifference::STRONG_IDENTITY_UNCHANGED) ;
		DRIVERCRATE_EXPECT( context, !scanned.candidates[0].allContentCached) ;
		DRIVERCRATE_EXPECT( context, !scanned.candidates[0].installable) ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @copydoc drivercrate::test::runOfficialReleaseMetadataTests
 */
//------------------------------------------------------------------------------
void runOfficialReleaseMetadataTests( TestContext &context)
{
	testReleaseRecords( context) ;
	testLocalProbe( context) ;
	testDiscoveryResults( context) ;
	testRejectionsWithoutNetwork( context) ;
	testSourceAndInstallBoundaries( context) ;
	testIntelEthernetServerDiscovery( context) ;
	testRicohUniversalPrintDiscovery( context) ;
	testWacomWindowsDiscovery( context) ;
	testFocusriteScarlett2i2Discovery( context) ;
	testFocusriteProviderCacheConstruction( context) ;
	testReleasePreparationTargets( context) ;
	testReleaseObservationEvaluation( context) ;
}
} // namespace drivercrate::test
