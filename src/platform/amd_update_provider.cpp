//------------------------------------------------------------------------------
/**
 * @file amd_update_provider.cpp
 * @brief AMD公式Web表示専用Provider実装。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 固定AMD公式pageだけを取得し、local Radeon表示名へ完全一致させます。Hardware IDを送信せず、AMD EXEをdownloadまたは実行しません。
 */
//------------------------------------------------------------------------------

#include "platform/amd_update_provider.h"

#include "core/candidate_audit.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/amd_catalog_parser.h"
#include "platform/windows_product_type.h"

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view DRIVER_INDEX_URL =
	L"https://www.amd.com/en/support/download/drivers.html" ;				// AMD固定探索起点。
constexpr std::uint64_t MAXIMUM_INDEX_BYTES = 2ULL * 1024ULL * 1024ULL ;	// 起点HTML上限。
constexpr std::uint64_t MAXIMUM_PRODUCT_PAGE_BYTES =
	4ULL * 1024ULL * 1024ULL ;							// 一製品pageのHTML上限。
constexpr std::size_t		MAXIMUM_AMD_DEVICES = 16U ;	// 一scanで外部pageへ照合するGPU上限。
constexpr std::wstring_view DISPLAY_CLASS_GUID_KEY =
	L"4D36E968E32511CEBFC108002BE10318" ;	// Display setup class GUID比較key。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをNativeErrorへ変換する。
 *
 * 元の診断値をProvider共通型へ保持する。
 *
 * @param[in] error Win32 APIが返したerror code。
 * @return HRESULT_FROM_WIN32で変換したbit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 表示名をASCII英数字の比較keyへ変換する。
 *
 * AMD対象deviceとDisplay classの事前絞込みだけに使用する。
 *
 * @param[in] value Local deviceのmanufacturer、modelまたはGUID。
 * @return ASCII英数字を大文字で連結した端末内比較key。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring displayMatchKey( const std::wstring_view value)
{
	std::wstring key ;	// 表示上の空白と記号差を除いた比較key。
	key.reserve( value.size()) ;
	// ASCII英数字を順序どおり保持して大小文字差だけを除く。
	for( const wchar_t character : value) {
		// 比較用keyのASCII小文字を大文字へ揃える。
		if( character >= L'a' && character <= L'z') {
			key.push_back( static_cast<wchar_t>( character - L'a' + L'A')) ;
		}
		// 既に大文字のASCII英字と数字は比較keyへそのまま保持する。
		else if( (character >= L'A' && character <= L'Z') ||
				(character >= L'0' && character <= L'9')) {
			key.push_back( character) ;
		}
	}

	return key ;
}

//------------------------------------------------------------------------------
/**
 * @brief AMD Radeon Display deviceか判定する。
 *
 * Chipset、NPU、RAID等をRadeon packageへ混在させない。
 *
 * @param[in] device 非機密local device snapshot。
 * @return Display classかつAMD名を確認できる場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAmdDisplayDevice( const OfficialCatalogDevice &device)
{
	const std::wstring classKey = displayMatchKey( device.deviceClassGuid) ;	// Setup class比較key。
	const std::wstring manufacturerKey =
		// Manufacturer比較key。
		displayMatchKey( device.manufacturer) ;
	const std::wstring modelKey = displayMatchKey( device.model) ;	// Model比較key。
	const bool amdName = manufacturerKey.find( L"ADVANCEDMICRODEVICES") != std::wstring::npos ||
						 manufacturerKey.find( L"AMD") != std::wstring::npos ||
						 modelKey.find( L"AMDRAD") != std::wstring::npos ||
						 // AMD Display表示名条件。
						 modelKey.find( L"RADEON") != std::wstring::npos ;
	return classKey == DISPLAY_CLASS_GUID_KEY && amdName ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実行中Windows clientのAMD page区分名を取得する。
 *
 * RtlGetVersionで実buildを取得し、Serverは呼出し側で除外する。
 * @return Windows 10／11 x64区分名。対象外または判定不能時は空。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring amdWindowsSection()
{
	HMODULE ntdll = GetModuleHandleW( L"ntdll.dll") ;	// Process所有の非所有module handle。
	// OS照会に必要な既存moduleを取得できない場合は対応区分を推測しない。
	if( ntdll == nullptr) {
		return {} ;
	}

	using RtlGetVersionFunction = LONG( WINAPI *)( PRTL_OSVERSIONINFOW) ;	// NTDLL署名。
	// GetProcAddressのFARPROCを文書化済みNTDLL signatureへ境界変換する。
	const auto rtlGetVersion = reinterpret_cast<RtlGetVersionFunction>(
		// 実OS version取得関数。
		GetProcAddress( ntdll, "RtlGetVersion")) ;
	// version照会APIが解決できない場合は対応OS名を返さない。
	if( rtlGetVersion == nullptr) {
		return {} ;
	}

	RTL_OSVERSIONINFOW version{} ;	// RtlGetVersionが設定する実OS version。
	version.dwOSVersionInfoSize = sizeof( version) ;
	// 実OS照会の失敗と未対応major versionではAMDのOS区分を選ばない。
	if( rtlGetVersion( &version) != 0 || version.dwMajorVersion != 10U) {
		return {} ;
	}

	return version.dwBuildNumber >= 22'000U ? L"Windows 11 - 64-Bit Edition"
											: L"Windows 10 - 64-Bit Edition" ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/amd_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult AmdUpdateProvider::scan( const ScanSessionId							scanSessionId,
								   const std::span<const OfficialCatalogDevice> devices,
								   const LocalHardwareIdMatcher				   &hardwareIdMatcher,
								   const ProviderProgressCallback			   &progressCallback)
{
	static_cast<void>( hardwareIdMatcher) ;
	invalidateScanSession() ;
	ScanResult result ;	// AMD Provider単独のscan結果。
	result.scanSessionId = scanSessionId ;
	result.outcome		 = OutcomeCode::FAILURE ;
	result.state		 = ProviderScanState::FAILURE ;
	// 未発行sessionまたは進捗通知先のないscan要求を拒否する。
	if( scanSessionId == 0U || !progressCallback) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	std::vector<const OfficialCatalogDevice *> amdDevices ;	// 照合対象AMD Display群。
	// 非DisplayやAMD名を確認できないdeviceをnetwork処理前に除外する。
	for( const OfficialCatalogDevice &device : devices) {
		// AMD Displayに該当するlocal deviceだけを検索対象へ含める。
		if( isAmdDisplayDevice( device)) {
			amdDevices.push_back( &device) ;
		}
	}

	result.coverage.eligibleDeviceCount = amdDevices.size() ;
	progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
					  .percentComplete = 0,
					  .completedItems  = 0,
					  .totalItems	   = amdDevices.size()}) ;
	// 対応deviceがない場合とServer環境では通信せず対象外を返す。
	if( amdDevices.empty() || isWindowsServer()) {
		result.succeeded = true ;
		result.outcome	 = OutcomeCode::SUCCESS ;
		result.state	 = ProviderScanState::NOT_APPLICABLE ;
		progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
						  .percentComplete = 100,
						  .completedItems  = amdDevices.size(),
						  .totalItems	   = amdDevices.size()}) ;
		scanSessionId_ = scanSessionId ;
		return result ;
	}

	// 対象device数が審査上限を超える場合は検索を開始しない。
	if( amdDevices.size() > MAXIMUM_AMD_DEVICES) {
		result.error = nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		return result ;
	}

	const std::wstring windowsSection = amdWindowsSection() ;	// 対象OS accordion名。
	// 実OSに対応するpage区分を確定できなければ検索を中止する。
	if( windowsSection.empty()) {
		result.error = nativeErrorFromWin32( ERROR_OLD_WIN_VERSION) ;
		return result ;
	}

	NativeError error =
		// 根拠session結果。
		httpClient_.beginSourceSession( scanSessionId, AMD_PROVIDER_ID) ;
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	std::wstring indexHtml ;	// UTF-16変換済みAMD製品選択page。
	error = httpClient_.getUtf8TextForSource(
		DRIVER_INDEX_URL, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID, MAXIMUM_INDEX_BYTES, indexHtml) ;
	// 原因の診断値を結果へ引き継いで中断し、不完全な処理を正常完了として扱わない。
	if( error != 0) {
		result.error = error ;
		return result ;
	}

	std::vector<AmdProductPage> products ;	// Schema検証済みAMD末端製品一覧。
	// 公式indexのschema検証失敗を候補なし成功と区別して返す。
	if( !parseAmdProductIndexHtml( indexHtml, products)) {
		result.state = ProviderScanState::METADATA_REJECTED ;
		result.error = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		return result ;
	}

	progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
					  .percentComplete = 20,
					  .completedItems  = 0,
					  .totalItems	   = amdDevices.size()}) ;

	bool		productPageFetched{} ;	// 一件以上のsecondary metadata取得成功時true。
	std::size_t candidateOrdinal{} ;	// Session内candidate／package連番。
	// Local AMD Displayごとに完全一致した一つの公式製品pageだけを取得する。
	for( std::size_t deviceIndex = 0U; deviceIndex < amdDevices.size(); ++deviceIndex) {
		const OfficialCatalogDevice &device = *amdDevices[deviceIndex] ;	// 現在のlocal device。
		AmdProductPage				 product ;								// 完全一致した公式末端製品page。
		// modelに一意に一致する公式製品pageがある場合にだけ詳細を取得する。
		if( findAmdProductPage( products, device.model, product)) {
			std::wstring productHtml ;	// UTF-16変換済み製品別support page。
			error = httpClient_.getUtf8TextForSource( product.url,
													 OFFICIAL_SECONDARY_METADATA_RESOURCE_ID,
													 MAXIMUM_PRODUCT_PAGE_BYTES, productHtml) ;
			// 製品page取得に失敗した場合は途中候補を破棄して原因を返す。
			if( error != 0) {
				result.error = error ;
				result.candidates.clear() ;
				return result ;
			}

			productPageFetched = true ;
			std::vector<AmdDriverPageEntry> entries ;	// 検証済みOS別表示metadata。
			// driver pageのmetadata検証に失敗した場合は途中候補を残さない。
			if( !parseAmdDriverPageHtml( productHtml, windowsSection, entries)) {
				result.state = ProviderScanState::METADATA_REJECTED ;
				result.error = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				result.candidates.clear() ;
				return result ;
			}

			// AMD page順を維持し、監査未完了の表示専用候補として追加する。
			for( const AmdDriverPageEntry &entry : entries) {
				UpdateCandidate candidate ;	// UIへ返すAMD公式配布情報。
				candidate.identity = L"amd-page:" + std::to_wstring( scanSessionId) + L":" +
									 std::to_wstring( candidateOrdinal) ;
				candidate.deviceIdentity  = device.deviceIdentity ;
				candidate.providerId	  = std::wstring( AMD_PROVIDER_ID) ;
				candidate.packageIdentity = L"amd-page-package:" + std::to_wstring( scanSessionId) +
											L":" + std::to_wstring( candidateOrdinal++) ;
				candidate.title		   = entry.title + L" " + entry.revision + L"（公式配布情報）" ;
				candidate.manufacturer = device.manufacturer ;
				candidate.model		   = device.model ;
				candidate.driverClass  = device.driverClass ;
				candidate.deviceClassGuid	   = device.deviceClassGuid ;
				candidate.provider			   = L"Advanced Micro Devices, Inc." ;
				candidate.version			   = entry.revision ;
				candidate.driverDate		   = entry.releaseDate ;
				candidate.sourceName		   = L"AMD Drivers and Support（表示専用）" ;
				candidate.sourceLocation	   = L"AMD公式 HTTPS（www.amd.com、payload未取得）" ;
				candidate.maximumDownloadBytes = entry.maximumDownloadBytes ;
				candidate.action			   = DriverAction::NONE ;
				candidate.defaultPreference	   = CandidateDefaultPreference::NONE ;
				candidate.discoveryBasis	   = CandidateDiscoveryBasis::OFFICIAL_WEB_PAGE ;
				candidate.audit				   = makeOfficialDiscoveryCandidateAudit() ;
				candidate.current			   = false ;
				candidate.recommended		   = false ;
				candidate.installable		   = false ;
				candidate.eulaAccepted		   = false ;
				candidate.allContentCached	   = false ;
				candidate.rebootMayBeRequired  = true ;
				candidate.browseOnly		   = false ;
				result.candidates.push_back( std::move( candidate)) ;
			}
		}

		++result.coverage.assessedDeviceCount ;
		const std::uint32_t percent = static_cast<std::uint32_t>(
			20U + (deviceIndex + 1U) * 75U / amdDevices.size()) ;	// 確定済み全体進捗。
		progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
						  .percentComplete = percent,
						  .completedItems  = deviceIndex + 1U,
						  .totalItems	   = amdDevices.size()}) ;
	}

	const bool primaryEvidence = httpClient_.hasSourceEvidence(
		scanSessionId, AMD_PROVIDER_ID, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ;	// 起点取得根拠。
	const bool secondaryEvidence =
		!productPageFetched ||
		httpClient_.hasSourceEvidence(
			scanSessionId, AMD_PROVIDER_ID,
			OFFICIAL_SECONDARY_METADATA_RESOURCE_ID) ;	// 必要な製品page取得根拠。
	// 一次・二次取得根拠が揃わない場合はsessionを失効させて候補を破棄する。
	if( !primaryEvidence || !secondaryEvidence) {
		invalidateScanSession() ;
		result.candidates.clear() ;
		result.state = ProviderScanState::SOURCE_REJECTED ;
		result.error = static_cast<NativeError>( E_UNEXPECTED) ;
		return result ;
	}

	result.succeeded = true ;
	result.outcome	 = OutcomeCode::SUCCESS ;
	result.state	 = result.candidates.empty() ? ProviderScanState::NO_CANDIDATES
												 : ProviderScanState::CANDIDATES_AVAILABLE ;
	progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
					  .percentComplete = 100,
					  .completedItems  = amdDevices.size(),
					  .totalItems	   = amdDevices.size()}) ;
	scanSessionId_ = scanSessionId ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/amd_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult AmdUpdateProvider::install( const ScanSessionId				 scanSessionId,
										 const std::span<const std::wstring> identities,
										 const std::uintptr_t				 parentWindowNative,
										 const ProviderProgressCallback		&progressCallback)
{
	static_cast<void>( scanSessionId) ;
	static_cast<void>( identities) ;
	static_cast<void>( parentWindowNative) ;
	static_cast<void>( progressCallback) ;
	InstallResult result ;	// 表示専用Providerの固定拒否結果。
	result.downloadOutcome = OutcomeCode::FAILURE ;
	result.downloadError   = static_cast<NativeError>( E_NOTIMPL) ;
	result.installOutcome  = OutcomeCode::FAILURE ;
	result.installError	   = static_cast<NativeError>( E_NOTIMPL) ;
	invalidateScanSession() ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/amd_update_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void AmdUpdateProvider::invalidateScanSession() noexcept
{
	scanSessionId_ = 0U ;
	httpClient_.invalidateSourceSession() ;
}

} // namespace drivercrate
