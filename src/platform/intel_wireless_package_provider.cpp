//------------------------------------------------------------------------------
/**
 * @file intel_wireless_package_provider.cpp
 * @brief 利用者選択INF package Provider共通実装。
 * @version 01.01.00
 * @date 2026/09/03
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  区分C候補の自動選択拒否。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Provider固有policyの共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  同一deviceの複数公式版表示追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Package由来class照合mode追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Provider固有class照合関数追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  利用者指定候補監査状態追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  共通個別INF検査とWindows適合観測の接続を追加。
 * </pre>
 *
 * @note 利用者選択INF ZIPを探索区分Cとして扱い、署名済みINFのPnP IDが現在deviceへ完全一致した場合だけ候補化します。Package pathとPnP IDはworker
 *       内に閉じ、install直前に全検証を反復します。
 */
//------------------------------------------------------------------------------

#include "platform/intel_wireless_package_provider.h"

#include "core/candidate_audit.h"
#include "core/candidate_assessment.h"
#include "core/device_observation.h"
#include "core/provider_registry.h"
#include "platform/intel_wireless_package.h"
#include "platform/official_download_workspace.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief 一つのdeviceへ対応した検証済みINF index群を保持する。
 */
struct MatchedPackages {
	/// Package contents内の重複なしindex群。
	std::vector<std::size_t> packageIndexes ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief ASCII文字列を大文字小文字を除いて比較する。
 *
 * Setup class名の比較だけに使用し、部分一致を許可しない。
 *
 * @param[in] left 左辺文字列。
 * @param[in] right 右辺文字列。
 * @return ASCII英字のcaseだけを無視して完全一致する場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool asciiStringsEqual( const std::wstring_view left,
									 const std::wstring_view right) noexcept
{
	// 長さの異なるASCII文字列を同一識別子とみなさない。
	if( left.size() != right.size()) {
		return false ;
	}

	// 同じ長さの文字列をASCIIの大小文字差だけ除いて比較する。
	for( std::size_t index = 0; index < left.size(); ++index) {
		const wchar_t leftCharacter	  = left[index] ;	// 現在位置の左辺文字。
		const wchar_t rightCharacter  = right[index] ;	// 現在位置の右辺文字。
		const wchar_t normalizedLeft  = leftCharacter >= L'A' && leftCharacter <= L'Z'
											? static_cast<wchar_t>( leftCharacter - L'A' + L'a')
											: leftCharacter ;	// ASCII小文字化した左辺文字。
		const wchar_t normalizedRight = rightCharacter >= L'A' && rightCharacter <= L'Z'
											? static_cast<wchar_t>( rightCharacter - L'A' + L'a')
											: rightCharacter ;	// ASCII小文字化した右辺文字。
		// 正規化後にも異なる文字があれば不一致とする。
		if( normalizedLeft != normalizedRight) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 4要素numeric driver versionを解析する。
 *
 * 日付や表示名を適用性に使わず、検証済み候補のaction分類だけにversionを使用する。
 *
 * @param[in] version `a.b.c.d`形式のdriver version。
 * @return 4要素の数値。形式不正またはoverflow時は`std::nullopt`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::array<std::uint32_t, 4>> parseVersion(
	const std::wstring_view version) noexcept
{
	std::array<std::uint32_t, 4> parts{} ;		// 解析済みversion要素。
	std::size_t					 partIndex{} ;	// 現在解析する0始まり要素index。
	std::uint64_t				 value{} ;		// Overflow検査用の現在要素値。
	bool						 hasDigit{} ;	// 現在要素に一桁以上あればtrue。
	// 終端を仮想separatorとして処理し、4要素以外を拒否する。
	for( std::size_t index = 0; index <= version.size(); ++index) {
		const wchar_t character = index == version.size() ? L'.' : version[index] ;	// 現在文字。
		// 版の数字を現在の数値要素へ取り込む。
		if( character >= L'0' && character <= L'9') {
			const std::uint64_t digit = static_cast<std::uint64_t>( character - L'0') ;	// 桁値。
			// 版要素の32-bit overflowを桁追加前に検出する。
			if( value > (std::numeric_limits<std::uint32_t>::max() - digit) / 10U) {
				return std::nullopt ;
			}

			value	 = value * 10U + digit ;
			hasDigit = true ;
			continue ;
		}

		// 不正な区切り、空要素、過剰要素を含む版を拒否する。
		if( character != L'.' || !hasDigit || partIndex >= parts.size()) {
			return std::nullopt ;
		}

		parts[partIndex] = static_cast<std::uint32_t>( value) ;
		++partIndex ;
		value	 = 0 ;
		hasDigit = false ;
	}

	return partIndex == parts.size() ? std::optional( parts) : std::nullopt ;
}

//------------------------------------------------------------------------------
/**
 * @brief 検証済みdriver versionを現在版に対するactionへ分類する。
 *
 * 比較不能時は新しい版と推測せず明示再導入へ分類する。
 *
 * @param[in] candidateVersion INFが宣言した4要素version。
 * @param[in] currentVersion SetupAPIが返した現在driver version。
 * @return 数値比較結果に対応するUpdate、ReinstallまたはDowngrade。
 */
//------------------------------------------------------------------------------
[[nodiscard]] DriverAction classifyAction( const std::wstring_view candidateVersion,
										  const std::wstring_view currentVersion) noexcept
{
	const auto candidate = parseVersion( candidateVersion) ;	// INF version解析結果。
	const auto current	 = parseVersion( currentVersion) ;		// 現在version解析結果。
	// 版を数値比較できない場合は通常更新ではなく再導入に分類する。
	if( !candidate.has_value() || !current.has_value()) {
		return DriverAction::REINSTALL ;
	}

	// 候補版が現在版を上回る場合だけ通常更新に分類する。
	if( candidate.value() > current.value()) {
		return DriverAction::UPDATE ;
	}

	// 候補版が現在版を下回る場合は旧版への切替として区別する。
	if( candidate.value() < current.value()) {
		return DriverAction::DOWNGRADE ;
	}

	return DriverAction::REINSTALL ;
}

//------------------------------------------------------------------------------
/**
 * @brief INF日付をUIの年月日順へ変換する。
 *
 * 日付は表示専用とし、候補適用性または新旧判定に使用しない。
 *
 * @param[in] value INF DriverVerの`MM/DD/YYYY`日付。
 * @return `YYYY/MM/DD`形式。形式不正時は空文字列。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring formatDriverDate( const std::wstring_view value)
{
	// INF日付の固定形式が不正な場合は表示日付を推測しない。
	if( value.size() != 10U || value[2] != L'/' || value[5] != L'/') {
		return {} ;
	}

	// Separator以外がASCII数字であることを確認する。
	for( std::size_t index = 0; index < value.size(); ++index) {
		// 検証済みの区切り位置を数字検査から除く。
		if( index == 2U || index == 5U) {
			continue ;
		}

		// 年月日の位置に数字以外があれば変換しない。
		if( value[index] < L'0' || value[index] > L'9') {
			return {} ;
		}
	}

	return std::wstring( value.substr( 6U, 4U)) + L"/" + std::wstring( value.substr( 0U, 2U)) + L"/" +
		   std::wstring( value.substr( 3U, 2U)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 入力fileへの到達失敗か判定する。
 *
 * 入力I/O失敗とpackage metadata拒否をProvider reportで区別する。
 *
 * @param[in] error Package検証が返したHRESULT bit pattern。
 * @return File欠落、path欠落、共有違反の場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isInputAccessError( const NativeError error) noexcept
{
	const NativeError fileNotFound =
		// File欠落HRESULT。
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND)) ;
	const NativeError pathNotFound =
		// Path欠落HRESULT。
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND)) ;
	const NativeError sharingViolation =
		// 共有違反HRESULT。
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_SHARING_VIOLATION)) ;
	return error == fileNotFound || error == pathNotFound || error == sharingViolation ;
}

//------------------------------------------------------------------------------
/**
 * @brief Intel検証済みPnP IDの候補化を許可する。
 *
 * Intel package検証が全IDを`PCI\\VEN_8086`へ限定済みのため追加の部分filterを行わない。
 * @param[in] hardwareId Package監査で検証済みのcatalog側PnP ID。呼出し中だけ借用する。
 * @return 空でない検証済みIDの場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool allowIntelHardwareId( const std::wstring_view hardwareId) noexcept
{
	return !hardwareId.empty() ;
}

//------------------------------------------------------------------------------
/**
 * @brief Intel Wireless用のProvider policyを作成する。
 *
 * Netwtw packageは一device一INFに限定し、曖昧時は候補化しない。
 * @return Intel固有のstable ID、表示文字列、検証関数を所有する値。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UserSelectedInfProviderPolicy makeIntelProviderPolicy()
{
	return {.providerId						= std::wstring( INTEL_WIRELESS_PACKAGE_PROVIDER_ID),
			.deviceClass					= L"Net",
			.identityPrefix					= L"intel-wireless-package:",
			.packagePrefix					= L"intel-wireless-inf:",
			.titlePrefix					= L"Intel Wireless Driver ",
			.sourceName						= L"Intel Wireless署名済みINF ZIP",
			.sourceLocation					= L"利用者選択local ZIP（端末内で署名・PnP ID検証）",
			.inspect						= inspectIntelWirelessPackageFile,
			.reverify						= reverifyIntelWirelessInfPackage,
			.hardwareIdAllowed				= allowIntelHardwareId,
			.allowMultiplePackagesPerDevice = false} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider policyに従ってdevice classを照合する。
 *
 * 固有関数がないProviderはASCII大文字小文字を無視した完全一致を維持する。本処理はnetwork I/Oを行わない。
 *
 * @param[in] policy Providerが単独所有するclass照合条件。
 * @param[in] packageClass 検証済みINFのsetup class。
 * @param[in] deviceClass 現在deviceのsetup class。
 * @return Providerが許可するclass対応の場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool providerDeviceClassMatches( const UserSelectedInfProviderPolicy &policy,
											  const std::wstring_view			   packageClass,
											  const std::wstring_view deviceClass) noexcept
{
	// Provider固有class matcherがある場合はその照合規則を使用する。
	if( policy.deviceClassMatches != nullptr) {
		return policy.deviceClassMatches( packageClass, deviceClass) ;
	}

	return asciiStringsEqual( packageClass, deviceClass) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider固有policyの必須項目を検証する。
 *
 * 不完全policyでfileを読み込む前にfail-closedで拒否する。
 *
 * @param[in] policy Providerが単独所有する検証・表示条件。
 * @return Stable ID、class、identity、表示、全関数がある場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidPolicy( const UserSelectedInfProviderPolicy &policy) noexcept
{
	const bool validClassMode =	// 固定classとpackage由来classを排他的に指定した状態。
		policy.usePackageDeviceClass ? policy.deviceClass.empty() : !policy.deviceClass.empty() ;
	const bool validClassMatcher =	// 追加照合はpackage由来class modeだけに限定する。
		policy.usePackageDeviceClass || policy.deviceClassMatches == nullptr ;
	return !policy.providerId.empty() && validClassMode && validClassMatcher &&
		   !policy.identityPrefix.empty() && !policy.packagePrefix.empty() &&
		   !policy.titlePrefix.empty() && !policy.sourceName.empty() &&
		   !policy.sourceLocation.empty() && policy.inspect != nullptr &&
		   policy.reverify != nullptr && policy.hardwareIdAllowed != nullptr ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/intel_wireless_package_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
UserSelectedInfPackageProvider::UserSelectedInfPackageProvider()
	: UserSelectedInfPackageProvider( makeIntelProviderPolicy())
{
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/intel_wireless_package_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
UserSelectedInfPackageProvider::UserSelectedInfPackageProvider( UserSelectedInfProviderPolicy policy)
	: policy_( std::move( policy))
{
}

//------------------------------------------------------------------------------
/**
 * @brief Scan sessionと保護workspaceを解放する。
 *
 * 既知の展開fileだけをworkspace destructorへ解放させる。
 */
//------------------------------------------------------------------------------
UserSelectedInfPackageProvider::~UserSelectedInfPackageProvider() = default ;

//------------------------------------------------------------------------------
/**
 * @see src/platform/intel_wireless_package_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
ScanResult UserSelectedInfPackageProvider::scan(
	const ScanSessionId scanSessionId, const ScanOptions &options,
	const std::span<const OfficialCatalogDevice> devices,
	const LocalHardwareIdMatcher				&hardwareIdMatcher,
	const ProviderProgressCallback &progressCallback, const CommonInfRankObserver &rankObserver)
{
	invalidateScanSession() ;
	ScanResult result{} ;	// 利用者選択packageの候補と到達状態。
	result.scanSessionId = scanSessionId ;
	result.outcome		 = OutcomeCode::FAILURE ;
	result.state		 = ProviderScanState::FAILURE ;
	// session、matcher、通知先、scan設定、policyを候補作成前に検証する。
	if( scanSessionId == 0 || !hardwareIdMatcher || !progressCallback ||
	   !validateScanOptions( options) || !isValidPolicy( policy_) ||
	   (policy_.useCommonInspection && !rankObserver)) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	const std::wstring_view selectedPath =
		// 選択ZIP。
		userSelectedFileForProvider( options, policy_.providerId) ;
	// 利用者が指定していないpathからpackageを取得しない。
	if( selectedPath.empty()) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	ownerThreadId_ = GetCurrentThreadId() ;
	result.coverage.eligibleDeviceCount =
		policy_.usePackageDeviceClass
			? static_cast<std::uint64_t>( devices.size())
			: static_cast<std::uint64_t>( std::count_if(
				  devices.begin(), devices.end(), [this]( const OfficialCatalogDevice &device) {
					  return asciiStringsEqual( device.driverClass, policy_.deviceClass) ;
				  })) ; // 検証前に判明する最大対象device数。
	progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
					  .percentComplete = 0,
					  .completedItems  = 0,
					  .totalItems	   = result.coverage.eligibleDeviceCount}) ;

	try {
		// Scan session保護領域。
		workspace_ = std::make_unique<OfficialDownloadWorkspace>() ;
		UserSelectedInfPackageContents contents ;	// 全署名検証済みZIP内容。
		const NativeError			   inspectionError =
			// 検証結果。
			policy_.inspect( selectedPath, scanSessionId, *workspace_, contents) ;
		// 入力アクセス失敗と内容拒否を区別し、失敗したscanを失効させる。
		if( inspectionError != 0) {
			result.error = inspectionError ;
			result.state = isInputAccessError( inspectionError)
							   ? ProviderScanState::FAILURE
							   : ProviderScanState::CONTENT_REJECTED ;
			invalidateScanSession() ;
			return result ;
		}

		// 共通検査要求と実際の検査結果を一致させ、従来検査へ暗黙fallbackしない。
		if( policy_.useCommonInspection != static_cast<bool>( contents.commonInspection)) {
			result.error = static_cast<NativeError>( E_UNEXPECTED) ;
			invalidateScanSession() ;
			return result ;
		}

		// 個別閉包を所有したまま、現在名・版・classに依存しないWindows照合へ接続する。
		if( policy_.useCommonInspection) {
			result = buildCommonCandidates( scanSessionId, devices, rankObserver, progressCallback,
										   *contents.commonInspection) ;
			// 全体失敗では部分候補とworkspaceを再利用しない。
			if( !result.succeeded) {
				invalidateScanSession() ;
				return result ;
			}

			commonInspection_ = std::move( contents.commonInspection) ;
			scanSessionId_	  = scanSessionId ;
			return result ;
		}

		const auto deviceClassIsEligible = [this, &contents]( const std::wstring_view deviceClass) {
			// package classを使わないpolicyでは固定device classへ照合する。
			if( !policy_.usePackageDeviceClass) {
				return asciiStringsEqual( deviceClass, policy_.deviceClass) ;
			}

			return std::ranges::any_of(
				contents.packages, [this, deviceClass]( const OfficialInfPackage &package) {
					return providerDeviceClassMatches( policy_, package.className, deviceClass) ;
				}) ;
		} ; // 固定classまたは全検証済みINFのclassから現在device対象範囲を決める処理。
		result.coverage.eligibleDeviceCount = static_cast<std::uint64_t>(
			std::count_if( devices.begin(), devices.end(),
						  [&deviceClassIsEligible]( const OfficialCatalogDevice &device) {
							  return deviceClassIsEligible( device.driverClass) ;
						  })) ;
		progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
						  .percentComplete = 65,
						  .completedItems  = 0,
						  .totalItems	   = result.coverage.eligibleDeviceCount}) ;

		// Opaque device identityから、呼出し中に借用するlocal表示metadataへの対応。
		std::unordered_map<std::wstring, const OfficialCatalogDevice *> deviceMetadata ;
		// Opaque identity別の表示metadata。
		deviceMetadata.reserve( devices.size()) ;
		// Provider対象classだけをcandidate metadata検索表へ一意に登録する。
		for( const OfficialCatalogDevice &device : devices) {
			// 対象classのdeviceだけをpackage照合用snapshotへ保持する。
			if( deviceClassIsEligible( device.driverClass)) {
				deviceMetadata.emplace( device.deviceIdentity, &device) ;
			}
		}

		// Local deviceごとに検証済みpackageとの一致結果を集約するmap。
		std::unordered_map<std::wstring, MatchedPackages> matchedPackages ;
		// 全検証済みINFのPnP IDをlocal mapへ完全一致させる。
		for( std::size_t packageIndex = 0; packageIndex < contents.packages.size(); ++packageIndex) {
			const OfficialInfPackage		&package = contents.packages[packageIndex] ;	// 現在INF。
			std::unordered_set<std::wstring> packageDevices ;								// 同一INF内のdevice重複排除集合。
			// package側のIDをpolicy検査後に端末内matcherへ照合する。
			for( const std::wstring &hardwareId : package.hardwareIds) {
				// Providerの許可外IDを端末照合へ渡さない。
				if( !policy_.hardwareIdAllowed( hardwareId)) {
					continue ;
				}

				const std::optional<std::wstring> matched =
					// Local完全一致結果。
					hardwareIdMatcher( hardwareId) ;
				// opaque deviceへ解決できたIDだけにclass照合を行う。
				if( matched.has_value()) {
					const auto metadata = deviceMetadata.find( matched.value()) ;	// Device metadata。
					// snapshotとclassの両方が一致するdeviceだけを対応先へ追加する。
					if( metadata != deviceMetadata.end() &&
					   providerDeviceClassMatches( policy_, package.className,
												  metadata->second->driverClass)) {
						packageDevices.insert( matched.value()) ;
					}
				}
			}

			// 照合済みdeviceごとに対応する検証済みINF indexを集約する。
			for( const std::wstring &deviceIdentity : packageDevices) {
				MatchedPackages &matches =
					matchedPackages[deviceIdentity] ;	// Device別の検証済みINF集合。
				// 同じpackage indexを一deviceへ重複登録しない。
				if( std::ranges::find( matches.packageIndexes, packageIndex) ==
				   matches.packageIndexes.end()) {
					matches.packageIndexes.push_back( packageIndex) ;
				}
			}
		}

		std::size_t candidateIndex{} ;	// Opaque candidate identity用の連番。
		// Device inventory順とpackage順を維持し、policyが許す一致だけを候補化する。
		for( const OfficialCatalogDevice &device : devices) {
			const auto matched = matchedPackages.find( device.deviceIdentity) ;	// INF一致結果。
			// 対応INFがないdeviceやpolicyで許可しない複数対応を候補から除外する。
			if( matched == matchedPackages.end() || matched->second.packageIndexes.empty() ||
			   (!policy_.allowMultiplePackagesPerDevice &&
				matched->second.packageIndexes.size() != 1U)) {
				continue ;
			}

			// 利用者が新版と過去版を個別に選べるよう、許可時は全一致INFを保持する。
			for( const std::size_t packageIndex : matched->second.packageIndexes) {
				// 保持package範囲外のindexを検出した場合はscanを失効させる。
				if( packageIndex >= contents.packages.size()) {
					result.error = static_cast<NativeError>( E_UNEXPECTED) ;
					invalidateScanSession() ;
					return result ;
				}

				const OfficialInfPackage &package =
					contents.packages[packageIndex] ;	// 候補の検証済みINF。
				// 候補構築時にclass対応が崩れていれば不整合としてscanを中止する。
				if( !providerDeviceClassMatches( policy_, package.className, device.driverClass)) {
					result.error = static_cast<NativeError>( E_UNEXPECTED) ;
					invalidateScanSession() ;
					return result ;
				}

				const std::wstring identity = policy_.identityPrefix +
											  std::to_wstring( scanSessionId) + L":" +
											  // Opaque候補ID。
											  std::to_wstring( candidateIndex) ;
				UpdateCandidate candidate ;	// UIへ渡すpath／PnP IDを含まない候補。
				candidate.identity		  = identity ;
				candidate.deviceIdentity  = device.deviceIdentity ;
				candidate.providerId	  = policy_.providerId ;
				candidate.packageIdentity = policy_.packagePrefix + contents.archiveSha256 + L":" +
											std::to_wstring( packageIndex) ;
				candidate.title			  = policy_.titlePrefix + package.driverVersion ;
				candidate.manufacturer	  = device.manufacturer ;
				candidate.model			  = device.model ;
				candidate.driverClass	  = device.driverClass ;
				candidate.deviceClassGuid = device.deviceClassGuid ;
				candidate.provider		  = package.providerName ;
				candidate.version		  = package.driverVersion ;
				candidate.driverDate	  = formatDriverDate( package.driverDate) ;
				candidate.sourceName	  = policy_.sourceName ;
				candidate.sourceLocation  = policy_.sourceLocation ;
				candidate.action = classifyAction( package.driverVersion, device.currentVersion) ;
				candidate.defaultPreference	  = CandidateDefaultPreference::NONE ;
				candidate.discoveryBasis	  = CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE ;
				candidate.audit				  = makeUserSelectedCandidateAudit() ;
				candidate.recommended		  = false ;
				candidate.installable		  = true ;
				candidate.eulaAccepted		  = false ;
				candidate.rebootMayBeRequired = true ;
				installTargets_.emplace(
					identity,
					InstallTarget{.deviceIdentity = device.deviceIdentity, .package = package}) ;
				result.candidates.push_back( std::move( candidate)) ;
				++candidateIndex ;
			}
		}

		entries_							= std::move( contents.entries) ;
		scanSessionId_						= scanSessionId ;
		result.coverage.assessedDeviceCount = result.coverage.eligibleDeviceCount ;
		result.succeeded					= true ;
		result.outcome						= OutcomeCode::SUCCESS ;
		result.state = result.candidates.empty() ? ProviderScanState::NO_CANDIDATES
												 : ProviderScanState::CANDIDATES_AVAILABLE ;
		progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
						  .percentComplete = 100,
						  .completedItems  = result.coverage.assessedDeviceCount,
						  .totalItems	   = result.coverage.eligibleDeviceCount}) ;
		return result ;
	} catch( const std::bad_alloc &) {
		result.error = static_cast<NativeError>( E_OUTOFMEMORY) ;
		result.candidates.clear() ;
		invalidateScanSession() ;
		return result ;
	} catch( ...) {
		// 観測callback等の例外で部分候補や所有workspaceを次の操作へ残さない。
		result.error = static_cast<NativeError>( E_UNEXPECTED) ;
		result.candidates.clear() ;
		invalidateScanSession() ;
		return result ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/intel_wireless_package_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
InstallResult UserSelectedInfPackageProvider::install(
	const ScanSessionId scanSessionId, const std::span<const std::wstring> identities,
	const std::uintptr_t parentWindowNative, const VerifiedExternalInfInstaller &installer,
	const ProviderProgressCallback &progressCallback)
{
	InstallResult result{} ;	// 選択順で返すcollection結果。
	result.updates.reserve( identities.size()) ;
	// 要求した全identityの結果行を先に用意し、拒否結果も個別に残せるようにする。
	for( const std::wstring &identity : identities) {
		result.updates.push_back( {.identity = identity}) ;
	}

	std::unordered_set<std::wstring> uniqueIdentities ;	// Candidate ID重複検出集合。
	std::unordered_set<std::wstring> uniqueDevices ;	// 一device一候補検証集合。
	bool valid = scanSessionId != 0 && scanSessionId == scanSessionId_ &&
				 GetCurrentThreadId() == ownerThreadId_ && !identities.empty() &&
				 workspace_ != nullptr && installer && progressCallback ;	// Session基本検証結果。
	// 全identityの存在、一意性、一device一候補をsystem変更前に確認する。
	for( const std::wstring &identity : identities) {
		const auto target = installTargets_.find( identity) ;	// Scan時target検索結果。
		// 要求不正、未知候補、重複候補、一deviceへの複数指定を検出する。
		if( !valid || !uniqueIdentities.insert( identity).second || target == installTargets_.end() ||
		   !uniqueDevices.insert( target->second.deviceIdentity).second) {
			valid = false ;
			break ;
		}
	}

	// 選択検証に失敗した場合は部分導入せず全体を拒否する。
	if( !valid) {
		result.downloadOutcome = OutcomeCode::FAILURE ;
		result.downloadError   = static_cast<NativeError>( E_INVALIDARG) ;
		result.installOutcome  = OutcomeCode::FAILURE ;
		result.installError	   = static_cast<NativeError>( E_INVALIDARG) ;
		// 拒否した選択の全候補へ同じ引数診断値を残す。
		for( UpdateExecutionResult &update : result.updates) {
			update.downloadOutcome = OutcomeCode::FAILURE ;
			update.downloadError   = static_cast<NativeError>( E_INVALIDARG) ;
			update.installOutcome  = OutcomeCode::FAILURE ;
			update.installError	   = static_cast<NativeError>( E_INVALIDARG) ;
		}

		invalidateScanSession() ;
		return result ;
	}

	result.downloadOutcome = OutcomeCode::SUCCESS ;
	// Local packageは追加downloadを行わず、scan時の保護copyを使用する。
	for( UpdateExecutionResult &update : result.updates) {
		update.downloadOutcome = OutcomeCode::SUCCESS ;
	}

	progressCallback( {.stage		   = ProviderStage::DOWNLOADING,
					  .percentComplete = 20,
					  .completedItems  = identities.size(),
					  .totalItems	   = identities.size()}) ;

	std::size_t installed{} ;	// INF適用に成功した候補数。
	NativeError lastError{} ;	// Collectionへ返す最後の失敗code。
	// 選択順に再検証し、一件失敗しても未処理候補の個別結果を残す。
	for( std::size_t index = 0; index < identities.size(); ++index) {
		const InstallTarget &target = installTargets_.at( identities[index]) ;	// 現在対象。
		lastError					= policy_.reverify( *workspace_, entries_, target.package) ;
		bool rebootRequired{} ;	// 現在INFが要求した再起動flag。
		// 再検証が成功したINFだけを指定deviceのinstallerへ渡す。
		if( lastError == 0) {
			const std::wstring infPath =
				// 再検証済みINF絶対path。
				workspace_->path( target.package.infRelativePath) ;
			lastError = installer( scanSessionId, target.deviceIdentity, infPath,
								  target.package.providerName, target.package.driverVersion,
								  parentWindowNative, rebootRequired) ;
		}

		UpdateExecutionResult &update = result.updates[index] ;	// 現在候補の個別結果。
		update.rebootRequired		  = rebootRequired ;
		result.rebootRequired		  = result.rebootRequired || rebootRequired ;
		// 実導入が成功した候補だけを完了件数へ含める。
		if( lastError == 0) {
			update.installOutcome = OutcomeCode::SUCCESS ;
			++installed ;
		} else {
			update.installOutcome = OutcomeCode::FAILURE ;
			update.installError	  = lastError ;
		}

		const std::uint64_t completed = index + 1U ;	// 検証・導入を終えた候補数。
		progressCallback( {.stage = ProviderStage::INSTALLING,
						  .percentComplete =
							  static_cast<std::uint32_t>( 20U + completed * 80U / identities.size()),
						  .completedItems = completed,
						  .totalItems	  = identities.size()}) ;
	}

	result.succeeded = installed == identities.size() ;
	result.installOutcome =
		result.succeeded
			? OutcomeCode::SUCCESS
			: (installed == 0 ? OutcomeCode::FAILURE : OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
	result.installError = result.succeeded ? 0 : lastError ;
	invalidateScanSession() ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/intel_wireless_package_provider.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void UserSelectedInfPackageProvider::invalidateScanSession() noexcept
{
	commonInspection_.reset() ;
	installTargets_.clear() ;
	entries_.clear() ;
	workspace_.reset() ;
	scanSessionId_ = 0 ;
	ownerThreadId_ = 0 ;
}

/**
 * @see src/platform/intel_wireless_package_provider.h 宣言側の契約を正本とする。
 */
ScanResult UserSelectedInfPackageProvider::buildCommonCandidates(
	const ScanSessionId scanSessionId, const std::span<const OfficialCatalogDevice> devices,
	const CommonInfRankObserver &rankObserver, const ProviderProgressCallback &progressCallback,
	const CommonDriverPackageInspection &inspection) const
{
	ScanResult result ;	// 個別結果を確認してから成功へ遷移する表示結果。
	result.scanSessionId = scanSessionId ;
	result.state		 = ProviderScanState::FAILURE ;
	result.outcome		 = OutcomeCode::FAILURE ;
	// 検査所有session・有限件数・観測境界を要求する。
	if( inspection.scanSessionId != scanSessionId || inspection.error != 0 ||
	   inspection.infs.size() > 128U || devices.size() > 4096U || !rankObserver ||
	   !progressCallback) {
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result ;
	}

	std::unordered_set<std::wstring> deviceIdentities ;	// 重複snapshotの拒否集合。
	// 欠損表示名は許すが、opaque identityと観測sessionの不整合は拒否する。
	for( const OfficialCatalogDevice &device : devices) {
		// 同じdeviceの二重表示、stale観測、長大IDを後段照合へ渡さない。
		if( device.deviceIdentity.empty() || device.deviceIdentity.size() > 256U ||
		   !deviceIdentities.insert( device.deviceIdentity).second ||
		   (device.deviceObservation &&
			!isDeviceObservationBound( *device.deviceObservation, scanSessionId,
									  device.deviceIdentity))) {
			result.error = static_cast<NativeError>( E_INVALIDARG) ;
			return result ;
		}
	}

	result.coverage.eligibleDeviceCount = devices.size() ;
	std::vector<bool> deviceAssessed( devices.size(), true) ;	// 全INFを判定できたdeviceだけを数える。
	std::uint64_t	  pairs{} ;									// 同期Windows照合の総数。32,768を上限にする。
	const std::uint64_t total = static_cast<std::uint64_t>( std::ranges::count_if(
									inspection.infs,
									[]( const CommonInfInspection &inf) {
										return inf.state == CommonInfInspectionState::VERIFIED ;
									})) *
								// 内容合格後に実際に照合する組合せ。
								devices.size() ;
	bool rejectedContent{} ;	// 未検査内容のあるdeviceを完全coverageとしない。
	// 各INFを一度だけ内容参照し、全present deviceへ独立に照合する。
	for( std::size_t infIndex = 0; infIndex < inspection.infs.size(); ++infIndex) {
		const CommonInfInspection &inspected = inspection.infs[infIndex] ;	// 所有期間内の一閉包。
		// 他sessionの検査を同じpackageとして扱わない。
		if( inspected.scanSessionId != scanSessionId) {
			result.error = static_cast<NativeError>( E_INVALIDARG) ;
			result.candidates.clear() ;
			return result ;
		}

		// 個別の内容拒否は他INFの適合検査を止めず、warningとして保持する。
		if( inspected.state != CommonInfInspectionState::VERIFIED) {
			rejectedContent = true ;
			// 最初の具体的な検査codeを後の成功で消さない。
			if( result.error == 0) {
				result.error =
					inspected.error != 0 ? inspected.error : static_cast<NativeError>( E_UNEXPECTED) ;
			}

			continue ;
		}

		// 不完全な合格構造をSetupAPIや候補へ渡さない。
		if( !inspected.workspace || inspected.closure.packages.size() != 1U ||
		   inspected.error != 0) {
			result.error = static_cast<NativeError>( E_INVALIDARG) ;
			result.candidates.clear() ;
			return result ;
		}

		const OfficialInfPackage &package =
			// 検査済みINF metadata。
			inspected.closure.packages.front() ;
		// IDが同じ複数portでも一件へ潰さず、device identityごとにWindowsへ問い合わせる。
		for( std::size_t deviceIndex = 0; deviceIndex < devices.size(); ++deviceIndex) {
			// 同期API呼出し上限で未確認部分を残して全体合格としない。
			if( pairs >= 32768U) {
				result.error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW)) ;
				result.candidates.clear() ;
				return result ;
			}

			const OfficialCatalogDevice &device = devices[deviceIndex] ;	// 現在の非機密snapshot。
			std::optional<std::uint32_t> rank ;								// Windowsが実際に一致させた候補rank。
			const NativeError			 error =
				rankObserver( scanSessionId, device.deviceIdentity, *inspected.workspace, package,
							 rank) ;	// 現在版を要求しない観測。
			++pairs ;
			progressCallback(
				{.stage			  = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
				 .percentComplete = static_cast<std::uint32_t>( 65U + pairs * 35U / total),
				 .completedItems  = pairs,
				 .totalItems	  = total}) ;
			// API失敗は「該当なし」にせず、当該deviceの判定未完了を残す。
			if( error != 0) {
				deviceAssessed[deviceIndex] = false ;
				// 最初の観測失敗を後続結果で上書きしない。
				if( result.error == 0) {
					result.error = error ;
				}

				continue ;
			}

			// Windowsが一致nodeを返さなかった組合せを候補化しない。
			if( !rank) {
				continue ;
			}

			UpdateCandidate candidate ;	// Pathと実IDを持たない表示専用候補。
			candidate.identity = policy_.identityPrefix + std::to_wstring( scanSessionId) + L":" +
								 std::to_wstring( infIndex) + L":" + std::to_wstring( deviceIndex) ;
			candidate.deviceIdentity = device.deviceIdentity ;
			candidate.providerId	 = policy_.providerId ;
			candidate.packageIdentity =
				policy_.packagePrefix + inspection.archiveSha256 + L":" + std::to_wstring( infIndex) ;
			candidate.title		   = policy_.titlePrefix + package.driverVersion ;
			candidate.manufacturer = device.manufacturer ;
			candidate.model		   = device.model ;
			candidate.driverClass =
				device.driverClass.empty() ? package.className : device.driverClass ;
			candidate.deviceClassGuid = device.deviceClassGuid ;
			candidate.provider		  = package.providerName ;
			candidate.version		  = package.driverVersion ;
			candidate.driverDate	  = formatDriverDate( package.driverDate) ;
			candidate.sourceName	  = policy_.sourceName ;
			candidate.sourceLocation  = policy_.sourceLocation ;
			candidate.action =
				device.deviceObservation && device.deviceObservation->driverPresence ==
												DeviceDriverPresence::NOT_INSTALLED
					? DriverAction::INITIAL_INSTALL
					: (parseVersion( device.currentVersion)
						   ? classifyAction( package.driverVersion, device.currentVersion)
						   : DriverAction::NONE) ;
			candidate.discoveryBasis			= CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE ;
			candidate.audit						= makeUserSelectedCandidateAudit() ;
			candidate.audit.systemApplicability = CandidateAuditGateState::PASSED ;
			candidate.audit.installReadiness	= CandidateInstallReadiness::BLOCKED ;
			const CandidateAssessmentFinding origin{
				CandidateAssessmentState::NOT_APPLICABLE, CandidateAssessmentReason::USER_PROVIDED,
				CandidateEvidenceKind::USER_INPUT,
				infIndex + 1U} ;			// Local取得を公式由来へ昇格しない。
			CandidateAssessment detail ;	// 現在順位とexecutorを未確認に保つ八軸。
			// 内容・適合・candidate identityの結合不整合を結果公開前に拒否する。
			if( !makeCommonInfCandidateAssessment( scanSessionId, candidate, inspected, infIndex + 1U,
												 origin, 0, rank, detail)) {
				result.error = static_cast<NativeError>( E_UNEXPECTED) ;
				result.candidates.clear() ;
				return result ;
			}

			candidate.assessment = std::move( detail) ;
			result.candidates.push_back( std::move( candidate)) ;
		}
	}

	result.coverage.assessedDeviceCount =
		rejectedContent ? 0U
						: static_cast<std::uint64_t>(
							  std::count( deviceAssessed.begin(), deviceAssessed.end(), true)) ;
	result.succeeded = true ;
	result.outcome = result.error == 0 ? OutcomeCode::SUCCESS : OutcomeCode::SUCCEEDED_WITH_ERRORS ;
	result.state   = result.candidates.empty()
						 ? (rejectedContent ? ProviderScanState::CONTENT_REJECTED
											: ProviderScanState::NO_CANDIDATES)
						 : ProviderScanState::CANDIDATES_AVAILABLE ;
	progressCallback( {.stage		   = ProviderStage::SEARCHING_OFFICIAL_CATALOGS,
					  .percentComplete = 100,
					  .completedItems  = total,
					  .totalItems	   = total}) ;
	return result ;
}

} // namespace drivercrate
