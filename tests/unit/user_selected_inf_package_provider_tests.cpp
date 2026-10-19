//------------------------------------------------------------------------------
/**
 * @file user_selected_inf_package_provider_tests.cpp
 * @brief 利用者選択INF Provider単体試験実装。
 * @version 01.02.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  PrinterとPrintQueueの照合試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  利用者指定候補監査状態試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  共通Providerの未導入・欠損・複数port接続試験を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  複数INF、版分類、個別拒否の共通Provider試験を追加。
 * </pre>
 *
 * @note 署名検証済み相当の架空metadataだけを注入し、network、実Hardware ID、SetupAPI installを使用せずProviderのclass照合を検証します。
 */
//------------------------------------------------------------------------------

#include "user_selected_inf_package_provider_tests.h"

#include "core/provider_registry.h"
#include "core/candidate_assessment.h"
#include "core/candidate_audit.h"
#include "core/device_observation.h"
#include "platform/common_driver_package.h"
#include "platform/generic_inf_package.h"
#include "platform/intel_wireless_package_provider.h"
#include "test_framework.h"

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 架空Printer INF packageを検証成功結果として返す。
 *
 * Package verifier自体を試験せず、その後のclassとPnP routingだけを独立して確認するためのfakeである。
 *
 * @param[in] selectedPath Scan設定が渡した架空ZIP path。
 * @param[in] scanSessionId 0ではないscan session ID。
 * @param[in,out] workspace 本fakeではfileを作成しない保護領域。
 * @param[out] contents 架空の検証済みPrinter INF metadata。
 * @return 入力が成立する場合は0、それ以外は`E_INVALIDARG`。
 */
//------------------------------------------------------------------------------
NativeError inspectFakePrinterPackage( const std::wstring_view		  selectedPath,
									  const ScanSessionId			  scanSessionId,
									  OfficialDownloadWorkspace		 &workspace,
									  UserSelectedInfPackageContents &contents)
{
	static_cast<void>( workspace) ;
	contents = {} ;
	// file未選択またはsession未発行の要求を架空の検証成功へ変換しない。
	if( selectedPath.empty() || scanSessionId == 0) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	OfficialInfPackage package ;	// Providerへ渡す署名検証済み相当の架空INF。
	package.infRelativePath		= L"fictional\\driver.inf" ;
	package.catalogRelativePath = L"fictional\\driver.cat" ;
	package.className			= L"Printer" ;
	package.providerName		= L"Fictional Printer Corporation" ;
	package.driverDate			= L"09/03/2026" ;
	package.driverVersion		= L"2.0.0.0" ;
	package.hardwareIds			= {L"USBPRINT\\FICTIONAL_PRINTER0001"} ;
	package.sourceFiles			= {L"fictional\\printer.gpd"} ;
	contents.archiveSha256		= std::wstring( 64U, L'a') ;
	contents.packages.push_back( std::move( package)) ;
	contents.verificationStage = UserSelectedInfPackageVerificationStage::COMPLETED ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空INFのinstall前再検証を成功させる。
 *
 * Constructor policyの必須関数を満たす。Installは実行しない。
 *
 * @param[in] workspace 本fakeでは参照しない保護領域。
 * @param[in] entries 本fakeでは参照しないentry群。
 * @param[in] expected Scan時の架空INF metadata。
 * @return 架空metadataが存在する場合は0。
 */
//------------------------------------------------------------------------------
NativeError reverifyFakePackage( const OfficialDownloadWorkspace		   &workspace,
								const std::span<const OfficialZipEntry> entries,
								const OfficialInfPackage			   &expected)
{
	static_cast<void>( workspace) ;
	static_cast<void>( entries) ;
	return expected.infRelativePath.empty() ? static_cast<NativeError>( E_INVALIDARG) : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空PnP IDの候補化を許可する。
 *
 * Providerのclass照合へ到達させるため内容を狭めない。
 *
 * @param[in] hardwareId Fake inspectorが返したPnP ID。
 * @return 空でない場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool allowFakeHardwareId( const std::wstring_view hardwareId) noexcept
{
	return !hardwareId.empty() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空汎用Provider policyを作成する。
 *
 * Class mode以外を同じ値にして境界だけを比較する。
 *
 * @param[in] usePackageClass INF由来classを使用する場合true。
 * @param[in] fixedClass 固定modeで対象にするsetup class。
 * @param[in] deviceClassMatches 追加class照合関数。空は完全一致。
 * @return Registry登録済みgeneric IDを持つ試験policy。
 */
//------------------------------------------------------------------------------
[[nodiscard]] UserSelectedInfProviderPolicy makeFakePolicy(
	const bool usePackageClass, const std::wstring_view fixedClass,
	UserSelectedDeviceClassMatcher deviceClassMatches = nullptr)
{
	return {.providerId						= std::wstring( GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID),
			.deviceClass					= std::wstring( fixedClass),
			.identityPrefix					= L"fake-candidate:",
			.packagePrefix					= L"fake-package:",
			.titlePrefix					= L"Fictional Driver ",
			.sourceName						= L"Fictional signed INF ZIP",
			.sourceLocation					= L"利用者選択local ZIP（取得元未証明）",
			.inspect						= inspectFakePrinterPackage,
			.reverify						= reverifyFakePackage,
			.hardwareIdAllowed				= allowFakeHardwareId,
			.deviceClassMatches				= deviceClassMatches,
			.allowMultiplePackagesPerDevice = true,
			.usePackageDeviceClass			= usePackageClass} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空generic Provider用scan設定を作成する。
 *
 * RegistryのProvider／file一対一検証も通過する値を返す。
 * @return Generic Providerと一件の架空ZIPを明示する設定。
 */
//------------------------------------------------------------------------------
[[nodiscard]] ScanOptions makeScanOptions()
{
	return {
		.useDefaultProviders = false,
		.enabledProviderIds	 = {std::wstring( GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID)},
		.userSelectedFiles	 = {{.providerId = std::wstring( GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID),
								 .path		 = L"C:\\Fictional\\driver-only.zip"}}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief INF由来classと現在deviceの完全一致を検証する。
 *
 * Printer INFをPrinter deviceだけへ候補化し、同じIDをPortsへ誤routingしないことを確認する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testPackageDeviceClass( TestContext &context)
{
	UserSelectedInfPackageProvider provider( makeFakePolicy( true, {})) ;	// 汎用class Provider。
	const ScanOptions			   options = makeScanOptions() ;			// 一件の架空入力。
	const std::array			   devices{
		  OfficialCatalogDevice{.deviceIdentity	 = L"device-printer",
											.model			 = L"Fictional Printer",
											.manufacturer	 = L"Fictional Corporation",
											.driverClass	 = L"Printer",
											.currentProvider = L"Fictional Corporation",
											.currentVersion	 = L"1.0.0.0"},
		  OfficialCatalogDevice{.deviceIdentity	 = L"device-ports",
											.model			 = L"Fictional Serial Adapter",
											.manufacturer	 = L"Fictional Corporation",
											.driverClass	 = L"Ports",
											.currentProvider = L"Fictional Corporation",
											.currentVersion = L"1.0.0.0"}} ;	// 異なるclassの現在device群。
	const LocalHardwareIdMatcher matcher =
		[]( const std::wstring_view hardwareId) -> std::optional<std::wstring> {
		return hardwareId == L"USBPRINT\\FICTIONAL_PRINTER0001"
				   ? std::optional<std::wstring>( L"device-printer")
				   : std::nullopt ;
	} ; // 架空IDをPrinter deviceだけへ解決するlocal matcher。
	std::uint32_t				   lastPercent{} ;	// Providerから最後に通知された確定進捗率。
	// 最終確定進捗を試験変数へ保持する同期callback。参照先は試験のscope内で有効。
	const ProviderProgressCallback progress = [&lastPercent]( const ProviderProgress &value) {
		lastPercent = value.percentComplete ;
	} ;
	const ScanResult result = provider.scan( 301, options, devices, matcher, progress) ;	// Scan結果。
	DRIVERCRATE_EXPECT( context, result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.coverage.eligibleDeviceCount == 1) ;
	DRIVERCRATE_EXPECT( context, result.coverage.assessedDeviceCount == 1) ;
	DRIVERCRATE_EXPECT( context, result.candidates.size() == 1) ;
	DRIVERCRATE_EXPECT( context, lastPercent == 100) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( !result.candidates.empty()) {
		const UpdateCandidate &candidate = result.candidates.front() ;	// 唯一のPrinter候補。
		DRIVERCRATE_EXPECT( context, candidate.deviceIdentity == L"device-printer") ;
		DRIVERCRATE_EXPECT( context, candidate.driverClass == L"Printer") ;
		DRIVERCRATE_EXPECT( context, candidate.provider == L"Fictional Printer Corporation") ;
		DRIVERCRATE_EXPECT( context, !candidate.recommended) ;
		DRIVERCRATE_EXPECT( context,
						   candidate.defaultPreference == CandidateDefaultPreference::NONE) ;
		DRIVERCRATE_EXPECT( context, candidate.audit.sourceOrigin ==
										CandidateAuditGateState::USER_PROVIDED_UNVERIFIED) ;
		DRIVERCRATE_EXPECT( context, candidate.audit.inspectionDownload ==
										CandidateAuditGateState::NOT_APPLICABLE) ;
		DRIVERCRATE_EXPECT( context,
						   candidate.audit.contentIntegrity == CandidateAuditGateState::PASSED) ;
		DRIVERCRATE_EXPECT( context, candidate.audit.systemApplicability ==
										CandidateAuditGateState::PROVIDER_VALIDATED) ;
		DRIVERCRATE_EXPECT( context, candidate.audit.installReadiness ==
										CandidateInstallReadiness::AUDIT_PENDING) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Printer INFからPrintQueueへの一方向照合を検証する。
 *
 * Generic Providerの限定class matcherがcoverage、PnP照合、最終candidate化のすべてで使用されることを確認する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testPackageDeviceClassMapping( TestContext &context)
{
	UserSelectedInfPackageProvider provider(
		// Printer限定class対応Provider。
		makeFakePolicy( true, {}, isGenericInfDeviceClassMatch)) ;
	const ScanOptions			 options = makeScanOptions() ;	// 一件の架空入力。
	const std::array			 devices{OfficialCatalogDevice{
					.deviceIdentity	 = L"device-print-queue",
					.model			 = L"Fictional Printer Queue",
					.manufacturer	 = L"Fictional Corporation",
					.driverClass	 = L"PrintQueue",
					.currentProvider = L"Fictional Corporation",
					.currentVersion	 = L"1.0.0.0"}} ;	// Printer INFとclass名が異なる現在device。
	const LocalHardwareIdMatcher matcher =
		[]( const std::wstring_view hardwareId) -> std::optional<std::wstring> {
		return hardwareId == L"USBPRINT\\FICTIONAL_PRINTER0001"
				   ? std::optional<std::wstring>( L"device-print-queue")
				   : std::nullopt ;
	} ; // PnP IDは従来どおり完全一致で解決するlocal matcher。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {
	} ; // 進捗値を破棄する非blocking callback。

	const ScanResult result = provider.scan( 305, options, devices, matcher, progress) ;	// Scan結果。
	DRIVERCRATE_EXPECT( context, result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.coverage.eligibleDeviceCount == 1) ;
	DRIVERCRATE_EXPECT( context, result.coverage.assessedDeviceCount == 1) ;
	DRIVERCRATE_EXPECT( context, result.candidates.size() == 1) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( !result.candidates.empty()) {
		const UpdateCandidate &candidate = result.candidates.front() ;	// 唯一のPrintQueue候補。
		DRIVERCRATE_EXPECT( context, candidate.deviceIdentity == L"device-print-queue") ;
		DRIVERCRATE_EXPECT( context, candidate.driverClass == L"PrintQueue") ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Class modeの矛盾とclass不一致を拒否する。
 *
 * 固定Ports policyへPrinter INFを注入しても候補化せず、汎用modeと固定classの同時指定をfile読込み前に拒否する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testClassPolicyRejections( TestContext &context)
{
	const ScanOptions			 options = makeScanOptions() ;	// 全caseで共用する架空入力。
	const std::array			 devices{OfficialCatalogDevice{
					.deviceIdentity	 = L"device-ports",
					.model			 = L"Fictional Serial Adapter",
					.manufacturer	 = L"Fictional Corporation",
					.driverClass	 = L"Ports",
					.currentProvider = L"Fictional Corporation",
					.currentVersion	 = L"1.0.0.0"}} ;	// 固定Ports policyだけが対象にするdevice。
	const LocalHardwareIdMatcher matcher =
		[]( const std::wstring_view) -> std::optional<std::wstring> {
		return std::wstring( L"device-ports") ;
	} ; // 同じPnP IDを意図的に別classへ解決するmatcher。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {
	} ; // 進捗値を破棄する非blocking callback。

	UserSelectedInfPackageProvider fixedProvider(
		// Printer INFと異なる固定class Provider。
		makeFakePolicy( false, L"Ports")) ;
	const ScanResult fixedResult =
		// 不一致scan結果。
		fixedProvider.scan( 302, options, devices, matcher, progress) ;
	DRIVERCRATE_EXPECT( context, fixedResult.succeeded) ;
	DRIVERCRATE_EXPECT( context, fixedResult.coverage.eligibleDeviceCount == 1) ;
	DRIVERCRATE_EXPECT( context, fixedResult.candidates.empty()) ;

	UserSelectedInfPackageProvider contradictoryProvider(
		// 二つのclass modeを同時指定した不正Provider。
		makeFakePolicy( true, L"Net")) ;
	const ScanResult contradictoryResult =
		// 拒否結果。
		contradictoryProvider.scan( 303, options, devices, matcher, progress) ;
	DRIVERCRATE_EXPECT( context, !contradictoryResult.succeeded) ;
	DRIVERCRATE_EXPECT( context,
					   contradictoryResult.error == static_cast<NativeError>( E_INVALIDARG)) ;

	UserSelectedInfPackageProvider missingClassProvider(
		// 固定classを欠落させた不正Provider。
		makeFakePolicy( false, {})) ;
	const ScanResult missingClassResult =
		// 拒否結果。
		missingClassProvider.scan( 304, options, devices, matcher, progress) ;
	DRIVERCRATE_EXPECT( context, !missingClassResult.succeeded) ;
	DRIVERCRATE_EXPECT( context, missingClassResult.error == static_cast<NativeError>( E_INVALIDARG)) ;

	UserSelectedInfPackageProvider fixedMatcherProvider( makeFakePolicy(
		false, L"Ports", isGenericInfDeviceClassMatch)) ;	// 固定modeで追加照合を指定。
	const ScanResult			   fixedMatcherResult =
		// 拒否結果。
		fixedMatcherProvider.scan( 306, options, devices, matcher, progress) ;
	DRIVERCRATE_EXPECT( context, !fixedMatcherResult.succeeded) ;
	DRIVERCRATE_EXPECT( context, fixedMatcherResult.error == static_cast<NativeError>( E_INVALIDARG)) ;
}

/**
 * @brief 共通Provider接続用の架空INF合格snapshotを一件生成する。
 * @param[in] scanSessionId 試験session。
 * @param[in] infRelativePath UIへ出してはならない架空INF相対path。
 * @param[in] driverVersion 架空INFの4要素version。
 * @param[in] hardwareId Local DBへ登録しない架空PnP ID。
 * @param[in] hasExternalDependencies 明示依存を未解決として保持する場合true。
 * @return 実fileや署名APIを使用しない個別合格snapshot。
 */
[[nodiscard]] CommonInfInspection makeFakeCommonInf( const ScanSessionId		scanSessionId,
													const std::wstring_view infRelativePath,
													const std::wstring_view driverVersion,
													const std::wstring_view hardwareId,
													const bool hasExternalDependencies = false)
{
	CommonInfInspection inf ;	// 実file／署名／PnP APIを呼ばない接続fixture。
	inf.scanSessionId	= scanSessionId ;
	inf.infRelativePath = infRelativePath ;
	inf.state			= CommonInfInspectionState::VERIFIED ;
	inf.workspace		= std::make_unique<OfficialDownloadWorkspace>() ;
	inf.closure.packages.push_back( {.infRelativePath		 = std::wstring( infRelativePath),
									.catalogRelativePath	 = L"fictional.cat",
									.className				 = L"Net",
									.providerName			 = L"Fictional",
									.driverDate				 = L"09/15/2026",
									.driverVersion			 = std::wstring( driverVersion),
									.hardwareIds			 = {std::wstring( hardwareId)},
									.sourceFiles			 = {L"fictional.sys"},
									.hasExternalDependencies = hasExternalDependencies}) ;
	return inf ;
}

/**
 * @brief 共通Provider接続だけに使う架空の内容合格snapshotを生成する。
 * @param[in] selectedPath 架空入力の非空path。
 * @param[in] scanSessionId 試験session。
 * @param[in,out] workspace 本fakeでは未使用の所有領域。
 * @param[out] contents 試験だけで生成する個別合格snapshot。
 * @return 正規の試験要求では0、それ以外はE_INVALIDARG。
 */
NativeError inspectFakeCommonPackage( const std::wstring_view		 selectedPath,
									 const ScanSessionId			 scanSessionId,
									 OfficialDownloadWorkspace		&workspace,
									 UserSelectedInfPackageContents &contents)
{
	static_cast<void>( workspace) ;
	contents = {} ;
	// 無効入力をfakeの成功経路へ通さない。
	if( selectedPath.empty() || scanSessionId == 0) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	auto inspection = std::make_unique<CommonDriverPackageInspection>() ;	// 試験用だけの所有結果。
	inspection->scanSessionId = scanSessionId ;
	inspection->archiveSha256.assign( 64U, L'a') ;
	inspection->archiveBytes = 12U ;
	CommonInfInspection inf ;	// 実file／署名／PnP APIを呼ばない接続fixture。
	inf.scanSessionId = scanSessionId ;
	inf.state		  = CommonInfInspectionState::VERIFIED ;
	inf.workspace	  = std::make_unique<OfficialDownloadWorkspace>() ;
	inf.closure.packages.push_back( {.infRelativePath	 = L"fictional.inf",
									.catalogRelativePath = L"fictional.cat",
									.className			 = L"Net",
									.providerName		 = L"Fictional",
									.driverDate			 = L"09/15/2026",
									.driverVersion		 = L"2.0.0.0",
									.hardwareIds		 = {L"PCI\\VEN_1234&DEV_9876"},
									.sourceFiles		 = {L"fictional.sys"}}) ;
	inspection->infs.push_back( std::move( inf)) ;
	contents.commonInspection = std::move( inspection) ;
	return 0 ;
}

/**
 * @brief 改名・別directoryの二INFを同じ外側packageの個別結果として返す。
 * @param[in] selectedPath 架空入力の非空path。
 * @param[in] scanSessionId 試験session。
 * @param[in,out] workspace 本fakeでは未使用の所有領域。
 * @param[out] contents 試験だけで生成する二つの個別合格snapshot。
 * @return 正規の試験要求では0、それ以外はE_INVALIDARG。
 */
NativeError inspectFakeMultipleCommonPackage( const std::wstring_view		 selectedPath,
											 const ScanSessionId			 scanSessionId,
											 OfficialDownloadWorkspace		&workspace,
											 UserSelectedInfPackageContents &contents)
{
	static_cast<void>( workspace) ;
	contents = {} ;
	// 無効入力をfakeの成功経路へ通さない。
	if( selectedPath.empty() || scanSessionId == 0) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	auto inspection = std::make_unique<CommonDriverPackageInspection>() ;	// 同じ外側archiveの結果。
	inspection->scanSessionId = scanSessionId ;
	inspection->archiveSha256.assign( 64U, L'b') ;
	inspection->archiveBytes = 24U ;
	inspection->infs.push_back( makeFakeCommonInf( scanSessionId, L"renamed\\net_main_renamed.inf",
												 L"2.0.0.0", L"PCI\\VEN_4321&DEV_1000")) ;
	inspection->infs.push_back( makeFakeCommonInf( scanSessionId, L"alternate\\auxiliary_driver.inf",
												 L"2.1.0.0", L"PCI\\VEN_4321&DEV_1001", true)) ;
	contents.commonInspection = std::move( inspection) ;
	return 0 ;
}

/**
 * @brief 一INFの個別署名拒否と別INFの合格を同じpackage結果として返す。
 * @param[in] selectedPath 架空入力の非空path。
 * @param[in] scanSessionId 試験session。
 * @param[in,out] workspace 本fakeでは未使用の所有領域。
 * @param[out] contents 個別拒否と合格を保持するsnapshot。
 * @return 正規の試験要求では0、それ以外はE_INVALIDARG。
 */
NativeError inspectFakePartialCommonPackage( const std::wstring_view			selectedPath,
											const ScanSessionId				scanSessionId,
											OfficialDownloadWorkspace	   &workspace,
											UserSelectedInfPackageContents &contents)
{
	const NativeError error = inspectFakeMultipleCommonPackage(
		selectedPath, scanSessionId, workspace, contents) ;	// 有効な二INFの基礎fixture。
	// 基礎fixtureの失敗や所有結果の欠落を改変しない。
	if( error != 0 || !contents.commonInspection || contents.commonInspection->infs.size() != 2U) {
		return error != 0 ? error : static_cast<NativeError>( E_UNEXPECTED) ;
	}

	CommonInfInspection &rejected =
		// 一件目だけの署名拒否。
		contents.commonInspection->infs.front() ;
	rejected.state = CommonInfInspectionState::SIGNATURE_REJECTED ;
	rejected.error = static_cast<NativeError>( E_ACCESSDENIED) ;
	rejected.workspace.reset() ;
	rejected.closure = {} ;
	return 0 ;
}

/**
 * @brief 名称・現在版欠損と同一packageの複数portを共通Providerから候補化する。
 * @param[in,out] context Assertion集計先。
 */
void testCommonProviderConnection( TestContext &context)
{
	UserSelectedInfProviderPolicy policy = makeFakePolicy( true, {}) ;	// 対象名で狭めない共通条件。
	policy.useCommonInspection			 = true ;
	policy.inspect						 = inspectFakeCommonPackage ;
	UserSelectedInfPackageProvider		 provider( std::move( policy)) ;	// 接続試験だけのProvider。
	std::array<OfficialCatalogDevice, 3> devices ;							// 名前・版・classを意図的に持たないdevice群。
	devices[0].deviceIdentity = L"device:common:port0" ;
	devices[1].deviceIdentity = L"device:common:port1" ;
	devices[2].deviceIdentity = L"device:common:unmatched" ;
	DeviceObservation observation ;	// WindowsのCode 28を模した未導入の正例。
	observation.scanSessionId	 = 501U ;
	observation.deviceIdentity	 = devices[1].deviceIdentity ;
	observation.driverPresence	 = DeviceDriverPresence::NOT_INSTALLED ;
	observation.node.read.state	 = DevicePropertyReadState::VALUE ;
	observation.node.statusFlags = 0x400U ;
	observation.node.problemCode = 28U ;
	devices[1].deviceObservation = observation ;
	std::size_t					 oldMatcherCalls{} ;	// 単一device matcherを使用しないことの確認。
	const LocalHardwareIdMatcher oldMatcher =
		[&oldMatcherCalls]( std::wstring_view) -> std::optional<std::wstring> {
		++oldMatcherCalls ;
		return std::nullopt ;
	} ; // 試験中のcounterを参照する。
	std::size_t					rankCalls{} ;	// 現在deviceごとの独立観測件数。
	const CommonInfRankObserver rankObserver =
		[&rankCalls]( const ScanSessionId session, const std::wstring_view device,
					 const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
					 std::optional<std::uint32_t> &rank) {
			static_cast<void>( workspace) ;
			++rankCalls ;
			rank.reset() ;
			// 固定sessionと架空package以外を成功へ変換しない。
			if( session != 501U || package.providerName != L"Fictional") {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			// 二つのportだけに同じWindows一致rankを返す。
			if( device == L"device:common:port0" || device == L"device:common:port1") {
				rank = 0x1000U ;
			}

			return NativeError{} ;
		} ; // 実Windowsへ作用しない差替え境界。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {} ;	// 同期の通知先。
	const ScanResult result = provider.scan( 501U, makeScanOptions(), devices, oldMatcher, progress,
											rankObserver) ;	// 通常scan APIから共通処理へ接続する。
	DRIVERCRATE_EXPECT( context, result.succeeded && result.candidates.size() == 2U) ;
	DRIVERCRATE_EXPECT( context, rankCalls == 3U && oldMatcherCalls == 0U) ;
	DRIVERCRATE_EXPECT( context, result.coverage.eligibleDeviceCount == 3U &&
									result.coverage.assessedDeviceCount == 3U) ;
	// 二つの候補を得た場合だけ、package共有と独立action・詳細を確認する。
	if( result.candidates.size() == 2U) {
		DRIVERCRATE_EXPECT( context, result.candidates[0].packageIdentity ==
										result.candidates[1].packageIdentity) ;
		DRIVERCRATE_EXPECT( context, result.candidates[0].identity != result.candidates[1].identity) ;
		DRIVERCRATE_EXPECT( context, result.candidates[0].action == DriverAction::NONE) ;
		DRIVERCRATE_EXPECT( context, result.candidates[1].action == DriverAction::INITIAL_INSTALL) ;
		const auto descriptors = builtInProviderDescriptors() ;	// 正本registryの非所有view。
		const auto found = std::ranges::find( descriptors, GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID,
											 &ProviderDescriptor::id) ;	// 共通Providerの登録位置。
		const ProviderDescriptor *descriptor =
			// 同じ信頼境界。
			found == descriptors.end() ? nullptr : &*found ;
		DRIVERCRATE_EXPECT( context, descriptor != nullptr) ;
		// 初回・不明の各候補に同じ詳細validatorを適用する。
		for( const UpdateCandidate &candidate : result.candidates) {
			DRIVERCRATE_EXPECT( context, !candidate.installable && !candidate.recommended) ;
			DRIVERCRATE_EXPECT( context, isCandidateDetailsValid( candidate, 501U)) ;
			DRIVERCRATE_EXPECT( context,
							   descriptor && isCandidateAuditValid( candidate, *descriptor)) ;
			DRIVERCRATE_EXPECT( context,
							   candidate.assessment && candidate.assessment->componentRole ==
														   CandidateComponentRole::BASE_DRIVER) ;
		}

		CandidateAssessment changed = *result.candidates.front().assessment ;	// 未知役割への改変。
		changed.componentRole		= static_cast<CandidateComponentRole>( 99) ;
		DRIVERCRATE_EXPECT( context, !isCandidateAssessmentValid( changed)) ;
	}

	devices[1].deviceObservation->scanSessionId = 500U ;
	rankCalls									= 0U ;
	const ScanResult stale = provider.scan( 501U, makeScanOptions(), devices, oldMatcher, progress,
										   rankObserver) ;	// 他session観測を拒否する。
	DRIVERCRATE_EXPECT( context, !stale.succeeded && stale.candidates.empty() && rankCalls == 0U) ;
	devices[1].deviceObservation->scanSessionId = 501U ;
	const CommonInfRankObserver throwing =
		[]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
		   const OfficialInfPackage &, std::optional<std::uint32_t> &) -> NativeError {
		throw std::runtime_error( "fixture observer") ;
	} ; // Provider境界の例外後始末を検証する。
	const ScanResult failed = provider.scan( 501U, makeScanOptions(), devices, oldMatcher, progress,
											throwing) ;	// Callback例外を通常の失敗へ変換する。
	DRIVERCRATE_EXPECT( context, !failed.succeeded && failed.candidates.empty() &&
									failed.error == static_cast<NativeError>( E_UNEXPECTED)) ;
	const ScanResult missing = provider.scan( 501U, makeScanOptions(), devices, oldMatcher,
											 progress) ;	// 共通観測なしで旧matcherへfallbackしない。
	DRIVERCRATE_EXPECT( context, !missing.succeeded && missing.candidates.empty()) ;
}

/**
 * @brief Local DB未登録の二INFと二portを、path非公開の独立候補へ展開する。
 * @param[in,out] context Assertion集計先。
 */
void testCommonMultipleInfAndPortIdentity( TestContext &context)
{
	UserSelectedInfProviderPolicy policy = makeFakePolicy( true, {}) ;	// 共通検査だけを使う条件。
	policy.useCommonInspection			 = true ;
	policy.inspect						 = inspectFakeMultipleCommonPackage ;
	UserSelectedInfPackageProvider		 provider( std::move( policy)) ;	// 架空の複数INF Provider。
	std::array<OfficialCatalogDevice, 2> devices ;							// Local DBに依存しない二port。
	devices[0].deviceIdentity = L"device:unregistered:port0" ;
	devices[1].deviceIdentity = L"device:unregistered:port1" ;
	std::size_t oldMatcherCalls{} ;	// Hardware ID DB型の旧matcherを使用しないことの確認。
	const LocalHardwareIdMatcher oldMatcher =
		[&oldMatcherCalls]( std::wstring_view) -> std::optional<std::wstring> {
		++oldMatcherCalls ;
		return std::nullopt ;
	} ; // 試験counterだけを借用する。
	std::size_t					rankCalls{} ;	// 二INFと二portの直積件数。
	const CommonInfRankObserver rankObserver =
		[&rankCalls]( const ScanSessionId session, const std::wstring_view		  device,
					 const OfficialDownloadWorkspace &, const OfficialInfPackage &package,
					 std::optional<std::uint32_t> &rank) {
			++rankCalls ;
			rank.reset() ;
			// Fixture外のsession、device、INFを成功へ通さない。
			if( session != 502U || !device.starts_with( L"device:unregistered:port") ||
			   (package.driverVersion != L"2.0.0.0" && package.driverVersion != L"2.1.0.0")) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			rank = 0x1000U ;
			return NativeError{} ;
		} ; // 実Windowsや実PnP IDを使用しない一致観測。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {} ;	// 同期の通知先。
	const ScanResult result = provider.scan( 502U, makeScanOptions(), devices, oldMatcher, progress,
											rankObserver) ;	// 通常scan API経由の複数展開。
	DRIVERCRATE_EXPECT( context, result.succeeded && result.error == 0) ;
	DRIVERCRATE_EXPECT( context, result.candidates.size() == 4U && rankCalls == 4U) ;
	DRIVERCRATE_EXPECT( context, oldMatcherCalls == 0U) ;
	std::unordered_set<std::wstring> candidateIdentities ;	// 行単位の一意性集合。
	std::unordered_set<std::wstring> packageIdentities ;	// INF単位の共有identity集合。
	// 全候補から非公開pathの漏えい、二port保持、八軸の有効性を確認する。
	for( const UpdateCandidate &candidate : result.candidates) {
		candidateIdentities.insert( candidate.identity) ;
		packageIdentities.insert( candidate.packageIdentity) ;
		DRIVERCRATE_EXPECT( context, candidate.title.find( L".inf") == std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context,
						   candidate.sourceLocation.find( L"renamed") == std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context,
						   candidate.sourceLocation.find( L"alternate") == std::wstring::npos) ;
		DRIVERCRATE_EXPECT( context, candidate.deviceIdentity == devices[0].deviceIdentity ||
										candidate.deviceIdentity == devices[1].deviceIdentity) ;
		DRIVERCRATE_EXPECT( context, candidate.assessment &&
										isCandidateAssessmentValid( *candidate.assessment)) ;
	}

	DRIVERCRATE_EXPECT( context, candidateIdentities.size() == 4U) ;
	DRIVERCRATE_EXPECT( context, packageIdentities.size() == 2U) ;
	// 候補順が成立する場合だけ、各INFの二portが同じpackageを共有することを確認する。
	if( result.candidates.size() == 4U) {
		DRIVERCRATE_EXPECT( context, result.candidates[0].packageIdentity ==
										result.candidates[1].packageIdentity) ;
		DRIVERCRATE_EXPECT( context, result.candidates[2].packageIdentity ==
										result.candidates[3].packageIdentity) ;
		DRIVERCRATE_EXPECT( context, result.candidates[0].packageIdentity !=
										result.candidates[2].packageIdentity) ;
		DRIVERCRATE_EXPECT( context, result.candidates[2].assessment->requirements.state ==
										CandidateAssessmentState::UNSUPPORTED) ;
	}
}

/**
 * @brief 版不明・同版・更新・旧版・未導入のaction分類と順位未確認を固定する。
 * @param[in,out] context Assertion集計先。
 */
void testCommonVersionActionsRemainDisplayOnly( TestContext &context)
{
	UserSelectedInfProviderPolicy policy = makeFakePolicy( true, {}) ;	// 共通検査だけを使う条件。
	policy.useCommonInspection			 = true ;
	policy.inspect						 = inspectFakeCommonPackage ;
	UserSelectedInfPackageProvider		 provider( std::move( policy)) ;	// 版分類を確認するProvider。
	std::array<OfficialCatalogDevice, 6> devices ;							// 版状態別の架空device。
	// 一意なopaque identityを割り当て、同じINFとのWindows一致だけを後段で模す。
	for( std::size_t index = 0; index < devices.size(); ++index) {
		devices[index].deviceIdentity = L"device:version:" + std::to_wstring( index) ;
	}

	devices[0].currentVersion = L"1.0.0.0" ;
	devices[1].currentVersion = L"2.0.0.0" ;
	devices[2].currentVersion = L"3.0.0.0" ;
	devices[3].currentVersion = {} ;
	devices[4].currentVersion = L"unknown" ;
	DeviceObservation notInstalled ;	// Code 28を伴う未導入の架空観測。
	notInstalled.scanSessionId				= 503U ;
	notInstalled.deviceIdentity				= devices[5].deviceIdentity ;
	notInstalled.driverPresence				= DeviceDriverPresence::NOT_INSTALLED ;
	notInstalled.node.read.state			= DevicePropertyReadState::VALUE ;
	notInstalled.node.statusFlags			= 0x400U ;
	notInstalled.node.problemCode			= 28U ;
	devices[5].deviceObservation			= notInstalled ;
	const LocalHardwareIdMatcher oldMatcher = []( std::wstring_view) -> std::optional<std::wstring> {
		return std::nullopt ;
	} ; // 未使用境界。
	const CommonInfRankObserver rankObserver =
		[]( const ScanSessionId session, const std::wstring_view			device,
		   const OfficialDownloadWorkspace &, const OfficialInfPackage &package,
		   std::optional<std::uint32_t> &rank) {
			rank.reset() ;
			// Fixture外の観測を合格へ変換しない。
			if( session != 503U || !device.starts_with( L"device:version:") ||
			   package.driverVersion != L"2.0.0.0") {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			rank = 0x2000U ;
			return NativeError{} ;
		} ; // 候補rankだけを返し、現在driverとの順位比較は行わない。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {} ;	// 同期の通知先。
	const ScanResult result = provider.scan( 503U, makeScanOptions(), devices, oldMatcher, progress,
											rankObserver) ;	// 六状態を一度に候補化する。
	constexpr std::array expectedActions{
		DriverAction::UPDATE, DriverAction::REINSTALL, DriverAction::DOWNGRADE,
		DriverAction::NONE,	  DriverAction::NONE,	   DriverAction::INITIAL_INSTALL} ;	// 期待分類。
	DRIVERCRATE_EXPECT( context,
					   result.succeeded && result.candidates.size() == expectedActions.size()) ;
	// 表示分類が成立しても、Windows優先順位とexecutorを推測で合格にしない。
	for( std::size_t index = 0; index < result.candidates.size(); ++index) {
		const UpdateCandidate &candidate = result.candidates[index] ;	// 現在の版状態に対応する行。
		DRIVERCRATE_EXPECT( context, candidate.action == expectedActions[index]) ;
		DRIVERCRATE_EXPECT( context, !candidate.installable && !candidate.recommended) ;
		DRIVERCRATE_EXPECT( context, candidate.assessment &&
										candidate.assessment->windowsSelection.state ==
											CandidateAssessmentState::NOT_CHECKED &&
										candidate.assessment->windowsSelection.reason ==
											CandidateAssessmentReason::RANK_UNVERIFIED) ;
	}
}

/**
 * @brief 一INFの内容拒否を別INFの表示候補と両立させ、全体成功へ誤変換しない。
 * @param[in,out] context Assertion集計先。
 */
void testCommonPartialContentRejection( TestContext &context)
{
	UserSelectedInfProviderPolicy policy = makeFakePolicy( true, {}) ;	// 個別拒否を返す共通条件。
	policy.useCommonInspection			 = true ;
	policy.inspect						 = inspectFakePartialCommonPackage ;
	UserSelectedInfPackageProvider provider( std::move( policy)) ;	// 部分結果を確認するProvider。
	std::array<OfficialCatalogDevice, 1> devices ;					// 合格INFへ一致する一device。
	devices[0].deviceIdentity				= L"device:partial:0" ;
	const LocalHardwareIdMatcher oldMatcher = []( std::wstring_view) -> std::optional<std::wstring> {
		return std::nullopt ;
	} ; // 未使用境界。
	std::size_t					rankCalls{} ;	// 拒否INFをWindowsへ渡さないことの確認。
	const CommonInfRankObserver rankObserver =
		[&rankCalls]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
					 const OfficialInfPackage &, std::optional<std::uint32_t> &rank) {
			++rankCalls ;
			rank = 0x1000U ;
			return NativeError{} ;
		} ; // 合格INFだけを一致させるfixture。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {} ;	// 同期の通知先。
	const ScanResult result = provider.scan( 504U, makeScanOptions(), devices, oldMatcher, progress,
											rankObserver) ;	// 個別拒否と一候補を結合する。
	DRIVERCRATE_EXPECT( context, result.succeeded && result.candidates.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, result.outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS &&
									result.state == ProviderScanState::CANDIDATES_AVAILABLE) ;
	DRIVERCRATE_EXPECT( context,
					   result.error == static_cast<NativeError>( E_ACCESSDENIED) && rankCalls == 1U) ;
	DRIVERCRATE_EXPECT( context, result.coverage.eligibleDeviceCount == 1U &&
									result.coverage.assessedDeviceCount == 0U) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/user_selected_inf_package_provider_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runUserSelectedInfPackageProviderTests( TestContext &context)
{
	testCommonPartialContentRejection( context) ;
	testCommonVersionActionsRemainDisplayOnly( context) ;
	testCommonMultipleInfAndPortIdentity( context) ;
	testCommonProviderConnection( context) ;
	DRIVERCRATE_EXPECT( context, isGenericInfCandidateHardwareId( L"PCI\\VEN_1234&DEV_5678")) ;
	DRIVERCRATE_EXPECT( context, !isGenericInfCandidateHardwareId( {})) ;
	testPackageDeviceClass( context) ;
	testPackageDeviceClassMapping( context) ;
	testClassPolicyRejections( context) ;
}

} // namespace drivercrate::test
