//------------------------------------------------------------------------------
/**
 * @file official_driver_package_tests.cpp
 * @brief 公式標準INF driver package単体試験実装。
 * @version 01.12.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  CAT member／PnP照合試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  DriverVer日付試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  汎用Provider名とscript拒否試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  SYS不要Printer INF試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  SYS不要WIA Image INF試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  圧縮実行program拒否試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Printer複合package拒否試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Firmware混入拒否試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Virtual audio拒否試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Virtual capture拒否試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Mobile flash payload拒否試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Virtual device境界試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  x64と異architectureの混在Models選択試験を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/04  空CoInstaller参照の限定受理と実動作・不正参照の拒否試験を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/05  保守参照の非承認・媒体path・CopyINF拒否境界を検証。
 * Ver.01.04.00 Shunji Ogawa  2026/10/05  保守の現在directory解決とtraversal維持を検証。
 * Ver.01.05.00 Shunji Ogawa  2026/10/05  空sourceの未署名拒否と通常導入policyの維持を検証。
 * Ver.01.06.00 Shunji Ogawa  2026/10/07  保守専用の全Models・null flagsと通常policy不変を回帰。
 * Ver.01.07.00 Shunji Ogawa  2026/10/07  明示seedの参照・有限依存抽出と旧caller非昇格を回帰。
 * Ver.01.08.00 Shunji Ogawa  2026/10/07  保守独立状態の共通射影と通常routeの隔離を回帰。
 * Ver.01.09.00 Shunji Ogawa  2026/10/07  空source・null参照の全選択と未知Class名policyを回帰。
 * Ver.01.10.00 Shunji Ogawa  2026/10/07  named必須構造・補助flagsと限定nullの分離を回帰。
 * Ver.01.11.00 Shunji Ogawa  2026/10/07  展開済みbinaryの明示named導入先・別名・不足と有限境界を回帰。
 * Ver.01.11.01 Shunji Ogawa  2026/10/07  named13の非absolute展開と媒体未宣言の元API診断・不足を回帰。
 * Ver.01.12.00 Shunji Ogawa  2026/10/07  一意な相対named13の元source正例とsource／copy／key／member衝突を回帰。
 * Ver.01.12.01 Shunji Ogawa  2026/10/24  必須解析に合わせ試験の所有・型・失敗制御を明示。
 * </pre>
 *
 * @note 実在するhardware IDや署名packageを使用せず、SetupAPIのINF構文とfail-closed条件を架空fixtureで検証します。
 */
//------------------------------------------------------------------------------

#include "official_driver_package_tests.h"

#include "platform/common_driver_package.h"
#include "platform/generic_inf_package.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_package.h"
#include "platform/official_file_verifier.h"
#include "test_framework.h"

#include <Windows.h>
#include <SetupAPI.h>
#include <miniz.h>

#include <array>
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {

// 保守の構造観測から導入型を暗黙構築できず、署名・bindingを迂回できない。
static_assert( !std::is_convertible_v<MaintenanceInfStructure, OfficialInfPackage>) ;
static_assert( !std::is_convertible_v<MaintenanceInfStructure, OfficialDriverClosure>) ;
static_assert( !std::is_convertible_v<MaintenanceInfStructure, CommonInfInspection>) ;
static_assert( !std::is_convertible_v<MaintenanceInfInspection, CommonInfInspection>) ;
static_assert( !std::is_convertible_v<MaintenanceInfReferences, OfficialInfPackage>) ;
static_assert( !std::is_convertible_v<MaintenanceDriverClosure, OfficialDriverClosure>) ;
static_assert( !std::is_constructible_v<CommonInfInspection, MaintenanceInfInspection>) ;
static_assert(
	!std::is_convertible_v<MaintenanceDriverPackageInspection, CommonDriverPackageInspection>) ;

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::array ACCEPTED_CLASSES{std::wstring_view( L"Net")} ;	// 試験で許可するclass。
constexpr std::array ACCEPTED_PRINTER_CLASS{						// SYS不要試験で許可するclass。
											std::wstring_view( L"Printer")} ;
constexpr std::array ACCEPTED_IMAGE_CLASS{	// WIA user-mode試験で許可するclass。
										  std::wstring_view( L"Image")} ;
constexpr std::array ACCEPTED_PROVIDERS{	// 許可する架空Provider。
										std::wstring_view( L"Fictional Wireless Corporation")} ;
constexpr std::array ACCEPTED_INF_SIGNATURES{	// 架空INFで許可するsignature。
											 std::wstring_view( L"$Windows NT$")} ;
constexpr std::array ACCEPTED_SIGNERS{	// 署名negative試験用allowlist。
									  std::wstring_view( L"Fictional Driver Signer")} ;
// 保守構造の架空Class。通常policyの許可集合とは独立する。
constexpr std::array MAINTENANCE_CLASSES{std::wstring_view( L"Ports"), std::wstring_view( L"System"),
										 std::wstring_view( L"MultiPortSerial")} ;
// 架空構造の有限policy。署名・実device・導入の成功を注入しない。
constexpr OfficialInfInspectionPolicy MAINTENANCE_POLICY{
	.maximumHardwareIds			= 16U,
	.maximumSourceFiles			= 16U,
	.acceptedClasses			= MAINTENANCE_CLASSES,
	.acceptedProviders			= ACCEPTED_PROVIDERS,
	.acceptedSignatures			= ACCEPTED_INF_SIGNATURES,
	.requireDriverBinary		= false,
	.rejectUnreferencedPrograms = false,
} ;

constexpr OfficialInfInspectionPolicy POLICY{
	.maximumHardwareIds = 16,
	.maximumSourceFiles = 16,
	.acceptedClasses	= ACCEPTED_CLASSES,
	.acceptedProviders	= ACCEPTED_PROVIDERS,
	.acceptedSignatures = ACCEPTED_INF_SIGNATURES,
} ; // 全正常fixtureに適用する有限policy。

constexpr std::string_view VALID_INF =
	"[Version]\r\n"
	"Signature=\"$Windows NT$\"\r\n"
	"Class=Net\r\n"
	"ClassGuid={4d36e972-e325-11ce-bfc1-08002be10318}\r\n"
	"Provider=%ProviderName%\r\n"
	"DriverVer=09/03/2026,1.2.3.4\r\n"
	"CatalogFile=sample.cat\r\n"
	"\r\n"
	"[Manufacturer]\r\n"
	"%ProviderName%=Models,NTamd64\r\n"
	"\r\n"
	"[Models.NTamd64]\r\n"
	"%DeviceName%=Install,PCI\\VEN_1234&DEV_5678,PCI\\VEN_1234\r\n"
	"\r\n"
	"[SourceDisksNames.amd64]\r\n"
	"1=%DiskName%,,,\r\n"
	"\r\n"
	"[SourceDisksFiles.amd64]\r\n"
	"sample.sys=1\r\n"
	"\r\n"
	"[Install.NT]\r\n"
	"CopyFiles=DriverCopy\r\n"
	"\r\n"
	"[DriverCopy]\r\n"
	"sample.sys\r\n"
	"\r\n"
	"[Strings]\r\n"
	"ProviderName=\"Fictional Wireless Corporation\"\r\n"
	"DeviceName=\"Fictional Wireless Adapter\"\r\n"
	"DiskName=\"Fictional Driver Disk\"\r\n" ;	// 正常な架空x64 network INF。

constexpr std::string_view PRINTER_INF =
	"[Version]\r\n"
	"Signature=\"$Windows NT$\"\r\n"
	"Class=Printer\r\n"
	"ClassGuid={4d36e979-e325-11ce-bfc1-08002be10318}\r\n"
	"Provider=%ProviderName%\r\n"
	"DriverVer=09/03/2026,5.6.7.8\r\n"
	"CatalogFile=printer.cat\r\n"
	"[Manufacturer]\r\n"
	"%ProviderName%=Models,NTamd64\r\n"
	"[Models.NTamd64]\r\n"
	"%DeviceName%=Install,USBPRINT\\FICTIONAL_PRINTER0001\r\n"
	"[SourceDisksNames.amd64]\r\n"
	"1=%DiskName%,,,\r\n"
	"[SourceDisksFiles.amd64]\r\n"
	"printer.gpd=1\r\n"
	"[Install.NT]\r\n"
	"CopyFiles=PrinterCopy\r\n"
	"[PrinterCopy]\r\n"
	"printer.gpd\r\n"
	"[Strings]\r\n"
	"ProviderName=\"Fictional Printer Corporation\"\r\n"
	"DeviceName=\"Fictional Printer\"\r\n"
	"DiskName=\"Fictional Printer Disk\"\r\n" ;	// SYSを持たない架空Printer INF。

constexpr std::string_view MIXED_PRINTER_INF =
	"[Version]\r\n"
	"Signature=\"$Windows NT$\"\r\n"
	"Class=Printer\r\n"
	"ClassGuid={4d36e979-e325-11ce-bfc1-08002be10318}\r\n"
	"Provider=%ProviderName%\r\n"
	"DriverVer=09/04/2026,5.6.7.9\r\n"
	"CatalogFile=printer.cat\r\n"
	"[Manufacturer]\r\n"
	"%ProviderName%=Models,NTamd64\r\n"
	"[Models.NTamd64]\r\n"
	"%DeviceName%=Install,USBPRINT\\FICTIONAL_PRINTER0002\r\n"
	"[SourceDisksNames.amd64]\r\n"
	"1=%DiskName%,,,\r\n"
	"[SourceDisksFiles.amd64]\r\n"
	"printer.gpd=1\r\n"
	"helper.exe=1\r\n"
	"resources.zip=1\r\n"
	"[Install.NT]\r\n"
	"CopyFiles=PrinterCopy\r\n"
	"[PrinterCopy]\r\n"
	"printer.gpd\r\n"
	"helper.exe\r\n"
	"resources.zip\r\n"
	"[Strings]\r\n"
	"ProviderName=\"Fictional Printer Corporation\"\r\n"
	"DeviceName=\"Fictional Mixed Printer\"\r\n"
	"DiskName=\"Fictional Printer Disk\"\r\n" ;	// 実行programを参照する架空Printer INF。

constexpr std::string_view IMAGE_INF =
	"[Version]\r\n"
	"Signature=\"$Windows NT$\"\r\n"
	"Class=Image\r\n"
	"ClassGuid={6bdd1fc6-810f-11d0-bec7-08002be2092f}\r\n"
	"Provider=%ProviderName%\r\n"
	"DriverVer=09/03/2026,9.8.7.6\r\n"
	"CatalogFile=scanner.cat\r\n"
	"[Manufacturer]\r\n"
	"%ProviderName%=Models,NTamd64\r\n"
	"[Models.NTamd64]\r\n"
	"%DeviceName%=Install,USB\\VID_1234&PID_5678\r\n"
	"[SourceDisksNames.amd64]\r\n"
	"1=%DiskName%,,,\r\n"
	"[SourceDisksFiles.amd64]\r\n"
	"scanner.dll=1\r\n"
	"[Install.NT]\r\n"
	"CopyFiles=ImageCopy\r\n"
	"[ImageCopy]\r\n"
	"scanner.dll\r\n"
	"[Strings]\r\n"
	"ProviderName=\"Fictional Imaging Corporation\"\r\n"
	"DeviceName=\"Fictional WIA Scanner\"\r\n"
	"DiskName=\"Fictional Scanner Disk\"\r\n" ;	// SYSなしの架空WIA Image INF。

constexpr std::string_view X86_ONLY_INF =
	"[Version]\r\n"
	"Signature=\"$Windows NT$\"\r\n"
	"Class=Net\r\n"
	"Provider=Fictional Wireless Corporation\r\n"
	"DriverVer=09/03/2026,1.2.3.4\r\n"
	"CatalogFile=sample.cat\r\n"
	"[Manufacturer]\r\n"
	"Fictional Wireless Corporation=Models,NTx86\r\n"
	"[Models.NTx86]\r\n"
	"Fictional Adapter=Install,PCI\\VEN_1234&DEV_5678\r\n"
	"[SourceDisksNames]\r\n"
	"1=Fictional Disk,,,\r\n"
	"[SourceDisksFiles]\r\n"
	"sample.sys=1\r\n" ;	// 現在x64ではModels sectionを選択できないINF。

constexpr std::string_view MIXED_ARCHITECTURE_INF =
	"[Version]\r\n"
	"Signature=\"$Windows NT$\"\r\n"
	"Class=Net\r\n"
	"Provider=Fictional Wireless Corporation\r\n"
	"DriverVer=09/15/2026,2.0.0.0\r\n"
	"CatalogFile=sample.cat\r\n"
	"[Manufacturer]\r\n"
	"Fictional Wireless Corporation=Models,NTamd64,NTx86\r\n"
	"[Models.NTamd64]\r\n"
	"Fictional x64 Adapter=Install,PCI\\VEN_4321&DEV_1000\r\n"
	"[Models.NTx86]\r\n"
	"Fictional x86 Adapter=Install,PCI\\VEN_4321&DEV_2000\r\n"
	"[SourceDisksNames.amd64]\r\n"
	"1=Fictional Disk,,,\r\n"
	"[SourceDisksFiles.amd64]\r\n"
	"sample.sys=1\r\n" ;	// 異architectureを含むがx64用Modelsを明示したINF。

constexpr std::string_view PROGRAM_INF =
	"[Version]\r\n"
	"Signature=\"$Windows NT$\"\r\n"
	"Class=Net\r\n"
	"Provider=Fictional Wireless Corporation\r\n"
	"DriverVer=09/03/2026,1.2.3.4\r\n"
	"CatalogFile=sample.cat\r\n"
	"[Manufacturer]\r\n"
	"Fictional Wireless Corporation=Models,NTamd64\r\n"
	"[Models.NTamd64]\r\n"
	"Fictional Adapter=Install,PCI\\VEN_1234&DEV_5678\r\n"
	"[SourceDisksNames.amd64]\r\n"
	"1=Fictional Disk,,,\r\n"
	"[SourceDisksFiles.amd64]\r\n"
	"sample.sys=1\r\n" ;	// 未参照programを同じarchiveへ混入する正常構造INF。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Workspaceへ一つの試験fileを書き込む。
 *
 * CREATE_NEWされたhandleを必ず閉じ、部分書込みを拒否する。
 *
 * @param[in,out] workspace Fileを作成し、scope終了時に削除する領域。
 * @param[in] relativePath 安全なASCII相対path。
 * @param[in] content Fileへ保存する全byte列。
 * @return 全byteを保存できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool writeWorkspaceFile( OfficialDownloadWorkspace &workspace,
									  const std::wstring_view	 relativePath,
									  const std::string_view	 content)
{
	// Win32書込み長の範囲を超えるfixtureは保存しない。
	if( content.size() > static_cast<std::size_t>( std::numeric_limits<DWORD>::max())) {
		return false ;
	}

	HANDLE file{INVALID_HANDLE_VALUE} ;	// 本関数がCloseHandleする所有file handle。
	// 保護領域でfileを作成できなければ書込みを開始しない。
	if( workspace.createFile( relativePath, file) != 0) {
		return false ;
	}

	DWORD	   written{} ;	// WriteFileが保存したbyte数。
	const bool result = WriteFile( file, content.data(), static_cast<DWORD>( content.size()),
								  &written, nullptr) != FALSE &&
						// 完全保存結果。
						written == content.size() ;
	CloseHandle( file) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正常な架空INF packageの構造検証を確認する。
 *
 * 現在x64用Models、文字列展開、PnP ID、CAT、SYS参照をSetupAPIから取得し、未署名CATは署名段階で拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testValidInfPackage( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// Scope終了時にfixtureを削除する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"inf-test", 101) == 0) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"valid\\sample.inf", VALID_INF)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"valid\\sample.cat", "not-signed")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"valid\\sample.sys", "driver")) ;

	const std::array entries{
		OfficialZipEntry{L"valid\\sample.inf", VALID_INF.size()},
		OfficialZipEntry{L"valid\\sample.cat", 10},
		OfficialZipEntry{L"valid\\sample.sys", 6},
	} ; // ZIP検証済みとして渡す正常file一覧。
	OfficialInfPackage package ;	// 検証成功時に設定される構造。
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"valid\\sample.inf",
														  POLICY, package) == 0) ;
	DRIVERCRATE_EXPECT( context, package.className == L"Net") ;
	DRIVERCRATE_EXPECT( context, package.providerName == L"Fictional Wireless Corporation") ;
	DRIVERCRATE_EXPECT( context, package.driverDate == L"09/03/2026") ;
	DRIVERCRATE_EXPECT( context, package.driverVersion == L"1.2.3.4") ;
	DRIVERCRATE_EXPECT( context, package.catalogRelativePath == L"valid\\sample.cat") ;
	DRIVERCRATE_EXPECT( context, package.hardwareIds.size() == 2) ;
	DRIVERCRATE_EXPECT( context, package.sourceFiles.size() == 1) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( !package.sourceFiles.empty()) {
		DRIVERCRATE_EXPECT( context, package.sourceFiles[0] == L"valid\\sample.sys") ;
	}

	DRIVERCRATE_EXPECT(
		context, verifyOfficialInfCatalogSignature( workspace, package, ACCEPTED_SIGNERS) != 0) ;
	DRIVERCRATE_EXPECT(
		context, verifyOfficialInfPackageIntegrity( workspace, package, ACCEPTED_SIGNERS) != 0) ;

	const std::array memberPaths{
		workspace.path( L"valid\\sample.inf"),
		workspace.path( L"valid\\sample.sys"),
	} ; // 未署名CATのmemberとして拒否される実在fixture path群。
	DRIVERCRATE_EXPECT( context, verifyOfficialCatalogMembers( workspace.path( L"valid\\sample.cat"),
															 memberPaths) != 0) ;
	const std::span<const std::wstring> noMembers ;	// 空入力を拒否するためのmember span。
	DRIVERCRATE_EXPECT( context, verifyOfficialCatalogMembers( workspace.path( L"valid\\sample.cat"),
															 noMembers) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief SYS不要Printer INFの限定受理を確認する。
 *
 * Printer policyだけがCAT保護対象のGPDを持つINFを受理し、他class、実行program、archive、firmwareへ拡張しない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testPrinterInfWithoutSys( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// SYS不要fixtureを所有する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"printer-inf-test", 106) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   writeWorkspaceFile( workspace, L"printer\\printer.inf", PRINTER_INF)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"printer\\printer.cat", "catalog")) ;
	DRIVERCRATE_EXPECT( context,
					   writeWorkspaceFile( workspace, L"printer\\printer.gpd", "print-data")) ;

	const std::array entries{
		OfficialZipEntry{L"printer\\printer.inf", PRINTER_INF.size()},
		OfficialZipEntry{L"printer\\printer.cat", 7},
		OfficialZipEntry{L"printer\\printer.gpd", 10},
	} ; // SYSを持たないPrinter packageの検証済みentry群。
	OfficialInfInspectionPolicy printerPolicy = POLICY ;	// Printer限定の構造policy。
	printerPolicy.acceptedClasses			  = ACCEPTED_PRINTER_CLASS ;
	printerPolicy.acceptedProviders			  = {} ;
	printerPolicy.acceptAnyProvider			  = true ;
	printerPolicy.requireDriverBinary		  = false ;
	OfficialInfPackage package ;	// 検証成功時のPrinter metadata。
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, entries, L"printer\\printer.inf",
												 printerPolicy, package) == 0) ;
	DRIVERCRATE_EXPECT( context, package.className == L"Printer") ;
	DRIVERCRATE_EXPECT( context, package.sourceFiles.size() == 1) ;
	DRIVERCRATE_EXPECT( context, isGenericInfPackageSupported( package)) ;
	DRIVERCRATE_EXPECT( context, isGenericInfDeviceClassMatch( L"Printer", L"Printer")) ;
	DRIVERCRATE_EXPECT( context, isGenericInfDeviceClassMatch( L"Printer", L"PrintQueue")) ;
	DRIVERCRATE_EXPECT( context, !isGenericInfDeviceClassMatch( L"Net", L"PrintQueue")) ;
	DRIVERCRATE_EXPECT( context, !isGenericInfDeviceClassMatch( L"PrintQueue", L"Printer")) ;
	const OfficialInfPackage	printerPackage = package ;	// 後続negative試験後の復元用metadata。

	OfficialInfInspectionPolicy sysRequiredPolicy = printerPolicy ;	// 従来のSYS必須policy。
	sysRequiredPolicy.requireDriverBinary		  = true ;
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, entries, L"printer\\printer.inf",
												 sysRequiredPolicy, package) != 0) ;

	package			  = printerPackage ;
	package.className = L"Net" ;
	DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;
	package.sourceFiles.push_back( L"printer\\driver.sys") ;
	DRIVERCRATE_EXPECT( context, isGenericInfPackageSupported( package)) ;

	package = printerPackage ;
	package.sourceFiles.push_back( L"printer\\resources.zip") ;
	DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;
	package.sourceFiles.back() = L"printer\\resources.cab" ;
	DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;
	package.sourceFiles.back() = L"printer\\device_firmware.bin" ;
	DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;
	package.sourceFiles.back() = L"printer\\device_firmware.dfu" ;
	DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;
	const std::array nestedReverifyEntries{
		OfficialZipEntry{L"printer\\resources.zip", 7},
	} ; // Install直前に拒否する内側archive entry。
	DRIVERCRATE_EXPECT(
		context, reverifyGenericInfPackage( workspace, nestedReverifyEntries, printerPackage) != 0) ;
	const std::array firmwareReverifyEntries{
		OfficialZipEntry{L"printer\\device_firmware.bin", 7},
	} ; // Install直前に拒否するfirmware image entry。
	DRIVERCRATE_EXPECT( context, reverifyGenericInfPackage( workspace, firmwareReverifyEntries,
														  printerPackage) != 0) ;

	DRIVERCRATE_EXPECT(
		context, writeWorkspaceFile( workspace, L"mixed-printer\\printer.inf", MIXED_PRINTER_INF)) ;
	DRIVERCRATE_EXPECT( context,
					   writeWorkspaceFile( workspace, L"mixed-printer\\printer.cat", "catalog")) ;
	DRIVERCRATE_EXPECT( context,
					   writeWorkspaceFile( workspace, L"mixed-printer\\printer.gpd", "print-data")) ;
	DRIVERCRATE_EXPECT( context,
					   writeWorkspaceFile( workspace, L"mixed-printer\\helper.exe", "program")) ;
	DRIVERCRATE_EXPECT( context,
					   writeWorkspaceFile( workspace, L"mixed-printer\\resources.zip", "archive")) ;
	const std::array mixedEntries{
		OfficialZipEntry{L"mixed-printer\\printer.inf", MIXED_PRINTER_INF.size()},
		OfficialZipEntry{L"mixed-printer\\printer.cat", 7},
		OfficialZipEntry{L"mixed-printer\\printer.gpd", 10},
		OfficialZipEntry{L"mixed-printer\\helper.exe", 7},
		OfficialZipEntry{L"mixed-printer\\resources.zip", 7},
	} ; // 実行programとnested archiveをINFが参照する複合Printer entry群。
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, mixedEntries,
														  L"mixed-printer\\printer.inf",
														  printerPolicy, package) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 汎用INFのsoftware device境界を確認する。
 *
 * 物理device用INFを維持し、software enumeratorの全許可classを別capabilityの設計完了まで拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testGenericSoftwareDeviceBoundary( TestContext &context)
{
	OfficialInfPackage package{
		.className	   = L"MEDIA",
		.providerName  = L"Fictional Professional Audio Corporation",
		.driverVersion = L"1.2.3.4",
		.hardwareIds   = {L"USB\\VID_1234&PID_5678"},
		.sourceFiles   = {L"audio\\fictional_audio.sys"},
	} ; // 汎用AV境界だけを検証する架空driver package。
	DRIVERCRATE_EXPECT( context, isGenericInfPackageSupported( package)) ;

	package.className	= L"Camera" ;
	package.sourceFiles = {L"capture\\fictional_camera.sys"} ;
	DRIVERCRATE_EXPECT( context, isGenericInfPackageSupported( package)) ;
	package.className	= L"Image" ;
	package.sourceFiles = {L"capture\\fictional_image.sys"} ;
	DRIVERCRATE_EXPECT( context, isGenericInfPackageSupported( package)) ;

	package.className	= L"MEDIA" ;
	package.hardwareIds = {L"ROOT\\FICTIONAL_VIRTUAL_AUDIO"} ;
	DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;
	package.className	= L"Camera" ;
	package.hardwareIds = {L"swd\\FICTIONAL_VIRTUAL_CAMERA"} ;
	DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;
	package.className	= L"Image" ;
	package.hardwareIds = {L"HTREE\\FICTIONAL_CAPTURE_ROOT"} ;
	DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;
	package.className	= L"MEDIA" ;
	package.hardwareIds = {L"UMB\\FICTIONAL_AUDIO_BUS"} ;
	DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;

	package.className	= L"Net" ;
	package.sourceFiles = {L"network\\fictional_network.sys"} ;
	package.hardwareIds = {L"ROOT\\FICTIONAL_VIRTUAL_NETWORK"} ;
	DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;
	package.className	= L"Display" ;
	package.sourceFiles = {L"display\\fictional_display.sys"} ;
	package.hardwareIds = {L"SWD\\FICTIONAL_VIRTUAL_DISPLAY"} ;
	DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;
	package.className	= L"HIDClass" ;
	package.sourceFiles = {L"input\\fictional_input.sys"} ;
	package.hardwareIds = {L"HTREE\\FICTIONAL_VIRTUAL_INPUT"} ;
	DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;
	package.className	= L"USBDevice" ;
	package.sourceFiles = {L"usb\\fictional_usb.sys"} ;
	package.hardwareIds = {L"UMB\\FICTIONAL_VIRTUAL_USB"} ;
	DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;

	package.className	= L"Net" ;
	package.sourceFiles = {L"network\\fictional_network.sys"} ;
	package.hardwareIds = {L"PCI\\VEN_1234&DEV_5678"} ;
	DRIVERCRATE_EXPECT( context, isGenericInfPackageSupported( package)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Virtual machine payloadの汎用経路拒否を確認する。
 *
 * Driver ZIPへ混在するvirtual disk／appliance imageをscan時とinstall直前の両方でfail-closedに拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testGenericVirtualMachinePayloadRejection( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// Install直前再検証の保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"virtual-payload-test", 109) == 0) ;
	OfficialInfPackage package{
		.className	   = L"Net",
		.providerName  = L"Fictional Virtual Device Corporation",
		.driverVersion = L"1.2.3.4",
		.hardwareIds   = {L"PCI\\VEN_1234&DEV_5678"},
		.sourceFiles   = {L"network\\fictional_network.sys"},
	} ; // Virtual machine payload境界だけを検証する架空package。
	constexpr std::array VIRTUAL_PAYLOAD_EXTENSIONS{
		std::wstring_view( L".ova"), std::wstring_view( L".ovf"), std::wstring_view( L".qcow"),
		std::wstring_view( L".qcow2"), std::wstring_view( L".vfd"), std::wstring_view( L".vhd"),
		// 拒否を要求するvirtual
		std::wstring_view( L".vhdx"), std::wstring_view( L".vmdk")} ;
	// payload拡張子。
	// 各拡張子を同じ架空packageへ一つずつ混在させ、全形式を有限回検証する。
	for( const std::wstring_view extension : VIRTUAL_PAYLOAD_EXTENSIONS) {
		std::wstring payloadPath = L"virtual\\guest_image" ;	// 現在の架空payload path。
		payloadPath.append( extension) ;
		package.sourceFiles = {L"network\\fictional_network.sys", payloadPath} ;
		DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;

		const std::array entries{
			OfficialZipEntry{payloadPath, 7},
		} ; // Scan後に混入した現在形式の架空entry。
		DRIVERCRATE_EXPECT( context, reverifyGenericInfPackage( workspace, entries, package) != 0) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Mobile flash payloadの汎用経路拒否を確認する。
 *
 * USB driverと同梱されたmobile firmware／flash imageをscan時とinstall直前の両方でfail-closedに拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testGenericMobileFlashPayloadRejection( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// Install直前再検証の保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"mobile-flash-test", 108) == 0) ;
	OfficialInfPackage package{
		.className	   = L"USBDevice",
		.providerName  = L"Fictional Mobile Device Corporation",
		.driverVersion = L"1.2.3.4",
		.hardwareIds   = {L"USB\\VID_1234&PID_5678"},
		.sourceFiles   = {L"mobile\\fictional_usb.sys"},
	} ; // Mobile USB driver境界だけを検証する架空package。
	constexpr std::array MOBILE_FLASH_EXTENSIONS{
		std::wstring_view( L".elf"), std::wstring_view( L".ftf"), std::wstring_view( L".img"),
		std::wstring_view( L".kdz"), std::wstring_view( L".mbn"), std::wstring_view( L".ofp"),
		std::wstring_view( L".pac"), std::wstring_view( L".pit"), std::wstring_view( L".sin"),
		// 拒否を要求するmobile flash拡張子。
		std::wstring_view( L".tot")} ;
	// 各拡張子を同じ架空packageへ一つずつ混在させ、全形式を有限回検証する。
	for( const std::wstring_view extension : MOBILE_FLASH_EXTENSIONS) {
		std::wstring payloadPath = L"mobile\\device_firmware" ;	// 現在の架空payload path。
		payloadPath.append( extension) ;
		package.sourceFiles = {L"mobile\\fictional_usb.sys", payloadPath} ;
		DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;

		const std::array entries{
			OfficialZipEntry{payloadPath, 7},
		} ; // Scan後に混入した現在形式の架空entry。
		DRIVERCRATE_EXPECT( context, reverifyGenericInfPackage( workspace, entries, package) != 0) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief SYS不要WIA Image INFの限定受理を確認する。
 *
 * CAT保護対象のvendor DLLを持つImage INFだけを受理し、DLLを持たない同classや他classへ条件を拡張しない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testWiaImageInfWithoutSys( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// SYS不要WIA fixtureを所有する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"wia-image-inf-test", 107) == 0) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"scanner\\scanner.inf", IMAGE_INF)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"scanner\\scanner.cat", "catalog")) ;
	DRIVERCRATE_EXPECT( context,
					   writeWorkspaceFile( workspace, L"scanner\\scanner.dll", "image-driver")) ;

	const std::array entries{
		OfficialZipEntry{L"scanner\\scanner.inf", IMAGE_INF.size()},
		OfficialZipEntry{L"scanner\\scanner.cat", 7},
		OfficialZipEntry{L"scanner\\scanner.dll", 12},
	} ; // SYSを持たないWIA user-mode packageの検証済みentry群。
	OfficialInfInspectionPolicy imagePolicy = POLICY ;	// Image限定の構造policy。
	imagePolicy.acceptedClasses				= ACCEPTED_IMAGE_CLASS ;
	imagePolicy.acceptedProviders			= {} ;
	imagePolicy.acceptAnyProvider			= true ;
	imagePolicy.requireDriverBinary			= false ;
	OfficialInfPackage package ;	// 検証成功時のWIA metadata。
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, entries, L"scanner\\scanner.inf",
												 imagePolicy, package) == 0) ;
	DRIVERCRATE_EXPECT( context, package.className == L"Image") ;
	DRIVERCRATE_EXPECT( context, package.sourceFiles.size() == 1) ;
	DRIVERCRATE_EXPECT( context, isGenericInfPackageSupported( package)) ;
	const OfficialInfPackage	imagePackage = package ;	// 後続negative試験後の復元用metadata。

	OfficialInfInspectionPolicy sysRequiredPolicy = imagePolicy ;	// 従来のSYS必須policy。
	sysRequiredPolicy.requireDriverBinary		  = true ;
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, entries, L"scanner\\scanner.inf",
												 sysRequiredPolicy, package) != 0) ;

	package				= imagePackage ;
	package.className	= L"Image" ;
	package.sourceFiles = {L"scanner\\scanner.gpd"} ;
	DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;
	package.className	= L"Camera" ;
	package.sourceFiles = {L"scanner\\scanner.dll"} ;
	DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;
	package.sourceFiles.push_back( L"scanner\\camera.sys") ;
	DRIVERCRATE_EXPECT( context, isGenericInfPackageSupported( package)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Policyと参照fileのfail-closed条件を確認する。
 *
 * Provider不一致、PnP ID上限、CAT欠落、参照SYS欠落をcandidateへ公開せず拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testInfPolicyRejections( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 複数negative fixtureを所有する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"inf-test", 102) == 0) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"policy\\sample.inf", VALID_INF)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"policy\\sample.cat", "catalog")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"policy\\sample.sys", "driver")) ;
	const std::array entries{
		OfficialZipEntry{L"policy\\sample.inf", VALID_INF.size()},
		OfficialZipEntry{L"policy\\sample.cat", 7},
		OfficialZipEntry{L"policy\\sample.sys", 6},
	} ; // 正常fileを含むZIP entry群。
	// INF publisherとの不一致を再現する、許可publisher集合。
	constexpr std::array		WRONG_PROVIDERS{std::wstring_view( L"Another Corporation")} ;
	OfficialInfInspectionPolicy wrongProviderPolicy = POLICY ;	// Provider不一致policy。
	wrongProviderPolicy.acceptedProviders			= WRONG_PROVIDERS ;
	OfficialInfPackage package ;	// 失敗時に空へ戻される出力。
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"policy\\sample.inf",
														  wrongProviderPolicy, package) != 0) ;
	DRIVERCRATE_EXPECT( context, package.infRelativePath.empty()) ;

	OfficialInfInspectionPolicy anyProviderPolicy = POLICY ;	// CAT保護名を許可する汎用policy。
	anyProviderPolicy.acceptedProviders			  = {} ;
	anyProviderPolicy.acceptAnyProvider			  = true ;
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"policy\\sample.inf",
														  anyProviderPolicy, package) == 0) ;
	DRIVERCRATE_EXPECT( context, package.providerName == L"Fictional Wireless Corporation") ;

	OfficialInfInspectionPolicy contradictoryPolicy = POLICY ;	// 二方式を併用する不正policy。
	contradictoryPolicy.acceptAnyProvider			= true ;
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"policy\\sample.inf",
														  contradictoryPolicy, package) != 0) ;

	OfficialInfInspectionPolicy missingProviderPolicy = POLICY ;	// 固定allowlist欠落policy。
	missingProviderPolicy.acceptedProviders			  = {} ;
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"policy\\sample.inf",
														  missingProviderPolicy, package) != 0) ;

	OfficialInfInspectionPolicy idLimitPolicy = POLICY ;	// ID上限を一件にしたpolicy。
	idLimitPolicy.maximumHardwareIds		  = 1 ;
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"policy\\sample.inf",
														  idLimitPolicy, package) != 0) ;

	const std::array missingCatalogEntries{
		OfficialZipEntry{L"policy\\sample.inf", VALID_INF.size()},
		OfficialZipEntry{L"policy\\sample.sys", 6},
	} ; // CATを意図的に除外したentry群。
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, missingCatalogEntries,
												 L"policy\\sample.inf", POLICY, package) != 0) ;

	const std::array missingDriverEntries{
		OfficialZipEntry{L"policy\\sample.inf", VALID_INF.size()},
		OfficialZipEntry{L"policy\\sample.cat", 7},
	} ; // INF参照SYSを意図的に除外したentry群。
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, missingDriverEntries,
												 L"policy\\sample.inf", POLICY, package) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief INF signatureをProvider固有allowlistで検証する。
 *
 * Prolific等の署名済みWin4 INFで使われる`$CHICAGO$`を、明示allowlistの場合だけ受理することを確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testInfSignaturePolicy( TestContext &context)
{
	std::string				   chicagoInf( VALID_INF) ;				// Signatureだけを変更する架空INF。
	constexpr std::string_view WINDOWS_SIGNATURE = "$Windows NT$" ;	// 置換前signature。
	constexpr std::string_view CHICAGO_SIGNATURE = "$CHICAGO$" ;	// Providerが明示するsignature。
	const std::size_t		   signaturePosition =
		// 固定fixture内の置換位置。
		chicagoInf.find( WINDOWS_SIGNATURE) ;
	DRIVERCRATE_EXPECT( context, signaturePosition != std::string::npos) ;
	// INF署名指定が見つからない場合は範囲外編集をせず検証を中止する。
	if( signaturePosition == std::string::npos) {
		return ;
	}

	chicagoInf.replace( signaturePosition, WINDOWS_SIGNATURE.size(), CHICAGO_SIGNATURE) ;

	OfficialDownloadWorkspace workspace ;	// Scope終了時にfixtureを削除する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"inf-test", 105) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   writeWorkspaceFile( workspace, L"signature\\sample.inf", chicagoInf)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"signature\\sample.cat", "catalog")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"signature\\sample.sys", "driver")) ;
	const std::array entries{
		OfficialZipEntry{L"signature\\sample.inf", chicagoInf.size()},
		OfficialZipEntry{L"signature\\sample.cat", 7},
		OfficialZipEntry{L"signature\\sample.sys", 6},
	} ; // CHICAGO signature fixtureのZIP entry群。
	constexpr std::array		CHICAGO_SIGNATURES{	// この試験で明示的に許可するsignature。
											   std::wstring_view( L"$CHICAGO$")} ;
	OfficialInfInspectionPolicy chicagoPolicy = POLICY ;	// CHICAGOだけを許可するpolicy。
	chicagoPolicy.acceptedSignatures		  = CHICAGO_SIGNATURES ;
	OfficialInfPackage package ;	// 成功時に設定され、拒否時に空へ戻る構造。
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, entries, L"signature\\sample.inf",
												 chicagoPolicy, package) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, entries, L"signature\\sample.inf",
												 POLICY, package) != 0) ;

	OfficialInfInspectionPolicy emptyPolicy = POLICY ;	// 空allowlistを拒否するpolicy。
	emptyPolicy.acceptedSignatures			= {} ;
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, entries, L"signature\\sample.inf",
												 emptyPolicy, package) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Architectureとprogram混入の拒否を確認する。
 *
 * x86専用Modelsとarchive内の未参照実行programをx64のdriver-only packageとして受理しない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testInfContentRejections( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// Negative fixtureを所有する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"inf-test", 103) == 0) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"x86\\sample.inf", X86_ONLY_INF)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"x86\\sample.cat", "catalog")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"x86\\sample.sys", "driver")) ;
	const std::array x86Entries{
		OfficialZipEntry{L"x86\\sample.inf", X86_ONLY_INF.size()},
		OfficialZipEntry{L"x86\\sample.cat", 7},
		OfficialZipEntry{L"x86\\sample.sys", 6},
	} ; // x86専用INFを含むentry群。
	OfficialInfPackage package ;	// 失敗時に空であるべき出力。
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, x86Entries, L"x86\\sample.inf",
														  POLICY, package) != 0) ;

	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"program\\sample.inf", PROGRAM_INF)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"program\\sample.cat", "catalog")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"program\\sample.sys", "driver")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"program\\helper.exe", "program")) ;
	const std::array programEntries{
		OfficialZipEntry{L"program\\sample.inf", PROGRAM_INF.size()},
		OfficialZipEntry{L"program\\sample.cat", 7},
		OfficialZipEntry{L"program\\sample.sys", 6},
		OfficialZipEntry{L"program\\helper.exe", 7},
	} ; // 実行programを含むentry群。
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, programEntries, L"program\\sample.inf",
												 POLICY, package) != 0) ;

	DRIVERCRATE_EXPECT( context,
					   writeWorkspaceFile( workspace, L"program\\helper.ex_", "compressed")) ;
	const std::array compressedProgramEntries{
		OfficialZipEntry{L"program\\sample.inf", PROGRAM_INF.size()},
		OfficialZipEntry{L"program\\sample.cat", 7},
		OfficialZipEntry{L"program\\sample.sys", 6},
		OfficialZipEntry{L"program\\helper.ex_", 10},
	} ; // Windows Setup形式で圧縮された実行programを含むentry群。
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, compressedProgramEntries,
												 L"program\\sample.inf", POLICY, package) != 0) ;

	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"program\\helper.ps1", "script")) ;
	const std::array scriptEntries{
		OfficialZipEntry{L"program\\sample.inf", PROGRAM_INF.size()},
		OfficialZipEntry{L"program\\sample.cat", 7},
		OfficialZipEntry{L"program\\sample.sys", 6},
		OfficialZipEntry{L"program\\helper.ps1", 6},
	} ; // PowerShell scriptを含むentry群。
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, scriptEntries, L"program\\sample.inf",
												 POLICY, package) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 混在Modelsから現在のx64 sectionだけを選ぶことを確認する。
 *
 * x86用PnP IDをx64候補へ混入せず、architecture不明の独自version比較へ置き換えない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testArchitectureSpecificModelsSelection( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 混在architecture fixtureの保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"inf-architecture-test", 111U) == 0) ;
	DRIVERCRATE_EXPECT(
		context, writeWorkspaceFile( workspace, L"mixed\\renamed.inf", MIXED_ARCHITECTURE_INF)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"mixed\\sample.cat", "catalog")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"mixed\\sample.sys", "driver")) ;
	const std::array entries{
		OfficialZipEntry{L"mixed\\renamed.inf", MIXED_ARCHITECTURE_INF.size()},
		OfficialZipEntry{L"mixed\\sample.cat", 7U},
		OfficialZipEntry{L"mixed\\sample.sys", 6U},
	} ; // x64とx86 Modelsを同じINFに保持するentry群。
	OfficialInfPackage package ;	// x64 sectionだけを保持する構造結果。
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"mixed\\renamed.inf",
														  POLICY, package) == 0) ;
	DRIVERCRATE_EXPECT( context, package.hardwareIds.size() == 1U) ;
	// 一件だけ取得できた場合に、x64用IDが選ばれx86用IDが除外されたことを確認する。
	if( package.hardwareIds.size() == 1U) {
		DRIVERCRATE_EXPECT( context, package.hardwareIds.front() == L"PCI\\VEN_4321&DEV_1000") ;
		DRIVERCRATE_EXPECT( context, package.hardwareIds.front() != L"PCI\\VEN_4321&DEV_2000") ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 現在deviceとのPnP ID照合規則を確認する。
 *
 * Hardware ID優先、Compatible ID照合、大文字小文字の差、部分一致と空IDの拒否を架空IDだけで確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testDeviceIdentityMatching( TestContext &context)
{
	OfficialInfPackage package ;	// 現在deviceとの照合に使用する検証済み相当package。
	package.hardwareIds = {L"PCI\\VEN_1234&DEV_5678", L"PCI\\VEN_1234"} ;

	constexpr std::array EXACT_HARDWARE_IDS{	// 大文字小文字だけが異なる完全ID。
											std::wstring_view( L"pci\\ven_1234&dev_5678")} ;
	constexpr std::array COMPATIBLE_IDS{	// より一般的な架空Compatible ID。
										std::wstring_view( L"PCI\\VEN_1234")} ;
	DRIVERCRATE_EXPECT( context,
					   matchOfficialInfToDevice( package, EXACT_HARDWARE_IDS, COMPATIBLE_IDS) ==
						   OfficialInfDeviceMatch::HARDWARE_ID) ;

	constexpr std::array UNRELATED_HARDWARE_IDS{	// INFへ一致しない架空Hardware ID。
												std::wstring_view( L"PCI\\VEN_9999&DEV_9999")} ;
	DRIVERCRATE_EXPECT( context,
					   matchOfficialInfToDevice( package, UNRELATED_HARDWARE_IDS, COMPATIBLE_IDS) ==
						   OfficialInfDeviceMatch::COMPATIBLE_ID) ;

	constexpr std::array PARTIAL_IDS{	// Prefixだけが一致するID。
									 std::wstring_view( L"PCI\\VEN_1234&DEV_5678&SUBSYS_00000000")} ;
	constexpr std::array EMPTY_IDS{std::wstring_view{}} ;	// 適用対象を拡張してはならない空ID。
	DRIVERCRATE_EXPECT( context, matchOfficialInfToDevice( package, PARTIAL_IDS, EMPTY_IDS) ==
									OfficialInfDeviceMatch::NONE) ;
	DRIVERCRATE_EXPECT( context, matchOfficialInfToDevice( package, EMPTY_IDS, EMPTY_IDS) ==
									OfficialInfDeviceMatch::NONE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空CoInstaller節の作用検査と署名境界を確認する。
 *
 * @param[in,out] context Assertion集計先。
 * @param[in] suffix 正常INFへ追加する架空sectionと指示。
 * @param[in] accepted 無作用として構造受理すべき場合true。
 * @param[in] identity 一時workspace用の試験operation ID。
 * @note 実DLLを実行せず、受理後も未署名CATは必ず拒否されることを確認する。
 */
//------------------------------------------------------------------------------
void checkCoInstallerFixture( TestContext &context, const std::string_view suffix,
							 const bool accepted, const std::uint64_t identity)
{
	OfficialDownloadWorkspace workspace ;	// Scope内でfixtureを所有する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"empty-coinstaller-test", identity) == 0) ;
	std::string inf( VALID_INF) ;	// 実IDを含まない正常fixtureへ追加する全byte。
	inf.insert( inf.find( "[Strings]\r\n") + std::string_view( "[Strings]\r\n").size(),
			   "EmptyTarget=\"EmptyCopy\"\r\n") ;
	inf.append( suffix) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"test\\sample.inf", inf)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"test\\sample.cat", "catalog")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"test\\sample.sys", "driver")) ;
	const std::array entries{
		OfficialZipEntry{L"test\\sample.inf", inf.size()},
		OfficialZipEntry{L"test\\sample.cat", 7},
		OfficialZipEntry{L"test\\sample.sys", 6},
	} ; // CATと通常SYS参照を維持した架空entry群。
	OfficialInfInspectionPolicy actionPolicy = POLICY ;	// 動作検査を要求する有限policy。
	actionPolicy.rejectInstallActions		 = true ;
	OfficialInfPackage package ;	// 失敗時には空へ戻す検証出力。
	const NativeError  error = inspectOfficialInfPackage( workspace, entries, L"test\\sample.inf",
														 actionPolicy, package) ;	// 構造検査結果。
	context.expect( (error == 0) == accepted,
				   "CoInstaller fixture " + std::to_string( identity) + " HRESULT " +
					   std::to_string( error),
				   __FILE__, __LINE__) ;
	// 受理済みfixtureでも署名境界を省略して導入可能としてはならない。
	if( accepted && error == 0) {
		DRIVERCRATE_EXPECT( context, package.sourceFiles.size() == 1U) ;
		DRIVERCRATE_EXPECT( context, !package.hasExternalDependencies) ;
		DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, package) != 0) ;
	}

	// 不正動作は候補用metadataを部分公開しない。
	if( !accepted) {
		DRIVERCRATE_EXPECT( context, package.infRelativePath.empty()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 空節と空参照だけを許可し、実動作・未知指示・循環・過大入力を拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testEmptyCoInstallerReferences( TestContext &context)
{
	constexpr std::array ACCEPTED{
		std::string_view( "\r\n[Install.NT.CoInstallers]\r\n; empty\r\n"),
		std::string_view(
			"\r\n[Install.NT.CoInstallers]\r\nAddReg=EmptyReg\r\nCopyFiles=EmptyCopy\r\n[EmptyReg]\r\n; no registration\r\n[EmptyCopy]\r\n; no file\r\n"),
		std::string_view(
			"\r\n[Install.NT.cOiNsTaLlErS]\r\nAddReg=Empty1,Empty2\r\n[Empty1]\r\n[Empty2]\r\n"),
		std::string_view(
			"\r\n[Install.NT.CoInstallers]\r\nCopyFiles=%EmptyTarget%\r\n[EmptyCopy]\r\n"),
		std::string_view(
			"\r\n[Install.NT.CoInstallers]\r\nAddReg=Empty\r\n[Empty]\r\n[Empty.NTamd64]\r\n"),
	} ; // 明示された無作用だけを持つ正常例。
	std::uint64_t identity = 300U ;	// Fixture間の独立workspace識別子。
	// 正常例ごとに構造受理と未署名CAT拒否を確認する。
	for( const std::string_view suffix : ACCEPTED) {
		checkCoInstallerFixture( context, suffix, true, identity++) ;
	}

	constexpr std::array REJECTED{
		std::string_view(
			"AddReg=Registration\r\n[Registration]\r\nHKR,,CoInstallers32,0x10000,\"helper.dll\"\r\n"),
		std::string_view( "CopyFiles=Files\r\n[Files]\r\nhelper.dll\r\n"),
		std::string_view( "CopyFiles=@helper.dll\r\n"),
		std::string_view( "AddReg=Missing\r\n"),
		std::string_view( "AddReg=\r\n"),
		std::string_view( "AddReg=Empty,\r\n[Empty]\r\n"),
		std::string_view( "AddReg=,Empty\r\n[Empty]\r\n"),
		std::string_view( "Unknown=Empty\r\n[Empty]\r\n"),
		std::string_view( "Include=other.inf\r\n"),
		std::string_view( "Needs=Empty\r\n[Empty]\r\n"),
		std::string_view( "DelReg=Empty\r\n[Empty]\r\n"),
		std::string_view( "RegisterDlls=Empty\r\n[Empty]\r\n"),
		std::string_view( "AddReg=Install.NT.CoInstallers\r\n"),
		std::string_view( "AddReg=Cycle\r\n[Cycle]\r\nAddReg=Install.NT.CoInstallers\r\n"),
		std::string_view( "AddReg=Empty\r\nAddReg=Empty\r\n[Empty]\r\n"),
		std::string_view( "CopyFiles=Empty\r\nCopyFiles=Empty\r\n[Empty]\r\n"),
		std::string_view( "AddReg=%Unresolved%\r\n"),
		std::string_view( "CopyFiles=..\\Empty\r\n[Empty]\r\n"),
		std::string_view( "AddReg=Empty\r\n[Empty]\r\n[Empty.NTamd64]\r\nHKR,,Value,0,\"data\"\r\n"),
		std::string_view( "AddReg=Empty\r\n[Empty]\r\n[Empty]\r\nHKR,,Value,0,\"data\"\r\n"),
		std::string_view( "helper.dll\r\n"),
		std::string_view( "AddReg=Empty\r\nCopyFiles=Empty\r\nUnknown=Empty\r\n[Empty]\r\n"),
		std::string_view(
			"AddReg=Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty\r\n[Empty]\r\n"),
	} ; // 実動作、未知、循環、構文不備と上限超過の拒否例。
	// 各拒否例を同じ正常driverに付加し、空参照許可の抜け道にしない。
	for( const std::string_view body : REJECTED) {
		std::string suffix( "\r\n[Install.NT.CoInstallers]\r\n") ;	// 現在拒否例の節本文。
		suffix.append( body) ;
		checkCoInstallerFixture( context, suffix, false, identity++) ;
	}

	std::string boundary( "\r\n[Install.NT.CoInstallers]\r\nAddReg=") ;	// 最大16参照の正常境界。
	// 一つの空節を参照する16個のfieldを固定上限まで構築する。
	for( std::size_t field = 0U; field < 16U; ++field) {
		boundary.append( field == 0U ? "Empty" : ",Empty") ;
	}

	boundary.append( "\r\n[Empty]\r\n") ;
	checkCoInstallerFixture( context, boundary, true, identity++) ;
	const std::string longName( 257U, 'A') ;									// section名の上限を一文字超える不正参照。
	std::string		  oversized( "\r\n[Install.NT.CoInstallers]\r\nAddReg=") ;	// 過長参照fixture。
	oversized.append( longName).append( "\r\n[").append( longName).append( "]\r\n") ;
	checkCoInstallerFixture( context, oversized, false, identity++) ;
	checkCoInstallerFixture(
		context,
		"\r\n[Install.NT.CoInstallers]\r\nAddReg=Empty\r\n[Empty]\r\n[Other]\r\nRegisterDlls=Empty\r\n",
		false, identity++) ;
}

/**
 * @brief 棚卸しと導入拒否を分離し、媒体pathと全CopyINFの境界を確認する。
 * @param[in,out] context Assertion集計先。
 * @note 実ID・署名済みpackage・導入APIを使わない。
 */
void testMaintenanceInfReferences( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 架空INFだけを所有する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"inf-reference-test", 801U) == 0) ;
	std::string		  inf( VALID_INF) ;						// EXEとBINの参照がある非実行fixture。
	const std::size_t source = inf.find( "sample.sys=1") ;	// source節へ追加する位置。
	inf.insert( source, "helper.exe=1\r\ndata.bin=1\r\n") ;
	inf.append(
		"\r\n[SourceDisksFiles]\r\ncommon.dll=1\r\n[Other]\r\nCopyINF=child\\peer.inf,child\\peer.inf\r\nInclude=machine.inf\r\n") ;
	inf.append( "\r\n[Anonymous]\r\n,sample.sys\r\n") ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"test\\sample.inf", inf)) ;
	const std::array entries{
		OfficialZipEntry{L"test\\sample.inf", inf.size()},
		OfficialZipEntry{L"test\\sample.cat", 7},
		OfficialZipEntry{L"test\\sample.sys", 6},
		OfficialZipEntry{L"test\\helper.exe", 7},
		OfficialZipEntry{L"test\\data.bin", 7},
		OfficialZipEntry{L"test\\common.dll", 7},
	} ; // 参照先はmetadataだけであり実byte合格ではない。
	OfficialInfReferenceInventory facts ;	// 導入packageへ変換できない出力。
	DRIVERCRATE_EXPECT(
		context, inspectOfficialInfReferences( workspace, entries, L"test\\sample.inf", facts) == 0) ;
	DRIVERCRATE_EXPECT( context, facts.stage == OfficialInfReferenceStage::INVENTORIED) ;
	DRIVERCRATE_EXPECT( context, facts.sourceFiles.size() == 4U) ;
	DRIVERCRATE_EXPECT( context, facts.copyInfPaths.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, facts.copyInfPaths.front() == L"test\\child\\peer.inf") ;
	DRIVERCRATE_EXPECT( context, facts.hasExternalDependencies) ;
	DRIVERCRATE_EXPECT( context, facts.installActionsError != 0) ;
	OfficialInfInspectionPolicy installPolicy = POLICY ;	// 既存の導入拒否境界。
	installPolicy.rejectUnreferencedPrograms  = false ;
	installPolicy.rejectInstallActions		  = true ;
	OfficialInfPackage package ;	// 保守成功でも導入構造は受理しない。
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"test\\sample.inf",
														  installPolicy, package) != 0) ;
	DRIVERCRATE_EXPECT( context, package.infRelativePath.empty()) ;

	std::string		  mediaInf( VALID_INF) ;						// SourceDisksNamesのmedia pathも含めるfixture。
	const std::size_t media = mediaInf.find( "1=%DiskName%,,,") ;	// 固定fixtureの媒体宣言位置。
	mediaInf.replace( media, std::string_view( "1=%DiskName%,,,").size(), "1=%DiskName%,,,media") ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"media\\sample.inf", mediaInf)) ;
	const std::array mediaEntries{
		OfficialZipEntry{L"media\\sample.inf", mediaInf.size()},
		OfficialZipEntry{L"media\\sample.cat", 7},
		OfficialZipEntry{L"media\\media\\sample.sys", 6},
	} ; // 媒体pathを省略した位置にはsourceが存在しない。
	DRIVERCRATE_EXPECT( context, inspectOfficialInfReferences( workspace, mediaEntries,
															 L"media\\sample.inf", facts) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   facts.sourceFiles == std::vector<std::wstring>{L"media\\media\\sample.sys"}) ;
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfReferences( workspace, std::span( mediaEntries).first( 2U),
													L"media\\sample.inf", facts) != 0) ;
	DRIVERCRATE_EXPECT( context, facts.stage == OfficialInfReferenceStage::SOURCES &&
									facts.sourceFiles.empty()) ;

	constexpr std::array REJECTED{
		std::string_view( "..\\peer.inf"),
		std::string_view( "\\peer.inf"),
		std::string_view( "C:\\peer.inf"),
		std::string_view( "https://invalid/peer.inf"),
		std::string_view( "helper.exe"),
		std::string_view( "%Missing%"),
		std::string_view( "child\\..\\peer.inf"),
		std::string_view( "peer.inf:"),
		std::string_view( "peer.inf."),
		std::string_view( "\"\""),
		std::string_view( ".\\..\\peer.inf"),
		std::string_view( ".\\C:\\peer.inf"),
		std::string_view( ".\\\\peer.inf"),
		std::string_view( "."),
		std::string_view( ".\\"),
	} ; // traversal、絶対、未解決、別形式、曖昧pathの拒否集合。
	std::size_t ordinal{} ;	// CREATE_NEWのfixture識別子。
	// 不正参照を一件ずつSetupAPIへ渡す。
	for( const std::string_view child : REJECTED) {
		std::string invalid( VALID_INF) ;	// 共通の正常driver本文。
		invalid.append( "\r\n[Other]\r\nCopyINF=").append( child).append( "\r\n") ;
		const std::wstring path =
			L"invalid" + std::to_wstring( ordinal++) + L"\\sample.inf" ;	// 一意な相対path。
		const std::wstring parent = path.substr( 0, path.find( L'\\')) ;	// 現在fixture親。
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, path, invalid)) ;
		const std::array invalidEntries{
			OfficialZipEntry{path, invalid.size()},
			OfficialZipEntry{parent + L"\\sample.cat", 7},
			OfficialZipEntry{parent + L"\\sample.sys", 6},
		} ; // 不正CopyINF以外の参照metadata。
		DRIVERCRATE_EXPECT(
			context, inspectOfficialInfReferences( workspace, invalidEntries, path, facts) != 0) ;
		DRIVERCRATE_EXPECT( context, facts.stage == OfficialInfReferenceStage::DEPENDENCIES) ;
		DRIVERCRATE_EXPECT( context, facts.infRelativePath.empty() && facts.copyInfPaths.empty()) ;
	}

	DRIVERCRATE_EXPECT(
		context, inspectOfficialInfReferences( workspace, entries, L"..\\sample.inf", facts) != 0) ;
	DRIVERCRATE_EXPECT( context, facts.stage == OfficialInfReferenceStage::OPEN) ;
	std::string longKeyInf( VALID_INF) ;	// 先頭fieldが過長なkeyと空の先頭fieldを区別するfixture。
	longKeyInf.append( "\r\n[LongKey]\r\n").append( 4'096U, 'A').append( "=value\r\n") ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"longkey\\sample.inf", longKeyInf)) ;
	const std::array longEntries{
		OfficialZipEntry{L"longkey\\sample.inf", longKeyInf.size()},
		OfficialZipEntry{L"longkey\\sample.cat", 7},
		OfficialZipEntry{L"longkey\\sample.sys", 6},
	} ; // 過長key以外は正常なmetadata。
	DRIVERCRATE_EXPECT( context, inspectOfficialInfReferences( workspace, longEntries,
															 L"longkey\\sample.inf", facts) != 0) ;
	DRIVERCRATE_EXPECT( context, facts.infRelativePath.empty()) ;
}

/**
 * @brief 保守参照の先頭現在directoryだけを解決し、親参照と絶対pathは拒否する。
 * @param[in,out] context Assertion集計先。
 * @note 架空INFを保護領域へ置き、実導入・実署名packageを使用しない。
 */
void testMaintenanceRelativeReferences( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 架空fixtureだけを所有する保護領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"inf-relative-test", 802U) == 0) ;
	constexpr std::array MEDIA{std::string_view( ".\\media"), std::string_view( ".\\.\\media"),
							   std::string_view( "./media"), std::string_view( "."),
							   // 明示現在directoryだけの正例。
							   std::string_view( ".\\")} ;
	// 別々の元fileとmetadataで媒体pathの解決を確認する。
	for( std::size_t index = 0U; index < MEDIA.size(); ++index) {
		std::string		  inf( VALID_INF) ;							// 有限の架空driver本文。
		const std::size_t position = inf.find( "1=%DiskName%,,,") ;	// 固定媒体pathの追加位置。
		inf.replace( position, std::string_view( "1=%DiskName%,,,").size(),
					"1=%DiskName%,,," + std::string( MEDIA[index])) ;
		inf.append( "\r\n[Other]\r\nCopyINF=.\\child\\peer.inf\r\n") ;
		// 正常な媒体とsource subdirの両方に現在directory指定を持つケースを含める。
		if( index == 0U) {
			const std::size_t sourcePosition =
				// source subdirの追加位置。
				inf.find( "sample.sys=1") ;
			inf.replace( sourcePosition, std::string_view( "sample.sys=1").size(),
						"sample.sys=1,.\\") ;
		}

		const std::wstring parent = L"valid" + std::to_wstring( index) ;	// CREATE_NEWの一意親。
		const std::wstring path	  = parent + L"\\sample.inf" ;				// 現在fixtureのINF。
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, path, inf)) ;
		const std::wstring source =
			parent + (index < 3U ? L"\\media\\sample.sys"
								 : L"\\sample.sys") ;	// 宣言媒体位置だけにある元source。
		const std::array entries{
			OfficialZipEntry{path, inf.size()}, OfficialZipEntry{parent + L"\\sample.cat", 7U},
			OfficialZipEntry{source, 6U}} ;		// 未取得sourceはmetadataとして扱う。
		OfficialInfReferenceInventory facts ;	// 署名・導入を承認しない参照結果。
		DRIVERCRATE_EXPECT( context,
						   inspectOfficialInfReferences( workspace, entries, path, facts) == 0) ;
		DRIVERCRATE_EXPECT( context, facts.sourceFiles == std::vector<std::wstring>{source}) ;
		DRIVERCRATE_EXPECT( context, facts.copyInfPaths ==
										std::vector<std::wstring>{parent + L"\\child\\peer.inf"}) ;
	}

	constexpr std::array UNSAFE{std::string_view( ".\\..\\media"), std::string_view( ".\\C:\\media"),
								std::string_view( ".\\\\server"),
								std::string_view( "media\\.\\child"),
								// 除去後も危険または未対応な媒体位置。
								std::string_view( "media\\..\\child")} ;
	// 危険な媒体を同名sourceへのfallbackで救済しない。
	for( std::size_t index = 0U; index < UNSAFE.size(); ++index) {
		std::string		  inf( VALID_INF) ;							// その他の節は正常に維持する。
		const std::size_t position = inf.find( "1=%DiskName%,,,") ;	// 媒体宣言位置。
		inf.replace( position, std::string_view( "1=%DiskName%,,,").size(),
					"1=%DiskName%,,," + std::string( UNSAFE[index])) ;
		const std::wstring parent = L"unsafe" + std::to_wstring( index) ;	// CREATE_NEW用一意親。
		const std::wstring path	  = parent + L"\\sample.inf" ;				// 不正媒体だけを含むINF。
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, path, inf)) ;
		const std::array entries{
			OfficialZipEntry{path, inf.size()}, OfficialZipEntry{parent + L"\\sample.cat", 7U},
			OfficialZipEntry{parent + L"\\sample.sys", 6U}} ;	// 名前だけで補完させないmetadata。
		OfficialInfReferenceInventory facts ;					// 部分参照を合格として保持しない。
		DRIVERCRATE_EXPECT( context,
						   inspectOfficialInfReferences( workspace, entries, path, facts) != 0) ;
		DRIVERCRATE_EXPECT( context, facts.sourceFiles.empty()) ;
	}
}

/**
 * @brief 空sourceでも署名を要求し、通常導入の構造policyを緩和しない。
 * @param[in,out] context Assertion集計先。
 * @note 架空CATを使用する負例であり、署名合格の正例は別の非実行実物試験で確認する。
 */
void testInfOnlyIntegrityBoundary( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// INF/CATのみを所有する架空fixture領域。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"inf-only-integrity-test", 172U) == 0) ;
	std::string		  inf( VALID_INF) ;									// 実機情報を含まない元fixture。
	const std::size_t begin = inf.find( "[SourceDisksNames.amd64]") ;	// 参照を除く区間先頭。
	const std::size_t end	= inf.find( "[Strings]") ;					// 表示用Stringsは保持する。
	inf.replace( begin, end - begin, "[Install.NT]\r\n; no source files\r\n\r\n") ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"only\\sample.inf", inf)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"only\\sample.cat", "unsigned")) ;
	const std::array entries{
		OfficialZipEntry{L"only\\sample.inf", inf.size()},
		OfficialZipEntry{L"only\\sample.cat", 8U}} ;	// 取得済みINF/CATだけの有限集合。
	OfficialInfReferenceInventory facts ;				// 内容署名とは別の保守棚卸し結果。
	DRIVERCRATE_EXPECT(
		context, inspectOfficialInfReferences( workspace, entries, L"only\\sample.inf", facts) == 0) ;
	DRIVERCRATE_EXPECT( context, facts.sourceFiles.empty()) ;
	DRIVERCRATE_EXPECT( context, facts.catalogRelativePath == L"only\\sample.cat") ;
	OfficialInfPackage content ;	// 参照検査後の署名呼出し専用値。
	content.infRelativePath		= facts.infRelativePath ;
	content.catalogRelativePath = facts.catalogRelativePath ;
	content.sourceFiles			= facts.sourceFiles ;
	DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, content) != 0) ;
	DRIVERCRATE_EXPECT(
		context, verifyOfficialInfPackageIntegrity( workspace, content, ACCEPTED_SIGNERS) != 0) ;
	DRIVERCRATE_EXPECT( context, verifyOfficialInfEmbeddedFileSignatures( workspace, content, {},
																		ACCEPTED_SIGNERS) ==
									static_cast<NativeError>( E_INVALIDARG)) ;
	OfficialInfPackage install ;	// 内容署名とは別に通常導入用の構造policyを確認する。
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"only\\sample.inf",
														  POLICY, install) != 0) ;
	DRIVERCRATE_EXPECT( context, install.infRelativePath.empty()) ;
	content.infRelativePath.clear() ;
	DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, content) != 0) ;
	content.infRelativePath = facts.infRelativePath ;
	content.catalogRelativePath.clear() ;
	DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, content) != 0) ;
}

/**
 * @brief 一つの架空保守INFを構造回帰用に組み立てる。
 * @param[in] serviceBody 現OS対応Services節の宣言。空名も原文字列で保持する。
 * @param[in] installBody 現OS用DDInstall本文。参照はfixtureの範囲だけ。
 * @param[in] extraSections 任意の架空source・Strings・付随節。
 * @param[in] extraModels 現OS Modelsへ加える架空行。
 * @return 元byte検証だけに使用する架空INF。実inventoryを含まない。
 */
[[nodiscard]] std::string makeMaintenanceInf( std::string_view serviceBody,
											 std::string_view installBody	= {},
											 std::string_view extraSections = {},
											 std::string_view extraModels	= {})
{
	std::string inf =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=System\r\n"
		"ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}\r\n"
		"Provider=Fictional Wireless Corporation\r\nDriverVer=10/07/2026,1.0.0.1\r\n"
		"CatalogFile=sample.cat\r\n[Manufacturer]\r\nFictional=Models,NTamd64,NTx86\r\n"
		"[Models.NTamd64]\r\nFirst=Install,ROOT\\FICTIONAL_STRUCTURE_0001\r\n" ;	// 固定架空元INF。
	inf += extraModels ;
	inf += "[Models.NTx86]\r\nOther=OtherOS,ROOT\\FICTIONAL_OTHER_OS_0001\r\n"
		   "[OtherOS.NTx86]\r\nUnknownOtherOS=ignored\r\n"
		   "[OtherOS.NTx86.Services]\r\nAddService=,broken\r\n[Install.NT]\r\n" ;
	inf += installBody ;
	inf += "\r\n[Install.NT.Services]\r\n" ;
	inf += serviceBody ;
	inf += "\r\n" ;
	inf += extraSections ;
	return inf ;
}

/**
 * @brief 架空INFとdummy CATをSetupAPIで構造観測する。
 * @param[in,out] context Assertion集計先。
 * @param[in] inf 架空INF全文。
 * @param[out] structure 保守構造。署名結果は未検査のまま。
 * @param[in] payloadPresent 架空SYSを固定entryへ含める場合true。
 * @param[in] checkIntField flags 2正例についてWindows整数APIも比較する場合true。
 * @return 保守APIの元HRESULT。読取失敗は構造を空にする。
 * @throws std::runtime_error 架空workspace初期化に失敗した場合。
 */
[[nodiscard]] NativeError inspectMaintenanceFixture( TestContext &context, std::string_view inf,
													MaintenanceInfStructure &structure,
													bool					 payloadPresent = false,
													bool					 checkIntField	= false)
{
	OfficialDownloadWorkspace workspace ;	// 同期観測完了まで架空byteを所有する。
	const NativeError		  initialized =
		// 24文字内のtag。
		workspace.initialize( L"maint-structure-fixture", 249U) ;
	DRIVERCRATE_EXPECT( context, initialized == 0) ;
	// Fixture自体を作れない場合は未初期化の領域・行contextを試験で参照しない。
	if( initialized != 0) {
		throw std::runtime_error( "Synthetic maintenance workspace initialization failed") ;
	}

	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"test\\sample.inf", inf)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"test\\sample.cat", "unsigned")) ;
	std::vector<OfficialZipEntry> entries{{L"test\\sample.inf", inf.size()},
										  {L"test\\sample.cat", 8U}} ;	// 署名成功ではない固定集合。
	// File参照正例だけが架空SYSのmetadata存在を持つ。
	if( payloadPresent) {
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"test\\sample.sys", "driver")) ;
		entries.push_back( {L"test\\sample.sys", 6U}) ;
	}

	// Literal／hex／Strings正例で同じ展開fieldのWindows整数値を比較する。
	if( checkIntField) {
		const HINF handle = SetupOpenInfFileW( workspace.path( L"test\\sample.inf").c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  nullptr) ;	// 本scopeが必ず閉じる借用元。
		DRIVERCRATE_EXPECT( context, handle != INVALID_HANDLE_VALUE) ;
		// 読取成功時だけcontextと整数APIを参照する。
		if( handle != INVALID_HANDLE_VALUE) {
			INFCONTEXT line{} ;	// 比較用のAddService行。
			DRIVERCRATE_EXPECT( context, SetupFindFirstLineW( handle, L"Install.NT.Services",
															L"AddService", &line) != FALSE) ;
			int flags = -1 ;	// API失敗時の比較sentinel。
			DRIVERCRATE_EXPECT( context, SetupGetIntField( &line, 2U, &flags) != FALSE) ;
			DRIVERCRATE_EXPECT( context, flags == 2) ;
			SetupCloseInfFile( handle) ;
		}
	}

	return inspectMaintenanceInfStructure( workspace, entries, L"test\\sample.inf",
										  MAINTENANCE_POLICY, structure) ;
}

/** @brief 一数値fixtureと期待する個別診断。 */
struct MaintenanceFlagCase {
	/// AddServiceの第1field以降を含む原文字列。
	std::string_view		   fields ;
	/// 架空Stringsの追加節。
	std::string_view		   strings ;
	/// 数値とservice構造の到達状態。
	MaintenanceInspectionState state ;
	/// 正例ならnull、不正または未対応ならunknown構造。
	MaintenanceInfContentKind  kind ;
} ;

/**
 * @brief Empty名・flags全field・Windows展開と個別不正／未対応の分離を回帰する。
 * @param[in,out] context Assertion集計先。
 */
void testMaintenanceNullFlags( TestContext &context)
{
	constexpr std::array<MaintenanceFlagCase, 18U> CASES{{
		{",2", {}, MaintenanceInspectionState::PASSED, MaintenanceInfContentKind::NULL_DRIVER},
		{",2,", {}, MaintenanceInspectionState::PASSED, MaintenanceInfContentKind::NULL_DRIVER},
		{",2,,", {}, MaintenanceInspectionState::PASSED, MaintenanceInfContentKind::NULL_DRIVER},
		{",0x00000002",
		 {},
		 MaintenanceInspectionState::PASSED,
		 MaintenanceInfContentKind::NULL_DRIVER},
		{",0X2", {}, MaintenanceInspectionState::PASSED, MaintenanceInfContentKind::NULL_DRIVER},
		{",%NullFlags%", "[Strings]\r\nNullFlags=2\r\n", MaintenanceInspectionState::PASSED,
		 MaintenanceInfContentKind::NULL_DRIVER},
		{",%NullFlags%,", "[Strings]\r\nNullFlags=0x2\r\n", MaintenanceInspectionState::PASSED,
		 MaintenanceInfContentKind::NULL_DRIVER},
		{",%Undefined%",
		 {},
		 MaintenanceInspectionState::UNSUPPORTED,
		 MaintenanceInfContentKind::UNKNOWN},
		{",%A%", "[Strings]\r\nA=%B%\r\nB=%A%\r\n", MaintenanceInspectionState::UNSUPPORTED,
		 MaintenanceInfContentKind::UNKNOWN},
		{",-2", {}, MaintenanceInspectionState::FAILED, MaintenanceInfContentKind::UNKNOWN},
		{",text", {}, MaintenanceInspectionState::FAILED, MaintenanceInfContentKind::UNKNOWN},
		{",2x", {}, MaintenanceInspectionState::FAILED, MaintenanceInfContentKind::UNKNOWN},
		{",4294967296", {}, MaintenanceInspectionState::FAILED, MaintenanceInfContentKind::UNKNOWN},
		{",0x100000000",
		 {},
		 MaintenanceInspectionState::FAILED,
		 MaintenanceInfContentKind::UNKNOWN},
		{",", {}, MaintenanceInspectionState::FAILED, MaintenanceInfContentKind::UNKNOWN},
		{",+2", {}, MaintenanceInspectionState::UNSUPPORTED, MaintenanceInfContentKind::UNKNOWN},
		{",3", {}, MaintenanceInspectionState::UNSUPPORTED, MaintenanceInfContentKind::UNKNOWN},
		{",4294967295",
		 {},
		 MaintenanceInspectionState::UNSUPPORTED,
		 MaintenanceInfContentKind::UNKNOWN},
	}} ; // 各fieldを0／2補完せず、decimalとhexを同じuint32契約で扱う。
	// 全18ケースを実行し、一件失敗しても残りの分母を省かない。
	for( const auto &testCase : CASES) {
		const std::string inf = makeMaintenanceInf( "AddService=" + std::string( testCase.fields), {},
												   testCase.strings) ;	// 架空原byte。
		MaintenanceInfStructure structure ;								// 署名・coverageは未検査の結果。
		const bool				positive =
			// 整数API比較範囲。
			testCase.state == MaintenanceInspectionState::PASSED ;
		DRIVERCRATE_EXPECT(
			context, inspectMaintenanceFixture( context, inf, structure, false, positive) == 0) ;
		DRIVERCRATE_EXPECT( context, structure.installs.size() == 1U) ;
		DRIVERCRATE_EXPECT( context, structure.parser.state == testCase.state) ;
		DRIVERCRATE_EXPECT( context, structure.contentKind == testCase.kind) ;
		DRIVERCRATE_EXPECT( context, structure.referenceCoverage ==
										MaintenanceInfReferenceCoverage::NOT_CHECKED) ;
		DRIVERCRATE_EXPECT( context, structure.rootIntegrity.state ==
										MaintenanceInspectionState::NOT_CHECKED) ;
		DRIVERCRATE_EXPECT( context, structure.dependency.state ==
										MaintenanceInfDependencyState::NOT_CHECKED) ;
		// 個別field状態は、選択を取得できた場合だけ安全に参照する。
		if( structure.installs.size() == 1U && structure.installs[0].services.size() == 1U) {
			const auto &service =
				structure.installs[0].services[0] ;	// Empty名を保持したworker内観測。
			DRIVERCRATE_EXPECT( context, service.serviceName.empty()) ;
			DRIVERCRATE_EXPECT( context, service.fieldCount >= 2U) ;
			DRIVERCRATE_EXPECT( context, service.parser.state == testCase.state) ;
			// 正例はoptional flags 2、それ以外は具体的診断値が必要。
			if( positive) {
				DRIVERCRATE_EXPECT( context, service.flags == 2U) ;
				DRIVERCRATE_EXPECT( context, structure.installs[0].issues.empty()) ;
			} else {
				DRIVERCRATE_EXPECT( context, !structure.installs[0].issues.empty()) ;
				DRIVERCRATE_EXPECT( context, service.parser.error != 0) ;
			}
		} else {
			DRIVERCRATE_EXPECT( context, false) ;
		}
	}

	// 直接過長とStrings単値過長を分け、Windows切捨て仕様を非切捨て証明にしない。
	for( const bool stringValue : {false, true}) {
		const std::string large( stringValue ? 600U : 5000U, '9') ;	// uint32へ収まらない全数字。
		const std::string inf = makeMaintenanceInf(
			stringValue ? "AddService=,%Large%" : "AddService=," + large, {},
			stringValue ? "[Strings]\r\nLarge=" + large + "\r\n" : "") ;	// 過長原byte。
		MaintenanceInfStructure structure ;									// 読取失敗または個別不正を保持する。
		const NativeError		error =
			// 実Windows挙動。
			inspectMaintenanceFixture( context, inf, structure) ;
		DRIVERCRATE_EXPECT( context, error != 0 || structure.parser.state !=
													  MaintenanceInspectionState::PASSED) ;
		DRIVERCRATE_EXPECT( context, structure.rootIntegrity.state ==
										MaintenanceInspectionState::NOT_CHECKED) ;
		// 全体読取失敗は空結果、個別不正はoptionalの成功値を持たない。
		if( error != 0) {
			DRIVERCRATE_EXPECT( context,
							   structure.infRelativePath.empty() && structure.installs.empty()) ;
		} else {
			DRIVERCRATE_EXPECT( context, structure.installs.size() == 1U &&
											!structure.installs[0].services[0].flags.has_value()) ;
		}
	}
}

/**
 * @brief 全Models・参照ありnull・限定named／複数service・未追跡用途を分離する。
 * @param[in,out] context Assertion集計先。
 */
void testMaintenanceStructureBoundaries( TestContext &context)
{
	MaintenanceInfStructure structure ;	// 各観測の前に入口が空へresetする結果。
	const std::string		copy =
		// Sourceなしcopy。
		makeMaintenanceInf( "AddService=,2", "CopyFiles=@sample.sys\r\n") ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, copy, structure, true) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.contentKind == MaintenanceInfContentKind::MIXED) ;
	DRIVERCRATE_EXPECT( context, !structure.sourceSectionPresent) ;
	DRIVERCRATE_EXPECT( context,
					   structure.installs.at( 0U).inventory.references.at( 0U).targetPresent) ;
	DRIVERCRATE_EXPECT( context,
					   structure.referenceCoverage == MaintenanceInfReferenceCoverage::NOT_CHECKED) ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, copy, structure) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   !structure.installs.at( 0U).inventory.references.at( 0U).targetPresent) ;
	DRIVERCRATE_EXPECT( context, structure.contentKind == MaintenanceInfContentKind::MIXED) ;

	const std::string dependency = makeMaintenanceInf(
		{}, "Include=fictional.inbox.inf\r\nNeeds=Explicit.NT\r\n",
		"[Install.NT.Services]\r\nNeeds=Service.Explicit\r\n") ;	// 別節Includeを借用できない構造。
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, dependency, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.contentKind == MaintenanceInfContentKind::UNKNOWN) ;
	DRIVERCRATE_EXPECT( context,
					   structure.dependency.state == MaintenanceInfDependencyState::OBSERVED) ;
	DRIVERCRATE_EXPECT( context, structure.dependency.reason == InfDependencyReason::NOT_CHECKED) ;
	DRIVERCRATE_EXPECT( context, structure.dependency.observedReferenceCount == 3U) ;
	DRIVERCRATE_EXPECT( context, structure.dependency.resolvedInfCount == 0U) ;
	DRIVERCRATE_EXPECT( context,
					   structure.rootIntegrity.state == MaintenanceInspectionState::NOT_CHECKED) ;

	const std::string named = makeMaintenanceInf(
		"AddService=FictionalService,2,ServiceInstall\r\n", {},
		// 未追跡file用途。
		"[ServiceInstall]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\nServiceBinary=%12%\\sample.sys\r\n") ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, named, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.parser.state == MaintenanceInspectionState::PASSED) ;
	DRIVERCRATE_EXPECT( context, structure.contentKind == MaintenanceInfContentKind::PACKAGE_FILES) ;
	DRIVERCRATE_EXPECT( context,
					   std::ranges::any_of( structure.installs.at( 0U).fileUses, []( const auto &use) {
						   return use.directive == L"ServiceBinary" ;
					   })) ; // ServiceBinaryは具体的用途を保持し、空参照へ消さない。

	const std::string multiple =
		// 二associated宣言。
		makeMaintenanceInf( "AddService=,2\r\nAddService=,0x2\r\n") ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, multiple, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.installs.at( 0U).services.size() == 2U) ;
	DRIVERCRATE_EXPECT( context, structure.parser.state == MaintenanceInspectionState::UNSUPPORTED) ;
	DRIVERCRATE_EXPECT(
		context, std::ranges::any_of( structure.installs.at( 0U).issues, []( const auto &issue) {
			return issue.reason == MaintenanceInfStructureReason::MULTIPLE_ASSOCIATED_SERVICES ;
		})) ; // 最初のnullだけで全体成功へ変換しない。

	const std::string referencedService = makeMaintenanceInf(
		"AddService=,2,ServiceInstall,Events\r\n", {},
		// 参照付きempty service。
		"[ServiceInstall]\r\nServiceBinary=%12%\\sample.sys\r\n[Events]\r\nEventMessageFile=%12%\\event.dll\r\n") ;
	DRIVERCRATE_EXPECT( context,
					   inspectMaintenanceFixture( context, referencedService, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.parser.state == MaintenanceInspectionState::UNSUPPORTED) ;
	DRIVERCRATE_EXPECT( context, structure.contentKind == MaintenanceInfContentKind::MIXED) ;
	DRIVERCRATE_EXPECT( context,
					   structure.installs.at( 0U).services.at( 0U).eventLogSection == L"Events") ;

	const std::string unknown =
		// 未解釈の作用。
		makeMaintenanceInf( "AddService=,2", "UnknownDeclaration=value\r\n") ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, unknown, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.parser.state == MaintenanceInspectionState::UNSUPPORTED) ;
	DRIVERCRATE_EXPECT( context, !structure.installs.at( 0U).inventory.coverageGaps.empty()) ;
	const std::string layout = makeMaintenanceInf( "AddService=,2") +
							   "[Version]\r\nLayoutFile=layout.inf\r\n" ;	// Queue外の用途。
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, layout, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.fileUses.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, structure.contentKind == MaintenanceInfContentKind::MIXED) ;

	const std::string models = makeMaintenanceInf(
		"AddService=,2", {},
		"[Second.NT]\r\nCopyFiles=@sample.sys\r\n[Second.NT.Services]\r\nAddService=,2\r\n",
		// 全現在OS選択。
		"Second=Second,ROOT\\FICTIONAL_STRUCTURE_0002\r\nAgain=Second,ROOT\\FICTIONAL_STRUCTURE_0003\r\n") ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, models, structure, true) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.installs.size() == 2U) ;
	DRIVERCRATE_EXPECT( context, structure.hardwareIds.size() == 3U) ;
	DRIVERCRATE_EXPECT( context, structure.contentKind == MaintenanceInfContentKind::MIXED) ;
	DRIVERCRATE_EXPECT( context, structure.installs.at( 0U).contentKind ==
									MaintenanceInfContentKind::NULL_DRIVER) ;
	DRIVERCRATE_EXPECT( context,
					   structure.installs.at( 1U).contentKind == MaintenanceInfContentKind::MIXED) ;
	DRIVERCRATE_EXPECT( context, structure.parser.state == MaintenanceInspectionState::PASSED) ;

	const std::string secondBad = makeMaintenanceInf(
		"AddService=,2", {}, "[Second.NT]\r\n[Second.NT.Services]\r\nAddService=,broken\r\n",
		"Second=Second,ROOT\\FICTIONAL_STRUCTURE_0002\r\n") ;	// 先頭成功・後続不正。
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, secondBad, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.installs.size() == 2U &&
									structure.parser.state == MaintenanceInspectionState::FAILED) ;
}

/** @brief Named宣言一つと限定parserの期待。架空文字列だけを静的借用する。 */
struct MaintenanceNamedServiceCase {
	/// 元AddServiceのfield群。実service名を含まない。
	std::string_view		   fields ;
	/// 架空Strings・event節の追加本文。
	std::string_view		   extra ;
	/// 参照存在・必須四項目を含む限定構造の期待。
	MaintenanceInspectionState state ;
} ;

/**
 * @brief Named 0／2・省略flags・必須参照と限定nullを同じ有限queueで回帰する。
 * @param[in,out] context Assertion集計先。
 * @note 構造だけを検査し、架空CATを署名成功へ扱わない。
 */
void testMaintenanceNamedServices( TestContext &context)
{
	constexpr std::string_view SERVICE_BODY =
		"[ServiceInstall]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\n"
		"ServiceBinary=%12%\\sample.sys\r\n" ;	// 四項目を持つ架空共通構造。
	constexpr std::array<MaintenanceNamedServiceCase, 21U> CASES{{
		{"FictionalService,2,ServiceInstall", {}, MaintenanceInspectionState::PASSED},
		{"FictionalService,0x2,ServiceInstall", {}, MaintenanceInspectionState::PASSED},
		{"FictionalService,%NamedFlags%,ServiceInstall", "[Strings]\r\nNamedFlags=2\r\n",
		 MaintenanceInspectionState::PASSED},
		{"FictionalAuxiliary,0,ServiceInstall", {}, MaintenanceInspectionState::PASSED},
		{"FictionalAuxiliary,,ServiceInstall", {}, MaintenanceInspectionState::PASSED},
		{"FictionalService,8,ServiceInstall", {}, MaintenanceInspectionState::UNSUPPORTED},
		{"FictionalService,0x4,ServiceInstall", {}, MaintenanceInspectionState::UNSUPPORTED},
		{"FictionalService,%Undefined%,ServiceInstall",
		 {},
		 MaintenanceInspectionState::UNSUPPORTED},
		{"FictionalService,+2,ServiceInstall", {}, MaintenanceInspectionState::UNSUPPORTED},
		{"FictionalService,-2,ServiceInstall", {}, MaintenanceInspectionState::FAILED},
		{"FictionalService,text,ServiceInstall", {}, MaintenanceInspectionState::FAILED},
		{"FictionalService,2x,ServiceInstall", {}, MaintenanceInspectionState::FAILED},
		{"FictionalService,4294967296,ServiceInstall", {}, MaintenanceInspectionState::FAILED},
		{"FictionalService,0x100000000,ServiceInstall", {}, MaintenanceInspectionState::FAILED},
		{"FictionalService,2", {}, MaintenanceInspectionState::FAILED},
		{"FictionalService,2,", {}, MaintenanceInspectionState::FAILED},
		{"FictionalService,2,MissingServiceInstall", {}, MaintenanceInspectionState::FAILED},
		{"%UndefinedName%,2,ServiceInstall", {}, MaintenanceInspectionState::UNSUPPORTED},
		{"FictionalService,2,%UndefinedSection%", {}, MaintenanceInspectionState::UNSUPPORTED},
		{"FictionalService,2,ServiceInstall,MissingEvent", {}, MaintenanceInspectionState::FAILED},
		{"FictionalService,2,ServiceInstall,Events,System", "[Events]\r\n",
		 MaintenanceInspectionState::UNSUPPORTED},
	}} ; // 構造認識と不正・未知を同じ分母で扱う。
	// 二十一宣言を一回ずつ検査し、不正caseを途中で除外しない。
	for( const auto &testCase : CASES) {
		const std::string inf =
			makeMaintenanceInf( "AddService=" + std::string( testCase.fields), {},
							   // 各caseだけの架空byte。
							   std::string( SERVICE_BODY) + std::string( testCase.extra)) ;
		MaintenanceInfStructure structure ;	// 初期化済みでも署名と位置は未検査。
		DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, inf, structure) == 0) ;
		DRIVERCRATE_EXPECT( context, structure.parser.state == testCase.state) ;
		DRIVERCRATE_EXPECT( context,
						   structure.contentKind != MaintenanceInfContentKind::NULL_DRIVER) ;
		DRIVERCRATE_EXPECT( context, structure.rootIntegrity.state ==
										MaintenanceInspectionState::NOT_CHECKED) ;
		// 一つの選択・宣言を取得した場合だけ内部構造を参照する。
		if( structure.installs.size() == 1U && structure.installs.front().services.size() == 1U) {
			const auto &install = structure.installs.front() ;	// この結果の同期借用。
			const auto &service = install.services.front() ;	// 元named identityを外へ出さない。
			DRIVERCRATE_EXPECT( context, service.parser.state == testCase.state) ;
			DRIVERCRATE_EXPECT( context, !service.serviceName.empty()) ;
			const bool marked = std::ranges::any_of( install.fileUses, []( const auto &use) {
				return use.directive == L"NamedServiceStructureNotAssessed" ;
			}) ; // named不足用途が参照readerへ消えずに残る。
			DRIVERCRATE_EXPECT( context,
							   marked == (testCase.state != MaintenanceInspectionState::PASSED)) ;
			// 省略fieldは明示空の場合だけ既定0に対応する。
			if( testCase.fields == "FictionalAuxiliary,,ServiceInstall") {
				DRIVERCRATE_EXPECT( context, service.flags == 0U && service.fieldCount == 3U) ;
			}

			// 数値overflowの元HRESULTを未対応markerで置換しない。
			if( testCase.fields.find( "4294967296") != std::string_view::npos ||
			   testCase.fields.find( "0x100000000") != std::string_view::npos) {
				DRIVERCRATE_EXPECT( context, service.parser.error ==
												static_cast<NativeError>(
													HRESULT_FROM_WIN32( ERROR_ARITHMETIC_OVERFLOW))) ;
			}
		} else {
			DRIVERCRATE_EXPECT( context, false) ;
		}
	}

	const std::string		longFlags( 5000U, '9') ;	// 名前付き宣言でも切捨て数値の成功を認めない。
	MaintenanceInfStructure longStructure ;				// 全体読取失敗または元flags診断を保持する。
	const NativeError		longError = inspectMaintenanceFixture(
		  context,
		  makeMaintenanceInf( "AddService=FictionalService," + longFlags + ",ServiceInstall", {},
								 SERVICE_BODY),
		  longStructure) ;	// 同じ長さ境界をnamedの既定0処理にも適用する。
	DRIVERCRATE_EXPECT( context, longError != 0 || longStructure.parser.state !=
													  MaintenanceInspectionState::PASSED) ;
	// 全体失敗の部分観測を成功のoptional flagsへ残さない。
	if( longError != 0) {
		DRIVERCRATE_EXPECT( context, longStructure.installs.empty()) ;
	} else {
		DRIVERCRATE_EXPECT( context,
						   !longStructure.installs.front().services.front().flags.has_value()) ;
	}

	constexpr std::array<std::string_view, 4U> REQUIRED_LINES{
		"ServiceType=1\r\n", "StartType=3\r\n", "ErrorControl=1\r\n",
		"ServiceBinary=%12%\\sample.sys\r\n"} ;	// 一欠落ずつの有限行集合。
	// 必須四行それぞれの欠落・空・重複を検査し、別項目で補完しない。
	for( const auto line : REQUIRED_LINES) {
		// 各項目を三つの独立した不正・未対応構成へ変える。
		for( const std::size_t variant : {0U, 1U, 2U}) {
			std::string		  body( SERVICE_BODY) ;			// 原架空四項目の独立copy。
			const std::size_t begin = body.find( line) ;	// 欠落させる必須行だけ。
			const std::string replacement =
				variant == 0U	? ""
				: variant == 1U ? std::string( line.substr( 0U, line.find( '=') + 1U)) + "\r\n"
								: std::string( line) + std::string( line) ;	// 重複は優先値を作らない。
			body.replace( begin, line.size(), replacement) ;
			MaintenanceInfStructure structure ;	// 署名と参照は今回も未検査。
			DRIVERCRATE_EXPECT(
				context,
				inspectMaintenanceFixture(
					context,
					makeMaintenanceInf( "AddService=FictionalService,2,ServiceInstall", {}, body),
					structure) == 0) ;
			DRIVERCRATE_EXPECT( context, structure.parser.state ==
											(variant == 2U ? MaintenanceInspectionState::UNSUPPORTED
														   : MaintenanceInspectionState::FAILED)) ;
		}
	}

	constexpr std::array<std::string_view, 5U> BAD_VALUES{
		"ServiceType=%Undefined%\r\n", "ServiceType=3\r\n", "StartType=5\r\n", "ErrorControl=4\r\n",
		"ServiceType=-1\r\n"} ;	// 数値syntaxと未知値を別観測にする。
	// 未解決token・一次仕様外数値・負値を必須行の成功として通さない。
	for( const auto line : BAD_VALUES) {
		std::string		  body( SERVICE_BODY) ;									// 一caseだけの元四項目。
		const std::size_t equals = line.find( '=') ;							// 正式keyを対応させる位置。
		const std::size_t begin	 = body.find( line.substr( 0U, equals + 1U)) ;	// 他行を借用しない。
		body.replace( begin, body.find( "\r\n", begin) + 2U - begin, line) ;
		MaintenanceInfStructure structure ;	// 実作用へ接続しない結果。
		DRIVERCRATE_EXPECT(
			context,
			inspectMaintenanceFixture(
				context,
				makeMaintenanceInf( "AddService=FictionalService,2,ServiceInstall", {}, body),
				structure) == 0) ;
		DRIVERCRATE_EXPECT( context, structure.parser.state ==
										(line.find( "-1") != line.npos
											 ? MaintenanceInspectionState::FAILED
											 : MaintenanceInspectionState::UNSUPPORTED)) ;
	}

	constexpr std::array<std::string_view, 4U> MIXED_SERVICES{
		"AddService=FictionalService,2,serviceinstall\r\nAddService=FictionalAuxiliary,,SERVICEINSTALL\r\n",
		"AddService=,2\r\nAddService=FictionalAuxiliary,0,ServiceInstall\r\n",
		"AddService=FictionalService,2,ServiceInstall\r\nAddService=,2\r\n",
		// shared・混在・二associated。
		"AddService=FictionalService,2,ServiceInstall\r\nAddService=FictionalSecond,2,ServiceInstall\r\n"} ;
	// Shared節を一度だけ読み、補助0と二associatedの違いを保持する。
	for( std::size_t index = 0U; index < MIXED_SERVICES.size(); ++index) {
		MaintenanceInfStructure structure ;	// 原同節へcase-insensitiveに結ぶ結果。
		DRIVERCRATE_EXPECT( context,
						   inspectMaintenanceFixture(
							   context, makeMaintenanceInf( MIXED_SERVICES[index], {}, SERVICE_BODY),
							   structure) == 0) ;
		DRIVERCRATE_EXPECT( context, structure.parser.state ==
										(index < 2U ? MaintenanceInspectionState::PASSED
													: MaintenanceInspectionState::UNSUPPORTED)) ;
		DRIVERCRATE_EXPECT( context, structure.contentKind ==
										(index == 1U || index == 2U
											 ? MaintenanceInfContentKind::MIXED
											 : MaintenanceInfContentKind::PACKAGE_FILES)) ;
	}

	const std::string prior = makeMaintenanceInf(
		{}, "Needs=SERVICEINSTALL\r\nAddService=FictionalService,2,ServiceInstall\r\n",
		// 先に辿る節と後続named。
		"[serviceinstall]\r\nservicetype=1\r\nstarttype=3\r\nerrorcontrol=1\r\nservicebinary=%12%\\sample.sys\r\n") ;
	// 宣言順序とkeyの大文字小文字を別の欠落にしない。
	MaintenanceInfStructure structure ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, prior, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.parser.state == MaintenanceInspectionState::UNSUPPORTED) ;
	DRIVERCRATE_EXPECT( context, structure.installs.front().services.front().parser.state ==
									MaintenanceInspectionState::UNSUPPORTED) ;
	const std::string shared = makeMaintenanceInf(
		"AddService=FictionalService,2,serviceinstall", "Needs=SERVICEINSTALL\r\n",
		// 合法Services宣言を後到達節へ結ぶ。
		"[serviceinstall]\r\nservicetype=1\r\nstarttype=3\r\nerrorcontrol=1\r\nservicebinary=%12%\\sample.sys\r\n") ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, shared, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.parser.state == MaintenanceInspectionState::PASSED) ;
}

/**
 * @brief Class差分試験だけに使う三fileの架空ZIPを生成する。
 * @param[in] inf 架空INFの全byte。
 * @param[out] archive 成功時だけのZIP byte。実driverを含まない。
 * @return 三fileのZIP確定成功ならtrue。Miniz資源は全経路で解放する。
 */
[[nodiscard]] bool makeMaintenanceClassArchive( std::string_view inf, std::string &archive)
{
	archive.clear() ;
	mz_zip_archive writer{} ;	// Scope内だけのMiniz writer状態。
	// 非実行memory writerを初期化できない場合は生成を開始しない。
	if( mz_zip_writer_init_heap( &writer, 0U, 0U) == 0) {
		return false ;
	}

	const bool added =
		mz_zip_writer_add_mem( &writer, "sample.inf", inf.data(), inf.size(), MZ_NO_COMPRESSION) !=
			0 &&
		mz_zip_writer_add_mem( &writer, "sample.cat", "unsigned", 8U, MZ_NO_COMPRESSION) != 0 &&
		mz_zip_writer_add_mem( &writer, "sample.sys", "driver", 6U, MZ_NO_COMPRESSION) !=
			0 ;				// 架空三byte列。
	void	   *bytes{} ;	// APIが返すbufferを直後にRAIIへ移す。
	std::size_t size{} ;	// 確定ZIPの有限byte数。
	const bool	finalized =
		added && mz_zip_writer_finalize_heap_archive( &writer, &bytes, &size) != 0 ;	// 確定結果。
	const std::unique_ptr<void, decltype( &mz_free)> ownedBytes(
		bytes, &mz_free) ;									// 全経路で解放する所有物。
	const bool ended = mz_zip_writer_end( &writer) != 0 ;	// Writer状態をstring確保より先に解放する。
	// 部分archiveを検査入力へ使用しない。
	if( !finalized || !ended || ownedBytes == nullptr || size == 0U) {
		return false ;
	}

	archive.assign( static_cast<const char *>( ownedBytes.get()), size) ;
	return true ;
}

/**
 * @brief 通常Ports・内容専用二Classと未知Class名のpolicy差を実common入口で確認する。
 * @param[in,out] context Assertion集計先。
 * @note Dummy CATは署名失敗の負例。ClassGuidを固定したClass名policy比較であり、
 *       WindowsのClass全体妥当性や実署名成功を認定しない。
 */
void testMaintenanceClassSeparation( TestContext &context)
{
	constexpr std::array<std::string_view, 4U> CLASSES{
		"Ports", "System", "MultiPortSerial", "FictionalUnknown"} ;	// Class名policyだけの差分集合。
	// 通常・内容専用・未知の全Class名を同じsource/CAT条件で比較する。
	for( std::size_t index = 0U; index < CLASSES.size(); ++index) {
		std::string inf( VALID_INF) ;	// 元の架空ID・copy・sourceを保持する。
		inf.replace( inf.find( "Class=Net"), 9U, "Class=" + std::string( CLASSES[index])) ;
		MaintenanceInfStructure structure ;	// 保守構造は新Classを導入許可へ変換しない。
		DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, inf, structure, true) == 0) ;
		DRIVERCRATE_EXPECT( context, structure.parser.state ==
										(index == 3U ? MaintenanceInspectionState::UNSUPPORTED
													 : MaintenanceInspectionState::PASSED)) ;
		DRIVERCRATE_EXPECT( context,
						   structure.contentKind == MaintenanceInfContentKind::PACKAGE_FILES) ;
		DRIVERCRATE_EXPECT( context, structure.sourceFileNames.size() == 1U) ;
		DRIVERCRATE_EXPECT( context, structure.rootIntegrity.state ==
										MaintenanceInspectionState::NOT_CHECKED) ;
		// 未知Class名は具体的な解析未対応へ残し、device不適合を判定しない。
		if( index == 3U) {
			DRIVERCRATE_EXPECT(
				context,
				std::ranges::any_of( structure.installs.at( 0U).issues, []( const auto &issue) {
					return issue.reason == MaintenanceInfStructureReason::CLASS_NOT_SUPPORTED &&
						   issue.finding.state == MaintenanceInspectionState::UNSUPPORTED &&
						   issue.finding.error == static_cast<drivercrate::NativeError>(
													  HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
				})) ;
		}

		std::string archive ;	// 同じ架空INF・dummy CAT・SYSだけの元ZIP。
		DRIVERCRATE_EXPECT( context, makeMaintenanceClassArchive( inf, archive)) ;
		OfficialDownloadWorkspace source ;	// 外側ZIPの固定入力を所有する。
		DRIVERCRATE_EXPECT( context, source.initialize( L"maint-class-fixture", 250U + index) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( source, L"payload.zip", archive)) ;
		std::wstring hash ;	// 実byteから固定した架空archive identity。
		DRIVERCRATE_EXPECT( context, computeFileSha256( source.path( L"payload.zip"), hash) == 0) ;
		const DriverArchiveInput input{250U + index, source.path( L"payload.zip"), archive.size(),
									   hash} ;				// 固定内容のみ。
		MaintenanceDriverPackageInspection maintenance ;	// 内容専用構造と通常routeを独立保持する。
		DRIVERCRATE_EXPECT( context, inspectMaintenanceDriverPackage(
										input, OfficialDriverArchiveFormat::ZIP, maintenance) == 0) ;
		DRIVERCRATE_EXPECT( context, maintenance.infs.size() == 1U) ;
		// 個別結果が取得できた場合だけ四軸の非昇格を確認する。
		if( maintenance.infs.size() == 1U) {
			const auto &row = maintenance.infs[0] ;	// 内容専用Class policyの実検査結果。
			DRIVERCRATE_EXPECT( context, row.parser.state ==
											(index == 3U ? MaintenanceInspectionState::UNSUPPORTED
														 : MaintenanceInspectionState::PASSED)) ;
			DRIVERCRATE_EXPECT( context, row.integrity.state == MaintenanceInspectionState::FAILED) ;
			DRIVERCRATE_EXPECT( context,
							   row.applicability.state == MaintenanceInspectionState::NOT_CHECKED) ;
			DRIVERCRATE_EXPECT( context,
							   row.contentKind == MaintenanceInfContentKind::PACKAGE_FILES) ;
			DRIVERCRATE_EXPECT( context,
							   row.referenceCoverage == MaintenanceInfReferenceCoverage::COMPLETE) ;
			DRIVERCRATE_EXPECT( context,
							   row.rootIntegrity.state == MaintenanceInspectionState::FAILED &&
								   row.rootIntegrity.error != 0) ;
			DRIVERCRATE_EXPECT( context,
							   row.infSha256 == structure.infSha256 && row.inspectedBytes > 0U) ;
			DRIVERCRATE_EXPECT( context,
							   row.dependency.state == MaintenanceInfDependencyState::NONE &&
								   row.dependenciesChecked && !row.hasExternalDependencies) ;
			DRIVERCRATE_EXPECT( context,
							   row.installRoute.state ==
								   (index == 0U ? MaintenanceInspectionState::PASSED
												: MaintenanceInspectionState::UNSUPPORTED)) ;
		}

		CommonDriverPackageInspection normal ;	// 通常19 Classはsource実装も従来のまま。
		DRIVERCRATE_EXPECT( context, inspectCommonDriverPackage(
										input, OfficialDriverArchiveFormat::ZIP, normal) == 0) ;
		DRIVERCRATE_EXPECT( context, normal.infs.size() == 1U) ;
		// 新二Classを通常commonの署名段階へ通さない。
		if( normal.infs.size() == 1U) {
			DRIVERCRATE_EXPECT( context,
							   normal.infs[0].state ==
								   (index == 0U ? CommonInfInspectionState::SIGNATURE_REJECTED
												: CommonInfInspectionState::CLOSURE_REJECTED)) ;
			DRIVERCRATE_EXPECT( context, normal.infs[0].error != 0) ;
		}

		OfficialDownloadWorkspace
			genericWorkspace ;				// 通常generic入口が自身のClass policyを要求する領域。
		GenericInfPackageContents generic ;	// 署名合格・candidateを発行できない架空結果。
		const NativeError		  genericError =
			inspectGenericInfPackageFile( source.path( L"payload.zip"), 260U + index,
										 genericWorkspace, generic) ;	// 従来固定policyの実入口。
		DRIVERCRATE_EXPECT( context, genericError != 0) ;
		DRIVERCRATE_EXPECT( context, generic.packages.empty()) ;
		// 新二Classは通常generic parserのClass gateで従来どおり拒否する。
		if( index > 0U) {
			DRIVERCRATE_EXPECT( context,
							   genericError == static_cast<drivercrate::NativeError>(
												   HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED))) ;
		}

		OfficialInfPackage
			copied ;	// 不完全な表示metadataはpayload helperも通らない。boolを認証としない。
		copied.className   = structure.className ;
		copied.hardwareIds = structure.hardwareIds ;
		copied.sourceFiles = {L"sample.sys"} ;
		DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( copied)) ;
	}
}

/**
 * @brief 全体入力・対象OS・容量の失敗で部分構造が空になることを確認する。
 * @param[in,out] context Assertion集計先。
 */
void testMaintenanceStructureInputFailures( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 架空の一INFとdummy CATだけを所有する。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"maint-input-fixture", 255U) == 0) ;
	const std::string inf =
		// 正常な構造から境界だけを変更する。
		makeMaintenanceInf( "AddService=,2") ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", inf)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
	std::vector<OfficialZipEntry> entries{{L"sample.inf", inf.size()},
										  {L"sample.cat", 8U}} ;	// 元byte metadata。
	MaintenanceInfStructure		  structure ;						// 入口が失敗時に必ず空へresetする出力。
	DRIVERCRATE_EXPECT( context, inspectMaintenanceInfStructure( workspace, entries, L"sample.inf",
															   MAINTENANCE_POLICY, structure) == 0) ;
	DRIVERCRATE_EXPECT(
		context, inspectMaintenanceInfStructure( workspace, entries, L"..\\sample.inf",
												MAINTENANCE_POLICY, structure) == E_INVALIDARG) ;
	DRIVERCRATE_EXPECT( context, structure.installs.empty() && structure.infSha256.empty()) ;
	entries.push_back( entries[0]) ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceInfStructure( workspace, entries, L"sample.inf",
															   MAINTENANCE_POLICY,
															   structure) == E_INVALIDARG) ;
	DRIVERCRATE_EXPECT( context, structure.installs.empty()) ;
	entries.pop_back() ;
	++entries[0].uncompressedSize ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceInfStructure( workspace, entries, L"sample.inf",
															   MAINTENANCE_POLICY, structure) != 0) ;
	DRIVERCRATE_EXPECT( context, structure.infRelativePath.empty()) ;
	--entries[0].uncompressedSize ;
	entries[0].sha256.assign( 64U, L'0') ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceInfStructure( workspace, entries, L"sample.inf",
															   MAINTENANCE_POLICY, structure) != 0) ;
	DRIVERCRATE_EXPECT( context, structure.installs.empty()) ;
	std::string otherOs( inf) ;	// 現在architectureのModelsを別architectureへ変更する。
	otherOs.replace( otherOs.find( "Fictional=Models,NTamd64,NTx86"),
					std::string_view( "Fictional=Models,NTamd64,NTx86").size(),
					"Fictional=Models,NTx86") ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, otherOs, structure) != 0) ;
	DRIVERCRATE_EXPECT( context, structure.installs.empty()) ;
	const std::string malformed =
		// Missing fieldはempty第一fieldと別。
		makeMaintenanceInf( "AddService=") ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, malformed, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.parser.state == MaintenanceInspectionState::FAILED) ;
	const std::string traversal =
		// 元package外参照。
		makeMaintenanceInf( "AddService=,2", "CopyFiles=@..\\escape.sys\r\n") ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, traversal, structure) != 0) ;
	DRIVERCRATE_EXPECT( context, structure.installs.empty()) ;
	std::string large = makeMaintenanceInf( "AddService=,2") ;	// 元選択節へ4,097行を追加する。
	large += "[Install.NT]\r\n" ;
	// 合計行数上限＋1を構築し、分割による予算resetを検出する。
	for( std::size_t row = 0U; row < 4097U; ++row) {
		large += "FeatureScore=0xF0\r\n" ;
	}

	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, large, structure) ==
									static_cast<drivercrate::NativeError>(
										HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW))) ;
	DRIVERCRATE_EXPECT( context, structure.installs.empty()) ;
}

/**
 * @brief 明示seedのfile位置と具体的な不足を架空INFで確認する。
 * @param[in,out] context 一processの有限assertion集計。
 */
void testMaintenanceExplicitReferences( TestContext &context)
{
	constexpr std::array<std::string_view, 12U> BODIES{
		"",
		"CopyFiles=@sample.sys\r\n",
		"CopyFiles=Files\r\n",
		"ServiceBinary=%12%\\sample.sys\r\n",
		"CopyINF=child.inf\r\n",
		"UnknownFileUse=mystery.dll\r\n",
		"AddReg=Scalar\r\n",
		"AddReg=FileReg\r\n",
		"Needs=Absent\r\n",
		"CopyFiles=MissingFiles\r\n",
		"AddReg=AbsentReg\r\n",
		"CopyFiles=@..\\escape.sys\r\n"} ;	// 原作用だけを変える小matrix。
	// sourceあり／なしを別fixtureとし、同じ参照を空集合へ救済させない。
	for( std::size_t index = 0U; index < BODIES.size(); ++index) {
		OfficialDownloadWorkspace workspace ;	// 架空INFとdummy byteだけを単独所有する。
		DRIVERCRATE_EXPECT( context,
						   workspace.initialize( L"maint-reference-test", 600U + index) == 0) ;
		const std::string extra =
			"[Files]\r\nrenamed.sys,sample.sys\r\n[Scalar]\r\nHKR,,,0,1\r\n"
			"[FileReg]\r\nHKR,,Binary,0,%12%\\unknown.dll\r\n" +
			std::string(
				index == 0U || index == 4U || index == 6U || index == 8U || index == 9U ||
						index == 10U
					? ""
					: "[SourceDisksNames.amd64]\r\n1=Fake,,,media\r\n"
					  "[SourceDisksFiles.amd64]\r\nsample.sys=1\r\n") ;	// 具体媒体位置を持つ場合だけ宣言する。
		const std::string inf =
			// 架空元byte。
			makeMaintenanceInf( "AddService=,2", BODIES[index], extra) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", inf)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"media\\sample.sys", "driver")) ;
		const std::array				   entries{OfficialZipEntry{L"sample.inf", inf.size()},
								   OfficialZipEntry{L"sample.cat", 8U},
								   OfficialZipEntry{L"media\\sample.sys", 6U}} ;	// 閉じた架空member。
		const std::array<std::wstring, 2U> seeds{L"Install.NT",
												 L"Install.NT.Services"} ;	// 原明示節だけ。
		MaintenanceInfReferences		   references ;						// 位置は署名の証明ではない。
		const auto						   error =
			inspectMaintenanceInfReferences( workspace, entries, L"sample.inf", seeds,
											MAINTENANCE_POLICY, references) ;	// 非実行の内容観測。
		// 不正pathは不足や署名失敗へ弱めず、全体の空結果で返す。
		if( index == 11U) {
			DRIVERCRATE_EXPECT( context, error != 0 && references.files.empty()) ;
			continue ;
		}

		DRIVERCRATE_EXPECT( context, error == 0) ;
		DRIVERCRATE_EXPECT( context, references.files.size() >= 2U) ;
		DRIVERCRATE_EXPECT( context, references.files.at( 0U).relativePath == L"sample.inf" &&
										references.files.at( 1U).relativePath == L"sample.cat") ;
		// 無参照nullと正当copy、明示Needsのlocal不在をfile不足と混同しない。
		if( index == 0U || index == 1U || index == 2U || index == 8U) {
			DRIVERCRATE_EXPECT( context, references.referenceCoverage ==
											MaintenanceInfReferenceCoverage::COMPLETE) ;
		} else {
			// binary DIRIDはWindowsの展開形が未対応なら位置不明のまま残せる。
			if( index != 3U) {
				DRIVERCRATE_EXPECT( context, references.referenceCoverage ==
												MaintenanceInfReferenceCoverage::INCOMPLETE) ;
			}
		}

		// 正当媒体位置とfile-list別名のsourceを元memberへ結ぶ。
		if( index == 1U || index == 2U) {
			DRIVERCRATE_EXPECT( context, references.sourceFiles ==
											std::vector<std::wstring>{L"media\\sample.sys"}) ;
			DRIVERCRATE_EXPECT(
				context, std::ranges::any_of( references.files, [index]( const auto &file) {
					return file.directive == (index == 1U ? L"CopyFiles" : L"CopyFileSource") &&
						   file.target == L"sample.sys" &&
						   file.location == MaintenanceInfFileLocation::LOCATED ;
				})) ;
		}

		// 未追跡file用途は原節・原directiveと非零診断を保持する。
		if( index == 4U || index == 5U || index == 7U || index == 9U || index == 10U) {
			DRIVERCRATE_EXPECT( context, std::ranges::any_of( references.files, []( const auto &file) {
								   return file.location != MaintenanceInfFileLocation::LOCATED &&
										  file.error != 0 ;
							   })) ;
		}
	}

	OfficialDownloadWorkspace workspace ;	// 同名scalar registryの通常source比較。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"maint-reg-source-test", 620U) == 0) ;
	const std::string inf = makeMaintenanceInf(
		"AddService=,2", "AddReg=Scalar\r\n",
		"[Scalar]\r\nHKR,,,0,1\r\n[SourceDisksNames.amd64]\r\n1=Fake,,,\r\n"
		"[SourceDisksFiles.amd64]\r\nsample.sys=1\r\n") ;	// 作用未評価だけでsource証拠を取り消さない。
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", inf)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
	const std::array entries{
		OfficialZipEntry{L"sample.inf", inf.size()}, OfficialZipEntry{L"sample.cat", 8U},
		OfficialZipEntry{L"sample.sys", 6U}} ;					// 位置棚卸しでは未抽出sourceも明示memberへ結ぶ。
	const std::array<std::wstring, 1U> seeds{L"Install.NT"} ;	// scalar registryだけを辿る。
	MaintenanceInfReferences		   references ;				// 全作用とfile位置coverageは別の状態。
	DRIVERCRATE_EXPECT( context,
					   inspectMaintenanceInfReferences( workspace, entries, L"sample.inf", seeds,
													   MAINTENANCE_POLICY, references) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   references.referenceCoverage == MaintenanceInfReferenceCoverage::COMPLETE) ;
	DRIVERCRATE_EXPECT( context, !references.inventory.coverageGaps.empty()) ;
	const std::array missingSource{OfficialZipEntry{L"sample.inf", inf.size()},
								   OfficialZipEntry{L"sample.cat", 8U}} ;	// 元source欠落。
	DRIVERCRATE_EXPECT( context,
					   inspectMaintenanceInfReferences( workspace, missingSource, L"sample.inf",
													   seeds, MAINTENANCE_POLICY, references) == 0) ;
	DRIVERCRATE_EXPECT( context, references.referenceCoverage ==
										MaintenanceInfReferenceCoverage::INCOMPLETE &&
									references.sourceFiles.empty()) ;
	DRIVERCRATE_EXPECT( context, std::ranges::any_of( references.files, []( const auto &file) {
						   return file.location == MaintenanceInfFileLocation::MISSING &&
								  file.relativePath == L"sample.sys" &&
								  file.error == static_cast<drivercrate::NativeError>(
													HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND)) ;
					   })) ;
}

/** @brief 明示導入先と元sourceの一構成。Windows位置や実device情報は保持しない。 */
struct MaintenanceBinarySourceCase {
	/// 到達DDInstallに置く原copy宣言。空は未到達listの負例。
	std::string_view		   copy{"CopyFiles=Files\r\n"} ;
	/// 同INFのDestinationDirs本文。defaultは別の未対応構成。
	std::string_view		   destinations{"Files=12\r\n"} ;
	/// 到達named listの元行。source別名をdestinationへ潰さない。
	std::string_view		   rows{"source.sys\r\n"} ;
	/// 非実行serviceのbinary原field。すべて架空leafである。
	std::string_view		   binary{"%12%\\source.sys"} ;
	/// SourceDisksFilesの相対subdir。媒体pathとは分ける。
	std::string_view		   sourceDirectory{"payload"} ;
	/// SourceDisksNamesの媒体path。
	std::string_view		   mediaDirectory{"media"} ;
	/// 明示SourceDisksFilesを持つ場合true。
	bool					   sourceDeclared{true} ;
	/// SourceDisksNamesの媒体を持つ場合true。
	bool					   mediaDeclared{true} ;
	/// 元source memberを欠落させる場合true。
	bool					   missingMember{} ;
	/// 位置観測だけの期待。
	MaintenanceInfFileLocation location{MaintenanceInfFileLocation::LOCATED} ;
	/// 元位置診断。未対応で0ならWindowsの非零原診断を要求し、OS間で固定しない。
	NativeError				   locationError{} ;
	/// 入力・容量等の全体拒否を期待する場合のHRESULT。
	NativeError				   callError{} ;
	/// 固定memberとは別の元API相対位置を要求する場合だけ非空。
	std::wstring_view		   expectedRelativePath ;
	/// 同じpackage内の元INF親。空ならpackage root。
	std::wstring_view		   infParent ;
	/// 実在する元member directory。媒体／source不正をfile作成へ渡さない。
	std::wstring_view		   memberDirectory{L"media\\payload"} ;
	/// 元SourceDisksFilesに同名二行を残す場合true。
	bool					   duplicateSource{} ;
	/// 固定member一覧へ同位置を二件残す場合true。
	bool					   duplicateMember{} ;
	/// 元INFの期待hashだけを不一致にする場合true。
	bool					   changedInfBytes{} ;
} ;

/**
 * @brief 展開済み全path・named固有導入先・明示sourceと合法未対応を実SetupAPIで回帰する。
 * @param[in,out] context 一processの有限assertion集計。
 * @note 位置観測でありCAT署名・導入先充足・端末適合を実行しない。
 */
void testMaintenanceBinarySources( TestContext &context)
{
	constexpr NativeError UNSUPPORTED = static_cast<drivercrate::NativeError>(
		// 位置未対応。
		HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
	constexpr NativeError DUPLICATE = static_cast<drivercrate::NativeError>(
		// 先頭選択しない診断。
		HRESULT_FROM_WIN32( ERROR_DUP_NAME)) ;
	constexpr std::array CASES{
		MaintenanceBinarySourceCase{},
		MaintenanceBinarySourceCase{.destinations = "Files=11\r\n", .binary = "%11%\\source.sys"},
		MaintenanceBinarySourceCase{.rows	= "renamed.sys,source.sys\r\n",
									.binary = "%12%\\renamed.sys"},
		MaintenanceBinarySourceCase{.destinations = "Files=12,fixture\r\n",
									.rows		  = "renamed.sys,source.sys\r\n",
									.binary		  = "%12%\\fixture\\renamed.sys"},
		MaintenanceBinarySourceCase{.destinations = "fIlEs=12,fixture\r\n",
									.rows		  = "RENAMED.SYS,source.sys\r\n",
									.binary		  = "%12%\\fixture\\renamed.sys"},
		// 同HINF全値・同名・source一行・subdir一致の正例だけを元source成功へ変更する。
		MaintenanceBinarySourceCase{.destinations = "Files=13,payload\r\n",
									.binary		  = "%13%\\payload\\source.sys"},
		MaintenanceBinarySourceCase{.destinations  = "Files=13,payload\r\n",
									.rows		   = "renamed.sys,source.sys\r\n",
									.binary		   = "%13%\\payload\\renamed.sys",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = UNSUPPORTED},
		MaintenanceBinarySourceCase{.destinations  = "Files=13,other\r\n",
									.binary		   = "%13%\\other\\source.sys",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = UNSUPPORTED},
		MaintenanceBinarySourceCase{.destinations  = "Files=10\r\n",
									.binary		   = "%10%\\source.sys",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = UNSUPPORTED},
		MaintenanceBinarySourceCase{.destinations  = "Files=%MissingDirid%\r\n",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = UNSUPPORTED},
		MaintenanceBinarySourceCase{.destinations  = "Files=+12\r\n",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = UNSUPPORTED},
		MaintenanceBinarySourceCase{.destinations = "Files=broken\r\n",
									.callError	  = static_cast<drivercrate::NativeError>(
										   HRESULT_FROM_WIN32( ERROR_INVALID_DATA))},
		MaintenanceBinarySourceCase{.destinations = "Files=4294967296\r\n",
									.callError	  = static_cast<drivercrate::NativeError>(
										   HRESULT_FROM_WIN32( ERROR_ARITHMETIC_OVERFLOW))},
		MaintenanceBinarySourceCase{.destinations  = "Unused=12\r\n",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = UNSUPPORTED},
		MaintenanceBinarySourceCase{.copy		   = "",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = UNSUPPORTED},
		MaintenanceBinarySourceCase{.destinations  = "Files=12,fixture\r\n",
									.binary		   = "%12%\\unrelated\\source.sys",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = UNSUPPORTED},
		MaintenanceBinarySourceCase{.binary		   = "Q:\\fictional\\source.sys",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = UNSUPPORTED},
		MaintenanceBinarySourceCase{.destinations  = "DefaultDestDir=12\r\n",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = UNSUPPORTED},
		MaintenanceBinarySourceCase{.copy		   = "CopyFiles=@source.sys\r\n",
									.destinations  = "DefaultDestDir=12\r\n",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = UNSUPPORTED},
		MaintenanceBinarySourceCase{.destinations  = "Files=12\r\nFiles=12\r\n",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = DUPLICATE},
		MaintenanceBinarySourceCase{.rows	= "renamed.sys,source.sys\r\nrenamed.sys,other.sys\r\n",
									.binary = "%12%\\renamed.sys",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = DUPLICATE},
		MaintenanceBinarySourceCase{.copy		   = "CopyFiles=Files,SecondFiles\r\n",
									.destinations  = "Files=12\r\nSecondFiles=12\r\n",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = DUPLICATE},
		MaintenanceBinarySourceCase{.binary = "source.sys"},
		MaintenanceBinarySourceCase{.missingMember = true,
									.location	   = MaintenanceInfFileLocation::MISSING,
									.locationError = static_cast<drivercrate::NativeError>(
										HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND))},
		MaintenanceBinarySourceCase{.sourceDeclared = false,
									.location		= MaintenanceInfFileLocation::UNSUPPORTED},
		MaintenanceBinarySourceCase{.mediaDeclared = false,
									.location	   = MaintenanceInfFileLocation::MISSING,
									.locationError = static_cast<drivercrate::NativeError>(
										HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND)),
									.expectedRelativePath = L"payload\\source.sys"},
		MaintenanceBinarySourceCase{.destinations = "Files=12,..\\escape\r\n",
									.callError	  = static_cast<drivercrate::NativeError>(
										   HRESULT_FROM_WIN32( ERROR_INVALID_DATA))},
		MaintenanceBinarySourceCase{.binary	   = "%12%\\..\\escape\\source.sys",
									.callError = static_cast<drivercrate::NativeError>(
										HRESULT_FROM_WIN32( ERROR_INVALID_DATA))},
		MaintenanceBinarySourceCase{.rows	   = "renamed.sys,..\\escape.sys\r\n",
									.binary	   = "%12%\\renamed.sys",
									.callError = static_cast<drivercrate::NativeError>(
										HRESULT_FROM_WIN32( ERROR_INVALID_DATA))},
		MaintenanceBinarySourceCase{.rows	   = "renamed.sys,source.sys:payload\r\n",
									.binary	   = "%12%\\renamed.sys",
									.callError = static_cast<drivercrate::NativeError>(
										HRESULT_FROM_WIN32( ERROR_INVALID_DATA))},
		MaintenanceBinarySourceCase{.rows	   = "source.sys:payload,source.sys\r\n",
									.binary	   = "%12%\\source.sys:payload",
									.callError = static_cast<drivercrate::NativeError>(
										HRESULT_FROM_WIN32( ERROR_INVALID_DATA))},
		MaintenanceBinarySourceCase{.destinations  = "Files=12,,ignored\r\n",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = UNSUPPORTED},
		MaintenanceBinarySourceCase{.binary		   = "%MissingBinary%\\source.sys",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = UNSUPPORTED},
		MaintenanceBinarySourceCase{.binary		   = "\\\\fictional\\share\\source.sys",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = UNSUPPORTED},
		MaintenanceBinarySourceCase{.binary		   = "\\\\?\\C:\\source.sys",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = UNSUPPORTED},
		MaintenanceBinarySourceCase{.destinations  = "UnknownKey=12\r\n",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = UNSUPPORTED},
		MaintenanceBinarySourceCase{.destinations = "Files=\r\n",
									.callError	  = static_cast<drivercrate::NativeError>(
										   HRESULT_FROM_WIN32( ERROR_INVALID_DATA))},
		MaintenanceBinarySourceCase{.sourceDirectory = "..\\escape",
									.callError		 = static_cast<drivercrate::NativeError>(
										  HRESULT_FROM_WIN32( ERROR_INVALID_DATA))},
		MaintenanceBinarySourceCase{.mediaDirectory = "..\\media",
									.callError		= static_cast<drivercrate::NativeError>(
										 HRESULT_FROM_WIN32( ERROR_INVALID_DATA))},
		MaintenanceBinarySourceCase{.binary	   = ".\\source.sys",
									.callError = static_cast<drivercrate::NativeError>(
										HRESULT_FROM_WIN32( ERROR_INVALID_DATA))},
		MaintenanceBinarySourceCase{.destinations = "Files=13,payload\r\n",
									.binary		  = "%13%\\payload\\..\\source.sys",
									.callError	  = static_cast<drivercrate::NativeError>(
										   HRESULT_FROM_WIN32( ERROR_INVALID_DATA))},
		MaintenanceBinarySourceCase{.destinations = "Files=13,payload\r\n",
									.binary		  = "%13%\\payload\\.\\source.sys",
									.callError	  = static_cast<drivercrate::NativeError>(
										   HRESULT_FROM_WIN32( ERROR_INVALID_DATA))},
		MaintenanceBinarySourceCase{.destinations = "Files=13,payload\r\n",
									.binary		  = "%13%\\payload\\source.sys:payload",
									.callError	  = static_cast<drivercrate::NativeError>(
										   HRESULT_FROM_WIN32( ERROR_INVALID_DATA))},
		MaintenanceBinarySourceCase{.copy = "CopyFiles=Files,SecondFiles\r\n",
									.destinations =
										"Files=13,payload\r\nSecondFiles=13,payload\r\n",
									.binary		   = "%13%\\payload\\source.sys",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = DUPLICATE},
		MaintenanceBinarySourceCase{.copy		   = "CopyFiles=Files,SecondFiles\r\n",
									.destinations  = "Files=13,payload\r\nSecondFiles=10\r\n",
									.binary		   = "%13%\\payload\\source.sys",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = UNSUPPORTED},
		// 原45構成を残し、相対13の元source条件だけを独立に追加する。
		MaintenanceBinarySourceCase{.destinations	 = "Files=13\r\n",
									.binary			 = "%13%\\source.sys",
									.sourceDirectory = "",
									.mediaDirectory	 = "",
									.memberDirectory = L""},
		MaintenanceBinarySourceCase{.destinations = "fIlEs=13,pAyLoAd\r\n",
									.rows		  = "SOURCE.SYS,source.sys\r\n",
									.binary		  = "%13%\\PAYLOAD\\SOURCE.SYS",
									.infParent	  = L"driver"},
		MaintenanceBinarySourceCase{.destinations	 = "Files=13,payload\r\n",
									.binary			 = "%13%\\payload\\source.sys",
									.mediaDirectory	 = "",
									.memberDirectory = L"payload"},
		MaintenanceBinarySourceCase{.destinations = "Files=13,payload\r\n",
									.binary		  = ".\\payload\\source.sys"},
		MaintenanceBinarySourceCase{.destinations	= "Files=13,payload\r\n",
									.binary			= "%13%\\payload\\source.sys",
									.sourceDeclared = false,
									.location		= MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError	= UNSUPPORTED},
		MaintenanceBinarySourceCase{.destinations  = "Files=13,payload\r\n",
									.binary		   = "%13%\\payload\\source.sys",
									.missingMember = true,
									.location	   = MaintenanceInfFileLocation::MISSING,
									.locationError = static_cast<drivercrate::NativeError>(
										HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND))},
		MaintenanceBinarySourceCase{.destinations	 = "Files=13,payload\r\n",
									.binary			 = "%13%\\payload\\source.sys",
									.location		 = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError	 = DUPLICATE,
									.duplicateSource = true},
		MaintenanceBinarySourceCase{.destinations  = "Files=13,payload\r\n",
									.rows		   = "source.sys\r\nsource.sys\r\n",
									.binary		   = "%13%\\payload\\source.sys",
									.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError = DUPLICATE},
		MaintenanceBinarySourceCase{
			.copy = "CopyFiles=Files,SecondFiles\r\n",
			.destinations =
				"Files=13,payload\r\nSecondFiles=13,payload\r\nSecondFiles=13,payload\r\n",
			.binary		   = "%13%\\payload\\source.sys",
			.location	   = MaintenanceInfFileLocation::UNSUPPORTED,
			.locationError = DUPLICATE},
		MaintenanceBinarySourceCase{.destinations	 = "Files=13,payload\r\n",
									.binary			 = "%13%\\payload\\source.sys",
									.callError		 = static_cast<NativeError>( E_INVALIDARG),
									.duplicateMember = true},
		MaintenanceBinarySourceCase{.destinations  = "Files=13,payload\r\n",
									.binary		   = "%13%\\payload\\source.sys",
									.mediaDeclared = false,
									.location	   = MaintenanceInfFileLocation::MISSING,
									.locationError = static_cast<drivercrate::NativeError>(
										HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND)),
									.expectedRelativePath = L"payload\\source.sys"},
		MaintenanceBinarySourceCase{.destinations	 = "Files=13\r\n",
									.rows			 = "renamed.sys,source.sys\r\n",
									.binary			 = "%13%\\renamed.sys",
									.sourceDirectory = "",
									.mediaDirectory	 = "",
									.location		 = MaintenanceInfFileLocation::UNSUPPORTED,
									.locationError	 = UNSUPPORTED,
									.memberDirectory = L""},
		MaintenanceBinarySourceCase{.destinations	 = "Files=13,payload\r\n",
									.binary			 = "%13%\\payload\\source.sys",
									.callError		 = static_cast<NativeError>( TRUST_E_BAD_DIGEST),
									.changedInfBytes = true},
	} ; // 原45と追加13を分け、合法未対応・不正・曖昧を削減しない。
	static_assert( CASES.size() == 58U) ;
	// 全構成を実SetupAPI・固定memberへ結び、source位置とbinary原値を別に確認する。
	for( std::size_t index = 0U; index < CASES.size(); ++index) {
		const auto				 &testCase = CASES[index] ;	// 静的ASCII構成だけを同期借用する。
		OfficialDownloadWorkspace workspace ;				// この構成の架空byteだけを所有する。
		DRIVERCRATE_EXPECT( context,
						   workspace.initialize( L"maint-binary-source", 1200U + index) == 0) ;
		std::string extra = "[ServiceInstall]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\n"
							"ServiceBinary=" +
							std::string( testCase.binary) + "\r\n[Files]\r\n" +
							std::string( testCase.rows) +
							"[SecondFiles]\r\nsource.sys\r\n[DestinationDirs]\r\n" +
							// 他OS節は到達listの根拠にしない。
							std::string( testCase.destinations) ;
		extra += "[OtherOS.NTx86]\r\nCopyFiles=ForeignFiles\r\n[ForeignFiles]\r\nsource.sys\r\n" ;
		// 媒体の欠落をsource節不在と別にする。
		if( testCase.mediaDeclared) {
			extra += "[SourceDisksNames.amd64]\r\n1=Fictional,,," +
					 std::string( testCase.mediaDirectory) + "\r\n" ;
		}

		// 元source宣言の全位置を残し、別名copyのdestinationで照会しない。
		if( testCase.sourceDeclared) {
			extra += "[SourceDisksFiles.amd64]\r\nsource.sys=1," +
					 std::string( testCase.sourceDirectory) + "\r\nother.sys=1," +
					 std::string( testCase.sourceDirectory) + "\r\n" ;
			// 同名source行をそのまま残し、APIの先頭選択を一意性の証明にしない。
			if( testCase.duplicateSource) {
				extra += "source.sys=1," + std::string( testCase.sourceDirectory) + "\r\n" ;
			}
		}

		const std::string  inf = makeMaintenanceInf( "AddService=FictionalService,2,ServiceInstall",
													testCase.copy, extra) ;	// 元一INF。
		const std::wstring parentPrefix =
			testCase.infParent.empty()
				? std::wstring{}
				: std::wstring( testCase.infParent) + L"\\" ;		// 元INF親だけの固定prefix。
		const std::wstring infPath = parentPrefix + L"sample.inf" ;	// 今回の元INF相対位置。
		const std::wstring catPath = parentPrefix + L"sample.cat" ;	// 同じ元INF親のCAT位置。
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, infPath, inf)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, catPath, "unsigned")) ;
		const std::wstring memberPrefix =
			parentPrefix + std::wstring( testCase.memberDirectory) +
			(testCase.memberDirectory.empty() ? L""
											  : L"\\") ;				// 不正媒体pathを使わない固定member親。
		const std::wstring sourcePath = memberPrefix + L"source.sys" ;	// 同じ原memberの正式名。
		const std::wstring otherPath  = memberPrefix + L"other.sys" ;	// 異source曖昧の独立member。
		std::vector<OfficialZipEntry> entries{
			{infPath, inf.size()}, {catPath, 8U}, {otherPath, 6U}} ;	// 閉じた元集合。
		// 元byte差の拒否はnamed13の位置照合より前の全体境界で維持する。
		if( testCase.changedInfBytes) {
			entries.front().sha256.assign( 64U, L'0') ;
		}

		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, otherPath, "second")) ;
		// 明示member欠落だけを変え、元INFのsource参照を消さない。
		if( !testCase.missingMember) {
			DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, sourcePath, "driver")) ;
			entries.push_back( {sourcePath, 6U}) ;
			// 固定memberの同位置衝突を先頭候補へ絞らない。
			if( testCase.duplicateMember) {
				entries.push_back( {sourcePath, 6U}) ;
			}
		}

		const std::array<std::wstring, 2U> seeds{L"Install.NT",
												 L"Install.NT.Services"} ;	// 元明示選択。
		MaintenanceInfReferences		   references ;						// 位置はbyte署名の成功ではない。
		const NativeError				   error = inspectMaintenanceInfReferences(
			 workspace, entries, infPath, seeds, MAINTENANCE_POLICY, references) ;	// 非実行観測。
		// DIRID13と媒体未宣言の初回差は同じ元INFでAPI段階だけを診断し、pathを表示しない。
		if( index == 5U || index == 6U || index == 7U || index == 25U) {
			const HINF raw = SetupOpenInfFileW( workspace.path( infPath).c_str(), nullptr,
											   INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											   nullptr) ;	// 直後にRAIIへ所有を移す。
			const std::unique_ptr<void, decltype( &SetupCloseInfFile)> diagnostic(
				raw == INVALID_HANDLE_VALUE ? nullptr : raw,
				&SetupCloseInfFile) ;	// 全経路で元HINFを閉じる。
			// 同じINFを開けた場合だけ元field／directory／media APIの状態を照合する。
			if( diagnostic) {
				INFCONTEXT line{} ;	// 元ServiceBinary行の同期context。
				const BOOL found =
					SetupFindFirstLineW( diagnostic.get(), L"ServiceInstall", L"ServiceBinary",
										&line) ;	// 元行を明示して取得する。
				DWORD stringRequired{} ;			// 元field必要長。
				SetLastError( ERROR_SUCCESS) ;
				const BOOL stringRead =
					found ? SetupGetStringFieldW( &line, 1U, nullptr, 0U, &stringRequired)
						  : FALSE ;							// 第一段階だけを観測する。
				const DWORD stringError = GetLastError() ;	// 元field APIの直後診断。
				DWORD		targetRequired{} ;				// 元named directory必要長。
				SetLastError( ERROR_SUCCESS) ;
				const BOOL targetRead =
					SetupGetTargetPathW( diagnostic.get(), nullptr, L"Files", nullptr, 0U,
										&targetRequired) ;	// defaultを使用しない明示照会。
				const DWORD targetError = GetLastError() ;	// target APIの直後診断。
				UINT		sourceId{} ;					// 元媒体identity。
				DWORD		sourceRequired{} ;				// 元SourceDisksFiles subdir必要長。
				SetLastError( ERROR_SUCCESS) ;
				const BOOL sourceRead = SetupGetSourceFileLocationW(
					diagnostic.get(), nullptr, L"source.sys", &sourceId, nullptr, 0U,
					&sourceRequired) ;						// 元source名だけを使う。
				const DWORD sourceError = GetLastError() ;	// source APIの直後診断。
				DWORD		mediaRequired{} ;				// 元媒体path必要長。
				SetLastError( ERROR_SUCCESS) ;
				const BOOL mediaRead =
					SetupGetSourceInfoW( diagnostic.get(), sourceId, SRCINFO_PATH, nullptr, 0U,
										&mediaRequired) ;	// 媒体未宣言の既定値を別に確認する。
				const DWORD	 mediaError = GetLastError() ;	// 媒体APIの直後診断。
				std::wstring binaryValue ;					// 形だけを数値で出力し、具体的pathを表示しない。
				std::wstring targetValue ;					// 同じnamed entryの形だけを比較する。
				// 有限必要長を確定した元fieldだけを第二段階で取得する。
				if( stringRead && stringRequired != 0U && stringRequired <= 4096U) {
					std::vector<wchar_t> buffer(
						stringRequired) ;	// 終端込みの元必要長だけを確保する。
					// 全field取得が成功した場合だけ形を観測する。
					if( SetupGetStringFieldW( &line, 1U, buffer.data(), stringRequired, nullptr)) {
						binaryValue = buffer.data() ;
					}
				}

				// 同じ一INFのnamed targetを有限bufferへ取得し、fieldと分けて観測する。
				if( targetRead && targetRequired != 0U && targetRequired <= 4096U) {
					std::vector<wchar_t> buffer( targetRequired) ;	// 終端込みのtarget必要長。
					// 全directory取得が成功した場合だけ形を比較する。
					if( SetupGetTargetPathW( diagnostic.get(), nullptr, L"Files", buffer.data(),
										   targetRequired, nullptr)) {
						targetValue = buffer.data() ;
					}
				}

				std::cout << "Binary source diagnostic: case " << index << ", field " << stringRead
						  << "/" << stringError << "/" << stringRequired << ", target "
						  << targetRead << "/" << targetError << "/" << targetRequired
						  << ", source " << sourceRead << "/" << sourceError << "/"
						  << sourceRequired << ", media " << mediaRead << "/" << mediaError << "/"
						  << mediaRequired << ", fieldDot " << binaryValue.starts_with( L".\\")
						  << ", targetDot " << targetValue.starts_with( L".\\") << ", fieldDrive "
						  << (binaryValue.size() >= 3U && binaryValue[1] == L':')
						  << ", targetDrive "
						  << (targetValue.size() >= 3U && targetValue[1] == L':') << '\n' ;
			}
		}

		context.expect( error == testCase.callError,
					   "binary source call case " + std::to_string( index) + " error " +
						   std::to_string( error),
					   __FILE__, __LINE__) ;
		// 全体拒否の部分観測を成功へ残さない。
		if( testCase.callError != 0) {
			DRIVERCRATE_EXPECT( context, references.files.empty() && references.infSha256.empty()) ;
			continue ;
		}

		const auto count = std::ranges::count_if( references.files, []( const auto &file) {
			return file.directive == L"ServiceBinary" ;
		}) ; // 観測欠落を空guardで成功にしない具体用途数。
		DRIVERCRATE_EXPECT( context, count == 1) ;
		// 一参照を得られなかった場合は不一致を保持して範囲外参照を避ける。
		if( count != 1) {
			continue ;
		}

		const auto binary = std::ranges::find_if( references.files, []( const auto &file) {
			return file.directive == L"ServiceBinary" ;
		}) ; // 既に非空と確認した元用途。
		DRIVERCRATE_EXPECT( context, !binary->target.empty()) ;
		DRIVERCRATE_EXPECT( context, binary->section == L"ServiceInstall" &&
										binary->directive == L"ServiceBinary") ;
		// 新相対正例は元全targetを保持し、literal DIRIDの逆証明を要求しない。
		if( (index == 5U || index >= 45U) &&
		   testCase.location == MaintenanceInfFileLocation::LOCATED) {
			DRIVERCRATE_EXPECT( context, binary->target.starts_with( L".\\") &&
											binary->target != L"source.sys") ;
		}

		const bool expectedError =
			testCase.location == MaintenanceInfFileLocation::UNSUPPORTED &&
					testCase.locationError == 0
				? binary->error != 0
				: binary->error == testCase.locationError ;	// 元Windows診断の独立期待。
		context.expect( binary->location == testCase.location && expectedError,
					   "binary source location case " + std::to_string( index) + " state " +
						   std::to_string( static_cast<int>( binary->location)) + " error " +
						   std::to_string( binary->error),
					   __FILE__, __LINE__) ;
		DRIVERCRATE_EXPECT( context, references.referenceCoverage ==
										(testCase.location == MaintenanceInfFileLocation::LOCATED
											 ? MaintenanceInfReferenceCoverage::COMPLETE
											 : MaintenanceInfReferenceCoverage::INCOMPLETE)) ;
		DRIVERCRATE_EXPECT( context, !std::ranges::any_of( references.inventory.visitedSections,
														 []( const auto &section) {
															 return section == L"ForeignFiles" ;
														 })) ;
		// 固定member位置を得た時だけ元source名を要求し、destination別名へ書き換えない。
		if( testCase.location == MaintenanceInfFileLocation::LOCATED ||
		   testCase.location == MaintenanceInfFileLocation::MISSING) {
			DRIVERCRATE_EXPECT( context,
							   binary->relativePath == (testCase.expectedRelativePath.empty()
															? std::wstring_view( sourcePath)
															: testCase.expectedRelativePath)) ;
		}

		// 別名正例のbinary原値を元source名で上書きしない。
		if( index == 2U || index == 3U || index == 4U) {
			DRIVERCRATE_EXPECT( context, binary->target.ends_with( L"renamed.sys")) ;
		}
	}

	std::cout << "Maintenance binary source cases: baseline 45, relative13 13\n" ;
	// metadataの全行とfieldにも既存上限を適用し、未知keyで容量を回避させない。
	for( const bool excessiveLines : {false, true}) {
		std::string destinations = "Files=12" ;	// 正常なnamed entryから境界だけを追加する。
		// 一行64 fieldの上限＋1を原値のまま作る。
		if( !excessiveLines) {
			destinations.append( 64U, ',') ;
			destinations += "\r\n" ;
		} else {
			destinations += "\r\n" ;
			// 未到達keyの4,097行も一つの共同予算へ含める。
			for( std::size_t row = 0U; row < 4097U; ++row) {
				destinations += "Unknown" + std::to_string( row) + "=12\r\n" ;
			}
		}

		const std::string inf = makeMaintenanceInf(
			"AddService=FictionalService,2,ServiceInstall", "CopyFiles=Files\r\n",
			"[Files]\r\nsource.sys\r\n[ServiceInstall]\r\nServiceType=1\r\nStartType=3\r\n"
			"ErrorControl=1\r\nServiceBinary=%12%\\source.sys\r\n[SourceDisksNames.amd64]\r\n"
			"1=Fictional,,,\r\n[SourceDisksFiles.amd64]\r\nsource.sys=1\r\n[DestinationDirs]\r\n" +
				destinations) ;					// 上限試験でも元sourceを明示する。
		OfficialDownloadWorkspace workspace ;	// 架空過大INFだけを一scopeで所有する。
		DRIVERCRATE_EXPECT(
			context, workspace.initialize( L"maint-binary-limit", 1290U + excessiveLines) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", inf)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
		const std::array				   entries{OfficialZipEntry{L"sample.inf", inf.size()},
								   OfficialZipEntry{L"sample.cat", 8U},
								   OfficialZipEntry{L"source.sys", 6U}} ;					// 位置だけの閉集合。
		const std::array<std::wstring, 2U> seeds{L"Install.NT", L"Install.NT.Services"} ;	// 明示名。
		MaintenanceInfReferences		   references ;										// 上限拒否は必ず空結果にする。
		DRIVERCRATE_EXPECT(
			context,
			inspectMaintenanceInfReferences( workspace, entries, L"sample.inf", seeds,
											MAINTENANCE_POLICY, references) ==
				static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW))) ;
		DRIVERCRATE_EXPECT( context, references.files.empty() &&
										references.inventory.visitedSections.empty()) ;
	}
}

/**
 * @brief 500 named listと500 binaryを同じINFの共同上限内で位置照合し、時間を記録する。
 * @param[in,out] context 一processの有限assertion集計。
 * @note 元sourceは一架空fileへ共有する。全候補比較を保持し、実directoryをopenしない。
 */
void testMaintenanceBinarySourceCapacity( TestContext &context)
{
	constexpr std::size_t COUNT = 500U ;					// 1,024節／4,096行を越えない閉じた容量構成。
	std::string			  install ;							// 一行最大64 fieldで500 listを明示する原DDInstall。
	std::string			  services ;						// 全namedを補助flags0として構造へ結ぶ宣言。
	std::string			  sections ;						// 各copy／serviceを原名で一意に持つ架空節。
	std::string destinations = "[DestinationDirs]\r\n" ;	// named固有entryだけの原metadata。
	// 全500を同じ一INFへ組み、分割による上限resetをしない。
	for( std::size_t index = 0U; index < COUNT; ++index) {
		const std::string suffix = std::to_string( index) ;	// 架空名称だけの有限識別子。
		// 一行64 listを越える前に新しいCopyFiles宣言を開始する。
		if( index % 64U == 0U) {
			install += "CopyFiles=" ;
		} else {
			install += "," ;
		}

		install += "Files" + suffix ;
		// 現行field上限と末尾終端を維持する。
		if( index % 64U == 63U || index + 1U == COUNT) {
			install += "\r\n" ;
		}

		services += "AddService=FictionalAux" + suffix + ",0,Service" + suffix + "\r\n" ;
		sections += "[Files" + suffix + "]\r\ntarget" + suffix + ".sys,source.sys\r\n" +
					"[Service" + suffix +
					"]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\n" +
					"ServiceBinary=%12%\\target" + suffix + ".sys\r\n" ;
		destinations += "Files" + suffix + "=12\r\n" ;
	}

	const std::string inf = makeMaintenanceInf(
		services, install,
		sections + destinations +
			"[SourceDisksNames.amd64]\r\n1=Fictional,,,\r\n[SourceDisksFiles.amd64]\r\nsource.sys=1\r\n") ;	// 元一INF。
	// この容量構成の架空byteだけを同期所有する。
	OfficialDownloadWorkspace workspace ;
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"maint-binary-capacity", 1299U) == 0) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", inf)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"source.sys", "driver")) ;
	const std::array				   entries{OfficialZipEntry{L"sample.inf", inf.size()},
							   OfficialZipEntry{L"sample.cat", 8U},
							   OfficialZipEntry{L"source.sys", 6U}} ;					// 元source一件の閉集合。
	const std::array<std::wstring, 2U> seeds{L"Install.NT", L"Install.NT.Services"} ;	// 原明示選択。
	MaintenanceInfReferences		   references ;										// 署名の証拠とは互換でない位置だけ。
	const auto		  started = std::chrono::steady_clock::now() ;						// この同期APIの開始時刻。
	const NativeError error =
		inspectMaintenanceInfReferences( workspace, entries, L"sample.inf", seeds,
										MAINTENANCE_POLICY, references) ;	// 一度の容量観測。
	const double seconds = std::chrono::duration<double>( std::chrono::steady_clock::now() - started)
							   .count() ;	// 実完了時間だけを記録する。
	DRIVERCRATE_EXPECT( context, error == 0) ;
	DRIVERCRATE_EXPECT( context,
					   references.referenceCoverage == MaintenanceInfReferenceCoverage::COMPLETE) ;
	const auto binaries = std::ranges::count_if( references.files, []( const auto &file) {
		return file.directive == L"ServiceBinary" ;
	}) ; // 空guardで欠落を成功へ補完しない主分母。
	DRIVERCRATE_EXPECT( context, binaries == static_cast<std::ptrdiff_t>( COUNT)) ;
	DRIVERCRATE_EXPECT( context, references.inventory.visitedSections.size() <= 1024U &&
									references.inventory.scannedLines <= 4096U) ;
	DRIVERCRATE_EXPECT( context, references.sourceFiles == std::vector<std::wstring>{L"source.sys"}) ;
	// 全500の原binary用途が同じ明示sourceへ一意に結べたことを確認する。
	for( const auto &file : references.files) {
		// 具体的な全binaryに位置・元診断・元sourceを要求する。
		if( file.directive == L"ServiceBinary") {
			DRIVERCRATE_EXPECT( context, file.location == MaintenanceInfFileLocation::LOCATED &&
											file.error == 0 && file.relativePath == L"source.sys" &&
											!file.target.empty()) ;
		}
	}

	DRIVERCRATE_EXPECT( context, seconds < 60.0) ;
	std::cout << "Maintenance binary capacity: lists " << COUNT << ", binaries " << binaries
			  << ", sections " << references.inventory.visitedSections.size() << ", lines "
			  << references.inventory.scannedLines << ", seconds " << seconds << '\n' ;
}

/** @brief 一つの架空archiveへ格納する所有byteとASCII正式名。 */
struct MaintenanceDependencyZipFile {
	/// 架空の元member名。実Windows fileを複写しない。
	std::string name ;
	/// このfixtureだけの元byte列。
	std::string bytes ;
} ;

/**
 * @brief 閉じた架空member集合をMinizの非実行archiveへまとめる。
 * @param[in] files fixtureが所有する元byteと一意相対名。
 * @return 全成功時のZIP byte。生成失敗はfixture例外とする。
 * @throws std::runtime_error Miniz初期化・確定失敗。
 */
[[nodiscard]] std::string makeMaintenanceDependencyArchive(
	std::span<const MaintenanceDependencyZipFile> files)
{
	mz_zip_archive writer{} ;	// この関数だけの非実行memory writer。
	// fixture生成失敗をparser成功やskipにしない。
	if( mz_zip_writer_init_heap( &writer, 0U, 0U) == 0) {
		throw std::runtime_error( "dependency ZIP initialize") ;
	}

	bool added = true ;	// 全memberの追加を要求する。
	// 架空memberだけを原順で格納し、外部fileを開かない。
	for( const auto &file : files) {
		added = added && mz_zip_writer_add_mem( &writer, file.name.c_str(), file.bytes.data(),
											   file.bytes.size(), MZ_NO_COMPRESSION) != 0 ;
	}

	void	   *bytes{} ;	// 確定直後に単独RAIIへ移すMiniz buffer。
	std::size_t size{} ;	// 確定ZIP byte数。
	const bool	finalized =
		added && mz_zip_writer_finalize_heap_archive( &writer, &bytes, &size) != 0 ;	// 全確定。
	const std::unique_ptr<void, decltype( &mz_free)> owned( bytes, &mz_free) ;			// 全経路で解放する。
	const bool ended = mz_zip_writer_end( &writer) != 0 ;								// string確保前にwriterを解放する。
	// 一memberの失敗でも部分archiveを検査へ渡さない。
	if( !finalized || !ended || owned == nullptr || size == 0U) {
		throw std::runtime_error( "dependency ZIP finalize") ;
	}

	return {static_cast<const char *>( owned.get()), size} ;
}

/**
 * @brief 明示空sourceとnull参照の位置・必要byte・全現在OS選択を独立に確認する。
 * @param[in,out] context 一processの有限assertion集計。
 * @note 架空PortsのClass名policyとsource境界だけを比較し、dummy CATを署名成功にしない。
 *       内容構造の成功は端末適合・導入許可を発行しない。
 */
void testMaintenanceSourceMatrix( TestContext &context)
{
	constexpr OfficialDriverClosurePolicy SOURCE_POLICY{
		.zipPolicy				   = {1024U * 1024U, 1024U * 1024U, 4U * 1024U * 1024U, 16U},
		.cabPolicy				   = {1024U * 1024U, 1024U * 1024U, 4U * 1024U * 1024U, 16U},
		.infPolicy				   = MAINTENANCE_POLICY,
		.maximumInfCount		   = 1U,
		.maximumClosureFiles	   = 16U,
		.maximumClosureBytes	   = 4U * 1024U * 1024U,
		.maximumExpansionRatio	   = 200U,
		.maximumNestedArchiveDepth = 1U} ;	// この六fixtureに必要な有限上限だけを使用する。
	// 無参照空source・参照完備・空source参照・byte欠落・source不在・後続選択を全て確認する。
	for( std::size_t scenario = 0U; scenario < 6U; ++scenario) {
		const bool emptySource =
			// 宣言は存在し行は0。
			scenario == 0U || scenario == 2U || scenario == 5U ;
		const bool sourcePresent = scenario != 4U ;	// source不在を明示空と区別する。
		const bool payloadPresent =
			// 架空必要byteの有無。
			scenario == 1U || scenario == 2U || scenario == 5U ;
		const std::string extra =
			(sourcePresent ? std::string( "[SourceDisksNames.amd64]\r\n1=Fake,,,\r\n"
										 "[SourceDisksFiles.amd64]\r\n") +
								 (emptySource ? "" : "sample.sys=1\r\n")
						   : "") +
			std::string( scenario == 5U ? "[Second.NT]\r\nCopyFiles=@sample.sys\r\n"
										 "[Second.NT.Services]\r\nAddService=,2\r\n"
									   : "") ;	// 他OSの不正fixtureは既存helperへ保持する。
		std::string inf = makeMaintenanceInf(
			"AddService=,2", scenario == 0U || scenario == 5U ? "" : "CopyFiles=@sample.sys\r\n",
			extra,
			// 架空元byte。
			scenario == 5U ? "Second=Second,ROOT\\FICTIONAL_SOURCE_0002\r\n" : "") ;
		inf.replace( inf.find( "Class=System"), std::string_view( "Class=System").size(),
					"Class=Ports") ;
		MaintenanceInfStructure structure ;	// 元全選択とsourceの不在／空集合を保持する。
		DRIVERCRATE_EXPECT( context,
						   inspectMaintenanceFixture( context, inf, structure, payloadPresent) == 0) ;
		DRIVERCRATE_EXPECT( context, structure.parser.state == MaintenanceInspectionState::PASSED) ;
		DRIVERCRATE_EXPECT( context, structure.sourceSectionPresent == sourcePresent) ;
		DRIVERCRATE_EXPECT( context, structure.sourceFileNames.size() ==
										(sourcePresent && !emptySource ? 1U : 0U)) ;
		DRIVERCRATE_EXPECT( context, structure.installs.size() == (scenario == 5U ? 2U : 1U)) ;
		DRIVERCRATE_EXPECT( context, structure.contentKind ==
										(scenario == 0U ? MaintenanceInfContentKind::NULL_DRIVER
														: MaintenanceInfContentKind::MIXED)) ;
		// 後続現在OS選択の参照を先頭nullの空集合へ落とさず、元節名へ結ぶ。
		if( scenario == 5U) {
			DRIVERCRATE_EXPECT(
				context,
				structure.installs.at( 0U).contentKind == MaintenanceInfContentKind::NULL_DRIVER &&
					structure.installs.at( 1U).inventory.selectedInstallSection == L"Second.NT" &&
					structure.installs.at( 1U).contentKind == MaintenanceInfContentKind::MIXED) ;
		}

		std::vector<MaintenanceDependencyZipFile> files{
			{"sample.inf", inf}, {"sample.cat", "unsigned"}} ;	// root INF／CATの元memberは必須。
		// 正例と位置未対応caseだけに元payloadを置き、byte存在でsource宣言を補完させない。
		if( payloadPresent) {
			files.push_back( {"sample.sys", "driver"}) ;
		}

		const std::string archive = makeMaintenanceDependencyArchive( files) ;	// 架空閉じた元ZIP。
		OfficialDownloadWorkspace source ;										// source元byteはこのscopeで単独所有する。
		DRIVERCRATE_EXPECT( context,
						   source.initialize( L"maint-source-matrix", 700U + scenario) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( source, L"payload.zip", archive)) ;
		std::wstring hash ;	// 同じ元byteを通常／保守双方へ結ぶ。
		DRIVERCRATE_EXPECT( context, computeFileSha256( source.path( L"payload.zip"), hash) == 0) ;
		const DriverArchiveInput input{700U + scenario, source.path( L"payload.zip"), archive.size(),
									   hash} ;	// 由来なし。
		const std::array<std::wstring_view, 1U> selected{
			L"sample.inf"} ;					// 一rootを一runで検査する。
		OfficialDownloadWorkspace workspace ;	// この保守閉包だけを所有する。
		MaintenanceDriverClosure  closure ;		// 構造の成功を導入型へ変換しない。
		const NativeError		  error = extractMaintenanceDriverClosure(
			{&input, OfficialDriverArchiveFormat::ZIP, {}, selected, L"maint-source-out"},
			SOURCE_POLICY, workspace, closure) ;	// 非実行の有限内容観測。
		DRIVERCRATE_EXPECT( context, error == 0) ;
		// fixtureの全体拒否後に部分配列を借用しない。
		if( error != 0) {
			continue ;
		}

		DRIVERCRATE_EXPECT( context, closure.references.size() == 1U) ;
		const auto &references = closure.references.at( 0U) ;	// 同じ一rootの全seed棚卸し。
		const auto	coverage =
			 scenario <= 1U
				 ? MaintenanceInfReferenceCoverage::COMPLETE
				 : MaintenanceInfReferenceCoverage::INCOMPLETE ;	// file位置と署名の成否を分ける。
		DRIVERCRATE_EXPECT( context, references.sourceSectionPresent == sourcePresent) ;
		DRIVERCRATE_EXPECT( context, references.referenceCoverage == coverage &&
										closure.structure.referenceCoverage == coverage) ;
		DRIVERCRATE_EXPECT( context, references.sourceFiles.size() == (scenario == 1U ? 1U : 0U)) ;
		// null＋copyはsource位置または具体的欠落を保持し、fileを空集合へ消さない。
		if( scenario > 0U) {
			const auto copy = std::ranges::find_if( references.files, []( const auto &file) {
				return file.directive == L"CopyFiles" && file.target == L"sample.sys" ;
			}) ; // 同じ原用途だけを照合する。
			DRIVERCRATE_EXPECT( context, copy != references.files.end()) ;
			// 原用途を取得できた場合だけ位置と元診断を比較する。
			if( copy != references.files.end()) {
				DRIVERCRATE_EXPECT(
					context,
					copy->location ==
						(scenario == 1U
							 ? MaintenanceInfFileLocation::LOCATED
							 : (scenario == 3U ? MaintenanceInfFileLocation::MISSING
											   : MaintenanceInfFileLocation::UNSUPPORTED))) ;
				DRIVERCRATE_EXPECT( context, scenario == 1U ? copy->error == 0 : copy->error != 0) ;
				// 宣言済みの必要byte欠落は未対応位置と区別し、元file診断を保つ。
				if( scenario == 3U) {
					DRIVERCRATE_EXPECT(
						context, copy->relativePath == L"sample.sys" &&
									 copy->error == static_cast<drivercrate::NativeError>(
														HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND))) ;
				}

				// 全Modelsから選ばれた後続節の原用途であることを確認する。
				if( scenario == 5U) {
					DRIVERCRATE_EXPECT( context, copy->section == L"Second.NT") ;
				}
			}
		}

		MaintenanceDriverPackageInspection maintenance ;	// 外向き結果も通常routeとは独立する。
		DRIVERCRATE_EXPECT( context, inspectMaintenanceDriverPackage(
										input, OfficialDriverArchiveFormat::ZIP, maintenance) == 0) ;
		DRIVERCRATE_EXPECT( context, maintenance.infs.size() == 1U) ;
		// 同じrootの観測が得られた場合だけunknown・通常routeを比較する。
		if( maintenance.infs.size() == 1U) {
			const auto &row = maintenance.infs.front() ;	// 端末適合を照合していないDTO。
			DRIVERCRATE_EXPECT( context, row.parser.state == MaintenanceInspectionState::PASSED &&
											row.contentKind == structure.contentKind &&
											row.referenceCoverage == coverage) ;
			DRIVERCRATE_EXPECT( context,
							   row.applicability.state == MaintenanceInspectionState::NOT_CHECKED &&
								   row.applicability.error == 0 &&
								   row.integrity.state != MaintenanceInspectionState::PASSED) ;
			DRIVERCRATE_EXPECT( context,
							   row.installRoute.state ==
								   (scenario == 1U ? MaintenanceInspectionState::PASSED
												   : MaintenanceInspectionState::UNSUPPORTED)) ;
		}

		CommonDriverPackageInspection normal ;	// 空sourceや必要byte欠落を従来通常policyが拒否する。
		DRIVERCRATE_EXPECT( context, inspectCommonDriverPackage(
										input, OfficialDriverArchiveFormat::ZIP, normal) == 0) ;
		DRIVERCRATE_EXPECT( context, normal.infs.size() == 1U) ;
		// 内容認識で通常source必須・署名の拒否段階を変更させない。
		if( normal.infs.size() == 1U) {
			DRIVERCRATE_EXPECT( context,
							   normal.infs.front().state ==
								   (scenario == 1U ? CommonInfInspectionState::SIGNATURE_REJECTED
												   : CommonInfInspectionState::CLOSURE_REJECTED)) ;
			DRIVERCRATE_EXPECT( context, normal.infs.front().error != 0) ;
		}
	}
}

/**
 * @brief sourceなしnullと有限package依存の抽出・未知／FAILED保持を確認する。
 * @param[in,out] context 一processの有限assertion集計。
 * @note dummy CATは常に実署名の負例。実device列挙・staging・導入・追加取得を呼ばない。
 */
void testMaintenanceDependencyClosure( TestContext &context)
{
	constexpr OfficialDriverClosurePolicy DEPENDENCY_POLICY{
		.zipPolicy				   = {1024U * 1024U, 1024U * 1024U, 4U * 1024U * 1024U, 256U},
		.cabPolicy				   = {1024U * 1024U, 1024U * 1024U, 4U * 1024U * 1024U, 256U},
		.infPolicy				   = MAINTENANCE_POLICY,
		.maximumInfCount		   = 1U,
		.maximumClosureFiles	   = 256U,
		.maximumClosureBytes	   = 4U * 1024U * 1024U,
		.maximumExpansionRatio	   = 200U,
		.maximumNestedArchiveDepth = 1U} ;	// 一root選択と候補closureの上限を区別する。
	// 無参照・参照付き・依存の原形を小matrixで比較する。
	for( std::size_t scenario = 0U; scenario < 11U; ++scenario) {
		std::string componentBody ;	// 核が扱わない明示component／コピーINFの二形。
		// 二用途だけを追加し、他部品の展開・全作用解析へ広げない。
		if( scenario == 9U || scenario == 10U) {
			componentBody = scenario == 9U
								? "AddComponent=FictionalComponent,0,ComponentSection\r\n"
								: "CopyINF=fixture-dep.inf\r\n" ;
		}

		const std::string install =
			scenario == 1U ? "CopyFiles=@sample.sys\r\n"
						   : (scenario >= 2U ? "Include=fixture-dep.inf\r\nNeeds=Shared\r\n"
											 : "") ;	// 原base節。
		const std::string services =
			"AddService=,2\r\n" +
			std::string( scenario == 4U
							? "Needs=Shared.Services\r\n"
							: (scenario == 3U
								   ? "Include=fixture-dep.inf\r\nNeeds=Shared.Services\r\n"
								   : "")) ;	// 同節条件。
		const std::string peer =
			"[Version]\r\nSignature=\"$Windows NT$\"\r\nCatalogFile=fixture-dep.cat\r\n"
			"[Shared]\r\n" +
			std::string( scenario == 6U ? "Needs=Shared\r\n" : "") +
			"[Shared.Services]\r\n[Shared.NTx86]\r\nUnknownOtherOS=ignored\r\n" ;	// 明示節と別OS。
		const std::string extra =
			scenario == 7U ? "[Second.NT]\r\nInclude=fixture-missing.inf\r\nNeeds=Absent\r\n"
						   : (scenario == 8U ? "[Install.NT.HW]\r\nUnknownFileUse=mystery.dll\r\n"
											 : "") ;	// 後続選択と付随節。
		const std::string inf = makeMaintenanceInf(
			services, scenario >= 9U ? componentBody : install,
			extra + (scenario == 9U ? "[ComponentSection]\r\nFeatureScore=0xF0\r\n" : ""),
			scenario == 7U ? "Second=Second,ROOT\\FICTIONAL_DEPENDENCY_0002\r\n"
						   : "") ;	// 全現在OS構造。
		std::vector<MaintenanceDependencyZipFile> files{
			{"driver/sample.inf", inf},
			{"driver/sample.cat", "unsigned"}} ;	// root INF／CATは常に元memberへ固定する。
		// 参照付きnullはsource未宣言でも実file存在を無参照の根拠にしない。
		if( scenario == 1U) {
			files.push_back( {"driver/sample.sys", "driver"}) ;
		}

		// 未発見case以外は、同名候補のbyteを閉じたarchiveだけへ置く。
		if( (scenario >= 3U && scenario < 9U) || scenario == 10U) {
			files.push_back( {"driver/fixture-dep.inf", peer}) ;
			files.push_back( {"driver/fixture-dep.cat", "unsigned"}) ;
		}

		// 元親とpackage rootの二候補を先頭選択で隠さない。
		if( scenario == 5U) {
			files.push_back( {"fixture-dep.inf", peer}) ;
			files.push_back( {"fixture-dep.cat", "unsigned"}) ;
		}

		const std::string		  archive = makeMaintenanceDependencyArchive( files) ;	// 架空元ZIP。
		OfficialDownloadWorkspace source ;												// 元ZIPの単独所有者。
		DRIVERCRATE_EXPECT( context,
						   source.initialize( L"maint-dependency-test", 650U + scenario) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( source, L"payload.zip", archive)) ;
		std::wstring hash ;	// 実元byteへ固定するidentity。
		DRIVERCRATE_EXPECT( context, computeFileSha256( source.path( L"payload.zip"), hash) == 0) ;
		const DriverArchiveInput input{650U + scenario, source.path( L"payload.zip"), archive.size(),
									   hash} ;										// 由来なし。
		const std::array<std::wstring_view, 1U> selected{L"driver\\sample.inf"} ;	// 正式一rootだけ。
		OfficialDownloadWorkspace				workspace ;							// 今回の内容閉包だけを単独所有する。
		MaintenanceDriverClosure				closure ;							// 通常導入型へ暗黙変換しない。
		const auto								error = extractMaintenanceDriverClosure(
			 {&input, OfficialDriverArchiveFormat::ZIP, {}, selected, L"maint-dep-output"},
			 DEPENDENCY_POLICY, workspace, closure) ;	// 実device APIへ接続しない。
		DRIVERCRATE_EXPECT( context, error == 0) ;
		// fixture拒否の後に部分配列を参照して試験processを破壊しない。
		if( error != 0) {
			continue ;
		}

		DRIVERCRATE_EXPECT( context,
						   closure.content.packages.size() == 1U && !closure.references.empty()) ;
		DRIVERCRATE_EXPECT(
			context, closure.structure.rootIntegrity.state == MaintenanceInspectionState::FAILED &&
						 closure.integrity.state == MaintenanceInspectionState::FAILED) ;
		DRIVERCRATE_EXPECT( context, closure.dependency.dependency.plan.deviceApplicability ==
											InfDependencyEvidence::NOT_CHECKED &&
										closure.dependency.dependency.plan.installRoute ==
											InfDependencyEvidence::NOT_CHECKED) ;
		// 無参照nullでもroot INF／CATを抽出し、署名失敗を未検査で消さない。
		if( scenario == 0U) {
			DRIVERCRATE_EXPECT( context, closure.content.entries.size() == 2U &&
											closure.references.front().sourceFiles.empty()) ;
			DRIVERCRATE_EXPECT( context, closure.structure.contentKind ==
												MaintenanceInfContentKind::NULL_DRIVER &&
											closure.structure.referenceCoverage ==
												MaintenanceInfReferenceCoverage::COMPLETE &&
											closure.structure.dependency.state ==
												MaintenanceInfDependencyState::NONE) ;
		}
		// 位置が全て確定したpackageは署名・由来不足だけでcoverageを取り消さない。
		else if( scenario == 3U) {
			DRIVERCRATE_EXPECT( context, closure.structure.referenceCoverage ==
											MaintenanceInfReferenceCoverage::COMPLETE) ;
		} else {
			DRIVERCRATE_EXPECT( context, closure.structure.referenceCoverage ==
											MaintenanceInfReferenceCoverage::INCOMPLETE) ;
		}

		// 未発見・別節借用・曖昧・循環を具体理由付きで保持する。
		if( scenario == 2U || scenario == 4U || scenario == 5U || scenario == 6U || scenario == 7U) {
			const auto reason =
				scenario == 5U ? InfDependencyReason::AMBIGUOUS
							   : (scenario == 6U ? InfDependencyReason::CYCLE
												 : InfDependencyReason::MISSING) ;	// 原不足種類。
			DRIVERCRATE_EXPECT( context, closure.structure.dependency.state ==
											MaintenanceInfDependencyState::UNRESOLVED) ;
			DRIVERCRATE_EXPECT( context, std::ranges::any_of( closure.dependency.dependency.edges,
															[reason]( const auto &edge) {
																return edge.reason == reason ;
															})) ;
		}

		// 核の未対応依存をNONEへ射影せず、原用途と独立診断を保持する。
		if( scenario == 9U || scenario == 10U) {
			DRIVERCRATE_EXPECT( context,
							   closure.dependency.dependency.edges.empty() &&
								   closure.structure.dependency.state ==
									   MaintenanceInfDependencyState::OBSERVED &&
								   closure.structure.dependency.observedReferenceCount > 0U) ;
			DRIVERCRATE_EXPECT(
				context,
				std::ranges::any_of( closure.references.front().files, [scenario]( const auto &file) {
					return file.directive == (scenario == 9U ? L"AddComponent" : L"CopyINF") &&
						   file.location == MaintenanceInfFileLocation::UNSUPPORTED &&
						   file.error != 0 ;
				})) ;
		}

		// 同節base／Servicesの独立Needsは原名のまま観測し、裸local由来を昇格しない。
		if( scenario == 3U) {
			DRIVERCRATE_EXPECT( context, closure.structure.dependency.state ==
												MaintenanceInfDependencyState::OBSERVED &&
											closure.references.size() == 2U) ;
			DRIVERCRATE_EXPECT( context,
							   std::ranges::any_of(
								   closure.dependency.dependency.sections, []( const auto &section) {
									   return section.section == L"Shared.Services" &&
											  section.state == InfDependencyReadState::PRESENT ;
								   })) ;
			DRIVERCRATE_EXPECT(
				context, std::ranges::all_of(
							 closure.dependency.dependency.documents, []( const auto &document) {
								 return document.origin != InfDependencyOrigin::PACKAGE ||
										document.provenance == InfDependencyEvidence::NOT_CHECKED ;
							 })) ;
		}

		MaintenanceDriverPackageInspection
			aggregate ;	// 閉包の各軸を保守DTOへ結ぶ。導入型は持たない。
		DRIVERCRATE_EXPECT( context, inspectMaintenanceDriverPackage(
										input, OfficialDriverArchiveFormat::ZIP, aggregate) == 0) ;
		DRIVERCRATE_EXPECT( context, !aggregate.infs.empty()) ;
		const auto projected = std::ranges::find_if( aggregate.infs, [&closure]( const auto &row) {
			return row.infSha256 == closure.structure.infSha256 ;
		}) ; // 同じroot byteを借用し、別INF行を先頭選択で代用しない。
		DRIVERCRATE_EXPECT( context, projected != aggregate.infs.end()) ;
		// 同じrootの射影が取得できた場合だけ独立軸と元診断を全て比較する。
		if( projected != aggregate.infs.end()) {
			DRIVERCRATE_EXPECT( context,
							   projected->parser.state == closure.structure.parser.state &&
								   projected->parser.error == closure.structure.parser.error) ;
			DRIVERCRATE_EXPECT( context, projected->contentKind == closure.structure.contentKind &&
											projected->referenceCoverage ==
												closure.structure.referenceCoverage) ;
			DRIVERCRATE_EXPECT( context, projected->rootIntegrity.state ==
												closure.structure.rootIntegrity.state &&
											projected->rootIntegrity.error ==
												closure.structure.rootIntegrity.error) ;
			DRIVERCRATE_EXPECT( context, projected->integrity.state == closure.integrity.state &&
											projected->integrity.error == closure.integrity.error) ;
			DRIVERCRATE_EXPECT(
				context, projected->dependency.state == closure.structure.dependency.state &&
							 projected->dependency.reason == closure.structure.dependency.reason &&
							 projected->dependency.error == closure.structure.dependency.error) ;
			DRIVERCRATE_EXPECT( context,
							   projected->dependency.observedReferenceCount ==
									   closure.structure.dependency.observedReferenceCount &&
								   projected->dependency.resolvedInfCount ==
									   closure.structure.dependency.resolvedInfCount) ;
			DRIVERCRATE_EXPECT( context,
							   projected->dependenciesChecked ==
									   (projected->dependency.state !=
										MaintenanceInfDependencyState::NOT_CHECKED) &&
								   projected->hasExternalDependencies ==
									   (projected->dependenciesChecked &&
										projected->dependency.observedReferenceCount != 0U)) ;
			DRIVERCRATE_EXPECT( context, projected->inspectedBytes == closure.content.expandedBytes) ;
			DRIVERCRATE_EXPECT( context, projected->installRoute.state ==
												MaintenanceInspectionState::UNSUPPORTED &&
											projected->installRoute.error != 0) ;
		}

		DRIVERCRATE_EXPECT(
			context, std::ranges::all_of( aggregate.infs, []( const auto &row) {
				return row.integrity.state != MaintenanceInspectionState::PASSED &&
					   row.applicability.state == MaintenanceInspectionState::NOT_CHECKED &&
					   (row.dependency.state != MaintenanceInfDependencyState::NOT_CHECKED ||
						(!row.dependenciesChecked && !row.hasExternalDependencies)) ;
			})) ;
		// 初回の同じ元byteで取消しとhash差の全体破棄だけを有限確認する。
		if( scenario == 0U) {
			MaintenanceDriverPackageInspection rejected ;	// 部分状態を公開してはならない全体拒否。
			DRIVERCRATE_EXPECT(
				context,
				inspectMaintenanceDriverPackage( input, OfficialDriverArchiveFormat::ZIP, rejected,
												[] { return true ; }) ==
					static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))) ;
			DRIVERCRATE_EXPECT( context, rejected.infs.empty() && rejected.archiveSha256.empty() &&
											rejected.inspectedBytes == 0U) ;
			DriverArchiveInput changed = input ;	// 元fileは変更せず、誤ったhash指定だけを作る。
			changed.sha256.assign( 64U, L'0') ;
			DRIVERCRATE_EXPECT(
				context, inspectMaintenanceDriverPackage( changed, OfficialDriverArchiveFormat::ZIP,
														 rejected) != 0) ;
			DRIVERCRATE_EXPECT( context, rejected.infs.empty() && rejected.archiveSha256.empty() &&
											rejected.inspectedBytes == 0U) ;
		}
	}

	std::string								  install ;	// root＋64候補で一run64 INF上限＋1を作る。
	std::vector<MaintenanceDependencyZipFile> files{
		{"sample.cat", "unsigned"}} ;	// 架空CATだけの初期集合。
	// 64の全明示名を一行64 field以内で与え、必要候補を切り捨てさせない。
	for( std::size_t index = 0U; index < 64U; ++index) {
		const std::string name =
			"fixture-cap-" + std::to_string( index) + ".inf" ;	// 実OSと無関係な架空名。
		install += (index == 0U ? "Include=" : ",") + name ;
		files.push_back( {name, "[Version]\r\nSignature=\"$Windows NT$\"\r\n"}) ;
	}

	install += "\r\n" ;
	files.push_back( {"sample.inf", makeMaintenanceInf( "AddService=,2", install)}) ;
	const std::string archive = makeMaintenanceDependencyArchive( files) ;	// 65 INFの有限原入力。
	OfficialDownloadWorkspace source ;										// 原入力だけの単独所有者。
	DRIVERCRATE_EXPECT( context, source.initialize( L"maint-dep-cap-test", 680U) == 0) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( source, L"payload.zip", archive)) ;
	std::wstring hash ;	// 実byteの元hash。
	DRIVERCRATE_EXPECT( context, computeFileSha256( source.path( L"payload.zip"), hash) == 0) ;
	const DriverArchiveInput				input{680U, source.path( L"payload.zip"), archive.size(),
									  hash} ;							// 一閉包の固定入力。
	const std::array<std::wstring_view, 1U> selected{L"sample.inf"} ;	// 一root選択。
	OfficialDownloadWorkspace				workspace ;					// 上限拒否の部分fileはscope終了で破棄する。
	MaintenanceDriverClosure				closure ;					// 全体失敗では空。
	DRIVERCRATE_EXPECT(
		context,
		extractMaintenanceDriverClosure(
			{&input, OfficialDriverArchiveFormat::ZIP, {}, selected, L"maint-dep-cap-out"},
			DEPENDENCY_POLICY, workspace, closure) ==
			static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW))) ;
	DRIVERCRATE_EXPECT( context, closure.references.empty() &&
									closure.dependency.dependency.documents.empty() &&
									closure.content.entries.empty()) ;
	const std::array<std::wstring_view, 2U> multiple{
		L"sample.inf", L"fixture-cap-0.inf"} ;		// 複数runでの予算回避をしない。
	OfficialDownloadWorkspace multipleWorkspace ;	// 拒否前に初期化しない。
	DRIVERCRATE_EXPECT(
		context,
		extractMaintenanceDriverClosure(
			{&input, OfficialDriverArchiveFormat::ZIP, {}, multiple, L"maint-multi-out"},
			DEPENDENCY_POLICY, multipleWorkspace, closure) ==
			static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED))) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_driver_package_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOfficialDriverPackageTests( TestContext &context)
{
	testValidInfPackage( context) ;
	testPrinterInfWithoutSys( context) ;
	testGenericSoftwareDeviceBoundary( context) ;
	testGenericMobileFlashPayloadRejection( context) ;
	testGenericVirtualMachinePayloadRejection( context) ;
	testWiaImageInfWithoutSys( context) ;
	testInfPolicyRejections( context) ;
	testInfSignaturePolicy( context) ;
	testInfContentRejections( context) ;
	testArchitectureSpecificModelsSelection( context) ;
	testDeviceIdentityMatching( context) ;
	testEmptyCoInstallerReferences( context) ;
	testMaintenanceInfReferences( context) ;
	testMaintenanceRelativeReferences( context) ;
	testInfOnlyIntegrityBoundary( context) ;
	testMaintenanceNullFlags( context) ;
	testMaintenanceStructureBoundaries( context) ;
	testMaintenanceNamedServices( context) ;
	testMaintenanceClassSeparation( context) ;
	testMaintenanceStructureInputFailures( context) ;
	testMaintenanceExplicitReferences( context) ;
	testMaintenanceBinarySources( context) ;
	testMaintenanceBinarySourceCapacity( context) ;
	testMaintenanceSourceMatrix( context) ;
	testMaintenanceDependencyClosure( context) ;
}

} // namespace drivercrate::test
