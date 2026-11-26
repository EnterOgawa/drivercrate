//------------------------------------------------------------------------------
/**
 * @file official_driver_package_tests.cpp
 * @brief 公式標準INF driver package単体試験実装
 * @version 01.42.02
 * @date 2026/09/03
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  新規作成
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  CAT member／PnP照合試験追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  DriverVer日付試験追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  汎用Provider名とscript拒否試験追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  SYS不要Printer INF試験追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  SYS不要WIA Image INF試験追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  圧縮実行program拒否試験追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Printer複合package拒否試験追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Firmware混入拒否試験追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Virtual audio拒否試験追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Virtual capture拒否試験追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Mobile flash payload拒否試験追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Virtual device境界試験追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  x64と異architectureの混在Models選択試験を追加
 * Ver.01.02.00 Shunji Ogawa  2026/10/04  空CoInstaller参照の限定受理と実動作・不正参照の拒否試験を追加
 * Ver.01.03.00 Shunji Ogawa  2026/10/05  保守参照の非承認・媒体path・CopyINF拒否境界を検証
 * Ver.01.04.00 Shunji Ogawa  2026/10/05  保守の現在directory解決とtraversal維持を検証
 * Ver.01.05.00 Shunji Ogawa  2026/10/05  空sourceの未署名拒否と通常導入policyの維持を検証
 * Ver.01.06.00 Shunji Ogawa  2026/10/07  保守専用の全Models・null flagsと通常policy不変を回帰
 * Ver.01.07.00 Shunji Ogawa  2026/10/07  明示seedの参照・有限依存抽出と旧caller非昇格を回帰
 * Ver.01.08.00 Shunji Ogawa  2026/10/07  保守独立状態の共通射影と通常routeの隔離を回帰
 * Ver.01.09.00 Shunji Ogawa  2026/10/07  空source・null参照の全選択と未知Class名policyを回帰
 * Ver.01.10.00 Shunji Ogawa  2026/10/07  named必須構造・補助flagsと限定nullの分離を回帰
 * Ver.01.11.00 Shunji Ogawa  2026/10/07  展開済みbinaryの明示named導入先・別名・不足と有限境界を回帰
 * Ver.01.11.01 Shunji Ogawa  2026/10/07  named13の非absolute展開と媒体未宣言の元API診断・不足を回帰
 * Ver.01.12.00 Shunji Ogawa  2026/10/07  一意な相対named13の元source正例とsource／copy／key／member衝突を回帰
 * Ver.01.12.01 Shunji Ogawa  2026/10/24  必須解析に合わせ試験の所有・型・失敗制御を明示
 * Ver.01.13.00 Shunji Ogawa  2026/11/03  共通公式packageの手動索引と選択内容検査を接続
 * Ver.01.14.00 Shunji Ogawa  2026/11/03  System/SecurityDevicesの共通内容とlocal限定を分離確認
 * Ver.01.15.00 Shunji Ogawa  2026/11/03  標準Componentのnull・Type1・原copy境界の回帰を追加
 * Ver.01.16.00 Shunji Ogawa  2026/11/03  有界large archiveと共有内容保持・標準serviceを接続
 * Ver.01.16.01 Shunji Ogawa  2026/11/07  現非実行policyと旧fixture期待を照合
 * Ver.01.16.02 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.16.03 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.17.00 Shunji Ogawa  2026/11/15  storage内容専用・全潜在null import・opaque Modelsと導入非互換を回帰
 * Ver.01.18.00 Shunji Ogawa  2026/11/16  MTDの正式対と内容用途の分離を検証
 * Ver.01.19.00 Shunji Ogawa  2026/11/17  MTD serviceと型付きHW属性の正負を検証
 * Ver.01.20.00 Shunji Ogawa  2026/11/17  標準TapeDriveの正式対・元拒否・共通署名境界を検証
 * Ver.01.21.00 Shunji Ogawa  2026/11/17  宣言Server scopeとpolicy・Models・identityを分離接続
 * Ver.01.21.01 Shunji Ogawa  2026/11/18  正規空Strings値とrequired nullの明示空source境界を回帰
 * Ver.01.22.00 Shunji Ogawa  2026/11/18  限定registry-onlyの実reader/閉包と導入拒否を有限回帰
 * Ver.01.22.01 Shunji Ogawa  2026/11/18  単独1-byteコメントとinline/設定/controlのraw proof境界を回帰
 * Ver.01.23.00 Shunji Ogawa  2026/11/20  収集専用の節訪問とHKRバイナリ値の有限枠を検証
 * Ver.01.24.00 Shunji Ogawa  2026/11/21  収集の一意行と延べ行の境界および従来上限を検証
 * Ver.01.25.00 Shunji Ogawa  2026/11/21  メディアチェンジャーの端末選択用途と保護条件を検証
 * Ver.01.26.00 Shunji Ogawa  2026/11/21  HDCの全選択と共有AutoLoggerの収集検査を検証
 * Ver.01.27.00 Shunji Ogawa  2026/11/21  元HDCの管理者領域の選択構造と用途境界を検証
 * Ver.01.28.00 Shunji Ogawa  2026/11/21  関連サービスの既存値保持付き文字列と負例を検証
 * Ver.01.29.00 Shunji Ogawa  2026/11/21  IDEブートの元作用と起動グループの境界を検証
 * Ver.01.30.00 Shunji Ogawa  2026/11/21  CopyINFの末尾空欄と不正な空参照を検証
 * Ver.01.31.00 Shunji Ogawa  2026/11/22  選択SCSI基本節の順位と元フィールドを検証
 * Ver.01.32.00 Shunji Ogawa  2026/11/22  Modelsの型別原順と一意ID上限を検証
 * Ver.01.33.00 Shunji Ogawa  2026/11/22  公式対象と元Models全行の有限読取りを検証
 * Ver.01.34.00 Shunji Ogawa  2026/11/22  公式対象の導入節と兼用・欠損の拒否を検証
 * Ver.01.35.00 Shunji Ogawa  2026/11/22  物理PCI Ethernet属性の一意性と値を対照検証
 * Ver.01.36.00 Shunji Ogawa  2026/11/22  公式範囲の共有レジストリ節と起点別の観測を検証
 * Ver.01.36.01 Shunji Ogawa  2026/11/22  無線設定の表示ラベルと実ファイル用途を対照
 * Ver.01.37.00 Shunji Ogawa  2026/11/22  ストレージ補助サービスの権限とイベントの拒否を検証
 * Ver.01.38.00 Shunji Ogawa  2026/11/23  自動起動補助サービスの元情報と端末作用の分離を検証
 * Ver.01.39.00 Shunji Ogawa  2026/11/23  トリアージAutoLoggerの元モードと選択範囲を対照検証
 * Ver.01.40.00 Shunji Ogawa  2026/11/23  Driver Storeの補助EXEの構文と別配置の拒否を検証
 * Ver.01.41.00 Shunji Ogawa  2026/11/23  イベント用DLLの元コピー先の正例と誤指定を検証
 * Ver.01.41.01 Shunji Ogawa  2026/11/23  必須System補助INFのドット区切り文字列名を検証
 * Ver.01.42.00 Shunji Ogawa  2026/11/24  収集Systemの全サービス走査と実行参照上限を検証
 * Ver.01.42.01 Shunji Ogawa  2026/11/24  空の旧媒体を持つ必須null補助を確認
 * Ver.01.42.02 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * </pre>
 *
 * @note 実在するhardware IDや署名packageを使用せず、SetupAPIのINF構文とfail-closed条件を架空fixtureで検証します
 */
//------------------------------------------------------------------------------

#include "official_driver_package_tests.h"

#include "platform/common_driver_package.h"
#include "platform/generic_inf_package.h"
#include "platform/inf_dependency_native_internal.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_package.h"
#include "platform/official_file_verifier.h"
#include "platform/storage_inf_effects_internal.h"
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

// 保守の構造観測から導入型を暗黙構築できず、署名・bindingを迂回できない
static_assert( !std::is_convertible_v<MaintenanceInfStructure, OfficialInfPackage>) ;
static_assert( !std::is_convertible_v<MaintenanceInfStructure, OfficialDriverClosure>) ;
static_assert( !std::is_convertible_v<MaintenanceInfStructure, CommonInfInspection>) ;
static_assert( !std::is_convertible_v<MaintenanceInfInspection, CommonInfInspection>) ;
static_assert( !std::is_convertible_v<MaintenanceInfReferences, OfficialInfPackage>) ;
static_assert( !std::is_convertible_v<MaintenanceDriverClosure, OfficialDriverClosure>) ;
static_assert( !std::is_constructible_v<CommonInfInspection, MaintenanceInfInspection>) ;
static_assert(
	!std::is_convertible_v<MaintenanceDriverPackageInspection, CommonDriverPackageInspection>) ;
// collector内容を通常導入の型や必要構成計画へ暗黙昇格させません
static_assert( !std::is_constructible_v<CommonInfInspection, CollectorInfContentInspection>) ;
static_assert( !std::is_convertible_v<CollectorInfContentInspection, CommonInfInspection>) ;
static_assert( !std::is_convertible_v<CollectorDriverPackageContent, CommonDriverPackageInspection>) ;

//------------------------------------------------------------------------------
// 定数定義
//------------------------------------------------------------------------------

constexpr std::array ACCEPTED_CLASSES{std::wstring_view( L"Net")} ;	// 試験で許可するclass
constexpr std::array ACCEPTED_PRINTER_CLASS{						// SYS不要試験で許可するclass
											std::wstring_view( L"Printer")} ;
constexpr std::array ACCEPTED_IMAGE_CLASS{	// WIA user-mode試験で許可するclass
										  std::wstring_view( L"Image")} ;
constexpr std::array ACCEPTED_PROVIDERS{	// 許可する架空Provider
										std::wstring_view( L"Fictional Wireless Corporation")} ;
constexpr std::array ACCEPTED_INF_SIGNATURES{	// 架空INFで許可するsignature
											 std::wstring_view( L"$Windows NT$")} ;
constexpr std::array ACCEPTED_SIGNERS{	// 署名negative試験用allowlist
									  std::wstring_view( L"Fictional Driver Signer")} ;
// 保守構造の架空Class。通常policyの許可集合とは独立する
constexpr std::array MAINTENANCE_CLASSES{std::wstring_view( L"Ports"), std::wstring_view( L"System"),
										 std::wstring_view( L"SecurityDevices"),
										 std::wstring_view( L"MultiPortSerial")} ;
// 架空構造の有限policy。署名・実device・導入の成功を注入しない
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
} ; // 全正常fixtureに適用する有限policy

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
	"DiskName=\"Fictional Driver Disk\"\r\n" ;	// 正常な架空x64 network INF

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
	"DiskName=\"Fictional Printer Disk\"\r\n" ;	// SYSを持たない架空Printer INF

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
	"DiskName=\"Fictional Printer Disk\"\r\n" ;	// 実行programを参照する架空Printer INF

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
	"DiskName=\"Fictional Scanner Disk\"\r\n" ;	// SYSなしの架空WIA Image INF

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
	"sample.sys=1\r\n" ;	// 現在x64ではModels sectionを選択できないINF

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
	"sample.sys=1\r\n" ;	// 異architectureを含むがx64用Modelsを明示したINF

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
	"sample.sys=1\r\n" ;	// 未参照programを同じarchiveへ混入する正常構造INF

//------------------------------------------------------------------------------
// 内部関数定義
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Workspaceへ一つの試験fileを書き込む
 *
 * CREATE_NEWされたhandleを必ず閉じ、部分書込みを拒否する
 *
 * @param[in,out] workspace Fileを作成し、scope終了時に削除する領域
 * @param[in] relativePath 安全なASCII相対path
 * @param[in] content Fileへ保存する全byte列
 * @return 全byteを保存できた場合は`true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool writeWorkspaceFile( OfficialDownloadWorkspace &workspace,
									  const std::wstring_view	 relativePath,
									  const std::string_view	 content)
{
	// Win32書込み長の範囲を超えるfixtureは保存しない
	if( content.size() > static_cast<std::size_t>( std::numeric_limits<DWORD>::max())) {
		return false ;
	}

	HANDLE file{INVALID_HANDLE_VALUE} ;	// 本関数がCloseHandleする所有file handle
	// 保護領域でfileを作成できなければ書込みを開始しない
	if( workspace.createFile( relativePath, file) != 0) {
		return false ;
	}

	DWORD	   written{} ;	// WriteFileが保存したbyte数
	const bool result = WriteFile( file, content.data(), static_cast<DWORD>( content.size()),
								  &written, nullptr) != FALSE &&
						// 完全保存結果
						written == content.size() ;
	CloseHandle( file) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正常な架空INF packageの構造検証を確認する
 *
 * 現在x64用Models、文字列展開、PnP ID、CAT、SYS参照をSetupAPIから取得し、未署名CATは署名段階で拒否する
 *
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void testValidInfPackage( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// Scope終了時にfixtureを削除する保護領域
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"inf-test", 101) == 0) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"valid\\sample.inf", VALID_INF)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"valid\\sample.cat", "not-signed")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"valid\\sample.sys", "driver")) ;

	const std::array entries{
		OfficialZipEntry{L"valid\\sample.inf", VALID_INF.size()},
		OfficialZipEntry{L"valid\\sample.cat", 10},
		OfficialZipEntry{L"valid\\sample.sys", 6},
	} ; // ZIP検証済みとして渡す正常file一覧
	OfficialInfPackage package ;	// 検証成功時に設定される構造
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"valid\\sample.inf",
														  POLICY, package) == 0) ;
	DRIVERCRATE_EXPECT( context, package.className == L"Net") ;
	DRIVERCRATE_EXPECT( context, package.providerName == L"Fictional Wireless Corporation") ;
	DRIVERCRATE_EXPECT( context, package.driverDate == L"09/03/2026") ;
	DRIVERCRATE_EXPECT( context, package.driverVersion == L"1.2.3.4") ;
	DRIVERCRATE_EXPECT( context, package.catalogRelativePath == L"valid\\sample.cat") ;
	DRIVERCRATE_EXPECT( context, package.hardwareIds.size() == 2) ;
	DRIVERCRATE_EXPECT( context, package.sourceFiles.size() == 1) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない
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
	} ; // 未署名CATのmemberとして拒否される実在fixture path群
	DRIVERCRATE_EXPECT( context, verifyOfficialCatalogMembers( workspace.path( L"valid\\sample.cat"),
															 memberPaths) != 0) ;
	const std::span<const std::wstring> noMembers ;	// 空入力を拒否するためのmember span
	DRIVERCRATE_EXPECT( context, verifyOfficialCatalogMembers( workspace.path( L"valid\\sample.cat"),
															 noMembers) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief SYS不要Printer INFの限定受理を確認する
 *
 * Printer policyだけがCAT保護対象のGPDを持つINFを受理し、他class、実行program、archive、firmwareへ拡張しない
 *
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void testPrinterInfWithoutSys( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// SYS不要fixtureを所有する保護領域
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
	} ; // SYSを持たないPrinter packageの検証済みentry群
	OfficialInfInspectionPolicy printerPolicy = POLICY ;	// Printer限定の構造policy
	printerPolicy.acceptedClasses			  = ACCEPTED_PRINTER_CLASS ;
	printerPolicy.acceptedProviders			  = {} ;
	printerPolicy.acceptAnyProvider			  = true ;
	printerPolicy.requireDriverBinary		  = false ;
	OfficialInfPackage package ;	// 検証成功時のPrinter metadata
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
	const OfficialInfPackage	printerPackage = package ;	// 後続negative試験後の復元用metadata

	OfficialInfInspectionPolicy sysRequiredPolicy = printerPolicy ;	// 従来のSYS必須policy
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
	} ; // Install直前に拒否する内側archive entry
	DRIVERCRATE_EXPECT(
		context, reverifyGenericInfPackage( workspace, nestedReverifyEntries, printerPackage) != 0) ;
	const std::array firmwareReverifyEntries{
		OfficialZipEntry{L"printer\\device_firmware.bin", 7},
	} ; // Install直前に拒否するfirmware image entry
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
	} ; // 実行programとnested archiveをINFが参照する複合Printer entry群
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, mixedEntries,
														  L"mixed-printer\\printer.inf",
														  printerPolicy, package) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 汎用INFのsoftware device境界を確認する
 *
 * 物理device用INFを維持し、software enumeratorの全許可classを別capabilityの設計完了まで拒否する
 *
 * @param[in,out] context Assertion集計先
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
	} ; // 汎用AV境界だけを検証する架空driver package
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
 * @brief Virtual machine payloadの汎用経路拒否を確認する
 *
 * Driver ZIPへ混在するvirtual disk／appliance imageをscan時とinstall直前の両方でfail-closedに拒否する
 *
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void testGenericVirtualMachinePayloadRejection( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// Install直前再検証の保護領域
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"virtual-payload-test", 109) == 0) ;
	OfficialInfPackage package{
		.className	   = L"Net",
		.providerName  = L"Fictional Virtual Device Corporation",
		.driverVersion = L"1.2.3.4",
		.hardwareIds   = {L"PCI\\VEN_1234&DEV_5678"},
		.sourceFiles   = {L"network\\fictional_network.sys"},
	} ; // Virtual machine payload境界だけを検証する架空package
	constexpr std::array VIRTUAL_PAYLOAD_EXTENSIONS{
		std::wstring_view( L".ova"), std::wstring_view( L".ovf"), std::wstring_view( L".qcow"),
		std::wstring_view( L".qcow2"), std::wstring_view( L".vfd"), std::wstring_view( L".vhd"),
		// 拒否を要求するvirtual
		std::wstring_view( L".vhdx"), std::wstring_view( L".vmdk")} ;
	// payload拡張子
	// 各拡張子を同じ架空packageへ一つずつ混在させ、全形式を有限回検証する
	for( const std::wstring_view extension : VIRTUAL_PAYLOAD_EXTENSIONS) {
		std::wstring payloadPath = L"virtual\\guest_image" ;	// 現在の架空payload path
		payloadPath.append( extension) ;
		package.sourceFiles = {L"network\\fictional_network.sys", payloadPath} ;
		DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;

		const std::array entries{
			OfficialZipEntry{payloadPath, 7},
		} ; // Scan後に混入した現在形式の架空entry
		DRIVERCRATE_EXPECT( context, reverifyGenericInfPackage( workspace, entries, package) != 0) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Mobile flash payloadの汎用経路拒否を確認する
 *
 * USB driverと同梱されたmobile firmware／flash imageをscan時とinstall直前の両方でfail-closedに拒否する
 *
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void testGenericMobileFlashPayloadRejection( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// Install直前再検証の保護領域
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"mobile-flash-test", 108) == 0) ;
	OfficialInfPackage package{
		.className	   = L"USBDevice",
		.providerName  = L"Fictional Mobile Device Corporation",
		.driverVersion = L"1.2.3.4",
		.hardwareIds   = {L"USB\\VID_1234&PID_5678"},
		.sourceFiles   = {L"mobile\\fictional_usb.sys"},
	} ; // Mobile USB driver境界だけを検証する架空package
	constexpr std::array MOBILE_FLASH_EXTENSIONS{
		std::wstring_view( L".ftf"), std::wstring_view( L".img"), std::wstring_view( L".kdz"),
		std::wstring_view( L".ofp"), std::wstring_view( L".pac"), std::wstring_view( L".pit"),
		std::wstring_view( L".sin"),
		// 拒否を要求するmobile flash拡張子
		std::wstring_view( L".tot")} ;
	// 各拡張子を同じ架空packageへ一つずつ混在させ、全形式を有限回検証する
	for( const std::wstring_view extension : MOBILE_FLASH_EXTENSIONS) {
		std::wstring payloadPath = L"mobile\\device_firmware" ;	// 現在の架空payload path
		payloadPath.append( extension) ;
		package.sourceFiles = {L"mobile\\fictional_usb.sys", payloadPath} ;
		DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;

		const std::array entries{
			OfficialZipEntry{payloadPath, 7},
		} ; // Scan後に混入した現在形式の架空entry
		DRIVERCRATE_EXPECT( context, reverifyGenericInfPackage( workspace, entries, package) != 0) ;
	}

	// コピーされる受動データはSYSと共存する通常driverとして評価し、単独では受理しません
	for( const auto extension : {L".bin", L".dfu", L".mbn", L".elf"}) {
		const std::wstring data =
			std::wstring{L"mobile\\device_data"} + extension ;	// 架空の参照fileです
		package.sourceFiles = {L"mobile\\fictional_usb.sys", data} ;
		DRIVERCRATE_EXPECT( context, isGenericInfPackageSupported( package)) ;
		package.sourceFiles = {data} ;
		DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( package)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief SYS不要WIA Image INFの限定受理を確認する
 *
 * CAT保護対象のvendor DLLを持つImage INFだけを受理し、DLLを持たない同classや他classへ条件を拡張しない
 *
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void testWiaImageInfWithoutSys( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// SYS不要WIA fixtureを所有する保護領域
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"wia-image-inf-test", 107) == 0) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"scanner\\scanner.inf", IMAGE_INF)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"scanner\\scanner.cat", "catalog")) ;
	DRIVERCRATE_EXPECT( context,
					   writeWorkspaceFile( workspace, L"scanner\\scanner.dll", "image-driver")) ;

	const std::array entries{
		OfficialZipEntry{L"scanner\\scanner.inf", IMAGE_INF.size()},
		OfficialZipEntry{L"scanner\\scanner.cat", 7},
		OfficialZipEntry{L"scanner\\scanner.dll", 12},
	} ; // SYSを持たないWIA user-mode packageの検証済みentry群
	OfficialInfInspectionPolicy imagePolicy = POLICY ;	// Image限定の構造policy
	imagePolicy.acceptedClasses				= ACCEPTED_IMAGE_CLASS ;
	imagePolicy.acceptedProviders			= {} ;
	imagePolicy.acceptAnyProvider			= true ;
	imagePolicy.requireDriverBinary			= false ;
	OfficialInfPackage package ;	// 検証成功時のWIA metadata
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, entries, L"scanner\\scanner.inf",
												 imagePolicy, package) == 0) ;
	DRIVERCRATE_EXPECT( context, package.className == L"Image") ;
	DRIVERCRATE_EXPECT( context, package.sourceFiles.size() == 1) ;
	DRIVERCRATE_EXPECT( context, isGenericInfPackageSupported( package)) ;
	const OfficialInfPackage	imagePackage = package ;	// 後続negative試験後の復元用metadata

	OfficialInfInspectionPolicy sysRequiredPolicy = imagePolicy ;	// 従来のSYS必須policy
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
 * @brief Policyと参照fileのfail-closed条件を確認する
 *
 * Provider不一致、PnP ID上限、CAT欠落、参照SYS欠落をcandidateへ公開せず拒否する
 *
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void testInfPolicyRejections( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 複数negative fixtureを所有する保護領域
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"inf-test", 102) == 0) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"policy\\sample.inf", VALID_INF)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"policy\\sample.cat", "catalog")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"policy\\sample.sys", "driver")) ;
	const std::array entries{
		OfficialZipEntry{L"policy\\sample.inf", VALID_INF.size()},
		OfficialZipEntry{L"policy\\sample.cat", 7},
		OfficialZipEntry{L"policy\\sample.sys", 6},
	} ; // 正常fileを含むZIP entry群
	// INF publisherとの不一致を再現する、許可publisher集合
	constexpr std::array		WRONG_PROVIDERS{std::wstring_view( L"Another Corporation")} ;
	OfficialInfInspectionPolicy wrongProviderPolicy = POLICY ;	// Provider不一致policy
	wrongProviderPolicy.acceptedProviders			= WRONG_PROVIDERS ;
	OfficialInfPackage package ;	// 失敗時に空へ戻される出力
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"policy\\sample.inf",
														  wrongProviderPolicy, package) != 0) ;
	DRIVERCRATE_EXPECT( context, package.infRelativePath.empty()) ;

	OfficialInfInspectionPolicy anyProviderPolicy = POLICY ;	// CAT保護名を許可する汎用policy
	anyProviderPolicy.acceptedProviders			  = {} ;
	anyProviderPolicy.acceptAnyProvider			  = true ;
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"policy\\sample.inf",
														  anyProviderPolicy, package) == 0) ;
	DRIVERCRATE_EXPECT( context, package.providerName == L"Fictional Wireless Corporation") ;

	OfficialInfInspectionPolicy contradictoryPolicy = POLICY ;	// 二方式を併用する不正policy
	contradictoryPolicy.acceptAnyProvider			= true ;
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"policy\\sample.inf",
														  contradictoryPolicy, package) != 0) ;

	OfficialInfInspectionPolicy missingProviderPolicy = POLICY ;	// 固定allowlist欠落policy
	missingProviderPolicy.acceptedProviders			  = {} ;
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"policy\\sample.inf",
														  missingProviderPolicy, package) != 0) ;

	OfficialInfInspectionPolicy idLimitPolicy = POLICY ;	// ID上限を一件にしたpolicy
	idLimitPolicy.maximumHardwareIds		  = 1 ;
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"policy\\sample.inf",
														  idLimitPolicy, package) != 0) ;

	const std::array missingCatalogEntries{
		OfficialZipEntry{L"policy\\sample.inf", VALID_INF.size()},
		OfficialZipEntry{L"policy\\sample.sys", 6},
	} ; // CATを意図的に除外したentry群
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, missingCatalogEntries,
												 L"policy\\sample.inf", POLICY, package) != 0) ;

	const std::array missingDriverEntries{
		OfficialZipEntry{L"policy\\sample.inf", VALID_INF.size()},
		OfficialZipEntry{L"policy\\sample.cat", 7},
	} ; // INF参照SYSを意図的に除外したentry群
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, missingDriverEntries,
												 L"policy\\sample.inf", POLICY, package) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief INF signatureをProvider固有allowlistで検証する
 *
 * Prolific等の署名済みWin4 INFで使われる`$CHICAGO$`を、明示allowlistの場合だけ受理することを確認する
 *
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void testInfSignaturePolicy( TestContext &context)
{
	std::string				   chicagoInf( VALID_INF) ;				// Signatureだけを変更する架空INF
	constexpr std::string_view WINDOWS_SIGNATURE = "$Windows NT$" ;	// 置換前signature
	constexpr std::string_view CHICAGO_SIGNATURE = "$CHICAGO$" ;	// Providerが明示するsignature
	const std::size_t		   signaturePosition =
		// 固定fixture内の置換位置
		chicagoInf.find( WINDOWS_SIGNATURE) ;
	DRIVERCRATE_EXPECT( context, signaturePosition != std::string::npos) ;
	// INF署名指定が見つからない場合は範囲外編集をせず検証を中止する
	if( signaturePosition == std::string::npos) {
		return ;
	}

	chicagoInf.replace( signaturePosition, WINDOWS_SIGNATURE.size(), CHICAGO_SIGNATURE) ;

	OfficialDownloadWorkspace workspace ;	// Scope終了時にfixtureを削除する保護領域
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"inf-test", 105) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   writeWorkspaceFile( workspace, L"signature\\sample.inf", chicagoInf)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"signature\\sample.cat", "catalog")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"signature\\sample.sys", "driver")) ;
	const std::array entries{
		OfficialZipEntry{L"signature\\sample.inf", chicagoInf.size()},
		OfficialZipEntry{L"signature\\sample.cat", 7},
		OfficialZipEntry{L"signature\\sample.sys", 6},
	} ; // CHICAGO signature fixtureのZIP entry群
	constexpr std::array		CHICAGO_SIGNATURES{	// この試験で明示的に許可するsignature
											   std::wstring_view( L"$CHICAGO$")} ;
	OfficialInfInspectionPolicy chicagoPolicy = POLICY ;	// CHICAGOだけを許可するpolicy
	chicagoPolicy.acceptedSignatures		  = CHICAGO_SIGNATURES ;
	OfficialInfPackage package ;	// 成功時に設定され、拒否時に空へ戻る構造
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, entries, L"signature\\sample.inf",
												 chicagoPolicy, package) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, entries, L"signature\\sample.inf",
												 POLICY, package) != 0) ;

	OfficialInfInspectionPolicy emptyPolicy = POLICY ;	// 空allowlistを拒否するpolicy
	emptyPolicy.acceptedSignatures			= {} ;
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, entries, L"signature\\sample.inf",
												 emptyPolicy, package) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Architectureとprogram混入の拒否を確認する
 *
 * x86専用Modelsとarchive内の未参照実行programをx64のdriver-only packageとして受理しない
 *
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void testInfContentRejections( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// Negative fixtureを所有する保護領域
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"inf-test", 103) == 0) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"x86\\sample.inf", X86_ONLY_INF)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"x86\\sample.cat", "catalog")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"x86\\sample.sys", "driver")) ;
	const std::array x86Entries{
		OfficialZipEntry{L"x86\\sample.inf", X86_ONLY_INF.size()},
		OfficialZipEntry{L"x86\\sample.cat", 7},
		OfficialZipEntry{L"x86\\sample.sys", 6},
	} ; // x86専用INFを含むentry群
	OfficialInfPackage package ;	// 失敗時に空であるべき出力
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
	} ; // 実行programを含むentry群
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
	} ; // Windows Setup形式で圧縮された実行programを含むentry群
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, compressedProgramEntries,
												 L"program\\sample.inf", POLICY, package) != 0) ;

	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"program\\helper.ps1", "script")) ;
	const std::array scriptEntries{
		OfficialZipEntry{L"program\\sample.inf", PROGRAM_INF.size()},
		OfficialZipEntry{L"program\\sample.cat", 7},
		OfficialZipEntry{L"program\\sample.sys", 6},
		OfficialZipEntry{L"program\\helper.ps1", 6},
	} ; // PowerShell scriptを含むentry群
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialInfPackage( workspace, scriptEntries, L"program\\sample.inf",
												 POLICY, package) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 混在Modelsから現在のx64 sectionだけを選ぶことを確認する
 *
 * x86用PnP IDをx64候補へ混入せず、architecture不明の独自version比較へ置き換えない
 *
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void testArchitectureSpecificModelsSelection( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 混在architecture fixtureの保護領域
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"inf-architecture-test", 111U) == 0) ;
	DRIVERCRATE_EXPECT(
		context, writeWorkspaceFile( workspace, L"mixed\\renamed.inf", MIXED_ARCHITECTURE_INF)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"mixed\\sample.cat", "catalog")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"mixed\\sample.sys", "driver")) ;
	const std::array entries{
		OfficialZipEntry{L"mixed\\renamed.inf", MIXED_ARCHITECTURE_INF.size()},
		OfficialZipEntry{L"mixed\\sample.cat", 7U},
		OfficialZipEntry{L"mixed\\sample.sys", 6U},
	} ; // x64とx86 Modelsを同じINFに保持するentry群
	OfficialInfPackage package ;	// x64 sectionだけを保持する構造結果
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"mixed\\renamed.inf",
														  POLICY, package) == 0) ;
	DRIVERCRATE_EXPECT( context, package.hardwareIds.size() == 1U) ;
	// 一件だけ取得できた場合に、x64用IDが選ばれx86用IDが除外されたことを確認する
	if( package.hardwareIds.size() == 1U) {
		DRIVERCRATE_EXPECT( context, package.hardwareIds.front() == L"PCI\\VEN_4321&DEV_1000") ;
		DRIVERCRATE_EXPECT( context, package.hardwareIds.front() != L"PCI\\VEN_4321&DEV_2000") ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 現在deviceとのPnP ID照合規則を確認する
 *
 * Hardware ID優先、Compatible ID照合、大文字小文字の差、部分一致と空IDの拒否を架空IDだけで確認する
 *
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void testDeviceIdentityMatching( TestContext &context)
{
	OfficialInfPackage package ;	// 現在deviceとの照合に使用する検証済み相当package
	package.hardwareIds = {L"PCI\\VEN_1234&DEV_5678", L"PCI\\VEN_1234"} ;

	constexpr std::array EXACT_HARDWARE_IDS{	// 大文字小文字だけが異なる完全ID
											std::wstring_view( L"pci\\ven_1234&dev_5678")} ;
	constexpr std::array COMPATIBLE_IDS{	// より一般的な架空Compatible ID
										std::wstring_view( L"PCI\\VEN_1234")} ;
	DRIVERCRATE_EXPECT( context,
					   matchOfficialInfToDevice( package, EXACT_HARDWARE_IDS, COMPATIBLE_IDS) ==
						   OfficialInfDeviceMatch::HARDWARE_ID) ;

	constexpr std::array UNRELATED_HARDWARE_IDS{	// INFへ一致しない架空Hardware ID
												std::wstring_view( L"PCI\\VEN_9999&DEV_9999")} ;
	DRIVERCRATE_EXPECT( context,
					   matchOfficialInfToDevice( package, UNRELATED_HARDWARE_IDS, COMPATIBLE_IDS) ==
						   OfficialInfDeviceMatch::COMPATIBLE_ID) ;

	constexpr std::array PARTIAL_IDS{	// Prefixだけが一致するID
									 std::wstring_view( L"PCI\\VEN_1234&DEV_5678&SUBSYS_00000000")} ;
	constexpr std::array EMPTY_IDS{std::wstring_view{}} ;	// 適用対象を拡張してはならない空ID
	DRIVERCRATE_EXPECT( context, matchOfficialInfToDevice( package, PARTIAL_IDS, EMPTY_IDS) ==
									OfficialInfDeviceMatch::NONE) ;
	DRIVERCRATE_EXPECT( context, matchOfficialInfToDevice( package, EMPTY_IDS, EMPTY_IDS) ==
									OfficialInfDeviceMatch::NONE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空CoInstaller節の作用検査と署名境界を確認する
 *
 * @param[in,out] context Assertion集計先
 * @param[in] suffix 正常INFへ追加する架空sectionと指示
 * @param[in] accepted 無作用として構造受理すべき場合true
 * @param[in] identity 一時workspace用の試験operation ID
 * @note 実DLLを実行せず、受理後も未署名CATは必ず拒否されることを確認する
 */
//------------------------------------------------------------------------------
void checkCoInstallerFixture( TestContext &context, const std::string_view suffix,
							 const bool accepted, const std::uint64_t identity)
{
	OfficialDownloadWorkspace workspace ;	// Scope内でfixtureを所有する保護領域
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"empty-coinstaller-test", identity) == 0) ;
	std::string inf( VALID_INF) ;	// 実IDを含まない正常fixtureへ追加する全byte
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
	} ; // CATと通常SYS参照を維持した架空entry群
	OfficialInfInspectionPolicy actionPolicy = POLICY ;	// 動作検査を要求する有限policy
	actionPolicy.rejectInstallActions		 = true ;
	OfficialInfPackage package ;	// 失敗時には空へ戻す検証出力
	const NativeError  error = inspectOfficialInfPackage( workspace, entries, L"test\\sample.inf",
														 actionPolicy, package) ;	// 構造検査結果
	context.expect( (error == 0) == accepted,
				   "CoInstaller fixture " + std::to_string( identity) + " HRESULT " +
					   std::to_string( error),
				   __FILE__, __LINE__) ;
	// 受理済みfixtureでも署名境界を省略して導入可能としてはならない
	if( accepted && error == 0) {
		DRIVERCRATE_EXPECT( context, package.sourceFiles.size() == 1U) ;
		DRIVERCRATE_EXPECT( context, !package.hasExternalDependencies) ;
		DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, package) != 0) ;
	}

	// 不正動作は候補用metadataを部分公開しない
	if( !accepted) {
		DRIVERCRATE_EXPECT( context, package.infRelativePath.empty()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 空節と空参照だけを許可し、実動作・未知指示・循環・過大入力を拒否する
 *
 * @param[in,out] context Assertion集計先
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
	} ; // 明示された無作用だけを持つ正常例
	std::uint64_t identity = 300U ;	// Fixture間の独立workspace識別子
	// 正常例ごとに構造受理と未署名CAT拒否を確認する
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
	} ; // 実動作、未知、循環、構文不備と上限超過の拒否例
	// 各拒否例を同じ正常driverに付加し、空参照許可の抜け道にしない
	for( const std::string_view body : REJECTED) {
		std::string suffix( "\r\n[Install.NT.CoInstallers]\r\n") ;	// 現在拒否例の節本文
		suffix.append( body) ;
		checkCoInstallerFixture( context, suffix, false, identity++) ;
	}

	std::string boundary( "\r\n[Install.NT.CoInstallers]\r\nAddReg=") ;	// 最大16参照の正常境界
	// 一つの空節を参照する16個のfieldを固定上限まで構築する
	for( std::size_t field = 0U; field < 16U; ++field) {
		boundary.append( field == 0U ? "Empty" : ",Empty") ;
	}

	boundary.append( "\r\n[Empty]\r\n") ;
	checkCoInstallerFixture( context, boundary, true, identity++) ;
	const std::string longName( 257U, 'A') ;									// section名の上限を一文字超える不正参照
	std::string		  oversized( "\r\n[Install.NT.CoInstallers]\r\nAddReg=") ;	// 過長参照fixture
	oversized.append( longName).append( "\r\n[").append( longName).append( "]\r\n") ;
	checkCoInstallerFixture( context, oversized, false, identity++) ;
	checkCoInstallerFixture(
		context,
		"\r\n[Install.NT.CoInstallers]\r\nAddReg=Empty\r\n[Empty]\r\n[Other]\r\nRegisterDlls=Empty\r\n",
		false, identity++) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 棚卸しと導入拒否を分離し、媒体pathと全CopyINFの境界を確認する
 * @param[in,out] context Assertion集計先
 * @note 実ID・署名済みpackage・導入APIを使わない
 */
//------------------------------------------------------------------------------
void testMaintenanceInfReferences( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 架空INFだけを所有する保護領域
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"inf-reference-test", 801U) == 0) ;
	std::string		  inf( VALID_INF) ;						// EXEとBINの参照がある非実行fixture
	const std::size_t source = inf.find( "sample.sys=1") ;	// source節へ追加する位置
	inf.insert( source, "helper.exe=1\r\ndata.bin=1\r\n") ;
	inf.append(
		"\r\n[SourceDisksFiles]\r\ncommon.dll=1\r\n[Other]\r\nCopyINF=child\\peer.inf,child\\peer.inf,\r\nInclude=machine.inf\r\n") ;
	inf.append( "\r\n[Anonymous]\r\n,sample.sys\r\n") ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"test\\sample.inf", inf)) ;
	const std::array entries{
		OfficialZipEntry{L"test\\sample.inf", inf.size()},
		OfficialZipEntry{L"test\\sample.cat", 7},
		OfficialZipEntry{L"test\\sample.sys", 6},
		OfficialZipEntry{L"test\\helper.exe", 7},
		OfficialZipEntry{L"test\\data.bin", 7},
		OfficialZipEntry{L"test\\common.dll", 7},
	} ; // 参照先はmetadataだけであり実byte合格ではない
	OfficialInfReferenceInventory facts ;	// 導入packageへ変換できない出力
	DRIVERCRATE_EXPECT(
		context, inspectOfficialInfReferences( workspace, entries, L"test\\sample.inf", facts) == 0) ;
	DRIVERCRATE_EXPECT( context, facts.stage == OfficialInfReferenceStage::INVENTORIED) ;
	DRIVERCRATE_EXPECT( context, facts.sourceFiles.size() == 4U) ;
	DRIVERCRATE_EXPECT( context,
					   facts.copyInfPaths == std::vector<std::wstring>{L"test\\child\\peer.inf"}) ;
	DRIVERCRATE_EXPECT( context, facts.hasExternalDependencies) ;
	DRIVERCRATE_EXPECT( context, facts.installActionsError != 0) ;
	OfficialInfInspectionPolicy installPolicy = POLICY ;	// 既存の導入拒否境界
	installPolicy.rejectUnreferencedPrograms  = false ;
	installPolicy.rejectInstallActions		  = true ;
	OfficialInfPackage package ;	// 保守成功でも導入構造は受理しない
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"test\\sample.inf",
														  installPolicy, package) != 0) ;
	DRIVERCRATE_EXPECT( context, package.infRelativePath.empty()) ;

	std::string		  mediaInf( VALID_INF) ;						// SourceDisksNamesのmedia pathも含めるfixture
	const std::size_t media = mediaInf.find( "1=%DiskName%,,,") ;	// 固定fixtureの媒体宣言位置
	mediaInf.replace( media, std::string_view( "1=%DiskName%,,,").size(), "1=%DiskName%,,,media") ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"media\\sample.inf", mediaInf)) ;
	const std::array mediaEntries{
		OfficialZipEntry{L"media\\sample.inf", mediaInf.size()},
		OfficialZipEntry{L"media\\sample.cat", 7},
		OfficialZipEntry{L"media\\media\\sample.sys", 6},
	} ; // 媒体pathを省略した位置にはsourceが存在しない
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
		std::string_view( "peer.inf,,"),
		std::string_view( ",peer.inf"),
		std::string_view( "peer.inf,,second.inf"),
		std::string_view( "..\\peer.inf,"),
		std::string_view( ".\\..\\peer.inf"),
		std::string_view( ".\\C:\\peer.inf"),
		std::string_view( ".\\\\peer.inf"),
		std::string_view( "."),
		std::string_view( ".\\"),
	} ; // traversal、絶対、未解決、別形式、曖昧pathの拒否集合
	std::size_t ordinal{} ;	// CREATE_NEWのfixture識別子
	// 不正参照を一件ずつSetupAPIへ渡す
	for( const std::string_view child : REJECTED) {
		std::string invalid( VALID_INF) ;	// 共通の正常driver本文
		invalid.append( "\r\n[Other]\r\nCopyINF=").append( child).append( "\r\n") ;
		const std::wstring path =
			L"invalid" + std::to_wstring( ordinal++) + L"\\sample.inf" ;	// 一意な相対path
		const std::wstring parent = path.substr( 0, path.find( L'\\')) ;	// 現在fixture親
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, path, invalid)) ;
		const std::array invalidEntries{
			OfficialZipEntry{path, invalid.size()},
			OfficialZipEntry{parent + L"\\sample.cat", 7},
			OfficialZipEntry{parent + L"\\sample.sys", 6},
		} ; // 不正CopyINF以外の参照metadata
		DRIVERCRATE_EXPECT(
			context, inspectOfficialInfReferences( workspace, invalidEntries, path, facts) != 0) ;
		DRIVERCRATE_EXPECT( context, facts.stage == OfficialInfReferenceStage::DEPENDENCIES) ;
		DRIVERCRATE_EXPECT( context, facts.infRelativePath.empty() && facts.copyInfPaths.empty()) ;
	}

	DRIVERCRATE_EXPECT(
		context, inspectOfficialInfReferences( workspace, entries, L"..\\sample.inf", facts) != 0) ;
	DRIVERCRATE_EXPECT( context, facts.stage == OfficialInfReferenceStage::OPEN) ;
	std::string longKeyInf( VALID_INF) ;	// 先頭fieldが過長なkeyと空の先頭fieldを区別するfixture
	longKeyInf.append( "\r\n[LongKey]\r\n").append( 4'096U, 'A').append( "=value\r\n") ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"longkey\\sample.inf", longKeyInf)) ;
	const std::array longEntries{
		OfficialZipEntry{L"longkey\\sample.inf", longKeyInf.size()},
		OfficialZipEntry{L"longkey\\sample.cat", 7},
		OfficialZipEntry{L"longkey\\sample.sys", 6},
	} ; // 過長key以外は正常なmetadata
	DRIVERCRATE_EXPECT( context, inspectOfficialInfReferences( workspace, longEntries,
															 L"longkey\\sample.inf", facts) != 0) ;
	DRIVERCRATE_EXPECT( context, facts.infRelativePath.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保守参照の先頭現在directoryだけを解決し、親参照と絶対pathは拒否する
 * @param[in,out] context Assertion集計先
 * @note 架空INFを保護領域へ置き、実導入・実署名packageを使用しない
 */
//------------------------------------------------------------------------------
void testMaintenanceRelativeReferences( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 架空fixtureだけを所有する保護領域
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"inf-relative-test", 802U) == 0) ;
	constexpr std::array MEDIA{std::string_view( ".\\media"), std::string_view( ".\\.\\media"),
							   std::string_view( "./media"), std::string_view( "."),
							   // 明示現在directoryだけの正例
							   std::string_view( ".\\")} ;
	// 別々の元fileとmetadataで媒体pathの解決を確認する
	for( std::size_t index = 0U; index < MEDIA.size(); ++index) {
		std::string		  inf( VALID_INF) ;							// 有限の架空driver本文
		const std::size_t position = inf.find( "1=%DiskName%,,,") ;	// 固定媒体pathの追加位置
		inf.replace( position, std::string_view( "1=%DiskName%,,,").size(),
					"1=%DiskName%,,," + std::string( MEDIA[index])) ;
		inf.append( "\r\n[Other]\r\nCopyINF=.\\child\\peer.inf\r\n") ;
		// 正常な媒体とsource subdirの両方に現在directory指定を持つケースを含める
		if( index == 0U) {
			const std::size_t sourcePosition =
				// source subdirの追加位置
				inf.find( "sample.sys=1") ;
			inf.replace( sourcePosition, std::string_view( "sample.sys=1").size(),
						"sample.sys=1,.\\") ;
		}

		const std::wstring parent = L"valid" + std::to_wstring( index) ;	// CREATE_NEWの一意親
		const std::wstring path	  = parent + L"\\sample.inf" ;				// 現在fixtureのINF
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, path, inf)) ;
		const std::wstring source =
			parent + (index < 3U ? L"\\media\\sample.sys"
								 : L"\\sample.sys") ;	// 宣言媒体位置だけにある元source
		const std::array			  entries{OfficialZipEntry{path, inf.size()},
								  OfficialZipEntry{parent + L"\\sample.cat", 7U},
								  OfficialZipEntry{source, 6U}} ;	// 未取得sourceはmetadataとして扱う
		OfficialInfReferenceInventory facts ;						// 署名・導入を承認しない参照結果
		DRIVERCRATE_EXPECT( context,
						   inspectOfficialInfReferences( workspace, entries, path, facts) == 0) ;
		DRIVERCRATE_EXPECT( context, facts.sourceFiles == std::vector<std::wstring>{source}) ;
		DRIVERCRATE_EXPECT( context, facts.copyInfPaths ==
										std::vector<std::wstring>{parent + L"\\child\\peer.inf"}) ;
	}

	constexpr std::array UNSAFE{std::string_view( ".\\..\\media"), std::string_view( ".\\C:\\media"),
								std::string_view( ".\\\\server"),
								std::string_view( "media\\.\\child"),
								// 除去後も危険または未対応な媒体位置
								std::string_view( "media\\..\\child")} ;
	// 危険な媒体を同名sourceへのfallbackで救済しない
	for( std::size_t index = 0U; index < UNSAFE.size(); ++index) {
		std::string		  inf( VALID_INF) ;							// その他の節は正常に維持する
		const std::size_t position = inf.find( "1=%DiskName%,,,") ;	// 媒体宣言位置
		inf.replace( position, std::string_view( "1=%DiskName%,,,").size(),
					"1=%DiskName%,,," + std::string( UNSAFE[index])) ;
		const std::wstring parent = L"unsafe" + std::to_wstring( index) ;	// CREATE_NEW用一意親
		const std::wstring path	  = parent + L"\\sample.inf" ;				// 不正媒体だけを含むINF
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, path, inf)) ;
		const std::array entries{
			OfficialZipEntry{path, inf.size()}, OfficialZipEntry{parent + L"\\sample.cat", 7U},
			OfficialZipEntry{parent + L"\\sample.sys", 6U}} ;	// 名前だけで補完させないmetadata
		OfficialInfReferenceInventory facts ;					// 部分参照を合格として保持しない
		DRIVERCRATE_EXPECT( context,
						   inspectOfficialInfReferences( workspace, entries, path, facts) != 0) ;
		DRIVERCRATE_EXPECT( context, facts.sourceFiles.empty()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 空sourceでも署名を要求し、通常導入の構造policyを緩和しない
 * @param[in,out] context Assertion集計先
 * @note 架空CATを使用する負例であり、署名合格の正例は別の非実行実物試験で確認する
 */
//------------------------------------------------------------------------------
void testInfOnlyIntegrityBoundary( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// INF/CATのみを所有する架空fixture領域
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"inf-only-integrity-test", 172U) == 0) ;
	std::string		  inf( VALID_INF) ;									// 実機情報を含まない元fixture
	const std::size_t begin = inf.find( "[SourceDisksNames.amd64]") ;	// 参照を除く区間先頭
	const std::size_t end	= inf.find( "[Strings]") ;					// 表示用Stringsは保持する
	inf.replace( begin, end - begin, "[Install.NT]\r\n; no source files\r\n\r\n") ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"only\\sample.inf", inf)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"only\\sample.cat", "unsigned")) ;
	const std::array entries{
		OfficialZipEntry{L"only\\sample.inf", inf.size()},
		OfficialZipEntry{L"only\\sample.cat", 8U}} ;	// 取得済みINF/CATだけの有限集合
	OfficialInfReferenceInventory facts ;				// 内容署名とは別の保守棚卸し結果
	DRIVERCRATE_EXPECT(
		context, inspectOfficialInfReferences( workspace, entries, L"only\\sample.inf", facts) == 0) ;
	DRIVERCRATE_EXPECT( context, facts.sourceFiles.empty()) ;
	DRIVERCRATE_EXPECT( context, facts.catalogRelativePath == L"only\\sample.cat") ;
	OfficialInfPackage content ;	// 参照検査後の署名呼出し専用値
	content.infRelativePath		= facts.infRelativePath ;
	content.catalogRelativePath = facts.catalogRelativePath ;
	content.sourceFiles			= facts.sourceFiles ;
	DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, content) != 0) ;
	DRIVERCRATE_EXPECT(
		context, verifyOfficialInfPackageIntegrity( workspace, content, ACCEPTED_SIGNERS) != 0) ;
	DRIVERCRATE_EXPECT( context, verifyOfficialInfEmbeddedFileSignatures( workspace, content, {},
																		ACCEPTED_SIGNERS) ==
									static_cast<NativeError>( E_INVALIDARG)) ;
	OfficialInfPackage install ;	// 内容署名とは別に通常導入用の構造policyを確認する
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"only\\sample.inf",
														  POLICY, install) != 0) ;
	DRIVERCRATE_EXPECT( context, install.infRelativePath.empty()) ;
	content.infRelativePath.clear() ;
	DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, content) != 0) ;
	content.infRelativePath = facts.infRelativePath ;
	content.catalogRelativePath.clear() ;
	DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, content) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つの架空保守INFを構造回帰用に組み立てる
 * @param[in] serviceBody 現OS対応Services節の宣言。空名も原文字列で保持する
 * @param[in] installBody 現OS用DDInstall本文。参照はfixtureの範囲だけ
 * @param[in] extraSections 任意の架空source・Strings・付随節
 * @param[in] extraModels 現OS Modelsへ加える架空行
 * @return 元byte検証だけに使用する架空INF。実inventoryを含まない
 */
//------------------------------------------------------------------------------
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
		"[Models.NTamd64]\r\nFirst=Install,ROOT\\FICTIONAL_STRUCTURE_0001\r\n" ;	// 固定架空元INF
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

//------------------------------------------------------------------------------
/**
 * @brief 架空INFとdummy CATをSetupAPIで構造観測する
 * @param[in,out] context Assertion集計先
 * @param[in] inf 架空INF全文
 * @param[out] structure 保守構造。署名結果は未検査のまま
 * @param[in] payloadPresent 架空SYSを固定entryへ含める場合true
 * @param[in] checkIntField flags 2正例についてWindows整数APIも比較する場合true
 * @param[in] policy 架空入力に適用する検査用途と件数上限
 * @param[in] scopedIds 非空なら元Modelsから照合する架空の公式範囲
 * @return 保守APIの元HRESULT。読取失敗は構造を空にする
 * @throws std::runtime_error 架空workspace初期化に失敗した場合
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectMaintenanceFixture(
	TestContext &context, std::string_view inf, MaintenanceInfStructure &structure,
	bool payloadPresent = false, bool checkIntField = false,
	const OfficialInfInspectionPolicy &policy	 = MAINTENANCE_POLICY,
	std::span<const std::wstring>	   scopedIds = {})
{
	OfficialDownloadWorkspace workspace ;	// 同期観測完了まで架空byteを所有する
	const NativeError		  initialized =
		// 24文字内のtag
		workspace.initialize( L"maint-structure-fixture", 249U) ;
	DRIVERCRATE_EXPECT( context, initialized == 0) ;
	// Fixture自体を作れない場合は未初期化の領域・行contextを試験で参照しない
	if( initialized != 0) {
		throw std::runtime_error( "Synthetic maintenance workspace initialization failed") ;
	}

	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"test\\sample.inf", inf)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"test\\sample.cat", "unsigned")) ;
	std::vector<OfficialZipEntry> entries{{L"test\\sample.inf", inf.size()},
										  {L"test\\sample.cat", 8U}} ;	// 署名成功ではない固定集合
	// File参照正例だけが架空SYSのmetadata存在を持つ
	if( payloadPresent) {
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"test\\sample.sys", "driver")) ;
		entries.push_back( {L"test\\sample.sys", 6U}) ;
	}

	// Literal／hex／Strings正例で同じ展開fieldのWindows整数値を比較する
	if( checkIntField) {
		const HINF handle = SetupOpenInfFileW( workspace.path( L"test\\sample.inf").c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  nullptr) ;	// 本scopeが必ず閉じる借用元
		DRIVERCRATE_EXPECT( context, handle != INVALID_HANDLE_VALUE) ;
		// 読取成功時だけcontextと整数APIを参照する
		if( handle != INVALID_HANDLE_VALUE) {
			INFCONTEXT line{} ;	// 比較用のAddService行
			DRIVERCRATE_EXPECT( context, SetupFindFirstLineW( handle, L"Install.NT.Services",
															L"AddService", &line) != FALSE) ;
			int flags = -1 ;	// API失敗時の比較sentinel
			DRIVERCRATE_EXPECT( context, SetupGetIntField( &line, 2U, &flags) != FALSE) ;
			DRIVERCRATE_EXPECT( context, flags == 2) ;
			SetupCloseInfFile( handle) ;
		}
	}

	OfficialInfScopedModelsEvidence scoped ;	// 元Modelsを照合した架空範囲です
	// 公式範囲の試験では同じ元INFから独立にハッシュとModelsを読み取ります
	if( !scopedIds.empty()) {
		structure		= {} ;
		auto	  &hash = entries.front().sha256 ;	// 同じ固定元INFに結ぶハッシュです
		// 試験INFの内容を同じ作業領域に結び付けるハッシュ計算結果
		const auto hashError = computeFileSha256( workspace.path( L"test\\sample.inf"), hash) ;
		// 元INF読み取りの失敗から試験用の範囲証拠を作りません
		if( hashError != 0U) {
			return hashError ;
		}

		const auto scopeError = readOfficialInfScopedModels(
			workspace, L"test\\sample.inf", hash, nullptr, scopedIds, scoped) ;	// 元Modelsの診断です
		// 架空の公式IDでも同じ節内の実行行に結び付くことを必要とします
		if( scopeError != 0U) {
			return scopeError ;
		}
	}

	return inspectMaintenanceInfStructure( workspace, entries, L"test\\sample.inf", policy,
										  structure, scopedIds.empty() ? nullptr : &scoped) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 収集の長いレジストリ行と共有節だけが追加枠を使うことを確認する
 * @param[in,out] context 架空入力と戻り値の比較を集計する試験状態
 * @note 署名や作用の安全性を認定せず、別起点の共有節を省略しない
 */
//------------------------------------------------------------------------------
void testCollectionInventoryBudget( TestContext &context)
{
	auto standard				= MAINTENANCE_POLICY ;	// 多起点fixtureを元ID上限の先で検査する
	standard.maximumHardwareIds = 256U ;
	auto collector				= standard ;	// 同じID上限で調査用途だけを変える
	collector.purpose			= OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;
	// 上限超過に対する期待診断
	const auto overflow = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW)) ;
	MaintenanceInfStructure structure ;	// 成功時の作用と失敗時の空状態
	std::string				binary ;	// 上限64を超える元バイナリの全値
	// 同じ長さの節を作り一意な行数を境界へ近づける
	for( std::size_t i = 0U; i < 80U; ++i) {
		binary += ",aF" ;
	}

	// 指定の登録行を共通試験素材へ組み込む
	const auto makeRegistry = [&]( const std::string &row) {
		return makeMaintenanceInf( {}, "AddReg=Config\r\n", "[Config]\r\n" + row + "\r\n") ;
	} ;
	const auto plain = makeRegistry( "HKR,Device,Sample,1" + binary) ;	// 84フィールド
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, plain, structure) == overflow) ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, plain, structure, false, false,
														  collector) == 0) ;
	DRIVERCRATE_EXPECT(
		context, std::ranges::any_of( structure.installs, []( const auto &install) {
			return std::ranges::any_of( install.inventory.coverageGaps, []( const auto &gap) {
				return gap.kind == OfficialInfInstallCoverageKind::REGISTRY_SCOPE_NOT_ASSESSED ;
			}) ;
		})) ;
	// 境界付近の登録行を独立に比較する
	for( const auto &row :
		{"HKLM,Device,Sample,1" + binary, "HKR,Device,Sample,0" + binary,
		 "HKR,Device,Sample,1" + binary + ",XX", "HKR,Device,Sample,1" + binary + binary}) {
		DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, makeRegistry( row), structure,
															  false, false, collector) == overflow) ;
		DRIVERCRATE_EXPECT( context, structure.installs.empty()) ;
	}

	std::string models ;				// 90の異なる導入起点に対応する架空機器
	std::string installs ;				// 全起点が同じ11レジストリ節へ到達する
	std::string addReg = "AddReg=" ;	// 各起点で記録される元の参照
	// 導入節を増やし同じ行への再到達を発生させる
	for( std::size_t i = 0U; i < 11U; ++i) {
		const auto name = "Shared" + std::to_string( i) ;	// 全起点で共有する節
		addReg += name + (i == 10U ? "\r\n" : ",") ;
		installs += "[" + name + "]\r\nHKR,,Marker,1,00\r\n" ;
	}

	// 共有行を追加し延べ上限だけを変化させる
	for( std::size_t i = 0U; i < 90U; ++i) {
		const auto name = "Root" + std::to_string( i) ;	// 当該Models行だけの導入名
		models += name + "=" + name + ",ROOT\\FICTIONAL_COLLECTION_" + std::to_string( i) + "\r\n" ;
		installs += "[" + name + ".NT]\r\n" + addReg ;
	}

	// すべての共有節を使う元INF
	const auto shared = makeMaintenanceInf( {}, {}, installs, models) ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, shared, structure, false, false,
														  standard) == overflow) ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, shared, structure, false, false,
														  collector) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.installs.size() == 91U) ;
	DRIVERCRATE_EXPECT( context, std::ranges::count_if( structure.installs, []( const auto &install) {
									return install.inventory.coverageGaps.size() == 11U ;
								}) == 90) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 共通宣言と単独・共有レジストリ節から行数境界用の架空INFを作る
 * @param[in] uniqueRows 最初の導入起点だけが読むレジストリ行数
 * @param[in] sharedRows 三つの導入起点がそれぞれ読むレジストリ行数。0なら追加の起点と共有節を省く
 * @return 元共通宣言、全起点と各行を持つ架空INF
 * @note レジストリ値に実ファイルを参照させず、個別保持項目の上限から行の上限を分離する
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string makeMaintenanceLineBudgetInf( std::size_t uniqueRows,
													   std::size_t sharedRows)
{
	// 共通宣言一行と最初の起点だけが参照する単独節から始める
	std::string sections = "[SourceDisksFiles.amd64]\r\nsample.sys=1\r\n[UniqueRegistry]\r\n" ;
	std::string models ;							// 共有節を再訪する追加の架空ROOT ID
	std::string install = "AddReg=UniqueRegistry" ;	// 最初の起点だけが単独節を参照する
	// 単独節に異なる値名を一行ずつ定義して、一意行予算を満たす
	for( std::size_t row = 0U; row < uniqueRows; ++row) {
		sections += "HKR,,Unique" + std::to_string( row) + ",1,00\r\n" ;
	}

	// 共有節のある例では同じ一節を別の二起点でも読ませる
	if( sharedRows != 0U) {
		install += ",SharedRegistry" ;
		models = "Second=SecondInstall,ROOT\\FICTIONAL_SHARED_0002\r\n"
				 "Third=ThirdInstall,ROOT\\FICTIONAL_SHARED_0003\r\n" ;
		sections += "[SecondInstall.NT]\r\nAddReg=SharedRegistry\r\n"
					"[ThirdInstall.NT]\r\nAddReg=SharedRegistry\r\n[SharedRegistry]\r\n" ;
		// 同じ共有節の各行を三起点から調査できるようにする
		for( std::size_t row = 0U; row < sharedRows; ++row) {
			sections += "HKR,,Shared" + std::to_string( row) + ",1,00\r\n" ;
		}
	}

	return makeMaintenanceInf( {}, install, sections, models) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 収集の一意4,096行と延べ8,192行および従来の4,096行上限を確認する
 * @param[in,out] context 境界の成否と元起点ごとの観測を集計する試験状態
 * @note 非実行の元構造だけを比較し、両上限の超過では共通宣言と個別観測を破棄する
 * @see docs/adr/0551-bounded-shared-inf-inventory-lines.md
 */
//------------------------------------------------------------------------------
void testCollectionInventoryLineBudget( TestContext &context)
{
	const auto standard	 = MAINTENANCE_POLICY ;	// 従来の構造調査用途
	auto	   collector = standard ;			// 同じpolicyで調査用途だけを変える
	collector.purpose	 = OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;
	// 元行上限のWin32エラーをHRESULTへ変換した期待値
	const auto overflow = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW)) ;
	MaintenanceInfStructure structure ;	// 成功後に同じ結果を再利用し、失敗時の消去も確認する
	// 試験scope内の結果と集計先を借用して、失敗時に元宣言も個別観測も残らないことを確認する
	const auto				expectEmpty = [&] {
		 DRIVERCRATE_EXPECT( context, structure.infRelativePath.empty() &&
													 structure.infSha256.empty() &&
													 structure.catalogRelativePath.empty()) ;
		 DRIVERCRATE_EXPECT( context, structure.hardwareIds.empty() && structure.installs.empty() &&
													 structure.fileUses.empty() &&
													 structure.sourceFileNames.empty() &&
													 !structure.sourceSectionPresent) ;
	} ;

	// 共通11行と3起点の宣言に単独2,034行、共有2,048行を足すと一意4,096行、延べ8,192行になる
	const auto shared = makeMaintenanceLineBudgetInf( 2034U, 2048U) ;	// 両上限を同時に満たす元INF
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, shared, structure, false, false,
														  collector) == 0) ;
	const std::vector<std::wstring> sharedIds{
		L"ROOT\\FICTIONAL_STRUCTURE_0001", L"ROOT\\FICTIONAL_SHARED_0002",
		L"ROOT\\FICTIONAL_SHARED_0003"} ;	// 現OSの全起点に結ぶ元ID
	DRIVERCRATE_EXPECT( context, structure.hardwareIds == sharedIds) ;
	DRIVERCRATE_EXPECT( context,
					   structure.sourceFileNames == std::vector<std::wstring>{L"sample.sys"}) ;
	DRIVERCRATE_EXPECT( context, structure.installs.size() == sharedIds.size()) ;
	// 全起点の観測が揃った場合にだけ、各起点で共有節の全行を読んだことを照合する
	if( structure.installs.size() == sharedIds.size()) {
		DRIVERCRATE_EXPECT( context, structure.installs[0].inventory.scannedLines == 4083U &&
										structure.installs[1].inventory.scannedLines == 2049U &&
										structure.installs[2].inventory.scannedLines == 2049U) ;
		// 三起点のいずれにも共有節の訪問と原作用の未評価を一件ずつ保持する
		for( const auto &install : structure.installs) {
			DRIVERCRATE_EXPECT( context, std::ranges::count( install.inventory.visitedSections,
														   L"SharedRegistry") == 1) ;
			DRIVERCRATE_EXPECT(
				context, std::ranges::count_if( install.inventory.coverageGaps, []( const auto &gap) {
							 return gap.section == L"SharedRegistry" &&
									gap.kind ==
										OfficialInfInstallCoverageKind::REGISTRY_SCOPE_NOT_ASSESSED ;
						 }) == 1) ;
		}
	}

	// 一意4,095行で延べ8,193行に達する入力は延べ上限だけで拒否する
	const auto tooManyVisits = makeMaintenanceLineBudgetInf( 2032U, 2049U) ;	// 延べ行だけ超過
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, tooManyVisits, structure, false,
														  false, collector) == overflow) ;
	expectEmpty() ;

	// 公式範囲では固有行が上限内の共有節を再利用し、各起点に作用と元用途を残す
	const auto scopedShared =
		makeMaintenanceLineBudgetInf( 2030U, 2049U) +
		"HKR,,CoInstallers32,0x00010000,helper.dll,helper.dll\r\n"
		"HKR,,FileUse,0,extra.sys\r\n" ;	// 同じ値の重複とその後続を持つ架空節です
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, scopedShared, structure, false,
														  false, collector, sharedIds) == 0U) ;
	DRIVERCRATE_EXPECT( context, structure.officialHardwareScope && structure.installs.size() == 3U) ;
	// 各起点で読み取った構造の意味と順序を再利用の有無にかかわらず照合します
	for( const auto &install : structure.installs) {
		const auto &inventory = install.inventory ;							// 同じ起点への全観測だけです
		const bool	first = inventory.baseInstallSection == L"Install" ;	// 単独節も訪問する起点です
		DRIVERCRATE_EXPECT( context, inventory.scannedLines == (first ? 4082U : 2052U)) ;
		DRIVERCRATE_EXPECT( context,
						   std::ranges::count_if( inventory.effects, []( const auto &effect) {
							   return effect.section == L"SharedRegistry" &&
									  effect.kind == OfficialInfInstallEffectKind::COINSTALLER ;
						   }) == 1) ;
		const std::array<std::wstring_view, 3U> files{L"helper.dll", L"helper.dll",
													  L"extra.sys"} ;	// 元値と重複を含む期待順です
		DRIVERCRATE_EXPECT( context, std::ranges::equal( install.fileUses, files, {},
													   &MaintenanceInfFileUse::target)) ;
		DRIVERCRATE_EXPECT(
			context, std::ranges::count_if( inventory.coverageGaps, []( const auto &gap) {
						 return gap.section == L"SharedRegistry" &&
								gap.kind ==
									OfficialInfInstallCoverageKind::REGISTRY_SCOPE_NOT_ASSESSED ;
					 }) == 1) ;
	}

	// 公式範囲の再利用で、元の固有行上限を越える入力を救済しません
	const auto scopedTooMany =
		makeMaintenanceLineBudgetInf( 2038U, 2049U) +
		"HKR,,DistinctA,1,00\r\nHKR,,DistinctB,1,00\r\n" ;	// 共通宣言を含めて固有4,096行を越えます
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, scopedTooMany, structure, false,
														  false, collector, sharedIds) == overflow) ;
	expectEmpty() ;

	// 同じ共有正例でも従来の調査は延べ4,096行を超えた時点で拒否する
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, shared, structure, false, false,
														  standard) == overflow) ;
	expectEmpty() ;

	// 一起点の共通9行と導入宣言1行に単独節を加え、一意行だけの境界を作る
	const auto distinct		   = makeMaintenanceLineBudgetInf( 4086U, 0U) ;	// 一意・延べとも4,096行
	const auto tooManyDistinct = makeMaintenanceLineBudgetInf( 4087U, 0U) ;	// 一意・延べとも4,097行
	// 共有のない上限と超過は両用途でそれぞれ元HRESULTと出力を確認する
	for( const auto &policy : {standard, collector}) {
		DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, distinct, structure, false,
															  false, policy) == 0) ;
		DRIVERCRATE_EXPECT( context,
						   structure.hardwareIds ==
							   std::vector<std::wstring>{L"ROOT\\FICTIONAL_STRUCTURE_0001"}) ;
		DRIVERCRATE_EXPECT( context, structure.installs.size() == 1U &&
										structure.installs.front().inventory.scannedLines == 4087U) ;
		DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, tooManyDistinct, structure,
															  false, false, policy) == overflow) ;
		expectEmpty() ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 公式無線設定の一部だけを元行の型と表示値で認識することを確認する
 * @param[in,out] context 架空の元INFと全ファイル観測の成否を集計する試験状態
 */
//------------------------------------------------------------------------------
void testScopedWirelessParameterLabels( TestContext &context)
{
	constexpr std::string_view inf =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=Net\r\n"
		"ClassGuid={4d36e972-e325-11ce-bfc1-08002be10318}\r\n"
		"Provider=Fictional Wireless Corporation\r\nDriverVer=10/07/2026,1.0.0.1\r\n"
		"CatalogFile=sample.cat\r\n[Manufacturer]\r\nFictional=Models,NTamd64\r\n"
		"[Models.NTamd64]\r\nFirst=Install,PCI\\VEN_FFFF&DEV_FFFE\r\n"
		"Second=SecondInstall,PCI\\VEN_FFFF&DEV_FFFD\r\n"
		"[Install.NT]\r\nCharacteristics=0x84\r\nBusType=5\r\n"
		"*IfType=71\r\n*MediaType=16\r\n*PhysicalMediaType=9\r\n"
		"AddReg=Settings\r\n[SecondInstall.NT]\r\nCharacteristics=0x84\r\nBusType=5\r\n"
		"*IfType=71\r\n*MediaType=16\r\n*PhysicalMediaType=9\r\n"
		"AddReg=Settings\r\n[Settings]\r\n"
		"HKR,Ndi\\Params\\Mode,ParamDesc,0,802.11a/b/g mode\r\n"
		"HKR,Ndi\\Params\\Mode\\enum,1,0x0,RTS/CTS enabled\r\n"
		"HKR,Ndi\\Params\\Mode,ParamDesc,0,program/loader.dll\r\n"
		"HKLM,Ndi\\Params\\Mode,ParamDesc,0,802.11a/g mode\r\n"
		"HKR,Ndi\\Params\\Mode,ParamDesc,0x20000,802.11b/g mode\r\n"
		"HKR,Ndi\\Params\\Mode\\enum,Name,0,802.11n/ac mode\r\n"
		"HKR,Ndi\\Params\\Mode,OtherValue,0,802.11a/g other\r\n" ;	// 表示ラベルと同形の負例を含む架空INF
	const std::array<std::wstring, 2U> ids{L"PCI\\VEN_FFFF&DEV_FFFE",
										   L"PCI\\VEN_FFFF&DEV_FFFD"} ;	// 二起点の架空の公式ID
	auto policy			   = MAINTENANCE_POLICY ;						// 実pkg署名や端末を使用しない保守用の試験policy
	policy.acceptedClasses = ACCEPTED_CLASSES ;
	policy.purpose		   = OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;
	MaintenanceInfStructure structure ;	// 同じ元構造の公式範囲と通常の結果
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, inf, structure, false, false,
														  policy, ids) == 0U) ;
	DRIVERCRATE_EXPECT( context, structure.installs.size() == ids.size()) ;
	// 両起点で共有節の用途型をそのまま保持することを照合する
	for( const auto &install : structure.installs) {
		const auto &uses = install.fileUses ;	// 公式範囲で元にあった全用途
		DRIVERCRATE_EXPECT( context, install.parser.state == MaintenanceInspectionState::PASSED) ;
		DRIVERCRATE_EXPECT( context, uses.size() == 7U) ;
		DRIVERCRATE_EXPECT( context, std::ranges::count( uses, L"WirelessParameterLabel",
													   &MaintenanceInfFileUse::directive) == 2) ;
		DRIVERCRATE_EXPECT( context, std::ranges::count( uses, L"RegistryFileUseNotAssessed",
													   &MaintenanceInfFileUse::directive) == 5) ;
	}

	DRIVERCRATE_EXPECT(
		context, inspectMaintenanceFixture( context, inf, structure, false, false, policy) == 0U) ;
	DRIVERCRATE_EXPECT( context, structure.installs.size() == ids.size()) ;
	// 公式の元選択がない保守経路では元の未検査用途のまま保持する
	for( const auto &install : structure.installs) {
		const auto &uses = install.fileUses ;	// 公式範囲のない同じ元用途
		DRIVERCRATE_EXPECT( context, std::ranges::count( uses, L"RegistryFileUseNotAssessed",
													   &MaintenanceInfFileUse::directive) == 7) ;
	}

	auto mixed = std::string{inf} ;	// 無線とEthernetの属性を混ぜた架空元INF
	mixed.replace( mixed.find( "*MediaType=16"), std::string_view{"*MediaType=16"}.size(),
				  "*MediaType=0") ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, mixed, structure, false, false,
														  policy, ids) == 0U) ;
	DRIVERCRATE_EXPECT( context, structure.installs.size() == ids.size() &&
									structure.installs.front().parser.state ==
										MaintenanceInspectionState::UNSUPPORTED) ;
}

/** @brief 一数値fixtureと期待する個別診断 */
struct MaintenanceFlagCase {
	/// AddServiceの第1field以降を含む原文字列
	std::string_view		   fields ;
	/// 架空Stringsの追加節
	std::string_view		   strings ;
	/// 数値とservice構造の到達状態
	MaintenanceInspectionState state ;
	/// 正例ならnull、不正または未対応ならunknown構造
	MaintenanceInfContentKind  kind ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief Empty名・flags全field・Windows展開と個別不正／未対応の分離を回帰する
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
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
	}} ; // 各fieldを0／2補完せず、decimalとhexを同じuint32契約で扱う
	// 全18ケースを実行し、一件失敗しても残りの分母を省かない
	for( const auto &testCase : CASES) {
		const std::string inf = makeMaintenanceInf( "AddService=" + std::string( testCase.fields), {},
												   testCase.strings) ;	// 架空原byte
		MaintenanceInfStructure structure ;								// 署名・coverageは未検査の結果
		const bool				positive =
			// 整数API比較範囲
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
		// 個別field状態は、選択を取得できた場合だけ安全に参照する
		if( structure.installs.size() == 1U && structure.installs[0].services.size() == 1U) {
			const auto &service =
				structure.installs[0].services[0] ;	// Empty名を保持したworker内観測
			DRIVERCRATE_EXPECT( context, service.serviceName.empty()) ;
			DRIVERCRATE_EXPECT( context, service.fieldCount >= 2U) ;
			DRIVERCRATE_EXPECT( context, service.parser.state == testCase.state) ;
			// 正例はoptional flags 2、それ以外は具体的診断値が必要
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

	// 直接過長とStrings単値過長を分け、Windows切捨て仕様を非切捨て証明にしない
	for( const bool stringValue : {false, true}) {
		const std::string large( stringValue ? 600U : 5000U, '9') ;	// uint32へ収まらない全数字
		const std::string inf = makeMaintenanceInf(
			stringValue ? "AddService=,%Large%" : "AddService=," + large, {},
			stringValue ? "[Strings]\r\nLarge=" + large + "\r\n" : "") ;	// 過長原byte
		MaintenanceInfStructure structure ;									// 読取失敗または個別不正を保持する
		const NativeError		error =
			// 実Windows挙動
			inspectMaintenanceFixture( context, inf, structure) ;
		DRIVERCRATE_EXPECT( context, error != 0 || structure.parser.state !=
													  MaintenanceInspectionState::PASSED) ;
		DRIVERCRATE_EXPECT( context, structure.rootIntegrity.state ==
										MaintenanceInspectionState::NOT_CHECKED) ;
		// 全体読取失敗は空結果、個別不正はoptionalの成功値を持たない
		if( error != 0) {
			DRIVERCRATE_EXPECT( context,
							   structure.infRelativePath.empty() && structure.installs.empty()) ;
		} else {
			DRIVERCRATE_EXPECT( context, structure.installs.size() == 1U &&
											!structure.installs[0].services[0].flags.has_value()) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 全Models・参照ありnull・限定named／複数service・未追跡用途を分離する
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void testMaintenanceStructureBoundaries( TestContext &context)
{
	MaintenanceInfStructure structure ;	// 各観測の前に入口が空へresetする結果
	const std::string		copy =
		// Sourceなしcopy
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
		"[Install.NT.Services]\r\nNeeds=Service.Explicit\r\n") ;	// 別節Includeを借用できない構造
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
		// 未追跡file用途
		"[ServiceInstall]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\nServiceBinary=%12%\\sample.sys\r\n") ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, named, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.parser.state == MaintenanceInspectionState::PASSED) ;
	DRIVERCRATE_EXPECT( context, structure.contentKind == MaintenanceInfContentKind::PACKAGE_FILES) ;
	DRIVERCRATE_EXPECT( context,
					   std::ranges::any_of( structure.installs.at( 0U).fileUses, []( const auto &use) {
						   return use.directive == L"ServiceBinary" ;
					   })) ; // ServiceBinaryは具体的用途を保持し、空参照へ消さない

	const std::string multiple =
		// 二associated宣言
		makeMaintenanceInf( "AddService=,2\r\nAddService=,0x2\r\n") ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, multiple, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.installs.at( 0U).services.size() == 2U) ;
	DRIVERCRATE_EXPECT( context, structure.parser.state == MaintenanceInspectionState::UNSUPPORTED) ;
	DRIVERCRATE_EXPECT(
		context, std::ranges::any_of( structure.installs.at( 0U).issues, []( const auto &issue) {
			return issue.reason == MaintenanceInfStructureReason::MULTIPLE_ASSOCIATED_SERVICES ;
		})) ; // 最初のnullだけで全体成功へ変換しない

	const std::string referencedService = makeMaintenanceInf(
		"AddService=,2,ServiceInstall,Events\r\n", {},
		// 参照付きempty service
		"[ServiceInstall]\r\nServiceBinary=%12%\\sample.sys\r\n[Events]\r\nEventMessageFile=%12%\\event.dll\r\n") ;
	DRIVERCRATE_EXPECT( context,
					   inspectMaintenanceFixture( context, referencedService, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.parser.state == MaintenanceInspectionState::UNSUPPORTED) ;
	DRIVERCRATE_EXPECT( context, structure.contentKind == MaintenanceInfContentKind::MIXED) ;
	DRIVERCRATE_EXPECT( context,
					   structure.installs.at( 0U).services.at( 0U).eventLogSection == L"Events") ;

	const std::string unknown =
		// 未解釈の作用
		makeMaintenanceInf( "AddService=,2", "UnknownDeclaration=value\r\n") ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, unknown, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.parser.state == MaintenanceInspectionState::UNSUPPORTED) ;
	DRIVERCRATE_EXPECT( context, !structure.installs.at( 0U).inventory.coverageGaps.empty()) ;
	const std::string layout = makeMaintenanceInf( "AddService=,2") +
							   "[Version]\r\nLayoutFile=layout.inf\r\n" ;	// Queue外の用途
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, layout, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.fileUses.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, structure.contentKind == MaintenanceInfContentKind::MIXED) ;

	const std::string models = makeMaintenanceInf(
		"AddService=,2", {},
		"[Second.NT]\r\nCopyFiles=@sample.sys\r\n[Second.NT.Services]\r\nAddService=,2\r\n",
		// 全現在OS選択
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
		"Second=Second,ROOT\\FICTIONAL_STRUCTURE_0002\r\n") ;	// 先頭成功・後続不正
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, secondBad, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.installs.size() == 2U &&
									structure.parser.state == MaintenanceInspectionState::FAILED) ;
}

/** @brief Named宣言一つと限定parserの期待。架空文字列だけを静的借用する */
struct MaintenanceNamedServiceCase {
	/// 元AddServiceのfield群。実service名を含まない
	std::string_view		   fields ;
	/// 架空Strings・event節の追加本文
	std::string_view		   extra ;
	/// 参照存在・必須四項目を含む限定構造の期待
	MaintenanceInspectionState state ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief Named 0／2・省略flags・必須参照と限定nullを同じ有限queueで回帰する
 * @param[in,out] context Assertion集計先
 * @note 構造だけを検査し、架空CATを署名成功へ扱わない
 */
//------------------------------------------------------------------------------
void testMaintenanceNamedServices( TestContext &context)
{
	constexpr std::string_view SERVICE_BODY =
		"[ServiceInstall]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\n"
		"ServiceBinary=%12%\\sample.sys\r\n" ;	// 四項目を持つ架空共通構造
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
	}} ; // 構造認識と不正・未知を同じ分母で扱う
	// 二十一宣言を一回ずつ検査し、不正caseを途中で除外しない
	for( const auto &testCase : CASES) {
		const std::string inf =
			makeMaintenanceInf( "AddService=" + std::string( testCase.fields), {},
							   // 各caseだけの架空byte
							   std::string( SERVICE_BODY) + std::string( testCase.extra)) ;
		MaintenanceInfStructure structure ;	// 初期化済みでも署名と位置は未検査
		DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, inf, structure) == 0) ;
		DRIVERCRATE_EXPECT( context, structure.parser.state == testCase.state) ;
		DRIVERCRATE_EXPECT( context,
						   structure.contentKind != MaintenanceInfContentKind::NULL_DRIVER) ;
		DRIVERCRATE_EXPECT( context, structure.rootIntegrity.state ==
										MaintenanceInspectionState::NOT_CHECKED) ;
		// 一つの選択・宣言を取得した場合だけ内部構造を参照する
		if( structure.installs.size() == 1U && structure.installs.front().services.size() == 1U) {
			const auto &install = structure.installs.front() ;	// この結果の同期借用
			const auto &service = install.services.front() ;	// 元named identityを外へ出さない
			DRIVERCRATE_EXPECT( context, service.parser.state == testCase.state) ;
			DRIVERCRATE_EXPECT( context, !service.serviceName.empty()) ;
			const bool marked = std::ranges::any_of( install.fileUses, []( const auto &use) {
				return use.directive == L"NamedServiceStructureNotAssessed" ;
			}) ; // named不足用途が参照readerへ消えずに残る
			DRIVERCRATE_EXPECT( context,
							   marked == (testCase.state != MaintenanceInspectionState::PASSED)) ;
			// 省略fieldは明示空の場合だけ既定0に対応する
			if( testCase.fields == "FictionalAuxiliary,,ServiceInstall") {
				DRIVERCRATE_EXPECT( context, service.flags == 0U && service.fieldCount == 3U) ;
			}

			// 数値overflowの元HRESULTを未対応markerで置換しない
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

	const std::string		longFlags( 5000U, '9') ;	// 名前付き宣言でも切捨て数値の成功を認めない
	MaintenanceInfStructure longStructure ;				// 全体読取失敗または元flags診断を保持する
	const NativeError		longError = inspectMaintenanceFixture(
		  context,
		  makeMaintenanceInf( "AddService=FictionalService," + longFlags + ",ServiceInstall", {},
								 SERVICE_BODY),
		  longStructure) ;	// 同じ長さ境界をnamedの既定0処理にも適用する
	DRIVERCRATE_EXPECT( context, longError != 0 || longStructure.parser.state !=
													  MaintenanceInspectionState::PASSED) ;
	// 全体失敗の部分観測を成功のoptional flagsへ残さない
	if( longError != 0) {
		DRIVERCRATE_EXPECT( context, longStructure.installs.empty()) ;
	} else {
		DRIVERCRATE_EXPECT( context,
						   !longStructure.installs.front().services.front().flags.has_value()) ;
	}

	constexpr std::array<std::string_view, 4U> REQUIRED_LINES{
		"ServiceType=1\r\n", "StartType=3\r\n", "ErrorControl=1\r\n",
		"ServiceBinary=%12%\\sample.sys\r\n"} ;	// 一欠落ずつの有限行集合
	// 必須四行それぞれの欠落・空・重複を検査し、別項目で補完しない
	for( const auto line : REQUIRED_LINES) {
		// 各項目を三つの独立した不正・未対応構成へ変える
		for( const std::size_t variant : {0U, 1U, 2U}) {
			std::string		  body( SERVICE_BODY) ;			// 原架空四項目の独立copy
			const std::size_t begin = body.find( line) ;	// 欠落させる必須行だけ
			const std::string replacement =
				variant == 0U	? ""
				: variant == 1U ? std::string( line.substr( 0U, line.find( '=') + 1U)) + "\r\n"
								: std::string( line) + std::string( line) ;	// 重複は優先値を作らない
			body.replace( begin, line.size(), replacement) ;
			MaintenanceInfStructure structure ;	// 署名と参照は今回も未検査
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
		"ServiceType=-1\r\n"} ;	// 数値syntaxと未知値を別観測にする
	// 未解決token・一次仕様外数値・負値を必須行の成功として通さない
	for( const auto line : BAD_VALUES) {
		std::string		  body( SERVICE_BODY) ;									// 一caseだけの元四項目
		const std::size_t equals = line.find( '=') ;							// 正式keyを対応させる位置
		const std::size_t begin	 = body.find( line.substr( 0U, equals + 1U)) ;	// 他行を借用しない
		body.replace( begin, body.find( "\r\n", begin) + 2U - begin, line) ;
		MaintenanceInfStructure structure ;	// 実作用へ接続しない結果
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
		// shared・混在・二associated
		"AddService=FictionalService,2,ServiceInstall\r\nAddService=FictionalSecond,2,ServiceInstall\r\n"} ;
	// Shared節を一度だけ読み、補助0と二associatedの違いを保持する
	for( std::size_t index = 0U; index < MIXED_SERVICES.size(); ++index) {
		MaintenanceInfStructure structure ;	// 原同節へcase-insensitiveに結ぶ結果
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
		// 先に辿る節と後続named
		"[serviceinstall]\r\nservicetype=1\r\nstarttype=3\r\nerrorcontrol=1\r\nservicebinary=%12%\\sample.sys\r\n") ;
	// 宣言順序とkeyの大文字小文字を別の欠落にしない
	MaintenanceInfStructure structure ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, prior, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.parser.state == MaintenanceInspectionState::UNSUPPORTED) ;
	DRIVERCRATE_EXPECT( context, structure.installs.front().services.front().parser.state ==
									MaintenanceInspectionState::UNSUPPORTED) ;
	const std::string shared = makeMaintenanceInf(
		"AddService=FictionalService,2,serviceinstall", "Needs=SERVICEINSTALL\r\n",
		// 合法Services宣言を後到達節へ結ぶ
		"[serviceinstall]\r\nservicetype=1\r\nstarttype=3\r\nerrorcontrol=1\r\nservicebinary=%12%\\sample.sys\r\n") ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, shared, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.parser.state == MaintenanceInspectionState::PASSED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Class差分試験だけに使う三fileの架空ZIPを生成する
 * @param[in] inf 架空INFの全byte
 * @param[out] archive 成功時だけのZIP byte。実driverを含まない
 * @return 三fileのZIP確定成功ならtrue。Miniz資源は全経路で解放する
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool makeMaintenanceClassArchive( std::string_view inf, std::string &archive)
{
	archive.clear() ;
	mz_zip_archive writer{} ;	// Scope内だけのMiniz writer状態
	// 非実行memory writerを初期化できない場合は生成を開始しない
	if( mz_zip_writer_init_heap( &writer, 0U, 0U) == 0) {
		return false ;
	}

	const bool added =
		mz_zip_writer_add_mem( &writer, "sample.inf", inf.data(), inf.size(), MZ_NO_COMPRESSION) !=
			0 &&
		mz_zip_writer_add_mem( &writer, "sample.cat", "unsigned", 8U, MZ_NO_COMPRESSION) != 0 &&
		mz_zip_writer_add_mem( &writer, "sample.sys", "driver", 6U, MZ_NO_COMPRESSION) !=
			0 ;				// 架空三byte列
	void	   *bytes{} ;	// APIが返すbufferを直後にRAIIへ移す
	std::size_t size{} ;	// 確定ZIPの有限byte数
	const bool	finalized =
		added && mz_zip_writer_finalize_heap_archive( &writer, &bytes, &size) != 0 ;	// 確定結果
	const std::unique_ptr<void, decltype( &mz_free)> ownedBytes( bytes,
															   &mz_free) ;	// 全経路で解放する所有物
	const bool ended = mz_zip_writer_end( &writer) != 0 ;					// Writer状態をstring確保より先に解放する
	// 部分archiveを検査入力へ使用しない
	if( !finalized || !ended || ownedBytes == nullptr || size == 0U) {
		return false ;
	}

	archive.assign( static_cast<const char *>( ownedBytes.get()), size) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 共通標準Classと内容専用・未知Classのpolicy差を実入口で確認する
 * @param[in,out] context Assertion集計先
 * @note Dummy CATは署名失敗の負例。ClassGuidを固定したClass名policy比較であり、WindowsのClass全体妥当性や実署名成功を認定しない
 */
//------------------------------------------------------------------------------
void testMaintenanceClassSeparation( TestContext &context)
{
	constexpr std::array<std::string_view, 6U> CLASSES{
		"Ports",   "System", "SecurityDevices", "MultiPortSerial", "FictionalUnknown",
		"Firmware"} ;	// 標準二Classの追加で未知Classやfirmwareを開放しません
	// 通常・内容専用・未知の全Class名を同じsource/CAT条件で比較する
	for( std::size_t index = 0U; index < CLASSES.size(); ++index) {
		std::string inf( VALID_INF) ;	// 元の架空ID・copy・sourceを保持する
		inf.replace( inf.find( "Class=Net"), 9U, "Class=" + std::string( CLASSES[index])) ;
		// 正常Systemは正式GUIDとの対を持ち、別ClassのGUIDを許可条件へ補完しません
		if( index == 1U) {
			inf.replace( inf.find( "{4d36e972-e325-11ce-bfc1-08002be10318}"), 38U,
						"{4d36e97d-e325-11ce-bfc1-08002be10318}") ;
		}

		MaintenanceInfStructure structure ;	// 保守構造は新Classを導入許可へ変換しない
		DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, inf, structure, true) == 0) ;
		DRIVERCRATE_EXPECT( context, structure.parser.state ==
										(index >= 4U ? MaintenanceInspectionState::UNSUPPORTED
													 : MaintenanceInspectionState::PASSED)) ;
		DRIVERCRATE_EXPECT( context,
						   structure.contentKind == MaintenanceInfContentKind::PACKAGE_FILES) ;
		DRIVERCRATE_EXPECT( context, structure.sourceFileNames.size() == 1U) ;
		DRIVERCRATE_EXPECT( context, structure.rootIntegrity.state ==
										MaintenanceInspectionState::NOT_CHECKED) ;
		// 未知Class名は具体的な解析未対応へ残し、device不適合を判定しない
		if( index >= 4U) {
			DRIVERCRATE_EXPECT(
				context,
				std::ranges::any_of( structure.installs.at( 0U).issues, []( const auto &issue) {
					return issue.reason == MaintenanceInfStructureReason::CLASS_NOT_SUPPORTED &&
						   issue.finding.state == MaintenanceInspectionState::UNSUPPORTED &&
						   issue.finding.error == static_cast<drivercrate::NativeError>(
													  HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
				})) ;
		}

		std::string archive ;	// 同じ架空INF・dummy CAT・SYSだけの元ZIP
		DRIVERCRATE_EXPECT( context, makeMaintenanceClassArchive( inf, archive)) ;
		OfficialDownloadWorkspace source ;	// 外側ZIPの固定入力を所有する
		DRIVERCRATE_EXPECT( context, source.initialize( L"maint-class-fixture", 250U + index) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( source, L"payload.zip", archive)) ;
		std::wstring hash ;	// 実byteから固定した架空archive identity
		DRIVERCRATE_EXPECT( context, computeFileSha256( source.path( L"payload.zip"), hash) == 0) ;
		const DriverArchiveInput input{250U + index, source.path( L"payload.zip"), archive.size(),
									   hash} ;				// 固定内容のみ
		MaintenanceDriverPackageInspection maintenance ;	// 内容専用構造と通常routeを独立保持する
		DRIVERCRATE_EXPECT( context, inspectMaintenanceDriverPackage(
										input, OfficialDriverArchiveFormat::ZIP, maintenance) == 0) ;
		DRIVERCRATE_EXPECT( context, maintenance.infs.size() == 1U) ;
		// 個別結果が取得できた場合だけ四軸の非昇格を確認する
		if( maintenance.infs.size() == 1U) {
			const auto &row = maintenance.infs[0] ;	// 内容専用Class policyの実検査結果
			DRIVERCRATE_EXPECT( context, row.parser.state ==
											(index >= 4U ? MaintenanceInspectionState::UNSUPPORTED
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
			// 架空Class番号と元routeの有限数値だけで旧期待との差を診断します
			std::cout << "INF_CLASS_ROUTE scenario=" << index
					  << " state=" << static_cast<int>( row.installRoute.state)
					  << " error=" << row.installRoute.error << '\n' ;
			DRIVERCRATE_EXPECT( context, row.installRoute.state ==
											(index < 3U ? MaintenanceInspectionState::PASSED
														: MaintenanceInspectionState::UNSUPPORTED)) ;
		}

		CommonDriverPackageInspection normal ;	// 公式性と独立した同じ共通CAT検査です
		DRIVERCRATE_EXPECT( context, inspectCommonDriverPackage(
										input, OfficialDriverArchiveFormat::ZIP, normal) == 0) ;
		DRIVERCRATE_EXPECT( context, normal.infs.size() == 1U) ;
		// 新二Classも署名失敗を保持し、未対応Classは構造段階で拒否します
		if( normal.infs.size() == 1U) {
			// 実IDを残さず元Class別の非実行拒否段階だけを観測します
			std::cout << "INF_CLASS_NORMAL scenario=" << index
					  << " state=" << static_cast<int>( normal.infs[0].state)
					  << " error=" << normal.infs[0].error << '\n' ;
			DRIVERCRATE_EXPECT( context,
							   normal.infs[0].state ==
								   (index < 3U ? CommonInfInspectionState::SIGNATURE_REJECTED
											   : CommonInfInspectionState::CLOSURE_REJECTED)) ;
			DRIVERCRATE_EXPECT( context, normal.infs[0].error != 0) ;
		}

		OfficialDownloadWorkspace
			genericWorkspace ;				// 通常generic入口が自身のClass policyを要求する領域
		GenericInfPackageContents generic ;	// 署名合格・candidateを発行できない架空結果
		const NativeError		  genericError =
			inspectGenericInfPackageFile( source.path( L"payload.zip"), 260U + index,
										 genericWorkspace, generic) ;	// 従来固定policyの実入口
		DRIVERCRATE_EXPECT( context, genericError != 0) ;
		DRIVERCRATE_EXPECT( context, generic.packages.empty()) ;
		// 内容Classの追加を取得元未証明localの許可へ流用しません
		if( index > 0U) {
			DRIVERCRATE_EXPECT( context,
							   genericError == static_cast<drivercrate::NativeError>(
												   HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED))) ;
		}

		OfficialInfPackage
			copied ;	// 不完全な表示metadataはpayload helperも通らない。boolを認証としない
		copied.className   = structure.className ;
		copied.hardwareIds = structure.hardwareIds ;
		copied.sourceFiles = {L"sample.sys"} ;
		DRIVERCRATE_EXPECT( context, !isGenericInfPackageSupported( copied)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 全体入力・対象OS・容量の失敗で部分構造が空になることを確認する
 * @param[in,out] context Assertion集計先
 */
//------------------------------------------------------------------------------
void testMaintenanceStructureInputFailures( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 架空の一INFとdummy CATだけを所有する
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"maint-input-fixture", 255U) == 0) ;
	const std::string inf =
		// 正常な構造から境界だけを変更する
		makeMaintenanceInf( "AddService=,2") ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", inf)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
	std::vector<OfficialZipEntry> entries{{L"sample.inf", inf.size()},
										  {L"sample.cat", 8U}} ;	// 元byte metadata
	MaintenanceInfStructure		  structure ;						// 入口が失敗時に必ず空へresetする出力
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
	std::string otherOs( inf) ;	// 現在architectureのModelsを別architectureへ変更する
	otherOs.replace( otherOs.find( "Fictional=Models,NTamd64,NTx86"),
					std::string_view( "Fictional=Models,NTamd64,NTx86").size(),
					"Fictional=Models,NTx86") ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, otherOs, structure) != 0) ;
	DRIVERCRATE_EXPECT( context, structure.installs.empty()) ;
	const std::string malformed =
		// Missing fieldはempty第一fieldと別
		makeMaintenanceInf( "AddService=") ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, malformed, structure) == 0) ;
	DRIVERCRATE_EXPECT( context, structure.parser.state == MaintenanceInspectionState::FAILED) ;
	const std::string traversal =
		// 元package外参照
		makeMaintenanceInf( "AddService=,2", "CopyFiles=@..\\escape.sys\r\n") ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, traversal, structure) != 0) ;
	DRIVERCRATE_EXPECT( context, structure.installs.empty()) ;
	std::string large = makeMaintenanceInf( "AddService=,2") ;	// 元選択節へ4,097行を追加する
	large += "[Install.NT]\r\n" ;
	// 合計行数上限＋1を構築し、分割による予算resetを検出する
	for( std::size_t row = 0U; row < 4097U; ++row) {
		large += "FeatureScore=0xF0\r\n" ;
	}

	DRIVERCRATE_EXPECT( context, inspectMaintenanceFixture( context, large, structure) ==
									static_cast<drivercrate::NativeError>(
										HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW))) ;
	DRIVERCRATE_EXPECT( context, structure.installs.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 明示seedのfile位置と具体的な不足を架空INFで確認する
 * @param[in,out] context 一processの有限assertion集計
 */
//------------------------------------------------------------------------------
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
		"CopyFiles=@..\\escape.sys\r\n"} ;	// 原作用だけを変える小matrix
	// sourceあり／なしを別fixtureとし、同じ参照を空集合へ救済させない
	for( std::size_t index = 0U; index < BODIES.size(); ++index) {
		OfficialDownloadWorkspace workspace ;	// 架空INFとdummy byteだけを単独所有する
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
					  "[SourceDisksFiles.amd64]\r\nsample.sys=1\r\n") ;	// 具体媒体位置を持つ場合だけ宣言する
		const std::string inf =
			// 架空元byte
			makeMaintenanceInf( "AddService=,2", BODIES[index], extra) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", inf)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"media\\sample.sys", "driver")) ;
		const std::array				   entries{OfficialZipEntry{L"sample.inf", inf.size()},
								   OfficialZipEntry{L"sample.cat", 8U},
								   OfficialZipEntry{L"media\\sample.sys", 6U}} ;	// 閉じた架空member
		const std::array<std::wstring, 2U> seeds{L"Install.NT",
												 L"Install.NT.Services"} ;	// 原明示節だけ
		MaintenanceInfReferences		   references ;						// 位置は署名の証明ではない
		const auto						   error =
			inspectMaintenanceInfReferences( workspace, entries, L"sample.inf", seeds,
											MAINTENANCE_POLICY, references) ;	// 非実行の内容観測
		// 不正pathは不足や署名失敗へ弱めず、全体の空結果で返す
		if( index == 11U) {
			DRIVERCRATE_EXPECT( context, error != 0 && references.files.empty()) ;
			continue ;
		}

		DRIVERCRATE_EXPECT( context, error == 0) ;
		DRIVERCRATE_EXPECT( context, references.files.size() >= 2U) ;
		DRIVERCRATE_EXPECT( context, references.files.at( 0U).relativePath == L"sample.inf" &&
										references.files.at( 1U).relativePath == L"sample.cat") ;
		// 無参照nullと正当copy、明示Needsのlocal不在をfile不足と混同しない
		if( index == 0U || index == 1U || index == 2U || index == 8U) {
			DRIVERCRATE_EXPECT( context, references.referenceCoverage ==
											MaintenanceInfReferenceCoverage::COMPLETE) ;
		} else {
			// binary DIRIDはWindowsの展開形が未対応なら位置不明のまま残せる
			if( index != 3U) {
				DRIVERCRATE_EXPECT( context, references.referenceCoverage ==
												MaintenanceInfReferenceCoverage::INCOMPLETE) ;
			}
		}

		// 正当媒体位置とfile-list別名のsourceを元memberへ結ぶ
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

		// 未追跡file用途は原節・原directiveと非零診断を保持する
		if( index == 4U || index == 5U || index == 7U || index == 9U || index == 10U) {
			DRIVERCRATE_EXPECT( context, std::ranges::any_of( references.files, []( const auto &file) {
								   return file.location != MaintenanceInfFileLocation::LOCATED &&
										  file.error != 0 ;
							   })) ;
		}
	}

	OfficialDownloadWorkspace workspace ;	// 同名scalar registryの通常source比較
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"maint-reg-source-test", 620U) == 0) ;
	const std::string inf = makeMaintenanceInf(
		"AddService=,2", "AddReg=Scalar\r\n",
		"[Scalar]\r\nHKR,,,0,1\r\n[SourceDisksNames.amd64]\r\n1=Fake,,,\r\n"
		"[SourceDisksFiles.amd64]\r\nsample.sys=1\r\n") ;	// 作用未評価だけでsource証拠を取り消さない
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", inf)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
	const std::array entries{
		OfficialZipEntry{L"sample.inf", inf.size()}, OfficialZipEntry{L"sample.cat", 8U},
		OfficialZipEntry{L"sample.sys", 6U}} ;					// 位置棚卸しでは未抽出sourceも明示memberへ結ぶ
	const std::array<std::wstring, 1U> seeds{L"Install.NT"} ;	// scalar registryだけを辿る
	MaintenanceInfReferences		   references ;				// 全作用とfile位置coverageは別の状態
	DRIVERCRATE_EXPECT( context,
					   inspectMaintenanceInfReferences( workspace, entries, L"sample.inf", seeds,
													   MAINTENANCE_POLICY, references) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   references.referenceCoverage == MaintenanceInfReferenceCoverage::COMPLETE) ;
	DRIVERCRATE_EXPECT( context, !references.inventory.coverageGaps.empty()) ;
	const std::array missingSource{OfficialZipEntry{L"sample.inf", inf.size()},
								   OfficialZipEntry{L"sample.cat", 8U}} ;	// 元source欠落
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

/** @brief 明示導入先と元sourceの一構成。Windows位置や実device情報は保持しない */
struct MaintenanceBinarySourceCase {
	/// 到達DDInstallに置く原copy宣言。空は未到達listの負例
	std::string_view		   copy{"CopyFiles=Files\r\n"} ;
	/// 同INFのDestinationDirs本文。defaultは別の未対応構成
	std::string_view		   destinations{"Files=12\r\n"} ;
	/// 到達named listの元行。source別名をdestinationへ潰さない
	std::string_view		   rows{"source.sys\r\n"} ;
	/// 非実行serviceのbinary原field。すべて架空leafである
	std::string_view		   binary{"%12%\\source.sys"} ;
	/// SourceDisksFilesの相対subdir。媒体pathとは分ける
	std::string_view		   sourceDirectory{"payload"} ;
	/// SourceDisksNamesの媒体path
	std::string_view		   mediaDirectory{"media"} ;
	/// 明示SourceDisksFilesを持つ場合true
	bool					   sourceDeclared{true} ;
	/// SourceDisksNamesの媒体を持つ場合true
	bool					   mediaDeclared{true} ;
	/// 元source memberを欠落させる場合true
	bool					   missingMember{} ;
	/// 位置観測だけの期待
	MaintenanceInfFileLocation location{MaintenanceInfFileLocation::LOCATED} ;
	/// 元位置診断。未対応で0ならWindowsの非零原診断を要求し、OS間で固定しない
	NativeError				   locationError{} ;
	/// 入力・容量等の全体拒否を期待する場合のHRESULT
	NativeError				   callError{} ;
	/// 固定memberとは別の元API相対位置を要求する場合だけ非空
	std::wstring_view		   expectedRelativePath ;
	/// 同じpackage内の元INF親。空ならpackage root
	std::wstring_view		   infParent ;
	/// 実在する元member directory。媒体／source不正をfile作成へ渡さない
	std::wstring_view		   memberDirectory{L"media\\payload"} ;
	/// 元SourceDisksFilesに同名二行を残す場合true
	bool					   duplicateSource{} ;
	/// 固定member一覧へ同位置を二件残す場合true
	bool					   duplicateMember{} ;
	/// 元INFの期待hashだけを不一致にする場合true
	bool					   changedInfBytes{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 展開済み全path・named固有導入先・明示sourceと合法未対応を実SetupAPIで回帰する
 * @param[in,out] context 一processの有限assertion集計
 * @note 位置観測でありCAT署名・導入先充足・端末適合を実行しない
 */
//------------------------------------------------------------------------------
void testMaintenanceBinarySources( TestContext &context)
{
	constexpr NativeError UNSUPPORTED = static_cast<drivercrate::NativeError>(
		// 位置未対応
		HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
	constexpr NativeError DUPLICATE = static_cast<drivercrate::NativeError>(
		// 先頭選択しない診断
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
		// 同HINF全値・同名・source一行・subdir一致の正例だけを元source成功へ変更する
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
		// 原45構成を残し、相対13の元source条件だけを独立に追加する
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
	} ; // 原45と追加13を分け、合法未対応・不正・曖昧を削減しない
	static_assert( CASES.size() == 58U) ;
	// 全構成を実SetupAPI・固定memberへ結び、source位置とbinary原値を別に確認する
	for( std::size_t index = 0U; index < CASES.size(); ++index) {
		const auto				 &testCase = CASES[index] ;	// 静的ASCII構成だけを同期借用する
		OfficialDownloadWorkspace workspace ;				// この構成の架空byteだけを所有する
		DRIVERCRATE_EXPECT( context,
						   workspace.initialize( L"maint-binary-source", 1200U + index) == 0) ;
		std::string extra = "[ServiceInstall]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\n"
							"ServiceBinary=" +
							std::string( testCase.binary) + "\r\n[Files]\r\n" +
							std::string( testCase.rows) +
							"[SecondFiles]\r\nsource.sys\r\n[DestinationDirs]\r\n" +
							// 他OS節は到達listの根拠にしない
							std::string( testCase.destinations) ;
		extra += "[OtherOS.NTx86]\r\nCopyFiles=ForeignFiles\r\n[ForeignFiles]\r\nsource.sys\r\n" ;
		// 媒体の欠落をsource節不在と別にする
		if( testCase.mediaDeclared) {
			extra += "[SourceDisksNames.amd64]\r\n1=Fictional,,," +
					 std::string( testCase.mediaDirectory) + "\r\n" ;
		}

		// 元source宣言の全位置を残し、別名copyのdestinationで照会しない
		if( testCase.sourceDeclared) {
			extra += "[SourceDisksFiles.amd64]\r\nsource.sys=1," +
					 std::string( testCase.sourceDirectory) + "\r\nother.sys=1," +
					 std::string( testCase.sourceDirectory) + "\r\n" ;
			// 同名source行をそのまま残し、APIの先頭選択を一意性の証明にしない
			if( testCase.duplicateSource) {
				extra += "source.sys=1," + std::string( testCase.sourceDirectory) + "\r\n" ;
			}
		}

		const std::string  inf = makeMaintenanceInf( "AddService=FictionalService,2,ServiceInstall",
													testCase.copy, extra) ;	// 元一INF
		const std::wstring parentPrefix =
			testCase.infParent.empty()
				? std::wstring{}
				: std::wstring( testCase.infParent) + L"\\" ;		// 元INF親だけの固定prefix
		const std::wstring infPath = parentPrefix + L"sample.inf" ;	// 今回の元INF相対位置
		const std::wstring catPath = parentPrefix + L"sample.cat" ;	// 同じ元INF親のCAT位置
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, infPath, inf)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, catPath, "unsigned")) ;
		const std::wstring memberPrefix =
			parentPrefix + std::wstring( testCase.memberDirectory) +
			(testCase.memberDirectory.empty() ? L"" : L"\\") ;			// 不正媒体pathを使わない固定member親
		const std::wstring sourcePath = memberPrefix + L"source.sys" ;	// 同じ原memberの正式名
		const std::wstring otherPath  = memberPrefix + L"other.sys" ;	// 異source曖昧の独立member
		std::vector<OfficialZipEntry> entries{
			{infPath, inf.size()}, {catPath, 8U}, {otherPath, 6U}} ;	// 閉じた元集合
		// 元byte差の拒否はnamed13の位置照合より前の全体境界で維持する
		if( testCase.changedInfBytes) {
			entries.front().sha256.assign( 64U, L'0') ;
		}

		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, otherPath, "second")) ;
		// 明示member欠落だけを変え、元INFのsource参照を消さない
		if( !testCase.missingMember) {
			DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, sourcePath, "driver")) ;
			entries.push_back( {sourcePath, 6U}) ;
			// 固定memberの同位置衝突を先頭候補へ絞らない
			if( testCase.duplicateMember) {
				entries.push_back( {sourcePath, 6U}) ;
			}
		}

		const std::array<std::wstring, 2U> seeds{L"Install.NT",
												 L"Install.NT.Services"} ;	// 元明示選択
		MaintenanceInfReferences		   references ;						// 位置はbyte署名の成功ではない
		const NativeError				   error = inspectMaintenanceInfReferences(
			 workspace, entries, infPath, seeds, MAINTENANCE_POLICY, references) ;	// 非実行観測
		// DIRID13と媒体未宣言の初回差は同じ元INFでAPI段階だけを診断し、pathを表示しない
		if( index == 5U || index == 6U || index == 7U || index == 25U) {
			const HINF raw = SetupOpenInfFileW( workspace.path( infPath).c_str(), nullptr,
											   INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											   nullptr) ;	// 直後にRAIIへ所有を移す
			const std::unique_ptr<void, decltype( &SetupCloseInfFile)> diagnostic(
				raw == INVALID_HANDLE_VALUE ? nullptr : raw,
				&SetupCloseInfFile) ;	// 全経路で元HINFを閉じる
			// 同じINFを開けた場合だけ元field／directory／media APIの状態を照合する
			if( diagnostic) {
				INFCONTEXT line{} ;	// 元ServiceBinary行の同期context
				const BOOL found =
					SetupFindFirstLineW( diagnostic.get(), L"ServiceInstall", L"ServiceBinary",
										&line) ;	// 元行を明示して取得する
				DWORD stringRequired{} ;			// 元field必要長
				SetLastError( ERROR_SUCCESS) ;
				const BOOL stringRead =
					found ? SetupGetStringFieldW( &line, 1U, nullptr, 0U, &stringRequired)
						  : FALSE ;							// 第一段階だけを観測する
				const DWORD stringError = GetLastError() ;	// 元field APIの直後診断
				DWORD		targetRequired{} ;				// 元named directory必要長
				SetLastError( ERROR_SUCCESS) ;
				const BOOL targetRead =
					SetupGetTargetPathW( diagnostic.get(), nullptr, L"Files", nullptr, 0U,
										&targetRequired) ;	// defaultを使用しない明示照会
				const DWORD targetError = GetLastError() ;	// target APIの直後診断
				UINT		sourceId{} ;					// 元媒体identity
				DWORD		sourceRequired{} ;				// 元SourceDisksFiles subdir必要長
				SetLastError( ERROR_SUCCESS) ;
				const BOOL sourceRead = SetupGetSourceFileLocationW(
					diagnostic.get(), nullptr, L"source.sys", &sourceId, nullptr, 0U,
					&sourceRequired) ;						// 元source名だけを使う
				const DWORD sourceError = GetLastError() ;	// source APIの直後診断
				DWORD		mediaRequired{} ;				// 元媒体path必要長
				SetLastError( ERROR_SUCCESS) ;
				const BOOL mediaRead =
					SetupGetSourceInfoW( diagnostic.get(), sourceId, SRCINFO_PATH, nullptr, 0U,
										&mediaRequired) ;	// 媒体未宣言の既定値を別に確認する
				const DWORD	 mediaError = GetLastError() ;	// 媒体APIの直後診断
				std::wstring binaryValue ;					// 形だけを数値で出力し、具体的pathを表示しない
				std::wstring targetValue ;					// 同じnamed entryの形だけを比較する
				// 有限必要長を確定した元fieldだけを第二段階で取得する
				if( stringRead && stringRequired != 0U && stringRequired <= 4096U) {
					std::vector<wchar_t> buffer( stringRequired) ;	// 終端込みの元必要長だけを確保する
					// 全field取得が成功した場合だけ形を観測する
					if( SetupGetStringFieldW( &line, 1U, buffer.data(), stringRequired, nullptr)) {
						binaryValue = buffer.data() ;
					}
				}

				// 同じ一INFのnamed targetを有限bufferへ取得し、fieldと分けて観測する
				if( targetRead && targetRequired != 0U && targetRequired <= 4096U) {
					std::vector<wchar_t> buffer( targetRequired) ;	// 終端込みのtarget必要長
					// 全directory取得が成功した場合だけ形を比較する
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
		// 全体拒否の部分観測を成功へ残さない
		if( testCase.callError != 0) {
			DRIVERCRATE_EXPECT( context, references.files.empty() && references.infSha256.empty()) ;
			continue ;
		}

		const auto count = std::ranges::count_if( references.files, []( const auto &file) {
			return file.directive == L"ServiceBinary" ;
		}) ; // 観測欠落を空guardで成功にしない具体用途数
		DRIVERCRATE_EXPECT( context, count == 1) ;
		// 一参照を得られなかった場合は不一致を保持して範囲外参照を避ける
		if( count != 1) {
			continue ;
		}

		const auto binary = std::ranges::find_if( references.files, []( const auto &file) {
			return file.directive == L"ServiceBinary" ;
		}) ; // 既に非空と確認した元用途
		DRIVERCRATE_EXPECT( context, !binary->target.empty()) ;
		DRIVERCRATE_EXPECT( context, binary->section == L"ServiceInstall" &&
										binary->directive == L"ServiceBinary") ;
		// 新相対正例は元全targetを保持し、literal DIRIDの逆証明を要求しない
		if( (index == 5U || index >= 45U) &&
		   testCase.location == MaintenanceInfFileLocation::LOCATED) {
			DRIVERCRATE_EXPECT( context, binary->target.starts_with( L".\\") &&
											binary->target != L"source.sys") ;
		}

		const bool expectedError =
			testCase.location == MaintenanceInfFileLocation::UNSUPPORTED &&
					testCase.locationError == 0
				? binary->error != 0
				: binary->error == testCase.locationError ;	// 元Windows診断の独立期待
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
		// 固定member位置を得た時だけ元source名を要求し、destination別名へ書き換えない
		if( testCase.location == MaintenanceInfFileLocation::LOCATED ||
		   testCase.location == MaintenanceInfFileLocation::MISSING) {
			DRIVERCRATE_EXPECT( context,
							   binary->relativePath == (testCase.expectedRelativePath.empty()
															? std::wstring_view( sourcePath)
															: testCase.expectedRelativePath)) ;
		}

		// 別名正例のbinary原値を元source名で上書きしない
		if( index == 2U || index == 3U || index == 4U) {
			DRIVERCRATE_EXPECT( context, binary->target.ends_with( L"renamed.sys")) ;
		}
	}

	std::cout << "Maintenance binary source cases: baseline 45, relative13 13\n" ;
	// metadataの全行とfieldにも既存上限を適用し、未知keyで容量を回避させない
	for( const bool excessiveLines : {false, true}) {
		std::string destinations = "Files=12" ;	// 正常なnamed entryから境界だけを追加する
		// 一行64 fieldの上限＋1を原値のまま作る
		if( !excessiveLines) {
			destinations.append( 64U, ',') ;
			destinations += "\r\n" ;
		} else {
			destinations += "\r\n" ;
			// 未到達keyの4,097行も一つの共同予算へ含める
			for( std::size_t row = 0U; row < 4097U; ++row) {
				destinations += "Unknown" + std::to_string( row) + "=12\r\n" ;
			}
		}

		const std::string inf = makeMaintenanceInf(
			"AddService=FictionalService,2,ServiceInstall", "CopyFiles=Files\r\n",
			"[Files]\r\nsource.sys\r\n[ServiceInstall]\r\nServiceType=1\r\nStartType=3\r\n"
			"ErrorControl=1\r\nServiceBinary=%12%\\source.sys\r\n[SourceDisksNames.amd64]\r\n"
			"1=Fictional,,,\r\n[SourceDisksFiles.amd64]\r\nsource.sys=1\r\n[DestinationDirs]\r\n" +
				destinations) ;					// 上限試験でも元sourceを明示する
		OfficialDownloadWorkspace workspace ;	// 架空過大INFだけを一scopeで所有する
		DRIVERCRATE_EXPECT(
			context, workspace.initialize( L"maint-binary-limit", 1290U + excessiveLines) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", inf)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
		const std::array				   entries{OfficialZipEntry{L"sample.inf", inf.size()},
								   OfficialZipEntry{L"sample.cat", 8U},
								   OfficialZipEntry{L"source.sys", 6U}} ;					// 位置だけの閉集合
		const std::array<std::wstring, 2U> seeds{L"Install.NT", L"Install.NT.Services"} ;	// 明示名
		MaintenanceInfReferences		   references ;										// 上限拒否は必ず空結果にする
		DRIVERCRATE_EXPECT(
			context,
			inspectMaintenanceInfReferences( workspace, entries, L"sample.inf", seeds,
											MAINTENANCE_POLICY, references) ==
				static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW))) ;
		DRIVERCRATE_EXPECT( context, references.files.empty() &&
										references.inventory.visitedSections.empty()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 500 named listと500 binaryを同じINFの共同上限内で位置照合し、時間を記録する
 * @param[in,out] context 一processの有限assertion集計
 * @note 元sourceは一架空fileへ共有する。全候補比較を保持し、実directoryをopenしない
 */
//------------------------------------------------------------------------------
void testMaintenanceBinarySourceCapacity( TestContext &context)
{
	constexpr std::size_t COUNT = 500U ;							// 1,024節／4,096行を越えない閉じた容量構成
	std::string			  install ;									// 一行最大64 fieldで500 listを明示する原DDInstall
	std::string			  services ;								// 全namedを補助flags0として構造へ結ぶ宣言
	std::string			  sections ;								// 各copy／serviceを原名で一意に持つ架空節
	std::string			  destinations = "[DestinationDirs]\r\n" ;	// named固有entryだけの原metadata
	// 全500を同じ一INFへ組み、分割による上限resetをしない
	for( std::size_t index = 0U; index < COUNT; ++index) {
		const std::string suffix = std::to_string( index) ;	// 架空名称だけの有限識別子
		// 一行64 listを越える前に新しいCopyFiles宣言を開始する
		if( index % 64U == 0U) {
			install += "CopyFiles=" ;
		} else {
			install += "," ;
		}

		install += "Files" + suffix ;
		// 現行field上限と末尾終端を維持する
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
			"[SourceDisksNames.amd64]\r\n1=Fictional,,,\r\n[SourceDisksFiles.amd64]\r\nsource.sys=1\r\n") ;	// 元一INF
	// この容量構成の架空byteだけを同期所有する
	OfficialDownloadWorkspace workspace ;
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"maint-binary-capacity", 1299U) == 0) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", inf)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"source.sys", "driver")) ;
	const std::array				   entries{OfficialZipEntry{L"sample.inf", inf.size()},
							   OfficialZipEntry{L"sample.cat", 8U},
							   OfficialZipEntry{L"source.sys", 6U}} ;					// 元source一件の閉集合
	const std::array<std::wstring, 2U> seeds{L"Install.NT", L"Install.NT.Services"} ;	// 原明示選択
	MaintenanceInfReferences		   references ;										// 署名の証拠とは互換でない位置だけ
	const auto		  started = std::chrono::steady_clock::now() ;						// この同期APIの開始時刻
	const NativeError error	  = inspectMaintenanceInfReferences(
		  workspace, entries, L"sample.inf", seeds, MAINTENANCE_POLICY, references) ;	// 一度の容量観測
	const double seconds = std::chrono::duration<double>( std::chrono::steady_clock::now() - started)
							   .count() ;	// 実完了時間だけを記録する
	DRIVERCRATE_EXPECT( context, error == 0) ;
	DRIVERCRATE_EXPECT( context,
					   references.referenceCoverage == MaintenanceInfReferenceCoverage::COMPLETE) ;
	const auto binaries = std::ranges::count_if( references.files, []( const auto &file) {
		return file.directive == L"ServiceBinary" ;
	}) ; // 空guardで欠落を成功へ補完しない主分母
	DRIVERCRATE_EXPECT( context, binaries == static_cast<std::ptrdiff_t>( COUNT)) ;
	DRIVERCRATE_EXPECT( context, references.inventory.visitedSections.size() <= 1024U &&
									references.inventory.scannedLines <= 4096U) ;
	DRIVERCRATE_EXPECT( context, references.sourceFiles == std::vector<std::wstring>{L"source.sys"}) ;
	// 全500の原binary用途が同じ明示sourceへ一意に結べたことを確認する
	for( const auto &file : references.files) {
		// 具体的な全binaryに位置・元診断・元sourceを要求する
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

/** @brief 一つの架空archiveへ格納する所有byteとASCII正式名 */
struct MaintenanceDependencyZipFile {
	/// 架空の元member名。実Windows fileを複写しない
	std::string name ;
	/// このfixtureだけの元byte列
	std::string bytes ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 閉じた架空member集合をMinizの非実行archiveへまとめる
 * @param[in] files fixtureが所有する元byteと一意相対名
 * @return 全成功時のZIP byte。生成失敗はfixture例外とする
 * @throws std::runtime_error Miniz初期化・確定失敗
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string makeMaintenanceDependencyArchive(
	std::span<const MaintenanceDependencyZipFile> files)
{
	mz_zip_archive writer{} ;	// この関数だけの非実行memory writer
	// fixture生成失敗をparser成功やskipにしない
	if( mz_zip_writer_init_heap( &writer, 0U, 0U) == 0) {
		throw std::runtime_error( "dependency ZIP initialize") ;
	}

	bool added = true ;	// 全memberの追加を要求する
	// 架空memberだけを原順で格納し、外部fileを開かない
	for( const auto &file : files) {
		added = added && mz_zip_writer_add_mem( &writer, file.name.c_str(), file.bytes.data(),
											   file.bytes.size(), MZ_NO_COMPRESSION) != 0 ;
	}

	void	   *bytes{} ;	// 確定直後に単独RAIIへ移すMiniz buffer
	std::size_t size{} ;	// 確定ZIP byte数
	const bool	finalized =
		added && mz_zip_writer_finalize_heap_archive( &writer, &bytes, &size) != 0 ;	// 全確定
	const std::unique_ptr<void, decltype( &mz_free)> owned( bytes, &mz_free) ;			// 全経路で解放する
	const bool ended = mz_zip_writer_end( &writer) != 0 ;								// string確保前にwriterを解放する
	// 一memberの失敗でも部分archiveを検査へ渡さない
	if( !finalized || !ended || owned == nullptr || size == 0U) {
		throw std::runtime_error( "dependency ZIP finalize") ;
	}

	return {static_cast<const char *>( owned.get()), size} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 明示空sourceとnull参照の位置・必要byte・全現在OS選択を独立に確認する
 * @param[in,out] context 一processの有限assertion集計
 * @note 架空PortsのClass名policyとsource境界だけを比較し、dummy CATを署名成功にしない。内容構造の成功は端末適合・導入許可を発行しない
 */
//------------------------------------------------------------------------------
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
		.maximumNestedArchiveDepth = 1U} ;	// この六fixtureに必要な有限上限だけを使用する
	// 無参照空source・参照完備・空source参照・byte欠落・source不在・後続選択を全て確認する
	for( std::size_t scenario = 0U; scenario < 6U; ++scenario) {
		const bool emptySource =
			// 宣言は存在し行は0
			scenario == 0U || scenario == 2U || scenario == 5U ;
		const bool sourcePresent = scenario != 4U ;	// source不在を明示空と区別する
		const bool payloadPresent =
			// 架空必要byteの有無
			scenario == 1U || scenario == 2U || scenario == 5U ;
		const std::string extra =
			(sourcePresent ? std::string( "[SourceDisksNames.amd64]\r\n1=Fake,,,\r\n"
										 "[SourceDisksFiles.amd64]\r\n") +
								 (emptySource ? "" : "sample.sys=1\r\n")
						   : "") +
			std::string( scenario == 5U ? "[Second.NT]\r\nCopyFiles=@sample.sys\r\n"
										 "[Second.NT.Services]\r\nAddService=,2\r\n"
									   : "") ;	// 他OSの不正fixtureは既存helperへ保持する
		std::string inf = makeMaintenanceInf(
			"AddService=,2", scenario == 0U || scenario == 5U ? "" : "CopyFiles=@sample.sys\r\n",
			extra,
			// 架空元byte
			scenario == 5U ? "Second=Second,ROOT\\FICTIONAL_SOURCE_0002\r\n" : "") ;
		inf.replace( inf.find( "Class=System"), std::string_view( "Class=System").size(),
					"Class=Ports") ;
		MaintenanceInfStructure structure ;	// 元全選択とsourceの不在／空集合を保持する
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
		// 後続現在OS選択の参照を先頭nullの空集合へ落とさず、元節名へ結ぶ
		if( scenario == 5U) {
			DRIVERCRATE_EXPECT(
				context,
				structure.installs.at( 0U).contentKind == MaintenanceInfContentKind::NULL_DRIVER &&
					structure.installs.at( 1U).inventory.selectedInstallSection == L"Second.NT" &&
					structure.installs.at( 1U).contentKind == MaintenanceInfContentKind::MIXED) ;
		}

		std::vector<MaintenanceDependencyZipFile> files{
			{"sample.inf", inf}, {"sample.cat", "unsigned"}} ;	// root INF／CATの元memberは必須
		// 正例と位置未対応caseだけに元payloadを置き、byte存在でsource宣言を補完させない
		if( payloadPresent) {
			files.push_back( {"sample.sys", "driver"}) ;
		}

		const std::string archive = makeMaintenanceDependencyArchive( files) ;	// 架空閉じた元ZIP
		OfficialDownloadWorkspace source ;										// source元byteはこのscopeで単独所有する
		DRIVERCRATE_EXPECT( context,
						   source.initialize( L"maint-source-matrix", 700U + scenario) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( source, L"payload.zip", archive)) ;
		std::wstring hash ;	// 同じ元byteを通常／保守双方へ結ぶ
		DRIVERCRATE_EXPECT( context, computeFileSha256( source.path( L"payload.zip"), hash) == 0) ;
		const DriverArchiveInput input{700U + scenario, source.path( L"payload.zip"), archive.size(),
									   hash} ;								// 由来なし
		const std::array<std::wstring_view, 1U> selected{L"sample.inf"} ;	// 一rootを一runで検査する
		OfficialDownloadWorkspace				workspace ;					// この保守閉包だけを所有する
		MaintenanceDriverClosure				closure ;					// 構造の成功を導入型へ変換しない
		const NativeError						error = extractMaintenanceDriverClosure(
			  {&input, OfficialDriverArchiveFormat::ZIP, {}, selected, L"maint-source-out"},
			  SOURCE_POLICY, workspace, closure) ;	// 非実行の有限内容観測
		DRIVERCRATE_EXPECT( context, error == 0) ;
		// fixtureの全体拒否後に部分配列を借用しない
		if( error != 0) {
			continue ;
		}

		DRIVERCRATE_EXPECT( context, closure.references.size() == 1U) ;
		const auto &references = closure.references.at( 0U) ;	// 同じ一rootの全seed棚卸し
		const auto	coverage =
			 scenario <= 1U
				 ? MaintenanceInfReferenceCoverage::COMPLETE
				 : MaintenanceInfReferenceCoverage::INCOMPLETE ;	// file位置と署名の成否を分ける
		DRIVERCRATE_EXPECT( context, references.sourceSectionPresent == sourcePresent) ;
		DRIVERCRATE_EXPECT( context, references.referenceCoverage == coverage &&
										closure.structure.referenceCoverage == coverage) ;
		DRIVERCRATE_EXPECT( context, references.sourceFiles.size() == (scenario == 1U ? 1U : 0U)) ;
		// null＋copyはsource位置または具体的欠落を保持し、fileを空集合へ消さない
		if( scenario > 0U) {
			const auto copy = std::ranges::find_if( references.files, []( const auto &file) {
				return file.directive == L"CopyFiles" && file.target == L"sample.sys" ;
			}) ; // 同じ原用途だけを照合する
			DRIVERCRATE_EXPECT( context, copy != references.files.end()) ;
			// 原用途を取得できた場合だけ位置と元診断を比較する
			if( copy != references.files.end()) {
				DRIVERCRATE_EXPECT(
					context,
					copy->location ==
						(scenario == 1U
							 ? MaintenanceInfFileLocation::LOCATED
							 : (scenario == 3U ? MaintenanceInfFileLocation::MISSING
											   : MaintenanceInfFileLocation::UNSUPPORTED))) ;
				DRIVERCRATE_EXPECT( context, scenario == 1U ? copy->error == 0 : copy->error != 0) ;
				// 宣言済みの必要byte欠落は未対応位置と区別し、元file診断を保つ
				if( scenario == 3U) {
					DRIVERCRATE_EXPECT(
						context, copy->relativePath == L"sample.sys" &&
									 copy->error == static_cast<drivercrate::NativeError>(
														HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND))) ;
				}

				// 全Modelsから選ばれた後続節の原用途であることを確認する
				if( scenario == 5U) {
					DRIVERCRATE_EXPECT( context, copy->section == L"Second.NT") ;
				}
			}
		}

		MaintenanceDriverPackageInspection maintenance ;	// 外向き結果も通常routeとは独立する
		DRIVERCRATE_EXPECT( context, inspectMaintenanceDriverPackage(
										input, OfficialDriverArchiveFormat::ZIP, maintenance) == 0) ;
		DRIVERCRATE_EXPECT( context, maintenance.infs.size() == 1U) ;
		// 同じrootの観測が得られた場合だけunknown・通常routeを比較する
		if( maintenance.infs.size() == 1U) {
			// 架空source条件のrouteだけを数値観測し、署名/内容結果を変えません
			std::cout << "INF_SOURCE_ROUTE scenario=" << scenario
					  << " state=" << static_cast<int>( maintenance.infs.front().installRoute.state)
					  << " error=" << maintenance.infs.front().installRoute.error << '\n' ;
			const auto &row = maintenance.infs.front() ;	// 端末適合を照合していないDTO
			DRIVERCRATE_EXPECT( context, row.parser.state == MaintenanceInspectionState::PASSED &&
											row.contentKind == structure.contentKind &&
											row.referenceCoverage == coverage) ;
			DRIVERCRATE_EXPECT( context,
							   row.applicability.state == MaintenanceInspectionState::NOT_CHECKED &&
								   row.applicability.error == 0 &&
								   row.integrity.state != MaintenanceInspectionState::PASSED) ;
			// Portsのnull serviceはsource位置が揃っても通常service構造の許可を得ません
			DRIVERCRATE_EXPECT(
				context, row.installRoute.state == MaintenanceInspectionState::UNSUPPORTED &&
							 row.installRoute.error ==
								 static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED))) ;
		}

		CommonDriverPackageInspection normal ;	// 空sourceや必要byte欠落を従来通常policyが拒否する
		DRIVERCRATE_EXPECT( context, inspectCommonDriverPackage(
										input, OfficialDriverArchiveFormat::ZIP, normal) == 0) ;
		DRIVERCRATE_EXPECT( context, normal.infs.size() == 1U) ;
		// 内容認識で通常source必須・署名の拒否段階を変更させない
		if( normal.infs.size() == 1U) {
			DRIVERCRATE_EXPECT( context,
							   normal.infs.front().state ==
								   (scenario == 1U ? CommonInfInspectionState::SIGNATURE_REJECTED
												   : CommonInfInspectionState::CLOSURE_REJECTED)) ;
			DRIVERCRATE_EXPECT( context, normal.infs.front().error != 0) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief sourceなしnullと有限package依存の抽出・未知／FAILED保持を確認する
 * @param[in,out] context 一processの有限assertion集計
 * @note dummy CATは常に実署名の負例。実device列挙・staging・導入・追加取得を呼ばない
 */
//------------------------------------------------------------------------------
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
		.maximumNestedArchiveDepth = 1U} ;	// 一root選択と候補closureの上限を区別する
	// 無参照・参照付き・依存の原形を小matrixで比較する
	for( std::size_t scenario = 0U; scenario < 11U; ++scenario) {
		std::string componentBody ;	// 核が扱わない明示component／コピーINFの二形
		// 二用途だけを追加し、他部品の展開・全作用解析へ広げない
		if( scenario == 9U || scenario == 10U) {
			componentBody = scenario == 9U
								? "AddComponent=FictionalComponent,0,ComponentSection\r\n"
								: "CopyINF=fixture-dep.inf\r\n" ;
		}

		const std::string install =
			scenario == 1U
				? "CopyFiles=@sample.sys\r\n"
				: (scenario >= 2U ? "Include=fixture-dep.inf\r\nNeeds=Shared\r\n" : "") ;	// 原base節
		const std::string services =
			"AddService=,2\r\n" +
			std::string( scenario == 4U
							? "Needs=Shared.Services\r\n"
							: (scenario == 3U
								   ? "Include=fixture-dep.inf\r\nNeeds=Shared.Services\r\n"
								   : "")) ;	// 同節条件
		const std::string peer =
			"[Version]\r\nSignature=\"$Windows NT$\"\r\nCatalogFile=fixture-dep.cat\r\n"
			"[Shared]\r\n" +
			std::string( scenario == 6U ? "Needs=Shared\r\n" : "") +
			"[Shared.Services]\r\n[Shared.NTx86]\r\nUnknownOtherOS=ignored\r\n" ;	// 明示節と別OS
		const std::string extra =
			scenario == 7U ? "[Second.NT]\r\nInclude=fixture-missing.inf\r\nNeeds=Absent\r\n"
						   : (scenario == 8U ? "[Install.NT.HW]\r\nUnknownFileUse=mystery.dll\r\n"
											 : "") ;	// 後続選択と付随節
		const std::string inf = makeMaintenanceInf(
			services, scenario >= 9U ? componentBody : install,
			extra + (scenario == 9U ? "[ComponentSection]\r\nFeatureScore=0xF0\r\n" : ""),
			scenario == 7U ? "Second=Second,ROOT\\FICTIONAL_DEPENDENCY_0002\r\n"
						   : "") ;	// 全現在OS構造
		std::vector<MaintenanceDependencyZipFile> files{
			{"driver/sample.inf", inf},
			{"driver/sample.cat", "unsigned"}} ;	// root INF／CATは常に元memberへ固定する
		// 参照付きnullはsource未宣言でも実file存在を無参照の根拠にしない
		if( scenario == 1U) {
			files.push_back( {"driver/sample.sys", "driver"}) ;
		}

		// 未発見case以外は、同名候補のbyteを閉じたarchiveだけへ置く
		if( (scenario >= 3U && scenario < 9U) || scenario == 10U) {
			files.push_back( {"driver/fixture-dep.inf", peer}) ;
			files.push_back( {"driver/fixture-dep.cat", "unsigned"}) ;
		}

		// 元親とpackage rootの二候補を先頭選択で隠さない
		if( scenario == 5U) {
			files.push_back( {"fixture-dep.inf", peer}) ;
			files.push_back( {"fixture-dep.cat", "unsigned"}) ;
		}

		const std::string		  archive = makeMaintenanceDependencyArchive( files) ;	// 架空元ZIP
		OfficialDownloadWorkspace source ;												// 元ZIPの単独所有者
		DRIVERCRATE_EXPECT( context,
						   source.initialize( L"maint-dependency-test", 650U + scenario) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( source, L"payload.zip", archive)) ;
		std::wstring hash ;	// 実元byteへ固定するidentity
		DRIVERCRATE_EXPECT( context, computeFileSha256( source.path( L"payload.zip"), hash) == 0) ;
		const DriverArchiveInput input{650U + scenario, source.path( L"payload.zip"), archive.size(),
									   hash} ;										// 由来なし
		const std::array<std::wstring_view, 1U> selected{L"driver\\sample.inf"} ;	// 正式一rootだけ
		OfficialDownloadWorkspace				workspace ;							// 今回の内容閉包だけを単独所有する
		MaintenanceDriverClosure				closure ;							// 通常導入型へ暗黙変換しない
		const auto								error = extractMaintenanceDriverClosure(
			 {&input, OfficialDriverArchiveFormat::ZIP, {}, selected, L"maint-dep-output"},
			 DEPENDENCY_POLICY, workspace, closure) ;	// 実device APIへ接続しない
		DRIVERCRATE_EXPECT( context, error == 0) ;
		// fixture拒否の後に部分配列を参照して試験processを破壊しない
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
		// 無参照nullでもroot INF／CATを抽出し、署名失敗を未検査で消さない
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
		// 位置が全て確定したpackageは署名・由来不足だけでcoverageを取り消さない
		else if( scenario == 3U) {
			DRIVERCRATE_EXPECT( context, closure.structure.referenceCoverage ==
											MaintenanceInfReferenceCoverage::COMPLETE) ;
		} else {
			DRIVERCRATE_EXPECT( context, closure.structure.referenceCoverage ==
											MaintenanceInfReferenceCoverage::INCOMPLETE) ;
		}

		// 未発見・別節借用・曖昧・循環を具体理由付きで保持する
		if( scenario == 2U || scenario == 4U || scenario == 5U || scenario == 6U || scenario == 7U) {
			const auto reason = scenario == 5U
									? InfDependencyReason::AMBIGUOUS
									: (scenario == 6U ? InfDependencyReason::CYCLE
													  : InfDependencyReason::MISSING) ;	// 原不足種類
			DRIVERCRATE_EXPECT( context, closure.structure.dependency.state ==
											MaintenanceInfDependencyState::UNRESOLVED) ;
			DRIVERCRATE_EXPECT( context, std::ranges::any_of( closure.dependency.dependency.edges,
															[reason]( const auto &edge) {
																return edge.reason == reason ;
															})) ;
		}

		// 核の未対応依存をNONEへ射影せず、原用途と独立診断を保持する
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

		// 同節base／Servicesの独立Needsは原名のまま観測し、裸local由来を昇格しない
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

		MaintenanceDriverPackageInspection aggregate ;	// 閉包の各軸を保守DTOへ結ぶ。導入型は持たない
		DRIVERCRATE_EXPECT( context, inspectMaintenanceDriverPackage(
										input, OfficialDriverArchiveFormat::ZIP, aggregate) == 0) ;
		DRIVERCRATE_EXPECT( context, !aggregate.infs.empty()) ;
		const auto projected = std::ranges::find_if( aggregate.infs, [&closure]( const auto &row) {
			return row.infSha256 == closure.structure.infSha256 ;
		}) ; // 同じroot byteを借用し、別INF行を先頭選択で代用しない
		DRIVERCRATE_EXPECT( context, projected != aggregate.infs.end()) ;
		// 同じrootの射影が取得できた場合だけ独立軸と元診断を全て比較する
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
		// 初回の同じ元byteで取消しとhash差の全体破棄だけを有限確認する
		if( scenario == 0U) {
			MaintenanceDriverPackageInspection rejected ;	// 部分状態を公開してはならない全体拒否
			DRIVERCRATE_EXPECT(
				context,
				inspectMaintenanceDriverPackage( input, OfficialDriverArchiveFormat::ZIP, rejected,
												[] { return true ; }) ==
					static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))) ;
			DRIVERCRATE_EXPECT( context, rejected.infs.empty() && rejected.archiveSha256.empty() &&
											rejected.inspectedBytes == 0U) ;
			DriverArchiveInput changed = input ;	// 元fileは変更せず、誤ったhash指定だけを作る
			changed.sha256.assign( 64U, L'0') ;
			DRIVERCRATE_EXPECT(
				context, inspectMaintenanceDriverPackage( changed, OfficialDriverArchiveFormat::ZIP,
														 rejected) != 0) ;
			DRIVERCRATE_EXPECT( context, rejected.infs.empty() && rejected.archiveSha256.empty() &&
											rejected.inspectedBytes == 0U) ;
		}
	}

	std::string								  install ;	// root＋64候補で一run64 INF上限＋1を作る
	std::vector<MaintenanceDependencyZipFile> files{
		{"sample.cat", "unsigned"}} ;	// 架空CATだけの初期集合
	// 64の全明示名を一行64 field以内で与え、必要候補を切り捨てさせない
	for( std::size_t index = 0U; index < 64U; ++index) {
		const std::string name =
			"fixture-cap-" + std::to_string( index) + ".inf" ;	// 実OSと無関係な架空名
		install += (index == 0U ? "Include=" : ",") + name ;
		files.push_back( {name, "[Version]\r\nSignature=\"$Windows NT$\"\r\n"}) ;
	}

	install += "\r\n" ;
	files.push_back( {"sample.inf", makeMaintenanceInf( "AddService=,2", install)}) ;
	const std::string archive = makeMaintenanceDependencyArchive( files) ;	// 65 INFの有限原入力
	OfficialDownloadWorkspace source ;										// 原入力だけの単独所有者
	DRIVERCRATE_EXPECT( context, source.initialize( L"maint-dep-cap-test", 680U) == 0) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( source, L"payload.zip", archive)) ;
	std::wstring hash ;	// 実byteの元hash
	DRIVERCRATE_EXPECT( context, computeFileSha256( source.path( L"payload.zip"), hash) == 0) ;
	const DriverArchiveInput				input{680U, source.path( L"payload.zip"), archive.size(),
									  hash} ;							// 一閉包の固定入力
	const std::array<std::wstring_view, 1U> selected{L"sample.inf"} ;	// 一root選択
	OfficialDownloadWorkspace				workspace ;					// 上限拒否の部分fileはscope終了で破棄する
	MaintenanceDriverClosure				closure ;					// 全体失敗では空
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
		L"sample.inf", L"fixture-cap-0.inf"} ;		// 複数runでの予算回避をしない
	OfficialDownloadWorkspace multipleWorkspace ;	// 拒否前に初期化しない
	DRIVERCRATE_EXPECT(
		context,
		extractMaintenanceDriverClosure(
			{&input, OfficialDriverArchiveFormat::ZIP, {}, multiple, L"maint-multi-out"},
			DEPENDENCY_POLICY, multipleWorkspace, closure) ==
			static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED))) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 標準ComponentとSystem device serviceの内容・作用境界を確認します
 * @param[in,out] context 架空INFの成功と具体的拒否を集計します
 * @note CATを偽装せず、実driver/device/導入APIを使用しません
 */
//------------------------------------------------------------------------------
void testStandardComponentActions( TestContext &context)
{
	// 架空の原ComponentとType1/null/copy宣言です
	constexpr std::string_view INF =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=SoftwareComponent\r\n"
		"ClassGuid={5c4c3332-344d-483c-8739-259e934c9cc8}\r\nProvider=Fixture Vendor\r\n"
		"DriverVer=11/03/2026,2.0.0.0\r\nCatalogFile=sample.cat\r\n"
		"[Manufacturer]\r\nVendor=Models,NTamd64\r\n[Models.NTamd64]\r\n"
		"Device=Install,SWC\\SYNTHETIC_COMPONENT_635\r\n"
		"[Install.NT]\r\nCopyFiles=Files\r\n[Install.NT.Services]\r\nAddService=,2\r\n"
		"[Install.NT.Software]\r\nAddSoftware=FixtureComponent,1,Software\r\n"
		"[Software]\r\nSoftwareType=1\r\nSoftwareBinary=helper.exe\r\nSoftwareVersion=2.3.4.5\r\n"
		"[DestinationDirs]\r\nDefaultDestDir=13\r\n[Files]\r\nhelper.exe\r\nmodel.onnx\r\nkernels.hipfb\r\nuser32.dll\r\n"
		"[SourceDisksNames]\r\n1=fixture,,,\r\n[SourceDisksFiles]\r\n"
		"helper.exe=1\r\nmodel.onnx=1\r\nkernels.hipfb=1\r\nuser32.dll=1\r\n" ;
	const std::array			classes{std::wstring_view( L"SoftwareComponent"),
								// 検査する役割です
								std::wstring_view( L"System")} ;
	const std::array			signatures{std::wstring_view( L"$Windows NT$")} ;	// 原構文識別です
	OfficialInfInspectionPolicy policy{32U, 32U, classes, {}, signatures} ;			// 通常構成の有限検査です
	policy.acceptAnyProvider			 = true ;
	policy.requireDriverBinary			 = false ;
	policy.rejectUnreferencedPrograms	 = false ;
	policy.rejectInstallActions			 = true ;
	policy.allowRequiredDriverComponents = true ;
	// 正規宣言と、版・copy・役割・nullの独立した不正を各一回確認します
	for( unsigned scenario = 0U; scenario < 19U; ++scenario) {
		std::string body( INF) ;	// 条件ごとに元fixtureを作り直します
		// 変更先は固定fixtureの存在する全文だけです
		const auto	change = [&]( std::string_view before, std::string_view after) {
			 const auto position = body.find( before) ;	// 正確な原文位置です
			 DRIVERCRATE_EXPECT( context, position != body.npos) ;
			 // fixture前提の欠落を別位置の変更へ補完しません
			 if( position != body.npos) {
				 body.replace( position, before.size(), after) ;
			 }
		} ;
		// 正例、独立コピーと具体的な不正構造を区別します
		switch( scenario) {
			// 同一INFの正規Type1とnullです
			case 0U:
				break ;

			// programはコピーだけであり独自実行しません
			case 1U:
				change( "AddSoftware=FixtureComponent,1,Software", "") ;
				break ;

			// nullの誤flagをfunction-driver不在へ補完しません
			case 2U:
				change( "AddService=,2", "AddService=,0") ;
				break ;

			// named serviceの欠損節をnullにしません
			case 3U:
				change( "AddService=,2", "AddService=Named,2") ;
				break ;

			// 未対応TypeをType1に縮約しません
			case 4U:
				change( "SoftwareType=1", "SoftwareType=2") ;
				break ;

			// Type1はDriverStoreへの元コピーが必要です
			case 5U:
				change( "DefaultDestDir=13", "DefaultDestDir=11") ;
				break ;

			// 同名binaryでも元CopyFilesを欠く場合は拒否します
			case 6U:
				change( "CopyFiles=Files", "") ;
				break ;

			// roleのGUIDを名称から補完しません
			case 7U:
				change( "{5c4c3332-344d-483c-8739-259e934c9cc8}",
					   "{4d36e97d-e325-11ce-bfc1-08002be10318}") ;
				break ;

			// 16bitを超える版は未知の正規値へ切り詰めません
			case 8U:
				change( "SoftwareVersion=2.3.4.5", "SoftwareVersion=2.3.65536.5") ;
				break ;

			// binaryの実参照欠損は署名検証以前に拒否します
			case 9U:
				change( "SoftwareBinary=helper.exe", "SoftwareBinary=missing.exe") ;
				break ;

			// 同sourceがinventoryから欠けても、実file存在だけを使用しません
			case 10U:
				break ;

			// 以降は関連kernelに結んだSystem device serviceを別に検査します
			default:
				change( "Class=SoftwareComponent", "Class=System") ;
				change( "{5c4c3332-344d-483c-8739-259e934c9cc8}",
					   "{4d36e97d-e325-11ce-bfc1-08002be10318}") ;
				change( "SWC\\SYNTHETIC_COMPONENT_635", "ACPI\\SYNTHETIC_DEVICE_635") ;
				change( "AddSoftware=FixtureComponent,1,Software", "") ;
				change(
					"AddService=,2",
					"AddService=FixtureKernel,2,Kernel\r\nAddService=FixtureDevice,0x800,DeviceService") ;
				change( "user32.dll\r\n[SourceDisksNames]",
					   "user32.dll\r\nkernel.sys\r\n[SourceDisksNames]") ;
				body +=
					"kernel.sys=1\r\n[Kernel]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\nServiceBinary=%13%\\kernel.sys\r\n"
					"[DeviceService]\r\nServiceType=0x10\r\nStartType=2\r\nErrorControl=1\r\nServiceBinary=%13%\\helper.exe\r\nDependencies=FixtureKernel\r\n" ;
				// 明示外部service名も標準Dependenciesであり、不一致だけでは不適合にしません
				if( scenario == 12U) {
					change( "Dependencies=FixtureKernel", "Dependencies=ExternalUnknown") ;
				}

				// Systemと称する別GUIDへWin32 device serviceの権限を渡しません
				if( scenario == 13U) {
					change( "{4d36e97d-e325-11ce-bfc1-08002be10318}",
						   "{4d36e972-e325-11ce-bfc1-08002be10318}") ;
				}

				// 非関連kernelを同deviceのfunction driverと補完しません
				if( scenario == 14U) {
					change( "AddService=FixtureKernel,2,Kernel",
						   "AddService=FixtureKernel,0,Kernel") ;
				}

				// Dependencies省略と任意event-log第4fieldも標準形式です
				if( scenario >= 15U) {
					change( "Dependencies=FixtureKernel", "") ;
					change( "AddService=FixtureDevice,0x800,DeviceService",
						   "AddService=FixtureDevice,0x800,DeviceService,Events") ;
					body += "\r\n[Events]\r\n" ;
				}

				// Type/Nameまでの六fieldとload-order groupを保持します
				if( scenario == 16U) {
					change( "DeviceService,Events",
						   "DeviceService,Events,Application,Fixture Event") ;
					body += "[DeviceService]\r\nDependencies=+FixtureGroup,RpcSs\r\n" ;
				}

				// 未知typeを既知のSystem event-logへ補正しません
				if( scenario == 17U) {
					change( "DeviceService,Events", "DeviceService,Events,Unknown") ;
				}

				// 存在しない元event-log節は標準の省略扱いにしません
				if( scenario == 18U) {
					change( "[Events]", "[OtherEvents]") ;
				}

				break ;
		}

		OfficialDownloadWorkspace workspace ;	// この条件だけの所有fileです
		DRIVERCRATE_EXPECT( context,
						   workspace.initialize( L"standard-component-test", 1635U + scenario) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "synthetic")) ;
		std::vector<OfficialZipEntry> entries{{L"sample.inf", body.size()},
											  {L"sample.cat", 9U}} ;	// 元file一覧です
		// CAT未検証の架空payloadを置き、内容構造だけを検査します
		for( const auto name : {L"helper.exe", L"model.onnx", L"kernels.hipfb", L"user32.dll"}) {
			DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, name, "synthetic")) ;
			// 明示欠損の条件だけを元inventoryへ反映します
			if( scenario != 10U || std::wstring_view( name) != L"helper.exe") {
				entries.push_back( {name, 9U}) ;
			}
		}

		// System条件だけが同INFの関連kernelも参照します
		if( scenario >= 11U) {
			DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"kernel.sys", "synthetic")) ;
			entries.push_back( {L"kernel.sys", 9U}) ;
		}

		OfficialInfPackage package ;	// 内容構造だけで導入許可にはなりません
		// 同じ通常低位parserの元診断です
		const auto		   error =
			inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy, package) ;
		DRIVERCRATE_EXPECT( context,
						   (error == 0) == (scenario <= 1U || scenario == 11U || scenario == 12U ||
											scenario == 15U || scenario == 16U)) ;
		// 正例でも元SWC役割と署名未合格をそのまま保持します
		if( error == 0) {
			DRIVERCRATE_EXPECT( context, package.role == (scenario >= 11U
															 ? DriverPlanRole::BASE_DRIVER
															 : DriverPlanRole::DRIVER_COMPONENT)) ;
			DRIVERCRATE_EXPECT( context, package.sourceFiles.size() == (scenario >= 11U ? 5U : 4U) &&
											!package.hasExternalDependencies) ;
			DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, package) != 0) ;
		} else {
			DRIVERCRATE_EXPECT( context, package.infRelativePath.empty()) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 全てのSystemサービス宣言の検査と実行ファイル用の上限を確認します
 * @param[in,out] context 収集用途と通常用途の構造検査を集計します
 * @note 架空INFを読み取るだけで署名や導入許可を生成しません
 */
//------------------------------------------------------------------------------
void testCollectorSystemServiceBudget( TestContext &context)
{
	constexpr std::string_view INF =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=System\r\n"
		"ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}\r\nProvider=Fixture\r\n"
		"DriverVer=11/03/2026,2.0.0.0\r\nCatalogFile=sample.cat\r\n"
		"[DestinationDirs]\r\nDefaultDestDir=13\r\n[SourceDisksNames]\r\n1=fixture,,,\r\n"
		// 全33機器に共通の架空カーネルサービスです
		"[Kernel]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\nServiceBinary=%13%\\kernel.sys\r\n" ;
	// 正式Systemだけを対象にします
	const std::array classes{std::wstring_view{L"System"}} ;
	// 構文識別です
	const std::array signatures{std::wstring_view{L"$Windows NT$"}} ;
	// 正常収集、通常用途、最後の不正宣言、33件の実行ファイル参照、管理者領域を確認します
	for( unsigned scenario = 0U; scenario < 5U; ++scenario) {
		const bool	withPrograms = scenario == 3U ;	// 複数節に同じEXEを宣言する対照です
		std::string body{INF} ;						// 試行ごとの架空INFです
		std::string sections ;						// 各機器が所有する導入節とサービス節です
		body += "[SourceDisksFiles]\r\nkernel.sys=1\r\n" ;
		body += withPrograms ? "helper.exe=1\r\n[Files]\r\nkernel.sys\r\nhelper.exe\r\n"
							   "[Helper]\r\nServiceType=0x10\r\nStartType=2\r\nErrorControl=1\r\n"
							   "ServiceBinary=%13%\\helper.exe\r\n"
							 : "[Files]\r\nkernel.sys\r\n" ;
		body += "[Manufacturer]\r\nFixture=Models,NTamd64\r\n[Models.NTamd64]\r\n" ;
		// 一つのバイナリを正規の33機器が別々の節から参照します
		for( unsigned index = 0U; index < 33U; ++index) {
			const auto suffix  = std::to_string( index) ;	// 架空IDと元節の対応番号です
			const auto install = "Install" + suffix ;		// 同じ機器の選択節です
			body += "Device=" + install + ",ACPI\\SYNTHETIC_SERVICE_" + suffix + "\r\n" ;
			sections +=
				"[" + install + ".NT]\r\nCopyFiles=Files\r\n[" + install + ".NT.Services]\r\n" ;
			sections += scenario == 2U && index == 32U
							? "AddService=FixtureKernel,2,MissingService\r\n"
							: "AddService=FixtureKernel,2,Kernel\r\n" ;
			// 実行ファイルの重複は宣言数の計数から除きません
			if( withPrograms) {
				sections += "AddService=FixtureHelper,0,Helper\r\n" ;
			}
		}

		body += sections ;

		OfficialDownloadWorkspace workspace ;	// 当該対照だけが所有するローカル入力です
		const auto				  mode =
			   scenario == 4U
							   ? OfficialWorkspaceMode::ADMINISTRATOR
							   : OfficialWorkspaceMode::CURRENT_USER_INSPECTION ;	// 端末側と同じ領域を対照にします
		DRIVERCRATE_EXPECT(
			context, workspace.initialize( L"system-service-budget", 9870U + scenario, mode) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "synthetic")) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"kernel.sys", "synthetic")) ;
		std::vector<OfficialZipEntry> entries{
			OfficialZipEntry{L"sample.inf", body.size()}, OfficialZipEntry{L"sample.cat", 9U},
			OfficialZipEntry{L"kernel.sys", 9U}} ;	// 元配布の閉じた一覧です
		// 実行ファイル付き条件では同じ一つのファイルに全宣言を結びます
		if( withPrograms) {
			DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"helper.exe", "synthetic")) ;
			entries.push_back( OfficialZipEntry{L"helper.exe", 9U}) ;
		}

		OfficialInfInspectionPolicy policy{
			64U, 32U, classes, {}, signatures} ;	// 機器数は全33件を受け取ります
		policy.acceptAnyProvider					= true ;
		policy.allowRequiredDriverComponents		= true ;
		policy.rejectInstallActions					= true ;
		policy.allowReferencedExecutablesForContent = true ;
		policy.rejectUnreferencedPrograms			= false ;
		policy.purpose = scenario == 1U ? OfficialInfInspectionPurpose::STANDARD_DRIVER
										: OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;
		OfficialInfPackage package ;	// 読取り専用の結果です
		const auto error = inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy,
													 package) ;	// 元の診断です
		const std::array<HRESULT, 5U> expected{0, HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW),
											   HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED),
											   HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW),
											   // 各条件の期待値です
											   HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW)} ;
		DRIVERCRATE_EXPECT( context, error == expected[scenario]) ;
		DRIVERCRATE_EXPECT( context, package.hardwareIds.size() == (scenario == 0U ? 33U : 0U)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 原Systemのfileなし継承と、宣言file/作用の欠損を区別します
 * @param[in,out] context 架空INFだけの構造境界を集計します
 */
//------------------------------------------------------------------------------
void testInheritedSystemContent( TestContext &context)
{
	constexpr std::string_view INF =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=System\r\nClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}\r\n"
		"Provider=Fixture\r\nDriverVer=11/03/2026,2.0.0.0\r\nCatalogFile=sample.cat\r\n"
		"[Manufacturer]\r\nFixture=Models,NTamd64\r\n[Models.NTamd64]\r\nDevice=Install,ACPI\\SYNTHETIC_INHERIT_641\r\n"
		"[Install]\r\nInclude=systemfixture.inf\r\nNeeds=Inherited.NT\r\n" ;	// 実Windows本文や導入APIを借用しません
	const std::array classes{std::wstring_view{L"System"}} ;					// 正式GUIDも元INFから検査します
	const std::array signatures{std::wstring_view{L"$Windows NT$"}} ;			// 構文識別だけです
	OfficialInfInspectionPolicy policy{
		32U, 32U, classes, {}, signatures} ;	// 通常構成の有限policyです
	policy.acceptAnyProvider			 = true ;
	policy.requireDriverBinary			 = false ;
	policy.rejectUnreferencedPrograms	 = false ;
	policy.rejectInstallActions			 = true ;
	policy.allowRequiredDriverComponents = true ;
	// 継承正例と明示作用・宣言欠損の独立負例を一回ずつ検査します
	for( unsigned scenario = 0U; scenario < 6U; ++scenario) {
		std::string body{INF} ;	// 元条件ごとの独立fixtureです
		// 自身の宣言がある各条件をfileなし形式へ変換しません
		switch( scenario) {
			// 未解決継承を残す正規のfileなし内容です
			case 0U:
				break ;

			// 宣言されたvendor fileの欠損です
			case 1U:
				body +=
					"[SourceDisksNames]\r\n1=fixture,,,\r\n[SourceDisksFiles]\r\nmissing.sys=1\r\n" ;
				break ;

			// 元CopyFilesを欠損listのまま許可しません
			case 2U:
				body += "[Install]\r\nCopyFiles=Missing\r\n" ;
				break ;

			// 元ServiceBinaryを任意serviceの内容許可へ変えません
			case 3U:
				body += "[Service]\r\nServiceBinary=%13%\\missing.sys\r\n" ;
				break ;

			// System名だけでは別GUIDへ継承形式を渡しません
			case 4U:
				body.replace( body.find( "4d36e97d"), 8U, "4d36e972") ;
				break ;

			// Includeだけを未宣言Needsへ補完しません
			default:
				body.replace( body.find( "Needs=Inherited.NT"),
							 std::string_view{"Needs=Inherited.NT"}.size(), "") ;
				break ;
		}

		OfficialDownloadWorkspace workspace ;	// 架空INF/CATだけの所有者です
		DRIVERCRATE_EXPECT( context,
						   workspace.initialize( L"inherited-system-test", 2641U + scenario) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "synthetic")) ;
		const std::array   entries{OfficialZipEntry{L"sample.inf", body.size()},
								   OfficialZipEntry{L"sample.cat", 9U}} ;	// 欠損bodyは補完しません
		OfficialInfPackage package ;										// 内容成功も導入許可を持ちません
		const auto error = inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy,
													 package) ;	// 原構造の実結果です
		DRIVERCRATE_EXPECT( context, (error == 0) == (scenario == 0U)) ;
		// 正例の未解決依存と署名未合格を成功へ水増ししません
		if( scenario == 0U) {
			DRIVERCRATE_EXPECT( context, package.sourceFiles.empty() &&
											package.unresolvedIncludeNeeds &&
											package.hasExternalDependencies) ;
			DRIVERCRATE_EXPECT( context,
							   !isGenericInfPackageSupported( package) &&
								   verifyWindowsInfPackageIntegrity( workspace, package) != 0) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元Modelsのbare/GUID/asteriskと順序・kindを保持し、不正文字/用途超過を拒否します
 * @param[in,out] context 実INF readerの結果を集計します
 * @note 256文字は容器上限の試験であり、Windows hardware IDの200文字未満という適合保証ではありません
 */
//------------------------------------------------------------------------------
void testOpaqueNativeModels( TestContext &context)
{
	const std::vector<std::pair<std::string, bool>> cases{
		{"FictionalEnclosure", true},
		{"{11111111-2222-3333-4444-555555555555}", true},
		{"*FictionalDevice", true},
		{"FiCtIoNaL\\A\\B", true},
		{std::string( 256U, 'F'), true},
		{"", false},
		{"Fictional Device", false},
		{"Fictional,Device", false},
		{std::string{"Fictional\x01"}, false},
		{std::string{"Fictional\x7f"}, false},
		{std::string{"Fictional\xc3\xa9"}, false},
		{std::string( 257U, 'F'), false},
		{std::string{"Fictional\0Tail", 14U}, false},
	} ; // 原fieldを補完しない有限正負集合です
	// 全caseを原INFへ独立に保存し、旧backslash必須の拒否を正例で回帰します
	for( std::size_t index = 0U; index < cases.size(); ++index) {
		const auto &[id, accepted] = cases[index] ;					// 元文字列と独立期待です
		std::string			   body{VALID_INF} ;					// 架空Netの既存copy/source条件を維持します
		const std::string_view original{"PCI\\VEN_1234&DEV_5678"} ;	// 置換する第2 fieldだけです
		body.replace( body.find( original), original.size(), "\"" + id + "\"") ;
		OfficialDownloadWorkspace workspace ;	// 元byteの独立ownerです
		DRIVERCRATE_EXPECT( context,
						   workspace.initialize( L"opaque-models-test", 3530U + index) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "not-signed")) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.sys", "driver")) ;
		const std::array   entries{OfficialZipEntry{L"sample.inf", body.size()},
								   OfficialZipEntry{L"sample.cat", 10U},
								   OfficialZipEntry{L"sample.sys", 6U}} ;	// 全元fileです
		OfficialInfPackage package ;										// 原順の一意ID列です
		const auto error = inspectOfficialInfPackage( workspace, entries, L"sample.inf", POLICY,
													 package) ;	// 元native結果です
		DRIVERCRATE_EXPECT( context, (error == 0) == accepted) ;
		// 正例のcase/kind/順序を公開metadataの同readerでも確認します
		if( accepted && error == 0) {
			const std::wstring expected{id.begin(), id.end()} ;	// ASCIIの元code unitだけです
			OfficialInfPublishedIdentity identity ;				// 導入権限を持たない型です
			DRIVERCRATE_EXPECT( context, package.hardwareIds == std::vector<std::wstring>(
																   {expected, L"PCI\\VEN_1234"})) ;
			DRIVERCRATE_EXPECT( context,
							   readOfficialInfPublishedIdentity( workspace, package, identity) == 0) ;
			DRIVERCRATE_EXPECT( context, identity.models.size() == 1U) ;
			// 元Modelsが読めた場合だけ元field種別と順序を比較します
			if( identity.models.size() == 1U) {
				DRIVERCRATE_EXPECT( context, identity.models.front().hardwareIds ==
												std::vector<std::wstring>{expected}) ;
				DRIVERCRATE_EXPECT( context, identity.models.front().compatibleIds ==
												std::vector<std::wstring>{L"PCI\\VEN_1234"}) ;
			}
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 大小文字を無視する重複検査と型別の元順・表記を確かめます
 * @param[in,out] context 元順、型と独立した一意ID上限の検査結果を集計します
 */
//------------------------------------------------------------------------------
void testModelIdDeduplication( TestContext &context)
{
	// 複数のID欄を含む、人工の元Models行と差し替える位置
	constexpr std::string_view original{
		"%DeviceName%=Install,PCI\\VEN_1234&DEV_5678,PCI\\VEN_1234\r\n"} ;
	// 大小文字の異なる重複、種別と元の行順を確認する対照のModels行
	constexpr std::string_view models{"Example=Install,TestBus\\Zulu,TestBus\\Shared\r\n"
									  "Other=Install,testbus\\zulu,TESTBUS\\SHARED\r\n"
									  "Third=Install,TestBus\\Alpha,testbus\\ZUlu\r\n"
									  "Fourth=Install,testbus\\shared,testbus\\alpha\r\n"} ;
	std::string				   body{VALID_INF} ;	// 旧正常構造のModels行だけを置き換えます
	body.replace( body.find( original), original.size(), models) ;
	OfficialDownloadWorkspace workspace ;	// 同じ元byteで上限内と上限超過を検査します
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"model-id-deduplication", 3560U) == 0) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "not-signed")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.sys", "driver")) ;
	// 同じ試験INFに対応するCATとSYSを含む展開メンバー表
	const std::array entries{OfficialZipEntry{L"sample.inf", body.size()},
							 OfficialZipEntry{L"sample.cat", 10U},
							 OfficialZipEntry{L"sample.sys", 6U}} ;
	auto			 policy	  = POLICY ;	// 一意な値3件までを許す検査条件です
	policy.maximumHardwareIds = 3U ;
	OfficialInfPackage package ;	// 大小文字違いをまとめた元順ID列です
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy,
														  package) == 0) ;
	DRIVERCRATE_EXPECT( context, package.hardwareIds ==
									std::vector<std::wstring>(
										{L"TestBus\\Zulu", L"TestBus\\Shared", L"TestBus\\Alpha"})) ;
	OfficialInfPublishedIdentity identity ;	// 型付きの原順と各型の最初の表記を確認します
	DRIVERCRATE_EXPECT( context,
					   readOfficialInfPublishedIdentity( workspace, package, identity) == 0) ;
	DRIVERCRATE_EXPECT( context, identity.models.size() == 1U) ;
	// 期待した唯一のModels節が得られた場合だけ、元の順序と表記を参照します
	if( identity.models.size() == 1U) {
		DRIVERCRATE_EXPECT( context,
						   identity.models.front().hardwareIds ==
							   std::vector<std::wstring>(
								   {L"TestBus\\Zulu", L"TestBus\\Alpha", L"testbus\\shared"})) ;
		DRIVERCRATE_EXPECT( context,
						   identity.models.front().compatibleIds ==
							   std::vector<std::wstring>(
								   {L"TestBus\\Shared", L"testbus\\ZUlu", L"testbus\\alpha"})) ;
	}

	// 元の一意上限エラーを確認します
	policy.maximumHardwareIds = 2U ;
	DRIVERCRATE_EXPECT(
		context, inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy, package) ==
					 HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW)) ;
	DRIVERCRATE_EXPECT( context, package.hardwareIds.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元行の証拠と、公式Hardware欄の位置、容量、拒否時の出力を確認します
 * @param[in,out] context 元INF読取りの各対照を集計します
 */
//------------------------------------------------------------------------------
void testScopedModelsEvidence( TestContext &context)
{
	// 現Windows側の実選択節と元行を再現する人工INFの先頭
	constexpr std::string_view header{"[Version]\r\nSignature=\"$Windows NT$\"\r\n"
									  "[Manufacturer]\r\nFictional=Rows,NTamd64.10.0\r\n"
									  "[Rows.NTamd64.10.0]\r\n"} ;
	// 最初はCompatible IDだけ、次はHardware ID欄に一致する対照行
	constexpr std::string_view firstRows{"First=Install,TestBus\\Other,TESTBUS\\Target\r\n"
										 "Second=Install2,TestBus\\Target\r\n"} ;
	// 行数の境界を確認するため繰り返す非対象の元行
	constexpr std::string_view tail{"Tail=Install,TestBus\\Tail\r\n"} ;
	const std::wstring		   target{L"testbus\\target"} ;	// 公式の大小文字を変更した完全値です
	// 同じ配布元のHardware欄に載る唯一の公式対象
	const std::array		   scope{target} ;
	// 架空INFの装飾済み節を選ぶための明示クライアント観測点
	const OfficialInfModelsPlatform platform{.buildNumber = 19045U} ;
	OfficialDownloadWorkspace		workspace ;	// 各対照は別名の元INFを使います
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"scoped-model-evidence", 3561U) == 0) ;

	// この試験内だけで元workspace、明示OS、観測出力を同期使用します
	const auto check = [&]( const std::wstring_view name, const std::string_view rows,
						   const std::span<const std::wstring> ids, const NativeError expected,
						   const std::function<bool()> &cancellation = {},
						   bool							alteredHash	 = false) {
		std::string body{header} ;	// 各原対照の完全なUTF-8 INFです
		body += rows ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, name, body)) ;
		std::wstring hash ;	// 所有ファイルの元ハッシュを独立に求めます
		DRIVERCRATE_EXPECT( context, computeFileSha256( workspace.path( name), hash) == 0) ;
		// 元INFのSHA-256だけを変え、内容証拠との不一致を試します
		if( alteredHash && !hash.empty()) {
			hash.front() = hash.front() == L'0' ? L'1' : L'0' ;
		}

		OfficialInfScopedModelsEvidence evidence ;	// 失敗時に前回値を返さないことも確認します
		evidence.infSha256 = L"old" ;
		// 同じ作業領域の元ファイルから公式Modelsを読んだ診断値
		const auto error = readOfficialInfScopedModels( workspace, name, hash, &platform, ids,
													   evidence, cancellation) ;
		DRIVERCRATE_EXPECT( context, error == expected) ;
		// 拒否した入力から元ハッシュや部分節を発行していないことを確認します
		if( expected != 0) {
			DRIVERCRATE_EXPECT( context, evidence.infSha256.empty() && evidence.sections.empty()) ;
		}

		return evidence ;
	} ;

	// 二つの対象行と一つの非対象行を含む、正常入力の元証拠
	const auto good = check( L"good.inf", std::string{firstRows} + std::string{tail}, scope, 0) ;
	DRIVERCRATE_EXPECT( context, good.infSha256.size() == 64U && good.sections.size() == 1U) ;
	// 一つの実選択節が得られた場合にだけ行要約と一致位置を確認します
	if( good.sections.size() == 1U) {
		const auto &section = good.sections.front() ;	// 元3行の独立期待値です
		DRIVERCRATE_EXPECT(
			context, section.modelSection == L"Rows.NTamd64.10.0" && section.modelRows == 3U &&
						 section.idFields == 4U &&
						 section.orderedRowsSha256 ==
							 L"01c3466f0fda9aad36856fa67891973046d7f7e4d2b5cd36e3cc522a0fa713ab") ;
		DRIVERCRATE_EXPECT( context, section.matches.size() == 1U &&
										section.matches.front().modelRow == 2U &&
										section.matches.front().hardwareId == L"TestBus\\Target" &&
										section.matches.front().installBase == L"Install2") ;
	}

	check( L"compatible.inf", "First=Install,TestBus\\Other,TESTBUS\\Target\r\n", scope,
		  HRESULT_FROM_WIN32( ERROR_NOT_FOUND)) ;
	check( L"duplicate.inf", std::string{firstRows} + "Third=Install,testbus\\target\r\n", scope,
		  HRESULT_FROM_WIN32( ERROR_DUP_NAME)) ;
	check( L"late-inf.inf", std::string{firstRows} + "Tail=Install\r\n", scope,
		  HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
	check( L"hash.inf", firstRows, scope, TRUST_E_BAD_DIGEST, {}, true) ;
	check( L"duplicate-scope.inf", firstRows, std::array{target, std::wstring{L"TESTBUS\\TARGET"}},
		  E_INVALIDARG) ;
	unsigned calls{} ;	// 元行を読み始めた後の取消しです
	check( L"cancel.inf", firstRows, scope, HRESULT_FROM_WIN32( ERROR_CANCELLED),
		  [&calls] { return ++calls >= 4U ; }) ;

	std::string manyRows ;	// 最終行にだけ公式Hardware IDがあります
	// 同じ非対象行を規定行数まで追加し、等号の上限を試します
	for( std::size_t index = 1U; index < 16'384U; ++index) {
		manyRows += tail ;
	}

	manyRows += "Last=Install2,TestBus\\Target\r\n" ;
	// 共通の行数上限ちょうどまで非対象行を含む入力の検証結果
	const auto atLimit = check( L"row-limit.inf", manyRows, scope, 0) ;
	DRIVERCRATE_EXPECT( context, atLimit.sections.size() == 1U &&
									atLimit.sections.front().matches.size() == 1U &&
									atLimit.sections.front().matches.front().modelRow == 16'384U) ;
	check( L"row-over.inf", manyRows + std::string{tail}, scope,
		  HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW)) ;

	std::string extraIds ;	// 同じIDでも元フィールドとして上限に加えます
	// 一行で消費するCompatible IDの件数を増やす対照を構築します
	for( unsigned index = 0U; index < 15U; ++index) {
		extraIds += ",TestBus\\Compat" ;
	}

	std::string wideRows ;	// 4,096行に各16 IDです
	// 非対象の幅広いModels行を追加してIDの全件上限まで増やします
	for( unsigned index = 1U; index < 4'096U; ++index) {
		wideRows += "Wide=Install,TestBus\\Other" + extraIds + "\r\n" ;
	}

	wideRows += "Last=Install2,TestBus\\Target" + extraIds + "\r\n" ;
	// 共通のIDフィールド上限と同じ件数で得た元証拠
	const auto atIdLimit = check( L"id-limit.inf", wideRows, scope, 0) ;
	DRIVERCRATE_EXPECT( context, atIdLimit.sections.size() == 1U &&
									atIdLimit.sections.front().idFields == 65'536U) ;
	check( L"id-over.inf", wideRows + std::string{tail}, scope,
		  HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元Modelsを検証した公式対象の導入節、節兼用、欠損、取消しを確認する
 * @param[in,out] context 架空INFの非実行棚卸しと各拒否を集計する
 */
//------------------------------------------------------------------------------
void testScopedModelsInventory( TestContext &context)
{
	// 元INFのModels観測を固定する明示OS。試験中の端末ビルドには依存しない
	const OfficialInfModelsPlatform platform{.buildNumber = 19045U} ;
	OfficialDownloadWorkspace		workspace ;	// 同じ元ファイルを証拠と棚卸しへ結ぶ
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"scoped-model-inventory", 3562U) == 0) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
	auto policy	   = POLICY ;	// 同じ有限構造条件で対象だけ変える
	policy.purpose = OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;
	// 正常な元選択の基本導入節へ結び付ける架空Hardware ID
	const std::wstring			firstId{L"PCI\\VEN_1234&DEV_5678"} ;
	// 追加の元選択にだけ対応する二番目の架空Hardware ID
	const std::wstring			secondId{L"TESTBUS\\SECOND"} ;
	// 条件確認の時点ですでに取消し済みとする同期コールバック
	const std::function<bool()> cancel = [] { return true ; } ;
	const auto check = [&]( std::wstring_view name, std::string_view directive, bool secondRoot,
						   NativeError expected, std::optional<std::ptrdiff_t> unknown = {}) {
		// ケースごとに差分を加える前の正常な元INF
		std::string body{VALID_INF} ;
		std::string extraRows ;	// 範囲外の基本節は元Modelsの全行証拠にだけ含める
		// 目的外の節を十分に増やし、元Modelsの範囲が解析予算と区別されることを確認します
		for( std::size_t row = 0U; row < 4096U; ++row) {
			extraRows += "Other=Outside,TESTBUS\\OTHER\r\n" ;
		}

		// 二つ目の対象を使うケースでは、その元行も公式範囲へ含めます
		if( secondRoot) {
			extraRows += "Second=SecondInstall,TESTBUS\\SECOND\r\n" ;
			body += "[SecondInstall.NT]\r\nAddReg=DriverCopy\r\n" ;
		}

		body.insert( body.find( "\r\n[SourceDisksNames.amd64]"), extraRows) ;
		body.replace( body.find( "CopyFiles=DriverCopy"),
					 std::string_view{"CopyFiles=DriverCopy"}.size(), directive) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, name, body)) ;
		// 試験INFの内容をModelsの証拠へ固定する元ハッシュ
		std::wstring hash ;
		DRIVERCRATE_EXPECT( context, computeFileSha256( workspace.path( name), hash) == 0) ;
		// 同じ元INFから完全一致を探す二つの架空の公式対象
		const std::array				ids{firstId, secondId} ;
		// 元INF、明示OSと元行の一致位置を保持する検査結果
		OfficialInfScopedModelsEvidence evidence ;
		DRIVERCRATE_EXPECT( context, readOfficialInfScopedModels(
										workspace, name, hash, &platform,
										std::span( ids).first( secondRoot ? 2U : 1U), evidence) == 0) ;
		DRIVERCRATE_EXPECT( context, evidence.platform == platform) ;
		// 検査すべき元INFと同じ閉包のCATを結ぶメンバー表
		const std::array		entries{OfficialZipEntry{std::wstring{name}, body.size(), hash},
									OfficialZipEntry{L"sample.cat", 8U}} ;
		// 公式範囲と実際の導入作用を双方確認する格納先
		MaintenanceInfStructure structure ;
		// 元Modelsの証拠を使って同じINFの導入構造を検査した診断値
		const auto				result =
			inspectMaintenanceInfStructure( workspace, entries, name, policy, structure, &evidence) ;
		DRIVERCRATE_EXPECT( context, result == expected) ;
		// 成功を期待するケースでは元選択と別の節が混ざらないことを確認します
		if( expected == 0) {
			DRIVERCRATE_EXPECT(
				context,
				structure.officialHardwareScope &&
					structure.hardwareIds == std::vector<std::wstring>{firstId} &&
					structure.installs.size() == 1U &&
					structure.installs.front().inventory.selectedInstallSection == L"Install.NT" &&
					structure.referenceCoverage == MaintenanceInfReferenceCoverage::NOT_CHECKED) ;
			// 未知の作用を観測させる対照では、内容が得られた場合にだけ実観測を照合します
			if( unknown && !structure.installs.empty()) {
				// 指定作用の関連属性を比較する一番目の選択構造
				const auto &observed = structure.installs.front() ;
				DRIVERCRATE_EXPECT(
					context,
					std::ranges::count_if( observed.inventory.effects, []( const auto &effect) {
						return effect.kind == OfficialInfInstallEffectKind::UNKNOWN_DIRECTIVE ;
					}) == *unknown) ;
			}

			DRIVERCRATE_EXPECT( context, inspectMaintenanceInfStructure(
											workspace, entries, name, policy, structure, &evidence,
											&cancel) == HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
			DRIVERCRATE_EXPECT( context, inspectMaintenanceInfStructure( workspace, entries, name,
																	   policy, structure) != 0) ;
		}

		DRIVERCRATE_EXPECT( context, structure.installs.empty() && !structure.officialHardwareScope) ;
	} ;

	check( L"scope.inf", "CopyFiles=DriverCopy", false, 0) ;
	check( L"missing.inf", "CopyFiles=Missing", false, HRESULT_FROM_WIN32( ERROR_SECTION_NOT_FOUND)) ;
	check( L"model-role.inf", "CopyFiles=Models.NTamd64", false,
		  HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
	check( L"shared-role.inf", "CopyFiles=DriverCopy", true, HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
	// 物理ネットワークの候補として許可する作用を記述した正常な元節
	const std::string physical{"CopyFiles=DriverCopy\r\nCharacteristics=0x84\r\nBusType=5\r\n"
							   "*IfType=6\r\n*MediaType=0\r\n*PhysicalMediaType=14"} ;
	check( L"physical-ethernet.inf", physical, false, 0, 0) ;
	check( L"duplicate-bus.inf", physical + "\r\nBusType=5", false, 0, 6) ;
	// 同じ媒体で属性だけ異なるように変更する対照の元節
	auto mismatched = physical ;
	mismatched.replace( mismatched.find( "*PhysicalMediaType=14"),
					   std::string_view{"*PhysicalMediaType=14"}.size(), "*PhysicalMediaType=9") ;
	check( L"mismatched-medium.inf", mismatched, false, 0, 5) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元MTDとSCSIのservice/HW作用を正負別に検査します
 * @param[in,out] context 原行を使った作用検査の結果を集計します
 */
//------------------------------------------------------------------------------
void testMtdStorageEffects( TestContext &context)
{
	// 原service/属性だけを与え、結果DTOやOS実体を偽の成功で置換しません
	for( unsigned scenario = 0U; scenario < 12U; ++scenario) {
		// 人工MTD serviceの元flags・開始方式・directiveです
		SelectedStorageServiceFacts service ;
		service.className		 = scenario == 11U ? L"SCSIAdapter" : L"MTD" ;
		service.classGuid		 = scenario == 11U ? L"{4d36e97b-e325-11ce-bfc1-08002be10318}"
												   : L"{4d36e970-e325-11ce-bfc1-08002be10318}" ;
		service.servicesSection	 = L"Install.Services" ;
		service.addServiceFields = {L"FixtureStorage", L"2", L"StorageService"} ;
		service.name			 = L"FixtureStorage" ;
		service.installSection	 = L"StorageService" ;
		service.flags			 = 2U ;
		service.type			 = 1U ;
		service.start			 = 3U ;
		service.errorControl	 = 1U ;
		service.binary			 = L"%12%\\fixture.sys" ;
		service.group			 = scenario == 11U ? L"SCSI Miniport" : L"SD / MMC" ;
		// MTDで許可しない開始方式を注入します
		if( scenario == 1U) {
			service.start = 1U ;
		}

		// MTDで許可しないSCSI groupを注入します
		if( scenario == 2U) {
			service.group = L"SCSI Miniport" ;
		}

		// kernel以外のservice typeを注入します
		if( scenario == 3U) {
			service.type = 16U ;
		}

		// 元AddService flagsの不一致を注入します
		if( scenario == 4U) {
			service.flags = 0U ;
		}

		// class名とGUIDの偽装を注入します
		if( scenario == 5U) {
			service.classGuid = L"{4d36e97b-e325-11ce-bfc1-08002be10318}" ;
		}

		service.directives = {{0U, L"ServiceType", {L"1"}},
							  {1U, L"StartType", {L"3"}},
							  {2U, L"ErrorControl", {L"1"}},
							  {3U, L"ServiceBinary", {L"%12%\\fixture.sys"}},
							  {4U, L"LoadOrderGroup", {*service.group}}} ;
		// 人工registry行の読取回数です
		std::size_t		   registryRows{} ;
		// 人工INF作用readerの完全API表です
		SystemInfEffectApi api ;
		api.registryRows = &registryRows ;
		api.read		 = [&]( const SystemInfSection &section, std::vector<SystemInfRow> &rows) {
			// 選択Services節の元AddService行を返します
			if( section.name == L"Install.Services") {
				rows = {{0U, L"AddService", service.addServiceFields}} ;
			}
			// service節の全directiveを原順に返します
			else if( section.name == L"StorageService") {
				// 元service directiveの各fieldを保持します
				for( const auto &directive : service.directives) {
					rows.push_back( {directive.ordinal, directive.key, directive.fields}) ;
				}
			}
			// 選択HW節のAddRegを返します
			else if( section.name == L"Install.HW") {
				rows = {{0U, L"AddReg", {L"HardwareValues"}}} ;
			}
			// MTDの二つの型付きhardware属性を返します
			else if( section.name == L"HardwareValues") {
				rows = {{0U, L"", {L"HKR", L"", L"DeviceType", L"0x10001", L"7"}},
						{1U, L"", {L"HKR", L"", L"DeviceCharacteristics", L"0x10001", L"0x101"}}} ;
				// DeviceTypeの不正値を注入します
				if( scenario == 6U) {
					rows[0].values[4] = L"8" ;
				}

				// Characteristicsの不正なregistry型を注入します
				if( scenario == 7U) {
					rows[1].values[3] = L"0" ;
				}

				// hardware属性の不正なsubkeyを注入します
				if( scenario == 8U) {
					rows[0].values[1] = L"Parameters" ;
				}

				// 同hardware属性の重複行を注入します
				if( scenario == 9U) {
					rows.push_back( {2U, L"", rows[0].values}) ;
				}

				// Characteristicsの不正値を注入します
				if( scenario == 10U) {
					rows[1].values[4] = L"0x100" ;
				}
			} else {
				return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND)) ;
			}

			return NativeError{} ;
		} ;
		// 人工ServicesとHWの原選択節です
		const std::array seeds{
			SystemInfSection{1U,
							 L"Install.Services",
							 SystemInfContext::SERVICES,
							 SystemInfContext::SERVICES,
							 {}},
			SystemInfSection{
				1U, L"Install.HW", SystemInfContext::HARDWARE, SystemInfContext::HARDWARE, {}}} ;
		// native作用readerの結果です
		StorageInfEffects result ;
		// 作用readerが返す診断stageです
		std::uint32_t	  stage{} ;
		// 作用readerの原HRESULTです
		const auto		  error = inspectStorageInfEffects(
			   seeds, api, service,
			   []( std::wstring_view, SystemServiceEvidence &) {
				   return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_SERVICE_DOES_NOT_EXIST)) ;
			   },
			   26100U, result, stage) ;
		DRIVERCRATE_EXPECT( context, (error == 0U) == (scenario == 0U || scenario == 11U)) ;
		// 正常例の型付き二属性と元作用を確認します
		if( scenario == 0U && error == 0U) {
			DRIVERCRATE_EXPECT( context, result.mtdDeviceType == 7U &&
											result.mtdDeviceCharacteristics == 0x101U) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 関連サービスの既存値保持付き文字列を元の命令と所有範囲で確認する
 * @param[in,out] context 読み取り専用の作用検査を集計する試験コンテキスト
 */
//------------------------------------------------------------------------------
void testStorageServicePreserveString( TestContext &context)
{
	// 各ケースは架空の関連サービスを使用し、レジストリとSCMへ書き込まない
	for( unsigned scenario = 0U; scenario < 9U; ++scenario) {
		SelectedStorageServiceFacts service ;	// 元の選択済みサービスを模した事実
		service.className		 = scenario == 7U ? L"MTD" : L"SCSIAdapter" ;
		service.classGuid		 = scenario == 7U ? L"{4d36e970-e325-11ce-bfc1-08002be10318}"
												  : L"{4d36e97b-e325-11ce-bfc1-08002be10318}" ;
		service.servicesSection	 = L"Install.Services" ;
		service.addServiceFields = {L"FixtureStorage", L"2", L"StorageService"} ;
		service.name			 = L"FixtureStorage" ;
		service.installSection	 = L"StorageService" ;
		service.flags			 = 2U ;
		service.type			 = 1U ;
		service.start			 = scenario == 7U ? 3U : 0U ;
		service.errorControl	 = 1U ;
		service.group			 = scenario == 7U ? L"SD / MMC" : L"SCSI Miniport" ;

		std::vector<std::wstring> fields{
			L"HKLM", L"SYSTEM\\CurrentControlSet\\Services\\FixtureStorage\\Parameters\\Device",
			L"FixtureParameter", L"0x00000002",
			L"FixtureValue=0;"} ;	// 元のAddReg行を模した全フィールド
		// 正常例に対し、所有範囲、型、値の境界を一つずつ変える
		switch( scenario) {
			// 別サービスのParametersを指定
			case 1U:
				fields[1] = L"SYSTEM\\CurrentControlSet\\Services\\OtherStorage\\Parameters" ;
				break ;

			// 関連サービスの本体を指定
			case 2U:
				fields[1] = L"SYSTEM\\CurrentControlSet\\Services\\FixtureStorage" ;
				break ;

			// 名前のない値を指定
			case 3U:
				fields[2].clear() ;
				break ;

			// DWORDと既存値保持を組み合わせる
			case 4U:
				fields[3] = L"0x00010003" ;
				break ;

			// 実行コマンドを値に指定
			case 5U:
				fields[4] = L"powershell -NoProfile" ;
				break ;

			// 機器相対のルートへ変更
			case 6U:
				fields[0] = L"HKR" ;
				fields[1] = L"Parameters\\Device" ;
				break ;

			// クラスと節の負例では元の行を保持
			default:
				break ;
		}

		const auto scope =
			// 元の参照文脈
			scenario == 8U ? SystemInfContext::HARDWARE : SystemInfContext::DEVICE ;
		std::size_t		   registryRows{} ;	// 元レジストリ行の読取回数
		SystemInfEffectApi api ;			// 人工INFを同期で読む試験API
		api.registryRows = &registryRows ;
		api.read		 = [&]( const SystemInfSection &section, std::vector<SystemInfRow> &rows) {
			// 元の節名ごとに選択された参照と書込みを読み取る
			if( section.name == L"Install.Services") {
				rows = {{0U, L"AddService", service.addServiceFields}} ;
			}
			// 選択された機器節が参照する登録先
			else if( section.name == L"Install") {
				rows = {{0U, L"AddReg", {L"SelectedValues"}}} ;
			}
			// 指定フラグと値を含む全フィールド
			else if( section.name == L"SelectedValues") {
				rows = {{0U, L"", fields}} ;
			}

			return NativeError{} ;
		} ;
		const std::array  seeds{SystemInfSection{1U, L"Install", scope, scope, {}},
								SystemInfSection{1U,
												 L"Install.Services",
												 SystemInfContext::SERVICES,
												 SystemInfContext::SERVICES,
												 {}}} ;	// 原の機器節と関連サービス宣言
		StorageInfEffects result ;						// 検査が成立した場合だけ返された作用
		std::uint32_t	  stage{} ;						// 失敗箇所を識別する固定診断
		const auto		  error = inspectStorageInfEffects(
			   seeds, api, service,
			   []( std::wstring_view, SystemServiceEvidence &) {
				   return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_SERVICE_DOES_NOT_EXIST)) ;
			   },
			   26100U, result, stage) ;			// 元の作用検査とサービス不存在の結果
		const bool accepted = scenario == 0U ;	// 正式SCSIの対象と値だけを許可
		DRIVERCRATE_EXPECT( context, (error == 0U) == accepted) ;
		DRIVERCRATE_EXPECT( context, accepted || (stage == 14004U && result.effects.empty())) ;
		DRIVERCRATE_EXPECT(
			context, !accepted || std::ranges::any_of( result.effects, [&]( const auto &effect) {
				return effect.action == StorageInfAction::REGISTRY_VALUE &&
					   effect.original.row.values == fields ;
			})) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief SCSIの順位が元の選択基本節に一度だけ現れる場合を検査する
 * @param[in,out] context 作用検査の結果を集計する試験コンテキスト
 */
//------------------------------------------------------------------------------
void testSelectedScsiFeatureScore( TestContext &context)
{
	// FeatureScoreの記載を許す、現在の選択基本節
	const SystemInfSection base{
		1U, L"Install", SystemInfContext::DEVICE, SystemInfContext::DEVICE, {}} ;
	// 起動サービスの元設定を持つ、同じ選択の付随節
	const SystemInfSection services{
		1U, L"Install.Services", SystemInfContext::SERVICES, SystemInfContext::SERVICES, {}} ;
	// FeatureScoreを別用途で宣言する対照のハードウェア節
	const SystemInfSection hardware{
		1U, L"Install.HW", SystemInfContext::HARDWARE, SystemInfContext::HARDWARE, {}} ;
	// 同じFeatureScoreが元の選択基本節以外に現れる負例の一覧
	const std::array invalidLocations{
		hardware,
		SystemInfSection{
			1U, L"OtherInstall", SystemInfContext::DEVICE, SystemInfContext::DEVICE, {}},
		SystemInfSection{2U, L"Install", SystemInfContext::DEVICE, SystemInfContext::DEVICE, {}}} ;
	// 元の基本節だけに一度現れる場合に確認する順位指定行
	const SystemInfRow			score{0U, L"FeatureScore", {L"0x80"}} ;
	// 実照合へ渡す、架空の選択済みストレージサービスの情報
	SelectedStorageServiceFacts service ;
	service.className			   = L"SCSIAdapter" ;
	service.classGuid			   = L"{4d36e97b-e325-11ce-bfc1-08002be10318}" ;
	service.selectedInstallSection = base.name ;
	service.servicesSection		   = services.name ;
	service.addServiceFields	   = {L"FixtureStorage", L"2", L"StorageService"} ;
	service.name				   = L"FixtureStorage" ;
	service.installSection		   = L"StorageService" ;
	service.flags				   = 2U ;
	service.type				   = 1U ;
	service.start				   = 0U ;
	service.errorControl		   = 1U ;
	service.group				   = L"SCSI Miniport" ;

	// 借用中の試験用サービスと与えた節に対して順位の拒否・受理を照合する同期処理
	const auto check = [&]( const SystemInfSection &location, const std::vector<SystemInfRow> &rows,
						   const bool expected) {
		// 基本とサービスの必須二節。別位置の対照を検査する場合は該当節も加えます
		std::vector<SystemInfSection> seeds{base, services} ;
		// 正常な基本節に加え、意図した別の節を解析対象へ明示します
		if( location != base) {
			seeds.push_back( location) ;
		}

		// 試験用のレジストリ行の読取り量。実機のレジストリは使用しない
		std::size_t		   registryRows{} ;
		// 与えた元設定と期待動作だけを返す試験用の作用照合API
		SystemInfEffectApi api ;
		api.registryRows = &registryRows ;
		api.read = [&]( const SystemInfSection &section, std::vector<SystemInfRow> &document) {
			// サービス節を読む際は同じ選択の元AddService設定を返します
			if( section == services) {
				document = {{0U, L"AddService", service.addServiceFields}} ;
			}
			// 対照の節を読む際は、試験が指定した順位行とその位置を返します
			else if( section == location) {
				document = rows ;
			}

			return NativeError{} ;
		} ;
		// 同じSCSI選択の実検査から得る導入作用の格納先
		StorageInfEffects result ;
		// 検査の進行または拒否位置を区別する試験診断
		std::uint32_t	  stage{} ;
		// 架空の元行と未登録サービスを使ったストレージ作用の検査結果
		const auto		  error = inspectStorageInfEffects(
			   seeds, api, service,
			   []( std::wstring_view, SystemServiceEvidence &) {
				   return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_SERVICE_DOES_NOT_EXIST)) ;
			   },
			   26100U, result, stage) ;
		DRIVERCRATE_EXPECT( context, (error == 0U) == expected) ;
		DRIVERCRATE_EXPECT( context, expected || (stage == 14003U && result.effects.empty())) ;
		// 正常例が保持すべき、同じ基本節と元FeatureScore行の組
		const SystemInfEffect expectedScore{base, score} ;
		DRIVERCRATE_EXPECT( context,
						   !expected ||
							   (result.featureScore == 0x80U && !result.effects.empty() &&
								result.effects.front().action == StorageInfAction::FEATURE_SCORE &&
								result.effects.front().original == expectedScore)) ;
	} ;

	check( base, {score}, true) ;
	// 所有しない位置の対照をすべて走査し、同じ順位値でも適用できないことを確認します
	for( const auto &location : invalidLocations) {
		check( location, {score}, false) ;
	}

	check( base, {{0U, score.key, {L"0x00"}}}, false) ;
	check( base, {{0U, score.key, {L"0x80", L"0x80"}}}, false) ;
	check( base, {score, {1U, score.key, score.values}}, false) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 自動起動補助の元コマンドを切り詰めたり別位置へ展開したりしないことを検査する
 * @param[in,out] context 元構文を変更した対照の検査結果
 * @note 無効な位置だけを渡すため、レジストリや実ファイルを読み書きしない
 */
//------------------------------------------------------------------------------
void testDriverStoreAuxiliaryCommandSyntax( TestContext &context)
{
	constexpr std::wstring_view file{L"fixture.exe"} ;	// 署名済み選択を模した同一ファイル名
	// Driver Store内部の同じ元ファイルを示す人工の環境変数付きパス
	const std::wstring			folder{
		 L"%SystemRoot%\\System32\\DriverStore\\FileRepository\\fixture.inf_amd64_123\\"} ;
	const auto		 path = folder + std::wstring{file} ;	// 架空の配置先。対照ではそのまま使用しない
	const std::array commands{
		L"\"" + path + L"\" /option",
		path + L" /option.exe",
		path + L":stream",
		std::wstring{L"%SystemRoot%\\System32\\fixture.exe"},
		folder + L"..\\fixture.exe",
		folder + L"sub\\fixture.exe",
		folder + L"other.exe",
		std::wstring{
			L"%windir%\\System32\\DriverStore\\FileRepository\\fixture.inf_amd64_123\\fixture.exe"},
		path + L" ",
		path + L'\0' + L".exe",
		std::wstring{
			L"\\SystemRoot\\System32\\DriverStore\\FileRepository\\fixture.inf_amd64_123\\fixture.exe"},
	} ; // 余分なコマンド、別パス、曖昧な末尾とNULを対照する
	// それぞれの元候補を拒否し、先行観測の値も残さない
	for( const auto &command : commands) {
		ProtectedExecutableSnapshot result ;	// すでに他の構成を読んだと仮定した出力
		result.existing.emplace().sha256 = L"fixture" ;
		std::wstring resolved{L"previous.exe"} ;	// 失敗時に空になる配置先
		// 元実行コマンドから元パス以外を採用しないことを比較する結果
		const auto	 error = readDriverStoreExecutableSnapshot( command, file, resolved, result) ;
		DRIVERCRATE_EXPECT( context, error == HRESULT_FROM_WIN32( ERROR_INVALID_NAME) &&
										resolved.empty() && !result.existing &&
										result.repositorySecurity.empty()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 名前付きイベント用DLLには明示で一意なSystem32直下の宛先を要求する
 * @param[in,out] context 架空INFの元DestinationDirsを照合する集計先
 * @note SetupAPIで元INFだけを開き、端末へのコピーは行わない
 */
//------------------------------------------------------------------------------
void testStorageEventCopyDestination( TestContext &context)
{
	constexpr std::string_view body =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\n"
		"[DestinationDirs]\r\nDefaultDestDir=11\r\nExact=11\r\n"
		"Drivers=12\r\nStore=13\r\nSubdir=11,Child\r\nEmptySubdir=11,\r\n"
		"Duplicate=11\r\nDuplicate=11\r\n" ;	// 元節ごとに一つだけ異なる架空宛先
	OfficialDownloadWorkspace workspace ;		// 端末への反映を伴わない人工INFの保護領域
	// 署名情報やコピー先を照合するため、人工INFを所有作業領域に準備できたかを示します
	const bool				  ready = workspace.initialize( L"storage-event-copy", 4212U,
														   OfficialWorkspaceMode::CURRENT_USER_INSPECTION) == 0U &&
					   writeWorkspaceFile( workspace, L"event-copy.inf", body) ;
	DRIVERCRATE_EXPECT( context, ready) ;
	// 準備後だけ元の実HINFを同期借用する
	if( !ready) {
		return ;
	}

	const HINF inf = SetupOpenInfFileW( workspace.path( L"event-copy.inf").c_str(), nullptr,
									   INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
									   nullptr) ;	// 元INFのキャッシュを作らない
	DRIVERCRATE_EXPECT( context, inf != INVALID_HANDLE_VALUE) ;
	// 無効ハンドルから読み取り成功を作らない
	if( inf == INVALID_HANDLE_VALUE) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, hasExplicitStorageEventCopyDestination( inf, L"Exact")) ;
	// 欠損時の既定先、重複、別DIRID、空を含む追加欄を個別に拒否する
	for( const auto name : {L"", L"Absent", L"DefaultDestDir", L"Drivers", L"Store", L"Subdir",
						   L"EmptySubdir", L"Duplicate"}) {
		DRIVERCRATE_EXPECT( context, !hasExplicitStorageEventCopyDestination( inf, name)) ;
	}

	SetupCloseInfFile( inf) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 要求時の補助サービスと元イベント所有を照合し、未評価の自動起動を端末読取前に拒否する
 * @param[in,out] context 架空INFの全宣言と計画境界を確認する試験コンテキスト
 */
//------------------------------------------------------------------------------
void testStorageAuxiliaryServiceEffects( TestContext &context)
{
	// 許可の範囲、順序、失敗監査を元サービスの形式へ合わせた架空の保護記述子
	constexpr std::wstring_view protection{
		L"D:AR(A;;0xF01FF;;;BA)(A;;0xF01FF;;;SY)(A;;0x2018D;;;IU)S:(AU;FA;0xF01FF;;;WD)"} ;
	// 権限・イベント資源と、自動起動・配置・元イベント欄の影響を個別に検査する
	for( unsigned scenario = 0U; scenario < 8U; ++scenario) {
		SelectedStorageServiceFacts service ;	// 架空の関連ブートサービス
		service.className			   = L"SCSIAdapter" ;
		service.classGuid			   = L"{4d36e97b-e325-11ce-bfc1-08002be10318}" ;
		service.selectedInstallSection = L"Install" ;
		service.servicesSection		   = L"Install.Services" ;
		service.name				   = L"FixtureKernel" ;
		service.installSection		   = L"KernelInstall" ;
		service.addServiceFields	   = {service.name, L"2", service.installSection, L"Events"} ;
		service.flags				   = SPSVCINST_ASSOCSERVICE ;
		service.type				   = SERVICE_KERNEL_DRIVER ;
		service.start				   = SERVICE_BOOT_START ;
		service.errorControl		   = SERVICE_ERROR_NORMAL ;
		service.group				   = L"SCSI Miniport" ;
		service.binaryTarget		   = L"C:\\Windows\\System32\\drivers\\fixture.sys" ;
		service.directives			   = {{0U, L"ServiceType", {L"1"}}} ;

		auto &helper = service.auxiliary.emplace() ;	// 架空の同INFから読み取った補助サービス
		helper.addServiceOrdinal = 1U ;
		helper.name				 = L"FixtureHelper" ;
		helper.installSection	 = L"HelperInstall" ;
		helper.addServiceFields	 = {helper.name, L"0", helper.installSection, L"Events"} ;
		helper.type				 = SERVICE_WIN32_OWN_PROCESS ;
		helper.start = scenario == 4U || scenario == 7U ? SERVICE_AUTO_START : SERVICE_DEMAND_START ;
		helper.errorControl = SERVICE_ERROR_NORMAL ;
		helper.copy.dirid	= scenario == 5U || scenario == 7U ? 13 : 11 ;
		helper.security		= scenario == 1U ? L"D:(A;;GA;;;WD)" : std::wstring{protection} ;
		helper.directives	= {{0U, L"ServiceType", {L"16"}},
							   {1U, L"StartType", {L"3"}},
							   {2U, L"ErrorControl", {L"1"}},
							   {3U, L"ServiceBinary", {L"C:\\Windows\\System32\\fixture.exe"}},
							   {4U, L"Security", {helper.security}}} ;
		// 保持済みの行に含まれても、別アカウントを設定する作用を拒否する
		if( scenario == 2U) {
			helper.directives.push_back( {5U, L"StartName", {L"LocalService"}}) ;
		}

		// 名前付きSystemイベントを含む六欄も、元事実だけでは端末作用を認めません
		if( scenario == 6U || scenario == 7U) {
			helper.addServiceFields.push_back( L"System") ;
			helper.addServiceFields.push_back( L"Fixture Middleware") ;
		}

		std::size_t		   graphReads{} ;	// 元INF内の作用節を読み始めた回数
		std::size_t		   serviceReads{} ;	// 端末SCMに相当する試験backendを照会した回数
		std::size_t		   registryRows{} ;	// 元グラフの共同レジストリ行数
		SystemInfEffectApi api ;			// 同じ架空documentの読み取りだけを返すbackend
		api.registryRows = &registryRows ;
		// 固定した架空の二サービスと各ケースの値を呼出し中だけ借用する
		api.read = [&]( const SystemInfSection &section, std::vector<SystemInfRow> &rows) {
			++graphReads ;
			// 同じ選択の元二宣言を原順で返す
			if( section.name == service.servicesSection) {
				rows = {{0U, L"AddService", service.addServiceFields},
						{1U, L"AddService", helper.addServiceFields}} ;
			}
			// 二つのサービス設定はそれぞれの元節から区別する
			else if( section.context == SystemInfContext::SERVICE) {
				// 元のサービス所有者に対応する設定行の借用
				const auto &directives =
					section.owner == helper.name ? helper.directives : service.directives ;
				// 元位置と値を保った一節を返す
				for( const auto &directive : directives) {
					rows.push_back( {directive.ordinal, directive.key, directive.fields}) ;
				}
			}
			// 同じ節から別々の所有者に同じ資源を登録する
			else if( section.context == SystemInfContext::EVENT_LOG) {
				rows = {{0U, L"AddReg", {L"EventValues"}}} ;
			}
			// 補助役の一方だけを欠損する場合も、関連役の成功で成立にしない
			else if( section.name == L"EventValues" &&
					(scenario != 3U || section.owner != helper.name)) {
				rows = {
					{0U,
					 L"",
					 {L"HKR", L"", L"EventMessageFile", L"0x20000",
					  L"%SystemRoot%\\System32\\IoLogMsg.dll;%SystemRoot%\\System32\\drivers\\fixture.sys"}},
					{1U, L"", {L"HKR", L"", L"TypesSupported", L"0x10001", L"7"}}} ;
			}

			return NativeError{} ;
		} ;
		api.module = []( std::uint64_t document, std::wstring_view value) -> NativeError {
			return document == 1U && value == L"%SystemRoot%\\System32\\IoLogMsg.dll" ? 0U : E_FAIL ;
		} ; // 試験の正規Windows資源だけを照合する
		// 同一INFから二つのサービス設定へ到達する起点
		const std::array  seeds{SystemInfSection{1U,
												 service.servicesSection,
												 SystemInfContext::SERVICES,
												 SystemInfContext::SERVICES,
												 {}}} ;
		StorageInfEffects result ;	// 合格時の非権限作用計画
		std::uint32_t	  stage{} ;	// 試験の数値診断
		// 端末の実サービスを開かず、架空の関連サービスの不存在だけを返す
		const auto		  error = inspectStorageInfEffects(
			   seeds, api, service,
			   [&]( std::wstring_view name, SystemServiceEvidence &) -> NativeError {
				   ++serviceReads ;
				   return name == service.name ? HRESULT_FROM_WIN32( ERROR_SERVICE_DOES_NOT_EXIST)
												   : E_FAIL ;
			   },
			   26100U, result, stage) ;
		DRIVERCRATE_EXPECT( context, (error == 0U) == (scenario == 0U)) ;
		DRIVERCRATE_EXPECT( context, scenario == 0U
										? result.service.auxiliary == service.auxiliary &&
											  registryRows == 4U && result.services.size() == 1U
										: result.effects.empty()) ;
		// 保留になった自動起動等の元値から作用解析や現在サービスの照会へ進まないことを確認します
		if( scenario >= 4U) {
			DRIVERCRATE_EXPECT( context, error == HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) &&
											stage == 14001U && graphReads == 0U &&
											serviceReads == 0U) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 正式MTD対と内容用途だけを許し偽装や必須importを拒否します
 * @param[in,out] context 架空INFごとの実検査結果を集計します
 */
//------------------------------------------------------------------------------
void testCollectorMtdStructure( TestContext &context)
{
	// MTDと通常Netの比較class集合です
	const std::array classes{std::wstring_view{L"MTD"}, std::wstring_view{L"Net"}} ;
	// 各用途と原Class/GUIDの組を独立の実INFとして評価します
	for( unsigned scenario = 0U; scenario < 12U; ++scenario) {
		// scenarioごとに変える人工INF本文です
		std::string body{VALID_INF} ;
		body.replace( body.find( "Class=Net"), 9U, "Class=MTD") ;
		body.replace( body.find( "4d36e972"), 8U, "4d36e970") ;
		// scenarioごとの内容inspection purposeです
		auto policy			   = POLICY ;
		policy.acceptedClasses = classes ;
		policy.purpose		   = OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;
		// MTD private storage candidate目的を個別に確認します
		if( scenario == 1U) {
			policy.purpose = OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE ;
		}
		// 通常STANDARD目的の拒否を確認します
		else if( scenario == 2U) {
			policy.purpose = OfficialInfInspectionPurpose::STANDARD_DRIVER ;
		}
		// required collector目的の拒否を確認します
		else if( scenario == 3U) {
			policy.purpose = OfficialInfInspectionPurpose::REQUIRED_COLLECTOR_IMPORT ;
		}
		// required storage目的の拒否を確認します
		else if( scenario == 4U) {
			policy.purpose = OfficialInfInspectionPurpose::REQUIRED_STORAGE_IMPORT ;
		}
		// MTD class GUIDの不一致を注入します
		else if( scenario == 5U) {
			body.replace( body.find( "4d36e970"), 8U, "4d36e972") ;
		}
		// MTD GUIDを別class名で偽装します
		else if( scenario == 6U) {
			body.replace( body.find( "Class=MTD"), 9U, "Class=Net") ;
		}
		// ClassGUID欠損を注入します
		else if( scenario == 7U) {
			body.replace(
				body.find( "ClassGuid="),
				std::string_view{"ClassGuid={4d36e970-e325-11ce-bfc1-08002be10318}\r\n"}.size(),
				"") ;
		}
		// ClassGUID重複を注入します
		else if( scenario == 8U) {
			body += "[Version]\r\nClassGuid={4d36e970-e325-11ce-bfc1-08002be10318}\r\n" ;
		}
		// Class名重複を注入します
		else if( scenario == 9U) {
			body += "[Version]\r\nClass=MTD\r\n" ;
		}
		// 通常Net classとのGUID不一致を注入します
		else if( scenario == 10U) {
			body.replace( body.find( "Class=MTD"), 9U, "Class=Net") ;
			policy.purpose = OfficialInfInspectionPurpose::STANDARD_DRIVER ;
		}
		// 通常Net classの比較controlを固定します
		else if( scenario == 11U) {
			body.replace( body.find( "Class=MTD"), 9U, "Class=Net") ;
			body.replace( body.find( "4d36e970"), 8U, "4d36e972") ;
			body += "[Version]\r\nClassGuid={4d36e970-e325-11ce-bfc1-08002be10318}\r\n" ;
			policy.purpose = OfficialInfInspectionPurpose::STANDARD_DRIVER ;
		}

		// 人工INFとCATを置く所有workspaceです
		OfficialDownloadWorkspace workspace ;
		DRIVERCRATE_EXPECT( context,
						   workspace.initialize( L"mtd-structure-test", 3590U + scenario) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "not-signed")) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.sys", "driver")) ;
		// 人工archive memberと元sizeです
		const std::array   entries{OfficialZipEntry{L"sample.inf", body.size()},
								   OfficialZipEntry{L"sample.cat", 10U},
								   OfficialZipEntry{L"sample.sys", 6U}} ;
		// 内容検査が返す人工package結果です
		OfficialInfPackage package ;
		// 内容検査の元診断です
		const auto		   error =
			inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy, package) ;
		DRIVERCRATE_EXPECT( context, (error == 0) == (scenario < 2U)) ;
		// 許可目的での正式MTD classとGUIDを確認します
		if( scenario < 2U && error == 0) {
			DRIVERCRATE_EXPECT( context, package.className == L"MTD" &&
											package.inspectionPurpose == policy.purpose &&
											!package.requiredNullCompanion) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 正式SCSIAdapterの内容だけを受理しClass/GUID対と通常拒否を確認します
 * @param[in,out] context 架空storage packageだけの結果を集計します
 */
//------------------------------------------------------------------------------
void testCollectorStorageStructure( TestContext &context)
{
	const std::array classes{std::wstring_view{L"SCSIAdapter"},
							 std::wstring_view{L"Net"}} ;	// 通常Classの追加許可ではありません
	auto			 policy = POLICY ;						// 同参照/件数を維持する内容用途です
	policy.acceptedClasses	= classes ;
	policy.purpose			= OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;
	// 正式対と両向きの不一致・欠測・重複・元source欠損を独立に比較します
	for( unsigned scenario = 0U; scenario < 7U; ++scenario) {
		std::string body{VALID_INF} ;	// 元copy/sourceは常に同じです
		body.replace( body.find( "Class=Net"), 9U, "Class=SCSIAdapter") ;
		body.replace( body.find( "4d36e972"), 8U, "4d36e97b") ;
		// 変更条件を一つずつ固定し、正常対で欠測を補完しません
		switch( scenario) {
			case 0U:	// 正式storage内容の正例です
				break ;

			case 1U:	// storage名に別ClassGUIDを結びません
				body.replace( body.find( "4d36e97b"), 8U, "4d36e972") ;
				break ;

			case 2U:	// 別Class名にstorage GUIDを結びません
				body.replace( body.find( "Class=SCSIAdapter"), 17U, "Class=Net") ;
				break ;

			case 3U:	// GUIDの欠測を正式名で補完しません
				body.replace(
					body.find( "ClassGuid="),
					std::string_view{"ClassGuid={4d36e97b-e325-11ce-bfc1-08002be10318}\r\n"}.size(),
					"") ;
				break ;

			case 4U:	// 二重GUIDを先頭一値だけで採用しません
				body += "[Version]\r\nClassGuid={4d36e97b-e325-11ce-bfc1-08002be10318}\r\n" ;
				break ;

			case 5U:	// 必須SYS欠損をnull形式へ読み替えません
				break ;

			default:	// 二重Classも正式対の一意性を満たしません
				body += "[Version]\r\nClass=SCSIAdapter\r\n" ;
				break ;
		}

		OfficialDownloadWorkspace workspace ;	// 各条件の独立元byteです
		DRIVERCRATE_EXPECT( context,
						   workspace.initialize( L"storage-structure-test", 3550U + scenario) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "not-signed")) ;
		std::vector<OfficialZipEntry> entries{{L"sample.inf", body.size()},
											  {L"sample.cat", 10U}} ;	// 元CATを省略しません
		// 欠損条件だけは原SYSを作成しません
		if( scenario != 5U) {
			DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.sys", "driver")) ;
			entries.push_back( {L"sample.sys", 6U}) ;
		}

		OfficialInfPackage package ;	// 内容用途の実構造です
		const auto error = inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy,
													 package) ;	// 実native parserです
		DRIVERCRATE_EXPECT( context, (error == 0) == (scenario == 0U)) ;
		// 内容成功でも元用途と未署名拒否を維持します
		if( error == 0) {
			DRIVERCRATE_EXPECT( context, package.inspectionPurpose ==
												OfficialInfInspectionPurpose::COLLECTOR_CONTENT &&
											!package.requiredNullCompanion) ;
			DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, package) != 0) ;
			auto standard	 = policy ;	// Class表を渡しても通常用途へstorageを許可しません
			standard.purpose = OfficialInfInspectionPurpose::STANDARD_DRIVER ;
			OfficialInfPackage refused ;	// 旧通常入口の拒否出力です
			DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"sample.inf",
																  standard, refused) != 0) ;
			DRIVERCRATE_EXPECT( context, refused.infRelativePath.empty()) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 標準TapeDriveの正式対と共通内容・必要構成・署名・適用性の境界を検証する
 * @param[in,out] context 架空INFだけの正負結果を集計する
 * @note 元CATは未署名であり、Classの構造成功から公式性・導入可能性を発行しない
 */
//------------------------------------------------------------------------------
void testStandardTapeDriveStructure( TestContext &context)
{
	constexpr std::string_view TAPE_GUID =
		"{6d807884-7d21-11cf-801c-08002be10318}" ;										// 正式setup GUID
	constexpr std::string_view NET_GUID = "{4d36e972-e325-11ce-bfc1-08002be10318}" ;	// 既存Net正例
	const std::array		   classes{std::wstring_view{L"TapeDrive"},
							   std::wstring_view{L"Net"}} ;	// 一般Class解放をしない
	// 正式対と旧Class control、取り違え、欠損、既存作用の拒否を独立した元byteで比較する
	for( unsigned scenario = 0U; scenario < 29U; ++scenario) {
		std::string body{VALID_INF} ;	// 実inventoryを含まない元の架空driver
		body.replace( body.find( "Class=Net"), 9U, "Class=TapeDrive") ;
		body.replace( body.find( NET_GUID), NET_GUID.size(), TAPE_GUID) ;
		body += "[Install.NT.Services]\r\nAddService=FixtureTape,2,TapeService\r\n"
				"[TapeService]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\n"
				"ServiceBinary=%12%\\sample.sys\r\n" ;
		auto policy							 = POLICY ;	// 既存作用/件数上限を維持する用途別copy
		policy.acceptedClasses				 = classes ;
		policy.allowRequiredDriverComponents = true ;
		policy.rejectUnreferencedPrograms	 = false ;
		policy.rejectInstallActions			 = true ;
		policy.allowReferencedExecutablesForContent = true ;
		// 一条件ずつ変更し、正常なClass名だけで他の欠損を補完しない
		switch( scenario) {
			case 0U:	// 通常用途の正式対
				break ;

			case 1U:	// 正当なClass/GUIDの大文字小文字差
				body.replace( body.find( "Class=TapeDrive"), 15U, "Class=tapedrive") ;
				body.replace( body.find( TAPE_GUID), TAPE_GUID.size(),
							 "{6D807884-7D21-11CF-801C-08002BE10318}") ;
				break ;

			case 2U:	// 内容用途でも同じ正式対を要求
				policy.purpose = OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;
				break ;

			case 3U:	// 端末の共有入口では通常Class用途へ戻る
				policy.purpose = OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE ;
				break ;

			case 4U:	// 必要INF内容の役割からも同じ正式対を検査
				policy.purpose = OfficialInfInspectionPurpose::REQUIRED_COLLECTOR_IMPORT ;
				break ;

			case 5U:	// 端末の必要INF役割でも同じ通常Class
				policy.purpose = OfficialInfInspectionPurpose::REQUIRED_STORAGE_IMPORT ;
				break ;

			case 6U:	// 正式GUIDの欠測をClass名で補完しない
				body.erase( body.find( "ClassGuid="), 10U + TAPE_GUID.size() + 2U) ;
				break ;

			case 7U:	// 別ClassのGUIDとの取り違え
				body.replace( body.find( TAPE_GUID), TAPE_GUID.size(), NET_GUID) ;
				break ;

			case 8U:	// device interface GUIDをsetup GUIDに流用しない
				body.replace( body.find( TAPE_GUID), TAPE_GUID.size(),
							 "{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}") ;
				break ;

			case 9U:	// 許可済みNet名へのTapeDrive GUID偽装
				body.replace( body.find( "Class=TapeDrive"), 15U, "Class=Net") ;
				break ;

			case 10U:	// 後置したTapeDrive GUIDも省略しない
				body.replace( body.find( "Class=TapeDrive"), 15U, "Class=Net") ;
				body.replace( body.find( TAPE_GUID), TAPE_GUID.size(), NET_GUID) ;
				body += "[Version]\r\nClassGUID=" + std::string( TAPE_GUID) + "\r\n" ;
				break ;

			case 11U:	// 後置したTapeDrive名も先頭Netで隠さない
				body.replace( body.find( "Class=TapeDrive"), 15U, "Class=Net") ;
				body.replace( body.find( TAPE_GUID), TAPE_GUID.size(), NET_GUID) ;
				body += "[Version]\r\nClass=TapeDrive\r\n" ;
				break ;

			case 12U:	// 同一GUIDの二重宣言も一意でない
				body += "[Version]\r\nClassGUID=" + std::string( TAPE_GUID) + "\r\n" ;
				break ;

			case 13U:	// 同一Classの二重宣言を拒否
				body += "[Version]\r\nClass=TapeDrive\r\n" ;
				break ;

			case 14U:	// Class行の余分fieldを省略しない
				body.replace( body.find( "Class=TapeDrive"), 15U, "Class=TapeDrive,Net") ;
				break ;

			case 15U:	// GUID行の余分fieldを省略しない
				body.replace( body.find( TAPE_GUID), TAPE_GUID.size(),
							 std::string( TAPE_GUID) + ",extra") ;
				break ;

			case 16U:	// 不許可Classを正式GUIDから採用しない
				body.replace( body.find( "Class=TapeDrive"), 15U, "Class=FictionalTape") ;
				break ;

			case 17U:	// 必須SYSの元file欠損
				break ;

			case 18U:	// 原CATの元file欠損
				break ;

			case 19U:	// 既知Run登録を新Classで許可しない
				body +=
					"[RunRegistry]\r\nHKLM,Software\\Microsoft\\Windows\\CurrentVersion\\Run,Fixture,0,app.exe\r\n" ;
				break ;

			case 20U:	// 任意DLL登録commandは従来どおり拒否
				body += "[Install.NT]\r\nRegisterDlls=Registration\r\n" ;
				break ;

			case 21U:	// CoInstallerの必要DLL欠損を無作用へしない
				body += "[Install.NT.CoInstallers]\r\nAddReg=CoReg\r\nCopyFiles=CoCopy\r\n"
						"[CoReg]\r\nHKR,,CoInstallers32,0x10000,\"missing.dll,Entry\"\r\n"
						"[CoCopy]\r\nmissing.dll\r\n[DestinationDirs]\r\nCoCopy=11\r\n" ;
				break ;

			case 22U:	// 導入構造用の元policyで未充足Win32 serviceを拒否
				body.replace( body.find( "ServiceType=1"), 13U, "ServiceType=16") ;
				policy.allowReferencedExecutablesForContent = false ;
				break ;

			case 23U:	// 同INFで参照する追加fileの欠損を省略しない
				body += "[SourceDisksFiles.amd64]\r\nmissing.dll=1\r\n" ;
				break ;

			case 24U:	// x86専用Modelsをx64対象へ流用しない
				body.replace( body.find( "Models,NTamd64"), 14U, "Models,NTx86") ;
				body.replace( body.find( "[Models.NTamd64]"), 16U, "[Models.NTx86]") ;
				break ;

			case 25U:	// 導入構造用の元policyで未知ServiceTypeを拒否
				body.replace( body.find( "ServiceType=1"), 13U, "ServiceType=128") ;
				policy.allowReferencedExecutablesForContent = false ;
				break ;

			case 26U:	// 必要構成modeでも無関係Classを解放しない
				body.replace( body.find( "Class=TapeDrive"), 15U, "Class=MediumChanger") ;
				policy.purpose = OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;
				break ;

			case 27U:	// 旧Net正式対の独立した正例を保持
				body.replace( body.find( "Class=TapeDrive"), 15U, "Class=Net") ;
				body.replace( body.find( TAPE_GUID), TAPE_GUID.size(), NET_GUID) ;
				break ;

			default:	// 大文字小文字差でも取り違えは拒否
				body.replace( body.find( "Class=TapeDrive"), 15U, "Class=net") ;
				body.replace( body.find( TAPE_GUID), TAPE_GUID.size(),
							 "{6D807884-7D21-11CF-801C-08002BE10318}") ;
				break ;
		}

		OfficialDownloadWorkspace workspace ;	// このcaseだけの所有fixture
		DRIVERCRATE_EXPECT( context,
						   workspace.initialize( L"tape-class-test", 3660U + scenario) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		std::vector<OfficialZipEntry> entries{{L"sample.inf", body.size()}} ;	// 実在fileだけを渡す
		// 欠損CAT条件を他のcaseのfileで補完しない
		if( scenario != 18U) {
			DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
			entries.push_back( {L"sample.cat", 8U}) ;
		}

		// 欠損SYS条件を他のcaseのfileで補完しない
		if( scenario != 17U) {
			DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.sys", "driver")) ;
			entries.push_back( {L"sample.sys", 6U}) ;
		}

		OfficialInfPackage package ;	// 構造成功時だけ保持する通常package
		const auto error	= inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy,
														package) ;	// 元parserの結果
		const bool expected = scenario < 6U || scenario == 27U ;	// 正例七件を固定
		std::cout << "TAPE_CLASS_STRUCTURE scenario=" << scenario << " error=" << error << '\n' ;
		DRIVERCRATE_EXPECT( context, (error == 0) == expected) ;
		// 内容成功から署名や実device適用性の成功を合成しない
		if( error == 0) {
			DRIVERCRATE_EXPECT( context,
							   !package.sourceFiles.empty() && !package.requiredNullCompanion) ;
			DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, package) != 0) ;
			const std::array matching{std::wstring_view{L"PCI\\VEN_1234&DEV_5678"}} ;	// 元の架空ID
			const std::array unrelated{
				std::wstring_view{L"PCI\\VEN_9999&DEV_9999"}} ;	// 不適合架空ID
			DRIVERCRATE_EXPECT( context, matchOfficialInfToDevice( package, matching, {}) ==
											OfficialInfDeviceMatch::HARDWARE_ID) ;
			DRIVERCRATE_EXPECT( context, matchOfficialInfToDevice( package, unrelated, {}) ==
											OfficialInfDeviceMatch::NONE) ;
		}

		// 正式Tapeと旧Netだけで実共通Class集合を通し、未署名拒否と必要INF不足を比較する
		if( scenario == 0U || scenario == 27U) {
			std::string archive ;	// 原架空INF/CAT/SYSの非実行ZIP
			DRIVERCRATE_EXPECT( context, makeMaintenanceClassArchive( body, archive)) ;
			DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"payload.zip", archive)) ;
			std::wstring hash ;	// 原ZIP byteの実hash
			DRIVERCRATE_EXPECT( context,
							   computeFileSha256( workspace.path( L"payload.zip"), hash) == 0) ;
			const DriverArchiveInput input{3760U + scenario, workspace.path( L"payload.zip"),
										   // 元入力
										   archive.size(), hash} ;
			const std::array		 selectors{
				std::pair{std::wstring_view{}, std::wstring_view{L"sample.inf"}}} ;	// 明示一INF
			CommonDriverPackageInspection normal ;									// 通常経路の元署名拒否
			CollectorDriverPackageContent content ;									// 非互換collector内容の元署名拒否
			DRIVERCRATE_EXPECT(
				context, inspectSelectedCommonDriverPackages(
							 input, OfficialDriverArchiveFormat::ZIP, selectors, normal) == 0) ;
			DRIVERCRATE_EXPECT( context, normal.infs.size() == 1U &&
											normal.infs.front().state ==
												CommonInfInspectionState::SIGNATURE_REJECTED) ;
			DRIVERCRATE_EXPECT(
				context, inspectCollectorDriverPackageContent(
							 input, OfficialDriverArchiveFormat::ZIP, selectors, content) == 0) ;
			DRIVERCRATE_EXPECT( context, content.infs.size() == 1U &&
											content.infs.front().state ==
												CommonInfInspectionState::SIGNATURE_REJECTED) ;
			DRIVERCRATE_EXPECT(
				context, inspectSelectedDeviceDriverPackages(
							 input, OfficialDriverArchiveFormat::ZIP, selectors, normal) == 0) ;
			DRIVERCRATE_EXPECT( context, normal.infs.size() == 1U &&
											normal.infs.front().state ==
												CommonInfInspectionState::SIGNATURE_REJECTED) ;

			body += "[Install.NT]\r\nCopyINF=missing.inf\r\n" ;
			DRIVERCRATE_EXPECT( context, makeMaintenanceClassArchive( body, archive)) ;
			DRIVERCRATE_EXPECT( context,
							   writeWorkspaceFile( workspace, L"missing-import.zip", archive)) ;
			DRIVERCRATE_EXPECT( context,
							   computeFileSha256( workspace.path( L"missing-import.zip"), hash) == 0) ;
			const DriverArchiveInput missing{3860U + scenario,
											 workspace.path( L"missing-import.zip"), archive.size(),
											 hash} ;	// 必須import欠損
			DRIVERCRATE_EXPECT(
				context, inspectCollectorDriverPackageContent(
							 missing, OfficialDriverArchiveFormat::ZIP, selectors, content) == 0) ;
			DRIVERCRATE_EXPECT( context, content.infs.size() == 1U &&
											content.infs.front().state ==
												CommonInfInspectionState::CLOSURE_REJECTED &&
											content.infs.front().error != 0) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 正式メディアチェンジャーの端末選択構造と用途の境界を確認する
 * @param[in,out] context 架空パッケージの検査結果を集計する
 * @note 架空CATから署名や導入の成功を生成しない
 */
//------------------------------------------------------------------------------
void testSelectedMediumChangerStructure( TestContext &context)
{
	// 端末と収集の両用途で使う架空の完全なINF
	constexpr std::string_view sample =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=MediumChanger\r\n"
		"ClassGuid={ce5939ae-ebde-11d0-b181-0000f8753ec4}\r\n"
		"Provider=\"Fictional Wireless Corporation\"\r\nDriverVer=09/03/2026,1.2.3.4\r\n"
		"CatalogFile=sample.cat\r\n[ControlFlags]\r\nExcludeFromSelect=*\r\n"
		"[Manufacturer]\r\nManufacturer=Models,NTamd64\r\n"
		"[Models.NTamd64]\r\nChanger=Install,SCSI\\ChangerTEST____Sample_Changer___\r\n"
		"[SourceDisksNames.amd64]\r\n1=\"Sample disk\",,,\r\n"
		"[SourceDisksFiles.amd64]\r\nsample.sys=1\r\n"
		"[DestinationDirs]\r\nDefaultDestDir=12\r\n[Install]\r\nCopyFiles=@sample.sys\r\n"
		"[Install.Services]\r\nAddService=sample,2,Service,Event\r\n"
		"[Service]\r\nServiceType=1\r\nStartType=1\r\nErrorControl=1\r\n"
		"ServiceBinary=%12%\\sample.sys\r\nLoadOrderGroup=SCSI Class\r\nDependencies=+SCSI Miniport\r\n"
		"[Event]\r\nAddReg=EventRegistry\r\n[EventRegistry]\r\n"
		"HKR,,EventMessageFile,0x00020000,\"%%SystemRoot%%\\System32\\IoLogMsg.dll;"
		"%%SystemRoot%%\\System32\\drivers\\sample.sys\"\r\nHKR,,TypesSupported,0x00010001,7\r\n" ;
	// 同じ構造で比較する収集・端末選択・通常・必要構成の用途
	const std::array purposes{OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE,
							  OfficialInfInspectionPurpose::COLLECTOR_CONTENT,
							  OfficialInfInspectionPurpose::STANDARD_DRIVER,
							  OfficialInfInspectionPurpose::REQUIRED_STORAGE_IMPORT,
							  OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE,
							  OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE} ;
	// 同じ元構造の用途、所有領域と依存を個別に変えて比較する
	for( std::size_t index = 0U; index < purposes.size(); ++index) {
		auto policy					= POLICY ;	// 輸送や展開の上限を変えない架空policy
		policy.purpose				= purposes[index] ;
		policy.rejectInstallActions = true ;
		std::string body{sample} ;	// この条件だけが所有する元INF
		// 最後の条件だけは名前付き依存に変更する
		if( index == 5U) {
			body.erase( body.find( "+SCSI Miniport"), 1U) ;
		}

		OfficialDownloadWorkspace workspace ;	// 同じ元用途に対応する保護領域
		// この条件で使う保護領域の種類
		const auto				  mode = index == 1U || index == 4U
											 ? OfficialWorkspaceMode::CURRENT_USER_INSPECTION
											 : OfficialWorkspaceMode::ADMINISTRATOR ;
		DRIVERCRATE_EXPECT(
			context, workspace.initialize( L"changer-structure-test", 3960U + index, mode) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.sys", "driver")) ;
		// 架空INFとCATとSYSの元一覧
		const std::array<OfficialZipEntry, 3U> entries{
			{{L"sample.inf", body.size()}, {L"sample.cat", 8U}, {L"sample.sys", 6U}}} ;
		OfficialInfPackage package ;	// 構造成功時だけ保持する元結果
		// この用途で同じ元構造を検査した結果
		const auto		   error =
			inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy, package) ;
		DRIVERCRATE_EXPECT( context, (error == 0) == (index < 2U)) ;
		// 構造成功でも固有の用途を保持し、架空署名は拒否する
		if( error == 0) {
			DRIVERCRATE_EXPECT( context, package.inspectionPurpose == purposes[index]) ;
			DRIVERCRATE_EXPECT( context, package.className == L"MediumChanger") ;
			DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, package) != 0) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元SYSを持つHDCの収集用途と全AMD64の導入節を検証する
 * @param[in,out] context 架空INFに対する構造検査結果
 * @note 架空CATに署名資格を与えず、端末の導入は呼び出さない
 */
//------------------------------------------------------------------------------
void testCollectorHdcStorageStructure( TestContext &context)
{
	constexpr std::string_view sample =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=HDC\r\n"
		"ClassGuid={4d36e96a-e325-11ce-bfc1-08002be10318}\r\n"
		"Provider=\"Fictional Wireless Corporation\"\r\nDriverVer=09/03/2026,1.2.3.4\r\n"
		"CatalogFile=sample.cat\r\n[ControlFlags]\r\nExcludeFromSelect=*\r\n"
		"[Manufacturer]\r\nManufacturer=Models,NTamd64.6.2,NTamd64.10.0\r\n"
		"[Models.NTamd64.6.2]\r\nController=Install,PCI\\VEN_1234&DEV_0001&CC_0106\r\n"
		"[Models.NTamd64.10.0]\r\nController=Install2,PCI\\VEN_1234&DEV_0002&CC_0106\r\n"
		"[SourceDisksNames]\r\n1=\"Sample disk\"\r\n"
		"[SourceDisksFiles.amd64]\r\nsample.sys=1\r\n"
		"[DestinationDirs]\r\nDefaultDestDir=12\r\n"
		"[Install.NTamd64]\r\nCopyFiles=@sample.sys\r\nFeatureScore=0x80\r\n"
		"[Install.NTamd64.HW]\r\nAddReg=DeviceParameters\r\n"
		"[Install.NTamd64.Services]\r\nAddService=sample,2,Service,Event\r\n"
		"[Install2.NTamd64]\r\nCopyFiles=@sample.sys\r\nFeatureScore=0x80\r\n"
		"[Install2.NTamd64.HW]\r\nAddReg=DeviceParameters\r\n"
		"[Install2.NTamd64.Services]\r\nAddService=sample,2,Service,Event\r\n"
		"[Service]\r\nServiceType=1\r\nStartType=0\r\nErrorControl=1\r\n"
		"ServiceBinary=%12%\\sample.sys\r\nLoadOrderGroup=SCSI Miniport\r\n"
		"[Event]\r\nAddReg=EventRegistry\r\n[EventRegistry]\r\n"
		"HKR,,EventMessageFile,0x00020000,\"%%SystemRoot%%\\System32\\IoLogMsg.dll;"
		"%%SystemRoot%%\\System32\\drivers\\sample.sys\"\r\nHKR,,TypesSupported,0x00010001,7\r\n"
		"[DeviceParameters]\r\nHKR,,Sample,0x00010001,1\r\n" ;	// 二つの元Modelsを持つ架空HDC
	// 収集と端末の正例、付随作用、追加サービス、保護領域と用途の違いを比較する
	for( std::size_t index = 0U; index < 6U; ++index) {
		auto policy	   = POLICY ;	// 既存の構造検査と同じ有限上限
		policy.purpose = index < 3U ? OfficialInfInspectionPurpose::COLLECTOR_CONTENT
									: OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE ;
		// 共通の通常用途だけを指定しHDCの追加選択から除く
		if( index == 5U) {
			policy.purpose = OfficialInfInspectionPurpose::STANDARD_DRIVER ;
		}

		policy.rejectInstallActions = true ;
		std::string body{sample} ;	// 一つの条件で検査する元INF
		// 選ばれる二つ目のAMD64 Modelsにだけ未検査の付随節を置く
		if( index == 1U) {
			constexpr std::string_view hardware =
				"[Install2.NTamd64.HW]" ;	// 二つ目の候補だけを変更する
			body.replace( body.find( hardware), hardware.size(), "[Install2.NTamd64.Other]") ;
		}
		// 二つ目のAMD64選択のサービス追加を検査する
		else if( index == 2U) {
			body.insert( body.find( "[Service]"), "AddService=Auxiliary,0,Service\r\n") ;
		}

		OfficialDownloadWorkspace workspace ;	// 架空INF、CAT、SYSだけの保護領域
		// 管理者保護領域と現在利用者の検査領域を比較する条件
		const auto mode = index == 4U ? OfficialWorkspaceMode::CURRENT_USER_INSPECTION
									  : OfficialWorkspaceMode::ADMINISTRATOR ;
		DRIVERCRATE_EXPECT( context,
						   workspace.initialize( L"hdc-structure-test", 4050U + index, mode) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.sys", "driver")) ;
		const std::array<OfficialZipEntry, 3U> entries{
			{{L"sample.inf", body.size()}, {L"sample.cat", 8U}, {L"sample.sys", 6U}}} ;	// 元の全項目
		OfficialInfPackage package ;													// 構造検査に成功した場合だけ元を保持する
		// 架空INFがこの用途の元節をすべて持つかの結果
		const auto		   error =
			inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy, package) ;
		DRIVERCRATE_EXPECT( context, (error == 0U) == (index == 0U || index == 3U)) ;
		// 構造が成立した場合も原CATの検査が別に必要であることを確認する
		if( error == 0U) {
			DRIVERCRATE_EXPECT( context, package.inspectionPurpose == policy.purpose) ;
			DRIVERCRATE_EXPECT( context, package.collectorInboxInstallGroups.empty()) ;
			DRIVERCRATE_EXPECT( context, package.nativeHdcInstallGroups.size() == 2U) ;
			DRIVERCRATE_EXPECT( context,
							   package.sourceFiles == std::vector<std::wstring>{L"sample.sys"}) ;
			DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, package) != 0U) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief HDCの共有AutoLoggerとイベント資源を原行の型と順序で検証する
 * @param[in,out] context 架空作用の検査結果
 * @note 現在のサービスやレジストリには接続しない
 */
//------------------------------------------------------------------------------
void testCollectorHdcStorageEffects( TestContext &context)
{
	SelectedStorageServiceFacts service ;	// 一つの署名済みSYSに結ぶ構造を模した原事実
	service.className			   = L"HDC" ;
	service.classGuid			   = L"{4d36e96a-e325-11ce-bfc1-08002be10318}" ;
	service.selectedInstallSection = L"Install.NTamd64" ;
	service.servicesSection		   = L"Install.NTamd64.Services" ;
	service.name				   = L"FixtureStorage" ;
	service.installSection		   = L"Service" ;
	service.addServiceFields	   = {service.name, L"2", service.installSection, L"Event"} ;
	service.flags				   = 2U ;
	service.type				   = SERVICE_KERNEL_DRIVER ;
	service.start				   = SERVICE_BOOT_START ;
	service.errorControl		   = SERVICE_ERROR_NORMAL ;
	service.group				   = L"SCSI Miniport" ;
	service.binarySource		   = L"sample.sys" ;
	service.binaryTarget		   = L"C:\\Windows\\System32\\drivers\\sample.sys" ;
	service.binary				   = service.binaryTarget ;
	service.directives			   = {{0U, L"ServiceType", {L"1"}},
									  {1U, L"StartType", {L"0"}},
									  {2U, L"ErrorControl", {L"1"}},
									  {3U, L"ServiceBinary", {service.binary}},
									  {4U, L"LoadOrderGroup", {*service.group}}} ;
	const std::array seeds{
		SystemInfSection{1U,
						 service.selectedInstallSection,
						 SystemInfContext::DEVICE,
						 SystemInfContext::DEVICE,
						 {}},
		SystemInfSection{
			1U, L"Install.NTamd64.HW", SystemInfContext::HARDWARE, SystemInfContext::HARDWARE, {}},
		SystemInfSection{1U,
						 service.servicesSection,
						 SystemInfContext::SERVICES,
						 SystemInfContext::SERVICES,
						 {}}} ;	// 同じ元選択の基本節と付随節
	const std::wstring session =
		L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\FixtureStorage" ;	// 架空の共有セッション
	const std::wstring provider =
		session + L"\\{22222222-2222-2222-2222-222222222222}" ;	// 架空提供者
	using Rows = std::vector<SystemInfRow> ;
	const std::array<std::pair<std::wstring_view, Rows>, 7U> original{{
		{service.selectedInstallSection,
		 {{0U, L"CopyFiles", {L"@sample.sys"}}, {1U, L"FeatureScore", {L"0x80"}}}},
		{L"Install.NTamd64.HW", {{0U, L"AddReg", {L"AutoLogger"}}}},
		{service.servicesSection, {{0U, L"AddService", service.addServiceFields}}},
		{service.installSection,
		 {{0U, L"ServiceType", {L"1"}},
		  {1U, L"StartType", {L"0"}},
		  {2U, L"ErrorControl", {L"1"}},
		  {3U, L"ServiceBinary", {service.binary}},
		  {4U, L"LoadOrderGroup", {*service.group}}}},
		{L"Event", {{0U, L"AddReg", {L"EventValues"}}}},
		{L"EventValues",
		 {{0U,
		   L"",
		   {L"HKR", L"", L"EventMessageFile", L"0x20000",
			L"%SystemRoot%\\System32\\IoLogMsg.dll;%SystemRoot%\\System32\\drivers\\sample.sys"}},
		  {1U, L"", {L"HKR", L"", L"TypesSupported", L"0x10001", L"7"}}}},
		{L"AutoLogger",
		 {{0U, L"", {L"HKLM", session, L"LogFileMode", L"0x10001", L"0x400"}},
		  {1U, L"", {L"HKLM", session, L"FileName"}},
		  {2U, L"", {L"HKLM", session, L"Guid", L"0", L"{11111111-1111-1111-1111-111111111111}"}},
		  {3U, L"", {L"HKLM", session, L"Start", L"0x10001", L"1"}},
		  {4U, L"", {L"HKLM", session, L"BufferSize", L"0x10001", L"999"}},
		  {5U, L"", {L"HKLM", provider, L"EnableProperty", L"0x10001", L"0"}},
		  {6U, L"", {L"HKLM", provider, L"Enabled", L"0x10001", L"1"}},
		  {7U, L"", {L"HKLM", provider, L"EnableLevel", L"0x10001", L"4"}},
		  {8U, L"", {L"HKLM", provider, L"EnableFlags", L"0x10001", L"0xffff"}}}},
	}} ; // 作用readerが受け取る架空の原節と全フィールド
	// 原行、ファイル出力、別プロバイダー、保護資源の失敗の四つを比較する
	for( unsigned scenario = 0U; scenario < 4U; ++scenario) {
		std::size_t		   registryRows{} ;	// 共有するregistry行予算
		SystemInfEffectApi api ;			// この試験の原行と保護資源だけに結ぶ操作
		api.registryRows = &registryRows ;
		api.read		 = [&]( const SystemInfSection &section, Rows &rows) -> NativeError {
			const auto source = std::ranges::find_if( original, [&]( const auto &entry) {
				return entry.first == section.name ;
			}) ; // 元の節名に完全一致する架空の読み取り位置
			// 指定外の節を読んだ場合は架空成功を返さない
			if( source == original.end()) {
				return HRESULT_FROM_WIN32( ERROR_SECTION_NOT_FOUND) ;
			}

			rows = source->second ;
			// 名前だけの宣言に外部ファイル出力を混ぜた対照
			if( section.name == L"AutoLogger" && scenario == 1U) {
				rows[1].values.insert( rows[1].values.end(), {L"0", L"C:\\fixture.etl"}) ;
			}
			// 一つのプロバイダーに閉じない登録先を含めた対照
			else if( section.name == L"AutoLogger" && scenario == 2U) {
				rows.back().values[1] = session + L"\\{33333333-3333-3333-3333-333333333333}" ;
			}

			return 0U ;
		} ;
		api.module = [&]( std::uint64_t document, std::wstring_view path) -> NativeError {
			return scenario != 3U && document == 1U &&
						   path == L"%SystemRoot%\\System32\\IoLogMsg.dll"
					   ? 0U
					   : E_ACCESSDENIED ;
		} ;
		StorageInfEffects result ;	// 正常な原作用だけを保持する検査結果
		std::uint32_t	  stage{} ;	// 一つ目の診断段階
		// 同一の元選択に対する作用検査の成否
		const auto error = inspectHdcInfContentEffects( seeds, api, service, 26100U, result, stage) ;
		DRIVERCRATE_EXPECT( context, (error == 0U) == (scenario == 0U)) ;
		DRIVERCRATE_EXPECT( context, result.services.empty()) ;
		DRIVERCRATE_EXPECT( context, result.autoLogger.has_value() == (scenario == 0U)) ;
		// 正常な原作用から得た順位と型付き共有設定を確認する
		if( result.autoLogger) {
			DRIVERCRATE_EXPECT( context, result.featureScore == 0x80U) ;
			DRIVERCRATE_EXPECT( context, result.autoLogger->providerPath == provider) ;
			DRIVERCRATE_EXPECT( context, result.autoLogger->bufferSize == 999U) ;
		}
	}

	// トリアージ指定、既存HDC値との混在、共有節の逸脱と予算を同じ架空INFで比較する
	for( unsigned scenario = 0U; scenario < 8U; ++scenario) {
		std::size_t		   registryRows = scenario == 7U ? 4090U : 0U ;	// 元グラフが先に消費した行数
		SystemInfEffectApi api ;										// 元HW節と直接参照にだけ結ぶ読取操作
		api.registryRows = &registryRows ;
		api.read		 = [&]( const SystemInfSection &section, Rows &rows) -> NativeError {
			// 元読み取りの文書と所有範囲が変わっていないことを確認する
			if( section.document != 1U || section.scope != SystemInfContext::HARDWARE ||
			   !section.owner.empty()) {
				return E_INVALIDARG ;
			}

			// 元機器節から直接参照するAddRegだけを試験へ渡す
			if( section == seeds[1]) {
				rows = original[1].second ;
				// 同一節の再参照と別節の共有セッション重複を対照する
				if( scenario == 4U || scenario == 5U) {
					rows.front().values.push_back( scenario == 4U ? L"AUTOLOGGER"
																		 : L"AnotherLogger") ;
				}

				return 0U ;
			}

			// 不明な外側の参照文脈を共有設定へ救済しない
			if( section.context != SystemInfContext::REGISTRY ||
			   (section.name != L"AutoLogger" && section.name != L"AnotherLogger")) {
				return E_INVALIDARG ;
			}

			rows			  = original.back().second ;
			rows[0].values[4] = scenario == 2U ? L"0x400" : L"0x90000400" ;
			rows[4].values[4] = scenario == 1U ? L"999" : L"5000" ;
			// 共有の正規セッションに相対行が混ざるケースを作る
			if( scenario == 3U) {
				rows.back().values.front() = L"HKR" ;
			}

			// 値が同じでもDWORD以外の型指定は受け入れない
			if( scenario == 6U) {
				rows[4].values[3] = L"0" ;
			}

			return 0U ;
		} ;
		std::optional<StorageAutoLoggerEffects> triage ;	// 照合した完全な共有設定
		triage.emplace() ;
		const auto error = readStorageTriageAutoLogger( seeds[1], api, triage) ;	// 元範囲の検査結果
		DRIVERCRATE_EXPECT( context, (error == 0U) == (scenario == 0U)) ;
		DRIVERCRATE_EXPECT( context, triage.has_value() == (scenario == 0U)) ;
		// 完全に成立した場合だけ元モードと元バッファー、所有先を保持する
		if( triage) {
			DRIVERCRATE_EXPECT( context,
							   triage->sessionPath == session && triage->providerPath == provider) ;
			DRIVERCRATE_EXPECT( context,
							   triage->logFileMode == 0x90000400U && triage->bufferSize == 5000U) ;
			DRIVERCRATE_EXPECT( context, registryRows == 9U) ;
		}
	}

	service.selectedInstallSection	 = L"IdeInstall" ;
	service.servicesSection			 = L"IdeInstall.Services" ;
	service.group					 = L"System Bus Extender" ;
	service.directives.back().fields = {*service.group} ;
	service.addServiceFields.pop_back() ;
	const std::array ideSeeds{SystemInfSection{1U,
											   service.selectedInstallSection,
											   SystemInfContext::DEVICE,
											   SystemInfContext::DEVICE,
											   {}},
							  SystemInfSection{1U,
											   service.servicesSection,
											   SystemInfContext::SERVICES,
											   SystemInfContext::SERVICES,
											   {}}} ;	// IDEの元二節
	// 元SYSのみ、別コピー、余分な順位、余分なサービス作用を比較する
	for( unsigned scenario = 0U; scenario < 4U; ++scenario) {
		std::size_t		   registryRows{} ;	// 読み取った追加登録の行数
		SystemInfEffectApi api ;			// IDEの元節だけを読む試験API
		api.registryRows = &registryRows ;
		api.read		 = [&]( const SystemInfSection &section, Rows &rows) -> NativeError {
			// 基本節の元SYSコピーを確認する
			if( section.name == service.selectedInstallSection) {
				rows = {{0U, L"CopyFiles", {scenario == 1U ? L"@other.sys" : L"@sample.sys"}}} ;
				// 元二節の構成に存在しない順位を追加する対照
				if( scenario == 2U) {
					rows.push_back( {1U, L"FeatureScore", {L"0x80"}}) ;
				}
			}
			// 関連サービスの参照行を元のフィールド数で返す
			else if( section.name == service.servicesSection) {
				rows = {{0U, L"AddService", service.addServiceFields}} ;
			}
			// 実行形式と起動グループの元設定を全行で返す
			else if( section.name == service.installSection) {
				// 読み取り前に構築した元サービス設定を使う
				for( const auto &directive : service.directives) {
					rows.push_back( {directive.ordinal, directive.key, directive.fields}) ;
				}
			}
			// 到達しない節を空の正常結果で補完しない
			else {
				return HRESULT_FROM_WIN32( ERROR_SECTION_NOT_FOUND) ;
			}

			return 0U ;
		} ;
		// サービス宣言自体に登録作用を足した場合も許可しない
		if( scenario == 3U) {
			service.directives.push_back( {5U, L"AddReg", {L"RegistryValues"}}) ;
		}

		StorageInfEffects result ;	// 全検査を通過した作用だけを保持する
		std::uint32_t	  stage{} ;	// 最初に失敗した検査の番号
		const auto error = inspectHdcInfContentEffects( ideSeeds, api, service, 19045U, result,
													   stage) ;	// 架空の元節の検査結果
		DRIVERCRATE_EXPECT( context, (error == 0U) == (scenario == 0U)) ;
		DRIVERCRATE_EXPECT( context, result.effects.size() == (scenario == 0U ? 7U : 0U)) ;
		DRIVERCRATE_EXPECT( context,
						   registryRows == 0U && !result.autoLogger && !result.featureScore) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Windowsのグループ順序の終端、一意性、前後関係を検証する
 * @param[in,out] context 架空の複数文字列に対する検査結果
 */
//------------------------------------------------------------------------------
void testStorageLoadOrder( TestContext &context)
{
	// 正しい順序で終端する元文字列
	constexpr wchar_t valid[] = L"Boot Bus Extender\0SCSI miniport\0SCSI Class\0" ;
	// 二つのグループが逆順の元文字列
	constexpr wchar_t reversed[] = L"SCSI Class\0SCSI Miniport\0" ;
	// 大文字小文字が異なる同名グループを持つ元文字列
	constexpr wchar_t duplicate[] = L"SCSI Miniport\0SCSI Class\0scsi MINIPORT\0" ;
	// 必要なクラスグループがない元文字列
	constexpr wchar_t missing[] = L"SCSI Miniport\0File System\0" ;
	// 最終NULが一つだけの元文字列
	constexpr wchar_t missingEnd[] = L"SCSI Miniport\0SCSI Class" ;
	// 途中の空文字列の後に別項目を持つ元文字列
	constexpr wchar_t badTail[] = L"SCSI Miniport\0SCSI Class\0\0Other\0" ;
	// 検査に成功したグループ位置の出力
	StorageLoadOrder  order ;
	DRIVERCRATE_EXPECT( context, inspectStorageLoadOrder( valid, order) == 0U) ;
	DRIVERCRATE_EXPECT( context, order.miniport == 1U && order.deviceClass == 2U) ;
	// 誤った順序、欠落、重複、終端不良と末尾の余分な値を拒否する
	for( const auto groups :
		{std::span<const wchar_t>{reversed}, std::span<const wchar_t>{duplicate},
		 std::span<const wchar_t>{missing}, std::span<const wchar_t>{missingEnd},
		 std::span<const wchar_t>{badTail}}) {
		order = {1U, 2U} ;
		DRIVERCRATE_EXPECT( context, inspectStorageLoadOrder( groups, order) != 0U) ;
		DRIVERCRATE_EXPECT( context, order == StorageLoadOrder{}) ;
	}

	// IDEで元位置が変わると同一の観測値にならない
	constexpr wchar_t ide[] = L"Boot Bus Extender\0System Bus Extender\0SCSI Miniport\0" ;
	// 順序が入れ替わった二回目の観測
	constexpr wchar_t ideMoved[] = L"System Bus Extender\0Boot Bus Extender\0" ;
	// 大文字小文字が異なる同名グループを二つ含む一覧
	constexpr wchar_t ideDuplicate[] = L"System Bus Extender\0SYSTEM BUS EXTENDER\0" ;
	// 同じ位置の前後を別の起動グループが横切る場合
	constexpr wchar_t ideCrossed[] = L"SCSI Miniport\0System Bus Extender\0Boot Bus Extender\0" ;
	StorageLoadOrder  before ;	// 最初に読み取ったグループ位置
	DRIVERCRATE_EXPECT( context, inspectStorageLoadOrder( ide, before, true) == 0U &&
									before.systemBusExtender == 1U) ;
	DRIVERCRATE_EXPECT( context, inspectStorageLoadOrder( ideMoved, order, true) == 0U &&
									order.systemBusExtender == 0U && order != before) ;
	DRIVERCRATE_EXPECT( context, inspectStorageLoadOrder( ideCrossed, order, true) == 0U &&
									order.systemBusExtender == before.systemBusExtender &&
									order != before) ;
	// 欠落と重複から部分的な順位を返さない
	for( auto groups : {std::span<const wchar_t>{valid}, std::span<const wchar_t>{ideDuplicate}}) {
		order = before ;
		DRIVERCRATE_EXPECT( context, inspectStorageLoadOrder( groups, order, true) != 0U &&
										order == StorageLoadOrder{}) ;
	}
}

/** @brief 独立literalで固定した限定registry-only構造の一変異です */
struct RegistryOnlyStructureCase {
	/// 実出力へ結ぶ固定case IDです
	std::string_view			 id ;
	/// helper出力から生成しない構造成功期待です
	bool						 accepted{} ;
	/// 元literal内の一意な置換対象です。空なら末尾追記です
	std::string_view			 from ;
	/// 当該一変異の元byteです
	std::string_view			 to ;
	/// 同じ人工INFへ明示する非権限用途です
	OfficialInfInspectionPurpose purpose{OfficialInfInspectionPurpose::REQUIRED_COLLECTOR_IMPORT} ;
	/// 必要構成flagの独立入力です
	bool						 required{true} ;
	/// Windows管理DATA flagの独立入力です
	bool						 managed{true} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 限定registry-onlyのA6/B34を実SetupAPIと元byteへ接続します
 * @param[in,out] context 全literal期待と実到達結果の集計先です
 * @note Fake CATの拒否は実署名成功ではありません。実device/registry書込/導入は行いません
 */
//------------------------------------------------------------------------------
void testRequiredRegistryOnlyStructure( TestContext &context)
{
	constexpr std::string_view INF =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=System\r\n"
		"ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}\r\nProvider=Fixture\r\n"
		"DriverVer=11/18/2026,1.2.3.4\r\nCatalogFile=sample.cat\r\n"
		"[Manufacturer]\r\n%Maker%=Models,NTx86,NTamd64\r\n"
		"[Models.NTx86]\r\n%Device32%=Install32,TESTBUS\\Registry32\r\n"
		"[Models.NTamd64]\r\n%Device64%=Install64,TESTBUS\\Registry64,*FixtureCompatible\r\n"
		"[Install32.NTx86]\r\nAddReg=Reg\r\n[Install32.NTx86.Services]\r\nAddService=,2\r\n"
		"[Install64.NTamd64]\r\nAddReg=Reg\r\n[Install64.NTamd64.Services]\r\nAddService=,2\r\n"
		"[Reg]\r\nHKR,Parameters\\Fixture,Level,%DwordFlags%,1\r\n"
		// 全ID/本文は架空です
		"[Strings]\r\nMaker=Fixture\r\nDevice32=Fictional32\r\nDevice64=Fictional64\r\nDwordFlags=65537\r\n" ;
	// DWORDの参照と同じStrings定義を一組で差し替える範囲です
	constexpr std::string_view FLAT_DWORD =
		"%DwordFlags%,1\r\n[Strings]\r\nMaker=Fixture\r\nDevice32=Fictional32\r\n"
		"Device64=Fictional64\r\nDwordFlags=65537\r\n" ;
	// 元行とSetupAPIの展開を比較するドット付きの同じ値です
	constexpr std::string_view DOTTED_DWORD =
		"%Dword.Flags%,1\r\n[Strings]\r\nMaker=Fixture\r\nDevice32=Fictional32\r\n"
		"Device64=Fictional64\r\nDword.Flags=65537\r\n" ;
	// 許容する元レジストリ行と作用を変えた拒否対照を独立に列挙した表
	const auto cases = std::to_array<RegistryOnlyStructureCase>(
		{{"A01", true, {}, {}},
		 {"A02", true, "DwordFlags=65537", "DwordFlags=0x00010001"},
		 {"A03",
		  true,
		  {},
		  "[SourceDisksFiles]\r\n[SourceDisksFiles.amd64]\r\n[SourceDisksNames]\r\n[SourceDisksNames.amd64]\r\n"},
		 {"A04", true, "HKR,", "hkr,"},
		 {"A05", true, "%DwordFlags%,1", "%DwordFlags%,0"},
		 {"A06", true, "%DwordFlags%,1", "%DwordFlags%,0xFFFFFFFF"},
		 {"B01", false, {}, {}, OfficialInfInspectionPurpose::STANDARD_DRIVER},
		 {"B02", false, {}, {}, OfficialInfInspectionPurpose::COLLECTOR_CONTENT},
		 {"B03", false, {}, {}, OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE},
		 {"B04", false, {}, {}, OfficialInfInspectionPurpose::REQUIRED_STORAGE_IMPORT},
		 {"B05", false, "4d36e97d", "4d36e972"},
		 {"B06", false, "Provider=Fixture",
		  "ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}\r\nProvider=Fixture"},
		 {"B07", false, "%Maker%=Models,NTx86,NTamd64\r\n", ""},
		 {"B08", false, "[Models.NTx86]\r\n%Device32%=Install32,TESTBUS\\Registry32\r\n", ""},
		 {"B09", false, "TESTBUS\\Registry32", "TESTBUS\\Invalid ID"},
		 {"B10", false, "[Install32.NTx86]\r\nAddReg=Reg",
		  "[Install32.NTx86]\r\nAddReg=Reg\r\nCopyFiles=@hidden.sys"},
		 {"B11", false, {}, "[Orphan]\r\nAddReg=Reg\r\n"},
		 {"B12", false, "[Install32.NTx86]\r\nAddReg=Reg",
		  "[Install32.NTx86]\r\nAddReg=Reg\r\nInclude=machine.inf\r\nNeeds=Fixture\r\n"},
		 {"B13", false, "[Install32.NTx86]\r\nAddReg=Reg",
		  "[Install32.NTx86]\r\nAddReg=Reg\r\nAddReg=Reg"},
		 {"B14", false, "[Reg]\r\nHKR,Parameters\\Fixture,Level,%DwordFlags%,1\r\n", ""},
		 {"B15", false, "AddReg=Reg\r\n[Install32", "AddReg=Reg,Reg\r\n[Install32"},
		 {"B16", false, "HKR,", "HKLM,"},
		 {"B17", false, "Parameters\\Fixture", "Other\\Fixture"},
		 {"B18", false, ",Level,", ",,"},
		 {"B19", false, "Parameters\\Fixture", "Parameters\\..\\Fixture"},
		 {"B20", false, "DwordFlags=65537", "DwordFlags=65539"},
		 {"B21", false, "DwordFlags=65537", "DwordFlags=0"},
		 {"B22", false, "%DwordFlags%,1", "%DwordFlags%,0x100000000"},
		 {"B23", false, "%DwordFlags%,1", "%DwordFlags%,1,0"},
		 {"B24", false, "AddService=,2", "AddService=Named,2"},
		 {"B25", false, "AddService=,2", "AddService=,0"},
		 {"B26", false, "AddService=,2", "AddService=,2,"},
		 {"B27", false, {}, "[SourceDisksFiles]\r\nmissing.sys=1\r\n"},
		 {"B28", false, {}, "[SourceDisksFiles.unknown]\r\n"},
		 {"B29", false, {}, "[HiddenReg.NTx86]\r\nHKLM,Parameters\\Fixture,Level,65537,1\r\n"},
		 {"B30", false, "Provider=Fixture", "Provider=Fixture\r\nUnknownKey=1"},
		 {"B31", false, "HKR,Parameters\\Fixture,Level,%DwordFlags%,1",
		  "HKR,Parameters\\Fixture,Level,%DwordFlags%,1\r\nHKR,Parameters\\Fixture,Level,%DwordFlags%,1"},
		 {"B32", false, "%DwordFlags%,1", "%DwordFlags%,%MissingDword%"},
		 {"B33", false, {}, {}, OfficialInfInspectionPurpose::REQUIRED_COLLECTOR_IMPORT, false},
		 {"B34",
		  false,
		  {},
		  {},
		  OfficialInfInspectionPurpose::REQUIRED_COLLECTOR_IMPORT,
		  true,
		  false},
		 {"E01", true, {}, "; Copyright \xA9\r\n"},
		 {"E02", true, {}, " \t; Copyright \xA9\r\n"},
		 {"E03", true, {}, "; Copyright \xA9"},
		 {"E04", false, "DwordFlags=65537", "DwordFlags=65537 ; \xA9"},
		 {"E05", false, "Maker=Fixture",
		  "Maker=Fix\xA9"
		  "ture"},
		 {"E06", false, "Maker=Fixture", "Maker=\"Fixture;\xA9\""},
		 {"E07", false, {}, std::string_view{"; \xA9\0\r\n", sizeof( "; \xA9\0\r\n") - 1U}},
		 {"E08", false, {}, "; \xA9\x01\r\n"},
		 {"E09", false, {}, "; \xA9\x7F\r\n"},
		 {"E10", false, "DwordFlags=65537", "; \xA9\nDwordFlags=65537 ; \xA9"},
		 {"E11", false, "DwordFlags=65537", "; \xA9\rDwordFlags=65537 ; \xA9"},
		 {"E12", false, {}, "; \xA9\x1F\r\n"},
		 {"F01", true, FLAT_DWORD, DOTTED_DWORD},
		 {"F02", true, {}, "Spare.DeviceDesc=Fictional\r\n"},
		 {"F03", false, "%DwordFlags%,1", "%Dword.Flags%,1"},
		 {"F04", false, {}, ".DeviceDesc=Fictional\r\n"},
		 {"F05", false, {}, "Device..Desc=Fictional\r\n"},
		 {"F06", false, {}, "DeviceDesc.=Fictional\r\n"},
		 {"F07", false, FLAT_DWORD, DOTTED_DWORD, OfficialInfInspectionPurpose::STANDARD_DRIVER}}) ;
	const std::array classes{std::wstring_view{L"System"}} ;	// 用途とは別の正式Classです
	std::uint64_t	 ordinal{} ;								// 同一caseの所有workspaceだけへ結びます
	// 元の回帰と単独コメント、ドット付き文字列の拒否まで検証します
	for( const auto &test : cases) {
		const int	failures = context.failureCount() ;	// 当該caseの実assertion差分だけです
		std::string body{INF} ;							// 他caseの変異を継承しません
		// 追記と元literal置換を区別し、誤ったfixtureを成功に数えません
		if( test.from.empty()) {
			body += test.to ;
		} else {
			const auto position = body.find( test.from) ;	// 正確な元変異位置です
			DRIVERCRATE_EXPECT( context, position != body.npos) ;
			// 未到達の変異を無変更negativeへしません
			if( position == body.npos) {
				throw std::runtime_error( "registry structure mutation prerequisite") ;
			}

			body.replace( position, test.from.size(), test.to) ;
		}

		auto policy							 = POLICY ;	// 旧正常policyから必要入力だけを変更します
		policy.acceptedClasses				 = classes ;
		policy.acceptAnyProvider			 = true ;
		policy.acceptedProviders			 = {} ;
		policy.requireDriverBinary			 = false ;
		policy.rejectUnreferencedPrograms	 = false ;
		policy.rejectInstallActions			 = true ;
		policy.allowRequiredDriverComponents = test.required ;
		policy.allowWindowsManagedDriverDataForContent = test.managed ;
		policy.purpose								   = test.purpose ;
		OfficialDownloadWorkspace workspace ;	// 実INF readerへ渡す新所有元byteです
		// この試験だけの保護領域を作った結果
		const auto				  initialized =
			workspace.initialize( L"registry-only-structure", 3900U + ordinal++) ;
		DRIVERCRATE_EXPECT( context, initialized == 0) ;
		const bool wrote = initialized == 0 && writeWorkspaceFile( workspace, L"sample.inf", body) &&
						   // CAT成功は注入しません
						   writeWorkspaceFile( workspace, L"sample.cat", "not-signed") ;
		DRIVERCRATE_EXPECT( context, wrote) ;
		// 所有/保存失敗を目的phaseの拒否として数えません
		if( !wrote) {
			throw std::runtime_error( "registry structure workspace prerequisite") ;
		}

		const std::array   entries{OfficialZipEntry{L"sample.inf", body.size()},
								   OfficialZipEntry{L"sample.cat", 10U}} ;	// 自身sourceを追加しません
		OfficialInfPackage package ;										// 元readerの全出力だけです
		// 試験対象の同梱構造を読み取った結果
		const auto		   error =
			inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy, package) ;
		DRIVERCRATE_EXPECT( context, (error == 0) == test.accepted) ;
		// 正例もID/hash/CATを別に確認し、形式だけの成功へ縮約しません
		if( test.accepted && error == 0) {
			const std::vector<std::wstring> expectedIds{
				L"TESTBUS\\Registry64", L"*FixtureCompatible"} ;	// 独立した元二fieldです
			DRIVERCRATE_EXPECT( context,
							   package.requiredRegistryOnlyCompanion &&
								   !package.requiredNullCompanion && package.sourceFiles.empty() &&
								   package.inspectionPurpose ==
									   OfficialInfInspectionPurpose::REQUIRED_COLLECTOR_IMPORT &&
								   package.hardwareIds == expectedIds) ;
			OfficialInfPublishedIdentity identity ;	// 同元byteからの独立ID区分です
			// 同じ保護INFに対する識別の診断
			const auto					 identityError =
				readOfficialInfPublishedIdentity( workspace, package, identity) ;
			std::wstring expectedHash ;	// 固定入力bodyの既SHAを使い、parserからexpectedを作りません
			DRIVERCRATE_EXPECT( context, computeBytesSha256( body, expectedHash) == 0) ;
			DRIVERCRATE_EXPECT( context, identityError == 0 && identity.infSha256 == expectedHash &&
											identity.models.size() == 1U) ;
			// 全Models一件という正常前提後だけ全ordered typed IDを比較します
			if( identity.models.size() == 1U) {
				DRIVERCRATE_EXPECT( context,
								   identity.models[0].modelSection == L"Models.NTamd64" &&
									   identity.models[0].hardwareIds ==
										   std::vector<std::wstring>{L"TESTBUS\\Registry64"} &&
									   identity.models[0].compatibleIds ==
										   std::vector<std::wstring>{L"*FixtureCompatible"}) ;
			}

			DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, package) != 0) ;
		}
		// negativeは構造入口の拒否と空出力を独立に確認します
		else if( !test.accepted) {
			// 上流構造拒否とmarker不成立を観測し、任意の後段errorで代用しません
			DRIVERCRATE_EXPECT( context, !package.requiredRegistryOnlyCompanion &&
											!package.requiredNullCompanion &&
											package.infRelativePath.empty()) ;
			// コメント/表示値以外の正常前提を保持した追補負例はsource例外不成立の原phaseで拒否します
			if( test.id.starts_with( "E")) {
				DRIVERCRATE_EXPECT( context, error == static_cast<NativeError>( 0xE0000102U)) ;
			}
		}

		std::cout << "RRS_STRUCTURE id=" << test.id
				  << " errorBits=" << static_cast<std::uint32_t>( error)
				  << " registry=" << package.requiredRegistryOnlyCompanion
				  << " null=" << package.requiredNullCompanion
				  << " caseFailures=" << context.failureCount() - failures << " install=0\n" ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 必須System null importだけを全潜在architecture/作用の閉集合で受理します
 * @param[in,out] context 元Models/空DDInstall/正確なnull serviceの正負結果を集計します
 */
//------------------------------------------------------------------------------
void testRequiredNullCollectorImport( TestContext &context)
{
	constexpr std::string_view INF =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=System\r\n"
		"ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}\r\nProvider=Fixture\r\n"
		"DriverVer=11/15/2026,1.2.3.4\r\nCatalogFile=sample.cat\r\n"
		"[Manufacturer]\r\nFixture=Models,NTx86,NTamd64\r\n"
		"[Models.NTx86]\r\nDevice=Null,FictionalEnclosure\r\n"
		"[Models.NTamd64]\r\nDevice=Null,FictionalEnclosure,*FictionalCompatible\r\n"
		"[Null.NTx86]\r\n[Null.NTx86.Services]\r\nAddService=,2\r\n"
		"[Null.NTamd64]\r\n[Null.NTamd64.Services]\r\nAddService=,%Flags%\r\n"
		"[Strings]\r\nFlags=0x00000002\r\n" ;					// 全IDは架空で、x86内容も検査します
	const std::array classes{std::wstring_view{L"System"}} ;	// 正式GUIDを別途要求します
	auto			 policy				 = POLICY ;				// 元件数/構文境界を保持します
	policy.acceptedClasses				 = classes ;
	policy.acceptAnyProvider			 = true ;
	policy.acceptedProviders			 = {} ;
	policy.requireDriverBinary			 = false ;
	policy.rejectUnreferencedPrograms	 = false ;
	policy.rejectInstallActions			 = true ;
	policy.allowRequiredDriverComponents = true ;
	policy.purpose						 = OfficialInfInspectionPurpose::REQUIRED_COLLECTOR_IMPORT ;
	// 正例とroot用途・非空・隠れた作用・不正flagsを一度ずつ独立検査します
	for( unsigned scenario = 0U; scenario < 32U; ++scenario) {
		std::string body{INF} ;			// 一caseだけの原変更です
		auto		current = policy ;	// 他caseへ用途を持ち越しません
		// 見えない別architectureと未参照節も空成功へ変換しません
		switch( scenario) {
			case 0U:	// required importだけの正例です
				break ;

			case 1U:	// 通常導入構造でnull例外を借用しません
				current.purpose = OfficialInfInspectionPurpose::STANDARD_DRIVER ;
				break ;

			case 2U:	// 明示rootへ必要importの資格を渡しません
				current.purpose = OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;
				break ;

			case 3U:	// named serviceをnullへ読み替えません
				body.replace( body.find( "AddService=,2"), 13U, "AddService=Named,2,Service") ;
				break ;

			case 4U:	// ASSOCSERVICE以外のflagsを拒否します
				body.replace( body.find( "Flags=0x00000002"), 16U, "Flags=0") ;
				break ;

			case 5U:	// extra fieldを無視しません
				body.replace( body.find( "AddService=,2"), 13U, "AddService=,2,") ;
				break ;

			case 6U:	// 選択外x86の非空DDInstallも拒否します
				body += "[Null.NTx86]\r\nAddReg=Hidden\r\n[Hidden]\r\nHKLM,Fixture,Value,0,1\r\n" ;
				break ;

			case 7U:	// hidden sourceを自身fileなしへ変換しません
				body += "[SourceDisksFiles.x86]\r\nhidden.sys=1\r\n" ;
				break ;

			case 8U:	// 未参照のコピー節も無作用へしません
				body += "[Hidden]\r\nCopyFiles=@hidden.sys\r\n" ;
				break ;

			case 9U:	// 未参照のSYS作用も省略しません
				body += "[Hidden]\r\nServiceBinary=%12%\\hidden.sys\r\n" ;
				break ;

			case 10U:	// 未参照のregistry作用も省略しません
				body += "[Hidden]\r\nAddReg=Registry\r\n[Registry]\r\nHKLM,Fixture,Value,0,1\r\n" ;
				break ;

			case 11U:	// 正式System以外を必要nullへ認定しません
				body.replace( body.find( "4d36e97d"), 8U, "4d36e972") ;
				break ;

			case 12U:	// hidden Modelsの未実在DDInstallを他baseで救済しません
				body.replace( body.find( "Device=Null,FictionalEnclosure"), 11U, "Device=Missing") ;
				break ;

			case 13U:	// hidden Servicesの二重宣言を先頭で認定しません
				body += "[Null.NTx86.Services]\r\nAddService=,2\r\n" ;
				break ;

			case 14U:	// 余分な未知Version keyをmetadataへ読み替えません
				body += "[Version]\r\nLayoutFile=hidden.inf\r\n" ;
				break ;

			case 15U:	// 実在する空x64 source宣言はfileを追加しません
				body += "[SourceDisksFiles.amd64]\r\n" ;
				break ;

			case 16U:	// 共通source宣言も明示0行だけを扱います
				body += "[SourceDisksFiles]\r\n" ;
				break ;

			case 17U:	// 明示空の共通媒体宣言を架空のfileへ変えません
				body += "[SourceDisksNames]\r\n" ;
				break ;

			case 18U:	// 正規x64媒体宣言も空であることを要求します
				body += "[SourceDisksNames.amd64]\r\n" ;
				break ;

			case 19U:	// 四標準節の同時宣言でも全節が明示空です
				body += "[SourceDisksFiles]\r\n[SourceDisksFiles.amd64]\r\n"
						"[SourceDisksNames]\r\n[SourceDisksNames.amd64]\r\n" ;
				break ;

			case 20U:	// 非空sourceをnullの自身fileなしへ変換しません
				body += "[SourceDisksFiles.amd64]\r\nhidden.sys=1\r\n" ;
				break ;

			case 21U:	// 媒体の非空宣言もnull閉集合から除外します
				body += "[SourceDisksNames]\r\n1=Fixture\r\n" ;
				break ;

			case 22U:	// 旧媒体節の元行数がどちらも0の必須補助です
				body += "[SourceDisksFiles.x86]\r\n[SourceDisksFiles.ia64]\r\n" ;
				break ;

			case 23U:	// ARM64の全Modelsが空導入を参照する必須補助INFです
				body.insert( body.find( "\r\n[Models.NTx86]"), ",NTarm64") ;
				body += "[Models.NTarm64]\r\nDevice=Null,FictionalEnclosure\r\n"
						"[SourceDisksFiles.arm64]\r\n" ;
				break ;

			case 24U:	// 未知装飾は空でも標準宣言と推定しません
				body += "[SourceDisksNames.unknown]\r\n" ;
				break ;

			case 25U:	// 通常rootは明示空でもrequired importではありません
				body += "[SourceDisksFiles.amd64]\r\n[SourceDisksNames]\r\n" ;
				current.purpose = OfficialInfInspectionPurpose::STANDARD_DRIVER ;
				break ;

			case 26U:	// collector rootへrequired importの資格を移しません
				body += "[SourceDisksFiles.amd64]\r\n[SourceDisksNames]\r\n" ;
				current.purpose = OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;
				break ;

			case 27U:	// 既required storage用途も同じ閉じたnullを要求します
				body += "[SourceDisksFiles.amd64]\r\n[SourceDisksNames]\r\n" ;
				current.purpose = OfficialInfInspectionPurpose::REQUIRED_STORAGE_IMPORT ;
				break ;

			case 28U:	// 空sourceで選択外architectureの作用を隠しません
				body += "[SourceDisksFiles.amd64]\r\n[Null.NTx86]\r\nCopyFiles=@hidden.sys\r\n" ;
				break ;

			case 30U:	// ARM64媒体の実ファイルを空として扱いません
				body += "[SourceDisksFiles.arm64]\r\nhidden.sys=1\r\n" ;
				break ;

			case 31U:	// 空のARM64媒体が元導入節のコピーを隠さないことを確認します
				body.insert( body.find( "\r\n[Models.NTx86]"), ",NTarm64") ;
				body += "[Models.NTarm64]\r\nDevice=Null,FictionalEnclosure\r\n"
						"[SourceDisksFiles.arm64]\r\n"
						"[Null.NTarm64]\r\nCopyFiles=@hidden.sys\r\n"
						"[Null.NTarm64.Services]\r\nAddService=,2\r\n" ;
				break ;

			default:	// 必要構成を許可しないpolicyへ空source例外を渡しません
				body += "[SourceDisksFiles.amd64]\r\n[SourceDisksNames]\r\n" ;
				current.allowRequiredDriverComponents = false ;
				break ;
		}

		OfficialDownloadWorkspace workspace ;	// INF/CAT以外を持たないownerです
		DRIVERCRATE_EXPECT( context,
						   workspace.initialize( L"required-null-test", 3570U + scenario) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "not-signed")) ;
		const std::array   entries{OfficialZipEntry{L"sample.inf", body.size()},
								   OfficialZipEntry{L"sample.cat", 10U}} ;	// 欠損SYSは補完しません
		OfficialInfPackage package ;										// 必須importだけの出力です
		const auto error = inspectOfficialInfPackage( workspace, entries, L"sample.inf", current,
													 package) ;	// 実readerです
		DRIVERCRATE_EXPECT( context, (error == 0) ==
										(scenario == 0U || (scenario >= 15U && scenario <= 19U) ||
										 scenario == 22U || scenario == 23U || scenario == 27U)) ;
		// 正例でも元ID/kindの読取とCAT検査を省略しません
		if( error == 0) {
			DRIVERCRATE_EXPECT( context, package.requiredNullCompanion &&
											package.sourceFiles.empty() &&
											package.inspectionPurpose == current.purpose) ;
			OfficialInfPublishedIdentity identity ;	// 原field由来の区分だけです
			DRIVERCRATE_EXPECT( context,
							   readOfficialInfPublishedIdentity( workspace, package, identity) == 0) ;
			DRIVERCRATE_EXPECT( context, identity.models.size() == 1U) ;
			// 原bare第一IDをCOMPATIBLEへ変更しません
			if( identity.models.size() == 1U) {
				DRIVERCRATE_EXPECT( context,
								   identity.models.front().hardwareIds ==
										   std::vector<std::wstring>{L"FictionalEnclosure"} &&
									   identity.models.front().compatibleIds ==
										   std::vector<std::wstring>{L"*FictionalCompatible"}) ;
			}

			DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, package) != 0) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 正規Stringsの実空valueだけを許し空作用・不正locale・非空禁止作用を拒否します
 * @param[in,out] context 実SetupAPIと通常package検査の正負結果を集計します
 */
//------------------------------------------------------------------------------
void testEmptyStringsMetadata( TestContext &context)
{
	auto policy					= POLICY ;	// 元通常構造に実作用検査を必ず加えます
	policy.rejectInstallActions = true ;
	constexpr std::array<std::string_view, 14U> DECLARATIONS{
		"[Strings]\r\nClassName=\"\"\r\n",
		"[Strings.0411]\r\nClassName=\"\"\r\n",
		"[sTrInGs.0409]\r\nClassName=\"\"\r\n",
		"[Strings.0a0F]\r\nClassName=\"\"\r\n",
		"[Strings.041]\r\nClassName=\"\"\r\n",
		"[Strings.GGGG]\r\nClassName=\"\"\r\n",
		"[Strings.04110]\r\nClassName=\"\"\r\n",
		"[Strings.0411.Extra]\r\nClassName=\"\"\r\n",
		"[Install.NT]\r\nEmpty=\"\"\r\n",
		"[Version]\r\nEmpty=\"\"\r\n",
		"[Strings]\r\nRunPreSetupCommands=\"\"\r\n",
		"[Strings.0411]\r\nMetadata=coinstallers32\r\n",
		"[SourceDisksNames]\r\nEmpty=\"\"\r\n",
		"[Strings.]\r\nClassName=\"\"\r\n"} ;	// 期待は節の役割と元literalから固定します
	// 各caseを同じ正常packageへ一つずつ追加し、他caseの結果を引き継ぎません
	for( std::size_t scenario = 0U; scenario < DECLARATIONS.size(); ++scenario) {
		const std::string body =
			std::string{VALID_INF} + std::string{DECLARATIONS[scenario]} ;	// 独立INFです
		OfficialDownloadWorkspace workspace ;								// 架空fileだけの所有領域です
		DRIVERCRATE_EXPECT( context,
						   workspace.initialize( L"empty-strings-test", 3990U + scenario) == 0) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "not-signed")) ;
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.sys", "driver")) ;
		const std::array   entries{OfficialZipEntry{L"sample.inf", body.size()},
								   OfficialZipEntry{L"sample.cat", 10U},
								   OfficialZipEntry{L"sample.sys", 6U}} ;	// 全必要memberです
		OfficialInfPackage package ;										// 署名資格を持たない構造結果です
		const auto error = inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy,
													 package) ;	// 実装を通します
		DRIVERCRATE_EXPECT( context, (error == 0) == (scenario < 4U)) ;
		// 正例の空metadataから偽CATの署名成功を作りません
		if( error == 0) {
			DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, package) != 0) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 人工generic INFでrequested V3の八Server tupleと既client二点を実readerへ渡します
 * @param[in,out] context 同hash/原節/全ID順序とguard拒否を集計する結果です
 * @note 一つのgeneric節はproduct/build弁別や実Server/署名/現在OS閉包の一般対応を証明しません
 */
//------------------------------------------------------------------------------
void testRequestedServerModels( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 試験新所有の人工INFだけを持ちます
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"requested-server-models", 3891U) == 0) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", VALID_INF)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "not-signed")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.sys", "driver")) ;
	const std::array   entries{OfficialZipEntry{L"sample.inf", VALID_INF.size()},
							   OfficialZipEntry{L"sample.cat", 10U},
							   OfficialZipEntry{L"sample.sys", 6U}} ;	// 元閉fileです
	OfficialInfPackage package ;										// 前段の現在OS guardを維持した構造結果です
	DRIVERCRATE_EXPECT( context, inspectOfficialInfPackage( workspace, entries, L"sample.inf", POLICY,
														  package) == 0) ;
	std::wstring digest ;	// 期待hashは人工原byteから直接計算します
	DRIVERCRATE_EXPECT( context, computeDriverContainerSha256( VALID_INF, digest) == 0) ;
	// 四版とDC/Serverを独立に実Windowsへ渡し、V2/currentOS fallbackを使いません
	for( const auto build : {14393U, 17763U, 20348U, 26100U}) {
		// 同buildでもproduct1をServerと分類しません
		for( const auto product : {2U, 3U}) {
			OfficialInfModelsPlatform platform ;	// 全六fieldを明示します
			platform.majorVersion		   = 10U ;
			platform.minorVersion		   = 0U ;
			platform.buildNumber		   = build ;
			platform.processorArchitecture = PROCESSOR_ARCHITECTURE_AMD64 ;
			platform.productType		   = static_cast<std::uint8_t>( product) ;
			platform.suiteMask			   = 0U ;
			OfficialInfPublishedIdentity identity ;	// 導入資格を持たない公開metadataです
			DRIVERCRATE_EXPECT( context, readOfficialInfPublishedIdentityForPlatform(
											workspace, package, platform, digest, identity) == 0) ;
			DRIVERCRATE_EXPECT( context, identity.infSha256 == digest &&
											identity.classGuid ==
												L"{4d36e972-e325-11ce-bfc1-08002be10318}" &&
											identity.models.size() == 1U) ;
			// 一節内の原kind/case/orderを固定literal期待へ照合します
			if( identity.models.size() == 1U) {
				DRIVERCRATE_EXPECT( context,
								   identity.models.front().modelSection == L"Models.NTamd64" &&
									   identity.models.front().hardwareIds ==
										   std::vector<std::wstring>{L"PCI\\VEN_1234&DEV_5678"} &&
									   identity.models.front().compatibleIds ==
										   std::vector<std::wstring>{L"PCI\\VEN_1234"}) ;
			}
		}
	}

	// 既client二点の成功をServer tupleの拡張で失いません
	for( const auto build : {19045U, 26100U}) {
		OfficialInfModelsPlatform platform ;	// 明示workstation入力です
		platform.buildNumber = build ;
		platform.productType = VER_NT_WORKSTATION ;
		OfficialInfPublishedIdentity identity ;	// generic同節です
		DRIVERCRATE_EXPECT( context,
						   readOfficialInfPublishedIdentityForPlatform( workspace, package, platform,
																	   digest, identity) == 0 &&
							   identity.infSha256 == digest && identity.models.size() == 1U) ;
	}

	// 一条件だけを変えた未対応tuple/別hashは実metadataを成功へ補完しません
	for( unsigned mode = 0U; mode < 6U; ++mode) {
		OfficialInfModelsPlatform platform ;	// Server正例からの独立負例です
		platform.buildNumber = 26100U ;
		platform.productType = VER_NT_SERVER ;
		// 未知productをhost!=1のshortcutで通しません
		if( mode == 0U) {
			platform.productType = 4U ;
		}

		// suite0観測を非0へ拡張しません
		if( mode == 1U) {
			platform.suiteMask = 2U ;
		}

		// 未列挙buildを推測しません
		if( mode == 2U) {
			platform.buildNumber = 26200U ;
		}

		// major/minorを省略しません
		if( mode == 3U) {
			platform.minorVersion = 1U ;
		}

		// ARM64成功を作りません
		if( mode == 4U) {
			platform.processorArchitecture = PROCESSOR_ARCHITECTURE_ARM64 ;
		}

		OfficialInfPublishedIdentity identity ;	// 拒否時空です
		DRIVERCRATE_EXPECT( context,
						   readOfficialInfPublishedIdentityForPlatform(
							   workspace, package, platform,
							   mode == 5U ? std::wstring( 64U, L'0') : digest, identity) != 0 &&
							   identity.models.empty()) ;
	}

	DRIVERCRATE_EXPECT( context, verifyOfficialFileMetadata( workspace.path( L"sample.inf"),
														   {VALID_INF.size(), digest}) == 0) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 公式標準INF driver packageの構造検証境界を検証する。公式標準INF driver package単体試験を実行する。正常構造、policy、欠落、
 *        architecture、混入拒否試験を順番に実行する
 * @param[in,out] context Assertion件数と失敗内容の集計先
 */
//------------------------------------------------------------------------------
void runOfficialDriverPackageTests( TestContext &context)
{
	testRequiredRegistryOnlyStructure( context) ;
	testRequestedServerModels( context) ;
	testOpaqueNativeModels( context) ;
	testModelIdDeduplication( context) ;
	testScopedModelsEvidence( context) ;
	testScopedModelsInventory( context) ;
	testMtdStorageEffects( context) ;
	testStorageServicePreserveString( context) ;
	testDriverStoreAuxiliaryCommandSyntax( context) ;
	testStorageEventCopyDestination( context) ;
	testStorageAuxiliaryServiceEffects( context) ;
	testSelectedScsiFeatureScore( context) ;
	testCollectorMtdStructure( context) ;
	testCollectorStorageStructure( context) ;
	testSelectedMediumChangerStructure( context) ;
	testCollectorHdcStorageStructure( context) ;
	testCollectorHdcStorageEffects( context) ;
	testStorageLoadOrder( context) ;
	testStandardTapeDriveStructure( context) ;
	testRequiredNullCollectorImport( context) ;
	testEmptyStringsMetadata( context) ;
	testStandardComponentActions( context) ;
	testCollectorSystemServiceBudget( context) ;
	testInheritedSystemContent( context) ;
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
	testCollectionInventoryBudget( context) ;
	testCollectionInventoryLineBudget( context) ;
	testScopedWirelessParameterLabels( context) ;
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
