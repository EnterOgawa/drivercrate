//------------------------------------------------------------------------------
/**
 * @file official_driver_closure_tests.cpp
 * @brief 公式driver package監査単体試験実装。
 * @version 01.09.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX候補発行と指定導入の共通接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX内容・適用性・report fixtureを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel導入fixture tagを上限内へ修正。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel複数device導入fixtureを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel候補公開fixtureを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel指定導入の状態変化fixtureを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel監査fixtureのworkspace tagを修正。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernet適用性・report fixture追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernet監査拒否fixture追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  共通監査とBroadcom接続試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  取得後差替え拒否試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  CAB閉包抽出fixture追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  CAB cleanup継続fixture追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  一段nested CAB fixture追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  閉包抽出失敗診断追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  外部writer fixture失敗guard追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASUS全INF内容監査fixture追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASUS PnP／Rank監査fixture追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASUS導入前再検証fixture追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  共通内容入力・個別検査・八軸結合のfixture追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  未解決依存と署名の独立観測・表示保留を検証。
 * Ver.01.02.01 Shunji Ogawa  2026/09/15  任意同梱物と全体改変失敗の区別を明示検証。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  Intel Windows 11の取得許可から共通検査までを接続。
 * Ver.01.04.00 Shunji Ogawa  2026/10/05  保守四軸と従来作用拒否・不正署名・取消しを検証。
 * Ver.01.05.00 Shunji Ogawa  2026/10/05  保守EXE限定受理と通常入口・他拡張子拒否を検証。
 * Ver.01.06.00 Shunji Ogawa  2026/10/05  通常二構文受理と署名・作用・欠損・改変拒否を検証。
 * Ver.01.07.00 Shunji Ogawa  2026/10/05  選択導入作用・明示参照の有限棚卸しを検証。
 * Ver.01.08.00 Shunji Ogawa  2026/10/05  拡張容量の境界・超過と旧境界超過の正例を追加。
 * Ver.01.09.00 Shunji Ogawa  2026/10/06  参照元文脈・未解釈不足・最大量の架空検証を追加。
 * Ver.01.09.01 Shunji Ogawa  2026/10/07  必須byte欠落とroot署名の独立判定回帰を採用契約へ整合。
 * </pre>
 *
 * @note Minizで生成した架空ZIPを使用し、INF、CAT、参照fileだけが保護workspaceへ抽出されることを検証します。
 */
//------------------------------------------------------------------------------

#include "official_driver_closure_tests.h"

#include "core/official_source_policy.h"
#include "core/candidate_assessment.h"
#include "platform/common_driver_package.h"
#include "platform/driver_store_provider.h"
#include "core/provider_registry.h"
#include "platform/asix_preparation.h"
#include "platform/asus_driver_package_audit.h"
#include "platform/broadcom_update_provider.h"
#include "platform/official_cab.h"
#include "platform/official_delegated_package_inspection.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_closure.h"
#include "platform/official_driver_package.h"
#include "platform/official_driver_package_audit.h"
#include "platform/official_file_verifier.h"
#include "platform/official_prepared_audit_report.h"
#include "platform/official_release_discovery_provider.h"
#include "test_framework.h"

#include <WinTrust.h>
#include <Windows.h>
#include <miniz.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 試験data定義。
//------------------------------------------------------------------------------

/**
 * @brief Driver closure検証用の架空ZIPへ格納する名前と内容を指定する。
 */
struct ZipFixtureEntry {
	/// ZIP central directoryへ保存するASCII相対path。
	std::string_view path ;
	/// 本試験function中有効な非所有content先頭。
	const void		*data{} ;
	/// Contentのbyte数。
	std::size_t		 size{} ;
} ;

/** @brief Intel Ethernet archive fixture一件の監査観測値を保持する。 */
struct IntelEthernetAuditFixtureOutcome {
	/// 監査API全体のHRESULT。
	NativeError				   auditError{} ;
	/// 内容・適用性の独立した監査結果。
	OfficialDriverPackageAudit audit ;
	/// 後段PnP／rank callbackの呼出し件数。
	std::size_t				   rankCallCount{} ;
} ;

/** @brief ASIX archive fixture一件の内容監査と後段PnP呼出しを保持する。 */
struct AsixAuditFixtureOutcome {
	/// 監査API全体のHRESULT。
	NativeError				   auditError{} ;
	/// 内容・適用性を分離した監査結果。
	OfficialDriverPackageAudit audit ;
	/// 内容合格後のPnP／rank callback呼出し件数。
	std::size_t				   rankCallCount{} ;
} ;

/** @brief Intel Ethernet指定導入executorへ渡す一scan分の架空保持物を所有する。 */
struct IntelEthernetPreparedInstallFixture {
	/// 外側取得fileを所有する保護領域。
	OfficialDownloadWorkspace			   acquisitionWorkspace ;
	/// 外側fileのsize／hash snapshot。
	OfficialAcquisitionResult			   acquisition ;
	/// 一つの架空INF metadataと保護領域を所有する監査済みpackage群。
	std::vector<OfficialAuditedInfPackage> auditedPackages ;
	/// 候補ID別のINF／binding routing。
	IntelEthernetPreparedInstallTargets	   targets ;
	/// 利用者選択を模した候補ID群。
	std::vector<std::wstring>			   identities ;
} ;

/**
 * @brief CAB cleanup callbackの呼出し順とfault注入位置を保持する。
 */
struct CabDiscardFixture {
	/// Callbackが受け取ったpath列。
	std::array<std::wstring_view, 3> observedPaths ;
	/// 完了したcallback呼出し数。
	std::size_t						 callCount{} ;
	/// HRESULTを返す1始まり呼出し位置。
	std::size_t						 failingCall{1U} ;
	/// 例外を投げる1始まり呼出し位置。
	std::size_t						 throwingCall{2U} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief CAB cleanup試験用に失敗と例外を順番に注入する。
 *
 * 指定例外位置では意図的に例外を投げ、production境界が後続pathを処理することを検証可能にする。
 *
 * @param[in,out] context `CabDiscardFixture`を指す非所有値。
 * @param[in] relativePath 今回破棄対象となる架空相対path。
 * @return 指定失敗位置は`E_ACCESSDENIED`、それ以外は0。
 */
//------------------------------------------------------------------------------
NativeError discardFixtureFile( void *const context, const std::wstring_view relativePath)
{
	// callbackのfixtureがない場合は無効な状態を参照せず診断を返す。
	if( context == nullptr) {
		return static_cast<NativeError>( E_POINTER) ;
	}

	auto *const fixture = static_cast<CabDiscardFixture *>( context) ;	// 呼出側が保証する試験状態。
	// 観測bufferの範囲に収まる呼出しだけを保存する。
	if( fixture->callCount < fixture->observedPaths.size()) {
		fixture->observedPaths[fixture->callCount] = relativePath ;
	}

	++fixture->callCount ;
	// Production cleanupのcatch-allと後続処理を検証する意図的な例外。
	if( fixture->callCount == fixture->throwingCall) {

		throw static_cast<NativeError>( E_FAIL) ;
	}

	return fixture->callCount == fixture->failingCall ? static_cast<NativeError>( E_ACCESSDENIED)
													  : 0 ;
}

constexpr std::array ACCEPTED_CLASSES{std::wstring_view( L"Net")} ;	// 試験許可class。
constexpr std::array ACCEPTED_PROVIDERS{							// 試験許可Provider。
										std::wstring_view( L"Fictional Device Corporation")} ;
constexpr std::array ACCEPTED_SIGNATURES{	// 試験許可INF signature。
										 std::wstring_view( L"$Windows NT$")} ;

constexpr OfficialDriverClosurePolicy POLICY{
	.zipPolicy = {1024U * 1024U, 256U * 1024U, 512U * 1024U, 32U},
	.cabPolicy = {1024U * 1024U, 256U * 1024U, 512U * 1024U, 32U},
	.infPolicy =
		{
			.maximumHardwareIds = 16U,
			.maximumSourceFiles = 16U,
			.acceptedClasses	= ACCEPTED_CLASSES,
			.acceptedProviders	= ACCEPTED_PROVIDERS,
			.acceptedSignatures = ACCEPTED_SIGNATURES,
		},
	.maximumInfCount		   = 4U,
	.maximumClosureFiles	   = 16U,
	.maximumClosureBytes	   = 256U * 1024U,
	.maximumExpansionRatio	   = 100U,
	.maximumNestedArchiveDepth = 1U,
} ; // 架空packageに適用する小さな有限policy。

constexpr std::string_view VALID_INF =
	"[Version]\r\n"
	"Signature=\"$Windows NT$\"\r\n"
	"Class=Net\r\n"
	"ClassGuid={4d36e972-e325-11ce-bfc1-08002be10318}\r\n"
	"Provider=%ProviderName%\r\n"
	"DriverVer=09/04/2026,2.0.0.1\r\n"
	"CatalogFile=sample.cat\r\n"
	"[Manufacturer]\r\n"
	"%ProviderName%=Models,NTamd64\r\n"
	"[Models.NTamd64]\r\n"
	"%DeviceName%=Install,PCI\\VEN_1234&DEV_5678\r\n"
	"[SourceDisksNames.amd64]\r\n"
	"1=%DiskName%,,,\r\n"
	"[SourceDisksFiles.amd64]\r\n"
	"sample.sys=1\r\n"
	"[Install.NT]\r\n"
	"CopyFiles=DriverCopy\r\n"
	"[DriverCopy]\r\n"
	"sample.sys\r\n"
	"[Strings]\r\n"
	"ProviderName=\"Fictional Device Corporation\"\r\n"
	"DeviceName=\"Fictional Network Device\"\r\n"
	"DiskName=\"Fictional Driver Disk\"\r\n" ;	// 標準x64 driver閉包を持つ架空INF。

constexpr std::string_view PROGRAM_INF =
	"[Version]\r\n"
	"Signature=\"$Windows NT$\"\r\n"
	"Class=Net\r\n"
	"ClassGuid={4d36e972-e325-11ce-bfc1-08002be10318}\r\n"
	"Provider=%ProviderName%\r\n"
	"DriverVer=09/04/2026,2.0.0.2\r\n"
	"CatalogFile=sample.cat\r\n"
	"[Manufacturer]\r\n"
	"%ProviderName%=Models,NTamd64\r\n"
	"[Models.NTamd64]\r\n"
	"%DeviceName%=Install,PCI\\VEN_1234&DEV_5678\r\n"
	"[SourceDisksNames.amd64]\r\n"
	"1=%DiskName%,,,\r\n"
	"[SourceDisksFiles.amd64]\r\n"
	"sample.sys=1\r\n"
	"setup.exe=1\r\n"
	"[Install.NT]\r\n"
	"CopyFiles=DriverCopy\r\n"
	"[DriverCopy]\r\n"
	"sample.sys\r\n"
	"setup.exe\r\n"
	"[Strings]\r\n"
	"ProviderName=\"Fictional Device Corporation\"\r\n"
	"DeviceName=\"Fictional Network Device\"\r\n"
	"DiskName=\"Fictional Driver Disk\"\r\n" ;	// EXEを閉包へ参照する拒否用INF。

constexpr std::string_view COMMAND_INF =
	"[Version]\r\n"
	"Signature=\"$Windows NT$\"\r\n"
	"Class=Net\r\n"
	"ClassGuid={4d36e972-e325-11ce-bfc1-08002be10318}\r\n"
	"Provider=%ProviderName%\r\n"
	"DriverVer=09/04/2026,2.0.0.3\r\n"
	"CatalogFile=sample.cat\r\n"
	"[Manufacturer]\r\n"
	"%ProviderName%=Models,NTamd64\r\n"
	"[Models.NTamd64]\r\n"
	"%DeviceName%=Install,PCI\\VEN_1234&DEV_5678\r\n"
	"[SourceDisksNames.amd64]\r\n"
	"1=%DiskName%,,,\r\n"
	"[SourceDisksFiles.amd64]\r\n"
	"sample.sys=1\r\n"
	"[Install.NT]\r\n"
	"CopyFiles=DriverCopy\r\n"
	"RunPostSetupCommands=Commands\r\n"
	"[DriverCopy]\r\n"
	"sample.sys\r\n"
	"[Commands]\r\n"
	"sample.exe\r\n"
	"[Strings]\r\n"
	"ProviderName=\"Fictional Device Corporation\"\r\n"
	"DeviceName=\"Fictional Network Device\"\r\n"
	"DiskName=\"Fictional Driver Disk\"\r\n" ;	// 実行directiveを持つ拒否用INF。

constexpr std::string_view X86_INF =
	"[Version]\r\n"
	"Signature=\"$Windows NT$\"\r\n"
	"Class=Net\r\n"
	"ClassGuid={4d36e972-e325-11ce-bfc1-08002be10318}\r\n"
	"Provider=%ProviderName%\r\n"
	"DriverVer=09/04/2026,2.0.0.4\r\n"
	"CatalogFile=sample.cat\r\n"
	"[Manufacturer]\r\n"
	"%ProviderName%=Models,NTx86\r\n"
	"[Models.NTx86]\r\n"
	"%DeviceName%=Install,PCI\\VEN_1234&DEV_5678\r\n"
	"[SourceDisksNames.x86]\r\n"
	"1=%DiskName%,,,\r\n"
	"[SourceDisksFiles.x86]\r\n"
	"sample.sys=1\r\n"
	"[Install.NT]\r\n"
	"CopyFiles=DriverCopy\r\n"
	"[DriverCopy]\r\n"
	"sample.sys\r\n"
	"[Strings]\r\n"
	"ProviderName=\"Fictional Device Corporation\"\r\n"
	"DeviceName=\"Fictional Network Device\"\r\n"
	"DiskName=\"Fictional Driver Disk\"\r\n" ;	// x64 sectionを持たない拒否用INF。

constexpr std::string_view CATALOG = "fictional catalog" ;	// 架空CAT byte列。
constexpr std::string_view DRIVER  = "fictional driver" ;	// 架空SYS byte列。
constexpr std::string_view SETUP   = "fictional setup" ;	// 閉包選択対象外のEXE byte列。

// Windows MakeCabで架空INF、CAT、SYSを格納したdriver閉包CAB fixture。
constexpr auto			   DRIVER_CLOSURE_CAB = std::to_array<unsigned char>(
	{0x4D, 0x53, 0x43, 0x46, 0x00, 0x00, 0x00, 0x00, 0xEE, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				 0x2C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00,
				 0x9C, 0x14, 0x00, 0x00, 0x92, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x19, 0x02, 0x00, 0x00,
				 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x5D, 0xF1, 0x85, 0x20, 0x00, 0x64, 0x72, 0x69, 0x76,
				 0x65, 0x72, 0x5C, 0x73, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x69, 0x6E, 0x66, 0x00, 0x12, 0x00,
				 0x00, 0x00, 0x19, 0x02, 0x00, 0x00, 0x00, 0x00, 0x24, 0x5D, 0xF1, 0x85, 0x20, 0x00, 0x64, 0x72,
				 0x69, 0x76, 0x65, 0x72, 0x5C, 0x73, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x61, 0x74, 0x00,
				 0x11, 0x00, 0x00, 0x00, 0x2B, 0x02, 0x00, 0x00, 0x00, 0x00, 0x24, 0x5D, 0xF1, 0x85, 0x20, 0x00,
				 0x64, 0x72, 0x69, 0x76, 0x65, 0x72, 0x5C, 0x73, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x73, 0x79,
				 0x73, 0x00, 0x3D, 0x75, 0x0F, 0x31, 0x54, 0x01, 0x3C, 0x02, 0x43, 0x4B, 0x55, 0x91, 0x4D, 0x8F,
				 0x82, 0x30, 0x10, 0x86, 0xEF, 0xFD, 0x15, 0x84, 0xE8, 0x9E, 0x00, 0x5B, 0x40, 0xD4, 0x43, 0x4F,
				 0xA0, 0x1B, 0x0F, 0x12, 0x13, 0x8D, 0x7B, 0x60, 0x89, 0xA9, 0xA5, 0x9A, 0x46, 0xA4, 0xA6, 0x05,
				 0x8D, 0xD9, 0xEC, 0x7F, 0xDF, 0xF2, 0xB1, 0x8A, 0xE9, 0x65, 0x66, 0xFA, 0xF4, 0x9D, 0x77, 0x3A,
				 0xC9, 0x8E, 0x49, 0xC5, 0x45, 0x91, 0x82, 0x0D, 0x3F, 0x15, 0xA4, 0xAC, 0x24, 0xC3, 0xE6, 0xE0,
				 0x8B, 0x17, 0x99, 0xB8, 0x2B, 0x23, 0xDE, 0x0E, 0x4C, 0x10, 0xE6, 0x44, 0x29, 0x1C, 0xB3, 0xB2,
				 0x8D, 0x3E, 0x2B, 0x9E, 0xE1, 0x1F, 0x3F, 0xF3, 0x02, 0x36, 0x9B, 0xB8, 0x36, 0xF3, 0xDC, 0xB1,
				 0x8D, 0x10, 0x65, 0xF6, 0xE1, 0x48, 0x91, 0x0D, 0xA7, 0x10, 0xBA, 0x07, 0x86, 0xA0, 0x87, 0xA6,
				 0xBF, 0x60, 0x2D, 0xC5, 0x8D, 0x67, 0x4C, 0xE2, 0xE1, 0x7F, 0x14, 0x93, 0x0B, 0x1B, 0x82, 0x48,
				 0xF2, 0x1B, 0x93, 0xBA, 0x35, 0x86, 0xB3, 0x11, 0xF4, 0x47, 0x2E, 0x74, 0x03, 0xCB, 0x75, 0xA0,
				 0x3E, 0x08, 0x84, 0xA4, 0x24, 0xB9, 0x38, 0x2D, 0x78, 0xCE, 0xB0, 0x22, 0x97, 0x6B, 0xCE, 0x1C,
				 0x4A, 0x4A, 0x90, 0xAC, 0x48, 0x51, 0x1D, 0x09, 0xAD, 0x2D, 0xCA, 0x14, 0xBC, 0x2B, 0xE2, 0x95,
				 0xC8, 0x58, 0xAE, 0xAC, 0x78, 0x4B, 0x2E, 0x59, 0xE0, 0x6B, 0xB8, 0xC9, 0x9D, 0x2E, 0xD7, 0x78,
				 0xC4, 0x6E, 0x9C, 0xB2, 0x16, 0x5E, 0x16, 0x4A, 0xB7, 0xC8, 0xAD, 0x75, 0xB8, 0xFC, 0xDE, 0xCD,
				 0xE3, 0x3D, 0x72, 0x3D, 0xFF, 0x23, 0x9A, 0xEF, 0xF6, 0xE3, 0x60, 0x32, 0x05, 0xC9, 0x46, 0x54,
				 0x92, 0xB2, 0x88, 0xAB, 0xB3, 0xAA, 0x79, 0xE5, 0x74, 0x1A, 0x08, 0x0F, 0xEB, 0x62, 0xA3, 0x61,
				 0x59, 0xD6, 0x1B, 0x58, 0xBB, 0x7D, 0x82, 0x9D, 0x6B, 0xF5, 0x50, 0x18, 0x81, 0xA4, 0xEB, 0xA6,
				 0xBD, 0xA4, 0x20, 0x14, 0xD7, 0x47, 0x83, 0xE2, 0xF6, 0x0B, 0xEA, 0x1C, 0x24, 0xAF, 0xB8, 0xFF,
				 0x56, 0xEB, 0x97, 0x92, 0x17, 0x27, 0x95, 0x82, 0xFE, 0xAC, 0xD8, 0x5C, 0x70, 0x5A, 0xEA, 0x95,
				 0x91, 0xDC, 0x68, 0x87, 0x32, 0x42, 0x21, 0xAF, 0x42, 0x92, 0xBA, 0x68, 0x82, 0xD7, 0xA0, 0x7D,
				 0x52, 0xAF, 0xEF, 0x2E, 0xE4, 0xB9, 0x7B, 0xA1, 0xA9, 0x6E, 0x90, 0x37, 0xB5, 0xC6, 0x86, 0x51,
				 0x5F, 0x99, 0xE0, 0xF8, 0x2C, 0xD3, 0x76, 0x1F, 0xBD, 0x4A, 0xD6, 0x80, 0xE0, 0x0F}) ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 架空entry群からmemory ZIPを生成する。
 *
 * Test process内だけでMiniz writerを使用し、外部toolに依存しない。
 *
 * @param[in] sourceEntries ZIPへ追加する架空entry群。
 * @param[out] archive 成功時のZIP container全byte列。
 * @return Central directoryを含むZIPを生成できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool createZipFixture( const std::span<const ZipFixtureEntry> sourceEntries,
									std::vector<std::byte>				  &archive)
{
	archive.clear() ;
	// entryのないZIP fixtureは作成対象にしない。
	if( sourceEntries.empty()) {
		return false ;
	}

	mz_zip_archive writer{} ;	// 終了処理が必要なMiniz writer状態。
	mz_zip_zero_struct( &writer) ;
	// ZIP writerを初期化できなければfixtureの生成を開始しない。
	if( mz_zip_writer_init_heap( &writer, 0, 0) == 0) {
		return false ;
	}

	// 入力順の全架空entryを圧縮してwriterへ追加する。
	for( const ZipFixtureEntry &entry : sourceEntries) {
		// entry内容がない場合や追加失敗時はwriterを終了して部分archiveを捨てる。
		if( entry.data == nullptr ||
		   mz_zip_writer_add_mem( &writer, std::string( entry.path).c_str(), entry.data, entry.size,
								 MZ_BEST_COMPRESSION) == 0) {
			mz_zip_writer_end( &writer) ;
			return false ;
		}
	}

	void	   *bytes{} ;	// Miniz allocatorが所有する完成ZIPの先頭。
	std::size_t size{} ;	// 完成ZIPのbyte数。
	// 空または未確定のZIPを拒否し、writerの資源を解放する。
	if( mz_zip_writer_finalize_heap_archive( &writer, &bytes, &size) == 0 || bytes == nullptr ||
	   size == 0) {
		mz_zip_writer_end( &writer) ;
		return false ;
	}

	try {
		const auto *beginning = static_cast<const std::byte *>( bytes) ;	// ZIP byte列の非所有先頭。
		archive.assign( beginning, beginning + size) ;
	} catch( ...) {
		mz_free( bytes) ;
		mz_zip_writer_end( &writer) ;
		throw ;
	}

	mz_free( bytes) ;
	return mz_zip_writer_end( &writer) != 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Memory archiveを保護workspaceの新規fileへ保存する。
 *
 * G11-Bが固定した入力fileと同じidentityを試験内で構成する。
 *
 * @param[in,out] workspace 入力ZIPを所有する初期化済み領域。
 * @param[in] name Workspace基準の安全なfile名。
 * @param[in] archive 書き込むZIPの全byte列。
 * @param[out] sha256 書込み完了fileの64桁SHA-256。
 * @return 全byte書込みとhash計算の成功時は0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError storeArchive( OfficialDownloadWorkspace	   &workspace,
									   const std::wstring_view			name,
									   const std::span<const std::byte> archive,
									   std::wstring					   &sha256)
{
	HANDLE		file{INVALID_HANDLE_VALUE} ;				// Workspaceが追跡する新規入力file handle。
	NativeError error = workspace.createFile( name, file) ;	// 作成結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	std::size_t offset{} ;	// 次に書き込むarchive byte位置。
	// DWORDで表現できる有限chunkでarchive全体を書き込む。
	while( offset < archive.size()) {
		const std::size_t remaining = archive.size() - offset ;	// 未書込みbyte数。
		const DWORD		  requested = static_cast<DWORD>(
			  std::min<std::size_t>( remaining, 1024U * 1024U)) ;	// 今回書き込むbyte数。
		DWORD	   written{} ;										// WriteFileが実際に書き込んだbyte数。
		const BOOL writeSucceeded =
			// API結果。
			WriteFile( file, archive.data() + offset, requested, &written, nullptr) ;
		// 失敗または短い書込みではarchive保存を中断し、原因を保持する。
		if( writeSucceeded == FALSE || written != requested) {
			const DWORD writeError =
				// 失敗理由。
				writeSucceeded == FALSE ? GetLastError() : ERROR_WRITE_FAULT ;
			error = static_cast<NativeError>( HRESULT_FROM_WIN32( writeError)) ;
			break ;
		}

		offset += written ;
	}

	// 既存の書込み診断を上書きせず、closeだけが失敗した場合に記録する。
	if( CloseHandle( file) == FALSE && error == 0) {
		error = static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
	}

	return error != 0 ? error : computeFileSha256( workspace.path( name), sha256) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実driverや実PnPを使用せず、Intel固有adapterから共通executorまでのrouting、再検証および結果分離を決定的に検証できる入力を作る。
 *
 * @param[out] fixture 成功時に外側file、監査済みINFおよびbindingを所有する。
 * @param[in] deviceCount 生成するdevice／候補数。1または2。
 * @return 保護領域、外側fileおよび指定数のroutingを構成できた場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool initializeIntelEthernetPreparedInstallFixture(
	IntelEthernetPreparedInstallFixture &fixture, const std::size_t deviceCount)
{
	// 本fixtureの単一・部分失敗用途を超える入力を構成しない。
	if( deviceCount == 0U || deviceCount > 2U) {
		return false ;
	}

	constexpr std::array OUTER_BYTES{std::byte{0x49}, std::byte{0x4E}, std::byte{0x54},
									 std::byte{0x43}} ;	// 実行形式ではない架空の外側file。
	// 外側fileの所有権を確立できない場合はfixtureを公開しない。
	if( fixture.acquisitionWorkspace.initialize( L"intel-install-input", 821U) != 0) {
		return false ;
	}

	std::wstring outerSha256 ;	// 保存した架空外側fileの実測SHA-256。
	// 不完全fileを取得済みsnapshotとして扱わない。
	if( storeArchive( fixture.acquisitionWorkspace, L"payload.zip", OUTER_BYTES, outerSha256) != 0) {
		return false ;
	}

	fixture.acquisition = {
		.state					 = OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
		.scanSessionId			 = 821U,
		.acquisitionId			 = 1U,
		.providerId				 = std::wstring( INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID),
		.resourceId				 = std::wstring( OFFICIAL_PAYLOAD_RESOURCE_ID),
		.inspectionPath			 = fixture.acquisitionWorkspace.path( L"payload.zip"),
		.byteCount				 = static_cast<std::uint64_t>( OUTER_BYTES.size()),
		.sha256					 = outerSha256,
		.publishedSha256Verified = true,
	} ;

	OfficialAuditedInfPackage audited ;	// 一件の再検証対象となる架空監査済みINF閉包。
	audited.workspace = std::make_unique<OfficialDownloadWorkspace>() ;
	// INF閉包の保護領域を確立できない場合はroutingを発行しない。
	if( audited.workspace->initialize( L"intel-install-inf", 821U) != 0) {
		return false ;
	}

	audited.closure.packages.push_back( {
		.infRelativePath	 = L"driver\\fictional.inf",
		.catalogRelativePath = L"driver\\fictional.cat",
		.className			 = L"Net",
		.providerName		 = L"Intel",
		.driverDate			 = L"09/08/2026",
		.driverVersion		 = L"2.0.0.0",
	}) ;
	audited.profile = OfficialDriverAuditProfile::INTEL_ETHERNET_SERVER2025 ;
	fixture.auditedPackages.push_back( std::move( audited)) ;

	const OfficialDriverRankAudit rank{
		.decision				  = OfficialDriverRankDecision::APPLICABLE,
		.currentPosition		  = {.kind = PnpIdentifierKind::HARDWARE_ID, .index = 0U},
		.candidatePosition		  = {.kind = PnpIdentifierKind::HARDWARE_ID, .index = 0U},
		.currentRank			  = 0x00001000U,
		.candidateRank			  = 0x00001000U,
		.currentIdentifierScore	  = 0x1000U,
		.candidateIdentifierScore = 0x1000U,
	} ; // 取得後と導入直前で完全一致させる架空rank snapshot。
	// 1件または2件のdeviceを同じ検証済みpayloadへ結び付け、入力順で保持する。
	for( std::size_t index = 0U; index < deviceCount; ++index) {
		const std::wstring suffix	= std::to_wstring( index) ;						// 架空IDを一意にする10進連番。
		const std::wstring identity = L"candidate:intel-ethernet:821:" + suffix ;	// 発行済み候補ID。
		IntelEthernetPreparedInstallTarget target{
			.prepared =
				{
					.packageIdentity	 = L"intel-ethernet:release:821:0",
					.deviceIdentity		 = L"device:821:fictional:" + suffix,
					.auditedPackageIndex = 0U,
					.rankAudit			 = rank,
				},
			.binding =
				{
					.token			   = 82101U + index,
					.currentProvider   = L"Intel",
					.currentVersion	   = L"1.0.0.0",
					.currentDate	   = L"2025/09/08",
					.candidateProvider = L"Intel",
					.candidateVersion  = L"2.0.0.0",
					.candidateDate	   = L"2026/09/08",
					.rankAudit		   = rank,
				},
		} ; // 同じINFとrankへ固定した現在device一件のbinding routing。
		fixture.targets.emplace( identity, std::move( target)) ;
		fixture.identities.push_back( identity) ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 取得済みarchiveを展開せず全file一覧化できることを検証する。
 *
 * Driver閉包と未参照utilityを含む全通常fileがinventoryへ残り、取得identityが維持されることを確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testArchiveInventory( TestContext &context)
{
	const ZipFixtureEntry fixtureEntries[]{
		{"driver/sample.inf", VALID_INF.data(), VALID_INF.size()},
		{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
		{"driver/sample.sys", DRIVER.data(), DRIVER.size()},
		{"tools/setup.exe", SETUP.data(), SETUP.size()},
	} ; // 一覧化で選別してはならない全file構成。
	std::vector<std::byte> archive ;	// 生成した入力ZIP byte列。
	DRIVERCRATE_EXPECT( context, createZipFixture( fixtureEntries, archive)) ;
	OfficialDownloadWorkspace input ;	// G11-B取得fileを模倣する保護領域。
	DRIVERCRATE_EXPECT( context, input.initialize( L"inventory-input", 101U) == 0) ;
	std::wstring sha256 ;	// 入力ZIPの固定SHA-256。
	DRIVERCRATE_EXPECT( context, storeArchive( input, L"payload.zip", archive, sha256) == 0) ;
	const std::wstring archivePath = input.path( L"payload.zip") ;	// 取得結果の絶対path。
	const OfficialAcquisitionResult acquisition{
		.state			= OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
		.scanSessionId	= 101U,
		.acquisitionId	= 1U,
		.providerId		= L"test-provider",
		.resourceId		= L"test-payload",
		.inspectionPath = archivePath,
		.byteCount		= static_cast<std::uint64_t>( archive.size()),
		.sha256			= sha256,
	} ; // G11-Bで固定済みの架空取得結果。
	const OfficialDriverArchiveInventoryRequest request{
		.acquisition	   = &acquisition,
		.archiveFormat	   = OfficialDriverArchiveFormat::ZIP,
		.nestedArchivePath = {}} ;				// 外側ZIPの一覧化要求。
	OfficialDriverArchiveInventory inventory ;	// 成功時の全通常file一覧。
	DRIVERCRATE_EXPECT( context,
					   inspectOfficialDriverArchiveInventory( request, POLICY, inventory) == 0) ;
	DRIVERCRATE_EXPECT( context, inventory.entries.size() == 4U) ;
	DRIVERCRATE_EXPECT( context, inventory.archiveDepth == 0U) ;
	DRIVERCRATE_EXPECT( context,
					   std::ranges::any_of( inventory.entries, []( const OfficialZipEntry &entry) {
						   return entry.relativePath == L"tools\\setup.exe" ;
					   })) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASUS packageの全INFを拒否後まで確認することを検証する。
 *
 * 架空CATを合格させず、先頭INFの拒否後も二件目まで監査して候補またはworkspaceを公開しないことを確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testAsusAllInfAudit( TestContext &context)
{
	const ZipFixtureEntry fixtureEntries[]{
		{"driver/sample.inf", VALID_INF.data(), VALID_INF.size()},
		{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
		{"driver/sample.sys", DRIVER.data(), DRIVER.size()},
		{"rejected/command.inf", COMMAND_INF.data(), COMMAND_INF.size()},
	} ; // 一件はCAT拒否、もう一件は閉包欠落となる二INF構成。
	std::vector<std::byte> archive ;	// 生成したASUS相当入力ZIP byte列。
	DRIVERCRATE_EXPECT( context, createZipFixture( fixtureEntries, archive)) ;
	OfficialDownloadWorkspace input ;	// G11-B取得fileを模倣する保護領域。
	DRIVERCRATE_EXPECT( context, input.initialize( L"asus-audit-input", 102U) == 0) ;
	std::wstring sha256 ;	// ASUS公開hashとlocal hashを模倣するSHA-256。
	DRIVERCRATE_EXPECT( context, storeArchive( input, L"payload.zip", archive, sha256) == 0) ;
	const std::wstring archivePath = input.path( L"payload.zip") ;	// 取得結果の内部絶対path。
	const OfficialAcquisitionResult acquisition{
		.state					 = OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
		.scanSessionId			 = 102U,
		.acquisitionId			 = 1U,
		.providerId				 = std::wstring( ASUS_PROVIDER_ID),
		.resourceId				 = std::wstring( OFFICIAL_PAYLOAD_RESOURCE_ID),
		.inspectionPath			 = archivePath,
		.byteCount				 = static_cast<std::uint64_t>( archive.size()),
		.sha256					 = sha256,
		.publishedSha256Verified = true,
	} ; // ASUS公式hash照合済みを模倣する取得結果。
	const AsusDriverPackageAuditRequest request{
		.acquisition	= &acquisition,
		.expectedSha256 = sha256,
		.archiveFormat	= OfficialDriverArchiveFormat::ZIP} ;	// 全INF内容監査要求。
	AsusDriverPackageAudit audit ;								// 全件拒否を保持する監査結果。
	DRIVERCRATE_EXPECT( context, auditAsusDriverPackage( request, audit) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   audit.summary.state == AsusDriverPackageAuditState::NO_SUPPORTED_INF) ;
	DRIVERCRATE_EXPECT( context, audit.summary.inventoryFileCount == 4U) ;
	DRIVERCRATE_EXPECT( context, audit.summary.infCount == 2U) ;
	DRIVERCRATE_EXPECT( context, audit.summary.auditedInfCount == 0U) ;
	DRIVERCRATE_EXPECT( context, audit.summary.rejectedInfCount == 2U) ;
	DRIVERCRATE_EXPECT( context, audit.summary.firstRejectionError != 0) ;
	DRIVERCRATE_EXPECT( context, audit.auditedPackages.empty()) ;

	OfficialAcquisitionResult wrongSource = acquisition ;	// 別Providerへ差し替える拒否fixture。
	wrongSource.providerId				  = L"not-asus" ;
	const AsusDriverPackageAuditRequest wrongRequest{
		.acquisition	= &wrongSource,
		.expectedSha256 = sha256,
		.archiveFormat	= OfficialDriverArchiveFormat::ZIP} ;	// 取得元不一致要求。
	AsusDriverPackageAudit rejected ;							// 取得元拒否結果。
	DRIVERCRATE_EXPECT( context, auditAsusDriverPackage( wrongRequest, rejected) != 0) ;
	DRIVERCRATE_EXPECT( context, rejected.summary.state == AsusDriverPackageAuditState::REJECTED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASUS packageの一意な一段nested INFを監査する。
 *
 * 外側にINFがない場合だけ一意な内側ZIPを選び、架空CATを合格させずarchive深度と拒否件数を保持する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testAsusNestedInfAudit( TestContext &context)
{
	const ZipFixtureEntry innerEntries[]{
		{"driver/sample.inf", VALID_INF.data(), VALID_INF.size()},
		{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
		{"driver/sample.sys", DRIVER.data(), DRIVER.size()},
	} ; // 一INF閉包を持つ内側ZIP構成。
	std::vector<std::byte> innerArchive ;	// 生成した内側ZIP byte列。
	DRIVERCRATE_EXPECT( context, createZipFixture( innerEntries, innerArchive)) ;
	const ZipFixtureEntry outerEntries[]{
		{"package/driver.zip", innerArchive.data(), innerArchive.size()},
		{"tools/setup.exe", SETUP.data(), SETUP.size()},
	} ; // 一意な内側ZIPと未参照utilityを持つ外側構成。
	std::vector<std::byte> outerArchive ;	// 生成した外側ZIP byte列。
	DRIVERCRATE_EXPECT( context, createZipFixture( outerEntries, outerArchive)) ;
	OfficialDownloadWorkspace input ;	// G11-B取得fileを模倣する保護領域。
	DRIVERCRATE_EXPECT( context, input.initialize( L"asus-nested-input", 103U) == 0) ;
	std::wstring sha256 ;	// 外側ZIPの公開hash相当値。
	DRIVERCRATE_EXPECT( context, storeArchive( input, L"payload.zip", outerArchive, sha256) == 0) ;
	const std::wstring archivePath = input.path( L"payload.zip") ;	// 取得結果の内部絶対path。
	const OfficialAcquisitionResult acquisition{
		.state					 = OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
		.scanSessionId			 = 103U,
		.acquisitionId			 = 1U,
		.providerId				 = std::wstring( ASUS_PROVIDER_ID),
		.resourceId				 = std::wstring( OFFICIAL_PAYLOAD_RESOURCE_ID),
		.inspectionPath			 = archivePath,
		.byteCount				 = static_cast<std::uint64_t>( outerArchive.size()),
		.sha256					 = sha256,
		.publishedSha256Verified = true,
	} ; // ASUS公式hash照合済みを模倣する外側取得結果。
	const AsusDriverPackageAuditRequest request{
		.acquisition	= &acquisition,
		.expectedSha256 = sha256,
		.archiveFormat	= OfficialDriverArchiveFormat::ZIP} ;	// 一段nested内容監査要求。
	AsusDriverPackageAudit audit ;								// 内側INF拒否を保持する監査結果。
	DRIVERCRATE_EXPECT( context, auditAsusDriverPackage( request, audit) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   audit.summary.state == AsusDriverPackageAuditState::NO_SUPPORTED_INF) ;
	DRIVERCRATE_EXPECT( context, audit.summary.inventoryFileCount == 3U) ;
	DRIVERCRATE_EXPECT( context, audit.summary.infCount == 1U) ;
	DRIVERCRATE_EXPECT( context, audit.summary.rejectedInfCount == 1U) ;
	DRIVERCRATE_EXPECT( context, audit.summary.archiveDepth == 1U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASUS内容監査済みINFをPnP／Rank合格対象だけに限定する。
 *
 * 同一classの全deviceを監査し、個別SetupAPI失敗後も継続してApplicableだけをopaqueな導入準備集合へ保持する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testAsusRankApplicability( TestContext &context)
{
	OfficialDriverClosure closure ;	// CAT監査まで合格した一INF閉包のfixture。
	closure.packages.push_back( {.infRelativePath	 = L"driver\\sample.inf",
								.catalogRelativePath = L"driver\\sample.cat",
								.className			 = L"Net",
								.providerName		 = L"Fictional Device Corporation",
								.driverDate			 = L"09/04/2026",
								.driverVersion		 = L"2.0.0.1",
								.hardwareIds		 = {L"PCI\\VEN_1234&DEV_5678"},
								.sourceFiles		 = {L"driver\\sample.sys"}}) ;
	AsusDriverPackageAudit audit ;	// G11-CとCAT合格済みを模倣する監査object。
	audit.scanSessionId			  = 301U ;
	audit.summary.state			  = AsusDriverPackageAuditState::AUDITED ;
	audit.summary.auditedInfCount = 1U ;
	audit.auditedPackages.push_back( {.workspace = std::make_unique<OfficialDownloadWorkspace>(),
									 .closure	= std::move( closure)}) ;

	const std::array devices{
		OfficialCatalogDevice{.deviceIdentity = L"device:301:0", .driverClass = L"Net"},
		OfficialCatalogDevice{.deviceIdentity = L"device:301:1", .driverClass = L"Net"},
		OfficialCatalogDevice{.deviceIdentity = L"device:301:2", .driverClass = L"MEDIA"},
	} ; // 二つの同一class deviceと一つの対象外class device。
	std::size_t						 auditorCallCount{} ;	// G11-D fakeへ到達した同一class組合せ数。
	const AsusOfficialInfRankAuditor rankAuditor =
		[&context, &auditorCallCount](
			const ScanSessionId scanSessionId, const std::wstring_view deviceIdentity,
			const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
			OfficialDriverRankAudit &rankAudit) -> NativeError {
		static_cast<void>( workspace) ;
		++auditorCallCount ;
		DRIVERCRATE_EXPECT( context, scanSessionId == 301U) ;
		DRIVERCRATE_EXPECT( context, package.className == L"Net") ;
		// 指定した一台だけに架空の適用性・rank合格を返し、対象の絞込みを検証する。
		if( deviceIdentity == L"device:301:0") {
			rankAudit.decision		= OfficialDriverRankDecision::APPLICABLE ;
			rankAudit.currentRank	= 0x00FF0001U ;
			rankAudit.candidateRank = 0x00FE0001U ;
			return 0 ;
		}

		return static_cast<NativeError>( E_FAIL) ;
	} ; // 一件を合格、一件をSetupAPI失敗とするread-only監査fixture。

	DRIVERCRATE_EXPECT( context,
					   auditAsusDriverApplicability( 301U, devices, rankAuditor, audit) == 0) ;
	DRIVERCRATE_EXPECT( context, auditorCallCount == 2U) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.state ==
									AsusDriverApplicabilityState::APPLICABLE_TARGETS) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.examinedPairCount == 2U) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.applicablePairCount == 1U) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.failedPairCount == 1U) ;
	DRIVERCRATE_EXPECT( context,
					   audit.applicability.firstPairError == static_cast<NativeError>( E_FAIL)) ;
	DRIVERCRATE_EXPECT( context, audit.rankApprovedTargets.size() == 1U) ;
	DRIVERCRATE_EXPECT( context,
					   audit.rankApprovedTargets.front().deviceIdentity == L"device:301:0") ;
	DRIVERCRATE_EXPECT( context, audit.rankApprovedTargets.front().auditedPackageIndex == 0U) ;

	OfficialDriverClosure rejectedClosure ;	// Rank退行対象の一INF閉包fixture。
	rejectedClosure.packages.push_back( {.infRelativePath	 = L"driver\\older.inf",
										.catalogRelativePath = L"driver\\older.cat",
										.className			 = L"Net",
										.providerName		 = L"Fictional Device Corporation",
										.driverDate			 = L"09/03/2026",
										.driverVersion		 = L"1.0.0.1",
										.hardwareIds		 = {L"PCI\\VEN_1234&DEV_5678"},
										.sourceFiles		 = {L"driver\\older.sys"}}) ;
	AsusDriverPackageAudit rejectedAudit ;	// 全組合せがrank退行する監査object。
	rejectedAudit.scanSessionId			  = 302U ;
	rejectedAudit.summary.state			  = AsusDriverPackageAuditState::AUDITED ;
	rejectedAudit.summary.auditedInfCount = 1U ;
	rejectedAudit.auditedPackages.push_back(
		{.workspace = std::make_unique<OfficialDownloadWorkspace>(),
		 .closure	= std::move( rejectedClosure)}) ;
	// 適用性で拒否される架空network deviceの入力集合。
	const std::array rejectedDevice{
		OfficialCatalogDevice{.deviceIdentity = L"device:302:0", .driverClass = L"Net"}} ;
	const AsusOfficialInfRankAuditor rejectingAuditor =
		[]( const ScanSessionId scanSessionId, const std::wstring_view deviceIdentity,
		   const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
		   OfficialDriverRankAudit &rankAudit) -> NativeError {
		static_cast<void>( scanSessionId) ;
		static_cast<void>( deviceIdentity) ;
		static_cast<void>( workspace) ;
		static_cast<void>( package) ;
		rankAudit.decision = OfficialDriverRankDecision::OVERALL_RANK_REGRESSION ;
		return 0 ;
	} ; // Windows rank退行を返すG11-D fixture。
	DRIVERCRATE_EXPECT( context, auditAsusDriverApplicability( 302U, rejectedDevice, rejectingAuditor,
															 rejectedAudit) == 0) ;
	DRIVERCRATE_EXPECT( context, rejectedAudit.applicability.state ==
									AsusDriverApplicabilityState::NO_APPLICABLE_TARGETS) ;
	DRIVERCRATE_EXPECT( context, rejectedAudit.applicability.rejectedPairCount == 1U) ;
	DRIVERCRATE_EXPECT( context, rejectedAudit.rankApprovedTargets.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASUS導入前再検証が不完全なscan記録を拒否する。
 *
 * Workspace、file snapshotまたは単一INFが欠けた監査記録をSetupAPIへ渡す前にfail-closedで拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testAsusInstallReverification( TestContext &context)
{
	const AsusAuditedInfPackage missingWorkspace ;	// Workspaceを持たない不正な監査記録。
	DRIVERCRATE_EXPECT( context, reverifyAsusAuditedInfPackage( missingWorkspace) != 0) ;

	AsusAuditedInfPackage missingSnapshot ;	// File snapshotを持たない不正な監査記録。
	missingSnapshot.workspace = std::make_unique<OfficialDownloadWorkspace>() ;
	missingSnapshot.closure.packages.push_back( {.infRelativePath	 = L"driver\\sample.inf",
												.catalogRelativePath = L"driver\\sample.cat",
												.className			 = L"Net",
												.providerName  = L"Fictional Device Corporation",
												.driverDate	   = L"09/04/2026",
												.driverVersion = L"2.0.0.1",
												.hardwareIds   = {L"PCI\\VEN_1234&DEV_5678"},
												.sourceFiles   = {L"driver\\sample.sys"}}) ;
	DRIVERCRATE_EXPECT( context, reverifyAsusAuditedInfPackage( missingSnapshot) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未参照installerを除いたdriver閉包を抽出できることを検証する。
 *
 * INFが参照しないsetup.exeをworkspaceへ書き出さない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testSelectiveMixedArchive( TestContext &context)
{
	const ZipFixtureEntry fixtureEntries[]{
		{"driver/sample.inf", VALID_INF.data(), VALID_INF.size()},
		{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
		{"driver/sample.sys", DRIVER.data(), DRIVER.size()},
		{"tools/setup.exe", SETUP.data(), SETUP.size()},
	} ; // Driverと未参照installerを持つmixed archive。
	std::vector<std::byte> archive ;	// 生成した外側ZIP byte列。
	DRIVERCRATE_EXPECT( context, createZipFixture( fixtureEntries, archive)) ;
	OfficialDownloadWorkspace input ;	// G11-B取得fileを模倣する保護領域。
	DRIVERCRATE_EXPECT( context, input.initialize( L"closure-input", 1U) == 0) ;
	std::wstring sha256 ;	// 入力ZIPの固定SHA-256。
	DRIVERCRATE_EXPECT( context, storeArchive( input, L"payload.zip", archive, sha256) == 0) ;
	const std::wstring archivePath =
		// Requestより長く生存する入力path。
		input.path( L"payload.zip") ;
	const OfficialAcquisitionResult acquisition{
		.state			= OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
		.scanSessionId	= 1U,
		.acquisitionId	= 1U,
		.providerId		= L"test-provider",
		.resourceId		= L"test-payload",
		.inspectionPath = archivePath,
		.byteCount		= static_cast<std::uint64_t>( archive.size()),
		.sha256			= sha256,
	} ; // G11-Bで固定済みの架空取得結果。
	// 閉包監査の対象として明示選択する、package内の架空INF path。
	constexpr std::array			   SELECTED_INF{std::wstring_view( L"driver\\sample.inf")} ;
	const OfficialDriverClosureRequest request{
		.acquisition	  = &acquisition,
		.archiveFormat	  = OfficialDriverArchiveFormat::ZIP,
		.selectedInfPaths = SELECTED_INF,
		.workspaceTag	  = L"closure-output",
	} ; // 一INFだけを選択する架空G11-C入力。
	OfficialDownloadWorkspace output ;	// 選択されたdriver閉包の出力先。
	OfficialDriverClosure	  closure ;	// 全検証成功時の閉包結果。
	const NativeError		  extractionError =
		// 閉包抽出結果。
		extractOfficialDriverClosure( request, POLICY, output, closure) ;
	// 混在ZIPの抽出失敗を報告し、不存在の閉包に対する詳細検証を行わない。
	if( extractionError != 0) {
		std::cerr << "mixed ZIP closure error: " << extractionError << '\n' ;
		DRIVERCRATE_EXPECT( context, extractionError == 0) ;
		return ;
	}

	DRIVERCRATE_EXPECT( context, closure.entries.size() == 3U) ;
	DRIVERCRATE_EXPECT( context, closure.packages.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, closure.archiveDepth == 0U) ;
	DRIVERCRATE_EXPECT( context, GetFileAttributesW( output.path( L"tools\\setup.exe").c_str()) ==
									INVALID_FILE_ATTRIBUTES) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 単一CABからdriver閉包だけを抽出できることを検証する。
 *
 * 架空INF、CAT、SYSを持つCABを二回列挙し、選択INFの閉包だけを取り込む。未表示INFとentry上限超過は拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testSelectiveCabArchive( TestContext &context)
{
	const std::span cabBytes = std::as_bytes( std::span( DRIVER_CLOSURE_CAB)) ;	// 固定CAB byte列。
	OfficialDownloadWorkspace input ;											// G11-B取得CABを模倣する保護領域。
	DRIVERCRATE_EXPECT( context, input.initialize( L"closure-cab-input", 8U) == 0) ;
	std::wstring sha256 ;	// 入力CABの固定SHA-256。
	DRIVERCRATE_EXPECT( context, storeArchive( input, L"payload.cab", cabBytes, sha256) == 0) ;
	const std::wstring archivePath = input.path( L"payload.cab") ;	// 取得結果が所有するpath。
	const OfficialAcquisitionResult acquisition{
		.state			= OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
		.scanSessionId	= 8U,
		.acquisitionId	= 1U,
		.providerId		= L"test-provider",
		.resourceId		= L"test-payload",
		.inspectionPath = archivePath,
		.byteCount		= static_cast<std::uint64_t>( cabBytes.size()),
		.sha256			= sha256,
	} ; // G11-Bで取得済みとする架空CAB identity。
	// 閉包監査の対象として明示選択する、package内の架空INF path。
	constexpr std::array			   SELECTED_INF{std::wstring_view( L"driver\\sample.inf")} ;
	const OfficialDriverClosureRequest request{
		.acquisition	  = &acquisition,
		.archiveFormat	  = OfficialDriverArchiveFormat::CABINET,
		.selectedInfPaths = SELECTED_INF,
		.workspaceTag	  = L"closure-cab-output",
	} ; // 一INFだけを選択するCAB閉包抽出要求。
	OfficialDownloadWorkspace output ;	// CABから選択した閉包の所有先。
	OfficialDriverClosure	  closure ;	// 全検証成功時のCAB閉包結果。
	const NativeError		  extractionError =
		// 閉包抽出結果。
		extractOfficialDriverClosure( request, POLICY, output, closure) ;
	// 単一CABの抽出失敗を報告し、不存在の閉包に対する詳細検証を行わない。
	if( extractionError != 0) {
		std::cerr << "single CAB closure error: " << extractionError << '\n' ;
		DRIVERCRATE_EXPECT( context, extractionError == 0) ;
		return ;
	}

	DRIVERCRATE_EXPECT( context, closure.entries.size() == 3U) ;
	DRIVERCRATE_EXPECT( context, closure.packages.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, closure.archiveDepth == 0U) ;
	DRIVERCRATE_EXPECT( context, GetFileAttributesW( output.path( L"driver\\sample.inf").c_str()) !=
									INVALID_FILE_ATTRIBUTES) ;
	DRIVERCRATE_EXPECT( context, GetFileAttributesW( output.path( L"driver\\sample.cat").c_str()) !=
									INVALID_FILE_ATTRIBUTES) ;
	DRIVERCRATE_EXPECT( context, GetFileAttributesW( output.path( L"driver\\sample.sys").c_str()) !=
									INVALID_FILE_ATTRIBUTES) ;

	// 存在しないINFを指定した場合の拒否用選択集合。
	constexpr std::array			   MISSING_INF{std::wstring_view( L"driver\\missing.inf")} ;
	const OfficialDriverClosureRequest missingRequest{
		.acquisition	  = &acquisition,
		.archiveFormat	  = OfficialDriverArchiveFormat::CABINET,
		.selectedInfPaths = MISSING_INF,
		.workspaceTag	  = L"closure-cab-missing",
	} ; // CAB inventoryに存在しないINFを指定する拒否要求。
	OfficialDownloadWorkspace missingOutput ;	// 未表示INF拒否時の未公開出力領域。
	OfficialDriverClosure	  missingClosure ;	// 未表示INF拒否時に空であるべき結果。
	DRIVERCRATE_EXPECT( context, extractOfficialDriverClosure( missingRequest, POLICY, missingOutput,
															 missingClosure) != 0) ;
	DRIVERCRATE_EXPECT( context, missingClosure.entries.empty()) ;

	OfficialDriverClosurePolicy limitedPolicy = POLICY ;	// CAB entry数だけを過小にするpolicy。
	limitedPolicy.cabPolicy.maximumEntryCount = 2U ;
	OfficialDownloadWorkspace limitedOutput ;	// Entry上限超過時の未公開出力領域。
	OfficialDriverClosure	  limitedClosure ;	// Entry上限超過時に空であるべき結果。
	DRIVERCRATE_EXPECT( context, extractOfficialDriverClosure( request, limitedPolicy, limitedOutput,
															 limitedClosure) != 0) ;
	DRIVERCRATE_EXPECT( context, limitedClosure.entries.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief INFが参照するinstallerを閉包抽出で拒否することを検証する。
 *
 * Archiveの未参照EXE許可を、INF閉包内のEXE参照へ拡張しない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testReferencedProgramRejected( TestContext &context)
{
	const ZipFixtureEntry fixtureEntries[]{
		{"sample.inf", PROGRAM_INF.data(), PROGRAM_INF.size()},
		{"sample.cat", CATALOG.data(), CATALOG.size()},
		{"sample.sys", DRIVER.data(), DRIVER.size()},
		{"setup.exe", SETUP.data(), SETUP.size()},
	} ; // INFがEXEを直接参照する拒否用archive。
	std::vector<std::byte> archive ;	// 生成した入力ZIP byte列。
	DRIVERCRATE_EXPECT( context, createZipFixture( fixtureEntries, archive)) ;
	OfficialDownloadWorkspace input ;	// G11-B取得fileの架空所有先。
	DRIVERCRATE_EXPECT( context, input.initialize( L"closure-reject-input", 2U) == 0) ;
	std::wstring sha256 ;	// 入力ZIPの固定SHA-256。
	DRIVERCRATE_EXPECT( context, storeArchive( input, L"payload.zip", archive, sha256) == 0) ;
	const std::wstring archivePath =
		// Requestより長く生存する入力path。
		input.path( L"payload.zip") ;
	const OfficialAcquisitionResult acquisition{
		.state			= OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
		.scanSessionId	= 2U,
		.acquisitionId	= 1U,
		.providerId		= L"test-provider",
		.resourceId		= L"test-payload",
		.inspectionPath = archivePath,
		.byteCount		= static_cast<std::uint64_t>( archive.size()),
		.sha256			= sha256,
	} ; // G11-Bで固定済みの架空取得結果。
	// Archive直下の架空INFを明示選択する集合。
	constexpr std::array			   SELECTED_INF{std::wstring_view( L"sample.inf")} ;
	const OfficialDriverClosureRequest request{
		.acquisition	  = &acquisition,
		.archiveFormat	  = OfficialDriverArchiveFormat::ZIP,
		.selectedInfPaths = SELECTED_INF,
		.workspaceTag	  = L"closure-reject-output",
	} ; // EXE参照INFの抽出要求。
	OfficialDownloadWorkspace output ;	// 失敗時の既知fileもscope終了時に破棄する領域。
	OfficialDriverClosure	  closure ;	// 失敗時は空であるべき閉包結果。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialDriverClosure( request, POLICY, output, closure) != 0) ;
	DRIVERCRATE_EXPECT( context, closure.entries.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief INFの実行directiveを閉包抽出で拒否することを検証する。
 *
 * File拡張子の検査だけに依存せず、任意commandの起動経路を静的INF解析で拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testInstallActionRejected( TestContext &context)
{
	const ZipFixtureEntry fixtureEntries[]{
		{"sample.inf", COMMAND_INF.data(), COMMAND_INF.size()},
		{"sample.cat", CATALOG.data(), CATALOG.size()},
		{"sample.sys", DRIVER.data(), DRIVER.size()},
	} ; // 実行directiveを含むINFと通常driver fileのarchive。
	std::vector<std::byte> archive ;	// 生成した入力ZIP byte列。
	DRIVERCRATE_EXPECT( context, createZipFixture( fixtureEntries, archive)) ;
	OfficialDownloadWorkspace input ;	// G11-B取得fileの架空所有先。
	DRIVERCRATE_EXPECT( context, input.initialize( L"closure-command-input", 6U) == 0) ;
	std::wstring sha256 ;	// 入力ZIPの固定SHA-256。
	DRIVERCRATE_EXPECT( context, storeArchive( input, L"payload.zip", archive, sha256) == 0) ;
	const std::wstring archivePath = input.path( L"payload.zip") ;	// 取得結果が所有するpath。
	const OfficialAcquisitionResult acquisition{
		.state			= OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
		.scanSessionId	= 6U,
		.acquisitionId	= 1U,
		.providerId		= L"test-provider",
		.resourceId		= L"test-payload",
		.inspectionPath = archivePath,
		.byteCount		= static_cast<std::uint64_t>( archive.size()),
		.sha256			= sha256,
	} ; // G11-Bで固定済みの架空取得結果。
	// Archive直下の架空INFを明示選択する集合。
	constexpr std::array			   SELECTED_INF{std::wstring_view( L"sample.inf")} ;
	const OfficialDriverClosureRequest request{
		.acquisition	  = &acquisition,
		.selectedInfPaths = SELECTED_INF,
		.workspaceTag	  = L"closure-command-output",
	} ; // 実行directiveを持つINFの抽出要求。
	OfficialDownloadWorkspace output ;	// 拒否fileをscope終了時に破棄する領域。
	OfficialDriverClosure	  closure ;	// 拒否時は空であるべき閉包結果。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialDriverClosure( request, POLICY, output, closure) != 0) ;
	DRIVERCRATE_EXPECT( context, closure.entries.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一段nested ZIPからdriver閉包だけを抽出できることを検証する。
 *
 * 外側ZIPから明示した一段ZIPだけを分離し、内側閉包を抽出する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testNestedZipClosure( TestContext &context)
{
	const ZipFixtureEntry innerEntries[]{
		{"sample.inf", VALID_INF.data(), VALID_INF.size()},
		{"sample.cat", CATALOG.data(), CATALOG.size()},
		{"sample.sys", DRIVER.data(), DRIVER.size()},
		{"setup.exe", SETUP.data(), SETUP.size()},
	} ; // Driver閉包と未参照EXEを持つ内側ZIP。
	std::vector<std::byte> innerArchive ;	// 生成した内側ZIP byte列。
	DRIVERCRATE_EXPECT( context, createZipFixture( innerEntries, innerArchive)) ;
	const ZipFixtureEntry outerEntries[]{
		{"packages/device.zip", innerArchive.data(), innerArchive.size()},
		{"readme.txt", SETUP.data(), SETUP.size()},
	} ; // 一段ZIPと選択外fileを持つ外側ZIP。
	std::vector<std::byte> outerArchive ;	// 生成した外側ZIP byte列。
	DRIVERCRATE_EXPECT( context, createZipFixture( outerEntries, outerArchive)) ;
	OfficialDownloadWorkspace input ;	// G11-B取得fileの架空所有先。
	DRIVERCRATE_EXPECT( context, input.initialize( L"closure-nested-input", 3U) == 0) ;
	std::wstring sha256 ;	// 外側ZIPの固定SHA-256。
	DRIVERCRATE_EXPECT( context, storeArchive( input, L"payload.zip", outerArchive, sha256) == 0) ;
	const std::wstring archivePath =
		// Requestより長く生存する入力path。
		input.path( L"payload.zip") ;
	const OfficialAcquisitionResult acquisition{
		.state			= OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
		.scanSessionId	= 3U,
		.acquisitionId	= 1U,
		.providerId		= L"test-provider",
		.resourceId		= L"test-payload",
		.inspectionPath = archivePath,
		.byteCount		= static_cast<std::uint64_t>( outerArchive.size()),
		.sha256			= sha256,
	} ; // G11-Bで固定済みの架空取得結果。
	// Archive直下の架空INFを明示選択する集合。
	constexpr std::array			   SELECTED_INF{std::wstring_view( L"sample.inf")} ;
	const OfficialDriverClosureRequest request{
		.acquisition	   = &acquisition,
		.archiveFormat	   = OfficialDriverArchiveFormat::ZIP,
		.nestedArchivePath = L"packages\\device.zip",
		.selectedInfPaths  = SELECTED_INF,
		.workspaceTag	   = L"closure-nested-output",
	} ; // 一段ZIP内のINFを選択する抽出要求。
	OfficialDownloadWorkspace output ;	// 内側driver閉包の出力先。
	OfficialDriverClosure	  closure ;	// 一段抽出の成功結果。
	const NativeError		  extractionError =
		// 閉包抽出結果。
		extractOfficialDriverClosure( request, POLICY, output, closure) ;
	// nested ZIPの抽出失敗を報告し、不存在の閉包に対する詳細検証を行わない。
	if( extractionError != 0) {
		std::cerr << "nested ZIP closure error: " << extractionError << '\n' ;
		DRIVERCRATE_EXPECT( context, extractionError == 0) ;
		return ;
	}

	DRIVERCRATE_EXPECT( context, closure.archiveDepth == 1U) ;
	DRIVERCRATE_EXPECT( context, closure.entries.size() == 3U) ;
	DRIVERCRATE_EXPECT( context, GetFileAttributesW( output.path( L"setup.exe").c_str()) ==
									INVALID_FILE_ATTRIBUTES) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一段nested CABからdriver閉包だけを抽出できることを検証する。
 *
 * 外側ZIPから明示した固定CABだけを分離し、内側のINF、CAT、SYS閉包を同じ有限policyで抽出する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testNestedCabClosure( TestContext &context)
{
	const std::span cabBytes =
		// 固定CAB fixtureのbyte view。
		std::as_bytes( std::span( DRIVER_CLOSURE_CAB)) ;
	const ZipFixtureEntry outerEntries[]{
		{"packages/device.cab", cabBytes.data(), cabBytes.size()},
		{"readme.txt", SETUP.data(), SETUP.size()},
	} ; // 一段CABと選択外fileを持つ外側ZIP。
	std::vector<std::byte> outerArchive ;	// 生成した外側ZIP byte列。
	DRIVERCRATE_EXPECT( context, createZipFixture( outerEntries, outerArchive)) ;
	OfficialDownloadWorkspace input ;	// G11-B取得fileの架空所有先。
	DRIVERCRATE_EXPECT( context, input.initialize( L"closure-nested-cab-input", 9U) == 0) ;
	std::wstring sha256 ;	// 外側ZIPの固定SHA-256。
	DRIVERCRATE_EXPECT( context, storeArchive( input, L"payload.zip", outerArchive, sha256) == 0) ;
	const std::wstring archivePath =
		// Requestより長く生存する入力path。
		input.path( L"payload.zip") ;
	const OfficialAcquisitionResult acquisition{
		.state			= OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
		.scanSessionId	= 9U,
		.acquisitionId	= 1U,
		.providerId		= L"test-provider",
		.resourceId		= L"test-payload",
		.inspectionPath = archivePath,
		.byteCount		= static_cast<std::uint64_t>( outerArchive.size()),
		.sha256			= sha256,
	} ; // G11-Bで固定済みの架空取得結果。
	// Directory配下の架空INFを明示選択する集合。
	constexpr std::array			   SELECTED_INF{std::wstring_view( L"driver\\sample.inf")} ;
	const OfficialDriverClosureRequest request{
		.acquisition	   = &acquisition,
		.archiveFormat	   = OfficialDriverArchiveFormat::ZIP,
		.nestedArchivePath = L"packages\\device.cab",
		.selectedInfPaths  = SELECTED_INF,
		.workspaceTag	   = L"closure-nested-cab-out",
	} ; // 一段CAB内のINFを選択する抽出要求。
	OfficialDownloadWorkspace output ;	// 内側CAB driver閉包の出力先。
	OfficialDriverClosure	  closure ;	// 一段CAB抽出の成功結果。
	const NativeError		  extractionError =
		// 閉包抽出結果。
		extractOfficialDriverClosure( request, POLICY, output, closure) ;
	// nested CABの抽出失敗を報告し、不存在の閉包に対する詳細検証を行わない。
	if( extractionError != 0) {
		std::cerr << "nested CAB closure error: " << extractionError << '\n' ;
		DRIVERCRATE_EXPECT( context, extractionError == 0) ;
		return ;
	}

	DRIVERCRATE_EXPECT( context, closure.archiveDepth == 1U) ;
	DRIVERCRATE_EXPECT( context, closure.entries.size() == 3U) ;
	DRIVERCRATE_EXPECT( context, closure.packages.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, GetFileAttributesW( output.path( L"driver\\sample.sys").c_str()) !=
									INVALID_FILE_ATTRIBUTES) ;
	DRIVERCRATE_EXPECT( context, GetFileAttributesW( output.path( L"readme.txt").c_str()) ==
									INVALID_FILE_ATTRIBUTES) ;

	OfficialDriverClosurePolicy nestedDisabled = POLICY ;	// Nested archive禁止policy。
	nestedDisabled.maximumNestedArchiveDepth   = 0U ;
	OfficialDownloadWorkspace disabledOutput ;	// 拒否時に未公開である出力領域。
	OfficialDriverClosure	  disabledClosure ;	// 拒否時に空である閉包結果。
	DRIVERCRATE_EXPECT( context, extractOfficialDriverClosure( request, nestedDisabled,
															 disabledOutput, disabledClosure) != 0) ;
	DRIVERCRATE_EXPECT( context, disabledClosure.entries.empty()) ;

	OfficialDriverClosurePolicy excessiveDepth = POLICY ;	// 二段以上を示す不正policy。
	excessiveDepth.maximumNestedArchiveDepth   = 2U ;
	OfficialDownloadWorkspace excessiveOutput ;		// 不正上限拒否時の未公開出力領域。
	OfficialDriverClosure	  excessiveClosure ;	// 不正上限拒否時に空である閉包結果。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialDriverClosure( request, excessiveDepth, excessiveOutput,
													excessiveClosure) != 0) ;
	DRIVERCRATE_EXPECT( context, excessiveClosure.entries.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief G11-Bで取得成功していないfileを閉包解析前に拒否する。
 *
 * Rejected状態をpathやhashが有効であるかのように解析しない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testUnacquiredInputRejected( TestContext &context)
{
	const OfficialAcquisitionResult acquisition{
		.state = OfficialAcquisitionState::REJECTED,
		.error = static_cast<NativeError>( E_ACCESSDENIED),
	} ; // 検査対象へ到達していない取得結果。
	// Archive直下の架空INFを明示選択する集合。
	constexpr std::array			   SELECTED_INF{std::wstring_view( L"sample.inf")} ;
	const OfficialDriverClosureRequest request{
		.acquisition	  = &acquisition,
		.selectedInfPaths = SELECTED_INF,
		.workspaceTag	  = L"closure-state-reject",
	} ; // 取得失敗結果を含む拒否用要求。
	OfficialDownloadWorkspace output ;	// 未初期化のままであるべき出力領域。
	OfficialDriverClosure	  closure ;	// 拒否時は空であるべき閉包結果。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialDriverClosure( request, POLICY, output, closure) != 0) ;
	DRIVERCRATE_EXPECT( context, closure.entries.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 取得後に同一sizeで差し替えたarchiveを拒否する。
 *
 * G11-Bで固定したSHA-256が解析開始時に不一致なら、抽出結果を公開しないことを確認する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testAcquiredArchiveTamperingRejected( TestContext &context)
{
	const ZipFixtureEntry fixtureEntries[]{
		{"driver/sample.inf", VALID_INF.data(), VALID_INF.size()},
		{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
		{"driver/sample.sys", DRIVER.data(), DRIVER.size()},
	} ; // 差替え前に正常なdriver閉包を持つ入力entry群。
	std::vector<std::byte> archive ;	// 取得済みidentityを固定するZIP byte列。
	DRIVERCRATE_EXPECT( context, createZipFixture( fixtureEntries, archive)) ;
	OfficialDownloadWorkspace input ;	// G11-Bの保護取得先を模倣する領域。
	DRIVERCRATE_EXPECT( context, input.initialize( L"closure-tamper-input", 7U) == 0) ;
	std::wstring sha256 ;	// 差替え前の入力ZIPから固定したSHA-256。
	DRIVERCRATE_EXPECT( context, storeArchive( input, L"payload.zip", archive, sha256) == 0) ;
	const std::wstring archivePath = input.path( L"payload.zip") ;	// 差替え対象の絶対path。
	const OfficialAcquisitionResult acquisition{
		.state			= OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
		.scanSessionId	= 7U,
		.acquisitionId	= 1U,
		.providerId		= L"test-provider",
		.resourceId		= L"test-payload",
		.inspectionPath = archivePath,
		.byteCount		= static_cast<std::uint64_t>( archive.size()),
		.sha256			= sha256,
	} ; // 差替え前のsizeとhashを持つG11-B取得結果。

	HANDLE file = CreateFileW( archivePath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
							  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) ;	// 改ざん対象handle。
	DRIVERCRATE_EXPECT( context, file != INVALID_HANDLE_VALUE) ;
	// 差替え対象のfileを開けない場合は変形試験を中止する。
	if( file == INVALID_HANDLE_VALUE) {
		return ;
	}

	constexpr std::byte TAMPERED_BYTE{0x00} ;	// ZIP先頭signatureを破壊する一byte。
	DWORD				written{} ;				// 同一sizeで上書きできたbyte数。
	const BOOL			writeSucceeded =
		// 一byte差替え結果。
		WriteFile( file, &TAMPERED_BYTE, 1U, &written, nullptr) ;
	const BOOL closeSucceeded = CloseHandle( file) ;	// 解析前のhandle close結果。
	DRIVERCRATE_EXPECT( context, writeSucceeded != FALSE && written == 1U) ;
	DRIVERCRATE_EXPECT( context, closeSucceeded != FALSE) ;

	// Directory配下の架空INFを明示選択する集合。
	constexpr std::array			   SELECTED_INF{std::wstring_view( L"driver\\sample.inf")} ;
	const OfficialDriverClosureRequest request{
		.acquisition	  = &acquisition,
		.archiveFormat	  = OfficialDriverArchiveFormat::ZIP,
		.selectedInfPaths = SELECTED_INF,
		.workspaceTag	  = L"closure-tamper-output",
	} ; // 改ざん後archiveを入力とする抽出要求。
	OfficialDownloadWorkspace output ;	// 拒否時に結果が公開されない出力領域。
	OfficialDriverClosure	  closure ;	// 拒否時に空であるべき閉包結果。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialDriverClosure( request, POLICY, output, closure) != 0) ;
	DRIVERCRATE_EXPECT( context, closure.entries.empty()) ;
	DRIVERCRATE_EXPECT( context, closure.packages.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief SetupAPI展開fileの予約とworkspace所有取込みを検証する。
 *
 * 予約pathに同期作成したfileだけをsize照合後にcleanup所有へ移す。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testExternalFileAdoption( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// SetupAPI展開先を模倣する保護領域。
	const NativeError		  initializationError =
		// Workspace初期化結果。
		workspace.initialize( L"closure-adopt", 4U) ;
	DRIVERCRATE_EXPECT( context, initializationError == 0) ;
	// workspace初期化に失敗した場合は所有権取込みの試験を始めない。
	if( initializationError != 0) {
		return ;
	}

	std::wstring	  outputPath ;	// 外部writerへ渡す追跡付き絶対path。
	const NativeError preparationError =
		// 予約結果。
		workspace.prepareExternalFile( L"driver\\sample.sys", outputPath) ;
	DRIVERCRATE_EXPECT( context, preparationError == 0) ;
	// 外部展開先を予約できなければfileを生成しない。
	if( preparationError != 0) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, GetFileAttributesW( outputPath.c_str()) == INVALID_FILE_ATTRIBUTES) ;
	const HANDLE file = CreateFileW( outputPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
									FILE_ATTRIBUTE_TEMPORARY,
									nullptr) ;	// 架空外部writerの所有handle。
	DRIVERCRATE_EXPECT( context, file != INVALID_HANDLE_VALUE) ;
	// 試験fileを作成できない場合は無効handleで書込みを続けない。
	if( file == INVALID_HANDLE_VALUE) {
		return ;
	}

	DWORD	   written{} ;	// 架空外部writerが書き込んだbyte数。
	const BOOL writeSucceeded =
		WriteFile( file, DRIVER.data(), static_cast<DWORD>( DRIVER.size()), &written,
				  nullptr) ;							// 架空展開結果。
	const BOOL closeSucceeded = CloseHandle( file) ;	// Workspace取込み前のhandle解放結果。
	DRIVERCRATE_EXPECT( context, writeSucceeded != FALSE) ;
	DRIVERCRATE_EXPECT( context, written == static_cast<DWORD>( DRIVER.size())) ;
	DRIVERCRATE_EXPECT( context, closeSucceeded != FALSE) ;
	DRIVERCRATE_EXPECT(
		context,
		workspace.adoptFile( L"driver\\sample.sys", static_cast<std::uint64_t>( DRIVER.size())) == 0) ;
	DRIVERCRATE_EXPECT( context, workspace.discardFile( L"driver\\sample.sys") == 0) ;
	DRIVERCRATE_EXPECT( context, GetFileAttributesW( outputPath.c_str()) == INVALID_FILE_ATTRIBUTES) ;
}

//------------------------------------------------------------------------------
/**
 * @brief CAB cleanupの全path継続を検証する。
 *
 * 一件目をHRESULT失敗、二件目を例外としても三件目までcallbackを呼び、最初の失敗を保持することを検証する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testCabCleanupContinuesAfterFailure( TestContext &context)
{
	// Cleanup callbackへ入力順に渡す三つの架空相対path。
	const std::array<std::wstring, 3>	  paths{L"driver\\locked.sys", L"driver\\exception.cat",
											L"driver\\remaining.inf"} ;
	// 失敗、例外、成功の三回を記録するfault注入状態。
	CabDiscardFixture					  fixture{} ;
	const OfficialCabFileDiscardOperation operation{
		.context  = &fixture,
		.callback = discardFixtureFile,
	} ; // Test function中だけ有効な非所有callback境界。
	const NativeError error =
		// 全件cleanup結果。
		discardOfficialCabFilesBestEffort( paths, operation) ;

	DRIVERCRATE_EXPECT( context, error == static_cast<NativeError>( E_ACCESSDENIED)) ;
	DRIVERCRATE_EXPECT( context, fixture.callCount == paths.size()) ;
	// 入力順を維持して全pathがcallbackへ渡されたことを確認する。
	for( std::size_t index = 0; index < paths.size(); ++index) {
		DRIVERCRATE_EXPECT( context, fixture.observedPaths[index] == paths[index]) ;
	}

	const OfficialCabFileDiscardOperation missingCallback{} ;	// 不正な空callback。
	DRIVERCRATE_EXPECT( context, discardOfficialCabFilesBestEffort( paths, missingCallback) ==
									static_cast<NativeError>( E_INVALIDARG)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Archiveの展開倍率超過をINF展開前に拒否する。
 *
 * 個別／合計size内でも高圧縮な未参照entryをZIP bombとして拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testExpansionRatioRejected( TestContext &context)
{
	const std::string	  repeated( 64U * 1024U, 'A') ;	// 高圧縮率を作る有限の架空byte列。
	const ZipFixtureEntry fixtureEntries[]{
		{"sample.inf", VALID_INF.data(), VALID_INF.size()},
		{"sample.cat", CATALOG.data(), CATALOG.size()},
		{"sample.sys", DRIVER.data(), DRIVER.size()},
		{"unused.dat", repeated.data(), repeated.size()},
	} ; // 展開後合計だけが入力ZIPの二倍を大きく超えるarchive。
	std::vector<std::byte> archive ;	// 生成した高圧縮入力ZIP。
	DRIVERCRATE_EXPECT( context, createZipFixture( fixtureEntries, archive)) ;
	OfficialDownloadWorkspace input ;	// G11-B取得fileの架空所有先。
	DRIVERCRATE_EXPECT( context, input.initialize( L"closure-ratio-input", 5U) == 0) ;
	std::wstring sha256 ;	// 入力ZIPの固定SHA-256。
	DRIVERCRATE_EXPECT( context, storeArchive( input, L"payload.zip", archive, sha256) == 0) ;
	const std::wstring archivePath = input.path( L"payload.zip") ;	// 取得結果が所有するpath。
	const OfficialAcquisitionResult acquisition{
		.state			= OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
		.scanSessionId	= 5U,
		.acquisitionId	= 1U,
		.providerId		= L"test-provider",
		.resourceId		= L"test-payload",
		.inspectionPath = archivePath,
		.byteCount		= static_cast<std::uint64_t>( archive.size()),
		.sha256			= sha256,
	} ; // G11-Bで固定済みの架空取得結果。
	// Archive直下の架空INFを明示選択する集合。
	constexpr std::array			   SELECTED_INF{std::wstring_view( L"sample.inf")} ;
	const OfficialDriverClosureRequest request{
		.acquisition	  = &acquisition,
		.selectedInfPaths = SELECTED_INF,
		.workspaceTag	  = L"closure-ratio-output",
	} ; // 高圧縮ZIPからの閉包抽出要求。
	OfficialDriverClosurePolicy strictPolicy = POLICY ;	// 展開倍率だけを厳格化するpolicy。
	strictPolicy.maximumExpansionRatio		 = 2U ;
	OfficialDownloadWorkspace output ;	// 拒否時は未初期化のままである出力領域。
	OfficialDriverClosure	  closure ;	// 拒否時は空であるべき閉包結果。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialDriverClosure( request, strictPolicy, output, closure) != 0) ;
	DRIVERCRATE_EXPECT( context, closure.entries.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定profileの入力境界と、試験内で生成したZIPの内容拒否に使用する。実取得または実署名の成功を表さない。
 * @return 公開hash照合済みという前提だけを持つ架空の取得記録。
 */
//------------------------------------------------------------------------------
OfficialAcquisitionResult fakeIntelEthernetAcquisition()
{
	return {.state					 = OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
			.scanSessionId			 = 811U,
			.acquisitionId			 = 1U,
			.providerId				 = std::wstring( INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID),
			.resourceId				 = std::wstring( OFFICIAL_PAYLOAD_RESOURCE_ID),
			.inspectionPath			 = L"unopened-intel-fixture.zip",
			.byteCount				 = 1U,
			.sha256					 = std::wstring( 64U, L'a'),
			.publishedSha256Verified = true} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公開系列名だけを模した表示値を使い、hardware IDや実機情報を含めない。
 * @return Intel Ethernet系列照合だけに用いる架空の非機密device。
 */
//------------------------------------------------------------------------------
OfficialCatalogDevice fakeIntelEthernetDevice()
{
	return {.deviceIdentity = L"device:811:fictional",
			.model			= L"Intel(R) E810 Fictional Adapter",
			.manufacturer	= L"Intel",
			.driverClass	= L"Net"} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公開hash照合済み取得を試験内だけで構成し、Intel固定profileへ渡す。架空CATが監査を通過した場合も実PnPへ進まず、予期しない呼出しとして記録する。
 *
 * @param[in] entries 一つの架空ZIPへ格納する有限entry群。
 * @param[out] outcome 生成と保存に成功した場合の監査結果とcallback件数。
 * @return Fixtureの生成、保存、hash計算まで成功した場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool runIntelEthernetArchiveFixture( const std::span<const ZipFixtureEntry> entries,
												  IntelEthernetAuditFixtureOutcome		&outcome)
{
	outcome = {} ;
	std::vector<std::byte> archive ;	// 本fixtureだけが所有する生成済みZIP。
	// 入力ZIPを構成できない場合は監査結果として扱わない。
	if( !createZipFixture( entries, archive)) {
		return false ;
	}

	OfficialDownloadWorkspace input ;	// 監査呼出し中に取得fileを所有する保護領域。
	// Workspaceを作れない場合は内容監査を開始しない。
	if( input.initialize( L"intel-ethernet-audit", 811U) != 0) {
		return false ;
	}

	std::wstring hash ;	// 保存したZIPの実測SHA-256。
	// 不完全fileを取得成功fixtureへ昇格しない。
	if( storeArchive( input, L"payload.zip", archive, hash) != 0) {
		return false ;
	}

	OfficialAcquisitionResult acquisition =
		// 今回の実測値を反映する取得identity。
		fakeIntelEthernetAcquisition() ;
	acquisition.inspectionPath = input.path( L"payload.zip") ;
	acquisition.byteCount	   = static_cast<std::uint64_t>( archive.size()) ;
	acquisition.sha256		   = hash ;
	const std::array			 devices{fakeIntelEthernetDevice()} ;	// 同じscanの架空対象device。
	const OfficialInfRankAuditor rank =
		[&outcome]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
				   const OfficialInfPackage &, OfficialDriverRankAudit &) -> NativeError {
		++outcome.rankCallCount ;
		return static_cast<NativeError>( E_UNEXPECTED) ;
	} ; // 拒否fixtureから呼ばれてはならない後段PnP監査。
	outcome.auditError = auditIntelEthernetPreparedPackage( 811U, acquisition, hash, devices, rank,
														   {}, outcome.audit) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全体処理失敗と個別INF拒否を区別し、PnP／rankへ進まないことを確認する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 * @param[in] entries 一つのINF拒否を発生させる架空ZIP entry群。
 */
//------------------------------------------------------------------------------
void expectIntelEthernetInfRejection( TestContext						   &context,
									 const std::span<const ZipFixtureEntry> entries)
{
	IntelEthernetAuditFixtureOutcome outcome ;										// 今回だけの監査観測値。
	const bool fixtureCreated = runIntelEthernetArchiveFixture( entries, outcome) ;	// 前提構築結果。
	DRIVERCRATE_EXPECT( context, fixtureCreated) ;
	// Fixture前提がない場合に後続の状態assertionを誤解させない。
	if( !fixtureCreated) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, outcome.auditError == 0) ;
	DRIVERCRATE_EXPECT( context, outcome.audit.summary.state ==
									OfficialDriverPackageAuditState::NO_SUPPORTED_INF) ;
	DRIVERCRATE_EXPECT( context, outcome.audit.summary.infCount == 1U) ;
	DRIVERCRATE_EXPECT( context, outcome.audit.summary.auditedInfCount == 0U) ;
	DRIVERCRATE_EXPECT( context, outcome.audit.summary.rejectedInfCount == 1U) ;
	DRIVERCRATE_EXPECT( context, outcome.audit.summary.firstRejectionError != 0) ;
	DRIVERCRATE_EXPECT( context, outcome.audit.auditedPackages.empty()) ;
	DRIVERCRATE_EXPECT( context, outcome.audit.rankApprovedTargets.empty()) ;
	DRIVERCRATE_EXPECT( context, outcome.audit.applicability.state ==
									OfficialDriverApplicabilityState::NOT_STARTED) ;
	DRIVERCRATE_EXPECT( context, outcome.rankCallCount == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Intel固定Provider、payload、session、系列、公開hash照合をfile読込み前に検証する。正しい固定条件は取消しへ到達することで確認する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetProfileAndHashGuards( TestContext &context)
{
	OfficialAcquisitionResult acquisition =
		// Fileを開かない入力境界fixture。
		fakeIntelEthernetAcquisition() ;
	std::array					 devices{fakeIntelEthernetDevice()} ;	// 同じscanの架空対象device。
	OfficialDriverPackageAudit	 audit ;								// 各拒否で更新される監査結果。
	std::size_t					 rankCallCount{} ;						// 取消し・入力拒否後のPnP呼出し件数。
	const OfficialInfRankAuditor rank =
		[&rankCallCount]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
						 const OfficialInfPackage &, OfficialDriverRankAudit &) -> NativeError {
		++rankCallCount ;
		return static_cast<NativeError>( E_UNEXPECTED) ;
	} ; // File読込み前の検証では呼ばれてはならない後段監査。
	const PreparationCancellation cancel = [] { return true ; } ;	// Valid入力の到達点。
	const NativeError			  cancelled =
		// 取消し期待値。
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
	DRIVERCRATE_EXPECT( context, auditIntelEthernetPreparedPackage( 811U, acquisition,
																  acquisition.sha256, devices, rank,
																  cancel, audit) == cancelled) ;
	DRIVERCRATE_EXPECT( context, audit.summary.state == OfficialDriverPackageAuditState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, rankCallCount == 0U) ;

	DRIVERCRATE_EXPECT( context, auditIntelEthernetPreparedPackage( 811U, acquisition, {}, devices,
																  rank, cancel, audit) ==
									static_cast<NativeError>( E_ACCESSDENIED)) ;
	const std::wstring otherHash( 64U, L'b') ;	// 取得時実測値と異なる公開hash。
	DRIVERCRATE_EXPECT( context, auditIntelEthernetPreparedPackage( 811U, acquisition, otherHash,
																  devices, rank, cancel, audit) ==
									static_cast<NativeError>( E_ACCESSDENIED)) ;
	acquisition.publishedSha256Verified = false ;
	DRIVERCRATE_EXPECT( context, auditIntelEthernetPreparedPackage(
									811U, acquisition, acquisition.sha256, devices, rank, cancel,
									audit) == static_cast<NativeError>( E_ACCESSDENIED)) ;
	acquisition			   = fakeIntelEthernetAcquisition() ;
	acquisition.providerId = std::wstring( BROADCOM_NET_XTREME_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, auditIntelEthernetPreparedPackage(
									811U, acquisition, acquisition.sha256, devices, rank, cancel,
									audit) == static_cast<NativeError>( E_ACCESSDENIED)) ;
	acquisition			   = fakeIntelEthernetAcquisition() ;
	acquisition.resourceId = std::wstring( OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ;
	DRIVERCRATE_EXPECT( context, auditIntelEthernetPreparedPackage(
									811U, acquisition, acquisition.sha256, devices, rank, cancel,
									audit) == static_cast<NativeError>( E_ACCESSDENIED)) ;
	acquisition = fakeIntelEthernetAcquisition() ;
	DRIVERCRATE_EXPECT( context, auditIntelEthernetPreparedPackage(
									812U, acquisition, acquisition.sha256, devices, rank, cancel,
									audit) == static_cast<NativeError>( E_INVALIDARG)) ;
	devices.front().driverClass = L"Ports" ;
	DRIVERCRATE_EXPECT( context, auditIntelEthernetPreparedPackage(
									811U, acquisition, acquisition.sha256, devices, rank, cancel,
									audit) == static_cast<NativeError>( E_INVALIDARG)) ;
	devices.front()		  = fakeIntelEthernetDevice() ;
	devices.front().model = L"Intel(R) Fictional Adapter" ;
	DRIVERCRATE_EXPECT( context, auditIntelEthernetPreparedPackage(
									811U, acquisition, acquisition.sha256, devices, rank, cancel,
									audit) == static_cast<NativeError>( E_INVALIDARG)) ;
	DRIVERCRATE_EXPECT( context, rankCallCount == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Net／SYS／CAT／x64 sectionと任意commandの固定条件を架空ZIPで拒否確認する。架空CATを信頼済み署名として扱わない。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetInfAndSignatureRejections( TestContext &context)
{
	const ZipFixtureEntry invalidSignature[]{
		{"driver/sample.inf", VALID_INF.data(), VALID_INF.size()},
		{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
		{"driver/sample.sys", DRIVER.data(), DRIVER.size()},
	} ; // 構造だけが有効でCAT署名が架空のZIP。
	expectIntelEthernetInfRejection( context, invalidSignature) ;

	const ZipFixtureEntry missingCatalog[]{
		{"driver/sample.inf", VALID_INF.data(), VALID_INF.size()},
		{"driver/sample.sys", DRIVER.data(), DRIVER.size()},
	} ; // CatalogFileの参照先がないZIP。
	expectIntelEthernetInfRejection( context, missingCatalog) ;

	const ZipFixtureEntry missingDriver[]{
		{"driver/sample.inf", VALID_INF.data(), VALID_INF.size()},
		{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
	} ; // 必須SYS参照先がないZIP。
	expectIntelEthernetInfRejection( context, missingDriver) ;

	std::string		  displayInf( VALID_INF) ;							// Net classだけをDisplayへ変えた架空INF。
	const std::size_t classPosition = displayInf.find( "Class=Net") ;	// 固定置換位置。
	DRIVERCRATE_EXPECT( context, classPosition != std::string::npos) ;
	// class指定を取得できた場合にだけDisplayへ置換し、Net限定条件を検証する。
	if( classPosition != std::string::npos) {
		displayInf.replace( classPosition, std::string_view( "Class=Net").size(), "Class=Display") ;
	}

	const ZipFixtureEntry wrongClass[]{
		{"driver/sample.inf", displayInf.data(), displayInf.size()},
		{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
		{"driver/sample.sys", DRIVER.data(), DRIVER.size()},
	} ; // Net profileへDisplay classを混入するZIP。
	expectIntelEthernetInfRejection( context, wrongClass) ;

	const ZipFixtureEntry wrongArchitecture[]{
		{"driver/sample.inf", X86_INF.data(), X86_INF.size()},
		{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
		{"driver/sample.sys", DRIVER.data(), DRIVER.size()},
	} ; // x64 sectionを持たないZIP。
	expectIntelEthernetInfRejection( context, wrongArchitecture) ;

	const ZipFixtureEntry arbitraryCommand[]{
		{"driver/sample.inf", COMMAND_INF.data(), COMMAND_INF.size()},
		{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
		{"driver/sample.sys", DRIVER.data(), DRIVER.size()},
	} ; // RunPostSetupCommandsを含むZIP。
	expectIntelEthernetInfRejection( context, arbitraryCommand) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一配布物のINF数上限と展開倍率上限を別々に超え、全体拒否とPnP未実行を確認する。大容量fileを実際に生成せず有限fixtureで検証する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetCountAndCapacityRejections( TestContext &context)
{
	constexpr std::size_t EXCESSIVE_INF_COUNT = 33U ;			// Intel profileの32 INF上限を一件超える数。
	std::array<std::string, EXCESSIVE_INF_COUNT> infPaths{} ;	// Entryが参照するpath所有領域。
	// Index順に全pathを確定してからviewを作り、vector構築中の参照切れを防ぐ。
	for( std::size_t index = 0U; index < infPaths.size(); ++index) {
		infPaths[index] = "driver/sample" + std::to_string( index) + ".inf" ;
	}

	std::vector<ZipFixtureEntry> excessiveEntries ;	// 33 INFと共有CAT／SYSのentry群。
	excessiveEntries.reserve( EXCESSIVE_INF_COUNT + 2U) ;
	// 現在のpathを順に参照し、Profile上限を超える全INFを同じ有効内容で追加する。
	for( const std::string &path : infPaths) {
		excessiveEntries.push_back( {path, VALID_INF.data(), VALID_INF.size()}) ;
	}

	excessiveEntries.push_back( {"driver/sample.cat", CATALOG.data(), CATALOG.size()}) ;
	excessiveEntries.push_back( {"driver/sample.sys", DRIVER.data(), DRIVER.size()}) ;
	IntelEthernetAuditFixtureOutcome excessiveOutcome ;	// INF数超過の観測値。
	const bool						 excessiveCreated =
		// 前提結果。
		runIntelEthernetArchiveFixture( excessiveEntries, excessiveOutcome) ;
	DRIVERCRATE_EXPECT( context, excessiveCreated) ;
	// INF数超過fixtureを作成できた場合にだけ全体拒否とrank未実行を検証する。
	if( excessiveCreated) {
		const NativeError tooLarge =
			// 期待値。
			static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
		DRIVERCRATE_EXPECT( context, excessiveOutcome.auditError == tooLarge) ;
		DRIVERCRATE_EXPECT( context, excessiveOutcome.audit.summary.state ==
										OfficialDriverPackageAuditState::REJECTED) ;
		DRIVERCRATE_EXPECT( context, excessiveOutcome.audit.auditedPackages.empty()) ;
		DRIVERCRATE_EXPECT( context, excessiveOutcome.rankCallCount == 0U) ;
	}

	constexpr std::size_t		 COMPRESSIBLE_BYTES = 1024U * 1024U ;	// 200倍上限を超える展開量。
	const std::vector<std::byte> compressible( COMPRESSIBLE_BYTES,
											  std::byte{0x41}) ;	// 小さく圧縮される架空data。
	const ZipFixtureEntry		 highRatioEntries[]{
		   {"driver/sample.inf", VALID_INF.data(), VALID_INF.size()},
		   {"driver/sample.cat", CATALOG.data(), CATALOG.size()},
		   {"driver/sample.sys", DRIVER.data(), DRIVER.size()},
		   {"driver/unused.bin", compressible.data(), compressible.size()},
	   } ; // INF閉包外も含むarchive全体の展開倍率拒否fixture。
	IntelEthernetAuditFixtureOutcome ratioOutcome ;	// 展開倍率超過の観測値。
	const bool						 ratioCreated =
		// 前提結果。
		runIntelEthernetArchiveFixture( highRatioEntries, ratioOutcome) ;
	DRIVERCRATE_EXPECT( context, ratioCreated) ;
	// 展開倍率超過fixtureを作成できた場合にだけ全体拒否とrank未実行を検証する。
	if( ratioCreated) {
		const NativeError tooLarge =
			// 期待値。
			static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
		DRIVERCRATE_EXPECT( context, ratioOutcome.auditError == tooLarge) ;
		DRIVERCRATE_EXPECT( context, ratioOutcome.audit.summary.state ==
										OfficialDriverPackageAuditState::REJECTED) ;
		DRIVERCRATE_EXPECT( context, ratioOutcome.audit.auditedPackages.empty()) ;
		DRIVERCRATE_EXPECT( context, ratioOutcome.rankCallCount == 0U) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 実署名・実fileを合格扱いにせず、後段状態機械へ必要な所有構造だけを作る。
 *
 * @param[in] packageCount 合成する内容監査済みINF数。本試験では1～2件。
 * @return PnP／rankとreport変換だけに用いる合成監査結果。
 */
//------------------------------------------------------------------------------
OfficialDriverPackageAudit fakeIntelEthernetRankInput( const std::size_t packageCount)
{
	OfficialDriverPackageAudit audit ;	// 各試験が所有する後段専用の合成監査結果。
	audit.scanSessionId			  = 811U ;
	audit.summary.state			  = OfficialDriverPackageAuditState::AUDITED ;
	audit.summary.infCount		  = packageCount ;
	audit.summary.auditedInfCount = packageCount ;
	// 各indexへ一つのNet INF構造を作り、複数INFとdeviceの組合せを再現する。
	for( std::size_t packageIndex = 0U; packageIndex < packageCount; ++packageIndex) {
		OfficialDriverClosure closure ;	// 現在indexの架空INF構造。
		closure.packages.push_back(
			{.className = L"Net", .hardwareIds = {L"PCI\\VEN_0000&DEV_0000"}}) ;
		audit.auditedPackages.push_back(
			{.workspace = std::make_unique<OfficialDownloadWorkspace>(),
			 .closure	= std::move( closure),
			 .profile	= OfficialDriverAuditProfile::INTEL_ETHERNET_SERVER2025}) ;
	}

	return audit ;
}

//------------------------------------------------------------------------------
/**
 * @brief 非機密reportのidentity・件数拒否だけを試験し、実PnP監査結果とはしない。
 *
 * @param[in] deviceIdentity 適用性合格対象としてcopyするopaque ID。
 * @return 一つのINFとdevice組合せが合格した合成監査結果。
 */
//------------------------------------------------------------------------------
OfficialDriverPackageAudit makeIntelEthernetReportAudit( std::wstring deviceIdentity)
{
	OfficialDriverPackageAudit audit =
		// Report変換に必要な一INF所有構造。
		fakeIntelEthernetRankInput( 1U) ;
	audit.applicability.state				= OfficialDriverApplicabilityState::APPLICABLE_TARGETS ;
	audit.applicability.examinedPairCount	= 1U ;
	audit.applicability.applicablePairCount = 1U ;
	OfficialDriverRankAudit rankAudit ;	// 実PnP IDを含まない合成合格値。
	rankAudit.decision = OfficialDriverRankDecision::APPLICABLE ;
	audit.rankApprovedTargets.push_back( {.deviceIdentity	  = std::move( deviceIdentity),
										 .auditedPackageIndex = 0U,
										 .rankAudit			  = rankAudit}) ;
	return audit ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実file、署名またはPnP合格を表さず、候補分類に必要な所有構造だけを作る。
 *
 * @param[in] deviceIdentities 合格組合せへ格納するopaque device ID群。
 * @param[in] candidateVersions 同じindexのINF原文version群。
 * @return 候補公開境界だけに用いる合成済み監査結果。
 */
//------------------------------------------------------------------------------
OfficialDriverPackageAudit makeIntelEthernetPublicationAudit(
	const std::span<const std::wstring> deviceIdentities,
	const std::span<const std::wstring> candidateVersions)
{
	// deviceとversionの対応が空または不一致なら候補分類fixtureを構築しない。
	if( deviceIdentities.empty() || deviceIdentities.size() != candidateVersions.size()) {
		throw std::logic_error( "invalid Intel Ethernet publication fixture") ;
	}

	OfficialDriverPackageAudit audit ;	// 今回の候補公開だけが所有する合成監査結果。
	audit.scanSessionId						= 811U ;
	audit.summary.state						= OfficialDriverPackageAuditState::AUDITED ;
	audit.summary.infCount					= candidateVersions.size() ;
	audit.summary.auditedInfCount			= candidateVersions.size() ;
	audit.applicability.state				= OfficialDriverApplicabilityState::APPLICABLE_TARGETS ;
	audit.applicability.examinedPairCount	= candidateVersions.size() ;
	audit.applicability.applicablePairCount = candidateVersions.size() ;
	// 一組合せごとに独立したINF閉包を作り、入力順の候補発行を再現する。
	for( std::size_t index = 0U; index < candidateVersions.size(); ++index) {
		OfficialDriverClosure closure ;	// 現在indexの架空INF閉包。
		closure.packages.push_back( {.className	   = L"Net",
									.providerName  = L"Intel",
									.driverDate	   = L"2026/09/01",
									.driverVersion = candidateVersions[index],
									.hardwareIds   = {L"PCI\\VEN_0000&DEV_0000"}}) ;
		audit.auditedPackages.push_back(
			{.workspace = std::make_unique<OfficialDownloadWorkspace>(),
			 .closure	= std::move( closure),
			 .profile	= OfficialDriverAuditProfile::INTEL_ETHERNET_SERVER2025}) ;
		OfficialDriverRankAudit rankAudit ;	// PnP文字列を含まない合成Applicable結果。
		rankAudit.decision = OfficialDriverRankDecision::APPLICABLE ;
		audit.rankApprovedTargets.push_back( {.deviceIdentity	  = deviceIdentities[index],
											 .auditedPackageIndex = index,
											 .rankAudit			  = rankAudit}) ;
	}

	return audit ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既存表示行IDを有限連番で作り、productionのreport変換を経由させる。
 *
 * @param[in] devices 同じscanの一意な非機密device群。
 * @param[in] audit 候補公開用の合成監査結果。
 * @return 候補発行前の監査合格report。
 */
//------------------------------------------------------------------------------
OfficialPreparationAuditReport makeIntelEthernetPublicationReport(
	const std::span<const OfficialCatalogDevice> devices, const OfficialDriverPackageAudit &audit)
{
	std::vector<std::wstring> candidateIdentities ;	// Device順の既存表示行ID群。
	candidateIdentities.reserve( devices.size()) ;
	// 既存行と新規発行候補のidentity空間を分離した連番を作る。
	for( std::size_t index = 0U; index < devices.size(); ++index) {
		candidateIdentities.push_back( L"existing-intel-candidate:" + std::to_wstring( index)) ;
	}

	return makeIntelEthernetPreparationAuditReport( 811U, L"intel-fixture-target", devices,
												   candidateIdentities, audit) ;
}

//------------------------------------------------------------------------------
/**
 * @brief DDInstall由来metadataの一致とtoken所有権を決定的に検証する。返却callbackは`callCount`の有効期間内だけ使用できる。
 *
 * @param[in,out] callCount 完了したbinding callback呼出し件数。
 * @param[in] firstToken 一件目へ返す0ではない架空token。
 * @param[in] mismatchProvider trueの場合は候補Providerを意図的に差し替える。
 * @return 実Driver Storeを呼ばず、入力metadataをbindingへcopyするcallback。
 */
//------------------------------------------------------------------------------
OfficialInfInstallBinder makeIntelEthernetPublicationBinder( std::size_t		   &callCount,
															const std::uint64_t firstToken,
															const bool			mismatchProvider)
{
	return [&callCount, nextToken = firstToken, mismatchProvider](
			   ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
			   const OfficialInfPackage &package, const std::wstring_view currentProvider,
			   const std::wstring_view currentVersion, const std::wstring_view currentDate,
			   const OfficialDriverRankAudit &rankAudit,
			   OfficialInfInstallBinding	 &binding) mutable -> NativeError {
		++callCount ;
		// 一回のcallbackごとに異なる架空token。
		binding.token = nextToken ;
		++nextToken ;
		binding.currentProvider = currentProvider ;
		binding.currentVersion	= currentVersion ;
		binding.currentDate		= currentDate ;
		binding.candidateProvider =
			mismatchProvider ? L"Fictional Global Provider" : package.providerName ;
		binding.candidateVersion = package.driverVersion ;
		binding.candidateDate	 = package.driverDate ;
		binding.rankAudit		 = rankAudit ;
		return 0 ;
	} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ候補版に対する現在版の大小と一致を、更新、旧版、再導入へ分類する。全候補は未推奨・未選択のまま保持routingと一対一になることも確認する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetCandidateVersionActions( TestContext &context)
{
	std::array						   devices{fakeIntelEthernetDevice(), fakeIntelEthernetDevice(),
					   // 三種類の現在版を持つ架空device群。
					   fakeIntelEthernetDevice()} ;
	const std::array<std::wstring, 3U> deviceIdentities{
		L"device:811:update", L"device:811:reinstall",
		L"device:811:downgrade"} ;	// 合格組合せと一致させるopaque ID群。
	const std::array<std::wstring, 3U> currentVersions{L"1.0.0.0", L"2.0.0.0",
													   L"3.0.0.0"} ;	// 候補版との比較用現在版群。
	// 各deviceへ一意なIDと比較可能な現在driver snapshotを設定する。
	for( std::size_t index = 0U; index < devices.size(); ++index) {
		devices[index].deviceIdentity  = deviceIdentities[index] ;
		devices[index].currentProvider = L"Intel" ;
		devices[index].currentVersion  = currentVersions[index] ;
		devices[index].currentDate	   = L"2025/09/01" ;
	}

	const std::array<std::wstring, 3U> candidateVersions{
		L"2.0.0.0", L"2.0.0.0", L"2.0.0.0"} ;	// 全deviceへ提示する同じ候補版。
	const OfficialDriverPackageAudit audit = makeIntelEthernetPublicationAudit(
		deviceIdentities, candidateVersions) ;	// 三組合せの合成監査結果。
	OfficialPreparationAuditReport report =
		// 発行前report。
		makeIntelEthernetPublicationReport( devices, audit) ;
	std::size_t					   bindingCallCount{} ;	// 発行できた組合せのcallback件数。
	const OfficialInfInstallBinder binder =
		// 正常binding。
		makeIntelEthernetPublicationBinder( bindingCallCount, 100U, false) ;
	const OfficialInfInstallBindingReleaser releaser = []( ScanSessionId, std::uint64_t) {
		return true ;
	} ; // 本正常系では呼ばれない解放境界。
	IntelEthernetPreparedInstallTargets routes ;	// 成功時の候補ID別routing。
	publishIntelEthernetPreparedCandidates( 811U, 1U, 4096U, devices, audit, binder, releaser,
										   report, routes) ;

	DRIVERCRATE_EXPECT( context,
					   report.publication.state ==
						   OfficialPreparationCandidatePublicationState::CANDIDATES_PUBLISHED) ;
	DRIVERCRATE_EXPECT( context, report.publication.examinedPairCount == 3U) ;
	DRIVERCRATE_EXPECT( context, report.publication.publishedCount == 3U) ;
	DRIVERCRATE_EXPECT( context, report.publication.excludedPairCount == 0U) ;
	DRIVERCRATE_EXPECT( context, report.publication.firstError == 0) ;
	DRIVERCRATE_EXPECT( context, report.candidatePublicationAttempted) ;
	DRIVERCRATE_EXPECT( context, report.publishedCandidates.size() == 3U) ;
	DRIVERCRATE_EXPECT( context, routes.size() == 3U) ;
	DRIVERCRATE_EXPECT( context, bindingCallCount == 3U) ;
	const std::array<DriverAction, 3U> expectedActions{
		DriverAction::UPDATE, DriverAction::REINSTALL,
		DriverAction::DOWNGRADE} ;	// 現在版と候補版の期待分類。
	// 入力順、版分類、未推奨状態およびroutingの一対一性を全候補で確認する。
	for( std::size_t index = 0U; index < report.publishedCandidates.size(); ++index) {
		const UpdateCandidate &candidate =
			report.publishedCandidates[index] ;	// 現在確認する発行候補。
		DRIVERCRATE_EXPECT( context, candidate.deviceIdentity == deviceIdentities[index]) ;
		DRIVERCRATE_EXPECT( context, candidate.version == candidateVersions[index]) ;
		DRIVERCRATE_EXPECT( context, candidate.action == expectedActions[index]) ;
		DRIVERCRATE_EXPECT( context,
						   candidate.defaultPreference == CandidateDefaultPreference::NONE) ;
		DRIVERCRATE_EXPECT( context, !candidate.recommended) ;
		DRIVERCRATE_EXPECT( context, candidate.installable) ;
		DRIVERCRATE_EXPECT( context, routes.contains( candidate.identity)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 候補版または現在版が厳密な4要素版でない組合せをbinding前に除外する。全件除外は検索失敗ではなく、候補なしと不正dataの理由を保持する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetUnknownVersionExclusion( TestContext &context)
{
	std::array						   devices{fakeIntelEthernetDevice(),
					   // 不明候補版と不明現在版の架空device群。
					   fakeIntelEthernetDevice()} ;
	const std::array<std::wstring, 2U> deviceIdentities{
		L"device:811:unknown-candidate",
		L"device:811:unknown-current"} ;	// 合格組合せ用opaque ID群。
	devices[0].deviceIdentity  = deviceIdentities[0] ;
	devices[0].currentProvider = L"Intel" ;
	devices[0].currentVersion  = L"1.0.0.0" ;
	devices[0].currentDate	   = L"2025/09/01" ;
	devices[1].deviceIdentity  = deviceIdentities[1] ;
	devices[1].currentProvider = L"Intel" ;
	devices[1].currentVersion  = L"unknown" ;
	devices[1].currentDate	   = L"2025/09/01" ;
	const std::array<std::wstring, 2U> candidateVersions{
		L"2.0.0", L"2.0.0.0"} ;	// 一件目だけが4要素を欠く候補版。
	const OfficialDriverPackageAudit audit = makeIntelEthernetPublicationAudit(
		deviceIdentities, candidateVersions) ;	// 二組合せの合成監査結果。
	OfficialPreparationAuditReport report =
		// 発行前report。
		makeIntelEthernetPublicationReport( devices, audit) ;
	std::size_t					   bindingCallCount{} ;	// 版拒否後は0のままであるcallback件数。
	const OfficialInfInstallBinder binder =
		// 未到達境界。
		makeIntelEthernetPublicationBinder( bindingCallCount, 200U, false) ;
	const OfficialInfInstallBindingReleaser releaser = []( ScanSessionId, std::uint64_t) {
		return true ;
	} ; // Token未発行のため未到達。
	IntelEthernetPreparedInstallTargets routes ;	// 全件除外時は空のrouting。
	publishIntelEthernetPreparedCandidates( 811U, 2U, 4096U, devices, audit, binder, releaser,
										   report, routes) ;

	const NativeError invalidData = static_cast<NativeError>(
		// 最初の版解析拒否HRESULT。
		HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
	DRIVERCRATE_EXPECT( context,
					   report.publication.state ==
						   OfficialPreparationCandidatePublicationState::NO_ELIGIBLE_CANDIDATES) ;
	DRIVERCRATE_EXPECT( context, report.publication.examinedPairCount == 2U) ;
	DRIVERCRATE_EXPECT( context, report.publication.publishedCount == 0U) ;
	DRIVERCRATE_EXPECT( context, report.publication.excludedPairCount == 2U) ;
	DRIVERCRATE_EXPECT( context, report.publication.firstError == invalidData) ;
	DRIVERCRATE_EXPECT( context, !report.candidatePublicationAttempted) ;
	DRIVERCRATE_EXPECT( context, report.publishedCandidates.empty()) ;
	DRIVERCRATE_EXPECT( context, routes.empty()) ;
	DRIVERCRATE_EXPECT( context, bindingCallCount == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 内容監査済みDDInstall由来ProviderとWindows node再固定値の差を全体拒否し、発行済みtokenを解放して部分候補を残さないことを確認する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetDdinstallBindingMismatch( TestContext &context)
{
	std::array devices{fakeIntelEthernetDevice()} ;	// 一件の正常系列device。
	devices[0].deviceIdentity  = L"device:811:ddinstall-mismatch" ;
	devices[0].currentProvider = L"Intel" ;
	devices[0].currentVersion  = L"1.0.0.0" ;
	devices[0].currentDate	   = L"2025/09/01" ;
	const std::array<std::wstring, 1U> deviceIdentities{
		devices[0].deviceIdentity} ;	// 合格組合せへ渡すopaque ID。
	const std::array<std::wstring, 1U> candidateVersions{
		L"2.0.0.0"} ;	// 内容監査済みDDInstall候補版。
	const OfficialDriverPackageAudit audit = makeIntelEthernetPublicationAudit(
		deviceIdentities, candidateVersions) ;	// 一組合せの合成監査結果。
	OfficialPreparationAuditReport report =
		// 発行前report。
		makeIntelEthernetPublicationReport( devices, audit) ;
	std::size_t					   bindingCallCount{} ;	// 差替え値を返したcallback件数。
	const OfficialInfInstallBinder binder =
		// Provider差替え。
		makeIntelEthernetPublicationBinder( bindingCallCount, 300U, true) ;
	std::size_t	  releaseCallCount{} ;	// 全体拒否で解放されたtoken件数。
	std::uint64_t releasedToken{} ;		// 解放callbackへ渡された最後の架空token。
	const OfficialInfInstallBindingReleaser releaser = [&releaseCallCount,
														&releasedToken]( const ScanSessionId session,
																		const std::uint64_t token) {
		++releaseCallCount ;
		releasedToken = token ;
		return session == 811U ;
	} ; // 試験scopeだけ有効なtoken解放観測境界。
	IntelEthernetPreparedInstallTargets routes ;	// 全体拒否時は空のrouting。
	publishIntelEthernetPreparedCandidates( 811U, 3U, 4096U, devices, audit, binder, releaser,
										   report, routes) ;

	DRIVERCRATE_EXPECT( context, report.publication.state ==
									OfficialPreparationCandidatePublicationState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, report.publication.examinedPairCount == 1U) ;
	DRIVERCRATE_EXPECT( context, report.publication.publishedCount == 0U) ;
	DRIVERCRATE_EXPECT( context, report.publication.excludedPairCount == 1U) ;
	DRIVERCRATE_EXPECT( context,
					   report.publication.firstError == static_cast<NativeError>( E_UNEXPECTED)) ;
	DRIVERCRATE_EXPECT( context, !report.candidatePublicationAttempted) ;
	DRIVERCRATE_EXPECT( context, report.publishedCandidates.empty()) ;
	DRIVERCRATE_EXPECT( context, routes.empty()) ;
	DRIVERCRATE_EXPECT( context, bindingCallCount == 1U) ;
	DRIVERCRATE_EXPECT( context, releaseCallCount == 1U) ;
	DRIVERCRATE_EXPECT( context, releasedToken == 300U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Intel公式READMEが既知非対応とする二つのHPE表示だけをbinding前に除外する。監査合格と候補0件を別状態として保持することも確認する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetUnsupportedOemExclusion( TestContext &context)
{
	std::array						   devices{fakeIntelEthernetDevice(),
					   // 二つの既知非対応OEM device。
					   fakeIntelEthernetDevice()} ;
	const std::array<std::wstring, 2U> deviceIdentities{
		L"device:811:hpe-synergy", L"device:811:hpe-adapter"} ;	// 合格組合せ用opaque ID群。
	const std::array<std::wstring, 2U> unsupportedModels{
		L"HPE Synergy 4610C 10/25Gb Ethernet Adapter",
		L"HPE 10/25Gb Ethernet Adapter"} ;	// ADR 0132で固定した二つの完全一致表示。
	// 二つのOEM deviceへ有効な現在版を設定し、製品表示だけで除外させる。
	for( std::size_t index = 0U; index < devices.size(); ++index) {
		devices[index].deviceIdentity  = deviceIdentities[index] ;
		devices[index].model		   = unsupportedModels[index] ;
		devices[index].currentProvider = L"Intel" ;
		devices[index].currentVersion  = L"1.0.0.0" ;
		devices[index].currentDate	   = L"2025/09/01" ;
	}

	const std::array<std::wstring, 2U> candidateVersions{
		L"2.0.0.0", L"2.0.0.0"} ;	// 比較可能だがOEM policyで除外する候補版群。
	const OfficialDriverPackageAudit audit = makeIntelEthernetPublicationAudit(
		deviceIdentities, candidateVersions) ;	// 二組合せの合成監査結果。
	OfficialPreparationAuditReport report =
		// 発行前report。
		makeIntelEthernetPublicationReport( devices, audit) ;
	std::size_t					   bindingCallCount{} ;	// OEM除外後は0のままであるcallback件数。
	const OfficialInfInstallBinder binder =
		// 未到達境界。
		makeIntelEthernetPublicationBinder( bindingCallCount, 400U, false) ;
	const OfficialInfInstallBindingReleaser releaser = []( ScanSessionId, std::uint64_t) {
		return true ;
	} ; // Token未発行のため未到達。
	IntelEthernetPreparedInstallTargets routes ;	// 全件除外時は空のrouting。
	publishIntelEthernetPreparedCandidates( 811U, 4U, 4096U, devices, audit, binder, releaser,
										   report, routes) ;

	const NativeError notSupported = static_cast<NativeError>(
		// 最初の既知OEM除外HRESULT。
		HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
	DRIVERCRATE_EXPECT( context,
					   report.publication.state ==
						   OfficialPreparationCandidatePublicationState::NO_ELIGIBLE_CANDIDATES) ;
	DRIVERCRATE_EXPECT( context, report.publication.examinedPairCount == 2U) ;
	DRIVERCRATE_EXPECT( context, report.publication.publishedCount == 0U) ;
	DRIVERCRATE_EXPECT( context, report.publication.excludedPairCount == 2U) ;
	DRIVERCRATE_EXPECT( context, report.publication.firstError == notSupported) ;
	DRIVERCRATE_EXPECT( context, !report.candidatePublicationAttempted) ;
	DRIVERCRATE_EXPECT( context, report.publishedCandidates.empty()) ;
	DRIVERCRATE_EXPECT( context, routes.empty()) ;
	DRIVERCRATE_EXPECT( context, bindingCallCount == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じdeviceへ完全一致する原文版を持つ二INFから一候補だけを発行する。後続重複は新しいbindingを発行せず、最初のroutingを維持する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetDuplicateVersionExclusion( TestContext &context)
{
	std::array devices{fakeIntelEthernetDevice()} ;	// 二INFが適用可能な一つの架空device。
	devices[0].deviceIdentity  = L"device:811:duplicate-version" ;
	devices[0].currentProvider = L"Intel" ;
	devices[0].currentVersion  = L"1.0.0.0" ;
	devices[0].currentDate	   = L"2025/09/01" ;
	const std::array<std::wstring, 2U> deviceIdentities{
		devices[0].deviceIdentity,
		devices[0].deviceIdentity} ;	// 二つの合格INFを同じdeviceへ結び付けるID群。
	const std::array<std::wstring, 2U> candidateVersions{
		L"2.0.0.0", L"2.0.0.0"} ;	// 完全一致する二つの原文候補版。
	const OfficialDriverPackageAudit audit = makeIntelEthernetPublicationAudit(
		deviceIdentities, candidateVersions) ;	// 二INF合格の合成監査結果。
	OfficialPreparationAuditReport report =
		// 発行前report。
		makeIntelEthernetPublicationReport( devices, audit) ;
	std::size_t					   bindingCallCount{} ;	// 重複除外前の一件だけを数えるcallback件数。
	const OfficialInfInstallBinder binder =
		// 正常binding。
		makeIntelEthernetPublicationBinder( bindingCallCount, 500U, false) ;
	const OfficialInfInstallBindingReleaser releaser = []( ScanSessionId, std::uint64_t) {
		return true ;
	} ; // 部分成功では呼ばれない解放境界。
	IntelEthernetPreparedInstallTargets routes ;	// 一件だけを保持する候補routing。
	publishIntelEthernetPreparedCandidates( 811U, 5U, 4096U, devices, audit, binder, releaser,
										   report, routes) ;

	const NativeError duplicate = static_cast<NativeError>(
		// 後続重複の期待HRESULT。
		HRESULT_FROM_WIN32( ERROR_ALREADY_EXISTS)) ;
	DRIVERCRATE_EXPECT( context,
					   report.publication.state ==
						   OfficialPreparationCandidatePublicationState::CANDIDATES_PUBLISHED) ;
	DRIVERCRATE_EXPECT( context, report.publication.examinedPairCount == 2U) ;
	DRIVERCRATE_EXPECT( context, report.publication.publishedCount == 1U) ;
	DRIVERCRATE_EXPECT( context, report.publication.excludedPairCount == 1U) ;
	DRIVERCRATE_EXPECT( context, report.publication.firstError == duplicate) ;
	DRIVERCRATE_EXPECT( context, report.candidatePublicationAttempted) ;
	DRIVERCRATE_EXPECT( context, report.publishedCandidates.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, routes.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, bindingCallCount == 1U) ;
	DRIVERCRATE_EXPECT( context, routes.contains( report.publishedCandidates.front().identity)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 監査合格後にdevice状態が変化してbindingできない場合を候補0件として返す。全体処理失敗へ変換せず、最初の個別HRESULTを保持することを確認する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetBindingRejectionHasNoCandidates( TestContext &context)
{
	std::array devices{fakeIntelEthernetDevice()} ;	// Binding時に変化した一つの架空device。
	devices[0].deviceIdentity  = L"device:811:binding-rejected" ;
	devices[0].currentProvider = L"Intel" ;
	devices[0].currentVersion  = L"1.0.0.0" ;
	devices[0].currentDate	   = L"2025/09/01" ;
	const std::array<std::wstring, 1U> deviceIdentities{
		devices[0].deviceIdentity} ;	// 合格組合せへ渡すopaque ID。
	const std::array<std::wstring, 1U> candidateVersions{
		L"2.0.0.0"} ;	// Binding前までは有効な候補版。
	const OfficialDriverPackageAudit audit = makeIntelEthernetPublicationAudit(
		deviceIdentities, candidateVersions) ;	// 一組合せの合成監査結果。
	OfficialPreparationAuditReport report =
		// 発行前report。
		makeIntelEthernetPublicationReport( devices, audit) ;
	std::size_t					   bindingCallCount{} ;	// 状態変更拒否を返すcallback件数。
	const OfficialInfInstallBinder binder =
		[&bindingCallCount]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
							const OfficialInfPackage &, std::wstring_view, std::wstring_view,
							std::wstring_view, const OfficialDriverRankAudit &,
							OfficialInfInstallBinding &) -> NativeError {
		++bindingCallCount ;
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_STATE)) ;
	} ; // 実PnPを呼ばずdevice状態変更を返すbinding境界。
	const OfficialInfInstallBindingReleaser releaser = []( ScanSessionId, std::uint64_t) {
		return true ;
	} ; // Token未発行のため未到達。
	IntelEthernetPreparedInstallTargets routes ;	// 個別拒否後は空のrouting。
	publishIntelEthernetPreparedCandidates( 811U, 6U, 4096U, devices, audit, binder, releaser,
										   report, routes) ;

	const NativeError changedState = static_cast<NativeError>(
		// 個別binding拒否の期待HRESULT。
		HRESULT_FROM_WIN32( ERROR_INVALID_STATE)) ;
	DRIVERCRATE_EXPECT( context,
					   report.publication.state ==
						   OfficialPreparationCandidatePublicationState::NO_ELIGIBLE_CANDIDATES) ;
	DRIVERCRATE_EXPECT( context, report.publication.examinedPairCount == 1U) ;
	DRIVERCRATE_EXPECT( context, report.publication.publishedCount == 0U) ;
	DRIVERCRATE_EXPECT( context, report.publication.excludedPairCount == 1U) ;
	DRIVERCRATE_EXPECT( context, report.publication.firstError == changedState) ;
	DRIVERCRATE_EXPECT( context, !report.candidatePublicationAttempted) ;
	DRIVERCRATE_EXPECT( context, report.publishedCandidates.empty()) ;
	DRIVERCRATE_EXPECT( context, routes.empty()) ;
	DRIVERCRATE_EXPECT( context, bindingCallCount == 1U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Install直前rankが監査時と同じでも、Driver Storeが現在driver metadataの変化を検出した場合は`ERROR_RETRY`を保持して導入失敗にする。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetSameRankCurrentDriverChange( TestContext &context)
{
	IntelEthernetPreparedInstallFixture fixture ;	// 本test中だけ保持する外側fileとrouting。
	const bool							initialized =
		// 前提構築結果。
		initializeIntelEthernetPreparedInstallFixture( fixture, 1U) ;
	DRIVERCRATE_EXPECT( context, initialized) ;
	// Fixtureを構築できない場合は不正な参照による後続失敗を避ける。
	if( !initialized) {
		return ;
	}

	std::size_t					reverificationCalls{} ;	// INF閉包再検証callbackの呼出し回数。
	std::size_t					rankCalls{} ;			// Install直前rank再監査callbackの呼出し回数。
	std::size_t					installCalls{} ;		// 保持bindingを受けた指定導入callbackの呼出し回数。
	std::uint64_t				observedToken{} ;		// 指定導入callbackへ渡されたopaque binding token。
	const PreparedInfReverifier reverifier =
		[&reverificationCalls]( const OfficialAuditedInfPackage &) -> NativeError {
		++reverificationCalls ;
		return 0 ;
	} ; // 本testでは閉包再検証を成功させ、後段binding再確認へ到達させる。
	const OfficialDriverRankAudit expectedRank =
		// 発行時の完全rank snapshot。
		fixture.targets.begin()->second.prepared.rankAudit ;
	const OfficialInfRankAuditor rankAuditor =
		[&rankCalls, &expectedRank]( ScanSessionId, std::wstring_view,
									const OfficialDownloadWorkspace &, const OfficialInfPackage &,
									OfficialDriverRankAudit &rank) -> NativeError {
		++rankCalls ;
		rank = expectedRank ;
		return 0 ;
	} ; // Rankだけは変化させず、現在driver metadata差を次の境界で模擬する。
	const NativeError changedState = static_cast<NativeError>(
		// Driver Store再固定が返す状態変化HRESULT。
		HRESULT_FROM_WIN32( ERROR_RETRY)) ;
	const OfficialBoundInfInstaller installer =
		[&installCalls, &observedToken,
		 changedState]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
					   const OfficialInfPackage &, const OfficialInfInstallBinding &binding,
					   std::uintptr_t, bool &) -> NativeError {
		++installCalls ;
		observedToken = binding.token ;
		return changedState ;
	} ; // 実SetupAPIを呼ばず、現在driver metadata差を検出したbinding再確認を模擬する。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {
	} ; // 共通executorが要求する同期的な進捗受信境界。
	const IntelEthernetPreparedInstallContext installContext{
		.scanSessionId	 = fixture.acquisition.scanSessionId,
		.acquisition	 = &fixture.acquisition,
		.targets		 = &fixture.targets,
		.auditedPackages = std::span<const OfficialAuditedInfPackage>( fixture.auditedPackages),
		.windowsServer	 = true,
		.windowsBuild	 = 26100U,
		.sourceEvidenceConfirmed = true,
	} ; // 所有fixtureの有効期間内だけ使用する非所有context。
	const InstallResult result = executeIntelEthernetPreparedInstall(
		installContext, fixture.identities, reverifier, rankAuditor, installer, 0U,
		progress) ;	// 外側hashからbinding再確認までのIntel固有経路を実行する。

	DRIVERCRATE_EXPECT( context, !result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.downloadOutcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, result.downloadError == 0) ;
	DRIVERCRATE_EXPECT( context, result.installOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, result.installError == changedState) ;
	DRIVERCRATE_EXPECT( context, !result.rebootRequired) ;
	DRIVERCRATE_EXPECT( context, result.updates.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( !result.updates.empty()) {
		const UpdateExecutionResult &update = result.updates.front() ;	// 一件の個別結果。
		DRIVERCRATE_EXPECT( context, update.downloadOutcome == OutcomeCode::SUCCESS) ;
		DRIVERCRATE_EXPECT( context, update.installOutcome == OutcomeCode::FAILURE) ;
		DRIVERCRATE_EXPECT( context, update.installError == changedState) ;
		DRIVERCRATE_EXPECT( context, !update.rebootRequired) ;
	}

	DRIVERCRATE_EXPECT( context, reverificationCalls == 1U) ;
	DRIVERCRATE_EXPECT( context, rankCalls == 1U) ;
	DRIVERCRATE_EXPECT( context, installCalls == 1U) ;
	DRIVERCRATE_EXPECT( context, observedToken == fixture.targets.begin()->second.binding.token) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Intel adapterが発行時のbinding値を改変せず指定導入境界へ渡し、Windows node再固定差の`ERROR_RETRY`を候補別結果へ保持することを確認する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetStagedNodeChangeRejected( TestContext &context)
{
	IntelEthernetPreparedInstallFixture fixture ;	// 本test中だけ保持する外側fileとrouting。
	const bool							initialized =
		// 前提構築結果。
		initializeIntelEthernetPreparedInstallFixture( fixture, 1U) ;
	DRIVERCRATE_EXPECT( context, initialized) ;
	// Fixtureを構築できない場合は後続callbackを開始しない。
	if( !initialized) {
		return ;
	}

	const IntelEthernetPreparedInstallTarget &expectedTarget =
		// 発行時に固定したINF、device、bindingの正本。
		fixture.targets.begin()->second ;
	const PreparedInfReverifier reverifier = []( const OfficialAuditedInfPackage &) -> NativeError {
		return 0 ;
	} ; // 閉包再検証成功。
	const OfficialInfRankAuditor rankAuditor =
		[&expectedTarget]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
						  const OfficialInfPackage &,
						  OfficialDriverRankAudit &rank) -> NativeError {
		rank = expectedTarget.prepared.rankAudit ;
		return 0 ;
	} ; // Staging直前まで発行時と同じrankを維持する。
	bool			  bindingForwarded{} ;	// 全非機密binding値が改変されず渡された場合はtrue。
	std::size_t		  installCalls{} ;		// Windows node差を返す指定導入callbackの呼出し回数。
	const NativeError nodeChanged = static_cast<NativeError>(
		// Staging後のWindows node再固定差の期待値。
		HRESULT_FROM_WIN32( ERROR_RETRY)) ;
	const OfficialBoundInfInstaller installer =
		[&bindingForwarded, &installCalls, &expectedTarget, nodeChanged](
			const ScanSessionId session, const std::wstring_view		 deviceIdentity,
			const OfficialDownloadWorkspace &, const OfficialInfPackage &package,
			const OfficialInfInstallBinding &binding, std::uintptr_t, bool &) -> NativeError {
		++installCalls ;
		bindingForwarded =
			session == 821U && deviceIdentity == expectedTarget.prepared.deviceIdentity &&
			package.providerName == L"Intel" && package.driverVersion == L"2.0.0.0" &&
			binding.token == expectedTarget.binding.token &&
			binding.currentProvider == expectedTarget.binding.currentProvider &&
			binding.currentVersion == expectedTarget.binding.currentVersion &&
			binding.currentDate == expectedTarget.binding.currentDate &&
			binding.candidateProvider == expectedTarget.binding.candidateProvider &&
			binding.candidateVersion == expectedTarget.binding.candidateVersion &&
			binding.candidateDate == expectedTarget.binding.candidateDate &&
			binding.rankAudit.currentRank == expectedTarget.binding.rankAudit.currentRank &&
			binding.rankAudit.candidateRank == expectedTarget.binding.rankAudit.candidateRank ;
		return nodeChanged ;
	} ; // 実SetupAPIを呼ばず、staged INFのWindows node差だけを模擬する。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {
	} ; // 共通executorが要求する同期的な進捗受信境界。
	const IntelEthernetPreparedInstallContext installContext{
		.scanSessionId	 = fixture.acquisition.scanSessionId,
		.acquisition	 = &fixture.acquisition,
		.targets		 = &fixture.targets,
		.auditedPackages = std::span<const OfficialAuditedInfPackage>( fixture.auditedPackages),
		.windowsServer	 = true,
		.windowsBuild	 = 26100U,
		.sourceEvidenceConfirmed = true,
	} ; // 所有fixtureの有効期間内だけ使用する非所有context。
	const InstallResult result = executeIntelEthernetPreparedInstall(
		installContext, fixture.identities, reverifier, rankAuditor, installer, 0U,
		progress) ;	// Intel adapterから指定導入境界までを実行する。

	DRIVERCRATE_EXPECT( context, bindingForwarded) ;
	DRIVERCRATE_EXPECT( context, installCalls == 1U) ;
	DRIVERCRATE_EXPECT( context, !result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.downloadOutcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, result.installOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, result.installError == nodeChanged) ;
	DRIVERCRATE_EXPECT( context, result.updates.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( !result.updates.empty()) {
		const UpdateExecutionResult &update = result.updates.front() ;	// Node差の個別結果。
		DRIVERCRATE_EXPECT( context, update.downloadOutcome == OutcomeCode::SUCCESS) ;
		DRIVERCRATE_EXPECT( context, update.installOutcome == OutcomeCode::FAILURE) ;
		DRIVERCRATE_EXPECT( context, update.installError == nodeChanged) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 取得後の外側hash snapshot差はINF再検証前、INF署名差はrank再監査前に拒否し、download結果とinstall結果を混同しないことを確認する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetHashAndSignatureChangesRejected( TestContext &context)
{
	IntelEthernetPreparedInstallFixture hashFixture ;	// 外側hash差を注入する一scan保持物。
	const bool							hashInitialized =
		// 前提構築結果。
		initializeIntelEthernetPreparedInstallFixture( hashFixture, 1U) ;
	DRIVERCRATE_EXPECT( context, hashInitialized) ;
	// 外側fileがない場合はhash拒否順序を検証できない。
	if( !hashInitialized) {
		return ;
	}

	hashFixture.acquisition.sha256.front() =
		// Snapshot差の注入。
		hashFixture.acquisition.sha256.front() == L'a' ? L'b' : L'a' ;
	std::size_t hashReverificationCalls{} ;	// Hash拒否後のINF再検証callback呼出し回数。
	std::size_t hashRankCalls{} ;			// Hash拒否後のrank callback呼出し回数。
	std::size_t hashInstallCalls{} ;		// Hash拒否後の指定導入callback呼出し回数。
	const PreparedInfReverifier hashReverifier =
		[&hashReverificationCalls]( const OfficialAuditedInfPackage &) -> NativeError {
		++hashReverificationCalls ;
		return static_cast<NativeError>( E_UNEXPECTED) ;
	} ; // 外側hash差の後には呼ばれてはならない再検証境界。
	const OfficialInfRankAuditor hashRank =
		[&hashRankCalls]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
						 const OfficialInfPackage &, OfficialDriverRankAudit &) -> NativeError {
		++hashRankCalls ;
		return static_cast<NativeError>( E_UNEXPECTED) ;
	} ; // 外側hash差の後には呼ばれてはならないrank境界。
	const OfficialBoundInfInstaller hashInstaller =
		[&hashInstallCalls]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
							const OfficialInfPackage &, const OfficialInfInstallBinding &,
							std::uintptr_t, bool &) -> NativeError {
		++hashInstallCalls ;
		return static_cast<NativeError>( E_UNEXPECTED) ;
	} ; // 外側hash差の後には呼ばれてはならない指定導入境界。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {
	} ; // 共通executorが要求する同期的な進捗受信境界。
	const IntelEthernetPreparedInstallContext hashContext{
		.scanSessionId	 = hashFixture.acquisition.scanSessionId,
		.acquisition	 = &hashFixture.acquisition,
		.targets		 = &hashFixture.targets,
		.auditedPackages = std::span<const OfficialAuditedInfPackage>( hashFixture.auditedPackages),
		.windowsServer	 = true,
		.windowsBuild	 = 26100U,
		.sourceEvidenceConfirmed = true,
	} ; // Hash差以外を成立させた非所有context。
	const InstallResult hashResult = executeIntelEthernetPreparedInstall(
		hashContext, hashFixture.identities, hashReverifier, hashRank, hashInstaller, 0U,
		progress) ;	// 実fileと異なるsnapshotによるfail-closed経路を実行する。

	DRIVERCRATE_EXPECT( context, !hashResult.succeeded) ;
	DRIVERCRATE_EXPECT( context, hashResult.downloadOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, hashResult.downloadError != 0) ;
	DRIVERCRATE_EXPECT( context, hashResult.installOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, hashResult.installError == hashResult.downloadError) ;
	DRIVERCRATE_EXPECT( context, hashReverificationCalls == 0U) ;
	DRIVERCRATE_EXPECT( context, hashRankCalls == 0U) ;
	DRIVERCRATE_EXPECT( context, hashInstallCalls == 0U) ;

	IntelEthernetPreparedInstallFixture signatureFixture ;	// INF署名差を注入する保持物。
	// 署名境界を差し替えるIntel Ethernet導入fixtureの初期化結果。
	const bool							signatureInitialized =
		initializeIntelEthernetPreparedInstallFixture( signatureFixture, 1U) ;
	DRIVERCRATE_EXPECT( context, signatureInitialized) ;
	// 外側fileがない場合はINF再検証の到達順序を確認できない。
	if( !signatureInitialized) {
		return ;
	}

	std::size_t		  signatureReverificationCalls{} ;	// 署名差を返す再検証callback呼出し回数。
	std::size_t		  signatureRankCalls{} ;			// 署名拒否後のrank callback呼出し回数。
	std::size_t		  signatureInstallCalls{} ;			// 署名拒否後の指定導入callback呼出し回数。
	const NativeError badSignature =
		// INF／CAT再検証差の架空HRESULT。
		static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	const PreparedInfReverifier signatureReverifier =
		[&signatureReverificationCalls,
		 badSignature]( const OfficialAuditedInfPackage &) -> NativeError {
		++signatureReverificationCalls ;
		return badSignature ;
	} ; // 実証明書を使用せず再検証時の署名／member hash差を模擬する。
	const OfficialInfRankAuditor signatureRank =
		[&signatureRankCalls]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
							  const OfficialInfPackage &,
							  OfficialDriverRankAudit &) -> NativeError {
		++signatureRankCalls ;
		return static_cast<NativeError>( E_UNEXPECTED) ;
	} ; // INF署名差の後には呼ばれてはならないrank境界。
	const OfficialBoundInfInstaller signatureInstaller =
		[&signatureInstallCalls]( ScanSessionId, std::wstring_view,
								 const OfficialDownloadWorkspace &, const OfficialInfPackage &,
								 const OfficialInfInstallBinding &, std::uintptr_t,
								 bool &) -> NativeError {
		++signatureInstallCalls ;
		return static_cast<NativeError>( E_UNEXPECTED) ;
	} ; // INF署名差の後には呼ばれてはならない指定導入境界。
	const IntelEthernetPreparedInstallContext signatureContext{
		.scanSessionId = signatureFixture.acquisition.scanSessionId,
		.acquisition   = &signatureFixture.acquisition,
		.targets	   = &signatureFixture.targets,
		.auditedPackages =
			std::span<const OfficialAuditedInfPackage>( signatureFixture.auditedPackages),
		.windowsServer			 = true,
		.windowsBuild			 = 26100U,
		.sourceEvidenceConfirmed = true,
	} ; // 再検証callback以外を成立させた非所有context。
	const InstallResult signatureResult = executeIntelEthernetPreparedInstall(
		signatureContext, signatureFixture.identities, signatureReverifier, signatureRank,
		signatureInstaller, 0U, progress) ;	// 外側hash成功後のINF再検証拒否を実行する。

	DRIVERCRATE_EXPECT( context, !signatureResult.succeeded) ;
	DRIVERCRATE_EXPECT( context, signatureResult.downloadOutcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, signatureResult.downloadError == 0) ;
	DRIVERCRATE_EXPECT( context, signatureResult.installOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, signatureResult.installError == badSignature) ;
	DRIVERCRATE_EXPECT( context, signatureReverificationCalls == 1U) ;
	DRIVERCRATE_EXPECT( context, signatureRankCalls == 0U) ;
	DRIVERCRATE_EXPECT( context, signatureInstallCalls == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Driver Storeへのstagingを終えた後で指定device導入が失敗した場合も、download成功とinstall失敗を分離し、再起動要求を誤って立てない。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetDeviceInstallFailureAfterStaging( TestContext &context)
{
	IntelEthernetPreparedInstallFixture fixture ;	// 本test中だけ保持する外側fileとrouting。
	const bool							initialized =
		// 前提構築結果。
		initializeIntelEthernetPreparedInstallFixture( fixture, 1U) ;
	DRIVERCRATE_EXPECT( context, initialized) ;
	// Fixtureを構築できない場合はsystem変更段階の模擬を開始しない。
	if( !initialized) {
		return ;
	}

	std::size_t reverificationCalls{} ;	// INF閉包再検証callbackの呼出し回数。
	std::size_t rankCalls{} ;			// Install直前rank再監査callbackの呼出し回数。
	std::size_t installCalls{} ;		// Staging後失敗を返す指定導入callbackの呼出し回数。
	bool		stagingCompleted{} ;	// Fake Driver Storeでstaging完了まで到達した場合はtrue。
	const PreparedInfReverifier reverifier =
		[&reverificationCalls]( const OfficialAuditedInfPackage &) -> NativeError {
		++reverificationCalls ;
		return 0 ;
	} ; // 本testでは閉包再検証を成功させる。
	const OfficialDriverRankAudit expectedRank =
		// 発行時の完全rank snapshot。
		fixture.targets.begin()->second.prepared.rankAudit ;
	const OfficialInfRankAuditor rankAuditor =
		[&rankCalls, &expectedRank]( ScanSessionId, std::wstring_view,
									const OfficialDownloadWorkspace &, const OfficialInfPackage &,
									OfficialDriverRankAudit &rank) -> NativeError {
		++rankCalls ;
		rank = expectedRank ;
		return 0 ;
	} ; // Staging前のrank再監査を成功させる。
	const NativeError deviceInstallFailure =
		// DiInstallDevice失敗を模擬する架空HRESULT。
		static_cast<NativeError>( E_FAIL) ;
	const OfficialBoundInfInstaller installer =
		[&installCalls, &stagingCompleted,
		 deviceInstallFailure]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
							   const OfficialInfPackage &, const OfficialInfInstallBinding &,
							   std::uintptr_t, bool &rebootRequired) -> NativeError {
		++installCalls ;
		stagingCompleted = true ;
		rebootRequired	 = false ;
		return deviceInstallFailure ;
	} ; // SetupCopyOEMInfW成功後にDiInstallDeviceだけが失敗する順序を模擬する。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {
	} ; // 共通executorが要求する同期的な進捗受信境界。
	const IntelEthernetPreparedInstallContext installContext{
		.scanSessionId	 = fixture.acquisition.scanSessionId,
		.acquisition	 = &fixture.acquisition,
		.targets		 = &fixture.targets,
		.auditedPackages = std::span<const OfficialAuditedInfPackage>( fixture.auditedPackages),
		.windowsServer	 = true,
		.windowsBuild	 = 26100U,
		.sourceEvidenceConfirmed = true,
	} ; // 所有fixtureの有効期間内だけ使用する非所有context。
	const InstallResult result = executeIntelEthernetPreparedInstall(
		installContext, fixture.identities, reverifier, rankAuditor, installer, 0U,
		progress) ;	// 再検証成功から指定device導入失敗までを実行する。

	DRIVERCRATE_EXPECT( context, stagingCompleted) ;
	DRIVERCRATE_EXPECT( context, reverificationCalls == 1U) ;
	DRIVERCRATE_EXPECT( context, rankCalls == 1U) ;
	DRIVERCRATE_EXPECT( context, installCalls == 1U) ;
	DRIVERCRATE_EXPECT( context, !result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.downloadOutcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, result.downloadError == 0) ;
	DRIVERCRATE_EXPECT( context, result.installOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, result.installError == deviceInstallFailure) ;
	DRIVERCRATE_EXPECT( context, !result.rebootRequired) ;
	DRIVERCRATE_EXPECT( context, result.updates.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( !result.updates.empty()) {
		const UpdateExecutionResult &update = result.updates.front() ;	// Staging後失敗の個別結果。
		DRIVERCRATE_EXPECT( context, update.downloadOutcome == OutcomeCode::SUCCESS) ;
		DRIVERCRATE_EXPECT( context, update.installOutcome == OutcomeCode::FAILURE) ;
		DRIVERCRATE_EXPECT( context, update.installError == deviceInstallFailure) ;
		DRIVERCRATE_EXPECT( context, !update.rebootRequired) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Intel Ethernet Server候補をWindows ClientまたはServer 2025以外のbuildで実行した場合、外側fileおよび全Windows
 *        callbackより前に拒否する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetServerEnvironmentRejections( TestContext &context)
{
	IntelEthernetPreparedInstallFixture fixture ;	// OS拒否間で共有する外側fileとrouting。
	const bool							initialized =
		// 前提構築結果。
		initializeIntelEthernetPreparedInstallFixture( fixture, 1U) ;
	DRIVERCRATE_EXPECT( context, initialized) ;
	// Fixtureを構築できない場合は拒否順序を検証しない。
	if( !initialized) {
		return ;
	}

	// 指定OSを一回実行し、system変更につながる全callbackが未到達であることを検証する処理。
	const auto verifyRejection = [&context, &fixture]( const bool		  windowsServer,
													  const std::uint32_t windowsBuild) {
		std::size_t					reverificationCalls{} ;	// INF閉包再検証callbackの呼出し回数。
		std::size_t					rankCalls{} ;			// Install直前rank callbackの呼出し回数。
		std::size_t					installCalls{} ;		// 指定導入callbackの呼出し回数。
		std::size_t					progressCalls{} ;		// 進捗callbackの呼出し回数。
		const PreparedInfReverifier reverifier =
			[&reverificationCalls]( const OfficialAuditedInfPackage &) -> NativeError {
			++reverificationCalls ;
			return static_cast<NativeError>( E_UNEXPECTED) ;
		} ; // OS拒否後には到達してはならない閉包再検証境界。
		const OfficialInfRankAuditor rankAuditor =
			[&rankCalls]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
						 const OfficialInfPackage &, OfficialDriverRankAudit &) -> NativeError {
			++rankCalls ;
			return static_cast<NativeError>( E_UNEXPECTED) ;
		} ; // OS拒否後には到達してはならないPnP／rank境界。
		const OfficialBoundInfInstaller installer =
			[&installCalls]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
							const OfficialInfPackage &, const OfficialInfInstallBinding &,
							std::uintptr_t, bool &) -> NativeError {
			++installCalls ;
			return static_cast<NativeError>( E_UNEXPECTED) ;
		} ; // OS拒否後には到達してはならない指定導入境界。
		const ProviderProgressCallback progress = [&progressCalls]( const ProviderProgress &) {
			++progressCalls ;
		} ; // 進捗受信境界。
		const IntelEthernetPreparedInstallContext installContext{
			.scanSessionId	 = fixture.acquisition.scanSessionId,
			.acquisition	 = &fixture.acquisition,
			.targets		 = &fixture.targets,
			.auditedPackages = std::span<const OfficialAuditedInfPackage>( fixture.auditedPackages),
			.windowsServer	 = windowsServer,
			.windowsBuild	 = windowsBuild,
			.sourceEvidenceConfirmed = true,
		} ; // OS条件だけを不成立にした非所有context。
		const InstallResult result = executeIntelEthernetPreparedInstall(
			installContext, fixture.identities, reverifier, rankAuditor, installer, 0U,
			progress) ;	// 実fileやWindows APIへ到達しないOS拒否経路。

		DRIVERCRATE_EXPECT( context, !result.succeeded) ;
		DRIVERCRATE_EXPECT( context, result.downloadOutcome == OutcomeCode::FAILURE) ;
		DRIVERCRATE_EXPECT( context, result.downloadError == static_cast<NativeError>( E_INVALIDARG)) ;
		DRIVERCRATE_EXPECT( context, result.installOutcome == OutcomeCode::FAILURE) ;
		DRIVERCRATE_EXPECT( context, result.installError == static_cast<NativeError>( E_INVALIDARG)) ;
		DRIVERCRATE_EXPECT( context, result.updates.size() == 1U) ;
		DRIVERCRATE_EXPECT( context, reverificationCalls == 0U) ;
		DRIVERCRATE_EXPECT( context, rankCalls == 0U) ;
		DRIVERCRATE_EXPECT( context, installCalls == 0U) ;
		DRIVERCRATE_EXPECT( context, progressCalls == 0U) ;
	} ;

	// Windows Clientでは同じbuild番号でも拒否する。
	verifyRejection( false, 26100U) ;
	// Windows ServerでもServer 2025未満のbuildを拒否する。
	verifyRejection( true, 26099U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ検証済みINFを選択した2 deviceの一方が成功して再起動を要求し、他方が失敗した場合の候補順結果と全体集約を確認する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetPartialFailureAndRebootAggregation( TestContext &context)
{
	IntelEthernetPreparedInstallFixture fixture ;	// 二device分の外側file、INF、routing。
	const bool							initialized =
		// 前提構築結果。
		initializeIntelEthernetPreparedInstallFixture( fixture, 2U) ;
	DRIVERCRATE_EXPECT( context, initialized) ;
	// 二device routingを構築できない場合は個別結果を参照しない。
	if( !initialized) {
		return ;
	}

	std::size_t					reverificationCalls{} ;	// 共有INF閉包の再検証callback呼出し回数。
	std::size_t					rankCalls{} ;			// Device別rank再監査callback呼出し回数。
	std::size_t					installCalls{} ;		// Device別指定導入callback呼出し回数。
	const PreparedInfReverifier reverifier =
		[&reverificationCalls]( const OfficialAuditedInfPackage &) -> NativeError {
		++reverificationCalls ;
		return 0 ;
	} ; // 二deviceが共有する同じINF閉包を正常とする。
	const OfficialDriverRankAudit expectedRank =
		// 固定rank snapshot。
		fixture.targets.at( fixture.identities.front()).prepared.rankAudit ;
	const OfficialInfRankAuditor rankAuditor =
		[&rankCalls, &expectedRank]( ScanSessionId, std::wstring_view,
									const OfficialDownloadWorkspace &, const OfficialInfPackage &,
									OfficialDriverRankAudit &rank) -> NativeError {
		++rankCalls ;
		rank = expectedRank ;
		return 0 ;
	} ; // 二deviceとも発行時rankから変化していない状態を返す。
	const std::wstring firstDevice =
		fixture.targets.at( fixture.identities.front())
			.prepared.deviceIdentity ;	// 成功と再起動を割り当てる一件目のdevice ID。
	const NativeError secondFailure =
		// 二件目だけに返す指定導入失敗。
		static_cast<NativeError>( E_FAIL) ;
	const OfficialBoundInfInstaller installer =
		[&installCalls, &firstDevice,
		 secondFailure]( ScanSessionId, const std::wstring_view deviceIdentity,
						const OfficialDownloadWorkspace &, const OfficialInfPackage &,
						const OfficialInfInstallBinding &, std::uintptr_t,
						bool &rebootRequired) -> NativeError {
		++installCalls ;
		// 先頭deviceだけを再起動付き成功とし、後続失敗との結果集約を検証する。
		if( deviceIdentity == firstDevice) {
			rebootRequired = true ;
			// 一件目だけ正常導入と再起動要求を返す。
			return 0 ;
		}

		rebootRequired = false ;
		// 二件目の個別失敗後も全体結果を確定させる。
		return secondFailure ;
	} ; // 実Windows変更を行わない二device指定導入境界。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {
	} ; // 共通executorが要求する同期的な進捗受信境界。
	const IntelEthernetPreparedInstallContext installContext{
		.scanSessionId	 = fixture.acquisition.scanSessionId,
		.acquisition	 = &fixture.acquisition,
		.targets		 = &fixture.targets,
		.auditedPackages = std::span<const OfficialAuditedInfPackage>( fixture.auditedPackages),
		.windowsServer	 = true,
		.windowsBuild	 = 26100U,
		.sourceEvidenceConfirmed = true,
	} ; // Server 2025条件と全監査根拠を成立させた非所有context。
	const InstallResult result = executeIntelEthernetPreparedInstall(
		installContext, fixture.identities, reverifier, rankAuditor, installer, 0U,
		progress) ;	// 二deviceの成功と失敗を同じ入力順で実行する。

	DRIVERCRATE_EXPECT( context, !result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.downloadOutcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, result.downloadError == 0) ;
	DRIVERCRATE_EXPECT( context, result.installOutcome == OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
	DRIVERCRATE_EXPECT( context, result.installError == secondFailure) ;
	DRIVERCRATE_EXPECT( context, result.rebootRequired) ;
	DRIVERCRATE_EXPECT( context, result.updates.size() == 2U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( result.updates.size() == 2U) {
		const UpdateExecutionResult &first	= result.updates[0] ;	// 成功した一件目の個別結果。
		const UpdateExecutionResult &second = result.updates[1] ;	// 失敗した二件目の個別結果。
		DRIVERCRATE_EXPECT( context, first.identity == fixture.identities[0]) ;
		DRIVERCRATE_EXPECT( context, first.downloadOutcome == OutcomeCode::SUCCESS) ;
		DRIVERCRATE_EXPECT( context, first.installOutcome == OutcomeCode::SUCCESS) ;
		DRIVERCRATE_EXPECT( context, first.installError == 0) ;
		DRIVERCRATE_EXPECT( context, first.rebootRequired) ;
		DRIVERCRATE_EXPECT( context, second.identity == fixture.identities[1]) ;
		DRIVERCRATE_EXPECT( context, second.downloadOutcome == OutcomeCode::SUCCESS) ;
		DRIVERCRATE_EXPECT( context, second.installOutcome == OutcomeCode::FAILURE) ;
		DRIVERCRATE_EXPECT( context, second.installError == secondFailure) ;
		DRIVERCRATE_EXPECT( context, !second.rebootRequired) ;
	}

	DRIVERCRATE_EXPECT( context, reverificationCalls == 1U) ;
	DRIVERCRATE_EXPECT( context, rankCalls == 2U) ;
	DRIVERCRATE_EXPECT( context, installCalls == 2U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一件目の指定導入callback例外を候補別失敗へ変換し、二件目の監査と導入を続行して、確定済みおよび後続結果を保持する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetCallbackExceptionContinues( TestContext &context)
{
	IntelEthernetPreparedInstallFixture fixture ;	// 例外後の継続を確認する二device routing。
	const bool							initialized =
		// 前提構築結果。
		initializeIntelEthernetPreparedInstallFixture( fixture, 2U) ;
	DRIVERCRATE_EXPECT( context, initialized) ;
	// 二device routingがない場合は後続候補結果を参照しない。
	if( !initialized) {
		return ;
	}

	std::size_t					reverificationCalls{} ;	// 共有INF閉包の再検証callback呼出し回数。
	std::size_t					rankCalls{} ;			// Device別rank再監査callback呼出し回数。
	std::size_t					installCalls{} ;		// 例外を含む指定導入callback呼出し回数。
	const PreparedInfReverifier reverifier =
		[&reverificationCalls]( const OfficialAuditedInfPackage &) -> NativeError {
		++reverificationCalls ;
		return 0 ;
	} ; // 共有INF閉包を一回だけ正常再検証する。
	const OfficialDriverRankAudit expectedRank =
		// 固定rank snapshot。
		fixture.targets.at( fixture.identities.front()).prepared.rankAudit ;
	const OfficialInfRankAuditor rankAuditor =
		[&rankCalls, &expectedRank]( ScanSessionId, std::wstring_view,
									const OfficialDownloadWorkspace &, const OfficialInfPackage &,
									OfficialDriverRankAudit &rank) -> NativeError {
		++rankCalls ;
		rank = expectedRank ;
		return 0 ;
	} ; // 例外後の二件目にも発行時と同じrankを返す。
	const std::wstring throwingDevice =
		fixture.targets.at( fixture.identities.front())
			.prepared.deviceIdentity ;	// 例外を発生させる一件目のdevice ID。
	const OfficialBoundInfInstaller installer =
		[&installCalls, &throwingDevice]( ScanSessionId, const std::wstring_view deviceIdentity,
										 const OfficialDownloadWorkspace &,
										 const OfficialInfPackage &,
										 const OfficialInfInstallBinding &, std::uintptr_t,
										 bool &rebootRequired) -> NativeError {
		++installCalls ;
		// 指定deviceでのみ導入callback例外を注入し、後続対象の継続を検証する。
		if( deviceIdentity == throwingDevice) {
			throw std::runtime_error( "fictional bound installer failure") ;
		}

		rebootRequired = false ;
		// 例外後に処理される二件目は正常導入とする。
		return 0 ;
	} ; // C++例外を候補境界の外へ漏らさない指定導入callback。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {
	} ; // 共通executorが要求する同期的な進捗受信境界。
	const IntelEthernetPreparedInstallContext installContext{
		.scanSessionId	 = fixture.acquisition.scanSessionId,
		.acquisition	 = &fixture.acquisition,
		.targets		 = &fixture.targets,
		.auditedPackages = std::span<const OfficialAuditedInfPackage>( fixture.auditedPackages),
		.windowsServer	 = true,
		.windowsBuild	 = 26100U,
		.sourceEvidenceConfirmed = true,
	} ; // Server 2025条件と全監査根拠を成立させた非所有context。
	const InstallResult result = executeIntelEthernetPreparedInstall(
		installContext, fixture.identities, reverifier, rankAuditor, installer, 0U,
		progress) ;	// 一件目の例外後も二件目を同じ入力順で実行する。

	DRIVERCRATE_EXPECT( context, !result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.downloadOutcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, result.installOutcome == OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
	DRIVERCRATE_EXPECT( context, result.installError == static_cast<NativeError>( E_UNEXPECTED)) ;
	DRIVERCRATE_EXPECT( context, !result.rebootRequired) ;
	DRIVERCRATE_EXPECT( context, result.updates.size() == 2U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( result.updates.size() == 2U) {
		const UpdateExecutionResult &first	= result.updates[0] ;	// 例外になった一件目の結果。
		const UpdateExecutionResult &second = result.updates[1] ;	// 続行成功した二件目の結果。
		DRIVERCRATE_EXPECT( context, first.identity == fixture.identities[0]) ;
		DRIVERCRATE_EXPECT( context, first.installOutcome == OutcomeCode::FAILURE) ;
		DRIVERCRATE_EXPECT( context, first.installError == static_cast<NativeError>( E_UNEXPECTED)) ;
		DRIVERCRATE_EXPECT( context, second.identity == fixture.identities[1]) ;
		DRIVERCRATE_EXPECT( context, second.installOutcome == OutcomeCode::SUCCESS) ;
		DRIVERCRATE_EXPECT( context, second.installError == 0) ;
	}

	DRIVERCRATE_EXPECT( context, reverificationCalls == 1U) ;
	DRIVERCRATE_EXPECT( context, rankCalls == 2U) ;
	DRIVERCRATE_EXPECT( context, installCalls == 2U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 新しいscan sessionへ旧取得物を渡した場合、外側file検証、進捗、INF再検証、PnP再監査および指定導入の全callbackより前に拒否する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetStaleScanSessionRejected( TestContext &context)
{
	IntelEthernetPreparedInstallFixture fixture ;	// 旧sessionに属する外側fileとrouting。
	const bool							initialized =
		// 前提構築結果。
		initializeIntelEthernetPreparedInstallFixture( fixture, 1U) ;
	DRIVERCRATE_EXPECT( context, initialized) ;
	// 旧取得物を構築できない場合はcallback到達順序を検証しない。
	if( !initialized) {
		return ;
	}

	std::size_t					reverificationCalls{} ;	// INF閉包再検証callbackの呼出し回数。
	std::size_t					rankCalls{} ;			// Install直前rank callbackの呼出し回数。
	std::size_t					installCalls{} ;		// 指定導入callbackの呼出し回数。
	std::size_t					progressCalls{} ;		// 進捗callbackの呼出し回数。
	const PreparedInfReverifier reverifier =
		[&reverificationCalls]( const OfficialAuditedInfPackage &) -> NativeError {
		++reverificationCalls ;
		return static_cast<NativeError>( E_UNEXPECTED) ;
	} ; // Session拒否後には到達してはならない閉包再検証境界。
	const OfficialInfRankAuditor rankAuditor =
		[&rankCalls]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
					 const OfficialInfPackage &, OfficialDriverRankAudit &) -> NativeError {
		++rankCalls ;
		return static_cast<NativeError>( E_UNEXPECTED) ;
	} ; // Session拒否後には到達してはならないPnP／rank境界。
	const OfficialBoundInfInstaller installer =
		[&installCalls]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
						const OfficialInfPackage &, const OfficialInfInstallBinding &,
						std::uintptr_t, bool &) -> NativeError {
		++installCalls ;
		return static_cast<NativeError>( E_UNEXPECTED) ;
	} ; // Session拒否後には到達してはならない指定導入境界。
	const ProviderProgressCallback progress = [&progressCalls]( const ProviderProgress &) {
		++progressCalls ;
	} ; // 進捗受信境界。
	const ScanSessionId newSession =
		fixture.acquisition.scanSessionId + 1U ;	// 旧取得物と一致しない新しいscan session。
	const IntelEthernetPreparedInstallContext installContext{
		.scanSessionId	 = newSession,
		.acquisition	 = &fixture.acquisition,
		.targets		 = &fixture.targets,
		.auditedPackages = std::span<const OfficialAuditedInfPackage>( fixture.auditedPackages),
		.windowsServer	 = true,
		.windowsBuild	 = 26100U,
		.sourceEvidenceConfirmed = true,
	} ; // Session以外を成立させた非所有context。
	const InstallResult result = executeIntelEthernetPreparedInstall(
		installContext, fixture.identities, reverifier, rankAuditor, installer, 0U,
		progress) ;	// 旧sessionの全callback前拒否を実行する。

	DRIVERCRATE_EXPECT( context, !result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.downloadOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, result.downloadError == static_cast<NativeError>( E_INVALIDARG)) ;
	DRIVERCRATE_EXPECT( context, result.installOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, result.installError == static_cast<NativeError>( E_INVALIDARG)) ;
	DRIVERCRATE_EXPECT( context, result.updates.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, reverificationCalls == 0U) ;
	DRIVERCRATE_EXPECT( context, rankCalls == 0U) ;
	DRIVERCRATE_EXPECT( context, installCalls == 0U) ;
	DRIVERCRATE_EXPECT( context, progressCalls == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 期待する契約拒否と、別種類の例外または誤受理を区別する。
 *
 * @param[in] session Reportへ結び付ける検索session。
 * @param[in] devices 呼出し中だけ有効な非機密device群。
 * @param[in] candidateIdentities devicesと同順の既存候補ID群。
 * @param[in] audit 拒否条件を一つ含む合成監査結果。
 * @return `std::logic_error`でfail-closed拒否した場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool intelEthernetReportRejected(
	const ScanSessionId session, const std::span<const OfficialCatalogDevice> devices,
	const std::span<const std::wstring> candidateIdentities,
	const OfficialDriverPackageAudit   &audit)
{
	try {
		static_cast<void>( makeIntelEthernetPreparationAuditReport(
			session, L"intel-fixture-target", devices, candidateIdentities, audit)) ;
	} catch( const std::logic_error &) {
		// 公開契約どおりの入力拒否。
		return true ;
	} catch( ...) {
		// 想定外例外を期待する拒否として扱わない。
		return false ;
	}

	// 不正入力をreportへ変換した場合は失敗。
	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二INFと三deviceで合格、非適用、OS API失敗を混在させ、合格組合せだけを保持する。個別失敗がある非合格行は非適用と断定しない。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetRankAndPartialFailure( TestContext &context)
{
	OfficialDriverPackageAudit audit = fakeIntelEthernetRankInput( 2U) ;	// 二INFの合成内容監査結果。
	std::array				   devices{fakeIntelEthernetDevice(), fakeIntelEthernetDevice(),
					   // 三つの同系列device。
					   fakeIntelEthernetDevice()} ;
	devices[0].deviceIdentity = L"device:811:passed" ;
	devices[1].deviceIdentity = L"device:811:failed" ;
	devices[2].deviceIdentity = L"device:811:rejected" ;
	const OfficialInfRankAuditor mixedRank =
		[]( ScanSessionId, const std::wstring_view identity, const OfficialDownloadWorkspace &,
		   const OfficialInfPackage &, OfficialDriverRankAudit &result) -> NativeError {
		// 一組合せのOS API失敗。
		if( identity == L"device:811:failed") {
			return static_cast<NativeError>( E_FAIL) ;
		}

		result.decision = identity == L"device:811:passed"
							  ? OfficialDriverRankDecision::APPLICABLE
							  : OfficialDriverRankDecision::OVERALL_RANK_REGRESSION ;
		return 0 ;
	} ; // 実PnPを呼ばず三つの判断を決定的に返す境界。
	DRIVERCRATE_EXPECT( context,
					   auditOfficialDriverApplicability( 811U, devices, mixedRank, audit) == 0) ;
	DRIVERCRATE_EXPECT( context, audit.summary.state == OfficialDriverPackageAuditState::AUDITED) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.state ==
									OfficialDriverApplicabilityState::APPLICABLE_TARGETS) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.examinedPairCount == 6U) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.applicablePairCount == 2U) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.failedPairCount == 2U) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.rejectedPairCount == 2U) ;
	DRIVERCRATE_EXPECT( context,
					   audit.applicability.firstPairError == static_cast<NativeError>( E_FAIL)) ;
	DRIVERCRATE_EXPECT( context, audit.rankApprovedTargets.size() == 2U) ;
	// 二INFで合格した対象は同じopaque deviceだけであることを確認する。
	for( const OfficialRankApprovedInfTarget &target : audit.rankApprovedTargets) {
		DRIVERCRATE_EXPECT( context, target.deviceIdentity == L"device:811:passed") ;
		DRIVERCRATE_EXPECT( context,
						   target.rankAudit.decision == OfficialDriverRankDecision::APPLICABLE) ;
	}

	const std::array<std::wstring, 3U> candidateIdentities{
		L"candidate:811:passed", L"candidate:811:failed",
		L"candidate:811:rejected"} ;	// 検索時の既存候補ID順。
	const OfficialPreparationAuditReport mixedReport = makeIntelEthernetPreparationAuditReport(
		811U, L"intel-fixture-target", devices, candidateIdentities, audit) ;	// 表示結果。
	DRIVERCRATE_EXPECT( context, mixedReport.content == CandidateAuditGateState::PASSED) ;
	DRIVERCRATE_EXPECT( context, mixedReport.applicability == CandidateAuditGateState::PASSED) ;
	DRIVERCRATE_EXPECT( context, mixedReport.candidates.size() == 3U) ;
	DRIVERCRATE_EXPECT( context, mixedReport.candidates[0].audit.systemApplicability ==
									CandidateAuditGateState::PASSED) ;
	DRIVERCRATE_EXPECT( context, mixedReport.candidates[1].audit.systemApplicability ==
									CandidateAuditGateState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, mixedReport.candidates[2].audit.systemApplicability ==
									CandidateAuditGateState::FAILURE) ;

	audit = fakeIntelEthernetRankInput( 1U) ;
	const OfficialInfRankAuditor rejectedRank =
		[]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
		   const OfficialInfPackage &, OfficialDriverRankAudit &result) -> NativeError {
		result.decision = OfficialDriverRankDecision::OVERALL_RANK_REGRESSION ;
		return 0 ;
	} ; // 全組合せを安全な非適用として返す境界。
	DRIVERCRATE_EXPECT( context,
					   auditOfficialDriverApplicability( 811U, devices, rejectedRank, audit) == 0) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.state ==
									OfficialDriverApplicabilityState::NO_APPLICABLE_TARGETS) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.examinedPairCount == 3U) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.rejectedPairCount == 3U) ;
	const OfficialPreparationAuditReport rejectedReport = makeIntelEthernetPreparationAuditReport(
		811U, L"intel-fixture-target", devices, candidateIdentities, audit) ;	// 非適用表示。
	DRIVERCRATE_EXPECT( context, rejectedReport.applicability == CandidateAuditGateState::REJECTED) ;
	// 個別失敗がない全非適用結果だけをRejectedとして表示する。
	for( const OfficialPreparationCandidateAudit &row : rejectedReport.candidates) {
		DRIVERCRATE_EXPECT( context,
						   row.audit.systemApplicability == CandidateAuditGateState::REJECTED) ;
		DRIVERCRATE_EXPECT( context,
						   row.audit.installReadiness == CandidateInstallReadiness::BLOCKED) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Reportが入力identityを所有し、旧session、件数不一致、重複、未知対象、不正INF indexをfail-closedで拒否することを確認する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetReportBindingAndLifetime( TestContext &context)
{
	std::vector<OfficialCatalogDevice> devices{	// Report作成後に破棄する入力device。
											   fakeIntelEthernetDevice()} ;
	std::vector<std::wstring>		   candidateIdentities{
		 L"candidate:811:owned"} ;	// Report作成後に破棄する入力候補ID。
	OfficialDriverPackageAudit audit =
		// 一組合せ合格の合成監査。
		makeIntelEthernetReportAudit( devices.front().deviceIdentity) ;
	const OfficialPreparationAuditReport report = makeIntelEthernetPreparationAuditReport(
		811U, L"intel-fixture-target", devices, candidateIdentities, audit) ;	// 所有DTO。
	devices.clear() ;
	candidateIdentities.clear() ;
	// 入力所有者を破棄し、reportへ非所有viewが残らないことを確認する。
	audit = {} ;
	DRIVERCRATE_EXPECT( context, report.targetIdentity == L"intel-fixture-target") ;
	DRIVERCRATE_EXPECT( context,
					   report.providerId == INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, report.candidates.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, report.candidates[0].identity == L"candidate:811:owned") ;
	DRIVERCRATE_EXPECT( context, report.candidates[0].audit.installReadiness ==
									CandidateInstallReadiness::BLOCKED) ;
	DRIVERCRATE_EXPECT( context, !report.candidatePublicationAttempted) ;
	DRIVERCRATE_EXPECT( context, report.publishedCandidates.empty()) ;

	devices				= {fakeIntelEthernetDevice()} ;
	candidateIdentities = {L"candidate:811:base"} ;
	audit				= makeIntelEthernetReportAudit( devices.front().deviceIdentity) ;
	DRIVERCRATE_EXPECT( context,
					   intelEthernetReportRejected( 812U, devices, candidateIdentities, audit)) ;
	DRIVERCRATE_EXPECT( context, intelEthernetReportRejected( 811U, devices, {}, audit)) ;

	devices.push_back( fakeIntelEthernetDevice()) ;
	devices.back().deviceIdentity = devices.front().deviceIdentity ;
	candidateIdentities.push_back( L"candidate:811:second") ;
	DRIVERCRATE_EXPECT( context,
					   intelEthernetReportRejected( 811U, devices, candidateIdentities, audit)) ;

	devices.back().deviceIdentity = L"device:811:second" ;
	candidateIdentities.back()	  = candidateIdentities.front() ;
	DRIVERCRATE_EXPECT( context,
					   intelEthernetReportRejected( 811U, devices, candidateIdentities, audit)) ;

	devices				= {fakeIntelEthernetDevice()} ;
	candidateIdentities = {L"candidate:811:base"} ;
	audit				= makeIntelEthernetReportAudit( L"device:811:unknown") ;
	DRIVERCRATE_EXPECT( context,
					   intelEthernetReportRejected( 811U, devices, candidateIdentities, audit)) ;

	audit = makeIntelEthernetReportAudit( devices.front().deviceIdentity) ;
	audit.rankApprovedTargets.front().auditedPackageIndex = 1U ;
	DRIVERCRATE_EXPECT( context,
					   intelEthernetReportRejected( 811U, devices, candidateIdentities, audit)) ;

	audit						  = makeIntelEthernetReportAudit( devices.front().deviceIdentity) ;
	audit.summary.auditedInfCount = 2U ;
	DRIVERCRATE_EXPECT( context,
					   intelEthernetReportRejected( 811U, devices, candidateIdentities, audit)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief PnP／rank途中の取消しとcallback例外で、部分合格、INF閉包、sessionを全て破棄し、非機密reportをFailedの導入不可状態に保つ。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testIntelEthernetRankCancellationAndException( TestContext &context)
{
	OfficialDriverPackageAudit audit =
		// 取消し前に部分処理させる二INF入力。
		fakeIntelEthernetRankInput( 2U) ;
	std::array devices{fakeIntelEthernetDevice(),
					   // 二つの同系列device。
					   fakeIntelEthernetDevice()} ;
	devices[0].deviceIdentity = L"device:811:first" ;
	devices[1].deviceIdentity = L"device:811:second" ;
	std::size_t					 rankCallCount{} ;	// 取消し確定前に完了したPnP callback件数。
	const OfficialInfRankAuditor rank =
		[&rankCallCount]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
						 const OfficialInfPackage &,
						 OfficialDriverRankAudit &result) -> NativeError {
		++rankCallCount ;
		result.decision = OfficialDriverRankDecision::APPLICABLE ;
		return 0 ;
	} ; // 最初の組合せだけを合格させる決定的callback。
	const OfficialAuditCancellation cancel = [&rankCallCount] {
		return rankCallCount != 0U ;
	} ; // 一件処理後に取消す照会。
	const NativeError cancelled =
		// 期待する取消し値。
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
	DRIVERCRATE_EXPECT(
		context, auditOfficialDriverApplicability( 811U, devices, rank, audit, cancel) == cancelled) ;
	DRIVERCRATE_EXPECT( context, rankCallCount == 1U) ;
	DRIVERCRATE_EXPECT( context, audit.scanSessionId == 0U) ;
	DRIVERCRATE_EXPECT( context, audit.summary.state == OfficialDriverPackageAuditState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, audit.summary.error == cancelled) ;
	DRIVERCRATE_EXPECT( context, audit.auditedPackages.empty()) ;
	DRIVERCRATE_EXPECT( context, audit.rankApprovedTargets.empty()) ;
	DRIVERCRATE_EXPECT( context,
					   audit.applicability.state == OfficialDriverApplicabilityState::FAILURE) ;
	const std::array<std::wstring, 2U> candidateIdentities{
		L"candidate:811:first", L"candidate:811:second"} ;	// 既存候補行ID。
	const OfficialPreparationAuditReport cancelledReport = makeIntelEthernetPreparationAuditReport(
		811U, L"intel-fixture-target", devices, candidateIdentities, audit) ;	// 取消し表示。
	DRIVERCRATE_EXPECT( context, cancelledReport.content == CandidateAuditGateState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, cancelledReport.applicability == CandidateAuditGateState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, cancelledReport.candidates[0].audit.installReadiness ==
									CandidateInstallReadiness::BLOCKED) ;

	audit = fakeIntelEthernetRankInput( 1U) ;
	const OfficialInfRankAuditor throwingRank =
		[]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
		   const OfficialInfPackage &, OfficialDriverRankAudit &) -> NativeError {
		throw std::logic_error( "fictional rank failure") ;
	} ; // Worker外へ漏らしてはならない例外。
	DRIVERCRATE_EXPECT( context,
					   auditOfficialDriverApplicability( 811U, devices, throwingRank, audit) ==
						   static_cast<NativeError>( E_UNEXPECTED)) ;
	DRIVERCRATE_EXPECT( context, audit.scanSessionId == 0U) ;
	DRIVERCRATE_EXPECT( context, audit.summary.state == OfficialDriverPackageAuditState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, audit.summary.error == static_cast<NativeError>( E_UNEXPECTED)) ;
	DRIVERCRATE_EXPECT( context, audit.auditedPackages.empty()) ;
	DRIVERCRATE_EXPECT( context, audit.rankApprovedTargets.empty()) ;
	DRIVERCRATE_EXPECT( context,
					   audit.applicability.state == OfficialDriverApplicabilityState::FAILURE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 入力境界の検証だけに用い、実取得または内容監査合格を表さない。
 * @return 公開hashなしのASIX取得成功を表す架空記録。
 */
//------------------------------------------------------------------------------
OfficialAcquisitionResult fakeAsixAcquisition()
{
	return {.state					 = OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
			.scanSessionId			 = 879U,
			.acquisitionId			 = 1U,
			.providerId				 = std::wstring( ASIX_AX88179A_PROVIDER_ID),
			.resourceId				 = std::wstring( OFFICIAL_PAYLOAD_RESOURCE_ID),
			.inspectionPath			 = L"unopened-asix-fixture.zip",
			.byteCount				 = 1U,
			.sha256					 = std::wstring( 64U, L'a'),
			.publishedSha256Verified = false} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Hardware ID、instance path、serial numberを含めない。
 *
 * @param[in] identity 架空のopaque device identity。
 * @return ASIX AX88179A系列照合だけに用いる非機密device。
 */
//------------------------------------------------------------------------------
OfficialCatalogDevice fakeAsixDevice( std::wstring identity)
{
	return {.deviceIdentity	 = std::move( identity),
			.model			 = L"ASIX AX88179A Fictional USB Ethernet Adapter",
			.manufacturer	 = L"ASIX Electronics Corp.",
			.driverClass	 = L"Net",
			.deviceClassGuid = L"{4d36e972-e325-11ce-bfc1-08002be10318}"} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公開hashなしのASIX取得結果を構成し、固定profileの内容拒否を検証する。架空CATは信頼済み署名として扱わず、PnP callback到達を失敗として記録する。
 *
 * @param[in] entries 架空ZIPへ保存する有限entry群。
 * @param[out] outcome 生成成功時の監査結果とPnP呼出し件数。
 * @return ZIP生成・保存・hash計算に成功した場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool runAsixArchiveFixture( const std::span<const ZipFixtureEntry> entries,
										 AsixAuditFixtureOutcome			   &outcome)
{
	outcome = {} ;
	std::vector<std::byte> archive ;	// 本fixtureだけが所有する生成済みZIP。
	// 入力ZIPを構成できない場合は監査結果として扱わない。
	if( !createZipFixture( entries, archive)) {
		return false ;
	}

	OfficialDownloadWorkspace input ;	// 監査中に取得fileを所有する保護領域。
	// Workspaceを作れない場合は内容監査を開始しない。
	if( input.initialize( L"asix-audit-fixture", 879U) != 0) {
		return false ;
	}

	std::wstring hash ;	// 保存したZIPの実測SHA-256。
	// 不完全fileを取得成功fixtureへ昇格しない。
	if( storeArchive( input, L"payload.zip", archive, hash) != 0) {
		return false ;
	}

	OfficialAcquisitionResult acquisition = fakeAsixAcquisition() ;	// 実測値を反映する記録。
	acquisition.inspectionPath			  = input.path( L"payload.zip") ;
	acquisition.byteCount				  = static_cast<std::uint64_t>( archive.size()) ;
	acquisition.sha256					  = hash ;
	const std::array devices{fakeAsixDevice( L"device:879:fictional")} ;	// 架空対象device。
	const OfficialInfRankAuditor rank =
		[&outcome]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
				   const OfficialInfPackage &, OfficialDriverRankAudit &) -> NativeError {
		++outcome.rankCallCount ;
		return static_cast<NativeError>( E_UNEXPECTED) ;
	} ; // 内容拒否fixtureでは到達してはならない後段PnP監査。
	outcome.auditError =
		auditAsixAx88179aPreparedPackage( 879U, acquisition, {}, devices, rank, {}, outcome.audit) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実署名・実fileを合格扱いにせず、後段状態機械の所有構造だけを作る。
 *
 * @param[in] packageCount 合成する内容監査済みINF数。
 * @return PnP／rankとreport変換だけに用いる合成監査結果。
 */
//------------------------------------------------------------------------------
OfficialDriverPackageAudit fakeAsixRankInput( const std::size_t packageCount)
{
	OfficialDriverPackageAudit audit ;	// 各試験が所有する後段専用の合成監査結果。
	audit.scanSessionId			  = 879U ;
	audit.summary.state			  = OfficialDriverPackageAuditState::AUDITED ;
	audit.summary.infCount		  = packageCount ;
	audit.summary.auditedInfCount = packageCount ;
	// 各indexへ一つのNet INF構造を作り、複数INFとdeviceの組合せを再現する。
	for( std::size_t packageIndex = 0U; packageIndex < packageCount; ++packageIndex) {
		OfficialDriverClosure closure ;	// 現在indexの架空INF構造。
		closure.packages.push_back(
			{.className = L"Net", .hardwareIds = {L"USB\\VID_0000&PID_0000"}}) ;
		audit.auditedPackages.push_back( {.workspace = std::make_unique<OfficialDownloadWorkspace>(),
										 .closure	= std::move( closure),
										 .profile	= OfficialDriverAuditProfile::ASIX_AX88179A}) ;
	}

	return audit ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASIX固定Provider、payload、session、任意公開hash、8 MiB入力上限をfile読込み前に検証する。正しい固定条件は取消し到達で確認する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testAsixProfileHashAndCapacityGuards( TestContext &context)
{
	OfficialAcquisitionResult acquisition = fakeAsixAcquisition() ;	// 変更する架空取得記録。
	std::array devices{fakeAsixDevice( L"device:879:guard")} ;		// 同じscanの架空device。
	OfficialDriverPackageAudit	 audit ;							// 各拒否で更新される監査結果。
	std::size_t					 rankCallCount{} ;					// 入力検証では0であるべきPnP呼出し件数。
	const OfficialInfRankAuditor rank =
		[&rankCallCount]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
						 const OfficialInfPackage &, OfficialDriverRankAudit &) -> NativeError {
		++rankCallCount ;
		return static_cast<NativeError>( E_UNEXPECTED) ;
	} ; // 内容監査前には到達してはならない後段境界。
	const PreparationCancellation cancel = [] { return true ; } ;	// Valid入力だけの到達点。
	const NativeError			  cancelled =
		// 期待する取消し値。
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
	DRIVERCRATE_EXPECT( context, auditAsixAx88179aPreparedPackage( 879U, acquisition, {}, devices,
																 rank, cancel, audit) == cancelled) ;
	DRIVERCRATE_EXPECT( context, audit.summary.state == OfficialDriverPackageAuditState::FAILURE) ;

	const std::wstring publishedHash = acquisition.sha256 ;	// 公開値として扱う合成hash。
	DRIVERCRATE_EXPECT( context, auditAsixAx88179aPreparedPackage( 879U, acquisition, publishedHash,
																 devices, rank, cancel, audit) ==
									static_cast<NativeError>( E_ACCESSDENIED)) ;
	acquisition.publishedSha256Verified = true ;
	DRIVERCRATE_EXPECT( context,
					   auditAsixAx88179aPreparedPackage( 879U, acquisition, publishedHash, devices,
														rank, cancel, audit) == cancelled) ;

	OfficialDownloadWorkspace oversizedWorkspace ;	// 上限超過fileを所有する一時領域。
	const NativeError		  workspaceError =
		// 初期化結果。
		oversizedWorkspace.initialize( L"asix-oversize-audit", 879U) ;
	DRIVERCRATE_EXPECT( context, workspaceError == 0) ;
	// 保護領域の初期化成功後にだけ入力上限を超える架空fileを作成する。
	if( workspaceError == 0) {
		std::vector<std::byte> oversizedBytes( 8ULL * 1024ULL * 1024ULL +
											  1ULL) ;	// 入力上限を一byte超える実file内容。
		std::wstring		   oversizedHash ;			// 上限超過fileの実測SHA-256。
		const NativeError	   storeError =
			storeArchive( oversizedWorkspace, L"payload.zip", oversizedBytes,
						 oversizedHash) ;	// 実sizeと一致する取得identityの構築結果。
		DRIVERCRATE_EXPECT( context, storeError == 0) ;
		// 上限超過fileの保存成功後にだけ実測sizeとhashを使って拒否を検証する。
		if( storeError == 0) {
			acquisition				   = fakeAsixAcquisition() ;
			acquisition.inspectionPath = oversizedWorkspace.path( L"payload.zip") ;
			acquisition.byteCount	   = static_cast<std::uint64_t>( oversizedBytes.size()) ;
			acquisition.sha256		   = oversizedHash ;
			DRIVERCRATE_EXPECT(
				context,
				auditAsixAx88179aPreparedPackage( 879U, acquisition, {}, devices, rank, {}, audit) ==
					static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE))) ;
		}
	}

	acquisition			   = fakeAsixAcquisition() ;
	acquisition.providerId = std::wstring( BROADCOM_NET_XTREME_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, auditAsixAx88179aPreparedPackage( 879U, acquisition, {}, devices,
																 rank, cancel, audit) ==
									static_cast<NativeError>( E_ACCESSDENIED)) ;
	acquisition			   = fakeAsixAcquisition() ;
	acquisition.resourceId = std::wstring( OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ;
	DRIVERCRATE_EXPECT( context, auditAsixAx88179aPreparedPackage( 879U, acquisition, {}, devices,
																 rank, cancel, audit) ==
									static_cast<NativeError>( E_ACCESSDENIED)) ;
	acquisition = fakeAsixAcquisition() ;
	DRIVERCRATE_EXPECT( context, auditAsixAx88179aPreparedPackage( 880U, acquisition, {}, devices,
																 rank, cancel, audit) ==
									static_cast<NativeError>( E_INVALIDARG)) ;
	devices.front().driverClass = L"Ports" ;
	DRIVERCRATE_EXPECT( context, auditAsixAx88179aPreparedPackage( 879U, acquisition, {}, devices,
																 rank, cancel, audit) ==
									static_cast<NativeError>( E_INVALIDARG)) ;
	DRIVERCRATE_EXPECT( context, rankCallCount == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Net／SYS／INF signature／CAT署名条件を架空ZIPで拒否し、PnPへ進めない。架空CATを信頼済み署名として扱わない。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testAsixInfAndSignatureRejections( TestContext &context)
{
	const ZipFixtureEntry invalidCatalogEntries[]{
		{"driver/sample.inf", VALID_INF.data(), VALID_INF.size()},
		{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
		{"driver/sample.sys", DRIVER.data(), DRIVER.size()},
	} ; // 構造は成立するがCAT署名が架空のNet package。
	AsixAuditFixtureOutcome outcome ;	// 各archive監査の観測結果。
	DRIVERCRATE_EXPECT( context, runAsixArchiveFixture( invalidCatalogEntries, outcome)) ;
	DRIVERCRATE_EXPECT( context, outcome.auditError == 0) ;
	DRIVERCRATE_EXPECT( context, outcome.audit.summary.state ==
									OfficialDriverPackageAuditState::NO_SUPPORTED_INF) ;
	DRIVERCRATE_EXPECT( context, outcome.audit.summary.infCount == 1U) ;
	DRIVERCRATE_EXPECT( context, outcome.audit.summary.rejectedInfCount == 1U) ;
	DRIVERCRATE_EXPECT( context, outcome.audit.summary.firstRejectionError != 0) ;
	DRIVERCRATE_EXPECT( context, outcome.audit.applicability.state ==
									OfficialDriverApplicabilityState::NOT_STARTED) ;
	DRIVERCRATE_EXPECT( context, outcome.rankCallCount == 0U) ;

	const ZipFixtureEntry missingDriverEntries[]{
		{"driver/sample.inf", VALID_INF.data(), VALID_INF.size()},
		{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
	} ; // INFが参照するSYSを欠くpackage。
	DRIVERCRATE_EXPECT( context, runAsixArchiveFixture( missingDriverEntries, outcome)) ;
	DRIVERCRATE_EXPECT( context, outcome.audit.summary.state ==
									OfficialDriverPackageAuditState::NO_SUPPORTED_INF) ;
	DRIVERCRATE_EXPECT( context, outcome.rankCallCount == 0U) ;

	std::string		  invalidSignature( VALID_INF) ;						// INF signatureだけを不許可値へ変える内容。
	const std::size_t signature = invalidSignature.find( "$Windows NT$") ;	// 置換位置。
	DRIVERCRATE_EXPECT( context, signature != std::string::npos) ;
	// 対象位置を取得できた場合だけfixtureを変形し、範囲外の編集で検証を中断させない。
	if( signature != std::string::npos) {
		invalidSignature.replace( signature, std::string_view( "$Windows NT$").size(), "$Fictional$") ;
		const ZipFixtureEntry invalidSignatureEntries[]{
			{"driver/sample.inf", invalidSignature.data(), invalidSignature.size()},
			{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
			{"driver/sample.sys", DRIVER.data(), DRIVER.size()},
		} ; // INF signature以外を同じに保つ拒否package。
		DRIVERCRATE_EXPECT( context, runAsixArchiveFixture( invalidSignatureEntries, outcome)) ;
		DRIVERCRATE_EXPECT( context, outcome.audit.summary.state ==
										OfficialDriverPackageAuditState::NO_SUPPORTED_INF) ;
		DRIVERCRATE_EXPECT( context, outcome.rankCallCount == 0U) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 内容監査後だけを合成し、二deviceのApplicableとrank退行を端末非依存で区別する。実署名または実PnP合格を主張しない。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testAsixRankApplicability( TestContext &context)
{
	OfficialDriverPackageAudit	 audit = fakeAsixRankInput( 1U) ;	// 一INFの後段専用結果。
	const std::array			 devices{fakeAsixDevice( L"device:879:passed"),
							 // 二deviceの入力順。
							 fakeAsixDevice( L"device:879:rejected")} ;
	const OfficialInfRankAuditor rank =
		[]( ScanSessionId, const std::wstring_view identity, const OfficialDownloadWorkspace &,
		   const OfficialInfPackage &, OfficialDriverRankAudit &result) -> NativeError {
		result.decision = identity == L"device:879:passed"
							  ? OfficialDriverRankDecision::APPLICABLE
							  : OfficialDriverRankDecision::OVERALL_RANK_REGRESSION ;
		return 0 ;
	} ; // OSを呼ばず二つの決定だけを返す境界。
	DRIVERCRATE_EXPECT( context, auditOfficialDriverApplicability( 879U, devices, rank, audit) == 0) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.state ==
									OfficialDriverApplicabilityState::APPLICABLE_TARGETS) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.examinedPairCount == 2U) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.applicablePairCount == 1U) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.rejectedPairCount == 1U) ;
	DRIVERCRATE_EXPECT( context, audit.rankApprovedTargets.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( audit.rankApprovedTargets.size() == 1U) {
		DRIVERCRATE_EXPECT( context, audit.rankApprovedTargets.front().deviceIdentity ==
										L"device:879:passed") ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Report変換に必要な状態だけを作り、実署名または実PnP合格を表さない。
 *
 * @param[in] deviceIdentity 適用性合格対象としてcopyするopaque ID。
 * @return 一つのINFとdevice組合せが合格した合成監査結果。
 */
//------------------------------------------------------------------------------
OfficialDriverPackageAudit makeAsixReportAudit( std::wstring deviceIdentity)
{
	OfficialDriverPackageAudit audit		= fakeAsixRankInput( 1U) ;	// 一INF所有構造。
	audit.applicability.state				= OfficialDriverApplicabilityState::APPLICABLE_TARGETS ;
	audit.applicability.examinedPairCount	= 1U ;
	audit.applicability.applicablePairCount = 1U ;
	OfficialDriverRankAudit rankAudit ;	// 実PnP IDを含まない合成合格値。
	rankAudit.decision = OfficialDriverRankDecision::APPLICABLE ;
	audit.rankApprovedTargets.push_back( {.deviceIdentity	  = std::move( deviceIdentity),
										 .auditedPackageIndex = 0U,
										 .rankAudit			  = rankAudit}) ;
	return audit ;
}

//------------------------------------------------------------------------------
/**
 * @brief 期待する契約拒否と想定外例外または誤受理を区別する。
 *
 * @param[in] session Reportへ結び付ける検索session。
 * @param[in] devices 呼出し中だけ有効な非機密device群。
 * @param[in] candidateIdentities devicesと同順の既存候補ID群。
 * @param[in] audit 拒否条件を一つ含む合成監査結果。
 * @return `std::logic_error`でfail-closed拒否した場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool asixReportRejected( const ScanSessionId						   session,
									  const std::span<const OfficialCatalogDevice> devices,
									  const std::span<const std::wstring> candidateIdentities,
									  const OfficialDriverPackageAudit	 &audit)
{
	try {
		static_cast<void>( makeAsixPreparationAuditReport( session, L"asix-fixture-target", devices,
														 candidateIdentities, audit)) ;
	} catch( const std::logic_error &) {
		// 公開契約どおりの入力拒否。
		return true ;
	} catch( ...) {
		// 想定外例外を期待する拒否として扱わない。
		return false ;
	}

	// 不正入力をreportへ変換した場合は失敗。
	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASIX wrapperと共通helperの同値性、DTO所有、候補発行なし、入力矛盾拒否を検証する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testAsixReportEquivalenceAndLifetime( TestContext &context)
{
	std::vector<OfficialCatalogDevice> devices{	// Report作成後に破棄するdevice入力。
											   fakeAsixDevice( L"device:879:owned")} ;
	std::vector<std::wstring>		   candidateIdentities{
		 L"candidate:879:owned"} ;	// Report作成後に破棄する候補ID入力。
	OfficialDriverPackageAudit audit =
		// 一組合せ合格の合成監査。
		makeAsixReportAudit( devices.front().deviceIdentity) ;
	const OfficialPreparationAuditReport wrapped = makeAsixPreparationAuditReport(
		879U, L"asix-fixture-target", devices, candidateIdentities, audit) ;	// ASIX wrapper結果。
	const OfficialPreparationAuditReport common = makeOfficialPreparedAuditReport(
		OfficialDriverAuditProfile::ASIX_AX88179A, 879U, L"asix-fixture-target", devices,
		candidateIdentities, audit) ;	// 固定profileを直接渡す共通結果。
	DRIVERCRATE_EXPECT( context, wrapped.targetIdentity == common.targetIdentity) ;
	DRIVERCRATE_EXPECT( context, wrapped.providerId == common.providerId) ;
	DRIVERCRATE_EXPECT( context, wrapped.content == common.content) ;
	DRIVERCRATE_EXPECT( context, wrapped.applicability == common.applicability) ;
	DRIVERCRATE_EXPECT( context, wrapped.infCount == common.infCount) ;
	DRIVERCRATE_EXPECT( context, wrapped.acceptedInfCount == common.acceptedInfCount) ;
	DRIVERCRATE_EXPECT( context, wrapped.examinedPairCount == common.examinedPairCount) ;
	DRIVERCRATE_EXPECT( context, wrapped.applicablePairCount == common.applicablePairCount) ;
	DRIVERCRATE_EXPECT( context, wrapped.candidates.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, common.candidates.size() == wrapped.candidates.size()) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( wrapped.candidates.size() == 1U && common.candidates.size() == 1U) {
		DRIVERCRATE_EXPECT( context,
						   wrapped.candidates[0].identity == common.candidates[0].identity) ;
		DRIVERCRATE_EXPECT( context, wrapped.candidates[0].audit.systemApplicability ==
										common.candidates[0].audit.systemApplicability) ;
		DRIVERCRATE_EXPECT( context, wrapped.candidates[0].audit.installReadiness ==
										CandidateInstallReadiness::BLOCKED) ;
	}

	DRIVERCRATE_EXPECT( context, !wrapped.candidatePublicationAttempted) ;
	DRIVERCRATE_EXPECT( context, wrapped.publishedCandidates.empty()) ;

	devices.clear() ;
	candidateIdentities.clear() ;
	// 入力所有者を破棄し、reportに非所有viewが残らないことを確認する。
	audit = {} ;
	DRIVERCRATE_EXPECT( context, wrapped.targetIdentity == L"asix-fixture-target") ;
	DRIVERCRATE_EXPECT( context, wrapped.providerId == ASIX_AX88179A_PROVIDER_ID) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( wrapped.candidates.size() == 1U) {
		DRIVERCRATE_EXPECT( context, wrapped.candidates[0].identity == L"candidate:879:owned") ;
	}

	devices				= {fakeAsixDevice( L"device:879:base")} ;
	candidateIdentities = {L"candidate:879:base"} ;
	audit				= makeAsixReportAudit( devices.front().deviceIdentity) ;
	DRIVERCRATE_EXPECT( context, asixReportRejected( 880U, devices, candidateIdentities, audit)) ;
	DRIVERCRATE_EXPECT( context, asixReportRejected( 879U, devices, {}, audit)) ;
	devices.push_back( fakeAsixDevice( L"device:879:second")) ;
	candidateIdentities.push_back( candidateIdentities.front()) ;
	DRIVERCRATE_EXPECT( context, asixReportRejected( 879U, devices, candidateIdentities, audit)) ;
	devices				  = {fakeAsixDevice( L"device:879:base")} ;
	candidateIdentities	  = {L"candidate:879:base"} ;
	devices.front().model = L"Fictional unrelated adapter" ;
	DRIVERCRATE_EXPECT( context, asixReportRejected( 879U, devices, candidateIdentities, audit)) ;
	devices.front()						  = fakeAsixDevice( L"device:879:base") ;
	audit.auditedPackages.front().profile = OfficialDriverAuditProfile::INTEL_ETHERNET_SERVER2025 ;
	DRIVERCRATE_EXPECT( context, asixReportRejected( 879U, devices, candidateIdentities, audit)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief PnP部分失敗、取消し、例外で部分合格を残さず、監査済み表示も導入不可を維持する。
 *
 * @param[in,out] context Assertion件数と失敗内容の集計先。
 */
//------------------------------------------------------------------------------
void testAsixPartialFailureCancellationAndInstallBlock( TestContext &context)
{
	OfficialDriverPackageAudit audit = fakeAsixRankInput( 1U) ;	// 三分岐の内容監査前提。
	std::array devices{fakeAsixDevice( L"device:879:passed"), fakeAsixDevice( L"device:879:failed"),
					   // 同じ配布物の三device。
					   fakeAsixDevice( L"device:879:rejected")} ;
	const OfficialInfRankAuditor mixedRank =
		[]( ScanSessionId, const std::wstring_view identity, const OfficialDownloadWorkspace &,
		   const OfficialInfPackage &, OfficialDriverRankAudit &result) -> NativeError {
		// 一組合せだけのOS API失敗。
		if( identity == L"device:879:failed") {
			return static_cast<NativeError>( E_FAIL) ;
		}

		result.decision = identity == L"device:879:passed"
							  ? OfficialDriverRankDecision::APPLICABLE
							  : OfficialDriverRankDecision::OVERALL_RANK_REGRESSION ;
		return 0 ;
	} ; // 実PnPを呼ばない決定的な三分岐。
	DRIVERCRATE_EXPECT( context,
					   auditOfficialDriverApplicability( 879U, devices, mixedRank, audit) == 0) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.examinedPairCount == 3U) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.applicablePairCount == 1U) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.failedPairCount == 1U) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.rejectedPairCount == 1U) ;
	const std::array<std::wstring, 3U> candidateIdentities{
		L"candidate:879:passed", L"candidate:879:failed",
		L"candidate:879:rejected"} ;	// 検索時の既存候補ID順。
	const OfficialPreparationAuditReport report = makeAsixPreparationAuditReport(
		879U, L"asix-fixture-target", devices, candidateIdentities, audit) ;	// 部分失敗表示。
	DRIVERCRATE_EXPECT( context, report.content == CandidateAuditGateState::PASSED) ;
	DRIVERCRATE_EXPECT( context, report.applicability == CandidateAuditGateState::PASSED) ;
	DRIVERCRATE_EXPECT( context, report.candidates.size() == devices.size()) ;
	// 全device分の結果がある場合にだけ各行の監査成否を参照する。
	if( report.candidates.size() == devices.size()) {
		DRIVERCRATE_EXPECT( context, report.candidates[0].audit.systemApplicability ==
										CandidateAuditGateState::PASSED) ;
		DRIVERCRATE_EXPECT( context, report.candidates[1].audit.systemApplicability ==
										CandidateAuditGateState::FAILURE) ;
		DRIVERCRATE_EXPECT( context, report.candidates[2].audit.systemApplicability ==
										CandidateAuditGateState::FAILURE) ;
		// 02cでは内容・適用性が合格しても全行の導入許可を発行しない。
		for( const OfficialPreparationCandidateAudit &row : report.candidates) {
			DRIVERCRATE_EXPECT( context,
							   row.audit.installReadiness == CandidateInstallReadiness::BLOCKED) ;
		}
	}

	audit = fakeAsixRankInput( 2U) ;
	std::size_t					 rankCallCount{} ;	// 取消し確定前に完了したcallback件数。
	const OfficialInfRankAuditor rank =
		[&rankCallCount]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
						 const OfficialInfPackage &,
						 OfficialDriverRankAudit &result) -> NativeError {
		++rankCallCount ;
		result.decision = OfficialDriverRankDecision::APPLICABLE ;
		return 0 ;
	} ; // 最初の組合せだけを合格させる決定的callback。
	const OfficialAuditCancellation cancel = [&rankCallCount] {
		return rankCallCount != 0U ;
	} ; // 一件処理後に取消す照会。
	const NativeError cancelled =
		// 期待する取消し値。
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
	DRIVERCRATE_EXPECT(
		context, auditOfficialDriverApplicability( 879U, devices, rank, audit, cancel) == cancelled) ;
	DRIVERCRATE_EXPECT( context, rankCallCount == 1U) ;
	DRIVERCRATE_EXPECT( context, audit.summary.state == OfficialDriverPackageAuditState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, audit.auditedPackages.empty()) ;
	DRIVERCRATE_EXPECT( context, audit.rankApprovedTargets.empty()) ;
	const OfficialPreparationAuditReport cancelledReport = makeAsixPreparationAuditReport(
		879U, L"asix-fixture-target", devices, candidateIdentities, audit) ;	// 取消し表示。
	DRIVERCRATE_EXPECT( context, cancelledReport.content == CandidateAuditGateState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, cancelledReport.applicability == CandidateAuditGateState::FAILURE) ;

	audit = fakeAsixRankInput( 1U) ;
	const OfficialInfRankAuditor throwingRank =
		[]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
		   const OfficialInfPackage &, OfficialDriverRankAudit &) -> NativeError {
		throw std::logic_error( "fictional ASIX rank failure") ;
	} ; // Worker外へ漏らさない例外。
	DRIVERCRATE_EXPECT( context,
					   auditOfficialDriverApplicability( 879U, devices, throwingRank, audit) ==
						   static_cast<NativeError>( E_UNEXPECTED)) ;
	DRIVERCRATE_EXPECT( context, audit.summary.state == OfficialDriverPackageAuditState::FAILURE) ;
	DRIVERCRATE_EXPECT( context, audit.auditedPackages.empty()) ;
	DRIVERCRATE_EXPECT( context, audit.rankApprovedTargets.empty()) ;

	const ProviderDescriptor *descriptor{} ;	// ASIXのregistry capabilityを確認する定義。
	// Stable IDが完全一致する組み込み定義一件だけを参照する。
	for( const ProviderDescriptor &entry : builtInProviderDescriptors()) {
		// ASIX stable IDに一致するregistry定義を検証対象にする。
		if( entry.id == ASIX_AX88179A_PROVIDER_ID) {
			descriptor = &entry ;
			break ;
		}
	}

	DRIVERCRATE_EXPECT( context, descriptor != nullptr) ;
	// 取得できたProvider定義に対してのみinstall capabilityを検証する。
	if( descriptor != nullptr) {
		DRIVERCRATE_EXPECT( context, (descriptor->capabilities &
									 capabilityMask( ProviderCapability::INSTALL)) != 0U) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 取消し・入力拒否をfileアクセス前に検証する。実署名の成功には使用しない。
 * @return 署名・実取得を行っていない架空の取得記録。
 */
//------------------------------------------------------------------------------
OfficialAcquisitionResult fakeBroadcomAcquisition()
{
	return {.state			= OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
			.scanSessionId	= 701U,
			.acquisitionId	= 1U,
			.providerId		= std::wstring( BROADCOM_NET_XTREME_PROVIDER_ID),
			.resourceId		= std::wstring( OFFICIAL_PAYLOAD_RESOURCE_ID),
			.inspectionPath = L"unopened-fixture.zip",
			.byteCount		= 1U,
			.sha256			= std::wstring( 64U, L'a')} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 具体的な型番・hardware ID・実機情報を使わない。
 * @return 系列照合だけに用いる架空の非機密device。
 */
//------------------------------------------------------------------------------
OfficialCatalogDevice fakeBroadcomDevice()
{
	return {.deviceIdentity = L"device:701:fictional",
			.model			= L"Broadcom NetXtreme-E Fictional Adapter",
			.manufacturer	= L"Broadcom",
			.driverClass	= L"Net"} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公開hashなしでも内容監査へ到達し、架空CATは拒否してPnP監査へ渡さない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testBroadcomSharedAuditNoPublicHash( TestContext &context)
{
	const ZipFixtureEntry entries[]{
		{"driver/sample.inf", VALID_INF.data(), VALID_INF.size()},
		{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
		{"driver/sample.sys", DRIVER.data(), DRIVER.size()},
		{"tools/setup.exe", SETUP.data(), SETUP.size()},
	} ; // 未参照utilityを含む架空のNet閉包。
	std::vector<std::byte> archive ;	// 本testが生成する小さなZIP。
	DRIVERCRATE_EXPECT( context, createZipFixture( entries, archive)) ;
	OfficialDownloadWorkspace input ;	// Testだけで所有する一時入力。
	DRIVERCRATE_EXPECT( context, input.initialize( L"broadcom-audit-fixture", 701U) == 0) ;
	std::wstring hash ;	// ZIPの実測hash。公開hashとはしない。
	DRIVERCRATE_EXPECT( context, storeArchive( input, L"payload.zip", archive, hash) == 0) ;
	OfficialAcquisitionResult acquisition = fakeBroadcomAcquisition() ;	// 内容解析へ渡す取得記録。
	acquisition.inspectionPath			  = input.path( L"payload.zip") ;
	acquisition.byteCount				  = static_cast<std::uint64_t>( archive.size()) ;
	acquisition.sha256					  = hash ;
	const std::array			 devices{fakeBroadcomDevice()} ;	// 同一scanの架空対象。
	std::size_t					 rankCalls{} ;						// 署名失敗後にPnPへ進んでいないことの観測値。
	const OfficialInfRankAuditor rank =
		[&rankCalls]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
					 const OfficialInfPackage &, OfficialDriverRankAudit &) -> NativeError {
		++rankCalls ;
		return static_cast<NativeError>( E_UNEXPECTED) ;
	} ; // 呼ばれてはならない後段監査。
	OfficialDriverPackageAudit audit ;	// 内容拒否と未開始PnPを別に保持する結果。
	DRIVERCRATE_EXPECT( context, auditBroadcomPreparedPackage( 701U, acquisition, {}, devices, rank,
															 {}, audit) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   audit.summary.state == OfficialDriverPackageAuditState::NO_SUPPORTED_INF) ;
	DRIVERCRATE_EXPECT( context, audit.summary.inventoryFileCount == 4U) ;
	DRIVERCRATE_EXPECT( context, audit.summary.infCount == 1U) ;
	DRIVERCRATE_EXPECT( context, audit.summary.rejectedInfCount == 1U) ;
	DRIVERCRATE_EXPECT( context, audit.summary.firstRejectionError != 0) ;
	DRIVERCRATE_EXPECT( context, audit.auditedPackages.empty()) ;
	DRIVERCRATE_EXPECT( context,
					   audit.applicability.state == OfficialDriverApplicabilityState::NOT_STARTED) ;
	DRIVERCRATE_EXPECT( context, rankCalls == 0U) ;
	DRIVERCRATE_EXPECT( context,
					   acquisition.state == OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION) ;
	DRIVERCRATE_EXPECT( context, !acquisition.publishedSha256Verified) ;

	// 実測hashの差替えだけを注入する。
	acquisition.sha256[0] = hash[0] == L'a' ? L'b' : L'a' ;
	DRIVERCRATE_EXPECT( context, auditBroadcomPreparedPackage( 701U, acquisition, {}, devices, rank,
															 {}, audit) != 0) ;
	DRIVERCRATE_EXPECT( context, audit.summary.state == OfficialDriverPackageAuditState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, rankCalls == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公開hash省略をASUSへ転用せず、未知profile・別取得元・公開hash矛盾を拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testSharedAuditProfileAndHashGuards( TestContext &context)
{
	OfficialAcquisitionResult acquisition =
		// Fileを開かない拒否fixture。
		fakeBroadcomAcquisition() ;
	OfficialDriverPackageAuditRequest request{
		.acquisition = &acquisition,
		.profile	 = OfficialDriverAuditProfile::BROADCOM_NET_XTREME_E} ;	// 公開hashなしの契約。
	OfficialDriverPackageAudit		audit ;									// 各入力拒否で残る結果。
	const OfficialAuditCancellation cancel = [] { return true ; } ;			// Valid入力のみ取消しへ進む。
	const NativeError				cancelled =
		// 期待値。
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
	DRIVERCRATE_EXPECT( context, auditOfficialDriverPackage( request, audit, cancel) == cancelled) ;
	DRIVERCRATE_EXPECT( context, auditAsusDriverPackage( request, audit) ==
									static_cast<NativeError>( E_ACCESSDENIED)) ;
	request.profile = static_cast<OfficialDriverAuditProfile>( 999) ;
	DRIVERCRATE_EXPECT( context, auditOfficialDriverPackage( request, audit, cancel) ==
									static_cast<NativeError>( E_ACCESSDENIED)) ;
	request.profile		   = OfficialDriverAuditProfile::ASUS ;
	acquisition.providerId = std::wstring( ASUS_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, auditOfficialDriverPackage( request, audit, cancel) ==
									static_cast<NativeError>( E_ACCESSDENIED)) ;
	request.expectedSha256 = acquisition.sha256 ;
	DRIVERCRATE_EXPECT( context, auditOfficialDriverPackage( request, audit, cancel) ==
									static_cast<NativeError>( E_ACCESSDENIED)) ;
	acquisition.publishedSha256Verified = true ;
	DRIVERCRATE_EXPECT( context, auditOfficialDriverPackage( request, audit, cancel) == cancelled) ;
	request.profile = OfficialDriverAuditProfile::BROADCOM_NET_XTREME_E ;
	DRIVERCRATE_EXPECT( context, auditOfficialDriverPackage( request, audit, cancel) ==
									static_cast<NativeError>( E_ACCESSDENIED)) ;
	acquisition.providerId = std::wstring( BROADCOM_NET_XTREME_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, auditOfficialDriverPackage( request, audit, cancel) == cancelled) ;
	request.expectedSha256 = {} ;
	DRIVERCRATE_EXPECT( context, auditOfficialDriverPackage( request, audit, cancel) ==
									static_cast<NativeError>( E_ACCESSDENIED)) ;
	acquisition.publishedSha256Verified = false ;
	acquisition.resourceId				= std::wstring( OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ;
	DRIVERCRATE_EXPECT( context, auditOfficialDriverPackage( request, audit, cancel) ==
									static_cast<NativeError>( E_ACCESSDENIED)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 取得後監査を別session・別系列へ転用せず、取消しやcallback例外で部分結果を残さない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testBroadcomPreparedAuditBoundary( TestContext &context)
{
	const OfficialAcquisitionResult acquisition = fakeBroadcomAcquisition() ;	// 未開封の架空記録。
	std::array				   devices{fakeBroadcomDevice()} ;					// 入力拒否のため変更する架空device。
	OfficialDriverPackageAudit audit ;											// 拒否後に空であるべき保持物。
	DRIVERCRATE_EXPECT(
		context, auditBroadcomPreparedPackage( 702U, acquisition, {}, devices, {}, {}, audit) ==
					 static_cast<NativeError>( E_INVALIDARG)) ;
	DRIVERCRATE_EXPECT( context,
					   auditBroadcomPreparedPackage( 701U, acquisition, {}, {}, {}, {}, audit) ==
						   static_cast<NativeError>( E_INVALIDARG)) ;
	devices.front().driverClass = L"Ports" ;
	DRIVERCRATE_EXPECT(
		context, auditBroadcomPreparedPackage( 701U, acquisition, {}, devices, {}, {}, audit) ==
					 static_cast<NativeError>( E_INVALIDARG)) ;
	devices.front() = fakeBroadcomDevice() ;
	DRIVERCRATE_EXPECT( context,
					   auditBroadcomPreparedPackage(
						   701U, acquisition, {}, devices, {}, [] { return true ; }, audit) ==
						   static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))) ;
	DRIVERCRATE_EXPECT( context, audit.auditedPackages.empty()) ;
	DRIVERCRATE_EXPECT( context, audit.rankApprovedTargets.empty()) ;
	DRIVERCRATE_EXPECT( context, auditBroadcomPreparedPackage(
									701U, acquisition, {}, devices, {}, []() -> bool { throw 1 ; },
									audit) == static_cast<NativeError>( E_UNEXPECTED)) ;
	DRIVERCRATE_EXPECT( context, audit.summary.state == OfficialDriverPackageAuditState::FAILURE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実署名や実ファイルを検証した結果とはしない。後段の分岐だけを検証する。
 * @return 署名監査済みという前提だけを模倣するPnP単体試験入力。
 */
//------------------------------------------------------------------------------
OfficialDriverPackageAudit fakeSharedRankInput()
{
	OfficialDriverPackageAudit audit ;	// Fake rank callback専用の未初期化workspace所有者。
	audit.scanSessionId			  = 701U ;
	audit.summary.state			  = OfficialDriverPackageAuditState::AUDITED ;
	audit.summary.auditedInfCount = 1U ;
	OfficialDriverClosure closure ;	// 架空の一INF構造だけを保持する。
	closure.packages.push_back( {.className = L"Net", .hardwareIds = {L"PCI\\VEN_0000&DEV_0000"}}) ;
	audit.auditedPackages.push_back( {.workspace = std::make_unique<OfficialDownloadWorkspace>(),
									 .closure	= std::move( closure),
									 .profile = OfficialDriverAuditProfile::BROADCOM_NET_XTREME_E}) ;
	return audit ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じscanでのみPnP監査し、途中取消しでは内容閉包と適用対象をともに破棄する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testSharedRankSessionAndCancellation( TestContext &context)
{
	OfficialDriverPackageAudit	 audit = fakeSharedRankInput() ;	// Fake内容監査結果。
	const std::array			 devices{fakeBroadcomDevice()} ;	// 一件の同一scan対象。
	std::size_t					 calls{} ;							// Fake照合が実行された件数。
	const OfficialInfRankAuditor rank =
		[&calls]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
				 const OfficialInfPackage &, OfficialDriverRankAudit &result) -> NativeError {
		++calls ;
		result.decision = OfficialDriverRankDecision::APPLICABLE ;
		return 0 ;
	} ; // OSを呼ばず同一sessionの成功分岐だけを検査する。
	DRIVERCRATE_EXPECT( context, auditOfficialDriverApplicability( 702U, devices, rank, audit) ==
									static_cast<NativeError>( E_INVALIDARG)) ;
	DRIVERCRATE_EXPECT( context, calls == 0U) ;
	DRIVERCRATE_EXPECT( context, auditOfficialDriverApplicability( 701U, devices, rank, audit) == 0) ;
	DRIVERCRATE_EXPECT( context, audit.rankApprovedTargets.size() == 1U) ;
	calls = 0U ;
	DRIVERCRATE_EXPECT( context, auditOfficialDriverApplicability( 701U, devices, rank, audit,
																 [&calls] { return calls > 0U ; }) ==
									static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))) ;
	DRIVERCRATE_EXPECT( context, calls == 1U) ;
	DRIVERCRATE_EXPECT( context, audit.auditedPackages.empty()) ;
	DRIVERCRATE_EXPECT( context, audit.rankApprovedTargets.empty()) ;
	DRIVERCRATE_EXPECT( context, audit.scanSessionId == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 個別PnP失敗・rank退行と合格を分け、全体例外では閉包を含めて破棄する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testSharedRankPartialFailure( TestContext &context)
{
	OfficialDriverPackageAudit audit = fakeSharedRankInput() ;	// 分岐専用の内容監査fixture。
	std::array				   devices{fakeBroadcomDevice(), fakeBroadcomDevice(),
					   // 三対象。
					   fakeBroadcomDevice()} ;
	devices[0].deviceIdentity = L"pass" ;
	devices[1].deviceIdentity = L"error" ;
	devices[2].deviceIdentity = L"regression" ;
	const OfficialInfRankAuditor rank =
		[]( ScanSessionId, const std::wstring_view identity, const OfficialDownloadWorkspace &,
		   const OfficialInfPackage &, OfficialDriverRankAudit &result) -> NativeError {
		// 個別OS失敗は非適用と区別する。
		if( identity == L"error") {
			return static_cast<NativeError>( E_FAIL) ;
		}

		result.decision = identity == L"pass" ? OfficialDriverRankDecision::APPLICABLE
											  : OfficialDriverRankDecision::OVERALL_RANK_REGRESSION ;
		return 0 ;
	} ; // 実PnPを呼ばない決定的な三分岐。
	DRIVERCRATE_EXPECT( context, auditOfficialDriverApplicability( 701U, devices, rank, audit) == 0) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.examinedPairCount == 3U) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.applicablePairCount == 1U) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.failedPairCount == 1U) ;
	DRIVERCRATE_EXPECT( context, audit.applicability.rejectedPairCount == 1U) ;
	DRIVERCRATE_EXPECT( context, audit.rankApprovedTargets.size() == 1U) ;
	const OfficialInfRankAuditor throwing =
		[]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
		   const OfficialInfPackage &,
		   OfficialDriverRankAudit &) -> NativeError { throw 1 ; } ;	// 全体例外。
	DRIVERCRATE_EXPECT( context, auditOfficialDriverApplicability( 701U, devices, throwing, audit) ==
									static_cast<NativeError>( E_UNEXPECTED)) ;
	DRIVERCRATE_EXPECT( context, audit.auditedPackages.empty()) ;
	DRIVERCRATE_EXPECT( context, audit.rankApprovedTargets.empty()) ;
	DRIVERCRATE_EXPECT( context,
					   audit.applicability.state == OfficialDriverApplicabilityState::FAILURE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 合成監査後の版分類、部分除外、token rollback、別profileを非通信で検証する。
 *
 * @param[in,out] context Assertion結果の集計先。
 */
//------------------------------------------------------------------------------
void testAsixBoundCandidatePublication( TestContext &context)
{
	// 正常、未知版、binding拒否、例外、別profile、重複token、版差、旧sessionを独立処理する。
	for( int scenario = 0; scenario < 8; ++scenario)	// 今回注入する一つの境界条件。
	{
		std::array devices{fakeAsixDevice( L"asix-a"), fakeAsixDevice( L"asix-b"),
						   // 同配布物へ対応する架空三device。
						   fakeAsixDevice( L"asix-c")} ;
		const std::array<std::wstring, 3> ids{L"asix-a", L"asix-b", L"asix-c"} ;	// 合格対象ID。
		// 全deviceに提示する同一の合成INF版。
		const std::array<std::wstring, 3> versions{L"2.0.0.0", L"2.0.0.0", L"2.0.0.0"} ;
		// 候補版との比較で更新・同版・旧版になる三つの現在driverを作る。
		for( std::size_t index = 0U; index < devices.size(); ++index)	// 現在のsnapshot位置。
		{
			devices[index].currentProvider = L"ASIX" ;
			devices[index].currentVersion  = std::to_wstring( index + 1U) + L".0.0.0" ;
			devices[index].currentDate	   = L"2025/09/01" ;
		}

		OfficialDriverPackageAudit audit =
			// 共通の合成所有構造。
			makeIntelEthernetPublicationAudit( ids, versions) ;
		// 架空閉包をASIX profileへ変換する。実CAT署名の合格を合成する入口ではない。
		for( auto &package : audit.auditedPackages)	// 監査後の状態だけを表す一閉包。
		{
			package.profile = OfficialDriverAuditProfile::ASIX_AX88179A ;
			package.closure.packages.front().providerName = L"ASIX" ;
		}

		// 未知の現在版を注入し、警告なしの再導入候補に変換されないことを検証する。
		if( scenario == 1) {
			devices[0].currentVersion.clear() ;	// 未知版は警告なし再導入へ変換しない。
		}

		OfficialPreparationAuditReport report = makeAsixPreparationAuditReport(
			811U, L"asix-target", devices, ids, audit) ;	// 候補発行前の既存行report。
		// 他Providerの監査profileを混入させ、境界不一致を検証する。
		if( scenario == 4) {
			audit.auditedPackages[0].profile =
				OfficialDriverAuditProfile::INTEL_ETHERNET_SERVER2025 ;	// 他profile混入。
		}

		std::size_t					   binds{} ;	// Windows node固定境界を呼んだ件数。
		std::size_t					   releases{} ;	// 全体rollbackで解放したtoken数。
		const OfficialInfInstallBinder binder =
			[&binds, scenario]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
							   const OfficialInfPackage &package, std::wstring_view provider,
							   std::wstring_view version, std::wstring_view date,
							   const OfficialDriverRankAudit &rank,
							   OfficialInfInstallBinding	 &binding) {
				++binds ;
				// 一回目のbindingへ再試行診断を注入し、部分対象の扱いを検証する。
				if( scenario == 2 && binds == 1U) {
					return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY)) ;
				}

				// 二回目のbindingに例外を注入し、先行tokenのrollbackを検証する。
				if( scenario == 3 && binds == 2U) {
					throw std::runtime_error( "fictional binder failure") ;
				}

				binding = {.token			  = scenario == 5 ? 100U : 100U + binds,
						   .currentProvider	  = std::wstring( provider),
						   .currentVersion	  = std::wstring( version),
						   .currentDate		  = std::wstring( date),
						   .candidateProvider = package.providerName,
						   .candidateVersion  = scenario == 6 ? L"9.0.0.0" : package.driverVersion,
						   .candidateDate	  = L"2026/09/01",
						   .rankAudit		  = rank} ;
				return NativeError{0} ;
			} ; // 実SetupAPIを呼ばず、版差・状態差を必要な時だけ注入する。
		const OfficialInfInstallBindingReleaser releaser = [&releases]( ScanSessionId,
																	   std::uint64_t) noexcept {
			++releases ;
			return true ;
		} ; // 架空tokenの破棄だけを観測する。
		BoundPreparedInstallTargets routes ;	// 発行成功時だけ保持するrouting。
		publishAsixPreparedCandidates( scenario == 7 ? 812U : 811U, 1U, 4096U, devices, audit,
									  binder, releaser, report, routes) ;
		const bool		  published = scenario <= 2 ;	// 正常と個別除外は残るdeviceを発行する。
		// 各scenarioで候補発行後に残るべき表示行数。
		const std::size_t expectedCount = scenario == 0 ? 3U : (published ? 2U : 0U) ;
		DRIVERCRATE_EXPECT( context, report.publishedCandidates.size() == expectedCount) ;
		DRIVERCRATE_EXPECT( context, routes.size() == expectedCount) ;
		DRIVERCRATE_EXPECT( context, report.candidatePublicationAttempted == published) ;
		DRIVERCRATE_EXPECT( context, report.content == CandidateAuditGateState::PASSED) ;
		DRIVERCRATE_EXPECT(
			context,
			report.publication.state ==
				(published ? OfficialPreparationCandidatePublicationState::CANDIDATES_PUBLISHED
						   : OfficialPreparationCandidatePublicationState::FAILURE)) ;
		DRIVERCRATE_EXPECT(
			context, releases == ((scenario == 3 || scenario == 5 || scenario == 6) ? 1U : 0U)) ;
		// 発行された全候補の取得元、版分類、未選択状態とbinding対応を確認する。
		for( const UpdateCandidate &candidate : report.publishedCandidates)	// 現在の候補DTO。
		{
			const auto found = std::ranges::find( ids, candidate.deviceIdentity) ;	// 対象位置。
			DRIVERCRATE_EXPECT( context, found != ids.end()) ;
			// 生成結果にないidentityをtest側の固定対象解除へ渡さない。
			if( found == ids.end()) {
				continue ;
			}

			const auto index = static_cast<std::size_t>( found - ids.begin()) ;	// 三device内位置。
			const std::array actions{DriverAction::UPDATE, DriverAction::REINSTALL,
									 DriverAction::DOWNGRADE} ;	// 版による正しい操作。
			DRIVERCRATE_EXPECT( context, candidate.providerId == ASIX_AX88179A_PROVIDER_ID) ;
			DRIVERCRATE_EXPECT( context, candidate.version == versions[index]) ;
			DRIVERCRATE_EXPECT( context, candidate.action == actions[index]) ;
			DRIVERCRATE_EXPECT( context, candidate.sourceLocation == L"www.asix.com.tw") ;
			DRIVERCRATE_EXPECT( context, !candidate.recommended && candidate.installable) ;
			DRIVERCRATE_EXPECT( context,
							   candidate.defaultPreference == CandidateDefaultPreference::NONE) ;
			DRIVERCRATE_EXPECT( context, candidate.allContentCached && candidate.eulaAccepted) ;
			DRIVERCRATE_EXPECT( context, routes.contains( candidate.identity)) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 架空取得fileとfake Windows境界で、再監査拒否・部分結果・OS制約を検証する。
 *
 * @param[in,out] context Assertion結果の集計先。
 */
//------------------------------------------------------------------------------
void testAsixBoundInstallResultsAndGuards( TestContext &context)
{
	// 各異常条件で新しい保護workspaceを使用し、前回失敗の状態を次例へ持ち越さない。
	for( int scenario = 0; scenario < 20; ++scenario)	// 単一の失敗条件を選ぶ有限index。
	{
		IntelEthernetPreparedInstallFixture fixture ;	// 既存のProvider非依存な架空所有構造。
		// 二device用の架空取得fileとroutingを準備できた場合true。
		const bool initialized = initializeIntelEthernetPreparedInstallFixture( fixture, 2U) ;
		DRIVERCRATE_EXPECT( context, initialized) ;
		// fixture構築失敗時はそのscenarioの導入模擬を行わない。
		if( !initialized) {
			continue ;
		}

		fixture.acquisition.providerId = std::wstring( ASIX_AX88179A_PROVIDER_ID) ;
		// ASIXの公開hash任意条件。
		fixture.acquisition.publishedSha256Verified = false ;
		fixture.auditedPackages[0].profile			= OfficialDriverAuditProfile::ASIX_AX88179A ;
		fixture.auditedPackages[0].closure.packages[0].providerName = L"ASIX" ;
		// Binding metadataも同じ合成ASIX閉包へ合わせ、tokenの役割を維持する。
		for( auto &entry : fixture.targets)	// 現在変換する候補routing。
		{
			entry.second.binding.candidateProvider = L"ASIX" ;
			entry.second.binding.currentProvider   = L"ASIX" ;
		}

		const OfficialDriverRankAudit rankSnapshot =
			// 同一rank基準値。
			fixture.targets.at( fixture.identities[0]).prepared.rankAudit ;
		// 取得後fileと異なるhashを注入して再検証時の差替え拒否を確認する。
		if( scenario == 3) {
			// 外側実fileとのhash差。
			fixture.acquisition.sha256.assign( 64U, L'0') ;
		}

		// 別Provider用の閉包profileを注入して混用の拒否を確認する。
		if( scenario == 11) {
			fixture.auditedPackages[0].profile =
				OfficialDriverAuditProfile::INTEL_ETHERNET_SERVER2025 ;	// 他Provider閉包。
		}

		// 選択identityを重複させ、二重処理の拒否を確認する。
		if( scenario == 12) {
			// 選択IDの重複。
			fixture.identities[1] = fixture.identities[0] ;
		}

		// 公開されていないidentityを注入して未表示候補の拒否を確認する。
		if( scenario == 13) {
			// 非公開ID。
			fixture.identities[1] = L"unknown-candidate" ;
		}

		// 未固定のnode tokenを注入して指定導入へ進まないことを確認する。
		if( scenario == 14) {
			// 未固定node。
			fixture.targets.begin()->second.binding.token = 0U ;
		}

		// ASIXの入力容量上限超過を注入し、取得fileの拒否を確認する。
		if( scenario == 15) {
			// ASIX上限超過。
			fixture.acquisition.byteCount = 8ULL * 1024ULL * 1024ULL + 1ULL ;
		}

		// 二候補を同じdeviceに結び付け、一device二選択の拒否を確認する。
		if( scenario == 18) {
			fixture.targets.at( fixture.identities[1]).prepared.deviceIdentity =
				fixture.targets.at( fixture.identities[0])
					.prepared.deviceIdentity ;	// 同device二選択。
		}

		// 取得元IDを別Providerへ差し替えてrouting境界の拒否を確認する。
		if( scenario == 19) {
			fixture.acquisition.providerId =
				// 取得元不一致。
				std::wstring( INTEL_ETHERNET_SERVER2025_OFFICIAL_PROVIDER_ID) ;
		}

		std::size_t					reverifications{} ;	// 一つの閉包に対する署名・file再監査回数。
		std::size_t					ranks{} ;			// 各deviceの現在PnP／rankを照合した回数。
		std::size_t					installs{} ;		// Fake指定導入境界を呼んだ回数。
		const PreparedInfReverifier reverifier = [&reverifications,
												  scenario]( const OfficialAuditedInfPackage &) {
			++reverifications ;
			// 署名callbackの例外を注入し、未検証の導入を防ぐ経路を確認する。
			if( scenario == 16) {
				throw std::runtime_error( "fictional signature callback exception") ;
			}

			return scenario == 4 ? static_cast<NativeError>( TRUST_E_BAD_DIGEST) : NativeError{0} ;
		} ; // 実CATの署名合格を作らず、後段の結果処理だけを試験する。
		const OfficialInfRankAuditor rank =
			[&ranks, &rankSnapshot,
			 scenario]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
					   const OfficialInfPackage &, OfficialDriverRankAudit &output) {
				++ranks ;
				// 初回rank callbackの例外を注入し、適用性未確定時の中断を確認する。
				if( scenario == 17 && ranks == 1U) {
					throw std::runtime_error( "fictional rank callback exception") ;
				}

				output = rankSnapshot ;
				// 適用判定を変えずrank値だけを変え、監査結果の完全一致検証を確認する。
				if( scenario == 5 && ranks == 1U) {
					// decisionだけ一致しても同じ監査とは扱わない。
					++output.candidateRank ;
				}

				return NativeError{0} ;
			} ; // 実deviceへ問い合わせないPnP監査境界。
		const OfficialBoundInfInstaller installer =
			[&context, &installs,
			 scenario]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
					   const OfficialInfPackage &, const OfficialInfInstallBinding &binding,
					   std::uintptr_t, bool										   &reboot) {
				++installs ;
				DRIVERCRATE_EXPECT( context, binding.token != 0U) ;
				// 初回導入の例外を注入し、対象別失敗と後続処理を確認する。
				if( scenario == 2 && installs == 1U) {
					throw std::runtime_error( "fictional install exception") ;
				}

				// 初回導入へ通常失敗または再試行診断を注入し、無条件retryをしないことを確認する。
				if( (scenario == 1 || scenario == 6) && installs == 1U) {
					return scenario == 6 ? static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY))
										 : static_cast<NativeError>( E_FAIL) ;
				}

				reboot = true ;
				return NativeError{0} ;
			} ; // Staging後失敗と同rank現在版変更を、実OS変更なしで再現する。
		std::uint32_t				   lastPercent{} ;	// 確定進捗の単調性を記録する。
		const ProviderProgressCallback progress = [&context,
												   &lastPercent]( const ProviderProgress &value) {
			DRIVERCRATE_EXPECT( context, value.percentComplete >= lastPercent) ;
			DRIVERCRATE_EXPECT( context, value.percentComplete <= 100U) ;
			lastPercent = value.percentComplete ;
		} ; // 待機時間では増えない処理進捗。
		const BoundPreparedInstallContext input{.scanSessionId	 = scenario == 9 ? 822U : 821U,
												.acquisition	 = &fixture.acquisition,
												.targets		 = &fixture.targets,
												.auditedPackages = fixture.auditedPackages,
												.windowsServer	 = scenario == 7,
												.windowsBuild	 = scenario == 8 ? 0U : 26100U,
												.sourceEvidenceConfirmed =
													scenario != 10} ;	// 固定契約へのfake環境入力。
		// Fake再検証・rank・install境界を通したASIX指定導入の試験結果。
		const InstallResult				  result = executeAsixPreparedInstall(
			  input, fixture.identities, reverifier, rank, installer, 0U, progress) ;
		const bool partial = scenario == 1 || scenario == 2 || scenario == 5 || scenario == 6 ||
							 // 一deviceだけ成功する例。
							 scenario == 17 ;
		DRIVERCRATE_EXPECT( context, result.updates.size() == 2U) ;
		DRIVERCRATE_EXPECT( context, result.succeeded == (scenario == 0)) ;
		DRIVERCRATE_EXPECT( context,
						   result.installOutcome ==
							   (scenario == 0 ? OutcomeCode::SUCCESS
											  : (partial ? OutcomeCode::SUCCEEDED_WITH_ERRORS
														 : OutcomeCode::FAILURE))) ;
		DRIVERCRATE_EXPECT( context, result.rebootRequired == (scenario == 0 || partial)) ;
		DRIVERCRATE_EXPECT(
			context, installs == (scenario == 0 || scenario == 1 || scenario == 2 || scenario == 6
									  ? 2U
									  : (scenario == 5 || scenario == 17 ? 1U : 0U))) ;
		DRIVERCRATE_EXPECT( context, reverifications <= 1U) ;
		// 二件の部分結果が揃う場合にだけ、取得成功と個別導入成否を分けて検証する。
		if( result.updates.size() == 2U && partial) {
			DRIVERCRATE_EXPECT( context, result.downloadOutcome == OutcomeCode::SUCCESS) ;
			DRIVERCRATE_EXPECT( context, result.updates[0].installOutcome == OutcomeCode::FAILURE) ;
			DRIVERCRATE_EXPECT( context, result.updates[1].installOutcome == OutcomeCode::SUCCESS) ;
			DRIVERCRATE_EXPECT( context, lastPercent == 100U) ;
		}
	}
}

/**
 * @brief 共通入力が公式取得を捏造せず、同じ非実行閉包へ到達することを検証する。
 * @param[in,out] context Assertion集計先。
 */
void testCommonArchiveContentBoundary( TestContext &context)
{
	const ZipFixtureEntry fixtureEntries[]{
		{"driver/sample.inf", VALID_INF.data(), VALID_INF.size()},
		{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
		{"driver/sample.sys", DRIVER.data(), DRIVER.size()},
		{"firmware/unselected.bin", DRIVER.data(), DRIVER.size()},
		{"tools/setup.exe", SETUP.data(), SETUP.size()},
		{"unsupported/other.inf", DRIVER.data(), DRIVER.size()},
	} ; // 未参照firmwareとinstaller、および不正INFを同梱する架空package。
	std::vector<std::byte> archive ;	// FixtureだけのZIP。
	DRIVERCRATE_EXPECT( context, createZipFixture( fixtureEntries, archive)) ;
	OfficialDownloadWorkspace source ;	// 明示選択を模した元file領域。
	DRIVERCRATE_EXPECT( context, source.initialize( L"common-source", 901U) == 0) ;
	std::wstring sha256 ;	// 元fileの同一性。
	DRIVERCRATE_EXPECT( context, storeArchive( source, L"payload.zip", archive, sha256) == 0) ;
	OfficialDownloadWorkspace	copied ;	// 共通API自身が作成する保護copy。
	DriverArchiveInput			input ;		// 公式取得stateを持たない内容入力。
	OfficialDriverArchiveFormat format{} ;	// Copyが確定する非実行形式。
	DRIVERCRATE_EXPECT( context, copyLocalDriverArchive( source.path( L"payload.zip"), 901U, copied,
													   input, format) == 0) ;
	DRIVERCRATE_EXPECT( context, input.sha256 == sha256 && input.byteCount == archive.size()) ;
	DRIVERCRATE_EXPECT( context, input.inspectionPath != source.path( L"payload.zip")) ;
	DRIVERCRATE_EXPECT( context, format == OfficialDriverArchiveFormat::ZIP) ;
	OfficialDriverArchiveInventory inventory ;	// 由来と独立した全file一覧。
	DRIVERCRATE_EXPECT( context,
					   inspectDriverArchiveInventory( {&input, format, {}}, POLICY, inventory) == 0) ;
	DRIVERCRATE_EXPECT( context, inventory.entries.size() == 6U) ;
	OfficialDownloadWorkspace closureWorkspace ;							// 単一の非実行driver閉包。
	OfficialDriverClosure	  closure ;										// 署名未検証の内容結果。
	const std::array selected{std::wstring_view( L"driver\\sample.inf")} ;	// 一つだけ選ぶINF。
	DRIVERCRATE_EXPECT( context,
					   extractDriverClosure( {&input, format, {}, selected, L"common-test-closure"},
											POLICY, closureWorkspace, closure) == 0) ;
	DRIVERCRATE_EXPECT( context, closure.entries.size() == 3U && closure.packages.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, closure.packages.front().hasExternalDependencies == false) ;
	DRIVERCRATE_EXPECT(
		context, GetFileAttributesW( closureWorkspace.path( L"firmware\\unselected.bin").c_str()) ==
					 INVALID_FILE_ATTRIBUTES) ;
	DRIVERCRATE_EXPECT( context,
					   GetFileAttributesW( closureWorkspace.path( L"tools\\setup.exe").c_str()) ==
						   INVALID_FILE_ATTRIBUTES) ;
	CommonDriverPackageInspection inspection ;	// 全INFを署名まで検査した個別結果。
	DRIVERCRATE_EXPECT( context, inspectCommonDriverPackage( input, format, inspection) == 0) ;
	DRIVERCRATE_EXPECT( context, inspection.error == 0 && inspection.infs.size() == 2U &&
									inspection.retainedBytes == 0U) ;
	// 失敗時にも全体完了と個別不合格を区別し、架空CATを署名合格へしない。
	if( inspection.infs.size() == 2U) {
		DRIVERCRATE_EXPECT( context, inspection.infs[0].state ==
										CommonInfInspectionState::SIGNATURE_REJECTED) ;
		DRIVERCRATE_EXPECT( context,
						   inspection.infs[1].state == CommonInfInspectionState::CLOSURE_REJECTED) ;
		DRIVERCRATE_EXPECT( context, inspection.infs[0].error != 0 && inspection.infs[1].error != 0) ;
		DRIVERCRATE_EXPECT( context, !inspection.infs[0].workspace && !inspection.infs[1].workspace) ;
	}

	OfficialAcquisitionResult notOfficial ;	// Local成功から公式取得証拠を生成しない負例。
	notOfficial.scanSessionId  = input.scanSessionId ;
	notOfficial.inspectionPath = input.inspectionPath ;
	notOfficial.byteCount	   = input.byteCount ;
	notOfficial.sha256		   = input.sha256 ;
	DRIVERCRATE_EXPECT( context, inspectOfficialDriverArchiveInventory( {&notOfficial, format, {}},
																	  POLICY, inventory) ==
									static_cast<NativeError>( E_ACCESSDENIED)) ;
	DRIVERCRATE_EXPECT( context, inventory.entries.empty()) ;
	DriverArchiveInput changed = input ;	// Hashだけを変更する改変入力。
	changed.sha256.assign( 64U, L'0') ;
	DRIVERCRATE_EXPECT( context, inspectCommonDriverPackage( changed, format, inspection) != 0) ;
	DRIVERCRATE_EXPECT( context, inspection.error != 0 && inspection.infs.empty() &&
									inspection.scanSessionId == 0U) ;
	DRIVERCRATE_EXPECT( context,
					   inspectCommonDriverPackage( input, format, inspection, [] { return true ; }) ==
						   static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))) ;
	DRIVERCRATE_EXPECT( context, inspection.infs.empty()) ;
	DRIVERCRATE_EXPECT( context, inspectCommonDriverPackage( input, format, inspection, []() -> bool {
									throw std::runtime_error( "fixture cancellation") ;
								}) == static_cast<NativeError>( E_UNEXPECTED)) ;
	DRIVERCRATE_EXPECT( context, inspection.infs.empty()) ;
}

/**
 * @brief Intel Windows 11の型付きrecordから生成ZIPの共通内容検査までを接続検証する。
 * @param[in,out] context Assertion集計先。
 */
void testIntelWindows11DelegatedArchiveContentConnection( TestContext &context)
{
	const ZipFixtureEntry fixtureEntries[]{
		{"driver/sample.inf", VALID_INF.data(), VALID_INF.size()},
		{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
		{"driver/sample.sys", DRIVER.data(), DRIVER.size()},
		{"unsupported/other.inf", DRIVER.data(), DRIVER.size()},
	} ; // 実driverを含まない静的内容検査用package。
	std::vector<std::byte> archive ;	// Minizが生成する取得payload相当のZIP。
	DRIVERCRATE_EXPECT( context, createZipFixture( fixtureEntries, archive)) ;
	OfficialDownloadWorkspace source ;	// 取得層の保護領域を模倣するworkspace。
	DRIVERCRATE_EXPECT( context, source.initialize( L"intel-win11-delegated", 905U) == 0) ;
	std::wstring sha256 ;	// 公開値と実取得値の両方へ使用する実測SHA-256。
	DRIVERCRATE_EXPECT( context, storeArchive( source, L"payload.zip", archive, sha256) == 0) ;

	constexpr ScanSessionId	   SESSION_ID		  = 1'505U ;	// Windows 11向け架空scan session。
	constexpr std::uint64_t	   RECORD_EVIDENCE_ID = 305U ;		// Session内の型付きrecord証拠ID。
	constexpr std::uint64_t	   GRANT_ID			  = 405U ;		// Session内の一回使用download grant ID。
	OfficialDistributionRecord record ;							// Intel公式起点へ結合する秘密URL所有record。
	record.rootEvidence = OfficialSourceEvidence{
		.scanSessionId			= SESSION_ID,
		.acquisitionId			= 205U,
		.providerId				= std::wstring{INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID},
		.policyId				= std::wstring{INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID},
		.resourceId				= std::wstring{OFFICIAL_LANDING_RESOURCE_ID},
		.redirectCount			= 0U,
		.originPolicyIndices	= {0U},
		.acquisition			= MeasurementAcquisition::NETWORK_BODY,
		.bodyAcquiredUtcSeconds = 25'000U,
		.originValidatedUtcSeconds = 25'001U,
		.cachePermitted			   = false} ;
	record.recordEvidenceId = RECORD_EVIDENCE_ID ;
	record.parserId			= L"intel-ethernet-windows11-page" ;
	record.parserRevision	= 3U ;
	record.recordRoute		= L"intel-download-record" ;
	record.recordKey		= L"727998" ;
	record.productFamily	= L"Intel Ethernet Network Adapters" ;
	record.operatingSystem	= L"Microsoft Windows 11" ;
	record.architecture		= OfficialDistributionArchitecture::WINDOWS_X64 ;
	record.packageVersion	= L"99.0.0" ;
	record.publishedDate	= L"2026-09-15" ;
	record.terms			= OfficialDistributionTerms::ACCEPTANCE_REQUIRED ;
	record.eulaRevision		= L"fixture-eula-2026-09" ;
	record.eulaText			= L"Fictional test terms for a non-executable driver archive." ;
	record.payloads.push_back( OfficialDistributionPayloadRecord{
		.resourceId				  = std::wstring{OFFICIAL_PAYLOAD_RESOURCE_ID},
		.payloadOrdinal			  = 0U,
		.kind					  = OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE,
		.fileDisplayName		  = L"Wired_driver_99.0.0_x64.zip",
		.publishedSizeBytes		  = static_cast<std::uint64_t>( archive.size()),
		.publishedSha256		  = sha256,
		.publisher				  = L"Intel Corporation",
		.expectedContentType	  = L"application/zip",
		.maximumBytes			  = 128U * 1024U * 1024U,
		.externalExpiryUtcSeconds = std::nullopt,
		.targetUrl				  = SecretOfficialUrl{
			   L"https://downloadmirror.intel.com/fixture/Wired_driver_99.0.0_x64.zip"}}) ;
	record.resolvedUtcSeconds = 25'002U ;

	OfficialDistributionRecordEvidence evidence ;	// URLを保持しないrecord検証結果。
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( record, evidence) == 0) ;
	RecordScopedDownloadGrant grant ;	// 一payloadだけに発行する短命取得許可。
	DRIVERCRATE_EXPECT( context, grant.issue( record, evidence, 0U, GRANT_ID, 25'010U, 0U) == 0) ;
	DRIVERCRATE_EXPECT( context, grant.claim( SESSION_ID, GRANT_ID, 25'020U) == 0) ;
	SecretOfficialUrl requestUrl =
		// 架空HTTP requestだけが一時所有する秘密URL。
		grant.takeTargetUrlForHttp() ;
	DRIVERCRATE_EXPECT( context, !requestUrl.empty()) ;
	DRIVERCRATE_EXPECT( context, grant.payloadView().targetUrl.empty()) ;
	DRIVERCRATE_EXPECT( context, grant.finishAcquisition(
									OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION, 0) == 0) ;

	const OfficialAcquisitionResult acquisition{
		.state					 = OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
		.error					 = 0,
		.networkCostError		 = 0,
		.networkCost			 = OfficialNetworkCostKind::UNRESTRICTED,
		.scanSessionId			 = SESSION_ID,
		.acquisitionId			 = 605U,
		.providerId				 = std::wstring{INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID},
		.resourceId				 = std::wstring{OFFICIAL_PAYLOAD_RESOURCE_ID},
		.inspectionPath			 = source.path( L"payload.zip"),
		.byteCount				 = static_cast<std::uint64_t>( archive.size()),
		.sha256					 = sha256,
		.publishedSizeVerified	 = true,
		.publishedSha256Verified = true,
		.delegatedRecord		 = true,
		.recordEvidenceId		 = RECORD_EVIDENCE_ID,
		.downloadGrantId		 = GRANT_ID,
		.grantReresolutionCount	 = 0U,
		.validatedDestinationAddressCount = 1U,
		.destinationLocallyResolved		  = true} ;	// 取得ledger相当の固定済みidentity。
	DelegatedOfficialPackageInput input ;			// URLを持たない共通検査入力。
	DRIVERCRATE_EXPECT( context, makeDelegatedOfficialPackageInput( acquisition, grant, input) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   input.archive.sha256 == sha256 && input.archive.byteCount == archive.size()) ;
	DRIVERCRATE_EXPECT( context, input.provenance.providerId ==
									INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, input.provenance.policyId ==
									INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID) ;

	CommonDriverPackageInspection inspection ;	// 全体成功とINF単位拒否を分ける静的検査結果。
	DRIVERCRATE_EXPECT( context,
					   inspectDelegatedOfficialDriverPackage( SESSION_ID, input, inspection) == 0) ;
	DRIVERCRATE_EXPECT( context, inspection.error == 0 && inspection.infs.size() == 2U) ;
	// 架空CATを合格へ昇格せず、他INFの閉包拒否後も個別結果を保持する。
	if( inspection.infs.size() == 2U) {
		DRIVERCRATE_EXPECT( context, inspection.infs[0].state ==
										CommonInfInspectionState::SIGNATURE_REJECTED) ;
		DRIVERCRATE_EXPECT( context,
						   inspection.infs[1].state == CommonInfInspectionState::CLOSURE_REJECTED) ;
	}

	OfficialAcquisitionResult changedAcquisition = acquisition ;	// 公開値と不一致にする取得結果。
	// 64桁小文字形式を維持したまま実取得hashだけを差し替える。
	if( !changedAcquisition.sha256.empty()) {
		changedAcquisition.sha256.front() = changedAcquisition.sha256.front() == L'a' ? L'b' : L'a' ;
	}

	DelegatedOfficialPackageInput rejected ;	// 失敗時に空へ戻るadapter出力。
	DRIVERCRATE_EXPECT( context,
					   makeDelegatedOfficialPackageInput( changedAcquisition, grant, rejected) != 0) ;
	DRIVERCRATE_EXPECT( context, rejected.archive.inspectionPath.empty()) ;
	DelegatedOfficialPackageInput changedInput = input ;	// Adapter後の改変を模倣する入力。
	changedInput.archive.sha256.assign( 64U, L'0') ;
	DRIVERCRATE_EXPECT(
		context, inspectDelegatedOfficialDriverPackage( SESSION_ID, changedInput, inspection) != 0) ;
	DRIVERCRATE_EXPECT( context, inspection.error != 0 && inspection.infs.empty()) ;
}

/**
 * @brief Local入力・件数・nested上限・公開直前の差替えを検証する。
 * @param[in,out] context Assertion集計先。
 */
void testCommonArchiveBounds( TestContext &context)
{
	const std::array invalidPaths{std::wstring_view( L"payload.zip"),
								  std::wstring_view( L"\\\\server\\payload.zip"),
								  std::wstring_view( L"C:\\payload.zip:stream"),
								  // 読取り前の拒否例。
								  std::wstring_view( L"C:\\setup.exe")} ;
	// 不正入力の全例を確認し、外部fileへアクセスしない。
	for( const std::wstring_view path : invalidPaths) {
		OfficialDownloadWorkspace	workspace ;	// 拒否時は未初期化のまま。
		DriverArchiveInput			input ;		// 失敗時の空出力。
		OfficialDriverArchiveFormat format{} ;	// 成功しないため使用しない。
		DRIVERCRATE_EXPECT( context,
						   copyLocalDriverArchive( path, 901U, workspace, input, format) != 0) ;
		DRIVERCRATE_EXPECT( context, input.inspectionPath.empty() && input.scanSessionId == 0U) ;
	}

	std::vector<std::string> names ;	// 各entry pathの寿命をfixture生成まで保持する。
	names.reserve( 129U) ;
	// INF上限の一件超過を、小さい不正INFで再現する。
	for( std::size_t index = 0; index < 129U; ++index) {
		names.push_back( "driver/entry" + std::to_string( index) + ".inf") ;
	}

	std::vector<ZipFixtureEntry> entries ;	// 上限超過時の全INF一覧。
	// 名前の格納完了後にviewを作り、再配置で無効化しない。
	for( const std::string &name : names) {
		entries.push_back( {name, DRIVER.data(), DRIVER.size()}) ;
	}

	std::vector<std::byte> archive ;	// 有限個の架空INFだけを保持するZIP。
	DRIVERCRATE_EXPECT( context, createZipFixture( entries, archive)) ;
	OfficialDownloadWorkspace source ;	// Fixtureの入力領域。
	DRIVERCRATE_EXPECT( context, source.initialize( L"common-bound-source", 902U) == 0) ;
	std::wstring hash ;	// 同一性だけのhash。
	DRIVERCRATE_EXPECT( context, storeArchive( source, L"payload.zip", archive, hash) == 0) ;
	DriverArchiveInput input{902U, source.path( L"payload.zip"), archive.size(), hash} ;	// 内容入力。
	CommonDriverPackageInspection inspection ;												// 全体超過では個別結果を残さない。
	DRIVERCRATE_EXPECT(
		context, inspectCommonDriverPackage( input, OfficialDriverArchiveFormat::ZIP, inspection) ==
					 static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW))) ;
	DRIVERCRATE_EXPECT( context, inspection.infs.empty() && inspection.retainedBytes == 0U) ;
	input.byteCount = 128ULL * 1024ULL * 1024ULL + 1U ;
	DRIVERCRATE_EXPECT(
		context, inspectCommonDriverPackage( input, OfficialDriverArchiveFormat::ZIP, inspection) ==
					 static_cast<NativeError>( E_INVALIDARG)) ;
	input.byteCount = archive.size() ;
	DRIVERCRATE_EXPECT(
		context, inspectCommonDriverPackage( input, static_cast<OfficialDriverArchiveFormat>( 99),
											inspection) != 0) ;
	input.scanSessionId = 0U ;
	DRIVERCRATE_EXPECT( context, inspectCommonDriverPackage( input, OfficialDriverArchiveFormat::ZIP,
														   inspection) != 0) ;
}

/**
 * @brief 八軸が内容・Windows適合・由来・未接続方式を混同しないことを検証する。
 * @param[in,out] context Assertion集計先。
 */
void testCommonInfAssessmentBinding( TestContext &context)
{
	CommonInfInspection inspected ;	// File検査は行わず、testだけで渡す署名成功snapshot。
	inspected.scanSessionId = 901U ;
	inspected.state			= CommonInfInspectionState::VERIFIED ;
	inspected.workspace		= std::make_unique<OfficialDownloadWorkspace>() ;
	inspected.closure.packages.push_back(
		{.providerName = L"Fictional", .driverVersion = L"2.0.0.0"}) ;
	UpdateCandidate candidate ;	// 同一性結合を検証する架空候補。
	candidate.identity		  = L"candidate:common:1" ;
	candidate.deviceIdentity  = L"device:common:1" ;
	candidate.packageIdentity = L"package:common:1" ;
	candidate.provider		  = L"Fictional" ;
	candidate.version		  = L"2.0.0.0" ;
	const CandidateAssessmentFinding origin{
		CandidateAssessmentState::NOT_APPLICABLE, CandidateAssessmentReason::USER_PROVIDED,
		CandidateEvidenceKind::USER_INPUT, 1U} ;	// Local由来の未証明状態。
	CandidateAssessment assessment ;				// Builderの検証済み出力。
	DRIVERCRATE_EXPECT( context, makeCommonInfCandidateAssessment( 901U, candidate, inspected, 1U,
																 origin, 0, 0x1000U, assessment)) ;
	DRIVERCRATE_EXPECT( context, assessment.applicability.state == CandidateAssessmentState::PASSED) ;
	DRIVERCRATE_EXPECT( context,
					   assessment.origin.reason == CandidateAssessmentReason::USER_PROVIDED) ;
	DRIVERCRATE_EXPECT( context, assessment.windowsSelection.reason ==
									CandidateAssessmentReason::RANK_UNVERIFIED) ;
	DRIVERCRATE_EXPECT( context,
					   !assessment.executorAvailable && !isCandidateAssessmentReady( assessment)) ;
	inspected.closure.packages.front().hasExternalDependencies = true ;
	DRIVERCRATE_EXPECT( context, makeCommonInfCandidateAssessment( 901U, candidate, inspected, 1U,
																 origin, 0, 0x1000U, assessment)) ;
	DRIVERCRATE_EXPECT( context,
					   assessment.signature.state == CandidateAssessmentState::PASSED &&
						   assessment.applicability.state == CandidateAssessmentState::PASSED) ;
	DRIVERCRATE_EXPECT( context,
					   assessment.requirements.state == CandidateAssessmentState::UNSUPPORTED &&
						   assessment.driverOnly.state == CandidateAssessmentState::UNSUPPORTED) ;
	DRIVERCRATE_EXPECT( context, assessment.explicitRequirements.empty() &&
									!isCandidateAssessmentReady( assessment)) ;
	inspected.closure.packages.front().hasExternalDependencies = false ;
	DRIVERCRATE_EXPECT( context,
					   makeCommonInfCandidateAssessment( 901U, candidate, inspected, 1U, origin, 0,
														std::nullopt, assessment)) ;
	DRIVERCRATE_EXPECT( context,
					   assessment.applicability.reason == CandidateAssessmentReason::PNP_MISMATCH) ;
	DRIVERCRATE_EXPECT( context, makeCommonInfCandidateAssessment(
									901U, candidate, inspected, 1U, origin,
									static_cast<NativeError>( E_FAIL), std::nullopt, assessment)) ;
	DRIVERCRATE_EXPECT( context, assessment.applicability.state == CandidateAssessmentState::FAILED) ;
	DRIVERCRATE_EXPECT( context, assessment.applicability.diagnostic.has_value()) ;
	DRIVERCRATE_EXPECT( context, !makeCommonInfCandidateAssessment(
									901U, candidate, inspected, 1U, origin,
									static_cast<NativeError>( E_FAIL), 0x1000U, assessment)) ;
	DRIVERCRATE_EXPECT( context, !makeCommonInfCandidateAssessment( 0U, candidate, inspected, 1U,
																  origin, 0, 0x1000U, assessment)) ;
	DRIVERCRATE_EXPECT( context, !makeCommonInfCandidateAssessment( 901U, candidate, inspected, 0U,
																  origin, 0, 0x1000U, assessment)) ;
	candidate.version = L"3.0.0.0" ;
	DRIVERCRATE_EXPECT( context, !makeCommonInfCandidateAssessment( 901U, candidate, inspected, 1U,
																  origin, 0, 0x1000U, assessment)) ;
	candidate.version = L"2.0.0.0" ;
	inspected.state	  = CommonInfInspectionState::SIGNATURE_REJECTED ;
	DRIVERCRATE_EXPECT( context, !makeCommonInfCandidateAssessment( 901U, candidate, inspected, 1U,
																  origin, 0, 0x1000U, assessment)) ;
	DriverStoreProvider			 provider ;			// Scanしていないworker境界の拒否だけを試験する。
	std::optional<std::uint32_t> rank = 0x1000U ;	// 失敗時に消すstale rank。
	DRIVERCRATE_EXPECT(
		context, provider.observeInfCandidateRank( 901U, L"device:common:1", *inspected.workspace,
												  inspected.closure.packages.front(), rank) != 0) ;
	DRIVERCRATE_EXPECT( context, !rank) ;
}

/**
 * @brief 合格snapshotの保護fileが同じ長さで改変されても再検証で拒否する。
 * @param[in,out] context Assertion集計先。
 */
void testCommonReverificationTamperRejection( TestContext &context)
{
	constexpr std::array ORIGINAL{std::byte{0x41}, std::byte{0x42}, std::byte{0x43},
								  std::byte{0x44}} ;	// Scan時に固定する架空INF byte列。
	constexpr std::array TAMPERED{std::byte{0x41}, std::byte{0x42}, std::byte{0x43},
								  std::byte{0x45}} ;	// 長さを変えず一byteだけ変更する内容。
	CommonInfInspection	 inspected ;					// VERIFIED相当の一file閉包。
	inspected.scanSessionId = 905U ;
	inspected.state			= CommonInfInspectionState::VERIFIED ;
	inspected.workspace		= std::make_unique<OfficialDownloadWorkspace>() ;
	DRIVERCRATE_EXPECT( context, inspected.workspace->initialize( L"common-reverify", 905U) == 0) ;
	std::wstring sha256 ;	// Scan時fileの実測SHA-256。
	DRIVERCRATE_EXPECT( context,
					   storeArchive( *inspected.workspace, L"sample.inf", ORIGINAL, sha256) == 0) ;
	inspected.closure.entries.push_back(
		{L"sample.inf", static_cast<std::uint64_t>( ORIGINAL.size()), sha256}) ;
	inspected.closure.packages.push_back( {.infRelativePath = L"sample.inf",
										  .providerName	   = L"Fictional",
										  .driverVersion   = L"2.0.0.0"}) ;
	HANDLE file = CreateFileW( inspected.workspace->path( L"sample.inf").c_str(), GENERIC_WRITE, 0,
							  nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
							  nullptr) ;	// 保護copyだけを同じ長さで置き換えるhandle。
	DRIVERCRATE_EXPECT( context, file != INVALID_HANDLE_VALUE) ;
	// Fileを開けた場合だけ改変byte列を書き、無効handleをAPIへ渡さない。
	if( file != INVALID_HANDLE_VALUE) {
		DWORD written{} ;	// 改変時に保存されたbyte数。
		DRIVERCRATE_EXPECT( context,
						   WriteFile( file, TAMPERED.data(), static_cast<DWORD>( TAMPERED.size()),
									 &written, nullptr) != FALSE) ;
		DRIVERCRATE_EXPECT( context, written == TAMPERED.size()) ;
		DRIVERCRATE_EXPECT( context, CloseHandle( file) != FALSE) ;
	}

	DRIVERCRATE_EXPECT( context, reverifyCommonDriverInf( inspected) != 0) ;
}

/**
 * @brief 外側INFと一段nested INFを両方検査し、最後の入力変化も拒否する。
 * @param[in,out] context Assertion集計先。
 */
void testCommonNestedAndLateChange( TestContext &context)
{
	const ZipFixtureEntry innerEntries[]{
		{"driver/sample.inf", VALID_INF.data(), VALID_INF.size()},
		{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
		{"driver/sample.sys", DRIVER.data(), DRIVER.size()},
	} ; // 内側も非実行の架空driverだけを保持する。
	std::vector<std::byte> inner ;	// 一段内側ZIP。
	DRIVERCRATE_EXPECT( context, createZipFixture( innerEntries, inner)) ;
	const ZipFixtureEntry outerEntries[]{
		{"driver/sample.inf", VALID_INF.data(), VALID_INF.size()},
		{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
		{"driver/sample.sys", DRIVER.data(), DRIVER.size()},
		{"nested/package.zip", inner.data(), inner.size()},
	} ; // 直下にINFがあっても内側検査を省略しない構成。
	std::vector<std::byte> outer ;	// 外側ZIP。
	DRIVERCRATE_EXPECT( context, createZipFixture( outerEntries, outer)) ;
	OfficialDownloadWorkspace source ;	// 外側archiveを所有するfixture領域。
	DRIVERCRATE_EXPECT( context, source.initialize( L"common-nested-source", 903U) == 0) ;
	std::wstring hash ;	// 外側の固定hash。
	DRIVERCRATE_EXPECT( context, storeArchive( source, L"payload.zip", outer, hash) == 0) ;
	DriverArchiveInput input{903U, source.path( L"payload.zip"), outer.size(), hash} ;	// 内容入力。
	CommonDriverPackageInspection inspection ;											// 直下と内側の全結果。
	DRIVERCRATE_EXPECT( context, inspectCommonDriverPackage( input, OfficialDriverArchiveFormat::ZIP,
														   inspection) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   inspection.infs.size() == 2U && inspection.inventoryFileCount == 7U) ;
	// 結果数が成立した場合だけ順序と所有権を確認する。
	if( inspection.infs.size() == 2U) {
		DRIVERCRATE_EXPECT( context, inspection.infs[0].nestedArchivePath.empty()) ;
		DRIVERCRATE_EXPECT( context, inspection.infs[1].nestedArchivePath == L"nested\\package.zip") ;
		DRIVERCRATE_EXPECT( context, inspection.infs[0].state ==
										CommonInfInspectionState::SIGNATURE_REJECTED) ;
		DRIVERCRATE_EXPECT( context, inspection.infs[1].state ==
										CommonInfInspectionState::SIGNATURE_REJECTED) ;
	}

	std::size_t calls{} ;	// JobとINFの前、および最後の照会を数える。
	const auto	lateChange = [&input, &calls]() {
		 ++calls ;
		 // 最後の取消し照会でidentity差替えを模し、最終hash照合が必要な状態を作る。
		 if( calls == 5U) {
			 input.sha256.assign( 64U, L'0') ;
		 }

		 return false ;
	} ; // 呼出し中だけ生存するfixture stateを参照する。
	DRIVERCRATE_EXPECT( context, inspectCommonDriverPackage( input, OfficialDriverArchiveFormat::ZIP,
														   inspection, lateChange) != 0) ;
	DRIVERCRATE_EXPECT( context,
					   calls == 5U && inspection.infs.empty() && inspection.scanSessionId == 0U) ;
}

/**
 * @brief 明示依存があるINFでも署名検査を行い、架空CATを署名合格へ進めない。
 * @param[in,out] context Assertion集計先。
 */
void testCommonExplicitDependencyObservation( TestContext &context)
{
	std::string		  inf( VALID_INF) ;								// 明示的な未解決依存を追加する架空INF。
	const std::size_t install = inf.find( "CopyFiles=DriverCopy") ;	// Fixture内の既知DDInstall。
	DRIVERCRATE_EXPECT( context, install != std::string::npos) ;
	// Fixture前提が崩れた場合は範囲外編集を行わない。
	if( install == std::string::npos) {
		return ;
	}

	inf.insert( install, "Include=required.inf\r\nNeeds=Required.Install\r\n") ;
	const ZipFixtureEntry entries[]{
		{"driver/sample.inf", inf.data(), inf.size()},
		{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
		{"driver/sample.sys", DRIVER.data(), DRIVER.size()},
	} ; // 同梱の有無から別の必須依存を推測しない。
	std::vector<std::byte> archive ;	// 非実行の小さなfixture。
	DRIVERCRATE_EXPECT( context, createZipFixture( entries, archive)) ;
	OfficialDownloadWorkspace source ;	// Fixtureだけの入力領域。
	DRIVERCRATE_EXPECT( context, source.initialize( L"common-dependency", 904U) == 0) ;
	std::wstring hash ;	// Fixtureの内容identity。
	DRIVERCRATE_EXPECT( context, storeArchive( source, L"payload.zip", archive, hash) == 0) ;
	const DriverArchiveInput input{904U, source.path( L"payload.zip"), archive.size(),
								   hash} ;	// 内容入力。
	std::vector<std::unique_ptr<OfficialDownloadWorkspace>>
		occupied ;	// 旧共通tagの同時保持上限を再現する。
	// 32件が存続していても別INFの領域を独立に作成できることを後段で確認する。
	for( std::size_t index = 0; index < 32U; ++index) {
		auto held =
			std::make_unique<OfficialDownloadWorkspace>() ;	// このtest終了まで保持する旧名の領域。
		DRIVERCRATE_EXPECT( context, held->initialize( L"common-inf-closure", 904U) == 0) ;
		occupied.push_back( std::move( held)) ;
	}

	CommonDriverPackageInspection inspection ;	// 未対応と全体失敗を区別する結果。
	DRIVERCRATE_EXPECT( context, inspectCommonDriverPackage( input, OfficialDriverArchiveFormat::ZIP,
														   inspection) == 0) ;
	DRIVERCRATE_EXPECT( context, inspection.infs.size() == 1U) ;
	// 個別結果が存在する場合だけ署名検査へ到達した失敗を確認する。
	if( inspection.infs.size() == 1U) {
		DRIVERCRATE_EXPECT( context, inspection.infs.front().state ==
										CommonInfInspectionState::SIGNATURE_REJECTED) ;
		DRIVERCRATE_EXPECT( context, inspection.infs.front().error != 0) ;
	}
}

/**
 * @brief 通常の標準二構文を認識し、架空CAT・作用・形式・欠損を拒否する。
 * @param[in,out] context 架空回帰のassertion集計先。
 * @note 実署名合格・実device・導入を偽装せず、構造から署名への到達だけを確認する。
 */
void testCommonStandardSyntaxBoundary( TestContext &context)
{
	constexpr std::array SYNTAXES{
		std::string_view( "$Windows NT$"),
		std::string_view( "$Chicago$"),
		std::string_view( "$cHiCaGo$"),
		std::string_view( "$wInDoWs Nt$"),
		std::string_view( "$Unknown$"),
		std::string_view( "Chicago"),
		std::string_view( "$Chicago$"),
		std::string_view( "$Chicago$"),
		std::string_view( "$Chicago$"),
		std::string_view( "$Chicago$"),
		std::string_view( "$Chicago$"),
		std::string_view(
			"$Chicago$")} ;	// 標準・大文字小文字・不正構文と他の安全境界を独立に比較する。
	// 全12 scenarioを小さい架空ZIPで検査し、意味の異なる拒否を混ぜない。
	for( std::size_t scenario = 0; scenario < SYNTAXES.size(); ++scenario) {
		std::string		  inf( VALID_INF) ;							// ID・CATは架空のまま構文だけを変える。
		const std::size_t signature = inf.find( "$Windows NT$") ;	// 既知のfixture位置。
		DRIVERCRATE_EXPECT( context, signature != std::string::npos) ;
		// Fixtureが変わった場合は範囲外のreplaceを行わない。
		if( signature == std::string::npos) {
			return ;
		}

		inf.replace( signature, std::string_view( "$Windows NT$").size(), SYNTAXES[scenario]) ;
		// 通常入口の追加作用拒否を旧構文でも維持する。
		if( scenario == 6U) {
			inf += "\r\n[Install.NT.CoInstallers]\r\nAddReg=ExtraActions\r\n"
				   "[ExtraActions]\r\nHKR,,CoInstallers32,0x00010000,\"extra.dll\"\r\n" ;
		}

		// 保守専用の参照EXE許可を通常入口へ持ち込まない。
		if( scenario == 7U) {
			std::size_t position{} ;	// 参照名の有限反復位置。
			// 架空INF内の全参照名を変更し、実EXEを使用しない。
			while( (position = inf.find( "sample.sys", position)) != std::string::npos) {
				inf.replace( position, std::string_view( "sample.sys").size(), "extra.exe") ;
				position += std::string_view( "extra.exe").size() ;
			}
		}

		// 旧構文の認識をx64判定の迂回にしない。
		if( scenario == 9U) {
			std::size_t position{} ;	// Architecture置換だけの反復位置。
			// ModelsとManufacturerの全x64修飾を架空x86へ変更する。
			while( (position = inf.find( "NTamd64", position)) != std::string::npos) {
				inf.replace( position, std::string_view( "NTamd64").size(), "NTx86") ;
				position += std::string_view( "NTx86").size() ;
			}
		}

		std::vector<ZipFixtureEntry> entries{{"driver/sample.inf", inf.data(), inf.size()},
											 {"driver/sample.cat", CATALOG.data(),
											  // 架空CATはどのscenarioでも同梱する。
											  CATALOG.size()}} ;
		// 参照欠損以外は同じ小さい参照byteを置く。
		if( scenario != 8U) {
			entries.push_back( {scenario == 7U ? "driver/extra.exe" : "driver/sample.sys",
							   DRIVER.data(), DRIVER.size()}) ;
		}

		std::vector<std::byte> archive ;	// 非実行の架空原byte。
		DRIVERCRATE_EXPECT( context, createZipFixture( entries, archive)) ;
		// Nested内の旧構文にも同じ通常署名policyを適用する。
		if( scenario == 10U) {
			const ZipFixtureEntry  nested{"nested/package.zip", archive.data(),
										  // 一段の内側byte。
										  archive.size()} ;
			std::vector<std::byte> outer ;	// 有限一段の外側ZIP。
			DRIVERCRATE_EXPECT( context, createZipFixture( std::span( &nested, 1U), outer)) ;
			archive = std::move( outer) ;
		}

		OfficialDownloadWorkspace source ;	// 各scenarioだけの原file所有者。
		DRIVERCRATE_EXPECT( context, source.initialize( L"common-syntax", 907U) == 0) ;
		std::wstring hash ;	// 実架空byteのSHA-256。
		DRIVERCRATE_EXPECT( context, storeArchive( source, L"payload.zip", archive, hash) == 0) ;
		DriverArchiveInput input{907U, source.path( L"payload.zip"), archive.size(),
								 hash} ;	// 固定入力。
		// 構文受理後も元identity不一致を全体で拒否する。
		if( scenario == 11U) {
			input.sha256.assign( 64U, L'0') ;
		}

		CommonDriverPackageInspection inspection ;	// 部分合格を持たせない架空結果。
		const NativeError			  error =
			inspectCommonDriverPackage( input, OfficialDriverArchiveFormat::ZIP,
									   inspection) ;	// 実の通常入口を使用する。
		// 元identity改変では一INFも外へ持ち出さない。
		if( scenario == 11U) {
			DRIVERCRATE_EXPECT( context, error != 0 && inspection.infs.empty()) ;
			continue ;
		}

		DRIVERCRATE_EXPECT( context, error == 0 && inspection.infs.size() == 1U) ;
		// 結果数が成立しない場合は先頭を参照しない。
		if( inspection.infs.size() != 1U) {
			continue ;
		}

		const CommonInfInspection &observed =
			// このscope内だけの個別結果。
			inspection.infs.front() ;
		const bool recognized = scenario < 4U || scenario == 10U ;	// 標準構文かつ他の拒否条件なし。
		DRIVERCRATE_EXPECT( context, observed.state ==
										(recognized ? CommonInfInspectionState::SIGNATURE_REJECTED
													: CommonInfInspectionState::CLOSURE_REJECTED)) ;
		DRIVERCRATE_EXPECT( context, observed.error != 0 && !observed.workspace) ;
		// 再検証APIへ未署名の結果を渡しても合格にならない。
		DRIVERCRATE_EXPECT( context, reverifyCommonDriverInf( observed) != 0) ;
		DRIVERCRATE_EXPECT( context,
						   inspectCommonDriverPackage( input, OfficialDriverArchiveFormat::ZIP,
													  inspection, [] { return true ; }) != 0 &&
							   inspection.infs.empty()) ;
	}
}

/**
 * @brief 非実行棚卸しの選択範囲・間接作用・欠落参照・容量・改変を架空INFで検証する。
 * @param[in,out] context 既存groupに追加するassertion集計先。
 * @note 実CAT・device・installを使用しない。metadata存在だけのIncludeを開いてはならない。
 */
void testSelectedInfInstallInventory( TestContext &context)
{
	static_assert( !std::is_convertible_v<OfficialInfInstallInventory, OfficialInfPackage>) ;
	// 一INFの有限scenarioを独立した保護workspaceで測り、旧拒否回帰は別のまま維持する。
	for( std::size_t scenario = 0U; scenario < 48U; ++scenario) {
		std::string	 inf( VALID_INF) ;		// CAT・IDは架空で、実driverではない。
		std::wstring base = L"Install" ;	// 現OS Modelsに属する通常の導入名。
		// 非選択機種とx86の追加作用を選択した処理へ混入させない。
		if( scenario == 1U || scenario == 27U || scenario == 34U) {
			inf += "\r\n[Other.NT]\r\nRunPostSetupCommands=Commands\r\n"
				   "[Install.NTx86.CoInstallers]\r\nAddReg=ForeignActions\r\n"
				   "[ForeignActions]\r\nHKR,,CoInstallers32,0x00010000,\"foreign.dll\"\r\n"
				   "[Commands]\r\nnever-run.exe\r\n" ;
		}

		// 選択処理の間接registry作用とcommand本文の非保持を確認する。
		if( scenario == 2U) {
			inf +=
				"\r\n[Install.NT.CoInstallers]\r\nAddReg=Actions\r\n"
				"[Actions]\r\nHKR,,CoInstallers32,0x00010000,\"extra.dll\"\r\n"
				"HKLM,SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,Example,0,\"never-run.exe\"\r\n" ;
		}

		// 外部INFの記載・metadata存在・Needs欠落を依存充足へ変換しない。
		if( scenario == 3U || scenario == 4U) {
			inf += "\r\n[Install.NT]\r\nInclude=included.inf\r\nNeeds=Outside.Install\r\n" ;
		}

		// Shared節と循環辺を保持しつつ有限に一度だけ走査する。
		if( scenario == 5U) {
			inf += "\r\n[Install.NT]\r\nNeeds=Extra,Extra\r\n"
				   "[Extra]\r\nNeeds=Install.NT\r\nCopyFiles=DriverCopy\r\n" ;
		}

		// 未知directiveを作用なしと認定しない。
		if( scenario == 6U) {
			inf += "\r\n[Install.NT]\r\nFutureAction=UninterpretedValue\r\n" ;
		}

		// package外への参照を検出したら部分観測を返さない。
		if( scenario == 7U) {
			inf += "\r\n[Install.NT]\r\nInclude=..\\outside.inf\r\n" ;
		}

		// 直接fileの欠落は観測として保持し、適合または署名失敗としない。
		if( scenario == 8U) {
			inf += "\r\n[Install.NT]\r\nCopyFiles=@missing.sys\r\n" ;
		}

		// 未登録の任意sectionはModels照合より先へ進めない。
		if( scenario == 9U) {
			base = L"Arbitrary" ;
			inf += "\r\n[Arbitrary.NT]\r\nCopyFiles=DriverCopy\r\n" ;
		}

		// 明示空DDInstallは作用0の観測であり、適用・導入の合格ではない。
		if( scenario == 10U) {
			const auto position = inf.find( "CopyFiles=DriverCopy\r\n") ;	// 既知fixtureの一指示。
			inf.erase( position, std::string_view( "CopyFiles=DriverCopy\r\n").size()) ;
		}

		// NULを含むsection指定をWin32の切捨てで受理しない。
		if( scenario == 14U) {
			base.push_back( L'\0') ;
			base += L"suffix" ;
		}

		// x86だけのModelsを現在x64用として選択しない。
		if( scenario == 15U) {
			std::size_t position{} ;	// 架空architecture置換の位置。
			// ManufacturerとModelsの全修飾だけを置き換える。
			while( (position = inf.find( "NTamd64", position)) != std::string::npos) {
				inf.replace( position, 7U, "NTx86") ;
				position += 5U ;
			}
		}

		// 空CoInstaller節を非空の宣言として数えない。
		if( scenario == 16U) {
			inf += "\r\n[Install.NT.CoInstallers]\r\n" ;
		}

		// Missingローカル参照を消したり別sectionへ補完したりしない。
		if( scenario == 17U) {
			inf += "\r\n[Install.NT]\r\nAddReg=Missing\r\n" ;
		}

		// 一節をregistry行とfile行の二形式へ解釈する入力を拒否する。
		if( scenario == 18U) {
			inf += "\r\n[Install.NT]\r\nAddReg=DriverCopy\r\n" ;
		}

		// 選択Servicesとその参照先だけを辿り、service binaryを実行しない。
		if( scenario == 19U) {
			inf += "\r\n[Install.NT.Services]\r\nAddService=Example,2,ServiceData\r\n"
				   "[ServiceData]\r\nServiceBinary=%12%\\sample.sys\r\nStartType=3\r\n" ;
		}

		// SetupAPIのStrings展開を使い、参照名の手作業置換を行わない。
		if( scenario == 20U) {
			inf += "\r\n[Install.NT]\r\nAddReg=%ExtraName%\r\n[ExtraRegistry]\r\n"
				   "HKR,,Example,0,\"value\"\r\n[Strings]\r\nExtraName=ExtraRegistry\r\n" ;
		}

		// 一行のfield数を64までへ固定する。
		if( scenario == 21U || scenario == 30U) {
			inf += "\r\n[Install.NT]\r\nFutureAction=" ;
			const std::size_t count = scenario == 21U ? 65U : 64U ;	// Field境界の正負を分ける。
			// 最大field数とその一つ超過の値を作る。
			for( std::size_t field = 0U; field < count; ++field) {
				inf += field == 0U ? "x" : ",x" ;
			}

			inf += "\r\n" ;
		}

		// 旧宣言上限を超えても最終上限内なら正しく観測する。
		if( scenario == 46U) {
			inf += "\r\n[Install.NT]\r\n" ;
			// 未知宣言数とは独立に、標準宣言の保持容量だけを測る。
			for( std::size_t row = 0U; row < 512U; ++row) {
				inf += "StartType=3\r\n" ;
			}
		}

		// 二作用のregistry行を使い、行上限より先に作用4,096件境界を確認する。
		if( scenario == 22U || scenario == 47U) {
			inf += "\r\n[Install.NT]\r\nAddReg=EffectRows\r\n[EffectRows]\r\n" ;
			// 初期二宣言と2,047行の二作用で最大4,096件を構成する。
			for( std::size_t row = 0U; row < 2047U; ++row) {
				inf += "HKR,Software\\Microsoft\\Windows\\CurrentVersion\\Run,"
					   "CoInstallers32,0,never-load.dll\r\n" ;
			}

			// 一作用だけの追加行で新上限を正確に一つ超える。
			if( scenario == 22U) {
				inf += "HKR,,CoInstallers32,0,never-load.dll\r\n" ;
			}
		}

		// 不透明dataも走査行数上限へ含める。
		if( scenario == 23U) {
			inf += "\r\n[DriverCopy]\r\n" ;
			// 初期行を含め、累積4,096行を超える。
			for( std::size_t row = 0U; row < 4096U; ++row) {
				inf += "sample.sys\r\n" ;
			}
		}

		// 多段Needsの1,024節境界と旧128節超過の正例を確認する。
		if( scenario == 24U || scenario == 29U || scenario == 44U) {
			const std::size_t count =
				// 初期二節と合わせた超過／最大。
				scenario == 24U ? 1023U : (scenario == 29U ? 1022U : 127U) ;
			inf += "\r\n[Install.NT]\r\nNeeds=Step0\r\n" ;
			// 有限chainを構成してqueue境界を測る。
			for( std::size_t step = 0U; step < count; ++step) {
				inf += "[Step" + std::to_string( step) + "]\r\n" ;
				// 最終節は空とし、chainの終端を明示する。
				if( step + 1U < count) {
					inf += "Needs=Step" + std::to_string( step + 1U) + "\r\n" ;
				}
			}
		}

		// 過長fieldは切捨てで受理しない。
		if( scenario == 25U) {
			inf += "\r\n[Install.NT]\r\nFutureAction=" + std::string( 4096U, 'x') + "\r\n" ;
		}

		// Shared参照の重複も数え、4,096件境界と旧512件超過の正例を確認する。
		if( scenario == 26U || scenario == 28U || scenario == 45U) {
			inf += "\r\n[Install.NT]\r\n" ;
			const std::size_t references =
				// 初期一参照を含む超過／最大。
				scenario == 26U ? 4096U : (scenario == 28U ? 4095U : 512U) ;
			// 各行は64 fieldを超えずに合計参照数だけを増やす。
			for( std::size_t field = 0U; field < references; ++field) {
				inf += field % 64U == 0U ? "Needs=Empty" : ",Empty" ;
				// 一行64 fieldまでで終端を入れ、参照量だけを独立に増やす。
				if( field % 64U == 63U || field + 1U == references) {
					inf += "\r\n" ;
				}
			}

			inf += "[Empty]\r\n" ;
		}

		// 空の直接file参照を親directoryへ読み替えない。
		if( scenario == 31U) {
			inf += "\r\n[Install.NT]\r\nCopyFiles=@\r\n" ;
		}

		// NTamd64の優先選択で非選択NT節の作用を拾わない。
		if( scenario == 32U) {
			inf += "\r\n[Install.NTamd64]\r\nCopyFiles=DriverCopy\r\n"
				   "[Install.NT.CoInstallers]\r\nAddReg=OtherRegistry\r\n"
				   "[OtherRegistry]\r\nHKR,,CoInstallers32,0x00010000,\"old.dll\"\r\n" ;
		}

		// 標準旧構文も同じ選択と非実行境界で扱う。
		if( scenario == 33U) {
			const auto position = inf.find( "$Windows NT$") ;	// 既知fixtureの識別子位置。
			inf.replace( position, 12U, "$cHiCaGo$") ;
		}

		// 現OS Modelsに登録された別機種の作用でも、選択した導入名へ混入させない。
		if( scenario == 34U) {
			inf += "\r\n[Models.NTamd64]\r\nOtherDevice=Other,PCI\\VEN_9876&DEV_5432\r\n" ;
		}

		// 選択commandと登録dataを読み、実行も本文の結果保存も行わない。
		if( scenario == 35U || scenario == 36U) {
			inf += "\r\n[Install.NT]\r\nRunPostSetupCommands=CommandData\r\n"
				   "[CommandData]\r\nnever-run.exe\r\n" ;
			// DLL自己登録の宣言も独立した作用として観測する。
			if( scenario == 36U) {
				inf += "\r\n[Install.NT]\r\nRegisterDlls=RegistrationData\r\n"
					   "[RegistrationData]\r\n11,,never-load.dll,1\r\n" ;
			}
		}

		// CopyINFの欠落参照をfile copyやIncludeと混同しない。
		if( scenario == 37U) {
			inf += "\r\n[Install.NT]\r\nCopyINF=copied.inf\r\n" ;
		}

		// Componentのローカル処理節の存在だけを観測する。
		if( scenario == 38U) {
			inf += "\r\n[Install.NT.Components]\r\nAddComponent=Example,0,ComponentData\r\n"
				   "[ComponentData]\r\nComponentIDs=FictionalComponent\r\n" ;
		}

		// 現OSより先のTargetOSVersionにしかない機種を現在Modelsへ取り込まない。
		if( scenario == 39U) {
			const auto position = inf.find( "Models,NTamd64\r\n") ;	// 元メーカー行の修飾。
			inf.replace( position, std::string_view( "Models,NTamd64\r\n").size(),
						"Models,NTamd64,NTamd64.10.0...999999\r\n") ;
			inf +=
				"\r\n[Models.NTamd64.10.0...999999]\r\nFuture=FutureInstall,PCI\\VEN_9876&DEV_4321\r\n"
				"[FutureInstall.NT]\r\nCopyFiles=DriverCopy\r\n" ;
			base = L"FutureInstall" ;
		}

		// Windowsが未修飾名を返しても実在しなければ拒否する。
		if( scenario == 40U) {
			const auto position = inf.find( "[Install.NT]") ;	// 元fixtureの選択節名。
			inf.replace( position, 12U, "[Unselected.NT]") ;
		}

		// 未知の構文識別子を標準構文として解析しない。
		if( scenario == 42U) {
			const auto position = inf.find( "$Windows NT$") ;	// 元fixtureの識別子位置。
			inf.replace( position, 12U, "$Unknown$") ;
		}

		// SetupAPIに渡す前に254文字を超える導入名を拒否する。
		if( scenario == 43U) {
			base.assign( 255U, L'X') ;
		}

		OfficialDownloadWorkspace workspace ;	// このscenarioだけのINF所有領域。
		DRIVERCRATE_EXPECT( context, workspace.initialize( L"install-inventory", 908U) == 0) ;
		std::wstring hash ;	// 架空INF自身の全byte hash。
		DRIVERCRATE_EXPECT( context, storeArchive( workspace, L"sample.inf",
												 std::as_bytes( std::span( inf.data(), inf.size())),
												 hash) == 0) ;
		std::vector<OfficialZipEntry> entries{
			{L"sample.inf", inf.size(), hash}} ;	// 元entryの実size／hash。
		// 重複INFを別物のinventoryとして受理しない。
		if( scenario == 11U) {
			entries.push_back( entries.front()) ;
		}

		// 宣言hash改変を解析前に拒否する。
		if( scenario == 12U) {
			entries.front().sha256.assign( 64U, L'0') ;
		}

		// 宣言size改変を解析前に拒否する。
		if( scenario == 13U) {
			++entries.front().uncompressedSize ;
		}

		// 入力INFの4 MiB上限をmetadataだけでも緩めない。
		if( scenario == 41U) {
			entries.front().uncompressedSize = 4U * 1024U * 1024U + 1U ;
		}

		// Includeはentry存在だけを観測し、実fileがなくても開かない。
		if( scenario == 4U) {
			entries.push_back( {L"included.inf", 1U, {}}) ;
		}

		OfficialInfInstallInventory inventory ;	// 署名・導入型ではない結果。
		// 失敗時の旧結果消去も確認する。
		inventory.baseInstallSection = L"stale" ;
		const NativeError error		 = inspectOfficialInfInstallInventory(
			 workspace, entries, L"sample.inf", base, inventory) ;	// 実の非実行共通入口。
		const bool rejected = scenario == 7U ||
							  (scenario >= 9U && scenario <= 15U && scenario != 10U) ||
							  // 独立した拒否条件。
							  scenario == 18U || (scenario >= 21U && scenario <= 26U) ||
							  scenario == 31U || (scenario >= 39U && scenario <= 43U) ;
		DRIVERCRATE_EXPECT( context, (error != 0) == rejected) ;
		// 拒否では旧値・部分作用・部分参照・hashを一つも保持しない。
		if( rejected) {
			DRIVERCRATE_EXPECT(
				context, inventory.baseInstallSection.empty() && inventory.infSha256.empty() &&
							 inventory.effects.empty() && inventory.references.empty() &&
							 inventory.visitedSections.empty() && inventory.coverageGaps.empty()) ;
			continue ;
		}

		// 前提不成立で結果集合を参照しない。
		if( error != 0) {
			continue ;
		}

		DRIVERCRATE_EXPECT( context,
						   inventory.selectedInstallSection ==
								   (scenario == 32U ? L"Install.NTamd64" : L"Install.NT") &&
							   inventory.infSha256 == hash) ;
		DRIVERCRATE_EXPECT( context, inventory.visitedSections.size() <= 1024U &&
										inventory.references.size() <= 4096U &&
										inventory.effects.size() <= 4096U &&
										inventory.scannedLines <= 4096U) ;
		const auto effects = [&inventory]( OfficialInfInstallEffectKind kind) {
			return std::ranges::count_if(
				inventory.effects,
				[kind]( const OfficialInfInstallEffect &item) { return item.kind == kind ; }) ;
		} ; // このscope内の種類だけを数え、本文をlogへ出さない。
		DRIVERCRATE_EXPECT( context, effects( OfficialInfInstallEffectKind::COINSTALLER) ==
										(scenario == 2U ? 2 : (scenario == 47U ? 2047 : 0))) ;
		DRIVERCRATE_EXPECT( context, effects( OfficialInfInstallEffectKind::REGISTRY_AUTORUN) ==
										(scenario == 2U ? 1 : (scenario == 47U ? 2047 : 0))) ;
		DRIVERCRATE_EXPECT( context, effects( OfficialInfInstallEffectKind::UNKNOWN_DIRECTIVE) ==
										(scenario == 6U || scenario == 30U ? 1 : 0)) ;
		DRIVERCRATE_EXPECT( context, effects( OfficialInfInstallEffectKind::COMMAND_EXECUTION) ==
										(scenario == 35U || scenario == 36U ? 1 : 0)) ;
		DRIVERCRATE_EXPECT( context, effects( OfficialInfInstallEffectKind::DLL_REGISTRATION) ==
										(scenario == 36U ? 1 : 0)) ;
		DRIVERCRATE_EXPECT( context, effects( OfficialInfInstallEffectKind::COPY_INF) ==
										(scenario == 37U ? 1 : 0)) ;
		DRIVERCRATE_EXPECT(
			context,
			std::ranges::none_of( inventory.effects, []( const OfficialInfInstallEffect &item) {
				return item.directive.find( L"never-run.exe") != std::wstring::npos ||
					   item.directive.find( L"never-load.dll") != std::wstring::npos ;
			})) ; // 宣言名だけを保持し、command本文を結果へ格納しない。
		// 依存記載二件と存在の区別を個別に確認する。
		if( scenario == 3U || scenario == 4U) {
			DRIVERCRATE_EXPECT( context,
							   inventory.references.size() == 3U &&
								   !inventory.references.back().targetPresent &&
								   inventory.references[1].targetPresent == (scenario == 4U)) ;
		}

		// Shared・循環辺は四本すべて保持するが、三節だけを走査する。
		if( scenario == 5U) {
			DRIVERCRATE_EXPECT( context, inventory.visitedSections.size() == 3U &&
											inventory.references.size() == 5U) ;
		}

		// Missing直接fileとMissingローカルsectionの区分を維持する。
		if( scenario == 8U || scenario == 17U) {
			DRIVERCRATE_EXPECT(
				context, !inventory.references.back().targetPresent &&
							 inventory.references.back().kind ==
								 (scenario == 8U ? OfficialInfInstallReferenceKind::DIRECT_FILE
												 : OfficialInfInstallReferenceKind::LOCAL_SECTION)) ;
		}

		// 最大参照数と最大訪問数の正例を別に確認する。
		if( scenario == 28U || scenario == 29U) {
			DRIVERCRATE_EXPECT( context, scenario == 28U
											? inventory.references.size() == 4096U
											: inventory.visitedSections.size() == 1024U) ;
		}

		// 旧境界超過と新作用最大の正例を個別の実測値へ結合する。
		if( scenario >= 44U) {
			DRIVERCRATE_EXPECT( context,
							   (scenario == 44U && inventory.visitedSections.size() == 129U) ||
								   (scenario == 45U && inventory.references.size() == 513U) ||
								   (scenario == 46U && inventory.effects.size() == 513U) ||
								   (scenario == 47U && inventory.effects.size() == 4096U)) ;
		}
	}
}

/**
 * @brief 同節／別節の明示依存と全不足種類・最大量を架空INFで確認する。
 * @param[in,out] context 一度だけ実行するassertion集計先。
 * @note 値とIDは架空。Include先・未走査節は開かず、実行と導入は行わない。
 */
void testSelectedInfReferenceContext( TestContext &context)
{
	constexpr std::array<std::string_view, 7> UNFOLLOWED{
		"AddProperty", "DelProperty",	  "LogConfig", "ProfileItems",
		"UpdateInis",  "UpdateIniFields", "Ini2Reg"} ;	// 既知不足の個別正例。
	// 元節・directiveと不足を一scenarioずつ独立に確認する。
	for( std::size_t scenario = 0U; scenario < 22U; ++scenario) {
		std::string inf( VALID_INF) ;	// 実deviceを含まない既存の有限fixture。
		// 同節に二Include・二Needsを持ち、一つのmetadata存在だけを模倣する。
		if( scenario == 0U) {
			inf += "\r\n[Install.NT]\r\nInclude=a.inf,b.inf\r\nNeeds=ExternalA,ExternalB\r\n" ;
		}

		// 別節のIncludeはNeedsの充足候補へ自動結合しない。
		if( scenario == 1U) {
			inf +=
				"\r\n[Install.NT]\r\nInclude=a.inf\r\n[Install.NT.Services]\r\nNeeds=ExternalA\r\n" ;
		}

		// Windows規則と同じcase非依存のdirective認識を保持する。
		if( scenario == 2U) {
			inf += "\r\n[Install.NT]\r\niNcLuDe=a.inf\r\nneEdS=ExternalA\r\n" ;
		}

		// 共有／循環でも参照辺の元節と個数を保持する。
		if( scenario == 3U) {
			inf += "\r\n[Install.NT]\r\nNeeds=Shared,Shared\r\n[Shared]\r\nNeeds=Install.NT\r\n" ;
		}

		// 未走査形式を認識しても参照先のcommandを解析済みにはしない。
		if( scenario >= 4U && scenario <= 10U) {
			inf += "\r\n[Install.NT]\r\n" + std::string( UNFOLLOWED[scenario - 4U]) +
				   "=NotFollowed\r\n[NotFollowed]\r\nRunPostSetupCommands=never-run.exe\r\n" ;
		}

		// Service第4 fieldだけをevent-log不足へ数える。
		if( scenario == 11U || scenario == 12U) {
			inf +=
				"\r\n[Install.NT.Services]\r\nAddService=Example,0,ServiceData," +
				std::string( scenario == 11U ? "EventData" : "") +
				",System,EventName\r\n"
				"[ServiceData]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\n"
				"ServiceBinary=%12%\\sample.sys\r\n[EventData]\r\nFutureAction=never-run.exe\r\n" ;
		}

		// 標準宣言のAddSoftwareも独立applicationの範囲未評価として残す。
		if( scenario == 13U) {
			inf += "\r\n[Install.NT.Software]\r\nAddSoftware=Example,0,SoftwareData\r\n"
				   "[SoftwareData]\r\nSoftwareType=2\r\nSoftwareId=pfn://example\r\n" ;
		}

		// 未知directiveを無作用へ変換しない。
		if( scenario == 14U) {
			inf += "\r\n[Install.NT]\r\nFutureAction=NotFollowed\r\n" ;
		}

		// 明示空節のdata本文には不足を作らない。
		if( scenario == 15U) {
			inf += "\r\n[Install.NT]\r\nCopyFiles=Empty\r\n[Empty]\r\n" ;
		}

		// Registryの本文認識を全作用の許可にしない。
		if( scenario == 16U) {
			inf +=
				"\r\n[Install.NT]\r\nAddReg=RegistryData\r\n[RegistryData]\r\nHKR,,Example,0,value\r\n" ;
		}

		// 不足4,096件の最大正例と、行数が一つ超える全体拒否を区別する。
		if( scenario == 17U || scenario == 18U) {
			const auto position = inf.find( "CopyFiles=DriverCopy") ;	// 既存の一参照行。
			inf.erase( position, std::string_view( "CopyFiles=DriverCopy").size()) ;
			inf += "\r\n[Install.NT]\r\n" ;
			// 一行一不足で、行上限と不足保持上限を正確に構成する。
			for( std::size_t row = 0U; row < (scenario == 17U ? 4096U : 4097U); ++row) {
				inf += "FutureAction=ignored\r\n" ;
			}
		}

		// 解析前の改変拒否でも旧不足を破棄する。
		if( scenario == 19U) {
			inf += "\r\n[Install.NT]\r\nFutureAction=ignored\r\n" ;
		}

		// Needsにないローカル欠落を依存辺へ誤分類しない。
		if( scenario == 20U) {
			inf +=
				"\r\n[Install.NT]\r\nInclude=a.inf\r\nNeeds=ExternalA\r\nAddReg=MissingRegistry\r\n" ;
		}

		// 空の選択節は不足なしでも完全性を認定する型へ変換しない。
		if( scenario == 21U) {
			const auto position = inf.find( "CopyFiles=DriverCopy") ;	// 元の参照宣言。
			inf.erase( position, std::string_view( "CopyFiles=DriverCopy").size()) ;
		}

		OfficialDownloadWorkspace workspace ;	// 一回の架空INFを単独所有する領域。
		DRIVERCRATE_EXPECT( context, workspace.initialize( L"inf-context", 909U) == 0) ;
		std::wstring hash ;	// 入力INF全byteの有限結合。
		DRIVERCRATE_EXPECT( context, storeArchive( workspace, L"sample.inf",
												 std::as_bytes( std::span( inf.data(), inf.size())),
												 hash) == 0) ;
		std::vector<OfficialZipEntry> entries{
			{L"sample.inf", inf.size(), hash}} ;	// 実INF metadata。
		// 未取得のIncludeは一覧存在だけであり、ファイルを開いてはならない。
		if( scenario == 0U) {
			entries.push_back( {L"a.inf", 1U, {}}) ;
		}

		// 誤ったhashを結果へ結合しない。
		if( scenario == 19U) {
			entries.front().sha256.assign( 64U, L'0') ;
		}

		OfficialInfInstallInventory inventory ;	// 新不足も旧拒否時に残さない観測。
		inventory.coverageGaps.push_back(
			{L"stale", L"stale", OfficialInfInstallCoverageKind::UNKNOWN_DIRECTIVE}) ;
		const NativeError error = inspectOfficialInfInstallInventory(
			workspace, entries, L"sample.inf", L"Install", inventory) ;	// 非実行入口。
		DRIVERCRATE_EXPECT( context, (error != 0) == (scenario == 18U || scenario == 19U)) ;
		// 拒否では新不足を含む全ての部分集合を消去する。
		if( error != 0) {
			DRIVERCRATE_EXPECT( context, inventory.coverageGaps.empty() &&
											inventory.references.empty() &&
											inventory.effects.empty()) ;
			continue ;
		}

		DRIVERCRATE_EXPECT( context, inventory.coverageGaps.size() <= inventory.scannedLines &&
										inventory.coverageGaps.size() <= 4096U) ;
		const auto countGaps = [&inventory]( OfficialInfInstallCoverageKind kind) {
			return std::ranges::count_if( inventory.coverageGaps,
										 [kind]( const auto &gap) { return gap.kind == kind ; }) ;
		} ; // 同期借用の有限不足だけを数える。
		DRIVERCRATE_EXPECT(
			context, countGaps( OfficialInfInstallCoverageKind::UNFOLLOWED_SECTION_REFERENCES) ==
						 (scenario >= 4U && scenario <= 10U ? 1 : 0)) ;
		DRIVERCRATE_EXPECT( context,
						   countGaps( OfficialInfInstallCoverageKind::UNFOLLOWED_SERVICE_EVENTLOG) ==
							   (scenario == 11U ? 1 : 0)) ;
		DRIVERCRATE_EXPECT(
			context,
			countGaps( OfficialInfInstallCoverageKind::SOFTWARE_INSTALLATION_NOT_ASSESSED) ==
				(scenario == 13U ? 1 : 0)) ;
		DRIVERCRATE_EXPECT( context, countGaps( OfficialInfInstallCoverageKind::UNKNOWN_DIRECTIVE) ==
										(scenario == 17U ? 4096 : (scenario == 14U ? 1 : 0))) ;
		DRIVERCRATE_EXPECT( context,
						   countGaps( OfficialInfInstallCoverageKind::DATA_ROWS_NOT_INTERPRETED) ==
							   (scenario == 17U || scenario == 21U ? 0 : 1)) ;
		DRIVERCRATE_EXPECT( context,
						   countGaps( OfficialInfInstallCoverageKind::REGISTRY_SCOPE_NOT_ASSESSED) ==
							   (scenario == 16U ? 1 : 0)) ;
		// 元節と二つの参照先・存在観測を一対一に保持する。
		if( scenario == 0U) {
			DRIVERCRATE_EXPECT( context, inventory.references.size() == 5U &&
											inventory.references[1].section == L"Install.NT" &&
											inventory.references[3].section == L"Install.NT") ;
			DRIVERCRATE_EXPECT( context, inventory.references[1].targetPresent &&
											!inventory.references[2].targetPresent &&
											!inventory.references[3].targetPresent) ;
		}

		// 別節の辺に同じ元節を付け直さない。
		if( scenario == 1U) {
			DRIVERCRATE_EXPECT( context,
							   inventory.references[1].section != inventory.references[2].section &&
								   inventory.references[2].directive == L"Needs") ;
		}

		// 循環と重複の辺は三本を保持し、同じ節は再走査しない。
		if( scenario == 3U) {
			DRIVERCRATE_EXPECT( context, inventory.references.size() == 4U &&
											inventory.visitedSections.size() == 3U) ;
		}

		// 第4 fieldのevent-log本文は未知directiveとして走査していない。
		if( scenario == 11U || scenario == 12U) {
			DRIVERCRATE_EXPECT(
				context, std::ranges::none_of( inventory.visitedSections, []( const auto &name) {
					return name == L"EventData" ;
				})) ;
		}
	}
}

/**
 * @brief 標準構文・参照coverage・root署名・従来作用拒否を独立に確認する。
 * @param[in,out] context 架空fixtureのassertion集計先。
 * @note 架空CATはどの経路でも合格しない。実device・導入APIを呼ばない。
 */
void testMaintenanceVerdictSeparation( TestContext &context)
{
	// 標準二識別子・作用あり・未知識別子・参照欠落を有限に比較する。
	for( std::size_t scenario = 0; scenario < 5U; ++scenario) {
		std::string inf( VALID_INF) ;	// 元fixtureの構文だけを変更し、CATは架空のままとする。
		// Legacy識別子を内容・通常入口の両方で受理することを確認する。
		if( scenario == 1U) {
			const std::size_t position = inf.find( "$Windows NT$") ;	// 既知のfixture識別子位置。
			DRIVERCRATE_EXPECT( context, position != std::string::npos) ;
			inf.replace( position, std::string_view( "$Windows NT$").size(), "$cHiCaGo$") ;
		}

		// 追加作用を内容不正と混同せず、従来入口の拒否は維持する。
		if( scenario == 2U) {
			inf += "\r\n[Install.NT.CoInstallers]\r\nAddReg=ExtraActions\r\n"
				   "[ExtraActions]\r\nHKR,,CoInstallers32,0x00010000,\"extra.dll\"\r\n" ;
		}

		// 未知識別子を既知形式へ正規化して受理しない。
		if( scenario == 3U) {
			const std::size_t position = inf.find( "$Windows NT$") ;	// 架空の未知値を置く位置。
			DRIVERCRATE_EXPECT( context, position != std::string::npos) ;
			inf.replace( position, std::string_view( "$Windows NT$").size(), "$Unknown$") ;
		}

		std::vector<ZipFixtureEntry> entries{
			{"driver/sample.inf", inf.data(), inf.size()},
			{"driver/sample.cat", CATALOG.data(), CATALOG.size()},
		} ; // 不正CATは常に保持する。
		// 欠落scenario以外は参照fileの構造を満たす。
		if( scenario != 4U) {
			entries.push_back( {"driver/sample.sys", DRIVER.data(), DRIVER.size()}) ;
		}

		std::vector<std::byte> archive ;	// 元byte固定用の非実行ZIP。
		DRIVERCRATE_EXPECT( context, createZipFixture( entries, archive)) ;
		OfficialDownloadWorkspace source ;	// Fixtureだけの元file領域。
		// Legacy識別子は一段nested経路でも署名検査へ到達する必要がある。
		if( scenario == 1U) {
			const ZipFixtureEntry  nestedEntry{"nested/package.zip", archive.data(),
											   // 内側の元byte。
											   archive.size()} ;
			std::vector<std::byte> outer ;	// 一段だけを許す外側fixture。
			DRIVERCRATE_EXPECT( context, createZipFixture( std::span( &nestedEntry, 1U), outer)) ;
			archive = std::move( outer) ;
		}

		DRIVERCRATE_EXPECT( context, source.initialize( L"maintenance-test", 905U) == 0) ;
		std::wstring hash ;	// 元archiveの内容identity。
		DRIVERCRATE_EXPECT( context, storeArchive( source, L"payload.zip", archive, hash) == 0) ;
		DriverArchiveInput				   input{905U, source.path( L"payload.zip"), archive.size(),
								 hash} ;			// 固定入力。
		MaintenanceDriverPackageInspection result ;	// 導入用workspaceを持たない四軸。
		DRIVERCRATE_EXPECT( context, inspectMaintenanceDriverPackage(
										input, OfficialDriverArchiveFormat::ZIP, result) == 0) ;
		DRIVERCRATE_EXPECT( context, result.infs.size() == 1U) ;
		// 結果数が揃った場合だけ各軸の独立性を確認する。
		if( result.infs.size() == 1U) {
			const MaintenanceInfInspection &row = result.infs.front() ;	// このfixtureだけの観測。
			DRIVERCRATE_EXPECT( context,
							   row.applicability.state == MaintenanceInspectionState::NOT_CHECKED) ;
			DRIVERCRATE_EXPECT( context, row.applicability.error == 0) ;
			// 有効構造の架空CATは実署名検証に失敗し、未検査とは区別する。
			if( scenario < 3U) {
				DRIVERCRATE_EXPECT( context, row.parser.state == MaintenanceInspectionState::PASSED) ;
				DRIVERCRATE_EXPECT( context,
								   row.integrity.state == MaintenanceInspectionState::FAILED) ;
				DRIVERCRATE_EXPECT( context, row.integrity.error != 0 && !row.infSha256.empty()) ;
				DRIVERCRATE_EXPECT( context,
								   row.rootIntegrity.state == MaintenanceInspectionState::FAILED &&
									   row.rootIntegrity.error == row.integrity.error) ;
				DRIVERCRATE_EXPECT(
					context, row.referenceCoverage ==
								 (scenario < 2U ? MaintenanceInfReferenceCoverage::COMPLETE
												: MaintenanceInfReferenceCoverage::INCOMPLETE)) ;
				DRIVERCRATE_EXPECT( context,
								   row.installRoute.state ==
									   (scenario < 2U ? MaintenanceInspectionState::PASSED
													  : MaintenanceInspectionState::UNSUPPORTED)) ;
			}
			// 必須SYSの欠落は位置不足へ残し、構造成功と既知root失敗を未検査で消さない。
			else if( scenario == 4U) {
				DRIVERCRATE_EXPECT( context, row.parser.state == MaintenanceInspectionState::PASSED) ;
				DRIVERCRATE_EXPECT( context, row.parser.error == 0) ;
				DRIVERCRATE_EXPECT( context,
								   row.contentKind == MaintenanceInfContentKind::PACKAGE_FILES) ;
				DRIVERCRATE_EXPECT( context, row.referenceCoverage ==
												MaintenanceInfReferenceCoverage::INCOMPLETE) ;
				DRIVERCRATE_EXPECT( context,
								   row.rootIntegrity.state == MaintenanceInspectionState::FAILED) ;
				DRIVERCRATE_EXPECT( context, row.rootIntegrity.error != 0) ;
				DRIVERCRATE_EXPECT( context,
								   row.integrity.state == MaintenanceInspectionState::FAILED) ;
				DRIVERCRATE_EXPECT( context, row.integrity.error == row.rootIntegrity.error) ;
				DRIVERCRATE_EXPECT( context, row.installRoute.state ==
												MaintenanceInspectionState::UNSUPPORTED) ;
				DRIVERCRATE_EXPECT( context, row.installRoute.error ==
												static_cast<NativeError>(
													HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND))) ;
				DRIVERCRATE_EXPECT( context,
								   row.dependency.state == MaintenanceInfDependencyState::NONE &&
									   row.dependency.reason == InfDependencyReason::NONE) ;
				DRIVERCRATE_EXPECT( context, row.dependency.observedReferenceCount == 0U &&
												row.dependency.resolvedInfCount == 0U) ;
				DRIVERCRATE_EXPECT( context, row.dependency.error == row.rootIntegrity.error) ;
				DRIVERCRATE_EXPECT( context,
								   row.dependenciesChecked && !row.hasExternalDependencies) ;
				DRIVERCRATE_EXPECT( context, !row.infSha256.empty() &&
												row.inspectedBytes == inf.size() + CATALOG.size()) ;
			} else {
				DRIVERCRATE_EXPECT( context, row.parser.state != MaintenanceInspectionState::PASSED) ;
				DRIVERCRATE_EXPECT( context,
								   row.integrity.state == MaintenanceInspectionState::NOT_CHECKED) ;
				DRIVERCRATE_EXPECT( context, row.installRoute.state ==
												MaintenanceInspectionState::NOT_CHECKED) ;
			}
		}

		CommonDriverPackageInspection old ;	// 通常の構文受理と作用拒否を確認する。
		DRIVERCRATE_EXPECT(
			context, inspectCommonDriverPackage( input, OfficialDriverArchiveFormat::ZIP, old) == 0) ;
		// 標準構文を受理しても架空CATは必ず署名で拒否する。
		if( scenario == 1U && old.infs.size() == 1U) {
			DRIVERCRATE_EXPECT( context, old.infs.front().state ==
											CommonInfInspectionState::SIGNATURE_REJECTED) ;
			DRIVERCRATE_EXPECT( context, old.infs.front().error != 0) ;
		}

		// 追加作用の拒否は保守用の作用許可へ合わせて緩和しない。
		if( scenario == 2U && old.infs.size() == 1U) {
			DRIVERCRATE_EXPECT( context, old.infs.front().state ==
											CommonInfInspectionState::CLOSURE_REJECTED) ;
		}

		// 保守構造の成功で必須SYS欠落を通常の導入候補へ昇格させない。
		if( scenario == 4U) {
			DRIVERCRATE_EXPECT( context, old.infs.size() == 1U) ;
			// 個別結果がある場合だけ、従来の閉包拒否と元診断を確認する。
			if( old.infs.size() == 1U) {
				DRIVERCRATE_EXPECT( context, old.infs.front().state ==
												CommonInfInspectionState::CLOSURE_REJECTED) ;
				DRIVERCRATE_EXPECT( context, old.infs.front().error != 0) ;
			}
		}

		DRIVERCRATE_EXPECT( context,
						   inspectMaintenanceDriverPackage( input, OfficialDriverArchiveFormat::ZIP,
														   result, [] { return true ; }) != 0) ;
		DRIVERCRATE_EXPECT( context, result.infs.empty() && result.scanSessionId == 0) ;
		// 取消しcallback例外も部分結果を残さず、worker境界へ漏らさない。
		DRIVERCRATE_EXPECT( context,
						   inspectMaintenanceDriverPackage(
							   input, OfficialDriverArchiveFormat::ZIP, result, []() -> bool {
								   throw std::runtime_error( "maintenance fixture") ;
							   }) == static_cast<NativeError>( E_UNEXPECTED)) ;
		DRIVERCRATE_EXPECT( context, result.infs.empty()) ;
		DriverArchiveInput overBudget = input ;	// 全体予算違反を元file読取前に拒否する。
		overBudget.byteCount		  = 129ULL * 1024ULL * 1024ULL ;
		DRIVERCRATE_EXPECT( context, inspectMaintenanceDriverPackage(
										overBudget, OfficialDriverArchiveFormat::ZIP, result) ==
										static_cast<NativeError>( E_INVALIDARG)) ;
		DRIVERCRATE_EXPECT( context, result.infs.empty()) ;
		input.sha256.assign( 64U, L'0') ;
		DRIVERCRATE_EXPECT( context, inspectMaintenanceDriverPackage(
										input, OfficialDriverArchiveFormat::ZIP, result) != 0) ;
		DRIVERCRATE_EXPECT( context, result.infs.empty()) ;
	}
}

/**
 * @brief 保守EXEの構造と参照欠落を分け、通常入口と禁止拡張子を緩和しない。
 * @param[in,out] context 架空fixtureのassertion集計先。
 * @note 架空CATは必ず失敗し、EXEは実行・導入・library loadしない。
 */
void testMaintenanceReferencedExecutableBoundary( TestContext &context)
{
	constexpr std::array NAMES{std::string_view( "setup.exe"), std::string_view( "setup.EXE"),
							   std::string_view( "setup.ex_"), std::string_view( "setup.msi"),
							   std::string_view( "setup.ps1"), std::string_view( "setup.bin"),
							   std::string_view( "setup.zip"),
							   // 最後のEXEだけが欠損している。構造と参照coverageを別に確認する。
							   std::string_view( "setup.exe")} ;
	// 有限の拡張子境界と欠損を、同じ不正CATで比較する。
	for( std::size_t scenario = 0; scenario < NAMES.size(); ++scenario) {
		std::string inf( PROGRAM_INF) ;	// 参照名だけを変更する架空INF。
		std::size_t position{} ;		// 全てのsource／copy参照を同じ名前へ置換する。
		// 既知fixture内の参照名を有限に置換し、INFと実file名を一致させる。
		while( (position = inf.find( "setup.exe", position)) != std::string::npos) {
			inf.replace( position, std::string_view( "setup.exe").size(), NAMES[scenario]) ;
			position += NAMES[scenario].size() ;
		}

		std::vector<ZipFixtureEntry> entries{
			{"sample.inf", inf.data(), inf.size()},
			{"sample.cat", CATALOG.data(), CATALOG.size()},
			{"sample.sys", DRIVER.data(), DRIVER.size()},
		} ; // 不正CATとSYSは全scenarioに保持する。
		// 最後のscenarioだけで必須参照を欠かせ、位置不足とroot署名を別に確認する。
		if( scenario + 1U != NAMES.size()) {
			entries.push_back( {NAMES[scenario].data(), SETUP.data(), SETUP.size()}) ;
		}

		std::vector<std::byte> archive ;	// 非実行の元byte固定用ZIP。
		DRIVERCRATE_EXPECT( context, createZipFixture( entries, archive)) ;
		OfficialDownloadWorkspace source ;	// Fixtureだけの保護領域。
		DRIVERCRATE_EXPECT( context, source.initialize( L"maintenance-exe-test", 906U) == 0) ;
		std::wstring hash ;	// 元入力のSHA-256。
		DRIVERCRATE_EXPECT( context, storeArchive( source, L"payload.zip", archive, hash) == 0) ;
		const DriverArchiveInput		   input{906U, source.path( L"payload.zip"), archive.size(),
										 hash} ;	// 元入力の固定identity。
		MaintenanceDriverPackageInspection result ;	// 導入用のpath・workspaceを持たない結果。
		const NativeError				   maintenanceError = inspectMaintenanceDriverPackage(
			 input, OfficialDriverArchiveFormat::ZIP, result) ;	// 全体破損と個別拒否を区別する。
		// 壊れたnested ZIPは全体失敗にし、INFの部分結果を保持しない。
		if( scenario == 6U) {
			DRIVERCRATE_EXPECT( context, maintenanceError != 0 && result.infs.empty()) ;
		} else {
			DRIVERCRATE_EXPECT( context, maintenanceError == 0 && result.infs.size() == 1U) ;
		}

		// 一件の結果がある場合だけ、署名へ進んだかを確認する。
		if( result.infs.size() == 1U) {
			const MaintenanceInfInspection &row = result.infs.front() ;	// 現scenarioの四軸。
			DRIVERCRATE_EXPECT( context,
							   row.applicability.state == MaintenanceInspectionState::NOT_CHECKED) ;
			DRIVERCRATE_EXPECT( context, row.applicability.error == 0) ;
			DRIVERCRATE_EXPECT( context, row.integrity.state != MaintenanceInspectionState::PASSED) ;
			// 非圧縮EXEだけは解析し、架空CATの署名失敗を別軸へ保持する。
			if( scenario < 2U) {
				DRIVERCRATE_EXPECT( context, row.parser.state == MaintenanceInspectionState::PASSED) ;
				DRIVERCRATE_EXPECT( context,
								   row.integrity.state == MaintenanceInspectionState::FAILED) ;
				DRIVERCRATE_EXPECT( context, row.integrity.error != 0 && !row.infSha256.empty()) ;
				DRIVERCRATE_EXPECT( context,
								   row.rootIntegrity.state == MaintenanceInspectionState::FAILED &&
									   row.rootIntegrity.error == row.integrity.error) ;
				DRIVERCRATE_EXPECT( context, row.referenceCoverage ==
												MaintenanceInfReferenceCoverage::COMPLETE) ;
				DRIVERCRATE_EXPECT( context, row.installRoute.state ==
												MaintenanceInspectionState::UNSUPPORTED) ;
			}
			// 必須EXEの欠落を構造不正へ潰さず、既知root失敗と通常経路の不成立を保持する。
			else if( scenario + 1U == NAMES.size()) {
				DRIVERCRATE_EXPECT( context, row.parser.state == MaintenanceInspectionState::PASSED) ;
				DRIVERCRATE_EXPECT( context, row.parser.error == 0) ;
				DRIVERCRATE_EXPECT( context,
								   row.contentKind == MaintenanceInfContentKind::PACKAGE_FILES) ;
				DRIVERCRATE_EXPECT( context, row.referenceCoverage ==
												MaintenanceInfReferenceCoverage::INCOMPLETE) ;
				DRIVERCRATE_EXPECT( context,
								   row.rootIntegrity.state == MaintenanceInspectionState::FAILED) ;
				DRIVERCRATE_EXPECT( context, row.rootIntegrity.error != 0) ;
				DRIVERCRATE_EXPECT( context,
								   row.integrity.state == MaintenanceInspectionState::FAILED) ;
				DRIVERCRATE_EXPECT( context, row.integrity.error == row.rootIntegrity.error) ;
				DRIVERCRATE_EXPECT( context, row.installRoute.state ==
												MaintenanceInspectionState::UNSUPPORTED) ;
				DRIVERCRATE_EXPECT( context, row.installRoute.error ==
												static_cast<NativeError>(
													HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND))) ;
				DRIVERCRATE_EXPECT( context,
								   row.dependency.state == MaintenanceInfDependencyState::NONE &&
									   row.dependency.reason == InfDependencyReason::NONE) ;
				DRIVERCRATE_EXPECT( context, row.dependency.observedReferenceCount == 0U &&
												row.dependency.resolvedInfCount == 0U) ;
				DRIVERCRATE_EXPECT( context, row.dependency.error == row.rootIntegrity.error) ;
				DRIVERCRATE_EXPECT( context,
								   row.dependenciesChecked && !row.hasExternalDependencies) ;
				DRIVERCRATE_EXPECT( context, !row.infSha256.empty() &&
												row.inspectedBytes ==
													inf.size() + CATALOG.size() + DRIVER.size()) ;
			} else {
				DRIVERCRATE_EXPECT( context, row.parser.state != MaintenanceInspectionState::PASSED) ;
				DRIVERCRATE_EXPECT( context,
								   row.integrity.state == MaintenanceInspectionState::NOT_CHECKED) ;
			}
		}

		CommonDriverPackageInspection normal ;	// 従来の参照EXE拒否を維持する結果。
		const NativeError			  normalError = inspectCommonDriverPackage(
			input, OfficialDriverArchiveFormat::ZIP, normal) ;	// 従来の全体破損境界。
		// 通常入口も破損nested ZIPを全体で拒否する。
		if( scenario == 6U) {
			DRIVERCRATE_EXPECT( context, normalError != 0 && normal.infs.empty()) ;
		} else {
			DRIVERCRATE_EXPECT( context, normalError == 0 && normal.infs.size() == 1U) ;
		}

		// 従来入口ではEXEを含むどのfixtureも閉包を受理しない。
		if( normal.infs.size() == 1U) {
			DRIVERCRATE_EXPECT( context, normal.infs.front().state ==
											CommonInfInspectionState::CLOSURE_REJECTED) ;
		}

		// 直接のpolicy指定でも通常閉包の拒否を回避できないことを確認する。
		if( scenario == 0U) {
			constexpr std::array SELECTED_INF{std::wstring_view( L"sample.inf")} ;	// 架空INFだけ。
			const DriverClosureRequest request{
				.input			  = &input,
				.archiveFormat	  = OfficialDriverArchiveFormat::ZIP,
				.selectedInfPaths = SELECTED_INF,
				.workspaceTag	  = L"maintenance-exe-output",
			} ; // 同じ元入力に拘束した非実行要求。
			OfficialDriverClosurePolicy policy = POLICY ;	// 既存構造条件を維持する。
			policy.infPolicy.allowReferencedExecutablesForContent = true ;
			OfficialDownloadWorkspace normalOutput ;	// 通常拒否後に解放する領域。
			OfficialDriverClosure	  normalClosure ;	// 失敗時は空。
			DRIVERCRATE_EXPECT(
				context, extractDriverClosure( request, policy, normalOutput, normalClosure) != 0) ;
			DRIVERCRATE_EXPECT( context, normalClosure.entries.empty()) ;
			OfficialDownloadWorkspace maintenanceOutput ;	// 非実行保守閉包の所有先。
			MaintenanceDriverClosure  maintenanceClosure ;	// 通常導入型と非互換。
			DRIVERCRATE_EXPECT( context,
							   extractMaintenanceDriverClosure( request, policy, maintenanceOutput,
															   maintenanceClosure) == 0) ;
			DRIVERCRATE_EXPECT( context, maintenanceClosure.content.entries.size() == 4U) ;
			policy.infPolicy.allowReferencedExecutablesForContent = false ;
			OfficialDownloadWorkspace defaultOutput ;	// 既定falseの拒否を確認する領域。
			MaintenanceDriverClosure  defaultClosure ;	// 暗黙のEXE許可をしない。
			DRIVERCRATE_EXPECT( context, extractMaintenanceDriverClosure(
											request, policy, defaultOutput, defaultClosure) != 0) ;
			DRIVERCRATE_EXPECT( context, defaultClosure.content.entries.empty()) ;
		}
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_driver_closure_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOfficialDriverClosureTests( TestContext &context)
{
	testMaintenanceReferencedExecutableBoundary( context) ;
	testMaintenanceVerdictSeparation( context) ;
	testCommonStandardSyntaxBoundary( context) ;
	testSelectedInfInstallInventory( context) ;
	testSelectedInfReferenceContext( context) ;
	testCommonArchiveContentBoundary( context) ;
	testIntelWindows11DelegatedArchiveContentConnection( context) ;
	testCommonArchiveBounds( context) ;
	testCommonNestedAndLateChange( context) ;
	testCommonExplicitDependencyObservation( context) ;
	testCommonInfAssessmentBinding( context) ;
	testCommonReverificationTamperRejection( context) ;
	testIntelEthernetProfileAndHashGuards( context) ;
	testIntelEthernetInfAndSignatureRejections( context) ;
	testIntelEthernetCountAndCapacityRejections( context) ;
	testIntelEthernetCandidateVersionActions( context) ;
	testIntelEthernetUnknownVersionExclusion( context) ;
	testIntelEthernetDdinstallBindingMismatch( context) ;
	testIntelEthernetUnsupportedOemExclusion( context) ;
	testIntelEthernetDuplicateVersionExclusion( context) ;
	testIntelEthernetBindingRejectionHasNoCandidates( context) ;
	testIntelEthernetSameRankCurrentDriverChange( context) ;
	testIntelEthernetStagedNodeChangeRejected( context) ;
	testIntelEthernetHashAndSignatureChangesRejected( context) ;
	testIntelEthernetDeviceInstallFailureAfterStaging( context) ;
	testIntelEthernetServerEnvironmentRejections( context) ;
	testIntelEthernetPartialFailureAndRebootAggregation( context) ;
	testIntelEthernetCallbackExceptionContinues( context) ;
	testIntelEthernetStaleScanSessionRejected( context) ;
	testIntelEthernetRankAndPartialFailure( context) ;
	testIntelEthernetReportBindingAndLifetime( context) ;
	testIntelEthernetRankCancellationAndException( context) ;
	testAsixProfileHashAndCapacityGuards( context) ;
	testAsixInfAndSignatureRejections( context) ;
	testAsixRankApplicability( context) ;
	testAsixReportEquivalenceAndLifetime( context) ;
	testAsixBoundCandidatePublication( context) ;
	testAsixBoundInstallResultsAndGuards( context) ;
	testAsixPartialFailureCancellationAndInstallBlock( context) ;
	testBroadcomSharedAuditNoPublicHash( context) ;
	testSharedAuditProfileAndHashGuards( context) ;
	testBroadcomPreparedAuditBoundary( context) ;
	testSharedRankSessionAndCancellation( context) ;
	testSharedRankPartialFailure( context) ;
	testArchiveInventory( context) ;
	testAsusAllInfAudit( context) ;
	testAsusNestedInfAudit( context) ;
	testAsusRankApplicability( context) ;
	testAsusInstallReverification( context) ;
	testSelectiveMixedArchive( context) ;
	testSelectiveCabArchive( context) ;
	testReferencedProgramRejected( context) ;
	testInstallActionRejected( context) ;
	testNestedZipClosure( context) ;
	testNestedCabClosure( context) ;
	testUnacquiredInputRejected( context) ;
	testAcquiredArchiveTamperingRejected( context) ;
	testExternalFileAdoption( context) ;
	testCabCleanupContinuesAfterFailure( context) ;
	testExpansionRatioRejected( context) ;
}

} // namespace drivercrate::test
