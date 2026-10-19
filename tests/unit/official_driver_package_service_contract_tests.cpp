//------------------------------------------------------------------------------
/**
 * @file official_driver_package_service_contract_tests.cpp
 * @brief 専用compileでサービス内容集合の正常終端と途中失敗を直接観測します。
 * @version 01.00.00
 * @date 2026/10/13
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/13  同有効HINFの正常集合と途中失敗empty契約を追加。
 * </pre>
 *
 * @note 製品ではcompileしません。署名・実device・サービス起動・導入の成功は認定しません。
 * @see docs/adr/0335-required-win32-service-component.md
 */
//------------------------------------------------------------------------------

#include "support/inf_dependency_native_test_api.h"
#include "test_framework.h"

#include <Windows.h>
#include <SetupAPI.h>
#include <array>
#include <cstddef>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::test {
/**
 * @brief 専用翻訳単位の列挙呼出しを実APIまたは固定障害へ結びます。
 * @param[in] inf 呼出し中に生存する有効な実INFです。
 * @param[in] index 元section indexです。
 * @param[out] buffer 元APIの出力先です。障害注入時は使用しません。
 * @param[in] capacity 元bufferの文字容量です。
 * @param[out] required 元APIの必要長です。null可です。
 * @return 実APIの成功値、または固定Win32診断を伴うFALSEです。
 */
BOOL WINAPI serviceContractEnumInfSections( HINF inf, UINT index, PWSTR buffer, UINT capacity,
										   PUINT required) ;
}

// 実SDK宣言後の呼出しだけを試験wrapperへ結び、製品の翻訳単位には定義しません。
#define SetupEnumInfSectionsW ::drivercrate::test::serviceContractEnumInfSections
#include "platform/official_driver_package.cpp"
#undef SetupEnumInfSectionsW

namespace drivercrate::test {
namespace {
/** @brief 一同期試験だけに借用する有限な列挙障害と直接出力観測です。 */
struct ServiceEnumFault {
	/// trueの一同期試験だけで指定診断を注入します。0診断の不整合応答も区別します。
	bool					   enabled{} ;
	/// 元障害診断です。enabled時のERROR_SUCCESSは不整合応答です。
	DWORD					   error{} ;
	/// 最初のServices節が返された次のindexです。
	UINT					   nextIndex{std::numeric_limits<UINT>::max()} ;
	/// 同Services節を返した生存中の実HINFです。
	HINF					   inf{INVALID_HANDLE_VALUE} ;
	/// private直接試験中だけ生存する出力vectorです。caller試験ではnullです。
	std::vector<std::wstring> *output{} ;
	/// 障害直前に既に追加済みの出力数です。
	std::size_t				   priorOutputs{} ;
	/// 指定障害を一回だけ観測した回数です。
	std::size_t				   injections{} ;
} ;

ServiceEnumFault		   serviceEnumFault ;	// 専用processの同期run以外には公開しません。

// 架空IDだけを含む、二つの同名copy/source/Win32 serviceを持つ固定INFです。
constexpr std::string_view SERVICE_INF =
	"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=SoftwareComponent\r\n"
	"ClassGuid={5c4c3332-344d-483c-8739-259e934c9cc8}\r\nProvider=\"Fixture Vendor\"\r\n"
	"DriverVer=10/11/2026,1.0.0.0\r\nCatalogFile=component.cat\r\n"
	"[Manufacturer]\r\nVendor=Models,NTamd64\r\n[Models.NTamd64]\r\n"
	"Device=Install,SWC\\SYNTH_SERVICE_CONTRACT\r\n"
	"[Install]\r\nCopyFiles=ServiceFiles\r\n"
	"[Install.Services]\r\nAddService=FixtureFirst,0,FirstService\r\n"
	"[FirstService]\r\nServiceType=0x10\r\nStartType=3\r\nErrorControl=1\r\n"
	"ServiceBinary=%13%\\first.exe\r\n[ServiceFiles]\r\nfirst.exe\r\n"
	"[Second]\r\nCopyFiles=SecondFiles\r\n"
	"[Second.Services]\r\nAddService=FixtureSecond,0,SecondService\r\n"
	"[SecondService]\r\nServiceType=0x20\r\nStartType=3\r\nErrorControl=1\r\n"
	"ServiceBinary=%13%\\second.exe\r\n[SecondFiles]\r\nsecond.exe\r\n"
	"[DestinationDirs]\r\nServiceFiles=13\r\nSecondFiles=13\r\n"
	"[SourceDisksNames]\r\n1=\"fixture\"\r\n[SourceDisksFiles]\r\n"
	"first.exe=1\r\nsecond.exe=1\r\n" ;

/**
 * @brief 所有workspaceへ固定fixture全byteを新規保存します。
 * @param[in,out] workspace 作成したfileをscope終了時に削除する所有者です。
 * @param[in] path 固定された安全な相対pathです。
 * @param[in] bytes 同期中だけ借用する有限fixtureです。
 * @return 全byte保存時true、作成または部分書込み失敗時falseです。
 */
bool writeServiceFixture( OfficialDownloadWorkspace &workspace, std::wstring_view path,
						 std::string_view bytes)
{
	HANDLE file{INVALID_HANDLE_VALUE} ;	// この関数だけが閉じる所有handleです。
	// file作成失敗やWin32長の上限を部分fixtureへ変換しません。
	if( bytes.size() > std::numeric_limits<DWORD>::max() || workspace.createFile( path, file) != 0) {
		return false ;
	}

	// 元HANDLEを同期scopeへ単独所有し、全returnと例外で閉じます。
	const std::unique_ptr<void, decltype( &CloseHandle)> ownedFile( file, &CloseHandle) ;
	DWORD												written{} ;	// 実APIが保存したbyte数です。
	// 一回の実書込みが全fixtureを保存したことだけを成功にします。
	const bool complete = WriteFile( file, bytes.data(), static_cast<DWORD>( bytes.size()), &written,
									nullptr) != FALSE &&
						  written == bytes.size() ;
	return complete ;
}

/**
 * @brief 固定番号の実private出力と元診断を記録します。
 * @param[in] id 新規条件番号です。
 * @param[in] error 実呼出しの戻り診断です。
 * @param[in] outputs 実private出力の件数です。
 */
void printServiceCase( const char *id, NativeError error, std::size_t outputs)
{
	std::cout << "SERVICE_CONTRACT " << id << " error=" << error << " outputs=" << outputs
			  << " prior=" << serviceEnumFault.priorOutputs
			  << " injections=" << serviceEnumFault.injections << '\n' ;
}
} // namespace

BOOL WINAPI serviceContractEnumInfSections( HINF inf, UINT index, PWSTR buffer, UINT capacity,
										   PUINT required)
{
	// 同生存HINFの最初のServices処理後にだけ元Win32障害を注入します。
	if( serviceEnumFault.enabled && inf == serviceEnumFault.inf &&
	   index == serviceEnumFault.nextIndex) {
		serviceEnumFault.priorOutputs =
			serviceEnumFault.output ? serviceEnumFault.output->size() : 0U ;
		++serviceEnumFault.injections ;
		SetLastError( serviceEnumFault.error) ;
		return FALSE ;
	}

	const BOOL result =
		::SetupEnumInfSectionsW( inf, index, buffer, capacity, required) ;	// 実列挙です。
	// 次の呼出しはこのsectionの解析・追加を終えた後だけに発生します。
	if( result && buffer && stringsEqual( buffer, L"Install.Services")) {
		serviceEnumFault.inf	   = inf ;
		serviceEnumFault.nextIndex = index + 1U ;
	}

	return result ;
}

/** @see tests/support/inf_dependency_native_test_api.h 宣言側の契約を正本とします。 */
void runOfficialServiceOutputContractTests( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// 架空fixtureだけを所有します。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"service-contract-test", 193U) == 0) ;
	DRIVERCRATE_EXPECT( context, writeServiceFixture( workspace, L"component.inf", SERVICE_INF)) ;
	DRIVERCRATE_EXPECT( context, writeServiceFixture( workspace, L"component.cat", "synthetic")) ;
	DRIVERCRATE_EXPECT( context, writeServiceFixture( workspace, L"first.exe", "synthetic-first")) ;
	DRIVERCRATE_EXPECT( context, writeServiceFixture( workspace, L"second.exe", "synthetic-second")) ;
	UINT			line{} ;	// 実INF構文失敗の原行番号です。
	// 同期試験終了まで所有し、閉じたhandleを再利用しない実INFです。
	const UniqueInf inf( SetupOpenInfFileW( workspace.path( L"component.inf").c_str(), nullptr,
										  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, &line)) ;
	DRIVERCRATE_EXPECT( context, inf.get() != INVALID_HANDLE_VALUE) ;
	// 無効handleを再利用せず、fixture失敗を上の分母へ残します。
	if( inf.get() == INVALID_HANDLE_VALUE) {
		return ;
	}

	std::vector<std::wstring> outputs{L"stale.exe"} ;	// 入口clearも確認する私有出力です。
	serviceEnumFault = {} ;
	// 各実呼出しの元診断です。
	NativeError error = collectRequiredServiceExecutables( inf.get(), L"SoftwareComponent", outputs) ;
	printServiceCase( "C92", error, outputs.size()) ;
	DRIVERCRATE_EXPECT( context, error == 0) ;
	DRIVERCRATE_EXPECT( context,
					   outputs == std::vector<std::wstring>( {L"first.exe", L"second.exe"})) ;
	// 同じ有効HINFの途中失敗を診断別に固定し、各出力emptyを直接観測します。
	for( const DWORD fault : {ERROR_READ_FAULT, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS}) {
		outputs					 = {L"stale.exe"} ;
		serviceEnumFault		 = {} ;
		serviceEnumFault.enabled = true ;
		serviceEnumFault.error	 = fault ;
		serviceEnumFault.output	 = &outputs ;
		error = collectRequiredServiceExecutables( inf.get(), L"SoftwareComponent", outputs) ;
		printServiceCase( fault == ERROR_READ_FAULT ? "C93"
												   : (fault == ERROR_SUCCESS ? "C98" : "C94"),
						 error, outputs.size()) ;
		DRIVERCRATE_EXPECT(
			context,
			error == nativeErrorFromWin32( fault == ERROR_SUCCESS ? ERROR_INVALID_DATA : fault)) ;
		DRIVERCRATE_EXPECT( context, outputs.empty()) ;
		DRIVERCRATE_EXPECT( context, serviceEnumFault.priorOutputs == 1U) ;
		DRIVERCRATE_EXPECT( context, serviceEnumFault.injections == 1U) ;
	}

	std::string invalid( SERVICE_INF) ;							// 第一serviceを維持し第二StartTypeだけを未対応にします。
	const auto	second = invalid.find( "[SecondService]") ;		// 固定第二宣言の開始です。
	const auto	start  = invalid.find( "StartType=3", second) ;	// 第二宣言だけの起動値です。
	DRIVERCRATE_EXPECT( context, start != std::string::npos) ;
	invalid.replace( start, std::string_view( "StartType=3").size(), "StartType=4") ;
	DRIVERCRATE_EXPECT( context, writeServiceFixture( workspace, L"invalid.inf", invalid)) ;
	// 第二宣言だけを変えた読取専用INFを同scopeで所有します。
	const UniqueInf invalidInf( SetupOpenInfFileW( workspace.path( L"invalid.inf").c_str(), nullptr,
												 INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, &line)) ;
	DRIVERCRATE_EXPECT( context, invalidInf.get() != INVALID_HANDLE_VALUE) ;
	// 無効な後続fixtureも閉じたhandleの再利用へ進めません。
	if( invalidInf.get() == INVALID_HANDLE_VALUE) {
		return ;
	}

	serviceEnumFault = {} ;
	outputs			 = {L"stale.exe"} ;
	error = collectRequiredServiceExecutables( invalidInf.get(), L"SoftwareComponent", outputs) ;
	printServiceCase( "C95", error, outputs.size()) ;
	DRIVERCRATE_EXPECT( context, error == nativeErrorFromWin32( ERROR_NOT_SUPPORTED)) ;
	DRIVERCRATE_EXPECT( context, outputs.empty()) ;
	const std::array<std::wstring_view, 1U> classes{L"SoftwareComponent"} ;	// 内容役割です。
	const std::array<std::wstring_view, 1U> signatures{L"$Windows NT$"} ;	// 元INF識別です。
	OfficialInfInspectionPolicy				policy{
		16U, 16U, classes, {}, signatures} ;	// 低位内容callerの固定policyです。
	policy.acceptAnyProvider			 = true ;
	policy.requireDriverBinary			 = false ;
	policy.rejectUnreferencedPrograms	 = false ;
	policy.allowRequiredDriverComponents = true ;
	const std::array entries{
		OfficialZipEntry{L"component.inf", SERVICE_INF.size()},
		OfficialZipEntry{L"component.cat", 9U}, OfficialZipEntry{L"first.exe", 15U},
		OfficialZipEntry{L"second.exe", 16U}} ;	// 同じ固定元byteの全inventoryです。
	OfficialInfPackage package ;				// 全成功時だけ公開される通常caller出力です。
	serviceEnumFault		 = {} ;
	serviceEnumFault.enabled = true ;
	serviceEnumFault.error	 = ERROR_READ_FAULT ;
	error = inspectOfficialInfPackage( workspace, entries, L"component.inf", policy, package) ;
	printServiceCase( "C96", error, package.sourceFiles.size()) ;
	DRIVERCRATE_EXPECT( context, error == nativeErrorFromWin32( ERROR_READ_FAULT)) ;
	DRIVERCRATE_EXPECT( context, package.infRelativePath.empty() && package.sourceFiles.empty()) ;
	DRIVERCRATE_EXPECT( context, serviceEnumFault.injections == 1U) ;
	serviceEnumFault		 = {} ;
	serviceEnumFault.enabled = true ;
	error = inspectOfficialInfPackage( workspace, entries, L"component.inf", policy, package) ;
	printServiceCase( "C99", error, package.sourceFiles.size()) ;
	DRIVERCRATE_EXPECT( context, error == nativeErrorFromWin32( ERROR_INVALID_DATA)) ;
	DRIVERCRATE_EXPECT( context, package.infRelativePath.empty() && package.sourceFiles.empty()) ;
	DRIVERCRATE_EXPECT( context, serviceEnumFault.injections == 1U) ;
	serviceEnumFault = {} ;
	error = inspectOfficialInfPackage( workspace, entries, L"component.inf", policy, package) ;
	printServiceCase( "C97", error, package.sourceFiles.size()) ;
	DRIVERCRATE_EXPECT( context, error == 0) ;
	DRIVERCRATE_EXPECT( context, package.sourceFiles ==
									std::vector<std::wstring>( {L"first.exe", L"second.exe"})) ;
	serviceEnumFault = {} ;
}
} // namespace drivercrate::test
