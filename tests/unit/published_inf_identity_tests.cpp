//------------------------------------------------------------------------------
/**
 * @file published_inf_identity_tests.cpp
 * @brief 架空INFの原Models節/ID種別/ClassGUIDの非許可receiptを確認します。
 * @version 01.00.00
 * @date 2026/10/14
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/14  原節/種別と欠測/元package不一致の限定試験を追加。
 * </pre>
 *
 * @note 架空INFだけを保護workspaceへ書きます。実device/署名成功/HTTP/導入を使用しません。
 * @see docs/adr/0338-local-acquisition-index-signing-and-import.md
 */
//------------------------------------------------------------------------------
#include "platform/official_driver_package.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include <array>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>
#include <windows.h>

namespace {

// 架空INFの有限集計です。
unsigned assertions{} ;
// 原不成立を除外しない集計です。
unsigned failures{} ;

/** @brief 一つの固定期待を集計します。
 * @param[in] value 全条件成立時だけtrueです。
 */
void	 expect( const bool value)
{
	++assertions ;
	// 失敗を後続成功で隠しません。
	if( !value) {
		++failures ;
		std::printf( "FAIL assertion=%u\n", assertions) ;
	}
}

/** @brief 小さな架空fileを同保護workspaceへ作ります。
 * @param[in,out] workspace 新規fileだけを追跡するownerです。
 * @param[in] name 架空の安全な相対basenameです。
 * @param[in] bytes 同期中だけ借用する有限原byteです。
 * @return 元createFileが追跡するfileの全write/flush/close成立時trueです。
 */
[[nodiscard]] bool writeFile( drivercrate::OfficialDownloadWorkspace &workspace,
							 const std::wstring_view name, const std::string_view bytes)
{
	HANDLE handle{} ;	// Workspaceが作る新規fileです。
	// 元作成codeの失敗から通常file直書きへ迂回しません。
	if( workspace.createFile( name, handle) != 0) {
		return false ;
	}

	DWORD	   written{} ;	// 小さな架空byteの実write数です。
	const bool saved = WriteFile( handle, bytes.data(), static_cast<DWORD>( bytes.size()), &written,
								 nullptr) != FALSE &&
					   written == bytes.size() &&
					   // 完全保存だけです。
					   FlushFileBuffers( handle) != FALSE ;
	const bool closed = CloseHandle( handle) != FALSE ;	// Short write時もhandleを閉じます。
	return saved && closed ;
}

/** @brief 現x64節/ID区分と元INF不一致/欠測の有限分母を確認します。 */
void run()
{
	using namespace drivercrate ;
	constexpr std::string_view INF =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=Net\r\n"
		"ClassGuid={4d36e972-e325-11ce-bfc1-08002be10318}\r\n"
		"Provider=Fictional Identity Publisher\r\nDriverVer=10/14/2026,1.2.3.4\r\nCatalogFile=sample.cat\r\n"
		"[Manufacturer]\r\nFictional=Models,NTx86,NTamd64\r\n"
		"[Models.NTx86]\r\nFictional=Install,PCI\\VEN_1234&DEV_9999\r\n"
		"[Models.NTamd64]\r\nFictional=Install,PCI\\VEN_1234&DEV_5678,PCI\\VEN_1234\r\n"
		"[SourceDisksNames.amd64]\r\n1=Fictional Disk,,,\r\n"
		"[SourceDisksFiles.amd64]\r\nsample.sys=1\r\n"
		"[Install.NT]\r\nCopyFiles=DriverCopy\r\n[DriverCopy]\r\nsample.sys\r\n" ;	// 全IDは架空です。
	OfficialDownloadWorkspace workspace ;											// 試験だけの新規保護領域です。
	expect( workspace.initialize( L"published-identity-test", 20401U) == 0) ;
	expect( writeFile( workspace, L"sample.inf", INF)) ;
	expect( writeFile( workspace, L"sample.cat", "unsigned artificial catalog")) ;
	expect( writeFile( workspace, L"sample.sys", "unsigned artificial driver")) ;
	const std::array	 entries{OfficialZipEntry{L"sample.inf", INF.size()},
							 OfficialZipEntry{L"sample.cat", 27U},
							 OfficialZipEntry{L"sample.sys", 26U}} ;	// 一INFの架空一覧です。
	constexpr std::array classes{std::wstring_view{L"Net"}} ;			// 元classだけです。
	constexpr std::array providers{
		std::wstring_view{L"Fictional Identity Publisher"}} ;				// 架空Providerだけです。
	constexpr std::array signatures{std::wstring_view{L"$Windows NT$"}} ;	// 標準INF文法だけです。
	const OfficialInfInspectionPolicy policy{16U, 16U, classes, providers,
											 signatures} ;	// 既存構造policyです。
	OfficialInfPackage				  package ;				// 構造成功は署名成功ではありません。
	expect( inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy, package) == 0) ;
	OfficialInfPublishedIdentity identity ;	// 非許可の原metadataです。
	expect( readOfficialInfPublishedIdentity( workspace, package, identity) == 0) ;
	expect( identity.models.size() == 1U) ;
	// 前段不成立では空vectorを参照しません。
	if( identity.models.size() == 1U) {
		expect( identity.models[0].modelSection == L"Models.NTamd64") ;
		expect( identity.models[0].hardwareIds ==
			   std::vector<std::wstring>{L"PCI\\VEN_1234&DEV_5678"}) ;
		expect( identity.models[0].compatibleIds == std::vector<std::wstring>{L"PCI\\VEN_1234"}) ;
	}

	expect( identity.classGuid == L"{4d36e972-e325-11ce-bfc1-08002be10318}") ;
	std::wstring expectedHash ;	// 元INFの共通hashです。
	expect( computeBytesSha256( INF, expectedHash) == 0 && identity.infSha256 == expectedHash) ;
	expect( verifyWindowsInfPackageIntegrity( workspace, package) !=
		   0) ;	// Metadata成功をCAT署名へ換算しません。
	// 別元packageという明示条件変更です。
	package.hardwareIds.push_back( L"PCI\\VEN_1234&DEV_0000") ;
	expect( readOfficialInfPublishedIdentity( workspace, package, identity) != 0) ;
	expect( identity.models.empty() && identity.infSha256.empty() && identity.classGuid.empty()) ;
	// 元ID欠測を明示します。
	package.hardwareIds.clear() ;
	expect( readOfficialInfPublishedIdentity( workspace, package, identity) != 0) ;
}

} // namespace

/** @brief 架空INFのread-only試験だけを実行します。
 * @return 全固定期待成立0、失敗1です。
 */
int main()
{
	try {
		run() ;
	} catch( ...) {
		expect( false) ;
	}

	std::printf(
		"PUBLISHED_INF_IDENTITY assertions=%u failures=%u actualDevices=0 signaturesPositive=0 install=0\n",
		assertions, failures) ;
	return failures == 0U ? 0 : 1 ;
}
