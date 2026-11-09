//------------------------------------------------------------------------------
/**
 * @file common_driver_content_tests.cpp
 * @brief 同INF付属内容の必要参照と未評価作用を局所検証します。
 * @version 01.02.00
 * @date 2026/11/05
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/05  CoInstaller・Type1の正負例と既存局所回帰を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/11/06  Windows管理driver scopeの実byte正負fixtureを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/11/08  元checkbox意図の表示保持とbinding拒否の固定診断を接続。
 * </pre>
 *
 * @note 共通実装を専用compileし、製品へ診断入口を追加しません。署名や導入成功を偽装しません。
 * @see docs/adr/0449-declared-catalog-hash-and-inf-attached-content.md
 */
//------------------------------------------------------------------------------

#include "platform/official_driver_package.cpp"
#include "official_driver_package_tests.cpp"

#include <crtdbg.h>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iterator>

namespace drivercrate::test {
namespace {
// 架空の一般deviceと同INFの元コピーだけを持つfixtureです。
constexpr std::string_view ATTACHED_INF =
	"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=Display\r\n"
	"ClassGUID={4d36e968-e325-11ce-bfc1-08002be10318}\r\nProvider=Fixture Vendor\r\n"
	"DriverVer=11/05/2026,2.0.0.0\r\nCatalogFile=sample.cat\r\n"
	"[Manufacturer]\r\nVendor=Models,NTamd64\r\n[Models.NTamd64]\r\n"
	"Device=Install,PCI\\SYNTH_ATTACHED_CONTENT\r\n"
	"[Install.NT]\r\nCopyFiles=DriverFiles,ProgramFiles\r\n"
	"[Install.NT.Services]\r\nAddService=FixtureKernel,2,KernelService\r\n"
	"[KernelService]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\nServiceBinary=%12%\\sample.sys\r\n"
	"[DestinationDirs]\r\nDriverFiles=12\r\nProgramFiles=13\r\nCoFiles=11\r\n"
	"[DriverFiles]\r\nsample.sys\r\n[ProgramFiles]\r\nhelper.exe\r\n"
	"[CoFiles]\r\nhelper.dll\r\n[SourceDisksNames]\r\n1=fixture,,,\r\n"
	"[SourceDisksFiles]\r\nsample.sys=1\r\nhelper.exe=1\r\nhelper.dll=1\r\n" ;

/**
 * @brief 一つの正負条件を元fixtureへ適用し、全内容と未評価flagを確認します。
 * @param[in,out] context 一processの有限集計先です。
 * @param[in] suffix 元deviceへ追加する原softwareまたはCoInstaller節です。
 * @param[in] before 元fixture内で置換する完全な文字列です。空なら置換しません。
 * @param[in] after 置換後の完全値です。
 * @param[in] contentOnly 非実行内容だけを許可する場合trueです。
 * @param[in] accepted 全構造検査が成功すべき場合trueです。
 * @param[in] unassessed 成功時の未評価program flagです。
 * @param[in] identity この条件だけの所有workspace番号です。
 */
void attachedCase( TestContext &context, std::string_view suffix, std::string_view before,
				  std::string_view after, bool contentOnly, bool accepted, bool unassessed,
				  std::uint64_t identity)
{
	OfficialDownloadWorkspace workspace ;	// 条件ごとの有限な原byte所有者です。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"attached-content-test", identity) == 0) ;
	std::string body( ATTACHED_INF) ;	// 別条件から変異を持ち越しません。
	body.append( suffix) ;
	// 正確な原文字列が存在する場合だけ一箇所を変更します。
	if( !before.empty()) {
		const auto position = body.find( before) ;	// 固定原fixtureの完全一致位置です。
		DRIVERCRATE_EXPECT( context, position != body.npos) ;
		// 前提欠損を別位置の編集へ補正しません。
		if( position != body.npos) {
			body.replace( position, before.size(), after) ;
		}
	}

	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.inf", body)) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.cat", "unsigned")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"sample.sys", "driver")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"helper.exe", "program")) ;
	DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, L"helper.dll", "library")) ;
	const std::array entries{
		OfficialZipEntry{L"sample.inf", body.size()}, OfficialZipEntry{L"sample.cat", 8U},
		OfficialZipEntry{L"sample.sys", 6U}, OfficialZipEntry{L"helper.exe", 7U},
		OfficialZipEntry{L"helper.dll", 7U}} ;	// 元全file集合です。
	constexpr std::array classes{std::wstring_view( L"Display"),
								 // 一般deviceと旧役割です。
								 std::wstring_view( L"SoftwareComponent")} ;
	constexpr std::array signatures{std::wstring_view( L"$Windows NT$")} ;	// 構文識別だけです。
	OfficialInfInspectionPolicy policy{
		32U, 32U, classes, {}, signatures} ;	// 各条件の共通policyです。
	policy.acceptAnyProvider					= true ;
	policy.requireDriverBinary					= false ;
	policy.rejectUnreferencedPrograms			= false ;
	policy.rejectInstallActions					= true ;
	policy.allowRequiredDriverComponents		= true ;
	policy.allowReferencedExecutablesForContent = contentOnly ;
	OfficialInfPackage package ;	// 全成功時だけ返る元内容です。
	const auto		   error = inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy,
														 package) ;	// 原構造診断です。
	context.expect( (error == 0) == accepted,
				   "attached fixture " + std::to_string( identity) + " error " +
					   std::to_string( error),
				   __FILE__, __LINE__) ;
	// 内容受理でも未署名CATを信頼したり、未評価programを導入可能へ変換しません。
	if( accepted && error == 0) {
		DRIVERCRATE_EXPECT( context, package.hasUnassessedProgramReferences == unassessed) ;
		DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, package) != 0) ;
	}
}

/**
 * @brief Windows-only scopeを元byteのcopy/service/softwareから検査します。
 * @param[in,out] context 一processの有限集計先です。
 * @param[in] before 元fixtureの置換対象です。空は正例です。
 * @param[in] after 元値を置換する負例です。
 * @param[in] accepted scopeが成立すべき場合trueです。
 * @param[in] identity 条件ごとの保護workspace番号です。
 * @param[in] contentRejected trueは既知autorunが全内容の既存guardで先に拒否される条件です。
 */
void windowsScopeCase( TestContext &context, std::string_view before, std::string_view after,
					  bool accepted, std::uint64_t identity, bool contentRejected = false)
{
	std::string body( ATTACHED_INF) ;	// 原一般deviceの同INF関係です。
	body.replace( body.find( "CopyFiles=DriverFiles,ProgramFiles"),
				 std::string_view( "CopyFiles=DriverFiles,ProgramFiles").size(),
				 "CopyFiles=DriverFiles,ProgramFiles,DataFiles") ;
	body.replace(
		body.find( "AddService=FixtureKernel,2,KernelService"),
		std::string_view( "AddService=FixtureKernel,2,KernelService").size(),
		"AddService=FixtureKernel,2,KernelService\r\nAddService=FixtureHelper,0,HelperService") ;
	body +=
		"[DestinationDirs]\r\nDataFiles=13\r\n[DataFiles]\r\nrecovery.bat\r\n"
		"[SourceDisksFiles]\r\nrecovery.bat=1\r\n"
		"[HelperService]\r\nServiceType=16\r\nStartType=2\r\nErrorControl=1\r\nServiceBinary=%13%\\helper.exe --data recovery.bat\r\n"
		"[Install.NT.Software]\r\nAddSoftware=RelatedDeviceProgram,0,RelatedSoftware\r\n"
		"[RelatedSoftware]\r\nSoftwareType=1\r\nSoftwareVersion=2.0.0.0\r\nSoftwareBinary=%13%\\helper.exe\r\n"
		"SoftwareArguments=--device <<DeviceInstanceID>>, --driver\r\n"
		"[PassiveReg]\r\nHKR,,Opaque,0x00010000" ;
	// 元NVIDIA同様の324 fieldsでも、opaque値の完全棚卸しをscopeの前提へ流用しません。
	for( unsigned field = 0U; field < 320U; ++field) {
		body += ",\"opaque\"" ;
	}

	body += "\r\n" ;
	// 原既知禁止位置を負例だけへ置き、無関係な正例の内容前提を汚染しません。
	if( contentRejected) {
		body +=
			"[AutorunReg]\r\nHKLM,\"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\",Fixture,0,\"foreign.exe\"\r\n"
			"[UserAutorunReg]\r\nHKCU,\"Software\\Microsoft\\Windows\\CurrentVersion\\rUn\",Fixture,0,\"foreign.exe\"\r\n" ;
	}

	// 一条件の原文字列だけを書換え、他条件へ持ち越しません。
	if( !before.empty()) {
		const auto position = body.find( before) ;	// 固定元値の一意位置です。
		DRIVERCRATE_EXPECT( context, position != body.npos) ;
		// 前提が欠けた条件を正例として進めません。
		if( position == body.npos) {
			return ;
		}

		body.replace( position, before.size(), after) ;
	}

	OfficialDownloadWorkspace workspace ;	// 同元byteだけの保護ownerです。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"windows-scope-fixture", identity) == 0) ;
	const std::array					   names{L"sample.inf", L"sample.cat", L"sample.sys",
							 L"helper.exe", L"helper.dll", L"recovery.bat"} ;	// 同元全参照です。
	const std::array<std::string_view, 6U> payloads{
		body,	   "unsigned", "driver",
		"program", "library",  "opaque recovery data"} ;	// 実行しないfixtureです。
	std::vector<OfficialZipEntry> entries ;					// 実size/hashを保持するがCATは未署名です。
	// 全fixture byteを独立sourceへ書き、実SHA256を取得します。
	for( std::size_t index = 0U; index < names.size(); ++index) {
		DRIVERCRATE_EXPECT( context, writeWorkspaceFile( workspace, names[index], payloads[index])) ;
		OfficialZipEntry entry{names[index], payloads[index].size()} ;	// 元実byteです。
		DRIVERCRATE_EXPECT( context,
						   computeFileSha256( workspace.path( names[index]), entry.sha256) == 0) ;
		entries.push_back( std::move( entry)) ;
	}

	constexpr std::array classes{std::wstring_view( L"Display")} ;			// 一般deviceの元Classです。
	constexpr std::array signatures{std::wstring_view( L"$Windows NT$")} ;	// 構文識別だけです。
	OfficialInfInspectionPolicy policy{32U, 32U, classes, {}, signatures} ;	// 全同元内容policyです。
	policy.acceptAnyProvider					   = true ;
	policy.rejectUnreferencedPrograms			   = false ;
	policy.rejectInstallActions					   = true ;
	policy.allowReferencedExecutablesForContent	   = true ;
	policy.allowRequiredDriverComponents		   = true ;
	policy.allowWindowsManagedDriverDataForContent = true ;
	OfficialInfPackage package ;	// 全内容構造の元metadataです。
	const auto		   parsed = inspectOfficialInfPackage( workspace, entries, L"sample.inf", policy,
														  package) ;	// 実元readerです。
	DRIVERCRATE_EXPECT( context,
					   parsed == (contentRejected ? nativeErrorFromWin32( ERROR_NOT_SUPPORTED) : 0)) ;
	// 内容構造の前提に失敗した条件をscope拒否成功へ数えません。
	if( parsed != 0) {
		return ;
	}

	OfficialInfPackage selected ;	// 同current Models/Windows節からの原関係です。
	DRIVERCRATE_EXPECT( context, inspectSelectedOfficialInfRelations( workspace, entries, package,
																	L"Install", selected) == 0) ;
	RequiredInfBindingDiagnostic diagnostic ;	// 選択scopeの最初の固定理由です。
	diagnostic.path	 = 2U ;
	const auto scope = inspectSelectedWindowsDriverPackageScope(
		workspace, entries, selected, &diagnostic) ;	// 内容と実行能力は別です。
	context.expect( (scope == 0) == accepted,
				   "Windows scope " + std::to_string( identity) + " error " + std::to_string( scope),
				   __FILE__, __LINE__) ;
	DRIVERCRATE_EXPECT( context, selected.hasUnassessedProgramReferences) ;
	DRIVERCRATE_EXPECT( context, diagnostic.path == 2U &&
									(accepted ? diagnostic.rejection == InfBindingReject::NONE
											  : diagnostic.rejection != InfBindingReject::NONE)) ;
	const auto first	= diagnostic.rejection ;	// 元の最初の拒否だけです。
	const auto observed = diagnostic.observed ;		// native観測値を再分類しません。
	const auto forwarded =
		diagnostic.reject( nativeErrorFromWin32( ERROR_NOT_SUPPORTED), InfBindingReject::DEPENDENCY,
						  999U) ;	// guardと原codeは不変です。
	DRIVERCRATE_EXPECT( context, forwarded == nativeErrorFromWin32( ERROR_NOT_SUPPORTED) &&
									(accepted || (diagnostic.rejection == first &&
												  diagnostic.observed == observed))) ;
	DRIVERCRATE_EXPECT( context, verifyWindowsInfPackageIntegrity( workspace, selected) != 0) ;
	selected.activeRequiredInfPaths.push_back( L"foreign.inf") ;
	DRIVERCRATE_EXPECT( context,
					   inspectSelectedWindowsDriverPackageScope( workspace, entries, selected) != 0) ;
}

/** @brief 受動コピーと既知外部操作を異なる原条件で局所検証します。
 * @param[in,out] context このprocessの有限集計先です。
 */
void windowsScopeMatrix( TestContext &context)
{
	windowsScopeCase( context, {}, {}, true, 71201U) ;
	windowsScopeCase( context, "DataFiles=13", "DataFiles=16422", false, 71202U) ;
	windowsScopeCase( context, "ServiceBinary=%13%\\helper.exe --data recovery.bat",
					 "ServiceBinary=%11%\\cmd.exe /c recovery.bat", false, 71203U) ;
	windowsScopeCase( context, "SoftwareType=1",
					 "SoftwareType=2\r\nSoftwareID=pfn://Fixture.DriverSupport_abcdefghjkmnp",
					 false, 71204U) ;
	windowsScopeCase( context, "SoftwareArguments=--device <<DeviceInstanceID>>",
					 "SoftwareArguments=--standalone-app", false, 71205U) ;
	windowsScopeCase( context, "[ProgramFiles]\r\nhelper.exe",
					 "[ProgramFiles]\r\nhelper.exe\r\nrenamed.dll,helper.dll", true, 71206U) ;
	windowsScopeCase( context, "CopyFiles=DriverFiles,ProgramFiles,DataFiles",
					 "CopyFiles=DriverFiles,ProgramFiles,DataFiles\r\nAddReg=AutorunReg", false,
					 71207U, true) ;
	windowsScopeCase( context, "[HelperService]\r\nServiceType=16",
					 "[HelperService]\r\nAddReg=AutorunReg\r\nServiceType=16", false, 71208U, true) ;
	windowsScopeCase( context, "[RelatedSoftware]\r\nSoftwareType=1",
					 "[RelatedSoftware]\r\nAddReg=AutorunReg\r\nSoftwareType=1", false, 71209U,
					 true) ;
	windowsScopeCase( context, "CopyFiles=DriverFiles,ProgramFiles,DataFiles",
					 "CopyFiles=DriverFiles,ProgramFiles,DataFiles\r\nAddReg=PassiveReg", true,
					 71210U) ;
	windowsScopeCase( context, "CopyFiles=DriverFiles,ProgramFiles,DataFiles",
					 "CopyFiles=DriverFiles,ProgramFiles,DataFiles\r\nAddReg=UserAutorunReg", false,
					 71211U, true) ;
	windowsScopeCase(
		context, "CopyFiles=DriverFiles,ProgramFiles,DataFiles",
		"CopyFiles=DriverFiles,ProgramFiles,DataFiles\r\nAddReg=PassiveReg\r\nAddReg=AutorunReg",
		false, 71212U, true) ;
}

/**
 * @brief 原software参照と限定CoInstallerの正負例を確認します。
 * @param[in,out] context 一processの有限集計先です。
 */
void attachedMatrix( TestContext &context)
{
	constexpr std::string_view SOFTWARE =
		"[Install.NT.Software]\r\nAddSoftware=FixtureProgram,0,Software\r\n"
		"[Software]\r\nSoftwareType=1\r\nSoftwareBinary=%13%\\helper.exe\r\nSoftwareVersion=2.0.0.0\r\n"
		"[UnreferencedStore]\r\nSoftwareType=2\r\nSoftwareID=pfn://fixture_unused\r\n" ;	// 未参照Type2は必要appへ変換しません。
	constexpr std::string_view COINSTALLER =
		"[Install.NT.CoInstallers]\r\nAddReg=Registration\r\nCopyFiles=CoFiles\r\n"
		// 元DLL/entrypointのdevice-local登録です。
		"[Registration]\r\nHKR,,CoInstallers32,0x00010000,\"helper.dll,FixtureEntry\"\r\n" ;
	std::uint64_t			   identity = 71000U ;	// 条件間で単独所有を区別します。
	constexpr std::string_view TYPE2 =
		"[Install.NT.Software]\r\nAddSoftware=FixtureStore,0,Store\r\n"
		// 架空PFNだけの元Store metadataです。
		"[Store]\r\nSoftwareType=2\r\nSoftwareID=pfn://Fixture.DriverSupport_abcdefghjkmnp\r\n" ;
	attachedCase( context, TYPE2, {}, {}, true, true, true, identity++) ;
	attachedCase( context, TYPE2, {}, {}, false, false, false, identity++) ;
	attachedCase( context, TYPE2, "pfn://Fixture.DriverSupport_abcdefghjkmnp",
				 "https://invalid.example/app", true, false, false, identity++) ;
	attachedCase( context, TYPE2, "pfn://Fixture.DriverSupport_abcdefghjkmnp", "pfn://invalid", true,
				 false, false, identity++) ;
	std::string metadataOnly( ATTACHED_INF) ;	// program参照がない場合も作用flagを保持します。
	metadataOnly.replace( metadataOnly.find( "CopyFiles=DriverFiles,ProgramFiles"),
						 std::string_view( "CopyFiles=DriverFiles,ProgramFiles").size(),
						 "CopyFiles=DriverFiles") ;
	metadataOnly.erase( metadataOnly.find( "helper.exe=1\r\n"),
					   std::string_view( "helper.exe=1\r\n").size()) ;
	attachedCase( context, TYPE2, ATTACHED_INF, metadataOnly, true, true, true, identity++) ;
	std::string duplicate( SOFTWARE) ;	// 同じ節の二番目AddSoftwareも検査します。
	duplicate.replace( duplicate.find( "[Software]"), 0U,
					  "[Install.NT.Software]\r\nAddSoftware=FixtureStore,0,Store\r\n") ;
	duplicate +=
		"[Store]\r\nSoftwareType=2\r\nSoftwareID=pfn://Fixture.DriverSupport_abcdefghjkmnp\r\n" ;
	attachedCase( context, duplicate,
				 "Class=Display\r\nClassGUID={4d36e968-e325-11ce-bfc1-08002be10318}",
				 "Class=SoftwareComponent\r\nClassGUID={5c4c3332-344d-483c-8739-259e934c9cc8}",
				 true, true, true, identity++) ;
	attachedCase( context, duplicate, "pfn://Fixture.DriverSupport_abcdefghjkmnp", "pfn://invalid",
				 true, false, false, identity++) ;
	attachedCase( context, SOFTWARE, {}, {}, true, true, true, identity++) ;
	attachedCase( context, SOFTWARE, {}, {}, false, false, false, identity++) ;
	attachedCase( context, SOFTWARE, "ProgramFiles=13", "ProgramFiles=11", true, false, false,
				 identity++) ;
	attachedCase( context, SOFTWARE, "SoftwareType=1", "SoftwareType=2", true, false, false,
				 identity++) ;
	attachedCase( context, SOFTWARE, "SoftwareBinary=%13%\\helper.exe",
				 "SoftwareBinary=%13%\\other.exe", true, false, false, identity++) ;
	attachedCase( context, SOFTWARE, "Install.NT.Software", "Orphan.Software", true, false, false,
				 identity++) ;
	// 標準値・不透明な別名・正式な等価system directoryを区別して確認します。
	attachedCase( context, COINSTALLER, {}, {}, true, true, true, identity++) ;
	attachedCase( context, COINSTALLER, "CoInstallers32", "CoInstallers64", true, true, true,
				 identity++) ;
	attachedCase( context, COINSTALLER, "CoFiles=11", "CoFiles=10,system32", true, true, true,
				 identity++) ;
	attachedCase( context, COINSTALLER, "HKR,,CoInstallers32", "HKLM,,CoInstallers32", true, false,
				 false, identity++) ;
	attachedCase( context, COINSTALLER, "HKR,,CoInstallers32",
				 "HKR,Software\\CurrentVersion\\Run,CoInstallers32", true, false, false,
				 identity++) ;
	attachedCase( context, COINSTALLER, "CoFiles=11", "CoFiles=12", true, false, false, identity++) ;
	attachedCase( context, COINSTALLER, "CoFiles=11", "CoFiles=10,other", true, false, false,
				 identity++) ;
	attachedCase( context, COINSTALLER, "helper.dll,FixtureEntry", "helper.dll,cmd /c execute", true,
				 false, false, identity++) ;
	attachedCase( context, COINSTALLER, "helper.dll,FixtureEntry", "..\\helper.dll,FixtureEntry",
				 true, false, false, identity++) ;
	attachedCase( context, COINSTALLER, "[CoFiles]\r\nhelper.dll",
				 "[CoFiles]\r\nhelper.dll,other.dll", true, false, false, identity++) ;
	attachedCase( context, COINSTALLER, "Install.NT.CoInstallers", "Orphan.CoInstallers", true,
				 false, false, identity++) ;
	attachedCase( context, COINSTALLER, "0x00010000,\"helper.dll", "0,\"helper.dll", true, false,
				 false, identity++) ;
}
} // namespace
} // namespace drivercrate::test

/**
 * @brief 非対話の局所回帰または明示INFの最初の構造診断を実行します。
 * @param[in] count 実行fileを含む引数数です。
 * @param[in] arguments --diagnose-infと私有原INF、または引数なしです。
 * @return 全試験成功0、不正入力2、fixtureまたは診断段階の失敗1です。
 * @note CRT/OSの非対話設定を入力やassertionより前に適用します。
 */
int wmain( const int count, wchar_t *arguments[])
{
	SetErrorMode( SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX) ;
	_set_abort_behavior( 0U, _WRITE_ABORT_MSG | _CALL_REPORTFAULT) ;
#if defined( _DEBUG)
	_CrtSetReportMode( _CRT_ASSERT, _CRTDBG_MODE_FILE) ;
	_CrtSetReportFile( _CRT_ASSERT, _CRTDBG_FILE_STDERR) ;
#endif
	try {
		// 明示元INFだけの構造を診断し、virtual source一覧に内容/CAT合格を発行しません。
		if( (count == 3 && std::wstring_view( arguments[1]) == L"--diagnose-structure") ||
		   (count == 4 && std::wstring_view( arguments[1]) == L"--diagnose-scope")) {
			std::ifstream						   input( std::filesystem::path( arguments[2]),
														 std::ios::binary) ;	// 原小INFだけです。
			const std::string					   bytes( std::istreambuf_iterator<char>{input},
														 {}) ;	// 元byteを変更しません。
			drivercrate::OfficialDownloadWorkspace workspace ;	// 診断専用の原INF保護領域です。
			// 原読取失敗や上限超過を空構造の成功へ変換しません。
			if( !input || bytes.empty() || bytes.size() > 4U * 1024U * 1024U ||
			   workspace.initialize( L"structure-only-test", 712U) != 0 ||
			   !drivercrate::test::writeWorkspaceFile( workspace, L"sample.inf", bytes)) {
				return 1 ;
			}

			const drivercrate::UniqueInf inf( SetupOpenInfFileW(
				workspace.path( L"sample.inf").c_str(), nullptr,
				INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr)) ;	// 元Windows readerだけです。
			std::wstring				 catalog ;						// 原CAT file宣言です。
			std::vector<std::wstring>	 sources ;						// 原全SDF位置です。実byte確認ではありません。
			// 不正構造をvirtual一覧の都合へ合わせません。
			if( inf.get() == INVALID_HANDLE_VALUE ||
			   drivercrate::readCatalogFile( inf.get(), catalog) != 0 ||
			   drivercrate::readOfficialInfSourcePaths( workspace, L"sample.inf", 8192U, sources) !=
				   0) {
				return 1 ;
			}

			std::vector<drivercrate::OfficialZipEntry> entries{
				{L"sample.inf", bytes.size()}, {catalog, 1U}} ;	// 存在宣言だけの非権限一覧です。
			// 原全source名を保持し、構造以外の成功を表しません。
			for( const auto &source : sources) {
				entries.push_back( {source, 1U}) ;
			}

			constexpr std::array classes{
				std::wstring_view( L"Display"), std::wstring_view( L"MEDIA"),
				std::wstring_view(
					// 今回の元三Classを比較する診断値です。製品allowlistではありません。
					L"USB")} ;
			constexpr std::array signatures{std::wstring_view( L"$Windows NT$")} ;	// 構文だけです。
			drivercrate::OfficialInfInspectionPolicy policy{
				4096U, 8192U, classes, {}, signatures} ;	// 元内容modeと同じ構造条件です。
			policy.acceptAnyProvider					   = true ;
			policy.requireDriverBinary					   = false ;
			policy.rejectUnreferencedPrograms			   = false ;
			policy.rejectInstallActions					   = true ;
			policy.allowReferencedExecutablesForContent	   = true ;
			policy.allowRequiredDriverComponents		   = true ;
			policy.allowWindowsManagedDriverDataForContent = true ;
			drivercrate::OfficialInfPackage package ;	// 内容合格へ転用しない元構造です。
			const auto						error = drivercrate::inspectOfficialInfPackage(
				 workspace, entries, L"sample.inf", policy, package) ;	// 元構造診断だけです。
			std::cout << "structureError=" << error << " sourceDeclarations=" << sources.size()
					  << " fullContentProof=0\n" ;
			// 原selected棚卸しAPIの失敗だけを内容/CATと独立して診断します。
			if( count == 4) {
				static_cast<void>( drivercrate::computeFileSha256( workspace.path( L"sample.inf"),
																 entries.front().sha256)) ;
				drivercrate::OfficialInfInstallInventory
						   inventory ;	// 導入許可を持たない原棚卸しです。
				const auto inventoryError = drivercrate::inspectOfficialInfInstallInventory(
					workspace, entries, L"sample.inf", arguments[3],
					inventory) ;	// 元API返値を保持します。
				std::cout << "selectedInventoryError=" << inventoryError << " fullContentProof=0\n" ;
				std::size_t maximumFields{} ;	// 元一行の最大field数だけを観測します。
				// 本文や値を出さず、原全節の最大構文容量だけを読みます。
				for( UINT ordinal = 0U; ordinal < 4096U; ++ordinal) {
					std::array<wchar_t, 256U> section{} ;	// 原節名の有限読取領域です。
					// 元Windows列挙の終端で終了します。
					if( !SetupEnumInfSectionsW( inf.get(), ordinal, section.data(),
											  static_cast<UINT>( section.size()), nullptr)) {
						break ;
					}

					INFCONTEXT row{} ;	// 元行を読取り専用で走査します。
					// 明示空節をfield不足へ変換しません。
					if( SetupFindFirstLineW( inf.get(), section.data(), nullptr, &row)) {
						// 原全行のfield数だけを集計します。
						do {
							maximumFields = (std::max)(
								maximumFields, static_cast<std::size_t>( SetupGetFieldCount( &row))) ;
						} while( SetupFindNextLine( &row, &row)) ;
					}
				}

				std::cout << "maximumRawFields=" << maximumFields << " executed=0\n" ;
				drivercrate::OfficialInfPackage selected ;	// 元選択の非権限構造だけです。
				const auto relationError = drivercrate::inspectSelectedOfficialInfRelations(
					workspace, entries, package, arguments[3], selected) ;	// 実元読取です。
				const auto scopeError =
					relationError != 0
						? relationError
						: drivercrate::inspectSelectedWindowsDriverPackageScope(
							  workspace, entries, selected) ;	// 全内容証拠ではありません。
				std::cout << "selectedScopeError=" << scopeError << " fullContentProof=0\n" ;
				drivercrate::OfficialInfInstallInventory
						   formal ;	// 全registryを辿らない元正式関係です。
				const auto formalError = drivercrate::readWindowsDriverScopeReferences(
					// 原関係診断です。
					inf.get(), selected, formal) ;
				std::cout << "formalReferencesError=" << formalError
						  << " copies=" << formal.references.size() << '\n' ;
				std::vector<drivercrate::WindowsDriverCopy> copies ;	// 同元位置の静的結合だけです。
				// 先頭の不成立copyの正式list/nameを示し、内容成功へ変換しません。
				for( const auto &reference : formal.references) {
					// 直接fileは本実測の対象外として後段の元診断へ残します。
					if( reference.kind !=
					   drivercrate::OfficialInfInstallReferenceKind::LOCAL_SECTION) {
						continue ;
					}

					const auto lines =
						// 元copy行数です。
						SetupGetLineCountW( inf.get(), reference.target.c_str()) ;
					// 全元行の同位置結合を原順で検査します。
					for( LONG index = 0L; index < lines; ++index) {
						INFCONTEXT	 line{} ;	// 同元行のcursorです。
						std::wstring target ;	// 元target leafです。
						std::wstring source ;	// 元rename sourceです。
						// 診断でも読取失敗を空fieldへ補完しません。
						if( !SetupGetLineByIndexW( inf.get(), reference.target.c_str(),
												 static_cast<DWORD>( index), &line) ||
						   drivercrate::readInfField( line, 1U, target) != 0 ||
						   (SetupGetFieldCount( &line) > 1U &&
							drivercrate::readInstallInventoryField( line, 2U, source) != 0)) {
							return 1 ;
						}

						const auto copyError = drivercrate::bindWindowsDriverCopy(
							inf.get(), workspace, entries, selected, reference.target, target,
							// 元静的関係だけです。
							source.empty() ? target : source, copies) ;
						// 最初の不成立で停止し、値本文を出しません。
						if( copyError != 0) {
							std::wcout << L"firstCopyList=" << reference.target << L" file="
									   << target << L" error=" << copyError << L'\n' ;
							return 1 ;
						}
					}
				}

				std::cout << "formalCopyBindings=" << copies.size() << " fullContentProof=0\n" ;
				return inventoryError == 0 ? 0 : 1 ;
			}

			return error == 0 ? 0 : 1 ;
		}

		// 明示された原INFの先頭段階だけを読み、payloadを実行しません。
		if( count == 3 && std::wstring_view( arguments[1]) == L"--diagnose-inf") {
			const drivercrate::UniqueInf inf(
				SetupOpenInfFileW( arguments[2], nullptr, INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
								  nullptr)) ;	// 同期中だけ所有する原INFです。
			// 原INFを開けない条件を別段階の成功へ変換しません。
			if( inf.get() == INVALID_HANDLE_VALUE) {
				std::cout << "open=" << GetLastError() << '\n' ;
				return 1 ;
			}

			bool	   dependencies{} ;	// 存在だけの観測です。
			const auto actions = drivercrate::validateInfInstallActions(
				// 内容modeの原診断です。
				inf.get(), false, dependencies, true, true) ;
			std::wstring className ;	// 原VersionのClassだけです。
			const auto	 classError = drivercrate::readInfDirective(
				  // 原取得診断です。
				  inf.get(), L"Version", L"Class", 1U, className) ;
			std::vector<std::wstring> executables ;	// 既知の必要参照だけです。
			const auto services = classError == 0 ? drivercrate::collectRequiredServiceExecutables(
														inf.get(), className, executables, true)
												  : classError ;	// 内容modeです。
			const auto copies =
				services == 0
					? drivercrate::collectRequiredCopyExecutables( inf.get(), className, executables)
					: services ;	// 原コピー診断です。
			std::cout << "actions=" << actions << " services=" << services << " copies=" << copies
					  << " knownExecutables=" << executables.size() << '\n' ;
			std::wstring catalog ;	// 元CAT指定の取得だけです。
			const auto	 catalogError =
				// 原CAT directive診断です。
				drivercrate::readCatalogFile( inf.get(), catalog) ;
			std::vector<std::wstring> ids ;	// 原Modelsだけから取得する診断用集合です。
			const auto				  modelsError = drivercrate::collectHardwareIds(
				   // 既存native選択の診断です。
				   inf.get(), 4096U, ids) ;
			std::cout << "catalogDeclaration=" << catalogError << " models=" << modelsError
					  << " modelIds=" << ids.size() << '\n' ;
			INFCONTEXT sourceRow{} ;	// 元amd64優先SourceDisksFilesの先頭です。
			// 存在する元sourceだけのfield/形式診断とし、全closure合格の代用にしません。
			if( SetupFindFirstLineW( inf.get(), L"SourceDisksFiles.amd64", nullptr, &sourceRow) ||
			   SetupFindFirstLineW( inf.get(), L"SourceDisksFiles", nullptr, &sourceRow)) {
				std::size_t sources{} ;	// 診断の有限行予算です。
				// 原位置readerと内容modeの拡張子境界を各sourceへ適用します。
				do {
					std::wstring file ;			// 原SDF keyの公開配布file名だけです。
					std::wstring directory ;	// 元source subdirです。
					std::wstring media ;		// 元媒体相対位置です。
					const auto	 keyError =
						// 原key診断です。
						drivercrate::readInfField( sourceRow, 0U, file) ;
					const auto sourceError = keyError == 0 ? drivercrate::readInfSourceDirectories(
																 inf.get(), file, directory, media)
														   : keyError ;	// 原位置診断です。
					const auto extension =
						// 同原fileの形式だけです。
						drivercrate::lowerExtension( file) ;
					const bool passive = extension == L".bin" || extension == L".dfu" ||
										 extension == L".mbn" ||
										 // 既存driver data形式です。
										 extension == L".elf" ;
					const bool program = extension == L".exe" || extension == L".msi" ||
										 // 内容modeの原参照です。
										 extension == L".cab" ;
					const bool rejected =
						!passive && !program &&
						std::ranges::find( drivercrate::REJECTED_REFERENCED_EXTENSIONS, extension) !=
							// 既存拒否集合です。
							drivercrate::REJECTED_REFERENCED_EXTENSIONS.end() ;
					// 最初の元診断または未知形式だけを示して停止します。
					if( ++sources > 8192U || sourceError != 0 || rejected) {
						std::wcout << L"firstSourceOrdinal=" << sources << L" sourceError="
								   << sourceError << L" extensionRejected=" << rejected
								   << L" extension=" << extension << L'\n' ;
						break ;
					}
				} while( SetupFindNextLine( &sourceRow, &sourceRow)) ;
				std::cout << "sourceDeclarationsObserved=" << sources << " closureProof=0\n" ;
			}

			// 元software失敗をClass限定と別の実コピー制約へ分離します。
			if( actions != 0) {
				// 全節の最初の不成立AddSoftwareだけを私有診断へ出します。
				for( UINT index = 0U; index < 4096U; ++index) {
					std::array<wchar_t, 257U> section{} ;	// 有限の原section名です。
					// 元列挙の終端で診断走査も終えます。
					if( !SetupEnumInfSectionsW( inf.get(), index, section.data(),
											  static_cast<UINT>( section.size()), nullptr)) {
						break ;
					}

					INFCONTEXT software{} ;	// 同元AddSoftwareです。
					// software参照がない節から別の作用を推測しません。
					if( !SetupFindFirstLineW( inf.get(), section.data(), L"AddSoftware", &software)) {
						continue ;
					}

					const auto error = drivercrate::validateRequiredSoftwareDeclaration(
						// 元必要参照の診断です。
						inf.get(), section.data(), software, true) ;
					// 最初の失敗に対応するDDInstallとコピーを直接確認します。
					if( error != 0) {
						std::wstring	   declaration ;	// 同元software-install節です。
						std::wstring	   binary ;			// 元binary全値です。
						const std::wstring install =
							std::wstring( section.data())
								.substr( 0U, std::wstring_view( section.data()).size() -
												9U) ;	// 元Software suffixを外します。
						const auto named = drivercrate::readInfField(
							software, 3U, declaration) ;	// 原参照診断です。
						const auto binaryError =
							named == 0 ? drivercrate::readRequiredServiceField(
											 inf.get(), declaration, L"SoftwareBinary", binary)
									   : named ;	// 原binary診断です。
						const auto file =
							binary.substr( binary.find_last_of( L'\\') == binary.npos
											  ? 0U
											  : binary.find_last_of( L'\\') + 1U) ;	// 同元leafです。
						std::wstring source ;										// 私有診断だけの位置です。
						const auto	 relaxedCopy =
							  binaryError == 0 ? drivercrate::inspectRequiredServiceCopy(
													 inf.get(), install, file, L"", source)
											   : binaryError ;	// 実行を伴わない位置検査だけです。
						std::wstring directory ;				// 同元source subdirです。
						std::wstring media ;					// 同元source媒体です。
						const auto	 sourceError = drivercrate::readRequiredServiceSourceDirectory(
							  // 元SDF診断です。
							  inf.get(), file, directory, media) ;
						std::wcout << L"firstSoftwareSection=" << section.data() << L" error="
								   << error << L" modelsLinked="
								   << drivercrate::hasModelsInstallReference( inf.get(), install)
								   << L" copiedSourceOnlyError=" << relaxedCopy << L" sourceError="
								   << sourceError << L'\n' ;
						break ;
					}
				}
			}

			return actions == 0 && services == 0 && copies == 0 ? 0 : 1 ;
		}

		// 不正CLIを試験成功へ読み替えません。
		if( count != 1) {
			return 2 ;
		}

		drivercrate::test::TestContext context ;	// 実行した局所assertionだけの集計です。
		drivercrate::test::testEmptyCoInstallerReferences( context) ;
		drivercrate::test::testStandardComponentActions( context) ;
		drivercrate::test::attachedMatrix( context) ;
		drivercrate::test::windowsScopeMatrix( context) ;
		std::cout << "Assertions: " << context.assertionCount()
				  << ", failures: " << context.failureCount() << '\n' ;
		return context.failureCount() == 0 ? 0 : 1 ;
	} catch( const std::bad_alloc &) {
		std::cerr << "INF fixture allocation failed.\n" ;
		return 1 ;
	} catch( const std::exception &) {
		std::cerr << "INF fixture exception.\n" ;
		return 1 ;
	} catch( ...) {
		std::cerr << "INF fixture unknown exception.\n" ;
		return 1 ;
	}
}
