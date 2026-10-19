//------------------------------------------------------------------------------
/**
 * @file prolific_official_provider_tests.cpp
 * @brief 公式serial取得・候補境界の内部試験。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  CP210x公式取得とserial共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  許可IDの候補監査と回帰確認。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 通信と実driver導入を行わず、候補IDの境界を検証します。未審査IDの許可や既存の監査条件の迂回は行いません。
 */
//------------------------------------------------------------------------------

#include "prolific_official_provider_tests.h"

#include "core/candidate_audit.h"
#include "core/provider_registry.h"
#include "core/update_types.h"
#include "platform/official_serial_provider.h"
#include "platform/prolific_serial_package.h"
#include "platform/silicon_labs_serial_package.h"
#include "test_framework.h"

#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {
//------------------------------------------------------------------------------
/**
 * @brief 架空の公式配布行を作る。
 *
 * 実通信やpayloadを使用しないparser fixtureを作る。
 *
 * @param[in] link 正常／拒否例のhref属性値。
 * @return 配布行を一つ含む架空HTML。
 */
//------------------------------------------------------------------------------
std::wstring page( const std::wstring_view link)
{
	return L"<table><tr><td><a href=\"" + std::wstring( link) +
		   L"\">download</a></td><td>Windows DCHU+DFx+Modem Standy Driver INF Setup "
		   L"( Win10 / Win11)</td></tr></table>" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式配布行の一意性とURL境界を検証する。
 *
 * 正常新版と第三者host、別package、HTML曖昧性を区別する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testParser( TestContext &context)
{
	constexpr std::wstring_view PATH =
		L"/wp-content/uploads/2026/09/PL2303G_DCHU_DFx_v2.zip" ;	// 架空の新版ZIP path。
	const std::wstring valid = page( PATH) ;						// 実通信しない正常fixture。
	std::wstring	   url ;										// Parserが成功時だけ設定する内部URL。
	DRIVERCRATE_EXPECT( context, parseProlificOfficialZipUrl( valid, url)) ;
	DRIVERCRATE_EXPECT( context, url == L"https://www.prolific.com.tw" + std::wstring( PATH)) ;
	constexpr std::array REJECTED{
		L"https://example.invalid/PL2303G_DCHU.zip",
		L"//www.prolific.com.tw/wp-content/uploads/2026/09/PL2303G_DCHU.zip",
		L"/wp-content/uploads/2026/09/PL2303_Installer.exe",
		L"/wp-content/uploads/2026/09/PL2303G_DCHU.zip?redirect=x",
		L"/wp-content/uploads/2026/09/PL2303G_DCHU%2fother.zip",
		L"/wp-content/uploads/2026/09/PL2303G_DCHU../other.zip",
		L"/wp-content/uploads/2026/09/PL2303G_DCHU..zip",
		L"/wp-content/uploads/2026/09/PL2303G_DCHU.zip.exe",
		L"/wp-content/uploads/abcd/09/PL2303G_DCHU.zip",
		L"/wp-content/uploads/2026/09/PL2303G_DCHU.zip&extra"} ;	// 明示的に許可しない配布形式。
	// 全拒否例で前回の正常URLを残さないことも確認する。
	for( const wchar_t *const rejected : REJECTED) {
		url = L"previous" ;
		DRIVERCRATE_EXPECT( context, !parseProlificOfficialZipUrl( page( rejected), url)) ;
		DRIVERCRATE_EXPECT( context, url.empty()) ;
	}

	DRIVERCRATE_EXPECT( context, !parseProlificOfficialZipUrl( valid + valid, url)) ;
	DRIVERCRATE_EXPECT( context, !parseProlificOfficialZipUrl( L"<html>challenge</html>", url)) ;
	DRIVERCRATE_EXPECT(
		context,
		!parseProlificOfficialZipUrl(
			L"<tr><a href=\"" + std::wstring( PATH) +
				L"\">x</a></tr>"
				L"<tr>Windows DCHU+DFx+Modem Standy Driver INF Setup ( Win10 / Win11)</tr>",
			url)) ;
	std::wstring multipleLinks = valid ;	// 同じ行に複数のdownload anchorがある拒否fixture。
	multipleLinks.insert( multipleLinks.find( L"</td>"), L"<a href=\"/other.zip\">x</a>") ;
	DRIVERCRATE_EXPECT( context, !parseProlificOfficialZipUrl( multipleLinks, url)) ;
	std::wstring withNul = valid ;	// 中途終端を隠した拒否fixture。
	withNul.insert( 4U, 1U, L'\0') ;
	DRIVERCRATE_EXPECT( context, !parseProlificOfficialZipUrl( withNul, url)) ;
	DRIVERCRATE_EXPECT(
		context, !parseProlificOfficialZipUrl( std::wstring( 2U * 1024U * 1024U + 1U, L'x'), url)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一回限りの同意と不正session拒否を検証する。
 *
 * 通信前guard、Provider状態、未知install IDを副作用なしで試験する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testConsent( TestContext &context)
{
	ScanOptions options{
		.useDefaultProviders = false,
		.enabledProviderIds	 = {std::wstring( PROLIFIC_OFFICIAL_PROVIDER_ID)}} ;	// 対象選択。
	// 対象Providerだけを選んでもpayload取得同意にはならない。
	DRIVERCRATE_EXPECT( context, !validateScanOptions( options)) ;
	options.prolificInspectionApproved = true ;
	DRIVERCRATE_EXPECT( context, validateScanOptions( options)) ;
	options.enabledProviderIds.push_back( std::wstring( PROLIFIC_OFFICIAL_PROVIDER_ID)) ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( options)) ;
	options.enabledProviderIds.clear() ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( options)) ;
	options.useDefaultProviders = true ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( options)) ;

	OfficialSerialProvider provider{
		OfficialSerialFamily::PROLIFIC} ;									// Source sessionがない未検索Provider。
	const ScanResult scan = provider.scan( 0U, options, {}, {}, {}, {}) ;	// IO前の不正入力拒否。
	DRIVERCRATE_EXPECT( context, !scan.succeeded && scan.error != 0 && scan.candidates.empty()) ;
	const std::array<std::wstring, 1> ids{L"unknown"} ;								// 未表示candidate identity。
	const InstallResult install = provider.install( 1U, ids, 0U, {}, {}, {}, {}) ;	// 導入を呼ばない。
	DRIVERCRATE_EXPECT( context, !install.succeeded) ;
	DRIVERCRATE_EXPECT( context, install.installError != 0) ;
	DRIVERCRATE_EXPECT( context, install.updates.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, install.updates.front().installOutcome == OutcomeCode::FAILURE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief CP210x familyの架空新版metadataを作る。
 *
 * 公開標準IDを含むが実端末の識別情報を使用しない。
 * @return 署名検証を意味しない構造test専用metadata。
 */
//------------------------------------------------------------------------------
OfficialInfPackage familyPackage()
{
	OfficialInfPackage package ;	// 既存file構造を維持した架空の将来版。
	package.infRelativePath		= L"silabser.inf" ;
	package.catalogRelativePath = L"silabser.cat" ;
	package.className			= L"Ports" ;
	package.providerName		= L"Silicon Laboratories Inc." ;
	package.driverDate			= L"09/05/2026" ;
	package.driverVersion		= L"12.0.0.1" ;
	package.sourceFiles			= {L"x64\\silabser.sys"} ;
	package.hardwareIds			= {L"USB\\VID_10C4&PID_EA60",		L"USB\\VID_10C4&PID_EA63",
								   L"USB\\VID_10C4&PID_EA70&MI_00", L"USB\\VID_10C4&PID_EA70&MI_01",
								   L"USB\\VID_10C4&PID_EA71&MI_00", L"USB\\VID_10C4&PID_EA71&MI_01",
								   L"USB\\VID_10C4&PID_EA71&MI_02", L"USB\\VID_10C4&PID_EA71&MI_03",
								   L"USB\\VID_10C4&PID_EA7A&MI_00", L"USB\\VID_10C4&PID_EA7A&MI_01",
								   L"USB\\VID_10C4&PID_EA7B&MI_00", L"USB\\VID_10C4&PID_EA7B&MI_01",
								   L"USB\\VID_10C4&PID_EA7B&MI_02", L"USB\\VID_10C4&PID_EA7B&MI_03"} ;
	return package ;
}

//------------------------------------------------------------------------------
/**
 * @brief 新版を許可し別familyと不正版を拒否する。
 *
 * 版固定だけを外し、署名検証前の構造境界が維持されることを試験する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testFamily( TestContext &context)
{
	OfficialInfPackage package = familyPackage() ;	// 正常な構造fixture。
	DRIVERCRATE_EXPECT( context, isSiliconLabsSerialPackageFamily( package)) ;
	package.driverVersion = L"11.5.0.417" ;
	package.driverDate	  = L"12/10/2025" ;
	DRIVERCRATE_EXPECT( context, isSiliconLabsSerialPackageFamily( package)) ;
	// 成分数・空成分・符号・桁上限を逸脱した不正版数の集合。
	constexpr std::array VERSIONS{L"",
								  L"12.0.0",
								  L"12.0.0.1.2",
								  L"12..0.1",
								  L"12.0.0.65536",
								  L"12.0.0.1beta",
								  L"-1.0.0.1",
								  L"12.0.0.999999999999999999"} ;
	// 無効なDriverVerを未知の新版として受理しない。
	for( const wchar_t *const version : VERSIONS) {
		package				  = familyPackage() ;
		package.driverVersion = version ;
		DRIVERCRATE_EXPECT( context, !isSiliconLabsSerialPackageFamily( package)) ;
	}

	// 暦・形式・範囲に違反する公開日の拒否用入力集合。
	constexpr std::array DATES{L"02/29/2025", L"13/01/2026", L"09/31/2026",
							   L"2026/09/05", L"01/01/0000", L"ab/cd/efgh"} ;
	// 日付の形式だけでなく暦上の存在を確認する。
	for( const wchar_t *const date : DATES) {
		package			   = familyPackage() ;
		package.driverDate = date ;
		DRIVERCRATE_EXPECT( context, !isSiliconLabsSerialPackageFamily( package)) ;
	}

	package			   = familyPackage() ;
	package.driverDate = L"02/29/2028" ;
	DRIVERCRATE_EXPECT( context, isSiliconLabsSerialPackageFamily( package)) ;
	package.hardwareIds.back() = package.hardwareIds.front() ;
	DRIVERCRATE_EXPECT( context, !isSiliconLabsSerialPackageFamily( package)) ;
	package = familyPackage() ;
	package.hardwareIds.pop_back() ;
	DRIVERCRATE_EXPECT( context, !isSiliconLabsSerialPackageFamily( package)) ;
	package					   = familyPackage() ;
	package.hardwareIds.back() = L"USB\\VID_0000&PID_0000" ;
	DRIVERCRATE_EXPECT( context, !isSiliconLabsSerialPackageFamily( package)) ;
	package				= familyPackage() ;
	package.sourceFiles = {L"arm64\\silabser.sys"} ;
	DRIVERCRATE_EXPECT( context, !isSiliconLabsSerialPackageFamily( package)) ;
	package						= familyPackage() ;
	package.catalogRelativePath = L"other.cat" ;
	DRIVERCRATE_EXPECT( context, !isSiliconLabsSerialPackageFamily( package)) ;
	package				 = familyPackage() ;
	package.providerName = L"Other Publisher" ;
	DRIVERCRATE_EXPECT( context, !isSiliconLabsSerialPackageFamily( package)) ;
	package			  = familyPackage() ;
	package.className = L"Firmware" ;
	DRIVERCRATE_EXPECT( context, !isSiliconLabsSerialPackageFamily( package)) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 公式INF内の許可外IDとdevice候補の境界を検証する。
 *
 * Fake matcherとrank監査で原本不変、許可ID限定、API失敗を確認。実device、network、file署名の代替合格には使用しない。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testDeviceAudit( TestContext &context)
{
	OfficialInfPackage package ;	// 内容監査後を模したmetadata。実fileは使わない。
	package.hardwareIds					  = {L"USB\\VID_067B&PID_0000", L"USB\\VID_067B&PID_2303",
											 L"USB\\VID_067B&PID_2304"} ;
	package.infRelativePath				  = L"driver.inf" ;
	package.catalogRelativePath			  = L"driver.cat" ;
	package.sourceFiles					  = {L"driver.sys"} ;
	package.className					  = L"Ports" ;
	package.providerName				  = L"Prolific" ;
	package.driverVersion				  = L"1.2.3.4" ;
	const OfficialInfPackage	 original = package ;									// 原本を変更しないことの比較用copy。
	OfficialDownloadWorkspace	 workspace ;											// Fake監査なのでfileを作らない所有object。
	std::size_t					 matcherCalls{} ;										// 許可IDだけに限定される照合回数。
	std::size_t					 auditorCalls{} ;										// 対象deviceに限定されるrank監査回数。
	std::optional<std::wstring>	 resolved = L"device:test" ;							// Fake local照合結果。
	NativeError					 auditorError{} ;										// API失敗を注入する場合の診断値。
	OfficialDriverRankDecision	 decision = OfficialDriverRankDecision::APPLICABLE ;	// 現在rank。
	const LocalHardwareIdMatcher matcher  = [&context, &matcherCalls,
											 &resolved]( const std::wstring_view id) {
		 ++matcherCalls ;
		 DRIVERCRATE_EXPECT( context, isProlificSerialCandidateHardwareId( id)) ;
		 return resolved ;
	} ; // 未審査IDを照合側へ送らないことも検証するfake。
	const OfficialSerialRankAuditor auditor =
		[&context, &auditorCalls, &auditorError, &decision, &original,
		 &workspace]( const ScanSessionId session, const std::wstring_view device,
					 const OfficialDownloadWorkspace &actualWorkspace,
					 const OfficialInfPackage &actual, OfficialDriverRankAudit &audit) {
			++auditorCalls ;
			DRIVERCRATE_EXPECT( context, session == 17U && device == L"device:test") ;
			DRIVERCRATE_EXPECT( context, &actualWorkspace == &workspace) ;
			DRIVERCRATE_EXPECT( context, actual.hardwareIds.size() == 2U) ;
			// 現在状態の監査へ渡すID集合は、原本から許可済みIDだけを残す。
			for( const std::wstring &id : actual.hardwareIds) {
				DRIVERCRATE_EXPECT( context, isProlificSerialCandidateHardwareId( id)) ;
			}

			DRIVERCRATE_EXPECT( context, actual.infRelativePath == original.infRelativePath) ;
			DRIVERCRATE_EXPECT( context, actual.catalogRelativePath == original.catalogRelativePath) ;
			DRIVERCRATE_EXPECT( context, actual.sourceFiles == original.sourceFiles) ;
			DRIVERCRATE_EXPECT( context, actual.className == original.className) ;
			DRIVERCRATE_EXPECT( context, actual.providerName == original.providerName) ;
			DRIVERCRATE_EXPECT( context, actual.driverVersion == original.driverVersion) ;
			audit.decision = decision ;
			return auditorError ;
		} ; // OS／rankの結果だけを注入し、導入APIは呼ばない。
	OfficialDriverRankAudit audit ;	// 各試験で上書きされる監査結果。
	DRIVERCRATE_EXPECT( context, auditOfficialSerialDevice( OfficialSerialFamily::PROLIFIC, 17U,
														  L"device:test", workspace, package,
														  matcher, auditor, audit) == 0) ;
	DRIVERCRATE_EXPECT( context, audit.decision == OfficialDriverRankDecision::APPLICABLE) ;
	DRIVERCRATE_EXPECT( context, matcherCalls == 1U && auditorCalls == 1U) ;
	DRIVERCRATE_EXPECT( context, package.hardwareIds == original.hardwareIds) ;

	package.hardwareIds = {L"USB\\VID_067B&PID_0000"} ;
	matcherCalls		= 0U ;
	auditorCalls		= 0U ;
	DRIVERCRATE_EXPECT( context, auditOfficialSerialDevice( OfficialSerialFamily::PROLIFIC, 17U,
														  L"device:test", workspace, package,
														  matcher, auditor, audit) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   audit.decision == OfficialDriverRankDecision::CANDIDATE_NOT_MATCHED) ;
	DRIVERCRATE_EXPECT( context, matcherCalls == 0U && auditorCalls == 0U) ;

	package	 = original ;
	resolved = L"device:other" ;
	DRIVERCRATE_EXPECT( context, auditOfficialSerialDevice( OfficialSerialFamily::PROLIFIC, 17U,
														  L"device:test", workspace, package,
														  matcher, auditor, audit) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   audit.decision == OfficialDriverRankDecision::CANDIDATE_NOT_MATCHED) ;
	DRIVERCRATE_EXPECT( context, auditorCalls == 0U) ;
	resolved.reset() ;
	DRIVERCRATE_EXPECT( context, auditOfficialSerialDevice( OfficialSerialFamily::PROLIFIC, 17U,
														  L"device:test", workspace, package,
														  matcher, auditor, audit) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   audit.decision == OfficialDriverRankDecision::CANDIDATE_NOT_MATCHED) ;
	DRIVERCRATE_EXPECT( context, auditorCalls == 0U) ;

	resolved = L"device:test" ;
	decision = OfficialDriverRankDecision::CANDIDATE_NOT_MATCHED ;
	DRIVERCRATE_EXPECT( context, auditOfficialSerialDevice( OfficialSerialFamily::PROLIFIC, 17U,
														  L"device:test", workspace, package,
														  matcher, auditor, audit) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   audit.decision == OfficialDriverRankDecision::CANDIDATE_NOT_MATCHED) ;
	decision = OfficialDriverRankDecision::OVERALL_RANK_REGRESSION ;
	DRIVERCRATE_EXPECT( context, auditOfficialSerialDevice( OfficialSerialFamily::PROLIFIC, 17U,
														  L"device:test", workspace, package,
														  matcher, auditor, audit) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   audit.decision == OfficialDriverRankDecision::OVERALL_RANK_REGRESSION) ;
	decision	 = OfficialDriverRankDecision::APPLICABLE ;
	auditorError = static_cast<NativeError>( 0x80070005U) ;
	DRIVERCRATE_EXPECT( context, auditOfficialSerialDevice( OfficialSerialFamily::PROLIFIC, 17U,
														  L"device:test", workspace, package,
														  matcher, auditor, audit) == auditorError) ;
	DRIVERCRATE_EXPECT( context, audit.decision == OfficialDriverRankDecision::NOT_EVALUATED) ;
	DRIVERCRATE_EXPECT( context, package.hardwareIds == original.hardwareIds) ;

	// 不正な要求でmatcherまたはrank APIへ進まないことを確認する。
	matcherCalls = 0U ;
	auditorCalls = 0U ;
	DRIVERCRATE_EXPECT( context,
					   auditOfficialSerialDevice( OfficialSerialFamily::PROLIFIC, 0U, L"device:test",
												 workspace, package, matcher, auditor, audit) != 0) ;
	DRIVERCRATE_EXPECT( context,
					   auditOfficialSerialDevice( OfficialSerialFamily::PROLIFIC, 17U, L"",
												 workspace, package, matcher, auditor, audit) != 0) ;
	DRIVERCRATE_EXPECT( context, auditOfficialSerialDevice( OfficialSerialFamily::PROLIFIC, 17U,
														  L"device:test", workspace, package, {},
														  auditor, audit) != 0) ;
	DRIVERCRATE_EXPECT( context, auditOfficialSerialDevice( OfficialSerialFamily::PROLIFIC, 17U,
														  L"device:test", workspace, package,
														  matcher, {}, audit) != 0) ;
	package.hardwareIds.clear() ;
	DRIVERCRATE_EXPECT( context, auditOfficialSerialDevice( OfficialSerialFamily::PROLIFIC, 17U,
														  L"device:test", workspace, package,
														  matcher, auditor, audit) != 0) ;
	package.hardwareIds.assign( 129U, L"USB\\VID_067B&PID_2303") ;
	DRIVERCRATE_EXPECT( context, auditOfficialSerialDevice( OfficialSerialFamily::PROLIFIC, 17U,
														  L"device:test", workspace, package,
														  matcher, auditor, audit) != 0) ;
	DRIVERCRATE_EXPECT( context, matcherCalls == 0U && auditorCalls == 0U) ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/prolific_official_provider_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runProlificOfficialProviderTests( TestContext &context)
{
	testParser( context) ;
	testConsent( context) ;
	testFamily( context) ;
	testDeviceAudit( context) ;
}
} // namespace drivercrate::test
