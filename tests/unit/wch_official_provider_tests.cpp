//------------------------------------------------------------------------------
/**
 * @file wch_official_provider_tests.cpp
 * @brief WCH公式取得とserial共通境界の試験実装。
 * @version 01.00.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公開取得の拒否試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * </pre>
 *
 * @note 実deviceを列挙せず、公開schemaの合成例とfake監査で境界を検証する。
 */
//------------------------------------------------------------------------------

#include "wch_official_provider_tests.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/official_serial_provider.h"
#include "platform/official_release_metadata.h"
#include "platform/wch_catalog_parser.h"
#include "platform/wch_serial_package.h"
#include "test_framework.h"

#include <array>
#include <cstddef>
#include <initializer_list>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace drivercrate::test {
namespace {
constexpr std::wstring_view HTML =	// 実scriptを実行しない、審査形式の合成landing。
	L"<script>\nwindow._CONFIG['domianURL'] = 'https://api1.wch.cn' // endpoint\n"
	L"</script><div id=\"app\"></div><script src=\"/js/app.js\"></script>" ;
constexpr std::wstring_view JSON =	// File IDと版は架空。関連fileを取得しないことも確認する。
	LR"({"code":0,"data":{"id":1001,"name":"CH341SER.ZIP","version":"5.1",)"
	LR"("categoryId":67,"auth":"0","redirect":null,"fullUrl":null,)"
	LR"("githubDownloadUrl":"","relationFileList":[{"name":"other.exe","id":9999}]}})" ;

//------------------------------------------------------------------------------
/**
 * @brief Testの誤記で不正fixtureが注入されない状態を拒否する。
 *
 * @param[in] input 合成fixture。
 * @param[in] from 変更箇所。
 * @param[in] to 正常または拒否用の値。
 * @return 一箇所変更したcopy。対象欠損は例外で試験失敗とする。
 */
//------------------------------------------------------------------------------
std::wstring replaced( const std::wstring_view input, const std::wstring_view from,
					  const std::wstring_view to)
{
	std::wstring	  result( input) ;					// 合成例を変更する所有copy。
	const std::size_t position = result.find( from) ;	// 一意の変更対象位置。
	// Test設定不正を黙認しない。
	if( position == result.npos) {
		throw std::runtime_error( "missing fixture field") ;
	}

	result.replace( position, from.size(), to) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 2配布種別の正常metadataと不正型／URL／認証／IDを検証する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testParser( TestContext &context)
{
	std::wstring	   url ;														// 前回の結果を失敗時に残さない内部URL出力。
	const std::wstring multi = replaced( JSON, L"CH341SER.ZIP", L"CH343SER.ZIP") ;	// 別family。
	DRIVERCRATE_EXPECT( context,
					   parseWchOfficialZipUrl( WchOfficialPackageKind::CH341, HTML, JSON, url)) ;
	DRIVERCRATE_EXPECT( context, url == L"https://file.wch.cn/download/file?id=1001") ;
	OfficialReleaseRecord detailed ;	// 明示配布版と旧URL wrapperの同値性を検証する。
	DRIVERCRATE_EXPECT(
		context, parseWchOfficialRelease( WchOfficialPackageKind::CH341, HTML, JSON, detailed)) ;
	DRIVERCRATE_EXPECT( context, detailed.downloadUrl == url &&
									detailed.family == OfficialReleaseFamily::WCH_CH341 &&
									detailed.packageVersion == L"5.1" &&
									detailed.releaseKey == L"1001") ;
	DRIVERCRATE_EXPECT( context, detailed.publishedDate.empty() &&
									detailed.publishedSha256.empty() &&
									!detailed.publishedSizeBytes &&
									detailed.license == OfficialReleaseLicense::UNRESOLVED) ;
	DRIVERCRATE_EXPECT(
		context, parseWchOfficialRelease( WchOfficialPackageKind::CH343, HTML, multi, detailed)) ;
	DRIVERCRATE_EXPECT( context, detailed.family == OfficialReleaseFamily::WCH_CH343 &&
									detailed.fileName == L"CH343SER.ZIP" &&
									detailed.packageVersion == L"5.1") ;
	DRIVERCRATE_EXPECT( context,
					   parseWchOfficialZipUrl( WchOfficialPackageKind::CH343, HTML, multi, url)) ;
	DRIVERCRATE_EXPECT( context,
					   parseOfficialSerialZipUrl( OfficialSerialFamily::WCH_CH341, HTML, JSON, url)) ;
	DRIVERCRATE_EXPECT(
		context, parseOfficialSerialZipUrl( OfficialSerialFamily::WCH_CH343, HTML, multi, url)) ;
	DRIVERCRATE_EXPECT(
		context, !parseOfficialSerialZipUrl( OfficialSerialFamily::WCH_CH343, HTML, JSON, url)) ;
	DRIVERCRATE_EXPECT( context, url.empty()) ;
	DRIVERCRATE_EXPECT( context,
					   parseWchOfficialZipUrl( WchOfficialPackageKind::CH341, HTML,
											  replaced( JSON, L"1001", L"2147483647"), url)) ;
	DRIVERCRATE_EXPECT( context, url == L"https://file.wch.cn/download/file?id=2147483647") ;
	const std::array<std::pair<std::wstring_view, std::wstring_view>, 25> mutations{
		{{L"1001", L"0"},
		 {L"1001", L"-1"},
		 {L"1001", L"1.5"},
		 {L"1001", L"2147483648"},
		 {L"1001", L"1e309"},
		 {L"1001", L"\"1001\""},
		 {L"1001", L"null"},
		 {L"1001", L"true"},
		 {L"\"code\":0", L"\"code\":1"},
		 {L"\"code\":0", L"\"code\":\"0\""},
		 {L"\"auth\":\"0\"", L"\"auth\":\"1\""},
		 {L"\"auth\":\"0\"", L"\"auth\":0"},
		 {L"\"categoryId\":67", L"\"categoryId\":68"},
		 {L"\"categoryId\":67", L"\"categoryId\":\"67\""},
		 {L"CH341SER.ZIP", L"CH343SER.ZIP"},
		 {L"CH341SER.ZIP", L"CH341SER.EXE"},
		 {L"\"version\":\"5.1\"", L"\"version\":null"},
		 {L"\"version\":\"5.1\",", L""},
		 {L"5.1", L"5..1"},
		 {L"5.1", L"5.1-beta"},
		 {L"5.1", L"5.1.0.0.1"},
		 {L"5.1", L""},
		 {L"\"redirect\":null", L"\"redirect\":\"https://example.invalid/\""},
		 {L"\"fullUrl\":null", L"\"fullUrl\":\"https://example.invalid/\""},
		 {L"\"githubDownloadUrl\":\"\"",
		  L"\"githubDownloadUrl\":\"https://example.invalid/\""}}} ;	// 単一不正fieldの拒否例。
	// 全拒否例でURLの持ち越しがないことも検証する。
	for( const auto &[from, to] : mutations) {
		DRIVERCRATE_EXPECT( context, !parseWchOfficialRelease( WchOfficialPackageKind::CH341, HTML,
															 replaced( JSON, from, to), detailed)) ;
		DRIVERCRATE_EXPECT( context, detailed == OfficialReleaseRecord{}) ;
		url = L"previous" ;
		DRIVERCRATE_EXPECT( context, !parseWchOfficialZipUrl( WchOfficialPackageKind::CH341, HTML,
															replaced( JSON, from, to), url)) ;
		DRIVERCRATE_EXPECT( context, url.empty()) ;
	}

	const std::array badJson{
		std::wstring( L"<html>challenge</html>"), std::wstring( L"{\"code\":0,\"data\":[]}"),
		std::wstring( L"{\"code\":0}"), std::wstring( JSON) + std::wstring( 1U, L'\0'),
		// 本文拒否例。
		std::wstring( 2U * 1024U * 1024U + 1U, L' ')} ;
	// 型と長さが不正な応答をWindows JSON parserへ無制限に渡さない。
	for( const std::wstring &json : badJson) {
		detailed.packageVersion = L"previous" ;
		DRIVERCRATE_EXPECT(
			context, !parseWchOfficialRelease( WchOfficialPackageKind::CH341, HTML, json, detailed)) ;
		DRIVERCRATE_EXPECT( context, detailed == OfficialReleaseRecord{}) ;
		DRIVERCRATE_EXPECT( context,
						   !parseWchOfficialZipUrl( WchOfficialPackageKind::CH341, HTML, json, url)) ;
	}

	const std::array badHtml{std::wstring( L"<html>challenge</html>"),
							 replaced( HTML, L"https://api1.wch.cn", L"https://example.invalid"),
							 replaced( HTML, L"window._CONFIG", L"// window._CONFIG"),
							 replaced( HTML, L"/js/app.js", L"/js/unknown.js"),
							 replaced( HTML, L" // endpoint", L" + 'extra'"),
							 std::wstring( HTML) +
								 L"\nwindow._CONFIG['domianURL'] = 'https://api1.wch.cn'",
							 std::wstring( HTML) + std::wstring( 1U, L'\0'),
							 // 別origin、再代入、過大pageの拒否例。
							 std::wstring( 2U * 1024U * 1024U + 1U, L' ')} ;
	// 正常JSONだけで不正な起点を許可しない。
	for( const std::wstring &html : badHtml) {
		detailed.packageVersion = L"previous" ;
		DRIVERCRATE_EXPECT(
			context, !parseWchOfficialRelease( WchOfficialPackageKind::CH341, html, JSON, detailed)) ;
		DRIVERCRATE_EXPECT( context, detailed == OfficialReleaseRecord{}) ;
		DRIVERCRATE_EXPECT( context,
						   !parseWchOfficialZipUrl( WchOfficialPackageKind::CH341, html, JSON, url)) ;
	}

	url = L"previous" ;
	DRIVERCRATE_EXPECT(
		context, !parseWchOfficialZipUrl( static_cast<WchOfficialPackageKind>( 99), HTML, JSON, url)) ;
	DRIVERCRATE_EXPECT( context, url.empty()) ;
	url = L"previous" ;
	DRIVERCRATE_EXPECT( context, !parseOfficialSerialZipUrl( static_cast<OfficialSerialFamily>( 99),
														   HTML, JSON, url)) ;
	DRIVERCRATE_EXPECT( context, url.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 4 familyの全同意組合せ、入力gate、予算と用途別hostを検証する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testConsentAndLimits( TestContext &context)
{
	constexpr std::array IDS{PROLIFIC_OFFICIAL_PROVIDER_ID, SILICON_LABS_OFFICIAL_PROVIDER_ID,
							 WCH_OFFICIAL_PROVIDER_ID,
							 WCH_MULTI_OFFICIAL_PROVIDER_ID} ;	// 審査済み4経路。
	// 選択4bitと同意4bitの全256組合せを検証し、別familyへの転用を防ぐ。
	for( unsigned mask = 0U; mask < 256U; ++mask) {
		ScanOptions options{.useDefaultProviders = false} ;	// 一回限りの合成設定。
		// 有限な4経路の選択bitだけをenabled集合へ反映する。
		for( std::size_t index = 0; index < IDS.size(); ++index) {
			// 組合せmaskが指定したfamilyだけを有効Provider集合へ追加する。
			if( (mask & (1U << index)) != 0U) {
				options.enabledProviderIds.emplace_back( IDS[index]) ;
			}
		}

		options.prolificInspectionApproved	  = (mask & 16U) != 0U ;
		options.siliconLabsInspectionApproved = (mask & 32U) != 0U ;
		options.wchInspectionApproved		  = (mask & 64U) != 0U ;
		options.wchMultiInspectionApproved	  = (mask & 128U) != 0U ;
		DRIVERCRATE_EXPECT( context, validateScanOptions( options) == ((mask & 15U) == (mask >> 4U))) ;
	}

	OfficialSerialProvider ch341{OfficialSerialFamily::WCH_CH341} ;				// 通信しない未検索instance。
	OfficialSerialProvider ch343{OfficialSerialFamily::WCH_CH343} ;				// 別familyの未検索instance。
	OfficialSerialProvider prolific{OfficialSerialFamily::PROLIFIC} ;			// 既存予算の回帰対象。
	OfficialSerialProvider silabs{OfficialSerialFamily::SILICON_LABS} ;			// 既存予算の回帰対象。
	OfficialSerialProvider unknown{static_cast<OfficialSerialFamily>( 99)} ;	// 未知enum拒否例。
	DRIVERCRATE_EXPECT( context, ch341.providerId() == WCH_OFFICIAL_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, ch343.providerId() == WCH_MULTI_OFFICIAL_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, ch341.maximumArchiveBytes() == 4ULL * 1024ULL * 1024ULL) ;
	DRIVERCRATE_EXPECT( context, ch343.maximumArchiveBytes() == ch341.maximumArchiveBytes()) ;
	DRIVERCRATE_EXPECT( context, prolific.maximumArchiveBytes() == 32ULL * 1024ULL * 1024ULL) ;
	DRIVERCRATE_EXPECT( context, silabs.maximumArchiveBytes() == prolific.maximumArchiveBytes()) ;
	DRIVERCRATE_EXPECT( context, unknown.maximumArchiveBytes() == 0U) ;
	const LocalHardwareIdMatcher matcher = []( const std::wstring_view) {
		return std::optional<std::wstring>{} ;
	} ; // 空inventory試験なので照合先なし。
	const OfficialSerialRankAuditor auditor =
		[]( const ScanSessionId, const std::wstring_view, const OfficialDownloadWorkspace &,
		   const OfficialInfPackage &,
		   OfficialDriverRankAudit &) { return NativeError{} ; } ;					// Fake。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {} ;	// UIへ通知しない。
	ScanOptions					   options{.useDefaultProviders = false,
										   .enabledProviderIds = {std::wstring( WCH_OFFICIAL_PROVIDER_ID)},
										   .wchInspectionApproved = true} ;	// CH341だけに同意した有効設定。
	DRIVERCRATE_EXPECT( context, validateScanOptions( options)) ;
	DRIVERCRATE_EXPECT( context, !ch343.scan( 1U, options, {}, matcher, auditor, progress).succeeded) ;
	const ScanResult empty =
		// 通信しない。
		ch341.scan( 1U, options, {}, matcher, auditor, progress) ;
	DRIVERCRATE_EXPECT( context,
					   empty.succeeded && empty.state == ProviderScanState::NOT_APPLICABLE) ;
	options.useDefaultProviders = true ;
	options.enabledProviderIds.clear() ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( options)) ;
	const std::array<std::wstring, 1> unissued{L"unissued"} ;	// 未表示IDを使う導入拒否例。
	DRIVERCRATE_EXPECT( context, !ch341.install( 1U, unissued, 0U, {}, {}, {}, {}).succeeded) ;
	// 2経路とも同じ厳密なhost分離を要求し、API hostをpayloadへ流用しない。
	for( const auto id : {WCH_OFFICIAL_PROVIDER_ID, WCH_MULTI_OFFICIAL_PROVIDER_ID}) {
		const auto *const policy = officialSourcePolicyForProvider( id) ;	// 非所有の取得契約。
		DRIVERCRATE_EXPECT( context, policy != nullptr) ;
		// 取得元policyがない場合は無効pointerを参照せず次のfamilyへ進む。
		// Test失敗後もnullptrを参照しない。
		if( policy == nullptr) {
			continue ;
		}

		const std::array expected{OFFICIAL_LANDING_RESOURCE_ID,
								  OFFICIAL_PRIMARY_METADATA_RESOURCE_ID,
								  OFFICIAL_PAYLOAD_RESOURCE_ID} ;				// 検査する用途順序。
		const std::array hosts{L"www.wch.cn", L"api1.wch.cn", L"file.wch.cn"} ;	// 用途別の正本。
		// 全用途のredirect禁止と完全一致hostを確認する。
		for( std::size_t index = 0; index < expected.size(); ++index) {
			// 同一policy内の非所有参照。未登録を合格にしない。
			const auto *const resource = findOfficialSourceResource( *policy, expected[index]) ;
			DRIVERCRATE_EXPECT( context, resource != nullptr) ;
			// 用途別resourceがない場合は詳細fieldを参照しない。
			if( resource == nullptr) {
				continue ;
			}

			DRIVERCRATE_EXPECT( context, resource->maximumRedirects == 0U) ;
			DRIVERCRATE_EXPECT( context, resource->allowedHosts.size() == 1U) ;
			// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
			if( resource->allowedHosts.size() == 1U) {
				DRIVERCRATE_EXPECT( context, resource->allowedHosts.front() == hosts[index]) ;
			}
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 2 familyの公開標準ID限定、原本不変、rank失敗をfakeで検証する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testFamilyAudit( TestContext &context)
{
	// 実端末のIDではなく、既存の公開package policyにある標準IDを試験する。
	for( const OfficialSerialFamily family :
		{OfficialSerialFamily::WCH_CH341, OfficialSerialFamily::WCH_CH343}) {
		const std::wstring_view allowed = family == OfficialSerialFamily::WCH_CH341
											  ? L"USB\\VID_1A86&PID_7523"
											  : L"USB\\VID_1A86&PID_55D3" ;	// 対象familyの標準ID。
		OfficialInfPackage		package ;									// 内容監査後を模す合成metadata。実fileを使わない。
		package.hardwareIds					= {L"USB\\VID_FFFE&PID_0001", std::wstring( allowed)} ;
		const auto				   original = package.hardwareIds ;						// 原本不変の比較用copy。
		OfficialDownloadWorkspace  workspace ;											// Fakeのためfileを生成しない領域。
		std::size_t				   calls{} ;											// Local一致後にrank監査した件数。
		NativeError				   failure{} ;											// Windows API失敗を模す診断値。
		OfficialDriverRankDecision decision	 = OfficialDriverRankDecision::APPLICABLE ;	// 注入rank。
		const LocalHardwareIdMatcher matcher = [&context, allowed]( const std::wstring_view id) {
			DRIVERCRATE_EXPECT( context, id == allowed) ;
			return std::optional<std::wstring>( L"device:test") ;
		} ; // 未審査IDがmatcherへ流れないことも検査する。
		const OfficialSerialRankAuditor auditor =
			[&context, &calls, &failure, &decision, allowed](
				const ScanSessionId, const std::wstring_view, const OfficialDownloadWorkspace &,
				const OfficialInfPackage &restricted, OfficialDriverRankAudit &audit) {
				++calls ;
				DRIVERCRATE_EXPECT( context, restricted.hardwareIds.size() == 1U) ;
				DRIVERCRATE_EXPECT( context, restricted.hardwareIds.front() == allowed) ;
				audit.decision = decision ;
				return failure ;
			} ; // 実OSを変更せず現在rankと失敗だけを注入する。
		OfficialDriverRankAudit audit ;	// 各呼出しで初期化される監査結果。
		DRIVERCRATE_EXPECT( context,
						   auditOfficialSerialDevice( family, 7U, L"device:test", workspace, package,
													 matcher, auditor, audit) == 0) ;
		DRIVERCRATE_EXPECT( context, calls == 1U && audit.decision == decision) ;
		DRIVERCRATE_EXPECT( context, package.hardwareIds == original) ;
		decision = OfficialDriverRankDecision::CANDIDATE_NOT_MATCHED ;
		DRIVERCRATE_EXPECT( context,
						   auditOfficialSerialDevice( family, 7U, L"device:test", workspace, package,
													 matcher, auditor, audit) == 0) ;
		DRIVERCRATE_EXPECT( context, audit.decision == decision) ;
		decision = OfficialDriverRankDecision::APPLICABLE ;
		failure	 = 1234 ;
		DRIVERCRATE_EXPECT( context,
						   auditOfficialSerialDevice( family, 7U, L"device:test", workspace, package,
													 matcher, auditor, audit) == failure) ;
		DRIVERCRATE_EXPECT( context, audit.decision != OfficialDriverRankDecision::APPLICABLE) ;
		// 別familyの標準IDも、このinstanceの許可IDとして取り込まない。
		package.hardwareIds = {family == OfficialSerialFamily::WCH_CH341
								   ? L"USB\\VID_1A86&PID_55D3"
								   : L"USB\\VID_1A86&PID_7523"} ;
		calls				= 0U ;
		DRIVERCRATE_EXPECT( context,
						   auditOfficialSerialDevice( family, 7U, L"device:test", workspace, package,
													 matcher, auditor, audit) == 0) ;
		DRIVERCRATE_EXPECT( context,
						   calls == 0U &&
							   audit.decision == OfficialDriverRankDecision::CANDIDATE_NOT_MATCHED) ;
	}
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/wch_official_provider_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runWchOfficialProviderTests( TestContext &context)
{
	testParser( context) ;
	testConsentAndLimits( context) ;
	testFamilyAudit( context) ;
}
} // namespace drivercrate::test
