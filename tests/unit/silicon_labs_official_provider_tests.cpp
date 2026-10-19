//------------------------------------------------------------------------------
/**
 * @file silicon_labs_official_provider_tests.cpp
 * @brief CP210x公式検索と共通serial境界の試験実装。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  CP210x公式検索の拒否境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Serial計測根拠の同意・失効回帰を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * </pre>
 *
 * @note 公開schemaの合成fixtureとfake照合を使い、通信・導入を行わない。
 */
//------------------------------------------------------------------------------

#include "silicon_labs_official_provider_tests.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/official_serial_provider.h"
#include "platform/official_release_metadata.h"
#include "platform/silicon_labs_catalog_parser.h"
#include "platform/silicon_labs_serial_package.h"
#include "test_framework.h"

#include <array>
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace drivercrate::test {
namespace {
constexpr std::wstring_view HTML =
	LR"(<div class="software-document-list row" data-resource="softwaredocumentlist" )"
	LR"(data-contenttypes="content-type:software" )"
	LR"(data-softwaretag="silicon-labs-software:drivers/vcp-drivers"></div>)" ;	// 公開区画の合成例。
constexpr std::wstring_view RECORD =
	LR"({"name":"CP210x Universal Windows Driver",)"
	LR"("externalPath":"/documents/public/software/CP210x_Universal_Windows_Driver.zip",)"
	LR"("contentTypeTagId":"content-type:software","format":"application/zip",)"
	LR"("sourceType":"DAM","language":"en","version":"12.0.0",)"
	LR"("softwareTypeTagId":["silicon-labs-software:drivers/vcp-drivers"]})" ;	// 架空新版。

//------------------------------------------------------------------------------
/**
 * @brief Networkや実payloadを使わず対象行の検証を試験する。
 *
 * @param[in] record 正常／拒否用の合成配布行。
 * @return 配列に一行を格納した公式schemaの合成JSON。
 */
//------------------------------------------------------------------------------
std::wstring catalog( const std::wstring_view record)
{
	return L"{\"content-type:software\":[" + std::wstring( record) + L"]}" ;
}

//------------------------------------------------------------------------------
/**
 * @brief Testの誤記で拒否例が正常fixtureのまま残ることを防ぐ。
 *
 * @param[in] input 合成fixture。
 * @param[in] from 一意の変更対象。
 * @param[in] to 注入する正常／不正値。
 * @return 一箇所を変更したfixture。対象欠損は例外で試験失敗とする。
 */
//------------------------------------------------------------------------------
std::wstring replaced( const std::wstring_view input, const std::wstring_view from,
					  const std::wstring_view to)
{
	std::wstring	  result( input) ;					// 変更後fixtureの所有copy。
	const std::size_t position = result.find( from) ;	// 注入するfieldの位置。
	// 誤ったtest設定を黙認しない。
	if( position == result.npos) {
		throw std::runtime_error( "missing fixture field") ;
	}

	result.replace( position, from.size(), to) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一意な公式配布、上限、型、URLと旧出力の破棄を検証する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testCatalog( TestContext &context)
{
	const std::wstring valid = catalog( RECORD) ;	// 正常な合成catalog。
	std::wstring	   url ;						// Parserの内部URL結果。
	DRIVERCRATE_EXPECT( context, parseSiliconLabsOfficialZipUrl( HTML, valid, url)) ;
	OfficialReleaseRecord detailed ;	// URL wrapperと明示表示版の共通結果。
	DRIVERCRATE_EXPECT( context, parseSiliconLabsOfficialRelease( HTML, valid, detailed)) ;
	DRIVERCRATE_EXPECT( context, detailed.downloadUrl == url &&
									detailed.family == OfficialReleaseFamily::SILICON_LABS_CP210X &&
									detailed.packageVersion == L"12.0.0") ;
	DRIVERCRATE_EXPECT( context, detailed.publishedDate.empty() &&
									detailed.publishedSha256.empty() &&
									!detailed.publishedSizeBytes &&
									detailed.license == OfficialReleaseLicense::UNRESOLVED) ;
	DRIVERCRATE_EXPECT( context, url == L"https://www.silabs.com/documents/public/software/"
									   L"CP210x_Universal_Windows_Driver.zip") ;
	constexpr std::array BAD_VERSIONS{L"",			 L"12",		   L"12..0",
									  L"12.0.0.0.1", L"65536.0.0", L"12.0-beta",
									  L"12.0.0 ",	 L"-12.0"} ;	// 不正な表示版。
	// 架空新版の受入を維持しつつ数値以外を拒否する。
	for( const wchar_t *const version : BAD_VERSIONS) {
		detailed.packageVersion = L"previous" ;
		DRIVERCRATE_EXPECT( context, !parseSiliconLabsOfficialRelease(
										HTML, replaced( valid, L"12.0.0", version), detailed)) ;
		DRIVERCRATE_EXPECT( context, detailed == OfficialReleaseRecord{}) ;
		url = L"previous" ;
		DRIVERCRATE_EXPECT( context, !parseSiliconLabsOfficialZipUrl(
										HTML, replaced( valid, L"12.0.0", version), url)) ;
		DRIVERCRATE_EXPECT( context, url.empty()) ;
	}

	const std::array<std::pair<std::wstring_view, std::wstring_view>, 15> mutations{
		{{L"/documents/public/software/", L"/documents/login/software/"},
		 {L"/documents/public/software/", L"https://example.invalid/"},
		 {L"/documents/public/software/", L"//www.silabs.com/documents/public/software/"},
		 {L"Driver.zip", L"Driver.zip?download=1"},
		 {L"Driver.zip", L"Driver.zip#fragment"},
		 {L"Driver.zip", L"Driver.zip.exe"},
		 {L"Driver.zip", L"Driver%2ezip"},
		 {L"\"format\":\"application/zip\"", L"\"format\":null"},
		 {L"\"version\":\"12.0.0\"", L"\"version\":12"},
		 {L"\"version\":\"12.0.0\",", L""},
		 {L"\"DAM\"", L"\"external\""},
		 {L"\"en\"", L"\"unknown\""},
		 {L"silicon-labs-software:drivers/vcp-drivers", L"silicon-labs-software:tools"},
		 {L"CP210x Universal Windows Driver", L"CP210x Macintosh OSX Driver"},
		 {L"\"contentTypeTagId\":\"content-type:software\"",
		  L"\"contentTypeTagId\":\"content-type:document\""}}} ;	// 配布境界の拒否例。
	// 各fieldの単独不正が、前回の正常URLを残さないことを検証する。
	for( const auto &[from, to] : mutations) {
		DRIVERCRATE_EXPECT(
			context, !parseSiliconLabsOfficialRelease( HTML, replaced( valid, from, to), detailed)) ;
		DRIVERCRATE_EXPECT( context, detailed == OfficialReleaseRecord{}) ;
		url = L"previous" ;
		DRIVERCRATE_EXPECT( context,
						   !parseSiliconLabsOfficialZipUrl( HTML, replaced( valid, from, to), url)) ;
		DRIVERCRATE_EXPECT( context, url.empty()) ;
	}

	const std::array badCatalogs{
		catalog( std::wstring( RECORD) + L"," + std::wstring( RECORD)),
		std::wstring( L"{\"content-type:software\":{}}"),
		std::wstring( L"{\"content-type:software\":[]}"),
		std::wstring( L"<html>challenge</html>"),
		std::wstring( 2U * 1024U * 1024U + 1U, L' '),
		valid + std::wstring( 1U, L'\0')} ;	// 曖昧性、型、上限、中途終端の拒否例。
	// 大容量もJSON parserの前で止め、実networkには接続しない。
	for( const std::wstring &json : badCatalogs) {
		detailed.packageVersion = L"previous" ;
		DRIVERCRATE_EXPECT( context, !parseSiliconLabsOfficialRelease( HTML, json, detailed)) ;
		DRIVERCRATE_EXPECT( context, detailed == OfficialReleaseRecord{}) ;
		url = L"previous" ;
		DRIVERCRATE_EXPECT( context, !parseSiliconLabsOfficialZipUrl( HTML, json, url)) ;
		DRIVERCRATE_EXPECT( context, url.empty()) ;
	}

	const std::array badPages{std::wstring( L"<html>challenge</html>"),
							  std::wstring( HTML) + std::wstring( HTML),
							  replaced( HTML, L"vcp-drivers", L"another-driver"),
							  replaced( HTML, L"content-type:software", L"content-type:document"),
							  std::wstring( HTML) + std::wstring( 1U, L'\0'),
							  // 正しいJSONだけでは許可しないpage例。
							  std::wstring( 2U * 1024U * 1024U + 1U, L' ')} ;
	// Landingの対象区画が不正なら配布URLを公開しない。
	for( const std::wstring &html : badPages) {
		detailed.packageVersion = L"previous" ;
		DRIVERCRATE_EXPECT( context, !parseSiliconLabsOfficialRelease( html, valid, detailed)) ;
		DRIVERCRATE_EXPECT( context, detailed == OfficialReleaseRecord{}) ;
		url = L"previous" ;
		DRIVERCRATE_EXPECT( context, !parseSiliconLabsOfficialZipUrl( html, valid, url)) ;
		DRIVERCRATE_EXPECT( context, url.empty()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 2メーカーの同意組合せと固定host／用途を副作用なしで試験する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testConsentAndRegistry( TestContext &context)
{
	// 選択2bitと同意2bitの全16組合せで、他メーカーへの同意転用を拒否する。
	for( unsigned mask = 0U; mask < 16U; ++mask) {
		ScanOptions options{.useDefaultProviders = false} ;	// 今回だけの試験設定。
		// 組合せmaskのProlific bitが指定されたscenarioにだけProviderを含める。
		if( (mask & 1U) != 0U) {
			options.enabledProviderIds.emplace_back( PROLIFIC_OFFICIAL_PROVIDER_ID) ;
		}

		// 組合せmaskのSilicon Labs bitが指定されたscenarioにだけProviderを含める。
		if( (mask & 2U) != 0U) {
			options.enabledProviderIds.emplace_back( SILICON_LABS_OFFICIAL_PROVIDER_ID) ;
		}

		options.prolificInspectionApproved	  = (mask & 4U) != 0U ;
		options.siliconLabsInspectionApproved = (mask & 8U) != 0U ;
		const bool expected = (mask & 3U) == (mask >> 2U) ;	// 両方の対応が一致する場合のみ有効。
		DRIVERCRATE_EXPECT( context, validateScanOptions( options) == expected) ;
	}

	ScanOptions defaults ;	// 既定OFFのProviderへ同意だけを与える拒否例。
	defaults.siliconLabsInspectionApproved = true ;
	DRIVERCRATE_EXPECT( context, !validateScanOptions( defaults)) ;
	const OfficialSourcePolicy *const policy =
		// 組み込み取得契約。
		officialSourcePolicyForProvider( SILICON_LABS_OFFICIAL_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, policy != nullptr) ;
	// Silicon Labs policyがある場合にだけ三用途の固定hostとredirect禁止を検証する。
	if( policy != nullptr) {
		DRIVERCRATE_EXPECT( context, policy->id == SILICON_LABS_OFFICIAL_SOURCE_POLICY_ID) ;
		DRIVERCRATE_EXPECT( context, policy->resources.size() == 3U) ;
		// Landing、JSON、payloadの全用途が一つの完全一致hostだけを許可する。
		for( const OfficialSourceResourcePolicy &resource : policy->resources) {
			DRIVERCRATE_EXPECT( context, resource.maximumRedirects == 0U) ;
			DRIVERCRATE_EXPECT( context, resource.allowedHosts.size() == 1U) ;
			DRIVERCRATE_EXPECT( context, resource.allowedHosts.front() == L"www.silabs.com") ;
		}
	}

	OfficialSerialProvider provider{OfficialSerialFamily::SILICON_LABS} ;	// IO前の未検索instance。
	DRIVERCRATE_EXPECT( context, provider.providerId() == SILICON_LABS_OFFICIAL_PROVIDER_ID) ;
	const ScanResult rejected = provider.scan( 1U, defaults, {}, {}, {}, {}) ;	// 同意不正で拒否。
	DRIVERCRATE_EXPECT( context, !rejected.succeeded && rejected.error != 0) ;
	const LocalHardwareIdMatcher unusedMatcher = []( const std::wstring_view) {
		return std::optional<std::wstring>{} ;
	} ; // 空inventory試験で照合や通信へ進めないfake。
	const OfficialSerialRankAuditor unusedAuditor =
		[]( const ScanSessionId, const std::wstring_view, const OfficialDownloadWorkspace &,
		   const OfficialInfPackage &, OfficialDriverRankAudit &) {
			return NativeError{} ;
		} ; // 実OSに依存しない入力gate試験用callback。
	const ProviderProgressCallback unusedProgress = []( const ProviderProgress &) {
	} ; // 空inventoryで進捗通知が必要でもUIへ接続しない。
	ScanOptions otherFamily{	// 設定自体は有効だが、CP210xへは取得を許可していない。
							.useDefaultProviders = false,
							.enabledProviderIds	 = {std::wstring( PROLIFIC_OFFICIAL_PROVIDER_ID)},
							.prolificInspectionApproved = true} ;
	DRIVERCRATE_EXPECT( context, validateScanOptions( otherFamily)) ;
	DRIVERCRATE_EXPECT(
		context, !provider.scan( 1U, otherFamily, {}, unusedMatcher, unusedAuditor, unusedProgress)
					  .succeeded) ;
	DRIVERCRATE_EXPECT( context, provider.measurementEvidence().providerId ==
									SILICON_LABS_OFFICIAL_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context,
					   provider.measurementEvidence().eligible.extent == MeasurementExtent::EXACT) ;
	DRIVERCRATE_EXPECT( context,
					   provider.measurementEvidence().queryOutcome == OutcomeCode::NOT_STARTED) ;
	otherFamily.enabledProviderIds			  = {std::wstring( SILICON_LABS_OFFICIAL_PROVIDER_ID)} ;
	otherFamily.prolificInspectionApproved	  = false ;
	otherFamily.siliconLabsInspectionApproved = true ;
	const ScanResult empty = provider.scan( 1U, otherFamily, {}, unusedMatcher, unusedAuditor,
										   unusedProgress) ;	// 同意が有効でも対象なしなら通信なし。
	DRIVERCRATE_EXPECT( context, empty.succeeded && empty.candidates.empty()) ;
	DRIVERCRATE_EXPECT( context, empty.state == ProviderScanState::NOT_APPLICABLE) ;
	DRIVERCRATE_EXPECT( context,
					   provider.measurementEvidence().queryOutcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, provider.measurementEvidence().queryCompleted.extent ==
									MeasurementExtent::EXACT) ;
	DRIVERCRATE_EXPECT( context,
					   provider.measurementEvidence().recordExtent == MeasurementExtent::EXACT) ;
	const std::array<std::wstring, 1> unknown{L"unissued"} ;							// 他sessionの未表示IDを模す。
	const InstallResult install = provider.install( 1U, unknown, 0U, {}, {}, {}, {}) ;	// IOなし。
	DRIVERCRATE_EXPECT( context, !install.succeeded && install.installError != 0) ;
	DRIVERCRATE_EXPECT( context, provider.measurementEvidence().providerId.empty()) ;
	OfficialSerialProvider invalid{static_cast<OfficialSerialFamily>( 99)} ;	// 定義外enum。
	DRIVERCRATE_EXPECT( context, invalid.providerId().empty()) ;
	DRIVERCRATE_EXPECT( context, !invalid.scan( 1U, {}, {}, {}, {}, {}).succeeded) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Family限定、署名原本不変、現在rankと失敗の保持を検証する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testFamilyAudit( TestContext &context)
{
	OfficialInfPackage package ;	// 実端末由来ではない公開標準IDを含む合成metadata。
	package.hardwareIds = {L"USB\\VID_10C4&PID_EA60", L"USB\\VID_067B&PID_2303"} ;
	const auto original = package.hardwareIds ;										// 許可subset処理で原本を変えない比較値。
	OfficialDownloadWorkspace  workspace ;											// Fakeのためfileを作成しない保護領域。
	std::size_t				   calls{} ;											// 許可ID一致後に呼ばれたrank監査の件数。
	NativeError				   failure{} ;											// API失敗注入時の保存診断値。
	OfficialDriverRankDecision decision	 = OfficialDriverRankDecision::APPLICABLE ;	// Fake現在rank。
	const LocalHardwareIdMatcher matcher = [&context]( const std::wstring_view id) {
		DRIVERCRATE_EXPECT( context, isSiliconLabsSerialCandidateHardwareId( id)) ;
		return std::optional<std::wstring>( L"device:test") ;
	} ; // 未審査IDがlocal照合へ流れないことを確認する。
	const OfficialSerialRankAuditor auditor = [&context, &calls, &failure,
											   &decision]( const ScanSessionId	  session,
														  const std::wstring_view device,
														  const OfficialDownloadWorkspace &,
														  const OfficialInfPackage &restricted,
														  OfficialDriverRankAudit  &audit) {
		++calls ;
		DRIVERCRATE_EXPECT( context, session == 7U && device == L"device:test") ;
		DRIVERCRATE_EXPECT( context, restricted.hardwareIds.size() == 1U) ;
		DRIVERCRATE_EXPECT( context,
						   isSiliconLabsSerialCandidateHardwareId( restricted.hardwareIds.front())) ;
		audit.decision = decision ;
		return failure ;
	} ; // 現在rankを注入するだけで実Windows APIへ接続しない。
	OfficialDriverRankAudit audit ;	// 各呼出しが初期化する監査結果。
	DRIVERCRATE_EXPECT( context, auditOfficialSerialDevice( OfficialSerialFamily::SILICON_LABS, 7U,
														  L"device:test", workspace, package,
														  matcher, auditor, audit) == 0) ;
	DRIVERCRATE_EXPECT( context, audit.decision == OfficialDriverRankDecision::APPLICABLE) ;
	DRIVERCRATE_EXPECT( context, package.hardwareIds == original && calls == 1U) ;
	decision = OfficialDriverRankDecision::CANDIDATE_NOT_MATCHED ;
	DRIVERCRATE_EXPECT( context, auditOfficialSerialDevice( OfficialSerialFamily::SILICON_LABS, 7U,
														  L"device:test", workspace, package,
														  matcher, auditor, audit) == 0) ;
	DRIVERCRATE_EXPECT( context, audit.decision == decision) ;
	failure	 = 1234 ;
	decision = OfficialDriverRankDecision::APPLICABLE ;
	DRIVERCRATE_EXPECT( context, auditOfficialSerialDevice( OfficialSerialFamily::SILICON_LABS, 7U,
														  L"device:test", workspace, package,
														  matcher, auditor, audit) == failure) ;
	DRIVERCRATE_EXPECT( context, audit.decision != OfficialDriverRankDecision::APPLICABLE) ;
	// 別familyだけなら照合も監査も行わない。
	package.hardwareIds = {L"USB\\VID_067B&PID_2303"} ;
	calls				= 0U ;
	DRIVERCRATE_EXPECT( context, auditOfficialSerialDevice( OfficialSerialFamily::SILICON_LABS, 7U,
														  L"device:test", workspace, package,
														  matcher, auditor, audit) == 0) ;
	DRIVERCRATE_EXPECT( context, calls == 0U) ;
	DRIVERCRATE_EXPECT( context,
					   audit.decision == OfficialDriverRankDecision::CANDIDATE_NOT_MATCHED) ;
	DRIVERCRATE_EXPECT( context, auditOfficialSerialDevice( static_cast<OfficialSerialFamily>( 99), 7U,
														  L"device:test", workspace, package,
														  matcher, auditor, audit) != 0) ;
	DRIVERCRATE_EXPECT( context, calls == 0U) ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/silicon_labs_official_provider_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runSiliconLabsOfficialProviderTests( TestContext &context)
{
	testCatalog( context) ;
	testConsentAndRegistry( context) ;
	testFamilyAudit( context) ;
}
} // namespace drivercrate::test
