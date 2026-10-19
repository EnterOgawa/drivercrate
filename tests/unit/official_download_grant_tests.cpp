//------------------------------------------------------------------------------
/**
 * @file official_download_grant_tests.cpp
 * @brief 公式配布record、download grant、root resolution単体試験を実装します。
 * @version 01.10.01
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Record／grant／root routing fixtureを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Hop期限と一回非cache再解決fixtureを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  静的HTML／JSON record helper fixtureを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  OF05再解決をIntel Windows 11 policyへ結合。
 * Ver.01.04.00 Shunji Ogawa  2026/09/15  OF13のEULA変更とgrant再使用拒否を明示検証。
 * Ver.01.05.00 Shunji Ogawa  2026/09/20  Archive表現上限とinstaller旧上限を個別検証。
 * Ver.01.06.00 Shunji Ogawa  2026/09/20  公式driver分類のstable fingerprint結合を検証。
 * Ver.01.07.00 Shunji Ogawa  2026/09/23  SHA-512指紋・移動・不正値・再解決の拒否を検証。
 * Ver.01.08.00 Shunji Ogawa  2026/09/28  収集専用射影と通常recordの指紋互換・拒否を検証。
 * Ver.01.09.00 Shunji Ogawa  2026/09/28  公開文字境界と変更前の通常record指紋を固定検証。
 * Ver.01.10.00 Shunji Ogawa  2026/09/29  CNG境界probeの通常hash・失敗後空出力を検証。
 * Ver.01.10.01 Shunji Ogawa  2026/10/02  AI依存を撤去し非AI共通処理と試験を維持。
 * </pre>
 *
 * @note 架空URLとcallbackだけを使用し、通信、file取得、driver導入、installer実行を行いません。
 */
//------------------------------------------------------------------------------

#include "official_download_grant_tests.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/official_download_grant.h"
#include "platform/official_record_utilities.h"
#include "platform/official_collector_public_text.h"
#include "platform/official_record_resolution.h"
#include "platform/secret_official_url.h"
#include "platform/official_static_record_parser.h"
#include "test_framework.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr ScanSessionId SESSION_ID			= 700U ;	// 基本fixtureのscan session。
constexpr std::uint64_t ROOT_BODY_UTC		= 10'000U ;	// 架空root本文取得UTC秒。
constexpr std::uint64_t ROOT_VALIDATED_UTC	= 10'001U ;	// 架空root検証UTC秒。
constexpr std::uint64_t RECORD_RESOLVED_UTC = 10'002U ;	// 架空record解決UTC秒。
// Worker commandが許可する最大root応答byte数。
constexpr std::uint64_t RECORD_LIMIT_BYTES = 4ULL * 1'024ULL * 1'024ULL ;
constexpr NativeError	TEST_FAILURE	   = static_cast<NativeError>( E_FAIL) ;	// 架空resolver失敗。

//------------------------------------------------------------------------------
// Fixture生成関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Intel固定landingからnetwork取得した架空source evidenceを作ります。
 * @param[in] session 結合するscan session ID。
 * @param[in] acquisitionId Root取得の0ではない連番。
 * @return 組み込みpolicyへ一致するURL非保持evidence。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialSourceEvidence makeRootEvidence( const ScanSessionId session,
													  const std::uint64_t acquisitionId)
{
	return OfficialSourceEvidence{
		.scanSessionId			= session,
		.acquisitionId			= acquisitionId,
		.providerId				= std::wstring{INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID},
		.policyId				= std::wstring{INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID},
		.resourceId				= std::wstring{OFFICIAL_LANDING_RESOURCE_ID},
		.redirectCount			= 0U,
		.originPolicyIndices	= {0U},
		.acquisition			= MeasurementAcquisition::NETWORK_BODY,
		.bodyAcquiredUtcSeconds = ROOT_BODY_UTC,
		.originValidatedUtcSeconds = ROOT_VALIDATED_UTC,
		.cachePermitted			   = false} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つの架空driver archive payload行を作ります。
 * @param[in] ordinal Record内の0起点順序。
 * @param[in] targetUrl Worker内だけで所有する架空完全URL。
 * @param[in] externalExpiryUtcSeconds 認識済み短命URLのexpiry。通常URLは未指定です。
 * @return 有限上限と公開hashを持つpayload行。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialDistributionPayloadRecord makePayload(
	const std::uint32_t ordinal, std::wstring targetUrl,
	const std::optional<std::uint64_t> externalExpiryUtcSeconds = std::nullopt)
{
	return OfficialDistributionPayloadRecord{
		.resourceId		= std::wstring{OFFICIAL_PAYLOAD_RESOURCE_ID},
		.payloadOrdinal = ordinal,
		.kind			= OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE,
		.fileDisplayName =
			ordinal == 0U ? L"fictional-driver.zip" : L"fictional-driver-secondary.zip",
		.publishedSizeBytes		  = 2'048U,
		.publishedSha256		  = std::wstring( 64U, L'a'),
		.publisher				  = L"Fictional Device Vendor",
		.expectedContentType	  = L"application/zip",
		.maximumBytes			  = 4'096U,
		.externalExpiryUtcSeconds = externalExpiryUtcSeconds,
		.targetUrl				  = SecretOfficialUrl{std::move( targetUrl)}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのpayloadを持つ有効な架空distribution recordを作ります。
 * @param[in] session 結合するscan session ID。
 * @param[in] recordEvidenceId Session内のrecord証拠ID。
 * @param[in] targetUrl Payloadの架空完全URL。
 * @param[in] externalExpiryUtcSeconds 認識済み外部expiry。通常URLは未指定です。
 * @return Intel組み込みrootへ結合できる型付きrecord。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialDistributionRecord makeRecord(
	const ScanSessionId session, const std::uint64_t recordEvidenceId, std::wstring targetUrl,
	const std::optional<std::uint64_t> externalExpiryUtcSeconds = std::nullopt)
{
	OfficialDistributionRecord record ;	// 全stable fieldを設定する結果。
	record.rootEvidence		= makeRootEvidence( session, recordEvidenceId + 100U) ;
	record.recordEvidenceId = recordEvidenceId ;
	record.parserId			= L"fixture-parser-v1" ;
	record.parserRevision	= 1U ;
	record.recordRoute		= L"fixture-record-route" ;
	record.recordKey		= L"fixture-record-001" ;
	record.productFamily	= L"Fictional Ethernet Family" ;
	record.operatingSystem	= L"Windows 11 x64" ;
	record.architecture		= OfficialDistributionArchitecture::WINDOWS_X64 ;
	record.packageVersion	= L"31.2.2" ;
	record.publishedDate	= L"2026-08-01" ;
	record.terms			= OfficialDistributionTerms::CONFIRMED_NO_CONSENT ;
	record.dependencies		= {L"base-driver"} ;
	record.payloads.push_back( makePayload( 0U, std::move( targetUrl), externalExpiryUtcSeconds)) ;
	record.resolvedUtcSeconds = RECORD_RESOLVED_UTC ;
	return record ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常証跡を持たない架空収集候補を作ります。
 * @return 同じ公式fieldを持つworker内限定候補。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialCollectorRecordCandidate makeCollectorCandidate()
{
	OfficialCollectorRecordCandidate candidate ;	// 通常evidenceなしの収集入力。
	candidate.recordEvidenceId = 1U ;
	candidate.parserId		   = L"fixture-parser-v1" ;
	candidate.parserRevision   = 1U ;
	candidate.recordRoute	   = L"fixture-record-route" ;
	candidate.recordKey		   = L"fixture-record-001" ;
	candidate.productFamily	   = L"Fictional Ethernet Family" ;
	candidate.operatingSystem  = L"Windows 11 x64" ;
	candidate.architecture	   = OfficialDistributionArchitecture::WINDOWS_X64 ;
	candidate.packageVersion   = L"31.2.2" ;
	candidate.publishedDate	   = L"2026-08-01" ;
	candidate.terms			   = OfficialDistributionTerms::CONFIRMED_NO_CONSENT ;
	candidate.dependencies	   = {L"base-driver"} ;
	candidate.payloads.push_back(
		makePayload( 0U, L"https://cdn-a.fixture.invalid/driver.zip?token=alpha")) ;
	candidate.resolvedUtcSeconds = RECORD_RESOLVED_UTC ;
	return candidate ;
}

//------------------------------------------------------------------------------
/**
 * @brief Root resolution sessionへ渡す一回の架空commandを作ります。
 * @param[in] operationId Applicationの単調operation ID。
 * @param[in] session Scan session ID。
 * @param[in] submittedUrl 直接取得してはならない架空入力URL。
 * @return Intel固定landingを明示した有限command。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialRecordResolutionCommand makeCommand( const OperationId	  operationId,
														  const ScanSessionId session,
														  std::wstring		  submittedUrl)
{
	return OfficialRecordResolutionCommand{
		.operationId		= operationId,
		.scanSessionId		= session,
		.providerId			= std::wstring{INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID},
		.rootResourceId		= std::wstring{OFFICIAL_LANDING_RESOURCE_ID},
		.maximumRecordBytes = 1'024U,
		.submittedUrl		= SecretOfficialUrl{std::move( submittedUrl)}} ;
}

//------------------------------------------------------------------------------
// Record fingerprint試験。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief URL／expiryを除外し、stable field変更だけを識別するfingerprintを検証します。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testStableRecordFingerprint( TestContext &context)
{
	// 完全URLとexpiryを除く比較元record。
	OfficialDistributionRecord baseline =
		makeRecord( SESSION_ID, 1U, L"https://cdn-a.fixture.invalid/driver.zip?token=alpha") ;
	OfficialDistributionRecordEvidence baselineEvidence ;	// 基準recordの検証結果。
	DRIVERCRATE_EXPECT( context,
					   validateOfficialDistributionRecord( baseline, baselineEvidence) == 0) ;
	const bool baselineIsNonZero =
		std::any_of( baselineEvidence.stableFingerprint.bytes.begin(),
					baselineEvidence.stableFingerprint.bytes.end(), []( const std::byte value) {
						return value != std::byte{} ;
					}) ; // SHA-256設定確認。
	DRIVERCRATE_EXPECT( context, baselineIsNonZero) ;
	OfficialDistributionRecordEvidence edgeEvidence ;	// 表記だけの境界値。Record検証済みとはしない。
	edgeEvidence.stableFingerprint.bytes.fill( std::byte{0}) ;
	DRIVERCRATE_EXPECT( context, officialRecordFingerprint( edgeEvidence) == std::string( 64U, '0')) ;
	edgeEvidence.stableFingerprint.bytes.fill( std::byte{0xff}) ;
	DRIVERCRATE_EXPECT( context, officialRecordFingerprint( edgeEvidence) == std::string( 64U, 'f')) ;
	DRIVERCRATE_EXPECT( context,
					   officialRecordFingerprint( baselineEvidence) ==
						   "3f2092958c2d04fe8bd1e14a1db4724e95fc31cd93b93dbb7590b52afc7e4a19") ;
	DRIVERCRATE_EXPECT( context, baselineEvidence.rootEvidence.scanSessionId == SESSION_ID) ;
	DRIVERCRATE_EXPECT( context, baselineEvidence.recordEvidenceId == 1U) ;
	DRIVERCRATE_EXPECT( context, baselineEvidence.payloadCount == 1U) ;

	// URLとexpiryだけを更新したrecord。
	OfficialDistributionRecord refreshed =
		makeRecord( SESSION_ID, 2U, L"https://cdn-b.fixture.invalid/driver.zip?token=beta", 20'000U) ;
	OfficialDistributionRecordEvidence refreshedEvidence ;	// URL／expiryだけを変更した結果。
	DRIVERCRATE_EXPECT( context,
					   validateOfficialDistributionRecord( refreshed, refreshedEvidence) == 0) ;
	DRIVERCRATE_EXPECT( context, baselineEvidence.stableFingerprint.bytes ==
									refreshedEvidence.stableFingerprint.bytes) ;

	// 同じhashを大文字hexで保持するrecord。
	OfficialDistributionRecord uppercaseHash =
		makeRecord( SESSION_ID, 3U, L"https://cdn-c.fixture.invalid/driver.zip") ;
	uppercaseHash.payloads[0].publishedSha256 = std::wstring( 64U, L'A') ;
	OfficialDistributionRecordEvidence uppercaseEvidence ;	// Hex表記だけを変えた結果。
	DRIVERCRATE_EXPECT( context,
					   validateOfficialDistributionRecord( uppercaseHash, uppercaseEvidence) == 0) ;
	DRIVERCRATE_EXPECT( context, baselineEvidence.stableFingerprint.bytes ==
									uppercaseEvidence.stableFingerprint.bytes) ;

	// Stableフィールドのversionを変更したrecord。
	OfficialDistributionRecord changedVersion =
		makeRecord( SESSION_ID, 4U, L"https://cdn-d.fixture.invalid/driver.zip") ;
	changedVersion.packageVersion = L"31.2.3" ;
	OfficialDistributionRecordEvidence changedVersionEvidence ;	// Stable版を変更した結果。
	DRIVERCRATE_EXPECT(
		context, validateOfficialDistributionRecord( changedVersion, changedVersionEvidence) == 0) ;
	DRIVERCRATE_EXPECT( context, baselineEvidence.stableFingerprint.bytes !=
									changedVersionEvidence.stableFingerprint.bytes) ;

	// Stableフィールドのfile表示名を変更したrecord。
	OfficialDistributionRecord changedFile =
		makeRecord( SESSION_ID, 5U, L"https://cdn-e.fixture.invalid/driver.zip") ;
	changedFile.payloads[0].fileDisplayName = L"changed-driver.zip" ;
	OfficialDistributionRecordEvidence changedFileEvidence ;	// Stable file表示名を変更した結果。
	DRIVERCRATE_EXPECT( context,
					   validateOfficialDistributionRecord( changedFile, changedFileEvidence) == 0) ;
	DRIVERCRATE_EXPECT( context, baselineEvidence.stableFingerprint.bytes !=
									changedFileEvidence.stableFingerprint.bytes) ;

	// Stableフィールドのdriver分類を変更したrecord。
	OfficialDistributionRecord changedCategory =
		makeRecord( SESSION_ID, 6U, L"https://cdn-f.fixture.invalid/driver.zip") ;
	changedCategory.driverCategory = L"LAN" ;
	OfficialDistributionRecordEvidence changedCategoryEvidence ;	// Stable分類を追加した結果。
	DRIVERCRATE_EXPECT(
		context, validateOfficialDistributionRecord( changedCategory, changedCategoryEvidence) == 0) ;
	DRIVERCRATE_EXPECT( context, baselineEvidence.stableFingerprint.bytes !=
									changedCategoryEvidence.stableFingerprint.bytes) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 収集専用の公開値拒否とUTF-8上限、field別slash文法を確認します。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testCollectorPublicBoundary( TestContext &context)
{
	const std::array<std::wstring, 7U> invalid{L"Public\x7f", L"Public\x85", L"VEN_1234",
											   L"vid_1234", L"folder/file", L"token=fictional",
											   // 合成の非公開形状。
											   std::wstring( 1U, static_cast<wchar_t>( 0xd800))} ;
	// 収集専用公開検証の境界を個別の改変で確認します。
	for( const auto &value : invalid) {
		auto candidate			= makeCollectorCandidate() ;	// 各回独立のworker候補。
		candidate.productFamily = value ;
		OfficialCollectorRecordProjection projected ;	// 拒否後は初期値。
		DRIVERCRATE_EXPECT( context,
						   projectOfficialCollectorRecord(
							   candidate, INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID,
							   OFFICIAL_LANDING_RESOURCE_ID, ROOT_VALIDATED_UTC, projected) != 0) ;
		DRIVERCRATE_EXPECT( context, projected.payloads.empty() && projected.productFamily.empty()) ;
	}

	// C0／DEL／C1の全code pointを普通の表示名に挿入して拒否します。
	for( wchar_t ch = 0; ch <= 0x9f; ++ch) {
		// 通常のASCII表示文字はこの拒否集合に含めません。
		if( ch >= 0x20 && ch < 0x7f) {
			continue ;
		}

		DRIVERCRATE_EXPECT( context,
						   !isOfficialCollectorPublicText( std::wstring{L"Public"} + ch, 1'024U)) ;
	}

	// UTF-8 byte境界と完全なsurrogate対だけを認めます。
	DRIVERCRATE_EXPECT( context, isOfficialCollectorPublicText( std::wstring( 341U, L'字'), 1'024U)) ;
	DRIVERCRATE_EXPECT( context, !isOfficialCollectorPublicText( std::wstring( 342U, L'字'), 1'024U)) ;
	DRIVERCRATE_EXPECT( context, isOfficialCollectorPublicText( L"\U0001f600", 4U)) ;
	DRIVERCRATE_EXPECT( context, !isOfficialCollectorPublicText( L"\U0001f600", 3U)) ;
	DRIVERCRATE_EXPECT( context, !isOfficialCollectorPublicText( std::wstring( 1U, 0xdc00), 32U)) ;
	DRIVERCRATE_EXPECT( context, isOfficialCollectorPublicText( L"Public & Adapter®", 256U)) ;
	DRIVERCRATE_EXPECT( context, isOfficialCollectorPublicText(
									L"2025/12/31", 32U, OfficialCollectorPublicTextKind::DATE)) ;
	DRIVERCRATE_EXPECT( context, !isOfficialCollectorPublicText(
									L"folder/file", 32U, OfficialCollectorPublicTextKind::DATE)) ;
	DRIVERCRATE_EXPECT(
		context, isOfficialCollectorPublicText( L"application/zip", 32U,
											   OfficialCollectorPublicTextKind::CONTENT_TYPE)) ;
	DRIVERCRATE_EXPECT( context, !isOfficialCollectorPublicText(
									L"a/b/c", 32U, OfficialCollectorPublicTextKind::CONTENT_TYPE)) ;
	DRIVERCRATE_EXPECT( context, !isOfficialCollectorPublicText( L"application/zip", 32U)) ;
	DRIVERCRATE_EXPECT(
		context, !isOfficialCollectorPublicText( L"../file", 32U,
												OfficialCollectorPublicTextKind::CONTENT_TYPE)) ;
	DRIVERCRATE_EXPECT( context, !isOfficialCollectorPublicText(
									L"a/..", 32U, OfficialCollectorPublicTextKind::CONTENT_TYPE)) ;
}

/** @brief 通常recordと収集候補の射影を検証します。
 * @param[in,out] context Assertion集計先。
 */
void testCollectorRecordProjection( TestContext &context)
{
	OfficialDistributionRecord ordinary = makeRecord(
		SESSION_ID, 1U, L"https://cdn-a.fixture.invalid/driver.zip?token=alpha") ;	// 比較元。
	OfficialDistributionRecordEvidence evidence ;									// 通常経路だけが発行できる証拠。
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( ordinary, evidence) == 0) ;

	OfficialCollectorRecordCandidate  candidate = makeCollectorCandidate() ;	// 同じstable field。
	OfficialCollectorRecordProjection projected ;								// URL・EULA本文なしの結果。
	DRIVERCRATE_EXPECT( context,
					   projectOfficialCollectorRecord(
						   candidate, INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID,
						   OFFICIAL_LANDING_RESOURCE_ID, ROOT_VALIDATED_UTC, projected) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   projected.stableFingerprint.bytes == evidence.stableFingerprint.bytes) ;
	DRIVERCRATE_EXPECT( context, projected.payloads.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, projected.payloads[0].fileDisplayName == L"fictional-driver.zip") ;
	DRIVERCRATE_EXPECT( context, projected.recordKey == L"fixture-record-001") ;
	const bool cannotBecomeOrdinaryEvidence = !std::is_convertible_v<
		OfficialCollectorRecordProjection,
		OfficialDistributionRecordEvidence> ;	// Grant証跡へ変換できない型関係。
	DRIVERCRATE_EXPECT( context, cannotBecomeOrdinaryEvidence) ;

	// Probeの成功通知は実SHA-256を省略できず、失敗だけが空出力を返します。
	for( unsigned mode = 0U; mode < 3U; ++mode) {
		std::size_t						 calls{} ;	// 同じcanonicalに対する再hashを検出する。
		const OfficialCollectorHashProbe probe = [&]() -> std::int32_t {
			++calls ;
			return mode == 2U ? static_cast<std::int32_t>( 0xc0000022U)
							  : static_cast<std::int32_t>( mode) ;
		} ; // 正常・成功通知・元NTSTATUS失敗の有限三条件。
		const auto error = projectOfficialCollectorRecordWithHashProbe(
			candidate, INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID,
			OFFICIAL_LANDING_RESOURCE_ID, ROOT_VALIDATED_UTC, projected, probe) ;	// 元検証。
		DRIVERCRATE_EXPECT( context, calls == 1U) ;
		// CNG原失敗の変換後は前回の成功配列とdigestを残しません。
		if( mode == 2U) {
			DRIVERCRATE_EXPECT( context, error == static_cast<NativeError>( 0xd0000022U) &&
											projected.payloads.empty() &&
											projected.recordKey.empty() &&
											std::ranges::all_of( projected.stableFingerprint.bytes,
																[]( const std::byte value) {
																	return value == std::byte{} ;
																})) ;
		} else {
			DRIVERCRATE_EXPECT( context, error == 0 && projected.stableFingerprint.bytes ==
														  evidence.stableFingerprint.bytes) ;
		}
	}

	// EULA本文は指紋へ含めるが、収集結果型にはrevisionだけを残す。
	ordinary.terms		   = OfficialDistributionTerms::ACCEPTANCE_REQUIRED ;
	ordinary.eulaRevision  = L"fictional-eula-v1" ;
	ordinary.eulaText	   = L"Fictional private license body" ;
	candidate.terms		   = ordinary.terms ;
	candidate.eulaRevision = ordinary.eulaRevision ;
	candidate.eulaText	   = ordinary.eulaText ;
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( ordinary, evidence) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   projectOfficialCollectorRecord(
						   candidate, INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID,
						   OFFICIAL_LANDING_RESOURCE_ID, ROOT_VALIDATED_UTC, projected) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   projected.stableFingerprint.bytes == evidence.stableFingerprint.bytes) ;
	DRIVERCRATE_EXPECT( context, projected.eulaRevision == L"fictional-eula-v1") ;

	// 不正なpolicy、起点用途、起点時刻は証拠を合成せず全て拒否する。
	DRIVERCRATE_EXPECT( context, projectOfficialCollectorRecord( candidate, L"unknown-policy",
															   OFFICIAL_LANDING_RESOURCE_ID,
															   ROOT_VALIDATED_UTC, projected) != 0) ;
	DRIVERCRATE_EXPECT( context, projected.payloads.empty()) ;
	DRIVERCRATE_EXPECT( context,
					   projectOfficialCollectorRecord(
						   candidate, INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID,
						   OFFICIAL_PAYLOAD_RESOURCE_ID, ROOT_VALIDATED_UTC, projected) != 0) ;
	DRIVERCRATE_EXPECT( context,
					   projectOfficialCollectorRecord(
						   candidate, INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID,
						   OFFICIAL_LANDING_RESOURCE_ID, RECORD_RESOLVED_UTC + 1U, projected) != 0) ;

	// Worker候補のURL形状公開keyとUTF-8 byte上限超過は射影に入れない。
	candidate.recordKey = L"https://example.invalid/secret?token=a" ;
	DRIVERCRATE_EXPECT( context,
					   projectOfficialCollectorRecord(
						   candidate, INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID,
						   OFFICIAL_LANDING_RESOURCE_ID, ROOT_VALIDATED_UTC, projected) != 0) ;
	candidate.recordKey = std::wstring( 257U, L'x') ;
	DRIVERCRATE_EXPECT( context,
					   projectOfficialCollectorRecord(
						   candidate, INTEL_ETHERNET_WINDOWS11_OFFICIAL_SOURCE_POLICY_ID,
						   OFFICIAL_LANDING_RESOURCE_ID, ROOT_VALIDATED_UTC, projected) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不正root、field、payload、重複、上限をrecord全体でfail-closedにすることを検証します。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testRecordRejections( TestContext &context)
{
	OfficialDistributionRecordEvidence evidence ;	// 各拒否で既定値へ戻る出力。
	// Cacheをofficial rootとする不正record。
	OfficialDistributionRecord		   cached =
		makeRecord( SESSION_ID, 10U, L"https://cdn.fixture.invalid/cached.zip") ;
	cached.rootEvidence.acquisition = MeasurementAcquisition::FRESH_CACHE ;
	cached.rootEvidence.bodyAcquiredUtcSeconds.reset() ;
	cached.rootEvidence.cachePermitted = true ;
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( cached, evidence) != 0) ;
	DRIVERCRATE_EXPECT( context, evidence.recordEvidenceId == 0U) ;

	// Payloadを1件も含まない不正record。
	OfficialDistributionRecord noPayload =
		makeRecord( SESSION_ID, 11U, L"https://cdn.fixture.invalid/empty.zip") ;
	noPayload.payloads.clear() ;
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( noPayload, evidence) != 0) ;

	// SHA-256形式を満たさない不正record。
	OfficialDistributionRecord badHash =
		makeRecord( SESSION_ID, 12U, L"https://cdn.fixture.invalid/hash.zip") ;
	badHash.payloads[0].publishedSha256 = L"not-a-sha256" ;
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( badHash, evidence) != 0) ;

	// 取得予算から独立したarchive表現上限とinstaller旧上限の境界record。
	OfficialDistributionRecord excessivePayload =
		makeRecord( SESSION_ID, 13U, L"https://cdn.fixture.invalid/large.zip") ;
	excessivePayload.payloads[0].maximumBytes = 512ULL * 1'024ULL * 1'024ULL + 1U ;
	DRIVERCRATE_EXPECT( context,
					   validateOfficialDistributionRecord( excessivePayload, evidence) != 0) ;
	--excessivePayload.payloads[0].maximumBytes ;
	DRIVERCRATE_EXPECT( context,
					   validateOfficialDistributionRecord( excessivePayload, evidence) == 0) ;
	excessivePayload.payloads[0].kind		  = OfficialDistributionPayloadKind::OFFICIAL_INSTALLER ;
	excessivePayload.payloads[0].maximumBytes = 128ULL * 1024ULL * 1024ULL + 1U ;
	DRIVERCRATE_EXPECT( context,
					   validateOfficialDistributionRecord( excessivePayload, evidence) != 0) ;
	--excessivePayload.payloads[0].maximumBytes ;
	DRIVERCRATE_EXPECT( context,
					   validateOfficialDistributionRecord( excessivePayload, evidence) == 0) ;

	// File表示名にpath要素を含む不正record。
	OfficialDistributionRecord pathName =
		makeRecord( SESSION_ID, 14U, L"https://cdn.fixture.invalid/path.zip") ;
	pathName.payloads[0].fileDisplayName = L"folder\\driver.zip" ;
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( pathName, evidence) != 0) ;

	// 同意必要だがEULA識別子がない不正record。
	OfficialDistributionRecord missingEula =
		makeRecord( SESSION_ID, 15U, L"https://cdn.fixture.invalid/eula.zip") ;
	missingEula.terms = OfficialDistributionTerms::ACCEPTANCE_REQUIRED ;
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( missingEula, evidence) != 0) ;

	// 同じfile表示名を複数payloadで使う不正record。
	OfficialDistributionRecord duplicate =
		makeRecord( SESSION_ID, 16U, L"https://cdn.fixture.invalid/one.zip") ;
	// 表示名重複を作る2番目payload。
	OfficialDistributionPayloadRecord duplicatePayload =
		makePayload( 1U, L"https://cdn.fixture.invalid/two.zip") ;
	duplicatePayload.fileDisplayName = duplicate.payloads[0].fileDisplayName ;
	duplicate.payloads.push_back( std::move( duplicatePayload)) ;
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( duplicate, evidence) != 0) ;

	// 同じ秘密URLを複数payloadで使う不正record。
	OfficialDistributionRecord duplicateTarget =
		makeRecord( SESSION_ID, 17U, L"https://cdn.fixture.invalid/shared.zip") ;
	duplicateTarget.payloads.push_back( makePayload( 1U, L"https://cdn.fixture.invalid/shared.zip")) ;
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( duplicateTarget, evidence) != 0) ;

	// 既知だが未対応の配布形式を明示したrecord。
	OfficialDistributionRecord unsupported =
		makeRecord( SESSION_ID, 18U, L"https://cdn.fixture.invalid/unknown.bin") ;
	unsupported.payloads[0].kind				= OfficialDistributionPayloadKind::UNSUPPORTED ;
	unsupported.payloads[0].fileDisplayName		= L"unknown.bin" ;
	unsupported.payloads[0].expectedContentType = L"application/octet-stream" ;
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( unsupported, evidence) == 0) ;
}

//------------------------------------------------------------------------------
// Grant状態試験。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Grantの発行、claim、成功終端、一回使用とmove所有を検証します。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testGrantSuccessAndMove( TestContext &context)
{
	static_assert( !std::is_copy_constructible_v<SecretOfficialUrl>) ;
	static_assert( !std::is_copy_assignable_v<SecretOfficialUrl>) ;
	static_assert( std::is_nothrow_move_constructible_v<SecretOfficialUrl>) ;
	static_assert( !std::is_copy_constructible_v<RecordScopedDownloadGrant>) ;
	static_assert( std::is_nothrow_move_constructible_v<RecordScopedDownloadGrant>) ;
	static_assert( !std::is_copy_constructible_v<OfficialRecordResolutionCommand>) ;

	// 発行から成功終端まで使う正常record。
	OfficialDistributionRecord record =
		makeRecord( SESSION_ID, 20U, L"https://temporary.fixture.invalid/driver.zip?token=secret") ;
	OfficialDistributionRecordEvidence evidence ;	// Grant発行元のrecord証拠。
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( record, evidence) == 0) ;

	RecordScopedDownloadGrant grant ;	// 未発行から開始するgrant。
	DRIVERCRATE_EXPECT( context, grant.issue( record, evidence, 0U, 90U, 20'000U, 0U) == 0) ;
	DRIVERCRATE_EXPECT( context, record.payloads[0].targetUrl.empty()) ;
	DRIVERCRATE_EXPECT( context, grant.metadata().state == OfficialDownloadGrantState::GRANT_ISSUED) ;
	DRIVERCRATE_EXPECT( context,
					   grant.metadata().outcome == OfficialDownloadGrantState::NOT_REQUESTED) ;
	DRIVERCRATE_EXPECT( context, grant.metadata().expiresUtcSeconds == 20'900U) ;
	DRIVERCRATE_EXPECT( context, !grant.metadata().externalExpiryPresent) ;
	DRIVERCRATE_EXPECT( context, grant.metadata().maximumBytes == 4'096U) ;
	DRIVERCRATE_EXPECT( context, grant.payloadView().targetUrl.empty()) ;

	const std::wstring publicMetadata = grant.metadata().providerId + grant.metadata().policyId +
										// UIへ渡せる文字列field集合。
										grant.metadata().rootResourceId ;
	DRIVERCRATE_EXPECT( context,
					   publicMetadata.find( L"temporary.fixture.invalid") == std::wstring::npos) ;
	DRIVERCRATE_EXPECT( context, publicMetadata.find( L"secret") == std::wstring::npos) ;

	RecordScopedDownloadGrant moved( std::move( grant)) ;	// 秘密URL所有権を引き取るgrant。
	DRIVERCRATE_EXPECT( context,
					   grant.metadata().state == OfficialDownloadGrantState::NOT_REQUESTED) ;
	DRIVERCRATE_EXPECT( context, moved.metadata().state == OfficialDownloadGrantState::GRANT_ISSUED) ;
	DRIVERCRATE_EXPECT( context, moved.claim( SESSION_ID, 90U, 20'100U) == 0) ;
	DRIVERCRATE_EXPECT( context, moved.payloadView().targetUrl ==
									L"https://temporary.fixture.invalid/driver.zip?token=secret") ;
	DRIVERCRATE_EXPECT( context, moved.finishAcquisition(
									OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION, 0) == 0) ;
	DRIVERCRATE_EXPECT( context, moved.metadata().state == OfficialDownloadGrantState::CONSUMED) ;
	DRIVERCRATE_EXPECT( context, moved.metadata().outcome ==
									OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION) ;
	DRIVERCRATE_EXPECT( context, moved.payloadView().targetUrl.empty()) ;
	DRIVERCRATE_EXPECT( context, moved.claim( SESSION_ID, 90U, 20'200U) != 0) ;
	DRIVERCRATE_EXPECT( context, moved.finishAcquisition(
									OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION, 0) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Grantの外部expiry、30秒余裕、拒否・失敗終端を検証します。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testGrantExpiryAndFailures( TestContext &context)
{
	// 内部期限より短い外部expiryの正常record。
	OfficialDistributionRecord expiring = makeRecord(
		SESSION_ID, 21U, L"https://temporary.fixture.invalid/expiring.zip?sig=one", 30'045U) ;
	OfficialDistributionRecordEvidence expiringEvidence ;	// 外部expiry付きrecord証拠。
	DRIVERCRATE_EXPECT( context,
					   validateOfficialDistributionRecord( expiring, expiringEvidence) == 0) ;
	RecordScopedDownloadGrant expiringGrant ;	// 外部expiryを短い期限へ反映するgrant。
	DRIVERCRATE_EXPECT( context,
					   expiringGrant.issue( expiring, expiringEvidence, 0U, 91U, 30'000U, 1U) == 0) ;
	DRIVERCRATE_EXPECT( context, expiringGrant.metadata().expiresUtcSeconds == 30'045U) ;
	DRIVERCRATE_EXPECT( context, expiringGrant.metadata().externalExpiryPresent) ;
	DRIVERCRATE_EXPECT( context, expiringGrant.metadata().reresolutionCount == 1U) ;
	DRIVERCRATE_EXPECT( context, expiringGrant.claim( SESSION_ID, 91U, 30'015U) == 0) ;
	DRIVERCRATE_EXPECT( context, expiringGrant.validateRequestStartDeadline( 30'015U) == 0) ;
	DRIVERCRATE_EXPECT( context, expiringGrant.validateRequestStartDeadline( 30'016U) != 0) ;
	DRIVERCRATE_EXPECT( context, expiringGrant.finishAcquisition( OfficialDownloadGrantState::FAILED,
																TEST_FAILURE) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   expiringGrant.metadata().outcome == OfficialDownloadGrantState::FAILED) ;
	DRIVERCRATE_EXPECT( context, expiringGrant.metadata().error == TEST_FAILURE) ;

	// 発行時の30秒安全余裕を満たさないrecord。
	OfficialDistributionRecord tooShort = makeRecord(
		SESSION_ID, 22U, L"https://temporary.fixture.invalid/short.zip?sig=two", 40'029U) ;
	OfficialDistributionRecordEvidence tooShortEvidence ;	// 安全余裕不足record証拠。
	DRIVERCRATE_EXPECT( context,
					   validateOfficialDistributionRecord( tooShort, tooShortEvidence) == 0) ;
	RecordScopedDownloadGrant rejectedIssue ;	// 発行失敗後も未発行を維持するgrant。
	DRIVERCRATE_EXPECT( context,
					   rejectedIssue.issue( tooShort, tooShortEvidence, 0U, 92U, 40'000U, 0U) != 0) ;
	DRIVERCRATE_EXPECT( context, !tooShort.payloads[0].targetUrl.empty()) ;
	DRIVERCRATE_EXPECT( context,
					   rejectedIssue.metadata().state == OfficialDownloadGrantState::NOT_REQUESTED) ;

	// Claim時に内部期限が切れているrecord。
	OfficialDistributionRecord expiresBeforeClaim =
		makeRecord( SESSION_ID, 23U, L"https://temporary.fixture.invalid/deadline.zip") ;
	OfficialDistributionRecordEvidence deadlineEvidence ;	// 内部15分期限のrecord証拠。
	DRIVERCRATE_EXPECT(
		context, validateOfficialDistributionRecord( expiresBeforeClaim, deadlineEvidence) == 0) ;
	RecordScopedDownloadGrant expiredGrant ;	// Claim時に消費される期限切れgrant。
	DRIVERCRATE_EXPECT( context, expiredGrant.issue( expiresBeforeClaim, deadlineEvidence, 0U, 93U,
												   50'000U, 0U) == 0) ;
	DRIVERCRATE_EXPECT( context, expiredGrant.claim( SESSION_ID, 93U, 50'871U) != 0) ;
	DRIVERCRATE_EXPECT( context,
					   expiredGrant.metadata().state == OfficialDownloadGrantState::CONSUMED) ;
	DRIVERCRATE_EXPECT( context, expiredGrant.metadata().outcome ==
									OfficialDownloadGrantState::GRANT_EXPIRED) ;
	DRIVERCRATE_EXPECT( context, expiredGrant.payloadView().targetUrl.empty()) ;

	// HTTP取得前のtarget検査で拒否するrecord。
	OfficialDistributionRecord preflight =
		makeRecord( SESSION_ID, 24U, L"https://temporary.fixture.invalid/rejected.zip") ;
	OfficialDistributionRecordEvidence preflightEvidence ;	// 宛先拒否用record証拠。
	DRIVERCRATE_EXPECT( context,
					   validateOfficialDistributionRecord( preflight, preflightEvidence) == 0) ;
	RecordScopedDownloadGrant preflightGrant ;	// Claim前にtarget拒否へ進めるgrant。
	DRIVERCRATE_EXPECT(
		context, preflightGrant.issue( preflight, preflightEvidence, 0U, 94U, 60'000U, 0U) == 0) ;
	DRIVERCRATE_EXPECT( context, preflightGrant.finishBeforeAcquisition(
									OfficialDownloadGrantState::TARGET_REJECTED,
									static_cast<NativeError>( E_ACCESSDENIED)) == 0) ;
	DRIVERCRATE_EXPECT( context, preflightGrant.metadata().outcome ==
									OfficialDownloadGrantState::TARGET_REJECTED) ;
	DRIVERCRATE_EXPECT( context, preflightGrant.payloadView().targetUrl.empty()) ;

	// Grantへ昇格できない未対応形式record。
	OfficialDistributionRecord unsupported =
		makeRecord( SESSION_ID, 25U, L"https://temporary.fixture.invalid/unsupported.bin") ;
	unsupported.payloads[0].kind				= OfficialDistributionPayloadKind::UNSUPPORTED ;
	unsupported.payloads[0].fileDisplayName		= L"unsupported.bin" ;
	unsupported.payloads[0].expectedContentType = L"application/octet-stream" ;
	OfficialDistributionRecordEvidence unsupportedEvidence ;	// 明示未対応record証拠。
	DRIVERCRATE_EXPECT( context,
					   validateOfficialDistributionRecord( unsupported, unsupportedEvidence) == 0) ;
	RecordScopedDownloadGrant unsupportedGrant ;	// 未対応方式を取得へ昇格させないgrant。
	DRIVERCRATE_EXPECT( context, unsupportedGrant.issue( unsupported, unsupportedEvidence, 0U, 95U,
													   70'000U, 0U) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief OF05の期限付きURL再解決とOF13のEULA変更拒否を検証します。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testOf05AndOf13GrantReresolution( TestContext &context)
{
	constexpr ScanSessionId refreshSession = 1'100U ;	// 再解決専用のscan session。
	std::uint32_t			resolverCalls{} ;			// 実行した固定root再取得回数。
	bool					cacheBypassed = true ;		// 全呼出しがcache禁止modeならtrue。
	std::wstring			responseTarget =
		L"https://refresh.fixture.invalid/driver.zip?sig=two" ;	// 次に返す秘密URL。
	std::optional<std::uint64_t>	 responseExpiry{201'000U} ;	// 次に返す認識済みexpiry。
	bool							 changeEula{} ;				// EULAを変更する故障注入。
	const OfficialRecordRootResolver resolver =
		[&]( const ScanSessionId session, const std::uint64_t recordEvidenceId, std::wstring_view,
			std::wstring_view, std::wstring_view, std::uint64_t,
			const OfficialRecordFetchMode fetchMode, OfficialDistributionRecord &record) {
			++resolverCalls ;
			cacheBypassed &= fetchMode == OfficialRecordFetchMode::BYPASS_CACHE ;
			record = makeRecord( session, recordEvidenceId, responseTarget, responseExpiry) ;
			// 許諾変更fixtureでは同意不要から新しい全文同意へ切り替える。
			if( changeEula) {
				record.terms		= OfficialDistributionTerms::ACCEPTANCE_REQUIRED ;
				record.eulaRevision = L"fixture-eula-revision-2" ;
				record.eulaText		= L"Fictional replacement terms that require renewed consent." ;
			}

			return static_cast<NativeError>( 0) ;
		} ;
	const std::array				registrations{OfficialRecordResolverRegistration{
					   .providerId	   = INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID,
					   .rootResourceId = OFFICIAL_LANDING_RESOURCE_ID,
					   .resolver	   = resolver}} ;	// 一つの固定root登録。
	OfficialRecordResolutionSession session ;			// 再解決operationを直列化するregistry。
	DRIVERCRATE_EXPECT( context, session.beginSession( refreshSession) == 0) ;

	OfficialDistributionRecord original =
		makeRecord( refreshSession, 31U, L"https://refresh.fixture.invalid/driver.zip?sig=one",
				   200'045U) ;								// 最初の期限付きrecord。
	OfficialDistributionRecordEvidence originalEvidence ;	// 元recordのstable証拠。
	DRIVERCRATE_EXPECT( context,
					   validateOfficialDistributionRecord( original, originalEvidence) == 0) ;
	RecordScopedDownloadGrant expired ;	// Hop開始前に30秒を下回る元grant。
	DRIVERCRATE_EXPECT( context,
					   expired.issue( original, originalEvidence, 0U, 200U, 200'000U, 0U) == 0) ;
	DRIVERCRATE_EXPECT( context, expired.claim( refreshSession, 200U, 200'016U) != 0) ;
	DRIVERCRATE_EXPECT( context,
					   expired.metadata().outcome == OfficialDownloadGrantState::GRANT_EXPIRED) ;

	RecordScopedDownloadGrant			  replacement ;	// URL変更時だけ発行される二つ目のgrant。
	// 非cache rootからURLだけを更新する正常結果。
	const OfficialGrantReresolutionResult refreshed = session.reresolveGrant(
		OfficialGrantReresolutionCommand{.operationId		 = 1U,
										 .scanSessionId		 = refreshSession,
										 .maximumRecordBytes = 1'024U,
										 .replacementGrantId = 201U,
										 .issuedUtcSeconds	 = 200'020U},
		expired, registrations, []() { return false ; }, replacement) ;
	DRIVERCRATE_EXPECT( context, refreshed.state == OfficialGrantReresolutionState::REFRESHED) ;
	DRIVERCRATE_EXPECT( context, refreshed.error == 0 && refreshed.previousGrantId == 200U) ;
	DRIVERCRATE_EXPECT( context, refreshed.replacementGrantId == 201U) ;
	DRIVERCRATE_EXPECT( context,
					   replacement.metadata().state == OfficialDownloadGrantState::GRANT_ISSUED) ;
	DRIVERCRATE_EXPECT( context, replacement.metadata().reresolutionCount == 1U) ;
	DRIVERCRATE_EXPECT( context, replacement.metadata().externalExpiryPresent) ;
	DRIVERCRATE_EXPECT( context, resolverCalls == 1U && cacheBypassed) ;

	DRIVERCRATE_EXPECT( context, replacement.claim( refreshSession, 201U, 200'021U) == 0) ;
	DRIVERCRATE_EXPECT( context, replacement.payloadView().targetUrl ==
									L"https://refresh.fixture.invalid/driver.zip?sig=two") ;
	const NativeError timeout =
		// 二回目拒否用診断。
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT)) ;
	DRIVERCRATE_EXPECT( context, replacement.finishAcquisition(
									OfficialDownloadGrantState::GRANT_EXPIRED, timeout) == 0) ;
	RecordScopedDownloadGrant			  thirdGrant ;	// 再解決回数1のgrantからは発行されない出力。
	// 同じgrant系列の二回目をresolver前に拒否した結果。
	const OfficialGrantReresolutionResult secondAttempt = session.reresolveGrant(
		OfficialGrantReresolutionCommand{.operationId		 = 2U,
										 .scanSessionId		 = refreshSession,
										 .maximumRecordBytes = 1'024U,
										 .replacementGrantId = 202U,
										 .issuedUtcSeconds	 = 200'030U},
		replacement, registrations, []() { return false ; }, thirdGrant) ;
	DRIVERCRATE_EXPECT( context,
					   secondAttempt.state == OfficialGrantReresolutionState::NOT_ELIGIBLE) ;
	DRIVERCRATE_EXPECT( context, resolverCalls == 1U) ;

	OfficialDistributionRecord changedOriginal =
		makeRecord( refreshSession, 32U, L"https://refresh.fixture.invalid/changed.zip?sig=one",
				   300'045U) ;								// Stable変更を試す元record。
	OfficialDistributionRecordEvidence changedEvidence ;	// Stable変更前のfingerprint。
	DRIVERCRATE_EXPECT( context,
					   validateOfficialDistributionRecord( changedOriginal, changedEvidence) == 0) ;
	RecordScopedDownloadGrant changedExpired ;	// 変更record再解決の元grant。
	DRIVERCRATE_EXPECT( context, changedExpired.issue( changedOriginal, changedEvidence, 0U, 203U,
													 300'000U, 0U) == 0) ;
	DRIVERCRATE_EXPECT( context, changedExpired.claim( refreshSession, 203U, 300'016U) != 0) ;
	responseTarget = L"https://refresh.fixture.invalid/changed.zip?sig=two" ;
	responseExpiry = 301'000U ;
	changeEula	   = true ;
	RecordScopedDownloadGrant			  changedOutput ;	// Stable変更時は未発行を維持する出力。
	// Stable package情報の変更をURL更新として扱わず確認へ戻す結果。
	const OfficialGrantReresolutionResult changed = session.reresolveGrant(
		OfficialGrantReresolutionCommand{.operationId		 = 3U,
										 .scanSessionId		 = refreshSession,
										 .maximumRecordBytes = 1'024U,
										 .replacementGrantId = 204U,
										 .issuedUtcSeconds	 = 300'020U},
		changedExpired, registrations, []() { return false ; }, changedOutput) ;
	DRIVERCRATE_EXPECT( context, changed.state == OfficialGrantReresolutionState::RECORD_CHANGED) ;
	DRIVERCRATE_EXPECT( context,
					   changedOutput.metadata().state == OfficialDownloadGrantState::NOT_REQUESTED) ;

	// 許諾を戻し、SHA-512だけが消えた再解決を独立して拒否する。
	changeEula = false ;
	auto hashOriginal =
		makeRecord( refreshSession, 34U, L"https://refresh.fixture.invalid/hash.zip?sig=one",
				   350'045U) ;	// 元record。
	hashOriginal.payloads[0].publishedSha512 = std::wstring( 128U, L'a') ;
	OfficialDistributionRecordEvidence hashEvidence ;	// SHA-512を含む元指紋。
	DRIVERCRATE_EXPECT( context,
					   validateOfficialDistributionRecord( hashOriginal, hashEvidence) == 0) ;
	RecordScopedDownloadGrant hashExpired ;	// 期限切れ後の再解決対象。
	DRIVERCRATE_EXPECT( context,
					   hashExpired.issue( hashOriginal, hashEvidence, 0U, 207U, 350'000U, 0U) == 0) ;
	DRIVERCRATE_EXPECT( context, hashExpired.claim( refreshSession, 207U, 350'016U) != 0) ;
	responseTarget = L"https://refresh.fixture.invalid/hash.zip?sig=two" ;
	responseExpiry = 351'000U ;
	RecordScopedDownloadGrant hashOutput ;	// SHA-512削除時には発行しない。
	const auto				  hashChanged = session.reresolveGrant(
		   OfficialGrantReresolutionCommand{.operationId		= 4U,
														.scanSessionId		= refreshSession,
														.maximumRecordBytes = 1'024U,
														.replacementGrantId = 208U,
														.issuedUtcSeconds	= 350'020U},
		   hashExpired, registrations, []() { return false ; }, hashOutput) ;	// 変更判定結果。
	DRIVERCRATE_EXPECT( context,
					   hashChanged.state == OfficialGrantReresolutionState::RECORD_CHANGED) ;
	DRIVERCRATE_EXPECT( context,
					   hashOutput.metadata().state == OfficialDownloadGrantState::NOT_REQUESTED) ;

	OfficialDistributionRecord sameOriginal =
		makeRecord( refreshSession, 33U, L"https://refresh.fixture.invalid/same.zip?sig=one",
				   400'045U) ;							// 同じURL拒否を試す元record。
	OfficialDistributionRecordEvidence sameEvidence ;	// 同じURL recordのfingerprint。
	DRIVERCRATE_EXPECT( context,
					   validateOfficialDistributionRecord( sameOriginal, sameEvidence) == 0) ;
	RecordScopedDownloadGrant sameExpired ;	// 同じURLへ再発行してはならない元grant。
	DRIVERCRATE_EXPECT( context,
					   sameExpired.issue( sameOriginal, sameEvidence, 0U, 205U, 400'000U, 0U) == 0) ;
	DRIVERCRATE_EXPECT( context, sameExpired.claim( refreshSession, 205U, 400'016U) != 0) ;
	responseTarget = L"https://refresh.fixture.invalid/same.zip?sig=one" ;
	responseExpiry = 401'000U ;
	changeEula	   = false ;
	RecordScopedDownloadGrant			  sameOutput ;	// 同一URL時は未発行を維持する出力。
	// 同じ期限切れURLへの無条件retryを拒否した結果。
	const OfficialGrantReresolutionResult same = session.reresolveGrant(
		OfficialGrantReresolutionCommand{.operationId		 = 5U,
										 .scanSessionId		 = refreshSession,
										 .maximumRecordBytes = 1'024U,
										 .replacementGrantId = 206U,
										 .issuedUtcSeconds	 = 400'020U},
		sameExpired, registrations, []() { return false ; }, sameOutput) ;
	DRIVERCRATE_EXPECT( context, same.state == OfficialGrantReresolutionState::REJECTED) ;
	DRIVERCRATE_EXPECT( context,
					   sameOutput.metadata().state == OfficialDownloadGrantState::NOT_REQUESTED) ;
	DRIVERCRATE_EXPECT( context, resolverCalls == 4U && cacheBypassed) ;
}

//------------------------------------------------------------------------------
// Root routing／session試験。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 未信頼URLを渡さず固定rootだけをresolverへ渡し、一回claimする経路を検証します。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testFixedRootResolution( TestContext &context)
{
	std::uint32_t					 resolverCalls{} ;	// 実際に固定root resolverを呼んだ回数。
	std::wstring					 receivedRoot ;		// Fakeが受け取った組み込みroot URL。
	const OfficialRecordRootResolver resolver =
		[&resolverCalls, &receivedRoot](
			const ScanSessionId session, const std::uint64_t recordEvidenceId,
			const std::wstring_view providerId, const std::wstring_view rootResourceId,
			const std::wstring_view builtInRootUrl, const std::uint64_t maximumRecordBytes,
			const OfficialRecordFetchMode fetchMode, OfficialDistributionRecord &record) {
			++resolverCalls ;
			receivedRoot = builtInRootUrl ;
			// Provider、resource、応答上限が登録値と一致する場合true。
			const bool fixedBinding = providerId == INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID &&
									  rootResourceId == OFFICIAL_LANDING_RESOURCE_ID &&
									  maximumRecordBytes == 1'024U &&
									  fetchMode == OfficialRecordFetchMode::BYPASS_CACHE ;
			// Registryが選択した固定値だけを受けた場合に有効recordを返す。
			if( !fixedBinding) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			record = makeRecord( session, recordEvidenceId,
								L"https://resolved-cdn.fixture.invalid/driver.zip?grant=resolver") ;
			return static_cast<NativeError>( 0) ;
		} ;
	const std::array registrations{OfficialRecordResolverRegistration{
		.providerId		= INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID,
		.rootResourceId = OFFICIAL_LANDING_RESOURCE_ID,
		.resolver		= resolver}} ;	// 一つの固定root登録。
	DRIVERCRATE_EXPECT( context, validateOfficialRecordResolverRegistrations( registrations)) ;

	OfficialRecordResolutionSession session ;	// Worker thread相当の有限registry。
	DRIVERCRATE_EXPECT( context, session.beginSession( 800U) == 0) ;
	// 未信頼入力URLを含むがresolverへ渡さないcommand。
	OfficialRecordResolutionCommand command =
		makeCommand( 1U, 800U, L"https://attacker.fixture.invalid/post?token=do-not-forward") ;
	const OfficialRecordResolutionResult result = session.resolve(
		// 非取消し実行結果。
		std::move( command), registrations, []() { return false ; }) ;
	DRIVERCRATE_EXPECT( context, command.submittedUrl.empty()) ;
	DRIVERCRATE_EXPECT( context, result.state == OfficialRecordResolutionState::RESOLVED) ;
	DRIVERCRATE_EXPECT( context, result.error == 0) ;
	DRIVERCRATE_EXPECT( context, result.recordEvidenceId == 1U) ;
	DRIVERCRATE_EXPECT( context, result.retainedRecordCount == 1U) ;
	DRIVERCRATE_EXPECT( context, resolverCalls == 1U) ;
	DRIVERCRATE_EXPECT( context, receivedRoot == officialMetadataEndpoint(
													INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID,
													OFFICIAL_LANDING_RESOURCE_ID)) ;
	// Resultが所有する全文字列field。
	const std::wstring publicResult = result.providerId + result.rootResourceId ;
	DRIVERCRATE_EXPECT( context,
					   publicResult.find( L"attacker.fixture.invalid") == std::wstring::npos) ;
	DRIVERCRATE_EXPECT( context, publicResult.find( L"do-not-forward") == std::wstring::npos) ;

	ResolvedOfficialDistributionRecord claimed ;	// 一回だけregistryから取り出す秘密record。
	DRIVERCRATE_EXPECT( context,
					   session.claimResolvedRecord( 800U, result.recordEvidenceId, claimed) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   claimed.record.payloads[0].targetUrl.view() ==
						   L"https://resolved-cdn.fixture.invalid/driver.zip?grant=resolver") ;
	DRIVERCRATE_EXPECT( context, session.retainedRecordCount() == 0U) ;
	ResolvedOfficialDistributionRecord duplicateClaim ;	// 再claim拒否の出力。
	DRIVERCRATE_EXPECT(
		context, session.claimResolvedRecord( 800U, result.recordEvidenceId, duplicateClaim) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未知、stale、重複、取消し、例外、record不一致をfail-closedにすることを検証します。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testResolutionRejections( TestContext &context)
{
	std::uint32_t					 resolverCalls{} ;	// 正常resolverを実行した回数。
	// 登録正常経路でrecordを返すfake resolver。
	const OfficialRecordRootResolver resolver =
		[&resolverCalls]( const ScanSessionId session, const std::uint64_t recordEvidenceId,
						 std::wstring_view, std::wstring_view, std::wstring_view, std::uint64_t,
						 OfficialRecordFetchMode, OfficialDistributionRecord &record) {
			++resolverCalls ;
			record = makeRecord( session, recordEvidenceId,
								L"https://resolved.fixture.invalid/driver.zip") ;
			return static_cast<NativeError>( 0) ;
		} ;
	const std::array				registrations{OfficialRecordResolverRegistration{
					   .providerId	   = INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID,
					   .rootResourceId = OFFICIAL_LANDING_RESOURCE_ID,
					   .resolver	   = resolver}} ;	// 正常登録。

	OfficialRecordResolutionSession session ;	// 拒否後も状態を確認するregistry。
	DRIVERCRATE_EXPECT( context, session.beginSession( 900U) == 0) ;
	DRIVERCRATE_EXPECT( context, session.beginSession( 900U) != 0) ;

	// RegistryにないProviderを指すcommand。
	OfficialRecordResolutionCommand unknown =
		makeCommand( 1U, 900U, L"https://unknown.fixture.invalid/path?token=hidden") ;
	unknown.providerId = L"unknown-provider" ;
	// 未知Providerを拒否した公開結果。
	const OfficialRecordResolutionResult unknownResult =
		session.resolve( std::move( unknown), registrations, []() { return false ; }) ;
	DRIVERCRATE_EXPECT( context, unknown.submittedUrl.empty()) ;
	DRIVERCRATE_EXPECT( context, unknownResult.state == OfficialRecordResolutionState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, unknownResult.providerId.empty()) ;
	DRIVERCRATE_EXPECT( context, resolverCalls == 0U) ;

	// Operation連番を進める正常command。
	OfficialRecordResolutionCommand valid =
		makeCommand( 1U, 900U, L"https://search.fixture.invalid/valid") ;
	// 後続のstale claimにも用いる正常結果。
	const OfficialRecordResolutionResult validResult =
		session.resolve( std::move( valid), registrations, []() { return false ; }) ;
	DRIVERCRATE_EXPECT( context, validResult.state == OfficialRecordResolutionState::RESOLVED) ;
	DRIVERCRATE_EXPECT( context, resolverCalls == 1U) ;

	// 使用済みoperation IDを再利用するcommand。
	OfficialRecordResolutionCommand duplicate =
		makeCommand( 1U, 900U, L"https://search.fixture.invalid/duplicate?secret=value") ;
	// 重複operationを拒否した公開結果。
	const OfficialRecordResolutionResult duplicateResult =
		session.resolve( std::move( duplicate), registrations, []() { return false ; }) ;
	DRIVERCRATE_EXPECT( context, duplicate.submittedUrl.empty()) ;
	DRIVERCRATE_EXPECT( context, duplicateResult.state == OfficialRecordResolutionState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, resolverCalls == 1U) ;

	// Active sessionより古いsessionを指すcommand。
	OfficialRecordResolutionCommand stale =
		makeCommand( 2U, 899U, L"https://search.fixture.invalid/stale") ;
	// Stale sessionを拒否した公開結果。
	const OfficialRecordResolutionResult staleResult =
		session.resolve( std::move( stale), registrations, []() { return false ; }) ;
	DRIVERCRATE_EXPECT( context, staleResult.state == OfficialRecordResolutionState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, resolverCalls == 1U) ;

	// Root応答上限を超えるcommand。
	OfficialRecordResolutionCommand oversized =
		makeCommand( 2U, 900U, L"https://search.fixture.invalid/oversized") ;
	oversized.maximumRecordBytes = RECORD_LIMIT_BYTES + 1U ;
	// 応答上限超過を拒否した公開結果。
	const OfficialRecordResolutionResult oversizedResult =
		session.resolve( std::move( oversized), registrations, []() { return false ; }) ;
	DRIVERCRATE_EXPECT( context, oversizedResult.state == OfficialRecordResolutionState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, resolverCalls == 1U) ;

	// Resolver呼出し前に取消すcommand。
	OfficialRecordResolutionCommand cancelled =
		makeCommand( 2U, 900U, L"https://search.fixture.invalid/cancelled") ;
	// Resolverを呼ばず取消した公開結果。
	const OfficialRecordResolutionResult cancelledResult =
		session.resolve( std::move( cancelled), registrations, []() { return true ; }) ;
	DRIVERCRATE_EXPECT( context, cancelledResult.state == OfficialRecordResolutionState::CANCELLED) ;
	DRIVERCRATE_EXPECT( context, resolverCalls == 1U) ;

	// C++例外をworker境界から漏らすfake resolver。
	const OfficialRecordRootResolver throwing =
		[]( ScanSessionId, std::uint64_t, std::wstring_view, std::wstring_view, std::wstring_view,
		   std::uint64_t, OfficialRecordFetchMode,
		   OfficialDistributionRecord &) -> NativeError { throw 7 ; } ;
	const std::array				throwingRegistrations{OfficialRecordResolverRegistration{
					   .providerId	   = INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID,
					   .rootResourceId = OFFICIAL_LANDING_RESOURCE_ID,
					   .resolver	   = throwing}} ;	// Callback例外登録。
	// 例外の失敗変換を起動するcommand。
	OfficialRecordResolutionCommand throws =
		makeCommand( 3U, 900U, L"https://search.fixture.invalid/throws") ;
	// Callback例外をE_FAILへ変換した公開結果。
	const OfficialRecordResolutionResult throwingResult =
		session.resolve( std::move( throws), throwingRegistrations, []() { return false ; }) ;
	DRIVERCRATE_EXPECT( context, throwingResult.state == OfficialRecordResolutionState::FAILED) ;
	DRIVERCRATE_EXPECT( context, throwingResult.error == TEST_FAILURE) ;

	// 登録Providerと異なるroot evidenceを返すfake resolver。
	const OfficialRecordRootResolver wrongProvider =
		[]( const ScanSessionId currentSession, const std::uint64_t recordEvidenceId,
		   std::wstring_view, std::wstring_view, std::wstring_view, std::uint64_t,
		   OfficialRecordFetchMode, OfficialDistributionRecord &record) {
			record						   = makeRecord( currentSession, recordEvidenceId,
														L"https://resolved.fixture.invalid/wrong.zip") ;
			record.rootEvidence.providerId = std::wstring{NVIDIA_PROVIDER_ID} ;
			return static_cast<NativeError>( 0) ;
		} ;
	const std::array				wrongRegistrations{OfficialRecordResolverRegistration{
					   .providerId	   = INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID,
					   .rootResourceId = OFFICIAL_LANDING_RESOURCE_ID,
					   .resolver	   = wrongProvider}} ;	// Provider差替えrecord登録。
	// EvidenceのProvider差替えを検出するcommand。
	OfficialRecordResolutionCommand wrong =
		makeCommand( 4U, 900U, L"https://search.fixture.invalid/wrong") ;
	// Provider不一致recordを拒否した公開結果。
	const OfficialRecordResolutionResult wrongResult =
		session.resolve( std::move( wrong), wrongRegistrations, []() { return false ; }) ;
	DRIVERCRATE_EXPECT( context, wrongResult.state == OfficialRecordResolutionState::REJECTED) ;

	const std::array duplicateRegistrations{
		registrations[0], registrations[0]} ;	// 同じProvider・root pairの二重登録。
	DRIVERCRATE_EXPECT( context,
					   !validateOfficialRecordResolverRegistrations( duplicateRegistrations)) ;
	const std::array wrongRootRegistration{OfficialRecordResolverRegistration{
		.providerId		= INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID,
		.rootResourceId = OFFICIAL_PAYLOAD_RESOURCE_ID,
		.resolver		= resolver}} ;	// Payloadをrootへ転用する不正登録。
	DRIVERCRATE_EXPECT( context,
					   !validateOfficialRecordResolverRegistrations( wrongRootRegistration)) ;

	DRIVERCRATE_EXPECT( context, session.beginSession( 901U) == 0) ;
	DRIVERCRATE_EXPECT( context, session.retainedRecordCount() == 0U) ;
	ResolvedOfficialDistributionRecord staleRecord ;	// 旧session record claimの出力。
	DRIVERCRATE_EXPECT(
		context, session.claimResolvedRecord( 900U, validResult.recordEvidenceId, staleRecord) != 0) ;
	session.invalidate() ;
	DRIVERCRATE_EXPECT( context, session.activeSessionId() == 0U) ;
	DRIVERCRATE_EXPECT( context, session.retainedRecordCount() == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一scan最大64 recordと65件目のresolver未実行を検証します。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testResolutionRecordLimit( TestContext &context)
{
	std::uint32_t					 resolverCalls{} ;	// 上限まで実行されたresolver回数。
	// 上限まで異なるrecordを返すfake resolver。
	const OfficialRecordRootResolver resolver =
		[&resolverCalls]( const ScanSessionId session, const std::uint64_t recordEvidenceId,
						 std::wstring_view, std::wstring_view, std::wstring_view, std::uint64_t,
						 OfficialRecordFetchMode, OfficialDistributionRecord &record) {
			++resolverCalls ;
			record = makeRecord( session, recordEvidenceId,
								L"https://resolved.fixture.invalid/driver-" +
									std::to_wstring( recordEvidenceId) + L".zip") ;
			return static_cast<NativeError>( 0) ;
		} ;
	const std::array				registrations{OfficialRecordResolverRegistration{
					   .providerId	   = INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID,
					   .rootResourceId = OFFICIAL_LANDING_RESOURCE_ID,
					   .resolver	   = resolver}} ;	// 上限試験用登録。
	OfficialRecordResolutionSession session ;			// 64 recordを保持するregistry。
	DRIVERCRATE_EXPECT( context, session.beginSession( 1'000U) == 0) ;

	bool allResolved = true ;	// 先頭64 commandが全て成功した場合true。
	// 一scanの許可上限64件まで異なるoperationを順に解決する。
	for( std::uint64_t index = 0U; index < 64U; ++index) {
		// 一意なoperation IDと架空入力URLを持つcommand。
		OfficialRecordResolutionCommand command = makeCommand(
			index + 1U, 1'000U, L"https://search.fixture.invalid/item-" + std::to_wstring( index)) ;
		// 現在の保持件数も返す一件の解決結果。
		const OfficialRecordResolutionResult result =
			session.resolve( std::move( command), registrations, []() { return false ; }) ;
		// 一件でも失敗した事実を保持し、残りの境界も最後まで検査する。
		if( result.state != OfficialRecordResolutionState::RESOLVED ||
		   result.retainedRecordCount != index + 1U) {
			allResolved = false ;
		}
	}

	DRIVERCRATE_EXPECT( context, allResolved) ;
	DRIVERCRATE_EXPECT( context, resolverCalls == 64U) ;
	DRIVERCRATE_EXPECT( context, session.retainedRecordCount() == 64U) ;
	// 64件のsession上限後に追加する65件目のcommand。
	OfficialRecordResolutionCommand overflow =
		makeCommand( 65U, 1'000U, L"https://search.fixture.invalid/item-overflow") ;
	// Resolverを呼ばず上限拒否した公開結果。
	const OfficialRecordResolutionResult overflowResult =
		session.resolve( std::move( overflow), registrations, []() { return false ; }) ;
	DRIVERCRATE_EXPECT( context, overflowResult.state == OfficialRecordResolutionState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, resolverCalls == 64U) ;
	session.invalidate() ;
	DRIVERCRATE_EXPECT( context, session.retainedRecordCount() == 0U) ;
}

//------------------------------------------------------------------------------
// 静的record helper試験。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Provider markerと同じ有限HTML tagの一意な属性だけを抽出することを検証します。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testStaticHtmlAttributeExtraction( TestContext &context)
{
	const std::wstring html =	// 一意なProvider markerと架空payload属性を持つ静的HTML。
		LR"(<html><body><a data-record="driver-main" href="https://cdn.fixture.invalid/driver.zip">Download</a></body></html>)" ;
	std::wstring value = L"old" ;	// 成功値と失敗時clearを確認する出力。
	DRIVERCRATE_EXPECT( context, extractUniqueOfficialHtmlAttribute(
									html, L"data-record=\"driver-main\"", L"href", 512U, value)) ;
	DRIVERCRATE_EXPECT( context, value == L"https://cdn.fixture.invalid/driver.zip") ;

	const std::wstring duplicateMarker =	// 同じProvider区画を二件持つ曖昧なHTML。
		html + html ;
	value = L"old" ;
	DRIVERCRATE_EXPECT( context, !extractUniqueOfficialHtmlAttribute( duplicateMarker,
																	L"data-record=\"driver-main\"",
																	L"href", 512U, value)) ;
	DRIVERCRATE_EXPECT( context, value.empty()) ;

	const std::wstring duplicateAttribute =	// 同じ開始tag内にhrefを二件持つ不正HTML。
		LR"(<a data-record="driver-main" href="https://one.fixture.invalid/a" href="https://two.fixture.invalid/b">x</a>)" ;
	DRIVERCRATE_EXPECT( context, !extractUniqueOfficialHtmlAttribute( duplicateAttribute,
																	L"data-record=\"driver-main\"",
																	L"href", 512U, value)) ;

	const std::wstring scriptAttribute =	// Script tagに埋め込まれた属性風の値。
		LR"(<script data-record="driver-main" href="https://cdn.fixture.invalid/script.zip"></script>)" ;
	DRIVERCRATE_EXPECT( context, !extractUniqueOfficialHtmlAttribute( scriptAttribute,
																	L"data-record=\"driver-main\"",
																	L"href", 512U, value)) ;

	const std::wstring outsideTag =	// Marker文字列を開始tag外のtextに置く入力。
		LR"(<div>data-record="driver-main"</div><a href="https://cdn.fixture.invalid/out.zip">x</a>)" ;
	DRIVERCRATE_EXPECT( context, !extractUniqueOfficialHtmlAttribute( outsideTag,
																	L"data-record=\"driver-main\"",
																	L"href", 512U, value)) ;

	const std::wstring encodedValue =	// Exact targetへ推測復号できないHTML entityを含む属性。
		LR"(<a data-record="driver-main" href="https://cdn.fixture.invalid/a?x=1&amp;y=2">x</a>)" ;
	DRIVERCRATE_EXPECT( context, !extractUniqueOfficialHtmlAttribute( encodedValue,
																	L"data-record=\"driver-main\"",
																	L"href", 512U, value)) ;

	const std::wstring singleQuoted =	// 対応外の単引用符属性を持つHTML。
		LR"(<a data-record="driver-main" href='https://cdn.fixture.invalid/single.zip'>x</a>)" ;
	DRIVERCRATE_EXPECT( context, !extractUniqueOfficialHtmlAttribute( singleQuoted,
																	L"data-record=\"driver-main\"",
																	L"href", 512U, value)) ;
	DRIVERCRATE_EXPECT( context, !extractUniqueOfficialHtmlAttribute(
									html, L"data-record=\"driver-main\"", L"href", 8'193U, value)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider指定JSON object pathで文字列型だけを抽出することを検証します。
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testStaticJsonStringExtraction( TestContext &context)
{
	const std::wstring json =	// 二段object pathと架空payload URLを持つ静的JSON。
		LR"({"record":{"payload":{"url":"https://cdn.fixture.invalid/driver.zip"}}})" ;
	constexpr std::array<std::wstring_view, 2> path{L"record", L"payload"} ;	// 明示object path。
	std::wstring value = L"old" ;												// 成功値と失敗時clearを確認する出力。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialJsonStringAtObjectPath( json, path, L"url", 512U, value)) ;
	DRIVERCRATE_EXPECT( context, value == L"https://cdn.fixture.invalid/driver.zip") ;

	constexpr std::array<std::wstring_view, 0> rootPath{} ;	// Root objectを直接読む空path。
	DRIVERCRATE_EXPECT( context, extractOfficialJsonStringAtObjectPath(
									LR"({"version":"1.2.3"})", rootPath, L"version", 16U, value)) ;
	DRIVERCRATE_EXPECT( context, value == L"1.2.3") ;

	value = L"old" ;
	DRIVERCRATE_EXPECT(
		context, !extractOfficialJsonStringAtObjectPath( LR"({"record":{"payload":{"url":123}}})",
														path, L"url", 512U, value)) ;
	DRIVERCRATE_EXPECT( context, value.empty()) ;
	DRIVERCRATE_EXPECT( context,
					   !extractOfficialJsonStringAtObjectPath(
						   LR"({"record":{"payload":[{"url":"https://cdn.fixture.invalid/a"}]}})",
						   path, L"url", 512U, value)) ;
	DRIVERCRATE_EXPECT( context, !extractOfficialJsonStringAtObjectPath(
									LR"({"record":{"payload":{"url":"line\u000abreak"}}})", path,
									L"url", 512U, value)) ;
	DRIVERCRATE_EXPECT( context,
					   !extractOfficialJsonStringAtObjectPath( json, path, L"url", 8U, value)) ;
	DRIVERCRATE_EXPECT( context,
					   !extractOfficialJsonStringAtObjectPath( L"{", path, L"url", 512U, value)) ;

	constexpr std::array<std::wstring_view, 9> deepPath{
		L"a", L"b", L"c", L"d", L"e", L"f", L"g", L"h", L"i"} ;	// 深さ上限超過path。
	DRIVERCRATE_EXPECT( context,
					   !extractOfficialJsonStringAtObjectPath( json, deepPath, L"url", 512U, value)) ;
	constexpr std::array<std::wstring_view, 1> invalidPath{
		L"payload.name"} ;	// 推測を招く不正path名。
	DRIVERCRATE_EXPECT(
		context, !extractOfficialJsonStringAtObjectPath( json, invalidPath, L"url", 512U, value)) ;
}

/** @brief 公開SHA-512の有無・正規化・改変とgrant所有を検証します。
 * @param[in,out] context Assertion集計先。
 */
void testSha512RecordBinding( TestContext &context)
{
	auto record =
		// 基準record。
		makeRecord( SESSION_ID, 981U, L"https://cdn.fixture.invalid/driver.zip") ;
	OfficialDistributionRecordEvidence legacy ;	// SHA-512未指定の元指紋。
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( record, legacy) == 0) ;
	record.payloads[0].publishedSha512 = std::wstring( 128U, L'a') ;
	OfficialDistributionRecordEvidence added ;	// SHA-512追加後の指紋。
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( record, added) == 0) ;
	DRIVERCRATE_EXPECT( context, legacy.stableFingerprint.bytes != added.stableFingerprint.bytes) ;
	record.payloads[0].publishedSha512 = std::wstring( 128U, L'A') ;
	OfficialDistributionRecordEvidence upper ;	// 大小文字差だけの指紋。
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( record, upper) == 0) ;
	DRIVERCRATE_EXPECT( context, upper.stableFingerprint.bytes == added.stableFingerprint.bytes) ;
	RecordScopedDownloadGrant grant ;	// 発行時のSHA-512を所有するgrant。
	DRIVERCRATE_EXPECT( context, grant.issue( record, upper, 0U, 991U, 20'000U, 0U) == 0) ;
	RecordScopedDownloadGrant moved( std::move( grant)) ;	// 移動後も公開hashを維持する。
	DRIVERCRATE_EXPECT( context, moved.payloadView().publishedSha512 == std::wstring( 128U, L'A')) ;
	DRIVERCRATE_EXPECT( context, moved.claim( SESSION_ID, 991U, 20'100U) == 0) ;
	DRIVERCRATE_EXPECT( context, moved.payloadView().publishedSha512 == std::wstring( 128U, L'A')) ;
	DRIVERCRATE_EXPECT( context, moved.finishAcquisition(
									OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION, 0) == 0) ;
	// Grantへ移動した秘密URLを別検証用の架空値で再設定する。
	record.payloads[0].targetUrl = SecretOfficialUrl{L"https://cdn.fixture.invalid/driver.zip"} ;
	record.payloads[0].publishedSha512 = std::wstring( 128U, L'b') ;
	OfficialDistributionRecordEvidence changed ;	// 値の変更は別のstable record。
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( record, changed) == 0) ;
	DRIVERCRATE_EXPECT( context, changed.stableFingerprint.bytes != added.stableFingerprint.bytes) ;
	RecordScopedDownloadGrant stale ;	// 元指紋の使い回しを拒否する。
	DRIVERCRATE_EXPECT( context, stale.issue( record, added, 0U, 992U, 20'000U, 0U) != 0) ;
	record.payloads[0].publishedSha512.clear() ;
	OfficialDistributionRecordEvidence removed ;	// 未指定へ戻すと旧表現へ一致する。
	DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( record, removed) == 0) ;
	DRIVERCRATE_EXPECT( context, removed.stableFingerprint.bytes == legacy.stableFingerprint.bytes) ;
	// 桁不足・超過・非hex・空白・algorithm取り違えを有限集合で拒否する。
	for( const auto &invalid :
		{std::wstring( 127U, L'a'), std::wstring( 129U, L'a'), std::wstring( 128U, L'g'),
		 std::wstring( 128U, L' '), std::wstring( 64U, L'a')}) {
		record.payloads[0].publishedSha512 = invalid ;
		OfficialDistributionRecordEvidence rejected ;	// 各不正入力の独立結果。
		DRIVERCRATE_EXPECT( context, validateOfficialDistributionRecord( record, rejected) != 0) ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_download_grant_tests.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
void runOfficialDownloadGrantTests( TestContext &context)
{
	testSha512RecordBinding( context) ;
	testStableRecordFingerprint( context) ;
	testCollectorRecordProjection( context) ;
	testCollectorPublicBoundary( context) ;
	testRecordRejections( context) ;
	testGrantSuccessAndMove( context) ;
	testGrantExpiryAndFailures( context) ;
	testOf05AndOf13GrantReresolution( context) ;
	testFixedRootResolution( context) ;
	testResolutionRejections( context) ;
	testResolutionRecordLimit( context) ;
	testStaticHtmlAttributeExtraction( context) ;
	testStaticJsonStringExtraction( context) ;
}

} // namespace drivercrate::test
