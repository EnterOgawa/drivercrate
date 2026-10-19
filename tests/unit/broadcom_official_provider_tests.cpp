//------------------------------------------------------------------------------
/**
 * @file broadcom_official_provider_tests.cpp
 * @brief Broadcom公開配布情報の合成metadata試験。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Registry期待値を導入接続後の能力へ更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  導入直前再検証と部分失敗試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  監査済み候補生成と未準備導入拒否を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Broadcomの取得後監査を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 架空metadata・一時file・fake導入で境界を確認し、実HTTP・実driver導入は行いません。
 */
//------------------------------------------------------------------------------

#include "broadcom_official_provider_tests.h"

#include "core/candidate_audit.h"
#include "core/official_driver_rank.h"
#include "core/official_preparation_operation.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/broadcom_catalog_parser.h"
#include "platform/broadcom_update_provider.h"
#include "platform/official_acquisition.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_package_audit.h"
#include "platform/official_file_verifier.h"
#include "test_framework.h"
#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {
// Record IDと版は架空。公式に存在する配布物の合格証明へ使わない。
constexpr std::wstring_view RECORD =
	LR"({"title":"Broadcom NetXtreme-E Windows Drivers","doc_status":"Current",)"
	LR"("archive_asset":"No","os":["Windows"],"asset_version":"100.2.3.4",)"
	LR"("content_id":"fictional-driver","content_type":"document","doc_type":"Drivers",)"
	LR"("type":"zip","extension":"zip","secured":"no","entitled":"no","locale":"en-us",)"
	LR"("data-type":"regular","data-expired":false,)"
	LR"("document_title":"Broadcom NetXtreme-E Windows Drivers",)"
	LR"("url":"https://docs.broadcom.com/docs/Windows_Drivers-100.2.3.4",)"
	LR"("data-url":"https://docs.broadcom.com/docs/Windows_Drivers-100.2.3.4",)"
	LR"("publication_number":"Windows_Drivers-100.2.3.4"})" ;
// 本文も架空のplaceholderであり、実在するlicenseの転載ではない。
constexpr std::wstring_view DOCUMENT =
	LR"({"status_code":"200","content_type":"document","content_id":"fictional-driver",)"
	LR"("doc_type":"Downloads","contenttype":"Downloads","document_type":"eula",)"
	LR"("document_title":"Broadcom NetXtreme-E Windows Drivers","locale":"en-us",)"
	LR"("publication_number":"Windows_Drivers-100.2.3.4","eula_type":"Shareable License",)"
	LR"("shareable_license":{"content_type":"general_page","locale":"en-us",)"
	LR"("body_text":"Fictional notice","body_bottom_text":"Fictional conditions"},)"
	LR"("url":"https://docs.broadcom.com/docs-and-downloads/ethernet-network-adapters/)"
	LR"(NXE/BRCM_100.9.8.7/Windows_Drivers-100.2.3.4.zip"})" ;

// Executorが外側取得identityを再検証するための架空byte列。
constexpr std::array<std::byte, 4> PREPARED_ARCHIVE_BYTES{std::byte{0x10}, std::byte{0x20},
														  std::byte{0x30}, std::byte{0x40}} ;

/** @brief Broadcom導入executorを実fileとfake callbackで確認する所有fixtureである。 */
struct BroadcomPreparedInstallFixture {
	/// 外側取得fileを所有する保護一時領域。
	OfficialDownloadWorkspace										archiveWorkspace ;
	/// 外側fileのsize／hash snapshot。
	OfficialAcquisitionResult										acquisition ;
	/// 全候補が共有するopaque package ID。
	std::wstring													packageIdentity ;
	/// 保持INF閉包群。
	std::vector<OfficialAuditedInfPackage>							auditedPackages ;
	/// 発行済み候補IDから保持INF／device／rankへのrouting。
	std::unordered_map<std::wstring, BroadcomPreparedInstallTarget> targets ;
	/// 利用者選択を模倣する候補ID順序。
	std::vector<std::wstring>										identities ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief G11-Bまたは保持INFのsnapshotをtest内だけで構成する。
 *
 * @param[in,out] workspace 初期化済みでfileを所有する一時領域。
 * @param[in] name Workspace基準の安全な相対file名。
 * @param[in] bytes 書き込む有限byte列。
 * @param[out] sha256 成功時の実file SHA-256。
 * @return 作成、全byte書込み、close、hash計算の成功時0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError storeFixtureFile( OfficialDownloadWorkspace	   &workspace,
										   const std::wstring_view			name,
										   const std::span<const std::byte> bytes,
										   std::wstring					   &sha256)
{
	HANDLE		file{INVALID_HANDLE_VALUE} ;				// Workspaceが追跡する書込みhandle。
	NativeError error = workspace.createFile( name, file) ;	// File作成または入力検証結果。
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す。
	if( error != 0) {
		return error ;
	}

	std::size_t offset{} ;	// 次に書き込むbyte位置。
	// DWORDの有限chunkで全byteを書き込み、短い書込みも失敗として扱う。
	while( offset < bytes.size()) {
		const std::size_t remaining = bytes.size() - offset ;	// 未書込みbyte数。
		const DWORD		  requested = static_cast<DWORD>(
			  std::min<std::size_t>( remaining, 1024U * 1024U)) ;	// 今回要求するbyte数。
		DWORD	   written{} ;										// WriteFileの実書込みbyte数。
		const BOOL succeeded =
			// API結果。
			WriteFile( file, bytes.data() + offset, requested, &written, nullptr) ;
		// 書込み失敗または短い書込みを検出したらfixture作成を中断して原因を保持する。
		if( succeeded == FALSE || written != requested) {
			const DWORD writeError =
				// 保持する失敗理由。
				succeeded == FALSE ? GetLastError() : ERROR_WRITE_FAULT ;
			error = static_cast<NativeError>( HRESULT_FROM_WIN32( writeError)) ;
			break ;
		}

		offset += written ;
	}

	// 先行する書込み失敗を上書きせず、closeだけが失敗した場合に診断を残す。
	if( CloseHandle( file) == FALSE && error == 0) {
		error = static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
	}

	return error != 0 ? error : computeFileSha256( workspace.path( name), sha256) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Scan後の同一size差替えを模倣し、hash検証が検出できる状態を作る。
 *
 * @param[in] path Test workspace内の既存通常file絶対path。
 * @param[in] value 先頭へ同一sizeで上書きする一byte。
 * @return 一byte上書きとhandle解放の成功時0。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError replaceFirstByte( const std::wstring_view path, const std::byte value)
{
	const std::wstring ownedPath( path) ;	// Win32へNUL終端で渡す呼出し中の所有path。
	const HANDLE file = CreateFileW( ownedPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
									OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
									nullptr) ;	// 同一file先頭を上書きするhandle。
	// 差替え用fileを開けない場合はOSの診断を返して試験の前提失敗とする。
	if( file == INVALID_HANDLE_VALUE) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
	}

	DWORD		written{} ;														// WriteFileが実際に置換したbyte数。
	const BOOL	succeeded = WriteFile( file, &value, 1U, &written, nullptr) ;	// 一byte差替え結果。
	NativeError error	  = succeeded != FALSE && written == 1U
								? 0
								: static_cast<NativeError>( HRESULT_FROM_WIN32(
								  // 書込み診断値。
								  succeeded == FALSE ? GetLastError() : ERROR_WRITE_FAULT)) ;
	// 先行処理が成功した場合にだけclose失敗を最終診断へ反映する。
	if( CloseHandle( file) == FALSE && error == 0) {
		error = static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実署名や実PnP IDを合格として偽装せず、再検証順序とcallback結果だけをtestできる入力を作る。
 *
 * @param[in] session 0ではない架空scan session。
 * @param[in] deviceCount 作成する一意device／候補数。1～16。
 * @param[out] fixture 成功時の外側file、閉包、routing所有値。
 * @return 全workspace、file、hash、有限routingを構成できた場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool initializePreparedInstallFixture( const ScanSessionId				session,
													const std::size_t				deviceCount,
													BroadcomPreparedInstallFixture &fixture)
{
	// 不正件数で一時fileを作成しない。
	if( session == 0U || deviceCount == 0U || deviceCount > 16U) {
		return false ;
	}

	// archive保持領域を作成できない場合は不完全なfixtureを使用しない。
	if( fixture.archiveWorkspace.initialize( L"broadcom-install-fixture", session) != 0) {
		return false ;
	}

	std::wstring archiveHash ;	// 外側file書込み後の固定SHA-256。
	// 架空archiveの保存とhash取得に失敗した場合はfixtureを完成扱いにしない。
	if( storeFixtureFile( fixture.archiveWorkspace, L"payload.zip", PREPARED_ARCHIVE_BYTES,
						archiveHash) != 0) {
		return false ;
	}

	fixture.packageIdentity			   = L"fictional-package:" + std::to_wstring( session) ;
	fixture.acquisition.state		   = OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ;
	fixture.acquisition.scanSessionId  = session ;
	fixture.acquisition.acquisitionId  = 1U ;
	fixture.acquisition.providerId	   = BROADCOM_NET_XTREME_PROVIDER_ID ;
	fixture.acquisition.resourceId	   = OFFICIAL_PAYLOAD_RESOURCE_ID ;
	fixture.acquisition.inspectionPath = fixture.archiveWorkspace.path( L"payload.zip") ;
	fixture.acquisition.byteCount	   = PREPARED_ARCHIVE_BYTES.size() ;
	fixture.acquisition.sha256		   = std::move( archiveHash) ;

	OfficialAuditedInfPackage audited ;	// Fake再検証に渡す一つの保持INF閉包。
	audited.workspace = std::make_unique<OfficialDownloadWorkspace>() ;
	// INF保持領域を作成できない場合は導入対象の構築を中止する。
	if( audited.workspace->initialize( L"broadcom-inf-fixture", session) != 0) {
		return false ;
	}

	audited.profile = OfficialDriverAuditProfile::BROADCOM_NET_XTREME_E ;
	audited.closure.packages.push_back( {.infRelativePath	 = L"driver\\fictional.inf",
										.catalogRelativePath = L"driver\\fictional.cat",
										.className			 = L"Net",
										.providerName		 = L"Broadcom",
										.driverDate			 = L"09/06/2026",
										.driverVersion		 = L"2.0.0.0"}) ;
	fixture.auditedPackages.push_back( std::move( audited)) ;

	OfficialDriverRankAudit rank ;	// 取得後監査で固定した共通の架空rank結果。
	rank.decision				  = OfficialDriverRankDecision::APPLICABLE ;
	rank.currentPosition		  = {PnpIdentifierKind::HARDWARE_ID, 0U} ;
	rank.candidatePosition		  = {PnpIdentifierKind::HARDWARE_ID, 0U} ;
	rank.currentRank			  = 0x00FF0001U ;
	rank.candidateRank			  = 0x00FE0001U ;
	rank.currentIdentifierScore	  = 1U ;
	rank.candidateIdentifierScore = 1U ;
	// 一つの保持INFを複数deviceへ対応させ、候補とdeviceだけを一意にする。
	for( std::size_t index = 0U; index < deviceCount; ++index) {
		const std::wstring identity =
			L"fictional-candidate:" + std::to_wstring( index) ;	// 選択候補ID。
		const std::wstring device =
			L"fictional-device:" + std::to_wstring( index) ;	// 対応するopaque device ID。
		fixture.identities.push_back( identity) ;
		// 同じidentityの対象が重複したfixtureは拒否する。
		if( !fixture.targets
				.emplace( identity,
						 BroadcomPreparedInstallTarget{.packageIdentity = fixture.packageIdentity,
													   .deviceIdentity	= device,
													   .auditedPackageIndex = 0U,
													   .rankAudit			= rank})
				.second) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Testだけが公式取得根拠確認済みを明示し、本番Providerは独自根拠を使用する。
 *
 * @param[in] fixture 呼出し中より長く生存する所有fixture。
 * @return 同じfixtureを参照する非所有executor context。
 */
//------------------------------------------------------------------------------
[[nodiscard]] BroadcomPreparedInstallContext preparedInstallContext(
	const BroadcomPreparedInstallFixture &fixture) noexcept
{
	return {.scanSessionId	 = fixture.acquisition.scanSessionId,
			.acquisition	 = &fixture.acquisition,
			.packageIdentity = fixture.packageIdentity,
			.targets		 = &fixture.targets,
			.auditedPackages = std::span<const OfficialAuditedInfPackage>( fixture.auditedPackages),
			.sourceEvidenceConfirmed = true} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既知の製品schemaへ架空recordを埋め込む。実siteへ接続しない。
 *
 * @param[in] records 架空の製品record要素。
 * @return 構築した合成文字列。変更対象の不在は例外。
 */
//------------------------------------------------------------------------------
std::wstring catalog( const std::wstring_view records)
{
	return LR"({"content_type":"emulex","asset_type":"Product","template":"ProductDetail",)"
		   LR"("locale":"en-us","url":"/products/ethernet-connectivity/network-adapters/n210tp",)"
		   LR"("product_tabs":[{"title":"Downloads","template":"Downloads","documents":[)" +
		   std::wstring( records) + L"]}]}" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 合成fixtureの一箇所だけを置換する。対象不在は例外とし、無変更の入力で試験を通さない。
 *
 * @param[in] input 変更元の合成fixture。
 * @param[in] before 置換対象として必須の文字列。
 * @param[in] after 置換後の合成値。
 * @return 構築した合成文字列。変更対象の不在は例外。
 */
//------------------------------------------------------------------------------
std::wstring changed( const std::wstring_view input, const std::wstring_view before,
					 const std::wstring_view after)
{
	std::wstring	  result( input) ;					// 元fixtureを保持する変更用copy。
	const std::size_t position = result.find( before) ;	// 意図した一箇所の位置。
	// 変形箇所が見つからないfixtureで誤って試験を通さないよう例外で中止する。
	if( position == result.npos) {
		throw std::logic_error( "Broadcom fixture mutation target missing") ;
	}

	result.replace( position, before.size(), after) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 合成製品JSONで現行分類、旧版除外、曖昧性、上限と型の拒否を確認する。
 *
 * @param[in,out] context 回帰試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testCatalog( TestContext &context)
{
	std::optional<BroadcomDriverRelease> release ;	// 成功時だけ設定される解析結果。
	DRIVERCRATE_EXPECT( context, parseBroadcomCatalog( catalog( RECORD), release)) ;
	DRIVERCRATE_EXPECT( context, release.has_value()) ;
	// 基本fixtureの不具合で未設定値を参照しない。
	if( !release.has_value()) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, release->assetVersion == L"100.2.3.4") ;
	DRIVERCRATE_EXPECT( context, release->contentId == L"fictional-driver") ;
	DRIVERCRATE_EXPECT(
		context, release->documentApiUrl ==
					 L"https://docs.broadcom.com/api/document/download/Windows_Drivers-100.2.3.4") ;

	// 旧版は既定候補へ戻さない。
	const auto archive	= changed( changed( RECORD, L"Current", L"Archive"),
								  LR"("archive_asset":"No")", LR"("archive_asset":"Yes")") ;
	const auto firmware = changed( RECORD, L"Broadcom NetXtreme-E Windows Drivers",
								  L"Fictional Firmware") ;	// Driverと無関係な別title。
	DRIVERCRATE_EXPECT( context, parseBroadcomCatalog( catalog( archive), release)) ;
	DRIVERCRATE_EXPECT( context, !release.has_value()) ;
	DRIVERCRATE_EXPECT( context, parseBroadcomCatalog( catalog( firmware), release)) ;
	DRIVERCRATE_EXPECT( context, !release.has_value()) ;
	DRIVERCRATE_EXPECT( context, parseBroadcomCatalog( catalog( L""), release)) ;
	DRIVERCRATE_EXPECT( context, !release.has_value()) ;
	DRIVERCRATE_EXPECT(
		context, parseBroadcomCatalog(
					 catalog( firmware + L"," + archive + L"," + std::wstring( RECORD)), release)) ;
	DRIVERCRATE_EXPECT( context, release.has_value()) ;
	DRIVERCRATE_EXPECT(
		context, !parseBroadcomCatalog( catalog( std::wstring( RECORD) + L"," + std::wstring( RECORD)),
									   release)) ;
	DRIVERCRATE_EXPECT( context, !release.has_value()) ;

	// 各fieldの型、配布条件、URL不整合を一項目ずつ拒否する。
	for( const auto &mutation :
		std::initializer_list<std::pair<std::wstring_view, std::wstring_view>>{
			{LR"("doc_status":"Current")", LR"("doc_status":null)"},
			{LR"("archive_asset":"No")", LR"("archive_asset":"Yes")"},
			{LR"("os":["Windows"])", LR"("os":"Windows")"},
			{LR"("os":["Windows"])", LR"("os":["Linux"])"},
			{LR"("os":["Windows"])", LR"("os":["Windows","Linux"])"},
			{LR"("asset_version":"100.2.3.4")", LR"("asset_version":100)"},
			{LR"("asset_version":"100.2.3.4")", LR"("asset_version":"100..3.4")"},
			{LR"("asset_version":"100.2.3.4")", LR"("asset_version":"100.2.3.4\u0000x")"},
			{LR"("content_id":"fictional-driver")", LR"("content_id":"")"},
			{LR"("content_id":"fictional-driver")", LR"("content_id":"fictional-driver\u0000x")"},
			{LR"("content_type":"document")", LR"("content_type":"utility")"},
			{LR"("doc_type":"Drivers")", LR"("doc_type":"Firmware")"},
			{LR"("type":"zip")", LR"("type":"exe")"},
			{LR"("extension":"zip")", LR"("extension":"msi")"},
			{LR"("secured":"no")", LR"("secured":"yes")"},
			{LR"("entitled":"no")", LR"("entitled":false)"},
			{LR"("locale":"en-us")", LR"("locale":"other")"},
			{LR"("data-type":"regular")", LR"("data-type":"restricted")"},
			{LR"("data-expired":false)", LR"("data-expired":true)"},
			{LR"("data-expired":false)", LR"("data-expired":"false")"},
			{L"https://docs.broadcom.com/docs/", L"http://docs.broadcom.com/docs/"},
			{L"https://docs.broadcom.com/docs/", L"https://docs.broadcom.com.invalid/docs/"},
			{LR"("publication_number":"Windows_Drivers-100.2.3.4")",
			 LR"("publication_number":"Windows_Drivers-100.2.3.5")"}}) {
		release = BroadcomDriverRelease{.contentId = L"stale"} ;
		DRIVERCRATE_EXPECT( context,
						   !parseBroadcomCatalog(
							   catalog( changed( RECORD, mutation.first, mutation.second)), release)) ;
		DRIVERCRATE_EXPECT( context, !release.has_value()) ;
	}

	const std::wstring valid = catalog( RECORD) ;	// 固定製品JSONの正常形。
	DRIVERCRATE_EXPECT(
		context,
		!parseBroadcomCatalog( changed( valid, L"]}]}",
									  L"]},{\"title\":\"Downloads\",\"template\":\"Downloads\","
									  L"\"documents\":[]}]}"),
							  release)) ;
	DRIVERCRATE_EXPECT(
		context, !parseBroadcomCatalog( changed( valid, L"/n210tp", L"/other-product"), release)) ;
	DRIVERCRATE_EXPECT(
		context, !parseBroadcomCatalog( changed( valid, L"ProductDetail", L"PageNotFound"), release)) ;
	DRIVERCRATE_EXPECT(
		context, !parseBroadcomCatalog( changed( valid, L"Downloads", L"Documentation"), release)) ;
	DRIVERCRATE_EXPECT( context, !parseBroadcomCatalog( L"{}", release)) ;
	DRIVERCRATE_EXPECT( context, !parseBroadcomCatalog( L"{", release)) ;
	DRIVERCRATE_EXPECT( context,
					   !parseBroadcomCatalog( std::wstring( 2U * 1024U * 1024U + 1U, L' '), release)) ;
	DRIVERCRATE_EXPECT( context, !parseBroadcomCatalog( valid + std::wstring( 1U, L'\0'), release)) ;
	std::wstring manyRecords ;	// Record数上限を超える合成入力。
	// 内容の選択とは別に総数上限512を確認する。
	for( std::size_t index = 0U; index < 513U; ++index) {
		manyRecords += (index == 0U ? L"" : L",") + firmware ;
	}

	DRIVERCRATE_EXPECT( context, !parseBroadcomCatalog( catalog( manyRecords), release)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 合成documentで製品record・公開license・ZIP URLの結合を確認する。
 *
 * @param[in,out] context 回帰試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testDocument( TestContext &context)
{
	std::optional<BroadcomDriverRelease> release ;	// 架空の製品record。
	DRIVERCRATE_EXPECT( context, parseBroadcomCatalog( catalog( RECORD), release)) ;
	// 前提fixture失敗時は未設定値を参照しない。
	if( !release.has_value()) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, validateBroadcomDocument( DOCUMENT, *release)) ;
	// 未知のEULA、別record、URL置換を全て拒否する。
	for( const auto &mutation :
		std::initializer_list<std::pair<std::wstring_view, std::wstring_view>>{
			{LR"("status_code":"200")", LR"("status_code":200)"},
			{LR"("status_code":"200")", LR"("status_code":"404")"},
			{L"fictional-driver", L"different-document"},
			{LR"("document_type":"eula")", LR"("document_type":"redirect")"},
			{LR"("contenttype":"Downloads")", LR"("contenttype":"PageNotFound")"},
			{LR"("locale":"en-us")", LR"("locale":"other")"},
			{LR"("doc_type":"Downloads")", LR"("doc_type":"SupportPortal")"},
			{L"Shareable License", L"Personal License"},
			{LR"("Fictional notice")", LR"("")"},
			{LR"("Fictional notice")", L"null"},
			{LR"("Fictional conditions")", LR"("  ")"},
			{LR"("Fictional conditions")", LR"("\u0000")"},
			{L"NXE/BRCM_", L"Other/BRCM_"},
			{L"BRCM_100.9.8.7", L"BRCM_100.9.8.7/.."},
			{L"BRCM_100.9.8.7", L"BRCM_100..8.7"},
			{L"100.2.3.4.zip", L"100.2.3.5.zip"},
			{L"100.2.3.4.zip", L"100.2.3.4.exe"},
			{L"100.2.3.4.zip", L"100.2.3.4.zip?token=fictional"},
			{L"100.2.3.4.zip", L"100.2.3.4.zip#fragment"},
			{L"100.2.3.4.zip", LR"(100.2.3.4.zip\u0000suffix)"},
			{L"https://docs.broadcom.com/", L"http://docs.broadcom.com/"},
			{L"https://docs.broadcom.com/", L"https://docs.broadcom.com.invalid/"},
			{L"https://docs.broadcom.com/", L"https://user@docs.broadcom.com/"},
			{L"https://docs.broadcom.com/", L"https://docs.broadcom.com:443/"}}) {
		DRIVERCRATE_EXPECT(
			context, !validateBroadcomDocument( changed( DOCUMENT, mutation.first, mutation.second),
											   *release)) ;
	}

	DRIVERCRATE_EXPECT( context, !validateBroadcomDocument( L"{}", *release)) ;
	DRIVERCRATE_EXPECT( context,
					   !validateBroadcomDocument( std::wstring( 256U * 1024U + 1U, L' '), *release)) ;
	release->documentApiUrl = L"https://example.invalid/document" ;
	DRIVERCRATE_EXPECT( context, !validateBroadcomDocument( DOCUMENT, *release)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 非機密の系列照合、表示候補、空検索と直接install拒否をnetworkなしで確認する。
 *
 * @param[in,out] context 回帰試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testProviderBoundary( TestContext &context)
{
	const OfficialCatalogDevice device{.deviceIdentity	= L"device:fictional",
									   .model			= L"Broadcom NetXtreme-E Fictional Adapter",
									   .manufacturer	= L"Broadcom Inc.",
									   .driverClass		= L"Net",
									   .deviceClassGuid = L"{4d36e972-e325-11ce-bfc1-08002be10318}",
									   .currentVersion =
										   L"1.0.0.0"} ;	// 実inventoryではない合成snapshot。
	DRIVERCRATE_EXPECT( context, broadcomNetxtremeEDevice( device)) ;
	// Consumer、別系列、class不一致、類似語では公式driver情報を関連付けない。
	for( const auto &model : {L"Broadcom NetXtreme II", L"Broadcom Wi-Fi",
							 L"Broadcom NetXtreme-Ethernet", L"OEM Fictional Adapter"}) {
		auto changedDevice	= device ;	// Device名だけを変更するcopy。
		changedDevice.model = model ;
		DRIVERCRATE_EXPECT( context, !broadcomNetxtremeEDevice( changedDevice)) ;
	}

	auto invalid  = device ;	// Class、manufacturer、表示長の拒否条件。
	invalid.model = L"broadcom netxtreme-e Fictional Adapter" ;
	DRIVERCRATE_EXPECT( context, broadcomNetxtremeEDevice( invalid)) ;
	invalid				= device ;
	invalid.driverClass = L"Ports" ;
	DRIVERCRATE_EXPECT( context, !broadcomNetxtremeEDevice( invalid)) ;
	invalid				 = device ;
	invalid.manufacturer = L"BroadcomImitation" ;
	DRIVERCRATE_EXPECT( context, !broadcomNetxtremeEDevice( invalid)) ;
	invalid					= device ;
	invalid.deviceClassGuid = L"{fictional-class}" ;
	DRIVERCRATE_EXPECT( context, !broadcomNetxtremeEDevice( invalid)) ;
	invalid		  = device ;
	invalid.model = std::wstring( 513U, L'X') ;
	DRIVERCRATE_EXPECT( context, !broadcomNetxtremeEDevice( invalid)) ;

	std::optional<BroadcomDriverRelease> release ;	// 表示DTO用の合成metadata。
	DRIVERCRATE_EXPECT( context, parseBroadcomCatalog( catalog( RECORD), release)) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( !release.has_value()) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, validateBroadcomDocument( DOCUMENT, *release)) ;
	// UI選択可否に使う値を全て検査する。
	const auto candidate = makeBroadcomDiscoveryCandidate( 7U, 0U, device, *release) ;
	DRIVERCRATE_EXPECT( context, candidate.deviceIdentity == device.deviceIdentity) ;
	DRIVERCRATE_EXPECT( context, candidate.providerId == BROADCOM_NET_XTREME_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, candidate.action == DriverAction::NONE) ;
	DRIVERCRATE_EXPECT( context, candidate.version.empty() && candidate.driverDate.empty()) ;
	DRIVERCRATE_EXPECT( context, candidate.maximumDownloadBytes == 0U) ;
	DRIVERCRATE_EXPECT( context,
					   !candidate.installable && !candidate.recommended && !candidate.current) ;
	DRIVERCRATE_EXPECT( context, !candidate.eulaAccepted && !candidate.allContentCached) ;
	DRIVERCRATE_EXPECT( context, candidate.defaultPreference == CandidateDefaultPreference::NONE) ;
	DRIVERCRATE_EXPECT( context, candidate.audit.sourceOrigin == CandidateAuditGateState::PASSED) ;
	DRIVERCRATE_EXPECT( context,
					   candidate.audit.contentIntegrity == CandidateAuditGateState::PENDING) ;
	DRIVERCRATE_EXPECT( context,
					   candidate.audit.systemApplicability == CandidateAuditGateState::PENDING) ;
	DRIVERCRATE_EXPECT( context,
					   candidate.audit.installReadiness == CandidateInstallReadiness::BLOCKED) ;

	BroadcomUpdateProvider		   provider ;	// 空／対象外scanはnetworkへ進まない実装。
	std::size_t					   notices{} ;	// 無通信で完了するscanの通知回数。
	const ProviderProgressCallback progress = [&notices]( const ProviderProgress &) {
		++notices ;
	} ; // UIの代わりに通知件数だけを保持する。
	const auto empty = provider.scan( 7U, {}, {}, progress) ;	// 現在deviceなし。
	DRIVERCRATE_EXPECT( context,
					   empty.succeeded && empty.state == ProviderScanState::NOT_APPLICABLE) ;
	DRIVERCRATE_EXPECT( context, empty.candidates.empty() && notices == 1U) ;
	const std::array unrelated{invalid} ;	// 系列名が不正なdeviceだけを渡す。
	DRIVERCRATE_EXPECT( context, provider.scan( 8U, unrelated, {}, progress).state ==
									ProviderScanState::NOT_APPLICABLE) ;
	const std::array duplicate{device, device} ;	// 通信前に拒否すべきopaque ID重複。
	DRIVERCRATE_EXPECT( context, !provider.scan( 9U, duplicate, {}, progress).succeeded) ;
	DRIVERCRATE_EXPECT( context, !provider.scan( 0U, {}, {}, progress).succeeded) ;
	DRIVERCRATE_EXPECT( context, !provider.scan( 10U, {}, {}, {}).succeeded) ;
	const std::vector<OfficialCatalogDevice> oversized( 4097U) ;	// 入力上限を越えるsnapshot群。
	DRIVERCRATE_EXPECT( context, !provider.scan( 11U, oversized, {}, progress).succeeded) ;
	const std::array requested{candidate.identity} ;							// 直接呼出しも実行しないことを確認する。
	const auto		 install = provider.install( 7U, requested, 0U, progress) ;	// 固定拒否結果。
	DRIVERCRATE_EXPECT( context, install.downloadOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, install.installOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, install.downloadError != 0 && install.installError != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Scan・Download・Install・OfficialNetwork、既定OFFと用途別固定hostを確認する。
 *
 * @param[in,out] context 回帰試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testRegistry( TestContext &context)
{
	const auto descriptors = builtInProviderDescriptors() ;	// Stable IDを正本とする登録一覧。
	const auto found = std::find_if( descriptors.begin(), descriptors.end(), []( const auto &value) {
		return value.id == BROADCOM_NET_XTREME_PROVIDER_ID ;
	}) ; // 対象Providerだけを検索する。
	DRIVERCRATE_EXPECT( context, found != descriptors.end()) ;
	// 対象Provider定義が見つからない場合は無効なiteratorを参照しない。
	if( found == descriptors.end()) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, !found->enabledByDefault) ;
	DRIVERCRATE_EXPECT( context, found->capabilities ==
									(capabilityMask( ProviderCapability::SCAN) |
									 capabilityMask( ProviderCapability::DOWNLOAD) |
									 capabilityMask( ProviderCapability::INSTALL) |
									 capabilityMask( ProviderCapability::OFFICIAL_NETWORK))) ;
	DRIVERCRATE_EXPECT( context, validateScanOptions( {.useDefaultProviders = false,
													 .enabledProviderIds  = {std::wstring(
														  BROADCOM_NET_XTREME_PROVIDER_ID)}})) ;
	DRIVERCRATE_EXPECT( context, validateBuiltInOfficialSourcePolicies()) ;
	// 製品JSON以外へ任意のqueryを送るhostを増やさない。
	const auto primary =
		officialSourceHosts( BROADCOM_NET_XTREME_PROVIDER_ID, OFFICIAL_PRIMARY_METADATA_RESOURCE_ID) ;
	// Document情報専用host。
	const auto secondary = officialSourceHosts( BROADCOM_NET_XTREME_PROVIDER_ID,
											   OFFICIAL_SECONDARY_METADATA_RESOURCE_ID) ;
	DRIVERCRATE_EXPECT( context, primary.size() == 1U && primary.front() == L"www.broadcom.com") ;
	DRIVERCRATE_EXPECT( context,
					   secondary.size() == 1U && secondary.front() == L"docs.broadcom.com") ;
	const auto payload = officialSourceHosts( BROADCOM_NET_XTREME_PROVIDER_ID,
											 OFFICIAL_PAYLOAD_RESOURCE_ID) ;	// ZIP専用host。
	DRIVERCRATE_EXPECT( context, payload.size() == 1U && payload.front() == L"docs.broadcom.com") ;
	// 用途数とredirect禁止を確認するpolicy。
	const auto *policy = officialSourcePolicyForProvider( BROADCOM_NET_XTREME_PROVIDER_ID) ;
	DRIVERCRATE_EXPECT( context, policy != nullptr && policy->resources.size() == 4U) ;
	// 取得元policyを取得できた場合にだけredirect制限を検証する。
	if( policy != nullptr) {
		// Redirectは全用途で禁止し、別hostへの自動委譲を許可しない。
		for( const auto &resource : policy->resources) {
			DRIVERCRATE_EXPECT( context, resource.maximumRedirects == 0U) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 実在する許諾本文を転載せず、既存検索fixtureから取得用の入力を作る。
 * @return 架空license識別子を含む合成document。
 */
//------------------------------------------------------------------------------
std::wstring preparedDocument()
{
	return changed( DOCUMENT, LR"("shareable_license":{)",
				   LR"("shareable_license":{"content_id":"fictional-license",)") ;
}

//------------------------------------------------------------------------------
/**
 * @brief 製品record・本文・ZIPを同じ配布物へ結合し、公表値の推測をしない。
 *
 * @param[in,out] context 回帰試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testPreparedDocument( TestContext &context)
{
	std::optional<BroadcomDriverRelease> release ;	// 製品側の合成record。
	DRIVERCRATE_EXPECT( context, parseBroadcomCatalog( catalog( RECORD), release)) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( !release) {
		return ;
	}

	OfficialReleaseRecord record ;							// 成功時の共通配布情報。
	const std::wstring	  document = preparedDocument() ;	// 実配布物を参照しない入力。
	DRIVERCRATE_EXPECT( context, parseBroadcomPreparedRelease( document, *release, record)) ;
	DRIVERCRATE_EXPECT( context, record.family == OfficialReleaseFamily::BROADCOM_NET_XTREME_E) ;
	DRIVERCRATE_EXPECT( context, record.packageVersion == L"100.2.3.4") ;
	DRIVERCRATE_EXPECT( context, record.fileName == L"Windows_Drivers-100.2.3.4.zip") ;
	DRIVERCRATE_EXPECT( context, record.eulaRevision == L"broadcom-license:fictional-license") ;
	DRIVERCRATE_EXPECT( context, record.eulaText == L"Fictional notice\r\nFictional conditions") ;
	DRIVERCRATE_EXPECT( context, !record.publishedSizeBytes && record.publishedSha256.empty()) ;
	const auto formatted = changed( document, L"Fictional notice",
								   L"<p><strong>Notice &amp; &#x41;</strong></p>") ;	// 合成HTML。
	DRIVERCRATE_EXPECT( context, parseBroadcomPreparedRelease( formatted, *release, record)) ;
	DRIVERCRATE_EXPECT( context, record.eulaText.starts_with( L"\r\nNotice & A\r\n")) ;
	DRIVERCRATE_EXPECT( context, record.eulaText.ends_with( L"Fictional conditions")) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 省略や誤表示になる本文・識別子を拒否し、既存表示専用検索は維持する。
 *
 * @param[in,out] context 回帰試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testPreparedDocumentRejection( TestContext &context)
{
	std::optional<BroadcomDriverRelease> release ;	// 変更しない製品側record。
	DRIVERCRATE_EXPECT( context, parseBroadcomCatalog( catalog( RECORD), release)) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( !release) {
		return ;
	}

	const std::wstring document = preparedDocument() ;	// 正常な合成本文の基準値。
	// 正常fixtureの一fieldだけを変え、出力初期化を含む拒否境界を調べる。
	for( const auto &mutation :
		std::initializer_list<std::pair<std::wstring_view, std::wstring_view>>{
			{L"fictional-license", L"invalid/license"},
			{L"Fictional notice", L"<script>hidden</script>"},
			{L"Fictional notice", L"<p"},
			{L"Fictional notice", L"&unknown;"},
			{L"Fictional notice", L"&#xD800;"},
			{L"Fictional notice", L"&#x110000;"},
			{L"Fictional notice", L"&#x202E;"},
			{L"Fictional notice", L"&#0;"},
			{L"Fictional notice", L"<div> </div>"}}) {
		OfficialReleaseRecord record ;	// 失敗時の残存値を検出する出力。
		record.eulaText = L"previous" ;
		DRIVERCRATE_EXPECT(
			context, !parseBroadcomPreparedRelease(
						 changed( document, mutation.first, mutation.second), *release, record)) ;
		DRIVERCRATE_EXPECT( context, record.family == OfficialReleaseFamily::UNKNOWN) ;
		DRIVERCRATE_EXPECT( context, record.eulaText.empty() && record.downloadUrl.empty()) ;
	}

	OfficialReleaseRecord record ;	// 取得用本文が不足する場合の出力。
	DRIVERCRATE_EXPECT( context, validateBroadcomDocument( DOCUMENT, *release)) ;
	DRIVERCRATE_EXPECT( context, !parseBroadcomPreparedRelease( DOCUMENT, *release, record)) ;
	DRIVERCRATE_EXPECT( context,
					   !parseBroadcomPreparedRelease(
						   changed( document, L"Fictional notice",
								   std::wstring( MAXIMUM_PREPARATION_EULA_CHARACTERS, L'A')),
						   *release, record)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ配布物に関係するdevice数を一対象へまとめ、本文に対する明示同意を要求する。
 *
 * @param[in,out] context 回帰試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testBroadcomPreparationTarget( TestContext &context)
{
	std::optional<BroadcomDriverRelease> release ;	// 架空の配布record。
	DRIVERCRATE_EXPECT( context, parseBroadcomCatalog( catalog( RECORD), release)) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( !release) {
		return ;
	}

	OfficialReleaseRecord record ;	// 対象化前のworker内metadata。
	DRIVERCRATE_EXPECT( context, parseBroadcomPreparedRelease( preparedDocument(), *release, record)) ;
	const auto targets = makeBroadcomPreparationTargets( record, 7U, 1U, 2U) ;	// 同型二台で一件。
	DRIVERCRATE_EXPECT( context, targets.size() == 1U) ;
	// 前提となる結果が揃わない場合は詳細検証を打ち切り、不正な要素参照による二次障害を防ぐ。
	if( targets.empty()) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, targets[0].deviceCount == 2U) ;
	DRIVERCRATE_EXPECT( context, targets[0].maximumBytes == 128ULL * 1024ULL * 1024ULL) ;
	DRIVERCRATE_EXPECT( context, targets[0].terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED) ;
	DRIVERCRATE_EXPECT( context, targets[0].eulaText == record.eulaText) ;
	OfficialPreparationSession	  session ;	// UIとworkerが共有する既存の承認境界。
	// 取得対象を固定session・計画ID・既定上限へ結合する架空準備計画。
	const OfficialPreparationPlan plan{7U, 1U, DEFAULT_OFFICIAL_PREPARATION_LIMITS, targets} ;
	DRIVERCRATE_EXPECT( context, session.initialize( plan) == OfficialPreparationError::NONE) ;
	OfficialPreparationApproval approval{
		9U, 7U, 1U, plan.limits, {{targets[0], true, false, false}}} ;	// EULA未同意の要求。
	DRIVERCRATE_EXPECT( context, session.approve( approval) != OfficialPreparationError::NONE) ;
	approval.decisions[0].eulaAccepted = true ;
	DRIVERCRATE_EXPECT( context, session.approve( approval) == OfficialPreparationError::NONE) ;
	DRIVERCRATE_EXPECT( context, session.claimNext().has_value()) ;
	DRIVERCRATE_EXPECT( context, makeBroadcomPreparationTargets( record, 0U, 1U, 1U).empty()) ;
	DRIVERCRATE_EXPECT( context, makeBroadcomPreparationTargets( record, 7U, 0U, 1U).empty()) ;
	DRIVERCRATE_EXPECT( context, makeBroadcomPreparationTargets( record, 7U, 1U, 0U).empty()) ;
	DRIVERCRATE_EXPECT( context, makeBroadcomPreparationTargets( record, 7U, 1U, 4097U).empty()) ;
	record.eulaText.clear() ;
	DRIVERCRATE_EXPECT( context, makeBroadcomPreparationTargets( record, 7U, 1U, 1U).empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全監査合格組合せだけを未選択候補へ変換し、同device／同版を重複排除する。
 *
 * @param[in,out] context 回帰試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testBroadcomPreparedCandidate( TestContext &context)
{
	OfficialCatalogDevice device ;	// 実PnP IDを持たない架空の現在device。
	device.deviceIdentity = L"fictional-broadcom-device" ;
	device.model		  = L"Broadcom NetXtreme-E Fictional Adapter" ;
	device.manufacturer	  = L"Broadcom" ;
	device.driverClass	  = L"Net" ;
	device.currentVersion = L"1.0.0.0" ;
	const std::array		  devices{device} ;	// 同じscanで系列照合済みのdevice snapshot。

	OfficialAcquisitionResult acquisition ;	// 架空のG11-B成功identity。
	acquisition.state		   = OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ;
	acquisition.scanSessionId  = 21U ;
	acquisition.acquisitionId  = 1U ;
	acquisition.providerId	   = BROADCOM_NET_XTREME_PROVIDER_ID ;
	acquisition.resourceId	   = OFFICIAL_PAYLOAD_RESOURCE_ID ;
	acquisition.inspectionPath = L"C:\\fictional\\broadcom.zip" ;
	acquisition.byteCount	   = 1024U ;
	acquisition.sha256		   = std::wstring( 64U, L'0') ;

	OfficialInfPackage package ;	// 内容監査済みとして保持する架空INF metadata。
	package.infRelativePath = L"fictional.inf" ;
	package.className		= L"Net" ;
	package.providerName	= L"Broadcom" ;
	package.driverDate		= L"09/06/2026" ;
	package.driverVersion	= L"2.0.0.0" ;
	OfficialAuditedInfPackage audited ;	// 実fileを参照しない候補変換専用閉包。
	audited.workspace = std::make_unique<OfficialDownloadWorkspace>() ;
	audited.profile	  = OfficialDriverAuditProfile::BROADCOM_NET_XTREME_E ;
	audited.closure.packages.push_back( std::move( package)) ;
	OfficialDriverPackageAudit audit ;	// 内容・適用性合格の合成保持結果。
	audit.scanSessionId			  = 21U ;
	audit.summary.state			  = OfficialDriverPackageAuditState::AUDITED ;
	audit.summary.infCount		  = 1U ;
	audit.summary.auditedInfCount = 1U ;
	audit.auditedPackages.push_back( std::move( audited)) ;
	OfficialDriverRankAudit rank ;	// G11-Dが返した架空の非機密rank結果。
	rank.decision = OfficialDriverRankDecision::APPLICABLE ;
	audit.rankApprovedTargets.push_back( {device.deviceIdentity, 0U, rank}) ;
	audit.rankApprovedTargets.push_back( {device.deviceIdentity, 0U, rank}) ;
	audit.applicability.state				= OfficialDriverApplicabilityState::APPLICABLE_TARGETS ;
	audit.applicability.examinedPairCount	= 2U ;
	audit.applicability.applicablePairCount = 2U ;

	const auto candidates =
		// 昇格結果。
		makeBroadcomPreparedCandidates( 21U, acquisition, devices, audit) ;
	DRIVERCRATE_EXPECT( context, candidates.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( !candidates.empty()) {
		const UpdateCandidate &candidate = candidates.front() ;	// 検証対象の新候補。
		DRIVERCRATE_EXPECT( context, candidate.identity == L"broadcom-driver:21:0") ;
		DRIVERCRATE_EXPECT( context, candidate.packageIdentity == L"broadcom-package:21:1") ;
		DRIVERCRATE_EXPECT( context, candidate.version == L"2.0.0.0") ;
		DRIVERCRATE_EXPECT( context, candidate.driverDate == L"2026/09/06") ;
		DRIVERCRATE_EXPECT( context, candidate.action == DriverAction::UPDATE) ;
		DRIVERCRATE_EXPECT( context, candidate.installable && !candidate.recommended) ;
		DRIVERCRATE_EXPECT( context,
						   candidate.audit.installReadiness == CandidateInstallReadiness::READY) ;
	}

	// 保持fileなしの取得identityへ差し替える。
	acquisition.inspectionPath.clear() ;
	bool rejected{} ;	// 不正取得identityが例外で拒否された場合true。
	try {
		static_cast<void>( makeBroadcomPreparedCandidates( 21U, acquisition, devices, audit)) ;
	} catch( const std::logic_error &) {
		rejected = true ;
	}

	DRIVERCRATE_EXPECT( context, rejected) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 外側取得fileと保持INFを同一sizeで差し替え、rank／installer到達前に拒否することを確認する。
 *
 * @param[in,out] context 回帰試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testBroadcomPreparedInstallTampering( TestContext &context)
{
	BroadcomPreparedInstallFixture archiveFixture ;	// 外側file差替え専用の所有fixture。
	DRIVERCRATE_EXPECT( context, initializePreparedInstallFixture( 31U, 1U, archiveFixture)) ;
	// Fixture初期化失敗後に非所有contextを作らない。
	if( archiveFixture.identities.empty()) {
		return ;
	}

	const std::wstring archivePath =
		archiveFixture.acquisition.inspectionPath ;	// 同一size差替え対象の外側file。
	DRIVERCRATE_EXPECT( context, replaceFirstByte( archivePath, std::byte{0x11}) == 0) ;
	std::size_t					archiveReverifyCalls{} ;	// 外側hash不一致後の閉包callback呼出し数。
	std::size_t					archiveRankCalls{} ;		// 外側hash不一致後のrank callback呼出し数。
	std::size_t					archiveInstallCalls{} ;		// 外側hash不一致後のinstaller呼出し数。
	const BroadcomInfReverifier archiveReverifier =
		[&archiveReverifyCalls]( const OfficialAuditedInfPackage &) -> NativeError {
		++archiveReverifyCalls ;
		return 0 ;
	} ; // 呼ばれた場合に後段到達を検出するfake閉包再検証。
	const OfficialInfRankAuditor archiveRank =
		[&archiveRankCalls]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
							const OfficialInfPackage &, OfficialDriverRankAudit &) -> NativeError {
		++archiveRankCalls ;
		return 0 ;
	} ; // 呼ばれた場合に外側検証の順序違反を検出するfake rank監査。
	const BroadcomVerifiedInfInstaller archiveInstaller =
		[&archiveInstallCalls]( ScanSessionId, std::wstring_view, std::wstring_view,
							   std::wstring_view, std::wstring_view, std::uintptr_t,
							   bool &) -> NativeError {
		++archiveInstallCalls ;
		return 0 ;
	} ; // 呼ばれた場合にsystem変更境界への誤到達を検出するfake導入。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {} ;	// 確定進捗受信先。
	const InstallResult			   archiveResult = executeBroadcomPreparedInstall(
		   preparedInstallContext( archiveFixture), archiveFixture.identities, archiveReverifier,
		   archiveRank, archiveInstaller, 0U,
		   progress) ;	// 改ざん済み外側fileの結果。
	DRIVERCRATE_EXPECT( context, archiveResult.downloadOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, archiveResult.installOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, archiveReverifyCalls == 0U) ;
	DRIVERCRATE_EXPECT( context, archiveRankCalls == 0U) ;
	DRIVERCRATE_EXPECT( context, archiveInstallCalls == 0U) ;

	BroadcomPreparedInstallFixture infFixture ;	// 保持INF差替え専用の所有fixture。
	DRIVERCRATE_EXPECT( context, initializePreparedInstallFixture( 32U, 1U, infFixture)) ;
	// Fixture初期化失敗時は保持workspaceを参照しない。
	if( infFixture.auditedPackages.empty()) {
		return ;
	}

	constexpr std::array<std::byte, 4> INF_BYTES{std::byte{0x41}, std::byte{0x42}, std::byte{0x43},
												 std::byte{0x44}} ;						// 架空INF内容。
	OfficialAuditedInfPackage		  &audited = infFixture.auditedPackages.front() ;	// 保持閉包。
	std::wstring					   infHash ;										// 差替え前の保持INF SHA-256。
	DRIVERCRATE_EXPECT( context, storeFixtureFile( *audited.workspace, L"driver\\fictional.inf",
												 INF_BYTES, infHash) == 0) ;
	audited.closure.entries.push_back( {.relativePath	 = L"driver\\fictional.inf",
									   .uncompressedSize = INF_BYTES.size(),
									   .sha256			 = infHash}) ;
	const std::wstring infPath =
		// 閉包差替え対象の絶対path。
		audited.workspace->path( L"driver\\fictional.inf") ;
	DRIVERCRATE_EXPECT( context, replaceFirstByte( infPath, std::byte{0x45}) == 0) ;
	std::size_t					infReverifyCalls{} ;	// 実閉包再検証の呼出し数。
	std::size_t					infRankCalls{} ;		// 閉包不一致後のrank callback呼出し数。
	std::size_t					infInstallCalls{} ;		// 閉包不一致後のinstaller呼出し数。
	const BroadcomInfReverifier infReverifier =
		[&infReverifyCalls]( const OfficialAuditedInfPackage &package) -> NativeError {
		++infReverifyCalls ;
		return reverifyOfficialAuditedInfPackage( package) ;
	} ; // 本番と同じ全file snapshot再検証。
	const OfficialInfRankAuditor infRank =
		[&infRankCalls]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
						const OfficialInfPackage &, OfficialDriverRankAudit &) -> NativeError {
		++infRankCalls ;
		return 0 ;
	} ; // 呼ばれた場合に閉包検証の順序違反を検出するfake rank監査。
	const BroadcomVerifiedInfInstaller infInstaller =
		[&infInstallCalls]( ScanSessionId, std::wstring_view, std::wstring_view, std::wstring_view,
						   std::wstring_view, std::uintptr_t, bool &) -> NativeError {
		++infInstallCalls ;
		return 0 ;
	} ; // 呼ばれた場合に差替えINFの誤導入を検出するfake導入。
	const InstallResult infResult = executeBroadcomPreparedInstall(
		preparedInstallContext( infFixture), infFixture.identities, infReverifier, infRank,
		infInstaller, 0U, progress) ;	// 改ざん済み保持INFの結果。
	DRIVERCRATE_EXPECT( context, infResult.downloadOutcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, infResult.installOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, infReverifyCalls == 1U) ;
	DRIVERCRATE_EXPECT( context, infRankCalls == 0U) ;
	DRIVERCRATE_EXPECT( context, infInstallCalls == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 導入直前rankが取得後監査と変わった場合、再検索要求でinstallerを呼ばない。
 *
 * @param[in,out] context 回帰試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testBroadcomPreparedInstallRankChange( TestContext &context)
{
	BroadcomPreparedInstallFixture fixture ;	// Rank変化専用の所有fixture。
	DRIVERCRATE_EXPECT( context, initializePreparedInstallFixture( 33U, 1U, fixture)) ;
	// Fixture初期化失敗後にroutingを参照しない。
	if( fixture.targets.empty()) {
		return ;
	}

	const OfficialDriverRankAudit expectedRank =
		// 取得後監査時の固定rank。
		fixture.targets.begin()->second.rankAudit ;
	std::size_t					installerCalls{} ;	// Rank不一致後のinstaller呼出し数。
	const BroadcomInfReverifier reverifier = []( const OfficialAuditedInfPackage &) -> NativeError {
		return 0 ;
	} ; // 合格するfake閉包再検証。
	const OfficialInfRankAuditor rank =
		[expectedRank]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
					   const OfficialInfPackage &,
					   OfficialDriverRankAudit &current) -> NativeError {
		current = expectedRank ;
		++current.candidateRank ;
		return 0 ;
	} ; // 一fieldだけ変化した現在rankを返すfake監査。
	const BroadcomVerifiedInfInstaller installer =
		[&installerCalls]( ScanSessionId, std::wstring_view, std::wstring_view, std::wstring_view,
						  std::wstring_view, std::uintptr_t, bool &) -> NativeError {
		++installerCalls ;
		return 0 ;
	} ; // 呼ばれた場合にrank拒否の迂回を検出するfake導入。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {} ;	// 確定進捗受信先。
	const InstallResult			   result	= executeBroadcomPreparedInstall(
		 preparedInstallContext( fixture), fixture.identities, reverifier, rank, installer, 0U,
		 progress) ;	// Rank変化後の導入結果。
	DRIVERCRATE_EXPECT( context, result.downloadOutcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, result.installOutcome == OutcomeCode::FAILURE) ;
	DRIVERCRATE_EXPECT( context, result.installError ==
									static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY))) ;
	DRIVERCRATE_EXPECT( context, installerCalls == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じpayloadの二deviceで一件成功・一件失敗を保持し、全体成功にしない。
 *
 * @param[in,out] context 回帰試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testBroadcomPreparedInstallPartialFailure( TestContext &context)
{
	BroadcomPreparedInstallFixture fixture ;	// 二deviceの部分失敗専用fixture。
	DRIVERCRATE_EXPECT( context, initializePreparedInstallFixture( 34U, 2U, fixture)) ;
	// 不完全routingを部分成功testへ使用しない。
	if( fixture.targets.size() != 2U) {
		return ;
	}

	const OfficialDriverRankAudit expectedRank =
		// 両deviceで返す取得後監査rank。
		fixture.targets.begin()->second.rankAudit ;
	std::size_t					  reverifyCalls{} ;		// 同じ保持INF閉包の再検証回数。
	std::size_t					  rankCalls{} ;			// Device別rank再監査回数。
	std::size_t					  installerCalls{} ;	// Device別installer呼出し回数。
	std::vector<ProviderProgress> progressEvents ;		// 確定順序で受信する進捗event群。
	const BroadcomInfReverifier	  reverifier =
		[&reverifyCalls]( const OfficialAuditedInfPackage &) -> NativeError {
		++reverifyCalls ;
		return 0 ;
	} ; // 同じINF indexに対するcache回数を確認するfake再検証。
	const OfficialInfRankAuditor rank =
		[&rankCalls, expectedRank]( ScanSessionId, std::wstring_view,
								   const OfficialDownloadWorkspace &, const OfficialInfPackage &,
								   OfficialDriverRankAudit &current) -> NativeError {
		++rankCalls ;
		current = expectedRank ;
		return 0 ;
	} ; // 各deviceで取得後rankと完全一致するfake監査。
	const BroadcomVerifiedInfInstaller installer =
		[&installerCalls]( ScanSessionId, const std::wstring_view deviceIdentity, std::wstring_view,
						  std::wstring_view, std::wstring_view, std::uintptr_t,
						  bool &rebootRequired) -> NativeError {
		++installerCalls ;
		// 先頭の架空deviceだけを再起動付き成功とし、後続の失敗と集約させる。
		if( deviceIdentity.ends_with( L":0")) {
			rebootRequired = true ;
			return 0 ;
		}

		rebootRequired = false ;
		return static_cast<NativeError>( E_FAIL) ;
	} ; // 先頭deviceだけ成功し、再起動を要求するfake導入。
	const ProviderProgressCallback progress = [&progressEvents]( const ProviderProgress &value) {
		progressEvents.push_back( value) ;
	} ; // Executorが通知した確定進捗の所有先。
	const InstallResult result = executeBroadcomPreparedInstall(
		preparedInstallContext( fixture), fixture.identities, reverifier, rank, installer, 42U,
		progress) ;	// 二deviceの部分失敗結果。
	DRIVERCRATE_EXPECT( context, !result.succeeded) ;
	DRIVERCRATE_EXPECT( context, result.downloadOutcome == OutcomeCode::SUCCESS) ;
	DRIVERCRATE_EXPECT( context, result.installOutcome == OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
	DRIVERCRATE_EXPECT( context, result.installError == static_cast<NativeError>( E_FAIL)) ;
	DRIVERCRATE_EXPECT( context, result.rebootRequired) ;
	DRIVERCRATE_EXPECT( context, result.updates.size() == 2U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( result.updates.size() == 2U) {
		DRIVERCRATE_EXPECT( context, result.updates[0].installOutcome == OutcomeCode::SUCCESS) ;
		DRIVERCRATE_EXPECT( context, result.updates[0].rebootRequired) ;
		DRIVERCRATE_EXPECT( context, result.updates[1].installOutcome == OutcomeCode::FAILURE) ;
		DRIVERCRATE_EXPECT( context,
						   result.updates[1].installError == static_cast<NativeError>( E_FAIL)) ;
	}

	DRIVERCRATE_EXPECT( context, reverifyCalls == 1U) ;
	DRIVERCRATE_EXPECT( context, rankCalls == 2U) ;
	DRIVERCRATE_EXPECT( context, installerCalls == 2U) ;
	DRIVERCRATE_EXPECT( context, progressEvents.size() == 4U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( !progressEvents.empty()) {
		DRIVERCRATE_EXPECT( context, progressEvents.back().percentComplete == 100U) ;
		DRIVERCRATE_EXPECT( context, progressEvents.back().completedItems == 2U) ;
		DRIVERCRATE_EXPECT( context, progressEvents.back().totalItems == 2U) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 検索・計画なしの取得要求はnetwork・workspace初期化へ進めない。
 *
 * @param[in,out] context 回帰試験のassertion集計先。
 */
//------------------------------------------------------------------------------
void testBroadcomUnpreparedDownload( TestContext &context)
{
	BroadcomUpdateProvider	provider ;	// HTTPを開始しない空の本番Provider。
	OfficialPreparationTask task ;		// 承認・計画を持たない要求。
	task.operationId	   = 1U ;
	task.scanSessionId	   = 1U ;
	task.planId			   = 1U ;
	task.target.providerId = std::wstring( BROADCOM_NET_XTREME_PROVIDER_ID) ;
	const auto result	   = provider.acquireForInspection( task, {}) ;	// 入力照合だけの拒否結果。
	DRIVERCRATE_EXPECT( context, result.state == OfficialPreparationItemState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, result.error == static_cast<NativeError>( E_INVALIDARG)) ;
	DRIVERCRATE_EXPECT( context, result.byteCount == 0U) ;
	DRIVERCRATE_EXPECT( context, provider.preparationTargets( 1U, 1U).empty()) ;
	DRIVERCRATE_EXPECT( context, !provider.preparationAuditSummary( 1U).has_value()) ;
	const std::array<std::wstring, 1> identities{L"broadcom-driver:1:0"} ;			// 未発行候補ID。
	const ProviderProgressCallback progress = []( const ProviderProgress &) {} ;	// 未呼出し通知先。
	const InstallResult install = provider.install( 1U, identities, 0U, progress) ;	// 事前拒否。
	DRIVERCRATE_EXPECT( context, install.downloadError == static_cast<NativeError>( E_INVALIDARG)) ;
	DRIVERCRATE_EXPECT( context, install.installError == static_cast<NativeError>( E_INVALIDARG)) ;
	DRIVERCRATE_EXPECT( context, install.updates.size() == 1U) ;
	provider.invalidatePreparation() ;
	DRIVERCRATE_EXPECT( context, provider.preparationTargets( 1U, 2U).empty()) ;
	DRIVERCRATE_EXPECT( context, !provider.preparationAuditSummary( 0U).has_value()) ;
	DRIVERCRATE_EXPECT( context, !provider.preparationAuditSummary( 1U).has_value()) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/broadcom_official_provider_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runBroadcomOfficialProviderTests( TestContext &context)
{
	testCatalog( context) ;
	testDocument( context) ;
	testProviderBoundary( context) ;
	testRegistry( context) ;
	testPreparedDocument( context) ;
	testPreparedDocumentRejection( context) ;
	testBroadcomPreparationTarget( context) ;
	testBroadcomPreparedCandidate( context) ;
	testBroadcomPreparedInstallTampering( context) ;
	testBroadcomPreparedInstallRankChange( context) ;
	testBroadcomPreparedInstallPartialFailure( context) ;
	testBroadcomUnpreparedDownload( context) ;
}

} // namespace drivercrate::test
