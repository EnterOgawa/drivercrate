//------------------------------------------------------------------------------
/**
 * @file nvidia_winof2_driver_audit_tests.cpp
 * @brief WinOF-2内容・PnP監査と候補発行単体試験実装。
 * @version 01.00.00
 * @date 2026/09/07
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  共通test framework includeへ修正。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 架空閉包と差替え監査でCAT、publisher、x64、PnP、rank拒否を確認し、実driverまたはinstallを実行しません。
 */
//------------------------------------------------------------------------------

#include "nvidia_winof2_driver_audit_tests.h"

#include "test_framework.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/nvidia_winof2_driver_audit.h"
#include "platform/official_download_workspace.h"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr ScanSessionId		SESSION		   = 91U ;	// 正常fixtureのscan session。
constexpr std::uint64_t		ACQUISITION_ID = 7U ;	// 正常fixtureの公式取得連番。
constexpr std::wstring_view SHA256 =
	L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ;	// 架空SHA-256。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Networkや実fileを使用せず、identity contractだけを作る。
 *
 * @param[in] session 架空scan session。
 * @param[in] acquisitionId 架空の公式取得連番。
 * @return 公開hash照合済みWinOF-2 payload取得結果。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialAcquisitionResult makeAcquisition( const ScanSessionId session,
														const std::uint64_t acquisitionId)
{
	OfficialAcquisitionResult acquisition ;	// 外側WinOF-2 EXEの架空取得結果。
	acquisition.state					= OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ;
	acquisition.scanSessionId			= session ;
	acquisition.acquisitionId			= acquisitionId ;
	acquisition.providerId				= std::wstring( NVIDIA_WINOF2_PROVIDER_ID) ;
	acquisition.resourceId				= std::wstring( OFFICIAL_PAYLOAD_RESOURCE_ID) ;
	acquisition.inspectionPath			= L"C:\\fictional\\winof2.exe" ;
	acquisition.byteCount				= 4096U ;
	acquisition.sha256					= SHA256 ;
	acquisition.publishedSizeVerified	= true ;
	acquisition.publishedSha256Verified = true ;
	return acquisition ;
}

//------------------------------------------------------------------------------
/**
 * @brief Makerと版だけを設定し、PnP IDは差替えrank境界内に留める。
 *
 * @param[in] deviceClass 架空deviceのsetup class。
 * @return Hardware IDを含まない同一scanのdevice snapshot。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialCatalogDevice makeDevice( const std::wstring_view deviceClass)
{
	OfficialCatalogDevice device ;	// WinOF-2対象の架空local device。
	device.deviceIdentity  = L"device-91-1" ;
	device.model		   = L"Fictional NVIDIA Networking Adapter" ;
	device.manufacturer	   = L"Mellanox Technologies" ;
	device.driverClass	   = deviceClass ;
	device.deviceClassGuid = L"{00000000-0000-0000-0000-000000000001}" ;
	device.currentProvider = L"Mellanox" ;
	device.currentVersion  = L"26.6.10000.0" ;
	device.currentDate	   = L"2026/01/01" ;
	return device ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実file内容を持たず、差替えreverifierへ渡すmetadataを作る。
 *
 * @param[in] session 閉包のscan session。
 * @param[in] acquisitionId 外側公式payloadの取得連番。
 * @param[in] deviceClass INFのsetup class。
 * @param[in] infName 選択した論理INF名。
 * @return CAT再検証前の架空WinOF-2 driver閉包。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NvidiaWinof2DriverClosure makeDriverClosure( const ScanSessionId	  session,
														  const std::uint64_t	  acquisitionId,
														  const std::wstring_view deviceClass,
														  const std::wstring_view infName)
{
	OfficialInfPackage package ;	// Windows x64構造監査済みを模倣するINF metadata。
	package.infRelativePath		= infName ;
	package.catalogRelativePath = L"mlx5.cat" ;
	package.className			= deviceClass ;
	package.providerName		= L"Mellanox" ;
	package.driverDate			= L"07/19/2026" ;
	package.driverVersion		= L"26.7.27199.0" ;
	package.hardwareIds.push_back( L"PCI\\VEN_FAKE&DEV_FAKE") ;
	package.sourceFiles.push_back( L"mlx5.sys") ;

	NvidiaWinof2DriverClosure driverClosure ;	// 後段identity付きの架空閉包結果。
	driverClosure.scanSessionId		  = session ;
	driverClosure.sourceAcquisitionId = acquisitionId ;
	driverClosure.databaseSize		  = 2048U ;
	driverClosure.databaseSha256	  = SHA256 ;
	driverClosure.selectedInfPath	  = infName ;
	driverClosure.cabinetFileCount	  = 4U ;
	driverClosure.closure.entries.push_back( {.relativePath	   = std::wstring( infName),
											 .uncompressedSize = 16U,
											 .sha256		   = std::wstring( SHA256)}) ;
	driverClosure.closure.entries.push_back(
		{.relativePath = L"mlx5.cat", .uncompressedSize = 16U, .sha256 = std::wstring( SHA256)}) ;
	driverClosure.closure.entries.push_back(
		{.relativePath = L"mlx5.sys", .uncompressedSize = 16U, .sha256 = std::wstring( SHA256)}) ;
	driverClosure.closure.packages.push_back( std::move( package)) ;
	driverClosure.closure.archiveDepth	= 1U ;
	driverClosure.closure.expandedBytes = 48U ;
	return driverClosure ;
}

//------------------------------------------------------------------------------
/**
 * @brief PnP ID文字列を結果へ複写せず、後段の候補発行だけを試す。
 *
 * @param[in,out] callCount 呼出しごとに加算する試験用件数。
 * @return 全入力をApplicableとする差替えrank auditor。
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialInfRankAuditor makeApplicableRankAuditor( std::size_t &callCount)
{
	return [&callCount]( const ScanSessionId, const std::wstring_view,
						const OfficialDownloadWorkspace &, const OfficialInfPackage &,
						OfficialDriverRankAudit &rankAudit) {
		++callCount ;
		rankAudit.decision		= OfficialDriverRankDecision::APPLICABLE ;
		rankAudit.currentRank	= 0x00001000U ;
		rankAudit.candidateRank = 0x00001000U ;
		return NativeError{} ;
	} ;
}

//------------------------------------------------------------------------------
/**
 * @brief CAT、PnP、rank合格時だけBlocked候補を一件発行する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testAuditedCandidate( TestContext &context)
{
	const OfficialAcquisitionResult acquisition =
		// 同一scanの外側取得identity。
		makeAcquisition( SESSION, ACQUISITION_ID) ;
	const std::vector devices{makeDevice( L"Net")} ;					// 一件の監査対象device。
	auto workspace = std::make_unique<OfficialDownloadWorkspace>() ;	// 架空閉包の単独所有領域。
	NvidiaWinof2DriverClosure driverClosure =
		// 正常閉包。
		makeDriverClosure( SESSION, ACQUISITION_ID, L"Net", L"mlx5.inf") ;
	std::size_t							reverifyCount{} ;	// 内容再検証の呼出し件数。
	const NvidiaWinof2ClosureReverifier reverifier =
		[&reverifyCount]( const OfficialAuditedInfPackage &package) {
			++reverifyCount ;
			return package.profile == OfficialDriverAuditProfile::NVIDIA_WINOF2
					   ? NativeError{}
					   : static_cast<NativeError>( E_UNEXPECTED) ;
		} ; // CAT、publisher、x64合格を模倣する差替え境界。
	std::size_t					 rankCount{} ;	// Local PnP／rank監査の呼出し件数。
	const OfficialInfRankAuditor rankAuditor =
		// Applicableを返す試験境界。
		makeApplicableRankAuditor( rankCount) ;
	NvidiaWinof2DriverAudit audit ;	// 取得identity、内容、適用性の監査結果。
	DRIVERCRATE_EXPECT( context, auditNvidiaWinof2DriverClosureForTesting(
									acquisition, std::move( workspace), std::move( driverClosure),
									devices, reverifier, rankAuditor, audit) == 0) ;
	DRIVERCRATE_EXPECT( context, reverifyCount == 1U) ;
	DRIVERCRATE_EXPECT( context, rankCount == 1U) ;
	DRIVERCRATE_EXPECT( context, audit.scanSessionId == SESSION) ;
	DRIVERCRATE_EXPECT( context, audit.sourceAcquisitionId == ACQUISITION_ID) ;
	DRIVERCRATE_EXPECT( context, audit.databaseSha256 == SHA256) ;
	DRIVERCRATE_EXPECT( context, audit.selectedInfPath == L"mlx5.inf") ;
	DRIVERCRATE_EXPECT( context,
					   audit.package.summary.state == OfficialDriverPackageAuditState::AUDITED) ;
	DRIVERCRATE_EXPECT( context, audit.package.applicability.state ==
									OfficialDriverApplicabilityState::APPLICABLE_TARGETS) ;

	const std::vector<UpdateCandidate> candidates =
		// 発行結果。
		makeNvidiaWinof2AuditedCandidates( acquisition, devices, audit) ;
	DRIVERCRATE_EXPECT( context, candidates.size() == 1U) ;
	DRIVERCRATE_EXPECT( context, candidates.front().version == L"26.7.27199.0") ;
	DRIVERCRATE_EXPECT( context, candidates.front().action == DriverAction::UPDATE) ;
	DRIVERCRATE_EXPECT( context, !candidates.front().installable) ;
	DRIVERCRATE_EXPECT( context, !candidates.front().recommended) ;
	DRIVERCRATE_EXPECT( context, !candidates.front().eulaAccepted) ;
	DRIVERCRATE_EXPECT( context, candidates.front().allContentCached) ;
	DRIVERCRATE_EXPECT( context, candidates.front().audit.contentIntegrity ==
									CandidateAuditGateState::PASSED) ;
	DRIVERCRATE_EXPECT( context, candidates.front().audit.systemApplicability ==
									CandidateAuditGateState::PASSED) ;
	DRIVERCRATE_EXPECT( context, candidates.front().audit.installReadiness ==
									CandidateInstallReadiness::BLOCKED) ;

	const OfficialAcquisitionResult otherAcquisition =
		// 同一session内の別取得identity。
		makeAcquisition( SESSION, ACQUISITION_ID + 1U) ;
	bool substitutionRejected{} ;	// 別取得結果からのpackage ID再発行を拒否した場合true。
	try {
		static_cast<void>( makeNvidiaWinof2AuditedCandidates( otherAcquisition, devices, audit)) ;
	} catch( const std::logic_error &) {
		// 期待するfail-closed経路。
		substitutionRejected = true ;
	}

	DRIVERCRATE_EXPECT( context, substitutionRejected) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 内容拒否後にrank auditorを呼ばず、閉包を合格集合へ残さない。
 *
 * @param[in,out] context Assertion集計先。
 * @param[in] rejection CAT、publisher、x64または閉包拒否診断値。
 */
//------------------------------------------------------------------------------
void expectContentRejection( TestContext &context, const NativeError rejection)
{
	const OfficialAcquisitionResult acquisition =
		// 正常な外側取得identity。
		makeAcquisition( SESSION, ACQUISITION_ID) ;
	const std::vector devices{makeDevice( L"Net")} ;	// 一件の対象device。
	auto			  workspace =
		std::make_unique<OfficialDownloadWorkspace>() ;	// 拒否後に破棄される閉包所有領域。
	NvidiaWinof2DriverClosure driverClosure =
		// 入力閉包。
		makeDriverClosure( SESSION, ACQUISITION_ID, L"Net", L"mlx5.inf") ;
	const NvidiaWinof2ClosureReverifier reverifier =
		[rejection]( const OfficialAuditedInfPackage &) { return rejection ; } ;	// 内容拒否境界。
	std::size_t					 rankCount{} ;										// 拒否時に0のままであるべきrank呼出し件数。
	const OfficialInfRankAuditor rankAuditor =
		// 呼ばれてはならない境界。
		makeApplicableRankAuditor( rankCount) ;
	NvidiaWinof2DriverAudit audit ;	// 取得identity付きの拒否状態と診断値。
	DRIVERCRATE_EXPECT( context, auditNvidiaWinof2DriverClosureForTesting(
									acquisition, std::move( workspace), std::move( driverClosure),
									devices, reverifier, rankAuditor, audit) == rejection) ;
	DRIVERCRATE_EXPECT( context, rankCount == 0U) ;
	DRIVERCRATE_EXPECT( context,
					   audit.package.summary.state == OfficialDriverPackageAuditState::REJECTED) ;
	DRIVERCRATE_EXPECT( context, audit.package.summary.firstRejectionError == rejection) ;
	DRIVERCRATE_EXPECT( context, audit.package.auditedPackages.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief CAT member、publisher、Windows x64、参照file拒否を分けてPnP監査前に停止する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testContentRejections( TestContext &context)
{
	expectContentRejection(
		context, static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CRC))) ;	// CAT member不一致。
	expectContentRejection( context,
						   // Publisher不一致。
						   static_cast<NativeError>( E_ACCESSDENIED)) ;
	expectContentRejection( context,
						   // Windows x64不成立。
						   static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_BAD_FORMAT))) ;
	expectContentRejection( context,
						   // RShim参照欠落。
						   static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND))) ;
}

//------------------------------------------------------------------------------
/**
 * @brief PnP ID不一致とfull rank退行を候補なしとして保持する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testPnpAndRankRejections( TestContext &context)
{
	const std::array decisions{OfficialDriverRankDecision::CANDIDATE_NOT_MATCHED,
							   OfficialDriverRankDecision::OVERALL_RANK_REGRESSION} ;	// 拒否判断群。
	// 各policy拒否を独立監査し、いずれも候補発行対象を残さないことを確認する。
	for( const OfficialDriverRankDecision decision : decisions) {
		const OfficialAcquisitionResult acquisition =
			// 正常外側取得identity。
			makeAcquisition( SESSION, ACQUISITION_ID) ;
		const std::vector devices{makeDevice( L"Net")} ;					// 一件の対象device。
		auto workspace = std::make_unique<OfficialDownloadWorkspace>() ;	// 架空閉包所有領域。
		NvidiaWinof2DriverClosure driverClosure =
			// 正常閉包。
			makeDriverClosure( SESSION, ACQUISITION_ID, L"Net", L"mlx5.inf") ;
		const NvidiaWinof2ClosureReverifier reverifier = []( const OfficialAuditedInfPackage &) {
			return NativeError{} ;
		} ; // 内容合格境界。
		const OfficialInfRankAuditor rankAuditor =
			[decision]( const ScanSessionId, const std::wstring_view,
					   const OfficialDownloadWorkspace &, const OfficialInfPackage &,
					   OfficialDriverRankAudit &rankAudit) {
				rankAudit.decision = decision ;
				return NativeError{} ;
			} ; // 現在のpolicy拒否を返すPnP／rank境界。
		NvidiaWinof2DriverAudit audit ;	// 取得identity付きの候補なし適用性結果。
		DRIVERCRATE_EXPECT( context, auditNvidiaWinof2DriverClosureForTesting(
										acquisition, std::move( workspace), std::move( driverClosure),
										devices, reverifier, rankAuditor, audit) == 0) ;
		DRIVERCRATE_EXPECT( context, audit.package.applicability.state ==
										OfficialDriverApplicabilityState::NO_APPLICABLE_TARGETS) ;
		DRIVERCRATE_EXPECT( context, audit.package.rankApprovedTargets.empty()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Stale取得連番とDisplay classを内容監査前に拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testIdentityAndDeviceRejections( TestContext &context)
{
	const OfficialAcquisitionResult acquisition =
		// 正常外側取得identity。
		makeAcquisition( SESSION, ACQUISITION_ID) ;
	const NvidiaWinof2ClosureReverifier reverifier = []( const OfficialAuditedInfPackage &) {
		return NativeError{} ;
	} ; // 呼ばれてはならない境界。
	std::size_t					 rankCount{} ;	// 入力拒否時に0のままであるべき件数。
	const OfficialInfRankAuditor rankAuditor =
		// 呼ばれてはならない境界。
		makeApplicableRankAuditor( rankCount) ;

	const std::vector netDevices{makeDevice( L"Net")} ;						// 正常classのdevice群。
	auto staleWorkspace = std::make_unique<OfficialDownloadWorkspace>() ;	// Stale閉包所有領域。
	NvidiaWinof2DriverClosure staleClosure =
		// 別取得連番。
		makeDriverClosure( SESSION, ACQUISITION_ID + 1U, L"Net", L"mlx5.inf") ;
	NvidiaWinof2DriverAudit staleAudit ;	// 取得連番のIdentity拒否結果。
	DRIVERCRATE_EXPECT( context, auditNvidiaWinof2DriverClosureForTesting(
									acquisition, std::move( staleWorkspace), std::move( staleClosure),
									netDevices, reverifier, rankAuditor, staleAudit) != 0) ;

	const std::vector displayDevices{makeDevice( L"Display")} ;				// 対象外Display device群。
	auto displayWorkspace = std::make_unique<OfficialDownloadWorkspace>() ;	// 対象外閉包所有領域。
	NvidiaWinof2DriverClosure displayClosure =
		// 対象外class。
		makeDriverClosure( SESSION, ACQUISITION_ID, L"Display", L"mlx5.inf") ;
	NvidiaWinof2DriverAudit displayAudit ;	// Display class拒否結果。
	DRIVERCRATE_EXPECT( context,
					   auditNvidiaWinof2DriverClosureForTesting(
						   acquisition, std::move( displayWorkspace), std::move( displayClosure),
						   displayDevices, reverifier, rankAuditor, displayAudit) != 0) ;
	DRIVERCRATE_EXPECT( context, rankCount == 0U) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/nvidia_winof2_driver_audit_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runNvidiaWinof2DriverAuditTests( TestContext &context)
{
	testAuditedCandidate( context) ;
	testContentRejections( context) ;
	testPnpAndRankRejections( context) ;
	testIdentityAndDeviceRejections( context) ;
}

} // namespace drivercrate::test
