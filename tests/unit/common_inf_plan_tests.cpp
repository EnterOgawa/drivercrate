//------------------------------------------------------------------------------
/**
 * @file common_inf_plan_tests.cpp
 * @brief 共通単一INF準備計画の封印所有・拒否・rollbackを非導入で検証する。
 * @version 01.00.00
 * @date 2026/10/06
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  非通信取得とfake内容／bindingの独立試験を追加。
 * </pre>
 *
 * @note 通常内容関数のfakeはこのEXEだけに定義する。製品policy・署名を変更しない。
 * 実通信・実PnP・staging・復元ポイント・導入・installerを呼ばない。
 * @see docs/adr/0285-common-inf-plan-factory.md
 */
//------------------------------------------------------------------------------
#include "platform/common_inf_plan.h"
#include "platform/official_file_verifier.h"
#include "core/provider_registry.h"
#include "core/official_source_policy.h"
#include "test_framework.h"

#include <Windows.h>
#include <iostream>
#include <functional>
#include <memory>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

constexpr wchar_t ABC_HASH[] =
	L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ;	// 架空abcの固定hash。
thread_local bool rejectContent{} ;											// 試験専用の全体解析失敗。
thread_local bool rejectReverify{} ;										// 試験専用の内容再検証失敗。
thread_local bool dependency{} ;											// 試験専用の明示依存観測。
thread_local bool rejectedInf{} ;											// 試験専用の個別署名拒否。

/** @brief 架空3 byteを既に開いたfixture fileへ書く。
 * @param[in] file 所有外の書込み可能handle。
 * @return 正確な全byte書込み0、失敗はHRESULT。
 */
NativeError		  writeFixture( HANDLE file)
{
	DWORD written{} ;	// 実確定書込み量。
	return WriteFile( file, "abc", 3U, &written, nullptr) && written == 3U ? 0 : E_FAIL ;
}

/** @brief 真のHTTPを行わずabcだけを取得境界へ返す。 */
class FixtureTransport final : public IOfficialAcquisitionTransport {
public:
	/** @brief この固定source試験ではdelegated GETを扱わない。
	 * @param[in,out] request 消費しない未対応request。
	 * @param[in] file 書き込まない出力handle。
	 * @param[in] progress 使用しない進捗通知。
	 * @param[in] cancellation 使用しない取消し照会。
	 * @param[out] destination 未確認の空結果。
	 * @return 常にE_NOTIMPL。
	 */
	NativeError downloadDelegated( OfficialDelegatedGetRequest &request, HANDLE file,
								  const HttpDownloadProgressCallback &progress,
								  const HttpCancellationCallback	 &cancellation,
								  OfficialPublicDestinationEvidence	 &destination) override
	{
		static_cast<void>( request) ;
		static_cast<void>( file) ;
		static_cast<void>( progress) ;
		static_cast<void>( cancellation) ;
		destination = {} ;
		return E_NOTIMPL ;
	}
	/** @brief 架空本文だけを保存する。
	 * @param[in] url 実通信しない架空fileの公式host形式URL。
	 * @param[in] resource 取得層が確認する用途。
	 * @param[in] maximum 許可byte予算。
	 * @param[in] file 架空byte出力handle。
	 * @param[in] progress 試験では使用しない通知先。
	 * @param[in] cancellation 試験では使用しない取消し照会。
	 * @return 全byte保存0、失敗はHRESULT。
	 */
	NativeError download( std::wstring_view url, std::wstring_view resource, std::uint64_t maximum,
						 HANDLE file, const HttpDownloadProgressCallback &progress,
						 const HttpCancellationCallback &cancellation) override
	{
		static_cast<void>( url) ;
		static_cast<void>( resource) ;
		static_cast<void>( maximum) ;
		static_cast<void>( progress) ;
		static_cast<void>( cancellation) ;
		return writeFixture( file) ;
	}
	/** @brief 非通信fixtureの取得根拠照会だけを成功にする。
	 * @param[in] session 実取得session。
	 * @param[in] provider 取得層のProvider。
	 * @param[in] resource 取得層の用途。
	 * @return この試験transportではtrue。実公式由来の測定ではない。
	 */
	bool hasSourceEvidence( ScanSessionId session, std::wstring_view provider,
						   std::wstring_view resource) const noexcept override
	{
		static_cast<void>( session) ;
		static_cast<void>( provider) ;
		static_cast<void>( resource) ;
		return true ;
	}
} ;

/** @brief 実NLMを使わず非課金状態を返す。 */
class FixtureCost final : public IOfficialNetworkCostReader {
public:
	/** @brief 試験専用の回線分類を返す。
	 * @param[out] cost 常にUNRESTRICTED。
	 * @return 常に0。実回線確認ではない。
	 */
	NativeError read( OfficialNetworkCostKind &cost) noexcept override
	{
		cost = OfficialNetworkCostKind::UNRESTRICTED ;
		return 0 ;
	}
} ;
} // namespace

/**
 * @brief 試験EXEだけで実通常検査を代替する。製品libraryの実関数へlinkしない。
 * @param[in] input 封印から生成された元byte identity。
 * @param[in] format 実行しない形式。
 * @param[out] inspection 架空の全通常検査結果。
 * @param[in] cancellation 初期化再入と取消しの検査用callback。
 * @return 架空完了0、設定した全体失敗または取消しのHRESULT。
 * @note 内容・CAT署名の実検査ではない。実file操作は架空workspaceだけへ行う。
 */
NativeError inspectCommonDriverPackage( const DriverArchiveInput		 &input,
									   OfficialDriverArchiveFormat	  format,
									   CommonDriverPackageInspection &inspection,
									   const std::function<bool()>	 &cancellation)
{
	static_cast<void>( format) ;
	inspection = {} ;
	// callback再入を本番と同じ位置で観測し、取消しでは部分結果を返さない。
	if( cancellation && cancellation()) {
		return HRESULT_FROM_WIN32( ERROR_CANCELLED) ;
	}

	// 全体失敗を個別合格へ補完しない試験を行う。
	if( rejectContent) {
		return E_FAIL ;
	}

	inspection.scanSessionId = input.scanSessionId ;
	inspection.archiveSha256 = input.sha256 ;
	inspection.archiveBytes	 = input.byteCount ;
	// 同じ元取得物に二つの独立INFを持つ架空の正常構造を作る。
	for( std::size_t index = 0U; index < 2U; ++index) {
		CommonInfInspection inf ;	// 一つの架空通常閉包。
		inf.scanSessionId	= input.scanSessionId ;
		inf.infRelativePath = L"driver.inf" ;
		inf.state			= rejectedInf ? CommonInfInspectionState::SIGNATURE_REJECTED
										  : CommonInfInspectionState::VERIFIED ;
		inf.error			= rejectedInf ? E_FAIL : 0 ;
		inf.workspace		= std::make_unique<OfficialDownloadWorkspace>() ;
		// File所有のfixture失敗を架空署名成功にしない。
		if( inf.workspace->initialize( L"common-plan-fixture", input.scanSessionId) != 0) {
			return E_FAIL ;
		}

		HANDLE file{} ;	// Fixture writer。作成後に必ず閉じる。
		// 元のworkspaceではない独立閉包fileを所有する。
		if( inf.workspace->createFile( L"driver.inf", file) != 0) {
			return E_FAIL ;
		}

		const NativeError written = writeFixture( file) ;	// 三byteの閉包member。
		CloseHandle( file) ;
		// 書込み失敗を検査合格へ補完しない。
		if( written != 0) {
			return written ;
		}

		OfficialInfPackage package ;	// 名前と版だけの架空package metadata。
		package.infRelativePath			= L"driver.inf" ;
		package.providerName			= L"Fictional Provider" ;
		package.className				= L"Net" ;
		package.driverVersion			= L"2.0.0.0" ;
		package.driverDate				= L"2026/01/01" ;
		package.hasExternalDependencies = dependency ;
		inf.closure.packages.push_back( std::move( package)) ;
		OfficialZipEntry entry ;	// 実fileの固定member metadata。
		entry.relativePath	   = L"driver.inf" ;
		entry.uncompressedSize = 3U ;
		entry.sha256		   = ABC_HASH ;
		inf.closure.entries.push_back( std::move( entry)) ;
		inspection.infs.push_back( std::move( inf)) ;
	}

	return 0 ;
}

/** @brief 試験EXEだけで署名再検証を代替し、実fixture byteは共通hashへ照合する。
 * @param[in] inspected Factoryが所有する架空内容閉包。
 * @return 実byte一致0、設定した再検証失敗はE_FAIL。
 * @note 実Windows署名の検証成功を意味しない。
 */
NativeError reverifyCommonDriverInf( const CommonInfInspection &inspected)
{
	// 設定した失敗を適合やbindingで補わない。
	if( rejectReverify) {
		return E_FAIL ;
	}

	const std::wstring path = inspected.workspace->path( L"driver.inf") ;	// 使用中固定の対象fixture。
	const HANDLE	   writer = CreateFileW( path.c_str(), GENERIC_WRITE,
											FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
											nullptr, OPEN_EXISTING, 0, nullptr) ;	// Writer競合確認。
	// 実行中のfile固定が外れていれば、fakeでも検査合格を返さない。
	if( writer != INVALID_HANDLE_VALUE) {
		CloseHandle( writer) ;
		return E_FAIL ;
	}

	// 他の失敗理由を正しいwrite拒否として数えない。
	if( GetLastError() != ERROR_SHARING_VIOLATION) {
		return E_FAIL ;
	}

	return verifyOfficialFileMetadata( path, {3U, ABC_HASH}) ;
}
} // namespace drivercrate

namespace drivercrate::test {
namespace {

/** @brief 実封印APIと架空内容・rank・binding境界を保持する独立fixture。 */
struct PlanFixture {
	/// 元取得issuerの実共有所有。
	std::shared_ptr<OfficialAcquisitionSession> session{
		std::make_shared<OfficialAcquisitionSession>()} ;
	/// Factoryへ移す前の元取得領域。
	std::unique_ptr<OfficialDownloadWorkspace> archive{
		std::make_unique<OfficialDownloadWorkspace>()} ;
	/// 実封印APIが発行する非複写証拠。
	OfficialAcquiredFileEvidence evidence ;
	/// Fakeのbinding発行回数。
	std::uint64_t				 binds{} ;
	/// Fakeの解放済みtoken列。
	std::vector<std::uint64_t>	 released ;
	/// 設定時だけbinderが不一致metadataを返す。
	bool						 corruptBinding{} ;
	/// 設定時だけ既存tokenを重複返却する。
	bool						 duplicateToken{} ;
	/// 設定時だけbinderが例外を送出する。
	bool						 throwingBinder{} ;
	/// 設定時だけrankを未確認にする。
	bool						 rejectRank{} ;
	/// 設定時だけ解放callbackが失敗する。
	bool						 rejectRelease{} ;
	/// 設定時だけbindingの完全rankが変化する。
	bool						 corruptRank{} ;
	/// Binding中に同じfactoryへ再入する試験用callback。
	std::function<void()>		 duringBind ;
	/** @brief 架空3 byteを取得し、実封印証拠を作る。
	 * @param[in,out] context Assertion集計先。
	 */
	explicit PlanFixture( TestContext &context)
	{
		rejectContent = rejectReverify = dependency = rejectedInf = false ;
		DRIVERCRATE_EXPECT( context, session->initialize( 91U, {64U, 128U, 256U, 0U, 8U, 16U}) == 0) ;
		DRIVERCRATE_EXPECT( context, archive->initialize( L"common-plan-source", 91U) == 0) ;
		FixtureTransport				 transport ;	// 完全非通信の取得境界。
		FixtureCost						 cost ;			// 実NLMを使わない回線分類。
		const OfficialAcquisitionRequest request{
			.url			   = L"https://us.download.nvidia.com/fixture.bin",
			.providerId		   = NVIDIA_PROVIDER_ID,
			.resourceId		   = OFFICIAL_PAYLOAD_RESOURCE_ID,
			.workspaceFileName = L"source.bin",
			.maximumFileBytes  = 64U} ;		// 架空byteだけの有限取得。
		OfficialAcquisitionResult result ;	// 元pathは出力せずfixture内だけで保持する。
		DRIVERCRATE_EXPECT(
			context, session->acquire(
						 request, *archive, transport, cost,
						 []( std::uint64_t, std::uint64_t) { /* 確定進捗を外部へ出力しない。 */ },
						 {}, result) == 0) ;
		DRIVERCRATE_EXPECT(
			context, session->bindAcquiredFile( *archive, result.acquisitionId, evidence) == 0) ;
	}
	/** @brief 既存単一INF API形状のfakeをfactoryへ渡す。
	 * @param[in,out] factory 検証対象の空factory。
	 * @param[in] cancellation 初期化再入・取消し試験用の任意callback。
	 * @return 検証対象initializeの元HRESULT。
	 */
	NativeError initialize( CommonInfPlanFactory			   &factory,
						   const OfficialAuditCancellation &cancellation = {})
	{
		// Fake rankはdevice IDや実SetupAPIへ接続しない。
		const OfficialInfRankAuditor rank =
			[this]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
				   const OfficialInfPackage &, OfficialDriverRankAudit &audit) {
				audit					   = {} ;
				audit.decision			   = rejectRank ? OfficialDriverRankDecision::NOT_EVALUATED
														: OfficialDriverRankDecision::APPLICABLE ;
				audit.currentPosition.kind = PnpIdentifierKind::HARDWARE_ID ;
				audit.candidatePosition.kind = PnpIdentifierKind::HARDWARE_ID ;
				return NativeError{} ;
			} ;
		// Fake binderは発行した値を検査対象へ返すだけでWindowsを変更しない。
		const OfficialInfInstallBinder binder =
			[this]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
				   const OfficialInfPackage &package, std::wstring_view provider,
				   std::wstring_view version, std::wstring_view date,
				   const OfficialDriverRankAudit &audit,
				   OfficialInfInstallBinding	 &binding) -> NativeError {
			binding.token = ++binds ;
			// 既存tokenを返す異常境界の停止条件を試験する。
			if( duplicateToken) {
				binding.token = 1U ;
			}

			// 発行直後の例外でも元tokenを解放できることを試験する。
			if( throwingBinder) {
				throw std::runtime_error( "fixture") ;
			}

			binding.currentProvider	  = provider ;
			binding.currentVersion	  = version ;
			binding.currentDate		  = date ;
			binding.candidateProvider = package.providerName ;
			binding.candidateVersion  = corruptBinding ? L"wrong" : package.driverVersion ;
			binding.candidateDate	  = package.driverDate ;
			binding.rankAudit		  = audit ;
			// 決定値が同じでもrank field変化を検出する。
			if( corruptRank) {
				++binding.rankAudit.candidatePosition.index ;
			}

			// 同じworkerのcallbackからの再入は本番のbusy境界へ渡す。
			if( duringBind) {
				duringBind() ;
			}

			return 0 ;
		} ;
		// 解放はfake tokenの記録だけを行い、導入済みfileへ触れない。
		const OfficialInfInstallBindingReleaser release = [this]( ScanSessionId,
																 std::uint64_t token) {
			released.push_back( token) ;
			return !rejectRelease ;
		} ;
		return factory.initialize( session, archive, evidence, OfficialDriverArchiveFormat::ZIP,
								  rank, binder, release, cancellation) ;
	}
} ;

/** @brief 実IDを使わない同じscanの正常なbinding要求を作る。
 * @return 一candidate・一device・現在版ありの架空要求。
 */
CommonInfPlanRequest makePlanRequest()
{
	return {91U,
			0U,
			L"candidate:fictional",
			L"device:fictional",
			L"Fictional Provider",
			L"1.0.0.0",
			L"2025/01/01"} ;
}

/** @brief 取得所有・発行・拒否・rollback・失効を実行する。
 * @param[in,out] context Assertion集計先。
 */
void runPlanTests( TestContext &context)
{
	static_assert( !std::is_copy_constructible_v<CommonInfInstallPlan>) ;
	static_assert( !std::is_copy_constructible_v<CommonInfPlanFactory>) ;
	static_assert( !std::is_constructible_v<CommonInfInstallPlan, CommonInfInspection>) ;
	static_assert( !std::is_constructible_v<CommonInfInstallPlan, MaintenanceInfInspection>) ;
	CommonInfInstallPlan empty ;	// 公開既定値を許可にできない空計画。
	DRIVERCRATE_EXPECT( context, !empty.isBound() && empty.invalidate() == 0) ;
	PlanFixture			 fixture( context) ;	// 後で保持callbackから借用される長寿命fixture。
	CommonInfPlanFactory factory ;				// 元取得物を所有する検証対象。
	DRIVERCRATE_EXPECT( context, fixture.initialize( factory) == 0) ;
	DRIVERCRATE_EXPECT( context, !fixture.archive && !fixture.evidence.issuerAlive() &&
									factory.infCount() == 2U) ;
	CommonInfPlanRequest request = makePlanRequest() ;	// 当該scanの正常要求。
	CommonInfInstallPlan first ;						// 最初の未commit計画。
	DRIVERCRATE_EXPECT( context, factory.prepare( request, first) == 0 && first.isBound()) ;
	CommonInfInstallPlan duplicate ;	// 候補ID重複の拒否対象。
	DRIVERCRATE_EXPECT( context, factory.prepare( request, duplicate) != 0 && !duplicate.isBound() &&
									fixture.binds == 1U) ;
	CommonInfInstallPlan moved( std::move( first)) ;	// 所有だけを移した同一計画。
	DRIVERCRATE_EXPECT( context, !first.isBound() && moved.isBound()) ;
	request.candidateIdentity = L"candidate:second" ;
	request.infIndex		  = 1U ;
	fixture.duplicateToken	  = true ;
	DRIVERCRATE_EXPECT( context, factory.prepare( request, duplicate) != 0 && moved.isBound() &&
									fixture.released.empty()) ;
	fixture.duplicateToken = false ;
	fixture.corruptBinding = true ;
	DRIVERCRATE_EXPECT( context, factory.prepare( request, duplicate) != 0 && !duplicate.isBound()) ;
	DRIVERCRATE_EXPECT( context, fixture.released == std::vector<std::uint64_t>{3U}) ;
	fixture.corruptBinding = false ;
	fixture.throwingBinder = true ;
	DRIVERCRATE_EXPECT( context, factory.prepare( request, duplicate) != 0 && !duplicate.isBound()) ;
	DRIVERCRATE_EXPECT( context, !fixture.released.empty() && fixture.released.back() == 4U) ;
	fixture.throwingBinder = false ;
	fixture.rejectRank	   = true ;
	DRIVERCRATE_EXPECT( context, factory.prepare( request, duplicate) != 0 && fixture.binds == 4U) ;
	fixture.rejectRank = false ;
	rejectReverify	   = true ;
	DRIVERCRATE_EXPECT( context, factory.prepare( request, duplicate) != 0 && fixture.binds == 4U) ;
	rejectReverify = false ;
	request.currentVersion.clear() ;
	DRIVERCRATE_EXPECT( context, factory.prepare( request, duplicate) != 0 && fixture.binds == 4U) ;
	request					  = makePlanRequest() ;
	request.candidateIdentity = L"candidate:second" ;
	request.scanSessionId	  = 92U ;
	DRIVERCRATE_EXPECT( context, factory.prepare( request, duplicate) != 0 && fixture.binds == 4U) ;
	request.scanSessionId = 91U ;
	request.infIndex	  = 2U ;
	DRIVERCRATE_EXPECT( context, factory.prepare( request, duplicate) != 0 && fixture.binds == 4U) ;
	request.infIndex	   = 1U ;
	fixture.duplicateToken = true ;
	fixture.throwingBinder = true ;
	const std::size_t beforeRollback =
		// 既存tokenを例外rollbackで壊さない監視。
		fixture.released.size() ;
	DRIVERCRATE_EXPECT( context,
					   factory.prepare( request, duplicate) == E_UNEXPECTED && moved.isBound()) ;
	DRIVERCRATE_EXPECT( context, fixture.released.size() == beforeRollback &&
									factory.lastCleanupError() == 0) ;
	fixture.duplicateToken = false ;
	fixture.throwingBinder = false ;
	std::thread other( [&] {
		// Joinまで生存する所有者を借り、別threadの全操作拒否を確認する。
		DRIVERCRATE_EXPECT( context, factory.prepare( request, duplicate) != 0 && !moved.isBound()) ;
		DRIVERCRATE_EXPECT( context, factory.invalidate() != 0 && moved.invalidate() != 0) ;
	}) ;
	other.join() ;
	DRIVERCRATE_EXPECT( context, factory.prepare( request, duplicate) == 0 && duplicate.isBound()) ;
	DRIVERCRATE_EXPECT( context, moved.invalidate() == 0 && !moved.isBound() && duplicate.isBound()) ;
	DRIVERCRATE_EXPECT( context, factory.invalidate() == 0 && !duplicate.isBound() &&
									factory.infCount() == 0U) ;
	const std::size_t released = fixture.released.size() ;	// 全失効後の二重解放監視。
	DRIVERCRATE_EXPECT( context, duplicate.invalidate() == 0 && fixture.released.size() == released) ;
	DRIVERCRATE_EXPECT( context, factory.prepare( request, first) != 0) ;
	// 全体拒否・取消し・個別拒否・依存は元所有と実行可否を別々に確認する。
	for( int mode = 0; mode < 5; ++mode) {
		PlanFixture			 rejected( context) ;	// 各停止条件で独立した実封印を作る。
		CommonInfPlanFactory target ;				// 失敗で元workspaceを奪わない空factory。
		rejectContent = mode == 0 ;
		dependency	  = mode == 2 ;
		rejectedInf	  = mode == 3 ;
		NativeError		  reentry{} ;	// 再入は別factoryではなく同じ対象へ行う。
		const NativeError result = rejected.initialize( target, [&] {
			// 初期化callback内の再入は失敗し、外側の元所有を上書きしない。
			if( mode == 4) {
				reentry = rejected.initialize( target) ;
			}

			return mode == 1 ;
		}) ;
		// 全体失敗と取消しでは元証拠・workspaceを保持する。
		if( mode < 2) {
			DRIVERCRATE_EXPECT( context,
							   result != 0 && rejected.archive && rejected.evidence.issuerAlive()) ;
		} else {
			DRIVERCRATE_EXPECT( context, result == 0 && !rejected.archive) ;
			CommonInfInstallPlan plan ;	// 個別拒否でも公開許可にはならない空計画。
			const NativeError	 prepared =
				// 個別bindingの停止位置。
				target.prepare( makePlanRequest(), plan) ;
			DRIVERCRATE_EXPECT( context, mode == 4 ? prepared == 0 && reentry != 0
												  : prepared != 0 && rejected.binds == 0U) ;
		}
	}

	PlanFixture			 failedCleanup( context) ;	// 元失敗とrollback失敗を独立に保持する検証対象。
	CommonInfPlanFactory cleanupFactory ;			// 他のfactoryのtokenは扱わない。
	DRIVERCRATE_EXPECT( context, failedCleanup.initialize( cleanupFactory) == 0) ;
	failedCleanup.corruptRank	= true ;
	failedCleanup.rejectRelease = true ;
	CommonInfInstallPlan failedPlan ;	// 不一致rankでは発行しない。
	DRIVERCRATE_EXPECT( context,
					   cleanupFactory.prepare( makePlanRequest(), failedPlan) == E_INVALIDARG) ;
	DRIVERCRATE_EXPECT( context, !failedPlan.isBound() && cleanupFactory.lastCleanupError() != 0) ;
	failedCleanup.corruptRank	= false ;
	failedCleanup.rejectRelease = false ;
	NativeError reentry{} ;	// binding中の再入停止の診断値。
	failedCleanup.duringBind = [&] {
		// Joinやmutexを使わない同期再入だけを試験する。
		CommonInfInstallPlan nested ;
		reentry = cleanupFactory.prepare( makePlanRequest(), nested) ;
		DRIVERCRATE_EXPECT( context, cleanupFactory.invalidate() != 0 && !nested.isBound()) ;
	} ;
	DRIVERCRATE_EXPECT( context, cleanupFactory.prepare( makePlanRequest(), failedPlan) == 0 &&
									failedPlan.isBound()) ;
	DRIVERCRATE_EXPECT( context, reentry != 0 && cleanupFactory.lastCleanupError() == 0) ;
	DRIVERCRATE_EXPECT( context, failedPlan.invalidate() == 0) ;
	PlanFixture			 lifetime( context) ;									// Callbackの借用先は最後まで保持する。
	CommonInfInstallPlan surviving ;											// Factoryより長く存在できるが、失効後は実行できない計画。
	std::weak_ptr<OfficialAcquisitionSession> weakIssuer = lifetime.session ;	// 共有所有の解放監視。
	{
		CommonInfPlanFactory temporary ;	// 生存取得の所有者。
		DRIVERCRATE_EXPECT( context, lifetime.initialize( temporary) == 0) ;
		lifetime.session.reset() ;
		DRIVERCRATE_EXPECT( context, !weakIssuer.expired()) ;
		DRIVERCRATE_EXPECT( context, temporary.prepare( makePlanRequest(), surviving) == 0) ;
	}
	DRIVERCRATE_EXPECT( context, !surviving.isBound() && !weakIssuer.expired()) ;
	DRIVERCRATE_EXPECT( context, surviving.invalidate() == 0 && weakIssuer.expired() &&
									lifetime.released.size() == 1U) ;
	PlanFixture					 invalidEvidence( context) ;	// 公開の空証拠を生存所有だけで補わない。
	CommonInfPlanFactory		 proofFactory ;					// 不正元入力を保持しない対象。
	OfficialAcquiredFileEvidence emptyEvidence ;				// どのissuerも発行していない空値。
	DRIVERCRATE_EXPECT( context, proofFactory.initialize(
									invalidEvidence.session, invalidEvidence.archive, emptyEvidence,
									OfficialDriverArchiveFormat::ZIP, {}, {}, {}) != 0) ;
	DRIVERCRATE_EXPECT( context, invalidEvidence.archive && invalidEvidence.evidence.issuerAlive() &&
									proofFactory.infCount() == 0U) ;
	OfficialAcquiredFileEvidence validProof(
		// 実発行済み証拠を別に保持する。
		std::move( invalidEvidence.evidence)) ;
	DRIVERCRATE_EXPECT( context, invalidEvidence.initialize( proofFactory) != 0 &&
									invalidEvidence.archive && validProof.issuerAlive()) ;
	invalidEvidence.evidence = std::move( validProof) ;
	const auto originalIssuer =
		invalidEvidence.session ;	// 元issuerは生存させたまま別issuerへ差し替える。
	invalidEvidence.session = std::make_shared<OfficialAcquisitionSession>() ;
	DRIVERCRATE_EXPECT(
		context, invalidEvidence.session->initialize( 92U, {64U, 128U, 256U, 0U, 8U, 16U}) == 0) ;
	DRIVERCRATE_EXPECT( context, invalidEvidence.initialize( proofFactory) != 0 &&
									invalidEvidence.archive &&
									invalidEvidence.evidence.issuerAlive()) ;
	static_cast<void>( originalIssuer) ;
}
} // namespace
} // namespace drivercrate::test

/** @brief 非通信・非導入の独立準備計画試験を実行する。
 * @return 全assertion成功0、失敗・例外は1。
 */
int main()
{
	try {
		drivercrate::test::TestContext context ;	// 検査結果件数だけを集計する。
		drivercrate::test::runPlanTests( context) ;
		std::cout << "Common INF plan assertions: " << context.assertionCount()
				  << ", failures: " << context.failureCount() << '\n' ;
		return context.failureCount() == 0 ? 0 : 1 ;
	} catch( ...) {
		// Path・URL・payloadを出力せず、例外を失敗終了値へ残す。
		std::cerr << "Common INF plan fixture failure.\n" ;
		return 1 ;
	}
}
