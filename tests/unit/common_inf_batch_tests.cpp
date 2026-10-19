//------------------------------------------------------------------------------
/**
 * @file common_inf_batch_tests.cpp
 * @brief 共通選択adapterの全件停止・直前照合・個別結果と失効を非導入で検証する。
 * @version 01.01.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  独立fakeの一括実行と共有所有試験を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/06  専用target向けの34定義試験hookを追加。
 * </pre>
 *
 * @note 実封印／file固定だけを使い、内容・rank・binding・導入は試験EXEだけのfakeとする。
 * 実通信・PnP・Windows署名・staging・導入・復元ポイント・installerを呼ばない。
 * @see docs/adr/0286-common-inf-batch-adapter.md
 */
//------------------------------------------------------------------------------
#include "platform/common_inf_plan.h"
#include "platform/official_file_verifier.h"
#include "core/provider_registry.h"
#include "core/official_source_policy.h"
#include "test_framework.h"

#include <Windows.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {
constexpr wchar_t ABC_HASH[] =
	L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ;	// 架空abcのhash。
thread_local std::size_t			  contentChecks{} ;						// 全通常再検証呼出し数。
thread_local std::size_t			  rejectContentAt{} ;					// 非零の場合だけ指定再検証を拒否する。
thread_local std::size_t			  fixtureInfCount{2U} ;					// 試験専用のINF件数。
thread_local bool					  fixtureDependency{} ;					// 試験専用の明示依存。
thread_local CommonInfInspectionState fixtureState{
	CommonInfInspectionState::VERIFIED} ;		// 内容境界の試験状態。
thread_local std::size_t fixtureDownloads{} ;	// 非通信transportの確定呼出し数。

/** @brief 架空fixtureを開いたfileへ保存する。
 * @param[in] file 借用writer。
 * @return 全3 byte保存0、失敗E_FAIL。
 */
NativeError				 writeBytes( HANDLE file)
{
	DWORD written{} ;	// 実確定保存量。
	return WriteFile( file, "abc", 3U, &written, nullptr) && written == 3U ? 0 : E_FAIL ;
}

/** @brief 指定fixtureへのwriterが共有違反で拒否された事実だけを確認する。
 * @param[in] path 当該試験workspace内の位置。
 * @return 正確な共有違反の場合true。それ以外false。
 */
bool writerBlocked( const std::wstring &path)
{
	// 実writer競合の観測handle。成功時は必ず閉じる。
	const HANDLE handle = CreateFileW( path.c_str(), GENERIC_WRITE,
									  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
									  nullptr, OPEN_EXISTING, 0, nullptr) ;
	// 別のopen失敗を正しい固定と数えない。
	if( handle == INVALID_HANDLE_VALUE) {
		return GetLastError() == ERROR_SHARING_VIOLATION ;
	}

	CloseHandle( handle) ;
	return false ;
}

/** @brief 公式HTTPを行わず、架空3 byteだけを取得層へ返す。 */
class BatchTransport final : public IOfficialAcquisitionTransport {
public:
	/** @brief 固定sourceの非通信保存を行う。
	 * @param[in] url 使用しない架空URL。
	 * @param[in] resource 使用しない用途。
	 * @param[in] maximum 使用しない予算。
	 * @param[in] file Fixture writer。
	 * @param[in] progress 使用しない通知。
	 * @param[in] cancellation 使用しない取消し。
	 * @return 全3 byte保存0、失敗E_FAIL。
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
		++fixtureDownloads ;
		return writeBytes( file) ;
	}
	/** @brief 当該fixtureでは委譲取得を行わない。
	 * @param[in,out] request 消費しない要求。
	 * @param[in] file 使用しないfile。
	 * @param[in] progress 使用しない通知。
	 * @param[in] cancellation 使用しない取消し。
	 * @param[out] destination 空の未確認結果。
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
	/** @brief 非通信fixtureのsource根拠だけを返す。
	 * @param[in] session 使用しないsession。
	 * @param[in] provider 使用しないProvider。
	 * @param[in] resource 使用しない用途。
	 * @return 常にtrue。実公式根拠の検証ではない。
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

/** @brief 実回線状態を照会しないfixture。 */
class BatchCost final : public IOfficialNetworkCostReader {
public:
	/** @brief 架空の非課金状態を返す。
	 * @param[out] cost 常にUNRESTRICTED。
	 * @return 常に0。
	 */
	NativeError read( OfficialNetworkCostKind &cost) noexcept override
	{
		cost = OfficialNetworkCostKind::UNRESTRICTED ;
		return 0 ;
	}
} ;
} // namespace

/** @brief 当該EXEだけで通常内容検査を有限の独立fixture INFへ代替する。
 * @param[in] input 封印元file情報。
 * @param[in] format 実行しない形式。
 * @param[out] inspection 既定二つ、上限拒否試験では129の架空通常閉包。
 * @param[in] cancellation このfixtureでは使用しない取消し。
 * @return Fixture作成0、失敗E_FAIL。
 * @note 実CAT・INF合格の測定ではない。
 */
NativeError inspectCommonDriverPackage( const DriverArchiveInput		 &input,
									   OfficialDriverArchiveFormat	  format,
									   CommonDriverPackageInspection &inspection,
									   const std::function<bool()>	 &cancellation)
{
	static_cast<void>( format) ;
	static_cast<void>( cancellation) ;
	inspection				 = {} ;
	inspection.scanSessionId = input.scanSessionId ;
	inspection.archiveSha256 = input.sha256 ;
	inspection.archiveBytes	 = input.byteCount ;
	// 全INFは実machineから独立した架空byteで作る。
	for( std::size_t index = 0U; index < fixtureInfCount; ++index) {
		CommonInfInspection inf ;	// 一つの独立所有閉包。
		inf.scanSessionId	= input.scanSessionId ;
		inf.infRelativePath = L"driver.inf" ;
		inf.state			= fixtureState ;
		inf.error	  = fixtureState == CommonInfInspectionState::VERIFIED ? 0 : E_ACCESSDENIED ;
		inf.workspace = std::make_unique<OfficialDownloadWorkspace>() ;
		// Workspace作成失敗をfake合格へ補わない。
		if( inf.workspace->initialize( L"common-batch-inf-" + std::to_wstring( index),
									 input.scanSessionId) != 0) {
			return E_FAIL ;
		}

		HANDLE file{} ;	// 必ず閉じるfixture writer。
		// 通常memberを一つだけ作成する。
		if( inf.workspace->createFile( L"driver.inf", file) != 0) {
			return E_FAIL ;
		}

		const NativeError error = writeBytes( file) ;	// 元hashと一致する架空byte保存。
		CloseHandle( file) ;
		// 失敗をfake署名合格として保持しない。
		if( error != 0) {
			return error ;
		}

		OfficialInfPackage package ;	// 実IDのない架空metadata。
		package.infRelativePath			= L"driver.inf" ;
		package.providerName			= L"Fictional Provider" ;
		package.className				= L"Net" ;
		package.driverVersion			= L"2.0.0.0" ;
		package.driverDate				= L"2026/01/01" ;
		package.hasExternalDependencies = fixtureDependency ;
		inf.closure.packages.push_back( std::move( package)) ;
		OfficialZipEntry entry ;	// 正確なfile照合値。
		entry.relativePath	   = L"driver.inf" ;
		entry.uncompressedSize = 3U ;
		entry.sha256		   = ABC_HASH ;
		inf.closure.entries.push_back( std::move( entry)) ;
		inspection.infs.push_back( std::move( inf)) ;
	}

	return 0 ;
}

/** @brief CAT署名だけをfakeにし、使用中固定と実fixture hashを確認する。
 * @param[in] inspected Factory所有の閉包。
 * @return 指定拒否E_FAIL、固定なしE_ACCESSDENIED、それ以外はhash照合結果。
 */
NativeError reverifyCommonDriverInf( const CommonInfInspection &inspected)
{
	++contentChecks ;
	// 決めた位置の検査を拒否してpreflightと直前検査を分ける。
	if( contentChecks == rejectContentAt) {
		return E_FAIL ;
	}

	const auto path = inspected.workspace->path( L"driver.inf") ;	// 内部fixtureの位置。
	return writerBlocked( path) ? verifyOfficialFileMetadata( path, {3U, ABC_HASH}) : E_ACCESSDENIED ;
}
} // namespace drivercrate

namespace drivercrate::test {
namespace {
/** @brief 実封印取得と非Windowsのrank／binding／指定導入callbackを保持する。 */
struct BatchFixture {
	/// Assertion集計。Fixtureより長く生存する。
	TestContext								   &context ;
	/// 非通信取得の生存issuer。
	std::shared_ptr<OfficialAcquisitionSession> session{
		std::make_shared<OfficialAcquisitionSession>()} ;
	/// 実fileと閉包を単独所有する検証対象。
	CommonInfPlanFactory					   factory ;
	/// Factoryへ移動前の元workspace。
	std::unique_ptr<OfficialDownloadWorkspace> archive{
		std::make_unique<OfficialDownloadWorkspace>()} ;
	/// 非複写の実封印。
	OfficialAcquiredFileEvidence evidence ;
	/// 元fixtureの位置。画面／logへ出さない。
	std::wstring				 sourcePath ;
	/// 準備時に借用観測したmember位置。画面／logへ出さない。
	std::vector<std::wstring>	 memberPaths ;
	/// 新規binding発行数。
	std::uint64_t				 binds{} ;
	/// Rank再監査数。
	std::size_t					 ranks{} ;
	/// Binding再検証数。
	std::size_t					 checks{} ;
	/// 指定導入fake呼出し数。
	std::size_t					 installs{} ;
	/// 解放token記録。
	std::vector<std::uint64_t>	 released ;
	/// 非零の場合だけ当該再検証を拒否する。
	std::size_t					 rejectBindingAt{} ;
	/// 非零の場合だけ当該導入fakeを拒否する。
	std::size_t					 rejectInstallAt{} ;
	/// 発行後rankの一fieldを変更する場合true。
	bool						 changeRank{} ;
	/// 導入fakeが例外を送出する場合true。
	bool						 throwInstall{} ;
	/// 解放fakeが失敗する場合true。
	bool						 rejectRelease{} ;

	/// Rankを未評価へ変更する試験専用flag。
	bool						 rejectRank{} ;
	/// 新規token発行後の元HRESULT。0の場合は成功。
	NativeError					 binderResult{} ;
	/// 発行後に例外を送出する試験専用flag。
	bool						 throwBinder{} ;
	/// 候補metadataを不一致へ変更する試験専用flag。
	bool						 corruptBinding{} ;
	/// 当該binding再検証で例外を送出する。0の場合は送出しない。
	std::size_t					 throwCheckAt{} ;
	/// 初期化の元結果。失敗時も元archiveと証拠を保持する。
	NativeError					 initializationError{} ;
	/// 同期再入と途中変更を行う検査hook。借用先は実行終了まで生存する。
	std::function<void()>		 duringInstall ;
	/** @brief 架空元byteを取得し、内部factoryへ移動する。
	 * @param[in,out] target Assertion集計先。
	 * @param[in] finishInitialization Falseの場合は封印取得までで止める。
	 * @param[in] infCount Fake検査が返すINF数。上限拒否試験以外は2。
	 * @param[in] externalDependencies Fake検査で明示依存を観測する場合true。
	 * @param[in] inspectionState Fake検査の個別内容状態。
	 */
	explicit BatchFixture(
		TestContext &target, bool finishInitialization = true, std::size_t infCount = 2U,
		bool					 externalDependencies = false,
		CommonInfInspectionState inspectionState	  = CommonInfInspectionState::VERIFIED)
		: context( target)
	{
		contentChecks = rejectContentAt = 0U ;
		fixtureInfCount					= infCount ;
		fixtureDependency				= externalDependencies ;
		fixtureState					= inspectionState ;
		fixtureDownloads				= 0U ;
		DRIVERCRATE_EXPECT( context, session->initialize( 91U, {64U, 128U, 256U, 0U, 8U, 16U}) == 0) ;
		DRIVERCRATE_EXPECT( context, archive->initialize( L"common-batch-source", 91U) == 0) ;
		BatchTransport			   transport ;	// 実通信しない境界。
		BatchCost				   cost ;		// 実NLMを使わない境界。
		OfficialAcquisitionRequest request{.url = L"https://us.download.nvidia.com/fixture.bin",
										   .providerId		  = NVIDIA_PROVIDER_ID,
										   .resourceId		  = OFFICIAL_PAYLOAD_RESOURCE_ID,
										   .workspaceFileName = L"source.bin",
										   .maximumFileBytes  = 64U} ;	// 有限fixture取得。
		OfficialAcquisitionResult  result ;								// 元file観測。
		DRIVERCRATE_EXPECT(
			context,
			session->acquire(
				request, *archive, transport, cost,
				[]( std::uint64_t, std::uint64_t) { /* 非通信fixtureの通知を外部出力しない。 */ },
				{}, result) == 0) ;
		DRIVERCRATE_EXPECT(
			context, session->bindAcquiredFile( *archive, result.acquisitionId, evidence) == 0) ;
		sourcePath = evidence.observation().inspectionPath ;
		// 空callback・別issuer試験は元取得を消費する前に止める。
		if( !finishInitialization) {
			return ;
		}

		// Fake rankは実Windows照合へ接続せず、全fieldの変更検出を確認する。
		const OfficialInfRankAuditor rank =
			[this]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
				   const OfficialInfPackage &, OfficialDriverRankAudit &value) {
				++ranks ;
				value					   = {} ;
				value.decision			   = rejectRank ? OfficialDriverRankDecision::NOT_EVALUATED
														: OfficialDriverRankDecision::APPLICABLE ;
				value.currentPosition.kind = value.candidatePosition.kind =
					PnpIdentifierKind::HARDWARE_ID ;
				value.candidateRank = changeRank ? 1U : 0U ;
				return NativeError{} ;
			} ;
		// Fake bindingは元現在版とcandidate metadataだけを保持する。
		const OfficialInfInstallBinder binder =
			[this]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &workspace,
				   const OfficialInfPackage &package, std::wstring_view provider,
				   std::wstring_view version, std::wstring_view date,
				   const OfficialDriverRankAudit &rankValue, OfficialInfInstallBinding &binding) {
				binding.token			  = ++binds ;
				binding.currentProvider	  = provider ;
				binding.currentVersion	  = version ;
				binding.currentDate		  = date ;
				binding.candidateProvider = package.providerName ;
				binding.candidateVersion  = corruptBinding ? L"mismatch" : package.driverVersion ;
				binding.candidateDate	  = package.driverDate ;
				binding.rankAudit		  = rankValue ;
				memberPaths.push_back( workspace.path( package.infRelativePath)) ;
				// 発行済みtokenの例外rollbackだけを試験する。
				if( throwBinder) {
					throw std::runtime_error( "binder") ;
				}

				return binderResult ;
			} ;
		// 解放は記録だけで、Windows登録INFを変更しない。
		const OfficialInfInstallBindingReleaser release = [this]( ScanSessionId,
																 std::uint64_t token) {
			released.push_back( token) ;
			return !rejectRelease ;
		} ;
		initializationError = factory.initialize(
			session, archive, evidence, OfficialDriverArchiveFormat::ZIP, rank, binder, release) ;
		DRIVERCRATE_EXPECT( context, initializationError == (infCount > 128U ? E_INVALIDARG : 0)) ;
	}
	/** @brief 一device用の内部計画を発行する。
	 * @param[in,out] plan 空の発行先。
	 * @param[in] number 架空candidate／device番号。
	 * @param[in] infIndex 元archive内の0起点INF。
	 * @return 計画へ照合するopaque選択。
	 */
	CommonInfPlanSelection prepare( CommonInfInstallPlan &plan, unsigned number,
								   std::size_t infIndex = 0U)
	{
		// 現在版を持つ架空deviceへの発行要求。
		CommonInfPlanRequest request{91U,
									 infIndex,
									 L"candidate:" + std::to_wstring( number),
									 L"device:" + std::to_wstring( number),
									 L"Fictional Provider",
									 L"1.0.0.0",
									 L"2025/01/01"} ;
		DRIVERCRATE_EXPECT( context, factory.prepare( request, plan) == 0) ;
		return {&plan, request.candidateIdentity, request.deviceIdentity} ;
	}
	/** @brief 借用callback先のfieldを破棄する前にfactoryを失効する。 */
	~BatchFixture()
	{
		static_cast<void>( factory.invalidate()) ;
	}
	/** @brief 既存API形状のfake再検証とfake指定導入だけで実行する。
	 * @param[in] selections 借用選択列。
	 * @param[in] progress 空または試験通知。
	 * @param[in] scan 現在選択scan。
	 * @return 検証対象の元結果。
	 */
	CommonInfPlanExecutionResult execute( std::span<const CommonInfPlanSelection> selections,
										 const ProviderProgressCallback			&progress = {},
										 ScanSessionId							 scan	  = 91U)
	{
		// 同じfixtureの検証回数と拒否位置だけを使い、実PnPを照会しない。
		const CommonInfBindingRevalidator check =
			[this]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
				   const OfficialInfPackage &, const OfficialInfInstallBinding &) {
				++checks ;
				// 再検証境界の例外でも全計画を失効させる。
				if( checks == throwCheckAt) {
					throw std::runtime_error( "revalidation") ;
				}

				return checks == rejectBindingAt ? static_cast<NativeError>( E_FAIL) : NativeError{} ;
			} ;
		// 使用中固定と個別結果を確認するfake。Windows変更APIを呼ばない。
		const OfficialBoundInfInstaller install =
			[this]( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
				   const OfficialInfPackage &, const OfficialInfInstallBinding &, std::uintptr_t,
				   bool &reboot) -> NativeError {
			++installs ;
			reboot = installs == 1U ;
			DRIVERCRATE_EXPECT( context, writerBlocked( sourcePath)) ;
			// 同じmemberを二deviceへ使っても実固定が継続する。
			for( const auto &path : memberPaths) {
				DRIVERCRATE_EXPECT( context, writerBlocked( path)) ;
			}

			// 元借用は実行中だけ生存し、再入試験でmove／破棄はしない。
			if( duringInstall) {
				duringInstall() ;
			}

			// 例外でも再起動観測と呼出し済みを残す。
			if( throwInstall) {
				throw std::runtime_error( "fixture") ;
			}

			return installs == rejectInstallAt ? E_FAIL : 0 ;
		} ;
		return CommonInfPlanExecutor::execute( scan, selections, check, install, 0U, progress) ;
	}
} ;

/** @brief 基本成功・共有・全件拒否・部分結果と失効を確認する。
 * @param[in,out] context Assertion集計先。
 */
void runBatchTests( TestContext &context)
{
	// 各停止位置を別fixtureで実行し、前試験の失効を次へ持ち込まない。
	for( unsigned mode = 0U; mode < 19U; ++mode) {
		BatchFixture						  fixture( context) ;	// 一実行だけに結合する所有者。
		CommonInfInstallPlan				  first ;				// 第一deviceのdraft。
		CommonInfInstallPlan				  second ;				// 第二deviceのdraft。
		// 同じarchiveの二deviceを選択する固定集合。
		std::array<CommonInfPlanSelection, 2> selected{
			fixture.prepare( first, 1U), fixture.prepare( second, 2U, mode == 1U ? 1U : 0U)} ;
		// Identity不一致と同device競合はprivate計画で補完しない。
		if( mode == 2U) {
			selected[1].candidateIdentity = L"unknown" ;
		}

		// 一deviceへの二つの基本計画を拒否する。
		if( mode == 3U) {
			selected[1].deviceIdentity = selected[0].deviceIdentity ;
		}

		// 二件目preflight失敗では第一導入も開始しない。
		if( mode == 4U) {
			fixture.rejectBindingAt = 2U ;
		}

		// 完全rankの一field変更で停止する。
		if( mode == 5U) {
			fixture.changeRank = true ;
		}

		// 二件目内容拒否では部分導入しない。
		if( mode == 6U) {
			rejectContentAt = contentChecks + 2U ;
		}

		// 第一導入失敗の後に第二を開始しない。
		if( mode == 7U) {
			fixture.rejectInstallAt = 1U ;
		}

		// 第二導入失敗でも第一成功を保持する。
		if( mode == 8U) {
			fixture.rejectInstallAt = 2U ;
		}

		// 呼出し後の例外をWindows変更なしとしない。
		if( mode == 9U) {
			fixture.throwInstall = true ;
		}

		// 第二の直前binding失敗で未開始を保つ。
		if( mode == 10U) {
			fixture.rejectBindingAt = 4U ;
		}

		// 解放失敗を元導入HRESULTから分ける。
		if( mode == 11U) {
			fixture.rejectRelease = true ;
		}

		// Null計画を公開identityで補完しない。
		if( mode == 14U) {
			selected[1].plan = nullptr ;
		}

		// 第一callback後のrank変化を第二の直前検査で拒否する。
		if( mode == 15U) {
			fixture.duringInstall = [&] { fixture.changeRank = true ; } ;
		}

		// 第一callback後の内容拒否でも第二を実行しない。
		if( mode == 16U) {
			fixture.duringInstall = [&] { rejectContentAt = contentChecks + 1U ; } ;
		}

		// 返却後の元archive改変を生存issuerで補完しない。
		if( mode == 17U) {
			// 自分のfixtureだけを改変する所有handle。
			const HANDLE writer = CreateFileW( fixture.sourcePath.c_str(), GENERIC_WRITE,
											  FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr) ;
			DRIVERCRATE_EXPECT( context, writer != INVALID_HANDLE_VALUE) ;
			// 無効handleへ書き込まない。
			if( writer != INVALID_HANDLE_VALUE) {
				DWORD written{} ;	// 確定改変量。
				DRIVERCRATE_EXPECT( context, WriteFile( writer, "xyz", 3U, &written, nullptr) &&
												written == 3U) ;
				CloseHandle( writer) ;
			}
		}

		std::vector<std::uint64_t>	   progress ;	// 実完了件数だけを記録する。
		// 通知例外の未開始と完了済み保持を確認する。
		const ProviderProgressCallback notify = [&]( const ProviderProgress &value) {
			progress.push_back( value.completedItems) ;
			// 最初の通知なら導入未開始、完了通知なら個別成功を保持する。
			if( mode == 12U || (mode == 13U && value.completedItems == 1U)) {
				throw std::runtime_error( "progress") ;
			}
		} ;
		const auto report =
			// 内部fake実行結果。
			fixture.execute( selected, notify, mode == 18U ? 92U : 91U) ;
		DRIVERCRATE_EXPECT( context, report.result.updates.size() == 2U &&
										report.installerInvoked.size() == 2U) ;
		DRIVERCRATE_EXPECT( context,
						   !first.isBound() && !second.isBound() && fixture.released.size() == 2U) ;
		DRIVERCRATE_EXPECT( context, !writerBlocked( fixture.sourcePath)) ;
		// 最初の二経路は共有INFと別INFの両方で全成功を確認する。
		if( mode <= 1U) {
			DRIVERCRATE_EXPECT( context, report.result.succeeded && fixture.installs == 2U &&
											fixture.checks == 4U) ;
			DRIVERCRATE_EXPECT( context, report.result.rebootRequired &&
											progress == std::vector<std::uint64_t>( {0U, 1U, 2U})) ;
		}
		// 全callback失敗を一部成功と数えない。
		else if( mode == 7U || mode == 9U) {
			DRIVERCRATE_EXPECT( context, fixture.installs == 1U &&
											report.result.installOutcome == OutcomeCode::FAILURE) ;
			DRIVERCRATE_EXPECT(
				context, report.installerInvoked[0] && !report.installerInvoked[1] &&
							 report.result.updates[0].installOutcome == OutcomeCode::FAILURE &&
							 report.result.updates[1].installOutcome == OutcomeCode::NOT_STARTED &&
							 report.result.rebootRequired) ;
			DRIVERCRATE_EXPECT( context,
							   report.result.installError == (mode == 9U ? E_UNEXPECTED : E_FAIL)) ;
		}
		// 先行成功と後続未開始／失敗を個別に保持する。
		else if( mode == 8U || mode == 10U || mode == 13U || mode == 15U || mode == 16U) {
			DRIVERCRATE_EXPECT( context,
							   !report.result.succeeded && report.result.installOutcome ==
															   OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
			DRIVERCRATE_EXPECT( context,
							   report.result.updates[0].installOutcome == OutcomeCode::SUCCESS) ;
			DRIVERCRATE_EXPECT( context, fixture.installs == (mode == 8U ? 2U : 1U) &&
											report.result.rebootRequired) ;
		}
		// 導入結果と解放診断は別の値である。
		else if( mode == 11U) {
			DRIVERCRATE_EXPECT( context, fixture.installs == 2U && report.cleanupError != 0 &&
											!report.result.succeeded) ;
			DRIVERCRATE_EXPECT( context,
							   report.result.installError == 0 &&
								   fixture.factory.lastCleanupError() == report.cleanupError) ;
		} else {
			DRIVERCRATE_EXPECT( context, fixture.installs == 0U &&
											report.result.installOutcome == OutcomeCode::FAILURE) ;
			DRIVERCRATE_EXPECT(
				context, report.result.updates[0].installOutcome == OutcomeCode::NOT_STARTED &&
							 report.result.updates[1].installOutcome == OutcomeCode::NOT_STARTED) ;
		}

		// 終了した同一計画は結果を持っていても再実行できない。
		const auto repeated = fixture.execute( selected) ;	// 失効集合への二度目の要求。
		DRIVERCRATE_EXPECT( context, !repeated.result.succeeded && fixture.released.size() == 2U) ;
	}

	BatchFixture		 reentry( context) ;	// 再入を拒否して外側を継続する独立所有者。
	CommonInfInstallPlan plan ;					// 外側操作のprivate計画。
	// 外側操作の一device集合。
	std::array<CommonInfPlanSelection, 1> chosen{reentry.prepare( plan, 1U)} ;
	std::thread							  other( [&] {
		  // Joinまで借用先を保持し、別threadの実行は何も失効しない。
		  const auto report = reentry.execute( chosen) ;
		  DRIVERCRATE_EXPECT( context, report.result.installError == RPC_E_WRONG_THREAD) ;
	  }) ;
	other.join() ;
	DRIVERCRATE_EXPECT( context,
					   plan.isBound() && reentry.released.empty() && reentry.installs == 0U) ;
	reentry.duringInstall = [&] {
		// 使用中のmove／破棄なしに同期再入と失効要求を拒否する。
		const auto nested = reentry.execute( chosen) ;
		DRIVERCRATE_EXPECT( context, nested.result.installError == RPC_E_WRONG_THREAD &&
										reentry.released.empty()) ;
		DRIVERCRATE_EXPECT( context, reentry.factory.invalidate() != 0 && plan.invalidate() != 0) ;
	} ;
	DRIVERCRATE_EXPECT( context, reentry.execute( chosen).result.succeeded && !plan.isBound()) ;
	BatchFixture						  left( context) ;	// 複数元取得を一括検査する第一所有者。
	BatchFixture						  right( context) ;	// 第二所有者。先行部分導入を防ぐ。
	CommonInfInstallPlan				  leftPlan ;		// 第一factoryの計画。
	CommonInfInstallPlan				  rightPlan ;		// 第二factoryの計画。
	// 異なる元取得を同じscanの一括選択として扱う。
	std::array<CommonInfPlanSelection, 2> together{left.prepare( leftPlan, 1U),
												   right.prepare( rightPlan, 2U)} ;
	right.changeRank   = true ;
	const auto stopped = left.execute( together) ;	// 後続所有者でpreflight停止。
	DRIVERCRATE_EXPECT( context,
					   !stopped.result.succeeded && left.installs == 0U && right.installs == 0U) ;
	DRIVERCRATE_EXPECT( context, !leftPlan.isBound() && !rightPlan.isBound() &&
									left.released.size() == 1U && right.released.size() == 1U) ;
}
} // namespace
} // namespace drivercrate::test

// 専用targetだけが同じfixtureへ追加定義を読み込み、旧325項目EXEを再buildしない。
#if defined( DRIVERCRATE_COMMON_INF_CONTRACT_TESTS)
#include "common_inf_contract_cases.h"
#endif

/** @brief 非通信・非導入の独立adapter試験を実行する。
 * @return 全assertion成功0、失敗・例外1。
 */
int main()
{
	try {
		drivercrate::test::TestContext context ;	// 件数だけを集計する。
		drivercrate::test::runBatchTests( context) ;
#if defined( DRIVERCRATE_COMMON_INF_CONTRACT_TESTS)
		std::cout << "Common INF contract base assertions: " << context.assertionCount()
				  << ", failures: " << context.failureCount() << '\n' ;
		drivercrate::test::runContractTests( context) ;
#endif
		std::cout << "Common INF batch assertions: " << context.assertionCount()
				  << ", failures: " << context.failureCount() << '\n' ;
		return context.failureCount() == 0 ? 0 : 1 ;
	} catch( ...) {
		// path・byte・IDを出力せず例外を失敗終了値へ残す。
		std::cerr << "Common INF batch fixture failure.\n" ;
		return 1 ;
	}
}
