//------------------------------------------------------------------------------
/**
 * @file collector_distribution_pipeline_tests.cpp
 * @brief 実固定子から通常runnerと実INF parserの有限fixtureへ接続します。
 * @version 01.08.00
 * @date 2026/10/24
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/23 保護実行経路の実子と同PAGE二payloadを確認。
 * Ver.01.01.00 Shunji Ogawa  2026/10/23 16MiB収集JSON文脈と現台帳原byteのhash回帰を追加。
 * Ver.01.01.01 Shunji Ogawa  2026/10/23 例外後の実子終端とlease保持/再取得のassertを追加。
 * Ver.01.01.02 Shunji Ogawa  2026/10/23 同run directoryの移動拒否と子終端までの保持を検査。
 * Ver.01.02.00 Shunji Ogawa  2026/10/23 汎用producerの実byteと未署名共通codec fixtureを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/23 署名低位だけを模擬し通常ZIP/INF/Modelsをproducerへ接続。
 * Ver.01.04.00 Shunji Ogawa  2026/10/23 同じ日次入口のdata追加・原byte保持・停止移設を検査。
 * Ver.01.05.00 Shunji Ogawa  2026/10/24 既存B更新の確認待ちimportと別review後の実INF検査を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/24  現行nested member identityと原record完全tupleへ整合。
 * Ver.01.07.00 Shunji Ogawa  2026/10/25 非保存native leaseから同schema切替の実childを検査。
 * Ver.01.08.00 Shunji Ogawa  2026/10/25 完全PAGE原byteとhash拒否・保存失敗の有限fixtureを追加。
 * </pre>
 * @note 元回帰は完全fakeです。parsed fixtureはHTTP/DNSと署名低位だけを模擬します。
 * @see docs/adr/0396-collector-distribution-pipeline-connection.md
 */
//------------------------------------------------------------------------------

// 既存の完全fake低位HTTP表と通常検査seamをそのまま再利用します。
#define main registryPrimitiveMain
#include "collector_registry_job_tests.cpp"
#undef main
#include "platform/collector_setup_workspace.cpp"
#include "platform/signed_index_codec_internal.h"
#include "platform/index_distribution_trust.h"
#include "platform/driver_package_signature_internal.h"
#include <fstream>
#include <filesystem>
#include <map>
#include <utility>
#include <stdexcept>
#include <Windows.h>

namespace drivercrate {
/** @brief 同じ製品callerの私有test I/O点だけを使用します。 */
class CollectorDistributionTestAccess final {
public:
	/// 故障probeの実発火回数です。別stageの拒否を負例成功へ数えません。
	static inline std::size_t faultCalls{} ;
	/// guard内で同じ実子の終端を確認した回数です。
	static inline std::size_t cleanupCalls{} ;
	/// 同じ実子終端と保持中writerの競合を共に確認した場合だけtrueです。
	static inline bool		  cleanupConfirmed{} ;
	/// 保存済み予約probeが借用する同じchild HANDLEの値です。guard後は参照しません。
	static inline HANDLE	  expectedChild{} ;
	/// 直接指定した自己所有workspaceです。移動先をこの配下へ限定します。
	static inline fs::path	  fixtureWorkspace ;
	/// 同じ予約probeの自己所有run directoryです。cleanup中だけ再検査します。
	static inline fs::path	  expectedRunRoot ;
	/// 当該fixtureで実際に試したdirectory移動の回数です。
	static inline std::size_t directoryMoveChecks{} ;
	/** @brief 自己所有run directoryだけを兄弟先へ移動し、特定の共有拒否を要求します。
	 * @param[in] runRoot 同じcallerの固定run directoryです。
	 * @return ERROR_SHARING_VIOLATIONで拒否された場合だけtrueです。
	 * @note 移動できた修正前は同じ場所へ必ず復元してから失敗させます。
	 */
	static bool				  directoryMoveDenied( const fs::path &runRoot)
	{
		fs::path source = runRoot ;	// API表記だけをWindows separatorへ統一します。
		source.make_preferred() ;
		const auto parent =
			fixtureWorkspace / L"monitor" / L"distribution" / L"runs" ;	// 自己所有の固定範囲です。
		const auto target = source.parent_path() / (source.filename().native() +
													L"-move-probe") ;	// 同じ親の兄弟先だけです。
		check( source.is_absolute() && source == source.lexically_normal() &&
			  source.root_name().native().size() == 2U && source.parent_path() == parent &&
			  target.is_absolute() && target == target.lexically_normal() &&
			  target.parent_path() == parent && source != target && !fs::exists( target)) ;
		const auto sourceApi = L"\\\\?\\" + source.native() ;	// 検証済み絶対DOS pathのAPI表記です。
		const auto targetApi = L"\\\\?\\" + target.native() ;	// 同じ自己所有の兄弟先です。
		++directoryMoveChecks ;
		const BOOL	moved = MoveFileExW( sourceApi.c_str(), targetApi.c_str(),
										0U) ;	// 当該directoryだけを一回試します。
		const DWORD error =
			// 元結果を直後に保持します。
			moved == FALSE ? GetLastError() : ERROR_SUCCESS ;
		// 修正前の実移動は外側へのwriteを起こさず、復元して親の安全停止へ進みます。
		if( moved != FALSE) {
			const BOOL	restored = MoveFileExW( targetApi.c_str(), sourceApi.c_str(),
											   0U) ;	// 検証済みの同じ二pathだけです。
			const DWORD restoreError =
				// 復元失敗も固定値で残します。
				restored == FALSE ? GetLastError() : ERROR_SUCCESS ;
			std::printf( "RUN_DIRECTORY_MOVE moved=1 restored=%u win32=%lu\n",
						restored != FALSE ? 1U : 0U, static_cast<unsigned long>( restoreError)) ;
			check( restored != FALSE) ;
			throw std::runtime_error( "RUN_DIRECTORY_MOVE_NOT_BLOCKED") ;
		}

		std::printf( "RUN_DIRECTORY_MOVE moved=0 win32=%lu\n", static_cast<unsigned long>( error)) ;
		check( error == ERROR_SHARING_VIOLATION) ;
		return true ;
	}
	/** @brief 予約保存後の破損/実子死亡/親死亡を独立targetだけへ設定します。
	 * @param[in] mode 0は通常、1は予約欠損、2は実子停止、3は親死亡、4は移動拒否、5/6は本文保存競合です。
	 */
	static void fault( const unsigned mode)
	{
		faultCalls		 = 0U ;
		cleanupCalls	 = 0U ;
		cleanupConfirmed = false ;
		expectedChild	 = nullptr ;
		expectedRunRoot.clear() ;
		directoryMoveChecks = 0U ;
		// 同じ実childが終了済みでもnative writerが解放されていない順序を確認します。
		CollectorRegistryJobProtectedCaller::terminationProbe_ =
			[mode]( HANDLE child, const LocalCollectorStateStore &lease) {
				// 親側拒否/実子停止の二負例だけを受入分母へ数えます。
				if( mode == 1U || mode == 2U) {
					++cleanupCalls ;
					LocalCollectorStateStore
						competing ;	// 同じ自己所有rootだけへ非作成で競合確認します。
					cleanupConfirmed = child == expectedChild &&
									   WaitForSingleObject( child, 0U) == WAIT_OBJECT_0 &&
									   lease.isWritable() &&
									   competing.initializeExistingWriter( lease.root()) ==
										   ERROR_SHARING_VIOLATION &&
									   directoryMoveDenied( expectedRunRoot) ;
				}
			} ;
		CollectorRegistryJobProtectedCaller::reservationProbe_ = [mode]( const fs::path &runRoot,
																		HANDLE			child,
																		std::uint32_t	ordinal) {
			// 設定した故障だけを実発火の分母へ数えます。
			if( mode != 0U) {
				++faultCalls ;
				expectedChild	= child ;
				expectedRunRoot = runRoot ;
			}

			// 既存正常2jobの最初の予約でだけ、移動拒否を実際に確認します。
			if( mode == 4U && ordinal == 0U) {
				check( directoryMoveDenied( runRoot)) ;
			}

			// 子完了前の親死亡では実jobが全子孫を停止し、予約は保持されます。
			if( mode == 3U) {
				ExitProcess( 73U) ;
			}

			// 既存の同child HANDLEだけを終了し、別processへ影響しません。
			if( mode == 2U) {
				requireBool( TerminateProcess( child, 91U), "TEST_CHILD_STOP") ;
				require( WaitForSingleObject( child, 5000U) == WAIT_OBJECT_0, "TEST_CHILD_STOP_WAIT") ;
			}

			// 原結果保存後の本文競合を、既存の予約probeで保存前にだけ用意します。
			if( (mode == 5U || mode == 6U) && ordinal == 0U) {
				const auto body = runRoot / L"page-0.body" ;	// 自己所有run内の固定保存先だけです。
				// CREATE_NEW競合と通常fileでない保存先を別の失敗として残します。
				if( mode == 5U) {
					distributionSave( body, "existing-body-must-remain") ;
				} else {
					check( fs::create_directory( body)) ;
				}
			}

			// 元予約破損probeの拒否条件を変更しません。
			if( mode == 1U) {
				const auto journalPath =
					// 自作fixture正本です。
					runRoot.parent_path().parent_path() / L"journal.json" ;
				auto journal = SetupJson::Parse(
					// 原保存値です。
					winrt::to_hstring( distributionRead( journalPath))) ;
				const auto reservation = SetupJson::Parse( winrt::to_hstring(
					distributionRead( runRoot / (L"reservation-" + std::to_wstring( ordinal) +
												L".json")))) ;	// 同予約です。
				journal.GetNamedObject( L"requests")
					.Remove( reservation.GetNamedString( L"payloadKey")) ;
				writeCollectorSetupProtectedMetadata( journalPath,
													 winrt::to_string( journal.Stringify()), true) ;
			}
		} ;
	}
	/** @brief 実子・writer・同じ通常runnerを通します。
	 * @param[in] package 自己所有fixtureの固定packageです。
	 * @param[in] root 自己所有fixtureのworkspaceです。
	 * @param[in] metadataMode 専用seamの固定metadata形式です。0は元回帰です。
	 * @param[in] daily trueなら保護同意を読む製品dispatcherを使います。
	 * @param[in] betaFiles 同じ自作B archiveの署名低位期待集合名です。本文やmetadataを置換しません。
	 * @return callerの終了値です。
	 */
	static int run( const std::filesystem::path &package, const std::filesystem::path &root,
				   const unsigned metadataMode = 0U, const bool daily = false,
				   const std::wstring betaFiles = L"b")
	{
		fixtureWorkspace = root ;
		// 捕捉する値はなく、同じ同期run中だけ既存fake表を借用します。
		CollectorRegistryJobProtectedCaller::executionProbe_ = [metadataMode, package, betaFiles](
																   const CollectorRegistryJob &job,
																   ScanSessionId		  session,
																   CollectorRunPageScope &scope,
																   const CollectorRunPageProof
																				*proof,
																   std::uint64_t cap,
																   std::chrono::steady_clock::
																	   time_point deadline,
																   CollectorRegistryJobResult
																	   &result) {
			// 本文とmetadataを置換せず、全原member hashへ結合した署名低位だけを模擬します。
			if( metadataMode == 29U) {
				// 自作ZIPと同時に生成した全原member hashだけを読みます。
				const auto document = SetupJson::Parse(
					winrt::to_hstring( distributionRead( package / L"fixture-signature-files.json"))) ;
				std::vector<driver_package_signature_detail::FixtureFile>
					files ;	// 同archiveの原file集合です。
				// 各INF/CAT/SYSの原byte hashとownerを切り捨てず低位scopeへ固定します。
				for( const auto &value :
					document.GetNamedArray( job.productCount() == 2U ? L"a" : betaFiles)) {
					const auto row = value.GetObject() ;	// 自作ZIPと同時生成した期待値です。
					files.push_back( {row.GetNamedString( L"name").c_str(),
									 row.GetNamedString( L"sha256").c_str(),
									 row.GetNamedString( L"infOwner").c_str()}) ;
				}

				auto signature = driver_package_signature_detail::Access::create(
					// 信頼I/Oだけのscopeです。
					std::move( files), 2U) ;
				check( signature != nullptr) ;
				fixture->sessions.push_back( session) ;
				const auto error = CollectorRegistryJobTestAccess::execute(
					job, job, 12U, result, &scope, proof, cap, session,
					deadline) ;								// 通常検査/identityを実行します。
				const auto receipt = signature->receipt() ;	// 実INF/CAT/member照会の件数です。
				check( receipt.inspectionRoots > 0U && receipt.setupCalls > 0U &&
					  receipt.verifyCalls > 0U && receipt.verifyCalls == receipt.closeCalls &&
					  receipt.rejectedCalls == 0U) ;
				std::printf(
					"PARSED_PRODUCER session=%llu infRoots=%zu signatureCalls=%zu memberCalls=%zu actualCatAccepted=0\n",
					static_cast<unsigned long long>( session), receipt.inspectionRoots,
					receipt.setupCalls, receipt.verifyCalls) ;
				return error ;
			}

			return CollectorRegistryJobTestAccess::execute(
				job, job,
				metadataMode == 27U	  ? (session == 1U ? 21U : 26U)
				: metadataMode == 28U ? (session == 1U ? 8U : 9U)
									  : metadataMode,
				result, &scope, proof, cap, session, deadline) ;
		} ;
		// 新日次も同じcallerを通し、試験専用の恒久pipelineへ置換しません。
		if( daily) {
			return runCollectorSetupDistributionDaily( package, {}, false, [] {}) ;
		}

		return runCollectorSetupWorkspace( package, L"distribution-run-once", root,
										  L"--confirm-inspection-download", [] {}) ;
	}
} ;

/** @brief 非通信hash fixtureの有限な原byteを読みます。
 * @param[in] path 自作manifestまたは指定済み公開研究入力です。
 * @param[in] maximum 読取り前に要求するbyte上限です。
 * @return 完全に読めた不変原byteです。
 * @note 製品のACL/leaseを代替せず、testだけの原source照合です。
 */
std::string readDistributionHashFixture( const fs::path &path, const std::size_t maximum)
{
	const auto size = fs::file_size( path) ;	// 読取り前の有限byte数です。
	check( size > 0U && size <= maximum) ;
	std::ifstream input( path, std::ios::binary) ;					// 指定済み公開fixtureを読取り専用で所有します。
	std::string	  bytes( static_cast<std::size_t>( size), '\0') ;	// 上限内だけを確保します。
	check( input.is_open() &&
		  input.read( bytes.data(), static_cast<std::streamsize>( bytes.size())).good() &&
		  input.gcount() == static_cast<std::streamsize>( bytes.size()) &&
		  fs::file_size( path) == size) ;
	return bytes ;
}

/** @brief 既定16MiBの文脈と現registry/locatorsのhashをPython期待値へ照合します。
 * @param[in] manifest 自作の有限境界値と明示公開入力の期待hashです。
 * @return 全比較成功0です。不一致は既存test checkで拒否します。
 */
int distributionHashFixtureChecks( const fs::path &manifest)
{
	const auto document = SetupJson::Parse(
		// 有限な期待値だけです。
		winrt::to_hstring( readDistributionHashFixture( manifest, 65536U))) ;
	const auto cases = document.GetNamedArray( L"cases") ;	// Python独立hashの固定6境界です。
	check( cases.Size() == 6U) ;
	// 既存1/8MiB入口を保持し、収集文脈の16MiBを超える直前で拒否します。
	for( const auto &value : cases) {
		const auto row = value.GetObject() ;	// 当該有限境界の独立期待値です。
		const auto size =
			// 固定集合のbyte数です。
			static_cast<std::size_t>( row.GetNamedNumber( L"bytes")) ;
		check( size == 1048576U || size == 1048577U || size == 8388608U || size == 8388609U ||
			  size == 16777216U || size == 16777217U) ;
		const std::string bytes( size, 'x') ;						// 実際の全byteをCNGへ渡します。
		const bool accepted = row.GetNamedBoolean( L"accepted") ;	// 16MiB以下だけが合格します。
		bool	   rejected{} ;										// 固定上限guardの発火だけを拒否成功に数えます。
		bool	   succeeded{} ;									// 許可された境界ではCNG比較の完了そのものを必要とします。
		try {
			const auto hash = distributionHash( bytes) ;	// 本物の配布文脈wrapperです。
			check( accepted && hash == row.GetNamedString( L"sha256")) ;
			succeeded = true ;
		} catch( const std::runtime_error &error) {
			rejected = std::string_view( error.what()) == "DISTRIBUTION_JSON_LIMIT" ;
		}

		check( succeeded == accepted && rejected == !accepted) ;
		std::wstring original ;	// 既存APIの失敗後出力も確認します。
		check( (computeBytesSha256( bytes, original) == 0) == (size <= 1048576U)) ;
		check( (computeCollectorMetadataSha256( bytes, original) == 0) == (size <= 8388608U)) ;
	}

	const auto files = document.GetNamedArray( L"files") ;	// 現台帳とlocator原byteだけです。
	check( files.Size() == 2U) ;
	// 全recordの検査・通信をせず、二つの原file全byteだけを照合します。
	for( const auto &value : files) {
		const auto row	 = value.GetObject() ;	// 明示された公開研究入力です。
		const auto bytes = readDistributionHashFixture(
			// 既定上限を維持します。
			fs::path( row.GetNamedString( L"path").c_str()), 16777216U) ;
		check( bytes.size() == row.GetNamedNumber( L"bytes") &&
			  distributionHash( bytes) == row.GetNamedString( L"sha256")) ;
		std::printf( "DISTRIBUTION_HASH_FILE bytes=%zu matched=1 network=0\n", bytes.size()) ;
	}

	std::printf(
		"DISTRIBUTION_HASH_TEST assertions=%zu boundaries=6 source_files=2 failures=0 network=0\n",
		checks) ;
	return 0 ;
}

/** @brief 収集済みA/Bを維持し、既存Bの二段階importと更新後の通常検査を確認します。
 * @param[in] package 同じEXE/moduleと旧新版synthetic archiveを固定した自己所有packageです。
 * @param[in] root 同じ保護workspaceです。旧待機や課金を編集しません。
 * @param[in] complete trueなら別processで明示reviewしたCURRENTを取り込みます。
 * @return 固定正常/拒否条件を満たす場合0です。
 * @note 初段を終了してからPython共通upsertが別reviewを行い、同じEXEで後段を起動します。
 */
int distributionExistingUpdateFixtureChecks( const fs::path &package, const fs::path &root,
											const bool complete)
{
	const auto evidence = root.parent_path() / L"update-evidence" ;	// 自己所有の原byte保存先です。
	const auto distribution = root / L"monitor/distribution" ;		// 同じ保護正本を読取ります。
	Fixture	   state ;												// HTTP/DNSだけの低位fakeで、実INF parserへ接続します。
	fixture = &state ;
	CollectorDistributionTestAccess::fault( 0U) ;
	// 保存するのは読取った原byteであり、運用正本へ値を書き戻しません。
	const auto snapshot = [&evidence, &root, &distribution]( const std::wstring &stage) {
		writeCollectorSetupProtectedMetadata( evidence / (stage + L"-active.json"),
											 distributionRead( root / L"data/active.json"), false) ;
		writeCollectorSetupProtectedMetadata(
			evidence / (stage + L"-head.json"),
			distributionRead( distribution / L"candidate-head.json"), false) ;
		writeCollectorSetupProtectedMetadata( evidence / (stage + L"-journal.json"),
											 distributionRead( distribution / L"journal.json"),
											 false) ;
	} ;
	// 後段は同じrootの待機/同意を使い、原点や運用stateを作り直しません。
	if( complete) {
		const auto head = distributionRead( distribution / L"candidate-head.json") ;	// 元候補です。
		const auto journal = distributionRead( distribution / L"journal.json") ;		// 元課金です。
		check( runCollectorSetupWorkspace( package, L"import-data", root,
										 root.parent_path() / L"data-update-current", [] {}) == 0 &&
			  state.sends == 0U) ;
		check( distributionRead( distribution / L"candidate-head.json") == head &&
			  distributionRead( distribution / L"journal.json") == journal) ;
		state.responses = {{distributionRead( package / L"fixture-page-b-updated.txt")},
						   {distributionRead( package / L"fixture-payload-b-updated.bin"), 200U,
							L"application/zip"}} ;
		check( CollectorDistributionTestAccess::run( package, root, 29U, true, L"bUpdated") == 2 &&
			  state.sends == 2U && state.sessions.size() == 1U && state.opened == state.closed &&
			  state.safe) ;
		snapshot( L"updated") ;
		const auto updatedHead =
			// 実更新結果です。
			distributionRead( distribution / L"candidate-head.json") ;
		const auto parsed =
			// 私有headを読取ります。
			SetupJson::Parse( winrt::to_hstring( updatedHead)) ;
		check( parsed.GetNamedNumber( L"generation") == 2.0 &&
			  parsed.GetNamedArray( L"includedCandidates").Size() == 2U && updatedHead != head) ;
		state.sends = 0U ;
		check( CollectorDistributionTestAccess::run( package, root, 29U, true, L"bUpdated") == 2 &&
			  state.sends == 0U && state.sessions.size() == 1U) ;
		check( distributionRead( distribution / L"candidate-head.json") == updatedHead) ;
		snapshot( L"final") ;
		std::printf(
			"DISTRIBUTION_EXISTING_UPDATE_COMPLETE assertions=%zu updated_b_gets=2 a_resend=0 next_gets=0 real_tasks=0\n",
			checks) ;
		return 0 ;
	}

	createCollectorSetupProtectedRoot( evidence) ;
	check( runCollectorSetupWorkspace( package, L"import-data", root,
									 root.parent_path() / L"data-existing-first", [] {}) == 0) ;
	check( runCollectorSetupWorkspace(
			  package, L"initialize-distribution-origins", root, {}, [] {},
			  root.parent_path() / L"native", root / L"monitor") == 0) ;
	check( runCollectorSetupDistributionDaily( package, root, true, [] {}) == 0 && state.sends == 0U) ;
	const auto page = distributionRead( package / L"fixture-page.txt") ;	// 旧A/Bの公式PAGE本文です。
	state.responses = {
		{page},
		{distributionRead( package / L"fixture-payload.bin"), 200U, L"application/zip"},
		{page},
		{distributionRead( package / L"fixture-payload-b.bin"), 200U, L"application/zip"}} ;
	check( CollectorDistributionTestAccess::run( package, root, 29U, true) == 0 &&
		  state.sends == 4U && state.sessions.size() == 2U && state.opened == state.closed &&
		  state.safe) ;
	snapshot( L"first") ;
	const auto pointer = distributionRead( root / L"data/active.json") ;	// 拒否前のactive原byteです。
	const auto head =
		// 収集済みA/Bの候補です。
		distributionRead( distribution / L"candidate-head.json") ;
	const auto journal =
		// 旧四URLの課金/待機です。
		distributionRead( distribution / L"journal.json") ;
	check( runCollectorSetupWorkspace( package, L"import-data", root,
									 root.parent_path() / L"data-update-early-current",
									 [] {}) == 2 &&
		  state.sends == 4U) ;
	check( distributionRead( root / L"data/active.json") == pointer &&
		  distributionRead( distribution / L"candidate-head.json") == head &&
		  distributionRead( distribution / L"journal.json") == journal) ;
	snapshot( L"rejected") ;
	check( runCollectorSetupWorkspace( package, L"import-data", root,
									 root.parent_path() / L"data-update-pending", [] {}) == 0 &&
		  state.sends == 4U) ;
	check( distributionRead( root / L"data/active.json") != pointer &&
		  distributionRead( distribution / L"candidate-head.json") == head &&
		  distributionRead( distribution / L"journal.json") == journal) ;
	state.sends = 0U ;
	check( CollectorDistributionTestAccess::run( package, root, 29U, true) == 2 &&
		  state.sends == 0U && state.sessions.size() == 2U) ;
	check( distributionRead( distribution / L"candidate-head.json") == head) ;
	snapshot( L"pending") ;
	std::printf(
		"DISTRIBUTION_EXISTING_UPDATE_PENDING assertions=%zu first_gets=4 direct_current_rejected=1 pending_gets=0 real_tasks=0\n",
		checks) ;
	return 0 ;
}
/** @brief 自己所有workspace/nativeの原byteを有限に比較します。
 * @param[in] root 保護fixtureの一rootです。
 * @param[in] workspace trueなら切替対象bindingと今回archiveだけを比較から除きます。
 * @return 相対memberと原byteの所有集合です。
 */
std::map<std::wstring, std::string> distributionSwitchBytes( const fs::path &root,
															const bool		workspace)
{
	std::map<std::wstring, std::string> result ;	// 今回fixtureの原byteだけを保持します。
	// 全通常fileを一度ずつ読み、元履歴・origin・lockを省略しません。
	for( const auto &entry : fs::recursive_directory_iterator( root)) {
		// Directory自身は元byte集合を持たないので通常fileだけを記録します。
		if( entry.is_regular_file()) {
			const auto relative = fs::relative( entry.path(), root) ;	// 絶対pathを結果へ出しません。
			// 変更を許す二hashの入れ物と原archive以外は完全不変を要求します。
			if( workspace &&
			   (relative == L"workspace.json" || *relative.begin() == L"package-switches")) {
				continue ;
			}

			check( result.size() < 4096U) ;
			const auto size =
				// 独立fingerprintはnative自身の明示ACLもそのまま読みます。
				entry.file_size() ;
			check( size <= 16777216U) ;
			std::string raw( static_cast<std::size_t>( size),
							'\0') ;	// 空lock fileもbyte集合へ含めます。
			// 所有writerが排他openする空lockは長さ0で比較し、非空fileだけを完全読取りします。
			if( size != 0U) {
				const fs::path readPath( L"\\\\?\\" +
										// 元native名の260文字境界も同じbyteで読みます。
										entry.path().native()) ;
				std::ifstream  stream(
					 // 認可readerを置換しないtest専用読取りです。
					 readPath, std::ios::binary) ;
				check( stream.is_open()) ;
				stream.read( raw.data(), static_cast<std::streamsize>( size)) ;
				check( stream.good() && stream.gcount() == static_cast<std::streamsize>( size)) ;
			}

			result.emplace( relative.native(), std::move( raw)) ;
		}
	}

	return result ;
}

/** @brief 既存実origin/leaseと固定childで非通信package切替を検査します。
 * @param[in] package 内部fixtureの検証seamを使う自己所有packageです。
 * @param[in] root 直前に初回完了した自己所有workspaceです。
 * @param[in] native 同じ三rootへ結合したnative originです。
 * @return 全拒否・原byte保持・正常切替が期待通りなら0です。
 * @note 製品の全bundle検査は通常setupの別試験で行い、このseamからTask/HTTPを起動しません。
 */
int distributionPackageSwitchFixtureChecks( const fs::path &package, const fs::path &root,
										   const fs::path &native)
{
	const auto current = distributionRead( root / L"workspace.json") ;	// 元の現package bindingです。
	auto	   previous =
		// 同schemaの原package hashだけを変えます。
		SetupJson::Parse( winrt::to_hstring( current)) ;
	previous.Insert( L"packageManifestSha256",
					SetupValue::CreateStringValue( std::wstring( 64U, L'1'))) ;
	previous.Insert( L"seedManifestSha256", SetupValue::CreateStringValue( std::wstring( 64U, L'2'))) ;
	const auto original =
		// 原空白もarchiveへ保持するraw byteです。
		winrt::to_string( previous.Stringify()) ;
	writeCollectorSetupProtectedMetadata( root / L"workspace.json", original, true) ;
	const fs::path review( distributionHash( original)) ;	// 事前reviewした原raw SHA-256です。
	const auto	   retainedWorkspace =
		// 三root内の元byte集合です。
		distributionSwitchBytes( root, true) ;
	const auto retainedNative =
		// 原key/anchor/lockを省略しません。
		distributionSwitchBytes( native, false) ;
	std::size_t verified{} ;								// 同じnative入口がpackage検査callbackを呼んだ回数です。
	const auto	verify = [&verified]() { ++verified ; } ;	// 同期で借用する内部package検査seamです。
	// 正常verifyは原bindingを受け入れず、切替専用の例外が漏れないことを実childで確認します。
	check( runCollectorSetupWorkspace( package, L"verify", root, {}, verify) == 2) ;
	// 原hash差はnative段階で拒否し、childやarchiveへ進みません。
	bool hashRejected{} ;	// 期待した固定stageだけを成功へ数えます。
	try {
		static_cast<void>( runCollectorSetupWorkspace( package, L"switch-package", root,
													 fs::path( std::wstring( 64U, L'0')), verify)) ;
	} catch( const std::exception &error) {
		hashRejected = std::string_view( error.what()) == "WORKSPACE_SWITCH_REVIEW_HASH" ;
	}

	check( hashRejected && !fs::exists( root / L"package-switches")) ;
	// 他のnative writerを保持して、同じ正規入口の競合拒否を確認します。
	{
		LocalCollectorStateStore held ;	// 自作nativeだけを非作成でlockします。
		check( held.initializeExistingWriter( native) == 0U) ;
		bool busy{} ;	// 原Win32 codeを持つnative writer stageだけを受理します。
		try {
			static_cast<void>(
				runCollectorSetupWorkspace( package, L"switch-package", root, review, verify)) ;
		} catch( const std::exception &error) {
			busy = std::string_view( error.what()) == "DISTRIBUTION_NATIVE_WRITER" ;
		}

		check( busy) ;
	}

	const auto descriptorPath =
		root / L"distribution-origin-init-v1.json" ;					// 原descriptorだけを試験します。
	const auto descriptorBytes = distributionRead( descriptorPath) ;	// 各負例後に原byteへ戻します。
	// descriptor内の三identityを一つずつ変え、推測した別rootへ結合しないことを確認します。
	for( const auto field : {L"nativeIdentity", L"workspaceIdentity", L"monitorIdentity"}) {
		auto descriptor =
			// 一fieldだけの人工差です。
			SetupJson::Parse( winrt::to_hstring( descriptorBytes)) ;
		descriptor.Insert( field, SetupValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
		writeCollectorSetupProtectedMetadata( descriptorPath,
											 winrt::to_string( descriptor.Stringify()), true) ;
		bool changed{} ;	// 実三rootとの一致拒否だけを確認します。
		try {
			static_cast<void>(
				runCollectorSetupWorkspace( package, L"switch-package", root, review, verify)) ;
		} catch( const std::exception &error) {
			changed = std::string_view( error.what()) == "DISTRIBUTION_ORIGIN_CHANGED" ;
		}

		check( changed &&
			  distributionRead( descriptorPath) == winrt::to_string( descriptor.Stringify())) ;
		writeCollectorSetupProtectedMetadata( descriptorPath, descriptorBytes, true) ;
	}

	// 原descriptorに未受入のnative履歴を検査しても、観測fieldを再保存しません。
	{
		LocalCollectorStateStore store ;	// このfixtureの一未知fileだけを作ります。
		check( store.initializeExistingWriter( native) == 0U &&
			  store.write( L"current/unreviewed.json", "{}") == 0U) ;
	}
	bool unreviewed{} ;	// 非保存modeが履歴を補完していないことを確認します。
	try {
		static_cast<void>(
			runCollectorSetupWorkspace( package, L"switch-package", root, review, verify)) ;
	} catch( const std::exception &error) {
		unreviewed = std::string_view( error.what()) == "WORKSPACE_SWITCH_NATIVE_HISTORY_UNREVIEWED" ;
	}

	check( unreviewed && distributionRead( descriptorPath) == descriptorBytes &&
		  distributionSwitchBytes( native, false).at( L"current\\unreviewed.json") == "{}") ;
	check( DeleteFileW( (native / L"current/unreviewed.json").c_str()) != FALSE) ;
	// 実owner検査へ許可外principalを渡す内部負例で、所有者境界を緩めないことを確認します。
	std::array<BYTE, SECURITY_MAX_SID_SIZE> other{} ;		// SIDを保持する固定容量です。
	DWORD sidBytes = static_cast<DWORD>( other.size()) ;	// APIが書くbyte数です。
	check( CreateWellKnownSid( WinWorldSid, nullptr, other.data(), &sidBytes) != FALSE) ;
	const auto rootHandle = openChecked( root, true, false) ;	// 同じ実rootのACL/ownerだけを読みます。
	bool	   ownerRejected{} ;								// 許可外userは原ownerを採用できません。
	try {
		checkSecurity( rootHandle.get(), other.data(), true, true) ;
	} catch( const std::exception &error) {
		ownerRejected = std::string_view( error.what()) == "WORKSPACE_OWNER_DACL" ||
						std::string_view( error.what()) == "WORKSPACE_PROTECTED_DACL" ;
	}

	check( ownerRejected) ;
	const auto wrongAcl =
		// 保護root契約を持たない通常childです。
		root.parent_path() / L"switch-inherited-root" ;
	fs::create_directory( wrongAcl) ;
	bool aclRejected{} ;	// 既存ACLは修復せず、正式入口のtree検査で拒否します。
	try {
		static_cast<void>(
			runCollectorSetupWorkspace( package, L"switch-package", wrongAcl, review, verify)) ;
	} catch( const std::exception &error) {
		aclRejected = std::string_view( error.what()) == "WORKSPACE_PROTECTED_DACL" ;
	}

	check( aclRejected && distributionRead( root / L"workspace.json") == original &&
		  distributionSwitchBytes( root, true) == retainedWorkspace &&
		  distributionSwitchBytes( native, false) == retainedNative) ;
	// 正常切替後も原byteを保持し、通常verifyだけが現bindingを受理します。
	check( runCollectorSetupWorkspace( package, L"switch-package", root, review, verify) == 0) ;
	check( distributionRead( root / L"package-switches" / (review.native() + L".json")) == original &&
		  distributionRead( root / L"workspace.json") == current &&
		  distributionSwitchBytes( root, true) == retainedWorkspace &&
		  distributionSwitchBytes( native, false) == retainedNative) ;
	check( runCollectorSetupWorkspace( package, L"verify", root, {}, verify) == 0) ;
	bool repeated{} ;	// 原hashの二回適用はnative段階で止まります。
	try {
		static_cast<void>(
			runCollectorSetupWorkspace( package, L"switch-package", root, review, verify)) ;
	} catch( const std::exception &error) {
		repeated = std::string_view( error.what()) == "WORKSPACE_SWITCH_REVIEW_HASH" ;
	}

	check( repeated && verified >= 10U && distributionSwitchBytes( native, false) == retainedNative) ;
	std::printf(
		"PACKAGE_SWITCH_NATIVE assertions=%zu failures=0 actual_child=1 prior_raw_retained=1 native_byte_changes=0 http=0 tasks=0 grants=0\n",
		checks) ;
	return 0 ;
}
} // namespace drivercrate

/** @brief 明示された自己所有fixtureで固定子を実起動します。
 * @param[in] count 固定fixture引数数です。
 * @param[in] args 製品には存在しない試験引数です。
 * @return 期待通りの正常検査/待機時0です。
 */
int wmain( const int count, wchar_t *args[])
{
	try {
		winrt::init_apartment() ;
		check( (count == 3 || count == 4 || count == 5) && args != nullptr) ;
		const std::filesystem::path package( args[1]) ;	// Test生成済みの自己所有packageです。
		const std::filesystem::path root( args[2]) ;	// 同fixture内のworkspaceです。
		// 自己所有一fileで実immutable pinの共有拒否と旧mutable/解放後の対照を確認します。
		if( package == L"--file-pin-fixture") {
			drivercrate::createCollectorSetupProtectedRoot( root) ;
			const auto source = root / L"owned.json" ;			// 新規作成する一fileだけです。
			const auto target = root / L"owned-renamed.json" ;	// 同じ検証済みroot内の一時名です。
			check( root.is_absolute() && root == root.lexically_normal() &&
				  source.parent_path() == root && target.parent_path() == root &&
				  !std::filesystem::exists( target)) ;
			drivercrate::writeCollectorSetupProtectedMetadata( source, "{\"selfOwned\":true}",
															  false) ;
			const auto original =
				// 最後まで変更しない原byteです。
				drivercrate::distributionRead( source) ;
			{
				const auto held = drivercrate::openChecked(
					source, false, true) ;	// 製品の同じimmutable helperです。
				const HANDLE writer =
					CreateFileW( source.c_str(), GENERIC_WRITE,
								FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
								OPEN_EXISTING, 0U, nullptr) ;	// byteを書きません。
				const DWORD writeError =
					// 元結果です。
					writer == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS ;
				// 不意に開けた場合もhandleを閉じ、結果を失敗として保持します。
				if( writer != INVALID_HANDLE_VALUE) {
					check( CloseHandle( writer) != FALSE) ;
				}

				check( writer == INVALID_HANDLE_VALUE && writeError == ERROR_SHARING_VIOLATION) ;
				const BOOL moved =
					// 同じroot内だけで試します。
					MoveFileExW( source.c_str(), target.c_str(), 0U) ;
				const DWORD moveError =
					// 元結果です。
					moved == FALSE ? GetLastError() : ERROR_SUCCESS ;
				// 元に戻せる自己所有fileだけを扱い、成功してしまった原結果も保持します。
				if( moved != FALSE) {
					check( MoveFileExW( target.c_str(), source.c_str(), 0U) != FALSE) ;
				}

				check( moved == FALSE && moveError == ERROR_SHARING_VIOLATION) ;
			}
			{
				const auto mutableHeld = drivercrate::openChecked(
					source, false, false) ;	// 旧mutableのアクセスを変えません。
				const HANDLE writer =
					CreateFileW( source.c_str(), GENERIC_WRITE,
								FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
								OPEN_EXISTING, 0U, nullptr) ;	// 解放後の対照です。
				check( writer != INVALID_HANDLE_VALUE && CloseHandle( writer) != FALSE) ;
			}
			check( MoveFileExW( source.c_str(), target.c_str(), 0U) != FALSE &&
				  MoveFileExW( target.c_str(), source.c_str(), 0U) != FALSE &&
				  drivercrate::distributionRead( source) == original) ;
			std::printf(
				"IMMUTABLE_FILE_PIN assertions=%zu write_win32=32 rename_win32=32 mutable_write=1 released_rename=1 unchanged=1\n",
				checks) ;
			return 0 ;
		}

		// 元の実producer公開参照だけを同じ非通信import入口へ渡します。
		if( count == 5 && std::wstring_view{args[3]} == L"--import-reference-fixture") {
			return drivercrate::runCollectorSetupWorkspace( package, L"import-data", root, args[4],
														   [] {}) ;
		}

		// 製品CLIへ公開しない非通信hash回帰だけを先に振分けます。
		if( package == L"--hash-fixture") {
			return drivercrate::distributionHashFixtureChecks( root) ;
		}

		// 実producerのbyteを検査する独立fixtureです。鍵/運用admissionを呼びません。
		if( package == L"--validate-unsigned-fixture" || package == L"--decode-index-fixture") {
			check( count == 5) ;
			const auto manifest = drivercrate::readDistributionHashFixture(
				root, drivercrate::INDEX_MANIFEST_MAX_BYTES) ;	// 原実出力です。
			const auto gzip = drivercrate::readDistributionHashFixture(
				args[3], drivercrate::INDEX_ASSET_MAX_BYTES) ;	// 原実GZipです。
			const auto now = std::chrono::sys_seconds{
				std::chrono::seconds{std::stoll( args[4])}} ;	// 試験用の有限UTCです。
			const auto bytes =
				// 原byte viewです。
				std::as_bytes( std::span<const char>{gzip.data(), gzip.size()}) ;
			// 通常validatorは最小期限も検査します。
			if( package == L"--validate-unsigned-fixture") {
				const auto result = drivercrate::validateUnsignedIndexCandidate(
					manifest, bytes, now) ;	// 同じ製品関数です。
				// 未署名成功には元manifest拒否がなく、認証成功値もありません。
				if( result.receipt) {
					check( !result.manifestFailure) ;
				}

				const auto manifestFailure =
					result.manifestFailure
						? std::to_string( static_cast<unsigned>( *result.manifestFailure))
						: "NONE" ;	// 元拒否だけを表示します。
				std::printf(
					"UNSIGNED_FIXTURE status=%u manifestFailure=%s asset=%u records=%u receipt=%u authenticated=0 keyOperations=0\n",
					static_cast<unsigned>( result.status), manifestFailure.c_str(),
					static_cast<unsigned>( result.assetStatus),
					static_cast<unsigned>( result.recordsStatus), result.receipt ? 1U : 0U) ;
				return result.receipt ? 0 : 2 ;
			}

			const auto decoded = drivercrate::signed_index_detail::decodeIndexManifestData(
				manifest, drivercrate::index_distribution_trust::KEY_ID,
				now) ;	// 旧v2互換の共通意味codecです。
			check( decoded.data.has_value()) ;
			const auto asset = drivercrate::signed_index_detail::decodeIndexAssetData(
				*decoded.data, bytes, now) ;	// 実CRC/hashも検査します。
			check( asset.data.has_value()) ;
			const auto records = drivercrate::signed_index_detail::decodeIndexRecordsData(
				*decoded.data, asset.data->expanded, now) ;	// 同じ全recordです。
			std::printf( "DECODE_FIXTURE status=%u receipt=%u authenticated=0 keyOperations=0\n",
						static_cast<unsigned>( records.status), records.data ? 1U : 0U) ;
			return records.data ? 0 : 2 ;
		}

		// Fixture生成前にだけ既存creatorで保護rootを作り、既存ACLを修復しません。
		if( package == L"--prepare-fixture") {
			drivercrate::createCollectorSetupProtectedRoot( root / L"package") ;
			drivercrate::createCollectorSetupProtectedRoot( root / L"workspace") ;
			return 0 ;
		}

		// 既存更新だけを二processへ分け、間の明示reviewを外部共通toolで行います。
		if( count == 4 && (std::wstring_view{args[3]} == L"--existing-update-data-fixture" ||
						  std::wstring_view{args[3]} == L"--existing-update-complete-fixture")) {
			return drivercrate::distributionExistingUpdateFixtureChecks(
				package, root, std::wstring_view{args[3]} == L"--existing-update-complete-fixture") ;
		}

		const std::filesystem::path native =
			// 運用storeを使いません。
			root.parent_path() / L"native" ;
		const bool dailyData = count == 4 && std::wstring_view{args[3]} ==
												 L"--daily-data-fixture" ;	// 有限追加正例です。
		// 実native import入口から初期Aだけを取り込み、package seedを毎回入力にしません。
		if( dailyData) {
			check( drivercrate::runCollectorSetupWorkspace( package, L"import-data", root,
														  root.parent_path() / L"data-first",
														  [] {}) == 0) ;
		}

		// 新規originは実通信なしで初期化し、両側保存と実writerを確認します。
		check( drivercrate::runCollectorSetupWorkspace(
				  package, L"initialize-distribution-origins", root, {}, [] {}, native,
				  root / L"monitor") == 0) ;
		// 専用package切替fixtureは実HTTP callerを設定する前に終了します。
		if( count == 4 && std::wstring_view{args[3]} == L"--switch-package-fixture") {
			return drivercrate::distributionPackageSwitchFixtureChecks( package, root, native) ;
		}

		drivercrate::CollectorSetupAdmission
					 oldAdmission ;	// 旧admissionの空request拒否は維持します。
		std::wstring oldReason ;	// 旧APIの固定拒否理由です。
		check( drivercrate::acquireCollectorSetupAdmission( native, drivercrate::distributionUtc(),
														  oldAdmission,
														  oldReason) == ERROR_INVALID_DATA &&
			  oldReason == L"NATIVE_REQUEST_SCOPE_MISSING") ;
		const auto page =
			// 低位fakeの原本文です。
			drivercrate::distributionRead( package / L"fixture-page.txt") ;
		const auto payload = drivercrate::distributionRead(
			package / L"fixture-payload.bin") ;	// 架空archive byteです。
		Fixture state ;							// 送信・DNS・保存先は全て自己所有fakeです。
		fixture			= &state ;
		state.responses = {
			{page}, {payload, 200U, L"application/zip"}, {payload, 200U, L"application/zip"}} ;
		// 原hash不一致・不完全・過大・保存競合を各新規fixtureで一度だけ確認します。
		if( count == 4 && std::wstring_view{args[3]}.starts_with( L"--page-")) {
			const auto mode		  = std::wstring_view{args[3]} ;				// 製品CLIにない固定の試験modeです。
			const bool mismatch	  = mode == L"--page-mismatch-fixture" ;		// 同HTTPの原hash拒否です。
			const bool incomplete = mode == L"--page-incomplete-fixture" ;		// 部分受信です。
			const bool oversize	  = mode == L"--page-oversize-fixture" ;		// 元2MiB上限です。
			const bool conflict	  = mode == L"--page-save-conflict-fixture" ;	// 既存fileです。
			const bool saveFailure =
				// 通常fileでない先です。
				mode == L"--page-save-failure-fixture" ;
			check( mismatch || incomplete || oversize || conflict || saveFailure) ;
			const std::string changed =
				page + "<!-- same-response-change -->" ;	// 隔離fakeだけの変更です。
			state.responses = {{oversize ? std::string( 2U * 1024U * 1024U + 1U, 'x') : changed}} ;
			// 取得途中のread失敗を完全な本文保存へ昇格させません。
			if( incomplete) {
				state.chunkBytes	 = 16U ;
				state.failAfterBytes = 16U ;
			}

			drivercrate::CollectorDistributionTestAccess::fault( conflict	  ? 5U
																: saveFailure ? 6U
																			  : 0U) ;
			bool captureRejected{} ;	// 元取得拒否とは別の保存stageです。
			int	 exit = -1 ;			// 例外時に子の元終了値を捏造しません。
			try {
				exit = drivercrate::CollectorDistributionTestAccess::run( package, root) ;
			} catch( const std::exception &error) {
				captureRejected = std::string_view{error.what()}.starts_with(
					"DISTRIBUTION_PAGE_BODY_SAVE_FAILED:") ;
			}

			check( state.sends == 1U && captureRejected == (conflict || saveFailure) &&
				  ((conflict || saveFailure) || exit == 2)) ;
			const auto runs = root / L"monitor/distribution/runs" ;		// このfixtureの唯一runです。
			auto first = std::filesystem::directory_iterator( runs) ;	// 固定run一件を検査します。
			check( first != std::filesystem::directory_iterator{}) ;
			const auto directory = first->path() ;	// 自己所有の実runです。
			++first ;
			check( first == std::filesystem::directory_iterator{}) ;
			const auto result =
				drivercrate::SetupJson::Parse( winrt::to_hstring( drivercrate::distributionRead(
					directory / L"result-0.json"))) ;							// 元結果を保持します。
			const auto transfer = result.GetNamedObject( L"payloadTransfer") ;	// 未開始の元観測です。
			check( transfer.GetNamedString( L"stage") == L"UNSTARTED" &&
				  transfer.GetNamedNumber( L"attemptedRequests") == 0.0 &&
				  transfer.GetNamedNumber( L"bodyBytesRead") == 0.0 &&
				  !std::filesystem::exists( root / L"monitor/distribution/candidate-head.json")) ;
			const auto run = drivercrate::distributionSavedRun(
				root / L"monitor", directory.filename().native()) ;	// 元予約と全分母だけを読みます。
			check( run.GetNamedArray( L"targets").Size() == 2U) ;
			// 完全な相違PAGEは原byte/hashと0x8007051Aを保持し、後続host待機を解除しません。
			if( mismatch) {
				check(
					result.GetNamedNumber( L"error") ==
						HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) &&
					drivercrate::distributionRead( directory / L"page-0.body") == changed &&
					!std::filesystem::exists( directory / L"page-1.body") &&
					result.GetNamedObject( L"pageObservation").GetNamedString( L"bodySha256") ==
						drivercrate::distributionHash( changed) &&
					run.GetNamedArray( L"jobs").Size() == 1U &&
					run.GetNamedArray( L"jobs").GetAt( 0U).GetObject().GetNamedString( L"phase") ==
						L"SETTLED_MAXIMUM" &&
					run.GetNamedArray( L"jobs").GetAt( 0U).GetObject().GetNamedNumber(
						L"chargedRequests") == 4.0 &&
					run.GetNamedArray( L"targets").GetAt( 1U).GetObject().GetNamedString( L"status") ==
						L"DEFERRED" &&
					run.GetNamedArray( L"targets")
							.GetAt( 1U)
							.GetObject()
							.GetNamedArray( L"reasons")
							.GetAt( 0U)
							.GetString() == L"HOST_REVIEW_REQUIRED") ;
				const auto candidate =
					drivercrate::SetupJson::Parse( winrt::to_hstring( drivercrate::distributionRead(
						directory / L"candidate-0.json"))) ;	// 元投影0です。
				check( candidate.GetNamedArray( L"records").Size() == 0U) ;
			}
			// 保存失敗は元HRESULTと予約最大課金を変えず、専用stageだけを拒否します。
			else if( conflict || saveFailure) {
				check( result.GetNamedNumber( L"error") ==
						  HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) &&
					  run.GetNamedArray( L"jobs").GetAt( 0U).GetObject().GetNamedString( L"phase") ==
						  L"RESERVED" &&
					  !std::filesystem::exists( directory / L"candidate-0.json")) ;
				// 既存fileの上書きも失敗directoryの自動削除も行いません。
				if( conflict) {
					check( drivercrate::distributionRead( directory / L"page-0.body") ==
						  "existing-body-must-remain") ;
				} else {
					check( std::filesystem::is_directory( directory / L"page-0.body")) ;
				}
			} else {
				check( result.GetNamedNumber( L"error") != 0.0 &&
					  !std::filesystem::exists( directory / L"page-0.body") &&
					  !std::filesystem::exists( directory / L"page-1.body")) ;
			}

			std::printf(
				"PAGE_BODY_FIXTURE assertions=%zu sends=1 payload=0 candidate=0 capture_rejected=%u original_result=1\n",
				checks, captureRejected ? 1U : 0U) ;
			return 0 ;
		}

		// 同じEXE/moduleのままA初回→data追加B→同日再送0を同じ日次入口で確認します。
		if( dailyData) {
			bool denied{} ;	// 未同意では子/HTTP/Taskを呼びません。
			try {
				static_cast<void>(
					drivercrate::runCollectorSetupDistributionDaily( package, {}, false, [] {})) ;
			} catch( const std::exception &) {
				denied = true ;
			}

			check( denied && state.sends == 0U) ;
			check( drivercrate::runCollectorSetupDistributionDaily( package, root, true, [] {}) ==
					  0 &&
				  state.sends == 0U) ;
			const auto cloned =
				// 自己所有の別実directoryです。
				root.parent_path() / L"copied-package" ;
			drivercrate::createCollectorSetupProtectedRoot( cloned) ;
			// 同原manifest/同意byteのcopyだけでは別packageを許可しません。
			for( const auto member :
				{L"package-manifest.json", L"collector-distribution-daily-consent.json"}) {
				drivercrate::copyCollectorSetupProtectedFile( package / member, cloned / member) ;
			}

			bool copyDenied{} ;	// 実package identityの違いを固定stageで確認します。
			try {
				static_cast<void>(
					drivercrate::runCollectorSetupDistributionDaily( cloned, {}, false, [] {})) ;
			} catch( const std::exception &error) {
				copyDenied =
					std::string_view( error.what()) == "DISTRIBUTION_DAILY_CONSENT_REQUIRED" ;
			}

			check( copyDenied && state.sends == 0U) ;
			drivercrate::CollectorDistributionTestAccess::fault( 0U) ;
			check( drivercrate::CollectorDistributionTestAccess::run( package, root, 29U, true) ==
					  0 &&
				  state.sends == 2U) ;
			const auto firstHead = drivercrate::distributionRead(
				root / L"monitor/distribution/candidate-head.json") ;	// 元期限を保持します。
			check( drivercrate::runCollectorSetupWorkspace( package, L"import-data", root,
														  root.parent_path() / L"data-added",
														  [] {}) == 0 &&
				  state.sends == 2U) ;
			check( drivercrate::distributionRead(
					  root / L"monitor/distribution/candidate-head.json") == firstHead) ;
			state.sends		= 0U ;
			state.responses = {{page},
							   {drivercrate::distributionRead( package / L"fixture-payload-b.bin"),
								200U, L"application/zip"}} ;
			check( drivercrate::CollectorDistributionTestAccess::run( package, root, 29U, true) ==
					  2 &&
				  state.sends == 2U) ;
			const auto head =
				drivercrate::SetupJson::Parse( winrt::to_hstring( drivercrate::distributionRead(
					root / L"monitor/distribution/candidate-head.json"))) ;	// A旧成功+B新成功です。
			check( head.GetNamedNumber( L"generation") == 2.0 &&
				  head.GetNamedArray( L"includedCandidates").Size() == 2U) ;
			state.sends = 0U ;
			check( drivercrate::CollectorDistributionTestAccess::run( package, root, 29U, true) ==
					  2 &&
				  state.sends == 0U) ;
			const auto transfer =
				// 新規停止snapshotだけです。
				root.parent_path() / L"operational-export" ;
			check( drivercrate::runCollectorSetupWorkspace( package, L"export", root, transfer,
														  [] {}) == 0 &&
				  state.sends == 0U) ;
			const auto migrated =
				// 元identityを複写しません。
				root.parent_path() / L"migrated-workspace" ;
			check( drivercrate::runCollectorSetupWorkspace( package, L"import", migrated,
														  transfer / L"snapshot", [] {}) == 0 &&
				  state.sends == 0U) ;
			check(
				!std::filesystem::exists( migrated / L"monitor/distribution/candidate-head.json") &&
				std::filesystem::is_empty( migrated / L"monitor/distribution/runs") &&
				std::filesystem::exists( migrated / L"monitor/distribution/reference.json")) ;
			const auto importedHistory =
				drivercrate::SetupJson::Parse( winrt::to_hstring( drivercrate::distributionRead(
					migrated /
					L"monitor/distribution/portable-history.json"))) ;	// 世代と元cursorを保持します。
			check( importedHistory.GetNamedNumber( L"maximumGeneration") == 2.0 &&
				  importedHistory.GetNamedObject( L"runs").Size() == 3U) ;
			check( drivercrate::runCollectorSetupWorkspace( package, L"import-data", migrated,
														  root.parent_path() / L"data-added",
														  [] {}) == 0) ;
			check( drivercrate::runCollectorSetupWorkspace(
					  package, L"initialize-distribution-origins", migrated, {}, [] {},
					  root.parent_path() / L"migrated-native", migrated / L"monitor") == 0) ;
			check( drivercrate::runCollectorSetupDistributionDaily( package, migrated, true, [] {}) ==
				  0) ;
			check( drivercrate::CollectorDistributionTestAccess::run( package, migrated, 29U, true) ==
					  2 &&
				  state.sends == 0U) ;
			check( !std::filesystem::exists( migrated / L"monitor/distribution/candidate-head.json")) ;
			std::printf(
				"DISTRIBUTION_DAILY_DATA assertions=%zu first_gets=2 added_b_gets=2 a_resend=0 next_gets=0 copy_denied=1 real_tasks=0\n",
				checks) ;
			return 0 ;
		}

		// A社二製品の一packageとB社別packageを同じ親callerで投影します。
		if( count == 4 && (std::wstring_view{args[3]} == L"--parsed-producer-fixture" ||
						  std::wstring_view{args[3]} == L"--nested-producer-fixture" ||
						  std::wstring_view{args[3]} == L"--parsed-producer-mutated-fixture" ||
						  std::wstring_view{args[3]} == L"--producer-fixture" ||
						  std::wstring_view{args[3]} == L"--producer-partial-fixture" ||
						  std::wstring_view{args[3]} == L"--producer-failed-fixture")) {
			const auto mode	  = std::wstring_view{args[3]} ;	// 有限な正常/部分/全失敗fixtureです。
			const bool parsed = mode == L"--parsed-producer-fixture" ||
								mode == L"--nested-producer-fixture" ||
								// 実parserを通す新正例です。
								mode == L"--parsed-producer-mutated-fixture" ;
			const auto otherPayload = drivercrate::distributionRead(
				package / L"fixture-payload-b.bin") ;	// 別の架空archiveです。
			state.responses = {{page},
							   {payload, 200U, L"application/zip"},
							   {page},
							   {otherPayload, 200U, L"application/zip"}} ;
			drivercrate::CollectorDistributionTestAccess::fault( 0U) ;
			check( drivercrate::CollectorDistributionTestAccess::run(
					  package, root,
					  parsed						  ? 29U
					  : mode == L"--producer-fixture" ? 27U
					  : mode == L"--producer-partial-fixture"
						  ? 28U
						  : 9U) == (parsed || mode == L"--producer-fixture" ? 0 : 2)) ;
			check( state.sends == 4U && state.sessions.size() == 2U &&
				  state.sessions[0] != state.sessions[1]) ;
			// 全失敗では新head/assetを作りません。
			if( mode == L"--producer-failed-fixture") {
				check( !std::filesystem::exists( root / L"monitor/distribution/candidate-head.json")) ;
			} else {
				const auto head =
					drivercrate::SetupJson::Parse( winrt::to_hstring( drivercrate::distributionRead(
						root /
						L"monitor/distribution/candidate-head.json"))) ;	// 同親validator後だけのheadです。
				check( head.GetNamedNumber( L"generation") == 1.0 &&
					  !head.GetNamedBoolean( L"signingGenerationFinalized")) ;
			}

			std::printf(
				"DISTRIBUTION_PRODUCER_FIXTURE assertions=%zu sends=4 manufacturers=2 products=3 jobs=2 expectedRecords=%u authenticated=0 actualCatAccepted=0\n",
				checks,
				parsed || mode == L"--producer-fixture" ? 3U
				: mode == L"--producer-partial-fixture" ? 1U
														: 0U) ;
			return 0 ;
		}

		// 親死亡は別processとして実行し、このbranchでは実HTTP前に終了します。
		if( count == 4) {
			check( std::wstring_view( args[3]) == L"--parent-death") ;
			drivercrate::CollectorDistributionTestAccess::fault( 3U) ;
			static_cast<void>( drivercrate::CollectorDistributionTestAccess::run( package, root)) ;
			return 1 ;
		}

		drivercrate::CollectorDistributionTestAccess::fault( 4U) ;
		check( drivercrate::CollectorDistributionTestAccess::run( package, root) == 0) ;
		check( state.sends == 3U && state.sessions.size() == 2U &&
			  state.sessions[0] != state.sessions[1]) ;
		check( drivercrate::CollectorDistributionTestAccess::directoryMoveChecks == 1U) ;
		drivercrate::CollectorDistributionTestAccess::fault( 0U) ;
		const auto second = drivercrate::CollectorDistributionTestAccess::run(
			package, root) ;	// 同日の待機確認です。
		check( second == 2 && state.sends == 3U) ;
		// 同意なしは実child/HTTPより前に拒否します。
		bool consentRejected{} ;	// 通信権限のない呼出しを確認します。
		try {
			static_cast<void>( drivercrate::runCollectorSetupWorkspace(
				package, L"distribution-run-once", root, {}, [] {})) ;
		} catch( const std::exception &) {
			consentRejected = true ;
		}

		check( consentRejected && state.sends == 3U) ;
		const auto workspaceBytes = drivercrate::distributionRead(
			root / L"workspace.json") ;	// 新規自作rootへの同じpackage bindingです。
		std::size_t windowIndex{} ;		// 保存窓ごとに別の自作originを使います。
		// 全保存窓を一回ずつ停止し、同じ予定実体の非通信resumeを確認します。
		for( const auto stage : {L"PLANNED", L"NATIVE_READY", L"MONITOR_READY", L"NATIVE_MARKER",
								L"WORKSPACE_MARKER"}) {
			const auto windowRoot =
				root.parent_path() /
				(L"origin-window-" + std::to_wstring( windowIndex)) ;	// 当該窓専用です。
			const auto windowNative =
				root.parent_path() /
				(L"native-window-" + std::to_wstring( windowIndex++)) ;	// 再使用しません。
			drivercrate::createCollectorSetupProtectedRoot( windowRoot) ;
			drivercrate::writeCollectorSetupProtectedMetadata( windowRoot / L"workspace.json",
															  workspaceBytes, false) ;
			drivercrate::distributionInitializationProbe =
				[stage]( const std::wstring_view observed) {
					// 確定済みの同phaseだけを停止します。
					if( observed == stage) {
						throw std::runtime_error( "TEST_INITIALIZATION_STOP") ;
					}
				} ;
			bool stopped{} ;	// 期待した保存後停止を数えます。
			try {
				static_cast<void>( drivercrate::runCollectorSetupWorkspace(
					package, L"initialize-distribution-origins", windowRoot, {}, [] {},
					windowNative, windowRoot / L"monitor")) ;
			} catch( const std::exception &) {
				stopped = true ;
			}

			drivercrate::distributionInitializationProbe = {} ;
			check( stopped && drivercrate::runCollectorSetupWorkspace(
								 package, L"initialize-distribution-origins", windowRoot, {}, [] {},
								 windowNative, windowRoot / L"monitor") == 0) ;
		}

		// 予約欠損と実子死亡は本物callerがHTTP前に拒否し、native writerを解放します。
		for( const unsigned mode : {1U, 2U}) {
			const auto faultRoot =
				// 自作の停止fixtureです。
				root.parent_path() / (L"fault-" + std::to_wstring( mode)) ;
			const auto faultNative =
				root.parent_path() /
				(L"fault-native-" + std::to_wstring( mode)) ;	// 運用storeを使いません。
			drivercrate::createCollectorSetupProtectedRoot( faultRoot) ;
			drivercrate::writeCollectorSetupProtectedMetadata( faultRoot / L"workspace.json",
															  workspaceBytes, false) ;
			check( drivercrate::runCollectorSetupWorkspace(
					  package, L"initialize-distribution-origins", faultRoot, {}, [] {},
					  faultNative, faultRoot / L"monitor") == 0) ;
			state.sends = 0U ;
			drivercrate::CollectorDistributionTestAccess::fault( mode) ;
			bool rejected{} ;	// 実予約guardまたは実子生存guardの拒否です。
			try {
				static_cast<void>(
					drivercrate::CollectorDistributionTestAccess::run( package, faultRoot)) ;
			} catch( const std::exception &error) {
				rejected = std::string_view( error.what()) ==
						   (mode == 1U ? "DISTRIBUTION_REQUEST_NOT_RESERVED"
									   : "DISTRIBUTION_PERMIT_REJECTED") ;
			}

			check( rejected && state.sends == 0U &&
				  drivercrate::CollectorDistributionTestAccess::faultCalls == 1U &&
				  drivercrate::CollectorDistributionTestAccess::cleanupCalls == 1U &&
				  drivercrate::CollectorDistributionTestAccess::cleanupConfirmed) ;
			drivercrate::CollectorDistributionTestAccess::fault( 0U) ;
			drivercrate::LocalCollectorStateStore released ;	// 例外後の実lease解放を確認します。
			check( released.initializeExistingWriter( faultNative) == 0U) ;
			std::printf(
				"DISTRIBUTION_CHILD_CLEANUP mode=%u child_ended=1 lease_held_until_end=1 reacquired=1\n",
				mode) ;
		}

		// 未知legacyを拒否した場合も観測済みを単調保存し、消失後をpristineにしません。
		{
			drivercrate::LocalCollectorStateStore
				store ;	// 元の空native fixtureだけへ未知履歴を置きます。
			check( store.initializeExistingWriter( native) == 0U &&
				  store.write( L"current/unrecognized.json", "{}") == 0U) ;
		}
		bool unknownRejected{} ;	// 未知schemaを元全validatorが拒否したことを確認します。
		try {
			drivercrate::SetupJson origin ;		// 拒否時に使用しません。
			bool				   pristine{} ;	// 成功へ数えません。
			static_cast<void>( drivercrate::acquireCollectorDistributionAdmission( root, package,
																				 origin, pristine)) ;
		} catch( const std::exception &error) {
			unknownRejected = std::string_view( error.what()) == "DISTRIBUTION_LEGACY_INVALID" ;
		}

		check( unknownRejected &&
			  DeleteFileW( (native / L"current/unrecognized.json").c_str()) != FALSE) ;
		bool reverseRejected{} ;	// 空へ戻しても既知originをfreshにしません。
		try {
			drivercrate::SetupJson origin ;		// 拒否時に使用しません。
			bool				   pristine{} ;	// 成功へ数えません。
			static_cast<void>( drivercrate::acquireCollectorDistributionAdmission( root, package,
																				 origin, pristine)) ;
		} catch( const std::exception &error) {
			reverseRejected =
				std::string_view( error.what()) == "DISTRIBUTION_LEGACY_HISTORY_MISSING" ;
		}

		check( reverseRejected) ;
		// 元encoderが作った旧v4を同じnative原点へ追加し、専用legacy型への単調移行を確認します。
		{
			drivercrate::LocalCollectorStateStore store ;	// 自作nativeだけへ完全旧履歴を保存します。
			check( store.initializeExistingWriter( native) == 0U) ;
			// Fixtureの全旧runとpointerを省略せず同じ保護writerで保存します。
			for( const auto &entry :
				std::filesystem::recursive_directory_iterator( package / L"fixture-legacy")) {
				// 通常JSONだけを既存storeの固定相対memberへ渡します。
				if( entry.is_regular_file()) {
					check( store.write(
							  std::filesystem::relative( entry.path(), package / L"fixture-legacy"),
							  drivercrate::distributionRead( entry.path())) == 0U) ;
				}
			}
		}
		{
			drivercrate::SetupJson origin ;		// 専用admissionの実結果です。
			bool				   pristine{} ;	// 有効旧履歴はpristineにしません。
			auto				   admitted = drivercrate::acquireCollectorDistributionAdmission(
				  root, package, origin, pristine) ;	// 実writerです。
			check( !pristine && admitted.snapshot.fileCount >= 3U &&
				  !admitted.requestHashes.empty()) ;
		}
		// 受入済み旧履歴を非保存検査してもdescriptor/key/runのbyteを変えません。
		{
			const auto before =
				// 原key/全履歴です。
				drivercrate::distributionSwitchBytes( native, false) ;
			const auto descriptor = drivercrate::distributionRead(
				root / L"distribution-origin-init-v1.json") ;	// 受入済みdescriptorの原byteです。
			drivercrate::SetupJson origin ;						// 同じ三rootだけを受けます。
			bool				   pristine{} ;					// 受入済み旧履歴を空へ降格しません。
			auto				   admitted = drivercrate::acquireCollectorDistributionAdmission(
				  root, package, origin, pristine, false) ;	// 切替と同じ非保存modeです。
			check( !pristine && admitted.snapshot.fileCount >= 3U &&
				  drivercrate::distributionRead( root / L"distribution-origin-init-v1.json") ==
					  descriptor &&
				  drivercrate::distributionSwitchBytes( native, false) == before) ;
		}
		// 一度確認したlegacy runの欠損後にpristineへ戻さないことを実fileで確認します。
		const auto legacyRun =
			*std::filesystem::directory_iterator( native / L"runs") ;	// 自作の一runだけです。
		check( DeleteFileW( (L"\\\\?\\" + legacyRun.path().native()).c_str()) != FALSE) ;
		bool legacyRejected{} ;	// 履歴欠損をfreshへ降格しません。
		try {
			drivercrate::SetupJson origin ;		// 拒否時には外へ使用しません。
			bool				   pristine{} ;	// 拒否結果を成功扱いしません。
			static_cast<void>( drivercrate::acquireCollectorDistributionAdmission( root, package,
																				 origin, pristine)) ;
		} catch( const std::exception &) {
			legacyRejected = true ;
		}

		check( legacyRejected) ;
		std::printf(
			"DISTRIBUTION_PIPE_TEST assertions=%zu successful_sends=3 negative_sends=%zu failures=0\n",
			checks, state.sends) ;
		return 0 ;
	} catch( const std::exception &error) {
		std::printf( "DISTRIBUTION_PIPE_TEST_FAILED stage=%s\n", error.what()) ;
		return 1 ;
	} catch( ...) {
		std::printf( "DISTRIBUTION_PIPE_TEST_FAILED stage=UNKNOWN\n") ;
		return 1 ;
	}
}
