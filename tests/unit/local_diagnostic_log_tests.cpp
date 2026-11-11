//------------------------------------------------------------------------------
/**
 * @file local_diagnostic_log_tests.cpp
 * @brief 匿名診断の保存先/秘密非出力/有界保存/非阻害を実fileで確認します。
 * @version 01.04.04
 * @date 2026/11/03
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/03  非通信の固定snapshotと自己所有fileだけで回帰。
 * Ver.01.01.00 Shunji Ogawa  2026/11/08  匿名導入診断と保存状態・元数値の有限確認を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/11/08  同一索引の通信省略と元HTTP失敗cacheの数値を区別。
 * Ver.01.03.00 Shunji Ogawa  2026/11/08  準備不成立後の元表示保持と段階別匿名診断を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/11/08  元checkbox意図の表示保持とbinding拒否の固定診断を接続。
 * Ver.01.04.01 Shunji Ogawa  2026/11/09  準備投影の全recordと、pause再開・停止・固定queue満杯を検証。
 * Ver.01.04.02 Shunji Ogawa  2026/11/09  module/pathの同容量bufferをheapへ移し全期待を保持。
 * Ver.01.04.03 Shunji Ogawa  2026/11/09  fixture handleの有効所有とwrite/closeの元結果を明示。
 * Ver.01.04.04 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 * @note 実device/通信/導入/製品UIを使いません。Fixtureを削除せず検査結果として保持します。
 * @see docs/adr/0427-local-anonymous-scan-diagnostics.md
 */
//------------------------------------------------------------------------------
#include "platform/local_diagnostic_log.h"
#include "platform/local_scan_diagnostics.h"
#include "platform/provider_worker.h"
#include "core/provider_registry.h"
#include "core/device_observation.h"
#include <Windows.h>
#include <winioctl.h>
#include <wrl/wrappers/corewrappers.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
unsigned assertions{} ;	// 固定期待の分母です。
unsigned failures{} ;	// 原失敗を後続成功で隠しません。

//------------------------------------------------------------------------------
/**
 * @brief 個別期待を数値だけで集計します。
 * @param[in] value 実測した期待成立値。
 */
//------------------------------------------------------------------------------
void	 expect( const bool value)
{
	++assertions ;
	// 失敗箇所は連番だけを出力します。
	if( !value) {
		++failures ;
		std::printf( "FAIL assertion=%u\n", assertions) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 自己所有の新しいfixture directoryだけを作ります。
 * @param[in] path 絶対fixture位置。
 * @return 作成済みの同位置。
 */
//------------------------------------------------------------------------------
std::filesystem::path directory( const std::filesystem::path &path)
{
	// 古い成果物を無条件再利用せず、各実行で新しい有限fixtureを作ります。
	if( !std::filesystem::create_directory( path)) {
		throw std::runtime_error( "fixture directory exists") ;
	}

	return path ;
}

//------------------------------------------------------------------------------
/**
 * @brief FixtureだけをCREATE_NEWで書きます。
 * @param[in] path 未作成の自己所有path。
 * @param[in] bytes 非機密の架空本文。
 */
//------------------------------------------------------------------------------
void write( const std::filesystem::path &path, const std::string_view bytes)
{
	Microsoft::WRL::Wrappers::FileHandle file(
		CreateFileW( path.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
					nullptr)) ;	// 同fixtureの有効handleだけを所有します。
	expect( file.IsValid()) ;
	// 作れないfixtureを成功扱いしません。
	if( !file.IsValid()) {
		return ;
	}

	DWORD	   written{} ;	// 元write数です。
	const BOOL saved = WriteFile( file.Get(), bytes.data(), static_cast<DWORD>( bytes.size()),
								 &written, nullptr) ;	// 同一writeの元BOOLです。
	expect( saved != FALSE && written == bytes.size()) ;
	const BOOL closed = CloseHandle( file.Detach()) ;	// 同じ所有handleを一度だけ明示closeします。
	expect( closed != FALSE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 試験fileの有限本文を読みます。
 * @param[in] path 自己所有fileだけです。
 * @return 保存された原byte。不在は空です。
 */
//------------------------------------------------------------------------------
std::string read( const std::filesystem::path &path)
{
	std::ifstream stream( path, std::ios::binary) ;	// Fixtureの読取だけです。
	return std::string( std::istreambuf_iterator<char>( stream), std::istreambuf_iterator<char>()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定2slotの本文を試験中だけ連結します。
 * @param[in] folder 所有fixtureの親。
 * @return 固定2fileの原byteだけです。
 */
//------------------------------------------------------------------------------
std::string logs( const std::filesystem::path &folder)
{
	return read( folder / L"log/scan-0.log") + read( folder / L"log/scan-1.log") ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空の秘密本文と正常/未判定数を同じ元DTOへ入れます。
 * @return 認証能力や導入許可を持たない架空event。
 */
//------------------------------------------------------------------------------
drivercrate::WorkerEvent sample()
{
	using namespace drivercrate ;
	WorkerEvent event ;	// 非通信の固定snapshotだけです。
	event.operationId			   = 7U ;
	event.scanResult.succeeded	   = true ;
	event.scanResult.scanSessionId = 3U ;
	event.scanResult.outcome	   = OutcomeCode::SUCCEEDED_WITH_ERRORS ;
	auto &index					   = event.indexSummary ;	// 非機密件数です。
	index.status				   = IndexScanStatus::PARTIAL ;
	index.totalRecords			   = 26U ;
	index.processedRecords		   = 26U ;
	index.relationCount			   = 9U ;
	index.matchedRelations		   = 2U ;
	index.undeterminedRelations	   = 7U ;
	index.verifiedPartialRelations = 1U ;
	index.refresh.emplace() ;
	index.refresh->status					 = IndexRefreshStatus::MANIFEST_REJECTED ;
	index.refresh->error					 = E_ACCESSDENIED ;
	index.refresh->httpStatus				 = 200U ;
	index.refresh->attemptedGeneration		 = 12U ;
	index.refresh->store.persistedGeneration = 11U ;
	index.refresh->store.usableSnapshot		 = true ;
	event.preparationPlan.emplace() ;
	event.preparationPlan->targets.resize( 1U) ;
	event.preparationPlan->targets.front().eulaText = L"PRIVATE_SENTINEL_PLAN" ;
	UpdateCandidate current ;	// 一つの登録済み現在行です。
	current.current		   = true ;
	current.deviceIdentity = L"PRIVATE_SENTINEL_DEVICE" ;
	current.title		   = L"PRIVATE_SENTINEL_TITLE" ;
	current.version		   = L"PRIVATE_SENTINEL_VERSION" ;
	current.sourceLocation = L"PRIVATE_SENTINEL_URL" ;
	current.deviceObservation.emplace() ;
	current.deviceObservation->scanSessionId	= 3U ;
	current.deviceObservation->deviceIdentity	= current.deviceIdentity ;
	current.deviceObservation->driverKey.state	= DevicePropertyReadState::VALUE ;
	current.deviceObservation->node.read.state	= DevicePropertyReadState::VALUE ;
	current.deviceObservation->node.statusFlags = 0U ;
	current.deviceObservation->driverPresence	= DeviceDriverPresence::REGISTERED ;
	event.scanResult.candidates.push_back( current) ;
	UpdateCandidate pending ;	// 既存driverへの未検査参照です。
	pending.deviceIdentity			  = current.deviceIdentity ;
	pending.title					  = current.title ;
	pending.preparationTargetIdentity = L"PRIVATE_SENTINEL_TARGET" ;
	event.scanResult.candidates.push_back( pending) ;
	UpdateCandidate older ;	// 元分類は保持し版文字列から推定しません。
	older.action = DriverAction::DOWNGRADE ;
	older.assessment.emplace() ;
	older.assessment->applicability.reason = CandidateAssessmentReason::OS_MISMATCH ;
	event.scanResult.candidates.push_back( older) ;
	ProviderScanReport report ;	// 表示名を持っていてもcanonical IDだけを記録します。
	report.descriptor			  = *findProviderDescriptor( WINDOWS_UPDATE_PROVIDER_ID) ;
	report.descriptor.displayName = L"PRIVATE_SENTINEL_PROVIDER" ;
	report.state				  = ProviderScanState::NO_CANDIDATES ;
	event.scanResult.providerReports.push_back( report) ;
	return event ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元snapshotの秘密非出力と0/不明/関係/計画の区別を確認します。
 * @param[in] root 新規自己所有fixture。
 */
//------------------------------------------------------------------------------
void privacy( const std::filesystem::path &root)
{
	using namespace drivercrate ;
	const auto		   folder = directory( root / L"privacy") ;	// 専用fixtureです。
	LocalDiagnosticLog log ;									// 同じ製品writerを使います。
	local_diagnostic_detail::Access::start( log, folder.native()) ;
	recordScanDiagnostics( sample(), 2, false, &log) ;
	DiagnosticRecord unknown ;	// 不正Provider文字列は固定unknownになります。
	unknown.provider = DiagnosticProvider::fromId( L"PRIVATE_SENTINEL_CREDENTIAL") ;
	log.append( unknown) ;
	expect( local_diagnostic_detail::Access::drain( log)) ;
	log.stop() ;
	const auto bytes = logs( folder) ;	// 自己所有2fileだけです。
	expect( !bytes.empty() && bytes.find( "PRIVATE_SENTINEL") == std::string::npos) ;
	expect( bytes.find( "event=index_refresh") != std::string::npos &&
		   bytes.find( "attemptedGeneration=12") != std::string::npos) ;
	expect( bytes.find( "persistedGeneration=11") != std::string::npos &&
		   bytes.find( "httpStatus=200") != std::string::npos) ;
	expect( bytes.find( "matched=2") != std::string::npos &&
		   bytes.find( "undetermined=7") != std::string::npos) ;
	expect( bytes.find( "planPresent=1 targets=1 indexTargets=0") != std::string::npos) ;
	expect( bytes.find( "registeredReferences=1 unknownPresenceReferences=0") != std::string::npos) ;
	expect( bytes.find( "downgrades=1") != std::string::npos &&
		   bytes.find( "osRejected=1") != std::string::npos) ;
	expect( bytes.find( "provider=windows-update") != std::string::npos &&
		   bytes.find( "provider=unknown") != std::string::npos) ;
	WorkerEvent		   notRun ;	// 未実行と26record実読取の区別です。
	LocalDiagnosticLog second ;	// 所有形式の再利用も確認します。
	local_diagnostic_detail::Access::start( second, folder.native()) ;
	recordScanDiagnostics( notRun, 0, false, &second) ;
	expect( local_diagnostic_detail::Access::drain( second)) ;
	second.stop() ;
	expect( logs( folder).find( "known=0") != std::string::npos) ;
	expect( logs( folder).find( "attemptedGeneration=12") != std::string::npos) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 本体再取得の省略と元HTTP失敗のfallbackを既存数値だけで区別します。
 * @param[in] root 新規自己所有fixtureです。
 */
//------------------------------------------------------------------------------
void indexReuseProjection( const std::filesystem::path &root)
{
	using namespace drivercrate ;
	const auto		   folder = directory( root / L"index-reuse") ;	// この三状態だけの所有logです。
	LocalDiagnosticLog log ;										// 新event/fieldを作らず元writerへ投影します。
	local_diagnostic_detail::Access::start( log, folder.native()) ;
	// 同一成功・通常取得・元HTTP失敗cacheを同じ閉じた数値入口へ渡します。
	for( const auto status : {IndexRefreshStatus::UNCHANGED, IndexRefreshStatus::REFRESHED,
							 IndexRefreshStatus::AUTHENTICATED_CACHE}) {
		auto  event		   = sample() ;						// 秘密sentinelを持つ同じ元snapshotです。
		auto &refresh	   = *event.indexSummary.refresh ;	// 外へ原本文を渡さない要約です。
		refresh.status	   = status ;
		refresh.httpStatus = status == IndexRefreshStatus::AUTHENTICATED_CACHE ? 503U : 200U ;
		refresh.error	   = status == IndexRefreshStatus::AUTHENTICATED_CACHE
								 ? static_cast<NativeError>( E_FAIL)
								 : 0 ;
		refresh.httpError  = refresh.error ;
		refresh.sends	   = status == IndexRefreshStatus::REFRESHED ? 2U : 1U ;
		refresh.usedAuthenticatedCache = status != IndexRefreshStatus::REFRESHED ;
		recordScanDiagnostics( event, 2, false, &log) ;
	}

	expect( local_diagnostic_detail::Access::drain( log)) ;
	log.stop() ;
	const auto bytes = logs( folder) ;	// 実保存した三行の固定enum/数値だけを検査します。
	expect(
		bytes.find(
			"event=index_refresh provider=signed-index-acquisition operation=7 status=11 error=0") !=
		std::string::npos) ;
	expect(
		bytes.find(
			"event=index_refresh provider=signed-index-acquisition operation=7 status=0 error=0") !=
		std::string::npos) ;
	expect(
		bytes.find(
			"event=index_refresh provider=signed-index-acquisition operation=7 status=1 error=-2147467259") !=
		std::string::npos) ;
	expect( bytes.find( "httpStatus=200 httpError=0 sends=1") != std::string::npos &&
		   bytes.find( "httpStatus=503 httpError=2147500037 sends=1") != std::string::npos) ;
	expect( bytes.find( "PRIVATE_SENTINEL") == std::string::npos &&
		   bytes.find( "https:") == std::string::npos) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常EXE位置を使いcwdへfallbackしないことを確認します。
 * @param[in] root 新規自己所有fixture。
 * @throws std::bad_alloc module位置bufferを確保できない場合。mainの既存捕捉へ渡します。
 */
//------------------------------------------------------------------------------
void destination( const std::filesystem::path &root)
{
	using namespace drivercrate ;
	const auto cwd = directory( root / L"other-cwd") ;	// 実EXEとは異なる位置です。
	expect( SetCurrentDirectoryW( cwd.c_str()) != FALSE) ;
	LocalDiagnosticLog log ;	// テストEXE自身の実module位置だけを使います。
	log.start() ;
	log.append( DiagnosticRecord{}) ;
	expect( local_diagnostic_detail::Access::drain( log)) ;
	log.stop() ;
	std::wstring executable( 32768U, L'\0') ;	// 同容量をheapで零初期化した実module位置です。
	const DWORD	 size = GetModuleFileNameW(
		 nullptr, executable.data(), static_cast<DWORD>( executable.size())) ;	// Cwdから独立です。
	expect( size > 0U && size < executable.size()) ;
	const auto folder =
		// 実EXEの親だけです。
		std::filesystem::path( executable.data()).parent_path() ;
	expect( logs( folder).find( "event=startup") != std::string::npos) ;
	expect( !std::filesystem::exists( cwd / L"log")) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不明/容量超過/保存不能fileを変更せず通常callerへ戻ります。
 * @param[in] root 新規自己所有fixture。
 */
//------------------------------------------------------------------------------
void failuresNonblocking( const std::filesystem::path &root)
{
	using namespace drivercrate ;
	const auto folder = directory( root / L"unknown") ;	// 不明fileを置くfixtureです。
	directory( folder / L"log") ;
	write( folder / L"log/scan-0.log", "UNKNOWN_USER_FILE") ;
	write( folder / L"log/scan-1.log",
		  "# DriverCrate anonymous diagnostics v1 app=1.0.0\nPRIVATE_SENTINEL_BODY\n") ;
	const auto		   before = logs( folder) ;	// 不明原byteを保持します。
	LocalDiagnosticLog log ;					// 拒否してもappendはcallerへ戻ります。
	local_diagnostic_detail::Access::start( log, folder.native()) ;
	const auto started = GetTickCount64() ;	// 非待機投入の上限確認だけです。
	// 大量の投入も有限queueを越して待機しません。
	for( unsigned index{}; index < 10000U; ++index) {
		log.append( DiagnosticRecord{}) ;
	}

	expect( GetTickCount64() - started < 2000U) ;
	expect( local_diagnostic_detail::Access::drain( log)) ;
	log.stop() ;
	expect( logs( folder) == before) ;
	const auto blocked = directory( root / L"blocked") ;	// logが通常fileのケースです。
	write( blocked / L"log", "UNKNOWN_BLOCKER") ;
	LocalDiagnosticLog noFolder ;	// 書込不可を通信/導入の失敗へしません。
	local_diagnostic_detail::Access::start( noFolder, blocked.native()) ;
	noFolder.append( DiagnosticRecord{}) ;
	expect( local_diagnostic_detail::Access::drain( noFolder)) ;
	noFolder.stop() ;
	expect( read( blocked / L"log") == "UNKNOWN_BLOCKER") ;
	LocalDiagnosticLog relative ;	// 相対folderは内部fixtureでも拒否します。
	local_diagnostic_detail::Access::start( relative, L"relative") ;
	relative.append( DiagnosticRecord{}) ;
	expect( local_diagnostic_detail::Access::drain( relative)) ;
	relative.stop() ;
	expect( !std::filesystem::exists( L"relative/log")) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実hardlinkが別fileへ追記/切詰めしないことを確認します。
 * @param[in] root 新規自己所有fixture。
 */
//------------------------------------------------------------------------------
void hardlink( const std::filesystem::path &root)
{
	using namespace drivercrate ;
	const auto folder = directory( root / L"hardlink") ;	// 自己所有のlinkだけです。
	directory( folder / L"log") ;
	write( folder / L"outside.txt", "UNCHANGED_HARDLINK_TARGET") ;
	expect( CreateHardLinkW( (folder / L"log/scan-0.log").c_str(), (folder / L"outside.txt").c_str(),
						   nullptr) != FALSE) ;
	write( folder / L"log/scan-1.log", "UNKNOWN_SECOND_SLOT") ;
	LocalDiagnosticLog log ;	// Link数2の実fileは再利用しません。
	local_diagnostic_detail::Access::start( log, folder.native()) ;
	log.append( DiagnosticRecord{}) ;
	expect( local_diagnostic_detail::Access::drain( log)) ;
	log.stop() ;
	expect( read( folder / L"outside.txt") == "UNCHANGED_HARDLINK_TARGET") ;
}

//------------------------------------------------------------------------------
/**
 * @brief 自己所有directoryの実junctionを使ってreparse拒否を確認します。
 * @param[in] root 新規自己所有fixture。
 */
//------------------------------------------------------------------------------
void junction( const std::filesystem::path &root)
{
	using namespace drivercrate ;
	const auto		   folder	  = directory( root / L"junction") ;		// Rootも参照先も自己所有です。
	const auto		   target	  = directory( folder / L"target") ;		// 空の参照先です。
	const auto		   link		  = directory( folder / L"log") ;			// Junction化する空directoryです。
	const std::wstring substitute = L"\\??\\" + target.native() ;			// NT形式のfixture参照先です。
	const auto count = substitute.size() + target.native().size() + 2U ;	// Null二つを含みます。
	std::vector<std::byte>	   bytes( 16U +
									 count * sizeof( wchar_t)) ;	// REPARSE_DATA_BUFFERの有限容量です。
	const DWORD				   tag = IO_REPARSE_TAG_MOUNT_POINT ;	// NTFS mount pointの固定tagです。
	const std::array<WORD, 6U> fields{static_cast<WORD>( 8U + count * sizeof( wchar_t)), 0U, 0U,
									  static_cast<WORD>( substitute.size() * sizeof( wchar_t)),
									  static_cast<WORD>( (substitute.size() + 1U) * sizeof( wchar_t)),
									  // 固定header layoutだけです。
									  static_cast<WORD>( target.native().size() * sizeof( wchar_t))} ;
	std::memcpy( bytes.data(), &tag, sizeof( tag)) ;
	std::memcpy( bytes.data() + 4U, fields.data(), sizeof( fields)) ;
	std::memcpy( bytes.data() + 16U, substitute.c_str(), (substitute.size() + 1U) * sizeof( wchar_t)) ;
	std::memcpy( bytes.data() + 16U + (substitute.size() + 1U) * sizeof( wchar_t), target.c_str(),
				(target.native().size() + 1U) * sizeof( wchar_t)) ;
	Microsoft::WRL::Wrappers::FileHandle handle(
		CreateFileW( link.c_str(), GENERIC_WRITE, 0U, nullptr, OPEN_EXISTING,
					FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
					nullptr)) ;	// 空の所有directoryだけです。
	expect( handle.IsValid()) ;
	// 所有handleの不成立を記録し、無効なI/Oへ進めません。
	if( !handle.IsValid()) {
		return ;
	}

	DWORD	   returned{} ;	// 元API結果です。
	const BOOL configured = DeviceIoControl( handle.Get(), FSCTL_SET_REPARSE_POINT, bytes.data(),
											static_cast<DWORD>( bytes.size()), nullptr, 0U,
											&returned, nullptr) ;	// 元API結果だけです。
	expect( configured != FALSE) ;
	const BOOL closed = CloseHandle( handle.Detach()) ;	// 同じ所有handleを一度だけ閉じます。
	expect( closed != FALSE) ;
	LocalDiagnosticLog log ;	// Junctionへはfileを作りません。
	local_diagnostic_detail::Access::start( log, folder.native()) ;
	log.append( DiagnosticRecord{}) ;
	expect( local_diagnostic_detail::Access::drain( log)) ;
	log.stop() ;
	expect( std::filesystem::is_empty( target)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実writeで固定2slotの容量と所有形式の再利用を確認します。
 * @param[in] root 新規自己所有fixture。
 */
//------------------------------------------------------------------------------
void capacity( const std::filesystem::path &root)
{
	using namespace drivercrate ;
	const auto		   folder = directory( root / L"capacity") ;	// 大量でも二fileだけです。
	LocalDiagnosticLog log ;										// 製品と同じ256KiB上限です。
	local_diagnostic_detail::Access::start( log, folder.native()) ;
	DiagnosticRecord record ;	// 長めでも型付き有限の一行です。
	record.event = DiagnosticEvent::CANDIDATE_DISPLAY ;
	// 最大16列を使って実byte上限へ到達させます。
	for( unsigned index{}; index < record.fields.size(); ++index) {
		record.add( static_cast<DiagnosticField>( index), 123456789012345U) ;
	}

	// 有限batchごとに排出し、queue落ちだけで容量試験を通しません。
	for( unsigned batch{}; batch < 48U; ++batch) {
		// 128記録ずつなので通常queue上限内です。
		for( unsigned index{}; index < 128U; ++index) {
			record.operation = batch * 128U + index + 1U ;
			log.append( record) ;
		}

		expect( local_diagnostic_detail::Access::drain( log)) ;
	}

	log.stop() ;
	std::uintmax_t total{} ;	// 固定二fileの実byte合計です。
	unsigned	   files{} ;	// 予期しないfile増加を検出します。
	// 自己所有log directoryだけを読取り、削除しません。
	for( const auto &entry : std::filesystem::directory_iterator( folder / L"log")) {
		++files ;
		const auto size = entry.file_size() ;	// 各slotの実sizeです。
		expect( size <= 256U * 1024U) ;
		total += size ;
	}

	expect( files == 2U && total <= 512U * 1024U && total > 256U * 1024U) ;
	expect( logs( folder).find( "operation=6144") != std::string::npos) ;
}
}

//------------------------------------------------------------------------------
/**
 * @brief 起動flush/保存失敗/有界終了の元状態を確認します。
 * @param[in] root 自己所有の新規fixtureです。
 */
//------------------------------------------------------------------------------
void storageHealth( const std::filesystem::path &root)
{
	using namespace drivercrate ;
	const auto		   folder = directory( root / L"日本語 space") ;	// 通常DOSのUnicode位置です。
	LocalDiagnosticLog log ;										// 実製品writerだけを使います。
	expect( log.status().state == DiagnosticStorageState::NOT_STARTED) ;
	local_diagnostic_detail::Access::start( log, folder.native()) ;
	log.append( DiagnosticRecord{}) ;
	expect( local_diagnostic_detail::Access::drain( log)) ;
	const auto active = log.status() ;	// 投入成功だけでなくflush済みを読みます。
	expect( active.state == DiagnosticStorageState::ACTIVE && active.startupFlushed &&
		   active.saved == 1U && active.pending == 0U && active.dropped == 0U) ;
	log.stop() ;
	expect( log.status().state == DiagnosticStorageState::STOPPED) ;
	// Writer局所失敗と終了待機を分けた固定条件です。
	for( const auto stage : {DiagnosticStorageStage::WRITE, DiagnosticStorageStage::FLUSH,
							DiagnosticStorageStage::STOP}) {
		const auto		   place = directory( root / (L"health-" +
											 // 有限fixtureです。
											 std::to_wstring( static_cast<unsigned>( stage)))) ;
		LocalDiagnosticLog failing ;	// 前のwriterの資源を再利用しません。
		local_diagnostic_detail::Access::start( failing, place.native()) ;
		failing.append( DiagnosticRecord{}) ;
		expect( local_diagnostic_detail::Access::drain( failing)) ;
		local_diagnostic_detail::Access::fail( failing, stage) ;
		// 停止待機はqueue保存失敗と別に注入します。
		if( stage == DiagnosticStorageStage::STOP) {
			const auto began = GetTickCount64() ;	// 有界終了の実時間だけです。
			failing.stop() ;
			expect( GetTickCount64() - began < 1000U) ;
			expect( failing.status().state == DiagnosticStorageState::STOP_TIMEOUT &&
				   failing.status().stage == DiagnosticStorageStage::STOP &&
				   !failing.status().codeKnown) ;
		} else {
			DiagnosticRecord record ;	// 起動行の後の一記録だけを失敗させます。
			record.event = DiagnosticEvent::INSTALL_STARTED ;
			failing.append( record) ;
			expect( local_diagnostic_detail::Access::drain( failing)) ;
			const auto failed = failing.status() ;	// 元停止理由を読みます。
			expect( failed.state == DiagnosticStorageState::FAILED && failed.stage == stage &&
				   failed.codeKnown &&
				   failed.code == static_cast<std::uint32_t>( stage == DiagnosticStorageStage::WRITE
																 ? ERROR_WRITE_FAULT
																 : ERROR_GEN_FAILURE) &&
				   failed.saved == 1U && failed.pending == 1U) ;
			failing.stop() ;
		}

		expect( local_diagnostic_detail::Access::drain( failing)) ;
	}

	const auto locked = directory( root / L"health-locked") ;	// 実共有拒否だけです。
	directory( locked / L"log") ;
	write( locked / L"log/scan-0.log", "LOCKED_ORIGINAL") ;
	write( locked / L"log/scan-1.log", "UNKNOWN_ORIGINAL") ;
	Microsoft::WRL::Wrappers::FileHandle handle(
		CreateFileW( (locked / L"log/scan-0.log").c_str(), GENERIC_READ, 0U, nullptr, OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL, nullptr)) ;	// 同scopeで自己所有fileだけをlockします。
	expect( handle.IsValid()) ;
	// 未取得handleの失敗を保持し、共有拒否のfixtureを偽造しません。
	if( !handle.IsValid()) {
		return ;
	}

	LocalDiagnosticLog denied ;	// 未知slotと共有拒否を消して救済しません。
	local_diagnostic_detail::Access::start( denied, locked.native()) ;
	denied.append( DiagnosticRecord{}) ;
	expect( local_diagnostic_detail::Access::drain( denied)) ;
	const auto failure = denied.status() ;	// 最初の元codeです。
	expect( failure.state == DiagnosticStorageState::FAILED &&
		   failure.stage == DiagnosticStorageStage::SLOT && failure.codeKnown &&
		   failure.code == ERROR_SHARING_VIOLATION) ;
	denied.stop() ;
	const BOOL closed = CloseHandle( handle.Detach()) ;	// 元の停止後に同lockだけを解除します。
	expect( closed != FALSE) ;
	expect( read( locked / L"log/scan-0.log") == "LOCKED_ORIGINAL" &&
		   read( locked / L"log/scan-1.log") == "UNKNOWN_ORIGINAL") ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元個別/role/postの数値投影と、版文字列の非出力を確認します。
 * @param[in] root 自己所有の新規fixtureです。
 */
//------------------------------------------------------------------------------
void installProjection( const std::filesystem::path &root)
{
	using namespace drivercrate ;
	// 正常/不変/比較不能/読取失敗/重複/別session/別device/事前不明/未導入を有限確認します。
	for( unsigned variant{}; variant < 10U; ++variant) {
		const auto folder =
			// 新規fixtureです。
			directory( root / (L"install-" + std::to_wstring( variant))) ;
		LocalDiagnosticLog log ;	// 同じwriterへ投影します。
		local_diagnostic_detail::Access::start( log, folder.native()) ;
		log.append( DiagnosticRecord{}) ;
		UpdateCandidate current ;	// 原文字列は出力禁止sentinelです。
		current.identity	   = L"PRIVATE_SENTINEL_CURRENT" ;
		current.deviceIdentity = L"PRIVATE_SENTINEL_DEVICE" ;
		current.current		   = true ;
		current.version		   = L"2.1.5.7" ;
		DeviceObservation observation ;	// 同scanへ結ぶ読取状態だけです。
		observation.scanSessionId	 = 791U ;
		observation.deviceIdentity	 = current.deviceIdentity ;
		observation.driverPresence	 = DeviceDriverPresence::REGISTERED ;
		observation.node.read.state	 = DevicePropertyReadState::VALUE ;
		observation.node.statusFlags = 0U ;
		observation.driverKey.state	 = DevicePropertyReadState::VALUE ;
		observation.version.state	 = DevicePropertyReadState::VALUE ;
		current.deviceObservation	 = observation ;
		auto candidate				 = current ;	// 実行能力やnative呼出しを作らない入力です。
		candidate.identity			 = L"PRIVATE_SENTINEL_CANDIDATE" ;
		candidate.current			 = false ;
		candidate.deviceObservation.reset() ;
		candidate.installable = true ;
		candidate.action	  = DriverAction::UPDATE ;
		candidate.providerId  = DRIVER_STORE_PROVIDER_ID ;
		candidate.version	  = variant == 9U ? L"621.14" : L"2.1.5.12" ;
		candidate.title		  = L"PRIVATE_SENTINEL_TITLE" ;
		std::vector<UpdateCandidate> candidates{current, candidate} ;	// 原順序です。
		WorkerEvent					 event ;							// 本文をserializeしない元終端です。
		event.operationId				   = 791U ;
		event.installResult.installOutcome = OutcomeCode::SUCCEEDED_WITH_ERRORS ;
		event.installResult.updates.push_back( {.identity		= candidate.identity,
											   .downloadOutcome = OutcomeCode::SUCCESS,
											   .installOutcome = OutcomeCode::SUCCEEDED_WITH_ERRORS,
											   .installError   = static_cast<NativeError>( S_FALSE),
											   .rebootRequired = true}) ;
		event.installResult.updates.front().requiredRoles = {
			{.role			 = DriverPlanRole::BASE_DRIVER,
			 .ordinal		 = 1U,
			 .stageOutcome	 = OutcomeCode::SUCCESS,
			 .installOutcome = OutcomeCode::SUCCESS,
			 .reflection	 = DriverPlanReflectionState::INSTALL_API_COMPLETED},
			{.role		   = DriverPlanRole::DRIVER_COMPONENT,
			 .ordinal	   = 2U,
			 .stageOutcome = OutcomeCode::SUCCESS,
			 .reflection   = DriverPlanReflectionState::WINDOWS_PENDING}} ;
		PostInstallDeviceObservation post ;	// 元返却DTOだけです。
		post.observation = observation ;
		post.version	 = variant == 1U ? L"2.1.5.7" : L"2.1.5.12" ;
		post.name		 = L"PRIVATE_SENTINEL_NAME" ;
		// 欠測や読取不能を版変化なしへ補完しません。
		if( variant == 2U) {
			post.version = L"PRIVATE_SENTINEL_UNKNOWN_VERSION" ;
		}
		// 読取拒否を元codeで保持します。
		else if( variant == 3U) {
			post.error = static_cast<NativeError>( E_ACCESSDENIED) ;
		}
		// 別scanの観測は比較しません。
		else if( variant == 5U) {
			post.observation.scanSessionId = 792U ;
		}
		// 別deviceへ現在値を移しません。
		else if( variant == 6U) {
			post.observation.deviceIdentity += L"-other" ;
		}
		// 事前の現在観測欠損は比較不能です。
		else if( variant == 7U) {
			candidates.front().deviceObservation.reset() ;
		}
		// 未導入の元観測を版の比較へ昇格しません。
		else if( variant == 8U) {
			post.observation.driverPresence	  = DeviceDriverPresence::NOT_INSTALLED ;
			post.observation.node.problemCode = 28U ;
			post.observation.node.statusFlags = 0x400U ;
			post.observation.driverKey.state  = DevicePropertyReadState::EMPTY ;
			post.observation.version.state	  = DevicePropertyReadState::EMPTY ;
			post.version.clear() ;
		}

		event.installResult.currentDevices.push_back( post) ;
		// 重複DTOを先頭採用しません。
		if( variant == 4U) {
			event.installResult.currentDevices.push_back( post) ;
		}

		const std::array<std::size_t, 1> selected{1U} ;	// 元一件だけです。
		recordInstallSelectionDiagnostics( 790U, candidates, selected, false, &log) ;
		recordInstallSelectionDiagnostics( 791U, candidates, selected, true, &log) ;
		OfficialPreparationApproval approval ;	// 本文/identityの非出力を確認します。
		approval.operationId			 = 790U ;
		approval.installIntentIdentities = {candidate.identity} ;
		recordPreparationDiagnostics( approval, nullptr, 3, &log) ;
		OfficialPreparationOperationResult prepared ;	// 元READY件数だけです。
		prepared.approvalError = OfficialPreparationError::NONE ;
		prepared.installResolutions.push_back(
			{candidate.identity, candidate.identity, PreparedInstallResolutionState::READY}) ;
		recordPreparationDiagnostics( approval, &prepared, 2, &log) ;
		recordInstallDiagnostics( event, 791U, candidates, 8, &log) ;
		expect( local_diagnostic_detail::Access::drain( log)) ;
		log.stop() ;
		const auto bytes = logs( folder) ;	// 保存した元byteだけです。
		expect( bytes.find( "PRIVATE_SENTINEL") == std::string::npos &&
			   bytes.find( "2.1.5.") == std::string::npos &&
			   bytes.find( "621.14") == std::string::npos) ;
		expect( bytes.find( "event=install_requested") != std::string::npos &&
			   bytes.find( "event=install_started") != std::string::npos &&
			   bytes.find( "event=preparation_operation") != std::string::npos &&
			   bytes.find( "readyCount=1") != std::string::npos) ;
		expect( bytes.find( "event=install_item provider=driver-store") != std::string::npos &&
			   bytes.find( "rebootRequired=1") != std::string::npos &&
			   bytes.find( "event=install_role") != std::string::npos &&
			   bytes.find( "event=install_protection") != std::string::npos) ;
		constexpr std::array<unsigned, 10> requested{1U, 2U, 0U, 0U, 0U,
													 0U, 0U, 1U, 0U, 0U} ;	// 独立期待です。
		constexpr std::array<unsigned, 10> changed{
			2U, 1U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 2U} ;	// 不明を変化なしへ補完しません。
		expect( bytes.find( "requestVersionRelation=" + std::to_string( requested[variant]) +
						  " beforeVersionRelation=" + std::to_string( changed[variant])) !=
			   std::string::npos) ;
		expect( log.status().startupFlushed && log.status().saved > 0U &&
			   log.status().pending == 0U) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元の準備段階・省略数・UI拒否を本文なしで保存します。
 * @param[in] root このtestだけが所有する新規fixture親です。
 */
//------------------------------------------------------------------------------
void preparationProjection( const std::filesystem::path &root)
{
	using namespace drivercrate ;
	// 正当summaryの有無を別slotで確認し、未検証の内容を投影しません。
	for( unsigned variant{}; variant < 2U; ++variant) {
		// 自己所有の新規slotだけへ匿名投影します。
		const auto		   folder = directory( root / (L"preparation-" + std::to_wstring( variant))) ;
		LocalDiagnosticLog log ;	// 実製品と同じ有界writerです。
		local_diagnostic_detail::Access::startPaused( log, folder.native()) ;
		OfficialPreparationApproval approval ;	// 私有文字列は内部結合にだけ使います。
		approval.operationId   = 798U ;
		approval.scanSessionId = 798U ;
		approval.planId		   = 798U ;
		OfficialPreparationOperationResult result ;	// 人工DTOの原数値だけです。
		result.approvalError = OfficialPreparationError::NONE ;
		IndexPreparationSummary index ;	// このfixtureでは全件照合済みの入力です。
		index.operationId	= approval.operationId ;
		index.scanSessionId = approval.scanSessionId ;
		index.planId		= approval.planId ;
		// 先頭16件だけが投影され、後二件は元総数と省略数へ残します。
		for( unsigned ordinal{}; ordinal < 18U; ++ordinal) {
			OfficialPreparationDecision decision ;	// Sentinelは記録されない本文です。
			decision.target.identity   = L"PRIVATE_SENTINEL_TARGET_" + std::to_wstring( ordinal) ;
			decision.target.providerId = SIGNED_INDEX_PROVIDER_ID ;
			decision.acquire		   = true ;
			approval.decisions.push_back( decision) ;
			approval.installIntentIdentities.push_back( L"PRIVATE_SENTINEL_INTENT_" +
													   std::to_wstring( ordinal)) ;
			result.items.push_back(
				{decision.target.identity,
				 {OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0, 1024U}}) ;
			OfficialPreparationAuditReport report ;	// 各拒否codeを独立段階へ渡します。
			report.targetIdentity						 = decision.target.identity ;
			report.providerId							 = SIGNED_INDEX_PROVIDER_ID ;
			report.content								 = CandidateAuditGateState::REJECTED ;
			report.contentError							 = static_cast<NativeError>( E_FAIL) ;
			report.firstContentRejection				 = static_cast<NativeError>( E_ACCESSDENIED) ;
			report.applicability						 = CandidateAuditGateState::PENDING ;
			report.firstPairError						 = static_cast<NativeError>( E_INVALIDARG) ;
			report.publication.firstError				 = static_cast<NativeError>( E_NOTIMPL) ;
			report.publication.bindingPath				 = 2U ;
			report.publication.bindingRejection			 = 201U ;
			report.publication.bindingObserved			 = 64U ;
			report.publication.bindingStage				 = 111U ;
			report.publication.bindingFlags				 = 29U ;
			report.publication.dependencyReason			 = 4U ;
			report.publication.rootSignatureError		 = static_cast<NativeError>( E_FAIL) ;
			report.publication.dependencySignatureError	 = static_cast<NativeError>( E_ACCESSDENIED) ;
			report.publication.dependencyProvenanceError = static_cast<NativeError>( E_INVALIDARG) ;
			report.infCount								 = 1U ;
			result.auditReports.push_back( report) ;
			result.installResolutions.push_back( {approval.installIntentIdentities.back(), L"",
												 ordinal == 0U
													 ? PreparedInstallResolutionState::READY
													 : PreparedInstallResolutionState::NOT_READY}) ;
			index.items.push_back( {.targetIdentity = decision.target.identity,
								   .acquisition = OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION,
								   .content = IndexedDriverInspectionState::INSPECTION_COMPLETED,
								   .firstInfRejection  = static_cast<NativeError>( E_ACCESSDENIED),
								   .inputBound		   = true,
								   .inventoryFileCount = 3U,
								   .infCount		   = 1U,
								   .parsedInfCount	   = 1U,
								   .signatureRejectedInfCount = 1U,
								   .auxiliaryHttp			  = {1U, 123U, 200U}}) ;
		}

		recordPreparationResultDiagnostics( approval, result, variant == 0U ? &index : nullptr,
										   &log) ;
		recordPreparationContinuationDiagnostics(
			approval.operationId, PreparationContinuationReason::SELECTION_REJECTED, 18U, 1U, &log) ;
		// 有限batchは既256枠内で、排出開始前に全元recordを欠落なく投入します。
		expect( log.status().saved == 0U && log.status().pending > 0U &&
			   log.status().pending <= 256U && log.status().dropped == 0U) ;
		local_diagnostic_detail::Access::resume( log) ;
		expect( local_diagnostic_detail::Access::drain( log)) ;
		log.stop() ;
		const auto bytes = logs( folder) ;	// 自己所有slotの保存済みbyteです。
		expect( bytes.find( "PRIVATE_SENTINEL") == std::string::npos) ;
		expect( bytes.find( "selectedCount=18 processed=16 omitted=2") != std::string::npos) ;
		expect( bytes.find( "event=preparation_resolution") != std::string::npos &&
			   bytes.find( "ordinal=16 ") != std::string::npos &&
			   bytes.find( "ordinal=17 ") == std::string::npos) ;
		expect( bytes.find( "stage=1 bound=1 codeKnown=1") != std::string::npos &&
			   bytes.find( "error=-2147467259") != std::string::npos &&
			   bytes.find( "stage=2 bound=1 codeKnown=1") != std::string::npos &&
			   bytes.find( "error=-2147024891") != std::string::npos) ;
		expect( bytes.find( "stage=4 bound=1 codeKnown=1") != std::string::npos &&
			   bytes.find( "error=-2147024809") != std::string::npos &&
			   bytes.find( "stage=5 bound=1 codeKnown=1") != std::string::npos) ;
		expect( (bytes.find( "stage=6 ") != std::string::npos) == (variant == 0U) &&
			   (bytes.find( "signatureRejectedCount=1") != std::string::npos) == (variant == 0U)) ;
		expect(
			bytes.find(
				"event=preparation_continuation provider=application operation=798 status=11 error=0 intentCount=18 readyCount=1 codeKnown=0") !=
			std::string::npos) ;
		expect(
			bytes.find(
				"bindingPath=2 bindingRejection=201 bindingObserved=64 bindingStage=111 bindingFlags=29 dependencyReason=4 rootSignatureError=2147500037 dependencySignatureError=2147942405 dependencyProvenanceError=2147942487") !=
			std::string::npos) ;
		expect( log.status().dropped == 0U && log.status().pending == 0U) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 内部pauseの再開・停止解除と、固定queue満杯の欠落計上を確認します。
 * @param[in] root 自己所有の新規fixture親です。
 */
//------------------------------------------------------------------------------
void pausedWriterControl( const std::filesystem::path &root)
{
	using namespace drivercrate ;
	const auto resumedFolder = directory( root / L"paused-resume") ;	// 明示再開だけの所有先です。
	LocalDiagnosticLog resumed ;										// 通常の非待機appendと固定queueを使います。
	local_diagnostic_detail::Access::startPaused( resumed, resumedFolder.native()) ;
	DiagnosticRecord record ;	// 文字列本文を持たない一recordです。
	record.event = DiagnosticEvent::INSTALL_STARTED ;
	resumed.append( record) ;
	expect( resumed.status().pending == 1U && resumed.status().saved == 0U &&
		   resumed.status().dropped == 0U) ;
	local_diagnostic_detail::Access::resume( resumed) ;
	expect( local_diagnostic_detail::Access::drain( resumed)) ;
	expect( resumed.status().saved == 1U && resumed.status().pending == 0U &&
		   resumed.status().dropped == 0U &&
		   logs( resumedFolder).find( "event=install_started") != std::string::npos) ;
	local_diagnostic_detail::Access::resume( resumed) ;
	resumed.stop() ;
	expect( resumed.status().state == DiagnosticStorageState::STOPPED) ;
	const auto stoppedFolder =
		// 明示resumeしない停止だけの所有先です。
		directory( root / L"paused-stop") ;
	LocalDiagnosticLog stopped ;	// 停止要求も同じwakeでpauseを解除します。
	local_diagnostic_detail::Access::startPaused( stopped, stoppedFolder.native()) ;
	stopped.append( record) ;
	expect( stopped.status().pending == 1U && stopped.status().saved == 0U) ;
	const auto began = GetTickCount64() ;	// 既200ms終了の非阻害だけを観測します。
	stopped.stop() ;
	expect( GetTickCount64() - began < 1000U) ;
	expect( local_diagnostic_detail::Access::drain( stopped)) ;
	const auto final = stopped.status() ;	// 原timeout観測を消さず、実終端と保存を別に確認します。
	expect( (final.state == DiagnosticStorageState::STOPPED ||
			final.state == DiagnosticStorageState::STOP_TIMEOUT) &&
		   final.saved == 1U && final.pending == 0U && final.dropped == 0U &&
		   logs( stoppedFolder).find( "event=install_started") != std::string::npos) ;
	const auto fullFolder = directory( root / L"paused-full") ;	// 容量境界だけの自己所有先です。
	LocalDiagnosticLog full ;									// 既256枠を変更せず、workerだけ排出前に止めます。
	local_diagnostic_detail::Access::startPaused( full, fullFolder.native()) ;
	const auto enqueueBegan = GetTickCount64() ;	// 既非待機投入と同じ有限時間条件です。
	// 先頭256件を保持し、次の一件だけを容量超過として計上します。
	for( unsigned index{}; index < 257U; ++index) {
		record.operation = index + 1U ;
		full.append( record) ;
	}

	expect( GetTickCount64() - enqueueBegan < 2000U) ;
	const auto queued = full.status() ;	// 排出前なので保存と欠落を推測しません。
	expect( queued.pending == 256U && queued.saved == 0U && queued.dropped == 1U) ;
	local_diagnostic_detail::Access::resume( full) ;
	expect( local_diagnostic_detail::Access::drain( full)) ;
	full.stop() ;
	const auto				   saved = full.status() ;		// 原一欠落を保存成功へ換算しません。
	const auto				   bytes = logs( fullFolder) ;	// Fixtureの二slotだけの原byteです。
	constexpr std::string_view dropped =
		"event=queue_dropped provider=application operation=0 status=0 error=0 total=1" ;	// 元固定通知です。
	const auto position = bytes.find( dropped) ;											// 通知が一件だけ保存されたことを確認します。
	expect( saved.saved == 256U && saved.pending == 0U && saved.dropped == 1U &&
		   position != std::string::npos &&
		   bytes.find( dropped, position + 1U) == std::string::npos) ;
	bool allAcceptedPresent{true} ;	// 先頭256件のどれかを重複で補いません。
	// 全受理ordinalの保存を確認し、拒否した257番を保存済みへ混ぜません。
	for( unsigned ordinal = 1U; ordinal <= 256U; ++ordinal) {
		allAcceptedPresent =
			allAcceptedPresent &&
			bytes.find( "operation=" + std::to_string( ordinal) + " status=") != std::string::npos ;
	}

	expect( allAcceptedPresent && bytes.find( "operation=257 status=") == std::string::npos) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 自己所有の新規fixtureで非通信回帰だけを実行します。
 * @param[in] argc 引数数。
 * @param[in] argv 任意の絶対fixture親を一つだけ受けます。
 * @return 全期待成立0。それ以外1。
 */
//------------------------------------------------------------------------------
int wmain( const int argc, wchar_t **argv)
{
	try {
		std::wstring module( 32768U, L'\0') ;	// 同容量をheapで零初期化した実test EXE位置です。
		GetModuleFileNameW( nullptr, module.data(), static_cast<DWORD>( module.size())) ;
		const auto parent = argc > 1 ? std::filesystem::path( argv[1])
									 : std::filesystem::path( module.data())
										   .parent_path() ;	// CTestの既定も自己所有buildだけです。
		const auto root	  = directory( parent / (L"diagnostic-fixture-" +
												// 実行ごとの新規fixtureです。
												std::to_wstring( GetCurrentProcessId()))) ;
		privacy( root) ;
		indexReuseProjection( root) ;
		storageHealth( root) ;
		installProjection( root) ;
		preparationProjection( root) ;
		pausedWriterControl( root) ;
		failuresNonblocking( root) ;
		hardlink( root) ;
		junction( root) ;
		capacity( root) ;
		destination( root) ;
	} catch( ...) {
		// Fixture作成例外も失敗の分母へ残します。任意本文を出力しません。
		++failures ;
	}

	std::printf( "assertions=%u failures=%u\n", assertions, failures) ;
	return failures == 0U ? 0 : 1 ;
}
