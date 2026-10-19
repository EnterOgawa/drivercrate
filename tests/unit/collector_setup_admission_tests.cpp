//------------------------------------------------------------------------------
/**
 * @file collector_setup_admission_tests.cpp
 * @brief 実validator製の人工旧v4と非作成native leaseの拒否境界を確認します。
 * @version 01.00.01
 * @date 2026/10/17
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/17 全旧fixture・実lease・未確認modeの有限試験を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/17 通常CTest・一意fixture・長pathと共通writer防御を検査。
 * </pre>
 *
 * @note 既存encoderを同じTUから使い、HTTPもcollector実行も行いません。
 *       --inspect-nativeは指定済み既存rootの非変更検査だけです。
 */
//------------------------------------------------------------------------------

// 製品の既存encoderと完全validatorで人工fixtureを作り、別の保存形式を発明しない。
#include "platform/local_driver_collector.cpp"
#include "platform/collector_setup_admission.h"

#include <Windows.h>
#include <objbase.h>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>

namespace drivercrate {
namespace {

// 実行したexpectを数え、固定群数をassertion実績へ置き換えない。
std::size_t admissionAssertions{} ;

/** @brief 条件不成立を固定理由の試験失敗へ変換します。
 * @param[in] condition 成功条件。
 * @note 内部fixtureだけが使用します。
 */
void		expectAdmission( const bool condition)
{
	++admissionAssertions ;
	// 誤ったfixtureを正常分母から取り除かない。
	if( !condition) {
		std::printf( "ADMISSION_FAILED_CHECK index=%zu\n", admissionAssertions) ;
		throw std::runtime_error( "ADMISSION_TEST_EXPECTATION") ;
	}
}

/** @brief 人工fixtureのWin32 I/Oだけにextended pathを渡します。
 * @param[in] path このtestが新規作成する絶対path。
 * @return 長pathを短縮せずAPIへ渡す表現。
 */
std::wstring fixtureApiPath( const std::filesystem::path &path)
{
	return L"\\\\?\\" + std::filesystem::path( path).make_preferred().native() ;
}

/** @brief 元encoderと保護storeで完全な旧v4の人工失敗履歴を作ります。
 * @param[in] root 呼出し元が一意に確保した新規人工fixture root。
 */
void createAdmissionFixture( const std::filesystem::path &root)
{
	LocalCollectorTarget target ;	// 組込み公式targetだけをbuilderで再構築する。
	expectAdmission( makeLocalCollectorTarget( L"INTEL_ETHERNET_WINDOWS11", {}, L"Windows 11 64-bit",
											 {}, target)) ;
	LocalCollectorRun run ;	// 実収集を起動せず元encoderへ渡す人工旧v4。
	run.manifestSha256 = std::wstring( 64U, L'a') ;
	run.contractSha256 = std::wstring( 64U, L'b') ;
	run.day			   = L"20261003" ;
	run.complete	   = true ;
	LocalCollectorTargetResult result ;	// 初回失敗のままで成功本文を合成しない。
	result.keySha256	   = target.keySha256 ;
	result.source		   = target.source ;
	result.publicModel	   = target.publicModel ;
	result.operatingSystem = target.operatingSystem ;
	result.category		   = target.category ;
	result.state		   = LocalCollectorTargetState::FAILED ;
	result.error		   = static_cast<std::uint32_t>( E_FAIL) ;
	result.lastAttemptAt   = 1790985600ULL ;
	result.nextAttemptAt   = result.lastAttemptAt + 86400U ;
	run.targets.push_back( result) ;
	LocalCollectorStateStore store ;	// 自作fixtureだけを新規作成する保護writer。
	expectAdmission( !std::filesystem::exists( root) && store.initialize( root, true) == 0U) ;
	const std::string body = encodeRun( run) ;	// 製品と同じ旧v4 canonical本文。
	std::wstring	  hash ;					// 製品と同じ確定pointer結合。
	expectAdmission(
		computeBytesSha256( body, hash) == 0 &&
		saveEnvelope( store, runFilePath( run.day, run.manifestSha256, run.contractSha256), body)) ;
	JsonObject pointer ;	// 製品と同じ最終pointer。
	putString( pointer, L"schema", L"dc-collector-current-v4") ;
	putString( pointer, L"day", run.day) ;
	putString( pointer, L"manifestSha256", run.manifestSha256) ;
	putString( pointer, L"contractSha256", run.contractSha256) ;
	putString( pointer, L"runSha256", hash) ;
	expectAdmission( saveEnvelope( store,
								 std::filesystem::path( L"current") /
									 (run.manifestSha256 + L"-" + run.contractSha256 + L".json"),
								 winrt::to_string( pointer.Stringify()))) ;
}

/** @brief 保持leaseを公開値だけのJSONへ射影します。
 * @param[in] admission 完全検証済みの借用lease。
 * @return hashと件数だけのJSON。
 */
std::string scopeJson( const CollectorSetupAdmission &admission)
{
	JsonObject result ;	// raw URL、端末path、IDを出力しない。
	putString( result, L"nativeDigest", admission.snapshot.digest) ;
	putNumber( result, L"nativeFileCount", admission.snapshot.fileCount) ;
	// method/actualURLとhostの比較hashだけを後続Python fixtureへ渡す。
	for( const auto &entry : {std::pair{L"requestHashes", admission.requestHashes},
							 std::pair{L"hostHashes", admission.hostHashes}}) {
		JsonArray values ;	// 一種類の完全scope。
		// 完全検査した集合を固定順で保持する。
		for( const auto &value : entry.second) {
			values.Append( JsonValue::CreateStringValue( value)) ;
		}

		result.Insert( entry.first, values) ;
	}

	return winrt::to_string( result.Stringify()) ;
}

/** @brief 作成と非作成writerが同じ予約祖先の防御を使うことを確認します。
 * @param[in] root この呼出しだけに割り当てた新規人工root。
 */
void legacyWriterChecks( const std::filesystem::path &root)
{
	createAdmissionFixture( root) ;
	{
		LocalCollectorStateStore existing ;	// 正常旧v4への非作成writer。
		expectAdmission( existing.initializeExistingWriter( root) == ERROR_SUCCESS) ;
	}
	const std::wstring lowerHash( 64U, L'a') ;	// 実在する予約子の小文字名。
	const std::wstring upperHash( 64U, L'A') ;	// Windowsで同じ実体を指す別名。
	createAdmissionFixture( root / L"segments" / lowerHash) ;
	{
		LocalCollectorStateStore parent ;	// 人工親にだけ存在markerを保存する。
		expectAdmission( parent.initializeExistingWriter( root) != ERROR_SUCCESS) ;
	}
	// 予約階層追加後の親は通常layoutで開けないため、既存ACLを継承した固定markerを作ります。
	const auto markerPath = root / L"current/collector-campaign-mode-v1.json" ;	// 人工親専用marker。
	const HANDLE marker =
		CreateFileW( fixtureApiPath( markerPath).c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_NEW,
					FILE_ATTRIBUTE_NORMAL, nullptr) ;	// 新規fileだけを許可する。
	expectAdmission( marker != INVALID_HANDLE_VALUE) ;
	DWORD	   written{} ;	// Marker本文の全byte書込みを要求する。
	const BOOL saved =
		// 本文で能力を自己申告しない。
		WriteFile( marker, "{}", 2U, &written, nullptr) ;
	const BOOL closed = CloseHandle( marker) ;	// 後続検査より先に書込みhandleを解放する。
	expectAdmission( saved && written == 2U && closed) ;
	// どちらの入口も、完全hashの大文字別名と固定historyを同じ事前段階で拒否する。
	for( const auto &candidate : {root / L"segments" / lowerHash, root / L"SeGmEnTs" / upperHash,
								 root / L"segments" / lowerHash / L"history",
								 root / L"SeGmEnTs" / upperHash / L"HiStOrY"}) {
		LocalCollectorStateStore creating ;	// 親能力を持たない通常writer。
		LocalCollectorStateStore existing ;	// 作成を許さない通常writer。
		expectAdmission( creating.initialize( candidate, true) == ERROR_INVALID_DATA) ;
		expectAdmission( existing.initializeExistingWriter( candidate) == ERROR_INVALID_DATA) ;
	}

	expectAdmission(
		GetFileAttributesW( fixtureApiPath( root / L"segments" / lowerHash / L"history").c_str()) ==
		INVALID_FILE_ATTRIBUTES) ;
}

/** @brief 固定fixtureの正常・競合・欠損・未来時計・未知modeを直列確認します。
 * @param[in] root 新規人工fixtureの絶対path。
 * @return 全検査成功時0。
 */
int admissionChecks( const std::filesystem::path &root)
{
	createAdmissionFixture( root) ;
	CollectorSetupAdmission admission ;	// 実native writerの所有lease。
	std::wstring			reason ;	// 拒否時の固定理由。
	expectAdmission( acquireCollectorSetupAdmission( root, 1792195200000ULL, admission, reason) ==
						0U &&
					admission.snapshot.fileCount == 2U && admission.requestHashes.size() == 1U &&
					admission.hostHashes.size() == 1U) ;
	std::printf( "SCOPE %s\n", scopeJson( admission).c_str()) ;
	CollectorSetupAdmission second ;	// 生存leaseとの競合を試す別owner。
	expectAdmission( acquireCollectorSetupAdmission( root, 1792195200000ULL, second, reason) ==
						ERROR_SHARING_VIOLATION &&
					!second.store) ;
	admission = {} ;
	expectAdmission( acquireCollectorSetupAdmission( root, 1000U, second, reason) ==
						ERROR_INVALID_DATA &&
					!second.store) ;
	expectAdmission(
		acquireCollectorSetupAdmission( root / L"missing", 1792195200000ULL, second, reason) != 0U &&
		!std::filesystem::exists( root / L"missing")) ;
	const auto sharedRoot = root.parent_path() / (root.filename().native() +
												  L"-shared") ;	// 元正常fixtureを変更しない別scope。
	createAdmissionFixture( sharedRoot) ;
	{
		LocalCollectorStateStore store ;	// 人工rootにだけ未対応予約を追加する。
		expectAdmission( store.initializeExistingWriter( sharedRoot) == 0U &&
						store.write( L"current/campaign-budget-v1.json", "{}") == 0U) ;
	}
	expectAdmission( acquireCollectorSetupAdmission( sharedRoot, 1792195200000ULL, second, reason) ==
						ERROR_INVALID_DATA &&
					reason == L"NATIVE_SHARED_SCOPE_UNSUPPORTED" && !second.store) ;
	const auto waitRoot =
		root.parent_path() /
		(root.filename().native() + L"-wait") ;	// targetが失われたsource待機専用の人工scope。
	createAdmissionFixture( waitRoot) ;
	{
		LocalCollectorStateStore store ;	// Intel runだけの人工rootへASUS待機を保存する。
		// 元validatorが受理する未知期限のsource待機。
		const SourceCooldown	 cooldown{1790985600ULL, 1791072000ULL, true, 503U} ;
		expectAdmission( store.initializeExistingWriter( waitRoot) == 0U &&
						saveCooldown( store, L"ASUS_CATALOG", cooldown)) ;
	}
	expectAdmission( acquireCollectorSetupAdmission( waitRoot, 1792195200000ULL, second, reason) ==
						ERROR_INVALID_DATA &&
					reason == L"NATIVE_REQUEST_SCOPE_UNVERIFIED" && !second.store) ;
	legacyWriterChecks( root.parent_path() / (root.filename().native() + L"-preflight")) ;
	std::printf( "ADMISSION_UNIT groups=8 checks=%zu failures=0 http=0\n", admissionAssertions) ;
	return 0 ;
}

} // namespace
} // namespace drivercrate

/** @brief 有限fixture試験または指定済み原storeの非変更検査を実行します。
 * @param[in] count 引数なし、または固定操作とrootを含む引数数。
 * @param[in] arguments test専用の操作と絶対path。
 * @return 全成功0、拒否2。
 */
int wmain( const int count, wchar_t *arguments[])
{
	try {
		winrt::init_apartment() ;
		// 通常CTestでは私有pathを要求せず、一意な新規fixtureと長pathを実際に使用する。
		if( count == 1) {
			GUID id{} ;	// 別実行のfixtureを再使用しない識別子。
			drivercrate::expectAdmission( SUCCEEDED( CoCreateGuid( &id))) ;
			wchar_t name[40]{} ;	// GUIDの有限文字列表現。
			drivercrate::expectAdmission( StringFromGUID2( id, name, 40) != 0) ;
			const auto base =
				std::filesystem::temp_directory_path() /
				(std::wstring( L"drivercrate-admission-") + name) ;	// 通常testだけの新規親。
			drivercrate::expectAdmission( CreateDirectoryW( base.c_str(), nullptr) != FALSE) ;
			drivercrate::admissionChecks( base / L"normal") ;
			auto longParent = base ;	// 同じfixture内で長い入力を構成する。
			// 各componentはWindows上限内とし、全pathがMAX_PATHを超えるまでだけ追加する。
			while( longParent.native().size() < 300U) {
				longParent /= std::wstring( 80U, L'x') ;
				drivercrate::expectAdmission(
					CreateDirectoryW( drivercrate::fixtureApiPath( longParent).c_str(), nullptr) !=
					FALSE) ;
			}

			drivercrate::admissionChecks( longParent / L"long") ;
			std::printf( "ADMISSION_PORTABLE default=1 long_path=1 retained=1 http=0\n") ;
			return 0 ;
		}

		drivercrate::expectAdmission( count == 3) ;
		const std::wstring_view		action = arguments[1] ;	// 製品CLIには追加しないtest専用操作。
		const std::filesystem::path root   = arguments[2] ;	// 親が固定した有限root。
		// 指定済みの実storeを作成・修復せず既存validatorだけで観測する。
		if( action == L"--inspect-native") {
			drivercrate::CollectorSetupAdmission admission ;	// 非変更の検査期間だけ保持するwriter。
			std::wstring						 reason ;		// raw stateを含まない拒否理由。
			const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
									std::chrono::system_clock::now().time_since_epoch())
									.count() ;	// OS実時計。
			const DWORD code = drivercrate::acquireCollectorSetupAdmission(
				root, static_cast<std::uint64_t>( millis), admission, reason) ;	// 全旧validator。
			std::printf(
				"NATIVE_INSPECTION win32=%lu files=%u requests=%zu hosts=%zu reason=%s mutation=0 http=0\n",
				static_cast<unsigned long>( code), admission.snapshot.fileCount,
				admission.requestHashes.size(), admission.hostHashes.size(),
				winrt::to_string( reason).c_str()) ;
			return code == 0U ? 0 : 2 ;
		}

		drivercrate::expectAdmission( action == L"--fixture" && root.is_absolute()) ;
		return drivercrate::admissionChecks( root) ;
	} catch( const std::exception &error) {
		std::printf( "ADMISSION_UNIT_REJECTED code=%s\n", error.what()) ;
		return 2 ;
	} catch( ...) {
		std::printf( "ADMISSION_UNIT_REJECTED code=EXCEPTION\n") ;
		return 2 ;
	}
}
