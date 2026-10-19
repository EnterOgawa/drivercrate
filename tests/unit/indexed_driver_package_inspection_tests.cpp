//------------------------------------------------------------------------------
/**
 * @file indexed_driver_package_inspection_tests.cpp
 * @brief 索引hint結合と通常検査の拒否境界を検証する。
 * @version 01.00.01
 * @date 2026/10/05
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/05  索引hintと通常検査の非導入接続を追加。
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note 小さい架空fileだけを保護workspaceへ置き、実device・導入APIを呼ばない。
 * @see docs/adr/0262-index-hint-to-acquired-package-inspection.md
 */
//------------------------------------------------------------------------------

#include "indexed_driver_package_inspection_tests.h"
#include "test_framework.h"
#include "platform/indexed_driver_package_inspection.h"
#include "platform/official_download_workspace.h"

#include <Windows.h>

#include <array>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

namespace drivercrate::test {
namespace {

constexpr ScanSessionId SESSION		  = 6302U ;							// 架空試験だけの非0session。
constexpr std::uint64_t MAXIMUM_BYTES = 128ULL * 1024ULL * 1024ULL ;	// 共通入力上限。
constexpr wchar_t		FIXTURE_HASH[] =
	L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ;	// abcのSHA-256。

/** @brief 架空writerの唯一のHANDLEをscope終了時に閉じる。 */
class FixtureHandle final {
public:
	/** @brief 未所有のwriterを作成する。 */
	FixtureHandle() = default ;
	/** @brief 成功時だけ取得したwriterを必ず閉じる。 */
	~FixtureHandle()
	{
		// 未所有HANDLEへCloseHandleを呼ばない。
		if( value != INVALID_HANDLE_VALUE) {
			CloseHandle( value) ;
		}
	}
	/**
	 * @brief 架空writer HANDLEの解放責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	FixtureHandle( const FixtureHandle &) = delete ;
	/**
	 * @brief 架空writer HANDLEの解放責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	FixtureHandle &operator=( const FixtureHandle &) = delete ;
	/// createFileの出力を単独所有する。既定では未所有。
	HANDLE		   value{INVALID_HANDLE_VALUE} ;
} ;

/**
 * @brief 同一recordを参照する架空hintを作る。
 * @return 3 byteの期待identity。索引認証を意味しない。
 */
IndexedDriverArchiveHint hintFixture()
{
	return {std::wstring( 64, L'1'), std::wstring( 64, L'2'), FIXTURE_HASH, 3} ;
}

/**
 * @brief 非I/Oの照合専用入力を作る。
 * @return 実在を要求しない架空local入力。
 */
DriverArchiveInput inputFixture()
{
	return {SESSION, L"C:\\fixture.zip", 3, FIXTURE_HASH} ;
}

/**
 * @brief 正例とmetadata・pathの拒否を検証する。
 * @param[in,out] context Assertionの所有者。
 */
void testHintIdentity( TestContext &context)
{
	const auto hint	 = hintFixture() ;	// 常に有効な比較基準。
	const auto input = inputFixture() ;	// File I/Oをしない基準入力。
	DRIVERCRATE_EXPECT( context, matchesIndexedDriverArchiveHint( SESSION, hint, input,
																OfficialDriverArchiveFormat::ZIP)) ;
	DRIVERCRATE_EXPECT( context, matchesIndexedDriverArchiveHint(
									SESSION, hint, input, OfficialDriverArchiveFormat::CABINET)) ;
	DRIVERCRATE_EXPECT( context, !matchesIndexedDriverArchiveHint( 0, hint, input,
																 OfficialDriverArchiveFormat::ZIP)) ;
	DRIVERCRATE_EXPECT( context, !matchesIndexedDriverArchiveHint( SESSION + 1, hint, input,
																 OfficialDriverArchiveFormat::ZIP)) ;
	DRIVERCRATE_EXPECT(
		context, !matchesIndexedDriverArchiveHint( SESSION, hint, input,
												  static_cast<OfficialDriverArchiveFormat>( 99))) ;
	const std::array<std::wstring, 5> badHashes = {L"", std::wstring( 63, L'0'),
												   std::wstring( 65, L'0'), std::wstring( 64, L'A'),
												   // 非canonical値。
												   std::wstring( 64, L'g')} ;
	// 三種類のhashを別々に破損させ、どれかを無視する実装を防ぐ。
	for( const std::wstring &hash : badHashes) {
		auto mutated		= hint ;	// 一項目だけを変える独立fixture。
		mutated.indexSha256 = hash ;
		DRIVERCRATE_EXPECT( context, !matchesIndexedDriverArchiveHint(
										SESSION, mutated, input, OfficialDriverArchiveFormat::ZIP)) ;
		mutated				 = hint ;
		mutated.recordSha256 = hash ;
		DRIVERCRATE_EXPECT( context, !matchesIndexedDriverArchiveHint(
										SESSION, mutated, input, OfficialDriverArchiveFormat::ZIP)) ;
		mutated				  = hint ;
		mutated.archiveSha256 = hash ;
		DRIVERCRATE_EXPECT( context, !matchesIndexedDriverArchiveHint(
										SESSION, mutated, input, OfficialDriverArchiveFormat::ZIP)) ;
	}

	const std::array<std::uint64_t, 4> badSizes = {
		0, 2, MAXIMUM_BYTES + 1,
		std::numeric_limits<std::uint64_t>::max()} ;	// 有限範囲外または不一致。
	// Sizeを単独で変えた場合は入力metadataの一致を認めない。
	for( const std::uint64_t bytes : badSizes) {
		auto mutated		 = hint ;	// Size以外は基準を維持する。
		mutated.archiveBytes = bytes ;
		DRIVERCRATE_EXPECT( context, !matchesIndexedDriverArchiveHint(
										SESSION, mutated, input, OfficialDriverArchiveFormat::ZIP)) ;
	}

	auto maximumHint		 = hint ;	// ちょうど上限を含む境界。
	auto maximumInput		 = input ;	// 同じ上限の非I/O入力。
	maximumHint.archiveBytes = MAXIMUM_BYTES ;
	maximumInput.byteCount	 = MAXIMUM_BYTES ;
	DRIVERCRATE_EXPECT( context, matchesIndexedDriverArchiveHint( SESSION, maximumHint, maximumInput,
																OfficialDriverArchiveFormat::ZIP)) ;
	maximumInput.byteCount += 1 ;
	DRIVERCRATE_EXPECT( context, !matchesIndexedDriverArchiveHint( SESSION, maximumHint, maximumInput,
																 OfficialDriverArchiveFormat::ZIP)) ;
	const std::array<std::wstring, 7> badPaths = {L"", L"relative.zip", L"\\\\server\\a.zip",
												  L"C:/a.zip", L"C:\\a.zip:stream", L"1:\\a.zip",
												  // Network・ADS・NULを含む。
												  std::wstring( L"C:\\a\0.zip", 10)} ;
	// Pathの構文不正を実I/Oの前に排除する。
	for( const std::wstring &path : badPaths) {
		auto mutated		   = input ;	// 基準identityを保持してpathだけを変える。
		mutated.inspectionPath = path ;
		DRIVERCRATE_EXPECT( context, !matchesIndexedDriverArchiveHint(
										SESSION, hint, mutated, OfficialDriverArchiveFormat::ZIP)) ;
	}

	auto mutated   = input ;	// Input側のhash不一致も拒否する。
	mutated.sha256 = std::wstring( 64, L'0') ;
	DRIVERCRATE_EXPECT( context, !matchesIndexedDriverArchiveHint( SESSION, hint, mutated,
																 OfficialDriverArchiveFormat::ZIP)) ;
}

/**
 * @brief 不正hint・事前取消し・callback例外でI/Oを始めないことを検証する。
 * @param[in,out] context Assertionの所有者。
 */
void testEarlyTermination( TestContext &context)
{
	auto						   hint	 = hintFixture() ;	// 最初だけ不一致へ変えるhint。
	const auto					   input = inputFixture() ;	// 実在しないためI/O開始も観測できる。
	IndexedDriverPackageInspection result ;					// 各呼出しで前結果を破棄する。
	unsigned int				   calls{} ;				// 同期callbackの呼出し回数。
	// 借用するcallsは検査呼出し中だけ存在し、取消しを要求する。
	const auto					   cancel = [&calls] {
		++calls ;
		return true ;
	} ;
	hint.archiveBytes = 2 ;
	DRIVERCRATE_EXPECT( context, inspectIndexedDriverPackage( SESSION, hint, input,
															OfficialDriverArchiveFormat::ZIP,
															result, cancel) != 0) ;
	DRIVERCRATE_EXPECT( context, calls == 0) ;
	DRIVERCRATE_EXPECT( context, result.state == IndexedDriverInspectionState::INPUT_REJECTED &&
									!result.inputBound) ;
	hint = hintFixture() ;
	DRIVERCRATE_EXPECT( context, inspectIndexedDriverPackage( SESSION, hint, input,
															OfficialDriverArchiveFormat::ZIP,
															result, cancel) ==
									static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))) ;
	DRIVERCRATE_EXPECT( context, calls == 1 &&
									result.state == IndexedDriverInspectionState::CANCELLED &&
									!result.inputBound) ;
	DRIVERCRATE_EXPECT( context, result.inspection.infs.empty()) ;
	// Captureなしcallbackの例外をworker境界で診断へ変換する。
	const auto throws = []() -> bool { throw std::runtime_error( "fixture") ; } ;
	DRIVERCRATE_EXPECT( context, inspectIndexedDriverPackage(
									SESSION, hint, input, OfficialDriverArchiveFormat::ZIP, result,
									throws) == static_cast<NativeError>( E_UNEXPECTED)) ;
	DRIVERCRATE_EXPECT( context, result.state == IndexedDriverInspectionState::INSPECTION_FAILED &&
									!result.inputBound && result.inspection.infs.empty()) ;
}

/**
 * @brief 架空3 byteを実照合し、不正ZIPと偽装hash・sizeを別段階で拒否する。
 * @param[in,out] context Assertionの所有者。
 */
void testActualFixtureBytes( TestContext &context)
{
	OfficialDownloadWorkspace workspace ;	// Scope内だけの架空file所有者。
	const NativeError		  initializeError =
		// 新規保護領域。
		workspace.initialize( L"index-hint-fixture", SESSION) ;
	DRIVERCRATE_EXPECT( context, initializeError == 0) ;
	// Workspace失敗時に一般Tempへのfallbackを書かない。
	if( initializeError != 0) {
		return ;
	}

	{
		FixtureHandle	  writer ;	// Write後に確実に閉じて読み取りを許可する。
		const NativeError createError =
			// 追跡付き新規file。
			workspace.createFile( L"archive.zip", writer.value) ;
		DRIVERCRATE_EXPECT( context, createError == 0) ;
		// 未作成fileへのWriteを避ける。
		if( createError != 0) {
			return ;
		}

		DWORD written{} ;	// 実際の3 byteだけを確認する。
		DRIVERCRATE_EXPECT( context, WriteFile( writer.value, "abc", 3, &written, nullptr) != FALSE &&
										written == 3) ;
	}
	auto hint			 = hintFixture() ;	// 架空byteに一致する期待値。
	auto input			 = inputFixture() ;	// 保護fileだけへpathを差し替える。
	input.inspectionPath = workspace.path( L"archive.zip") ;
	IndexedDriverPackageInspection result ;	// 失敗結果も毎回初期化される。
	DRIVERCRATE_EXPECT( context,
					   inspectIndexedDriverPackage( SESSION, hint, input,
												   OfficialDriverArchiveFormat::ZIP, result) != 0) ;
	DRIVERCRATE_EXPECT( context,
					   result.inputBound &&
						   result.state == IndexedDriverInspectionState::INSPECTION_FAILED &&
						   result.inspection.infs.empty()) ;
	hint.archiveSha256 = std::wstring( 64, L'0') ;
	input.sha256	   = hint.archiveSha256 ;
	DRIVERCRATE_EXPECT( context, matchesIndexedDriverArchiveHint( SESSION, hint, input,
																OfficialDriverArchiveFormat::ZIP)) ;
	DRIVERCRATE_EXPECT( context,
					   inspectIndexedDriverPackage( SESSION, hint, input,
												   OfficialDriverArchiveFormat::ZIP, result) != 0) ;
	DRIVERCRATE_EXPECT( context, !result.inputBound &&
									result.state == IndexedDriverInspectionState::INPUT_REJECTED &&
									result.inspection.infs.empty()) ;
	hint				 = hintFixture() ;
	input				 = inputFixture() ;
	input.inspectionPath = workspace.path( L"archive.zip") ;
	hint.archiveBytes	 = 2 ;
	input.byteCount		 = 2 ;
	DRIVERCRATE_EXPECT( context,
					   inspectIndexedDriverPackage( SESSION, hint, input,
												   OfficialDriverArchiveFormat::ZIP, result) != 0) ;
	DRIVERCRATE_EXPECT( context, !result.inputBound &&
									result.state == IndexedDriverInspectionState::INPUT_REJECTED) ;
}

} // namespace

/** @see tests/unit/indexed_driver_package_inspection_tests.h 宣言側を正本とする。 */
void runIndexedDriverPackageInspectionTests( TestContext &context)
{
	testHintIdentity( context) ;
	testEarlyTermination( context) ;
	testActualFixtureBytes( context) ;
}

} // namespace drivercrate::test
