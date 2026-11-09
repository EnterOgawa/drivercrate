//------------------------------------------------------------------------------
/**
 * @file resource_content_tests.cpp
 * @brief resource原範囲と実公式packageの非実行接続を有限検証する。
 * @version 01.00.01
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/03  独立小PEと実原outerの通常内容接続を検証。
 * Ver.01.00.01 Shunji Ogawa  2026/11/09  取消/CRC code期待のNativeError型だけを明示。
 * </pre>
 * @note network・製品UI・driver/FW実行・Windows stagingを行わない。
 */
//------------------------------------------------------------------------------
#include "platform/official_resource_content.h"
#include "platform/official_mapped_file.h"
#include "platform/official_file_verifier.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_package.h"
#include "platform/indexed_driver_package_inspection.h"
#include "platform/local_collector_projected_json.h"
#include "platform/signed_index_acquisition_descriptor_internal.h"
#include "test_framework.h"
#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <string>

namespace {
using namespace drivercrate ;
using Writer = collector_projected_json::Writer ;
/** @brief 公開packageの原期待値だけを作る。
 * @return 642の受入済みsize/hash。inner tuple/offsetは既定値の未確定。
 */
OfficialResourceContentPlan request()
{
	OfficialResourceContentPlan plan ;	// 研究済み原byteの非authority期待値。
	plan.rootBytes	  = 6426032U ;
	plan.rootSha256	  = L"e5efa7ab37818095abb8091b756501250587853c2bf9f79a0b0a3b6d220f10a8" ;
	plan.archive	  = {{{true, 0U, L"ZIP"}, {false, 103U, {}}, 1033U},
						 0U,
						 2130074U,
						 L"fb090cc71a5a56777cc289e53c44bf896dde563b9e861176cbfe0c29f2028458"} ;
	plan.memberPath	  = L"ASMx4242_FWUpdateV40014_u424251223200012AcmAPDIO2V1.exe" ;
	plan.memberBytes  = 6323864U ;
	plan.memberSha256 = L"3980ab08eb25da26d2d461567e4a7166d85e78f3d11bda0deca730367d644548" ;
	plan.files		  = {
		   {OfficialResourceRole::INF,
				L"asmfilter64.inf",
				{{}, 0U, 2604U, L"f56ac6c80f04e86fb2f7b3abd39f8ca533284e8968fb78f9f6cd31a6349a047d"}},
		   {OfficialResourceRole::CATALOG,
				L"asmfilter64.cat",
				{{}, 0U, 11840U, L"a50e735e7299835669d58db7910683b29a0b5678670b32087fd059e433eb7433"}},
		   {OfficialResourceRole::DRIVER_FILE,
				L"asmfilter64.sys",
				{{}, 0U, 43560U, L"d13aac4d9b4b0866869a130b23c67a1a05316a5da3e80c31acba2d16efa28728"}}} ;
	plan.selectedInf = L"asmfilter64.inf" ;
	return plan ;
}
/** @brief 原resource atomを既存有界JSON writerへ出す。
 * @param[in,out] out 出力sink。
 * @param[in] value 原atom。
 */
void emitAtom( Writer &out, const OfficialResourceIdentifier &value)
{
	out.append( value.named ? "{\"kind\":\"STRING\",\"value\":" : "{\"kind\":\"ID\",\"value\":") ;
	// UTF-16原名と数値IDを別型で出す。
	if( value.named) {
		out.wideText( value.text) ;
	} else {
		out.number( value.id) ;
	}

	out.append( "}") ;
}
/** @brief native確定tupleと原範囲を出す。
 * @param[in,out] out 有界sink。
 * @param[in] value 全検証済み原slice。
 */
void emitSlice( Writer &out, const OfficialResourceSlice &value)
{
	out.append( "\"resource\":{\"type\":") ;
	emitAtom( out, value.resource.type) ;
	out.append( ",\"name\":") ;
	emitAtom( out, value.resource.name) ;
	out.append( ",\"language\":{\"kind\":\"ID\",\"value\":") ;
	out.number( value.resource.language) ;
	out.append( "}},\"offset\":") ;
	out.number( value.offset) ;
	out.append( ",\"length\":") ;
	out.number( value.length) ;
	out.append( ",\"sha256\":") ;
	out.wideText( value.sha256) ;
}
/** @brief 全native証拠を公開wireと同じ閉じたcontentへ出す。
 * @param[in] plan native解決成功値。
 * @return 有界な原選択JSON。署名/正式recordではない。
 */
std::string emitPlan( const OfficialResourceContentPlan &plan)
{
	Writer out( 64U * 1024U) ;	// 単一小型recipeの有界sink。
	out.append( "{\"kind\":\"PE_RESOURCE_RANGES_V1\",\"root\":{\"bytes\":") ;
	out.number( plan.rootBytes) ;
	out.append( ",\"sha256\":") ;
	out.wideText( plan.rootSha256) ;
	out.append( "},\"archive\":{") ;
	emitSlice( out, plan.archive) ;
	out.append( "},\"member\":{\"path\":") ;
	out.wideText( plan.memberPath) ;
	out.append( ",\"bytes\":") ;
	out.number( plan.memberBytes) ;
	out.append( ",\"sha256\":") ;
	out.wideText( plan.memberSha256) ;
	out.append( "},\"files\":[") ;
	// 元role順を保ち、rawtupleをlistingへ変換しない。
	for( std::size_t index = 0U; index < plan.files.size(); ++index) {
		const auto &file = plan.files[index] ;	// native確定した原role。
		// 余剰commaを作らない。
		if( index != 0U) {
			out.append( ",") ;
		}

		out.append( "{\"role\":") ;
		out.text( file.role == OfficialResourceRole::INF		  ? "INF"
				 : file.role == OfficialResourceRole::CATALOG ? "CATALOG"
															  : "DRIVER_FILE") ;
		out.append( ",\"basename\":") ;
		out.wideText( file.basename) ;
		out.append( ",") ;
		emitSlice( out, file.slice) ;
		out.append( "}") ;
	}

	out.append( "],\"selectedInf\":") ;
	out.wideText( plan.selectedInf) ;
	out.append( "}") ;
	return out.take() ;
}
/** @brief 独立645の六small PEと静的role境界を確認する。
 * @param[in,out] test 有限assertion集計。
 * @param[in] directory 受入済みvector directory。
 */
void vectors( test::TestContext &test, std::wstring directory)
{
	std::ranges::replace( directory, L'/', L'\\') ;
	constexpr std::array names{
		L"01-valid-named-tuple",	 L"02-resource-raw-tail",
		L"03-rva-extent-wrap",		 L"04-leaf-directory-cycle",
		L"05-duplicate-exact-tuple", L"06-explicit-distinct-languages"} ;	// 独立原fixture。
	// 合法二件と不正四件を同じnative readerへ渡す。
	for( std::size_t index = 0U; index < names.size(); ++index) {
		OfficialMappedFile file ;	// 各原small PEの固定owner。
		const auto		   opened =
			// 原byteだけを読む。
			file.open( directory + L"\\" + names[index] + L".pe.bin", 4096U) ;
		DRIVERCRATE_EXPECT( test, opened == 0) ;
		std::vector<OfficialResourceSlice> leaves ;	// 全成功時だけの原tuple。
		const auto error = opened == 0 ? collectOfficialPeResourceRanges( file.bytes(), leaves)
									   : opened ;	// 実parser結果。
		DRIVERCRATE_EXPECT( test, (error == 0) == (index == 0U || index == 5U)) ;
		// 明示別言語を重複と混同しない。
		if( index == 0U && error == 0) {
			DRIVERCRATE_EXPECT( test, leaves.size() == 1U && leaves[0].offset == 1024U &&
										 leaves[0].length == 43U) ;
			DRIVERCRATE_EXPECT( test, leaves[0].resource.type.named &&
										 leaves[0].resource.type.text == L"ZIP" &&
										 leaves[0].resource.name.id == 103U &&
										 leaves[0].resource.language == 1033U) ;
		}
		// 明示別言語の合法例を独立に確認する。
		else if( index == 5U && error == 0) {
			DRIVERCRATE_EXPECT( test, leaves.size() == 2U && leaves[0].resource.language !=
																leaves[1].resource.language) ;
		}
		// 明示real modeだけで原公式byteを通常検査する。
		else if( error != 0) {
			DRIVERCRATE_EXPECT( test, leaves.empty()) ;
		}
	}

	auto plan = request() ;	// 正規role contractの静的期待値。
	DRIVERCRATE_EXPECT( test, validOfficialResourceContentPlan( plan)) ;
	plan.files[2].basename = L"ASMFILTER64.INF" ;
	DRIVERCRATE_EXPECT( test, !validOfficialResourceContentPlan( plan)) ;
	plan					   = request() ;
	plan.files[0].slice.sha256 = L"bad" ;
	DRIVERCRATE_EXPECT( test, !validOfficialResourceContentPlan( plan)) ;
	plan					   = request() ;
	plan.files[0].slice.offset = UINT64_MAX ;
	DRIVERCRATE_EXPECT( test, !validOfficialResourceContentPlan( plan)) ;
	plan					   = request() ;
	plan.files[0].slice.length = 0U ;
	DRIVERCRATE_EXPECT( test, !validOfficialResourceContentPlan( plan)) ;
	plan			   = request() ;
	plan.files[0].role = static_cast<OfficialResourceRole>( 99) ;
	DRIVERCRATE_EXPECT( test, !validOfficialResourceContentPlan( plan)) ;
	plan				   = request() ;
	plan.files[0].basename = L"..\\unsafe.inf" ;
	DRIVERCRATE_EXPECT( test, !validOfficialResourceContentPlan( plan)) ;
	OfficialResourceContentReader cancelled ;	// I/O前取消しの出力owner。
	DRIVERCRATE_EXPECT( test, cancelled.initialize( L"C:\\nonexistent-resource-input.bin", request(),
												  [] { return true ; }) ==
								 static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))) ;
	DRIVERCRATE_EXPECT( test, cancelled.entries().empty()) ;
}
/** @brief 原642をcollector解決から通常indexed content/identityへ通す。
 * @param[in,out] test 有限assertion集計。
 * @param[in] path 原outer絶対path。
 */
void real( test::TestContext &test, const std::wstring_view path)
{
	OfficialResourceContentPlan plan ;	// nativeで初めて確定するinner tuple/offset。
	const auto					resolved =
		// 非実行原PE解析。
		resolveOfficialResourceContentPlan( path, request(), plan) ;
	std::printf( "{\"resolveError\":%ld}\n", static_cast<long>( resolved)) ;
	DRIVERCRATE_EXPECT( test, resolved == 0) ;
	// 初回失敗を別toolの成功へ置換しない。
	if( resolved != 0) {
		return ;
	}

	const auto json = emitPlan( plan) ;	// 解決済みcontentの原値。
	std::printf( "{\"researchOnly\":true,\"content\":%s}\n", json.c_str()) ;
	auto shared = std::make_shared<const OfficialResourceContentPlan>(
		plan) ;	// 元hint/inputで共有する非authority選択。
	IndexedDriverArchiveHint hint{
		std::wstring( 64U, L'a'),   std::wstring( 64U, L'b'),
		plan.rootSha256,		   plan.rootBytes,
		{{L"", plan.selectedInf}}, shared} ;	// 元公開IDとは独立のread-only内容入力。
	DriverArchiveInput			   input{648U, std::wstring( path), plan.rootBytes, plan.rootSha256,
							 shared} ;			// 原outer identityを維持。
	IndexedDriverPackageInspection inspection ;	// 通常署名閉包を所有する結果。
	const auto					   contentError = inspectIndexedDriverPackage(
		648U, hint, input, OfficialDriverArchiveFormat::PE_RESOURCE_CONTAINER,
		inspection) ;	// 実通常内容入口。
	std::printf( "{\"contentError\":%ld,\"state\":%u,\"infs\":%zu,\"retainedBytes\":%llu}\n",
				static_cast<long>( contentError), static_cast<unsigned>( inspection.state),
				inspection.inspection.infs.size(),
				static_cast<unsigned long long>( inspection.inspection.retainedBytes)) ;
	DRIVERCRATE_EXPECT( test, contentError == 0 && inspection.inputBound) ;
	DRIVERCRATE_EXPECT( test, inspection.inspection.infs.size() == 1U) ;
	// 個別拒否を全体APIの成功だけで隠さない。
	if( !inspection.inspection.infs.empty()) {
		const auto &inf = inspection.inspection.infs.front() ;	// 元同一INFの結果。
		std::printf( "{\"infState\":%u,\"infError\":%ld}\n", static_cast<unsigned>( inf.state),
					static_cast<long>( inf.error)) ;
		DRIVERCRATE_EXPECT( test, inf.state == CommonInfInspectionState::VERIFIED && inf.error == 0) ;
		// 検査済み元HINFからだけ公開identityを読む。
		if( inf.state == CommonInfInspectionState::VERIFIED && inf.workspace &&
		   inf.closure.packages.size() == 1U) {
			const auto					&package = inf.closure.packages.front() ;	// 同じ原閉包。
			OfficialInfPublishedIdentity identity ;									// 元INFの非authority identity。
			auto		 error = readOfficialInfPublishedIdentity( *inf.workspace, package,
																  identity) ;	// 元identityの実結果。
			std::wstring publisher ;											// 実Windows publisher。
			// 公開identity後も全原CAT/memberを検査する。
			if( error == 0) {
				error = verifyWindowsInfPackageIntegrity( *inf.workspace, package) ;
			}

			// 元CATからpublisherを確認する。
			if( error == 0) {
				error = readWindowsInfPackagePublisher( *inf.workspace, package, publisher) ;
			}

			std::size_t ids{} ;	// 原公開Modelsの件数。
			// 端末inventoryを照会せず公開IDだけ数える。
			for( const auto &model : identity.models) {
				ids += model.hardwareIds.size() + model.compatibleIds.size() ;
			}

			std::printf(
				"{\"identityError\":%ld,\"publicIds\":%zu,\"models\":%zu,\"unresolvedIncludes\":%zu,\"applicability\":0,\"install\":0}\n",
				static_cast<long>( error), ids, identity.models.size(),
				static_cast<std::size_t>( package.unresolvedIncludeNeeds)) ;
			DRIVERCRATE_EXPECT( test, error == 0 && ids == 7U && !publisher.empty()) ;
			DRIVERCRATE_EXPECT( test, package.driverVersion == L"1.0.5.0000") ;
		}
	}

	auto changed		  = plan ;	// 原parent hash改変の負例。
	changed.rootSha256[0] = changed.rootSha256[0] == L'0' ? L'1' : L'0' ;
	OfficialResourceContentReader reader ;	// 元byte不一致を公開しないowner。
	DRIVERCRATE_EXPECT( test, reader.initialize( path, changed) ==
								 static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CRC))) ;
	DRIVERCRATE_EXPECT( test, reader.entries().empty()) ;
	changed							 = plan ;
	changed.files[0].slice.sha256[0] = L'0' ;
	DRIVERCRATE_EXPECT( test, reader.initialize( path, changed) ==
								 static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CRC))) ;
	bool	 cancel{} ;		// 保存段階だけで取消す外部状態。
	unsigned callbacks{} ;	// 取消し照会の現在件数。
	DRIVERCRATE_EXPECT(
		test, reader.initialize( path, plan, [&] { return cancel && ++callbacks > 1U ; }) == 0) ;
	OfficialDownloadWorkspace workspace ;	// 取消し後の所有fileだけを検査する。
	DRIVERCRATE_EXPECT( test, workspace.initialize( L"resource-cancel", 648U) == 0) ;
	const std::array<std::wstring_view, 1U> selected{plan.selectedInf} ;	// 元一件の原名。
	std::vector<OfficialZipEntry>			files ;							// 全成功時だけの出力。
	cancel = true ;
	DRIVERCRATE_EXPECT( test, reader.extract( selected, workspace, files) ==
								 static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))) ;
	DRIVERCRATE_EXPECT( test, files.empty() &&
								 GetFileAttributesW( workspace.path( plan.selectedInf).c_str()) ==
									 INVALID_FILE_ATTRIBUTES) ;
	cancel = false ;
	OfficialDownloadWorkspace collision ;	// 事前所有fileを誤削除しないことを確認。
	DRIVERCRATE_EXPECT( test, collision.initialize( L"resource-collision", 648U) == 0) ;
	HANDLE existing = INVALID_HANDLE_VALUE ;	// 呼出し前から存在するCATの所有handle。
	DRIVERCRATE_EXPECT( test, collision.createFile( plan.files[1].basename, existing) == 0) ;
	// fileを閉じてからCREATE_NEW衝突を発生させる。
	if( existing != INVALID_HANDLE_VALUE) {
		CloseHandle( existing) ;
	}

	const std::array<std::wstring_view, 2U> selectedCollision{
		plan.files[0].basename, plan.files[1].basename} ;	// 一件成功後に既存CATへ衝突。
	DRIVERCRATE_EXPECT( test,
					   reader.extract( selectedCollision, collision, files) != 0 && files.empty()) ;
	DRIVERCRATE_EXPECT( test, GetFileAttributesW( collision.path( plan.files[0].basename).c_str()) ==
								 INVALID_FILE_ATTRIBUTES) ;
	DRIVERCRATE_EXPECT( test, GetFileAttributesW( collision.path( plan.files[1].basename).c_str()) !=
								 INVALID_FILE_ATTRIBUTES) ;
	auto missing = plan ;	// 宣言本体欠損の内容負例。
	missing.files.pop_back() ;
	auto missingShared = std::make_shared<const OfficialResourceContentPlan>(
		missing) ;							// 元親は同じ、必要SYSだけ欠損。
	auto missingHint			 = hint ;	// 同じ元sessionの明示欠損計画。
	missingHint.resourceContent	 = missingShared ;
	auto missingInput			 = input ;	// 失効/任意pathへ変換しない原入力。
	missingInput.resourceContent = missingShared ;
	IndexedDriverPackageInspection missingInspection ;	// 個別拒否を保持する結果。
	const auto					   missingError = inspectIndexedDriverPackage(
		648U, missingHint, missingInput, OfficialDriverArchiveFormat::PE_RESOURCE_CONTAINER,
		missingInspection) ;	// 既存closureの実欠損診断。
	DRIVERCRATE_EXPECT( test, missingError == 0 && missingInspection.inspection.infs.size() == 1U &&
								 missingInspection.inspection.infs[0].state ==
									 CommonInfInspectionState::CLOSURE_REJECTED) ;
	DRIVERCRATE_EXPECT(
		test, !matchesIndexedDriverArchiveHint( 649U, hint, input,
											   OfficialDriverArchiveFormat::PE_RESOURCE_CONTAINER)) ;
	auto noPlan = hint ;	// 元planを失ったhintを別形式へ補完しない。
	noPlan.resourceContent.reset() ;
	DRIVERCRATE_EXPECT(
		test, !matchesIndexedDriverArchiveHint( 648U, noPlan, input,
											   OfficialDriverArchiveFormat::PE_RESOURCE_CONTAINER)) ;
	OfficialMappedFile original ;	// 改変負例の元read-only owner。
	DRIVERCRATE_EXPECT( test, original.open( path, 64U * 1024U * 1024U) == 0) ;
	std::vector<std::byte> corrupt( original.bytes().begin(),
								   // このsmall原物だけの有界人工copy。
								   original.bytes().end()) ;
	corrupt[static_cast<std::size_t>( plan.archive.offset) + 8U] ^= std::byte{1U} ;
	auto crcPlan = plan ;	// 親/子hashは変更済byteへ正確に結び、CRCだけを壊す。
	DRIVERCRATE_EXPECT( test, computeDriverContainerSha256(
								 {reinterpret_cast<const char *>( corrupt.data()), corrupt.size()},
								 crcPlan.rootSha256) == 0) ;
	DRIVERCRATE_EXPECT( test,
					   computeDriverContainerSha256(
						   {reinterpret_cast<const char *>( corrupt.data() + plan.archive.offset),
							static_cast<std::size_t>( plan.archive.length)},
						   crcPlan.archive.sha256) == 0) ;
	OfficialDownloadWorkspace scratch ;	// 改変fixtureだけの所有領域。
	DRIVERCRATE_EXPECT( test, scratch.initialize( L"resource-crc-fixture", 648U) == 0) ;
	HANDLE modified = INVALID_HANDLE_VALUE ;	// 非実行.binだけの所有handle。
	DRIVERCRATE_EXPECT( test, scratch.createFile( L"corrupt-container.bin", modified) == 0) ;
	DWORD	   written{} ;	// 有界small fixtureの実書込み量。
	const BOOL saved = modified != INVALID_HANDLE_VALUE &&
					   WriteFile( modified, corrupt.data(), static_cast<DWORD>( corrupt.size()),
								 &written, nullptr) ;	// 元driverとして公開しない人工入力。
	// 元file handleだけを閉じ、未知fileを探索/削除しない。
	if( modified != INVALID_HANDLE_VALUE) {
		CloseHandle( modified) ;
	}

	DRIVERCRATE_EXPECT( test, saved && written == corrupt.size()) ;
	OfficialResourceContentReader crc ;	// CRC失敗の部分inventoryを残さないowner。
	const auto					  crcError = crc.initialize( scratch.path( L"corrupt-container.bin"),
															crcPlan) ;	// hash合格後の既存7z CRC診断。
	DRIVERCRATE_EXPECT( test, crcError != 0 && crcError != E_INVALIDARG && crc.entries().empty()) ;
	std::printf(
		"{\"crcError\":%ld,\"missingBodyInspectionError\":%ld,\"ownedCleanupVerified\":true}\n",
		static_cast<long>( crcError), static_cast<long>( missingError)) ;
}
} // namespace
/** @brief 読取限定の有限modeだけを受理する。
 * @param[in] argc 元引数件数。
 * @param[in] argv modeと明示入力。
 * @return 全期待成功0、拒否2、境界失敗1。
 */
int wmain( const int argc, wchar_t **argv)
{
	// 任意追加引数や未知modeを実行へ解釈しない。
	if( argc != 3) {
		return 2 ;
	}

	test::TestContext test ;	// この原processの集計。
	try {
		// modeごとに原read-only APIだけを使用する。
		if( std::wstring_view( argv[1]) == L"vectors") {
			vectors( test, argv[2]) ;
		}
		// 明示real modeだけで原公式byteを通常検査する。
		else if( std::wstring_view( argv[1]) == L"real") {
			real( test, argv[2]) ;
		} else {
			return 2 ;
		}
	} catch( ...) {
		DRIVERCRATE_EXPECT( test, false) ;
	}

	std::printf( "Assertions=%d failures=%d\n", test.assertionCount(), test.failureCount()) ;
	return test.failureCount() == 0 ? 0 : 1 ;
}
