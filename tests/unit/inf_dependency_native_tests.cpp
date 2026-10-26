//------------------------------------------------------------------------------
/**
 * @file inf_dependency_native_tests.cpp
 * @brief 架空fileと明示実行の標準INFによるnative依存adapter試験。
 * @version 01.00.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  架空file境界と標準INF専用測定を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/24  必須解析に合わせ試験の所有・型・失敗制御を明示。
 * </pre>
 *
 * @note 通常試験は架空INFだけを読む。別targetの明示optionだけが標準INFを読む。
 * PnP列挙・package取得・staging・installを行わない。Windows署名処理は失効照会し得る。
 * @see docs/adr/0270-read-only-inf-dependency-native-adapter.md
 */
//------------------------------------------------------------------------------

#include "platform/inf_dependency_native.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "test_framework.h"

#include <Windows.h>
#include <algorithm>
#include <array>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
using namespace drivercrate ;

constexpr std::string_view PREFIX =
	"[Version]\r\nSignature=\"$Windows NT$\"\r\n" ;	// 架空WIN4の形式だけ。

/** @brief 架空byteを保護workspaceへ作成し、実hashとsizeを固定する。
 * @param[in,out] workspace この試験だけの保護領域。
 * @param[in] name 安全な架空相対名。
 * @param[in] text 架空INF本文。実device IDを含めない。
 * @return 閉じたmember一覧へ登録する実byte期待値。
 * @throws std::runtime_error 作成・書込み・hash失敗。
 */
InfDependencyPackageMember makeMember( OfficialDownloadWorkspace &workspace,
									  const std::wstring &name, std::string_view text)
{
	HANDLE file = INVALID_HANDLE_VALUE ;	// createFileから所有を受け取り直ちに閉じる。
	// 作成失敗後は架空成功を作らない。
	if( workspace.createFile( name, file) != 0) {
		throw std::runtime_error( "fixture create") ;
	}

	DWORD	   written{} ;	// 実際に書き込んだbyte数。
	// Win32書込みの成功値。byte数は別途比較する。
	const bool success =
		WriteFile( file, text.data(), static_cast<DWORD>( text.size()), &written, nullptr) != FALSE ;
	CloseHandle( file) ;
	// 短縮書込みを有効なfixtureにしない。
	if( !success || written != text.size()) {
		throw std::runtime_error( "fixture write") ;
	}

	InfDependencyPackageMember member{name, {}, text.size()} ;	// この実fileの期待値。
	// 実byteのhashを利用し、入力hashを架空定数へ置換しない。
	if( computeFileSha256( workspace.path( name), member.sha256) != 0) {
		throw std::runtime_error( "fixture hash") ;
	}

	return member ;
}

/** @brief 架空workspaceを初期化する。
 * @param[in,out] workspace 一試験だけの単独所有領域。
 * @throws std::runtime_error 保護領域の初期化失敗。
 */
void initialize( OfficialDownloadWorkspace &workspace)
{
	// 権限不足を成功やskipとして隠さない。
	if( workspace.initialize( L"inf-native-fixture", 1U) != 0) {
		throw std::runtime_error( "fixture initialize") ;
	}
}

/** @brief 成功観測を導入許可へ昇格させないことを確認する。
 * @param[in,out] context 集計先。
 * @param[in] result 架空fileの観測結果。
 */
void expectNonExecutable( drivercrate::test::TestContext	 &context,
						 const InfDependencyNativeResult &result)
{
	DRIVERCRATE_EXPECT( context,
					   result.dependency.plan.actionCoverage == InfDependencyEvidence::NOT_CHECKED) ;
	DRIVERCRATE_EXPECT( context, result.dependency.plan.deviceApplicability ==
									InfDependencyEvidence::NOT_CHECKED) ;
	DRIVERCRATE_EXPECT( context,
					   result.dependency.plan.installRoute == InfDependencyEvidence::NOT_CHECKED) ;
	DRIVERCRATE_EXPECT( context, !result.dependency.plan.rootEvidenceVerified) ;
	// 架空packageの存在を公式配布由来と表現しない。
	for( const auto &document : result.dependency.documents) {
		DRIVERCRATE_EXPECT( context, document.byteBinding == InfDependencyEvidence::VERIFIED) ;
		DRIVERCRATE_EXPECT( context, document.provenance == InfDependencyEvidence::NOT_CHECKED) ;
		DRIVERCRATE_EXPECT( context, document.signature == InfDependencyEvidence::FAILED) ;
	}
}

/** @brief path・実byte・明示節・書込競合を架空fileで検証する。
 * @param[in,out] context assertion集計先。
 */
void fixtures( drivercrate::test::TestContext &context)
{
	const std::array<std::wstring_view, 24U> invalid{
		L"",		  L"..\\x.inf", L".\\x.inf",   L"x/driver.inf", L"\\x.inf",
		L"C:\\x.inf", L"x:stream",	L"a\\\\x.inf", L"x.inf.",		L"x.inf ",
		L"NUL.inf",	  L"COM1.inf",	L"LPT9.inf",   L"CONIN$.inf",	L"CONOUT$.inf",
		L"a%20.inf",  L"a?.inf",	L"a*.inf",	   L"a|b.inf",		L"a\"b.inf",
		L"a<.inf",	  L"a>.inf",	L"\u65e5.inf", L"x.inf\\"} ;	// 相対pathの拒否集合。
	// 不正pathを正規化で救済しない。
	for( const auto path : invalid) {
		DRIVERCRATE_EXPECT( context, !validInfDependencyPath( path, false)) ;
	}

	DRIVERCRATE_EXPECT( context, validInfDependencyPath( L"folder\\driver.inf", false)) ;
	DRIVERCRATE_EXPECT( context, validInfDependencyPath( L"C:\\Users\\\u65e5\\driver.inf", true)) ;
	DRIVERCRATE_EXPECT( context, !validInfDependencyPath( L"C:\\COM\u00b9.inf", true)) ;
	DRIVERCRATE_EXPECT( context, !validInfDependencyPath( L"\\\\server\\a.inf", true)) ;
	DRIVERCRATE_EXPECT( context, !validInfDependencyPath( L"\\\\?\\C:\\a.inf", true)) ;
	DRIVERCRATE_EXPECT( context, !validInfDependencyPath( std::wstring( 260U, L'a'), false)) ;
	DRIVERCRATE_EXPECT( context, !validInfDependencyPath( std::wstring( L"a\0b.inf", 7U), false)) ;
	OfficialDownloadWorkspace workspace ;	// 一試験runの架空file所有者。
	initialize( workspace) ;
	const auto root = makeMember(
		workspace, L"root.inf",
		std::string( PREFIX) +
			"[Install]\r\nInclude=peer.inf\r\nNeeds=Shared\r\n[Empty]\r\n[Local]\r\nNeeds=Empty,Absent\r\n") ;	// 明示参照。
	const auto peer =
		// 空の共有節。
		makeMember( workspace, L"peer.inf", std::string( PREFIX) + "[Shared]\r\n") ;
	std::vector<InfDependencyPackageMember> members{root, peer} ;	// 閉じた架空一覧。
	const std::array<std::wstring, 1U>		seeds{L"Install"} ;		// 明示seed。
	InfDependencyNativeResult				result ;				// 全成功時だけのsnapshot。
	DRIVERCRATE_EXPECT(
		context, inspectNativeInfDependencies( workspace, members, 0U, seeds, 9U, result) == 0) ;
	DRIVERCRATE_EXPECT( context, result.dependency.documents.size() == 2U) ;
	DRIVERCRATE_EXPECT( context, result.dependency.edges.size() == 2U) ;
	DRIVERCRATE_EXPECT( context, result.findings.size() == 2U) ;
	// 署名不足でも参照の存在観測を消さない。
	for( const auto &edge : result.dependency.edges) {
		DRIVERCRATE_EXPECT( context, edge.state == InfDependencyState::OBSERVED) ;
	}

	expectNonExecutable( context, result) ;
	const std::array<std::wstring, 1U> local{L"Local"} ;	// 空節と欠落の分離。
	DRIVERCRATE_EXPECT(
		context, inspectNativeInfDependencies( workspace, members, 0U, local, 10U, result) == 0) ;
	DRIVERCRATE_EXPECT( context, result.dependency.edges.size() == 2U) ;
	DRIVERCRATE_EXPECT( context, result.dependency.edges[0].state == InfDependencyState::OBSERVED) ;
	DRIVERCRATE_EXPECT( context, result.dependency.edges[1].reason == InfDependencyReason::MISSING) ;
	const std::array<std::wstring, 1U> missing{L"Absent"} ;	// 未存在の明示seed。
	DRIVERCRATE_EXPECT(
		context, inspectNativeInfDependencies( workspace, members, 0U, missing, 11U, result) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   result.dependency.sections.size() == 1U &&
						   result.dependency.sections[0].state == InfDependencyReadState::MISSING) ;
	// 入力拒否では古い結果を一切残さない。
	for( std::size_t variant = 0U; variant < 8U; ++variant) {
		auto		  changed = members ;	// 一項目だけの入力変化。
		std::size_t	  rootIndex{} ;			// 通常の開始位置。
		std::uint64_t observation = 12U ;	// 通常の非零run。
		// それぞれ独立した拒否入力を生成する。
		if( variant == 0U) {
			changed[0].sha256[0] = changed[0].sha256[0] == L'a' ? L'b' : L'a' ;
		}

		// 原sizeと異なる入力を拒否させる。
		if( variant == 1U) {
			++changed[0].byteCount ;
		}

		// 大文字hashを暗黙正規化させない。
		if( variant == 2U) {
			changed[0].sha256 = std::wstring( 64U, L'A') ;
		}

		// 重複memberの閉じていない一覧を拒否させる。
		if( variant == 3U) {
			changed.push_back( root) ;
		}

		// Workspace外への相対位置を拒否させる。
		if( variant == 4U) {
			changed[0].relativePath = L"..\\root.inf" ;
		}

		// 一INFの実byte上限超過を拒否させる。
		if( variant == 5U) {
			changed[0].byteCount = 4U * 1024U * 1024U + 1U ;
		}

		// 未登録の開始位置を拒否させる。
		if( variant == 6U) {
			rootIndex = 2U ;
		}

		// 非零でない観測世代を拒否させる。
		if( variant == 7U) {
			observation = 0U ;
		}

		DRIVERCRATE_EXPECT( context, inspectNativeInfDependencies( workspace, changed, rootIndex,
																 seeds, observation, result) != 0) ;
		DRIVERCRATE_EXPECT( context, result.dependency.documents.empty() && result.findings.empty()) ;
	}

	HANDLE writer = CreateFileW( workspace.path( root.relativePath).c_str(), GENERIC_WRITE,
								FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0U,
								nullptr) ;	// 同時writerを残す。
	DRIVERCRATE_EXPECT( context, writer != INVALID_HANDLE_VALUE) ;
	const auto conflict = inspectNativeInfDependencies( workspace, members, 0U, seeds, 13U,
													   result) ;	// 固定を競合させる。
	// 有効なfixture writerだけを閉じる。
	if( writer != INVALID_HANDLE_VALUE) {
		CloseHandle( writer) ;
	}

	DRIVERCRATE_EXPECT(
		context, conflict == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_SHARING_VIOLATION))) ;
	DRIVERCRATE_EXPECT( context, result.dependency.documents.empty()) ;

	OfficialDownloadWorkspace ambiguousWorkspace ;	// 同名だが別fileの候補を置く。
	initialize( ambiguousWorkspace) ;
	const auto ambiguousRoot = makeMember(
		ambiguousWorkspace, L"folder\\root.inf",
		std::string( PREFIX) +
			"[Install]\r\nInclude=peer.inf\r\nNeeds=Shared\r\n") ;	// 親とrootの双方を指定。
	const auto parentPeer = makeMember( ambiguousWorkspace, L"folder\\peer.inf",
									   // 親directoryの別file。
									   std::string( PREFIX) + "[Shared]\r\n") ;
	const auto rootPeer	  = makeMember( ambiguousWorkspace, L"peer.inf",
									   // 同hashでも別の物理file。
									   std::string( PREFIX) + "[Shared]\r\n") ;
	const std::array<InfDependencyPackageMember, 3U> ambiguousMembers{ambiguousRoot, parentPeer,
																	  rootPeer} ;	// 閉じた一覧。
	DRIVERCRATE_EXPECT( context, inspectNativeInfDependencies( ambiguousWorkspace, ambiguousMembers,
															 0U, seeds, 14U, result) == 0) ;
	DRIVERCRATE_EXPECT( context, result.dependency.documents.size() == 3U &&
									result.dependency.edges.size() == 2U) ;
	// 同hashの別fileを一件へ合併しない。
	for( const auto &edge : result.dependency.edges) {
		DRIVERCRATE_EXPECT( context, edge.reason == InfDependencyReason::AMBIGUOUS &&
										edge.candidateCount == 2U) ;
	}

	const std::array<std::string, 8U> bodies{
		"[Install]\r\nNeeds=Install\r\n",
		"[Install]\r\nNeeds=\r\n",
		"[Install]\r\nInclude=../peer.inf\r\n",
		"[Install]\r\nNeeds=" + std::string( 255U, 'a') + "\r\n",
		"[Install]\r\nInclude=never-drivercrate-native-fixture.inf\r\n",
		"[Install]\r\nNeeds=Shared\r\n[Shared]\r\nNeeds=Install\r\n",
		"[Install]\r\nInclude=peer.inf,peer.inf\r\nNeeds=Shared\r\n",
		"[Install]\r\nInclude=peer.inf\r\nNeeds=Shared\r\n[Shared]\r\n"} ;	// parserと核の境界入力。
	// 一runの原byteだけを使い、過去snapshotを使い回さない。
	for( std::size_t variant = 0U; variant < bodies.size(); ++variant) {
		OfficialDownloadWorkspace variantWorkspace ;	// このrunだけの所有領域。
		initialize( variantWorkspace) ;
		const auto variantRoot = makeMember( variantWorkspace, L"root.inf",
											// 原byte。
											std::string( PREFIX) + bodies[variant]) ;
		const auto variantPeer = makeMember( variantWorkspace, L"peer.inf",
											// 共通先。
											std::string( PREFIX) + "[Shared]\r\n") ;
		const std::array<InfDependencyPackageMember, 2U> variantMembers{variantRoot,
																		variantPeer} ;	// 明示一覧。
		const auto variantError = inspectNativeInfDependencies(
			variantWorkspace, variantMembers, 0U, seeds, 20U + variant, result) ;	// 実parser。
		DRIVERCRATE_EXPECT( context, (variantError != 0) == (variant == 3U)) ;
		// 過長fieldだけが全体拒否となり、古いgraphを残さない。
		if( variant == 3U) {
			DRIVERCRATE_EXPECT( context, result.dependency.edges.empty() && result.findings.empty()) ;
			continue ;
		}

		expectNonExecutable( context, result) ;
		// 循環・不正名・未発見をそれぞれ独立した理由へ残す。
		if( variant == 0U || variant == 5U) {
			DRIVERCRATE_EXPECT( context,
							   std::ranges::any_of( result.dependency.edges, []( const auto &edge) {
								   // 循環が有限停止した事実だけを確認する。
								   return edge.reason == InfDependencyReason::CYCLE ;
							   })) ;
		}

		// 空Needsと親移動Includeを不正参照として残す。
		if( variant == 1U || variant == 2U) {
			DRIVERCRATE_EXPECT( context, result.dependency.edges.size() == 1U &&
											result.dependency.edges[0].state ==
												InfDependencyState::INVALID_REFERENCE) ;
		}

		// 照会済みの架空不在を署名不足に読み替えない。
		if( variant == 4U) {
			DRIVERCRATE_EXPECT( context,
							   result.dependency.edges[0].reason == InfDependencyReason::MISSING) ;
		}

		// 同じ物理fileへの重複辺は保持し、documentだけを共有する。
		if( variant == 6U) {
			DRIVERCRATE_EXPECT( context, result.dependency.documents.size() == 2U &&
											result.dependency.edges.size() == 3U) ;
		}

		// 元INFとInclude先双方の同名節を恣意的に一方へ決めない。
		if( variant == 7U) {
			DRIVERCRATE_EXPECT( context,
							   result.dependency.edges[1].reason == InfDependencyReason::AMBIGUOUS) ;
		}
	}

	// 個別行数・field数・空field累積の三上限を別々に確認する。
	for( std::size_t variant = 0U; variant < 3U; ++variant) {
		OfficialDownloadWorkspace boundedWorkspace ;	// 大量入力だけの所有領域。
		initialize( boundedWorkspace) ;
		std::string body = std::string( PREFIX) + "[Install]\r\n" ;	// 有限な原本文。
		// field上限を試す場合は一行へ、行上限では一directiveずつ追加する。
		if( variant != 0U) {
			body += "Needs=" ;
		}

		// 最大4,097参照の架空入力を生成する。
		for( std::size_t ordinal = 0U; ordinal < (variant == 2U ? 4096U : 4097U); ++ordinal) {
			body += variant == 0U ? "Needs=Absent\r\n" : (ordinal == 0U ? "Absent" : ",Absent") ;
		}

		// 上限ちょうどの非空field後に空fieldを追加して累積を越えさせる。
		if( variant == 2U) {
			body += "\r\nNeeds=\r\n" ;
		}

		const auto boundedRoot =
			// 4 MiB未満の上限試験。
			makeMember( boundedWorkspace, L"root.inf", body) ;
		const std::array<InfDependencyPackageMember, 1U> boundedMembers{
			boundedRoot} ;	// 閉じた一覧。
		DRIVERCRATE_EXPECT( context,
						   inspectNativeInfDependencies( boundedWorkspace, boundedMembers, 0U, seeds,
														40U + variant, result) != 0) ;
		DRIVERCRATE_EXPECT( context, result.dependency.edges.empty() && result.findings.empty()) ;
	}
}

/** @brief 標準INF4件を明示optionだけで読み、署名と由来の実測数を出力する。
 * @return 観測成功0、native失敗1。導入や全package検証の成功値ではない。
 */
int windowsProbe()
{
	OfficialDownloadWorkspace workspace ;	// 架空rootだけを所有する測定領域。
	initialize( workspace) ;
	const auto root = makeMember(
		workspace, L"probe.inf",
		std::string( PREFIX) +
			"[Probe]\r\nInclude=ks.inf,wdmaudio.inf,machine.inf,usb.inf\r\nNeeds=Version\r\n") ;	// 公開標準名だけ。
	const std::array<InfDependencyPackageMember, 1U> members{root} ;								// 架空packageの閉じた一覧。
	const std::array<std::wstring, 1U>				 seeds{L"Probe"} ;								// 明示節のみ。
	InfDependencyNativeResult						 result ;										// 読取専用の実観測。
	const auto										 error =
		// PnP照会なし。
		inspectNativeInfDependencies( workspace, members, 0U, seeds, 100U, result) ;
	std::size_t system{} ;		// 標準INFの観測数。
	std::size_t signatures{} ;	// 独立署名成功数。
	std::size_t provenance{} ;	// 同OS由来成功数。
	std::size_t resolved{} ;	// 一意SYSTEM辺だけの数。
	std::size_t ambiguous{} ;	// 同名節の候補を隠さず保留した辺数。
	std::string documents ;		// 実標準INFのhash／sizeだけを保持するJSON。
	// 名称・path・署名display・IDを測定出力へ出さない。
	for( const auto &document : result.dependency.documents) {
		// 架空rootを標準INFの分母へ含めない。
		if( document.origin == InfDependencyOrigin::SYSTEM) {
			std::string hash ;	// 検証済み小文字hexだけのASCII出力。
			// hashの既知ASCII範囲を明示変換し、暗黙narrowingしない。
			for( const wchar_t digit : document.sha256) {
				hash.push_back( static_cast<char>( digit)) ;
			}

			documents += (system == 0U ? "" : ",") + std::string( "{\"sha256\":\"") + hash +
						 "\",\"bytes\":" + std::to_string( document.byteCount) + "}" ;
			++system ;
			signatures += document.signature == InfDependencyEvidence::VERIFIED ? 1U : 0U ;
			provenance += document.provenance == InfDependencyEvidence::VERIFIED ? 1U : 0U ;
		}
	}

	// 明示Version節は元INFと標準INFで曖昧なので、一意Includeだけを数える。
	for( const auto &edge : result.dependency.edges) {
		resolved += edge.state == InfDependencyState::RESOLVED_SYSTEM ? 1U : 0U ;
		ambiguous += edge.reason == InfDependencyReason::AMBIGUOUS ? 1U : 0U ;
	}

	std::cout << "{\"error\":" << error << ",\"systemInfObserved\":" << system
			  << ",\"signatureVerified\":" << signatures
			  << ",\"systemProvenanceVerified\":" << provenance
			  << ",\"resolvedSystemEdges\":" << resolved << ",\"ambiguousEdges\":" << ambiguous
			  << ",\"edges\":" << result.dependency.edges.size() << ",\"documents\":[" << documents
			  << "]"
			  << ",\"productInstallConnected\":false,\"actualDriverAdded\":0}\n" ;
	return error == 0 && system == 4U && signatures == 4U && provenance == 4U && resolved == 4U &&
				   ambiguous == 1U
			   ? 0
			   : 1 ;
}
} // namespace

/** @brief 通常の架空試験または明示測定targetを実行する。
 * @param[in] argc optionを含む引数数。
 * @param[in] argv 呼出し中有効な終端付きoption。
 * @return 全assertionまたは測定成功0、入力・試験失敗1。
 */
int wmain( int argc, wchar_t **argv)
{
	try {
#ifdef DRIVERCRATE_NATIVE_WINDOWS_PROBE
		// 実標準INFの署名照会を明示optionなしで開始しない。
		if( argc != 2 || std::wstring_view( argv[1]) != L"--windows-probe") {
			return 1 ;
		}

		return windowsProbe() ;
#else
		// 通常CTestから測定optionを通さない。
		if( argc != 1 || argv == nullptr) {
			return 1 ;
		}

		drivercrate::test::TestContext context ;	// 一processのassertion集計。
		fixtures( context) ;
		std::cout << "Assertions: " << context.assertionCount()
				  << ", failures: " << context.failureCount() << '\n' ;
		return context.failureCount() == 0 ? 0 : 1 ;
#endif
	} catch( ...) {
		std::cerr << "Native fixture failure.\n" ;
		return 1 ;
	}
}
