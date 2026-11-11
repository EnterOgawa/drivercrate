//------------------------------------------------------------------------------
/**
 * @file official_catalog_algorithm_tests.cpp
 * @brief CAT宣言算法の非通信境界と明示された原CATを検査します。
 * @version 01.00.01
 * @date 2026/11/05
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/05  元算法の直接境界試験と非実行CAT測定を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 *
 * @note 共通実装を専用compileし、製品に試験用入口を追加しません。実導入・file変更をしません。
 * @see docs/adr/0449-declared-catalog-hash-and-inf-attached-content.md
 */
//------------------------------------------------------------------------------

#include "platform/official_file_verifier.cpp"
#include "platform/official_download_workspace.h"
#include "test_framework.h"

#include <crtdbg.h>
#include <cstdlib>
#include <exception>
#include <iostream>

//------------------------------------------------------------------------------
/**
 * @brief 既存人工scopeの元hash/root-ownerと新しいCAT宣言検査を接続します。
 * @param[in,out] context 一processの有限集計先です。
 * @note 実署名を持たない人工fileだけで、実CATの受入証拠には使用しません。
 */
//------------------------------------------------------------------------------
void testSyntheticCatalogScope( drivercrate::test::TestContext &context)
{
	drivercrate::OfficialDownloadWorkspace workspace ;	// この試験だけの保護所有領域です。
	DRIVERCRATE_EXPECT( context, workspace.initialize( L"cat-scope-test", 71050U) == 0) ;
	std::vector<drivercrate::driver_package_signature_detail::FixtureFile>
		files ;	// 既存factoryの完全固定hash集合です。
	// 異なるbyteのINF/CAT/SYSを全て固定し、任意の成功boolは渡しません。
	for( const auto name : {L"sample.inf", L"sample.cat", L"sample.sys"}) {
		HANDLE file{INVALID_HANDLE_VALUE} ;	// 作成後は下のRAIIだけが閉じます。
		DRIVERCRATE_EXPECT( context, workspace.createFile( name, file) == 0) ;
		std::unique_ptr<void, decltype( &CloseHandle)> owner(
			file, &CloseHandle) ;				// hash前に明示closeし、全returnでも回収します。
		const std::wstring_view bytes( name) ;	// 名前のUTF16 byteを架空内容にします。
		DWORD					written{} ;		// 実書込みbyte数です。
		DRIVERCRATE_EXPECT( context, WriteFile( file, bytes.data(),
											  static_cast<DWORD>( bytes.size() * sizeof( wchar_t)),
											  &written, nullptr) != FALSE) ;
		DRIVERCRATE_EXPECT( context, written == bytes.size() * sizeof( wchar_t)) ;
		owner.reset() ;
		std::wstring hash ;	// 元全byteから計算した固定SHA256です。
		DRIVERCRATE_EXPECT( context,
						   drivercrate::computeFileSha256( workspace.path( name), hash) == 0) ;
		files.push_back( {name, hash, L"sample.inf"}) ;
	}

	const auto scope = drivercrate::driver_package_signature_detail::Access::create(
		// 既存の明示人工scopeだけです。
		std::move( files)) ;
	DRIVERCRATE_EXPECT( context, scope != nullptr) ;
	// scope作成失敗をnative署名の成功へ読み替えません。
	if( scope == nullptr) {
		return ;
	}

	const std::array members{workspace.path( L"sample.inf"),
							 // 同ownerの全memberです。
							 workspace.path( L"sample.sys")} ;
	DRIVERCRATE_EXPECT( context, drivercrate::verifyOfficialCatalogMembers(
									workspace.path( L"sample.cat"), members) != 0) ;
	SP_INF_SIGNER_INFO_W signer{} ;	// 元SetupVerifyInf相当の完全な出力です。
	signer.cbSize = sizeof( signer) ;
	DRIVERCRATE_EXPECT( context,
					   drivercrate::driver_package_signature_detail::setupVerifyInf(
						   workspace.path( L"sample.inf").c_str(), nullptr, &signer) != FALSE) ;
	DRIVERCRATE_EXPECT( context, drivercrate::verifyOfficialCatalogMembers(
									workspace.path( L"sample.cat"), members) == 0) ;
	const auto receipt = scope->receipt() ;	// 実際の人工VERIFY/CLOSE呼出し数だけです。
	DRIVERCRATE_EXPECT( context, receipt.verifyCalls == 2U && receipt.closeCalls == 2U) ;
	std::unique_ptr<void, decltype( &CloseHandle)> mutated(
		CreateFileW( workspace.path( L"sample.sys").c_str(), GENERIC_WRITE, 0U, nullptr,
					TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr),
		&CloseHandle) ;	// 所有試験fileだけを改変します。
	DRIVERCRATE_EXPECT( context, mutated.get() != INVALID_HANDLE_VALUE) ;
	mutated.reset() ;
	DRIVERCRATE_EXPECT( context, drivercrate::verifyOfficialCatalogMembers(
									workspace.path( L"sample.cat"), members) != 0) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原CAT診断または架空算法の有限matrixを実行します。
 * @param[in] count 実行fileを含む引数数です。
 * @param[in] arguments --diagnose-catと原CAT、または--membersとCATとmember集合です。
 * @return 全検査成功0、入力不正2、境界試験・例外・原検査失敗1です。
 * @note CRT/OSの非対話設定を入力とassertionより前に適用します。
 */
//------------------------------------------------------------------------------
int wmain( const int count, wchar_t *arguments[])
{
	SetErrorMode( SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX) ;
	_set_abort_behavior( 0U, _WRITE_ABORT_MSG | _CALL_REPORTFAULT) ;
#if defined( _DEBUG)
	_CrtSetReportMode( _CRT_ASSERT, _CRTDBG_MODE_FILE) ;
	_CrtSetReportFile( _CRT_ASSERT, _CRTDBG_FILE_STDERR) ;
#endif
	try {
		// 明示pathだけを読取り、原宣言の取得とcontext失敗を区別します。
		if( count == 3 && std::wstring_view( arguments[1]) == L"--diagnose-cat") {
			std::vector<drivercrate::CatalogMemberDigest> declarations ;	// 原CATの全member宣言です。
			const auto									  declaration =
				// 宣言診断です。
				drivercrate::readCatalogAlgorithms( arguments[2], declarations) ;
			const auto algorithm = declarations.empty()
									   ? nullptr
									   : declarations.front().algorithm ;	// 最初の原算法です。
			const auto bytes =
				declarations.empty()
					? 0U
					: static_cast<DWORD>( declarations.front().bytes.size()) ;	// 同じ原長です。
			drivercrate::CatalogHashContext context ;							// 同原CATに結ぶ一contextです。
			const auto initialization = declaration == 0 ? context.initialize( algorithm, bytes)
														 : declaration ;	// 原段階です。
			std::wcout << L"declaration=" << declaration << L" algorithm="
					   << (algorithm == nullptr ? L"NONE" : algorithm) << L" bytes=" << bytes
					   << L" initialization=" << initialization << L'\n' ;
			return initialization == 0 ? 0 : 1 ;
		}

		// 保存memberの改変拒否も同じproduction検証へ渡します。
		if( count >= 4 && std::wstring_view( arguments[1]) == L"--members") {
			std::vector<std::wstring> members ;	// 元順で検証する有限集合です。
			// 明示されたmemberだけを保持し、探索・実行しません。
			for( int index = 3; index < count; ++index) {
				members.emplace_back( arguments[index]) ;
			}

			const auto error = drivercrate::verifyOfficialCatalogMembers(
				arguments[2], members) ;	// 原trust結果です。
			std::cout << "memberError=" << error << '\n' ;
			return error == 0 ? 0 : 1 ;
		}

		// 想定しないCLIを架空試験の成功へ読み替えません。
		if( count != 1) {
			return 2 ;
		}

		drivercrate::test::TestContext context ;	// 非通信matrixの有限集計です。
		std::array<BYTE, 64U>		   digest{} ;	// byte値と無関係な宣言構造だけの試験です。
		const std::array<std::pair<const char *, DWORD>, 4U> cases{
			{{szOID_OIWSEC_sha1, 20U},
			 {szOID_NIST_sha256, 32U},
			 {szOID_NIST_sha384, 48U},
			 {szOID_NIST_sha512, 64U}}} ;	// 既知の正確なOID/長さです。
		// 各既知算法と一byte不足の独立拒否を確認します。
		for( const auto &entry : cases) {
			SIP_INDIRECT_DATA data{} ;	// OS構造の原宣言相当です。
			data.DigestAlgorithm.pszObjId = const_cast<PSTR>( entry.first) ;
			data.Digest					  = {entry.second, digest.data()} ;
			PCWSTR algorithm{} ;	// 原成功だけで非nullになる出力です。
			DWORD  bytes{} ;		// 元全長だけを期待します。
			DRIVERCRATE_EXPECT(
				context, drivercrate::readCatalogMemberAlgorithm( data, algorithm, bytes) == 0) ;
			DRIVERCRATE_EXPECT( context, algorithm != nullptr && bytes == entry.second) ;
			--data.Digest.cbData ;
			DRIVERCRATE_EXPECT(
				context, drivercrate::readCatalogMemberAlgorithm( data, algorithm, bytes) != 0) ;
			DRIVERCRATE_EXPECT( context, algorithm == nullptr && bytes == 0U) ;
		}

		SIP_INDIRECT_DATA unknown{} ;				// 既知へのfallbackを持たない架空OIDです。
		char			  oid[] = "1.2.3.4.999" ;	// Windows構造の変更可能fieldに渡す同期bufferです。
		unknown.DigestAlgorithm.pszObjId = oid ;
		unknown.Digest					 = {32U, digest.data()} ;
		PCWSTR algorithm{} ;	// 拒否後の出力です。
		DWORD  bytes{} ;		// 拒否後は0です。
		DRIVERCRATE_EXPECT( context,
						   drivercrate::readCatalogMemberAlgorithm( unknown, algorithm, bytes) != 0) ;
		DRIVERCRATE_EXPECT( context, algorithm == nullptr && bytes == 0U) ;
		unknown.DigestAlgorithm.pszObjId = nullptr ;
		DRIVERCRATE_EXPECT( context,
						   drivercrate::readCatalogMemberAlgorithm( unknown, algorithm, bytes) != 0) ;
		testSyntheticCatalogScope( context) ;
		std::cout << "Assertions: " << context.assertionCount()
				  << ", failures: " << context.failureCount() << '\n' ;
		return context.failureCount() == 0 ? 0 : 1 ;
	} catch( const std::bad_alloc &) {
		std::cerr << "CAT fixture allocation failed.\n" ;
		return 1 ;
	} catch( const std::exception &) {
		std::cerr << "CAT fixture exception.\n" ;
		return 1 ;
	} catch( ...) {
		std::cerr << "CAT fixture unknown exception.\n" ;
		return 1 ;
	}
}
