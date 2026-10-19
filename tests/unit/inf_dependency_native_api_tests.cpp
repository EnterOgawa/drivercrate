//------------------------------------------------------------------------------
/**
 * @file inf_dependency_native_api_tests.cpp
 * @brief 架空OS・署名・Storeと実fileでnative障害を再現する専用試験。
 * @version 01.04.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  独立証拠・再確認・API障害の注入試験を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/07  sourceなしinbox観測と全payload非検証・FAILED保持を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/07  同節Services・明示Needs名と未採用payload節の分離を回帰。
 * Ver.01.03.00 Shunji Ogawa  2026/10/13  サービス集合の正常・途中失敗契約八条件を接続。
 * Ver.01.04.00 Shunji Ogawa  2026/10/15  NeedsのHKR全行と型・設置文脈の正負回帰を追加。
 * </pre>
 *
 * @note この専用targetではtrust／OS APIを全て架空化する。実署名・実device・導入の測定ではない。
 * @see docs/adr/0271-compile-isolated-inf-native-api-tests.md
 */
//------------------------------------------------------------------------------

#include "support/inf_dependency_native_test_api.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "test_framework.h"
#include <WinIoCtl.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <future>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {
/** @brief 元APIの障害または根拠変化。一runで一種類だけ注入する。 */
enum class Fault {
	/// 架空APIの正常観測。
	NONE,
	/// 開始OS照会が失敗する。
	VERSION_START,
	/// 終了OS照会が失敗する。
	VERSION_END,
	/// 終了OS majorが変わる。
	MAJOR_CHANGED,
	/// 終了OS minorが変わる。
	MINOR_CHANGED,
	/// 終了OS buildが変わる。
	BUILD_CHANGED,
	/// 終了OSがServerへ変わる。
	PRODUCT_CHANGED,
	/// 開始product typeが未知。
	PRODUCT_UNKNOWN,
	/// native architectureがx64以外。
	ARCHITECTURE,
	/// 開始buildが零。
	BUILD_ZERO,
	/// 開始majorが零。
	MAJOR_ZERO,
	/// OS起点照会が失敗。
	DIRECTORY_ERROR,
	/// OS起点がUNC。
	DIRECTORY_UNC,
	/// 初回system INF署名失敗。
	SIGNATURE_START,
	/// 終了system INF署名失敗。
	SIGNATURE_END,
	/// 完全scoreがWHQLで標準由来未確認。
	WHQL_SCORE,
	/// 終了完全scoreがWHQLへ変わる。
	SCORE_CHANGED,
	/// 初回CATが許可領域外。
	CAT_OUTSIDE,
	/// 終了CATが別位置へ変わる。
	CAT_CHANGED,
	/// 初回signerが空。
	SIGNER_EMPTY,
	/// CAT応答に終端がない。
	CAT_UNTERMINATED,
	/// 終了signerが空。
	SIGNER_END_EMPTY,
	/// 初回CAT member署名が失敗。
	CAT_SIGNATURE_START,
	/// 終了CAT member署名が失敗。
	CAT_SIGNATURE_END,
	/// 初回Store対応情報がない。
	STORE_START,
	/// 終了Store対応照会が失敗。
	STORE_END,
	/// 初回Storeが許可領域外。
	STORE_OUTSIDE,
	/// 終了Storeが別位置へ変わる。
	STORE_CHANGED,
	/// 対応Storeの実byteが異なる。
	STORE_BYTES,
	/// Store成功応答の位置が空。
	STORE_EMPTY,
	/// Store成功応答に埋込みNUL。
	STORE_NUL,
	/// Store APIが不正応答を報告。
	STORE_MALFORMED,
	/// 属性APIが失敗。
	ATTRIBUTES_ERROR,
	/// INF発見後のCAT属性照会がpath不在を報告。
	ATTRIBUTES_PATH,
	/// 開いた参照INFの属性APIがfile不在を報告。
	ATTRIBUTES_INF_NOT_FOUND,
	/// 途中の属性応答がreparseへ変わる。
	ATTRIBUTES_REPARSE,
	/// 途中の属性応答でfile／directory種類が変わる。
	ATTRIBUTES_TYPE,
	/// 属性callbackの例外。
	ATTRIBUTES_THROW,
	/// 署名callbackの例外。
	SIGNATURE_THROW,
	/// 終了OS callbackの例外。
	VERSION_THROW,
	/// CAT位置の実fileが未発見。
	CAT_MISSING,
	/// CAT親directoryも未発見。
	CAT_PARENT_MISSING,
	/// 保持中の実fileへwriterを試みる。
	WRITER,
	/// 同期test APIへの再入を試みる。
	REENTRY,
	/// rootの実期待hashだけが異なる。
	HASH_CHANGED,
	/// root署名不合格でも資料存在を保持。
	ROOT_SIGNATURE,
} ;

/** @brief 一runの入力障害と期待する全体診断。 */
struct Scenario {
	/// 一種類の注入。
	Fault		fault ;
	/// 観測成功0、全体拒否では元HRESULT。
	NativeError expectedError ;
} ;
constexpr std::array<Scenario, 46U> SCENARIOS{{
	{Fault::NONE, 0},
	{Fault::VERSION_START, E_ACCESSDENIED},
	{Fault::VERSION_END, E_ACCESSDENIED},
	{Fault::MAJOR_CHANGED, HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH)},
	{Fault::MINOR_CHANGED, HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH)},
	{Fault::BUILD_CHANGED, HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH)},
	{Fault::PRODUCT_CHANGED, HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH)},
	{Fault::PRODUCT_UNKNOWN, HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)},
	{Fault::ARCHITECTURE, HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)},
	{Fault::BUILD_ZERO, HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)},
	{Fault::MAJOR_ZERO, HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)},
	{Fault::DIRECTORY_ERROR, E_ACCESSDENIED},
	{Fault::DIRECTORY_UNC, E_INVALIDARG},
	{Fault::SIGNATURE_START, 0},
	{Fault::SIGNATURE_END, E_ACCESSDENIED},
	{Fault::WHQL_SCORE, 0},
	{Fault::SCORE_CHANGED, HRESULT_FROM_WIN32( ERROR_FILE_INVALID)},
	{Fault::CAT_OUTSIDE, 0},
	{Fault::CAT_CHANGED, HRESULT_FROM_WIN32( ERROR_FILE_INVALID)},
	{Fault::SIGNER_EMPTY, E_UNEXPECTED},
	{Fault::CAT_UNTERMINATED, E_UNEXPECTED},
	{Fault::SIGNER_END_EMPTY, HRESULT_FROM_WIN32( ERROR_FILE_INVALID)},
	{Fault::CAT_SIGNATURE_START, 0},
	{Fault::CAT_SIGNATURE_END, E_ACCESSDENIED},
	{Fault::STORE_START, 0},
	{Fault::STORE_END, E_ACCESSDENIED},
	{Fault::STORE_OUTSIDE, E_ACCESSDENIED},
	{Fault::STORE_CHANGED, HRESULT_FROM_WIN32( ERROR_FILE_INVALID)},
	{Fault::STORE_BYTES, 0},
	{Fault::STORE_EMPTY, E_ACCESSDENIED},
	{Fault::STORE_NUL, E_ACCESSDENIED},
	{Fault::STORE_MALFORMED, E_UNEXPECTED},
	{Fault::ATTRIBUTES_ERROR, E_ACCESSDENIED},
	{Fault::ATTRIBUTES_PATH, HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND)},
	{Fault::ATTRIBUTES_INF_NOT_FOUND, HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND)},
	{Fault::ATTRIBUTES_REPARSE, E_ACCESSDENIED},
	{Fault::ATTRIBUTES_TYPE, E_ACCESSDENIED},
	{Fault::ATTRIBUTES_THROW, E_FAIL},
	{Fault::SIGNATURE_THROW, E_FAIL},
	{Fault::VERSION_THROW, E_FAIL},
	{Fault::CAT_MISSING, HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND)},
	{Fault::CAT_PARENT_MISSING, HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND)},
	{Fault::WRITER, 0},
	{Fault::REENTRY, 0},
	{Fault::HASH_CHANGED, HRESULT_FROM_WIN32( ERROR_FILE_INVALID)},
	{Fault::ROOT_SIGNATURE, 0},
}} ; // 公開しない固定障害matrix。実署名測定ではない。

/** @brief 一runの実fileと借用callbackの状態を所有する。 */
struct Fixture {
	/// 架空fileだけを所有する保護領域。
	OfficialDownloadWorkspace				   workspace ;
	/// 閉じたpackage一覧。system fileをpackageとして登録しない。
	std::array<InfDependencyPackageMember, 1U> members ;
	/// 一同期runのAPI集合。capture先のthisはrun終了まで生存する。
	InfDependencyNativeTestApi				   api ;
	/// 注入する一障害。
	Fault									   fault{Fault::NONE} ;
	/// OS開始／終了照会の回数。
	std::size_t								   versionCalls{} ;
	/// system INFの署名開始／終了照会回数。
	std::size_t								   signatureCalls{} ;
	/// system CATの開始／終了照会回数。
	std::size_t								   catalogCalls{} ;
	/// system Storeの開始／終了照会回数。
	std::size_t								   storeCalls{} ;
	/// packageを含む署名callback全呼出し数。
	std::size_t								   allSignatureCalls{} ;
	/// 属性変更を開始する時点。system署名の初回観測後true。
	bool									   changedAttributes{} ;
	/// 保持中fileへのwriterの元診断。
	DWORD									   writerError{} ;
	/// 再入を拒否した元診断。
	NativeError								   reentryError{} ;
	/// CAT memberを一INFだけに結合した場合true。
	bool									   memberBound{true} ;
	/// 二threadで異なる文脈を確認する架空build。
	DWORD									   build{26100U} ;

	/** @brief 架空fileとAPI集合を初期化する。
	 * @param[in] selected このrunの一障害。
	 * @param[in] payloadBody 到達Shared節からの架空file用途。実payload fileは作成しない。
	 * @param[in] rootBody 空なら既存root本文、それ以外はこのfixtureだけの明示節群。
	 * @param[in] systemSection 同期fixtureで使用する架空参照節名。装飾の独自補完をしない。
	 * @throws std::runtime_error 架空file作成／hash失敗。
	 */
	explicit Fixture( Fault selected, std::string_view payloadBody = {},
					 std::string_view rootBody = {}, std::string_view systemSection = "Shared")
		: fault( selected)
	{
		// 初期化失敗をskipや架空成功にしない。
		if( workspace.initialize( L"inf-native-api-test", 1U) != 0) {
			throw std::runtime_error( "fixture initialize") ;
		}

		const std::string root =
			"[Version]\r\nSignature=\"$Windows NT$\"\r\n" +
			std::string( rootBody.empty() ? "[Install]\r\nInclude=peer.inf\r\nNeeds=Shared\r\n"
										 : rootBody) ;	// 元正例または限定六形の架空明示本文。
		members[0] = file( L"root.inf", root) ;
		const std::string system =
			"[Version]\r\nSignature=\"$Windows NT$\"\r\n" +
			std::string( payloadBody.empty() ? "" : "LayoutFile=fixture-layout.inf\r\n") + "[" +
			std::string( systemSection) + "]\r\n" +
			// 実IDを含まない原byte。
			std::string( payloadBody) ;
		(void)file( L"windows\\INF\\peer.inf", system) ;
		(void)file( L"windows\\System32\\DriverStore\\FileRepository\\fixture\\peer.inf",
				   fault == Fault::STORE_BYTES ? system + ";different\r\n" : system) ;
		(void)file( L"fixture.cat", "synthetic package catalog") ;
		// 実CAT欠落の拒否を試す場合だけ、system CATを作成しない。
		if( fault != Fault::CAT_PARENT_MISSING) {
			(void)file( L"windows\\System32\\CatRoot\\placeholder.txt", "synthetic parent") ;
		}

		// 親directoryの不在も別の元診断として試す。
		if( fault != Fault::CAT_MISSING && fault != Fault::CAT_PARENT_MISSING) {
			(void)file( L"windows\\System32\\CatRoot\\fixture.cat", "synthetic system catalog") ;
		}

		// 同じbyteへ結合できない期待値を入力する。
		if( fault == Fault::HASH_CHANGED) {
			members[0].sha256[0] = members[0].sha256[0] == L'a' ? L'b' : L'a' ;
		}

		api.version = [this]( auto &version, auto &native) {
			// Fixtureの同期生存期間だけを借用し、実OSを変更しない。
			return versionInfo( version, native) ;
		} ;
		api.windowsDirectory = [this]( auto &path) -> NativeError {
			// 起点APIの元失敗を注入する。
			if( fault == Fault::DIRECTORY_ERROR) {
				return E_ACCESSDENIED ;
			}

			path = fault == Fault::DIRECTORY_UNC ? L"\\\\synthetic\\windows"
												 : workspace.path( L"windows") ;
			return 0 ;
		} ;
		api.infSignature = [this]( const auto &path, auto &signer) {
			return signature( path, signer) ;
		} ; // 同期借用。
		api.catalogSignature = [this]( const auto &catalog, auto paths) -> NativeError {
			// 同じ一INF memberを署名処理へ渡す境界だけを確認する。
			memberBound = memberBound && paths.size() == 1U &&
						  (paths.front() == workspace.path( L"root.inf") ||
						   paths.front() == workspace.path( L"windows\\INF\\peer.inf")) ;
			// systemとpackage CATを独立に数える。
			if( catalog == workspace.path( L"windows\\System32\\CatRoot\\fixture.cat")) {
				++catalogCalls ;
				// 初回不合格と終了失効を別々に注入する。
				if( (fault == Fault::CAT_SIGNATURE_START && catalogCalls == 1U) ||
				   (fault == Fault::CAT_SIGNATURE_END && catalogCalls == 2U)) {
					return E_ACCESSDENIED ;
				}
			}

			return 0 ;
		} ;
		api.driverStore = [this]( const auto &path, auto &location) -> NativeError {
			++storeCalls ;
			// 元INF以外のStoreを照会したfixtureを拒否する。
			if( path != workspace.path( L"windows\\INF\\peer.inf")) {
				return E_INVALIDARG ;
			}

			// 初回照会の不在だけを未検査に保持する。
			if( fault == Fault::STORE_START && storeCalls == 1U) {
				return HRESULT_FROM_WIN32( ERROR_NOT_FOUND) ;
			}

			// 終了照会失敗後に旧由来を使わせない。
			if( fault == Fault::STORE_END && storeCalls == 2U) {
				return E_ACCESSDENIED ;
			}

			// 元APIの不正応答を未知由来へ弱めない。
			if( fault == Fault::STORE_MALFORMED) {
				return E_UNEXPECTED ;
			}

			location = workspace.path(
				L"windows\\System32\\DriverStore\\FileRepository\\fixture\\peer.inf") ;
			// 許可領域外の成功応答を注入する。
			if( fault == Fault::STORE_OUTSIDE) {
				location = workspace.path( L"root.inf") ;
			}

			// 終了対応変更を同じbyteとして補完させない。
			if( fault == Fault::STORE_CHANGED && storeCalls == 2U) {
				location += L".different" ;
			}

			// 空の成功位置は不正として拒否する。
			if( fault == Fault::STORE_EMPTY) {
				location.clear() ;
			}

			// 終端付き文字列へ埋込みNULを混入する。
			if( fault == Fault::STORE_NUL) {
				location.push_back( L'\0') ;
			}

			return 0 ;
		} ;
		api.attributes = [this]( HANDLE handle, auto &attributes) -> NativeError {
			// 有効INF handleの属性失敗を、open不在へ読み替えさせない。
			if( fault == Fault::ATTRIBUTES_INF_NOT_FOUND) {
				std::array<wchar_t, MAX_PATH + 4U> name{} ;	// 固定handleの実最終位置。
				const DWORD						   count = GetFinalPathNameByHandleW(
					   handle, name.data(), static_cast<DWORD>( name.size()),
					   FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;	// 元位置だけをfixture内で照合する。
				// 元INFに到達した応答だけを注入する。名称を出力しない。
				if( count > 4U && count < name.size() &&
				   CompareStringOrdinal( name.data() + 4U, -1,
										workspace.path( L"windows\\INF\\peer.inf").c_str(), -1,
										TRUE) == CSTR_EQUAL) {
					return HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND) ;
				}
			}

			// 属性APIそのものの失敗を注入する。
			if( fault == Fault::ATTRIBUTES_ERROR) {
				return E_ACCESSDENIED ;
			}

			// INF固定後の別根拠に対するpath不在を原INF不在へ読み替えさせない。
			if( changedAttributes && fault == Fault::ATTRIBUTES_PATH) {
				return HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND) ;
			}

			// 属性callback例外の全体拒否を試す。
			if( fault == Fault::ATTRIBUTES_THROW) {
				throw std::runtime_error( "synthetic attributes") ;
			}

			// 実handleの属性は確認し、通常file開閉やhashを架空化しない。
			if( !GetFileInformationByHandleEx( handle, FileAttributeTagInfo, &attributes,
											 sizeof( attributes))) {
				return HRESULT_FROM_WIN32( GetLastError()) ;
			}

			// 途中のreparse応答を通常fileへ読み替えさせない。
			if( changedAttributes && fault == Fault::ATTRIBUTES_REPARSE) {
				attributes.FileAttributes |= FILE_ATTRIBUTE_REPARSE_POINT ;
			}

			// 途中の種類変更を別fileとして採用させない。
			if( changedAttributes && fault == Fault::ATTRIBUTES_TYPE) {
				attributes.FileAttributes ^= FILE_ATTRIBUTE_DIRECTORY ;
			}

			return 0 ;
		} ;
	}

	/** @brief 一架空fileを新規作成し実hashを固定する。
	 * @param[in] name 所有領域内のASCII相対位置。
	 * @param[in] bytes 架空の原byte。
	 * @return 実byte／sizeに結合したmember。
	 * @throws std::runtime_error 作成・書込み・hash失敗。
	 */
	InfDependencyPackageMember file( const std::wstring &name, std::string_view bytes)
	{
		HANDLE handle = INVALID_HANDLE_VALUE ;	// この関数だけで取得し閉じる所有handle。
		// 作成失敗後は書込みへ進まない。
		if( workspace.createFile( name, handle) != 0) {
			throw std::runtime_error( "fixture create") ;
		}

		DWORD	   written{} ;	// 実byte数。
		const bool success = WriteFile( handle, bytes.data(), static_cast<DWORD>( bytes.size()),
									   &written, nullptr) != FALSE ;	// 元成功値。
		CloseHandle( handle) ;
		// 短縮writeを正常fixtureとみなさない。
		if( !success || written != bytes.size()) {
			throw std::runtime_error( "fixture write") ;
		}

		InfDependencyPackageMember result{name, {}, bytes.size()} ;	// 期待する実byte。
		// CNGで実fileを結合し、hashだけの架空成功を使わない。
		if( computeFileSha256( workspace.path( name), result.sha256) != 0) {
			throw std::runtime_error( "fixture hash") ;
		}

		return result ;
	}

	/** @brief 開始／終了の架空OS応答を生成する。
	 * @param[out] version 未知product typeも含む元応答。
	 * @param[out] native native architectureの元応答。
	 * @return API成功0、注入した診断値。
	 */
	NativeError versionInfo( OSVERSIONINFOEXW &version, SYSTEM_INFO &native)
	{
		++versionCalls ;
		// 開始と終了の失敗を区別して再現する。
		if( (fault == Fault::VERSION_START && versionCalls == 1U) ||
		   (fault == Fault::VERSION_END && versionCalls == 2U)) {
			return E_ACCESSDENIED ;
		}

		// 終了callback例外でもslotを解除させる。
		if( fault == Fault::VERSION_THROW && versionCalls == 2U) {
			throw std::runtime_error( "synthetic version") ;
		}

		version.dwMajorVersion		  = 10U ;
		version.dwMinorVersion		  = 0U ;
		version.dwBuildNumber		  = build ;
		version.wProductType		  = VER_NT_WORKSTATION ;
		native.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64 ;
		// 全version fieldを一つずつ変更して終了一致を検査する。
		if( fault == Fault::MAJOR_CHANGED && versionCalls == 2U) {
			++version.dwMajorVersion ;
		}

		// minor差も同じOSと推測しない。
		if( fault == Fault::MINOR_CHANGED && versionCalls == 2U) {
			++version.dwMinorVersion ;
		}

		// build差で監視PCの旧観測を転用しない。
		if( fault == Fault::BUILD_CHANGED && versionCalls == 2U) {
			++version.dwBuildNumber ;
		}

		// client／Server差を同じ文脈へまとめない。
		if( fault == Fault::PRODUCT_CHANGED && versionCalls == 2U) {
			version.wProductType = VER_NT_SERVER ;
		}

		// 未知product typeのclient推測を拒否させる。
		if( fault == Fault::PRODUCT_UNKNOWN) {
			version.wProductType = 0U ;
		}

		// native x86をx64として採用させない。
		if( fault == Fault::ARCHITECTURE) {
			native.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL ;
		}

		// 不明buildを有効なOS文脈にしない。
		if( fault == Fault::BUILD_ZERO) {
			version.dwBuildNumber = 0U ;
		}

		// 不明majorを有効なOS文脈にしない。
		if( fault == Fault::MAJOR_ZERO) {
			version.dwMajorVersion = 0U ;
		}

		return 0 ;
	}

	/** @brief 架空署名応答と保持中fileのwriter／再入を再現する。
	 * @param[in] path 固定した原INF位置。
	 * @param[out] signer 有限の架空応答。
	 * @return 成功0、注入した診断値。
	 */
	NativeError signature( const std::wstring &path, SP_INF_SIGNER_INFO_W &signer)
	{
		++allSignatureCalls ;
		const bool system =
			// 位置だけの架空境界。
			path == workspace.path( L"windows\\INF\\peer.inf") ;
		// 初回rootの署名失敗でも資料観測を消させない。
		if( !system && fault == Fault::ROOT_SIGNATURE) {
			return E_ACCESSDENIED ;
		}

		// system署名の開始／終了を独立に数える。
		if( system) {
			++signatureCalls ;
			changedAttributes = true ;
			// 初回不足と終了失効の元診断を保持する。
			if( (fault == Fault::SIGNATURE_START && signatureCalls == 1U) ||
			   (fault == Fault::SIGNATURE_END && signatureCalls == 2U)) {
				return E_ACCESSDENIED ;
			}

			// callback例外をWin32境界の外へ漏らさない。
			if( fault == Fault::SIGNATURE_THROW) {
				throw std::runtime_error( "synthetic signature") ;
			}
		}

		const std::wstring catalog =
			system ? workspace.path( L"windows\\System32\\CatRoot\\fixture.cat")
				   : workspace.path( L"fixture.cat") ;	// 架空CAT。
		// path容量を暗黙切詰めしない。
		if( catalog.size() >= MAX_PATH) {
			throw std::runtime_error( "fixture path length") ;
		}

		std::ranges::copy( catalog, signer.CatalogFile) ;
		signer.CatalogFile[catalog.size()] = L'\0' ;
		signer.DigitalSigner[0]			   = L'x' ;
		signer.DigitalSigner[1]			   = L'\0' ;
		signer.SignerScore				   = SIGNERSCORE_INBOX ;
		// WHQLとINBOXの共通mask値を由来の根拠へ使わせない。
		if( system && (fault == Fault::WHQL_SCORE ||
					  (fault == Fault::SCORE_CHANGED && signatureCalls == 2U))) {
			signer.SignerScore = SIGNERSCORE_WHQL ;
		}

		// 初回の無関係CATを許可範囲外へ返す。
		if( system && fault == Fault::CAT_OUTSIDE) {
			std::ranges::copy( L"C:\\synthetic.cat", signer.CatalogFile) ;
		}

		// 終了時CATの変更を開始成功で補完しない。
		if( system && fault == Fault::CAT_CHANGED && signatureCalls == 2U) {
			signer.CatalogFile[3] = signer.CatalogFile[3] == L'a' ? L'b' : L'a' ;
		}

		// 初回の空signerを成功署名として採用しない。
		if( system && fault == Fault::SIGNER_EMPTY) {
			signer.DigitalSigner[0] = L'\0' ;
		}

		// 有限応答の終端欠損を拒否させる。
		if( system && fault == Fault::CAT_UNTERMINATED) {
			std::ranges::fill( signer.CatalogFile, L'x') ;
		}

		// 終了signer不足は全体拒否にする。
		if( system && fault == Fault::SIGNER_END_EMPTY && signatureCalls == 2U) {
			signer.DigitalSigner[0] = L'\0' ;
		}

		// 実INF handle保持中は別writerが開けないことを確認する。
		if( !system && fault == Fault::WRITER) {
			const HANDLE writer =
				CreateFileW( path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
							nullptr, OPEN_EXISTING, 0U, nullptr) ;	// 書込み自体は行わない。
			writerError = writer == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS ;
			// 万一開けた場合も閉じて元byteを変更しない。
			if( writer != INVALID_HANDLE_VALUE) {
				CloseHandle( writer) ;
			}
		}

		// 同じthreadのtest APIを再入で差し替えさせない。
		if( !system && fault == Fault::REENTRY) {
			InfDependencyNativeResult		   nested ;				// 再入拒否結果だけ。
			const std::array<std::wstring, 1U> seeds{L"Install"} ;	// 架空seed。
			reentryError =
				inspectInfDependenciesWithTestApi( api, workspace, members, 0U, seeds, 2U, nested) ;
		}

		return 0 ;
	}

	/** @brief 同期fixtureを一回だけ実行する。
	 * @param[out] result 全成功時の架空観測。
	 * @return adapterの元診断値。
	 */
	NativeError run( InfDependencyNativeResult &result)
	{
		const std::array<std::wstring, 1U> seeds{L"Install"} ;	// 一つの明示節。
		return inspectInfDependenciesWithTestApi( api, workspace, members, 0U, seeds, 100U, result) ;
	}
} ;

/** @brief 拒否・独立証拠・非実行計画とRAII解除を検査する。
 * @param[in,out] context このprocessのassertion集計。
 */
void matrix( TestContext &context)
{
	// 一種類の障害ごとに新しい実fileとAPI状態を所有する。
	for( const auto &scenario : SCENARIOS) {
		Fixture					  fixture( scenario.fault) ;		// 一runの同期所有者。
		InfDependencyNativeResult result ;							// 全成功時だけの結果。
		const auto				  error = fixture.run( result) ;	// 元API診断を保持する。
		// 原因を識別できる固定case番号と診断だけを出す。pathを出力しない。
		if( error != scenario.expectedError ||
		   (error == 0 && result.dependency.documents.size() != 2U)) {
			std::cerr << "Synthetic case " << static_cast<int>( scenario.fault) << ", error "
					  << error << ", documents " << result.dependency.documents.size() << '\n' ;
		}

		DRIVERCRATE_EXPECT( context, error == scenario.expectedError) ;
		// 全体拒否では古い部分graphを一つも返さない。
		if( error != 0) {
			DRIVERCRATE_EXPECT( context, result.dependency.documents.empty() &&
											result.dependency.sections.empty() &&
											result.dependency.edges.empty() &&
											result.dependency.plan.entries.empty() &&
											result.findings.empty()) ;
		} else {
			DRIVERCRATE_EXPECT( context, result.dependency.documents.size() == 2U &&
											result.dependency.edges.size() == 2U) ;
			DRIVERCRATE_EXPECT( context, result.findings.size() == 2U) ;
			// 不正なfixture応答を診断した後に存在しない要素を参照しない。
			if( result.dependency.documents.size() != 2U || result.dependency.edges.size() != 2U ||
			   result.findings.size() != 2U) {
				continue ;
			}

			DRIVERCRATE_EXPECT( context, result.dependency.documents[0].provenance ==
											InfDependencyEvidence::NOT_CHECKED) ;
			DRIVERCRATE_EXPECT( context, !result.dependency.plan.rootEvidenceVerified) ;
			DRIVERCRATE_EXPECT( context, result.dependency.plan.actionCoverage ==
												InfDependencyEvidence::NOT_CHECKED &&
											result.dependency.plan.deviceApplicability ==
												InfDependencyEvidence::NOT_CHECKED &&
											result.dependency.plan.installRoute ==
												InfDependencyEvidence::NOT_CHECKED) ;
			const bool signatureFailed = scenario.fault == Fault::SIGNATURE_START ||
										 scenario.fault == Fault::CAT_OUTSIDE ||
										 // 初回署名不足だけ。
										 scenario.fault == Fault::CAT_SIGNATURE_START ;
			const bool provenanceUnknown = signatureFailed || scenario.fault == Fault::WHQL_SCORE ||
										   // 由来の未確認。
										   scenario.fault == Fault::STORE_START ;
			const auto &system = result.dependency.documents[1] ;	// 架空system snapshot。
			DRIVERCRATE_EXPECT( context, system.signature ==
											(signatureFailed ? InfDependencyEvidence::FAILED
															 : InfDependencyEvidence::VERIFIED)) ;
			DRIVERCRATE_EXPECT( context,
							   system.provenance ==
								   (provenanceUnknown ? InfDependencyEvidence::NOT_CHECKED
													  : (scenario.fault == Fault::STORE_BYTES
															 ? InfDependencyEvidence::FAILED
															 : InfDependencyEvidence::VERIFIED))) ;
			// 未検査・不合格を存在なしや解決済みへ変換しない。
			for( const auto &edge : result.dependency.edges) {
				DRIVERCRATE_EXPECT( context,
								   edge.state ==
									   (provenanceUnknown || scenario.fault == Fault::STORE_BYTES
											? InfDependencyState::OBSERVED
											: InfDependencyState::RESOLVED_SYSTEM)) ;
			}

			DRIVERCRATE_EXPECT( context, fixture.memberBound) ;
			DRIVERCRATE_EXPECT( context, result.findings[1].signatureError ==
											(signatureFailed ? E_ACCESSDENIED : 0)) ;
			DRIVERCRATE_EXPECT( context, result.findings[1].provenanceError ==
											(scenario.fault == Fault::STORE_START
												 ? HRESULT_FROM_WIN32( ERROR_NOT_FOUND)
												 : (scenario.fault == Fault::STORE_BYTES
														? HRESULT_FROM_WIN32( ERROR_FILE_INVALID)
														: 0))) ;
			DRIVERCRATE_EXPECT( context, result.dependency.context.build == fixture.build &&
											result.dependency.context.observationId == 100U &&
											result.dependency.context.machine == 0x8664U) ;
		}

		// 初回署名不合格を終了時の再照会で昇格させない。
		if( scenario.fault == Fault::SIGNATURE_START) {
			DRIVERCRATE_EXPECT( context, fixture.signatureCalls == 1U) ;
		}

		// 初回CAT不合格を終了時の再照会で昇格させない。
		if( scenario.fault == Fault::CAT_SIGNATURE_START) {
			DRIVERCRATE_EXPECT( context, fixture.catalogCalls == 1U) ;
		}

		// 初回Store未確認を終了時の取得成功で昇格させない。
		if( scenario.fault == Fault::STORE_START) {
			DRIVERCRATE_EXPECT( context, fixture.storeCalls == 1U) ;
		}

		// 完全scoreがinboxでない場合は対応Store証拠を作らない。
		if( scenario.fault == Fault::WHQL_SCORE) {
			DRIVERCRATE_EXPECT( context, fixture.storeCalls == 0U) ;
		}

		// byte不一致は上位API照会より前に止まる。
		if( scenario.fault == Fault::HASH_CHANGED) {
			DRIVERCRATE_EXPECT( context, fixture.allSignatureCalls == 0U) ;
		}

		// 元writer診断を成功扱いで消さない。
		if( scenario.fault == Fault::WRITER) {
			DRIVERCRATE_EXPECT( context, fixture.writerError == ERROR_SHARING_VIOLATION) ;
		}

		// 再入拒否の元診断を確認する。
		if( scenario.fault == Fault::REENTRY) {
			DRIVERCRATE_EXPECT( context, fixture.reentryError == E_INVALIDARG) ;
		}

		Fixture					  subsequent( Fault::NONE) ;	// 例外・拒否後の新しいAPI集合。
		InfDependencyNativeResult clean ;						// 古いslotを借用しない次run。
		DRIVERCRATE_EXPECT( context,
						   subsequent.run( clean) == 0 && clean.dependency.documents.size() == 2U) ;
	}

	Fixture fixture( Fault::NONE) ;	// 必須集合の欠損だけを試す。
	// 五つの必須APIが一つでもない場合に実APIへfallbackしない。
	for( std::size_t missing = 0U; missing < 5U; ++missing) {
		auto incomplete = fixture.api ;	// 一項目だけを落とす固定集合。
		// OS queryを欠落させる。
		if( missing == 0U) {
			incomplete.version = {} ;
		}

		// 起点queryを欠落させる。
		if( missing == 1U) {
			incomplete.windowsDirectory = {} ;
		}

		// INF signatureを欠落させる。
		if( missing == 2U) {
			incomplete.infSignature = {} ;
		}

		// CAT signatureを欠落させる。
		if( missing == 3U) {
			incomplete.catalogSignature = {} ;
		}

		// Store queryを欠落させる。
		if( missing == 4U) {
			incomplete.driverStore = {} ;
		}

		InfDependencyNativeResult		   result ;				// 拒否で空になる出力。
		const std::array<std::wstring, 1U> seeds{L"Install"} ;	// 架空の一節。
		DRIVERCRATE_EXPECT( context, inspectInfDependenciesWithTestApi(
										incomplete, fixture.workspace, fixture.members, 0U, seeds,
										100U, result) == E_INVALIDARG) ;
		DRIVERCRATE_EXPECT( context,
						   result.dependency.documents.empty() && fixture.versionCalls == 0U) ;
	}

	std::array<std::future<bool>, 2U> runs ;	// 二threadの独立fixture結果を所有する。
	// thread-local slotを別threadへ転用しないことを確認する。
	for( std::size_t index = 0U; index < runs.size(); ++index) {
		runs[index] = std::async( std::launch::async, [index] {
			Fixture parallel( Fault::NONE) ;	// このthreadだけで所有する同期capture。
			parallel.build += static_cast<DWORD>( index) ;
			InfDependencyNativeResult result ;	// このthreadだけの出力。
			return parallel.run( result) == 0 && result.dependency.context.build == parallel.build ;
		}) ;
	}

	// 全thread完了後に集計し、共有assertion stateを同時更新しない。
	for( auto &run : runs) {
		DRIVERCRATE_EXPECT( context, run.get()) ;
	}
}

/**
 * @brief 同節Services・明示Needs名と未採用参照節の分離を実readerで確認する。
 * @param[in,out] context 一processの有限assertion集計。
 * @note OS／INF署名／CAT／Store応答は既存のfake境界だけを使用する。
 *       実hash・節読取は実APIで、fake成功を全payload署名や端末導入能力へ昇格しない。
 */
void referenceSelection( TestContext &context)
{
	// 同節正例・Include借用拒否・三suffix不一致・Includeだけの未採用節を全て確認する。
	for( std::size_t scenario = 0U; scenario < 6U; ++scenario) {
		const std::string rootBody =
			"[Install]\r\nInclude=peer.inf\r\n" +
			std::string( scenario == 5U ? "" : "Needs=Shared\r\n") +
			std::string( scenario <= 1U
							? "[Install.Services]\r\n" +
								  std::string( scenario == 0U ? "Include=peer.inf\r\n" : "") +
								  "Needs=Shared.Services\r\n"
							: "") ;	// 元節自身のInclude集合だけを与える。
		const std::string_view systemSection =
			scenario == 2U
				? "Shared.NT"
				: (scenario == 3U
					   ? "Shared.Services"
					   : (scenario == 4U ? "Shared.NTarm64" : "Shared")) ;	// 参照先の原節名。
		const std::string_view payloadBody =
			scenario <= 1U
				? "[Shared.Services]\r\n"
				: (scenario >= 4U ? "CopyFiles=@unselected.sys\r\n" : "") ;		// 実payloadは作らない。
		Fixture fixture( Fault::NONE, payloadBody, rootBody, systemSection) ;	// 同runの同期所有者。
		std::vector<std::wstring> seeds{L"Install"} ;							// 明示された元節だけを選ぶ。
		// Services正例と借用拒否だけを独立seedとして明示する。
		if( scenario <= 1U) {
			seeds.push_back( L"Install.Services") ;
		}

		InfDependencyNativeResult result ;	// 全成功時だけの独立したgraphと用途観測。
		const NativeError		  error = inspectInfDependenciesWithTestApi(
			fixture.api, fixture.workspace, fixture.members, 0U, seeds, 200U + scenario,
			result) ;	// 架空APIを同期借用。
		DRIVERCRATE_EXPECT( context, error == 0) ;
		DRIVERCRATE_EXPECT( context, result.dependency.documents.size() == 2U &&
										result.findings.size() == 2U) ;
		// fixture拒否や不完全な配列を報告した後に部分値を参照しない。
		if( error != 0 || result.dependency.documents.size() != 2U || result.findings.size() != 2U) {
			continue ;
		}

		DRIVERCRATE_EXPECT( context, result.dependency.documents.front().origin ==
											InfDependencyOrigin::PACKAGE &&
										result.dependency.documents.front().provenance ==
											InfDependencyEvidence::NOT_CHECKED &&
										!result.dependency.plan.rootEvidenceVerified) ;
		DRIVERCRATE_EXPECT(
			context,
			result.dependency.documents.back().origin == InfDependencyOrigin::SYSTEM &&
				result.dependency.documents.back().byteBinding == InfDependencyEvidence::VERIFIED &&
				result.dependency.documents.back().provenance == InfDependencyEvidence::VERIFIED &&
				result.dependency.documents.back().signature == InfDependencyEvidence::VERIFIED) ;
		DRIVERCRATE_EXPECT(
			context,
			result.dependency.plan.actionCoverage == InfDependencyEvidence::NOT_CHECKED &&
				result.dependency.plan.deviceApplicability == InfDependencyEvidence::NOT_CHECKED &&
				result.dependency.plan.installRoute == InfDependencyEvidence::NOT_CHECKED) ;
		DRIVERCRATE_EXPECT( context, result.dependency.plan.referencesResolved ==
										(scenario == 0U || scenario == 5U)) ;
		DRIVERCRATE_EXPECT(
			context,
			result.dependency.edges.size() ==
				(scenario == 0U ? 4U : (scenario == 1U ? 3U : (scenario == 5U ? 1U : 2U)))) ;
		DRIVERCRATE_EXPECT( context, fixture.memberBound && result.fixedFileCount == 5U &&
										result.fixedByteCount > 0U &&
										result.dependency.context.machine == 0x8664U &&
										result.dependency.context.observationId == 200U + scenario) ;

		// 同節二形は元ServicesのNeedsを独立した辺として比較する。
		if( scenario <= 1U) {
			const auto services =
				std::ranges::find_if( result.dependency.edges, []( const auto &edge) {
					return edge.sourceIdentity == 1U && edge.sourceSection == L"Install.Services" &&
						   edge.directive == InfDependencyDirective::NEEDS &&
						   edge.target == L"Shared.Services" ;
				}) ; // このgraphだけを借用し、base辺を代用しない。
			DRIVERCRATE_EXPECT( context, services != result.dependency.edges.end()) ;
			// 対象辺が得られた場合だけ一意性・存在・同節の結果を照合する。
			if( services != result.dependency.edges.end()) {
				DRIVERCRATE_EXPECT( context,
								   services->state == (scenario == 0U
														   ? InfDependencyState::RESOLVED_SYSTEM
														   : InfDependencyState::UNRESOLVED)) ;
				DRIVERCRATE_EXPECT( context, services->reason ==
												(scenario == 0U ? InfDependencyReason::NONE
																: InfDependencyReason::MISSING)) ;
				DRIVERCRATE_EXPECT( context,
								   services->targetIdentity == (scenario == 0U ? 2U : 0U) &&
									   services->candidateCount == (scenario == 0U ? 1U : 0U)) ;
			}
		}

		// 現OSの署名済み資料が存在しても、明示Needs名を装飾／Services名へ補完しない。
		if( scenario >= 2U && scenario <= 4U) {
			DRIVERCRATE_EXPECT( context,
							   std::ranges::any_of( result.dependency.edges, []( const auto &edge) {
								   return edge.sourceSection == L"Install" &&
										  edge.directive == InfDependencyDirective::NEEDS &&
										  edge.target == L"Shared" &&
										  edge.state == InfDependencyState::UNRESOLVED &&
										  edge.reason == InfDependencyReason::MISSING &&
										  edge.targetIdentity == 0U && edge.candidateCount == 0U ;
							   })) ; // 不一致を署名FAILEDやdevice不適合へ変換しない。
		}

		// 選ばれないARM64節とIncludeだけのShared節を必要payloadへ混同しない。
		if( scenario >= 4U) {
			DRIVERCRATE_EXPECT( context, std::ranges::none_of( result.fileUses, []( const auto &use) {
								   return use.target == L"unselected.sys" ||
										  use.directive == L"CopyFiles" ||
										  use.section == L"Shared.NTarm64" ;
							   })) ; // Version用途は独立観測として保持でき、全payload合格ではない。
		}
	}
}

/** @brief Mount-point reparse bufferの公式byte layout。所有領域内だけで使用する。 */
struct JunctionData {
	/// IO_REPARSE_TAG_MOUNT_POINTの固定tag。
	DWORD									 tag{IO_REPARSE_TAG_MOUNT_POINT} ;
	/// 後続のWORD offset群とpath byte数。
	WORD									 length{} ;
	/// APIで予約される零field。
	WORD									 reserved{} ;
	/// pathBuffer先頭からのNT代替名byte offset。
	WORD									 substituteOffset{} ;
	/// 終端を除くNT代替名byte数。
	WORD									 substituteLength{} ;
	/// 表示名先頭までのpathBuffer内byte offset。
	WORD									 printOffset{} ;
	/// 終端を除く表示名byte数。
	WORD									 printLength{} ;
	/// 有限なNT名と表示名。両方に終端を置く。
	std::array<wchar_t, 2U * MAX_PATH + 10U> paths{} ;
} ;
// APIの固定headerとoffset群。
static_assert( offsetof( JunctionData, paths) == 16U) ;

/** @brief 所有領域内だけの実junctionを作成・拒否確認・tag解除する。
 * @param[in,out] context 実path拒否を別に集計する。
 * @note OS領域は変更しない。参照先も同じ架空領域内で、driverを導入しない。
 */
void junction( TestContext &context)
{
	Fixture fixture( Fault::NONE) ;	// 署名／OSは架空で、fileとreparseは実物。
	DRIVERCRATE_EXPECT( context, fixture.workspace.discardFile( L"windows\\INF\\peer.inf") == 0) ;
	const std::wstring directory =
		// 空の追跡済みdirectory。
		fixture.workspace.path( L"windows\\INF") ;
	const std::wstring target = fixture.workspace.path(
		L"windows\\System32\\DriverStore\\FileRepository\\fixture") ;			// 同領域内。
	const std::wstring substitute = L"\\??\\" + target ;						// mount pointのNT形式。
	JunctionData	   data ;													// 全byteを零初期化するAPI入力。
	const std::size_t  characters = substitute.size() + target.size() + 2U ;	// 終端二つを含む容量。
	// 固定bufferの容量を越えるfixtureを暗黙切詰めしない。
	if( characters > data.paths.size()) {
		throw std::runtime_error( "junction fixture capacity") ;
	}

	data.substituteLength = static_cast<WORD>( substitute.size() * sizeof( wchar_t)) ;
	data.printOffset	  = static_cast<WORD>( (substitute.size() + 1U) * sizeof( wchar_t)) ;
	data.printLength	  = static_cast<WORD>( target.size() * sizeof( wchar_t)) ;
	data.length			  = static_cast<WORD>( 8U + characters * sizeof( wchar_t)) ;
	std::ranges::copy( substitute, data.paths.begin()) ;
	std::ranges::copy( target, data.paths.begin() + substitute.size() + 1U) ;
	const HANDLE handle = CreateFileW(
		directory.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
		nullptr) ;	// 空の所有directoryだけ。
	DRIVERCRATE_EXPECT( context, handle != INVALID_HANDLE_VALUE) ;
	// 開けないfixtureを成功やskipとして扱わない。
	if( handle == INVALID_HANDLE_VALUE) {
		return ;
	}

	DWORD	   returned{} ;	// DeviceIoControlの元返却byte数。
	const bool created = DeviceIoControl( handle, FSCTL_SET_REPARSE_POINT, &data,
										 static_cast<DWORD>( 8U + data.length), nullptr, 0U,
										 &returned, nullptr) != FALSE ;	// tag設定の元成功値。
	DRIVERCRATE_EXPECT( context, created) ;
	// 設定失敗ではhandleを閉じ、通常directoryを保持する。
	if( !created) {
		CloseHandle( handle) ;
		return ;
	}

	InfDependencyNativeResult result ;							// reparse拒否後は空の結果。
	const auto				  error = fixture.run( result) ;	// Windows設定・署名policyは変更しない。
	JunctionData			  removal ;							// 同じtagを同じ所有handleから除去する有限header。
	const bool				  removed =
		DeviceIoControl( handle, FSCTL_DELETE_REPARSE_POINT, &removal, 8U, nullptr, 0U, &returned,
						nullptr) != FALSE ;	// 参照先fileは削除しない。
	CloseHandle( handle) ;
	DRIVERCRATE_EXPECT( context, removed) ;
	DRIVERCRATE_EXPECT( context, error == E_ACCESSDENIED) ;
	DRIVERCRATE_EXPECT( context, result.dependency.documents.empty() && result.findings.empty()) ;
	DRIVERCRATE_EXPECT( context, fixture.signatureCalls == 0U) ;
}
/**
 * @brief INF自身のfake署名とSYSTEM payload未検証を独立に保持する。
 * @param[in,out] context 一processの有限assertion集計。
 * @note fakeの署名成功は実Windows署名の測定ではなく、payloadも取得・複写しない。
 */
void payloadObservation( TestContext &context)
{
	constexpr std::array FAULTS{Fault::NONE, Fault::STORE_START,
								Fault::SIGNATURE_START} ;	// 独立証拠三状態。
	// sourceなしinbox構造・由来未確認・署名FAILEDを別runで観測する。
	for( const auto fault : FAULTS) {
		Fixture fixture(
			fault,
			"CopyFiles=@fixture-payload.sys\r\nServiceBinary=%12%\\fixture-payload.sys\r\n"
			"AddReg=Registry\r\nUnknownFileUse=mystery.dll\r\n"
			"[Shared.NTx86]\r\nCopyFiles=@other-os.sys\r\n") ;	// source節と実payloadなしの明示用途。
		InfDependencyNativeResult result ;						// 全体成功時の原graphと用途だけ。
		DRIVERCRATE_EXPECT( context, fixture.run( result) == 0) ;
		DRIVERCRATE_EXPECT( context, result.dependency.documents.size() == 2U &&
										result.dependency.edges.size() == 2U) ;
		DRIVERCRATE_EXPECT( context, result.dependency.documents.at( 0U).provenance ==
										InfDependencyEvidence::NOT_CHECKED) ;
		DRIVERCRATE_EXPECT(
			context,
			result.dependency.plan.actionCoverage == InfDependencyEvidence::NOT_CHECKED &&
				result.dependency.plan.deviceApplicability == InfDependencyEvidence::NOT_CHECKED &&
				result.dependency.plan.installRoute == InfDependencyEvidence::NOT_CHECKED) ;
		DRIVERCRATE_EXPECT( context, std::ranges::any_of( result.fileUses, []( const auto &use) {
							   return use.identity == 2U && use.section == L"Version" &&
									  use.directive == L"LayoutFile" &&
									  use.target == L"fixture-layout.inf" ;
						   })) ;
		DRIVERCRATE_EXPECT( context, std::ranges::any_of( result.fileUses, []( const auto &use) {
							   return use.identity == 2U && use.section == L"Shared" &&
									  use.directive == L"ServiceBinary" && !use.target.empty() ;
						   })) ;
		DRIVERCRATE_EXPECT( context, std::ranges::any_of( result.fileUses, []( const auto &use) {
							   return use.identity == 2U && use.section == L"Shared" &&
									  use.directive == L"UnknownFileUse" &&
									  use.target == L"mystery.dll" ;
						   })) ;
		DRIVERCRATE_EXPECT( context, std::ranges::none_of( result.fileUses, []( const auto &use) {
							   return use.target == L"other-os.sys" ||
									  use.section == L"Shared.NTx86" ;
						   })) ;
		DRIVERCRATE_EXPECT(
			context,
			result.fixedFileCount ==
					(fault == Fault::NONE ? 5U : (fault == Fault::STORE_START ? 4U : 3U)) &&
				result.fixedByteCount > 0U) ;
		// 署名不合格を根拠未検査で上書きせず、元findingを保持する。
		if( fault == Fault::SIGNATURE_START) {
			DRIVERCRATE_EXPECT( context, result.dependency.documents.at( 1U).signature ==
											InfDependencyEvidence::FAILED) ;
			DRIVERCRATE_EXPECT( context, result.findings.at( 1U).signatureError == E_ACCESSDENIED &&
											!result.dependency.plan.referencesResolved) ;
		} else {
			DRIVERCRATE_EXPECT( context, result.dependency.documents.at( 1U).signature ==
											InfDependencyEvidence::VERIFIED) ;
			DRIVERCRATE_EXPECT( context,
							   result.dependency.documents.at( 1U).provenance ==
								   (fault == Fault::NONE ? InfDependencyEvidence::VERIFIED
														 : InfDependencyEvidence::NOT_CHECKED)) ;
			DRIVERCRATE_EXPECT( context,
							   result.dependency.plan.referencesResolved == (fault == Fault::NONE)) ;
		}
	}
}
/** @brief NeedsのHKR設定を正負の実INFと有限予算で検査します。
 * @param[in,out] context 同一processの集計です。
 */
void needsRegistry( TestContext &context)
{
	InfDependencyNativeResult graph ;	// 架空identityだけの文脈伝播graphです。
	graph.dependency.sections = {{1U, L"Install", InfDependencyReadState::PRESENT},
								 {1U, L"Install.HW", InfDependencyReadState::PRESENT},
								 {1U, L"Install.Services", InfDependencyReadState::PRESENT},
								 {2U, L"Shared", InfDependencyReadState::PRESENT},
								 {3U, L"Shared", InfDependencyReadState::PRESENT}} ;
	graph.dependency.edges	  = {{1U, L"Install", L"Shared", InfDependencyDirective::NEEDS,
								  InfDependencyState::RESOLVED_SYSTEM, InfDependencyReason::NONE, 2U,
								  1U}} ;
	const std::array<std::wstring, 3U> seeds{L"Install", L"Install.HW",
											 L"Install.Services"} ;	// 同rootだけです。
	const auto						   initial =
		// identityが違う同名節は除きます。
		inspectNeedsRegistryContextsForTest( graph, seeds, 1U) ;
	DRIVERCRATE_EXPECT( context, (initial == std::vector<unsigned char>{1U, 2U, 4U, 1U, 0U})) ;
	graph.dependency.edges.push_back( {1U, L"Install.HW", L"Shared", InfDependencyDirective::NEEDS,
									  InfDependencyState::RESOLVED_SYSTEM,
									  InfDependencyReason::NONE, 2U, 1U}) ;
	const auto shared =
		// 両device文脈を保持します。
		inspectNeedsRegistryContextsForTest( graph, seeds, 1U) ;
	DRIVERCRATE_EXPECT( context, shared[3U] == 3U && shared[4U] == 0U) ;
	graph.dependency.edges.push_back(
		{1U, L"Install.Services", L"Shared", InfDependencyDirective::NEEDS,
		 InfDependencyState::RESOLVED_SYSTEM, InfDependencyReason::NONE, 2U, 1U}) ;
	const auto mixed =
		// Servicesの拒否bitを消しません。
		inspectNeedsRegistryContextsForTest( graph, seeds, 1U) ;
	DRIVERCRATE_EXPECT( context, mixed[3U] == 7U) ;
	const auto wrongRoot =
		// 別rootから権限を作りません。
		inspectNeedsRegistryContextsForTest( graph, seeds, 9U) ;
	DRIVERCRATE_EXPECT(
		context, std::ranges::all_of( wrongRoot, []( const auto value) { return value == 0U ; })) ;
	const auto missingSeeds =
		// 空選択を基本節へ補完しません。
		inspectNeedsRegistryContextsForTest( graph, {}, 1U) ;
	DRIVERCRATE_EXPECT(
		context, std::ranges::all_of( missingSeeds, []( const auto value) { return value == 0U ; })) ;
	const std::array<std::string, 3U> malformed{
		"[Install]\r\nAddReg=Absent\r\n[Other]\r\nHKR,,Setting,0,text\r\n",
		"[Install]\r\nAddReg=Settings\r\n[Other]\r\nHKR,,Setting,0,text\r\n",
		"[Install]\r\nAddReg=" + std::string( 65U * 9U, 'x') +
			"\r\n"} ;	// 欠損/別節/長さの原拒否です。
	// 正常行が別節にあっても欠損した正確な参照先の代わりにしません。
	for( const auto &body : malformed) {
		Fixture		fixture( Fault::NONE, {}, body) ;	// この条件だけの閉じた架空INFです。
		std::size_t rows{} ;							// 参照拒否前に成功行を付与しません。
		DRIVERCRATE_EXPECT( context, inspectNeedsAddRegForTest( fixture.workspace.path( L"root.inf"),
															  1U, rows) != 0U) ;
		DRIVERCRATE_EXPECT( context, rows == 0U) ;
	}

	/** @brief 正負一条件の原宣言と元文脈を固定します。 */
	struct Case {
		/// 元Settingsの全行と追加節です。
		std::string	  rows ;
		/// 同選択からの文脈bitです。
		unsigned char contexts ;
		/// 処理前の累積行数です。
		std::size_t	  before ;
		/// 元全宣言の期待可否です。
		bool		  accepted ;
	} ;
	const std::vector<Case> cases{
		{"HKR,,Setting,,text\r\n", 1U, 0U, true},
		{"HKR,Ndi\\Params,Setting,0,ordinary\r\n", 2U, 0U, true},
		{"hkr,,Setting,0x00010001,42\r\n", 3U, 0U, true},
		{"HKR,,Setting,0x00020000,\"%SystemRoot%\\settings\"\r\n", 1U, 0U, true},
		{"HKR,,First,0,one\r\nHKR,,Second,0x00010001,2\r\n", 1U, 0U, true},
		{"HKR,,Setting,0,text\r\n", 1U, 4095U, true},
		{"HKLM,,Setting,0,text\r\n", 1U, 0U, false},
		{"HKR,,Setting,0x4,text\r\n", 1U, 0U, false},
		{"HKR,,Setting,0x00010001,not-a-number\r\n", 1U, 0U, false},
		{"HKR,,Setting,0,text\r\n[Settings.security]\r\n\"D:P\"\r\n", 1U, 0U, false},
		{"HKR,,Setting,0,text\r\n", 0U, 0U, false},
		{"HKR,,Setting,0,text\r\n", 5U, 0U, false},
		{"HKR,\"..\\Escape\",Setting,0,text\r\n", 1U, 0U, false},
		{"HKR,\"\\Absolute\",Setting,0,text\r\n", 1U, 0U, false},
		{"HKR,,UpperFilters,0,text\r\n", 1U, 0U, false},
		{"HKR,,Setting,0,program.exe\r\n", 1U, 0U, false},
		{"HKR,,Setting,0," + std::string( 255U, 'x') + "\r\n", 1U, 0U, false},
		{"HKR,,First,0,one\r\nHKLM,,Second,0,two\r\n", 1U, 0U, false},
		{"HKR,,Setting,0,text\r\n", 1U, 4096U, false},
		{"HKR,,Setting,0,text,extra\r\n", 1U, 0U, false}} ;	// 元型と後続行拒否を独立にします。
	// 一条件一元INFで全行を読み、元予算を成功後の値へ書き換えません。
	for( const auto &testCase : cases) {
		const std::string body = "[Install]\r\nAddReg=Settings\r\n[Settings]\r\n" +
								 testCase.rows ;		// 架空の到達先だけです。
		Fixture	   fixture( Fault::NONE, {}, body) ;	// 署名fakeをparser成功の証拠へ使いません。
		auto	   rows = testCase.before ;				// 呼出し前の有限予算です。
		// 全field/全行の元parser診断を一条件へ結合します。
		const auto error =
			inspectNeedsAddRegForTest( fixture.workspace.path( L"root.inf"), testCase.contexts, rows) ;
		DRIVERCRATE_EXPECT( context, (error == 0U) == testCase.accepted) ;
		// 全成功では一行以上が検査され、累積上限を守る必要があります。
		if( testCase.accepted && error == 0U) {
			DRIVERCRATE_EXPECT( context, rows > testCase.before && rows <= 4096U) ;
		}
	}
}
} // namespace
} // namespace drivercrate::test

/** @brief 非通信の架空API matrixだけを実行し件数を表示する。
 * @return 全成功0、assertion・fixture例外の失敗1。
 */
int main()
{
	drivercrate::test::TestContext context ;	// 一processの有限集計。
	try {
		drivercrate::test::matrix( context) ;
		drivercrate::test::referenceSelection( context) ;
		drivercrate::test::junction( context) ;
		drivercrate::test::payloadObservation( context) ;
		drivercrate::test::needsRegistry( context) ;
		drivercrate::test::runOfficialServiceOutputContractTests( context) ;
	} catch( ...) {
		std::cerr << "Synthetic native API fixture failed.\n" ;
		return 1 ;
	}

	std::cout
		<< "API scenarios: 46, selection cases: 6, junction cases: 1, payload cases: 3, service cases: 8, registry cases: 23, context cases: 5, Assertions: "
		<< context.assertionCount() << ", failures: " << context.failureCount() << '\n' ;
	return context.failureCount() == 0 ? 0 : 1 ;
}
