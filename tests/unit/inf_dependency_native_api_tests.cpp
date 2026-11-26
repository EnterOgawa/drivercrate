//------------------------------------------------------------------------------
/**
 * @file inf_dependency_native_api_tests.cpp
 * @brief 架空OS・署名・Storeと実fileでnative障害を再現する専用試験
 * @version 01.25.00
 * @date 2026/10/06
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/10/07  sourceなしinbox観測と全payload非検証・FAILED保持を追加
 * Ver.01.02.00 Shunji Ogawa  2026/10/07  同節Services・明示Needs名と未採用payload節の分離を回帰
 * Ver.01.03.00 Shunji Ogawa  2026/10/13  サービス集合の正常・途中失敗契約八条件を接続
 * Ver.01.04.00 Shunji Ogawa  2026/10/15  NeedsのHKR全行と型・設置文脈の正負回帰を追加
 * Ver.01.04.01 Shunji Ogawa  2026/10/24 実openのfile／path不在と未解決保持を別条件で確認
 * Ver.01.04.02 Shunji Ogawa  2026/10/24  必須解析に合わせ試験の所有・型・失敗制御を明示
 * Ver.01.05.00 Shunji Ogawa  2026/11/08  正規選択Include文脈と同名Needs転送を有限接続
 * Ver.01.05.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.05.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.05.03 Shunji Ogawa  2026/11/13  Needs AddRegの元拒否leafを既匿名診断へ接続
 * Ver.01.05.04 Shunji Ogawa  2026/11/13  847kの検証済みSYSTEM媒体作用と限定資格を接続
 * Ver.01.05.05 Shunji Ogawa  2026/11/13  847p9の型付きSYSTEM全作用と全選択資格を接続
 * Ver.01.05.06 Shunji Ogawa  2026/11/20  同名stubを同期fixtureの再検証callbackへ移動
 * Ver.01.06.00 Shunji Ogawa  2026/11/20  収集が選択したSDバスの作用・元文書・余分な行の拒否を回帰
 * Ver.01.07.00 Shunji Ogawa  2026/11/20  標準Portsの選択・サービス・フィルター・イベント資源と各拒否を回帰
 * Ver.01.08.00 Shunji Ogawa  2026/11/20  標準NVMeとPCIの選択、起動サービス、電源値域と原全行を回帰
 * Ver.01.09.00 Shunji Ogawa  2026/11/21  標準AHCIの元除外・電源と共有登録作用を検証
 * Ver.01.10.00 Shunji Ogawa  2026/11/22  仮想Wi-Fiバスの元サービス宣言と現在の実体差を検証
 * Ver.01.11.00 Shunji Ogawa  2026/11/22  仮想Wi-Fiバスの現行と旧形式の全到達節とフィルター置換を回帰
 * Ver.01.12.00 Shunji Ogawa  2026/11/22  仮想Wi-Fiバスの表示名と説明の展開前後の一致条件を回帰
 * Ver.01.13.00 Shunji Ogawa  2026/11/23  署名文書の範囲型電源設定とAC/DC既定値の読取りを回帰
 * Ver.01.14.00 Shunji Ogawa  2026/11/23  現用署名元と候補の電源定義の分類を回帰
 * Ver.01.15.00 Shunji Ogawa  2026/11/23  省略されたイベント資源を現用の参照根拠に照合
 * Ver.01.16.00 Shunji Ogawa  2026/11/23  起動サービスと現在SYSの署名元の照合を回帰
 * Ver.01.17.00 Shunji Ogawa  2026/11/23  名前付きイベントDLLの所有と共有変更を回帰
 * Ver.01.18.00 Shunji Ogawa  2026/11/23  電源設定GUIDの直下・別グループの競合を回帰
 * Ver.01.19.00 Shunji Ogawa  2026/11/23  現用同梱NVMeのPCI依存節と電源宣言を回帰
 * Ver.01.20.00 Shunji Ogawa  2026/11/24  無線バスの同一文書内転送と元選択の拒否対照を追加
 * Ver.01.21.00 Shunji Ogawa  2026/11/24  USB Bluetooth三節の参照不足と異なる文書への解決を回帰
 * Ver.01.22.00 Shunji Ogawa  2026/11/24  USB Bluetoothの保護コピーと配備先の異常を回帰
 * Ver.01.23.00 Shunji Ogawa  2026/11/24  USB BluetoothとPCIの機器設定宣言の型と所有節を回帰
 * Ver.01.24.00 Shunji Ogawa  2026/11/24  USB Bluetoothの共有作用を元INFの写しで回帰
 * Ver.01.25.00 Shunji Ogawa  2026/11/24  同梱WinUSBの元作用とサービス実体の正負対照を追加
 * </pre>
 *
 * @note この専用targetではtrust／OS APIを全て架空化する。実署名・実device・導入の測定ではない
 * @see docs/adr/0271-compile-isolated-inf-native-api-tests.md
 */
//------------------------------------------------------------------------------

#include "support/inf_dependency_native_test_api.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "platform/common_driver_package.h"
#include "platform/system_inf_effects_internal.h"
#include "platform/storage_inf_effects_internal.h"
#include "platform/inf_dependency_native_internal.h"
#include <Sddl.h>
#include "platform/official_driver_package.h"
#include "platform/driver_package_signature_internal.h"
#include "test_framework.h"
#include <WinIoCtl.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <crtdbg.h>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <iostream>
#include <map>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
namespace {
thread_local const CommonInfInspection *commonContentUnderTest{} ;	// 専用EXEの現在fixtureだけです
thread_local std::size_t				commonContentRechecks{} ;	// 所有byteの実再確認回数です
//------------------------------------------------------------------------------
/**
 * @brief 専用EXEだけで元内容の署名境界をfake化し、全原byteは実hashへ再照合します
 * @param[in] inspected この同期fixtureが登録した元内容だけです
 * @return 同一fixtureと原byte一致0、それ以外は元拒否HRESULTです
 * @note 同期fixtureのAPI表に結合して使います
 */
//------------------------------------------------------------------------------
NativeError reverifyFixtureCommonInf( const CommonInfInspection &inspected)
{
	// 任意の成功boolや別所有者を内容証拠として受理しません
	if( &inspected != commonContentUnderTest || !inspected.workspace ||
	   inspected.state != CommonInfInspectionState::VERIFIED || inspected.error != 0 ||
	   inspected.scanSessionId == 0U || inspected.closure.packages.size() != 1U ||
	   inspected.closure.entries.empty()) {
		return E_INVALIDARG ;
	}

	++commonContentRechecks ;
	// 同じ保護workspaceの全fileをsize/hashへ再照合します
	for( const auto &entry : inspected.closure.entries) {
		const auto error = verifyOfficialFileMetadata(
			inspected.workspace->path( entry.relativePath),
			{entry.uncompressedSize, entry.sha256}) ;	// 実際の架空byteだけです
		// 一つの差替えも成功へ補いません
		if( error != 0) {
			return error ;
		}
	}

	return 0 ;
}
} // namespace
}

namespace drivercrate::test {
namespace {
/** @brief 元APIの障害または根拠変化。一runで一種類だけ注入する */
enum class Fault {
	/// 架空APIの正常観測
	NONE,
	/// 開始OS照会が失敗する
	VERSION_START,
	/// 終了OS照会が失敗する
	VERSION_END,
	/// 終了OS majorが変わる
	MAJOR_CHANGED,
	/// 終了OS minorが変わる
	MINOR_CHANGED,
	/// 終了OS buildが変わる
	BUILD_CHANGED,
	/// 終了OSがServerへ変わる
	PRODUCT_CHANGED,
	/// 開始product typeが未知
	PRODUCT_UNKNOWN,
	/// native architectureがx64以外
	ARCHITECTURE,
	/// 開始buildが零
	BUILD_ZERO,
	/// 開始majorが零
	MAJOR_ZERO,
	/// OS起点照会が失敗
	DIRECTORY_ERROR,
	/// OS起点がUNC
	DIRECTORY_UNC,
	/// 初回system INF署名失敗
	SIGNATURE_START,
	/// 終了system INF署名失敗
	SIGNATURE_END,
	/// 完全scoreがWHQLで標準由来未確認
	WHQL_SCORE,
	/// 終了完全scoreがWHQLへ変わる
	SCORE_CHANGED,
	/// 初回CATが許可領域外
	CAT_OUTSIDE,
	/// 終了CATが別位置へ変わる
	CAT_CHANGED,
	/// 初回signerが空
	SIGNER_EMPTY,
	/// CAT応答に終端がない
	CAT_UNTERMINATED,
	/// 終了signerが空
	SIGNER_END_EMPTY,
	/// 初回CAT member署名が失敗
	CAT_SIGNATURE_START,
	/// 終了CAT member署名が失敗
	CAT_SIGNATURE_END,
	/// 初回Store対応情報がない
	STORE_START,
	/// 終了Store対応照会が失敗
	STORE_END,
	/// 初回Storeが許可領域外
	STORE_OUTSIDE,
	/// 終了Storeが別位置へ変わる
	STORE_CHANGED,
	/// 対応Storeの実byteが異なる
	STORE_BYTES,
	/// Store成功応答の位置が空
	STORE_EMPTY,
	/// Store成功応答に埋込みNUL
	STORE_NUL,
	/// Store APIが不正応答を報告
	STORE_MALFORMED,
	/// 属性APIが失敗
	ATTRIBUTES_ERROR,
	/// INF発見後のCAT属性照会がpath不在を報告
	ATTRIBUTES_PATH,
	/// 開いた参照INFの属性APIがfile不在を報告
	ATTRIBUTES_INF_NOT_FOUND,
	/// 途中の属性応答がreparseへ変わる
	ATTRIBUTES_REPARSE,
	/// 途中の属性応答でfile／directory種類が変わる
	ATTRIBUTES_TYPE,
	/// 属性callbackの例外
	ATTRIBUTES_THROW,
	/// 署名callbackの例外
	SIGNATURE_THROW,
	/// 終了OS callbackの例外
	VERSION_THROW,
	/// CAT位置の実fileが未発見
	CAT_MISSING,
	/// CAT親directoryも未発見
	CAT_PARENT_MISSING,
	/// 保持中の実fileへwriterを試みる
	WRITER,
	/// 同期test APIへの再入を試みる
	REENTRY,
	/// rootの実期待hashだけが異なる
	HASH_CHANGED,
	/// root署名不合格でも資料存在を保持
	ROOT_SIGNATURE,
} ;

/** @brief 一runの入力障害と期待する全体診断 */
struct Scenario {
	/// 一種類の注入
	Fault		fault ;
	/// 観測成功0、全体拒否では元HRESULT
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
}} ; // 公開しない固定障害matrix。実署名測定ではない

/** @brief 一runの実fileと借用callbackの状態を所有する */
struct Fixture {
	/// 架空fileだけを所有する保護領域
	OfficialDownloadWorkspace				   workspace ;
	/// 閉じたpackage一覧。system fileをpackageとして登録しない
	std::array<InfDependencyPackageMember, 1U> members ;
	/// 一同期runのAPI集合。capture先のthisはrun終了まで生存する
	InfDependencyNativeTestApi				   api ;
	/// 注入する一障害
	Fault									   fault{Fault::NONE} ;
	/// OS開始／終了照会の回数
	std::size_t								   versionCalls{} ;
	/// system INFの署名開始／終了照会回数
	std::size_t								   signatureCalls{} ;
	/// system CATの開始／終了照会回数
	std::size_t								   catalogCalls{} ;
	/// system Storeの開始／終了照会回数
	std::size_t								   storeCalls{} ;
	/// packageを含む署名callback全呼出し数
	std::size_t								   allSignatureCalls{} ;
	/// 属性変更を開始する時点。system署名の初回観測後true
	bool									   changedAttributes{} ;
	/// 保持中fileへのwriterの元診断
	DWORD									   writerError{} ;
	/// 再入を拒否した元診断
	NativeError								   reentryError{} ;
	/// CAT memberを一INFだけに結合した場合true
	bool									   memberBound{true} ;
	/// 二threadで異なる文脈を確認する架空build
	DWORD									   build{26100U} ;

	/**
	 * @brief 架空fileとAPI集合を初期化する
	 * @param[in] selected このrunの一障害
	 * @param[in] payloadBody 到達Shared節からの架空file用途。実payload fileは作成しない
	 * @param[in] rootBody 空なら既存root本文、それ以外はこのfixtureだけの明示節群
	 * @param[in] systemSection 同期fixtureで使用する架空参照節名。装飾の独自補完をしない
	 * @throws std::runtime_error 架空file作成／hash失敗
	 */
	explicit Fixture( Fault selected, std::string_view payloadBody = {},
					 std::string_view rootBody = {}, std::string_view systemSection = "Shared")
		: fault( selected)
	{
		// 初期化失敗をskipや架空成功にしない
		if( workspace.initialize( L"inf-native-api-test", 1U) != 0) {
			throw std::runtime_error( "fixture initialize") ;
		}

		const std::string root =
			"[Version]\r\nSignature=\"$Windows NT$\"\r\n" +
			std::string( rootBody.empty() ? "[Install]\r\nInclude=peer.inf\r\nNeeds=Shared\r\n"
										 : rootBody) ;	// 元正例または限定六形の架空明示本文
		members[0] = file( L"root.inf", root) ;
		std::string resolvedBody( payloadBody) ;	// 新原文の自己参照だけを所有位置へ結びます
		constexpr std::string_view SELF =
			"${FIXTURE_SYSTEM_INF}" ;										// 架空入力生成時だけのplaceholderです
		const auto ownPath = workspace.path( L"windows\\INF\\peer.inf") ;	// このfixtureの元位置です
		// ASCIIの所有位置を元byte生成前だけ置換し、製品parserに補正をさせません
		if( resolvedBody.find( SELF) != resolvedBody.npos) {
			// 非ASCII位置を壊れたbyteへ変換しません
			if( std::ranges::any_of( ownPath, []( wchar_t c) { return c > 0x7f || c < L' ' ; })) {
				throw std::runtime_error( "synthetic self reference path not ASCII") ;
			}

			std::string ascii ;	// 検査済みASCIIだけを明示変換します
			// 値範囲を確認済みの各文字だけを元UTF-8 byteへ写します
			for( const auto c : ownPath) {
				ascii.push_back( static_cast<char>( c)) ;
			}

			std::size_t position{} ;	// 元生成byteの自己参照位置です
			// 各placeholderを同一の所有位置へ固定します
			while( (position = resolvedBody.find( SELF, position)) != resolvedBody.npos) {
				resolvedBody.replace( position, SELF.size(), ascii) ;
				position += ascii.size() ;
			}
		}

		const std::string_view windowsToken =
			"${FIXTURE_SYSTEM_ROOT}" ;	// 架空原byte生成前の固定DIRID投影です
		std::string windowsRoot ;		// 元所有scopeへ結ぶ位置です。任意探索へ使いません
		// 同所有fixtureの全対象を順に検査します
		for( const auto c : workspace.path( L"windows")) {	// 同所有fixtureの全対象を順に確認します
			// 固定した入力条件だけを分離し、他対象や期待へ流用しません
			if( c < L' ' ||
			   c > 0x7f) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
				throw std::runtime_error( "synthetic Windows root not ASCII") ;
			}

			windowsRoot.push_back( static_cast<char>( c)) ;
		}

		// 同所有fixtureの全対象を順に検査します
		for( auto position = resolvedBody.find( windowsToken);
			position != resolvedBody.npos;	// 同所有fixtureの全対象を順に確認します
			position = resolvedBody.find( windowsToken, position + windowsRoot.size())) {
			resolvedBody.replace( position, windowsToken.size(), windowsRoot) ;
		}

		const std::string system =
			"[Version]\r\nSignature=\"$Windows NT$\"\r\n" +
			std::string( payloadBody.empty() ? "" : "LayoutFile=fixture-layout.inf\r\n") + "[" +
			std::string( systemSection) + "]\r\n" +
			// 実IDを含まない原byte
			resolvedBody ;
		(void)file( L"windows\\INF\\peer.inf", system) ;
		(void)file( L"windows\\System32\\DriverStore\\FileRepository\\fixture\\peer.inf",
				   fault == Fault::STORE_BYTES ? system + ";different\r\n" : system) ;
		(void)file( L"fixture.cat", "synthetic package catalog") ;
		// 実CAT欠落の拒否を試す場合だけ、system CATを作成しない
		if( fault != Fault::CAT_PARENT_MISSING) {
			(void)file( L"windows\\System32\\CatRoot\\placeholder.txt", "synthetic parent") ;
		}

		// 親directoryの不在も別の元診断として試す
		if( fault != Fault::CAT_MISSING && fault != Fault::CAT_PARENT_MISSING) {
			(void)file( L"windows\\System32\\CatRoot\\fixture.cat", "synthetic system catalog") ;
		}

		// 同じbyteへ結合できない期待値を入力する
		if( fault == Fault::HASH_CHANGED) {
			members[0].sha256[0] = members[0].sha256[0] == L'a' ? L'b' : L'a' ;
		}

		api.reverifyCommonInf = &reverifyFixtureCommonInf ;
		api.version			  = [this]( auto &version, auto &native) {
			  // Fixtureの同期生存期間だけを借用し、実OSを変更しない
			  return versionInfo( version, native) ;
		} ;
		api.windowsDirectory = [this]( auto &path) -> NativeError {
			// 起点APIの元失敗を注入する
			if( fault == Fault::DIRECTORY_ERROR) {
				return E_ACCESSDENIED ;
			}

			path = fault == Fault::DIRECTORY_UNC ? L"\\\\synthetic\\windows"
												 : workspace.path( L"windows") ;
			return 0 ;
		} ;
		api.infSignature = [this]( const auto &path, auto &signer) {
			return signature( path, signer) ;
		} ; // 同期借用
		api.catalogSignature = [this]( const auto &catalog, auto paths) -> NativeError {
			// 同じ一INF memberを署名処理へ渡す境界だけを確認する
			memberBound = memberBound && paths.size() == 1U &&
						  (paths.front() == workspace.path( L"root.inf") ||
						   paths.front() == workspace.path( L"windows\\INF\\peer.inf")) ;
			// systemとpackage CATを独立に数える
			if( catalog == workspace.path( L"windows\\System32\\CatRoot\\fixture.cat")) {
				++catalogCalls ;
				// 初回不合格と終了失効を別々に注入する
				if( (fault == Fault::CAT_SIGNATURE_START && catalogCalls == 1U) ||
				   (fault == Fault::CAT_SIGNATURE_END && catalogCalls == 2U)) {
					return E_ACCESSDENIED ;
				}
			}

			return 0 ;
		} ;
		api.driverStore = [this]( const auto &path, auto &location) -> NativeError {
			++storeCalls ;
			// 元INF以外のStoreを照会したfixtureを拒否する
			if( path != workspace.path( L"windows\\INF\\peer.inf")) {
				return E_INVALIDARG ;
			}

			// 初回照会の不在だけを未検査に保持する
			if( fault == Fault::STORE_START && storeCalls == 1U) {
				return HRESULT_FROM_WIN32( ERROR_NOT_FOUND) ;
			}

			// 終了照会失敗後に旧由来を使わせない
			if( fault == Fault::STORE_END && storeCalls == 2U) {
				return E_ACCESSDENIED ;
			}

			// 元APIの不正応答を未知由来へ弱めない
			if( fault == Fault::STORE_MALFORMED) {
				return E_UNEXPECTED ;
			}

			location = workspace.path(
				L"windows\\System32\\DriverStore\\FileRepository\\fixture\\peer.inf") ;
			// 許可領域外の成功応答を注入する
			if( fault == Fault::STORE_OUTSIDE) {
				location = workspace.path( L"root.inf") ;
			}

			// 終了対応変更を同じbyteとして補完させない
			if( fault == Fault::STORE_CHANGED && storeCalls == 2U) {
				location += L".different" ;
			}

			// 空の成功位置は不正として拒否する
			if( fault == Fault::STORE_EMPTY) {
				location.clear() ;
			}

			// 終端付き文字列へ埋込みNULを混入する
			if( fault == Fault::STORE_NUL) {
				location.push_back( L'\0') ;
			}

			return 0 ;
		} ;
		api.attributes = [this]( HANDLE handle, auto &attributes) -> NativeError {
			// 有効INF handleの属性失敗を、open不在へ読み替えさせない
			if( fault == Fault::ATTRIBUTES_INF_NOT_FOUND) {
				std::array<wchar_t, MAX_PATH + 4U> name{} ;	// 固定handleの実最終位置
				const DWORD						   count = GetFinalPathNameByHandleW(
					   handle, name.data(), static_cast<DWORD>( name.size()),
					   FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;	// 元位置だけをfixture内で照合する
				// 元INFに到達した応答だけを注入する。名称を出力しない
				if( count > 4U && count < name.size() &&
				   CompareStringOrdinal( name.data() + 4U, -1,
										workspace.path( L"windows\\INF\\peer.inf").c_str(), -1,
										TRUE) == CSTR_EQUAL) {
					return HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND) ;
				}
			}

			// 属性APIそのものの失敗を注入する
			if( fault == Fault::ATTRIBUTES_ERROR) {
				return E_ACCESSDENIED ;
			}

			// INF固定後の別根拠に対するpath不在を原INF不在へ読み替えさせない
			if( changedAttributes && fault == Fault::ATTRIBUTES_PATH) {
				return HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND) ;
			}

			// 属性callback例外の全体拒否を試す
			if( fault == Fault::ATTRIBUTES_THROW) {
				throw std::runtime_error( "synthetic attributes") ;
			}

			// 実handleの属性は確認し、通常file開閉やhashを架空化しない
			if( !GetFileInformationByHandleEx( handle, FileAttributeTagInfo, &attributes,
											 sizeof( attributes))) {
				return HRESULT_FROM_WIN32( GetLastError()) ;
			}

			// 途中のreparse応答を通常fileへ読み替えさせない
			if( changedAttributes && fault == Fault::ATTRIBUTES_REPARSE) {
				attributes.FileAttributes |= FILE_ATTRIBUTE_REPARSE_POINT ;
			}

			// 途中の種類変更を別fileとして採用させない
			if( changedAttributes && fault == Fault::ATTRIBUTES_TYPE) {
				attributes.FileAttributes ^= FILE_ATTRIBUTE_DIRECTORY ;
			}

			return 0 ;
		} ;
	}

	/**
	 * @brief 一架空fileを新規作成し実hashを固定する
	 * @param[in] name 所有領域内のASCII相対位置
	 * @param[in] bytes 架空の原byte
	 * @return 実byte／sizeに結合したmember
	 * @throws std::runtime_error 作成・書込み・hash失敗
	 */
	InfDependencyPackageMember file( const std::wstring &name, std::string_view bytes)
	{
		HANDLE handle = INVALID_HANDLE_VALUE ;	// この関数だけで取得し閉じる所有handle
		// 作成失敗後は書込みへ進まない
		if( workspace.createFile( name, handle) != 0) {
			throw std::runtime_error( "fixture create") ;
		}

		DWORD	   written{} ;	// 実byte数
		const bool success = WriteFile( handle, bytes.data(), static_cast<DWORD>( bytes.size()),
									   &written, nullptr) != FALSE ;	// 元成功値
		CloseHandle( handle) ;
		// 短縮writeを正常fixtureとみなさない
		if( !success || written != bytes.size()) {
			throw std::runtime_error( "fixture write") ;
		}

		InfDependencyPackageMember result{name, {}, bytes.size()} ;	// 期待する実byte
		// CNGで実fileを結合し、hashだけの架空成功を使わない
		if( computeFileSha256( workspace.path( name), result.sha256) != 0) {
			throw std::runtime_error( "fixture hash") ;
		}

		return result ;
	}

	/**
	 * @brief 開始／終了の架空OS応答を生成する
	 * @param[out] version 未知product typeも含む元応答
	 * @param[out] native native architectureの元応答
	 * @return API成功0、注入した診断値
	 */
	NativeError versionInfo( OSVERSIONINFOEXW &version, SYSTEM_INFO &native)
	{
		++versionCalls ;
		// 開始と終了の失敗を区別して再現する
		if( (fault == Fault::VERSION_START && versionCalls == 1U) ||
		   (fault == Fault::VERSION_END && versionCalls == 2U)) {
			return E_ACCESSDENIED ;
		}

		// 終了callback例外でもslotを解除させる
		if( fault == Fault::VERSION_THROW && versionCalls == 2U) {
			throw std::runtime_error( "synthetic version") ;
		}

		version.dwMajorVersion		  = 10U ;
		version.dwMinorVersion		  = 0U ;
		version.dwBuildNumber		  = build ;
		version.wProductType		  = VER_NT_WORKSTATION ;
		native.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64 ;
		// 全version fieldを一つずつ変更して終了一致を検査する
		if( fault == Fault::MAJOR_CHANGED && versionCalls == 2U) {
			++version.dwMajorVersion ;
		}

		// minor差も同じOSと推測しない
		if( fault == Fault::MINOR_CHANGED && versionCalls == 2U) {
			++version.dwMinorVersion ;
		}

		// build差で監視PCの旧観測を転用しない
		if( fault == Fault::BUILD_CHANGED && versionCalls == 2U) {
			++version.dwBuildNumber ;
		}

		// client／Server差を同じ文脈へまとめない
		if( fault == Fault::PRODUCT_CHANGED && versionCalls == 2U) {
			version.wProductType = VER_NT_SERVER ;
		}

		// 未知product typeのclient推測を拒否させる
		if( fault == Fault::PRODUCT_UNKNOWN) {
			version.wProductType = 0U ;
		}

		// native x86をx64として採用させない
		if( fault == Fault::ARCHITECTURE) {
			native.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL ;
		}

		// 不明buildを有効なOS文脈にしない
		if( fault == Fault::BUILD_ZERO) {
			version.dwBuildNumber = 0U ;
		}

		// 不明majorを有効なOS文脈にしない
		if( fault == Fault::MAJOR_ZERO) {
			version.dwMajorVersion = 0U ;
		}

		return 0 ;
	}

	/**
	 * @brief 架空署名応答と保持中fileのwriter／再入を再現する
	 * @param[in] path 固定した原INF位置
	 * @param[out] signer 有限の架空応答
	 * @return 成功0、注入した診断値
	 */
	NativeError signature( const std::wstring &path, SP_INF_SIGNER_INFO_W &signer)
	{
		++allSignatureCalls ;
		const bool system =
			// 位置だけの架空境界
			path == workspace.path( L"windows\\INF\\peer.inf") ;
		// 初回rootの署名失敗でも資料観測を消させない
		if( !system && fault == Fault::ROOT_SIGNATURE) {
			return E_ACCESSDENIED ;
		}

		// system署名の開始／終了を独立に数える
		if( system) {
			++signatureCalls ;
			changedAttributes = true ;
			// 初回不足と終了失効の元診断を保持する
			if( (fault == Fault::SIGNATURE_START && signatureCalls == 1U) ||
			   (fault == Fault::SIGNATURE_END && signatureCalls == 2U)) {
				return E_ACCESSDENIED ;
			}

			// callback例外をWin32境界の外へ漏らさない
			if( fault == Fault::SIGNATURE_THROW) {
				throw std::runtime_error( "synthetic signature") ;
			}
		}

		const std::wstring catalog =
			system ? workspace.path( L"windows\\System32\\CatRoot\\fixture.cat")
				   : workspace.path( L"fixture.cat") ;	// 架空CAT
		// path容量を暗黙切詰めしない
		if( catalog.size() >= MAX_PATH) {
			throw std::runtime_error( "fixture path length") ;
		}

		std::ranges::copy( catalog, signer.CatalogFile) ;
		signer.CatalogFile[catalog.size()] = L'\0' ;
		signer.DigitalSigner[0]			   = L'x' ;
		signer.DigitalSigner[1]			   = L'\0' ;
		signer.SignerScore				   = SIGNERSCORE_INBOX ;
		// WHQLとINBOXの共通mask値を由来の根拠へ使わせない
		if( system && (fault == Fault::WHQL_SCORE ||
					  (fault == Fault::SCORE_CHANGED && signatureCalls == 2U))) {
			signer.SignerScore = SIGNERSCORE_WHQL ;
		}

		// 初回の無関係CATを許可範囲外へ返す
		if( system && fault == Fault::CAT_OUTSIDE) {
			std::ranges::copy( L"C:\\synthetic.cat", signer.CatalogFile) ;
		}

		// 終了時CATの変更を開始成功で補完しない
		if( system && fault == Fault::CAT_CHANGED && signatureCalls == 2U) {
			signer.CatalogFile[3] = signer.CatalogFile[3] == L'a' ? L'b' : L'a' ;
		}

		// 初回の空signerを成功署名として採用しない
		if( system && fault == Fault::SIGNER_EMPTY) {
			signer.DigitalSigner[0] = L'\0' ;
		}

		// 有限応答の終端欠損を拒否させる
		if( system && fault == Fault::CAT_UNTERMINATED) {
			std::ranges::fill( signer.CatalogFile, L'x') ;
		}

		// 終了signer不足は全体拒否にする
		if( system && fault == Fault::SIGNER_END_EMPTY && signatureCalls == 2U) {
			signer.DigitalSigner[0] = L'\0' ;
		}

		// 実INF handle保持中は別writerが開けないことを確認する
		if( !system && fault == Fault::WRITER) {
			const HANDLE writer =
				CreateFileW( path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
							nullptr, OPEN_EXISTING, 0U, nullptr) ;	// 書込み自体は行わない
			writerError = writer == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS ;
			// 万一開けた場合も閉じて元byteを変更しない
			if( writer != INVALID_HANDLE_VALUE) {
				CloseHandle( writer) ;
			}
		}

		// 同じthreadのtest APIを再入で差し替えさせない
		if( !system && fault == Fault::REENTRY) {
			InfDependencyNativeResult		   nested ;				// 再入拒否結果だけ
			const std::array<std::wstring, 1U> seeds{L"Install"} ;	// 架空seed
			reentryError =
				inspectInfDependenciesWithTestApi( api, workspace, members, 0U, seeds, 2U, nested) ;
		}

		return 0 ;
	}

	/**
	 * @brief 同期fixtureを一回だけ実行する
	 * @param[out] result 全成功時の架空観測
	 * @return adapterの元診断値
	 */
	NativeError run( InfDependencyNativeResult &result)
	{
		const std::array<std::wstring, 1U> seeds{L"Install"} ;	// 一つの明示節
		return inspectInfDependenciesWithTestApi( api, workspace, members, 0U, seeds, 100U, result) ;
	}
} ;

//------------------------------------------------------------------------------
/**
 * @brief 拒否・独立証拠・非実行計画とRAII解除を検査する
 * @param[in,out] context このprocessのassertion集計
 */
//------------------------------------------------------------------------------
void matrix( TestContext &context)
{
	// 一種類の障害ごとに新しい実fileとAPI状態を所有する
	for( const auto &scenario : SCENARIOS) {
		Fixture					  fixture( scenario.fault) ;		// 一runの同期所有者
		InfDependencyNativeResult result ;							// 全成功時だけの結果
		const auto				  error = fixture.run( result) ;	// 元API診断を保持する
		// 原因を識別できる固定case番号と診断だけを出す。pathを出力しない
		if( error != scenario.expectedError ||
		   (error == 0 && result.dependency.documents.size() != 2U)) {
			std::cerr << "Synthetic case " << static_cast<int>( scenario.fault) << ", error "
					  << error << ", documents " << result.dependency.documents.size() << '\n' ;
		}

		DRIVERCRATE_EXPECT( context, error == scenario.expectedError) ;
		// 全体拒否では古い部分graphを一つも返さない
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
			// 不正なfixture応答を診断した後に存在しない要素を参照しない
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
										 // 初回署名不足だけ
										 scenario.fault == Fault::CAT_SIGNATURE_START ;
			const bool provenanceUnknown = signatureFailed || scenario.fault == Fault::WHQL_SCORE ||
										   // 由来の未確認
										   scenario.fault == Fault::STORE_START ;
			const auto &system = result.dependency.documents[1] ;	// 架空system snapshot
			DRIVERCRATE_EXPECT( context, system.signature ==
											(signatureFailed ? InfDependencyEvidence::FAILED
															 : InfDependencyEvidence::VERIFIED)) ;
			DRIVERCRATE_EXPECT( context,
							   system.provenance ==
								   (provenanceUnknown ? InfDependencyEvidence::NOT_CHECKED
													  : (scenario.fault == Fault::STORE_BYTES
															 ? InfDependencyEvidence::FAILED
															 : InfDependencyEvidence::VERIFIED))) ;
			// 未検査・不合格を存在なしや解決済みへ変換しない
			for( const auto &edge : result.dependency.edges) {
				DRIVERCRATE_EXPECT( context,
								   edge.state ==
									   (provenanceUnknown || scenario.fault == Fault::STORE_BYTES
											? InfDependencyState::OBSERVED
											: InfDependencyState::RESOLVED_SYSTEM)) ;
			}

			DRIVERCRATE_EXPECT( context, fixture.memberBound) ;
			DRIVERCRATE_EXPECT(
				context,
				result.findings[1].signatureError ==
					(signatureFailed ? static_cast<NativeError>( E_ACCESSDENIED) : NativeError{})) ;
			DRIVERCRATE_EXPECT(
				context,
				result.findings[1].provenanceError ==
					(scenario.fault == Fault::STORE_START
						 ? static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_FOUND))
						 : (scenario.fault == Fault::STORE_BYTES
								? static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_INVALID))
								: 0))) ;
			DRIVERCRATE_EXPECT( context, result.dependency.context.build == fixture.build &&
											result.dependency.context.observationId == 100U &&
											result.dependency.context.machine == 0x8664U) ;
		}

		// 初回署名不合格を終了時の再照会で昇格させない
		if( scenario.fault == Fault::SIGNATURE_START) {
			DRIVERCRATE_EXPECT( context, fixture.signatureCalls == 1U) ;
		}

		// 初回CAT不合格を終了時の再照会で昇格させない
		if( scenario.fault == Fault::CAT_SIGNATURE_START) {
			DRIVERCRATE_EXPECT( context, fixture.catalogCalls == 1U) ;
		}

		// 初回Store未確認を終了時の取得成功で昇格させない
		if( scenario.fault == Fault::STORE_START) {
			DRIVERCRATE_EXPECT( context, fixture.storeCalls == 1U) ;
		}

		// 完全scoreがinboxでない場合は対応Store証拠を作らない
		if( scenario.fault == Fault::WHQL_SCORE) {
			DRIVERCRATE_EXPECT( context, fixture.storeCalls == 0U) ;
		}

		// byte不一致は上位API照会より前に止まる
		if( scenario.fault == Fault::HASH_CHANGED) {
			DRIVERCRATE_EXPECT( context, fixture.allSignatureCalls == 0U) ;
		}

		// 元writer診断を成功扱いで消さない
		if( scenario.fault == Fault::WRITER) {
			DRIVERCRATE_EXPECT( context, fixture.writerError == ERROR_SHARING_VIOLATION) ;
		}

		// 再入拒否の元診断を確認する
		if( scenario.fault == Fault::REENTRY) {
			DRIVERCRATE_EXPECT( context, fixture.reentryError == E_INVALIDARG) ;
		}

		Fixture					  subsequent( Fault::NONE) ;	// 例外・拒否後の新しいAPI集合
		InfDependencyNativeResult clean ;						// 古いslotを借用しない次run
		DRIVERCRATE_EXPECT( context,
						   subsequent.run( clean) == 0 && clean.dependency.documents.size() == 2U) ;
	}

	Fixture fixture( Fault::NONE) ;	// 必須集合の欠損だけを試す
	// 五つの必須APIが一つでもない場合に実APIへfallbackしない
	for( std::size_t missing = 0U; missing < 5U; ++missing) {
		auto incomplete = fixture.api ;	// 一項目だけを落とす固定集合
		// OS queryを欠落させる
		if( missing == 0U) {
			incomplete.version = {} ;
		}

		// 起点queryを欠落させる
		if( missing == 1U) {
			incomplete.windowsDirectory = {} ;
		}

		// INF signatureを欠落させる
		if( missing == 2U) {
			incomplete.infSignature = {} ;
		}

		// CAT signatureを欠落させる
		if( missing == 3U) {
			incomplete.catalogSignature = {} ;
		}

		// Store queryを欠落させる
		if( missing == 4U) {
			incomplete.driverStore = {} ;
		}

		InfDependencyNativeResult		   result ;				// 拒否で空になる出力
		const std::array<std::wstring, 1U> seeds{L"Install"} ;	// 架空の一節
		DRIVERCRATE_EXPECT( context, inspectInfDependenciesWithTestApi(
										incomplete, fixture.workspace, fixture.members, 0U, seeds,
										100U, result) == E_INVALIDARG) ;
		DRIVERCRATE_EXPECT( context,
						   result.dependency.documents.empty() && fixture.versionCalls == 0U) ;
	}

	std::array<std::future<bool>, 2U> runs ;	// 二threadの独立fixture結果を所有する
	// thread-local slotを別threadへ転用しないことを確認する
	for( std::size_t index = 0U; index < runs.size(); ++index) {
		runs[index] = std::async( std::launch::async, [index] {
			Fixture parallel( Fault::NONE) ;	// このthreadだけで所有する同期capture
			parallel.build += static_cast<DWORD>( index) ;
			InfDependencyNativeResult result ;	// このthreadだけの出力
			return parallel.run( result) == 0 && result.dependency.context.build == parallel.build ;
		}) ;
	}

	// 全thread完了後に集計し、共有assertion stateを同時更新しない
	for( auto &run : runs) {
		DRIVERCRATE_EXPECT( context, run.get()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同節Services・明示Needs名と未採用参照節の分離を実readerで確認する
 * @param[in,out] context 一processの有限assertion集計
 * @note OS／INF署名／CAT／Store応答は既存のfake境界だけを使用する。実hash・節読取は実APIで、fake成功を全payload署名や端末導入能力へ昇格しない
 */
//------------------------------------------------------------------------------
void referenceSelection( TestContext &context)
{
	// 同節正例・Include借用拒否・三suffix不一致・Includeだけの未採用節を全て確認する
	for( std::size_t scenario = 0U; scenario < 6U; ++scenario) {
		const std::string rootBody =
			"[Install]\r\nInclude=peer.inf\r\n" +
			std::string( scenario == 5U ? "" : "Needs=Shared\r\n") +
			std::string( scenario <= 1U
							? "[Install.Services]\r\n" +
								  std::string( scenario == 0U ? "Include=peer.inf\r\n" : "") +
								  "Needs=Shared.Services\r\n"
							: "") ;	// 元節自身のInclude集合だけを与える
		const std::string_view systemSection =
			scenario == 2U
				? "Shared.NT"
				: (scenario == 3U
					   ? "Shared.Services"
					   : (scenario == 4U ? "Shared.NTarm64" : "Shared")) ;	// 参照先の原節名
		const std::string_view payloadBody =
			scenario <= 1U
				? "[Shared.Services]\r\n"
				: (scenario >= 4U ? "CopyFiles=@unselected.sys\r\n" : "") ;		// 実payloadは作らない
		Fixture fixture( Fault::NONE, payloadBody, rootBody, systemSection) ;	// 同runの同期所有者
		std::vector<std::wstring> seeds{L"Install"} ;							// 明示された元節だけを選ぶ
		// Services正例と借用拒否だけを独立seedとして明示する
		if( scenario <= 1U) {
			seeds.push_back( L"Install.Services") ;
		}

		InfDependencyNativeResult result ;	// 全成功時だけの独立したgraphと用途観測
		const NativeError		  error = inspectInfDependenciesWithTestApi(
			fixture.api, fixture.workspace, fixture.members, 0U, seeds, 200U + scenario,
			result) ;	// 架空APIを同期借用
		DRIVERCRATE_EXPECT( context, error == 0) ;
		DRIVERCRATE_EXPECT( context, result.dependency.documents.size() == 2U &&
										result.findings.size() == 2U) ;
		// fixture拒否や不完全な配列を報告した後に部分値を参照しない
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

		// 同節二形は元ServicesのNeedsを独立した辺として比較する
		if( scenario <= 1U) {
			const auto services =
				std::ranges::find_if( result.dependency.edges, []( const auto &edge) {
					return edge.sourceIdentity == 1U && edge.sourceSection == L"Install.Services" &&
						   edge.directive == InfDependencyDirective::NEEDS &&
						   edge.target == L"Shared.Services" ;
				}) ; // このgraphだけを借用し、base辺を代用しない
			DRIVERCRATE_EXPECT( context, services != result.dependency.edges.end()) ;
			// 対象辺が得られた場合だけ一意性・存在・同節の結果を照合する
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

		// 現OSの署名済み資料が存在しても、明示Needs名を装飾／Services名へ補完しない
		if( scenario >= 2U && scenario <= 4U) {
			DRIVERCRATE_EXPECT( context,
							   std::ranges::any_of( result.dependency.edges, []( const auto &edge) {
								   return edge.sourceSection == L"Install" &&
										  edge.directive == InfDependencyDirective::NEEDS &&
										  edge.target == L"Shared" &&
										  edge.state == InfDependencyState::UNRESOLVED &&
										  edge.reason == InfDependencyReason::MISSING &&
										  edge.targetIdentity == 0U && edge.candidateCount == 0U ;
							   })) ; // 不一致を署名FAILEDやdevice不適合へ変換しない
		}

		// 選ばれないARM64節とIncludeだけのShared節を必要payloadへ混同しない
		if( scenario >= 4U) {
			DRIVERCRATE_EXPECT( context, std::ranges::none_of( result.fileUses, []( const auto &use) {
								   return use.target == L"unselected.sys" ||
										  use.directive == L"CopyFiles" ||
										  use.section == L"Shared.NTarm64" ;
							   })) ; // Version用途は独立観測として保持でき、全payload合格ではない
		}
	}
}

/** @brief Mount-point reparse bufferの公式byte layout。所有領域内だけで使用する */
struct JunctionData {
	/// IO_REPARSE_TAG_MOUNT_POINTの固定tag
	DWORD									 tag{IO_REPARSE_TAG_MOUNT_POINT} ;
	/// 後続のWORD offset群とpath byte数
	WORD									 length{} ;
	/// APIで予約される零field
	WORD									 reserved{} ;
	/// pathBuffer先頭からのNT代替名byte offset
	WORD									 substituteOffset{} ;
	/// 終端を除くNT代替名byte数
	WORD									 substituteLength{} ;
	/// 表示名先頭までのpathBuffer内byte offset
	WORD									 printOffset{} ;
	/// 終端を除く表示名byte数
	WORD									 printLength{} ;
	/// 有限なNT名と表示名。両方に終端を置く
	std::array<wchar_t, 2U * MAX_PATH + 10U> paths{} ;
} ;
// APIの固定headerとoffset群
static_assert( offsetof( JunctionData, paths) == 16U) ;

//------------------------------------------------------------------------------
/**
 * @brief 所有領域内だけの実junctionを作成・拒否確認・tag解除する
 * @param[in,out] context 実path拒否を別に集計する
 * @note OS領域は変更しない。参照先も同じ架空領域内で、driverを導入しない
 */
//------------------------------------------------------------------------------
void junction( TestContext &context)
{
	Fixture fixture( Fault::NONE) ;	// 署名／OSは架空で、fileとreparseは実物
	DRIVERCRATE_EXPECT( context, fixture.workspace.discardFile( L"windows\\INF\\peer.inf") == 0) ;
	const std::wstring directory =
		// 空の追跡済みdirectory
		fixture.workspace.path( L"windows\\INF") ;
	const std::wstring target = fixture.workspace.path(
		L"windows\\System32\\DriverStore\\FileRepository\\fixture") ;			// 同領域内
	const std::wstring substitute = L"\\??\\" + target ;						// mount pointのNT形式
	JunctionData	   data ;													// 全byteを零初期化するAPI入力
	const std::size_t  characters = substitute.size() + target.size() + 2U ;	// 終端二つを含む容量
	// 固定bufferの容量を越えるfixtureを暗黙切詰めしない
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
		nullptr) ;	// 空の所有directoryだけ
	DRIVERCRATE_EXPECT( context, handle != INVALID_HANDLE_VALUE) ;
	// 開けないfixtureを成功やskipとして扱わない
	if( handle == INVALID_HANDLE_VALUE) {
		return ;
	}

	DWORD	   returned{} ;	// DeviceIoControlの元返却byte数
	const bool created = DeviceIoControl( handle, FSCTL_SET_REPARSE_POINT, &data,
										 static_cast<DWORD>( 8U + data.length), nullptr, 0U,
										 &returned, nullptr) != FALSE ;	// tag設定の元成功値
	DRIVERCRATE_EXPECT( context, created) ;
	// 設定失敗ではhandleを閉じ、通常directoryを保持する
	if( !created) {
		CloseHandle( handle) ;
		return ;
	}

	InfDependencyNativeResult result ;							// reparse拒否後は空の結果
	const auto				  error = fixture.run( result) ;	// Windows設定・署名policyは変更しない
	JunctionData			  removal ;							// 同じtagを同じ所有handleから除去する有限header
	const bool				  removed =
		DeviceIoControl( handle, FSCTL_DELETE_REPARSE_POINT, &removal, 8U, nullptr, 0U, &returned,
						nullptr) != FALSE ;	// 参照先fileは削除しない
	CloseHandle( handle) ;
	DRIVERCRATE_EXPECT( context, removed) ;
	DRIVERCRATE_EXPECT( context, error == E_ACCESSDENIED) ;
	DRIVERCRATE_EXPECT( context, result.dependency.documents.empty() && result.findings.empty()) ;
	DRIVERCRATE_EXPECT( context, fixture.signatureCalls == 0U) ;
}
//------------------------------------------------------------------------------
/**
 * @brief INF自身のfake署名とSYSTEM payload未検証を独立に保持する
 * @param[in,out] context 一processの有限assertion集計
 * @note fakeの署名成功は実Windows署名の測定ではなく、payloadも取得・複写しない
 */
//------------------------------------------------------------------------------
void payloadObservation( TestContext &context)
{
	constexpr std::array FAULTS{Fault::NONE, Fault::STORE_START,
								Fault::SIGNATURE_START} ;	// 独立証拠三状態
	// sourceなしinbox構造・由来未確認・署名FAILEDを別runで観測する
	for( const auto fault : FAULTS) {
		Fixture fixture(
			fault,
			"CopyFiles=@fixture-payload.sys\r\nServiceBinary=%12%\\fixture-payload.sys\r\n"
			"AddReg=Registry\r\nUnknownFileUse=mystery.dll\r\n"
			"[Shared.NTx86]\r\nCopyFiles=@other-os.sys\r\n") ;	// source節と実payloadなしの明示用途
		InfDependencyNativeResult result ;						// 全体成功時の原graphと用途だけ
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
		// 署名不合格を根拠未検査で上書きせず、元findingを保持する
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
//------------------------------------------------------------------------------
/**
 * @brief 実openのfile／path不在だけを未解決候補へ保持する
 * @param[in,out] context 非通信の二条件を集計する
 * @note 既存matrixの有効handle後不在・権限・reparse拒否を代用しない
 */
//------------------------------------------------------------------------------
void referenceOpenAbsence( TestContext &context)
{
	constexpr std::array PARENTS{false, true} ;	// 親なしpath不在と親ありfile不在
	// 独立workspaceの親有無を先に観測し、実openの不在だけを与える
	for( const bool parentsExist : PARENTS) {
		Fixture fixture( Fault::NONE) ;	// 既存の架空APIと実fileの所有範囲
		// 親がある場合だけ両system探索先に無関係なfileを作る
		if( parentsExist) {
			(void)fixture.file( L"empty-windows\\INF\\placeholder.txt", "synthetic parent") ;
			(void)fixture.file( L"empty-windows\\System32\\placeholder.txt", "synthetic parent") ;
		}

		const std::wstring missing =
			// 明示不在位置
			fixture.workspace.path( L"empty-windows\\INF\\peer.inf") ;
		const DWORD attributes = GetFileAttributesW( missing.c_str()) ;	// 同じ親条件の実観測
		const DWORD observed   = GetLastError() ;						// 次のAPI前に原診断を保持する
		DRIVERCRATE_EXPECT( context, attributes == INVALID_FILE_ATTRIBUTES) ;
		DRIVERCRATE_EXPECT( context,
						   observed == static_cast<DWORD>( parentsExist ? ERROR_FILE_NOT_FOUND
																	   : ERROR_PATH_NOT_FOUND)) ;
		fixture.api.windowsDirectory = [&fixture]( std::wstring &path) -> NativeError {
			path = fixture.workspace.path( L"empty-windows") ;
			return 0 ;
		} ; // この同期runだけの未存在資料起点
		InfDependencyNativeResult result ;	// 不在は成功した参照にしない
		DRIVERCRATE_EXPECT( context, fixture.run( result) == 0) ;
		DRIVERCRATE_EXPECT( context, result.dependency.documents.size() == 1U &&
										!result.dependency.plan.referencesResolved &&
										!result.dependency.plan.rootEvidenceVerified) ;
		DRIVERCRATE_EXPECT(
			context, std::ranges::any_of( result.dependency.edges, []( const auto &edge) {
				return edge.target == L"peer.inf" && edge.state == InfDependencyState::UNRESOLVED &&
					   edge.reason == InfDependencyReason::MISSING && edge.targetIdentity == 0U &&
					   edge.candidateCount == 0U ;
			})) ; // 元Include欠落を保持し、版や署名成功で補完しない
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 選択した無線INFと同梱文書内の旧名転送を架空graphで照合する
 * @param[in,out] context 同じprocessの試験集計
 */
//------------------------------------------------------------------------------
void legacyWifiBusEdges( TestContext &context)
{
	const std::wstring			legacy	 = L"VWiFiBus.PnPFilterRegistration" ;	// 旧名の元節
	const auto					hardware = legacy + L".HW" ;					// 旧名が指す元の同梱節
	OfficialInfInstallInventory inventory ;										// 元基本からの外部参照だけの架空台帳
	inventory.selectedInstallSection = L"Install" ;
	inventory.references			 = {
		{L"Install.HW", L"Include", L"netvwifibus.inf",
					 OfficialInfInstallReferenceKind::INCLUDE_INF, false},
		{L"Install.HW", L"Needs", legacy, OfficialInfInstallReferenceKind::LOCAL_SECTION, false}} ;
	const std::vector<InfDependencyEdge> resolved{
		{1U, L"Install.HW", L"netvwifibus.inf", InfDependencyDirective::INCLUDE,
		 InfDependencyState::RESOLVED_SYSTEM, InfDependencyReason::NONE, 2U, 1U},
		{1U, L"Install.HW", legacy, InfDependencyDirective::NEEDS,
		 InfDependencyState::RESOLVED_SYSTEM, InfDependencyReason::NONE, 2U, 1U},
		{2U, legacy, hardware, InfDependencyDirective::NEEDS, InfDependencyState::RESOLVED_SYSTEM,
		 InfDependencyReason::NONE, 2U, 1U},
	} ; // 元INFの2辺と同じ同梱文書内の一辺
	DRIVERCRATE_EXPECT( context, matchScopedWifiBusReferencesForTest( inventory, 1U, resolved)) ;
	DRIVERCRATE_EXPECT( context, !matchScopedWifiBusReferencesForTest(
									inventory, 1U, std::span{resolved}.first( 2U))) ;
	auto changed				  = resolved ;	// 元選択に存在しない転送の対照を順に作る
	changed.back().targetIdentity = 3U ;
	DRIVERCRATE_EXPECT( context, !matchScopedWifiBusReferencesForTest( inventory, 1U, changed)) ;
	changed						  = resolved ;
	changed.back().sourceIdentity = 3U ;
	changed.back().targetIdentity = 3U ;
	DRIVERCRATE_EXPECT( context, !matchScopedWifiBusReferencesForTest( inventory, 1U, changed)) ;
	changed				 = resolved ;
	changed.back().state = InfDependencyState::RESOLVED_PACKAGE ;
	DRIVERCRATE_EXPECT( context, !matchScopedWifiBusReferencesForTest( inventory, 1U, changed)) ;
	changed				  = resolved ;
	changed.back().target = L"Elsewhere.HW" ;
	DRIVERCRATE_EXPECT( context, !matchScopedWifiBusReferencesForTest( inventory, 1U, changed)) ;
	changed = resolved ;
	changed.push_back( resolved.back()) ;
	DRIVERCRATE_EXPECT( context, !matchScopedWifiBusReferencesForTest( inventory, 1U, changed)) ;
	changed							 = resolved ;
	changed[1U].sourceSection		 = L"Install.Services" ;
	inventory.references[1U].section = L"Install.Services" ;
	DRIVERCRATE_EXPECT( context, !matchScopedWifiBusReferencesForTest( inventory, 1U, changed)) ;
	changed.pop_back() ;
	changed[1U].sourceSection		 = L"Install.HW" ;
	changed[1U].target				 = hardware ;
	inventory.references[1U].section = L"Install.HW" ;
	inventory.references[1U].target	 = hardware ;
	DRIVERCRATE_EXPECT( context, matchScopedWifiBusReferencesForTest( inventory, 1U, changed)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief USB Bluetoothの元三節と二つのWindows同梱文書への参照を正負の対照で確認する
 * @param[in,out] context 同じプロセスの試験集計
 * @note 節名と文書識別子は架空。装置への操作やWindows同梱署名の検査は行わない
 */
//------------------------------------------------------------------------------
void scopedBluetoothUsbEdges( TestContext &context)
{
	const std::array<std::wstring, 3U> seeds{L"Install.NTamd64", L"Install.NTamd64.HW",
											 L"Install.NTamd64.Services"} ;	// 架空INFの選択三節
	using Directive = InfDependencyDirective ;								// 架空の参照種別
	using State		= InfDependencyState ;									// 架空の解決状態
	using Reason	= InfDependencyReason ;									// 架空の解決理由
	const std::array<InfDependencyEdge, 8U> edges{{
		{1U, seeds[0], L"bth.inf", Directive::INCLUDE, State::RESOLVED_SYSTEM, Reason::NONE, 2U,
		 1U},
		{1U, seeds[0], L"BthUsb.NT", Directive::NEEDS, State::RESOLVED_SYSTEM, Reason::NONE, 2U,
		 1U},
		{1U, seeds[1], L"bth.inf", Directive::INCLUDE, State::RESOLVED_SYSTEM, Reason::NONE, 2U,
		 1U},
		{1U, seeds[1], L"BthUsb.NT.HW", Directive::NEEDS, State::RESOLVED_SYSTEM, Reason::NONE, 2U,
		 1U},
		{1U, seeds[2], L"bth.inf", Directive::INCLUDE, State::RESOLVED_SYSTEM, Reason::NONE, 2U,
		 1U},
		{1U, seeds[2], L"BthUsb.NT.Services", Directive::NEEDS, State::RESOLVED_SYSTEM,
		 Reason::NONE, 2U, 1U},
		{2U, L"BthUsb.NT.HW", L"pci.inf", Directive::INCLUDE, State::RESOLVED_SYSTEM, Reason::NONE,
		 3U, 1U},
		{2U, L"BthUsb.NT.HW", L"PciD3ColdSupported.HW", Directive::NEEDS, State::RESOLVED_SYSTEM,
		 Reason::NONE, 3U, 1U},
	}} ; // 元三対と同梱内一対を持つ正例
	DRIVERCRATE_EXPECT( context, matchScopedBluetoothUsbReferencesForTest( edges, seeds, 1U)) ;
	DRIVERCRATE_EXPECT( context, !matchScopedBluetoothUsbReferencesForTest( edges, seeds, 8U)) ;
	DRIVERCRATE_EXPECT(
		context, !matchScopedBluetoothUsbReferencesForTest( std::span{edges}.first( 7U), seeds, 1U)) ;

	// 一辺ずつ同名のパッケージINFに置き換え、同梱由来の混入拒否を確認する
	for( std::size_t index = 0U; index < edges.size(); ++index) {
		auto changed		 = edges ;	// 一つの由来だけを変えた架空グラフ
		changed[index].state = State::RESOLVED_PACKAGE ;
		DRIVERCRATE_EXPECT( context, !matchScopedBluetoothUsbReferencesForTest( changed, seeds, 1U)) ;
	}

	auto changed			   = edges ;	// この後に独立した異常を作るための作業値
	changed[2U].targetIdentity = 4U ;
	DRIVERCRATE_EXPECT( context, !matchScopedBluetoothUsbReferencesForTest( changed, seeds, 1U)) ;
	changed		   = edges ;
	changed.back() = edges.front() ;
	DRIVERCRATE_EXPECT( context, !matchScopedBluetoothUsbReferencesForTest( changed, seeds, 1U)) ;
	changed						  = edges ;
	changed.back().sourceIdentity = 1U ;
	DRIVERCRATE_EXPECT( context, !matchScopedBluetoothUsbReferencesForTest( changed, seeds, 1U)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief USB Bluetoothの保護コピーと明示配備先を架空元INFで検査する
 * @param[in,out] context 同じプロセスの試験集計
 * @note 元INFは試験用領域内に作成する。Windowsからディレクトリ名を読み取り、コピーは実行しない
 */
//------------------------------------------------------------------------------
void scopedBluetoothUsbCopyCases( TestContext &context)
{
	constexpr std::string_view INF =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\n"
		"[BthUsb.NT]\r\nCopyFiles=BthUsb.NT.Copy,BthPort.NT.CopyFiles\r\n"
		"AddReg=Fsquirt.NT.AddReg\r\n[DestinationDirs]\r\n"
		"BthUsb.NT.Copy=12\r\nBthPort.NT.CopyFiles=12\r\n"
		"[BthUsb.NT.Copy]\r\nbthusb.sys,,,0x100\r\n"
		"[BthPort.NT.CopyFiles]\r\nbthport.sys,,,0x100\r\n" ;	// 保護コピー二つの架空元INF
	constexpr std::array<std::pair<std::string_view, std::string_view>, 9U> CHANGES{{
		{"CopyFiles=BthUsb.NT.Copy,BthPort.NT.CopyFiles", "CopyFiles=BthUsb.NT.Copy"},
		{"CopyFiles=BthUsb.NT.Copy,BthPort.NT.CopyFiles",
		 "CopyFiles=BthPort.NT.CopyFiles,BthUsb.NT.Copy"},
		{"BthPort.NT.CopyFiles=12", "BthPort.NT.CopyFiles=11"},
		{"BthPort.NT.CopyFiles=12", "BthPort.NT.CopyFiles=12,Fixture"},
		{"BthPort.NT.CopyFiles=12", "BthPort.NT.CopyFiles=12\r\nBthPort.NT.CopyFiles=12"},
		{"bthusb.sys,,,0x100", "bthusb.sys,alternate.sys,,0x100"},
		{"bthusb.sys,,,0x100", "bthusb.sys,,,0x104"},
		{"bthport.sys,,,0x100", "bthport.sys,,,0x100\r\nbthport.sys,,,0x100"},
		{"bthport.sys,,,0x100", "bthport.sys,,,0x100\r\n[BthPort.NT.CopyFiles.Security]\r\n"
								"\"D:P(A;;GA;;;SY)\""},
	}} ; // 参照順、元パス、宛先、フラグ、権限の独立した差

	std::array<wchar_t, MAX_PATH>
			   directory{} ;	// 実SetupAPIが展開する値との比較に使う現Windowsの位置
	// 正例の参照先を組み立てるために現在のWindowsディレクトリの長さを取得する
	const auto length = GetWindowsDirectoryW( directory.data(), static_cast<UINT>( directory.size())) ;
	// OS情報の読み取り不成立を試験成功にしない
	if( length == 0U || length >= directory.size()) {
		throw std::runtime_error( "fixture cannot read Windows directory") ;
	}

	const auto drivers =
		std::wstring{directory.data(), length} + L"\\System32\\drivers" ;	// 正例の配備先
	Fixture	   fixture( Fault::NONE) ;										// 現試験中だけ所有する架空INF領域
	const auto baseline =
		// 元対照を追跡する相対位置とバイト
		fixture.file( L"bluetooth-copy.inf", INF) ;
	const auto path = fixture.workspace.path( baseline.relativePath) ;	// 試験用INFの読み取り位置
	DRIVERCRATE_EXPECT( context, verifyBluetoothUsbCopyDeclarationForTest( path, drivers) == 0U) ;
	DRIVERCRATE_EXPECT(
		context, verifyBluetoothUsbCopyDeclarationForTest( path, drivers + L"\\Fixture") != 0U) ;

	std::size_t index{} ;	// 各負例を別のファイルへ保存する番号
	// 一条件だけ変えた元INFを順に読み取り、余分なコピーと別宛先を個別に拒否する
	for( const auto &change : CHANGES) {
		std::string modified{INF} ;								// この負例だけの元内容
		const auto	position = modified.find( change.first) ;	// 基準入力の置換位置
		modified.replace( position, change.first.size(), change.second) ;
		const auto member = fixture.file( L"bluetooth-copy-" + std::to_wstring( ++index) + L".inf",
										 modified) ;	// 他の負例と共有しない元INF
		DRIVERCRATE_EXPECT( context,
						   verifyBluetoothUsbCopyDeclarationForTest(
							   fixture.workspace.path( member.relativePath), drivers) != 0U) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief BluetoothとPCIの機器相対作用を架空の二文書の正負対照で確認する
 * @param[in,out] context 同じプロセスの試験集計
 * @note SetupAPIでテスト領域内の宣言を読み取る。機器のキーは開かず設定を適用しない
 */
//------------------------------------------------------------------------------
void scopedBluetoothUsbHardwareCases( TestContext &context)
{
	constexpr std::string_view BLUETOOTH =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\n"
		"[BthUsb.NT.HW]\r\nAddReg=BthPort.NT.HW.AddReg\r\nDelReg=BthPort.NT.HW.DelReg\r\n"
		"Include=pci.inf\r\nNeeds=PciD3ColdSupported.HW\r\n"
		"[BthPort.NT.HW.AddReg]\r\nHKR,,Scans Before Out of Range,0x10003,8\r\n"
		"HKR,,SCO Max Channels,0x10001,2\r\n"
		"HKR,,Store Link Key COD Masks,1,00,00,1f,43,00,00,05,40,00,00,1f,83,00,00,05,80\r\n"
		"[BthPort.NT.HW.DelReg]\r\nHKR,,Scans Before Out of Range,0\r\n"
		"HKR,,SCO Max Channels,0\r\nHKR,,Store Link Key COD Masks,0\r\nHKR,,SCO Support Level,0\r\n" ;	// 架空Bluetooth
	constexpr std::string_view PCI =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\n"
		"[PciD3ColdSupported.HW]\r\nAddReg=PciD3ColdSupported.RegHW\r\n"
		"[PciD3ColdSupported.RegHW]\r\n"
		"HKR,e5b3b5ac-9725-4f78-963f-03dfb1d828c7,D3ColdSupported,0x10001,1\r\n" ;	// 架空PCI
	constexpr std::array<std::pair<std::string_view, std::string_view>, 13U> BLUETOOTH_CHANGES{{
		{"AddReg=BthPort.NT.HW.AddReg\r\nDelReg=BthPort.NT.HW.DelReg",
		 "DelReg=BthPort.NT.HW.DelReg\r\nAddReg=BthPort.NT.HW.AddReg"},
		{"Needs=PciD3ColdSupported.HW", "Needs=PciD3ColdSupported.HW,Unexpected.HW"},
		{"DelReg=BthPort.NT.HW.DelReg", "AddReg=BthPort.NT.HW.DelReg"},
		{"HKR,,SCO Support Level,0", "HKLM,,SCO Support Level,0"},
		{"HKR,,SCO Support Level,0", "HKR,Other,SCO Support Level,0"},
		{"HKR,,SCO Support Level,0", "HKR,,,0"},
		{"HKR,,SCO Support Level,0", "HKR,,SCO Support Level"},
		{"HKR,,SCO Support Level,0", "HKR,,SCO Support Level,"},
		{"HKR,,SCO Support Level,0", "HKR,,SCO Support Level,0x4000"},
		{"Scans Before Out of Range,0x10003,8", "Scans Before Out of Range,0x10001,8"},
		{"00,00,1f,43", "00,00,1f,44"},
		{"00,00,1f,43", ",00,1f,43"},
		{"HKR,,SCO Support Level,0", "HKR,,SCO Support Level,0\r\n[BthPort.NT.HW.DelReg.Security]"},
	}} ; // Bluetoothの元参照、値操作、場所、型、ACLの違い
	constexpr std::array<std::pair<std::string_view, std::string_view>, 4U>	 PCI_CHANGES{{
		 {"e5b3b5ac-9725-4f78-963f-03dfb1d828c7", ""},
		 {"e5b3b5ac-9725-4f78-963f-03dfb1d828c7", "e5b3b5ac-9725-4f78-963f-03dfb1d828c8"},
		 {"D3ColdSupported,0x10001,1", "D3ColdSupported,0x10001,0"},
		 {"AddReg=PciD3ColdSupported.RegHW", "AddReg=PciD3ColdSupported.RegHW\r\nDelReg=Other"},
	 }} ; // 同梱PCIの設定と所有節の違い
	Fixture	   fixture( Fault::NONE) ;	// この試験専用の元INF領域
	const auto bluetooth =
		// 正例Bluetoothの位置
		fixture.file( L"bluetooth-hardware.inf", BLUETOOTH) ;
	const auto pci = fixture.file( L"pci-hardware.inf", PCI) ;	// 正例PCIの位置
	const auto bluetoothPath =
		// 読み取り用元Bluetooth
		fixture.workspace.path( bluetooth.relativePath) ;
	const auto pciPath = fixture.workspace.path( pci.relativePath) ;	// 読み取り用元PCI
	DRIVERCRATE_EXPECT( context,
					   verifyBluetoothUsbHardwareDeclarationsForTest( bluetoothPath, pciPath) == 0U) ;
	DRIVERCRATE_EXPECT( context,
					   verifyBluetoothUsbHardwareDeclarationsForTest( pciPath, bluetoothPath) != 0U) ;

	std::size_t index{} ;	// 各負例の一意な試験ファイル番号
	const auto	modifiedPath = [&fixture, &index]( std::string_view text, const auto &change) {
		 std::string modified{text} ;	// 一つの条件だけを変更する元入力
		 modified.replace( modified.find( change.first), change.first.size(), change.second) ;
		 const auto member =
			 fixture.file( L"bluetooth-settings-" + std::to_wstring( ++index) + L".inf",
						  modified) ;	// 書換え前後を別の位置にする
		 return fixture.workspace.path( member.relativePath) ;
	} ; // 同期中だけ試験領域と番号を借用する

	// Bluetooth側だけを変え、別文書の正しい設定で不足が補われないことを確認する
	for( const auto &change : BLUETOOTH_CHANGES) {
		DRIVERCRATE_EXPECT( context, verifyBluetoothUsbHardwareDeclarationsForTest(
										modifiedPath( BLUETOOTH, change), pciPath) != 0U) ;
	}

	// PCI側だけを変え、同じ名前でも元の位置・型・値に結び付かない設定を拒否する
	for( const auto &change : PCI_CHANGES) {
		DRIVERCRATE_EXPECT( context, verifyBluetoothUsbHardwareDeclarationsForTest(
										bluetoothPath, modifiedPath( PCI, change)) != 0U) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief NeedsのHKR設定を正負の実INFと有限予算で検査します
 * @param[in,out] context 同一processの集計です
 */
//------------------------------------------------------------------------------
void needsRegistry( TestContext &context)
{
	InfDependencyNativeResult graph ;	// 架空identityだけの文脈伝播graphです
	graph.dependency.sections = {{1U, L"Install", InfDependencyReadState::PRESENT},
								 {1U, L"Install.HW", InfDependencyReadState::PRESENT},
								 {1U, L"Install.Services", InfDependencyReadState::PRESENT},
								 {2U, L"Shared", InfDependencyReadState::PRESENT},
								 {3U, L"Shared", InfDependencyReadState::PRESENT}} ;
	graph.dependency.edges	  = {{1U, L"Install", L"Shared", InfDependencyDirective::NEEDS,
								  InfDependencyState::RESOLVED_SYSTEM, InfDependencyReason::NONE, 2U,
								  1U}} ;
	const std::array<std::wstring, 3U> seeds{L"Install", L"Install.HW",
											 L"Install.Services"} ;	// 同rootだけです
	const auto						   initial =
		// identityが違う同名節は除きます
		inspectNeedsRegistryContextsForTest( graph, seeds, 1U) ;
	DRIVERCRATE_EXPECT( context, (initial == std::vector<unsigned char>{1U, 2U, 4U, 1U, 0U})) ;
	graph.dependency.edges.push_back( {1U, L"Install.HW", L"Shared", InfDependencyDirective::NEEDS,
									  InfDependencyState::RESOLVED_SYSTEM,
									  InfDependencyReason::NONE, 2U, 1U}) ;
	const auto shared =
		// 両device文脈を保持します
		inspectNeedsRegistryContextsForTest( graph, seeds, 1U) ;
	DRIVERCRATE_EXPECT( context, shared[3U] == 3U && shared[4U] == 0U) ;
	graph.dependency.edges.push_back(
		{1U, L"Install.Services", L"Shared", InfDependencyDirective::NEEDS,
		 InfDependencyState::RESOLVED_SYSTEM, InfDependencyReason::NONE, 2U, 1U}) ;
	const auto mixed =
		// Servicesの拒否bitを消しません
		inspectNeedsRegistryContextsForTest( graph, seeds, 1U) ;
	DRIVERCRATE_EXPECT( context, mixed[3U] == 7U) ;
	const auto wrongRoot =
		// 別rootから権限を作りません
		inspectNeedsRegistryContextsForTest( graph, seeds, 9U) ;
	DRIVERCRATE_EXPECT(
		context, std::ranges::all_of( wrongRoot, []( const auto value) { return value == 0U ; })) ;
	const auto missingSeeds =
		// 空選択を基本節へ補完しません
		inspectNeedsRegistryContextsForTest( graph, {}, 1U) ;
	DRIVERCRATE_EXPECT(
		context, std::ranges::all_of( missingSeeds, []( const auto value) { return value == 0U ; })) ;
	const std::array<std::string, 3U> malformed{
		"[Install]\r\nAddReg=Absent\r\n[Other]\r\nHKR,,Setting,0,text\r\n",
		"[Install]\r\nAddReg=Settings\r\n[Other]\r\nHKR,,Setting,0,text\r\n",
		"[Install]\r\nAddReg=" + std::string( 65U * 9U, 'x') + "\r\n"} ;	// 欠損/別節/長さの原拒否です
	// 正常行が別節にあっても欠損した正確な参照先の代わりにしません
	for( const auto &body : malformed) {
		Fixture		fixture( Fault::NONE, {}, body) ;	// この条件だけの閉じた架空INFです
		std::size_t rows{} ;							// 参照拒否前に成功行を付与しません
		DRIVERCRATE_EXPECT( context, inspectNeedsAddRegForTest( fixture.workspace.path( L"root.inf"),
															  1U, rows) != 0U) ;
		DRIVERCRATE_EXPECT( context, rows == 0U) ;
	}

	/** @brief 正負一条件の原宣言と元文脈を固定します */
	struct Case {
		/// 元Settingsの全行と追加節です
		std::string	  rows ;
		/// 同選択からの文脈bitです
		unsigned char contexts ;
		/// 処理前の累積行数です
		std::size_t	  before ;
		/// 元全宣言の期待可否です
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
		{"HKR,,Setting,0,text,extra\r\n", 1U, 0U, false}} ;	// 元型と後続行拒否を独立にします
	// 一条件一元INFで全行を読み、元予算を成功後の値へ書き換えません
	for( const auto &testCase : cases) {
		const std::string body = "[Install]\r\nAddReg=Settings\r\n[Settings]\r\n" +
								 testCase.rows ;		// 架空の到達先だけです
		Fixture	   fixture( Fault::NONE, {}, body) ;	// 署名fakeをparser成功の証拠へ使いません
		auto	   rows = testCase.before ;				// 呼出し前の有限予算です
		// 全field/全行の元parser診断を一条件へ結合します
		const auto error =
			inspectNeedsAddRegForTest( fixture.workspace.path( L"root.inf"), testCase.contexts, rows) ;
		DRIVERCRATE_EXPECT( context, (error == 0U) == testCase.accepted) ;
		// 全成功では一行以上が検査され、累積上限を守る必要があります
		if( testCase.accepted && error == 0U) {
			DRIVERCRATE_EXPECT( context, rows > testCase.before && rows <= 4096U) ;
		}
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 実AddReg readerの元返却値と最初の閉じた拒否leafを確認します
 * @param[in,out] context 同同期の原assertion集計です
 * @note 実registryへ適用せず、所有fixtureの元INFを診断あり/なしで読みます
 */
//------------------------------------------------------------------------------
void needsRegistryDiagnostics( TestContext &context)
{
	using Stage = NeedsAddRegDiagnosticStage ;	// 製品の明示値です
	/** @brief 実INFへ与える一つの元条件と独立した期待です */
	struct Case {
		/// Version節以外の元INF全行です
		std::string	  body ;
		/// 元DDInstall/HWのcontext bitです
		unsigned char contexts ;
		/// 呼出し前の累積行数です
		std::size_t	  before ;
		/// 成功は0、拒否は製品の明示stageです
		std::uint32_t stage ;
		/// 有界件数/固定enum/SDK flagsだけの期待です
		std::uint32_t observed ;
		/// 方針の元HRESULTです。reader値未固定は0で診断なしの原errorへ照合します
		NativeError	  error ;
	} ;
	const auto setting = []( const std::string_view rows) {
		return "[Install]\r\nAddReg=Settings\r\n[Settings]\r\n" + std::string( rows) ;
	} ; // 架空の正確な参照節だけを所有copyにします
	const NativeError unsupported = HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;	// 元方針です
	const NativeError invalid	  = E_INVALIDARG ;								// 元数値parser失敗をAPI errorで置換しません
	std::string		  many		  = "[Install]\r\nAddReg=" ;					// 元64参照上限を一件だけ超えます
	// 65個の短い正確な節名でfield数だけを変えます
	for( unsigned index{}; index < 65U; ++index) {
		many += index == 0U ? "Settings" : ",Settings" ;
	}

	many += "\r\n[Settings]\r\nHKR,,Setting,0,text\r\n" ;
	const auto number = []( const Stage stage) {
		return static_cast<std::uint32_t>( stage) ;
	} ; // 閉enumの数値化です
	const std::vector<Case> cases{
		{setting( "HKR,,Setting,0,text\r\n"), 1U, 0U, 0U, 0U, 0U},
		{setting( "HKR,,Setting,0,text\r\n"), 0U, 0U, number( Stage::CONTEXT), 0U, unsupported},
		{setting( "HKR,,Setting,0,text\r\n"), 5U, 0U, number( Stage::CONTEXT), 5U, unsupported},
		{many, 1U, 0U, number( Stage::REFERENCE_COUNT), 65U, unsupported},
		{setting( "HKR,,Setting,0,text\r\n"), 1U, 4097U, number( Stage::INITIAL_ROW_BUDGET), 4097U,
		 unsupported},
		{"[Install]\r\nAddReg=Bad[]\r\n", 1U, 0U, number( Stage::SECTION_NAME), 1U, invalid},
		{setting( "HKR,,Setting,0,text\r\n[Settings.security]\r\n\"D:P\"\r\n"), 1U, 0U,
		 number( Stage::SECURITY_DECLARATION), 1U, unsupported},
		{"[Install]\r\nAddReg=Absent\r\n", 1U, 0U, number( Stage::SECTION_ROWS), 0U,
		 HRESULT_FROM_WIN32( ERROR_SECTION_NOT_FOUND)},
		{setting( "HKR,,Setting,0,text\r\n"), 1U, 4096U, number( Stage::ROW_BUDGET), 4097U,
		 HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW)},
		{setting( "HKR,Setting\r\n"), 1U, 0U, number( Stage::FIELD_COUNT), 2U, unsupported},
		{setting( "HKR,,Setting,0,text,extra\r\n"), 1U, 0U, number( Stage::FIELD_COUNT), 6U,
		 unsupported},
		{setting( "HKR,,Setting,0," + std::string( 255U, 'x') + "\r\n"), 1U, 0U,
		 number( Stage::FIELD_READ), 5U, 0U},
		{setting( "HKLM,,Setting,0,text\r\n"), 1U, 0U, number( Stage::ROOT), 0U, unsupported},
		{setting( "HKR,\"..\\Escape\",Setting,0,text\r\n"), 1U, 0U, number( Stage::SUBKEY_COMPONENT),
		 0U, unsupported},
		{setting( "HKR,\"Trailing\\\",Setting,0,text\r\n"), 1U, 0U,
		 number( Stage::SUBKEY_TRAILING_SEPARATOR), 0U, unsupported},
		{setting( "HKR,,UpperFilters,0,text\r\n"), 1U, 0U, number( Stage::SPECIAL_VALUE), 4U,
		 unsupported},
		{setting( "HKR,,Setting,bad-flags,text\r\n"), 1U, 0U, number( Stage::FLAGS_PARSE), 0U,
		 invalid},
		{setting( "HKR,,Setting,0x00010000,text\r\n"), 1U, 0U, number( Stage::FLAGS), 0x00010000U,
		 unsupported},
		{setting( "HKR,,Setting,0x00010001,bad-number\r\n"), 1U, 0U, number( Stage::DWORD_VALUE), 5U,
		 invalid},
		{setting( "HKR,,Setting,0x00010001\r\n"), 1U, 0U, number( Stage::DWORD_VALUE), 4U, invalid},
		{setting( "HKR,,Setting,0,file.exe\r\n"), 1U, 0U, number( Stage::PROGRAM_REFERENCE), 1U,
		 unsupported},
		{setting( "HKR,,Setting,0,file.dll\r\n"), 1U, 0U, number( Stage::PROGRAM_REFERENCE), 2U,
		 unsupported},
		{setting( "HKR,,Setting,0,file.sys\r\n"), 1U, 0U, number( Stage::PROGRAM_REFERENCE), 3U,
		 unsupported},
		{setting( "HKR,,Setting,0,file.com\r\n"), 1U, 0U, number( Stage::PROGRAM_REFERENCE), 4U,
		 unsupported}} ;	// 元方針を合法構文の新許可へ変更しません
	// 同じ実byteを診断なし/ありで読み、成功DTOから期待を作りません
	for( const auto &testCase : cases) {
		Fixture	   fixture( Fault::NONE, {}, testCase.body) ;	// 同scopeで完全cleanupします
		auto	   originalRows = testCase.before ;				// 診断なしの元累積です
		const auto original		= inspectNeedsAddRegForTest(
			// 元API境界です
			fixture.workspace.path( L"root.inf"), testCase.contexts, originalRows) ;
		auto						 rows = testCase.before ;	// 同一入力の独立累積です
		RequiredInfBindingDiagnostic diagnostic ;				// 一条件だけの未記録診断です
		const auto					 error =
			inspectNeedsAddRegForTest( fixture.workspace.path( L"root.inf"), testCase.contexts, rows,
									  &diagnostic) ;	// 製品parserです
		DRIVERCRATE_EXPECT( context, error == original && rows == originalRows) ;
		// 正常結果へ架空の拒否leafを付与しません
		if( testCase.stage == 0U) {
			DRIVERCRATE_EXPECT( context, error == 0U &&
											diagnostic.rejection == InfBindingReject::NONE &&
											diagnostic.stage == 0U) ;
		} else {
			DRIVERCRATE_EXPECT( context,
							   error != 0U && (testCase.error == 0U || error == testCase.error)) ;
			DRIVERCRATE_EXPECT( context, diagnostic.rejection == InfBindingReject::DEPENDENCY &&
											diagnostic.stage == testCase.stage &&
											diagnostic.observed == testCase.observed) ;
		}
	}

	Fixture fixture( Fault::NONE, {}, setting( "HKR,,Setting,0x00010000,text\r\n")) ;	// 同じ元拒否です
	RequiredInfBindingDiagnostic first ;												// 先行する別拒否を保持します
	first.stage = 999U ;
	static_cast<void>( first.reject( invalid, InfBindingReject::ARCHITECTURE, 77U)) ;
	std::size_t rows{} ;	// 元累積だけです
	const auto	error = inspectNeedsAddRegForTest( fixture.workspace.path( L"root.inf"), 1U, rows,
												  &first) ;	// 後段の同parserです
	DRIVERCRATE_EXPECT( context, error == unsupported &&
									first.rejection == InfBindingReject::ARCHITECTURE &&
									first.stage == 999U && first.observed == 77U) ;
	std::cout << "NEEDS_ADDREG_DIAGNOSTICS cases=" << cases.size()
			  << " firstError=1 nativeRegistryWrites=0\n" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実Common入口の正規選択文脈と同名二段転送・HW効果を確認します
 * @param[in,out] context 元assertion集計先です
 */
//------------------------------------------------------------------------------
void selectedCommonContext( TestContext &context)
{
	// HWの正当なHKRと拒否すべきHKLMだけを別fixtureへ渡します
	for( unsigned scenario{}; scenario < 2U; ++scenario) {
		const std::string rootBody =
			"Class=Net\r\nClassGUID={4d36e972-e325-11ce-bfc1-08002be10318}\r\n"
			"Provider=Fixture Provider\r\nDriverVer=01/01/2026,2.0.0.0\r\nCatalogFile=fixture.cat\r\n"
			"[Manufacturer]\r\nMaker=Models,NTamd64\r\n[Models.NTamd64]\r\n"
			"Device=Install,PCI\\SYNTH_INCLUDE_CONTEXT\r\n"
			"[Install.NTamd64]\r\nCopyFiles=@driver.sys\r\nInclude=peer.inf\r\n"
			"[Install.NTamd64.HW]\r\nNeeds=Shared.HW\r\n"
			// 実device/元vendor本文を含まない原選択です
			"[DestinationDirs]\r\nDefaultDestDir=12\r\n[SourceDisksNames]\r\n1=fixture,,,\r\n[SourceDisksFiles]\r\ndriver.sys=1\r\n" ;
		Fixture			  fixture( Fault::NONE, "Include=leaf.inf\r\nNeeds=Shared.HW\r\n", rootBody,
								  "Shared.HW") ;	// 同名転送元です
		const std::string leaf =
			"[Version]\r\nSignature=\"$Windows NT$\"\r\n[Shared.HW]\r\nAddReg=Settings\r\n[Settings]\r\n" +
			std::string( scenario == 0U
							? "HKR,,PowerFlag,0x00010001,1\r\n"
							: "HKLM,,PowerFlag,0x00010001,1\r\n") ;	// registry変更は実行しません
		(void)fixture.file( L"windows\\INF\\leaf.inf", leaf) ;
		(void)fixture.file( L"windows\\System32\\DriverStore\\FileRepository\\fixture\\leaf.inf",
						   leaf) ;
		fixture.api.infSignature = [&fixture]( const std::wstring   &path,
											  SP_INF_SIGNER_INFO_W &signer) -> NativeError {
			const bool system = path == fixture.workspace.path( L"windows\\INF\\peer.inf") ||
								path == fixture.workspace.path(
											L"windows\\INF\\leaf.inf") ;	// 架空inbox二資料だけです
			// このfixture外のINFへ署名成功を返しません
			if( !system && path != fixture.workspace.path( L"root.inf")) {
				return E_INVALIDARG ;
			}

			const auto catalog =
				fixture.workspace.path( system ? L"windows\\System32\\CatRoot\\fixture.cat"
											  : L"fixture.cat") ;	// 同じ元CATです
			const std::wstring signerName = L"Synthetic signer" ;	// 実署名者ではありません
			// 固定SDK bufferを超える応答は拒否します
			if( catalog.size() >= MAX_PATH || signerName.size() >= MAX_PATH) {
				return E_INVALIDARG ;
			}

			std::copy( catalog.c_str(), catalog.c_str() + catalog.size() + 1U, signer.CatalogFile) ;
			std::copy( signerName.c_str(), signerName.c_str() + signerName.size() + 1U,
					  signer.DigitalSigner) ;
			signer.SignerScore = system ? SIGNERSCORE_INBOX : SIGNERSCORE_WHQL ;
			return 0 ;
		} ; // 既test APIの同期寿命だけで借用します
		fixture.api.catalogSignature = [&fixture]( const auto &, auto paths) -> NativeError {
			// 元INF自身だけのmember検査をfake化します
			if( paths.size() != 1U ||
			   (paths.front() != fixture.workspace.path( L"root.inf") &&
				paths.front() != fixture.workspace.path( L"windows\\INF\\peer.inf") &&
				paths.front() != fixture.workspace.path( L"windows\\INF\\leaf.inf"))) {
				return E_INVALIDARG ;
			}

			return 0 ;
		} ;
		fixture.api.driverStore = [&fixture]( const auto &path, auto &location) -> NativeError {
			// 元二資料以外のStore成功を作りません
			if( path != fixture.workspace.path( L"windows\\INF\\peer.inf") &&
			   path != fixture.workspace.path( L"windows\\INF\\leaf.inf")) {
				return E_INVALIDARG ;
			}

			const auto leafName = path.substr( path.find_last_of( L'\\') + 1U) ;	// 同じ元leaf名です
			location			= fixture.workspace.path(
				   L"windows\\System32\\DriverStore\\FileRepository\\fixture\\" + leafName) ;
			return 0 ;
		} ;
		const auto driverMember =
			// 実行しない原SYS byteです
			fixture.file( L"driver.sys", "synthetic kernel driver") ;
		OfficialZipEntry driverEntry{driverMember.relativePath,
									 driverMember.byteCount} ;	// 元検査集合だけです
		driverEntry.sha256 = driverMember.sha256 ;
		CommonInfInspection inspected ;	// 私有入口が前後に再検証するfixtureだけです
		inspected.scanSessionId	  = 8806U ;
		inspected.infRelativePath = L"root.inf" ;
		inspected.state			  = CommonInfInspectionState::VERIFIED ;
		inspected.workspace		  = std::shared_ptr<OfficialDownloadWorkspace>(
			  &fixture.workspace,
			  []( OfficialDownloadWorkspace *) {}) ;							// 所有はFixtureに残し、この同期callだけ借用します
		OfficialZipEntry rootEntry{L"root.inf", fixture.members[0].byteCount} ;	// 実root byteです
		rootEntry.sha256 = fixture.members[0].sha256 ;
		OfficialZipEntry catalogEntry{L"fixture.cat",
									  // 実CAT byteです
									  std::string_view( "synthetic package catalog").size()} ;
		DRIVERCRATE_EXPECT( context, computeFileSha256( fixture.workspace.path( L"fixture.cat"),
													  catalogEntry.sha256) == 0) ;
		inspected.closure.entries = {rootEntry, catalogEntry, driverEntry} ;
		const std::array classes{std::wstring_view( L"Net")} ;				// 架空基本driver classです
		const std::array signatures{std::wstring_view( L"$Windows NT$")} ;	// INF書式だけです
		OfficialInfInspectionPolicy policy{
			32U, 32U, classes, {}, signatures} ;	// 内容parserの正規入力です
		policy.acceptAnyProvider			 = true ;
		policy.allowRequiredDriverComponents = true ;
		OfficialInfPackage original ;	// 実内容parserが返す元metadataです
		const auto		   parsed =
			inspectOfficialInfPackage( fixture.workspace, inspected.closure.entries, L"root.inf",
									  policy, original) ;	// 元byteを読みます
		DRIVERCRATE_EXPECT( context, parsed == 0) ;
		// 不正な架空内容を製品私有入口へ渡しません
		if( parsed != 0) {
			throw std::runtime_error( "common include fixture content rejected") ;
		}

		inspected.closure.packages.push_back( original) ;
		OfficialInfPackage selected ;	// 正規のselected基本/付属を実readerで得ます
		const auto		   selectedError = inspectSelectedOfficialInfRelations(
			fixture.workspace, inspected.closure.entries, original, L"Install",
			selected) ;	// 装飾をfixtureで補完しません
		DRIVERCRATE_EXPECT( context, selectedError == 0 &&
										selected.selectedInstallSection == L"Install.NTamd64") ;
		const std::array<std::wstring, 2U> seeds{L"Install.NTamd64",
												 L"Install.NTamd64.HW"} ;	// 元実在節だけです
		InfDependencyNativeResult		   legacy ;							// null文脈の旧入口は共有しません
		DRIVERCRATE_EXPECT( context, inspectInfDependenciesWithTestApi(
										fixture.api, fixture.workspace, fixture.members, 0U, seeds,
										8806U, legacy) == 0 &&
										!legacy.dependency.plan.referencesResolved) ;
		commonContentUnderTest = &inspected ;
		commonContentRechecks  = 0U ;
		InfDependencyNativeResult	 result ;		// 実Common入口から返るgraphだけです
		RequiredInfBindingDiagnostic diagnostic ;	// 効果の元数値だけです
		const auto					 error =
			inspectCommonInfDependenciesWithTestApi( fixture.api, inspected, selected, result,
													&diagnostic) ;	// 製品の文脈構築を迂回しません
		commonContentUnderTest = nullptr ;
		std::cout << "COMMON_SELECTED_CONTEXT case=" << scenario << " error=" << error
				  << " stage=" << diagnostic.stage
				  << " registryRows=" << diagnostic.verifiedRegistryRowCount
				  << " contentRechecks=" << commonContentRechecks << std::endl ;
		DRIVERCRATE_EXPECT( context, scenario == 0U ? error == 0 : error != 0) ;
		DRIVERCRATE_EXPECT( context, commonContentRechecks >= 2U) ;
		// 正例は二段の元NeedsとHW用HKR一行を完全に検査します
		if( scenario == 0U) {
			DRIVERCRATE_EXPECT( context, result.dependency.plan.referencesResolved &&
											result.dependency.plan.rootEvidenceVerified &&
											diagnostic.verifiedRegistryRowCount == 1U) ;
			const auto contexts = inspectNeedsRegistryContextsForTest(
				result, seeds, result.dependency.documents.front().identity) ;	// 元HW文脈です
			const auto leafSection =
				std::ranges::find_if( result.dependency.sections, [&]( const auto &section) {
					return section.identity == result.dependency.documents.back().identity &&
						   section.section == L"Shared.HW" ;
				}) ; // 正確な転送終端だけです
			DRIVERCRATE_EXPECT( context,
							   leafSection != result.dependency.sections.end() &&
								   contexts[static_cast<std::size_t>(
									   leafSection - result.dependency.sections.begin())] == 2U) ;
		} else {
			DRIVERCRATE_EXPECT( context, result.dependency.documents.empty()) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 架空標準Needsを持つ元基本INF本文を生成します
 * @param[in] include 同選択から明示する参照INFです
 * @param[in] needs 同選択から明示する正確な節です
 * @return 実ID/Windows原文を含まない固定metadataと選択関係です
 */
//------------------------------------------------------------------------------
std::string systemMediaRoot( std::string_view include = "peer.inf",
							std::string_view needs	 = "Shared")
{
	return "Class=Net\r\nClassGUID={4d36e972-e325-11ce-bfc1-08002be10318}\r\n"
		   "Provider=Fixture\r\nDriverVer=01/01/2026,2.0.0.0\r\nCatalogFile=fixture.cat\r\n"
		   "[Manufacturer]\r\nMaker=Models,NTamd64\r\n[Models.NTamd64]\r\n"
		   "Device=Install,PCI\\SYNTH_SYSTEM_MEDIA\r\n[Install.NTamd64]\r\nCopyFiles=@driver.sys\r\n"
		   "Include=" +
		   std::string( include) + "\r\nNeeds=" + std::string( needs) +
		   "\r\n[DestinationDirs]\r\nDefaultDestDir=12\r\n[SourceDisksNames]\r\n1=Fixture,,,\r\n"
		   "[SourceDisksFiles]\r\ndriver.sys=1\r\n" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元架空byteから実Common reader/私有Native入口を一度評価します
 * @param[in,out] fixture 同同期が所有する原INF/署名・OS APIです
 * @param[out] result 全native再確認成功時だけのgraphです
 * @param[out] diagnostic 元parser/効果の固定診断です
 * @return 元内容/選択/native parserのHRESULTです
 * @note 内容署名だけが専用fakeで、全原fileのsize/hash再確認を省略しません
 */
//------------------------------------------------------------------------------
NativeError evaluateSystemCommonFixture( Fixture &fixture, InfDependencyNativeResult &result,
										RequiredInfBindingDiagnostic &diagnostic)
{
	const auto driver =
		// 原payload byteです
		fixture.file( L"driver.sys", "fictional nonexecuting driver") ;
	CommonInfInspection inspected ;	// 同workspaceだけの私有入力です
	inspected.scanSessionId	  = 8847U ;
	inspected.infRelativePath = L"root.inf" ;
	inspected.state			  = CommonInfInspectionState::VERIFIED ;
	inspected.workspace		  = std::shared_ptr<OfficialDownloadWorkspace>(
		  &fixture.workspace,
		  []( OfficialDownloadWorkspace *) {}) ;						// 同期中だけ借用し、所有はFixtureに残します
	OfficialZipEntry root{L"root.inf", fixture.members[0].byteCount} ;	// 元INF tupleです
	root.sha256 = fixture.members[0].sha256 ;
	OfficialZipEntry catalog{
		L"fixture.cat", std::string_view( "synthetic package catalog").size()} ;	// 元CAT tupleです
	auto error =
		// 実byteです
		computeFileSha256( fixture.workspace.path( L"fixture.cat"), catalog.sha256) ;
	// Hash不明の内容を許可入力へ変換しません
	if( error != 0U) {
		return error ;
	}

	OfficialZipEntry payload{driver.relativePath, driver.byteCount} ;	// 元SYS tupleです
	payload.sha256			  = driver.sha256 ;
	inspected.closure.entries = {root, catalog, payload} ;
	const std::array			classes{std::wstring_view( L"Net")} ;				// 架空基本Classです
	const std::array			signatures{std::wstring_view( L"$Windows NT$")} ;	// INF書式だけです
	OfficialInfInspectionPolicy policy{32U, 32U, classes, {}, signatures} ;			// 既実readerのpolicyです
	policy.acceptAnyProvider			 = true ;
	policy.allowRequiredDriverComponents = true ;
	OfficialInfPackage original ;	// 実INF readerだけが作ります
	error = inspectOfficialInfPackage( fixture.workspace, inspected.closure.entries, L"root.inf",
									  policy, original) ;
	// 内容失敗は元HRESULTのままです
	if( error != 0U) {
		return error ;
	}

	inspected.closure.packages.push_back( original) ;
	OfficialInfPackage selected ;	// 同原INFのWindows選択関係です
	error = inspectSelectedOfficialInfRelations( fixture.workspace, inspected.closure.entries,
												original, L"Install", selected) ;
	// 原選択をfixtureの成功DTOで補完しません
	if( error != 0U) {
		return error ;
	}

	commonContentUnderTest = &inspected ;
	commonContentRechecks  = 0U ;
	error = inspectCommonInfDependenciesWithTestApi( fixture.api, inspected, selected, result,
													&diagnostic) ;
	commonContentUnderTest = nullptr ;
	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空SYSTEMの媒体/固定登録正負を実Common parserで確認します
 * @param[in,out] context 同期中だけの元assertion集計です
 * @note Windows原文や実GUIDを複写せず、実helper実行/registry/driverへ作用しません
 */
//------------------------------------------------------------------------------
void systemMediaCases( TestContext &context)
{
	const std::string category = "HKLM,SYSTEM\\CurrentControlSet\\Control\\MediaCategories\\"
								 "{10000000-0000-4000-8000-000000000001}," ;	// 架空標準scopeです
	const std::string mediaInterface =
		"HKLM,SYSTEM\\CurrentControlSet\\Control\\MediaInterfaces\\"
		"{10000000-0000-4000-8000-000000000002}," ;	// 独立した架空GUIDです
	const std::string arguments =
		"{10000000-0000-4000-8000-000000000003},"
		"{10000000-0000-4000-8000-000000000004},{10000000-0000-4000-8000-000000000005}" ;	// 三つの架空GUIDです
	const std::string run =
		"HKLM,SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce,FixtureRegister,0,\"" ;	// 同原文の一値です
	// interfaceが追加する二行を後続HKRへ持ち越す独立条件です
	std::string nearLimit ;
	// 元節4095行がinterface追加後に4097行となる入力を作ります
	for( unsigned index = 0U; index < 4093U; ++index) {
		nearLimit += "HKR,,Setting,0,text\r\n" ;
	}

	nearLimit +=
		run + "rundll32.exe streamci,StreamingDeviceSetup " + arguments +
		",${FIXTURE_SYSTEM_INF},Interface\"\r\nHKR,,AfterInterface,0,text\r\n"
		"[Interface]\r\nAddReg=Interface.Settings\r\n[Interface.Settings]\r\n"
		"HKR,,CLSID,0,{10000000-0000-4000-8000-000000000006}\r\nHKR,,FriendlyName,0,Fixture interface\r\n" ;
	/** @brief 元宣言だけを変える独立正負条件です */
	struct Case {
		/// 同SYSTEM Settingsの元行です
		std::string rows ;
		/// 閉じた作用としての独立期待です
		bool		accepted ;
		/// 原helper trustの元error又はtuple変化を注入します。0正常/1拒否/2差分/3不足/4非INBOXです
		unsigned	fault{} ;
	} ;
	const std::vector<Case> cases{
		{category + "Name,0,Fixture category\r\n", true},
		{category + "Name,Fixture category\r\n", true},
		{category + "Name,12invalid\r\n", false},
		{category + "Name,0xinvalid\r\n", false},
		{category + "Name,unknown.dll\r\n", false},
		{category + "Name,\r\n", false},
		{category + "Other,Fixture category\r\n", false},
		{category + "\\PropertyPages\\{10000000-0000-4000-8000-000000000007},,0,\r\n", false},
		{category + "Display,1,01,00,ff,80\r\n", true},
		{mediaInterface + ",0,Fixture interface\r\n", true},
		{mediaInterface + "IID,1,00,00,00,00,01,02,03,04,05,06,07,08,09,0a,0b,ff\r\n", true},
		{category + "Name,0x4,Fixture\r\n", false},
		{category + "Display,1,00,00,00\r\n", false},
		{category + "Display,1,00,00,00,100\r\n", false},
		{mediaInterface + "IID,1,00,00,00,00\r\n", false},
		{category + "Unknown,0,Fixture\r\n", false},
		{category + "Name,0,unknown.dll\r\n", false},
		{"HKLM,SOFTWARE\\Unrelated,Name,0,Fixture\r\n", false},
		{"HKCU,,Name,0,Fixture\r\n", false},
		{"HKLM,SYSTEM\\CurrentControlSet\\Control\\MediaCategories\\invalid,Name,0,Fixture\r\n",
		 false},
		{category + "Name,0,Fixture\r\n[Settings.security]\r\n\"D:P\"\r\n", false},
		{run + "rundll32.exe streamci,StreamingDeviceSetup " + arguments + "\"\r\n", true},
		{run + "rundll32.exe streamci.dll,StreamingDeviceSetup " + arguments + "\"\r\n", true},
		{run + "rundll32.exe streamci,StreamingDeviceSetup " + arguments +
			 ",${FIXTURE_SYSTEM_INF},Interface\"\r\n[Interface]\r\nAddReg=Interface.Settings\r\n"
			 "[Interface.Settings]\r\nHKR,,CLSID,0,{10000000-0000-4000-8000-000000000006}\r\n"
			 "HKR,,FriendlyName,0,Fixture interface\r\n",
		 true},
		{run + "rundll32.exe streamci,StreamingDeviceSetup " + arguments +
			 ",C:\\Other\\wrong.inf,Interface\"\r\n",
		 false},
		{run + "rundll32.exe streamci,StreamingDeviceSetup " + arguments +
			 ",${FIXTURE_SYSTEM_INF},Absent\"\r\n",
		 false},
		{run + "rundll32.exe streamci,StreamingDeviceSetup " + arguments +
			 ",${FIXTURE_SYSTEM_INF},Interface\"\r\n[Interface]\r\nRunPreSetupCommands=Unknown\r\n",
		 false},
		{run + "rundll32.exe other.dll,StreamingDeviceSetup " + arguments + "\"\r\n", false},
		{run + "rundll32.exe streamci,streamingdevicesetup " + arguments + "\"\r\n", false},
		{run + "rundll32.exe streamci,StreamingDeviceSetup " + arguments + ",extra\"\r\n", false},
		{run + "rundll32.exe streamci,StreamingDeviceSetup invalid," + arguments + "\"\r\n", false},
		{run + "cmd.exe /c anything\"\r\n", false},
		{run + "rundll32.exe streamci,StreamingDeviceSetup " + arguments + "\"\r\n", false, 1U},
		{run + "rundll32.exe streamci,StreamingDeviceSetup " + arguments + "\"\r\n", false, 2U},
		{run + "rundll32.exe streamci,StreamingDeviceSetup " + arguments + "\"\r\n", false, 3U},
		{category + "Name,0,Fixture category\r\n", false, 4U},
		{nearLimit, false}} ;	// 成功期待は元policyの都合で下げません
	unsigned ordinal{} ;		// 任意INF本文を出さない閉じた順序です
	// 一条件一所有fixtureで原byte/署名/文脈を独立に評価します
	for( const auto &test : cases) {
		Fixture fixture( Fault::NONE, "AddReg=Settings\r\n[Settings]\r\n" + test.rows,
						// 実Common入力です
						systemMediaRoot()) ;
		static_cast<void>(
			fixture.file( L"windows\\System32\\rundll32.exe", "fictional nonexecuting helper one")) ;
		static_cast<void>(
			fixture.file( L"windows\\System32\\streamci.dll", "fictional nonexecuting helper two")) ;
		unsigned trustCalls{} ;	// 同run終端の再検証でSD差を独立に注入します
		// 明示不足条件以外だけに、実fixture byteへ結合した完全な人工期待を与えます
		if( test.fault != 3U) {
			fixture.api.systemFileTrust = [&]( const std::wstring	 &path,
											  WindowsSystemFileTrust &proof) -> NativeError {
				++trustCalls ;
				// 指定した元trust errorをそのまま伝達します
				if( test.fault == 1U) {
					return E_ACCESSDENIED ;
				}

				const auto expected = fixture.workspace.path(
					L"windows\\System32\\rundll32.exe") ;	// 二原helperだけです
				const bool first = path == expected ;		// fixtureの独立した元byteです
				// 関係のないfileへ人工trustを返しません
				if( !first && path != fixture.workspace.path( L"windows\\System32\\streamci.dll")) {
					return E_INVALIDARG ;
				}

				proof.filePath = path ;
				proof.fileBytes =
					first ? std::string_view( "fictional nonexecuting helper one").size()
						  : std::string_view( "fictional nonexecuting helper two").size() ;
				proof.fileSecurity = {
					static_cast<std::byte>( test.fault == 2U && trustCalls > 2U ? 2U : 1U)} ;
				return computeFileSha256( path, proof.fileSha256) ;
			} ; // 実Windowsの署名/SD成功を表すものではありません
		}

		// 非INBOX由来をSYSTEM作用の許可へ昇格させません
		if( test.fault == 4U) {
			const auto original		 = fixture.api.infSignature ;	// 元完全署名表です
			fixture.api.infSignature = [original]( const auto &path, auto &signer) {
				const auto error   = original( path, signer) ;	// 元署名errorです
				signer.SignerScore = SIGNERSCORE_WHQL ;
				return error ;
			} ;
		}

		InfDependencyNativeResult	 result ;		// 実Common私有入口の結果です
		RequiredInfBindingDiagnostic diagnostic ;	// 同失敗の元数値です
		const auto					 error =
			// 実parserへ接続します
			evaluateSystemCommonFixture( fixture, result, diagnostic) ;
		std::cout << "SYSTEM_MEDIA_CASE ordinal=" << ++ordinal << " error=" << error
				  << " stage=" << diagnostic.stage << " observed=" << diagnostic.observed
				  << " rows=" << diagnostic.verifiedRegistryRowCount
				  << " helperProofs=" << result.systemFiles.size() << std::endl ;
		DRIVERCRATE_EXPECT( context, test.accepted ? error == 0U : error != 0U) ;
		DRIVERCRATE_EXPECT( context, test.accepted ? commonContentRechecks >= 2U
												  : result.dependency.documents.empty()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 架空SYSTEMのservice/framework/作用閉包を実Common parserで検証します
 * @param[in,out] context 同期中だけの元assertion集計です
 * @note 全SYS/DLL/CAT/署名入力をfixtureが所有し実driver/registryへ作用しません
 */
//------------------------------------------------------------------------------
void typedSystemCases( TestContext &context)
{
	const std::string root = systemMediaRoot() +	// 元所有scopeへ結ぶ位置です。任意探索へ使いません
							 "[Install.NTamd64.Services]\r\nInclude=peer.inf\r\nNeeds=Services\r\n"
							 "[Install.NTamd64.HW]\r\nInclude=peer.inf\r\nNeeds=Hardware\r\n"
							 "[Install.NTamd64.Wdf]\r\nInclude=peer.inf\r\nNeeds=Framework\r\n" ;
	const std::string normal =	// 固定契約から作る独立した正負の期待です
		"PreferDeviceInfo=1\r\nAddReg=DeviceData\r\nAddProperty=Properties\r\n"
		"[DeviceData]\r\nHKR,,DevLoader,0,*ntkern\r\nHKR,,NTMPDriver,0,dep.sys\r\n"
		"[Properties]\r\nGenericDriverInstalled,,,,1\r\n"
		"[Services]\r\nAddService=Dependency,2,Service\r\n"
		"[Service]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\nServiceBinary=${FIXTURE_SYSTEM_ROOT}\\System32\\drivers\\dep.sys\r\n"
		"[Hardware]\r\nAddReg=HardwareData\r\n[HardwareData]\r\n"
		"HKR,{10000000-0000-4000-8000-000000000001},D3ColdSupported,0x10001,1\r\n"
		"HKR,,LowerFilters,0x10000,Dependency\r\n"
		"[Framework]\r\nKmdfService=Dependency,Kernel\r\n[Kernel]\r\nKmdfLibraryVersion=1.15\r\n" ;
	/** @brief 一条件だけを元INF byteへ注入する独立期待です */
	struct Case {
		/// 元にある置換対象です。空は末尾追加です
		std::string before ;
		/// 原INFへの置換値です
		std::string after ;
		/// policy上の独立期待です
		bool		accepted{} ;
		/// 元module不在を注入する場合trueです
		bool		missing{} ;
	} ;
	const std::vector<Case> cases{
		// 固定契約から作る独立した正負の期待です
		{"", "", true},
		{"PreferDeviceInfo=1", "PreferDeviceInfo=0", false},
		{"DevLoader,0,*ntkern", "DevLoader,0,other", false},
		{"NTMPDriver,0,dep.sys", "NTMPDriver,0,other.sys", false},
		{"ServiceType=1", "ServiceType=16", false},
		{"StartType=3", "StartType=2", false},
		{"ErrorControl=1", "ErrorControl=0", false},
		{"ServiceBinary=${FIXTURE_SYSTEM_ROOT}\\System32\\drivers\\dep.sys",
		 "ServiceBinary=%11%\\dep.sys", false},
		{"LowerFilters,0x10000", "LowerFilters,0x10008", false},
		{"D3ColdSupported,0x10001,1", "D3ColdSupported,0x10001,2", false},
		{"KmdfLibraryVersion=1.15", "KmdfLibraryVersion=1.15.tail", false},
		{"AddService=Dependency,2,Service",
		 "AddService=Dependency,2,Service\r\nAddService=Dependency,2,Service", false},
		{"GenericDriverInstalled,,,,1", "GenericDriverInstalled,,,,0", false},
		{"HKR,,DevLoader", "HKCU,,DevLoader", false},
		{"", "\r\n[DeviceData.security]\r\n\"D:P\"\r\n", false},
		{"", "", false, true}} ;
	unsigned ordinal{} ;	// 元field/型の全消費を確認する局所位置又は閉じた分類です
	// 同所有fixtureの全対象を順に検査します
	for( const auto &test : cases) {	// 同所有fixtureの全対象を順に確認します
		auto body = normal ;			// この同期だけで保持する元値です。許可の代用にしません
		// 固定した入力条件だけを分離し、他対象や期待へ流用しません
		if( test.before.empty()) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			body += test.after ;
		} else {
			const auto position =
				// 元field/型の全消費を確認する局所位置又は閉じた分類です
				body.find( test.before) ;
			// 固定した入力条件だけを分離し、他対象や期待へ流用しません
			if( position ==
			   body.npos) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
				throw std::runtime_error( "typed fixture replacement missing") ;
			}

			body.replace( position, test.before.size(), test.after) ;
		}

		Fixture	   fixture( Fault::NONE, body, root) ;	// 同原文/操作へ結ぶ検査又は結果の所有値です
		const auto path = fixture.workspace.path(
			L"windows\\System32\\drivers\\dep.sys") ;	// 元所有scopeへ結ぶ位置です。任意探索へ使いません
		// 固定した入力条件だけを分離し、他対象や期待へ流用しません
		if( !test.missing) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			static_cast<void>(
				fixture.file( L"windows\\System32\\drivers\\dep.sys", "fictional protected module")) ;
		}

		fixture.api.systemFileTrust = [path]( const std::wstring		&actual,
											 WindowsSystemFileTrust &proof) -> NativeError {
			// 固定した入力条件だけを分離し、他対象や期待へ流用しません
			if( actual != path) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
				return E_INVALIDARG ;
			}

			proof.filePath	   = actual ;
			proof.fileBytes	   = std::string_view{"fictional protected module"}.size() ;
			proof.fileSecurity = {std::byte{1U}} ;
			return computeFileSha256( actual, proof.fileSha256) ;
		} ; // 人工trustも元file完全hashへ結び、実Windowsへfallbackしません
		InfDependencyNativeResult	 result ;		// 同原文/操作へ結ぶ検査又は結果の所有値です
		RequiredInfBindingDiagnostic diagnostic ;	// 同原文/操作へ結ぶ検査又は結果の所有値です
		const auto					 error = evaluateSystemCommonFixture(
			  fixture, result, diagnostic) ;	// 直後に保持した元API又は検査errorです
		std::cout << "SYSTEM_TYPED_CASE ordinal=" << ++ordinal << " error=" << error
				  << " stage=" << diagnostic.stage << " observed=" << diagnostic.observed << '\n' ;
		DRIVERCRATE_EXPECT( context, (error == 0U) == test.accepted) ;
		// 固定した入力条件だけを分離し、他対象や期待へ流用しません
		if( test.accepted) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			DRIVERCRATE_EXPECT( context, !result.systemEffects.empty() &&
											result.systemFiles.size() == 1U &&
											!result.delayedRegistration) ;
		} else {
			DRIVERCRATE_EXPECT( context, result.systemEffects.empty() && result.systemFiles.empty()) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同service ETWの全位置集合とVfW三者対応を共有型検査で確認します
 * @param[in,out] context 同processの有限assertion集計です
 * @note 架空原文の全fieldだけを純readerから渡し、実module/registryを変更しません
 */
//------------------------------------------------------------------------------
void typedRelationCases( TestContext &context)
{
	const std::wstring publisher =
		L"{10000000-0000-4000-8000-000000000001}" ;	// 同原文の標準媒体/ETW作用へ結ぶ固定の役割です
	const std::wstring channelRoot =				// 同原文の標準媒体/ETW作用へ結ぶ固定の役割です
		L"Software\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Synthetic" ;
	const std::wstring publisherRoot =	// 同原文の標準媒体/ETW作用へ結ぶ固定の役割です
		L"Software\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\" + publisher ;
	const std::wstring loggerRoot =	// 同原文の標準媒体/ETW作用へ結ぶ固定の役割です
		L"System\\CurrentControlSet\\Control\\WMI\\Autologger\\EventLog-System\\" + publisher ;
	const std::wstring security =	// 元権限/署名の照合中だけ使う証拠です
		L"O:BAG:SYD:(A;;0xf0007;;;SY)(A;;7;;;BA)(A;;3;;;BO)(A;;5;;;SO)(A;;2;;;S-1-5-33)(A;;1;;;S-1-5-32-573)" ;
	std::vector<SystemInfRow> eventRows ;	// 同原文の標準媒体/ETW作用へ結ぶ固定の役割です
	const auto append = [&eventRows]( const std::wstring &path, const std::wstring &key,
									 const std::wstring &flags, const std::wstring &value) {
		eventRows.push_back(
			{static_cast<std::uint32_t>( eventRows.size()), {}, {L"HKLM", path, key, flags, value}}) ;
	} ; // 仮想原文の順番と全fieldを固定します
	// 同所有fixtureの全対象を順に検査します
	for( unsigned index = 0U; index < 2U; ++index) {	// 同所有fixtureの全対象を順に確認します
		const auto name =
			index == 0U
				? L"Synthetic/Operational"
				: L"Synthetic/Analytic" ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
		const auto path =
			channelRoot + (index == 0U
							   ? L"/Operational"
							   : L"/Analytic") ;	// 元所有scopeへ結ぶ位置です。任意探索へ使いません
		append( path, L"OwningPublisher", L"0", publisher) ;
		append( path, L"Enabled", L"0x10001", L"1") ;
		append( path, L"Isolation", L"0x10001", L"1") ;
		append( path, L"ChannelAccess", L"0", security) ;
		append( path, L"Type", L"0x10001", index == 0U ? L"1" : L"2") ;
		const auto reference = publisherRoot + L"\\ChannelReferences\\" +
							   // 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
							   std::to_wstring( index) ;
		append( reference, L"", L"0", name) ;
		append( reference, L"Id", L"0x10001", std::to_wstring( 16U + index)) ;
		append( reference, L"Flags", L"0x10001", L"0") ;
	}

	append( publisherRoot, L"", L"0", L"Synthetic") ;
	append( publisherRoot, L"ResourceFileName", L"0x20000", L"%12%\\dep.sys") ;
	append( publisherRoot, L"MessageFileName", L"0x20000", L"%12%\\dep.sys") ;
	append( publisherRoot + L"\\ChannelReferences", L"Count", L"0x10001", L"2") ;
	append( loggerRoot, L"Enabled", L"0x10001", L"1") ;
	append( loggerRoot, L"EnableLevel", L"0x10001", L"5") ;
	append( loggerRoot, L"LoggerName", L"0", L"EventLog-System") ;
	append( loggerRoot, L"MatchAnyKeyword", L"0xb0001", L"0xffffffffffffffff") ;
	append( loggerRoot, L"MatchAllKeyword", L"0xb0001", L"0") ;
	append( loggerRoot, L"EnableProperty", L"0x10001", L"1") ;
	DRIVERCRATE_EXPECT( context, eventRows.size() == 26U) ;
	// 同所有fixtureの全対象を順に検査します
	for( unsigned fault = 0U; fault < 12U; ++fault) {	// 同所有fixtureの全対象を順に確認します
		auto rows = eventRows ;							// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
		// 固定した入力条件だけを分離し、他対象や期待へ流用しません
		if( fault == 1U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			rows.pop_back() ;
		}
		// この固定負例の条件だけを変更し、他の期待は維持します
		else if( fault == 2U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			rows[1U].values[1] = channelRoot + L"-orphan/Operational" ;
		}
		// この固定負例の条件だけを変更し、他の期待は維持します
		else if( fault == 3U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			rows[1U] = rows[0U] ;
		}
		// この固定負例の条件だけを変更し、他の期待は維持します
		else if( fault == 4U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			rows[0U].values[4] = L"{20000000-0000-4000-8000-000000000002}" ;
		}
		// この固定負例の条件だけを変更し、他の期待は維持します
		else if( fault == 5U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			rows[3U].values[4].erase( 0U, 4U) ;
		}
		// この固定負例の条件だけを変更し、他の期待は維持します
		else if( fault == 6U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			rows[3U].values[4].replace( 4U, 4U, L"G:BA") ;
		}
		// この固定負例の条件だけを変更し、他の期待は維持します
		else if( fault == 7U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			rows[3U].values[4].append( 1U, L'\0') ;
		}
		// この固定負例の条件だけを変更し、他の期待は維持します
		else if( fault == 8U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			rows[3U].values[4] += L"(A;;1;;;WD)" ;
		}
		// この固定負例の条件だけを変更し、他の期待は維持します
		else if( fault == 9U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			rows[17U].values[4] = L"%11%\\dep.sys" ;
		}
		// この固定負例の条件だけを変更し、他の期待は維持します
		else if( fault == 10U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			rows[6U].values[4] = L"17" ;
		}
		// この固定負例の条件だけを変更し、他の期待は維持します
		else if( fault == 11U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			rows[3U].values[4].replace( 12U, 1U, L"OI") ;
		}

		SystemInfEffectApi api ;			// 同同期中だけ使用する完全な限定操作表です
		std::size_t		   registryRows{} ;	// この同期だけで保持する元値です。許可の代用にしません
		api.registryRows = &registryRows ;
		api.read		 = [&rows]( const SystemInfSection	 &section,
						   std::vector<SystemInfRow> &out) -> NativeError {
			// 固定した入力条件だけを分離し、他対象や期待へ流用しません
			if( section.document !=
			   1U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
				return E_INVALIDARG ;
			}

			// 固定した入力条件だけを分離し、他対象や期待へ流用しません
			if( section.name == L"Services" &&
			   section.context ==
				   SystemInfContext::
					   SERVICES) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
				out = {{0U, L"AddService", {L"Synthetic", L"2", L"Service", L"Events"}}} ;
			}
			// この固定負例の条件だけを変更し、他の期待は維持します
			else if(
				section.name == L"Service" &&
				section.owner ==
					L"Synthetic" &&	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
				section.context == SystemInfContext::SERVICE) {
				out = {{0U, L"ServiceType", {L"1"}},
					   {1U, L"StartType", {L"3"}},
					   {2U, L"ErrorControl", {L"1"}},
					   {3U, L"ServiceBinary", {L"%12%\\dep.sys"}}} ;
			}
			// この固定負例の条件だけを変更し、他の期待は維持します
			else if(
				section.name == L"Events" &&
				section.owner ==
					L"Synthetic" &&	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
				section.context == SystemInfContext::EVENT_LOG) {
				out = {{0U, L"AddReg", {L"Data"}}} ;
			}
			// この固定負例の条件だけを変更し、他の期待は維持します
			else if(
				section.name == L"Data" &&
				section.owner ==
					L"Synthetic" &&	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
				section.context == SystemInfContext::REGISTRY &&
				section.scope == SystemInfContext::EVENT_LOG) {
				out = rows ;
			} else {
				return E_INVALIDARG ;
			}

			return 0U ;
		} ; // 同document/context/ownerの完全表以外をnativeへ補完しません
		api.module = []( std::uint64_t document, std::wstring_view value) -> NativeError {
			return document == 1U && value == L"%12%\\dep.sys" ? 0U : E_ACCESSDENIED ;
		} ;
		api.service = []( std::wstring_view, SystemServiceEvidence &) -> NativeError {
			return E_ACCESSDENIED ;
		} ;
		api.legacyRegistry = []( const SystemInfEffect &, bool) -> NativeError {
			return E_ACCESSDENIED ;
		} ;
		const std::array seeds{SystemInfSection{
			1U, L"Services",
			SystemInfContext::
				SERVICES}} ;					// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
		SystemInfEffects result ;				// 同原文/操作へ結ぶ検査又は結果の所有値です
		std::uint32_t	 stage{}, observed{} ;	// 同原文/操作へ結ぶ検査又は結果の所有値です
		const auto		 error = inspectSystemInfEffects(
			  seeds, api, result, stage, observed) ;	// 直後に保持した元API又は検査errorです
		std::cout << "SYSTEM_ETW_CASE ordinal=" << fault << " error=" << error << " stage=" << stage
				  << '\n' ;
		DRIVERCRATE_EXPECT( context, fault == 0U ? error == 0U && !result.effects.empty()
												: error != 0U && result.effects.empty()) ;
	}

	// 同所有fixtureの全対象を順に検査します
	for( unsigned fault = 0U; fault < 4U; ++fault) {	// 同所有fixtureの全対象を順に確認します
		std::vector<SystemInfRow> rows{
			// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
			{0U,
			 {},
			 {L"HKLM",
			  L"SYSTEM\\CurrentControlSet\\Control\\MediaResources\\MSVideo\\MSVideo.VFWWDM",
			  L"Driver", L"0", L"vfwwdm32.dll"}},
			{1U,
			 {},
			 {L"HKLM", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32", L"MSVideo8",
			  L"0", L"vfwwdm32.dll"}},
			{2U,
			 {},
			 {L"HKLM", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers.desc",
			  L"vfwwdm32.dll", L"0", L"Synthetic video"}}} ;
		// 固定した入力条件だけを分離し、他対象や期待へ流用しません
		if( fault == 1U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			rows[1U].values[2] = L"MSVideo9" ;
		}
		// この固定負例の条件だけを変更し、他の期待は維持します
		else if( fault == 2U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			rows[0U].values[1] += L"-other" ;
		}
		// この固定負例の条件だけを変更し、他の期待は維持します
		else if( fault == 3U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			rows.pop_back() ;
		}

		std::size_t		   registryRows{} ;	// この同期だけで保持する元値です。許可の代用にしません
		SystemInfEffectApi api ;			// 同同期中だけ使用する完全な限定操作表です
		api.registryRows = &registryRows ;
		api.read		 = [&rows]( const SystemInfSection	 &section,
						   std::vector<SystemInfRow> &out) -> NativeError {
			// 固定した入力条件だけを分離し、他対象や期待へ流用しません
			if( section.document != 1U ||
			   section.name !=
				   L"Data" ||	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			   section.context != SystemInfContext::REGISTRY ||
			   section.scope != SystemInfContext::DEVICE) {
				return E_INVALIDARG ;
			}

			out = rows ;
			return 0U ;
		} ;
		api.module = []( std::uint64_t document, std::wstring_view value) -> NativeError {
			return document == 1U && value == L"vfwwdm32.dll" ? 0U : E_ACCESSDENIED ;
		} ;
		api.service = []( std::wstring_view, SystemServiceEvidence &) -> NativeError {
			return E_ACCESSDENIED ;
		} ;
		api.legacyRegistry = []( const SystemInfEffect &, bool) -> NativeError {
			return E_ACCESSDENIED ;
		} ;
		const std::array seeds{
			// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
			SystemInfSection{1U, L"Data", SystemInfContext::REGISTRY, SystemInfContext::DEVICE}} ;
		SystemInfEffects result ;				// 同原文/操作へ結ぶ検査又は結果の所有値です
		std::uint32_t	 stage{}, observed{} ;	// 同原文/操作へ結ぶ検査又は結果の所有値です
		const auto		 error = inspectSystemInfEffects(
			  seeds, api, result, stage, observed) ;	// 直後に保持した元API又は検査errorです
		DRIVERCRATE_EXPECT( context,
						   fault == 0U ? error == 0U : error != 0U && result.effects.empty()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 特殊値のWindows大小文字同値と文脈/全field拒否を共有型検査で確認します
 * @param[in,out] context 同processの有限assertion集計です
 * @note 純readerの全fieldだけを渡し、実file/registry/serviceへfallbackしません
 */
//------------------------------------------------------------------------------
void typedRegistryNameCases( TestContext &context)
{
	/** @brief 同じproduction validatorへ与える独立した全field期待です */
	struct Case {
		/// 原scopeです
		SystemInfContext		  scope ;
		/// 名前を省略しない元dataです
		std::vector<std::wstring> fields ;
		/// 許される表示型だけtrueです
		bool					  accepted{} ;
	} ;
	std::array<Case, 10U> cases{
		// 固定契約から作る独立した正負の期待です
		{{SystemInfContext::DEVICE, {L"HKR", L"", L"Label", L"0", L"非ASCII表示"}, true},
		 {SystemInfContext::DEVICE, {L"HKR", L"", L"DevLoader", L"0", L"*ntkern"}, true},
		 {SystemInfContext::HARDWARE, {L"HKR", L"", L"DevLoader", L"0", L"*ntkern"}},
		 {SystemInfContext::DEVICE, {L"HKR", L"", L"NTMPDr\u0131ver", L"0", L"display"}},
		 {SystemInfContext::DEVICE, {L"HKR", L"", L"D3Cold\u017fupported", L"0x10001", L"2"}},
		 {SystemInfContext::HARDWARE, {L"HKR", L"", L"D3Cold\u017fupported", L"0x10001", L"2"}},
		 {SystemInfContext::DEVICE, {L"HKR", L"", L"LowerFilter\u017f", L"0", L"display"}},
		 {SystemInfContext::INTERFACE,
		  {L"HKR", L"", L"CLSID", L"0", L"{10000000-0000-4000-8000-000000000001}"}},
		 {SystemInfContext::DEVICE, {L"HKCU", L"", L"Label", L"0", L"display"}},
		 {SystemInfContext::DEVICE, {L"HKLM", L"Software\\Unknown", L"Label", L"0", L"display"}}}} ;
	const auto streamComparison = CompareStringOrdinal( L"NTMPDr\u0131ver", -1, L"NTMPDriver", -1,
													   TRUE) ;	// Windows自身による全名前の等値です
	const auto powerComparison	= CompareStringOrdinal(
		 L"D3Cold\u017fupported", -1, L"D3ColdSupported", -1, TRUE) ;	// ASCII独自foldを正本にしません
	const auto filterComparison =
		CompareStringOrdinal( L"LowerFilter\u017f", -1, L"LowerFilters", -1,
							 TRUE) ;	// 異なるUnicode名の表示dataは別に保ちます
	DRIVERCRATE_EXPECT( context,
					   streamComparison != 0 && powerComparison != 0 && filterComparison != 0) ;
	cases[3U].accepted = streamComparison != CSTR_EQUAL ;
	cases[4U].accepted = powerComparison != CSTR_EQUAL ;
	cases[5U].accepted = powerComparison != CSTR_EQUAL ;
	cases[6U].accepted = filterComparison != CSTR_EQUAL ;
	std::cout << "SYSTEM_NAME_COMPARE stream=" << streamComparison << " power=" << powerComparison
			  << " filter=" << filterComparison << '\n' ;

	// Windows自身の等値判定に対応する全名前条件を共有validatorへ通します
	for( const auto &test : cases) {	// 同所有fixtureの全対象を順に確認します
		std::size_t		   rows{} ;		// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
		SystemInfEffectApi api ;		// 同同期中だけ使用する完全な限定操作表です
		api.registryRows = &rows ;
		api.read		 = [&test]( const SystemInfSection	 &section,
						   std::vector<SystemInfRow> &out) -> NativeError {
			// 固定した入力条件だけを分離し、他対象や期待へ流用しません
			if( section.document != 1U ||
			   section.name !=
				   L"Data" ||	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			   section.context != SystemInfContext::REGISTRY ||
			   section.scope != test.scope || section.owner != L"same-owner") {
				return E_INVALIDARG ;
			}

			out = {{0U, {}, test.fields}} ;
			return 0U ;
		} ; // 純readerも未知document/文脈/所有者を成功へ補完しません
		api.module = []( std::uint64_t, std::wstring_view) -> NativeError { return E_ACCESSDENIED ; } ;
		api.service = []( std::wstring_view, SystemServiceEvidence &) -> NativeError {
			return E_ACCESSDENIED ;
		} ;
		api.legacyRegistry = []( const SystemInfEffect &, bool) -> NativeError { return 0U ; } ;
		const std::array seeds{
			// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
			SystemInfSection{1U, L"Data", SystemInfContext::REGISTRY, test.scope, L"same-owner"}} ;
		SystemInfEffects result ;				// 同原文/操作へ結ぶ検査又は結果の所有値です
		std::uint32_t	 stage{}, observed{} ;	// 同原文/操作へ結ぶ検査又は結果の所有値です
		const auto		 error = inspectSystemInfEffects(
			  seeds, api, result, stage, observed) ;	// 直後に保持した元API又は検査errorです
		DRIVERCRATE_EXPECT( context, (error == 0U) == test.accepted) ;
		DRIVERCRATE_EXPECT( context,
						   test.accepted ? result.effects.size() == 1U : result.effects.empty()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 署名済みSDバス文書のIDと選択三節に結んだ全行の保存、限定作用、拒否を確認します
 * @param[in,out] context 現在の専用テストの結果集計です
 * @note 原行の同期readerと実体判定を架空化し、サービス・registry・fileを変更しません
 */
//------------------------------------------------------------------------------
void typedSdBusCases( TestContext &context)
{
	using Sections					 = std::map<std::wstring, std::vector<SystemInfRow>> ;
	using Context					 = SystemInfContext ;
	constexpr std::uint64_t DOCUMENT = 7U ;	// 収集原文であることを仮定する唯一のfixture IDです
	const std::array		seeds{
		   SystemInfSection{DOCUMENT, L"SDHostIntelCherryTrail", Context::DEVICE, Context::DEVICE, {}},
		   SystemInfSection{
			   DOCUMENT, L"SDHostIntelCherryTrail.HW", Context::HARDWARE, Context::HARDWARE, {}},
		   SystemInfSection{DOCUMENT,
							L"SDHostIntelCherryTrail.Services",
							Context::SERVICES,
							Context::SERVICES,
								{}}} ;	// 同一元選択の三つの入口です
	// SetupAPIの全fieldを独立したreaderで再現し、数値の表記とローカライズ時の表示文も残します
	const Sections original{
		{L"SDHostIntelCherryTrail",
		 {{0U, L"CopyFiles", {L"CSCopyFiles"}}, {1U, L"AddReg", {L"SDBUSReg"}}}},
		{L"SDHostIntelCherryTrail.HW",
		 {{0U, L"AddReg", {L"SDBUSLocationReg"}},
		  {1U, L"AddReg", {L"SDHostIntelCherryTrail.HW.addreg"}}}},
		{L"SDHostIntelCherryTrail.Services",
		 {{0U, L"AddService", {L"sdbus", L"2", L"sdbus_Service_Inst"}}}},
		{L"sdbus_Service_Inst",
		 {{0U, L"ServiceType", {L"1"}},
		  {1U, L"StartType", {L"3"}},
		  {2U, L"ErrorControl", {L"1"}},
		  {3U, L"ServiceBinary", {L"%12%\\sdbus.sys"}},
		  {4U, L"LoadOrderGroup", {L"System Bus Extender"}},
		  {5U, L"AddReg", {L"SDBUSServiceReg"}}}},
		{L"SDBUSReg", {{0U, {}, {L"HKR", L"", L"Driver", L"", L"sdbus.sys"}}}},
		{L"SDBUSLocationReg",
		 {{0U, {}, {L"HKR", L"", L"UINumberDescFormat", L"", L"スロット %1!u!"}}}},
		{L"SDHostIntelCherryTrail.HW.addreg",
		 {{0U, {}, {L"HKR", L"", L"CompatType", L"0x00010001", L"0xB"}},
		  {1U, {}, {L"HKR", L"", L"HostRevision", L"0x00010001", L"0x1"}},
		  {2U, {}, {L"HKR", L"", L"FunctionBlockIndex", L"0x00010001", L"0"}},
		  {3U, {}, {L"HKR", L"", L"OverrideFlags", L"0x00010001", L"0x60200000"}}}},
		{L"SDBUSServiceReg",
		 {{0U, {}, {L"HKR", L"", L"BootFlags", L"0x00010003", L"0x00000008"}},
		  {1U, {}, {L"HKR", L"Parameters", L"SdCmdFlags", L"1", L"05", L"01", L"3f", L"fF"}},
		  {2U,
		   {},
		   {L"HKR", L"Parameters", L"SdAppCmdFlags", L"1", L"33", L"01", L"06", L"01", L"33",
			L"01"}}}}} ;
	std::size_t trial{} ;	// 差異があったfixtureを特定する固定順の通番です
	// 原入力・選択・文書ID・実ファイルの証拠を検査ごとに独立させます
	const auto	check = [&]( const Sections &source, std::span<const SystemInfSection> selection,
							std::uint64_t bound, bool moduleAvailable, bool accepted) {
		 ++trial ;
		 std::size_t		rows{} ;		// 既存検査との共同registry予算です
		 std::size_t		modules{} ;		// 元サービスbinaryの実体確認回数です
		 std::size_t		services{} ;	// Windows稼働サービスの照会が増えていないことを検査します
		 SystemInfEffectApi api ;			// この同期fixtureの限定操作だけを使います
		 api.sdBusInboxDocument = bound ;
		 api.registryRows		= &rows ;
		 api.read				= [&source]( const SystemInfSection	  &section,
								std::vector<SystemInfRow> &out) -> NativeError {
			   const auto item = source.find( section.name) ;	// 元文書の同名節からだけ全行を得ます
			   // 未指定の文書・節から期待行を補いません
			   if( section.document != DOCUMENT || item == source.end()) {
				   return HRESULT_FROM_WIN32( ERROR_SECTION_NOT_FOUND) ;
			   }

			   out = item->second ;
			   return 0U ;
		 } ;
		 api.module = [&]( std::uint64_t document, std::wstring_view path) -> NativeError {
			 ++modules ;
			 return document == DOCUMENT && moduleAvailable &&
							(path == L"%12%\\sdbus.sys" ||
							 path == L"X:\\TestOS\\System32\\drivers\\sdbus.sys")
						? 0U
						: E_ACCESSDENIED ;
		 } ;
		 api.service = [&]( std::wstring_view, SystemServiceEvidence &) -> NativeError {
			 ++services ;
			 return E_ACCESSDENIED ;
		 } ;
		 api.legacyRegistry = []( const SystemInfEffect &, bool) -> NativeError {
			 return E_ACCESSDENIED ;
		 } ;
		 SystemInfEffects result ;		// 成功時だけ全作用が返ります
		 std::uint32_t	  stage{} ;		// 固定された拒否段階です
		 std::uint32_t	  observed{} ;	// 型・件数だけの補助診断です
		 const auto		  error = inspectSystemInfEffects( selection, api, result, stage,
														  observed) ;	// 通常の型付き入口を通します
		 // 想定外の成否だけを公開可能な件数と元数値で示します
		 if( (error == 0U) != accepted) {
			 std::cerr << "SDBUS_TYPED_CASE trial=" << trial << " stage=" << stage
					   << " error=" << error << '\n' ;
		 }

		 DRIVERCRATE_EXPECT( context, (error == 0U) == accepted && services == 0U) ;
		 // 正式な限定作用と同元コピーだけを返し、全原fieldの内容も一致させます
		 if( accepted) {
			 DRIVERCRATE_EXPECT( context,
								modules == 1U && rows == 9U && result.effects.size() == 20U &&
									result.services.empty() && result.copySections.size() == 1U &&
									result.copySections.front() == seeds.front()) ;
			 // 読み出した行の順序・名前・空欄・全byteを元表へ照合します
			 for( const auto &effect : result.effects) {
				 DRIVERCRATE_EXPECT( context,
									effect.source.document == DOCUMENT &&
										source.at( effect.source.name).at( effect.row.ordinal) ==
											effect.row) ;
			 }
		 } else {
			 DRIVERCRATE_EXPECT( context, result.effects.empty() && result.copySections.empty() &&
											 result.services.empty()) ;
		 }

		 // 同原実ファイルの所有確認に失敗した元HRESULTを保ちます
		 if( !moduleAvailable) {
			 DRIVERCRATE_EXPECT( context,
								modules == 1U && error == static_cast<NativeError>( E_ACCESSDENIED)) ;
		 }
	} ;
	check( original, seeds, DOCUMENT, true, true) ;
	check( original, seeds, 0U, true, false) ;
	check( original, seeds, DOCUMENT + 1U, true, false) ;
	check( original, seeds, DOCUMENT, false, false) ;
	auto expanded = original ;	// SetupAPIの同じDIRID展開と同値な数値表記を独立に確認します
	expanded.at( L"sdbus_Service_Inst")[3].values[0] = L"X:\\TestOS\\System32\\drivers\\sdbus.sys" ;
	expanded.at( L"SDBUSServiceReg")[0].values[4]	= L"8" ;
	expanded.at( L"SDBUSServiceReg")[1].values[5]	= L"e0" ;
	expanded.at( L"SDHostIntelCherryTrail.HW.addreg")[0].values[4] = L"4294967295" ;
	check( expanded, seeds, DOCUMENT, true, true) ;
	/** @brief 元の一行の指定fieldだけを変更する負例です */
	struct Mutation {
		/// 変更対象の原節名です
		const wchar_t *section ;
		/// 元の0基点行です
		std::size_t	   row ;
		/// 元の0基点fieldです
		std::size_t	   field ;
		/// 単独で拒否される原fieldへの置換値です
		const wchar_t *value ;
	} ;
	constexpr Mutation CHANGES[] = {
		{L"SDHostIntelCherryTrail", 0U, 0U, L"OtherCopy"},
		{L"SDHostIntelCherryTrail.Services", 0U, 0U, L"other"},
		{L"SDHostIntelCherryTrail.Services", 0U, 1U, L"0"},
		{L"sdbus_Service_Inst", 1U, 0U, L"0"},
		{L"sdbus_Service_Inst", 4U, 0U, L"Base"},
		{L"sdbus_Service_Inst", 3U, 0U, L"%11%\\sdbus.sys"},
		{L"sdbus_Service_Inst", 3U, 0U, L"%12%\\other.sys"},
		{L"sdbus_Service_Inst", 3U, 0U, L"sdbus.sys"},
		{L"sdbus_Service_Inst", 3U, 0U, L"X:\\OtherOS\\System32\\drivers\\sdbus.sys"},
		{L"SDBUSReg", 0U, 4U, L"%12%\\sdbus.sys"},
		{L"SDBUSLocationReg", 0U, 4U, L"Slot %1!u! %2!s!"},
		{L"SDHostIntelCherryTrail.HW.addreg", 3U, 0U, L"HKLM"},
		{L"SDHostIntelCherryTrail.HW.addreg", 3U, 3U, L"0x10003"},
		{L"SDHostIntelCherryTrail.HW.addreg", 3U, 4U, L"0x100000000"},
		{L"SDBUSServiceReg", 0U, 1U, L"Parameters"},
		{L"SDBUSServiceReg", 0U, 3U, L"0x10001"},
		{L"SDBUSServiceReg", 0U, 4U, L"9"},
		{L"SDBUSServiceReg", 1U, 3U, L"0x00000003"},
		{L"SDBUSServiceReg", 1U, 5U, L"0G"},
		{L"SDBUSServiceReg", 1U, 6U, L"40"},
		{L"SDBUSServiceReg", 2U, 9U, L"02"},
		{L"SDBUSServiceReg", 2U, 4U, L"006"}} ;	// 役割・設定・実体を一要素ずつ変えます
	// 正例の残りを維持し、一要素だけの改変でも全作用を拒否させます
	for( const auto &change : CHANGES) {
		auto changed = original ;	// 別の負例の影響を持ち越しません
		changed.at( change.section).at( change.row).values.at( change.field) = change.value ;
		check( changed, seeds, DOCUMENT, true, false) ;
	}

	auto extra = original ;	// 通常のSERVICEで扱える追加directiveもこの集合では拒否します
	extra.at( L"sdbus_Service_Inst").push_back( {6U, L"DisplayName", {L"Another display"}}) ;
	check( extra, seeds, DOCUMENT, true, false) ;
	extra = original ;
	extra.at( L"SDHostIntelCherryTrail.Services")[0].values.push_back( L"") ;
	check( extra, seeds, DOCUMENT, true, false) ;
	extra = original ;
	extra.at( L"SDBUSServiceReg")[2].values.push_back( L"00") ;
	check( extra, seeds, DOCUMENT, true, false) ;
	extra.at( L"SDBUSServiceReg")[2].values.resize( 66U, L"00") ;
	check( extra, seeds, DOCUMENT, true, false) ;
	extra.at( L"SDBUSServiceReg")[2].values.resize( 4U) ;
	check( extra, seeds, DOCUMENT, true, false) ;
	extra							= original ;
	extra.at( L"SDBUSServiceReg")[2] = extra.at( L"SDBUSServiceReg")[1] ;
	check( extra, seeds, DOCUMENT, true, false) ;
	extra = original ;
	extra.at( L"SDBUSServiceReg").pop_back() ;
	check( extra, seeds, DOCUMENT, true, false) ;
	auto wrongScope		  = seeds ;	// 同名・同byteのHWをdevice作用として選んだ負例です
	wrongScope[1].context = Context::DEVICE ;
	wrongScope[1].scope	  = Context::DEVICE ;
	check( original, wrongScope, DOCUMENT, true, false) ;
	check( original, std::span{seeds}.first( 2U), DOCUMENT, true, false) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同梱Portsの選択と全作用、所有者、メッセージ資源の両方を共通入口で確認します
 * @param[in,out] context 専用テストの有限な結果集計です
 * @note 同文書と実体の成否を架空化し、WindowsファイルやSCM・registryを操作しません
 */
//------------------------------------------------------------------------------
void typedMsPortsCases( TestContext &context)
{
	using Context					 = SystemInfContext ;
	using Sections					 = std::map<std::wstring, std::vector<SystemInfRow>> ;
	constexpr std::uint64_t DOCUMENT = 19U ;	// 署名・Store・元Ports選択が成立したと仮定する文書です
	const std::array		seeds{
		   SystemInfSection{DOCUMENT, L"Serial.NT", Context::DEVICE, Context::DEVICE, {}},
		   SystemInfSection{DOCUMENT, L"ComPort.NT.HW", Context::HARDWARE, Context::HARDWARE, {}},
		   SystemInfSection{DOCUMENT,
							L"ComPort.NT.Services",
							Context::SERVICES,
							Context::SERVICES,
								{}}} ;	// 元パッケージから実際に選ぶ三節です
	// 元Windows参照に対応する全fieldを架空の表示文字列で再現します。非選択節には不正な行を置きます
	const Sections original{
		{L"Serial.NT", {{0U, L"CopyFiles", {L"Serial.NT.Copy"}}}},
		{L"ComPort.NT.HW", {{0U, L"AddReg", {L"ComPort.NT.HW.AddReg"}}}},
		{L"ComPort.NT.Services",
		 {{0U,
		   L"AddService",
		   {L"Serial", L"0x00000002", L"Serial_Service_Inst", L"Serial_EventLog_Inst"}},
		  {1U, L"AddService", {L"Serenum", L"", L"Serenum_Service_Inst"}}}},
		{L"Serial_Service_Inst",
		 {{0U, L"DisplayName", {L"架空のシリアルサービス"}},
		  {1U, L"ServiceType", {L"1"}},
		  {2U, L"StartType", {L"3"}},
		  {3U, L"ErrorControl", {L"0"}},
		  {4U, L"ServiceBinary", {L"%12%\\serial.sys"}},
		  {5U, L"LoadOrderGroup", {L"Extended base"}}}},
		{L"Serenum_Service_Inst",
		 {{0U, L"DisplayName", {L"Synthetic filter"}},
		  {1U, L"ServiceType", {L"1"}},
		  {2U, L"StartType", {L"3"}},
		  {3U, L"ErrorControl", {L"1"}},
		  {4U, L"ServiceBinary", {L"%12%\\serenum.sys"}},
		  {5U, L"LoadOrderGroup", {L"PNP Filter"}}}},
		{L"ComPort.NT.HW.AddReg",
		 {{0U, {}, {L"HKR", L"", L"UpperFilters", L"0x10000", L"serenum"}}}},
		{L"Serial_EventLog_Inst", {{0U, L"AddReg", {L"Serial_EventLog_AddReg"}}}},
		{L"Serial_EventLog_AddReg",
		 {{0U,
		   {},
		   {L"HKR", L"", L"EventMessageFile", L"0x00020000",
			L"%SystemRoot%\\System32\\IoLogMsg.dll;%SystemRoot%\\System32\\drivers\\serial.sys"}},
		  {1U, {}, {L"HKR", L"", L"TypesSupported", L"0x00010001", L"7"}}}},
		{L"ComPort.NT.AddReg", {{0U, {}, {L"Unselected"}}}},
		{L"ComPort.NT.Copy", {{0U, L"Unselected", {L"other.sys"}}}}} ;
	std::size_t trial{} ;	// 想定と異なる成否の入力を特定するための通番です
	// 各試験が所有するcallbackと元fieldを同期検査の間だけ借用します
	const auto	check = [&]( const Sections &source, std::span<const SystemInfSection> selection,
							std::uint64_t bound, std::size_t deniedCall, bool accepted,
							std::size_t incomingEdges = 0U) {
		 ++trial ;
		 std::size_t rows{} ;					// HWおよびeventのregistry行が共有する予算です
		 std::size_t serviceReads{} ;			// 既存サービスの照会を要求していないことを確認します
		 std::vector<std::wstring> modules ;	// 参照順に受け取った完全なモジュール位置です
		 SystemInfEffectApi		   api ;		// INBOX文書の資格と実体判定をこの一回だけ再現します
		 api.msPortsInboxDocument = bound ;
		 api.registryRows		  = &rows ;
		 api.graphReferences	  = incomingEdges ;
		 api.read				  = [&]( const SystemInfSection	  &section,
						std::vector<SystemInfRow> &out) -> NativeError {
			 const auto part = source.find( section.name) ;	// 同じ元文書の完全な一節です
			 // 元選択外の別文書・不存在節を作用なしの成功にしません
			 if( section.document != DOCUMENT || part == source.end()) {
				 return HRESULT_FROM_WIN32( ERROR_SECTION_NOT_FOUND) ;
			 }

			 out = part->second ;
			 return 0U ;
		 } ;
		 api.module = [&]( std::uint64_t document, std::wstring_view path) -> NativeError {
			 modules.emplace_back( path) ;
			 // 正規のWindows位置を仮定した二つのSYSと一つのDLLだけに成功を返します
			 constexpr std::wstring_view ALLOWED[] = {
				 L"%12%\\serial.sys",
				 L"%12%\\serenum.sys",
				 L"%SystemRoot%\\System32\\IoLogMsg.dll",
				 L"%SystemRoot%\\System32\\drivers\\serial.sys",
				 L"X:\\FixtureOS\\System32\\drivers\\serial.sys",
				 L"X:\\FixtureOS\\System32\\drivers\\serenum.sys",
				 L"X:\\FixtureOS\\System32\\IoLogMsg.dll"} ;
			 return document == DOCUMENT && modules.size() != deniedCall &&
							std::ranges::find( ALLOWED, path) != std::end( ALLOWED)
						? 0U
						: E_ACCESSDENIED ;
		 } ;
		 api.service = [&]( std::wstring_view, SystemServiceEvidence &) -> NativeError {
			 ++serviceReads ;
			 return E_ACCESSDENIED ;
		 } ;
		 api.legacyRegistry = []( const SystemInfEffect &, bool) -> NativeError {
			 return E_ACCESSDENIED ;
		 } ;
		 SystemInfEffects result ;		// 全作用と元コピーが成立した場合だけ返ります
		 std::uint32_t	  stage{} ;		// 最初の閉じた失敗区分です
		 std::uint32_t	  observed{} ;	// 失敗したファイルの役割または件数です
		 const auto		  error =
			 // 同じ製品の検査です
			 inspectSystemInfEffects( selection, api, result, stage, observed) ;
		 // 想定外の成否だけを数値診断へ残します
		 if( (error == 0U) != accepted) {
			 std::cerr << "PORTS_TYPED_CASE trial=" << trial << " stage=" << stage
					   << " error=" << error << '\n' ;
		 }

		 DRIVERCRATE_EXPECT( context, (error == 0U) == accepted && serviceReads == 0U) ;
		 // 四つの役割ごとに元API失敗を保存し、それ以後の実体を検証済みへ含めません
		 if( deniedCall != 0U) {
			 const auto role = deniedCall <= 2U
								   ? SystemInfModuleRole::SERVICE_SYS
								   : SystemInfModuleRole::EVENT_RESOURCE ;	// 失敗入力の役割です
			 DRIVERCRATE_EXPECT(
				 context,
				 modules.size() == deniedCall && error == static_cast<NativeError>( E_ACCESSDENIED) &&
					 stage == static_cast<std::uint32_t>( SystemInfDiagnosticStage::MODULE) &&
					 observed == static_cast<std::uint32_t>( role)) ;
		 }

		 // 拒否された元行や作用を部分成功として返しません
		 if( !accepted) {
			 DRIVERCRATE_EXPECT( context, result.effects.empty() && result.copySections.empty() &&
											 result.services.empty()) ;
			 return ;
		 }

		 DRIVERCRATE_EXPECT( context, result.effects.size() == 20U && rows == 3U &&
										 result.references == incomingEdges + 10U &&
										 result.services.empty() &&
										 result.copySections.size() == 1U &&
										 result.copySections.front() == seeds.front()) ;
		 DRIVERCRATE_EXPECT( context,
							modules.size() == 4U &&
								modules[0] == source.at( L"Serial_Service_Inst")[4].values[0] &&
								modules[1] == source.at( L"Serenum_Service_Inst")[4].values[0] &&
								(modules[2] == L"%SystemRoot%\\System32\\IoLogMsg.dll" ||
								 modules[2] == L"X:\\FixtureOS\\System32\\IoLogMsg.dll") &&
								(modules[3] == L"%SystemRoot%\\System32\\drivers\\serial.sys" ||
								 modules[3] == L"X:\\FixtureOS\\System32\\drivers\\serial.sys")) ;
		 // 元の空flag、イベントの区切り、表示名と数値表記を含む原行全体を照合します
		 for( const auto &effect : result.effects) {
			 DRIVERCRATE_EXPECT( context, effect.source.document == DOCUMENT &&
											 source.at( effect.source.name).at( effect.row.ordinal) ==
												 effect.row) ;
		 }
	} ;
	check( original, seeds, DOCUMENT, 0U, true) ;
	check( original, seeds, 0U, 0U, false) ;
	check( original, seeds, DOCUMENT + 1U, 0U, false) ;
	check( original, seeds, DOCUMENT, 0U, true, 4086U) ;
	check( original, seeds, DOCUMENT, 0U, false, 4087U) ;
	// 一方のサービスやイベント資源だけの成立で残りの失敗を隠さないことを確認します
	for( std::size_t denied = 1U; denied <= 4U; ++denied) {
		check( original, seeds, DOCUMENT, denied, false) ;
	}

	auto expanded = original ;	// SetupAPIによるDIRID解決とローカライズを独立に再現します
	expanded.at( L"Serial_Service_Inst")[4].values[0] =
		L"X:\\FixtureOS\\System32\\drivers\\serial.sys" ;
	expanded.at( L"Serenum_Service_Inst")[4].values[0] =
		L"X:\\FixtureOS\\System32\\drivers\\serenum.sys" ;
	expanded.at( L"Serial_Service_Inst")[0].values[0]	= L"Synthetic port" ;
	expanded.at( L"ComPort.NT.Services")[0].values[1]	= L"2" ;
	expanded.at( L"Serial_EventLog_AddReg")[1].values[4] = L"0x3" ;
	check( expanded, seeds, DOCUMENT, 0U, true) ;
	expanded.at( L"Serial_EventLog_AddReg")[0].values[4] =
		L"X:\\FixtureOS\\System32\\IoLogMsg.dll;X:\\FixtureOS\\System32\\drivers\\serial.sys" ;
	check( expanded, seeds, DOCUMENT, 0U, true) ;

	/** @brief 元の一つのfieldを置換して所有先・型または位置の不一致を作ります */
	struct Change {
		/// 対象の元文書内の節名です
		const wchar_t *section ;
		/// 節の0基点の元行番号です
		std::size_t	   row ;
		/// 行の0基点のfield番号です
		std::size_t	   field ;
		/// 一条件だけの拒否を作る置換値です
		const wchar_t *value ;
	} ;
	constexpr Change CHANGES[] = {
		{L"Serial.NT", 0U, 0U, L"ComPort.NT.Copy"},
		{L"ComPort.NT.HW", 0U, 0U, L"ComPort.NT.AddReg"},
		{L"ComPort.NT.Services", 0U, 0U, L"Other"},
		{L"ComPort.NT.Services", 0U, 1U, L"0"},
		{L"ComPort.NT.Services", 0U, 1U, L""},
		{L"ComPort.NT.Services", 0U, 1U, L"0x80000002"},
		{L"ComPort.NT.Services", 1U, 1U, L"0"},
		{L"ComPort.NT.Services", 1U, 1U, L"2"},
		{L"ComPort.NT.Services", 1U, 2U, L"Serial_Service_Inst"},
		{L"Serial_Service_Inst", 0U, 0U, L"Invalid\nname"},
		{L"Serial_Service_Inst", 1U, 0U, L"2"},
		{L"Serenum_Service_Inst", 2U, 0U, L"0"},
		{L"Serial_Service_Inst", 3U, 0U, L"1"},
		{L"Serenum_Service_Inst", 3U, 0U, L"0"},
		{L"Serial_Service_Inst", 4U, 0U, L"%12%\\serenum.sys"},
		{L"Serenum_Service_Inst", 4U, 0U, L"%11%\\serenum.sys"},
		{L"Serenum_Service_Inst", 4U, 0U, L"serenum.sys"},
		{L"Serenum_Service_Inst", 4U, 0U, L"X:\\OtherOS\\System32\\drivers\\serenum.sys"},
		{L"Serial_Service_Inst", 5U, 0U, L"PNP Filter"},
		{L"Serenum_Service_Inst", 5U, 0U, L"Extended base"},
		{L"ComPort.NT.HW.AddReg", 0U, 0U, L"HKLM"},
		{L"ComPort.NT.HW.AddReg", 0U, 1U, L"Parameters"},
		{L"ComPort.NT.HW.AddReg", 0U, 2U, L"LowerFilters"},
		{L"ComPort.NT.HW.AddReg", 0U, 3U, L"0x10008"},
		{L"ComPort.NT.HW.AddReg", 0U, 4U, L"Serial"},
		{L"Serial_EventLog_AddReg", 0U, 0U, L"HKLM"},
		{L"Serial_EventLog_AddReg", 0U, 1U, L"Parameters"},
		{L"Serial_EventLog_AddReg", 0U, 3U, L"0x10000"},
		{L"Serial_EventLog_AddReg", 1U, 3U, L"1"},
		{L"Serial_EventLog_AddReg", 1U, 4U, L"0"},
		{L"Serial_EventLog_AddReg", 1U, 4U,
		 L"8"}} ;	// 選択外のコピー、所有サービス、型と実行の許否を決めるflagを個別に変えます
	// 他の正常な元行が不足を補完しないことを各fieldごとに確認します
	for( const auto &change : CHANGES) {
		auto changed = original ;	// 別の負例の元行を持ち越しません
		changed.at( change.section).at( change.row).values.at( change.field) = change.value ;
		check( changed, seeds, DOCUMENT, 0U, false) ;
	}

	constexpr std::wstring_view BAD_LISTS[] = {
		L"", L"IoLogMsg.dll;serial.sys", L"%SystemRoot%\\System32\\IoLogMsg.dll",
		L";%SystemRoot%\\System32\\drivers\\serial.sys", L"%SystemRoot%\\System32\\IoLogMsg.dll;",
		L"%SystemRoot%\\System32\\IoLogMsg.dll;%SystemRoot%\\System32\\drivers\\serial.sys;extra",
		L"%SystemRoot%\\System32\\drivers\\serial.sys;%SystemRoot%\\System32\\IoLogMsg.dll",
		L"%SystemRoot%\\System32\\IoLogMsg.dll;%SystemRoot%\\System32\\drivers\\serenum.sys",
		L"%SystemRoot%\\System32\\IoLogMsg.dll;%SystemRoot%\\System32\\IoLogMsg.dll",
		L"%Other%\\System32\\IoLogMsg.dll;%SystemRoot%\\System32\\drivers\\serial.sys",
		L"X:\\OtherOS\\System32\\IoLogMsg.dll;%SystemRoot%\\System32\\drivers\\serial.sys",
		L"%SystemRoot%\\System32\\IoLogMsg.dll;%SystemRoot%\\System32\\drivers\\serial.sys -arg",
		L"%SystemRoot%\\System32\\..\\System32\\IoLogMsg.dll;%SystemRoot%\\System32\\drivers\\serial.sys",
		// 二つの完全なWindows資源の位置と順番を外す例です
		L"%%SystemRoot%\\System32\\IoLogMsg.dll;%SystemRoot%\\System32\\drivers\\serial.sys",
		L"%%SystemRoot%%\\System32\\IoLogMsg.dll;%%SystemRoot%%\\System32\\drivers\\serial.sys"} ;
	// 一つのREG_EXPAND_SZの中にある参照を最後まで検査します
	for( const auto list : BAD_LISTS) {
		auto changed = original ;	// 同じ正常な元サービスへ各不正な資源列を接続します
		changed.at( L"Serial_EventLog_AddReg")[0].values[4] = list ;
		check( changed, seeds, DOCUMENT, 0U, false) ;
	}

	auto changed = original ;	// 足りない行・余分なfield・重複を個別に検査します
	changed.at( L"Serial_EventLog_AddReg")[0].values[4].append( 1U, L'\0') ;
	check( changed, seeds, DOCUMENT, 0U, false) ;
	changed.at( L"Serial_EventLog_AddReg")[0].values[4].assign( 510U, L'x') ;
	check( changed, seeds, DOCUMENT, 0U, false) ;
	changed										 = original ;
	changed.at( L"Serial_EventLog_AddReg")[0].key = L"Unexpected" ;
	check( changed, seeds, DOCUMENT, 0U, false) ;
	changed = original ;
	changed.at( L"ComPort.NT.HW.AddReg")[0].values.push_back( L"Other") ;
	check( changed, seeds, DOCUMENT, 0U, false) ;
	changed = original ;
	changed.at( L"ComPort.NT.Services")[1].values.push_back( L"Serial_EventLog_Inst") ;
	check( changed, seeds, DOCUMENT, 0U, false) ;
	changed									 = original ;
	changed.at( L"Serial_EventLog_AddReg")[1] = changed.at( L"Serial_EventLog_AddReg")[0] ;
	check( changed, seeds, DOCUMENT, 0U, false) ;
	changed = original ;
	changed.at( L"Serial_Service_Inst").pop_back() ;
	check( changed, seeds, DOCUMENT, 0U, false) ;
	changed = original ;
	changed.at( L"Serial.NT").push_back( {1U, L"CopyFiles", {L"ComPort.NT.Copy"}}) ;
	check( changed, seeds, DOCUMENT, 0U, false) ;
	auto wrong	   = seeds ;	// 同じ節名から先の読取でも、元選択の所有者・型を必要とします
	wrong[1].owner = L"Serial" ;
	check( original, wrong, DOCUMENT, 0U, false) ;
	wrong			 = seeds ;
	wrong[1].context = Context::DEVICE ;
	wrong[1].scope	 = Context::DEVICE ;
	check( original, wrong, DOCUMENT, 0U, false) ;
	check( original, std::span{seeds}.subspan( 1U), DOCUMENT, 0U, false) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 標準AHCIの選択節、元除外と作用を署名済み文書を仮定した読取りで検証する
 * @param[in,out] context 元作用の正常例と独立した不一致の集計先
 * @note 架空の文書とAPIで閉じた作用を確かめ、実際のSCMやレジストリへ変更を行わない
 */
//------------------------------------------------------------------------------
void typedAhciInboxCases( TestContext &context)
{
	using Context							= SystemInfContext ;
	using Sections							= std::map<std::wstring, std::vector<SystemInfRow>> ;
	static constexpr std::uint64_t DOCUMENT = 41U ;						// 同梱元署名とStoreの照合済み文書を表す架空ID
	constexpr auto				   BINARY	= L"%12%\\storahci.sys" ;	// 元選択サービスの宣言
	constexpr auto	 EVENT = L"%SystemRoot%\\System32\\IoLogMsg.dll" ;	// 元イベント資源の宣言
	const std::array seeds{
		SystemInfSection{DOCUMENT, L"msahci_Inst", Context::DEVICE, Context::DEVICE, {}},
		SystemInfSection{DOCUMENT, L"msahci_Inst.HW", Context::HARDWARE, Context::HARDWARE, {}},
		SystemInfSection{
			DOCUMENT, L"msahci_Inst.Services", Context::SERVICES, Context::SERVICES, {}},
	} ; // Windows側の三参照が選択された状態
	const Sections original{
		{L"msahci_Inst",
		 {{0U, L"CopyFiles", {L"storahci_copyfiles"}},
		  {1U, L"AddPowerSetting", {L"AhciPowerSetting1", L"AhciPowerSetting2"}},
		  {2U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_2653&SUBSYS_0F001179"}},
		  {3U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_2653&SUBSYS_0F101179"}},
		  {4U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_27C5&SUBSYS_0F001179"}},
		  {5U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_27C5&SUBSYS_0F101179"}},
		  {6U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_27C5&SUBSYS_0F031179"}},
		  {7U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_27C5&SUBSYS_0F131179"}},
		  {8U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_27C5&SUBSYS_FF011179"}},
		  {9U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_0F031179"}},
		  {10U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_0F131179"}},
		  {11U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF011179"}},
		  {12U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF021179"}},
		  {13U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF031179"}},
		  {14U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF041179"}},
		  {15U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF111179"}},
		  {16U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF121179"}},
		  {17U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF131179"}},
		  {18U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF141179"}},
		  {19U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF311179"}},
		  {20U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF321179"}},
		  {21U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF331179"}},
		  {22U, L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF341179"}}}},
		{L"msahci_Inst.HW", {{0U, L"AddReg", {L"msahci_Inst_HW_AddReg"}}}},
		{L"msahci_Inst.Services",
		 {{0U,
		   L"AddService",
		   {L"storahci", L"2", L"msahci_Service_Inst_Client", L"storahci_EventLog_Inst"}}}},
		{L"msahci_Service_Inst_Client",
		 {{0U, L"DisplayName", {L"Fixture AHCI service"}},
		  {1U, L"ServiceType", {L"1"}},
		  {2U, L"StartType", {L"0"}},
		  {3U, L"ErrorControl", {L"3"}},
		  {4U, L"ServiceBinary", {L"%12%\\storahci.sys"}},
		  {5U, L"LoadOrderGroup", {L"SCSI Miniport"}},
		  {6U, L"AddReg", {L"storahci_general_values"}},
		  {7U, L"AddReg", {L"device_specific_values"}},
		  {8U, L"AddReg", {L"client_sku_values"}}}},
		{L"storahci_EventLog_Inst", {{0U, L"AddReg", {L"storahci_EventLog_AddReg"}}}},
		{L"storahci_EventLog_AddReg",
		 {{0U,
		   {},
		   {L"HKR", L"", L"EventMessageFile", L"0x20000", L"%SystemRoot%\\System32\\IoLogMsg.dll"}},
		  {1U, {}, {L"HKR", L"", L"TypesSupported", L"0x10001", L"7"}}}},
		{L"msahci_Inst_HW_AddReg",
		 {{0U, {}, {L"HKR", L"Interrupt Management", L"0x00000010"}},
		  {1U,
		   {},
		   {L"HKR", L"Interrupt Management\\MessageSignaledInterruptProperties", L"0x00000010"}},
		  {2U, {}, {L"HKR", L"Interrupt Management\\Affinity Policy", L"0x00000010"}},
		  {3U,
		   {},
		   {L"HKR", L"Interrupt Management\\MessageSignaledInterruptProperties", L"MSISupported",
			L"0x10001", L"1"}},
		  {4U,
		   {},
		   {L"HKR", L"Interrupt Management\\MessageSignaledInterruptProperties",
			L"MessageNumberLimit", L"0x10001", L"8"}},
		  {5U,
		   {},
		   {L"HKR", L"Interrupt Management\\Affinity Policy", L"DevicePolicy", L"0x10001", L"5"}},
		  {6U,
		   {},
		   {L"HKR", L"Interrupt Management\\Affinity Policy", L"DevicePriority", L"0x10001", L"3"}},
		  {7U,
		   {},
		   {L"HKR", L"Interrupt Management\\Affinity Policy", L"GroupPolicy", L"0x10001", L"1"}},
		  {8U, {}, {L"HKR", L"StorPort", L"EnableIdlePowerManagement", L"0x10001", L"0x01"}},
		  {9U, {}, {L"HKR", L"DMA Management", L"RemappingSupported", L"0x10001", L"1"}},
		  {10U, {}, {L"HKR", L"DMA Management", L"RemappingFlags", L"0x10001", L"0x1"}}}},
		{L"storahci_general_values",
		 {{0U,
		   {},
		   {L"HKLM", L"SYSTEM\\CurrentControlSet\\Control\\Compatibility\\Driver\\storahci.sys",
			L"Shims", L"0x10008", L"Srbshim"}},
		  {1U, {}, {L"HKR", L"Parameters\\PnpInterface", L"5", L"0x10001", L"0x00000001"}},
		  {2U, {}, {L"HKR", L"Parameters", L"BusType", L"0x10001", L"0x0000000B"}},
		  {3U, {}, {L"HKR", L"Parameters", L"IoTimeoutValue", L"0x10001", L"0x0000001E"}},
		  {4U, {}, {L"HKR", L"Parameters", L"BusyRetryCount", L"0x10001", L"0x000000F0"}},
		  {5U, {}, {L"HKR", L"Parameters", L"BusyPauseTimeInMs", L"0x10001", L"0x000001F4"}}}},
		{L"device_specific_values",
		 {{0U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"ResetInInit", L"0x10008", L"VEN_1106&DEV_6287&REV_*"}},
		  {1U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"SingleIO", L"0x10008", L"VEN_1106&DEV_6287&REV_00"}},
		  {2U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"SingleIO", L"0x10008", L"VEN_1106&DEV_6287&REV_10"}},
		  {3U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"SingleIO", L"0x10008", L"VEN_1106&DEV_6287&REV_20"}},
		  {4U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"IgnoreHotPlug", L"0x10008",
			L"VEN_1002&DEV_4380&REV_*"}},
		  {5U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"NeverNonQueuedErrorRecovery", L"0x10008",
			L"VEN_1002&DEV_4380&REV_*"}},
		  {6U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"EnableCLOReset", L"0x10008",
			L"VEN_1002&DEV_4391&REV_*"}},
		  {7U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"ExpectedMsiMessageCount", L"0x10008",
			L"VEN_1022&DEV_7801&REV_00 8"}},
		  {8U, {}, {L"HKR", L"Parameters\\Device", L"NoFUACommand", L"0x10008", L"HTE*"}},
		  {9U, {}, {L"HKR", L"Parameters\\Device", L"NoFUACommand", L"0x10008", L"Hitachi*"}},
		  {10U, {}, {L"HKR", L"Parameters\\Device", L"NoFUACommand", L"0x10008", L"HTS*"}},
		  {11U, {}, {L"HKR", L"Parameters\\Device", L"NoFUACommand", L"0x10008", L"HDS*"}},
		  {12U, {}, {L"HKR", L"Parameters\\Device", L"NoFUACommand", L"0x10008", L"HDT*"}},
		  {13U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"NeedSetTransferModeCommand", L"0x10008",
			L"MCBQE64GBMPP*"}},
		  {14U, {}, {L"HKR", L"Parameters\\Device", L"NoLPM", L"0x10008", L"WD740ADFD?00NLR1*"}},
		  {15U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"NoLPM", L"0x10008", L"WDC WD740ADFD?00NLR1*"}},
		  {16U, {}, {L"HKR", L"Parameters\\Device", L"NoLPM", L"0x10008", L"Maxtor 6V???E0*"}},
		  {17U, {}, {L"HKR", L"Parameters\\Device", L"NoLPM", L"0x10008", L"Maxtor 6V???F0*"}},
		  {18U, {}, {L"HKR", L"Parameters\\Device", L"NoLPM", L"0x10008", L"Maxtor 7V???E0*"}},
		  {19U, {}, {L"HKR", L"Parameters\\Device", L"NoLPM", L"0x10008", L"Maxtor 7V???F0*"}},
		  {20U, {}, {L"HKR", L"Parameters\\Device", L"NoLPM", L"0x10008", L"SanDisk SSD P4*"}},
		  {21U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"NoIdleD3", L"0x10008", L"INTEL SSD?C??????A4"}},
		  {22U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"NoIdleD3", L"0x10008", L"INTEL SSD?C??????A4?"}},
		  {23U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"NoIdleD3", L"0x10008", L"INTEL SSD?C??????A4??"}},
		  {24U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"NoIdleD3", L"0x10008", L"INTEL SSD?C??????A5"}},
		  {25U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"NoIdleD3", L"0x10008", L"INTEL SSD?C??????A5?"}},
		  {26U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"NoIdleD3", L"0x10008", L"INTEL SSD?C??????A5??"}},
		  {27U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"PRDTSplit", L"0x10008", L"VEN_1022&DEV_43B5&REV_*"}},
		  {28U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"PRDTSplit", L"0x10008", L"VEN_1022&DEV_43B6&REV_*"}},
		  {29U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"PRDTSplit", L"0x10008", L"VEN_1022&DEV_43B7&REV_*"}},
		  {30U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"PRDTSplit", L"0x10008", L"VEN_1022&DEV_43B8&REV_*"}},
		  {31U,
		   {},
		   {L"HKR", L"Parameters\\Device", L"PRDTSplit", L"0x10008", L"VEN_1022&DEV_43C8&REV_*"}}}},
		{L"client_sku_values",
		 {{0U, {}, {L"HKR", L"Parameters", L"IoLatencyCap", L"0x10001", L"0x000001F4"}}}},
		{L"AhciPowerSetting1",
		 {{0U, L"Subgroup", {L"{0012ee47-9041-4b5d-9b77-535fba8b1442}"}},
		  {1U,
		   L"Setting",
		   {L"{0b2d69d7-a2a1-449c-9680-f91c70521c60}", L"Fixture name", L"Fixture description", L"",
			L"0x00000001"}},
		  {2U, L"Value", {L"0", L"Fixture name", L"Fixture description", L"0x00010001", L"0"}},
		  {3U, L"Value", {L"1", L"Fixture name", L"Fixture description", L"0x00010001", L"1"}},
		  {4U, L"Value", {L"2", L"Fixture name", L"Fixture description", L"0x00010001", L"3"}},
		  {5U, L"Value", {L"3", L"Fixture name", L"Fixture description", L"0x00010001", L"2"}},
		  {6U, L"Default", {L"{8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C}", L"0", L"0"}},
		  {7U, L"Default", {L"{8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C}", L"1", L"1"}},
		  {8U, L"Default", {L"{381B4222-F694-41F0-9685-FF5BB260DF2E}", L"0", L"1"}},
		  {9U, L"Default", {L"{381B4222-F694-41F0-9685-FF5BB260DF2E}", L"1", L"1"}},
		  {10U, L"Default", {L"{A1841308-3541-4FAB-BC81-F71556F20B4A}", L"0", L"2"}},
		  {11U, L"Default", {L"{A1841308-3541-4FAB-BC81-F71556F20B4A}", L"1", L"2"}}}},
		{L"AhciPowerSetting2",
		 {{0U, L"Subgroup", {L"{0012ee47-9041-4b5d-9b77-535fba8b1442}"}},
		  {1U,
		   L"Setting",
		   {L"{DAB60367-53FE-4fbc-825E-521D069D2456}", L"Fixture name", L"Fixture description", L"",
			L"0x00000001"}},
		  {2U, L"ValueRange", {L"0", L"300000", L"1", L"millisecond"}},
		  {3U, L"Default", {L"{8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C}", L"0", L"0"}},
		  {4U, L"Default", {L"{8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C}", L"1", L"0"}},
		  {5U, L"Default", {L"{381B4222-F694-41F0-9685-FF5BB260DF2E}", L"0", L"100"}},
		  {6U, L"Default", {L"{381B4222-F694-41F0-9685-FF5BB260DF2E}", L"1", L"100"}},
		  {7U, L"Default", {L"{A1841308-3541-4FAB-BC81-F71556F20B4A}", L"0", L"100"}},
		  {8U,
		   L"Default",
		   {L"{A1841308-3541-4FAB-BC81-F71556F20B4A}", L"1",
			L"100"}}}}} ;	// 同梱AHCIの元作用と架空の表示文言
	const std::array<std::wstring, 1U> allowed{
		L"PCI\\VEN_1234&DEV_5678&SUBSYS_01001234&REV_01"} ;	// 元配布の架空対象
	const auto check = [&]( const Sections &fixture, std::span<const std::wstring> ids,
						   bool accepted, bool moduleAllowed = true,
						   std::uint64_t document = DOCUMENT) {
		std::size_t				  registryRows{} ;	// 同一の選択に属する登録作用の件数
		std::vector<std::wstring> modules ;			// 元のサービス実体とイベント資源だけを記録する
		SystemInfEffectApi		  api ;				// 同期中だけ使う架空の読取API
		api.storAhciInboxDocument = document ;
		api.ahciHardwareIds		  = ids ;
		api.registryRows		  = &registryRows ;
		api.read				  = [&]( const SystemInfSection	  &section,
						std::vector<SystemInfRow> &out) -> NativeError {
			 const auto found = fixture.find( section.name) ;	// 同じ元文書から選んだ節
			 // 不在や別文書の節を空作用として渡さない
			 if( section.document != DOCUMENT || found == fixture.end()) {
				 return HRESULT_FROM_WIN32( ERROR_SECTION_NOT_FOUND) ;
			 }

			 out = found->second ;
			 return 0U ;
		} ;
		api.module = [&]( std::uint64_t identity, std::wstring_view path) -> NativeError {
			modules.emplace_back( path) ;
			return moduleAllowed && identity == DOCUMENT && (path == BINARY || path == EVENT)
					   ? 0U
					   : static_cast<NativeError>( E_ACCESSDENIED) ;
		} ;
		api.service = []( std::wstring_view, SystemServiceEvidence &) -> NativeError {
			return E_ACCESSDENIED ;
		} ;
		api.legacyRegistry = []( const SystemInfEffect &, bool) -> NativeError {
			return E_ACCESSDENIED ;
		} ;
		SystemInfEffects result ;				// 全ての作用が一致した場合だけ返る原観測
		std::uint32_t	 stage{}, observed{} ;	// 元本文を持たない失敗位置
		const auto		 error =
			// 製品と同じ作用検査
			inspectSystemInfEffects( seeds, api, result, stage, observed) ;
		DRIVERCRATE_EXPECT( context, (error == 0U) == accepted) ;
		// 失敗した作用の部分保持や、別用途から借りた実体を許可しない
		if( accepted) {
			const std::vector<std::wstring> expected{BINARY,
													 EVENT} ;	// 実体と正規Windows資源の検査順
			DRIVERCRATE_EXPECT( context, modules == expected && result.copySections.size() == 1U &&
											registryRows == 52U && stage == 0U && observed == 0U) ;
		} else {
			DRIVERCRATE_EXPECT( context, result.effects.empty() && result.copySections.empty()) ;
		}
	} ;
	check( original, allowed, true) ;
	check( original, allowed, false, false) ;
	check( original, {}, false) ;
	check( original, allowed, false, true, 0U) ;
	const std::array<std::wstring, 1U> revised{
		L"pci\\ven_8086&dev_2653&subsys_0f001179&rev_03"} ;					// 元除外と同一SUBSYSでREVだけが具体的なID
	const std::array<std::wstring, 1U> broad{L"PCI\\VEN_8086&DEV_2829"} ;	// 元除外を含む広いID
	check( original, revised, false) ;
	check( original, broad, false) ;
	auto altered = original ;	// 架空元作用の一箇所を変更する対照
	altered.at( L"AhciPowerSetting1")[2].values.back() = L"9" ;
	check( altered, allowed, false) ;
	altered												  = original ;
	altered.at( L"AhciPowerSetting2").back().values.back() = L"1000001" ;
	check( altered, allowed, false) ;
	altered														 = original ;
	altered.at( L"storahci_general_values").front().values.back() = L"OtherShim" ;
	check( altered, allowed, false) ;
	altered														= original ;
	altered.at( L"msahci_Service_Inst_Client")[2].values.front() = L"3" ;
	check( altered, allowed, false) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同一署名文書の範囲型電源設定を、元参照・値域・AC/DC既定値で正負照合します
 * @param[in,out] context 架空の元文書を読む専用結果の集計先です
 * @note 端末のレジストリ、電源設定、SCMの読み取りは行いません
 */
//------------------------------------------------------------------------------
void rangedStoragePowerCases( TestContext &context)
{
	const SystemInfSection	  selected{1U,
									   L"Install.NTamd64",
									   SystemInfContext::DEVICE,
									   SystemInfContext::DEVICE,
									   {}} ;	// 一つの元DDInstallだけを指す
	std::vector<SystemInfRow> root{
		{0U, L"AddPowerSetting", {L"FixturePower", L"fixturepower"}}} ;	// 同一節への再参照を含む元行
	// 現用のGUIDを使わない架空の設定と、Windowsが定義する三プランのAC/DC組
	const std::vector<SystemInfRow> original{
		{0U, L"Subgroup", {L"{12345678-1234-1234-1234-123456789abc}"}},
		{1U,
		 L"Setting",
		 {L"{11111111-1111-1111-1111-111111111111}", L"Test delay", L"", L"", L"1"}},
		{2U, L"ValueRange", {L"10", L"102", L"3", L"Milliseconds"}},
		{3U, L"Default", {L"{8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C}", L"0", L"10"}},
		{4U, L"Default", {L"{8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C}", L"1", L"13"}},
		{5U, L"Default", {L"{381B4222-F694-41F0-9685-FF5BB260DF2E}", L"0", L"16"}},
		{6U, L"Default", {L"{381B4222-F694-41F0-9685-FF5BB260DF2E}", L"1", L"19"}},
		{7U, L"Default", {L"{A1841308-3541-4FAB-BC81-F71556F20B4A}", L"0", L"22"}},
		{8U, L"Default", {L"{A1841308-3541-4FAB-BC81-F71556F20B4A}", L"1", L"100"}}} ;
	auto			   rows = original ;	// 条件ごとに元値の一部だけを変える
	std::size_t		   reads{} ;			// 元選択と参照先を読む回数
	SystemInfEffectApi api ;				// 元署名文書の読取りだけを模擬する
	api.read = [&]( const SystemInfSection	 &section,
				   std::vector<SystemInfRow> &result) -> NativeError {
		++reads ;
		// 元文書、文脈と選択に一致する節だけを返します
		if( section == selected) {
			result = root ;
			return 0U ;
		}

		// 別文書からの補完や任意の参照先を成功にしません
		if( section.document != selected.document ||
		   section.context != SystemInfContext::POWER_SETTING || section.scope != selected.scope ||
		   section.owner != selected.name ||
		   (section.name != L"FixturePower" && section.name != L"SecondPower")) {
			return E_INVALIDARG ;
		}

		result = rows ;
		return 0U ;
	} ;
	std::vector<RangedStoragePowerSetting> result ;									// 全参照が成立した場合の値だけを保持する
	const std::array<std::uint32_t, 6U> defaults{10U, 13U, 16U, 19U, 22U, 100U} ;	// 各プランのAC/DC
	DRIVERCRATE_EXPECT( context,
					   readSelectedRangedStoragePowerSettings( selected, api, result) == 0U) ;
	DRIVERCRATE_EXPECT( context, reads == 2U && result.size() == 1U &&
									result[0].defaults == defaults && result[0].minimum == 10U &&
									result[0].maximum == 102U && result[0].increment == 3U &&
									result[0].attributes == 1U && result[0].description.empty() &&
									result[0].unitLabel == L"Milliseconds") ;

	/** @brief 一欄だけ置き換える元行の条件です */
	struct Change {
		/// 元節の行番号です
		std::size_t	   row ;
		/// 元行で変える位置です
		std::size_t	   field ;
		/// 対照として設定する元欄です
		const wchar_t *value ;
	} ;
	// 非表示以外の属性、不正値域、オーバーフロー、既定値の重複・範囲外・刻み違いを対照にする
	constexpr Change CHANGES[]{
		{1U, 4U, L"2"}, {2U, 0U, L"103"}, {2U, 1U, L"4294967296"}, {2U, 2U, L"0"},
		{4U, 1U, L"0"}, {5U, 1U, L"2"},	  {6U, 2U, L"20"},		   {8U, 2U, L"103"},
	} ;
	// 各対照は別の元入力として再構築し、前の結果を失敗時に保持しないことを確認します
	for( const auto &change : CHANGES) {
		rows								  = original ;
		rows[change.row].values[change.field] = change.value ;
		result.resize( 1U) ;
		DRIVERCRATE_EXPECT( context,
						   readSelectedRangedStoragePowerSettings( selected, api, result) != 0U &&
							   result.empty()) ;
	}

	rows				  = original ;
	root[0].values.back() = L"SecondPower" ;
	DRIVERCRATE_EXPECT( context,
					   readSelectedRangedStoragePowerSettings( selected, api, result) != 0U &&
						   result.empty()) ;
	root[0].values.back() = L"fixturepower" ;
	api.graphReferences	  = 4095U ;
	DRIVERCRATE_EXPECT( context, readSelectedRangedStoragePowerSettings( selected, api, result) ==
										HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) &&
									result.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現用電源定義の新規、維持、変更と共有先の不明を架空観測で確認する
 * @param[in,out] context 独立した分類試験の結果集計
 * @note Windowsの実際の機器、電源プラン、レジストリを使用しない
 */
//------------------------------------------------------------------------------
void storagePowerChangeCases( TestContext &context)
{
	std::array<RangedStoragePowerSetting, 1U> candidate ;	// 候補が宣言する架空の電源定義
	auto &target	 = candidate.front() ;					// 同じ定義の元GUIDと値域だけを変更する
	target.subgroup	 = L"{12345678-1234-1234-1234-123456789abc}" ;
	target.setting	 = L"{11111111-1111-1111-1111-111111111111}" ;
	target.maximum	 = 100U ;
	target.increment = 1U ;
	target.defaults	 = {0U, 10U, 20U, 30U, 40U, 50U} ;
	StoragePowerSettingsSnapshot absent ;	// 保護付きの親だけが実在する現在観測
	absent.controlSet = L"ControlSet001" ;
	auto &leaf		  = absent.settings.emplace_back() ;	// 候補と同じ位置の正式な不在
	leaf.subgroup	  = target.subgroup ;
	leaf.setting	  = target.setting ;
	leaf.keys[0U]	  = {{std::byte{1}}, 1U} ;
	StorageAutomaticDeviceSnapshot	device ;	// 初回の選択と空の共有機器一覧
	std::vector<StoragePowerChange> changes ;	// 各回の出力が差し替わる分類
	// 一つの現在観測を借用して、その時点の候補と現用元から分類を確認する
	const auto						verify = [&]( const StoragePowerSettingsSnapshot &observed,
							 StoragePowerChange					 expected) {
		 DRIVERCRATE_EXPECT(
			 context, classifyStoragePowerChanges( candidate, observed, device, changes) == 0U &&
						  changes.size() == 1U && changes[0] == expected) ;
	} ;
	verify( absent, StoragePowerChange::CREATE) ;
	// 全域を観測した空の一覧と、元位置だけが不在の場合を区別する
	auto &absentLocations = leaf.locations.emplace() ;	// 同じ架空設定の全登録場所
	verify( absent, StoragePowerChange::CREATE) ;
	absentLocations.rootMatch = true ;
	verify( absent, StoragePowerChange::UNVERIFIED) ;
	absentLocations.rootMatch = false ;
	const std::wstring foreignGroup{L"{22222222-2222-2222-2222-222222222222}"} ;	// 別登録の場所
	absentLocations.matchingSubgroups = {foreignGroup} ;
	verify( absent, StoragePowerChange::UNVERIFIED) ;
	absentLocations.matchingSubgroups.clear() ;

	auto  present = absent ;					// 同じ位置に既存定義がある別の観測
	auto &values  = present.settings.front() ;	// 既存の設定値と保護の作業値
	values.keys.fill( leaf.keys[0U]) ;
	values.minimum	 = target.minimum ;
	values.maximum	 = target.maximum ;
	values.increment = target.increment ;
	std::ranges::copy( target.defaults, values.defaults.begin()) ;
	verify( present, StoragePowerChange::UNVERIFIED) ;

	auto &registered = device.selected.package.emplace() ;	// 選択機器の署名付き現用定義
	registered.powerSettings.push_back( target) ;
	// 現用の元署名と値がそろっても、観測された所在が競合していれば維持と判定しない
	verify( present, StoragePowerChange::UNVERIFIED) ;
	values.locations->matchingSubgroups = {L"{12345678-1234-1234-1234-123456789ABC}"} ;
	verify( present, StoragePowerChange::KEEP) ;
	values.locations->rootMatch = true ;
	verify( present, StoragePowerChange::UNVERIFIED) ;
	values.locations->rootMatch = false ;
	values.locations->matchingSubgroups.push_back( foreignGroup) ;
	verify( present, StoragePowerChange::UNVERIFIED) ;
	values.locations->matchingSubgroups.pop_back() ;
	verify( absent, StoragePowerChange::UNVERIFIED) ;
	target.defaults[0] = 2U ;
	verify( present, StoragePowerChange::UPDATE_SELECTED) ;
	auto &peer				= device.owners.emplace_back() ;	// 選択しない機器が同じ定義を利用する
	peer.registered.package = registered ;
	verify( present, StoragePowerChange::UPDATE_SHARED) ;
	values.defaults[0].reset() ;
	verify( present, StoragePowerChange::UNVERIFIED) ;
	peer.registered.package.reset() ;
	DRIVERCRATE_EXPECT( context, classifyStoragePowerChanges( candidate, present, device, changes) ==
										HRESULT_FROM_WIN32( ERROR_RETRY) &&
									changes.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 名前付きイベントの資源省略と現在の署名根拠を独立して検証する
 * @param[in,out] context 架空の現用登録と現在観測の試験集計
 * @note 実サービスやWindowsイベントの変更を行わない
 */
//------------------------------------------------------------------------------
void storageAutomaticEventChangeCases( TestContext &context)
{
	SelectedStorageServiceFacts candidate ;	// 作用検査済み候補を表す架空の元選択
	candidate.name						  = L"FixtureKernel" ;
	candidate.binaryTarget				  = L"X:\\FixtureOS\\System32\\drivers\\fixture.sys" ;
	candidate.auxiliary.emplace().name	  = L"FixtureHelper" ;
	candidate.auxiliary->addServiceFields = {L"FixtureHelper", L"0",	  L"Helper",
											 L"Events",		   L"System", L"Fixture Shared Event"} ;
	const std::wstring			 hash( 64U, L'a') ;	// 架空の選択に結ぶ比較用ハッシュ
	StorageAutomaticHostSnapshot host ;				// 端末の現在値と選択外機器の模擬観測
	host.device.emplace() ;
	host.events.events[0U].name = candidate.name ;
	auto &event					= host.events.events[1U] ;	// 現在の同名イベント
	event.name					= candidate.auxiliary->addServiceFields[5U] ;
	event.present				= true ;
	event.typesSupported		= 31U ;
	event.categoryCount			= 1U ;
	event.security				= {std::byte{1}} ;
	auto &owner =
		// 共有機器の元登録
		host.device->owners.emplace_back().registered.package.emplace() ;
	auto &source		  = owner.eventReferences[1U].emplace() ;	// 署名付き現用登録の明示イベント
	source.name			  = event.name ;
	source.typesSupported = 31U ;
	source.categoryCount  = 1U ;
	// 当該ソースの現在値の意味を、分類処理全体を通して確かめる
	const auto verify = [&]( StorageServiceChange expected) {
		DRIVERCRATE_EXPECT(
			context, classifyStorageAutomaticServiceChanges( candidate, hash, hash, host) == 0U &&
						 host.serviceChanges && (*host.serviceChanges)[2U] == expected) ;
	} ;
	verify( StorageServiceChange::KEEP) ;
	event.messageFile	  = L"%SystemRoot%\\System32\\fixture.dll" ;
	event.messageFileType = REG_EXPAND_SZ ;
	DRIVERCRATE_EXPECT( context, matchesRegisteredStorageEvent( source, event, true) &&
									!matchesRegisteredStorageEvent( source, event)) ;
	verify( StorageServiceChange::UNVERIFIED) ;
	source.messageFile	  = *event.messageFile ;
	source.resourceLeaf	  = L"fixture.dll" ;
	source.resourceSha256 = hash ;
	source.resourceBytes  = 256U ;
	auto &existing =
		// 現用署名と照合した実ファイル
		source.deployedResource.emplace().existing.emplace() ;
	existing.sha256 = hash ;
	existing.bytes	= source.resourceBytes ;
	verify( StorageServiceChange::KEEP) ;
	event.messageFileType = REG_SZ ;
	verify( StorageServiceChange::UNVERIFIED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief イベント登録とSystem32のDLLを現用署名へ独立に照合し、所有と共有変更を検証する
 * @param[in,out] context 架空の候補、現用機器と配置を用いた試験の集計先
 * @note 実際のDLL、レジストリ、サービスや機器を変更しない
 */
//------------------------------------------------------------------------------
void storageAutomaticEventResourceCases( TestContext &context)
{
	SelectedStorageServiceFacts candidate ;	// 架空の元選択と名前付きイベント
	candidate.name			= L"FixtureKernel" ;
	candidate.binaryTarget	= L"X:\\FixtureOS\\System32\\drivers\\fixture.sys" ;
	auto &helper			= candidate.auxiliary.emplace() ;	// 同じ元選択の補助サービスと資源
	helper.name				= L"FixtureHelper" ;
	helper.addServiceFields = {helper.name, L"0",	   L"Helper",
							   L"Events",	L"System", L"Fixture Shared Event"} ;
	auto &copy				= helper.eventMessageCopy.emplace() ;	// コピー元とSystem32の元定義
	copy.fields				= {L"fixture.dll"} ;
	copy.sha256.assign( 64U, L'a') ;
	copy.target							 = L"X:\\FixtureOS\\System32\\fixture.dll" ;
	copy.bytes							 = 256U ;
	copy.dirid							 = 11 ;
	const auto					 oldHash = copy.sha256 ;			// 元ファイルを維持する場合の完全ハッシュ
	StorageAutomaticHostSnapshot host ;								// 実機変更なしで差を与える現在観測
	auto						&device = host.device.emplace() ;	// 選択機器と選択外の利用機器
	host.events.events[0U].name			= candidate.name ;
	auto &named							= host.events.events[1U] ;	// 同名イベントの現在状態
	named.name							= helper.addServiceFields[5U] ;
	auto &placement = host.eventResource.emplace().destination ;	// 候補が指定する正規DLLの現在配置
	placement.directorySecurity = {std::byte{1}} ;
	// 同じ候補の元選択を借用し、登録とDLLの分類をそれぞれ確認する
	const auto verify = [&]( StorageServiceChange event, StorageServiceChange file) {
		DRIVERCRATE_EXPECT( context, classifyStorageAutomaticServiceChanges( candidate, oldHash,
																		   oldHash, host) == 0U &&
										host.serviceChanges &&
										(*host.serviceChanges)[2U] == event &&
										host.eventResource->change == file) ;
	} ;
	using Change = StorageServiceChange ;
	verify( Change::CREATE, Change::CREATE) ;
	auto &existing	  = placement.existing.emplace() ;	// 同じ名前で残っている実ファイル
	existing.sha256	  = oldHash ;
	existing.bytes	  = copy.bytes ;
	existing.security = {std::byte{1}} ;
	verify( Change::CREATE, Change::UNVERIFIED) ;
	named.present	  = true ;
	named.messageFile = L"%SystemRoot%\\System32\\IoLogMsg.dll;%SystemRoot%\\System32\\fixture.dll" ;
	named.messageFileType = REG_EXPAND_SZ ;
	named.typesSupported  = 31U ;
	named.categoryCount	  = 1U ;
	named.security		  = {std::byte{1}} ;
	auto &peer =
		// 同じイベント値を使い、資源を省略する元登録
		device.owners.emplace_back().registered ;
	auto &omitted		   = peer.package.emplace().eventReferences[1U].emplace() ;	// 資源省略の参照
	omitted.name		   = named.name ;
	omitted.typesSupported = 31U ;
	omitted.categoryCount  = 1U ;
	peer.events.events[1U] = named ;
	verify( Change::UNVERIFIED, Change::UNVERIFIED) ;
	// 明示した資源の所有を確認する選択機器の元参照
	auto &owner			   = device.selected.package.emplace().eventReferences[1U].emplace( omitted) ;
	owner.messageFile	   = *named.messageFile ;
	owner.resourceLeaf	   = copy.fields.front() ;
	owner.resourceSha256   = oldHash ;
	owner.resourceBytes	   = copy.bytes ;
	owner.deployedResource = placement ;
	device.selected.events.events[1U] = named ;
	verify( Change::KEEP, Change::KEEP) ;
	copy.sha256.assign( 64U, L'b') ;
	verify( Change::KEEP, Change::UPDATE_SHARED) ;
	device.owners.clear() ;
	verify( Change::KEEP, Change::UPDATE_SELECTED) ;
	existing.fileId[0U] = 2U ;
	verify( Change::KEEP, Change::UNVERIFIED) ;
	existing.fileId[0U] = 0U ;
	existing.security.clear() ;
	verify( Change::KEEP, Change::UNVERIFIED) ;
	existing.security = {std::byte{1}} ;
	auto &other = device.owners.emplace_back().registered ;	// 別イベントで同じDLLを使う現用機器
	// 同じ資源に結び付いた別名イベントの元参照
	auto &differentEvent		 = other.package.emplace().eventReferences[1U].emplace( owner) ;
	differentEvent.name			 = L"Other Fixture Event" ;
	other.events.events[1U]		 = named ;
	other.events.events[1U].name = differentEvent.name ;
	verify( Change::KEEP, Change::UPDATE_SHARED) ;
	device.selected.package.reset() ;
	verify( Change::UNVERIFIED, Change::UPDATE_SHARED) ;
	placement.existing.reset() ;
	verify( Change::UNVERIFIED, Change::UNVERIFIED) ;
	placement.directorySecurity.clear() ;
	DRIVERCRATE_EXPECT(
		context, classifyStorageAutomaticServiceChanges( candidate, oldHash, oldHash, host) != 0U &&
					 !host.serviceChanges && host.eventResource->change == Change::UNVERIFIED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空の起動サービスとSYSの所有を現用の署名元に照合する
 * @param[in,out] context 所有の有無といずれの変更を確認したかを集計する
 * @note 実機器とWindowsの設定、ファイルを操作しない
 */
//------------------------------------------------------------------------------
void storageAutomaticBootChangeCases( TestContext &context)
{
	SelectedStorageServiceFacts candidate ;	// 架空の元選択とSYSの全バイトを表すハッシュ
	candidate.name		   = L"FixtureBoot" ;
	candidate.type		   = SERVICE_KERNEL_DRIVER ;
	candidate.start		   = SERVICE_BOOT_START ;
	candidate.errorControl = SERVICE_ERROR_NORMAL ;
	candidate.group		   = L"SCSI Miniport" ;
	candidate.binaryTarget = L"X:\\FixtureOS\\System32\\drivers\\fixture.sys" ;
	candidate.binarySha256.assign( 64U, L'a') ;
	StorageAutomaticBootSnapshot boot ;	// 保護付き親の下に候補のSYSとSCMを読む作業観測
	boot.related.name				   = candidate.name ;
	boot.destination.directorySecurity = {std::byte{1}} ;
	StorageAutomaticDeviceSnapshot device ;	// 選択機器と他機器の現在元署名を差し替える
	// 同じ選択の各状態を関数全体で判定する
	const auto					   verify = [&]( StorageServiceChange expected) {
		DRIVERCRATE_EXPECT( context,
											   classifyStorageAutomaticBoot( candidate, device, boot) == expected) ;
	} ;

	verify( StorageServiceChange::CREATE) ;
	auto &file	  = boot.destination.existing.emplace() ;	// 配置先に残るSYSの保護と元ハッシュ
	file.sha256	  = candidate.binarySha256 ;
	file.security = {std::byte{1}} ;
	verify( StorageServiceChange::UNVERIFIED) ;

	auto &config		= boot.related.evidence.emplace() ;	// Windowsが返した架空の現在構成
	config.name			= candidate.name ;
	config.type			= candidate.type ;
	config.start		= candidate.start ;
	config.errorControl = candidate.errorControl ;
	config.group		= *candidate.group ;
	config.binary		= L"\\SystemRoot\\System32\\drivers\\fixture.sys" ;
	config.security		= {std::byte{1}} ;
	verify( StorageServiceChange::UNVERIFIED) ;

	auto &owner					= device.selected.package.emplace() ;	// 署名付き元INFとCATの実選択
	owner.installedService		= candidate.name ;
	owner.driverSha256			= file.sha256 ;
	owner.bootService.emplace() = {candidate.binaryTarget, *candidate.group, candidate.type,
								   candidate.start, candidate.errorControl} ;
	verify( StorageServiceChange::KEEP) ;
	candidate.binarySha256.assign( 64U, L'b') ;
	verify( StorageServiceChange::UPDATE_SELECTED) ;
	auto &peer =
		// 同名サービスを使う別機器
		device.owners.emplace_back().registered.package.emplace() ;
	peer = owner ;
	verify( StorageServiceChange::UPDATE_SHARED) ;
	peer.driverSha256.assign( 64U, L'c') ;
	verify( StorageServiceChange::UNVERIFIED) ;
	peer.driverSha256 = file.sha256 ;
	config.binary	  = L"X:\\OtherOS\\System32\\drivers\\fixture.sys" ;
	verify( StorageServiceChange::UNVERIFIED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ標準NVMeとPCIが所有する全作用を構造、原順、実体検査の受渡しまで確認します
 * @param[in,out] context 専用テストの有限な結果集計です
 * @note 架空の文書IDと読取専用callbackを使い、実電源・registry・SCMを操作しません
 */
//------------------------------------------------------------------------------
void typedNvmeInboxCases( TestContext &context)
{
	using Context						= SystemInfContext ;
	using Sections						= std::map<std::wstring, std::vector<SystemInfRow>> ;
	using Documents						= std::map<std::uint64_t, Sections> ;
	static constexpr std::uint64_t NVME = 23U ;				// 標準NVMeの原署名と対応Storeを仮定する文書です
	static constexpr std::uint64_t PCI	= 29U ;				// 選択されたPCI HWを保有する独立した文書です
	constexpr auto SERVICE_BINARY = L"%12%\\stornvme.sys" ;	// 未展開DIRID付きのサービス実体です
	constexpr auto ABSOLUTE_BINARY =
		L"X:\\FixtureOS\\System32\\drivers\\stornvme.sys" ;	// SetupAPI展開済みの実体位置です
	constexpr auto MESSAGE =
		L"%SystemRoot%\\System32\\IoLogMsg.dll" ;	// 展開式を保持するイベント資源です
	constexpr auto MSI =
		L"Interrupt Management\\MessageSignaledInterruptProperties" ;	// 元HWの割り込み設定です
	constexpr auto AFFINITY =
		L"Interrupt Management\\Affinity Policy" ;	// 元HWのアフィニティ設定です
	constexpr auto OVERRIDES =
		L"nvme_registry_device_specific_values" ;		// 同じサービスの架空PCI追記です
	constexpr auto	 POWER1 = L"NVMePowerSetting1" ;	// 一番目の電源設定の元参照です
	constexpr auto	 POWER2 = L"NVMePowerSetting2" ;	// 二番目の電源設定の元参照です
	const std::array seeds{
		SystemInfSection{NVME, L"Stornvme_Inst", Context::DEVICE, Context::DEVICE, {}},
		SystemInfSection{NVME, L"Stornvme_Inst.HW", Context::HARDWARE, Context::HARDWARE, {}},
		SystemInfSection{NVME, L"Stornvme_Inst.Services", Context::SERVICES, Context::SERVICES, {}},
		SystemInfSection{PCI, L"PciForceSBR.HW", Context::HARDWARE, Context::HARDWARE, {}},
	} ; // 選択graphが元所有者と結んだ四つの開始節です
	// 全参照と全fieldを同期fixtureへ与え、同じ文書に選択外の作用も置きます
	Documents original{
		{NVME,
		 {{L"Stornvme_Inst",
		   {{0U, L"CopyFiles", {L"Stornvme_copyfiles"}},
			{1U,
			 L"AddPowerSetting",
			 {POWER1, POWER2, L"NVMePowerSetting3", L"NVMePowerSetting4"}}}},
		  {L"Stornvme_Inst.HW",
		   {{0U, L"AddReg", {L"Stornvme_Inst_HW_AddReg"}},
			{1U, L"Include", {L"pci.inf"}},
			{2U, L"Needs", {L"PciForceSBR.HW"}}}},
		  {L"Stornvme_Inst.Services",
		   {{0U,
			 L"AddService",
			 {L"stornvme", L"0x00000002", L"Stornvme_Service_Inst", L"Stornvme_EventLog_Inst"}}}},
		  {L"Stornvme_Service_Inst",
		   {{0U, L"DisplayName", {L"架空の NVMe サービス"}},
			{1U, L"ServiceType", {L"1"}},
			{2U, L"StartType", {L"0"}},
			{3U, L"ErrorControl", {L"3"}},
			{4U, L"ServiceBinary", {SERVICE_BINARY}},
			{5U, L"LoadOrderGroup", {L"SCSI Miniport"}},
			{6U, L"AddReg", {L"nvme_registry_values"}},
			{7U, L"AddReg", {OVERRIDES}}}},
		  {L"Stornvme_EventLog_Inst", {{0U, L"AddReg", {L"Stornvme_EventLog_AddReg"}}}},
		  {L"Stornvme_EventLog_AddReg",
		   {{0U, {}, {L"HKR", L"", L"EventMessageFile", L"0x00020000", MESSAGE}},
			{1U, {}, {L"HKR", L"", L"TypesSupported", L"0x00010001", L"7"}}}},
		  {L"Stornvme_Inst_HW_AddReg",
		   {{0U, {}, {L"HKR", L"Interrupt Management", L"0x00000010"}},
			{1U, {}, {L"HKR", MSI, L"0x00000010"}},
			{2U, {}, {L"HKR", AFFINITY, L"0x00000010"}},
			{3U, {}, {L"HKR", MSI, L"MSISupported", L"0x10001", L"1"}},
			{4U, {}, {L"HKR", MSI, L"MessageNumberLimit", L"0x10001", L"2048"}},
			{5U, {}, {L"HKR", AFFINITY, L"DevicePolicy", L"0x10001", L"5"}},
			{6U, {}, {L"HKR", AFFINITY, L"DevicePriority", L"0x10001", L"3"}},
			{7U, {}, {L"HKR", AFFINITY, L"GroupPolicy", L"0x10001", L"1"}},
			{8U, {}, {L"HKR", L"DMA Management", L"RemappingSupported", L"0x10001", L"1"}},
			{9U, {}, {L"HKR", L"DMA Management", L"RemappingFlags", L"0x10001", L"0x1"}}}},
		  {L"nvme_registry_values",
		   {{0U, {}, {L"HKR", L"Parameters\\PnpInterface", L"5", L"0x10001", L"1"}},
			{1U, {}, {L"HKR", L"Parameters", L"BusType", L"0x10001", L"0x11"}},
			{2U, {}, {L"HKR", L"Parameters", L"IoTimeoutValue", L"0x10001", L"0xA"}},
			{3U, {}, {L"HKR", L"Parameters", L"StorageSupportedFeatures", L"0x10001", L"3"}}}},
		  {L"IntelNVMeDeviceInstallSection", {{0U, L"Unknown", {L"Unexpected"}}}}}},
		{PCI,
		 {{L"PciForceSBR.HW", {{0U, L"AddReg", {L"PciForceSBR.RegHW"}}}},
		  {L"PciForceSBR.RegHW",
		   {{0U,
			 {},
			 {L"HKR", L"e5b3b5ac-9725-4f78-963f-03dfb1d828c7", L"ForceSBR", L"0x10001", L"1"}}}},
		  {L"PCI_BRIDGE.Services", {{0U, L"CopyFiles", {L"Unselected"}}}}}}} ;
	// 五つの架空PCI IDは同じマルチ文字列へ別々の追記を作ります
	for( std::uint32_t index = 0U; index < 5U; ++index) {
		original.at( NVME)[OVERRIDES].push_back(
			{index,
			 {},
			 {L"HKR", L"Parameters\\Device", L"IoStripeAlignment", L"0x10008",
			  L"VEN_FFFE&DEV_BA0" + std::to_wstring( index) + L"&REV_?? 128"}}) ;
	}

	original.at( NVME)[OVERRIDES].push_back(
		{5U,
		 {},
		 {L"HKR", L"Parameters\\Device", L"DisableF0TimestampSync", L"0x10008",
		  L"VEN_FFFF&DEV_BA00&REV_?? 1"}}) ;
	// 四つの元設定GUIDを参照の位置に結びます
	constexpr std::array GUIDS{
		L"{FC95AF4D-40E7-4B6D-835A-56D131DBC80E}", L"{D639518A-E56D-4345-8AF2-B9F32FB26109}",
		L"{DBC9E238-6DE9-49E3-92CD-8C2B4946B472}", L"{D3D55EFD-C1FF-424E-9DC3-441BE7833010}"} ;
	// 三つのプランは各設定に同じ順で現れます
	constexpr std::array PLANS{L"{8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C}",
							   L"{381B4222-F694-41F0-9685-FF5BB260DF2E}",
							   L"{A1841308-3541-4FAB-BC81-F71556F20B4A}"} ;
	// 四つの設定は各自のGUIDとローカライズ済み表示、すべてのプラン・状態を所有します
	for( std::size_t index = 0U; index < GUIDS.size(); ++index) {
		const auto sectionName =
			L"NVMePowerSetting" + std::to_wstring( index + 1U) ;	// 元AddPowerSettingの参照名です
		auto &rows = original.at( NVME)[sectionName] ;				// 一設定分の九行を所有します
		rows	   = {{0U, L"Subgroup", {L"{0012ee47-9041-4b5d-9b77-535fba8b1442}"}},
					  {1U,
					   L"Setting",
					   {GUIDS[index], L"架空の電源名", L"架空の電源設定です", L"", L"0x00000001"}},
					  {2U, L"ValueRange", {L"0", L"60000", L"1", L"ミリ秒"}}} ;
		// 同じ設定内で三プランそれぞれのACとDCを一度ずつ定義します
		for( const auto plan : PLANS) {
			rows.push_back(
				{static_cast<std::uint32_t>( rows.size()), L"Default", {plan, L"0", L"0"}}) ;
			rows.push_back(
				{static_cast<std::uint32_t>( rows.size()), L"Default", {plan, L"1", L"60000"}}) ;
		}
	}

	// 所有fixtureだけを借用して原文全行と実ファイルの個別失敗を共通入口に与えます
	const auto check = [&]( const Documents &source, std::span<const SystemInfSection> selection,
						   bool accepted, std::uint64_t nvmeId = NVME, std::uint64_t pciId = PCI,
						   std::size_t deniedModule = 0U, std::size_t incomingEdges = 0U) {
		std::size_t				  registryRows{} ;		// 元全registry作用の有限件数です
		std::size_t				  forbiddenReads{} ;	// 選択外の作用、SCM、旧registry検査の呼出しです
		std::vector<std::wstring> modules ;				// NVMeの元サービスとイベント資源を参照順で保持します
		SystemInfEffectApi		  api ;					// 一回の同期検査にだけ渡す架空APIです
		api.storNvmeInboxDocument = nvmeId ;
		api.pciNvmeInboxDocument  = pciId ;
		api.registryRows		  = &registryRows ;
		api.graphReferences		  = incomingEdges ;
		api.read				  = [&]( const SystemInfSection	  &section,
						std::vector<SystemInfRow> &out) -> NativeError {
			 const auto document = source.find( section.document) ;	// 同じ文書IDの原節だけを参照します
			 // 選択外の節が正常入力から読まれる場合を検出します
			 if( section.name == L"IntelNVMeDeviceInstallSection" ||
				section.name == L"PCI_BRIDGE.Services") {
				 ++forbiddenReads ;
			 }

			 // 不明な文書や欠けた節を既定の空節で補いません
			 if( document == source.end()) {
				 return E_INVALIDARG ;
			 }

			 const auto part = document->second.find( section.name) ;	// 同文書内の一致する元節です
			 // 他の節の行を読み取って検査を続けません
			 if( part == document->second.end()) {
				 return HRESULT_FROM_WIN32( ERROR_SECTION_NOT_FOUND) ;
			 }

			 out = part->second ;
			 return 0U ;
		} ;
		api.module = [&]( std::uint64_t document, std::wstring_view path) -> NativeError {
			modules.emplace_back( path) ;
			return document == NVME && modules.size() != deniedModule &&
						   (path == SERVICE_BINARY || path == ABSOLUTE_BINARY || path == MESSAGE)
					   ? 0U
					   : E_ACCESSDENIED ;
		} ;
		api.service = [&]( std::wstring_view, SystemServiceEvidence &) -> NativeError {
			++forbiddenReads ;
			return E_ACCESSDENIED ;
		} ;
		api.legacyRegistry = [&]( const SystemInfEffect &, bool) -> NativeError {
			++forbiddenReads ;
			return E_ACCESSDENIED ;
		} ;
		SystemInfEffects result ;		// 全作用が成立した場合の原行とコピー参照です
		std::uint32_t	 stage{} ;		// 失敗時は有限な型だけを出力します
		std::uint32_t	 observed{} ;	// 実体検査に失敗した場合の役割です
		const auto		 error = inspectSystemInfEffects( selection, api, result, stage,
														 observed) ;	// 全作用の製品入口です
		DRIVERCRATE_EXPECT( context, (error == 0U) == accepted) ;
		// 不明な実体の元失敗を維持して以後の検査を止めます
		if( deniedModule != 0U) {
			const auto role = deniedModule == 1U
								  ? SystemInfModuleRole::SERVICE_SYS
								  : SystemInfModuleRole::EVENT_RESOURCE ;	// 失敗を返した実体用途です
			DRIVERCRATE_EXPECT( context, modules.size() == deniedModule &&
											error == static_cast<NativeError>( E_ACCESSDENIED) &&
											stage == static_cast<std::uint32_t>(
														 SystemInfDiagnosticStage::MODULE) &&
											observed == static_cast<std::uint32_t>( role)) ;
		}

		// 不一致を一部の作用の成功として返しません
		if( !accepted) {
			DRIVERCRATE_EXPECT( context, result.effects.empty() && result.copySections.empty() &&
											result.services.empty()) ;
			return stage ;
		}

		DRIVERCRATE_EXPECT(
			context, stage == 0U && forbiddenReads == 0U && registryRows == 23U &&
						 result.effects.size() == 75U && result.references == incomingEdges + 14U &&
						 result.services.empty() && result.copySections.size() == 1U &&
						 result.copySections.front() == seeds.front()) ;
		DRIVERCRATE_EXPECT(
			context, modules.size() == 2U &&
						 modules[0] == source.at( NVME).at( L"Stornvme_Service_Inst")[4].values[0] &&
						 modules[1] == MESSAGE) ;
		// 所有文書、行順、全fieldを返し、架空の実体や共通経路に書換えません
		for( const auto &effect : result.effects) {
			DRIVERCRATE_EXPECT(
				context,
				source.at( effect.source.document).at( effect.source.name).at( effect.row.ordinal) ==
					effect.row) ;
			// 電源設定の所有者は一つのNVMe基本節です
			if( effect.source.context == Context::POWER_SETTING) {
				DRIVERCRATE_EXPECT( context, effect.source.document == NVME &&
												effect.source.owner == L"Stornvme_Inst") ;
			}

			// PCIは元HWに属する規定の二節だけを返します
			if( effect.source.document == PCI) {
				DRIVERCRATE_EXPECT( context, effect.source.scope == Context::HARDWARE &&
												effect.source.owner.empty() &&
												(effect.source.name == L"PciForceSBR.HW" ||
												 effect.source.name == L"PciForceSBR.RegHW")) ;
			}
		}

		return stage ;
	} ;
	check( original, seeds, true) ;
	check( original, seeds, false, 0U, 0U) ;
	check( original, seeds, false, NVME, 0U) ;
	check( original, seeds, false, 0U, PCI) ;
	check( original, seeds, false, NVME, NVME) ;
	check( original, seeds, false, PCI, NVME) ;
	check( original, seeds, true, NVME, PCI, 0U, 4082U) ;
	check( original, seeds, false, NVME, PCI, 0U, 4083U) ;
	check( original, seeds, false, NVME, PCI, 1U) ;
	check( original, seeds, false, NVME, PCI, 2U) ;
	check( original, std::span{seeds}.first( 3U), false) ;

	auto changed = original ;	// 各負例の変更を持ち越さない独立入力です
	changed.at( NVME).at( L"Stornvme_Service_Inst")[4].values[0] = ABSOLUTE_BINARY ;
	changed.at( NVME).at( POWER1)[3].values[2]				   = L"0x0000000A" ;
	check( changed, seeds, true) ;

	/** @brief 原field一つだけを変えて専用検査の最初の拒否区分を確認します */
	struct Change {
		/// 作用を所有する文書IDです
		std::uint64_t			 document ;
		/// 原文書内の節名です
		const wchar_t			*section ;
		/// 元節内の0起点行です
		std::size_t				 row ;
		/// 元行内の0起点fieldです
		std::size_t				 field ;
		/// 一条件だけを変える入力です
		const wchar_t			*value ;
		/// 他の成功源で補わず保持する元拒否です
		SystemInfDiagnosticStage stage ;
	} ;
	constexpr auto POWER = SystemInfDiagnosticStage::POWER_SETTING ;	// 電源参照と設定の有限診断です
	constexpr auto DIRECTIVE =
		SystemInfDiagnosticStage::DIRECTIVE ;	// 元選択や起動サービスの有限診断です
	constexpr auto REGISTRY =
		SystemInfDiagnosticStage::REGISTRY ;	// 元registry行と所有scopeの有限診断です
	// 各負例は検査対象のfieldを一つだけ置き換えます
	constexpr Change CHANGES[]{
		{NVME, L"Stornvme_Inst", 1U, 0U, POWER2, POWER},
		{NVME, L"Stornvme_Inst.HW", 1U, 0U, L"other.inf", DIRECTIVE},
		{NVME, L"Stornvme_Service_Inst", 2U, 0U, L"3", DIRECTIVE},
		{NVME, L"Stornvme_Service_Inst", 3U, 0U, L"1", DIRECTIVE},
		{NVME, L"Stornvme_Service_Inst", 4U, 0U, L"%12%\\other.sys", DIRECTIVE},
		{NVME, L"Stornvme_Service_Inst", 5U, 0U, L"Boot Bus Extender", DIRECTIVE},
		{NVME, L"Stornvme_Inst_HW_AddReg", 0U, 2U, L"0x00000004", REGISTRY},
		{NVME, L"nvme_registry_values", 0U, 2U, L"0x5", REGISTRY},
		{NVME, OVERRIDES, 0U, 3U, L"0x10000", REGISTRY},
		{NVME, OVERRIDES, 0U, 4U, L"VEN_FFFE&DEV_BA01&REV_?? 128", REGISTRY},
		{NVME, L"Stornvme_EventLog_AddReg", 0U, 4U,
		 L"%SystemRoot%\\System32\\IoLogMsg.dll;other.dll", REGISTRY},
		{PCI, L"PciForceSBR.RegHW", 0U, 0U, L"HKLM", REGISTRY},
		{PCI, L"PciForceSBR.RegHW", 0U, 4U, L"2", REGISTRY},
		{NVME, POWER1, 0U, 0U, L"{00000000-0000-0000-0000-000000000000}", POWER},
		{NVME, POWER1, 1U, 0U, GUIDS[1], POWER},
		{NVME, POWER1, 1U, 1U, L"@missing.dll,-123", POWER},
		{NVME, POWER1, 1U, 2U, L"%Unresolved%", POWER},
		{NVME, POWER1, 1U, 3U, L"1", POWER},
		{NVME, POWER1, 1U, 4U, L"3", POWER},
		{NVME, POWER1, 2U, 2U, L"2", POWER},
		{NVME, POWER1, 2U, 3U, L"秒", POWER},
		{NVME, POWER1, 3U, 0U, L"{00000000-0000-0000-0000-000000000000}", POWER},
		{NVME, POWER1, 3U, 1U, L"1", POWER},
		{NVME, POWER1, 3U, 1U, L"2", POWER},
		{NVME, POWER1, 3U, 2U, L"60001", POWER},
	} ;
	// 別作用の成立や先行値の読み出しで元不一致を補わないことを個別に確かめます
	for( const auto &change : CHANGES) {
		changed = original ;
		changed.at( change.document).at( change.section).at( change.row).values.at( change.field) =
			change.value ;
		DRIVERCRATE_EXPECT( context, check( changed, seeds, false) ==
										static_cast<std::uint32_t>( change.stage)) ;
	}

	changed = original ;
	changed.at( NVME).at( POWER1).pop_back() ;
	check( changed, seeds, false) ;
	changed								   = original ;
	changed.at( NVME).at( POWER1)[4].ordinal = 3U ;
	check( changed, seeds, false) ;
	changed = original ;
	changed.at( NVME).at( POWER1).push_back( {9U, L"AddReg", {OVERRIDES}}) ;
	check( changed, seeds, false) ;
	changed = original ;
	changed.at( NVME).at( L"Stornvme_Inst").push_back( {2U, L"DelFiles", {L"Stornvme_copyfiles"}}) ;
	check( changed, seeds, false) ;
	changed											= original ;
	changed.at( PCI).at( L"PciForceSBR.RegHW")[0].key = L"NamedRow" ;
	check( changed, seeds, false) ;
	auto wrongOwner		= seeds ;	// 同じ節の見かけで別HW所有者に移す負例です
	wrongOwner[3].owner = L"stornvme" ;
	check( original, wrongOwner, false) ;
	auto extra = std::vector<SystemInfSection>{	// 同じ署名済みPCIの選択外サービスを加えます
											   seeds.begin(), seeds.end()} ;
	extra.push_back( {PCI, L"PCI_BRIDGE.Services", Context::SERVICES, Context::SERVICES, {}}) ;
	check( original, extra, false) ;

	// 同じ原行を現在登録の読取り入口へ渡し、選択外の節を監視する
	const auto inspectRegistered = [&]( const Documents &source, bool accepted) {
		std::size_t		   outside{} ;	// 選択と元参照の範囲外を読んだ件数
		SystemInfEffectApi api ;		// INFの行以外の操作を持たない現在登録用の架空API
		api.storNvmeInboxDocument = NVME ;
		api.pciNvmeInboxDocument  = PCI ;
		// 同じ文書の指定節だけを返し、電源宣言は署名済み原行から読む
		api.read = [&]( const SystemInfSection	 &request,
					   std::vector<SystemInfRow> &rows) -> NativeError {
			// 選択外のPCI節の参照を成功として扱わない
			if( request.name == L"FixtureUnused.HW") {
				++outside ;
			}

			const auto &sections = source.at( request.document) ;	// 同じ文書の元節
			const auto	found	 = sections.find( request.name) ;	// 元選択が指定した元節
			// 不在は空節に置き換えず元診断を返す
			if( found == sections.end()) {
				return HRESULT_FROM_WIN32( ERROR_SECTION_NOT_FOUND) ;
			}

			rows = found->second ;
			return 0U ;
		} ;

		std::vector<RangedStoragePowerSetting> settings ;						// 元選択の電源宣言の結果
		const auto error = readVerifiedNvmeInboxPowerSettings( api, settings) ;	// 現在登録の元照合
		DRIVERCRATE_EXPECT( context,
						   outside == 0U && (accepted ? error == 0U && settings.size() == 4U
													  : error != 0U && settings.empty())) ;
	} ;
	changed								 = original ;
	changed.at( PCI)[L"FixtureUnused.HW"] = {{0U, L"AddPowerSetting", {POWER1}}} ;
	inspectRegistered( changed, true) ;
	changed.at( PCI).at( L"PciForceSBR.HW").push_back( {1U, L"AddPowerSetting", {POWER1}}) ;
	inspectRegistered( changed, false) ;
	changed													= original ;
	changed.at( NVME).at( L"Stornvme_Inst.HW")[1U].values[0U] = L"fixture.inf" ;
	inspectRegistered( changed, false) ;
}
//------------------------------------------------------------------------------
/**
 * @brief Store投影表の読取欠落を構築時拒否し旧表の構築契約を維持します
 * @param[in,out] context 同processの有限assertion集計です
 * @note Scopeを構築/破棄するだけで、file/native操作を呼びません
 */
//------------------------------------------------------------------------------
void projectionScopeCases( TestContext &context)
{
	std::size_t						  calls{} ;	// 構築中に一操作でも呼ばれれば独立期待に反します
	inf_dependency_native_detail::Api api ;		// 元五操作の完全な無実行表です
	api.version = [&calls]( OSVERSIONINFOEXW &, SYSTEM_INFO &) -> NativeError {
		++calls ;
		return E_NOTIMPL ;
	} ;
	api.windowsDirectory = [&calls]( std::wstring &) -> NativeError {
		++calls ;
		return E_NOTIMPL ;
	} ;
	api.infSignature = [&calls]( const std::wstring &, SP_INF_SIGNER_INFO_W &) -> NativeError {
		++calls ;
		return E_NOTIMPL ;
	} ;
	api.catalogSignature = [&calls]( const std::wstring &,
									std::span<const std::wstring>) -> NativeError {
		++calls ;
		return E_NOTIMPL ;
	} ;
	api.driverStore = [&calls]( const std::wstring &, std::wstring &) -> NativeError {
		++calls ;
		return E_NOTIMPL ;
	} ;
	OfficialDownloadWorkspace projected ;	// 初期化しない非所有参照先です。実fileを作りません
	api.projectedStore = &projected ;
	auto missing =
		// 欠落readPathを実FSへ補完させません
		inf_dependency_native_detail::Access::create( api) ;
	DRIVERCRATE_EXPECT( context, !missing && calls == 0U) ;
	missing.reset() ;
	api.projectedStore = nullptr ;
	auto legacy =
		// 投影なしの旧完全表は維持します
		inf_dependency_native_detail::Access::create( api) ;
	DRIVERCRATE_EXPECT( context, legacy && calls == 0U) ;
	legacy.reset() ;
	api.projectedStore = &projected ;
	api.readPath	   = [&calls]( std::wstring_view, std::wstring &) -> NativeError {
		  ++calls ;
		  return E_NOTIMPL ;
	} ;
	auto complete = inf_dependency_native_detail::Access::create(
		api) ;	// 完全表の構築だけを確認し内容許可としません
	DRIVERCRATE_EXPECT( context, complete && calls == 0U) ;
	complete.reset() ;
	DRIVERCRATE_EXPECT( context,
					   calls == 0U && inf_dependency_native_detail::activeApi() == nullptr) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同梱WinUSBの三選択節、相対値およびサービス実体を同じ文書で要求することを確認します
 * @param[in,out] context 同じ試験processの集計です
 * @note 文書と実体の証拠を架空化し、端末のサービス設定を読み取らずに検査します
 */
//------------------------------------------------------------------------------
void typedWinUsbInboxCases( TestContext &context)
{
	using Context				   = SystemInfContext ;
	using Stage					   = SystemInfDiagnosticStage ;
	using Sections				   = std::map<std::wstring, std::vector<SystemInfRow>> ;
	constexpr std::uint64_t INBOX  = 2U ;					// 正規の架空WinUSB文書です
	constexpr auto			BINARY = L"%12%\\WinUSB.SYS" ;	// サービスが指定する元DIRIDとファイルです
	const std::array		selected{
		   SystemInfSection{INBOX, L"WINUSB.NT", Context::DEVICE, Context::DEVICE, {}},
		   SystemInfSection{INBOX, L"WINUSB.NT.HW", Context::HARDWARE, Context::HARDWARE, {}},
		   SystemInfSection{INBOX, L"WINUSB.NT.Services", Context::SERVICES, Context::SERVICES, {}},
	   } ; // 同じ文書に到達した三つの元入口です
	const Sections original{
		{L"WINUSB.NT",
		 {{0U, L"CopyFiles", {L"WINUSB.CopyFiles"}}, {1U, L"AddReg", {L"WINUSB.AddReg"}}}},
		{L"WINUSB.NT.HW", {}},
		{L"WINUSB.NT.Services", {{0U, L"AddService", {L"WINUSB", L"0x2", L"WINUSB.AddService"}}}},
		{L"WINUSB.AddService",
		 {{0U, L"DisplayName", {L"架空USBドライバー"}},
		  {1U, L"Description", {L"架空USB機器用のドライバー"}},
		  {2U, L"ServiceType", {L"1"}},
		  {3U, L"StartType", {L"3"}},
		  {4U, L"ErrorControl", {L"1"}},
		  {5U, L"ServiceBinary", {BINARY}}}},
		{L"WINUSB.AddReg",
		 {{0U, {}, {L"HKR", L"", L"DevLoader", L"", L"*ntkern"}},
		  {1U, {}, {L"HKR", L"", L"NTMPDriver", L"", L"winusb.sys"}}}},
	} ; // 同じ文書だけが返す展開済みの到達全行です

	// 各試行で文書、元の選択と実体拒否の引数を借用し、部分結果が出ないことを確認します
	const auto check = [&]( const Sections &source, std::span<const SystemInfSection> selection,
						   std::uint64_t bound, Stage expected = {},
						   std::wstring_view rejectModule = {}) {
		std::size_t				  registryRows{} ;	// 同期検査と共有するレジストリ行予算です
		std::vector<std::wstring> modules ;			// コピーとは独立した実体検査の引数です
		SystemInfEffectApi		  api ;				// 同じ試行内の同期操作です
		api.registryRows		= &registryRows ;
		api.winUsbInboxDocument = bound ;
		api.read				= [&source]( const SystemInfSection	  &section,
								std::vector<SystemInfRow> &rows) -> NativeError {
			   const auto item = source.find( section.name) ;	// 元文書の選択節です
			   // 別文書の同じ節や欠けた空節を補いません
			   if( section.document != INBOX || item == source.end()) {
				   return HRESULT_FROM_WIN32( ERROR_SECTION_NOT_FOUND) ;
			   }

			   rows = item->second ;
			   return 0U ;
		} ;
		api.module = [&]( std::uint64_t identity, std::wstring_view value) -> NativeError {
			modules.emplace_back( value) ;
			return identity == INBOX && value != rejectModule &&
						   (value == BINARY || value == L"winusb.sys")
					   ? 0U
					   : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		} ;
		api.legacyRegistry = [&]( const SystemInfEffect &, bool) -> NativeError {
			DRIVERCRATE_EXPECT( context, false) ;
			return E_NOTIMPL ;
		} ;
		api.service = [&]( std::wstring_view, SystemServiceEvidence &) -> NativeError {
			DRIVERCRATE_EXPECT( context, false) ;
			return E_NOTIMPL ;
		} ;

		SystemInfEffects result ;		// 全作用が成立した場合だけ返る証拠です
		std::uint32_t	 stage{} ;		// 最初の固定拒否分類です
		std::uint32_t	 observed{} ;	// 原作用に対応する固定補足です
		const auto		 error =
			// 試行結果です
			inspectSystemInfEffects( selection, api, result, stage, observed) ;
		DRIVERCRATE_EXPECT( context, stage == static_cast<std::uint32_t>( expected)) ;
		// 完全一致した場合は二つの役割を同じSYSへ結び、元コピー節を後続へ返します
		if( expected == Stage{}) {
			const std::vector<std::wstring> expectedModules{
				BINARY, L"winusb.sys"} ;	// 原サービスと互換値の順です
			DRIVERCRATE_EXPECT( context, error == 0U && modules == expectedModules) ;
			DRIVERCRATE_EXPECT( context, registryRows == 2U && result.effects.size() == 11U &&
											result.references == 5U && result.services.empty()) ;
			DRIVERCRATE_EXPECT( context, result.copySections.size() == 1U &&
											result.copySections.front() == selection.front()) ;
		} else {
			DRIVERCRATE_EXPECT( context, error != 0U && result.effects.empty() &&
											result.copySections.empty()) ;
		}

		// 実体照合が拒否した場合は元の証明エラーと役割を維持します
		if( !rejectModule.empty()) {
			const auto role = rejectModule == BINARY
								  ? SystemInfModuleRole::SERVICE_SYS
								  : SystemInfModuleRole::STREAM_SYS ;	// 指定した照合の役割です
			DRIVERCRATE_EXPECT( context, error == static_cast<NativeError>( TRUST_E_BAD_DIGEST) &&
											observed == static_cast<std::uint32_t>( role)) ;
		}
	} ;

	check( original, selected, INBOX) ;
	check( original, std::span{selected}.first( 2U), INBOX, Stage::REFERENCE) ;
	check( original, selected, INBOX + 1U, Stage::REFERENCE) ;
	check( original, selected, 0U, Stage::DIRECTIVE) ;
	check( original, selected, INBOX, Stage::MODULE, BINARY) ;
	check( original, selected, INBOX, Stage::MODULE, L"winusb.sys") ;

	auto altered = original ;	// 個別に変更する元文書の対照です
	altered.erase( L"WINUSB.NT.HW") ;
	check( altered, selected, INBOX, Stage::READ) ;
	altered												= original ;
	altered.at( L"WINUSB.NT.Services").front().values[1] = L"0" ;
	check( altered, selected, INBOX, Stage::DIRECTIVE) ;
	altered												   = original ;
	altered.at( L"WINUSB.AddService").at( 1U).values.front() = L"@fixture.cpl,-1" ;
	check( altered, selected, INBOX, Stage::DIRECTIVE) ;
	altered										  = original ;
	altered.at( L"WINUSB.AddReg").at( 1U).values[0] = L"HKLM" ;
	check( altered, selected, INBOX, Stage::REGISTRY) ;
	altered = original ;
	altered.at( L"WINUSB.NT.HW").push_back( {0U, L"AddReg", {L"WINUSB.AddReg"}}) ;
	check( altered, selected, INBOX, Stage::REFERENCE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元文書の全到達節とコピー・上位フィルター・既存サービスの限定作用を確認します
 * @param[in,out] context 同processの有限集計です
 * @param[in] good 既存サービスの架空の構成と保護済みSDです
 * @note 読取と原実体の照合を架空化し、実コピーや端末のフィルター設定は行いません
 */
//------------------------------------------------------------------------------
void typedWifiBusInboxCases( TestContext &context, const SystemServiceEvidence &good)
{
	using Context					  = SystemInfContext ;
	using Stage						  = SystemInfDiagnosticStage ;
	using Sections					  = std::map<std::wstring, std::vector<SystemInfRow>> ;
	constexpr std::uint64_t		INBOX = 2U ;	// 元INBOX署名とStoreの確認を仮定する文書IDです
	constexpr std::wstring_view MODULE =
		L"C:\\Fixture\\Store\\vwifibus.sys" ;								// 同じ架空Store内の登録済み実体です
	constexpr auto FILTER		   = L"PnPFilterRegistration" ;				// 上位フィルターの元登録節です
	constexpr auto LEGACY_HARDWARE = L"VWiFiBus.PnPFilterRegistration.HW" ;	// 旧HW節です
	constexpr auto DISPLAY = L"架空のワイヤレス バス" ;								// 現在の言語で展開した架空の表示名です
	constexpr auto DESCRIPTION =
		L"架空のバス機能を実装します" ;	// 現在の言語で展開した架空の説明です
	const std::array modern{
		SystemInfSection{INBOX, L"VWiFiBus", Context::DEVICE, Context::DEVICE, {}},
		SystemInfSection{INBOX, L"VWiFiBus.HW", Context::HARDWARE, Context::HARDWARE, {}},
		SystemInfSection{INBOX, L"VWiFiBus.Services", Context::SERVICES, Context::SERVICES, {}},
		SystemInfSection{
			INBOX, L"VWiFiBus.Interfaces", Context::INTERFACES, Context::INTERFACES, {}},
	} ; // 原グラフが選択した現行文書の入口です
	const SystemInfSection filter{
		INBOX, FILTER, Context::REGISTRY, Context::HARDWARE, {}} ;	// AddRegが所有する元作用です
	const Sections original{
		{L"VWiFiBus", {{0U, L"CopyFiles", {L"VWiFiBus.CopyFilesInternal", L"CopyKMDriver"}}}},
		{L"VWiFiBus.HW", {{0U, L"AddReg", {FILTER}}}},
		{L"VWiFiBus.Interfaces", {}},
		{L"VWiFiBus.Services", {{0U, L"AddService", {L"vwifibus", L"", L"vwifibus_Service_Inst"}}}},
		{L"vwifibus_Service_Inst",
		 {{0U, L"DisplayName", {DISPLAY}},
		  {1U, L"ServiceType", {L"1"}},
		  {2U, L"StartType", {L"3"}},
		  {3U, L"ErrorControl", {L"1"}},
		  {4U, L"ServiceBinary", {L"%13%\\vwifibus.sys"}},
		  {5U, L"Description", {DESCRIPTION}}}},
		{FILTER, {{0U, {}, {L"HKR", L"", L"UpperFilters", L"0x00010000", L"vwifibus"}}}},
	} ; // 同原文書の展開済み全行です

	auto direct			  = good ;	// SCM値と登録文字列が同じ現サービスの証拠です
	direct.name			  = L"vwifibus" ;
	direct.binary		  = MODULE ;
	direct.display		  = DISPLAY ;
	direct.description	  = DESCRIPTION ;
	direct.rawDisplay	  = DISPLAY ;
	direct.rawDescription = DESCRIPTION ;
	auto indirect		  = direct ;	// 同じ展開値を返す正規の間接参照です
	indirect.rawDisplay =
		L"@netvwifibus.inf,%vwifibus_ServiceDisplayName%;Virtual Wireless Bus Driver" ;
	indirect.rawDescription =
		L"@netvwifibus.inf,%vwifibus_ServiceDesc%;Implements bus functionality for Virtual Wireless" ;

	/** @brief 原文の変更と独立して、文書資格又は現在のサービスを変える対照です */
	enum class Fault {
		/// 原文書の資格とサービスを保ちます
		NONE,
		/// 到達文書にINBOX資格を結びません
		UNBOUND_DOCUMENT,
		/// 同一文書を別の標準作用の資格と重複させます
		CONFLICTING_DOCUMENT,
		/// 現在の構成だけに異なるロード順序グループを入れます
		SERVICE_GROUP,
		/// 現在の実行位置だけを同名の別ファイルにします
		SERVICE_BINARY,
	} ;
	// 一回の読取から結果と診断を得ます。元行の表と期待する構成は呼出し中だけ借用します
	const auto check = [&]( std::string_view trial, const Sections &source,
						   std::span<const SystemInfSection> selection, Stage expectedStage = {},
						   Fault						fault	   = Fault::NONE,
						   const SystemServiceEvidence *configured = nullptr) {
		const auto failures = context.failureCount() ;	// 固定のケース名で失敗箇所を補足します
		const bool accepted =
			// 期待する全体結果です
			expectedStage == Stage{} && fault == Fault::NONE ;
		const auto &current = configured ? *configured : direct ;	// 試行に対応する現在の証拠です
		std::size_t registryRows{} ;								// 元行の共同予算です
		std::size_t moduleCalls{} ;									// 元宣言と現在の実体についての照合回数です
		std::size_t serviceCalls{} ;								// 正しい名前のSCM照会回数です
		SystemInfEffectApi api ;									// 一試行にだけ有効な同期read表です
		api.registryRows		 = &registryRows ;
		api.wifiBusInboxDocument = fault == Fault::UNBOUND_DOCUMENT ? 0U : INBOX ;
		api.msPortsInboxDocument = fault == Fault::CONFLICTING_DOCUMENT ? INBOX : 0U ;
		api.legacyRegistry = []( const SystemInfEffect &, bool) -> NativeError { return E_NOTIMPL ; } ;
		api.read		   = [&source]( const SystemInfSection	 &section,
							   std::vector<SystemInfRow> &rows) -> NativeError {
			  const auto item = source.find( section.name) ;	// 同文書内の元節を借用します
			  // 元の文書にない節や異なる文書の節を補いません
			  if( section.document != INBOX || item == source.end()) {
				  return HRESULT_FROM_WIN32( ERROR_SECTION_NOT_FOUND) ;
			  }

			  rows = item->second ;
			  return 0U ;
		} ;
		api.service = [&]( std::wstring_view name, SystemServiceEvidence &output) -> NativeError {
			// 同名の既存サービスだけに現在の構成を返します
			if( name != L"vwifibus") {
				return E_INVALIDARG ;
			}

			++serviceCalls ;
			output = current ;
			// モジュール照合まで進む別の現サービスパスだけを設定します
			if( fault == Fault::SERVICE_BINARY) {
				output.binary = L"C:\\Fixture\\Other\\vwifibus.sys" ;
			}

			// 既存の構成差による拒否も確認します
			if( fault == Fault::SERVICE_GROUP) {
				output.group = L"OtherGroup" ;
			}

			return 0U ;
		} ;
		api.module = [&]( std::uint64_t document, std::wstring_view path) -> NativeError {
			++moduleCalls ;
			return document == INBOX && (path == L"%13%\\vwifibus.sys" || path == MODULE)
					   ? 0U
					   : static_cast<NativeError>( E_ACCESSDENIED) ;
		} ;

		SystemInfEffects result ;		// 全作用が成立した場合だけ元作用を保持します
		std::uint32_t	 stage{} ;		// 最初の固定拒否区分です
		std::uint32_t	 observed{} ;	// 拒否の固定補足です
		const auto		 error = inspectSystemInfEffects( selection, api, result, stage,
														 observed) ;	// 型付き検査の結果です
		DRIVERCRATE_EXPECT( context, (error == 0U) == accepted) ;
		DRIVERCRATE_EXPECT( context, stage == static_cast<std::uint32_t>( expectedStage)) ;
		DRIVERCRATE_EXPECT( context, result.wifiBusFilterDocument == (accepted ? INBOX : 0U)) ;
		DRIVERCRATE_EXPECT( context,
						   serviceCalls == (accepted || expectedStage == Stage::SERVICE_SNAPSHOT ||
													expectedStage == Stage::MODULE
												? 1U
												: 0U)) ;
		DRIVERCRATE_EXPECT( context,
						   moduleCalls == (accepted || expectedStage == Stage::MODULE ? 2U
										   : expectedStage == Stage::SERVICE_SNAPSHOT ? 1U
																					  : 0U)) ;
		// 原コピー節と元行は端末側の再照合へ渡す完全な値として保持します
		if( accepted) {
			DRIVERCRATE_EXPECT( context, registryRows == 1U &&
											std::ranges::count( result.effects, filter,
															   &SystemInfEffect::source) == 1) ;
			DRIVERCRATE_EXPECT( context, result.copySections.size() == 1U &&
											result.copySections.front() == selection.front()) ;
			DRIVERCRATE_EXPECT( context,
							   result.services.size() == 1U && result.services.front() == current) ;
			// 検査で保持された位置、keyと全fieldを元文書に照合します
			for( const auto &effect : result.effects) {
				DRIVERCRATE_EXPECT( context,
								   effect.source.document == INBOX &&
									   source.at( effect.source.name).at( effect.row.ordinal) ==
										   effect.row) ;
			}
		} else {
			DRIVERCRATE_EXPECT( context, result.effects.empty() && result.copySections.empty() &&
											result.services.empty()) ;
		}

		// 失敗時は試験ケース名と有限な元診断だけを表示します
		if( context.failureCount() != failures) {
			std::cerr << "WIFI_BUS_TYPED_CASE trial=" << trial << " stage=" << stage
					  << " observed=" << observed << " error=" << error << '\n' ;
		}
	} ;
	check( "modern", original, modern) ;
	check( "modern_without_interfaces", original, std::span{modern}.first( 3U)) ;
	check( "original_indirect", original, modern, {}, Fault::NONE, &indirect) ;
	DRIVERCRATE_EXPECT( context, direct != indirect) ;

	/** @brief 一つのサービス文字列だけを変更する対照です */
	struct TextChange {
		/// 失敗時に表示する架空ケース名です
		const char	*name ;
		/// 一試行で置換する証拠の項目です
		std::wstring SystemServiceEvidence::*field ;
		/// 元証拠と異なる文字列です
		const wchar_t						*value ;
	} ;
	const TextChange textChanges[]{
		{"different_display", &SystemServiceEvidence::display, L"別の表示名"},
		{"different_description", &SystemServiceEvidence::description, L"別の説明"},
		{"unexpanded_description", &SystemServiceEvidence::description,
		 indirect.rawDescription.c_str()},
		{"other_resource_file", &SystemServiceEvidence::rawDisplay,
		 L"@other.inf,%vwifibus_ServiceDisplayName%;Virtual Wireless Bus Driver"},
		{"other_resource_token", &SystemServiceEvidence::rawDescription,
		 L"@netvwifibus.inf,%Other%;Implements bus functionality for Virtual Wireless"},
		{"other_fallback", &SystemServiceEvidence::rawDescription,
		 L"@netvwifibus.inf,%vwifibus_ServiceDesc%;Changed fallback"},
		{"missing_registered_description", &SystemServiceEvidence::rawDescription, L""},
	} ; // 元の適用条件を保ったまま登録値と展開値の両方を個別に確認します
	// 各変更が元設定と異なる証拠になり、再観測の比較と構造検査の両方で見つかることを確認します
	for( const auto &trial : textChanges) {
		auto modified			= indirect ;	// 一項目だけを変える現在の証拠です
		modified.*(trial.field) = trial.value ;
		DRIVERCRATE_EXPECT( context, modified != indirect) ;
		check( trial.name, original, modern, Stage::SERVICE_SNAPSHOT, Fault::NONE, &modified) ;
	}

	auto legacy =
		std::vector<SystemInfSection>{modern.begin(), modern.end() - 1} ;	// 旧形式の元入口です
	legacy[0].name = L"VWiFiBus.CopyFiles" ;
	legacy[1].name = LEGACY_HARDWARE ;
	legacy.push_back(
		{INBOX, L"VWiFiBus.PnPFilterRegistration", Context::HARDWARE, Context::HARDWARE, {}}) ;
	auto legacyRows = original ;	// 旧基本節、HW節と委譲元に元行を置きます
	legacyRows.emplace( legacy[0].name, original.at( modern[0].name)) ;
	legacyRows.emplace( legacy[1].name, original.at( modern[1].name)) ;
	legacyRows.emplace( legacy.back().name,
					   std::vector<SystemInfRow>{{0U, L"Needs", {LEGACY_HARDWARE}}}) ;
	check( "legacy_wrapper", legacyRows, legacy) ;
	check( "unbound_document", original, modern, Stage::SERVICE, Fault::UNBOUND_DOCUMENT) ;
	check( "conflicting_document", original, modern, {}, Fault::CONFLICTING_DOCUMENT) ;
	check( "service_group", original, modern, Stage::SERVICE_SNAPSHOT, Fault::SERVICE_GROUP) ;
	check( "service_binary", original, modern, Stage::MODULE, Fault::SERVICE_BINARY) ;

	auto changed = original ;	// 各対照では一つの元行又は到達節だけを変更します
	changed.at( modern[2].name)[0].values[1] = L"2" ;
	check( "associated_service", changed, modern, Stage::DIRECTIVE) ;
	changed							= original ;
	changed.at( FILTER)[0].values[3] = L"0x00010008" ;
	check( "append_filter_flag", changed, modern, Stage::REGISTRY) ;
	changed = original ;
	changed.at( FILTER)[0].values.push_back( L"otherfilter") ;
	check( "extra_filter", changed, modern, Stage::REGISTRY) ;
	changed									= original ;
	changed.at( modern[0].name)[0].values[1] = L"OtherCopy" ;
	check( "wrong_copy", changed, modern, Stage::DIRECTIVE) ;
	changed = original ;
	changed.at( modern[3].name).push_back( {0U, L"Needs", {L"OtherInterface"}}) ;
	check( "nonempty_interfaces", changed, modern, Stage::DIRECTIVE) ;
	legacyRows.at( legacy.back().name)[0].values[0] = modern[1].name ;
	check( "wrong_legacy_wrapper", legacyRows, legacy, Stage::DIRECTIVE) ;

	auto wrongScope		= modern ;	// 別scopeの同名HW節へ登録を結び替えます
	wrongScope[1].scope = Context::DEVICE ;
	check( "wrong_hardware_scope", original, wrongScope, Stage::REFERENCE) ;
	auto extra = std::vector<SystemInfSection>{modern.begin(), modern.end()} ;	// 追加の空節です
	extra.push_back( {INBOX, L"Other.HW", Context::HARDWARE, Context::HARDWARE, {}}) ;
	changed					   = original ;
	changed[extra.back().name] = {} ;
	check( "extra_empty_section", changed, extra, Stage::REFERENCE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実SCMと共有する純SD/config validatorへ不正境界を与えます
 * @param[in,out] context 同processの有限集計です
 * @note 架空SDだけを生成し、実serviceの読書きを行いません
 */
//------------------------------------------------------------------------------
void systemServiceSecurityCases( TestContext &context)
{
	const auto evidence = []( const wchar_t *sddl) {
		SystemServiceEvidence result ;	// 同原文/操作へ結ぶ検査又は結果の所有値です
		result.name			= L"Synthetic" ;
		result.type			= SERVICE_KERNEL_DRIVER ;
		result.start		= SERVICE_DEMAND_START ;
		result.errorControl = 1U ;
		result.binary		= L"System32\\drivers\\synthetic.sys" ;
		PSECURITY_DESCRIPTOR raw{} ;	// この同期だけで保持する元値です。許可の代用にしません
		// 固定した入力条件だけを分離し、他対象や期待へ流用しません
		if( !ConvertStringSecurityDescriptorToSecurityDescriptorW(
			   sddl, SDDL_REVISION_1,
			   &raw,	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			   nullptr)) {
			throw std::runtime_error( "service SD fixture rejected") ;
		}

		const auto length = GetSecurityDescriptorLength( raw) ;	// 元全長又は共同予算の有限件数です
		const auto first  = static_cast<const std::byte *>(
			 raw) ;	// 元field/型の全消費を確認する局所位置又は閉じた分類です
		result.security.assign( first, first + length) ;
		LocalFree( raw) ;
		return result ;
	} ; // 既Windows parserを共有し、判定を成功DTOへ置換しません
	const auto good = evidence(
		L"O:BAG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;WD)") ;	// 固定契約から作る独立した正負の期待です
	DRIVERCRATE_EXPECT( context, validateSystemServiceEvidence( good) == 0U) ;
	const std::array<const wchar_t *, 7U> bad{
		// 固定契約から作る独立した正負の期待です
		{L"O:BAG:SYD:P(A;;GA;;;SY)(A;;GW;;;WD)", L"O:WDG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)",
		 L"O:BAG:SYD:NO_ACCESS_CONTROL",
		 L"O:BAG:SYD:P(OA;;GR;10000000-0000-4000-8000-000000000001;;WD)",
		 L"O:BAG:SYD:P(A;;GA;;;WD)", L"O:BAG:SYD:P(A;;0x1000000;;;WD)",
		 L"O:BAG:SYD:P(A;;WO;;;WD)"}} ;
	// 同所有fixtureの全対象を順に検査します
	for( const auto text : bad) {	// 同所有fixtureの全対象を順に確認します
		DRIVERCRATE_EXPECT( context, validateSystemServiceEvidence( evidence( text)) != 0U) ;
	}

	// 同所有fixtureの全対象を順に検査します
	for( unsigned fault = 0U; fault < 9U; ++fault) {	// 同所有fixtureの全対象を順に確認します
		auto changed  = good ;							// この同期だけで保持する元値です。許可の代用にしません
		auto relative = reinterpret_cast<SECURITY_DESCRIPTOR_RELATIVE *>(
			// 元権限/署名の照合中だけ使う証拠です
			changed.security.data()) ;
		// 固定した入力条件だけを分離し、他対象や期待へ流用しません
		if( fault == 0U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			relative->Owner = 0U ;
		}
		// この固定負例の条件だけを変更し、他の期待は維持します
		else if( fault == 1U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			relative->Group = 0U ;
		}
		// この固定負例の条件だけを変更し、他の期待は維持します
		else if( fault == 2U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			relative->Dacl = static_cast<DWORD>( changed.security.size() - 1U) ;
		}
		// この固定負例の条件だけを変更し、他の期待は維持します
		else if( fault == 3U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			relative->Owner |= 1U ;
		}
		// この固定負例の条件だけを変更し、他の期待は維持します
		else if( fault == 4U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			relative->Control &= ~SE_SELF_RELATIVE ;
		}
		// この固定負例の条件だけを変更し、他の期待は維持します
		else if( fault == 5U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			changed.security.push_back( std::byte{}) ;
		}
		// 元SDの一条件だけを変え、他の正常fieldは保持します
		else if( fault == 6U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			changed.binary.append( 1U, L'\0') ;
		}
		// 元SDの一条件だけを変え、他の正常fieldは保持します
		else if( fault == 7U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			changed.dependencies.assign( 65U, L"Synthetic") ;
		} else {
			auto acl = reinterpret_cast<ACL *>(
				// 元権限/署名の照合中だけ使う証拠です
				changed.security.data() + relative->Dacl) ;
			auto ace =	// 元権限/署名の照合中だけ使う証拠です
				reinterpret_cast<ACE_HEADER *>( reinterpret_cast<std::byte *>( acl) + sizeof( ACL)) ;
			ace->AceFlags = SUCCESSFUL_ACCESS_ACE_FLAG ;
		}

		DRIVERCRATE_EXPECT( context, validateSystemServiceEvidence( changed) != 0U) ;
	}

	typedWifiBusInboxCases( context, good) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現OSの二参考INF/Store/copy/helperを同Common/Needs実parserで非実行評価します
 * @param[in] camera 元Camera SYSTEM閉包を選ぶ場合trueです
 * @return 全作用/cache-only署名/権限/原byte成立0、元error時1です
 * @note 架空rootとINBOX分類入力だけがtest bootstrapです。実SetupVerifyInfFile scoreの測定ではありません
 */
//------------------------------------------------------------------------------
int referenceSystemMedia( const bool camera = false)
{
	std::array<wchar_t, MAX_PATH> directory{} ;	// 現OSの唯一のWindows位置です
	const auto					  characters = GetWindowsDirectoryW(
		   // OS APIだけです
		   directory.data(), static_cast<UINT>( directory.size())) ;
	// Root不明で実fileへ進みません
	if( characters == 0U || characters >= directory.size()) {
		return 2 ;
	}

	const std::wstring windows( directory.data()) ;	// 環境変数から置換しません
	Fixture			   fixture(
		   Fault::NONE, {},
		   systemMediaRoot(
			   camera ? "usbvideo.inf" : "ks.inf,wdmaudio.inf",
			   camera ? "USBVideo.NT"
							  : "KS.Registration,WDMAUDIO.Registration")) ;	// 元CABの共通参照名だけです
	const auto rootSignature	 = fixture.api.infSignature ;				// 架空rootに限る完全署名表です
	const auto rootCatalog		 = fixture.api.catalogSignature ;			// 架空rootに限る完全member表です
	fixture.api.windowsDirectory = [windows]( std::wstring &path) {
		path = windows ;
		return NativeError{} ;
	} ; // 二参考INFの元OS位置だけです
	fixture.api.version = []( OSVERSIONINFOEXW &version, SYSTEM_INFO &system) -> NativeError {
		using Query		  = LONG( WINAPI *)( OSVERSIONINFOEXW *) ;	// 公式同期ABIの動的境界です
		const auto module = GetModuleHandleW( L"ntdll.dll") ;		// OS moduleを非所有で借用します
		const auto address =
			module ? GetProcAddress( module, "RtlGetVersion") : nullptr ;	// 読取APIだけです
		Query query{} ;														// 同一Windows ABIへaddressを結びます
		static_assert( sizeof( query) == sizeof( address)) ;
		std::memcpy( &query, &address, sizeof( query)) ;
		// API不明を架空OS情報へ補完しません
		if( !query) {
			return E_NOTIMPL ;
		}

		version.dwOSVersionInfoSize = sizeof( version) ;
		const auto status			= query( &version) ;	// 現OSの元状態です
		GetNativeSystemInfo( &system) ;
		return status == 0 ? NativeError{} : static_cast<NativeError>( status) ;
	} ;
	fixture.api.infSignature = [&]( const std::wstring	&path,
								   SP_INF_SIGNER_INFO_W &signer) -> NativeError {
		// 架空rootを実Windows署名として数えません
		if( path == fixture.workspace.path( L"root.inf")) {
			return rootSignature( path, signer) ;
		}

		// 読取対象は明示した二原INFだけです
		if( path != windows + L"\\INF\\ks.inf" && path != windows + L"\\INF\\wdmaudio.inf" &&
		   path != windows + L"\\INF\\usbvideo.inf" && path != windows + L"\\INF\\kscaptur.inf" &&
		   path != windows + L"\\INF\\pci.inf") {
			return E_INVALIDARG ;
		}

		WindowsSystemFileTrust proof ;	// 実local CATのhash/trust/SDを独立確認します
		const auto error = driver_package_signature_detail::Access::verifySystemCatalogFile(
			path, proof) ;	// 強度/cache-only/publisherを実測します
		// 未検証CAT/未終端をSDK型へ転記しません
		if( error != 0U || proof.catalogPath.empty() || proof.catalogPath.size() >= MAX_PATH) {
			return error != 0U ? error : static_cast<NativeError>( E_INVALIDARG) ;
		}

		std::copy( proof.catalogPath.c_str(),
				  proof.catalogPath.c_str() + proof.catalogPath.size() + 1U, signer.CatalogFile) ;
		constexpr std::wstring_view PUBLISHER =
			L"Microsoft Windows" ;	// 実完全publisher検証後だけ転記します
		std::copy( PUBLISHER.begin(), PUBLISHER.end(), signer.DigitalSigner) ;
		signer.DigitalSigner[PUBLISHER.size()] = L'\0' ;
		signer.SignerScore					   = SIGNERSCORE_INBOX ;
		return 0U ;
	} ; // scoreは内部参考文脈の入力であり、実SetupAPI scoreを測定した値ではありません
	fixture.api.catalogSignature = [&]( const std::wstring			&catalog,
									   std::span<const std::wstring> members) {
		// test bootstrapのCATと実OS CATを混同しません
		if( catalog == fixture.workspace.path( L"fixture.cat")) {
			return rootCatalog( catalog, members) ;
		}

		return driver_package_signature_detail::Access::verifyWindowsCatalogMembers( catalog,
																					members) ;
	} ; // 全実INF/Store payload/現提供copyを原CATへ結びます
	fixture.api.driverStore = [windows]( const std::wstring &path,
										std::wstring	   &store) -> NativeError {
		// 明示二INF以外のStoreを探索しません
		if( path != windows + L"\\INF\\ks.inf" && path != windows + L"\\INF\\wdmaudio.inf" &&
		   path != windows + L"\\INF\\usbvideo.inf" && path != windows + L"\\INF\\kscaptur.inf" &&
		   path != windows + L"\\INF\\pci.inf") {
			return E_INVALIDARG ;
		}

		std::array<wchar_t, MAX_PATH> location{} ;	// 元APIの有限応答です
		// 内容を読まず、同原INFの正確なStore位置だけを取得します
		if( !SetupGetInfDriverStoreLocationW( path.c_str(), nullptr, nullptr, location.data(),
											static_cast<DWORD>( location.size()), nullptr)) {
			const DWORD error = GetLastError() ;	// 元API直後の値です
			return error != 0U ? static_cast<NativeError>( HRESULT_FROM_WIN32( error))
							   : static_cast<NativeError>( E_UNEXPECTED) ;
		}

		store = location.data() ;
		return 0U ;
	} ;
	fixture.api.systemFileTrust = []( const std::wstring &path, WindowsSystemFileTrust &proof) {
		return verifyWindowsSystemFileCachedOnly( path, proof) ;
	} ; // 実固定2helperの署名/元SD/非特権write拒否です
	InfDependencyNativeResult	 result ;		// 同実parserが返す全作用結果です
	RequiredInfBindingDiagnostic diagnostic ;	// 同元失敗の数値だけです
	const auto					 error =
		// CopyFilesも既実処理へ通します
		evaluateSystemCommonFixture( fixture, result, diagnostic) ;
	std::cout
		<< "SYSTEM_REFERENCE error=" << error << " stage=" << diagnostic.stage
		<< " observed=" << diagnostic.observed
		<< " registryRows=" << diagnostic.verifiedRegistryRowCount
		<< " fixedFiles=" << result.fixedFiles.size()
		<< " helperProofs=" << result.systemFiles.size()
		<< " referenceInfs=2 bootstrapRootSynthetic=1 setupApiScoreMeasured=0 realExecute=0 registryWrites=0"
		<< std::endl ;
	return error != 0U ? 1 : 0 ;
}

} // namespace
} // namespace drivercrate::test

//------------------------------------------------------------------------------
/**
 * @brief 非通信の架空API matrix又は明示した固定OS参考のread-only検査を実行します
 * @param[in] argc 実行名と任意の閉じた一modeだけを含む引数数です
 * @param[in] argv mainの寿命中に借用する引数です。未知modeは実Windows検査へ進みません
 * @return 全成功0、assertion・fixture例外の失敗1
 */
//------------------------------------------------------------------------------
int main( int argc, char **argv)
{
	SetErrorMode( SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX) ;
	_set_abort_behavior( 0U, _WRITE_ABORT_MSG | _CALL_REPORTFAULT) ;
#if defined( _DEBUG)
	_CrtSetReportMode( _CRT_ASSERT, _CRTDBG_MODE_FILE) ;
	_CrtSetReportFile( _CRT_ASSERT, _CRTDBG_FILE_STDERR) ;
#endif
	// 明示した試験用元INFで共有作用の読取りだけを行う
	if( argc == 3 && std::string_view( argv[1]) == "--bluetooth-shared-readonly") {
		try {
			const auto path	 = std::filesystem::path{argv[2]}.wstring() ;	// 試験用INFの元位置
			const auto error = drivercrate::test::verifyBluetoothUsbSharedDeclarationsForTest(
				path) ;	// 原宣言の照合結果
			std::cout << "BLUETOOTH_SHARED_DECLARATIONS error=" << error << '\n' ;
			return error == 0U ? 0 : 1 ;
		} catch( ...) {
			std::cerr << "BLUETOOTH_SHARED_DECLARATIONS fixture exception\n" ;
			return 1 ;
		}
	}

	// 参考原文の全作用を同実parserで非実行検査する明示入口です
	if( argc == 2 && (std::string_view( argv[1]) == "--system-reference-readonly" ||
					 std::string_view( argv[1]) == "--system-reference-camera-readonly")) {
		try {
			return drivercrate::test::referenceSystemMedia( std::string_view( argv[1]) ==
														   "--system-reference-camera-readonly") ;
		} catch( ...) {
			std::cerr << "SYSTEM_REFERENCE fixture exception\n" ;
			return 1 ;
		}
	}

	// 明示した固定2fileのread-only資格だけは人工署名scopeを一切使用しません
	if( argc == 2 && std::string_view( argv[1]) == "--system-files-readonly") {
		std::array<wchar_t, MAX_PATH> windows{} ;	// OS APIが返す唯一のWindows位置です
		const auto					  size = GetWindowsDirectoryW(
			   // 環境変数は読みません
			   windows.data(), static_cast<UINT>( windows.size())) ;
		// 固定root不明時は実fileへ進みません
		if( size == 0U || size >= windows.size()) {
			return 2 ;
		}

		int		 failures{} ;	// 実trust/権限の不成立を保持します
		unsigned ordinal{} ;	// file名やCAT位置を出さない閉じた順序です
		// この二名だけを検証し、実行/registry/driverへ作用しません
		for( const auto leaf : {L"rundll32.exe", L"streamci.dll"}) {
			const std::wstring path =
				// OS固定pathです
				std::wstring( windows.data()) + L"\\System32\\" + leaf ;
			drivercrate::WindowsSystemFileTrust proof ;		// 実APIが返した原tupleだけです
			std::uint32_t						stage{} ;	// 元API地点の閉じた数値だけです
			const auto error = drivercrate::verifyWindowsSystemFileCachedOnly(
				path, proof, &stage) ;	// cache-only署名/実AccessCheckです
			std::cout << "SYSTEM_FILE_READONLY ordinal=" << ++ordinal << " error=" << error
					  << " stage=" << stage << " fileBytes=" << proof.fileBytes
					  << " fileSecurityBytes=" << proof.fileSecurity.size()
					  << " catalogBytes=" << proof.catalogBytes
					  << " catalogSecurityBytes=" << proof.catalogSecurity.size()
					  << " catalogSelected=" << !proof.catalogPath.empty()
					  << " realExecute=0 registryWrites=0" << std::endl ;
			std::wcout << L"SYSTEM_FILE_PRIVATE ordinal=" << ordinal << L" fileSha256="
					   << proof.fileSha256 << L" catalogSha256=" << proof.catalogSha256
					   << L" catalogPath=" << proof.catalogPath << std::endl ;
			failures += error != 0U ? 1 : 0 ;
		}

		return failures != 0 ? 1 : 0 ;
	}

	// 不明な引数から実OS操作へ分岐しません
	if( argc != 1) {
		return 2 ;
	}

	drivercrate::test::TestContext context ;	// 一processの有限集計
	try {
		drivercrate::test::matrix( context) ;
		drivercrate::test::referenceSelection( context) ;
		drivercrate::test::junction( context) ;
		drivercrate::test::payloadObservation( context) ;
		drivercrate::test::referenceOpenAbsence( context) ;
		drivercrate::test::needsRegistry( context) ;
		drivercrate::test::legacyWifiBusEdges( context) ;
		drivercrate::test::scopedBluetoothUsbEdges( context) ;
		drivercrate::test::scopedBluetoothUsbCopyCases( context) ;
		drivercrate::test::scopedBluetoothUsbHardwareCases( context) ;
		drivercrate::test::needsRegistryDiagnostics( context) ;
		drivercrate::test::selectedCommonContext( context) ;
		drivercrate::test::systemMediaCases( context) ;
		drivercrate::test::typedSystemCases( context) ;
		drivercrate::test::typedSdBusCases( context) ;
		drivercrate::test::typedMsPortsCases( context) ;
		drivercrate::test::typedNvmeInboxCases( context) ;
		drivercrate::test::typedWinUsbInboxCases( context) ;
		drivercrate::test::rangedStoragePowerCases( context) ;
		drivercrate::test::storagePowerChangeCases( context) ;
		drivercrate::test::storageAutomaticEventChangeCases( context) ;
		drivercrate::test::storageAutomaticEventResourceCases( context) ;
		drivercrate::test::storageAutomaticBootChangeCases( context) ;
		drivercrate::test::typedAhciInboxCases( context) ;
		drivercrate::test::typedRegistryNameCases( context) ;
		drivercrate::test::typedRelationCases( context) ;
		drivercrate::test::systemServiceSecurityCases( context) ;
		drivercrate::test::projectionScopeCases( context) ;
		drivercrate::test::runOfficialServiceOutputContractTests( context) ;
	} catch( ...) {
		std::cerr << "Synthetic native API fixture failed.\n" ;
		return 1 ;
	}

	std::cout
		<< "API scenarios: 46, selection cases: 6, junction cases: 1, payload cases: 3, open absence cases: 2, service cases: 8, registry cases: 23, context cases: 5, Assertions: "
		<< context.assertionCount() << ", failures: " << context.failureCount() << '\n' ;
	return context.failureCount() == 0 ? 0 : 1 ;
}
